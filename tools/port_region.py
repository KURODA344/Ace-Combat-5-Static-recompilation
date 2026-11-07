"""Port the SLUS_208.51 (US) configuration to another build of Ace Combat 5.

The files in config/ are keyed to addresses in the US executable. Other
releases (the Japanese SLPS_254.18 in particular) are the same program built
from slightly different sources, so most functions and data items are only
shifted. This tool works out those shifts and writes a translated copy of the
configuration:

    python tools/port_region.py SLPS_254.18 -o config/jp

The US executable itself is not needed. Function boundaries in ida_db.json are
aligned against the target's own code (jal targets, stack-frame prologues and
returns), and data items IDA named are aligned against the addresses the
target's code builds with lui/addiu pairs and gp-relative accesses. Every
mapping is voted on by the neighbouring functions/items, so an isolated
coincidence never wins.

Besides the translated config files it writes addr_map.json, the US -> target
address map as ranges; ps2recomp compiles it into the generated code
(--addr-map) so the runtime can translate the addresses it hard-codes.
"""
import argparse
import bisect
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2recomp.elf import ElfFile  # noqa: E402

US_GP = 0x00448270
US_TEXT_END = 0x00399310
US_VUTEXT_END = 0x003C7E30
US_BSS_END = 0x00484B2C

JR_RA = 0x03E00008


class Target:
    def __init__(self, path):
        self.elf = ElfFile(path)
        self.lo, self.hi = self.elf.text_ranges()[0]
        self.words = {a: self.elf.word(a) for a in range(self.lo, self.hi, 4)}
        jal, pro, after_ret = set(), set(), set()
        for a, w in self.words.items():
            if w >> 26 == 3:
                t = (a & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
                if self.lo <= t < self.hi:
                    jal.add(t)
            elif w >> 16 == 0x27BD and w & 0x8000:
                pro.add(a)
            elif w == JR_RA:
                # the next function starts after the delay slot and any
                # alignment padding
                b = a + 8
                while self.words.get(b) == 0:
                    b += 4
                after_ret.add(b)
        self.jal = jal
        # code addresses the data holds: handler tables, vtables, callbacks
        self.ptrs = set()
        for sec in self.elf.sections:
            if not sec.addr or not sec.data or sec.name.startswith(".text") \
                    or sec.name.startswith(".vu") or sec.name.startswith(".DVP"):
                continue
            for i in range(0, len(sec.data) - 3, 4):
                v = int.from_bytes(sec.data[i:i + 4], "little")
                if self.lo <= v < self.hi and not v & 3:
                    self.ptrs.add(v)
        self.code_starts = jal | pro | after_ret
        self.starts = self.code_starts | self.ptrs
        self.gp = self._find_gp()
        self.refs = self._data_refs()

    def word(self, a):
        w = self.words.get(a)
        if w is None:
            w = self.elf.word(a)
        return w

    def _find_gp(self):
        # crt0 builds gp from constants (lui/ori/addiu, possibly through
        # another register and a move) before it calls anything
        e = self.elf.entry
        val = {0: 0}
        dst = None
        for a in range(e, e + 0x400, 4):
            w = self.words.get(a, 0)
            op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
            imm = w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 0x0F:
                val[rt] = imm << 16
                dst = rt
            elif op in (0x09, 0x19) and rs in val:
                val[rt] = (val[rs] + simm) & 0xFFFFFFFF
                dst = rt
            elif op == 0x0D and rs in val:
                val[rt] = val[rs] | imm
                dst = rt
            elif op == 0 and w & 0x3F in (0x25, 0x2D, 0x21) and rs in val and rt == 0:
                val[rd] = val[rs]
                dst = rd
            else:
                if (op in (2, 3) or (op == 0 and w & 0x3F in (8, 9))) and val.get(28):
                    return val[28]
                continue
        if val.get(28):
            return val[28]
        raise ValueError("cannot find the gp set-up at the entry point")

    def _data_refs(self):
        refs = set()
        hi = {}
        for a in range(self.lo, self.hi, 4):
            w = self.words[a]
            op, rs, rt = w >> 26, (w >> 21) & 31, (w >> 16) & 31
            simm = (w & 0xFFFF) - 0x10000 if w & 0x8000 else w & 0xFFFF
            if op == 0x0F:
                hi[rt] = (a, (w & 0xFFFF) << 16)
                continue
            # addiu, ori and the loads/stores, including lq/sq and the cop1 ones
            if op in (0x09, 0x0D) or 0x1E <= op <= 0x1F or 0x20 <= op <= 0x3F:
                lo = w & 0xFFFF if op == 0x0D else simm
                if rs == 28:
                    refs.add((self.gp + simm) & 0xFFFFFFFF)
                elif rs in hi and a - hi[rs][0] <= 64:
                    refs.add((hi[rs][1] + lo) & 0xFFFFFFFF)
            if w >> 26 in (2, 3) or w == JR_RA:
                hi.clear()
        return refs


def vote(items, valid, score_ok, lo_d, hi_d, step, window, prefer, own=0):
    """For each address in items pick the shift the most neighbours agree on."""
    out = []
    for i, s in enumerate(items):
        nb = items[max(0, i - window): i + window + 1]
        best = None
        for d in range(lo_d, hi_d, step):
            if not valid(s + d):
                continue
            # its own evidence counts for more than any one neighbour's
            sc = sum(score_ok(n, d) for n in nb) + own * score_ok(s, d)
            key = (sc, -abs(d - prefer))
            if best is None or key > best[0]:
                best = (key, d)
        out.append((s, best[1] if best else None, best[0][0] if best else 0))
    return out


def map_code(t, db, us_ptrs=()):
    funcs = sorted({(f["ea"], f["chunks"][0][1]) for f in db["functions"]
                    if f["ea"] < US_TEXT_END})
    ends = dict(funcs)
    starts = [s for s, _ in funcs]

    def ok(s, d):
        n = int(s + d in t.starts)
        e = ends[s]
        if t.words.get(e + d - 8) == JR_RA:
            n += 1
        # a function the US data points at lands where the target's data does
        if s in us_ptrs and s + d in t.ptrs:
            n += 2
        return n

    us_ptrs = set(us_ptrs)
    voted = vote(starts, lambda a: a in t.starts, ok, -0x400, 0xC00, 4, 12,
                 t.lo - 0x100000 + (t.hi - US_TEXT_END), own=4)
    res = {}
    for s, d, sc in voted:
        if d is not None and sc >= 6:
            res[s] = d
    # the clear runs carry the weak ones: a function between two neighbours
    # that agree takes their shift when the target has a function start there
    for i, s in enumerate(starts):
        if s in res:
            continue
        nb = [res.get(starts[j]) for j in (i - 1, i + 1) if 0 <= j < len(starts)]
        for d in nb:
            if d is not None and s + d in t.starts:
                res[s] = d
                break
    # code inside a function maps with the entry when its size is unchanged:
    # the next function moved by the same amount, or it still ends in jr ra
    intact = {}
    for i, (s, e) in enumerate(funcs):
        d = res.get(s)
        if d is None:
            continue
        nxt = funcs[i + 1][0] if i + 1 < len(funcs) else None
        intact[s] = (res.get(nxt) == d) or t.words.get(e + d - 8) == JR_RA
    return funcs, res, intact


def ida_string_name(b):
    """The name IDA gives a string: 'a' and its words capitalised, 15 chars."""
    words = re.findall(rb"[A-Za-z0-9]+", b)
    s = "".join(w[:1].decode().upper() + w[1:].decode().lower() for w in words)
    return ("a" + s)[:15]


def string_anchors(t, db, sections):
    """US string names -> where the target holds the same string."""
    by_name = {}
    for sec in sections.values():
        data, base = sec.data, sec.addr
        i = 0
        while i < len(data):
            if data[i] == 0:
                i += 1
                continue
            j = data.find(b"\0", i)
            if j < 0:
                break
            raw = data[i:j]
            if all(32 <= c < 127 or c in (9, 10, 13) for c in raw) and len(raw) >= 2:
                by_name.setdefault(ida_string_name(raw), []).append(base + i)
            i = j + 1
    uniq, dups = [], []
    for k, v in db["names"].items():
        a = int(k)
        if a < US_VUTEXT_END or not v.startswith("a"):
            continue
        cands = [p for p in by_name.get(re.sub(r"_\d+$", "", v), ())
                 if 0 <= p - a < 0x1000]
        if len(cands) == 1:
            uniq.append((a, cands[0] - a))
        elif cands:
            dups.append((a, cands))
    # a string that occurs several times ("%d %d %d", "Can't load module")
    # is placed only where the unique ones around it say it should be
    uniq.sort()
    keys = [a for a, _ in uniq]
    out = list(uniq)
    for a, cands in dups:
        i = bisect.bisect_right(keys, a)
        near = {uniq[j][1] for j in (i - 1, i) if 0 <= j < len(uniq)}
        hit = [p for p in cands if p - a in near]
        if len(hit) == 1:
            out.append((a, hit[0] - a))
    return out


def map_data(t, db, code_map, switches):
    """US data -> target, as sorted [lo, hi, delta] segments.

    A section that kept its size moves as a whole. Inside one that grew or
    shrank, only what an anchor pins down is mapped: strings matched by their
    IDA name, and the jump tables the target's switches read."""
    tsec = {s.name.lower(): s for s in t.elf.sections if s.addr and s.size}
    usec = [s for s in db["segments"]
            if s["name"].lower() in tsec and s["start"] >= US_VUTEXT_END]
    strs = {s.name: s for s in t.elf.sections
            if s.name in (".data", ".rodata", ".sdata") and s.data}
    anchors = dict(string_anchors(t, db, strs))
    for us_tab, tab in switches.items():
        anchors[us_tab] = tab - us_tab
    segs = []
    for s in usec:
        ts = tsec[s["name"].lower()]
        lo, hi = s["start"], s["end"]
        d0 = ts.addr - lo
        if ts.size == hi - lo:
            segs.append([lo, hi, d0])
            continue
        d1 = ts.addr + ts.size - hi
        pts = sorted((a, d) for a, d in anchors.items() if lo <= a < hi)
        # an anchor that disagrees with both neighbours is a coincidence
        pts = [p for i, p in enumerate(pts)
               if not (0 < i < len(pts) - 1 and pts[i - 1][1] == pts[i + 1][1] != p[1])]
        cur = None
        for a, d in pts:
            if cur and cur[2] == d:
                cur[1] = a + 4
                continue
            if cur:
                segs.append(cur)
            start = lo if (not segs or segs[-1][1] <= lo) and d == d0 and cur is None else a
            cur = [start, a + 4, d]
        if cur:
            if cur[2] == d1:
                cur[1] = hi
            segs.append(cur)
        elif d0 == d1:
            segs.append([lo, hi, d0])
    segs.sort()
    return segs


class AddrMap:
    def __init__(self, t, funcs, code, intact, data):
        self.t = t
        self.fstarts = [s for s, _ in funcs]
        self.funcs = funcs
        self.code = code
        self.intact = intact
        self.dsegs = data
        self.dkeys = [s[0] for s in data]
        # .vutext keeps its size and moves with the end of .text
        self.vu_d = t.hi - US_TEXT_END

    def fn(self, a):
        """Map a function entry; None if it could not be placed."""
        d = self.code.get(a)
        return None if d is None else a + d

    def code_addr(self, a):
        if a < 0x100000:
            return None
        if a >= US_TEXT_END:
            if a < US_VUTEXT_END:
                return a + self.vu_d
            return None
        if a in self.code:
            return a + self.code[a]
        i = bisect.bisect_right(self.fstarts, a) - 1
        if i < 0:
            return None
        s, e = self.funcs[i]
        if a < e and self.intact.get(s):
            return a + self.code[s]
        return None

    def data_addr(self, a):
        if a < US_VUTEXT_END:
            return self.code_addr(a)
        i = bisect.bisect_right(self.dkeys, a) - 1
        if i >= 0 and self.dsegs[i][0] <= a < self.dsegs[i][1]:
            return a + self.dsegs[i][2]
        return None

    def addr(self, a):
        return self.code_addr(a) if a < US_VUTEXT_END else self.data_addr(a)

    def ranges(self):
        """The map as [us_lo, us_hi, delta] ranges for the runtime."""
        out = []

        def add(lo, hi, d):
            if out and out[-1][1] == lo and out[-1][2] == d:
                out[-1][1] = hi
            else:
                out.append([lo, hi, d])

        for s, e in self.funcs:
            d = self.code.get(s)
            if d is None:
                continue
            add(s, e if self.intact.get(s) else s + 4, d)
        add(US_TEXT_END, US_VUTEXT_END, self.vu_d)
        for lo, hi, d in self.dsegs:
            add(lo, hi, d)
        # IDA chunks can run past the next function's entry: the runtime
        # bisects, so the ranges must be sorted and must not overlap
        out.sort()
        for k in range(len(out) - 1):
            out[k][1] = min(out[k][1], out[k + 1][0])
        return [r for r in out if r[1] > r[0]]


def scan_switches(t):
    """GCC's jump tables, read straight from the target's code:

        sltiu at, rX, N  ...  lui rB, %hi(tab)  ...  lw rT, %lo(tab)(rB)  ...  jr rT
    """
    out = []
    for a in range(t.lo, t.hi, 4):
        w = t.words[a]
        if w >> 26 or w & 0x3F != 8 or (w >> 21) & 31 == 31:
            continue
        rt = (w >> 21) & 31
        tab = n = base = None
        lo_off = None
        for b in range(a - 4, max(t.lo, a - 4 * 16), -4):
            x = t.words[b]
            op, rs_, rt_ = x >> 26, (x >> 21) & 31, (x >> 16) & 31
            imm = x & 0xFFFF
            if x >> 26 in (2, 3) or x == JR_RA:
                break
            if lo_off is None and op == 0x23 and rt_ == rt:
                lo_off = imm - 0x10000 if imm & 0x8000 else imm
                base = rs_
            elif lo_off is not None and tab is None and op == 0x0F and rt_ == base:
                tab = ((imm << 16) + lo_off) & 0xFFFFFFFF
            elif op == 0x0B and n is None:
                n = imm
        if tab is None or not n or n > 1024:
            continue
        try:
            tg = [t.elf.word(tab + 4 * i) for i in range(n)]
        except Exception:
            continue
        if not all(t.lo <= x < t.hi and x & 3 == 0 and abs(x - a) < 0x10000 for x in tg):
            continue
        out.append({"ea": a, "func": a, "jumps": tab, "ncases": n, "elbase": 0,
                    "startea": a, "targets": sorted(set(tg))})
    return out


def accessor(t, a):
    """('get' | 'set', address) for a three-instruction accessor of one word:

        lui r, %hi(x)   jr ra   lw v0, %lo(x)(r)    (getter)
        lui r, %hi(x)   jr ra   sw a0, %lo(x)(r)    (setter)
    """
    w0, w1, w2 = t.words.get(a, 0), t.words.get(a + 4, 0), t.words.get(a + 8, 0)
    if w0 >> 26 != 0x0F or w1 != JR_RA:
        return None
    r = (w0 >> 16) & 31
    if (w2 >> 21) & 31 != r:
        return None
    lo = w2 & 0xFFFF
    x = (((w0 & 0xFFFF) << 16) + (lo - 0x10000 if lo & 0x8000 else lo)) & 0xFFFFFFFF
    if w2 >> 26 == 0x23 and (w2 >> 16) & 31 == 2:
        return ("get", x)
    if w2 >> 26 == 0x2B and (w2 >> 16) & 31 == 4:
        return ("set", x)
    return None


def sequence_words(t, lo, hi):
    """Words the code in [lo, hi) bumps through accessors: it calls the getter,
    adds 1 to the result and passes that to the setter of the same word."""
    hits = {}
    for a in range(lo, hi, 4):
        w = t.words[a]
        if w >> 26 != 3:
            continue
        g = accessor(t, (a & 0xF0000000) | ((w & 0x3FFFFFF) << 2))
        if not g or g[0] != "get":
            continue
        inc = None
        for b in range(a + 8, a + 40, 4):
            x = t.words.get(b, 0)
            if x >> 26 == 0x09 and (x >> 21) & 31 == 2 and x & 0xFFFF == 1:
                inc = (x >> 16) & 31
            elif x >> 26 == 3 and inc is not None:
                s = accessor(t, (b & 0xF0000000) | ((x & 0x3FFFFFF) << 2))
                if s == ("set", g[1]):
                    hits[g[1]] = hits.get(g[1], 0) + 1
                break
    return hits


def pin_bss(t, m, cfg):
    """.bss has no names to anchor on; pin the few words the runtime reads.

    NUSNDSTR_SEQ (runtime/src/ps2_hle_iop.c) is the sound-stream module's
    sequence number: each command it queues carries get_seq() + 1, which it
    then stores with set_seq(). It lives in the module that binds RPC server
    0x81000201. (The queue's length, right next to it, is incremented too but
    is not monotonic, and pinning that one hangs the mission loads.)"""
    out = []
    try:
        with open(os.path.join(cfg, "rpc_sids.json")) as fp:
            sids = json.load(fp)
    except OSError:
        return out
    fn = next((int(b["fn"], 16) for b in sids.get("bind", ())
               if b["sid"] == "0x81000201"), None)
    jfn = m.fn(fn) if fn else None
    if jfn is None:
        return out
    us_seq = 0x0047EC9C
    hits = {a: n for a, n in sequence_words(t, jfn - 0x2000, jfn + 0x2000).items()
            if 0 <= a - us_seq < 0x1000}
    if hits:
        a = max(hits, key=hits.get)
        out.append((us_seq, a, "nusndstr sequence number"))
    return out


def hexkey(a):
    return "0x%08X" % a


def port(args):
    t = Target(args.elf)
    cfg = args.config
    with open(os.path.join(cfg, "ida_db.json")) as fp:
        db = json.load(fp)
    with open(os.path.join(cfg, "ida_seeds.json")) as fp:
        seeds = json.load(fp)
    funcs, code, intact = map_code(t, db, seeds.get("ptr", ()))
    m = AddrMap(t, funcs, code, intact, [])
    # a US switch whose jr landed on a jump table the target's code reads
    # pins that table's address: the best data anchors there are
    scanned = scan_switches(t)
    by_ea = {s["ea"]: s["jumps"] for s in scanned}
    tabs = {}
    for s in db["switches"]:
        ea = m.code_addr(s["ea"])
        if ea in by_ea:
            tabs[s["jumps"]] = by_ea[ea]
    m.dsegs = map_data(t, db, m, tabs)
    for us_a, a, what in pin_bss(t, m, cfg):
        m.dsegs.append([us_a, us_a + 4, a - us_a])
        print("pinned: %s %08X -> %08X" % (what, us_a, a))
    m.dsegs.sort()
    m.dkeys = [s[0] for s in m.dsegs]
    os.makedirs(args.out, exist_ok=True)
    lost = {}

    def note(what, a):
        lost.setdefault(what, []).append("%08X" % a)

    # ida_db.json: functions, names, and the switch tables re-read from the
    # target's own jump tables
    nf = []
    for f in db["functions"]:
        ea = m.fn(f["ea"]) if f["ea"] < US_TEXT_END else m.code_addr(f["ea"])
        if ea is None:
            note("functions", f["ea"])
            continue
        chunks = []
        for lo, hi in f["chunks"]:
            nlo = m.code_addr(lo)
            nhi = m.code_addr(hi - 4)
            if nlo is not None and nhi is not None and nhi + 4 - nlo == hi - lo:
                chunks.append([nlo, nhi + 4])
        if not chunks:
            chunks = [[ea, ea + 4]]
        g = dict(f)
        g["ea"], g["chunks"] = ea, chunks
        nf.append(g)
    names = {}
    for k, v in db["names"].items():
        a = m.addr(int(k))
        if a is None:
            note("names", int(k))
        else:
            names[str(a)] = v
    sw = []
    for s in db["switches"]:
        ea, tab = m.code_addr(s["ea"]), m.data_addr(s["jumps"])
        if ea is None or tab is None:
            note("switches", s["ea"])
            continue
        tg = [t.elf.word(tab + 4 * i) for i in range(s["ncases"])]
        if not all(t.lo <= x < t.hi and x & 3 == 0 for x in tg):
            note("switches", s["ea"])
            continue
        g = dict(s)
        g.update(ea=ea, jumps=tab, targets=sorted(set(tg)),
                 func=m.fn(s["func"]) or ea,
                 startea=m.code_addr(s["startea"]) or ea)
        sw.append(g)
    n_mapped = len(sw)
    have = {s["ea"] for s in sw}
    found = 0
    for s in scanned:
        if s["ea"] not in have:
            sw.append(s)
            found += 1
    print("switches: +%d more found by scanning the target's code" % found)
    ndb = dict(db)
    ndb["meta"] = dict(db["meta"], entry=t.elf.entry, input=os.path.abspath(args.elf))
    ndb["functions"], ndb["names"], ndb["switches"] = nf, names, sw
    with open(os.path.join(args.out, "ida_db.json"), "w") as fp:
        json.dump(ndb, fp)

    ns = {}
    for k, v in seeds.items():
        ns[k] = []
        for a in v:
            b = m.code_addr(a)
            if b is None:
                note("seeds." + k, a)
            else:
                ns[k].append(b)
    # and every code address the target's data holds: handler tables and
    # vtables IDA saw only in the US build (a jump-table case among them is
    # harmless, it only splits a function)
    have = set(ns.get("ptr", ()))
    extra = sorted(a for a in t.ptrs if a not in have)
    ns.setdefault("ptr", []).extend(extra)
    print("seeds: +%d code pointers read from the target's data" % len(extra))
    # and the callbacks its code builds with lui/addiu (handlers it registers)
    have = set(ns.get("xref", ())) | set(ns["ptr"])
    built = sorted(a for a in t.refs if t.lo <= a < t.hi and not a & 3 and a not in have)
    ns.setdefault("xref", []).extend(built)
    print("seeds: +%d code addresses built by the target's code" % len(built))
    with open(os.path.join(args.out, "ida_seeds.json"), "w") as fp:
        json.dump(ns, fp)

    # symbol files and hooks are keyed by function entries
    for name in ("sdk_symbols.json", "manual_symbols.json", "hooks.json"):
        with open(os.path.join(cfg, name)) as fp:
            raw = json.load(fp)
        out = {}
        for k, v in raw.items():
            if k.startswith("//") or k.startswith("#"):
                out[k] = v
                continue
            a = m.fn(int(k, 0)) or m.code_addr(int(k, 0))
            if a is None:
                note(name, int(k, 0))
                continue
            out[hexkey(a)] = v
        with open(os.path.join(args.out, name), "w") as fp:
            json.dump(out, fp, indent=1)

    for name in ("overrides.json",):
        with open(os.path.join(cfg, name)) as fp:
            raw = json.load(fp)
        out = {}
        for k, v in raw.items():
            if k.startswith("0x"):
                a = m.fn(int(k, 0))
                if a is None:
                    note(name, int(k, 0))
                    continue
                k = hexkey(a)
            out[k] = v
        with open(os.path.join(args.out, name), "w") as fp:
            json.dump(out, fp, indent=1)

    with open(os.path.join(cfg, "game_symbols.txt")) as fp:
        lines = fp.read().splitlines()
    gs = ["# Translated from the SLUS_208.51 list by tools/port_region.py."]
    for ln in lines:
        mm = re.match(r"([0-9A-Fa-f]{8})(\s.*)", ln)
        if not mm:
            if not ln.startswith("# Names for"):
                gs.append(ln)
            continue
        a = m.fn(int(mm.group(1), 16))
        if a is None:
            note("game_symbols", int(mm.group(1), 16))
            continue
        gs.append("%08X%s" % (a, mm.group(2)))
    with open(os.path.join(args.out, "game_symbols.txt"), "w") as fp:
        fp.write("\n".join(gs) + "\n")

    # SLPS_254.18 -> SLPS-25418, the form the disc's SYSTEM.CNF and mods use
    base = os.path.basename(args.elf).upper()
    game_id = re.sub(r"^(\w{4})_(\d{3})\.(\d{2})$", r"\1-\2\3", base)
    amap = {"from": "SLUS_208.51", "to": base, "game_id": game_id,
            "gp": [US_GP, t.gp], "ranges": m.ranges()}
    with open(os.path.join(args.out, "addr_map.json"), "w") as fp:
        json.dump(amap, fp)

    total = len([f for f in db["functions"] if f["ea"] < US_TEXT_END])
    print("code: %d/%d US functions placed, %d with their whole body"
          % (len(code), total, sum(1 for v in intact.values() if v)))
    print("names: %d/%d placed" % (len(names), len(db["names"])))
    print("switches: %d/%d re-read from the target's jump tables"
          % (n_mapped, len(db["switches"])))
    print("gp: US %08X -> %08X" % (US_GP, t.gp))
    for k, v in sorted(lost.items()):
        print("  not placed: %-22s %d  (%s%s)"
              % (k, len(v), " ".join(v[:6]), " ..." if len(v) > 6 else ""))
    with open(os.path.join(args.out, "port_report.json"), "w") as fp:
        json.dump(lost, fp, indent=1)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("elf", help="the executable to port to (e.g. SLPS_254.18)")
    ap.add_argument("-o", "--out", required=True, help="output config folder")
    ap.add_argument("--config", default="config", help="the US config folder")
    port(ap.parse_args())


if __name__ == "__main__":
    main()
