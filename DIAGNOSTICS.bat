@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
set "DISC=%~1"
if not defined DISC if exist "game.iso" set "DISC=%~dp0game.iso"
if not defined DISC if exist "game\SYSTEM.CNF" set "DISC=%~dp0game"
if not defined DISC goto missing
if not exist "%DISC%" goto missing
set "PS2_SHADER_DIR=%~dp0runtime\shaders"
set "PS2_SAVE_DIR=%~dp0saves"
set "PS2_SPEED_LOG=1"
set "PS2_PROFILE_PHASES=1"
set "PS2_PROFILE_GUEST=1"
set "PS2_PAD_DIAG=1"
set "PS2_CENSUS=0"
set "PS2_VU_PROFILE="
set "PS2_VU_VERIFY="
set "PS2_TRACE_VU="
set "PS2_TRACE_PAD="
echo Diagnostic mode adds profiling overhead. Close the game normally for final summaries.
echo Ace Combat 5 - Playtest 2026-09-13-r10
echo Booting; the first picture can take about 20 seconds.
echo Session output is saved to diagnostics.log.
> "%~dp0diagnostics.log" echo AC5 Playtest 2026-09-13-r10 diagnostics v2
>> "%~dp0diagnostics.log" echo Started %DATE% %TIME%
powershell -NoProfile -Command "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List; Get-FileHash -Algorithm SHA256 -LiteralPath 'runtime/ac5.exe' | Format-List" >> "%~dp0diagnostics.log" 2>&1
"%~dp0runtime\ac5.exe" --data "%~dp0runtime" --disc "%DISC%" --vblanks 0 --watchdog 0 >> "%~dp0diagnostics.log" 2>&1
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" exit /b 0
echo Game exited with code %RC%. Please send diagnostics.log with your report.
pause
exit /b %RC%
:missing
echo Drag your Ace Combat 5 USA ISO onto DIAGNOSTICS.bat.
echo Or put it beside this launcher as game.iso, then double-click DIAGNOSTICS.bat.
pause
exit /b 1
