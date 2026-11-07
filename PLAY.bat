@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
set "DISC=%~1"
if not defined DISC if exist "game.iso" set "DISC=%~dp0game.iso"
if not defined DISC if exist "game\SYSTEM.CNF" set "DISC=%~dp0game"
if not defined DISC goto missing
if not exist "%DISC%" goto missing
for /f "delims==" %%V in ('set PS2_ 2^>nul') do set "%%V="
set "PS2_SHADER_DIR=%~dp0runtime\shaders"
set "PS2_SAVE_DIR=%~dp0saves"
set "PS2_RN_CENSUS=0"
echo Ace Combat 5 - Playtest 2026-09-13-r10
echo Booting; the first picture can take about 20 seconds.
echo Session output is saved to last-play.log.
"%~dp0runtime\ac5.exe" --data "%~dp0runtime" --disc "%DISC%" --vblanks 0 --watchdog 0 > "%~dp0last-play.log" 2>&1
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" exit /b 0
echo Game exited with code %RC%. Please send last-play.log with your report.
pause
exit /b %RC%
:missing
echo Drag your Ace Combat 5 USA ISO onto PLAY.bat.
echo Or put it beside this launcher as game.iso, then double-click PLAY.bat.
pause
exit /b 1
