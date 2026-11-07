@echo off
rem Starts the Japanese build (SLPS-25418). Double-click it, or run it from any folder.
cd /d "%~dp0"
start "" "build\gcc\ac5.exe" --data generated --disc ACECOMBAT05.ISO --watchdog 0
