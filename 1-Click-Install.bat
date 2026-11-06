@echo off
title Installing Security Sentinel...
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\Install.ps1"
echo.
pause
