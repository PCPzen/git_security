@echo off
title Uninstalling Security Sentinel...
cd /d "%~dp0"
if exist "%ProgramFiles%\SecuritySentinel\Uninstall.ps1" (
    powershell.exe -NoProfile -File "%ProgramFiles%\SecuritySentinel\Uninstall.ps1"
) else (
    powershell.exe -NoProfile -File "%~dp0core\Uninstall.ps1"
)
echo.
pause
