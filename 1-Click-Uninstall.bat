@echo off
title Uninstalling Security Sentinel...
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\Uninstall.ps1"
echo.
pause
