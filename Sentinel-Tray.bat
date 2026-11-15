@echo off
title Security Sentinel Tray
cd /d "%~dp0"
if exist "%ProgramFiles%\SecuritySentinel\SentinelTray.ps1" (
    start "" powershell.exe -NoProfile -WindowStyle Hidden -File "%ProgramFiles%\SecuritySentinel\SentinelTray.ps1"
) else (
    start "" powershell.exe -NoProfile -WindowStyle Hidden -File "%~dp0core\SentinelTray.ps1"
)
exit
