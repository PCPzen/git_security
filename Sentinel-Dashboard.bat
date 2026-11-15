@echo off
title Security Sentinel Dashboard
if exist "%ProgramFiles%\SecuritySentinel\SentinelDashboard.ps1" (
    start "" powershell.exe -NoProfile -WindowStyle Hidden -File "%ProgramFiles%\SecuritySentinel\SentinelDashboard.ps1"
) else (
    start "" powershell.exe -NoProfile -WindowStyle Hidden -File "%~dp0core\SentinelDashboard.ps1"
)
exit
