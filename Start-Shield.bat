@echo off
title Starting Security Sentinel Shield...
cd /d "%~dp0"
if exist "%ProgramFiles%\SecuritySentinel\Start-Shield.ps1" (
    powershell.exe -NoProfile -File "%ProgramFiles%\SecuritySentinel\Start-Shield.ps1"
) else (
    powershell.exe -NoProfile -File "%~dp0core\Start-Shield.ps1"
)
exit
