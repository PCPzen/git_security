@echo off
title Stopping Security Sentinel Shield...
cd /d "%~dp0"
if exist "%ProgramFiles%\SecuritySentinel\Stop-Shield.ps1" (
    powershell.exe -NoProfile -File "%ProgramFiles%\SecuritySentinel\Stop-Shield.ps1"
) else (
    powershell.exe -NoProfile -File "%~dp0core\Stop-Shield.ps1"
)
exit
