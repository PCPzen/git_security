@echo off
title Stopping Security Sentinel Shield...
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\Stop-Shield.ps1"
exit
