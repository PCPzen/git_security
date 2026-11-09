@echo off
title Starting Security Sentinel Shield...
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\Start-Shield.ps1"
exit
