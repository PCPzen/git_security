@echo off
title Security Sentinel Tray
cd /d "%~dp0"
start powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0core\SentinelTray.ps1"
exit
