@echo off
title Security Sentinel Dashboard
start powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0core\SentinelDashboard.ps1"
exit
