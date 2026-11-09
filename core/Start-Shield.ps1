# =====================================================================
# Security Sentinel Ultra v8.0 - Start Shield
# Launches the autonomous background protection engine
# =====================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$StateDir   = "$env:LOCALAPPDATA\SecuritySentinel"
$ScriptPath = Join-Path $StateDir "SentinelWatchdog.ps1"
if (-not (Test-Path $ScriptPath)) { $ScriptPath = Join-Path $PSScriptRoot "SentinelWatchdog.ps1" }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - STARTING SHIELD         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check if already running
$pidFile = Join-Path $StateDir "sentinel.pid"
if (Test-Path $pidFile) {
    $curPid = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ($curPid -match '^\d+$') {
        $p = Get-Process -Id [int]$curPid -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host "[INFO] Security Sentinel Shield is ALREADY RUNNING (PID: $curPid)." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            exit 0
        }
    }
}

# 2. Try starting registered Scheduled Task
$started = $false
try {
    Start-ScheduledTask -TaskName "SecuritySentinelWatchdog" -ErrorAction Stop
    $started = $true
    Write-Host "[OK] Watchdog service started via Windows Task Scheduler." -ForegroundColor Green
} catch {
    # 3. Fallback: launch direct background process
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -File `"$ScriptPath`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($proc) {
        $started = $true
        Write-Host "[OK] Watchdog process launched in background (PID: $($proc.Id))." -ForegroundColor Green
    }
}

Start-Sleep -Seconds 1
if ($started) {
    Write-Host "`n>>> SECURITY SENTINEL ULTRA SHIELD IS NOW ACTIVE & PROTECTING <<<" -ForegroundColor Green
} else {
    Write-Host "`n[FAIL] Failed to launch Sentinel Watchdog." -ForegroundColor Red
}
Start-Sleep -Seconds 2

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgpfM1X+fGlZxh
# thxvBefLnSxDLxo9kJJkAtwVdrAjtqCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
# tEDV87OXYXwsMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNl
# bnRpbmVsIFVsdHJhIENvZGUgU2lnbmluZzAeFw0yNjExMDkxODA2NDBaFw0zMTEx
# MDkxODE2NDBaMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNlbnRpbmVsIFVsdHJhIENv
# ZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNKKvtK
# ERrpKZl/ygPwjprcar+6Xk/3xKwms9K7GDTSH8EYVjwFvMsNGB8+On0f31+3hmyt
# KZzePEl5panG4eomaJwGl5qLzD2qyJVAtpgRKh+fiUgjFgm+FOm46u74WMC/Jhr2
# UZe+h6PpO7eoAizbrVRHPaHIOSfIMxnQFVtkkV66T0O5ELGaqTsLZbeQRZsvf6pl
# mIRLQ7nDIzQ6HqRuaWYfU/GNB8/uDhymxuRyLVV6y6pJ/lO2plVgHwC1JHIT7M+S
# t6Fx8wOkUB9McT6P/T4uXHP56PufSxPC7Q4IgDBQ4sQr6NKqtxzVeZ8LBeZW9dsF
# /E1ggkQ3GpNEDmECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBTzQylDY2rNT15+NYtrGro9m44IMjANBgkqhkiG
# 9w0BAQsFAAOCAQEASGAB2FcY0MsNMQsmt1MEmkmsNWWM15Bf3/gojZQeA84NS39J
# Q3AvtZsrUFq7czi6dm0Oh5GtmEhBBaXxdQeZc48SviS1ZkH+ydm4wFNDz0htXqem
# K5iqgz9JWlYbO0Q1SpCwnrL2lqtXUTqnq1K83NVlyEfMJy1N/pve+DlOLEBjvPvr
# PJDNfUZ79skHaztddUvFUfRFIOaMr0sop2XozdqDsD3Au4im941zJTleYk7m+0Qx
# V0WFPnXMN88dI7JkFgmgmoT53b362u5EU9KHRnwLNjrGIb4+NpAH5QtH7Xl1hqde
# Hxvq+WiRbpJEMEiPyUN71mzSsOfIzKk16U4MIjGCAfUwggHxAgEBMEMwLzEtMCsG
# A1UEAwwkU2VjdXJpdHkgU2VudGluZWwgVWx0cmEgQ29kZSBTaWduaW5nAhBqicxA
# tgYytEDV87OXYXwsMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGiZrTgvZQwZzTQ0NjsG
# agDlZ2c8gg1r1t9AlF3YBF12MA0GCSqGSIb3DQEBAQUABIIBAEMGTGgDcZiAHTnN
# TvA8y12oT+8WU0jJ88JAESxFVLzvTzRqxxKVhK3g8N52s2XxaeHdvmnDGBJJQVsB
# yHcMJeOWhOkA+3GC8IQHxOI0Fra6/xL4TGMq5NdJZdb9h98aCVouCStR9Vn38QxA
# DuZJZr2MXftCPD8nFAxJjer/PneeuSr9bgC2WY1oSA57j4gGC1zNlZeAW7G9Du8Y
# yGMJ4x29kQ7zIjyXIrQ0hZRofmvULqtudLBEM/7zmgWpLwDxp8WDO9pcP5iGiM1O
# YzgXmubX5cg1lSE2EaZvi+b3ZQu4lwbK2D5HmdY83g8py4Pnbq+5NGZAhtuqPKPq
# JqmyB1g=
# SIG # End signature block
