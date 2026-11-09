# =====================================================================
# Security Sentinel Ultra v8.0 - Stop Shield
# Graceful Authenticated Disarm and Stop of Watchdog & Guardian
# =====================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$StateDir      = "$env:LOCALAPPDATA\SecuritySentinel"
$PidFile       = Join-Path $StateDir "sentinel.pid"
$StopTokenFile = Join-Path $StateDir "graceful_stop.token"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - STOPPING SHIELD         " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Retrieve Secret from HKLM IntegrityAnchor
$entropy = $null
$regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
if (Test-Path $regPath) {
    $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
    if ($b64) {
        try { $entropy = [Convert]::FromBase64String($b64) } catch {}
    }
}
if (-not $entropy) {
    $entropy = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
}

# 2. Issue CSPRNG Authenticated Stop Token
try {
    $wdPid = if (Test-Path $PidFile) { (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
    $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($StopTokenFile, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    Write-Host "[TOKEN] Authenticated Stop-Token issued." -ForegroundColor DarkGray
} catch {}

# 3. Stop Scheduled Tasks
Stop-ScheduledTask -TaskName "SecuritySentinelWatchdog" -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName "SecuritySentinelGuardian" -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 1500

# 4. Stop running PowerShell processes for Watchdog/Guardian
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

if (Test-Path $PidFile) { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue }
if (Test-Path $StopTokenFile) { Remove-Item $StopTokenFile -Force -ErrorAction SilentlyContinue }

Write-Host "`n>>> SECURITY SENTINEL SHIELD HAS BEEN STOPPED / PAUSED <<<" -ForegroundColor Yellow
Write-Host "You can start it again anytime via Start-Shield.bat or Sentinel-Dashboard.bat" -ForegroundColor White
Start-Sleep -Seconds 2

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDBsZmNuaTG9Et
# e/0gi2Mzsq8o999evWQqygTcjs8Lq6CCAzIwggMuMIICFqADAgECAhBqicxAtgYy
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINpjIQglcfXr7+U4fR3R
# dAuv7K4nAu+e/TMPYJhVquckMA0GCSqGSIb3DQEBAQUABIIBAKAca2AGCAlCAbIf
# 9fNWpizx/ymiAcrckZMSIlSlMa6jQ6o8nUpt+mCORiV80114Y1Tr2IGtdC8X3Ohc
# JSRguCl/iKCXsRQCzfqy0NztpZPzc1CQJuABLyKCrXbXzdX04bvOJ/8Mf/EhvsZT
# 8Xr6BDZyMomC1qmOzmUUx50+wE7CCXytLSuHa1DevRqiuATQPpNPZxmJ8T8EuQKE
# blaTz8v2O2OCdSbgM+lxUjcXKzb5rIaHCv8yeaaJhHvqKCg6c9XwgATOM0MB2Rvh
# hLgfPlf9jyz/ucChopPzI8trqgG1K45E47O9Z0uR1Rgbs26FngfVR5eHeiLIxiJQ
# W9zjcjw=
# SIG # End signature block
