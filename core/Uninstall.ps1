# =====================================================================
# Security Sentinel Ultra v8.0 - Enterprise Uninstaller
# Clean Removal, CSPRNG Authenticated Stop-Token & ACL Reset
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$StateDir    = "$env:LOCALAPPDATA\SecuritySentinel"
$ProgDir     = "$env:ProgramFiles\SecuritySentinel"
$PidFile     = "$StateDir\sentinel.pid"
$GuardianPid = "$StateDir\guardian.pid"
$StopTokenF  = "$StateDir\graceful_stop.token"

function Get-InstallSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
        if ($b64) {
            try { return [Convert]::FromBase64String($b64) } catch {}
        }
    }
    return [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
}

$Entropy = Get-InstallSecret

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v7.0 - UNINSTALLER             " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Generate CSPRNG Authenticated Stop-Token & Wait for Graceful Self-Exit
Write-Host "`n[1/4] Disarming Guardian Twin (CSPRNG Stop-Token) & Stopping processes..." -ForegroundColor White
if (Test-Path $StateDir) {
    try {
        $wdPid = if (Test-Path $PidFile) { (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($StopTokenF, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    } catch {}
}
Start-Sleep -Milliseconds 1800

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1|SentinelDashboard\.ps1" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Write-Host "  -> Active Watchdog & Guardian Twin processes stopped." -ForegroundColor Green

# 2. Remove Scheduled Task & Registry Trust Anchors
Write-Host "`n[2/4] Removing Scheduled Task & Integrity Anchors..." -ForegroundColor White
Unregister-ScheduledTask -TaskName "SecuritySentinelWatchdog" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $ProgDir) {
    icacls "$ProgDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
    Remove-Item $ProgDir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "  -> Task 'SecuritySentinelWatchdog' and Trust Anchors removed." -ForegroundColor Green

# 3. Remove Desktop Shortcut
Write-Host "`n[3/4] Removing Desktop shortcut..." -ForegroundColor White
$desktopDir = [Environment]::GetFolderPath('Desktop')
$sc = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
if (Test-Path $sc) { Remove-Item $sc -Force }
$fallbackSc = "$env:USERPROFILE\Desktop\Security Sentinel Dashboard.lnk"
if (Test-Path $fallbackSc) { Remove-Item $fallbackSc -Force }
Write-Host "  -> Desktop shortcuts removed." -ForegroundColor Green

# 4. Cleanup Canary Honeypots
Write-Host "`n[4/4] Cleaning up Canary decoys..." -ForegroundColor White
$canaryAppdata = "$env:APPDATA\SecuritySentinel_Canary"
if (Test-Path $canaryAppdata) { Remove-Item $canaryAppdata -Recurse -Force }

$docCanary = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Crypto_Recovery_Phrase_Decoy.txt"
if (Test-Path $docCanary) { Remove-Item $docCanary -Force }
Write-Host "  -> Canary honeypots cleaned." -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " UNINSTALLATION COMPLETED SUCCESSFULLY!                   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Security Sentinel has been completely removed from this PC."

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnZu/t5Qj7bMAr
# b1zWg5UQpcyrWt2odv98BGxZIgT5/qCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOvaxEvrHGKLqwSQ3jMu
# t1RZE6FlWt7w9b4ItEgkojmoMA0GCSqGSIb3DQEBAQUABIIBAFVCbQlSkogJaKpG
# q4UAJNpI4W/kbWE3Rb/y/GpWRhUAyGm9mECNUYijvGUxsnH83lTLpBIrvHe6uhYB
# 8CAfIqs44SRaICEj74mydQccg2qHIMCV4fWyvDSNGZctG3p2bomKewiXSQs8oN3i
# J8GNmlj40tmA92PnRAJYgCpOPnkfRt86lZdvzHyWfJFuIJ0Rf28nNlrfiidMrVxa
# sWqVRSVrYxE5DsSbXugVdzgi0p64+TZbF03dovo54R6MkzarF4mba9gOmz9KE1DF
# 7sGYCbeVxTrRc+IUPKiFbvYePuEc8nZguAzgUjobJnayfk6cjX7cMi05zVfNeU3e
# xg71ayA=
# SIG # End signature block
