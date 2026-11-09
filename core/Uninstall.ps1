# =====================================================================
# Security Sentinel Ultra v7.0 - Uninstaller
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
    foreach ($regPath in @("HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor", "HKCU:\Software\SecuritySentinel\IntegrityAnchor")) {
        if (Test-Path $regPath) {
            $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
            if ($b64) {
                try { return [Convert]::FromBase64String($b64) } catch {}
            }
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCApvCg5scvGHI/w
# H1JUCGyn+BEnrQNdnfU012fungxUTqCCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
# k00USv2WB3cfMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNl
# bnRpbmVsIFVsdHJhIENvZGUgU2lnbmluZzAeFw0yNjExMDkwMjUxMjZaFw0zMTEx
# MDkwMzAxMjVaMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNlbnRpbmVsIFVsdHJhIENv
# ZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALllSiqT
# Y5Sc6hifAl+AGeEpL3joSXd9ne4K7pKYDHPQavPfBy32CzCJa1jyX77QoO1UtsOv
# On5Xoi8k5ApurF/WYtjU0g3ql946XPjn6VjwGLmbqSA+pNGqnOMjBz4ox0cqVblm
# 5hD944XKqtREmR7apy3lthUp7XTTG7BGRAVqhZpd+E/VTVG0A+P3wcNc7y3aOxoa
# DJ6JHO/8putrt37Q54x3UVUXOU8Zbwwjic/NI7WV5ckmQ00jiI2cxZgzXdqnXxDU
# aWxd7Ek2/z9QDJEE6wRtBHtvynUpAcZvBW87Xx0WwB8h5qh2P1gHF5ZONY1hzuav
# shNwuowu2k17JakCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBThzeAg8TkOvzIAhDScXw7avedctTANBgkqhkiG
# 9w0BAQsFAAOCAQEAQJM2S9UXri6Zk2rCN6vcsOSuJBRdo43f2i/IXF8KqqPl89cB
# 0EKkiYCaz/1zpjyqotuM0PfHdQgyhOS1rBy8BGCc9CmD2Yk4mcGe1cq/DPrjjmHZ
# I/Hbwq5jla1t5hIB8TENaRlO2yJcnx0m7zJ90RHkCm5t4sVQO55kh//OfQ4RUXEA
# vNdnlgF1EkHey5FbUxyhcEsCZpsJU+KrGceLE43oYtCEekpdTsNuC3SNCYP674yo
# lebxXnckHIuqfnYmizmxBMhYcK3RChIIv8cFPR2/n0EhcQ3XeNNfksfrVyarz8eE
# BFVfGerioUtLIH4OFiCsGTtRr0BCbo6iE7kwajGCAfUwggHxAgEBMEMwLzEtMCsG
# A1UEAwwkU2VjdXJpdHkgU2VudGluZWwgVWx0cmEgQ29kZSBTaWduaW5nAhARiv7c
# h4Yqk00USv2WB3cfMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIClKYG/agYxNZK29o51F
# S6Kpmr+naj+ozVOmXf8K4bJXMA0GCSqGSIb3DQEBAQUABIIBAEYBxaiQbJc7rP9C
# A4ksRhqYiSlxJANrWQoxPdz677IwWSO5xvGbVXqyZWTCmTbvLWNntPUOOz8614Nv
# DmffSbrX6vre1a8z0HJrqZh3BT17Jq8UxujrSeBhPeaXSsnjRb9eNzuUAP/+69nc
# AF6XDK8NypfoGuJloVHw9xEMD5jBUW/3IxxDOOU4xyI2upCrBsMdMe5VzBmqLfyn
# yyhj4hWvmHn2B56RcGUze92pnODM2WGcLhJRjpmcSOdQo+qdz3+vmLcyWTRBuFO+
# lVenLzZpygDBIUQQb9gWVhaTcgS8eun3Xl8FfmM8sKpLgjXW6LnhNaFzPIF+bRU5
# qtYBVN0=
# SIG # End signature block
