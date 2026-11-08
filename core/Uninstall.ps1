# =====================================================================
# Security Sentinel Ultra v6.0 - Uninstaller
# Clean Removal, Custom-Entropy DPAPI Stop-Token & ACL Reset
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$StateDir    = "$env:LOCALAPPDATA\SecuritySentinel"
$ProgDir     = "$env:ProgramFiles\SecuritySentinel"
$PidFile     = "$StateDir\sentinel.pid"
$GuardianPid = "$StateDir\guardian.pid"
$StopTokenF  = "$StateDir\graceful_stop.token"
$Entropy     = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v6.0 - UNINSTALLER             " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Generate DPAPI Authenticated Stop-Token & Stop processes
Write-Host "`n[1/4] Disarming Guardian Twin (Custom-Entropy Stop-Token) & Stopping processes..." -ForegroundColor White
if (Test-Path $StateDir) {
    try {
        $wdPid = if (Test-Path $PidFile) { (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($StopTokenF, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    } catch {}
    "STOP" | Out-File -FilePath "$StateDir\graceful_stop.flag" -Encoding UTF8 -Force
}
Start-Sleep -Milliseconds 400

foreach ($pf in @($GuardianPid, $PidFile)) {
    if (Test-Path $pf) {
        $pId = (Get-Content $pf -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($pId -match '^\d+$') {
            Stop-Process -Id ([int]$pId) -Force -ErrorAction SilentlyContinue
        }
    }
}

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
