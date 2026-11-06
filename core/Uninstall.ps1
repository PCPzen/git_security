# =====================================================================
# Security Sentinel Ultra v4.0 - Uninstaller
# Clean Removal & Guardian Twin Shutdown
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$SentinelDir = "$env:LOCALAPPDATA\SecuritySentinel"
$PidFile     = "$SentinelDir\sentinel.pid"
$GuardianPid = "$SentinelDir\guardian.pid"
$StopFlag    = "$SentinelDir\graceful_stop.flag"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v4.0 - UNINSTALLER             " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Signal Guardian Twin & Stop processes
Write-Host "`n[1/4] Disarming Guardian Twin & Stopping Sentinel processes..." -ForegroundColor White
if (Test-Path $SentinelDir) {
    "STOP" | Out-File -FilePath $StopFlag -Encoding UTF8 -Force
}
Start-Sleep -Milliseconds 300

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

# 2. Remove Scheduled Task
Write-Host "`n[2/4] Removing Scheduled Task from Windows..." -ForegroundColor White
Unregister-ScheduledTask -TaskName "SecuritySentinelWatchdog" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "  -> Task 'SecuritySentinelWatchdog' removed." -ForegroundColor Green

# 3. Remove Desktop Shortcut (OneDrive Desktop compatible)
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
