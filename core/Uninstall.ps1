# =====================================================================
# Security Sentinel Ultra v8.0 - Enterprise Uninstaller
# Clean Removal, Unified CSPRNG Stop-Token & ACL Reset
# =====================================================================
param(
    [string]$InstallDir = ""
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Resolve-SentinelStateDir {
    $defaultDir = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
    if ($env:SENTINEL_TEST_MODE -eq "1" -and $env:SENTINEL_STATE_DIR) {
        try {
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
            $candidate = [System.IO.Path]::GetFullPath($env:SENTINEL_STATE_DIR)
            if ($candidate.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $candidate
            }
        } catch {}
    }
    return $defaultDir
}

$StateDir     = Resolve-SentinelStateDir
$ProgDir      = "$env:ProgramFiles\SecuritySentinel"
$RegInstallDir = $null
foreach ($rp in @("HKLM:\SOFTWARE\SecuritySentinel\PublicHashes", "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor")) {
    if (Test-Path $rp) {
        $d = (Get-ItemProperty -Path $rp -Name "InstallDir" -ErrorAction SilentlyContinue).InstallDir
        if ($d) { $RegInstallDir = $d; break }
    }
}
$PidFile      = "$StateDir\sentinel.pid"
$GuardianPidF = "$StateDir\guardian.pid"
$StopTokenF   = "$StateDir\graceful_stop.token"
$PauseFile    = "$StateDir\paused_until.txt"

function Get-SentinelSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        try {
            $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction Stop).InstallSecret
            if ($b64) {
                $bytes = [Convert]::FromBase64String($b64)
                if ($bytes -and $bytes.Length -ge 16) { return $bytes }
            }
        } catch {}
        return $null
    }
    $vaultFile = Join-Path $StateDir "vault.sec"
    if (Test-Path $vaultFile) {
        try {
            $encB64 = (Get-Content $vaultFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
            $encBytes = [Convert]::FromBase64String($encB64)
            $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            if ($decBytes -and $decBytes.Length -ge 16) { return $decBytes }
        } catch {}
    }
    return $null
}

$Entropy = Get-SentinelSecret

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - UNINSTALLER             " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Generate CSPRNG Authenticated Stop-Token & Wait for Graceful Self-Exit
Write-Host "`n[1/4] Disarming Guardian Twin (CSPRNG Stop-Token) & Stopping processes..." -ForegroundColor White
if ((Test-Path $StateDir) -and $Entropy) {
    try {
        $wdPid = if (Test-Path $PidFile) { (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($StopTokenF, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
        try {
            $ev = [System.Threading.EventWaitHandle]::OpenExisting("Local\SecuritySentinelStopSignal")
            [void]$ev.Set()
            $ev.Close()
        } catch {}
    } catch {}
}
Start-Sleep -Milliseconds 2200

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1|SentinelDashboard\.ps1|SentinelTray\.ps1" } | ForEach-Object {
    Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue
}
Remove-Item $StopTokenF -Force -ErrorAction SilentlyContinue
Remove-Item $PauseFile -Force -ErrorAction SilentlyContinue
Write-Host "  -> Active Watchdog & Guardian Twin processes stopped." -ForegroundColor Green

# 2. Remove Scheduled Tasks & Registry Trust Anchors
Write-Host "`n[2/4] Removing Scheduled Tasks & Integrity Anchors..." -ForegroundColor White
Unregister-ScheduledTask -TaskName "SecuritySentinelWatchdog" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SecuritySentinelGuardian" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SecuritySentinelAutoResume" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
foreach ($targetDir in @($ProgDir, $RegInstallDir, $InstallDir) | Where-Object { $_ } | Select-Object -Unique) {
    if (Test-Path $targetDir) {
        icacls "$targetDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
        Remove-Item $targetDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  -> Tasks and Trust Anchors removed." -ForegroundColor Green

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
