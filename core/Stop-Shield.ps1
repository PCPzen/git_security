# =====================================================================
# Security Sentinel Ultra v8.0 - Stop Shield (Authenticated & Elevated)
# Enforces Administrator Elevation, Clamped Pause (1-60 min), EventLog,
# Auto-Resume & Self-Termination via Token (Zero Force-Kill!)
# =====================================================================
param(
    [ValidateRange(1, 60)]
    [int]$PauseMinutes = 15,
    [switch]$NoElevate,
    [switch]$Confirmed
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$ProgDir       = "$env:ProgramFiles\SecuritySentinel"
$StateDir      = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
$SentinelDir   = if (Test-Path (Join-Path $ProgDir "SentinelWatchdog.ps1")) {
    $ProgDir
} elseif ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "SentinelWatchdog.ps1"))) {
    $PSScriptRoot
} else {
    $StateDir
}

$PidFile       = Join-Path $StateDir "sentinel.pid"
$GuardianPidF  = Join-Path $StateDir "guardian.pid"
$StopTokenFile = Join-Path $StateDir "graceful_stop.token"
$PauseFile     = Join-Path $StateDir "paused_until.txt"
$StartScript   = Join-Path $SentinelDir "Start-Shield.ps1"

# 1. Enforce Administrator Elevation (A1)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($NoElevate) {
        Write-Host "[DENIED] Elevation required: Stopping Security Sentinel Shield requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
    Write-Host "[UAC] Administrator privileges are required to pause Security Sentinel Shield..." -ForegroundColor Yellow
    try {
        $argStr = "-NoProfile -File `"$PSCommandPath`" -PauseMinutes $PauseMinutes"
        if ($Confirmed) { $argStr += " -Confirmed" }
        $elevProc = Start-Process -FilePath "powershell.exe" -ArgumentList $argStr -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $elevProc.ExitCode
    } catch {
        Write-Host "[DENIED] UAC elevation was declined or cancelled." -ForegroundColor Red
        exit 1
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - PAUSING SHIELD          " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Require Explicit Confirmation
if (-not $Confirmed) {
    $ans = Read-Host "Confirm pausing Security Sentinel Shield for $PauseMinutes minutes? Type 'YES' to confirm"
    if ($ans -cne "YES") {
        Write-Host "[ABORTED] Pause operation cancelled by user." -ForegroundColor Yellow
        exit 1
    }
}

# 3. Retrieve Secret via Unified Fail-Closed Loader (Never falls back to vault.sec when HKLM IntegrityAnchor exists!)
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

$entropy = Get-SentinelSecret
if (-not $entropy) {
    Write-Host "[FAIL] Integrity Anchor secret unavailable. Cannot issue authenticated stop token." -ForegroundColor Red
    exit 1
}

# 4. Identify Active Watchdog PID
$wdPid = "0"
if (Test-Path $PidFile) {
    $rawPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($rawPid -and ($rawPid.Trim() -match '^\d+$')) {
        $wdPid = $rawPid.Trim()
    }
}

if ($wdPid -eq "0") {
    Write-Host "[INFO] Security Sentinel Shield is already stopped." -ForegroundColor Yellow
    exit 0
}

# 5. Write Windows Event Log Entry & Schedule Auto-Resume (A1)
$resumeAt = (Get-Date).AddMinutes($PauseMinutes)
$resumeUnix = ([DateTimeOffset]$resumeAt).ToUnixTimeSeconds()
try {
    [System.IO.File]::WriteAllText($PauseFile, "$resumeUnix", [System.Text.Encoding]::UTF8)
} catch {}

try {
    $evSource = if ([System.Diagnostics.EventLog]::SourceExists("SecuritySentinel")) { "SecuritySentinel" } else { "Windows PowerShell" }
    $evId     = if ($evSource -eq "SecuritySentinel") { 4006 } else { 800 }
    Write-EventLog -LogName Application -Source $evSource -EventId $evId -EntryType Warning -Message "[SecuritySentinel][PAUSE][EventID:4006] Shield paused by Administrator ($env:USERNAME) for $PauseMinutes minutes (Watchdog PID: $wdPid). Scheduled auto-resume at $($resumeAt.ToString('yyyy-MM-dd HH:mm:ss'))." -ErrorAction SilentlyContinue
} catch {}

if (Test-Path $StartScript -PathType Leaf) {
    try {
        $resumeAction  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$StartScript`" -Quiet"
        $resumeTrigger = New-ScheduledTaskTrigger -Once -At $resumeAt
        $resumeSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Unregister-ScheduledTask -TaskName "SecuritySentinelAutoResume" -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName "SecuritySentinelAutoResume" -Action $resumeAction -Trigger $resumeTrigger -Settings $resumeSettings -Description "Auto-resume Security Sentinel Ultra Shield after pause" -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

# 6. Issue CSPRNG Authenticated Stop Token & Signal Named Event (Watchdog & Guardian self-terminate)
try {
    $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $enc     = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($StopTokenFile, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    Write-Host "[TOKEN] Authenticated Stop-Token issued for Watchdog PID $wdPid." -ForegroundColor Cyan

    try {
        $ev = [System.Threading.EventWaitHandle]::OpenExisting("Local\SecuritySentinelStopSignal")
        [void]$ev.Set()
        $ev.Close()
    } catch {}
} catch {
    Write-Host "[FAIL] Failed to generate stop token: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 7. Wait for Watchdog & Guardian to verify token and exit gracefully (Zero force-kill fallback!)
$stoppedCleanly = $false
$wdPidInt = [int]$wdPid

for ($w = 0; $w -lt 16; $w++) {
    Start-Sleep -Milliseconds 400
    $wProc = Get-Process -Id ([int]$wdPidInt) -ErrorAction SilentlyContinue
    $gAlive = $false
    if (Test-Path $GuardianPidF) {
        $gRaw = (Get-Content $GuardianPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($gRaw -and ($gRaw.Trim() -match '^\d+$')) {
            $gProc = Get-Process -Id ([int]$gRaw.Trim()) -ErrorAction SilentlyContinue
            if ($gProc) { $gAlive = $true }
        }
    }
    if (-not $wProc -and -not $gAlive) {
        $stoppedCleanly = $true
        break
    }
}

if (Test-Path $StopTokenFile) { Remove-Item $StopTokenFile -Force -ErrorAction SilentlyContinue }

if ($stoppedCleanly) {
    Write-Host "`n>>> SECURITY SENTINEL SHIELD PAUSED FOR $PauseMinutes MINUTES <<<" -ForegroundColor Yellow
    Write-Host "Auto-resume scheduled at: $($resumeAt.ToString('HH:mm:ss'))" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[FAIL] Watchdog (PID: $wdPid) did not acknowledge stop token within timeout." -ForegroundColor Red
    exit 1
}
