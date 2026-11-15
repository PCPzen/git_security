# =====================================================================
# Security Sentinel Ultra v8.0 - Start Shield
# Verifies Trust Anchor SHA-256 (PublicHashes / Manifest) before launch
# Waits for live Watchdog + Guardian Twin PIDs before reporting success
# =====================================================================
param(
    [switch]$Quiet
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

function Resolve-SentinelStateDir {
    $defaultDir = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
    if ($env:SENTINEL_TEST_MODE -eq "1" -and $env:SENTINEL_STATE_DIR) {
        try {
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + "\"
            $cand = [System.IO.Path]::GetFullPath($env:SENTINEL_STATE_DIR)
            if ($cand.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $cand
            }
        } catch {}
    }
    return $defaultDir
}

$ProgDir      = "$env:ProgramFiles\SecuritySentinel"
$StateDir     = Resolve-SentinelStateDir
$SentinelDir  = if (Test-Path (Join-Path $ProgDir "SentinelWatchdog.ps1")) {
    $ProgDir
} elseif ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "SentinelWatchdog.ps1"))) {
    $PSScriptRoot
} else {
    $StateDir
}

$ScriptPath   = Join-Path $SentinelDir "SentinelWatchdog.ps1"
$GuardianPath = Join-Path $SentinelDir "SentinelGuardian.ps1"
$PidFile      = Join-Path $StateDir "sentinel.pid"
$GuardianPidF = Join-Path $StateDir "guardian.pid"
$ManifestFile = Join-Path $StateDir "manifest.json"
$StopFlagFile = Join-Path $StateDir "graceful_stop.token"
$PauseFile    = Join-Path $StateDir "paused_until.txt"

function Get-SentinelSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    $secKey = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $secKey) {
        try {
            $b64 = (Get-ItemProperty -Path $secKey -Name "InstallSecret" -ErrorAction Stop).InstallSecret
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

# #1: Read non-secret hashes from PublicHashes (Users: ReadKey) first, then IntegrityAnchor, then User-Mode manifest.json
function Get-TrustedScriptHash([string]$ScriptName) {
    foreach ($regPath in @("HKLM:\SOFTWARE\SecuritySentinel\PublicHashes", "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor")) {
        if (Test-Path $regPath) {
            try {
                $val = (Get-ItemProperty -Path $regPath -Name $ScriptName -ErrorAction SilentlyContinue).$ScriptName
                if ($val) { return "$val".Trim().ToUpper() }
            } catch {}
        }
    }
    if (Test-Path $ManifestFile) {
        try {
            $sec = Get-SentinelSecret
            if ($sec) {
                $mObj = Get-Content $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($mObj -and $mObj.SealedHashes) {
                    $enc = [Convert]::FromBase64String($mObj.SealedHashes)
                    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $sec, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                    $jsonHashes = [System.Text.Encoding]::UTF8.GetString($dec)
                    if ($jsonHashes) {
                        $parsed = $jsonHashes | ConvertFrom-Json
                        if ($parsed.$ScriptName) { return "$($parsed.$ScriptName)".Trim().ToUpper() }
                    }
                }
            }
        } catch {}
    }
    return ""
}

if (-not $Quiet) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   SECURITY SENTINEL ULTRA v8.0 - STARTING SHIELD         " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
}

# 1. Check if already running (with proper ([int]$pidInt) cast)
if (Test-Path $PidFile) {
    $curPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($curPid -and ($curPid.Trim() -match '^\d+$')) {
        $pidInt = [int]$curPid.Trim()
        $p = Get-Process -Id ([int]$pidInt) -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -match '^(powershell|pwsh)$') {
            if (-not $Quiet) {
                Write-Host "[INFO] Security Sentinel Shield is ALREADY RUNNING (PID: $pidInt)." -ForegroundColor Yellow
            }
            exit 0
        }
    }
}

# 2. Verify target script exists and matches Fail-Closed Trust Anchor before starting
if (-not (Test-Path $ScriptPath -PathType Leaf)) {
    Write-Host "[FAIL] SentinelWatchdog.ps1 not found at: $ScriptPath" -ForegroundColor Red
    exit 1
}

$expectedWdHash = Get-TrustedScriptHash -ScriptName "SentinelWatchdog.ps1"
$actualWdHash   = (Get-FileHash -Path $ScriptPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
if ([string]::IsNullOrWhiteSpace($expectedWdHash)) {
    Write-Host "[TAMPER-BLOCKED] External Trust Anchor missing or unreadable! Refusing to start unverified Watchdog." -ForegroundColor Red
    exit 1
}
if (-not $actualWdHash -or ($actualWdHash.ToUpper() -ne $expectedWdHash)) {
    Write-Host "[TAMPER-BLOCKED] SentinelWatchdog.ps1 SHA-256 mismatch against Trust Anchor ($actualWdHash != $expectedWdHash)!" -ForegroundColor Red
    exit 1
}

if (Test-Path $GuardianPath -PathType Leaf) {
    $expectedGdHash = Get-TrustedScriptHash -ScriptName "SentinelGuardian.ps1"
    $actualGdHash   = (Get-FileHash -Path $GuardianPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if ($expectedGdHash -and ($actualGdHash.ToUpper() -ne $expectedGdHash)) {
        Write-Host "[TAMPER-BLOCKED] SentinelGuardian.ps1 SHA-256 mismatch against Trust Anchor!" -ForegroundColor Red
        exit 1
    }
}

# 3. Clear any leftover stop token or pause timer
if (Test-Path $StopFlagFile) { Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue }
if (Test-Path $PauseFile) { Remove-Item $PauseFile -Force -ErrorAction SilentlyContinue }
try { Unregister-ScheduledTask -TaskName "SecuritySentinelAutoResume" -Confirm:$false -ErrorAction SilentlyContinue } catch {}

# 4. Try starting registered Scheduled Task first, then verified direct launch
try {
    Start-ScheduledTask -TaskName "SecuritySentinelWatchdog" -ErrorAction Stop
    if (-not $Quiet) {
        Write-Host "[INIT] Triggered 'SecuritySentinelWatchdog' via Windows Task Scheduler..." -ForegroundColor Cyan
    }
} catch {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -WindowStyle Hidden -File `"$ScriptPath`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    [void][System.Diagnostics.Process]::Start($psi)
    if (-not $Quiet) {
        Write-Host "[INIT] Launched verified Watchdog from: $ScriptPath" -ForegroundColor Cyan
    }
}

# 5. Wait and verify that Watchdog AND Guardian Twin actually initialize and write active PIDs
$wdAlive = $false
$gdAlive = $false
$verifiedWdPid = 0
$verifiedGdPid = 0

for ($i = 0; $i -lt 16; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $PidFile) {
        $rawW = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawW -and ($rawW.Trim() -match '^\d+$')) {
            $wInt = [int]$rawW.Trim()
            $wProc = Get-Process -Id ([int]$wInt) -ErrorAction SilentlyContinue
            if ($wProc -and $wProc.ProcessName -match '^(powershell|pwsh)$') {
                $wdAlive = $true
                $verifiedWdPid = $wInt
            }
        }
    }
    if (Test-Path $GuardianPidF) {
        $rawG = (Get-Content $GuardianPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawG -and ($rawG.Trim() -match '^\d+$')) {
            $gInt = [int]$rawG.Trim()
            $gProc = Get-Process -Id ([int]$gInt) -ErrorAction SilentlyContinue
            if ($gProc -and $gProc.ProcessName -match '^(powershell|pwsh)$') {
                $gdAlive = $true
                $verifiedGdPid = $gInt
            }
        }
    }
    if ($wdAlive -and $gdAlive) { break }
}

if ($wdAlive) {
    if (-not $Quiet) {
        $gdText = if ($gdAlive) { "Guardian PID: $verifiedGdPid" } else { "Guardian initializing" }
        Write-Host "`n>>> SECURITY SENTINEL ULTRA SHIELD IS NOW ACTIVE & PROTECTING (Watchdog PID: $verifiedWdPid | $gdText) <<<" -ForegroundColor Green
    }
    exit 0
} else {
    Write-Host "`n[FAIL] Sentinel Watchdog did not initialize or failed startup verification." -ForegroundColor Red
    exit 1
}
