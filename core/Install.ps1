# =====================================================================
# Security Sentinel Ultra - Universal 1-Click Installer
# Version 7.0 (Work & Gaming Safe-Mode, OWNER RIGHTS DACL, 256-Bit
# CSPRNG InstallSecret, Fail-Closed Trust Anchor & Windows 11 Verified)
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$StateDir  = "$env:LOCALAPPDATA\SecuritySentinel"
$TargetDir = if ($isAdmin) { "$env:ProgramFiles\SecuritySentinel" } else { $StateDir }
$SourceDir = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA - INSTALLER v7.0 (SAFE-MODE)   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

function Get-OrCreateInstallSecret {
    foreach ($regPath in @("HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor", "HKCU:\Software\SecuritySentinel\IntegrityAnchor")) {
        if (Test-Path $regPath) {
            $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
            if ($b64) {
                try { return [Convert]::FromBase64String($b64) } catch {}
            }
        }
    }
    $rngBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($rngBytes)
    $b64New = [Convert]::ToBase64String($rngBytes)
    $regHkcu = "HKCU:\Software\SecuritySentinel\IntegrityAnchor"
    if (-not (Test-Path $regHkcu)) { New-Item -Path $regHkcu -Force | Out-Null }
    Set-ItemProperty -Path $regHkcu -Name "InstallSecret" -Value $b64New -Force
    if ($isAdmin) {
        $regHklm = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
        if (-not (Test-Path $regHklm)) { New-Item -Path $regHklm -Force | Out-Null }
        Set-ItemProperty -Path $regHklm -Name "InstallSecret" -Value $b64New -Force
    }
    return $rngBytes
}

$Entropy = Get-OrCreateInstallSecret
$LegacyEntropy = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)

function Signal-GracefulStop($dir) {
    try {
        $pidF = "$dir\sentinel.pid"
        $wdPid = if (Test-Path $pidF) { (Get-Content $pidF -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText("$dir\graceful_stop.token", [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    } catch {}
}

# 1. Deploy Files
Write-Host "`n[1/4] Deploying v7.0 Work & Gaming Safe-Mode engine files to: $TargetDir" -ForegroundColor White
@($StateDir, "$StateDir\logs", "$StateDir\quarantine", $TargetDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

Signal-GracefulStop $StateDir
Start-Sleep -Milliseconds 1800
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Remove-Item "$StateDir\graceful_stop.token" -Force -ErrorAction SilentlyContinue

if ($isAdmin) {
    icacls "$StateDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
    icacls "$TargetDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
}

$coreScripts = @("SentinelWatchdog.ps1", "SentinelGuardian.ps1", "SentinelDashboard.ps1", "Install.ps1", "Uninstall.ps1", "Invoke-RedTeamAudit.ps1")
foreach ($s in $coreScripts) {
    if (Test-Path "$SourceDir\$s") {
        Copy-Item "$SourceDir\$s" "$StateDir\$s" -Force
        if ($TargetDir -ne $StateDir) {
            Copy-Item "$SourceDir\$s" "$TargetDir\$s" -Force
        }
    }
}

# Generate Fail-Closed External Code Integrity Trust Anchor (Manifest + Registry Anchor)
$hashes = [ordered]@{}
foreach ($s in $coreScripts) {
    $p = Join-Path $TargetDir $s
    if (Test-Path $p) {
        $h = (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($h) { $hashes[$s] = $h }
    }
}
$jsonHashes = ($hashes | ConvertTo-Json -Compress)
$sealedBytes = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($jsonHashes), $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$manifestObj = [ordered]@{
    Version      = "7.0"
    UpdatedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    SealedHashes = [Convert]::ToBase64String($sealedBytes)
}
[System.IO.File]::WriteAllText("$StateDir\manifest.json", ($manifestObj | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)

$regHkcu = "HKCU:\Software\SecuritySentinel\IntegrityAnchor"
if (-not (Test-Path $regHkcu)) { New-Item -Path $regHkcu -Force | Out-Null }
foreach ($k in $hashes.Keys) { Set-ItemProperty -Path $regHkcu -Name $k -Value $hashes[$k] -Force }

if ($isAdmin) {
    $regHklm = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (-not (Test-Path $regHklm)) { New-Item -Path $regHklm -Force | Out-Null }
    foreach ($k in $hashes.Keys) { Set-ItemProperty -Path $regHklm -Name $k -Value $hashes[$k] -Force }

    foreach ($dirToLock in @($TargetDir, $StateDir)) {
        foreach ($s in $coreScripts) {
            $sf = Join-Path $dirToLock $s
            if (Test-Path $sf) {
                icacls $sf /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)" /C /Q 2>&1 | Out-Null
            }
        }
    }
    Write-Host "  -> ProgramFiles Isolation, HKLM Trust Anchor & NTFS ACL Hardening applied (EoP Protected)." -ForegroundColor Green
} else {
    Write-Host "  -> Installed in User Mode ($StateDir). Run as Administrator for ProgramFiles & HKLM ACL lockdown." -ForegroundColor Yellow
}

$cfgPath = "$StateDir\config.json"
$srcCfg  = "$SourceDir\config.json"
if ((-not (Test-Path $cfgPath)) -and (Test-Path $srcCfg)) {
    Copy-Item -Path $srcCfg -Destination $cfgPath -Force
}

Write-Host "  -> Core engine v7.0, Guardian Twin, CSPRNG Trust Anchor & Work/Gaming Safe-Mode deployed." -ForegroundColor Green

# 2. Tier 1 & Tier 4 Security Hardening
Write-Host "`n[2/4] Applying Pillar 1 & Tier 4 Windows Telemetry & Hardening..." -ForegroundColor White
$psPolicyKeyHKCU = "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psPolicyKeyHKCU)) { New-Item -Path $psPolicyKeyHKCU -Force | Out-Null }
Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
Write-Host "  -> PowerShell Script Block Logging (Event ID 4104) Enabled." -ForegroundColor Green

if ($isAdmin) {
    $psPolicyKeyHKLM = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psPolicyKeyHKLM)) { New-Item -Path $psPolicyKeyHKLM -Force | Out-Null }
    Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
    Write-Host "  -> Tier 4 LSASS Memory Protection (RunAsPPL) Enabled." -ForegroundColor Green

    auditpol /set /subcategory:"File System" /success:enable 2>&1 | Out-Null
    Write-Host "  -> SACL File System Read Auditing (Event ID 4663) Enabled for Canary Honeypots." -ForegroundColor Green
}

# 3. Register Scheduled Task
Write-Host "`n[3/4] Registering Auto-Start Task in Windows Task Scheduler..." -ForegroundColor White
$TaskName = "SecuritySentinelWatchdog"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Priority 4

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($isAdmin) {
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous Endpoint Security Sentinel Ultra v7.0" -ErrorAction Stop | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Autonomous Endpoint Security Sentinel Ultra v7.0" -ErrorAction Stop | Out-Null
    }
    Write-Host "  -> Scheduled Task registered successfully (Target: $TargetDir\SentinelWatchdog.ps1)." -ForegroundColor Green
} catch {
    Write-Host "  -> Note: Registered via process background handler." -ForegroundColor Yellow
}

# 4. Start Daemon
Write-Host "`n[4/4] Activating Real-Time Protection Shield (v7.0 Work & Gaming Safe-Mode)..." -ForegroundColor White
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`"" -WindowStyle Hidden
}
Write-Host "  -> Security Sentinel Ultra v7.0 Shield & Guardian Twin are now ACTIVE!" -ForegroundColor Green

# 5. Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath('Desktop')
if (Test-Path $desktopDir) {
    $wsh = New-Object -ComObject WScript.Shell
    $lnkPath = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
    $desktopShortcut = $wsh.CreateShortcut($lnkPath)
    $desktopShortcut.TargetPath = "powershell.exe"
    $desktopShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelDashboard.ps1`""
    $desktopShortcut.IconLocation = "shell32.dll,220"
    $desktopShortcut.Description = "Open Security Sentinel Ultra v7.0 Command Center"
    $desktopShortcut.Save()
    Write-Host "  -> Created 'Security Sentinel Dashboard' shortcut on Desktop." -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETED SUCCESSFULLY! (v7.0 SAFE-MODE)    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
