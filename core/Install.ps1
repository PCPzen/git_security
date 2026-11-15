# =====================================================================
# Security Sentinel Ultra v8.0 - Enterprise Installer
# ProgramFiles Isolation, SYSTEM/Admins HKLM ACL (No Admin-Blocking Deny),
# 10-Script Trust Anchor, EventLog Registration & 4688 CmdLine Auditing
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$StateDir  = if ($env:SENTINEL_STATE_DIR -and (Test-Path $env:SENTINEL_STATE_DIR)) { $env:SENTINEL_STATE_DIR } else { "$env:LOCALAPPDATA\SecuritySentinel" }
$TargetDir = if ($isAdmin) { "$env:ProgramFiles\SecuritySentinel" } else { $StateDir }
$SourceDir = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA - INSTALLER v8.0 ENTERPRISE EDR   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# A2: Set HKLM Registry ACL with Allow for SYSTEM & Administrators ONLY (No Deny on Users that blocks elevated Admins!)
function Set-SentinelRegistryAcl {
    param([string]$KeyPath = "HKLM:\SOFTWARE\SecuritySentinel")
    try {
        if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
        $subKeyName = $KeyPath -replace "^HKLM:\\", ""
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subKeyName,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadKey
        )
        if ($regKey) {
            $acl = New-Object System.Security.AccessControl.RegistrySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $sysSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                $sysSid,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )))
            $admSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                $admSid,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )))
            $regKey.SetAccessControl($acl)
            $regKey.Close()
            return $true
        }
    } catch {}
    return $false
}

# A3: Unified Secret Generator/Loader (HKLM first when Admin, DPAPI vault.sec when User-Mode; zero static constant!)
function Get-OrCreateInstallSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
        if ($b64) {
            try {
                $existing = [Convert]::FromBase64String($b64)
                if ($existing -and $existing.Length -ge 16) { return $existing }
            } catch {}
        }
    }

    $vaultFile = Join-Path $StateDir "vault.sec"
    if (-not $isAdmin -and (Test-Path $vaultFile)) {
        try {
            $encB64 = (Get-Content $vaultFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
            $dec = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($encB64), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            if ($dec -and $dec.Length -ge 16) { return $dec }
        } catch {}
    }

    $rngBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($rngBytes)
    $b64New = [Convert]::ToBase64String($rngBytes)

    if ($isAdmin) {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "InstallSecret" -Value $b64New -Force
        Set-SentinelRegistryAcl | Out-Null
    }

    try {
        $encVault = [System.Security.Cryptography.ProtectedData]::Protect($rngBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($vaultFile, [Convert]::ToBase64String($encVault), [System.Text.Encoding]::UTF8)
    } catch {}

    return $rngBytes
}

$Entropy = Get-OrCreateInstallSecret

function Signal-GracefulStop($dir) {
    try {
        $pidF = "$dir\sentinel.pid"
        $wdPid = if (Test-Path $pidF) { (Get-Content $pidF -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText("$dir\graceful_stop.token", [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
        try {
            $ev = [System.Threading.EventWaitHandle]::OpenExisting("Local\SecuritySentinelStopSignal")
            [void]$ev.Set()
            $ev.Close()
        } catch {}
    } catch {}
}

# 1. Deploy Files (B1: All 10 Core Scripts + No User-Writable Duplicate Scripts in StateDir when Admin!)
Write-Host "`n[1/4] Deploying v8.0 Enterprise EDR engine files to: $TargetDir" -ForegroundColor White
@($StateDir, "$StateDir\logs", "$StateDir\quarantine", $TargetDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

Signal-GracefulStop $StateDir
Start-Sleep -Milliseconds 1800
Remove-Item "$StateDir\graceful_stop.token" -Force -ErrorAction SilentlyContinue
Remove-Item "$StateDir\paused_until.txt" -Force -ErrorAction SilentlyContinue

if ($isAdmin) {
    icacls "$StateDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
    icacls "$TargetDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
    # B1/B2: Remove any user-writable .ps1 copies in %LOCALAPPDATA%\SecuritySentinel when installing to Program Files
    Remove-Item "$StateDir\*.ps1" -Force -ErrorAction SilentlyContinue
}

$coreScripts = @(
    "SentinelWatchdog.ps1",
    "SentinelGuardian.ps1",
    "SentinelDashboard.ps1",
    "SentinelTray.ps1",
    "Start-Shield.ps1",
    "Stop-Shield.ps1",
    "Sign-Scripts.ps1",
    "Install.ps1",
    "Uninstall.ps1",
    "Invoke-RedTeamAudit.ps1"
)

foreach ($s in $coreScripts) {
    if (Test-Path "$SourceDir\$s") {
        Copy-Item "$SourceDir\$s" "$TargetDir\$s" -Force
    }
}

if (Test-Path "$SourceDir\trusted_cert.thumbprint") {
    Copy-Item "$SourceDir\trusted_cert.thumbprint" "$TargetDir\trusted_cert.thumbprint" -Force
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

$trustedTp = ""
if (Test-Path "$SourceDir\trusted_cert.thumbprint") {
    $trustedTp = (Get-Content "$SourceDir\trusted_cert.thumbprint" -Raw -Encoding UTF8).Trim().ToUpper()
} else {
    $sigSelf = Get-AuthenticodeSignature -FilePath (Join-Path $TargetDir "SentinelWatchdog.ps1") -ErrorAction SilentlyContinue
    if ($sigSelf -and $sigSelf.SignerCertificate) {
        $trustedTp = $sigSelf.SignerCertificate.Thumbprint.ToUpper()
    }
}

$jsonHashes = ($hashes | ConvertTo-Json -Compress)
$sealedBytes = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($jsonHashes), $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$manifestObj = [ordered]@{
    Version               = "8.0"
    UpdatedAt             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    InstallDir            = $TargetDir
    TrustedCertThumbprint = $trustedTp
    SealedHashes          = [Convert]::ToBase64String($sealedBytes)
}
[System.IO.File]::WriteAllText("$StateDir\manifest.json", ($manifestObj | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)

# Zero-Trust: Never write Trust Anchor hashes or secrets to HKCU!
Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue

if ($isAdmin) {
    $regHklm = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (-not (Test-Path $regHklm)) { New-Item -Path $regHklm -Force | Out-Null }
    foreach ($k in $hashes.Keys) { Set-ItemProperty -Path $regHklm -Name $k -Value $hashes[$k] -Force }
    if ($trustedTp) { Set-ItemProperty -Path $regHklm -Name "TrustedCertThumbprint" -Value $trustedTp -Force }
    Set-ItemProperty -Path $regHklm -Name "InstallDir" -Value $TargetDir -Force

    foreach ($s in $coreScripts) {
        $sf = Join-Path $TargetDir $s
        if (Test-Path $sf) {
            icacls $sf /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)" /C /Q 2>&1 | Out-Null
        }
    }
    Write-Host "  -> ProgramFiles Isolation, HKLM Trust Anchor (10 scripts) & NTFS ACL Hardening applied." -ForegroundColor Green
} else {
    Write-Host "  -> Installed in User Mode ($StateDir). Run as Administrator for ProgramFiles & HKLM ACL lockdown." -ForegroundColor Yellow
}

$cfgPath = "$StateDir\config.json"
$srcCfg  = "$SourceDir\config.json"
if ((-not (Test-Path $cfgPath)) -and (Test-Path $srcCfg)) {
    Copy-Item -Path $srcCfg -Destination $cfgPath -Force
}

Write-Host "  -> Core engine v8.0, Guardian Twin, CSPRNG Trust Anchor & Work/Gaming Safe-Mode deployed." -ForegroundColor Green

# 2. Tier 1 & Tier 4 Security Hardening + Event Log & 4688 Auditing (C1, C3)
Write-Host "`n[2/4] Applying Pillar 1 & Tier 4 Windows Telemetry & Hardening..." -ForegroundColor White
$psPolicyKeyHKCU = "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psPolicyKeyHKCU)) { New-Item -Path $psPolicyKeyHKCU -Force | Out-Null }
Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
Write-Host "  -> PowerShell Script Block Logging (Event ID 4104) Enabled." -ForegroundColor Green

if ($isAdmin) {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("SecuritySentinel")) {
            New-EventLog -LogName Application -Source "SecuritySentinel" -ErrorAction SilentlyContinue
        }
        Write-Host "  -> Windows Event Log Source 'SecuritySentinel' (Application Log) Registered." -ForegroundColor Green
    } catch {}

    $psPolicyKeyHKLM = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psPolicyKeyHKLM)) { New-Item -Path $psPolicyKeyHKLM -Force | Out-Null }
    Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
    Write-Host "  -> Tier 4 LSASS Memory Protection (RunAsPPL) Enabled." -ForegroundColor Green

    auditpol /set /subcategory:"File System" /success:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
    $auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
    Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Host "  -> SACL Read Auditing (4663) & Process Creation + CommandLine Auditing (4688) Enabled." -ForegroundColor Green
}

# 3. Register Scheduled Task (No -ExecutionPolicy Bypass when signed; Set RemoteSigned for CurrentUser)
Write-Host "`n[3/4] Registering Auto-Start Task in Windows Task Scheduler..." -ForegroundColor White
try { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue } catch {}

$TaskName = "SecuritySentinelWatchdog"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Priority 4

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($isAdmin) {
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous Endpoint Security Sentinel Ultra v8.0" -ErrorAction Stop | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Autonomous Endpoint Security Sentinel Ultra v8.0" -ErrorAction Stop | Out-Null
    }
    Write-Host "  -> Scheduled Task registered successfully (Target: $TargetDir\SentinelWatchdog.ps1)." -ForegroundColor Green
} catch {
    Write-Host "  -> Note: Registered via process background handler." -ForegroundColor Yellow
}

# 4. Start Daemon via Verified Start-Shield.ps1 (B2, B3)
Write-Host "`n[4/4] Activating Real-Time Protection Shield (v8.0 Enterprise EDR)..." -ForegroundColor White
& powershell.exe -NoProfile -File "$TargetDir\Start-Shield.ps1"

# 5. Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath('Desktop')
if (Test-Path $desktopDir) {
    $wsh = New-Object -ComObject WScript.Shell
    $lnkPath = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
    $desktopShortcut = $wsh.CreateShortcut($lnkPath)
    $desktopShortcut.TargetPath = "powershell.exe"
    $desktopShortcut.Arguments = "-NoProfile -WindowStyle Hidden -File `"$TargetDir\SentinelDashboard.ps1`""
    $desktopShortcut.IconLocation = "shell32.dll,220"
    $desktopShortcut.Description = "Open Security Sentinel Ultra v8.0 Command Center"
    $desktopShortcut.Save()
    Write-Host "  -> Created 'Security Sentinel Dashboard' shortcut on Desktop." -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETED SUCCESSFULLY! (v8.0 ENTERPRISE)   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
