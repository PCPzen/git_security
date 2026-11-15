# =====================================================================
# Security Sentinel Ultra v8.0 - Enterprise Installer
# ProgramFiles Isolation, Fail-Closed HKLM ACL Verification (Before Secret),
# Zero vault.sec Leak in Admin Mode, PublicHashes Subkey & Safe Hardening
# =====================================================================
param(
    [string]$InstallDir = "",
    [switch]$EnableSystemHardening,
    [switch]$Quiet
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$StateDir  = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
$TargetDir = if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir
} elseif ($isAdmin) {
    "$env:ProgramFiles\SecuritySentinel"
} else {
    $StateDir
}
$SourceDir = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA - INSTALLER v8.0 ENTERPRISE EDR   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# A2 & #4: Set HKLM Registry ACL FIRST and verify by reading back (Fail-Closed!)
function Set-AndVerifySentinelRegistryAcl {
    param(
        [Parameter(Mandatory=$true)][string]$KeyPath,
        [switch]$AllowUsersRead
    )
    if (-not (Test-Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
    }
    $subKeyName = $KeyPath -replace "^HKLM:\\", ""
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $subKeyName,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadKey
    )
    if (-not $regKey) {
        throw "Unable to open registry key for ACL hardening: $KeyPath"
    }
    try {
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $inh  = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $prop = [System.Security.AccessControl.PropagationFlags]::None

        $sysSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $admSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($sysSid, [System.Security.AccessControl.RegistryRights]::FullControl, $inh, $prop, [System.Security.AccessControl.AccessControlType]::Allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($admSid, [System.Security.AccessControl.RegistryRights]::FullControl, $inh, $prop, [System.Security.AccessControl.AccessControlType]::Allow)))

        if ($AllowUsersRead) {
            $usrSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($usrSid, [System.Security.AccessControl.RegistryRights]::ReadKey, $inh, $prop, [System.Security.AccessControl.AccessControlType]::Allow)))
        }
        $regKey.SetAccessControl($acl)
    } finally {
        $regKey.Close()
    }

    # Read back ACL and verify it is strictly protected and has zero Deny rules
    $verifyAcl = Get-Acl -Path $KeyPath
    if (-not $verifyAcl.AreAccessRulesProtected) {
        throw "ACL verification failed on ${KeyPath}: Inheritance protection is not enabled."
    }
    $denyRules = @($verifyAcl.Access | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny })
    if ($denyRules.Count -gt 0) {
        throw "ACL verification failed on ${KeyPath}: Unexpected Deny ACE detected."
    }
    if (-not $AllowUsersRead) {
        $usrSidVal = "S-1-5-32-545"
        $userRules = @($verifyAcl.Access | Where-Object {
            try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $usrSidVal } catch { $false }
        })
        if ($userRules.Count -gt 0) {
            throw "ACL verification failed on ${KeyPath}: BUILTIN\Users must not have access to secret key."
        }
    }
}

# #1 & #4: Unified Secret Generator/Loader
# - In Admin mode: Lock ACL FIRST, verify ACL, write InstallSecret ONLY to HKLM, and DELETE vault.sec!
# - In User mode: Use DPAPI vault.sec (never static constant).
function Get-OrCreateInstallSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

    $vaultFile = Join-Path $StateDir "vault.sec"

    if ($isAdmin) {
        # Remove any user-readable vault.sec so non-elevated processes can NEVER read the Admin secret.
        # If vault.sec existed (e.g., from a legacy install), rotate the HKLM secret so the leaked key is invalidated!
        $hadLeakedVault = $false
        if (Test-Path $vaultFile) {
            $hadLeakedVault = $true
            Remove-Item -Path $vaultFile -Force -ErrorAction Stop
            Remove-Item -Path (Join-Path $StateDir "manifest.json") -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $StateDir "logs\sentinel.tip") -Force -ErrorAction SilentlyContinue
            $oldLog = Join-Path $StateDir "logs\sentinel.log"
            if (Test-Path $oldLog) {
                Move-Item -Path $oldLog -Destination (Join-Path $StateDir "logs\sentinel.pre_rotation_$(Get-Date -Format 'yyyyMMddHHmmss').log") -Force -ErrorAction SilentlyContinue
            }
        }

        $rootKey = "HKLM:\SOFTWARE\SecuritySentinel"
        $secKey  = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
        Set-AndVerifySentinelRegistryAcl -KeyPath $rootKey
        Set-AndVerifySentinelRegistryAcl -KeyPath $secKey

        if (-not $hadLeakedVault) {
            $b64 = (Get-ItemProperty -Path $secKey -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
            if ($b64) {
                try {
                    $existing = [Convert]::FromBase64String($b64)
                    if ($existing -and $existing.Length -ge 16) { return $existing }
                } catch {}
            }
        } else {
            Write-Host "  -> [SECURITY] Legacy vault.sec detected in Admin mode; purged and rotating HKLM InstallSecret." -ForegroundColor Yellow
        }

        $rngBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($rngBytes)
        $rng.Dispose()
        $b64New = [Convert]::ToBase64String($rngBytes)

        Set-ItemProperty -Path $secKey -Name "InstallSecret" -Value $b64New -Force
        return $rngBytes
    } else {
        if (Test-Path $vaultFile) {
            try {
                $encB64 = (Get-Content $vaultFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
                $dec = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($encB64), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                if ($dec -and $dec.Length -ge 16) { return $dec }
            } catch {}
        }

        $rngBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($rngBytes)
        $rng.Dispose()
        $encVault = [System.Security.Cryptography.ProtectedData]::Protect($rngBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($vaultFile, [Convert]::ToBase64String($encVault), [System.Text.Encoding]::UTF8)
        return $rngBytes
    }
}

try {
    $Entropy = Get-OrCreateInstallSecret
} catch {
    Write-Host "[FATAL] Failed to initialize or lock Integrity Anchor secret: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Signal-GracefulStop($dir) {
    try {
        $pidF = "$dir\sentinel.pid"
        if (-not (Test-Path $pidF)) { return }
        $wdPid = (Get-Content $pidF -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($wdPid -notmatch '^\d+$') { return }
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
Start-Sleep -Milliseconds 1200
Remove-Item "$StateDir\graceful_stop.token" -Force -ErrorAction SilentlyContinue
Remove-Item "$StateDir\paused_until.txt" -Force -ErrorAction SilentlyContinue

if ($isAdmin -and ($TargetDir -ne $StateDir)) {
    try { icacls "$StateDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null } catch {}
    try { icacls "$TargetDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null } catch {}
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
    $srcFile = Join-Path $SourceDir $s
    $dstFile = Join-Path $TargetDir $s
    if ((Test-Path $srcFile) -and ($srcFile -ne $dstFile)) {
        Copy-Item $srcFile $dstFile -Force
    }
}

# Generate Fail-Closed External Code Integrity Trust Anchor
$hashes = [ordered]@{}
foreach ($s in $coreScripts) {
    $p = Join-Path $TargetDir $s
    if (Test-Path $p) {
        $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash
        if ($h) { $hashes[$s] = $h }
    }
}

# #9: Only pin TrustedCertThumbprint if SentinelWatchdog.ps1 actually has a VALID Authenticode signature!
$trustedTp = ""
$wdTarget = Join-Path $TargetDir "SentinelWatchdog.ps1"
$sigSelf = Get-AuthenticodeSignature -FilePath $wdTarget -ErrorAction SilentlyContinue
if ($sigSelf -and $sigSelf.Status -eq 'Valid' -and $sigSelf.SignerCertificate) {
    $actualTp = $sigSelf.SignerCertificate.Thumbprint.ToUpper()
    $tpFileSrc = Join-Path $SourceDir "trusted_cert.thumbprint"
    if (Test-Path $tpFileSrc) {
        $fileTp = (Get-Content $tpFileSrc -Raw -Encoding UTF8).Trim().ToUpper()
        if ($fileTp -eq $actualTp) {
            $trustedTp = $actualTp
            [System.IO.File]::WriteAllText((Join-Path $TargetDir "trusted_cert.thumbprint"), $trustedTp, [System.Text.Encoding]::UTF8)
        } else {
            Write-Host "  [WARN] trusted_cert.thumbprint mismatch against actual Watchdog signature; using verified signer thumbprint." -ForegroundColor Yellow
            $trustedTp = $actualTp
        }
    } else {
        $trustedTp = $actualTp
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

Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue

if ($isAdmin) {
    # #1: Store non-secret script hashes in PublicHashes (Users: ReadKey) and keep secret ONLY in IntegrityAnchor (SYSTEM/Admins only)
    $pubKey = "HKLM:\SOFTWARE\SecuritySentinel\PublicHashes"
    Set-AndVerifySentinelRegistryAcl -KeyPath $pubKey -AllowUsersRead
    foreach ($k in $hashes.Keys) { Set-ItemProperty -Path $pubKey -Name $k -Value $hashes[$k] -Force }
    if ($trustedTp) { Set-ItemProperty -Path $pubKey -Name "TrustedCertThumbprint" -Value $trustedTp -Force }
    Set-ItemProperty -Path $pubKey -Name "InstallDir" -Value $TargetDir -Force

    foreach ($s in $coreScripts) {
        $sf = Join-Path $TargetDir $s
        if (Test-Path $sf) {
            icacls $sf /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)" /C /Q 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to apply NTFS ACL to $sf"
            }
        }
    }
    Write-Host "  -> Target Isolation ($TargetDir), HKLM IntegrityAnchor + PublicHashes & NTFS ACL Hardening verified." -ForegroundColor Green
} else {
    Write-Host "  -> Installed in User Mode ($TargetDir). Run as Administrator for HKLM ACL & PublicHashes lockdown." -ForegroundColor Yellow
}

$cfgPath = "$StateDir\config.json"
$srcCfg  = "$SourceDir\config.json"
if ((-not (Test-Path $cfgPath)) -and (Test-Path $srcCfg)) {
    Copy-Item -Path $srcCfg -Destination $cfgPath -Force
}

Write-Host "  -> Core engine v8.0, Guardian Twin, CSPRNG Trust Anchor & Work/Gaming Safe-Mode deployed." -ForegroundColor Green

# 2. Tier 1 & Tier 4 Security Hardening + Event Log & 4688 Auditing (C1, C3, #8)
Write-Host "`n[2/4] Applying Pillar 1 & Tier 4 Windows Telemetry..." -ForegroundColor White
try {
    $psPolicyKeyHKCU = "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psPolicyKeyHKCU)) { New-Item -Path $psPolicyKeyHKCU -Force | Out-Null }
    Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $psPolicyKeyHKCU -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
    Write-Host "  -> PowerShell Script Block Logging (Event ID 4104) Enabled." -ForegroundColor Green
} catch {
    Write-Host "  -> [WARN] Could not set HKCU ScriptBlockLogging policy: $($_.Exception.Message)" -ForegroundColor Yellow
}

if ($isAdmin) {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("SecuritySentinel")) {
            New-EventLog -LogName Application -Source "SecuritySentinel"
        }
        Write-Host "  -> Windows Event Log Source 'SecuritySentinel' (Application Log) Registered." -ForegroundColor Green
    } catch {
        Write-Host "  -> [WARN] Event Log source registration note: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $applyHardening = $EnableSystemHardening.IsPresent
    if (-not $applyHardening -and (-not $Quiet)) {
        $ansHard = Read-Host "`nEnable OS-wide RunAsPPL (LSASS protection, requires reboot & may affect unsigned drivers) and Audit Policy (4663/4688)? [y/N]"
        if ($ansHard -match '^(y|yes)$') { $applyHardening = $true }
    }

    if ($applyHardening) {
        try {
            $psPolicyKeyHKLM = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            if (-not (Test-Path $psPolicyKeyHKLM)) { New-Item -Path $psPolicyKeyHKLM -Force | Out-Null }
            Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $psPolicyKeyHKLM -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
            Write-Host "  -> Tier 4 LSASS Memory Protection (RunAsPPL) Enabled (Reboot required)." -ForegroundColor Green

            auditpol /set /subcategory:"File System" /success:enable 2>&1 | Out-Null
            auditpol /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
            $auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
            Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
            Write-Host "  -> SACL Read Auditing (4663) & Process Creation + CommandLine Auditing (4688) Enabled." -ForegroundColor Green
        } catch {
            Write-Host "  -> [WARN] OS Hardening notice: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  -> Skipped global RunAsPPL / Audit Policy (pass -EnableSystemHardening to enable)." -ForegroundColor DarkGray
    }
}

# 3. Register Scheduled Task (Never modify or downgrade user ExecutionPolicy)
Write-Host "`n[3/4] Registering Auto-Start Task in Windows Task Scheduler..." -ForegroundColor White
try {
    $curPol = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
    if ($curPol -eq "Restricted") {
        Write-Host "  -> [WARN] CurrentUser ExecutionPolicy is 'Restricted'; local unsigned scripts may be blocked." -ForegroundColor Yellow
    } else {
        Write-Host "  -> Preserved existing CurrentUser ExecutionPolicy: $curPol" -ForegroundColor DarkGray
    }
} catch {}

$TaskName = "SecuritySentinelWatchdog"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Priority 4

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($isAdmin) {
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous Endpoint Security Sentinel Ultra v8.0" | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Autonomous Endpoint Security Sentinel Ultra v8.0" | Out-Null
    }
    Write-Host "  -> Scheduled Task registered successfully (Target: $TargetDir\SentinelWatchdog.ps1)." -ForegroundColor Green
} catch {
    Write-Host "  -> [WARN] Scheduled Task registration failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. Start Daemon via Verified Start-Shield.ps1 (B2, B3)
Write-Host "`n[4/4] Activating Real-Time Protection Shield (v8.0 Enterprise EDR)..." -ForegroundColor White
& powershell.exe -NoProfile -File "$TargetDir\Start-Shield.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Shield failed startup verification during installation!" -ForegroundColor Red
    exit 1
}

# 5. Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath('Desktop')
if ($desktopDir -and (Test-Path $desktopDir)) {
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $lnkPath = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
        $desktopShortcut = $wsh.CreateShortcut($lnkPath)
        $desktopShortcut.TargetPath = "powershell.exe"
        $desktopShortcut.Arguments = "-NoProfile -WindowStyle Hidden -File `"$TargetDir\SentinelDashboard.ps1`""
        $desktopShortcut.IconLocation = "shell32.dll,220"
        $desktopShortcut.Description = "Open Security Sentinel Ultra v8.0 Command Center"
        $desktopShortcut.Save()
        Write-Host "  -> Created 'Security Sentinel Dashboard' shortcut on Desktop." -ForegroundColor Green
    } catch {}
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETED SUCCESSFULLY! (v8.0 ENTERPRISE)   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
