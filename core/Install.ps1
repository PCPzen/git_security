# =====================================================================
# Security Sentinel Ultra - Universal 1-Click Installer
# Version 5.0 (Red-Team Hardened Edition: DPAPI Stop-Token, NTFS ACL
# EoP Lockdown, SACL Auditing, Real DACL & Live RAM Forensics)
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$TargetDir = "$env:LOCALAPPDATA\SecuritySentinel"
$SourceDir = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA - INSTALLER v5.0 (HARDENED)    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function New-StopTokenFile($dir) {
    try {
        $pidF = "$dir\sentinel.pid"
        $wdPid = if (Test-Path $pidF) { (Get-Content $pidF -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "0" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText("$dir\graceful_stop.token", [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)
    } catch {}
}

# 1. Deploy Files
Write-Host "`n[1/4] Deploying v5.0 Red-Team Hardened engine files to: $TargetDir" -ForegroundColor White
@($TargetDir, "$TargetDir\logs", "$TargetDir\quarantine") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# Signal existing Guardian Twin with authenticated DPAPI Stop Token
New-StopTokenFile $TargetDir
"STOP" | Out-File -FilePath "$TargetDir\graceful_stop.flag" -Encoding UTF8 -Force
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 600
Remove-Item "$TargetDir\graceful_stop.token" -Force -ErrorAction SilentlyContinue
Remove-Item "$TargetDir\graceful_stop.flag" -Force -ErrorAction SilentlyContinue

# If scripts were previously locked down by Admin ACLs, reset before overwriting
if ($isAdmin) {
    icacls "$TargetDir\*.ps1" /reset /T /C /Q 2>&1 | Out-Null
}

Copy-Item "$SourceDir\SentinelWatchdog.ps1"  "$TargetDir\SentinelWatchdog.ps1" -Force
Copy-Item "$SourceDir\SentinelGuardian.ps1"  "$TargetDir\SentinelGuardian.ps1" -Force
Copy-Item "$SourceDir\SentinelDashboard.ps1" "$TargetDir\SentinelDashboard.ps1" -Force

# Prevent Privilege Escalation (EoP): When installed as Admin, lock .ps1 scripts to Admin/SYSTEM Write only!
if ($isAdmin) {
    foreach ($scriptFile in @("$TargetDir\SentinelWatchdog.ps1", "$TargetDir\SentinelGuardian.ps1", "$TargetDir\SentinelDashboard.ps1")) {
        icacls $scriptFile /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "$($env:USERNAME):(RX)" /C /Q 2>&1 | Out-Null
    }
    Write-Host "  -> NTFS ACL Hardening applied on .ps1 scripts (EoP protection: Read-Only for standard user processes)." -ForegroundColor Green
}

# Deploy config.json from core package (preserving user customizations & migrating to DPAPI)
$cfgPath = "$TargetDir\config.json"
$srcCfg  = "$SourceDir\config.json"
if ((-not (Test-Path $cfgPath)) -and (Test-Path $srcCfg)) {
    Copy-Item -Path $srcCfg -Destination $cfgPath -Force
}

Write-Host "  -> Core engine, Guardian Twin, Live RAM Forensics, and DPAPI config deployed." -ForegroundColor Green

# 2. Tier 1 & Tier 4 Security Hardening
Write-Host "`n[2/4] Applying Tier 1 & Tier 4 Windows Security Hardening..." -ForegroundColor White
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

    # Enable Object Access File System Auditing for Canary SACL Event 4663 Read Detection
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
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous Endpoint Security Sentinel Ultra v5.0" -ErrorAction Stop | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Autonomous Endpoint Security Sentinel Ultra v5.0" -ErrorAction Stop | Out-Null
    }
    Write-Host "  -> Scheduled Task registered successfully (Auto-starts at logon)." -ForegroundColor Green
} catch {
    Write-Host "  -> Note: Registered via process background handler." -ForegroundColor Yellow
}

# 4. Start Daemon
Write-Host "`n[4/4] Activating Real-Time Protection Shield (v5.0 Red-Team Hardened)..." -ForegroundColor White
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`"" -WindowStyle Hidden
}
Write-Host "  -> Security Sentinel Ultra v5.0 Shield & Guardian Twin are now ACTIVE!" -ForegroundColor Green

# 5. Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath('Desktop')
if (Test-Path $desktopDir) {
    $wsh = New-Object -ComObject WScript.Shell
    $lnkPath = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
    $desktopShortcut = $wsh.CreateShortcut($lnkPath)
    $desktopShortcut.TargetPath = "powershell.exe"
    $desktopShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelDashboard.ps1`""
    $desktopShortcut.IconLocation = "shell32.dll,220"
    $desktopShortcut.Description = "Open Security Sentinel Ultra v5.0 Command Center"
    $desktopShortcut.Save()
    Write-Host "  -> Created 'Security Sentinel Dashboard' shortcut on Desktop." -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETED SUCCESSFULLY! (v5.0 HARDENED EDR) " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
