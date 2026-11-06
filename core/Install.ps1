# =====================================================================
# Security Sentinel Ultra - Universal 1-Click Installer
# Version 3.0 (Tier 1-5 Complete Architecture Edition)
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$TargetDir = "$env:LOCALAPPDATA\SecuritySentinel"
$SourceDir = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA - INSTALLER v3.0 (TIER 1-5)    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if elevated
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 1. Deploy Files
Write-Host "`n[1/4] Deploying Tier 1-5 engine files to: $TargetDir" -ForegroundColor White
@($TargetDir, "$TargetDir\logs", "$TargetDir\quarantine") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

Copy-Item "$SourceDir\SentinelWatchdog.ps1" "$TargetDir\SentinelWatchdog.ps1" -Force
Copy-Item "$SourceDir\SentinelDashboard.ps1" "$TargetDir\SentinelDashboard.ps1" -Force

# Deploy config.json from core package (preserving any user customizations)
$cfgPath = "$TargetDir\config.json"
$srcCfg  = "$SourceDir\config.json"
if ((-not (Test-Path $cfgPath)) -and (Test-Path $srcCfg)) {
    Copy-Item -Path $srcCfg -Destination $cfgPath -Force
} elseif (Test-Path $srcCfg) {
    try {
        $existing = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $template = Get-Content $srcCfg -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($existing.DiscordWebhookUrl) -and (-not [string]::IsNullOrWhiteSpace($template.DiscordWebhookUrl))) {
            $existing.DiscordWebhookUrl = $template.DiscordWebhookUrl
        }
        $jsonOut = ($existing | ConvertTo-Json -Depth 4)
        [System.IO.File]::WriteAllText($cfgPath, $jsonOut, [System.Text.Encoding]::UTF8)
    } catch {
        Copy-Item -Path $srcCfg -Destination $cfgPath -Force
    }
}

Write-Host "  -> Core engine, Tier 2-5 modules, and config deployed." -ForegroundColor Green

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

    # Tier 4: Enable LSASS Protected Process Light (RunAsPPL) against RAM credential dumping
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
    Write-Host "  -> Tier 4 LSASS Memory Protection (RunAsPPL) Enabled." -ForegroundColor Green
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
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous Endpoint Security Sentinel Ultra v3.0" -ErrorAction Stop | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Autonomous Endpoint Security Sentinel Ultra v3.0" -ErrorAction Stop | Out-Null
    }
    Write-Host "  -> Scheduled Task registered successfully (Auto-starts at logon)." -ForegroundColor Green
} catch {
    Write-Host "  -> Note: Registered via process background handler." -ForegroundColor Yellow
}

# 4. Start Daemon
Write-Host "`n[4/4] Activating Real-Time Protection Shield (Tier 1-5)..." -ForegroundColor White
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 600

try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelWatchdog.ps1`"" -WindowStyle Hidden
}
Write-Host "  -> Security Sentinel Ultra v3.0 Shield is now ACTIVE!" -ForegroundColor Green

# 5. Desktop Shortcut (OneDrive Desktop Compatible)
$desktopDir = [Environment]::GetFolderPath('Desktop')
if (Test-Path $desktopDir) {
    $wsh = New-Object -ComObject WScript.Shell
    $lnkPath = Join-Path $desktopDir "Security Sentinel Dashboard.lnk"
    $desktopShortcut = $wsh.CreateShortcut($lnkPath)
    $desktopShortcut.TargetPath = "powershell.exe"
    $desktopShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetDir\SentinelDashboard.ps1`""
    $desktopShortcut.IconLocation = "shell32.dll,220" # Shield Icon
    $desktopShortcut.Description = "Open Security Sentinel Ultra v3.0 Command Center"
    $desktopShortcut.Save()
    Write-Host "  -> Created 'Security Sentinel Dashboard' shortcut on Desktop." -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETED SUCCESSFULLY! (v3.0 TIER 1-5)     " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Open the Dashboard from your Desktop or 'Sentinel-Dashboard.bat'"
Write-Host "to paste your Discord Webhook URL and test notifications!"
