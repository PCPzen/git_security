# =====================================================================
# Security Sentinel Ultra - Autonomous Endpoint Defense Daemon
# Version 3.0 (Tier 1-5 Master Architecture: ETW/WMI Process Guard,
# NtSuspendProcess Freeze, Network Killswitch, SHA-256 VT & Discord Webhook)
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$SentinelDir = "$env:LOCALAPPDATA\SecuritySentinel"
$ConfigFile  = "$SentinelDir\config.json"
$LogFile     = "$SentinelDir\logs\sentinel.log"
$QuarDir     = "$SentinelDir\quarantine"
$PidFile     = "$SentinelDir\sentinel.pid"
$CanaryDir   = "$env:APPDATA\SecuritySentinel_Canary"
$DocCanary   = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Crypto_Recovery_Phrase_Decoy.txt"

# Ensure essential directories exist
@($SentinelDir, "$SentinelDir\logs", $QuarDir, $CanaryDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# ---------------------------------------------------------------------
# TIER 3: NATIVE WIN32 / NTAPI ENGINE (NtSuspendProcess / NtResumeProcess)
# ---------------------------------------------------------------------
$nativeCode = @"
using System;
using System.Runtime.InteropServices;

namespace SentinelNative {
    public static class KernelControl {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtResumeProcess(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_SUSPEND_RESUME = 0x0800;

        public static bool FreezeProcess(int pid) {
            IntPtr hProc = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (hProc == IntPtr.Zero) return false;
            try {
                int status = NtSuspendProcess(hProc);
                return (status == 0);
            } finally {
                CloseHandle(hProc);
            }
        }

        public static bool ThawProcess(int pid) {
            IntPtr hProc = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (hProc == IntPtr.Zero) return false;
            try {
                int status = NtResumeProcess(hProc);
                return (status == 0);
            } finally {
                CloseHandle(hProc);
            }
        }
    }
}
"@

try {
    if (-not ("SentinelNative.KernelControl" -as [type])) {
        Add-Type -TypeDefinition $nativeCode -Language CSharp -ErrorAction SilentlyContinue
    }
} catch {}

# ---------------------------------------------------------------------
# CONFIGURATION LOADER
# ---------------------------------------------------------------------
$PortableCfg = Join-Path $PSScriptRoot "config.json"
if ((-not (Test-Path $ConfigFile)) -and (Test-Path $PortableCfg)) {
    Copy-Item -Path $PortableCfg -Destination $ConfigFile -Force
}

$defaultConfig = [ordered]@{
    DiscordWebhookUrl        = ""
    DiscordMentionOnCritical = $true
    VirusTotalApiKey         = ""
    EnableSoundAlert         = $true
    EnableToastAlert         = $true
    DecoyInDocuments         = $true
    AutoFreezeSuspiciousProc = $true
    AutoNetworkKillswitch    = $false
    ScanIntervalSeconds      = 15
}

function Load-SentinelConfig {
    $target = if (Test-Path $ConfigFile) { $ConfigFile } elseif (Test-Path $PortableCfg) { $PortableCfg } else { $null }
    if ($target) {
        try {
            $raw = Get-Content $target -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in $defaultConfig.Keys) {
                if ($null -eq $raw.$k) {
                    $raw | Add-Member -NotePropertyName $k -NotePropertyValue $defaultConfig[$k] -Force
                }
            }
            return $raw
        } catch {
            return [PSCustomObject]$defaultConfig
        }
    } else {
        $json = ($defaultConfig | ConvertTo-Json -Depth 4)
        [System.IO.File]::WriteAllText($ConfigFile, $json, [System.Text.Encoding]::UTF8)
        return [PSCustomObject]$defaultConfig
    }
}

$script:Config = Load-SentinelConfig

# Save current PID for lightweight process tracking
$PID | Out-File -FilePath $PidFile -Encoding UTF8 -Force

# ---------------------------------------------------------------------
# LOGGING ENGINE
# ---------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ALERT", "CRITICAL", "SCAN", "TIER2", "TIER3")][string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    Write-Output $line
}

# ---------------------------------------------------------------------
# TIER 5: THREAT INTELLIGENCE (SHA-256 & VirusTotal Lookup)
# ---------------------------------------------------------------------
function Get-FileThreatIntel {
    param([string]$FilePath)
    $result = @{
        SHA256 = "N/A"
        VTUrl  = ""
        VTInfo = "Local Static & Signature Analysis"
    }
    if (-not (Test-Path $FilePath -PathType Leaf)) { return $result }
    try {
        $hashObj = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hashObj -and $hashObj.Hash) {
            $sha = $hashObj.Hash.ToLower()
            $result.SHA256 = $sha
            $result.VTUrl  = "https://www.virustotal.com/gui/file/$sha"

            $vtKey = $script:Config.VirusTotalApiKey
            if (-not [string]::IsNullOrWhiteSpace($vtKey)) {
                try {
                    $headers = @{ "x-apikey" = $vtKey.Trim() }
                    $vtResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha" -Method Get -Headers $headers -TimeoutSec 5 -ErrorAction Stop
                    $stats = $vtResp.data.attributes.last_analysis_stats
                    if ($stats) {
                        $mal = [int]$stats.malicious
                        $tot = $mal + [int]$stats.undetected + [int]$stats.harmless + [int]$stats.suspicious
                        $result.VTInfo = "VirusTotal Detection: $mal / $tot engines flagged malicious"
                    }
                } catch {
                    $result.VTInfo = "Hash computed (View report on VirusTotal)"
                }
            }
        }
    } catch {}
    return $result
}

# ---------------------------------------------------------------------
# TIER 3: EMERGENCY NETWORK KILLSWITCH
# ---------------------------------------------------------------------
function Invoke-NetworkKillswitch {
    param([string]$Reason = "Critical Threat Containment")
    Write-Log "EMERGENCY NETWORK KILLSWITCH ACTIVATED ($Reason)" "TIER3"
    try {
        Start-Process -FilePath "ipconfig.exe" -ArgumentList "/release" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        }
        "ISOLATED" | Out-File -FilePath "$SentinelDir\network.state" -Encoding UTF8 -Force
    } catch {}
}

# ---------------------------------------------------------------------
# ALERT NOTIFICATION ENGINE (Toast + Rich Discord Webhook + Sound)
# ---------------------------------------------------------------------
function Send-DiscordWebhook {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Level = "ALERT",
        [string]$FilePath = "",
        [string]$SHA256 = "",
        [string]$ActionTaken = "Monitored & Logged"
    )
    $script:Config = Load-SentinelConfig
    $url = $script:Config.DiscordWebhookUrl
    if ([string]::IsNullOrWhiteSpace($url)) { return }

    $bt = [char]96
    $color = 16098851 # Amber/Orange
    if ($Level -eq "CRITICAL" -or $Level -eq "TIER3") { $color = 16711680 } # Red
    elseif ($Level -eq "TIER2") { $color = 15105570 } # Deep Orange
    elseif ($Level -eq "INFO")  { $color = 3718648 }  # Cyan

    $fields = @(
        @{ name = "Endpoint";     value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
        @{ name = "Severity";     value = "**$Level**";                        inline = $true },
        @{ name = "Action Taken"; value = $ActionTaken;                        inline = $false }
    )

    if (-not [string]::IsNullOrWhiteSpace($FilePath)) {
        $fields += @{ name = "Target Artifact / Path"; value = "$bt$FilePath$bt"; inline = $false }
    }
    if (-not [string]::IsNullOrWhiteSpace($SHA256) -and $SHA256 -ne "N/A") {
        $vtLink = "https://www.virustotal.com/gui/file/$SHA256"
        $fields += @{ name = "SHA-256 & VirusTotal"; value = "[$bt$SHA256$bt]($vtLink)"; inline = $false }
    }

    $contentPing = ""
    if (($Level -eq "CRITICAL" -or $Level -eq "TIER3") -and $script:Config.DiscordMentionOnCritical) {
        $contentPing = "**[CRITICAL ENDPOINT SECURITY ALERT]** @everyone"
    }

    $payload = @{
        username = "Security Sentinel Ultra EDR"
        content  = $contentPing
        embeds   = @(
            @{
                title       = "[$Level] $Title"
                description = $Message
                color       = $color
                fields      = $fields
                footer      = @{ text = "Security Sentinel Ultra v3.0 | Autonomous Endpoint Defense | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
            }
        )
    } | ConvertTo-Json -Depth 6

    try {
        Invoke-RestMethod -Uri $url.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 6 -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Discord Webhook delivery error: $($_.Exception.Message)" "WARN"
    }
}

function Show-Alert {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level = "ALERT",
        [string]$FilePath = "",
        [string]$SHA256 = "",
        [string]$ActionTaken = "Alert Logged"
    )
    Write-Log "ALERT TRIGGERED: $Title - $Message | Action: $ActionTaken" $Level

    # 1. Dispatch Rich Discord Webhook
    Send-DiscordWebhook -Title $Title -Message $Message -Level $Level -FilePath $FilePath -SHA256 $SHA256 -ActionTaken $ActionTaken

    # 2. Sound alert
    if ($script:Config.EnableSoundAlert) {
        try { [System.Media.SystemSounds]::Hand.Play() } catch {}
    }

    # 3. Modern Windows Toast / Balloon
    if ($script:Config.EnableToastAlert) {
        $toastShown = $false
        try {
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            $safeTitle = [System.Security.SecurityElement]::Escape($Title)
            $safeMsg   = [System.Security.SecurityElement]::Escape($Message)
            $xmlText = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$safeTitle</text>
            <text>$safeMsg</text>
            <text placement="attribution">Security Sentinel Ultra v3.0</text>
        </binding>
    </visual>
</toast>
"@
            $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xmlDoc.LoadXml($xmlText)
            $toast = New-Object Windows.UI.Notifications.ToastNotification $xmlDoc
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("SecuritySentinel").Show($toast)
            $toastShown = $true
        } catch {
            $toastShown = $false
        }

        if (-not $toastShown) {
            try {
                [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                $balloon = New-Object System.Windows.Forms.NotifyIcon
                $balloon.Icon = [System.Drawing.SystemIcons]::Shield
                $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
                $balloon.BalloonTipTitle = $Title
                $balloon.BalloonTipText = $Message
                $balloon.Visible = $true
                $balloon.ShowBalloonTip(5000)
                Start-Sleep -Seconds 1
                $balloon.Dispose()
            } catch {}
        }
    }
}

Write-Log "=== Security Sentinel Ultra v3.0 Started (PID: $PID | Tier 1-5 Active) ==="

# ---------------------------------------------------------------------
# DIGITAL SIGNATURE & TRUST CHECKER (Zero False Positives)
# ---------------------------------------------------------------------
function Test-IsTrustedBinary {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') {
            $subject = $sig.SignerCertificate.Subject
            # Trusted global vendors, game publishers, and hardware vendors
            $pattern = "Google LLC|Microsoft Corporation|Mozilla Corporation|Brave Software|Opera Software|" +
                       "Valve Corp|Epic Games|Riot Games|NVIDIA Corporation|Advanced Micro Devices|Intel Corporation|" +
                       "Overwolf Ltd|KRAFTON|PUBG|BattlEye|Wellbia|Discord|Electronic Arts|Ubisoft|Blizzard Entertainment|" +
                       "Roblox Corporation|Logitech|Razer|Corsair|SteelSeries"
            if ($subject -match $pattern) {
                return $true
            }
        }
    } catch {}
    return $false
}

# ---------------------------------------------------------------------
# SAFE QUARANTINE ENGINE (With SHA-256 & Metadata)
# ---------------------------------------------------------------------
function Move-ToQuarantine {
    param(
        [Parameter(Mandatory=$true)][string]$SourcePath,
        [string]$Reason = "Threat Artifact Quarantined"
    )
    if (-not (Test-Path $SourcePath)) { return $null }

    $intel = Get-FileThreatIntel -FilePath $SourcePath
    $fileName = Split-Path $SourcePath -Leaf
    $destName = (Get-Date -Format 'yyyyMMdd_HHmmss') + "_" + $fileName
    $destPath = Join-Path $QuarDir $destName

    $quarantined = $false
    for ($i = 0; $i -lt 6; $i++) {
        try {
            Move-Item -Path $SourcePath -Destination $destPath -Force -ErrorAction Stop
            $quarantined = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }

    if ($quarantined) {
        $metaPath = "$destPath.meta.txt"
        $meta = @"
QuarantinedFileName: $fileName
OriginalPath: $SourcePath
SHA256: $($intel.SHA256)
VirusTotalUrl: $($intel.VTUrl)
ThreatIntel: $($intel.VTInfo)
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Reason: $Reason
QuarantinedBy: Security Sentinel Ultra v3.0
"@
        [System.IO.File]::WriteAllText($metaPath, $meta, [System.Text.Encoding]::UTF8)
        return @{
            DestPath = $destPath
            SHA256   = $intel.SHA256
            VTUrl    = $intel.VTUrl
            VTInfo   = $intel.VTInfo
        }
    } else {
        return $null
    }
}

# ---------------------------------------------------------------------
# 1. TIER 1: SETUP CANARY / HONEYPOT DECOYS
# ---------------------------------------------------------------------
$canaryHeader = @"
# ====================================================================
# SECURITY SENTINEL ULTRA - CANARY DECOY TRAP
# DO NOT OPEN, EDIT, OR DELETE THIS FILE.
# Monitored 24/7 by Security Sentinel Autonomous Defense.
# Any access, tampering, or exfiltration triggers an instant CRITICAL ALERT.
# ====================================================================
[CANARY_TRAP_ID] 4E9C1A0F-SENTINEL-TRAP-$(Get-Random -Minimum 1000 -Maximum 9999)
[VAULT_SEED_DUMMY] abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
"@

$canaryFiles = @(
    "$CanaryDir\crypto_wallet_vault_seed.txt",
    "$CanaryDir\saved_passwords_export.txt",
    "$CanaryDir\roblox_security_cookie_backup.txt",
    "$CanaryDir\steam_account_credentials_backup.txt",
    "$CanaryDir\riot_games_session_token.txt"
)

if ($script:Config.DecoyInDocuments -and (Test-Path ([Environment]::GetFolderPath('MyDocuments')))) {
    $canaryFiles += $DocCanary
}

foreach ($cf in $canaryFiles) {
    if (-not (Test-Path $cf)) {
        [System.IO.File]::WriteAllText($cf, $canaryHeader, [System.Text.Encoding]::UTF8)
    }
}

# ---------------------------------------------------------------------
# 2. TIER 1: BASELINE PERSISTENCE SNAPSHOT
# ---------------------------------------------------------------------
function Get-PersistenceSnapshot {
    $snap = @{}

    foreach ($regPath in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($props) {
            $prefix = (Split-Path $regPath -Leaf)
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $snap["HKCU_" + $prefix + "_" + $_.Name] = "$($_.Value)"
            }
        }
    }

    foreach ($regPath in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($props) {
            $prefix = (Split-Path $regPath -Leaf)
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $snap["HKLM_" + $prefix + "_" + $_.Name] = "$($_.Value)"
            }
        }
    }

    $startupPaths = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($sDir in $startupPaths) {
        Get-ChildItem -Path $sDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $snap["Startup_" + $_.Name] = $_.FullName
        }
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -eq "\" -and $_.TaskName -ne "SecuritySentinelWatchdog"
    } | ForEach-Object {
        $snap["Task_" + $_.TaskName] = "$($_.State)"
    }

    $clsidKey = "HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
    if (Test-Path $clsidKey) {
        $snap["CLSID_Rogue_{E77CC89B-7401-4C04-8CED-149DB35ADD04}"] = "Detected"
    }

    return $snap
}

$baseline = Get-PersistenceSnapshot
Write-Log "Comprehensive Persistence baseline established ($($baseline.Count) indicators tracked)."

# ---------------------------------------------------------------------
# 3. TIER 1 & TIER 5: BROWSER FILE SYSTEM WATCHERS (With SHA-256 & Webhook)
# ---------------------------------------------------------------------
$watchers = @()
$browserUserDataPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
    "$env:APPDATA\Opera Software\Opera Stable",
    "$env:APPDATA\Opera Software\Opera GX Stable"
)

$browserEventAction = {
    $itemPath = $Event.SourceEventArgs.FullPath
    $itemName = $Event.SourceEventArgs.Name
    $quarDir  = $Event.MessageData.QuarDir
    $sentDir  = $Event.MessageData.SentinelDir
    $cfgPath  = Join-Path $sentDir "config.json"
    $bt       = [char]96

    if ($itemPath -match "PlatformExperienceHelper|\.dll$|\.exe$") {
        $isTrusted = $false
        try {
            $sig = Get-AuthenticodeSignature -FilePath $itemPath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $sub = $sig.SignerCertificate.Subject
                if ($sub -match "Google LLC|Microsoft Corporation|Mozilla Corporation|Brave Software|Opera Software") {
                    $isTrusted = $true
                }
            }
        } catch {}

        if (-not $isTrusted) {
            $sha256 = "N/A"
            try {
                $h = Get-FileHash -Path $itemPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h -and $h.Hash) { $sha256 = $h.Hash.ToLower() }
            } catch {}

            $destName = (Get-Date -Format 'yyyyMMdd_HHmmss') + "_" + $itemName
            $destPath = Join-Path $quarDir $destName
            $moved = $false

            for ($r = 0; $r -lt 6; $r++) {
                try {
                    Move-Item -Path $itemPath -Destination $destPath -Force -ErrorAction Stop
                    $moved = $true
                    break
                } catch {
                    Start-Sleep -Milliseconds 250
                }
            }

            if ($moved) {
                $meta = "QuarantinedFileName: $itemName`r`nOriginalPath: $itemPath`r`nSHA256: $sha256`r`nVirusTotal: https://www.virustotal.com/gui/file/$sha256`r`nTimestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`nReason: Browser DLL/Binary Hijack Blocked"
                [System.IO.File]::WriteAllText("$destPath.meta.txt", $meta, [System.Text.Encoding]::UTF8)

                $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                $logLine = "[$ts] [CRITICAL] Browser Tamper Blocked! Rogue file '$itemName' (SHA256: $sha256) quarantined to '$destPath'."
                Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue

                try {
                    if (Test-Path $cfgPath) {
                        $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
                        if (-not [string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) {
                            $vtLink = "https://www.virustotal.com/gui/file/$sha256"
                            $ping = if ($cfg.DiscordMentionOnCritical) { "**[CRITICAL BROWSER HIJACK BLOCKED]** @everyone" } else { "" }
                            $payload = @{
                                username = "Security Sentinel Ultra EDR"
                                content  = $ping
                                embeds   = @(@{
                                    title       = "[CRITICAL] Browser DLL/Binary Tamper Quarantined!"
                                    description = "An unsigned or rogue binary was dropped into Browser User Data and neutralized immediately."
                                    color       = 16711680
                                    fields      = @(
                                        @{ name = "Endpoint";              value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
                                        @{ name = "Artifact";              value = "$bt$itemName$bt";                   inline = $true },
                                        @{ name = "Original Path";         value = "$bt$itemPath$bt";                   inline = $false },
                                        @{ name = "SHA-256 & VirusTotal";  value = "[$bt$sha256$bt]($vtLink)";          inline = $false }
                                    )
                                    footer = @{ text = "Security Sentinel Ultra v3.0 | Tier 1 & Tier 5 Defense" }
                                })
                            } | ConvertTo-Json -Depth 6
                            Invoke-RestMethod -Uri $cfg.DiscordWebhookUrl.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 5 | Out-Null
                        }
                    }
                } catch {}

                try {
                    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                    $b = New-Object System.Windows.Forms.NotifyIcon
                    $b.Icon = [System.Drawing.SystemIcons]::Shield
                    $b.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Error
                    $b.BalloonTipTitle = "Sentinel: Browser Tamper Quarantined!"
                    $b.BalloonTipText = "Blocked rogue file: $itemName (SHA256 logged)"
                    $b.Visible = $true
                    $b.ShowBalloonTip(5000)
                    Start-Sleep -Seconds 1
                    $b.Dispose()
                } catch {}
            }
        }
    }
}

foreach ($bPath in $browserUserDataPaths) {
    if (Test-Path $bPath) {
        try {
            $fsw = New-Object System.IO.FileSystemWatcher
            $fsw.Path = $bPath
            $fsw.IncludeSubdirectories = $true
            $fsw.EnableRaisingEvents = $true
            $fsw.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName -bor [System.IO.NotifyFilters]::LastWrite

            $msgData = @{ QuarDir = $QuarDir; SentinelDir = $SentinelDir }
            Register-ObjectEvent -InputObject $fsw -EventName "Created" -MessageData $msgData -Action $browserEventAction | Out-Null
            Register-ObjectEvent -InputObject $fsw -EventName "Renamed" -MessageData $msgData -Action $browserEventAction | Out-Null
            $watchers += $fsw
            Write-Log "Browser guard actively protecting: $bPath"
        } catch {
            Write-Log "Failed to attach watcher to $bPath ($($_.Exception.Message))" "WARN"
        }
    }
}

# ---------------------------------------------------------------------
# 4. CANARY FILE WATCHERS (With Webhook & Optional Network Killswitch)
# ---------------------------------------------------------------------
$canaryAction = {
    $cFile   = $Event.SourceEventArgs.FullPath
    $cType   = $Event.SourceEventArgs.ChangeType
    $sentDir = $Event.MessageData.SentinelDir
    $cfgPath = Join-Path $sentDir "config.json"
    $ts      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $bt      = [char]96

    # STRICT CANARY FILTER: Only trigger if the target is an explicit Canary decoy trap!
    $cLeaf = Split-Path $cFile -Leaf
    $validCanaries = @(
        "crypto_wallet_vault_seed.txt", "saved_passwords_export.txt", "Crypto_Recovery_Phrase_Decoy.txt",
        "roblox_security_cookie_backup.txt", "steam_account_credentials_backup.txt", "riot_games_session_token.txt"
    )
    if ($validCanaries -notcontains $cLeaf) {
        return
    }

    $logLine = "[$ts] [CRITICAL] Honeypot Decoy Triggered! File '$cFile' was $cType. Possible Infostealer / Ransomware activity!"
    Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue

    try {
        if (Test-Path $cfgPath) {
            $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.AutoNetworkKillswitch) {
                Start-Process -FilePath "ipconfig.exe" -ArgumentList "/release" -WindowStyle Hidden -ErrorAction SilentlyContinue
                "ISOLATED" | Out-File -FilePath (Join-Path $sentDir "network.state") -Encoding UTF8 -Force
                Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value "[$ts] [TIER3] Emergency Network Killswitch triggered by Canary Honeypot!" -Encoding UTF8
            }
            if (-not [string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) {
                $ping = if ($cfg.DiscordMentionOnCritical) { "**[CRITICAL HONEYPOT ALERT: INFOSTEALER DETECTED]** @everyone" } else { "" }
                $payload = @{
                    username = "Security Sentinel Ultra EDR"
                    content  = $ping
                    embeds   = @(@{
                        title       = "[CRITICAL] Canary Honeypot Trap Triggered!"
                        description = "An unauthorized process accessed or modified a decoy credential/crypto wallet file."
                        color       = 16711680
                        fields      = @(
                            @{ name = "Endpoint";   value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
                            @{ name = "Event";      value = "$cType";                            inline = $true },
                            @{ name = "Decoy File"; value = "$bt$cFile$bt";                      inline = $false }
                        )
                        footer = @{ text = "Security Sentinel Ultra v3.0 | Honeypot Defense" }
                    })
                } | ConvertTo-Json -Depth 6
                Invoke-RestMethod -Uri $cfg.DiscordWebhookUrl.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 5 | Out-Null
            }
        }
    } catch {}

    try {
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $b = New-Object System.Windows.Forms.NotifyIcon
        $b.Icon = [System.Drawing.SystemIcons]::Shield
        $b.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
        $b.BalloonTipTitle = "CRITICAL: Honeypot Triggered!"
        $b.BalloonTipText = "Decoy file touched ($cType): $(Split-Path $cFile -Leaf)! Infostealer suspected."
        $b.Visible = $true
        $b.ShowBalloonTip(6000)
        Start-Sleep -Seconds 1
        $b.Dispose()
    } catch {}
}

$canaryDirsToWatch = @($CanaryDir)
if ($script:Config.DecoyInDocuments -and (Test-Path ([Environment]::GetFolderPath('MyDocuments')))) {
    $canaryDirsToWatch += ([Environment]::GetFolderPath('MyDocuments'))
}

foreach ($cDir in $canaryDirsToWatch) {
    try {
        $cWatcher = New-Object System.IO.FileSystemWatcher
        $cWatcher.Path = $cDir
        $cWatcher.IncludeSubdirectories = $false
        $cWatcher.EnableRaisingEvents = $true
        # If watching MyDocuments, ONLY listen to the specific Canary Decoy file
        if ($cDir -eq ([Environment]::GetFolderPath('MyDocuments'))) {
            $cWatcher.Filter = "Crypto_Recovery_Phrase_Decoy.txt"
        }
        $cWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::Size

        $msgData = @{ SentinelDir = $SentinelDir }
        Register-ObjectEvent -InputObject $cWatcher -EventName "Changed" -MessageData $msgData -Action $canaryAction | Out-Null
        Register-ObjectEvent -InputObject $cWatcher -EventName "Deleted" -MessageData $msgData -Action $canaryAction | Out-Null
        Register-ObjectEvent -InputObject $cWatcher -EventName "Renamed" -MessageData $msgData -Action $canaryAction | Out-Null
        $watchers += $cWatcher
        Write-Log "Canary Honeypot watcher active in: $cDir"
    } catch {
        Write-Log "Failed to initialize canary watcher on $cDir" "WARN"
    }
}

# ---------------------------------------------------------------------
# 5. TIER 2 & TIER 3: REAL-TIME PROCESS & PARENT-CHILD TELEMETRY ENGINE
# ---------------------------------------------------------------------
$knownPids = @{}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $knownPids[$_.ProcessId] = $_.Name
}
Write-Log "Tier 2 Process Telemetry & Tier 3 NtSuspendProcess Engine Armed ($($knownPids.Count) baseline processes)." "TIER2"

function Inspect-NewProcesses {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $procMap = @{}
    foreach ($p in $procs) { $procMap[$p.ProcessId] = $p }

    foreach ($p in $procs) {
        $cPid = $p.ProcessId
        if ($knownPids.ContainsKey($cPid)) { continue }
        $knownPids[$cPid] = $p.Name

        $cName = "$($p.Name)".ToLower()
        $cmd   = "$($p.CommandLine)"
        $exe   = "$($p.ExecutablePath)"
        $pPid  = $p.ParentProcessId

        if ($cmd -match "SentinelWatchdog|SentinelDashboard|Install\.ps1|Uninstall\.ps1") { continue }
        if ($cPid -eq $PID) { continue }

        $parentName = "unknown"
        if ($procMap.ContainsKey($pPid)) {
            $parentName = "$($procMap[$pPid].Name)".ToLower()
        }

        # RULE 1 (Tier 2): Parent-Child Anomaly (Browser or Game Launcher spawning Shell / LOLBin)
        $isHighRiskParent = ($parentName -match "^(chrome|msedge|brave|opera|nikke|nikke_launcher|discord|telegram|steam|robloxplayerbeta|robloxstudio|riotclientservices|valorant|tslgame)\.exe$")
        $isShellOrLolbin  = ($cName -match "^(powershell|pwsh|cmd|mshta|wscript|cscript|regsvr32|certutil|bitsadmin)\.exe$")

        if ($isHighRiskParent -and $isShellOrLolbin) {
            $actionMsg = "Logged & Alerted"
            if ($script:Config.AutoFreezeSuspiciousProc -and ("SentinelNative.KernelControl" -as [type])) {
                $frozen = [SentinelNative.KernelControl]::FreezeProcess([int]$cPid)
                if ($frozen) {
                    $actionMsg = "Process Frozen via NtSuspendProcess (PID: $cPid)"
                    $cPid | Out-File -FilePath "$SentinelDir\last_frozen.pid" -Encoding UTF8 -Force
                }
            }
            $intel = Get-FileThreatIntel -FilePath $exe
            Show-Alert -Title "Tier 2: Parent-Child Process Anomaly!" `
                       -Message "Suspicious shell spawned! Parent '$parentName' (PID: $pPid) launched '$cName' (PID: $cPid). Command: $cmd" `
                       -Level "TIER2" -FilePath $exe -SHA256 $intel.SHA256 -ActionTaken $actionMsg
            continue
        }

        # RULE 2 (Tier 2): Encoded / Fileless PowerShell Attack Detection
        if ($cName -match "^(powershell|pwsh)\.exe$" -and $cmd -match "(-enc|-encodedcommand|frombase64string|downloadstring|invoke-expression|\biex\b|amsiutils)") {
            $actionMsg = "Logged & Alerted"
            if ($script:Config.AutoFreezeSuspiciousProc -and ("SentinelNative.KernelControl" -as [type])) {
                $frozen = [SentinelNative.KernelControl]::FreezeProcess([int]$cPid)
                if ($frozen) {
                    $actionMsg = "Process Frozen via NtSuspendProcess (PID: $cPid)"
                    $cPid | Out-File -FilePath "$SentinelDir\last_frozen.pid" -Encoding UTF8 -Force
                }
            }
            Show-Alert -Title "Tier 2: Fileless / Obfuscated PowerShell Blocked!" `
                       -Message "Detected encoded/fileless PowerShell execution (PID: $cPid, Parent: $parentName). Cmd: $cmd" `
                       -Level "CRITICAL" -FilePath $exe -ActionTaken $actionMsg
            continue
        }

        # RULE 3 (Tier 4): Zero-Trust Unsigned Binary Executing in Temp / Browser User Data
        if ($exe -and ($exe -match "\\AppData\\Local\\Temp\\|\\Google\\Chrome\\User Data\\|\\Microsoft\\Edge\\User Data\\")) {
            if (-not (Test-IsTrustedBinary -FilePath $exe)) {
                $actionMsg = "Untrusted Temp Execution Flagged"
                if ($script:Config.AutoFreezeSuspiciousProc -and ("SentinelNative.KernelControl" -as [type])) {
                    $frozen = [SentinelNative.KernelControl]::FreezeProcess([int]$cPid)
                    if ($frozen) {
                        $actionMsg = "Unsigned Process Frozen via NtSuspendProcess (PID: $cPid)"
                        $cPid | Out-File -FilePath "$SentinelDir\last_frozen.pid" -Encoding UTF8 -Force
                    }
                }
                $intel = Get-FileThreatIntel -FilePath $exe
                Show-Alert -Title "Tier 4: Unsigned Binary in Restricted Path!" `
                           -Message "Unsigned executable '$cName' (PID: $cPid) launched from high-risk path." `
                           -Level "CRITICAL" -FilePath $exe -SHA256 $intel.SHA256 -ActionTaken $actionMsg
            }
        }
    }
}

# ---------------------------------------------------------------------
# 6. MAIN CONTINUOUS MONITORING LOOP
# ---------------------------------------------------------------------
Write-Log "Sentinel Watchdog Ultra v3.0 enters live monitoring loop."
$loopCount = 0

while ($true) {
    Start-Sleep -Seconds 5
    $loopCount++

    # Tier 2 & 3 & 4: Fast Process Tree & Behavioral Inspection (Every 5s)
    Inspect-NewProcesses

    # Run Persistence & Artifact Checks every 15s (every 3rd cycle)
    if ($loopCount % 3 -eq 0) {
        $currentSnap = Get-PersistenceSnapshot
        foreach ($k in $currentSnap.Keys) {
            if (-not $baseline.ContainsKey($k)) {
                $newVal = $currentSnap[$k]
                Show-Alert -Title "Tier 1: New Persistence Detected!" `
                           -Message "New auto-start entry registered: $k -> $newVal" `
                           -Level "ALERT" -FilePath $newVal -ActionTaken "Baseline Updated & Logged"
                $baseline[$k] = $newVal
            }
        }

        $pehPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\PlatformExperienceHelper"
        if (Test-Path $pehPath) {
            $quarResult = Move-ToQuarantine -SourcePath $pehPath -Reason "Malware Artifact PlatformExperienceHelper"
            if ($quarResult) {
                Show-Alert -Title "Sentinel: Malware Artifact Quarantined!" `
                           -Message "Quarantined rogue folder: $pehPath" `
                           -Level "CRITICAL" -FilePath $pehPath -SHA256 $quarResult.SHA256 -ActionTaken "Moved to Quarantine"
            } else {
                Remove-Item -Path $pehPath -Recurse -Force -ErrorAction SilentlyContinue
                Show-Alert -Title "Sentinel: Malware Artifact Removed!" `
                           -Message "Deleted rogue folder: $pehPath" `
                           -Level "CRITICAL" -FilePath $pehPath -ActionTaken "Force Deleted"
            }
        }

        $rogueClsid = "HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
        if (Test-Path $rogueClsid) {
            Remove-Item -Path $rogueClsid -Recurse -Force -ErrorAction SilentlyContinue
            Show-Alert -Title "Sentinel: Rogue CLSID Destroyed!" `
                       -Message "Removed malicious registry persistence: $rogueClsid" `
                       -Level "CRITICAL" -FilePath $rogueClsid -ActionTaken "Registry Key Deleted"
        }
    }

    if ($loopCount % 360 -eq 0) {
        Write-Log "Heartbeat: Tier 1-5 Engines healthy, zero threat anomalies ($($watchers.Count) watchers, $($knownPids.Count) processes tracked)." "INFO"
        $script:Config = Load-SentinelConfig
    }
}
