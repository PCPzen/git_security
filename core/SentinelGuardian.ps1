# =====================================================================
# Security Sentinel Ultra v4.0 - Guardian Twin (Self-Defense Watchdog)
# Dual-Process Heartbeat Monitor & Anti-Tamper Resurrection Engine
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$SentinelDir  = "$env:LOCALAPPDATA\SecuritySentinel"
$WatchdogPath = "$SentinelDir\SentinelWatchdog.ps1"
$ConfigFile   = "$SentinelDir\config.json"
$LogFile      = "$SentinelDir\logs\sentinel.log"
$WatchdogPidF = "$SentinelDir\sentinel.pid"
$GuardianPidF = "$SentinelDir\guardian.pid"
$StopFlagFile = "$SentinelDir\graceful_stop.flag"

# Record Guardian Twin PID
$PID | Out-File -FilePath $GuardianPidF -Encoding UTF8 -Force

function Write-GuardianLog {
    param([string]$Message, [string]$Level = "CRITICAL")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Send-TamperDiscordAlert {
    param([string]$DeadPid, [string]$NewPid)
    if (-not (Test-Path $ConfigFile)) { return }
    try {
        $cfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) { return }
        $ping = if ($cfg.DiscordMentionOnCritical) { "**[CRITICAL TAMPER PROTECTION ALERT]** @everyone" } else { "" }
        $payload = @{
            username = "Security Sentinel Ultra v4.0 EDR"
            content  = $ping
            embeds   = @(@{
                title       = "[CRITICAL] Tier 3 Tamper Protection: Watchdog Resurrected!"
                description = "An unauthorized attempt to terminate **Security Sentinel Watchdog** was detected! **Guardian Twin** immediately intercepted the termination and resurrected the defense engine."
                color       = 16711680
                fields      = @(
                    @{ name = "Endpoint";        value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
                    @{ name = "Terminated PID";  value = "$DeadPid";                          inline = $true },
                    @{ name = "Resurrected PID"; value = "$NewPid (Active)";                  inline = $true },
                    @{ name = "Defense Status";  value = "Dual-Process Guardian Twin Armed";  inline = $false }
                )
                footer = @{ text = "Security Sentinel Ultra v4.0 | Anti-Tamper Self-Defense | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
            })
        } | ConvertTo-Json -Depth 6
        Invoke-RestMethod -Uri $cfg.DiscordWebhookUrl.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 5 | Out-Null
    } catch {}
}

# Main Guardian Twin Heartbeat Loop (0.0% CPU, ~10MB RAM)
while ($true) {
    Start-Sleep -Seconds 3

    # Check if an authorized user restart/uninstall is happening
    if (Test-Path $StopFlagFile) {
        Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if (-not (Test-Path $WatchdogPath)) { continue }

    $wdAlive = $false
    $lastPid = "Unknown"
    if (Test-Path $WatchdogPidF) {
        $rawPid = (Get-Content $WatchdogPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawPid -and ($rawPid.Trim() -match "^\d+$")) {
            $lastPid = $rawPid.Trim()
            $proc = Get-Process -Id ([int]$lastPid) -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -match "powershell|pwsh") {
                $wdAlive = $true
            }
        }
    }

    if (-not $wdAlive) {
        # Double-check graceful stop flag before triggering tamper resurrection
        Start-Sleep -Milliseconds 400
        if (Test-Path $StopFlagFile) {
            Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
            exit 0
        }

        # Resurrect Watchdog immediately
        $newProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        $newPid = if ($newProc) { "$($newProc.Id)" } else { "Spawned" }

        Write-GuardianLog "[TAMPER-GUARD] Watchdog (PID: $lastPid) was unexpectedly terminated! Guardian Twin resurrected Watchdog (New PID: $newPid)." "CRITICAL"
        Send-TamperDiscordAlert -DeadPid $lastPid -NewPid $newPid
        Start-Sleep -Seconds 3
    }
}
