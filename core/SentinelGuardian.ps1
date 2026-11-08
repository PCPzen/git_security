# =====================================================================
# Security Sentinel Ultra v5.0 - Guardian Twin (Red-Team Hardened)
# Dual-Process Heartbeat, Real DACL Writeback, DPAPI Stop-Token Verification
# & SHA-256 Watchdog Script Integrity Guard
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$SentinelDir  = "$env:LOCALAPPDATA\SecuritySentinel"
$WatchdogPath = "$SentinelDir\SentinelWatchdog.ps1"
$ConfigFile   = "$SentinelDir\config.json"
$LogFile      = "$SentinelDir\logs\sentinel.log"
$WatchdogPidF = "$SentinelDir\sentinel.pid"
$GuardianPidF = "$SentinelDir\guardian.pid"
$StopFlagFile = "$SentinelDir\graceful_stop.token"

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

# Apply Real Kernel DACL Self-Defense on Guardian Twin Process
$daclCode = @"
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SentinelGuardianNative {
    public static class SelfDefense {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        private const int DACL_SECURITY_INFORMATION = 0x00000004;

        public static bool HardenDacl() {
            try {
                IntPtr hProc = GetCurrentProcess();
                uint lenNeeded = 0;
                GetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, new byte[0], 0, out lenNeeded);
                if (lenNeeded == 0) return false;
                byte[] sdBytes = new byte[lenNeeded];
                if (!GetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, sdBytes, lenNeeded, out lenNeeded)) return false;

                RawSecurityDescriptor rsd = new RawSecurityDescriptor(sdBytes, 0);
                RawAcl dacl = rsd.DiscretionaryAcl;
                if (dacl == null) return false;

                SecurityIdentifier worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                int denyMask = 0x0001 | 0x0008 | 0x0020 | 0x0800;
                CommonAce denyAce = new CommonAce(AceFlags.None, AceQualifier.AccessDenied, denyMask, worldSid, false, null);

                dacl.InsertAce(0, denyAce);
                rsd.DiscretionaryAcl = dacl;

                byte[] newSdBytes = new byte[rsd.BinaryLength];
                rsd.GetBinaryForm(newSdBytes, 0);
                return SetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, newSdBytes);
            } catch {
                return false;
            }
        }
    }
}
"@

try {
    if (-not ("SentinelGuardianNative.SelfDefense" -as [type])) {
        Add-Type -TypeDefinition $daclCode -Language CSharp -ErrorAction SilentlyContinue
    }
    [void][SentinelGuardianNative.SelfDefense]::HardenDacl()
} catch {}

# Record Guardian Twin PID & Expected Watchdog SHA-256
$PID | Out-File -FilePath $GuardianPidF -Encoding UTF8 -Force
$script:ExpectedWatchdogHash = if (Test-Path $WatchdogPath) {
    (Get-FileHash -Path $WatchdogPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
} else { "" }

function Unprotect-DpapiString([string]$cipherBase64) {
    if ([string]::IsNullOrWhiteSpace($cipherBase64)) { return "" }
    try {
        $enc = [Convert]::FromBase64String($cipherBase64)
        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($dec)
    } catch { return "" }
}

function Test-AuthenticatedStopToken {
    if (-not (Test-Path $StopFlagFile)) { return $false }
    try {
        $raw = (Get-Content $StopFlagFile -Raw -Encoding UTF8).Trim()
        $plain = Unprotect-DpapiString $raw
        if (-not $plain -or -not $plain.StartsWith("STOP|")) { return $false }
        $parts = $plain.Split('|')
        if ($parts.Count -lt 3) { return $false }
        $ts = [long]$parts[2]
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        return ([Math]::Abs($now - $ts) -le 60)
    } catch {
        return $false
    }
}

function Write-GuardianLog {
    param([string]$Message, [string]$Level = "CRITICAL")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Send-TamperDiscordAlert {
    param([string]$DeadPid, [string]$NewPid, [string]$Note = "Dual-Process Guardian Twin Armed (DACL Hardened)")
    if (-not (Test-Path $ConfigFile)) { return }
    try {
        $cfg = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $webhookUrl = if (-not [string]::IsNullOrWhiteSpace($cfg.DiscordWebhookEncrypted)) {
            Unprotect-DpapiString $cfg.DiscordWebhookEncrypted
        } else {
            $cfg.DiscordWebhookUrl
        }
        if ([string]::IsNullOrWhiteSpace($webhookUrl)) { return }

        $ping = if ($cfg.DiscordMentionOnCritical) { "**[CRITICAL TAMPER PROTECTION ALERT]** @everyone" } else { "" }
        $payload = @{
            username = "Security Sentinel Ultra v5.0 EDR"
            content  = $ping
            embeds   = @(@{
                title       = "[CRITICAL] Tier 3 Tamper Protection: Watchdog Resurrected!"
                description = "An unauthorized attempt to terminate **Security Sentinel Watchdog** was detected! **Guardian Twin** immediately intercepted the termination, verified SHA-256 script integrity, and resurrected the defense engine."
                color       = 16711680
                fields      = @(
                    @{ name = "Endpoint";        value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
                    @{ name = "Terminated PID";  value = "$DeadPid";                          inline = $true },
                    @{ name = "Resurrected PID"; value = "$NewPid (Active)";                  inline = $true },
                    @{ name = "Defense Status";  value = $Note;                               inline = $false }
                )
                footer = @{ text = "Security Sentinel Ultra v5.0 | Red-Team Hardened Self-Defense | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
            })
        } | ConvertTo-Json -Depth 6
        Invoke-RestMethod -Uri $webhookUrl.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 5 | Out-Null
    } catch {}
}

# Main Guardian Twin Heartbeat Loop
while ($true) {
    Start-Sleep -Seconds 3

    if (Test-AuthenticatedStopToken) {
        Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
        exit 0
    }

    if (-not (Test-Path $WatchdogPath)) { continue }

    # Verify Watchdog Script SHA-256 Integrity
    if ($script:ExpectedWatchdogHash) {
        $currHash = (Get-FileHash -Path $WatchdogPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($currHash -and ($currHash -ne $script:ExpectedWatchdogHash)) {
            Write-GuardianLog "[TAMPER-GUARD] CRITICAL: SentinelWatchdog.ps1 hash mismatch detected ($currHash != $($script:ExpectedWatchdogHash))! Refusing to execute tampered script!" "CRITICAL"
            Send-TamperDiscordAlert -DeadPid "TAMPERED" -NewPid "BLOCKED" -Note "ALERT: SentinelWatchdog.ps1 modified on disk! Execution blocked to prevent EoP."
            Start-Sleep -Seconds 10
            continue
        }
    }

    $wdAlive = $false
    $lastPid = "Unknown"
    if (Test-Path $WatchdogPidF) {
        $rawPid = (Get-Content $WatchdogPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawPid -and ($rawPid.Trim() -match "^\d+$")) {
            $lastPid = $rawPid.Trim()
            $proc = Get-Process -Id ([int]$lastPid) -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -match "^(powershell|pwsh)$") {
                $wdAlive = $true
            }
        }
    }

    if (-not $wdAlive) {
        Start-Sleep -Milliseconds 400
        if (Test-AuthenticatedStopToken) {
            Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
            exit 0
        }

        $newProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        $newPid = if ($newProc) { "$($newProc.Id)" } else { "Spawned" }

        Write-GuardianLog "[TAMPER-GUARD] Watchdog (PID: $lastPid) was unexpectedly terminated! Guardian Twin verified SHA-256 and resurrected Watchdog (New PID: $newPid)." "CRITICAL"
        Send-TamperDiscordAlert -DeadPid $lastPid -NewPid $newPid
        Start-Sleep -Seconds 3
    }
}
