# =====================================================================
# Security Sentinel Ultra v8.0 - Guardian Twin (Fail-Closed Hardened)
# 1. Real Kernel DACL Writeback with OWNER RIGHTS (S-1-3-4) Restriction
#    (Blocks WRITE_DAC & PROCESS_TERMINATE even from same-user processes)
# 2. Unified CSPRNG Secret (HKLM / DPAPI Vault) + PID-Bound Stop-Token
# 3. Fail-Closed External Trust Anchor (Zero disk-hash or static fallback!)
# =====================================================================
param(
    [switch]$LibraryOnly,
    [string]$TestStateDir = ""
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$ProgDir      = "$env:ProgramFiles\SecuritySentinel"
$StateDir     = if ($LibraryOnly -and -not [string]::IsNullOrWhiteSpace($TestStateDir)) {
    $TestStateDir
} else {
    Join-Path $env:LOCALAPPDATA "SecuritySentinel"
}
$SentinelDir  = if (Test-Path (Join-Path $ProgDir "SentinelWatchdog.ps1")) {
    $ProgDir
} elseif ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "SentinelWatchdog.ps1"))) {
    $PSScriptRoot
} else {
    $StateDir
}

$WatchdogPath = Join-Path $SentinelDir "SentinelWatchdog.ps1"
$ConfigFile   = "$StateDir\config.json"
$LogFile      = "$StateDir\logs\sentinel.log"
$WatchdogPidF = "$StateDir\sentinel.pid"
$GuardianPidF = "$StateDir\guardian.pid"
$ManifestFile = "$StateDir\manifest.json"
$StopFlagFile = "$StateDir\graceful_stop.token"

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

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
                RawAcl newDacl = new RawAcl(rsd.DiscretionaryAcl != null ? rsd.DiscretionaryAcl.Revision : (byte)2, 4);

                SecurityIdentifier worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                int denyMask = 0x0001 | 0x0008 | 0x0020 | 0x0800 | 0x00040000 | 0x00080000;
                newDacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, denyMask, worldSid, false, null));

                SecurityIdentifier ownerRightsSid = new SecurityIdentifier("S-1-3-4");
                int ownerAllowMask = 0x0400 | 0x1000 | 0x0010 | 0x00100000;
                newDacl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, ownerAllowMask, ownerRightsSid, false, null));

                SecurityIdentifier currentSid = WindowsIdentity.GetCurrent().User;
                newDacl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, ownerAllowMask, currentSid, false, null));

                rsd.DiscretionaryAcl = newDacl;
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
} catch {}

# A3: Unified Secret Loader (HKLM first, then DPAPI vault.sec; zero static public constant!)
function Get-GuardianInstallationSecretBytes {
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

$script:SentinelEntropyBytes = Get-GuardianInstallationSecretBytes

function Unprotect-DpapiString([string]$cipherBase64) {
    if ([string]::IsNullOrWhiteSpace($cipherBase64) -or (-not $script:SentinelEntropyBytes)) { return "" }
    try {
        $enc = [Convert]::FromBase64String($cipherBase64)
        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($dec)
    } catch {}
    return ""
}

# FAIL-CLOSED TRUST ANCHOR: Never falls back to reading current file hash from disk!
function Get-TrustedWatchdogHash {
    foreach ($regPath in @("HKLM:\SOFTWARE\SecuritySentinel\PublicHashes", "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor")) {
        if (Test-Path $regPath) {
            try {
                $val = (Get-ItemProperty -Path $regPath -Name "SentinelWatchdog.ps1" -ErrorAction SilentlyContinue)."SentinelWatchdog.ps1"
                if ($val) { return "$val" }
            } catch {}
        }
    }
    if (Test-Path $ManifestFile) {
        try {
            $mObj = Get-Content $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($mObj -and $mObj.SealedHashes) {
                $jsonHashes = Unprotect-DpapiString $mObj.SealedHashes
                if ($jsonHashes) {
                    $parsed = $jsonHashes | ConvertFrom-Json
                    if ($parsed."SentinelWatchdog.ps1") { return "$($parsed.'SentinelWatchdog.ps1')" }
                }
            }
        } catch {}
    }
    return ""
}

$script:LastKnownWatchdogPid = ""

function Test-GuardianStopToken {
    param([string]$ExpectedWatchdogPid = "")
    if (-not (Test-Path $StopFlagFile)) { return $false }
    if (-not $script:SentinelEntropyBytes) { return $false }
    try {
        $raw = (Get-Content $StopFlagFile -Raw -Encoding UTF8).Trim()
        $enc = [Convert]::FromBase64String($raw)
        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $plain = [System.Text.Encoding]::UTF8.GetString($dec)
        if (-not $plain -or -not $plain.StartsWith("STOP|")) {
            Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
            return $false
        }
        $parts = $plain.Split('|')
        if ($parts.Count -lt 3) {
            Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
            return $false
        }
        $tokenPid = $parts[1].Trim()
        $ts = [long]$parts[2]
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ([Math]::Abs($now - $ts) -gt 60) {
            Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
            return $false
        }

        $targetPid = $ExpectedWatchdogPid
        if (-not $targetPid -and (Test-Path $WatchdogPidF)) {
            $rawPid = (Get-Content $WatchdogPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($rawPid -and ($rawPid.Trim() -match "^\d+$")) {
                $targetPid = $rawPid.Trim()
            }
        }
        if (-not $targetPid -and $script:LastKnownWatchdogPid) {
            $targetPid = $script:LastKnownWatchdogPid
        }
        if (-not $targetPid) {
            $targetPid = "$PID"
        }

        if ($tokenPid -ne $targetPid) {
            Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
            return $false
        }
        return $true
    } catch {
        Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
        return $false
    }
}

if ($LibraryOnly) {
    return
}

try {
    [void][SentinelGuardianNative.SelfDefense]::HardenDacl()
} catch {}

$PID | Out-File -FilePath $GuardianPidF -Encoding UTF8 -Force

function Write-GuardianLog {
    param([string]$Message, [string]$Level = "CRITICAL")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $coreLine = "[$ts] [$Level] $Message"

    # C1: Primary sink is Windows Event Log
    try {
        $source = if ([System.Diagnostics.EventLog]::SourceExists("SecuritySentinel")) { "SecuritySentinel" } else { "Windows PowerShell" }
        $evId   = if ($source -eq "SecuritySentinel") { 4000 } else { 800 }
        Write-EventLog -LogName Application -Source $source -EventId $evId -EntryType Error -Message "[SecuritySentinel][$Level][Guardian] $Message" -ErrorAction SilentlyContinue
    } catch {}

    # Append with HMAC chain tag if key is available
    try {
        $prevHmac = "0000000000000000"
        if (Test-Path $LogFile) {
            $lastLn = Get-Content -Path $LogFile -Tail 1 -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($lastLn -and $lastLn -match "\[HMAC:([0-9A-Fa-f]{16})\]$") {
                $prevHmac = $Matches[1].ToUpper()
            }
        }
        $keyBytes = if ($script:SentinelEntropyBytes -and $script:SentinelEntropyBytes.Length -ge 16) {
            $script:SentinelEntropyBytes
        } else {
            [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_LOG_HMAC_DEFAULT_KEY_V8")
        }
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$keyBytes)
        $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$prevHmac|$coreLine"))
        $hmac.Dispose()
        $newHmac = ([BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 16))
        Add-Content -Path $LogFile -Value "$coreLine [HMAC:$newHmac]" -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

function Send-TamperDiscordAlert {
    param([string]$DeadPid, [string]$NewPid, [string]$Note = "Dual-Process Guardian Twin Armed (OWNER RIGHTS DACL + Fail-Closed Trust Anchor)")
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
            username = "Security Sentinel Ultra v8.0 EDR"
            content  = $ping
            embeds   = @(@{
                title       = "[CRITICAL] Tier 3 Tamper Protection: Watchdog Resurrected!"
                description = "An unauthorized attempt to terminate **Security Sentinel Watchdog** was detected! **Guardian Twin** immediately intercepted the termination, verified SHA-256 script integrity against the Fail-Closed External Trust Anchor, and resurrected the defense engine."
                color       = 16711680
                fields      = @(
                    @{ name = "Endpoint";        value = "$env:COMPUTERNAME ($env:USERNAME)"; inline = $true },
                    @{ name = "Terminated PID";  value = "$DeadPid";                          inline = $true },
                    @{ name = "Resurrected PID"; value = "$NewPid (Active)";                  inline = $true },
                    @{ name = "Defense Status";  value = $Note;                               inline = $false }
                )
                footer = @{ text = "Security Sentinel Ultra v8.0 | Enterprise Self-Defense | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
            })
        } | ConvertTo-Json -Depth 6
        Invoke-RestMethod -Uri $webhookUrl.Trim() -Method Post -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 5 | Out-Null
    } catch {}
}

while ($true) {
    for ($w = 0; $w -lt 6; $w++) {
        Start-Sleep -Milliseconds 500
        if (Test-GuardianStopToken) {
            Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
            exit 0
        }
    }

    if (-not (Test-Path $WatchdogPath)) { continue }

    # Fail-Closed Verification against External Trust Anchor (Zero disk fallback!)
    $expectedHash = Get-TrustedWatchdogHash
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        Write-GuardianLog "[TAMPER-GUARD] CRITICAL: External Trust Anchor missing or corrupted! Fail-Closed active: refusing to execute unverified SentinelWatchdog.ps1!" "CRITICAL"
        Start-Sleep -Seconds 10
        continue
    }

    $currHash = (Get-FileHash -Path $WatchdogPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if (-not $currHash -or ($currHash -ne $expectedHash)) {
        Write-GuardianLog "[TAMPER-GUARD] CRITICAL: SentinelWatchdog.ps1 hash mismatch against Trust Anchor ($currHash != $expectedHash)! Refusing to execute tampered script!" "CRITICAL"
        Send-TamperDiscordAlert -DeadPid "TAMPERED" -NewPid "BLOCKED" -Note "ALERT: SentinelWatchdog.ps1 modified on disk! Execution blocked by Fail-Closed Trust Anchor to prevent EoP."
        Start-Sleep -Seconds 10
        continue
    }

    $wdAlive = $false
    $lastPid = if ($script:LastKnownWatchdogPid) { $script:LastKnownWatchdogPid } else { "Unknown" }
    if (Test-Path $WatchdogPidF) {
        $rawPid = (Get-Content $WatchdogPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rawPid -and ($rawPid.Trim() -match "^\d+$")) {
            $lastPid = $rawPid.Trim()
            $script:LastKnownWatchdogPid = $lastPid
            $proc = Get-Process -Id ([int]$lastPid) -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -match "^(powershell|pwsh)$") {
                $wdAlive = $true
            }
        }
    }

    if (-not $wdAlive) {
        Start-Sleep -Milliseconds 400
        if (Test-GuardianStopToken) {
            Remove-Item $GuardianPidF -Force -ErrorAction SilentlyContinue
            exit 0
        }

        $newProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$WatchdogPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        $newPid = if ($newProc) { "$($newProc.Id)"; $script:LastKnownWatchdogPid = "$($newProc.Id)" } else { "Spawned" }

        Write-GuardianLog "[TAMPER-GUARD] Watchdog (PID: $lastPid) was unexpectedly terminated! Guardian Twin verified Fail-Closed Trust Anchor SHA-256 and resurrected Watchdog (New PID: $newPid)." "CRITICAL"
        Send-TamperDiscordAlert -DeadPid $lastPid -NewPid $newPid
        Start-Sleep -Seconds 3
    }
}
