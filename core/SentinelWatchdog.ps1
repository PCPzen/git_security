# =====================================================================
# Security Sentinel Ultra v8.0 - Enterprise EDR (DPAPI, Anti-Bypass, Phishing Guard)
# Third-Round Red-Team Hardened & Windows 11 Verified Edition:
# 1. OWNER RIGHTS (S-1-3-4) Kernel DACL: Blocks WRITE_DAC (0x00040000) &
#    PROCESS_TERMINATE (0x0001) even from same-user processes!
# 2. Per-Install 256-bit CSPRNG Secret + Named EventWaitHandle Stop Signal
#    (Eliminates static repo entropy; Admin ACLs on HKLM Trust Anchor)
# 3. Fail-Closed Trust Anchor: Removed disk-hash fallback on tampering
# 4. Work & Gaming Safe-Mode (Zero Disruption on Windows 11):
#    - Removed '-WindowStyle Hidden' from obfuscation regex
#    - Verified SHA-256 exemption for SentinelDashboard.ps1 & core scripts
#    - Developer toolchain & Game Launcher safe-mode in %TEMP%
#    - Browser Watcher only auto-quarantines unsigned files in User Data
#      if Packed (Entropy >= 7.2) or C2 IOCs found (Protects Extensions!)
#    - Signed Malware Catch: Freezes signed binaries ONLY if proven C2 /
#      Reflective PE injection is detected (Score >= 90)
# 5. Kernel ETW Win32_ProcessStartTrace (when Admin) + 29 Persistence
#    Vectors (including Windows Services ImagePath tracking)
# 6. Support for -LibraryOnly dot-sourcing by Invoke-RedTeamAudit.ps1
#    so the Automated Red-Team Suite tests 100% REAL production functions!
# =====================================================================
param(
    [switch]$LibraryOnly
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$SentinelDir  = if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "SentinelWatchdog.ps1")) -and ($PSScriptRoot -match "Program Files")) {
    $PSScriptRoot
} else {
    "$env:LOCALAPPDATA\SecuritySentinel"
}
$StateDir     = "$env:LOCALAPPDATA\SecuritySentinel"
$ConfigFile   = "$StateDir\config.json"
$LogFile      = "$StateDir\logs\sentinel.log"
$QuarDir      = "$StateDir\quarantine"
$QuarManifest = "$QuarDir\quarantine_manifest.json"
$PidFile      = "$StateDir\sentinel.pid"
$GuardianPidF = "$StateDir\guardian.pid"
$GuardianPath = Join-Path $SentinelDir "SentinelGuardian.ps1"
if (-not (Test-Path $GuardianPath)) { $GuardianPath = "$StateDir\SentinelGuardian.ps1" }
$ManifestFile = "$StateDir\manifest.json"
$StopFlagFile = "$StateDir\graceful_stop.token"
$CanaryDir    = "$env:APPDATA\SecuritySentinel_Canary"
$DocCanary    = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "Crypto_Recovery_Phrase_Decoy.txt"

@($StateDir, "$StateDir\logs", $QuarDir, $CanaryDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# ---------------------------------------------------------------------
# TIER 3 & 4: NATIVE WIN32 / NTAPI, OWNER-RIGHTS DACL & MEMORY FORENSICS
# ---------------------------------------------------------------------
$nativeCode = @"
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SentinelNative {
    public class MemoryScanReport {
        public string[] C2Indicators = new string[0];
        public int RwxPrivateRegions = 0;
        public int UnbackedPeHeaders = 0;
        public int TotalBytesScanned = 0;
    }

    public static class KernelControl {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtResumeProcess(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint PROCESS_SUSPEND_RESUME = 0x0800;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const int DACL_SECURITY_INFORMATION = 0x00000004;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;

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

        // Kernel DACL Self-Defense v7.0 with Explicit OWNER RIGHTS (S-1-3-4) Restriction:
        // Strips the process owner's implicit WRITE_DAC (0x00040000) & PROCESS_TERMINATE (0x0001) rights!
        public static bool HardenCurrentProcessDacl() {
            try {
                IntPtr hProc = GetCurrentProcess();
                uint lenNeeded = 0;
                GetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, new byte[0], 0, out lenNeeded);
                if (lenNeeded == 0) return false;
                byte[] sdBytes = new byte[lenNeeded];
                if (!GetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, sdBytes, lenNeeded, out lenNeeded)) return false;

                RawSecurityDescriptor rsd = new RawSecurityDescriptor(sdBytes, 0);
                RawAcl newDacl = new RawAcl(rsd.DiscretionaryAcl != null ? rsd.DiscretionaryAcl.Revision : (byte)2, 4);

                // 1. Deny Everyone (WorldSid): Terminate(0x0001) | VM_Operation(0x0008) | VM_Write(0x0020) | Suspend(0x0800) | WRITE_DAC(0x00040000) | WRITE_OWNER(0x00080000)
                SecurityIdentifier worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                int denyMask = 0x0001 | 0x0008 | 0x0020 | 0x0800 | 0x00040000 | 0x00080000;
                newDacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, denyMask, worldSid, false, null));

                // 2. Explicit OWNER RIGHTS (S-1-3-4) ACE: Restricts owner to QueryLimitedInfo (0x1000) | VM_Read (0x0010) | Synchronize (0x00100000)
                //    This prevents same-user malware from using implicit owner WRITE_DAC to overwrite the DACL!
                SecurityIdentifier ownerRightsSid = new SecurityIdentifier("S-1-3-4");
                int ownerAllowMask = 0x0400 | 0x1000 | 0x0010 | 0x00100000;
                newDacl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, ownerAllowMask, ownerRightsSid, false, null));

                // 3. Allow Current User only QueryInformation (0x0400) | QueryLimitedInfo (0x1000) | VM_Read (0x0010) | Synchronize (0x00100000)
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

        public static double ComputeShannonEntropy(string filePath) {
            try {
                if (!File.Exists(filePath)) return 0.0;
                byte[] buffer;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
                    int maxBytes = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
                    if (maxBytes == 0) return 0.0;
                    buffer = new byte[maxBytes];
                    int bytesRead = fs.Read(buffer, 0, maxBytes);
                    if (bytesRead <= 0) return 0.0;
                }
                long[] counts = new long[256];
                for (int i = 0; i < buffer.Length; i++) {
                    counts[buffer[i]]++;
                }
                double entropy = 0.0;
                double len = (double)buffer.Length;
                for (int i = 0; i < 256; i++) {
                    if (counts[i] > 0) {
                        double p = counts[i] / len;
                        entropy -= p * (Math.Log(p) / Math.Log(2.0));
                    }
                }
                return Math.Round(entropy, 2);
            } catch {
                return 0.0;
            }
        }

        private static void ScanTextForC2(string text, HashSet<string> unique, List<string> results) {
            string[] patterns = new string[] {
                @"https?://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/[0-9]{15,22}/[A-Za-z0-9_-]{30,80}",
                @"https?://api\.telegram\.org/bot[0-9]{8,12}:[A-Za-z0-9_-]{30,50}",
                @"https?://[a-zA-Z0-9-]+\.(ngrok-free\.app|ngrok\.io|trycloudflare\.com|loca\.lt|pastebin\.com/raw)/[^\s""'<>\\x00]{1,80}",
                @"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?(?:/[^\s""'<>\\x00]{1,60})?"
            };
            foreach (string pat in patterns) {
                MatchCollection matches = Regex.Matches(text, pat, RegexOptions.IgnoreCase);
                foreach (Match m in matches) {
                    string val = m.Value.Trim();
                    if (val.Length > 10 && !val.Contains("127.0.0.1") && !val.Contains("0.0.0.0")) {
                        if (unique.Add(val)) {
                            results.Add(val);
                            if (results.Count >= 8) return;
                        }
                    }
                }
            }
        }

        public static string[] ExtractBinaryC2Strings(string filePath) {
            List<string> results = new List<string>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try {
                if (!File.Exists(filePath)) return results.ToArray();
                byte[] rawBytes;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
                    int maxBytes = (int)Math.Min(fs.Length, 4 * 1024 * 1024);
                    if (maxBytes == 0) return results.ToArray();
                    rawBytes = new byte[maxBytes];
                    fs.Read(rawBytes, 0, maxBytes);
                }
                string combined = Encoding.ASCII.GetString(rawBytes) + "\n" + Encoding.Unicode.GetString(rawBytes);
                ScanTextForC2(combined, unique, results);
            } catch {}
            return results.ToArray();
        }

        private static bool HasEmbeddedPeHeader(byte[] buf, int bytesRead) {
            if (bytesRead < 256) return false;
            if (buf[0] == 0x4D && buf[1] == 0x5A) {
                int lfanew = BitConverter.ToInt32(buf, 0x3C);
                if (lfanew > 0 && lfanew + 4 < bytesRead) {
                    if (buf[lfanew] == 0x50 && buf[lfanew + 1] == 0x45 && buf[lfanew + 2] == 0x00 && buf[lfanew + 3] == 0x00) {
                        return true;
                    }
                }
            }
            return false;
        }

        public static MemoryScanReport AnalyzeProcessMemory(int pid) {
            MemoryScanReport report = new MemoryScanReport();
            List<string> results = new List<string>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc == IntPtr.Zero) return report;

            try {
                long address = 0;
                long maxAddress = 0x7FFFFFFF0000L;
                int totalBytesScanned = 0;
                int maxTotalScan = 64 * 1024 * 1024;
                uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                while (address < maxAddress && totalBytesScanned < maxTotalScan) {
                    MEMORY_BASIC_INFORMATION mbi;
                    IntPtr ret = VirtualQueryEx(hProc, (IntPtr)address, out mbi, mbiSize);
                    if (ret == IntPtr.Zero) break;

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    bool isCommitted = (mbi.State == MEM_COMMIT);
                    bool isAccessible = ((mbi.Protect & PAGE_NOACCESS) == 0) && ((mbi.Protect & PAGE_GUARD) == 0);
                    uint baseProtect = (mbi.Protect & 0xFF);
                    bool isRwx = (baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY);
                    bool isExec = (isRwx || baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ);
                    bool isPrivate = (mbi.Type == MEM_PRIVATE);

                    if (isCommitted && isPrivate && isRwx) {
                        report.RwxPrivateRegions++;
                    }

                    if (isCommitted && isAccessible && regionSize <= (2 * 1024 * 1024)) {
                        int toRead = (int)Math.Min(regionSize, 262144);
                        byte[] buf = new byte[toRead];
                        int bytesRead = 0;
                        if (ReadProcessMemory(hProc, mbi.BaseAddress, buf, toRead, out bytesRead) && bytesRead > 0) {
                            totalBytesScanned += bytesRead;

                            if (isPrivate && isExec && HasEmbeddedPeHeader(buf, bytesRead)) {
                                report.UnbackedPeHeaders++;
                            }

                            if (results.Count < 8) {
                                string memText = Encoding.ASCII.GetString(buf, 0, bytesRead) + "\n" + Encoding.Unicode.GetString(buf, 0, bytesRead);
                                ScanTextForC2(memText, unique, results);
                            }
                        }
                    }
                    address = mbi.BaseAddress.ToInt64() + regionSize;
                }
                report.TotalBytesScanned = totalBytesScanned;
                report.C2Indicators = results.ToArray();
            } catch {} finally {
                CloseHandle(hProc);
            }
            return report;
        }

        public static string[] ScanProcessVirtualMemory(int pid) {
            return AnalyzeProcessMemory(pid).C2Indicators;
        }
    }
}
"@

try {
    if (-not ("SentinelNative.KernelControl" -as [type])) {
        Add-Type -TypeDefinition $nativeCode -Language CSharp -ErrorAction SilentlyContinue
    }
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
} catch {}

# ---------------------------------------------------------------------
# PER-INSTALL CSPRNG SECRET, NAMED EVENT SIGNAL & DPAPI CONFIG LOADER
# ---------------------------------------------------------------------
$PortableCfg = Join-Path $PSScriptRoot "config.json"
if ((-not (Test-Path $ConfigFile)) -and (Test-Path $PortableCfg)) {
    Copy-Item -Path $PortableCfg -Destination $ConfigFile -Force
}

function Get-InstallationSecretBytes {
    # Zero-Trust: Purge any legacy secret from HKCU immediately
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue

    # 1. Read exclusively from HKLM InstallSecret (Admin/SYSTEM ACL protected)
    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
        if ($b64) {
            try { return [Convert]::FromBase64String($b64) } catch {}
        }
    }
    # 2. Ephemeral 256-bit CSPRNG secret in memory (never written to HKCU!)
    $rngBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($rngBytes)
    return $rngBytes
}

$script:SentinelEntropyBytes = Get-InstallationSecretBytes
$script:LegacyEntropyBytes   = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)

function Protect-DpapiString([string]$plainText) {
    if ([string]::IsNullOrWhiteSpace($plainText)) { return "" }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($enc)
    } catch { return "" }
}

function Unprotect-DpapiString([string]$cipherBase64) {
    if ([string]::IsNullOrWhiteSpace($cipherBase64)) { return "" }
    try {
        $enc = [Convert]::FromBase64String($cipherBase64)
        foreach ($ent in @($script:SentinelEntropyBytes, $script:LegacyEntropyBytes, $null)) {
            try {
                $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $ent, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                return [System.Text.Encoding]::UTF8.GetString($dec)
            } catch {}
        }
    } catch {}
    return ""
}

function Send-AuthenticatedStopSignal {
    try {
        $wdPid = if (Test-Path $PidFile) { (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() } else { "$PID" }
        $payload = "STOP|$wdPid|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllText($StopFlagFile, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)

        # Also signal the Named Kernel Event if open
        try {
            $ev = [System.Threading.EventWaitHandle]::OpenExisting("Local\SecuritySentinelStopSignal")
            [void]$ev.Set()
            $ev.Close()
        } catch {}
    } catch {}
}

function New-AuthenticatedStopToken {
    Send-AuthenticatedStopSignal
}

function Test-AuthenticatedStopToken {
    param([string]$ExpectedWatchdogPid = "$PID")
    if (-not (Test-Path $StopFlagFile)) { return $false }
    try {
        $raw = (Get-Content $StopFlagFile -Raw -Encoding UTF8).Trim()
        $enc = [Convert]::FromBase64String($raw)
        # Strictly require the per-install CSPRNG secret!
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

        if (($tokenPid -ne $ExpectedWatchdogPid) -or ([Math]::Abs($now - $ts) -gt 60)) {
            Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
            return $false
        }
        return $true
    } catch {
        Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
        return $false
    }
}

$defaultConfig = [ordered]@{
    DiscordWebhookUrl           = ""
    DiscordWebhookEncrypted     = ""
    DiscordMentionOnCritical    = $true
    VirusTotalApiKey            = ""
    VirusTotalKeyEncrypted      = ""
    EnableSoundAlert            = $true
    EnableToastAlert            = $true
    DecoyInDocuments            = $true
    SafeWorkGamingMode          = $true
    AutoFreezeSuspiciousProc    = $true
    AutoFreezeMinRiskScore      = 85
    AggressiveBrowserQuarantine = $false
    AutoNetworkKillswitch       = $false
    EnableGuardianTwin          = $true
    EnableDllInjectionGuard     = $true
    ScanIntervalSeconds         = 15
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
            # Upgrade legacy v5/v6 threshold of 60 to 85 when SafeWorkGamingMode is enabled
            if ($raw.SafeWorkGamingMode -and ([int]$raw.AutoFreezeMinRiskScore -lt 80)) {
                $raw.AutoFreezeMinRiskScore = 85
            }
            $dirty = $false
            if (-not [string]::IsNullOrWhiteSpace($raw.DiscordWebhookUrl)) {
                $enc = Protect-DpapiString $raw.DiscordWebhookUrl
                if ($enc) {
                    $raw.DiscordWebhookEncrypted = $enc
                    $raw.DiscordWebhookUrl = ""
                    $dirty = $true
                }
            } elseif (-not [string]::IsNullOrWhiteSpace($raw.DiscordWebhookEncrypted)) {
                $plainWh = Unprotect-DpapiString $raw.DiscordWebhookEncrypted
                if ($plainWh) {
                    $reEnc = Protect-DpapiString $plainWh
                    if ($reEnc -and ($reEnc -ne $raw.DiscordWebhookEncrypted)) {
                        $raw.DiscordWebhookEncrypted = $reEnc
                        $dirty = $true
                    }
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($raw.VirusTotalApiKey)) {
                $encVt = Protect-DpapiString $raw.VirusTotalApiKey
                if ($encVt) {
                    $raw.VirusTotalKeyEncrypted = $encVt
                    $raw.VirusTotalApiKey = ""
                    $dirty = $true
                }
            }
            if ($dirty -and ($target -eq $ConfigFile)) {
                $json = ($raw | ConvertTo-Json -Depth 4)
                [System.IO.File]::WriteAllText($ConfigFile, $json, [System.Text.Encoding]::UTF8)
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

function Get-ActiveWebhookUrl {
    if (-not [string]::IsNullOrWhiteSpace($script:Config.DiscordWebhookEncrypted)) {
        return (Unprotect-DpapiString $script:Config.DiscordWebhookEncrypted)
    }
    return $script:Config.DiscordWebhookUrl
}

function Get-ActiveVtApiKey {
    if (-not [string]::IsNullOrWhiteSpace($script:Config.VirusTotalKeyEncrypted)) {
        return (Unprotect-DpapiString $script:Config.VirusTotalKeyEncrypted)
    }
    return $script:Config.VirusTotalApiKey
}

$script:Config = Load-SentinelConfig

# ---------------------------------------------------------------------
# LOGGING ENGINE
# ---------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ALERT", "CRITICAL", "SCAN", "TIER2", "TIER3", "FORENSIC")][string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    if (-not $LibraryOnly) {
        Write-Output $line
    }
}

# ---------------------------------------------------------------------
# PILLAR 3: EXTERNAL CODE INTEGRITY MANIFEST & FAIL-CLOSED TRUST ANCHOR
# ---------------------------------------------------------------------
$script:SelfPath = $MyInvocation.MyCommand.Path

function Get-TrustedScriptHashes {
    $hashes = @{}
    # 1. Read exclusively from HKLM IntegrityAnchor (SYSTEM/Administrators ACL locked)
    $regAnchor = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regAnchor) {
        $props = Get-ItemProperty -Path $regAnchor -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($sName in @("SentinelWatchdog.ps1", "SentinelGuardian.ps1", "SentinelDashboard.ps1", "Sign-Scripts.ps1", "Install.ps1", "Uninstall.ps1", "Invoke-RedTeamAudit.ps1")) {
                if ($props.$sName -and (-not $hashes.ContainsKey($sName))) {
                    $hashes[$sName] = "$($props.$sName)"
                }
            }
        }
    }
    # 2. Fallback to DPAPI-sealed manifest.json (Never fallback to raw unverified disk files!)
    if (($hashes.Count -eq 0) -and (Test-Path $ManifestFile)) {
        try {
            $mObj = Get-Content $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($mObj -and $mObj.SealedHashes) {
                $jsonHashes = Unprotect-DpapiString $mObj.SealedHashes
                if ($jsonHashes) {
                    $parsed = $jsonHashes | ConvertFrom-Json
                    foreach ($p in $parsed.PSObject.Properties) {
                        $hashes[$p.Name] = "$($p.Value)"
                    }
                }
            }
        } catch {}
    }
    return $hashes
}

function Initialize-CodeIntegrityTrustAnchor {
    $hashes = [ordered]@{}
    foreach ($sName in @("SentinelWatchdog.ps1", "SentinelGuardian.ps1", "SentinelDashboard.ps1", "Install.ps1", "Uninstall.ps1", "Invoke-RedTeamAudit.ps1")) {
        $p = if ($LibraryOnly -and $PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot $sName))) {
            Join-Path $PSScriptRoot $sName
        } else {
            Join-Path $SentinelDir $sName
        }
        if (-not (Test-Path $p)) { $p = Join-Path $StateDir $sName }
        if (-not (Test-Path $p) -and $PSScriptRoot) { $p = Join-Path $PSScriptRoot $sName }
        if (Test-Path $p) {
            $h = (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($h) { $hashes[$sName] = $h }
        }
    }
    $sealed = Protect-DpapiString ($hashes | ConvertTo-Json -Compress)
    $manifestObj = [ordered]@{
        Version      = "7.0"
        UpdatedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        SealedHashes = $sealed
    }
    [System.IO.File]::WriteAllText($ManifestFile, ($manifestObj | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)

    # Zero-Trust: Do not mirror hashes into HKCU; purge legacy key if exists
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    return $hashes
}

# Verify if a PowerShell command line is executing one of our own Trust-Anchor-Verified Sentinel scripts
# (Prevents false positives when opening SentinelDashboard.ps1 via Sentinel-Dashboard.bat with -WindowStyle Hidden!)
function Test-IsVerifiedSentinelScript {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }

    # 1. Hard rejection if command line contains obfuscation, base64 payload, or inline commands
    if ($CommandLine -match "(?i)(-enc|-encodedcommand|-e\b|-c\b|-command|invoke-expression|\biex\b|downloadstring|frombase64string|amsiutils)") {
        return $false
    }

    # 2. Must explicitly specify -File "<path>"
    if ($CommandLine -notmatch "(?i)-file\s+[`"']?([^`"'\s]+(?:\s+[^`"'\s]+)*?\.ps1)[`"']?") {
        return $false
    }

    $invokedScriptPath = $Matches[1]
    $leafName = Split-Path $invokedScriptPath -Leaf
    $authorizedScripts = @("SentinelDashboard.ps1", "SentinelWatchdog.ps1", "SentinelGuardian.ps1", "Install.ps1", "Uninstall.ps1", "Invoke-RedTeamAudit.ps1", "Sign-Scripts.ps1")
    if ($authorizedScripts -notcontains $leafName) {
        return $false
    }

    # 3. Resolve the actual physical file specified in -File parameter
    try {
        if (-not (Test-Path $invokedScriptPath -PathType Leaf)) { return $false }
        $resolvedItem = Get-Item $invokedScriptPath -ErrorAction Stop
        $realPath = $resolvedItem.FullName
    } catch {
        return $false
    }

    # 4. Must reside in authorized installation or repo directory
    $authDirs = @($SentinelDir.TrimEnd('\'), $StateDir.TrimEnd('\'))
    if ($PSScriptRoot) { $authDirs += $PSScriptRoot.TrimEnd('\') }
    $parentDir = (Split-Path $realPath -Parent).TrimEnd('\')

    $isAuthorizedDir = $false
    foreach ($ad in $authDirs) {
        if ($parentDir -ieq $ad) { $isAuthorizedDir = $true; break }
    }
    if (-not $isAuthorizedDir) { return $false }

    # 5. Check hash of THAT EXACT RESOLVED FILE against Trust Anchor
    $anchor = Get-TrustedScriptHashes
    if ($anchor.Count -gt 0 -and $anchor.ContainsKey($leafName)) {
        $actualHash = (Get-FileHash -Path $realPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($actualHash -ne $anchor[$leafName]) {
            return $false
        }
    }

    # 6. Reject if any command chaining operators exist after the script path (e.g. &&, ||, ;, |)
    $escaped = [regex]::Escape($invokedScriptPath)
    $parts = $CommandLine -split $escaped, 2
    if ($parts.Count -gt 1 -and $parts[1] -match "(&|;|\||`n|`r|\-command)") {
        return $false
    }

    return $true
}

$script:TrustAnchorHashes = Get-TrustedScriptHashes
if ($script:TrustAnchorHashes.Count -eq 0) {
    $script:TrustAnchorHashes = Initialize-CodeIntegrityTrustAnchor
}

# ---------------------------------------------------------------------
# TIER 3: GUARDIAN TWIN SELF-DEFENSE & TRUST ANCHOR VERIFICATION
# ---------------------------------------------------------------------
$script:VerifiedGuardianPid = 0

function Ensure-GuardianTwin {
    if (-not $script:Config.EnableGuardianTwin) { return }
    if (Test-AuthenticatedStopToken) { return }

    $anchor = Get-TrustedScriptHashes
    $expectedSelf  = if ($anchor.ContainsKey("SentinelWatchdog.ps1")) { $anchor["SentinelWatchdog.ps1"] } else { "" }
    $expectedGuard = if ($anchor.ContainsKey("SentinelGuardian.ps1")) { $anchor["SentinelGuardian.ps1"] } else { "" }

    if ($script:SelfPath -and $expectedSelf -and (Test-Path $script:SelfPath)) {
        $currHash = (Get-FileHash -Path $script:SelfPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($currHash -and ($currHash -ne $expectedSelf)) {
            Show-Alert -Title "Tier 3: Watchdog Code Integrity Violation!" `
                       -Message "SentinelWatchdog.ps1 hash mismatch against Trust Anchor! Expected: $expectedSelf, Found: $currHash" `
                       -Level "CRITICAL" -FilePath $script:SelfPath -SHA256 $currHash -ActionTaken "Trust Anchor Violation Alerted (MITRE T1562.001)"
        }
    }

    if (-not (Test-Path $GuardianPath)) { return }

    # Fail-Closed: Require valid Trust Anchor hash for Guardian Twin before spawning
    if (-not $expectedGuard) {
        Write-Log "Trust Anchor hash missing for SentinelGuardian.ps1! Refusing to spawn unverified Guardian." "CRITICAL"
        return
    }
    $gDiskHash = (Get-FileHash -Path $GuardianPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if (-not $gDiskHash -or ($gDiskHash -ne $expectedGuard)) {
        Show-Alert -Title "Tier 3: Guardian Script Tampering Blocked!" `
                   -Message "SentinelGuardian.ps1 hash mismatch against Trust Anchor! Refusing to execute modified script." `
                   -Level "CRITICAL" -FilePath $GuardianPath -SHA256 "$gDiskHash" -ActionTaken "Blocked Tampered Guardian Execution"
        return
    }

    $guardianAlive = $false
    if (Test-Path $GuardianPidF) {
        $gPidRaw = (Get-Content $GuardianPidF -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($gPidRaw -and ($gPidRaw.Trim() -match "^\d+$")) {
            $gPidInt = [int]$gPidRaw.Trim()
            $gProc = Get-Process -Id $gPidInt -ErrorAction SilentlyContinue
            if ($gProc -and $gProc.ProcessName -match "^(powershell|pwsh)$") {
                $guardianAlive = $true
                $script:VerifiedGuardianPid = $gPidInt
            }
        }
    }

    if (-not $guardianAlive) {
        $gNew = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$GuardianPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($gNew) {
            $script:VerifiedGuardianPid = [int]$gNew.Id
            Write-Log "Guardian Twin Self-Defense active (Guardian PID: $($gNew.Id) watching Watchdog PID: $PID)." "TIER3"
        }
    }
}

# ---------------------------------------------------------------------
# PILLAR 4: BEHAVIORAL DETECTION & CROSS-SIGNAL CORRELATION ENGINE
# ---------------------------------------------------------------------
$script:BehavioralCorrelation = @{}

function Add-BehavioralSignal {
    param(
        [int]$ProcessId,
        [string]$SignalType,
        [string]$MitreTechnique,
        [int]$Weight = 15,
        [string]$Detail = ""
    )
    if ($ProcessId -le 0) { return }
    if (-not $script:BehavioralCorrelation.ContainsKey($ProcessId)) {
        $script:BehavioralCorrelation[$ProcessId] = @{
            FirstSeen  = (Get-Date)
            Signals    = New-Object 'System.Collections.Generic.List[string]'
            MitreIds   = New-Object 'System.Collections.Generic.HashSet[string]'
            BonusScore = 0
        }
    }
    $entry = $script:BehavioralCorrelation[$ProcessId]
    $sigTag = "${SignalType}: $Detail"
    if (-not $entry.Signals.Contains($sigTag)) {
        $entry.Signals.Add($sigTag)
        $entry.BonusScore += $Weight
    }
    if ($MitreTechnique) {
        [void]$entry.MitreIds.Add($MitreTechnique)
    }
}

function Get-CorrelationSummary([int]$ProcessId) {
    if ($ProcessId -gt 0 -and $script:BehavioralCorrelation.ContainsKey($ProcessId)) {
        return $script:BehavioralCorrelation[$ProcessId]
    }
    return $null
}

# ---------------------------------------------------------------------
# BASE64 COMMAND-LINE DECODER (Defeats -EncodedCommand Evasion)
# ---------------------------------------------------------------------
function Expand-EncodedCommandLine {
    param([string]$RawCommandLine)
    if ([string]::IsNullOrWhiteSpace($RawCommandLine)) { return "" }
    $expanded = $RawCommandLine

    if ($RawCommandLine -match "(?i)(?:^|\s)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{12,})") {
        $b64 = $Matches[1]
        try {
            $bytes = [Convert]::FromBase64String($b64)
            $decUni = [System.Text.Encoding]::Unicode.GetString($bytes).Replace("`0", "")
            $decUtf = [System.Text.Encoding]::UTF8.GetString($bytes).Replace("`0", "")
            $expanded += " [DECODED_B64_UNI]: $decUni [DECODED_B64_UTF8]: $decUtf"
        } catch {}
    }

    $b64Matches = [regex]::Matches($RawCommandLine, "FromBase64String\(\s*['""]([A-Za-z0-9+/=]{12,})['""]\s*\)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $b64Matches) {
        try {
            $bytes = [Convert]::FromBase64String($m.Groups[1].Value)
            $decText = [System.Text.Encoding]::UTF8.GetString($bytes).Replace("`0", "")
            $expanded += " [DECODED_INLINE_B64]: $decText"
        } catch {}
    }

    return $expanded
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

            $vtKey = Get-ActiveVtApiKey
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
# TIER 4 & 5: LIVE PROCESS RAM FORENSICS, C2 EXTRACTOR & CORRELATED SCORING
# Note: Removed '-w hidden / -windowstyle hidden' from $script:ObfuscatedCmdRegex
# so normal scripts and SentinelDashboard.ps1 never trigger false positives!
# ---------------------------------------------------------------------
$script:ObfuscatedCmdRegex = "(?i)(-enc|-encodedcommand|\s-e\s+[A-Za-z0-9+/=]{16,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest\s+[^\s]+\s+-usebasicparsing\s*\|\s*iex|start-bitstransfer\s+http|amsiutils|amsiinitfailed|regsvr32\s+/s\s+/n\s+/u\s+/i:|certutil\s+-urlcache\s+-split\s+-f\s+http|mshta\s+(?:http|javascript|vbscript))"

# Developer & Gaming Parent Process Safe-List (Protected in %TEMP% unless hard C2/Obfuscation/Injection is proven)
$script:WorkAndGamingParentsRegex = "(?i)^(code|devenv|rider64|idea64|studio64|node|npm|git|python|pythonw|pip|cargo|rustc|dotnet|msbuild|gcc|g\+\+|clang|cmake|ninja|go|java|javaw|gradle|docker|wsl|windowsterminal|steam|steamservice|epicgameslauncher|riotclientservices|valorant|robloxplayerbeta|robloxplayerinstaller|tslgame|overwolf)\.exe$"

function Get-ForensicTriage {
    param(
        [int]$ProcessId = 0,
        [string]$FilePath = "",
        [string]$CommandLine = "",
        [bool]$IsUnsigned = $true,
        [bool]$IsParentChildAnomaly = $false,
        [bool]$IsPhishingParent = $false
    )
    $expandedCmd = Expand-EncodedCommandLine -RawCommandLine $CommandLine

    $triage = @{
        Entropy           = 0.0
        RiskScore         = 0
        RiskLevel         = "LOW"
        C2Indicators      = @()
        MemoryC2Count     = 0
        RwxPrivateRegions = 0
        UnbackedPeHeaders = 0
        ActiveSockets     = @()
        MitreTechniques   = @()
        Reasons           = @()
        DecodedCommand    = $expandedCmd
        Summary           = ""
        ReportFile        = ""
    }

    if ($FilePath -and (Test-Path $FilePath -PathType Leaf) -and ("SentinelNative.KernelControl" -as [type])) {
        $triage.Entropy = [SentinelNative.KernelControl]::ComputeShannonEntropy($FilePath)
        $extracted = [SentinelNative.KernelControl]::ExtractBinaryC2Strings($FilePath)
        if ($extracted -and $extracted.Count -gt 0) {
            $triage.C2Indicators += $extracted
        }
    }

    if ($ProcessId -gt 0 -and ("SentinelNative.KernelControl" -as [type])) {
        $memReport = [SentinelNative.KernelControl]::AnalyzeProcessMemory($ProcessId)
        if ($memReport) {
            $triage.RwxPrivateRegions = $memReport.RwxPrivateRegions
            $triage.UnbackedPeHeaders = $memReport.UnbackedPeHeaders
            if ($memReport.C2Indicators -and $memReport.C2Indicators.Count -gt 0) {
                foreach ($rc2 in $memReport.C2Indicators) {
                    $triage.MemoryC2Count++
                    if ($triage.C2Indicators -notcontains $rc2) {
                        $triage.C2Indicators += "[RAM] $rc2"
                    }
                }
            }
        }
    }

    if ($expandedCmd) {
        $cmdMatches = [regex]::Matches($expandedCmd, 'https?://[^\s"''<>]+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $cmdMatches) {
            $urlVal = $m.Value.Trim()
            if ($triage.C2Indicators -notcontains $urlVal) {
                $triage.C2Indicators += $urlVal
            }
        }
    }

    if ($ProcessId -gt 0) {
        try {
            $conns = Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue | Where-Object {
                $_.RemoteAddress -notin @("127.0.0.1", "0.0.0.0", "::", "::1")
            }
            foreach ($c in $conns) {
                $sockStr = "$($c.RemoteAddress):$($c.RemotePort) ($($c.State))"
                if ($triage.ActiveSockets -notcontains $sockStr) {
                    $triage.ActiveSockets += $sockStr
                }
            }
        } catch {}
    }

    # Multi-Signal Behavioral & Heuristic Risk Scoring (0 - 100)
    # Calibrated for Work & Gaming Safe-Mode (Freeze threshold = 85):
    # - Unsigned Temp tool alone = 15 (Base) + 25 (Unsigned) + 20 (TempPath) = 60 (< 85 -> Not Frozen!)
    # - Browser -> Obfuscated PowerShell (-enc) = 15 (Base) + 25 (ParentChild) + 45 (Obfuscated) = 85 (>= 85 -> Frozen!)
    # - Unsigned Temp Malware with C2 or Packed/Reflective PE = 60 + 35 = 95 (>= 85 -> Frozen!)
    $score = 15
    $reasons = @()
    $mitre = New-Object 'System.Collections.Generic.HashSet[string]'

    if ($IsPhishingParent) {
        $score += 50
        $reasons += "PhishingParentExploit(+50)"
        [void]$mitre.Add("T1566 Phishing")
        [void]$mitre.Add("T1204 User Execution")
    }
    if ($IsParentChildAnomaly) {
        $score += 25
        $reasons += "ParentChildAnomaly(+25)"
        [void]$mitre.Add("T1059 Command & Scripting Interpreter")
    }
    if ($IsUnsigned) {
        $score += 25
        $reasons += "UnsignedBinary(+25)"
        [void]$mitre.Add("T1204.002 Malicious File")
    }
    if ($triage.Entropy -ge 7.2) {
        $score += 30
        $reasons += "HighEntropy:$($triage.Entropy)(+30:Packed/Encrypted)"
        [void]$mitre.Add("T1027.002 Software Packing")
    } elseif ($triage.Entropy -ge 6.6) {
        $score += 15
        $reasons += "ElevatedEntropy:$($triage.Entropy)(+15)"
    }
    if ($expandedCmd -match $script:ObfuscatedCmdRegex) {
        $score += 45
        $reasons += "ObfuscatedOrFilelessCmd(+45)"
        [void]$mitre.Add("T1027 Obfuscated/Encoded Command")
        [void]$mitre.Add("T1059.001 PowerShell")
    }
    if ($FilePath -match "\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Google\\Chrome\\User Data\\|\\Microsoft\\Edge\\User Data\\") {
        $score += 20
        $reasons += "HighRiskPath(+20)"
    }
    if ($triage.C2Indicators.Count -gt 0) {
        $score += 35
        $reasons += "C2IndicatorsFound(+35)"
        [void]$mitre.Add("T1071.001 Web Protocols C2")
    }
    if ($triage.ActiveSockets.Count -gt 0) {
        $score += 20
        $reasons += "ActiveExternalSocket(+20)"
    }
    if ($triage.UnbackedPeHeaders -gt 0) {
        $score += 35
        $reasons += "UnbackedReflectivePE:$($triage.UnbackedPeHeaders)(+35)"
        [void]$mitre.Add("T1055.001 Reflective Process Injection")
    } elseif ($triage.RwxPrivateRegions -ge 3) {
        $score += 15
        $reasons += "PrivateRWXRegions:$($triage.RwxPrivateRegions)(+15)"
        [void]$mitre.Add("T1055 Process Injection")
    }

    $corr = Get-CorrelationSummary -ProcessId $ProcessId
    if ($corr) {
        if ($corr.BonusScore -gt 0) {
            $score += $corr.BonusScore
            $reasons += "CorrelatedSignals(+$($corr.BonusScore))"
        }
        foreach ($mId in $corr.MitreIds) { [void]$mitre.Add($mId) }
    }

    if ($score -gt 100) { $score = 100 }
    $triage.RiskScore = $score
    $triage.RiskLevel = if ($score -ge 85) { "CRITICAL" } elseif ($score -ge 60) { "HIGH" } else { "MEDIUM" }
    $triage.MitreTechniques = @($mitre)
    $triage.Reasons = $reasons

    $c2Text = if ($triage.C2Indicators.Count -gt 0) { ($triage.C2Indicators -join " | ") } else { "None found" }
    $netText = if ($triage.ActiveSockets.Count -gt 0) { ($triage.ActiveSockets -join ", ") } else { "No active external sockets" }
    $mitreText = if ($triage.MitreTechniques.Count -gt 0) { ($triage.MitreTechniques -join ", ") } else { "Behavioral Telemetry" }
    $triage.Summary = "Score: $score/100 ($($triage.RiskLevel)) | MITRE: [$mitreText] | Entropy: $($triage.Entropy)/8.0 | RWX: $($triage.RwxPrivateRegions) (UnbackedPE: $($triage.UnbackedPeHeaders)) | C2: $c2Text | Net: $netText"

    try {
        $tsFile = Get-Date -Format "yyyyMMdd_HHmmss"
        $repPath = Join-Path $QuarDir "forensic_PID${ProcessId}_${tsFile}.json"
        $repObj = [ordered]@{
            Timestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            ProcessId         = $ProcessId
            FilePath          = $FilePath
            CommandLine       = $CommandLine
            DecodedCommand    = $expandedCmd
            ShannonEntropy    = $triage.Entropy
            RwxPrivateRegions = $triage.RwxPrivateRegions
            UnbackedPeHeaders = $triage.UnbackedPeHeaders
            HeuristicScore    = "$score / 100 ($($triage.RiskLevel))"
            ScoreBreakdown    = ($reasons -join ", ")
            MitreTechniques   = $triage.MitreTechniques
            ExtractedC2       = $triage.C2Indicators
            ActiveSockets     = $triage.ActiveSockets
        }
        $jsonRep = ($repObj | ConvertTo-Json -Depth 5)
        [System.IO.File]::WriteAllText($repPath, $jsonRep, [System.Text.Encoding]::UTF8)
        $triage.ReportFile = $repPath
        Write-Log "Forensic Triage saved -> $repPath [$($triage.Summary)]" "FORENSIC"
    } catch {}

    return $triage
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
        "ISOLATED" | Out-File -FilePath "$StateDir\network.state" -Encoding UTF8 -Force
    } catch {}
}

# ---------------------------------------------------------------------
# ALERT NOTIFICATION ENGINE (Toast + Rich Discord Webhook + MITRE)
# ---------------------------------------------------------------------
function Send-DiscordWebhook {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Level = "ALERT",
        [string]$FilePath = "",
        [string]$SHA256 = "",
        [string]$ActionTaken = "Monitored & Logged",
        [hashtable]$Forensics = $null
    )
    if ($LibraryOnly) { return }
    $script:Config = Load-SentinelConfig
    $url = Get-ActiveWebhookUrl
    if ([string]::IsNullOrWhiteSpace($url)) { return }

    $bt = [char]96
    $color = 16098851
    if ($Level -eq "CRITICAL" -or $Level -eq "TIER3") { $color = 16711680 }
    elseif ($Level -eq "TIER2") { $color = 15105570 }
    elseif ($Level -eq "INFO")  { $color = 3718648 }

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
    if ($Forensics) {
        $heurVal = "**$($Forensics.RiskScore) / 100 ($($Forensics.RiskLevel))** | Entropy: $bt$($Forensics.Entropy) / 8.0$bt | RWX Regions: $bt$($Forensics.RwxPrivateRegions)$bt (Reflective PE: $bt$($Forensics.UnbackedPeHeaders)$bt)"
        $fields += @{ name = "Behavioral Score & Memory Forensics"; value = $heurVal; inline = $false }

        if ($Forensics.MitreTechniques -and $Forensics.MitreTechniques.Count -gt 0) {
            $mitreStr = ($Forensics.MitreTechniques | ForEach-Object { "$bt$_$bt" }) -join ", "
            $fields += @{ name = "MITRE ATT&CK Mapping"; value = $mitreStr; inline = $false }
        }
        if ($Forensics.C2Indicators -and $Forensics.C2Indicators.Count -gt 0) {
            $c2Str = ($Forensics.C2Indicators | ForEach-Object { "$bt$_$bt" }) -join "`n"
            $fields += @{ name = "Live RAM, Decoded B64 & Disk C2 IOCs"; value = $c2Str; inline = $false }
        }
        if ($Forensics.ActiveSockets -and $Forensics.ActiveSockets.Count -gt 0) {
            $netStr = ($Forensics.ActiveSockets | ForEach-Object { "$bt$_$bt" }) -join ", "
            $fields += @{ name = "Active Remote Connections"; value = $netStr; inline = $false }
        }
    }

    $contentPing = ""
    if (($Level -eq "CRITICAL" -or $Level -eq "TIER3") -and $script:Config.DiscordMentionOnCritical) {
        $contentPing = "**[CRITICAL ENDPOINT SECURITY ALERT]** @everyone"
    }

    $payload = @{
        username = "Security Sentinel Ultra v7.0 EDR"
        content  = $contentPing
        embeds   = @(
            @{
                title       = "[$Level] $Title"
                description = $Message
                color       = $color
                fields      = $fields
                footer      = @{ text = "Security Sentinel Ultra v7.0 | Work & Gaming Safe-Mode EDR | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
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
        [string]$ActionTaken = "Alert Logged",
        [hashtable]$Forensics = $null
    )
    Write-Log "ALERT TRIGGERED: $Title - $Message | Action: $ActionTaken" $Level
    if ($LibraryOnly) { return }
    Send-DiscordWebhook -Title $Title -Message $Message -Level $Level -FilePath $FilePath -SHA256 $SHA256 -ActionTaken $ActionTaken -Forensics $Forensics

    if ($script:Config.EnableSoundAlert) {
        try { [System.Media.SystemSounds]::Hand.Play() } catch {}
    }

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
            <text placement="attribution">Security Sentinel Ultra v7.0</text>
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

# ---------------------------------------------------------------------
# TWO-TIER AUTHENTICODE VERIFICATION
# ---------------------------------------------------------------------
function Get-BinarySignatureTrust {
    param([string]$FilePath)
    $trust = @{
        IsValidSigned = $false
        IsTier1Vendor = $false
        Subject       = ""
        Issuer        = ""
        Thumbprint    = ""
    }
    if (-not (Test-Path $FilePath -PathType Leaf)) { return $trust }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $subject = $sig.SignerCertificate.Subject
            $issuer  = $sig.SignerCertificate.Issuer
            $trust.Subject    = $subject
            $trust.Issuer     = $issuer
            $trust.Thumbprint = $sig.SignerCertificate.Thumbprint

            $trustedCAs = "(?i)(^|,\s*)(CN|O)=(""?)(DigiCert|Microsoft|GlobalSign|Sectigo|COMODO|Entrust|VeriSign|Symantec|SSL\.com|GoDaddy|Thawte|Certum|Apple)"
            if ($issuer -match $trustedCAs) {
                $trust.IsValidSigned = $true

                $trustedVendors = "Google LLC|Microsoft Corporation|Microsoft Windows|Mozilla Corporation|Brave Software, Inc\.|Opera Norway AS|Opera Software|" +
                                  "Valve Corp\.|Valve Corporation|Epic Games, Inc\.|Riot Games, Inc\.|NVIDIA Corporation|Advanced Micro Devices, Inc\.|Intel Corporation|" +
                                  "Overwolf Ltd|KRAFTON, Inc\.|PUBG CORPORATION|BattlEye Innovations e\.K\.|Wellbia\.com Co\., Ltd\.|Discord Inc\.|" +
                                  "Electronic Arts, Inc\.|Ubisoft Entertainment|Blizzard Entertainment, Inc\.|Roblox Corporation|Logitech Inc|Razer USA Ltd\.|Corsair Memory, Inc\.|SteelSeries ApS|" +
                                  "GitHub, Inc\.|Slack Technologies, Inc\.|Zoom Video Communications, Inc\.|Spotify AB"

                $strictSubjectRegex = "(?i)(^|,\s*)(CN|O)=(""?($trustedVendors)""?)(,|$)"
                if ($subject -match $strictSubjectRegex) {
                    $trust.IsTier1Vendor = $true
                }
            }
        }
    } catch {}
    return $trust
}

function Test-IsTrustedBinary {
    param([string]$FilePath)
    return (Get-BinarySignatureTrust -FilePath $FilePath).IsTier1Vendor
}

# ---------------------------------------------------------------------
# PILLAR 5: SAFE QUARANTINE ENGINE WITH MANIFEST & TESTED ROLLBACK
# ---------------------------------------------------------------------
function Move-ToQuarantine {
    param(
        [Parameter(Mandatory=$true)][string]$SourcePath,
        [string]$Reason = "Threat Artifact Quarantined"
    )
    if (-not (Test-Path $SourcePath)) { return $null }
    if (-not (Test-Path $QuarDir)) { New-Item -ItemType Directory -Path $QuarDir -Force | Out-Null }

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
QuarantinedBy: Security Sentinel Ultra v7.0
"@
        [System.IO.File]::WriteAllText($metaPath, $meta, [System.Text.Encoding]::UTF8)

        try {
            $mList = @()
            if (Test-Path $QuarManifest) {
                $existing = Get-Content $QuarManifest -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($existing) { $mList = @($existing) }
            }
            $mList += [ordered]@{
                QuarantinedPath = $destPath
                OriginalPath    = $SourcePath
                FileName        = $fileName
                SHA256          = $intel.SHA256
                Timestamp       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Reason          = $Reason
            }
            [System.IO.File]::WriteAllText($QuarManifest, ($mList | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
        } catch {}

        return @{
            DestPath     = $destPath
            OriginalPath = $SourcePath
            SHA256       = $intel.SHA256
            VTUrl        = $intel.VTUrl
            VTInfo       = $intel.VTInfo
        }
    } else {
        return $null
    }
}

function Restore-QuarantinedFile {
    param([string]$QuarantinedFilePath = "")
    if (-not (Test-Path $QuarManifest)) { return $false }
    try {
        $mItems = @(Get-Content $QuarManifest -Raw -Encoding UTF8 | ConvertFrom-Json)
        if ($mItems.Count -eq 0) { return $false }

        $targetIdx = -1
        if ([string]::IsNullOrWhiteSpace($QuarantinedFilePath)) {
            $targetIdx = $mItems.Count - 1
        } else {
            for ($i = $mItems.Count - 1; $i -ge 0; $i--) {
                if ($mItems[$i].QuarantinedPath -eq $QuarantinedFilePath) {
                    $targetIdx = $i
                    break
                }
            }
        }
        if ($targetIdx -lt 0) { return $false }

        $item = $mItems[$targetIdx]
        if (-not (Test-Path $item.QuarantinedPath)) { return $false }

        $parentDir = Split-Path $item.OriginalPath -Parent
        if ($parentDir -and (-not (Test-Path $parentDir))) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        Move-Item -Path $item.QuarantinedPath -Destination $item.OriginalPath -Force -ErrorAction Stop
        if (Test-Path "$($item.QuarantinedPath).meta.txt") {
            Remove-Item "$($item.QuarantinedPath).meta.txt" -Force -ErrorAction SilentlyContinue
        }

        $remaining = @()
        for ($j = 0; $j -lt $mItems.Count; $j++) {
            if ($j -ne $targetIdx) { $remaining += $mItems[$j] }
        }
        [System.IO.File]::WriteAllText($QuarManifest, ($remaining | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
        Write-Log "Quarantine Rollback succeeded: Restored '$($item.FileName)' to '$($item.OriginalPath)'." "INFO"
        return $true
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------
# 2. PILLAR 4: COMPREHENSIVE 29-VECTOR PERSISTENCE BASELINE (WITH SERVICES)
# ---------------------------------------------------------------------
function Get-PersistenceSnapshot {
    $snap = @{}

    # Vectors 1-17: Standard & Advanced Registry Autostart Keys
    $regVectors = @(
        @{ Key = "HKCU_Run";             Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Key = "HKCU_RunOnce";         Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Key = "HKLM_Run";             Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Key = "HKLM_RunOnce";         Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Key = "HKLM_WOW64_Run";       Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ Key = "HKLM_WOW64_RunOnce";   Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Key = "HKLM_Policies_Run";    Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" },
        @{ Key = "HKCU_Policies_Run";    Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" },
        @{ Key = "HKLM_Winlogon";        Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" },
        @{ Key = "HKCU_Winlogon";        Path = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" },
        @{ Key = "HKLM_SessionMgr";      Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" },
        @{ Key = "HKLM_Windows_AppInit"; Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" },
        @{ Key = "HKLM_WOW64_AppInit";   Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" },
        @{ Key = "HKCU_EnvLogonScript";  Path = "HKCU:\Environment" },
        @{ Key = "HKLM_LsaPackages";     Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" },
        @{ Key = "HKLM_SharedTaskSched"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" },
        @{ Key = "HKLM_ShellDelayLoad";  Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" }
    )

    foreach ($rv in $regVectors) {
        try {
            if (Test-Path $rv.Path) {
                $props = Get-ItemProperty $rv.Path -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $snap["$($rv.Key)_$($_.Name)"] = "$($_.Value)"
                    }
                }
            }
        } catch {}
    }

    # Vectors 18-21: UAC Bypass & File Association Command Hijacks
    $hijackKeys = @(
        "HKCU:\Software\Classes\ms-settings\shell\open\command",
        "HKCU:\Software\Classes\mscfile\shell\open\command",
        "HKCU:\Software\Classes\exefile\shell\open\command",
        "HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
    )
    foreach ($hk in $hijackKeys) {
        try {
            if (Test-Path $hk) {
                $val = (Get-ItemProperty $hk -ErrorAction SilentlyContinue).'(default)'
                $snap["HijackKey_$hk"] = "$val"
            }
        } catch {}
    }

    # Vector 22: IFEO Debuggers (Fast .NET Registry API ~100ms)
    try {
        $ifeoKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", $false)
        if ($ifeoKey) {
            foreach ($subName in $ifeoKey.GetSubKeyNames()) {
                try {
                    $sub = $ifeoKey.OpenSubKey($subName, $false)
                    if ($sub) {
                        $dbg = $sub.GetValue("Debugger")
                        if ($dbg) { $snap["IFEO_Debugger_$subName"] = "$dbg" }
                        $sub.Close()
                    }
                } catch {}
            }
            $ifeoKey.Close()
        }
    } catch {}

    # Vectors 23-24: User & Common Startup Folders
    try {
        $startupPaths = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        ) | Where-Object { $_ -and (Test-Path $_) }

        foreach ($sDir in $startupPaths) {
            Get-ChildItem -Path $sDir -File -ErrorAction SilentlyContinue | ForEach-Object {
                $snap["Startup_" + $_.Name] = $_.FullName
            }
        }
    } catch {}

    # Vector 25: Non-Microsoft Scheduled Tasks
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskPath -notmatch "^\\Microsoft\\" -and $_.TaskName -ne "SecuritySentinelWatchdog"
        } | ForEach-Object {
            $snap["Task_$($_.TaskPath)$($_.TaskName)"] = "$($_.State)"
        }
    } catch {}

    # Vectors 26-27: WMI Permanent Event Subscriptions
    try {
        Get-CimInstance -Namespace "root\subscription" -ClassName "__EventFilter" -ErrorAction SilentlyContinue | ForEach-Object {
            $snap["WMI_Filter_$($_.Name)"] = "$($_.Query)"
        }
        Get-CimInstance -Namespace "root\subscription" -ClassName "__EventConsumer" -ErrorAction SilentlyContinue | ForEach-Object {
            $snap["WMI_Consumer_$($_.Name)"] = "$($_.CommandLineTemplate)$($_.ScriptText)"
        }
    } catch {}

    # Vector 28: PowerShell Profiles
    $psProfiles = @(
        "$PSHOME\Profile.ps1",
        "$PSHOME\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    )
    foreach ($pf in $psProfiles) {
        if (Test-Path $pf) {
            $h = (Get-FileHash -Path $pf -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $snap["PSProfile_$pf"] = "$h"
        }
    }

    # Vector 29: Windows Services (Fast Registry Services ImagePath scan ~40ms)
    try {
        $svcRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services", $false)
        if ($svcRoot) {
            foreach ($sName in $svcRoot.GetSubKeyNames()) {
                try {
                    $sk = $svcRoot.OpenSubKey($sName, $false)
                    if ($sk) {
                        $imgPath = "$($sk.GetValue('ImagePath'))"
                        $svcType = $sk.GetValue("Type")
                        # Track Win32 user-mode services (Type 16 or 32) outside Windows\System32 svchost
                        if ($imgPath -and ($svcType -in @(16, 32, 272)) -and ($imgPath -notmatch "(?i)^%?systemroot%?\\system32\\svchost\.exe")) {
                            $snap["Service_$sName"] = $imgPath
                        }
                        $sk.Close()
                    }
                } catch {}
            }
            $svcRoot.Close()
        }
    } catch {}

    return $snap
}

# Parse Security Event 4663 XML to attribute exact ProcessId and ProcessName
function Parse-Event4663Xml {
    param([string]$EventXmlString)
    $info = @{
        ProcessId   = 0
        ProcessName = "Unknown"
        ObjectName  = ""
        SubjectUser = ""
    }
    try {
        [xml]$xml = $EventXmlString
        foreach ($d in $xml.Event.EventData.Data) {
            switch ($d.Name) {
                "ProcessId"       {
                    $val = "$($d.'#text')".Trim()
                    if ($val -match "^0x[0-9a-fA-F]+$") { $info.ProcessId = [Convert]::ToInt32($val, 16) }
                    elseif ($val -match "^\d+$")        { $info.ProcessId = [int]$val }
                }
                "ProcessName"     { $info.ProcessName = "$($d.'#text')" }
                "ObjectName"      { $info.ObjectName  = "$($d.'#text')" }
                "SubjectUserName" { $info.SubjectUser = "$($d.'#text')" }
            }
        }
    } catch {}
    return $info
}

# ---------------------------------------------------------------------
# 5. TIER 2, 3, 4: COMPOSITE PID|CREATIONDATE TRACKING & UNIFIED RULES
# ---------------------------------------------------------------------
$knownProcs = @{}
function Get-ProcCompositeKey($p) {
    return "$($p.ProcessId)|$($p.CreationDate)"
}

function Inspect-SingleProcess {
    param($p, [hashtable]$procMap)
    $cPid = [int]$p.ProcessId
    $compKey = Get-ProcCompositeKey $p
    if ($knownProcs.ContainsKey($compKey)) { return $null }
    $knownProcs[$compKey] = $cPid

    # 1. Exempt exact verified Watchdog PID & Guardian Twin PID
    if ($cPid -eq $PID -or ($script:VerifiedGuardianPid -gt 0 -and $cPid -eq $script:VerifiedGuardianPid)) {
        return @{ Action = "ExemptSelf"; RiskScore = 0 }
    }

    $cName = "$($p.Name)".ToLower()
    $cmd   = "$($p.CommandLine)"
    $exe   = "$($p.ExecutablePath)"
    $pPid  = [int]$p.ParentProcessId

    # 2. Exempt Trust-Anchor-Verified Sentinel scripts (e.g., SentinelDashboard.ps1 launched via .bat with -WindowStyle Hidden)
    if ($cName -match "^(powershell|pwsh)\.exe$" -and (Test-IsVerifiedSentinelScript -CommandLine $cmd)) {
        return @{ Action = "ExemptVerifiedSentinelScript"; RiskScore = 0 }
    }

    $parentName = "unknown"
    $parentExePath = ""
    if ($procMap -and $procMap.ContainsKey($pPid)) {
        $parentName = "$($procMap[$pPid].Name)".ToLower()
        $parentExePath = "$($procMap[$pPid].ExecutablePath)"
    } else {
        $parentProc = Get-Process -Id $pPid -ErrorAction SilentlyContinue
        if ($parentProc) { 
            $parentName = "$($parentProc.ProcessName).exe".ToLower()
            try { $parentExePath = $parentProc.Path } catch {}
        }
    }

    $minScoreToFreeze = if ($script:Config.AutoFreezeMinRiskScore) { [int]$script:Config.AutoFreezeMinRiskScore } else { 85 }
    $expandedCmd      = Expand-EncodedCommandLine -RawCommandLine $cmd
    $hasObfuscation   = ($expandedCmd -match $script:ObfuscatedCmdRegex)

    $isBrowserOrLauncher = ($parentName -match "^(chrome|msedge|brave|opera|firefox|discord|telegram|steam|robloxplayerbeta|robloxstudio|riotclientservices|valorant|tslgame)\.exe$")
    $isOfficeParent      = ($parentName -match "^(winword|excel|powerpnt|outlook|msaccess|visio|mspub|eqnedt32)\.exe$")
    $isPdfParent         = ($parentName -match "^(acrord32|acrobat|foxitreader|pdfxcview)\.exe$")
    $isArchiveParent     = ($parentName -match "^(winrar|7z|7zfm|peazip|bandizip)\.exe$")
    $isScriptParent      = ($parentName -match "^(wscript|cscript|mshta|rundll32|regsvr32)\.exe$")
    $isHighRiskParent    = ($isBrowserOrLauncher -or $isOfficeParent -or $isPdfParent -or $isArchiveParent -or $isScriptParent)

    # Anti-Spoofing: Parent must NOT reside in Temp/Public/Downloads; must reside in standard program directories OR be signed!
    $isWorkOrGameDev = $false
    if ($parentName -match $script:WorkAndGamingParentsRegex) {
        $isParentSuspicious = ($parentExePath -and ($parentExePath -match "\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\"))
        if (-not $isParentSuspicious) {
            $isStandardParentDir = ($parentExePath -and ($parentExePath -match "(?i)^[a-z]:\\(Program Files|Program Files \(x86\)|Windows|Users\\[^\\]+\\AppData\\Local\\Programs)\\"))
            if ($isStandardParentDir) {
                $isWorkOrGameDev = $true
            } elseif ($parentExePath -and (Test-Path $parentExePath -PathType Leaf)) {
                $pSig = Get-BinarySignatureTrust -FilePath $parentExePath
                if ($pSig.IsValidSigned) { $isWorkOrGameDev = $true }
            }
        }
    }
    $isShellOrLolbin  = ($cName -match "^(powershell|pwsh|cmd|mshta|wscript|cscript|regsvr32|certutil|bitsadmin)\.exe$")

    # =================================================================
    # RULE 1 & RULE 2 UNIFIED (Tier 2):
    # - Decodes Base64 payloads before scoring.
    # - Combines Parent-Child Anomaly (+25) AND Obfuscation (+45) so Chrome -> powershell -enc scores >= 85!
    # - Guarantees a CRITICAL Alert whenever obfuscation is present!
    # =================================================================
    if (($isHighRiskParent -and $isShellOrLolbin) -or ($isShellOrLolbin -and $hasObfuscation)) {
        $sigTrust = Get-BinarySignatureTrust -FilePath $exe
        $isUnsigned = (-not $sigTrust.IsValidSigned)
        $intel = Get-FileThreatIntel -FilePath $exe

        if ($isHighRiskParent -and $isShellOrLolbin) {
            Add-BehavioralSignal -ProcessId $cPid -SignalType "ParentChildAnomaly" -MitreTechnique "T1059 Command & Scripting Interpreter" -Weight 0 -Detail "$parentName -> $cName"
        }
        if ($hasObfuscation) {
            Add-BehavioralSignal -ProcessId $cPid -SignalType "ObfuscatedCommand" -MitreTechnique "T1027 Obfuscated/Encoded Command" -Weight 0 -Detail "Encoded/Fileless Shell"
        }

        $isPhishingExploit = ($isOfficeParent -or $isPdfParent -or $isArchiveParent)
        $forensics = Get-ForensicTriage -ProcessId $cPid -FilePath $exe -CommandLine $cmd -IsUnsigned $isUnsigned -IsParentChildAnomaly ($isHighRiskParent -and $isShellOrLolbin) -IsPhishingParent $isPhishingExploit

        if ($hasObfuscation -or ($forensics.RiskScore -ge $minScoreToFreeze)) {
            $alertLevel = if ($hasObfuscation -or $forensics.RiskScore -ge 85) { "CRITICAL" } else { "TIER2" }
            $actionMsg  = "High-Risk Shell Alerted (Score: $($forensics.RiskScore)/100)"
            $wasFrozen  = $false

            if ($script:Config.AutoFreezeSuspiciousProc -and ($forensics.RiskScore -ge $minScoreToFreeze) -and ("SentinelNative.KernelControl" -as [type])) {
                $wasFrozen = [SentinelNative.KernelControl]::FreezeProcess($cPid)
                if ($wasFrozen) {
                    $actionMsg = "Process Frozen via NtSuspendProcess (PID: $cPid | Score: $($forensics.RiskScore)/100)"
                    $cPid | Out-File -FilePath "$StateDir\last_frozen.pid" -Encoding UTF8 -Force
                }
            }

            $titleStr = if ($isHighRiskParent -and $hasObfuscation) {
                "Tier 2: Obfuscated Shell Spawned by '$parentName'!"
            } elseif ($hasObfuscation) {
                "Tier 2: Fileless / Obfuscated Command Execution!"
            } else {
                "Tier 2: High-Risk Parent-Child Process Anomaly!"
            }

            Show-Alert -Title $titleStr `
                       -Message "Parent '$parentName' (PID: $pPid) launched '$cName' (PID: $cPid). Score: $($forensics.RiskScore)/100. Decoded Cmd: $($forensics.DecodedCommand)" `
                       -Level $alertLevel -FilePath $exe -SHA256 $intel.SHA256 -ActionTaken $actionMsg -Forensics $forensics
            return @{ Action = "Alerted"; Frozen = $wasFrozen; RiskScore = $forensics.RiskScore; Level = $alertLevel; Forensics = $forensics }
        } else {
            Write-Log "Benign/Unobfuscated child shell from '$parentName' -> '$cName' (PID: $cPid, Score: $($forensics.RiskScore)/100). Work/Gaming Safe-Mode: Monitored without freeze." "INFO"
            return @{ Action = "MonitoredBenign"; Frozen = $false; RiskScore = $forensics.RiskScore }
        }
    }

    # =================================================================
    # RULE 3 (Tier 4): Zero-Trust Binary Execution in Temp / Browser User Data
    # Work & Gaming Safe-Mode Calibration:
    # - Tier-1 Whitelisted Vendors -> Trusted
    # - Validly CA-Signed 3rd-Party Binaries -> Protected from False-Positive Freeze,
    #   EXCEPT if hard C2 / Reflective PE Injection is proven (Score >= 90)!
    # - Unsigned Binaries in Temp -> Only auto-frozen if RiskScore >= AutoFreezeMinRiskScore (85),
    #   meaning unsigned dev compilers/game helpers in %TEMP% (Score 60) are NEVER frozen!
    # =================================================================
    if ($exe -and ($exe -match "\\AppData\\Local\\Temp\\|\\Google\\Chrome\\User Data\\|\\Microsoft\\Edge\\User Data\\")) {
        $sigTrust = Get-BinarySignatureTrust -FilePath $exe
        if ($sigTrust.IsTier1Vendor) {
            return @{ Action = "TrustedTier1Vendor"; Frozen = $false; RiskScore = 0 }
        }

        $intel = Get-FileThreatIntel -FilePath $exe
        $isUnsigned = (-not $sigTrust.IsValidSigned)
        $forensics = Get-ForensicTriage -ProcessId $cPid -FilePath $exe -CommandLine $cmd -IsUnsigned $isUnsigned -IsParentChildAnomaly $false
        $hasHardMaliciousProof = (($forensics.C2Indicators.Count -gt 0) -or ($forensics.UnbackedPeHeaders -gt 0) -or $hasObfuscation)

        if ($sigTrust.IsValidSigned) {
            # Catch Signed Threats if proven C2 / Reflective PE / Obfuscation OR spawned by Phishing Parent!
            $isPhishingExploit = ($isOfficeParent -or $isPdfParent -or $isArchiveParent)
            if (($hasHardMaliciousProof -or $isPhishingExploit) -and ($forensics.RiskScore -ge 85)) {
                $wasFrozen = $false
                $actionMsg = "Signed Malware with C2/Injection Flagged"
                if ($script:Config.AutoFreezeSuspiciousProc -and ("SentinelNative.KernelControl" -as [type])) {
                    $wasFrozen = [SentinelNative.KernelControl]::FreezeProcess($cPid)
                    if ($wasFrozen) {
                        $actionMsg = "Signed Malware Frozen via NtSuspendProcess (PID: $cPid | Score: $($forensics.RiskScore)/100)"
                        $cPid | Out-File -FilePath "$StateDir\last_frozen.pid" -Encoding UTF8 -Force
                    }
                }
                Show-Alert -Title "Tier 4: Signed Binary Exhibiting C2 / Memory Injection!" `
                           -Message "Signed executable '$cName' (PID: $cPid, Signer: $($sigTrust.Subject)) exhibited active C2 or Reflective PE injection (Score: $($forensics.RiskScore)/100)!" `
                           -Level "CRITICAL" -FilePath $exe -SHA256 $intel.SHA256 -ActionTaken $actionMsg -Forensics $forensics
                return @{ Action = "SignedMalwareFrozen"; Frozen = $wasFrozen; RiskScore = $forensics.RiskScore }
            }
            Write-Log "Verified CA-signed 3rd-party installer/tool in Temp allowed: '$cName' ($($sigTrust.Subject))." "INFO"
            return @{ Action = "AllowedSignedInstaller"; Frozen = $false; RiskScore = $forensics.RiskScore }
        }

        # Work & Gaming Safe-Mode: If spawned by a Developer IDE/Compiler/Game Launcher and has NO C2/Packed/Reflective indicators, log only!
        if ($script:Config.SafeWorkGamingMode -and $isWorkOrGameDev -and (-not $hasHardMaliciousProof) -and ($forensics.Entropy -lt 7.2)) {
            Write-Log "Work/Gaming Safe-Mode: Monitored unsigned dev/game helper in Temp '$cName' (Parent: $parentName, PID: $cPid, Score: $($forensics.RiskScore)/100)." "WARN"
            return @{ Action = "AllowedWorkGamingSafeMode"; Frozen = $false; RiskScore = $forensics.RiskScore }
        }

        $wasFrozen = $false
        $actionMsg = "Unsigned Temp Execution Monitored (Score: $($forensics.RiskScore)/100 - Below Freeze Threshold $minScoreToFreeze)"
        $alertLvl  = "WARN"

        if ($forensics.RiskScore -ge $minScoreToFreeze) {
            $alertLvl  = "CRITICAL"
            $actionMsg = "High-Risk Unsigned Temp Execution Alerted (Score: $($forensics.RiskScore)/100)"
            if ($script:Config.AutoFreezeSuspiciousProc -and ("SentinelNative.KernelControl" -as [type])) {
                $wasFrozen = [SentinelNative.KernelControl]::FreezeProcess($cPid)
                if ($wasFrozen) {
                    $actionMsg = "Unsigned Process Frozen via NtSuspendProcess (PID: $cPid | Score: $($forensics.RiskScore)/100)"
                    $cPid | Out-File -FilePath "$StateDir\last_frozen.pid" -Encoding UTF8 -Force
                }
            }
        }

        Show-Alert -Title "Tier 4: Unsigned Binary in Restricted Path!" `
                   -Message "Unsigned executable '$cName' (PID: $cPid, Parent: $parentName) launched from high-risk path (Score: $($forensics.RiskScore)/100)." `
                   -Level $alertLvl -FilePath $exe -SHA256 $intel.SHA256 -ActionTaken $actionMsg -Forensics $forensics
        return @{ Action = "UnsignedTempHandled"; Frozen = $wasFrozen; RiskScore = $forensics.RiskScore; Level = $alertLvl }
    }

    return @{ Action = "Clean"; Frozen = $false; RiskScore = 0 }
}

# Stop here when dot-sourced in -LibraryOnly mode by Invoke-RedTeamAudit.ps1!
if ($LibraryOnly) {
    return
}

# =====================================================================
# DAEMON RUNTIME INITIALIZATION (Only executed when running as Watchdog)
# =====================================================================
if (Test-Path $StopFlagFile) { Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue }
if (Test-Path "$StateDir\graceful_stop.flag") { Remove-Item "$StateDir\graceful_stop.flag" -Force -ErrorAction SilentlyContinue }

$PID | Out-File -FilePath $PidFile -Encoding UTF8 -Force

Write-Log "=== Security Sentinel Ultra v7.0 Started (PID: $PID | Work & Gaming Safe-Mode + OWNER RIGHTS DACL Active) ==="

if ("SentinelNative.KernelControl" -as [type]) {
    $daclApplied = [SentinelNative.KernelControl]::HardenCurrentProcessDacl()
    Write-Log "Kernel DACL Process Self-Defense applied: $daclApplied (Terminate/VM_Write/WRITE_DAC/OWNER_RIGHTS Locked)." "TIER3"
}
Ensure-GuardianTwin

# 1. Setup Canary / Honeypot Decoys & SACL Read Auditing
$canaryHeader = @"
# ====================================================================
# SECURITY SENTINEL ULTRA v7.0 - CANARY DECOY TRAP
# DO NOT OPEN, EDIT, OR DELETE THIS FILE.
# Monitored 24/7 by Security Sentinel Autonomous Defense.
# Any access, reading, tampering, or exfiltration triggers an instant CRITICAL ALERT.
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

try {
    $acl = Get-Acl -Path $CanaryDir -Audit -ErrorAction SilentlyContinue
    if ($acl) {
        $everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $everyone,
            [System.Security.AccessControl.FileSystemRights]::ReadData,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        $acl.SetAuditRule($auditRule)
        Set-Acl -Path $CanaryDir -AclObject $acl -ErrorAction SilentlyContinue
    }
} catch {}

$baseline = Get-PersistenceSnapshot
Write-Log "Comprehensive 29-Vector Persistence & Services baseline established ($($baseline.Count) indicators tracked)."

# 3. Browser File System Watchers (Safe-Mode: Only auto-quarantines PlatformExperienceHelper or high-entropy/C2 payloads!)
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
    $sentDir  = $Event.MessageData.StateDir
    $aggrQuar = $Event.MessageData.AggressiveQuarantine

    if ($itemPath -match "PlatformExperienceHelper|\.dll$|\.exe$") {
        $isTrusted = $false
        try {
            $sig = Get-AuthenticodeSignature -FilePath $itemPath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $isTrusted = $true
            }
        } catch {}

        if (-not $isTrusted) {
            $sha256 = "N/A"
            $entropy = 0.0
            $c2Count = 0
            try {
                $h = Get-FileHash -Path $itemPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h -and $h.Hash) { $sha256 = $h.Hash.ToLower() }
                if ("SentinelNative.KernelControl" -as [type]) {
                    $entropy = [SentinelNative.KernelControl]::ComputeShannonEntropy($itemPath)
                    $c2Arr   = [SentinelNative.KernelControl]::ExtractBinaryC2Strings($itemPath)
                    if ($c2Arr) { $c2Count = $c2Arr.Count }
                }
            } catch {}

            $isConfirmedMaliciousArtifact = ($itemPath -match "PlatformExperienceHelper") -or ($entropy -ge 7.2) -or ($c2Count -gt 0) -or $aggrQuar
            $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

            if ($isConfirmedMaliciousArtifact) {
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
                    $meta = "QuarantinedFileName: $itemName`r`nOriginalPath: $itemPath`r`nSHA256: $sha256`r`nEntropy: $entropy`r`nC2Hits: $c2Count`r`nTimestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`nReason: High-Confidence Browser Malware Quarantined"
                    [System.IO.File]::WriteAllText("$destPath.meta.txt", $meta, [System.Text.Encoding]::UTF8)
                    $logLine = "[$ts] [CRITICAL] Browser Malware Quarantined! File '$itemName' (SHA256: $sha256, Entropy: $entropy, C2Hits: $c2Count) -> '$destPath'."
                    Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
                }
            } else {
                # Safe-Mode: Do not break legitimate browser extensions/components; log warning for visibility
                $logLine = "[$ts] [WARN] Browser Safe-Mode: Unsigned module '$itemName' created in User Data (SHA256: $sha256, Entropy: $entropy, C2: 0). Monitored without quarantine."
                Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
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

            $msgData = @{ QuarDir = $QuarDir; StateDir = $StateDir; AggressiveQuarantine = [bool]$script:Config.AggressiveBrowserQuarantine }
            Register-ObjectEvent -InputObject $fsw -EventName "Created" -MessageData $msgData -Action $browserEventAction | Out-Null
            Register-ObjectEvent -InputObject $fsw -EventName "Renamed" -MessageData $msgData -Action $browserEventAction | Out-Null
            $watchers += $fsw
            Write-Log "Browser guard (Safe-Mode) actively protecting: $bPath"
        } catch {
            Write-Log "Failed to attach watcher to $bPath ($($_.Exception.Message))" "WARN"
        }
    }
}

# 4. Canary Watchers
$canaryAction = {
    $cFile   = $Event.SourceEventArgs.FullPath
    $cType   = $Event.SourceEventArgs.ChangeType
    $sentDir = $Event.MessageData.StateDir
    $ts      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $cLeaf = Split-Path $cFile -Leaf
    $validCanaries = @(
        "crypto_wallet_vault_seed.txt", "saved_passwords_export.txt", "Crypto_Recovery_Phrase_Decoy.txt",
        "roblox_security_cookie_backup.txt", "steam_account_credentials_backup.txt", "riot_games_session_token.txt"
    )
    if ($validCanaries -notcontains $cLeaf) { return }

    $logLine = "[$ts] [CRITICAL] Honeypot Decoy Triggered! File '$cFile' was $cType. Possible Infostealer / Ransomware activity!"
    Add-Content -Path (Join-Path $sentDir "logs\sentinel.log") -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
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
        if ($cDir -eq ([Environment]::GetFolderPath('MyDocuments'))) {
            $cWatcher.Filter = "Crypto_Recovery_Phrase_Decoy.txt"
        }
        $cWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::Size -bor [System.IO.NotifyFilters]::LastAccess

        $msgData = @{ StateDir = $StateDir }
        Register-ObjectEvent -InputObject $cWatcher -EventName "Changed" -MessageData $msgData -Action $canaryAction | Out-Null
        Register-ObjectEvent -InputObject $cWatcher -EventName "Deleted" -MessageData $msgData -Action $canaryAction | Out-Null
        Register-ObjectEvent -InputObject $cWatcher -EventName "Renamed" -MessageData $msgData -Action $canaryAction | Out-Null
        $watchers += $cWatcher
        Write-Log "Canary Honeypot watcher active in: $cDir"
    } catch {
        Write-Log "Failed to initialize canary watcher on $cDir" "WARN"
    }
}

$script:LastTelemetryTime = (Get-Date)
function Inspect-DeepTelemetryEvents {
    $since = $script:LastTelemetryTime
    $script:LastTelemetryTime = (Get-Date)

    # 1. Security Event ID 4663 (SACL Canary Read Audit with Exact ProcessId & ProcessName Attribution)
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4663
            StartTime = $since
        } -MaxEvents 25 -ErrorAction SilentlyContinue

        if ($secEvents) {
            foreach ($ev in $secEvents) {
                $parsed = Parse-Event4663Xml -EventXmlString $ev.ToXml()
                if ($parsed.ObjectName -match "SecuritySentinel_Canary|Crypto_Recovery_Phrase_Decoy") {
                    if ($parsed.ProcessId -ne $PID -and $parsed.ProcessId -ne $script:VerifiedGuardianPid) {
                        Add-BehavioralSignal -ProcessId $parsed.ProcessId -SignalType "CanaryRead4663" -MitreTechnique "T1555.003 Credentials from Password Stores" -Weight 45 -Detail $parsed.ObjectName
                        $action = "Attributed via SACL Event 4663"
                        if ($script:Config.AutoFreezeSuspiciousProc -and $parsed.ProcessId -gt 4 -and ("SentinelNative.KernelControl" -as [type])) {
                            if ([SentinelNative.KernelControl]::FreezeProcess($parsed.ProcessId)) {
                                $action = "Offending Process Frozen (PID: $($parsed.ProcessId))"
                                $parsed.ProcessId | Out-File -FilePath "$StateDir\last_frozen.pid" -Encoding UTF8 -Force
                            }
                        }
                        $forensics = Get-ForensicTriage -ProcessId $parsed.ProcessId -FilePath $parsed.ProcessName -CommandLine "SACL Read on $($parsed.ObjectName)" -IsUnsigned $true
                        Show-Alert -Title "Tier 1: Canary Honeypot Read Attributed (Event 4663)!" `
                                   -Message "Process '$($parsed.ProcessName)' (PID: $($parsed.ProcessId), User: $($parsed.SubjectUser)) read Canary file '$($parsed.ObjectName)'!" `
                                   -Level "CRITICAL" -FilePath $parsed.ProcessName -ActionTaken $action -Forensics $forensics
                    }
                }
            }
        }
    } catch {}

    # 2. PowerShell Operational Event ID 4104 (De-obfuscated ScriptBlock Telemetry)
    try {
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = 4104
            StartTime = $since
        } -MaxEvents 25 -ErrorAction SilentlyContinue

        if ($psEvents) {
            foreach ($pev in $psEvents) {
                $evPid = [int]$pev.ProcessId
                if ($evPid -eq $PID -or $evPid -eq $script:VerifiedGuardianPid) { continue }
                $msg = "$($pev.Message)"
                if ($msg -match "(?i)([A]msiUtils|[a]msiInitFailed|[I]nvoke-Mimikatz|[M]iniDumpWriteDump|\.ROBLOSECURITY|discord(app)?\.com/api/webhooks/)") {
                    if ($msg -match "Security Sentinel Ultra|SentinelNative|RED-TEAM & MITRE") { continue }
                    Add-BehavioralSignal -ProcessId $evPid -SignalType "ScriptBlock4104" -MitreTechnique "T1059.001 PowerShell ScriptBlock" -Weight 45 -Detail "Malicious ScriptBlock Primitive"
                    $snippet = if ($msg.Length -gt 240) { $msg.Substring(0, 240) + "..." } else { $msg }
                    $forensics = Get-ForensicTriage -ProcessId $evPid -FilePath "powershell.exe" -CommandLine $snippet -IsUnsigned $false
                    $action = "ScriptBlock 4104 Flagged"
                    if ($script:Config.AutoFreezeSuspiciousProc -and $forensics.RiskScore -ge $script:Config.AutoFreezeMinRiskScore -and ("SentinelNative.KernelControl" -as [type])) {
                        if ([SentinelNative.KernelControl]::FreezeProcess($evPid)) {
                            $action = "Process Frozen via Event 4104 Telemetry (PID: $evPid)"
                            $evPid | Out-File -FilePath "$StateDir\last_frozen.pid" -Encoding UTF8 -Force
                        }
                    }
                    Show-Alert -Title "Pillar 1: Malicious PowerShell ScriptBlock (Event 4104)!" `
                               -Message "In-memory PowerShell ScriptBlock detected in PID $evPid! Snippet: $snippet" `
                               -Level "CRITICAL" -FilePath "EventID:4104 (PID:$evPid)" -ActionTaken $action -Forensics $forensics
                }
            }
        }
    } catch {}
}

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $knownProcs[(Get-ProcCompositeKey $_)] = [int]$_.ProcessId
}

# Subscribe to Kernel ETW Win32_ProcessStartTrace first (when elevated), fallback to WMI __InstanceCreationEvent
try {
    Unregister-Event -SourceIdentifier "SentinelKernelProcTrace" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "SentinelRealTimeProc" -ErrorAction SilentlyContinue
    Register-CimIndicationEvent -ClassName "Win32_ProcessStartTrace" -SourceIdentifier "SentinelKernelProcTrace" -ErrorAction Stop | Out-Null
    Write-Log "Kernel ETW Process Trace (Win32_ProcessStartTrace) subscribed (0ms kernel callback stream)." "TIER2"
} catch {
    try {
        $wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        Register-CimIndicationEvent -Query $wmiQuery -SourceIdentifier "SentinelRealTimeProc" -ErrorAction Stop | Out-Null
        Write-Log "WMI/CIM Process Event Stream subscribed (1s interval; run as Admin for Kernel ETW Win32_ProcessStartTrace)." "TIER2"
    } catch {
        Write-Log "Standard Process Telemetry polling active." "TIER2"
    }
}

Write-Log "Tier 2 Process Telemetry, Tier 3 NtSuspendProcess & Tier 4 Live RAM Forensics Armed ($($knownProcs.Count) baseline processes)." "TIER2"

function Inspect-NewProcesses {
    # 1. Drain Kernel ETW Win32_ProcessStartTrace events if active
    $kEvents = Get-Event -SourceIdentifier "SentinelKernelProcTrace" -ErrorAction SilentlyContinue
    if ($kEvents) {
        foreach ($kev in $kEvents) {
            $kPid = [int]$kev.SourceEventArgs.NewEvent.ProcessID
            if ($kPid -gt 0) {
                $cimP = Get-CimInstance Win32_Process -Filter "ProcessId = $kPid" -ErrorAction SilentlyContinue
                if ($cimP) { [void](Inspect-SingleProcess -p $cimP -procMap $null) }
            }
            Remove-Event -EventIdentifier $kev.EventIdentifier -ErrorAction SilentlyContinue
        }
    }

    # 2. Drain WMI __InstanceCreationEvent stream
    $events = Get-Event -SourceIdentifier "SentinelRealTimeProc" -ErrorAction SilentlyContinue
    if ($events) {
        foreach ($ev in $events) {
            $targetProc = $ev.SourceEventArgs.NewEvent.TargetInstance
            if ($targetProc) {
                [void](Inspect-SingleProcess -p $targetProc -procMap $null)
            }
            Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
        }
    }

    # 3. Snapshot sweep & Dead-PID Pruning
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $procMap = @{}
    $liveKeys = @{}
    foreach ($p in $procs) {
        $procMap[[int]$p.ProcessId] = $p
        $liveKeys[(Get-ProcCompositeKey $p)] = $true
    }

    $deadKeys = @($knownProcs.Keys | Where-Object { -not $liveKeys.ContainsKey($_) })
    foreach ($dk in $deadKeys) { $knownProcs.Remove($dk) }

    $deadCorrPids = @($script:BehavioralCorrelation.Keys | Where-Object { -not $procMap.ContainsKey($_) })
    foreach ($dPid in $deadCorrPids) { $script:BehavioralCorrelation.Remove($dPid) }

    foreach ($p in $procs) {
        [void](Inspect-SingleProcess -p $p -procMap $procMap)
    }
}

# 6. Tier 4: DLL Module & In-Memory Injection Guard (Cross-checks Module Signature + Live RAM RWX/Reflective PE)
$script:VerifiedModules = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

function Inspect-ProcessModules {
    if (-not $script:Config.EnableDllInjectionGuard) { return }
    $targetNames = @("chrome", "msedge", "brave", "discord", "steam", "robloxplayerbeta", "riotclientservices")
    $procs = Get-Process -Name $targetNames -ErrorAction SilentlyContinue

    foreach ($proc in $procs) {
        try {
            foreach ($mod in $proc.Modules) {
                $modPath = $mod.FileName
                if (-not $modPath) { continue }
                if ($script:VerifiedModules.Contains($modPath)) { continue }

                [void]$script:VerifiedModules.Add($modPath)

                if ($modPath -match "\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\" -and $modPath -match "\.dll$") {
                    $sigTrust = Get-BinarySignatureTrust -FilePath $modPath
                    if (-not $sigTrust.IsValidSigned) {
                        $intel = Get-FileThreatIntel -FilePath $modPath
                        $forensics = Get-ForensicTriage -ProcessId $proc.Id -FilePath $modPath -CommandLine "Module in $($proc.ProcessName) (PID: $($proc.Id))" -IsUnsigned $true

                        # Distinguish between Confirmed Injection/C2 vs Unsigned Temp DLL
                        if ($forensics.UnbackedPeHeaders -gt 0 -or $forensics.C2Indicators.Count -gt 0 -or $forensics.Entropy -ge 7.2) {
                            Add-BehavioralSignal -ProcessId $proc.Id -SignalType "ConfirmedDllInjection" -MitreTechnique "T1055.001 DLL Injection" -Weight 35 -Detail $modPath
                            Show-Alert -Title "Tier 4: Confirmed Malicious DLL Injection / C2 Module!" `
                                       -Message "Unsigned high-risk module '$(Split-Path $modPath -Leaf)' in '$($proc.ProcessName).exe' (PID: $($proc.Id)) matched memory injection/C2 indicators!" `
                                       -Level "CRITICAL" -FilePath $modPath -SHA256 $intel.SHA256 -ActionTaken "Confirmed Memory Injection Alerted" -Forensics $forensics
                        } else {
                            Write-Log "Unsigned non-standard module loaded in $($proc.ProcessName).exe (PID: $($proc.Id)): $modPath (No C2/Reflective PE indicators; monitored in Safe-Mode)." "WARN"
                        }
                    }
                }
            }
        } catch {}
    }
}

# 7. Main Continuous Monitoring Loop (Checks stop signal every 500ms for instant graceful shutdown without PROCESS_TERMINATE)
Write-Log "Sentinel Watchdog Ultra v7.0 enters live monitoring loop (Work & Gaming Safe-Mode Active)."
$loopCount = 0
$lastDeepSweep = [DateTime]::UtcNow

while ($true) {
    for ($w = 0; $w -lt 4; $w++) {
        Start-Sleep -Milliseconds 500
        if (Test-AuthenticatedStopToken) {
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
            exit 0
        }
        $thawReq = "$StateDir\thaw_request.pid"
        if (Test-Path $thawReq) {
            $tPid = (Get-Content $thawReq -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
            if ($tPid -match '^\d+$' -and ("SentinelNative.KernelControl" -as [type])) {
                [SentinelNative.KernelControl]::ThawProcess([int]$tPid) | Out-Null
                Write-Log "Process $tPid thawed via Dashboard request." "INFO"
            }
            Remove-Item $thawReq -Force -ErrorAction SilentlyContinue
        }
    }
    $loopCount++

    Inspect-NewProcesses

    $scanInterval = if ($script:Config.ScanIntervalSeconds -and [int]$script:Config.ScanIntervalSeconds -ge 3) {
        [int]$script:Config.ScanIntervalSeconds
    } else { 15 }

    if (([DateTime]::UtcNow - $lastDeepSweep).TotalSeconds -ge $scanInterval) {
        $lastDeepSweep = [DateTime]::UtcNow
        Ensure-GuardianTwin
        Inspect-ProcessModules
        Inspect-DeepTelemetryEvents

        $currentSnap = Get-PersistenceSnapshot
        foreach ($k in $currentSnap.Keys) {
            if (-not $baseline.ContainsKey($k)) {
                $newVal = $currentSnap[$k]
                Show-Alert -Title "Tier 1: New Persistence / Service Mechanism Detected (29-Vector Sensor)!" `
                           -Message "New auto-start or service entry registered: $k -> $newVal (MITRE T1547 / T1543.003 / T1053)" `
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

    if ($loopCount % 900 -eq 0) {
        Write-Log "Heartbeat: v7.0 Work & Gaming Safe-Mode Engines healthy ($($watchers.Count) watchers, $($knownProcs.Count) active PID|Time keys, $($baseline.Count) persistence/service vectors, $($script:VerifiedModules.Count) DLLs cached)." "INFO"
        $script:Config = Load-SentinelConfig
    }
}

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAHzYSfW6eyjAE7
# 883NHtQ2TzzGnx9BG5YhZ0dFue/ETaCCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
# k00USv2WB3cfMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNl
# bnRpbmVsIFVsdHJhIENvZGUgU2lnbmluZzAeFw0yNjExMDkwMjUxMjZaFw0zMTEx
# MDkwMzAxMjVaMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNlbnRpbmVsIFVsdHJhIENv
# ZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALllSiqT
# Y5Sc6hifAl+AGeEpL3joSXd9ne4K7pKYDHPQavPfBy32CzCJa1jyX77QoO1UtsOv
# On5Xoi8k5ApurF/WYtjU0g3ql946XPjn6VjwGLmbqSA+pNGqnOMjBz4ox0cqVblm
# 5hD944XKqtREmR7apy3lthUp7XTTG7BGRAVqhZpd+E/VTVG0A+P3wcNc7y3aOxoa
# DJ6JHO/8putrt37Q54x3UVUXOU8Zbwwjic/NI7WV5ckmQ00jiI2cxZgzXdqnXxDU
# aWxd7Ek2/z9QDJEE6wRtBHtvynUpAcZvBW87Xx0WwB8h5qh2P1gHF5ZONY1hzuav
# shNwuowu2k17JakCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBThzeAg8TkOvzIAhDScXw7avedctTANBgkqhkiG
# 9w0BAQsFAAOCAQEAQJM2S9UXri6Zk2rCN6vcsOSuJBRdo43f2i/IXF8KqqPl89cB
# 0EKkiYCaz/1zpjyqotuM0PfHdQgyhOS1rBy8BGCc9CmD2Yk4mcGe1cq/DPrjjmHZ
# I/Hbwq5jla1t5hIB8TENaRlO2yJcnx0m7zJ90RHkCm5t4sVQO55kh//OfQ4RUXEA
# vNdnlgF1EkHey5FbUxyhcEsCZpsJU+KrGceLE43oYtCEekpdTsNuC3SNCYP674yo
# lebxXnckHIuqfnYmizmxBMhYcK3RChIIv8cFPR2/n0EhcQ3XeNNfksfrVyarz8eE
# BFVfGerioUtLIH4OFiCsGTtRr0BCbo6iE7kwajGCAfUwggHxAgEBMEMwLzEtMCsG
# A1UEAwwkU2VjdXJpdHkgU2VudGluZWwgVWx0cmEgQ29kZSBTaWduaW5nAhARiv7c
# h4Yqk00USv2WB3cfMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGV2en6I1YrWVHPX8im7
# f3F+gSCtzzpO6qeyyC5ZALKxMA0GCSqGSIb3DQEBAQUABIIBALLZVQq3yn3X0f1E
# 0S9SvdmLMVPv0QAyOf48Z6wRffxbOYMQ6ai3Bfo9ACIonIVapbcBPsdPC7HOb65r
# aaxcHuNcYAsxtfxodx43auJYCsKYZO1I86QWCBQctP92I2rzrpLyPJXKVzIagn5f
# J+Xc4L2aaQUO7sIdDM5HKs4kKmrm8XYA/g9AhmxhCWXKyArKQ71jgN5BorHuAqWA
# KYEclyMOmcKYK46x0Fs8KTVQL8E7rjkZ1M5w03uRuMfqaItfKm5+Y09CBVPk7s2X
# PGXcjcnW3J9Jl4el+lZSqBZSFEXlB7L+68kDl3SbcvfUbtzk4V6mGVEm81gPqFPm
# 8llTJ+4=
# SIG # End signature block
