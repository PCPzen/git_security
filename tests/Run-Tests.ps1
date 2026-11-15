# =====================================================================
# Security Sentinel Ultra v8.0 - Automated Test Runner
# Zero-dependency standalone test execution engine
# Tests: A1-A4, B1-B5, C1, C3, C4, DPAPI, Anti-Bypass, Phishing, Safe-Mode
# =====================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - ENTERPRISE AUTOMATED TEST SUITE     " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$ScriptRoot   = Split-Path -Parent $PSScriptRoot
$CoreDir      = Join-Path $ScriptRoot "core"
$WatchdogPath = Join-Path $CoreDir "SentinelWatchdog.ps1"

if (-not (Test-Path $WatchdogPath)) {
    Write-Host "[FATAL] SentinelWatchdog.ps1 not found at: $WatchdogPath" -ForegroundColor Red
    exit 1
}

$TestStateDir = Join-Path $env:TEMP "SecuritySentinel_UnitTests_$PID"
New-Item -ItemType Directory -Path $TestStateDir -Force | Out-Null
$env:SENTINEL_TEST_MODE = "1"
$env:SENTINEL_STATE_DIR = $TestStateDir

try {
    . $WatchdogPath -LibraryOnly
    $script:TrustAnchorHashes = Initialize-CodeIntegrityTrustAnchor

    $totalTests = 0
    $passedTests = 0
    $failedTests = 0

    function Assert-Test([string]$Name, [bool]$Condition, [string]$Details = "") {
        $script:totalTests++
        if ($Condition) {
            $script:passedTests++
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            if ($Details) { Write-Host "         -> $Details" -ForegroundColor DarkGray }
        } else {
            $script:failedTests++
            Write-Host "  [FAIL] $Name" -ForegroundColor Red
            if ($Details) { Write-Host "         -> $Details" -ForegroundColor Yellow }
        }
    }

    Write-Host "`n[SUITE 1] Unified DPAPI Secret Vault & Static Entropy Rejection (A3)" -ForegroundColor Yellow
    $secret = "https://discord.com/api/webhooks/enterprise_test_token"
    $enc = Protect-DpapiString -PlainText $secret
    Assert-Test -Name "DPAPI Protect generates non-empty ciphertext" -Condition (-not [string]::IsNullOrEmpty($enc) -and $enc -ne $secret)
    $dec = Unprotect-DpapiString -CipherBase64 $enc
    Assert-Test -Name "DPAPI Unprotect accurately recovers plaintext" -Condition ($dec -eq $secret)
    $corrupt = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("BadCiphertext"))
    Assert-Test -Name "DPAPI Unprotect rejects corrupted input gracefully" -Condition ((Unprotect-DpapiString -CipherBase64 $corrupt) -eq "")

    # A3: Verify static public entropy SENTINEL_ULTRA_V6_ENTROPY_<COMPUTERNAME> is strictly rejected
    $staticEntropy = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
    $staticEnc = [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($secret), $staticEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
    Assert-Test -Name "A3: Unprotect-DpapiString strictly rejects static public entropy constant" -Condition ((Unprotect-DpapiString -CipherBase64 $staticEnc) -eq "")

    Write-Host "`n[SUITE 2] Trust Anchor 10-Script Coverage & Anti-Bypass Protection (B1, B2)" -ForegroundColor Yellow
    Assert-Test -Name "B1: Trust Anchor includes all 10 core scripts (Start-Shield, Stop-Shield, SentinelTray, etc.)" -Condition (
        ($script:AuthorizedCoreScripts.Count -eq 10) -and
        ($script:TrustAnchorHashes.ContainsKey("Start-Shield.ps1")) -and
        ($script:TrustAnchorHashes.ContainsKey("Stop-Shield.ps1")) -and
        ($script:TrustAnchorHashes.ContainsKey("SentinelTray.ps1"))
    ) -Details "Anchored count: $($script:TrustAnchorHashes.Count)"

    $cmdBypass1 = "powershell.exe -enc VGVzdFBheWxvYWQ= SentinelDashboard.ps1"
    Assert-Test -Name "Reject encoded command with appended script name" -Condition (-not (Test-IsVerifiedSentinelScript -CommandLine $cmdBypass1))
    $cmdBypass2 = "powershell.exe -Command `"Invoke-Expression`" SentinelDashboard.ps1"
    Assert-Test -Name "Reject inline command flag with appended script name" -Condition (-not (Test-IsVerifiedSentinelScript -CommandLine $cmdBypass2))
    $cmdNoFile = "powershell.exe -ExecutionPolicy Bypass SentinelDashboard.ps1"
    Assert-Test -Name "Reject invocations missing explicit -File parameter" -Condition (-not (Test-IsVerifiedSentinelScript -CommandLine $cmdNoFile))
    $cmdChained = "powershell.exe -File `"C:\Safe\SentinelDashboard.ps1`" && whoami"
    Assert-Test -Name "Reject commands with operator chaining (&&, ;, |)" -Condition (-not (Test-IsVerifiedSentinelScript -CommandLine $cmdChained))
    $cmdTemp = "powershell.exe -File `"C:\Users\Public\SentinelDashboard.ps1`""
    Assert-Test -Name "Reject scripts residing outside authorized directories" -Condition (-not (Test-IsVerifiedSentinelScript -CommandLine $cmdTemp))

    Write-Host "`n[SUITE 3] Phishing Parent Matrix & Macro Anomaly Detection" -ForegroundColor Yellow
    $macroForensics = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Windows\System32\cmd.exe" -CommandLine "cmd.exe /c powershell -enc test" -IsUnsigned $false -IsParentChildAnomaly $true -IsPhishingParent $true
    Assert-Test -Name "Phishing parent anomaly scores >= 85 for immediate Freeze" -Condition ($macroForensics.RiskScore -ge 85) -Details "Score: $($macroForensics.RiskScore)/100"
    Assert-Test -Name "Forensic reasons include PhishingParentExploit(+50)" -Condition ($macroForensics.Reasons -contains "PhishingParentExploit(+50)")
    Assert-Test -Name "MITRE ATT&CK includes T1566 Phishing" -Condition ($macroForensics.MitreTechniques -contains "T1566 Phishing")

    Write-Host "`n[SUITE 4] Safe-Mode Zero-Trust Parent & AppData Spoofing Defense (A4)" -ForegroundColor Yellow
    $fakeNodeForensics = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Users\victim\AppData\Local\Temp\node.exe" -CommandLine "node.exe -e evil()" -IsUnsigned $true -IsParentChildAnomaly $false -IsPhishingParent $false
    Assert-Test -Name "Unsigned Temp binary 'node.exe' scores at least 60 (No silent pass)" -Condition ($fakeNodeForensics.RiskScore -ge 60) -Details "Score: $($fakeNodeForensics.RiskScore)/100"
    Assert-Test -Name "Unsigned Temp binary flags UnsignedBinary(+25) and HighRiskPath(+20)" -Condition ($fakeNodeForensics.Reasons -contains "UnsignedBinary(+25)" -and $fakeNodeForensics.Reasons -contains "HighRiskPath(+20)")

    # Real Inspect-SingleProcess test with Spoofed Parent in Temp
    $childProc = [PSCustomObject]@{
        ProcessId       = 8881
        Name            = "worker.exe"
        ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
        CommandLine     = "worker.exe --task"
        ParentProcessId = 7771
        CreationDate    = "2026111501"
    }
    $spoofedParentMap = @{
        7771 = [PSCustomObject]@{
            ProcessId      = 7771
            Name           = "steam.exe"
            ExecutablePath = "C:\Users\victim\AppData\Local\Temp\steam.exe"
        }
    }
    $spoofedRes = Inspect-SingleProcess -p $childProc -procMap $spoofedParentMap
    Assert-Test -Name "Inspect-SingleProcess REJECTS Safe-Mode pass when parent is spoofed in Temp" -Condition ($spoofedRes.Action -ne "AllowedWorkGamingSafeMode") -Details "Action: $($spoofedRes.Action)"

    # A4: Spoofed unsigned parent in AppData\Local\Programs MUST also be rejected!
    $childProcAppData = [PSCustomObject]@{
        ProcessId       = 8884
        Name            = "worker.exe"
        ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
        CommandLine     = "worker.exe --task"
        ParentProcessId = 7774
        CreationDate    = "2026111504"
    }
    $spoofedAppDataMap = @{
        7774 = [PSCustomObject]@{
            ProcessId      = 7774
            Name           = "node.exe"
            ExecutablePath = "C:\Users\victim\AppData\Local\Programs\nodejs\node.exe"
        }
    }
    $appDataRes = Inspect-SingleProcess -p $childProcAppData -procMap $spoofedAppDataMap
    Assert-Test -Name "A4: Inspect-SingleProcess REJECTS Safe-Mode pass when unsigned parent is in AppData\Local\Programs" -Condition ($appDataRes.Action -ne "AllowedWorkGamingSafeMode") -Details "Action: $($appDataRes.Action)"

    $childProcLegit = [PSCustomObject]@{
        ProcessId       = 8882
        Name            = "worker.exe"
        ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
        CommandLine     = "worker.exe --task"
        ParentProcessId = 7771
        CreationDate    = "2026111502"
    }
    $legitParentMap = @{
        7771 = [PSCustomObject]@{
            ProcessId      = 7771
            Name           = "steam.exe"
            ExecutablePath = "C:\Program Files (x86)\Steam\steam.exe"
        }
    }
    $legitRes = Inspect-SingleProcess -p $childProcLegit -procMap $legitParentMap
    Assert-Test -Name "Inspect-SingleProcess ACCEPTS Safe-Mode pass when parent is genuine in Program Files" -Condition ($legitRes.Action -eq "AllowedWorkGamingSafeMode") -Details "Action: $($legitRes.Action)"

    Write-Host "`n[SUITE 5] Stop Token Security, Elevation Gate & Registry ACL Hardening (A1, A2, A3)" -ForegroundColor Yellow
    $invalidToken = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
    Assert-Test -Name "Stop token with mismatched PID strictly rejected" -Condition (-not $invalidToken)

    # Attacker Token Forgery Simulation
    $attackerPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
    $attackerBytes = [System.Text.Encoding]::UTF8.GetBytes($attackerPayload)
    $fakeAttackerEntropy = [System.Text.Encoding]::UTF8.GetBytes("ATTACKER_FAKE_SECRET_1234567890123")
    $forgedEnc = [System.Security.Cryptography.ProtectedData]::Protect($attackerBytes, $fakeAttackerEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $stopTokenPath = Join-Path $StateDir "graceful_stop.token"
    [System.IO.File]::WriteAllText($stopTokenPath, [Convert]::ToBase64String($forgedEnc), [System.Text.Encoding]::UTF8)

    $forgedTokenAccepted = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
    Assert-Test -Name "Attacker stop token forged without secret strictly rejected" -Condition (-not $forgedTokenAccepted)

    # A3: Token forged with static constant SENTINEL_ULTRA_V6_ENTROPY_<COMPUTERNAME>
    $staticTokenEnc = [System.Security.Cryptography.ProtectedData]::Protect($attackerBytes, $staticEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($stopTokenPath, [Convert]::ToBase64String($staticTokenEnc), [System.Text.Encoding]::UTF8)
    $staticTokenAccepted = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
    Assert-Test -Name "A3: Stop token signed with static public constant strictly rejected" -Condition (-not $staticTokenAccepted)

    # Replay Attack Protection: Token with expired timestamp (> 60s)
    $expiredPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.AddSeconds(-120).ToUnixTimeSeconds())"
    $expiredEnc = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($expiredPayload), $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllText($stopTokenPath, [Convert]::ToBase64String($expiredEnc), [System.Text.Encoding]::UTF8)
    $expiredTokenAccepted = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
    Assert-Test -Name "Replay attack stop token with expired timestamp strictly rejected" -Condition (-not $expiredTokenAccepted)

    # A2: Verify New-SentinelRegistryAclObject has Protected Allow-only ACL (0 Deny ACEs for Users)
    $regAcl = New-SentinelRegistryAclObject
    $denyRules = @($regAcl.Access | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny })
    $allowRules = @($regAcl.Access | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow })
    Assert-Test -Name "A2: Set-SentinelRegistryAcl uses protected Allow-only ACL (0 Deny ACEs that could lock out elevated Admin)" -Condition ($denyRules.Count -eq 0 -and $allowRules.Count -eq 2 -and $regAcl.AreAccessRulesProtected)

    # A1 & B3 & C4 Static & Behavioral Verification of Stop-Shield.ps1, Start-Shield.ps1, SentinelTray.ps1
    $stopContent  = Get-Content (Join-Path $CoreDir "Stop-Shield.ps1") -Raw -Encoding UTF8
    $startContent = Get-Content (Join-Path $CoreDir "Start-Shield.ps1") -Raw -Encoding UTF8
    $trayContent  = Get-Content (Join-Path $CoreDir "SentinelTray.ps1") -Raw -Encoding UTF8
    Assert-Test -Name "A1: Stop-Shield.ps1 enforces Administrator elevation, EventID 4006 audit, and has zero Stop-Process -Force" -Condition (
        ($stopContent -match "WindowsBuiltInRole\]::Administrator") -and
        ($stopContent -match "4006") -and
        ($stopContent -notmatch "Stop-Process") -and
        ($stopContent -notmatch "SENTINEL_ULTRA_V6_ENTROPY_")
    )
    Assert-Test -Name "B3 & B4: Start-Shield.ps1 verifies Trust Anchor hash, polls live PIDs, and uses ([int]`$x)" -Condition (
        ($startContent -match "Get-TrustedScriptHash") -and
        ($startContent -match "Get-Process -Id \(\[int\]") -and
        ($startContent -notmatch "Get-Process -Id \[int\]")
    )
    Assert-Test -Name "C4: SentinelTray.ps1 tracks Dashboard via dashboard.pid and delegates stop to elevated Stop-Shield.ps1" -Condition (
        ($trayContent -match "dashboard\.pid") -and
        ($trayContent -match "Stop-Shield\.ps1") -and
        ($trayContent -notmatch "Stop-Process")
    )

    Write-Host "`n[SUITE 6] Tamper-Evident Log HMAC Chain (C1) & Event 4663 / 4688 / Sysmon XML Parsers (C3)" -ForegroundColor Yellow
    Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
    Write-Log "Unit test log entry 1" "INFO"
    Write-Log "Unit test log entry 2" "ALERT"
    $logIntegrityOk = Test-SentinelLogIntegrity -Path $LogFile
    Assert-Test -Name "C1: Write-Log produces valid chained HMAC-SHA256 log entries" -Condition ($logIntegrityOk.Valid -and $logIntegrityOk.TotalLines -eq 2)

    Add-Content -Path $LogFile -Value "[2026-11-15 12:00:00] [INFO] Forged unchained line [HMAC:0000000000000000]" -Encoding UTF8
    $logTamperCheck = Test-SentinelLogIntegrity -Path $LogFile
    Assert-Test -Name "C1: Test-SentinelLogIntegrity detects forged/modified log line" -Condition ((-not $logTamperCheck.Valid) -and ($logTamperCheck.TamperedLine -eq 3))

    $testXml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">VictimUser</Data>
    <Data Name="ObjectName">C:\Users\Victim\AppData\Roaming\SecuritySentinel_Canary\crypto_wallet_vault_seed.txt</Data>
    <Data Name="ProcessId">0x12b0</Data>
    <Data Name="ProcessName">C:\Users\Victim\AppData\Local\Temp\stealer.exe</Data>
  </EventData>
</Event>
"@
    $parsedEv = Parse-Event4663Xml -EventXmlString $testXml
    Assert-Test -Name "SACL 4663 XML correctly parses hex ProcessId (0x12b0 -> 4784)" -Condition ($parsedEv.ProcessId -eq 4784)

    $xml4688 = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID><TimeCreated SystemTime="2026-11-15T09:00:00Z"/></System>
  <EventData>
    <Data Name="NewProcessId">0x1a00</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ProcessId">0x0800</Data>
    <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
  </EventData>
</Event>
"@
    $parsed4688 = Parse-ProcessCreationEventXml -EventXmlString $xml4688
    Assert-Test -Name "C3: Security Event 4688 XML parser extracts ProcessId, CommandLine, and ParentProcessId" -Condition (
        ($parsed4688.ProcessId -eq 6656) -and
        ($parsed4688.ParentProcessId -eq 2048) -and
        ($parsed4688.Name -eq "cmd.exe") -and
        ($parsed4688.CommandLine -eq "cmd.exe /c whoami")
    )

    Write-Host "`n[SUITE 11] Hardening Regression Checks (StateDir Gate, Pause Clamp, Log Tail-Truncation, Admin Vault)" -ForegroundColor Yellow
    $savedMode = $env:SENTINEL_TEST_MODE
    $savedDir  = $env:SENTINEL_STATE_DIR
    try {
        $env:SENTINEL_TEST_MODE = $null
        $env:SENTINEL_STATE_DIR = Join-Path $env:TEMP "ShouldBeIgnoredWithoutTestMode"
        $resolvedProd = Resolve-SentinelStateDir
        Assert-Test -Name "SENTINEL_STATE_DIR is ignored when SENTINEL_TEST_MODE != 1" -Condition ($resolvedProd -eq (Join-Path $env:LOCALAPPDATA "SecuritySentinel"))

        $env:SENTINEL_TEST_MODE = "1"
        $env:SENTINEL_STATE_DIR = "C:\Windows\System32\EvilSentinelState"
        $resolvedOutsideTemp = Resolve-SentinelStateDir
        Assert-Test -Name "SENTINEL_STATE_DIR is rejected when outside %TEMP% even in test mode" -Condition ($resolvedOutsideTemp -eq (Join-Path $env:LOCALAPPDATA "SecuritySentinel"))
    } finally {
        $env:SENTINEL_TEST_MODE = $savedMode
        $env:SENTINEL_STATE_DIR = $savedDir
    }

    $stopScriptText = Get-Content (Join-Path $CoreDir "Stop-Shield.ps1") -Raw -Encoding UTF8
    Assert-Test -Name "Stop-Shield.ps1 clamps PauseMinutes with ValidateRange(1, 60)" -Condition ($stopScriptText -match 'ValidateRange\(1,\s*60\)')

    $installScriptText = Get-Content (Join-Path $CoreDir "Install.ps1") -Raw -Encoding UTF8
    Assert-Test -Name "Install.ps1 uses ErrorActionPreference=Stop and PublicHashes subkey" -Condition (
        ($installScriptText -match "\`$ErrorActionPreference\s*=\s*'Stop'") -and
        ($installScriptText -match "PublicHashes") -and
        ($installScriptText -match "Set-AndVerifySentinelRegistryAcl")
    )

    # Log tail-truncation detection via sentinel.tip
    $truncLog = Join-Path $TestStateDir "trunc_test.log"
    $savedLogFile = $script:LogFile
    $savedTipFile = $script:LogTipFile
    try {
        $script:LogFile    = $truncLog
        $script:LogTipFile = "$truncLog.tip"
        Remove-Item $truncLog, $script:LogTipFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Chain entry 1" -Level "INFO"
        Write-Log -Message "Chain entry 2" -Level "INFO"
        Write-Log -Message "Chain entry 3 (tail)" -Level "WARN"
        $beforeTrunc = Test-SentinelLogIntegrity -Path $truncLog
        $lines = Get-Content -Path $truncLog -Encoding UTF8
        [System.IO.File]::WriteAllLines($truncLog, $lines[0..1], [System.Text.Encoding]::UTF8)
        $afterTrunc = Test-SentinelLogIntegrity -Path $truncLog
        Assert-Test -Name "Test-SentinelLogIntegrity detects tail-truncation via sentinel.tip" -Condition ($beforeTrunc.Valid -and (-not $afterTrunc.Valid))
    } finally {
        $script:LogFile    = $savedLogFile
        $script:LogTipFile = $savedTipFile
    }

    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "   SUMMARY: $passedTests / $totalTests TESTS PASSED ($failedTests FAILED)" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
    Write-Host "======================================================================" -ForegroundColor Cyan

    if ($failedTests -gt 0) { exit 1 } else { exit 0 }
} catch {
    Write-Host "[FATAL] Unhandled error in Run-Tests.ps1: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "        At: $($_.InvocationInfo.PositionMessage)" -ForegroundColor Yellow
    exit 1
} finally {
    $env:SENTINEL_TEST_MODE = $null
    $env:SENTINEL_STATE_DIR = $null
    Remove-Item -Path $TestStateDir -Recurse -Force -ErrorAction SilentlyContinue
}
