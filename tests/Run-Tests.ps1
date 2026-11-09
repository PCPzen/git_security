# =====================================================================
# Security Sentinel Ultra v8.0 - Automated Test Runner
# Zero-dependency standalone test execution engine
# Tests: DPAPI, Anti-Bypass, Phishing, Parent-Spoofing Safe-Mode, Token Forgery
# =====================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - ENTERPRISE AUTOMATED TEST SUITE     " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$ScriptRoot = Split-Path -Parent $PSScriptRoot
$WatchdogPath = Join-Path $ScriptRoot "core\SentinelWatchdog.ps1"

if (-not (Test-Path $WatchdogPath)) {
    Write-Host "[FATAL] SentinelWatchdog.ps1 not found at: $WatchdogPath" -ForegroundColor Red
    exit 1
}

. $WatchdogPath -LibraryOnly

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

Write-Host "`n[SUITE 1] DPAPI Secret Vault & Integrity Anchor" -ForegroundColor Yellow
$secret = "https://discord.com/api/webhooks/enterprise_test_token"
$enc = Protect-DpapiString -PlainText $secret
Assert-Test -Name "DPAPI Protect generates non-empty ciphertext" -Condition (-not [string]::IsNullOrEmpty($enc) -and $enc -ne $secret)
$dec = Unprotect-DpapiString -CipherBase64 $enc
Assert-Test -Name "DPAPI Unprotect accurately recovers plaintext" -Condition ($dec -eq $secret)
$corrupt = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("BadCiphertext"))
Assert-Test -Name "DPAPI Unprotect rejects corrupted input gracefully" -Condition ((Unprotect-DpapiString -CipherBase64 $corrupt) -eq "")

Write-Host "`n[SUITE 2] Dashboard Exemption Anti-Bypass Protection" -ForegroundColor Yellow
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

Write-Host "`n[SUITE 4] Safe-Mode Zero-Trust Parent & Spoofing Defense (Real Inspect-SingleProcess)" -ForegroundColor Yellow
$fakeNodeForensics = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Users\victim\AppData\Local\Temp\node.exe" -CommandLine "node.exe -e evil()" -IsUnsigned $true -IsParentChildAnomaly $false -IsPhishingParent $false
Assert-Test -Name "Unsigned Temp binary 'node.exe' scores at least 60 (No silent pass)" -Condition ($fakeNodeForensics.RiskScore -ge 60) -Details "Score: $($fakeNodeForensics.RiskScore)/100"
Assert-Test -Name "Unsigned Temp binary flags UnsignedBinary(+25) and HighRiskPath(+20)" -Condition ($fakeNodeForensics.Reasons -contains "UnsignedBinary(+25)" -and $fakeNodeForensics.Reasons -contains "HighRiskPath(+20)")

# Real Inspect-SingleProcess test with Spoofed Parent vs Legitimate Parent
$childProc = [PSCustomObject]@{
    ProcessId        = 8881
    Name             = "worker.exe"
    ExecutablePath   = "C:\Users\victim\AppData\Local\Temp\worker.exe"
    CommandLine      = "worker.exe --task"
    ParentProcessId  = 7771
}
$spoofedParentMap = @{
    7771 = [PSCustomObject]@{
        ProcessId      = 7771
        Name           = "steam.exe"
        ExecutablePath = "C:\Users\victim\AppData\Local\Temp\steam.exe" # SPOOFED PARENT IN TEMP!
    }
}
$spoofedRes = Inspect-SingleProcess -p $childProc -procMap $spoofedParentMap
Assert-Test -Name "Inspect-SingleProcess REJECTS Safe-Mode pass when parent is spoofed in Temp" -Condition ($spoofedRes.Action -ne "AllowedWorkGamingSafeMode") -Details "Action: $($spoofedRes.Action)"

$childProcLegit = [PSCustomObject]@{
    ProcessId        = 8882
    Name             = "worker.exe"
    ExecutablePath   = "C:\Users\victim\AppData\Local\Temp\worker.exe"
    CommandLine      = "worker.exe --task"
    ParentProcessId  = 7771
}
$legitParentMap = @{
    7771 = [PSCustomObject]@{
        ProcessId      = 7771
        Name           = "steam.exe"
        ExecutablePath = "C:\Program Files (x86)\Steam\steam.exe" # GENUINE PARENT IN PROGRAM FILES!
    }
}
$legitRes = Inspect-SingleProcess -p $childProcLegit -procMap $legitParentMap
Assert-Test -Name "Inspect-SingleProcess ACCEPTS Safe-Mode pass when parent is genuine in Program Files" -Condition ($legitRes.Action -eq "AllowedWorkGamingSafeMode") -Details "Action: $($legitRes.Action)"

Write-Host "`n[SUITE 5] Stop Token Security, Token Forgery & Registry Vault Defense" -ForegroundColor Yellow
$invalidToken = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
Assert-Test -Name "Stop token with mismatched PID strictly rejected" -Condition (-not $invalidToken)

# Attacker Token Forgery Simulation: Attacker tries to forge stop token without the real HKLM secret
$attackerPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$attackerBytes = [System.Text.Encoding]::UTF8.GetBytes($attackerPayload)
$fakeAttackerEntropy = [System.Text.Encoding]::UTF8.GetBytes("ATTACKER_FAKE_SECRET_1234567890123")
$forgedEnc = [System.Security.Cryptography.ProtectedData]::Protect($attackerBytes, $fakeAttackerEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$stopTokenPath = Join-Path $StateDir "graceful_stop.token"
[System.IO.File]::WriteAllText($stopTokenPath, [Convert]::ToBase64String($forgedEnc), [System.Text.Encoding]::UTF8)

$forgedTokenAccepted = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
Assert-Test -Name "Attacker stop token forged without HKLM secret strictly rejected" -Condition (-not $forgedTokenAccepted)

# Replay Attack Protection: Token with expired timestamp (> 60s)
$expiredPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.AddSeconds(-120).ToUnixTimeSeconds())"
$expiredEnc = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($expiredPayload), $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.IO.File]::WriteAllText($stopTokenPath, [Convert]::ToBase64String($expiredEnc), [System.Text.Encoding]::UTF8)
$expiredTokenAccepted = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
Assert-Test -Name "Replay attack stop token with expired timestamp strictly rejected" -Condition (-not $expiredTokenAccepted)

# Zero-Trust HKCU Secret Purge Verification
$hkcuSecretExists = $false
if (Test-Path "HKCU:\Software\SecuritySentinel\IntegrityAnchor") {
    $val = (Get-ItemProperty -Path "HKCU:\Software\SecuritySentinel\IntegrityAnchor" -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
    if ($val) { $hkcuSecretExists = $true }
}
Assert-Test -Name "Zero-Trust: No InstallSecret stored in HKCU (Same-user malware cannot read)" -Condition (-not $hkcuSecretExists)

Write-Host "`n[SUITE 6] Canary Honeypot & SACL XML Attribution" -ForegroundColor Yellow
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
Assert-Test -Name "SACL 4663 XML correctly parses ProcessName" -Condition ($parsedEv.ProcessName -eq "C:\Users\Victim\AppData\Local\Temp\stealer.exe")
Assert-Test -Name "SACL 4663 XML correctly identifies Canary ObjectName" -Condition ($parsedEv.ObjectName -match "SecuritySentinel_Canary")

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   SUMMARY: $passedTests / $totalTests TESTS PASSED ($failedTests FAILED)" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan

if ($failedTests -gt 0) { exit 1 } else { exit 0 }

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBtOIANfpMMb7Ly
# rxjsLs1MiD4uEX3erTa6R9jg+jYU6KCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ90F2LT7Yl814FXkykm
# hwFCgzMGdfOaDxS0RdvTxFx6MA0GCSqGSIb3DQEBAQUABIIBAGV1kABnbUs+I5tA
# cDuUNmIsBa4secPELu+OGXI0LGt823UJiTiPm7PFrQKeUFLzlSg+JVjPixt9dwWh
# 3Txc6fAcHIEkByOzYJT4iCKY4Mly4J4dHJMP7oiuX5VHairD3mid82varpVBlkSP
# Kqg36ATlVLDszsliiYPlshNGmI8pOWvMXriB28GN7BbW4IAJ+ZXgDsBo82vUvGK6
# AMHVZCV+PAkrQJDFge/19Y+tx/+sk9nb+ZYs9BiSlex3jzK0eF+RYK6GcySByFzm
# mF00SV9Sx5jCaMsdmAsYLUCagKFlO+zp3GIIcX/Wvq2tV2PUkyBFLLgB1Rz2ZB2y
# cYamuZo=
# SIG # End signature block
