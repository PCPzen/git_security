# =====================================================================
# Security Sentinel Ultra v8.0 - Automated Test Runner
# Zero-dependency standalone test execution engine
# =====================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - AUTOMATED TEST SUITE RUNNER         " -ForegroundColor Cyan
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

Write-Host "`n[SUITE 4] Safe-Mode Zero-Trust Name-Spoofing Immunity" -ForegroundColor Yellow
$fakeNodeForensics = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Users\victim\AppData\Local\Temp\node.exe" -CommandLine "node.exe -e evil()" -IsUnsigned $true -IsParentChildAnomaly $false -IsPhishingParent $false
Assert-Test -Name "Unsigned Temp binary 'node.exe' scores at least 60 (No silent pass)" -Condition ($fakeNodeForensics.RiskScore -ge 60) -Details "Score: $($fakeNodeForensics.RiskScore)/100"
Assert-Test -Name "Unsigned Temp binary flags UnsignedBinary(+25) and HighRiskPath(+20)" -Condition ($fakeNodeForensics.Reasons -contains "UnsignedBinary(+25)" -and $fakeNodeForensics.Reasons -contains "HighRiskPath(+20)")

Write-Host "`n[SUITE 5] Stop Token Security & Forgery Protection" -ForegroundColor Yellow
$invalidToken = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
Assert-Test -Name "Stop token with mismatched PID rejected" -Condition (-not $invalidToken)

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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0ZGKihD5ExQKC
# d46mNGx+4sYcyyNYqrHC0/+E8om0AqCCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINbHCeOYrNvqE3D1e5tV
# ec0fjAQ1NT2xbG02F4VDVuqTMA0GCSqGSIb3DQEBAQUABIIBAFB2Cyg6ufU6NGlN
# ZSLKzuo2BegxgyEkDMq3sNAxaf5uWQHCLwYoKnRtA4DwHL8ih5bKzinW7IYjXxHL
# igFNRikY8NCWBbsJzN6MYLtuZdsj8j1Fz3YMhgJBtbs5+Dj3VID5U1DqT6rKnhaX
# l2fZNBKTgRDCwmn/how2pJcilIVa5v5TeIEPPd2r7pUAORqRclFpVW+E/oB7wgfO
# +oMd+tm3QlRXS5PoKX1//YwUcoF9yDTR2MlDfaVMVLHZbj1/rsFn8JFl2BPz6k3L
# zsWJIqXjvpb0oR51kP3oaPvB98e9/cJO+zZxJSwmvmXnEUurmTRYyab6yRBZcPLI
# xwgpQt8=
# SIG # End signature block
