# =====================================================================
# Security Sentinel Ultra v8.0 - Authenticode Code Signing Tool
# Generates a trusted Code Signing Certificate and signs all .ps1 scripts
# Enables running under: Set-ExecutionPolicy AllSigned -Scope CurrentUser
# =====================================================================

[CmdletBinding()]
param(
    [string]$TargetDir = "$PSScriptRoot",
    [string]$CertSubject = "CN=Security Sentinel Ultra Code Signing"
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - AUTHENTICODE SIGNING TOOL           " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Look for existing valid Code Signing cert
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object {
    $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date)
} | Select-Object -First 1

if (-not $cert) {
    Write-Host "[CERT] Creating new 5-year SHA256 Code Signing Certificate..." -ForegroundColor Yellow
    try {
        $cert = New-SelfSignedCertificate -Subject $CertSubject `
                                          -CertStoreLocation "Cert:\CurrentUser\My" `
                                          -KeyUsage DigitalSignature `
                                          -KeyLength 2048 `
                                          -HashAlgorithm "SHA256" `
                                          -Type CodeSigningCert `
                                          -NotAfter (Get-Date).AddYears(5) `
                                          -ErrorAction Stop
        Write-Host "       -> Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to create self-signed certificate: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[CERT] Found existing valid Code Signing Certificate: $($cert.Thumbprint)" -ForegroundColor Green
}

# 2. Add to TrustedPublisher without interactive prompt
try {
    $storePub = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
    $storePub.Open("ReadWrite")
    $storePub.Add($cert)
    $storePub.Close()
    Write-Host "[CERT] Installed certificate to CurrentUser\TrustedPublisher." -ForegroundColor Green
} catch {
    Write-Host "[WARN] TrustedPublisher notice: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# 3. Locate all .ps1 files in repository and sign them
$rootPath = Split-Path -Parent $PSScriptRoot
$filesToSign = @(Get-ChildItem -Path $rootPath -Filter "*.ps1" -Recurse | Where-Object { $_.FullName -notmatch "\\\.git\\" })

Write-Host "`n[SIGN] Signing $($filesToSign.Count) PowerShell scripts with Authenticode (SHA256)..." -ForegroundColor Yellow
$signedCount = 0

foreach ($f in $filesToSign) {
    try {
        $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop
        if ($res.Status -eq "Valid") {
            Write-Host "  [SIGNED] $($f.Name) (Status: Valid)" -ForegroundColor Green
            $signedCount++
        } else {
            Write-Host "  [WARN]   $($f.Name) (Status: $($res.Status))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [FAIL]   $($f.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   SIGNING COMPLETE: $signedCount / $($filesToSign.Count) FILES VALIDLY SIGNED" -ForegroundColor Green
Write-Host "   Execution Policy compatibility: Set-ExecutionPolicy AllSigned" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7H9KoL0NKbisl
# z9RyRJCJqLwGgwMeA8jes5EARp8ic6CCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKNMvQ0noK6nlqoGtLtA
# Z4Ydnpn9sjKksT+2VjrnCQWJMA0GCSqGSIb3DQEBAQUABIIBALlPtt9NxUIUKKR7
# /x/r1K5yzxA4NntEOdklG+N+XY9cuoBUikdTkPJO6c6h7wwuSiqpwLh7t1gBiCRS
# cBRKkQ0vo+0f8u5V4XJJLmCuyt0yjG6wmch8Zjjjkb3VEef7MSn/yQl8nyAJtPuu
# JSOasbGIwNoRdkaT/WGqi6twjAIEzw6SjOEn5dfq0OTeOMIr+ut31+gMxwcSdJ0S
# YOYL/q9Qb03QHPV9pyK3k1cB6e7UWqj/R5EqIrobDaS7CYNKfF0ajwTlUSIseegG
# nQHmE99o9JNXYP3EHbZhTIG0QzWc1Yi8lf7jhDkk3fZHe8LnxqyUAcanUXj0bYXq
# 7unRWEo=
# SIG # End signature block
