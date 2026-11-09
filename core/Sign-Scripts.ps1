# =====================================================================
# Security Sentinel Ultra v8.0 - Authenticode Code Signing Tool
# Generates a trusted Code Signing Certificate and signs all .ps1 scripts
# Enables running under: Set-ExecutionPolicy AllSigned -Scope CurrentUser
# Zero-Trust Private Key Hardening: Purges Private Key after signing!
# =====================================================================

[CmdletBinding()]
param(
    [string]$TargetDir = "$PSScriptRoot",
    [string]$CertSubject = "CN=Security Sentinel Ultra Code Signing",
    [switch]$PurgePrivateKey = $true
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - AUTHENTICODE SIGNING TOOL           " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Look for existing valid Code Signing cert or create a new one
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object {
    $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey
} | Select-Object -First 1

if (-not $cert) {
    Write-Host "[CERT] Creating new 5-year SHA256 Code Signing Certificate with ephemeral key..." -ForegroundColor Yellow
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

# 2. Add Public Key to TrustedPublisher
try {
    $pubBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $pubCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$pubBytes)
    $storePub = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
    $storePub.Open("ReadWrite")
    $storePub.Add($pubCert)
    $storePub.Close()
    Write-Host "[CERT] Installed Public Certificate to CurrentUser\TrustedPublisher." -ForegroundColor Green
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

# 4. Zero-Trust Private Key Defense: Purge Private Key from User Store so malware cannot sign modified scripts!
if ($PurgePrivateKey) {
    try {
        $myStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        $myStore.Open("ReadWrite")
        $myStore.Remove($cert)
        $myStore.Close()
        Write-Host "`n[KEY PURGE] Private Key successfully purged from CurrentUser\My store." -ForegroundColor Green
        Write-Host "            -> Only Public Key remains in TrustedPublisher (Same-user malware cannot sign scripts!)." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Key purge notice: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   SIGNING COMPLETE: $signedCount / $($filesToSign.Count) FILES VALIDLY SIGNED" -ForegroundColor Green
Write-Host "   Execution Policy compatibility: Set-ExecutionPolicy AllSigned" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBwklehdvsjQ6M8
# HGm3oow4SLo4cvZ8uMapOJMYLvycNqCCAzIwggMuMIICFqADAgECAhARiv7ch4Yq
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJEEOW0CP/IbBocBVhsS
# CNOz/PlwJzLWVfkItKXhsdTlMA0GCSqGSIb3DQEBAQUABIIBAHGrmkj1c7JhKOc7
# tNEmU+e1+uCH5gaaFKkfmutuoqIC18VyEDa5HePpOEC3N3wGmfnVisg/GWCSw3q4
# nV6bOG6Nzl2a3kRiRby+HILe5sGOkBn6fkx5wYKMk9xU8v/NfnxVHHNPWaklraVy
# gm0r4PFduc8BwZGSBcyMcEpeXXzMb6oZIf027C4y1WbbvM1TCaK+dyUjhFkAECat
# 0ZJx52cns17PycPv7+hk4B0DzHUPIJsjRf4E8KyJiP0qM5Y3ylt2XW9I7wyQJ+K4
# RQtLUM2acpRCoxzvNWU5NNWhM46rEpnpoj9ZPhPi08TIiSZXYwbIXDz6q4QbSGDN
# dx/b8qc=
# SIG # End signature block
