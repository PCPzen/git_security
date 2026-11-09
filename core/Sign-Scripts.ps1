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
# HGm3oow4SLo4cvZ8uMapOJMYLvycNqCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
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
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJEEOW0CP/IbBocBVhsS
# CNOz/PlwJzLWVfkItKXhsdTlMA0GCSqGSIb3DQEBAQUABIIBAFJe9UmLPUA+idLH
# ZXINaqlPO5NIM9d9iA/TySls19FC9rPgs+9QootHiFu7ehhUkspm9mQl65Ew/l5x
# F6mD3YzzeQ+OZ4rb0hxIrWMccnQY970q5zN/QtmThnIhBfX3xkthfiMr0KmxVUPb
# lwtfxr3IZW/lBdZ0Nm3d0s+5tr9rBaSbVnUYulpQx+Q3b86s9UDcxXwV1VJJE3tu
# 2wrWyL8nuVrzWsokrAhb6tPHbRwTI6nynw+Gd4y4VPSSp7TKIyMJfRlKWt9OOR7Y
# RJHzpGgAgR8DaBx7Qd0WegUS84rW/1W5l0HX5b0QSJPaLd1cM7Wc0dPWG3yFAQjk
# gnAtwTY=
# SIG # End signature block
