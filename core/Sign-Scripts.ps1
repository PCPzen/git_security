# =====================================================================
# Security Sentinel Ultra v8.0 - Authenticode Code Signing & Pinning Tool
# Reuses a single persistent certificate, prunes stale duplicates from
# TrustedPublisher, pins TrustedCertThumbprint, and supports CNG Key Purge
# =====================================================================
[CmdletBinding()]
param(
    [string]$TargetDir = "$PSScriptRoot",
    [string]$CertSubject = "CN=Security Sentinel Ultra Code Signing",
    [switch]$PurgePrivateKey = $false
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   SECURITY SENTINEL ULTRA v8.0 - AUTHENTICODE SIGNING & PINNING      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Look for existing valid Code Signing cert with Private Key or create one
$allMatchingMy = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object {
    $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey
} | Sort-Object NotAfter -Descending)

$cert = $allMatchingMy | Select-Object -First 1

if (-not $cert) {
    Write-Host "[CERT] Creating 5-year SHA256 Code Signing Certificate..." -ForegroundColor Yellow
    try {
        $cert = New-SelfSignedCertificate -Subject $CertSubject `
                                          -CertStoreLocation "Cert:\CurrentUser\My" `
                                          -KeyUsage DigitalSignature `
                                          -KeyLength 2048 `
                                          -HashAlgorithm "SHA256" `
                                          -Type CodeSigningCert `
                                          -NotAfter (Get-Date).AddYears(5) `
                                          -ErrorAction Stop
        Write-Host "       -> Created Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to create self-signed certificate: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[CERT] Reusing active Code Signing Certificate: $($cert.Thumbprint)" -ForegroundColor Green
}

# 2. Prune stale/duplicate certificates with the same Subject from CurrentUser\My & CurrentUser\TrustedPublisher
foreach ($storeName in @("My", "TrustedPublisher")) {
    try {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
        $st.Open("ReadWrite")
        foreach ($oldCert in @($st.Certificates)) {
            if ($oldCert.Subject -eq $CertSubject -and $oldCert.Thumbprint -ne $cert.Thumbprint) {
                $st.Remove($oldCert)
                Write-Host "[CLEAN] Removed stale certificate ($($oldCert.Thumbprint)) from CurrentUser\$storeName." -ForegroundColor DarkGray
            }
        }
        $st.Close()
    } catch {}
}

# 3. Ensure active Public Certificate is in CurrentUser\TrustedPublisher
try {
    $pubBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $pubCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$pubBytes)
    $storePub = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
    $storePub.Open("ReadWrite")
    $existingPub = $storePub.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $existingPub) {
        $storePub.Add($pubCert)
        Write-Host "[CERT] Installed Public Certificate to CurrentUser\TrustedPublisher." -ForegroundColor Green
    }
    $storePub.Close()
} catch {
    Write-Host "[WARN] TrustedPublisher notice: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# 4. Pin Certificate Thumbprint into core/trusted_cert.thumbprint & HKLM Anchor (if Admin)
$thumbprint = $cert.Thumbprint.ToUpper()
$tpFile = Join-Path $PSScriptRoot "trusted_cert.thumbprint"
try {
    [System.IO.File]::WriteAllText($tpFile, $thumbprint, [System.Text.Encoding]::UTF8)
    Write-Host "[PIN]  Pinned TrustedCertThumbprint ($thumbprint) to trusted_cert.thumbprint" -ForegroundColor Green
} catch {}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    $regAnchor = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regAnchor) {
        Set-ItemProperty -Path $regAnchor -Name "TrustedCertThumbprint" -Value $thumbprint -Force -ErrorAction SilentlyContinue
    }
}

# 5. Locate all .ps1 files in repository and sign them (Sign-Scripts.ps1 signed last)
$rootPath = Split-Path -Parent $PSScriptRoot
$allPs1 = @(Get-ChildItem -Path $rootPath -Filter "*.ps1" -Recurse | Where-Object { $_.FullName -notmatch "\\\.git\\" })
$otherScripts = @($allPs1 | Where-Object { $_.Name -ne "Sign-Scripts.ps1" })
$selfScript   = @($allPs1 | Where-Object { $_.Name -eq "Sign-Scripts.ps1" })
$filesToSign  = $otherScripts + $selfScript

Write-Host "`n[SIGN] Signing $($filesToSign.Count) PowerShell scripts with Authenticode (SHA256)..." -ForegroundColor Yellow
$signedCount = 0

foreach ($f in $filesToSign) {
    try {
        $res = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop
        if ($res.SignerCertificate -and $res.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
            Write-Host "  [SIGNED] $($f.Name) (Thumbprint: $($cert.Thumbprint.Substring(0, 12))...)" -ForegroundColor Green
            $signedCount++
        } else {
            Write-Host "  [WARN]   $($f.Name) (Status: $($res.Status))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [FAIL]   $($f.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 6. Optional CNG/CAPI Private Key Container Destruction + Store Removal
if ($PurgePrivateKey) {
    try {
        try {
            $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsaKey -is [System.Security.Cryptography.RSACng] -and $rsaKey.Key) {
                $rsaKey.Key.Delete()
                Write-Host "`n[KEY PURGE] Underlying CNG Private Key container permanently destroyed." -ForegroundColor Green
            }
        } catch {}

        $myStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        $myStore.Open("ReadWrite")
        $myStore.Remove($cert)
        $myStore.Close()
        Write-Host "[KEY PURGE] Certificate removed from CurrentUser\My store." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Key purge notice: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "   SIGNING COMPLETE: $signedCount / $($filesToSign.Count) FILES SIGNED (PINNED: $thumbprint)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
