<#
.SYNOPSIS
    Create a self-signed code-signing certificate for Nazgul.

.DESCRIPTION
    Produces a code-signing certificate in the current user's certificate store and
    exports two files:

      nazgul-codesign.cer  - the PUBLIC certificate. Hand this to IT so they can add
                             it to Trusted Publishers (via GPO or the SentinelOne
                             console). It contains no private key and is safe to share.
      nazgul-codesign.pfx  - the PRIVATE key + certificate, password protected. Keep
                             this secret. It is what actually signs the binaries.

    A self-signed certificate is trusted only on machines where its public .cer has
    been added to the Trusted Publishers (and Trusted Root) store. On a managed work
    machine that placement is an administrator / security-team action.

.EXAMPLE
    pwsh -File scripts/new-selfsigned-cert.ps1 -Password (Read-Host -AsSecureString)
#>
[CmdletBinding()]
param(
    [string] $Subject = "Wyatt Rossell (Nazgul OSINT)",
    [string] $OutDir = "$PSScriptRoot\..\certs",
    [int]    $Years = 3,
    [System.Security.SecureString] $Password
)

$ErrorActionPreference = "Stop"

if (-not $Password) {
    $Password = Read-Host -Prompt "Choose a password to protect the .pfx private key" -AsSecureString
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

Write-Host "Creating self-signed code-signing certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$Subject" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears($Years) `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

$cer = Join-Path $OutDir "nazgul-codesign.cer"
$pfx = Join-Path $OutDir "nazgul-codesign.pfx"

Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $Password | Out-Null

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Public cert: $cer   (share with IT)"
Write-Host "  Private pfx: $pfx   (keep secret)"
Write-Host ""
Write-Host "To sign local builds, set this once per shell:" -ForegroundColor Cyan
Write-Host "  `$env:NAZGUL_CERT_THUMBPRINT = '$($cert.Thumbprint)'"
Write-Host "then run:  npm run tauri build"
Write-Host ""
Write-Host "The certificate is in Cert:\CurrentUser\My. It signs from there by thumbprint;"
Write-Host "the .pfx is only needed to move signing to another machine or to CI."
