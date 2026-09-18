<#
.SYNOPSIS
    Authenticode-sign one file for Nazgul. Called by Tauri's bundler (signCommand)
    for each artifact, and usable on its own.

.DESCRIPTION
    Signing is opt-in. It runs only when a certificate is configured through the
    environment; otherwise it prints a note and exits 0 so ordinary/dev builds and
    forks are never blocked by a missing certificate.

    Certificate selection, in order:
      NAZGUL_CERT_THUMBPRINT  - SHA-1 thumbprint of a cert in Cert:\CurrentUser\My
                                or Cert:\LocalMachine\My (preferred; no secrets on disk).
      NAZGUL_PFX + NAZGUL_PFX_PASSWORD
                              - path to a .pfx and its password (used by CI).

    Every signature is RFC-3161 timestamped so it stays valid after the certificate
    expires.

.PARAMETER Path
    The file to sign. Tauri passes the artifact path here via the %1 placeholder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Path
)

$ErrorActionPreference = "Stop"
$timestampUrl = if ($env:NAZGUL_TIMESTAMP_URL) { $env:NAZGUL_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }

$thumb = $env:NAZGUL_CERT_THUMBPRINT
$pfx   = $env:NAZGUL_PFX

if (-not $thumb -and -not $pfx) {
    Write-Host "sign.ps1: no signing certificate configured, leaving '$Path' unsigned." -ForegroundColor Yellow
    exit 0
}

if (-not (Test-Path $Path)) {
    Write-Error "sign.ps1: file not found: $Path"
    exit 1
}

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "${env:ProgramFiles}\Windows Kits\10\bin")
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $found = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match "\\x64\\" } |
                Sort-Object FullName -Descending | Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    return $null
}

$signtool = Find-SignTool
if (-not $signtool) {
    Write-Error "sign.ps1: signtool.exe not found. Install the Windows SDK (App Certification Kit)."
    exit 1
}

$common = @("sign", "/fd", "SHA256", "/tr", $timestampUrl, "/td", "SHA256", "/v")

if ($thumb) {
    $signArgs = $common + @("/sha1", $thumb, $Path)
} else {
    if (-not $env:NAZGUL_PFX_PASSWORD) {
        Write-Error "sign.ps1: NAZGUL_PFX is set but NAZGUL_PFX_PASSWORD is not."
        exit 1
    }
    $signArgs = $common + @("/f", $pfx, "/p", $env:NAZGUL_PFX_PASSWORD, $Path)
}

Write-Host "sign.ps1: signing $Path" -ForegroundColor Cyan
& $signtool @signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "sign.ps1: signtool failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Informational verify only. A self-signed certificate fails /pa until its root is
# trusted on the machine; that is expected and must not fail the build. Native stderr
# under ErrorActionPreference=Stop would throw, so soften it for this call.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $signtool verify /pa $Path *> $null
$verifyOk = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prevEAP

if ($verifyOk) {
    Write-Host "sign.ps1: signed and verified (chain trusted here) $Path" -ForegroundColor Green
} else {
    Write-Host "sign.ps1: signed $Path (chain not trusted on this machine yet; add the certificate to Trusted Publishers)" -ForegroundColor Green
}

# Real-time antivirus opens the just-written file to scan it, and the bundler's next
# step (copying it into the installer layout) then fails with "file in use" (os error
# 32). Wait until the file can be opened exclusively, i.e. the scanner has let go.
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
        $fs.Close()
        break
    } catch {
        Start-Sleep -Milliseconds 250
    }
}
exit 0
