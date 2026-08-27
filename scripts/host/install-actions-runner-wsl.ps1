[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$Sha256,

    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$InstallerScript
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($InstallerScript)) {
    $InstallerScript = Join-Path $PSScriptRoot "install-actions-runner.sh"
}
if ($DistroName -ne "Ubuntu-24.04-CI") {
    throw "DistroName must be Ubuntu-24.04-CI."
}
if (-not (Test-Path -LiteralPath $InstallerScript -PathType Leaf)) {
    throw "Installer script not found: $InstallerScript"
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe is unavailable."
}

$installer = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $InstallerScript)).Replace("`r`n", "`n")
$verifierPath = Join-Path (Split-Path -Parent $InstallerScript) "verify-actions-runner.sh"
if (-not (Test-Path -LiteralPath $verifierPath -PathType Leaf)) {
    throw "Verifier script not found: $verifierPath"
}
$verifier = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $verifierPath)).Replace("`r`n", "`n")
$installerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($installer))
$verifierBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($verifier))
$normalizedSha256 = $Sha256.ToLowerInvariant()

$wslCommand = @"
set -euo pipefail
work_dir=`$(mktemp -d)
trap 'rm -rf -- "`$work_dir"' EXIT
printf '%s' '$installerBase64' | base64 --decode >"`$work_dir/install-actions-runner.sh"
printf '%s' '$verifierBase64' | base64 --decode >"`$work_dir/verify-actions-runner.sh"
chmod 0700 "`$work_dir/install-actions-runner.sh" "`$work_dir/verify-actions-runner.sh"
"`$work_dir/install-actions-runner.sh" --version '$Version' --sha256 '$normalizedSha256'
"@

& wsl.exe --distribution $DistroName --user root -- bash -lc $wslCommand
if ($LASTEXITCODE -ne 0) {
    throw "GitHub Actions Runner installation failed with exit code $LASTEXITCODE."
}
Write-Host "GitHub Actions Runner $Version installed and verified in $DistroName."
