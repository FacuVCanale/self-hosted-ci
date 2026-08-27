[CmdletBinding()]
param(
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$BootstrapScript,
    [switch]$TerminateAfterBootstrap
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($BootstrapScript)) {
    $BootstrapScript = Join-Path $PSScriptRoot "bootstrap-ubuntu-24.04-wsl.sh"
}

if ($DistroName -ne "Ubuntu-24.04-CI") {
    throw "DistroName must be Ubuntu-24.04-CI."
}
if (-not (Test-Path -LiteralPath $BootstrapScript -PathType Leaf)) {
    throw "Bootstrap script not found: $BootstrapScript"
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe is unavailable."
}

$installedDistros = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Trim([char]0).Trim() } | Where-Object { $_ }
if ($LASTEXITCODE -ne 0) {
    throw "Unable to list WSL distributions."
}
if ($installedDistros -notcontains $DistroName) {
    throw "Required dedicated WSL distribution is not installed: $DistroName"
}

$bootstrap = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $BootstrapScript)).Replace("`r`n", "`n")
$bootstrapBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($bootstrap))
$wslCommand = "printf '%s' '$bootstrapBase64' | base64 --decode | bash"
& wsl.exe --distribution $DistroName --user root -- bash -lc $wslCommand
if ($LASTEXITCODE -ne 0) {
    throw "Host bootstrap failed with exit code $LASTEXITCODE."
}

if ($TerminateAfterBootstrap) {
    & wsl.exe --terminate $DistroName
    if ($LASTEXITCODE -ne 0) {
        throw "Bootstrap succeeded, but terminating $DistroName failed."
    }
    Write-Host "Bootstrap complete; $DistroName was terminated and will apply wsl.conf on next start."
}
else {
    Write-Host "Bootstrap complete. Run 'wsl.exe --terminate $DistroName' before further verification."
}
