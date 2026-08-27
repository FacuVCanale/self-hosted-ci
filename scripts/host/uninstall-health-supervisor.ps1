[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$ReaderAccount = "selfhosted-ci-health",
    [switch]$Apply,
    [switch]$AcknowledgeTaskRemoval,
    [switch]$AcknowledgeFinalPasswordRotation,
    [switch]$AcknowledgeHealthArtifactRemoval
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Health-Supervisor"
$ControlRoot = "C:\ProgramData\self-hosted-ci\control"
$HealthRoot = "C:\ProgramData\self-hosted-ci\health"
$InstalledSupervisor = Join-Path $ControlRoot "run-health-supervisor.ps1"
$SnapshotPath = Join-Path $HealthRoot "current.json"
$SshdConfig = "C:\ProgramData\ssh\sshd_config"
$SshdBackup = Join-Path $ControlRoot "sshd_config.before-health-sftp"
$SftpBegin = "# BEGIN SELF_HOSTED_CI_HEALTH_SFTP"
$SftpEnd = "# END SELF_HOSTED_CI_HEALTH_SFTP"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Test-IsAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-CryptographicAccountPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        $text = "Aa1!" + [Convert]::ToBase64String($bytes)
        return ConvertTo-SecureString $text -AsPlainText -Force
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $text = $null; $rng.Dispose() }
}

function Assert-SafeArtifactTree([string]$Root, [string[]]$AllowedFiles) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "required artifact directory is absent: $Root" }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "artifact root is a reparse point" }
    $allowed = @($AllowedFiles | ForEach-Object { [IO.Path]::GetFullPath($_) })
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "artifact descendant is a reparse point: $($item.FullName)" }
        if ($item.PSIsContainer -or $allowed -notcontains [IO.Path]::GetFullPath($item.FullName)) { throw "unexpected artifact blocks uninstall: $($item.FullName)" }
    }
    foreach ($path in $allowed) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "required allowlisted artifact is absent: $path" } }
}

function Remove-ManagedSftpConfiguration {
    $content = Get-Content -LiteralPath $SshdConfig -Raw
    $pattern = '(?ms)\r?\n' + [regex]::Escape($SftpBegin) + '.*?' + [regex]::Escape($SftpEnd) + '\r?\nMatch all\r?\n'
    $updated = [regex]::Replace($content, $pattern, "`r`n", 1)
    if ($updated -eq $content -or $updated.Contains($SftpBegin) -or $updated.Contains($SftpEnd)) { throw "managed SFTP block is missing or ambiguous" }
    $temporary = "$SshdConfig.self-hosted-ci.tmp"
    try {
        [IO.File]::WriteAllText($temporary, $updated, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $SshdConfig -Force
        $sshd = (Get-Command sshd.exe -ErrorAction Stop).Source
        & $sshd -t -f $SshdConfig
        if ($LASTEXITCODE -ne 0) { throw "sshd rejected configuration after managed block removal" }
        Restart-Service -Name sshd -ErrorAction Stop
        if ((Get-Service -Name sshd).Status -ne "Running") { throw "sshd did not return to Running" }
    }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "uninstaller requires an elevated Windows console" }
if ($ReaderAccount -ne "selfhosted-ci-health") { throw "reader account name is pinned" }
$account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if ($account.SID.Value -ne $ExpectedServiceAccountSid) { throw "service-account SID mismatch" }
[ordered]@{ mode = "plan"; apply_requested = [bool]$Apply; task_name = $TaskName; remove = @($ControlRoot, $HealthRoot); rotate_service_password = $true } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeTaskRemoval -or -not $AcknowledgeFinalPasswordRotation -or -not $AcknowledgeHealthArtifactRemoval) { throw "Apply requires all removal acknowledgements" }

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) { throw "expected health supervisor task is absent" }
$actualSid = ([Security.Principal.NTAccount]::new([string]$task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])).Value
if ($task.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $task.Principal.LogonType -ne "Password" -or $task.Principal.RunLevel -ne "Limited") { throw "task path/principal postcondition failed" }
if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $PowerShellExe) { throw "task action executable is not exact" }
$nonceMatch = [regex]::Match([string]$task.Actions[0].Arguments, '-InstallNonce "(?<nonce>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"')
if (-not $nonceMatch.Success) { throw "task action install nonce is invalid" }
$expectedArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$InstalledSupervisor`" -ExpectedServiceAccountSid `"$ExpectedServiceAccountSid`" -InstallNonce `"$($nonceMatch.Groups['nonce'].Value)`" -ExpectedServiceAccount `"$ServiceAccount`" -ExpectedDistroName `"$DistroName`" -SnapshotPath `"$SnapshotPath`""
if ($task.Actions[0].Arguments -ne $expectedArguments) { throw "task action arguments are not exact" }
Assert-SafeArtifactTree $ControlRoot @($InstalledSupervisor, $SshdBackup)
Assert-SafeArtifactTree $HealthRoot @($SnapshotPath)
$managedConfig = Get-Content -LiteralPath $SshdConfig -Raw
if ([regex]::Matches($managedConfig, [regex]::Escape($SftpBegin)).Count -ne 1 -or [regex]::Matches($managedConfig, [regex]::Escape($SftpEnd)).Count -ne 1) { throw "managed SFTP configuration is missing or duplicated" }
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$stopDeadline = (Get-Date).AddSeconds(30)
do { Start-Sleep -Milliseconds 500; $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop } while ([string]$task.State -eq "Running" -and (Get-Date) -lt $stopDeadline)
if ([string]$task.State -eq "Running") { throw "task did not stop within the bounded deadline" }
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "task still exists after removal" }
$password = $null
try {
    $password = New-CryptographicAccountPassword
    Set-LocalUser -Name $account.Name -Password $password -ErrorAction Stop
}
finally { if ($null -ne $password) { $password.Dispose() } }
Disable-LocalUser -Name $ReaderAccount -ErrorAction Stop
if ((Get-LocalUser -Name $ReaderAccount -ErrorAction Stop).Enabled) { throw "health reader did not remain disabled" }
Remove-ManagedSftpConfiguration
foreach ($path in @($ControlRoot, $HealthRoot)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
[ordered]@{ status = "uninstalled"; task_absent = $true; stored_task_credential_invalidated = $true; health_artifacts_removed = $true; runner_registration_changed = $false } | ConvertTo-Json -Compress
