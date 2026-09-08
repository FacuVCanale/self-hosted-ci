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
$MarkerRoot = Join-Path $env:ProgramFiles "self-hosted-ci\transactions"
$MarkerPath = Join-Path $MarkerRoot "health-supervisor-uninstall-v1.json"
$MarkerVersion = 1

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

function Get-TransactionRootAcl {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admins)
    foreach ($sid in @($system, $admins)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Assert-TransactionRoot([bool]$AllowAbsent) {
    if (-not (Test-Path -LiteralPath $env:ProgramFiles -PathType Container)) { throw "Program Files is absent" }
    $programFilesItem = Get-Item -LiteralPath $env:ProgramFiles -Force
    if (($programFilesItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Program Files is a reparse point" }
    if (-not (Test-Path -LiteralPath $MarkerRoot)) {
        if ($AllowAbsent) { return }
        throw "transaction root is absent"
    }
    if (-not (Test-Path -LiteralPath $MarkerRoot -PathType Container)) { throw "transaction root is not a directory" }
    $rootItem = Get-Item -LiteralPath $MarkerRoot -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "transaction root is a reparse point" }
    $acl = Get-Acl -LiteralPath $MarkerRoot
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") { throw "transaction root ACL is not protected" }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "transaction root ACL is not exact" }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne "Allow" -or
            $rule.IdentityReference.Value -notin @("S-1-5-18", "S-1-5-32-544") -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "transaction root ACL is not exact"
        }
    }
}

function Ensure-TransactionRoot {
    if (-not (Test-Path -LiteralPath $MarkerRoot)) {
        [void](New-Item -ItemType Directory -Path $MarkerRoot -Force)
        Set-Acl -LiteralPath $MarkerRoot -AclObject (Get-TransactionRootAcl)
    }
    Assert-TransactionRoot $false
}

function Assert-SafeArtifactTree([string]$Root, [string[]]$AllowedFiles, [bool]$AllowMissing, [bool]$RequireAll) {
    if (-not (Test-Path -LiteralPath $Root)) {
        if ($AllowMissing) { return }
        throw "required artifact directory is absent: $Root"
    }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "artifact root is not a directory: $Root" }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "artifact root is a reparse point" }
    $allowed = @($AllowedFiles | ForEach-Object { [IO.Path]::GetFullPath($_) })
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "artifact descendant is a reparse point: $($item.FullName)" }
        if ($item.PSIsContainer -or $allowed -notcontains [IO.Path]::GetFullPath($item.FullName)) { throw "unexpected artifact blocks uninstall: $($item.FullName)" }
    }
    if ($RequireAll) {
        foreach ($path in $allowed) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "required allowlisted artifact is absent: $path" } }
    }
}

function Get-MarkerAcl {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admins)
    foreach ($sid in @($system, $admins)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Assert-UninstallMarker {
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) { throw "uninstall reconciliation marker is absent" }
    $item = Get-Item -LiteralPath $MarkerPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "uninstall reconciliation marker is a reparse point" }
    $acl = Get-Acl -LiteralPath $MarkerPath
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") { throw "uninstall reconciliation marker ACL is not protected" }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "uninstall reconciliation marker ACL is not exact" }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne "Allow" -or $rule.IdentityReference.Value -notin @("S-1-5-18", "S-1-5-32-544") -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw "uninstall reconciliation marker ACL is not exact" }
    }
    $raw = [IO.File]::ReadAllText($MarkerPath)
    $value = $raw | ConvertFrom-Json
    $names = @($value.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @("created_at", "distro", "marker_version", "reader_account", "service_account_sid", "task_name") | Sort-Object
    $parsed = [DateTimeOffset]::MinValue
    $createdAtValid = [DateTimeOffset]::TryParse([string]$value.created_at, [ref]$parsed)
    $canonical = ([ordered]@{ marker_version=$MarkerVersion; task_name=$TaskName; service_account_sid=$ExpectedServiceAccountSid; distro=$DistroName; reader_account=$ReaderAccount; created_at=[string]$value.created_at } | ConvertTo-Json -Compress) + "`n"
    if (($names -join "`n") -cne ($expectedNames -join "`n") -or
        $value.marker_version -ne $MarkerVersion -or $value.task_name -cne $TaskName -or
        $value.service_account_sid -cne $ExpectedServiceAccountSid -or $value.distro -cne $DistroName -or
        $value.reader_account -cne $ReaderAccount -or -not $createdAtValid -or
        [string]$value.created_at -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$' -or
        $parsed.Offset -ne [TimeSpan]::Zero -or $raw -cne $canonical) {
        throw "uninstall reconciliation marker content is not exact"
    }
}

function New-UninstallMarker {
    Ensure-TransactionRoot
    if (Test-Path -LiteralPath $MarkerPath) { throw "uninstall reconciliation marker already exists" }
    $temporary = "$MarkerPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $value = [ordered]@{ marker_version=$MarkerVersion; task_name=$TaskName; service_account_sid=$ExpectedServiceAccountSid; distro=$DistroName; reader_account=$ReaderAccount; created_at=[DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($value | ConvertTo-Json -Compress) + "`n")
    try {
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        Set-Acl -LiteralPath $temporary -AclObject (Get-MarkerAcl)
        Move-Item -LiteralPath $temporary -Destination $MarkerPath
        Assert-UninstallMarker
    }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function Get-ManagedSftpState {
    $content = Get-Content -LiteralPath $SshdConfig -Raw
    $expectedBlock = @"

$SftpBegin
Match all
Match User $ReaderAccount
    AuthorizedKeysFile C:/Users/selfhosted-ci-health/.ssh/authorized_keys
    ForceCommand internal-sftp
    DisableForwarding yes
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTTY no
    X11Forwarding no
$SftpEnd
Match all
"@
    $beginCount = [regex]::Matches($content, [regex]::Escape($SftpBegin)).Count
    $endCount = [regex]::Matches($content, [regex]::Escape($SftpEnd)).Count
    if ($beginCount -eq 0 -and $endCount -eq 0) { return "absent" }
    if ($beginCount -ne 1 -or $endCount -ne 1 -or -not $content.EndsWith($expectedBlock + "`r`n", [StringComparison]::Ordinal)) { throw "managed SFTP configuration is missing, duplicated, or not exact" }
    return "present"
}

function Assert-SshdValidAndRunning([bool]$AllowStart) {
    $sshd = (Get-Command sshd.exe -ErrorAction Stop).Source
    & $sshd -t -f $SshdConfig
    if ($LASTEXITCODE -ne 0) { throw "sshd rejected reconciled configuration" }
    if ((Get-Service -Name sshd -ErrorAction Stop).Status -ne "Running" -and $AllowStart) { Start-Service -Name sshd -ErrorAction Stop }
    if ((Get-Service -Name sshd -ErrorAction Stop).Status -ne "Running") { throw "sshd did not return to Running" }
}

function Remove-ManagedSftpConfiguration([string]$State) {
    if ($State -eq "absent") { Assert-SshdValidAndRunning $true; return }
    if ($State -ne "present") { throw "managed SFTP state is invalid" }
    $content = Get-Content -LiteralPath $SshdConfig -Raw
    $originalAcl = Get-Acl -LiteralPath $SshdConfig
    $pattern = '(?ms)\r?\n' + [regex]::Escape($SftpBegin) + '.*?' + [regex]::Escape($SftpEnd) + '\r?\nMatch all\r?\n'
    $updated = [regex]::Replace($content, $pattern, "`r`n", 1)
    if ($updated -eq $content -or $updated.Contains($SftpBegin) -or $updated.Contains($SftpEnd)) { throw "managed SFTP block is missing or ambiguous" }
    $temporary = "$SshdConfig.self-hosted-ci.tmp"
    $rollback = "$SshdConfig.self-hosted-ci.rollback"
    try {
        [IO.File]::WriteAllText($temporary, $updated, [Text.UTF8Encoding]::new($false))
        Set-Acl -LiteralPath $temporary -AclObject $originalAcl
        $sshd = (Get-Command sshd.exe -ErrorAction Stop).Source
        & $sshd -t -f $temporary
        if ($LASTEXITCODE -ne 0) { throw "sshd rejected candidate configuration before managed block removal" }
        Move-Item -LiteralPath $temporary -Destination $SshdConfig -Force
        try {
            Restart-Service -Name sshd -ErrorAction Stop
            Assert-SshdValidAndRunning $false
        }
        catch {
            $activationFailure = $_.Exception.Message
            $rollbackFailure = $null
            try {
                [IO.File]::WriteAllText($rollback, $content, [Text.UTF8Encoding]::new($false))
                Set-Acl -LiteralPath $rollback -AclObject $originalAcl
                & $sshd -t -f $rollback
                if ($LASTEXITCODE -ne 0) { throw "sshd rejected rollback configuration" }
                Move-Item -LiteralPath $rollback -Destination $SshdConfig -Force
                Restart-Service -Name sshd -ErrorAction Stop
                Assert-SshdValidAndRunning $false
            }
            catch { $rollbackFailure = $_.Exception.Message }
            $failure = [ordered]@{ operation="remove-managed-sftp"; activation_failure=$activationFailure; rollback_failure=$rollbackFailure } | ConvertTo-Json -Compress
            throw "managed SFTP removal failed: $failure"
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
        if (Test-Path -LiteralPath $rollback) { Remove-Item -LiteralPath $rollback -Force }
    }
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "uninstaller requires an elevated Windows console" }
if ($ReaderAccount -ne "selfhosted-ci-health") { throw "reader account name is pinned" }
$account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if ($account.SID.Value -ne $ExpectedServiceAccountSid) { throw "service-account SID mismatch" }
Assert-TransactionRoot $true
$markerPresent = Test-Path -LiteralPath $MarkerPath
if ($markerPresent) { Assert-UninstallMarker }
[ordered]@{ mode = "plan"; apply_requested = [bool]$Apply; task_name = $TaskName; remove = @($ControlRoot, $HealthRoot); rotate_service_password = $true; reconciliation_marker_present = [bool]$markerPresent; reconciliation_mode = [bool]$markerPresent } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeTaskRemoval -or -not $AcknowledgeFinalPasswordRotation -or -not $AcknowledgeHealthArtifactRemoval) { throw "Apply requires all removal acknowledgements" }

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task -and -not $markerPresent) { throw "expected health supervisor task is absent without owning reconciliation marker" }
$reader = Get-LocalUser -Name $ReaderAccount -ErrorAction Stop
if (-not $reader.Enabled -and -not $markerPresent) { throw "health reader is disabled without owning reconciliation marker" }
if ($null -ne $task) {
    $actualSid = ([Security.Principal.NTAccount]::new([string]$task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])).Value
    if ($task.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $task.Principal.LogonType -ne "Password" -or $task.Principal.RunLevel -ne "Limited") { throw "task path/principal postcondition failed" }
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $PowerShellExe) { throw "task action executable is not exact" }
    $nonceMatch = [regex]::Match([string]$task.Actions[0].Arguments, '-InstallNonce "(?<nonce>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"')
    if (-not $nonceMatch.Success) { throw "task action install nonce is invalid" }
    $expectedArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$InstalledSupervisor`" -ExpectedServiceAccountSid `"$ExpectedServiceAccountSid`" -InstallNonce `"$($nonceMatch.Groups['nonce'].Value)`" -ExpectedServiceAccount `"$ServiceAccount`" -ExpectedDistroName `"$DistroName`" -SnapshotPath `"$SnapshotPath`""
    if ($task.Actions[0].Arguments -ne $expectedArguments) { throw "task action arguments are not exact" }
}
Assert-SafeArtifactTree $ControlRoot @($InstalledSupervisor, $SshdBackup) $markerPresent (-not $markerPresent)
Assert-SafeArtifactTree $HealthRoot @($SnapshotPath) $markerPresent (-not $markerPresent)
$sftpState = Get-ManagedSftpState
if ($sftpState -eq "absent" -and -not $markerPresent) { throw "managed SFTP configuration is absent without owning reconciliation marker" }
Assert-SshdValidAndRunning $markerPresent
if (-not $markerPresent) { New-UninstallMarker; $markerPresent = $true }
if ($null -ne $task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $stopDeadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Milliseconds 500; $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop } while ([string]$task.State -eq "Running" -and (Get-Date) -lt $stopDeadline)
    if ([string]$task.State -eq "Running") { throw "task did not stop within the bounded deadline" }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "task still exists after removal" }
$password = $null
try {
    $password = New-CryptographicAccountPassword
    Set-LocalUser -Name $account.Name -Password $password -ErrorAction Stop
}
finally { if ($null -ne $password) { $password.Dispose() } }
Disable-LocalUser -Name $ReaderAccount -ErrorAction Stop
if ((Get-LocalUser -Name $ReaderAccount -ErrorAction Stop).Enabled) { throw "health reader did not remain disabled" }
Remove-ManagedSftpConfiguration $sftpState
foreach ($path in @($ControlRoot, $HealthRoot)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "task reappeared after removal" }
if ((Get-LocalUser -Name $ReaderAccount -ErrorAction Stop).Enabled) { throw "health reader re-enabled during uninstall" }
if ((Get-ManagedSftpState) -ne "absent") { throw "managed SFTP configuration remains after uninstall" }
Assert-SshdValidAndRunning $true
foreach ($path in @($ControlRoot, $HealthRoot)) { if (Test-Path -LiteralPath $path) { throw "health artifact root remains after uninstall: $path" } }
Assert-UninstallMarker
Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Stop
if (Test-Path -LiteralPath $MarkerPath) { throw "uninstall reconciliation marker remains after commit" }
[ordered]@{ status = "uninstalled"; reconciliation_performed = $true; task_absent = $true; stored_task_credential_invalidated = $true; reader_disabled = $true; sftp_configuration_absent = $true; sshd_valid_and_running = $true; health_artifacts_removed = $true; reconciliation_marker_removed = $true; runner_registration_changed = $false } | ConvertTo-Json -Compress
