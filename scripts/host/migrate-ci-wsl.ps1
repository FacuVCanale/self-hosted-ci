[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [string]$SourceDistroName = "Ubuntu-24.04",
    [string]$ImportedDistroName = "Ubuntu-24.04-CI",
    [string]$ExportPath = "C:\ProgramData\self-hosted-ci\exports\Ubuntu-24.04-20260827.tar",
    [string]$DestinationPath = "C:\ProgramData\self-hosted-ci\wsl",
    [string]$ExpectedExportSha256 = "ad9e329eadc4211182c32d71a2830b6a492efedb2dc94735f3dd5287925ca0e9",
    [long]$ExpectedExportBytes = 0,
    [string]$ExpectedServiceAccountSid,
    [int]$TimeoutSeconds = 900,
    [switch]$Apply,
    [switch]$AcknowledgeSourceAndExportWillBePreserved,
    [switch]$AcknowledgeImportRunsAsServiceIdentity
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedSourceDistro = "Ubuntu-24.04"
$ExpectedImportedDistro = "Ubuntu-24.04-CI"
$ExpectedExport = "C:\ProgramData\self-hosted-ci\exports\Ubuntu-24.04-20260827.tar"
$ExpectedDestination = "C:\ProgramData\self-hosted-ci\wsl"
$TaskName = "SelfHostedCI-Import-Ubuntu-24.04-CI"
$TaskRoot = "C:\ProgramData\self-hosted-ci\migration"
$WorkerPath = Join-Path $TaskRoot "import-ci-wsl-worker.ps1"
$ResultPath = Join-Path $TaskRoot "import-result.json"
$StdoutPath = Join-Path $TaskRoot "import.stdout.log"
$StderrPath = Join-Path $TaskRoot "import.stderr.log"

function Assert-Windows {
    if ($env:OS -ne "Windows_NT") {
        throw "This script must run on Windows PowerShell or PowerShell on Windows."
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NormalizedPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Get-WslDistros {
    $lines = @(& wsl.exe --list --quiet 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list WSL distributions: $($lines -join ' ')"
    }
    return @($lines | ForEach-Object { ([string]$_).Trim([char]0).Trim() } | Where-Object { $_ })
}

function Assert-NotReparsePoint([string]$LiteralPath, [string]$Description) {
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $LiteralPath"
    }
}

function Get-LocalServiceIdentity([string]$Name) {
    $account = Get-LocalUser -Name $Name -ErrorAction Stop
    if (-not $account.Enabled) {
        throw "Service account is disabled: $Name"
    }
    if ([string]$account.PrincipalSource -ne "Local") {
        throw "Service account must be a local Windows account: $Name"
    }

    $administrators = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop)
    if ($adminMembers.SID.Value -contains $account.SID.Value) {
        throw "Service account must not be a member of the local Administrators group: $Name"
    }

    return $account
}

function New-ProtectedDirectoryAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid, $ServiceSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function New-ProtectedExportAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $serviceRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $ServiceSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($serviceRule)
    return $acl
}

function Assert-ProtectedAcl([string]$LiteralPath, [string[]]$AllowedSidValues) {
    $acl = Get-Acl -LiteralPath $LiteralPath
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance must be disabled: $LiteralPath"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Deny ACL entries are not allowed on migration artifacts: $LiteralPath"
        }
        if ($AllowedSidValues -notcontains $rule.IdentityReference.Value) {
            throw "Unexpected ACL identity $($rule.IdentityReference.Value) on $LiteralPath"
        }
    }
    foreach ($sid in $AllowedSidValues) {
        if ($rules.IdentityReference.Value -notcontains $sid) {
            throw "Required ACL identity $sid is missing from $LiteralPath"
        }
    }
}

function Write-Plan(
    [object]$Account,
    [IO.FileInfo]$ExportFile,
    [string]$ActualHash,
    [long]$RequiredFreeBytes,
    [long]$AvailableFreeBytes
) {
    $plan = [ordered]@{
        mode = "plan"
        apply_requested = [bool]$Apply
        service_account = $Account.Name
        service_account_sid = $Account.SID.Value
        service_account_non_admin = $true
        source_distro = $SourceDistroName
        source_preserved = $true
        export_path = $ExportFile.FullName
        export_bytes = $ExportFile.Length
        export_sha256 = $ActualHash
        export_preserved = $true
        imported_distro = $ImportedDistroName
        destination_path = $DestinationPath
        required_free_bytes = $RequiredFreeBytes
        available_free_bytes = $AvailableFreeBytes
        task_name = $TaskName
        task_log_directory = $TaskRoot
        operations = @(
            "protect export ACL for SYSTEM, Administrators, and read-only service identity",
            "protect destination/task ACLs for SYSTEM, Administrators, and service identity",
            "register and start a passwordless S4U task as the non-admin service identity",
            "import or verify the exact WSL2 distro under that identity",
            "verify HKCU WSL registration, exact BasePath, version, SID, and task result",
            "remove the one-time scheduled task; preserve logs, source distro, export, and destination"
        )
        forbidden_operations = @("unregistering any WSL distro", "deleting the source distro", "deleting the export")
    }
    $plan | ConvertTo-Json -Depth 5
}

Assert-Windows

foreach ($command in @("wsl.exe", "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember", "Register-ScheduledTask")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required Windows command is unavailable: $command"
    }
}

if ($SourceDistroName -ne $ExpectedSourceDistro) {
    throw "SourceDistroName must be $ExpectedSourceDistro."
}
if ($ImportedDistroName -ne $ExpectedImportedDistro) {
    throw "ImportedDistroName must be $ExpectedImportedDistro."
}
if ((Get-NormalizedPath $ExportPath) -ne (Get-NormalizedPath $ExpectedExport)) {
    throw "ExportPath must be the pinned export: $ExpectedExport"
}
if ((Get-NormalizedPath $DestinationPath) -ne (Get-NormalizedPath $ExpectedDestination)) {
    throw "DestinationPath must be the pinned dedicated location: $ExpectedDestination"
}
if ($ExpectedExportSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw "ExpectedExportSha256 must be exactly 64 hexadecimal characters."
}
if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 3600) {
    throw "TimeoutSeconds must be between 60 and 3600."
}
if (-not (Test-Path -LiteralPath $ExportPath -PathType Leaf)) {
    throw "Pinned WSL export not found: $ExportPath"
}
Assert-NotReparsePoint $ExportPath "WSL export"

$exportFile = Get-Item -LiteralPath $ExportPath -Force
$actualHash = (Get-FileHash -LiteralPath $ExportPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedExportSha256.ToLowerInvariant()) {
    throw "WSL export SHA-256 mismatch. Expected $ExpectedExportSha256, got $actualHash."
}
if ($ExpectedExportBytes -gt 0 -and $exportFile.Length -ne $ExpectedExportBytes) {
    throw "WSL export size mismatch. Expected $ExpectedExportBytes bytes, got $($exportFile.Length)."
}

$account = Get-LocalServiceIdentity $ServiceAccount
$distrosBefore = @(Get-WslDistros)
if ($distrosBefore -notcontains $SourceDistroName) {
    throw "Preserved source distro is not registered for the current operator: $SourceDistroName"
}
if ($SourceDistroName -eq $ImportedDistroName) {
    throw "Source and imported distro names must be different."
}

$destinationRoot = [IO.Path]::GetPathRoot((Get-NormalizedPath $DestinationPath))
$drive = Get-PSDrive -Name $destinationRoot.Substring(0, 1)
$requiredFreeBytes = [Math]::Max(($exportFile.Length * 2L) + 1GB, 5GB)
if ($drive.Free -lt $requiredFreeBytes) {
    throw "Insufficient free disk space. Required at least $requiredFreeBytes bytes, found $($drive.Free)."
}

Write-Plan $account $exportFile $actualHash $requiredFreeBytes $drive.Free

if (-not $Apply) {
    Write-Host "Plan only: no ACL, scheduled-task, WSL registration, or filesystem changes were made."
    Write-Host "For Apply, pin -ExpectedExportBytes $($exportFile.Length) and -ExpectedServiceAccountSid $($account.SID.Value)."
    exit 0
}

if (-not (Test-IsAdministrator)) {
    throw "Apply must run from an elevated local PowerShell console."
}
if (-not [Environment]::UserInteractive -or $Host.Name -ne "ConsoleHost") {
    throw "Apply must run interactively from a local PowerShell console."
}
if (-not $AcknowledgeSourceAndExportWillBePreserved) {
    throw "Apply requires -AcknowledgeSourceAndExportWillBePreserved."
}
if (-not $AcknowledgeImportRunsAsServiceIdentity) {
    throw "Apply requires -AcknowledgeImportRunsAsServiceIdentity."
}
if ($ExpectedExportBytes -le 0) {
    throw "Apply requires the exact non-zero -ExpectedExportBytes reported by plan mode."
}
if ([string]::IsNullOrWhiteSpace($ExpectedServiceAccountSid)) {
    throw "Apply requires -ExpectedServiceAccountSid reported by plan mode."
}
if ($account.SID.Value -ne $ExpectedServiceAccountSid) {
    throw "Service-account SID mismatch. Expected $ExpectedServiceAccountSid, got $($account.SID.Value)."
}

$serviceSid = [Security.Principal.SecurityIdentifier]::new($account.SID.Value)
$allowedSids = @("S-1-5-18", "S-1-5-32-544", $serviceSid.Value)
$destinationExisted = Test-Path -LiteralPath $DestinationPath -PathType Container

foreach ($directory in @($DestinationPath, $TaskRoot)) {
    if (Test-Path -LiteralPath $directory) {
        Assert-NotReparsePoint $directory "Migration directory"
    }
    else {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    Set-Acl -LiteralPath $directory -AclObject (New-ProtectedDirectoryAcl $serviceSid)
    Assert-ProtectedAcl $directory $allowedSids
}
Set-Acl -LiteralPath $ExportPath -AclObject (New-ProtectedExportAcl $serviceSid)
Assert-ProtectedAcl $ExportPath $allowedSids

if (-not $destinationExisted) {
    $destinationItems = @(Get-ChildItem -LiteralPath $DestinationPath -Force)
    if ($destinationItems.Count -ne 0) {
        throw "New destination directory is unexpectedly non-empty: $DestinationPath"
    }
}

$workerSource = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DistroName,
    [Parameter(Mandatory = $true)][string]$ExportPath,
    [Parameter(Mandatory = $true)][string]$DestinationPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSid,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-Distros {
    $lines = @(& wsl.exe --list --quiet 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Unable to list WSL distributions: $($lines -join ' ')" }
    return @($lines | ForEach-Object { ([string]$_).Trim([char]0).Trim() } | Where-Object { $_ })
}

try {
    $actualSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($actualSid -ne $ExpectedSid) { throw "Worker identity SID mismatch." }
    $destination = [IO.Path]::GetFullPath($DestinationPath).TrimEnd('\')
    $distros = @(Get-Distros)
    $operation = "verified-existing"
    if ($distros -notcontains $DistroName) {
        if (@(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
            throw "Destination must be empty before first import."
        }
        $process = Start-Process -FilePath "wsl.exe" -ArgumentList @(
            "--import", $DistroName, $destination, $ExportPath, "--version", "2"
        ) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        if ($process.ExitCode -ne 0) { throw "wsl.exe --import failed with exit code $($process.ExitCode)." }
        $operation = "imported"
        $distros = @(Get-Distros)
    }
    if ($distros -notcontains $DistroName) { throw "Imported distro is not visible under the service identity." }

    $registrations = @(Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction Stop |
        ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } |
        Where-Object { $_.DistributionName -eq $DistroName })
    if ($registrations.Count -ne 1) { throw "Expected exactly one HKCU WSL registration for $DistroName." }
    $registration = $registrations[0]
    $registeredBasePath = [IO.Path]::GetFullPath([string]$registration.BasePath).TrimEnd('\')
    if ($registeredBasePath -ne $destination) { throw "Imported distro BasePath mismatch." }
    if ([int]$registration.Version -ne 2) { throw "Imported distro is not WSL2." }

    $result = [ordered]@{
        status = "verified"
        operation = $operation
        identity_sid = $actualSid
        distro_name = $DistroName
        base_path = $registeredBasePath
        version = [int]$registration.Version
        verified_at = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    exit 0
}
catch {
    $failure = [ordered]@{
        status = "failed"
        identity_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        message = $_.Exception.Message
        failed_at = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $failure | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    exit 1
}
'@

[IO.File]::WriteAllText($WorkerPath, $workerSource, [Text.UTF8Encoding]::new($false))
Set-Acl -LiteralPath $WorkerPath -AclObject (New-ProtectedExportAcl $serviceSid)
Assert-ProtectedAcl $WorkerPath $allowedSids
foreach ($artifact in @($ResultPath, $StdoutPath, $StderrPath)) {
    if (Test-Path -LiteralPath $artifact) {
        Remove-Item -LiteralPath $artifact -Force
    }
}

$accountId = "$env:COMPUTERNAME\$($account.Name)"
$powerShellExe = Join-Path $PSHOME "powershell.exe"
if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
    $powerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
}
$quotedArguments = @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $WorkerPath),
    '-DistroName', ('"{0}"' -f $ImportedDistroName),
    '-ExportPath', ('"{0}"' -f $ExportPath),
    '-DestinationPath', ('"{0}"' -f $DestinationPath),
    '-ExpectedSid', ('"{0}"' -f $serviceSid.Value),
    '-ResultPath', ('"{0}"' -f $ResultPath),
    '-StdoutPath', ('"{0}"' -f $StdoutPath),
    '-StderrPath', ('"{0}"' -f $StderrPath)
) -join ' '
$action = New-ScheduledTaskAction -Execute $powerShellExe -Argument $quotedArguments
$principal = New-ScheduledTaskPrincipal -UserId $accountId -LogonType S4U -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings

$registered = $false
try {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    $registered = $true
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $TaskName

    $deadline = $startedAt.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $taskState = (Get-ScheduledTask -TaskName $TaskName).State
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        $completed = [string]$taskState -eq "Ready" -and
            $taskInfo.LastRunTime -ge $startedAt
    } while (-not $completed -and (Get-Date) -lt $deadline)

    if (-not $completed) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        throw "Timed out waiting for S4U import task after $TimeoutSeconds seconds."
    }
    if ($taskInfo.LastTaskResult -ne 0) {
        $workerFailure = if (Test-Path -LiteralPath $ResultPath) { Get-Content -LiteralPath $ResultPath -Raw } else { "no result file" }
        throw "S4U import task failed with result $($taskInfo.LastTaskResult): $workerFailure"
    }
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw "S4U import task reported success without a result file."
    }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if ($result.status -ne "verified" -or $result.identity_sid -ne $serviceSid.Value) {
        throw "S4U result did not verify the expected service identity."
    }
    if ($result.distro_name -ne $ImportedDistroName -or [int]$result.version -ne 2) {
        throw "S4U result did not verify the expected WSL2 distro."
    }
    if ((Get-NormalizedPath ([string]$result.base_path)) -ne (Get-NormalizedPath $DestinationPath)) {
        throw "S4U result did not verify the exact destination path."
    }

    $distrosAfter = @(Get-WslDistros)
    if ($distrosAfter -notcontains $SourceDistroName) {
        throw "Source distro disappeared from the operator identity; preservation invariant failed."
    }
    if (-not (Test-Path -LiteralPath $ExportPath -PathType Leaf)) {
        throw "Export disappeared; preservation invariant failed."
    }
    $hashAfter = (Get-FileHash -LiteralPath $ExportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sizeAfter = (Get-Item -LiteralPath $ExportPath).Length
    if ($hashAfter -ne $actualHash -or $sizeAfter -ne $ExpectedExportBytes) {
        throw "Export changed during migration; preservation invariant failed."
    }

    [ordered]@{
        status = "complete"
        imported_distro = $ImportedDistroName
        service_account_sid = $serviceSid.Value
        destination_path = $DestinationPath
        source_distro_preserved = $true
        export_preserved = $true
        export_sha256 = $hashAfter
        export_bytes = $sizeAfter
        worker_result = $result
    } | ConvertTo-Json -Depth 6
}
finally {
    if ($registered -and (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}
