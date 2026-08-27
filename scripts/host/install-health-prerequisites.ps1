[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$ReaderAccount = "selfhosted-ci-health",
    [Parameter(Mandatory = $true)][string]$AuthorizedKey,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [int]$TimeoutSeconds = 180,
    [switch]$Apply,
    [switch]$AcknowledgeCreateDisabledReader,
    [switch]$AcknowledgeOneTimePasswordRotation,
    [ValidateSet("none", "worker-before-wsl", "payload-after-install", "payload-evidence-failure")][string]$FailureInjection = "none",
    [switch]$AcknowledgeFailureInjection
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-Health-Prerequisites"
$PersistentTaskName = "SelfHostedCI-Health-Supervisor"
$Root = "C:\ProgramData\self-hosted-ci\health-bootstrap"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$PayloadTemplate = Join-Path $PSScriptRoot "install-health-wsl-payload.sh.in"
$CollectorPath = Join-Path $PSScriptRoot "collect-health-snapshot.py"
$WriterPath = Join-Path $PSScriptRoot "update-health-heartbeat.py"
$ServicePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "packaging/systemd/self-hosted-ci-health-heartbeat.service"
$TimerPath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "packaging/systemd/self-hosted-ci-health-heartbeat.timer"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$ReaderDescription = "Managed disabled self-hosted-ci health reader"

function Test-IsAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return ConvertTo-SecureString ("Aa1!" + [Convert]::ToBase64String($bytes)) -AsPlainText -Force }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $rng.Dispose() }
}

function Test-GroupContainsSid([object]$Group, [string]$TargetSid, [Collections.Generic.HashSet[string]]$Visited) {
    if (-not $Visited.Add($Group.SID.Value)) { return $false }
    foreach ($member in @(Get-LocalGroupMember -Group $Group -ErrorAction Stop)) {
        if ($member.SID.Value -eq $TargetSid) { return $true }
        if ([string]$member.ObjectClass -eq "Group") {
            try { $nested = Get-LocalGroup -SID $member.SID -ErrorAction Stop }
            catch { throw "cannot resolve nested administrator group $($member.Name): $($_.Exception.Message)" }
            if (Test-GroupContainsSid $nested $TargetSid $Visited) { return $true }
        }
    }
    return $false
}
function Assert-NonAdmin([object]$Account, [string]$Description) {
    $admins = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (Test-GroupContainsSid $admins $Account.SID.Value $visited) { throw "$Description must be effectively non-admin" }
}
function Assert-NoReparseTree([string]$Path, [bool]$AllowMissingLeaf = $false) {
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor -and (Test-Path -LiteralPath $cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse point is forbidden: $cursor" }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }; $cursor = $parent
    }
    if (-not $AllowMissingLeaf -and -not (Test-Path -LiteralPath $full)) { throw "expected path is absent: $full" }
    if (Test-Path -LiteralPath $full -PathType Container) {
        foreach ($item in @(Get-ChildItem -LiteralPath $full -Force -Recurse)) { if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse descendant is forbidden: $($item.FullName)" } }
    }
}

function New-ProtectedAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @([Security.Principal.SecurityIdentifier]::new("S-1-5-18"), $admins, $ServiceSid)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Set-ExactAuthorizedKey([object]$Reader, [string]$Key) {
    if ($Key -notmatch '^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?$') { throw "authorized key must be one supported public key line" }
    $profile = Join-Path "C:\Users" $Reader.Name
    $expectedProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    if ([IO.Path]::GetFullPath($profile) -ne $expectedProfile) { throw "reader profile path is not canonical" }
    $ssh = Join-Path $profile ".ssh"
    $file = Join-Path $ssh "authorized_keys"
    Assert-NoReparseTree "C:\Users"
    Assert-NoReparseTree $profile $true
    foreach ($path in @($profile, $ssh)) { if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path) } }
    Assert-NoReparseTree $profile
    [IO.File]::WriteAllText($file, $Key.Trim() + "`n", [Text.UTF8Encoding]::new($false))
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    foreach ($entry in @(@($profile, $true), @($ssh, $true), @($file, $false))) {
        $acl = if ($entry[1]) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
        $acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($admins)
        foreach ($sid in @($system, $admins, $Reader.SID)) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::ReadAndExecute, [Security.AccessControl.AccessControlType]::Allow))
        }
        Set-Acl -LiteralPath $entry[0] -AclObject $acl
    }
}

function Render-Payload {
    $payload = Get-Content -LiteralPath $PayloadTemplate -Raw
    foreach ($item in @(
        @("COLLECTOR", $CollectorPath), @("WRITER", $WriterPath), @("SERVICE", $ServicePath), @("TIMER", $TimerPath)
    )) {
        $bytes = [IO.File]::ReadAllBytes($item[1])
        $sha = ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
        $payload = $payload.Replace("@@$($item[0])_SHA@@", $sha).Replace("@@$($item[0])_B64@@", [Convert]::ToBase64String($bytes))
    }
    $payload = $payload.Replace("@@FAILURE_MODE@@", $FailureInjection)
    if ($payload -match '@@[A-Z0-9_]+@@') { throw "payload template has unresolved markers" }
    return $payload
}

function Register-OneShot([string]$UserId, [Security.SecureString]$Password) {
    $bstr = [IntPtr]::Zero; $plain = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password); $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect(); $folder = $scheduler.GetFolder("\")
        $definition = $scheduler.NewTask(0); $definition.Principal.UserId = $UserId
        $definition.Principal.LogonType = 1 # TASK_LOGON_PASSWORD
        $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA
        $definition.Settings.Enabled = $true; $definition.Settings.ExecutionTimeLimit = "PT5M"; $definition.Settings.StartWhenAvailable = $false
        $action = $definition.Actions.Create(0); $action.Path = $PowerShellExe; $action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
        return $folder.RegisterTaskDefinition($TaskName, $definition, 6, $UserId, $plain, 1, $null)
    }
    finally { $plain = $null; if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "installer requires an elevated Windows console" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($ReaderAccount -ne "selfhosted-ci-health" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "reader and distro names are pinned" }
if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 600) { throw "invalid timeout" }
foreach ($path in @($PayloadTemplate, $CollectorPath, $WriterPath, $ServicePath, $TimerPath)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "source file missing: $path" } }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service "service account"
$existingReader = Get-LocalUser -Name $ReaderAccount -ErrorAction SilentlyContinue
if ($null -ne $existingReader) {
    Assert-NonAdmin $existingReader "health reader"
    if ($existingReader.Enabled -or [string]$existingReader.Description -ne $ReaderDescription) { throw "preexisting health reader must be disabled and have exact managed provenance" }
    $existingProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    Assert-NoReparseTree $existingProfile
    $existingKey = Join-Path $existingProfile ".ssh\authorized_keys"
    Assert-NoReparseTree $existingKey
    if ((Get-Content -LiteralPath $existingKey -Raw).Trim() -ne $AuthorizedKey.Trim()) { throw "preexisting health reader authorized key is not exact" }
}
$payload = Render-Payload
$payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
$payloadSha = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
[ordered]@{ mode="plan"; apply_requested=[bool]$Apply; task_name=$TaskName; service_sid=$service.SID.Value; reader_action=$(if ($null -eq $existingReader) { "create-disabled" } else { "verify-disabled" }); distro=$DistroName; payload_sha256=$payloadSha; persistent_task_must_be_absent=$true; runner_registration="not_performed"; external_calls="not_performed" } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeCreateDisabledReader -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both acknowledgements" }
if ($FailureInjection -ne "none" -and -not $AcknowledgeFailureInjection) { throw "failure injection requires its explicit acknowledgement" }
if (Get-ScheduledTask -TaskName $PersistentTaskName -ErrorAction SilentlyContinue) { throw "persistent supervisor must not exist; bootstrap must run first" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
$expectedStagingRoot = [IO.Path]::GetFullPath("C:\ProgramData\self-hosted-ci\health-bootstrap")
if ([IO.Path]::GetFullPath($Root) -ne $expectedStagingRoot) { throw "health bootstrap staging root is not canonical" }
Assert-NoReparseTree "C:\ProgramData"
Assert-NoReparseTree (Split-Path -Parent $Root) $true
Assert-NoReparseTree $Root $true

$createdReader = $false; $registered = $false; $passwordApplied = $false; $password = $null
try {
    if ($null -eq $existingReader) {
        $readerPassword = New-RandomPassword
        try { $existingReader = New-LocalUser -Name $ReaderAccount -Password $readerPassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description $ReaderDescription; $createdReader = $true }
        finally { $readerPassword.Dispose() }
    }
    Assert-NonAdmin $existingReader "health reader"
    Disable-LocalUser -Name $ReaderAccount
    Set-ExactAuthorizedKey $existingReader $AuthorizedKey
    if (-not (Test-Path -LiteralPath $Root)) { [void](New-Item -ItemType Directory -Path $Root) }
    Assert-NoReparseTree $Root
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $worker = @"
`$ErrorActionPreference = 'Stop'
`$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (`$sid -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
if ('$FailureInjection' -eq 'worker-before-wsl') { throw 'injected failure before WSL' }
`$raw = @('$payloadB64') | & wsl.exe --distribution '$DistroName' --user root -- bash -lc "base64 --decode | bash" 2>&1
if (`$LASTEXITCODE -ne 0) { throw "WSL health install failed: `$(`$raw -join ' ')" }
`$document = (`$raw | Select-Object -Last 1) | ConvertFrom-Json
if (`$document.status -ne 'installed' -or `$document.first_heartbeat -eq `$document.second_heartbeat) { throw 'WSL postcondition failed' }
[IO.File]::WriteAllText('$ResultPath', (`$document | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
    $password = New-RandomPassword; Set-LocalUser -Name $service.Name -Password $password; $passwordApplied = $true
    [void](Register-OneShot "$env:COMPUTERNAME\$($service.Name)" $password); $registered = $true
    $password.Dispose(); $password = $null
    $observed = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $actualSid = ([Security.Principal.NTAccount]::new([string]$observed.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])).Value
    $expectedArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
    if ($observed.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $observed.Principal.LogonType -ne "Password" -or $observed.Principal.RunLevel -ne "Limited") { throw "one-shot task principal postcondition failed" }
    if (@($observed.Actions).Count -ne 1 -or $observed.Actions[0].Execute -ne $PowerShellExe -or $observed.Actions[0].Arguments -ne $expectedArguments) { throw "one-shot task action postcondition failed" }
    $startedAt = [DateTimeOffset]::Now
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $finished = $false
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $ranNow = ([DateTimeOffset]$info.LastRunTime) -ge $startedAt.AddSeconds(-2)
        $finished = $ranNow -and [string]$task.State -ne "Running" -and ([uint32]$info.LastTaskResult -ne 267011 -or (Test-Path -LiteralPath $ResultPath -PathType Leaf))
    } while (-not $finished -and (Get-Date) -lt $deadline)
    if (-not $finished) { throw "one-shot task timed out" }
    if ([uint32]$info.LastTaskResult -ne 0 -or -not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) { throw "one-shot task failed" }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if ($result.status -ne "installed" -or $result.first_heartbeat -eq $result.second_heartbeat) { throw "two-heartbeat postcondition failed" }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    $finalPassword = New-RandomPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword }
    finally { $finalPassword.Dispose() }
    $passwordApplied = $false
    Assert-NoReparseTree $Root
    Remove-Item -LiteralPath $Root -Recurse -Force
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task reappeared before completion evidence" }
    [ordered]@{ status="installed"; reader_account=$ReaderAccount; reader_enabled=$false; two_distinct_heartbeats=$true; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; runner_registration_changed=$false } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $rollback = [Collections.Generic.List[string]]::new()
    if ($registered -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        try {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "task remains after cleanup" }
            $registered = $false
        }
        catch { $rollback.Add("task cleanup: $($_.Exception.Message)") }
    }
    if ($passwordApplied) { $recovery = New-RandomPassword; try { Set-LocalUser -Name $service.Name -Password $recovery } catch { $rollback.Add("credential invalidation: $($_.Exception.Message)") } finally { $recovery.Dispose() } }
    if (Test-Path -LiteralPath $Root) { try { Assert-NoReparseTree $Root; Remove-Item -LiteralPath $Root -Recurse -Force } catch { $rollback.Add("staging cleanup: $($_.Exception.Message)") } }
    if ($createdReader) {
        try {
            Remove-LocalUser -Name $ReaderAccount
            $readerProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
            if (Test-Path -LiteralPath $readerProfile) { Assert-NoReparseTree $readerProfile; Remove-Item -LiteralPath $readerProfile -Recurse -Force }
            if ((Get-LocalUser -Name $ReaderAccount -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $readerProfile)) { throw "reader rollback postcondition failed" }
        }
        catch { $rollback.Add("reader rollback: $($_.Exception.Message)") }
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $rollback.Add("task absence postcondition failed") }
    if ($rollback.Count) { throw "Install failed: $original. Rollback failures: $($rollback -join '; ')" }
    throw "Install failed and host rollback was verified: $original"
}
finally { if ($null -ne $password) { $password.Dispose() } }
