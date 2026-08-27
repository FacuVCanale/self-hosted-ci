[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$ReaderAccount = "selfhosted-ci-health",
    [string]$DistroName = "Ubuntu-24.04-CI",
    [int]$TimeoutSeconds = 180,
    [switch]$Apply,
    [switch]$AcknowledgeRemoveDisabledReader,
    [switch]$AcknowledgeRemoveWslHealthPackage,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Uninstall-Health-Prerequisites"
$PersistentTaskName = "SelfHostedCI-Health-Supervisor"
$Root = "C:\ProgramData\self-hosted-ci\health-bootstrap"
$WorkerPath = Join-Path $Root "uninstall-worker.ps1"
$ResultPath = Join-Path $Root "uninstall-result.json"
$PayloadPath = Join-Path $PSScriptRoot "uninstall-health-wsl-payload.sh.in"
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
    $bytes = New-Object byte[] 48; $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return ConvertTo-SecureString ("Aa1!" + [Convert]::ToBase64String($bytes)) -AsPlainText -Force }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $rng.Dispose() }
}
function New-ProtectedAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544"); $acl.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @([Security.Principal.SecurityIdentifier]::new("S-1-5-18"), $admins, $ServiceSid)) { [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)) }
    return $acl
}
function Assert-NoReparsePath([string]$Path, [bool]$AllowMissingLeaf = $false) {
    $full = [IO.Path]::GetFullPath($Path)
    $leafExists = Test-Path -LiteralPath $full
    if (-not $AllowMissingLeaf -and -not $leafExists) { throw "expected path is absent: $full" }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse point is forbidden: $cursor" }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }; $cursor = $parent
    }
}
function Assert-NoReparseDescendants([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    Assert-NoReparsePath $full
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return }
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($full)
    while ($pending.Count -gt 0) {
        $cursor = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $cursor -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse descendant is forbidden: $($item.FullName)" }
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
        }
    }
}
function Register-OneShot([string]$UserId, [Security.SecureString]$Password) {
    $bstr = [IntPtr]::Zero; $plain = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password); $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect(); $folder = $scheduler.GetFolder("\")
        $definition = $scheduler.NewTask(0); $definition.Principal.UserId = $UserId
        $definition.Principal.LogonType = 1 # TASK_LOGON_PASSWORD
        $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA
        $definition.Settings.Enabled = $true; $definition.Settings.ExecutionTimeLimit = "PT5M"
        $action = $definition.Actions.Create(0); $action.Path = $PowerShellExe; $action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
        return $folder.RegisterTaskDefinition($TaskName, $definition, 6, $UserId, $plain, 1, $null)
    }
    finally { $plain = $null; if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}
function Render-Payload {
    $payload = Get-Content -LiteralPath $PayloadPath -Raw
    foreach ($item in @(@("COLLECTOR", $CollectorPath), @("WRITER", $WriterPath), @("SERVICE", $ServicePath), @("TIMER", $TimerPath))) {
        $bytes = [IO.File]::ReadAllBytes($item[1])
        $sha = ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
        $payload = $payload.Replace("@@$($item[0])_SHA@@", $sha)
    }
    if ($payload -match '@@[A-Z0-9_]+@@') { throw "uninstall payload has unresolved markers" }
    return $payload
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "uninstaller requires an elevated Windows console" }
if ($ReaderAccount -ne "selfhosted-ci-health" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "reader and distro names are pinned" }
foreach ($path in @($PayloadPath, $CollectorPath, $WriterPath, $ServicePath, $TimerPath)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "uninstall source is missing: $path" } }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if ($service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
$reader = Get-LocalUser -Name $ReaderAccount -ErrorAction Stop
$profile = Join-Path "C:\Users" $ReaderAccount; $ssh = Join-Path $profile ".ssh"; $key = Join-Path $ssh "authorized_keys"
[ordered]@{ mode="plan"; apply_requested=[bool]$Apply; task_name=$TaskName; remove_wsl_health_package=$true; remove_disabled_reader=$ReaderAccount; persistent_task_must_be_absent=$true; runner_registration="not_performed" } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeRemoveDisabledReader -or -not $AcknowledgeRemoveWslHealthPackage -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires all removal acknowledgements" }
if ($reader.Enabled -or [string]$reader.Description -ne $ReaderDescription) { throw "health reader must be disabled with exact managed provenance" }
if (Get-ScheduledTask -TaskName $PersistentTaskName -ErrorAction SilentlyContinue) { throw "persistent supervisor must be uninstalled first" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
$expectedStagingRoot = [IO.Path]::GetFullPath("C:\ProgramData\self-hosted-ci\health-bootstrap")
if ([IO.Path]::GetFullPath($Root) -ne $expectedStagingRoot) { throw "health bootstrap staging root is not canonical" }
Assert-NoReparsePath "C:\ProgramData"
Assert-NoReparsePath (Split-Path -Parent $Root) $true
Assert-NoReparsePath $Root $true
foreach ($path in @($profile, $ssh, $key)) { if (-not (Test-Path -LiteralPath $path)) { throw "expected reader artifact is absent: $path" } }
if ([IO.Path]::GetFullPath($profile) -ne [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")) { throw "reader profile path is not canonical" }
foreach ($path in @("C:\Users", $profile, $ssh, $key)) {
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse point blocks exact uninstall: $path" }
}
$unexpected = @(Get-ChildItem -LiteralPath $profile -Force -Recurse | Where-Object { $_.FullName -notin @($ssh, $key) })
if ($unexpected.Count) { throw "unexpected reader profile artifact blocks exact uninstall: $($unexpected[0].FullName)" }

$payloadBytes = [Text.Encoding]::UTF8.GetBytes((Render-Payload)); $payloadB64 = [Convert]::ToBase64String($payloadBytes)
$registered = $false; $passwordApplied = $false; $password = $null
try {
    if (-not (Test-Path -LiteralPath $Root)) { [void](New-Item -ItemType Directory -Path $Root) }
    Assert-NoReparsePath $Root
    Assert-NoReparseDescendants $Root
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
`$raw = @('$payloadB64') | & wsl.exe --distribution '$DistroName' --user root -- bash -lc "base64 --decode | bash" 2>&1
if (`$LASTEXITCODE -ne 0) { throw "WSL health uninstall failed: `$(`$raw -join ' ')" }
`$document = (`$raw | Select-Object -Last 1) | ConvertFrom-Json
if (`$document.status -ne 'uninstalled') { throw 'WSL uninstall postcondition failed' }
[IO.File]::WriteAllText('$ResultPath', (`$document | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
    $password = New-RandomPassword; Set-LocalUser -Name $service.Name -Password $password; $passwordApplied = $true
    [void](Register-OneShot "$env:COMPUTERNAME\$($service.Name)" $password); $registered = $true; $password.Dispose(); $password = $null
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
        Start-Sleep -Seconds 2; $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop; $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $ranNow = ([DateTimeOffset]$info.LastRunTime) -ge $startedAt.AddSeconds(-2)
        $finished = $ranNow -and [string]$task.State -ne "Running" -and ([uint32]$info.LastTaskResult -ne 267011 -or (Test-Path -LiteralPath $ResultPath -PathType Leaf))
    } while (-not $finished -and (Get-Date) -lt $deadline)
    if (-not $finished -or [uint32]$info.LastTaskResult -ne 0 -or -not (Test-Path -LiteralPath $ResultPath)) { throw "one-shot uninstall failed or timed out" }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    $final = New-RandomPassword; try { Set-LocalUser -Name $service.Name -Password $final } finally { $final.Dispose() }; $passwordApplied = $false
    Remove-LocalUser -Name $ReaderAccount
    Remove-Item -LiteralPath $profile -Recurse -Force
    Assert-NoReparsePath $Root
    Assert-NoReparseDescendants $Root
    Remove-Item -LiteralPath $Root -Recurse -Force
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task reappeared before completion evidence" }
    if (Get-LocalUser -Name $ReaderAccount -ErrorAction SilentlyContinue) { throw "health reader remains after exact uninstall" }
    foreach ($path in @($profile, $Root)) { if (Test-Path -LiteralPath $path) { throw "managed artifact remains after exact uninstall: $path" } }
    [ordered]@{ status="uninstalled"; reader_absent=$true; wsl_health_package_absent=$true; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; runner_registration_changed=$false } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new()
    if ($registered -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        try {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "task remains after cleanup" }
            $registered = $false
        }
        catch { $cleanup.Add("task cleanup failed: $($_.Exception.Message)") }
    }
    if ($passwordApplied) {
        $recovery = $null
        try { $recovery = New-RandomPassword; Set-LocalUser -Name $service.Name -Password $recovery; $passwordApplied = $false }
        catch { $cleanup.Add("credential invalidation failed: $($_.Exception.Message)") }
        finally { if ($null -ne $recovery) { $recovery.Dispose() } }
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $cleanup.Add("task absence postcondition failed") }
    $readerStillExists = $null -ne (Get-LocalUser -Name $ReaderAccount -ErrorAction SilentlyContinue)
    $profileStillExists = Test-Path -LiteralPath $profile
    if ($readerStillExists -ne $profileStillExists) { $cleanup.Add("reader/account artifact postcondition is partial") }
    if ($cleanup.Count) { throw "Uninstall failed: $original. Cleanup failures: $($cleanup -join '; ')" }
    throw "Uninstall failed closed with verified task cleanup and credential invalidation: $original"
}
finally { if ($null -ne $password) { $password.Dispose() } }
