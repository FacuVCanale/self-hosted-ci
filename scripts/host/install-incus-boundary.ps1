[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [int]$TimeoutSeconds = 300,
    [switch]$Apply,
    [switch]$AcknowledgeIncusBoundaryMutation,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-Incus-Boundary"
$Root = "C:\ProgramData\self-hosted-ci\incus-boundary"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$DiagnosticsRoot = "C:\ProgramData\self-hosted-ci\diagnostics\incus-boundary"
$PayloadTemplate = Join-Path $PSScriptRoot "install-incus-boundary-wsl-payload.sh.in"
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
        return ConvertTo-SecureString ("Aa1!" + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $rng.Dispose() }
}

function Test-GroupContainsSid([object]$Group, [string]$TargetSid, [Collections.Generic.HashSet[string]]$Visited) {
    if (-not $Visited.Add($Group.SID.Value)) { return $false }
    foreach ($member in @(Get-LocalGroupMember -Group $Group -ErrorAction Stop)) {
        if ($member.SID.Value -eq $TargetSid) { return $true }
        if ([string]$member.ObjectClass -eq "Group") {
            $nested = Get-LocalGroup -SID $member.SID -ErrorAction Stop
            if (Test-GroupContainsSid $nested $TargetSid $Visited) { return $true }
        }
    }
    return $false
}

function Assert-NonAdmin([object]$Account) {
    $admins = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (Test-GroupContainsSid $admins $Account.SID.Value $visited) { throw "service account must be effectively non-admin" }
}

function New-ProtectedAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($system, $admins, $ServiceSid)) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Register-OneShot([string]$UserId, [Security.SecureString]$Password) {
    $bstr = [IntPtr]::Zero; $plain = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect(); $folder = $scheduler.GetFolder("\")
        $definition = $scheduler.NewTask(0)
        $definition.Principal.UserId = $UserId
        $definition.Principal.LogonType = 1 # TASK_LOGON_PASSWORD
        $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA / Limited
        $definition.Settings.Enabled = $true
        $definition.Settings.AllowDemandStart = $true
        $definition.Settings.StartWhenAvailable = $false
        $definition.Settings.ExecutionTimeLimit = "PT7M"
        $definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
        $action = $definition.Actions.Create(0)
        $action.Path = $PowerShellExe
        $action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
        return $folder.RegisterTaskDefinition($TaskName, $definition, 6, $UserId, $plain, 1, $null)
    }
    finally {
        $plain = $null
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

function Save-FailureDiagnostics([string]$FailureMessage, [Security.Principal.SecurityIdentifier]$ServiceSid) {
    $bundle = Join-Path $DiagnosticsRoot ([Guid]::NewGuid().ToString())
    [void](New-Item -ItemType Directory -Path $bundle -Force)
    Set-Acl -LiteralPath $bundle -AclObject (New-ProtectedAcl $ServiceSid)
    foreach ($entry in @(
        @{ Source = $StdoutPath; Name = "worker.stdout.log" },
        @{ Source = $StderrPath; Name = "worker.stderr.log" },
        @{ Source = $ResultPath; Name = "install-result.json" }
    )) {
        if (Test-Path -LiteralPath $entry.Source -PathType Leaf) { Copy-Item -LiteralPath $entry.Source -Destination (Join-Path $bundle $entry.Name) }
    }
    $safe = [ordered]@{
        observed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        task_name = $TaskName; service_sid = $ServiceSid.Value; distro = $DistroName
        failure = $FailureMessage; external_services_configured = $false
    }
    [IO.File]::WriteAllText((Join-Path $bundle "failure.json"), ($safe | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $bundle
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "installer requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($TimeoutSeconds -ne 300) { throw "TimeoutSeconds is pinned to 300" }
if (-not (Test-Path -LiteralPath $PayloadTemplate -PathType Leaf)) { throw "payload template is absent" }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service

$payloadBytes = [IO.File]::ReadAllBytes($PayloadTemplate)
$payloadSha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
[ordered]@{
    mode = $(if ($Apply) { "apply" } else { "plan" }); apply_requested = [bool]$Apply
    task_name = $TaskName; service_sid = $service.SID.Value; distro = $DistroName
    project = "ci-jit"; storage_pool = "ci-jit-dedicated"; storage_driver = "dir"; storage_filesystem = "ext4"; storage_pool_size = "16GiB"
    storage_mount_persistence = "systemd-mount-unit"; storage_pool_source = "/var/lib/self-hosted-ci/incus-storage/ci-jit/pool"
    bridge = "ci-jit-isolated"; profile = "ci-jit"
    payload_sha256 = $payloadSha256; external_services_configured = $false
    runner_registration = "not_performed"; no_host_changes = (-not [bool]$Apply)
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeIncusBoundaryMutation -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both explicit acknowledgements" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
if (Test-Path -LiteralPath $Root) { throw "staging root already exists" }

$registered = $false; $passwordApplied = $false; $temporaryPassword = $null
try {
    [void](New-Item -ItemType Directory -Path $Root)
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $bootstrap = @'
import base64
import hashlib
import os
import subprocess
import sys
import tempfile

expected = sys.argv[1]
encoded = sys.stdin.buffer.read().replace(b"\r", b"").replace(b"\n", b"")
raw = base64.b64decode(encoded, validate=True)
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("payload sha256 mismatch")
fd, path = tempfile.mkstemp(prefix="self-hosted-ci-incus-boundary.", suffix=".sh", dir="/run")
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    subprocess.run(["/bin/bash", "-n", path], check=True)
    subprocess.run(["/bin/bash", path], check=True)
finally:
    try: os.unlink(path)
    except FileNotFoundError: pass
'@
    $bootstrapB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrap))
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
`$unitName = 'self-hosted-ci-incus-boundary'
function Stop-WslInstallUnit {
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /bin/true
    if (`$LASTEXITCODE -ne 0) { throw 'WSL transport unavailable while terminating boundary unit' }
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl kill --kill-whom=all `$unitName 2>`$null
    `$killExit = `$LASTEXITCODE
    if (`$killExit -notin @(0,5)) { throw "systemctl kill failed with exit code `$killExit" }
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl stop `$unitName 2>`$null
    `$stopExit = `$LASTEXITCODE
    if (`$stopExit -notin @(0,5)) { throw "systemctl stop failed with exit code `$stopExit" }
    `$show = @(& `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl show `$unitName --property=ActiveState --property=SubState --property=ControlGroup --value 2>&1)
    `$showExit = `$LASTEXITCODE
    if (`$showExit -eq 4) { return }
    if (`$showExit -ne 0 -or `$show.Count -ne 3) { throw 'WSL boundary unit termination is unobservable' }
    if (([string]`$show[0]).Trim() -notin @('inactive','failed') -or ([string]`$show[1]).Trim() -notin @('dead','failed')) { throw 'WSL boundary unit could not be terminated' }
    `$controlGroup = ([string]`$show[2]).Trim()
    if (`$controlGroup) {
        & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /usr/bin/test '!' -s "/sys/fs/cgroup`$controlGroup/cgroup.procs"
        if (`$LASTEXITCODE -ne 0) { throw 'WSL boundary unit cgroup still contains processes' }
    }
}
`$psi = [Diagnostics.ProcessStartInfo]::new()
`$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
`$psi.Arguments = '-d $DistroName -u root -- systemd-run --quiet --wait --pipe --collect --setenv=WSL_DISTRO_NAME=$DistroName --property=RuntimeMaxSec=300 --property=TimeoutStopSec=15 --property=KillMode=control-group --unit=' + `$unitName + ' /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$bootstrapB64''))" $payloadSha256'
`$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true
`$psi.RedirectStandardInput = `$true; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'could not start exact WSL boundary installer' }
`$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
`$process.StandardInput.Write('$payloadB64'); `$process.StandardInput.Close()
if (-not `$process.WaitForExit($TimeoutSeconds * 1000)) {
    try { `$process.Kill() } catch {}; Stop-WslInstallUnit
    throw 'WSL boundary installer timed out and its systemd unit was terminated'
}
`$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
if (`$process.ExitCode -ne 0) { Stop-WslInstallUnit; throw "WSL boundary installer failed: `$(`$process.ExitCode)" }
`$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1
`$result = `$last | ConvertFrom-Json
if (`$result.status -ne 'installed' -or `$result.external_services_configured -ne `$false -or `$result.instances -ne 0 -or `$result.storage_volumes -ne 0 -or `$result.root_is_only_disk -ne `$true -or `$result.forbidden_devices -ne `$false -or `$result.negative_canaries_passed -ne `$true) { throw 'Incus boundary postcondition failed' }
if (`$result.storage_driver -ne 'dir' -or `$result.storage_filesystem -ne 'ext4' -or `$result.storage_filesystem_uuid -notmatch '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or `$result.storage_project_quota -ne `$true -or `$result.storage_quota_canary_passed -ne `$true -or `$result.storage_mount_persistent -ne `$true -or `$result.storage_mount_unit_enabled -ne `$true -or `$result.storage_mount_unit_active -ne `$true -or `$result.incus_mount_ordering_verified -ne `$true -or `$result.storage_mount_root_owned -ne `$true -or `$result.storage_pool_size -ne '16GiB' -or `$result.storage_image_apparent_bytes -ne 17179869184 -or `$result.storage_filesystem_bytes -ne 17179869184 -or `$result.storage_image_allocated_bytes -le 0 -or `$result.storage_image_allocated_bytes -gt `$result.storage_image_apparent_bytes) { throw 'Incus bounded storage postcondition failed' }
[IO.File]::WriteAllText('$ResultPath', (`$result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
    $temporaryPassword = New-CryptographicAccountPassword
    Set-LocalUser -Name $service.Name -Password $temporaryPassword
    $passwordApplied = $true
    [void](Register-OneShot "$env:COMPUTERNAME\$($service.Name)" $temporaryPassword)
    $registered = $true
    $temporaryPassword.Dispose(); $temporaryPassword = $null
    $observed = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $actualSid = ([Security.Principal.NTAccount]::new([string]$observed.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])).Value
    if ($observed.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $observed.Principal.LogonType -ne "Password" -or $observed.Principal.RunLevel -ne "Limited") { throw "one-shot task principal postcondition failed" }
    $expectedArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
    if (@($observed.Actions).Count -ne 1 -or $observed.Actions[0].Execute -ne $PowerShellExe -or $observed.Actions[0].Arguments -ne $expectedArguments) { throw "one-shot task action postcondition failed" }
    if (-not $observed.Settings.AllowDemandStart -or $observed.Settings.StartWhenAvailable -or $observed.Settings.MultipleInstances -ne "IgnoreNew") { throw "one-shot task settings postcondition failed" }
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds + 30)
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $complete = [string]$task.State -ne "Running" -and (Test-Path -LiteralPath $ResultPath -PathType Leaf)
        $failed = [string]$task.State -ne "Running" -and [uint32]$info.LastTaskResult -notin @(0, 267009)
    } while (-not $complete -and -not $failed -and (Get-Date) -lt $deadline)
    if (-not $complete -or [uint32]$info.LastTaskResult -ne 0) { throw "one-shot task failed or timed out" }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    foreach ($property in @('root_is_only_disk','profile_unprivileged','idmap_isolated','negative_canaries_passed','storage_quota_canary_passed','storage_mount_unit_enabled','storage_mount_unit_active','incus_mount_ordering_verified')) { if ($result.$property -ne $true) { throw "boundary result missing $property" } }
    foreach ($property in @('forbidden_devices','bridge_uplink','ipv4_nat','ipv6_nat','external_services_configured')) { if ($result.$property -ne $false) { throw "boundary result violates $property" } }
    if ($result.project_restricted -ne $true -or $result.project_instance_limit -ne 1 -or $result.nesting -ne $false -or $result.process_limit -ne 2048 -or $result.root_disk_size -ne '12GiB' -or $result.storage_driver -ne 'dir' -or $result.storage_filesystem -ne 'ext4' -or $result.storage_filesystem_uuid -notmatch '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or $result.storage_project_quota -ne $true -or $result.storage_quota_canary_passed -ne $true -or $result.storage_mount_persistent -ne $true -or $result.storage_mount_unit_enabled -ne $true -or $result.storage_mount_unit_active -ne $true -or $result.incus_mount_ordering_verified -ne $true -or $result.storage_mount_root_owned -ne $true -or $result.storage_pool_size -ne '16GiB' -or $result.storage_image_apparent_bytes -ne 17179869184 -or $result.storage_filesystem_bytes -ne 17179869184 -or $result.storage_image_allocated_bytes -le 0 -or $result.storage_image_allocated_bytes -gt $result.storage_image_apparent_bytes -or $result.storage_volumes -ne 0) { throw "boundary hardening postcondition failed" }
    $finalPassword = New-CryptographicAccountPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword -ErrorAction Stop }
    finally { $finalPassword.Dispose() }
    $passwordApplied = $false
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    Remove-Item -LiteralPath $Root -Recurse -Force
    [ordered]@{ status="installed"; project="ci-jit"; storage_pool="ci-jit-dedicated"; storage_driver="dir"; storage_filesystem="ext4"; storage_filesystem_uuid=$result.storage_filesystem_uuid; storage_pool_size="16GiB"; storage_project_quota=$true; storage_quota_canary_passed=$true; storage_mount_persistent=$true; storage_mount_persistence="systemd-mount-unit"; storage_mount_unit_enabled=$true; storage_mount_unit_active=$true; incus_mount_ordering_verified=$true; storage_mount_root_owned=$true; storage_image_apparent_bytes=$result.storage_image_apparent_bytes; storage_image_allocated_bytes=$result.storage_image_allocated_bytes; storage_filesystem_bytes=$result.storage_filesystem_bytes; bridge="ci-jit-isolated"; profile="ci-jit"; external_services_configured=$false; runner_registration_performed=$false; one_shot_task_absent=$true; stored_task_credential_invalidated=$true } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new(); $diagnosticBundle = $null
    try { $diagnosticBundle = Save-FailureDiagnostics $original $service.SID }
    catch { $cleanup.Add("diagnostic preservation: $($_.Exception.Message)") }
    if ($passwordApplied) {
        $recoveryPassword = New-CryptographicAccountPassword
        try { Set-LocalUser -Name $service.Name -Password $recoveryPassword -ErrorAction Stop; $passwordApplied = $false }
        catch { $cleanup.Add("credential invalidation: $($_.Exception.Message)") }
        finally { $recoveryPassword.Dispose() }
    }
    if ($registered -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop; $registered = $false }
        catch { $cleanup.Add("task cleanup: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $Root) { try { Remove-Item -LiteralPath $Root -Recurse -Force } catch { $cleanup.Add("staging cleanup: $($_.Exception.Message)") } }
    if ($cleanup.Count) { throw "Incus boundary install failed: $original. Cleanup failures: $($cleanup -join '; ')" }
    throw "Incus boundary install failed; task, credential, and staging cleanup were verified. Diagnostics: $diagnosticBundle. Idempotent WSL reconciliation may be rerun: $original"
}
finally { if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() } }
