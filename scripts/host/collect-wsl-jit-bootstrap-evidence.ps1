[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [int]$TimeoutSeconds = 600,
    [switch]$Apply,
    [switch]$AcknowledgeBootstrapEvidenceCollection,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Collect-WSL-JIT-Bootstrap-Evidence"
$PackageRoot = "C:\ProgramData\self-hosted-ci\package"
$WindowsCollectorPath = Join-Path $PackageRoot "scripts\host\collect-windows-wsl-semantic-contract.ps1"
$WslCollectorPath = Join-Path $PackageRoot "scripts\host\collect-wsl-jit-semantic-observations.py"
$Root = "C:\ProgramData\self-hosted-ci\bootstrap-evidence-collection"
$WorkerPath = Join-Path $Root "collect-worker.ps1"
$ResultPath = Join-Path $Root "collect-result.json"
$WslStagingPath = Join-Path $Root "wsl-observation.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$OutputRoot = "C:\ProgramData\self-hosted-ci\bootstrap-evidence\v1"
$WindowsEvidenceRoot = "C:\ProgramData\self-hosted-ci\semantic-contract-staging\v1"
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

function Assert-NoReparsePath([string]$Path, [string]$Boundary) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($Boundary).TrimEnd('\')
    if ($full -ne $root -and -not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "path escapes its expected boundary" }
    $cursor = $full
    while ($cursor.Length -ge $root.Length) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "reparse points are forbidden" }
        if ($cursor -eq $root) { break }
        $cursor = Split-Path -Parent $cursor
    }
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

function New-PrivateAcl([bool]$Directory) {
    if ($Directory) { $acl = [Security.AccessControl.DirectorySecurity]::new() }
    else { $acl = [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admins)
    if ($Directory) {
        $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @($system, $admins)) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
    }
    else {
        foreach ($sid in @($system, $admins)) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
        }
    }
    return $acl
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Save-ContentAddressedJson([string]$Source, [string]$Prefix) {
    $sha256 = Get-Sha256 $Source
    $destination = Join-Path $OutputRoot ("$Prefix-$sha256.json")
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "content-addressed evidence destination is unsafe" }
        if ((Get-Sha256 $destination) -cne $sha256) { throw "content-addressed evidence collision" }
    }
    else {
        Copy-Item -LiteralPath $Source -Destination $destination -ErrorAction Stop
    }
    Set-Acl -LiteralPath $destination -AclObject (New-PrivateAcl $false)
    return [ordered]@{ path = $destination; sha256 = $sha256; bytes = (Get-Item -LiteralPath $destination -Force).Length }
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
        $definition.Settings.ExecutionTimeLimit = "PT12M"
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

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "collector requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($TimeoutSeconds -ne 600) { throw "TimeoutSeconds is pinned to 600" }
foreach ($path in @($PackageRoot, $WindowsCollectorPath, $WslCollectorPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "required package input is absent: $path" }
    Assert-NoReparsePath $path $PackageRoot
}
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service
$wslCollectorSha256 = Get-Sha256 $WslCollectorPath

[ordered]@{
    mode = $(if ($Apply) { "apply" } else { "plan" })
    apply_requested = [bool]$Apply
    task_name = $TaskName
    service_sid = $service.SID.Value
    distro = $DistroName
    windows_collector = "scripts/host/collect-windows-wsl-semantic-contract.ps1"
    wsl_collector = "scripts/host/collect-wsl-jit-semantic-observations.py"
    wsl_collector_sha256 = $wslCollectorSha256
    output_root = $OutputRoot
    operations = @("collect elevated Windows semantic evidence", "collect WSL semantic evidence through an exact Password/Limited one-shot task", "preserve both JSON documents by SHA-256", "rotate the service password before and after collection", "remove task and staging")
    github_contacted = $false
    runner_registration_changed = $false
    activation_changed = $false
    no_host_changes = (-not [bool]$Apply)
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeBootstrapEvidenceCollection -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both explicit acknowledgements" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
if (Test-Path -LiteralPath $Root) { throw "staging root already exists" }

$registered = $false; $passwordApplied = $false; $temporaryPassword = $null
$windowsSaved = $null; $wslSaved = $null
try {
    if (-not (Test-Path -LiteralPath $OutputRoot)) { [void](New-Item -ItemType Directory -Path $OutputRoot -Force) }
    Assert-NoReparsePath $OutputRoot "C:\ProgramData\self-hosted-ci"
    Set-Acl -LiteralPath $OutputRoot -AclObject (New-PrivateAcl $true)

    $windowsResultLine = & $WindowsCollectorPath -ExpectedServiceAccountSid $ExpectedServiceAccountSid | Select-Object -Last 1
    $windowsResult = $windowsResultLine | ConvertFrom-Json
    if ($windowsResult.status -ne "observed") { throw "Windows collector did not return an observation" }
    $windowsEvidencePath = [IO.Path]::GetFullPath([string]$windowsResult.evidence_path)
    if (-not (Test-Path -LiteralPath $windowsEvidencePath -PathType Leaf)) { throw "Windows evidence file is absent" }
    Assert-NoReparsePath $windowsEvidencePath $WindowsEvidenceRoot
    $windowsObservation = Get-Content -LiteralPath $windowsEvidencePath -Raw | ConvertFrom-Json
    if ($windowsObservation.schema -ne "self-hosted-ci/windows-wsl-semantic-contract" -or [int]$windowsObservation.schema_version -ne 1) { throw "Windows evidence schema mismatch" }
    $windowsSaved = Save-ContentAddressedJson $windowsEvidencePath "windows-wsl-semantic-contract"

    [void](New-Item -ItemType Directory -Path $Root)
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $collectorLinuxRoot = "/run/self-hosted-ci-bootstrap-evidence"
    $collectorLinuxPath = "$collectorLinuxRoot/collect-wsl-jit-semantic-observations.py"
    $wslCollectorBytes = (Get-Item -LiteralPath $WslCollectorPath -Force -ErrorAction Stop).Length
    $stage = @'
import hashlib, os, pathlib, sys
target, expected_sha256, expected_bytes = sys.argv[1], sys.argv[2], int(sys.argv[3])
root = pathlib.Path(target).parent
if root != pathlib.Path("/run/self-hosted-ci-bootstrap-evidence") or pathlib.Path(target).name != "collect-wsl-jit-semantic-observations.py":
    raise SystemExit("unexpected WSL collector staging path")
if root.exists() or os.path.lexists(target):
    raise SystemExit("WSL collector staging path already exists")
os.mkdir(root, 0o700)
root_details = os.stat(root, follow_symlinks=False)
if not root.is_dir() or root.is_symlink() or root_details.st_uid != 0 or (root_details.st_mode & 0o777) != 0o700:
    raise SystemExit("WSL collector staging directory is unsafe")
temporary = root / ".collector.tmp"
try:
    payload = sys.stdin.buffer.read(expected_bytes + 1)
    if len(payload) != expected_bytes:
        raise SystemExit("WSL collector byte count mismatch")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise SystemExit("WSL collector sha256 mismatch during staging")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.replace(temporary, target)
    details = os.stat(target, follow_symlinks=False)
    if not os.path.isfile(target) or os.path.islink(target) or details.st_nlink != 1 or details.st_uid != 0 or (details.st_mode & 0o777) != 0o600:
        raise SystemExit("staged WSL collector is unsafe")
    with open(target, "rb") as handle:
        staged = handle.read(expected_bytes + 1)
    if len(staged) != expected_bytes or hashlib.sha256(staged).hexdigest() != expected_sha256:
        raise SystemExit("staged WSL collector verification failed")
except BaseException:
    try:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        if os.path.lexists(target):
            os.unlink(target)
        os.rmdir(root)
    except OSError:
        pass
    raise
'@
    $stageB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stage))
    $bootstrap = @'
import hashlib, os, subprocess, sys
collector, expected = sys.argv[1], sys.argv[2]
if os.environ.get("WSL_DISTRO_NAME") != "Ubuntu-24.04-CI" or os.geteuid() != 0:
    raise SystemExit("unexpected WSL collector identity")
details = os.stat(collector, follow_symlinks=False)
if not os.path.isfile(collector) or os.path.islink(collector) or details.st_nlink != 1:
    raise SystemExit("WSL collector input is unsafe")
with open(collector, "rb") as handle:
    actual = hashlib.sha256(handle.read()).hexdigest()
if actual != expected:
    raise SystemExit("WSL collector sha256 mismatch")
completed = subprocess.run(["/usr/bin/python3", collector], check=False)
raise SystemExit(completed.returncode)
'@
    $bootstrapB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrap))
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
function Remove-WslCollectorStage {
    `$cleanupProgram = 'import os,sys; root=sys.argv[1]; target=sys.argv[2]; temporary=os.path.join(root,".collector.tmp"); os.unlink(target) if os.path.lexists(target) else None; os.unlink(temporary) if os.path.lexists(temporary) else None; os.rmdir(root) if os.path.lexists(root) else None; raise SystemExit(0 if not os.path.lexists(target) and not os.path.lexists(temporary) and not os.path.lexists(root) else 1)'
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /usr/bin/python3 -c `$cleanupProgram '$collectorLinuxRoot' '$collectorLinuxPath'
    if (`$LASTEXITCODE -ne 0) { throw 'WSL collector staging cleanup failed' }
}
function Stage-WslCollector {
    `$collectorBytes = [IO.File]::ReadAllBytes('$WslCollectorPath')
    if (`$collectorBytes.Length -ne $wslCollectorBytes) { throw 'Windows collector byte count changed before staging' }
    `$stagePsi = [Diagnostics.ProcessStartInfo]::new()
    `$stagePsi.FileName = "`$env:SystemRoot\System32\wsl.exe"
    `$stagePsi.Arguments = '-d $DistroName -u root -- /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$stageB64''))" $collectorLinuxPath $wslCollectorSha256 $wslCollectorBytes'
    `$stagePsi.UseShellExecute = `$false; `$stagePsi.CreateNoWindow = `$true
    `$stagePsi.RedirectStandardInput = `$true; `$stagePsi.RedirectStandardOutput = `$true; `$stagePsi.RedirectStandardError = `$true
    `$stageProcess = [Diagnostics.Process]::new(); `$stageProcess.StartInfo = `$stagePsi
    if (-not `$stageProcess.Start()) { throw 'could not start exact WSL collector staging transport' }
    try {
        `$stageProcess.StandardInput.BaseStream.Write(`$collectorBytes, 0, `$collectorBytes.Length)
        `$stageProcess.StandardInput.BaseStream.Flush()
        `$stageProcess.StandardInput.Close()
        `$stageStdoutTask = `$stageProcess.StandardOutput.ReadToEndAsync(); `$stageStderrTask = `$stageProcess.StandardError.ReadToEndAsync()
        if (-not `$stageProcess.WaitForExit(60000)) { try { `$stageProcess.Kill() } catch {}; throw 'WSL collector staging transport timed out' }
        `$stageStdout = `$stageStdoutTask.GetAwaiter().GetResult(); `$stageStderr = `$stageStderrTask.GetAwaiter().GetResult()
        if (`$stageProcess.ExitCode -ne 0) { throw "WSL collector staging transport failed: `$stageStderr" }
    }
    finally { [Array]::Clear(`$collectorBytes, 0, `$collectorBytes.Length) }
}
function Stop-WslCollectionUnit {
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /bin/true
    if (`$LASTEXITCODE -ne 0) { throw 'WSL transport unavailable while terminating collection unit' }
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl kill --kill-whom=all self-hosted-ci-bootstrap-evidence-collect 2>`$null
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl stop self-hosted-ci-bootstrap-evidence-collect 2>`$null
    `$show = @(& `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl show self-hosted-ci-bootstrap-evidence-collect --property=ActiveState --property=SubState --property=ControlGroup --value 2>&1)
    `$showExit = `$LASTEXITCODE
    if (`$showExit -eq 4) { return }
    if (`$showExit -ne 0 -or `$show.Count -ne 3) { throw 'WSL collection unit termination state is unobservable' }
    `$active = ([string]`$show[0]).Trim(); `$sub = ([string]`$show[1]).Trim(); `$controlGroup = ([string]`$show[2]).Trim()
    if (`$active -notin @('inactive','failed') -or `$sub -notin @('dead','failed')) { throw 'WSL collection unit could not be terminated' }
    if (`$controlGroup) {
        & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /usr/bin/test '!' -s "/sys/fs/cgroup`$controlGroup/cgroup.procs"
        if (`$LASTEXITCODE -ne 0) { throw 'WSL collection unit cgroup still contains processes' }
    }
}
`$stageAttempted = `$false; `$collectionFailure = `$null
try {
    `$stageAttempted = `$true
    Stage-WslCollector
    `$psi = [Diagnostics.ProcessStartInfo]::new()
    `$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
    `$psi.Arguments = '-d $DistroName -u root -- systemd-run --quiet --wait --pipe --collect --setenv=WSL_DISTRO_NAME=$DistroName --property=RuntimeMaxSec=600 --property=TimeoutStopSec=15 --property=KillMode=control-group --unit=self-hosted-ci-bootstrap-evidence-collect /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$bootstrapB64''))" $collectorLinuxPath $wslCollectorSha256'
    `$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true
    `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
    `$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
    if (-not `$process.Start()) { throw 'could not start exact WSL evidence collector' }
    `$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
    if (-not `$process.WaitForExit($TimeoutSeconds * 1000)) { try { `$process.Kill() } catch {}; Stop-WslCollectionUnit; throw 'WSL evidence collector timed out and its systemd unit was terminated' }
    `$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
    [IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
    `$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1
    if (-not `$last) { throw 'WSL collector produced no JSON observation' }
    `$observation = `$last | ConvertFrom-Json
    if (`$observation.collector -ne 'wsl-jit-semantic-observations' -or [int]`$observation.schema_version -ne 1) { throw 'WSL evidence schema mismatch' }
    [IO.File]::WriteAllText('$WslStagingPath', `$last + "`n", [Text.UTF8Encoding]::new(`$false))
    [ordered]@{ status='observed'; exit_code=`$process.ExitCode; collection_status=`$observation.collection_status } | ConvertTo-Json -Compress | Set-Content -LiteralPath '$ResultPath' -Encoding UTF8
}
catch { `$collectionFailure = `$_.Exception.Message }
finally {
    if (`$stageAttempted) {
        try { Remove-WslCollectorStage }
        catch {
            if (`$collectionFailure) { `$collectionFailure += "; `$(`$_.Exception.Message)" }
            else { `$collectionFailure = `$_.Exception.Message }
        }
    }
}
if (`$collectionFailure) { throw `$collectionFailure }
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
    $actions = @($observed.Actions)
    if ($observed.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $observed.Principal.LogonType -ne "Password" -or $observed.Principal.RunLevel -ne "Limited") { throw "one-shot task principal postcondition failed" }
    if ($actions.Count -ne 1 -or [IO.Path]::GetFullPath([string]$actions[0].Execute) -ne [IO.Path]::GetFullPath($PowerShellExe) -or [string]$actions[0].Arguments -ne "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`"") { throw "one-shot task action postcondition failed" }
    if (-not $observed.Settings.Enabled -or -not $observed.Settings.AllowDemandStart -or $observed.Settings.StartWhenAvailable -or $observed.Settings.MultipleInstances -ne "IgnoreNew") { throw "one-shot task settings postcondition failed" }

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
    if ($result.status -ne "observed" -or -not (Test-Path -LiteralPath $WslStagingPath -PathType Leaf)) { throw "WSL collection postcondition failed" }
    $wslObservation = Get-Content -LiteralPath $WslStagingPath -Raw | ConvertFrom-Json
    $wslSaved = Save-ContentAddressedJson $WslStagingPath "wsl-jit-semantic-observations"

    $finalPassword = New-CryptographicAccountPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword -ErrorAction Stop }
    finally { $finalPassword.Dispose() }
    $passwordApplied = $false
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    Remove-Item -LiteralPath $Root -Recurse -Force
    if (-not [bool]$windowsObservation.contract_satisfied -or $result.exit_code -ne 0 -or $wslObservation.collection_status -ne "complete") { throw "bootstrap evidence was preserved but is not complete enough to build and sign" }
    [ordered]@{
        status = "collected"
        bootstrap_ready = $true
        windows_evidence_path = $windowsSaved.path
        windows_evidence_sha256 = $windowsSaved.sha256
        windows_evidence_bytes = $windowsSaved.bytes
        wsl_evidence_path = $wslSaved.path
        wsl_evidence_sha256 = $wslSaved.sha256
        wsl_evidence_bytes = $wslSaved.bytes
        one_shot_task_absent = $true
        stored_task_credential_invalidated = $true
        github_contacted = $false
        runner_registration_changed = $false
        activation_changed = $false
    } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new()
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
    $preservedPaths = [Collections.Generic.List[string]]::new()
    if ($null -ne $windowsSaved) { [void]$preservedPaths.Add([string]$windowsSaved.path) }
    if ($null -ne $wslSaved) { [void]$preservedPaths.Add([string]$wslSaved.path) }
    $preserved = $preservedPaths -join ", "
    if ($cleanup.Count) { throw "bootstrap evidence collection failed: $original. Preserved: $preserved. Cleanup failures: $($cleanup -join '; ')" }
    throw "bootstrap evidence collection failed; task, credential, and staging cleanup were verified. Preserved: $preserved. Original error: $original"
}
finally { if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() } }
