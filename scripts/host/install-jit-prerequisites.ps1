[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [Parameter(Mandatory = $true)][string]$IncusVersion,
    [int]$TimeoutSeconds = 600,
    [switch]$Apply,
    [switch]$AcknowledgeHostPackageInstallation,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-JIT-Prerequisites"
$Root = "C:\ProgramData\self-hosted-ci\jit-prerequisites"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$DiagnosticsRoot = "C:\ProgramData\self-hosted-ci\diagnostics\jit-prerequisites"
$PayloadTemplate = Join-Path $PSScriptRoot "install-jit-prerequisites-wsl-payload.sh.in"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$ExpectedGarmVersion = "0.2.1"
$ExpectedGarmSha256 = "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746"
$ExpectedGarmCliVersion = "0.2.1"
$ExpectedGarmCliSha256 = "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e"
$ExpectedGarmProviderIncusVersion = "0.1.5"
$ExpectedGarmProviderIncusSha256 = "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f"
$ExpectedIncusVersion = "6.0.0-1ubuntu0.3"

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

function Save-FailureDiagnostics([string]$FailureMessage, [Security.Principal.SecurityIdentifier]$ServiceSid) {
    $bundle = Join-Path $DiagnosticsRoot ([Guid]::NewGuid().ToString())
    [void](New-Item -ItemType Directory -Path $bundle -Force)
    Set-Acl -LiteralPath $bundle -AclObject (New-ProtectedAcl $ServiceSid)
    foreach ($entry in @(
        @{ Source = $StdoutPath; Name = "worker.stdout.log" },
        @{ Source = $StderrPath; Name = "worker.stderr.log" },
        @{ Source = $ResultPath; Name = "install-result.json" }
    )) {
        if (Test-Path -LiteralPath $entry.Source -PathType Leaf) {
            Copy-Item -LiteralPath $entry.Source -Destination (Join-Path $bundle $entry.Name)
        }
    }
    $safeFailure = [ordered]@{
        observed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        task_name = $TaskName
        service_sid = $ServiceSid.Value
        distro = $DistroName
        incus_version = $IncusVersion
        garm_version = $ExpectedGarmVersion
        failure = $FailureMessage
        runner_registration_performed = $false
    }
    [IO.File]::WriteAllText((Join-Path $bundle "failure.json"), ($safeFailure | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $bundle
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "installer requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($IncusVersion -ne $ExpectedIncusVersion) { throw "IncusVersion must match the pinned policy version $ExpectedIncusVersion" }
if ($TimeoutSeconds -ne 600) { throw "TimeoutSeconds is pinned to 600" }
if (-not (Test-Path -LiteralPath $PayloadTemplate -PathType Leaf)) { throw "payload template is absent" }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service

$payload = (Get-Content -LiteralPath $PayloadTemplate -Raw).Replace('@@INCUS_VERSION@@', $IncusVersion)
if ($payload -match '@@[A-Z0-9_]+@@') { throw "payload has unresolved markers" }
$payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
$payloadSha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
[ordered]@{
    mode = $(if ($Apply) { "apply" } else { "plan" }); apply_requested = [bool]$Apply; task_name = $TaskName
    service_sid = $service.SID.Value; distro = $DistroName; incus_version = $IncusVersion
    garm_version = $ExpectedGarmVersion; garm_sha256 = $ExpectedGarmSha256
    garm_cli_version = $ExpectedGarmCliVersion; garm_cli_sha256 = $ExpectedGarmCliSha256
    garm_provider_incus_version = $ExpectedGarmProviderIncusVersion; garm_provider_incus_sha256 = $ExpectedGarmProviderIncusSha256
    payload_sha256 = $payloadSha256; garm_enabled = $false
    runner_registration = "not_performed"; no_host_changes = (-not [bool]$Apply)
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeHostPackageInstallation -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both explicit acknowledgements" }
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
fd, path = tempfile.mkstemp(prefix="self-hosted-ci-jit-prerequisites.", suffix=".sh", dir="/run")
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    subprocess.run(["/bin/bash", "-n", path], check=True)
    subprocess.run(["/bin/bash", path], check=True)
finally:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
'@
    $bootstrapB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrap))
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
`$unitName = 'self-hosted-ci-jit-prerequisites'
function Stop-WslInstallUnit {
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /bin/true
    if (`$LASTEXITCODE -ne 0) { throw 'WSL transport unavailable while terminating install unit' }
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl kill --kill-whom=all `$unitName 2>`$null
    & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl stop `$unitName 2>`$null
    `$show = @(& `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- systemctl show `$unitName --property=ActiveState --property=SubState --property=ControlGroup --value 2>&1)
    `$showExit = `$LASTEXITCODE
    if (`$showExit -eq 4) { return }
    if (`$showExit -ne 0 -or `$show.Count -ne 3) { throw 'WSL install unit termination state is unobservable' }
    `$active = ([string]`$show[0]).Trim(); `$sub = ([string]`$show[1]).Trim(); `$controlGroup = ([string]`$show[2]).Trim()
    if (`$active -notin @('inactive','failed') -or `$sub -notin @('dead','failed')) { throw 'WSL install unit could not be terminated' }
    if (`$controlGroup) {
        & `$env:SystemRoot\System32\wsl.exe -d $DistroName -u root -- /usr/bin/test '!' -s "/sys/fs/cgroup`$controlGroup/cgroup.procs"
        if (`$LASTEXITCODE -ne 0) { throw 'WSL install unit cgroup still contains processes' }
    }
}
`$psi = [Diagnostics.ProcessStartInfo]::new()
`$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
`$psi.Arguments = '-d $DistroName -u root -- systemd-run --quiet --wait --pipe --collect --setenv=WSL_DISTRO_NAME=$DistroName --property=RuntimeMaxSec=600 --property=TimeoutStopSec=15 --property=KillMode=control-group --unit=' + `$unitName + ' /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$bootstrapB64''))" $payloadSha256'
`$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true
`$psi.RedirectStandardInput = `$true; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'could not start exact WSL prerequisite installer' }
`$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
`$process.StandardInput.Write('$payloadB64'); `$process.StandardInput.Close()
if (-not `$process.WaitForExit($TimeoutSeconds * 1000)) {
    try { `$process.Kill() } catch {}
    Stop-WslInstallUnit
    throw 'WSL prerequisite installer timed out and its systemd unit was terminated'
}
`$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
if (`$process.ExitCode -ne 0) { Stop-WslInstallUnit; throw "WSL prerequisite installer failed: `$(`$process.ExitCode)" }
`$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1
`$result = `$last | ConvertFrom-Json
if (`$result.status -ne 'installed' -or `$result.garm_enabled -ne `$false -or `$result.runner_registration_performed -ne `$false) { throw 'JIT prerequisite postcondition failed' }
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
    if ($result.garm_version -ne $ExpectedGarmVersion -or $result.garm_sha256 -ne $ExpectedGarmSha256 -or
        $result.garm_cli_version -ne $ExpectedGarmCliVersion -or $result.garm_cli_sha256 -ne $ExpectedGarmCliSha256 -or
        $result.garm_provider_incus_version -ne $ExpectedGarmProviderIncusVersion -or $result.garm_provider_incus_sha256 -ne $ExpectedGarmProviderIncusSha256 -or
        $result.garm_manager_incus_admin -ne $false -or $result.incus_version -ne $IncusVersion -or
        $result.dnsmasq_base_installed -ne $true -or $result.dnsmasq_service_absent -ne $true -or
        $result.nftables_installed -ne $true -or $result.squid_installed -ne $true -or
        $result.distribution_network_services_disabled -ne $true -or
        $result.garm_enabled -ne $false -or $result.runner_registration_performed -ne $false) {
        throw "installed prerequisite postcondition failed"
    }
    $finalPassword = New-CryptographicAccountPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword -ErrorAction Stop }
    finally { $finalPassword.Dispose() }
    $passwordApplied = $false
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    Remove-Item -LiteralPath $Root -Recurse -Force
    [ordered]@{ status="installed"; incus_version=$IncusVersion; garm_version=$ExpectedGarmVersion; garm_cli_version=$ExpectedGarmCliVersion; garm_provider_incus_version=$ExpectedGarmProviderIncusVersion; dnsmasq_base_installed=$true; dnsmasq_service_absent=$true; nftables_installed=$true; squid_installed=$true; distribution_network_services_disabled=$true; garm_manager_incus_admin=$false; garm_enabled=$false; runner_registration_performed=$false; one_shot_task_absent=$true; stored_task_credential_invalidated=$true } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new()
    $diagnosticBundle = $null
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
    if ($cleanup.Count) { throw "JIT prerequisite install failed: $original. Cleanup failures: $($cleanup -join '; ')" }
    throw "JIT prerequisite install failed; Windows task, credential, and staging cleanup were verified. Diagnostics: $diagnosticBundle. WSL may contain reconciliable partial prerequisite state: $original"
}
finally { if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() } }
