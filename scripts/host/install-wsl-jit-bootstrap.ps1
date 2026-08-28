[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$BundleRelativePath = "artifacts/bootstrap/bootstrap-boundary-bundle.tar",
    [Parameter(Mandatory = $true)][string]$ExpectedBundleSha256,
    [Parameter(Mandatory = $true)][long]$ExpectedBundleBytes,
    [Parameter(Mandatory = $true)][string]$ExpectedReviewerFingerprint,
    [Parameter(Mandatory = $true)][string]$ExpectedBootstrapNonce,
    [int]$TimeoutSeconds = 900,
    [switch]$Apply,
    [switch]$AcknowledgeInertBootstrapMutation,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-WSL-JIT-Bootstrap"
$PackageRoot = "C:\ProgramData\self-hosted-ci\package"
$Root = "C:\ProgramData\self-hosted-ci\bootstrap-install"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$DiagnosticsRoot = "C:\ProgramData\self-hosted-ci\diagnostics\bootstrap-install\v1"
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
    $rootPath = [IO.Path]::GetFullPath($Boundary).TrimEnd('\')
    if ($full -ne $rootPath -and -not $full.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "path escapes package root" }
    $cursor = $full
    while ($cursor.Length -ge $rootPath.Length) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "reparse points are forbidden in package inputs" }
        if ($cursor -eq $rootPath) { break }
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
        $definition.Settings.ExecutionTimeLimit = "PT15M"
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
    $bundle = Join-Path $DiagnosticsRoot ([DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + [Guid]::NewGuid().ToString())
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
        diagnostic_version = 1; observed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        task_name = $TaskName; service_sid = $ServiceSid.Value; distro = $DistroName
        bundle_sha256 = $ExpectedBundleSha256; failure = $FailureMessage
        garm_activated = $false; github_configured = $false; runner_registration_changed = $false
    }
    [IO.File]::WriteAllText((Join-Path $bundle "failure.json"), ($safe | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $bundle
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "bootstrap installer requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($TimeoutSeconds -ne 900) { throw "TimeoutSeconds is pinned to 900" }
if ($BundleRelativePath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*\.tar$' -or $BundleRelativePath.Contains('..')) { throw "bundle path must be a safe package-relative tar path" }
if ($ExpectedBundleSha256 -notmatch '^[0-9a-f]{64}$' -or $ExpectedBundleSha256 -cne $ExpectedBundleSha256.ToLowerInvariant()) { throw "ExpectedBundleSha256 must be exact lowercase SHA-256" }
if ($ExpectedBundleBytes -le 0) { throw "ExpectedBundleBytes must be positive" }
if ($ExpectedReviewerFingerprint -notmatch '^[0-9a-f]{64}$' -or $ExpectedReviewerFingerprint -cne $ExpectedReviewerFingerprint.ToLowerInvariant()) { throw "ExpectedReviewerFingerprint must be exact lowercase SHA-256" }
if ($ExpectedBootstrapNonce -notmatch '^[0-9a-f]{32}$') { throw "ExpectedBootstrapNonce must be exact lowercase 128-bit hex" }
if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) { throw "package root is absent" }
$bundlePath = [IO.Path]::GetFullPath((Join-Path $PackageRoot $BundleRelativePath))
if (-not (Test-Path -LiteralPath $bundlePath -PathType Leaf)) { throw "bootstrap bundle is absent" }
Assert-NoReparsePath $bundlePath $PackageRoot
$actualBundleSha256 = (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualBundleBytes = (Get-Item -LiteralPath $bundlePath -Force).Length
if ($actualBundleSha256 -cne $ExpectedBundleSha256 -or $actualBundleBytes -ne $ExpectedBundleBytes) { throw "bootstrap bundle content address does not match" }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service

[ordered]@{
    mode = $(if ($Apply) { "apply" } else { "plan" }); apply_requested = [bool]$Apply
    task_name = $TaskName; service_sid = $service.SID.Value; distro = $DistroName
    bundle_relative_path = $BundleRelativePath.Replace('\','/'); bundle_sha256 = $actualBundleSha256; bundle_bytes = $actualBundleBytes
    transport = "stdin-no-drvfs"; operation = "verify signed bootstrap and provision inert contract"
    garm_activated = $false; github_configured = $false; runner_registration_performed = $false
    no_host_changes = (-not [bool]$Apply)
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeInertBootstrapMutation -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both explicit acknowledgements" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
if (Test-Path -LiteralPath $Root) { throw "staging root already exists" }

$registered = $false; $passwordApplied = $false; $temporaryPassword = $null
try {
    [void](New-Item -ItemType Directory -Path $Root)
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $payload = @'
set -euo pipefail
umask 077
readonly bundle="$1" expected_sha="$2" expected_fingerprint="$3" expected_nonce="$4"
readonly work=/run/self-hosted-ci-bootstrap-install
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
[[ "$(id -u)" == 0 && "${WSL_DISTRO_NAME:-}" == 'Ubuntu-24.04-CI' ]] || { echo 'unexpected bootstrap identity' >&2; exit 2; }
[[ -f "$bundle" && ! -L "$bundle" && "$(sha256sum -- "$bundle" | awk '{print $1}')" == "$expected_sha" ]] || { echo 'bootstrap bundle hash mismatch' >&2; exit 2; }
rm -rf -- "$work"; install -d -o root -g root -m 0700 "$work" "$work/extracted"
python3 - "$bundle" "$work/extracted" <<'PY'
import pathlib, sys, tarfile
source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
required = {
 "bootstrap/package/scripts/host/provision-wsl-jit-contract.sh",
 "bootstrap/bootstrap-boundary-v1.signed.json", "bootstrap/windows-observation.json",
 "bootstrap/wsl-observation.json", "bootstrap/bootstrap-public-manifest-v1.json",
 "bootstrap/reviewer-public-key.pem",
}
with tarfile.open(source, "r:") as archive:
    members = archive.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit("unsafe bootstrap bundle member")
        if member.uid != 0 or member.gid != 0 or member.mode & 0o7022:
            raise SystemExit("bootstrap bundle ownership or mode is unsafe")
    names = {pathlib.PurePosixPath(member.name).as_posix() for member in members}
    roots = {pathlib.PurePosixPath(member.name).parts[0] for member in members if pathlib.PurePosixPath(member.name).parts}
    if roots != {"bootstrap"} or not required.issubset(names):
        raise SystemExit("bootstrap bundle layout is invalid")
    archive.extractall(target, numeric_owner=True, filter="data")
PY
readonly root="$work/extracted/bootstrap" package="$work/extracted/bootstrap/package"
for input in bootstrap-boundary-v1.signed.json windows-observation.json wsl-observation.json bootstrap-public-manifest-v1.json reviewer-public-key.pem; do
  [[ -f "$root/$input" && ! -L "$root/$input" ]] || { echo "missing bootstrap input: $input" >&2; exit 2; }
done
[[ -x "$package/scripts/host/provision-wsl-jit-contract.sh" ]] || { echo 'provisioner is absent or not executable' >&2; exit 2; }
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED && ! -e /etc/self-hosted-ci/outbound-worker.runtime-ready ]] || { echo 'bootstrap precondition is not inert' >&2; exit 2; }
bash "$package/scripts/host/provision-wsl-jit-contract.sh" --apply \
  --bootstrap-evidence "$root/bootstrap-boundary-v1.signed.json" \
  --windows-observation "$root/windows-observation.json" --wsl-observation "$root/wsl-observation.json" \
  --public-manifest "$root/bootstrap-public-manifest-v1.json" --reviewer-public-key "$root/reviewer-public-key.pem" \
  --reviewer-key-fingerprint "$expected_fingerprint" --expected-bootstrap-nonce "$expected_nonce" \
  --acknowledge-host-mutation --acknowledge-dedicated-boundary >/dev/null
systemctl is-enabled --quiet self-hosted-ci-garm.service && { echo 'GARM was unexpectedly enabled' >&2; exit 2; }
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED && ! -e /etc/self-hosted-ci/outbound-worker.runtime-ready ]] || { echo 'bootstrap unexpectedly activated runtime' >&2; exit 2; }
printf '%s\n' '{"status":"installed","bootstrap_verified":true,"transport":"stdin-no-drvfs","garm_enabled":false,"github_configured":false,"runtime_ready_created":false,"runner_registration_performed":false}'
'@
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $payloadSha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
    $bootstrap = @'
import base64, hashlib, json, os, pathlib, subprocess, sys, tempfile
envelope = json.loads(sys.stdin.buffer.read())
if set(envelope) != {"archive_b64", "archive_sha256", "payload_b64", "payload_sha256"}:
    raise SystemExit("invalid stdin envelope")
archive = base64.b64decode(envelope["archive_b64"], validate=True)
payload = base64.b64decode(envelope["payload_b64"], validate=True)
if hashlib.sha256(archive).hexdigest() != envelope["archive_sha256"] or hashlib.sha256(payload).hexdigest() != envelope["payload_sha256"]:
    raise SystemExit("stdin payload hash mismatch")
work = pathlib.Path(tempfile.mkdtemp(prefix="self-hosted-ci-bootstrap.", dir="/run"))
archive_path, payload_path = work / "bundle.tar", work / "apply.sh"
try:
    archive_path.write_bytes(archive); payload_path.write_bytes(payload); os.chmod(payload_path, 0o700)
    subprocess.run(["/bin/bash", "-n", str(payload_path)], check=True)
    subprocess.run(["/bin/bash", str(payload_path), str(archive_path), envelope["archive_sha256"], *sys.argv[1:]], check=True)
finally:
    import shutil
    shutil.rmtree(work, ignore_errors=True)
'@
    $bootstrapB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrap))
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
`$archiveBytes = [IO.File]::ReadAllBytes('$bundlePath')
`$archiveSha = ([Security.Cryptography.SHA256]::Create().ComputeHash(`$archiveBytes) | ForEach-Object { `$_.ToString('x2') }) -join ''
if (`$archiveSha -cne '$ExpectedBundleSha256' -or `$archiveBytes.Length -ne $ExpectedBundleBytes) { throw 'bundle changed before stdin transfer' }
`$envelope = [ordered]@{ archive_b64=[Convert]::ToBase64String(`$archiveBytes); archive_sha256=`$archiveSha; payload_b64='$payloadB64'; payload_sha256='$payloadSha256' } | ConvertTo-Json -Compress
[Array]::Clear(`$archiveBytes, 0, `$archiveBytes.Length)
`$psi = [Diagnostics.ProcessStartInfo]::new(); `$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
`$psi.Arguments = '-d $DistroName -u root -- systemd-run --quiet --wait --pipe --collect --setenv=WSL_DISTRO_NAME=$DistroName --property=RuntimeMaxSec=840 --property=TimeoutStopSec=15 --property=KillMode=control-group --unit=self-hosted-ci-bootstrap-install /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$bootstrapB64''))" $ExpectedReviewerFingerprint $ExpectedBootstrapNonce'
`$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true; `$psi.RedirectStandardInput = `$true; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'could not start exact WSL bootstrap installer' }
`$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
`$process.StandardInput.Write(`$envelope); `$process.StandardInput.Close(); `$envelope = `$null
if (-not `$process.WaitForExit($TimeoutSeconds * 1000)) { try { `$process.Kill() } catch {}; throw 'WSL bootstrap installer timed out' }
`$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false)); [IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
if (`$process.ExitCode -ne 0) { throw "WSL bootstrap installer failed: `$(`$process.ExitCode)" }
`$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1; `$result = `$last | ConvertFrom-Json
if (`$result.status -ne 'installed' -or `$result.bootstrap_verified -ne `$true -or `$result.transport -ne 'stdin-no-drvfs' -or `$result.garm_enabled -ne `$false -or `$result.github_configured -ne `$false -or `$result.runtime_ready_created -ne `$false -or `$result.runner_registration_performed -ne `$false) { throw 'bootstrap postcondition failed' }
[IO.File]::WriteAllText('$ResultPath', (`$result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
    $temporaryPassword = New-CryptographicAccountPassword
    Set-LocalUser -Name $service.Name -Password $temporaryPassword; $passwordApplied = $true
    [void](Register-OneShot "$env:COMPUTERNAME\$($service.Name)" $temporaryPassword); $registered = $true
    $temporaryPassword.Dispose(); $temporaryPassword = $null
    $observed = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $actualSid = ([Security.Principal.NTAccount]::new([string]$observed.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])).Value
    $expectedArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WorkerPath`""
    if ($observed.TaskPath -ne "\" -or $actualSid -ne $ExpectedServiceAccountSid -or $observed.Principal.LogonType -ne "Password" -or $observed.Principal.RunLevel -ne "Limited") { throw "one-shot task principal postcondition failed" }
    if (@($observed.Actions).Count -ne 1 -or $observed.Actions[0].Execute -ne $PowerShellExe -or $observed.Actions[0].Arguments -ne $expectedArguments) { throw "one-shot task action postcondition failed" }
    if (-not $observed.Settings.AllowDemandStart -or $observed.Settings.StartWhenAvailable -or $observed.Settings.MultipleInstances -ne "IgnoreNew") { throw "one-shot task settings postcondition failed" }
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds + 30)
    do {
        Start-Sleep -Seconds 2; $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop; $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $complete = [string]$task.State -ne "Running" -and (Test-Path -LiteralPath $ResultPath -PathType Leaf)
        $failed = [string]$task.State -ne "Running" -and [uint32]$info.LastTaskResult -notin @(0, 267009)
    } while (-not $complete -and -not $failed -and (Get-Date) -lt $deadline)
    if (-not $complete -or [uint32]$info.LastTaskResult -ne 0) { throw "one-shot task failed or timed out" }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if ($result.status -ne "installed" -or $result.bootstrap_verified -ne $true) { throw "bootstrap result postcondition failed" }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop; $registered = $false
    $finalPassword = New-CryptographicAccountPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword -ErrorAction Stop; $passwordApplied = $false } finally { $finalPassword.Dispose() }
    Remove-Item -LiteralPath $Root -Recurse -Force
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task cleanup postcondition failed" }
    if (Test-Path -LiteralPath $Root) { throw "staging cleanup postcondition failed" }
    [ordered]@{ status="installed"; bootstrap_verified=$true; transport="stdin-no-drvfs"; garm_enabled=$false; github_configured=$false; runtime_ready_created=$false; runner_registration_performed=$false; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; staging_absent=$true } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new(); $diagnosticBundle = $null
    try { $diagnosticBundle = Save-FailureDiagnostics $original $service.SID } catch { $cleanup.Add("diagnostic preservation: $($_.Exception.Message)") }
    if ($registered -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop; $registered = $false } catch { $cleanup.Add("task cleanup: $($_.Exception.Message)") }
    }
    if ($passwordApplied) {
        $recoveryPassword = New-CryptographicAccountPassword
        try { Set-LocalUser -Name $service.Name -Password $recoveryPassword -ErrorAction Stop; $passwordApplied = $false } catch { $cleanup.Add("credential invalidation: $($_.Exception.Message)") } finally { $recoveryPassword.Dispose() }
    }
    if (Test-Path -LiteralPath $Root) { try { Remove-Item -LiteralPath $Root -Recurse -Force } catch { $cleanup.Add("staging cleanup: $($_.Exception.Message)") } }
    if ($cleanup.Count) { throw "Bootstrap install failed: $original. Cleanup failures: $($cleanup -join '; ')" }
    throw "Bootstrap install failed; task, credential, and staging cleanup were verified. Diagnostics: $diagnosticBundle. Idempotent WSL reconciliation may be rerun: $original"
}
finally { if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() } }
