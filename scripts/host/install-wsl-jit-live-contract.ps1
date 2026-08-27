[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$BundleRelativePath = "artifacts/live-contract/live-contract-bundle.tar",
    [string]$UnsignedSourceRelativePath = "artifacts/live-contract/unsigned-live-contract-source.tar",
    [string]$ExpectedInputSha256,
    [long]$ExpectedInputBytes,
    [string]$ExpectedReviewerFingerprint,
    [int]$TimeoutSeconds = 600,
    [switch]$CollectUnsigned,
    [switch]$Apply,
    [switch]$AcknowledgeLiveContractMutation,
    [switch]$AcknowledgeUnsignedCollection,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-WSL-JIT-Live-Contract"
$PackageRoot = "C:\ProgramData\self-hosted-ci\package"
$Root = "C:\ProgramData\self-hosted-ci\live-contract-install"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$UnsignedStagingPath = Join-Path $Root "unsigned-live-contract.tar"
$UnsignedOutputRoot = "C:\ProgramData\self-hosted-ci\unsigned-live-contract"
$DiagnosticsRoot = "C:\ProgramData\self-hosted-ci\diagnostics\live-contract-install\v1"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$DiagnosticVersion = 1

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
    if ($full -ne $root -and -not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "path escapes package root" }
    $cursor = $full
    while ($cursor.Length -ge $root.Length) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "reparse points are forbidden in package inputs" }
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
        diagnostic_version = $DiagnosticVersion
        observed_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        task_name = $TaskName
        service_sid = $ServiceSid.Value
        distro = $DistroName
        input_sha256 = $inputSha256
        operation = $operation
        failure = $FailureMessage
        garm_activated = $false
        github_configured = $false
        runtime_ready_created = $false
    }
    [IO.File]::WriteAllText((Join-Path $bundle "failure.json"), ($safe | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $bundle
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "installer requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($TimeoutSeconds -ne 600) { throw "TimeoutSeconds is pinned to 600" }
$operation = $(if ($CollectUnsigned) { "collect-unsigned" } else { "install-signed" })
$inputRelativePath = $(if ($CollectUnsigned) { $UnsignedSourceRelativePath } else { $BundleRelativePath })
if ($inputRelativePath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or $inputRelativePath.Contains('..')) { throw "input path must be a safe package-relative path" }
if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) { throw "package root is absent" }
$inputPath = [IO.Path]::GetFullPath((Join-Path $PackageRoot $inputRelativePath))
if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw "live contract input archive is absent" }
Assert-NoReparsePath $inputPath $PackageRoot
$inputBytes = [IO.File]::ReadAllBytes($inputPath)
$inputSha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($inputBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
[Array]::Clear($inputBytes, 0, $inputBytes.Length)
$inputLength = (Get-Item -LiteralPath $inputPath -Force).Length
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service

[ordered]@{
    mode = $(if ($Apply) { "apply" } else { "plan" })
    apply_requested = [bool]$Apply
    task_name = $TaskName
    service_sid = $service.SID.Value
    distro = $DistroName
    operation = $operation
    input_relative_path = $inputRelativePath.Replace('\','/')
    input_sha256 = $inputSha256
    input_bytes = $inputLength
    diagnostic_contract_version = $DiagnosticVersion
    operations = $(if ($CollectUnsigned) { @("regenerate the unsigned live artifact contract", "export a deterministic content-addressed tar", "leave provisioning and activation untouched") } else { @("regenerate and compare the signed live artifact contract", "verify and provision under the dedicated WSL service identity", "leave GARM and GitHub integration inactive") })
    garm_activated = $false
    github_configured = $false
    runtime_ready_created = $false
    no_host_changes = (-not [bool]$Apply)
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if ($ExpectedInputSha256 -notmatch '^[0-9a-f]{64}$' -or $ExpectedInputSha256 -cne $inputSha256) { throw "Apply requires the exact lowercase ExpectedInputSha256" }
if ($ExpectedInputBytes -le 0 -or $ExpectedInputBytes -ne $inputLength) { throw "Apply requires the exact positive ExpectedInputBytes" }
if (-not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires AcknowledgeOneTimePasswordRotation" }
if ($CollectUnsigned -and -not $AcknowledgeUnsignedCollection) { throw "CollectUnsigned Apply requires AcknowledgeUnsignedCollection" }
if (-not $CollectUnsigned -and -not $AcknowledgeLiveContractMutation) { throw "signed install Apply requires AcknowledgeLiveContractMutation" }
if (-not $CollectUnsigned -and ($ExpectedReviewerFingerprint -notmatch '^[0-9a-f]{64}$' -or $ExpectedReviewerFingerprint -cne $ExpectedReviewerFingerprint.ToLowerInvariant())) { throw "signed install Apply requires an exact lowercase ExpectedReviewerFingerprint" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
if (Test-Path -LiteralPath $Root) { throw "staging root already exists" }

$registered = $false; $passwordApplied = $false; $temporaryPassword = $null
try {
    [void](New-Item -ItemType Directory -Path $Root)
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $inputLinuxPath = "/mnt/c/ProgramData/self-hosted-ci/package/" + $inputRelativePath.Replace('\','/')
    $packageLinuxPath = "/mnt/c/ProgramData/self-hosted-ci/package"
    if ($CollectUnsigned) {
        $payload = @'
set -euo pipefail
umask 077
readonly package_root="$1" source_archive="$2" expected_sha="$3" output_tar="$4"
readonly work=/run/self-hosted-ci-live-contract-collect
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
[[ "$(id -u)" == 0 && "${WSL_DISTRO_NAME:-}" == 'Ubuntu-24.04-CI' ]] || { echo 'unexpected live contract collector identity' >&2; exit 2; }
[[ -f "$source_archive" && ! -L "$source_archive" ]] || { echo 'unsigned source archive is unsafe or absent' >&2; exit 2; }
[[ "$(sha256sum -- "$source_archive" | awk '{print $1}')" == "$expected_sha" ]] || { echo 'unsigned source archive sha256 mismatch' >&2; exit 2; }
rm -rf -- "$work"
install -d -o root -g root -m 0700 "$work" "$work/source"
python3 - "$source_archive" "$work/source" <<'PY'
import pathlib, sys, tarfile
source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
with tarfile.open(source, "r:") as archive:
    members = archive.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev() or member.uid != 0 or member.gid != 0 or member.mode & 0o7022:
            raise SystemExit("unsafe unsigned source member")
    names = {pathlib.PurePosixPath(member.name) for member in members}
    if {pathlib.PurePosixPath(member.name).parts[0] for member in members if pathlib.PurePosixPath(member.name).parts} != {"contract"} or pathlib.PurePosixPath("contract/runner-boundary-template-v2.json") not in names:
        raise SystemExit("unsigned source layout is invalid")
    archive.extractall(target, numeric_owner=True, filter="data")
PY
readonly contract_root="$work/source/contract"
python3 "$package_root/scripts/host/stage-wsl-jit-live-contract.py" \
  --input-boundary "$contract_root/runner-boundary-template-v2.json" \
  --output-boundary "$work/staged.json" --measurement-root "$contract_root"
python3 "$package_root/scripts/host/collect-wsl-jit-measurements.py" \
  --input "$work/staged.json" --output "$contract_root/runner-boundary-measured-v2.json" --measurement-root "$contract_root"
rm -f -- "$contract_root/runner-boundary-v2.json" "$contract_root/reviewer-public-key.pem" "$contract_root/reviewer-key.sha256"
tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$work/source" -cf "$output_tar" contract
sha="$(sha256sum -- "$output_tar" | awk '{print $1}')"
bytes="$(stat -c %s -- "$output_tar")"
printf '{"status":"collected","unsigned_bundle_sha256":"%s","unsigned_bundle_bytes":%s,"garm_enabled":false,"github_configured":false,"runtime_ready_created":false,"runner_registration_performed":false}\n' "$sha" "$bytes"
'@
    }
    else {
        $payload = @'
set -euo pipefail
umask 077
readonly package_root="$1" bundle="$2" expected_sha="$3"
readonly work=/run/self-hosted-ci-live-contract-install
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
[[ "$(id -u)" == 0 ]] || { echo 'live contract payload requires root' >&2; exit 2; }
[[ "${WSL_DISTRO_NAME:-}" == 'Ubuntu-24.04-CI' ]] || { echo 'unexpected WSL distro' >&2; exit 2; }
[[ -f "$bundle" && ! -L "$bundle" ]] || { echo 'live contract bundle is unsafe or absent' >&2; exit 2; }
actual_sha="$(sha256sum -- "$bundle" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || { echo 'live contract bundle sha256 mismatch' >&2; exit 2; }
rm -rf -- "$work"
install -d -o root -g root -m 0700 "$work" "$work/bundle"
python3 - "$bundle" "$work/bundle" <<'PY'
import pathlib, sys, tarfile
source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
required = {"runner-boundary-template-v2.json", "runner-boundary-v2.json", "reviewer-public-key.pem", "reviewer-key.sha256"}
with tarfile.open(source, "r:") as archive:
    members = archive.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit("unsafe live contract bundle member")
        if member.uid != 0 or member.gid != 0:
            raise SystemExit("live contract bundle members must be root-owned")
        if member.mode & 0o7022:
            raise SystemExit("live contract bundle member has unsafe mode")
    roots = {pathlib.PurePosixPath(member.name).parts[0] for member in members if pathlib.PurePosixPath(member.name).parts}
    names = {pathlib.PurePosixPath(member.name) for member in members}
    if roots != {"contract"} or not {pathlib.PurePosixPath("contract") / name for name in required}.issubset(names):
        raise SystemExit("live contract bundle layout is invalid")
    archive.extractall(target, numeric_owner=True, filter="data")
PY
readonly contract_root="$work/bundle/contract"
for required in runner-boundary-template-v2.json runner-boundary-v2.json reviewer-public-key.pem reviewer-key.sha256; do
  [[ -f "$contract_root/$required" && ! -L "$contract_root/$required" ]] || { echo "missing bundle member: $required" >&2; exit 2; }
done
fingerprint="$(tr -d '\r\n' <"$contract_root/reviewer-key.sha256")"
[[ "$fingerprint" == "$4" ]] || { echo 'reviewer fingerprint differs from external pin' >&2; exit 2; }
python3 "$package_root/scripts/host/stage-wsl-jit-live-contract.py" \
  --input-boundary "$contract_root/runner-boundary-template-v2.json" \
  --output-boundary "$work/staged.json" --measurement-root "$contract_root"
python3 "$package_root/scripts/host/collect-wsl-jit-measurements.py" \
  --input "$work/staged.json" --output "$work/measured.json" --measurement-root "$contract_root"
PYTHONPATH="$package_root" python3 - "$work/measured.json" "$contract_root/runner-boundary-v2.json" <<'PY'
import pathlib, sys
from github_automation.crypto import canonicalize_jcs, parse_ijson
measured = parse_ijson(pathlib.Path(sys.argv[1]).read_bytes())
signed = parse_ijson(pathlib.Path(sys.argv[2]).read_bytes())
if "attestation" not in signed:
    raise SystemExit("signed live contract has no attestation")
signed.pop("attestation")
if canonicalize_jcs(measured) != canonicalize_jcs(signed):
    raise SystemExit("regenerated live contract differs from signed content")
PY
python3 "$package_root/scripts/host/verify-wsl-jit-readiness.py" \
  --evidence "$contract_root/runner-boundary-v2.json" --measurement-root "$contract_root" \
  --reviewer-public-key "$contract_root/reviewer-public-key.pem" --pinned-fingerprint "$4" >/dev/null
ready_sentinel=/etc/self-hosted-ci/outbound-worker.runtime-ready
if [[ -e "$ready_sentinel" ]]; then
  [[ -f "$ready_sentinel" && ! -L "$ready_sentinel" ]] || { echo 'preexisting runtime-ready sentinel is unsafe' >&2; exit 2; }
  ready_before="$(sha256sum -- "$ready_sentinel" | awk '{print $1}')"
else
  ready_before=absent
fi
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || { echo 'preexisting activation approval must be removed by its owning workflow' >&2; exit 2; }
bash "$package_root/scripts/host/provision-wsl-jit-contract.sh" --apply \
  --evidence "$contract_root/runner-boundary-v2.json" --reviewer-public-key "$contract_root/reviewer-public-key.pem" \
  --reviewer-key-fingerprint "$fingerprint" --acknowledge-host-mutation --acknowledge-dedicated-boundary >/dev/null
systemctl is-enabled --quiet self-hosted-ci-garm.service && { echo 'GARM was unexpectedly enabled' >&2; exit 2; }
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || { echo 'activation approval was unexpectedly created' >&2; exit 2; }
if [[ "$ready_before" == absent ]]; then
  [[ ! -e "$ready_sentinel" ]] || { echo 'runtime-ready sentinel was unexpectedly created' >&2; exit 2; }
else
  [[ -f "$ready_sentinel" && ! -L "$ready_sentinel" && "$(sha256sum -- "$ready_sentinel" | awk '{print $1}')" == "$ready_before" ]] || { echo 'runtime-ready sentinel changed' >&2; exit 2; }
fi
printf '%s\n' '{"status":"installed","live_contract_verified":true,"garm_enabled":false,"github_configured":false,"runtime_ready_created":false,"runner_registration_performed":false}'
'@
    }
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $payloadSha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
    $bootstrap = @'
import base64, hashlib, os, subprocess, sys, tempfile
expected = sys.argv[1]
raw = base64.b64decode(sys.stdin.buffer.read().replace(b"\r", b"").replace(b"\n", b""), validate=True)
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("payload sha256 mismatch")
fd, path = tempfile.mkstemp(prefix="self-hosted-ci-live-contract.", suffix=".sh", dir="/run")
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.chmod(path, 0o700)
    subprocess.run(["/bin/bash", "-n", path], check=True)
    subprocess.run(["/bin/bash", path, *sys.argv[2:]], check=True)
finally:
    try: os.unlink(path)
    except FileNotFoundError: pass
'@
    $bootstrapB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bootstrap))
    $payloadArguments = $(if ($CollectUnsigned) { "$packageLinuxPath $inputLinuxPath $inputSha256 /mnt/c/ProgramData/self-hosted-ci/live-contract-install/unsigned-live-contract.tar" } else { "$packageLinuxPath $inputLinuxPath $inputSha256 $ExpectedReviewerFingerprint" })
    $worker = @"
`$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
`$psi = [Diagnostics.ProcessStartInfo]::new()
`$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
`$psi.Arguments = '-d $DistroName -u root -- systemd-run --quiet --wait --pipe --collect --setenv=WSL_DISTRO_NAME=$DistroName --property=RuntimeMaxSec=600 --property=TimeoutStopSec=15 --property=KillMode=control-group --unit=self-hosted-ci-live-contract-install /usr/bin/python3 -c "import base64;exec(base64.b64decode(''$bootstrapB64''))" $payloadSha256 $payloadArguments'
`$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true
`$psi.RedirectStandardInput = `$true; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'could not start exact WSL live contract installer' }
`$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
`$process.StandardInput.Write('$payloadB64'); `$process.StandardInput.Close()
if (-not `$process.WaitForExit($TimeoutSeconds * 1000)) { try { `$process.Kill() } catch {}; throw 'WSL live contract installer timed out' }
`$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
if (`$process.ExitCode -ne 0) { throw "WSL live contract installer failed: `$(`$process.ExitCode)" }
`$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1
`$result = `$last | ConvertFrom-Json
if ('$operation' -eq 'collect-unsigned') {
    if (`$result.status -ne 'collected' -or `$result.unsigned_bundle_sha256 -notmatch '^[0-9a-f]{64}$' -or `$result.unsigned_bundle_bytes -le 0) { throw 'unsigned collection postcondition failed' }
} elseif (`$result.status -ne 'installed' -or `$result.live_contract_verified -ne `$true -or `$result.garm_enabled -ne `$false -or `$result.github_configured -ne `$false -or `$result.runtime_ready_created -ne `$false -or `$result.runner_registration_performed -ne `$false) { throw 'live contract postcondition failed' }
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
    if ($CollectUnsigned) {
        if ($result.status -ne "collected" -or $result.unsigned_bundle_sha256 -notmatch '^[0-9a-f]{64}$' -or $result.unsigned_bundle_bytes -le 0 -or -not (Test-Path -LiteralPath $UnsignedStagingPath -PathType Leaf)) { throw "collected unsigned contract postcondition failed" }
        $actualUnsignedSha = (Get-FileHash -LiteralPath $UnsignedStagingPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualUnsignedSha -ne $result.unsigned_bundle_sha256 -or (Get-Item -LiteralPath $UnsignedStagingPath).Length -ne $result.unsigned_bundle_bytes) { throw "unsigned output hash or size mismatch" }
        [void](New-Item -ItemType Directory -Path $UnsignedOutputRoot -Force)
        Set-Acl -LiteralPath $UnsignedOutputRoot -AclObject (New-ProtectedAcl $service.SID)
        $unsignedName = "unsigned-live-contract-$actualUnsignedSha.tar"
        $unsignedDestination = Join-Path $UnsignedOutputRoot $unsignedName
        if (Test-Path -LiteralPath $unsignedDestination -PathType Leaf) {
            if ((Get-FileHash -LiteralPath $unsignedDestination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $actualUnsignedSha) { throw "content-addressed unsigned output collision" }
        } else {
            Copy-Item -LiteralPath $UnsignedStagingPath -Destination $unsignedDestination
        }
    } elseif ($result.status -ne "installed" -or $result.live_contract_verified -ne $true -or $result.garm_enabled -ne $false -or $result.github_configured -ne $false -or $result.runtime_ready_created -ne $false -or $result.runner_registration_performed -ne $false) { throw "installed live contract postcondition failed" }
    $finalPassword = New-CryptographicAccountPassword
    try { Set-LocalUser -Name $service.Name -Password $finalPassword -ErrorAction Stop }
    finally { $finalPassword.Dispose() }
    $passwordApplied = $false
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    $registered = $false
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task remains after unregister" }
    Remove-Item -LiteralPath $Root -Recurse -Force
    if ($CollectUnsigned) {
        [ordered]@{ status="collected"; unsigned_bundle_path=$unsignedDestination; unsigned_bundle_sha256=$actualUnsignedSha; unsigned_bundle_bytes=[int64]$result.unsigned_bundle_bytes; provisioned=$false; garm_enabled=$false; github_configured=$false; runtime_ready_created=$false; runner_registration_performed=$false; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; staging_absent=$true } | ConvertTo-Json -Compress
    } else {
        [ordered]@{ status="installed"; live_contract_verified=$true; bundle_sha256=$inputSha256; garm_enabled=$false; github_configured=$false; runtime_ready_created=$false; runner_registration_performed=$false; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; staging_absent=$true } | ConvertTo-Json -Compress
    }
}
catch {
    $original = $_.Exception.Message; $cleanup = [Collections.Generic.List[string]]::new(); $diagnosticBundle = $null
    try { $diagnosticBundle = Save-FailureDiagnostics $original $service.SID }
    catch { $cleanup.Add("diagnostic preservation: $($_.Exception.Message)") }
    if ($registered -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop; $registered = $false }
        catch { $cleanup.Add("task cleanup: $($_.Exception.Message)") }
    }
    if ($passwordApplied) {
        $recoveryPassword = New-CryptographicAccountPassword
        try { Set-LocalUser -Name $service.Name -Password $recoveryPassword -ErrorAction Stop; $passwordApplied = $false }
        catch { $cleanup.Add("credential invalidation: $($_.Exception.Message)") }
        finally { $recoveryPassword.Dispose() }
    }
    if (Test-Path -LiteralPath $Root) { try { Remove-Item -LiteralPath $Root -Recurse -Force } catch { $cleanup.Add("staging cleanup: $($_.Exception.Message)") } }
    if ($cleanup.Count) { throw "Live contract install failed: $original. Cleanup failures: $($cleanup -join '; ')" }
    throw "Live contract install failed; task, credential, and staging cleanup were verified. Diagnostics: $diagnosticBundle. Idempotent WSL reconciliation may be rerun: $original"
}
finally { if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() } }
