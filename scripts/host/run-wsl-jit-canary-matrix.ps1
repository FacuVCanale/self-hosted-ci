[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$BundleRelativePath = "artifacts/canary/canary-runtime-bundle.tar",
    [Parameter(Mandatory = $true)][string]$ExpectedBundleSha256,
    [Parameter(Mandatory = $true)][long]$ExpectedBundleBytes,
    [Parameter(Mandatory = $true)][string]$ExpectedReviewerFingerprint,
    [Parameter(Mandatory = $true)][string]$ExpectedCanaryNonce,
    [int]$TimeoutSeconds = 5400,
    [switch]$Apply,
    [switch]$AcknowledgeCanaryGitHubContact,
    [switch]$AcknowledgeTransientRunnerRegistration,
    [switch]$AcknowledgeDistroRestart,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Run-WSL-JIT-Canary-Matrix"
$PackageRoot = "C:\ProgramData\self-hosted-ci\package"
$Root = "C:\ProgramData\self-hosted-ci\canary-matrix"
$WorkerPath = Join-Path $Root "worker.ps1"
$ResultPath = Join-Path $Root "result.json"
$StdoutPath = Join-Path $Root "worker.stdout.log"
$StderrPath = Join-Path $Root "worker.stderr.log"
$DiagnosticsRoot = "C:\ProgramData\self-hosted-ci\diagnostics\canary-matrix\v1"
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
        $definition.Principal.LogonType = 1
        $definition.Principal.RunLevel = 0
        $definition.Settings.Enabled = $true
        $definition.Settings.AllowDemandStart = $true
        $definition.Settings.StartWhenAvailable = $false
        $definition.Settings.ExecutionTimeLimit = "PT95M"
        $definition.Settings.MultipleInstances = 2
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

function Write-Worker([string]$Phase) {
    if ($Phase -notin @("initial", "resume")) { throw "invalid worker phase" }
    $linuxPayload = @'
set -euo pipefail
umask 077
readonly phase="$1" expected_sha="$2" expected_bytes="$3" reviewer_fingerprint="$4" nonce="$5"
readonly input=/run/self-hosted-ci-canary-input.tar work=/run/self-hosted-ci-canary-input
cleanup(){ rm -rf -- "$work" "$input"; }
trap cleanup EXIT HUP INT TERM
[[ "$(id -u)" == 0 && "${WSL_DISTRO_NAME:-}" == 'Ubuntu-24.04-CI' ]] || { echo 'unexpected canary WSL identity' >&2; exit 2; }
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED && ! -e /etc/self-hosted-ci/outbound-worker.runtime-ready ]] || { echo 'production activation is present' >&2; exit 2; }
cat >"$input"
[[ "$(stat -c %s -- "$input")" == "$expected_bytes" ]] || { echo 'canary bundle byte count mismatch' >&2; exit 2; }
[[ "$(sha256sum -- "$input" | awk '{print $1}')" == "$expected_sha" ]] || { echo 'canary bundle sha256 mismatch' >&2; exit 2; }
install -d -o root -g root -m 0700 "$work"
python3 - "$input" "$work" <<'PY'
import pathlib, sys, tarfile
source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
required = {"canary/authorization.json", "canary/runtime-config.json"}
with tarfile.open(source, "r:") as archive:
    members = archive.getmembers()
    names = {m.name for m in members}
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit("unsafe canary bundle member")
        if member.uid != 0 or member.gid != 0 or member.mode & 0o7077:
            raise SystemExit("canary bundle ownership or mode is unsafe")
    if {pathlib.PurePosixPath(name).parts[0] for name in names if pathlib.PurePosixPath(name).parts} != {"canary"} or not required.issubset(names):
        raise SystemExit("canary bundle layout is invalid")
    archive.extractall(target, numeric_owner=True, filter="data")
PY
[[ -d /etc/self-hosted-ci && ! -L /etc/self-hosted-ci ]] || { echo 'GARM configuration root is absent or unsafe' >&2; exit 2; }
[[ -d /etc/self-hosted-ci/garm && ! -L /etc/self-hosted-ci/garm ]] || { echo 'GARM configuration directory is absent or unsafe' >&2; exit 2; }
install -d -o root -g garm-manager -m 0751 /etc/self-hosted-ci
install -d -o root -g garm-manager -m 0750 /etc/self-hosted-ci/garm
[[ "$(stat -c '%U:%G:%a' /etc/self-hosted-ci)" == root:garm-manager:751 ]] || { echo 'GARM configuration root metadata drifted' >&2; exit 2; }
[[ "$(stat -c '%U:%G:%a' /etc/self-hosted-ci/garm)" == root:garm-manager:750 ]] || { echo 'GARM configuration directory metadata drifted' >&2; exit 2; }
[[ -f /etc/self-hosted-ci/garm/config.toml && ! -L /etc/self-hosted-ci/garm/config.toml ]] || { echo 'GARM configuration is absent or unsafe' >&2; exit 2; }
[[ "$(stat -c '%U:%G:%a' /etc/self-hosted-ci/garm/config.toml)" == root:garm-manager:640 ]] || { echo 'GARM configuration metadata drifted' >&2; exit 2; }
runuser -u garm-manager -- test -r /etc/self-hosted-ci/garm/config.toml || { echo 'GARM configuration is unreadable by garm-manager' >&2; exit 2; }
[[ -d /var/lib/self-hosted-ci && ! -L /var/lib/self-hosted-ci ]] || { echo 'GARM state root is absent or unsafe' >&2; exit 2; }
[[ -d /var/lib/self-hosted-ci/garm && ! -L /var/lib/self-hosted-ci/garm ]] || { echo 'GARM runtime directory is absent or unsafe' >&2; exit 2; }
install -d -o root -g garm-manager -m 0710 /var/lib/self-hosted-ci
install -d -o garm-manager -g garm-manager -m 0700 /var/lib/self-hosted-ci/garm
[[ "$(stat -c '%U:%G:%a' /var/lib/self-hosted-ci)" == root:garm-manager:710 ]] || { echo 'GARM state root metadata drifted' >&2; exit 2; }
[[ "$(stat -c '%U:%G:%a' /var/lib/self-hosted-ci/garm)" == garm-manager:garm-manager:700 ]] || { echo 'GARM runtime directory metadata drifted' >&2; exit 2; }
runuser -u garm-manager -- test -x /var/lib/self-hosted-ci || { echo 'GARM state root is not traversable by garm-manager' >&2; exit 2; }
runuser -u garm-manager -- test -r /var/lib/self-hosted-ci/garm || { echo 'GARM runtime directory is unreadable by garm-manager' >&2; exit 2; }
runuser -u garm-manager -- test -w /var/lib/self-hosted-ci/garm || { echo 'GARM runtime directory is not writable by garm-manager' >&2; exit 2; }
runuser -u garm-manager -- test -x /var/lib/self-hosted-ci/garm || { echo 'GARM runtime directory is not traversable by garm-manager' >&2; exit 2; }
install -o root -g root -m 0600 "$work/canary/authorization.json" /etc/self-hosted-ci/canary-authorization.json
install -o root -g root -m 0600 "$work/canary/runtime-config.json" /etc/self-hosted-ci/canary-runtime.json
/usr/local/lib/self-hosted-ci/verify-jit-canary-authorization.py \
  --authorization /etc/self-hosted-ci/canary-authorization.json \
  --reviewer-public-key /etc/self-hosted-ci/bootstrap/reviewer-public-key.pem \
  --pinned-fingerprint "$reviewer_fingerprint" >"$work/verified.json"
python3 - "$work/verified.json" "$nonce" <<'PY'
import json, pathlib, sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("authorized") is not True or value.get("nonce") != sys.argv[2]:
    raise SystemExit("canary nonce or authorization verification mismatch")
PY
args=(execute --config /etc/self-hosted-ci/canary-runtime.json --authorization /etc/self-hosted-ci/canary-authorization.json)
export PYTHONPATH=/usr/local/lib/self-hosted-ci
set +e
/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py "${args[@]}"
status=$?
set -e
if [[ "$status" == 75 && "$phase" == initial ]]; then
  printf '{"status":"reboot-checkpoint","nonce":"%s"}\n' "$nonce"
  exit 75
fi
[[ "$status" == 0 ]] || exit "$status"
/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py production-fence
printf '{"status":"terminal","nonce":"%s","runtime_empty":true,"production_activation_changed":false,"outbound_worker_started":false}\n' "$nonce"
'@
    $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxPayload))
    $escapedBundle = $bundlePath.Replace("'", "''")
    $worker = @"
`$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
`$psi = [Diagnostics.ProcessStartInfo]::new()
`$psi.FileName = '$env:SystemRoot\System32\wsl.exe'
`$command = "printf '%s' '$payloadB64' | base64 -d >/run/self-hosted-ci-canary-worker.sh; chmod 0700 /run/self-hosted-ci-canary-worker.sh; exec bash /run/self-hosted-ci-canary-worker.sh '$Phase' '$bundleSha256' '$bundleLength' '$ExpectedReviewerFingerprint' '$ExpectedCanaryNonce'"
`$psi.Arguments = '--distribution $DistroName --user root -- bash -lc "' + `$command.Replace('"','\"') + '"'
`$psi.UseShellExecute = `$false
`$psi.RedirectStandardInput = `$true
`$psi.RedirectStandardOutput = `$true
`$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'failed to start WSL canary worker' }
`$input = [IO.File]::OpenRead('$escapedBundle')
try { `$input.CopyTo(`$process.StandardInput.BaseStream); `$process.StandardInput.Close() } finally { `$input.Dispose() }
`$stdout = `$process.StandardOutput.ReadToEnd(); `$stderr = `$process.StandardError.ReadToEnd()
`$process.WaitForExit()
`$workerExitCode = `$process.ExitCode
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
`$last = @(`$stdout -split "`r?`n" | Where-Object { `$_.Trim() })[-1]
try { `$result = `$last | ConvertFrom-Json -ErrorAction Stop } catch { `$result = [ordered]@{status='failed';exit_code=`$workerExitCode} }
[IO.File]::WriteAllText('$ResultPath', (`$result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
if (`$workerExitCode -eq 75 -and '$Phase' -eq 'initial') {
    if (`$result.status -ne 'reboot-checkpoint' -or `$result.nonce -ne '$ExpectedCanaryNonce') { throw 'reboot worker exit was not bound to the exact durable checkpoint' }
    & '$env:SystemRoot\System32\wsl.exe' --terminate '$DistroName'
    if (`$LASTEXITCODE -ne 0) { throw 'service identity failed to terminate the dedicated WSL distro at reboot checkpoint' }
    `$shutdownDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        `$runningDistros = @(& '$env:SystemRoot\System32\wsl.exe' --list --running --quiet | ForEach-Object { (`$_ -replace [char]0, '').Trim() })
        if (`$LASTEXITCODE -ne 0) { throw 'service identity failed to verify dedicated WSL distro shutdown' }
        if (`$runningDistros -notcontains '$DistroName') { break }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt `$shutdownDeadline)
    if (`$runningDistros -contains '$DistroName') { throw 'dedicated WSL distro did not reach the stopped state' }
}
exit `$workerExitCode
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
}

function Wait-OneShot([int]$WaitSeconds = $TimeoutSeconds) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
    $before = Invoke-SchedulerObservation "read task info before start" { Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop }
    Start-ScheduledTask -TaskName $TaskName
    $runObserved = $false
    do {
        Start-Sleep -Seconds 2
        $task = Invoke-SchedulerObservation "read task state while waiting" { Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
        $info = Invoke-SchedulerObservation "read task info while waiting" { Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop }
        if ($info.LastRunTime -gt $before.LastRunTime) { $runObserved = $true }
        if ($runObserved -and $task.State -ne "Running") { return [int64]$info.LastTaskResult }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "canary one-shot task timed out"
}

function Invoke-SchedulerObservation([string]$Operation, [scriptblock]$Action) {
    $failures = [Collections.Generic.List[string]]::new()
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try { return & $Action }
        catch {
            $exception = $_.Exception
            $hresult = "0x{0:X8}" -f ([uint32]$exception.HResult)
            $failures.Add("attempt=$attempt type=$($exception.GetType().FullName) hresult=$hresult message=$($exception.Message)")
            if ($attempt -eq 5) {
                throw "$Operation failed after bounded read-only retries: $($failures -join ' | ')"
            }
            Start-Sleep -Milliseconds (200 * $attempt)
        }
    }
}

function Stop-And-Wait-OneShot {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { return }
    if ($task.State -eq "Running") {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        } while ($task.State -eq "Running" -and [DateTimeOffset]::UtcNow -lt $deadline)
        if ($task.State -eq "Running") {
            & "$env:SystemRoot\System32\wsl.exe" --terminate $DistroName
            if ($LASTEXITCODE -ne 0) { throw "failed to terminate the exact dedicated WSL distro after task stop timeout" }
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 500
                $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            } while ($task.State -eq "Running" -and [DateTimeOffset]::UtcNow -lt $deadline)
        }
        if ($task.State -eq "Running") { throw "scheduled task remained running after stop and exact WSL termination" }
    }
}

function Write-CleanupWorker {
    $cleanupPayload = @'
import json, pathlib, shutil, subprocess, sys
sys.path.insert(0, "/usr/local/lib/self-hosted-ci")
from github_automation.canary_worker import CANARY_UNITS, CANARY_SENTINEL, CANARY_SECRET_ROOT, CanaryRuntime, CanaryStateStore, STATE_ROOT, load_live_canary_driver, read_root_json
config=read_root_json(pathlib.Path("/etc/self-hosted-ci/canary-runtime.json"))
authorization=read_root_json(pathlib.Path("/etc/self-hosted-ci/canary-authorization.json"))
runtime=CanaryRuntime(config, authorization)
driver=load_live_canary_driver(config, authorization)
subprocess.run(["systemctl","stop","self-hosted-ci-canary-broker.service"],check=False)
for unit in CANARY_UNITS[:-1]:
    subprocess.run(["systemctl","start",unit],check=True)
recovered=list(driver.recover_all())
empty=driver.prove_runtime_empty()
expected={"scale_sets":0,"instances":0,"runners":0,"registrations":0}
if empty != expected:
    raise SystemExit("canary cleanup runtime inventory is not empty")
runtime.quarantine_after_failure(None)
store=CanaryStateStore(STATE_ROOT, authorization["nonce"])
state=store.load()
if state is not None and not (state.get("state")=="terminal" and state.get("runtime_empty") is True):
    store.transition("failed-quarantined-clean", current_scenario=None, runtime_empty=True, recovered_allocations=recovered)
for unit in CANARY_UNITS:
    observed=subprocess.run(["systemctl","is-active",unit],capture_output=True,text=True,check=False)
    if observed.returncode == 0:
        raise SystemExit("canary unit remains active after cleanup")
quarantine=subprocess.run(["systemctl","is-active","self-hosted-ci-network-quarantine.service"],capture_output=True,text=True,check=False)
if quarantine.returncode != 0 or quarantine.stdout.strip() != "active":
    raise SystemExit("network quarantine is not active after cleanup")
if CANARY_SENTINEL.exists() or CANARY_SECRET_ROOT.exists():
    raise SystemExit("canary approval or secret staging survived cleanup")
print(json.dumps({"status":"cleanup-quarantined","nonce":authorization["nonce"],"runtime_empty":True,"network_quarantine":"active","canary_units_active":0,"recovered_allocations":recovered},sort_keys=True,separators=(",",":")))
'@
    $cleanupB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cleanupPayload))
    $worker = @"
`$ErrorActionPreference = 'Stop'
`$psi = [Diagnostics.ProcessStartInfo]::new()
`$psi.FileName = '$env:SystemRoot\System32\wsl.exe'
`$command = "printf '%s' '$cleanupB64' | base64 -d >/run/self-hosted-ci-canary-cleanup.py; chmod 0700 /run/self-hosted-ci-canary-cleanup.py; trap 'rm -f -- /run/self-hosted-ci-canary-cleanup.py /run/self-hosted-ci-canary-worker.sh' EXIT; python3 /run/self-hosted-ci-canary-cleanup.py"
`$psi.Arguments = '--distribution $DistroName --user root -- bash -lc "' + `$command.Replace('"','\"') + '"'
`$psi.UseShellExecute = `$false; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
`$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
if (-not `$process.Start()) { throw 'failed to start WSL canary cleanup worker' }
`$stdout = `$process.StandardOutput.ReadToEnd(); `$stderr = `$process.StandardError.ReadToEnd(); `$process.WaitForExit()
[IO.File]::WriteAllText('$StdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
[IO.File]::WriteAllText('$StderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
`$last = @(`$stdout -split "`r?`n" | Where-Object { `$_.Trim() })[-1]
try { `$result = `$last | ConvertFrom-Json -ErrorAction Stop } catch { `$result = [ordered]@{status='cleanup-failed';exit_code=`$process.ExitCode} }
[IO.File]::WriteAllText('$ResultPath', (`$result | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
exit `$process.ExitCode
"@
    [IO.File]::WriteAllText($WorkerPath, $worker, [Text.UTF8Encoding]::new($false))
}

function Write-SanitizedDiagnosticCopy([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    if ($item.Length -gt 1048576) { throw "diagnostic source exceeds the one-megabyte safety bound" }
    $content = [IO.File]::ReadAllText($Source, [Text.Encoding]::UTF8)
    $content = [Text.RegularExpressions.Regex]::Replace(
        $content,
        '(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----',
        '[REDACTED_PRIVATE_KEY]'
    )
    $content = [Text.RegularExpressions.Regex]::Replace(
        $content,
        '(?i)("?(?:password|token|secret|private_key)"?\s*[:=]\s*)[^\s,;}]+',
        '$1[REDACTED]'
    )
    [IO.File]::WriteAllText($Destination, $content, [Text.UTF8Encoding]::new($false))
}

function Save-FailureDiagnostics([string]$Failure, [Security.Principal.SecurityIdentifier]$ServiceSid, [string]$Phase, [Management.Automation.ErrorRecord]$ErrorRecord) {
    $bundle = Join-Path $DiagnosticsRoot ([DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + [Guid]::NewGuid())
    [void](New-Item -ItemType Directory -Path $bundle -Force)
    Set-Acl -LiteralPath $bundle -AclObject (New-ProtectedAcl $ServiceSid)
    foreach ($entry in @(@{p=$StdoutPath;n="worker.stdout.log"}, @{p=$StderrPath;n="worker.stderr.log"}, @{p=$ResultPath;n="result.json"})) {
        Write-SanitizedDiagnosticCopy $entry.p (Join-Path $bundle $entry.n)
    }
    $exceptionType = $null; $hresult = $null; $scriptName = $null; $scriptLine = $null; $position = $null
    if ($ErrorRecord) {
        $exceptionType = $ErrorRecord.Exception.GetType().FullName
        $hresult = "0x{0:X8}" -f ([uint32]$ErrorRecord.Exception.HResult)
        $scriptName = $ErrorRecord.InvocationInfo.ScriptName
        $scriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        $position = $ErrorRecord.InvocationInfo.PositionMessage
    }
    $safe = [ordered]@{observed_at=[DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");task_name=$TaskName;service_sid=$ServiceSid.Value;distro=$DistroName;bundle_sha256=$bundleSha256;bundle_bytes=$bundleLength;nonce=$ExpectedCanaryNonce;phase=$Phase;failure=$Failure;exception_type=$exceptionType;hresult=$hresult;script_name=$scriptName;script_line=$scriptLine;position=$position;production_activation_changed=$false;outbound_worker_started=$false}
    [IO.File]::WriteAllText((Join-Path $bundle "failure.json"), ($safe | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $bundle
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "canary wrapper requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ($ExpectedBundleSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedReviewerFingerprint -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedCanaryNonce -cnotmatch '^[0-9a-f]{32}$') { throw "hash fingerprint and nonce pins must be exact lowercase hex" }
if ($ExpectedBundleBytes -le 0 -or $TimeoutSeconds -ne 5400) { throw "bundle bytes must be positive and TimeoutSeconds is pinned to 5400" }
if ($BundleRelativePath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or $BundleRelativePath.Contains('..')) { throw "bundle path must be safe and package-relative" }
$bundlePath = [IO.Path]::GetFullPath((Join-Path $PackageRoot $BundleRelativePath))
if (-not (Test-Path -LiteralPath $bundlePath -PathType Leaf)) { throw "canary bundle is absent" }
Assert-NoReparsePath $bundlePath $PackageRoot
$bundleLength = (Get-Item -LiteralPath $bundlePath -Force).Length
$bundleSha256 = (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($bundleLength -ne $ExpectedBundleBytes -or $bundleSha256 -cne $ExpectedBundleSha256) { throw "canary bundle differs from exact external pins" }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if (-not $service.Enabled -or $service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity mismatch" }
Assert-NonAdmin $service

[ordered]@{mode=$(if($Apply){"apply"}else{"plan"});apply_requested=[bool]$Apply;task_name=$TaskName;service_sid=$service.SID.Value;distro=$DistroName;bundle_sha256=$bundleSha256;bundle_bytes=$bundleLength;reviewer_fingerprint=$ExpectedReviewerFingerprint;nonce=$ExpectedCanaryNonce;max_allocations=6;max_concurrency=1;production_activation_authorized=$false;required_check_authorized=$false;outbound_worker_authorized=$false;distro_restart_only_after_durable_checkpoint=$true;transport="Windows-to-WSL-stdin-no-drvfs";no_host_changes=(-not [bool]$Apply)} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not ($AcknowledgeCanaryGitHubContact -and $AcknowledgeTransientRunnerRegistration -and $AcknowledgeDistroRestart -and $AcknowledgeOneTimePasswordRotation)) { throw "Apply requires all four explicit canary acknowledgements" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "canary one-shot task already exists" }
if (Test-Path -LiteralPath $Root) { throw "canary staging root already exists" }

$temporaryPassword = $null; $passwordApplied = $false; $registered = $false; $phase = "initial"
$successReceipt = $null; $operationFailure = $null; $operationDiagnostics = $null
try {
    [void](New-Item -ItemType Directory -Path $Root)
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $temporaryPassword = New-CryptographicAccountPassword
    Set-LocalUser -Name $ServiceAccount -Password $temporaryPassword -ErrorAction Stop
    $passwordApplied = $true
    Write-Worker "initial"
    [void](Register-OneShot "$env:COMPUTERNAME\$ServiceAccount" $temporaryPassword)
    $registered = $true
    $result = Wait-OneShot
    if ($result -eq 75) {
        $checkpoint = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($checkpoint.status -ne "reboot-checkpoint" -or $checkpoint.nonce -ne $ExpectedCanaryNonce) { throw "reboot exit was not bound to the durable canary checkpoint" }
        $phase = "resume"
        Write-Worker "resume"
        $result = Wait-OneShot
    }
    if ($result -ne 0) { throw "canary matrix task failed (result=$result)" }
    $terminal = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($terminal.status -ne "terminal" -or $terminal.nonce -ne $ExpectedCanaryNonce -or $terminal.runtime_empty -ne $true -or $terminal.production_activation_changed -ne $false -or $terminal.outbound_worker_started -ne $false) { throw "canary terminal receipt is not exact" }
    $successReceipt = [ordered]@{status="terminal";nonce=$ExpectedCanaryNonce;scenarios=@("success","failure","cancel","timeout","force-cancel","reboot");runtime_empty=$true;distro_restarted=($phase -eq "resume");one_shot_task_absent=$true;stored_task_credential_invalidated=$true;staging_absent=$true;production_activation_changed=$false;required_check_changed=$false;outbound_worker_started=$false}
}
catch {
    $operationFailure = $_.Exception.Message
    $operationDiagnostics = Save-FailureDiagnostics $operationFailure $service.SID $phase $_
}
finally {
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    if ($registered -and $passwordApplied) {
        try {
            Stop-And-Wait-OneShot
            Write-CleanupWorker
            $cleanupResult = Wait-OneShot 300
            if ($cleanupResult -ne 0) { throw "WSL canary cleanup task failed (result=$cleanupResult)" }
            $cleanupReceipt = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -ErrorAction Stop
            if ($cleanupReceipt.status -ne "cleanup-quarantined" -or $cleanupReceipt.nonce -ne $ExpectedCanaryNonce -or $cleanupReceipt.runtime_empty -ne $true -or $cleanupReceipt.network_quarantine -ne "active" -or $cleanupReceipt.canary_units_active -ne 0) { throw "WSL cleanup and quarantine receipt is not exact" }
            Stop-And-Wait-OneShot
        }
        catch { $cleanupFailures.Add("WSL lane cleanup: " + $_.Exception.Message) }
    }
    if ($registered) {
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "scheduled task remains registered" }
            $registered = $false
        }
        catch { $cleanupFailures.Add("task cleanup: " + $_.Exception.Message) }
    }
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "scheduled task remains registered" }
    }
    catch { $cleanupFailures.Add("task absence verification: " + $_.Exception.Message) }
    if ($passwordApplied) {
        $replacement = New-CryptographicAccountPassword
        try {
            Set-LocalUser -Name $ServiceAccount -Password $replacement -ErrorAction Stop
            $rotatedService = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
            if (-not $rotatedService.Enabled -or $rotatedService.SID.Value -ne $ExpectedServiceAccountSid) { throw "service identity drifted during final credential rotation" }
            Assert-NonAdmin $rotatedService
            $passwordApplied = $false
        }
        catch { $cleanupFailures.Add("credential cleanup: " + $_.Exception.Message) }
        finally { $replacement = $null }
    }
    $temporaryPassword = $null
    if ($cleanupFailures.Count -gt 0 -and -not $operationDiagnostics) {
        try { $operationDiagnostics = Save-FailureDiagnostics ($cleanupFailures -join "; ") $service.SID $phase $null }
        catch { $cleanupFailures.Add("diagnostic preservation: " + $_.Exception.Message) }
    }
    if (Test-Path -LiteralPath $Root) {
        try {
            Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $Root) { throw "staging root remains present" }
        }
        catch { $cleanupFailures.Add("staging cleanup: " + $_.Exception.Message) }
    }
    if ($cleanupFailures.Count -gt 0) {
        if (-not $operationDiagnostics) {
            try { $operationDiagnostics = Save-FailureDiagnostics ($cleanupFailures -join "; ") $service.SID $phase $null }
            catch { $cleanupFailures.Add("diagnostic preservation: " + $_.Exception.Message) }
        }
        throw "JIT canary cleanup postconditions failed; diagnostics: $operationDiagnostics; failures: $($cleanupFailures -join '; ')"
    }
}

if ($operationFailure) { throw "JIT canary matrix failed; diagnostics preserved at $operationDiagnostics. Original error: $operationFailure" }
if (-not $successReceipt -or $registered -or $passwordApplied -or (Test-Path -LiteralPath $Root) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { throw "JIT canary success postconditions are not exact" }
$successReceipt | ConvertTo-Json -Compress
