[CmdletBinding()]
param(
    [string]$ExpectedDistroName = "Ubuntu-24.04-CI",
    [string]$ExpectedServiceAccountSid = $env:SELF_HOSTED_CI_EXPECTED_SID,
    [ValidateRange(1, 86400)]
    [int]$HeartbeatMaxAgeSeconds = 180
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-ServiceState {
    param([Parameter(Mandatory = $true)][string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [ordered]@{ installed = $false; status = "absent" }
    }
    return [ordered]@{ installed = $true; status = $service.Status.ToString().ToLowerInvariant() }
}

$now = [DateTimeOffset]::UtcNow
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$identityMatches = (-not [string]::IsNullOrWhiteSpace($ExpectedServiceAccountSid)) -and
    ($currentSid -eq $ExpectedServiceAccountSid)
$hostServices = [ordered]@{
    sshd = Get-ServiceState -Name "sshd"
    wsl = Get-ServiceState -Name "WslService"
    lxss_manager = Get-ServiceState -Name "LxssManager"
}

$distro = [ordered]@{
    name = $ExpectedDistroName
    observable = $false
    status = "not_observable"
    platform = $null
    os_id = $null
    os_version = $null
}
$runner = [ordered]@{
    installed = $null
    registered = $null
    labels = @("linux", "self-hosted", "wsl-jit", "x64")
}
$services = [ordered]@{}
$heartbeat = [ordered]@{
    status = "not_observable"
    observed_at = $null
    age_seconds = $null
    max_age_seconds = $HeartbeatMaxAgeSeconds
}
$boundary = [ordered]@{
    activation_approved = $null
    network_policy_enabled = $null
}
$probeError = $null

if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    try {
        $visibleDistros = @(& wsl.exe --list --quiet 2>$null) |
            ForEach-Object { $_.Trim([char]0).Trim() } |
            Where-Object { $_ }
        if ($LASTEXITCODE -eq 0 -and $visibleDistros -contains $ExpectedDistroName) {
            $probe = @'
set -euo pipefail
python3 - <<'PY'
import json
import os
import pathlib
import subprocess
import time

install = pathlib.Path("/opt/self-hosted-ci/actions-runner")
state = pathlib.Path("/var/lib/self-hosted-ci")
heartbeat = state / "health" / "heartbeat"

def service(name):
    def call(*args):
        result = subprocess.run(
            ["systemctl", *args, name], text=True, capture_output=True, check=False
        )
        return result.stdout.strip(), result.returncode
    active, active_rc = call("is-active")
    enabled, enabled_rc = call("is-enabled")
    return {
        "active": active if active_rc in (0, 3) else "unknown",
        "enabled": enabled if enabled_rc in (0, 1) else "unknown",
    }

registered_files = [".runner", ".credentials", ".credentials_rsaparams"]
registered = any((install / name).exists() for name in registered_files)
installed = (
    (install / ".self-hosted-ci-install").is_file()
    and (install / "bin" / "Runner.Listener").is_file()
    and os.access(install / "bin" / "Runner.Listener", os.X_OK)
)
heartbeat_at = heartbeat.stat().st_mtime if heartbeat.is_file() else None
with open("/etc/os-release", encoding="utf-8") as handle:
    os_release = dict(
        line.rstrip().split("=", 1) for line in handle if "=" in line
    )
kernel = pathlib.Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").strip()
print(json.dumps({
    "platform": "wsl2" if "wsl2" in kernel.lower() else "unknown",
    "distro_name": os.environ.get("WSL_DISTRO_NAME"),
    "os_id": os_release.get("ID", "").strip('"'),
    "os_version": os_release.get("VERSION_ID", "").strip('"'),
    "runner_installed": installed,
    "runner_registered": registered,
    "services": {
        name: service(name) for name in (
            "incus.service",
            "self-hosted-ci-boundary-verify.service",
            "self-hosted-ci-egress-proxy.service",
            "self-hosted-ci-garm.service",
            "self-hosted-ci-network-policy.service",
        )
    },
    "heartbeat_at_epoch": heartbeat_at,
    "activation_approved": pathlib.Path("/etc/self-hosted-ci/ACTIVATION_APPROVED").is_file(),
    "network_policy_enabled": pathlib.Path("/etc/self-hosted-ci/runner-network-v2.enabled").is_file(),
}, sort_keys=True, separators=(",", ":")))
PY
'@
            $probeBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe.Replace("`r`n", "`n")))
            $wslCommand = "printf '%s' '$probeBase64' | base64 --decode | bash"
            $probeJson = & wsl.exe --distribution $ExpectedDistroName --user root -- bash -lc $wslCommand 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "WSL health probe exited with $LASTEXITCODE"
            }
            $observed = ($probeJson -join "`n") | ConvertFrom-Json
            if ($observed.distro_name -ne $ExpectedDistroName) {
                throw "WSL_DISTRO_NAME did not match the expected dedicated distro"
            }
            $distro.observable = $true
            $distro.status = "available"
            $distro.platform = $observed.platform
            $distro.os_id = $observed.os_id
            $distro.os_version = $observed.os_version
            $runner.installed = [bool]$observed.runner_installed
            $runner.registered = [bool]$observed.runner_registered
            foreach ($property in $observed.services.PSObject.Properties) {
                $services[$property.Name] = [ordered]@{
                    active = $property.Value.active
                    enabled = $property.Value.enabled
                }
            }
            $boundary.activation_approved = [bool]$observed.activation_approved
            $boundary.network_policy_enabled = [bool]$observed.network_policy_enabled
            if ($null -eq $observed.heartbeat_at_epoch) {
                $heartbeat.status = "absent"
            }
            else {
                $heartbeatAt = [DateTimeOffset]::FromUnixTimeSeconds([int64][Math]::Floor([double]$observed.heartbeat_at_epoch))
                $age = [Math]::Max(0, [Math]::Floor(($now - $heartbeatAt).TotalSeconds))
                $heartbeat.observed_at = $heartbeatAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                $heartbeat.age_seconds = [int64]$age
                $heartbeat.status = if ($age -le $HeartbeatMaxAgeSeconds) { "fresh" } else { "stale" }
            }
        }
    }
    catch {
        $probeError = $_.Exception.Message
        $distro.status = "probe_failed"
    }
}
else {
    $distro.status = "wsl_unavailable"
}

$blockingReasons = [Collections.Generic.List[string]]::new()
if (-not $identityMatches) { $blockingReasons.Add("service_identity_not_verified") }
if (-not $distro.observable) { $blockingReasons.Add("dedicated_distro_not_observable") }
if ($distro.platform -ne "wsl2" -or $distro.os_id -ne "ubuntu" -or $distro.os_version -ne "24.04") {
    $blockingReasons.Add("platform_not_verified")
}
if ($runner.installed -ne $true) { $blockingReasons.Add("runner_not_installed") }
if ($runner.registered -ne $false) { $blockingReasons.Add("runner_registration_not_clean") }
if ($heartbeat.status -ne "fresh") { $blockingReasons.Add("heartbeat_not_fresh") }
if ($boundary.activation_approved -ne $true) { $blockingReasons.Add("activation_not_approved") }
if ($boundary.network_policy_enabled -ne $true) { $blockingReasons.Add("network_policy_not_enabled") }
foreach ($requiredService in @(
    "incus.service",
    "self-hosted-ci-boundary-verify.service",
    "self-hosted-ci-egress-proxy.service",
    "self-hosted-ci-garm.service",
    "self-hosted-ci-network-policy.service"
)) {
    if (-not $services.Contains($requiredService) -or $services[$requiredService].active -ne "active") {
        $blockingReasons.Add("service_not_active:$requiredService")
    }
}

$result = [ordered]@{
    schema_version = 1
    checked_at = $now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    mode = "read_only"
    host = [ordered]@{
        reachable = $true
        current_sid = $currentSid
        expected_service_account_sid_configured = -not [string]::IsNullOrWhiteSpace($ExpectedServiceAccountSid)
        service_identity_verified = $identityMatches
        services = $hostServices
    }
    distro = $distro
    runner = $runner
    services = $services
    heartbeat = $heartbeat
    boundary = $boundary
    eligibility = [ordered]@{
        eligible_for_local_ci = ($blockingReasons.Count -eq 0)
        blocking_reasons = @($blockingReasons)
    }
    probe_error = $probeError
}

$result | ConvertTo-Json -Depth 8 -Compress
