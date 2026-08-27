[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [Parameter(Mandatory = $true)][string]$InstallNonce,
    [string]$ExpectedServiceAccount = "selfhosted-ci-svc",
    [string]$ExpectedDistroName = "Ubuntu-24.04-CI",
    [string]$SnapshotPath = "C:\ProgramData\self-hosted-ci\health\current.json",
    [ValidateRange(10, 3600)][int]$IntervalSeconds = 30,
    [ValidateRange(30, 86400)][int]$SnapshotLifetimeSeconds = 180,
    [switch]$Once
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-AtomicUtf8([string]$LiteralPath, [string]$Content) {
    $directory = Split-Path -Parent $LiteralPath
    $temporary = Join-Path $directory (".current-{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
    $encoding = [Text.UTF8Encoding]::new($false)
    try {
        [IO.File]::WriteAllText($temporary, $Content + "`n", $encoding)
        Move-Item -LiteralPath $temporary -Destination $LiteralPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Get-ServiceState([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { return [ordered]@{ installed = $false; status = "absent" } }
    return [ordered]@{ installed = $true; status = $service.Status.ToString().ToLowerInvariant() }
}

function Get-HostServices {
    return [ordered]@{
        sshd = Get-ServiceState "sshd"
        wsl = Get-ServiceState "WslService"
        lxss_manager = Get-ServiceState "LxssManager"
    }
}

function Get-UnobservableWslServices {
    $result = [ordered]@{}
    foreach ($name in @(
        "incus.service", "self-hosted-ci-boundary-verify.service",
        "self-hosted-ci-egress-proxy.service", "self-hosted-ci-garm.service",
        "self-hosted-ci-health-heartbeat.timer", "self-hosted-ci-network-policy.service"
    )) { $result[$name] = [ordered]@{ active = "unknown"; enabled = "unknown" } }
    return $result
}

function New-FailClosedSnapshot([DateTimeOffset]$Now, [string]$CurrentSid, [string]$ErrorMessage) {
    return [ordered]@{
        schema_version = 2
        install_nonce = $InstallNonce
        generated_at = $Now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        expires_at = $Now.AddSeconds($SnapshotLifetimeSeconds).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        producer = [ordered]@{ windows_sid = $CurrentSid; account = $ExpectedServiceAccount; distro = $ExpectedDistroName }
        host = [ordered]@{ service_identity_verified = ($CurrentSid -eq $ExpectedServiceAccountSid); services = Get-HostServices }
        distro = [ordered]@{ name = $ExpectedDistroName; platform = $null; os_id = $null; os_version = $null }
        runner = [ordered]@{ installed = $null; registered = $null; labels = @("linux", "self-hosted", "wsl-jit", "x64") }
        services = Get-UnobservableWslServices
        heartbeat = [ordered]@{ status = "not_observable"; observed_at = $null; age_seconds = $null; max_age_seconds = $SnapshotLifetimeSeconds }
        boundary = [ordered]@{ activation_approved = $null; network_policy_enabled = $null }
        eligibility = [ordered]@{ eligible_for_local_ci = $false; blocking_reasons = @("supervisor_probe_failed") }
        probe_error = $ErrorMessage
    }
}

function Get-Snapshot {
    $now = [DateTimeOffset]::UtcNow
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($currentSid -ne $ExpectedServiceAccountSid) {
        return New-FailClosedSnapshot $now $currentSid "service identity mismatch"
    }
    try {
        $visible = @(& wsl.exe --list --quiet 2>&1) | ForEach-Object { ([string]$_).Trim([char]0).Trim() } | Where-Object { $_ }
        if ($LASTEXITCODE -ne 0 -or $visible -notcontains $ExpectedDistroName) {
            throw "dedicated distro is not registered for the service identity"
        }
        $raw = @(& wsl.exe --distribution $ExpectedDistroName --user root --exec `
            /usr/local/lib/self-hosted-ci/collect-health-snapshot.py `
            --distro $ExpectedDistroName --heartbeat-max-age $SnapshotLifetimeSeconds 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "WSL collector failed with exit code $LASTEXITCODE" }
        $observed = (($raw -join "`n") | ConvertFrom-Json)
        if ([int]$observed.schema_version -ne 1 -or [string]$observed.distro.name -ne $ExpectedDistroName) {
            throw "WSL collector returned an incompatible observation"
        }
        $hostServices = Get-HostServices
        $blocking = [Collections.Generic.List[string]]::new()
        foreach ($reason in @($observed.eligibility.blocking_reasons)) { $blocking.Add([string]$reason) }
        if ($hostServices.sshd.status -ne "running") { $blocking.Add("host_service_not_running:sshd") }
        if ($hostServices.wsl.status -ne "running" -and $hostServices.lxss_manager.status -ne "running") { $blocking.Add("host_service_not_running:wsl") }
        return [ordered]@{
            schema_version = 2
            install_nonce = $InstallNonce
            generated_at = $now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            expires_at = $now.AddSeconds($SnapshotLifetimeSeconds).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            producer = [ordered]@{ windows_sid = $currentSid; account = $ExpectedServiceAccount; distro = $ExpectedDistroName }
            host = [ordered]@{ service_identity_verified = $true; services = $hostServices }
            distro = $observed.distro
            runner = $observed.runner
            services = $observed.services
            heartbeat = $observed.heartbeat
            boundary = $observed.boundary
            eligibility = [ordered]@{ eligible_for_local_ci = ([bool]$observed.eligibility.eligible_for_local_ci -and $blocking.Count -eq 0); blocking_reasons = @($blocking | Sort-Object -Unique) }
            probe_error = $null
        }
    }
    catch {
        return New-FailClosedSnapshot $now $currentSid $_.Exception.Message
    }
}

if ($env:OS -ne "Windows_NT") { throw "health supervisor requires Windows" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid expected service SID" }
if ($InstallNonce -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') { throw "invalid install nonce" }
if ($ExpectedDistroName -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "invalid distro name" }
$expectedRoot = [IO.Path]::GetFullPath("C:\ProgramData\self-hosted-ci\health")
$actualRoot = [IO.Path]::GetFullPath((Split-Path -Parent $SnapshotPath))
if ($actualRoot -ne $expectedRoot) { throw "snapshot path must remain in the protected health directory" }

do {
    $snapshot = Get-Snapshot
    Write-AtomicUtf8 $SnapshotPath ($snapshot | ConvertTo-Json -Depth 8 -Compress)
    if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
} while (-not $Once)
