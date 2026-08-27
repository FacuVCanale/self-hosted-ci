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
    [ValidateSet("none", "host-after-reader", "worker-before-wsl", "payload-after-install", "payload-evidence-failure")][string]$FailureInjection = "none",
    [switch]$AcknowledgeFailureInjection
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "SelfHostedCI-Install-Health-Prerequisites"
$PersistentTaskName = "SelfHostedCI-Health-Supervisor"
$Root = "C:\ProgramData\self-hosted-ci\health-bootstrap"
$WorkerPath = Join-Path $Root "install-worker.ps1"
$ResultPath = Join-Path $Root "install-result.json"
$WorkerStdoutPath = Join-Path $Root "worker.stdout.log"
$WorkerStderrPath = Join-Path $Root "worker.stderr.log"
$WorkerErrorPath = Join-Path $Root "worker-error.json"
$WorkerContextPath = Join-Path $Root "worker-context.json"
$ExpectedDistroBasePath = "C:\ProgramData\self-hosted-ci\wsl"
$EvidenceRoot = "C:\ProgramData\self-hosted-ci\diagnostics\health-prerequisites"
$AttemptId = [guid]::NewGuid().ToString("D")
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

function New-AdminOnlyAcl([bool]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admins)
    foreach ($sid in @($system, $admins)) {
        if ($Directory) {
            $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
        else { [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)) }
    }
    return $acl
}

function Assert-ExactManagedReaderProfile([string]$Profile) {
    $expected = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    if ([IO.Path]::GetFullPath($Profile) -ne $expected) { throw "reader profile path is not canonical" }
    Assert-NoReparsePath $Profile
    Assert-NoReparseDescendants $Profile
    $ssh = Join-Path $Profile ".ssh"; $key = Join-Path $ssh "authorized_keys"
    foreach ($path in @($ssh, $key)) { if (-not (Test-Path -LiteralPath $path)) { throw "expected managed reader artifact is absent: $path" } }
    $allowed = @([IO.Path]::GetFullPath($ssh), [IO.Path]::GetFullPath($key))
    foreach ($item in @(Get-ChildItem -LiteralPath $Profile -Force -Recurse -ErrorAction Stop)) {
        if ([IO.Path]::GetFullPath($item.FullName) -notin $allowed) { throw "unexpected reader profile artifact blocks rollback: $($item.FullName)" }
    }
}

function Remove-ExactManagedReaderProfile([string]$Profile) {
    Assert-ExactManagedReaderProfile $Profile
    $ssh = Join-Path $Profile ".ssh"; $key = Join-Path $ssh "authorized_keys"
    foreach ($entry in @(@($key, $false), @($ssh, $true), @($Profile, $true))) {
        Set-Acl -LiteralPath $entry[0] -AclObject (New-AdminOnlyAcl ([bool]$entry[1]))
    }
    Remove-Item -LiteralPath $Profile -Recurse -Force
    if (Test-Path -LiteralPath $Profile) { throw "reader profile remains after exact rollback" }
}

function Save-FailureEvidence([string]$OriginalMessage, [object]$Task, [object]$TaskInfo) {
    Assert-NoReparsePath $EvidenceRoot $true
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { [void](New-Item -ItemType Directory -Path $EvidenceRoot -Force) }
    Set-Acl -LiteralPath $EvidenceRoot -AclObject (New-AdminOnlyAcl $true)
    $attempt = Join-Path $EvidenceRoot $AttemptId
    [void](New-Item -ItemType Directory -Path $attempt)
    Set-Acl -LiteralPath $attempt -AclObject (New-AdminOnlyAcl $true)
    foreach ($source in @($WorkerStdoutPath, $WorkerStderrPath, $WorkerErrorPath, $WorkerContextPath, $ResultPath)) {
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            $destination = Join-Path $attempt ([IO.Path]::GetFileName($source))
            Copy-Item -LiteralPath $source -Destination $destination
            Set-Acl -LiteralPath $destination -AclObject (New-AdminOnlyAcl $false)
        }
    }
    $summary = [ordered]@{
        status = "failed"; attempt_id = $AttemptId; original_message = $OriginalMessage
        task_state = $(if ($null -eq $Task) { $null } else { [string]$Task.State })
        last_task_result = $(if ($null -eq $TaskInfo) { $null } else { [uint32]$TaskInfo.LastTaskResult })
        last_run_time = $(if ($null -eq $TaskInfo) { $null } else { ([DateTimeOffset]$TaskInfo.LastRunTime).ToString("o") })
        captured_files = @((Get-ChildItem -LiteralPath $attempt -File | Select-Object -ExpandProperty Name))
    }
    $summaryPath = Join-Path $attempt "task-summary.json"
    [IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    Set-Acl -LiteralPath $summaryPath -AclObject (New-AdminOnlyAcl $false)
    return $attempt
}

function Set-ExactAuthorizedKey([object]$Reader, [string]$Key) {
    if ($Key -notmatch '^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?$') { throw "authorized key must be one supported public key line" }
    $profile = Join-Path "C:\Users" $Reader.Name
    $expectedProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    if ([IO.Path]::GetFullPath($profile) -ne $expectedProfile) { throw "reader profile path is not canonical" }
    $ssh = Join-Path $profile ".ssh"
    $file = Join-Path $ssh "authorized_keys"
    Assert-NoReparsePath "C:\Users"
    Assert-NoReparsePath $profile $true
    foreach ($path in @($profile, $ssh)) {
        if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path) }
        Assert-NoReparsePath $path
    }
    Assert-NoReparsePath $file $true
    [IO.File]::WriteAllText($file, $Key.Trim() + "`n", [Text.UTF8Encoding]::new($false))
    Assert-NoReparsePath $file
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
        $definition.Settings.AllowDemandStart = $true
        $definition.Settings.DisallowStartIfOnBatteries = $false
        $definition.Settings.StopIfGoingOnBatteries = $false
        $definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
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
$orphanReaderProfile = $false
if ($null -ne $existingReader) {
    Assert-NonAdmin $existingReader "health reader"
    if ($existingReader.Enabled -or [string]$existingReader.Description -ne $ReaderDescription) { throw "preexisting health reader must be disabled and have exact managed provenance" }
    $existingProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    Assert-NoReparsePath $existingProfile
    Assert-NoReparseDescendants $existingProfile
    $existingKey = Join-Path $existingProfile ".ssh\authorized_keys"
    Assert-NoReparsePath $existingKey
    if ((Get-Content -LiteralPath $existingKey -Raw).Trim() -ne $AuthorizedKey.Trim()) { throw "preexisting health reader authorized key is not exact" }
}
else {
    $existingProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
    if (Test-Path -LiteralPath $existingProfile) {
        Assert-ExactManagedReaderProfile $existingProfile
        $existingKey = Join-Path $existingProfile ".ssh\authorized_keys"
        if ((Get-Content -LiteralPath $existingKey -Raw).Trim() -ne $AuthorizedKey.Trim()) { throw "orphan health reader authorized key is not exact" }
        $orphanReaderProfile = $true
    }
}
$payload = Render-Payload
$payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
$payloadSha = ([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
[ordered]@{ mode="plan"; apply_requested=[bool]$Apply; task_name=$TaskName; service_sid=$service.SID.Value; reader_action=$(if ($orphanReaderProfile) { "recover-orphan-create-disabled" } elseif ($null -eq $existingReader) { "create-disabled" } else { "verify-disabled" }); distro=$DistroName; payload_sha256=$payloadSha; persistent_task_must_be_absent=$true; runner_registration="not_performed"; external_calls="not_performed" } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeCreateDisabledReader -or -not $AcknowledgeOneTimePasswordRotation) { throw "Apply requires both acknowledgements" }
if ($FailureInjection -ne "none" -and -not $AcknowledgeFailureInjection) { throw "failure injection requires its explicit acknowledgement" }
if (Get-ScheduledTask -TaskName $PersistentTaskName -ErrorAction SilentlyContinue) { throw "persistent supervisor must not exist; bootstrap must run first" }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task already exists" }
$expectedStagingRoot = [IO.Path]::GetFullPath("C:\ProgramData\self-hosted-ci\health-bootstrap")
if ([IO.Path]::GetFullPath($Root) -ne $expectedStagingRoot) { throw "health bootstrap staging root is not canonical" }
Assert-NoReparsePath "C:\ProgramData"
Assert-NoReparsePath (Split-Path -Parent $Root) $true
Assert-NoReparsePath $Root $true

$createdReader = $false; $registered = $false; $passwordApplied = $false; $password = $null
try {
    if ($null -eq $existingReader) {
        if ($orphanReaderProfile) { Remove-ExactManagedReaderProfile ([IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")) }
        $readerPassword = New-RandomPassword
        try { $existingReader = New-LocalUser -Name $ReaderAccount -Password $readerPassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description $ReaderDescription; $createdReader = $true }
        finally { $readerPassword.Dispose() }
    }
    Assert-NonAdmin $existingReader "health reader"
    Disable-LocalUser -Name $ReaderAccount
    Set-ExactAuthorizedKey $existingReader $AuthorizedKey
    if ($FailureInjection -eq "host-after-reader") { throw "injected host failure after reader setup" }
    if (-not (Test-Path -LiteralPath $Root)) { [void](New-Item -ItemType Directory -Path $Root) }
    Assert-NoReparsePath $Root
    Assert-NoReparseDescendants $Root
    Set-Acl -LiteralPath $Root -AclObject (New-ProtectedAcl $service.SID)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $worker = @"
`$ErrorActionPreference = 'Stop'
function Get-ExactRegistration([string]`$RegistryRoot) {
    `$base = "`$RegistryRoot\Software\Microsoft\Windows\CurrentVersion\Lxss"
    try {
        `$matches = @(Get-ChildItem -LiteralPath `$base -ErrorAction Stop | ForEach-Object {
            `$value = Get-ItemProperty -LiteralPath `$_.PSPath -ErrorAction Stop
            if ([string]`$value.DistributionName -eq '$DistroName') {
                [ordered]@{ key=`$_.PSChildName; distribution_name=[string]`$value.DistributionName; version=[int]`$value.Version; base_path=[string]`$value.BasePath; state=[int]`$value.State }
            }
        })
        return [ordered]@{ accessible=`$true; exact_match_count=`$matches.Count; exact_matches=`$matches; error=`$null }
    }
    catch { return [ordered]@{ accessible=`$false; exact_match_count=0; exact_matches=@(); error=`$_.Exception.Message } }
}
try {
    `$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if (`$sid -ne '$ExpectedServiceAccountSid') { throw 'worker service SID mismatch' }
    if ('$FailureInjection' -eq 'worker-before-wsl') { throw 'injected failure before WSL' }
    `$hkcuRegistration = Get-ExactRegistration 'Registry::HKEY_CURRENT_USER'
    `$exactSidRegistration = Get-ExactRegistration 'Registry::HKEY_USERS\$ExpectedServiceAccountSid'
    `$registrationValidated = `$false; `$registrationError = `$null; `$distroGuid = `$null
    try {
        if (-not `$hkcuRegistration.accessible -or -not `$exactSidRegistration.accessible) { throw 'WSL registration hive is not accessible' }
        if (`$hkcuRegistration.exact_match_count -ne 1 -or `$exactSidRegistration.exact_match_count -ne 1) { throw 'expected exactly one WSL registration in both identity hives' }
        `$hkcuMatch = `$hkcuRegistration.exact_matches[0]; `$exactSidMatch = `$exactSidRegistration.exact_matches[0]
        if ([string]`$hkcuMatch.key -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') { throw 'WSL registration key is not a canonical GUID' }
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]`$hkcuMatch.key, [string]`$exactSidMatch.key)) { throw 'HKCU and exact-SID WSL registration GUIDs differ' }
        foreach (`$match in @(`$hkcuMatch, `$exactSidMatch)) {
            if (-not [StringComparer]::Ordinal.Equals([string]`$match.distribution_name, '$DistroName')) { throw 'WSL registration name is not exact' }
            if ([int]`$match.version -ne 2) { throw 'WSL registration version is not 2' }
            if ([IO.Path]::GetFullPath([string]`$match.base_path).TrimEnd('\') -ne [IO.Path]::GetFullPath('$ExpectedDistroBasePath').TrimEnd('\')) { throw 'WSL registration BasePath is not exact' }
        }
        `$distroGuid = [string]`$hkcuMatch.key; `$registrationValidated = `$true
    }
    catch { `$registrationError = `$_.Exception.Message }
    `$visibility = [Collections.Generic.List[object]]::new(); `$distroVisible = `$false
    for (`$attempt = 1; `$attempt -le 10; `$attempt++) {
        `$listRaw = @(& "`$env:SystemRoot\System32\wsl.exe" --list --quiet 2>&1)
        `$listExitCode = `$LASTEXITCODE
        `$names = @(`$listRaw | ForEach-Object { ([string]`$_).Replace([string][char]0, [string]::Empty).Trim() } | Where-Object { `$_ })
        `$visibility.Add([ordered]@{ attempt=`$attempt; observed_at=[DateTimeOffset]::UtcNow.ToString('o'); exit_code=`$listExitCode; names=`$names; raw=(`$listRaw -join "`n") })
        `$exactNames = @(`$names | Where-Object { [StringComparer]::Ordinal.Equals([string]`$_, '$DistroName') })
        if (`$listExitCode -eq 0 -and `$exactNames.Count -eq 1) { `$distroVisible = `$true; break }
        if (`$attempt -lt 10) { Start-Sleep -Seconds 2 }
    }
    `$context = [ordered]@{
        identity_sid=`$sid; process_session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId
        user_profile_environment=[string]`$env:USERPROFILE; user_profile_folder=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        hkcu_registration=`$hkcuRegistration; exact_sid_hku_registration=`$exactSidRegistration
        registration_validated=`$registrationValidated; registration_error=`$registrationError; selected_distribution_id=`$distroGuid
        visibility_attempts=`$visibility; exact_distro_visible=`$distroVisible
    }
    [IO.File]::WriteAllText('$WorkerContextPath', (`$context | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new(`$false))
    if (-not `$registrationValidated) { throw "exact WSL registry validation failed: `$registrationError" }
    if (-not `$distroVisible) { throw 'exact WSL distro remained invisible after bounded preflight' }
    `$psi = [Diagnostics.ProcessStartInfo]::new()
    `$psi.FileName = "`$env:SystemRoot\System32\wsl.exe"
    `$psi.Arguments = '--distribution-id ' + `$distroGuid + ' --user root -- bash -lc "base64 --decode | bash"'
    `$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true
    `$psi.RedirectStandardInput = `$true; `$psi.RedirectStandardOutput = `$true; `$psi.RedirectStandardError = `$true
    `$process = [Diagnostics.Process]::new(); `$process.StartInfo = `$psi
    if (-not `$process.Start()) { throw 'could not start WSL health installer' }
    `$stdoutTask = `$process.StandardOutput.ReadToEndAsync(); `$stderrTask = `$process.StandardError.ReadToEndAsync()
    `$process.StandardInput.WriteLine('$payloadB64'); `$process.StandardInput.Close()
    if (-not `$process.WaitForExit(150000)) { try { `$process.Kill() } catch {}; throw 'WSL health installer timed out' }
    `$stdout = `$stdoutTask.GetAwaiter().GetResult(); `$stderr = `$stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText('$WorkerStdoutPath', `$stdout, [Text.UTF8Encoding]::new(`$false))
    [IO.File]::WriteAllText('$WorkerStderrPath', `$stderr, [Text.UTF8Encoding]::new(`$false))
    if (`$process.ExitCode -ne 0) { throw "WSL health install failed with exit code `$(`$process.ExitCode)" }
    `$last = @(`$stdout -split '[\r\n]+' | Where-Object { `$_.Trim() }) | Select-Object -Last 1
    `$document = `$last | ConvertFrom-Json
    if (`$document.status -ne 'installed' -or `$document.first_heartbeat -eq `$document.second_heartbeat) { throw 'WSL postcondition failed' }
    [IO.File]::WriteAllText('$ResultPath', (`$document | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new(`$false))
}
catch {
    `$failure = [ordered]@{ status='failed'; message=`$_.Exception.Message; category=[string]`$_.CategoryInfo; script_stack_trace=`$_.ScriptStackTrace }
    [IO.File]::WriteAllText('$WorkerErrorPath', (`$failure | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new(`$false))
    throw
}
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
    if (-not $observed.Settings.AllowDemandStart -or $observed.Settings.DisallowStartIfOnBatteries -or $observed.Settings.StopIfGoingOnBatteries -or $observed.Settings.MultipleInstances -ne "IgnoreNew") { throw "one-shot task settings postcondition failed" }
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
    Assert-NoReparsePath $Root
    Assert-NoReparseDescendants $Root
    Remove-Item -LiteralPath $Root -Recurse -Force
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw "one-shot task reappeared before completion evidence" }
    [ordered]@{ status="installed"; reader_account=$ReaderAccount; reader_enabled=$false; two_distinct_heartbeats=$true; one_shot_task_absent=$true; stored_task_credential_invalidated=$true; runner_registration_changed=$false } | ConvertTo-Json -Compress
}
catch {
    $original = $_.Exception.Message; $rollback = [Collections.Generic.List[string]]::new()
    $evidencePath = $null
    $taskSnapshot = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $taskInfoSnapshot = if ($null -eq $taskSnapshot) { $null } else { Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue }
    try { $evidencePath = Save-FailureEvidence $original $taskSnapshot $taskInfoSnapshot }
    catch { $rollback.Add("failure evidence preservation: $($_.Exception.Message)") }
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
    if (Test-Path -LiteralPath $Root) { try { Assert-NoReparsePath $Root; Assert-NoReparseDescendants $Root; Remove-Item -LiteralPath $Root -Recurse -Force } catch { $rollback.Add("staging cleanup: $($_.Exception.Message)") } }
    if ($createdReader) {
        try {
            $readerProfile = [IO.Path]::GetFullPath("C:\Users\selfhosted-ci-health")
            if (Test-Path -LiteralPath $readerProfile) { Remove-ExactManagedReaderProfile $readerProfile }
            Remove-LocalUser -Name $ReaderAccount
            if ((Get-LocalUser -Name $ReaderAccount -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $readerProfile)) { throw "reader rollback postcondition failed" }
        }
        catch { $rollback.Add("reader rollback: $($_.Exception.Message)") }
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $rollback.Add("task absence postcondition failed") }
    $evidence = if ($null -eq $evidencePath) { "unavailable" } else { $evidencePath }
    if ($rollback.Count) { throw "Install failed: $original. Evidence: $evidence. Rollback failures: $($rollback -join '; ')" }
    throw "Install failed and host rollback was verified: $original. Evidence: $evidence"
}
finally { if ($null -ne $password) { $password.Dispose() } }
