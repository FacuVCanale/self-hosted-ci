[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$DistroName = "Ubuntu-24.04-CI",
    [string]$ExpectedBasePath = "C:\ProgramData\self-hosted-ci\wsl",
    [string]$OutputRoot = "C:\ProgramData\self-hosted-ci\semantic-contract-staging\v1"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ContractVersion = 1
$AdministratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
$SystemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$StagingRoot = "C:\ProgramData\self-hosted-ci\semantic-contract-staging"

function Test-IsAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoReparsePath([string]$Path, [bool]$AllowMissingLeaf = $false) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $AllowMissingLeaf -and -not (Test-Path -LiteralPath $full)) { throw "expected path is absent: $full" }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "reparse point is forbidden: $cursor" }
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function New-PrivateAcl([bool]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($AdministratorsSid)
    foreach ($sid in @($SystemSid, $AdministratorsSid)) {
        if ($Directory) {
            $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        }
        else {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)
        }
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
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

function New-Check([bool]$Satisfied, [string]$Reason) {
    return [ordered]@{ status = $(if ($Satisfied) { "satisfied" } else { "failed" }); reason = $Reason }
}

function New-UnobservedCheck([string]$Reason) {
    return [ordered]@{ status = "unobserved"; reason = $Reason }
}

function Get-NormalizedFileAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [ordered]@{
            sid = $_.IdentityReference.Value
            type = [string]$_.AccessControlType
            rights = [string]$_.FileSystemRights
            inherited = [bool]$_.IsInherited
            inheritance_flags = [string]$_.InheritanceFlags
            propagation_flags = [string]$_.PropagationFlags
        }
    })
    return [ordered]@{
        owner_sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        inheritance_protected = [bool]$acl.AreAccessRulesProtected
        rules = $rules
    }
}

function Test-ExactBasePathAcl([object]$AclObservation, [string]$ServiceSid) {
    if ($AclObservation.owner_sid -ne $AdministratorsSid.Value -or -not $AclObservation.inheritance_protected) { return $false }
    $allowed = @($SystemSid.Value, $AdministratorsSid.Value, $ServiceSid)
    if ($AclObservation.rules.Count -ne 3) { return $false }
    foreach ($rule in $AclObservation.rules) {
        if ($allowed -notcontains $rule.sid -or $rule.type -ne "Allow" -or $rule.inherited -or $rule.rights -ne "FullControl") { return $false }
        if ($rule.inheritance_flags -ne "ContainerInherit, ObjectInherit" -or $rule.propagation_flags -ne "None") { return $false }
    }
    foreach ($sid in $allowed) { if (@($AclObservation.rules.sid) -notcontains $sid) { return $false } }
    return $true
}

function Get-UserHiveRegistryOwnerSid([string]$Sid, [string]$RelativePath) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
    $key = $null
    try {
        $key = $base.OpenSubKey("$Sid\$RelativePath", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($null -eq $key) { throw "service registry key is absent" }
        return $key.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "collector requires an elevated Windows console" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "service account and distro names are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw "invalid service SID" }
if ([IO.Path]::GetFullPath($ExpectedBasePath).TrimEnd('\') -ne "C:\ProgramData\self-hosted-ci\wsl") { throw "ExpectedBasePath is pinned" }
if ([IO.Path]::GetFullPath($OutputRoot).TrimEnd('\') -ne "C:\ProgramData\self-hosted-ci\semantic-contract-staging\v1") { throw "OutputRoot is pinned" }

$checks = [ordered]@{}
$accountObservation = $null
$registrationObservation = [ordered]@{ accessible = $false; exact_match_count = 0; matches = @(); error = $null }
$basePathObservation = [ordered]@{ exists = $false; canonical_path = $ExpectedBasePath; reparse_free = $false; acl = $null; error = $null }

try {
    $account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
    $admins = Get-LocalGroup -SID $AdministratorsSid -ErrorAction Stop
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $effectiveAdmin = Test-GroupContainsSid $admins $account.SID.Value $visited
    $accountObservation = [ordered]@{
        name = $account.Name
        sid = $account.SID.Value
        enabled = [bool]$account.Enabled
        principal_source = [string]$account.PrincipalSource
        effective_administrator = [bool]$effectiveAdmin
    }
    $checks.account_name = New-Check ($account.Name -ceq $ServiceAccount) "observed exact local account name"
    $checks.account_sid = New-Check ($account.SID.Value -eq $ExpectedServiceAccountSid) "observed exact service SID"
    $checks.account_enabled = New-Check ([bool]$account.Enabled) "service account must be enabled"
    $checks.account_local = New-Check ([string]$account.PrincipalSource -eq "Local") "service account must be local"
    $checks.account_non_admin = New-Check (-not $effectiveAdmin) "service account must be effectively non-admin, including nested groups"
}
catch {
    $accountObservation = [ordered]@{ error = $_.Exception.Message }
    foreach ($name in @("account_name", "account_sid", "account_enabled", "account_local", "account_non_admin")) {
        $checks[$name] = New-UnobservedCheck "local service identity could not be observed"
    }
}

$registryRoot = "Registry::HKEY_USERS\$ExpectedServiceAccountSid\Software\Microsoft\Windows\CurrentVersion\Lxss"
try {
    $matches = @(Get-ChildItem -LiteralPath $registryRoot -ErrorAction Stop | ForEach-Object {
        $value = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
        if ([string]$value.DistributionName -ceq $DistroName) {
            [ordered]@{
                key = $_.PSChildName
                distribution_name = [string]$value.DistributionName
                version = [int]$value.Version
                base_path = [string]$value.BasePath
                owner_sid = Get-UserHiveRegistryOwnerSid $ExpectedServiceAccountSid ("Software\Microsoft\Windows\CurrentVersion\Lxss\" + $_.PSChildName)
            }
        }
    })
    $registrationObservation = [ordered]@{ accessible = $true; exact_match_count = $matches.Count; matches = $matches; error = $null }
    $checks.registration_hive_accessible = New-Check $true "exact service-SID HKEY_USERS hive was accessible"
    $checks.registration_unique = New-Check ($matches.Count -eq 1) "expected exactly one exact-name registration under the service SID"
    if ($matches.Count -eq 1) {
        $match = $matches[0]
        $canonicalBase = [IO.Path]::GetFullPath([string]$match.base_path).TrimEnd('\')
        $checks.registration_guid = New-Check ([string]$match.key -match '^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$') "registration key must be a canonical GUID"
        $checks.registration_version = New-Check ([int]$match.version -eq 2) "registration must be WSL2"
        $checks.registration_base_path = New-Check ($canonicalBase -eq [IO.Path]::GetFullPath($ExpectedBasePath).TrimEnd('\')) "registration BasePath must be exact"
        $checks.registration_owner = New-Check ([string]$match.owner_sid -eq $ExpectedServiceAccountSid) "registration key owner must be the service SID"
    }
    else {
        foreach ($name in @("registration_guid", "registration_version", "registration_base_path", "registration_owner")) {
            $checks[$name] = New-UnobservedCheck "a unique registration was not available"
        }
    }
}
catch {
    $registrationObservation.error = $_.Exception.Message
    foreach ($name in @("registration_hive_accessible", "registration_unique", "registration_guid", "registration_version", "registration_base_path", "registration_owner")) {
        $checks[$name] = New-UnobservedCheck "exact service-SID registration hive could not be observed"
    }
}

try {
    $basePathObservation.exists = Test-Path -LiteralPath $ExpectedBasePath -PathType Container
    if (-not $basePathObservation.exists) { throw "expected WSL BasePath is absent" }
    Assert-NoReparsePath $ExpectedBasePath
    $basePathObservation.reparse_free = $true
    $basePathObservation.acl = Get-NormalizedFileAcl $ExpectedBasePath
    $checks.base_path_exists = New-Check $true "exact BasePath exists"
    $checks.base_path_reparse_free = New-Check $true "BasePath ancestry contains no reparse point"
    $checks.base_path_acl = New-Check (Test-ExactBasePathAcl $basePathObservation.acl $ExpectedServiceAccountSid) "BasePath ACL must be protected and exactly SYSTEM/Administrators/service FullControl"
}
catch {
    $basePathObservation.error = $_.Exception.Message
    if (-not $checks.Contains("base_path_exists")) { $checks.base_path_exists = New-Check $false "exact BasePath was not observable as a directory" }
    if (-not $checks.Contains("base_path_reparse_free")) { $checks.base_path_reparse_free = New-UnobservedCheck "BasePath ancestry could not be validated" }
    if (-not $checks.Contains("base_path_acl")) { $checks.base_path_acl = New-UnobservedCheck "BasePath ACL could not be validated" }
}

$statuses = @($checks.Values | ForEach-Object { $_.status })
$contractSatisfied = ($statuses.Count -gt 0 -and @($statuses | Where-Object { $_ -ne "satisfied" }).Count -eq 0)
$document = [ordered]@{
    schema = "self-hosted-ci/windows-wsl-semantic-contract"
    schema_version = $ContractVersion
    observed_at = [DateTimeOffset]::UtcNow.ToString("o")
    collector_identity_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    expected = [ordered]@{
        service_account = $ServiceAccount
        service_sid = $ExpectedServiceAccountSid
        distro_name = $DistroName
        base_path = $ExpectedBasePath
        wsl_version = 2
    }
    observations = [ordered]@{
        account = $accountObservation
        registration = $registrationObservation
        base_path = $basePathObservation
    }
    checks = $checks
    contract_satisfied = $contractSatisfied
    side_effects = [ordered]@{
        scheduled_task_created = $false
        password_rotated = $false
        wsl_started = $false
        github_contacted = $false
        runner_registration_changed = $false
        evidence_file_created = $true
    }
}

Assert-NoReparsePath "C:\ProgramData"
Assert-NoReparsePath "C:\ProgramData\self-hosted-ci"
Assert-NoReparsePath $StagingRoot $true
if (-not (Test-Path -LiteralPath $StagingRoot)) { [void](New-Item -ItemType Directory -Path $StagingRoot) }
Assert-NoReparsePath $StagingRoot
Set-Acl -LiteralPath $StagingRoot -AclObject (New-PrivateAcl $true)
if (-not (Test-Path -LiteralPath $OutputRoot)) { [void](New-Item -ItemType Directory -Path $OutputRoot -Force) }
Assert-NoReparsePath $OutputRoot
Set-Acl -LiteralPath $OutputRoot -AclObject (New-PrivateAcl $true)
$outputPath = Join-Path $OutputRoot (([DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")) + "-" + [Guid]::NewGuid().ToString("D") + ".json")
[IO.File]::WriteAllText($outputPath, ($document | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
Set-Acl -LiteralPath $outputPath -AclObject (New-PrivateAcl $false)
[ordered]@{
    status = "observed"
    contract_satisfied = $contractSatisfied
    evidence_path = $outputPath
    failed_checks = @($checks.GetEnumerator() | Where-Object { $_.Value.status -eq "failed" } | ForEach-Object { $_.Key })
    unobserved_checks = @($checks.GetEnumerator() | Where-Object { $_.Value.status -eq "unobserved" } | ForEach-Object { $_.Key })
    task_created = $false
    password_rotated = $false
    github_contacted = $false
    runner_registration_changed = $false
} | ConvertTo-Json -Compress
