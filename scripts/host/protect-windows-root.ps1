[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$ReaderAccount = "selfhosted-ci-health",
    [switch]$Apply,
    [switch]$AcknowledgeProtectedRootAcl,
    [switch]$AclRoundTripPreflight
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = "C:\ProgramData\self-hosted-ci"
$AdministratorsSid = "S-1-5-32-544"
$SystemSid = "S-1-5-18"

function Test-IsAdministrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PinnedLocalAccount([string]$Name, [bool]$RequireEnabled) {
    $account = Get-LocalUser -Name $Name -ErrorAction Stop
    if ([string]$account.PrincipalSource -ne "Local") { throw "account must be a local Windows identity: $Name" }
    if ($account.SID.Value -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw "account SID is not an exact local-user SID: $Name" }
    if ($RequireEnabled -and -not $account.Enabled) { throw "service account must be enabled" }
    return $account
}

function Test-GroupContainsSid([object]$Group, [string]$TargetSid, [Collections.Generic.HashSet[string]]$Visited) {
    if (-not $Visited.Add($Group.SID.Value)) { return $false }
    foreach ($member in @(Get-LocalGroupMember -Group $Group -ErrorAction Stop)) {
        if ($member.SID.Value -eq $TargetSid) { return $true }
        if ([string]$member.ObjectClass -eq "Group") {
            try {
                $nested = Get-LocalGroup -SID $member.SID -ErrorAction Stop
                if (Test-GroupContainsSid $nested $TargetSid $Visited) { return $true }
            }
            catch { throw "cannot prove non-admin identity through nested group $($member.Name): $($_.Exception.Message)" }
        }
    }
    return $false
}

function Assert-NonAdmin([object]$Account, [object]$Administrators) {
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (Test-GroupContainsSid $Administrators $Account.SID.Value $visited) { throw "account must be effectively non-admin: $($Account.Name)" }
}

function New-ExactDirectoryAcl(
    [Security.Principal.SecurityIdentifier]$OwnerSid,
    [Collections.IDictionary]$ExpectedRights
) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($OwnerSid)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in $ExpectedRights.Keys) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new([string]$sid),
            [Security.AccessControl.FileSystemRights]$ExpectedRights[$sid],
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Assert-ExactDirectoryAcl(
    [string]$LiteralPath,
    [Security.Principal.SecurityIdentifier]$ExpectedOwnerSid,
    [Collections.IDictionary]$ExpectedRights
) {
    $actual = Get-Acl -LiteralPath $LiteralPath
    if (-not $actual.AreAccessRulesProtected) { throw "Windows directory DACL is not protected" }
    if (-not $actual.AreAccessRulesCanonical) { throw "Windows directory DACL is not canonical" }
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $ExpectedOwnerSid.Value) { throw "Windows directory owner is not exact" }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $ExpectedRights.Count) { throw "Windows directory DACL rule count is not exact" }
    $observed = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($observed.ContainsKey($sid) -or -not $ExpectedRights.Contains($sid)) { throw "Windows directory DACL contains a duplicate or unknown SID" }
        if ($rule.IsInherited -or $rule.AccessControlType -ne "Allow" -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]$ExpectedRights[$sid]) {
            throw "Windows directory DACL ACE is not semantically exact: $sid"
        }
        $observed[$sid] = $true
    }

    $binary = $actual.GetSecurityDescriptorBinaryForm()
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($binary, 0)
    $requiredFlags = [int]([Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected -bor
        [Security.AccessControl.ControlFlags]::SelfRelative)
    $allowedFlags = $requiredFlags -bor [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
    if (([int]$descriptor.ControlFlags -band $requiredFlags) -ne $requiredFlags -or
        ([int]$descriptor.ControlFlags -band (-bnot $allowedFlags)) -ne 0) {
        throw "Windows directory DACL control flags are not semantically exact"
    }
    if ($null -eq $descriptor.DiscretionaryAcl -or $descriptor.DiscretionaryAcl.Count -ne $ExpectedRights.Count) {
        throw "Windows directory raw DACL rule count is not exact"
    }
    $expectedAceFlags = [Security.AccessControl.AceFlags]([int][Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][Security.AccessControl.AceFlags]::ObjectInherit)
    $rawObserved = @{}
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.OpaqueLength -ne 0 -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.AceFlags -ne $expectedAceFlags) {
            throw "Windows directory raw DACL ACE type or flags are not exact"
        }
        $sid = $ace.SecurityIdentifier.Value
        if ($rawObserved.ContainsKey($sid) -or -not $ExpectedRights.Contains($sid) -or
            $ace.AccessMask -ne [int][Security.AccessControl.FileSystemRights]$ExpectedRights[$sid]) {
            throw "Windows directory raw DACL ACE SID or mask is not exact: $sid"
        }
        $rawObserved[$sid] = $true
    }

    $actualSddl = $actual.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    return $actualSddl
}

if ($env:OS -ne "Windows_NT") { throw "Windows root protection requires Windows" }
if ($AclRoundTripPreflight) {
    if ($Apply -or $AcknowledgeProtectedRootAcl) { throw "ACL round-trip preflight cannot request root mutation" }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $preflightRights = [ordered]@{}
    $preflightRights[$SystemSid] = $fullControl
    $preflightRights[$currentSid.Value] = $fullControl
    $preflightAcl = New-ExactDirectoryAcl $currentSid $preflightRights
    $expectedSddl = $preflightAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $fixture = [IO.Path]::Combine([IO.Path]::GetTempPath(), "self-hosted-ci-acl-preflight-$([Guid]::NewGuid().ToString('N'))")
    $fixtureRemoved = $false
    try {
        [void][IO.Directory]::CreateDirectory($fixture)
        Set-Acl -LiteralPath $fixture -AclObject $preflightAcl
        $observedSddl = Assert-ExactDirectoryAcl $fixture $currentSid $preflightRights
    }
    finally {
        if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete($fixture, $true) }
        $fixtureRemoved = -not [IO.Directory]::Exists($fixture)
    }
    if (-not $fixtureRemoved) { throw "ACL round-trip preflight fixture cleanup failed" }
    $observedDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new($observedSddl)
    [ordered]@{
        status = "verified"
        operation = "windows-root-acl-roundtrip-preflight"
        expected_dacl_sddl = $expectedSddl
        observed_dacl_sddl = $observedSddl
        auto_inherited_metadata_observed = [bool]($observedDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
        root_mutated = $false
        temporary_fixture_removed = $true
    } | ConvertTo-Json -Compress
    return
}

if (-not (Test-IsAdministrator)) { throw "Windows root protection requires an elevated Windows console" }
if ($ServiceAccount -cne "selfhosted-ci-svc" -or $ReaderAccount -cne "selfhosted-ci-health") { throw "Windows root identities are pinned" }
if ($ExpectedServiceAccountSid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw "expected service-account SID is invalid" }
$service = Get-PinnedLocalAccount $ServiceAccount $true
$reader = Get-PinnedLocalAccount $ReaderAccount $false
if ($service.SID.Value -cne $ExpectedServiceAccountSid) { throw "service-account SID mismatch" }
if ($service.SID.Value -eq $reader.SID.Value) { throw "service and reader identities must be distinct" }
$administrators = Get-LocalGroup -SID $AdministratorsSid -ErrorAction Stop
Assert-NonAdmin $service $administrators
Assert-NonAdmin $reader $administrators
if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "Windows self-hosted-ci root must already exist as a directory" }
$rootItem = Get-Item -LiteralPath $Root -Force
if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Windows self-hosted-ci root must not be a reparse point" }
$serviceSid = [Security.Principal.SecurityIdentifier]::new($service.SID.Value)
$readerSid = [Security.Principal.SecurityIdentifier]::new($reader.SID.Value)
$fullControl = [Security.AccessControl.FileSystemRights]::FullControl
$readOnly = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
$rootRights = [ordered]@{}
$rootRights[$SystemSid] = $fullControl
$rootRights[$AdministratorsSid] = $fullControl
$rootRights[$serviceSid.Value] = $readOnly
$rootRights[$readerSid.Value] = $readOnly
$targetAcl = New-ExactDirectoryAcl ([Security.Principal.SecurityIdentifier]::new($AdministratorsSid)) $rootRights
$targetSddl = $targetAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
[ordered]@{
    mode = "plan"
    apply_requested = [bool]$Apply
    root = $Root
    owner_sid = $AdministratorsSid
    service_account = $service.Name
    service_account_sid = $service.SID.Value
    reader_account = $reader.Name
    reader_account_sid = $reader.SID.Value
    target_dacl_sddl = $targetSddl
    child_writes = $false
    runner_changed = $false
    github_changed = $false
    wsl_changed = $false
} | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgeProtectedRootAcl) { throw "Apply requires acknowledgement of the protected Windows root ACL" }

$originalAcl = Get-Acl -LiteralPath $Root
try {
    Set-Acl -LiteralPath $Root -AclObject $targetAcl
    $verifiedSddl = Assert-ExactDirectoryAcl $Root ([Security.Principal.SecurityIdentifier]::new($AdministratorsSid)) $rootRights
}
catch {
    $original = $_.Exception.Message
    try { Set-Acl -LiteralPath $Root -AclObject $originalAcl }
    catch { throw "Windows root protection failed: $original. ACL rollback also failed: $($_.Exception.Message)" }
    throw "Windows root protection failed and the prior root ACL was restored: $original"
}
[ordered]@{
    status = "protected"
    root = $Root
    owner_sid = $AdministratorsSid
    service_account_sid = $service.SID.Value
    reader_account_sid = $reader.SID.Value
    dacl_sddl = $verifiedSddl
    dacl_protected = $true
    explicit_ace_count = 4
    service_and_reader_read_only = $true
    child_writes = $false
    runner_changed = $false
    github_changed = $false
    wsl_changed = $false
} | ConvertTo-Json -Compress
