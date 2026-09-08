[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$ReaderAccount = "selfhosted-ci-health",
    [switch]$Apply,
    [switch]$AcknowledgeProtectedRootAcl
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

function New-RootAcl([Security.Principal.SecurityIdentifier]$ServiceSid, [Security.Principal.SecurityIdentifier]$ReaderSid) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.SecurityIdentifier]::new($AdministratorsSid)
    $acl.SetOwner($owner)
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $readOnly = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($entry in @(
        @([Security.Principal.SecurityIdentifier]::new($SystemSid), $fullControl),
        @($owner, $fullControl),
        @($ServiceSid, $readOnly),
        @($ReaderSid, $readOnly)
    )) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $entry[0], $entry[1],
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Assert-ExactRootAcl(
    [Security.Principal.SecurityIdentifier]$ServiceSid,
    [Security.Principal.SecurityIdentifier]$ReaderSid
) {
    $actual = Get-Acl -LiteralPath $Root
    if (-not $actual.AreAccessRulesProtected) { throw "Windows root DACL is not protected" }
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $AdministratorsSid) { throw "Windows root owner is not Administrators" }
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $readOnly = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $expected = @{}
    $expected[$SystemSid] = $fullControl
    $expected[$AdministratorsSid] = $fullControl
    $expected[$ServiceSid.Value] = $readOnly
    $expected[$ReaderSid.Value] = $readOnly
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expected.Count) { throw "Windows root DACL rule count is not exact" }
    $observed = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($observed.ContainsKey($sid) -or -not $expected.ContainsKey($sid)) { throw "Windows root DACL contains a duplicate or unknown SID" }
        if ($rule.IsInherited -or $rule.AccessControlType -ne "Allow" -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.FileSystemRights -ne $expected[$sid]) {
            throw "Windows root DACL ACE is not semantically exact: $sid"
        }
        $observed[$sid] = $true
    }
    $expectedAcl = New-RootAcl $ServiceSid $ReaderSid
    $actualSddl = $actual.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $expectedSddl = $expectedAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    if ($actualSddl -cne $expectedSddl) { throw "Windows root DACL SDDL is not semantically exact" }
    return $actualSddl
}

if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator)) { throw "Windows root protection requires an elevated Windows console" }
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
$targetAcl = New-RootAcl $serviceSid $readerSid
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
    $verifiedSddl = Assert-ExactRootAcl $serviceSid $readerSid
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
