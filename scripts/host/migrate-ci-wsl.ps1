[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [string]$SourceDistroName = "Ubuntu-24.04",
    [string]$ImportedDistroName = "Ubuntu-24.04-CI",
    [string]$ExportPath = "C:\ProgramData\self-hosted-ci\exports\Ubuntu-24.04-20260827.tar",
    [string]$DestinationPath = "C:\ProgramData\self-hosted-ci\wsl",
    [string]$ExpectedExportSha256 = "ad9e329eadc4211182c32d71a2830b6a492efedb2dc94735f3dd5287925ca0e9",
    [long]$ExpectedExportBytes = 0,
    [string]$ExpectedServiceAccountSid,
    [int]$TimeoutSeconds = 900,
    [switch]$Apply,
    [switch]$AcknowledgeSourceAndExportWillBePreserved,
    [switch]$AcknowledgeImportRunsAsServiceIdentity,
    [switch]$AcknowledgeGrantBatchLogonRight,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedSourceDistro = "Ubuntu-24.04"
$ExpectedImportedDistro = "Ubuntu-24.04-CI"
$ExpectedExport = "C:\ProgramData\self-hosted-ci\exports\Ubuntu-24.04-20260827.tar"
$ExpectedDestination = "C:\ProgramData\self-hosted-ci\wsl"
$TaskName = "SelfHostedCI-Import-Ubuntu-24.04-CI"
$TaskRoot = "C:\ProgramData\self-hosted-ci\migration"
$WorkerPath = Join-Path $TaskRoot "import-ci-wsl-worker.ps1"
$ResultPath = Join-Path $TaskRoot "import-result.json"
$StdoutPath = Join-Path $TaskRoot "import.stdout.log"
$StderrPath = Join-Path $TaskRoot "import.stderr.log"

function Assert-Windows {
    if ($env:OS -ne "Windows_NT") {
        throw "This script must run on Windows PowerShell or PowerShell on Windows."
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NormalizedPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Get-WslDistros {
    $lines = @(& wsl.exe --list --quiet 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list WSL distributions: $($lines -join ' ')"
    }
    return @($lines | ForEach-Object { ([string]$_).Trim([char]0).Trim() } | Where-Object { $_ })
}

function Assert-NotReparsePoint([string]$LiteralPath, [string]$Description) {
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $LiteralPath"
    }
}

function Get-LocalServiceIdentity([string]$Name) {
    $account = Get-LocalUser -Name $Name -ErrorAction Stop
    if (-not $account.Enabled) {
        throw "Service account is disabled: $Name"
    }
    if ([string]$account.PrincipalSource -ne "Local") {
        throw "Service account must be a local Windows account: $Name"
    }

    $administrators = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop)
    if ($adminMembers.SID.Value -contains $account.SID.Value) {
        throw "Service account must not be a member of the local Administrators group: $Name"
    }

    return $account
}

function New-ProtectedDirectoryAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid, $ServiceSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function New-ProtectedExportAcl([Security.Principal.SecurityIdentifier]$ServiceSid) {
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $serviceRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $ServiceSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($serviceRule)
    return $acl
}

function Assert-ProtectedAcl([string]$LiteralPath, [string[]]$AllowedSidValues) {
    $acl = Get-Acl -LiteralPath $LiteralPath
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance must be disabled: $LiteralPath"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Deny ACL entries are not allowed on migration artifacts: $LiteralPath"
        }
        if ($AllowedSidValues -notcontains $rule.IdentityReference.Value) {
            throw "Unexpected ACL identity $($rule.IdentityReference.Value) on $LiteralPath"
        }
    }
    foreach ($sid in $AllowedSidValues) {
        if ($rules.IdentityReference.Value -notcontains $sid) {
            throw "Required ACL identity $sid is missing from $LiteralPath"
        }
    }
}

function Initialize-LsaRightsApi {
    if ("SelfHostedCi.LsaRights" -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SelfHostedCi
{
    public static class LsaRights
    {
        private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
        private const uint POLICY_LOOKUP_NAMES = 0x00000800;
        private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            [In] LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr ObjectHandle);

        private static IntPtr OpenPolicy()
        {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr handle;
            uint status = LsaOpenPolicy(
                IntPtr.Zero,
                ref attributes,
                POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
                out handle);
            ThrowOnLsaError(status, "LsaOpenPolicy");
            return handle;
        }

        private static IntPtr CopySid(string sidValue)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidValue);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static void ThrowOnLsaError(uint status, string operation)
        {
            if (status == 0) return;
            int win32 = unchecked((int)LsaNtStatusToWinError(status));
            throw new Win32Exception(win32, operation + " failed");
        }

        public static string[] GetAccountRights(string sidValue)
        {
            IntPtr policy = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr rightsBuffer = IntPtr.Zero;
            try
            {
                policy = OpenPolicy();
                sid = CopySid(sidValue);
                uint count;
                uint status = LsaEnumerateAccountRights(policy, sid, out rightsBuffer, out count);
                if (status == STATUS_OBJECT_NAME_NOT_FOUND) return new string[0];
                ThrowOnLsaError(status, "LsaEnumerateAccountRights");

                List<string> rights = new List<string>();
                int itemSize = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                for (uint index = 0; index < count; index++)
                {
                    IntPtr item = new IntPtr(rightsBuffer.ToInt64() + ((long)index * itemSize));
                    LSA_UNICODE_STRING value = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        item, typeof(LSA_UNICODE_STRING));
                    string right = Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
                    if (!String.IsNullOrEmpty(right)) rights.Add(right);
                }
                return rights.ToArray();
            }
            finally
            {
                if (rightsBuffer != IntPtr.Zero) LsaFreeMemory(rightsBuffer);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (policy != IntPtr.Zero) LsaClose(policy);
            }
        }

        public static void AddAccountRight(string sidValue, string rightName)
        {
            IntPtr policy = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr rightBuffer = IntPtr.Zero;
            try
            {
                policy = OpenPolicy();
                sid = CopySid(sidValue);
                rightBuffer = Marshal.StringToHGlobalUni(rightName);
                LSA_UNICODE_STRING right = new LSA_UNICODE_STRING();
                right.Buffer = rightBuffer;
                right.Length = checked((ushort)(rightName.Length * 2));
                right.MaximumLength = checked((ushort)((rightName.Length + 1) * 2));
                ThrowOnLsaError(
                    LsaAddAccountRights(policy, sid, new LSA_UNICODE_STRING[] { right }, 1),
                    "LsaAddAccountRights");
            }
            finally
            {
                if (rightBuffer != IntPtr.Zero) Marshal.FreeHGlobal(rightBuffer);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (policy != IntPtr.Zero) LsaClose(policy);
            }
        }
    }
}
'@
}

function Grant-ExactBatchLogonRight([string]$SidValue) {
    Initialize-LsaRightsApi
    $batchRight = "SeBatchLogonRight"
    $denyRight = "SeDenyBatchLogonRight"
    $before = @([SelfHostedCi.LsaRights]::GetAccountRights($SidValue) | Sort-Object -Unique)
    if ($before -contains $denyRight) {
        throw "Service-account SID $SidValue has SeDenyBatchLogonRight; refusing to weaken or override a deny assignment."
    }

    $wasAssigned = $before -contains $batchRight
    if (-not $wasAssigned) {
        [SelfHostedCi.LsaRights]::AddAccountRight($SidValue, $batchRight)
    }

    $after = @([SelfHostedCi.LsaRights]::GetAccountRights($SidValue) | Sort-Object -Unique)
    if ($after -contains $denyRight) {
        throw "Service-account SID acquired SeDenyBatchLogonRight during Apply; refusing to continue."
    }
    if ($after -notcontains $batchRight) {
        throw "LSA did not persist SeBatchLogonRight for service-account SID $SidValue."
    }
    $expectedAfter = @($before + $batchRight | Sort-Object -Unique)
    $difference = @(Compare-Object -ReferenceObject $expectedAfter -DifferenceObject $after)
    if ($difference.Count -ne 0) {
        throw "LSA rights changed beyond the single authorized SeBatchLogonRight addition; refusing to continue."
    }

    return [ordered]@{
        sid = $SidValue
        right = $batchRight
        already_assigned = $wasAssigned
        rights_before = $before
        rights_after = $after
        exact_addition_verified = $true
    }
}

function New-CryptographicAccountPassword {
    $randomBytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($randomBytes)
        $passwordText = "Aa1!" + [Convert]::ToBase64String($randomBytes)
        return ConvertTo-SecureString $passwordText -AsPlainText -Force
    }
    finally {
        [Array]::Clear($randomBytes, 0, $randomBytes.Length)
        $passwordText = $null
        $rng.Dispose()
    }
}

function Register-PasswordImportTask(
    [string]$Name,
    [string]$UserId,
    [string]$Executable,
    [string]$Arguments,
    [int]$ExecutionTimeoutSeconds,
    [Security.SecureString]$AccountPassword
) {
    # Registering for a different local identity requires credentials. Keep the
    # plaintext lifetime bounded to this COM call and zero the source BSTR.
    $taskCreateOrUpdate = 6
    $taskLogonPassword = 1
    $taskRunLevelLua = 0
    $taskActionExec = 0
    $taskInstancesIgnoreNew = 2
    $passwordBstr = [IntPtr]::Zero
    $passwordForCom = $null

    try {
        $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccountPassword)
        $passwordForCom = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
        $scheduler = New-Object -ComObject "Schedule.Service"
        $scheduler.Connect()
        $folder = $scheduler.GetFolder("\")
        $definition = $scheduler.NewTask(0)
        $definition.RegistrationInfo.Description = "One-time preservative self-hosted-ci WSL import"
        $definition.Principal.UserId = $UserId
        $definition.Principal.LogonType = $taskLogonPassword
        $definition.Principal.RunLevel = $taskRunLevelLua
        $definition.Settings.Enabled = $true
        $definition.Settings.AllowDemandStart = $true
        $definition.Settings.DisallowStartIfOnBatteries = $false
        $definition.Settings.StopIfGoingOnBatteries = $false
        $definition.Settings.MultipleInstances = $taskInstancesIgnoreNew
        $definition.Settings.ExecutionTimeLimit = "PT${ExecutionTimeoutSeconds}S"
        $action = $definition.Actions.Create($taskActionExec)
        $action.Path = $Executable
        $action.Arguments = $Arguments

        $registeredTask = $folder.RegisterTaskDefinition(
            $Name,
            $definition,
            $taskCreateOrUpdate,
            $UserId,
            $passwordForCom,
            $taskLogonPassword,
            $null
        )
        if ($null -eq $registeredTask) {
            throw "Task Scheduler returned no registered task."
        }
        return $registeredTask
    }
    catch {
        throw "Task Scheduler rejected the one-time password task before WSL was started. Original error: $($_.Exception.Message)"
    }
    finally {
        $passwordForCom = $null
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
        }
    }
}

function Write-Plan(
    [object]$Account,
    [IO.FileInfo]$ExportFile,
    [string]$ActualHash,
    [long]$RequiredFreeBytes,
    [long]$AvailableFreeBytes
) {
    $plan = [ordered]@{
        mode = "plan"
        apply_requested = [bool]$Apply
        service_account = $Account.Name
        service_account_sid = $Account.SID.Value
        service_account_non_admin = $true
        source_distro = $SourceDistroName
        source_preserved = $true
        export_path = $ExportFile.FullName
        export_bytes = $ExportFile.Length
        export_sha256 = $ActualHash
        export_preserved = $true
        imported_distro = $ImportedDistroName
        destination_path = $DestinationPath
        required_free_bytes = $RequiredFreeBytes
        available_free_bytes = $AvailableFreeBytes
        task_name = $TaskName
        task_log_directory = $TaskRoot
        acknowledgements_required_for_apply = @(
            "AcknowledgeSourceAndExportWillBePreserved",
            "AcknowledgeImportRunsAsServiceIdentity",
            "AcknowledgeGrantBatchLogonRight",
            "AcknowledgeOneTimePasswordRotation"
        )
        operations = @(
            "protect export ACL for SYSTEM, Administrators, and read-only service identity",
            "protect destination/task ACLs for SYSTEM, Administrators, and service identity",
            "fail if the service SID has SeDenyBatchLogonRight; add only SeBatchLogonRight through LSA and verify the exact rights set",
            "rotate the service account to an in-memory random password, register a one-time Password/LUA task, then rotate immediately to a second unknown random password during cleanup",
            "import or verify the exact WSL2 distro under that identity",
            "verify HKCU WSL registration, exact BasePath, version, SID, and task result",
            "remove the one-time scheduled task; preserve logs, source distro, export, and destination"
        )
        forbidden_operations = @("unregistering any WSL distro", "deleting the source distro", "deleting the export")
    }
    $plan | ConvertTo-Json -Depth 5
}

Assert-Windows

foreach ($command in @("wsl.exe", "Get-LocalUser", "Set-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember", "Get-ScheduledTask")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required Windows command is unavailable: $command"
    }
}

if ($SourceDistroName -ne $ExpectedSourceDistro) {
    throw "SourceDistroName must be $ExpectedSourceDistro."
}
if ($ImportedDistroName -ne $ExpectedImportedDistro) {
    throw "ImportedDistroName must be $ExpectedImportedDistro."
}
if ((Get-NormalizedPath $ExportPath) -ne (Get-NormalizedPath $ExpectedExport)) {
    throw "ExportPath must be the pinned export: $ExpectedExport"
}
if ((Get-NormalizedPath $DestinationPath) -ne (Get-NormalizedPath $ExpectedDestination)) {
    throw "DestinationPath must be the pinned dedicated location: $ExpectedDestination"
}
if ($ExpectedExportSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw "ExpectedExportSha256 must be exactly 64 hexadecimal characters."
}
if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 3600) {
    throw "TimeoutSeconds must be between 60 and 3600."
}
if (-not (Test-Path -LiteralPath $ExportPath -PathType Leaf)) {
    throw "Pinned WSL export not found: $ExportPath"
}
Assert-NotReparsePoint $ExportPath "WSL export"

$exportFile = Get-Item -LiteralPath $ExportPath -Force
$actualHash = (Get-FileHash -LiteralPath $ExportPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedExportSha256.ToLowerInvariant()) {
    throw "WSL export SHA-256 mismatch. Expected $ExpectedExportSha256, got $actualHash."
}
if ($ExpectedExportBytes -gt 0 -and $exportFile.Length -ne $ExpectedExportBytes) {
    throw "WSL export size mismatch. Expected $ExpectedExportBytes bytes, got $($exportFile.Length)."
}

$account = Get-LocalServiceIdentity $ServiceAccount
$distrosBefore = @(Get-WslDistros)
if ($distrosBefore -notcontains $SourceDistroName) {
    throw "Preserved source distro is not registered for the current operator: $SourceDistroName"
}
if ($SourceDistroName -eq $ImportedDistroName) {
    throw "Source and imported distro names must be different."
}

$destinationRoot = [IO.Path]::GetPathRoot((Get-NormalizedPath $DestinationPath))
$drive = Get-PSDrive -Name $destinationRoot.Substring(0, 1)
$requiredFreeBytes = [Math]::Max(($exportFile.Length * 2L) + 1GB, 5GB)
if ($drive.Free -lt $requiredFreeBytes) {
    throw "Insufficient free disk space. Required at least $requiredFreeBytes bytes, found $($drive.Free)."
}

Write-Plan $account $exportFile $actualHash $requiredFreeBytes $drive.Free

if (-not $Apply) {
    Write-Host "Plan only: no ACL, scheduled-task, WSL registration, or filesystem changes were made."
    Write-Host "For Apply, pin -ExpectedExportBytes $($exportFile.Length) and -ExpectedServiceAccountSid $($account.SID.Value)."
    exit 0
}

if (-not (Test-IsAdministrator)) {
    throw "Apply must run from an elevated local PowerShell console."
}
if (-not [Environment]::UserInteractive -or $Host.Name -ne "ConsoleHost") {
    throw "Apply must run interactively from a local PowerShell console."
}
if (-not $AcknowledgeSourceAndExportWillBePreserved) {
    throw "Apply requires -AcknowledgeSourceAndExportWillBePreserved."
}
if (-not $AcknowledgeImportRunsAsServiceIdentity) {
    throw "Apply requires -AcknowledgeImportRunsAsServiceIdentity."
}
if (-not $AcknowledgeGrantBatchLogonRight) {
    throw "Apply requires -AcknowledgeGrantBatchLogonRight because password tasks need SeBatchLogonRight."
}
if (-not $AcknowledgeOneTimePasswordRotation) {
    throw "Apply requires -AcknowledgeOneTimePasswordRotation for the temporary and final service-account password rotations."
}
if ($ExpectedExportBytes -le 0) {
    throw "Apply requires the exact non-zero -ExpectedExportBytes reported by plan mode."
}
if ([string]::IsNullOrWhiteSpace($ExpectedServiceAccountSid)) {
    throw "Apply requires -ExpectedServiceAccountSid reported by plan mode."
}
if ($account.SID.Value -ne $ExpectedServiceAccountSid) {
    throw "Service-account SID mismatch. Expected $ExpectedServiceAccountSid, got $($account.SID.Value)."
}

$serviceSid = [Security.Principal.SecurityIdentifier]::new($account.SID.Value)
$allowedSids = @("S-1-5-18", "S-1-5-32-544", $serviceSid.Value)
$destinationExisted = Test-Path -LiteralPath $DestinationPath -PathType Container
$batchLogonEvidence = Grant-ExactBatchLogonRight $serviceSid.Value

foreach ($directory in @($DestinationPath, $TaskRoot)) {
    if (Test-Path -LiteralPath $directory) {
        Assert-NotReparsePoint $directory "Migration directory"
    }
    else {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    Set-Acl -LiteralPath $directory -AclObject (New-ProtectedDirectoryAcl $serviceSid)
    Assert-ProtectedAcl $directory $allowedSids
}
Set-Acl -LiteralPath $ExportPath -AclObject (New-ProtectedExportAcl $serviceSid)
Assert-ProtectedAcl $ExportPath $allowedSids

if (-not $destinationExisted) {
    $destinationItems = @(Get-ChildItem -LiteralPath $DestinationPath -Force)
    if ($destinationItems.Count -ne 0) {
        throw "New destination directory is unexpectedly non-empty: $DestinationPath"
    }
}

$workerSource = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DistroName,
    [Parameter(Mandatory = $true)][string]$ExportPath,
    [Parameter(Mandatory = $true)][string]$DestinationPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSid,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][int]$ImportTimeoutSeconds
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-Distros {
    $lines = @(& wsl.exe --list --quiet 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Unable to list WSL distributions: $($lines -join ' ')" }
    return @($lines | ForEach-Object { ([string]$_).Trim([char]0).Trim() } | Where-Object { $_ })
}

try {
    $actualSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($actualSid -ne $ExpectedSid) { throw "Worker identity SID mismatch." }
    $destination = [IO.Path]::GetFullPath($DestinationPath).TrimEnd('\')
    $distros = @(Get-Distros)
    $operation = "verified-existing"
    if ($distros -notcontains $DistroName) {
        if (@(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
            throw "Destination must be empty before first import."
        }
        $process = Start-Process -FilePath "wsl.exe" -ArgumentList @(
            "--import", $DistroName, $destination, $ExportPath, "--version", "2"
        ) -NoNewWindow -PassThru -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        if (-not $process.WaitForExit($ImportTimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            $process.WaitForExit()
            throw "wsl.exe --import exceeded its $ImportTimeoutSeconds second timeout and was terminated."
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "wsl.exe --import failed with exit code $($process.ExitCode)." }
        $operation = "imported"
        $distros = @(Get-Distros)
    }
    if ($distros -notcontains $DistroName) { throw "Imported distro is not visible under the service identity." }

    $registrations = @(Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction Stop |
        ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } |
        Where-Object { $_.DistributionName -eq $DistroName })
    if ($registrations.Count -ne 1) { throw "Expected exactly one HKCU WSL registration for $DistroName." }
    $registration = $registrations[0]
    $registeredBasePath = [IO.Path]::GetFullPath([string]$registration.BasePath).TrimEnd('\')
    if ($registeredBasePath -ne $destination) { throw "Imported distro BasePath mismatch." }
    if ([int]$registration.Version -ne 2) { throw "Imported distro is not WSL2." }

    $result = [ordered]@{
        status = "verified"
        operation = $operation
        identity_sid = $actualSid
        distro_name = $DistroName
        base_path = $registeredBasePath
        version = [int]$registration.Version
        verified_at = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    exit 0
}
catch {
    $failure = [ordered]@{
        status = "failed"
        identity_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        message = $_.Exception.Message
        failed_at = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $failure | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    exit 1
}
'@

[IO.File]::WriteAllText($WorkerPath, $workerSource, [Text.UTF8Encoding]::new($false))
Set-Acl -LiteralPath $WorkerPath -AclObject (New-ProtectedExportAcl $serviceSid)
Assert-ProtectedAcl $WorkerPath $allowedSids
foreach ($artifact in @($ResultPath, $StdoutPath, $StderrPath)) {
    if (Test-Path -LiteralPath $artifact) {
        Remove-Item -LiteralPath $artifact -Force
    }
}

$accountId = "$env:COMPUTERNAME\$($account.Name)"
$powerShellExe = Join-Path $PSHOME "powershell.exe"
if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
    $powerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
}
$quotedArguments = @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $WorkerPath),
    '-DistroName', ('"{0}"' -f $ImportedDistroName),
    '-ExportPath', ('"{0}"' -f $ExportPath),
    '-DestinationPath', ('"{0}"' -f $DestinationPath),
    '-ExpectedSid', ('"{0}"' -f $serviceSid.Value),
    '-ResultPath', ('"{0}"' -f $ResultPath),
    '-StdoutPath', ('"{0}"' -f $StdoutPath),
    '-StderrPath', ('"{0}"' -f $StderrPath),
    '-ImportTimeoutSeconds', ([Math]::Max(30, $TimeoutSeconds - 30).ToString())
) -join ' '
$registered = $false
$temporaryPasswordApplied = $false
$temporaryPassword = $null
$passwordRotationStartedAt = $null
$passwordRotationCompletedAt = $null
$finalPasswordRotatedAt = $null
$completionEvidence = $null
try {
    $temporaryPassword = New-CryptographicAccountPassword
    $passwordRotationStartedAt = [DateTimeOffset]::UtcNow
    Set-LocalUser -Name $account.Name -Password $temporaryPassword -ErrorAction Stop
    $temporaryPasswordApplied = $true
    $passwordRotationCompletedAt = [DateTimeOffset]::UtcNow

    $registeredTask = Register-PasswordImportTask `
        -Name $TaskName `
        -UserId $accountId `
        -Executable $powerShellExe `
        -Arguments $quotedArguments `
        -ExecutionTimeoutSeconds $TimeoutSeconds `
        -AccountPassword $temporaryPassword
    $registered = $true
    $temporaryPassword.Dispose()
    $temporaryPassword = $null
    $taskPostcondition = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($taskPostcondition.Principal.LogonType -ne "Password") {
        throw "Registered task failed the Password logon-type postcondition."
    }
    if ($taskPostcondition.Principal.RunLevel -ne "Limited") {
        throw "Registered task failed the limited run-level postcondition."
    }
    if (@($accountId, $serviceSid.Value) -notcontains $taskPostcondition.Principal.UserId) {
        throw "Registered task failed the service-identity postcondition."
    }
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

    $deadline = $startedAt.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $taskState = (Get-ScheduledTask -TaskName $TaskName).State
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        $completed = [string]$taskState -eq "Ready" -and
            $taskInfo.LastRunTime -ge $startedAt
    } while (-not $completed -and (Get-Date) -lt $deadline)

    if (-not $completed) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        throw "Timed out waiting for one-time import task after $TimeoutSeconds seconds."
    }
    if ($taskInfo.LastTaskResult -ne 0) {
        $workerFailure = if (Test-Path -LiteralPath $ResultPath) { Get-Content -LiteralPath $ResultPath -Raw } else { "no result file" }
        throw "One-time import task failed with result $($taskInfo.LastTaskResult): $workerFailure"
    }
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw "One-time import task reported success without a result file."
    }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if ($result.status -ne "verified" -or $result.identity_sid -ne $serviceSid.Value) {
        throw "Worker result did not verify the expected service identity."
    }
    if ($result.distro_name -ne $ImportedDistroName -or [int]$result.version -ne 2) {
        throw "Worker result did not verify the expected WSL2 distro."
    }
    if ((Get-NormalizedPath ([string]$result.base_path)) -ne (Get-NormalizedPath $DestinationPath)) {
        throw "Worker result did not verify the exact destination path."
    }

    $distrosAfter = @(Get-WslDistros)
    if ($distrosAfter -notcontains $SourceDistroName) {
        throw "Source distro disappeared from the operator identity; preservation invariant failed."
    }
    if (-not (Test-Path -LiteralPath $ExportPath -PathType Leaf)) {
        throw "Export disappeared; preservation invariant failed."
    }
    $hashAfter = (Get-FileHash -LiteralPath $ExportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sizeAfter = (Get-Item -LiteralPath $ExportPath).Length
    if ($hashAfter -ne $actualHash -or $sizeAfter -ne $ExpectedExportBytes) {
        throw "Export changed during migration; preservation invariant failed."
    }

    $completionEvidence = [ordered]@{
        status = "complete"
        imported_distro = $ImportedDistroName
        service_account_sid = $serviceSid.Value
        batch_logon_right = $batchLogonEvidence
        destination_path = $DestinationPath
        source_distro_preserved = $true
        export_preserved = $true
        export_sha256 = $hashAfter
        export_bytes = $sizeAfter
        worker_result = $result
    }
}
finally {
    $cleanupFailures = @()
    $finalPasswordRotated = $false
    $taskDeleted = $false
    if ($temporaryPasswordApplied) {
        $finalPassword = $null
        try {
            $finalPassword = New-CryptographicAccountPassword
            Set-LocalUser -Name $account.Name -Password $finalPassword -ErrorAction Stop
            $finalPasswordRotated = $true
            $finalPasswordRotatedAt = [DateTimeOffset]::UtcNow
        }
        catch {
            $cleanupFailures += "Final service-account password rotation failed: $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $finalPassword) { $finalPassword.Dispose() }
        }
    }
    if ($null -ne $temporaryPassword) { $temporaryPassword.Dispose() }
    if ($registered) {
        try {
            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if ([string]$existingTask.State -eq "Running") {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                $stopDeadline = (Get-Date).AddSeconds(30)
                do {
                    Start-Sleep -Milliseconds 500
                    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                } while ([string]$existingTask.State -eq "Running" -and (Get-Date) -lt $stopDeadline)
                if ([string]$existingTask.State -eq "Running") {
                    throw "Task remained running after the bounded cleanup stop."
                }
            }
            $scheduler = New-Object -ComObject "Schedule.Service"
            $scheduler.Connect()
            $folder = $scheduler.GetFolder("\")
            $folder.DeleteTask($TaskName, 0)
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
                throw "Task still exists after DeleteTask."
            }
            $taskDeleted = $true
        }
        catch {
            $cleanupFailures += "One-time task deletion failed: $($_.Exception.Message)"
        }
    }
    else {
        $taskDeleted = $true
    }

    $passwordCleanupEvidence = [ordered]@{
        service_account_sid = $serviceSid.Value
        temporary_rotation_started_at = if ($null -ne $passwordRotationStartedAt) { $passwordRotationStartedAt.ToString("o") } else { $null }
        temporary_rotation_completed = $temporaryPasswordApplied
        temporary_rotation_completed_at = if ($null -ne $passwordRotationCompletedAt) { $passwordRotationCompletedAt.ToString("o") } else { $null }
        final_rotation_completed = $finalPasswordRotated
        final_rotation_completed_at = if ($null -ne $finalPasswordRotatedAt) { $finalPasswordRotatedAt.ToString("o") } else { $null }
        one_time_task_deleted = $taskDeleted
        stored_task_credential_invalidated = $finalPasswordRotated
        password_material_logged_or_persisted = $false
    }
    if ($null -ne $completionEvidence) {
        $completionEvidence.account_password_rotation = $passwordCleanupEvidence
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "Fail-closed cleanup error. Password/task evidence: $($passwordCleanupEvidence | ConvertTo-Json -Compress). Errors: $($cleanupFailures -join '; ')"
    }
}

$completionEvidence | ConvertTo-Json -Depth 8
