[CmdletBinding()]
param(
    [string]$ServiceAccount = "selfhosted-ci-svc"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-DiagnosticPreconditions {
    if ($env:OS -ne "Windows_NT") {
        throw "Run this diagnostic on Windows."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this diagnostic from an elevated local PowerShell console."
    }
    if (-not [Environment]::UserInteractive -or $Host.Name -ne "ConsoleHost") {
        throw "Run this diagnostic interactively from a local PowerShell console."
    }
}

function Initialize-ReadOnlyLsaApi {
    if ("SelfHostedCi.ReadOnlyLsaRights" -as [type]) {
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
    public static class ReadOnlyLsaRights
    {
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
        private static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr ObjectHandle);

        private static void ThrowOnError(uint status, string operation)
        {
            if (status == 0) return;
            int win32 = unchecked((int)LsaNtStatusToWinError(status));
            throw new Win32Exception(win32, operation + " failed");
        }

        public static string[] GetAccountRights(string sidValue)
        {
            IntPtr policy = IntPtr.Zero;
            IntPtr sidPointer = IntPtr.Zero;
            IntPtr rightsBuffer = IntPtr.Zero;
            try
            {
                LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
                attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
                ThrowOnError(LsaOpenPolicy(
                    IntPtr.Zero, ref attributes, POLICY_LOOKUP_NAMES, out policy), "LsaOpenPolicy");

                SecurityIdentifier sid = new SecurityIdentifier(sidValue);
                byte[] sidBytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBytes, 0);
                sidPointer = Marshal.AllocHGlobal(sidBytes.Length);
                Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);

                uint count;
                uint status = LsaEnumerateAccountRights(policy, sidPointer, out rightsBuffer, out count);
                if (status == STATUS_OBJECT_NAME_NOT_FOUND) return new string[0];
                ThrowOnError(status, "LsaEnumerateAccountRights");

                List<string> result = new List<string>();
                int itemSize = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                for (uint index = 0; index < count; index++)
                {
                    IntPtr itemPointer = new IntPtr(rightsBuffer.ToInt64() + ((long)index * itemSize));
                    LSA_UNICODE_STRING item = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        itemPointer, typeof(LSA_UNICODE_STRING));
                    string value = Marshal.PtrToStringUni(item.Buffer, item.Length / 2);
                    if (!String.IsNullOrEmpty(value)) result.Add(value);
                }
                return result.ToArray();
            }
            finally
            {
                if (rightsBuffer != IntPtr.Zero) LsaFreeMemory(rightsBuffer);
                if (sidPointer != IntPtr.Zero) Marshal.FreeHGlobal(sidPointer);
                if (policy != IntPtr.Zero) LsaClose(policy);
            }
        }
    }
}
'@
}

function Get-HResultHex([Exception]$Exception) {
    return "0x$($Exception.HResult.ToString('X8'))"
}

function Get-PrincipalEvidence([object]$Account) {
    Initialize-ReadOnlyLsaApi
    $groups = @()
    foreach ($group in @(Get-LocalGroup)) {
        $members = @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue)
        if ($members.SID.Value -contains $Account.SID.Value) {
            $groups += [ordered]@{
                name = $group.Name
                sid = $group.SID.Value
                rights = @([SelfHostedCi.ReadOnlyLsaRights]::GetAccountRights($group.SID.Value) | Sort-Object)
            }
        }
    }
    $cimAccount = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$($Account.Name.Replace("'", "''"))'"
    return [ordered]@{
        name = $Account.Name
        canonical_name = "$env:COMPUTERNAME\$($Account.Name)"
        sid = $Account.SID.Value
        enabled = $Account.Enabled
        principal_source = [string]$Account.PrincipalSource
        password_required = if ($null -ne $cimAccount) { [bool]$cimAccount.PasswordRequired } else { $null }
        password_expires = $Account.PasswordExpires
        user_may_change_password = $Account.UserMayChangePassword
        locked_out = if ($null -ne $cimAccount) { [bool]$cimAccount.Lockout } else { $null }
        direct_rights = @([SelfHostedCi.ReadOnlyLsaRights]::GetAccountRights($Account.SID.Value) | Sort-Object)
        direct_groups = $groups
        limit_blank_password_use = (Get-ItemPropertyValue `
            -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue)
    }
}

function Test-ComS4URegistration([string]$TaskName, [string]$UserId) {
    $started = [DateTimeOffset]::UtcNow
    try {
        $scheduler = New-Object -ComObject "Schedule.Service"
        $scheduler.Connect()
        $folder = $scheduler.GetFolder("\")
        $definition = $scheduler.NewTask(0)
        $definition.RegistrationInfo.Description = "Disposable S4U registration diagnostic"
        $definition.Principal.UserId = $UserId
        $definition.Principal.LogonType = 2
        $definition.Principal.RunLevel = 0
        $definition.Settings.Enabled = $true
        $definition.Settings.AllowDemandStart = $true
        $action = $definition.Actions.Create(0)
        $action.Path = "$env:SystemRoot\System32\cmd.exe"
        $action.Arguments = "/d /c exit 0"
        $registered = $folder.RegisterTaskDefinition($TaskName, $definition, 2, $UserId, $null, 2, $null)
        if ($null -eq $registered) { throw "Task Scheduler returned no task object." }
        return [ordered]@{
            surface = "TaskScheduler.COM"
            user_id = $UserId
            task_name = $TaskName
            registered = $true
            registered_user_id = $registered.Definition.Principal.UserId
            registered_logon_type = [string]$registered.Definition.Principal.LogonType
            registered_run_level = [string]$registered.Definition.Principal.RunLevel
            hresult = "0x00000000"
            error = $null
            attempted_at = $started.ToString("o")
        }
    }
    catch {
        return [ordered]@{
            surface = "TaskScheduler.COM"
            user_id = $UserId
            task_name = $TaskName
            registered = $false
            hresult = Get-HResultHex $_.Exception
            error = $_.Exception.Message
            attempted_at = $started.ToString("o")
        }
    }
}

function Test-SchtasksNoPasswordRegistration([string]$TaskName, [string]$UserId) {
    $arguments = @(
        "/Create", "/TN", $TaskName,
        "/TR", "cmd.exe /d /c exit 0",
        "/SC", "DAILY", "/ST", "23:59",
        "/RU", $UserId, "/NP", "/RL", "LIMITED", "/F", "/HResult"
    )
    $started = [DateTimeOffset]::UtcNow
    $output = @(& schtasks.exe @arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $registeredUserId = $null
    $registeredLogonType = $null
    $registeredRunLevel = $null
    if ($exitCode -eq 0) {
        try {
            [xml]$taskXml = (& schtasks.exe /Query /TN $TaskName /XML 2>&1 | Out-String)
            $registeredUserId = [string]$taskXml.Task.Principals.Principal.UserId
            $registeredLogonType = [string]$taskXml.Task.Principals.Principal.LogonType
            $registeredRunLevel = [string]$taskXml.Task.Principals.Principal.RunLevel
        }
        catch {
            $output += "Task registered, but XML verification failed: $($_.Exception.Message)"
            $exitCode = 1
        }
    }
    return [ordered]@{
        surface = "schtasks.exe /NP"
        user_id = $UserId
        task_name = $TaskName
        registered = $exitCode -eq 0
        registered_user_id = $registeredUserId
        registered_logon_type = $registeredLogonType
        registered_run_level = $registeredRunLevel
        exit_code = $exitCode
        exit_code_hex = "0x$(([int]$exitCode).ToString('X8'))"
        output = $output
        attempted_at = $started.ToString("o")
    }
}

function Get-TaskSchedulerEvents([datetime]$StartTime, [string]$TaskPrefix) {
    $events = @()
    foreach ($logName in @(
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TaskScheduler/Maintenance",
        "System"
    )) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $matching = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $StartTime } `
                -ErrorAction Stop | Where-Object {
                    $_.ProviderName -eq "Microsoft-Windows-TaskScheduler" -or
                    $_.Message -like "*$TaskPrefix*"
                } | Select-Object -First 100)
            $events += [ordered]@{
                log_name = $logName
                enabled = $log.IsEnabled
                events = @($matching | ForEach-Object {
                    [ordered]@{
                        time_created = $_.TimeCreated.ToUniversalTime().ToString("o")
                        id = $_.Id
                        level = $_.LevelDisplayName
                        provider = $_.ProviderName
                        message = $_.Message
                    }
                })
            }
        }
        catch {
            $events += [ordered]@{
                log_name = $logName
                enabled = $false
                query_error = $_.Exception.Message
                events = @()
            }
        }
    }
    return $events
}

Assert-DiagnosticPreconditions
$account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
$taskService = Get-Service -Name Schedule -ErrorAction Stop
$diagnosticStarted = Get-Date
$taskPrefix = "SelfHostedCI-S4U-Diagnostic-$([Guid]::NewGuid().ToString('N'))"
$taskNames = @(
    "$taskPrefix-ComName",
    "$taskPrefix-ComSid",
    "$taskPrefix-SchtasksNP"
)
$results = @()
$cleanupFailures = @()

try {
    $results += Test-ComS4URegistration $taskNames[0] "$env:COMPUTERNAME\$($account.Name)"
    $results += Test-ComS4URegistration $taskNames[1] $account.SID.Value
    $results += Test-SchtasksNoPasswordRegistration $taskNames[2] "$env:COMPUTERNAME\$($account.Name)"
}
finally {
    foreach ($taskName in $taskNames) {
        try {
            $scheduler = New-Object -ComObject "Schedule.Service"
            $scheduler.Connect()
            $scheduler.GetFolder("\").DeleteTask($taskName, 0)
        }
        catch {
            if ($_.Exception.HResult -ne -2147024894) {
                $cleanupFailures += [ordered]@{
                    task_name = $taskName
                    hresult = Get-HResultHex $_.Exception
                    error = $_.Exception.Message
                }
                Write-Warning "Cleanup could not delete diagnostic task ${taskName}: $($_.Exception.Message)"
            }
        }
    }
}

$tasksDirectoryAcl = Get-Acl -LiteralPath "$env:SystemRoot\System32\Tasks"
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$report = [ordered]@{
    schema = "self-hosted-ci-s4u-diagnostic-v1"
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    destructive_actions = $false
    wsl_invoked = $false
    rights_changed = $false
    diagnostic_tasks_cleaned = $cleanupFailures.Count -eq 0
    cleanup_failures = $cleanupFailures
    current_process = [ordered]@{
        identity = $currentIdentity.Name
        sid = $currentIdentity.User.Value
        elevated = $true
        host = $Host.Name
        session_name = $env:SESSIONNAME
    }
    task_scheduler = [ordered]@{
        service_status = [string]$taskService.Status
        service_start_type = [string]$taskService.StartType
        tasks_directory_owner = $tasksDirectoryAcl.Owner
        tasks_directory_sddl = $tasksDirectoryAcl.Sddl
    }
    service_account = Get-PrincipalEvidence $account
    registration_attempts = $results
    events = @(Get-TaskSchedulerEvents $diagnosticStarted $taskPrefix)
    interpretation = @(
        "COM name succeeds but SID fails: use canonical account name; SID is rejected by this Task Scheduler build.",
        "COM SID succeeds but name fails: canonical-name resolution is the defect; bind the principal to the SID.",
        "schtasks /NP succeeds while both COM variants fail: use the supported /NP surface and verify its exported XML is S4U/Limited.",
        "all variants fail only when caller SID differs from target SID: Windows is enforcing the documented different-user credential boundary; SeBatchLogonRight is not the registration blocker.",
        "all three return access denied with SeBatchLogonRight present and no effective deny: inspect elevation/token filtering, Tasks directory/SYSTEM ACLs, and TaskScheduler events.",
        "registration succeeds but a later run fails: the registration path is sound; investigate effective batch-logon deny, account password state, and launch events separately."
    )
}
$report | ConvertTo-Json -Depth 10
