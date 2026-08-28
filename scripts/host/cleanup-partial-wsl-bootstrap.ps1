[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedServiceAccountSid,
    [string]$ServiceAccount = "selfhosted-ci-svc",
    [string]$DistroName = "Ubuntu-24.04-CI",
    [switch]$Apply,
    [switch]$AcknowledgePartialTlsCleanup,
    [switch]$AcknowledgeOneTimePasswordRotation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$taskName = "SelfHostedCI-Cleanup-Partial-WSL-Bootstrap"
$root = "C:\ProgramData\self-hosted-ci\partial-bootstrap-cleanup"
$workerPath = Join-Path $root "worker.ps1"
$resultPath = Join-Path $root "result.json"
$powershellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return ConvertTo-SecureString ("Aa1!" + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    } finally { [Array]::Clear($bytes, 0, $bytes.Length); $rng.Dispose() }
}

function Register-OneShot([string]$UserId, [Security.SecureString]$Password) {
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect()
        $definition = $scheduler.NewTask(0)
        $definition.Principal.UserId = $UserId; $definition.Principal.LogonType = 1; $definition.Principal.RunLevel = 0
        $definition.Settings.Enabled = $true; $definition.Settings.AllowDemandStart = $true
        $definition.Settings.StartWhenAvailable = $false; $definition.Settings.ExecutionTimeLimit = "PT5M"
        $action = $definition.Actions.Create(0); $action.Path = $powershellExe
        $action.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`""
        return $scheduler.GetFolder("\").RegisterTaskDefinition($taskName, $definition, 6, $UserId, $plain, 1, $null)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "elevated console required" }
if ($ServiceAccount -ne "selfhosted-ci-svc" -or $DistroName -ne "Ubuntu-24.04-CI") { throw "identity and distro are pinned" }
$service = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
if ($service.SID.Value -ne $ExpectedServiceAccountSid) { throw "service SID mismatch" }
[ordered]@{ mode = $(if ($Apply) { "apply" } else { "plan" }); task = $taskName; operation = "remove exact incomplete Incus GARM TLS artifacts only" } | ConvertTo-Json -Compress
if (-not $Apply) { return }
if (-not $AcknowledgePartialTlsCleanup -or -not $AcknowledgeOneTimePasswordRotation) { throw "apply acknowledgements are required" }

$registered = $false; $passwordChanged = $false; $password = $null
try {
    if (Test-Path -LiteralPath $root) { throw "cleanup staging already exists" }
    [void](New-Item -ItemType Directory -Path $root)
    $worker = @"
`$ErrorActionPreference = 'Stop'
& wsl.exe -d '$DistroName' -u root -- /bin/rm -f -- /etc/self-hosted-ci/garm/incus-client.crt /etc/self-hosted-ci/garm/incus-client.key /etc/self-hosted-ci/garm/incus-server.crt /etc/self-hosted-ci/garm/garm-provider-incus.toml
if (`$LASTEXITCODE -ne 0) { throw 'exact WSL cleanup failed' }
[IO.File]::WriteAllText('$resultPath', '{"status":"cleaned"}', [Text.UTF8Encoding]::new(`$false))
"@
    [IO.File]::WriteAllText($workerPath, $worker, [Text.UTF8Encoding]::new($false))
    $password = New-RandomPassword; Set-LocalUser -Name $ServiceAccount -Password $password; $passwordChanged = $true
    [void](Register-OneShot "$env:COMPUTERNAME\$ServiceAccount" $password); $registered = $true
    $password.Dispose(); $password = $null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddMinutes(5)
    do { Start-Sleep -Seconds 1; $state = (Get-ScheduledTask -TaskName $taskName).State } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if ($state -eq 'Running' -or $info.LastTaskResult -ne 0 -or -not (Test-Path -LiteralPath $resultPath)) { throw "one-shot cleanup failed" }
    Get-Content -LiteralPath $resultPath -Raw
} finally {
    if ($registered) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    if ($passwordChanged) { $replacement = New-RandomPassword; try { Set-LocalUser -Name $ServiceAccount -Password $replacement } finally { $replacement.Dispose() } }
    if ($password) { $password.Dispose() }
}
