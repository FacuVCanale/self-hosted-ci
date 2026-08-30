$ErrorActionPreference = "Stop"

function Invoke-SchedulerObservation([string]$Operation, [scriptblock]$Action) {
    $failures = [Collections.Generic.List[string]]::new()
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try { return & $Action }
        catch {
            $exception = $_.Exception
            $hresult = "0x{0:X8}" -f $exception.HResult
            $failures.Add("attempt=$attempt type=$($exception.GetType().FullName) hresult=$hresult message=$($exception.Message)")
            if ($attempt -eq 5) { throw "$Operation failed after bounded read-only retries: $($failures -join ' | ')" }
            Start-Sleep -Milliseconds (200 * $attempt)
        }
    }
}

$attempts = 0
$result = Invoke-SchedulerObservation "test observation" {
    $script:attempts++
    if ($script:attempts -lt 3) { throw [UnauthorizedAccessException]::new("Access denied") }
    return "observed"
}
if ($result -ne "observed" -or $attempts -ne 3) { throw "transient retry contract failed" }

$attempts = 0
try {
    Invoke-SchedulerObservation "test exhaustion" {
        $script:attempts++
        throw [UnauthorizedAccessException]::new("Access denied")
    }
    throw "exhaustion contract did not fail"
}
catch {
    if ($_.Exception.Message -notmatch "attempt=5" -or $_.Exception.Message -notmatch "hresult=0x80070005") { throw }
}
if ($attempts -ne 5) { throw "retry budget was not exact" }

@{status="passed"; transient_attempts=3; exhausted_attempts=5; hresult="0x80070005"} | ConvertTo-Json -Compress
