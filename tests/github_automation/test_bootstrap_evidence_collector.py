from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/host/collect-wsl-jit-bootstrap-evidence.ps1"


class BootstrapEvidenceCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = COLLECTOR.read_text(encoding="utf-8")

    def test_is_elevated_plan_only_by_default(self):
        for token in (
            "collector requires an elevated Windows console",
            'mode = $(if ($Apply) { "apply" } else { "plan" })',
            "if (-not $Apply) { return }",
            "AcknowledgeBootstrapEvidenceCollection",
            "AcknowledgeOneTimePasswordRotation",
            'no_host_changes = (-not [bool]$Apply)',
        ):
            self.assertIn(token, self.source)

    def test_runs_windows_then_exact_wsl_collectors(self):
        windows = self.source.index("& $WindowsCollectorPath")
        scheduled = self.source.index("Start-ScheduledTask -TaskName $TaskName")
        self.assertLess(windows, scheduled)
        for token in (
            "collect-windows-wsl-semantic-contract.ps1",
            "collect-wsl-jit-semantic-observations.py",
            'WSL_DISTRO_NAME") != "Ubuntu-24.04-CI"',
            "WSL collector sha256 mismatch",
            'collectionUnit = "self-hosted-ci-bootstrap-evidence-collect-$attemptId"',
            "RuntimeMaxSec=$SystemdTimeoutSeconds",
            "KillMode=control-group",
            "Stop-WslCollectionUnit",
            "WSL collection unit cgroup still contains processes",
        ):
            self.assertIn(token, self.source)

    def test_stages_wsl_collector_by_stdin_without_drvfs(self):
        for token in (
            'collectorLinuxRoot = "/run/self-hosted-ci-bootstrap-evidence-$attemptId"',
            "RedirectStandardInput = `$true",
            "StandardInput.BaseStream.Write",
            "WSL collector byte count mismatch",
            "WSL collector sha256 mismatch during staging",
            "staged WSL collector verification failed",
            "details.st_uid != 0",
            "(details.st_mode & 0o777) != 0o600",
            "os.mkdir(root, 0o700)",
            "root_details.st_uid != 0",
            "(root_details.st_mode & 0o777) != 0o700",
        ):
            self.assertIn(token, self.source)
        for forbidden in ("/mnt/c/", "drvfs"):
            self.assertNotIn(forbidden, self.source)

    def test_wsl_staging_cleanup_is_fail_closed_on_all_collection_paths(self):
        for token in (
            "function Remove-WslCollectorStage",
            "if os.path.lexists(path): os.unlink(path)",
            'temporary=os.path.join(root,".collector.tmp")',
            "os.rmdir(root)",
            "WSL collector staging cleanup failed",
            "finally {",
            "`$stageAttempted = `$true",
            "if (`$stageAttempted)",
            "if (`$collectionFailure) {",
            "throw `$collectionFailure",
            "WSL evidence transport exceeded its nested timeout",
            "Complete-WslCollectionCleanup",
            "Assert-WslCollectorStageAbsent",
            "cleanup_verified=`$true",
        ):
            self.assertIn(token, self.source)

    def test_staging_cleanup_program_is_idempotent_and_reports_exact_residue(self):
        match = re.search(
            r"`\$cleanupProgram = '(.*?)'\n    `\$cleanup =",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        cleanup_program = match.group(1)
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "stage"
            root.mkdir()
            target = root / "collector.py"
            target.write_text("payload", encoding="utf-8")
            first = subprocess.run(
                ["python3", "-c", cleanup_program, str(root), str(target)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            second = subprocess.run(
                ["python3", "-c", cleanup_program, str(root), str(target)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, second.returncode, second.stderr)

            root.mkdir()
            target.write_text("payload", encoding="utf-8")
            (root / "unexpected").write_text("residue", encoding="utf-8")
            dirty = subprocess.run(
                ["python3", "-c", cleanup_program, str(root), str(target)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(1, dirty.returncode)
            self.assertIn("root cleanup failed (OSError)", dirty.stderr)
            self.assertIn("entries=['unexpected']", dirty.stderr)
            self.assertIn("remaining=root", dirty.stderr)

    def test_cleanup_observes_unloaded_unit_before_mutation_and_preserves_detail(self):
        stop = self.source.index("function Stop-WslCollectionUnit")
        initial_load_state = self.source.index("`$unitShow = Get-WslCollectionUnitLoadState", stop)
        not_found_guard = self.source.index("if (-not (Test-WslCollectionUnitNotFound `$unitShow))", initial_load_state)
        kill = self.source.index("@('kill', '--kill-whom=all'", not_found_guard)
        self.assertLess(initial_load_state, not_found_guard)
        self.assertLess(not_found_guard, kill)
        for token in (
            "function Invoke-WslCleanupCommand",
            "function Test-WslCollectionUnitNotFound",
            "function Get-WslCollectionUnitLoadState",
            "WSL collection unit LoadState probe failed",
            "WSL collection unit cleanup command failed",
            "root cleanup failed",
            "entries=",
            "remaining=",
            "WSL collector staging cleanup failed (exit=",
            "WSL collector staging absence could not be verified (exit=",
        ):
            self.assertIn(token, self.source)

    def test_one_shot_is_password_limited_and_exact(self):
        for token in (
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA / Limited",
            "one-shot task principal postcondition failed",
            "one-shot task action postcondition failed",
            "one-shot task settings postcondition failed",
            'ServiceAccount = "selfhosted-ci-svc"',
            'DistroName = "Ubuntu-24.04-CI"',
            "Assert-NonAdmin $service",
        ):
            self.assertIn(token, self.source)

    def test_preserves_both_private_content_addressed_documents(self):
        for token in (
            'OutputRoot = "C:\\ProgramData\\self-hosted-ci\\bootstrap-evidence\\v1"',
            'Save-ContentAddressedJson $windowsEvidencePath "windows-wsl-semantic-contract"',
            'Save-ContentAddressedJson $WslStagingPath "wsl-jit-semantic-observations"',
            '"$Prefix-$sha256.json"',
            "content-addressed evidence collision",
            "evidence source changed while it was being preserved",
            "[IO.File]::Move($temporary, $destination)",
            "New-PrivateAcl $false",
            "SetAccessRuleProtection($true, $false)",
            "foreach ($sid in @($system, $admins))",
            "bootstrap_ready = $true",
        ):
            self.assertIn(token, self.source)

    def test_scheduler_polling_waits_for_a_real_run_and_allows_pending_codes(self):
        for token in (
            "$baselineLastRunTime = [DateTime]$baselineInfo.LastRunTime",
            "$lastRunAdvanced = [DateTime]$info.LastRunTime -gt $baselineLastRunTime",
            '$taskState -eq "Running"',
            "$resultPresent",
            "$runObserved = $runObserved -or $lastRunAdvanced",
            "[uint32]267008, [uint32]267009, [uint32]267011",
            "$complete = $runObserved",
            "result_present=$resultPresent",
        ):
            self.assertIn(token, self.source)
        start = self.source.index("Start-ScheduledTask -TaskName $TaskName")
        baseline = self.source.index("$baselineLastRunTime")
        self.assertLess(baseline, start)

    def test_timeouts_are_strictly_nested_and_reserve_cleanup(self):
        expected = (
            "$StageTimeoutSeconds = 45",
            "$CollectorTimeoutSeconds = 330",
            "$SystemdTimeoutSeconds = 360",
            "$WslTimeoutSeconds = 390",
            "$WorkerCleanupBudgetSeconds = 60",
            "$TaskTimeoutSeconds = 570",
            "$ParentTimeoutSeconds = 600",
            "$CleanupBudgetSeconds = $ParentTimeoutSeconds - $TaskTimeoutSeconds",
            'ExecutionTimeLimit = "PT9M"',
            "$StageTimeoutSeconds + $WslTimeoutSeconds + $WorkerCleanupBudgetSeconds",
            "runtime timeout hierarchy is invalid",
        )
        for token in expected:
            self.assertIn(token, self.source)

    def test_worker_and_parent_preserve_diagnostics_before_cleanup(self):
        for token in (
            'DiagnosticsRoot = "C:\\ProgramData\\self-hosted-ci\\diagnostics\\bootstrap-evidence\\v1"',
            "function Save-FailureDiagnostics",
            'status=\'failed\'; error=`$collectionFailure',
            "worker.stdout.log",
            "worker.stderr.log",
            "collect-result.json",
            "failure.json",
            "Task state/result:",
        ):
            self.assertIn(token, self.source)
        preserve = self.source.rindex("Save-FailureDiagnostics $original")
        cleanup = self.source.rindex("Remove-Item -LiteralPath $Root -Recurse -Force")
        self.assertLess(preserve, cleanup)
        quiesce = self.source.rindex("Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop")
        self.assertLess(quiesce, preserve)
        self.assertIn("task did not quiesce before diagnostic preservation", self.source)

    def test_stage_drains_pipes_before_writing_stdin(self):
        start = self.source.index("if (-not `$stageProcess.Start())")
        stdout = self.source.index("`$stageStdoutTask =", start)
        stderr = self.source.index("`$stageStderrTask =", start)
        write = self.source.index("StandardInput.BaseStream.Write", start)
        self.assertLess(stdout, write)
        self.assertLess(stderr, write)

    def test_rotates_credentials_and_cleans_task_and_staging(self):
        for token in (
            "New-CryptographicAccountPassword",
            "Set-LocalUser -Name $service.Name -Password $temporaryPassword",
            "Set-LocalUser -Name $service.Name -Password $finalPassword",
            "Set-LocalUser -Name $service.Name -Password $recoveryPassword",
            "Unregister-ScheduledTask",
            "Remove-Item -LiteralPath $Root -Recurse -Force",
            "one_shot_task_absent = $true",
            "stored_task_credential_invalidated = $true",
        ):
            self.assertIn(token, self.source)

    def test_collection_has_no_github_runner_or_activation_mutation(self):
        for token in (
            "github_contacted = $false",
            "runner_registration_changed = $false",
            "activation_changed = $false",
        ):
            self.assertIn(token, self.source)
        for forbidden in (
            "github.com",
            "config.sh",
            "ACTIVATION_APPROVED",
            "outbound-worker.runtime-ready",
        ):
            self.assertNotIn(forbidden, self.source)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_script_parses_in_powershell(self):
        command = (
            "$errors=$null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{COLLECTOR}',[ref]$null,[ref]$errors); "
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
        )
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", command],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
