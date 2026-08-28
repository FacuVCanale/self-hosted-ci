from pathlib import Path
import shutil
import subprocess
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
            "self-hosted-ci-bootstrap-evidence-collect",
            "RuntimeMaxSec=600",
            "KillMode=control-group",
            "Stop-WslCollectionUnit",
            "WSL collection unit cgroup still contains processes",
        ):
            self.assertIn(token, self.source)

    def test_stages_wsl_collector_by_stdin_without_drvfs(self):
        for token in (
            'collectorLinuxRoot = "/run/self-hosted-ci-bootstrap-evidence"',
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
            "os.unlink(target) if os.path.lexists(target) else None",
            'temporary=os.path.join(root,".collector.tmp")',
            "os.rmdir(root)",
            "WSL collector staging cleanup failed",
            "finally {",
            "`$stageAttempted = `$true",
            "if (`$stageAttempted)",
            'if (`$collectionFailure) { throw `$collectionFailure }',
            "WSL evidence collector timed out and its systemd unit was terminated",
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
            "New-PrivateAcl $false",
            "SetAccessRuleProtection($true, $false)",
            "foreach ($sid in @($system, $admins))",
            "bootstrap_ready = $true",
        ):
            self.assertIn(token, self.source)

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
