from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/diagnose-s4u-task.ps1"


class S4UDiagnosticScriptTests(unittest.TestCase):
    def test_interpolated_task_name_is_delimited_before_colon(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("diagnostic task ${taskName}:", source)
        self.assertNotIn("diagnostic task $taskName:", source)

    def test_compares_name_sid_and_schtasks_np_with_disposable_tasks(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Test-ComS4URegistration $taskNames[0]", source)
        self.assertIn("Test-ComS4URegistration $taskNames[1] $account.SID.Value", source)
        self.assertIn("Test-SchtasksNoPasswordRegistration $taskNames[2]", source)
        self.assertIn('"/RU", $UserId, "/NP", "/RL", "LIMITED"', source)
        self.assertIn("registered_logon_type", source)
        self.assertIn("registered_run_level", source)
        self.assertIn("/Query /TN $TaskName /XML", source)
        self.assertIn('.DeleteTask($taskName, 0)', source)
        self.assertIn("finally {", source)

    def test_is_diagnostic_only_and_never_invokes_wsl_or_changes_rights(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8").lower()
        self.assertNotIn("wsl.exe", source)
        self.assertNotIn("lsaaddaccountrights", source)
        self.assertNotIn("lsaremoveaccountrights", source)
        self.assertNotIn("secedit", source)
        self.assertIn("destructive_actions = $false", source)
        self.assertIn("rights_changed = $false", source)

    def test_captures_account_policy_service_acl_hresult_and_events(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "LsaEnumerateAccountRights",
            "PasswordRequired",
            "LimitBlankPasswordUse",
            "Get-Service -Name Schedule",
            'Get-Acl -LiteralPath "$env:SystemRoot\\System32\\Tasks"',
            "Get-HResultHex",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-TaskScheduler/Maintenance",
        ):
            self.assertIn(token, source)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_script_parses_in_powershell(self) -> None:
        command = (
            "$errors=$null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}',[ref]$null,[ref]$errors); "
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
        )
        result = subprocess.run(["pwsh", "-NoProfile", "-Command", command], text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
