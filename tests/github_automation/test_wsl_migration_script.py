from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/migrate-ci-wsl.ps1"


class WslMigrationScriptTests(unittest.TestCase):
    def test_script_has_plan_only_default_and_explicit_apply_acknowledgements(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("[switch]$Apply", source)
        self.assertIn("if (-not $Apply)", source)
        self.assertIn("no ACL, scheduled-task, WSL registration, or filesystem changes were made", source)
        self.assertIn("[switch]$AcknowledgeSourceAndExportWillBePreserved", source)
        self.assertIn("[switch]$AcknowledgeImportRunsAsServiceIdentity", source)
        self.assertIn("[switch]$AcknowledgeGrantBatchLogonRight", source)
        self.assertIn("Apply requires -AcknowledgeGrantBatchLogonRight", source)
        self.assertIn("Apply requires the exact non-zero -ExpectedExportBytes", source)
        self.assertIn("Apply requires -ExpectedServiceAccountSid", source)

    def test_script_pins_source_export_hash_and_destination(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('$ExpectedSourceDistro = "Ubuntu-24.04"', source)
        self.assertIn('$ExpectedImportedDistro = "Ubuntu-24.04-CI"', source)
        self.assertIn(
            '$ExpectedExport = "C:\\ProgramData\\self-hosted-ci\\exports\\Ubuntu-24.04-20260827.tar"', source
        )
        self.assertIn('$ExpectedDestination = "C:\\ProgramData\\self-hosted-ci\\wsl"', source)
        self.assertIn("ad9e329eadc4211182c32d71a2830b6a492efedb2dc94735f3dd5287925ca0e9", source)
        self.assertIn("Get-FileHash -LiteralPath $ExportPath -Algorithm SHA256", source)
        self.assertIn("WSL export size mismatch", source)
        self.assertIn("Insufficient free disk space", source)

    def test_script_requires_elevation_local_nonadmin_account_and_protected_acls(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Test-IsAdministrator", source)
        self.assertIn('[Environment]::UserInteractive', source)
        self.assertIn('$Host.Name -ne "ConsoleHost"', source)
        self.assertIn('Get-LocalGroup -SID "S-1-5-32-544"', source)
        self.assertIn("must not be a member of the local Administrators group", source)
        self.assertIn("SetAccessRuleProtection($true, $false)", source)
        self.assertIn("Unexpected ACL identity", source)
        self.assertIn("Assert-NotReparsePoint", source)

    def test_script_imports_once_via_s4u_and_verifies_service_hkcu_registration(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("function Register-S4UImportTask", source)
        self.assertIn('$scheduler = New-Object -ComObject "Schedule.Service"', source)
        self.assertIn("$definition.Principal.LogonType = $taskLogonS4U", source)
        self.assertIn("$definition.Principal.RunLevel = $taskRunLevelLua", source)
        self.assertIn("$folder.RegisterTaskDefinition(", source)
        self.assertIn("Task Scheduler rejected the local-account S4U task before WSL was started", source)
        self.assertIn('"--import", $DistroName, $destination, $ExportPath, "--version", "2"', source)
        self.assertIn('"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"', source)
        self.assertIn("Worker identity SID mismatch", source)
        self.assertIn("Imported distro BasePath mismatch", source)
        self.assertIn("Imported distro is not WSL2", source)
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false", source)

    def test_task_registration_is_fail_fast_and_has_exact_postconditions(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        register = source.index("$registeredTask = Register-S4UImportTask")
        marked_registered = source.index("$registered = $true", register)
        postcondition = source.index("Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop", marked_registered)
        start = source.index("Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop", postcondition)
        self.assertLess(register, marked_registered)
        self.assertLess(marked_registered, postcondition)
        self.assertLess(postcondition, start)
        self.assertIn('Principal.LogonType -ne "S4U"', source)
        self.assertIn('Principal.RunLevel -ne "Limited"', source)
        self.assertIn("Principal.UserId", source)

    def test_apply_grants_only_batch_logon_through_lsa_and_fails_on_direct_deny(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("function Grant-ExactBatchLogonRight", source)
        self.assertIn('private static extern uint LsaAddAccountRights(', source)
        self.assertIn('private static extern uint LsaEnumerateAccountRights(', source)
        self.assertIn('$batchRight = "SeBatchLogonRight"', source)
        self.assertIn('$denyRight = "SeDenyBatchLogonRight"', source)
        self.assertIn("refusing to weaken or override a deny assignment", source)
        self.assertIn("Compare-Object -ReferenceObject $expectedAfter -DifferenceObject $after", source)
        self.assertIn("changed beyond the single authorized SeBatchLogonRight addition", source)
        self.assertIn("$batchLogonEvidence = Grant-ExactBatchLogonRight $serviceSid.Value", source)

    def test_script_does_not_use_broad_security_policy_tools_or_remove_rights(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8").lower()
        self.assertNotIn("secedit", source)
        self.assertIsNone(re.search(r"(?im)^\s*(?:&\s*)?ntrights(?:\.exe)?\b", source))
        self.assertNotIn("lsaremoveaccountrights", source)

    def test_script_contains_no_source_or_export_deletion_path(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertNotIn("wsl.exe --unregister", lowered)
        self.assertNotIn("wsl --unregister", lowered)
        self.assertNotIn("remove-item -literalpath $exportpath", lowered)
        self.assertNotIn("remove-item -path $exportpath", lowered)
        self.assertIn("source_distro_preserved = $true", source)
        self.assertIn("export_preserved = $true", source)

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
