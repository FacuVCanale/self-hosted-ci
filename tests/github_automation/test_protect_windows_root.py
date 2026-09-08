from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/protect-windows-root.ps1"


class ProtectWindowsRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_plan_and_ack_precede_the_only_acl_mutation(self) -> None:
        plan = self.source.index('[ordered]@{\n    mode = "plan"')
        plan_return = self.source.index("if (-not $Apply) { return }", plan)
        acknowledgement = self.source.index(
            "if (-not $AcknowledgeProtectedRootAcl)", plan_return
        )
        mutation = self.source.index("Set-Acl -LiteralPath $Root -AclObject $targetAcl")
        self.assertLess(plan, plan_return)
        self.assertLess(plan_return, acknowledgement)
        self.assertLess(acknowledgement, mutation)
        self.assertEqual(
            2,
            self.source.count("Set-Acl -LiteralPath $Root -AclObject"),
            "the target mutation plus exact rollback are the only root writes",
        )

    def test_identity_root_and_acl_contracts_are_fail_closed(self) -> None:
        for token in (
            'if ($env:OS -ne "Windows_NT" -or -not (Test-IsAdministrator))',
            '$ServiceAccount -cne "selfhosted-ci-svc"',
            '$ReaderAccount -cne "selfhosted-ci-health"',
            "service-account SID mismatch",
            "service and reader identities must be distinct",
            'PrincipalSource -ne "Local"',
            "Test-GroupContainsSid $Administrators $Account.SID.Value $visited",
            "Windows self-hosted-ci root must already exist as a directory",
            "Windows self-hosted-ci root must not be a reparse point",
            "$acl.SetAccessRuleProtection($true, $false)",
            "$acl.SetOwner($owner)",
            "[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit",
            "[Security.AccessControl.PropagationFlags]::None",
            "$rules.Count -ne $expected.Count",
            "$actualSddl -cne $expectedSddl",
            "service_account_sid = $service.SID.Value",
            "reader_account_sid = $reader.SID.Value",
        ):
            self.assertIn(token, self.source)
        self.assertIn(
            "$readOnly = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize",
            self.source,
        )
        self.assertEqual(2, self.source.count("$readOnly ="))

    def test_scope_excludes_children_and_runtime_mutation(self) -> None:
        for forbidden in (
            "get-childitem",
            "remove-item",
            "new-item",
            "copy-item",
            "wsl.exe",
            "systemctl",
            "gh api",
            "github.com",
            "register-scheduledtask",
            "start-scheduledtask",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.source.lower())
        for token in (
            "child_writes = $false",
            "runner_changed = $false",
            "github_changed = $false",
            "wsl_changed = $false",
        ):
            self.assertEqual(2, self.source.count(token))

    def test_powershell_parser_accepts_script_when_available(self) -> None:
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if executable is None:
            self.skipTest("PowerShell parser is unavailable")
        command = (
            "$errors=$null;$tokens=$null;"
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{SCRIPT}',[ref]$tokens,[ref]$errors);"
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
        )
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", command],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
