import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/host/collect-windows-wsl-semantic-contract.ps1"


class WindowsWslSemanticContractCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = COLLECTOR.read_text(encoding="utf-8")

    def test_is_elevated_observation_not_an_apply_installer(self) -> None:
        for token in (
            "collector requires an elevated Windows console",
            'status = "observed"',
            "evidence_file_created = $true",
            "scheduled_task_created = $false",
            "password_rotated = $false",
            "wsl_started = $false",
            "github_contacted = $false",
            "runner_registration_changed = $false",
        ):
            self.assertIn(token, self.source)
        for forbidden in (
            "Register-ScheduledTask",
            "RegisterTaskDefinition",
            "Set-LocalUser",
            "New-LocalUser",
            "wsl.exe",
            "github.com",
            "config.sh",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_observes_exact_enabled_local_effectively_non_admin_identity(self) -> None:
        for token in (
            'ServiceAccount = "selfhosted-ci-svc"',
            "Get-LocalUser -Name $ServiceAccount",
            "account.SID.Value -eq $ExpectedServiceAccountSid",
            "[bool]$account.Enabled",
            'PrincipalSource -eq "Local"',
            "Test-GroupContainsSid",
            "account_non_admin",
            "including nested groups",
        ):
            self.assertIn(token, self.source)

    def test_registration_is_read_from_exact_service_sid_hive(self) -> None:
        for token in (
            "Registry::HKEY_USERS\\$ExpectedServiceAccountSid\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss",
            "exact_match_count = $matches.Count",
            "registration_unique",
            "registration_guid",
            "registration_version",
            "registration_base_path",
            "registration_owner",
            "owner must be the service SID",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn("HKEY_CURRENT_USER", self.source)

    def test_base_path_and_acl_boundary_are_exact(self) -> None:
        for token in (
            'ExpectedBasePath = "C:\\ProgramData\\self-hosted-ci\\wsl"',
            "Assert-NoReparsePath $ExpectedBasePath",
            "GetOwner([Security.Principal.SecurityIdentifier])",
            "inheritance_protected",
            "rules.Count -ne 3",
            "ContainerInherit, ObjectInherit",
            "SYSTEM/Administrators/service FullControl",
            "S-1-5-18",
            "S-1-5-32-544",
        ):
            self.assertIn(token, self.source)

    def test_absent_evidence_is_never_reported_as_satisfied(self) -> None:
        self.assertIn('status = "unobserved"', self.source)
        self.assertIn(
            'status = $(if ($Satisfied) { "satisfied" } else { "failed" })', self.source
        )
        self.assertIn('Where-Object { $_ -ne "satisfied" }', self.source)
        self.assertNotIn("contract_satisfied = $true", self.source)
        self.assertNotIn('status = "pass"', self.source)

    def test_private_evidence_staging_has_protected_admin_system_acl(self) -> None:
        for token in (
            'OutputRoot = "C:\\ProgramData\\self-hosted-ci\\semantic-contract-staging\\v1"',
            "SetAccessRuleProtection($true, $false)",
            "SetOwner($AdministratorsSid)",
            "foreach ($sid in @($SystemSid, $AdministratorsSid))",
            "Set-Acl -LiteralPath $StagingRoot",
            "Set-Acl -LiteralPath $OutputRoot",
            "Set-Acl -LiteralPath $outputPath",
            "Assert-NoReparsePath $OutputRoot",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn(
            "$ExpectedServiceAccountSid)) {",
            self.source.split("function New-PrivateAcl", 1)[1].split(
                "function Test-GroupContainsSid", 1
            )[0],
        )

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_script_parses_in_powershell(self) -> None:
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
