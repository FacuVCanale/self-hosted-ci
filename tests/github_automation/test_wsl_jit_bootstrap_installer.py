from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-wsl-jit-bootstrap.ps1"


class WslJitBootstrapInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_plan_default_and_exact_external_pins(self):
        for token in (
            'mode = $(if ($Apply) { "apply" } else { "plan" })',
            'if (-not $Apply) { return }',
            "ExpectedBundleSha256",
            "ExpectedBundleBytes",
            "ExpectedReviewerFingerprint",
            "ExpectedBootstrapNonce",
            "AcknowledgeInertBootstrapMutation",
            "AcknowledgeOneTimePasswordRotation",
        ):
            self.assertIn(token, self.source)

    def test_bundle_is_package_relative_content_addressed_and_safe(self):
        for token in (
            "bundle path must be a safe package-relative tar path",
            "Assert-NoReparsePath $bundlePath $PackageRoot",
            "bootstrap bundle content address does not match",
            'member.issym() or member.islnk() or member.isdev()',
            'member.uid != 0 or member.gid != 0 or member.mode & 0o7022',
            'roots != {"bootstrap"}',
            'archive.extractall(target, numeric_owner=True, filter="data")',
        ):
            self.assertIn(token, self.source)

    def test_wsl_transport_is_stdin_only_not_drvfs(self):
        for token in (
            'transport = "stdin-no-drvfs"',
            "RedirectStandardInput = `$true",
            "archive_b64",
            "stdin payload hash mismatch",
            "bundle changed before stdin transfer",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn("/mnt/c/", self.source)

    def test_exact_limited_service_identity_and_cleanup(self):
        for token in (
            'ServiceAccount = "selfhosted-ci-svc"',
            'DistroName = "Ubuntu-24.04-CI"',
            "Assert-NonAdmin $service",
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA / Limited",
            "one-shot task principal postcondition failed",
            "one-shot task action postcondition failed",
            "one-shot task settings postcondition failed",
            "Set-LocalUser -Name $service.Name -Password $finalPassword",
            "Set-LocalUser -Name $service.Name -Password $recoveryPassword",
            "Unregister-ScheduledTask",
            "Remove-Item -LiteralPath $Root -Recurse -Force",
            "task, credential, and staging cleanup were verified",
        ):
            self.assertIn(token, self.source)

    def test_signed_bootstrap_provisions_inert_contract_only(self):
        provision = self.source.index("provision-wsl-jit-contract.sh")
        apply_call = self.source.index('bash "$package/scripts/host/provision-wsl-jit-contract.sh" --apply')
        self.assertLess(provision, apply_call)
        for token in (
            '--bootstrap-evidence "$root/bootstrap-boundary-v1.signed.json"',
            '--windows-observation "$root/windows-observation.json"',
            '--wsl-observation "$root/wsl-observation.json"',
            '--public-manifest "$root/bootstrap-public-manifest-v1.json"',
            '--reviewer-public-key "$root/reviewer-public-key.pem"',
            '--reviewer-key-fingerprint "$expected_fingerprint"',
            '--expected-bootstrap-nonce "$expected_nonce"',
            "GARM was unexpectedly enabled",
            "bootstrap unexpectedly activated runtime",
            'github_configured=$false',
            'runner_registration_performed=$false',
        ):
            self.assertIn(token, self.source)

    def test_diagnostics_are_redacted_and_versioned(self):
        self.assertIn('diagnostics\\bootstrap-install\\v1', self.source)
        self.assertIn("diagnostic_version = 1", self.source)
        self.assertNotIn("private-key", self.source.lower())


if __name__ == "__main__":
    unittest.main()
