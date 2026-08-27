from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-wsl-jit-live-contract.ps1"


class WslJitLiveContractInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_plan_only_is_default_and_apply_is_acknowledged(self):
        self.assertIn('mode = $(if ($Apply) { "apply" } else { "plan" })', self.source)
        self.assertIn('if (-not $Apply) { return }', self.source)
        self.assertIn("AcknowledgeLiveContractMutation", self.source)
        self.assertIn("AcknowledgeOneTimePasswordRotation", self.source)
        self.assertIn("ExpectedInputSha256", self.source)
        self.assertIn("ExpectedInputBytes", self.source)

    def test_signed_install_uses_external_reviewer_and_bundle_pins(self):
        for token in (
            "ExpectedReviewerFingerprint",
            "reviewer fingerprint differs from external pin",
            '--pinned-fingerprint "$4"',
            "Apply requires the exact lowercase ExpectedInputSha256",
            "Apply requires the exact positive ExpectedInputBytes",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn('--pinned-fingerprint "$fingerprint"', self.source)

    def test_exact_non_admin_service_identity_owns_one_shot(self):
        for token in (
            'ServiceAccount = "selfhosted-ci-svc"',
            'DistroName = "Ubuntu-24.04-CI"',
            "Assert-NonAdmin $service",
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA / Limited",
            "one-shot task principal postcondition failed",
            "one-shot task action postcondition failed",
            "one-shot task settings postcondition failed",
        ):
            self.assertIn(token, self.source)

    def test_bundle_is_content_addressed_and_safely_extracted(self):
        for token in (
            "Assert-NoReparsePath $inputPath $PackageRoot",
            "live contract bundle sha256 mismatch",
            'member.issym() or member.islnk() or member.isdev()',
            'archive.extractall(target, numeric_owner=True, filter="data")',
            'roots != {"contract"}',
            "live contract bundle layout is invalid",
        ):
            self.assertIn(token, self.source)

    def test_unsigned_collection_bootstraps_external_signing_without_provisioning(self):
        for token in (
            "[switch]$CollectUnsigned",
            "AcknowledgeUnsignedCollection",
            '$operation = $(if ($CollectUnsigned) { "collect-unsigned" }',
            "unsigned-live-contract-$actualUnsignedSha.tar",
            'provisioned=$false',
            'runtime_ready_created=$false',
        ):
            self.assertIn(token, self.source)

    def test_regenerates_verifies_then_provisions_without_activation(self):
        stage = self.source.index("stage-wsl-jit-live-contract.py")
        collect = self.source.index("collect-wsl-jit-measurements.py")
        compare = self.source.index("regenerated live contract differs from signed content")
        verify = self.source.index("verify-wsl-jit-readiness.py")
        provision = self.source.index("provision-wsl-jit-contract.sh")
        self.assertLess(stage, collect)
        self.assertLess(collect, compare)
        self.assertLess(compare, verify)
        self.assertLess(verify, provision)
        for token in (
            "GARM was unexpectedly enabled",
            "activation approval was unexpectedly created",
            "runtime-ready sentinel was unexpectedly created",
            "runtime-ready sentinel changed",
            'garm_enabled=$false',
            'github_configured=$false',
            'runtime_ready_created=$false',
            'runner_registration_performed=$false',
        ):
            self.assertIn(token, self.source)

    def test_password_task_and_staging_are_cleaned_on_success_and_failure(self):
        for token in (
            "New-CryptographicAccountPassword",
            "Set-LocalUser -Name $service.Name -Password $finalPassword",
            "Set-LocalUser -Name $service.Name -Password $recoveryPassword",
            "Unregister-ScheduledTask",
            "Remove-Item -LiteralPath $Root -Recurse -Force",
            "task, credential, and staging cleanup were verified",
            'stored_task_credential_invalidated=$true',
            'one_shot_task_absent=$true',
        ):
            self.assertIn(token, self.source)

    def test_diagnostics_are_versioned_and_redacted_to_public_metadata(self):
        self.assertIn('$DiagnosticsRoot = "C:\\ProgramData\\self-hosted-ci\\diagnostics\\live-contract-install\\v1"', self.source)
        self.assertIn("diagnostic_version = $DiagnosticVersion", self.source)
        self.assertNotIn("reviewer-private-key", self.source)
        self.assertNotIn("private_key", self.source)


if __name__ == "__main__":
    unittest.main()
