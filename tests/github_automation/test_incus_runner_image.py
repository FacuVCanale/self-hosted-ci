from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/prepare-incus-runner-image.sh"
PROVISION = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"
VERIFIER = ROOT / "scripts/host/verify-live-artifact-contract.py"
FINGERPRINT = "a" * 64


class IncusRunnerImageTests(unittest.TestCase):
    def command(self, *extra: str) -> list[str]:
        return [
            "bash",
            str(SCRIPT),
            *extra,
            "--source-remote",
            "images",
            "--source-ref",
            "ubuntu/24.04/cloud",
            "--expected-fingerprint",
            FINGERPRINT,
            "--local-alias",
            "runner-ubuntu-24.04-pinned",
        ]

    def test_plan_is_exact_machine_readable_and_inert(self) -> None:
        result = subprocess.run(self.command("--plan"), text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual("plan", value["mode"])
        self.assertEqual("ci-jit", value["project"])
        self.assertEqual("images", value["source_remote"])
        self.assertEqual("ubuntu/24.04/cloud", value["source_ref"])
        self.assertEqual(FINGERPRINT, value["expected_fingerprint"])
        self.assertEqual("runner-ubuntu-24.04-pinned", value["local_alias"])
        self.assertFalse(value["host_changes"])
        self.assertEqual("not_performed", value["remote_calls"])
        self.assertFalse(value["garm_enabled"])
        self.assertEqual("not_performed", value["runner_registration"])

    def test_inputs_are_explicit_and_fingerprint_is_lowercase_sha256(self) -> None:
        missing = subprocess.run(
            ["bash", str(SCRIPT), "--plan"], text=True, capture_output=True
        )
        self.assertNotEqual(0, missing.returncode)
        uppercase = subprocess.run(
            [
                part if part != FINGERPRINT else "A" * 64
                for part in self.command("--plan")
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(0, uppercase.returncode)
        self.assertIn("lowercase SHA-256", uppercase.stderr)

    def test_apply_has_pinned_copy_exact_postconditions_and_safe_alias_rollback(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "--acknowledge-remote-image-fetch",
            "--acknowledge-local-image-alias-mutation",
            'incus image list "${source_remote}:${source_ref}" --format json',
            'incus image list "${TARGET_REMOTE}:${expected_fingerprint}" --project "${PROJECT}" --format json',
            'incus image list "${TARGET_REMOTE}:${local_alias}" --project "${PROJECT}" --format json',
            'incus image copy "${source_remote}:${expected_fingerprint}" "${TARGET_REMOTE}:"',
            '--target-project "${PROJECT}"',
            'incus image alias create "${TARGET_REMOTE}:${local_alias}" "${expected_fingerprint}"',
            'incus image alias delete "${TARGET_REMOTE}:${local_alias}"',
            "created_alias=false",
            "transaction_succeeded=false",
            "GARM must be inactive while preparing its runner image",
            "activation sentinel must be absent while preparing the runner image",
            "ci-jit must contain zero instances while preparing the runner image",
            "ci-jit instance inventory changed during runner-image preparation",
            "local alias already points to a different fingerprint",
            "exact local alias postcondition failed",
            "source inventory does not expose the exact source ref",
            "local fingerprint inventory is ambiguous",
            "local image postcondition inventory is invalid",
            'image.get("type") != "container"',
            'image.get("architecture") != architecture',
            '"garm_enabled":false',
            '"runner_registration_performed":false',
        ):
            self.assertIn(token, source)
        self.assertNotIn("--reuse", source)
        self.assertNotIn("--copy-aliases", source)
        self.assertNotIn("--auto-update", source)
        self.assertNotIn("incus image info", source)

    def test_script_is_installed_and_covered_by_the_signed_live_contract(self) -> None:
        target = "/usr/local/lib/self-hosted-ci/prepare-incus-runner-image.sh"
        self.assertIn(
            "prepare-incus-runner-image.sh", PROVISION.read_text(encoding="utf-8")
        )
        self.assertIn(target, STAGER.read_text(encoding="utf-8"))
        self.assertIn(target, VERIFIER.read_text(encoding="utf-8"))

    def test_garm_configuration_uses_incus_6_compatible_image_info(self) -> None:
        configure = (ROOT / "scripts/host/configure-garm-jit.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('incus image info "${image_alias}" --project ci-jit', configure)
        self.assertNotIn(
            'incus image info "${image_alias}" --project ci-jit --format json',
            configure,
        )

    def test_script_parses(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
