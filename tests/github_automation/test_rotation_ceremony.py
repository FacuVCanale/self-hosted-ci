import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REVIEWER = ROOT / "scripts/host/review-overworld-image-rotation.py"
PROFILE = ROOT / "repository_profiles/overworld/profile.json"
MANIFEST = ROOT / "images/overworld-pr-v1/manifest.json"
CEREMONY = ROOT / "scripts/host/run-overworld-rotation-ceremony.sh"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RotationReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sha = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        live = self.root / "measured/contract/live/source"
        live.mkdir(parents=True)
        (self.root / "measured/contract/runner-boundary-measured-v2.json").write_text("{}\n", encoding="utf-8")
        source = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{self.sha}:scripts/host/run-health-supervisor.ps1"]
        )
        (live / "001-run-health-supervisor.ps1").write_bytes(source)
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.receipt = self.root / "receipt.json"
        self.observation = self.root / "observation.json"
        self.receipt_value = {
            "status": "built", "project": "ci-jit", "profile": manifest["profile"],
            "base_fingerprint": "a" * 64,
            "manifest_sha256": digest(MANIFEST),
            "candidate_alias": f'{manifest["profile"]}-{digest(PROFILE)[:12]}',
            "fingerprint": "b" * 64,
            "builder_privileged": False, "builder_nesting": False,
            "credentials_persisted": False, "alias_moved": False,
        }
        marker = {
            "repository_profile_image_marker_version": 1,
            "repository": profile["repository"], "profile_id": profile["profile_id"],
            "profile_digest": digest(PROFILE), "image_marker": profile["image_marker"],
            "runner_memory_bytes": profile["runner_memory_bytes"],
            "toolchain": profile["toolchain"],
            "dependency_snapshots": profile["dependency_snapshots"],
        }
        self.observation_value = {
            "alias": self.receipt_value["candidate_alias"],
            "fingerprint": self.receipt_value["fingerprint"], "marker": marker,
        }
        self.write_inputs()
        config = self.root / ".config/self-hosted-ci"
        config.mkdir(parents=True)
        (config / "config.json").write_text(json.dumps({
            "distro": "Ubuntu-24.04-CI", "public_repository": "FacuVCanale/self-hosted-ci",
            "public_sha": self.sha, "ssh_key": str(self.root / "key"),
            "ssh_target": "selfhosted-ci-svc@example",
        }), encoding="utf-8")
        (config / "rotation-ceremony-install.json").write_text(json.dumps({
            "install_receipt_version": 1,
            "installed_ceremony_sha256": digest(CEREMONY),
            "previous_ceremony_sha256": "e" * 64,
            "public_sha": self.sha,
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_inputs(self) -> None:
        self.receipt.write_text(json.dumps(self.receipt_value), encoding="utf-8")
        self.observation.write_text(json.dumps(self.observation_value), encoding="utf-8")

    def command(self, profile: Path = PROFILE) -> list[str]:
        return [
            "python3", str(REVIEWER), "--ceremony-directory", str(self.root),
            "--repository", str(ROOT), "--sha", self.sha, "--receipt", str(self.receipt),
            "--profile", str(profile), "--manifest", str(MANIFEST),
            "--image-observation", str(self.observation),
            "--live-previous-fingerprint", "c" * 64,
        ]

    def ceremony(self, *, profile: Path = PROFILE, reviewer: Path = REVIEWER, signer: Path) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ, "HOME": str(self.root), "REVIEW_ONLY": "true",
            "CEREMONY_TEST_REPOSITORY": str(ROOT), "CEREMONY_TEST_PYTHON": "python3",
            "REVIEW_C": str(self.root), "ROTATION_RECEIPT": str(self.receipt),
            "ROTATION_PROFILE": str(profile), "ROTATION_MANIFEST": str(MANIFEST),
            "ROTATION_REVIEWER": str(reviewer),
            "ROTATION_IMAGE_OBSERVATION": str(self.observation),
            "ROTATION_LIVE_PREVIOUS_IMAGE_FINGERPRINT": "c" * 64,
            "ROTATION_TEST_SIGNER_COMMAND": f': > {shlex.quote(str(signer))}',
        }
        return subprocess.run(["bash", str(CEREMONY), self.sha], text=True, capture_output=True, env=env)

    def test_matching_sources_receipt_profile_and_image_pass(self) -> None:
        result = subprocess.run(self.command(), text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("REVIEW_OK", result.stdout)

    def test_real_ceremony_boundary_blocks_mutations_before_signer(self) -> None:
        mutations = []
        image = json.loads(json.dumps(self.observation_value))
        image["alias"] += "-mutated"
        mutations.append(("image", image, self.receipt_value, PROFILE))
        fingerprint = json.loads(json.dumps(self.receipt_value))
        fingerprint["fingerprint"] = "d" * 64
        mutations.append(("fingerprint", self.observation_value, fingerprint, PROFILE))
        mutated_profile = self.root / "profile.json"
        profile_value = json.loads(PROFILE.read_text(encoding="utf-8"))
        profile_value["runner_memory_bytes"] += 1
        mutated_profile.write_text(json.dumps(profile_value), encoding="utf-8")
        mutations.append(("profile", self.observation_value, self.receipt_value, mutated_profile))
        reviewer_copy = self.root / "reviewer.py"
        reviewer_copy.write_bytes(REVIEWER.read_bytes() + b"\n# identity drift\n")
        mutations.append(("source-identity", self.observation_value, self.receipt_value, PROFILE))
        for name, observation, receipt, profile in mutations:
            with self.subTest(name=name):
                self.observation_value, self.receipt_value = observation, receipt
                self.write_inputs()
                signer = self.root / f"signer-{name}"
                reviewer = reviewer_copy if name == "source-identity" else REVIEWER
                result = self.ceremony(profile=profile, reviewer=reviewer, signer=signer)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("REVIEW_FAIL", result.stdout)
                self.assertFalse(signer.exists(), "signer marker must remain absent")
                self.receipt_value = json.loads(self.receipt.read_text(encoding="utf-8"))

    def test_pristine_base_may_differ_from_verified_previous(self) -> None:
        self.assertNotEqual(self.receipt_value["base_fingerprint"], "c" * 64)
        signer = self.root / "signer-base-distinct"
        result = self.ceremony(signer=signer)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(signer.exists())


class RotationInstallerContractTests(unittest.TestCase):
    def test_installer_is_the_only_versioned_replacement_path(self) -> None:
        source = (ROOT / "scripts/install-agent-interfaces.py").read_text(encoding="utf-8")
        self.assertIn("--install-rotation-ceremony", source)
        self.assertIn("previous_ceremony_sha256", source)
        self.assertIn("committed != ceremony_source", source)
        self.assertIn("installed != ceremony_source", source)

if __name__ == "__main__":
    unittest.main()
