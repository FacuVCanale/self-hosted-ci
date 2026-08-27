from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/host/verify-live-artifact-contract.py"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_live_artifact_contract", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load_stager():
    spec = importlib.util.spec_from_file_location("stage_wsl_jit_live_contract", STAGER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class LiveArtifactContractTests(unittest.TestCase):
    TARGET = "/usr/local/lib/self-hosted-ci/runtime.sh"

    def verify_fixture(self, verifier, bundle, measurement, prefix):
        return verifier.verify_contract(
            bundle, measurement, prefix, required_targets={self.TARGET},
        )

    def fixture(self, root: Path):
        verifier = load_verifier()
        measurement = root / "measurements"
        source = measurement / "live/source/runtime.sh"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(source, 0o755)
        target = root / "installed/usr/local/lib/self-hosted-ci/runtime.sh"
        target.parent.mkdir(parents=True)
        target.write_bytes(source.read_bytes())
        os.chmod(target, 0o755)
        data = source.read_bytes()
        contract = {
            "live_artifact_contract_version": 1,
            "artifacts": [{
                "target": self.TARGET,
                "source_ref": "live/source/runtime.sh",
                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                "mode": "0755", "uid": os.stat(target).st_uid,
                "gid": os.stat(target).st_gid, "kind": "script",
            }],
        }
        contract_path = measurement / verifier.CONTRACT_REF
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        os.chmod(contract_path, 0o640)

        def record(path: Path, ref: str):
            info, payload = os.stat(path), path.read_bytes()
            return {"ref": ref, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "mode": f"{info.st_mode & 0o7777:04o}", "uid": info.st_uid, "gid": info.st_gid}

        bundle = root / "boundary.json"
        bundle.write_text(json.dumps({"measurements": {"artifacts": [
            record(contract_path, verifier.CONTRACT_REF), record(source, "live/source/runtime.sh")
        ]}}), encoding="utf-8")
        return verifier, bundle, measurement, root / "installed", target

    def test_exact_live_artifact_contract_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            verifier, bundle, measurement, prefix, _ = self.fixture(Path(tmp))
            self.assertEqual(self.verify_fixture(verifier, bundle, measurement, prefix), 1)

    def test_hash_mode_and_symlink_drift_fail_closed(self):
        for mutation in ("hash", "mode", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                verifier, bundle, measurement, prefix, target = self.fixture(Path(tmp))
                if mutation == "hash":
                    target.write_text("drift", encoding="utf-8")
                elif mutation == "mode":
                    os.chmod(target, 0o777)
                else:
                    target.unlink(); target.symlink_to("/bin/true")
                with self.assertRaises(verifier.ContractError):
                    self.verify_fixture(verifier, bundle, measurement, prefix)

    def test_owner_contract_and_hardlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            verifier, bundle, measurement, prefix, target = self.fixture(Path(tmp))
            contract_path = measurement / verifier.CONTRACT_REF
            contract = json.loads(contract_path.read_text())
            contract["artifacts"][0]["uid"] += 1
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            info, payload = os.stat(contract_path), contract_path.read_bytes()
            value = json.loads(bundle.read_text())
            value["measurements"]["artifacts"][0] = {
                "ref": verifier.CONTRACT_REF, "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload), "mode": f"{info.st_mode & 0o7777:04o}",
                "uid": info.st_uid, "gid": info.st_gid,
            }
            bundle.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(verifier.ContractError, "live artifact drift"):
                self.verify_fixture(verifier, bundle, measurement, prefix)

        with tempfile.TemporaryDirectory() as tmp:
            verifier, bundle, measurement, prefix, target = self.fixture(Path(tmp))
            os.link(target, target.with_suffix(".second-link"))
            with self.assertRaisesRegex(verifier.ContractError, "hard-linked artifact"):
                self.verify_fixture(verifier, bundle, measurement, prefix)

    def test_public_contract_rejects_secret_targets(self):
        verifier = load_verifier()
        for target in (
            "/etc/self-hosted-ci/garm/config.toml",
            "/etc/self-hosted-ci/garm/incus-client.key",
            "/tmp/unmanaged",
        ):
            with self.subTest(target=target), self.assertRaises(verifier.ContractError):
                verifier._validate_target_name(target)

    def test_provision_activation_and_units_revalidate_live_contract(self):
        provision = (ROOT / "scripts/host/provision-wsl-jit-contract.sh").read_text()
        activation = (ROOT / "scripts/host/activate-garm-jit.sh").read_text()
        library = (ROOT / "scripts/host/garm-jit-transaction-lib.sh").read_text()
        self.assertIn("verify-live-artifact-contract.py", provision)
        self.assertIn("installed live runtime artifacts failed signed-contract verification", provision)
        self.assertIn("require_live_artifact_contract", activation)
        self.assertIn("signed live artifact contract is invalid or drifted", library)
        for name in (
            "self-hosted-ci-boundary-verify.service", "self-hosted-ci-garm.service",
            "self-hosted-ci-network-policy.service", "self-hosted-ci-egress-proxy.service",
        ):
            unit = (ROOT / "packaging/systemd" / name).read_text()
            self.assertIn("verify-live-artifact-contract.py", unit)

    def test_stager_has_exact_public_files_and_pinned_binaries_without_secrets(self):
        source = STAGER.read_text()
        verifier, stager = load_verifier(), load_stager()
        staged_targets = {item[1] for item in stager.PUBLIC_ARTIFACTS}
        staged_targets.update(item[0] for item in stager.PINNED_BINARIES)
        self.assertEqual(verifier.REQUIRED_LIVE_TARGETS, staged_targets)
        for token in (
            "packaging/network/squid.conf", "garm-provider-incus.toml",
            "prepare-incus-runner-image.sh", "configure-garm-jit.sh",
            "/usr/local/bin/garm", "/usr/local/bin/garm-cli",
            "/usr/local/libexec/garm/garm-provider-incus", "live/live-artifacts-v1.json",
        ):
            self.assertIn(token, source)
        self.assertNotIn('"/etc/self-hosted-ci/garm/config.toml",', source)
        self.assertNotIn("incus-client.key\",", source)


if __name__ == "__main__":
    unittest.main()
