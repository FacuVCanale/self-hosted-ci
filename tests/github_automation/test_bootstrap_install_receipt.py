from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.bootstrap_boundary import build_bootstrap_boundary, sign_bootstrap_boundary
from github_automation.crypto import canonicalize_jcs, spki_fingerprint
from tests.github_automation.test_bootstrap_boundary import public_manifest, windows_observation, wsl_observation


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/verify-bootstrap-install.py"
SPEC = importlib.util.spec_from_file_location("verify_bootstrap_install", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFIER)


class BootstrapInstallReceiptTests(unittest.TestCase):
    def fixture(self, root: Path):
        bootstrap_root = root / "etc/self-hosted-ci/bootstrap"
        installed_root = root / "installed"
        receipt = root / "var/lib/self-hosted-ci/bootstrap/bootstrap-install-receipt-v1.json"
        bootstrap_root.mkdir(parents=True)
        bootstrap_root.chmod(0o700)
        manifest = public_manifest()
        key = ed25519.Ed25519PrivateKey.generate()
        boundary = sign_bootstrap_boundary(
            build_bootstrap_boundary(
                windows_observation(),
                wsl_observation(),
                manifest,
                nonce="f" * 32,
            ),
            key,
        )
        files = {
            "bootstrap-boundary-v1.signed.json": canonicalize_jcs(boundary) + b"\n",
            "bootstrap-public-manifest-v1.json": canonicalize_jcs(manifest) + b"\n",
            "reviewer-public-key.pem": key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "reviewer-key.sha256": (spki_fingerprint(key.public_key()) + "\n").encode(),
        }
        for name, data in files.items():
            path = bootstrap_root / name
            path.write_bytes(data)
            path.chmod(0o600)
        targets = {}
        for item in manifest["artifacts"]:
            if item["target"] == "@execution/provision-wsl-jit-contract.sh":
                target = bootstrap_root / "provision-wsl-jit-contract.sh"
            else:
                target = installed_root.joinpath(*PurePosixPath(item["target"]).parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / item["source"]).read_bytes())
            target.chmod(int(item["mode"], 8))
            targets[item["target"]] = target
        return bootstrap_root, installed_root, receipt, targets

    def root_stat(self):
        original = os.stat

        def pretend_root(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            values = list(info)
            values[4] = 0
            return os.stat_result(values)

        return patch.object(VERIFIER.os, "stat", side_effect=pretend_root)

    def test_measures_every_exact_target_and_atomically_revalidates_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            bootstrap, installed, receipt, _ = self.fixture(Path(directory))
            with self.root_stat():
                measured = VERIFIER.measure(bootstrap, installed)
            self.assertEqual(81, measured["artifact_count"])
            self.assertEqual(
                "e1ca6657561ec2cad2ca1a3e4d6083241f3ec96715803efc02c875495870d355",
                measured["bootstrap_mapping_digest"],
            )
            with (
                patch.object(VERIFIER.os, "chown"),
                patch.object(VERIFIER.os, "fchown"),
            ):
                VERIFIER._write_atomic(receipt, measured)
            receipt.chmod(0o600)
            with self.root_stat():
                stored = VERIFIER.verify_receipt(receipt, measured)
            self.assertEqual(64, len(stored["receipt_digest"]))
            self.assertEqual(81, len(stored["installed_targets"]))

    def test_content_mode_symlink_and_hardlink_drift_fail_closed(self):
        for mutation in ("content", "mode", "symlink", "parent-symlink", "hardlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                bootstrap, installed, _, targets = self.fixture(Path(directory))
                target = targets[
                    "/usr/local/lib/self-hosted-ci/verify-bootstrap-install.py"
                ]
                if mutation == "content":
                    target.write_bytes(b"drift")
                elif mutation == "mode":
                    target.chmod(0o777)
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to("/bin/true")
                elif mutation == "parent-symlink":
                    parent = target.parent
                    relocated = parent.with_name(parent.name + "-real")
                    parent.rename(relocated)
                    parent.symlink_to(relocated)
                else:
                    os.link(target, target.with_suffix(".hardlink"))
                with self.root_stat(), self.assertRaises(VERIFIER.BootstrapInstallError):
                    VERIFIER.measure(bootstrap, installed)

    def test_provisioner_persists_exact_inputs_then_requires_remeasurement(self):
        source = (ROOT / "scripts/host/provision-wsl-jit-contract.sh").read_text()
        for token in (
            'bootstrap-boundary-v1.signed.json',
            'bootstrap-public-manifest-v1.json',
            'reviewer-public-key.pem',
            'reviewer-key.sha256',
            'bootstrap-install-receipt-v1.json',
            'verify-bootstrap-install.py --write-receipt',
            'installed inert bootstrap failed exact target remeasurement',
        ):
            self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
