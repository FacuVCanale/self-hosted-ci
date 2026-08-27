from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.runner_boundary import verify_runner_boundary_attestation


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/sign-wsl-jit-boundary.py"


class BoundarySigningCliTests(unittest.TestCase):
    def test_signs_unsigned_input_atomically_with_external_locked_key(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            unsigned = root / "unsigned.json"
            signed = root / "signed.json"
            key_path = root / "reviewer.pem"
            unsigned.write_text('{"activation_requested":false}', encoding="utf-8")
            key = ed25519.Ed25519PrivateKey.generate()
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(0o600)
            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--input",
                    str(unsigned),
                    "--output",
                    str(signed),
                    "--reviewer-private-key",
                    str(key_path),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            value = json.loads(signed.read_text(encoding="utf-8"))
            fingerprint = value["attestation"]["signer_fingerprint"]
            verify_runner_boundary_attestation(
                value, key.public_key(), pinned_fingerprint=fingerprint
            )
            self.assertEqual(0o600, os.stat(signed).st_mode & 0o777)
            self.assertNotIn(
                "attestation", json.loads(unsigned.read_text(encoding="utf-8"))
            )

    def test_rejects_repository_key_and_permissive_key(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("must remain outside the repository", source)
        self.assertIn("must not be group/world accessible", source)
        self.assertIn("input boundary must be unsigned", source)


if __name__ == "__main__":
    unittest.main()
