from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import canonicalize_jcs
from github_automation.runner_boundary import sign_runner_boundary


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/build-wsl-jit-live-contract-tar.py"


class LiveContractTarBuilderTests(unittest.TestCase):
    def run_builder(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_builds_reproducible_source_tar_with_normalized_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "input"
            contract.mkdir()
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            (contract / "evidence").mkdir()
            (contract / "evidence/item.json").write_text('{"ok":true}\n')
            first, second = root / "first.tar", root / "second.tar"
            for output in (first, second):
                self.run_builder(
                    "source", "--contract-dir", str(contract), "--output", str(output)
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], sorted(
                    [member.name for member in members], key=lambda name: (name.count("/"), name)
                ))
                for member in members:
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                    expected_mode = (
                        0o755
                        if member.isdir()
                        else 0o640
                        if member.name.startswith("contract/evidence/")
                        else 0o644
                    )
                    self.assertEqual(member.mode, expected_mode)

    def test_builds_signed_bundle_without_private_key_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract"
            contract.mkdir()
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            (contract / "runner-boundary-measured-v2.json").write_text('{"measured":true}\n')
            unsigned = root / "unsigned.tar"
            self.run_builder("source", "--contract-dir", str(contract), "--output", str(unsigned))
            private = ed25519.Ed25519PrivateKey.generate()
            public = private.public_key()
            public_path = root / "reviewer-public.pem"
            public_path.write_bytes(public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            der = public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fingerprint = hashlib.sha256(der).hexdigest()
            signed_boundary = root / "signed.json"
            signed_boundary.write_bytes(
                canonicalize_jcs(sign_runner_boundary({}, private)) + b"\n"
            )
            output = root / "signed.tar"
            self.run_builder(
                "signed", "--unsigned-tar", str(unsigned),
                "--signed-boundary", str(signed_boundary),
                "--reviewer-public-key", str(public_path),
                "--reviewer-key-fingerprint", fingerprint,
                "--output", str(output),
            )
            with tarfile.open(output, "r:") as archive:
                names = set(archive.getnames())
                self.assertTrue({
                    "contract/runner-boundary-v2.json",
                    "contract/reviewer-public-key.pem",
                    "contract/reviewer-key.sha256",
                }.issubset(names))
                value = archive.extractfile("contract/reviewer-key.sha256").read()
                self.assertEqual(value, (fingerprint + "\n").encode("ascii"))
            self.assertNotIn(
                'add_argument("--reviewer-private-key"', SCRIPT.read_text()
            )

    def test_rejects_symlink_and_private_key_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract"
            contract.mkdir()
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            (contract / "link").symlink_to(contract / "runner-boundary-template-v2.json")
            result = self.run_builder(
                "source", "--contract-dir", str(contract),
                "--output", str(root / "bad.tar"), expected=2,
            )
            self.assertIn("forbidden", result.stderr)
            (contract / "link").unlink()
            (contract / "reviewer-private.key").write_text("secret")
            result = self.run_builder(
                "source", "--contract-dir", str(contract),
                "--output", str(root / "bad-key.tar"), expected=2,
            )
            self.assertIn("private-key-like", result.stderr)

    def test_rejects_traversal_in_unsigned_tar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malicious = root / "malicious.tar"
            with tarfile.open(malicious, "w") as archive:
                info = tarfile.TarInfo("contract/../escape")
                info.size = 1
                archive.addfile(info, __import__("io").BytesIO(b"x"))
            result = self.run_builder(
                "signed", "--unsigned-tar", str(malicious),
                "--signed-boundary", str(root / "missing"),
                "--reviewer-public-key", str(root / "missing-key"),
                "--reviewer-key-fingerprint", "0" * 64,
                "--output", str(root / "bad.tar"), expected=2,
            )
            self.assertIn("unsafe archive path", result.stderr)

    def test_rejects_unsigned_or_invalidly_signed_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract"
            contract.mkdir()
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            unsigned = root / "unsigned.tar"
            self.run_builder("source", "--contract-dir", str(contract), "--output", str(unsigned))
            private = ed25519.Ed25519PrivateKey.generate()
            public = private.public_key()
            public_path = root / "public.pem"
            public_path.write_bytes(public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            fingerprint = hashlib.sha256(public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )).hexdigest()
            boundary = root / "boundary.json"
            boundary.write_text("{}\n")
            result = self.run_builder(
                "signed", "--unsigned-tar", str(unsigned),
                "--signed-boundary", str(boundary),
                "--reviewer-public-key", str(public_path),
                "--reviewer-key-fingerprint", fingerprint,
                "--output", str(root / "signed.tar"), expected=2,
            )
            self.assertIn("attestation", result.stderr)


if __name__ == "__main__":
    unittest.main()
