from __future__ import annotations

import hashlib
import io
import json
import os
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

    def signing_material(self, root: Path, boundary: dict):
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key()
        public_path = root / "reviewer-public.pem"
        public_path.write_bytes(public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        fingerprint = hashlib.sha256(public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hexdigest()
        signed_boundary = root / "signed.json"
        signed_boundary.write_bytes(
            canonicalize_jcs(sign_runner_boundary(boundary, private)) + b"\n"
        )
        return public_path, fingerprint, signed_boundary

    def test_builds_reproducible_source_tar_with_normalized_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "input"
            contract.mkdir()
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            os.chmod(contract, 0o700)
            (contract / "evidence").mkdir()
            (contract / "evidence/item.json").write_text('{"ok":true}\n')
            os.chmod(contract / "evidence", 0o700)
            os.chmod(contract / "evidence/item.json", 0o640)
            (contract / "runner-boundary-measured-v2.json").write_text("{}\n")
            os.chmod(contract / "runner-boundary-measured-v2.json", 0o600)
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
            evidence = contract / "evidence/item.json"
            evidence.parent.mkdir()
            evidence.write_text('{"measured":true}\n')
            evidence.chmod(0o640)
            unsigned = root / "unsigned.tar"
            self.run_builder("source", "--contract-dir", str(contract), "--output", str(unsigned))
            payload = evidence.read_bytes()
            boundary = {"measurements": {"artifacts": [{
                "ref": "evidence/item.json", "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload), "mode": "0640", "uid": 0, "gid": 0,
            }]}}
            public_path, fingerprint, signed_boundary = self.signing_material(root, boundary)
            outputs = (root / "signed.tar", root / "signed-again.tar")
            for output in outputs:
                self.run_builder(
                    "signed", "--unsigned-tar", str(unsigned),
                    "--signed-boundary", str(signed_boundary),
                    "--reviewer-public-key", str(public_path),
                    "--reviewer-key-fingerprint", fingerprint,
                    "--output", str(output),
                )
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            output = outputs[0]
            with tarfile.open(output, "r:") as archive:
                names = set(archive.getnames())
                self.assertTrue({
                    "contract/runner-boundary-v2.json",
                    "contract/reviewer-public-key.pem",
                    "contract/reviewer-key.sha256",
                }.issubset(names))
                value = archive.extractfile("contract/reviewer-key.sha256").read()
                self.assertEqual(value, (fingerprint + "\n").encode("ascii"))
                self.assertEqual(archive.getmember("contract/evidence/item.json").mode, 0o640)
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

    def test_rejects_noncanonical_but_validly_signed_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract"
            evidence = contract / "evidence/item.json"
            evidence.parent.mkdir(parents=True)
            (contract / "runner-boundary-template-v2.json").write_text("{}\n")
            evidence.write_bytes(b"evidence\n")
            evidence.chmod(0o640)
            unsigned = root / "unsigned.tar"
            self.run_builder(
                "source", "--contract-dir", str(contract), "--output", str(unsigned)
            )
            record = {
                "ref": "evidence/item.json",
                "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "size": len(evidence.read_bytes()),
                "mode": "0640",
                "uid": 0,
                "gid": 0,
            }
            public, fingerprint, signed = self.signing_material(
                root, {"measurements": {"artifacts": [record]}}
            )
            signed_value = json.loads(signed.read_text(encoding="utf-8"))
            signed.write_text(
                json.dumps(signed_value, indent=2) + "\n", encoding="utf-8"
            )
            output = root / "bad.tar"
            result = self.run_builder(
                "signed",
                "--unsigned-tar",
                str(unsigned),
                "--signed-boundary",
                str(signed),
                "--reviewer-public-key",
                str(public),
                "--reviewer-key-fingerprint",
                fingerprint,
                "--output",
                str(output),
                expected=2,
            )
            self.assertIn("canonical JCS plus newline", result.stderr)
            self.assertFalse(output.exists())

    def test_accepts_restrictive_transport_metadata_and_normalizes_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.tar"
            with tarfile.open(unsigned, "w", format=tarfile.PAX_FORMAT) as archive:
                for name, mode in (("contract", 0o700), ("contract/evidence", 0o700)):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, mode
                    archive.addfile(member)
                for name, data, mode in (
                    ("contract/runner-boundary-template-v2.json", b"{}\n", 0o600),
                    ("contract/runner-boundary-measured-v2.json", b"{}\n", 0o600),
                    ("contract/evidence/item.json", b"evidence\n", 0o640),
                ):
                    member = tarfile.TarInfo(name)
                    member.mode, member.size = mode, len(data)
                    archive.addfile(member, io.BytesIO(data))
            data = b"evidence\n"
            boundary = {"measurements": {"artifacts": [{
                "ref": "evidence/item.json", "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data), "mode": "0640", "uid": 0, "gid": 0,
            }]}}
            public, fingerprint, signed = self.signing_material(root, boundary)
            output = root / "signed.tar"
            self.run_builder(
                "signed", "--unsigned-tar", str(unsigned),
                "--signed-boundary", str(signed), "--reviewer-public-key", str(public),
                "--reviewer-key-fingerprint", fingerprint, "--output", str(output),
            )
            with tarfile.open(output, "r:") as archive:
                self.assertEqual(archive.getmember("contract").mode, 0o755)
                self.assertEqual(archive.getmember("contract/evidence").mode, 0o755)
                self.assertEqual(
                    archive.getmember("contract/runner-boundary-measured-v2.json").mode,
                    0o644,
                )
                self.assertEqual(archive.getmember("contract/evidence/item.json").mode, 0o640)

    def test_rejects_non_installable_or_mismatched_measurement(self):
        for mutation, expected_message in (
            ({"mode": "0644"}, "not installable"),
            ({"mode": "0600"}, "must be exactly 0640"),
            ({"sha256": "0" * 64}, "differs from archive member"),
            ({"size": 1}, "differs from archive member"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                contract = root / "contract"
                evidence = contract / "evidence/item.json"
                evidence.parent.mkdir(parents=True)
                (contract / "runner-boundary-template-v2.json").write_text("{}\n")
                evidence.write_bytes(b"evidence\n")
                evidence.chmod(0o640)
                unsigned = root / "unsigned.tar"
                self.run_builder("source", "--contract-dir", str(contract), "--output", str(unsigned))
                record = {
                    "ref": "evidence/item.json",
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                    "size": len(evidence.read_bytes()), "mode": "0640", "uid": 0, "gid": 0,
                }
                record.update(mutation)
                public, fingerprint, signed = self.signing_material(
                    root, {"measurements": {"artifacts": [record]}}
                )
                result = self.run_builder(
                    "signed", "--unsigned-tar", str(unsigned),
                    "--signed-boundary", str(signed), "--reviewer-public-key", str(public),
                    "--reviewer-key-fingerprint", fingerprint,
                    "--output", str(root / "bad.tar"), expected=2,
                )
                self.assertIn(expected_message, result.stderr)

    def test_rejects_a_referenced_member_whose_transport_mode_differs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.tar"
            data = b"evidence\n"
            with tarfile.open(unsigned, "w") as archive:
                for name in ("contract", "contract/evidence"):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, 0o700
                    archive.addfile(member)
                for name, payload, mode in (
                    ("contract/runner-boundary-template-v2.json", b"{}\n", 0o600),
                    ("contract/evidence/item.json", data, 0o600),
                ):
                    member = tarfile.TarInfo(name)
                    member.mode, member.size = mode, len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            boundary = {"measurements": {"artifacts": [{
                "ref": "evidence/item.json", "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data), "mode": "0640", "uid": 0, "gid": 0,
            }]}}
            public, fingerprint, signed = self.signing_material(root, boundary)
            result = self.run_builder(
                "signed", "--unsigned-tar", str(unsigned),
                "--signed-boundary", str(signed), "--reviewer-public-key", str(public),
                "--reviewer-key-fingerprint", fingerprint,
                "--output", str(root / "bad.tar"), expected=2,
            )
            self.assertIn("differs from archive member", result.stderr)

    def test_rejects_unsigned_archive_member_not_owned_by_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.tar"
            with tarfile.open(unsigned, "w") as archive:
                contract = tarfile.TarInfo("contract")
                contract.type, contract.mode = tarfile.DIRTYPE, 0o700
                archive.addfile(contract)
                template = tarfile.TarInfo(
                    "contract/runner-boundary-template-v2.json"
                )
                template.mode, template.uid, template.size = 0o600, 1000, 3
                archive.addfile(template, io.BytesIO(b"{}\n"))
            result = self.run_builder(
                "signed",
                "--unsigned-tar",
                str(unsigned),
                "--signed-boundary",
                str(root / "absent-boundary.json"),
                "--reviewer-public-key",
                str(root / "absent-public-key.pem"),
                "--reviewer-key-fingerprint",
                "0" * 64,
                "--output",
                str(root / "bad.tar"),
                expected=2,
            )
            self.assertIn("must be root-owned", result.stderr)
            self.assertFalse((root / "bad.tar").exists())


if __name__ == "__main__":
    unittest.main()
