from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import canonicalize_jcs, spki_fingerprint
from github_automation.runner_boundary import sign_runner_boundary


ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "scripts/host/preflight-wsl-jit-live-contract.py"
INSTALLER = ROOT / "scripts/host/install-wsl-jit-evidence.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def add(archive: tarfile.TarFile, name: str, data: bytes | None, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    info.mode = mode
    if data is None:
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    else:
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))


class LiveContractPreflightTests(unittest.TestCase):
    def bundle(self, root: Path, *, evidence_mode: int = 0o640) -> Path:
        output = root / "bundle.tar"
        with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
            add(archive, "contract", None, 0o755)
            add(archive, "contract/evidence", None, 0o755)
            add(archive, "contract/evidence/item.json", b"{}\n", evidence_mode)
            for name in (
                "runner-boundary-template-v2.json",
                "runner-boundary-v2.json",
                "reviewer-public-key.pem",
                "reviewer-key.sha256",
            ):
                add(archive, f"contract/{name}", b"{}\n", 0o644)
        return output

    def complete_fixture(
        self, root: Path, *, signed_evidence_mode: str = "0640"
    ) -> tuple[Path, Path, str]:
        package = root / "package"
        (package / "scripts/host").mkdir(parents=True)
        shutil.copytree(ROOT / "github_automation", package / "github_automation")
        shutil.copy2(INSTALLER, package / "scripts/host/install-wsl-jit-evidence.py")
        copier = """#!/usr/bin/env python3
import argparse, shutil
p=argparse.ArgumentParser(); p.add_argument('--input-boundary', '--input', dest='source', required=True); p.add_argument('--output-boundary', '--output', dest='output', required=True); p.add_argument('--measurement-root'); a=p.parse_args(); shutil.copyfile(a.source, a.output)
"""
        (package / "scripts/host/stage-wsl-jit-live-contract.py").write_text(copier)
        (package / "scripts/host/collect-wsl-jit-measurements.py").write_text(copier)
        (package / "scripts/host/verify-wsl-jit-readiness.py").write_text(
            "#!/usr/bin/env python3\nraise SystemExit(0)\n"
        )

        evidence = b'{"fixture":true}\n'
        record = {
            "ref": "evidence/item.json",
            "sha256": hashlib.sha256(evidence).hexdigest(),
            "size": len(evidence),
            "mode": signed_evidence_mode,
            "uid": 0,
            "gid": 0,
        }
        payload = {
            "components": [{"evidence_refs": [record["ref"]]}],
            "host_security": {"checks": []},
            "measurements": {"artifacts": [record]},
        }
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key()
        fingerprint = spki_fingerprint(public)
        signed = canonicalize_jcs(sign_runner_boundary(payload, private)) + b"\n"
        template = canonicalize_jcs(payload) + b"\n"
        public_pem = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        bundle = root / f"complete-{signed_evidence_mode}.tar"
        with tarfile.open(bundle, "w", format=tarfile.PAX_FORMAT) as archive:
            add(archive, "contract", None, 0o755)
            add(archive, "contract/evidence", None, 0o755)
            add(archive, "contract/evidence/item.json", evidence, 0o640)
            add(archive, "contract/runner-boundary-template-v2.json", template, 0o644)
            add(archive, "contract/runner-boundary-v2.json", signed, 0o644)
            add(archive, "contract/reviewer-public-key.pem", public_pem, 0o644)
            add(
                archive,
                "contract/reviewer-key.sha256",
                (fingerprint + "\n").encode("ascii"),
                0o644,
            )
        return bundle, package, fingerprint

    def run_complete_preflight(
        self, preflight, bundle: Path, package: Path, fingerprint: str, parent: Path
    ):
        real_stat = os.stat

        def root_owned(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            fields = list(result)
            fields[4] = fields[5] = 0
            return os.stat_result(fields)

        with (
            mock.patch.object(preflight.os, "stat", side_effect=root_owned),
            mock.patch.object(preflight.os, "chown"),
        ):
            return preflight.preflight(
                bundle,
                expected_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
                expected_bytes=bundle.stat().st_size,
                pinned_fingerprint=fingerprint,
                package_root=package,
                temporary_parent=parent,
                enforce_identity=False,
            )

    def test_complete_preflight_passes_every_bundle_guard(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_complete")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, package, fingerprint = self.complete_fixture(root)
            result = self.run_complete_preflight(
                preflight, bundle, package, fingerprint, root
            )
            self.assertEqual(result["status"], "verified")
            self.assertFalse(result["host_mutated"])
            self.assertEqual(result["measurement_artifacts"], 1)

    def test_resigned_0644_measurement_reaches_shared_installability_guard(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_resigned_bad_mode")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, package, fingerprint = self.complete_fixture(
                root, signed_evidence_mode="0644"
            )
            with self.assertRaisesRegex(
                ValueError, "signed evidence is writable/executable outside root"
            ):
                self.run_complete_preflight(
                    preflight, bundle, package, fingerprint, root
                )

    def test_archive_guard_accepts_only_exact_root_owned_modes(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract")
        with tempfile.TemporaryDirectory() as temporary:
            members = preflight.inspect_archive(self.bundle(Path(temporary)).read_bytes())
            self.assertIn("contract/evidence/item.json", {item.name for item in members})

    def test_archive_guard_rejects_evidence_readable_outside_root(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_bad_mode")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                preflight.PreflightError, "mode is not 0640.*evidence/item.json"
            ):
                preflight.inspect_archive(
                    self.bundle(Path(temporary), evidence_mode=0o644).read_bytes()
                )

    def test_preflight_uses_the_exact_snapshot_bound_to_external_hash(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_snapshot")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, package, fingerprint = self.complete_fixture(root)
            expected = bundle.read_bytes()
            replacement_root = root / "replacement"
            replacement_root.mkdir()
            replacement = self.bundle(replacement_root)
            real_inspect = preflight.inspect_archive

            def replace_path_after_hash(snapshot: bytes):
                bundle.write_bytes(replacement.read_bytes())
                return real_inspect(snapshot)

            with mock.patch.object(
                preflight, "inspect_archive", side_effect=replace_path_after_hash
            ):
                result = self.run_complete_preflight(
                    preflight, bundle, package, fingerprint, root
                )
            self.assertEqual(result["bundle_sha256"], hashlib.sha256(expected).hexdigest())
            self.assertNotEqual(bundle.read_bytes(), expected)

    def test_exact_layout_rejects_unsigned_extra_file(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_extra")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, package, fingerprint = self.complete_fixture(root)
            rebuilt = root / "bundle-with-extra.tar"
            with tarfile.open(bundle, "r:") as source, tarfile.open(
                rebuilt, "w", format=tarfile.PAX_FORMAT
            ) as target:
                for member in source.getmembers():
                    target.addfile(member, source.extractfile(member) if member.isfile() else None)
                add(target, "contract/extra", b"not signed\n", 0o644)
            with self.assertRaisesRegex(preflight.PreflightError, "exact signed/control"):
                self.run_complete_preflight(
                    preflight, rebuilt, package, fingerprint, root
                )

    def test_exact_layout_accepts_pinned_binary_without_source_ref(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_pinned_binary")
        with tempfile.TemporaryDirectory() as temporary:
            contract = Path(temporary)
            manifest = contract / "live/live-artifacts-v1.json"
            manifest.parent.mkdir()
            manifest.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {"kind": "pinned-binary", "source_ref": None},
                            {
                                "kind": "script",
                                "source_ref": "live/source/install.sh",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            names = preflight._required_archive_names(
                contract, {"live/live-artifacts-v1.json": {}}
            )
            self.assertIn("contract/live/source/install.sh", names)
            self.assertNotIn("contract/None", names)

    def test_archive_rejects_member_and_extracted_size_bombs(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_size_limits")
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
            add(archive, "contract", None, 0o755)
            add(
                archive,
                "contract/oversize",
                b"x" * (preflight.MAX_MEMBER_BYTES + 1),
                0o644,
            )
        with self.assertRaisesRegex(preflight.PreflightError, "too large"):
            preflight.inspect_archive(payload.getvalue())

    def test_external_hash_and_size_fail_before_package_or_extraction(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_hash")
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary))
            with self.assertRaisesRegex(preflight.PreflightError, "external hash/size"):
                preflight.preflight(
                    bundle,
                    expected_sha256="0" * 64,
                    expected_bytes=bundle.stat().st_size,
                    pinned_fingerprint="1" * 64,
                    package_root=ROOT,
                    enforce_identity=False,
                )

    def test_validated_output_requires_absent_path_under_private_root_parent(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_output")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "private"
            parent.mkdir(mode=0o700)
            output = parent / "validated-contract"
            sentinel = Path(temporary) / "runtime-sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            real_stat = os.stat

            def root_owned(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if Path(path) == parent:
                    fields = list(result)
                    fields[4] = fields[5] = 0
                    return os.stat_result(fields)
                return result

            with mock.patch.object(preflight.os, "stat", side_effect=root_owned):
                self.assertEqual(
                    preflight.validated_output_destination(output), output.resolve()
                )
            self.assertFalse(output.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
            output.mkdir()
            with self.assertRaisesRegex(preflight.PreflightError, "absent"):
                preflight.validated_output_destination(output)

    def test_validated_output_rejects_group_or_world_accessible_parent(self) -> None:
        preflight = load(PREFLIGHT, "preflight_live_contract_output_mode")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "public"
            parent.mkdir(mode=0o755)
            real_stat = os.stat

            def root_owned(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if Path(path) == parent:
                    fields = list(result)
                    fields[4] = fields[5] = 0
                    return os.stat_result(fields)
                return result

            with mock.patch.object(preflight.os, "stat", side_effect=root_owned):
                with self.assertRaisesRegex(preflight.PreflightError, "private root:root"):
                    preflight.validated_output_destination(parent / "contract")

    def test_shared_installability_guard_rejects_0644_signed_evidence(self) -> None:
        installer = load(INSTALLER, "install_evidence_preflight")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_file = root / "evidence/item.json"
            evidence_file.parent.mkdir()
            evidence_file.write_bytes(b"{}\n")
            os.chmod(evidence_file, 0o644)
            boundary = root / "boundary.json"
            boundary.write_text(
                json.dumps(
                    {
                        "components": [{"evidence_refs": ["evidence/item.json"]}],
                        "host_security": {"checks": []},
                        "measurements": {
                            "artifacts": [
                                {
                                    "ref": "evidence/item.json",
                                    "sha256": hashlib.sha256(b"{}\n").hexdigest(),
                                    "size": 3,
                                    "mode": "0644",
                                    "uid": 0,
                                    "gid": 0,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                installer.InstallError, "writable/executable outside root"
            ):
                installer.validate(boundary, root)

    def test_shared_guard_verifies_actual_owner_mode_hash_and_size(self) -> None:
        installer = load(INSTALLER, "install_evidence_exact_metadata")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence/item.json"
            source.parent.mkdir()
            source.write_bytes(b"{}\n")
            source.chmod(0o640)
            record = {
                "ref": "evidence/item.json",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "size": source.stat().st_size,
                "mode": "0640",
                "uid": 0,
                "gid": 0,
            }
            boundary = root / "boundary.json"
            boundary.write_text(
                json.dumps(
                    {
                        "components": [{"evidence_refs": [record["ref"]]}],
                        "host_security": {"checks": []},
                        "measurements": {"artifacts": [record]},
                    }
                ),
                encoding="utf-8",
            )
            real_stat = os.stat

            def root_owned(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if Path(path) == source:
                    fields = list(result)
                    fields[4] = fields[5] = 0
                    return os.stat_result(fields)
                return result

            with mock.patch.object(installer.os, "stat", side_effect=root_owned):
                _, records = installer.validate(boundary, root)
                self.assertEqual(records[record["ref"]], record)
                source.write_bytes(b"tampered\n")
                with self.assertRaisesRegex(
                    installer.InstallError, "differs from source"
                ):
                    installer.validate(boundary, root)


if __name__ == "__main__":
    unittest.main()
