from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/host/verify-live-artifact-contract.py"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_live_artifact_contract", VERIFIER
    )
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

    def test_all_staged_artifact_kinds_are_accepted_by_the_verifier(self):
        stager = load_stager()
        verifier = load_verifier()
        self.assertTrue(
            {item[3] for item in stager.PUBLIC_ARTIFACTS}.issubset(
                verifier.ALLOWED_ARTIFACT_KINDS
            )
        )

    def verify_fixture(self, verifier, bundle, measurement, prefix):
        return verifier.verify_contract(
            bundle,
            measurement,
            prefix,
            required_targets={self.TARGET},
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
            "artifacts": [
                {
                    "target": self.TARGET,
                    "source_ref": "live/source/runtime.sh",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "mode": "0755",
                    "uid": os.stat(target).st_uid,
                    "gid": os.stat(target).st_gid,
                    "kind": "script",
                }
            ],
        }
        contract_path = measurement / verifier.CONTRACT_REF
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        os.chmod(contract_path, 0o640)

        def record(path: Path, ref: str):
            info, payload = os.stat(path), path.read_bytes()
            return {
                "ref": ref,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": f"{info.st_mode & 0o7777:04o}",
                "uid": info.st_uid,
                "gid": info.st_gid,
            }

        bundle = root / "boundary.json"
        bundle.write_text(
            json.dumps(
                {
                    "measurements": {
                        "artifacts": [
                            record(contract_path, verifier.CONTRACT_REF),
                            record(source, "live/source/runtime.sh"),
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        return verifier, bundle, measurement, root / "installed", target

    def test_exact_live_artifact_contract_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            verifier, bundle, measurement, prefix, _ = self.fixture(Path(tmp))
            self.assertEqual(
                self.verify_fixture(verifier, bundle, measurement, prefix), 1
            )

    def test_hash_mode_and_symlink_drift_fail_closed(self):
        for mutation in ("hash", "mode", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                verifier, bundle, measurement, prefix, target = self.fixture(Path(tmp))
                if mutation == "hash":
                    target.write_text("drift", encoding="utf-8")
                elif mutation == "mode":
                    os.chmod(target, 0o777)
                else:
                    target.unlink()
                    target.symlink_to("/bin/true")
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
                "ref": verifier.CONTRACT_REF,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": f"{info.st_mode & 0o7777:04o}",
                "uid": info.st_uid,
                "gid": info.st_gid,
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
        self.assertIn(
            "installed live runtime artifacts failed signed-contract verification",
            provision,
        )
        self.assertIn("require_live_artifact_contract", activation)
        self.assertIn("signed live artifact contract is invalid or drifted", library)
        for name in (
            "self-hosted-ci-boundary-verify.service",
            "self-hosted-ci-garm.service",
            "self-hosted-ci-network-policy.service",
            "self-hosted-ci-egress-proxy.service",
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
            "packaging/network/squid.conf",
            "garm-provider-incus.toml",
            "prepare-incus-runner-image.sh",
            "configure-garm-jit.sh",
            "/usr/local/bin/garm",
            "/usr/local/bin/garm-cli",
            "/usr/local/libexec/garm/garm-provider-incus",
            "live/live-artifacts-v1.json",
        ):
            self.assertIn(token, source)
        self.assertNotIn('"/etc/self-hosted-ci/garm/config.toml",', source)
        self.assertNotIn('incus-client.key",', source)

    def test_stager_prunes_the_owned_live_namespace_and_is_idempotent(self):
        stager = load_stager()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "live/source/stale.sh"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale\n", encoding="utf-8")
            boundary = {
                "components": [
                    {
                        "id": "garm",
                        "evidence_refs": [
                            "evidence/keep.json",
                            "live/source/stale.sh",
                            "live/live-artifacts-v1.json",
                        ],
                    }
                ],
                "host_security": {
                    "checks": [
                        {
                            "evidence_refs": [
                                "evidence/security.json",
                                "live/source/obsolete-security-check.sh",
                            ]
                        }
                    ]
                },
            }
            expected = copy.deepcopy(boundary)
            expected["components"][0]["evidence_refs"] = ["evidence/keep.json"]
            expected["host_security"]["checks"][0]["evidence_refs"] = [
                "evidence/security.json"
            ]

            stager._reset_live_namespace(boundary, root)
            self.assertEqual(boundary, expected)
            self.assertFalse((root / "live").exists())

            first = copy.deepcopy(boundary)
            stager._reset_live_namespace(boundary, root)
            self.assertEqual(boundary, first)
            self.assertFalse((root / "live").exists())

    def test_stager_rejects_an_unsafe_or_malformed_live_namespace(self):
        stager = load_stager()
        for kind in ("symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                live = root / "live"
                if kind == "symlink":
                    live.symlink_to(root / "missing")
                else:
                    live.write_text("not a directory\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "live measurement root"):
                    stager._reset_live_namespace({"components": []}, root)

        malformed = {
            "components": [{"id": "garm", "evidence_refs": ["live/ok", 1]}]
        }
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            ValueError, "must contain strings"
        ):
            stager._reset_live_namespace(malformed, Path(temporary))

    def test_full_staging_is_reproducible_across_reconciliation(self):
        stager = load_stager()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "runtime.sh"
            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            measurement = root / "measurements"
            stale = measurement / "live/source/stale.sh"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale\n", encoding="utf-8")
            initial = root / "initial.json"
            first, second = root / "first.json", root / "second.json"
            initial.write_text(
                json.dumps(
                    {
                        "components": [
                            {
                                "id": "garm",
                                "evidence_refs": ["live/source/stale.sh"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            artifacts = ((
                "runtime.sh",
                self.TARGET,
                "0755",
                "script",
                "garm",
            ),)
            with (
                mock.patch.object(stager, "ROOT", root),
                mock.patch.object(stager, "PUBLIC_ARTIFACTS", artifacts),
                mock.patch.object(stager, "PINNED_BINARIES", ()),
                mock.patch.object(stager.os, "geteuid", return_value=0),
                mock.patch.object(stager.os, "chown"),
                mock.patch.object(
                    stager.grp, "getgrnam", return_value=mock.Mock(gr_gid=0)
                ),
            ):
                self.assertEqual(
                    stager.main([
                        "--input-boundary", str(initial),
                        "--output-boundary", str(first),
                        "--measurement-root", str(measurement),
                    ]),
                    0,
                )
                snapshot = {
                    path.relative_to(measurement).as_posix(): (
                        path.read_bytes(), path.stat().st_mode & 0o7777
                    )
                    for path in measurement.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(
                    stager.main([
                        "--input-boundary", str(first),
                        "--output-boundary", str(second),
                        "--measurement-root", str(measurement),
                    ]),
                    0,
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(snapshot, {
                path.relative_to(measurement).as_posix(): (
                    path.read_bytes(), path.stat().st_mode & 0o7777
                )
                for path in measurement.rglob("*")
                if path.is_file()
            })
            self.assertNotIn("live/source/stale.sh", snapshot)


if __name__ == "__main__":
    unittest.main()
