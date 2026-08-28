from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.bootstrap_boundary import (
    AUTHORIZATION,
    BOOTSTRAP_ATTESTATION_DOMAIN,
    BootstrapBoundaryError,
    build_bootstrap_boundary,
    sign_bootstrap_boundary,
    verify_bootstrap_boundary,
)
from github_automation.crypto import sign_detached, spki_fingerprint

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "scripts/host/build-wsl-jit-bootstrap.py"
BUILD_MANIFEST = ROOT / "scripts/host/build-wsl-jit-bootstrap-manifest.py"
SIGN = ROOT / "scripts/host/sign-wsl-jit-bootstrap.py"
VERIFY = ROOT / "scripts/host/verify-wsl-jit-bootstrap.py"
SCHEMA = ROOT / "schemas/bootstrap-boundary-v1.schema.json"
SID = "S-1-5-21-1-2-3-1008"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def public_manifest() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "manifest.json"
        result = subprocess.run(
            [sys.executable, str(BUILD_MANIFEST), "--output", str(output)],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(output.read_text())


def windows_observation() -> dict:
    rules = [
        {
            "sid": sid,
            "type": "Allow",
            "rights": "FullControl",
            "inherited": False,
            "inheritance_flags": "ContainerInherit, ObjectInherit",
            "propagation_flags": "None",
        }
        for sid in ("S-1-5-18", "S-1-5-32-544", SID)
    ]
    check_names = (
        "account_name",
        "account_sid",
        "account_enabled",
        "account_local",
        "account_non_admin",
        "registration_hive_accessible",
        "registration_unique",
        "registration_guid",
        "registration_version",
        "registration_base_path",
        "registration_owner",
        "base_path_exists",
        "base_path_reparse_free",
        "base_path_acl",
    )
    return {
        "schema": "self-hosted-ci/windows-wsl-semantic-contract",
        "schema_version": 1,
        "observed_at": timestamp(NOW).replace("Z", "+00:00"),
        "collector_identity_sid": "S-1-5-32-544",
        "expected": {
            "service_account": "selfhosted-ci-svc",
            "service_sid": SID,
            "distro_name": "Ubuntu-24.04-CI",
            "base_path": r"C:\ProgramData\self-hosted-ci\wsl",
            "wsl_version": 2,
        },
        "observations": {
            "account": {
                "name": "selfhosted-ci-svc",
                "sid": SID,
                "enabled": True,
                "principal_source": "Local",
                "effective_administrator": False,
            },
            "registration": {
                "accessible": True,
                "exact_match_count": 1,
                "matches": [
                    {
                        "key": "{12345678-1234-1234-1234-123456789abc}",
                        "distribution_name": "Ubuntu-24.04-CI",
                        "version": 2,
                        "base_path": r"C:\ProgramData\self-hosted-ci\wsl",
                        "owner_sid": SID,
                    }
                ],
                "error": None,
            },
            "base_path": {
                "exists": True,
                "canonical_path": r"C:\ProgramData\self-hosted-ci\wsl",
                "reparse_free": True,
                "acl": {
                    "owner_sid": "S-1-5-32-544",
                    "inheritance_protected": True,
                    "rules": rules,
                },
                "error": None,
            },
        },
        "checks": {
            name: {"status": "satisfied", "reason": "observed"} for name in check_names
        },
        "contract_satisfied": True,
        "side_effects": {
            "scheduled_task_created": False,
            "password_rotated": False,
            "wsl_started": False,
            "github_contacted": False,
            "runner_registration_changed": False,
            "evidence_file_created": True,
        },
    }


def wsl_observation() -> dict:
    empty_names_digest = hashlib.sha256(b"[]").hexdigest()
    project = {
        "features.images": "false",
        "features.profiles": "true",
        "features.storage.volumes": "true",
        "restricted": "true",
        "restricted.containers.privilege": "isolated",
        "restricted.containers.nesting": "block",
        "restricted.containers.lowlevel": "block",
        "restricted.devices.disk": "managed",
        "restricted.devices.nic": "managed",
        "restricted.networks.access": "ci-jit-isolated",
        "limits.instances": "1",
        "limits.containers": "1",
        "limits.virtual-machines": "0",
        "limits.cpu": "2",
        "limits.memory": "4GiB",
        "limits.processes": "2048",
        "limits.disk": "12GiB",
    }
    profile = {
        "security.privileged": "false",
        "security.nesting": "false",
        "security.idmap.isolated": "true",
        "limits.cpu": "2",
        "limits.memory": "4GiB",
        "limits.processes": "2048",
    }
    bridge = {
        "ipv4.address": "10.254.0.1/28",
        "ipv4.dhcp": "true",
        "ipv4.dhcp.ranges": "10.254.0.2-10.254.0.2",
        "ipv4.dhcp.gateway": "none",
        "ipv4.nat": "false",
        "ipv4.firewall": "false",
        "ipv6.address": "none",
        "ipv6.nat": "false",
        "ipv6.firewall": "false",
        "dns.mode": "none",
    }
    pins = {
        "incus": {"version": "6.0.0-1ubuntu0.3"},
        "garm": {
            "version": "0.2.1",
            "artifact_sha256": "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746",
            "binary_sha256": "b04fda186bfa0c98a902a3bb7525987217565681ec33b553921945dbb574b87e",
        },
        "garm-cli": {
            "version": "0.2.1",
            "artifact_sha256": "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e",
            "binary_sha256": "a973c9061cf7962b4f90c8220ed6f6cc8abeeed20780ea8b9e31ce6dfc99bd9b",
        },
        "garm-provider-incus": {
            "version": "0.1.5",
            "artifact_sha256": "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f",
            "binary_sha256": "0fe2c592cece494ad5fc6a6fe05ef2e621fb5d47fb03cc472c2b1d6739428891",
        },
    }
    binary_hashes = {
        "garm": pins["garm"]["binary_sha256"],
        "garm-cli": pins["garm-cli"]["binary_sha256"],
        "garm-provider-incus": pins["garm-provider-incus"]["binary_sha256"],
        "incus": "1" * 64,
        "nft": "2" * 64,
        "squid": "3" * 64,
    }
    return {
        "schema_version": 1,
        "collector": "wsl-jit-semantic-observations",
        "observed_at": timestamp(NOW + timedelta(seconds=1)),
        "expected_distro": "Ubuntu-24.04-CI",
        "collection_status": "complete",
        "observations": {
            "wsl_boundary": {
                "distro_environment_matches": True,
                "wsl_conf": {
                    "readable": True,
                    "sha256": "4" * 64,
                    "settings": {
                        "automount.enabled": "false",
                        "automount.mountfstab": "false",
                        "interop.enabled": "false",
                        "interop.appendwindowspath": "false",
                    },
                },
            },
            "mounts_and_interop": {
                "mount_class_counts": {
                    "drvfs": 0,
                    "windows_drive_target": 0,
                    "docker_desktop": 0,
                    "wsl_shared": 0,
                },
                "wsl_interop": {"present": False, "enabled": False},
                "windows_path_entry_count": 0,
            },
            "credential_surfaces": {
                "docker_socket": False,
                "docker_desktop_socket": False,
                "persistent_actions_runner": False,
                "garm_control_credentials": False,
                "github_or_authority_private_keys": False,
                "ssh_agent_socket": False,
                "private_or_deploy_key_candidates": False,
                "persistent_actions_runner_service_unit": False,
                "recursive_credential_candidates": False,
            },
            "linux_identities": {
                "garm-manager": {
                    "present": True,
                    "uid": 990,
                    "gid": 990,
                    "primary_group": "garm-manager",
                    "supplementary_groups": [],
                    "home": "/var/lib/garm",
                    "shell": "/usr/sbin/nologin",
                }
            },
            "software": {
                "expected_pins": pins,
                "packages": {
                    name: {"installed": True, "version": version}
                    for name, version in {
                        "dnsmasq-base": "2.90",
                        "e2fsprogs": "1.47",
                        "incus": "6.0.0-1ubuntu0.3",
                        "nftables": "1.0",
                        "squid": "6.6",
                        "util-linux": "2.39",
                    }.items()
                },
                "binaries": {
                    name: {
                        "path": f"/expected/{name}",
                        "present": True,
                        "sha256": digest,
                    }
                    for name, digest in binary_hashes.items()
                },
            },
            "incus": {
                "project": {"present": True, "config": project},
                "profile": {
                    "present": True,
                    "config": profile,
                    "devices": {
                        "root": {
                            "path": "/",
                            "pool": "ci-jit-dedicated",
                            "size": "12GiB",
                            "type": "disk",
                        },
                        "eth0": {
                            "name": "eth0",
                            "network": "ci-jit-isolated",
                            "security.ipv4_filtering": "true",
                            "security.ipv6_filtering": "true",
                            "security.mac_filtering": "true",
                            "type": "nic",
                        },
                    },
                },
                "storage": {
                    "present": True,
                    "config": {
                        "source": "/var/lib/self-hosted-ci/incus-storage/ci-jit/pool"
                    },
                    "driver": "dir",
                },
                "bridge": {"present": True, "config": bridge, "type": "bridge"},
                "instances": {
                    "observable": True,
                    "count": 0,
                    "names_sha256": empty_names_digest,
                },
            },
            "network": {
                "nftables": {
                    "observable": True,
                    "table_names": [],
                    "rule_count": 0,
                    "canonical_sha256": "5" * 64,
                },
                "expected_listeners": {
                    "dns": False,
                    "egress-proxy": False,
                    "garm-proxy": False,
                },
                "resolver_classes": {
                    "loopback": 0,
                    "private": 1,
                    "public": 0,
                    "link_local": 0,
                    "invalid": 0,
                },
            },
            "garm": {
                "services": {
                    name: {"active": "inactive", "enabled": "disabled"}
                    for name in ("garm.service", "self-hosted-ci-garm.service")
                },
                "process_count": 0,
                "health_state": {
                    "observable": False,
                    "zero_scale_sets": None,
                    "configured_target_count": None,
                },
                "state_database_present": False,
                "persistent_runner_registration_present": False,
            },
        },
        "probe_errors": [],
    }


class BootstrapBoundaryTests(unittest.TestCase):
    def test_build_sign_verify_authorizes_only_inert_provisioning(self):
        windows, wsl = windows_observation(), wsl_observation()
        private = ed25519.Ed25519PrivateKey.generate()
        manifest = public_manifest()
        evidence = sign_bootstrap_boundary(
            build_bootstrap_boundary(windows, wsl, manifest, now=NOW, nonce="1" * 32),
            private,
        )
        decision = verify_bootstrap_boundary(
            evidence,
            windows,
            wsl,
            manifest,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            expected_nonce=evidence["nonce"],
            source_root=ROOT,
            now=NOW,
        )
        self.assertTrue(decision.authorized, decision.blockers)
        self.assertEqual(evidence["authorization"], AUTHORIZATION)
        self.assertNotEqual(
            BOOTSTRAP_ATTESTATION_DOMAIN,
            b"self-hosted-ci/wsl-jit-boundary-attestation/v1",
        )

    def test_each_authority_expansion_is_rejected(self):
        private = ed25519.Ed25519PrivateKey.generate()
        manifest = public_manifest()
        unsigned = build_bootstrap_boundary(
            windows_observation(),
            wsl_observation(),
            manifest,
            now=NOW,
            nonce="2" * 32,
        )
        for field in (
            "activation_authorized",
            "github_contact_authorized",
            "runtime_ready_authorized",
            "runner_registration_authorized",
        ):
            changed = copy.deepcopy(unsigned)
            changed["authorization"][field] = True
            evidence = sign_bootstrap_boundary(changed, private)
            decision = verify_bootstrap_boundary(
                evidence,
                windows_observation(),
                wsl_observation(),
                manifest,
                private.public_key(),
                pinned_fingerprint=spki_fingerprint(private.public_key()),
                expected_nonce=evidence["nonce"],
                source_root=ROOT,
                now=NOW,
            )
            self.assertFalse(decision.authorized)
            self.assertIn("authorization-not-inert-only", decision.blockers)

    def test_observation_drift_and_wrong_domain_signature_are_rejected(self):
        private = ed25519.Ed25519PrivateKey.generate()
        windows, wsl = windows_observation(), wsl_observation()
        manifest = public_manifest()
        evidence = sign_bootstrap_boundary(
            build_bootstrap_boundary(windows, wsl, manifest, now=NOW, nonce="3" * 32),
            private,
        )
        drifted = copy.deepcopy(wsl)
        drifted["observations"]["incus"]["instances"]["count"] = 1
        decision = verify_bootstrap_boundary(
            evidence,
            windows,
            drifted,
            manifest,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            expected_nonce=evidence["nonce"],
            source_root=ROOT,
            now=NOW,
        )
        self.assertFalse(decision.authorized)
        self.assertIn("wsl-incus-instances", decision.blockers)
        self.assertIn("wsl-observation-binding", decision.blockers)

        wrong_domain = copy.deepcopy(evidence)
        unsigned = {
            key: item for key, item in wrong_domain.items() if key != "attestation"
        }
        wrong_domain["attestation"]["signature"] = sign_detached(
            unsigned,
            private,
            domain=b"self-hosted-ci/wsl-jit-boundary-attestation/v1",
        )
        decision = verify_bootstrap_boundary(
            wrong_domain,
            windows,
            wsl,
            manifest,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            expected_nonce=evidence["nonce"],
            source_root=ROOT,
            now=NOW,
        )
        self.assertFalse(decision.authorized)
        self.assertIn("attestation-signature", decision.blockers)

    def test_windows_unsatisfied_or_wsl_unknown_never_builds(self):
        windows = windows_observation()
        manifest = public_manifest()
        windows["checks"]["account_sid"]["status"] = "unobserved"
        with self.assertRaises(BootstrapBoundaryError):
            build_bootstrap_boundary(windows, wsl_observation(), manifest, now=NOW)
        wsl = wsl_observation()
        wsl["observations"]["credential_surfaces"]["ssh_agent_socket"] = None
        with self.assertRaises(BootstrapBoundaryError):
            build_bootstrap_boundary(windows_observation(), wsl, manifest, now=NOW)

    def test_freshness_expiry_and_nonce_are_fail_closed(self):
        manifest = public_manifest()
        windows, wsl = windows_observation(), wsl_observation()
        stale = copy.deepcopy(windows)
        stale["observed_at"] = timestamp(NOW - timedelta(seconds=901))
        with self.assertRaisesRegex(
            BootstrapBoundaryError, "windows-observation-stale"
        ):
            build_bootstrap_boundary(stale, wsl, manifest, now=NOW)
        future = copy.deepcopy(wsl)
        future["observed_at"] = timestamp(NOW + timedelta(seconds=31))
        with self.assertRaisesRegex(
            BootstrapBoundaryError, "wsl-observation-from-future"
        ):
            build_bootstrap_boundary(windows, future, manifest, now=NOW)
        first = build_bootstrap_boundary(windows, wsl, manifest, now=NOW)
        second = build_bootstrap_boundary(windows, wsl, manifest, now=NOW)
        self.assertNotEqual(first["nonce"], second["nonce"])

        private = ed25519.Ed25519PrivateKey.generate()
        evidence = sign_bootstrap_boundary(first, private)
        replayed_with_different_challenge = verify_bootstrap_boundary(
            evidence,
            windows,
            wsl,
            manifest,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            expected_nonce="f" * 32,
            source_root=ROOT,
            now=NOW,
        )
        self.assertFalse(replayed_with_different_challenge.authorized)
        self.assertIn("bootstrap-nonce", replayed_with_different_challenge.blockers)
        expired = verify_bootstrap_boundary(
            evidence,
            windows,
            wsl,
            manifest,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            expected_nonce=evidence["nonce"],
            source_root=ROOT,
            now=NOW + timedelta(seconds=601),
        )
        self.assertFalse(expired.authorized)
        self.assertIn("bootstrap-expired", expired.blockers)

    def test_public_manifest_binds_exact_mapping_and_current_bytes(self):
        manifest = public_manifest()
        changed = copy.deepcopy(manifest)
        changed["artifacts"].pop()
        with self.assertRaisesRegex(BootstrapBoundaryError, "public-manifest"):
            build_bootstrap_boundary(
                windows_observation(), wsl_observation(), changed, now=NOW
            )

        private = ed25519.Ed25519PrivateKey.generate()
        evidence = sign_bootstrap_boundary(
            build_bootstrap_boundary(
                windows_observation(),
                wsl_observation(),
                manifest,
                now=NOW,
                nonce="4" * 32,
            ),
            private,
        )
        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary)
            for artifact in manifest["artifacts"]:
                source = ROOT / artifact["source"]
                destination = copied_root / artifact["source"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            drifted_source = copied_root / manifest["artifacts"][0]["source"]
            drifted_source.write_bytes(drifted_source.read_bytes() + b"\n")
            decision = verify_bootstrap_boundary(
                evidence,
                windows_observation(),
                wsl_observation(),
                manifest,
                private.public_key(),
                pinned_fingerprint=spki_fingerprint(private.public_key()),
                expected_nonce=evidence["nonce"],
                source_root=copied_root,
                now=NOW,
            )
        self.assertFalse(decision.authorized)
        self.assertTrue(
            any(
                blocker.startswith("public-source-drift:")
                for blocker in decision.blockers
            )
        )

    def test_cli_round_trip_and_key_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows_path, wsl_path = root / "windows.json", root / "wsl.json"
            manifest_path = root / "manifest.json"
            windows_path.write_text(json.dumps(windows_observation()))
            wsl_path.write_text(json.dumps(wsl_observation()))
            unsigned, signed = root / "unsigned.json", root / "signed.json"
            private = ed25519.Ed25519PrivateKey.generate()
            private_path, public_path = (
                root / "reviewer-private.pem",
                root / "reviewer-public.pem",
            )
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            os.chmod(private_path, 0o600)
            public_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            commands = (
                [
                    sys.executable,
                    str(BUILD_MANIFEST),
                    "--output",
                    str(manifest_path),
                ],
                [
                    sys.executable,
                    str(BUILD),
                    "--windows-observation",
                    str(windows_path),
                    "--wsl-observation",
                    str(wsl_path),
                    "--public-manifest",
                    str(manifest_path),
                    "--nonce",
                    "9" * 32,
                    "--output",
                    str(unsigned),
                ],
                [
                    sys.executable,
                    str(SIGN),
                    "--input",
                    str(unsigned),
                    "--output",
                    str(signed),
                    "--reviewer-private-key",
                    str(private_path),
                ],
                [
                    sys.executable,
                    str(VERIFY),
                    "--evidence",
                    str(signed),
                    "--windows-observation",
                    str(windows_path),
                    "--wsl-observation",
                    str(wsl_path),
                    "--public-manifest",
                    str(manifest_path),
                    "--reviewer-public-key",
                    str(public_path),
                    "--pinned-fingerprint",
                    spki_fingerprint(private.public_key()),
                    "--expected-nonce",
                    "9" * 32,
                ],
            )
            for command in commands:
                result = subprocess.run(
                    command, text=True, capture_output=True, check=False
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            verified = json.loads(result.stdout)
            self.assertEqual(verified, {"authorized": True, "blockers": []})
            wrong = subprocess.run(
                [*commands[-1][:-1], "0" * 64],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(wrong.returncode, 3)

    def test_schema_and_cli_contract_are_exact(self):
        schema = json.loads(SCHEMA.read_text())
        self.assertFalse(schema["additionalProperties"])
        for script in (BUILD_MANIFEST, BUILD, SIGN, VERIFY):
            compile(script.read_text(), str(script), "exec")
        verify_source = VERIFY.read_text()
        for option in (
            "--evidence",
            "--windows-observation",
            "--wsl-observation",
            "--public-manifest",
            "--expected-nonce",
            "--reviewer-public-key",
            "--pinned-fingerprint",
        ):
            self.assertIn(option, verify_source)


if __name__ == "__main__":
    unittest.main()
