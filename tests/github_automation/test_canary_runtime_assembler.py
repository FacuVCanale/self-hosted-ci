from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.canary_boundary import sign_canary_authorization
from github_automation.crypto import canonicalize_jcs, spki_fingerprint
from tests.github_automation.test_canary_boundary import authorization


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/assemble-jit-canary-runtime.py"
SPEC = importlib.util.spec_from_file_location("canary_runtime_assembler", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ASSEMBLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSEMBLER)


class CanaryRuntimeAssemblerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.reviewer = ed25519.Ed25519PrivateKey.generate()
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.paths: dict[str, Path] = {}
        self._bytes(
            "reviewer-public.pem",
            self.reviewer.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        self._bytes(
            "allocation-private.pem",
            self.signer.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            private=True,
        )
        auth = authorization()
        signer_fingerprint = spki_fingerprint(self.signer.public_key())
        entity = dict(auth["garm_entity"])
        entity["entity_flag"] = "--repo"
        repository_id = str(auth["repository_id"])
        self._json(
            "dispatcher.json",
            {
                "schema_version": 1,
                "purpose": "workflow-dispatch",
                "app_id": 10,
                "app_slug": "canary-dispatcher",
                "installation_id": 11,
                "repository": auth["repository"],
                "repository_id": auth["repository_id"],
                "repository_selection": "selected",
                "default_branch": "main",
                "workflow_id": "ci-jit-canary-child.yml",
                "workflow_path": ".github/workflows/ci-jit-canary-child.yml",
                "permissions": {
                    "metadata": "read",
                    "pull_requests": "read",
                    "actions": "write",
                    "administration": "read",
                },
                "private_key_file": "/etc/self-hosted-ci/secrets/dispatcher.pem",
            },
            private=True,
        )
        self._json(
            "health.json",
            {
                "schema_version": 3,
                "garm_cli_home": "/run/self-hosted-ci/garm-cli",
                "manager_configured": True,
                "provider_configured": True,
                "image_configured": True,
                "broker_configured": True,
                "zero_scale_sets": True,
                "image": {
                    "alias": auth["image_alias"],
                    "fingerprint": auth["image_fingerprint"],
                },
                "targets": {repository_id: entity},
            },
            private=True,
        )
        self._json(
            "broker.json",
            {
                "allocation_signer_fingerprint": signer_fingerprint,
                "garm_cli_home": "/run/self-hosted-ci/garm-cli",
                "provider_name": "incus_ci_jit",
                "image_alias": auth["image_alias"],
                "image_fingerprint": auth["image_fingerprint"],
                "live_job_verifier": "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py",
                "targets": {repository_id: entity},
            },
            private=True,
        )
        self._json("authorization-template.json", auth, private=True)
        self._bytes("live-verifier.py", b"#!/usr/bin/env python3\nprint('ok')\n")
        self._bytes("network-policy.sh", b"#!/bin/sh\nexit 0\n")
        self._json(
            "bootstrap-receipt.json",
            {"schema_version": 1, "receipt_digest": "a" * 64},
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _bytes(self, name: str, data: bytes, private: bool = False):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600 if private else 0o644)
        self.paths[name] = path

    def _json(self, name: str, value, private: bool = False):
        self._bytes(name, canonicalize_jcs(value) + b"\n", private)

    def prepare_args(self, output: Path):
        return [
            "prepare",
            "--output-directory", str(output),
            "--authorization-template", str(self.paths["authorization-template.json"]),
            "--dispatcher-app-config", str(self.paths["dispatcher.json"]),
            "--default-branch", "main",
            "--reviewer-public-key", str(self.paths["reviewer-public.pem"]),
            "--allocation-signer-private-key", str(self.paths["allocation-private.pem"]),
            "--garm-health-file", str(self.paths["health.json"]),
            "--broker-config-file", str(self.paths["broker.json"]),
            "--live-job-verifier", str(self.paths["live-verifier.py"]),
            "--network-policy", str(self.paths["network-policy.sh"]),
            "--bootstrap-install-receipt", str(self.paths["bootstrap-receipt.json"]),
            "--reviewer-public-key-runtime-path", "/etc/self-hosted-ci/boundary-reviewer-public-key.pem",
            "--allocation-signer-runtime-path", "/etc/self-hosted-ci/secrets/allocation.pem",
            "--garm-health-runtime-path", "/var/lib/self-hosted-ci/garm/health-state.json",
            "--broker-config-runtime-path", "/etc/self-hosted-ci/garm-allocation-broker.json",
            "--live-job-verifier-runtime-path", "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py",
            "--network-policy-runtime-path", "/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh",
            "--bootstrap-install-receipt-runtime-path", "/var/lib/self-hosted-ci/bootstrap/bootstrap-install-receipt-v1.json",
        ]

    def run_main(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return ASSEMBLER.main(arguments)

    def test_help_exposes_two_phase_external_signing_boundary(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("prepare", result.stdout)
        self.assertIn("bundle", result.stdout)
        self.assertIn("without signing or GitHub", result.stdout)
        self.assertIn("contact", result.stdout)

    def test_prepare_measures_live_digests_and_emits_exact_configs(self):
        output = self.root / "prepared"
        result = self.run_main(self.prepare_args(output))
        self.assertEqual(0, result)
        self.assertEqual(
            {
                "runtime-config.json",
                "authorization-unsigned.json",
                "prepare-manifest.json",
            },
            {path.name for path in output.iterdir()},
        )
        dispatcher_bytes = self.paths["dispatcher.json"].read_bytes()
        dispatcher = json.loads(dispatcher_bytes)
        runtime = json.loads((output / "runtime-config.json").read_text())
        unsigned = json.loads((output / "authorization-unsigned.json").read_text())
        manifest = json.loads((output / "prepare-manifest.json").read_text())
        self.assertEqual(
            hashlib.sha256(dispatcher_bytes).hexdigest(),
            unsigned["github_app_config_digest"],
        )
        self.assertEqual(
            {
                "metadata": "read",
                "pull_requests": "read",
                "actions": "write",
                "administration": "read",
            },
            dispatcher["permissions"],
        )
        self.assertEqual(
            hashlib.sha256(self.paths["live-verifier.py"].read_bytes()).hexdigest(),
            unsigned["live_job_verifier_digest"],
        )
        self.assertEqual(
            spki_fingerprint(self.signer.public_key()),
            unsigned["allocation_signer_fingerprint"],
        )
        self.assertEqual(
            str(self.paths["dispatcher.json"].resolve()),
            runtime["digested_files"]["github_app_config"],
        )
        self.assertEqual(
            hashlib.sha256(dispatcher_bytes).hexdigest(),
            manifest["live_dispatcher_app_config"]["sha256"],
        )
        self.assertFalse(manifest["github_contacted"])
        self.assertFalse(manifest["authorization_signed"])
        for path in output.iterdir():
            self.assertEqual(0o600, stat_mode(path))

    def test_prepare_accepts_exact_organization_runner_group_and_rejects_drift(self):
        auth = json.loads(self.paths["authorization-template.json"].read_text())
        auth["repository"] = "alethia-earth/Overworld"
        auth["repository_id"] = 1172953958
        auth["workflow_ref"] = "alethia-earth/Overworld/.github/workflows/ci-jit-canary-child.yml@refs/heads/master"
        auth["garm_entity"] = {
            "authority_kind": "organization-runner-group",
            "entity_id": "12345678-1234-4123-8123-123456789abc",
            "entity_name": "alethia-earth",
            "runner_group": "overworld-ci-jit",
        }
        dispatcher = json.loads(self.paths["dispatcher.json"].read_text())
        dispatcher.update(repository=auth["repository"], repository_id=auth["repository_id"], default_branch="master")
        target = dict(auth["garm_entity"], entity_flag="--org")
        health = json.loads(self.paths["health.json"].read_text())
        broker = json.loads(self.paths["broker.json"].read_text())
        health["targets"] = {str(auth["repository_id"]): target}
        broker["targets"] = {str(auth["repository_id"]): target}
        self._json("authorization-template.json", auth, private=True)
        self._json("dispatcher.json", dispatcher, private=True)
        self._json("health.json", health, private=True)
        self._json("broker.json", broker, private=True)

        output = self.root / "prepared-org"
        args = self.prepare_args(output)
        args[args.index("--default-branch") + 1] = "master"
        self.assertEqual(0, self.run_main(args))

        original_broker = json.loads(self.paths["broker.json"].read_text())
        for index, (field, value) in enumerate((("runner_group", "wrong-group"), ("entity_flag", "--repo"))):
            drifted = json.loads(self.paths["broker.json"].read_text())
            drifted["targets"][str(auth["repository_id"])][field] = value
            self._json("broker.json", drifted, private=True)
            with self.subTest(field=field):
                drift_args = self.prepare_args(self.root / f"prepared-org-drift-{index}")
                drift_args[drift_args.index("--default-branch") + 1] = "master"
                self.assertNotEqual(0, self.run_main(drift_args))
            self._json("broker.json", original_broker, private=True)

    def test_timeout_scenario_completes_before_default_observer_deadline(self):
        workflow = (
            ROOT / "templates/workflows/ci-jit-canary-child.yml"
        ).read_text(encoding="utf-8")
        local_job = workflow.split("  local-canary:\n", 1)[1]
        timeout_minutes = int(
            re.search(r"(?m)^    timeout-minutes: ([0-9]+)$", local_job).group(1)
        )
        timeout_sleep = int(
            re.search(r"(?m)^            timeout\) exec sleep ([0-9]+) ;;$", local_job).group(1)
        )
        job_timeout_seconds = timeout_minutes * 60
        observer_timeout = ASSEMBLER.DEFAULT_REQUEST_TIMEOUT_SECONDS
        self.assertGreater(timeout_sleep, job_timeout_seconds)
        self.assertGreaterEqual(observer_timeout - job_timeout_seconds, 60)

    def test_bundle_accepts_only_matching_external_signature_and_exact_tar(self):
        prepared = self.root / "prepared"
        self.assertEqual(0, self.run_main(self.prepare_args(prepared)))
        unsigned = json.loads((prepared / "authorization-unsigned.json").read_text())
        signed = self.root / "signed.json"
        signed.write_bytes(
            canonicalize_jcs(sign_canary_authorization(unsigned, self.reviewer)) + b"\n"
        )
        signed.chmod(0o600)
        bundle = self.root / "canary-runtime-bundle.tar"
        manifest = self.root / "canary-runtime-bundle.manifest.json"
        result = self.run_main(
            [
                "bundle",
                "--prepared-directory", str(prepared),
                "--signed-authorization", str(signed),
                "--reviewer-public-key", str(self.paths["reviewer-public.pem"]),
                "--output-tar", str(bundle),
                "--output-manifest", str(manifest),
            ]
        )
        self.assertEqual(0, result)
        with tarfile.open(bundle, "r:") as archive:
            self.assertEqual(
                ["canary/authorization.json", "canary/runtime-config.json"],
                archive.getnames(),
            )
            for member in archive.getmembers():
                self.assertEqual((0, 0, 0o600, 0), (member.uid, member.gid, member.mode, member.mtime))
        receipt = json.loads(manifest.read_text())
        self.assertEqual(bundle.stat().st_size, receipt["bundle"]["bytes"])
        self.assertEqual(
            hashlib.sha256(bundle.read_bytes()).hexdigest(),
            receipt["bundle"]["sha256"],
        )
        self.assertFalse(receipt["github_contacted"])
        self.assertFalse(receipt["authorization_signed_by_assembler"])

    def test_prepare_rejects_permission_or_authority_drift(self):
        dispatcher = json.loads(self.paths["dispatcher.json"].read_text())
        dispatcher["permissions"].pop("pull_requests")
        self._json("dispatcher.json", dispatcher, private=True)
        self.assertEqual(2, self.run_main(self.prepare_args(self.root / "blocked")))

    def test_bundle_rejects_signed_authorization_from_another_preparation(self):
        prepared = self.root / "prepared"
        self.assertEqual(0, self.run_main(self.prepare_args(prepared)))
        unsigned = json.loads((prepared / "authorization-unsigned.json").read_text())
        unsigned["nonce"] = "f" * 32
        signed = self.root / "signed.json"
        signed.write_bytes(
            canonicalize_jcs(sign_canary_authorization(unsigned, self.reviewer)) + b"\n"
        )
        signed.chmod(0o600)
        self.assertEqual(
            2,
            self.run_main(
                [
                    "bundle",
                    "--prepared-directory", str(prepared),
                    "--signed-authorization", str(signed),
                    "--reviewer-public-key", str(self.paths["reviewer-public.pem"]),
                    "--output-tar", str(self.root / "bundle.tar"),
                    "--output-manifest", str(self.root / "manifest.json"),
                ]
            ),
        )

    def test_bundle_rejects_tampered_prepared_runtime(self):
        prepared = self.root / "prepared"
        self.assertEqual(0, self.run_main(self.prepare_args(prepared)))
        unsigned = json.loads((prepared / "authorization-unsigned.json").read_text())
        signed = self.root / "signed.json"
        signed.write_bytes(
            canonicalize_jcs(sign_canary_authorization(unsigned, self.reviewer)) + b"\n"
        )
        signed.chmod(0o600)
        runtime = json.loads((prepared / "runtime-config.json").read_text())
        runtime["request_timeout_seconds"] = 301
        (prepared / "runtime-config.json").write_bytes(canonicalize_jcs(runtime) + b"\n")
        self.assertEqual(
            2,
            self.run_main(
                [
                    "bundle",
                    "--prepared-directory", str(prepared),
                    "--signed-authorization", str(signed),
                    "--reviewer-public-key", str(self.paths["reviewer-public.pem"]),
                    "--output-tar", str(self.root / "tampered.tar"),
                    "--output-manifest", str(self.root / "tampered.json"),
                ]
            ),
        )

    def test_bundle_remeasures_same_preinstalled_dispatcher_app_bytes(self):
        prepared = self.root / "prepared"
        self.assertEqual(0, self.run_main(self.prepare_args(prepared)))
        unsigned = json.loads((prepared / "authorization-unsigned.json").read_text())
        signed = self.root / "signed.json"
        signed.write_bytes(
            canonicalize_jcs(sign_canary_authorization(unsigned, self.reviewer)) + b"\n"
        )
        signed.chmod(0o600)
        dispatcher = json.loads(self.paths["dispatcher.json"].read_text())
        dispatcher["app_slug"] = "drifted-dispatcher"
        self.paths["dispatcher.json"].write_bytes(canonicalize_jcs(dispatcher) + b"\n")
        self.assertEqual(
            2,
            self.run_main(
                [
                    "bundle",
                    "--prepared-directory", str(prepared),
                    "--signed-authorization", str(signed),
                    "--reviewer-public-key", str(self.paths["reviewer-public.pem"]),
                    "--output-tar", str(self.root / "dispatcher-drift.tar"),
                    "--output-manifest", str(self.root / "dispatcher-drift.json"),
                ]
            ),
        )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
