from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-outbound-worker-runtime.py"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"


def load_installer():
    spec = importlib.util.spec_from_file_location(
        "install_outbound_worker_runtime", INSTALLER
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load_stager():
    spec = importlib.util.spec_from_file_location(
        "stage_wsl_jit_live_contract_for_runtime", STAGER
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class OutboundWorkerRuntimeInstallerTests(unittest.TestCase):
    def test_broker_cleanup_timeout_is_distinct_from_http_timeout(self):
        source = (ROOT / "scripts/host/outbound-coordinator-worker.py").read_text()
        self.assertIn('max(1200, c["request_timeout_seconds"])', source)

    def config(self) -> dict:
        return {
            "schema_version": 1,
            "mode": "ci-jit-pilot",
            "authority_kind": "personal-repository",
            "runner_group": None,
            "app_id": 123,
            "app_slug": "self-hosted-ci-worker",
            "installation_id": 456,
            "repository": "OWNER/REPO",
            "repository_id": 789,
            "repository_selection": "selected",
            "default_branch": "main",
            "workflow_id": "ci-jit-pilot-child.yml",
            "workflow_path": ".github/workflows/ci-jit-pilot-child.yml",
            "permissions": {
                "metadata": "read",
                "pull_requests": "read",
                "actions": "write",
                "administration": "read",
            },
            "github_app_private_key_file": "/etc/self-hosted-ci/secrets/github-app.pem",
            "authority_helper_file": "/usr/local/libexec/self-hosted-ci/authority-v1-approval-helper",
            "authority_manifest_file": "/etc/self-hosted-ci/authority-v1/key-manifest.json",
            "authority_signer_key_file": "/etc/self-hosted-ci/secrets/authority-v1-ed25519.pem",
            "allocation_signer_key_file": "/etc/self-hosted-ci/secrets/allocation-ed25519.pem",
            "image_fingerprint": "f" * 64,
            "gatestore_file": "/var/lib/self-hosted-ci/outbound-worker/gatestore.sqlite3",
            "approval_store_file": "/var/lib/self-hosted-ci/outbound-worker/approvals.sqlite3",
            "worker_state_file": "/var/lib/self-hosted-ci/outbound-worker/worker.sqlite3",
            "broker_executable": "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py",
            "approval_ttl_seconds": 240,
            "poll_seconds": 15,
            "request_timeout_seconds": 30,
        }

    def stage_runtime(self, root: Path) -> None:
        stager = load_stager()
        for relative, target, mode, _kind, _component in stager.PUBLIC_ARTIFACTS:
            if not target.startswith(
                "/usr/local/lib/self-hosted-ci/github_automation/"
            ):
                continue
            destination = root / target.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
            os.chmod(destination, int(mode, 8))
        broker = root / "usr/local/lib/self-hosted-ci/garm-allocation-broker.py"
        broker.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/host/garm-allocation-broker.py", broker)
        os.chmod(broker, 0o755)

    def sources(self, root: Path) -> tuple[Path, Path, Path]:
        config = root / "config.json"
        github_key = root / "github.pem"
        allocation_key = root / "allocation.pem"
        config.write_text(json.dumps(self.config()), encoding="utf-8")
        github_key.write_bytes(
            private_pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        )
        allocation_key.write_bytes(private_pem(ed25519.Ed25519PrivateKey.generate()))
        for path in (config, github_key, allocation_key):
            os.chmod(path, 0o600)
        return config, github_key, allocation_key

    def test_default_is_inert_plan_and_apply_is_ack_guarded(self) -> None:
        plan = subprocess.run([str(INSTALLER)], text=True, capture_output=True)
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertEqual(False, json.loads(plan.stdout)["apply_requested"])
        apply = subprocess.run(
            [str(INSTALLER), "--apply"], text=True, capture_output=True
        )
        self.assertNotEqual(0, apply.returncode)
        self.assertIn(
            "--apply must run as root"
            if os.geteuid()
            else "both explicit acknowledgements",
            apply.stderr,
        )

    def test_exact_config_rejects_unknown_fields_and_unsafe_paths(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            for mutation in (
                "unknown",
                "secret-path",
                "database-crossing",
                "full-mode",
            ):
                value = self.config()
                if mutation == "unknown":
                    value["extra"] = True
                elif mutation == "secret-path":
                    value["github_app_private_key_file"] = "/tmp/key.pem"
                elif mutation == "database-crossing":
                    value["worker_state_file"] = value["approval_store_file"]
                else:
                    value["mode"] = "ci-gate-full"
                path.write_text(json.dumps(value), encoding="utf-8")
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(installer.InstallError),
                ):
                    installer.load_config(path)

    def test_apply_is_idempotent_and_creates_sentinel_only_after_local_smoke(
        self,
    ) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage_runtime(root)
            config, github_key, allocation_key = self.sources(root)
            for _ in range(2):
                result = installer.install_runtime(
                    config,
                    github_key,
                    allocation_key,
                    prefix=root,
                    expected_uid=os.getuid(),
                )
                self.assertTrue(result["runtime_ready"])
                self.assertFalse(result["external_calls"])
                self.assertFalse(result["dispatch"])
                verified = installer.verify_runtime(
                    prefix=root, expected_uid=os.getuid()
                )
                self.assertEqual("verified", verified["status"])
            sentinel = root / "etc/self-hosted-ci/outbound-worker.runtime-ready"
            self.assertEqual(0o600, os.stat(sentinel).st_mode & 0o777)
            self.assertEqual(
                0o751,
                os.stat(root / "etc/self-hosted-ci").st_mode & 0o777,
            )

    def test_failed_apply_removes_existing_readiness(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ready = root / "etc/self-hosted-ci/outbound-worker.runtime-ready"
            ready.parent.mkdir(parents=True)
            ready.write_text("stale", encoding="utf-8")
            config, github_key, allocation_key = self.sources(root)
            allocation_key.write_bytes(
                private_pem(
                    rsa.generate_private_key(public_exponent=65537, key_size=2048)
                )
            )
            with self.assertRaises(installer.InstallError):
                installer.install_runtime(
                    config,
                    github_key,
                    allocation_key,
                    prefix=root,
                    expected_uid=os.getuid(),
                )
            self.assertFalse(ready.exists())

    def test_staged_package_has_isolated_import_closure(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage_runtime(root)
            installer._isolated_import_smoke(root)
        provision = (ROOT / "scripts/host/provision-wsl-jit-contract.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("check_delivery.py", provision)
        self.assertIn("install-outbound-worker-runtime.py", provision)
        unit = (
            ROOT / "packaging/systemd/self-hosted-ci-outbound-worker.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ConditionPathExists=/etc/self-hosted-ci/outbound-worker.runtime-ready",
            unit,
        )
        self.assertIn(
            "ExecCondition=/usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py --verify",
            unit,
        )


if __name__ == "__main__":
    unittest.main()
