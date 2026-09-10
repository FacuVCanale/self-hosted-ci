"""Guards for the host CLI itself, not just the modules it imports.

Both regressions these tests cover shipped green: the pure modules were tested,
and the host script was only asserted against as text. A test that never calls
`runtime` or `root_config` cannot notice that the CLI stopped starting.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER_CLI = ROOT / "scripts/host/outbound-coordinator-worker.py"
INSTALLER = ROOT / "scripts/host/install-outbound-worker-runtime.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def base_config() -> dict:
    return {
        "schema_version": 1,
        "mode": "ci-jit-pilot",
        "authority_kind": "organization-runner-group",
        "runner_group": "overworld-ci-jit",
        "app_id": 4834963,
        "app_slug": "facu-ci-dispatcher-alethia",
        "installation_id": 159149826,
        "repository": "alethia-earth/Overworld",
        "repository_id": 1172953958,
        "repository_selection": "selected",
        "default_branch": "master",
        "workflow_id": "ci-jit-pilot-child.yml",
        "workflow_path": ".github/workflows/ci-jit-pilot-child.yml",
        "permissions": {
            "metadata": "read", "contents": "read", "pull_requests": "read",
            "actions": "write", "administration": "read",
        },
        "github_app_private_key_file": "/etc/self-hosted-ci/secrets/dispatcher.pem",
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


GATE = {
    "app_id": 4729014, "app_slug": "facu-ci-gate", "installation_id": 156799177,
    "private_key_file": "/etc/self-hosted-ci/secrets/gate-github-app.pem",
}
AUTO = {"enabled": True, "poll_seconds": 60}


class RuntimeArityTests(unittest.TestCase):
    """`runtime()` and the caller that unpacks it must not drift apart."""

    def setUp(self):
        self.tree = ast.parse(WORKER_CLI.read_text(encoding="utf-8"))

    def _runtime_return_arities(self) -> set[int]:
        arities = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "runtime":
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Return) and isinstance(inner.value, ast.Tuple):
                        arities.add(len(inner.value.elts))
        return arities

    def _unpack_arities(self) -> set[int]:
        arities = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            call = node.value.func
            if not (isinstance(call, ast.Name) and call.id == "runtime"):
                continue
            for target in node.targets:
                if isinstance(target, ast.Tuple):
                    arities.add(len(target.elts))
        return arities

    def test_every_runtime_return_matches_every_unpack(self):
        returns, unpacks = self._runtime_return_arities(), self._unpack_arities()
        self.assertTrue(returns, "runtime() must return a tuple")
        self.assertTrue(unpacks, "main() must unpack runtime()")
        self.assertEqual(
            returns, unpacks,
            f"runtime() returns {sorted(returns)} values but callers unpack {sorted(unpacks)}",
        )

    def test_runtime_returns_a_single_consistent_shape(self):
        self.assertEqual(len(self._runtime_return_arities()), 1)


class HostConfigValidationTests(unittest.TestCase):
    """The CLI's own config validator, exercised rather than grepped."""

    def setUp(self):
        self.cli = load(WORKER_CLI, "outbound_coordinator_worker_under_test")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def write(self, value) -> Path:
        path = Path(self.temporary.name) / "outbound-worker.json"
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return path

    def config(self, value):
        path = self.write(value)
        info = os.lstat(path)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            # root_config demands root ownership; call the pure validation body
            # through the same entry point by relaxing only the ownership probe.
            original = os.lstat

            def relaxed(target):
                result = original(target)

                class Faked:
                    st_mode = result.st_mode
                    st_uid = 0
                    st_nlink = result.st_nlink
                    st_size = result.st_size

                return Faked()

            os.lstat = relaxed
            try:
                return self.cli.root_config(path)
            finally:
                os.lstat = original
        return self.cli.root_config(path)

    def test_a_config_with_neither_optional_block_is_accepted(self):
        value = self.config(base_config())
        self.assertIsNone(value.get("gate"))
        self.assertIsNone(value.get("auto_dispatch"))

    def test_gate_alone_is_accepted(self):
        self.assertEqual(self.config({**base_config(), "gate": GATE})["gate"], GATE)

    def test_auto_dispatch_alone_is_accepted(self):
        self.assertEqual(
            self.config({**base_config(), "auto_dispatch": AUTO})["auto_dispatch"], AUTO
        )

    def test_both_optional_blocks_together_are_accepted(self):
        value = self.config({**base_config(), "gate": GATE, "auto_dispatch": AUTO})
        self.assertEqual((value["gate"], value["auto_dispatch"]), (GATE, AUTO))

    def test_an_unbounded_or_malformed_interval_is_refused(self):
        for auto in (
            {"enabled": True, "poll_seconds": 1},
            {"enabled": True, "poll_seconds": 100000},
            {"enabled": "yes", "poll_seconds": 60},
            {"enabled": True},
            {"enabled": True, "poll_seconds": 60, "extra": 1},
        ):
            with self.subTest(auto=auto), self.assertRaises(Exception):
                self.config({**base_config(), "auto_dispatch": auto})

    def test_an_unknown_top_level_field_is_still_refused(self):
        with self.assertRaises(Exception):
            self.config({**base_config(), "surprise": 1})


class InstallerOptionalBlockTests(unittest.TestCase):
    """The installer must accept exactly the blocks the CLI accepts."""

    def setUp(self):
        self.installer = load(INSTALLER, "install_outbound_worker_runtime_under_test")
        self.cli = load(WORKER_CLI, "outbound_coordinator_worker_for_parity")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def load_config(self, value):
        path = Path(self.temporary.name) / "outbound-worker.json"
        path.write_text(json.dumps(value))
        return self.installer.load_config(path)

    def test_installer_accepts_auto_dispatch(self):
        value = self.load_config({**base_config(), "auto_dispatch": AUTO})
        self.assertEqual(value["auto_dispatch"], AUTO)

    def test_installer_accepts_both_blocks(self):
        value = self.load_config({**base_config(), "gate": GATE, "auto_dispatch": AUTO})
        self.assertEqual((value["gate"], value["auto_dispatch"]), (GATE, AUTO))

    def test_installer_refuses_an_unbounded_interval(self):
        for auto in (
            {"enabled": True, "poll_seconds": 1},
            {"enabled": True, "poll_seconds": 100000},
            {"enabled": True},
        ):
            with self.subTest(auto=auto), self.assertRaises(self.installer.InstallError):
                self.load_config({**base_config(), "auto_dispatch": auto})

    def test_the_two_validators_allow_the_same_optional_blocks(self):
        # The regression that broke the host was exactly this drift: the CLI
        # learned a block the installer still rejected.
        source = WORKER_CLI.read_text(encoding="utf-8")
        for name in sorted(self.installer.OPTIONAL_FIELDS):
            self.assertIn(f'"{name}"', source)
        self.assertEqual(self.installer.OPTIONAL_FIELDS, {"gate", "auto_dispatch"})


if __name__ == "__main__":
    unittest.main()
