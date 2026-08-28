from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/collect-wsl-jit-semantic-observations.py"
SHELL = ROOT / "scripts/host/collect-wsl-jit-semantic-observations.sh"


def load_module():
    spec = importlib.util.spec_from_file_location("wsl_semantic_observations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SemanticObservationCollectorTests(unittest.TestCase):
    def test_scripts_are_syntactically_valid_and_have_no_override(self):
        compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec")
        shell = subprocess.run(
            ["bash", "-n", str(SHELL)], text=True, capture_output=True, check=False
        )
        self.assertEqual(shell.returncode, 0, shell.stderr)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('add_argument("--pass"', source)
        rejected = subprocess.run(
            [sys.executable, str(SCRIPT), "--pass"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")

    def test_command_failure_is_sanitized_and_fails_closed(self):
        module = load_module()

        def run(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                [], 1, stdout="secret-output", stderr="token=secret"
            )

        collector = module.Collector(run=run, environ={})
        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/fake"):
            self.assertIsNone(collector.command("probe", ["fake"]))
        serialized = json.dumps(collector.errors)
        self.assertEqual(
            collector.errors, [{"probe": "probe", "reason": "command-failed"}]
        )
        self.assertNotIn("secret", serialized)

    def test_collection_is_observational_and_never_emits_pass(self):
        module = load_module()
        collector = module.Collector(
            environ={"WSL_DISTRO_NAME": module.EXPECTED_DISTRO, "PATH": "/usr/bin"}
        )
        with (
            mock.patch.object(collector, "wsl_boundary", return_value={}),
            mock.patch.object(collector, "mounts_and_interop", return_value={}),
            mock.patch.object(collector, "credential_surfaces", return_value={}),
            mock.patch.object(collector, "identities", return_value={}),
            mock.patch.object(collector, "packages_and_binaries", return_value={}),
            mock.patch.object(collector, "incus", return_value={}),
            mock.patch.object(collector, "network", return_value={}),
            mock.patch.object(collector, "garm", return_value={}),
        ):
            result = collector.collect()
        self.assertEqual(result["collection_status"], "complete")
        self.assertNotIn('"pass"', json.dumps(result).lower())
        collector.errors.append({"probe": "x", "reason": "unavailable"})
        with (
            mock.patch.object(collector, "wsl_boundary", return_value={}),
            mock.patch.object(collector, "mounts_and_interop", return_value={}),
            mock.patch.object(collector, "credential_surfaces", return_value={}),
            mock.patch.object(collector, "identities", return_value={}),
            mock.patch.object(collector, "packages_and_binaries", return_value={}),
            mock.patch.object(collector, "incus", return_value={}),
            mock.patch.object(collector, "network", return_value={}),
            mock.patch.object(collector, "garm", return_value={}),
        ):
            result = collector.collect()
        self.assertEqual(result["collection_status"], "incomplete")

    def test_incus_output_is_reduced_to_non_secret_semantics(self):
        module = load_module()
        payloads = {
            "/1.0/projects/ci-jit": {
                "config": {"restricted": "true"},
                "secret": "drop",
            },
            "/1.0/profiles/ci-jit?project=ci-jit": {
                "config": {},
                "devices": {"root": {"pool": "ci-jit-dedicated"}},
            },
            "/1.0/storage-pools/ci-jit-dedicated": {
                "driver": "dir",
                "config": {
                    "source": "/var/lib/self-hosted-ci/incus-storage/ci-jit/pool"
                },
            },
            "/1.0/networks/ci-jit-isolated": {
                "type": "bridge",
                "config": {
                    "ipv4.nat": "false",
                    "raw.dnsmasq": "server=/private.example/10.0.0.9",
                    "ipv4.routes": "10.0.0.0/8",
                },
            },
        }
        collector = module.Collector(environ={})

        def json_command(_probe, argv):
            if argv[1] == "query":
                return payloads[argv[2]]
            return [{"name": "ephemeral-one", "expanded_config": {"secret": "drop"}}]

        with mock.patch.object(collector, "json_command", side_effect=json_command):
            result = collector.incus()
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("ephemeral-one", serialized)
        self.assertNotIn("private.example", serialized)
        self.assertNotIn("10.0.0.0/8", serialized)
        self.assertIs(
            result["bridge"]["config"]["raw.dnsmasq.present"], True
        )
        self.assertIs(
            result["bridge"]["config"]["ipv4.routes.present"], True
        )
        self.assertEqual(result["instances"]["count"], 1)

    def test_garm_empty_process_inventory_is_not_an_error(self):
        module = load_module()
        collector = module.Collector(environ={})

        def command(probe, _argv, **_kwargs):
            if probe == "garm-processes":
                return ""
            return "inactive\n" if probe.endswith(":active") else "disabled\n"

        with (
            mock.patch.object(collector, "command", side_effect=command),
            mock.patch.object(
                collector,
                "credential_surfaces",
                return_value={"persistent_actions_runner": False},
            ),
            mock.patch.object(module.Path, "lstat", side_effect=OSError),
        ):
            result = collector.garm()
        self.assertEqual(result["process_count"], 0)
        self.assertFalse(
            any(error["probe"] == "garm-processes" for error in collector.errors)
        )

    def test_disabled_or_absent_systemd_service_is_observed_without_probe_error(self):
        module = load_module()

        def run(argv, **_kwargs):
            if "is-active" in argv:
                return subprocess.CompletedProcess(argv, 3, stdout="inactive\n", stderr="")
            return subprocess.CompletedProcess(argv, 4, stdout="\n", stderr="")

        collector = module.Collector(run=run, environ={})
        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/systemctl"):
            state = collector.service_state("missing.service")
        self.assertEqual(state, {"active": "inactive", "enabled": "not-found"})
        self.assertEqual(collector.errors, [])

    def test_recursive_nested_ssh_credentials_are_detected_without_path_output(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "deep" / "profile" / ".ssh"
            nested.mkdir(parents=True)
            secret = nested / "id_ed25519"
            secret.write_text("do-not-emit")
            self.assertTrue(module.recursive_credential_candidates((root,)))
            result = {"recursive_credential_candidates": True}
            serialized = json.dumps(result)
            self.assertNotIn(str(secret), serialized)
            self.assertNotIn("do-not-emit", serialized)

    def test_recursive_scan_fails_closed_when_bounded_inventory_is_exceeded(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").mkdir()
            self.assertIsNone(
                module.recursive_credential_candidates((root,), maximum_entries=0)
            )

    def test_recursive_scan_flags_innocently_named_symlinks(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_dir = root / "target-dir"
            target_dir.mkdir()
            (root / "provider-current").symlink_to(target_dir, target_is_directory=True)
            self.assertTrue(module.recursive_credential_candidates((root,)))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_file = root / "target-file"
            target_file.write_text("secret", encoding="utf-8")
            (root / "current").symlink_to(target_file)
            self.assertTrue(module.recursive_credential_candidates((root,)))

    def test_credential_surfaces_recursively_scan_configured_garm_home(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            garm_home = Path(temporary)
            nested_secret = garm_home / "providers" / "github" / "private.key"
            nested_secret.parent.mkdir(parents=True)
            nested_secret.write_text("do-not-emit", encoding="utf-8")
            collector = module.Collector(environ={})

            with mock.patch.object(
                module.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_dir=str(garm_home)),
            ), mock.patch.object(
                module,
                "credential_scan_roots",
                return_value=(garm_home,),
            ):
                result = collector.credential_surfaces()

            self.assertTrue(result["recursive_credential_candidates"])
            serialized = json.dumps(result)
            self.assertNotIn(str(nested_secret), serialized)
            self.assertNotIn("do-not-emit", serialized)
            self.assertIn(Path("/var/lib/garm"), module.credential_scan_roots())


if __name__ == "__main__":
    unittest.main()
