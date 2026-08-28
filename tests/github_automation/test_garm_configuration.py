from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/configure-garm-jit.sh"
PROVIDER = ROOT / "templates/garm/garm-provider-incus.toml"
PROVISION = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
LIBRARY = ROOT / "scripts/host/garm-jit-transaction-lib.sh"


class GarmConfigurationTests(unittest.TestCase):
    def test_plan_is_machine_readable_and_inert(self) -> None:
        result = subprocess.run(
            ["bash", str(INSTALLER), "--plan"], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual("plan", value["mode"])
        self.assertFalse(value["host_changes"])
        self.assertEqual("not_performed", value["external_calls"])
        self.assertFalse(value["garm_enabled"])
        self.assertEqual("not_performed", value["runner_registration"])

    def test_apply_is_explicit_secret_safe_and_rollback_capable(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "--jwt-secret-file",
            "--database-passphrase-file",
            "--garm-admin-username-file",
            "--garm-admin-password-file",
            "--runner-manager-app-config-file",
            "--dispatcher-app-config-file",
            "--live-job-verifier-app-config-file",
            "--garm-cli-home",
            "/run/self-hosted-ci/garm-cli",
            "--acknowledge-root-secret-installation",
            "--acknowledge-garm-database-mutation",
            "--acknowledge-external-github-configuration",
            "require_root_secret",
            "TOML-safe characters",
            "transaction_succeeded",
            "configure-rollback",
            'urllib.request.Request("http://127.0.0.1:9997/first-run"',
            "github credentials update",
            "github credentials add",
            "repo update",
            "repo add",
            "--private-key-path",
            "--random-webhook-secret",
            "derived_entity_id",
            'cp -a "${transaction_dir}/garm.db"',
        ):
            self.assertIn(token, source)
        self.assertNotIn('--jwt-secret "', source)
        self.assertNotIn('--database-passphrase "', source)
        self.assertIn('cp -a "${transaction_dir}/config.toml"', source)
        self.assertIn('cp -a "${transaction_dir}/health-state.json"', source)
        self.assertIn('"${SESSION_HELPER}" run -- --format json', source)
        self.assertNotIn("/usr/local/bin/garm-cli --password", source)
        self.assertNotIn("--password-file", source)
        self.assertNotIn("--install-webhook", source)
        self.assertIn("GitHub App identities and private keys must be pairwise distinct", source)
        self.assertIn("GitHub App public-key fingerprints must be pairwise distinct", source)
        self.assertIn('require_root_secret "${dispatcher_private_key}"', source)
        self.assertIn("SubjectPublicKeyInfo", source)
        self.assertIn('{"metadata":"read","actions":"read","administration":"write"}', source)
        self.assertIn(
            '{"metadata":"read","pull_requests":"read","actions":"write"}',
            source,
        )
        self.assertIn('("live-job-read",{"metadata":"read","actions":"read"})', source)
        dispatcher = json.loads(
            (ROOT / "templates/garm/dispatcher-app.json.example").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("workflow-dispatch", dispatcher["purpose"])
        self.assertEqual(
            {"metadata": "read", "pull_requests": "read", "actions": "write"},
            dispatcher["permissions"],
        )
        self.assertEqual("main", dispatcher["default_branch"])
        self.assertEqual("ci-jit-canary-child.yml", dispatcher["workflow_id"])
        self.assertEqual(
            ".github/workflows/ci-jit-canary-child.yml",
            dispatcher["workflow_path"],
        )
        self.assertLess(source.index("github credentials add"), source.index('scaleset list'))
        self.assertLess(source.index("repo add"), source.index('scaleset list'))

    def test_provider_and_runner_network_contract_are_exact(self) -> None:
        provider = PROVIDER.read_text(encoding="utf-8")
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[image_remotes.images]",
            'addr = "https://images.linuxcontainers.org"',
            "skip_verify = false",
        ):
            self.assertIn(token, provider)
        for token in (
            "http://10.254.0.1:8080/api/v1/callbacks",
            "http://10.254.0.1:8080/api/v1/metadata",
        ):
            self.assertIn(token, source)

    def test_duplicate_public_key_bytes_are_rejected_across_distinct_paths(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        marker = 'import hashlib, pathlib, sys\nfrom cryptography.hazmat.primitives import serialization'
        body = marker + source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
            paths = [root / f"app-{index}.pem" for index in range(3)]
            for path in paths:
                path.write_bytes(encoded)
            duplicate = subprocess.run([sys.executable, "-c", body, *map(str, paths)], text=True, capture_output=True)
            self.assertNotEqual(0, duplicate.returncode)
            self.assertIn("fingerprints must be pairwise distinct", duplicate.stderr)
            for path in paths:
                unique = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                path.write_bytes(unique.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            accepted = subprocess.run([sys.executable, "-c", body, *map(str, paths)], text=True, capture_output=True)
            self.assertEqual(0, accepted.returncode, accepted.stderr)

    def test_live_evidence_configures_broker_with_zero_scale_sets(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "garm_cli provider list",
            "garm_cli controller show",
            "garm_cli scaleset list",
            "configuration requires zero scale sets",
            '"schema_version":3',
            '"broker_configured":True',
            '"zero_scale_sets":True',
            "--repository-id",
            "--allocation-authority-public-key",
            "--live-job-verifier",
            "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py",
            '"health_state_derived_from_live_api":true',
            "os.fsync(out.fileno())",
            "os.replace(tmp,path)",
            "os.fsync(dfd)",
        ):
            self.assertIn(token, source)
        for forbidden in (
            "scaleset add",
            "scaleset update",
            "--max-runners",
            "--min-idle-runners",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"targets":{repository_id:target}', source)
        self.assertIn('"garm_cli_home":cli_home', source)
        self.assertIn('"garm_enabled":false', source)
        self.assertIn("configure-garm-jit.sh", PROVISION.read_text(encoding="utf-8"))

    def test_script_parses(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
