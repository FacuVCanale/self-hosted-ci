from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
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
    def test_garm_identity_can_traverse_the_protected_configuration_root(self):
        provisioner = (ROOT / "scripts/host/provision-wsl-jit-contract.sh").read_text()
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertIn(
            'install -d -o root -g garm-manager -m 0751 "${TARGET_ROOT}"',
            provisioner,
        )
        self.assertIn(
            'install -d -o root -g garm-manager -m 0750 "${TARGET_ROOT}/garm"',
            provisioner,
        )
        self.assertIn(
            "install -d -o root -g garm-manager -m 0751 /etc/self-hosted-ci",
            configurator,
        )
        self.assertIn(
            "install -d -o root -g garm-manager -m 0750 /etc/self-hosted-ci/garm",
            configurator,
        )
        self.assertIn(
            "install -d -o root -g garm-manager -m 0710 /var/lib/self-hosted-ci",
            configurator,
        )
        self.assertIn(
            'install -d -o root -g garm-manager -m 0710 "${STATE_ROOT}"',
            provisioner,
        )
        self.assertIn(
            'install -d -o garm-manager -g garm-manager -m 0700 "${STATE_ROOT}/garm"',
            provisioner,
        )

    def test_first_run_uses_the_versioned_garm_api_base_path(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertIn("http://127.0.0.1:9997/api/v1/first-run", configurator)
        self.assertNotIn('http://127.0.0.1:9997/first-run"', configurator)

    def test_transactions_wait_for_the_garm_loopback_api(self):
        library = LIBRARY.read_text()
        activate = (ROOT / "scripts/host/activate-garm-jit.sh").read_text()
        deactivate = (ROOT / "scripts/host/deactivate-garm-jit.sh").read_text()
        self.assertIn("wait_for_garm_cli()", library)
        self.assertIn('wait_for_garm_cli||die "GARM loopback API did not become ready"', activate)
        self.assertIn('wait_for_garm_cli||die "GARM recovery API did not become ready"', deactivate)

    def test_controller_urls_are_initialized_before_controller_info_is_read(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        update = configurator.index(
            'garm_cli controller update --callback-url "${CALLBACK_URL}" --metadata-url "${METADATA_URL}"'
        )
        show = configurator.index("if garm_cli controller show")
        self.assertLess(update, show)

    def test_transaction_rolls_back_primary_and_blob_databases(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertIn(
            "readonly GARM_BLOB_DATABASE=/var/lib/self-hosted-ci/garm/blob-garm.db",
            configurator,
        )
        self.assertIn(
            'restore_or_remove "${had_blob_database}" "${transaction_dir}/blob-garm.db" "${GARM_BLOB_DATABASE}"',
            configurator,
        )
        self.assertIn(
            '"${GARM_BLOB_DATABASE}-wal" "${GARM_BLOB_DATABASE}-shm"',
            configurator,
        )

    @staticmethod
    def _embedded_two_path_python(function_name: str) -> str:
        source = INSTALLER.read_text(encoding="utf-8")
        marker = f'{function_name}() {{\n  python3 - "$1" "$2" <<\'PY\'\n'
        return source.split(marker, 1)[1].split("\nPY\n}", 1)[0]

    def test_both_sqlite_snapshots_include_committed_wal_pages(self) -> None:
        body = self._embedded_two_path_python("snapshot_sqlite_database")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for database_name in ("garm.db", "blob-garm.db"):
                with self.subTest(database=database_name):
                    source = root / database_name
                    snapshot = root / f"{database_name}.snapshot"
                    connection = sqlite3.connect(source)
                    try:
                        self.assertEqual(
                            "wal",
                            connection.execute("PRAGMA journal_mode=WAL").fetchone()[0],
                        )
                        connection.execute("PRAGMA wal_autocheckpoint=0")
                        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
                        connection.commit()
                        connection.execute(
                            "INSERT INTO evidence VALUES ('committed-in-wal')"
                        )
                        connection.commit()
                        self.assertTrue(Path(f"{source}-wal").exists())
                        result = subprocess.run(
                            [sys.executable, "-c", body, str(source), str(snapshot)],
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                        self.assertEqual(0, result.returncode, result.stderr)
                    finally:
                        connection.close()
                    with sqlite3.connect(snapshot) as restored:
                        self.assertEqual(
                            [("committed-in-wal",)],
                            restored.execute("SELECT value FROM evidence").fetchall(),
                        )

    def test_durable_copy_atomically_restores_content_and_metadata(self) -> None:
        body = self._embedded_two_path_python("copy_file_durably")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "snapshot"
            destination = root / "live"
            source.write_bytes(b"known-good\n")
            source.chmod(0o640)
            destination.write_bytes(b"drifted\n")
            result = subprocess.run(
                [sys.executable, "-c", body, str(source), str(destination)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(0o640, os.stat(destination).st_mode & 0o777)
            self.assertEqual(os.stat(source).st_uid, os.stat(destination).st_uid)
            self.assertFalse(destination.is_symlink())

    def test_durable_copy_syncs_after_content_and_metadata_changes(self) -> None:
        body = self._embedded_two_path_python("copy_file_durably")
        final_write = body.index("outgoing.write(block)")
        chmod = body.index("os.fchmod(outgoing.fileno()")
        chown = body.index("os.fchown(outgoing.fileno()")
        file_sync = body.index("os.fsync(outgoing.fileno())")
        replace = body.index("os.replace(temporary, destination)")
        directory_sync = body.index("os.fsync(directory_fd)")
        self.assertLess(final_write, file_sync)
        self.assertLess(chmod, file_sync)
        self.assertLess(chown, file_sync)
        self.assertLess(file_sync, replace)
        self.assertLess(replace, directory_sync)

    def test_admin_username_matches_upstream_alphanumeric_contract(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertIn('re.fullmatch(r"[A-Za-z0-9]{1,64}", value)', configurator)

    def test_empty_garm_inventories_accept_upstream_null_encoding(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertGreaterEqual(configurator.count("if inventory is None: inventory=[]"), 2)
        self.assertIn("if scale_sets is None: scale_sets=[]", configurator)
        self.assertIn("if instances is None: instances=[]", configurator)

    def test_canary_inputs_are_written_root_only(self):
        configurator = (ROOT / "scripts/host/configure-garm-jit.sh").read_text()
        self.assertIn(
            "for path,value,mode in ((outbound_path,outbound,0o600),(broker_path,broker,0o600),(health_path,state,0o600)):",
            configurator,
        )

    def test_runtime_image_rotation_is_locked_cas_guarded_and_rollback_capable(self):
        source = INSTALLER.read_text(encoding="utf-8")
        lock = source.index("acquire_transaction_lock")
        service_inventory = source.index('systemctl is-enabled "${unit}"')
        runtime_inventory = source.index("zero_runtime_state")
        first_mutation = source.index("install -d -o root -g garm-manager")
        self.assertLess(lock, service_inventory)
        self.assertLess(lock, runtime_inventory)
        self.assertLess(runtime_inventory, first_mutation)
        for token in (
            'source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/garm-jit-transaction-lib.sh"',
            "--expected-previous-image-fingerprint",
            'observed not in {previous,new}',
            '"${OUTBOUND_RUNTIME_INSTALLER}" --verify',
            'value.get("repository")!=repository',
            'value.get("default_branch")!=branch',
            'value.get("authority_kind")!=authority',
            'value.get("runner_group")!=expected_group',
            'copy_file_durably "${OUTBOUND_CONFIG}" "${transaction_dir}/outbound-worker.json"',
            'restore_or_remove "${had_outbound_config}" "${transaction_dir}/outbound-worker.json" "${OUTBOUND_CONFIG}"',
            'outbound["image_fingerprint"]=fingerprint',
            'outbound.get("image_fingerprint") not in {previous_fingerprint,fingerprint}',
            "require_health_configuration",
            '"runtime_image_contract_consistent":true',
        ):
            self.assertIn(token, source)
        self.assertGreaterEqual(
            source.count('"${OUTBOUND_RUNTIME_INSTALLER}" --verify'), 2
        )
        write = source.index(
            "for path,value,mode in ((outbound_path,outbound,0o600),(broker_path,broker,0o600),(health_path,state,0o600)):"
        )
        verify_after = source.index(
            '"${OUTBOUND_RUNTIME_INSTALLER}" --verify', write
        )
        cross_check = source.index("require_health_configuration", verify_after)
        success = source.index("transaction_succeeded=true")
        self.assertLess(write, verify_after)
        self.assertLess(verify_after, cross_check)
        self.assertLess(cross_check, success)
        final_cas = source.index(
            'outbound.get("image_fingerprint") not in {previous_fingerprint,fingerprint}'
        )
        final_write = source.index('outbound["image_fingerprint"]=fingerprint', final_cas)
        self.assertLess(source.index("acquire_transaction_lock"), final_cas)
        self.assertLess(final_cas, final_write)

    def test_outbound_image_compare_and_swap_accepts_new_idempotently(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        marker = (
            'python3 - "${OUTBOUND_CONFIG}" "${repository}" "${repository_id}" '
            '"${default_branch}" "${authority_kind}" "${runner_group}" '
            '"${expected_previous_image_fingerprint}" "${image_fingerprint}" <<\'PY\'\n'
        )
        body = source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        previous = "a" * 64
        new = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "outbound.json"
            value = {
                "repository": "owner/repo",
                "repository_id": 42,
                "default_branch": "main",
                "authority_kind": "organization-runner-group",
                "runner_group": "ci",
                "image_fingerprint": previous,
            }
            config.write_text(json.dumps(value), encoding="utf-8")
            args = [
                sys.executable,
                "-c",
                body,
                str(config),
                "owner/repo",
                "42",
                "main",
                "organization-runner-group",
                "ci",
                previous,
                new,
            ]
            self.assertEqual(
                0, subprocess.run(args, check=False, capture_output=True).returncode
            )
            value["image_fingerprint"] = new
            config.write_text(json.dumps(value), encoding="utf-8")
            args[-2] = "c" * 64
            self.assertEqual(
                0, subprocess.run(args, check=False, capture_output=True).returncode
            )
            value["image_fingerprint"] = "d" * 64
            config.write_text(json.dumps(value), encoding="utf-8")
            self.assertNotEqual(
                0, subprocess.run(args, check=False, capture_output=True).returncode
            )

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
            'urllib.request.Request("http://127.0.0.1:9997/api/v1/first-run"',
            "github credentials update",
            "github credentials add",
            "repo update",
            "repo add",
            "--private-key-path",
            "--random-webhook-secret",
            "derived_entity_id",
            'snapshot_sqlite_database "${GARM_DATABASE}" "${transaction_dir}/garm.db"',
            'snapshot_sqlite_database "${GARM_BLOB_DATABASE}" "${transaction_dir}/blob-garm.db"',
        ):
            self.assertIn(token, source)
        self.assertNotIn('--jwt-secret "', source)
        self.assertNotIn('--database-passphrase "', source)
        self.assertIn('restore_or_remove "${had_config}" "${transaction_dir}/config.toml"', source)
        self.assertIn('restore_or_remove "${had_health}" "${transaction_dir}/health-state.json"', source)
        self.assertIn('"${SESSION_HELPER}" run -- --format json', source)
        self.assertNotIn("/usr/local/bin/garm-cli --password", source)
        self.assertNotIn("--password-file", source)
        self.assertNotIn("--install-webhook", source)
        self.assertIn("GitHub App identities and private keys must be pairwise distinct", source)
        self.assertIn("GitHub App public-key fingerprints must be pairwise distinct", source)
        self.assertIn('require_root_secret "${dispatcher_private_key}"', source)
        self.assertIn('GITHUB_CREDENTIAL_NAME="self-hosted-ci-runner-manager-${repository_id}"', source)
        self.assertNotIn('GITHUB_CREDENTIAL_NAME="self-hosted-ci-sandbox-app"', source)
        self.assertIn("SubjectPublicKeyInfo", source)
        self.assertIn('{"metadata":"read","actions":"read","administration":"write"}', source)
        self.assertIn('{"metadata":"read","organization_self_hosted_runners":"write"}', source)
        self.assertIn(
            '{"metadata":"read","contents":"read","pull_requests":"read","actions":"write","administration":"read"}',
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
            {
                "metadata": "read",
                "contents": "read",
                "pull_requests": "read",
                "actions": "write",
                "administration": "read",
            },
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

    def test_bootstrap_supports_exact_organization_runner_group_authority(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "--authority-kind personal-repository|organization-runner-group",
            "--repository OWNER/REPO",
            "--default-branch BRANCH",
            "organization authority requires the repository owner as its exact organization entity",
            "organization authority requires an exact selected runner group",
            'entity_flag=--org',
            'garm_cli org list --name "${entity_name}" --endpoint github.com',
            'garm_cli org update "${derived_entity_id}"',
            'garm_cli org add --name "${entity_name}"',
            'garm_cli org show "${derived_entity_id}" --endpoint github.com',
            'created_entity_kind=org',
            'garm_cli "${created_entity_kind}" delete "${created_entity_id}" --keep-webhook',
        ):
            self.assertIn(token, source)
        self.assertIn('garm_cli scaleset list "${entity_flag}" "${entity_id}"', source)
        organization_template = json.loads(
            (ROOT / "templates/garm/runner-manager-org-app.json.example").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {"metadata": "read", "organization_self_hosted_runners": "write"},
            organization_template["permissions"],
        )
        self.assertEqual("selected", organization_template["repository_selection"])
        self.assertNotIn("bootstrap configuration currently requires personal-repository", source)

    def test_app_binding_is_separate_from_garm_entity_and_branch_is_explicit(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('"${repository}" "${repository_id}" "${default_branch}" "${authority_kind}"', source)
        self.assertIn('v.get("default_branch")!=default_branch', source)
        self.assertNotIn('v.get("default_branch")!="main"', source)

    def test_script_parses(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
