from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-incus-garm-tls.sh"
PROVIDER = ROOT / "templates/garm/garm-provider-incus.toml"
PROVISION = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
EVIDENCE_INSTALLER = ROOT / "scripts/host/install-wsl-jit-evidence.py"


def load_evidence_installer():
    spec = importlib.util.spec_from_file_location(
        "install_wsl_jit_evidence", EVIDENCE_INSTALLER
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IncusGarmTlsTests(unittest.TestCase):
    def test_installer_is_plan_only_by_default_and_apply_is_guarded(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(INSTALLER)], text=True, capture_output=True
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(["bash", str(INSTALLER)], text=True, capture_output=True)
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn('"mode":"plan"', plan.stdout)
        self.assertIn('"garm_enabled":false', plan.stdout)
        apply = subprocess.run(
            ["bash", str(INSTALLER), "--apply"], text=True, capture_output=True
        )
        self.assertNotEqual(0, apply.returncode)
        self.assertIn("requires --acknowledge-loopback-tls-boundary", apply.stderr)

    def test_provider_uses_only_restricted_loopback_tls(self) -> None:
        source = PROVIDER.read_text()
        for exact in (
            'project_name = "ci-jit"',
            "include_default_profile = false",
            'url = "https://127.0.0.1:8443"',
            'client_certificate = "/etc/self-hosted-ci/garm/incus-client.crt"',
            'client_key = "/etc/self-hosted-ci/garm/incus-client.key"',
            'tls_server_certificate = "/etc/self-hosted-ci/garm/incus-server.crt"',
            'instance_type = "container"',
        ):
            self.assertIn(exact, source)
        self.assertNotIn("unix_socket", source)
        self.assertNotIn("skip_verify = true", source)

    def test_installer_enforces_identity_acl_and_negative_canaries(self) -> None:
        source = INSTALLER.read_text()
        for required in (
            "core.https_address=127.0.0.1:8443",
            "--restricted --projects",
            "root:garm-manager:640",
            "restricted trust identity is not unique",
            "'/1.0/projects/default'",
            '"security.privileged": "true"',
            "privileged canary left an instance",
            "activation sentinel must be absent",
            "GARM must be disabled during TLS boundary installation",
            '"garm_enabled":false',
            '"runner_registration_performed":false',
        ):
            self.assertIn(required, source)
        self.assertIn("grep -Eq '^(incus|incus-admin|sudo|admin|wheel)$'", source)
        self.assertIn("privileged canary was rejected for an unrelated reason", source)
        self.assertIn('--cacert "${server_cert}"', source)
        self.assertIn('--resolve "${server_name}:8443:127.0.0.1"', source)
        self.assertIn("--noproxy '*'", source)
        self.assertNotIn("--insecure", source)

    def test_provisioning_installs_tls_boundary_but_keeps_activation_inert(
        self,
    ) -> None:
        source = PROVISION.read_text()
        self.assertIn('install-incus-garm-tls.sh" --apply', source)
        self.assertIn(
            '--provider-template "/usr/local/share/self-hosted-ci/garm-provider-incus.toml"',
            source,
        )
        self.assertIn("--acknowledge-loopback-tls-boundary", source)
        self.assertIn(
            'bash "${repo_root}/scripts/host/install-runner-network-runtime.sh"', source
        )
        self.assertIn("systemctl start self-hosted-ci-boundary-verify.service", source)
        self.assertIn(
            "systemctl is-active --quiet self-hosted-ci-boundary-verify.service", source
        )
        self.assertIn('rm -f "${TARGET_ROOT}/ACTIVATION_APPROVED"', source)
        for transaction_script in (
            "activate-garm-jit.sh",
            "deactivate-garm-jit.sh",
            "garm-jit-transaction-lib.sh",
        ):
            self.assertIn(transaction_script, source)
            self.assertNotIn(
                f'/usr/local/lib/self-hosted-ci/{transaction_script}" --', source
            )
        self.assertIn(
            'install -o root -g root -m 0755 "${repo_root}/scripts/host/${transaction_script}" "/usr/local/lib/self-hosted-ci/${transaction_script}"',
            source,
        )

    def test_verified_evidence_is_installed_from_exact_signed_refs(self) -> None:
        source = EVIDENCE_INSTALLER.read_text()
        for required in (
            'target_root / "runner-boundary-v2.json"',
            'target_root / "host-evidence"',
            "if set(records) != required:",
            'record.get("uid") != 0',
            'record.get("gid") != 0',
            "target.is_symlink()",
            "os.replace(stage, target_evidence)",
            "os.replace(bundle_stage, target_bundle)",
        ):
            self.assertIn(required, source)
        provision = PROVISION.read_text()
        self.assertIn('install-wsl-jit-evidence.py"', provision)
        self.assertIn('--evidence "${evidence}"', provision)
        self.assertIn('--target-root "${TARGET_ROOT}"', provision)
        self.assertIn('--measurement-root "${TARGET_ROOT}/host-evidence"', provision)
        self.assertIn(
            "installed runner-boundary evidence failed post-install verification",
            provision,
        )

    def test_evidence_installer_copies_only_signed_refs_via_staging(self) -> None:
        installer = load_evidence_installer()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            measurement_root = root / "measurements"
            referenced = measurement_root / "evidence" / "incus.json"
            referenced.parent.mkdir(parents=True)
            referenced.write_text('{"verified":true}\n', encoding="utf-8")
            referenced.chmod(0o640)
            secret = measurement_root / "reviewer-private-key.pem"
            secret.write_text("must-not-copy", encoding="utf-8")
            bundle = measurement_root / "boundary.json"
            bundle.write_text(
                json.dumps(
                    {
                        "components": [{"evidence_refs": ["evidence/incus.json"]}],
                        "host_security": {"checks": []},
                        "measurements": {
                            "artifacts": [
                                {
                                    "ref": "evidence/incus.json",
                                    "uid": 0,
                                    "gid": 0,
                                    "mode": "0640",
                                    "sha256": "0" * 64,
                                    "size": referenced.stat().st_size,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            target = root / "target"
            target.mkdir()
            with (
                mock.patch.object(installer.os, "geteuid", return_value=0),
                mock.patch.object(installer.os, "chown"),
            ):
                installer.install(bundle, measurement_root, target)
            self.assertEqual(
                referenced.read_bytes(),
                (target / "host-evidence/evidence/incus.json").read_bytes(),
            )
            self.assertFalse(
                (target / "host-evidence/reviewer-private-key.pem").exists()
            )
            self.assertEqual(
                bundle.read_bytes(), (target / "runner-boundary-v2.json").read_bytes()
            )
            self.assertFalse(
                any(
                    path.name.startswith(".host-evidence.") for path in target.iterdir()
                )
            )


if __name__ == "__main__":
    unittest.main()
