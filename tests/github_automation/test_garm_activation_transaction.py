from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTIVATE = ROOT / "scripts/host/activate-garm-jit.sh"
DEACTIVATE = ROOT / "scripts/host/deactivate-garm-jit.sh"
LIBRARY = ROOT / "scripts/host/garm-jit-transaction-lib.sh"
SERVICE = ROOT / "packaging/systemd/self-hosted-ci-garm.service"
RUNBOOK = ROOT / "docs/runbook-bootstrap-local-ci.md"


class GarmActivationTransactionTests(unittest.TestCase):
    def test_plan_is_side_effect_free_and_machine_readable(self) -> None:
        for script in (ACTIVATE, DEACTIVATE):
            result = subprocess.run(
                ["bash", str(script), "--plan"], text=True, capture_output=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("plan", payload["mode"])
            self.assertEqual("not_performed", payload["external_calls"])
            self.assertFalse(payload["host_changes"])

    def test_apply_requires_exact_inputs_and_two_acknowledgements(self) -> None:
        activate = ACTIVATE.read_text(encoding="utf-8")
        deactivate = DEACTIVATE.read_text(encoding="utf-8")
        for source in (activate, deactivate):
            for token in (
                "--incus-project",
                "--garm-cli-home",
                "--acknowledge-external-github-mutation",
                '"$incus_project" == ci-jit',
                "acquire_transaction_lock",
            ):
                self.assertIn(token, source)
            self.assertNotIn("--scale-set-id", source)
            self.assertNotIn("--scale-set-name", source)
        self.assertIn("--acknowledge-local-ci-activation", activate)
        self.assertIn("--acknowledge-local-ci-deactivation", deactivate)
        self.assertIn("require_command_contracts", activate)
        self.assertIn("require_deactivation_command_contracts", deactivate)
        for script in (ACTIVATE, DEACTIVATE):
            result = subprocess.run(
                ["bash", str(script), "--apply"], text=True, capture_output=True
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("requires both explicit acknowledgements", result.stderr)

    def test_activation_is_fail_closed_and_sentinel_is_durable(self) -> None:
        source = ACTIVATE.read_text(encoding="utf-8")
        library = LIBRARY.read_text(encoding="utf-8")
        for token in (
            "require_real_policy_units",
            "require_base_health",
            "require_health_configuration",
            "zero_runtime_state",
            "create_activation_sentinel",
            'systemctl enable --now "$POLICY_SERVICE" "$PROXY_SERVICE"',
            "create_network_sentinel",
            'systemctl enable --now "$BROKER_SERVICE"',
        ):
            self.assertIn(token, source)
        self.assertIn('systemctl start "$BOUNDARY_SERVICE"', source)
        self.assertIn("require_canary_production_fence", source)
        self.assertIn("production-fence", library)
        self.assertLess(
            source.index("require_canary_production_fence"),
            source.index("require_live_artifact_contract"),
        )
        self.assertLess(
            source.index('systemctl start "$BOUNDARY_SERVICE"'),
            source.index("require_base_health"),
        )
        for token in ("os.fsync(f.fileno())", "os.replace(t,p)", "os.fsync(d)"):
            self.assertIn(token, library)
        self.assertLess(
            source.index("create_activation_sentinel"),
            source.index('systemctl enable --now "$POLICY_SERVICE"'),
        )
        self.assertLess(
            source.index('systemctl enable --now "$POLICY_SERVICE"'),
            source.index("create_network_sentinel"),
        )
        self.assertLess(
            source.index("create_network_sentinel"),
            source.index('systemctl enable --now "$GARM_SERVICE"'),
        )
        self.assertLess(
            source.index('systemctl enable --now "$GARM_SERVICE"'),
            source.index('systemctl enable --now "$BROKER_SERVICE"'),
        )

    def test_rollback_and_deactivation_disable_before_cleanup(self) -> None:
        library = LIBRARY.read_text(encoding="utf-8")
        deactivate = DEACTIVATE.read_text(encoding="utf-8")
        disable = deactivate.index(
            'systemctl disable --now "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"'
        )
        drain = deactivate.index("recover_allocations")
        stop = deactivate.index("stop_after_zero")
        self.assertLess(disable, drain)
        self.assertLess(drain, stop)
        self.assertIn("GARM and policy remain active", deactivate)
        self.assertIn('systemctl start "$POLICY_SERVICE" "$PROXY_SERVICE"', deactivate)
        self.assertLess(
            disable,
            deactivate.index('systemctl start "$POLICY_SERVICE" "$PROXY_SERVICE"'),
        )
        self.assertIn(
            "run deactivation to reconcile it", ACTIVATE.read_text(encoding="utf-8")
        )
        self.assertLess(
            library.index(
                'systemctl disable --now "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"'
            ),
            library.index('systemctl disable --now "$GARM_SERVICE"'),
        )
        self.assertLess(
            library.index('systemctl disable --now "$GARM_SERVICE"'),
            library.index(
                "remove_activation_sentinel", library.index("stop_after_zero")
            ),
        )
        self.assertLess(
            library.index(
                "remove_activation_sentinel", library.index("stop_after_zero")
            ),
            library.index('systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"'),
        )
        self.assertLess(
            library.index('systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"'),
            library.index("remove_network_sentinel", library.index("stop_after_zero")),
        )
        self.assertIn("GARM_SESSION_FAILURE_QUARANTINE=true", deactivate)
        self.assertIn('"$NETWORK_POLICY_SCRIPT" quarantine', library)
        self.assertIn('"$GARM_SESSION_HELPER" run -- --format json', library)

    def test_deactivation_closes_admission_before_optional_runtime_contract_checks(self) -> None:
        deactivate = DEACTIVATE.read_text(encoding="utf-8")
        library = LIBRARY.read_text(encoding="utf-8")
        disable = deactivate.index(
            'systemctl disable --now "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"'
        )
        prerequisites = deactivate.index("require_deactivation_command_contracts")
        recovery = deactivate.index("recover_allocations")
        self.assertLess(disable, prerequisites)
        self.assertLess(prerequisites, recovery)
        self.assertNotIn("require_health_configuration", deactivate)
        deactivation_contract = library.split(
            "require_deactivation_command_contracts(){", 1
        )[1].split("\nrequire_command_contracts()", 1)[0]
        self.assertNotIn("$OUTBOUND_CONFIG", deactivation_contract)
        self.assertNotIn("$HEALTH_STATE", deactivation_contract)
        self.assertIn(
            'require_root_regular_file "$OUTBOUND_CONFIG" 0600',
            library.split("require_command_contracts(){", 1)[1].split("\n", 1)[0],
        )

    def test_zero_runtime_can_be_proved_after_canonical_deactivation(self) -> None:
        library = LIBRARY.read_text(encoding="utf-8")
        for token in (
            "configured_scale_sets_empty_offline()",
            "/var/lib/self-hosted-ci/garm/garm.db",
            'systemctl is-active "$unit"',
            '[[ "$state" == inactive ]]',
            "garm_database_files_safe()",
            '"$GARM_DATABASE-wal"',
            '"$GARM_DATABASE-shm"',
            'runuser -u garm-manager -- /usr/bin/python3',
            "file:{sys.argv[1]}?mode=ro",
            'PRAGMA query_only=ON',
            '"scale_sets","instances"',
            'SELECT COUNT(*) FROM scale_sets',
            'SELECT COUNT(*) FROM instances',
            "configured_runtime_empty()",
            "zero_runtime_state(){ configured_runtime_empty&&incus_project_empty; }",
        ):
            self.assertIn(token, library)
        self.assertNotIn("INSERT ", library)
        self.assertNotIn("UPDATE ", library)
        self.assertNotIn("DELETE FROM", library)

    def test_garm_service_forbids_host_wide_incus_admin(self) -> None:
        source = SERVICE.read_text(encoding="utf-8")
        self.assertNotIn("SupplementaryGroups=incus-admin", source)
        self.assertIn("project-scoped Incus TLS credentials", source)
        self.assertIn("NoNewPrivileges=true", source)

    def test_provider_prerequisite_is_tls_project_scoped(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        for token in (
            'project_name = "ci-jit"',
            'url = "https://127.0.0.1:8443"',
            "include_default_profile = false",
            "incus-client.crt",
            "incus-client.key",
            "expires within 30 days",
            "garm-manager belongs to a forbidden privileged group",
        ):
            self.assertIn(token, source)

    def test_security_checks_do_not_depend_on_python_assertions(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)
        self.assertIn("raise SystemExit", source)

    def test_activation_cross_checks_outbound_broker_and_health_contracts(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        for token in (
            'readonly OUTBOUND_CONFIG=/etc/self-hosted-ci/outbound-worker.json',
            'require_root_regular_file "$OUTBOUND_CONFIG" 0600',
            'b=json.load(open(sys.argv[2])); o=json.load(open(sys.argv[3]))',
            'repository_id=str(o.get("repository_id"))',
            'target.get("authority_kind")!=o.get("authority_kind")',
            'target.get("runner_group")!=o.get("runner_group")',
            'o.get("image_fingerprint")!=b.get("image_fingerprint")',
        ):
            self.assertIn(token, source)

    def test_health_cross_check_rejects_outbound_image_or_authority_drift(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        marker = "import json,sys\n"
        body = marker + source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        fingerprint = "a" * 64
        target = {
            "authority_kind": "organization-runner-group",
            "entity_flag": "--org",
            "entity_id": "11111111-1111-1111-1111-111111111111",
            "entity_name": "owner",
            "runner_group": "ci",
        }
        broker = {
            "garm_cli_home": "/run/self-hosted-ci/garm-cli",
            "provider_name": "incus_ci_jit",
            "image_alias": "image-v1",
            "image_fingerprint": fingerprint,
            "live_job_verifier": "/verifier",
            "targets": {"42": target},
        }
        health = {
            "schema_version": 3,
            "garm_cli_home": "/run/self-hosted-ci/garm-cli",
            "manager_configured": True,
            "provider_configured": True,
            "image_configured": True,
            "broker_configured": True,
            "zero_scale_sets": True,
            "image": {"alias": "image-v1", "fingerprint": fingerprint},
            "targets": {"42": target},
        }
        outbound = {
            "repository": "owner/repo",
            "repository_id": 42,
            "default_branch": "main",
            "authority_kind": "organization-runner-group",
            "runner_group": "ci",
            "image_fingerprint": fingerprint,
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("health", "broker", "outbound")]

            def run() -> subprocess.CompletedProcess[str]:
                for path, value in zip(paths, (health, broker, outbound), strict=True):
                    path.write_text(json.dumps(value), encoding="utf-8")
                return subprocess.run(
                    [sys.executable, "-c", body, *map(str, paths), "/verifier"],
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(0, run().returncode)
            outbound["image_fingerprint"] = "b" * 64
            self.assertNotEqual(0, run().returncode)
            outbound["image_fingerprint"] = fingerprint
            outbound["runner_group"] = "other"
            self.assertNotEqual(0, run().returncode)

    def test_scripts_parse_as_bash(self) -> None:
        for script in (ACTIVATE, DEACTIVATE, LIBRARY):
            result = subprocess.run(
                ["bash", "-n", str(script)], text=True, capture_output=True
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_runbook_matches_dynamic_scale_set_lifecycle(self) -> None:
        source = RUNBOOK.read_text(encoding="utf-8")
        self.assertNotIn("--scale-set-id", source)
        self.assertNotIn("--scale-set-name", source)
        self.assertNotIn("--drain-timeout-seconds", source)
        self.assertNotIn("reconcilia un scale set deshabilitado", source)
        self.assertIn("zero_scale_sets: true", source)
        self.assertIn("scale set efímero por escenario", source)
        self.assertIn("build-wsl-jit-lifecycle-evidence.py", source)
        for scenario in ("success", "failure", "cancel", "timeout", "force-cancel", "reboot"):
            self.assertIn(f"proofs/{scenario}.json", source)
        activation = source.split("La activación no recibe identidad de scale set", 1)[1]
        activation = activation.split("## Sandbox y GitHub App", 1)[0]
        self.assertIn("activate-garm-jit.sh --apply", activation)
        self.assertNotIn("--scale-set", activation)


if __name__ == "__main__":
    unittest.main()
