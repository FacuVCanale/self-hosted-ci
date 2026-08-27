from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTIVATE = ROOT / "scripts/host/activate-garm-jit.sh"
DEACTIVATE = ROOT / "scripts/host/deactivate-garm-jit.sh"
LIBRARY = ROOT / "scripts/host/garm-jit-transaction-lib.sh"
SERVICE = ROOT / "packaging/systemd/self-hosted-ci-garm.service"


class GarmActivationTransactionTests(unittest.TestCase):
    def test_plan_is_side_effect_free_and_machine_readable(self) -> None:
        for script in (ACTIVATE, DEACTIVATE):
            result = subprocess.run(["bash", str(script), "--plan"], text=True, capture_output=True)
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
                "--garm-cli-home", "--acknowledge-external-github-mutation",
                '"$incus_project" == ci-jit', "require_command_contracts", "acquire_transaction_lock",
            ):
                self.assertIn(token, source)
            self.assertNotIn("--scale-set-id", source)
            self.assertNotIn("--scale-set-name", source)
        self.assertIn("--acknowledge-local-ci-activation", activate)
        self.assertIn("--acknowledge-local-ci-deactivation", deactivate)
        for script in (ACTIVATE, DEACTIVATE):
            result = subprocess.run(["bash", str(script), "--apply"], text=True, capture_output=True)
            self.assertEqual(1, result.returncode)
            self.assertIn("requires both explicit acknowledgements", result.stderr)

    def test_activation_is_fail_closed_and_sentinel_is_durable(self) -> None:
        source = ACTIVATE.read_text(encoding="utf-8")
        library = LIBRARY.read_text(encoding="utf-8")
        for token in (
            "require_real_policy_units", "require_base_health", "require_health_configuration",
            "zero_runtime_state", "create_activation_sentinel", 'systemctl enable --now "$POLICY_SERVICE" "$PROXY_SERVICE"',
            "create_network_sentinel", 'systemctl enable --now "$BROKER_SERVICE"',
        ):
            self.assertIn(token, source)
        self.assertIn('systemctl start "$BOUNDARY_SERVICE"', source)
        self.assertLess(source.index('systemctl start "$BOUNDARY_SERVICE"'), source.index("require_base_health"))
        for token in ("os.fsync(f.fileno())", "os.replace(t,p)", "os.fsync(d)"):
            self.assertIn(token, library)
        self.assertLess(source.index("create_activation_sentinel"), source.index('systemctl enable --now "$POLICY_SERVICE"'))
        self.assertLess(source.index('systemctl enable --now "$POLICY_SERVICE"'), source.index("create_network_sentinel"))
        self.assertLess(source.index("create_network_sentinel"), source.index('systemctl enable --now "$GARM_SERVICE"'))
        self.assertLess(source.index('systemctl enable --now "$GARM_SERVICE"'), source.index('systemctl enable --now "$BROKER_SERVICE"'))

    def test_rollback_and_deactivation_disable_before_cleanup(self) -> None:
        library = LIBRARY.read_text(encoding="utf-8")
        deactivate = DEACTIVATE.read_text(encoding="utf-8")
        disable = deactivate.index('systemctl stop "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"')
        drain = deactivate.index('recover_allocations')
        stop = deactivate.index("stop_after_zero")
        self.assertLess(disable, drain)
        self.assertLess(drain, stop)
        self.assertIn("GARM and policy remain active", deactivate)
        self.assertIn('systemctl start "$POLICY_SERVICE" "$PROXY_SERVICE"', deactivate)
        self.assertLess(deactivate.index('systemctl start "$POLICY_SERVICE" "$PROXY_SERVICE"'), disable)
        self.assertIn("run deactivation to reconcile it", ACTIVATE.read_text(encoding="utf-8"))
        self.assertLess(library.index('systemctl disable --now "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"'), library.index('systemctl disable --now "$GARM_SERVICE"'))
        self.assertLess(library.index('systemctl disable --now "$GARM_SERVICE"'), library.index("remove_activation_sentinel", library.index("stop_after_zero")))
        self.assertLess(library.index("remove_activation_sentinel", library.index("stop_after_zero")), library.index('systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"'))
        self.assertLess(library.index('systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"'), library.index("remove_network_sentinel", library.index("stop_after_zero")))
        self.assertIn("GARM_SESSION_FAILURE_QUARANTINE=true", deactivate)
        self.assertIn('"$NETWORK_POLICY_SCRIPT" quarantine', library)
        self.assertIn('"$GARM_SESSION_HELPER" run -- --format json', library)

    def test_garm_service_forbids_host_wide_incus_admin(self) -> None:
        source = SERVICE.read_text(encoding="utf-8")
        self.assertNotIn("SupplementaryGroups=incus-admin", source)
        self.assertIn("project-scoped Incus TLS credentials", source)
        self.assertIn("NoNewPrivileges=true", source)

    def test_provider_prerequisite_is_tls_project_scoped(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        for token in (
            'project_name = "ci-jit"', 'url = "https://127.0.0.1:8443"',
            "include_default_profile = false", "incus-client.crt", "incus-client.key",
            "expires within 30 days", "garm-manager belongs to a forbidden privileged group",
        ):
            self.assertIn(token, source)

    def test_security_checks_do_not_depend_on_python_assertions(self) -> None:
        source = LIBRARY.read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)
        self.assertIn("raise SystemExit", source)

    def test_scripts_parse_as_bash(self) -> None:
        for script in (ACTIVATE, DEACTIVATE, LIBRARY):
            result = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
