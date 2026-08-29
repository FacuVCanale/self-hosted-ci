from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
import base64
import json
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import spki_fingerprint
from github_automation.runner_jit import SqliteAllocationLedger, sign_allocation
from github_automation.runner_jit_broker import (
    AllocationBroker,
    ExternalLiveWorkflowJobVerifier,
    GARM_CLEANUP_CONVERGENCE_SECONDS,
    GarmCliAllocationDriver,
    JobStartedContext,
)
from tests.github_automation.test_runner_jit import payload, reservation


NOW = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)


class FakeGarm:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.scales: dict[str, dict] = {}
        self.runner_name = "runner-unique"

    def assert_no_persistent_scale_set(self):
        self.events.append("assert-zero-persistent")

    def ensure_disabled_scale_set(self, value):
        self.events.append("create-disabled")
        self.scales[value["scale_set_name"]] = {"id": "41", "enabled": False}
        return "41"

    def bind_signed_allocation(self, scale_id, value, envelope):
        self.events.append("bind-signed")

    def find_scale_set(self, name):
        return self.scales.get(name, {}).get("id")

    def enable_scale_set(self, scale_id, name):
        self.events.append("enable")
        self.scales[name]["enabled"] = True

    def assert_runner_claim(self, scale_id, name, runner_name, payload):
        self.events.append("claim")
        if runner_name != self.runner_name or not self.scales[name]["enabled"]:
            raise AssertionError

    def disable_scale_set(self, scale_id, name):
        self.events.append("disable")
        self.scales[name]["enabled"] = False

    def drain_scale_set(self, scale_id, name):
        self.events.append("drain")

    def delete_scale_set(self, scale_id, name):
        self.events.append("delete")
        self.scales.pop(name)

    def assert_scale_set_absent(self, name):
        self.events.append("absent")
        if name in self.scales:
            raise AssertionError

    def measure_cleanup(self, allocation_id, name):
        if name in self.scales:
            raise AssertionError
        return {
            "registration_removed": True,
            "workspace_removed": True,
            "token_removed": True,
            "container_removed": True,
            "allocation_removed": True,
            "orphan_registrations": 0,
        }

    def assert_runtime_empty(self):
        if self.scales:
            raise AssertionError


class FakeLiveJobVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, payload, context):
        self.calls.append((payload["job_id"], context.run_id))


class DelayedCleanupGarm(FakeGarm):
    def __init__(self) -> None:
        super().__init__()
        self.cleanup_measurements = 0

    def measure_cleanup(self, allocation_id, name):
        self.cleanup_measurements += 1
        if self.cleanup_measurements == 1:
            from github_automation.runner_jit import RunnerJitError

            raise RunnerJitError("allocation Incus instance survived cleanup")
        return super().measure_cleanup(allocation_id, name)


class AllocationBrokerTests(unittest.TestCase):
    def test_garm_cleanup_window_covers_slow_reconciliation_loops(self):
        self.assertGreaterEqual(GARM_CLEANUP_CONVERGENCE_SECONDS, 600)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.driver = FakeGarm()
        self.ledger = SqliteAllocationLedger(Path(self.tempdir.name) / "ledger.sqlite3")
        self.live = FakeLiveJobVerifier()
        self.broker = AllocationBroker(
            self.ledger,
            self.driver,
            self.private.public_key(),
            spki_fingerprint(self.private.public_key()),
            self.live,
        )
        self.payload = payload()
        self.reservation = reservation()
        self.envelope = sign_allocation(self.payload, self.private, now=NOW)

    def tearDown(self):
        self.tempdir.cleanup()

    def context(self, **changes):
        value = {
            "repository_id": self.payload["repository_id"],
            "repository": self.payload["repository"],
            "dispatch_sha": self.payload["dispatch_sha"],
            "tested_sha": self.payload["tested_sha"],
            "workflow_ref": self.payload["workflow_ref"],
            "run_id": self.payload["run_id"],
            "run_attempt": self.payload["run_attempt"],
            "job_name": self.payload["job_name"],
            "runner_name": self.driver.runner_name,
            "scale_set_name": self.payload["scale_set_name"],
        }
        value.update(changes)
        return JobStartedContext.from_mapping(value)

    def test_exact_transient_lifecycle_has_no_persistent_scale_set(self):
        prepared = self.broker.reserve(self.reservation, now=NOW)
        self.assertEqual(self.payload["scale_set_name"], prepared["runner_label"])
        self.assertEqual(
            "reserved", self.ledger.get(self.payload["allocation_id"]).state
        )
        self.broker.finalize(self.envelope, now=NOW)
        self.broker.job_started(self.payload["allocation_id"], self.context(), now=NOW)
        self.broker.finish(self.payload["allocation_id"], outcome="success")
        self.assertEqual(
            "cleaned", self.ledger.get(self.payload["allocation_id"]).state
        )
        self.assertEqual(
            [
                "assert-zero-persistent",
                "create-disabled",
                "bind-signed",
                "enable",
                "claim",
                "disable",
                "disable",
                "drain",
                "delete",
                "absent",
            ],
            self.driver.events,
        )
        self.assertEqual({}, self.driver.scales)
        self.assertEqual(
            [(self.payload["job_id"], self.payload["run_id"])], self.live.calls
        )

    def test_provider_bootstrap_installs_signed_binding_and_fail_closed_hook(self):
        hook = Path(self.tempdir.name) / "hook.py"
        hook.write_text("#!/usr/bin/env python3\nprint('hook')\n", encoding="utf-8")
        driver = GarmCliAllocationDriver(
            {
                "garm_cli_home": "/var/lib/garm",
                "provider_name": "incus_ci_jit",
                "image_alias": "runner-pinned",
                "image_fingerprint": "b" * 64,
                "targets": {
                    self.payload["repository_id"]: {
                        "authority_kind": "personal-repository",
                        "entity_flag": "--repo",
                        "entity_id": "1",
                        "entity_name": self.payload["repository"],
                        "runner_group": None,
                    }
                },
            },
            hook,
        )
        bootstrap = driver._bootstrap(self.envelope).decode("utf-8")
        self.assertIn("/etc/self-hosted-ci/allocation.json", bootstrap)
        self.assertIn(self.payload["allocation_id"], bootstrap)
        self.assertIn(self.payload["scale_set_name"], bootstrap)
        self.assertIn(
            "ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/self-hosted-ci/bin/runner-job-started-hook.sh",
            bootstrap,
        )
        self.assertIn(
            "exec /usr/bin/python3 /opt/self-hosted-ci/bin/runner-job-started-hook.py",
            bootstrap,
        )
        self.assertIn("chmod 0755 /opt/self-hosted-ci/bin/runner-job-started-hook.sh", bootstrap)
        self.assertIn(
            "export HTTPS_PROXY=http://10.254.0.1:3128",
            bootstrap,
        )
        self.assertIn(
            "export NO_PROXY=10.254.0.1,127.0.0.1,localhost",
            bootstrap,
        )
        self.assertIn(
            "DefaultEnvironment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/self-hosted-ci/bin/runner-job-started-hook.sh HTTPS_PROXY=http://10.254.0.1:3128",
            bootstrap,
        )
        self.assertIn(
            "> /etc/profile.d/self-hosted-ci-runner-proxy.sh",
            bootstrap,
        )
        self.assertIn("chmod 0644 /etc/profile.d/self-hosted-ci-runner-proxy.sh", bootstrap)
        self.assertIn("systemctl daemon-reexec", bootstrap)

    def test_scale_set_binds_complete_offline_runner_template(self):
        hook = Path(self.tempdir.name) / "hook.py"
        hook.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        template = Path(self.tempdir.name) / "runner-install.tmpl"
        template.write_text("#!/bin/bash\necho '{{ .DownloadURL }}'\n", encoding="utf-8")
        driver = GarmCliAllocationDriver(
            {
                "garm_cli_home": "/run/self-hosted-ci/garm-cli",
                "provider_name": "incus_ci_jit",
                "image_alias": "runner-pinned",
                "image_fingerprint": "b" * 64,
                "targets": {},
            },
            hook,
        )
        observed = {}

        def run(*args):
            if args[:2] == ("scaleset", "update"):
                path = Path(args[args.index("--extra-specs-file") + 1])
                observed["extra_specs"] = json.loads(path.read_text(encoding="utf-8"))
            return {}

        driver._run = run
        show_calls = 0

        def show_exact(*_args):
            nonlocal show_calls
            show_calls += 1
            return {"id": "1", "name": "jit"} if show_calls == 1 else dict(observed)

        driver._show_exact = show_exact
        with mock.patch(
            "github_automation.runner_jit_broker.RUNNER_INSTALL_TEMPLATE", template
        ):
            driver.bind_signed_allocation("1", self.payload, self.envelope)
        decoded = base64.b64decode(observed["extra_specs"]["runner_install_template"])
        self.assertEqual(template.read_bytes(), decoded)
        self.assertNotIn(b"installdependencies.sh", decoded)

    def test_offline_template_keeps_full_jit_lifecycle_without_apt(self):
        raw = (
            Path(__file__).resolve().parents[2]
            / "templates/garm/runner-install-offline.sh.tmpl"
        ).read_bytes()
        self.assertTrue(raw.startswith(b"#!/bin/bash\n"))
        self.assertNotIn(b"var CloudConfigTemplate", raw)
        template = raw.decode("utf-8")
        for required in (
            "{{ .DownloadURL }}",
            "{{ .MetadataURL }}",
            "{{ .CallbackURL }}",
            "{{- if .UseJITConfig }}",
            "systemctl start $SVC_NAME",
            "verifying pre-baked runner dependencies",
        ):
            self.assertIn(required, template)
        for forbidden in ("installdependencies.sh", "apt-get", " apt "):
            self.assertNotIn(forbidden, template)

    def test_garm_cli_commands_always_recreate_the_ephemeral_session(self):
        hook = Path(self.tempdir.name) / "hook.py"
        hook.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        driver = GarmCliAllocationDriver(
            {
                "garm_cli_home": "/run/self-hosted-ci/garm-cli",
                "provider_name": "incus_ci_jit",
                "image_alias": "runner-pinned",
                "image_fingerprint": "b" * 64,
                "targets": {},
            },
            hook,
        )
        completed = mock.Mock(returncode=0, stdout="[]")
        with mock.patch("subprocess.run", return_value=completed) as run:
            self.assertEqual([], driver._run("scaleset", "list", "--repo", "id"))
        self.assertEqual(
            [
                "/usr/local/lib/self-hosted-ci/garm-cli-session.py",
                "run",
                "--",
                "--format",
                "json",
                "scaleset",
                "list",
                "--repo",
                "id",
            ],
            run.call_args.args[0],
        )

    def test_garm_omitempty_false_and_zero_fields_preserve_disabled_jit_contract(self):
        hook = Path(self.tempdir.name) / "hook.py"
        hook.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        driver = GarmCliAllocationDriver(
            {
                "garm_cli_home": "/run/self-hosted-ci/garm-cli",
                "provider_name": "incus_ci_jit",
                "image_alias": "runner-pinned",
                "image_fingerprint": "b" * 64,
                "targets": {},
            },
            hook,
        )
        driver._run = mock.Mock(return_value={"id": 1, "name": "jit", "max_runners": 1})
        self.assertEqual(
            {"id": 1, "name": "jit", "max_runners": 1},
            driver._show_exact("1", "jit", False),
        )

    def test_broker_units_wait_for_authenticated_garm_readiness(self):
        for name in (
            "self-hosted-ci-allocation-broker.service",
            "self-hosted-ci-canary-broker.service",
        ):
            source = (Path(__file__).parents[2] / "packaging/systemd" / name).read_text()
            self.assertIn("garm-cli-session.py ensure", source)
            self.assertIn("&& /usr/local/lib/self-hosted-ci/garm-allocation-broker.py recover", source)
            self.assertIn('[ "$i" -lt 60 ]', source)
            self.assertIn("Environment=INCUS_CONF=/run/self-hosted-ci/incus-client", source)
            self.assertIn("/run/self-hosted-ci", source)

    def test_hook_uses_only_fixed_bridge_local_broker_before_steps(self):
        source = (
            Path(__file__).parents[2] / "scripts/host/runner-job-started-hook.py"
        ).read_text()
        self.assertIn('BROKER_URL = "http://10.254.0.1:8079/v1/job-started"', source)
        self.assertNotIn("BROKER_URL = os.environ", source)
        for field in (
            "GITHUB_REPOSITORY_ID",
            "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_JOB",
            "RUNNER_NAME",
        ):
            self.assertIn(field, source)
        self.assertIn('ALLOCATION_FILE = Path("/etc/self-hosted-ci/allocation.json")', source)
        self.assertIn('value["payload"].get("tested_sha")', source)
        self.assertNotIn('value["payload"].get("tested_merge_sha")', source)
        self.assertNotIn('required_env("CI_GATE_TRUSTED_TESTED_SHA")', source)
        self.assertIn("response.status != 204 or response_body", source)

    def test_broker_http_threads_are_strictly_bounded(self):
        source = (
            Path(__file__).parents[2] / "scripts/host/garm-allocation-broker.py"
        ).read_text()
        self.assertIn("class BoundedThreadingHTTPServer", source)
        self.assertIn("threading.BoundedSemaphore(max_workers)", source)
        self.assertIn("max_workers=4", source)

    def test_external_live_job_verifier_requires_exact_numeric_job_response(self):
        executable = Path(self.tempdir.name) / "verify-job"
        executable.write_text(
            "#!/bin/sh\nprintf '%s' '{\"verified\":false}'\n", encoding="utf-8"
        )
        executable.chmod(0o755)
        verifier = ExternalLiveWorkflowJobVerifier(executable)
        with self.assertRaisesRegex(
            ValueError, "live workflow-job verifier executable is unsafe"
        ):
            verifier.verify(self.payload, self.context())

    def test_job_started_cross_binding_fails_before_disable_or_start(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        with self.assertRaisesRegex(ValueError, "crossed"):
            self.broker.job_started(
                self.payload["allocation_id"], self.context(run_id="999"), now=NOW
            )
        self.assertEqual("issued", self.ledger.get(self.payload["allocation_id"]).state)
        self.assertTrue(self.driver.scales[self.payload["scale_set_name"]]["enabled"])

    def test_reboot_recovery_disables_drains_deletes_and_is_idempotent(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        recovered = self.broker.recover_all()
        self.assertEqual([self.payload["allocation_id"]], recovered)
        self.assertEqual(
            "cleaned", self.ledger.get(self.payload["allocation_id"]).state
        )
        self.assertEqual([], self.broker.recover_all())
        self.assertEqual({}, self.driver.scales)

    def test_recovery_accepts_already_absent_bound_scale_set(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        self.driver.scales.pop(self.payload["scale_set_name"])
        self.driver.events.clear()

        recovered = self.broker.recover_all()

        self.assertEqual([self.payload["allocation_id"]], recovered)
        self.assertEqual(
            "cleaned", self.ledger.get(self.payload["allocation_id"]).state
        )
        self.assertNotIn("disable", self.driver.events)
        self.assertNotIn("delete", self.driver.events)
        self.assertIn("absent", self.driver.events)

    def test_reboot_between_reserve_and_dispatch_cleans_disabled_scale_set(self):
        self.broker.reserve(self.reservation, now=NOW)
        recovered = self.broker.recover_all()
        self.assertEqual([self.payload["allocation_id"]], recovered)
        record = self.ledger.get(self.payload["allocation_id"])
        self.assertEqual("cleaned", record.state)
        self.assertEqual(0, record.jobs_started)
        self.assertEqual({}, self.driver.scales)

    def test_exact_recovery_does_not_touch_other_allocation(self):
        first = reservation()
        second = reservation(
            allocation_id="0198ef24-f800-7000-8000-000000000002", nonce="B" * 43
        )
        self.broker.reserve(first, now=NOW)
        self.broker.reserve(second, now=NOW)
        receipt = self.broker.recover(first["allocation_id"])
        self.assertEqual(
            {"allocation_id": first["allocation_id"], "state": "absent"}, receipt
        )
        self.assertNotIn(first["scale_set_name"], self.driver.scales)
        self.assertIn(second["scale_set_name"], self.driver.scales)
        self.assertEqual("reserved", self.ledger.get(second["allocation_id"]).state)

    def test_terminal_workflow_before_job_started_recovers_exact_allocation(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        receipt = self.broker.finish(self.payload["allocation_id"], outcome="failure")
        self.assertEqual(
            {
                "allocation_id": self.payload["allocation_id"],
                "runner_label": self.payload["scale_set_name"],
                "state": "cleaned",
            },
            receipt,
        )
        self.assertEqual(
            "cleaned", self.ledger.get(self.payload["allocation_id"]).state
        )
        self.assertNotIn(self.payload["scale_set_name"], self.driver.scales)

    def test_finish_waits_for_instance_teardown_before_marking_cleanup(self):
        driver = DelayedCleanupGarm()
        broker = AllocationBroker(
            self.ledger,
            driver,
            self.private.public_key(),
            spki_fingerprint(self.private.public_key()),
            self.live,
        )
        broker.reserve(self.reservation, now=NOW)
        broker.finalize(self.envelope, now=NOW)
        context = self.context(runner_name=driver.runner_name)
        broker.job_started(self.payload["allocation_id"], context, now=NOW)
        with mock.patch("github_automation.runner_jit_broker.time.sleep"):
            broker.finish(self.payload["allocation_id"], outcome="success")
        self.assertEqual(2, driver.cleanup_measurements)
        self.assertEqual(
            "cleaned", self.ledger.get(self.payload["allocation_id"]).state
        )

    def test_cleanup_proof_is_exact_cross_label_safe_and_concurrent(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        self.broker.job_started(self.payload["allocation_id"], self.context(), now=NOW)
        receipt = self.broker.finish(self.payload["allocation_id"], outcome="success")
        self.assertEqual("cleaned", receipt["state"])
        with self.assertRaisesRegex(ValueError, "crossed"):
            self.broker.prove_clean(
                self.payload["allocation_id"], "wsl-jit-" + "0" * 32
            )
        with ThreadPoolExecutor(max_workers=4) as pool:
            proofs = list(
                pool.map(
                    lambda _: self.broker.prove_clean(
                        self.payload["allocation_id"], self.payload["scale_set_name"]
                    ),
                    range(8),
                )
            )
        self.assertTrue(all(proof["runtime_empty"] is True for proof in proofs))

    def test_cleanup_proof_rejects_orphan_runtime(self):
        self.broker.reserve(self.reservation, now=NOW)
        self.broker.finalize(self.envelope, now=NOW)
        self.broker.job_started(self.payload["allocation_id"], self.context(), now=NOW)
        self.broker.finish(self.payload["allocation_id"], outcome="success")
        self.driver.scales["orphan"] = {"id": "99", "enabled": False}
        with self.assertRaises(AssertionError):
            self.broker.prove_clean(
                self.payload["allocation_id"], self.payload["scale_set_name"]
            )


if __name__ == "__main__":
    unittest.main()
