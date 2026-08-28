from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.canary_worker import (
    BrokerCanaryScenarioDriver,
    CANARY_UNITS,
    SCENARIOS,
    CanaryRuntimeError,
    CanaryRebootRequired,
    CanaryRuntime,
    CanaryStateStore,
    CommandResult,
    LiveCanaryDispatchAdapter,
    assert_production_fence,
)
from github_automation.crypto import spki_fingerprint
from github_automation.runner_jit import SqliteAllocationLedger, sign_allocation
from github_automation.runner_jit_broker import AllocationBroker, JobStartedContext
from tests.github_automation.test_runner_jit import payload, reservation
from tests.github_automation.test_runner_jit_broker import FakeGarm, FakeLiveJobVerifier
from tests.github_automation.test_canary_boundary import (
    PRIVATE as CANARY_PRIVATE,
    authorization as canary_authorization,
)
from github_automation.canary_boundary import sign_canary_authorization
from github_automation.canary_boundary import authorization_digest
from github_automation.worker_authority import HTTPResponse

_PROOF_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/host/build-wsl-jit-lifecycle-evidence.py"
)
_PROOF_SPEC = importlib.util.spec_from_file_location("lifecycle_proof_builder", _PROOF_SCRIPT)
assert _PROOF_SPEC is not None and _PROOF_SPEC.loader is not None
_PROOF_MODULE = importlib.util.module_from_spec(_PROOF_SPEC)
_PROOF_SPEC.loader.exec_module(_PROOF_MODULE)


NOW = datetime.now(timezone.utc).replace(microsecond=0)
AUTH = sign_canary_authorization(canary_authorization(), CANARY_PRIVATE)


def proof_record(scenario):
    value = {
        "authorization_digest": "0" * 64,
        "nonce": "a" * 32,
        "scenario": scenario,
        "allocation_id": "12345678-1234-4123-8123-123456789abc",
        "scale_set_id": "22345678-1234-4123-8123-123456789abc",
        "scale_set_name": "wsl-jit-" + "c" * 32,
        "run_id": 1,
        "run_attempt": 1,
        "job_id": 2,
        "runner_name": "runner-one",
        "repository": "x/y",
        "repository_id": 1,
        "dispatch_sha": "a" * 40,
        "head_sha": "b" * 40,
        "tested_merge_sha": "c" * 40,
        "image_fingerprint": "1" * 64,
        "network_policy_digest": "2" * 64,
        "github_app_config_digest": "3" * 64,
        "allocation_signer_fingerprint": "4" * 64,
        "reserved_at": "2026-08-28T12:00:00Z",
        "started_at": "2026-08-28T12:00:01Z",
        "finished_at": "2026-08-28T12:00:02Z",
        "jobs_started": 1,
        "conclusion": scenario,
        "normal_cancel_receipt": None,
        "force_cancel_receipt": None,
        "cleanup_record": {
            "registration_removed": True,
            "workspace_removed": True,
            "token_removed": True,
            "container_removed": True,
            "allocation_removed": True,
            "cleanup_digest": "5" * 64,
        },
        "garm_inventory_post": {"remaining": 0, "inventory_digest": "6" * 64},
        "incus_inventory_post": {"remaining": 0, "inventory_digest": "7" * 64},
        "github_inventory_post": {"remaining": 0, "inventory_digest": "8" * 64},
        "proof_digest": "9" * 64,
    }
    return value


class Dispatch:
    def __init__(self, private, driver, scenario="success"):
        self.private = private
        self.driver = driver
        self.scenario = scenario
        self.reboot_cancelled = False
        self.value = payload()
        self.value["issued_at"] = NOW.isoformat().replace("+00:00", "Z")
        self.value["expires_at"] = (NOW + timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        )

    def reservation(self, scenario):
        self.scenario = scenario
        value = reservation(allocation_id=self.value["allocation_id"])
        value["issued_at"] = self.value["issued_at"]
        value["expires_at"] = self.value["expires_at"]
        self.value["scale_set_name"] = value["scale_set_name"]
        self.value["labels"] = value["labels"]
        return value

    def dispatch_and_observe(self, scenario, runner_label):
        envelope = sign_allocation(self.value, self.private, now=NOW)
        context = JobStartedContext.from_mapping(
            {
                "repository_id": self.value["repository_id"],
                "repository": self.value["repository"],
                "dispatch_sha": self.value["dispatch_sha"],
                "tested_sha": self.value["tested_sha"],
                "workflow_ref": self.value["workflow_ref"],
                "run_id": self.value["run_id"],
                "run_attempt": self.value["run_attempt"],
                "job_name": self.value["job_name"],
                "runner_name": self.driver.runner_name,
                "scale_set_name": runner_label,
            }
        )
        return envelope, context

    def await_terminal(self, scenario, context):
        return scenario

    def await_runner_claim(self, broker, allocation_id, context):
        broker.job_started(allocation_id, context, now=NOW)

    def proof_evidence(self, runner_label):
        normal = None
        force = None
        if self.scenario in {"cancel", "force-cancel"}:
            normal = {
                "operation_id": "normal-cancel",
                "observed_at": "2026-08-28T12:00:01Z",
                "receipt_digest": "a" * 64,
            }
        if self.reboot_cancelled:
            normal = {
                "operation_id": "reboot-cancel",
                "observed_at": (NOW + timedelta(seconds=2)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "receipt_digest": "c" * 64,
            }
        if self.scenario == "force-cancel":
            force = {
                "operation_id": "force-cancel",
                "observed_at": "2026-08-28T12:00:02Z",
                "receipt_digest": "b" * 64,
            }
        return {
            "run_id": int(self.value["run_id"]),
            "run_attempt": self.value["run_attempt"],
            "job_id": int(self.value["job_id"]),
            "runner_name": self.driver.runner_name,
            "started_at": (NOW + timedelta(seconds=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "finished_at": (NOW + timedelta(seconds=2)).isoformat().replace(
                "+00:00", "Z"
            ),
            "runner_claimed": True,
            "normal_cancel_receipt": normal,
            "force_cancel_receipt": force,
        }

    def github_inventory(self, runner_label):
        return {"remaining": 0, "inventory_digest": "0" * 64}

    def reboot_host(self, allocation_id):
        self.reboot_cancelled = True
        raise CanaryRebootRequired(
            allocation_id, self.value["scale_set_name"], self.proof_evidence(self.value["scale_set_name"])
        )

    def resume_reboot_evidence(self, evidence):
        return {
            **evidence,
            "finished_at": (NOW + timedelta(seconds=3)).isoformat().replace(
                "+00:00", "Z"
            ),
        }


class CanaryFakeGarm(FakeGarm):
    def canary_runtime_inventory(self):
        return {"garm": list(self.scales.values()), "incus": []}


class FakeRunner:
    def __init__(self, active=()):
        self.active = set(active)

    def run(self, argv, *, timeout=60):
        if tuple(argv[:2]) == ("systemctl", "is-active"):
            unit = argv[2]
            return CommandResult(
                0 if unit in self.active else 3,
                "active\n" if unit in self.active else "inactive\n",
                "",
            )
        return CommandResult(0, "", "")


class CanaryStateStoreTests(unittest.TestCase):
    def test_matrix_state_and_proofs_are_durable_and_resume_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            initialized = store.initialize("b" * 64, "boot-one")
            self.assertEqual("authorized", initialized["state"])
            resumed = store.initialize("b" * 64, "boot-one")
            self.assertEqual(initialized, resumed)
            for scenario in SCENARIOS:
                store.proof(scenario, proof_record(scenario))
            self.assertEqual(
                set(SCENARIOS),
                {path.stem for path in store.proof_root.glob("*.json")},
            )

    def test_nonce_cannot_resume_across_boot_or_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            with self.assertRaisesRegex(CanaryRuntimeError, "cannot resume"):
                store.initialize("c" * 64, "boot-one")
            with self.assertRaisesRegex(CanaryRuntimeError, "cannot resume"):
                store.initialize("b" * 64, "boot-two")

    def test_only_in_progress_reboot_may_resume_on_a_new_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            store.transition(
                "running",
                current_scenario="reboot",
                completed_scenarios=list(SCENARIOS[:-1]),
            )
            resumed = store.initialize("b" * 64, "boot-two")
            self.assertEqual("boot-two", resumed["boot_id"])
            self.assertEqual("boot-one", resumed["rebooted_from_boot_id"])

    def test_signed_allocation_budget_is_durable_across_nonces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, scenario in enumerate(SCENARIOS):
                signed = sign_canary_authorization(
                    canary_authorization(nonce=f"{index + 1:032x}"), CANARY_PRIVATE
                )
                store = CanaryStateStore(root, signed["nonce"])
                store.initialize(authorization_digest(signed), "boot-one")
                store.consume_allocation(signed, scenario)
            replay = sign_canary_authorization(
                canary_authorization(nonce="f" * 32), CANARY_PRIVATE
            )
            replay_store = CanaryStateStore(root, replay["nonce"])
            replay_store.initialize(authorization_digest(replay), "boot-one")
            with self.assertRaisesRegex(CanaryRuntimeError, "budget is exhausted"):
                replay_store.consume_allocation(replay, "success")

    def test_failed_quarantined_clean_matrix_is_not_replayable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            store.transition("failed-quarantined-clean", runtime_empty=True)
            with self.assertRaisesRegex(CanaryRuntimeError, "cannot resume"):
                store.initialize("b" * 64, "boot-one")

    def test_reboot_checkpoint_resumes_exact_allocation_after_new_boot(self):
        class Driver:
            def __init__(self):
                self.resumed = None

            def run(self, scenario):
                raise CanaryRebootRequired(
                    "allocation-reboot", "wsl-jit-" + "c" * 32, {"seed": True}
                )

            def resume_reboot(self, allocation_id, runner_label, evidence):
                self.resumed = (allocation_id, runner_label)
                value = proof_record("reboot")
                value["allocation_id"] = "12345678-1234-4123-8123-123456789abc"
                value["scale_set_name"] = runner_label
                return value

        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            store.transition("ready", completed_scenarios=list(SCENARIOS[:-1]))
            runtime = CanaryRuntime({}, AUTH)
            driver = Driver()
            with self.assertRaises(CanaryRebootRequired):
                runtime.run_matrix(store, driver)
            state = store.load()
            self.assertEqual("allocation-reboot", state["reboot_allocation_id"])
            store.initialize("b" * 64, "boot-two")
            runtime.run_matrix(store, driver)
            self.assertEqual(
                ("allocation-reboot", "wsl-jit-" + "c" * 32), driver.resumed
            )
            self.assertEqual(list(SCENARIOS), store.load()["completed_scenarios"])

    def test_proof_rejects_wrong_outcome_or_unclean_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            base = proof_record("success")
            base["conclusion"] = "failure"
            with self.assertRaisesRegex(CanaryRuntimeError, "crossed"):
                store.proof("success", base)
            base["conclusion"] = "success"
            base["cleanup_record"]["allocation_removed"] = False
            with self.assertRaisesRegex(CanaryRuntimeError, "cleanup"):
                store.proof("success", base)

    def test_reboot_proof_requires_exactly_one_started_job(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CanaryStateStore(Path(directory), "a" * 32)
            store.initialize("b" * 64, "boot-one")
            proof = proof_record("reboot")
            proof["jobs_started"] = 0
            with self.assertRaisesRegex(CanaryRuntimeError, "one-job lifecycle"):
                store.proof("reboot", proof)


class BrokerCanaryDriverTests(unittest.TestCase):
    def test_driver_uses_real_broker_lifecycle_and_proves_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            private = ed25519.Ed25519PrivateKey.generate()
            garm = CanaryFakeGarm()
            broker = AllocationBroker(
                SqliteAllocationLedger(Path(directory) / "ledger.sqlite3"),
                garm,
                private.public_key(),
                spki_fingerprint(private.public_key()),
                FakeLiveJobVerifier(),
            )
            proof = BrokerCanaryScenarioDriver(
                broker, Dispatch(private, garm), AUTH
            ).run("success")
            self.assertEqual("success", proof["conclusion"])
            self.assertEqual(1, proof["jobs_started"])
            self.assertEqual(0, proof["garm_inventory_post"]["remaining"])
            self.assertEqual({}, garm.scales)
            _PROOF_MODULE._validate_proof(
                proof, AUTH, authorization_digest(AUTH)
            )

    def test_all_nonreboot_scenarios_emit_builder_valid_rich_proofs(self):
        for scenario in SCENARIOS[:-1]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                private = ed25519.Ed25519PrivateKey.generate()
                garm = CanaryFakeGarm()
                broker = AllocationBroker(
                    SqliteAllocationLedger(Path(directory) / "ledger.sqlite3"),
                    garm,
                    private.public_key(),
                    spki_fingerprint(private.public_key()),
                    FakeLiveJobVerifier(),
                )
                proof = BrokerCanaryScenarioDriver(
                    broker, Dispatch(private, garm, scenario), AUTH
                ).run(scenario)
                _PROOF_MODULE._validate_proof(
                    proof, AUTH, authorization_digest(AUTH)
                )

    def test_reboot_claims_real_job_then_proves_active_runner_cleanup_after_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            private = ed25519.Ed25519PrivateKey.generate()
            garm = CanaryFakeGarm()
            broker = AllocationBroker(
                SqliteAllocationLedger(Path(directory) / "ledger.sqlite3"),
                garm,
                private.public_key(),
                spki_fingerprint(private.public_key()),
                FakeLiveJobVerifier(),
            )
            driver = BrokerCanaryScenarioDriver(
                broker, Dispatch(private, garm, "reboot"), AUTH
            )
            with self.assertRaises(CanaryRebootRequired) as raised:
                driver.run("reboot")
            checkpoint = raised.exception
            record = broker.ledger.get(checkpoint.allocation_id)
            self.assertEqual("running", record.state)
            self.assertEqual(1, record.jobs_started)
            self.assertTrue(checkpoint.evidence["runner_claimed"])
            self.assertIn("enable", garm.events)
            self.assertIn("claim", garm.events)
            broker.recover(checkpoint.allocation_id)
            proof = driver.resume_reboot(
                checkpoint.allocation_id,
                checkpoint.runner_label,
                checkpoint.evidence,
            )
            _PROOF_MODULE._validate_proof(
                proof, AUTH, authorization_digest(AUTH)
            )
            self.assertEqual(1, proof["jobs_started"])
            self.assertEqual({}, garm.scales)

    def test_proof_fails_closed_without_live_runtime_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            private = ed25519.Ed25519PrivateKey.generate()
            garm = FakeGarm()
            broker = AllocationBroker(
                SqliteAllocationLedger(Path(directory) / "ledger.sqlite3"),
                garm,
                private.public_key(),
                spki_fingerprint(private.public_key()),
                FakeLiveJobVerifier(),
            )
            with self.assertRaisesRegex(
                CanaryRuntimeError, "inventory is not measurable"
            ):
                BrokerCanaryScenarioDriver(
                    broker, Dispatch(private, garm), AUTH
                ).run("success")

    def test_proof_fails_closed_without_live_job_timestamps(self):
        class MissingTimestamps(Dispatch):
            def proof_evidence(self, runner_label):
                value = dict(super().proof_evidence(runner_label))
                value.pop("started_at")
                value.pop("finished_at")
                return value

        with tempfile.TemporaryDirectory() as directory:
            private = ed25519.Ed25519PrivateKey.generate()
            garm = CanaryFakeGarm()
            broker = AllocationBroker(
                SqliteAllocationLedger(Path(directory) / "ledger.sqlite3"),
                garm,
                private.public_key(),
                spki_fingerprint(private.public_key()),
                FakeLiveJobVerifier(),
            )
            with self.assertRaisesRegex(CanaryRuntimeError, "timestamps are absent"):
                BrokerCanaryScenarioDriver(
                    broker, MissingTimestamps(private, garm), AUTH
                ).run("success")


class LiveCanaryDispatchAdapterTests(unittest.TestCase):
    def test_target_revalidation_accepts_omitted_merge_sha_but_not_drift(self):
        adapter = LiveCanaryDispatchAdapter.__new__(LiveCanaryDispatchAdapter)
        adapter.authorization = {
            "repository_id": 1,
            "repository": "x/y",
            "pull_request": 2,
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "tested_merge_sha": "c" * 40,
        }
        adapter.authority = SimpleNamespace(workflow_path=".github/workflows/canary.yml")

        class Client:
            merge_sha = None
            def repository(self, token):
                return {"id": 1, "full_name": "x/y"}
            def pull_request(self, number, token):
                return {
                    "number": 2, "state": "open", "head": {"sha": "a" * 40},
                    "base": {"sha": "b" * 40}, "merge_commit_sha": self.merge_sha,
                }
            def workflow(self, token):
                return {"path": ".github/workflows/canary.yml", "state": "active"}

        adapter.client = Client()
        adapter._revalidate_target(object())
        adapter.client.merge_sha = "d" * 40
        with self.assertRaisesRegex(CanaryRuntimeError, "crossed authorization"):
            adapter._revalidate_target(object())

    def test_reservation_never_exceeds_the_five_minute_allocation_contract(self):
        adapter = LiveCanaryDispatchAdapter.__new__(LiveCanaryDispatchAdapter)
        adapter.authorization = {
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "garm_entity": {
                "authority_kind": "personal-repository",
                "runner_group": None,
            },
            "repository_id": 1,
            "repository": "x/y",
            "head_sha": "a" * 40,
            "workflow_ref": "x/y/.github/workflows/canary.yml@refs/heads/main",
            "image_fingerprint": "b" * 64,
        }
        adapter._reservation = None
        reservation_value = adapter.reservation("success")
        issued = datetime.fromisoformat(reservation_value["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(reservation_value["expires_at"].replace("Z", "+00:00"))
        self.assertEqual(timedelta(minutes=5), expires - issued)

    def test_github_runner_inventory_pages_until_total_count(self):
        class Transport:
            def __init__(self):
                self.pages = []

            def request(self, method, url, *, headers, json_body=None):
                page = int(url.rsplit("page=", 1)[1])
                self.pages.append(page)
                runners = [
                    {"id": page * 1000 + index, "name": f"other-{page}-{index}", "labels": []}
                    for index in range(100 if page == 1 else 1)
                ]
                if page == 2:
                    runners[0] = {
                        "id": 2000,
                        "name": "claimed-runner",
                        "labels": [{"name": "canary-label"}],
                    }
                return HTTPResponse(
                    200,
                    json.dumps({"total_count": 101, "runners": runners}).encode(),
                )

        adapter = LiveCanaryDispatchAdapter.__new__(LiveCanaryDispatchAdapter)
        adapter.authority = SimpleNamespace(repository="x/y")
        adapter.client = SimpleNamespace(
            authenticate=lambda: SimpleNamespace(value="token")
        )
        adapter.transport = Transport()
        adapter._observed = {"runner_name": "claimed-runner"}
        with self.assertRaisesRegex(CanaryRuntimeError, "survived cleanup"):
            adapter.github_inventory("canary-label")
        self.assertEqual([1, 2], adapter.transport.pages)


class ProductionFenceTests(unittest.TestCase):
    def test_fence_rejects_active_canary_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(CanaryRuntimeError, "unit is active"):
                assert_production_fence(
                    state_root=Path(directory),
                    canary_sentinel=Path(directory) / "sentinel",
                    runner=FakeRunner({CANARY_UNITS[0]}),
                )

    def test_fence_rejects_nonterminal_or_unclean_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / ("a" * 32) / "state.json"
            state.parent.mkdir()
            state.write_text(
                json.dumps({"state": "teardown", "runtime_empty": False}) + "\n"
            )
            with self.assertRaisesRegex(CanaryRuntimeError, "nonterminal"):
                assert_production_fence(
                    state_root=Path(directory),
                    canary_sentinel=Path(directory) / "sentinel",
                    runner=FakeRunner(),
                )

    def test_fence_accepts_only_terminal_runtime_empty_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / ("a" * 32) / "state.json"
            state.parent.mkdir()
            state.write_text(
                json.dumps({"state": "terminal", "runtime_empty": True}) + "\n"
            )
            assert_production_fence(
                state_root=Path(directory),
                canary_sentinel=Path(directory) / "sentinel",
                runner=FakeRunner(),
            )

    def test_fence_accepts_failed_matrix_only_after_verified_clean_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / ("a" * 32) / "state.json"
            state.parent.mkdir()
            state.write_text(
                json.dumps(
                    {"state": "failed-quarantined-clean", "runtime_empty": True}
                )
                + "\n"
            )
            assert_production_fence(
                state_root=Path(directory),
                canary_sentinel=Path(directory) / "sentinel",
                runner=FakeRunner(),
            )


class CanarySystemdTests(unittest.TestCase):
    def test_canary_units_are_static_and_never_depend_on_production_activation(self):
        root = Path(__file__).resolve().parents[2] / "packaging/systemd"
        for name in (
            "self-hosted-ci-canary.target",
            "self-hosted-ci-canary-network-policy.service",
            "self-hosted-ci-canary-egress-proxy.service",
            "self-hosted-ci-canary-garm.service",
            "self-hosted-ci-canary-broker.service",
            "self-hosted-ci-canary-cleanup.service",
        ):
            source = (root / name).read_text()
            self.assertNotIn("[Install]", source)
            self.assertNotIn("ACTIVATION_APPROVED", source)
            self.assertNotIn("outbound-worker.runtime-ready", source)
            self.assertNotIn("self-hosted-ci-outbound-worker.service", source)

    def test_quarantine_is_the_only_enabled_unit_and_precedes_incus(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "packaging/systemd/self-hosted-ci-network-quarantine.service"
        ).read_text()
        self.assertIn("Before=incus.service", source)
        self.assertIn("apply-runner-network-policy.sh quarantine", source)
        self.assertIn("[Install]", source)
        self.assertIn("WantedBy=multi-user.target", source)

    def test_canary_policy_quarantines_on_stop(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "packaging/systemd/self-hosted-ci-canary-network-policy.service"
        ).read_text()
        self.assertIn("ExecStartPost=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh verify", source)
        self.assertIn("ExecStop=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh quarantine", source)


if __name__ == "__main__":
    unittest.main()
