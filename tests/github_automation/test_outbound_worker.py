from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from github_automation.github import ObservedWorkflowJob
from github_automation.gatestore import GateStore
from github_automation.local_approval import (
    LocalApprovalStore,
    PilotWorkRequestBuilder,
    ResolvedApprovalTarget,
)
from github_automation.outbound_worker import OutboundWorker, PilotWorker, WorkerState
from tests.github_automation.test_github_contracts import protocol
from tests.github_automation.test_runner_jit import reservation


class Source:
    def __init__(self, request):
        self.request = request
        self.completed = []
        self.failed = []

    def poll(self):
        return self.request

    def claim(self, request_id, request, *, lease_seconds):
        pass

    def resume(self, request_id, request, *, lease_seconds):
        return request

    def retry(self, request_id, reason):
        self.failed.append((request_id, "retry:" + reason))

    def complete(self, request_id, result):
        self.completed.append((request_id, result))

    def fail(self, request_id, reason):
        self.failed.append((request_id, reason))


class Broker:
    def __init__(self):
        self.calls = []

    def reserve(self, value):
        self.calls.append(("reserve", value["allocation_id"]))
        return {
            "allocation_id": value["allocation_id"],
            "scale_set_id": "9",
            "runner_label": value["scale_set_name"],
            "state": "reserved-disabled",
        }

    def finalize(self, envelope):
        self.calls.append(("finalize", envelope["payload"]["job_id"]))
        return {
            "allocation_id": envelope["payload"]["allocation_id"],
            "state": "enabled-awaiting-claim",
        }

    def recover(self, allocation_id):
        self.calls.append(("recover", allocation_id))
        return {"allocation_id": allocation_id, "state": "absent"}

    def finish(self, allocation_id, outcome):
        self.calls.append(("finish", allocation_id, outcome))

    def prove_clean(self, allocation_id, runner_label):
        self.calls.append(("prove-clean", allocation_id))
        return {
            "allocation_id": allocation_id,
            "runner_label": runner_label,
            "state": "cleaned",
            "scale_set_absent": True,
            "runtime_empty": True,
        }


class GitHub:
    def __init__(self):
        self.dispatches = 0

    def dispatch_package(self, package):
        self.dispatches += 1
        return 444

    def observe_exact_job(self, run_id, label):
        return ObservedWorkflowJob(run_id, 1, 555, "local-quality", "f" * 40)

    def run(self, run_id):
        return {"id": run_id, "status": "completed", "conclusion": "success"}

    def jobs(self, run_id):
        return {
            "jobs": [
                {
                    "id": 555,
                    "run_id": run_id,
                    "name": "local-quality",
                    "labels": ["self-hosted", self.label],
                    "status": "completed",
                    "conclusion": "success",
                }
            ]
        }


class Signer:
    def sign_allocation(self, payload):
        return {"payload": payload, "signature": "external"}


def work_request():
    allocation = reservation(allocation_id="12345678-1234-4123-8123-123456789abc")
    return {
        "request_id": "request-1",
        "protocol_package": protocol(),
        "reservation": allocation,
    }


class OutboundWorkerTests(unittest.TestCase):
    def test_sqlite_idempotency_is_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            state = WorkerState(path)
            state.begin("r1")
            state.finish("r1", {"status": "dispatched", "run_id": 7})
            self.assertEqual(7, state.done("r1")["run_id"])
            state.db.close()
            reopened = WorkerState(path)
            self.assertEqual(7, reopened.done("r1")["run_id"])

    def test_completion_delivery_is_recoverable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            value = work_request()
            state = WorkerState(Path(directory) / "state.sqlite3")
            source = Source(value)
            state.claim(value["request_id"], value)
            state.finish(value["request_id"], {"status": "dispatched", "run_id": 7})
            result = OutboundWorker(
                state, source, Broker(), GitHub(), Signer()
            ).run_once()
            self.assertEqual(7, result["run_id"])
            self.assertEqual(
                "done", state.db.execute("SELECT state FROM requests").fetchone()[0]
            )

    def test_claim_is_atomic_and_expired_claim_is_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            first = WorkerState(path)
            second = WorkerState(path)
            value = work_request()
            self.assertEqual(
                "acquired",
                first.claim(value["request_id"], value, now=100, lease_seconds=10),
            )
            self.assertEqual(
                "busy",
                second.claim(value["request_id"], value, now=105, lease_seconds=10),
            )
            self.assertEqual(
                "acquired",
                second.claim(value["request_id"], value, now=111, lease_seconds=10),
            )

    def test_persisted_dispatch_receipt_prevents_redispatch_after_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            value = work_request()
            state = WorkerState(Path(directory) / "state.sqlite3")
            self.assertEqual(
                "acquired",
                state.claim(value["request_id"], value, now=100, lease_seconds=1),
            )
            state.record(value["request_id"], "dispatched", run_id=444)
            state.fail(value["request_id"])
            source = Source(value)
            broker = Broker()
            github = GitHub()
            result = OutboundWorker(state, source, broker, github, Signer()).run_once()
            self.assertEqual(
                {"status": "dispatched", "backend": "local", "run_id": 444}, result
            )
            self.assertEqual(0, github.dispatches)
            self.assertEqual(
                1, len([call for call in broker.calls if call[0] == "finalize"])
            )
            self.assertEqual("finalized", state.progress(value["request_id"])["phase"])

    def test_crash_after_dispatch_intent_without_receipt_never_redispatches(self):
        with tempfile.TemporaryDirectory() as directory:
            value = work_request()
            state = WorkerState(Path(directory) / "state.sqlite3")
            self.assertEqual(
                "acquired",
                state.claim(value["request_id"], value, now=100, lease_seconds=1),
            )
            reserved = {
                "allocation_id": value["reservation"]["allocation_id"],
                "scale_set_id": "9",
                "runner_label": value["reservation"]["scale_set_name"],
                "state": "reserved-disabled",
            }
            state.record(value["request_id"], "reserved", reserved=reserved)
            state.record(value["request_id"], "dispatching")
            state.fail(value["request_id"])
            source = Source(value)
            broker = Broker()
            github = GitHub()
            worker = OutboundWorker(state, source, broker, github, Signer())
            with self.assertRaisesRegex(Exception, "ambiguous"):
                worker.run_once()
            self.assertEqual(0, github.dispatches)
            self.assertEqual(
                1, len([call for call in broker.calls if call[0] == "recover"])
            )
            with self.assertRaisesRegex(Exception, "manual reconciliation"):
                worker.run_once()
            self.assertEqual(0, github.dispatches)

    def test_completed_result_is_replayed_without_any_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            value = work_request()
            state = WorkerState(Path(directory) / "state.sqlite3")
            source = Source(value)
            broker = Broker()
            github = GitHub()
            worker = OutboundWorker(state, source, broker, github, Signer())
            first = worker.run_once()
            second = worker.run_once()
            self.assertEqual(first, second)
            self.assertEqual(1, github.dispatches)
            self.assertEqual(
                1, len([call for call in broker.calls if call[0] == "reserve"])
            )
            self.assertEqual(2, len(source.completed))

    def test_cli_plan_has_no_ingress_or_external_relay(self):
        script = (
            Path(__file__).resolve().parents[2]
            / "scripts/host/outbound-coordinator-worker.py"
        )
        result = subprocess.run(
            ["python3", str(script), "plan"], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode)
        value = json.loads(result.stdout)
        self.assertFalse(value["inbound_listener"])
        self.assertFalse(value["external_relay"])
        self.assertFalse(value["automatic_pr_polling"])

    def test_pilot_resumes_durable_post_dispatch_failure_without_redispatch(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = Clock()
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=clock),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=clock,
            )
            approved = source.approve("example-owner/example-repo", 42)
            state = WorkerState(root / "worker.sqlite3")
            broker = Broker()
            github = GitHub()
            github.label = ""
            original_observe = github.observe_exact_job

            def observe(run_id, label):
                github.label = label
                return original_observe(run_id, label)

            github.observe_exact_job = observe
            original_run = github.run
            calls = {"run": 0}

            def fail_once(run_id):
                calls["run"] += 1
                if calls["run"] == 1:
                    raise RuntimeError("transient GitHub failure")
                return original_run(run_id)

            github.run = fail_once
            worker = PilotWorker(state, source, broker, github, Signer())
            with self.assertRaisesRegex(RuntimeError, "transient"):
                worker.run_once()
            self.assertEqual("claimed", source.status()[0]["state"])
            self.assertEqual(
                "retry",
                state.db.execute(
                    "SELECT state FROM requests WHERE id=?", (approved["request_id"],)
                ).fetchone()[0],
            )
            result = worker.run_once()
            self.assertEqual("completed", result["status"])
            self.assertEqual(1, github.dispatches)
            self.assertEqual(
                ["finish", "prove-clean"],
                [
                    call[0]
                    for call in broker.calls
                    if call[0] in {"finish", "prove-clean"}
                ],
            )
            self.assertEqual("completed", source.status()[0]["state"])

    def test_revoked_durable_approval_reconciles_without_crash_loop(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        class FlakyRecoveryBroker(Broker):
            def __init__(self):
                super().__init__()
                self.recoveries = 0

            def recover(self, allocation_id):
                self.recoveries += 1
                if self.recoveries == 1:
                    raise RuntimeError("cleanup temporarily unavailable")
                return super().recover(allocation_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=Clock()),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=Clock(),
            )
            approved = source.approve("example-owner/example-repo", 42)
            state = WorkerState(root / "worker.sqlite3")
            broker = FlakyRecoveryBroker()
            github = GitHub()
            original_observe = github.observe_exact_job

            def observe(run_id, label):
                github.label = label
                return original_observe(run_id, label)

            github.observe_exact_job = observe
            github.run = lambda _run_id: (_ for _ in ()).throw(
                RuntimeError("transient GitHub failure")
            )
            worker = PilotWorker(state, source, broker, github, Signer())
            with self.assertRaisesRegex(RuntimeError, "transient"):
                worker.run_once()
            allocation_id = json.loads(
                state.db.execute(
                    "SELECT request FROM requests WHERE id=?", (approved["request_id"],)
                ).fetchone()[0]
            )["reservation"]["allocation_id"]
            source.revoke("example-owner/example-repo", 42)

            with self.assertRaisesRegex(RuntimeError, "cleanup temporarily"):
                worker.run_once()
            self.assertEqual(
                "retry",
                state.db.execute(
                    "SELECT state FROM requests WHERE id=?", (approved["request_id"],)
                ).fetchone()[0],
            )

            result = worker.run_once()

            self.assertEqual(
                {"status": "failed", "reason": "LocalApprovalError"}, result
            )
            self.assertEqual(
                [("recover", allocation_id)],
                [call for call in broker.calls if call[0] == "recover"],
            )
            self.assertEqual(2, broker.recoveries)
            self.assertEqual(1, github.dispatches)
            self.assertEqual("revoked", source.status()[0]["state"])
            self.assertEqual(
                "failed",
                state.db.execute(
                    "SELECT state FROM requests WHERE id=?", (approved["request_id"],)
                ).fetchone()[0],
            )
            self.assertEqual({"status": "idle"}, worker.run_once())

    def test_expired_pilot_package_reconciles_without_crash_loop(self):
        class Clock:
            now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

            def __call__(self):
                return self.now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = Clock()
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=clock),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=clock,
            )
            approved = source.approve("example-owner/example-repo", 42)
            request = source.poll()
            source.claim(approved["request_id"], request, lease_seconds=7200)
            state = WorkerState(root / "worker.sqlite3")
            state.claim(approved["request_id"], request, lease_seconds=7200)
            broker = Broker()
            state.record(
                approved["request_id"],
                "reserved",
                reserved=broker.reserve(request["reservation"]),
            )
            state.fail(approved["request_id"])
            clock.now += timedelta(minutes=5)
            worker = PilotWorker(state, source, broker, GitHub(), Signer())

            result = worker.run_once()

            self.assertEqual({"status": "failed", "reason": "JitPilotError"}, result)
            self.assertEqual(
                [("recover", request["reservation"]["allocation_id"])],
                [call for call in broker.calls if call[0] == "recover"],
            )
            self.assertEqual("failed", source.status()[0]["state"])
            self.assertEqual({"status": "idle"}, worker.run_once())

    def test_startup_recovers_running_worker_lease_and_claimed_approval(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=Clock()),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=Clock(),
            )
            approved = source.approve("example-owner/example-repo", 42)
            request = source.poll()
            source.claim(approved["request_id"], request, lease_seconds=7200)
            state = WorkerState(root / "worker.sqlite3")
            self.assertEqual(
                "acquired",
                state.claim(approved["request_id"], request, lease_seconds=7200),
            )
            state.record(approved["request_id"], "dispatched", run_id=444)
            self.assertEqual(1, state.recover_running())
            github = GitHub()
            github.label = request["pilot_package"]["runner_label"]
            result = PilotWorker(state, source, Broker(), github, Signer()).run_once()
            self.assertEqual("completed", result["status"])
            self.assertEqual(0, github.dispatches)

    def test_cleanup_proof_failure_retries_finish_without_dispatch_or_finalize(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        class FlakyCleanupBroker(Broker):
            def __init__(self):
                super().__init__()
                self.proofs = 0

            def prove_clean(self, allocation_id, runner_label):
                self.proofs += 1
                if self.proofs == 1:
                    raise RuntimeError("cleanup proof unavailable")
                return super().prove_clean(allocation_id, runner_label)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=Clock()),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=Clock(),
            )
            source.approve("example-owner/example-repo", 42)
            state = WorkerState(root / "worker.sqlite3")
            broker = FlakyCleanupBroker()
            github = GitHub()
            original = github.observe_exact_job

            def observe(run_id, label):
                github.label = label
                return original(run_id, label)

            github.observe_exact_job = observe
            worker = PilotWorker(state, source, broker, github, Signer())
            with self.assertRaisesRegex(RuntimeError, "cleanup proof"):
                worker.run_once()
            result = worker.run_once()
            self.assertEqual("completed", result["status"])
            self.assertEqual(1, github.dispatches)
            self.assertEqual(
                1, len([call for call in broker.calls if call[0] == "finalize"])
            )
            self.assertEqual(
                2, len([call for call in broker.calls if call[0] == "finish"])
            )

    def test_pre_dispatch_cleanup_failure_resumes_cleanup_without_dispatch(self):
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123",
                    repository,
                    pr,
                    "a" * 40,
                    "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40,
                    "c" * 40,
                )

        class BadReserveBroker(Broker):
            def __init__(self):
                super().__init__()
                self.recoveries = 0

            def reserve(self, value):
                receipt = super().reserve(value)
                receipt["runner_label"] = "wsl-jit-" + "0" * 32
                return receipt

            def recover(self, allocation_id):
                self.recoveries += 1
                if self.recoveries == 1:
                    raise RuntimeError("broker unavailable during cleanup")
                return super().recover(allocation_id)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = LocalApprovalStore(
                root / "approvals.sqlite3",
                GateStore(root / "gate.sqlite3", clock=Clock()),
                Resolver(),
                PilotWorkRequestBuilder("d" * 64),
                clock=Clock(),
            )
            source.approve("example-owner/example-repo", 42)
            state = WorkerState(root / "worker.sqlite3")
            broker = BadReserveBroker()
            github = GitHub()
            worker = PilotWorker(state, source, broker, github, Signer())
            with self.assertRaisesRegex(RuntimeError, "cleanup"):
                worker.run_once()
            result = worker.run_once()
            self.assertEqual({"status": "failed", "reason": "WorkerError"}, result)
            self.assertEqual(0, github.dispatches)
            self.assertEqual("failed", source.status()[0]["state"])


if __name__ == "__main__":
    unittest.main()
