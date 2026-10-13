from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

from github_automation.github import ObservedWorkflowJob
from github_automation.gatestore import GateStore
from github_automation.local_approval import (
    LocalApprovalStore,
    PilotWorkRequestBuilder,
    ResolvedApprovalTarget,
)
from github_automation.outbound_worker import OutboundWorker, PilotWorker, WorkerState, WorkerError
from github_automation.runner_jit import RunnerJitError
from tests.github_automation.test_outbound_worker_host_cli import load, WORKER_CLI
from github_automation.pilot_checks import GateCheckError
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
        self.outcomes = []
        self.timeline = []
        self.active_allocations = set()

    def reserve(self, value):
        self.calls.append(("reserve", value["allocation_id"]))
        self.active_allocations.add(value["allocation_id"])
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
        self.timeline.append("recover")
        self.active_allocations.discard(allocation_id)
        return {"allocation_id": allocation_id, "state": "absent"}

    def finish(self, allocation_id, outcome):
        self.calls.append(("finish", allocation_id, outcome))
        self.timeline.append("finish")
        self.active_allocations.discard(allocation_id)

    def prove_clean(self, allocation_id, runner_label):
        self.calls.append(("prove-clean", allocation_id))
        return {
            "allocation_id": allocation_id,
            "runner_label": runner_label,
            "state": "cleaned",
            "scale_set_absent": True,
            "runtime_empty": True,
        }

    def record_outcome(self, value):
        self.outcomes.append(value)
        self.timeline.append("record-outcome")
        return {"recorded": True}


class GitHub:
    def __init__(self):
        self.dispatches = 0
        self.cancelled = []

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

    def cancel_exact_run(self, run_id):
        self.cancelled.append(run_id)


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


class RecordingPublisher:
    """Stands in for the gate App and records every publication decision."""

    def __init__(self):
        self.started = []
        self.concluded = []
        self.abandoned = []
        self.discarded = []

    def start(self, *, head_sha, details_url):
        self.started.append((head_sha, "/actions/runs/" in details_url))
        return {"backend lint + test": 1, "frontend lint + test": 2}

    def conclude(self, *, checks, job_id, job_conclusion, details_url):
        self.concluded.append((dict(checks), job_id, job_conclusion))
        return {}

    def abandon(self, *, checks, reason, details_url):
        self.abandoned.append(reason)
        return {}

    def discard(self, *, checks, reason, details_url):
        self.discarded.append((dict(checks), reason))
        return {name: "skipped" for name in checks}

    def publish_discarded(self, *, head_sha, reason, details_url, **_resume):
        self.discarded.append(({"head_sha": head_sha}, reason))
        return {
            "backend lint + test": "skipped",
            "frontend lint + test": "skipped",
        }


class OutboundWorkerTests(unittest.TestCase):
    def test_pilot_mints_claim_deadline_after_nine_minute_job_observation(self):
        class Clock:
            now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

            def __call__(self):
                return self.now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123", repository, pr, "a" * 40, "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40, "c" * 40,
                )

        class DelayedGitHub(GitHub):
            def observe_exact_job(self, run_id, label):
                clock.now += timedelta(minutes=9)
                self.label = label
                return super().observe_exact_job(run_id, label)

        class CapturingBroker(Broker):
            payload = None

            def finalize(self, envelope):
                self.payload = envelope["payload"]
                return super().finalize(envelope)

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
            source.approve("example-owner/example-repo", 42)
            broker = CapturingBroker()
            result = PilotWorker(
                WorkerState(root / "worker.sqlite3"),
                source,
                broker,
                DelayedGitHub(),
                Signer(),
            ).run_once()

            self.assertEqual("completed", result["status"])
            self.assertEqual("2026-08-27T12:04:00Z", broker.payload["approval_expires_at"])
            self.assertEqual("2026-08-27T12:09:00Z", broker.payload["issued_at"])
            self.assertEqual("2026-08-27T12:21:00Z", broker.payload["claim_deadline"])

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
        # Automatic dispatch is an outbound poll of one opted-in repository, and
        # the plan must say so rather than claim there is no polling at all.
        self.assertEqual(
            value["automatic_pr_polling"], "opt-in-outbound-poll-of-one-repository"
        )
        self.assertEqual(value["approval"], "operator-explicit")

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


    def _pilot_fixture(self, directory, publisher, github=None):
        """One approved pilot assignment wired to a recording Check publisher."""
        now = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

        class Clock:
            def __call__(self):
                return now

        class Resolver:
            def resolve(self, repository, pr):
                return ResolvedApprovalTarget(
                    "123", repository, pr, "a" * 40, "main",
                    f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                    "b" * 40, "c" * 40,
                )

        root = Path(directory)
        clock = Clock()
        source = LocalApprovalStore(
            root / "approvals.sqlite3",
            GateStore(root / "gate.sqlite3", clock=clock),
            Resolver(),
            PilotWorkRequestBuilder("d" * 64),
            clock=clock,
        )
        source.approve("example-owner/example-repo", 42)
        state = WorkerState(root / "worker.sqlite3")
        github = github or GitHub()
        # The fake job only reports the label the observation captured, exactly
        # as the live client does.
        github.label = ""
        original_observe = github.observe_exact_job

        def observe(run_id, label):
            github.label = label
            return original_observe(run_id, label)

        github.observe_exact_job = observe
        worker = PilotWorker(
            state, source, Broker(), github, Signer(),
            checks=publisher, repository="example-owner/example-repo",
        )
        return worker, state, source

    def test_recovered_expired_allocation_closes_checks_and_is_terminal(self):
        for dispatched in (False, True):
            with self.subTest(dispatched=dispatched), tempfile.TemporaryDirectory() as directory:
                publisher = RecordingPublisher()
                worker, state, source = self._pilot_fixture(directory, publisher)
                request = source.poll()
                key = request["request_id"]
                source.claim(key, request, lease_seconds=7200)
                state.claim(key, request)
                progress = {"reserved": worker.broker.reserve(request["reservation"]),
                            "checks": {"backend lint + test": 1}}
                if dispatched:
                    progress["run_id"] = 444
                state.record(key, "reserved", **progress)
                state.recover_running()
                now = source.clock()
                source.clock = lambda: now + timedelta(minutes=5)

                result = worker.run_once()

                reason = "the local allocation expired before the run started"
                self.assertEqual("failed", result["status"])
                self.assertTrue(result["reason"].startswith(reason))
                self.assertEqual([reason], publisher.abandoned)
                self.assertEqual(0, worker.github.dispatches)
                self.assertEqual([("reserve", request["reservation"]["allocation_id"]),
                                  ("recover", request["reservation"]["allocation_id"])], worker.broker.calls)
                self.assertEqual("allocation-expired", state.progress(key)["phase"])
                self.assertEqual("failed", source.status()[0]["state"])
                self.assertIsNone(state.recoverable())
                self.assertEqual("failed", state.claim(key, request))
                self.assertEqual({"status": "idle"}, worker.run_once())
                if dispatched:
                    self.assertIn("cancellation is unavailable", result["reason"])

                cli = load(WORKER_CLI, "worker_terminal_status_test")
                output = StringIO()
                with patch.object(cli, "runtime", return_value=({}, source, worker, None)), redirect_stdout(output):
                    self.assertEqual(0, cli.main(["status"]))
                terminal = json.loads(output.getvalue())["terminal_assignments"][0]
                self.assertEqual(key, terminal["request_id"])
                self.assertEqual(result["reason"], terminal["reason"])
                self.assertEqual("allocation-expired", terminal["phase"])

    def test_serve_isolates_assignment_errors_and_processes_next_approval(self):
        class StopLoop(Exception):
            pass

        for error in (WorkerError, RunnerJitError, GateCheckError, OSError):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                worker, state, source = self._pilot_fixture(directory, RecordingPublisher())
                first = source.poll()
                source.claim(first["request_id"], first, lease_seconds=7200)
                state.claim(first["request_id"], first)
                state.record(first["request_id"], "claimed")
                second = source.approve("example-owner/example-repo", 43)
                original_reserve = worker.broker.reserve
                calls = []

                def reserve(value):
                    calls.append(value["allocation_id"])
                    if len(calls) == 1:
                        raise error("broken assignment")
                    return original_reserve(value)

                worker.broker.reserve = reserve
                cli = load(WORKER_CLI, "worker_serve_isolation_test")
                stderr = StringIO()
                with patch.object(cli, "runtime", return_value=({"poll_seconds": 1}, source, worker, None)), patch.object(cli.time, "sleep", side_effect=[None, StopLoop()]), redirect_stderr(stderr):
                    with self.assertRaises(StopLoop):
                        cli.main(["serve"])
                self.assertIn(f"assignment failed: {error.__name__}", stderr.getvalue())
                self.assertEqual(2, len(calls))
                self.assertEqual(1, worker.github.dispatches)
                self.assertEqual("completed", next(row for row in source.status() if row["request_id"] == second["request_id"])["state"])
                self.assertEqual(1, len(state.terminals()))
                self.assertIsNone(state.recoverable())
                self.assertEqual({"status": "idle"}, worker.run_once())

    def test_published_checks_target_the_pull_request_head_and_close_green(self):
        publisher = RecordingPublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, _state, _source = self._pilot_fixture(directory, publisher)
            result = worker.run_once()
        self.assertEqual("completed", result["status"])
        # "a" * 40 is the approval's PR head, not the default branch dispatch ref.
        self.assertEqual(publisher.started, [("a" * 40, True)])
        self.assertEqual(len(publisher.concluded), 1)
        self.assertEqual(publisher.abandoned, [])

    def test_new_head_cancels_only_the_exact_old_run_and_cleans_its_allocation(self):
        publisher = RecordingPublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(directory, publisher)
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    None
                    if checks["count"] == 1
                    else "a newer commit superseded this pull request head"
                )

            source.supersession_reason = supersession
            first = worker.run_once()
            current = source.clock()
            source.clock = lambda: current + timedelta(seconds=15)
            result = worker.run_once()
            request = json.loads(
                state.db.execute("SELECT request FROM requests").fetchone()[0]
            )

        allocation_id = request["reservation"]["allocation_id"]
        self.assertEqual("pending", first["status"])
        self.assertEqual("cancelled", result["status"])
        self.assertEqual([444], worker.github.cancelled)
        self.assertEqual(
            [("finish", allocation_id, "success"), ("prove-clean", allocation_id)],
            [
                call
                for call in worker.broker.calls
                if call[0] in {"finish", "prove-clean"}
            ],
        )
        self.assertEqual(1, len(publisher.discarded))
        self.assertEqual("superseded-head", worker.broker.outcomes[-1]["cause_code"])
        self.assertLess(
            worker.broker.timeline.index("record-outcome"),
            worker.broker.timeline.index("finish"),
        )
        self.assertIn("newer commit", publisher.discarded[0][1])

    def test_base_moved_before_admission_cancels_without_dispatch_or_allocation(self):
        publisher = RecordingPublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, _state, source = self._pilot_fixture(directory, publisher)
            source.resolver.resolve = lambda repository, pr: ResolvedApprovalTarget(
                "123",
                repository,
                pr,
                "a" * 40,
                "main",
                f"{repository}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
                "d" * 40,
                "e" * 40,
            )
            result = worker.run_once()

        self.assertEqual("cancelled", result["status"])
        self.assertEqual(0, worker.github.dispatches)
        self.assertEqual([], worker.github.cancelled)
        self.assertEqual([], worker.broker.calls)
        self.assertEqual(1, len(publisher.discarded))

    def test_preallocation_discard_retries_the_same_check_run_ids(self):
        class RetryPublisher(RecordingPublisher):
            def __init__(self):
                super().__init__()
                self.created = []
                self.fail_once = True

            def publish_discarded(self, **value):
                for name in ("backend lint + test", "frontend lint + test"):
                    if name in value["completed"]:
                        continue
                    identifier = value["checks"].get(name)
                    if identifier is None:
                        identifier = 100 + len(self.created)
                        self.created.append(name)
                        value["record_pending"](name)
                        value["record_created"](name, identifier)
                    if self.fail_once:
                        self.fail_once = False
                        raise GateCheckError("transient Check Run failure")
                    value["record_completed"](name)
                return {name: "skipped" for name in value["completed"]}

        publisher = RetryPublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, _state, source = self._pilot_fixture(directory, publisher)
            source.supersession_reason = lambda _key, _request: "the base moved"
            first = worker.run_once()
            second = worker.run_once()

        self.assertEqual("retry", first["status"])
        self.assertEqual("cancelled", second["status"])
        self.assertEqual(
            ["backend lint + test", "frontend lint + test"], publisher.created
        )

    def test_supersession_after_admission_waits_for_cancelled_then_proves_clean(self):
        class CancellingGitHub(GitHub):
            cancelled_state = False

            def cancel_exact_run(self, run_id):
                super().cancel_exact_run(run_id)
                self.cancelled_state = True

            def run(self, run_id):
                return {
                    "id": run_id,
                    "status": "completed" if self.cancelled_state else "in_progress",
                    "conclusion": "cancelled" if self.cancelled_state else None,
                }

            def jobs(self, run_id):
                return {
                    "jobs": [
                        {
                            "id": 555,
                            "run_id": run_id,
                            "name": "local-quality",
                            "labels": ["self-hosted", self.label],
                            "status": (
                                "completed" if self.cancelled_state else "in_progress"
                            ),
                            "conclusion": (
                                "cancelled" if self.cancelled_state else None
                            ),
                        }
                    ]
                }

        publisher = RecordingPublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, _state, source = self._pilot_fixture(
                directory, publisher, github=CancellingGitHub()
            )
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            first = worker.run_once()
            now = source.clock()
            source.clock = lambda: now + timedelta(seconds=15)
            result = worker.run_once()

        self.assertEqual("pending", first["status"])
        self.assertEqual("cancelled", result["status"])
        self.assertEqual("cancel", result["outcome"])
        self.assertEqual([444], worker.github.cancelled)
        self.assertEqual(
            ["finish", "prove-clean"],
            [call[0] for call in worker.broker.calls if call[0] in {"finish", "prove-clean"}],
        )
        self.assertEqual(1, len(publisher.discarded))
        self.assertEqual("superseded-head", worker.broker.outcomes[-1]["cause_code"])
        self.assertIsNone(worker.broker.outcomes[-1]["prior_ledger_state"])
        self.assertFalse(worker.broker.outcomes[-1]["executed"])
        self.assertLess(
            worker.broker.timeline.index("record-outcome"),
            worker.broker.timeline.index("finish"),
        )

    def test_slow_supersession_is_durable_and_records_one_nonexecuted_outcome(self):
        class SlowCancellationGitHub(GitHub):
            polls = 0

            def run(self, run_id):
                self.polls += 1
                terminal = self.polls > 6
                return {
                    "id": run_id,
                    "status": "completed" if terminal else "in_progress",
                    "conclusion": "cancelled" if terminal else None,
                }

            def jobs(self, run_id):
                terminal = self.polls > 6
                return {
                    "jobs": [{
                        "id": 555, "run_id": run_id, "name": "local-quality",
                        "labels": ["self-hosted", self.label],
                        "status": "completed" if terminal else "in_progress",
                        "conclusion": "cancelled" if terminal else None,
                    }]
                }

        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(
                directory, RecordingPublisher(), github=SlowCancellationGitHub()
            )
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            other_allocation = "87654321-4321-4123-8123-cba987654321"
            worker.broker.active_allocations.add(other_allocation)
            current = source.clock()
            results = [worker.run_once()]
            request_id = state.db.execute("SELECT id FROM requests").fetchone()[0]
            first_progress = state.progress(request_id)
            state.close()
            reopened = WorkerState(Path(directory) / "worker.sqlite3")
            worker.state = reopened
            # Six read cycles at 15 seconds exceed the old 30-second timeout,
            # but stay within the new 180-second durable convergence window.
            for step in range(1, 7):
                source.clock = lambda step=step: current + timedelta(seconds=15 * step)
                results.append(worker.run_once())
                self.assertIn(other_allocation, worker.broker.active_allocations)

            progress = reopened.progress(request_id)

        self.assertTrue(all(item["status"] == "pending" for item in results[:-1]))
        self.assertEqual("cancelled", results[-1]["status"])
        self.assertEqual(1, len(worker.github.cancelled))
        self.assertEqual(
            ["superseded-head"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )
        self.assertFalse(worker.broker.outcomes[0]["executed"])
        self.assertNotIn("worker-error", [event["cause_code"] for event in worker.broker.outcomes])
        self.assertEqual("cancel-requested", first_progress["phase"])
        self.assertEqual(first_progress["cancel_deadline"], progress["cancel_deadline"])
        allocation = worker.broker.outcomes[0]["allocation_id"]
        self.assertFalse(any(call[1] != allocation for call in worker.broker.calls if call[0] == "recover"))

    def test_cancel_timeout_recovers_exact_allocation_without_raising(self):
        class NeverConvergesGitHub(GitHub):
            def run(self, run_id):
                return {"id": run_id, "status": "in_progress", "conclusion": None}

            def jobs(self, run_id):
                return {"jobs": [{
                    "id": 555, "run_id": run_id, "name": "local-quality",
                    "labels": ["self-hosted", self.label],
                    "status": "in_progress", "conclusion": None,
                }]}

        with tempfile.TemporaryDirectory() as directory:
            worker, _state, source = self._pilot_fixture(
                directory, RecordingPublisher(), github=NeverConvergesGitHub()
            )
            worker.cancel_convergence_timeout = timedelta(seconds=30)
            worker.cancel_convergence_poll = timedelta(seconds=10)
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            current = source.clock()
            first = worker.run_once()
            source.clock = lambda: current + timedelta(seconds=10)
            second = worker.run_once()
            source.clock = lambda: current + timedelta(seconds=31)
            result = worker.run_once()

        self.assertEqual(("pending", "pending", "failed"), (
            first["status"], second["status"], result["status"]
        ))
        self.assertEqual(
            ["cancel-not-converged"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )
        allocation = worker.broker.outcomes[0]["allocation_id"]
        self.assertIn(("recover", allocation), worker.broker.calls)
        self.assertNotIn("worker-error", [event["cause_code"] for event in worker.broker.outcomes])

    def test_cancel_timeout_recovery_is_absorbing_and_never_reclassified(self):
        class LaterConvergesGitHub(GitHub):
            polls = 0

            def run(self, run_id):
                self.polls += 1
                terminal = self.polls > 2
                return {
                    "id": run_id,
                    "status": "completed" if terminal else "in_progress",
                    "conclusion": "cancelled" if terminal else None,
                }

            def jobs(self, run_id):
                terminal = self.polls > 2
                return {"jobs": [{
                    "id": 555, "run_id": run_id, "name": "local-quality",
                    "labels": ["self-hosted", self.label],
                    "status": "completed" if terminal else "in_progress",
                    "conclusion": "cancelled" if terminal else None,
                }]}

        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(
                directory, RecordingPublisher(), github=LaterConvergesGitHub()
            )
            worker.cancel_convergence_timeout = timedelta(seconds=30)
            worker.cancel_convergence_poll = timedelta(seconds=10)
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            current = source.clock()
            self.assertEqual("pending", worker.run_once()["status"])
            request_id = state.db.execute("SELECT id FROM requests").fetchone()[0]
            source.clock = lambda: current + timedelta(seconds=31)
            original_recover = worker.broker.recover
            recover_attempts = {"count": 0}

            def fail_once(allocation_id):
                recover_attempts["count"] += 1
                if recover_attempts["count"] == 1:
                    raise RunnerJitError("transient recovery failure")
                return original_recover(allocation_id)

            worker.broker.recover = fail_once
            self.assertEqual("retry", worker.run_once()["status"])
            polls_at_timeout = worker.github.polls
            self.assertEqual(
                "cancel-recovery-pending",
                state.progress(request_id)["phase"],
            )
            result = worker.run_once()

        self.assertEqual("failed", result["status"])
        self.assertEqual(polls_at_timeout, worker.github.polls)
        self.assertEqual(2, recover_attempts["count"])
        self.assertEqual(
            ["cancel-not-converged"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )

    def test_cancel_timeout_recovers_before_retrying_transient_check_closure(self):
        class NeverConvergesGitHub(GitHub):
            def run(self, run_id):
                return {"id": run_id, "status": "in_progress", "conclusion": None}

            def jobs(self, run_id):
                return {"jobs": [{
                    "id": 555, "run_id": run_id, "name": "local-quality",
                    "labels": ["self-hosted", self.label],
                    "status": "in_progress", "conclusion": None,
                }]}

        class FailsOncePublisher(RecordingPublisher):
            def __init__(self):
                super().__init__()
                self.close_attempts = 0

            def abandon(self, **value):
                self.close_attempts += 1
                if self.close_attempts == 1:
                    raise GateCheckError("transient close failure")
                return super().abandon(**value)

        publisher = FailsOncePublisher()
        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(
                directory, publisher, github=NeverConvergesGitHub()
            )
            worker.cancel_convergence_timeout = timedelta(seconds=30)
            worker.cancel_convergence_poll = timedelta(seconds=10)
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            current = source.clock()
            self.assertEqual("pending", worker.run_once()["status"])
            source.clock = lambda: current + timedelta(seconds=31)
            first_timeout = worker.run_once()
            request_id = state.db.execute("SELECT id FROM requests").fetchone()[0]
            progress = state.progress(request_id)
            recovery_calls = [call for call in worker.broker.calls if call[0] == "recover"]
            result = worker.run_once()

        self.assertEqual("retry", first_timeout["status"])
        self.assertTrue(progress["cancel_recovery_complete"])
        self.assertEqual(1, len(recovery_calls))
        self.assertEqual("failed", result["status"])
        self.assertEqual(2, publisher.close_attempts)
        self.assertEqual(
            ["cancel-not-converged"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )
        self.assertEqual(
            1,
            len([call for call in worker.broker.calls if call[0] == "recover"]),
        )

    def test_cancel_timeout_retries_outcome_before_recovery(self):
        class NeverConvergesGitHub(GitHub):
            def run(self, run_id):
                return {"id": run_id, "status": "in_progress", "conclusion": None}

            def jobs(self, run_id):
                return {"jobs": [{
                    "id": 555, "run_id": run_id, "name": "local-quality",
                    "labels": ["self-hosted", self.label],
                    "status": "in_progress", "conclusion": None,
                }]}

        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(
                directory, RecordingPublisher(), github=NeverConvergesGitHub()
            )
            worker.cancel_convergence_timeout = timedelta(seconds=30)
            worker.cancel_convergence_poll = timedelta(seconds=10)
            checks = {"count": 0}

            def supersession(_key, _request):
                checks["count"] += 1
                return (
                    "a newer commit superseded this pull request head"
                    if checks["count"] >= 3
                    else None
                )

            source.supersession_reason = supersession
            current = source.clock()
            self.assertEqual("pending", worker.run_once()["status"])
            original_record = worker.broker.record_outcome
            attempts = {"count": 0}

            def fail_once(event):
                attempts["count"] += 1
                if attempts["count"] == 1:
                    raise RunnerJitError("transient outcome failure")
                return original_record(event)

            worker.broker.record_outcome = fail_once
            source.clock = lambda: current + timedelta(seconds=31)
            first_timeout = worker.run_once()
            request_id = state.db.execute("SELECT id FROM requests").fetchone()[0]
            progress = state.progress(request_id)
            self.assertEqual([], [call for call in worker.broker.calls if call[0] == "recover"])
            result = worker.run_once()

        self.assertEqual("retry", first_timeout["status"])
        self.assertEqual("cancel-timeout-recording", progress["phase"])
        self.assertEqual("failed", result["status"])
        self.assertEqual(2, attempts["count"])
        self.assertEqual(
            ["cancel-not-converged"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )
        self.assertEqual(
            1,
            len([call for call in worker.broker.calls if call[0] == "recover"]),
        )

    def test_supersession_resumes_after_crash_between_dispatch_and_observation(self):
        class CrashAfterDispatchGitHub(GitHub):
            def observe_exact_job(self, run_id, label):
                self.label = label
                raise SystemExit("simulated process death after dispatch receipt")

            def run(self, run_id):
                return {"id": run_id, "status": "completed", "conclusion": "cancelled"}

            def jobs(self, run_id):
                return {"jobs": []}

        with tempfile.TemporaryDirectory() as directory:
            worker, state, source = self._pilot_fixture(
                directory, RecordingPublisher(), github=CrashAfterDispatchGitHub()
            )
            with self.assertRaisesRegex(SystemExit, "simulated process death"):
                worker.run_once()
            request_id = state.db.execute("SELECT id FROM requests").fetchone()[0]
            self.assertEqual("dispatched", state.progress(request_id)["phase"])
            self.assertIsNone(state.progress(request_id).get("job_id"))
            state.close()

            reopened = WorkerState(Path(directory) / "worker.sqlite3")
            self.assertEqual(1, reopened.recover_running())
            worker.state = reopened
            source.supersession_reason = lambda _key, _request: (
                "a newer commit superseded this pull request head"
            )
            current = source.clock()
            first = worker.run_once()
            source.clock = lambda: current + timedelta(seconds=15)
            result = worker.run_once()

        self.assertEqual("pending", first["status"])
        self.assertEqual("cancelled", result["status"])
        self.assertIsNone(result["job_id"])
        self.assertEqual([444], worker.github.cancelled)
        self.assertEqual(
            ["superseded-head"],
            [event["cause_code"] for event in worker.broker.outcomes],
        )
        allocation = worker.broker.outcomes[0]["allocation_id"]
        self.assertIn(("recover", allocation), worker.broker.calls)

    def test_a_lost_run_closes_its_checks_instead_of_hanging_in_progress(self):
        publisher = RecordingPublisher()

        class LosesTheRun(GitHub):
            def run(self, run_id):
                raise RuntimeError("the host lost the run")

        with tempfile.TemporaryDirectory() as directory:
            worker, _state, _source = self._pilot_fixture(
                directory, publisher, github=LosesTheRun()
            )
            with self.assertRaisesRegex(RuntimeError, "lost the run"):
                worker.run_once()
        self.assertEqual(len(publisher.started), 1)
        self.assertEqual(len(publisher.abandoned), 1)
        self.assertIn("RuntimeError", publisher.abandoned[0])

    def test_a_resumed_attempt_never_opens_a_second_pair_of_checks(self):
        publisher = RecordingPublisher()

        class FailsOnce(GitHub):
            def __init__(self):
                super().__init__()
                self.runs = 0

            def run(self, run_id):
                self.runs += 1
                if self.runs == 1:
                    raise RuntimeError("transient GitHub failure")
                return super().run(run_id)

        with tempfile.TemporaryDirectory() as directory:
            worker, _state, _source = self._pilot_fixture(
                directory, publisher, github=FailsOnce()
            )
            with self.assertRaisesRegex(RuntimeError, "transient"):
                worker.run_once()
            worker.run_once()
        self.assertEqual(len(publisher.started), 1)

    def test_a_check_publication_failure_never_fails_a_valid_local_run(self):
        class Broken(RecordingPublisher):
            def start(self, *, head_sha, details_url):
                raise GateCheckError("gate key is unavailable")

        publisher = Broken()
        with tempfile.TemporaryDirectory() as directory:
            worker, _state, _source = self._pilot_fixture(directory, publisher)
            result = worker.run_once()
        self.assertEqual("completed", result["status"])
        self.assertEqual(publisher.concluded, [])

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

            self.assertEqual({"status": "failed", "reason": "the local allocation expired before the run started"}, result)
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

    def test_finalized_pilot_resumes_after_package_ttl_without_recovery(self):
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
            self.assertEqual(
                "acquired",
                state.claim(approved["request_id"], request, lease_seconds=7200),
            )
            allocation_id = request["reservation"]["allocation_id"]
            state.record(
                approved["request_id"],
                "finalized",
                run_id=444,
                job_id=555,
                reserved={
                    "allocation_id": allocation_id,
                    "scale_set_id": "9",
                    "runner_label": request["pilot_package"]["runner_label"],
                    "state": "reserved-disabled",
                },
                observed={
                    "run_id": 444,
                    "run_attempt": 1,
                    "job_id": 555,
                    "job_name": "local-quality",
                    "dispatch_sha": "f" * 40,
                },
                finalized={
                    "allocation_id": allocation_id,
                    "state": "enabled-awaiting-claim",
                },
            )
            self.assertEqual(1, state.recover_running())
            clock.now += timedelta(minutes=5)
            broker = Broker()
            github = GitHub()
            github.label = request["pilot_package"]["runner_label"]

            result = PilotWorker(state, source, broker, github, Signer()).run_once()

            self.assertEqual("completed", result["status"])
            self.assertEqual(0, github.dispatches)
            self.assertEqual(
                ["finish", "prove-clean"],
                [call[0] for call in broker.calls],
            )
            self.assertEqual("completed", source.status()[0]["state"])

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

    def test_pre_dispatch_cleanup_failure_is_terminal_without_dispatch(self):
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
                    raise OSError("broker unavailable during cleanup")
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
            with self.assertRaises(WorkerError):
                worker.run_once()
            self.assertEqual({"status": "idle"}, worker.run_once())
            self.assertIn("cleanup failed: OSError", state.terminals()[0]["reason"])
            self.assertEqual(0, github.dispatches)
            self.assertEqual("failed", source.status()[0]["state"])


if __name__ == "__main__":
    unittest.main()
