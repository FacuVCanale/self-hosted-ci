from __future__ import annotations

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from github_automation.gatestore import (
    ConflictError,
    ControlFailure,
    FencedError,
    GateStore,
    LateEvidence,
    ReplayError,
)


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self.value

    def set(self, value: datetime) -> None:
        with self._lock:
            self.value = value


class GateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "gate.db"
        self.t0 = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
        self.clock = Clock(self.t0)
        self.store = GateStore(self.path, clock=self.clock)
        self.head_generation = self.store.observe_head("repo-1", 7, "a" * 40)
        self.gate = self.store.acquire(
            logical_key="repo-1:7:head:ci-gate",
            head_generation=self.head_generation,
            base_sha="b" * 40,
            tested_merge_sha="c" * 40,
            owner="run-10/1",
            check_run_id=9001,
            lease_ttl=timedelta(hours=1),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def admission(
        self, *, store: GateStore | None = None, deadline: datetime | None = None
    ):
        target = store or self.store
        return target.create_local_admission_after_pre_marker_verify(
            logical_key=self.gate.logical_key,
            generation=self.gate.generation,
            owner=self.gate.owner,
            lease_epoch=self.gate.lease_epoch,
            verifier_decision={
                "valid": True,
                "boundary": "pre-marker",
                "decision_id": "verify-1",
            },
            authority={
                "attestation_id": "att-1",
                "envelope_digest": "d" * 64,
                "nonce_hash": "n" * 64,
                "manifest_generation": 4,
                "key_id": "online-2",
            },
            child_run_id=101,
            child_job_id=202,
            tested_merge_sha="c" * 40,
            canonical_command_digest="e" * 64,
            wrapper_digest="f" * 64,
            execution_deadline=deadline or self.t0 + timedelta(minutes=40),
        )

    def success(
        self, admission, *, store: GateStore | None = None, evidence=None, expiry=None
    ):
        target = store or self.store
        return target.complete_local_success_if_authorized(
            logical_key=self.gate.logical_key,
            generation=self.gate.generation,
            owner=self.gate.owner,
            lease_epoch=self.gate.lease_epoch,
            admission_id=admission.admission_id,
            admission_digest=admission.admission_digest,
            evidence=evidence
            or {"conclusion": "success", "run_id": 101, "job_id": 202},
            attestation_valid=True,
            attestation_expires_at=expiry or self.t0 + timedelta(minutes=10),
        )

    def failure(
        self,
        admission,
        *,
        store: GateStore | None = None,
        evidence=None,
        terminal_at=None,
    ):
        target = store or self.store
        return target.complete_local_failure_if_current(
            logical_key=self.gate.logical_key,
            generation=self.gate.generation,
            owner=self.gate.owner,
            lease_epoch=self.gate.lease_epoch,
            admission_id=admission.admission_id,
            admission_digest=admission.admission_digest,
            evidence=evidence
            or {"kind": "FUNCTIONAL_FAILURE", "conclusion": "failure", "exit_code": 1},
            terminal_at=terminal_at or self.t0 + timedelta(minutes=5),
            child_run_id=101,
            child_job_id=202,
            tested_merge_sha="c" * 40,
            canonical_command_digest="e" * 64,
        )

    def test_s77_observed_aba_advances_head_generation_and_same_sha_does_not(self) -> None:
        self.assertEqual(1, self.head_generation)
        self.assertEqual(1, self.store.observe_head("repo-1", 7, "a" * 40))
        self.assertEqual(2, self.store.observe_head("repo-1", 7, "z" * 40))
        self.assertEqual(3, self.store.observe_head("repo-1", 7, "a" * 40))

    def test_s80_nonce_binding_is_idempotent_only_for_exact_tuple(self) -> None:
        kwargs: dict[str, Any] = {
            "attestation_id": "att-1",
            "nonce_hash": "nonce-1",
            "logical_key": self.gate.logical_key,
            "generation": 1,
            "expected_head_generation": 1,
            "envelope_digest": "d" * 64,
            "target": {"repository": "o/r", "pr": 7, "head": "a" * 40},
        }
        self.assertEqual("bound", self.store.bind_attestation_nonce(**kwargs))
        self.assertEqual("idempotent", self.store.bind_attestation_nonce(**kwargs))
        with self.assertRaises(ReplayError):
            self.store.bind_attestation_nonce(
                **(kwargs | {"envelope_digest": "e" * 64})
            )
        with self.assertRaises(FencedError):
            self.store.bind_attestation_nonce(
                **(kwargs | {"expected_head_generation": 2})
            )

    def test_s18_same_sha_owner_serializes_and_expired_takeover_fences_old_epoch(
        self,
    ) -> None:
        other = GateStore(self.path, clock=self.clock)
        with self.assertRaises(ConflictError):
            other.acquire(
                logical_key=self.gate.logical_key,
                head_generation=1,
                base_sha="b" * 40,
                tested_merge_sha="c" * 40,
                owner="run-11/1",
                check_run_id=9001,
            )
        self.clock.set(self.t0 + timedelta(hours=1))
        takeover = other.acquire(
            logical_key=self.gate.logical_key,
            head_generation=1,
            base_sha="b" * 40,
            tested_merge_sha="c" * 40,
            owner="run-11/1",
            check_run_id=9001,
        )
        self.assertEqual(2, takeover.lease_epoch)
        with self.assertRaises(FencedError):
            self.store.heartbeat(
                self.gate.logical_key, 1, self.gate.owner, self.gate.lease_epoch
            )

    def test_new_merge_creates_generation_and_fences_previous(self) -> None:
        newer = self.store.acquire(
            logical_key=self.gate.logical_key,
            head_generation=1,
            base_sha="b" * 40,
            tested_merge_sha="d" * 40,
            owner="run-12/1",
            check_run_id=9002,
        )
        self.assertEqual(2, newer.generation)
        with self.assertRaises(FencedError):
            self.store.heartbeat(
                self.gate.logical_key, 1, self.gate.owner, self.gate.lease_epoch
            )

    def test_s66_admission_and_marker_are_atomic_immutable_and_cross_bound(self) -> None:
        admission = self.admission()
        self.assertEqual(admission, self.admission())
        self.assertEqual(64, len(admission.admission_digest))
        self.assertEqual(64, len(admission.marker_digest))
        with self.assertRaises(ConflictError):
            self.store.create_local_admission_after_pre_marker_verify(
                logical_key=self.gate.logical_key,
                generation=1,
                owner=self.gate.owner,
                lease_epoch=1,
                verifier_decision={
                    "valid": True,
                    "boundary": "pre-marker",
                    "decision_id": "verify-2",
                },
                authority={"attestation_id": "forged"},
                child_run_id=101,
                child_job_id=202,
                tested_merge_sha="c" * 40,
                canonical_command_digest="e" * 64,
                wrapper_digest="f" * 64,
                execution_deadline=self.t0 + timedelta(minutes=40),
            )

    def test_invalid_pre_marker_decision_creates_no_admission(self) -> None:
        with self.assertRaises(ControlFailure):
            self.store.create_local_admission_after_pre_marker_verify(
                logical_key=self.gate.logical_key,
                generation=1,
                owner=self.gate.owner,
                lease_epoch=1,
                verifier_decision={"valid": False, "boundary": "pre-marker"},
                authority={},
                child_run_id=101,
                child_job_id=202,
                tested_merge_sha="c" * 40,
                canonical_command_digest="e" * 64,
                wrapper_digest="f" * 64,
                execution_deadline=self.t0 + timedelta(minutes=40),
            )
        self.assertIsNone(self.store.get_admission(self.gate.logical_key, 1))

    def test_s95_local_success_at_t_minus_one_commits_atomic_trio(self) -> None:
        admission = self.admission()
        expiry = self.t0 + timedelta(seconds=1)
        result = self.success(admission, expiry=expiry)
        self.assertEqual("committed", result.status)
        self.clock.set(expiry)
        with self.assertRaises(FencedError):
            self.store.select_github_winner(
                logical_key=self.gate.logical_key,
                generation=1,
                owner=self.gate.owner,
                lease_epoch=1,
                reason="expiry",
            )
        gate = self.store.get_gate(self.gate.logical_key, 1)
        assert gate is not None
        self.assertEqual(("local", "success"), (gate.winner, gate.result_kind))
        self.assertEqual(1, len(self.store.pending_outbox()))

    def test_s96_github_first_fences_expired_local_without_outbox(self) -> None:
        admission = self.admission()
        self.store.select_github_winner(
            logical_key=self.gate.logical_key,
            generation=1,
            owner=self.gate.owner,
            lease_epoch=1,
            reason="expiry",
        )
        with self.assertRaises(FencedError):
            self.success(admission)
        self.assertEqual([], self.store.pending_outbox())

    def test_s97_simultaneous_local_and_github_has_one_stable_winner(self) -> None:
        admission = self.admission()
        barrier = threading.Barrier(2)
        local_store = GateStore(self.path, clock=self.clock)
        github_store = GateStore(self.path, clock=self.clock)

        def local():
            barrier.wait()
            try:
                return self.success(admission, store=local_store).winner
            except FencedError:
                return "fenced"

        def github():
            barrier.wait()
            try:
                github_store.select_github_winner(
                    logical_key=self.gate.logical_key,
                    generation=1,
                    owner=self.gate.owner,
                    lease_epoch=1,
                    reason="race",
                )
                return "github"
            except FencedError:
                return "fenced"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(local), pool.submit(github))
            results = {future.result() for future in futures}
        gate = self.store.get_gate(self.gate.logical_key, 1)
        assert gate is not None
        self.assertIn(gate.winner, {"local", "github"})
        self.assertIn("fenced", results)
        self.assertLessEqual(len(self.store.pending_outbox()), 1)

    def test_s98_crashes_inside_local_completion_rollback_everything(self) -> None:
        admission = self.admission()
        for stage in ("after_winner", "after_terminal", "after_outbox"):
            with self.subTest(stage=stage):

                def crash(current: str, expected=stage) -> None:
                    if current == expected:
                        raise RuntimeError("simulated crash")

                crashing = GateStore(self.path, clock=self.clock, fault_hook=crash)
                with self.assertRaises(RuntimeError):
                    self.success(admission, store=crashing)
                gate = self.store.get_gate(self.gate.logical_key, 1)
                assert gate is not None
                self.assertIsNone(gate.winner)
                self.assertIsNone(gate.result_kind)
                self.assertEqual([], self.store.pending_outbox())

    def test_s99_post_commit_retry_is_idempotent_and_different_evidence_conflicts(
        self,
    ) -> None:
        admission = self.admission()
        first = self.success(admission)
        retry = self.success(admission)
        self.assertEqual("idempotent", retry.status)
        self.assertEqual(first.outbox_key, retry.outbox_key)
        with self.assertRaises(ConflictError):
            self.success(
                admission,
                evidence={"conclusion": "success", "run_id": 101, "attempt": 2},
            )
        self.assertEqual(1, len(self.store.pending_outbox()))

    def test_s100_ambiguous_delivery_readback_is_same_evidence_only(self) -> None:
        admission = self.admission()
        completion = self.success(admission)
        self.store.record_outbox_attempt(completion.outbox_key)
        self.assertEqual(
            "delivered",
            self.store.mark_outbox_delivered(
                completion.outbox_key,
                observed_evidence_digest=completion.evidence_digest,
            ),
        )
        self.assertEqual(
            "idempotent",
            self.store.mark_outbox_delivered(
                completion.outbox_key,
                observed_evidence_digest=completion.evidence_digest,
            ),
        )
        with self.assertRaises(ConflictError):
            self.store.mark_outbox_delivered(
                completion.outbox_key, observed_evidence_digest="0" * 64
            )

    def test_s08_s101_s102_timely_historical_admission_failure_ignores_current_proof(
        self,
    ) -> None:
        admission = self.admission()
        self.clock.set(self.t0 + timedelta(minutes=20))
        completion = self.failure(admission)
        self.assertEqual(
            ("local", "functional_failure"), (completion.winner, completion.result_kind)
        )
        with self.assertRaises((ConflictError, FencedError)):
            self.success(admission, expiry=self.t0 + timedelta(minutes=10))

    def test_s103_failure_and_github_race_has_one_immutable_winner(self) -> None:
        admission = self.admission()
        barrier = threading.Barrier(2)
        failure_store = GateStore(self.path, clock=self.clock)
        github_store = GateStore(self.path, clock=self.clock)

        def failure():
            barrier.wait()
            try:
                return self.failure(admission, store=failure_store).winner
            except FencedError:
                return "fenced"

        def github():
            barrier.wait()
            try:
                github_store.select_github_winner(
                    logical_key=self.gate.logical_key,
                    generation=1,
                    owner=self.gate.owner,
                    lease_epoch=1,
                    reason="timeout",
                )
                return "github"
            except FencedError:
                return "fenced"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(failure), pool.submit(github))
            results = {future.result() for future in futures}
        self.assertIn("fenced", results)
        gate = self.store.get_gate(self.gate.logical_key, 1)
        assert gate is not None
        self.assertIn(gate.winner, {"local", "github"})
        self.assertLessEqual(len(self.store.pending_outbox()), 1)

    def test_s104_failure_retry_same_evidence_is_idempotent_different_conflicts(
        self,
    ) -> None:
        admission = self.admission()
        first = self.failure(admission)
        self.assertEqual("idempotent", self.failure(admission).status)
        self.assertEqual(first.outbox_key, self.failure(admission).outbox_key)
        with self.assertRaises(ConflictError):
            self.failure(
                admission,
                evidence={
                    "kind": "FUNCTIONAL_FAILURE",
                    "conclusion": "failure",
                    "exit_code": 2,
                },
            )

    def test_s105_crash_during_admission_exposes_no_partial_pair(self) -> None:
        for stage in ("after_admission_insert", "after_marker_insert"):
            with self.subTest(stage=stage):

                def crash(current: str, expected=stage) -> None:
                    if current == expected:
                        raise RuntimeError("simulated crash")

                crashing = GateStore(self.path, clock=self.clock, fault_hook=crash)
                with self.assertRaises(RuntimeError):
                    self.admission(store=crashing)
                self.assertIsNone(self.store.get_admission(self.gate.logical_key, 1))

    def test_s106_deadline_equality_favors_failure_and_d_plus_one_is_late(self) -> None:
        deadline = self.t0 + timedelta(minutes=40)
        admission = self.admission(deadline=deadline)
        completion = self.failure(admission, terminal_at=deadline)
        self.assertEqual("functional_failure", completion.result_kind)

        other_path = Path(self.temp.name) / "late.db"
        late_store = GateStore(other_path, clock=self.clock)
        late_store.observe_head("repo-1", 7, "a" * 40)
        self.gate = late_store.acquire(
            logical_key=self.gate.logical_key,
            head_generation=1,
            base_sha="b" * 40,
            tested_merge_sha="c" * 40,
            owner=self.gate.owner,
            check_run_id=9001,
        )
        late_admission = self.admission(store=late_store, deadline=deadline)
        with self.assertRaises(LateEvidence):
            self.failure(
                late_admission,
                store=late_store,
                terminal_at=deadline + timedelta(microseconds=1),
            )
        gate = late_store.get_gate(self.gate.logical_key, 1)
        assert gate is not None
        self.assertIsNone(gate.winner)

    def test_s108_missing_or_forged_admission_never_authorizes_result(self) -> None:
        with self.assertRaises(ControlFailure):
            self.store.complete_local_failure_if_current(
                logical_key=self.gate.logical_key,
                generation=1,
                owner=self.gate.owner,
                lease_epoch=1,
                admission_id="forged",
                admission_digest="0" * 64,
                evidence={"kind": "FUNCTIONAL_FAILURE", "conclusion": "failure"},
                terminal_at=self.t0,
                child_run_id=101,
                child_job_id=202,
                tested_merge_sha="c" * 40,
                canonical_command_digest="e" * 64,
            )
        gate = self.store.get_gate(self.gate.logical_key, 1)
        assert gate is not None
        self.assertIsNone(gate.winner)
        self.assertEqual([], self.store.pending_outbox())


if __name__ == "__main__":
    unittest.main()
