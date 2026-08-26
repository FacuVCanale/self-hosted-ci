from __future__ import annotations

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from github_automation.authority_boundary import decide_authority_loss
from github_automation.gatestore import (
    ConflictError,
    ControlFailure,
    FencedError,
    GateStore,
    ReplayError,
)


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class ScenarioGapClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "gate.db"
        self.t0 = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
        self.clock = Clock(self.t0)
        self.store = GateStore(self.db, clock=self.clock)
        self.store.observe_head("repo-1", 7, "a" * 40)
        self.gate = self.store.acquire(
            logical_key="repo-1:7:head:ci-gate", head_generation=1,
            base_sha="b" * 40, tested_merge_sha="c" * 40,
            owner="run-10/1", check_run_id=9001, lease_ttl=timedelta(hours=2),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def admission(self):
        return self.store.create_local_admission_after_pre_marker_verify(
            logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
            lease_epoch=1,
            verifier_decision={"valid": True, "boundary": "pre-marker", "decision_id": "v1"},
            authority={"attestation_id": "att-1", "envelope_digest": "d" * 64,
                       "nonce_hash": "n" * 64, "manifest_generation": 1, "key_id": "online"},
            child_run_id=101, child_job_id=202, tested_merge_sha="c" * 40,
            canonical_command_digest="e" * 64, wrapper_digest="f" * 64,
            execution_deadline=self.t0 + timedelta(minutes=40),
        )

    def failure(self, admission, *, store=None):
        target = store or self.store
        return target.complete_local_failure_if_current(
            logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
            lease_epoch=1, admission_id=admission.admission_id,
            admission_digest=admission.admission_digest,
            evidence={"kind": "FUNCTIONAL_FAILURE", "conclusion": "failure", "exit_code": 1},
            terminal_at=self.t0 + timedelta(minutes=5), child_run_id=101, child_job_id=202,
            tested_merge_sha="c" * 40, canonical_command_digest="e" * 64,
        )

    def success(self, admission, *, store=None, expiry=None):
        target = store or self.store
        return target.complete_local_success_if_authorized(
            logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
            lease_epoch=1, admission_id=admission.admission_id,
            admission_digest=admission.admission_digest,
            evidence={"kind": "SUCCESS", "conclusion": "success"},
            attestation_valid=True,
            attestation_expires_at=expiry or self.t0 + timedelta(minutes=30),
        )

    def test_s70_head_drift_routes_before_admission_and_fences_after(self) -> None:
        before = decide_authority_loss(boundary="dispatch", admission_exists=False, reason="head_drift")
        self.assertTrue(before.route_github)
        self.assertFalse(before.fence_allocation)
        self.assertFalse(before.allow_success)
        after = decide_authority_loss(boundary="local-success", admission_exists=True, reason="head_drift")
        self.assertTrue(after.fence_allocation and after.cancel_allocation)
        self.assertTrue(after.allow_historical_failure)
        self.assertFalse(after.allow_success)

    def assert_drift_is_failure_only(self, reason: str) -> None:
        admission = self.admission()
        decision = decide_authority_loss(
            boundary="local-success", admission_exists=True, reason=reason
        )
        self.assertEqual((True, True, True, False), (
            decision.fence_allocation, decision.cancel_allocation,
            decision.allow_historical_failure, decision.allow_success,
        ))
        self.clock.value = self.t0 + timedelta(minutes=20)
        self.assertEqual("functional_failure", self.failure(admission).result_kind)
        with self.assertRaises((ConflictError, FencedError)):
            self.success(admission)

    def test_s72_effective_writer_inventory_drift_is_failure_only_after_admission(self) -> None:
        self.assert_drift_is_failure_only("inventory_drift")

    def test_s73_writer_revocation_is_failure_only_after_admission(self) -> None:
        self.assert_drift_is_failure_only("writer_revoked")

    def test_s75_team_membership_drift_is_failure_only_after_admission(self) -> None:
        self.assert_drift_is_failure_only("team_drift")

    def test_s85_unavailable_key_has_no_bypass_routes_github_and_alerts(self) -> None:
        decision = decide_authority_loss(
            boundary="dispatch", admission_exists=False, reason="key_unavailable"
        )
        self.assertTrue(decision.route_github)
        self.assertFalse(decision.allow_success)
        self.assertEqual("signing_authority_unavailable", decision.alert_code)
        self.assertNotIn("password", repr(decision).lower())
        self.assertNotIn("shared_secret", repr(decision).lower())

    def test_s94_unobserved_aba_same_sha_still_cannot_reuse_consumed_nonce(self) -> None:
        binding = {
            "attestation_id": "att-1", "nonce_hash": "nonce-1",
            "logical_key": self.gate.logical_key, "generation": 1,
            "expected_head_generation": 1, "envelope_digest": "d" * 64,
            "target": {"repository": "o/r", "pr": 7, "head": "a" * 40},
        }
        self.assertEqual("bound", self.store.bind_attestation_nonce(**binding))
        self.assertEqual(1, self.store.observe_head("repo-1", 7, "a" * 40))
        second = self.store.acquire(
            logical_key=self.gate.logical_key, head_generation=1,
            base_sha="9" * 40, tested_merge_sha="8" * 40,
            owner=self.gate.owner, check_run_id=9001,
        )
        self.assertEqual(2, second.generation)
        with self.assertRaises(ReplayError):
            self.store.bind_attestation_nonce(**(binding | {"generation": 2}))

    def test_s95_local_success_t_minus_one_commits_and_github_at_t_loses(self) -> None:
        admission = self.admission()
        self.clock.value = self.t0 + timedelta(minutes=39, seconds=59)
        completion = self.success(admission, expiry=self.t0 + timedelta(minutes=40))
        with self.assertRaises(FencedError):
            self.store.select_github_winner(
                logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
                lease_epoch=1, reason="deadline",
            )
        self.assertEqual("local", self.store.get_gate(self.gate.logical_key, 1).winner)
        self.assertEqual(1, len(self.store.pending_outbox()))
        self.assertEqual(completion.outbox_key, self.store.pending_outbox()[0]["outbox_key"])

    def test_s96_github_at_t_fences_late_local_success_and_has_no_local_outbox(self) -> None:
        admission = self.admission()
        self.clock.value = self.t0 + timedelta(minutes=40)
        self.assertEqual("selected", self.store.select_github_winner(
            logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
            lease_epoch=1, reason="deadline",
        ))
        with self.assertRaises(FencedError):
            self.success(admission, expiry=self.t0 + timedelta(minutes=40))
        self.assertEqual("github", self.store.get_gate(self.gate.logical_key, 1).winner)
        self.assertEqual([], self.store.pending_outbox())

    def test_s97_simultaneous_success_and_github_has_one_stable_winner_outbox(self) -> None:
        admission = self.admission()
        self.clock.value = self.t0 + timedelta(minutes=39, seconds=59)
        barrier = threading.Barrier(2)
        other = GateStore(self.db, clock=self.clock)
        def local():
            barrier.wait()
            try:
                return self.success(admission).winner
            except FencedError:
                return "fenced"
        def hosted():
            barrier.wait()
            try:
                other.select_github_winner(logical_key=self.gate.logical_key, generation=1,
                    owner=self.gate.owner, lease_epoch=1, reason="deadline")
                return "github"
            except FencedError:
                return "fenced"
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(local), pool.submit(hosted))
            results = {future.result() for future in futures}
        gate = self.store.get_gate(self.gate.logical_key, 1)
        self.assertIn(gate.winner, {"local", "github"})
        self.assertIn("fenced", results)
        self.assertLessEqual(len(self.store.pending_outbox()), 1)

    def test_s98_crashes_inside_success_transaction_never_leave_partial_state(self) -> None:
        admission = self.admission()
        for stage in ("after_winner", "after_terminal", "after_outbox"):
            with self.subTest(stage=stage):
                alternate_db = Path(self.temp.name) / f"{stage}.db"
                clock = Clock(self.t0)
                base = GateStore(alternate_db, clock=clock)
                base.observe_head("repo-1", 7, "a" * 40)
                gate = base.acquire(logical_key=self.gate.logical_key, head_generation=1,
                    base_sha="b" * 40, tested_merge_sha="c" * 40,
                    owner=self.gate.owner, check_run_id=9001)
                adm = base.create_local_admission_after_pre_marker_verify(
                    logical_key=gate.logical_key, generation=1, owner=gate.owner, lease_epoch=1,
                    verifier_decision={"valid": True, "boundary": "pre-marker"},
                    authority={"attestation_id": "a"}, child_run_id=101, child_job_id=202,
                    tested_merge_sha="c" * 40, canonical_command_digest="e" * 64,
                    wrapper_digest="f" * 64, execution_deadline=self.t0 + timedelta(minutes=40))
                def crash(current, expected=stage):
                    if current == expected:
                        raise RuntimeError("crash")
                crashing = GateStore(alternate_db, clock=clock, fault_hook=crash)
                with self.assertRaises(RuntimeError):
                    crashing.complete_local_success_if_authorized(
                        logical_key=gate.logical_key, generation=1, owner=gate.owner, lease_epoch=1,
                        admission_id=adm.admission_id, admission_digest=adm.admission_digest,
                        evidence={"conclusion": "success"}, attestation_valid=True,
                        attestation_expires_at=self.t0 + timedelta(minutes=1))
                observed = base.get_gate(gate.logical_key, 1)
                self.assertIsNone(observed.winner)
                self.assertIsNone(observed.result_kind)
                self.assertEqual([], base.pending_outbox())

    def test_s101_current_failure_requires_exact_admitted_execution(self) -> None:
        admission = self.admission()
        with self.assertRaises(ControlFailure):
            self.store.complete_local_failure_if_current(
                logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
                lease_epoch=1, admission_id=admission.admission_id,
                admission_digest=admission.admission_digest,
                evidence={"kind": "FUNCTIONAL_FAILURE", "conclusion": "failure"},
                terminal_at=self.t0, child_run_id=999, child_job_id=202,
                tested_merge_sha="c" * 40, canonical_command_digest="e" * 64)
        self.assertIsNone(self.store.get_gate(self.gate.logical_key, 1).winner)
        self.assertEqual([], self.store.pending_outbox())

    def test_s102_historical_admission_after_drift_is_failure_only(self) -> None:
        admission = self.admission()
        self.clock.value = self.t0 + timedelta(minutes=20)
        self.assertEqual("functional_failure", self.failure(admission).result_kind)
        with self.assertRaises((ConflictError, FencedError)):
            self.success(admission, expiry=self.t0 + timedelta(minutes=10))

    def test_s104_failure_retry_rejects_success_shaped_evidence(self) -> None:
        admission = self.admission()
        first = self.failure(admission)
        self.assertEqual("idempotent", self.failure(admission).status)
        with self.assertRaises(ControlFailure):
            self.store.complete_local_failure_if_current(
                logical_key=self.gate.logical_key, generation=1, owner=self.gate.owner,
                lease_epoch=1, admission_id=admission.admission_id,
                admission_digest=admission.admission_digest,
                evidence={"kind": "FUNCTIONAL_FAILURE", "conclusion": "success"},
                terminal_at=self.t0, child_run_id=101, child_job_id=202,
                tested_merge_sha="c" * 40, canonical_command_digest="e" * 64)
        self.assertEqual(first.outbox_key, self.store.pending_outbox()[0]["outbox_key"])

    def test_s103_failure_first_keeps_winner_and_outbox_immutable(self) -> None:
        admission = self.admission()
        failure = self.failure(admission)
        with self.assertRaises(FencedError):
            self.store.select_github_winner(logical_key=self.gate.logical_key, generation=1,
                owner=self.gate.owner, lease_epoch=1, reason="timeout")
        self.assertEqual("local", self.store.get_gate(self.gate.logical_key, 1).winner)
        self.assertEqual(failure.outbox_key, self.store.pending_outbox()[0]["outbox_key"])

    def test_s107_timeout_first_keeps_winner_and_outbox_immutable_against_late_failure(self) -> None:
        second_db = Path(self.temp.name) / "timeout-first.db"
        second = GateStore(second_db, clock=self.clock)
        second.observe_head("repo-1", 7, "a" * 40)
        gate = second.acquire(logical_key=self.gate.logical_key, head_generation=1,
            base_sha="b" * 40, tested_merge_sha="c" * 40,
            owner=self.gate.owner, check_run_id=9001, lease_ttl=timedelta(hours=2))
        admission2 = second.create_local_admission_after_pre_marker_verify(
            logical_key=gate.logical_key, generation=1, owner=gate.owner, lease_epoch=1,
            verifier_decision={"valid": True, "boundary": "pre-marker"},
            authority={"attestation_id": "att-2"}, child_run_id=101, child_job_id=202,
            tested_merge_sha="c" * 40, canonical_command_digest="e" * 64,
            wrapper_digest="f" * 64, execution_deadline=self.t0 + timedelta(minutes=40))
        second.select_github_winner(logical_key=gate.logical_key, generation=1,
            owner=gate.owner, lease_epoch=1, reason="timeout")
        with self.assertRaises(FencedError):
            second.complete_local_failure_if_current(
                logical_key=gate.logical_key, generation=1, owner=gate.owner, lease_epoch=1,
                admission_id=admission2.admission_id, admission_digest=admission2.admission_digest,
                evidence={"kind": "FUNCTIONAL_FAILURE", "conclusion": "failure"},
                terminal_at=self.t0, child_run_id=101, child_job_id=202,
                tested_merge_sha="c" * 40, canonical_command_digest="e" * 64)
        self.assertEqual("github", second.get_gate(gate.logical_key, 1).winner)
        self.assertEqual([], second.pending_outbox())

    def test_s108_invalid_each_boundary_without_admission_has_no_mutation(self) -> None:
        for boundary in ("dispatch", "claim", "pre-marker", "local-success"):
            decision = decide_authority_loss(
                boundary=boundary, admission_exists=False, reason="proof_invalid"
            )
            with self.subTest(boundary=boundary):
                self.assertTrue(decision.route_github)
                self.assertFalse(decision.allow_historical_failure)
                self.assertFalse(decision.allow_success)
        self.assertIsNone(self.store.get_admission(self.gate.logical_key, 1))
        self.assertIsNone(self.store.get_gate(self.gate.logical_key, 1).winner)
        self.assertEqual([], self.store.pending_outbox())


if __name__ == "__main__":
    unittest.main()
