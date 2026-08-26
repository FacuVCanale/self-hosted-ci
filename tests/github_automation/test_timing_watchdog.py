from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from github_automation.timing import (
    FailureClass,
    FailureOutcome,
    POLICY_V1,
    api_tolerance_breached,
    claim_is_timely,
    claim_timeout_due,
    classify_failure,
    completion_is_timely,
    execution_timeout_due,
    force_cancel_due,
    force_cancel_verification_due,
    heartbeat_due,
    http_ack_within_target,
    inventory_is_fresh,
    lease_is_valid,
    queue_alert_due,
    queue_dead_letter_due,
    preclaim_fallback_sla_breached,
    total_fallback_sla_breached,
    watchdog_due,
)
from github_automation.watchdog import (
    ActionKind,
    Decision,
    ObservedState,
    execute_decision,
    reconcile,
    reconcile_execution_timeout_after_reread,
)


T = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def state(**changes) -> ObservedState:
    values = dict(
        logical_key="123:42:head:ci-gate",
        generation=7,
        owner="coordinator:900:1",
        lease_epoch=3,
        lease_expires_at=T + timedelta(minutes=5),
        phase="LOCAL_DISPATCHED",
        claim_deadline=T,
    )
    values.update(changes)
    return ObservedState(**values)


class TimingOracleTests(unittest.TestCase):
    def test_policy_v1_exact_values(self) -> None:
        self.assertEqual(1, POLICY_V1.version)
        self.assertEqual(timedelta(seconds=60), POLICY_V1.heartbeat)
        self.assertEqual(timedelta(minutes=5), POLICY_V1.lease_ttl)
        self.assertEqual(timedelta(minutes=10), POLICY_V1.claim_deadline)
        self.assertEqual(timedelta(minutes=40), POLICY_V1.execution_deadline)
        self.assertEqual((timedelta(seconds=2), timedelta(seconds=8), timedelta(seconds=32)), POLICY_V1.dispatch_retry_backoff)
        self.assertLessEqual(POLICY_V1.preclaim_fallback_sla, timedelta(minutes=12))
        self.assertLessEqual(POLICY_V1.total_fallback_gate_sla, timedelta(minutes=100))

    def test_s05_s06_s54_claim_t_minus_one_t_t_plus_one(self) -> None:
        self.assertTrue(claim_is_timely(T - timedelta(seconds=1), T))
        self.assertTrue(claim_is_timely(T, T))
        self.assertFalse(claim_is_timely(T + timedelta(seconds=1), T))
        self.assertFalse(claim_is_timely(None, T))
        self.assertFalse(claim_timeout_due(T, T, timely_claim=False))
        self.assertTrue(claim_timeout_due(T + timedelta(seconds=1), T, timely_claim=False))
        self.assertFalse(claim_timeout_due(T + timedelta(seconds=1), T, timely_claim=True))

    def test_s19_s23_s47_s54_lease_fences_at_equality(self) -> None:
        self.assertTrue(lease_is_valid(T - timedelta(seconds=1), T))
        self.assertFalse(lease_is_valid(T, T))
        self.assertFalse(lease_is_valid(T + timedelta(seconds=1), T))

    def test_s54_force_cancel_queue_and_http_exact_comparators(self) -> None:
        cancel = T
        self.assertFalse(force_cancel_due(T + timedelta(seconds=89), cancel))
        self.assertTrue(force_cancel_due(T + timedelta(seconds=90), cancel))
        self.assertTrue(force_cancel_due(T + timedelta(seconds=91), cancel))
        self.assertFalse(force_cancel_verification_due(T + timedelta(seconds=119), cancel))
        self.assertTrue(force_cancel_verification_due(T + timedelta(seconds=120), cancel))
        self.assertFalse(queue_alert_due(T + timedelta(minutes=9, seconds=59), T))
        self.assertTrue(queue_alert_due(T + timedelta(minutes=10), T))
        self.assertFalse(queue_dead_letter_due(T + timedelta(hours=23, minutes=59), T))
        self.assertTrue(queue_dead_letter_due(T + timedelta(hours=24), T))
        self.assertTrue(http_ack_within_target(timedelta(seconds=9, microseconds=999999), durable_enqueue=True))
        self.assertFalse(http_ack_within_target(timedelta(seconds=10), durable_enqueue=True))
        self.assertFalse(http_ack_within_target(timedelta(seconds=1), durable_enqueue=False))

    def test_s54_heartbeat_watchdog_freshness_tolerance_and_slas(self) -> None:
        before = timedelta(microseconds=1)
        self.assertFalse(heartbeat_due(T + POLICY_V1.heartbeat - before, T))
        self.assertTrue(heartbeat_due(T + POLICY_V1.heartbeat, T))
        self.assertFalse(watchdog_due(T + POLICY_V1.watchdog_interval - before, T))
        self.assertTrue(watchdog_due(T + POLICY_V1.watchdog_interval, T))
        self.assertTrue(inventory_is_fresh(T + POLICY_V1.inventory_freshness, T))
        self.assertFalse(inventory_is_fresh(T + POLICY_V1.inventory_freshness + before, T))
        self.assertFalse(api_tolerance_breached(T + POLICY_V1.api_tolerance, T))
        self.assertTrue(api_tolerance_breached(T + POLICY_V1.api_tolerance + before, T))
        self.assertFalse(preclaim_fallback_sla_breached(T + POLICY_V1.preclaim_fallback_sla, T))
        self.assertTrue(preclaim_fallback_sla_breached(T + POLICY_V1.preclaim_fallback_sla + before, T))
        self.assertFalse(total_fallback_sla_breached(T + POLICY_V1.total_fallback_gate_sla, T))
        self.assertTrue(total_fallback_sla_breached(T + POLICY_V1.total_fallback_gate_sla + before, T))

    def test_s67_s106_completion_equality_precedes_timeout(self) -> None:
        for terminal, expected in ((T - timedelta(seconds=1), True), (T, True), (T + timedelta(seconds=1), False)):
            with self.subTest(terminal=terminal):
                self.assertEqual(expected, completion_is_timely(terminal, T))
        self.assertFalse(execution_timeout_due(T, T, timely_completion=False))
        self.assertTrue(execution_timeout_due(T + timedelta(seconds=1), T, timely_completion=False))
        self.assertFalse(execution_timeout_due(T + timedelta(seconds=1), T, timely_completion=True))

    def test_s09_failure_taxonomy_is_strict_and_fail_closed(self) -> None:
        self.assertEqual(FailureOutcome.LOCAL_FINAL_FAILURE, classify_failure(FailureClass.FUNCTIONAL_FAILURE, admitted=True, terminal_at=T, execution_deadline=T))
        self.assertEqual(FailureOutcome.EVIDENCE_ONLY_FALLBACK, classify_failure(FailureClass.FUNCTIONAL_FAILURE, admitted=True, terminal_at=T + timedelta(seconds=1), execution_deadline=T))
        self.assertEqual(FailureOutcome.BLOCK_ALERT, classify_failure(FailureClass.FUNCTIONAL_FAILURE, admitted=False, terminal_at=T, execution_deadline=T))
        expected = {
            FailureClass.STALE_INPUT: FailureOutcome.STALE_CANCEL,
            FailureClass.INFRA_PRETEST: FailureOutcome.FALLBACK_ONCE,
            FailureClass.INFRA_TRANSPORT_LOSS: FailureOutcome.FALLBACK_ONCE,
            FailureClass.PROTOCOL_FAILURE: FailureOutcome.BLOCK_ALERT,
            FailureClass.CONTROL_FAILURE: FailureOutcome.BLOCK_ALERT,
            FailureClass.FALLBACK_FAILURE: FailureOutcome.FALLBACK_FINAL_FAILURE,
        }
        for failure, outcome in expected.items():
            with self.subTest(failure=failure):
                self.assertEqual(outcome, classify_failure(failure))


class WatchdogTests(unittest.TestCase):
    def test_s107_authoritative_reread_offers_timely_failure_before_timeout_in_both_orders(self) -> None:
        running = state(
            phase="LOCAL_RUNNING",
            execution_deadline=T,
            lease_expires_at=T + timedelta(hours=1),
            admission_valid=True,
        )
        for now in (T + timedelta(seconds=1), T + timedelta(minutes=10)):
            with self.subTest(now=now):
                decision = reconcile_execution_timeout_after_reread(
                    running,
                    now=now,
                    authoritative_terminal_at=T,
                    authoritative_failure_class=FailureClass.FUNCTIONAL_FAILURE,
                )
                self.assertEqual(ActionKind.OFFER_LOCAL_FAILURE, decision.kind)
        timeout = reconcile_execution_timeout_after_reread(
            running,
            now=T + timedelta(seconds=1),
            authoritative_terminal_at=None,
            authoritative_failure_class=None,
        )
        self.assertEqual(ActionKind.SELECT_GITHUB, timeout.kind)

    def test_s05_s06_claim_fallback_only_after_deadline(self) -> None:
        queued = state(job_started_at=None, lease_expires_at=T + timedelta(hours=2))
        self.assertEqual(ActionKind.NOOP, reconcile(queued, now=T).kind)
        decision = reconcile(queued, now=T + timedelta(seconds=1))
        self.assertEqual(ActionKind.SELECT_GITHUB, decision.kind)
        self.assertEqual(decision.idempotency_key, reconcile(queued, now=T + timedelta(hours=1)).idempotency_key)

    def test_s17_duplicate_delivery_has_stable_action_key(self) -> None:
        expired = state(lease_expires_at=T - timedelta(seconds=1))
        first = reconcile(expired, now=T)
        second = reconcile(expired, now=T + timedelta(minutes=1))
        self.assertEqual(ActionKind.TAKE_OVER, first.kind)
        self.assertEqual(first.idempotency_key, second.idempotency_key)

    def test_s19_watchdog_detects_expired_lease_but_not_live_owner(self) -> None:
        self.assertEqual(ActionKind.NOOP, reconcile(state(), now=T).kind)
        self.assertEqual(ActionKind.TAKE_OVER, reconcile(state(lease_expires_at=T), now=T).kind)

    def test_s20_s21_recovery_selects_and_resumes_one_fallback(self) -> None:
        lost = state(phase="LOCAL_RUNNING", execution_deadline=T, lease_expires_at=T + timedelta(hours=1), job_active=True)
        self.assertEqual(ActionKind.SELECT_GITHUB, reconcile(lost, now=T + timedelta(seconds=1)).kind)
        selected = replace(lost, winner="github", job_active=False, fallback_dispatched=False)
        self.assertEqual(ActionKind.DISPATCH_FALLBACK, reconcile(selected, now=T + timedelta(seconds=1)).kind)
        self.assertEqual(ActionKind.NOOP, reconcile(replace(selected, fallback_dispatched=True), now=T + timedelta(seconds=1)).kind)

    def test_s22_ambiguity_blocks_without_inferred_fallback(self) -> None:
        decision = reconcile(state(ambiguous=True), now=T)
        self.assertEqual(ActionKind.BLOCK_ALERT, decision.kind)

    def test_s46_cancel_force_cancel_and_restart_resume(self) -> None:
        selected = state(winner="github", job_active=True, lease_expires_at=T + timedelta(hours=1))
        self.assertEqual(ActionKind.REQUEST_NORMAL_CANCEL, reconcile(selected, now=T).kind)
        cancelling = replace(selected, cancel_requested_at=T)
        self.assertEqual(ActionKind.NOOP, reconcile(cancelling, now=T + timedelta(seconds=89)).kind)
        self.assertEqual(ActionKind.REQUEST_FORCE_CANCEL, reconcile(cancelling, now=T + timedelta(seconds=90)).kind)
        forced = replace(cancelling, force_cancel_requested_at=T + timedelta(seconds=90))
        self.assertEqual(ActionKind.NOOP, reconcile(forced, now=T + timedelta(seconds=209)).kind)
        self.assertEqual(ActionKind.VERIFY_FORCE_CANCEL, reconcile(forced, now=T + timedelta(seconds=210)).kind)
        stopped = replace(forced, job_active=False)
        self.assertEqual(ActionKind.DISPATCH_FALLBACK, reconcile(stopped, now=T + timedelta(seconds=210)).kind)

    def test_s65_control_failure_blocks_and_does_not_infer_fallback(self) -> None:
        decision = reconcile(state(failure_class=FailureClass.CONTROL_FAILURE), now=T)
        self.assertEqual(ActionKind.BLOCK_ALERT, decision.kind)

    def test_s67_s101_s102_s106_historical_failure_and_deadline(self) -> None:
        base = state(
            phase="LOCAL_RUNNING", execution_deadline=T, lease_expires_at=T + timedelta(hours=1),
            failure_class=FailureClass.FUNCTIONAL_FAILURE, admission_valid=True,
            proof_valid=False, authority_boundary=None,
        )
        self.assertEqual(ActionKind.OFFER_LOCAL_FAILURE, reconcile(replace(base, job_terminal_at=T), now=T + timedelta(seconds=1)).kind)
        self.assertEqual(ActionKind.SELECT_GITHUB, reconcile(replace(base, job_terminal_at=T + timedelta(seconds=1)), now=T + timedelta(seconds=2)).kind)
        self.assertEqual(ActionKind.BLOCK_ALERT, reconcile(replace(base, admission_valid=False, job_terminal_at=T), now=T).kind)

    def test_s90_s108_invalid_current_authority_selects_once_but_is_audit_only_after_winner(self) -> None:
        for boundary in ("dispatch", "claim", "pre_marker_admission", "local_success"):
            with self.subTest(boundary=boundary):
                invalid = state(proof_valid=False, authority_boundary=boundary)
                self.assertEqual(ActionKind.SELECT_GITHUB, reconcile(invalid, now=T).kind)
        github_won = state(winner="github", proof_valid=False, authority_boundary="local_success", fallback_dispatched=True)
        self.assertEqual(ActionKind.NOOP, reconcile(github_won, now=T).kind)

    def test_s10_s11_s24_late_local_is_ignored_after_github_winner(self) -> None:
        won = state(winner="github", fallback_dispatched=True, job_active=False)
        for failure in (None, FailureClass.FUNCTIONAL_FAILURE):
            with self.subTest(failure=failure):
                self.assertEqual(ActionKind.NOOP, reconcile(replace(won, failure_class=failure, job_terminal_at=T), now=T).kind)
        failed = replace(won, fallback_terminal=True, failure_class=FailureClass.FALLBACK_FAILURE)
        self.assertEqual(ActionKind.COMPLETE_FALLBACK_FAILURE, reconcile(failed, now=T).kind)

    def test_s47_fencing_and_idempotent_external_effects(self) -> None:
        adapter = FakeAdapter()
        decision = Decision(ActionKind.DISPATCH_FALLBACK, "key", 2, "owner", 3, "resume")
        adapter.owns = False
        self.assertEqual("fenced", execute_decision(decision, adapter))
        self.assertEqual([], adapter.effects)
        adapter.owns = True
        self.assertEqual("performed", execute_decision(decision, adapter))
        self.assertEqual("idempotent", execute_decision(decision, adapter))
        self.assertEqual([decision], adapter.effects)

    def test_s19_takeover_is_an_internal_cas_not_blocked_by_old_lease(self) -> None:
        adapter = FakeAdapter()
        adapter.owns = False
        decision = reconcile(state(lease_expires_at=T), now=T)
        self.assertEqual(ActionKind.TAKE_OVER, decision.kind)
        self.assertEqual("performed", execute_decision(decision, adapter))
        self.assertEqual("idempotent", execute_decision(decision, adapter))

    def test_s47_lease_loss_between_decision_and_effect_has_no_effect(self) -> None:
        adapter = FakeAdapter()
        adapter.owns = False
        decision = reconcile(state(winner="github", job_active=False, fallback_dispatched=False), now=T)
        self.assertEqual(ActionKind.DISPATCH_FALLBACK, decision.kind)
        self.assertEqual("fenced", execute_decision(decision, adapter))


class FakeAdapter:
    def __init__(self) -> None:
        self.owns = True
        self.effects: list[Decision] = []
        self.completed: set[str] = set()

    def owns_live_lease(self, decision: Decision) -> bool:
        return self.owns

    def action_already_completed(self, idempotency_key: str) -> bool:
        return idempotency_key in self.completed

    def perform(self, decision: Decision) -> None:
        self.effects.append(decision)

    def record_completed(self, idempotency_key: str) -> None:
        self.completed.add(idempotency_key)


if __name__ == "__main__":
    unittest.main()
