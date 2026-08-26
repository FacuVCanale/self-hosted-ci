"""Idempotent watchdog/reconciler decisions for the reference control plane.

The planner is deterministic and side-effect free.  ``execute_decision`` uses
small adapters and fences immediately before every external effect, allowing a
future durable provider to replace the reference GateStore without weakening
the ownership contract.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Protocol

from .timing import (
    FailureClass,
    FailureOutcome,
    claim_is_timely,
    claim_timeout_due,
    classify_failure,
    completion_is_timely,
    execution_timeout_due,
    force_cancel_due,
    force_cancel_verification_due,
    lease_is_valid,
)


class ActionKind(str, Enum):
    NOOP = "noop"
    FENCED = "fenced"
    TAKE_OVER = "take_over"
    BLOCK_ALERT = "block_alert"
    MARK_STALE_CANCEL = "mark_stale_cancel"
    OFFER_LOCAL_FAILURE = "offer_local_failure"
    SELECT_GITHUB = "select_github"
    REQUEST_NORMAL_CANCEL = "request_normal_cancel"
    REQUEST_FORCE_CANCEL = "request_force_cancel"
    VERIFY_FORCE_CANCEL = "verify_force_cancel"
    DISPATCH_FALLBACK = "dispatch_fallback"
    COMPLETE_FALLBACK_FAILURE = "complete_fallback_failure"


CURRENT_AUTHORITY_BOUNDARIES = frozenset(
    {"dispatch", "claim", "pre_marker_admission", "local_success"}
)


@dataclass(frozen=True)
class ObservedState:
    logical_key: str
    generation: int
    owner: str
    lease_epoch: int
    lease_expires_at: datetime
    phase: str
    winner: str | None = None
    claim_deadline: datetime | None = None
    execution_deadline: datetime | None = None
    job_started_at: datetime | None = None
    job_terminal_at: datetime | None = None
    job_active: bool = False
    failure_class: FailureClass | None = None
    admission_valid: bool = False
    proof_valid: bool = True
    authority_boundary: str | None = None
    ambiguous: bool = False
    stale_input: bool = False
    cancel_requested_at: datetime | None = None
    force_cancel_requested_at: datetime | None = None
    fallback_dispatched: bool = False
    fallback_terminal: bool = False


@dataclass(frozen=True)
class Decision:
    kind: ActionKind
    logical_key: str
    generation: int
    owner: str
    lease_epoch: int
    reason: str

    @property
    def idempotency_key(self) -> str:
        return f"{self.logical_key}:{self.generation}:{self.kind.value}"


def _decision(state: ObservedState, kind: ActionKind, reason: str) -> Decision:
    return Decision(kind, state.logical_key, state.generation, state.owner, state.lease_epoch, reason)


def reconcile(state: ObservedState, *, now: datetime) -> Decision:
    """Choose one resumable action using only authoritative observations."""
    causal_deadline = (
        state.claim_deadline if state.phase == "LOCAL_DISPATCHED"
        else state.execution_deadline if state.phase == "LOCAL_RUNNING"
        else None
    )
    if (
        not lease_is_valid(now, state.lease_expires_at)
        and (causal_deadline is None or state.lease_expires_at <= causal_deadline)
    ):
        return _decision(state, ActionKind.TAKE_OVER, "lease_expired_before_pending_transition")
    if state.ambiguous:
        return _decision(state, ActionKind.BLOCK_ALERT, "ambiguous_authoritative_state")
    if state.stale_input:
        return _decision(state, ActionKind.MARK_STALE_CANCEL, "stale_pr_tuple")

    if state.winner == "local":
        return _decision(state, ActionKind.NOOP, "local_winner_terminal")

    if state.winner == "github":
        if state.job_active:
            if state.cancel_requested_at is None:
                return _decision(state, ActionKind.REQUEST_NORMAL_CANCEL, "cancel_losing_local_run")
            if not force_cancel_due(now, state.cancel_requested_at):
                return _decision(state, ActionKind.NOOP, "normal_cancel_grace")
            if state.force_cancel_requested_at is None:
                return _decision(state, ActionKind.REQUEST_FORCE_CANCEL, "normal_cancel_stalled")
            if force_cancel_verification_due(now, state.force_cancel_requested_at):
                return _decision(state, ActionKind.VERIFY_FORCE_CANCEL, "verify_force_cancel")
            return _decision(state, ActionKind.NOOP, "force_cancel_verification_wait")
        if not state.fallback_dispatched:
            return _decision(state, ActionKind.DISPATCH_FALLBACK, "resume_persisted_github_winner")
        if state.fallback_terminal and state.failure_class is FailureClass.FALLBACK_FAILURE:
            return _decision(state, ActionKind.COMPLETE_FALLBACK_FAILURE, "hosted_attempt_failed")
        return _decision(state, ActionKind.NOOP, "github_path_in_progress_or_terminal")

    if not state.proof_valid and state.authority_boundary in CURRENT_AUTHORITY_BOUNDARIES:
        return _decision(state, ActionKind.SELECT_GITHUB, "current_authority_invalid")

    if state.failure_class is not None:
        outcome = classify_failure(
            state.failure_class,
            admitted=state.admission_valid,
            terminal_at=state.job_terminal_at,
            execution_deadline=state.execution_deadline,
        )
        mapping = {
            FailureOutcome.LOCAL_FINAL_FAILURE: ActionKind.OFFER_LOCAL_FAILURE,
            FailureOutcome.FALLBACK_ONCE: ActionKind.SELECT_GITHUB,
            FailureOutcome.STALE_CANCEL: ActionKind.MARK_STALE_CANCEL,
            FailureOutcome.BLOCK_ALERT: ActionKind.BLOCK_ALERT,
            FailureOutcome.FALLBACK_FINAL_FAILURE: ActionKind.COMPLETE_FALLBACK_FAILURE,
            FailureOutcome.EVIDENCE_ONLY_FALLBACK: ActionKind.SELECT_GITHUB,
        }
        return _decision(state, mapping[outcome], outcome.value)

    if state.phase == "LOCAL_DISPATCHED" and state.claim_deadline is not None:
        timely_claim = claim_is_timely(state.job_started_at, state.claim_deadline)
        if timely_claim:
            return _decision(state, ActionKind.NOOP, "formal_claim_visible")
        if claim_timeout_due(now, state.claim_deadline, timely_claim=False):
            return _decision(state, ActionKind.SELECT_GITHUB, "claim_timeout")

    if state.phase == "LOCAL_RUNNING" and state.execution_deadline is not None:
        timely_completion = completion_is_timely(state.job_terminal_at, state.execution_deadline)
        if execution_timeout_due(now, state.execution_deadline, timely_completion=timely_completion):
            return _decision(state, ActionKind.SELECT_GITHUB, "execution_timeout_after_exact_job_reread")

    # Preserve a generation's already-determined transition (and therefore its
    # idempotency key) even after the owner's lease expires. Execution still
    # rechecks the live lease and fences the stale owner; TAKE_OVER is used only
    # when no higher-priority durable transition is due.
    if not lease_is_valid(now, state.lease_expires_at):
        return _decision(state, ActionKind.TAKE_OVER, "lease_expired")

    return _decision(state, ActionKind.NOOP, "no_transition_due")


class ReconcileAdapter(Protocol):
    def owns_live_lease(self, decision: Decision) -> bool: ...
    def action_already_completed(self, idempotency_key: str) -> bool: ...
    def perform(self, decision: Decision) -> None: ...
    def record_completed(self, idempotency_key: str) -> None: ...


def execute_decision(decision: Decision, adapter: ReconcileAdapter) -> str:
    """Execute once, fencing again immediately before the external effect."""
    if decision.kind in (ActionKind.NOOP, ActionKind.FENCED):
        return decision.kind.value
    if adapter.action_already_completed(decision.idempotency_key):
        return "idempotent"
    # TAKE_OVER is a GateStore CAS, not an external side effect; it necessarily
    # starts without owning the expired lease.  The adapter must atomically
    # acquire a new epoch.  Every other action is fenced immediately here.
    if decision.kind is not ActionKind.TAKE_OVER and not adapter.owns_live_lease(decision):
        return ActionKind.FENCED.value
    adapter.perform(decision)
    adapter.record_completed(decision.idempotency_key)
    return "performed"


def reconcile_execution_timeout_after_reread(
    state: ObservedState,
    *,
    now: datetime,
    authoritative_terminal_at: datetime | None,
    authoritative_failure_class: FailureClass | None,
) -> Decision:
    """Offer any already-visible timely exact-job result before timeout selection.

    The caller must obtain these fields from the exact GitHub Runs/Jobs API
    observation while holding the current GateStore lease. Runner/coordinator
    timestamps are intentionally not accepted by this boundary.
    """
    reread = replace(
        state,
        job_terminal_at=authoritative_terminal_at,
        failure_class=authoritative_failure_class,
    )
    return reconcile(reread, now=now)


__all__ = [
    "ActionKind", "CURRENT_AUTHORITY_BOUNDARIES", "Decision", "ObservedState",
    "ReconcileAdapter", "execute_decision", "reconcile",
    "reconcile_execution_timeout_after_reread",
]
