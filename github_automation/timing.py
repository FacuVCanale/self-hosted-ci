"""Normative timing oracle and failure taxonomy (policy version 1).

Only timestamps obtained from the named authoritative source may be supplied to
these helpers.  Runner and coordinator wall clocks are deliberately absent from
the API so they cannot accidentally decide a protocol transition.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


TIMING_POLICY_VERSION = 1


@dataclass(frozen=True)
class TimingPolicyV1:
    version: int = TIMING_POLICY_VERSION
    heartbeat: timedelta = timedelta(seconds=60)
    lease_ttl: timedelta = timedelta(minutes=5)
    watchdog_interval: timedelta = timedelta(minutes=5)
    api_tolerance: timedelta = timedelta(minutes=2)
    inventory_freshness: timedelta = timedelta(minutes=5)
    claim_deadline: timedelta = timedelta(minutes=10)
    execution_deadline: timedelta = timedelta(minutes=40)
    normal_cancel_grace: timedelta = timedelta(seconds=90)
    force_cancel_verify: timedelta = timedelta(minutes=2)
    dispatch_retry_backoff: tuple[timedelta, ...] = (
        timedelta(seconds=2), timedelta(seconds=8), timedelta(seconds=32)
    )
    poll_initial: timedelta = timedelta(seconds=15)
    poll_cap: timedelta = timedelta(seconds=30)
    reviewer_timeout: timedelta = timedelta(seconds=120)
    reviewer_retry_backoff: tuple[timedelta, ...] = (
        timedelta(seconds=30), timedelta(minutes=2)
    )
    reviewer_queue_alert: timedelta = timedelta(minutes=10)
    reviewer_queue_max_age: timedelta = timedelta(hours=24)
    reviewer_dlq_retention: timedelta = timedelta(days=7)
    preclaim_fallback_sla: timedelta = timedelta(minutes=12)
    total_fallback_gate_sla: timedelta = timedelta(minutes=100)


POLICY_V1 = TimingPolicyV1()


class ClockAuthority(str, Enum):
    GITHUB_API = "github_api"
    GATESTORE = "gatestore"
    DURABLE_QUEUE = "durable_queue"


class FailureClass(str, Enum):
    FUNCTIONAL_FAILURE = "FUNCTIONAL_FAILURE"
    STALE_INPUT = "STALE_INPUT"
    INFRA_PRETEST = "INFRA_PRETEST"
    INFRA_TRANSPORT_LOSS = "INFRA_TRANSPORT_LOSS"
    PROTOCOL_FAILURE = "PROTOCOL_FAILURE"
    CONTROL_FAILURE = "CONTROL_FAILURE"
    FALLBACK_FAILURE = "FALLBACK_FAILURE"


class FailureOutcome(str, Enum):
    LOCAL_FINAL_FAILURE = "local_final_failure"
    FALLBACK_ONCE = "fallback_once"
    STALE_CANCEL = "stale_cancel"
    BLOCK_ALERT = "block_alert"
    FALLBACK_FINAL_FAILURE = "fallback_final_failure"
    EVIDENCE_ONLY_FALLBACK = "evidence_only_fallback"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("authoritative timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def deadline_from(causal_timestamp: datetime, duration: timedelta) -> datetime:
    """Persist an absolute deadline at its causal transition."""
    if duration <= timedelta(0):
        raise ValueError("deadline duration must be positive")
    return _utc(causal_timestamp) + duration


def claim_is_timely(started_at: datetime | None, claim_deadline: datetime) -> bool:
    return started_at is not None and _utc(started_at) <= _utc(claim_deadline)


def claim_timeout_due(now: datetime, claim_deadline: datetime, *, timely_claim: bool) -> bool:
    return not timely_claim and _utc(now) > _utc(claim_deadline)


def lease_is_valid(now: datetime, lease_expires_at: datetime) -> bool:
    return _utc(now) < _utc(lease_expires_at)


def completion_is_timely(terminal_at: datetime | None, execution_deadline: datetime) -> bool:
    return terminal_at is not None and _utc(terminal_at) <= _utc(execution_deadline)


def execution_timeout_due(
    now: datetime, execution_deadline: datetime, *, timely_completion: bool
) -> bool:
    return not timely_completion and _utc(now) > _utc(execution_deadline)


def force_cancel_due(now: datetime, cancel_requested_at: datetime) -> bool:
    return _utc(now) >= _utc(cancel_requested_at) + POLICY_V1.normal_cancel_grace


def force_cancel_verification_due(now: datetime, force_cancel_requested_at: datetime) -> bool:
    return _utc(now) >= _utc(force_cancel_requested_at) + POLICY_V1.force_cancel_verify


def queue_alert_due(now: datetime, enqueued_at: datetime) -> bool:
    return _utc(now) - _utc(enqueued_at) >= POLICY_V1.reviewer_queue_alert


def queue_dead_letter_due(now: datetime, enqueued_at: datetime) -> bool:
    return _utc(now) - _utc(enqueued_at) >= POLICY_V1.reviewer_queue_max_age


def heartbeat_due(now: datetime, last_heartbeat_at: datetime) -> bool:
    return _utc(now) - _utc(last_heartbeat_at) >= POLICY_V1.heartbeat


def watchdog_due(now: datetime, last_reconciled_at: datetime) -> bool:
    return _utc(now) - _utc(last_reconciled_at) >= POLICY_V1.watchdog_interval


def inventory_is_fresh(now: datetime, observed_at: datetime) -> bool:
    age = _utc(now) - _utc(observed_at)
    return timedelta(0) <= age <= POLICY_V1.inventory_freshness


def api_tolerance_breached(now: datetime, threshold_at: datetime) -> bool:
    return _utc(now) > _utc(threshold_at) + POLICY_V1.api_tolerance


def preclaim_fallback_sla_breached(now: datetime, dispatched_at: datetime) -> bool:
    return _utc(now) > _utc(dispatched_at) + POLICY_V1.preclaim_fallback_sla


def total_fallback_sla_breached(now: datetime, gate_started_at: datetime) -> bool:
    return _utc(now) > _utc(gate_started_at) + POLICY_V1.total_fallback_gate_sla


def http_ack_within_target(response_duration: timedelta, *, durable_enqueue: bool) -> bool:
    return durable_enqueue and timedelta(0) <= response_duration < timedelta(seconds=10)


def classify_failure(
    failure: FailureClass,
    *,
    admitted: bool = False,
    terminal_at: datetime | None = None,
    execution_deadline: datetime | None = None,
) -> FailureOutcome:
    """Map a strict, trusted failure class to its only permitted outcome.

    Classification of raw child data belongs to a trusted wrapper/GitHub API
    adapter.  In particular, callers cannot relabel PR-command failure as infra.
    """
    if failure is FailureClass.FUNCTIONAL_FAILURE:
        if not admitted or terminal_at is None or execution_deadline is None:
            return FailureOutcome.BLOCK_ALERT
        if completion_is_timely(terminal_at, execution_deadline):
            return FailureOutcome.LOCAL_FINAL_FAILURE
        return FailureOutcome.EVIDENCE_ONLY_FALLBACK
    if failure is FailureClass.STALE_INPUT:
        return FailureOutcome.STALE_CANCEL
    if failure in (FailureClass.INFRA_PRETEST, FailureClass.INFRA_TRANSPORT_LOSS):
        return FailureOutcome.FALLBACK_ONCE
    if failure in (FailureClass.PROTOCOL_FAILURE, FailureClass.CONTROL_FAILURE):
        return FailureOutcome.BLOCK_ALERT
    if failure is FailureClass.FALLBACK_FAILURE:
        return FailureOutcome.FALLBACK_FINAL_FAILURE
    raise ValueError(f"unknown failure class: {failure!r}")


__all__ = [
    "ClockAuthority", "FailureClass", "FailureOutcome", "POLICY_V1",
    "TIMING_POLICY_VERSION", "TimingPolicyV1", "api_tolerance_breached",
    "claim_is_timely",
    "claim_timeout_due", "classify_failure", "completion_is_timely",
    "deadline_from", "execution_timeout_due", "force_cancel_due",
    "force_cancel_verification_due", "http_ack_within_target",
    "heartbeat_due", "inventory_is_fresh", "lease_is_valid",
    "preclaim_fallback_sla_breached", "queue_alert_due",
    "queue_dead_letter_due", "total_fallback_sla_breached", "watchdog_due",
]
