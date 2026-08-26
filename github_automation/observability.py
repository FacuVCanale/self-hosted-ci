"""Redacted, append-only evidence and readiness contracts.

These types are deliberately storage- and vendor-neutral.  They provide a
reference format for tests and sandbox adapters; they do not claim that an
external GitHub, Windows, WSL, or runner-manager check has been performed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable, Mapping


REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?:secret|token|password|private[_-]?key|authorization|cookie|credential)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def redact(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact likely credentials while retaining useful evidence."""
    if key is not None and _SECRET_KEY.search(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub(REDACTED, value)
    return value


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    occurred_at: str
    event: str
    subject: str
    details: Mapping[str, Any]
    previous_digest: str | None
    digest: str


class AppendOnlyAuditLog:
    """Hash-chained in-memory reference log with import verification."""

    def __init__(self, records: Iterable[Mapping[str, Any]] = ()) -> None:
        self._records: list[AuditRecord] = []
        for raw in records:
            self._append_imported(raw)

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def append(
        self,
        event: str,
        subject: str,
        details: Mapping[str, Any],
        *,
        occurred_at: datetime,
    ) -> AuditRecord:
        if not event or not subject:
            raise ValueError("event and subject are required")
        payload = {
            "sequence": len(self._records) + 1,
            "occurred_at": _timestamp(occurred_at),
            "event": event,
            "subject": subject,
            "details": redact(details),
            "previous_digest": self._records[-1].digest if self._records else None,
        }
        record = AuditRecord(**payload, digest=hashlib.sha256(canonical_json(payload).encode()).hexdigest())
        self._records.append(record)
        return record

    def _append_imported(self, raw: Mapping[str, Any]) -> None:
        expected_sequence = len(self._records) + 1
        previous = self._records[-1].digest if self._records else None
        payload = {key: raw.get(key) for key in (
            "sequence", "occurred_at", "event", "subject", "details", "previous_digest"
        )}
        expected_digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        if payload["sequence"] != expected_sequence or payload["previous_digest"] != previous:
            raise ValueError("audit chain sequence/predecessor mismatch")
        if raw.get("digest") != expected_digest:
            raise ValueError("audit record digest mismatch")
        self._records.append(AuditRecord(**payload, digest=expected_digest))

    def as_dict(self) -> dict[str, Any]:
        return {"audit_schema_version": 1, "records": [asdict(record) for record in self._records]}


@dataclass(frozen=True)
class Alert:
    code: str
    severity: str
    message: str


def invariant_alerts(snapshot: Mapping[str, Any]) -> tuple[Alert, ...]:
    """Detect high-value state-machine and boundary invariant violations."""
    alerts: list[Alert] = []
    winners = snapshot.get("winner_records", [])
    terminals = snapshot.get("terminal_records", [])
    outbox = snapshot.get("outbox_records", [])
    if len(winners) > 1:
        alerts.append(Alert("multiple_winners", "critical", "more than one winner record"))
    if terminals and not outbox:
        alerts.append(Alert("terminal_without_outbox", "critical", "terminal exists without outbox"))
    if outbox and not terminals:
        alerts.append(Alert("outbox_without_terminal", "critical", "outbox exists without terminal"))
    if snapshot.get("admission_exists") and not snapshot.get("pre_marker_verified"):
        alerts.append(Alert("admission_without_verification", "critical", "admission lacks successful pre-marker verification"))
    if snapshot.get("terminal_after_deadline_won"):
        alerts.append(Alert("late_terminal_won", "critical", "terminal_at>D became winner"))
    if snapshot.get("success_proof_role") == "historical_admission_for_failure":
        alerts.append(Alert("success_from_historical_admission", "critical", "success used failure-only historical admission"))
    if snapshot.get("different_evidence_retry"):
        alerts.append(Alert("different_evidence_retry", "critical", "retry changed immutable evidence"))
    if snapshot.get("wrong_app_source"):
        alerts.append(Alert("wrong_app_source", "critical", "ci-gate source differs from pinned App"))
    if snapshot.get("stale_heartbeat") or snapshot.get("gate_without_live_owner"):
        alerts.append(Alert("stale_owner", "warning", "gate has no live owner"))
    if snapshot.get("fallback_sla_breached"):
        alerts.append(Alert("fallback_sla_breached", "critical", "fallback missed deadline plus tolerance"))
    for key, code in (
        ("network_policy_failure", "network_policy_failure"),
        ("runner_manager_drift", "runner_manager_drift"),
        ("app_authority_drift", "app_authority_drift"),
        ("timing_oracle_divergence", "timing_oracle_divergence"),
        ("cleanup_residue", "cleanup_residue"),
    ):
        if snapshot.get(key):
            alerts.append(Alert(code, "critical", code.replace("_", " ")))
    return tuple(alerts)


READINESS_STATUSES = frozenset({"pass", "fail", "unverified", "not_applicable"})


@dataclass(frozen=True)
class ReadinessCriterion:
    criterion_id: str
    status: str
    evidence: tuple[str, ...] = ()
    blocker: str | None = None

    def __post_init__(self) -> None:
        if not self.criterion_id or self.status not in READINESS_STATUSES:
            raise ValueError("invalid readiness criterion")
        if self.status == "pass" and not self.evidence:
            raise ValueError("pass requires concrete evidence")
        if self.status in {"fail", "unverified"} and not self.blocker:
            raise ValueError("fail/unverified requires an explicit blocker")


@dataclass(frozen=True)
class ReadinessMatrix:
    repository: str
    criteria: tuple[ReadinessCriterion, ...]
    schema_version: int = 1

    @property
    def ready(self) -> bool:
        return bool(self.criteria) and all(item.status in {"pass", "not_applicable"} for item in self.criteria)

    def as_dict(self) -> dict[str, Any]:
        return {
            "readiness_schema_version": self.schema_version,
            "repository": self.repository,
            "ready": self.ready,
            "criteria": [asdict(item) for item in self.criteria],
            "external_blockers": [
                {"criterion_id": item.criterion_id, "reason": item.blocker}
                for item in self.criteria if item.status == "unverified"
            ],
        }


def evidence_bundle(
    *, repository: str, audit: AppendOnlyAuditLog, readiness: ReadinessMatrix,
    artifacts: Mapping[str, Any], generated_at: datetime,
) -> dict[str, Any]:
    """Build a deterministic, redacted evidence envelope for independent review."""
    return {
        "evidence_bundle_schema_version": 1,
        "repository": repository,
        "generated_at": _timestamp(generated_at),
        "audit": audit.as_dict(),
        "readiness": readiness.as_dict(),
        "artifacts": redact(artifacts),
    }


__all__ = [
    "Alert", "AppendOnlyAuditLog", "AuditRecord", "ReadinessCriterion",
    "ReadinessMatrix", "canonical_json", "evidence_bundle", "invariant_alerts", "redact",
]
