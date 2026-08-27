"""Fail-closed contracts for disposable GitHub Actions runner allocations.

This module does not call GitHub, GARM, Incus, or the host.  It defines the
signed allocation accepted by the future broker and a transactional SQLite
ledger that makes claim/replay/lifecycle decisions durable across restarts.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import canonicalize_jcs, sign_detached, spki_fingerprint, verify_detached


ALLOCATION_DOMAIN = b"self-hosted-ci/runner-jit-allocation/v1"
MAX_ALLOCATION_TTL = timedelta(minutes=5)
TERMINAL_OUTCOMES = frozenset(
    {"success", "failure", "cancel", "timeout", "force-cancel", "reboot"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_WORKFLOW_REF = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+@refs/heads/[A-Za-z0-9._/-]+$"
)
_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
_RUNNER_GROUP = re.compile(r"^[^*\r\n]{1,100}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_JOB_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,100}$")
_TRANSIENT_LABEL = re.compile(r"^wsl-jit-[0-9a-f]{32}$")


class RunnerJitError(ValueError):
    """A signed allocation or lifecycle transition violates the contract."""


def allocation_scale_set_name(payload: Mapping[str, Any]) -> str:
    """Return the sole GitHub label for this allocation.

    The label is content-derived from the two single-use allocation identifiers,
    so a caller cannot select a shared/persistent pool by choosing a friendly
    label.  The full signed payload still binds the repository, workflow, run,
    job, image, and expiry.
    """

    allocation_id = _validate_uuid(payload.get("allocation_id"), "allocation_id")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise RunnerJitError("nonce must be 32 bytes encoded as unpadded base64url")
    digest = hashlib.sha256(
        canonicalize_jcs({"allocation_id": allocation_id, "nonce": nonce})
    ).hexdigest()
    return f"wsl-jit-{digest[:32]}"


RESERVATION_FIELDS = frozenset(
    {
        "allocation_reservation_version",
        "allocation_id",
        "repository_id",
        "repository",
        "head_sha",
        "workflow_ref",
        "job_name",
        "authority_kind",
        "runner_group",
        "scale_set_name",
        "labels",
        "image_fingerprint",
        "nonce",
        "issued_at",
        "expires_at",
        "max_jobs",
        "ephemeral",
    }
)


def validate_allocation_reservation(
    reservation: Mapping[str, Any], *, now: datetime
) -> None:
    if not isinstance(reservation, Mapping) or set(reservation) != RESERVATION_FIELDS:
        raise RunnerJitError("allocation reservation requires exact v1 fields")
    synthetic = dict(reservation)
    synthetic.pop("allocation_reservation_version")
    synthetic.update(
        {
            "runner_allocation_version": 1,
            "run_id": "1",
            "run_attempt": 1,
            "job_id": "1",
            "dispatch_sha": synthetic["head_sha"],
            "tested_sha": synthetic["head_sha"],
        }
    )
    validate_allocation_payload(synthetic, now=now)
    if reservation["allocation_reservation_version"] != 1:
        raise RunnerJitError("allocation_reservation_version must be 1")


def reservation_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    projected = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "runner_allocation_version",
            "run_id",
            "run_attempt",
            "job_id",
            "dispatch_sha",
            "tested_sha",
        }
    }
    projected["allocation_reservation_version"] = 1
    return projected


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerJitError(f"{field} must be canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunnerJitError(f"{field} is invalid") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise RunnerJitError(f"{field} must use whole UTC seconds")
    return parsed


def _validate_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise RunnerJitError(f"{field} must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise RunnerJitError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise RunnerJitError(f"{field} must be a lowercase canonical UUID")
    return value


def validate_allocation_payload(payload: Mapping[str, Any], *, now: datetime) -> None:
    required = {
        "runner_allocation_version",
        "allocation_id",
        "repository_id",
        "repository",
        "head_sha",
        "tested_sha",
        "dispatch_sha",
        "workflow_ref",
        "run_id",
        "run_attempt",
        "job_id",
        "job_name",
        "authority_kind",
        "runner_group",
        "scale_set_name",
        "labels",
        "image_fingerprint",
        "nonce",
        "issued_at",
        "expires_at",
        "max_jobs",
        "ephemeral",
    }
    if not isinstance(payload, Mapping) or set(payload) != required:
        raise RunnerJitError("allocation payload requires exact v1 fields")
    if payload["runner_allocation_version"] != 1:
        raise RunnerJitError("runner_allocation_version must be 1")
    _validate_uuid(payload["allocation_id"], "allocation_id")
    if not isinstance(payload["repository_id"], str) or not re.fullmatch(
        r"[1-9][0-9]*", payload["repository_id"]
    ):
        raise RunnerJitError(
            "repository_id must be a canonical positive integer string"
        )
    if not isinstance(payload["repository"], str) or not _REPOSITORY.fullmatch(
        payload["repository"]
    ):
        raise RunnerJitError("repository is invalid")
    if not isinstance(payload["head_sha"], str) or not _SHA1.fullmatch(
        payload["head_sha"]
    ):
        raise RunnerJitError("head_sha must be lowercase full SHA-1")
    for field in ("tested_sha", "dispatch_sha"):
        if not isinstance(payload[field], str) or not _SHA1.fullmatch(payload[field]):
            raise RunnerJitError(f"{field} must be lowercase full SHA-1")
    if not isinstance(payload["workflow_ref"], str) or not _WORKFLOW_REF.fullmatch(
        payload["workflow_ref"]
    ):
        raise RunnerJitError("workflow_ref must identify a default-branch workflow")
    for field in ("run_id", "job_id"):
        if not isinstance(payload[field], str) or not re.fullmatch(
            r"[1-9][0-9]*", payload[field]
        ):
            raise RunnerJitError(f"{field} must be a canonical positive integer string")
    if (
        not isinstance(payload["run_attempt"], int)
        or isinstance(payload["run_attempt"], bool)
        or payload["run_attempt"] < 1
    ):
        raise RunnerJitError("run_attempt must be a positive integer")
    if (
        not isinstance(payload["job_name"], str)
        or payload["job_name"] != payload["job_name"].strip()
        or not _JOB_NAME.fullmatch(payload["job_name"])
    ):
        raise RunnerJitError("job_name is invalid")
    authority_kind = payload["authority_kind"]
    runner_group = payload["runner_group"]
    if authority_kind == "personal-repository":
        if runner_group is not None:
            raise RunnerJitError(
                "personal repository allocations cannot use a runner group"
            )
    elif authority_kind == "organization-runner-group":
        if (
            not isinstance(runner_group, str)
            or runner_group != runner_group.strip()
            or not _RUNNER_GROUP.fullmatch(runner_group)
        ):
            raise RunnerJitError(
                "organization allocations require an exact selected runner group"
            )
    else:
        raise RunnerJitError("authority_kind is invalid")
    labels = payload["labels"]
    expected_scale_set_name = allocation_scale_set_name(payload)
    if (
        payload["scale_set_name"] != expected_scale_set_name
        or not _TRANSIENT_LABEL.fullmatch(payload["scale_set_name"])
        or labels != [expected_scale_set_name]
        or not all(
            isinstance(label, str) and _LABEL.fullmatch(label) for label in labels
        )
    ):
        raise RunnerJitError(
            "labels must select exactly the allocation-derived transient scale set"
        )
    if not isinstance(payload["image_fingerprint"], str) or not _SHA256.fullmatch(
        payload["image_fingerprint"]
    ):
        raise RunnerJitError("image_fingerprint must be lowercase SHA-256")
    if not isinstance(payload["nonce"], str) or not _NONCE.fullmatch(payload["nonce"]):
        raise RunnerJitError("nonce must be 32 bytes encoded as unpadded base64url")
    if payload["max_jobs"] != 1 or payload["ephemeral"] is not True:
        raise RunnerJitError(
            "allocations must be ephemeral and limited to exactly one job"
        )
    issued = _parse_time(payload["issued_at"], "issued_at")
    expires = _parse_time(payload["expires_at"], "expires_at")
    if expires <= issued or expires - issued > MAX_ALLOCATION_TTL:
        raise RunnerJitError(
            "allocation lifetime must be positive and at most five minutes"
        )
    if now.tzinfo != timezone.utc:
        raise RunnerJitError("now must be timezone-aware UTC")
    if now < issued - timedelta(seconds=30) or now >= expires:
        raise RunnerJitError("allocation is not currently valid")
    canonicalize_jcs(payload)


def sign_allocation(
    payload: Mapping[str, Any], private_key: ed25519.Ed25519PrivateKey, *, now: datetime
) -> dict[str, Any]:
    validate_allocation_payload(payload, now=now)
    return {
        "payload": dict(payload),
        "signer_fingerprint": spki_fingerprint(private_key.public_key()),
        "signature": sign_detached(payload, private_key, domain=ALLOCATION_DOMAIN),
    }


def verify_allocation(
    envelope: Mapping[str, Any],
    public_key: ed25519.Ed25519PublicKey,
    *,
    pinned_fingerprint: str,
    now: datetime,
) -> Mapping[str, Any]:
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "payload",
        "signer_fingerprint",
        "signature",
    }:
        raise RunnerJitError("allocation envelope requires exact fields")
    actual = spki_fingerprint(public_key)
    if (
        not _SHA256.fullmatch(pinned_fingerprint)
        or envelope["signer_fingerprint"] != pinned_fingerprint
        or actual != pinned_fingerprint
    ):
        raise RunnerJitError("allocation signer does not match the pinned Ed25519 key")
    payload = envelope["payload"]
    if not isinstance(payload, Mapping):
        raise RunnerJitError("allocation payload must be an object")
    validate_allocation_payload(payload, now=now)
    try:
        verify_detached(
            payload, envelope["signature"], public_key, domain=ALLOCATION_DOMAIN
        )
    except ValueError as exc:
        raise RunnerJitError("allocation signature is invalid") from exc
    return payload


@dataclass(frozen=True)
class AllocationRecord:
    allocation_id: str
    state: str
    outcome: str | None
    jobs_started: int
    cleanup_complete: bool
    issued_at: datetime
    expires_at: datetime
    recovery_required: bool
    cleanup_pending: bool
    cleanup_idempotency_key: str | None
    cleanup_evidence_digest: str | None


class SqliteAllocationLedger:
    """Atomic replay and lifecycle ledger; safe for concurrent broker threads."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS runner_allocations (
                allocation_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL UNIQUE,
                payload_digest TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT,
                jobs_started INTEGER NOT NULL DEFAULT 0, cleanup_complete INTEGER NOT NULL DEFAULT 0,
                issued_at TEXT, expires_at TEXT,
                recovery_required INTEGER NOT NULL DEFAULT 0,
                cleanup_pending INTEGER NOT NULL DEFAULT 0,
                cleanup_idempotency_key TEXT,
                cleanup_evidence_digest TEXT
                )"""
            )
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(runner_allocations)")
            }
            if "issued_at" not in columns:
                connection.execute(
                    "ALTER TABLE runner_allocations ADD COLUMN issued_at TEXT"
                )
            if "expires_at" not in columns:
                connection.execute(
                    "ALTER TABLE runner_allocations ADD COLUMN expires_at TEXT"
                )
            for name, declaration in (
                ("recovery_required", "INTEGER NOT NULL DEFAULT 0"),
                ("cleanup_pending", "INTEGER NOT NULL DEFAULT 0"),
                ("cleanup_idempotency_key", "TEXT"),
                ("cleanup_evidence_digest", "TEXT"),
                ("payload_json", "TEXT"),
                ("scale_set_name", "TEXT"),
                ("garm_scale_set_id", "TEXT"),
                ("reservation_json", "TEXT"),
            ):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE runner_allocations ADD COLUMN {name} {declaration}"
                    )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _digests(payload: Mapping[str, Any]) -> tuple[str, str]:
        body = canonicalize_jcs(payload)
        payload_digest = hashlib.sha256(body).hexdigest()
        # A nonce is single-use across the entire broker, not merely within one
        # repository or allocation id. This turns cross-target reuse into a
        # UNIQUE constraint failure that we classify as replay below.
        binding = canonicalize_jcs({"nonce": payload["nonce"]})
        return hashlib.sha256(binding).hexdigest(), payload_digest

    def admit(
        self,
        envelope: Mapping[str, Any],
        public_key: ed25519.Ed25519PublicKey,
        *,
        pinned_fingerprint: str,
        now: datetime,
    ) -> str:
        """Verify authority/freshness before atomically admitting an allocation."""

        payload = verify_allocation(
            envelope, public_key, pinned_fingerprint=pinned_fingerprint, now=now
        )
        binding_digest, payload_digest = self._digests(payload)
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT binding_digest, payload_digest FROM runner_allocations WHERE allocation_id = ?",
                (payload["allocation_id"],),
            ).fetchone()
            if row:
                connection.rollback()
                if row == (binding_digest, payload_digest):
                    return "idempotent"
                raise RunnerJitError("allocation_id replayed with different content")
            collision = connection.execute(
                "SELECT allocation_id FROM runner_allocations WHERE binding_digest = ?",
                (binding_digest,),
            ).fetchone()
            if collision:
                connection.rollback()
                raise RunnerJitError("allocation binding replay detected")
            connection.execute(
                """INSERT INTO runner_allocations(
                allocation_id,binding_digest,payload_digest,state,issued_at,expires_at
                ,payload_json,scale_set_name
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    payload["allocation_id"],
                    binding_digest,
                    payload_digest,
                    "issued",
                    payload["issued_at"],
                    payload["expires_at"],
                    canonicalize_jcs(payload).decode("utf-8"),
                    payload["scale_set_name"],
                ),
            )
            connection.commit()
            return "issued"

    def reserve(self, reservation: Mapping[str, Any], *, now: datetime) -> str:
        validate_allocation_reservation(reservation, now=now)
        binding_digest, reservation_digest = self._digests(reservation)
        body = canonicalize_jcs(reservation).decode("utf-8")
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT binding_digest,reservation_json FROM runner_allocations WHERE allocation_id=?",
                (reservation["allocation_id"],),
            ).fetchone()
            if row:
                connection.rollback()
                if row == (binding_digest, body):
                    return "idempotent"
                raise RunnerJitError(
                    "allocation reservation replayed with different content"
                )
            if connection.execute(
                "SELECT 1 FROM runner_allocations WHERE binding_digest=?",
                (binding_digest,),
            ).fetchone():
                connection.rollback()
                raise RunnerJitError("allocation reservation nonce replay detected")
            connection.execute(
                """INSERT INTO runner_allocations(
                allocation_id,binding_digest,payload_digest,state,issued_at,expires_at,
                scale_set_name,reservation_json
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    reservation["allocation_id"],
                    binding_digest,
                    reservation_digest,
                    "reserved",
                    reservation["issued_at"],
                    reservation["expires_at"],
                    reservation["scale_set_name"],
                    body,
                ),
            )
            connection.commit()
            return "reserved"

    def finalize(
        self,
        envelope: Mapping[str, Any],
        public_key: ed25519.Ed25519PublicKey,
        *,
        pinned_fingerprint: str,
        now: datetime,
    ) -> str:
        payload = verify_allocation(
            envelope, public_key, pinned_fingerprint=pinned_fingerprint, now=now
        )
        body = canonicalize_jcs(payload).decode("utf-8")
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,reservation_json,payload_json FROM runner_allocations WHERE allocation_id=?",
                (payload["allocation_id"],),
            ).fetchone()
            if not row:
                connection.rollback()
                raise RunnerJitError("signed allocation has no prior reservation")
            if row[2] is not None:
                connection.rollback()
                if row[2] == body:
                    return "idempotent"
                raise RunnerJitError("allocation was finalized with different content")
            reservation = json.loads(row[1]) if row[1] else None
            if row[0] != "reserved" or reservation_projection(payload) != reservation:
                connection.rollback()
                raise RunnerJitError(
                    "signed allocation crossed its immutable reservation"
                )
            connection.execute(
                "UPDATE runner_allocations SET payload_digest=?,payload_json=?,state='issued' WHERE allocation_id=?",
                (digest, body, payload["allocation_id"]),
            )
            connection.commit()
            return "issued"

    def payload(self, allocation_id: str) -> Mapping[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json FROM runner_allocations WHERE allocation_id=?",
                (allocation_id,),
            ).fetchone()
        if not row or not row[0]:
            raise RunnerJitError("allocation payload is absent")
        value = json.loads(row[0])
        if not isinstance(value, Mapping):
            raise RunnerJitError("allocation payload is invalid")
        return value

    def reservation(self, allocation_id: str) -> Mapping[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT reservation_json FROM runner_allocations WHERE allocation_id=?",
                (allocation_id,),
            ).fetchone()
        if not row or not row[0]:
            raise RunnerJitError("allocation reservation is absent")
        value = json.loads(row[0])
        if not isinstance(value, Mapping):
            raise RunnerJitError("allocation reservation is invalid")
        return value

    def bind_scale_set(
        self, allocation_id: str, scale_set_id: str, scale_set_name: str
    ) -> str:
        if not isinstance(scale_set_id, str) or not re.fullmatch(
            r"[1-9][0-9]*", scale_set_id
        ):
            raise RunnerJitError(
                "GARM scale-set ID must be a canonical positive integer string"
            )
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT scale_set_name,garm_scale_set_id FROM runner_allocations WHERE allocation_id=?",
                (allocation_id,),
            ).fetchone()
            if not row:
                connection.rollback()
                raise RunnerJitError("unknown allocation")
            if row[0] != scale_set_name:
                connection.rollback()
                raise RunnerJitError("scale-set name crossed allocation binding")
            if row[1] is not None:
                connection.rollback()
                if row[1] == scale_set_id:
                    return "idempotent"
                raise RunnerJitError(
                    "allocation is already bound to a different scale set"
                )
            connection.execute(
                "UPDATE runner_allocations SET garm_scale_set_id=? WHERE allocation_id=?",
                (scale_set_id, allocation_id),
            )
            connection.commit()
            return "bound"

    def scale_set_binding(self, allocation_id: str) -> tuple[str, str]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT scale_set_name,garm_scale_set_id FROM runner_allocations WHERE allocation_id=?",
                (allocation_id,),
            ).fetchone()
        if not row or not row[0] or not row[1]:
            raise RunnerJitError("allocation has no durable scale-set binding")
        return row[0], row[1]

    def recoverable_allocation_ids(self) -> list[str]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT allocation_id FROM runner_allocations WHERE cleanup_complete=0 ORDER BY allocation_id"
            ).fetchall()
        return [row[0] for row in rows]

    def transition(
        self,
        allocation_id: str,
        action: str,
        *,
        now: datetime | None = None,
        outcome: str | None = None,
        normal_cancel_attempted: bool = False,
        cleanup_idempotency_key: str | None = None,
        cleanup_evidence: Mapping[str, Any] | None = None,
    ) -> AllocationRecord:
        allowed = {
            "claim",
            "start",
            "finish",
            "cleanup",
            "recover",
            "ack-recovery-cleanup",
        }
        if action not in allowed:
            raise RunnerJitError("unknown lifecycle action")
        if action in {"claim", "start"}:
            if now is None or now.tzinfo != timezone.utc:
                raise RunnerJitError("claim/start require a timezone-aware UTC now")
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT state,outcome,jobs_started,cleanup_complete,issued_at,expires_at,
                recovery_required,cleanup_pending,cleanup_idempotency_key,cleanup_evidence_digest,
                payload_digest
                FROM runner_allocations WHERE allocation_id=?""",
                (allocation_id,),
            ).fetchone()
            if not row:
                connection.rollback()
                raise RunnerJitError("unknown allocation")
            (
                state,
                stored_outcome,
                jobs,
                cleaned,
                issued_text,
                expires_text,
                recovery_required,
                cleanup_pending,
                stored_cleanup_key,
                stored_evidence_digest,
                payload_digest,
            ) = row
            if issued_text is None or expires_text is None:
                connection.rollback()
                raise RunnerJitError("allocation lease timestamps are absent")
            issued_at = _parse_time(issued_text, "issued_at")
            expires_at = _parse_time(expires_text, "expires_at")
            if action in {"claim", "start"} and (
                now < issued_at - timedelta(seconds=30) or now >= expires_at
            ):
                connection.rollback()
                raise RunnerJitError(
                    "allocation lease expired before lifecycle transition"
                )
            if action == "claim" and state == "issued":
                state = "claimed"
            elif action == "start" and state == "claimed" and jobs == 0:
                state, jobs = "running", 1
            elif (
                action == "finish"
                and state == "running"
                and jobs == 1
                and outcome in TERMINAL_OUTCOMES
                and (outcome != "force-cancel" or normal_cancel_attempted is True)
            ):
                state, stored_outcome = "terminal", outcome
            elif (
                action == "cleanup"
                and state == "terminal"
                and jobs == 1
                and stored_outcome in TERMINAL_OUTCOMES
            ):
                state, cleaned = "cleaned", 1
            elif action == "cleanup" and state == "cleaned":
                connection.rollback()
                return AllocationRecord(
                    allocation_id,
                    state,
                    stored_outcome,
                    jobs,
                    bool(cleaned),
                    issued_at,
                    expires_at,
                    bool(recovery_required),
                    bool(cleanup_pending),
                    stored_cleanup_key,
                    stored_evidence_digest,
                )
            elif (
                action == "recover"
                and state in {"reserved", "issued", "claimed", "running"}
                and jobs in {0, 1}
            ):
                state, stored_outcome = "recovery_required", "reboot"
                recovery_required, cleanup_pending = 1, 1
                stored_cleanup_key = hashlib.sha256(
                    canonicalize_jcs(
                        {
                            "allocation_id": allocation_id,
                            "payload_digest": payload_digest,
                            "operation": "reboot-cleanup-v1",
                        }
                    )
                ).hexdigest()
            elif (
                action == "recover"
                and state == "recovery_required"
                and stored_outcome == "reboot"
            ):
                connection.rollback()
                return AllocationRecord(
                    allocation_id,
                    state,
                    stored_outcome,
                    jobs,
                    bool(cleaned),
                    issued_at,
                    expires_at,
                    bool(recovery_required),
                    bool(cleanup_pending),
                    stored_cleanup_key,
                    stored_evidence_digest,
                )
            elif action == "ack-recovery-cleanup":
                required_evidence = {
                    "allocation_id",
                    "cleanup_idempotency_key",
                    "jobs_started",
                    "registration_removed",
                    "workspace_removed",
                    "token_removed",
                    "container_removed",
                    "allocation_removed",
                    "orphan_registrations",
                }
                if (
                    not isinstance(cleanup_evidence, Mapping)
                    or set(cleanup_evidence) != required_evidence
                    or cleanup_idempotency_key != stored_cleanup_key
                    or cleanup_evidence.get("allocation_id") != allocation_id
                    or cleanup_evidence.get("cleanup_idempotency_key")
                    != stored_cleanup_key
                    or cleanup_evidence.get("jobs_started") != jobs
                    or cleanup_evidence.get("orphan_registrations") != 0
                    or any(
                        cleanup_evidence.get(field) is not True
                        for field in (
                            "registration_removed",
                            "workspace_removed",
                            "token_removed",
                            "container_removed",
                            "allocation_removed",
                        )
                    )
                ):
                    connection.rollback()
                    raise RunnerJitError(
                        "recovery cleanup acknowledgement evidence is invalid"
                    )
                evidence_digest = hashlib.sha256(
                    canonicalize_jcs(cleanup_evidence)
                ).hexdigest()
                if (
                    state == "recovery_required"
                    and recovery_required
                    and cleanup_pending
                ):
                    state, cleaned = "cleaned", 1
                    recovery_required, cleanup_pending = 0, 0
                    stored_evidence_digest = evidence_digest
                elif (
                    state == "cleaned"
                    and stored_outcome == "reboot"
                    and stored_evidence_digest == evidence_digest
                ):
                    connection.rollback()
                    return AllocationRecord(
                        allocation_id,
                        state,
                        stored_outcome,
                        jobs,
                        bool(cleaned),
                        issued_at,
                        expires_at,
                        bool(recovery_required),
                        bool(cleanup_pending),
                        stored_cleanup_key,
                        stored_evidence_digest,
                    )
                else:
                    connection.rollback()
                    raise RunnerJitError(
                        "recovery cleanup acknowledgement conflicts with durable state"
                    )
            else:
                connection.rollback()
                raise RunnerJitError(f"invalid lifecycle transition: {state}->{action}")
            connection.execute(
                """UPDATE runner_allocations SET state=?,outcome=?,jobs_started=?,cleanup_complete=?,
                recovery_required=?,cleanup_pending=?,cleanup_idempotency_key=?,cleanup_evidence_digest=?
                WHERE allocation_id=?""",
                (
                    state,
                    stored_outcome,
                    jobs,
                    cleaned,
                    recovery_required,
                    cleanup_pending,
                    stored_cleanup_key,
                    stored_evidence_digest,
                    allocation_id,
                ),
            )
            connection.commit()
            return AllocationRecord(
                allocation_id,
                state,
                stored_outcome,
                jobs,
                bool(cleaned),
                issued_at,
                expires_at,
                bool(recovery_required),
                bool(cleanup_pending),
                stored_cleanup_key,
                stored_evidence_digest,
            )

    def get(self, allocation_id: str) -> AllocationRecord:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT state,outcome,jobs_started,cleanup_complete,issued_at,expires_at,
                recovery_required,cleanup_pending,cleanup_idempotency_key,cleanup_evidence_digest
                FROM runner_allocations WHERE allocation_id=?""",
                (allocation_id,),
            ).fetchone()
        if not row:
            raise RunnerJitError("unknown allocation")
        if row[4] is None or row[5] is None:
            raise RunnerJitError("allocation lease timestamps are absent")
        return AllocationRecord(
            allocation_id,
            row[0],
            row[1],
            row[2],
            bool(row[3]),
            _parse_time(row[4], "issued_at"),
            _parse_time(row[5], "expires_at"),
            bool(row[6]),
            bool(row[7]),
            row[8],
            row[9],
        )
