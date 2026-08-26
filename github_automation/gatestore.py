"""Transactional reference GateStore for the self-hosted automation sandbox.

This module deliberately uses SQLite as a small, inspectable reference backend.
It is suitable for protocol tests and a single-node sandbox; it is not the
production durability/availability claim for the eventual control plane.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class GateStoreError(RuntimeError):
    """Base class for fail-closed GateStore errors."""


class ConflictError(GateStoreError):
    """The requested operation conflicts with immutable persisted state."""


class FencedError(GateStoreError):
    """The caller no longer owns the current live lease/generation."""


class ReplayError(ConflictError):
    """An attestation nonce was already bound to a different gate tuple."""


class ControlFailure(GateStoreError):
    """Admission/marker authority is absent, invalid, or cross-bound."""


class LateEvidence(GateStoreError):
    """Evidence is authentic but cannot win because it arrived too late."""


@dataclass(frozen=True)
class Gate:
    logical_key: str
    generation: int
    head_generation: int
    owner: str
    lease_epoch: int
    lease_expires_at: datetime
    base_sha: str
    tested_merge_sha: str
    check_run_id: int
    winner: str | None
    result_kind: str | None
    evidence_digest: str | None


@dataclass(frozen=True)
class Admission:
    admission_id: str
    admission_digest: str
    marker_digest: str
    started_at: datetime
    execution_deadline: datetime


@dataclass(frozen=True)
class Completion:
    status: str
    winner: str
    result_kind: str
    evidence_digest: str
    outbox_key: str


Clock = Callable[[], datetime]
FaultHook = Callable[[str], None]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class GateStore:
    """SQLite implementation of the normative single-winner state machine.

    Each method opens its own connection.  That is intentional: concurrent
    coordinators are serialized by SQLite rather than by a process-local lock.
    ``fault_hook`` may raise at named points; the surrounding transaction then
    rolls back, making crash-boundary tests deterministic.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Clock | None = None,
        fault_hook: FaultHook | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("GateStore needs a file-backed SQLite database")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fault_hook = fault_hook
        self._timeout = timeout
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=self._timeout, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS heads (
                    repository_id TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    head_generation INTEGER NOT NULL CHECK (head_generation > 0),
                    PRIMARY KEY (repository_id, pr_number)
                );
                CREATE TABLE IF NOT EXISTS gates (
                    logical_key TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    head_generation INTEGER NOT NULL CHECK (head_generation > 0),
                    base_sha TEXT NOT NULL,
                    tested_merge_sha TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
                    lease_expires_at TEXT NOT NULL,
                    check_run_id INTEGER NOT NULL,
                    winner TEXT CHECK (winner IN ('local', 'github')),
                    result_kind TEXT CHECK (result_kind IN ('success', 'functional_failure')),
                    evidence_digest TEXT,
                    terminal_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (logical_key, generation)
                );
                CREATE TABLE IF NOT EXISTS nonce_bindings (
                    attestation_id TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL,
                    logical_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    head_generation INTEGER NOT NULL,
                    envelope_digest TEXT NOT NULL,
                    target_digest TEXT NOT NULL,
                    bound_at TEXT NOT NULL,
                    PRIMARY KEY (attestation_id, nonce_hash)
                );
                CREATE TABLE IF NOT EXISTS admissions (
                    logical_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    admission_id TEXT NOT NULL UNIQUE,
                    admission_digest TEXT NOT NULL UNIQUE,
                    marker_core_digest TEXT NOT NULL,
                    marker_digest TEXT NOT NULL UNIQUE,
                    authority_json TEXT NOT NULL,
                    execution_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    execution_deadline TEXT NOT NULL,
                    PRIMARY KEY (logical_key, generation),
                    FOREIGN KEY (logical_key, generation)
                        REFERENCES gates(logical_key, generation)
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    outbox_key TEXT PRIMARY KEY,
                    logical_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    winner TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    check_run_id INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'delivered')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT,
                    FOREIGN KEY (logical_key, generation)
                        REFERENCES gates(logical_key, generation)
                );
                """
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _now(self) -> datetime:
        return _utc(self._clock())

    def observe_head(self, repository_id: str, pr_number: int, head_sha: str) -> int:
        """Return the authoritative epoch, incrementing on every observed change."""
        if not repository_id or pr_number <= 0 or not head_sha:
            raise ValueError(
                "repository_id, positive pr_number and head_sha are required"
            )
        with self._transaction() as db:
            row = db.execute(
                "SELECT head_sha, head_generation FROM heads WHERE repository_id=? AND pr_number=?",
                (repository_id, pr_number),
            ).fetchone()
            if row is None:
                generation = 1
                db.execute(
                    "INSERT INTO heads VALUES (?, ?, ?, ?)",
                    (repository_id, pr_number, head_sha, generation),
                )
            elif row["head_sha"] == head_sha:
                generation = int(row["head_generation"])
            else:
                generation = int(row["head_generation"]) + 1
                db.execute(
                    "UPDATE heads SET head_sha=?, head_generation=? WHERE repository_id=? AND pr_number=?",
                    (head_sha, generation, repository_id, pr_number),
                )
            return generation

    def acquire(
        self,
        *,
        logical_key: str,
        head_generation: int,
        base_sha: str,
        tested_merge_sha: str,
        owner: str,
        check_run_id: int,
        lease_ttl: timedelta = timedelta(minutes=5),
    ) -> Gate:
        now = self._now()
        expires = now + lease_ttl
        if lease_ttl <= timedelta(0):
            raise ValueError("lease_ttl must be positive")
        with self._transaction() as db:
            latest = db.execute(
                "SELECT * FROM gates WHERE logical_key=? ORDER BY generation DESC LIMIT 1",
                (logical_key,),
            ).fetchone()
            same_tuple = latest is not None and (
                latest["head_generation"] == head_generation
                and latest["base_sha"] == base_sha
                and latest["tested_merge_sha"] == tested_merge_sha
            )
            if latest is None or not same_tuple:
                generation = 1 if latest is None else int(latest["generation"]) + 1
                epoch = 1
                db.execute(
                    """INSERT INTO gates(logical_key,generation,head_generation,base_sha,
                       tested_merge_sha,owner,lease_epoch,lease_expires_at,check_run_id,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        logical_key,
                        generation,
                        head_generation,
                        base_sha,
                        tested_merge_sha,
                        owner,
                        epoch,
                        _timestamp(expires),
                        check_run_id,
                        _timestamp(now),
                        _timestamp(now),
                    ),
                )
            else:
                generation = int(latest["generation"])
                lease_live = now < _parse_timestamp(latest["lease_expires_at"])
                if latest["owner"] != owner and lease_live:
                    raise ConflictError("generation already has a live owner")
                if latest["winner"] is not None and latest["owner"] != owner:
                    raise ConflictError(
                        "terminal generation cannot be reacquired by another owner"
                    )
                epoch = int(latest["lease_epoch"])
                if latest["owner"] != owner or not lease_live:
                    epoch += 1
                db.execute(
                    """UPDATE gates SET owner=?, lease_epoch=?, lease_expires_at=?, updated_at=?
                       WHERE logical_key=? AND generation=?""",
                    (
                        owner,
                        epoch,
                        _timestamp(expires),
                        _timestamp(now),
                        logical_key,
                        generation,
                    ),
                )
            return self._gate(db, logical_key, generation)

    def heartbeat(
        self,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        *,
        lease_ttl: timedelta = timedelta(minutes=5),
    ) -> Gate:
        now = self._now()
        with self._transaction() as db:
            row = self._owned(db, logical_key, generation, owner, lease_epoch, now)
            db.execute(
                "UPDATE gates SET lease_expires_at=?, updated_at=? WHERE logical_key=? AND generation=?",
                (_timestamp(now + lease_ttl), _timestamp(now), logical_key, generation),
            )
            return self._gate_from_row(
                dict(row) | {"lease_expires_at": _timestamp(now + lease_ttl)}
            )

    def bind_attestation_nonce(
        self,
        *,
        attestation_id: str,
        nonce_hash: str,
        logical_key: str,
        generation: int,
        expected_head_generation: int,
        envelope_digest: str,
        target: Mapping[str, Any] | None = None,
    ) -> str:
        now = self._now()
        target_digest = _digest(target or {})
        candidate = (
            logical_key,
            generation,
            expected_head_generation,
            envelope_digest,
            target_digest,
        )
        with self._transaction() as db:
            gate = db.execute(
                "SELECT head_generation FROM gates WHERE logical_key=? AND generation=?",
                (logical_key, generation),
            ).fetchone()
            if gate is None or int(gate["head_generation"]) != expected_head_generation:
                raise FencedError(
                    "head generation expectation does not match GateStore"
                )
            existing = db.execute(
                "SELECT * FROM nonce_bindings WHERE attestation_id=? AND nonce_hash=?",
                (attestation_id, nonce_hash),
            ).fetchone()
            if existing is not None:
                persisted = tuple(
                    existing[key]
                    for key in (
                        "logical_key",
                        "generation",
                        "head_generation",
                        "envelope_digest",
                        "target_digest",
                    )
                )
                if persisted == candidate:
                    return "idempotent"
                raise ReplayError("nonce is already bound to another gate tuple")
            db.execute(
                "INSERT INTO nonce_bindings VALUES (?,?,?,?,?,?,?,?)",
                (
                    attestation_id,
                    nonce_hash,
                    logical_key,
                    generation,
                    expected_head_generation,
                    envelope_digest,
                    target_digest,
                    _timestamp(now),
                ),
            )
            return "bound"

    bindAttestationNonce = bind_attestation_nonce

    def create_local_admission_after_pre_marker_verify(
        self,
        *,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        verifier_decision: Mapping[str, Any],
        authority: Mapping[str, Any],
        child_run_id: int,
        child_job_id: int,
        tested_merge_sha: str,
        canonical_command_digest: str,
        wrapper_digest: str,
        execution_deadline: datetime,
    ) -> Admission:
        now = self._now()
        if (
            verifier_decision.get("valid") is not True
            or verifier_decision.get("boundary") != "pre-marker"
        ):
            raise ControlFailure(
                "admission requires a successful current pre-marker decision"
            )
        execution = {
            "child_run_id": child_run_id,
            "child_job_id": child_job_id,
            "tested_merge_sha": tested_merge_sha,
            "canonical_command_digest": canonical_command_digest,
            "wrapper_digest": wrapper_digest,
        }
        with self._transaction() as db:
            gate = self._owned(db, logical_key, generation, owner, lease_epoch, now)
            if (
                gate["winner"] is not None
                or gate["tested_merge_sha"] != tested_merge_sha
            ):
                raise FencedError(
                    "generation already decided or tested merge mismatched"
                )
            existing = db.execute(
                "SELECT * FROM admissions WHERE logical_key=? AND generation=?",
                (logical_key, generation),
            ).fetchone()
            authority_json = _canonical(
                dict(authority) | {"verifier_decision": dict(verifier_decision)}
            )
            execution_json = _canonical(execution)
            if existing is not None:
                if (
                    existing["authority_json"] != authority_json
                    or existing["execution_json"] != execution_json
                    or existing["execution_deadline"] != _timestamp(execution_deadline)
                ):
                    raise ConflictError(
                        "immutable admission already exists with different authority/execution"
                    )
                return self._admission_from_row(existing)
            marker_core = {
                "logical_key": logical_key,
                "generation": generation,
                **execution,
                "started_at": _timestamp(now),
            }
            marker_core_digest = _digest(marker_core)
            record = {
                "logical_key": logical_key,
                "generation": generation,
                "head_generation": int(gate["head_generation"]),
                "owner": owner,
                "lease_epoch": lease_epoch,
                "authority": dict(authority),
                "execution": execution,
                "verifier_decision": dict(verifier_decision),
                "execution_deadline": _timestamp(execution_deadline),
                "marker_core_digest": marker_core_digest,
            }
            admission_digest = _digest(record)
            admission_id = str(uuid.uuid4())
            marker_digest = _digest(
                marker_core
                | {"admission_id": admission_id, "admission_digest": admission_digest}
            )
            db.execute(
                """INSERT INTO admissions VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    logical_key,
                    generation,
                    admission_id,
                    admission_digest,
                    marker_core_digest,
                    marker_digest,
                    authority_json,
                    execution_json,
                    _timestamp(now),
                    _timestamp(execution_deadline),
                ),
            )
            self._fault("after_admission_insert")
            # Admission and marker occupy one immutable row.  This second hook
            # represents the point after their complete cross-binding.
            self._fault("after_marker_insert")
            row = db.execute(
                "SELECT * FROM admissions WHERE admission_id=?", (admission_id,)
            ).fetchone()
            return self._admission_from_row(row)

    def complete_local_success_if_authorized(
        self,
        *,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        admission_id: str,
        admission_digest: str,
        evidence: Mapping[str, Any],
        attestation_valid: bool,
        attestation_expires_at: datetime,
    ) -> Completion:
        now = self._now()
        if not attestation_valid or now >= _utc(attestation_expires_at):
            raise FencedError(
                "current attestation is invalid or expired at transaction time"
            )
        with self._transaction() as db:
            self._owned(db, logical_key, generation, owner, lease_epoch, now)
            self._require_admission(
                db, logical_key, generation, admission_id, admission_digest
            )
            return self._complete(
                db, logical_key, generation, "local", "success", evidence, now
            )

    def complete_local_failure_if_current(
        self,
        *,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        admission_id: str,
        admission_digest: str,
        evidence: Mapping[str, Any],
        terminal_at: datetime,
        child_run_id: int,
        child_job_id: int,
        tested_merge_sha: str,
        canonical_command_digest: str,
    ) -> Completion:
        now = self._now()
        with self._transaction() as db:
            self._owned(db, logical_key, generation, owner, lease_epoch, now)
            admission = self._require_admission(
                db, logical_key, generation, admission_id, admission_digest
            )
            execution = json.loads(admission["execution_json"])
            expected = {
                "child_run_id": child_run_id,
                "child_job_id": child_job_id,
                "tested_merge_sha": tested_merge_sha,
                "canonical_command_digest": canonical_command_digest,
            }
            if any(execution.get(key) != value for key, value in expected.items()):
                raise ControlFailure(
                    "failure evidence does not match immutable admission execution"
                )
            if (
                evidence.get("kind") != "FUNCTIONAL_FAILURE"
                or evidence.get("conclusion") == "success"
            ):
                raise ControlFailure(
                    "only terminal functional failure evidence is accepted"
                )
            if _utc(terminal_at) > _parse_timestamp(admission["execution_deadline"]):
                raise LateEvidence(
                    "terminal evidence is later than the persisted deadline"
                )
            normalized = dict(evidence) | {
                "terminal_at": _timestamp(terminal_at),
                **expected,
            }
            return self._complete(
                db,
                logical_key,
                generation,
                "local",
                "functional_failure",
                normalized,
                now,
            )

    def select_github_winner(
        self,
        *,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        reason: str,
    ) -> str:
        now = self._now()
        with self._transaction() as db:
            gate = self._owned(db, logical_key, generation, owner, lease_epoch, now)
            if gate["winner"] is None:
                db.execute(
                    "UPDATE gates SET winner='github', updated_at=? WHERE logical_key=? AND generation=?",
                    (_timestamp(now), logical_key, generation),
                )
                self._fault("after_winner")
                return "selected"
            if gate["winner"] == "github":
                return "idempotent"
            raise FencedError(f"winner is already {gate['winner']}")

    def complete_hosted_winner(
        self,
        *,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        evidence: Mapping[str, Any],
        hosted_predicate_valid: bool,
    ) -> Completion:
        now = self._now()
        if not hosted_predicate_valid:
            raise ControlFailure("hosted conclusion predicate failed")
        with self._transaction() as db:
            gate = self._owned(db, logical_key, generation, owner, lease_epoch, now)
            if gate["winner"] != "github":
                raise FencedError("GitHub must be the immutable selected winner")
            result = (
                "success"
                if evidence.get("conclusion") == "success"
                else "functional_failure"
            )
            return self._complete(
                db, logical_key, generation, "github", result, evidence, now
            )

    def pending_outbox(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM outbox WHERE state='pending' ORDER BY created_at, outbox_key"
            ).fetchall()
            return [
                dict(row) | {"payload": json.loads(row["payload_json"])} for row in rows
            ]

    def mark_outbox_delivered(
        self, outbox_key: str, *, observed_evidence_digest: str
    ) -> str:
        now = self._now()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM outbox WHERE outbox_key=?", (outbox_key,)
            ).fetchone()
            if row is None:
                raise ControlFailure("unknown outbox item")
            if row["evidence_digest"] != observed_evidence_digest:
                raise ConflictError(
                    "Check Run evidence marker differs from committed evidence"
                )
            if row["state"] == "delivered":
                return "idempotent"
            db.execute(
                "UPDATE outbox SET state='delivered', attempts=attempts+1, delivered_at=? WHERE outbox_key=?",
                (_timestamp(now), outbox_key),
            )
            return "delivered"

    def record_outbox_attempt(self, outbox_key: str) -> None:
        with self._transaction() as db:
            if (
                db.execute(
                    "UPDATE outbox SET attempts=attempts+1 WHERE outbox_key=?",
                    (outbox_key,),
                ).rowcount
                != 1
            ):
                raise ControlFailure("unknown outbox item")

    def get_gate(self, logical_key: str, generation: int | None = None) -> Gate | None:
        with self._connect() as db:
            if generation is None:
                row = db.execute(
                    "SELECT * FROM gates WHERE logical_key=? ORDER BY generation DESC LIMIT 1",
                    (logical_key,),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM gates WHERE logical_key=? AND generation=?",
                    (logical_key, generation),
                ).fetchone()
            return None if row is None else self._gate_from_row(row)

    def get_admission(self, logical_key: str, generation: int) -> Admission | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM admissions WHERE logical_key=? AND generation=?",
                (logical_key, generation),
            ).fetchone()
            return None if row is None else self._admission_from_row(row)

    def _owned(
        self,
        db: sqlite3.Connection,
        logical_key: str,
        generation: int,
        owner: str,
        lease_epoch: int,
        now: datetime,
    ) -> sqlite3.Row:
        latest = db.execute(
            "SELECT MAX(generation) AS generation FROM gates WHERE logical_key=?",
            (logical_key,),
        ).fetchone()
        if latest is None or latest["generation"] != generation:
            raise FencedError("generation is not current")
        row = db.execute(
            "SELECT * FROM gates WHERE logical_key=? AND generation=?",
            (logical_key, generation),
        ).fetchone()
        if (
            row is None
            or row["owner"] != owner
            or int(row["lease_epoch"]) != lease_epoch
        ):
            raise FencedError("owner or lease epoch is stale")
        if now >= _parse_timestamp(row["lease_expires_at"]):
            raise FencedError("lease expired")
        return row

    def _require_admission(
        self,
        db: sqlite3.Connection,
        logical_key: str,
        generation: int,
        admission_id: str,
        admission_digest: str,
    ) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM admissions WHERE logical_key=? AND generation=?",
            (logical_key, generation),
        ).fetchone()
        if (
            row is None
            or row["admission_id"] != admission_id
            or row["admission_digest"] != admission_digest
        ):
            raise ControlFailure("missing, forged or mismatched local admission")
        return row

    def _complete(
        self,
        db: sqlite3.Connection,
        logical_key: str,
        generation: int,
        winner: str,
        result_kind: str,
        evidence: Mapping[str, Any],
        now: datetime,
    ) -> Completion:
        evidence_json = _canonical(evidence)
        evidence_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
        gate = db.execute(
            "SELECT * FROM gates WHERE logical_key=? AND generation=?",
            (logical_key, generation),
        ).fetchone()
        if gate["winner"] is not None and gate["winner"] != winner:
            raise FencedError(f"winner is already {gate['winner']}")
        if gate["result_kind"] is not None:
            if (
                gate["result_kind"] == result_kind
                and gate["evidence_digest"] == evidence_digest
            ):
                key = self._outbox_key(logical_key, generation, winner, evidence_digest)
                return Completion(
                    "idempotent", winner, result_kind, evidence_digest, key
                )
            raise ConflictError("terminal generation already has different evidence")
        db.execute(
            """UPDATE gates SET winner=?,result_kind=?,evidence_digest=?,terminal_json=?,updated_at=?
               WHERE logical_key=? AND generation=?""",
            (
                winner,
                result_kind,
                evidence_digest,
                evidence_json,
                _timestamp(now),
                logical_key,
                generation,
            ),
        )
        self._fault("after_winner")
        self._fault("after_terminal")
        key = self._outbox_key(logical_key, generation, winner, evidence_digest)
        payload = {
            "logical_key": logical_key,
            "generation": generation,
            "winner": winner,
            "result_kind": result_kind,
            "evidence_digest": evidence_digest,
            "evidence": dict(evidence),
        }
        db.execute(
            """INSERT INTO outbox(outbox_key,logical_key,generation,winner,evidence_digest,
               check_run_id,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (
                key,
                logical_key,
                generation,
                winner,
                evidence_digest,
                gate["check_run_id"],
                _canonical(payload),
                _timestamp(now),
            ),
        )
        self._fault("after_outbox")
        return Completion("committed", winner, result_kind, evidence_digest, key)

    @staticmethod
    def _outbox_key(
        logical_key: str, generation: int, winner: str, evidence_digest: str
    ) -> str:
        return f"{logical_key}:{generation}:{winner}:{evidence_digest}"

    def _gate(self, db: sqlite3.Connection, logical_key: str, generation: int) -> Gate:
        row = db.execute(
            "SELECT * FROM gates WHERE logical_key=? AND generation=?",
            (logical_key, generation),
        ).fetchone()
        return self._gate_from_row(row)

    @staticmethod
    def _gate_from_row(row: sqlite3.Row | Mapping[str, Any]) -> Gate:
        return Gate(
            logical_key=row["logical_key"],
            generation=int(row["generation"]),
            head_generation=int(row["head_generation"]),
            owner=row["owner"],
            lease_epoch=int(row["lease_epoch"]),
            lease_expires_at=_parse_timestamp(row["lease_expires_at"]),
            base_sha=row["base_sha"],
            tested_merge_sha=row["tested_merge_sha"],
            check_run_id=int(row["check_run_id"]),
            winner=row["winner"],
            result_kind=row["result_kind"],
            evidence_digest=row["evidence_digest"],
        )

    @staticmethod
    def _admission_from_row(row: sqlite3.Row) -> Admission:
        return Admission(
            admission_id=row["admission_id"],
            admission_digest=row["admission_digest"],
            marker_digest=row["marker_digest"],
            started_at=_parse_timestamp(row["started_at"]),
            execution_deadline=_parse_timestamp(row["execution_deadline"]),
        )


__all__ = [
    "Admission",
    "Completion",
    "ConflictError",
    "ControlFailure",
    "FencedError",
    "Gate",
    "GateStore",
    "GateStoreError",
    "LateEvidence",
    "ReplayError",
]
