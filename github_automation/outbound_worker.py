"""Durable outbound coordinator worker; no inbound network listener exists."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .coordinator import (
    ChildDispatchAdapter,
    LocalAllocationAdapter,
    ReserveDefinitelyUnavailableBeforeEffect,
    ReservePartialFailure,
    outbound_local_dispatch,
)
from .crypto import spki_fingerprint
from .github import ObservedWorkflowJob
from .jit_pilot import JitPilotError, JitPilotPackageV1, PilotTerminalMonitor
from .local_approval import LocalApprovalError
from .pilot_checks import GateCheckError, PilotCheckPublisher
from .worker_authority import WorkerAuthorityError
from .runner_jit import (
    RunnerJitError,
    RunnerJitTemporalError,
    sign_allocation,
    validate_allocation_payload,
    validate_allocation_reservation,
)


class WorkerError(RuntimeError):
    pass


class WorkSource(Protocol):
    def poll(self) -> Mapping[str, Any] | None: ...
    def claim(
        self, request_id: str, request: Mapping[str, Any], *, lease_seconds: int
    ) -> None: ...
    def resume(
        self, request_id: str, request: Mapping[str, Any], *, lease_seconds: int
    ) -> Mapping[str, Any]: ...
    def retry(self, request_id: str, reason: str) -> None: ...
    def complete(self, request_id: str, result: Mapping[str, Any]) -> None: ...
    def fail(self, request_id: str, reason: str) -> None: ...


class FileAllocationSigner:
    """Signs only a fully validated allocation assembled by the worker."""

    def __init__(self, path: Path):
        s = os.lstat(path)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != 0
            or s.st_nlink != 1
            or stat.S_IMODE(s.st_mode) != 0o600
        ):
            raise WorkerError(
                "allocation signer key must be root-owned 0600 regular file"
            )
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise WorkerError("allocation signer key must be Ed25519")
        self._key = key
        self.fingerprint = spki_fingerprint(key.public_key())

    def sign_allocation(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        validate_allocation_payload(payload, now=datetime.now(timezone.utc))
        return sign_allocation(payload, self._key, now=datetime.now(timezone.utc))


class LocalBrokerCli:
    def __init__(self, executable: Path, timeout: int = 30):
        self.executable = executable
        self.timeout = timeout

    def _json(
        self, args: list[str], value: Mapping[str, Any] | None = None
    ) -> Mapping[str, Any]:
        temporary = None
        try:
            if value is not None:
                fd, name = tempfile.mkstemp(
                    prefix="allocation.", suffix=".json", dir="/run/self-hosted-ci-worker"
                )
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as out:
                    json.dump(value, out, separators=(",", ":"), sort_keys=True)
                temporary = name
                args = args + [name]
            result = subprocess.run(
                [str(self.executable), *args],
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            if result.returncode == 20:
                raise ReserveDefinitelyUnavailableBeforeEffect(
                    "local allocation broker is definitely unavailable"
                )
            if result.returncode == 21:
                allocation_id = (
                    value.get("allocation_id") if value is not None else None
                )
                if not isinstance(allocation_id, str):
                    raise WorkerError(
                        "partial reserve response omitted allocation identity"
                    )
                raise ReservePartialFailure(allocation_id)
            if result.returncode:
                raise WorkerError("local allocation broker operation failed")
            parsed = json.loads(result.stdout or "{}")
            if not isinstance(parsed, dict):
                raise WorkerError("broker response is not an object")
            return parsed
        finally:
            if temporary:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def reserve(self, reservation):
        return self._json(["reserve", "--reservation"], reservation)

    def finalize(self, envelope):
        return self._json(["finalize", "--envelope"], envelope)

    def recover(self, allocation_id):
        return self._json(["recover", "--allocation-id", allocation_id])

    def finish(self, allocation_id, outcome):
        return self._json(
            ["finish", "--allocation-id", allocation_id, "--outcome", outcome]
        )

    def prove_clean(self, allocation_id, runner_label):
        return self._json(
            [
                "prove-clean",
                "--allocation-id",
                allocation_id,
                "--runner-label",
                runner_label,
            ]
        )

    def record_outcome(self, value):
        return self._json(["record-outcome", "--event"], value)


class WorkerState:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,state TEXT NOT NULL,result TEXT,request TEXT,progress TEXT NOT NULL DEFAULT '{}',lease_until REAL)"
        )
        existing = {row[1] for row in self.db.execute("PRAGMA table_info(requests)")}
        for name, definition in (
            ("request", "TEXT"),
            ("progress", "TEXT NOT NULL DEFAULT '{}'"),
            ("lease_until", "REAL"),
        ):
            if name not in existing:
                self.db.execute(f"ALTER TABLE requests ADD COLUMN {name} {definition}")

    def close(self) -> None:
        db = getattr(self, "db", None)
        if db is not None:
            db.close()
            self.db = None

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def done(self, key: str) -> Mapping[str, Any] | None:
        row = self.db.execute(
            "SELECT result FROM requests WHERE id=? AND state IN ('completing','done')",
            (key,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def recoverable(self) -> Mapping[str, Any] | None:
        row = self.db.execute(
            "SELECT request FROM requests WHERE state IN ('completing','retry') ORDER BY CASE state WHEN 'completing' THEN 0 ELSE 1 END,rowid LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        if not isinstance(value, dict):
            raise WorkerError("recoverable request is invalid")
        return value

    def recover_running(self) -> int:
        """Release process-local leases after a supervised worker restart."""
        self.db.execute(
            "UPDATE requests SET state='retry',lease_until=NULL WHERE state='running'"
        )
        return self.db.execute("SELECT changes()").fetchone()[0]

    def claim(
        self,
        key: str,
        request: Mapping[str, Any],
        *,
        now: float | None = None,
        lease_seconds: int = 300,
    ) -> str:
        current = time.time() if now is None else now
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":"))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT state,request,lease_until FROM requests WHERE id=?", (key,)
            ).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO requests(id,state,result,request,progress,lease_until) VALUES(?,'running',NULL,?,'{}',?)",
                    (key, encoded, current + lease_seconds),
                )
                outcome = "acquired"
            elif row[0] == "failed":
                outcome = "failed"
            elif row[0] == "done":
                outcome = "done"
            elif row[0] == "completing":
                outcome = "completing"
            elif row[1] is not None and row[1] != encoded:
                raise WorkerError("request id was reused with different contents")
            elif row[0] == "running" and row[2] is not None and row[2] > current:
                outcome = "busy"
            else:
                self.db.execute(
                    "UPDATE requests SET state='running',request=?,lease_until=? WHERE id=?",
                    (encoded, current + lease_seconds, key),
                )
                outcome = "acquired"
            self.db.execute("COMMIT")
            return outcome
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def begin(self, key: str) -> None:
        self.claim(key, {"request_id": key})

    def progress(self, key: str) -> Mapping[str, Any]:
        row = self.db.execute(
            "SELECT progress FROM requests WHERE id=?", (key,)
        ).fetchone()
        if row is None:
            raise WorkerError("request state is missing")
        value = json.loads(row[0] or "{}")
        if not isinstance(value, dict):
            raise WorkerError("request progress is invalid")
        return value

    def record(self, key: str, phase: str, **values: Any) -> None:
        current = self.progress(key)
        current.update(values)
        current["phase"] = phase
        self.db.execute(
            "UPDATE requests SET progress=?,lease_until=? WHERE id=? AND state='running'",
            (
                json.dumps(current, sort_keys=True, separators=(",", ":")),
                time.time() + 300,
                key,
            ),
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            raise WorkerError("request progress lost its claim")

    def finish(self, key: str, result: Mapping[str, Any]) -> None:
        self.db.execute(
            "UPDATE requests SET state='completing',result=?,lease_until=NULL WHERE id=? AND state='running'",
            (json.dumps(result, sort_keys=True, separators=(",", ":")), key),
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            raise WorkerError("request completion lost its claim")

    def delivered(self, key: str) -> None:
        self.db.execute(
            "UPDATE requests SET state='done' WHERE id=? AND state='completing'", (key,)
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            raise WorkerError("request result delivery lost its claim")

    def fail(self, key: str) -> None:
        self.db.execute(
            "UPDATE requests SET state='retry',lease_until=NULL WHERE id=? AND state='running'",
            (key,),
        )

    def terminal(self, key: str, phase: str, reason: str) -> None:
        progress = dict(self.progress(key), phase=phase, failure_reason=reason)
        self.db.execute(
            "UPDATE requests SET state='failed',progress=?,result=?,lease_until=NULL WHERE id=?",
            (json.dumps(progress), json.dumps({"status": "failed", "reason": reason}), key),
        )

    def terminals(self) -> list[Mapping[str, Any]]:
        return [
            {"request_id": key, **json.loads(result), "phase": json.loads(progress).get("phase")}
            for key, result, progress in self.db.execute(
                "SELECT id,result,progress FROM requests WHERE state='failed' ORDER BY rowid"
            )
        ]

    def abort(self, key: str, reason: str) -> None:
        self.db.execute(
            "UPDATE requests SET state='failed',result=?,lease_until=NULL WHERE id=? AND state='running'",
            (
                json.dumps(
                    {"status": "failed", "reason": reason},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                key,
            ),
        )
        if self.db.execute("SELECT changes()").fetchone()[0] != 1:
            raise WorkerError("request abort lost its claim")


class _WorkerProgress:
    def __init__(self, state: WorkerState, key: str):
        self.state = state
        self.key = key

    def reserved(self, value: Mapping[str, str]) -> None:
        self.state.record(self.key, "reserved", reserved=dict(value))

    def dispatching(self) -> None:
        self.state.record(self.key, "dispatching")

    def dispatched(self, run_id: int) -> None:
        self.state.record(self.key, "dispatched", run_id=run_id)

    def observed(self, value) -> None:
        self.state.record(
            self.key,
            "observed",
            observed={
                "run_id": value.run_id,
                "run_attempt": value.run_attempt,
                "job_id": value.job_id,
                "job_name": value.job_name,
            },
        )

    def allocation_window(self, issued_at: str, claim_deadline: str) -> None:
        self.state.record(
            self.key,
            "allocation-window",
            allocation_issued_at=issued_at,
            claim_deadline=claim_deadline,
        )

    def finalizing(self) -> None:
        self.state.record(self.key, "finalizing")

    def finalized(self, value: Mapping[str, str]) -> None:
        self.state.record(self.key, "finalized", finalized=dict(value))

    def recovered(self) -> None:
        self.state.record(self.key, "recovered")

    def dispatch_ambiguous(self) -> None:
        self.state.record(self.key, "dispatch-ambiguous", dispatch_ambiguous=True)


class _AssignmentWorker:
    """Contain failures to the durable request selected for this cycle."""

    def run_once(self) -> Mapping[str, Any]:
        request = self.state.recoverable() or self.source.poll()
        if request is None:
            return {"status": "idle"}
        try:
            return self._run_assignment(request)
        except (WorkerError, RunnerJitError, GateCheckError, OSError) as exc:
            key = request.get("request_id")
            if not isinstance(key, str):
                raise
            expired = isinstance(exc, RunnerJitTemporalError)
            reason = (
                "the local allocation expired before the run started"
                if expired else f"assignment failed: {type(exc).__name__}"
            )
            # Ensure even malformed requests with a usable identity are quarantined.
            row = self.state.db.execute(
                "SELECT request FROM requests WHERE id=?", (key,)
            ).fetchone()
            if row is None:
                self.state.claim(key, request)
            elif json.loads(row[0]) != request:
                raise WorkerAuthorityError("failed assignment crossed durable request identity") from exc
            progress = self.state.progress(key)
            if progress.get("run_id") is not None:
                reason += "; GitHub run cancellation is unavailable in this worker; manual cancellation may be required"
            phase = "allocation-expired" if expired else "assignment-failed"
            try:
                reason = self._retire_assignment(key, request, progress, reason)
            finally:
                self.state.terminal(key, phase, reason)
            if expired:
                return {"status": "failed", "reason": reason}
            raise

    def _retire_assignment(self, key, request, progress, reason):
        try:
            if isinstance(self, PilotWorker):
                self._close_checks(key, reason=reason.split(";", 1)[0])
                if progress:
                    self._recover_exact(self._recovery_allocation_id(request))
        except (WorkerError, RunnerJitError, JitPilotError, GateCheckError, OSError) as exc:
            reason += f"; cleanup failed: {type(exc).__name__} (manual reconciliation required)"
            print(f"assignment cleanup failed: {type(exc).__name__}", file=sys.stderr)
        finally:
            self.source.fail(key, reason)
        return reason


class OutboundWorker(_AssignmentWorker):
    def __init__(
        self,
        state: WorkerState,
        source: WorkSource,
        broker: LocalAllocationAdapter,
        github: ChildDispatchAdapter,
        signer: FileAllocationSigner,
    ):
        self.state = state
        self.source = source
        self.broker = broker
        self.github = github
        self.signer = signer

    def _run_assignment(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(request) != {
            "request_id",
            "protocol_package",
            "reservation",
        } or not isinstance(request["request_id"], str):
            raise WorkerError("work request fields are not exact")
        key = request["request_id"]
        claim = self.state.claim(key, request)
        if claim in {"done", "completing"}:
            prior = self.state.done(key)
            if prior is None:
                raise WorkerError("completed request result is missing")
            self.source.complete(key, prior)
            if claim == "completing":
                self.state.delivered(key)
            return prior
        if claim == "failed":
            return {"status": "failed", "reason": self.state.progress(key).get("failure_reason")}
        if claim == "busy":
            return {"status": "busy", "request_id": key}
        if self.state.progress(key):
            request = self.source.resume(key, request, lease_seconds=7200)
        else:
            self.source.claim(key, request, lease_seconds=7200)
        try:
            resume = self.state.progress(key)
            if resume.get("dispatch_ambiguous") is True:
                raise WorkerError(
                    "GitHub dispatch outcome is ambiguous; manual reconciliation is required"
                )
            package, observed = outbound_local_dispatch(
                request["protocol_package"],
                request["reservation"],
                allocation=self.broker,
                github=self.github,
                signer=self.signer,
                progress=_WorkerProgress(self.state, key),
                resume=resume,
            )
            result = {
                "status": "dispatched",
                "backend": package.values["backend"],
                "run_id": observed.run_id if observed else None,
            }
            self.state.finish(key, result)
            self.source.complete(key, result)
            self.state.delivered(key)
            return result
        except (WorkerError, RunnerJitError, GateCheckError, OSError):
            raise
        except Exception as exc:
            self.state.fail(key)
            self.source.fail(key, type(exc).__name__)
            raise


class PilotWorker(_AssignmentWorker):
    """Durable pilot lifecycle. A dispatch receipt is the no-return boundary."""

    def __init__(
        self,
        state: WorkerState,
        source: WorkSource,
        broker: Any,
        github: Any,
        signer: Any,
        checks: PilotCheckPublisher | None = None,
        repository: str | None = None,
        claim_ttl: timedelta = timedelta(minutes=12),
        cancel_convergence_timeout: timedelta = timedelta(minutes=3),
        cancel_convergence_poll: timedelta = timedelta(seconds=15),
    ):
        if claim_ttl <= timedelta(0) or claim_ttl > timedelta(minutes=15):
            raise ValueError("claim TTL must be in (0, 15 minutes]")
        if cancel_convergence_timeout <= timedelta(0):
            raise ValueError("cancel convergence timeout must be positive")
        if (
            cancel_convergence_poll <= timedelta(0)
            or cancel_convergence_poll > cancel_convergence_timeout
        ):
            raise ValueError(
                "cancel convergence poll must be positive and not exceed its timeout"
            )
        self.state = state
        self.source = source
        self.broker = broker
        self.github = github
        self.signer = signer
        self.checks = checks
        self.repository = repository
        self.claim_ttl = claim_ttl
        self.cancel_convergence_timeout = cancel_convergence_timeout
        self.cancel_convergence_poll = cancel_convergence_poll

    def _details_url(self, run_id: int, job_id: int) -> str:
        """The exact job page a published Check Run points its author at."""
        return (
            f"https://github.com/{self.repository}/actions/runs/{run_id}"
            f"/job/{job_id}"
        )

    def _open_checks(
        self, key: str, progress: Mapping[str, Any], package: Any, run_id: int, job_id: int
    ) -> Mapping[str, int]:
        """Open the pull request Check Runs once, and remember their identities.

        Publication is best effort by design: a Check Run that cannot be opened
        must never abort a local run that is already valid, and the durable
        record keeps a resumed attempt from opening a second pair.
        """
        recorded = progress.get("checks")
        if isinstance(recorded, dict) and recorded:
            return recorded
        if self.checks is None or self.repository is None:
            return {}
        try:
            opened = self.checks.start(
                head_sha=package.head_sha,
                details_url=self._details_url(run_id, job_id),
            )
        except (GateCheckError, OSError):
            return {}
        self._record(key, "checks-open", checks=dict(opened))
        return opened

    def _close_checks(
        self, key: str, *, job_id: int | None = None, conclusion: str | None = None,
        reason: str | None = None, discarded_reason: str | None = None,
    ) -> bool:
        """Close whatever Check Runs this assignment opened, exactly once.

        Every terminal path calls this, including the failure paths, so a
        published Check Run can never be left `in_progress` forever.
        """
        if self.checks is None:
            return True
        try:
            progress = self.state.progress(key)
        except WorkerError:
            return False
        checks = progress.get("checks")
        if not isinstance(checks, dict) or not checks or progress.get("checks_closed"):
            return True
        run_id, observed = progress.get("run_id"), progress.get("observed") or {}
        details = self._details_url(run_id, observed.get("job_id") or job_id or 0)
        try:
            if discarded_reason is not None:
                self.checks.discard(
                    checks=checks, reason=discarded_reason, details_url=details
                )
            elif conclusion is not None and job_id is not None:
                self.checks.conclude(
                    checks=checks, job_id=job_id, job_conclusion=conclusion,
                    details_url=details,
                )
            else:
                self.checks.abandon(
                    checks=checks, reason=reason or "the local run ended without a result",
                    details_url=details,
                )
        except (GateCheckError, OSError) as exc:
            # A Check that could not be closed is the one failure mode this
            # design promises never to leave silent: record it and say so, so
            # the open Check is visible instead of merely forgotten.
            print(
                f"check run close failed: {type(exc).__name__}",
                file=sys.stderr,
                flush=True,
            )
            try:
                self.state.record(
                    key,
                    progress.get("phase") or "checks-close-failed",
                    checks_close_failed=type(exc).__name__,
                )
            except WorkerError:
                pass
            return False
        try:
            self.state.record(key, progress.get("phase") or "checks-closed", checks_closed=True)
        except WorkerError:
            return False
        return True

    def _supersession_reason(
        self, key: str, request: Mapping[str, Any]
    ) -> str | None:
        revalidate = getattr(self.source, "supersession_reason", None)
        if revalidate is None:
            return None
        reason = revalidate(key, request)
        if reason is not None and (not isinstance(reason, str) or not reason):
            raise WorkerError("supersession reason is invalid")
        return reason

    @staticmethod
    def _cause_for_reason(reason: str) -> str:
        mapping = {
            "a newer commit superseded this pull request head": "superseded-head",
            "the default branch moved before this run was admitted": "superseded-base",
            "the pull request merge ref changed before this run was admitted": "superseded-merge",
            "the pull request was closed before this run was admitted": "pr-closed",
        }
        return mapping.get(reason, "worker-error")

    @staticmethod
    def _cancel_time(value: Any, field: str) -> datetime:
        if not isinstance(value, str):
            raise WorkerError(f"{field} is not a durable timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise WorkerError(f"{field} is not a durable timestamp") from exc
        if parsed.tzinfo != timezone.utc:
            raise WorkerError(f"{field} is not UTC")
        return parsed

    def _request_superseded_cancel(
        self,
        key: str,
        reason: str,
        run_id: int,
        job_id: int | None,
    ) -> bool:
        """Persist cancellation intent before making the idempotent API call."""
        now = self.source.clock().replace(microsecond=0)
        requested_at = now.isoformat().replace("+00:00", "Z")
        deadline = (now + self.cancel_convergence_timeout).isoformat().replace(
            "+00:00", "Z"
        )
        self.state.record(
            key,
            "cancel-requesting",
            run_id=run_id,
            job_id=job_id,
            cancel_reason=reason,
            cancel_requested_at=requested_at,
            cancel_deadline=deadline,
        )
        accepted = False
        error = None
        try:
            accepted = self.github.cancel_exact_run(run_id) is not False
        except (LocalApprovalError, WorkerAuthorityError, OSError) as exc:
            error = type(exc).__name__
        self.state.record(
            key,
            "cancel-requested",
            cancel_accepted=accepted,
            cancel_last_error=error,
            cancel_next_poll_at=(now + self.cancel_convergence_poll)
            .isoformat()
            .replace("+00:00", "Z"),
        )
        # Returning true tells the in-process terminal monitor to yield.  The
        # durable phase, not this callback, owns convergence from this point.
        return True

    def _cancel_pending(
        self, key: str, run_id: int, *, accepted: bool, error: str | None
    ) -> Mapping[str, Any]:
        now = self.source.clock().replace(microsecond=0)
        self.state.record(
            key,
            "cancel-requested",
            cancel_accepted=accepted,
            cancel_last_error=error,
            cancel_next_poll_at=(now + self.cancel_convergence_poll)
            .isoformat()
            .replace("+00:00", "Z"),
        )
        self.state.fail(key)
        return {
            "status": "pending",
            "mode": "ci-jit-pilot",
            "run_id": run_id,
            "reason": "exact run cancellation is converging",
        }

    def _cancel_not_converged(
        self,
        key: str,
        request: Mapping[str, Any],
        progress: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        run_id = progress["run_id"]
        reason = "exact workflow run cancellation exceeded its total timeout"
        # This phase is absorbing and precedes the idempotent outcome write.
        # A crash at either side of that write resumes here, never in GitHub
        # polling, so an escalated timeout cannot later be reclassified.
        self.state.record(key, "cancel-timeout-recording")
        try:
            self._record_outcome(
                key,
                request,
                "cancel-not-converged",
                run_id=run_id,
                job_id=progress.get("job_id"),
                executed=False,
                success=False,
            )
        except (WorkerError, RunnerJitError, OSError) as exc:
            self.state.record(
                key,
                "cancel-timeout-recording",
                cancel_last_error=type(exc).__name__,
            )
            self.state.fail(key)
            return {
                "status": "retry",
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "reason": "cancel timeout outcome recording remains pending",
            }
        self.state.record(key, "cancel-recovery-pending")
        return self._continue_cancel_recovery(key, request, self.state.progress(key))

    def _continue_cancel_recovery(
        self,
        key: str,
        request: Mapping[str, Any],
        progress: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Finish an escalated timeout without polling or reclassifying it."""
        run_id = progress.get("run_id")
        reason = "exact workflow run cancellation exceeded its total timeout"
        if not progress.get("cancel_recovery_complete"):
            try:
                self._recover_exact(self._recovery_allocation_id(request))
            except (WorkerError, RunnerJitError, OSError) as exc:
                self.state.record(
                    key,
                    "cancel-recovery-pending",
                    cancel_last_error=type(exc).__name__,
                )
                self.state.fail(key)
                return {
                    "status": "retry",
                    "mode": "ci-jit-pilot",
                    "run_id": run_id,
                    "reason": "cancel timeout recovery remains pending",
                }
            self.state.record(
                key,
                "cancel-recovery-pending",
                cancel_recovery_complete=True,
                cancel_last_error=None,
            )
        if not self._close_checks(key, reason=reason):
            self.state.fail(key)
            return {
                "status": "retry",
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "reason": "cancel timeout Check Run closure remains pending",
            }
        try:
            self.source.fail(key, reason)
        except LocalApprovalError:
            pass
        self.state.abort(key, reason)
        return {
            "status": "failed",
            "mode": "ci-jit-pilot",
            "run_id": run_id,
            "reason": reason,
        }

    def _continue_cancel_requested(
        self,
        key: str,
        request: Mapping[str, Any],
        progress: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        run_id, job_id = progress.get("run_id"), progress.get("job_id")
        reason = progress.get("cancel_reason")
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or run_id < 1
            or (
                job_id is not None
                and (
                    isinstance(job_id, bool)
                    or not isinstance(job_id, int)
                    or job_id < 1
                )
            )
            or not isinstance(reason, str)
            or not reason
        ):
            raise WorkerError("durable cancellation identity is invalid")
        now = self.source.clock().replace(microsecond=0)
        deadline = self._cancel_time(progress.get("cancel_deadline"), "cancel_deadline")
        next_poll = self._cancel_time(
            progress.get("cancel_next_poll_at"), "cancel_next_poll_at"
        )
        if now < next_poll and now < deadline:
            self.state.fail(key)
            return {
                "status": "pending",
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "reason": "exact run cancellation poll is not due",
            }
        try:
            run = self.github.run(run_id)
            jobs = self.github.jobs(run_id)
        except (LocalApprovalError, WorkerAuthorityError, OSError) as exc:
            if now >= deadline:
                return self._cancel_not_converged(key, request, progress)
            return self._cancel_pending(
                key, run_id, accepted=bool(progress.get("cancel_accepted")),
                error=type(exc).__name__,
            )
        if run.get("id") != run_id or not isinstance(jobs.get("jobs"), list):
            raise WorkerError("cancel convergence crossed the exact run")
        package = request["pilot_package"]
        runner_label = package["runner_label"]
        matches = [
            job
            for job in jobs["jobs"]
            if isinstance(job, Mapping)
            and job_id is not None
            and job.get("id") == job_id
            and job.get("run_id") == run_id
            and job.get("name") == "local-quality"
            and runner_label in job.get("labels", [])
        ]
        if job_id is not None and len(matches) != 1:
            raise WorkerError("cancel convergence cannot prove the exact local job")
        job = matches[0] if matches else None
        terminal = run.get("status") == "completed" and (
            job is None or job.get("status") == "completed"
        )
        if not terminal:
            if (
                run.get("status") not in {"queued", "in_progress", "completed"}
                or (
                    job is not None
                    and job.get("status") not in {"queued", "in_progress", "completed"}
                )
            ):
                raise WorkerError("cancel convergence observed an invalid state")
            if now >= deadline:
                return self._cancel_not_converged(key, request, progress)
            accepted = bool(progress.get("cancel_accepted"))
            error = None
            if not accepted:
                try:
                    accepted = self.github.cancel_exact_run(run_id) is not False
                except (LocalApprovalError, WorkerAuthorityError, OSError) as exc:
                    error = type(exc).__name__
            return self._cancel_pending(
                key, run_id, accepted=accepted, error=error
            )
        if job_id is None:
            self._record_outcome(
                key, request, self._cause_for_reason(reason), run_id=run_id,
                executed=False, success=False,
            )
            self._recover_exact(self._recovery_allocation_id(request))
            outcome = "cancel"
        else:
            monitor = PilotTerminalMonitor(
                self.github, self.broker, time.sleep, time.monotonic
            )
            monitor.before_finish = lambda _conclusion: self._record_outcome(
                key,
                request,
                self._cause_for_reason(reason),
                run_id=run_id,
                job_id=job_id,
                # Supersession is coordination noise, even if the allocation was
                # already admitted.  It never enters the code-quality denominator.
                executed=False,
                success=False,
            )
            outcome = monitor.monitor(
                allocation_id=self._recovery_allocation_id(request),
                runner_label=runner_label,
                run_id=run_id,
                job_id=job_id,
            )
            if outcome is None:
                raise WorkerError("terminal cancellation unexpectedly yielded")
        if not self._close_checks(key, discarded_reason=reason):
            self.state.fail(key)
            return {
                "status": "retry",
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "reason": "supersession Check Run publication remains pending",
            }
        result = {
            "status": "cancelled",
            "mode": "ci-jit-pilot",
            "run_id": run_id,
            "job_id": job_id,
            "outcome": outcome,
            "reason": reason,
        }
        self.state.finish(key, result)
        try:
            self.source.complete(key, result)
        except LocalApprovalError:
            pass
        self.state.delivered(key)
        return result

    def _record_outcome(
        self, key: str, request: Mapping[str, Any], cause: str, *,
        run_id: int | None = None, job_id: int | None = None,
        executed: bool | None = False, success: bool = False,
        prior_ledger_state: str | None = None,
    ) -> None:
        package = request["pilot_package"]
        progress = self.state.progress(key)
        allocation_id = package["allocation_id"] if progress.get("reserved") is not None else None
        occurred = self.source.clock().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        recorder = getattr(self.broker, "record_outcome", None)
        if recorder is None:  # Compatibility for narrow test doubles; production broker requires it.
            return
        receipt = recorder({
            "event_key": f"request:{key}:{cause}", "cause_code": cause,
            "occurred_at": occurred, "allocation_id": allocation_id,
            "run_id": run_id or progress.get("run_id"),
            "job_id": job_id or (progress.get("observed") or {}).get("job_id"),
            "repository": package["repository"], "pr_number": package["pr_number"],
            "head_sha": package["head_sha"], "executed": executed, "success": success,
            "prior_ledger_state": prior_ledger_state,
        })
        if not isinstance(receipt, Mapping) or set(receipt) != {"recorded"} or type(receipt["recorded"]) is not bool:
            raise WorkerError("outcome receipt is invalid")

    def _complete_superseded(
        self,
        key: str,
        request: Mapping[str, Any],
        reason: str,
        *,
        run_id: int | None = None,
    ) -> Mapping[str, Any]:
        """Cancel, report and clean one exact obsolete assignment."""
        progress = self.state.progress(key)
        exact_run = run_id if run_id is not None else progress.get("run_id")
        if exact_run is not None:
            observed = progress.get("observed") or {}
            self._request_superseded_cancel(
                key,
                reason,
                exact_run,
                observed.get("job_id") or progress.get("job_id"),
            )
            self.state.fail(key)
            return {
                "status": "pending",
                "mode": "ci-jit-pilot",
                "run_id": exact_run,
                "reason": "exact run cancellation was requested",
            }
        cancellation_converged = True
        checks = progress.get("checks")
        publication_pending = False
        if isinstance(checks, dict) and checks:
            publication_pending = not self._close_checks(
                key, discarded_reason=reason
            )
        elif self.checks is not None and self.repository is not None:
            package = request.get("pilot_package")
            if isinstance(package, Mapping):
                discard_checks = dict(progress.get("discard_checks") or {})
                discard_completed = list(progress.get("discard_completed") or [])

                def record_pending(name):
                    pending = list(self.state.progress(key).get("discard_pending") or [])
                    if name not in pending:
                        pending.append(name)
                    self.state.record(key, "discard-reporting", discard_pending=pending)

                def record_created(name, identifier):
                    recorded = dict(self.state.progress(key).get("discard_checks") or {})
                    recorded[name] = identifier
                    self.state.record(key, "discard-reporting", discard_checks=recorded)

                def record_completed(name):
                    completed = list(self.state.progress(key).get("discard_completed") or [])
                    if name not in completed:
                        completed.append(name)
                    self.state.record(key, "discard-reporting", discard_completed=completed)

                try:
                    self.checks.publish_discarded(
                        head_sha=package["head_sha"],
                        reason=reason,
                        scope=f"request:{key}",
                        details_url=(
                            f"https://github.com/{self.repository}/pull/"
                            f"{package['pr_number']}"
                        ),
                        checks=discard_checks,
                        completed=discard_completed,
                        record_pending=record_pending,
                        record_created=record_created,
                        record_completed=record_completed,
                    )
                except (GateCheckError, OSError):
                    publication_pending = True
        self._record_outcome(
            key, request, self._cause_for_reason(reason), run_id=exact_run
        )
        if progress.get("reserved") is not None:
            self._recover_exact(self._recovery_allocation_id(request))
        if publication_pending:
            self.state.fail(key)
            return {
                "status": "retry",
                "mode": "ci-jit-pilot",
                "run_id": exact_run,
                "reason": "supersession Check Run publication remains pending",
            }
        result = {
            "status": "cancelled" if cancellation_converged else "completed",
            "mode": "ci-jit-pilot",
            "run_id": exact_run,
            "reason": reason,
        }
        self.state.finish(key, result)
        try:
            self.source.complete(key, result)
        except LocalApprovalError:
            # The auto-dispatcher may already have revoked this obsolete head.
            pass
        self.state.delivered(key)
        return result

    def _record(self, key: str, phase: str, **values: Any) -> None:
        self.state.record(key, phase, **values)
        self.source.claim(key, self.state_request, lease_seconds=7200)

    def _recover_exact(self, allocation_id: str) -> None:
        receipt = self.broker.recover(allocation_id)
        if receipt != {"allocation_id": allocation_id, "state": "absent"}:
            raise WorkerError("pilot allocation recovery proof is not exact")

    def _package(
        self, request: Mapping[str, Any], progress: Mapping[str, Any]
    ) -> JitPilotPackageV1:
        package_value = progress.get("dispatch_package", request["pilot_package"])
        package_now = self.source.clock()
        reservation_now = package_now
        if progress.get("run_id") is not None:
            # A durable dispatch receipt is the no-return boundary. After it,
            # the package remains the authenticated identity of the active
            # assignment even when its admission TTL has elapsed.
            issued_at = package_value.get("issued_at")
            if not isinstance(issued_at, str):
                raise JitPilotError("issued_at must be canonical UTC")
            try:
                package_now = datetime.fromisoformat(
                    issued_at.removesuffix("Z") + "+00:00"
                )
                if isinstance(progress.get("dispatch_package"), dict):
                    reservation_issued = request["reservation"].get(
                        "approval_issued_at", request["reservation"].get("issued_at")
                    )
                    reservation_now = datetime.fromisoformat(
                        str(reservation_issued).removesuffix("Z") + "+00:00"
                    )
            except ValueError as exc:
                raise JitPilotError("issued_at must be canonical UTC") from exc
        if not isinstance(progress.get("finalized"), dict):
            validate_allocation_reservation(
                request["reservation"], now=reservation_now
            )
        return JitPilotPackageV1.from_mapping(package_value, now=package_now)

    @staticmethod
    def _recovery_allocation_id(request: Mapping[str, Any]) -> str:
        """Authenticate the static allocation binding without accepting its expiry."""

        package_value = request.get("pilot_package")
        reservation = request.get("reservation")
        if not isinstance(package_value, Mapping) or not isinstance(
            reservation, Mapping
        ):
            raise WorkerError("pilot recovery binding is absent")
        try:
            package_issued = datetime.fromisoformat(
                str(package_value.get("issued_at", "")).removesuffix("Z") + "+00:00"
            )
            reservation_issued = datetime.fromisoformat(
                str(
                    reservation.get(
                        "approval_issued_at", reservation.get("issued_at", "")
                    )
                ).removesuffix("Z")
                + "+00:00"
            )
            package = JitPilotPackageV1.from_mapping(
                package_value, now=package_issued
            )
            validate_allocation_reservation(reservation, now=reservation_issued)
        except (TypeError, ValueError) as exc:
            raise WorkerError("pilot recovery binding is invalid") from exc
        if (
            package.backend != "local"
            or package.allocation_id != reservation.get("allocation_id")
            or package.runner_label != reservation.get("scale_set_name")
        ):
            raise WorkerError("pilot recovery binding crossed allocation identity")
        return package.allocation_id

    def _terminal_reconcile(
        self,
        key: str,
        request: Mapping[str, Any],
        progress: Mapping[str, Any],
        reason: str,
    ) -> Mapping[str, Any]:
        allocation_id = self._recovery_allocation_id(request)
        self.state.record(key, "cleanup-required", failure_reason=reason)
        self._close_checks(
            key, reason=f"the local assignment was terminated ({reason})"
        )
        if progress:
            try:
                self._recover_exact(allocation_id)
            except Exception:
                self.state.fail(key)
                raise
        try:
            self.source.fail(key, reason)
        except LocalApprovalError:
            # Revoked/expired approvals are already terminal at the authority
            # source. Exact local cleanup remains mandatory, but replaying a
            # terminal source transition must not keep the worker recoverable.
            pass
        except Exception:
            self.state.fail(key)
            raise
        self.state.abort(key, reason)
        self._record_outcome(key, request, "worker-error")
        return {"status": "failed", "reason": reason}

    def _run_assignment(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(request) != {
            "request_id",
            "pilot_package",
            "reservation",
        } or not isinstance(request.get("request_id"), str):
            raise WorkerError("pilot work request fields are not exact")
        key = request["request_id"]
        claim = self.state.claim(key, request, lease_seconds=7200)
        if claim in {"done", "completing"}:
            result = self.state.done(key)
            if result is None:
                raise WorkerError("completed pilot result is missing")
            self.source.complete(key, result)
            if claim == "completing":
                self.state.delivered(key)
            return result
        if claim == "failed":
            return {"status": "failed", "reason": self.state.progress(key).get("failure_reason")}
        if claim == "busy":
            return {"status": "busy", "request_id": key}
        progress = self.state.progress(key)
        if progress.get("phase") == "cancel-requesting":
            accepted = False
            error = None
            try:
                accepted = self.github.cancel_exact_run(progress["run_id"]) is not False
            except (LocalApprovalError, WorkerAuthorityError, OSError) as exc:
                error = type(exc).__name__
            return self._cancel_pending(
                key, progress["run_id"], accepted=accepted, error=error
            )
        if progress.get("phase") == "cancel-timeout-recording":
            return self._cancel_not_converged(key, request, progress)
        if progress.get("phase") == "cancel-recovery-pending":
            return self._continue_cancel_recovery(key, request, progress)
        if progress.get("phase") == "cancel-requested":
            return self._continue_cancel_requested(key, request, progress)
        if progress.get("phase") == "cleanup-required":
            return self._terminal_reconcile(
                key,
                request,
                progress,
                progress.get("failure_reason") or "pre-dispatch-failure",
            )
        reason = self._supersession_reason(key, request)
        if reason is not None:
            return self._complete_superseded(key, request, reason)
        try:
            if progress:
                request = self.source.resume(key, request, lease_seconds=7200)
            else:
                self.source.claim(key, request, lease_seconds=7200)
        except LocalApprovalError as exc:
            return self._terminal_reconcile(
                key, request, progress, type(exc).__name__
            )
        self.state_request = request
        reservation = request["reservation"]
        try:
            progress = self.state.progress(key)
            if (
                not isinstance(progress.get("dispatch_package"), dict)
                and progress.get("run_id") is None
            ):
                package_now = self.source.clock().replace(microsecond=0)
                dispatch_package = dict(request["pilot_package"])
                dispatch_package.update(
                    issued_at=package_now.isoformat().replace("+00:00", "Z"),
                    expires_at=(package_now + timedelta(minutes=15))
                    .isoformat()
                    .replace("+00:00", "Z"),
                )
                JitPilotPackageV1.from_mapping(dispatch_package, now=package_now)
                self.state.record(
                    key,
                    "package-issued",
                    dispatch_package=dispatch_package,
                )
                progress = self.state.progress(key)
            package = self._package(request, progress)
        except JitPilotError as exc:
            return self._terminal_reconcile(
                key, request, progress, type(exc).__name__
            )
        try:
            reserved = progress.get("reserved") or self.broker.reserve(reservation)
            if "reserved" not in progress:
                self._record(key, "reserved", reserved=reserved)
            if reserved != {
                "allocation_id": package.allocation_id,
                "scale_set_id": reserved.get("scale_set_id"),
                "runner_label": package.runner_label,
                "state": "reserved-disabled",
            }:
                raise WorkerError("pilot reserve response crossed package")
            run_id = progress.get("run_id")
            if run_id is None:
                if progress.get("phase") == "dispatching" or progress.get(
                    "dispatch_ambiguous"
                ):
                    raise WorkerError(
                        "pilot dispatch receipt is ambiguous; refusing redispatch"
                    )
                self._record(key, "dispatching")
                run_id = self.github.dispatch_package(progress["dispatch_package"])
                if (
                    isinstance(run_id, bool)
                    or not isinstance(run_id, int)
                    or run_id < 1
                ):
                    raise WorkerError("pilot dispatch receipt is invalid")
                self._record(key, "dispatched", run_id=run_id)
            observed_data = progress.get("observed")
            if isinstance(observed_data, dict):
                observed = ObservedWorkflowJob(
                    observed_data["run_id"],
                    observed_data["run_attempt"],
                    observed_data["job_id"],
                    observed_data["job_name"],
                    observed_data["dispatch_sha"],
                )
            else:
                observed = self.github.observe_exact_job(run_id, package.runner_label)
                observed_data = {
                    "run_id": observed.run_id,
                    "run_attempt": observed.run_attempt,
                    "job_id": observed.job_id,
                    "job_name": observed.job_name,
                    "dispatch_sha": observed.dispatch_sha,
                }
                self._record(
                    key,
                    "observed",
                    run_id=run_id,
                    job_id=observed.job_id,
                    observed=observed_data,
                )
            if observed.run_id != run_id or observed.job_name != "local-quality":
                raise WorkerError("pilot observation crossed dispatch identity")
            progress = self.state.progress(key)
            if reservation.get("allocation_reservation_version") == 2 and not (
                isinstance(progress.get("allocation_issued_at"), str)
                and isinstance(progress.get("claim_deadline"), str)
            ):
                allocation_now = self.source.clock().replace(microsecond=0)
                self._record(
                    key,
                    "allocation-window",
                    allocation_issued_at=allocation_now.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    claim_deadline=(allocation_now + self.claim_ttl)
                    .isoformat()
                    .replace("+00:00", "Z"),
                )
                progress = self.state.progress(key)
            # The pull request Check Runs open only once the exact job identity
            # is proven, so nothing is ever published for a run we do not own.
            self._open_checks(
                key, self.state.progress(key), package, run_id, observed.job_id
            )
            reason = self._supersession_reason(key, request)
            if reason is not None:
                return self._complete_superseded(
                    key, request, reason, run_id=run_id
                )
            payload = dict(reservation)
            payload.pop("allocation_reservation_version")
            payload.update(
                runner_allocation_version=reservation[
                    "allocation_reservation_version"
                ],
                run_id=str(run_id),
                run_attempt=observed.run_attempt,
                job_id=str(observed.job_id),
                dispatch_sha=observed.dispatch_sha,
                tested_sha=package.tested_merge_sha,
            )
            if reservation["allocation_reservation_version"] == 2:
                payload.update(
                    issued_at=progress["allocation_issued_at"],
                    claim_deadline=progress["claim_deadline"],
                )
            finalized = progress.get("finalized")
            if not isinstance(finalized, dict):
                envelope = self.signer.sign_allocation(payload)
                finalized = self.broker.finalize(envelope)
                if (
                    finalized.get("allocation_id") != package.allocation_id
                    or finalized.get("state") != "enabled-awaiting-claim"
                ):
                    raise WorkerError("pilot finalize response is not exact")
                self._record(
                    key,
                    "finalized",
                    run_id=run_id,
                    job_id=observed.job_id,
                    observed=observed_data,
                    finalized=finalized,
                )
            cancellation = {"reason": None}

            def current_supersession() -> str | None:
                current = self._supersession_reason(key, request)
                cancellation["reason"] = current
                return current

            monitor = PilotTerminalMonitor(
                self.github,
                self.broker,
                time.sleep,
                time.monotonic,
                supersession=current_supersession,
                cancel_run=lambda exact_run_id: self._request_superseded_cancel(
                    key, cancellation["reason"] or "the local run was superseded",
                    exact_run_id, observed.job_id,
                ),
            )
            def record_terminal(conclusion: str) -> None:
                cause = (
                    self._cause_for_reason(monitor.supersession_reason)
                    if monitor.supersession_reason is not None
                    else {
                        "success": "success", "failure": "job-failure",
                        "cancelled": "job-cancelled", "cancel": "job-cancelled",
                        "timeout": "job-timeout",
                    }.get(conclusion, "worker-error")
                )
                self._record_outcome(
                    key, request, cause, run_id=run_id, job_id=observed.job_id,
                    executed=None,
                    success=conclusion == "success" and monitor.supersession_reason is None,
                )
            monitor.before_finish = record_terminal
            outcome = monitor.monitor(
                allocation_id=package.allocation_id,
                runner_label=package.runner_label,
                run_id=run_id,
                job_id=observed.job_id,
            )
            if outcome is None:
                self.state.fail(key)
                return {
                    "status": "pending",
                    "mode": "ci-jit-pilot",
                    "run_id": run_id,
                    "reason": "exact run cancellation was requested",
                }
            if monitor.supersession_reason is not None:
                checks_closed = self._close_checks(
                    key, discarded_reason=monitor.supersession_reason
                )
                if not checks_closed:
                    self.state.fail(key)
                    return {
                        "status": "retry",
                        "mode": "ci-jit-pilot",
                        "run_id": run_id,
                        "reason": "supersession Check Run publication remains pending",
                    }
            else:
                self._close_checks(key, job_id=observed.job_id, conclusion=outcome)
            result = {
                "status": (
                    "cancelled"
                    if monitor.supersession_reason is not None
                    else "completed"
                ),
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "job_id": observed.job_id,
                "outcome": outcome,
            }
            if monitor.supersession_reason is not None:
                result["reason"] = monitor.supersession_reason
            self.state.finish(key, result)
            try:
                self.source.complete(key, result)
            except LocalApprovalError:
                if monitor.supersession_reason is None:
                    raise
            self.state.delivered(key)
            return result
        except (WorkerError, RunnerJitError, GateCheckError, OSError):
            raise
        except Exception as exc:
            latest = self.state.progress(key)
            run_id = latest.get("run_id")
            self._close_checks(
                key,
                reason=(
                    "the self-hosted runner stopped owning this run "
                    f"({type(exc).__name__})"
                ),
            )
            self._record_outcome(
                key, request, "worker-error", run_id=run_id,
                job_id=(latest.get("observed") or {}).get("job_id"),
                executed=False, success=False,
            )
            if run_id is not None:
                self.source.retry(key, type(exc).__name__)
                self.state.fail(key)
                raise
            if latest.get("phase") == "dispatching":
                recovery_failure = None
                try:
                    self._recover_exact(package.allocation_id)
                except Exception as cleanup_exc:
                    recovery_failure = cleanup_exc
                self._record(key, "dispatch-ambiguous", dispatch_ambiguous=True)
                self.source.retry(key, "dispatch-ambiguous")
                self.state.fail(key)
                if recovery_failure is not None:
                    raise recovery_failure
                raise
            reason = type(exc).__name__
            self._record(key, "cleanup-required", failure_reason=reason)
            try:
                self._recover_exact(package.allocation_id)
            except Exception:
                self.source.retry(key, "cleanup-required")
                self.state.fail(key)
                raise
            self.source.fail(key, reason)
            self.state.abort(key, reason)
            raise
