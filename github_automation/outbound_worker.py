"""Durable outbound coordinator worker; no inbound network listener exists."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
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
from .jit_pilot import JitPilotPackageV1, PilotTerminalMonitor
from .runner_jit import sign_allocation, validate_allocation_payload


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
                    prefix="allocation.", suffix=".json", dir="/run/self-hosted-ci"
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

    def finalizing(self) -> None:
        self.state.record(self.key, "finalizing")

    def finalized(self, value: Mapping[str, str]) -> None:
        self.state.record(self.key, "finalized", finalized=dict(value))

    def recovered(self) -> None:
        self.state.record(self.key, "recovered")

    def dispatch_ambiguous(self) -> None:
        self.state.record(self.key, "dispatch-ambiguous", dispatch_ambiguous=True)


class OutboundWorker:
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

    def run_once(self) -> Mapping[str, Any]:
        request = self.state.recoverable() or self.source.poll()
        if request is None:
            return {"status": "idle"}
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
        except Exception as exc:
            self.state.fail(key)
            self.source.fail(key, type(exc).__name__)
            raise


class PilotWorker:
    """Durable pilot lifecycle. A dispatch receipt is the no-return boundary."""

    def __init__(
        self,
        state: WorkerState,
        source: WorkSource,
        broker: Any,
        github: Any,
        signer: Any,
    ):
        self.state = state
        self.source = source
        self.broker = broker
        self.github = github
        self.signer = signer

    def _record(self, key: str, phase: str, **values: Any) -> None:
        self.state.record(key, phase, **values)
        self.source.claim(key, self.state_request, lease_seconds=7200)

    def _recover_exact(self, allocation_id: str) -> None:
        receipt = self.broker.recover(allocation_id)
        if receipt != {"allocation_id": allocation_id, "state": "absent"}:
            raise WorkerError("pilot allocation recovery proof is not exact")

    def run_once(self) -> Mapping[str, Any]:
        request = self.state.recoverable() or self.source.poll()
        if request is None:
            return {"status": "idle"}
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
        if claim == "busy":
            return {"status": "busy", "request_id": key}
        progress = self.state.progress(key)
        if progress:
            request = self.source.resume(key, request, lease_seconds=7200)
        else:
            self.source.claim(key, request, lease_seconds=7200)
        self.state_request = request
        reservation = request["reservation"]
        package = JitPilotPackageV1.from_mapping(
            request["pilot_package"], now=self.source.clock()
        )
        try:
            if progress.get("phase") == "cleanup-required":
                self._recover_exact(package.allocation_id)
                self.source.fail(
                    key, progress.get("failure_reason") or "pre-dispatch-failure"
                )
                self.state.abort(
                    key, progress.get("failure_reason") or "pre-dispatch-failure"
                )
                return {
                    "status": "failed",
                    "reason": progress.get("failure_reason") or "pre-dispatch-failure",
                }
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
                run_id = self.github.dispatch_package(request["pilot_package"])
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
            payload = dict(reservation)
            payload.pop("allocation_reservation_version")
            payload.update(
                runner_allocation_version=1,
                run_id=str(run_id),
                run_attempt=observed.run_attempt,
                job_id=str(observed.job_id),
                dispatch_sha=observed.dispatch_sha,
                tested_sha=package.tested_merge_sha,
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
            outcome = PilotTerminalMonitor(
                self.github, self.broker, time.sleep, time.monotonic
            ).monitor(
                allocation_id=package.allocation_id,
                runner_label=package.runner_label,
                run_id=run_id,
                job_id=observed.job_id,
            )
            result = {
                "status": "completed",
                "mode": "ci-jit-pilot",
                "run_id": run_id,
                "job_id": observed.job_id,
                "outcome": outcome,
            }
            self.state.finish(key, result)
            self.source.complete(key, result)
            self.state.delivered(key)
            return result
        except Exception as exc:
            latest = self.state.progress(key)
            run_id = latest.get("run_id")
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
