#!/usr/bin/env python3
"""Local-only CLI/HTTP entry point for transient GARM allocations."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.coordinator import ReservePartialFailure
from github_automation.crypto import spki_fingerprint
from github_automation.runner_jit import (
    OUTCOME_RETENTION_DAYS,
    RunnerJitError,
    SqliteAllocationLedger,
)
from github_automation.runner_jit_broker import (
    AllocationBroker,
    ExternalLiveWorkflowJobVerifier,
    GarmCliAllocationDriver,
    JobStartedDenial,
    JobStartedObservationPolicy,
    JobStartedContext,
    durable_denial_cause,
    exception_causes,
    utc_now,
)

CONFIG = Path("/etc/self-hosted-ci/garm/allocation-broker.json")
PUBLIC_KEY = Path("/etc/self-hosted-ci/garm/allocation-authority-public-key.pem")
LEDGER = Path("/var/lib/self-hosted-ci/garm/allocation-ledger.sqlite3")
HOOK_SOURCE = Path("/usr/local/lib/self-hosted-ci/runner-job-started-hook.py")


def root_file(path: Path, maximum_size: int) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise RunnerJitError(f"unsafe broker file: {path}")
    if info.st_mode & 0o027 or info.st_size > maximum_size:
        raise RunnerJitError(f"broker file permissions/size are unsafe: {path}")
    return path.read_bytes()


def load_broker(observation_policy: JobStartedObservationPolicy = JobStartedObservationPolicy()) -> AllocationBroker:
    config = json.loads(root_file(CONFIG, 65536))
    public_key = serialization.load_pem_public_key(root_file(PUBLIC_KEY, 4096))
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise RunnerJitError("allocation authority public key must be Ed25519")
    fingerprint = spki_fingerprint(public_key)
    configured_fingerprint = config.pop("allocation_signer_fingerprint", None)
    live_job_verifier = config.pop("live_job_verifier", None)
    outcome_retention_days = config.pop(
        "outcome_retention_days", OUTCOME_RETENTION_DAYS
    )
    if not isinstance(live_job_verifier, str) or not live_job_verifier.startswith(
        "/usr/local/libexec/self-hosted-ci/"
    ):
        raise RunnerJitError("live workflow-job verifier path is not exact")
    if configured_fingerprint != fingerprint:
        raise RunnerJitError(
            "allocation authority public key is not pinned by broker config"
        )
    LEDGER.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    return AllocationBroker(
        SqliteAllocationLedger(
            LEDGER, outcome_retention_days=outcome_retention_days
        ),
        GarmCliAllocationDriver(config, HOOK_SOURCE),
        public_key,
        fingerprint,
        ExternalLiveWorkflowJobVerifier(Path(live_job_verifier)),
        observation_policy=observation_policy,
    )


def load_json(path: Path) -> dict:
    value = json.loads(root_file(path, 131072))
    if not isinstance(value, dict):
        raise RunnerJitError("JSON input must be an object")
    return value


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Keep an untrusted runner from creating unbounded broker threads."""

    daemon_threads = True
    request_queue_size = 4

    def __init__(self, *args, max_workers: int = 4, **kwargs):
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


def job_started_handler(broker: AllocationBroker, *, journal=None):
    # Capture the journal sink when the server is constructed. Request handling
    # runs on background threads, where consulting process-global sys.stderr can
    # race with another thread temporarily redirecting it.
    journal = sys.stderr if journal is None else journal

    class Handler(BaseHTTPRequestHandler):
        server_version = "self-hosted-ci-allocation-broker/1"

        def log_message(self, format, *args):
            return

        def deny(self, phase, error_code, mismatched_fields=(), exc=None):
            denial = {
                "error_code": error_code,
                "mismatched_fields": list(mismatched_fields),
                "phase": phase,
            }
            body = json.dumps(
                denial,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            print(
                json.dumps(
                    {"event": "job_started_denied", **denial, "cause": exception_causes(exc)},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=journal,
                flush=True,
            )
            allocation_id = getattr(self, "outcome_allocation_id", None)
            cause_code = durable_denial_cause(error_code, exc)
            if allocation_id is not None and cause_code is not None:
                broker.record_outcome(
                    event_key=f"job-started:{allocation_id}:{cause_code}",
                    cause_code=cause_code,
                    allocation_id=allocation_id,
                    now=utc_now(),
                )
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            denial = None
            try:
                if (
                    self.path != "/v1/job-started"
                    or self.headers.get("Content-Type") != "application/json"
                ):
                    denial = ("request", "unknown-operation", ())
                    return
                length = self.headers.get("Content-Length", "")
                if not length.isdigit() or not 1 <= int(length) <= 16384:
                    denial = ("request", "invalid-length", ())
                    return
                try:
                    value = json.loads(self.rfile.read(int(length)))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    denial = ("request", "invalid-json", (), exc)
                    return
                if not isinstance(value, dict) or set(value) != {
                    "allocation_id",
                    "context",
                }:
                    denial = ("request", "invalid-envelope", ())
                    return
                self.outcome_allocation_id = value["allocation_id"]
                try:
                    context = JobStartedContext.from_mapping(value["context"])
                except RunnerJitError as exc:
                    denial = ("request", "invalid-context", (), exc)
                    return
                broker.job_started(
                    value["allocation_id"],
                    context,
                    now=utc_now(),
                )
                self.send_response(204)
                self.end_headers()
            except JobStartedDenial as exc:
                denial = (exc.phase, exc.error_code, exc.mismatched_fields, exc)
            except (OSError, ValueError, RunnerJitError) as exc:
                denial = ("broker", "operation-denied", (), exc)
            except Exception as exc:
                denial = ("broker", "internal-error", (), exc)
            finally:
                if denial is not None:
                    self.deny(*denial)

    return Handler


def serve(broker: AllocationBroker) -> None:
    handler = job_started_handler(broker)

    server = BoundedThreadingHTTPServer(("10.254.0.1", 8079), handler, max_workers=4)
    server.serve_forever()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    defaults = JobStartedObservationPolicy()
    parser.add_argument("--job-started-observation-timeout-seconds", type=float, default=defaults.timeout_seconds)
    parser.add_argument("--job-started-poll-interval-seconds", type=float, default=defaults.poll_interval_seconds)
    sub = parser.add_subparsers(dest="command", required=True)
    reserve = sub.add_parser("reserve")
    reserve.add_argument("--reservation", required=True, type=Path)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--envelope", required=True, type=Path)
    finish = sub.add_parser("finish")
    finish.add_argument("--allocation-id", required=True)
    finish.add_argument(
        "--outcome",
        required=True,
        choices=("success", "failure", "cancel", "timeout", "force-cancel"),
    )
    finish.add_argument("--normal-cancel-attempted", action="store_true")
    prove = sub.add_parser("prove-clean")
    prove.add_argument("--allocation-id", required=True)
    prove.add_argument("--runner-label", required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--allocation-id")
    record = sub.add_parser("record-outcome")
    record.add_argument("--event", required=True, type=Path)
    outcomes = sub.add_parser("outcomes")
    outcomes.add_argument("--since-days", required=True, type=int)
    sub.add_parser("serve")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print(json.dumps({"error": "allocation broker must run as root", "cause": []}), file=sys.stderr)
        return 2
    try:
        policy = JobStartedObservationPolicy(
            timeout_seconds=args.job_started_observation_timeout_seconds,
            poll_interval_seconds=args.job_started_poll_interval_seconds,
        )
        broker = load_broker(policy)
        if args.command == "reserve":
            print(
                json.dumps(
                    broker.reserve(load_json(args.reservation), now=utc_now()),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "finalize":
            print(
                json.dumps(
                    broker.finalize(load_json(args.envelope), now=utc_now()),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "finish":
            print(
                json.dumps(
                    broker.finish(
                        args.allocation_id,
                        outcome=args.outcome,
                        normal_cancel_attempted=args.normal_cancel_attempted,
                    ),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "prove-clean":
            print(
                json.dumps(
                    broker.prove_clean(args.allocation_id, args.runner_label),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.command == "recover":
            value = (
                broker.recover(args.allocation_id)
                if args.allocation_id
                else {"recovered": broker.recover_all(), "runtime_empty": True}
            )
            print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        elif args.command == "record-outcome":
            value = load_json(args.event)
            value["now"] = datetime.fromisoformat(value.pop("occurred_at").replace("Z", "+00:00"))
            print(json.dumps({"recorded": broker.record_outcome(**value)}, sort_keys=True, separators=(",", ":")))
        elif args.command == "outcomes":
            if not 1 <= args.since_days <= 365:
                raise RunnerJitError("outcome window must be between 1 and 365 days")
            now = utc_now()
            events = broker.ledger.outcomes(since=now - timedelta(days=args.since_days), now=now)
            print(json.dumps({"events": events, "since_days": args.since_days}, sort_keys=True, separators=(",", ":")))
        else:
            broker.recover_all()
            serve(broker)
    except ReservePartialFailure as exc:
        print(
            json.dumps(
                {"error": "partial-reserve", "allocation_id": exc.allocation_id, "cause": exception_causes(exc)},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 21
    except (OSError, ValueError, RunnerJitError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": "allocation broker blocked", "cause": exception_causes(exc)}, separators=(",", ":")), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
