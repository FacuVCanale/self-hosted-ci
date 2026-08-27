#!/usr/bin/env python3
"""Local-only CLI/HTTP entry point for transient GARM allocations."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from github_automation.coordinator import ReservePartialFailure
from github_automation.crypto import spki_fingerprint
from github_automation.runner_jit import RunnerJitError, SqliteAllocationLedger
from github_automation.runner_jit_broker import (
    AllocationBroker,
    ExternalLiveWorkflowJobVerifier,
    GarmCliAllocationDriver,
    JobStartedContext,
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


def load_broker() -> AllocationBroker:
    config = json.loads(root_file(CONFIG, 65536))
    public_key = serialization.load_pem_public_key(root_file(PUBLIC_KEY, 4096))
    fingerprint = spki_fingerprint(public_key)
    configured_fingerprint = config.pop("allocation_signer_fingerprint", None)
    live_job_verifier = config.pop("live_job_verifier", None)
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
        SqliteAllocationLedger(LEDGER),
        GarmCliAllocationDriver(config, HOOK_SOURCE),
        public_key,
        fingerprint,
        ExternalLiveWorkflowJobVerifier(Path(live_job_verifier)),
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


def serve(broker: AllocationBroker) -> None:
    class Handler(BaseHTTPRequestHandler):
        server_version = "self-hosted-ci-allocation-broker/1"

        def log_message(self, fmt, *args):
            return

        def do_POST(self):
            try:
                if (
                    self.path != "/v1/job-started"
                    or self.headers.get("Content-Type") != "application/json"
                ):
                    raise RunnerJitError("unknown broker operation")
                length = self.headers.get("Content-Length", "")
                if not length.isdigit() or not 1 <= int(length) <= 16384:
                    raise RunnerJitError("invalid broker request length")
                value = json.loads(self.rfile.read(int(length)))
                if not isinstance(value, dict) or set(value) != {
                    "allocation_id",
                    "context",
                }:
                    raise RunnerJitError("job-started request requires exact fields")
                broker.job_started(
                    value["allocation_id"],
                    JobStartedContext.from_mapping(value["context"]),
                    now=utc_now(),
                )
                self.send_response(204)
                self.end_headers()
            except (OSError, ValueError, RunnerJitError, json.JSONDecodeError):
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()

    server = BoundedThreadingHTTPServer(("10.254.0.1", 8079), Handler, max_workers=4)
    server.serve_forever()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
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
    sub.add_parser("serve")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("allocation broker must run as root", file=sys.stderr)
        return 2
    try:
        broker = load_broker()
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
        else:
            broker.recover_all()
            serve(broker)
    except ReservePartialFailure as exc:
        print(
            json.dumps(
                {"error": "partial-reserve", "allocation_id": exc.allocation_id},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 21
    except (OSError, ValueError, RunnerJitError, json.JSONDecodeError) as exc:
        print(f"allocation broker blocked: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
