#!/usr/bin/env python3
"""Fail-closed GitHub runner job-started hook for a transient allocation."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

BROKER_URL = "http://10.254.0.1:8079/v1/job-started"
ALLOCATION_ID_FILE = Path("/etc/self-hosted-ci/allocation-id")
SCALE_SET_NAME_FILE = Path("/etc/self-hosted-ci/scale-set-name")
ALLOCATION_FILE = Path("/etc/self-hosted-ci/allocation.json")
DIAGNOSTIC_FIELDS = frozenset(
    {
        "repository_id",
        "repository",
        "dispatch_sha",
        "tested_sha",
        "workflow_ref",
        "run_id",
        "run_attempt",
        "job_name",
        "scale_set_name",
    }
)
DIAGNOSTIC_COMPONENT = re.compile(r"[a-z][a-z0-9-]{0,31}")
DIAGNOSTIC_CODES = {
    "request": frozenset(
        {
            "unknown-operation",
            "invalid-length",
            "invalid-json",
            "invalid-envelope",
            "invalid-context",
        }
    ),
    "allocation": frozenset({"binding-unavailable"}),
    "signed-context": frozenset({"context-mismatch"}),
    "runner-claim": frozenset({"claim-not-observed"}),
    "live-job": frozenset({"job-not-verified"}),
    "ledger-claim": frozenset({"claim-transition-denied"}),
    "runner-disable": frozenset({"disable-failed"}),
    "ledger-start": frozenset({"start-transition-denied"}),
    "broker": frozenset({"operation-denied", "internal-error"}),
}


def read_root_binding(path: Path, pattern: str) -> str:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise ValueError(f"unsafe allocation binding file: {path}")
    if info.st_mode & 0o022 or info.st_size > 128:
        raise ValueError(f"allocation binding file permissions/size are unsafe: {path}")
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(pattern, value):
        raise ValueError(f"invalid allocation binding value: {path}")
    return value


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"required runner context is absent: {name}")
    return value


def read_tested_sha() -> str:
    info = os.lstat(ALLOCATION_FILE)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise ValueError(f"unsafe allocation binding file: {ALLOCATION_FILE}")
    if info.st_mode & 0o022 or info.st_size > 16384:
        raise ValueError(
            f"allocation binding file permissions/size are unsafe: {ALLOCATION_FILE}"
        )
    value = json.loads(ALLOCATION_FILE.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("payload"), dict):
        raise ValueError("allocation binding envelope is invalid")
    tested_sha = value["payload"].get("tested_sha")
    if not isinstance(tested_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tested_sha):
        raise ValueError("allocation binding tested merge SHA is invalid")
    return tested_sha


def denial_diagnostic(raw: bytes) -> str:
    if not raw or len(raw) > 4096:
        raise ValueError("invalid denial response")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "error_code",
        "mismatched_fields",
        "phase",
    }:
        raise ValueError("invalid denial response")
    phase = value["phase"]
    error_code = value["error_code"]
    fields = value["mismatched_fields"]
    if (
        not isinstance(phase, str)
        or DIAGNOSTIC_COMPONENT.fullmatch(phase) is None
        or not isinstance(error_code, str)
        or DIAGNOSTIC_COMPONENT.fullmatch(error_code) is None
        or error_code not in DIAGNOSTIC_CODES.get(phase, ())
        or not isinstance(fields, list)
        or any(not isinstance(field, str) for field in fields)
        or fields != sorted(set(fields))
        or any(field not in DIAGNOSTIC_FIELDS for field in fields)
    ):
        raise ValueError("invalid denial response")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    if raw != canonical:
        raise ValueError("invalid denial response")
    field_names = ",".join(fields) if fields else "none"
    return (
        f"phase={phase} error_code={error_code} "
        f"mismatched_fields={field_names}"
    )


def main() -> int:
    try:
        allocation_id = read_root_binding(
            ALLOCATION_ID_FILE,
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        )
        scale_set_name = read_root_binding(SCALE_SET_NAME_FILE, r"wsl-jit-[0-9a-f]{32}")
        attempt = required_env("GITHUB_RUN_ATTEMPT")
        if not re.fullmatch(r"[1-9][0-9]*", attempt):
            raise ValueError("GITHUB_RUN_ATTEMPT is not a positive integer")
        payload = {
            "allocation_id": allocation_id,
            "context": {
                "repository_id": required_env("GITHUB_REPOSITORY_ID"),
                "repository": required_env("GITHUB_REPOSITORY"),
                "dispatch_sha": required_env("GITHUB_SHA"),
                "tested_sha": read_tested_sha(),
                "workflow_ref": required_env("GITHUB_WORKFLOW_REF"),
                "run_id": required_env("GITHUB_RUN_ID"),
                "run_attempt": int(attempt),
                "job_name": required_env("GITHUB_JOB"),
                "runner_name": required_env("RUNNER_NAME"),
                "scale_set_name": scale_set_name,
            },
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        request = urllib.request.Request(
            BROKER_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        # The broker performs the live GitHub job-authority check before it
        # answers. Its bounded verifier may need several eventually-consistent
        # reads, so the hook deadline must cover that complete server budget.
        with urllib.request.urlopen(request, timeout=60) as response:
            response_body = response.read(4097)
            if response.status != 204 or response_body:
                raise ValueError("allocation broker returned an unexpected response")
    except urllib.error.HTTPError as exc:
        diagnostic = "phase=transport error_code=broker-http-error mismatched_fields=none"
        if exc.code == 403:
            try:
                diagnostic = denial_diagnostic(exc.read(4097))
            except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
                diagnostic = (
                    "phase=transport error_code=invalid-denial-response "
                    "mismatched_fields=none"
                )
        print(
            f"self-hosted-ci job-started hook blocked execution: {diagnostic}",
            file=sys.stderr,
        )
        return 1
    except urllib.error.URLError:
        print(
            "self-hosted-ci job-started hook blocked execution: "
            "phase=transport error_code=broker-unavailable mismatched_fields=none",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        print(
            "self-hosted-ci job-started hook blocked execution: "
            "phase=hook error_code=local-validation-failed mismatched_fields=none",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
