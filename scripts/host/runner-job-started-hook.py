#!/usr/bin/env python3
"""Fail-closed GitHub runner job-started hook for a transient allocation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.request


BROKER_URL = "http://10.254.0.1:8079/v1/job-started"
ALLOCATION_ID_FILE = Path("/etc/self-hosted-ci/allocation-id")
SCALE_SET_NAME_FILE = Path("/etc/self-hosted-ci/scale-set-name")


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


def main() -> int:
    try:
        allocation_id = read_root_binding(
            ALLOCATION_ID_FILE, r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
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
                "tested_sha": required_env("CI_GATE_TRUSTED_TESTED_SHA"),
                "workflow_ref": required_env("GITHUB_WORKFLOW_REF"),
                "run_id": required_env("GITHUB_RUN_ID"),
                "run_attempt": int(attempt),
                "job_name": required_env("GITHUB_JOB"),
                "runner_name": required_env("RUNNER_NAME"),
                "scale_set_name": scale_set_name,
            },
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            BROKER_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response_body = response.read(4097)
            if response.status != 204 or response_body:
                raise ValueError("allocation broker returned an unexpected response")
    except (OSError, ValueError, UnicodeError, urllib.error.URLError) as exc:
        print(f"self-hosted-ci job-started hook blocked execution: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
