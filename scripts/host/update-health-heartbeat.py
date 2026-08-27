#!/usr/bin/env python3
"""Atomically publish the WSL supervisor heartbeat."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile


HEALTH_ROOT = Path("/var/lib/self-hosted-ci/health")
HEARTBEAT = HEALTH_ROOT / "heartbeat.json"


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("heartbeat writer must run as root")
    HEALTH_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if HEALTH_ROOT.is_symlink() or (HEARTBEAT.exists() and HEARTBEAT.is_symlink()):
        raise SystemExit("health paths must not be symlinks")
    payload = json.dumps(
        {"schema_version": 1, "written_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".heartbeat-", dir=HEALTH_ROOT)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, HEARTBEAT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
