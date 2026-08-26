#!/usr/bin/env python3
"""Validate host evidence without changing the machine or registering a runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.host_security import HostSecurityError, evaluate_host_security, inert_host_evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, help="host-security schema-v1 JSON")
    args = parser.parse_args(argv)
    try:
        if args.evidence is None:
            value = inert_host_evidence(platform.system().lower())
        else:
            value = json.loads(args.evidence.read_text(encoding="utf-8"))
        result = evaluate_host_security(value)
    except (OSError, json.JSONDecodeError, HostSecurityError) as exc:
        print(json.dumps({"enabled": False, "status": "invalid", "blockers": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps({"enabled": result.enabled, "status": result.status, "blockers": result.blockers}, sort_keys=True))
    return 0 if result.enabled else 3


if __name__ == "__main__":
    sys.exit(main())
