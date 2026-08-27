#!/usr/bin/env python3
"""Read-only evaluator for a WSL JIT runner-boundary evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SCRIPT = Path(__file__).resolve()
ROOT = next(
    (candidate for candidate in (SCRIPT.parents[2], SCRIPT.parent) if (candidate / "github_automation").is_dir()),
    SCRIPT.parents[2],
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.runner_boundary import (
    RunnerBoundaryError,
    evaluate_runner_boundary,
    verify_host_measurements,
)
from github_automation.host_security import HostSecurityError
from github_automation.crypto import parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument(
        "--measurement-root", type=Path,
        help="root containing measured artifacts (defaults to the evidence file directory)",
    )
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    fingerprint = parser.add_mutually_exclusive_group(required=True)
    fingerprint.add_argument("--pinned-fingerprint")
    fingerprint.add_argument("--pinned-fingerprint-file", type=Path)
    args = parser.parse_args(argv)
    try:
        value = parse_ijson(args.evidence.read_bytes())
        loaded_key = serialization.load_pem_public_key(args.reviewer_public_key.read_bytes())
        if not isinstance(loaded_key, ed25519.Ed25519PublicKey):
            raise RunnerBoundaryError("reviewer public key must be Ed25519")
        pinned = (
            args.pinned_fingerprint
            if args.pinned_fingerprint is not None
            else args.pinned_fingerprint_file.read_text(encoding="ascii").strip()
        )
        measured, blockers = verify_host_measurements(
            value, args.measurement_root or args.evidence.parent
        )
        result = evaluate_runner_boundary(
            value,
            measured_component_digests=measured,
            measurement_blockers=blockers,
            reviewer_public_key=loaded_key,
            pinned_reviewer_fingerprint=pinned,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RunnerBoundaryError, HostSecurityError) as exc:
        print(json.dumps({"enabled": False, "status": "invalid", "blockers": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps({"enabled": result.enabled, "status": result.status, "blockers": result.blockers}, sort_keys=True))
    return 0 if result.enabled else 3


if __name__ == "__main__":
    raise SystemExit(main())
