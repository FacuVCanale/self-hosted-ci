#!/usr/bin/env python3
"""Verify the reviewer-signed JIT canary authorization."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.canary_boundary import CanaryBoundaryError, authorization_digest, verify_canary_authorization
from github_automation.crypto import parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    parser.add_argument("--pinned-fingerprint", required=True)
    args = parser.parse_args(argv)
    try:
        value = parse_ijson(args.authorization.read_bytes())
        key = serialization.load_pem_public_key(args.reviewer_public_key.read_bytes())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise CanaryBoundaryError("reviewer public key must be Ed25519")
        decision = verify_canary_authorization(
            value, key, pinned_fingerprint=args.pinned_fingerprint, now=datetime.now(timezone.utc)
        )
        output = {"authorized": decision.authorized, "blockers": decision.blockers}
        if decision.authorized:
            output.update({"authorization_digest": authorization_digest(value), "nonce": decision.nonce})
    except (OSError, TypeError, ValueError, CanaryBoundaryError) as exc:
        print(json.dumps({"authorized": False, "blockers": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0 if decision.authorized else 3


if __name__ == "__main__":
    raise SystemExit(main())
