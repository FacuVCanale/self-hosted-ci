#!/usr/bin/env python3
"""Verify that a signed bootstrap boundary authorizes inert provisioning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.bootstrap_boundary import (
    BootstrapBoundaryError,
    verify_bootstrap_boundary,
)
from github_automation.crypto import parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--windows-observation", required=True, type=Path)
    parser.add_argument("--wsl-observation", required=True, type=Path)
    parser.add_argument("--public-manifest", required=True, type=Path)
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    parser.add_argument("--pinned-fingerprint", required=True)
    parser.add_argument("--expected-nonce", required=True)
    args = parser.parse_args(argv)
    try:
        evidence = parse_ijson(args.evidence.read_bytes())
        windows = parse_ijson(args.windows_observation.read_bytes())
        wsl = parse_ijson(args.wsl_observation.read_bytes())
        manifest = parse_ijson(args.public_manifest.read_bytes())
        loaded = serialization.load_pem_public_key(
            args.reviewer_public_key.read_bytes()
        )
        if not isinstance(loaded, ed25519.Ed25519PublicKey):
            raise BootstrapBoundaryError("reviewer public key must be Ed25519")
        decision = verify_bootstrap_boundary(
            evidence,
            windows,
            wsl,
            manifest,
            loaded,
            pinned_fingerprint=args.pinned_fingerprint,
            expected_nonce=args.expected_nonce,
            source_root=ROOT,
        )
    except (OSError, TypeError, ValueError, BootstrapBoundaryError) as exc:
        print(json.dumps({"authorized": False, "blockers": [str(exc)]}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {"authorized": decision.authorized, "blockers": decision.blockers},
            sort_keys=True,
        )
    )
    return 0 if decision.authorized else 3


if __name__ == "__main__":
    raise SystemExit(main())
