#!/usr/bin/env python3
"""Sign bootstrap-boundary-v1 with its independent Ed25519 domain."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.bootstrap_boundary import (
    BootstrapBoundaryError,
    sign_bootstrap_boundary,
)
from github_automation.crypto import canonicalize_jcs, parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reviewer-private-key", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        key_path = args.reviewer_private_key.resolve(strict=True)
        if ROOT.resolve() in key_path.parents:
            raise BootstrapBoundaryError(
                "reviewer private key must remain outside the repository"
            )
        if key_path.stat().st_mode & 0o077:
            raise BootstrapBoundaryError("reviewer private key must be private")
        loaded = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            raise BootstrapBoundaryError("reviewer private key must be Ed25519")
        value = parse_ijson(args.input.read_bytes())
        if args.output.exists() or args.output.is_symlink():
            raise BootstrapBoundaryError("output must not already exist")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(
                canonicalize_jcs(sign_bootstrap_boundary(value, loaded)) + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError, BootstrapBoundaryError) as exc:
        print(f"bootstrap boundary signing failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
