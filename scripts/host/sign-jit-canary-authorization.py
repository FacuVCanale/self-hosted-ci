#!/usr/bin/env python3
"""Sign a narrow JIT canary authorization with the external reviewer key."""

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

from github_automation.canary_boundary import CanaryBoundaryError, sign_canary_authorization
from github_automation.crypto import canonicalize_jcs, parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reviewer-private-key", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        source = args.input.resolve(strict=True)
        output = args.output.resolve(strict=False)
        key_path = args.reviewer_private_key.resolve(strict=True)
        if source == output:
            raise CanaryBoundaryError("signed output must differ from unsigned input")
        if ROOT.resolve() in key_path.parents:
            raise CanaryBoundaryError("reviewer private key must remain outside the repository")
        if key_path.stat().st_mode & 0o077:
            raise CanaryBoundaryError("reviewer private key must not be group/world accessible")
        if output.exists() or output.is_symlink():
            raise CanaryBoundaryError("signed output must not already exist")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CanaryBoundaryError("reviewer private key must be Ed25519")
        encoded = canonicalize_jcs(sign_canary_authorization(parse_ijson(source.read_bytes()), key)) + b"\n"
        output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError, CanaryBoundaryError) as exc:
        print(f"canary authorization signing failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
