#!/usr/bin/env python3
"""Sign one measured WSL JIT boundary with an external Ed25519 reviewer key."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.crypto import canonicalize_jcs, parse_ijson
from github_automation.runner_boundary import RunnerBoundaryError, sign_runner_boundary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reviewer-private-key", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        source = args.input.resolve(strict=True)
        destination = args.output.resolve(strict=False)
        private_key_path = args.reviewer_private_key.resolve(strict=True)
        if source == destination:
            raise RunnerBoundaryError(
                "signed output must differ from the unsigned input"
            )
        if ROOT.resolve() in private_key_path.parents:
            raise RunnerBoundaryError(
                "reviewer private key must remain outside the repository"
            )
        key_stat = private_key_path.stat()
        if key_stat.st_mode & 0o077:
            raise RunnerBoundaryError(
                "reviewer private key must not be group/world accessible"
            )
        unsigned = parse_ijson(source.read_bytes())
        if "attestation" in unsigned:
            raise RunnerBoundaryError("input boundary must be unsigned")
        loaded = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password=None
        )
        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            raise RunnerBoundaryError("reviewer private key must be Ed25519")
        encoded = canonicalize_jcs(sign_runner_boundary(unsigned, loaded)) + b"\n"
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
    except (OSError, TypeError, ValueError, RunnerBoundaryError) as exc:
        print(f"boundary signing failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
