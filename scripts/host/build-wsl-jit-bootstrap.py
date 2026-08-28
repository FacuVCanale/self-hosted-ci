#!/usr/bin/env python3
"""Build an unsigned bootstrap-boundary-v1 from exact host observations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.bootstrap_boundary import (
    BootstrapBoundaryError,
    build_bootstrap_boundary,
)
from github_automation.crypto import canonicalize_jcs, parse_ijson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-observation", required=True, type=Path)
    parser.add_argument("--wsl-observation", required=True, type=Path)
    parser.add_argument("--public-manifest", required=True, type=Path)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        windows = parse_ijson(args.windows_observation.read_bytes())
        wsl = parse_ijson(args.wsl_observation.read_bytes())
        manifest = parse_ijson(args.public_manifest.read_bytes())
        output = (
            canonicalize_jcs(
                build_bootstrap_boundary(windows, wsl, manifest, nonce=args.nonce)
            )
            + b"\n"
        )
        if args.output.exists() or args.output.is_symlink():
            raise BootstrapBoundaryError("output must not already exist")
        args.output.write_bytes(output)
    except (OSError, TypeError, ValueError, BootstrapBoundaryError) as exc:
        print(f"bootstrap boundary build failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
