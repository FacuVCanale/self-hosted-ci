#!/usr/bin/env python3
"""Build the JCS manifest of exact public bytes used by inert provisioning."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.bootstrap_boundary import (
    PUBLIC_MANIFEST_ARTIFACT_COUNT,
    PUBLIC_MANIFEST_MAPPING_DIGEST,
    BootstrapBoundaryError,
    public_manifest_blockers,
)
from github_automation.crypto import canonicalize_jcs


def exact_pairs() -> list[dict[str, str]]:
    stager = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"
    spec = importlib.util.spec_from_file_location("bootstrap_live_stager", stager)
    if spec is None or spec.loader is None:
        raise BootstrapBoundaryError("live stager could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pairs = [
        {"source": source, "target": target, "mode": mode}
        for source, target, mode, _kind, _component in module.PUBLIC_ARTIFACTS
    ]
    pairs.append(
        {
            "source": "scripts/host/provision-wsl-jit-contract.sh",
            "target": "@execution/provision-wsl-jit-contract.sh",
            "mode": "0755",
        }
    )
    pairs.sort(key=lambda item: (item["target"], item["source"]))
    if (
        len(pairs) != PUBLIC_MANIFEST_ARTIFACT_COUNT
        or hashlib.sha256(canonicalize_jcs(pairs)).hexdigest()
        != PUBLIC_MANIFEST_MAPPING_DIGEST
    ):
        raise BootstrapBoundaryError("public provisioning mapping drifted")
    return pairs


def build_manifest() -> dict[str, object]:
    artifacts: list[dict[str, object]] = []
    for pair in exact_pairs():
        path = ROOT.joinpath(*Path(pair["source"]).parts)
        if (
            path.is_symlink()
            or not path.is_file()
            or ROOT.resolve() not in path.resolve().parents
        ):
            raise BootstrapBoundaryError(f"public source is unsafe: {pair['source']}")
        data = path.read_bytes()
        artifacts.append(
            {
                **pair,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    value = {
        "bootstrap_public_manifest_version": 1,
        "mapping_digest": PUBLIC_MANIFEST_MAPPING_DIGEST,
        "artifacts": artifacts,
    }
    blockers = public_manifest_blockers(value)
    if blockers:
        raise BootstrapBoundaryError(
            "public manifest is invalid: " + ",".join(blockers)
        )
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.output.exists() or args.output.is_symlink():
            raise BootstrapBoundaryError("output must not already exist")
        args.output.write_bytes(canonicalize_jcs(build_manifest()) + b"\n")
    except (OSError, TypeError, ValueError, BootstrapBoundaryError) as exc:
        print(f"bootstrap public manifest build failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
