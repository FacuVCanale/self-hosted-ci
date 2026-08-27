#!/usr/bin/env python3
"""Content-address host artifacts for the WSL JIT readiness verifier.

The collector never assigns pass/verified status. It only replaces the
measurement section and component digests with observations from disk. The
independent verifier still recomputes every byte, owner and mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.crypto import canonicalize_jcs, parse_ijson


def aggregate(records: list[dict]) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(records)).hexdigest()


def resolve_ref(root: Path, ref: str) -> Path:
    relative = PurePosixPath(ref)
    if not ref or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"invalid measurement ref: {ref!r}")
    path = root.joinpath(*relative.parts)
    resolved_root = root.resolve()
    if path.is_symlink() or not path.is_file() or resolved_root not in path.resolve().parents:
        raise ValueError(f"measurement ref is not a regular in-root file: {ref}")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--measurement-root", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        value = parse_ijson(args.input.read_bytes())
        # Any prior signature is necessarily stale after measurement. Only an
        # independent reviewer signs the completed, content-addressed bundle.
        value.pop("attestation", None)
        components = value["components"]
        refs = sorted({ref for component in components for ref in component["evidence_refs"]})
        refs.extend(
            ref for check in value["host_security"]["checks"]
            for ref in check["evidence_refs"] if ref not in refs
        )
        records: list[dict] = []
        for ref in sorted(refs):
            path = resolve_ref(args.measurement_root, ref)
            data = path.read_bytes()
            stat = os.stat(path, follow_symlinks=False)
            records.append({
                "ref": ref,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mode": f"{stat.st_mode & 0o7777:04o}",
                "uid": stat.st_uid,
                "gid": stat.st_gid,
            })
        by_ref = {record["ref"]: record for record in records}
        value["measurements"] = {
            "host_measurement_version": 1,
            "measurement_set_digest": aggregate(records),
            "artifacts": records,
        }
        for component in components:
            component["artifact_digest"] = aggregate(
                [by_ref[ref] for ref in sorted(component["evidence_refs"])]
            )
        args.output.write_bytes(canonicalize_jcs(value) + b"\n")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"measurement collection failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
