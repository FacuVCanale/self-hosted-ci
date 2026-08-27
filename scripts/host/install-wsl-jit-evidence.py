#!/usr/bin/env python3
"""Atomically install an already verified WSL JIT evidence bundle."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.crypto import parse_ijson


class InstallError(ValueError):
    pass


def regular_file(path: Path, root: Path | None = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise InstallError(f"not a regular file: {path}")
    if root is not None and root.resolve() not in path.resolve().parents:
        raise InstallError(f"file escapes measurement root: {path}")


def safe_ref(root: Path, ref: str) -> Path:
    relative = PurePosixPath(ref)
    if not ref or relative.is_absolute() or ".." in relative.parts:
        raise InstallError(f"invalid evidence ref: {ref!r}")
    path = root.joinpath(*relative.parts)
    regular_file(path, root)
    return path


def install(evidence: Path, measurement_root: Path, target_root: Path) -> None:
    if os.geteuid() != 0:
        raise InstallError("evidence installation must run as root")
    regular_file(evidence)
    if measurement_root.is_symlink() or not measurement_root.is_dir():
        raise InstallError("measurement root is not a real directory")
    if target_root.is_symlink() or not target_root.is_dir():
        raise InstallError("target root is not a real directory")

    value = parse_ijson(evidence.read_bytes())
    artifacts = value.get("measurements", {}).get("artifacts", [])
    records = {item.get("ref"): item for item in artifacts if isinstance(item, dict)}
    if len(records) != len(artifacts) or None in records:
        raise InstallError("measurement artifact records are invalid or duplicated")
    required = {
        ref
        for component in value.get("components", [])
        for ref in component.get("evidence_refs", [])
    }
    required.update(
        ref
        for check in value.get("host_security", {}).get("checks", [])
        for ref in check.get("evidence_refs", [])
    )
    if set(records) != required:
        raise InstallError(
            "measurement artifacts are not the exact signed reference set"
        )

    target_evidence = target_root / "host-evidence"
    target_bundle = target_root / "runner-boundary-v2.json"
    for target in (target_evidence, target_bundle):
        if target.is_symlink():
            raise InstallError(f"refusing symlink target: {target}")

    stage = Path(tempfile.mkdtemp(prefix=".host-evidence.stage.", dir=target_root))
    bundle_stage = target_root / f".runner-boundary-v2.{os.getpid()}.tmp"
    backup = target_root / f".host-evidence.backup.{os.getpid()}"
    replaced = False
    committed = False
    try:
        os.chown(stage, 0, 0)
        os.chmod(stage, 0o750)
        for ref, record in sorted(records.items()):
            if record.get("uid") != 0 or record.get("gid") != 0:
                raise InstallError(f"signed evidence is not root-owned: {ref}")
            mode_text = record.get("mode")
            if (
                not isinstance(mode_text, str)
                or len(mode_text) != 4
                or any(ch not in "01234567" for ch in mode_text)
            ):
                raise InstallError(f"signed evidence mode is invalid: {ref}")
            mode = int(mode_text, 8)
            if mode & 0o7137:
                raise InstallError(
                    f"signed evidence is writable/executable outside root: {ref}"
                )
            source = safe_ref(measurement_root, ref)
            destination = stage.joinpath(*PurePosixPath(ref).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            parent = destination.parent
            while parent != stage.parent:
                os.chown(parent, 0, 0)
                os.chmod(parent, 0o750)
                parent = parent.parent
            shutil.copyfile(source, destination, follow_symlinks=False)
            os.chown(destination, 0, 0)
            os.chmod(destination, mode)

        shutil.copyfile(evidence, bundle_stage, follow_symlinks=False)
        os.chown(bundle_stage, 0, 0)
        os.chmod(bundle_stage, 0o640)
        if target_evidence.exists():
            if not target_evidence.is_dir():
                raise InstallError("existing host-evidence target is not a directory")
            os.replace(target_evidence, backup)
        os.replace(stage, target_evidence)
        replaced = True
        os.replace(bundle_stage, target_bundle)
        committed = True
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if replaced and not committed:
            if target_evidence.exists():
                shutil.rmtree(target_evidence)
            if backup.exists():
                os.replace(backup, target_evidence)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
        if bundle_stage.exists():
            bundle_stage.unlink()
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--measurement-root", required=True, type=Path)
    parser.add_argument("--target-root", default=Path("/etc/self-hosted-ci"), type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.evidence, args.measurement_root, args.target_root)
    except (OSError, InstallError, TypeError, ValueError) as exc:
        print(f"evidence installation blocked: {exc}", file=sys.stderr)
        return 2
    print(
        '{"status":"installed","bundle":"runner-boundary-v2.json","measurement_root":"host-evidence","root_owned":true,"symlinks":false}'
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
