#!/usr/bin/env python3
"""Install the shared Codex/Claude skill and agent-facing CLI on macOS/Linux."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import hashlib
import subprocess
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.agent_operator import DISTRO, FULL_SHA, SSH_TARGET, exact_repository  # noqa: E402


SKILL = ROOT / "skills/self-hosted-ci"
CLI = ROOT / "scripts/self-hosted-ci.py"
ROTATION_CEREMONY = ROOT / "scripts/host/run-overworld-rotation-ceremony.sh"


def validate_link(link: Path, target: Path) -> bool:
    if link.is_symlink() and link.resolve() == target.resolve():
        return False
    if link.exists() or link.is_symlink():
        raise SystemExit(f"refusing to replace existing path: {link}")
    return True


def create_symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    link.symlink_to(target, target_is_directory=target.is_dir())


def atomic_private_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_bytes(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_identity(path: Path) -> tuple[int, int, int, int, int]:
    value = path.stat()
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, stat.S_IMODE(value.st_mode))


@contextmanager
def installation_lock(config: Path):
    config.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = config.parent / "install.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--ssh-key", required=True, type=Path)
    parser.add_argument("--distro", default="Ubuntu-24.04-CI")
    parser.add_argument("--public-repository", default="FacuVCanale/self-hosted-ci")
    parser.add_argument("--public-sha", required=True)
    parser.add_argument("--config", type=Path, default=Path("~/.config/self-hosted-ci/config.json").expanduser())
    parser.add_argument("--bin-dir", type=Path, default=Path("~/.local/bin").expanduser())
    parser.add_argument("--install-rotation-ceremony", action="store_true")
    parser.add_argument("--acknowledge-rotation-ceremony-replacement", action="store_true")
    parser.add_argument("--rotation-ceremony-target", type=Path, default=Path("~/.local/share/self-hosted-ci/ceremony.sh").expanduser())
    parser.add_argument("--rotation-ceremony-receipt", type=Path, default=Path("~/.config/self-hosted-ci/rotation-ceremony-install.json").expanduser())
    args = parser.parse_args()
    if not SKILL.is_dir() or not CLI.is_file():
        raise SystemExit("distribution is missing the shared skill or CLI")
    if not SSH_TARGET.fullmatch(args.ssh_target):
        raise SystemExit("SSH target is invalid")
    if not DISTRO.fullmatch(args.distro):
        raise SystemExit("WSL distro name is invalid")
    exact_repository(args.public_repository)
    if not FULL_SHA.fullmatch(args.public_sha):
        raise SystemExit("public SHA must be a full lowercase commit SHA")
    key = args.ssh_key.expanduser().resolve()
    if not key.is_file():
        raise SystemExit("SSH identity file is unavailable")
    config = args.config.expanduser()
    ceremony_target = args.rotation_ceremony_target.expanduser()
    ceremony_receipt = args.rotation_ceremony_receipt.expanduser()
    ceremony_source: bytes | None = None
    previous_ceremony: bytes | None = None
    previous_ceremony_mode: int | None = None
    previous_ceremony_receipt: bytes | None = None
    previous_ceremony_receipt_mode: int | None = None
    previous_ceremony_identity: tuple[int, int, int, int, int] | None = None
    previous_ceremony_receipt_identity: tuple[int, int, int, int, int] | None = None
    if args.install_rotation_ceremony:
        if not ROTATION_CEREMONY.is_file() or ROTATION_CEREMONY.is_symlink():
            raise SystemExit("tracked rotation ceremony is absent or unsafe")
        ceremony_source = ROTATION_CEREMONY.read_bytes()
        committed = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{args.public_sha}:scripts/host/run-overworld-rotation-ceremony.sh"],
            check=True, capture_output=True,
        ).stdout
        if committed != ceremony_source:
            raise SystemExit("rotation ceremony source differs from the requested commit")
    links = [
        (Path("~/.codex/skills/self-hosted-ci").expanduser(), SKILL),
        (Path("~/.claude/skills/self-hosted-ci").expanduser(), SKILL),
        (args.bin_dir.expanduser() / "self-hosted-ci", CLI),
    ]
    value = {
        "ssh_target": args.ssh_target,
        "ssh_key": str(key),
        "distro": args.distro,
        "public_repository": args.public_repository,
        "public_sha": args.public_sha,
    }
    created: list[Path] = []
    with installation_lock(config):
        if ceremony_source is not None:
            if ceremony_target.exists() or ceremony_target.is_symlink():
                if ceremony_target.is_symlink() or not ceremony_target.is_file():
                    raise SystemExit("refusing to replace an unsafe rotation ceremony target")
                if not args.acknowledge_rotation_ceremony_replacement:
                    raise SystemExit("rotation ceremony replacement requires explicit acknowledgement")
                previous_ceremony = ceremony_target.read_bytes()
                previous_ceremony_mode = stat.S_IMODE(ceremony_target.stat().st_mode)
                previous_ceremony_identity = file_identity(ceremony_target)
            if ceremony_receipt.exists() or ceremony_receipt.is_symlink():
                if ceremony_receipt.is_symlink() or not ceremony_receipt.is_file():
                    raise SystemExit("refusing to replace an unsafe rotation ceremony receipt")
                previous_ceremony_receipt = ceremony_receipt.read_bytes()
                previous_ceremony_receipt_mode = stat.S_IMODE(ceremony_receipt.stat().st_mode)
                previous_ceremony_receipt_identity = file_identity(ceremony_receipt)
        planned = [(link, target) for link, target in links if validate_link(link, target)]
        try:
            for link, target in planned:
                create_symlink(link, target)
                created.append(link)
            if ceremony_source is not None:
                current_source = ROTATION_CEREMONY.read_bytes()
                current_committed = subprocess.run(
                    ["git", "-C", str(ROOT), "show", f"{args.public_sha}:scripts/host/run-overworld-rotation-ceremony.sh"],
                    check=True, capture_output=True,
                ).stdout
                if current_source != ceremony_source or current_committed != ceremony_source:
                    raise RuntimeError("rotation ceremony source changed while waiting for the installation lock")
                if previous_ceremony is not None and (
                    file_identity(ceremony_target) != previous_ceremony_identity
                    or ceremony_target.read_bytes() != previous_ceremony
                ):
                    raise RuntimeError("rotation ceremony target changed while waiting for replacement")
                if previous_ceremony_receipt is not None and (
                    file_identity(ceremony_receipt) != previous_ceremony_receipt_identity
                    or ceremony_receipt.read_bytes() != previous_ceremony_receipt
                ):
                    raise RuntimeError("rotation ceremony receipt changed while waiting for replacement")
                atomic_bytes(ceremony_target, ceremony_source, 0o700)
                installed = ceremony_target.read_bytes()
                if installed != ceremony_source:
                    raise RuntimeError("installed rotation ceremony differs from committed source")
                atomic_private_json(ceremony_receipt, {
                    "install_receipt_version": 1,
                    "installed_ceremony_sha256": sha256(installed),
                    "previous_ceremony_sha256": sha256(previous_ceremony) if previous_ceremony is not None else None,
                    "public_sha": args.public_sha,
                })
            # Config is the commit point: agents cannot discover a half-installed interface.
            atomic_private_json(config, value)
        except BaseException:
            for link in reversed(created):
                if link.is_symlink():
                    link.unlink()
            if ceremony_source is not None:
                if previous_ceremony is None:
                    ceremony_target.unlink(missing_ok=True)
                else:
                    assert previous_ceremony_mode is not None
                    atomic_bytes(ceremony_target, previous_ceremony, previous_ceremony_mode)
                if previous_ceremony_receipt is None:
                    ceremony_receipt.unlink(missing_ok=True)
                else:
                    assert previous_ceremony_receipt_mode is not None
                    atomic_bytes(ceremony_receipt, previous_ceremony_receipt, previous_ceremony_receipt_mode)
            raise
    print(json.dumps({
        "status": "installed",
        "cli": str(args.bin_dir / "self-hosted-ci"),
        "codex_skill": str(Path("~/.codex/skills/self-hosted-ci").expanduser()),
        "claude_skill": str(Path("~/.claude/skills/self-hosted-ci").expanduser()),
        "config": str(config),
        "rotation_ceremony": str(ceremony_target) if ceremony_source is not None else None,
        "rotation_ceremony_receipt": str(ceremony_receipt) if ceremony_source is not None else None,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
