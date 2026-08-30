#!/usr/bin/env python3
"""Install the shared Codex/Claude skill and agent-facing CLI on macOS/Linux."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
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


def validate_link(link: Path, target: Path) -> bool:
    if link.is_symlink() and link.resolve() == target.resolve():
        return False
    if link.exists() or link.is_symlink():
        raise SystemExit(f"refusing to replace existing path: {link}")
    return True


def create_symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    link.symlink_to(target, target_is_directory=target.is_dir())


def atomic_private_json(path: Path, value: dict[str, str]) -> None:
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
        planned = [(link, target) for link, target in links if validate_link(link, target)]
        try:
            for link, target in planned:
                create_symlink(link, target)
                created.append(link)
            # Config is the commit point: agents cannot discover a half-installed interface.
            atomic_private_json(config, value)
        except BaseException:
            for link in reversed(created):
                if link.is_symlink():
                    link.unlink()
            raise
    print(json.dumps({
        "status": "installed",
        "cli": str(args.bin_dir / "self-hosted-ci"),
        "codex_skill": str(Path("~/.codex/skills/self-hosted-ci").expanduser()),
        "claude_skill": str(Path("~/.claude/skills/self-hosted-ci").expanduser()),
        "config": str(config),
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
