#!/usr/bin/env python3
"""Reject external edge-runtime code, credentials, dependencies, and deployment surfaces."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
TEST_FILE = "tests/github_automation/test_local_only_guard.py"
FORBIDDEN_FILE_NAMES = re.compile(r"^wrangler(?:\..+)?$", re.IGNORECASE)
FORBIDDEN_CONTENT = (
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"\bwrangler\b", re.IGNORECASE),
    re.compile(r"\bcompatibility_date\b", re.IGNORECASE),
    re.compile(r"\bdurable_objects\b", re.IGNORECASE),
    re.compile(r"\bworkers\.dev\b", re.IGNORECASE),
)
OPERATIONAL_SUFFIXES = {
    ".cjs", ".js", ".json", ".jsonc", ".mjs", ".ps1", ".py", ".sh",
    ".toml", ".ts", ".yaml", ".yml",
}
OPERATIONAL_NAMES = {"Makefile", "Dockerfile", "package-lock.json", "package.json"}


def repository_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, capture_output=True,
    )
    return [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def candidate_files(root: Path) -> list[Path]:
    if (root / ".git").exists():
        return repository_files(root)
    return [path for path in root.rglob("*") if path.is_file()]


def is_operational(path: Path) -> bool:
    return path.suffix.lower() in OPERATIONAL_SUFFIXES or path.name in OPERATIONAL_NAMES


def violations(root: Path) -> list[str]:
    errors: list[str] = []
    for path in candidate_files(root):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.resolve() == SELF or relative.as_posix() == TEST_FILE:
            continue
        if FORBIDDEN_FILE_NAMES.match(path.name):
            errors.append(f"forbidden deployment configuration: {relative}")
            continue
        if not is_operational(path):
            continue
        if FORBIDDEN_CONTENT[0].search(relative.as_posix()):
            errors.append(f"forbidden provider token in operational path: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in FORBIDDEN_CONTENT:
            if pattern.search(text):
                errors.append(f"forbidden external runtime capability in {relative}: {pattern.pattern}")
                break
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    args = parser.parse_args()
    errors = violations(args.root.resolve())
    if errors:
        raise SystemExit("\n".join(errors))
    print("local-only capability guard: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
