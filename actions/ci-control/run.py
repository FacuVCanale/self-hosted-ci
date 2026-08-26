#!/usr/bin/env python3
"""Narrow GitHub Action entry point for the public CI control runtime."""

from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from github_automation.coordinator import main  # noqa: E402


COMMANDS = {
    "coordinate": ["coordinate"],
    "reconcile": ["reconcile"],
    "child": ["child"],
    "child-claim": ["child", "--claim"],
    "child-mark-started": ["child", "--mark-started"],
    "child-complete-hosted": ["child", "--complete-hosted"],
}


def run() -> int:
    command = os.environ.get("CI_CONTROL_COMMAND", "")
    argv = COMMANDS.get(command)
    if argv is None:
        print(f"unsupported ci-control command: {command!r}", file=sys.stderr)
        return 2
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(run())
