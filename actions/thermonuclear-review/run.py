#!/usr/bin/env python3
"""Publish policy provenance while the external reviewer remains blocked."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "skills/thermo-nuclear-code-quality-review/SKILL.md"


def append(path_name: str, lines: tuple[str, ...]) -> None:
    destination = os.environ.get(path_name)
    if not destination:
        return
    with Path(destination).open("a", encoding="utf-8") as handle:
        handle.writelines(f"{line}\n" for line in lines)


def run() -> int:
    if os.environ.get("REVIEW_MODE") != "informational":
        print("thermonuclear review supports informational mode only", file=sys.stderr)
        return 2
    if os.environ.get("ACTIVATION_APPROVED") != "false":
        print(
            "thermonuclear review is blocked: this distribution has no approved model or GitHub delivery adapter",
            file=sys.stderr,
        )
        return 2
    digest = hashlib.sha256(POLICY.read_bytes()).hexdigest()
    append("GITHUB_OUTPUT", ("status=blocked", f"policy_sha256={digest}"))
    append(
        "GITHUB_STEP_SUMMARY",
        (
            "## Thermonuclear PR reviewer",
            "",
            "Status: **blocked / informational only**.",
            "",
            "The review policy is versioned with this Action, but no model is called, no PR code is executed, and no review is posted.",
            f"Policy SHA-256: `{digest}`",
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
