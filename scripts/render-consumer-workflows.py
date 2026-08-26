#!/usr/bin/env python3
"""Render inert workflow templates with an immutable public runtime reference."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / "templates/workflows"
PLACEHOLDER_REPOSITORY = "FacuVCanale/self-hosted-ci"
PLACEHOLDER_SHA = "0" * 40
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=PLACEHOLDER_REPOSITORY)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not REPOSITORY.fullmatch(args.repository):
        raise SystemExit("--repository must be an owner/repository name")
    if not FULL_SHA.fullmatch(args.sha) or args.sha == PLACEHOLDER_SHA:
        raise SystemExit("--sha must be a non-zero full 40-character lowercase commit SHA")
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise SystemExit("--output must be outside the distribution repository")
    output.mkdir(parents=True, exist_ok=True)
    for source in sorted(WORKFLOWS.glob("*.yml")):
        rendered = source.read_text(encoding="utf-8").replace(
            f"{PLACEHOLDER_REPOSITORY}/", f"{args.repository}/"
        ).replace(f"@{PLACEHOLDER_SHA}", f"@{args.sha}")
        (output / source.name).write_text(rendered, encoding="utf-8")
    reviewer = ROOT / "examples/workflows/thermonuclear-review.yml"
    rendered = reviewer.read_text(encoding="utf-8").replace(
        f"{PLACEHOLDER_REPOSITORY}/", f"{args.repository}/"
    ).replace(f"@{PLACEHOLDER_SHA}", f"@{args.sha}")
    (output / reviewer.name).write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
