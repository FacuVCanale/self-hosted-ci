#!/usr/bin/env python3
"""Fail closed when public workflow distribution boundaries drift."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_SHA = "0" * 40
ACTION_REF = re.compile(r"uses:\s+FacuVCanale/self-hosted-ci/(actions/[a-z0-9-]+)@([0-9a-f]{40})")


def main() -> int:
    errors: list[str] = []
    references: list[tuple[str, str]] = []
    workflow_paths = sorted((ROOT / "templates/workflows").glob("*.yml")) + [
        ROOT / "examples/workflows/thermonuclear-review.yml"
    ]
    for path in workflow_paths:
        text = path.read_text(encoding="utf-8")
        if "baked into" in text:
            errors.append(f"{path.relative_to(ROOT)} assumes a baked runtime")
        matches = ACTION_REF.findall(text)
        references.extend(matches)
        for action, sha in matches:
            if not (ROOT / action / "action.yml").is_file():
                errors.append(f"{path.relative_to(ROOT)} references missing {action}")
            if sha != PLACEHOLDER_SHA:
                errors.append(f"{path.relative_to(ROOT)} source template must retain the render placeholder")
    expected_actions = {"actions/ci-control", "actions/thermonuclear-review"}
    if {action for action, _ in references} != expected_actions:
        errors.append("workflow templates do not reference both public Actions")
    if len(references) != 7:
        errors.append(f"expected 7 pinned Action call sites, found {len(references)}")
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        if PLACEHOLDER_SHA in path.read_text(encoding="utf-8"):
            errors.append(f"active workflow contains an unresolved SHA: {path.relative_to(ROOT)}")
    reviewer = (ROOT / "actions/thermonuclear-review/action.yml").read_text(encoding="utf-8")
    example = (ROOT / "examples/workflows/thermonuclear-review.yml").read_text(encoding="utf-8")
    for forbidden in ("pull-requests: write", "checks: write", "issues: write"):
        if forbidden in example:
            errors.append(f"thermonuclear bootstrap unexpectedly grants {forbidden}")
    if 'default: "false"' not in reviewer or "THERMONUCLEAR_REVIEWER_ENABLED == 'true'" not in example:
        errors.append("thermonuclear activation is not double-gated")
    if errors:
        raise SystemExit("\n".join(errors))
    print("public distribution boundaries: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
