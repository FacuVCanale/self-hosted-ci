#!/usr/bin/env python3
"""Fail closed when public workflow distribution boundaries drift."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_SHA = "0" * 40
ACTION_REF = re.compile(
    r"uses:\s+FacuVCanale/self-hosted-ci/(actions/[a-z0-9-]+)@([0-9a-f]{40})"
)
WORKFLOW_REF = re.compile(
    r"uses:\s+FacuVCanale/self-hosted-ci/(\.github/workflows/thermonuclear-review\.yml)@([0-9a-f]{40})"
)


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
                errors.append(
                    f"{path.relative_to(ROOT)} source template must retain the render placeholder"
                )
    expected_action_counts = {
        "actions/ci-control": 6,
        "actions/jit-canary-validate": 1,
        "actions/jit-pilot-validate": 1,
    }
    observed_action_counts = {
        action: sum(1 for observed, _ in references if observed == action)
        for action in {action for action, _ in references}
    }
    if observed_action_counts != expected_action_counts:
        errors.append(
            "CI workflow templates do not reference the exact public Action set: "
            f"expected {expected_action_counts}, found {observed_action_counts}"
        )
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        if PLACEHOLDER_SHA in path.read_text(encoding="utf-8"):
            errors.append(
                f"active workflow contains an unresolved SHA: {path.relative_to(ROOT)}"
            )
    reviewer = (ROOT / "actions/thermonuclear-review/action.yml").read_text(
        encoding="utf-8"
    )
    example = (ROOT / "examples/workflows/thermonuclear-review.yml").read_text(
        encoding="utf-8"
    )
    hosted = (ROOT / ".github/workflows/thermonuclear-review.yml").read_text(
        encoding="utf-8"
    )
    workflow_refs = WORKFLOW_REF.findall(example)
    if workflow_refs != [
        (".github/workflows/thermonuclear-review.yml", PLACEHOLDER_SHA)
    ]:
        errors.append(
            "thermonuclear example must pin exactly one reusable-workflow placeholder"
        )
    for forbidden in ("pull-requests: write", "checks: write", "issues: write"):
        if forbidden in example:
            errors.append(f"thermonuclear bootstrap unexpectedly grants {forbidden}")
    if (
        'default: "false"' not in reviewer
        or "THERMONUCLEAR_REVIEWER_ENABLED == 'true'" not in hosted
    ):
        errors.append("thermonuclear activation is not double-gated")
    if (
        "actions/checkout" in hosted
        or "job.workflow_sha" not in hosted
        or "job.workflow_repository" not in hosted
    ):
        errors.append(
            "thermonuclear reusable workflow does not load its exact trusted source"
        )
    if errors:
        raise SystemExit("\n".join(errors))
    print("public distribution boundaries: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
