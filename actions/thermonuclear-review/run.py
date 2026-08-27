#!/usr/bin/env python3
"""Entrypoint for the hosted Thermonuclear informational reviewer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from github_automation.hosted_reviewer import (  # noqa: E402
    DEFAULT_MODEL,
    HostedReviewer,
    GitHubAppClient,
    OpenAIResponsesProvider,
    PullRequestIdentity,
    ReviewLimits,
)


POLICY_PATH = Path(__file__).with_name("policy-v1.md")
PROVENANCE_PATH = Path(__file__).with_name("provenance-v1.json")


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"required environment variable is missing: {name}")
    return value


def _positive_int(name: str) -> int:
    value = int(_required(name))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _append(name: str, lines: list[str]) -> None:
    destination = os.environ.get(name)
    if destination:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")


def _verify_policy() -> str:
    policy = POLICY_PATH.read_text(encoding="utf-8")
    provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    digest = hashlib.sha256(policy.encode("utf-8")).hexdigest()
    if provenance.get("local_policy", {}).get("sha256") != digest:
        raise ValueError("clean-room policy provenance digest mismatch")
    return policy


def run() -> int:
    enabled = os.environ.get("THERMONUCLEAR_ENABLED", "false").lower()
    if enabled != "true":
        _append("GITHUB_OUTPUT", ["status=disabled"])
        _append(
            "GITHUB_STEP_SUMMARY",
            [
                "## Thermonuclear PR reviewer",
                "",
                "Status: **disabled** (opt-in only).",
                "No GitHub App or model request was attempted.",
            ],
        )
        return 0
    policy = _verify_policy()
    identity = PullRequestIdentity(
        repository=_required("THERMONUCLEAR_REPOSITORY"),
        number=_positive_int("THERMONUCLEAR_PR_NUMBER"),
        base_sha=_required("THERMONUCLEAR_BASE_SHA"),
        head_sha=_required("THERMONUCLEAR_HEAD_SHA"),
    )
    for sha in (identity.base_sha, identity.head_sha):
        if len(sha) != 40 or any(char not in "0123456789abcdef" for char in sha):
            raise ValueError("base/head SHA must be exact lowercase SHA-1")
    app_id = _positive_int("THERMONUCLEAR_APP_ID")
    github = GitHubAppClient(
        app_id=app_id,
        expected_app_id=_positive_int("THERMONUCLEAR_EXPECTED_APP_ID"),
        installation_id=_positive_int("THERMONUCLEAR_INSTALLATION_ID"),
        private_key_pem=_required("THERMONUCLEAR_APP_PRIVATE_KEY"),
        repository=identity.repository,
    )
    provider = OpenAIResponsesProvider(
        _required("OPENAI_API_KEY"),
        model=os.environ.get("THERMONUCLEAR_MODEL", DEFAULT_MODEL),
        policy=policy,
    )
    comment_id = HostedReviewer(github, provider, limits=ReviewLimits()).run(identity)
    _append("GITHUB_OUTPUT", ["status=commented", f"comment_id={comment_id}"])
    _append(
        "GITHUB_STEP_SUMMARY",
        [
            "## Thermonuclear PR reviewer",
            "",
            "An informational App-owned comment was created or updated.",
            f"Reviewed head: `{identity.head_sha}`",
            f"Comment id: `{comment_id}`",
        ],
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except Exception as exc:
        print(f"thermonuclear reviewer failed closed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
