#!/usr/bin/env python3
"""Render a machine-readable, side-effect-free automation readiness status."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from github_automation.operator import OperatorState, compatibility_readiness, plan_disable, plan_enable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path, help="non-secret JSON observation file")
    parser.add_argument("--operation", choices=("enable", "disable"), default="enable")
    args = parser.parse_args(argv)
    try:
        raw = json.loads(args.state.read_text(encoding="utf-8"))
        state = OperatorState(
            repository=raw["repository"],
            ci_mode=raw.get("ci_mode", "github"),
            enable_completed=tuple(raw.get("enable_completed", ())),
            disable_completed=tuple(raw.get("disable_completed", ())),
            external_facts=raw.get("external_facts", {}),
            bootstrap_repository_created=raw.get("bootstrap_repository_created", False),
        )
        readiness = compatibility_readiness({"repository": state.repository, **raw.get("compatibility", {})})
        decision = plan_enable(state, readiness) if args.operation == "enable" else plan_disable(state)
        print(json.dumps({"readiness": readiness.as_dict(), "operator": decision.as_dict()}, sort_keys=True))
        return 0 if decision.status == "complete" else 3 if decision.status == "blocked" else 2
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc), "status": "invalid"}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
