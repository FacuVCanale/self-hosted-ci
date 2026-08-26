"""Inert command surface used by the trusted workflow templates.

The module validates packages and exposes stable subcommands, but deliberately
does not mint App tokens or infer missing production authority. Network side
effects require an installed control-plane adapter that is outside this
bootstrap repository.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping

from .github import ProtocolFailure, ProtocolPackage


class CoordinatorUnavailable(RuntimeError):
    pass


def _package_from_environment(environment: Mapping[str, str]) -> ProtocolPackage:
    raw = environment.get("CI_GATE_PROTOCOL_PACKAGE")
    if not raw:
        raise ProtocolFailure("CI_GATE_PROTOCOL_PACKAGE is required")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolFailure("protocol package is not valid JSON") from exc
    return ProtocolPackage.from_mapping(value)


def _assert_live_tuple(package: ProtocolPackage, environment: Mapping[str, str]) -> None:
    """Require an authoritative, adapter-supplied PR tuple before child use.

    The bootstrap has no GitHub credentialed adapter, so absence is deliberately
    a control failure instead of treating the signed dispatch package as current.
    """
    raw = environment.get("CI_GATE_CURRENT_TUPLE")
    if not raw:
        raise ProtocolFailure("authoritative CI_GATE_CURRENT_TUPLE is required")
    try:
        current = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolFailure("current GitHub tuple is not valid JSON") from exc
    if not isinstance(current, Mapping) or set(current) != {
        "repository_id", "repository", "pr_number", "head_sha", "base_sha",
        "tested_merge_sha", "generation",
    }:
        raise ProtocolFailure("current GitHub tuple fields are not exact")
    package.assert_current_tuple(**current)


def _write_outputs(package: ProtocolPackage, environment: Mapping[str, str]) -> None:
    output = environment.get("GITHUB_OUTPUT")
    if not output:
        return
    values = package.values
    lines = (
        f"backend={values['backend']}\n"
        f"tested_sha={values['tested_sha']}\n"
        f"logical_key={values['logical_key']}\n"
        f"generation={values['generation']}\n"
    )
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(lines)


def child(environment: Mapping[str, str], *, action: str = "validate") -> int:
    package = _package_from_environment(environment)
    if action == "validate":
        _assert_live_tuple(package, environment)
        _write_outputs(package, environment)
        return 0
    raise CoordinatorUnavailable(
        f"child action {action!r} requires the installed transactional control-plane adapter"
    )


def coordinate(environment: Mapping[str, str]) -> int:
    if environment.get("CI_GATE_COORDINATOR_ENABLED") != "true":
        raise CoordinatorUnavailable("coordinator is disabled by default")
    raise CoordinatorUnavailable(
        "dispatch requires the installed GitHub/GateStore adapter and exact external authority"
    )


def reconcile(environment: Mapping[str, str]) -> int:
    if environment.get("CI_GATE_COORDINATOR_ENABLED") != "true":
        raise CoordinatorUnavailable("reconciler is disabled by default")
    raise CoordinatorUnavailable(
        "reconciliation requires the installed GitHub/GateStore adapter and exact external authority"
    )


def main(argv: list[str] | None = None, environment: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m github_automation.coordinator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("coordinate")
    child_parser = subparsers.add_parser("child")
    actions = child_parser.add_mutually_exclusive_group()
    actions.add_argument("--claim", action="store_true")
    actions.add_argument("--mark-started", action="store_true")
    actions.add_argument("--complete-hosted", action="store_true")
    subparsers.add_parser("reconcile")
    args = parser.parse_args(argv)
    env = os.environ if environment is None else environment
    try:
        if args.command == "coordinate":
            return coordinate(env)
        if args.command == "reconcile":
            return reconcile(env)
        action = "claim" if args.claim else "mark-started" if args.mark_started else "complete-hosted" if args.complete_hosted else "validate"
        return child(env, action=action)
    except (ProtocolFailure, CoordinatorUnavailable) as exc:
        print(f"ci-gate control failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
