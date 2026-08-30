#!/usr/bin/env python3
"""Agent-facing CLI for selected-repository Windows CI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.agent_operator import (  # noqa: E402
    AgentOperator,
    AgentOperatorError,
    HostConfig,
    OperatorPaths,
    PrivateOperatorStore,
    resolve_current_repository,
)


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="self-hosted-ci")
    cli.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("SELF_HOSTED_CI_CONFIG", "~/.config/self-hosted-ci/config.json")).expanduser(),
    )
    cli.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("SELF_HOSTED_CI_STATE_DIR", "~/.config/self-hosted-ci/operator")).expanduser(),
    )
    commands = cli.add_subparsers(dest="command", required=True)
    for name in ("status", "use-local", "use-github"):
        command = commands.add_parser(name)
        command.add_argument("repository", nargs="?")
        if name != "status":
            command.add_argument("--apply", action="store_true")
    run = commands.add_parser("run-local")
    run.add_argument("repository", nargs="?")
    run.add_argument("--pr", required=True, type=int)
    run.add_argument("--apply", action="store_true")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("repository", nargs="?")
    return cli


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        repository = getattr(args, "repository", None) or resolve_current_repository()
        operator = AgentOperator(
            PrivateOperatorStore(OperatorPaths(args.state_dir)),
            HostConfig.load(args.config),
        )
        if args.command == "status":
            result = operator.status(repository)
        elif args.command == "use-local":
            result = operator.use_local(repository, apply=args.apply)
        elif args.command == "use-github":
            result = operator.use_github(repository, apply=args.apply)
        elif args.command == "run-local":
            result = operator.run_local(repository, args.pr, apply=args.apply)
        else:
            result = operator.status(repository)
            result["doctor"] = "healthy" if result["health"]["eligible"] else "blocked"
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("status") not in {"blocked", "error"} else 3
    except AgentOperatorError as exc:
        print(json.dumps({
            "status": "error", "code": exc.code, "message": str(exc), "details": exc.details,
        }, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
