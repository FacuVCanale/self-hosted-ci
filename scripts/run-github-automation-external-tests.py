#!/usr/bin/env python3
"""Fail-closed launcher for credentialed/host GitHub automation suites.

The repository intentionally contains no live GitHub, WSL, or pilot adapter.
An operator supplies an exact command and the suite-specific prerequisites.
Missing prerequisites are an explicit blocked result (exit 3), never a skip.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "tests/github_automation/fixtures/external-suites-v1.json"
BLOCKED = 3


def _contract() -> Mapping[str, object]:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if value.get("contract_version") != 1 or not isinstance(value.get("suites"), dict):
        raise RuntimeError("external suite contract is invalid")
    return value


def _blocked(suite: str, missing: Sequence[str], evidence: str) -> int:
    result = {
        "external_test_contract_version": 1,
        "suite": suite,
        "status": "blocked",
        "reason": "missing explicit external prerequisites",
        "missing": list(missing),
        "required_evidence": evidence,
    }
    print(json.dumps(result, sort_keys=True))
    return BLOCKED


def main(argv: Sequence[str] | None = None, environment: Mapping[str, str] | None = None) -> int:
    contract = _contract()
    suites = contract["suites"]
    assert isinstance(suites, dict)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=tuple(suites))
    args = parser.parse_args(argv)
    env = dict(os.environ if environment is None else environment)
    config = suites[args.suite]
    if not isinstance(config, dict):
        raise RuntimeError(f"external suite {args.suite} contract is invalid")
    required = config.get("required_env")
    command_env = config.get("command_env")
    evidence = config.get("evidence")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise RuntimeError(f"external suite {args.suite} prerequisites are invalid")
    if not isinstance(command_env, str) or not isinstance(evidence, str):
        raise RuntimeError(f"external suite {args.suite} command/evidence contract is invalid")
    missing = [name for name in required if not env.get(name, "").strip()]
    if missing:
        return _blocked(args.suite, missing, evidence)
    command = shlex.split(env[command_env])
    if not command:
        return _blocked(args.suite, [command_env], evidence)
    completed = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if completed.returncode != 0:
        print(json.dumps({
            "external_test_contract_version": 1,
            "suite": args.suite,
            "status": "failed",
            "command_exit_code": completed.returncode,
            "required_evidence": evidence,
        }, sort_keys=True))
        return completed.returncode or 1
    print(json.dumps({
        "external_test_contract_version": 1,
        "suite": args.suite,
        "status": "passed",
        "required_evidence": evidence,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
