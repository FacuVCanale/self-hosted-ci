#!/usr/bin/env python3
"""Root entry point for the isolated JIT canary matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[2]
if (repo_root / "github_automation").is_dir():
    sys.path.insert(0, str(repo_root))

from github_automation.canary_worker import (  # noqa: E402
    CanaryRuntime,
    CanaryRuntimeError,
    CanaryRebootRequired,
    load_live_canary_driver,
    read_root_json,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/self-hosted-ci/canary-runtime.json")
    parser.add_argument(
        "--authorization", default="/etc/self-hosted-ci/canary-authorization.json"
    )
    parser.add_argument("--resume-nonce")
    parser.add_argument(
        "command", choices=("verify", "prepare", "execute", "production-fence")
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "production-fence":
            from github_automation.canary_worker import assert_production_fence

            assert_production_fence()
            value = {"status": "production-fence-clear"}
        else:
            runtime = CanaryRuntime(
                read_root_json(Path(args.config)),
                read_root_json(Path(args.authorization)),
            )
            if args.resume_nonce is not None and (
                args.command != "execute"
                or runtime.authorization.get("nonce") != args.resume_nonce
            ):
                raise CanaryRuntimeError("resume nonce crossed signed authorization")
            if args.command == "verify" and Path(
                "/run/self-hosted-ci/CANARY_APPROVED"
            ).exists():
                authorization, store = runtime.verify_prepared()
            elif args.command == "execute":
                driver = load_live_canary_driver(
                    runtime.config, runtime.authorization
                )
                value = runtime.execute(driver)
                print(json.dumps(value, sort_keys=True, separators=(",", ":")))
                return 0
            else:
                authorization, store = runtime.preflight()
            if args.command == "prepare":
                runtime.prepare(store, store.load()["authorization_digest"])
            value = {
                "status": "verified" if args.command == "verify" else "prepared",
                "nonce": authorization.nonce,
                "production_activation_changed": False,
                "outbound_worker_started": False,
            }
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except CanaryRebootRequired as exc:
        print(
            json.dumps(
                {
                    "status": "reboot-checkpoint",
                    "nonce": runtime.authorization["nonce"],
                    "allocation_id": exc.allocation_id,
                    "runner_label": exc.runner_label,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 75
    except (CanaryRuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"canary matrix blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
