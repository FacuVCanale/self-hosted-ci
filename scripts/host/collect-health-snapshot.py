#!/usr/bin/env python3
"""Produce one strict, side-effect-free WSL health observation on stdout."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess


SERVICES = (
    "incus.service",
    "self-hosted-ci-boundary-verify.service",
    "self-hosted-ci-egress-proxy.service",
    "self-hosted-ci-garm.service",
    "self-hosted-ci-health-heartbeat.timer",
    "self-hosted-ci-network-policy.service",
)


def systemd_state(name: str) -> dict[str, str]:
    def query(operation: str) -> tuple[str, int]:
        result = subprocess.run(
            ["systemctl", operation, name], text=True, capture_output=True, check=False,
            timeout=10,
        )
        return result.stdout.strip(), result.returncode

    active, active_code = query("is-active")
    enabled, enabled_code = query("is-enabled")
    return {
        "active": active if active_code in (0, 3) else "unknown",
        "enabled": enabled if enabled_code in (0, 1) else "unknown",
    }


def heartbeat(path: Path, maximum_age: int, now: datetime) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "absent", "observed_at": None, "age_seconds": None,
        "max_age_seconds": maximum_age,
    }
    if not path.is_file() or path.is_symlink():
        return result
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if set(payload) != {"schema_version", "written_at"} or payload["schema_version"] != 1:
            result["status"] = "invalid"
            return result
        written = datetime.fromisoformat(payload["written_at"].replace("Z", "+00:00"))
        if written.tzinfo is None:
            raise ValueError("heartbeat timestamp has no timezone")
        age = max(0, int((now - written.astimezone(timezone.utc)).total_seconds()))
        result.update(
            status="fresh" if age <= maximum_age else "stale",
            observed_at=written.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            age_seconds=age,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        result["status"] = "invalid"
    return result


def observe(distro: str, maximum_age: int) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    install = Path("/opt/self-hosted-ci/actions-runner")
    registered = any((install / name).exists() for name in (".runner", ".credentials", ".credentials_rsaparams"))
    installed = (
        (install / ".self-hosted-ci-install").is_file()
        and (install / "bin/Runner.Listener").is_file()
        and os.access(install / "bin/Runner.Listener", os.X_OK)
    )
    os_release = {}
    with Path("/etc/os-release").open(encoding="utf-8") as handle:
        os_release = {key: value.strip('"') for key, value in (line.rstrip().split("=", 1) for line in handle if "=" in line)}
    heartbeat_state = heartbeat(Path("/var/lib/self-hosted-ci/health/heartbeat.json"), maximum_age, now)
    services = {name: systemd_state(name) for name in SERVICES}
    boundary = {
        "activation_approved": Path("/etc/self-hosted-ci/ACTIVATION_APPROVED").is_file(),
        "network_policy_enabled": Path("/etc/self-hosted-ci/runner-network-v2.enabled").is_file(),
    }
    reasons: list[str] = []
    if "wsl2" not in platform.release().lower(): reasons.append("platform_not_verified")
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04": reasons.append("platform_not_verified")
    if os.environ.get("WSL_DISTRO_NAME") != distro: reasons.append("dedicated_distro_not_verified")
    if not installed: reasons.append("runner_not_installed")
    if registered: reasons.append("runner_registration_not_clean")
    if heartbeat_state["status"] != "fresh": reasons.append("heartbeat_not_fresh")
    if not boundary["activation_approved"]: reasons.append("activation_not_approved")
    if not boundary["network_policy_enabled"]: reasons.append("network_policy_not_enabled")
    for name in SERVICES:
        if services[name]["active"] != "active": reasons.append(f"service_not_active:{name}")
        if services[name]["enabled"] not in ({"enabled"} if name in {"incus.service", "self-hosted-ci-garm.service", "self-hosted-ci-health-heartbeat.timer"} else {"enabled", "static"}):
            reasons.append(f"service_not_enabled:{name}")
    reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": 1,
        "observed_at": now.isoformat().replace("+00:00", "Z"),
        "distro": {"name": distro, "platform": "wsl2" if "wsl2" in platform.release().lower() else "unknown", "os_id": os_release.get("ID"), "os_version": os_release.get("VERSION_ID")},
        "runner": {"installed": installed, "registered": registered, "labels": ["linux", "self-hosted", "wsl-jit", "x64"]},
        "services": services,
        "heartbeat": heartbeat_state,
        "boundary": boundary,
        "eligibility": {"eligible_for_local_ci": not reasons, "blocking_reasons": reasons},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="Ubuntu-24.04-CI")
    parser.add_argument("--heartbeat-max-age", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.heartbeat_max_age <= 86400:
        raise SystemExit("invalid heartbeat maximum age")
    print(json.dumps(observe(args.distro, args.heartbeat_max_age), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
