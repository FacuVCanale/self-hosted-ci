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
import stat


SERVICES = (
    "incus.service",
    "self-hosted-ci-boundary-verify.service",
    "self-hosted-ci-allocation-broker.service",
    "self-hosted-ci-egress-proxy.service",
    "self-hosted-ci-garm.service",
    "self-hosted-ci-health-heartbeat.timer",
    "self-hosted-ci-network-policy.service",
)

GARM_HEALTH_STATE = Path("/etc/self-hosted-ci/garm/health-state.json")
GARM_CONFIG = Path("/etc/self-hosted-ci/garm/config.toml")
GARM_BINARY = Path("/usr/local/bin/garm")
GARM_PROVIDER = Path("/usr/local/libexec/garm/garm-provider-incus")
GARM_CLI = Path("/usr/local/bin/garm-cli")
GARM_SESSION_HELPER = Path("/usr/local/lib/self-hosted-ci/garm-cli-session.py")
GARM_RUNTIME_HOME = "/run/self-hosted-ci/garm-cli"
GARM_SESSION_SECRETS = tuple(
    Path(f"/etc/self-hosted-ci/garm/{name}")
    for name in ("admin-username", "admin-password", "jwt-secret")
)
GARM_STATE_KEYS = {
    "schema_version",
    "manager_configured",
    "provider_configured",
    "image_configured",
    "broker_configured",
    "zero_scale_sets",
    "image",
    "targets",
    "garm_cli_home",
}
BROKER_CONFIG = Path("/etc/self-hosted-ci/garm/allocation-broker.json")
LIVE_JOB_VERIFIER = Path(
    "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py"
)


def systemd_state(name: str) -> dict[str, str]:
    def query(operation: str) -> tuple[str, int]:
        result = subprocess.run(
            ["systemctl", operation, name],
            text=True,
            capture_output=True,
            check=False,
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
        "status": "absent",
        "observed_at": None,
        "age_seconds": None,
        "max_age_seconds": maximum_age,
    }
    if not path.is_file() or path.is_symlink():
        return result
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            set(payload) != {"schema_version", "written_at"}
            or payload["schema_version"] != 1
        ):
            result["status"] = "invalid"
            return result
        written = datetime.fromisoformat(payload["written_at"].replace("Z", "+00:00"))
        if written.tzinfo is None:
            raise ValueError("heartbeat timestamp has no timezone")
        age = max(0, int((now - written.astimezone(timezone.utc)).total_seconds()))
        result.update(
            status="fresh" if age <= maximum_age else "stale",
            observed_at=written.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            age_seconds=age,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        result["status"] = "invalid"
    return result


def regular_root_file(
    path: Path, *, executable: bool = False, maximum_size: int | None = None
) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_nlink != 1
    ):
        return False
    if details.st_mode & 0o022 or (executable and not details.st_mode & 0o111):
        return False
    return maximum_size is None or details.st_size <= maximum_size


def root_secret_file(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        regular_root_file(path, maximum_size=4096)
        and stat.S_IMODE(details.st_mode) == 0o600
    )


def garm_configuration_state() -> dict[str, bool | None]:
    unknown = {
        "manager_configured": None,
        "provider_configured": None,
        "image_configured": None,
        "broker_configured": None,
        "zero_scale_sets": None,
    }
    if not regular_root_file(GARM_HEALTH_STATE, maximum_size=4096):
        return unknown
    try:
        payload = json.loads(GARM_HEALTH_STATE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unknown
    if (
        not isinstance(payload, dict)
        or set(payload) != GARM_STATE_KEYS
        or payload.get("schema_version") != 3
    ):
        return unknown
    values = {
        key: payload[key]
        for key in (
            "manager_configured",
            "provider_configured",
            "image_configured",
            "broker_configured",
            "zero_scale_sets",
        )
    }
    if any(type(value) is not bool for value in values.values()):
        return unknown
    cli_home = payload["garm_cli_home"]
    if cli_home != GARM_RUNTIME_HOME:
        return unknown
    if not regular_root_file(GARM_CLI, executable=True) or not regular_root_file(
        GARM_SESSION_HELPER, executable=True
    ):
        return unknown
    if any(not root_secret_file(path) for path in GARM_SESSION_SECRETS):
        return unknown
    if not regular_root_file(
        BROKER_CONFIG, maximum_size=65536
    ) or not regular_root_file(LIVE_JOB_VERIFIER, executable=True):
        return unknown
    try:
        broker = json.loads(BROKER_CONFIG.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unknown
    if broker.get("targets") != payload["targets"] or broker.get(
        "live_job_verifier"
    ) != str(LIVE_JOB_VERIFIER):
        return unknown

    def query(*args: str) -> object:
        result = subprocess.run(
            [str(GARM_SESSION_HELPER), "run", "--", "--format", "json", *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            raise ValueError("garm-cli query failed")
        return json.loads(result.stdout)

    try:
        controller = query("controller", "show")
        providers = query("provider", "list")
        inventories = [
            query("scaleset", "list", target["entity_flag"], target["entity_id"])
            for target in payload["targets"].values()
        ]
        image_result = subprocess.run(
            [
                "incus",
                "image",
                "info",
                payload["image"]["alias"],
                "--project",
                "ci-jit",
                "--format",
                "json",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if image_result.returncode != 0:
            raise ValueError("Incus image query failed")
        live_image = json.loads(image_result.stdout)
    except (
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):
        return unknown
    if (
        not isinstance(controller, dict)
        or controller.get("callback_url") != "http://10.254.0.1:8080/api/v1/callbacks"
        or controller.get("metadata_url") != "http://10.254.0.1:8080/api/v1/metadata"
    ):
        return unknown
    if (
        not isinstance(providers, list)
        or len(providers) != 1
        or providers[0].get("name") != "incus_ci_jit"
        or providers[0].get("type") != "external"
    ):
        return unknown
    if any(inventory != [] for inventory in inventories):
        return unknown
    image = payload["image"]
    if (
        not isinstance(image, dict)
        or set(image) != {"alias", "fingerprint"}
        or live_image.get("fingerprint") != image["fingerprint"]
        or image["alias"]
        not in [item.get("name") for item in live_image.get("aliases", [])]
    ):
        return unknown
    values["manager_configured"] = bool(
        values["manager_configured"]
        and regular_root_file(GARM_BINARY, executable=True)
        and regular_root_file(GARM_CONFIG, maximum_size=65536)
    )
    values["provider_configured"] = bool(
        values["provider_configured"]
        and regular_root_file(GARM_PROVIDER, executable=True)
    )
    values["broker_configured"] = bool(values["broker_configured"])
    values["zero_scale_sets"] = bool(
        values["zero_scale_sets"] and all(inventory == [] for inventory in inventories)
    )
    return values


def idle_instance_count() -> int | None:
    try:
        result = subprocess.run(
            ["incus", "list", "--project", "ci-jit", "--format", "json"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        payload = json.loads(result.stdout)
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            return None
        return len(payload)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def persistent_registration_present() -> bool | None:
    legacy = Path("/opt/self-hosted-ci/actions-runner")
    for name in (".runner", ".credentials", ".credentials_rsaparams"):
        try:
            (legacy / name).lstat()
            return True
        except FileNotFoundError:
            pass
        except OSError:
            return None
    unit_roots = (
        Path("/etc/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/lib/systemd/system"),
    )
    for root in unit_roots:
        try:
            if root.is_dir() and any(
                entry.name.startswith("actions.runner.")
                and entry.name.endswith(".service")
                for entry in root.iterdir()
            ):
                return True
        except OSError:
            return None
    return False


def observe(distro: str, maximum_age: int) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    os_release = {}
    with Path("/etc/os-release").open(encoding="utf-8") as handle:
        os_release = {
            key: value.strip('"')
            for key, value in (
                line.rstrip().split("=", 1) for line in handle if "=" in line
            )
        }
    heartbeat_state = heartbeat(
        Path("/var/lib/self-hosted-ci/health/heartbeat.json"), maximum_age, now
    )
    services = {name: systemd_state(name) for name in SERVICES}
    configured = garm_configuration_state()
    persistent_registration = persistent_registration_present()
    idle_instances = idle_instance_count()
    manager_state = services["self-hosted-ci-garm.service"]["active"]
    broker_state = services["self-hosted-ci-allocation-broker.service"]["active"]
    runner = {
        "mode": "garm-jit",
        "manager": {
            "configured": configured["manager_configured"],
            "state": manager_state,
        },
        "provider": {"configured": configured["provider_configured"]},
        "image": {"configured": configured["image_configured"]},
        "broker": {
            "configured": configured["broker_configured"],
            "state": broker_state,
        },
        "transient_inventories_clean": configured["zero_scale_sets"],
        "persistent_registration": persistent_registration,
        "idle_instances": idle_instances,
    }
    boundary = {
        "activation_approved": Path(
            "/etc/self-hosted-ci/ACTIVATION_APPROVED"
        ).is_file(),
        "network_policy_enabled": Path(
            "/etc/self-hosted-ci/runner-network-v2.enabled"
        ).is_file(),
    }
    reasons: list[str] = []
    if "wsl2" not in platform.release().lower():
        reasons.append("platform_not_verified")
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        reasons.append("platform_not_verified")
    if os.environ.get("WSL_DISTRO_NAME") != distro:
        reasons.append("dedicated_distro_not_verified")
    if configured["manager_configured"] is not True:
        reasons.append("garm_manager_not_configured")
    if configured["provider_configured"] is not True:
        reasons.append("garm_provider_not_configured")
    if configured["image_configured"] is not True:
        reasons.append("runner_image_not_configured")
    if configured["broker_configured"] is not True:
        reasons.append("allocation_broker_not_configured")
    if configured["zero_scale_sets"] is not True:
        reasons.append("transient_scale_sets_not_clean")
    if persistent_registration is not False:
        reasons.append("persistent_runner_registration_not_clean")
    if idle_instances is None:
        reasons.append("jit_instances_not_observable")
    elif idle_instances != 0:
        reasons.append("idle_jit_instances_present")
    if heartbeat_state["status"] != "fresh":
        reasons.append("heartbeat_not_fresh")
    if not boundary["activation_approved"]:
        reasons.append("activation_not_approved")
    if not boundary["network_policy_enabled"]:
        reasons.append("network_policy_not_enabled")
    for name in SERVICES:
        if services[name]["active"] != "active":
            reasons.append(f"service_not_active:{name}")
        if services[name]["enabled"] not in (
            {"enabled"}
            if name
            in {
                "incus.service",
                "self-hosted-ci-garm.service",
                "self-hosted-ci-allocation-broker.service",
                "self-hosted-ci-health-heartbeat.timer",
            }
            else {"enabled", "static"}
        ):
            reasons.append(f"service_not_enabled:{name}")
    reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": 1,
        "observed_at": now.isoformat().replace("+00:00", "Z"),
        "distro": {
            "name": distro,
            "platform": "wsl2" if "wsl2" in platform.release().lower() else "unknown",
            "os_id": os_release.get("ID"),
            "os_version": os_release.get("VERSION_ID"),
        },
        "runner": runner,
        "services": services,
        "heartbeat": heartbeat_state,
        "boundary": boundary,
        "eligibility": {
            "eligible_for_local_ci": not reasons,
            "blocking_reasons": reasons,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="Ubuntu-24.04-CI")
    parser.add_argument("--heartbeat-max-age", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.heartbeat_max_age <= 86400:
        raise SystemExit("invalid heartbeat maximum age")
    print(
        json.dumps(
            observe(args.distro, args.heartbeat_max_age),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
