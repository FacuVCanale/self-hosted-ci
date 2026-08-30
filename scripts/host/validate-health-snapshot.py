#!/usr/bin/env python3
"""Strictly validate a downloaded health snapshot and return a stable status code."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

TOP_LEVEL = {
    "schema_version",
    "install_nonce",
    "generated_at",
    "expires_at",
    "producer",
    "host",
    "distro",
    "runner",
    "services",
    "heartbeat",
    "boundary",
    "eligibility",
    "probe_error",
}
SID = re.compile(r"^S-1-[0-9]+(?:-[0-9]+)+$")
SERVICES = {
    "incus.service",
    "self-hosted-ci-allocation-broker.service",
    "self-hosted-ci-boundary-verify.service",
    "self-hosted-ci-egress-proxy.service",
    "self-hosted-ci-garm.service",
    "self-hosted-ci-health-heartbeat.timer",
    "self-hosted-ci-network-policy.service",
}
HOST_SERVICES = {"sshd", "wsl", "lxss_manager"}
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
ENABLED_STATES = {
    "incus.service": {"enabled", "indirect"},
    "self-hosted-ci-boundary-verify.service": {"enabled", "static"},
    "self-hosted-ci-allocation-broker.service": {"enabled"},
    "self-hosted-ci-egress-proxy.service": {"enabled", "static"},
    "self-hosted-ci-garm.service": {"enabled"},
    "self-hosted-ci-health-heartbeat.timer": {"enabled"},
    "self-hosted-ci-network-policy.service": {"enabled", "static"},
}


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must be UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def validate(
    payload: object, expected_sid: str, expected_distro: str, now: datetime
) -> tuple[int, str]:
    if (
        not isinstance(payload, dict)
        or set(payload) != TOP_LEVEL
        or payload.get("schema_version") != 2
    ):
        return 5, "invalid_snapshot_schema"
    try:
        generated, expires = (
            timestamp(payload["generated_at"]),
            timestamp(payload["expires_at"]),
        )
        if not isinstance(payload["install_nonce"], str) or not UUID.fullmatch(
            payload["install_nonce"]
        ):
            raise ValueError()
        producer, host, distro = payload["producer"], payload["host"], payload["distro"]
        runner, services, heartbeat = (
            payload["runner"],
            payload["services"],
            payload["heartbeat"],
        )
        boundary, eligibility = payload["boundary"], payload["eligibility"]
        if not isinstance(producer, dict) or set(producer) != {
            "windows_sid",
            "account",
            "distro",
        }:
            raise ValueError()
        if producer["windows_sid"] != expected_sid or not SID.fullmatch(
            producer["windows_sid"]
        ):
            raise ValueError()
        if (
            producer["account"] != "selfhosted-ci-svc"
            or producer["distro"] != expected_distro
        ):
            raise ValueError()
        if (
            not isinstance(host, dict)
            or set(host) != {"service_identity_verified", "services"}
            or host["service_identity_verified"] is not True
        ):
            raise ValueError()
        if (
            not isinstance(host["services"], dict)
            or set(host["services"]) != HOST_SERVICES
        ):
            raise ValueError()
        for state in host["services"].values():
            if (
                not isinstance(state, dict)
                or set(state) != {"installed", "status"}
                or not isinstance(state["installed"], bool)
                or not isinstance(state["status"], str)
            ):
                raise ValueError()
            if state["status"] not in {"running", "stopped", "paused", "absent"}:
                raise ValueError()
            if state["installed"] != (state["status"] != "absent"):
                raise ValueError()
        if (
            not isinstance(distro, dict)
            or set(distro) != {"name", "platform", "os_id", "os_version"}
            or distro.get("name") != expected_distro
        ):
            raise ValueError()
        legacy_probe_runner = {"installed", "registered", "labels"}
        jit_runner = {
            "mode",
            "manager",
            "provider",
            "image",
            "broker",
            "transient_inventories_clean",
            "persistent_registration",
            "idle_instances",
        }
        if not isinstance(runner, dict) or set(runner) not in (
            legacy_probe_runner,
            jit_runner,
        ):
            raise ValueError()
        if set(runner) == legacy_probe_runner:
            if payload["probe_error"] is None or runner.get("labels") != [
                "linux",
                "self-hosted",
                "wsl-jit",
                "x64",
            ]:
                raise ValueError()
            if (
                runner.get("registered") is not None
                or runner.get("installed") is not None
            ):
                raise ValueError()
        else:
            if runner["mode"] != "garm-jit":
                raise ValueError()
            if not isinstance(runner["manager"], dict) or set(runner["manager"]) != {
                "configured",
                "state",
            }:
                raise ValueError()
            if (
                runner["manager"]["configured"] is not None
                and type(runner["manager"]["configured"]) is not bool
            ):
                raise ValueError()
            if runner["manager"]["state"] not in {
                "active",
                "inactive",
                "failed",
                "unknown",
            }:
                raise ValueError()
            for key in ("provider", "image"):
                if not isinstance(runner[key], dict) or set(runner[key]) != {
                    "configured"
                }:
                    raise ValueError()
                if (
                    runner[key]["configured"] is not None
                    and type(runner[key]["configured"]) is not bool
                ):
                    raise ValueError()
            if not isinstance(runner["broker"], dict) or set(runner["broker"]) != {
                "configured",
                "state",
            }:
                raise ValueError()
            if (
                runner["broker"]["configured"] is not None
                and type(runner["broker"]["configured"]) is not bool
            ):
                raise ValueError()
            if runner["broker"]["state"] not in {
                "active",
                "inactive",
                "failed",
                "unknown",
            }:
                raise ValueError()
            if (
                runner["transient_inventories_clean"] is not None
                and type(runner["transient_inventories_clean"]) is not bool
            ):
                raise ValueError()
            if (
                runner["persistent_registration"] is not None
                and type(runner["persistent_registration"]) is not bool
            ):
                raise ValueError()
            if runner["idle_instances"] is not None and (
                not isinstance(runner["idle_instances"], int)
                or isinstance(runner["idle_instances"], bool)
                or runner["idle_instances"] < 0
            ):
                raise ValueError()
        if not isinstance(services, dict) or set(services) != SERVICES:
            raise ValueError()
        for name, state in services.items():
            if (
                not isinstance(state, dict)
                or set(state) != {"active", "enabled"}
                or not all(isinstance(state[key], str) for key in state)
            ):
                raise ValueError()
            if state["active"] not in {
                "active",
                "inactive",
                "failed",
                "unknown",
            } or state["enabled"] not in {
                "enabled",
                "indirect",
                "disabled",
                "static",
                "masked",
                "unknown",
            }:
                raise ValueError()
        if (
            set(runner) == jit_runner
            and runner["manager"]["state"]
            != services["self-hosted-ci-garm.service"]["active"]
        ):
            raise ValueError()
        if (
            set(runner) == jit_runner
            and runner["broker"]["state"]
            != services["self-hosted-ci-allocation-broker.service"]["active"]
        ):
            raise ValueError()
        if not isinstance(heartbeat, dict) or set(heartbeat) != {
            "status",
            "observed_at",
            "age_seconds",
            "max_age_seconds",
        }:
            raise ValueError()
        if heartbeat["status"] not in {
            "fresh",
            "stale",
            "absent",
            "invalid",
            "not_observable",
        }:
            raise ValueError()
        if (
            not isinstance(heartbeat["max_age_seconds"], int)
            or heartbeat["max_age_seconds"] < 1
        ):
            raise ValueError()
        if heartbeat["age_seconds"] is not None and (
            not isinstance(heartbeat["age_seconds"], int)
            or heartbeat["age_seconds"] < 0
        ):
            raise ValueError()
        observed = (
            timestamp(heartbeat["observed_at"])
            if heartbeat["observed_at"] is not None
            else None
        )
        if heartbeat["status"] in {"fresh", "stale"}:
            if observed is None or not isinstance(heartbeat["age_seconds"], int):
                raise ValueError()
            expected_age = max(0, int((generated - observed).total_seconds()))
            if abs(
                heartbeat["age_seconds"] - expected_age
            ) > 2 or observed > generated + timedelta(seconds=2):
                raise ValueError()
            if (heartbeat["status"] == "fresh") != (
                heartbeat["age_seconds"] <= heartbeat["max_age_seconds"]
            ):
                raise ValueError()
        elif observed is not None or heartbeat["age_seconds"] is not None:
            raise ValueError()
        if not isinstance(boundary, dict) or set(boundary) != {
            "activation_approved",
            "network_policy_enabled",
        }:
            raise ValueError()
        if boundary["activation_approved"] not in (True, False, None) or boundary[
            "network_policy_enabled"
        ] not in (True, False, None):
            raise ValueError()
        if not isinstance(eligibility, dict) or set(eligibility) != {
            "eligible_for_local_ci",
            "blocking_reasons",
        }:
            raise ValueError()
        if not isinstance(eligibility["eligible_for_local_ci"], bool):
            raise ValueError()
        if not isinstance(eligibility["blocking_reasons"], list) or not all(
            isinstance(item, str) and item for item in eligibility["blocking_reasons"]
        ):
            raise ValueError()
        if expires <= generated or expires - generated > timedelta(seconds=300):
            raise ValueError()
        if payload["probe_error"] is not None and (
            not isinstance(payload["probe_error"], str)
            or not payload["probe_error"]
            or len(payload["probe_error"]) > 1024
        ):
            raise ValueError()
        if payload["probe_error"] is not None and (
            eligibility["eligible_for_local_ci"]
            or "supervisor_probe_failed" not in eligibility["blocking_reasons"]
        ):
            raise ValueError()
        if len(set(eligibility["blocking_reasons"])) != len(
            eligibility["blocking_reasons"]
        ):
            raise ValueError()
        if payload["probe_error"] is not None:
            expected_blockers = {"supervisor_probe_failed"}
        else:
            expected_blockers: set[str] = set()
            if (
                distro["platform"] != "wsl2"
                or distro["os_id"] != "ubuntu"
                or distro["os_version"] != "24.04"
            ):
                expected_blockers.add("platform_not_verified")
            if runner["manager"]["configured"] is not True:
                expected_blockers.add("garm_manager_not_configured")
            if runner["provider"]["configured"] is not True:
                expected_blockers.add("garm_provider_not_configured")
            if runner["image"]["configured"] is not True:
                expected_blockers.add("runner_image_not_configured")
            if runner["broker"]["configured"] is not True:
                expected_blockers.add("allocation_broker_not_configured")
            if runner["transient_inventories_clean"] is not True:
                expected_blockers.add("transient_scale_sets_not_clean")
            if runner["persistent_registration"] is not False:
                expected_blockers.add("persistent_runner_registration_not_clean")
            if runner["idle_instances"] is None:
                expected_blockers.add("jit_instances_not_observable")
            elif runner["idle_instances"] != 0:
                expected_blockers.add("idle_jit_instances_present")
            if heartbeat["status"] != "fresh":
                expected_blockers.add("heartbeat_not_fresh")
            if boundary["activation_approved"] is not True:
                expected_blockers.add("activation_not_approved")
            if boundary["network_policy_enabled"] is not True:
                expected_blockers.add("network_policy_not_enabled")
            for name, state in services.items():
                if state["active"] != "active":
                    expected_blockers.add(f"service_not_active:{name}")
                if state["enabled"] not in ENABLED_STATES[name]:
                    expected_blockers.add(f"service_not_enabled:{name}")
            if host["services"]["sshd"]["status"] != "running":
                expected_blockers.add("host_service_not_running:sshd")
            if (
                host["services"]["wsl"]["status"] != "running"
                and host["services"]["lxss_manager"]["status"] != "running"
            ):
                expected_blockers.add("host_service_not_running:wsl")
        if eligibility["blocking_reasons"] != sorted(expected_blockers):
            raise ValueError()
        if eligibility["eligible_for_local_ci"] != (not expected_blockers):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        return 5, "invalid_snapshot_contract"
    if generated > now + timedelta(seconds=30):
        return 5, "snapshot_from_future"
    if now >= expires:
        return 4, "snapshot_expired"
    if not eligibility["eligible_for_local_ci"]:
        return 3, "local_ci_ineligible"
    if (
        eligibility["blocking_reasons"]
        or heartbeat["status"] != "fresh"
        or distro["platform"] != "wsl2"
        or distro["os_id"] != "ubuntu"
        or distro["os_version"] != "24.04"
        or runner["manager"] != {"configured": True, "state": "active"}
        or runner["provider"] != {"configured": True}
        or runner["image"] != {"configured": True}
        or runner["broker"] != {"configured": True, "state": "active"}
        or runner["transient_inventories_clean"] is not True
        or runner["persistent_registration"] is not False
        or runner["idle_instances"] != 0
        or boundary != {"activation_approved": True, "network_policy_enabled": True}
    ):
        return 5, "eligible_snapshot_has_blockers"
    return 0, "healthy"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--expected-sid", required=True)
    parser.add_argument("--expected-distro", default="Ubuntu-24.04-CI")
    args = parser.parse_args()
    if not SID.fullmatch(args.expected_sid):
        print("invalid_expected_sid")
        return 2
    try:
        payload = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        print("invalid_snapshot_json")
        return 5
    code, status = validate(
        payload, args.expected_sid, args.expected_distro, datetime.now(timezone.utc)
    )
    print(
        json.dumps(
            {"status": status, "snapshot": payload},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
