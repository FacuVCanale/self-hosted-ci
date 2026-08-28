"""Signed semantic boundary for inert WSL JIT provisioning.

This contract authorizes only installation of inert contract/runtime material.
It is deliberately independent from the runner activation boundary and cannot
authorize GitHub access, runtime-ready state, or runner registration.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import canonicalize_jcs, sign_detached, spki_fingerprint, verify_detached


class BootstrapBoundaryError(ValueError):
    pass


BOOTSTRAP_ATTESTATION_DOMAIN = b"self-hosted-ci/wsl-jit-bootstrap-boundary/v1"
EXPECTED_DISTRO = "Ubuntu-24.04-CI"
EXPECTED_BASE_PATH = r"C:\ProgramData\self-hosted-ci\wsl"
EXPECTED_SOFTWARE = {
    "incus": {"version": "6.0.0-1ubuntu0.3"},
    "garm": {
        "version": "0.2.1",
        "artifact_sha256": "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746",
        "binary_sha256": "b04fda186bfa0c98a902a3bb7525987217565681ec33b553921945dbb574b87e",
    },
    "garm-cli": {
        "version": "0.2.1",
        "artifact_sha256": "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e",
        "binary_sha256": "a973c9061cf7962b4f90c8220ed6f6cc8abeeed20780ea8b9e31ce6dfc99bd9b",
    },
    "garm-provider-incus": {
        "version": "0.1.5",
        "artifact_sha256": "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f",
        "binary_sha256": "0fe2c592cece494ad5fc6a6fe05ef2e621fb5d47fb03cc472c2b1d6739428891",
    },
}
AUTHORIZATION = {
    "operation": "provision-wsl-jit-contract",
    "mode": "inert-only",
    "activation_authorized": False,
    "github_contact_authorized": False,
    "runtime_ready_authorized": False,
    "runner_registration_authorized": False,
}
WINDOWS_TOP_LEVEL = {
    "schema",
    "schema_version",
    "observed_at",
    "collector_identity_sid",
    "expected",
    "observations",
    "checks",
    "contract_satisfied",
    "side_effects",
}
WSL_TOP_LEVEL = {
    "schema_version",
    "collector",
    "observed_at",
    "expected_distro",
    "collection_status",
    "observations",
    "probe_errors",
}
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SID = re.compile(r"^S-1-[0-9]+(?:-[0-9]+)+$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
MAX_OBSERVATION_AGE_SECONDS = 900
MAX_OBSERVATION_SKEW_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 30
BOOTSTRAP_TTL_SECONDS = 600
PUBLIC_MANIFEST_ARTIFACT_COUNT = 80
PUBLIC_MANIFEST_MAPPING_DIGEST = (
    "9f9cc82e1d65be945898bd45518ccb6fa78aa18844b979f1412e239436d1a930"
)


@dataclass(frozen=True)
class BootstrapBoundaryDecision:
    authorized: bool
    blockers: tuple[str, ...]


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise BootstrapBoundaryError("bootstrap clock must be timezone-aware")
    return current.astimezone(timezone.utc)


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise BootstrapBoundaryError(f"{field} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise BootstrapBoundaryError(f"{field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise BootstrapBoundaryError(f"{field} must be UTC")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def observation_time_blockers(
    windows: Mapping[str, Any],
    wsl: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[str, ...]:
    blockers: list[str] = []
    try:
        windows_at = _timestamp(windows.get("observed_at"), "windows observed_at")
        wsl_at = _timestamp(wsl.get("observed_at"), "wsl observed_at")
    except BootstrapBoundaryError as exc:
        return (str(exc),)
    for name, observed in (("windows", windows_at), ("wsl", wsl_at)):
        age = (now - observed).total_seconds()
        if age < -MAX_FUTURE_SKEW_SECONDS:
            blockers.append(f"{name}-observation-from-future")
        elif age > MAX_OBSERVATION_AGE_SECONDS:
            blockers.append(f"{name}-observation-stale")
    if abs((windows_at - wsl_at).total_seconds()) > MAX_OBSERVATION_SKEW_SECONDS:
        blockers.append("observation-pair-skew")
    return tuple(blockers)


def public_manifest_blockers(value: Mapping[str, Any]) -> tuple[str, ...]:
    required = {
        "bootstrap_public_manifest_version",
        "mapping_digest",
        "artifacts",
    }
    if set(value) != required or value.get("bootstrap_public_manifest_version") != 1:
        return ("public-manifest-schema",)
    artifacts = value.get("artifacts")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != PUBLIC_MANIFEST_ARTIFACT_COUNT
    ):
        return ("public-manifest-artifact-count",)
    pairs: list[dict[str, str]] = []
    seen_targets: set[str] = set()
    blockers: list[str] = []
    for item in artifacts:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"source", "target", "mode", "sha256", "size"}
            or not isinstance(item.get("source"), str)
            or PurePosixPath(item["source"]).is_absolute()
            or ".." in PurePosixPath(item["source"]).parts
            or not isinstance(item.get("target"), str)
            or not item["target"]
            or not isinstance(item.get("mode"), str)
            or re.fullmatch(r"0[0-7]{3}", item["mode"]) is None
            or not isinstance(item.get("sha256"), str)
            or HEX_DIGEST.fullmatch(item["sha256"]) is None
            or not isinstance(item.get("size"), int)
            or item["size"] < 0
        ):
            blockers.append("public-manifest-artifact-schema")
            continue
        if item["target"] in seen_targets:
            blockers.append("public-manifest-target-duplicate")
        seen_targets.add(item["target"])
        pairs.append(
            {
                "source": item["source"],
                "target": item["target"],
                "mode": item["mode"],
            }
        )
    pairs.sort(key=lambda item: (item["target"], item["source"]))
    mapping_digest = hashlib.sha256(canonicalize_jcs(pairs)).hexdigest()
    if (
        value.get("mapping_digest") != PUBLIC_MANIFEST_MAPPING_DIGEST
        or mapping_digest != PUBLIC_MANIFEST_MAPPING_DIGEST
    ):
        blockers.append("public-manifest-mapping")
    return tuple(dict.fromkeys(blockers))


def verify_public_manifest_bytes(
    value: Mapping[str, Any], source_root: Path
) -> tuple[str, ...]:
    blockers = list(public_manifest_blockers(value))
    if blockers:
        return tuple(blockers)
    root = source_root.resolve()
    for item in value["artifacts"]:
        path = root.joinpath(*PurePosixPath(item["source"]).parts)
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or root not in path.resolve().parents
            ):
                blockers.append(f"public-source-unsafe:{item['target']}")
                continue
            data = path.read_bytes()
        except OSError:
            blockers.append(f"public-source-unreadable:{item['target']}")
            continue
        if (
            len(data) != item["size"]
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            blockers.append(f"public-source-drift:{item['target']}")
    return tuple(dict.fromkeys(blockers))


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _exact_false_map(value: object, keys: set[str]) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == keys
        and all(value[key] is False for key in keys)
    )


def windows_observation_blockers(value: Mapping[str, Any]) -> tuple[str, ...]:
    blockers: list[str] = []
    if set(value) != WINDOWS_TOP_LEVEL:
        return ("windows-schema-fields",)
    if (
        value.get("schema") != "self-hosted-ci/windows-wsl-semantic-contract"
        or value.get("schema_version") != 1
    ):
        blockers.append("windows-schema-version")
    if value.get("contract_satisfied") is not True:
        blockers.append("windows-contract-unsatisfied")

    expected = _mapping(value.get("expected"))
    expected_keys = {
        "service_account",
        "service_sid",
        "distro_name",
        "base_path",
        "wsl_version",
    }
    if expected is None or set(expected) != expected_keys:
        blockers.append("windows-expected-schema")
        expected = {}
    service_sid = expected.get("service_sid")
    if (
        expected.get("service_account") != "selfhosted-ci-svc"
        or not isinstance(service_sid, str)
        or SID.fullmatch(service_sid) is None
        or expected.get("distro_name") != EXPECTED_DISTRO
        or expected.get("base_path") != EXPECTED_BASE_PATH
        or expected.get("wsl_version") != 2
    ):
        blockers.append("windows-expected-boundary")

    checks = _mapping(value.get("checks"))
    if not checks or any(
        not isinstance(check, Mapping)
        or set(check) != {"status", "reason"}
        or check.get("status") != "satisfied"
        or not isinstance(check.get("reason"), str)
        for check in checks.values()
    ):
        blockers.append("windows-checks-unsatisfied")

    side_effects = _mapping(value.get("side_effects"))
    expected_side_effects = {
        "scheduled_task_created": False,
        "password_rotated": False,
        "wsl_started": False,
        "github_contacted": False,
        "runner_registration_changed": False,
        "evidence_file_created": True,
    }
    if side_effects != expected_side_effects:
        blockers.append("windows-collector-side-effects")

    observations = _mapping(value.get("observations"))
    if observations is None or set(observations) != {
        "account",
        "registration",
        "base_path",
    }:
        blockers.append("windows-observations-schema")
        observations = {}
    account = _mapping(observations.get("account"))
    if (
        account is None
        or set(account)
        != {"name", "sid", "enabled", "principal_source", "effective_administrator"}
        or account.get("name") != "selfhosted-ci-svc"
        or account.get("sid") != service_sid
        or account.get("enabled") is not True
        or account.get("principal_source") != "Local"
        or account.get("effective_administrator") is not False
    ):
        blockers.append("windows-service-identity")

    registration = _mapping(observations.get("registration"))
    matches = registration.get("matches") if registration else None
    if (
        registration is None
        or set(registration) != {"accessible", "exact_match_count", "matches", "error"}
        or registration.get("accessible") is not True
        or registration.get("exact_match_count") != 1
        or registration.get("error") is not None
        or not isinstance(matches, list)
        or len(matches) != 1
    ):
        blockers.append("windows-wsl-registration")
    else:
        match = _mapping(matches[0])
        if (
            match is None
            or set(match)
            != {"key", "distribution_name", "version", "base_path", "owner_sid"}
            or match.get("distribution_name") != EXPECTED_DISTRO
            or match.get("version") != 2
            or match.get("base_path") != EXPECTED_BASE_PATH
            or match.get("owner_sid") != service_sid
            or not isinstance(match.get("key"), str)
            or re.fullmatch(
                r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}",
                match["key"],
            )
            is None
        ):
            blockers.append("windows-wsl-registration-details")

    base_path = _mapping(observations.get("base_path"))
    acl = _mapping(base_path.get("acl")) if base_path else None
    rules = acl.get("rules") if acl else None
    allowed_sids = {"S-1-5-18", "S-1-5-32-544", service_sid}
    if (
        base_path is None
        or set(base_path)
        != {"exists", "canonical_path", "reparse_free", "acl", "error"}
        or base_path.get("exists") is not True
        or base_path.get("canonical_path") != EXPECTED_BASE_PATH
        or base_path.get("reparse_free") is not True
        or base_path.get("error") is not None
        or acl is None
        or set(acl) != {"owner_sid", "inheritance_protected", "rules"}
        or acl.get("owner_sid") != "S-1-5-32-544"
        or acl.get("inheritance_protected") is not True
        or not isinstance(rules, list)
        or len(rules) != 3
    ):
        blockers.append("windows-base-path-boundary")
    elif (
        any(
            not isinstance(rule, Mapping)
            or set(rule)
            != {
                "sid",
                "type",
                "rights",
                "inherited",
                "inheritance_flags",
                "propagation_flags",
            }
            or rule.get("sid") not in allowed_sids
            or rule.get("type") != "Allow"
            or rule.get("rights") != "FullControl"
            or rule.get("inherited") is not False
            or rule.get("inheritance_flags") != "ContainerInherit, ObjectInherit"
            or rule.get("propagation_flags") != "None"
            for rule in rules
        )
        or {rule["sid"] for rule in rules} != allowed_sids
    ):
        blockers.append("windows-base-path-acl")
    return tuple(dict.fromkeys(blockers))


def _exact_config(actual: object, expected: Mapping[str, str]) -> bool:
    return isinstance(actual, Mapping) and dict(actual) == dict(expected)


def wsl_observation_blockers(value: Mapping[str, Any]) -> tuple[str, ...]:
    blockers: list[str] = []
    if set(value) != WSL_TOP_LEVEL:
        return ("wsl-schema-fields",)
    if (
        value.get("schema_version") != 1
        or value.get("collector") != "wsl-jit-semantic-observations"
    ):
        blockers.append("wsl-schema-version")
    if (
        value.get("expected_distro") != EXPECTED_DISTRO
        or value.get("collection_status") != "complete"
        or value.get("probe_errors") != []
    ):
        blockers.append("wsl-collection-incomplete")
    observations = _mapping(value.get("observations"))
    observation_keys = {
        "wsl_boundary",
        "mounts_and_interop",
        "credential_surfaces",
        "linux_identities",
        "software",
        "incus",
        "network",
        "garm",
    }
    if observations is None or set(observations) != observation_keys:
        return tuple(dict.fromkeys([*blockers, "wsl-observations-schema"]))

    boundary = _mapping(observations["wsl_boundary"])
    wsl_conf = _mapping(boundary.get("wsl_conf")) if boundary else None
    settings = _mapping(wsl_conf.get("settings")) if wsl_conf else None
    if (
        boundary is None
        or set(boundary) != {"distro_environment_matches", "wsl_conf"}
        or boundary.get("distro_environment_matches") is not True
        or wsl_conf is None
        or set(wsl_conf) != {"readable", "sha256", "settings"}
        or wsl_conf.get("readable") is not True
        or not isinstance(wsl_conf.get("sha256"), str)
        or HEX_DIGEST.fullmatch(wsl_conf["sha256"]) is None
        or settings is None
        or set(settings)
        != {
            "automount.enabled",
            "automount.mountfstab",
            "interop.enabled",
            "interop.appendwindowspath",
        }
        or any(str(setting).lower() != "false" for setting in settings.values())
    ):
        blockers.append("wsl-config-boundary")

    mounts = _mapping(observations["mounts_and_interop"])
    counts = _mapping(mounts.get("mount_class_counts")) if mounts else None
    interop = _mapping(mounts.get("wsl_interop")) if mounts else None
    if (
        mounts is None
        or set(mounts)
        != {"mount_class_counts", "wsl_interop", "windows_path_entry_count"}
        or counts is None
        or set(counts)
        != {"drvfs", "windows_drive_target", "docker_desktop", "wsl_shared"}
        or any(count != 0 for count in counts.values())
        or interop != {"present": False, "enabled": False}
        or mounts.get("windows_path_entry_count") != 0
    ):
        blockers.append("wsl-mount-or-interop-boundary")

    credentials = _mapping(observations["credential_surfaces"])
    expected_credentials = {
        "docker_socket",
        "docker_desktop_socket",
        "persistent_actions_runner",
        "garm_control_credentials",
        "github_or_authority_private_keys",
        "ssh_agent_socket",
        "private_or_deploy_key_candidates",
        "persistent_actions_runner_service_unit",
        "recursive_credential_candidates",
    }
    if credentials is None or not _exact_false_map(credentials, expected_credentials):
        blockers.append("wsl-credential-surface")

    identities = _mapping(observations["linux_identities"])
    manager = _mapping(identities.get("garm-manager")) if identities else None
    forbidden_groups = {"sudo", "admin", "wheel", "incus", "incus-admin"}
    if (
        identities is None
        or set(identities) != {"garm-manager"}
        or manager is None
        or set(manager)
        != {
            "present",
            "uid",
            "gid",
            "primary_group",
            "supplementary_groups",
            "home",
            "shell",
        }
        or manager.get("present") is not True
        or not isinstance(manager.get("uid"), int)
        or manager["uid"] <= 0
        or not isinstance(manager.get("gid"), int)
        or manager["gid"] <= 0
        or manager.get("home") != "/var/lib/garm"
        or manager.get("shell") not in {"/usr/sbin/nologin", "/bin/false"}
        or not isinstance(manager.get("supplementary_groups"), list)
        or forbidden_groups.intersection(manager["supplementary_groups"])
    ):
        blockers.append("wsl-linux-identity")

    software = _mapping(observations["software"])
    packages = _mapping(software.get("packages")) if software else None
    binaries = _mapping(software.get("binaries")) if software else None
    if software is None or set(software) != {"expected_pins", "packages", "binaries"}:
        blockers.append("wsl-software-schema")
    if software is None or software.get("expected_pins") != EXPECTED_SOFTWARE:
        blockers.append("wsl-software-pins")
    required_packages = {
        "dnsmasq-base",
        "e2fsprogs",
        "incus",
        "nftables",
        "squid",
        "util-linux",
    }
    if (
        packages is None
        or set(packages) != required_packages
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"installed", "version"}
            or item.get("installed") is not True
            or not isinstance(item.get("version"), str)
            or not item["version"]
            for item in packages.values()
        )
        or packages.get("incus", {}).get("version")
        != EXPECTED_SOFTWARE["incus"]["version"]
    ):
        blockers.append("wsl-packages")
    expected_binary_names = {
        "garm",
        "garm-cli",
        "garm-provider-incus",
        "incus",
        "nft",
        "squid",
    }
    if binaries is None or set(binaries) != expected_binary_names:
        blockers.append("wsl-binaries-schema")
    else:
        for name, item in binaries.items():
            if (
                not isinstance(item, Mapping)
                or set(item) != {"path", "present", "sha256"}
                or item.get("present") is not True
                or not isinstance(item.get("sha256"), str)
                or HEX_DIGEST.fullmatch(item["sha256"]) is None
            ):
                blockers.append(f"wsl-binary:{name}")
            expected_hash = EXPECTED_SOFTWARE.get(name, {}).get("binary_sha256")
            if expected_hash is not None and item.get("sha256") != expected_hash:
                blockers.append(f"wsl-binary-pin:{name}")

    incus = _mapping(observations["incus"])
    if incus is None or set(incus) != {
        "project",
        "profile",
        "storage",
        "bridge",
        "instances",
    }:
        blockers.append("wsl-incus-schema")
    else:
        project = _mapping(incus["project"])
        profile = _mapping(incus["profile"])
        storage = _mapping(incus["storage"])
        bridge = _mapping(incus["bridge"])
        instances = _mapping(incus["instances"])
        required_project = {
            "features.images": "false",
            "features.profiles": "true",
            "features.storage.volumes": "true",
            "restricted": "true",
            "restricted.containers.privilege": "isolated",
            "restricted.containers.nesting": "block",
            "restricted.containers.lowlevel": "block",
            "restricted.devices.disk": "managed",
            "restricted.devices.nic": "managed",
            "restricted.networks.access": "ci-jit-isolated",
            "limits.instances": "1",
            "limits.containers": "1",
            "limits.virtual-machines": "0",
            "limits.cpu": "2",
            "limits.memory": "4GiB",
            "limits.processes": "2048",
            "limits.disk": "12GiB",
        }
        required_profile = {
            "security.privileged": "false",
            "security.nesting": "false",
            "security.idmap.isolated": "true",
            "limits.cpu": "2",
            "limits.memory": "4GiB",
            "limits.processes": "2048",
        }
        required_bridge = {
            "ipv4.address": "10.254.0.1/28",
            "ipv4.dhcp": "true",
            "ipv4.dhcp.ranges": "10.254.0.2-10.254.0.2",
            "ipv4.dhcp.gateway": "10.254.0.1",
            "ipv4.routing": "false",
            "ipv4.nat": "false",
            "ipv4.firewall": "false",
            "ipv6.address": "none",
            "ipv6.routing": "false",
            "ipv6.nat": "false",
            "ipv6.firewall": "false",
            "dns.mode": "none",
        }
        required_devices = {
            "root": {
                "path": "/",
                "pool": "ci-jit-dedicated",
                "size": "12GiB",
                "type": "disk",
            },
            "eth0": {
                "name": "eth0",
                "network": "ci-jit-isolated",
                "security.ipv4_filtering": "true",
                "security.ipv6_filtering": "true",
                "security.mac_filtering": "true",
                "type": "nic",
            },
        }
        if project != {"present": True, "config": required_project}:
            blockers.append("wsl-incus-project")
        if profile != {
            "present": True,
            "config": required_profile,
            "devices": required_devices,
        }:
            blockers.append("wsl-incus-profile")
        if storage != {
            "present": True,
            "config": {"source": "/var/lib/self-hosted-ci/incus-storage/ci-jit/pool"},
            "driver": "dir",
        }:
            blockers.append("wsl-incus-storage")
        if bridge != {"present": True, "config": required_bridge, "type": "bridge"}:
            blockers.append("wsl-incus-bridge")
        if (
            instances is None
            or set(instances) != {"observable", "count", "names_sha256"}
            or instances.get("observable") is not True
            or instances.get("count") != 0
            or not isinstance(instances.get("names_sha256"), str)
            or HEX_DIGEST.fullmatch(instances["names_sha256"]) is None
        ):
            blockers.append("wsl-incus-instances")

    network = _mapping(observations["network"])
    nftables = _mapping(network.get("nftables")) if network else None
    listeners = _mapping(network.get("expected_listeners")) if network else None
    resolver = _mapping(network.get("resolver_classes")) if network else None
    if (
        network is None
        or set(network) != {"nftables", "expected_listeners", "resolver_classes"}
        or nftables is None
        or set(nftables)
        != {"observable", "table_names", "rule_count", "canonical_sha256"}
        or nftables.get("observable") is not True
        or not isinstance(nftables.get("table_names"), list)
        or not isinstance(nftables.get("rule_count"), int)
        or not isinstance(nftables.get("canonical_sha256"), str)
        or HEX_DIGEST.fullmatch(nftables["canonical_sha256"]) is None
        or listeners is None
        or set(listeners) != {"dns", "egress-proxy", "garm-proxy"}
        or any(type(item) is not bool for item in listeners.values())
        or resolver is None
        or set(resolver) != {"loopback", "private", "public", "link_local", "invalid"}
        or any(not isinstance(item, int) or item < 0 for item in resolver.values())
        or resolver.get("invalid") != 0
    ):
        blockers.append("wsl-network-observation")

    garm = _mapping(observations["garm"])
    services = _mapping(garm.get("services")) if garm else None
    health = _mapping(garm.get("health_state")) if garm else None
    if (
        garm is None
        or set(garm)
        != {
            "services",
            "process_count",
            "health_state",
            "state_database_present",
            "persistent_runner_registration_present",
        }
        or services is None
        or set(services) != {"garm.service", "self-hosted-ci-garm.service"}
        or any(
            not isinstance(service, Mapping)
            or set(service) != {"active", "enabled"}
            or service.get("active") not in {"inactive", "failed", "unknown"}
            or service.get("enabled") not in {"disabled", "not-found"}
            for service in services.values()
        )
        or garm.get("process_count") != 0
        or garm.get("state_database_present") is not False
        or garm.get("persistent_runner_registration_present") is not False
        or health is None
        or set(health) != {"observable", "zero_scale_sets", "configured_target_count"}
        or (
            health
            != {
                "observable": False,
                "zero_scale_sets": None,
                "configured_target_count": None,
            }
            and (
                health.get("observable") is not True
                or health.get("zero_scale_sets") is not True
                or health.get("configured_target_count") != 0
            )
        )
    ):
        blockers.append("wsl-garm-inert-state")
    return tuple(dict.fromkeys(blockers))


def build_bootstrap_boundary(
    windows_observation: Mapping[str, Any],
    wsl_observation: Mapping[str, Any],
    public_manifest: Mapping[str, Any],
    *,
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    issued = _now(now)
    blockers = (
        *windows_observation_blockers(windows_observation),
        *wsl_observation_blockers(wsl_observation),
        *observation_time_blockers(windows_observation, wsl_observation, now=issued),
        *public_manifest_blockers(public_manifest),
    )
    if blockers:
        raise BootstrapBoundaryError(
            "semantic observations are not provisionable: " + ",".join(blockers)
        )
    selected_nonce = nonce or secrets.token_hex(16)
    if NONCE.fullmatch(selected_nonce) is None:
        raise BootstrapBoundaryError("bootstrap nonce must be 128-bit lowercase hex")
    return build_bootstrap_boundary_unchecked(
        windows_observation,
        wsl_observation,
        public_manifest,
        issued_at=issued,
        nonce=selected_nonce,
    )


def sign_bootstrap_boundary(
    value: Mapping[str, Any], private_key: ed25519.Ed25519PrivateKey
) -> dict[str, Any]:
    if "attestation" in value:
        raise BootstrapBoundaryError("bootstrap boundary must be unsigned")
    canonicalize_jcs(value)
    return {
        **value,
        "attestation": {
            "attestation_version": 1,
            "signer_fingerprint": spki_fingerprint(private_key.public_key()),
            "signature": sign_detached(
                value, private_key, domain=BOOTSTRAP_ATTESTATION_DOMAIN
            ),
        },
    }


def verify_bootstrap_boundary(
    evidence: Mapping[str, Any],
    windows_observation: Mapping[str, Any],
    wsl_observation: Mapping[str, Any],
    public_manifest: Mapping[str, Any],
    public_key: ed25519.Ed25519PublicKey,
    *,
    pinned_fingerprint: str,
    expected_nonce: str,
    source_root: Path,
    now: datetime | None = None,
) -> BootstrapBoundaryDecision:
    current = _now(now)
    blockers: list[str] = []
    expected_fields = {
        "bootstrap_boundary_version",
        "issued_at",
        "expires_at",
        "nonce",
        "authorization",
        "windows_observation",
        "wsl_observation",
        "public_manifest",
        "attestation",
    }
    if (
        set(evidence) != expected_fields
        or evidence.get("bootstrap_boundary_version") != 1
    ):
        raise BootstrapBoundaryError("bootstrap boundary requires exact v1 fields")
    if evidence.get("authorization") != AUTHORIZATION:
        blockers.append("authorization-not-inert-only")
    try:
        issued = _timestamp(evidence.get("issued_at"), "bootstrap issued_at")
        expires = _timestamp(evidence.get("expires_at"), "bootstrap expires_at")
        if (
            expires <= issued
            or (expires - issued).total_seconds() != BOOTSTRAP_TTL_SECONDS
        ):
            blockers.append("bootstrap-lifetime")
        if current < issued - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            blockers.append("bootstrap-not-yet-valid")
        if current > expires:
            blockers.append("bootstrap-expired")
    except BootstrapBoundaryError as exc:
        blockers.append(str(exc))
        issued = current
    if (
        NONCE.fullmatch(expected_nonce) is None
        or not isinstance(evidence.get("nonce"), str)
        or NONCE.fullmatch(evidence["nonce"]) is None
        or evidence["nonce"] != expected_nonce
    ):
        blockers.append("bootstrap-nonce")
    attestation = _mapping(evidence.get("attestation"))
    actual_fingerprint = spki_fingerprint(public_key)
    if (
        attestation is None
        or set(attestation)
        != {"attestation_version", "signer_fingerprint", "signature"}
        or attestation.get("attestation_version") != 1
        or HEX_DIGEST.fullmatch(pinned_fingerprint) is None
        or actual_fingerprint != pinned_fingerprint
        or attestation.get("signer_fingerprint") != pinned_fingerprint
    ):
        blockers.append("attestation-key-or-schema")
    else:
        unsigned = {key: item for key, item in evidence.items() if key != "attestation"}
        try:
            verify_detached(
                unsigned,
                attestation["signature"],
                public_key,
                domain=BOOTSTRAP_ATTESTATION_DOMAIN,
            )
        except (TypeError, ValueError):
            blockers.append("attestation-signature")
    blockers.extend(windows_observation_blockers(windows_observation))
    blockers.extend(wsl_observation_blockers(wsl_observation))
    blockers.extend(
        observation_time_blockers(windows_observation, wsl_observation, now=current)
    )
    blockers.extend(verify_public_manifest_bytes(public_manifest, source_root))
    expected_unsigned = build_bootstrap_boundary_unchecked(
        windows_observation,
        wsl_observation,
        public_manifest,
        issued_at=issued,
        nonce=evidence.get("nonce"),
    )
    for field in (
        "issued_at",
        "expires_at",
        "nonce",
        "windows_observation",
        "wsl_observation",
        "public_manifest",
    ):
        if evidence.get(field) != expected_unsigned[field]:
            blockers.append(f"{field.replace('_', '-')}-binding")
    unique = tuple(dict.fromkeys(blockers))
    return BootstrapBoundaryDecision(authorized=not unique, blockers=unique)


def build_bootstrap_boundary_unchecked(
    windows_observation: Mapping[str, Any],
    wsl_observation: Mapping[str, Any],
    public_manifest: Mapping[str, Any],
    *,
    issued_at: datetime,
    nonce: object,
) -> dict[str, Any]:
    """Build digest bindings without granting authority; verifier helper only."""
    return {
        "bootstrap_boundary_version": 1,
        "issued_at": _format_timestamp(issued_at),
        "expires_at": _format_timestamp(
            issued_at + timedelta(seconds=BOOTSTRAP_TTL_SECONDS)
        ),
        "nonce": nonce,
        "authorization": dict(AUTHORIZATION),
        "windows_observation": {
            "schema": windows_observation.get("schema"),
            "schema_version": windows_observation.get("schema_version"),
            "observed_at": windows_observation.get("observed_at"),
            "sha256": _digest(windows_observation),
        },
        "wsl_observation": {
            "collector": wsl_observation.get("collector"),
            "schema_version": wsl_observation.get("schema_version"),
            "observed_at": wsl_observation.get("observed_at"),
            "sha256": _digest(wsl_observation),
        },
        "public_manifest": {
            "bootstrap_public_manifest_version": public_manifest.get(
                "bootstrap_public_manifest_version"
            ),
            "mapping_digest": public_manifest.get("mapping_digest"),
            "artifact_count": len(public_manifest.get("artifacts", []))
            if isinstance(public_manifest.get("artifacts"), list)
            else None,
            "sha256": _digest(public_manifest),
        },
    }
