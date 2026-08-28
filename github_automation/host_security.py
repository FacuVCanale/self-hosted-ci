"""Fail-closed host, WSL, network, and runner-lifecycle preflight.

The module intentionally does not configure a host.  It validates externally
collected evidence and only emits ``enabled=True`` when every normative proof is
present.  This keeps the implementation useful on macOS and in CI without
pretending that those environments prove a Windows/WSL boundary.
"""

from __future__ import annotations

from configparser import ConfigParser
from dataclasses import dataclass
from typing import Any, Mapping


class HostSecurityError(ValueError):
    """Evidence is malformed or contradicts the normative contract."""


REQUIRED_WSL_SETTINGS = {
    ("automount", "enabled"): "false",
    ("automount", "mountfstab"): "false",
    ("interop", "enabled"): "false",
    ("interop", "appendwindowspath"): "false",
}

BLOCKED_NETWORK_CIDRS = frozenset(
    {
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    }
)

REQUIRED_CHECKS = frozenset(
    {
        "dedicated-windows-account",
        "non-admin-windows-account",
        "dedicated-ci-distro",
        "dedicated-linux-account",
        "windows-acl-deny",
        "wsl-config",
        "prohibited-mounts-absent",
        "prohibited-sockets-absent",
        "prohibited-secrets-absent",
        "management-workload-separated",
        "default-deny-egress",
        "blocked-network-ranges",
        "proxy-allowlist-dns-fail-closed",
        "policy-loaded-before-registration",
        "policy-persists-windows-reboot",
        "policy-persists-wsl-reboot",
        "jit-one-job",
        "cleanup-success",
        "cleanup-failure",
        "cleanup-cancel",
        "cleanup-timeout",
        "cleanup-force-cancel",
        "cleanup-reboot",
        "no-orphan-registration",
    }
)

PROHIBITED_ARTIFACT_KINDS = frozenset(
    {
        "windows-drive",
        "fstab-windows-mount",
        "windows-executable",
        "windows-path",
        "wsl-interop",
        "docker-desktop-socket",
        "container-engine-socket",
        "personal-distro-mount",
        "ssh-agent",
        "deploy-credential",
        "reviewer-credential",
        "control-plane-credential",
    }
)


@dataclass(frozen=True)
class EvidenceCheck:
    check_id: str
    status: str
    evidence_refs: tuple[str, ...]
    notes: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvidenceCheck":
        if not isinstance(value, Mapping):
            raise HostSecurityError("host check must be an object")
        allowed = {"id", "status", "evidence_refs", "notes"}
        if set(value) - allowed or set(value) < {"id", "status", "evidence_refs"}:
            raise HostSecurityError("host check has missing or unknown fields")
        status = value["status"]
        refs = value["evidence_refs"]
        if not isinstance(value["id"], str) or not value["id"]:
            raise HostSecurityError("host check id must be a non-empty string")
        if status not in {"pass", "fail", "unverified"}:
            raise HostSecurityError(f"invalid host check status: {status!r}")
        if not isinstance(refs, list) or not all(isinstance(ref, str) and ref for ref in refs):
            raise HostSecurityError("evidence_refs must be a list of non-empty strings")
        if status == "pass" and not refs:
            raise HostSecurityError("a passing host check requires evidence")
        notes = value.get("notes", "")
        if not isinstance(notes, str):
            raise HostSecurityError("host check notes must be a string")
        return cls(value["id"], status, tuple(refs), notes)


@dataclass(frozen=True)
class HostSecurityResult:
    enabled: bool
    status: str
    blockers: tuple[str, ...]


def validate_wsl_conf(text: str) -> tuple[str, ...]:
    """Return missing/unsafe settings; an empty tuple is a valid config."""

    parser = ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except Exception as exc:  # ConfigParser exposes several parse exceptions.
        return (f"wsl-config-unparseable:{type(exc).__name__}",)
    blockers = []
    for (section, option), expected in REQUIRED_WSL_SETTINGS.items():
        actual = parser.get(section, option, fallback=None)
        if actual is None or actual.strip().lower() != expected:
            blockers.append(f"wsl-config:{section}.{option}={actual!r}")
    return tuple(blockers)


def evaluate_network_policy(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate default-deny, management separation, and reboot ordering proof."""

    if not isinstance(value, Mapping):
        return ("network-policy-schema",)
    required = {
        "default_deny",
        "management_separated",
        "denied_cidrs",
        "denied_service_classes",
        "proxy_only_egress",
        "private_dns_fail_closed",
        "loaded_before_registration",
        "windows_reboot_verified",
        "wsl_reboot_verified",
    }
    if set(value) != required:
        return ("network-policy-schema",)
    blockers: list[str] = []
    for field in (
        "default_deny",
        "management_separated",
        "proxy_only_egress",
        "private_dns_fail_closed",
        "loaded_before_registration",
        "windows_reboot_verified",
        "wsl_reboot_verified",
    ):
        if value[field] is not True:
            blockers.append(f"network-policy:{field}")
    denied = value["denied_cidrs"]
    if not isinstance(denied, list) or not all(isinstance(item, str) for item in denied) or not BLOCKED_NETWORK_CIDRS.issubset(denied):
        blockers.append("network-policy:blocked-cidrs")
    services = value["denied_service_classes"]
    required_services = {"windows-host", "management", "reviewer", "control", "deploy", "local-sockets", "container-api"}
    if not isinstance(services, list) or not all(isinstance(item, str) for item in services) or not required_services.issubset(services):
        blockers.append("network-policy:service-canaries")
    return tuple(blockers)


def evaluate_runner_lifecycle(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Prove one ephemeral registration/job and cleanup in every terminal mode."""

    if not isinstance(value, Mapping):
        return ("runner-lifecycle-schema",)
    required = {
        "jit",
        "ephemeral_registration",
        "jobs_started",
        "registration_removed",
        "workspace_removed",
        "token_removed",
        "container_removed",
        "allocation_removed",
        "normal_cancel_attempted_before_force",
        "terminal_mode",
        "orphan_registrations",
    }
    if set(value) != required:
        return ("runner-lifecycle-schema",)
    blockers: list[str] = []
    if value["jit"] is not True or value["ephemeral_registration"] is not True:
        blockers.append("runner-lifecycle:not-jit-ephemeral")
    mode = value["terminal_mode"]
    if value["jobs_started"] != 1:
        blockers.append("runner-lifecycle:not-exactly-one-job")
    for field in ("registration_removed", "workspace_removed", "token_removed", "container_removed", "allocation_removed"):
        if value[field] is not True:
            blockers.append(f"runner-lifecycle:{field}")
    if mode not in {"success", "failure", "cancel", "timeout", "force-cancel", "reboot"}:
        blockers.append("runner-lifecycle:terminal-mode")
    if mode == "force-cancel" and value["normal_cancel_attempted_before_force"] is not True:
        blockers.append("runner-lifecycle:force-without-normal-cancel")
    if value["orphan_registrations"] != 0:
        blockers.append("runner-lifecycle:orphan-registration")
    return tuple(blockers)


def evaluate_host_security(value: Mapping[str, Any]) -> HostSecurityResult:
    """Recompute the host decision. Unknown and missing evidence fail closed."""

    if not isinstance(value, Mapping):
        raise HostSecurityError("host evidence must be an object")
    allowed = {
        "host_security_schema_version",
        "platform",
        "distro_name",
        "personal_distro_names",
        "wsl_conf",
        "checks",
        "observed_artifact_kinds",
        "network_policy",
        "runner_lifecycle_runs",
    }
    if set(value) != allowed or value.get("host_security_schema_version") != 1:
        raise HostSecurityError("host evidence schema v1 requires exact fields")
    blockers: list[str] = []
    if value["platform"] != "wsl2":
        blockers.append("platform-unverified-not-wsl2")
    distro = value["distro_name"]
    personal = value["personal_distro_names"]
    if not isinstance(distro, str) or not distro or not isinstance(personal, list) or distro in personal:
        blockers.append("distro-not-dedicated")
    blockers.extend(validate_wsl_conf(value["wsl_conf"]))

    observed = value["observed_artifact_kinds"]
    if not isinstance(observed, list) or not all(isinstance(item, str) for item in observed):
        blockers.append("observed-artifacts-schema")
    else:
        blockers.extend(f"prohibited-artifact:{kind}" for kind in sorted(PROHIBITED_ARTIFACT_KINDS.intersection(observed)))

    raw_checks = value["checks"]
    if not isinstance(raw_checks, list):
        raise HostSecurityError("checks must be a list")
    checks = [EvidenceCheck.from_mapping(item) for item in raw_checks]
    by_id = {item.check_id: item for item in checks}
    if len(by_id) != len(checks):
        raise HostSecurityError("duplicate host check id")
    blockers.extend(f"missing-check:{check}" for check in sorted(REQUIRED_CHECKS - set(by_id)))
    blockers.extend(f"check-{check.status}:{check.check_id}" for check in checks if check.status != "pass")
    blockers.extend(evaluate_network_policy(value["network_policy"]))

    runs = value["runner_lifecycle_runs"]
    if not isinstance(runs, list):
        raise HostSecurityError("runner_lifecycle_runs must be a list")
    modes = set()
    for index, run in enumerate(runs):
        if isinstance(run, Mapping):
            modes.add(run.get("terminal_mode"))
        blockers.extend(f"run-{index}:{reason}" for reason in evaluate_runner_lifecycle(run))
    required_modes = {"success", "failure", "cancel", "timeout", "force-cancel", "reboot"}
    blockers.extend(f"missing-lifecycle-mode:{mode}" for mode in sorted(required_modes - modes))

    unique = tuple(dict.fromkeys(blockers))
    return HostSecurityResult(not unique, "verified" if not unique else "unverified", unique)


def inert_host_evidence(platform: str) -> dict[str, Any]:
    """Build explicit non-enabling evidence for unsupported/current hosts."""

    return {
        "host_security_schema_version": 1,
        "platform": platform,
        "distro_name": "",
        "personal_distro_names": [],
        "wsl_conf": "",
        "checks": [],
        "observed_artifact_kinds": [],
        "network_policy": {},
        "runner_lifecycle_runs": [],
    }
