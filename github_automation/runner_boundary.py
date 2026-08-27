"""Strict readiness evaluation for the WSL2 + GARM + Incus JIT boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import canonicalize_jcs, sign_detached, spki_fingerprint, verify_detached
from .host_security import BLOCKED_NETWORK_CIDRS, evaluate_host_security


class RunnerBoundaryError(ValueError):
    pass


REQUIRED_COMPONENTS = frozenset(
    {"windows-account", "wsl-distro", "incus", "garm", "network-policy", "runner-image"}
)
BOUNDARY_ATTESTATION_DOMAIN = b"self-hosted-ci/wsl-jit-boundary-attestation/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RunnerBoundaryDecision:
    enabled: bool
    status: str
    blockers: tuple[str, ...]


def _aggregate_digest(records: list[Mapping[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(records)).hexdigest()


def sign_runner_boundary(
    value: Mapping[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> dict[str, Any]:
    if "attestation" in value:
        raise RunnerBoundaryError("boundary must be unsigned before attestation")
    payload = dict(value)
    canonicalize_jcs(payload)
    return {
        **payload,
        "attestation": {
            "attestation_version": 1,
            "signer_fingerprint": spki_fingerprint(private_key.public_key()),
            "signature": sign_detached(
                payload, private_key, domain=BOUNDARY_ATTESTATION_DOMAIN
            ),
        },
    }


def verify_runner_boundary_attestation(
    value: Mapping[str, Any],
    public_key: ed25519.Ed25519PublicKey,
    *,
    pinned_fingerprint: str,
) -> None:
    attestation = value.get("attestation")
    if (
        not isinstance(attestation, Mapping)
        or set(attestation)
        != {"attestation_version", "signer_fingerprint", "signature"}
        or attestation.get("attestation_version") != 1
    ):
        raise RunnerBoundaryError(
            "runner boundary attestation requires exact v1 fields"
        )
    actual = spki_fingerprint(public_key)
    if (
        not _HEX_DIGEST.fullmatch(pinned_fingerprint)
        or attestation.get("signer_fingerprint") != pinned_fingerprint
        or actual != pinned_fingerprint
    ):
        raise RunnerBoundaryError(
            "runner boundary signer does not match pinned reviewer key"
        )
    payload = {key: item for key, item in value.items() if key != "attestation"}
    try:
        verify_detached(
            payload,
            attestation.get("signature"),
            public_key,
            domain=BOUNDARY_ATTESTATION_DOMAIN,
        )
    except ValueError as exc:
        raise RunnerBoundaryError(
            "runner boundary attestation signature is invalid"
        ) from exc


def verify_host_measurements(
    value: Mapping[str, Any], evidence_root: Path
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Recompute content, ownership and mode for every referenced host artifact.

    The evidence root is supplied by the host-side verifier, not by the bundle.
    Symlinks, absolute paths, path traversal, missing references and metadata
    drift all fail closed.
    """

    measurements = value.get("measurements")
    if (
        not isinstance(measurements, Mapping)
        or set(measurements)
        != {"host_measurement_version", "measurement_set_digest", "artifacts"}
        or measurements.get("host_measurement_version") != 1
    ):
        return {}, ("host-measurement-schema",)
    artifacts = measurements["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        return {}, ("host-measurement-artifacts-empty",)
    blockers: list[str] = []
    observed: dict[str, Mapping[str, Any]] = {}
    normalized_records: list[Mapping[str, Any]] = []
    root = evidence_root.resolve()
    for item in artifacts:
        required = {"ref", "sha256", "size", "mode", "uid", "gid"}
        if not isinstance(item, Mapping) or set(item) != required:
            blockers.append("host-measurement-artifact-schema")
            continue
        ref = item["ref"]
        if (
            not isinstance(ref, str)
            or not ref
            or PurePosixPath(ref).is_absolute()
            or ".." in PurePosixPath(ref).parts
        ):
            blockers.append("host-measurement-ref-invalid")
            continue
        if ref in observed:
            blockers.append(f"host-measurement-ref-duplicate:{ref}")
            continue
        path = root.joinpath(*PurePosixPath(ref).parts)
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or root not in path.resolve().parents
            ):
                blockers.append(f"host-measurement-file-invalid:{ref}")
                continue
            data = path.read_bytes()
            stat = os.stat(path, follow_symlinks=False)
        except OSError:
            blockers.append(f"host-measurement-file-unreadable:{ref}")
            continue
        actual = {
            "ref": ref,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": f"{stat.st_mode & 0o7777:04o}",
            "uid": stat.st_uid,
            "gid": stat.st_gid,
        }
        if (
            not isinstance(item["sha256"], str)
            or not _HEX_DIGEST.fullmatch(item["sha256"])
            or not isinstance(item["size"], int)
            or item["size"] < 0
            or not isinstance(item["mode"], str)
            or not re.fullmatch(r"[0-7]{4}", item["mode"])
            or not isinstance(item["uid"], int)
            or item["uid"] < 0
            or not isinstance(item["gid"], int)
            or item["gid"] < 0
        ):
            blockers.append(f"host-measurement-metadata-invalid:{ref}")
        elif dict(item) != actual:
            blockers.append(f"host-measurement-drift:{ref}")
        observed[ref] = actual
        normalized_records.append(actual)
    normalized_records.sort(key=lambda item: item["ref"])
    set_digest = _aggregate_digest(normalized_records)
    if measurements.get("measurement_set_digest") != set_digest:
        blockers.append("host-measurement-set-digest-mismatch")

    component_digests: dict[str, str] = {}
    components = value.get("components")
    if isinstance(components, list):
        for component in components:
            if not isinstance(component, Mapping) or not isinstance(
                component.get("id"), str
            ):
                continue
            refs = component.get("evidence_refs")
            if not isinstance(refs, list) or any(ref not in observed for ref in refs):
                blockers.append(f"component-measurement-missing:{component['id']}")
                continue
            records = [observed[ref] for ref in sorted(refs)]
            component_digests[component["id"]] = _aggregate_digest(records)

    host = value.get("host_security")
    if isinstance(host, Mapping) and isinstance(host.get("checks"), list):
        for check in host["checks"]:
            if isinstance(check, Mapping) and check.get("status") == "pass":
                refs = check.get("evidence_refs")
                if not isinstance(refs, list) or any(
                    ref not in observed for ref in refs
                ):
                    blockers.append(
                        f"host-check-measurement-missing:{check.get('id', 'unknown')}"
                    )

    network_bytes = canonicalize_jcs(value.get("network_policy"))
    network_refs = [
        ref
        for component in components or []
        if isinstance(component, Mapping) and component.get("id") == "network-policy"
        for ref in component.get("evidence_refs", [])
    ]
    if not any(
        ref in observed
        and root.joinpath(*PurePosixPath(ref).parts).read_bytes() == network_bytes
        for ref in network_refs
    ):
        blockers.append("network-policy-host-measurement-mismatch")
    return component_digests, tuple(dict.fromkeys(blockers))


def evaluate_runner_boundary(
    value: Mapping[str, Any],
    *,
    measured_component_digests: Mapping[str, str] | None = None,
    measurement_blockers: tuple[str, ...] = (),
    reviewer_public_key: ed25519.Ed25519PublicKey | None = None,
    pinned_reviewer_fingerprint: str | None = None,
) -> RunnerBoundaryDecision:
    required = {
        "runner_boundary_version",
        "activation_requested",
        "components",
        "host_security",
        "network_policy",
        "measurements",
        "attestation",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("runner_boundary_version") != 2
    ):
        raise RunnerBoundaryError("runner boundary requires exact v2 fields")
    blockers: list[str] = []
    if reviewer_public_key is None or pinned_reviewer_fingerprint is None:
        blockers.append("boundary-attestation-not-verified")
    else:
        verify_runner_boundary_attestation(
            value,
            reviewer_public_key,
            pinned_fingerprint=pinned_reviewer_fingerprint,
        )
    if measured_component_digests is None:
        blockers.append("host-measurement-not-verified")
        measured_component_digests = {}
    blockers.extend(measurement_blockers)
    if value["activation_requested"] is not True:
        blockers.append("activation-not-requested")
    components = value["components"]
    if not isinstance(components, list):
        raise RunnerBoundaryError("components must be a list")
    seen: set[str] = set()
    for item in components:
        if not isinstance(item, Mapping) or set(item) != {
            "id",
            "status",
            "artifact_digest",
            "evidence_refs",
        }:
            raise RunnerBoundaryError("component evidence requires exact fields")
        component_id = item["id"]
        if component_id in seen or component_id not in REQUIRED_COMPONENTS:
            raise RunnerBoundaryError("component id is duplicate or unknown")
        seen.add(component_id)
        refs = item["evidence_refs"]
        if (
            item["status"] != "verified"
            or not isinstance(item["artifact_digest"], str)
            or not _DIGEST.fullmatch(item["artifact_digest"])
        ):
            blockers.append(f"component-unverified:{component_id}")
        if (
            not isinstance(refs, list)
            or not refs
            or not all(isinstance(ref, str) and ref for ref in refs)
        ):
            blockers.append(f"component-evidence-missing:{component_id}")
        if measured_component_digests.get(component_id) != item["artifact_digest"]:
            blockers.append(
                f"component-host-measurement-digest-mismatch:{component_id}"
            )
    blockers.extend(
        f"component-missing:{item}" for item in sorted(REQUIRED_COMPONENTS - seen)
    )
    host = evaluate_host_security(value["host_security"])
    blockers.extend(f"host:{item}" for item in host.blockers)
    if value["host_security"].get("distro_name") != "Ubuntu-24.04-CI":
        blockers.append("host:unexpected-dedicated-distro-name")
    network = value["network_policy"]
    network_required = {
        "network_policy_version",
        "enabled",
        "default_egress",
        "blocked_cidrs",
        "blocked_endpoints",
        "allowed_destinations",
        "dns_private_or_rebound_resolution",
        "must_load_before_runner_registration",
        "must_survive_reboot",
        "on_install_or_verification_failure",
    }
    if (
        not isinstance(network, Mapping)
        or set(network) != network_required
        or network.get("network_policy_version") != 2
    ):
        blockers.append("network-policy-v2-invalid")
    else:
        if network["enabled"] is not True or network["default_egress"] != "deny":
            blockers.append("network-policy-not-enabled-default-deny")
        denied = network["blocked_cidrs"]
        if not isinstance(denied, list) or not BLOCKED_NETWORK_CIDRS.issubset(denied):
            blockers.append("network-policy-private-ranges-incomplete")
        endpoints = network["blocked_endpoints"]
        required_endpoints = {
            "windows-host",
            "windows-gateway",
            "metadata",
            "management-plane",
            "reviewer",
            "control-plane",
            "deploy",
            "container-engine-sockets",
            "incus-api",
        }
        if not isinstance(endpoints, list) or not required_endpoints.issubset(
            endpoints
        ):
            blockers.append("network-policy-blocked-endpoints-incomplete")
        if network["allowed_destinations"] != ["github-actions-egress-proxy"]:
            blockers.append("network-policy-egress-not-proxy-only")
        if network["dns_private_or_rebound_resolution"] != "deny":
            blockers.append("network-policy-dns-not-fail-closed")
        if (
            network["must_load_before_runner_registration"] is not True
            or network["must_survive_reboot"] is not True
        ):
            blockers.append("network-policy-order-or-persistence-unverified")
        if network["on_install_or_verification_failure"] != "block-local-dispatch":
            blockers.append("network-policy-failure-not-blocking")
    unique = tuple(dict.fromkeys(blockers))
    return RunnerBoundaryDecision(
        not unique, "verified" if not unique else "blocked", unique
    )
