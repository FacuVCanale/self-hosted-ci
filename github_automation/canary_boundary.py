"""Signed, narrowly-scoped authorization for runner lifecycle canaries.

The authorization deliberately cannot enable production dispatch, a required
check, or the outbound worker.  It permits at most six single-job allocations
solely to collect the six terminal lifecycle proofs required by the final
runner boundary.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import canonicalize_jcs, sign_detached, spki_fingerprint, verify_detached


class CanaryBoundaryError(ValueError):
    pass


CANARY_ATTESTATION_DOMAIN = b"self-hosted-ci/jit-canary-authorization/v1"
CANARY_SCENARIOS = (
    "success",
    "failure",
    "cancel",
    "timeout",
    "force-cancel",
    "reboot",
)
MAX_AUTHORIZATION_TTL_SECONDS = 120 * 60
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REF = re.compile(r"^[A-Za-z0-9._/-]+$")
_WORKFLOW = ".github/workflows/ci-jit-canary-child.yml"

_UNSIGNED_FIELDS = {
    "schema_version",
    "purpose",
    "production_activation_authorized",
    "outbound_worker_authorized",
    "required_check_authorized",
    "github_contact_authorized",
    "runner_registration_authorized",
    "repository",
    "repository_id",
    "pull_request",
    "base_sha",
    "head_sha",
    "tested_merge_sha",
    "workflow_ref",
    "dispatch_sha",
    "garm_entity",
    "image_alias",
    "image_fingerprint",
    "allocation_signer_fingerprint",
    "github_app_config_digest",
    "live_job_verifier_digest",
    "network_policy_digest",
    "bootstrap_install_receipt_digest",
    "scenarios",
    "max_allocations",
    "max_concurrency",
    "max_jobs_per_allocation",
    "issued_at",
    "expires_at",
    "nonce",
}


@dataclass(frozen=True)
class CanaryAuthorizationDecision:
    authorized: bool
    blockers: tuple[str, ...]
    nonce: str | None = None
    repository: str | None = None
    scenarios: tuple[str, ...] = ()
    issued_at: datetime | None = None
    expires_at: datetime | None = None


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CanaryBoundaryError(f"{field} must be canonical UTC seconds")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CanaryBoundaryError(f"{field} must be canonical UTC seconds") from exc
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise CanaryBoundaryError(f"{field} must be canonical UTC seconds")
    return parsed


def _uuid(value: object, field: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _unsigned(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "attestation"}


def authorization_digest(value: Mapping[str, Any]) -> str:
    """Digest the unsigned authorization; signatures are transport metadata."""

    payload = _unsigned(value)
    blockers = validate_canary_authorization(payload)
    if blockers:
        raise CanaryBoundaryError(", ".join(blockers))
    return hashlib.sha256(canonicalize_jcs(payload)).hexdigest()


def validate_canary_authorization(
    value: Mapping[str, Any], *, now: datetime | None = None
) -> tuple[str, ...]:
    blockers: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _UNSIGNED_FIELDS:
        return ("canary-authorization-schema",)
    if value.get("schema_version") != 1 or value.get("purpose") != "runner-lifecycle-proof-only":
        blockers.append("canary-authorization-purpose")
    for field, expected in (
        ("production_activation_authorized", False),
        ("outbound_worker_authorized", False),
        ("required_check_authorized", False),
        ("github_contact_authorized", True),
        ("runner_registration_authorized", True),
    ):
        if value.get(field) is not expected:
            blockers.append(f"canary-authorization:{field}")
    repository = value.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        blockers.append("canary-authorization:repository")
    for field in ("repository_id", "pull_request"):
        if type(value.get(field)) is not int or value[field] < 1:
            blockers.append(f"canary-authorization:{field}")
    for field in ("base_sha", "head_sha", "tested_merge_sha", "dispatch_sha"):
        if not isinstance(value.get(field), str) or not _SHA.fullmatch(value[field]):
            blockers.append(f"canary-authorization:{field}")
    workflow = value.get("workflow_ref")
    if (
        not isinstance(workflow, str)
        or not isinstance(repository, str)
        or not workflow.startswith(repository + "/" + _WORKFLOW + "@refs/heads/")
        or not _REF.fullmatch(workflow.rsplit("@refs/heads/", 1)[-1])
    ):
        blockers.append("canary-authorization:workflow_ref")
    entity = value.get("garm_entity")
    entity_fields = {"authority_kind", "entity_id", "entity_name", "runner_group"}
    if not isinstance(entity, Mapping) or set(entity) != entity_fields:
        blockers.append("canary-authorization:garm_entity")
    else:
        kind = entity.get("authority_kind")
        if kind not in {"personal-repository", "organization-runner-group"}:
            blockers.append("canary-authorization:garm_authority")
        if not _uuid(entity.get("entity_id"), "entity_id") or not isinstance(entity.get("entity_name"), str) or not entity["entity_name"]:
            blockers.append("canary-authorization:garm_identity")
        group = entity.get("runner_group")
        if (kind == "personal-repository" and group is not None) or (
            kind == "organization-runner-group" and (not isinstance(group, str) or not group)
        ):
            blockers.append("canary-authorization:runner_group")
    if not isinstance(value.get("image_alias"), str) or not value["image_alias"]:
        blockers.append("canary-authorization:image_alias")
    for field in (
        "image_fingerprint",
        "allocation_signer_fingerprint",
        "github_app_config_digest",
        "live_job_verifier_digest",
        "network_policy_digest",
        "bootstrap_install_receipt_digest",
    ):
        if not isinstance(value.get(field), str) or not _HEX_256.fullmatch(value[field]):
            blockers.append(f"canary-authorization:{field}")
    if value.get("scenarios") != list(CANARY_SCENARIOS):
        blockers.append("canary-authorization:scenarios")
    for field, expected in (
        ("max_allocations", 6),
        ("max_concurrency", 1),
        ("max_jobs_per_allocation", 1),
    ):
        if value.get(field) != expected or type(value.get(field)) is not int:
            blockers.append(f"canary-authorization:{field}")
    if not isinstance(value.get("nonce"), str) or not _NONCE.fullmatch(value["nonce"]):
        blockers.append("canary-authorization:nonce")
    try:
        issued = _timestamp(value.get("issued_at"), "issued_at")
        expires = _timestamp(value.get("expires_at"), "expires_at")
        if expires <= issued or (expires - issued).total_seconds() > MAX_AUTHORIZATION_TTL_SECONDS:
            blockers.append("canary-authorization:lifetime")
        if now is not None:
            if now.tzinfo is None:
                raise CanaryBoundaryError("canary verification clock must be timezone-aware")
            current = now.astimezone(timezone.utc)
            if current < issued:
                blockers.append("canary-authorization:not-yet-valid")
            elif current >= expires:
                blockers.append("canary-authorization:expired")
    except CanaryBoundaryError as exc:
        blockers.append(str(exc))
    return tuple(dict.fromkeys(blockers))


def sign_canary_authorization(
    value: Mapping[str, Any], private_key: ed25519.Ed25519PrivateKey
) -> dict[str, Any]:
    if "attestation" in value:
        raise CanaryBoundaryError("canary authorization must be unsigned before attestation")
    blockers = validate_canary_authorization(value)
    if blockers:
        raise CanaryBoundaryError(", ".join(blockers))
    payload = dict(value)
    return {
        **payload,
        "attestation": {
            "attestation_version": 1,
            "signer_fingerprint": spki_fingerprint(private_key.public_key()),
            "signature": sign_detached(payload, private_key, domain=CANARY_ATTESTATION_DOMAIN),
        },
    }


def verify_canary_authorization(
    value: Mapping[str, Any],
    public_key: ed25519.Ed25519PublicKey,
    *,
    pinned_fingerprint: str,
    now: datetime | None = None,
) -> CanaryAuthorizationDecision:
    if not isinstance(value, Mapping) or set(value) != _UNSIGNED_FIELDS | {"attestation"}:
        raise CanaryBoundaryError("signed canary authorization requires exact fields")
    attestation = value.get("attestation")
    if (
        not isinstance(attestation, Mapping)
        or set(attestation) != {"attestation_version", "signer_fingerprint", "signature"}
        or attestation.get("attestation_version") != 1
    ):
        raise CanaryBoundaryError("canary authorization attestation requires exact v1 fields")
    actual = spki_fingerprint(public_key)
    if (
        not _HEX_256.fullmatch(pinned_fingerprint)
        or actual != pinned_fingerprint
        or attestation.get("signer_fingerprint") != pinned_fingerprint
    ):
        raise CanaryBoundaryError("canary authorization signer does not match pinned reviewer key")
    payload = _unsigned(value)
    try:
        verify_detached(payload, attestation.get("signature"), public_key, domain=CANARY_ATTESTATION_DOMAIN)
    except ValueError as exc:
        raise CanaryBoundaryError("canary authorization signature is invalid") from exc
    blockers = validate_canary_authorization(payload, now=now)
    issued = expires = None
    try:
        issued = _timestamp(payload.get("issued_at"), "issued_at")
        expires = _timestamp(payload.get("expires_at"), "expires_at")
    except CanaryBoundaryError:
        pass
    return CanaryAuthorizationDecision(
        not blockers,
        blockers,
        payload.get("nonce") if isinstance(payload.get("nonce"), str) else None,
        payload.get("repository") if isinstance(payload.get("repository"), str) else None,
        tuple(payload.get("scenarios", ())) if isinstance(payload.get("scenarios"), list) else (),
        issued,
        expires,
    )
