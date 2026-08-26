"""Fail-closed, side-effect-free contracts for the GitHub control boundary.

The objects in this module validate data immediately before a network adapter
would use it.  They deliberately do not perform HTTP calls or handle secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Sequence


PINNED_GITHUB_API_VERSION = "2026-03-10"
CI_GATE_NAME = "ci-gate"
ALLOWED_CONTROL_ROLES = frozenset({"coordinator", "reconciler"})
MINIMUM_APP_PERMISSIONS = {"metadata": "read", "checks": "write"}
FORBIDDEN_APP_PERMISSIONS = frozenset(
    {
        "contents",
        "commit_statuses",
        "actions",
        "workflows",
        "administration",
        "pull_requests",
        "issues",
        "deployments",
        "environments",
        "secrets",
        "members",
        "organization_administration",
    }
)

_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACCOUNT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


class GitHubContractError(ValueError):
    """A GitHub boundary input is unsafe, ambiguous, or outside v1."""


class ControlFailure(GitHubContractError):
    """GitHub App authority is not the exact pinned authority."""


class ProtocolFailure(GitHubContractError):
    """Coordinator/child protocol evidence is invalid or ambiguous."""


@dataclass(frozen=True)
class RuntimeIdentity:
    role: str
    workflow_identity: str
    workflow_ref: str
    reviewed_default_branch_code: bool = True


@dataclass(frozen=True)
class MintRequest:
    app_id: int
    installation_id: int
    repository: str
    repository_id: int
    permissions: Mapping[str, str]
    ttl_seconds: int
    memory_only: bool = True
    masked: bool = True
    export_to_children: bool = False
    persist: bool = False


@dataclass(frozen=True)
class AppAuthorityV1:
    """Non-secret authority record for one selected repository."""

    owner: str
    app_id: int
    app_slug: str
    repository: str
    repository_id: int
    installation_id: int
    control_workflow_identity: str
    control_workflow_ref: str
    key_fingerprint: str
    key_version: int
    rotated_at: datetime
    permissions: Mapping[str, str]
    ci_gate_authority_version: int = 1
    key_state: str = "active"

    def __post_init__(self) -> None:
        if self.ci_gate_authority_version != 1:
            raise ControlFailure("ci_gate_authority_version must be 1")
        if not _ACCOUNT.fullmatch(self.owner):
            raise ControlFailure("authority owner must be a canonical GitHub account")
        _positive_int(self.app_id, "app_id", ControlFailure)
        _positive_int(self.repository_id, "repository_id", ControlFailure)
        _positive_int(self.installation_id, "installation_id", ControlFailure)
        _positive_int(self.key_version, "key_version", ControlFailure)
        _exact_repository(self.repository, ControlFailure)
        if not self.app_slug or self.app_slug != self.app_slug.lower():
            raise ControlFailure("app_slug must be a non-empty canonical slug")
        if not self.control_workflow_identity or not self.control_workflow_ref:
            raise ControlFailure("exact control workflow identity/ref are required")
        if not _SHA256.fullmatch(self.key_fingerprint):
            raise ControlFailure("key_fingerprint must be lowercase SHA-256")
        _aware(self.rotated_at, "rotated_at", ControlFailure)
        if dict(self.permissions) != MINIMUM_APP_PERMISSIONS:
            raise ControlFailure("App permissions must be exactly metadata:read/checks:write")
        if self.key_state not in {"active", "revoked"}:
            raise ControlFailure("App key_state must be active or revoked")

    def mint(self, identity: RuntimeIdentity, request: MintRequest) -> MintRequest:
        """Authorize a narrow token request; no token or key material is handled."""
        if self.key_state != "active":
            raise ControlFailure("revoked App key cannot mint")
        if (
            identity.role not in ALLOWED_CONTROL_ROLES
            or identity.workflow_identity != self.control_workflow_identity
            or identity.workflow_ref != self.control_workflow_ref
            or not identity.reviewed_default_branch_code
        ):
            raise ControlFailure("runtime identity is not the pinned control plane")
        if (
            request.app_id != self.app_id
            or request.installation_id != self.installation_id
            or request.repository != self.repository
            or request.repository_id != self.repository_id
        ):
            raise ControlFailure("App/install/repository scope mismatch")
        if dict(request.permissions) != MINIMUM_APP_PERMISSIONS:
            raise ControlFailure("mint permissions are not exactly narrow")
        if isinstance(request.ttl_seconds, bool) or not 0 < request.ttl_seconds <= 3600:
            raise ControlFailure("token TTL must be in 1..3600 seconds")
        if not request.memory_only or not request.masked or request.export_to_children or request.persist:
            raise ControlFailure("token storage/export invariants violated")
        return request

    def permits(self, operation: str, *, repository: str, installation_id: int) -> bool:
        """Model the positive and negative permission matrix without a token."""
        if self.key_state != "active":
            return False
        if repository != self.repository or installation_id != self.installation_id:
            return False
        return operation in {"checks:create", "checks:update", "metadata:read"}

    def rotated_to(self, successor: "AppAuthorityV1") -> "AppAuthorityV1":
        """Validate the new-before-old portion of a key rotation."""
        stable = (
            "owner",
            "app_id",
            "app_slug",
            "repository",
            "repository_id",
            "installation_id",
            "control_workflow_identity",
            "control_workflow_ref",
            "permissions",
            "ci_gate_authority_version",
        )
        if any(getattr(self, field) != getattr(successor, field) for field in stable):
            raise ControlFailure("rotation changed pinned App authority")
        if self.key_state != "active" or successor.key_state != "active":
            raise ControlFailure("rotation requires active old and new keys before switch")
        if successor.key_version <= self.key_version:
            raise ControlFailure("rotation key_version must increase")
        if successor.key_fingerprint == self.key_fingerprint:
            raise ControlFailure("rotation must change key fingerprint")
        if successor.rotated_at <= self.rotated_at:
            raise ControlFailure("rotation timestamp must increase")
        return successor

    def revoked(self) -> "AppAuthorityV1":
        return AppAuthorityV1(**{**self.__dict__, "key_state": "revoked"})


@dataclass(frozen=True)
class DispatchRequest:
    repository: str
    workflow_id: str
    ref: str
    default_branch: str
    api_version: str = PINNED_GITHUB_API_VERSION

    def __post_init__(self) -> None:
        _exact_repository(self.repository, ProtocolFailure)
        if (
            not isinstance(self.workflow_id, str)
            or not self.workflow_id
            or "/" in self.workflow_id
            or self.workflow_id in {".", ".."}
        ):
            raise ProtocolFailure("dispatch workflow_id must be one exact workflow file or ID")
        if not isinstance(self.default_branch, str) or not self.default_branch:
            raise ProtocolFailure("exact default branch is required")
        if self.ref != self.default_branch:
            raise ProtocolFailure("child workflow ref must be the trusted default branch")
        if self.api_version != PINNED_GITHUB_API_VERSION:
            raise ProtocolFailure("GitHub API version is not pinned")


def parse_dispatch_response(request: DispatchRequest, status: int, body: Mapping[str, Any]) -> int:
    """Consume the exact returned run ID.  Run-list correlation is not an API."""
    if status != 200:
        raise ProtocolFailure("dispatch must return HTTP 200")
    if set(body) != {"workflow_run_id", "run_url", "html_url"}:
        raise ProtocolFailure("dispatch response schema must contain only workflow_run_id, run_url and html_url")
    run_id = body.get("workflow_run_id")
    _positive_int(run_id, "workflow_run_id", ProtocolFailure)
    expected_run_url = f"https://api.github.com/repos/{request.repository}/actions/runs/{run_id}"
    expected_html_url = f"https://github.com/{request.repository}/actions/runs/{run_id}"
    if body.get("run_url") != expected_run_url:
        raise ProtocolFailure("dispatch run_url is not bound to the exact repository and run")
    if body.get("html_url") != expected_html_url:
        raise ProtocolFailure("dispatch html_url is not bound to the exact repository and run")
    return run_id


_PROTOCOL_FIELDS = frozenset(
    {
        "protocol_version", "timing_policy_version", "execution_trust_policy_version",
        "repository_id", "repository", "pr_number", "logical_key", "generation",
        "owner_run_id", "owner_run_attempt", "head_sha", "base_sha", "tested_merge_sha",
        "tested_sha", "check_target_sha", "default_branch", "backend",
        "policy_version", "execution_trust_mode", "execution_trust_attestation_authority_version",
        "execution_trust_key_manifest_version", "key_manifest_generation", "key_manifest_digest",
        "key_manifest_generation_at_issuance", "key_manifest_digest_at_issuance", "attestation_id",
        "attestation_key_id", "attestation_key_version", "attestation_public_key_fingerprint",
        "attestation_head_generation", "attestation_expires_at", "attestation_nonce_binding",
        "attestation_envelope_digest", "attestation_request_linkage_hash", "inventory_guard_status",
        "missing_source_ids", "effective_writer_inventory_hash", "inventory_observed_at",
        "inventory_guard_freshness_policy_version", "local_admission_id", "local_admission_digest",
        "local_evidence_id", "local_evidence_digest", "local_result_kind", "local_child_run_id",
        "local_child_job_id", "started_test_marker_digest", "canonical_command_digest", "terminal_at",
        "ci_gate_check_run_id", "check_outbox_idempotency_key", "claim_deadline",
        "execution_deadline",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "key_manifest_generation_at_issuance", "key_manifest_digest_at_issuance", "attestation_id",
        "attestation_key_id", "attestation_key_version", "attestation_public_key_fingerprint",
        "attestation_head_generation", "attestation_expires_at", "attestation_nonce_binding",
        "attestation_envelope_digest", "attestation_request_linkage_hash",
    }
)


@dataclass(frozen=True)
class ProtocolPackage:
    values: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProtocolPackage":
        if not isinstance(value, Mapping):
            raise ProtocolFailure("protocol must be an object")
        missing = sorted(_PROTOCOL_FIELDS - set(value))
        unknown = sorted(set(value) - _PROTOCOL_FIELDS)
        if missing or unknown:
            raise ProtocolFailure(f"protocol fields mismatch; missing={missing}, unknown={unknown}")
        data = dict(value)
        for field in ("protocol_version", "timing_policy_version", "execution_trust_policy_version",
                      "execution_trust_attestation_authority_version",
                      "execution_trust_key_manifest_version", "inventory_guard_freshness_policy_version"):
            if data[field] != 1:
                raise ProtocolFailure(f"{field} must be 1")
        for field in ("repository_id", "pr_number", "generation", "owner_run_id", "owner_run_attempt",
                      "key_manifest_generation", "ci_gate_check_run_id"):
            _positive_int(data[field], field, ProtocolFailure)
        _exact_repository(data["repository"], ProtocolFailure)
        for field in ("head_sha", "base_sha", "tested_merge_sha", "tested_sha", "check_target_sha"):
            if not isinstance(data[field], str) or not _SHA.fullmatch(data[field]):
                raise ProtocolFailure(f"{field} must be a full lowercase 40-character SHA")
        if data["tested_sha"] != data["tested_merge_sha"] or data["check_target_sha"] != data["tested_merge_sha"]:
            raise ProtocolFailure("PR tested/check target SHA must equal exact synthetic merge SHA")
        expected_key = f'{data["repository_id"]}:{data["pr_number"]}:{data["head_sha"]}:ci-gate'
        if data["logical_key"] != expected_key:
            raise ProtocolFailure("logical_key does not bind repository/PR/head/ci-gate")
        if not isinstance(data["default_branch"], str) or not data["default_branch"]:
            raise ProtocolFailure("trusted default branch is required")
        if not isinstance(data["policy_version"], str) or not _SHA.fullmatch(data["policy_version"]):
            raise ProtocolFailure("policy_version must be an exact commit SHA")
        if not isinstance(data["key_manifest_digest"], str) or not _SHA256.fullmatch(data["key_manifest_digest"]):
            raise ProtocolFailure("key_manifest_digest must be lowercase SHA-256")
        if data["inventory_guard_status"] not in {"complete", "partial", "unavailable"}:
            raise ProtocolFailure("invalid inventory guard status")
        if not isinstance(data["missing_source_ids"], list) or data["missing_source_ids"] != sorted(set(data["missing_source_ids"])):
            raise ProtocolFailure("missing_source_ids must be a sorted unique list")
        for field in ("claim_deadline", "execution_deadline"):
            _parse_time(data[field], field)
        backend = data["backend"]
        if backend == "local":
            if data["execution_trust_mode"] != "exact-sha-attestation":
                raise ProtocolFailure("local backend requires exact-sha-attestation")
            if any(data[field] is None for field in _ATTESTATION_FIELDS):
                raise ProtocolFailure("local backend requires complete attestation authority fields")
            for field in ("key_manifest_digest_at_issuance", "attestation_public_key_fingerprint",
                          "attestation_envelope_digest", "attestation_request_linkage_hash",
                          "effective_writer_inventory_hash"):
                if not isinstance(data[field], str) or not _SHA256.fullmatch(data[field]):
                    raise ProtocolFailure(f"{field} must be lowercase SHA-256")
            if data["inventory_guard_status"] == "unavailable":
                raise ProtocolFailure("local backend rejects unavailable inventory")
        elif backend == "github":
            if data["execution_trust_mode"] != "github-hosted":
                raise ProtocolFailure("github backend requires github-hosted trust mode")
            if any(data[field] is not None for field in _ATTESTATION_FIELDS):
                raise ProtocolFailure("hosted dispatch cannot carry attestation authority")
            local_fields = {
                "local_admission_id", "local_admission_digest", "local_evidence_id",
                "local_evidence_digest", "local_result_kind", "local_child_run_id",
                "local_child_job_id", "started_test_marker_digest", "canonical_command_digest",
                "terminal_at", "check_outbox_idempotency_key",
            }
            if any(data[field] is not None for field in local_fields):
                raise ProtocolFailure("hosted dispatch cannot cross-bind local result fields")
        else:
            raise ProtocolFailure("backend must be local or github")
        return cls(data)

    def assert_current_tuple(self, *, repository_id: int, repository: str, pr_number: int,
                             head_sha: str, base_sha: str, tested_merge_sha: str,
                             generation: int) -> None:
        expected = {
            "repository_id": repository_id, "repository": repository, "pr_number": pr_number,
            "head_sha": head_sha, "base_sha": base_sha, "tested_merge_sha": tested_merge_sha,
            "generation": generation,
        }
        if any(self.values[key] != wanted for key, wanted in expected.items()):
            raise ProtocolFailure("protocol package is stale or for a different exact tuple")

    def assert_checkout(self, git_head: str) -> None:
        if git_head != self.values["tested_sha"]:
            raise ProtocolFailure("checkout HEAD differs from tested_sha")


def validate_ci_gate_source(event: Mapping[str, Any], *, authority: AppAuthorityV1,
                            check_target_sha: str) -> bool:
    """Accept only the explicit custom Check Run from the dedicated App."""
    return bool(
        event.get("kind") == "check_run"
        and event.get("explicit_custom_check") is True
        and event.get("name") == CI_GATE_NAME
        and event.get("app_id") == authority.app_id
        and event.get("app_slug") == authority.app_slug
        and event.get("repository") == authority.repository
        and event.get("installation_id") == authority.installation_id
        and event.get("head_sha") == check_target_sha
    )


def validate_formal_claim(*, package: ProtocolPackage, dispatch_run_id: int,
                          run: Mapping[str, Any], jobs: Sequence[Mapping[str, Any]],
                          expected_workflow_id: str, expected_job_name: str,
                          expected_labels: Sequence[str], expected_runner_id: str) -> bool:
    """Validate the normative Runs+Jobs API claim predicate."""
    data = package.values
    if run.get("id") != dispatch_run_id or run.get("id") != data["local_child_run_id"]:
        raise ProtocolFailure("claim run is not the exact dispatch-returned run ID")
    exact_run = {
        "workflow_id": expected_workflow_id,
        "repository": data["repository"],
        "workflow_ref": data["default_branch"],
        "generation": data["generation"],
        "backend": "local",
    }
    if any(run.get(key) != value for key, value in exact_run.items()):
        raise ProtocolFailure("run identity/ref/generation/backend mismatch")
    if len(jobs) != 1:
        raise ProtocolFailure("formal claim requires exactly one expected job")
    job = jobs[0]
    if job.get("id") != data["local_child_job_id"] or job.get("name") != expected_job_name:
        raise ProtocolFailure("exact child job identity mismatch")
    started_at = _parse_time(job.get("started_at"), "started_at")
    if started_at > _parse_time(data["claim_deadline"], "claim_deadline"):
        raise ProtocolFailure("job did not start by claim deadline")
    if set(job.get("labels", ())) != set(expected_labels):
        raise ProtocolFailure("job labels do not exactly match the allocation")
    runner = job.get("runner")
    if not isinstance(runner, Mapping) or runner.get("id") != expected_runner_id:
        raise ProtocolFailure("fresh exact runner identity is absent")
    if runner.get("ephemeral") is not True or runner.get("fresh") is not True:
        raise ProtocolFailure("runner is not a fresh ephemeral allocation")
    if runner.get("online") is not True:
        raise ProtocolFailure("claimed runner is not online")
    return True


def hosted_conclusion_allowed(*, package: ProtocolPackage, gate: Mapping[str, Any],
                              hosted: Mapping[str, Any], authority: AppAuthorityV1,
                              now: datetime) -> bool:
    """Evaluate hosted completion without consulting any attestation state."""
    data = package.values
    try:
        lease_expiry = _parse_time(gate.get("lease_expires_at"), "lease_expires_at")
        terminal_at = _parse_time(hosted.get("terminal_at"), "terminal_at")
        execution_deadline = _parse_time(hosted.get("execution_deadline"), "execution_deadline")
        _aware(now, "now", ProtocolFailure)
    except GitHubContractError:
        return False
    if data["backend"] != "github" or gate.get("winner") != "github":
        return False
    if now.astimezone(timezone.utc) >= lease_expiry:
        return False
    exact_gate = {
        "owner": data["owner_run_id"], "generation": data["generation"],
        "logical_key": data["logical_key"], "repository_id": data["repository_id"],
        "repository": data["repository"], "pr_number": data["pr_number"],
        "head_sha": data["head_sha"], "base_sha": data["base_sha"],
        "tested_merge_sha": data["tested_merge_sha"],
    }
    if any(gate.get(key) != value for key, value in exact_gate.items()):
        return False
    if not (hosted.get("tested_sha") == hosted.get("check_target_sha") == data["tested_merge_sha"]):
        return False
    if hosted.get("canonical_command_digest") != gate.get("canonical_command_digest"):
        return False
    if hosted.get("workflow_id") != gate.get("hosted_workflow_id"):
        return False
    if hosted.get("workflow_ref") != data["default_branch"]:
        return False
    if hosted.get("run_id") != gate.get("hosted_run_id") or hosted.get("job_id") != gate.get("hosted_job_id"):
        return False
    if hosted.get("trustworthy_github_hosted") is not True or terminal_at > execution_deadline:
        return False
    source = hosted.get("check_source")
    return isinstance(source, Mapping) and validate_ci_gate_source(
        source, authority=authority, check_target_sha=data["check_target_sha"]
    )


def _positive_int(value: Any, field: str, error: type[GitHubContractError]) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise error(f"{field} must be a positive integer")


def _exact_repository(value: Any, error: type[GitHubContractError]) -> None:
    if not isinstance(value, str) or "*" in value or not _REPOSITORY.fullmatch(value):
        raise error("repository must be one exact owner/repo")


def _aware(value: Any, field: str, error: type[GitHubContractError]) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise error(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_time(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        return _aware(value, field, ProtocolFailure)
    if not isinstance(value, str):
        raise ProtocolFailure(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolFailure(f"{field} must be an ISO-8601 timestamp") from exc
    return _aware(parsed, field, ProtocolFailure)
