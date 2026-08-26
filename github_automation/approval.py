"""Bounded, fail-closed approval request and procedural audit contracts.

This module deliberately does not load keys or sign.  It constrains the input
that an out-of-repository signing helper may accept and records only opaque,
non-authoritative request linkage plus the normalized exact target/outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping

from .crypto import canonicalize_jcs


_CANONICAL_POSITIVE = re.compile(r"^[1-9][0-9]*$")
_HEAD_SHA = re.compile(r"^[0-9a-f]{40}$")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ApprovalContractError(ValueError):
    pass


@dataclass(frozen=True)
class BoundedSigningRequest:
    repository_id: str
    repository: str
    pr_number: int
    head_sha: str
    request_linkage_hash: str
    expected_head_generation: str | None = None

    @classmethod
    def validate(cls, value: Mapping[str, Any]) -> "BoundedSigningRequest":
        if not isinstance(value, Mapping):
            raise ApprovalContractError("signing request must be a typed object")
        required = {"repository_id", "repository", "pr_number", "head_sha", "request_linkage_hash"}
        optional = {"expected_head_generation"}
        if not required <= set(value) or set(value) - required - optional:
            raise ApprovalContractError("signing request has missing or forbidden fields")
        request = cls(
            repository_id=value["repository_id"],
            repository=value["repository"],
            pr_number=value["pr_number"],
            head_sha=value["head_sha"],
            request_linkage_hash=value["request_linkage_hash"],
            expected_head_generation=value.get("expected_head_generation"),
        )
        if not isinstance(request.repository_id, str) or not _CANONICAL_POSITIVE.fullmatch(request.repository_id):
            raise ApprovalContractError("repository_id must be a canonical positive string")
        if not isinstance(request.repository, str) or not _REPOSITORY.fullmatch(request.repository):
            raise ApprovalContractError("repository must be one exact owner/repo")
        if type(request.pr_number) is not int or request.pr_number < 1:
            raise ApprovalContractError("pr_number must identify one exact PR")
        if not isinstance(request.head_sha, str) or not _HEAD_SHA.fullmatch(request.head_sha):
            raise ApprovalContractError("head_sha must identify one resolved current head")
        if not isinstance(request.request_linkage_hash, str) or not _HEX_256.fullmatch(request.request_linkage_hash):
            raise ApprovalContractError("request linkage must be an opaque SHA-256 value")
        if request.expected_head_generation is not None and (
            not isinstance(request.expected_head_generation, str)
            or not _CANONICAL_POSITIVE.fullmatch(request.expected_head_generation)
        ):
            raise ApprovalContractError("expected_head_generation must be canonical when supplied")
        return request

    def target_mapping(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "repository": self.repository,
            "pr_number": self.pr_number,
            "head_sha": self.head_sha,
            "expected_head_generation": self.expected_head_generation,
        }


@dataclass(frozen=True)
class ProceduralApprovalContext:
    """Agent-asserted procedural evidence; never a cryptographic assertion."""

    explicit_same_thread_request: bool
    requested_target_count: int
    requested_scope: str
    references_future_head: bool = False


@dataclass(frozen=True)
class ApprovalAuditRecord:
    request_linkage_hash: str | None
    target: Mapping[str, Any] | None
    outcome: str
    reason: str

    def to_mapping(self) -> dict[str, Any]:
        # Fixed projection prevents transcript, prompt, credentials, key
        # material or shared passwords from leaking through caller metadata.
        return {
            "request_linkage_hash": self.request_linkage_hash,
            "target": dict(self.target) if self.target is not None else None,
            "outcome": self.outcome,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    request: BoundedSigningRequest | None
    audit: ApprovalAuditRecord


@dataclass(frozen=True)
class ResolvedSigningTarget:
    repository_id: str
    repository: str
    pr_number: int
    head_sha: str
    head_generation: str


def resolve_signing_target(
    request: BoundedSigningRequest,
    *,
    github_repository_id: str,
    github_repository: str,
    github_pr_number: int,
    github_head_sha: str,
    gatestore_head_generation: str,
) -> ResolvedSigningTarget:
    """Exact-compare GitHub state and read generation from GateStore input.

    ``expected_head_generation`` is only a compare-and-reject guard.  The
    returned signed generation always comes from the authoritative GateStore
    observation supplied by the helper adapter.
    """

    observed = (github_repository_id, github_repository, github_pr_number, github_head_sha)
    requested = (request.repository_id, request.repository, request.pr_number, request.head_sha)
    if observed != requested:
        raise ApprovalContractError("GitHub target changed or did not resolve exactly")
    if not isinstance(gatestore_head_generation, str) or not _CANONICAL_POSITIVE.fullmatch(
        gatestore_head_generation
    ):
        raise ApprovalContractError("GateStore head generation is unavailable or invalid")
    if (
        request.expected_head_generation is not None
        and request.expected_head_generation != gatestore_head_generation
    ):
        raise ApprovalContractError("expected head generation does not match GateStore")
    return ResolvedSigningTarget(*observed, gatestore_head_generation)


def evaluate_signing_request(
    raw_request: Mapping[str, Any],
    context: ProceduralApprovalContext,
) -> ApprovalDecision:
    """Evaluate bounded helper shape plus the agent's same-thread policy.

    The boolean in ``context`` is a procedural assertion supplied by the
    trusted agent.  Neither this function nor a signer can prove conversation
    provenance, and the opaque linkage hash is intentionally not consulted as
    an authority predicate.
    """

    request: BoundedSigningRequest | None = None
    try:
        request = BoundedSigningRequest.validate(raw_request)
    except (ApprovalContractError, TypeError):
        linkage = raw_request.get("request_linkage_hash") if isinstance(raw_request, Mapping) else None
        if not isinstance(linkage, str) or not _HEX_256.fullmatch(linkage):
            linkage = None
        return ApprovalDecision(False, None, ApprovalAuditRecord(linkage, None, "denied", "invalid_bounded_request"))

    denial: str | None = None
    if not context.explicit_same_thread_request:
        denial = "no_explicit_same_thread_request"
    elif type(context.requested_target_count) is not int or context.requested_target_count != 1:
        denial = "request_is_not_one_exact_target"
    elif context.requested_scope != "exact-pr-head":
        denial = "blanket_or_non_exact_scope"
    elif context.references_future_head:
        denial = "future_head_request"

    outcome = "denied" if denial else "accepted"
    audit = ApprovalAuditRecord(
        request.request_linkage_hash,
        request.target_mapping(),
        outcome,
        denial or "bounded_exact_target_accepted",
    )
    return ApprovalDecision(denial is None, request if denial is None else None, audit)


def opaque_request_linkage_hash(thread_id: str, turn_id: str) -> str:
    """Hash opaque identifiers only; transcript text is never an input."""

    if not isinstance(thread_id, str) or not thread_id or not isinstance(turn_id, str) or not turn_id:
        raise ApprovalContractError("opaque thread and turn identifiers are required")
    payload = {"thread_id": thread_id, "turn_id": turn_id}
    return hashlib.sha256(b"github-automation/request-linkage/v1\x00" + canonicalize_jcs(payload)).hexdigest()
