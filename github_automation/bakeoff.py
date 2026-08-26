"""Deterministic runner-manager bake-off evaluator (schema/policy v1)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping


class BakeoffError(ValueError):
    """The evidence document is invalid or its stored result was manipulated."""


CANDIDATE_IDS = frozenset({"fireactions", "garm-incus", "myoung34-docker-github-actions-runner"})
UPSTREAMS = {
    "fireactions": "https://github.com/hostinger/fireactions",
    "garm-incus": "https://github.com/cloudbase/garm",
    "myoung34-docker-github-actions-runner": "https://github.com/myoung34/docker-github-actions-runner",
}
HARD_GATES = frozenset(
    {
        "immutable-pin-provenance",
        "jit-one-job-disposal",
        "terminal-reboot-cleanup",
        "no-host-container-socket",
        "no-network-bypass",
        "wsl-compatibility",
        "target-authority-capability",
        "maintenance-security-threshold",
    }
)
SCOPED_WEIGHTS = {
    "rootless": 30,
    "personal-jit": 20,
    "org-restricted-groups": 15,
    "fit-4c-16gib": 15,
    "observability": 10,
    "reboot-recovery": 10,
}
CRITERION_STATUSES = frozenset({"pass", "fail", "not_applicable"})
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class CandidateResult:
    candidate_id: str
    eligible: bool
    scoped_score: int
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class BakeoffResult:
    result: str
    candidate_id: str | None
    candidates: tuple[CandidateResult, ...]


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise BakeoffError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BakeoffError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise BakeoffError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _reject_waivers(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if "waiver" in str(key).lower():
                raise BakeoffError(f"waiver field forbidden at {path}.{key}")
            _reject_waivers(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_waivers(child, f"{path}[{index}]")


def _criterion_map(raw: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(raw, list):
        raise BakeoffError("criteria must be a list")
    result: dict[str, Mapping[str, Any]] = {}
    for criterion in raw:
        if not isinstance(criterion, Mapping) or set(criterion) != {"id", "class", "status", "evidence_refs", "notes"}:
            raise BakeoffError("criterion v1 requires exact fields")
        identifier = criterion["id"]
        if not isinstance(identifier, str) or identifier in result:
            raise BakeoffError("criterion ids must be unique strings")
        expected_class = "hard_gate" if identifier in HARD_GATES else "scoped_capability" if identifier in SCOPED_WEIGHTS else None
        if expected_class is None or criterion["class"] != expected_class:
            raise BakeoffError(f"unexpected criterion or class: {identifier}")
        if criterion["status"] not in CRITERION_STATUSES:
            raise BakeoffError(f"invalid criterion status: {identifier}")
        refs = criterion["evidence_refs"]
        if not isinstance(refs, list) or not all(isinstance(ref, str) and ref for ref in refs):
            raise BakeoffError(f"invalid evidence refs: {identifier}")
        if criterion["status"] == "pass" and not refs:
            raise BakeoffError(f"pass without evidence: {identifier}")
        result[identifier] = criterion
    expected = HARD_GATES | set(SCOPED_WEIGHTS)
    if set(result) != expected:
        raise BakeoffError(f"criteria set mismatch: {sorted(expected - set(result))}")
    return result


def _artifact_valid(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "version", "tag", "image_digest", "evidence_digest", "signature_verified", "sbom_ref", "provenance_ref"
    }:
        return False
    return (
        all(isinstance(value[field], str) and value[field] for field in ("version", "tag", "sbom_ref", "provenance_ref"))
        and SHA256.fullmatch(str(value["image_digest"])) is not None
        and SHA256.fullmatch(str(value["evidence_digest"])) is not None
        and value["signature_verified"] is True
    )


def _maintenance_security_valid(value: Any, evaluated_at: datetime) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "archived", "selected_version_supported", "last_release_or_maintenance_at",
        "unmitigated_critical", "oldest_unmitigated_high_at", "upstream_fixed_pin_available",
    }:
        return False
    try:
        activity = _parse_time(value["last_release_or_maintenance_at"], "last_release_or_maintenance_at")
    except BakeoffError:
        return False
    if value["archived"] is not False or value["selected_version_supported"] is not True:
        return False
    if activity < evaluated_at - timedelta(days=365):
        return False
    if value["unmitigated_critical"] is not False:
        return False
    high = value["oldest_unmitigated_high_at"]
    if high is not None:
        try:
            high_at = _parse_time(high, "oldest_unmitigated_high_at")
        except BakeoffError:
            return False
        if high_at < evaluated_at - timedelta(days=30) and value["upstream_fixed_pin_available"] is not True:
            return False
    return True


def _rootful_accepted(
    decision: Any,
    *,
    candidate_id: str,
    target_repository: str,
    required_approver: str,
    evaluated_at: datetime,
) -> bool:
    if not isinstance(decision, Mapping) or set(decision) != {
        "decision_id", "approver", "candidate_id", "repositories", "mitigations", "expires_at", "revoked"
    }:
        return False
    repositories = decision["repositories"]
    mitigations = decision["mitigations"]
    try:
        expires_at = _parse_time(decision["expires_at"], "rootful expires_at")
    except BakeoffError:
        return False
    return (
        decision["decision_id"] == "rootful-runner-risk-v1"
        and decision["approver"] == required_approver
        and decision["candidate_id"] == candidate_id
        and isinstance(repositories, list)
        and target_repository in repositories
        and all(isinstance(repo, str) and "/" in repo and "*" not in repo for repo in repositories)
        and isinstance(mitigations, list)
        and bool(mitigations)
        and all(isinstance(item, str) and item for item in mitigations)
        and expires_at > evaluated_at
        and decision["revoked"] is False
    )


def evaluate_bakeoff(
    document: Mapping[str, Any], *, target_repository: str, required_approver: str
) -> BakeoffResult:
    """Validate and independently reproduce eligibility, scores, and winner."""

    if not isinstance(document, Mapping):
        raise BakeoffError("bake-off evidence must be an object")
    if not isinstance(target_repository, str) or target_repository.count("/") != 1 or "*" in target_repository:
        raise BakeoffError("target_repository must be one exact owner/repo")
    if not isinstance(required_approver, str) or not required_approver.strip():
        raise BakeoffError("required_approver must be configured explicitly")
    _reject_waivers(document)
    if set(document) != {"runner_bakeoff_schema_version", "selection_policy_version", "evaluated_at", "candidates", "selection"}:
        raise BakeoffError("bake-off schema v1 requires exact top-level fields")
    if document["runner_bakeoff_schema_version"] != 1 or document["selection_policy_version"] != 1:
        raise BakeoffError("unsupported bake-off schema or policy version")
    evaluated_at = _parse_time(document["evaluated_at"], "evaluated_at")
    raw_candidates = document["candidates"]
    if not isinstance(raw_candidates, list) or len(raw_candidates) != len(CANDIDATE_IDS):
        raise BakeoffError("all three candidates are required exactly once")

    results: list[CandidateResult] = []
    seen: set[str] = set()
    for candidate in raw_candidates:
        if not isinstance(candidate, Mapping) or set(candidate) != {
            "candidate_id", "upstream", "selected_artifact", "rootful", "rootful_risk_decision",
            "maintenance_security", "criteria", "eligible", "scoped_score",
        }:
            raise BakeoffError("candidate schema v1 requires exact fields")
        candidate_id = candidate["candidate_id"]
        if not isinstance(candidate_id, str):
            raise BakeoffError("candidate id must be a string")
        if candidate_id not in CANDIDATE_IDS or candidate_id in seen:
            raise BakeoffError("candidate ids must be the three stable ids")
        if candidate["upstream"] != UPSTREAMS[candidate_id]:
            raise BakeoffError(f"unexpected upstream for {candidate_id}")
        seen.add(candidate_id)
        criteria = _criterion_map(candidate["criteria"])
        blockers = [gate for gate in sorted(HARD_GATES) if criteria[gate]["status"] != "pass"]
        if criteria["immutable-pin-provenance"]["status"] == "pass" and not _artifact_valid(candidate["selected_artifact"]):
            blockers.append("immutable-artifact-proof-invalid")
        if criteria["maintenance-security-threshold"]["status"] == "pass" and not _maintenance_security_valid(candidate["maintenance_security"], evaluated_at):
            blockers.append("maintenance-security-threshold-invalid")
        rootful = candidate["rootful"]
        if rootful is not True and rootful is not False and rootful is not None:
            raise BakeoffError("rootful must be true, false, or null")
        if rootful is True and not _rootful_accepted(
            candidate["rootful_risk_decision"], candidate_id=candidate_id,
            target_repository=target_repository, required_approver=required_approver,
            evaluated_at=evaluated_at,
        ):
            blockers.append("rootful-risk-decision-invalid")
        if rootful is None:
            blockers.append("rootful-mode-unresolved")
        if rootful is True and criteria["rootless"]["status"] == "pass":
            blockers.append("rootful-cannot-claim-rootless")
        if rootful is not True and candidate["rootful_risk_decision"] is not None:
            blockers.append("unexpected-rootful-risk-decision")
        score = sum(weight for criterion, weight in SCOPED_WEIGHTS.items() if criteria[criterion]["status"] == "pass")
        eligible = not blockers
        if not isinstance(candidate["eligible"], bool):
            raise BakeoffError(f"eligible must be boolean for {candidate_id}")
        if not isinstance(candidate["scoped_score"], int) or isinstance(candidate["scoped_score"], bool):
            raise BakeoffError(f"scoped_score must be an integer for {candidate_id}")
        if candidate["eligible"] is not eligible or candidate["scoped_score"] != score:
            raise BakeoffError(f"stored result mismatch for {candidate_id}")
        results.append(CandidateResult(candidate_id, eligible, score, tuple(blockers)))

    eligible_results = [candidate for candidate in results if candidate.eligible]
    winner = min(eligible_results, key=lambda item: (-item.scoped_score, item.candidate_id)) if eligible_results else None
    selection = document["selection"]
    if not isinstance(selection, Mapping) or set(selection) != {"result", "candidate_id", "reason", "independent_verifier_signoff"}:
        raise BakeoffError("selection schema v1 requires exact fields")
    signoff = selection["independent_verifier_signoff"]
    signoff_valid = isinstance(signoff, Mapping) and set(signoff) == {"verifier", "signed_at", "evidence_digest"}
    if signoff_valid:
        signoff_valid = (
            isinstance(signoff["verifier"], str) and bool(signoff["verifier"])
            and SHA256.fullmatch(str(signoff["evidence_digest"])) is not None
            and _parse_time(signoff["signed_at"], "signed_at") <= evaluated_at
        )
    selected_id = winner.candidate_id if winner is not None and signoff_valid else None
    result = "selected" if selected_id else "none-pass"
    if selection["result"] != result or selection["candidate_id"] != selected_id:
        raise BakeoffError("stored selection does not match deterministic result")
    return BakeoffResult(result, selected_id, tuple(results))
