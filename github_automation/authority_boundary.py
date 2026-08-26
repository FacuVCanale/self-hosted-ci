"""Pure fail-closed decisions for attestation authority loss at local boundaries."""

from __future__ import annotations

from dataclasses import dataclass


CURRENT_BOUNDARIES = frozenset({"dispatch", "claim", "pre-marker", "local-success"})


@dataclass(frozen=True)
class AuthorityBoundaryDecision:
    route_github: bool
    fence_allocation: bool
    cancel_allocation: bool
    allow_historical_failure: bool
    allow_success: bool
    alert_code: str | None


def decide_authority_loss(
    *, boundary: str, admission_exists: bool, reason: str
) -> AuthorityBoundaryDecision:
    """Return the only permitted effects after current authority is unavailable.

    A historical admission is deliberately not current authority.  It preserves
    only the narrow failure path; the GateStore still validates exact execution
    identity and the authoritative terminal deadline transactionally.
    """
    if boundary not in CURRENT_BOUNDARIES:
        raise ValueError("unknown current-authority boundary")
    if reason not in {
        "head_drift", "inventory_drift", "writer_revoked", "team_drift",
        "expired", "key_unavailable", "proof_invalid",
    }:
        raise ValueError("unknown authority-loss reason")
    before_admission = not admission_exists
    return AuthorityBoundaryDecision(
        route_github=before_admission,
        fence_allocation=not before_admission,
        cancel_allocation=not before_admission,
        allow_historical_failure=admission_exists,
        allow_success=False,
        alert_code="signing_authority_unavailable" if reason == "key_unavailable" else None,
    )


__all__ = ["AuthorityBoundaryDecision", "CURRENT_BOUNDARIES", "decide_authority_loss"]
