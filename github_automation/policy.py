"""Fail-closed routing policy. Inventory and relationships never authorize local CI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .inventory import InventoryObservation
from .registry import RepositoryConfig


@dataclass(frozen=True)
class ExecutionDecision:
    backend: str
    local_eligible: bool
    reason: str


def evaluate_execution_trust(
    config: RepositoryConfig,
    *,
    now: datetime,
    inventory: InventoryObservation | None = None,
    attestation_valid: bool = False,
    external_contributor: bool = False,
    dependabot: bool = False,
    relationship_signals: Iterable[str] = (),
) -> ExecutionDecision:
    # relationship_signals is accepted only to make the negative contract explicit.
    tuple(relationship_signals)
    if config.ci_runner != "local-with-github-fallback":
        return ExecutionDecision("github", False, "registry-default-or-hosted")
    if external_contributor or dependabot:
        return ExecutionDecision("github", False, "untrusted-event")
    if config.execution_trust is None or config.execution_trust.get("mode") != "exact-sha-attestation":
        return ExecutionDecision("github", False, "missing-exact-sha-policy")
    if inventory is None:
        return ExecutionDecision("github", False, "inventory-unavailable")
    if inventory.status == "unavailable":
        return ExecutionDecision("github", False, "inventory-unavailable")
    if not inventory.is_fresh(now):
        return ExecutionDecision("github", False, "inventory-stale")
    if not attestation_valid:
        return ExecutionDecision("github", False, "attestation-invalid-or-absent")
    return ExecutionDecision("local", True, "exact-sha-attestation-and-fresh-negative-guard")
