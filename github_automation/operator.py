"""Fail-closed, idempotent operator rollout/rollback planner.

No method performs GitHub or host mutations.  It consumes verified facts and
emits the next exact operation, keeping credentialed/external work explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .observability import ReadinessCriterion, ReadinessMatrix


ENABLE_ORDER = (
    "prove_authority",
    "install_pr_workflow",
    "github_smoke",
    "allowlist_or_runner_group",
    "local_smoke",
    "fallback_smoke",
)
DISABLE_ORDER = (
    "set_github_first",
    "fence_and_cancel_local",
    "github_smoke",
    "revoke_exact_authority",
    "reconcile",
)


class Operation(str, Enum):
    ENABLE = "enable"
    DISABLE = "disable"


@dataclass(frozen=True)
class OperatorState:
    repository: str
    ci_mode: str = "github"
    enable_completed: tuple[str, ...] = ()
    disable_completed: tuple[str, ...] = ()
    external_facts: Mapping[str, bool | None] | None = None
    bootstrap_repository_created: bool = False


@dataclass(frozen=True)
class OperatorDecision:
    operation: Operation
    status: str
    next_step: str | None
    completed: tuple[str, ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "operator_contract_version": 1,
            "operation": self.operation.value,
            "status": self.status,
            "next_step": self.next_step,
            "completed": list(self.completed),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
        }


def _validate_prefix(completed: tuple[str, ...], order: tuple[str, ...]) -> None:
    if len(set(completed)) != len(completed) or completed != order[: len(completed)]:
        raise ValueError("completed steps must be an exact, duplicate-free prefix")


def _plan(operation: Operation, state: OperatorState, order: tuple[str, ...]) -> OperatorDecision:
    completed = state.enable_completed if operation is Operation.ENABLE else state.disable_completed
    _validate_prefix(completed, order)
    warnings = () if state.bootstrap_repository_created else (
        "private github-automation bootstrap repository is not externally verified",
    )
    if len(completed) == len(order):
        return OperatorDecision(operation, "complete", None, completed, (), warnings)
    next_step = order[len(completed)]
    fact = (state.external_facts or {}).get(next_step)
    if fact is True:
        # The caller persists this transition and invokes again.  Keeping the
        # planner pure makes duplicate deliveries harmless.
        return OperatorDecision(operation, "ready", next_step, completed, (), warnings)
    reason = (
        f"external verification failed for {next_step}"
        if fact is False else f"external verification required for {next_step}"
    )
    return OperatorDecision(operation, "blocked", next_step, completed, (reason,), warnings)


def plan_enable(state: OperatorState, readiness: ReadinessMatrix) -> OperatorDecision:
    if state.ci_mode != "github" and not state.enable_completed:
        raise ValueError("enable must start with GitHub-hosted CI")
    if not readiness.ready:
        blockers = tuple(
            f"{item.criterion_id}: {item.blocker or item.status}"
            for item in readiness.criteria if item.status not in {"pass", "not_applicable"}
        )
        return OperatorDecision(Operation.ENABLE, "blocked", None, state.enable_completed, blockers, ())
    return _plan(Operation.ENABLE, state, ENABLE_ORDER)


def plan_disable(state: OperatorState) -> OperatorDecision:
    return _plan(Operation.DISABLE, state, DISABLE_ORDER)


def compatibility_readiness(facts: Mapping[str, bool | None]) -> ReadinessMatrix:
    """Required-check/release/deploy facts; missing external proof stays unverified."""
    labels = {
        "dedicated_app_required_check": "pinned-source ci-gate ruleset proof",
        "supply_chain_independent": "independent supply-chain proof",
        "push_main_ci": "GitHub-hosted push-main CI proof",
        "verify_release": "verify-release.sh compatibility proof",
        "railway_isolated": "Railway deploy isolation proof",
    }
    criteria = []
    for criterion_id, description in labels.items():
        value = facts.get(criterion_id)
        status = "pass" if value is True else "fail" if value is False else "unverified"
        criteria.append(ReadinessCriterion(
            criterion_id, status,
            evidence=(description,) if value is True else (),
            blocker=None if value is True else f"{description} is {'failed' if value is False else 'not externally verified'}",
        ))
    return ReadinessMatrix(repository=str(facts.get("repository", "unknown")), criteria=tuple(criteria))


__all__ = [
    "DISABLE_ORDER", "ENABLE_ORDER", "Operation", "OperatorDecision", "OperatorState",
    "compatibility_readiness", "plan_disable", "plan_enable",
]
