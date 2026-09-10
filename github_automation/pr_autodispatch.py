"""Turn open pull requests into exact local CI approvals, with no ingress.

The control plane is outbound only: there is no webhook, no listener and no
relay.  Automatic dispatch is therefore a poll of the exact opted-in repository
performed by the host that already holds the dispatch authority.

The planner below is pure.  It takes what GitHub reports and what the local
approval store already holds, and returns the exact mutations to apply.  Every
rule it encodes is a rule about one repository: it can never widen scope, and it
never cancels work belonging to a different pull request.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

#: Approval states that still own, or may still own, the single local runner.
ACTIVE_STATES = frozenset({"pending", "claimed"})
#: States that mean this exact head already had its turn; re-approving it would
#: silently re-run a commit whose result is already published.
SETTLED_STATES = frozenset({"completed", "failed", "revoked", "expired"})
_SHA = re.compile(r"[0-9a-f]{40}")


class AutoDispatchError(ValueError):
    """One automatic dispatch input was not exact."""


@dataclass(frozen=True)
class OpenPullRequest:
    """One open pull request of the exact repository, at one exact head."""

    number: int
    head_sha: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.number, bool)
            or not isinstance(self.number, int)
            or self.number < 1
        ):
            raise AutoDispatchError("pull request number must be positive")
        if not isinstance(self.head_sha, str) or not _SHA.fullmatch(self.head_sha):
            raise AutoDispatchError("pull request head must be a full commit SHA")


@dataclass(frozen=True)
class Action:
    """One exact mutation to apply to the local approval store."""

    kind: str
    pr_number: int
    head_sha: str
    reason: str


def plan(
    *,
    open_pull_requests: Sequence[OpenPullRequest],
    approvals: Sequence[Mapping[str, object]],
) -> tuple[Action, ...]:
    """Decide which approvals to revoke and which heads to approve.

    Rules, in the order they matter:

    * A pull request whose active approval points at an older head is superseded:
      the stale approval is revoked and the current head approved.  A new commit
      therefore always requires a new approval, never inherits the old one.
    * A head that already reached a settled state is never approved again.
    * A head that already has an active approval is left alone; approval is
      idempotent, and re-approving would only churn the store.
    * Approvals belonging to a pull request that is no longer open are revoked.
    * Nothing is ever cancelled across pull requests.  The host runs one job at
      a time, so several approved heads simply queue in arrival order.
    """
    heads = {}
    for pull_request in open_pull_requests:
        if not isinstance(pull_request, OpenPullRequest):
            raise AutoDispatchError("open pull request entries must be exact")
        if pull_request.number in heads:
            raise AutoDispatchError("GitHub reported one pull request twice")
        heads[pull_request.number] = pull_request.head_sha

    active: dict[int, list[str]] = {}
    settled: set[tuple[int, str]] = set()
    for approval in approvals:
        number, head, state = (
            approval.get("pr_number"),
            approval.get("head_sha"),
            approval.get("state"),
        )
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number < 1
            or not isinstance(head, str)
            or not _SHA.fullmatch(head)
            or not isinstance(state, str)
        ):
            raise AutoDispatchError("stored approval row is not exact")
        if state in ACTIVE_STATES:
            active.setdefault(number, []).append(head)
        elif state in SETTLED_STATES:
            settled.add((number, head))

    actions: list[Action] = []
    for number in sorted(active):
        current = heads.get(number)
        stale = [head for head in active[number] if head != current]
        if not stale:
            continue
        actions.append(
            Action(
                "revoke",
                number,
                stale[0],
                "closed" if current is None else "superseded by a newer commit",
            )
        )
    for number in sorted(heads):
        head = heads[number]
        if head in active.get(number, []) or (number, head) in settled:
            continue
        actions.append(Action("approve", number, head, "new pull request head"))
    return tuple(actions)


__all__ = [
    "ACTIVE_STATES",
    "Action",
    "AutoDispatchError",
    "OpenPullRequest",
    "SETTLED_STATES",
    "plan",
]
