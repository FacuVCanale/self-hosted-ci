"""Effectively-once Check Run delivery with exact read-back reconciliation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol


class CheckDeliveryError(RuntimeError):
    pass


class CheckEvidenceConflict(CheckDeliveryError):
    pass


class AmbiguousCheckWrite(CheckDeliveryError):
    """Transport failed after GitHub may have accepted the exact PATCH."""


class CheckTransport(Protocol):
    def patch_exact(self, check_run_id: int, payload: Mapping[str, object]) -> None: ...
    def get_exact(self, check_run_id: int) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class CheckDelivery:
    check_run_id: int
    evidence_digest: str
    conclusion: str
    target_sha: str

    @property
    def marker(self) -> str:
        return f"github-automation-evidence:{self.evidence_digest}"


def deliver_exact(delivery: CheckDelivery, transport: CheckTransport) -> str:
    payload = {
        "conclusion": delivery.conclusion,
        "head_sha": delivery.target_sha,
        "external_id": delivery.marker,
    }
    try:
        transport.patch_exact(delivery.check_run_id, payload)
        return "delivered"
    except AmbiguousCheckWrite:
        observed = transport.get_exact(delivery.check_run_id)
        if observed.get("id") != delivery.check_run_id:
            raise CheckDeliveryError("read-back did not return the exact Check Run")
        if observed.get("external_id") == delivery.marker:
            if observed.get("head_sha") != delivery.target_sha or observed.get("conclusion") != delivery.conclusion:
                raise CheckEvidenceConflict("evidence marker matched but Check fields conflict")
            return "reconciled"
        if observed.get("external_id"):
            raise CheckEvidenceConflict("exact Check Run contains different evidence")
        raise
