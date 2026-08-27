"""Inert command surface used by the trusted workflow templates.

The module validates packages and exposes stable subcommands, but deliberately
does not mint App tokens or infer missing production authority. Network side
effects require an installed control-plane adapter that is outside this
bootstrap repository.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Protocol

from .github import ObservedWorkflowJob, ProtocolFailure, ProtocolPackage


class CoordinatorUnavailable(RuntimeError):
    pass


class ReserveDefinitelyUnavailableBeforeEffect(CoordinatorUnavailable):
    """The local broker proved that reserve had no durable side effect."""


class ReservePartialFailure(CoordinatorUnavailable):
    """Reserve may be retried only after exact allocation cleanup is proved."""

    def __init__(
        self, allocation_id: str, message: str = "allocation reserve partially applied"
    ):
        super().__init__(message)
        self.allocation_id = allocation_id


def _package_from_environment(environment: Mapping[str, str]) -> ProtocolPackage:
    raw = environment.get("CI_GATE_PROTOCOL_PACKAGE")
    if not raw:
        raise ProtocolFailure("CI_GATE_PROTOCOL_PACKAGE is required")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolFailure("protocol package is not valid JSON") from exc
    return ProtocolPackage.from_mapping(value)


def _assert_live_tuple(
    package: ProtocolPackage, environment: Mapping[str, str]
) -> None:
    """Require an authoritative, adapter-supplied PR tuple before child use.

    The bootstrap has no GitHub credentialed adapter, so absence is deliberately
    a control failure instead of treating the signed dispatch package as current.
    """
    raw = environment.get("CI_GATE_CURRENT_TUPLE")
    if not raw:
        raise ProtocolFailure("authoritative CI_GATE_CURRENT_TUPLE is required")
    try:
        current = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolFailure("current GitHub tuple is not valid JSON") from exc
    if not isinstance(current, Mapping) or set(current) != {
        "repository_id",
        "repository",
        "pr_number",
        "head_sha",
        "base_sha",
        "tested_merge_sha",
        "generation",
    }:
        raise ProtocolFailure("current GitHub tuple fields are not exact")
    package.assert_current_tuple(**current)


def _write_outputs(package: ProtocolPackage, environment: Mapping[str, str]) -> None:
    output = environment.get("GITHUB_OUTPUT")
    if not output:
        return
    values = package.values
    lines = (
        f"backend={values['backend']}\n"
        f"tested_sha={values['tested_sha']}\n"
        f"logical_key={values['logical_key']}\n"
        f"generation={values['generation']}\n"
        f"runner_label={values['runner_label'] or ''}\n"
    )
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(lines)


def child(environment: Mapping[str, str], *, action: str = "validate") -> int:
    package = _package_from_environment(environment)
    if action == "validate":
        _assert_live_tuple(package, environment)
        _write_outputs(package, environment)
        return 0
    raise CoordinatorUnavailable(
        f"child action {action!r} requires the installed transactional control-plane adapter"
    )


def coordinate(environment: Mapping[str, str]) -> int:
    if environment.get("CI_GATE_COORDINATOR_ENABLED") != "true":
        raise CoordinatorUnavailable("coordinator is disabled by default")
    raise CoordinatorUnavailable(
        "hosted workflow cannot reach the local allocation broker; use the outbound local coordinator worker or dispatch GitHub-hosted"
    )


class LocalAllocationAdapter(Protocol):
    def reserve(self, reservation: Mapping[str, Any]) -> Mapping[str, str]: ...
    def finalize(self, envelope: Mapping[str, Any]) -> Mapping[str, str]: ...
    def recover(self, allocation_id: str) -> Mapping[str, str]: ...


class ChildDispatchAdapter(Protocol):
    def dispatch_package(self, package: Mapping[str, Any]) -> int: ...
    def observe_exact_job(
        self, run_id: int, runner_label: str
    ) -> ObservedWorkflowJob: ...


class BoundedAllocationSigner(Protocol):
    """External signer boundary; implementations never expose private key material."""

    def sign_allocation(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class DispatchProgress(Protocol):
    def reserved(self, value: Mapping[str, str]) -> None: ...
    def dispatching(self) -> None: ...
    def dispatched(self, run_id: int) -> None: ...
    def observed(self, value: ObservedWorkflowJob) -> None: ...
    def finalizing(self) -> None: ...
    def finalized(self, value: Mapping[str, str]) -> None: ...
    def recovered(self) -> None: ...
    def dispatch_ambiguous(self) -> None: ...


def _assert_exact_recovery(
    recovered: Mapping[str, str],
    allocation_id: str,
) -> None:
    if recovered != {"allocation_id": allocation_id, "state": "absent"}:
        raise CoordinatorUnavailable("exact allocation recovery did not prove absence")


def github_hosted_fallback(package: Mapping[str, Any]) -> ProtocolPackage:
    """Remove all local authority before a hosted fallback dispatch."""
    value = dict(package)
    value.update(
        backend="github",
        execution_trust_mode="github-hosted",
        allocation_id=None,
        allocation_nonce=None,
        runner_label=None,
    )
    for field in (
        "key_manifest_generation_at_issuance",
        "key_manifest_digest_at_issuance",
        "attestation_id",
        "attestation_key_id",
        "attestation_key_version",
        "attestation_public_key_fingerprint",
        "attestation_head_generation",
        "attestation_expires_at",
        "attestation_nonce_binding",
        "attestation_envelope_digest",
        "attestation_request_linkage_hash",
        "local_admission_id",
        "local_admission_digest",
        "local_evidence_id",
        "local_evidence_digest",
        "local_result_kind",
        "local_child_run_id",
        "local_child_job_id",
        "started_test_marker_digest",
        "canonical_command_digest",
        "terminal_at",
        "check_outbox_idempotency_key",
    ):
        value[field] = None
    return ProtocolPackage.from_mapping(value)


def outbound_local_dispatch(
    package: Mapping[str, Any],
    reservation: Mapping[str, Any],
    *,
    allocation: LocalAllocationAdapter,
    github: ChildDispatchAdapter,
    signer: BoundedAllocationSigner,
    progress: DispatchProgress | None = None,
    resume: Mapping[str, Any] | None = None,
) -> tuple[ProtocolPackage, ObservedWorkflowJob | None]:
    """Run reserve→dispatch→observe→external-sign→finalize from the local host.

    The caller is an outbound worker on the self-hosted machine. GitHub Actions
    never receives broker ingress or signing-key access. Adapter operations must
    be idempotent by allocation_id/run_id so reboot recovery can replay safely.
    """
    resume = dict(resume or {})
    persisted_reserved = resume.get("reserved")
    should_reserve = persisted_reserved is None or resume.get("phase") == "recovered"
    try:
        reserved = (
            allocation.reserve(reservation) if should_reserve else persisted_reserved
        )
    except ReserveDefinitelyUnavailableBeforeEffect:
        hosted = github_hosted_fallback(package)
        github.dispatch_package(hosted.values)
        return hosted, None
    except ReservePartialFailure as exc:
        allocation_id = reservation.get("allocation_id")
        if not isinstance(allocation_id, str) or exc.allocation_id != allocation_id:
            raise CoordinatorUnavailable(
                "partial reserve failure crossed the allocation"
            ) from exc
        _assert_exact_recovery(allocation.recover(allocation_id), allocation_id)
        hosted = github_hosted_fallback(package)
        github.dispatch_package(hosted.values)
        return hosted, None
    except Exception as exc:
        # An untyped failure may have occurred before or after the broker made
        # durable changes. Never race it with a hosted dispatch.
        raise CoordinatorUnavailable("allocation reserve outcome is ambiguous") from exc
    expected = {"allocation_id", "scale_set_id", "runner_label", "state"}
    if set(reserved) != expected or reserved["state"] != "reserved-disabled":
        raise CoordinatorUnavailable("allocation reserve response is not exact")
    if reserved["allocation_id"] != reservation.get("allocation_id") or reserved[
        "runner_label"
    ] != reservation.get("scale_set_name"):
        raise CoordinatorUnavailable(
            "allocation reserve response crossed the reservation"
        )
    if progress is not None:
        progress.reserved(reserved)
    local = dict(package)
    local.update(
        allocation_id=reserved["allocation_id"],
        allocation_nonce=reservation.get("nonce"),
        runner_label=reserved["runner_label"],
    )
    dispatch_receipt_ambiguous = False
    try:
        protocol = ProtocolPackage.from_mapping(local)
        resumed_run_id = resume.get("run_id")
        if resumed_run_id is None:
            if resume.get("phase") == "dispatching":
                raise CoordinatorUnavailable(
                    "GitHub dispatch receipt is ambiguous; refusing redispatch"
                )
            if progress is not None:
                progress.dispatching()
            dispatch_receipt_ambiguous = True
            dispatch_run_id = github.dispatch_package(protocol.values)
            if (
                not isinstance(dispatch_run_id, int)
                or isinstance(dispatch_run_id, bool)
                or dispatch_run_id <= 0
            ):
                raise CoordinatorUnavailable("GitHub dispatch receipt is invalid")
            if progress is not None:
                progress.dispatched(dispatch_run_id)
            dispatch_receipt_ambiguous = False
        else:
            if (
                not isinstance(resumed_run_id, int)
                or isinstance(resumed_run_id, bool)
                or resumed_run_id <= 0
            ):
                raise CoordinatorUnavailable(
                    "persisted GitHub dispatch receipt is invalid"
                )
            dispatch_run_id = resumed_run_id
        observed = github.observe_exact_job(dispatch_run_id, reserved["runner_label"])
        if observed.run_id != dispatch_run_id:
            raise CoordinatorUnavailable(
                "observed job is not bound to the dispatch run"
            )
        if progress is not None:
            progress.observed(observed)
        payload = dict(reservation)
        payload.pop("allocation_reservation_version", None)
        payload.update(
            runner_allocation_version=1,
            run_id=str(observed.run_id),
            run_attempt=observed.run_attempt,
            job_id=str(observed.job_id),
            job_name=observed.job_name,
            dispatch_sha=observed.dispatch_sha,
            tested_sha=protocol.values["tested_sha"],
        )
        envelope = signer.sign_allocation(payload)
        if resume.get("phase") == "finalizing" and "finalized" not in resume:
            raise CoordinatorUnavailable(
                "allocation finalize receipt is ambiguous; refusing replay"
            )
        if progress is not None:
            progress.finalizing()
        finalized = allocation.finalize(envelope)
        if (
            finalized.get("allocation_id") != reserved["allocation_id"]
            or finalized.get("state") != "enabled-awaiting-claim"
        ):
            raise CoordinatorUnavailable("allocation finalize response is not exact")
        if progress is not None:
            progress.finalized(finalized)
        return protocol, observed
    except Exception:
        _assert_exact_recovery(
            allocation.recover(reserved["allocation_id"]), reserved["allocation_id"]
        )
        if progress is not None:
            if dispatch_receipt_ambiguous or (
                resume.get("phase") == "dispatching" and resumed_run_id is None
            ):
                progress.dispatch_ambiguous()
            else:
                progress.recovered()
        raise


def reconcile(environment: Mapping[str, str]) -> int:
    if environment.get("CI_GATE_COORDINATOR_ENABLED") != "true":
        raise CoordinatorUnavailable("reconciler is disabled by default")
    raise CoordinatorUnavailable(
        "reconciliation requires the installed GitHub/GateStore adapter and exact external authority"
    )


def main(
    argv: list[str] | None = None, environment: Mapping[str, str] | None = None
) -> int:
    parser = argparse.ArgumentParser(prog="python -m github_automation.coordinator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("coordinate")
    child_parser = subparsers.add_parser("child")
    actions = child_parser.add_mutually_exclusive_group()
    actions.add_argument("--claim", action="store_true")
    actions.add_argument("--mark-started", action="store_true")
    actions.add_argument("--complete-hosted", action="store_true")
    subparsers.add_parser("reconcile")
    args = parser.parse_args(argv)
    env = os.environ if environment is None else environment
    try:
        if args.command == "coordinate":
            return coordinate(env)
        if args.command == "reconcile":
            return reconcile(env)
        action = (
            "claim"
            if args.claim
            else "mark-started"
            if args.mark_started
            else "complete-hosted"
            if args.complete_hosted
            else "validate"
        )
        return child(env, action=action)
    except (ProtocolFailure, CoordinatorUnavailable) as exc:
        print(f"ci-gate control failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
