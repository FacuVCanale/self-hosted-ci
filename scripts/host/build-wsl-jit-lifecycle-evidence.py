#!/usr/bin/env python3
"""Build one exact six-scenario lifecycle proof set from canary records."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.canary_boundary import CANARY_SCENARIOS, CanaryBoundaryError, authorization_digest, verify_canary_authorization
from github_automation.crypto import canonicalize_jcs, parse_ijson


PROOF_FIELDS = {
    "authorization_digest", "nonce", "scenario", "allocation_id", "scale_set_id", "scale_set_name",
    "run_id", "run_attempt", "job_id", "runner_name", "repository", "repository_id", "dispatch_sha",
    "head_sha", "tested_merge_sha", "image_fingerprint", "network_policy_digest", "github_app_config_digest",
    "allocation_signer_fingerprint", "reserved_at", "started_at", "finished_at", "jobs_started", "conclusion",
    "normal_cancel_receipt", "force_cancel_receipt", "cleanup_record", "garm_inventory_post", "incus_inventory_post",
    "github_inventory_post", "proof_digest",
}
SHARED = ("repository", "repository_id", "head_sha", "tested_merge_sha", "dispatch_sha", "image_fingerprint", "network_policy_digest", "github_app_config_digest", "allocation_signer_fingerprint")


class LifecycleProofError(ValueError):
    pass


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LifecycleProofError(f"{field} must be canonical UTC seconds")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LifecycleProofError(f"{field} must be canonical UTC seconds") from exc
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise LifecycleProofError(f"{field} must be canonical UTC seconds")
    return parsed


def _uuid(value: object, field: str) -> None:
    try:
        parsed = UUID(value) if isinstance(value, str) else None
    except ValueError as exc:
        raise LifecycleProofError(f"{field} must be a canonical UUID") from exc
    if parsed is None or str(parsed) != value:
        raise LifecycleProofError(f"{field} must be a canonical UUID")


def _receipt(value: object, field: str) -> None:
    if not isinstance(value, Mapping) or set(value) != {"operation_id", "observed_at", "receipt_digest"}:
        raise LifecycleProofError(f"{field} receipt is invalid")
    if not isinstance(value["operation_id"], str) or not value["operation_id"] or not isinstance(value["receipt_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["receipt_digest"]):
        raise LifecycleProofError(f"{field} receipt is invalid")
    _time(value["observed_at"], field + ".observed_at")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LifecycleProofError(f"{field} must be a lowercase SHA-256 digest")


def _validate_proof(proof: Mapping[str, object], auth: Mapping[str, object], digest: str) -> None:
    if not isinstance(proof, Mapping) or set(proof) != PROOF_FIELDS:
        raise LifecycleProofError("lifecycle proof requires exact fields")
    if proof["authorization_digest"] != digest or proof["nonce"] != auth["nonce"]:
        raise LifecycleProofError("lifecycle proof crossed authorization binding")
    for field in SHARED:
        if proof[field] != auth[field]:
            raise LifecycleProofError(f"lifecycle proof crossed {field}")
    scenario = proof["scenario"]
    if scenario not in CANARY_SCENARIOS or proof["conclusion"] != scenario:
        raise LifecycleProofError("lifecycle proof conclusion crossed scenario")
    _uuid(proof["allocation_id"], "allocation_id")
    if not isinstance(proof["scale_set_id"], str) or not re.fullmatch(r"[1-9][0-9]*", proof["scale_set_id"]):
        raise LifecycleProofError("scale_set_id must be a canonical positive decimal string")
    for field in ("run_id", "run_attempt", "job_id"):
        if type(proof[field]) is not int or proof[field] < 1:
            raise LifecycleProofError(f"{field} must be positive")
    if not all(isinstance(proof[field], str) and proof[field] for field in ("scale_set_name", "runner_name")):
        raise LifecycleProofError("runner/scale-set identity is invalid")
    reserved, finished = _time(proof["reserved_at"], "reserved_at"), _time(proof["finished_at"], "finished_at")
    started = None if proof["started_at"] is None else _time(proof["started_at"], "started_at")
    if finished < reserved or (started is not None and not reserved <= started <= finished):
        raise LifecycleProofError("lifecycle timestamps are not ordered")
    if proof["jobs_started"] != 1 or started is None:
        raise LifecycleProofError("lifecycle jobs_started/start timestamp mismatch")
    normal, force = proof["normal_cancel_receipt"], proof["force_cancel_receipt"]
    if scenario == "force-cancel":
        _receipt(normal, "normal_cancel")
        _receipt(force, "force_cancel")
        if _time(normal["observed_at"], "normal_cancel.observed_at") >= _time(force["observed_at"], "force_cancel.observed_at"):
            raise LifecycleProofError("force-cancel must follow normal cancel")
    elif force is not None:
        raise LifecycleProofError("force-cancel receipt is only valid for force-cancel")
    elif scenario == "cancel":
        _receipt(normal, "normal_cancel")
    elif normal is not None:
        raise LifecycleProofError("normal cancel receipt is not valid for scenario")
    cleanup = proof["cleanup_record"]
    cleanup_fields = {"registration_removed", "workspace_removed", "token_removed", "container_removed", "allocation_removed", "cleanup_digest"}
    if not isinstance(cleanup, Mapping) or set(cleanup) != cleanup_fields or any(cleanup[field] is not True for field in cleanup_fields - {"cleanup_digest"}):
        raise LifecycleProofError("cleanup record is not exact and complete")
    _digest(cleanup["cleanup_digest"], "cleanup_record.cleanup_digest")
    for field in ("garm_inventory_post", "incus_inventory_post", "github_inventory_post"):
        inventory = proof[field]
        if not isinstance(inventory, Mapping) or set(inventory) != {"remaining", "inventory_digest"} or inventory["remaining"] != 0:
            raise LifecycleProofError(f"{field} is not globally clean")
        _digest(inventory["inventory_digest"], field + ".inventory_digest")
    supplied = proof["proof_digest"]
    _digest(supplied, "proof_digest")
    expected = hashlib.sha256(canonicalize_jcs({key: value for key, value in proof.items() if key != "proof_digest"})).hexdigest()
    if supplied != expected:
        raise LifecycleProofError("lifecycle proof digest mismatch")


def build(authorization: Mapping[str, object], proofs: list[Mapping[str, object]]) -> dict[str, object]:
    digest = authorization_digest(authorization)
    if len(proofs) != len(CANARY_SCENARIOS):
        raise LifecycleProofError("exactly six lifecycle proofs are required")
    for proof in proofs:
        _validate_proof(proof, authorization, digest)
    if [proof["scenario"] for proof in proofs] != list(CANARY_SCENARIOS):
        raise LifecycleProofError("lifecycle proofs must contain the six scenarios in canonical order")
    for field in ("allocation_id", "run_id", "job_id"):
        values = [proof[field] for proof in proofs]
        if len(set(values)) != len(values):
            raise LifecycleProofError(f"lifecycle proof {field} values must be unique")
    return {"schema_version": 1, "authorization_digest": digest, "nonce": authorization["nonce"], **{field: authorization[field] for field in SHARED}, "proofs": proofs}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    parser.add_argument("--pinned-fingerprint", required=True)
    parser.add_argument("--proof", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        authorization = parse_ijson(args.authorization.read_bytes())
        key = serialization.load_pem_public_key(args.reviewer_public_key.read_bytes())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise LifecycleProofError("reviewer public key must be Ed25519")
        decision = verify_canary_authorization(authorization, key, pinned_fingerprint=args.pinned_fingerprint)
        if decision.blockers:
            raise LifecycleProofError(", ".join(decision.blockers))
        output = args.output.resolve(strict=False)
        if output.exists() or output.is_symlink():
            raise LifecycleProofError("lifecycle output must not already exist")
        value = build(authorization, [parse_ijson(path.read_bytes()) for path in args.proof])
        output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonicalize_jcs(value) + b"\n")
            handle.flush(); os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError, CanaryBoundaryError, LifecycleProofError) as exc:
        print(f"lifecycle proof build failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
