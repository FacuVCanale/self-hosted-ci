#!/usr/bin/env python3
"""Fail closed when installed WSL JIT runtime artifacts drift from signed evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

CONTRACT_REF = "live/live-artifacts-v1.json"
ALLOWED_ARTIFACT_KINDS = frozenset(
    {"script", "python-module", "unit", "public-config", "pinned-binary"}
)
NON_EXECUTABLE_ARTIFACT_KINDS = frozenset(
    {"python-module", "unit", "public-config"}
)
ALLOWED_TARGET_PREFIXES = (
    "/usr/local/lib/self-hosted-ci/",
    "/usr/local/libexec/self-hosted-ci/",
    "/usr/local/share/self-hosted-ci/",
    "/etc/self-hosted-ci/",
    "/etc/systemd/system/",
)
ALLOWED_BINARY_TARGETS = {
    "/usr/local/bin/garm",
    "/usr/local/bin/garm-cli",
    "/usr/local/libexec/garm/garm-provider-incus",
}
FORBIDDEN_PUBLIC_TARGETS = {
    "/etc/self-hosted-ci/garm/config.toml",
    "/etc/self-hosted-ci/garm/incus-client.key",
    "/etc/self-hosted-ci/garm/incus-client.crt",
    "/etc/self-hosted-ci/garm/incus-server.crt",
    "/etc/self-hosted-ci/boundary-reviewer-public-key.pem",
}
REQUIRED_LIVE_TARGETS = {
    "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py",
    "/usr/local/lib/self-hosted-ci/verify-live-artifact-contract.py",
    "/usr/local/lib/self-hosted-ci/collect-wsl-jit-measurements.py",
    "/usr/local/lib/self-hosted-ci/collect-health-snapshot.py",
    "/usr/local/lib/self-hosted-ci/garm-cli-session.py",
    "/usr/local/lib/self-hosted-ci/update-health-heartbeat.py",
    "/usr/local/lib/self-hosted-ci/install-wsl-jit-evidence.py",
    "/usr/local/lib/self-hosted-ci/prepare-incus-runner-image.sh",
    "/usr/local/lib/self-hosted-ci/configure-garm-jit.sh",
    "/usr/local/lib/self-hosted-ci/activate-garm-jit.sh",
    "/usr/local/lib/self-hosted-ci/deactivate-garm-jit.sh",
    "/usr/local/lib/self-hosted-ci/garm-jit-transaction-lib.sh",
    "/usr/local/lib/self-hosted-ci/install-incus-garm-tls.sh",
    "/usr/local/lib/self-hosted-ci/install-runner-network-runtime.sh",
    "/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh",
    "/usr/local/lib/self-hosted-ci/run-egress-proxies.sh",
    "/usr/local/lib/self-hosted-ci/garm-callback-proxy.py",
    "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py",
    "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py",
    "/usr/local/lib/self-hosted-ci/runner-job-started-hook.py",
    "/usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py",
    "/usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py",
    "/usr/local/lib/self-hosted-ci/jit-pilot-terminal-monitor.py",
    "/usr/local/lib/self-hosted-ci/verify-bootstrap-install.py",
    "/usr/local/lib/self-hosted-ci/sign-jit-canary-authorization.py",
    "/usr/local/lib/self-hosted-ci/verify-jit-canary-authorization.py",
    "/usr/local/lib/self-hosted-ci/build-wsl-jit-lifecycle-evidence.py",
    "/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py",
    "/usr/local/lib/self-hosted-ci/collect-wsl-jit-semantic-observations.py",
    "/usr/local/lib/self-hosted-ci/collect-wsl-jit-semantic-observations.sh",
    "/usr/local/lib/self-hosted-ci/verify-wsl-jit-bootstrap.py",
    "/usr/local/lib/self-hosted-ci/github_automation/__init__.py",
    "/usr/local/lib/self-hosted-ci/github_automation/bootstrap_boundary.py",
    "/usr/local/lib/self-hosted-ci/github_automation/canary_boundary.py",
    "/usr/local/lib/self-hosted-ci/github_automation/canary_worker.py",
    "/usr/local/lib/self-hosted-ci/github_automation/timing.py",
    "/usr/local/lib/self-hosted-ci/github_automation/crypto.py",
    "/usr/local/lib/self-hosted-ci/github_automation/host_security.py",
    "/usr/local/lib/self-hosted-ci/github_automation/runner_boundary.py",
    "/usr/local/lib/self-hosted-ci/github_automation/runner_jit.py",
    "/usr/local/lib/self-hosted-ci/github_automation/runner_jit_broker.py",
    "/usr/local/lib/self-hosted-ci/github_automation/github.py",
    "/usr/local/lib/self-hosted-ci/github_automation/github_adapter.py",
    "/usr/local/lib/self-hosted-ci/github_automation/check_delivery.py",
    "/usr/local/lib/self-hosted-ci/github_automation/inventory.py",
    "/usr/local/lib/self-hosted-ci/github_automation/policy.py",
    "/usr/local/lib/self-hosted-ci/github_automation/registry.py",
    "/usr/local/lib/self-hosted-ci/github_automation/coordinator.py",
    "/usr/local/lib/self-hosted-ci/github_automation/outbound_worker.py",
    "/usr/local/lib/self-hosted-ci/github_automation/worker_authority.py",
    "/usr/local/lib/self-hosted-ci/github_automation/gatestore.py",
    "/usr/local/lib/self-hosted-ci/github_automation/jit_pilot.py",
    "/usr/local/lib/self-hosted-ci/github_automation/local_approval.py",
    "/usr/local/share/self-hosted-ci/schemas/jit-canary-authorization-v1.schema.json",
    "/usr/local/share/self-hosted-ci/schemas/runner-lifecycle-proof-v1.schema.json",
    "/etc/self-hosted-ci/garm/config.toml.example",
    "/etc/self-hosted-ci/incus/runner-profile.yaml",
    "/usr/local/share/self-hosted-ci/garm-provider-incus.toml",
    "/usr/local/share/self-hosted-ci/runner-install-offline.sh.tmpl",
    "/usr/local/share/self-hosted-ci/outbound-worker.json.example",
    "/usr/local/share/self-hosted-ci/worker-app-authority.json.example",
    "/usr/local/share/self-hosted-ci/runner-manager-app.json.example",
    "/usr/local/share/self-hosted-ci/runner-manager-org-app.json.example",
    "/usr/local/share/self-hosted-ci/dispatcher-app.json.example",
    "/usr/local/share/self-hosted-ci/live-job-verifier-app.json.example",
    "/etc/self-hosted-ci/garm/garm-provider-incus.toml",
    "/etc/self-hosted-ci/network/squid.conf",
    "/etc/systemd/system/self-hosted-ci-boundary-verify.service",
    "/etc/systemd/system/self-hosted-ci-garm.service",
    "/etc/systemd/system/self-hosted-ci-network-policy.service",
    "/etc/systemd/system/self-hosted-ci-egress-proxy.service",
    "/etc/systemd/system/self-hosted-ci-allocation-broker.service",
    "/etc/systemd/system/self-hosted-ci-outbound-worker.service",
    "/etc/systemd/system/self-hosted-ci-health-heartbeat.service",
    "/etc/systemd/system/self-hosted-ci-health-heartbeat.timer",
    "/etc/systemd/system/self-hosted-ci-canary.target",
    "/etc/systemd/system/self-hosted-ci-canary-broker.service",
    "/etc/systemd/system/self-hosted-ci-canary-cleanup.service",
    "/etc/systemd/system/self-hosted-ci-canary-egress-proxy.service",
    "/etc/systemd/system/self-hosted-ci-canary-garm.service",
    "/etc/systemd/system/self-hosted-ci-canary-network-policy.service",
    "/etc/systemd/system/self-hosted-ci-network-quarantine.service",
    *ALLOWED_BINARY_TARGETS,
}


class ContractError(ValueError):
    pass


def _load_exact_json(path: Path) -> Any:
    def exact_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ContractError(f"duplicate JSON key in {path}: {key}")
            value[key] = item
        return value

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=exact_object)


def _digest(path: Path) -> tuple[str, int, os.stat_result]:
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"not a regular file: {path}")
    info = os.stat(path, follow_symlinks=False)
    if info.st_nlink != 1:
        raise ContractError(f"hard-linked artifact is forbidden: {path}")
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data), info


def _safe_ref(root: Path, ref: str) -> Path:
    relative = PurePosixPath(ref)
    if not ref or relative.is_absolute() or ".." in relative.parts:
        raise ContractError(f"unsafe evidence ref: {ref!r}")
    path = root.joinpath(*relative.parts)
    resolved_root = root.resolve()
    if (
        path.is_symlink()
        or not path.is_file()
        or resolved_root not in path.resolve().parents
    ):
        raise ContractError(f"evidence ref escapes its root: {ref}")
    return path


def _validate_target_name(target: str) -> None:
    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or ".." in PurePosixPath(target).parts
    ):
        raise ContractError(f"unsafe live target: {target!r}")
    if target in FORBIDDEN_PUBLIC_TARGETS or target.endswith((".key", ".crt", ".pem")):
        raise ContractError(
            f"secret or credential target is forbidden in public contract: {target}"
        )
    if target not in ALLOWED_BINARY_TARGETS and not target.startswith(
        ALLOWED_TARGET_PREFIXES
    ):
        raise ContractError(f"live target is outside managed roots: {target}")


def _target_path(prefix: Path, target: str) -> Path:
    relative = PurePosixPath(target).relative_to("/")
    path = prefix.joinpath(*relative.parts)
    current = prefix
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ContractError(f"symlink parent is forbidden: {current}")
    return path


def verify_contract(
    bundle_path: Path,
    measurement_root: Path,
    target_prefix: Path = Path("/"),
    *,
    required_targets: set[str] | None = None,
) -> int:
    if (
        bundle_path.is_symlink()
        or measurement_root.is_symlink()
        or target_prefix.is_symlink()
    ):
        raise ContractError(
            "bundle, measurement root, and target prefix must not be symlinks"
        )
    bundle = _load_exact_json(bundle_path)
    measurements = bundle.get("measurements", {}).get("artifacts", [])
    measured = {
        item.get("ref"): item for item in measurements if isinstance(item, dict)
    }
    if len(measured) != len(measurements) or CONTRACT_REF not in measured:
        raise ContractError(
            "signed live artifact contract measurement is absent or duplicated"
        )
    contract_path = _safe_ref(measurement_root, CONTRACT_REF)
    contract_hash, contract_size, contract_stat = _digest(contract_path)
    expected_contract = measured[CONTRACT_REF]
    actual_contract = {
        "ref": CONTRACT_REF,
        "sha256": contract_hash,
        "size": contract_size,
        "mode": f"{contract_stat.st_mode & 0o7777:04o}",
        "uid": contract_stat.st_uid,
        "gid": contract_stat.st_gid,
    }
    if expected_contract != actual_contract:
        raise ContractError("live artifact contract drifted from signed measurement")

    contract = _load_exact_json(contract_path)
    if not isinstance(contract, dict) or set(contract) != {
        "live_artifact_contract_version",
        "artifacts",
    }:
        raise ContractError("live artifact contract has unexpected fields")
    if (
        contract["live_artifact_contract_version"] != 1
        or not isinstance(contract["artifacts"], list)
        or not contract["artifacts"]
    ):
        raise ContractError("live artifact contract v1 is invalid or empty")
    seen_targets: set[str] = set()
    seen_sources: set[str] = set()
    for item in contract["artifacts"]:
        required = {
            "target",
            "source_ref",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
            "kind",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise ContractError("live artifact record has unexpected fields")
        target, source_ref = item["target"], item["source_ref"]
        _validate_target_name(target)
        if target in seen_targets:
            raise ContractError(f"duplicate live target: {target}")
        seen_targets.add(target)
        if (
            not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in item["sha256"])
            or not isinstance(item["size"], int)
            or item["size"] < 0
            or not isinstance(item["mode"], str)
            or len(item["mode"]) != 4
            or any(ch not in "01234567" for ch in item["mode"])
            or not isinstance(item["uid"], int)
            or item["uid"] < 0
            or (target_prefix == Path("/") and item["uid"] != 0)
            or not isinstance(item["gid"], int)
            or item["gid"] < 0
            or item["kind"] not in ALLOWED_ARTIFACT_KINDS
        ):
            raise ContractError(f"invalid live artifact metadata: {target}")
        mode_value = int(item["mode"], 8)
        if mode_value & 0o7022:
            raise ContractError(
                f"live artifact mode grants unsafe write or special permissions: {target}"
            )
        if (
            item["kind"] in NON_EXECUTABLE_ARTIFACT_KINDS
            and mode_value & 0o111
        ):
            raise ContractError(f"non-executable live artifact is executable: {target}")
        if source_ref is not None:
            if not isinstance(source_ref, str) or source_ref in seen_sources:
                raise ContractError(
                    f"invalid or duplicate live source ref: {source_ref!r}"
                )
            seen_sources.add(source_ref)
            source = _safe_ref(measurement_root, source_ref)
            source_hash, source_size, source_stat = _digest(source)
            source_actual = {
                "ref": source_ref,
                "sha256": source_hash,
                "size": source_size,
                "mode": f"{source_stat.st_mode & 0o7777:04o}",
                "uid": source_stat.st_uid,
                "gid": source_stat.st_gid,
            }
            if measured.get(source_ref) != source_actual:
                raise ContractError(
                    f"live source is not an exact signed measurement: {source_ref}"
                )
            if source_hash != item["sha256"] or source_size != item["size"]:
                raise ContractError(
                    f"live source does not match target contract: {source_ref}"
                )
        elif target not in ALLOWED_BINARY_TARGETS or item["kind"] != "pinned-binary":
            raise ContractError(
                f"only pinned binaries may omit a measured source: {target}"
            )

        destination = _target_path(target_prefix, target)
        actual_hash, actual_size, info = _digest(destination)
        actual = {
            "sha256": actual_hash,
            "size": actual_size,
            "mode": f"{info.st_mode & 0o7777:04o}",
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        expected = {key: item[key] for key in ("sha256", "size", "mode", "uid", "gid")}
        if actual != expected:
            raise ContractError(f"live artifact drift: {target}")
    expected_targets = (
        REQUIRED_LIVE_TARGETS if required_targets is None else required_targets
    )
    if seen_targets != expected_targets:
        missing = sorted(expected_targets - seen_targets)
        extra = sorted(seen_targets - expected_targets)
        raise ContractError(
            f"live artifact inventory is not exact; missing={missing}, extra={extra}"
        )
    return len(seen_targets)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--measurement-root", required=True, type=Path)
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pinned-fingerprint")
    group.add_argument("--pinned-fingerprint-file", type=Path)
    args = parser.parse_args(argv)
    fingerprint = args.pinned_fingerprint
    if args.pinned_fingerprint_file:
        fingerprint = args.pinned_fingerprint_file.read_text(encoding="ascii").strip()
    readiness = Path(__file__).with_name("verify-wsl-jit-readiness.py")
    command = [
        sys.executable,
        str(readiness),
        "--evidence",
        str(args.evidence),
        "--measurement-root",
        str(args.measurement_root),
        "--reviewer-public-key",
        str(args.reviewer_public_key),
        "--pinned-fingerprint",
        fingerprint or "",
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        count = verify_contract(args.evidence, args.measurement_root)
    except (ContractError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"live artifact verification blocked: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"status": "verified", "live_artifacts": count}, separators=(",", ":")
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
