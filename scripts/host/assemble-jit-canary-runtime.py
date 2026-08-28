#!/usr/bin/env python3
"""Assemble the local, externally-signed JIT canary runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.canary_boundary import (  # noqa: E402
    CanaryBoundaryError,
    validate_canary_authorization,
    verify_canary_authorization,
)
from github_automation.crypto import (  # noqa: E402
    canonicalize_jcs,
    parse_ijson,
    spki_fingerprint,
)
from github_automation.worker_authority import (  # noqa: E402
    WORKER_PERMISSIONS,
    WorkerAppAuthorityV1,
    WorkerAuthorityError,
)


class AssemblyError(ValueError):
    pass


_DIGEST = re.compile(r"[0-9a-f]{64}")
_RUNTIME_DISPATCH_FIELDS = {
    "schema_version",
    "purpose",
    "app_id",
    "app_slug",
    "installation_id",
    "repository",
    "repository_id",
    "repository_selection",
    "default_branch",
    "workflow_id",
    "workflow_path",
    "permissions",
    "private_key_file",
}
_SOURCE_DISPATCH_FIELDS = _RUNTIME_DISPATCH_FIELDS
_RUNTIME_FIELDS = {
    "schema_version",
    "reviewer_public_key_file",
    "reviewer_fingerprint",
    "digested_files",
    "garm_health_file",
    "broker_config_file",
    "allocation_signer_private_key_file",
    "broker_executable",
    "request_timeout_seconds",
}
_DIGEST_NAMES = {
    "github_app_config",
    "live_job_verifier",
    "network_policy",
    "bootstrap_install_receipt",
}
DEFAULT_REQUEST_TIMEOUT_SECONDS = 300


def _file(path: Path, *, maximum: int = 1_048_576, private: bool = False) -> bytes:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 1
        or info.st_size > maximum
        or path.is_symlink()
    ):
        raise AssemblyError(f"unsafe assembly input: {path}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise AssemblyError(f"private assembly input is group/world accessible: {path}")
    return path.read_bytes()


def _json(path: Path, *, private: bool = False) -> Mapping[str, Any]:
    try:
        value = parse_ijson(_file(path, maximum=131_072, private=private))
    except (OSError, TypeError, ValueError) as exc:
        raise AssemblyError(f"invalid assembly JSON: {path}") from exc
    if not isinstance(value, Mapping):
        raise AssemblyError(f"assembly JSON is not an object: {path}")
    return value


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _new_output(root: Path) -> None:
    if root.exists() or root.is_symlink():
        raise AssemblyError("prepared output directory must not already exist")
    root.mkdir(parents=True, mode=0o700)


def _dispatcher_app(source: Mapping[str, Any], branch: str) -> Mapping[str, Any]:
    if set(source) != _SOURCE_DISPATCH_FIELDS:
        raise AssemblyError("dispatcher App source fields are not exact")
    if (
        source.get("schema_version") != 1
        or source.get("purpose") != "workflow-dispatch"
        or source.get("repository_selection") != "selected"
        or source.get("permissions") != WORKER_PERMISSIONS
        or type(source.get("app_id")) is not int
        or source["app_id"] < 1
        or type(source.get("installation_id")) is not int
        or source["installation_id"] < 1
        or not isinstance(source.get("private_key_file"), str)
        or not source["private_key_file"].startswith(
            "/etc/self-hosted-ci/secrets/"
        )
    ):
        raise AssemblyError("dispatcher App source authority is invalid")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("/"):
        raise AssemblyError("default branch is invalid")
    if (
        source.get("default_branch") != branch
        or source.get("workflow_id") != "ci-jit-canary-child.yml"
        or source.get("workflow_path")
        != ".github/workflows/ci-jit-canary-child.yml"
    ):
        raise AssemblyError("dispatcher workflow binding is invalid")
    value = dict(source)
    if set(value) != _RUNTIME_DISPATCH_FIELDS:
        raise AssemblyError("dispatcher runtime fields are not exact")
    try:
        WorkerAppAuthorityV1(
            value["app_id"],
            value["app_slug"],
            value["installation_id"],
            value["repository"],
            value["repository_id"],
            value["repository_selection"],
            value["default_branch"],
            value["workflow_id"],
            value["workflow_path"],
            value["permissions"],
        )
    except WorkerAuthorityError as exc:
        raise AssemblyError("dispatcher runtime authority is invalid") from exc
    return value


def _prepare(args: argparse.Namespace) -> Mapping[str, Any]:
    output = args.output_directory.resolve(strict=False)
    _new_output(output)
    dispatcher_source = _json(args.dispatcher_app_config, private=True)
    dispatcher = _dispatcher_app(dispatcher_source, args.default_branch)
    dispatcher_path = args.dispatcher_app_config.resolve(strict=True)
    dispatcher_bytes = _file(dispatcher_path, maximum=131_072, private=True)

    reviewer_key = serialization.load_pem_public_key(
        _file(args.reviewer_public_key, maximum=65_536)
    )
    if not isinstance(reviewer_key, ed25519.Ed25519PublicKey):
        raise AssemblyError("reviewer public key must be Ed25519")
    reviewer_fingerprint = spki_fingerprint(reviewer_key)
    signer_key = serialization.load_pem_private_key(
        _file(args.allocation_signer_private_key, maximum=65_536, private=True),
        password=None,
    )
    if not isinstance(signer_key, ed25519.Ed25519PrivateKey):
        raise AssemblyError("allocation signer must be Ed25519")
    signer_fingerprint = spki_fingerprint(signer_key.public_key())

    live_verifier = _file(args.live_job_verifier)
    network_policy = _file(args.network_policy)
    bootstrap_receipt = _file(args.bootstrap_install_receipt)
    digests = {
        "github_app_config": _digest(dispatcher_bytes),
        "live_job_verifier": _digest(live_verifier),
        "network_policy": _digest(network_policy),
        "bootstrap_install_receipt": _digest(bootstrap_receipt),
    }
    if set(digests) != _DIGEST_NAMES or any(
        not _DIGEST.fullmatch(value) for value in digests.values()
    ):
        raise AssemblyError("live digest assembly failed")

    health = _json(args.garm_health_file, private=True)
    broker = _json(args.broker_config_file, private=True)
    template = dict(_json(args.authorization_template, private=True))
    if "attestation" in template:
        raise AssemblyError("authorization template must be unsigned")
    template.update(
        allocation_signer_fingerprint=signer_fingerprint,
        github_app_config_digest=digests["github_app_config"],
        live_job_verifier_digest=digests["live_job_verifier"],
        network_policy_digest=digests["network_policy"],
        bootstrap_install_receipt_digest=digests[
            "bootstrap_install_receipt"
        ],
    )
    blockers = validate_canary_authorization(template)
    if blockers:
        raise AssemblyError("unsigned authorization is invalid: " + ",".join(blockers))
    repository_id = str(template["repository_id"])
    entity = dict(template["garm_entity"])
    entity["entity_flag"] = (
        "--repo"
        if entity["authority_kind"] == "personal-repository"
        else "--org"
    )
    expected_health = {
        "schema_version": 3,
        "garm_cli_home": broker.get("garm_cli_home"),
        "manager_configured": True,
        "provider_configured": True,
        "image_configured": True,
        "broker_configured": True,
        "zero_scale_sets": True,
        "image": {
            "alias": template["image_alias"],
            "fingerprint": template["image_fingerprint"],
        },
        "targets": {repository_id: entity},
    }
    expected_broker_fields = {
        "allocation_signer_fingerprint",
        "garm_cli_home",
        "provider_name",
        "image_alias",
        "image_fingerprint",
        "live_job_verifier",
        "targets",
    }
    if (
        dispatcher["repository"] != template["repository"]
        or dispatcher["repository_id"] != template["repository_id"]
        or template["workflow_ref"]
        != f"{template['repository']}/.github/workflows/ci-jit-canary-child.yml@refs/heads/{args.default_branch}"
        or health != expected_health
        or set(broker) != expected_broker_fields
        or broker.get("targets") != {repository_id: entity}
        or broker.get("allocation_signer_fingerprint") != signer_fingerprint
        or broker.get("image_alias") != template["image_alias"]
        or broker.get("image_fingerprint") != template["image_fingerprint"]
    ):
        raise AssemblyError("authorization crossed configured GARM/App authority")

    runtime = {
        "schema_version": 1,
        "reviewer_public_key_file": args.reviewer_public_key_runtime_path,
        "reviewer_fingerprint": reviewer_fingerprint,
        "digested_files": {
            "github_app_config": str(dispatcher_path),
            "live_job_verifier": args.live_job_verifier_runtime_path,
            "network_policy": args.network_policy_runtime_path,
            "bootstrap_install_receipt": args.bootstrap_install_receipt_runtime_path,
        },
        "garm_health_file": args.garm_health_runtime_path,
        "broker_config_file": args.broker_config_runtime_path,
        "allocation_signer_private_key_file": args.allocation_signer_runtime_path,
        "broker_executable": "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py",
        "request_timeout_seconds": args.request_timeout_seconds,
    }
    if set(runtime) != _RUNTIME_FIELDS or set(runtime["digested_files"]) != _DIGEST_NAMES:
        raise AssemblyError("runtime config fields are not exact")
    for path_value in (
        runtime["reviewer_public_key_file"],
        *runtime["digested_files"].values(),
        runtime["garm_health_file"],
        runtime["broker_config_file"],
        runtime["allocation_signer_private_key_file"],
    ):
        if not isinstance(path_value, str) or not path_value.startswith("/") or ".." in Path(path_value).parts:
            raise AssemblyError("runtime config contains an unsafe path")
    if not 30 <= runtime["request_timeout_seconds"] <= 3600:
        raise AssemblyError("runtime request timeout is outside bounds")

    artifacts = {
        "runtime-config.json": canonicalize_jcs(runtime) + b"\n",
        "authorization-unsigned.json": canonicalize_jcs(template) + b"\n",
    }
    for name, data in artifacts.items():
        _atomic(output / name, data, 0o600)
    manifest = {
        "schema_version": 1,
        "status": "prepared-awaiting-external-signature",
        "artifacts": {
            name: {"bytes": len(data), "sha256": _digest(data), "mode": "0600"}
            for name, data in sorted(artifacts.items())
        },
        "reviewer_fingerprint": reviewer_fingerprint,
        "allocation_signer_fingerprint": signer_fingerprint,
        "live_dispatcher_app_config": {
            "path": str(dispatcher_path),
            "bytes": len(dispatcher_bytes),
            "sha256": _digest(dispatcher_bytes),
            "mode": "0600",
        },
        "github_contacted": False,
        "authorization_signed": False,
    }
    _atomic(output / "prepare-manifest.json", canonicalize_jcs(manifest) + b"\n", 0o600)
    return manifest


def _tar_member(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def _bundle(args: argparse.Namespace) -> Mapping[str, Any]:
    prepared = args.prepared_directory.resolve(strict=True)
    expected_names = {
        "runtime-config.json",
        "authorization-unsigned.json",
        "prepare-manifest.json",
    }
    if {path.name for path in prepared.iterdir()} != expected_names:
        raise AssemblyError("prepared directory contents are not exact")
    prepare_manifest = _json(prepared / "prepare-manifest.json", private=True)
    if set(prepare_manifest) != {
        "schema_version",
        "status",
        "artifacts",
        "reviewer_fingerprint",
        "allocation_signer_fingerprint",
        "live_dispatcher_app_config",
        "github_contacted",
        "authorization_signed",
    } or prepare_manifest.get("schema_version") != 1 or prepare_manifest.get(
        "status"
    ) != "prepared-awaiting-external-signature" or prepare_manifest.get(
        "github_contacted"
    ) is not False or prepare_manifest.get("authorization_signed") is not False:
        raise AssemblyError("prepare manifest fields are not exact")
    artifacts = prepare_manifest.get("artifacts")
    prepared_artifact_names = expected_names - {"prepare-manifest.json"}
    if not isinstance(artifacts, Mapping) or set(artifacts) != prepared_artifact_names:
        raise AssemblyError("prepare manifest artifact set is not exact")
    for name in prepared_artifact_names:
        data = _file(prepared / name, maximum=131_072, private=True)
        receipt = artifacts[name]
        if not isinstance(receipt, Mapping) or receipt != {
            "bytes": len(data),
            "sha256": _digest(data),
            "mode": "0600",
        }:
            raise AssemblyError("prepared artifact manifest verification failed")
    unsigned_bytes = _file(prepared / "authorization-unsigned.json", maximum=131_072, private=True)
    unsigned = parse_ijson(unsigned_bytes)
    signed_bytes = canonicalize_jcs(_json(args.signed_authorization, private=True)) + b"\n"
    signed = parse_ijson(signed_bytes)
    public_key = serialization.load_pem_public_key(
        _file(args.reviewer_public_key, maximum=65_536)
    )
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise AssemblyError("reviewer public key must be Ed25519")
    fingerprint = spki_fingerprint(public_key)
    if prepare_manifest.get("reviewer_fingerprint") != fingerprint:
        raise AssemblyError("prepared reviewer fingerprint drifted")
    decision = verify_canary_authorization(
        signed, public_key, pinned_fingerprint=fingerprint
    )
    if not decision.authorized:
        raise AssemblyError("signed authorization was rejected")
    if {key: value for key, value in signed.items() if key != "attestation"} != unsigned:
        raise AssemblyError("signed authorization crossed prepared unsigned bytes")

    dispatcher_receipt = prepare_manifest.get("live_dispatcher_app_config")
    if not isinstance(dispatcher_receipt, Mapping) or set(dispatcher_receipt) != {
        "path",
        "bytes",
        "sha256",
        "mode",
    } or not isinstance(dispatcher_receipt.get("path"), str):
        raise AssemblyError("live dispatcher App receipt is invalid")
    dispatcher_path = Path(dispatcher_receipt["path"])
    dispatcher_bytes = _file(dispatcher_path, maximum=131_072, private=True)
    if dispatcher_receipt != {
        "path": str(dispatcher_path),
        "bytes": len(dispatcher_bytes),
        "sha256": _digest(dispatcher_bytes),
        "mode": "0600",
    }:
        raise AssemblyError("live dispatcher App config drifted after preparation")
    runtime = _json(prepared / "runtime-config.json", private=True)
    if (
        set(runtime) != _RUNTIME_FIELDS
        or set(runtime.get("digested_files", {})) != _DIGEST_NAMES
        or runtime.get("reviewer_fingerprint") != fingerprint
        or runtime["digested_files"].get("github_app_config")
        != str(dispatcher_path)
        or signed.get("github_app_config_digest") != _digest(dispatcher_bytes)
        or signed.get("allocation_signer_fingerprint")
        != prepare_manifest.get("allocation_signer_fingerprint")
    ):
        raise AssemblyError("prepared runtime config crossed signed authorization")

    runtime_bytes = _file(prepared / "runtime-config.json", maximum=131_072, private=True)
    members = {
        "canary/authorization.json": signed_bytes,
        "canary/runtime-config.json": runtime_bytes,
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(members.items()):
            _tar_member(archive, name, data)
    tar_bytes = buffer.getvalue()
    if args.output_tar.exists() or args.output_tar.is_symlink():
        raise AssemblyError("bundle output must not already exist")
    if args.output_manifest.exists() or args.output_manifest.is_symlink():
        raise AssemblyError("bundle manifest output must not already exist")
    _atomic(args.output_tar, tar_bytes, 0o600)
    manifest = {
        "schema_version": 1,
        "status": "bundle-ready",
        "bundle": {
            "bytes": len(tar_bytes),
            "sha256": _digest(tar_bytes),
            "format": "ustar",
        },
        "members": {
            name: {"bytes": len(data), "sha256": _digest(data), "mode": "0600", "uid": 0, "gid": 0}
            for name, data in sorted(members.items())
        },
        "dispatcher_app_config": dict(dispatcher_receipt),
        "reviewer_fingerprint": fingerprint,
        "github_contacted": False,
        "authorization_signed_by_assembler": False,
    }
    _atomic(args.output_manifest, canonicalize_jcs(manifest) + b"\n", 0o600)
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and bundle a fail-closed JIT canary runtime without signing or GitHub contact."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="measure live inputs and emit unsigned artifacts")
    prepare.add_argument("--output-directory", required=True, type=Path)
    prepare.add_argument("--authorization-template", required=True, type=Path)
    prepare.add_argument("--dispatcher-app-config", required=True, type=Path)
    prepare.add_argument("--default-branch", required=True)
    prepare.add_argument("--reviewer-public-key", required=True, type=Path)
    prepare.add_argument("--allocation-signer-private-key", required=True, type=Path)
    prepare.add_argument("--garm-health-file", required=True, type=Path)
    prepare.add_argument("--broker-config-file", required=True, type=Path)
    prepare.add_argument("--live-job-verifier", required=True, type=Path)
    prepare.add_argument("--network-policy", required=True, type=Path)
    prepare.add_argument("--bootstrap-install-receipt", required=True, type=Path)
    prepare.add_argument("--reviewer-public-key-runtime-path", required=True)
    prepare.add_argument("--allocation-signer-runtime-path", required=True)
    prepare.add_argument("--garm-health-runtime-path", required=True)
    prepare.add_argument("--broker-config-runtime-path", required=True)
    prepare.add_argument("--live-job-verifier-runtime-path", required=True)
    prepare.add_argument("--network-policy-runtime-path", required=True)
    prepare.add_argument("--bootstrap-install-receipt-runtime-path", required=True)
    prepare.add_argument(
        "--request-timeout-seconds",
        type=int,
        default=DEFAULT_REQUEST_TIMEOUT_SECONDS,
    )

    bundle = sub.add_parser("bundle", help="verify an external signature and emit the exact tar")
    bundle.add_argument("--prepared-directory", required=True, type=Path)
    bundle.add_argument("--signed-authorization", required=True, type=Path)
    bundle.add_argument("--reviewer-public-key", required=True, type=Path)
    bundle.add_argument("--output-tar", required=True, type=Path)
    bundle.add_argument("--output-manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _prepare(args) if args.command == "prepare" else _bundle(args)
        print(canonicalize_jcs(result).decode("utf-8"))
        return 0
    except (AssemblyError, CanaryBoundaryError, OSError, TypeError, ValueError) as exc:
        print(f"canary runtime assembly blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
