#!/usr/bin/env python3
"""Remeasure the persisted inert bootstrap and its exact installed targets."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.bootstrap_boundary import (
    AUTHORIZATION,
    BOOTSTRAP_ATTESTATION_DOMAIN,
    BootstrapBoundaryError,
    public_manifest_blockers,
)
from github_automation.crypto import (
    canonicalize_jcs,
    parse_ijson,
    spki_fingerprint,
    verify_detached,
)


BOOTSTRAP_FILES = {
    "boundary": "bootstrap-boundary-v1.signed.json",
    "manifest": "bootstrap-public-manifest-v1.json",
    "reviewer_key": "reviewer-public-key.pem",
    "reviewer_pin": "reviewer-key.sha256",
    "provisioner": "provision-wsl-jit-contract.sh",
}
RECEIPT_NAME = "bootstrap-install-receipt-v1.json"
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class BootstrapInstallError(ValueError):
    pass


def _regular(path: Path, *, mode: int | None = None, root_only: bool = False) -> os.stat_result:
    if path.is_symlink() or not path.is_file():
        raise BootstrapInstallError(f"not a regular file: {path}")
    info = os.stat(path, follow_symlinks=False)
    if info.st_nlink != 1:
        raise BootstrapInstallError(f"hard-linked file is forbidden: {path}")
    if info.st_uid != 0:
        raise BootstrapInstallError(f"file is not root-owned: {path}")
    actual_mode = info.st_mode & 0o7777
    if mode is not None and actual_mode != mode:
        raise BootstrapInstallError(f"file mode drifted: {path}")
    if root_only and actual_mode & 0o077:
        raise BootstrapInstallError(f"file is not root-only: {path}")
    return info


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_symlink_ancestors(path: Path, root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise BootstrapInstallError(f"installed root is unsafe: {root}")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise BootstrapInstallError(f"installed target escapes root: {path}") from exc
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise BootstrapInstallError(f"installed target has symlink ancestor: {path}")


def _installed_path(installed_root: Path, bootstrap_root: Path, target: str) -> Path:
    if target == "@execution/provision-wsl-jit-contract.sh":
        path = bootstrap_root / BOOTSTRAP_FILES["provisioner"]
        _reject_symlink_ancestors(path, bootstrap_root)
        return path
    value = PurePosixPath(target)
    if not value.is_absolute() or ".." in value.parts:
        raise BootstrapInstallError(f"manifest target is unsafe: {target}")
    path = installed_root.joinpath(*value.parts[1:])
    _reject_symlink_ancestors(path, installed_root)
    return path


def _record(path: Path, manifest_target: str) -> dict[str, object]:
    info = _regular(path)
    data = path.read_bytes()
    return {
        "manifest_target": manifest_target,
        "installed_path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": f"{info.st_mode & 0o7777:04o}",
        "link_count": info.st_nlink,
        "symlink": False,
    }


def measure(bootstrap_root: Path, installed_root: Path) -> dict[str, object]:
    if bootstrap_root.is_symlink() or not bootstrap_root.is_dir():
        raise BootstrapInstallError("bootstrap root is not a real directory")
    root_info = os.stat(bootstrap_root, follow_symlinks=False)
    if root_info.st_uid != 0 or root_info.st_mode & 0o077:
        raise BootstrapInstallError("bootstrap root must be root-only")
    paths = {name: bootstrap_root / filename for name, filename in BOOTSTRAP_FILES.items()}
    for name, path in paths.items():
        if name == "provisioner":
            continue
        _regular(path, mode=0o600, root_only=True)
    _regular(paths["provisioner"], mode=0o755)

    boundary = parse_ijson(paths["boundary"].read_bytes())
    manifest = parse_ijson(paths["manifest"].read_bytes())
    pin = paths["reviewer_pin"].read_text(encoding="ascii").strip()
    if not HEX_256.fullmatch(pin):
        raise BootstrapInstallError("persisted reviewer pin is invalid")
    key = serialization.load_pem_public_key(paths["reviewer_key"].read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey) or spki_fingerprint(key) != pin:
        raise BootstrapInstallError("persisted reviewer key does not match its pin")
    if public_manifest_blockers(manifest):
        raise BootstrapInstallError("persisted bootstrap manifest is invalid")
    expected_boundary_fields = {
        "bootstrap_boundary_version", "issued_at", "expires_at", "nonce", "authorization",
        "windows_observation", "wsl_observation", "public_manifest", "attestation",
    }
    if set(boundary) != expected_boundary_fields or boundary.get("bootstrap_boundary_version") != 1 or boundary.get("authorization") != AUTHORIZATION:
        raise BootstrapInstallError("persisted bootstrap boundary is invalid")
    attestation = boundary.get("attestation")
    if not isinstance(attestation, Mapping) or set(attestation) != {"attestation_version", "signer_fingerprint", "signature"} or attestation.get("attestation_version") != 1 or attestation.get("signer_fingerprint") != pin:
        raise BootstrapInstallError("persisted bootstrap attestation is invalid")
    unsigned = {name: value for name, value in boundary.items() if name != "attestation"}
    try:
        verify_detached(unsigned, attestation["signature"], key, domain=BOOTSTRAP_ATTESTATION_DOMAIN)
    except (TypeError, ValueError) as exc:
        raise BootstrapInstallError("persisted bootstrap signature is invalid") from exc
    manifest_digest = hashlib.sha256(canonicalize_jcs(manifest)).hexdigest()
    binding = boundary.get("public_manifest")
    if not isinstance(binding, Mapping) or binding.get("sha256") != manifest_digest or binding.get("mapping_digest") != manifest.get("mapping_digest") or binding.get("artifact_count") != len(manifest.get("artifacts", [])):
        raise BootstrapInstallError("persisted manifest crossed the signed bootstrap binding")

    records = []
    seen: set[str] = set()
    provisioner_digest = None
    for item in manifest["artifacts"]:
        target = item["target"]
        if target in seen:
            raise BootstrapInstallError(f"duplicate manifest target: {target}")
        seen.add(target)
        path = _installed_path(installed_root, bootstrap_root, target)
        record = _record(path, target)
        if record["sha256"] != item["sha256"] or record["size"] != item["size"] or record["mode"] != item["mode"] or record["uid"] != 0:
            raise BootstrapInstallError(f"installed bootstrap target drifted: {target}")
        if target == "@execution/provision-wsl-jit-contract.sh":
            provisioner_digest = record["sha256"]
        records.append(record)
    records.sort(key=lambda item: item["manifest_target"])
    targets_digest = hashlib.sha256(canonicalize_jcs(records)).hexdigest()
    return {
        "bootstrap_install_receipt_version": 1,
        "bootstrap_boundary_sha256": _sha(paths["boundary"]),
        "bootstrap_public_manifest_sha256": manifest_digest,
        "bootstrap_mapping_digest": manifest["mapping_digest"],
        "reviewer_key_fingerprint": pin,
        "reviewer_public_key_sha256": _sha(paths["reviewer_key"]),
        "provisioner_sha256": provisioner_digest,
        "nonce": boundary["nonce"],
        "artifact_count": len(records),
        "installed_targets_digest": targets_digest,
        "installed_targets": records,
    }


def _write_atomic(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise BootstrapInstallError("receipt parent is a symlink")
    os.chown(path.parent, 0, 0)
    os.chmod(path.parent, 0o700)
    payload = dict(value)
    payload["installed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload["receipt_digest"] = hashlib.sha256(canonicalize_jcs(payload)).hexdigest()
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonicalize_jcs(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def verify_receipt(receipt: Path, measured: Mapping[str, object]) -> dict[str, object]:
    _regular(receipt, mode=0o600, root_only=True)
    stored = parse_ijson(receipt.read_bytes())
    if not isinstance(stored, Mapping) or set(stored) != set(measured) | {"installed_at", "receipt_digest"}:
        raise BootstrapInstallError("bootstrap install receipt requires exact v1 fields")
    if {key: value for key, value in stored.items() if key not in {"installed_at", "receipt_digest"}} != dict(measured):
        raise BootstrapInstallError("bootstrap install receipt does not match current measurements")
    installed_at = stored.get("installed_at")
    if not isinstance(installed_at, str) or not installed_at.endswith("Z"):
        raise BootstrapInstallError("bootstrap receipt timestamp is invalid")
    unsigned = {key: value for key, value in stored.items() if key != "receipt_digest"}
    if stored.get("receipt_digest") != hashlib.sha256(canonicalize_jcs(unsigned)).hexdigest():
        raise BootstrapInstallError("bootstrap receipt digest is invalid")
    return dict(stored)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-root", type=Path, default=Path("/etc/self-hosted-ci/bootstrap"))
    parser.add_argument("--installed-root", type=Path, default=Path("/"))
    parser.add_argument("--receipt", type=Path, default=Path("/var/lib/self-hosted-ci/bootstrap/bootstrap-install-receipt-v1.json"))
    parser.add_argument("--write-receipt", action="store_true")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise BootstrapInstallError("bootstrap remeasurement must run as root")
        measured = measure(args.bootstrap_root, args.installed_root)
        if args.write_receipt:
            _write_atomic(args.receipt, measured)
            result = verify_receipt(args.receipt, measured)
        else:
            result = verify_receipt(args.receipt, measured)
    except (OSError, TypeError, ValueError, BootstrapBoundaryError, BootstrapInstallError) as exc:
        print(f"bootstrap install verification failed: {exc}", file=sys.stderr)
        return 2
    print(canonicalize_jcs({"status": "verified", "receipt_digest": result["receipt_digest"], "installed_targets_digest": result["installed_targets_digest"]}).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
