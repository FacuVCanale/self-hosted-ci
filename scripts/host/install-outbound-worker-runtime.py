#!/usr/bin/env python3
"""Install and locally validate the outbound worker runtime, without network I/O."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


CONFIG_TARGET = PurePosixPath("/etc/self-hosted-ci/outbound-worker.json")
READY_TARGET = PurePosixPath("/etc/self-hosted-ci/outbound-worker.runtime-ready")
PACKAGE_TARGET = PurePosixPath("/usr/local/lib/self-hosted-ci")
SECRET_ROOT = PurePosixPath("/etc/self-hosted-ci/secrets")
STATE_ROOT = PurePosixPath("/var/lib/self-hosted-ci/outbound-worker")
BROKER_TARGET = "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py"
REQUIRED_FIELDS = {
    "schema_version", "mode", "app_id", "app_slug", "installation_id",
    "repository", "repository_id", "repository_selection", "default_branch",
    "workflow_id", "workflow_path", "permissions", "github_app_private_key_file",
    "authority_helper_file", "authority_manifest_file", "authority_signer_key_file",
    "allocation_signer_key_file", "image_fingerprint", "gatestore_file",
    "approval_store_file", "worker_state_file", "broker_executable",
    "approval_ttl_seconds", "poll_seconds", "request_timeout_seconds",
}
EXACT_PERMISSIONS = {"metadata": "read", "pull_requests": "read", "actions": "write"}


class InstallError(ValueError):
    pass


def _physical(prefix: Path, logical: PurePosixPath | str) -> Path:
    value = PurePosixPath(logical)
    if not value.is_absolute() or ".." in value.parts:
        raise InstallError(f"path is not absolute and normalized: {logical}")
    return prefix.joinpath(*value.relative_to("/").parts)


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InstallError(f"duplicate config key: {key}")
        value[key] = item
    return value


def load_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_exact_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError("outbound worker config is not readable exact JSON") from exc
    if not isinstance(value, dict) or set(value) != REQUIRED_FIELDS:
        raise InstallError("outbound worker config fields are not exact")
    if value["schema_version"] != 1 or value["mode"] != "ci-jit-pilot":
        raise InstallError("runtime-ready installation supports only schema v1 ci-jit-pilot")
    for field in ("app_id", "installation_id", "repository_id"):
        if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] < 1:
            raise InstallError(f"{field} must be a positive integer")
    for field in ("approval_ttl_seconds", "poll_seconds", "request_timeout_seconds"):
        if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] < 1:
            raise InstallError(f"{field} must be a positive integer")
    if value["approval_ttl_seconds"] > 300:
        raise InstallError("approval_ttl_seconds must not exceed five minutes")
    if value["repository_selection"] != "selected" or value["permissions"] != EXACT_PERMISSIONS:
        raise InstallError("worker App selection or permissions are not exact")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(value["repository"])):
        raise InstallError("repository is invalid")
    if not re.fullmatch(r"[A-Za-z0-9-]+", str(value["app_slug"])):
        raise InstallError("app_slug is invalid")
    workflow_id = value["workflow_id"]
    if not isinstance(workflow_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow_id):
        raise InstallError("workflow_id is invalid")
    if value["workflow_path"] != f".github/workflows/{workflow_id}":
        raise InstallError("workflow_path does not match workflow_id")
    if not isinstance(value["default_branch"], str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", value["default_branch"]) or value["default_branch"].startswith("/"):
        raise InstallError("default_branch is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(value["image_fingerprint"])):
        raise InstallError("image_fingerprint must be lowercase SHA-256")
    github_key = PurePosixPath(str(value["github_app_private_key_file"]))
    allocation_key = PurePosixPath(str(value["allocation_signer_key_file"]))
    if github_key.parent != SECRET_ROOT or allocation_key.parent != SECRET_ROOT or github_key == allocation_key:
        raise InstallError("worker private keys must be distinct direct children of the managed secrets directory")
    for field in ("gatestore_file", "approval_store_file", "worker_state_file"):
        state_path = PurePosixPath(str(value[field]))
        if state_path.parent != STATE_ROOT or state_path.suffix not in {".db", ".sqlite3"}:
            raise InstallError(f"{field} must be a managed outbound-worker database")
    if len({value["gatestore_file"], value["approval_store_file"], value["worker_state_file"]}) != 3:
        raise InstallError("worker databases must use distinct paths")
    if value["broker_executable"] != BROKER_TARGET:
        raise InstallError("broker_executable is not the exact managed broker")
    return value


def _private_key(path: Path, expected: str) -> None:
    try:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise InstallError(f"{expected} private key is invalid") from exc
    if expected == "GitHub App":
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise InstallError("GitHub App private key must be RSA 2048-bit or stronger")
    elif not isinstance(key, ed25519.Ed25519PrivateKey):
        raise InstallError("allocation signer key must be Ed25519")


def _secure_file(path: Path, *, executable: bool = False, expected_uid: int = 0) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise InstallError(f"required runtime file is missing: {path}") from exc
    expected_mode = 0o755 if executable else 0o600
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != expected_mode or info.st_size < 1
    ):
        raise InstallError(f"runtime file must be owned by uid {expected_uid}, regular, single-link mode {expected_mode:04o}: {path}")


def _atomic_install(source: Path, target: Path, mode: int, *, uid: int = 0, gid: int = 0) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _isolated_import_smoke(prefix: Path) -> None:
    package_root = _physical(prefix, PACKAGE_TARGET)
    code = """
import importlib, pkgutil, sys
root=sys.argv[1]
sys.path.insert(0,root)
package=importlib.import_module('github_automation')
names=sorted(m.name for m in pkgutil.iter_modules(package.__path__))
if 'check_delivery' not in names:
    raise SystemExit('check_delivery is absent from installed package')
for name in names:
    importlib.import_module(f'github_automation.{name}')
importlib.import_module('github_automation.github_adapter')
print('isolated-import-smoke-ok')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(package_root)],
        text=True, capture_output=True, timeout=30, check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    if result.returncode != 0 or result.stdout.strip() != "isolated-import-smoke-ok":
        raise InstallError(f"installed Python import closure failed: {result.stderr.strip()}")


def verify_runtime(*, prefix: Path = Path("/"), expected_uid: int = 0, require_ready: bool = True) -> dict[str, Any]:
    config_target = _physical(prefix, CONFIG_TARGET)
    _secure_file(config_target, expected_uid=expected_uid)
    config = load_config(config_target)
    github_target = _physical(prefix, config["github_app_private_key_file"])
    allocation_target = _physical(prefix, config["allocation_signer_key_file"])
    for path in (github_target, allocation_target):
        _secure_file(path, expected_uid=expected_uid)
    _private_key(github_target, "GitHub App")
    _private_key(allocation_target, "allocation signer")
    broker = _physical(prefix, config["broker_executable"])
    _secure_file(broker, executable=True, expected_uid=expected_uid)
    for field in ("gatestore_file", "approval_store_file", "worker_state_file"):
        parent = _physical(prefix, PurePosixPath(config[field]).parent)
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise InstallError("outbound worker state directory must be owner-only")
    _isolated_import_smoke(prefix)
    if require_ready:
        ready_target = _physical(prefix, READY_TARGET)
        _secure_file(ready_target, expected_uid=expected_uid)
        try:
            ready = json.loads(ready_target.read_text(encoding="utf-8"), object_pairs_hook=_exact_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InstallError("runtime-ready sentinel is invalid") from exc
        expected = {"schema_version": 1, "mode": config["mode"], "local_smoke": "passed", "external_calls": False, "dispatch": False}
        if ready != expected:
            raise InstallError("runtime-ready sentinel fields are not exact")
    return {"status": "verified", "mode": config["mode"], "runtime_ready": require_ready, "external_calls": False, "dispatch": False}


def install_runtime(
    config_source: Path, github_key_source: Path, allocation_key_source: Path,
    *, prefix: Path = Path("/"), expected_uid: int = 0,
) -> dict[str, Any]:
    ready_target = _physical(prefix, READY_TARGET)
    ready_target.unlink(missing_ok=True)
    for source in (config_source, github_key_source, allocation_key_source):
        _secure_file(source, expected_uid=expected_uid)
    config = load_config(config_source)
    _private_key(github_key_source, "GitHub App")
    _private_key(allocation_key_source, "allocation signer")
    config_target = _physical(prefix, CONFIG_TARGET)
    etc_root = _physical(prefix, "/etc/self-hosted-ci")
    secrets_root = _physical(prefix, SECRET_ROOT)
    state_root = _physical(prefix, STATE_ROOT)
    for directory, mode in ((etc_root, 0o750), (secrets_root, 0o700), (state_root, 0o700)):
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, expected_uid, 0 if expected_uid == 0 else os.getgid())
        os.chmod(directory, mode)
    github_target = _physical(prefix, config["github_app_private_key_file"])
    allocation_target = _physical(prefix, config["allocation_signer_key_file"])
    target_gid = 0 if expected_uid == 0 else os.getgid()
    _atomic_install(config_source, config_target, 0o600, uid=expected_uid, gid=target_gid)
    _atomic_install(github_key_source, github_target, 0o600, uid=expected_uid, gid=target_gid)
    _atomic_install(allocation_key_source, allocation_target, 0o600, uid=expected_uid, gid=target_gid)
    for path in (config_target, github_target, allocation_target):
        _secure_file(path, expected_uid=expected_uid)
    installed = load_config(config_target)
    if installed != config:
        raise InstallError("installed config changed during installation")
    _private_key(github_target, "GitHub App")
    _private_key(allocation_target, "allocation signer")
    verify_runtime(prefix=prefix, expected_uid=expected_uid, require_ready=False)
    sentinel = {"schema_version": 1, "mode": installed["mode"], "local_smoke": "passed", "external_calls": False, "dispatch": False}
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=ready_target.parent, delete=False) as output:
        json.dump(sentinel, output, sort_keys=True, separators=(",", ":")); output.write("\n")
        temporary = Path(output.name)
    try:
        os.chown(temporary, expected_uid, 0 if expected_uid == 0 else os.getgid())
        os.chmod(temporary, 0o600)
        os.replace(temporary, ready_target)
    finally:
        temporary.unlink(missing_ok=True)
    _secure_file(ready_target, expected_uid=expected_uid)
    verify_runtime(prefix=prefix, expected_uid=expected_uid, require_ready=True)
    return {"status": "installed", **sentinel, "runtime_ready": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--config-source", type=Path)
    parser.add_argument("--github-app-private-key-source", type=Path)
    parser.add_argument("--allocation-signer-key-source", type=Path)
    parser.add_argument("--acknowledge-install-root-only-worker-secrets", action="store_true")
    parser.add_argument("--acknowledge-local-smoke-has-no-github-proof", action="store_true")
    args = parser.parse_args(argv)
    if args.apply and args.verify:
        parser.error("--apply and --verify are mutually exclusive")
    if args.verify:
        try:
            print(json.dumps(verify_runtime(), sort_keys=True, separators=(",", ":")))
            return 0
        except (InstallError, OSError, subprocess.SubprocessError) as exc:
            print(f"outbound worker runtime verification blocked: {exc}", file=sys.stderr)
            return 2
    plan = {"mode": "plan", "apply_requested": args.apply, "runtime_ready": False, "external_calls": False, "dispatch": False}
    print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
    if not args.apply:
        return 0
    try:
        if os.geteuid() != 0:
            raise InstallError("--apply must run as root")
        if not (args.acknowledge_install_root_only_worker_secrets and args.acknowledge_local_smoke_has_no_github_proof):
            raise InstallError("--apply requires both explicit acknowledgements")
        if not all((args.config_source, args.github_app_private_key_source, args.allocation_signer_key_source)):
            raise InstallError("--apply requires config and both private-key sources")
        result = install_runtime(args.config_source, args.github_app_private_key_source, args.allocation_signer_key_source)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        try:
            _physical(Path("/"), READY_TARGET).unlink(missing_ok=True)
        except OSError:
            pass
        print(f"outbound worker runtime install blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
