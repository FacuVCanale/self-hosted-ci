#!/usr/bin/env python3
"""Build deterministic public tar inputs for the WSL JIT live contract."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_automation.crypto import parse_ijson
from github_automation.runner_boundary import verify_runner_boundary_attestation


class BundleError(ValueError):
    pass


FINGERPRINT = re.compile(r"[0-9a-f]{64}")
PRIVATE_KEY_NAMES = re.compile(r"(?:^|[-_.])private(?:[-_.]|$)|\.key$", re.I)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
)
RESERVED_SIGNED_NAMES = {
    "contract/runner-boundary-v2.json",
    "contract/reviewer-public-key.pem",
    "contract/reviewer-key.sha256",
}


def _safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise BundleError(f"unsafe archive path: {name!r}")
    return path


def _assert_public(name: str, data: bytes) -> None:
    if PRIVATE_KEY_NAMES.search(PurePosixPath(name).name):
        raise BundleError(f"private-key-like input is forbidden: {name}")
    if any(marker in data for marker in PRIVATE_KEY_MARKERS):
        raise BundleError(f"private key material is forbidden: {name}")


def _entry(name: str, data: bytes | None) -> tuple[str, bytes | None]:
    normalized = _safe_relative(name).as_posix()
    if data is not None:
        _assert_public(normalized, data)
    return normalized, data


def _write_tar(output: Path, entries: list[tuple[str, bytes | None]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(entries, key=lambda item: (item[0].count("/"), item[0]))
    seen: set[str] = set()
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as raw, tarfile.open(
            fileobj=raw, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            for name, data in ordered:
                if name in seen:
                    raise BundleError(f"duplicate archive path: {name}")
                seen.add(name)
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                if data is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.mode = 0o644
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _directory_entries(contract_dir: Path) -> list[tuple[str, bytes | None]]:
    if contract_dir.is_symlink():
        raise BundleError("contract source symlink is forbidden")
    root = contract_dir.resolve(strict=True)
    if not root.is_dir():
        raise BundleError("contract source must be a real directory")
    template = root / "runner-boundary-template-v2.json"
    if not template.is_file() or template.is_symlink():
        raise BundleError("runner-boundary-template-v2.json is required")
    entries: list[tuple[str, bytes | None]] = [("contract", None)]
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs.sort()
        files.sort()
        for item in dirs:
            source = current_path / item
            mode = source.lstat().st_mode
            if not stat.S_ISDIR(mode) or source.is_symlink():
                raise BundleError(f"non-directory or symlink is forbidden: {source}")
            relative = source.relative_to(root).as_posix()
            entries.append(_entry(f"contract/{relative}", None))
        for item in files:
            source = current_path / item
            mode = source.lstat().st_mode
            if not stat.S_ISREG(mode) or source.is_symlink():
                raise BundleError(f"non-regular file is forbidden: {source}")
            relative = source.relative_to(root).as_posix()
            entries.append(_entry(f"contract/{relative}", source.read_bytes()))
    return entries


def _unsigned_entries(source: Path) -> list[tuple[str, bytes | None]]:
    entries: list[tuple[str, bytes | None]] = []
    seen: set[str] = set()
    with tarfile.open(source, "r:") as archive:
        for member in archive.getmembers():
            name = _safe_relative(member.name).as_posix().rstrip("/")
            if name in seen:
                raise BundleError(f"duplicate archive path: {name}")
            seen.add(name)
            if not (name == "contract" or name.startswith("contract/")):
                raise BundleError("unsigned archive must contain only contract/")
            if member.issym() or member.islnk() or member.isdev():
                raise BundleError(f"links and devices are forbidden: {name}")
            if member.mode & 0o7022:
                raise BundleError(f"unsafe input mode: {name}")
            if member.isdir():
                entries.append(_entry(name, None))
            elif member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BundleError(f"could not read archive member: {name}")
                entries.append(_entry(name, extracted.read()))
            else:
                raise BundleError(f"unsupported archive member: {name}")
    names = {name for name, _ in entries}
    if "contract" not in names or "contract/runner-boundary-template-v2.json" not in names:
        raise BundleError("unsigned archive layout is incomplete")
    if RESERVED_SIGNED_NAMES & names:
        raise BundleError("unsigned archive already contains signed-bundle files")
    return entries


def _public_key(
    path: Path, fingerprint: str
) -> tuple[bytes, ed25519.Ed25519PublicKey]:
    if FINGERPRINT.fullmatch(fingerprint) is None:
        raise BundleError("reviewer fingerprint must be 64 lowercase hex characters")
    data = path.read_bytes()
    _assert_public(path.name, data)
    loaded = serialization.load_pem_public_key(data)
    if not isinstance(loaded, ed25519.Ed25519PublicKey):
        raise BundleError("reviewer public key must be Ed25519")
    der = loaded.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if hashlib.sha256(der).hexdigest() != fingerprint:
        raise BundleError("reviewer public key fingerprint mismatch")
    return data, loaded


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source")
    source.add_argument("--contract-dir", required=True, type=Path)
    source.add_argument("--output", required=True, type=Path)
    signed = commands.add_parser("signed")
    signed.add_argument("--unsigned-tar", required=True, type=Path)
    signed.add_argument("--signed-boundary", required=True, type=Path)
    signed.add_argument("--reviewer-public-key", required=True, type=Path)
    signed.add_argument("--reviewer-key-fingerprint", required=True)
    signed.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "source":
            if args.output.resolve(strict=False) == args.contract_dir.resolve(strict=True):
                raise BundleError("output must differ from the contract source")
            entries = _directory_entries(args.contract_dir)
        else:
            entries = _unsigned_entries(args.unsigned_tar)
            output = args.output.resolve(strict=False)
            inputs = (
                args.unsigned_tar.resolve(strict=True),
                args.signed_boundary.resolve(strict=True),
                args.reviewer_public_key.resolve(strict=True),
            )
            if output in inputs:
                raise BundleError("output must differ from every signed-bundle input")
            boundary = args.signed_boundary.read_bytes()
            _assert_public(args.signed_boundary.name, boundary)
            boundary_value = parse_ijson(boundary)
            if not isinstance(boundary_value, dict):
                raise BundleError("signed boundary must be a JSON object")
            public_key, loaded_public_key = _public_key(
                args.reviewer_public_key, args.reviewer_key_fingerprint
            )
            verify_runner_boundary_attestation(
                boundary_value,
                loaded_public_key,
                pinned_fingerprint=args.reviewer_key_fingerprint,
            )
            entries.extend(
                (
                    ("contract/runner-boundary-v2.json", boundary),
                    ("contract/reviewer-public-key.pem", public_key),
                    (
                        "contract/reviewer-key.sha256",
                        (args.reviewer_key_fingerprint + "\n").encode("ascii"),
                    ),
                )
            )
        _write_tar(args.output, entries)
    except (BundleError, OSError, tarfile.TarError, ValueError) as exc:
        print(f"live contract tar build failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
