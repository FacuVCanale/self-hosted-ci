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

from github_automation.crypto import canonicalize_jcs, parse_ijson
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
# archive path, payload (None for a directory), deterministic output mode,
# observed input mode. Keeping the two policies separate lets the transport use
# root-private 0700/0600 controls without weakening exact signed evidence modes.
Entry = tuple[str, bytes | None, int, int]


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


def _output_mode(name: str, data: bytes | None) -> int:
    if data is None:
        return 0o755
    if name.startswith(("contract/evidence/", "contract/live/")):
        return 0o640
    return 0o644


def _entry(name: str, data: bytes | None, input_mode: int) -> Entry:
    normalized = _safe_relative(name).as_posix()
    if input_mode < 0 or input_mode > 0o7777 or input_mode & 0o7022:
        raise BundleError(f"unsafe input mode: {normalized}")
    if data is not None:
        _assert_public(normalized, data)
    return normalized, data, _output_mode(normalized, data), input_mode


def _write_tar(output: Path, entries: list[Entry]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(entries, key=lambda item: (item[0].count("/"), item[0]))
    seen: set[str] = set()
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as raw, tarfile.open(
            fileobj=raw, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            for name, data, mode, _input_mode in ordered:
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
                    info.mode = mode
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.mode = mode
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


def _directory_entries(contract_dir: Path) -> list[Entry]:
    if contract_dir.is_symlink():
        raise BundleError("contract source symlink is forbidden")
    root = contract_dir.resolve(strict=True)
    if not root.is_dir():
        raise BundleError("contract source must be a real directory")
    template = root / "runner-boundary-template-v2.json"
    if not template.is_file() or template.is_symlink():
        raise BundleError("runner-boundary-template-v2.json is required")
    entries: list[Entry] = [_entry("contract", None, stat.S_IMODE(root.stat().st_mode))]
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
            entries.append(
                _entry(f"contract/{relative}", None, stat.S_IMODE(mode))
            )
        for item in files:
            source = current_path / item
            mode = source.lstat().st_mode
            if not stat.S_ISREG(mode) or source.is_symlink():
                raise BundleError(f"non-regular file is forbidden: {source}")
            relative = source.relative_to(root).as_posix()
            entries.append(
                _entry(
                    f"contract/{relative}",
                    source.read_bytes(),
                    stat.S_IMODE(mode),
                )
            )
    return entries


def _unsigned_entries(source: Path) -> list[Entry]:
    entries: list[Entry] = []
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
            if member.uid != 0 or member.gid != 0:
                raise BundleError(f"unsigned archive member must be root-owned: {name}")
            if member.isdir():
                entries.append(_entry(name, None, member.mode))
            elif member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BundleError(f"could not read archive member: {name}")
                entries.append(_entry(name, extracted.read(), member.mode))
            else:
                raise BundleError(f"unsupported archive member: {name}")
    names = {name for name, _, _, _ in entries}
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


def _validate_signed_measurements(entries: list[Entry], boundary: dict) -> None:
    by_name = {
        name: (data, output_mode, input_mode)
        for name, data, output_mode, input_mode in entries
    }
    artifacts = boundary.get("measurements", {}).get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        raise BundleError("signed boundary has no measurement artifacts")
    seen: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise BundleError("signed measurement record is invalid")
        ref = record.get("ref")
        if not isinstance(ref, str) or ref in seen:
            raise BundleError("signed measurement refs are invalid or duplicated")
        seen.add(ref)
        entry = by_name.get(f"contract/{ref}")
        if entry is None or entry[0] is None:
            raise BundleError(f"signed measurement source is absent: {ref}")
        data, output_mode, input_mode = entry
        mode_text = record.get("mode")
        if (
            record.get("uid") != 0
            or record.get("gid") != 0
            or not isinstance(mode_text, str)
            or len(mode_text) != 4
            or any(character not in "01234567" for character in mode_text)
        ):
            raise BundleError(f"signed measurement metadata is invalid: {ref}")
        recorded_mode = int(mode_text, 8)
        if recorded_mode & 0o7137:
            raise BundleError(f"signed evidence mode is not installable: {ref}")
        if recorded_mode != 0o640 or output_mode != recorded_mode:
            raise BundleError(f"signed evidence mode must be exactly 0640: {ref}")
        if (
            input_mode != recorded_mode
            or record.get("size") != len(data)
            or record.get("sha256") != hashlib.sha256(data).hexdigest()
        ):
            raise BundleError(f"signed measurement differs from archive member: {ref}")


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
            if boundary != canonicalize_jcs(boundary_value) + b"\n":
                raise BundleError("signed boundary must be canonical JCS plus newline")
            public_key, loaded_public_key = _public_key(
                args.reviewer_public_key, args.reviewer_key_fingerprint
            )
            verify_runner_boundary_attestation(
                boundary_value,
                loaded_public_key,
                pinned_fingerprint=args.reviewer_key_fingerprint,
            )
            _validate_signed_measurements(entries, boundary_value)
            entries.extend(
                (
                    _entry("contract/runner-boundary-v2.json", boundary, 0o644),
                    _entry("contract/reviewer-public-key.pem", public_key, 0o644),
                    _entry(
                        "contract/reviewer-key.sha256",
                        (args.reviewer_key_fingerprint + "\n").encode("ascii"),
                        0o644,
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
