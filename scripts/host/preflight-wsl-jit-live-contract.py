#!/usr/bin/env python3
"""Reproduce every signed live-contract install guard without host mutation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class PreflightError(ValueError):
    pass


EXPECTED_DISTRO = "Ubuntu-24.04-CI"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REQUIRED = {
    "contract/runner-boundary-template-v2.json",
    "contract/runner-boundary-v2.json",
    "contract/reviewer-public-key.pem",
    "contract/reviewer-key.sha256",
}
OPTIONAL_CANONICAL_CONTROL = "contract/runner-boundary-measured-v2.json"
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_EXTRACTED_BYTES = 32 * 1024 * 1024


def _package_modules(package_root: Path):
    if package_root.is_symlink():
        raise PreflightError("package root must be a real directory")
    package_root = package_root.resolve(strict=True)
    if not package_root.is_dir():
        raise PreflightError("package root must be a real directory")
    automation = package_root / "github_automation"
    if automation.is_symlink() or not automation.is_dir():
        raise PreflightError("package root lacks github_automation")
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from github_automation.crypto import canonicalize_jcs, parse_ijson, spki_fingerprint
    from github_automation.runner_boundary import verify_runner_boundary_attestation

    installer_path = package_root / "scripts/host/install-wsl-jit-evidence.py"
    if installer_path.is_symlink() or not installer_path.is_file():
        raise PreflightError("package root lacks the evidence installer")
    spec = importlib.util.spec_from_file_location(
        "self_hosted_ci_evidence_installer", installer_path
    )
    if spec is None or spec.loader is None:
        raise PreflightError("could not load the evidence installer")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    return (
        package_root,
        canonicalize_jcs,
        parse_ijson,
        spki_fingerprint,
        verify_runner_boundary_attestation,
        installer,
    )


def _regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise PreflightError(f"{description} must be a regular file")


def _archive_name(name: str) -> str:
    path = PurePosixPath(name)
    normalized = path.as_posix().rstrip("/")
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or "" in path.parts
        or normalized == "."
    ):
        raise PreflightError(f"unsafe archive path: {name!r}")
    return normalized


def inspect_archive(bundle_bytes: bytes) -> list[tarfile.TarInfo]:
    """Validate every archive entry and return safe regular/dir members."""

    members: list[tarfile.TarInfo] = []
    seen: set[str] = set()
    extracted_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            if len(members) >= MAX_ARCHIVE_MEMBERS:
                raise PreflightError("archive contains too many members")
            name = _archive_name(member.name)
            if name in seen:
                raise PreflightError(f"duplicate archive path: {name}")
            seen.add(name)
            if name != "contract" and not name.startswith("contract/"):
                raise PreflightError("bundle must contain only contract/")
            if member.uid != 0 or member.gid != 0:
                raise PreflightError(f"archive member is not root-owned: {name}")
            if member.isdir():
                expected_mode = 0o755
            elif member.isfile():
                if member.sparse is not None or any(
                    key.startswith("GNU.sparse.") for key in member.pax_headers
                ):
                    raise PreflightError(f"sparse archive member is forbidden: {name}")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise PreflightError(f"archive member is too large: {name}")
                extracted_bytes += member.size
                if extracted_bytes > MAX_EXTRACTED_BYTES:
                    raise PreflightError("archive extracted size exceeds the limit")
                expected_mode = (
                    0o640
                    if name.startswith(("contract/evidence/", "contract/live/"))
                    else 0o644
                )
            else:
                raise PreflightError(f"unsupported archive member type: {name}")
            if stat.S_IMODE(member.mode) != expected_mode:
                raise PreflightError(
                    f"archive member mode is not {expected_mode:04o}: {name}"
                )
            member.name = name
            members.append(member)
    if "contract" not in seen or not REQUIRED.issubset(seen):
        raise PreflightError("live contract bundle layout is incomplete")
    return members


def extract_archive(
    bundle_bytes: bytes, members: list[tarfile.TarInfo], target: Path
) -> None:
    """Extract validated regular files and directories without tar path handling."""

    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:") as archive:
        by_name = {_archive_name(item.name): item for item in archive.getmembers()}
        for member in sorted(
            (item for item in members if item.isdir()),
            key=lambda item: (item.name.count("/"), item.name),
        ):
            destination = target.joinpath(*PurePosixPath(member.name).parts)
            destination.mkdir(mode=0o755)
            os.chown(destination, 0, 0)
            os.chmod(destination, 0o755)
        for member in sorted(
            (item for item in members if item.isfile()), key=lambda item: item.name
        ):
            destination = target.joinpath(*PurePosixPath(member.name).parts)
            if not destination.parent.is_dir() or destination.parent.is_symlink():
                raise PreflightError(f"archive member parent is absent: {member.name}")
            source = archive.extractfile(by_name[member.name])
            if source is None:
                raise PreflightError(f"archive member is unreadable: {member.name}")
            with destination.open("xb") as output:
                shutil.copyfileobj(source, output)
            os.chown(destination, 0, 0)
            os.chmod(destination, stat.S_IMODE(member.mode))


def _required_archive_names(contract: Path, records: dict[str, dict]) -> set[str]:
    """Return the exact signed/control file and parent-directory closure."""

    files = set(REQUIRED)
    measured_control = contract / PurePosixPath(OPTIONAL_CANONICAL_CONTROL).name
    if measured_control.exists() or measured_control.is_symlink():
        _regular_file(measured_control, "measured boundary control")
        files.add(OPTIONAL_CANONICAL_CONTROL)
    for ref in records:
        files.add(f"contract/{_archive_name(ref)}")

    live_manifest_ref = "live/live-artifacts-v1.json"
    if live_manifest_ref in records:
        live_manifest_path = contract.joinpath(*PurePosixPath(live_manifest_ref).parts)
        manifest = json.loads(live_manifest_path.read_bytes())
        artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
        if not isinstance(artifacts, list):
            raise PreflightError("live artifact manifest is invalid")
        source_refs: set[str] = set()
        for artifact in artifacts:
            source_ref = artifact.get("source_ref") if isinstance(artifact, dict) else None
            if source_ref is None:
                continue
            if not isinstance(source_ref, str) or source_ref in source_refs:
                raise PreflightError("live artifact source refs are invalid or duplicated")
            source_refs.add(source_ref)
            files.add(f"contract/{_archive_name(source_ref)}")

    names = set(files)
    for name in files:
        path = PurePosixPath(name)
        for parent in path.parents:
            if parent.as_posix() == ".":
                break
            names.add(parent.as_posix())
    return names


def validate_exact_archive_layout(
    members: list[tarfile.TarInfo], contract: Path, records: dict[str, dict]
) -> None:
    actual = {member.name for member in members}
    expected = _required_archive_names(contract, records)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise PreflightError(
            "archive does not match the exact signed/control closure: "
            f"unexpected={unexpected[:5]!r} missing={missing[:5]!r}"
        )


def _run(package_root: Path, arguments: list[str]) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(package_root)
    result = subprocess.run(
        arguments,
        cwd=package_root,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise PreflightError(f"product guard failed: {detail}")


def validated_output_destination(path: Path) -> Path:
    """Return an absent output directly below a private root-owned directory."""

    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise PreflightError("validated contract destination must be absolute and absent")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PreflightError("validated contract parent must be a real directory")
    parent_stat = os.stat(parent, follow_symlinks=False)
    if (
        parent_stat.st_uid != 0
        or parent_stat.st_gid != 0
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise PreflightError("validated contract parent must be private root:root")
    resolved_parent = parent.resolve(strict=True)
    if path.resolve(strict=False).parent != resolved_parent:
        raise PreflightError("validated contract destination escapes its parent")
    return resolved_parent / path.name


def preflight(
    bundle: Path,
    *,
    expected_sha256: str,
    expected_bytes: int,
    pinned_fingerprint: str,
    package_root: Path,
    temporary_parent: Path | None = None,
    validated_contract_root: Path | None = None,
    enforce_identity: bool = True,
) -> dict:
    if enforce_identity and (
        os.geteuid() != 0 or os.environ.get("WSL_DISTRO_NAME") != EXPECTED_DISTRO
    ):
        raise PreflightError(
            f"preflight must run as root in the exact {EXPECTED_DISTRO} distro"
        )
    if DIGEST.fullmatch(expected_sha256) is None or expected_bytes <= 0:
        raise PreflightError("expected bundle hash/size are not canonical")
    if DIGEST.fullmatch(pinned_fingerprint) is None:
        raise PreflightError("pinned fingerprint is not lowercase SHA-256")
    output_destination = (
        validated_output_destination(validated_contract_root)
        if validated_contract_root is not None
        else None
    )
    _regular_file(bundle, "bundle")
    bundle_details = os.stat(bundle, follow_symlinks=False)
    if bundle_details.st_size <= 0 or bundle_details.st_size > MAX_BUNDLE_BYTES:
        raise PreflightError("bundle size is outside the preflight limit")
    if enforce_identity and (
        bundle_details.st_uid != 0
        or bundle_details.st_gid != 0
        or stat.S_IMODE(bundle_details.st_mode) != 0o600
    ):
        raise PreflightError("bundle must be an exact root:root 0600 regular file")
    bundle_bytes = bundle.read_bytes()
    actual_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    if actual_sha256 != expected_sha256 or len(bundle_bytes) != expected_bytes:
        raise PreflightError("bundle differs from the exact external hash/size")

    (
        package_root,
        canonicalize_jcs,
        parse_ijson,
        spki_fingerprint,
        verify_attestation,
        evidence_installer,
    ) = _package_modules(package_root)
    members = inspect_archive(bundle_bytes)

    parent = temporary_parent
    if parent is not None:
        if parent.is_symlink() or not parent.is_dir():
            raise PreflightError("temporary parent must be a real directory")
    with tempfile.TemporaryDirectory(
        prefix="self-hosted-ci-live-contract-preflight.", dir=parent
    ) as temporary:
        extracted = Path(temporary) / "bundle"
        extract_archive(bundle_bytes, members, extracted)
        contract = extracted / "contract"
        boundary_path = contract / "runner-boundary-v2.json"
        public_key_path = contract / "reviewer-public-key.pem"
        fingerprint_path = contract / "reviewer-key.sha256"
        for path in (
            contract / "runner-boundary-template-v2.json",
            boundary_path,
            public_key_path,
            fingerprint_path,
        ):
            _regular_file(path, f"required member {path.name}")

        if fingerprint_path.read_bytes() != (pinned_fingerprint + "\n").encode("ascii"):
            raise PreflightError("embedded reviewer fingerprint differs from external pin")
        loaded_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(loaded_key, ed25519.Ed25519PublicKey):
            raise PreflightError("reviewer public key must be Ed25519")
        if spki_fingerprint(loaded_key) != pinned_fingerprint:
            raise PreflightError("reviewer SPKI fingerprint differs from external pin")

        signed_bytes = boundary_path.read_bytes()
        signed = parse_ijson(signed_bytes)
        if not isinstance(signed, dict):
            raise PreflightError("signed boundary must be a JSON object")
        if signed_bytes != canonicalize_jcs(signed) + b"\n":
            raise PreflightError("signed boundary is not canonical JCS plus newline")
        verify_attestation(
            signed, loaded_key, pinned_fingerprint=pinned_fingerprint
        )
        _, records = evidence_installer.validate(boundary_path, contract)
        validate_exact_archive_layout(members, contract, records)

        measured_control = contract / PurePosixPath(OPTIONAL_CANONICAL_CONTROL).name
        if measured_control.exists():
            measured_value = parse_ijson(measured_control.read_bytes())
            signed_payload = {
                key: value for key, value in signed.items() if key != "attestation"
            }
            if canonicalize_jcs(measured_value) != canonicalize_jcs(signed_payload):
                raise PreflightError(
                    "included measured boundary differs from signed content"
                )

        staged = Path(temporary) / "staged.json"
        measured = Path(temporary) / "measured.json"
        _run(
            package_root,
            [
                sys.executable,
                str(package_root / "scripts/host/stage-wsl-jit-live-contract.py"),
                "--input-boundary",
                str(contract / "runner-boundary-template-v2.json"),
                "--output-boundary",
                str(staged),
                "--measurement-root",
                str(contract),
            ],
        )
        _run(
            package_root,
            [
                sys.executable,
                str(package_root / "scripts/host/collect-wsl-jit-measurements.py"),
                "--input",
                str(staged),
                "--output",
                str(measured),
                "--measurement-root",
                str(contract),
            ],
        )
        regenerated = parse_ijson(measured.read_bytes())
        signed_payload = {key: value for key, value in signed.items() if key != "attestation"}
        if canonicalize_jcs(regenerated) != canonicalize_jcs(signed_payload):
            raise PreflightError("regenerated live contract differs from signed content")
        evidence_installer.validate(boundary_path, contract)
        _run(
            package_root,
            [
                sys.executable,
                str(package_root / "scripts/host/verify-wsl-jit-readiness.py"),
                "--evidence",
                str(boundary_path),
                "--measurement-root",
                str(contract),
                "--reviewer-public-key",
                str(public_key_path),
                "--pinned-fingerprint",
                pinned_fingerprint,
            ],
        )

        if output_destination is not None:
            # Recheck immediately before the atomic publication. A failed
            # preflight never creates the requested output.
            output_destination = validated_output_destination(output_destination)
            os.replace(contract, output_destination)

    result = {
        "status": "verified",
        "host_mutated": False,
        "bundle_sha256": actual_sha256,
        "bundle_bytes": len(bundle_bytes),
        "reviewer_fingerprint": pinned_fingerprint,
        "measurement_artifacts": len(records),
        "guards": [
            "external-hash-size",
            "archive-layout-types-owner-modes",
            "archive-exact-signed-closure-and-size-limits",
            "ed25519-spki-fingerprint",
            "boundary-canonical-jcs",
            "boundary-signature",
            "evidence-installability",
            "package-regeneration-equality",
            "runner-readiness",
        ],
    }
    if output_destination is not None:
        result["validated_contract_root"] = str(output_destination)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-bytes", required=True, type=int)
    parser.add_argument("--pinned-fingerprint", required=True)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--temporary-parent", type=Path, default=Path("/run"))
    parser.add_argument("--validated-contract-root", type=Path)
    args = parser.parse_args(argv)
    try:
        result = preflight(
            args.bundle,
            expected_sha256=args.expected_sha256,
            expected_bytes=args.expected_bytes,
            pinned_fingerprint=args.pinned_fingerprint,
            package_root=args.package_root,
            temporary_parent=args.temporary_parent,
            validated_contract_root=args.validated_contract_root,
        )
    except (OSError, PreflightError, TypeError, ValueError, tarfile.TarError) as exc:
        print(f"live contract preflight blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
