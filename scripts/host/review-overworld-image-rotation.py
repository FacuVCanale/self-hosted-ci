#!/usr/bin/env python3
"""Review measured sources and an Overworld image receipt before signing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


class ReviewError(ValueError):
    pass


def exact_json(path: Path) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ReviewError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    if not path.is_file() or path.is_symlink():
        raise ReviewError(f"unsafe or absent input: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewError(f"invalid JSON input: {path.name}") from exc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review_sources(ceremony: Path, repository: Path, sha: str) -> int:
    live = ceremony / "measured/contract/live/source"
    boundary = exact_json(ceremony / "measured/contract/runner-boundary-measured-v2.json")
    if not isinstance(boundary, dict) or "attestation" in boundary or not live.is_dir() or live.is_symlink():
        raise ReviewError("unsafe measured contract")
    tree = subprocess.check_output(
        ["git", "-C", str(repository), "ls-tree", "-rz", "--name-only", sha]
    ).decode().split("\0")
    by_name: dict[str, list[str]] = {}
    for path in filter(None, tree):
        by_name.setdefault(PurePosixPath(path).name, []).append(path)
    files = sorted(path for path in live.rglob("*") if path.is_file() or path.is_symlink())
    ok = True
    for source in files:
        relative = source.relative_to(live)
        if source.is_symlink():
            print("UNSAFE", relative)
            ok = False
            continue
        name = re.sub(r"^\d+-", "", relative.name)
        data = source.read_bytes()
        matches = [
            candidate for candidate in by_name.get(name, [])
            if subprocess.check_output(["git", "-C", str(repository), "show", f"{sha}:{candidate}"]) == data
        ]
        if not matches:
            print("UNMAPPED", relative, f"basename_candidates={len(by_name.get(name, []))}")
            ok = False
        elif len(matches) > 1:
            print("AMBIGUOUS", relative, *matches)
            ok = False
        else:
            print("MATCH", relative, matches[0])
    if not ok:
        raise ReviewError(f"measured source disagreement files={len(files)}")
    return len(files)


def review_rotation(
    receipt_path: Path, profile_path: Path, manifest_path: Path,
    observation_path: Path, live_previous_fingerprint: str,
) -> None:
    receipt = exact_json(receipt_path)
    profile = exact_json(profile_path)
    manifest = exact_json(manifest_path)
    observation = exact_json(observation_path)
    fields = {
        "status", "project", "profile", "base_fingerprint", "manifest_sha256",
        "candidate_alias", "fingerprint",
        "builder_privileged", "builder_nesting", "credentials_persisted", "alias_moved",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields:
        raise ReviewError("build receipt fields are not exact")
    if not isinstance(profile, dict) or not isinstance(manifest, dict):
        raise ReviewError("versioned profile or manifest is not an object")
    profile_digest, manifest_digest = sha256(profile_path), sha256(manifest_path)
    image_profile = manifest.get("profile")
    expected_alias = f"{image_profile}-{profile_digest[:12]}"
    digests = (receipt.get("base_fingerprint"), receipt.get("fingerprint"), live_previous_fingerprint)
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digests):
        raise ReviewError("receipt fingerprints are invalid")
    if (
        receipt.get("status") != "built" or receipt.get("project") != "ci-jit"
        or receipt.get("profile") != image_profile
        or receipt.get("manifest_sha256") != manifest_digest or receipt.get("candidate_alias") != expected_alias
        or receipt.get("builder_privileged") is not False or receipt.get("builder_nesting") is not False
        or receipt.get("credentials_persisted") is not False or receipt.get("alias_moved") is not False
    ):
        raise ReviewError("build receipt does not match the versioned profile")
    if not isinstance(observation, dict) or set(observation) != {"alias", "fingerprint", "marker"}:
        raise ReviewError("image observation fields are not exact")
    marker = observation.get("marker")
    marker_fields = {
        "repository_profile_image_marker_version", "repository", "profile_id",
        "profile_digest", "image_marker", "runner_memory_bytes", "toolchain",
        "dependency_snapshots",
    }
    if (
        observation.get("alias") != receipt["candidate_alias"]
        or observation.get("fingerprint") != receipt["fingerprint"]
        or not isinstance(marker, dict) or set(marker) != marker_fields
        or marker.get("repository_profile_image_marker_version") != 1
        or marker.get("repository") != profile.get("repository")
        or marker.get("profile_id") != profile.get("profile_id")
        or marker.get("profile_digest") != profile_digest
        or marker.get("image_marker") != profile.get("image_marker")
        or marker.get("runner_memory_bytes") != profile.get("runner_memory_bytes")
        or marker.get("toolchain") != profile.get("toolchain")
        or marker.get("dependency_snapshots") != profile.get("dependency_snapshots")
    ):
        raise ReviewError("published image observation does not match receipt and profile")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ceremony-directory", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--image-observation", required=True, type=Path)
    parser.add_argument("--live-previous-fingerprint", required=True)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[0-9a-f]{40,64}", args.sha):
            raise ReviewError("review SHA is invalid")
        files = review_sources(args.ceremony_directory, args.repository, args.sha)
        review_rotation(
            args.receipt, args.profile, args.manifest, args.image_observation,
            args.live_previous_fingerprint,
        )
    except (ReviewError, OSError, subprocess.CalledProcessError) as exc:
        print(f"REVIEW_FAIL {exc}")
        return 1
    print(f"REVIEW_OK files={files} rotation_receipt=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
