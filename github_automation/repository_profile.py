"""Fail-closed loading and execution for immutable repository CI profiles."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Mapping


PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MARKER_PATH = Path("/etc/self-hosted-ci/repository-profile-image-v1.json")
PROFILE_PATHS = {
    ("alethia-earth/Overworld", "overworld-ci-v1"): PurePosixPath(
        "repository_profiles/overworld/profile.json"
    ),
}
PROFILE_FIELDS = {
    "repository_command_profile_version",
    "profile_id",
    "repository",
    "image_marker",
    "runner_memory_bytes",
    "source_workflow_path",
    "source_workflow_sha256",
    "dependency_snapshots",
    "runner_script",
    "runner_script_sha256",
    "phases",
    "toolchain",
}
TOOLCHAIN_FIELDS = {
    "bun", "garm", "minio", "playwright", "postgresql_backend", "postgis_backend",
    "postgresql_e2e", "postgis_e2e", "python", "uv",
    "waterfall_revision",
}
MARKER_FIELDS = {
    "repository_profile_image_marker_version",
    "repository",
    "profile_id",
    "profile_digest",
    "image_marker",
    "runner_memory_bytes",
    "toolchain",
    "dependency_snapshots",
}
FORBIDDEN_SCRIPT_FRAGMENTS = (
    "docker", "/var/run/docker.sock", "sudo", "apt-get", "apt ", "npm ",
    "npx ", "bunx ", "eval ", "source ", "bash -c", "sh -c",
)


class RepositoryProfileError(ValueError):
    """One immutable profile or image binding was not exact."""


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise RepositoryProfileError("duplicate JSON key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                RepositoryProfileError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepositoryProfileError("invalid profile JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact_toolchain(value: object) -> Mapping[str, str]:
    if not isinstance(value, dict) or set(value) != TOOLCHAIN_FIELDS:
        raise RepositoryProfileError("toolchain fields are not exact")
    expected = {
        "bun": "1.4.0",
        "garm": "0.2.1",
        "minio": "RELEASE.2025-07-23T15-54-02Z",
        "playwright": "1.59.1",
        "postgresql_backend": "16",
        "postgis_backend": "3.4",
        "postgresql_e2e": "17",
        "postgis_e2e": "3.5",
        "python": "3.12",
        "uv": "0.8.22",
        "waterfall_revision": "6df90210830b2ebe36eda6b96d91237914d000e4",
    }
    if value != expected:
        raise RepositoryProfileError("toolchain values are not the pinned Overworld contract")
    return value


def load_profile(
    root: Path,
    *,
    repository: str,
    profile_id: str,
    expected_digest: str,
) -> tuple[Mapping[str, Any], Path]:
    if not REPOSITORY.fullmatch(repository) or not PROFILE_ID.fullmatch(profile_id):
        raise RepositoryProfileError("repository/profile identity is invalid")
    relative = PROFILE_PATHS.get((repository, profile_id))
    if relative is None:
        raise RepositoryProfileError("repository/profile is not allowlisted")
    if not SHA256.fullmatch(expected_digest):
        raise RepositoryProfileError("profile digest is invalid")
    profile_path = root.joinpath(*relative.parts)
    raw = profile_path.read_bytes()
    if _sha256(raw) != expected_digest:
        raise RepositoryProfileError("profile digest mismatch")
    value = _strict_json(raw)
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise RepositoryProfileError("profile fields are not exact")
    if (
        value.get("repository_command_profile_version") != 1
        or value.get("repository") != repository
        or value.get("profile_id") != profile_id
        or value.get("image_marker") != "overworld-ci-jit-v1"
        or value.get("runner_memory_bytes") != 4294967296
        or value.get("source_workflow_path") != ".github/workflows/ci.yml"
        or not SHA256.fullmatch(str(value.get("source_workflow_sha256", "")))
        or value.get("phases") != ["backend", "frontend", "e2e"]
    ):
        raise RepositoryProfileError("profile identity, image, memory, workflow or phases mismatch")
    _exact_toolchain(value.get("toolchain"))
    expected_snapshots = {
        "backend": {
            "lock_path": "backend/bun.lock",
            "lock_sha256": "b235110fe83b4b3a4eafb337efc0bb8d7424aea33a72f0338b2192892ce79fdb",
            "node_modules_path": "/opt/self-hosted-ci/overworld-deps/backend-node_modules",
        },
        "frontend": {
            "lock_path": "frontend/bun.lock",
            "lock_sha256": "6004b42bc89358fc0d83f81f8015658246139ce830e1e569279700850e5d63b3",
            "node_modules_path": "/opt/self-hosted-ci/overworld-deps/frontend-node_modules",
        },
    }
    if value.get("dependency_snapshots") != expected_snapshots:
        raise RepositoryProfileError("dependency snapshots are not the pinned lock contract")
    script_relative = PurePosixPath(str(value.get("runner_script", "")))
    if (
        script_relative.is_absolute()
        or ".." in script_relative.parts
        or script_relative.as_posix() != value.get("runner_script")
        or script_relative != PurePosixPath("repository_profiles/overworld/run-overworld-ci.sh")
    ):
        raise RepositoryProfileError("runner script path is not exact")
    script_path = root.joinpath(*script_relative.parts)
    script_raw = script_path.read_bytes()
    if _sha256(script_raw) != value.get("runner_script_sha256"):
        raise RepositoryProfileError("runner script digest mismatch")
    lowered = script_raw.decode("utf-8").lower().replace(
        "privilege_helper=/usr/bin/sudo",
        "privilege_helper=<verified-non-executable>",
    )
    if any(fragment in lowered for fragment in FORBIDDEN_SCRIPT_FRAGMENTS):
        raise RepositoryProfileError("runner script contains a forbidden execution surface")
    return value, script_path


def verify_image_marker(
    marker_path: Path,
    *,
    profile: Mapping[str, Any],
    profile_digest: str,
) -> None:
    value = _strict_json(marker_path.read_bytes())
    if not isinstance(value, dict) or set(value) != MARKER_FIELDS:
        raise RepositoryProfileError("image marker fields are not exact")
    expected = {
        "repository_profile_image_marker_version": 1,
        "repository": profile["repository"],
        "profile_id": profile["profile_id"],
        "profile_digest": profile_digest,
        "image_marker": profile["image_marker"],
        "runner_memory_bytes": profile["runner_memory_bytes"],
        "toolchain": profile["toolchain"],
        "dependency_snapshots": profile["dependency_snapshots"],
    }
    if value != expected:
        raise RepositoryProfileError("image marker does not bind the exact profile")


def verify_source_workflow(profile: Mapping[str, Any], *, base_sha: str, workspace: Path) -> None:
    if not FULL_SHA.fullmatch(base_sha):
        raise RepositoryProfileError("base SHA is invalid")
    path = profile["source_workflow_path"]
    result = subprocess.run(
        ["git", "show", f"{base_sha}:{path}"],
        cwd=workspace,
        capture_output=True,
        check=False,
    )
    if result.returncode or _sha256(result.stdout) != profile["source_workflow_sha256"]:
        raise RepositoryProfileError("base workflow differs from the reviewed profile source")


def run_from_environment(environment: Mapping[str, str] | None = None) -> int:
    env = os.environ if environment is None else environment
    try:
        repository = env.get("PROFILE_REPOSITORY", "")
        if env.get("GITHUB_REPOSITORY", "") != repository:
            raise RepositoryProfileError("GitHub repository differs from literal profile repository")
        action_root = Path(env["GITHUB_ACTION_PATH"]).resolve().parents[1]
        workspace = Path(env["GITHUB_WORKSPACE"]).resolve()
        digest = env.get("PROFILE_DIGEST", "")
        profile, script = load_profile(
            action_root,
            repository=repository,
            profile_id=env.get("PROFILE_ID", ""),
            expected_digest=digest,
        )
        if env.get("PROFILE_IMAGE_MARKER", "") != profile["image_marker"]:
            raise RepositoryProfileError("workflow image marker differs from profile")
        verify_image_marker(MARKER_PATH, profile=profile, profile_digest=digest)
        verify_source_workflow(profile, base_sha=env.get("PROFILE_BASE_SHA", ""), workspace=workspace)
        tested_merge_sha = env.get("PROFILE_TESTED_MERGE_SHA", "")
        if not FULL_SHA.fullmatch(tested_merge_sha):
            raise RepositoryProfileError("tested merge SHA is invalid")
        result = subprocess.run([str(script)], cwd=workspace, check=False)
        if result.returncode:
            raise RepositoryProfileError(f"repository profile failed with exit code {result.returncode}")
    except (KeyError, OSError, RepositoryProfileError) as exc:
        print(f"repository command profile rejected: {exc}", file=os.sys.stderr)
        return 2
    return 0
