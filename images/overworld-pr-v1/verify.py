#!/usr/bin/env python3
"""Fail closed on the immutable Overworld image marker and toolchain."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess


MARKER = Path("/etc/self-hosted-ci/repository-profile-image-v1.json")


def output(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def verify_runner_executable(path: Path) -> None:
    if Path(path.resolve()).is_relative_to("/root"):
        raise SystemExit("Waterfall interpreter resolves through a root-private path")
    if subprocess.run(
        ["runuser", "-u", "runner", "--", "test", "-x", str(path)],
        check=False,
    ).returncode:
        raise SystemExit("Waterfall interpreter is not executable by runner")


def verify_frontend_eslint_link(frontend_modules: Path) -> None:
    if frontend_modules.is_symlink() or not frontend_modules.is_dir():
        raise SystemExit("frontend dependency root is unsafe")
    canonical_root = frontend_modules.resolve(strict=True)
    link = frontend_modules / ".bin/eslint"
    if not link.is_symlink():
        raise SystemExit("frontend eslint launcher is not a symlink")
    raw_target = Path(os.readlink(link))
    if raw_target.is_absolute():
        raise SystemExit("frontend eslint launcher is absolute")
    try:
        resolved_target = (link.parent / raw_target).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SystemExit("frontend eslint launcher is broken") from exc
    expected_target = canonical_root / "eslint/bin/eslint.js"
    if (
        not resolved_target.is_relative_to(canonical_root)
        or resolved_target != expected_target
        or not resolved_target.is_file()
    ):
        raise SystemExit("frontend eslint launcher target is not exact and confined")
    package = canonical_root / "eslint/package.json"
    if (
        package.is_symlink()
        or not package.is_file()
        or package.resolve(strict=True).parent != canonical_root / "eslint"
    ):
        raise SystemExit("frontend eslint package metadata is absent or unsafe")
    try:
        package_metadata = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("frontend eslint package metadata is invalid") from exc
    if package_metadata.get("name") != "eslint" or not isinstance(
        package_metadata.get("version"), str
    ):
        raise SystemExit("frontend eslint package identity drifted")


def main() -> int:
    runner_uid = int(output("id", "-u", "runner"))
    runner_groups = set(output("id", "-nG", "runner").split())
    if runner_uid < 1000 or runner_groups != {"runner"}:
        raise SystemExit("runner privilege boundary drifted")
    sudoers = subprocess.run(
        ["grep", "-R", "-E", "(^|[[:space:],:])runner([[:space:],:]|$)", "/etc/sudoers", "/etc/sudoers.d"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if sudoers.returncode == 0:
        raise SystemExit("runner has explicit sudoers authorization")
    finalizer = Path("/usr/local/sbin/self-hosted-ci-finalize-runner")
    if not finalizer.is_file() or finalizer.stat().st_uid != 0 or (finalizer.stat().st_mode & 0o777) != 0o700:
        raise SystemExit("runner finalizer ownership or mode drifted")
    marker = json.loads(MARKER.read_text(encoding="utf-8"))
    if set(marker) != {
        "repository_profile_image_marker_version", "repository", "profile_id",
        "profile_digest", "image_marker", "runner_memory_bytes", "toolchain",
        "dependency_snapshots",
    }:
        raise SystemExit("image marker shape drifted")
    expected_toolchain = {
        "bun": "1.4.0", "garm": "0.2.1", "minio": "RELEASE.2025-07-23T15-54-02Z",
        "playwright": "1.59.1", "postgresql_backend": "16", "postgis_backend": "3.4",
        "postgresql_e2e": "17", "postgis_e2e": "3.5", "python": "3.12", "uv": "0.8.22",
        "waterfall_revision": "6df90210830b2ebe36eda6b96d91237914d000e4",
    }
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
    if (
        marker["repository_profile_image_marker_version"] != 1
        or marker["profile_id"] != "overworld-ci-v1"
        or marker["repository"] != "alethia-earth/Overworld"
        or marker["image_marker"] != "overworld-ci-jit-v1"
        or marker["runner_memory_bytes"] != 4294967296
        or marker["toolchain"] != expected_toolchain
        or marker["dependency_snapshots"] != expected_snapshots
        or not re.fullmatch(r"[0-9a-f]{64}", marker["profile_digest"])
    ):
        raise SystemExit("image marker identity drifted")
    inventory_path = Path("/usr/share/doc/self-hosted-ci/overworld-pr-v1-sbom.json")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory.get("repository_profile_digest") != marker["profile_digest"]:
        raise SystemExit("image inventory profile digest drifted")
    checks = {
        "bun": ("bun", "--version", "1.4.0"),
        "uv": ("uv", "--version", "0.8.22"),
        "pyright": ("pyright", "--version", "1.1.408"),
        "playwright": ("playwright", "--version", "1.59.1"),
    }
    for name, (*command, version) in checks.items():
        if version not in output(*command):
            raise SystemExit(f"{name} version drifted")
    if not list(Path("/opt/ms-playwright").glob("chromium-1217*")):
        raise SystemExit("pinned Playwright Chromium is absent")
    dependencies = Path("/opt/self-hosted-ci/overworld-deps")
    for required in (
        dependencies / "backend-node_modules",
        dependencies / "frontend-node_modules",
        dependencies / "bun-cache",
        dependencies / "waterfall/.venv/bin/python",
        dependencies / "waterfall/.venv/bin/pyright",
        dependencies / "frontend-node_modules/next/dist/server/dev/browser-logs/file-logger.js",
        Path("/opt/self-hosted-ci/browsers/chromium/chrome"),
        Path("/opt/ms-playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell"),
    ):
        if not required.exists():
            raise SystemExit(f"offline dependency is absent: {required}")
    waterfall_python = dependencies / "waterfall/.venv/bin/python"
    verify_runner_executable(waterfall_python)
    verify_frontend_eslint_link(dependencies / "frontend-node-modules")
    if (dependencies / "waterfall/.self-hosted-ci-commit").read_text(encoding="ascii").strip() != expected_toolchain["waterfall_revision"]:
        raise SystemExit("Waterfall offline source revision drifted")
    if any(dependencies.rglob(".git")):
        raise SystemExit("source-control metadata persisted in offline dependencies")
    for major, postgis in (("16", "3.4"), ("17", "3.5")):
        version = output(f"/usr/lib/postgresql/{major}/bin/psql", "--version")
        if f"PostgreSQL) {major}." not in version:
            raise SystemExit(f"PostgreSQL {major} version drifted")
        control = Path(f"/usr/share/postgresql/{major}/extension/postgis.control").read_text(encoding="utf-8")
        if f"default_version = '{postgis}." not in control:
            raise SystemExit(f"PostGIS {postgis} version drifted")
        if Path(f"/etc/postgresql/{major}/main").exists():
            raise SystemExit(f"PostgreSQL {major} default cluster persisted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
