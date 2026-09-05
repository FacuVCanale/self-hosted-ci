#!/usr/bin/env python3
"""Fail closed on the immutable Overworld image marker and toolchain."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess


MARKER = Path("/etc/self-hosted-ci/repository-profile-image-v1.json")


def output(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def main() -> int:
    marker = json.loads(MARKER.read_text(encoding="utf-8"))
    if set(marker) != {
        "repository_profile_image_marker_version", "repository", "profile_id",
        "profile_digest", "image_marker", "runner_memory_bytes", "toolchain",
    }:
        raise SystemExit("image marker shape drifted")
    expected_toolchain = {
        "bun": "1.4.0", "garm": "0.2.1", "minio": "RELEASE.2025-07-23T15-54-02Z",
        "playwright": "1.59.1", "postgresql_backend": "16", "postgis_backend": "3.4",
        "postgresql_e2e": "17", "postgis_e2e": "3.5", "python": "3.12", "uv": "0.8.22",
        "waterfall_revision": "6df90210830b2ebe36eda6b96d91237914d000e4",
    }
    if (
        marker["repository_profile_image_marker_version"] != 1
        or marker["profile_id"] != "overworld-ci-v1"
        or marker["repository"] != "alethia-earth/Overworld"
        or marker["image_marker"] != "overworld-ci-jit-v1"
        or marker["runner_memory_bytes"] != 4294967296
        or marker["toolchain"] != expected_toolchain
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
        dependencies / "uv-cache",
        dependencies / "waterfall/.venv/bin/python",
        dependencies / "waterfall/.venv/bin/pyright",
        Path("/opt/self-hosted-ci/browsers/chromium/chrome"),
    ):
        if not required.exists():
            raise SystemExit(f"offline dependency is absent: {required}")
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
