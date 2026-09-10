#!/usr/bin/env python3
"""Provision the public, credential-free Overworld CI image payload."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


ROOT = Path("/run/self-hosted-ci-profile-build")
MANIFEST = ROOT / "manifest.json"
PROFILE = ROOT / "profile.json"
BUNDLE_INPUTS = ROOT / "bundle-inputs.json"
PROFILE_ASSETS = ROOT / "profile-assets"
PROFILE_ASSET_ROOT = Path("/opt/self-hosted-ci/overworld-profile-assets")
PROFILE_ASSET_FILES = {
    "next-font-google-mocked-responses.cjs": (1071, "c137ca4b0b65cea2c2f37f202ce2d174d0db55c36755ff43540bd24f98cf67ff"),
    "fonts/FragmentMono-OFL.txt": (4405, "ef14426248ca0404eae1ae65e61802b1627b5ec33aab117fb36edf401a81636e"),
    "fonts/FragmentMono-Regular.ttf": (125368, "0fe011f425873c2e0fc73a189e394e340ad48d2b9a99a576bdeec75cee000460"),
    "fonts/Geist-OFL.txt": (4387, "1781d2806a07d91c4edf4740b88449fab7d0eadad53f7c351b94cd4d4eb8c00f"),
    "fonts/GeistMono-OFL.txt": (4387, "1781d2806a07d91c4edf4740b88449fab7d0eadad53f7c351b94cd4d4eb8c00f"),
    "fonts/GeistMono[wght].ttf": (171948, "d00e590b8eb3a59acc329b2d044fd143ae935090b7da33199ebee27cc7de8196"),
    "fonts/Geist[wght].ttf": (169056, "73894e0448cae90a92b6c2f8732b7bb9acb7b94c418bff559dad4a18e1de9659"),
    "fonts/README.md": (947, "1e8cdd235cd6596caaad2fa793795b6ea1fefe496ce5f6d823f0bf982e7cad4e"),
}


def run(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, env=env, cwd=cwd).stdout.strip()


def apt_get(*args: str, env: dict[str, str] | None = None) -> str:
    return run("apt-get", "-o", "DPkg::Lock::Timeout=300", *args, env=env)


def stop_automatic_apt() -> None:
    run(
        "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "300s",
        "systemctl", "stop", "apt-daily.timer", "apt-daily-upgrade.timer",
    )
    run(
        "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "300s",
        "systemctl", "stop",
        "apt-daily.service", "apt-daily-upgrade.service",
        "unattended-upgrades.service",
    )


def fetch(url: str, digest: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "self-hosted-ci-image-builder/1"})
    with urllib.request.urlopen(request, timeout=180) as response, target.open("wb") as output:
        shutil.copyfileobj(response, output)
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"artifact digest mismatch: {url}")


def fetch_unpinned(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "self-hosted-ci-image-builder/1"})
    with urllib.request.urlopen(request, timeout=180) as response, target.open("wb") as output:
        shutil.copyfileobj(response, output)


def verify_bundle(name: str, commit: str, digest: str) -> None:
    bundle = ROOT / f"{name}.bundle"
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"{name} bundle digest drifted")
    heads = run("git", "bundle", "list-heads", str(bundle)).splitlines()
    if not any(line.split(maxsplit=1)[0] == commit for line in heads):
        raise SystemExit(f"{name} commit is not an advertised bundle head")


def output_commit(repository: Path) -> str:
    return run("git", "-C", str(repository), "rev-parse", "HEAD")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_profile_assets() -> dict[str, dict[str, object]]:
    if PROFILE_ASSETS.is_symlink() or not PROFILE_ASSETS.is_dir():
        raise SystemExit("profile asset staging root is unsafe")
    expected = set(PROFILE_ASSET_FILES)
    observed = {
        path.relative_to(PROFILE_ASSETS).as_posix()
        for path in PROFILE_ASSETS.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if observed != expected:
        raise SystemExit("profile asset staging inventory drifted")
    if any(path.is_symlink() for path in PROFILE_ASSETS.rglob("*")):
        raise SystemExit("profile asset staging contains a symlink")
    payloads: dict[str, bytes] = {}
    for relative, (expected_size, expected_sha256) in PROFILE_ASSET_FILES.items():
        source = PROFILE_ASSETS / relative
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"profile asset is absent or unsafe: {relative}")
        payload = source.read_bytes()
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise SystemExit(f"profile asset identity drifted: {relative}")
        payloads[relative] = payload
    if PROFILE_ASSET_ROOT.exists() or PROFILE_ASSET_ROOT.is_symlink():
        raise SystemExit("profile asset destination already exists")
    PROFILE_ASSET_ROOT.mkdir(parents=True, mode=0o755)
    PROFILE_ASSET_ROOT.chmod(0o755)
    os.chown(PROFILE_ASSET_ROOT, 0, 0, follow_symlinks=False)
    fonts = PROFILE_ASSET_ROOT / "fonts"
    fonts.mkdir(mode=0o755)
    fonts.chmod(0o755)
    os.chown(fonts, 0, 0, follow_symlinks=False)
    inventory: dict[str, dict[str, object]] = {}
    for relative, (expected_size, expected_sha256) in PROFILE_ASSET_FILES.items():
        destination = PROFILE_ASSET_ROOT / relative
        destination.write_bytes(payloads[relative])
        os.chown(destination, 0, 0, follow_symlinks=False)
        destination.chmod(0o644)
        inventory[relative] = {
            "mode": "0644",
            "sha256": expected_sha256,
            "size": expected_size,
        }
    return inventory


def detach_regular_files(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(path.read_bytes())
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, path.stat().st_mode & 0o7777)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def normalize_tree_ownership(root: Path) -> None:
    def fail_on_walk_error(error: OSError) -> None:
        raise error

    if root.is_symlink() or not root.is_dir():
        raise SystemExit(f"cannot normalize unsafe dependency tree: {root}")
    os.chown(root, 0, 0, follow_symlinks=False)
    for directory, names, files in os.walk(root, followlinks=False, onerror=fail_on_walk_error):
        parent = Path(directory)
        for name in (*names, *files):
            os.chown(parent / name, 0, 0, follow_symlinks=False)


def validate_internal_dependency_symlinks(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise SystemExit(f"dependency tree root is unsafe: {root}")
    canonical_root = root.resolve(strict=True)
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        target = Path(os.readlink(path))
        if target.is_absolute():
            raise SystemExit(f"dependency tree contains an absolute symlink: {path}")
        try:
            resolved = (path.parent / target).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SystemExit(f"dependency tree contains a broken symlink: {path}") from exc
        if not resolved.is_relative_to(canonical_root):
            raise SystemExit(f"dependency tree symlink escapes its root: {path}")
        if not (resolved.is_file() or resolved.is_dir()):
            raise SystemExit(f"dependency tree symlink target is unsupported: {path}")


def copy_dependency_tree(source: Path, destination: Path) -> None:
    validate_internal_dependency_symlinks(source)
    shutil.copytree(source, destination, symlinks=True)
    validate_internal_dependency_symlinks(destination)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode & 0o7777
        if path.is_symlink():
            payload = f"link\0{relative}\0{mode:o}\0{os.readlink(path)}\n".encode()
        elif path.is_dir():
            payload = f"dir\0{relative}\0{mode:o}\n".encode()
        elif path.is_file():
            payload = f"file\0{relative}\0{mode:o}\0{sha256_file(path)}\n".encode()
        else:
            raise SystemExit(f"unsupported dependency snapshot entry: {path}")
        digest.update(payload)
    return digest.hexdigest()


def seed_backend_snapshot_for_frontend(overworld: Path, dependencies: Path) -> str:
    backend = overworld / "backend/node_modules"
    backend_snapshot = dependencies / "backend-node_modules"
    if backend.exists() or backend.is_symlink():
        raise SystemExit("backend dependency seed destination is not absent")
    expected_digest = tree_digest(backend_snapshot)
    copy_dependency_tree(backend_snapshot, backend)
    if tree_digest(backend_snapshot) != expected_digest:
        raise SystemExit("backend dependency snapshot mutated while seeding frontend")
    if tree_digest(backend) != expected_digest:
        raise SystemExit("frontend received a drifted backend dependency seed")
    return expected_digest


def remove_exact_regenerated_modules(
    overworld: Path, dependencies: Path, expected_backend_digest: str
) -> None:
    backend = overworld / "backend/node_modules"
    backend_snapshot = dependencies / "backend-node_modules"
    if tree_digest(backend_snapshot) != expected_backend_digest:
        raise SystemExit("backend dependency snapshot mutated during frontend install")
    if backend.is_symlink() or not backend.is_dir():
        raise SystemExit("expected exact regenerated backend dependency tree")
    if tree_digest(backend) != expected_backend_digest:
        raise SystemExit("regenerated backend dependency tree drifted")
    shutil.rmtree(backend)
    if backend.exists() or backend.is_symlink():
        raise SystemExit("regenerated backend dependency tree cleanup failed")
    frontend = overworld / "frontend/node_modules"
    if frontend.exists() or frontend.is_symlink():
        raise SystemExit("unexpected regenerated frontend dependency tree")


def require_profile(value: object, waterfall_commit: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "repository_command_profile_version", "profile_id", "repository", "image_marker",
        "runner_memory_bytes", "source_workflow_path", "source_workflow_sha256",
        "dependency_snapshots", "runner_script", "runner_script_sha256", "phases", "toolchain",
    }:
        raise SystemExit("repository profile shape drifted")
    expected_toolchain = {
        "bun": "1.4.0", "garm": "0.2.1", "minio": "RELEASE.2025-07-23T15-54-02Z",
        "node": "22.23.2",
        "playwright": "1.59.1", "postgresql_backend": "16", "postgis_backend": "3.4",
        "postgresql_e2e": "17", "postgis_e2e": "3.5", "python": "3.12", "uv": "0.8.22",
        "waterfall_revision": waterfall_commit,
    }
    if (
        value["repository_command_profile_version"] != 1
        or value["repository"] != "alethia-earth/Overworld"
        or value["profile_id"] != "overworld-ci-v1"
        or value["image_marker"] != "overworld-ci-jit-v1"
        or value["runner_memory_bytes"] != 4294967296
        or value["phases"] != ["backend", "frontend", "e2e"]
        or value["toolchain"] != expected_toolchain
    ):
        raise SystemExit("repository profile identity drifted")
    snapshots = value["dependency_snapshots"]
    if not isinstance(snapshots, dict) or set(snapshots) != {"backend", "frontend"}:
        raise SystemExit("repository dependency snapshot shape drifted")
    for component in ("backend", "frontend"):
        snapshot = snapshots[component]
        if not isinstance(snapshot, dict) or set(snapshot) != {
            "lock_path", "lock_sha256", "node_modules_path"
        }:
            raise SystemExit(f"{component} dependency snapshot shape drifted")
        if (
            snapshot["lock_path"] != f"{component}/bun.lock"
            or snapshot["node_modules_path"] != f"/opt/self-hosted-ci/overworld-deps/{component}-node_modules"
            or not isinstance(snapshot["lock_sha256"], str)
            or not re_full_sha256(snapshot["lock_sha256"])
        ):
            raise SystemExit(f"{component} dependency snapshot identity drifted")
    return value


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def require_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "profile", "repository", "architecture", "ubuntu_version",
        "pgdg", "artifacts", "apt_packages", "runtime_entrypoints", "marker_path", "inventory_path",
    }:
        raise SystemExit("profile manifest shape drifted")
    if value["schema_version"] != 1 or value["profile"] != "overworld-pr-v1":
        raise SystemExit("profile manifest identity drifted")
    pgdg = value["pgdg"]
    if not isinstance(pgdg, dict) or set(pgdg) != {
        "key_url", "key_fingerprint", "repository", "suite"
    }:
        raise SystemExit("PGDG repository contract drifted")
    if (
        pgdg["key_url"] != "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
        or pgdg["key_fingerprint"] != "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
        or pgdg["repository"] != "https://apt-archive.postgresql.org/pub/repos/apt"
        or pgdg["suite"] != "noble-pgdg-archive"
    ):
        raise SystemExit("PGDG repository identity drifted")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "node", "bun", "uv", "pyright", "playwright", "playwright_core", "next", "chromium",
        "chromium_headless_shell", "minio", "mc"
    }:
        raise SystemExit("profile artifact set drifted")
    for name, artifact in artifacts.items():
        if not isinstance(artifact, dict) or not str(artifact.get("url", "")).startswith("https://"):
            raise SystemExit(f"{name} source is not trusted HTTPS")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not re_full_sha256(digest):
            raise SystemExit(f"{name} digest is not lowercase SHA-256")
    if value["runtime_entrypoints"] != {
        "next_node": {
            "path": "/usr/local/bin/node",
            "sha256": "3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327",
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        }
    }:
        raise SystemExit("runtime entrypoint contract drifted")
    return value


def extract_npm(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if any(not member.name.startswith("package/") or member.issym() or member.islnk() for member in members):
            raise SystemExit("npm archive contains an unsafe member")
        for member in members:
            member.name = member.name.removeprefix("package/")
            if member.name:
                source.extract(member, destination, filter="data")


def extract_chromium(archive_path: Path, destination: Path, prefix: str, executable_name: str) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        for entry in entries:
            path = Path(entry.filename)
            mode = entry.external_attr >> 16
            if (
                path.is_absolute()
                or ".." in path.parts
                or not entry.filename.startswith(f"{prefix}/")
                or (mode & 0o170000) == 0o120000
            ):
                raise SystemExit("Chromium archive contains an unsafe member")
        archive.extractall(destination)
    chrome = destination / prefix / executable_name
    if not chrome.is_file():
        raise SystemExit("Chromium archive lacks the exact browser executable")
    for executable in (chrome, destination / prefix / "chrome_sandbox"):
        if executable.exists():
            executable.chmod(executable.stat().st_mode | 0o111)
    return chrome


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("provisioner must run as container root")
    manifest = require_manifest(json.loads(MANIFEST.read_text(encoding="utf-8")))
    bundle_inputs = json.loads(BUNDLE_INPUTS.read_text(encoding="utf-8"))
    profile_digest = hashlib.sha256(PROFILE.read_bytes()).hexdigest()
    if set(bundle_inputs) != {
        "overworld_commit", "overworld_bundle_sha256", "waterfall_commit", "waterfall_bundle_sha256"
    }:
        raise SystemExit("bundle input contract drifted")
    profile = require_profile(
        json.loads(PROFILE.read_text(encoding="utf-8")), str(bundle_inputs["waterfall_commit"])
    )
    profile_assets = install_profile_assets()
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release:
        raise SystemExit("Ubuntu 24.04 is required")
    if subprocess.run(["id", "runner"], check=False, stdout=subprocess.DEVNULL).returncode != 0:
        run("useradd", "--create-home", "--shell", "/bin/bash", "--user-group", "runner")
    run("passwd", "--lock", "runner")
    for group in run("id", "-nG", "runner").split():
        if group != "runner":
            run("gpasswd", "--delete", "runner", group)
    if run("id", "-nG", "runner") != "runner":
        raise SystemExit("runner supplementary groups could not be removed")
    finalizer = Path("/usr/local/sbin/self-hosted-ci-finalize-runner")
    finalizer.write_text(
        """#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 && $# -eq 2 && $2 == runner ]]
[[ $1 =~ ^actions\\.runner\\.[A-Za-z0-9_.-]+\\.service$ ]]
service_name=$1
runner_user=$2
unit=/etc/systemd/system/$service_name
committed=false
rollback() {
  original_rc=$?
  trap - EXIT
  [[ $committed == true ]] && exit "$original_rc"
  set +e
  systemctl stop "$service_name" >/dev/null 2>&1
  systemctl disable "$service_name" >/dev/null 2>&1
  systemctl reset-failed "$service_name" >/dev/null 2>&1
  active_state=$(systemctl show "$service_name" --property ActiveState --value 2>/dev/null)
  active_query_rc=$?
  enabled_state=$(systemctl is-enabled "$service_name" 2>/dev/null)
  enabled_rc=$?
  if [[ $active_query_rc -ne 0 || $active_state != inactive || $enabled_rc -ne 1 || $enabled_state != disabled ]]; then
    echo 'runner rollback postcondition could not be proven' >&2
    exit 125
  fi
  exit "$original_rc"
}
trap rollback EXIT
if [[ ! -f $unit || -L $unit ]]; then
  exit 1
fi
unit_stat=$(stat -c %U:%G:%a "$unit")
case "$unit_stat" in
  root:root:644|root:root:664) ;;
  *) exit 1 ;;
esac
chmod 0644 "$unit"
[[ $(stat -c %U:%G:%a "$unit") == root:root:644 ]]
grep -Fxq 'User=runner' "$unit"
! grep -Eq '^ExecStart=[+!]' "$unit"
systemctl daemon-reload
systemctl disable --now "$service_name" >/dev/null 2>&1 || true
[[ $(systemctl show "$service_name" --property User --value) == "$runner_user" ]]
[[ -z $(systemctl show "$service_name" --property SupplementaryGroups --value) ]]
[[ $(systemctl show "$service_name" --property DynamicUser --value) == no ]]
for group in $(id -nG runner); do
  [[ $group == runner ]] || gpasswd --delete runner "$group" >/dev/null
done
[[ $(id -nG runner) == runner ]]
chown root:root /usr/bin/sudo
chmod 0750 /usr/bin/sudo
runuser -u runner -- test ! -x /usr/bin/sudo
systemctl enable --now "$service_name"
systemctl is-active --quiet "$service_name"
main_pid=$(systemctl show "$service_name" --property MainPID --value)
[[ $main_pid =~ ^[1-9][0-9]*$ && $(stat -c %U "/proc/$main_pid") == "$runner_user" ]]
primary_gid=$(id -g "$runner_user")
[[ $(awk '/^Groups:/ { $1=""; sub(/^ /, ""); print }' "/proc/$main_pid/status") == "$primary_gid" ]]
committed=true
""",
        encoding="utf-8",
    )
    finalizer.chmod(0o700)
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    stop_automatic_apt()
    sources = Path("/etc/apt/sources.list.d/ubuntu.sources")
    if sources.exists():
        text = sources.read_text(encoding="utf-8")
        text = text.replace("http://archive.ubuntu.com", "https://archive.ubuntu.com")
        text = text.replace("http://security.ubuntu.com", "https://security.ubuntu.com")
        sources.write_text(text, encoding="utf-8")
        active_source_lines = [
            line.strip() for line in text.splitlines()
            if line.strip().startswith(("URIs:", "deb "))
        ]
        if not active_source_lines or any("http://" in line for line in active_source_lines):
            raise SystemExit("APT sources were not upgraded to HTTPS")
    apt_get("update", env=env)
    apt_get("install", "-y", "--no-install-recommends", "gnupg", env=env)
    pgdg = manifest["pgdg"]
    assert isinstance(pgdg, dict)
    with tempfile.TemporaryDirectory(prefix="pgdg-key-") as key_temp:
        armored = Path(key_temp) / "pgdg.asc"
        fetch_unpinned(str(pgdg["key_url"]), armored)
        fingerprint = run("gpg", "--batch", "--show-keys", "--with-colons", str(armored))
        fingerprints = [line.split(":")[9] for line in fingerprint.splitlines() if line.startswith("fpr:")]
        if fingerprints[:1] != [pgdg["key_fingerprint"]]:
            raise SystemExit("PGDG signing key fingerprint drifted")
        run("gpg", "--batch", "--dearmor", "--output", "/usr/share/keyrings/postgresql-pgdg.gpg", str(armored))
    Path("/etc/apt/sources.list.d/pgdg.list").write_text(
        f'deb [signed-by=/usr/share/keyrings/postgresql-pgdg.gpg] {pgdg["repository"]} {pgdg["suite"]} main\n',
        encoding="utf-8",
    )
    apt_get("update", env=env)
    apt_get("install", "-y", "--no-install-recommends", *manifest["apt_packages"], env=env)
    for package, prefix in (
        ("postgresql-16-postgis-3", "3.4."),
        ("postgresql-17-postgis-3", "3.5."),
    ):
        if not run("dpkg-query", "-W", "-f=${Version}", package).startswith(prefix):
            raise SystemExit(f"{package} semantic version drifted")
    for major in ("16", "17"):
        cluster = Path(f"/etc/postgresql/{major}/main")
        if cluster.exists():
            run("pg_dropcluster", "--stop", major, "main")
    run("systemctl", "disable", "postgresql.service")
    artifacts: dict[str, dict[str, str]] = manifest["artifacts"]  # type: ignore[assignment]
    with tempfile.TemporaryDirectory(prefix="overworld-image-") as temp:
        tx = Path(temp)
        downloads = tx / "downloads"
        downloads.mkdir(mode=0o700)
        downloaded: dict[str, Path] = {}
        for name, artifact in artifacts.items():
            target = downloads / name
            fetch(artifact["url"], artifact["sha256"], target)
            downloaded[name] = target

        node_contract = manifest["runtime_entrypoints"]["next_node"]
        node_path = Path(str(node_contract["path"]))
        with tarfile.open(downloaded["node"], "r:xz") as archive:
            expected_node = "node-v22.23.2-linux-x64/bin/node"
            candidates = [member for member in archive.getmembers() if member.name.endswith("/bin/node")]
            if len(candidates) != 1 or candidates[0].name != expected_node or not candidates[0].isfile():
                raise SystemExit("Node archive lacks the exact runtime executable")
            source = archive.extractfile(candidates[0])
            if source is None:
                raise SystemExit("Node runtime executable cannot be read")
            with node_path.open("wb") as output:
                shutil.copyfileobj(source, output)
        os.chown(node_path, int(node_contract["uid"]), int(node_contract["gid"]))
        node_path.chmod(int(str(node_contract["mode"]), 8))
        if hashlib.sha256(node_path.read_bytes()).hexdigest() != node_contract["sha256"]:
            raise SystemExit("Node runtime executable digest drifted")
        if run(str(node_path), "--version") != "v22.23.2":
            raise SystemExit("Node runtime version drifted")

        with zipfile.ZipFile(downloaded["bun"]) as archive:
            names = archive.namelist()
            if names != ["bun-linux-x64/", "bun-linux-x64/bun"]:
                raise SystemExit("Bun archive inventory drifted")
            archive.extractall(tx / "bun")
        shutil.copy2(tx / "bun/bun-linux-x64/bun", "/usr/local/bin/bun")
        os.chmod("/usr/local/bin/bun", 0o755)

        with tarfile.open(downloaded["uv"], "r:gz") as archive:
            safe = [m for m in archive.getmembers() if not (m.issym() or m.islnk())]
            if len(safe) != len(archive.getmembers()):
                raise SystemExit("uv archive contains links")
            archive.extractall(tx / "uv", members=safe, filter="data")
        for binary in ("uv", "uvx"):
            matches = list((tx / "uv").glob(f"*/{binary}"))
            if len(matches) != 1:
                raise SystemExit(f"uv archive lacks exact {binary} binary")
            shutil.copy2(matches[0], f"/usr/local/bin/{binary}")
            os.chmod(f"/usr/local/bin/{binary}", 0o755)

        node_modules = Path("/opt/self-hosted-ci/node_modules")
        node_modules.mkdir(parents=True, exist_ok=False)
        for package in ("pyright", "playwright", "playwright_core"):
            target_name = "playwright-core" if package == "playwright_core" else package
            extract_npm(downloaded[package], node_modules / target_name)
        next_package = Path("/var/tmp/self-hosted-ci-next-package")
        extract_npm(downloaded["next"], next_package)
        next_metadata = json.loads((next_package / "package.json").read_text(encoding="utf-8"))
        if next_metadata.get("name") != "next" or next_metadata.get("version") != "16.2.3":
            raise SystemExit("pinned Next.js package identity drifted")
        if not (next_package / "dist/server/dev/browser-logs/file-logger.js").is_file():
            raise SystemExit("pinned Next.js package is incomplete")
        Path("/usr/local/bin/pyright").write_text(
            "#!/bin/sh\nexec /usr/local/bin/bun /opt/self-hosted-ci/node_modules/pyright/index.js \"$@\"\n",
            encoding="utf-8",
        )
        Path("/usr/local/bin/playwright").write_text(
            "#!/bin/sh\nexport PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright\nexec /usr/local/bin/bun /opt/self-hosted-ci/node_modules/playwright/cli.js \"$@\"\n",
            encoding="utf-8",
        )
        os.chmod("/usr/local/bin/pyright", 0o755)
        os.chmod("/usr/local/bin/playwright", 0o755)
        for name in ("minio", "mc"):
            shutil.copy2(downloaded[name], f"/usr/local/bin/{name}")
            os.chmod(f"/usr/local/bin/{name}", 0o755)
        Path("/opt/ms-playwright").mkdir(mode=0o755)
        chromium = extract_chromium(
            downloaded["chromium"], Path("/opt/ms-playwright/chromium-1217"),
            "chrome-linux64", "chrome",
        )
        extract_chromium(
            downloaded["chromium_headless_shell"],
            Path("/opt/ms-playwright/chromium_headless_shell-1217"),
            "chrome-headless-shell-linux64", "chrome-headless-shell",
        )
        browser_contract = Path("/opt/self-hosted-ci/browsers")
        browser_contract.mkdir(parents=True, exist_ok=False)
        (browser_contract / "chromium").symlink_to(chromium.parent)
    apt_get("clean")

    dependencies = Path("/opt/self-hosted-ci/overworld-deps")
    dependencies.mkdir(parents=True, exist_ok=False)
    verify_bundle("overworld", bundle_inputs["overworld_commit"], bundle_inputs["overworld_bundle_sha256"])
    verify_bundle("waterfall", bundle_inputs["waterfall_commit"], bundle_inputs["waterfall_bundle_sha256"])
    waterfall = dependencies / "waterfall"
    run("git", "clone", "--no-checkout", str(ROOT / "waterfall.bundle"), str(waterfall))
    run("git", "-C", str(waterfall), "checkout", "--detach", bundle_inputs["waterfall_commit"])
    if output_commit(waterfall) != bundle_inputs["waterfall_commit"]:
        raise SystemExit("Waterfall checkout drifted")
    (waterfall / ".self-hosted-ci-commit").write_text(bundle_inputs["waterfall_commit"] + "\n", encoding="ascii")
    uv_cache = dependencies / "uv-cache"
    uv_python = dependencies / "uv-python"
    uv_python.mkdir(mode=0o755)
    uv_environment = {
        **os.environ,
        "UV_CACHE_DIR": str(uv_cache),
        "UV_PYTHON_INSTALL_DIR": str(uv_python),
    }
    run("uv", "sync", "--frozen", "--project", str(waterfall), env=uv_environment)
    waterfall_python = waterfall / ".venv/bin/python"
    if not waterfall_python.exists() or Path(waterfall_python.resolve()).is_relative_to("/root"):
        raise SystemExit("Waterfall interpreter is not runner-accessible")
    run("runuser", "-u", "runner", "--", "test", "-x", str(waterfall_python))
    pyright_wrapper = waterfall / ".venv/bin/pyright"
    pyright_wrapper.write_text("#!/bin/sh\nexec /usr/local/bin/pyright \"$@\"\n", encoding="utf-8")
    pyright_wrapper.chmod(0o755)
    overworld = Path("/var/tmp/overworld-source")
    run("git", "clone", "--no-checkout", str(ROOT / "overworld.bundle"), str(overworld))
    run("git", "-C", str(overworld), "checkout", "--detach", bundle_inputs["overworld_commit"])
    if output_commit(overworld) != bundle_inputs["overworld_commit"]:
        raise SystemExit("Overworld checkout drifted")
    bun_cache = dependencies / "bun-cache"
    snapshots = profile["dependency_snapshots"]
    assert isinstance(snapshots, dict)
    backend_snapshot_digest = ""
    for component in ("backend", "frontend"):
        component_root = overworld / component
        snapshot = snapshots[component]
        assert isinstance(snapshot, dict)
        lockfile = overworld / str(snapshot["lock_path"])
        if sha256_file(lockfile) != snapshot["lock_sha256"]:
            raise SystemExit(f"{component} lockfile digest drifted")
        run("bun", "install", "--frozen-lockfile", cwd=component_root, env={**os.environ, "BUN_INSTALL_CACHE_DIR": str(bun_cache)})
        if component == "frontend":
            installed_next = component_root / "node_modules/next"
            if installed_next.is_symlink() or not installed_next.is_dir():
                raise SystemExit("Bun did not install the pinned Next.js package directory")
            shutil.rmtree(installed_next)
            shutil.copytree(next_package, installed_next, symlinks=False)
            detach_regular_files(installed_next)
        source_modules = component_root / "node_modules"
        target_modules = dependencies / f"{component}-node_modules"
        if component == "backend":
            shutil.move(str(source_modules), target_modules)
            backend_snapshot_digest = seed_backend_snapshot_for_frontend(overworld, dependencies)
        else:
            copy_dependency_tree(source_modules, target_modules)
            shutil.rmtree(source_modules)
            sealed_frontend = Path("/opt/self-hosted-ci/.frontend-node-modules-sealed")
            copy_dependency_tree(target_modules, sealed_frontend)
            detach_regular_files(sealed_frontend)
            normalize_tree_ownership(sealed_frontend)
            required_next = target_modules / "next/dist/server/dev/browser-logs/file-logger.js"
            if not required_next.is_file() or required_next.resolve() != required_next:
                raise SystemExit("frontend dependency snapshot retained a staging-backed path")
            current = required_next.parent
            while current != target_modules:
                if current.is_symlink():
                    raise SystemExit("frontend dependency snapshot retained a symlink ancestor")
                current = current.parent
    shutil.rmtree(next_package)
    # Frontend's postinstall emits the shared type bridge through the exact
    # backend snapshot seed. Reject mutation of either the seed or its source.
    if not backend_snapshot_digest:
        raise SystemExit("backend dependency snapshot was not seeded for frontend")
    remove_exact_regenerated_modules(overworld, dependencies, backend_snapshot_digest)
    for path in dependencies.rglob("*"):
        if path.is_dir():
            path.chmod((path.stat().st_mode & ~0o022) | 0o055)
        elif path.is_file():
            path.chmod((path.stat().st_mode & ~0o022) | 0o044)
    smoke_root = Path("/var/tmp/overworld-offline-smoke")
    shutil.copytree(overworld, smoke_root, symlinks=True)
    for component in ("backend", "frontend"):
        component_root = smoke_root / component
        shutil.copytree(dependencies / f"{component}-node_modules", component_root / "node_modules", symlinks=True)
        cache = smoke_root / f"bun-cache-{component}"
        temporary = smoke_root / f"bun-tmp-{component}"
        cache.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
    run("chown", "-R", "runner:runner", str(smoke_root))
    for component in ("backend", "frontend"):
        cache = smoke_root / f"bun-cache-{component}"
        temporary = smoke_root / f"bun-tmp-{component}"
        modules = smoke_root / component / "node_modules"
        before = tree_digest(modules)
        if component == "backend":
            run(
                "runuser", "-u", "runner", "--", "env",
                "HOME=/home/runner", f"XDG_CACHE_HOME={cache}",
                f"BUN_INSTALL_CACHE_DIR={cache}",
                f"TMPDIR={temporary}",
                "HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
                "https_proxy=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9",
                "ALL_PROXY=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9",
                "NO_PROXY=", "no_proxy=",
                "bun", "install", "--frozen-lockfile", "--offline", "--ignore-scripts",
                cwd=smoke_root / component,
            )
        if component == "frontend":
            run(
                "runuser", "-u", "runner", "--", "env",
                "HOME=/home/runner", f"XDG_CACHE_HOME={cache}",
                f"BUN_INSTALL_CACHE_DIR={cache}",
                f"TMPDIR={temporary}",
                "HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
                "https_proxy=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9",
                "ALL_PROXY=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9",
                "NO_PROXY=", "no_proxy=",
                "bun", str(modules / ".bin/eslint"), "--version",
                cwd=component_root,
            )
            run(
                "runuser", "-u", "runner", "--", "env", "HOME=/home/runner",
                "bun", "-e",
                'require("./node_modules/next/dist/server/node-environment-extensions/console-file.js")',
                cwd=component_root,
            )
            if run(
                "runuser", "-u", "runner", "--", "env",
                "HOME=/home/runner", "NODE_OPTIONS=--max-old-space-size=1280",
                "HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
                "https_proxy=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9",
                "ALL_PROXY=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9",
                "NO_PROXY=", "no_proxy=", str(node_path),
                str(modules / "next/dist/bin/next"), "--version",
                cwd=component_root,
            ) != "Next.js v16.2.3":
                raise SystemExit("pinned Next.js Node entrypoint smoke drifted")
            if run(
                "runuser", "-u", "runner", "--", "env",
                "HOME=/home/runner", "NODE_OPTIONS=--max-old-space-size=1280",
                str(node_path), "-e",
                "const limit=require('node:v8').getHeapStatistics().heap_size_limit; "
                "process.stdout.write(`${limit}:${Math.ceil(limit * 0.8)}`)",
                cwd=component_root,
            ) != "1392508928:1114007143":
                raise SystemExit("pinned Next.js Node heap contract drifted")
            if run(
                "runuser", "-u", "runner", "--", "env",
                "HOME=/home/runner", "BUN_OPTIONS=--smol",
                "HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
                "https_proxy=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9",
                "ALL_PROXY=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9",
                "NO_PROXY=", "no_proxy=", "bun", "--smol",
                str(modules / ".bin/playwright"), "--version",
                cwd=component_root,
            ) != "Version 1.59.1":
                raise SystemExit("pinned Playwright Bun --smol entrypoint smoke drifted")
        if tree_digest(modules) != before:
            raise SystemExit(f"{component} validation mutated its dependency snapshot")
    shutil.rmtree(smoke_root)
    pyright_target = overworld / "backend/src/modules/methodology-obligations/waterfall-stage-push-contract.py"
    run(
        str(pyright_wrapper), str(pyright_target),
        env={**os.environ, "PYTHONPATH": f"{waterfall}:{waterfall / 'src'}"},
    )
    for tree in (waterfall / ".git", overworld, ROOT / "overworld.bundle", ROOT / "waterfall.bundle"):
        if tree.is_dir():
            shutil.rmtree(tree)
        elif tree.exists():
            tree.unlink()
    run(
        "runuser", "-u", "runner", "--", "env",
        "HOME=/home/runner",
        "HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
        "https_proxy=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9",
        "ALL_PROXY=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9",
        "NO_PROXY=", "no_proxy=",
        "uv", "--no-config", "pip", "check", "--python", str(waterfall_python),
    )
    run(
        "runuser", "-u", "runner", "--", "env",
        "HOME=/home/runner", "UV_OFFLINE=1", "UV_NO_SYNC=1",
        "uv", "run", "--frozen", "--project", str(waterfall),
        "python", "-c", "import waterfall",
    )
    shutil.rmtree(uv_cache)
    for forbidden_git in dependencies.rglob(".git"):
        raise SystemExit(f"source-control metadata persisted: {forbidden_git}")
    retained_source = [path for path in waterfall.rglob("*") if waterfall / ".venv" not in path.parents]
    for forbidden_name in (".env", ".npmrc", ".netrc", "hosts.yml"):
        if any(path.is_file() and path.name == forbidden_name for path in retained_source):
            raise SystemExit(f"credential-shaped file persisted: {forbidden_name}")

    manifest_bytes = MANIFEST.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    binaries = ["node", "bun", "uv", "uvx", "pyright", "playwright", "minio", "mc", "psql"]
    binary_inventory = {}
    for name in binaries:
        resolved = shutil.which(name)
        if not resolved:
            raise SystemExit(f"required executable is absent: {name}")
        path = Path(resolved).resolve()
        binary_inventory[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    postgres = Path(run("pg_config", "--bindir")) / "postgres"
    if not postgres.is_file():
        raise SystemExit("PostgreSQL server executable is absent")
    binary_inventory["postgres"] = {
        "path": str(postgres),
        "sha256": hashlib.sha256(postgres.read_bytes()).hexdigest(),
    }
    if "POSTGIS=" not in run("pg_config", "--configure") and not Path("/usr/share/postgresql/16/extension/postgis.control").is_file():
        raise SystemExit("PostGIS extension contract is absent")
    packages = run("dpkg-query", "-W", "-f=${Package}\t${Version}\n").splitlines()
    inventory = {
        "schema_version": 1,
        "profile": manifest["profile"],
        "manifest_sha256": manifest_sha,
        "artifacts": artifacts,
        "binaries": binary_inventory,
        "runtime_entrypoints": manifest["runtime_entrypoints"],
        "dpkg": sorted(packages),
        "playwright_chromium_revision": artifacts["playwright"]["chromium_revision"],
        "repository_profile_digest": profile_digest,
        "profile_assets": profile_assets,
        "source_bundles": bundle_inputs,
    }
    inventory_path = Path(str(manifest["inventory_path"]))
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    marker = {
        "repository_profile_image_marker_version": 1,
        "repository": profile["repository"],
        "profile_id": profile["profile_id"],
        "profile_digest": profile_digest,
        "image_marker": profile["image_marker"],
        "runner_memory_bytes": profile["runner_memory_bytes"],
        "toolchain": profile["toolchain"],
        "dependency_snapshots": profile["dependency_snapshots"],
    }
    marker_path = Path(str(manifest["marker_path"]))
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    for forbidden in (Path("/root/.npmrc"), Path("/root/.netrc"), Path("/root/.config/gh/hosts.yml")):
        if forbidden.exists():
            raise SystemExit(f"credential surface persisted: {forbidden}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
