from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "images/overworld-pr-v1"
BUILDER = ROOT / "scripts/host/build-repository-profile-image.sh"
PROVISION_CONTRACT = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"
LIVE_VERIFIER = ROOT / "scripts/host/verify-live-artifact-contract.py"


class OverworldProfileImageTests(unittest.TestCase):
    def test_regenerated_modules_cleanup_accepts_only_exact_backend_tree(self) -> None:
        spec = importlib.util.spec_from_file_location("overworld_image_provision", PROFILE / "provision.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def make_tree(root: Path, *, backend: object = "exact", frontend: object = None) -> tuple[Path, Path]:
            overworld = root / "overworld"
            dependencies = root / "dependencies"
            snapshot = dependencies / "backend-node_modules"
            snapshot.mkdir(parents=True)
            (snapshot / "package.txt").write_text("exact", encoding="utf-8")
            (overworld / "backend").mkdir(parents=True)
            (overworld / "frontend").mkdir(parents=True)
            if backend == "exact":
                target = overworld / "backend/node_modules"
                target.mkdir()
                (target / "package.txt").write_text("exact", encoding="utf-8")
            elif backend == "drift":
                target = overworld / "backend/node_modules"
                target.mkdir()
                (target / "package.txt").write_text("drift", encoding="utf-8")
            elif backend == "file":
                (overworld / "backend/node_modules").write_text("not a tree", encoding="utf-8")
            elif backend == "symlink":
                (overworld / "backend/node_modules").symlink_to(snapshot, target_is_directory=True)
            if frontend is not None:
                target = overworld / "frontend/node_modules"
                if frontend == "dir": target.mkdir()
                elif frontend == "file": target.write_text("unexpected", encoding="utf-8")
                elif frontend == "symlink": target.symlink_to(snapshot, target_is_directory=True)
            return overworld, dependencies

        with tempfile.TemporaryDirectory() as directory:
            overworld, dependencies = make_tree(Path(directory))
            module.remove_exact_regenerated_modules(overworld, dependencies)
            self.assertFalse((overworld / "backend/node_modules").exists())

        for backend in (None, "drift", "file", "symlink"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as directory:
                overworld, dependencies = make_tree(Path(directory), backend=backend)
                with self.assertRaises(SystemExit):
                    module.remove_exact_regenerated_modules(overworld, dependencies)

        for frontend in ("dir", "file", "symlink"):
            with self.subTest(frontend=frontend), tempfile.TemporaryDirectory() as directory:
                overworld, dependencies = make_tree(Path(directory), frontend=frontend)
                with self.assertRaisesRegex(SystemExit, "unexpected regenerated frontend"):
                    module.remove_exact_regenerated_modules(overworld, dependencies)

    def test_image_verifier_enforces_runner_accessible_waterfall_python(self) -> None:
        spec = importlib.util.spec_from_file_location("overworld_image_verify", PROFILE / "verify.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        python = Path("/opt/self-hosted-ci/overworld-deps/waterfall/.venv/bin/python")

        with mock.patch.object(Path, "resolve", return_value=Path("/root/.local/python3.11")):
            with self.assertRaisesRegex(SystemExit, "root-private"):
                module.verify_runner_executable(python)

        inaccessible = subprocess.CompletedProcess([], 1)
        with mock.patch.object(Path, "resolve", return_value=Path("/opt/self-hosted-ci/uv-python/python3.11")), mock.patch.object(
            module.subprocess, "run", return_value=inaccessible
        ) as run:
            with self.assertRaisesRegex(SystemExit, "not executable by runner"):
                module.verify_runner_executable(python)
            run.assert_called_once_with(
                ["runuser", "-u", "runner", "--", "test", "-x", str(python)], check=False
            )

        accessible = subprocess.CompletedProcess([], 0)
        with mock.patch.object(Path, "resolve", return_value=Path("/opt/self-hosted-ci/uv-python/python3.11")), mock.patch.object(
            module.subprocess, "run", return_value=accessible
        ):
            module.verify_runner_executable(python)

    def test_manifest_has_exact_profile_and_immutable_artifact_sources(self) -> None:
        manifest = json.loads((PROFILE / "manifest.json").read_text(encoding="utf-8"))
        spec = importlib.util.spec_from_file_location("overworld_image_provision_manifest", PROFILE / "provision.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIs(module.require_manifest(manifest), manifest)
        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual("overworld-pr-v1", manifest["profile"])
        self.assertEqual("alethia-earth/Overworld", manifest["repository"])
        self.assertEqual(
            {"bun", "uv", "pyright", "playwright", "playwright_core", "next", "chromium", "chromium_headless_shell", "minio", "mc"},
            set(manifest["artifacts"]),
        )
        self.assertEqual("1.4.0", manifest["artifacts"]["bun"]["version"])
        self.assertEqual("1.1.408", manifest["artifacts"]["pyright"]["version"])
        self.assertEqual("1.59.1", manifest["artifacts"]["playwright"]["version"])
        self.assertEqual("16.2.3", manifest["artifacts"]["next"]["version"])
        self.assertEqual("1217", manifest["artifacts"]["chromium"]["revision"])
        self.assertEqual("1217", manifest["artifacts"]["chromium_headless_shell"]["revision"])
        for artifact in manifest["artifacts"].values():
            self.assertTrue(artifact["url"].startswith("https://"))
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            {
                "key_url": "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
                "key_fingerprint": "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
                "repository": "https://apt-archive.postgresql.org/pub/repos/apt",
                "suite": "noble-pgdg-archive",
            },
            manifest["pgdg"],
        )
        for package in (
            "postgresql-16=16.15-1.pgdg24.04+2",
            "postgresql-16-postgis-3=3.4.3+dfsg-2.pgdg24.04+1",
            "postgresql-17=17.11-1.pgdg24.04+2",
            "postgresql-17-postgis-3=3.5.3+dfsg-2.pgdg24.04+1",
        ):
            self.assertIn(package, manifest["apt_packages"])

    def test_plan_is_inert_and_machine_readable(self) -> None:
        result = subprocess.run(
            ["bash", str(BUILDER), "--plan"], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value["host_changes"])
        self.assertFalse(value["builder_privileged"])
        self.assertFalse(value["builder_nesting"])
        self.assertFalse(value["alias_reuse"])
        self.assertTrue(value["runtime_must_be_empty"])

    def test_builder_is_transactional_fenced_and_never_moves_an_alias(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("/var/lib/self-hosted-ci/profile-image-build/transaction.", source)
        self.assertNotIn("mktemp -d /run/self-hosted-ci/profile-image", source)
        self.assertIn('incus query "/1.0/instances/${builder}?project=${PROJECT}&recursion=1"', source)
        self.assertNotIn('incus config show "${builder}"', source)
        self.assertIn('--env "https_proxy=${https_proxy}"', source)
        self.assertIn('--env "http_proxy=${https_proxy}"', source)
        self.assertIn("cloud-init status --wait", source)
        required = (
            "acquire_transaction_lock",
            "zero_runtime_state",
            "self-hosted-ci-outbound-worker.service",
            "self-hosted-ci-allocation-broker.service",
            "self-hosted-ci-garm.service",
            'squid -N -f "${profile_dir}/squid-build.conf"',
            'systemctl stop "${BUILD_PROXY_UNIT}"',
            'security.privileged=false security.nesting=false security.idmap.isolated=true',
            'set(d)!={"eth0","root"}',
            'd["eth0"].get("network")!="ci-jit-isolated"',
            'incus publish "${builder}"',
            'incus image alias delete "${candidate_alias}"',
            'incus image delete "${published_fingerprint}"',
            '--overworld-bundle',
            '--expected-overworld-commit',
            '--waterfall-bundle',
            '--expected-waterfall-commit',
            'git bundle list-heads "${overworld_bundle}"',
            'git bundle list-heads "${waterfall_bundle}"',
            'incus file push "${overworld_bundle}"',
            'incus file push "${waterfall_bundle}"',
            'credentials_persisted":false',
            'alias_moved":false',
        )
        for token in required:
            self.assertIn(token, source)
        for forbidden in ("--reuse", "--copy-aliases", "security.privileged=true", "security.nesting=true", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("SQUID_CONFIG", source)
        self.assertIn("10.254.0.1:8079", source)
        self.assertIn("RuntimeMaxSec=2h", source)
        self.assertIn("Conflicts=${FENCED_SERVICES[*]}", source)
        self.assertIn("--collect", source)
        self.assertIn("KillMode=control-group", source)
        self.assertIn("systemctl is-active --quiet \"${BUILD_PROXY_UNIT}\" && status=1", source)
        self.assertIn("grep -Eq '(^|:)8079$'", source)

    def test_build_egress_is_exact_and_not_a_general_wildcard(self) -> None:
        policy = (PROFILE / "squid-build.conf").read_text(encoding="utf-8")
        for domain in (
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "apt-archive.postgresql.org",
            "storage.googleapis.com",
            "www.postgresql.org",
            "github.com",
            "release-assets.githubusercontent.com",
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "dl.min.io",
        ):
            self.assertIn(domain, policy)
        self.assertNotIn("dstdomain .githubusercontent.com", policy)
        self.assertNotIn("dstdomain .com", policy)
        self.assertIn("http_access deny all", policy)

    def test_provisioner_emits_marker_inventory_and_rejects_credentials(self) -> None:
        source = (PROFILE / "provision.py").read_text(encoding="utf-8")
        for token in (
            "manifest_sha256",
            '"repository_profile_image_marker_version": 1',
            '"profile_digest": profile_digest',
            '"runner_memory_bytes": profile["runner_memory_bytes"]',
            '"toolchain": profile["toolchain"]',
            '"dependency_snapshots": profile["dependency_snapshots"]',
            "dpkg-query",
            "PLAYWRIGHT_BROWSERS_PATH",
            '"bun", "install", "--frozen-lockfile"',
            '"uv", "sync", "--frozen"',
            'downloaded["chromium"], Path("/opt/ms-playwright/chromium-1217")',
            'str(pyright_wrapper), str(pyright_target)',
            'sha256_file(lockfile)',
            'run("pg_dropcluster", "--stop", major, "main")',
            'waterfall / ".git"',
            'ROOT / "overworld.bundle"',
            "/root/.npmrc",
            "/root/.netrc",
            "/root/.config/gh/hosts.yml",
        ):
            self.assertIn(token, source)
        manifest = (PROFILE / "manifest.json").read_text(encoding="utf-8")
        self.assertIn("repository-profile-image-v1.json", manifest)
        self.assertNotIn("WATERFALL_CI_TOKEN", source)
        self.assertNotIn("GITHUB_TOKEN", source)
        self.assertNotIn("output(", source)
        self.assertIn("APT sources were not upgraded to HTTPS", source)
        self.assertIn('downloads = tx / "downloads"', source)
        self.assertIn("target = downloads / name", source)
        self.assertNotIn("target = tx / name", source)
        self.assertIn("shutil.rmtree(uv_cache)", source)
        self.assertNotIn('run("chown", "-R", "runner:runner", str(uv_cache))', source)
        self.assertNotIn('run("chmod", "-R", "u+rwX,go+rX", str(uv_cache))', source)
        self.assertIn('"UV_OFFLINE=1", "UV_NO_SYNC=1"', source)
        self.assertIn('"python", "-c", "import waterfall"', source)
        self.assertIn('downloaded["next"], next_package', source)
        self.assertIn('next_metadata.get("version") != "16.2.3"', source)
        self.assertIn('official_browser_logs = next_package / "dist/server/dev/browser-logs"', source)
        self.assertIn('shutil.copytree(official_browser_logs, installed_browser_logs)', source)
        self.assertNotIn('shutil.copytree(next_package, installed_next)', source)
        self.assertIn('browser-logs/file-logger.js', source)
        self.assertIn('node-environment-extensions/console-file.js', source)
        self.assertEqual(1, source.count('"bun", "install", "--frozen-lockfile", "--offline", "--ignore-scripts"'))
        self.assertIn('if component == "backend":', source)
        verifier_source = (PROFILE / "verify.py").read_text(encoding="utf-8")
        self.assertNotIn('dependencies / "uv-cache"', verifier_source)
        self.assertIn('if any(dependencies.rglob(".git")):', verifier_source)
        self.assertIn('frontend-node_modules/next/dist/server/dev/browser-logs/file-logger.js', verifier_source)
        self.assertNotIn('run("playwright", "install"', source)
        self.assertIn('"UV_PYTHON_INSTALL_DIR": str(uv_python)', source)
        self.assertIn('run("runuser", "-u", "runner", "--", "test", "-x", str(waterfall_python))', source)
        marker = source.index('(waterfall / ".self-hosted-ci-commit").write_text')
        initial_sync = source.index('run("uv", "sync", "--frozen", "--project"')
        offline_check = source.index('"uv", "--no-config", "pip", "check", "--python", str(waterfall_python)')
        git_cleanup = source.index('for tree in (waterfall / ".git"')
        self.assertLess(marker, initial_sync)
        self.assertLess(git_cleanup, offline_check)
        self.assertEqual(1, source.count('(waterfall / ".self-hosted-ci-commit").write_text'))
        for offline_smoke_contract in (
            'smoke_root = Path("/var/tmp/overworld-offline-smoke")',
            'cache = smoke_root / f"bun-cache-{component}"',
            'temporary = smoke_root / f"bun-tmp-{component}"',
            'run("chown", "-R", "runner:runner", str(smoke_root))',
            '"runuser", "-u", "runner", "--", "env"',
            'f"BUN_INSTALL_CACHE_DIR={cache}"',
            'f"TMPDIR={temporary}"',
            '"HOME=/home/runner", f"XDG_CACHE_HOME={cache}"',
            '"HTTPS_PROXY=http://127.0.0.1:9"',
            '"ALL_PROXY=http://127.0.0.1:9"',
            '"NO_PROXY="',
            '"bun", "install", "--frozen-lockfile", "--offline", "--ignore-scripts"',
            'shutil.rmtree(smoke_root)',
            'before = tree_digest(modules)',
            'if tree_digest(modules) != before:',
        ):
            self.assertIn(offline_smoke_contract, source)
        regenerated_cleanup = source.index('remove_exact_regenerated_modules(overworld, dependencies)', source.index("def main"))
        hardening = source.index('for path in dependencies.rglob("*")')
        copying = source.index('shutil.copytree(overworld, smoke_root')
        executing = source.index('"bun", "install", "--frozen-lockfile", "--offline", "--ignore-scripts"')
        cleanup = source.index('shutil.rmtree(smoke_root)', executing)
        self.assertLess(regenerated_cleanup, hardening)
        self.assertLess(hardening, copying)
        self.assertLess(copying, executing)
        self.assertLess(executing, cleanup)
        self.assertIn('[[ $(id -nG runner) == runner ]]', source)
        self.assertIn('runuser -u runner -- test ! -x /usr/bin/sudo', source)
        self.assertIn('root:root:644|root:root:664', source)
        self.assertIn('chmod 0644 "$unit"', source)
        for rollback_contract in (
            "trap - EXIT",
            "--property ActiveState --value",
            "systemctl is-enabled",
            "exit 125",
        ):
            self.assertIn(rollback_contract, source)

    def test_runner_finalizer_rollback_rejects_unproven_systemd_state(self) -> None:
        source = (PROFILE / "provision.py").read_text(encoding="utf-8")
        start = source.index("rollback() {")
        end = source.index("\n}\ntrap rollback EXIT", start) + 2
        rollback = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            systemctl = Path(directory) / "systemctl"
            systemctl.write_text(
                """#!/bin/bash
[[ $2 == actions.runner.test.service ]] || exit 98
case "$1" in
  stop|disable|reset-failed) exit 1 ;;
  show) [[ ${MOCK_STATE:-error} == error ]] && exit 4; echo "${MOCK_STATE}"; exit 0 ;;
  is-enabled) [[ ${MOCK_ENABLED:-error} == error ]] && exit 4; echo "${MOCK_ENABLED}"; [[ $MOCK_ENABLED == disabled ]] && exit 1; exit 0 ;;
esac
exit 9
""",
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            env = {**os.environ, "PATH": f"{directory}:{os.environ['PATH']}"}
            harness = (
                f"set -uo pipefail\n{rollback}\ncommitted=false\n"
                "service_name=actions.runner.test.service\n"
                "(exit ${ORIGINAL_RC:-42}); rollback\n"
            )
            for state, enabled in (("error", "error"), ("active", "disabled"), ("inactive", "enabled")):
                result = subprocess.run(
                    ["bash", "-c", harness], env={**env, "MOCK_STATE": state, "MOCK_ENABLED": enabled},
                    text=True, capture_output=True,
                )
                self.assertEqual(125, result.returncode, (state, enabled, result.stderr))

            result = subprocess.run(
                ["bash", "-c", harness],
                env={**env, "MOCK_STATE": "inactive", "MOCK_ENABLED": "disabled"},
                text=True,
                capture_output=True,
            )
            self.assertEqual(42, result.returncode, result.stderr)

    def test_runner_finalizer_validates_unit_mode_before_normalizing(self) -> None:
        source = (PROFILE / "provision.py").read_text(encoding="utf-8")
        start = source.index("if [[ ! -f $unit || -L $unit ]]")
        end = source.index("\ngrep -Fxq", start)
        mode_contract = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            unit = Path(directory) / "actions.runner.test.service"
            unit.write_text("[Service]\nUser=runner\n", encoding="utf-8")
            bin_dir = Path(directory) / "bin"
            bin_dir.mkdir()
            stat = bin_dir / "stat"
            stat.write_text(
                """#!/bin/bash
if [[ -f $MOCK_CHMOD_MARKER ]]; then printf '%s\n' root:root:644; else printf '%s\n' "$MOCK_INITIAL_STAT"; fi
""",
                encoding="utf-8",
            )
            stat.chmod(0o755)
            chmod = bin_dir / "chmod"
            chmod.write_text(
                """#!/bin/bash
[[ $1 == 0644 && $2 == "$MOCK_UNIT" ]] || exit 97
printf normalized > "$MOCK_CHMOD_MARKER"
""",
                encoding="utf-8",
            )
            chmod.chmod(0o755)
            for initial, expected in (("root:root:664", 0), ("root:root:644", 0), ("root:root:666", 1), ("root:root:640", 1), ("other:root:664", 1)):
                marker = Path(directory) / "normalized"
                marker.unlink(missing_ok=True)
                harness = f"set -euo pipefail\nunit={unit!s}\n{mode_contract}\n"
                result = subprocess.run(
                    ["bash", "-c", harness],
                    env={
                        **os.environ,
                        "PATH": f"{bin_dir}:{os.environ['PATH']}",
                        "MOCK_INITIAL_STAT": initial,
                        "MOCK_CHMOD_MARKER": str(marker),
                        "MOCK_UNIT": str(unit),
                    },
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(expected, result.returncode, (initial, result.stderr))
                self.assertEqual(expected == 0, marker.exists(), initial)

            symlink = Path(directory) / "unit-link"
            symlink.symlink_to(unit)
            marker = Path(directory) / "normalized"
            marker.unlink(missing_ok=True)
            result = subprocess.run(
                ["bash", "-c", f"set -euo pipefail\nunit={symlink!s}\n{mode_contract}\n"],
                env={
                    **os.environ,
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "MOCK_INITIAL_STAT": "root:root:664",
                    "MOCK_CHMOD_MARKER": str(marker),
                    "MOCK_UNIT": str(symlink),
                },
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())

    def test_verifier_enforces_exact_profile_marker_and_offline_dependencies(self) -> None:
        source = (PROFILE / "verify.py").read_text(encoding="utf-8")
        for field in (
            "repository_profile_image_marker_version",
            "repository",
            "profile_id",
            "profile_digest",
            "image_marker",
            "runner_memory_bytes",
            "toolchain",
            "dependency_snapshots",
        ):
            self.assertIn(f'"{field}"', source)
        for token in (
            "backend-node_modules",
            "frontend-node_modules",
            "waterfall/.self-hosted-ci-commit",
            "chromium_headless_shell-1217",
            "source-control metadata persisted",
            '("16", "3.4")',
            '("17", "3.5")',
            "default cluster persisted",
            "runner privilege boundary drifted",
            "runner finalizer ownership or mode drifted",
            "Waterfall interpreter resolves through a root-private path",
            "Waterfall interpreter is not executable by runner",
            'runner_groups != {"runner"}',
        ):
            self.assertIn(token, source)

    def test_scripts_parse_and_manifest_digest_is_stable(self) -> None:
        expected = hashlib.sha256((PROFILE / "manifest.json").read_bytes()).hexdigest()
        self.assertRegex(expected, r"^[0-9a-f]{64}$")
        shell = subprocess.run(["bash", "-n", str(BUILDER)], text=True, capture_output=True)
        self.assertEqual(0, shell.returncode, shell.stderr)
        python = subprocess.run(
            ["python3", "-m", "py_compile", str(PROFILE / "provision.py"), str(PROFILE / "verify.py")],
            text=True,
            capture_output=True,
        )
        self.assertEqual(0, python.returncode, python.stderr)

    def test_builder_forces_stop_only_after_bounded_graceful_shutdown(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        graceful = 'if ! incus stop "${builder}" --project "${PROJECT}" --timeout 60; then'
        forced = 'incus stop "${builder}" --project "${PROJECT}" --force'
        stopped = 'incus list "${builder}" --project "${PROJECT}" --format csv -c s | grep -Fxq STOPPED'
        publish = 'incus publish "${builder}" --project "${PROJECT}" --alias "${candidate_alias}"'
        flush = 'incus exec "${builder}" --project "${PROJECT}" -- /bin/sync'
        self.assertEqual(1, source.count(flush))
        self.assertEqual(1, source.count(graceful))
        self.assertEqual(1, source.count(forced))
        self.assertLess(source.index(flush), source.index(graceful))
        self.assertLess(source.index(graceful), source.index(forced))
        self.assertLess(source.index(forced), source.index(stopped))
        self.assertLess(source.index(stopped), source.index(publish))
        post_cleanup_file_check = "test -f /opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/dist/server/dev/browser-logs/file-logger.js"
        boot_check = 'incus exec "${published_verifier}" --project "${PROJECT}" -- /bin/test -f /opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/dist/server/dev/browser-logs/file-logger.js'
        self.assertGreaterEqual(source.count(post_cleanup_file_check), 2)
        self.assertIn(boot_check, source)
        self.assertLess(source.index(publish), source.index(boot_check))

    def test_builder_and_profile_are_installed_under_signed_live_contract(self) -> None:
        provision = PROVISION_CONTRACT.read_text(encoding="utf-8")
        stager = STAGER.read_text(encoding="utf-8")
        verifier = LIVE_VERIFIER.read_text(encoding="utf-8")
        self.assertIn("build-repository-profile-image.sh", provision)
        for target in (
            "/usr/local/lib/self-hosted-ci/build-repository-profile-image.sh",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/manifest.json",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/squid-build.conf",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/provision.py",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/verify.py",
            "/usr/local/share/self-hosted-ci/repository-profiles/overworld/profile.json",
        ):
            self.assertIn(target, stager)
            self.assertIn(target, verifier)


if __name__ == "__main__":
    unittest.main()
