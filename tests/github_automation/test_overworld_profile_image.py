from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
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
    def test_cloud_init_status_parser_accepts_only_clean_supported_transitions(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        parser = source.split("  python3 - \"${phase}\" \"${status_json}\" <<'PY'\n", 1)[1].split("\nPY\n}", 1)[0]

        def decide(payload: object, phase: str = "preflight") -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                parser_path = Path(directory) / "cloud-init-status.py"
                status_path = Path(directory) / "status.json"
                parser_path.write_text(parser, encoding="utf-8")
                status_path.write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.run(
                    ["python3", str(parser_path), phase, str(status_path)],
                    text=True,
                    capture_output=True,
                )

        clean = {"errors": [], "recoverable_errors": {}}
        accepted = (
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator"}, "preflight", "terminal"),
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator"}, "wait", "terminal"),
            ({**clean, "status": "disabled", "extended_status": "disabled", "boot_status_code": "disabled-by-generator"}, "preflight", "terminal"),
            ({**clean, "status": "disabled", "extended_status": "disabled", "boot_status_code": "disabled-by-generator"}, "wait", "terminal"),
            ({**clean, "status": "running", "extended_status": "running", "boot_status_code": "enabled-by-generator"}, "preflight", "wait"),
            ({**clean, "status": "not started", "extended_status": "not started", "boot_status_code": "enabled-by-generator"}, "preflight", "wait"),
        )
        for payload, phase, decision in accepted:
            with self.subTest(payload=payload, phase=phase):
                result = decide(payload, phase)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(decision, result.stdout.strip())

        rejected = (
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "disabled-by-generator"}, "preflight"),
            ({**clean, "status": "disabled", "extended_status": "disabled", "boot_status_code": "enabled-by-generator"}, "preflight"),
            ({**clean, "status": "running", "extended_status": "running", "boot_status_code": "enabled-by-generator"}, "wait"),
            ({**clean, "status": "unknown", "extended_status": "unknown", "boot_status_code": "enabled-by-generator"}, "preflight"),
            ({**clean, "status": "running", "extended_status": "done", "boot_status_code": "enabled-by-generator"}, "preflight"),
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled"}, "preflight"),
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-systemd-generator"}, "preflight"),
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator", "errors": ["secret value"]}, "preflight"),
            ({**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator", "recoverable_errors": {"WARNING": ["secret value"]}}, "preflight"),
            ({"status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator"}, "preflight"),
        )
        for payload, phase in rejected:
            with self.subTest(payload=payload, phase=phase):
                result = decide(payload, phase)
                self.assertNotEqual(0, result.returncode)
                self.assertNotIn("secret value", result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            parser_path = Path(directory) / "cloud-init-status.py"
            status_path = Path(directory) / "status.json"
            parser_path.write_text(parser, encoding="utf-8")
            status_path.write_text("not JSON: secret value", encoding="utf-8")
            result = subprocess.run(
                ["python3", str(parser_path), "preflight", str(status_path)],
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("cloud-init preflight returned invalid JSON", result.stderr.strip())

    def test_cloud_init_readiness_wrapper_preserves_terminal_disabled_and_bounds_wait(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        functions = source[
            source.index("cloud_init_status_decision(){") : source.index("inspect_running_sentinels(){")
        ]

        def run_guard(
            preflight: object,
            *,
            waited: object | None = None,
            preflight_rc: int = 0,
            waited_rc: int = 0,
        ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = root / "guard.sh"
                calls = root / "calls"
                preflight_path = root / "preflight.json"
                waited_path = root / "waited.json"
                preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
                waited_path.write_text(json.dumps(waited), encoding="utf-8")
                script.write_text(
                    "set -Eeuo pipefail\n"
                    "readonly PROJECT=ci-jit\n"
                    f"workdir={str(root)!r}\n"
                    f"calls_file={str(calls)!r}\n"
                    f"preflight_path={str(preflight_path)!r}\n"
                    f"waited_path={str(waited_path)!r}\n"
                    f"preflight_rc={preflight_rc}\n"
                    f"waited_rc={waited_rc}\n"
                    "incus(){\n"
                    "  case \" $* \" in\n"
                    "    *\" status --wait \"*) printf 'wait\\n' >>\"${calls_file}\"; printf 'untrusted wait secret stderr\\n' >&2; "
                    "       if [[ \"${waited_rc}\" -ne 0 ]]; then return \"${waited_rc}\"; fi; command cat \"${waited_path}\" ;;\n"
                    "    *) printf 'preflight\\n' >>\"${calls_file}\"; printf 'untrusted secret stderr\\n' >&2; "
                    "       if [[ \"${preflight_rc}\" -ne 0 ]]; then return \"${preflight_rc}\"; fi; command cat \"${preflight_path}\" ;;\n"
                    "  esac\n"
                    "}\n"
                    f"{functions}\n"
                    "wait_for_cloud_init_readiness builder\n",
                    encoding="utf-8",
                )
                result = subprocess.run(["bash", str(script)], text=True, capture_output=True)
                recorded_calls = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
            return result, recorded_calls

        clean = {"errors": [], "recoverable_errors": {}}
        disabled = {**clean, "status": "disabled", "extended_status": "disabled", "boot_status_code": "disabled-by-generator"}
        result, calls = run_guard(disabled)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["preflight"], calls)

        running = {**clean, "status": "running", "extended_status": "running", "boot_status_code": "enabled-by-generator"}
        done = {**clean, "status": "done", "extended_status": "done", "boot_status_code": "enabled-by-generator"}
        result, calls = run_guard(running, waited=done)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["preflight", "wait"], calls)

        for rc in (1, 2, 124):
            with self.subTest(rc=rc):
                result, calls = run_guard(done, preflight_rc=rc)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(["preflight"], calls)
                self.assertIn(f"cloud-init preflight command failed: rc={rc}", result.stderr)
                self.assertNotIn("untrusted secret stderr", result.stderr)

        for rc in (1, 2, 124):
            with self.subTest(waited_rc=rc):
                result, calls = run_guard(running, waited=done, waited_rc=rc)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(["preflight", "wait"], calls)
                self.assertIn(f"cloud-init wait command failed: rc={rc}", result.stderr)
                self.assertNotIn("untrusted wait secret stderr", result.stderr)

    def test_cloud_init_readiness_guard_is_bounded_and_machine_readable(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        guard = source.split("wait_for_cloud_init_readiness(){", 1)[1].split("\n}\ninspect_running_sentinels(){", 1)[0]
        self.assertIn('/usr/bin/timeout -k 10s 15s /usr/bin/cloud-init status --format=json', guard)
        self.assertIn('/usr/bin/timeout -k 10s 180s /usr/bin/cloud-init status --wait --format=json', guard)
        self.assertEqual(1, guard.count("status --wait"))
        self.assertIn('cloud_init_status_decision preflight "${preflight_json}"', guard)
        self.assertIn('cloud_init_status_decision wait "${waited_json}"', guard)
        self.assertNotIn("cat ", guard)
        self.assertNotIn('preflight_stderr}" >&2', guard)
        self.assertNotIn('waited_stderr}" >&2', guard)

    def test_streaming_tar_scan_can_bound_tarinfo_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "many-members.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                for index in range(512):
                    member = tarfile.TarInfo(f"rootfs/member-{index}")
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"x"))

            maximum_cached = 0
            with tarfile.open(archive_path, mode="r|*") as archive:
                while True:
                    member = archive.next()
                    if member is None:
                        break
                    maximum_cached = max(maximum_cached, len(archive.members))
                    archive.members.clear()

        self.assertLessEqual(maximum_cached, 1)

    def test_dependency_tree_ownership_normalization_includes_root_without_following_links(self) -> None:
        spec = importlib.util.spec_from_file_location("overworld_image_provision_ownership", PROFILE / "provision.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "snapshot"
            child = root / "directory"
            child.mkdir(parents=True)
            (child / "file.js").write_text("payload", encoding="utf-8")
            outside = base / "outside"
            outside.mkdir()
            (outside / "must-not-be-traversed").write_text("external", encoding="utf-8")
            (root / "link").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(module.os, "chown") as chown:
                module.normalize_tree_ownership(root)

        calls = {(Path(call.args[0]), *call.args[1:], call.kwargs["follow_symlinks"]) for call in chown.call_args_list}
        self.assertEqual(
            {
                (root, 0, 0, False),
                (child, 0, 0, False),
                (child / "file.js", 0, 0, False),
                (root / "link", 0, 0, False),
            },
            calls,
        )
        self.assertNotIn(outside / "must-not-be-traversed", {call[0] for call in calls})

    def test_dependency_tree_ownership_normalization_fails_on_walk_error(self) -> None:
        spec = importlib.util.spec_from_file_location("overworld_image_provision_ownership_error", PROFILE / "provision.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fail_walk(_root: Path, *, followlinks: bool, onerror: object) -> object:
                self.assertFalse(followlinks)
                assert callable(onerror)
                onerror(PermissionError("scandir denied"))
                return iter(())

            with mock.patch.object(module.os, "chown"), mock.patch.object(module.os, "walk", side_effect=fail_walk):
                with self.assertRaisesRegex(PermissionError, "scandir denied"):
                    module.normalize_tree_ownership(root)

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
        self.assertIn('wait_for_cloud_init_readiness "${builder}"', source)
        required = (
            "acquire_transaction_lock",
            "zero_runtime_state",
            "self-hosted-ci-outbound-worker.service",
            "self-hosted-ci-allocation-broker.service",
            "self-hosted-ci-garm.service",
            'squid -N -f "${profile_dir}/squid-build.conf"',
            'systemctl stop "${BUILD_PROXY_UNIT}"',
            'security.privileged=false security.nesting=false security.idmap.isolated=true',
            'cat /sys/fs/cgroup/memory.events >&2',
            "die 'image provisioning failed'",
            "die 'provisioned image verification failed'",
            "die 'Next.js browser log sealing failed'",
            "die 'provisioned image cleanup verification failed'",
            'npm credential file persisted',
            'netrc credential file persisted',
            'GitHub CLI credential file persisted',
            'required Next.js browser log module missing after cleanup',
            'mv /opt/self-hosted-ci/.frontend-node-modules-sealed "$target"',
            'frontend dependency seal persisted',
            "die 'provisioned image sync failed'",
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

    def test_builder_is_deleted_before_published_image_verification(self) -> None:
        lines = BUILDER.read_text(encoding="utf-8").splitlines()
        publish = 'incus publish "${builder}" --project "${PROJECT}" --alias "${candidate_alias}" >/dev/null'
        builder_delete = 'incus delete "${builder}" --project "${PROJECT}"'
        verifier_init = 'incus init "${published_fingerprint}" "${published_verifier}" --project "${PROJECT}" --profile ci-jit'

        self.assertEqual(1, lines.count(publish))
        self.assertEqual(1, lines.count(builder_delete))
        self.assertEqual(1, lines.count(verifier_init))
        self.assertLess(lines.index(publish), lines.index(builder_delete))
        self.assertLess(lines.index(builder_delete), lines.index(verifier_init))

    def test_builder_requires_the_versioned_incus_archive_anchor(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        function = source.split(
            "assert_incus_archive_exclude_contract(){", 1
        )[1].split("\n}\nassert_host_dev_null_contract(){", 1)[0]
        for token in (
            "6.0.0-1ubuntu0.3",
            "/etc/systemd/system/incus.service.d/ci-jit-archive-excludes.conf",
            "/etc/self-hosted-ci/incus-archive-exclude-compat.json",
            "0:0:644:1",
            "0:0:600:1",
            '"nested_dev_canary_passed":true',
            '"root_dev_exclusion_preserved":true',
            "Environment=TAR_OPTIONS=--anchored",
            "property=DropInPaths",
            "property=Environment",
            "TAR_OPTIONS=--anchored",
        ):
            self.assertIn(token, function)
        self.assertEqual(1, source.count("\nassert_incus_archive_exclude_contract\n"))
        self.assertLess(
            source.index("\nassert_incus_archive_exclude_contract\n"),
            source.index("acquire_transaction_lock"),
        )

    def test_builder_discriminates_rootfs_persistence_across_publication(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        sentinels = (
            "/etc/self-hosted-ci/repository-profile-image-v1.json",
            "/opt/self-hosted-ci/node_modules/pyright/package.json",
            "/opt/self-hosted-ci/overworld-deps/frontend-node-modules/react/package.json",
            "/opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/package.json",
            "/opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/dist/server/dev/browser-logs/receive-logs.js",
            "/opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/dist/server/dev/browser-logs/file-logger.js",
        )
        sentinel_block = source.split("readonly PUBLISH_SENTINELS=(", 1)[1].split(")", 1)[0]
        self.assertEqual(sentinels, tuple(line.strip() for line in sentinel_block.splitlines() if line.strip()))

        probe = source.split("inspect_running_sentinels(){", 1)[1].split("\n}\nusage(){", 1)[0]
        for token in (
            '[ ! -f "$path" ] || [ -L "$path" ]',
            '[ ! -d "$directory" ] || [ -L "$directory" ]',
            'uid=%u gid=%g mode=%a links=%h size=%s device=%d',
            'uid=0\\ gid=0\\ *',
            'findmnt -rn -T "$path" -o TARGET,SOURCE,FSTYPE',
            'findmnt -rn -T "$directory" -o TARGET,SOURCE,FSTYPE',
            '[ "$directory" = /opt ] && break',
            'sha256sum -- "$path"',
            'sentinel digest changed',
            'exit "$failed"',
        ):
            self.assertIn(token, probe)
        self.assertEqual(2, probe.count('[ "${mount%% *}" != / ]'))
        self.assertNotIn("2>/dev/null", probe)
        self.assertNotIn("| sed", probe)
        self.assertIn("sentinel mount target is not rootfs", probe)
        self.assertIn("sentinel ancestor mount target is not rootfs", probe)
        self.assertNotRegex(probe, r"\b(?:cat|head|tail)\b")

        post_cleanup = 'inspect_running_sentinels "${builder}" builder-post-cleanup'
        digest_inventory = 'incus exec "${builder}" --project "${PROJECT}" -- sha256sum -- "${PUBLISH_SENTINELS[@]}"'
        sync = 'incus exec "${builder}" --project "${PROJECT}" -- /bin/sync'
        stopped = 'incus list "${builder}" --project "${PROJECT}" --format csv -c s | grep -Fxq STOPPED'
        stopped_pull = 'incus file pull "${builder}${sentinel}" - --project "${PROJECT}" >"${sentinel_probe}"'
        publish = 'incus publish "${builder}" --project "${PROJECT}" --alias "${candidate_alias}" >/dev/null'
        builder_delete = 'incus delete "${builder}" --project "${PROJECT}"'
        verifier_init = 'incus init "${published_fingerprint}" "${published_verifier}" --project "${PROJECT}" --profile ci-jit'
        initialized_pull = 'incus file pull "${published_verifier}${sentinel}" - --project "${PROJECT}" >"${sentinel_probe}"'
        verifier_start = 'incus start "${published_verifier}" --project "${PROJECT}"'
        running_check = 'inspect_running_sentinels "${published_verifier}" published-verifier-post-start "${expected_sentinel_digests[@]}"'
        export = 'incus image export "${published_fingerprint}" "${published_export_dir}/image" --project "${PROJECT}"'
        tar_check = 'python3 - "${published_export_dir}" "${workdir}/publish-sentinels.sha256" "${PUBLISH_SENTINELS[@]}"'
        device_check = 'inspect_running_device_contract "${published_verifier}"'

        for check in (post_cleanup, digest_inventory, stopped_pull, initialized_pull, export, tar_check, running_check, device_check):
            self.assertEqual(1, source.count(check))
        stopped_probe = source[source.index(stopped_pull):source.index(publish)]
        self.assertIn('|| die "stopped-builder rootfs is missing or cannot expose sentinel: ${sentinel}"', stopped_probe)
        initialized_probe = source[source.index(initialized_pull):source.index(verifier_start)]
        self.assertIn("diagnostic only", initialized_probe)
        self.assertNotIn("die ", initialized_probe)
        self.assertNotIn('incus file pull "${builder}${sentinel}" /dev/null', source)
        self.assertNotIn('incus file pull "${published_verifier}${sentinel}" /dev/null', source)
        self.assertIn('sentinel_probe="${workdir}/sentinel-probe"', source)
        self.assertIn('chmod 0600 "${sentinel_probe}"', source)
        self.assertIn("uid=0 gid=0 mode=600", source)
        self.assertEqual(3, source.count(': >"${sentinel_probe}"'))
        self.assertIn("builder sentinel digest inventory is incomplete", source)
        self.assertIn("published image boot sentinel verification failed", source)
        publish_position = source.index(publish)
        positions = (
            source.index(post_cleanup),
            source.index(digest_inventory),
            source.index(sync),
            source.index(stopped),
            source.index(stopped_pull),
            publish_position,
            source.index(export, publish_position),
            source.index(tar_check, publish_position),
            source.index(builder_delete, publish_position),
            source.index(verifier_init),
            source.index(initialized_pull),
            source.index(verifier_start),
            source.index(running_check),
            source.index(device_check),
        )
        self.assertTrue(all(left < right for left, right in zip(positions, positions[1:])))
        tar_probe = source[source.index(tar_check):source.index(builder_delete, publish_position)]
        for token in (
            'tarfile.open(archives[0], mode="r|*")',
            "member = archive.next()",
            "archive.members.clear()",
            'wanted = {f"rootfs/{sentinel.removeprefix(\'/\')}": sentinel for sentinel in sentinels}',
            "if member.name in seen",
            "member.isfile()",
            "member.uid != 0",
            "member.gid != 0",
            "archive.extractfile(member)",
            "with stream:",
            "digest.update(chunk)",
            "published image archive sentinel digest changed",
            "missing = set(wanted) - seen",
        ):
            self.assertIn(token, tar_probe)
        self.assertIn("if len(archives) != 1", tar_probe)
        self.assertNotIn("members = {}", tar_probe)
        self.assertNotIn("for member in archive", tar_probe)
        self.assertNotRegex(tar_probe, r"\b(?:cat|head|tail)\b")

        device_probe = source.split("inspect_running_device_contract(){", 1)[1].split("\n}\nusage(){", 1)[0]
        for token in (
            "[ -c /dev/null ]",
            'mode=%a major=%t minor=%T',
            'uid=0 gid=0 mode=666 major=1 minor=3',
            'findmnt -rn -T /dev -o TARGET,SOURCE,FSTYPE',
            '[ "${mount%% *}" = /dev ]',
            "printf probe > /dev/null",
        ):
            self.assertIn(token, device_probe)
        self.assertNotIn("2>/dev/null", device_probe)
        self.assertNotIn("| sed", device_probe)

        host_device_probe = source.split("assert_host_dev_null_contract(){", 1)[1].split("\n}\nusage(){", 1)[0]
        for token in (
            "[[ -c /dev/null && ! -L /dev/null ]]",
            "uid=%u gid=%g mode=%a major=%t minor=%T",
            "uid=0 gid=0 mode=666 major=1 minor=3",
            "printf probe > /dev/null",
        ):
            self.assertIn(token, host_device_probe)
        self.assertEqual(2, source.count("\nassert_host_dev_null_contract\n"))
        self.assertLess(source.index("\nassert_host_dev_null_contract\n"), source.index('incus start "${builder}"'))
        second_guard = source.index("\nassert_host_dev_null_contract\n", source.index("\nassert_host_dev_null_contract\n") + 1)
        self.assertLess(second_guard, source.index(verifier_start))

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
        self.assertIn('"apt-daily.timer", "apt-daily-upgrade.timer"', source)
        self.assertIn('"unattended-upgrades.service"', source)
        self.assertLess(source.index('"unattended-upgrades.service"'), source.index('run("apt-get", "clean")'))
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
        self.assertIn('shutil.copytree(next_package, installed_next, symlinks=False)', source)
        self.assertIn('detach_regular_files(installed_next)', source)
        self.assertIn('shutil.copytree(target_modules, sealed_frontend, symlinks=False)', source)
        self.assertIn('detach_regular_files(sealed_frontend)', source)
        self.assertIn('normalize_tree_ownership(sealed_frontend)', source)
        self.assertIn('os.replace(temporary, path)', source)
        self.assertNotIn('shutil.copytree(official_browser_logs, installed_browser_logs)', source)
        self.assertIn('run("cp", "-aL", f"{source_modules}/.", str(target_modules))', source)
        self.assertIn('required_next.resolve() != required_next', source)
        self.assertIn('frontend dependency snapshot retained a symlink ancestor', source)
        self.assertIn('if component == "backend":', source)
        self.assertIn('shutil.move(str(source_modules), target_modules)', source)
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
        post_cleanup_file_check = "required=/opt/self-hosted-ci/overworld-deps/frontend-node-modules/next/dist/server/dev/browser-logs/file-logger.js"
        boot_check = 'inspect_running_sentinels "${published_verifier}" published-verifier-post-start "${expected_sentinel_digests[@]}"'
        self.assertIn(post_cleanup_file_check, source)
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
