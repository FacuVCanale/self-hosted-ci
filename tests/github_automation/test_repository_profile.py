from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import re
import signal
import sys
import time
from unittest import mock

from jsonschema import Draft202012Validator

from github_automation.repository_profile import (
    RepositoryProfileError,
    _run_profile,
    load_profile,
    verify_image_marker,
    verify_source_workflow,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "repository_profiles/overworld/profile.json"
SCRIPT = ROOT / "repository_profiles/overworld/run-overworld-ci.sh"
FONT_MOCK = ROOT / "images/overworld-pr-v1/profile-assets/next-font-google-mocked-responses.cjs"
REPOSITORY = "alethia-earth/Overworld"
PROFILE_ID = "overworld-ci-v1"
INVENTORY_TESTS = {
    "src/database/migration-0072-site-inflight.pg.test.ts",
    "src/modules/inference/inference-run-site-inflight.pg.test.ts",
    "src/modules/inference/inventory-to-report.stage-push.contract.pg.test.ts",
}
E2E_PG_TESTS = {
    "src/modules/organization/invitations/service.pg.test.ts",
    "src/modules/auth/session.pg.test.ts",
    "src/modules/provider/producers/routes.pg.test.ts",
    "src/metrics/mrv-grid-sql.pg.test.ts",
    "src/modules/audit/service.pg.test.ts",
    "src/modules/inference/closure-pin.pg.test.ts",
    "src/modules/inference/mrv-freeze-lock.pg.test.ts",
    "src/audit/routes.pg.test.ts",
    "src/audit/routes-lot-mutations.pg.test.ts",
    "src/audit/routes-profile.pg.test.ts",
    "src/audit/routes-admin-ingest.pg.test.ts",
    "src/modules/portfolio/service.pg.test.ts",
    "src/modules/organization/projects/registry-submissions/service.pg.test.ts",
    "src/modules/observability/series-qc-data.pg.test.ts",
    "src/modules/quantification/flux-provenance.pg.test.ts",
    "src/modules/quantification/declared-deduction-assessments.pg.test.ts",
    "src/modules/inference/methodology-gate-migration.pg.test.ts",
    "src/database/dev-seed/san-joaquin.pg.test.ts",
    "src/modules/inference/series-coverage.pg.test.ts",
    "src/modules/reports/grants.pg.test.ts",
    "src/modules/explore/grants.pg.test.ts",
    "src/modules/dashboard/data/grants.pg.test.ts",
    "src/modules/inference/pushes.pg.test.ts",
    "src/modules/quantification/cycle-activity.pg.test.ts",
    "src/metrics/engine-adoption.pg.test.ts",
    "src/metrics/metrics-mv-gated.pg.test.ts",
    "src/database/migrate.pg.test.ts",
    "src/modules/internal/inference/idempotency.pg.test.ts",
    "src/modules/internal/inference/runs/runs.pg.test.ts",
    "src/modules/internal/cycles/closure-inputs/closure-inputs.pg.test.ts",
    "src/modules/producer/sites/cycles/methodology-profile/service.pg.test.ts",
    "src/modules/producer/sites/cycles/activity-declarations/service.pg.test.ts",
    "src/modules/methodology-obligations/service.pg.test.ts",
    "src/modules/internal/towers/sensor-data/export.pg.test.ts",
}


class RepositoryProfileTests(unittest.TestCase):
    def profile_digest(self, root: Path = ROOT) -> str:
        return hashlib.sha256(
            (root / "repository_profiles/overworld/profile.json").read_bytes()
        ).hexdigest()

    def copy_profile_root(self, destination: Path) -> None:
        shutil.copytree(ROOT / "repository_profiles", destination / "repository_profiles")

    def load(self, root: Path = ROOT):
        return load_profile(
            root,
            repository=REPOSITORY,
            profile_id=PROFILE_ID,
            expected_digest=self.profile_digest(root),
        )

    def test_profile_matches_schema_and_exact_reviewed_contract(self):
        schema = json.loads(
            (ROOT / "schemas/repository-command-profile-v1.schema.json").read_text()
        )
        value = json.loads(PROFILE.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
        profile, script = self.load()
        self.assertEqual(REPOSITORY, profile["repository"])
        self.assertEqual(PROFILE_ID, profile["profile_id"])
        self.assertEqual("overworld-ci-jit-v1", profile["image_marker"])
        self.assertEqual(4294967296, profile["runner_memory_bytes"])
        self.assertEqual(["backend", "frontend", "e2e"], profile["phases"])
        self.assertEqual(".github/workflows/ci.yml", profile["source_workflow_path"])
        self.assertEqual(
            "b829e0b180bd1ae1ecd9809f33e218ac1df6ff9d37935e2ba5ddd98e7d33baa5",
            profile["source_workflow_sha256"],
        )
        self.assertEqual(
            {
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
            },
            profile["dependency_snapshots"],
        )
        self.assertEqual("0.8.22", profile["toolchain"]["uv"])
        self.assertEqual("22.23.2", profile["toolchain"]["node"])
        self.assertEqual(
            "6789de6b434afea00f4107104cd37039102d772e23de8181155ca22b7b56d3c6",
            profile["runner_script_sha256"],
        )
        self.assertEqual(SCRIPT, script)

    def test_profile_digest_repository_profile_and_script_are_all_bound(self):
        with self.assertRaisesRegex(RepositoryProfileError, "digest mismatch"):
            load_profile(
                ROOT,
                repository=REPOSITORY,
                profile_id=PROFILE_ID,
                expected_digest="0" * 64,
            )
        for repository, profile_id in (
            ("alethia-earth/Other", PROFILE_ID),
            (REPOSITORY, "other-profile"),
            ("alethia-earth/*", PROFILE_ID),
        ):
            with self.subTest(repository=repository, profile=profile_id), self.assertRaises(
                RepositoryProfileError
            ):
                load_profile(
                    ROOT,
                    repository=repository,
                    profile_id=profile_id,
                    expected_digest=self.profile_digest(),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_profile_root(root)
            script = root / "repository_profiles/overworld/run-overworld-ci.sh"
            script.write_text(script.read_text() + "\ntrue\n")
            with self.assertRaisesRegex(RepositoryProfileError, "script digest mismatch"):
                self.load(root)

    def test_image_marker_has_exact_fields_and_binds_profile_digest(self):
        profile, _ = self.load()
        digest = self.profile_digest()
        expected = {
            "repository_profile_image_marker_version": 1,
            "repository": REPOSITORY,
            "profile_id": PROFILE_ID,
            "profile_digest": digest,
            "image_marker": "overworld-ci-jit-v1",
            "runner_memory_bytes": 4294967296,
            "toolchain": profile["toolchain"],
            "dependency_snapshots": profile["dependency_snapshots"],
        }
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker.json"
            marker.write_text(json.dumps(expected, sort_keys=True))
            verify_image_marker(marker, profile=profile, profile_digest=digest)
            for key, value in (
                ("repository", "alethia-earth/Other"),
                ("profile_digest", "0" * 64),
                ("image_marker", "other-image"),
                ("runner_memory_bytes", 1),
            ):
                with self.subTest(key=key):
                    changed = dict(expected)
                    changed[key] = value
                    marker.write_text(json.dumps(changed, sort_keys=True))
                    with self.assertRaisesRegex(RepositoryProfileError, "exact profile"):
                        verify_image_marker(marker, profile=profile, profile_digest=digest)
            changed = dict(expected)
            changed["extra"] = True
            marker.write_text(json.dumps(changed))
            with self.assertRaisesRegex(RepositoryProfileError, "fields are not exact"):
                verify_image_marker(marker, profile=profile, profile_digest=digest)

    def test_reviewed_base_workflow_digest_must_match(self):
        profile, _ = self.load()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            subprocess.run(["git", "init", "-q", str(workspace)], check=True)
            subprocess.run(
                ["git", "-C", str(workspace), "config", "user.email", "ci@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(workspace), "config", "user.name", "CI"], check=True
            )
            workflow = workspace / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_bytes(b"reviewed workflow\n")
            subprocess.run(["git", "-C", str(workspace), "add", "."], check=True)
            subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "base"], check=True)
            sha = subprocess.check_output(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"], text=True
            ).strip()
            changed = dict(profile)
            changed["source_workflow_sha256"] = hashlib.sha256(
                b"reviewed workflow\n"
            ).hexdigest()
            verify_source_workflow(changed, base_sha=sha, workspace=workspace)
            changed["source_workflow_sha256"] = "0" * 64
            with self.assertRaisesRegex(RepositoryProfileError, "differs"):
                verify_source_workflow(changed, base_sha=sha, workspace=workspace)

    def test_profile_action_replaces_shell_and_supervisor_preserves_launch_contract(self):
        action = (ROOT / "actions/run-repository-profile/action.yml").read_text()
        self.assertIn('run: exec python3 "$GITHUB_ACTION_PATH/run.py"', action)
        self.assertNotIn('run: python3 "$GITHUB_ACTION_PATH/run.py"', action)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            script = root / "profile.py"
            script.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "print(json.dumps({"
                "'pid': os.getpid(), 'argv': sys.argv, 'cwd': os.getcwd(), "
                "'sentinel': os.environ.get('EXACT_SENTINEL')}))\n"
                "raise SystemExit(7)\n"
            )
            script.chmod(0o755)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; "
                    "from github_automation.repository_profile import _run_profile; "
                    f"raise SystemExit(_run_profile(Path({str(script)!r}), "
                    f"workspace=Path({str(workspace)!r}), "
                    "environment={'EXACT_SENTINEL': 'preserved'}))",
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(7, result.returncode, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual([str(script)], observed["argv"])
            self.assertEqual(str(workspace.resolve()), observed["cwd"])
            self.assertEqual("preserved", observed["sentinel"])

    def test_profile_supervisor_preserves_exact_spawn_contract_and_restores_handlers_on_error(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            script = workspace / "profile.sh"
            environment = {"PROFILE_TESTED_MERGE_SHA": "a" * 40, "EXACT": "value"}
            previous_handlers = {
                signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
            }

            with mock.patch(
                "github_automation.repository_profile.subprocess.Popen",
                side_effect=OSError("spawn blocked for test"),
            ) as popen:
                with self.assertRaisesRegex(OSError, "spawn blocked"):
                    _run_profile(script, workspace=workspace, environment=environment)

            popen.assert_called_once_with(
                [str(script)],
                cwd=workspace,
                env=environment,
                shell=False,
                start_new_session=True,
            )
            self.assertEqual(
                previous_handlers,
                {
                    signum: signal.getsignal(signum)
                    for signum in (signal.SIGINT, signal.SIGTERM)
                },
            )

    def test_profile_supervisor_forwards_pre_spawn_signal_after_process_group_exists(self):
        class Process:
            pid = 424242

            @staticmethod
            def wait() -> int:
                return -signal.SIGTERM

        def spawn(*_args: object, **_kwargs: object) -> Process:
            signal.raise_signal(signal.SIGTERM)
            return Process()

        def observe_group(process_group: int, signum: int) -> None:
            self.assertEqual(424242, process_group)
            if signum == 0:
                raise ProcessLookupError

        with mock.patch(
            "github_automation.repository_profile.subprocess.Popen", side_effect=spawn
        ), mock.patch(
            "github_automation.repository_profile.os.killpg", side_effect=observe_group
        ) as killpg:
            status = _run_profile(
                Path("/profile.sh"), workspace=Path("/workspace"), environment={}
            )

        self.assertEqual(143, status)
        self.assertEqual(
            [mock.call(424242, signal.SIGTERM), mock.call(424242, 0)],
            killpg.call_args_list,
        )

    def test_profile_supervisor_cancellation_runs_trap_and_removes_process_group(self):
        for signum, expected_status in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready = root / "ready"
                cleanup = root / "cleanup"
                script = root / "profile.sh"
                script.write_text(
                    "#!/bin/bash\n"
                    "set -u\n"
                    "cleanup() { printf '%s' \"$1\" > \"$CLEANUP_PATH\"; }\n"
                    "trap 'cleanup 130; exit 130' INT\n"
                    "trap 'cleanup 143; exit 143' TERM\n"
                    "/bin/sleep 300 &\n"
                    "grandchild=$!\n"
                    "printf '%s %s\\n' \"$$\" \"$grandchild\" > \"$READY_PATH\"\n"
                    "wait \"$grandchild\"\n"
                )
                script.chmod(0o755)
                command = (
                    "from pathlib import Path; "
                    "from github_automation.repository_profile import _run_profile; "
                    f"raise SystemExit(_run_profile(Path({str(script)!r}), "
                    f"workspace=Path({str(root)!r}), environment={{"
                    f"'READY_PATH': {str(ready)!r}, 'CLEANUP_PATH': {str(cleanup)!r}}}))"
                )
                entry = subprocess.Popen(
                    [sys.executable, "-c", command],
                    cwd=ROOT,
                    env={**os.environ, "PYTHONPATH": str(ROOT)},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(500):
                    if ready.is_file():
                        break
                    time.sleep(0.01)
                else:
                    entry.kill()
                    self.fail("profile child and grandchild did not become ready")
                leader, grandchild = (int(value) for value in ready.read_text().split())
                os.kill(entry.pid, signum)
                stdout, stderr = entry.communicate(timeout=10)
                self.assertEqual(expected_status, entry.returncode, (stdout, stderr))
                self.assertEqual(str(expected_status), cleanup.read_text())
                for process in (leader, grandchild):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(process, 0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(leader, 0)

    def test_runner_has_fixed_phases_memory_instrumentation_and_no_privileged_installers(self):
        text = SCRIPT.read_text()
        lowered = text.lower().replace(
            "privilege_helper=/usr/bin/sudo",
            "privilege_helper=<verified-non-executable>",
        )
        for phase in ("phase_backend", "phase_frontend", "phase_e2e"):
            self.assertEqual(1, text.count(phase))
        for evidence in (
            "memory.current", "memory.peak", "memory.events", "memory.swap.current",
            "memory.swap.peak", "memory.pressure", "pids.current", "memory.max", "memory.jsonl",
            "MEMORY_FIT_LIMIT_BYTES=3865468928", "oom_kill_delta",
            "MEMORY_HIGH_OVERSHOOT_TOLERANCE_BYTES=4194304",
            "MEMORY_PRESSURE_SOME_LIMIT_PERCENT=10",
            "MEMORY_PRESSURE_FULL_LIMIT_PERCENT=5",
            "memory_high_events_delta", "memory_max_events_delta",
            "memory_pressure_some_delta_usec", "memory_pressure_full_delta_usec",
            "! -w /sys/fs/cgroup/memory.peak", "! -w /sys/fs/cgroup/memory.pressure",
            "sampler_status=0",
            "sampler_status=$?", "sampler_status == 0",
            "high_delta >= 0",
            "pressure_some_delta <= pressure_some_budget",
            "pressure_full_delta <= pressure_full_budget",
            "max_delta == 0",
            "phase_swap_peak == 0",
            "phase_peak < MEMORY_FIT_LIMIT_BYTES + MEMORY_HIGH_OVERSHOOT_TOLERANCE_BYTES",
            "-r /sys/fs/cgroup/memory.current", "-r /sys/fs/cgroup/pids.current",
            '$(cat /sys/fs/cgroup/memory.high) == "$MEMORY_FIT_LIMIT_BYTES"',
            "GIT_NO_REPLACE_OBJECTS=1",
        ):
            self.assertIn(evidence, text)
        for forbidden in (
            "docker",
            "/var/run/docker.sock",
            "sudo",
            "apt-get",
            "apt ",
            "npm ",
            "npx ",
            "bunx ",
            "eval ",
            "source ",
            "bash -c",
            "sh -c",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)
        self.assertIn("privilege_helper=/usr/bin/sudo", text)
        self.assertNotIn("$@", text)
        self.assertNotIn("${{", text)
        self.assertNotIn("find backend", text)
        self.assertEqual(1, text.count("bun install --frozen-lockfile --offline --ignore-scripts"))
        self.assertIn('[[ "$component" == backend ]]', text)
        self.assertIn("node-environment-extensions/console-file.js", text)
        self.assertIn('BUN_INSTALL_CACHE_DIR="$cache" TMPDIR="$temporary"', text)
        self.assertIn('cache="$STATE_ROOT/bun-cache-$component"', text)
        self.assertIn('temporary="$STATE_ROOT/bun-tmp-$component"', text)
        self.assertIn("install_prebaked_node_modules backend", text)
        self.assertIn("install_prebaked_node_modules frontend", text)
        self.assertIn("bun ./node_modules/.bin/eslint --max-warnings 0", text)
        self.assertIn("bun ./node_modules/.bin/tsc --noEmit", text)
        self.assertIn("NODE_ENV=test bun ./node_modules/.bin/jest --ci", text)
        self.assertIn(
            '"$NEXT_NODE" ./node_modules/next/dist/bin/next dev --webpack -p "$FRONTEND_PORT"',
            text,
        )
        self.assertNotIn(
            '"$NEXT_NODE" "$FRONTEND_MODULES/next/dist/bin/next"',
            text,
        )
        self.assertIn("BUN_OPTIONS=--smol bun --smol ./node_modules/.bin/playwright test", text)
        frontend_and_e2e = text[text.index("phase_frontend()") : text.rindex("\nrequire_image_contract\n")]
        self.assertNotIn("bun run lint", frontend_and_e2e)
        self.assertNotIn("bun run typecheck", frontend_and_e2e)
        self.assertNotIn("bun run test -- --ci", frontend_and_e2e)
        self.assertNotIn("bun run dev", frontend_and_e2e)
        self.assertNotIn("bun run --cwd frontend playwright", frontend_and_e2e)
        self.assertIn("sha256sum \"$component/bun.lock\"", text)
        self.assertIn("/opt/ms-playwright/chromium-1217*", text)
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright", text)
        self.assertIn('[[ $(uv --version) == "uv 0.8.22" ]]', text)
        self.assertIn('[[ $(node --version) == v22.23.2 ]]', text)
        self.assertIn('uv --no-config pip check --python "$WATERFALL_ROOT/.venv/bin/python"', text)
        self.assertIn("export UV_OFFLINE=1 UV_NO_SYNC=1", text)
        self.assertNotIn("--runInBand", text)
        self.assertNotIn("bun run build)", text)
        self.assertNotIn('bun ./node_modules/.bin/next dev --webpack -p "$FRONTEND_PORT")', text)
        self.assertIn("start_postgres 16", text)
        self.assertIn("start_postgres 17", text)
        self.assertEqual(1, text.count('-o "-F -c shared_buffers=32MB -k $PGSOCKET -p $port -h 127.0.0.1"'))
        self.assertIn("PG16_DATA", text)
        self.assertIn("PG17_DATA", text)
        self.assertIn("stop_postgres", text)
        self.assertIn("for-each-ref --format='%(refname)' refs/replace", text)
        self.assertIn("! -e .git/commondir", text)
        self.assertIn("worktree_config=.git/config.worktree", text)
        self.assertIn('runner_identity="$(id -u):$(id -g)"', text)
        self.assertIn("$runner_identity:644:83", text)
        self.assertIn(
            "443a5f645c23c3d0c0aa09f634b2ad111d46ef61946b598a2fb311678ab47454",
            text,
        )
        self.assertIn('unlink "$worktree_config"', text)
        self.assertIn('[[ ! -e "$worktree_config" && ! -L "$worktree_config" ]]', text)
        self.assertIn("! -e .git/info/attributes", text)
        self.assertIn("! -e .git/info/sparse-checkout", text)
        self.assertIn("unlink .git/index", text)
        self.assertIn("HEAD^{tree}", text)

    def test_memory_pressure_parser_is_exact_and_fail_closed(self):
        text = SCRIPT.read_text()
        parser = text[
            text.index("read_memory_pressure_total() {") : text.index("\nmemory_sampler() {")
        ].replace("/sys/fs/cgroup/memory.pressure", '"$PRESSURE_FILE"')

        def read(candidate: str, stall: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                pressure = Path(directory) / "memory.pressure"
                pressure.write_text(candidate)
                return subprocess.run(
                    ["bash", "-c", f"{parser}\nread_memory_pressure_total {stall}"],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "PRESSURE_FILE": str(pressure)},
                )

        valid = (
            "some avg10=0.00 avg60=1.25 avg300=2.50 total=12345\n"
            "full avg10=0.00 avg60=0.01 avg300=0.02 total=678\n"
        )
        some = read(valid, "some")
        self.assertEqual(0, some.returncode, some.stderr)
        self.assertEqual("12345", some.stdout)
        full = read(valid, "full")
        self.assertEqual(0, full.returncode, full.stderr)
        self.assertEqual("678", full.stdout)
        for malformed in (
            "some avg10=0 avg60=1.25 avg300=2.50 total=12345\n",
            "some avg10=0.00 avg60=1.25 avg300=2.50 total=not-a-number\n",
            valid + "some avg10=0.00 avg60=0.00 avg300=0.00 total=12346\n",
            "full avg10=0.00 avg60=0.01 avg300=0.02 total=678\n",
        ):
            with self.subTest(malformed=malformed):
                self.assertNotEqual(0, read(malformed, "some").returncode)

    def test_monotonic_clock_parser_requires_exact_uptime_fields(self):
        text = SCRIPT.read_text()
        parser = text[
            text.index("read_monotonic_usec() {") : text.index("\nreset_phase_measurement_state() {")
        ].replace("/proc/uptime", '"$UPTIME_FILE"')

        def read(candidate: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                uptime = Path(directory) / "uptime"
                uptime.write_text(candidate)
                return subprocess.run(
                    ["bash", "-c", f"{parser}\nread_monotonic_usec"],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "UPTIME_FILE": str(uptime)},
                )

        valid = read("123.45 987.65\n")
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertEqual("123450000", valid.stdout)
        largest_safe = read("9223372036854.77 0.00\n")
        self.assertEqual(0, largest_safe.returncode, largest_safe.stderr)
        self.assertEqual("9223372036854770000", largest_safe.stdout)
        for malformed in (
            "123.45\n",
            "123.45 idle\n",
            "123.45 987\n",
            "123.456 987.65\n",
            "123.45 987.654\n",
            "123.45 987.65 extra\n",
            "123.45 987.65\n0.00 0.00\n",
            "123.45  987.65\n",
            "123.45\t987.65\n",
            "9223372036854.78 0.00\n",
            "9223372036855.00 0.00\n",
        ):
            with self.subTest(malformed=malformed):
                self.assertNotEqual(0, read(malformed).returncode)

    def test_phase_measurement_start_publishes_state_only_after_all_baselines(self):
        prefix = SCRIPT.read_text().split("require_image_contract() {", 1)[0]

        def start(*, fail_event: str = "", fail_pressure: str = "",
                  fail_monotonic: bool = False) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                command = prefix + f"""
read_memory_event() {{
  [[ "$1" != "{fail_event}" ]] || return 1
  printf '1'
}}
read_memory_pressure_total() {{
  [[ "$1" != "{fail_pressure}" ]] || return 1
  printf '1'
}}
read_monotonic_usec() {{ {'return 1' if fail_monotonic else "printf '1000000'"}; }}
set +e
start_phase_measurement frontend
start_status=$?
set -e
sentinel_absent=0
[[ ! -e "$STATE_ROOT/memory-frontend.running" ]] && sentinel_absent=1
printf '{{"start_status":%s,"active_phase":"%s","active_sampler_pid":"%s","active_sampler_sentinel":"%s","sentinel_absent":%s}}\n' \
  "$start_status" "$ACTIVE_PHASE" "$ACTIVE_SAMPLER_PID" "$ACTIVE_SAMPLER_SENTINEL" "$sentinel_absent"
exit "$start_status"
"""
                return subprocess.run(
                    ["bash"], input=command, capture_output=True, text=True,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": str(Path(directory) / "runner-temp"),
                        "PROFILE_TESTED_MERGE_SHA": "0" * 40,
                    },
                )

        for case in (
            {"fail_event": "oom"},
            {"fail_event": "max"},
            {"fail_pressure": "some"},
            {"fail_pressure": "full"},
            {"fail_monotonic": True},
        ):
            with self.subTest(case=case):
                failed = start(**case)
                self.assertNotEqual(0, failed.returncode)
                state = json.loads(failed.stdout)
                self.assertEqual(1, state["start_status"])
                self.assertEqual("", state["active_phase"])
                self.assertEqual("", state["active_sampler_pid"])
                self.assertEqual("", state["active_sampler_sentinel"])
                self.assertEqual(1, state["sentinel_absent"])

    def test_phase_memory_guard_uses_monotonic_pressure_slos_and_hard_limits(self):
        prefix = SCRIPT.read_text().split("require_image_contract() {", 1)[0]

        def finish(*, high: int = 10, maximum: int = 20, peak: int = 3865468927,
                   swap_peak: int = 0, sampler_status: int = 0,
                   oom_after: int = 1, oom_kill_after: int = 2,
                   started_usec: int = 1_000_000, finished_usec: int = 2_000_000,
                   pressure_some_start: int = 100, pressure_some_after: int = 100_100,
                   pressure_full_start: int = 50, pressure_full_after: int = 50_050,
                   phase: str = "frontend", report_state: bool = False,
                   fail_event: str = "", fail_pressure: str = "",
                   fail_monotonic: bool = False, fail_cgroup: str = "") -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                finish_command = f"finish_phase_measurement {phase}"
                if report_state:
                    finish_command = f"""set +e
sampler_pid_before=$ACTIVE_SAMPLER_PID
sentinel_before=$ACTIVE_SAMPLER_SENTINEL
finish_phase_measurement {phase}
finish_status=$?
set -e
sampler_reaped=0
sentinel_absent=0
summary_lines=$(wc -l < "$MEMORY_SUMMARY")
if ! kill -0 "$sampler_pid_before" 2>/dev/null; then sampler_reaped=1; fi
if [[ ! -e "$sentinel_before" && ! -L "$sentinel_before" ]]; then sentinel_absent=1; fi
printf '{{"finish_status":%s,"active_phase":"%s","active_sampler_pid":"%s","active_sampler_sentinel":"%s","active_oom":%s,"active_oom_kill":%s,"active_high":%s,"active_max":%s,"active_pressure_some":%s,"active_pressure_full":%s,"active_started_monotonic_usec":%s,"sampler_reaped":%s,"sentinel_absent":%s,"summary_lines":%s}}\\n' \\
  "$finish_status" "$ACTIVE_PHASE" "$ACTIVE_SAMPLER_PID" "$ACTIVE_SAMPLER_SENTINEL" "$ACTIVE_OOM" "$ACTIVE_OOM_KILL" "$ACTIVE_HIGH" "$ACTIVE_MAX" "$ACTIVE_PRESSURE_SOME" "$ACTIVE_PRESSURE_FULL" "$ACTIVE_STARTED_MONOTONIC_USEC" "$sampler_reaped" "$sentinel_absent" "$summary_lines"
exit "$finish_status"
"""
                command = prefix + f"""
ACTIVE_PHASE={phase}
ACTIVE_OOM=1
ACTIVE_OOM_KILL=2
ACTIVE_HIGH=10
ACTIVE_MAX=20
ACTIVE_PRESSURE_SOME={pressure_some_start}
ACTIVE_PRESSURE_FULL={pressure_full_start}
ACTIVE_STARTED_MONOTONIC_USEC={started_usec}
ACTIVE_SAMPLER_SENTINEL="$STATE_ROOT/test.running"
: > "$ACTIVE_SAMPLER_SENTINEL"
(exit {sampler_status}) &
ACTIVE_SAMPLER_PID=$!
read_memory_event() {{
  [[ "$1" != "{fail_event}" ]] || return 1
  case "$1" in
    oom) printf '{oom_after}' ;;
    oom_kill) printf '{oom_kill_after}' ;;
    high) printf '{high}' ;;
    max) printf '{maximum}' ;;
    *) return 1 ;;
  esac
}}
read_memory_pressure_total() {{
  [[ "$1" != "{fail_pressure}" ]] || return 1
  case "$1" in some) printf '{pressure_some_after}' ;; full) printf '{pressure_full_after}' ;; *) return 1 ;; esac
}}
read_monotonic_usec() {{ {'return 1' if fail_monotonic else f"printf '{finished_usec}'"}; }}
read_cgroup_value() {{
  [[ "$1" != "{fail_cgroup}" ]] || return 1
  case "$1" in memory.peak) printf '{peak}' ;; memory.swap.peak) printf '{swap_peak}' ;; *) return 1 ;; esac
}}
{finish_command}
"""
                return subprocess.run(
                    ["bash"],
                    input=command,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": str(Path(directory) / "runner-temp"),
                        "PROFILE_TESTED_MERGE_SHA": "0" * 40,
                    },
                )

        passed = finish()
        self.assertEqual(0, passed.returncode, passed.stderr)
        summary = json.loads(passed.stdout)
        self.assertEqual(0, summary["memory_high_events_delta"])
        self.assertEqual(0, summary["memory_max_events_delta"])
        self.assertEqual(100_000, summary["memory_pressure_some_delta_usec"])
        self.assertEqual(50_000, summary["memory_pressure_full_delta_usec"])
        self.assertEqual(1_000_000, summary["phase_elapsed_monotonic_usec"])
        self.assertEqual(100_000, summary["memory_pressure_some_budget_usec"])
        self.assertEqual(50_000, summary["memory_pressure_full_budget_usec"])
        self.assertEqual(1000, summary["memory_pressure_some_ratio_basis_points"])
        self.assertEqual(500, summary["memory_pressure_full_ratio_basis_points"])
        self.assertEqual(10, summary["memory_pressure_some_limit_percent"])
        self.assertEqual(5, summary["memory_pressure_full_limit_percent"])
        self.assertEqual(4194304, summary["memory_high_overshoot_tolerance_bytes"])
        # Run 34372708368 observed these exact frontend counters. Its old
        # contract did not capture monotonic elapsed time, so the 207,986,207us
        # interval below is the approximate wall-clock interval visible in the
        # GitHub log; new runs emit the exact monotonic interval in their JSON.
        healthy_frontend = finish(
            high=11_120,
            peak=3_867_824_128,
            started_usec=1_000_000,
            finished_usec=208_986_207,
            pressure_some_after=820_031,
            pressure_full_after=675_141,
        )
        self.assertEqual(0, healthy_frontend.returncode, healthy_frontend.stderr)
        high_events_healthy_psi = finish(high=1_000_010)
        self.assertEqual(0, high_events_healthy_psi.returncode, high_events_healthy_psi.stderr)
        self.assertEqual(0, finish(pressure_some_after=100_100).returncode)
        self.assertNotEqual(0, finish(pressure_some_after=100_101).returncode)
        self.assertEqual(0, finish(pressure_full_after=50_050).returncode)
        self.assertNotEqual(0, finish(pressure_full_after=50_051).returncode)
        for case in (
            {"high": 9},
            {"oom_after": 2},
            {"oom_kill_after": 3},
            {"maximum": 21},
            {"peak": 3869663232},
            {"high": 101690, "peak": 3874357248},
            {"swap_peak": 1},
            {"sampler_status": 1},
        ):
            with self.subTest(case=case):
                self.assertNotEqual(0, finish(**case).returncode)

        for case in (
            {"finished_usec": 1_000_000},
            {"finished_usec": 999_999},
            {"pressure_some_after": 99},
            {"pressure_full_after": 49},
        ):
            with self.subTest(clean_state=case):
                failed = finish(**case, report_state=True)
                self.assertNotEqual(0, failed.returncode)
                self.assertEqual(1, len(failed.stdout.splitlines()), failed.stdout)
                state = json.loads(failed.stdout)
                self.assertEqual(1, state["finish_status"])
                self.assertEqual("", state["active_phase"])
                self.assertEqual("", state["active_sampler_pid"])
                self.assertEqual("", state["active_sampler_sentinel"])
                self.assertEqual(1, state["sampler_reaped"])
                self.assertEqual(1, state["sentinel_absent"])
                self.assertEqual(0, state["summary_lines"])
                for key, value in state.items():
                    if key.startswith("active_") and key not in {
                        "active_phase", "active_sampler_pid", "active_sampler_sentinel"
                    }:
                        self.assertEqual(0, value, key)

        for case in (
            {"fail_event": "oom"},
            {"fail_event": "max"},
            {"fail_pressure": "some"},
            {"fail_pressure": "full"},
            {"fail_monotonic": True},
            {"fail_cgroup": "memory.peak"},
            {"fail_cgroup": "memory.swap.peak"},
        ):
            with self.subTest(final_read_failure=case):
                failed = finish(**case, report_state=True)
                self.assertNotEqual(0, failed.returncode)
                self.assertEqual(1, len(failed.stdout.splitlines()), failed.stdout)
                state = json.loads(failed.stdout)
                self.assertEqual(1, state["finish_status"])
                self.assertEqual("", state["active_phase"])
                self.assertEqual("", state["active_sampler_pid"])
                self.assertEqual("", state["active_sampler_sentinel"])
                self.assertEqual(1, state["sampler_reaped"])
                self.assertEqual(1, state["sentinel_absent"])
                self.assertEqual(0, state["summary_lines"])

    def test_backend_service_data_reset_is_exact_guarded_and_idempotent(self):
        text = SCRIPT.read_text()
        helper = text[
            text.index("reset_backend_service_data() {") : text.index("\nstop_local_service() {")
        ]

        def reset(*, drift: bool = False, symlink: bool = False,
                  permissive: bool = False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "state"
                root.mkdir()
                postgres = root / ("other-postgres" if drift else "postgres-16")
                minio = root / "minio"
                backing = root / "postgres-backing"
                if symlink:
                    backing.mkdir(mode=0o700)
                    (backing / "keep").write_text("owned elsewhere")
                    postgres.symlink_to(backing, target_is_directory=True)
                else:
                    postgres.mkdir(mode=0o700)
                    (postgres / "discard").write_text("backend data")
                    if permissive:
                        postgres.chmod(0o755)
                minio.mkdir(mode=0o700)
                (minio / "discard").write_text("backend objects")
                command = f"""
set -euo pipefail
STATE_ROOT={root}
PG16_DATA={postgres}
MINIO_DATA={minio}
stat() {{
  [[ "$1" == -c && "$2" == '%u:%g:%a' ]]
  "$PYTHON" -c 'import os, stat, sys; value=os.stat(sys.argv[1]); print(f"{{value.st_uid}}:{{value.st_gid}}:{{stat.S_IMODE(value.st_mode):o}}")' "$3"
}}
{helper}
reset_backend_service_data
reset_backend_service_data
"""
                completed = subprocess.run(
                    ["bash"],
                    input=command,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "PYTHON": sys.executable},
                )
                observed = {
                    "postgres_exists": postgres.exists(),
                    "postgres_is_symlink": postgres.is_symlink(),
                    "postgres_discard": (postgres / "discard").is_file(),
                    "minio_exists": minio.is_dir(),
                    "minio_discard": (minio / "discard").is_file(),
                    "minio_entries": list(minio.iterdir()) if minio.is_dir() else None,
                    "minio_mode": minio.stat().st_mode & 0o777 if minio.is_dir() else None,
                    "backing_keep": (backing / "keep").is_file(),
                }
                return completed, observed

        completed, observed = reset()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertFalse(observed["postgres_exists"])
        self.assertTrue(observed["minio_exists"])
        self.assertEqual([], observed["minio_entries"])
        self.assertEqual(0o700, observed["minio_mode"])

        completed, observed = reset(drift=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertTrue(observed["postgres_exists"])
        self.assertTrue(observed["postgres_discard"])
        self.assertTrue(observed["minio_discard"])

        completed, observed = reset(symlink=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertTrue(observed["postgres_is_symlink"])
        self.assertTrue(observed["backing_keep"])
        self.assertTrue(observed["minio_discard"])

        completed, observed = reset(permissive=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertTrue(observed["postgres_discard"])
        self.assertTrue(observed["minio_discard"])

    def test_backend_resets_service_data_only_after_services_stop(self):
        text = SCRIPT.read_text()
        backend = text[text.index("phase_backend() {") : text.index("\nphase_frontend() {")]
        reset = backend.index("  reset_backend_service_data\n")
        self.assertLess(backend.index("  stop_local_services\n"), reset)
        self.assertLess(backend.index("  stop_postgres\n"), reset)
        self.assertEqual(1, backend.count("  reset_backend_service_data\n"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "GNU stat contract")
    def test_checkout_worktree_config_is_exactly_normalized(self):
        canonical = (
            b"[core]\n\tsparseCheckout = false\n\tsparseCheckoutCone = false\n"
            b"[index]\n\tsparse = false\n"
        )
        self.assertEqual(83, len(canonical))
        self.assertEqual(
            "443a5f645c23c3d0c0aa09f634b2ad111d46ef61946b598a2fb311678ab47454",
            hashlib.sha256(canonical).hexdigest(),
        )

        def run(candidate: bytes | None, *, mode: int = 0o644, symlink: bool = False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                git = root / ".git"
                git.mkdir()
                target = git / "config.worktree"
                if candidate is not None:
                    if symlink:
                        backing = root / "backing"
                        backing.write_bytes(candidate)
                        target.symlink_to(backing)
                    else:
                        target.write_bytes(candidate)
                        target.chmod(mode)
                command = (
                    f"source <(sed '/^prepare_workspace() {{$/,$d' {SCRIPT}); "
                    "normalize_checkout_worktree_config"
                )
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=root,
                    env={**os.environ, "RUNNER_TEMP": str(root / "runner-temp"), "PROFILE_TESTED_MERGE_SHA": "0" * 40},
                    capture_output=True,
                    text=True,
                )
                return result, target.exists() or target.is_symlink()

        for candidate, mode, symlink, succeeds in (
            (None, 0o644, False, True),
            (canonical, 0o644, False, True),
            (canonical + b"x", 0o644, False, False),
            (canonical.replace(b"false", b"true", 1), 0o644, False, False),
            (canonical, 0o600, False, False),
            (canonical, 0o644, True, False),
        ):
            with self.subTest(candidate=candidate, mode=oct(mode), symlink=symlink):
                result, remains = run(candidate, mode=mode, symlink=symlink)
                self.assertEqual(succeeds, result.returncode == 0, result.stderr)
                self.assertEqual(not succeeds and candidate is not None, remains)

    def test_prebaked_modules_initialization_runs_under_nounset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            component = root / "component"
            prebaked = root / "prebaked"
            component.mkdir()
            prebaked.mkdir()
            (component / "bun.lock").write_text("lock\n")
            prefix = SCRIPT.read_text().split("normalize_checkout_worktree_config() {", 1)[0]
            command = prefix + f"""
sha256sum() {{ printf '%s  %s\\n' expected "$1"; }}
stat() {{ if [[ "$2" == %u ]]; then printf '0\\n'; else printf 'dr-xr-xr-x\\n'; fi; }}
bun() {{ return 0; }}
install_prebaked_node_modules {component} expected {prebaked}
test -d {component}/node_modules
"""
            result = subprocess.run(
                ["bash"],
                input=command,
                env={
                    **os.environ,
                    "RUNNER_TEMP": str(root / "runner-temp"),
                    "PROFILE_TESTED_MERGE_SHA": "0" * 40,
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_exact_reviewed_postgres_tests_are_all_and_only_listed(self):
        text = SCRIPT.read_text()
        observed = re.findall(r"src/[A-Za-z0-9_./-]+\.pg\.test\.ts", text)
        self.assertEqual(INVENTORY_TESTS | E2E_PG_TESTS, set(observed))
        self.assertEqual(len(INVENTORY_TESTS | E2E_PG_TESTS), len(observed))
        inventory_block = text.split("export INVENTORY_REPORT_CONTRACT=true", 1)[1]
        inventory_block = inventory_block.split("local pg_test", 1)[0]
        self.assertEqual(INVENTORY_TESTS, set(re.findall(r"src/[A-Za-z0-9_./-]+\.pg\.test\.ts", inventory_block)))
        self.assertEqual(1, text.count("export INVENTORY_REPORT_CONTRACT=true"))

    def test_e2e_defers_frontend_until_all_pg_regressions_finish(self):
        text = SCRIPT.read_text()
        playwright_function = text[
            text.index("run_playwright_e2e() {") : text.index("\nphase_e2e() {")
        ]
        e2e = text[text.index("phase_e2e() {") : text.index("\nrequire_image_contract\n")]
        first_backend = e2e.index("  start_backend\n")
        initial_backend_stop = e2e.index("  stop_local_service backend\n")
        pg_loop = e2e.index('  for pg_test in "${pg_tests[@]}"; do')
        clean_backend = e2e.index("  start_backend\n", first_backend + 1)
        frontend = e2e.index("  start_frontend\n")
        playwright = e2e.index("run_playwright_e2e")
        self.assertEqual(2, e2e.count("  start_backend\n"))
        self.assertLess(first_backend, initial_backend_stop)
        self.assertLess(initial_backend_stop, pg_loop)
        self.assertLess(pg_loop, clean_backend)
        self.assertLess(clean_backend, frontend)
        self.assertLess(frontend, playwright)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "backend").mkdir()
            (root / "frontend").mkdir()
            trace = root / "trace"
            command = f"""
set -euo pipefail
readonly STATE_ROOT={root / 'state'}
readonly PG17_DATA={root / 'pg17'}
readonly E2E_PGPORT=55433
readonly MINIO_PORT=59002
readonly BACKEND_PORT=3000
readonly FRONTEND_PORT=3001
readonly TRACE={trace}
{playwright_function}
{e2e}
start_postgres() {{ printf 'postgres\n' >> "$TRACE"; }}
start_minio() {{ printf 'minio\n' >> "$TRACE"; }}
start_backend() {{ printf 'backend\n' >> "$TRACE"; }}
stop_local_service() {{ printf 'stop:%s\n' "$1" >> "$TRACE"; }}
start_frontend() {{ printf 'frontend\n' >> "$TRACE"; }}
stop_local_services() {{ printf 'stop:all\n' >> "$TRACE"; }}
stop_postgres() {{ printf 'stop:postgres\n' >> "$TRACE"; }}
bun() {{ printf 'bun:%s:%s\n' "${{BUN_OPTIONS-unset}}" "$*" >> "$TRACE"; }}
phase_e2e
printf 'after:%s\n' "${{BUN_OPTIONS-unset}}" >> "$TRACE"
"""
            result = subprocess.run(
                ["bash"],
                cwd=root,
                input=command,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            events = trace.read_text().splitlines()
            self.assertEqual(["postgres", "minio", "backend", "stop:backend"], events[:4])
            pg_events = [event for event in events if event.startswith("bun:unset:test ")]
            self.assertEqual(len(E2E_PG_TESTS), len(pg_events))
            last_pg = max(events.index(event) for event in pg_events)
            self.assertEqual("backend", events[last_pg + 1])
            self.assertEqual("frontend", events[last_pg + 2])
            self.assertTrue(events[last_pg + 3].startswith("bun:--smol:--smol ./node_modules/.bin/playwright test "))
            self.assertEqual(["stop:all", "stop:postgres", "after:unset"], events[-3:])

    def test_playwright_smol_contract_is_executable_and_propagates_exit_status(self):
        runner = SCRIPT.read_text()
        playwright = runner[
            runner.index("run_playwright_e2e() {") : runner.index("\nphase_e2e() {")
        ]
        self.assertEqual(1, runner.count("BUN_OPTIONS=--smol"))
        self.assertEqual(1, runner.count("bun --smol ./node_modules/.bin/playwright"))

        for expected_status in (0, 23):
            with self.subTest(expected_status=expected_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "frontend").mkdir()
                trace = root / "trace"
                fake_bun = root / "bun"
                fake_bun.write_text(
                    "#!/bin/sh\n"
                    "printf 'BUN_OPTIONS=%s\\n' \"$BUN_OPTIONS\" > \"$TRACE\"\n"
                    "printf 'CI=%s\\n' \"$CI\" >> \"$TRACE\"\n"
                    "printf 'E2E_BASE_URL=%s\\n' \"$E2E_BASE_URL\" >> \"$TRACE\"\n"
                    "printf 'PLAYWRIGHT_BROWSERS_PATH=%s\\n' \"$PLAYWRIGHT_BROWSERS_PATH\" >> \"$TRACE\"\n"
                    "printf 'ARGV=%s\\n' \"$*\" >> \"$TRACE\"\n"
                    "exit \"$FAKE_BUN_EXIT\"\n",
                    encoding="utf-8",
                )
                fake_bun.chmod(0o755)
                command = f"""
set -uo pipefail
readonly FRONTEND_PORT=3001
{playwright}
run_playwright_e2e
status=$?
printf 'BUN_OPTIONS_AFTER=%s\n' "${{BUN_OPTIONS-unset}}"
printf 'STATUS=%s\n' "$status"
"""
                result = subprocess.run(
                    ["bash"],
                    cwd=root,
                    input=command,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": f"{root}:/usr/bin:/bin",
                        "TRACE": str(trace),
                        "FAKE_BUN_EXIT": str(expected_status),
                    },
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(
                    f"BUN_OPTIONS_AFTER=unset\nSTATUS={expected_status}\n",
                    result.stdout,
                )
                self.assertEqual(
                    [
                        "BUN_OPTIONS=--smol",
                        "CI=true",
                        "E2E_BASE_URL=http://localhost:3001",
                        "PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright",
                        "ARGV=--smol ./node_modules/.bin/playwright test e2e/auth-flow.spec.ts e2e/a11y.spec.ts --reporter=list",
                    ],
                    trace.read_text(encoding="utf-8").splitlines(),
                )

    def test_runner_uses_only_the_baked_root_owned_font_asset_path(self):
        runner = SCRIPT.read_text()
        self.assertIn(
            "readonly NEXT_FONT_ASSET_ROOT=/opt/self-hosted-ci/overworld-profile-assets",
            runner,
        )
        self.assertNotIn("SCRIPT_DIR", runner)
        self.assertNotIn("repository_profiles/overworld/fonts", runner)

    def test_next_font_mock_is_exact_scoped_and_fails_closed_on_drift(self):
        expected_urls = {
            "https://fonts.googleapis.com/css2?family=Fragment+Mono:wght@400&display=swap",
            "https://fonts.googleapis.com/css2?family=Geist:wght@100..900&display=swap",
            "https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&display=swap",
        }
        responses = json.loads(
            subprocess.check_output(
                [
                    "node",
                    "-e",
                    "process.stdout.write(JSON.stringify(require(process.argv[1])))",
                    str(FONT_MOCK),
                ],
                text=True,
            )
        )
        self.assertEqual(expected_urls, set(responses))
        expected_fonts = {
            "FragmentMono-Regular.ttf": "0fe011f425873c2e0fc73a189e394e340ad48d2b9a99a576bdeec75cee000460",
            "Geist[wght].ttf": "73894e0448cae90a92b6c2f8732b7bb9acb7b94c418bff559dad4a18e1de9659",
            "GeistMono[wght].ttf": "d00e590b8eb3a59acc329b2d044fd143ae935090b7da33199ebee27cc7de8196",
        }
        observed_fonts = set()
        for css in responses.values():
            lines = css.splitlines()
            self.assertIn("/* latin */", lines)
            self.assertEqual(1, lines.count("  font-display: swap;"))
            matches = [re.search(r"src: url\((.+?)\)", line) for line in lines]
            font_paths = [Path(match.group(1)) for match in matches if match]
            self.assertEqual(1, len(font_paths))
            font = font_paths[0]
            self.assertTrue(font.is_absolute())
            self.assertEqual(FONT_MOCK.parent / "fonts", font.parent)
            observed_fonts.add(font.name)
        self.assertEqual(set(expected_fonts), observed_fonts)

        provenance = (FONT_MOCK.parent / "fonts/README.md").read_text()
        self.assertIn("0cf764bb712367b6079cbb4fd2353e6f54ec6850", provenance)
        for name, expected_sha in expected_fonts.items():
            font = FONT_MOCK.parent / "fonts" / name
            self.assertTrue(font.is_file())
            self.assertFalse(font.is_symlink())
            self.assertEqual(0, font.stat().st_mode & 0o022)
            self.assertEqual(expected_sha, hashlib.sha256(font.read_bytes()).hexdigest())
            self.assertIn(name, provenance)
            self.assertIn(expected_sha, provenance)
        for upstream_path in (
            "ofl/geist/Geist[wght].ttf",
            "ofl/geistmono/GeistMono[wght].ttf",
            "ofl/fragmentmono/FragmentMono-Regular.ttf",
        ):
            self.assertIn(upstream_path, provenance)
        for license_name in ("Geist-OFL.txt", "GeistMono-OFL.txt", "FragmentMono-OFL.txt"):
            license_text = (FONT_MOCK.parent / "fonts" / license_name).read_text()
            self.assertIn("SIL OPEN FONT LICENSE Version 1.1", license_text)
            self.assertIn(license_name, provenance)

        runner = SCRIPT.read_text()
        self.assertEqual(1, runner.count("NEXT_FONT_GOOGLE_MOCKED_RESPONSES="))
        self.assertEqual(1, runner.count("NODE_OPTIONS=--max-old-space-size=1152"))
        self.assertNotIn("NODE_OPTIONS=--max-old-space-size=1024", runner)
        self.assertNotIn("NODE_OPTIONS=--max-old-space-size=1536", runner)
        frontend = runner[runner.index("start_frontend() {") : runner.index("\nphase_e2e() {")]
        self.assertIn('NEXT_FONT_GOOGLE_MOCKED_RESPONSES="$NEXT_FONT_MOCK"', frontend)
        self.assertNotIn("NEXT_FONT_GOOGLE_MOCKED_RESPONSES", runner[: runner.index("start_frontend() {")])
        self.assertLess(frontend.index("require_next_font_mock"), frontend.index('"$NEXT_NODE"'))
        self.assertIn(
            'require_pinned_root_executable "$NEXT_NODE" "$NEXT_NODE_SHA256"',
            frontend,
        )
        self.assertIn(
            'exec env NODE_OPTIONS=--max-old-space-size=1152', frontend
        )
        self.assertIn(
            '"$NEXT_NODE" ./node_modules/next/dist/bin/next dev --webpack -p "$FRONTEND_PORT"',
            frontend,
        )
        self.assertNotIn('$FRONTEND_MODULES/next/dist/bin/next', frontend)
        self.assertNotIn("bun ./node_modules/.bin/next", frontend)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            state = root / "state"
            state.mkdir()
            fake_node = root / "pinned-node"
            fake_node.write_text(
                "#!/bin/sh\n"
                "printf 'NODE_OPTIONS=%s\\n' \"$NODE_OPTIONS\"\n"
                "printf 'ARGV=%s\\n' \"$*\"\n"
            )
            fake_node.chmod(0o755)
            command = f"""
set -euo pipefail
require_next_font_mock() {{ :; }}
require_pinned_root_executable() {{ :; }}
curl() {{ return 0; }}
NEXT_NODE="$FAKE_NODE"
NEXT_NODE_SHA256=unused-by-fake-guard
NEXT_FONT_MOCK=/unused/font-mock.cjs
FRONTEND_PORT=3000
BACKEND_PORT=3001
STATE_ROOT="$FAKE_STATE_ROOT"
{frontend}
start_frontend
wait "$(cat "$STATE_ROOT/frontend.pid")"
cat "$STATE_ROOT/frontend.log"
"""
            result = subprocess.run(
                ["bash"],
                cwd=root,
                input=command,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "FAKE_NODE": str(fake_node),
                    "FAKE_STATE_ROOT": str(state),
                },
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("NODE_OPTIONS=--max-old-space-size=1152", result.stdout)
            self.assertIn(
                "ARGV=./node_modules/next/dist/bin/next dev --webpack -p 3000",
                result.stdout,
            )
        self.assertIn('readonly NEXT_NODE=/usr/local/bin/node', runner)
        self.assertIn(
            'readonly NEXT_NODE_SHA256=3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327',
            runner,
        )
        self.assertIn('readonly NEXT_FONT_ASSET_ROOT=/opt/self-hosted-ci/overworld-profile-assets', runner)
        self.assertIn('[[ -f "$path" && ! -L "$path" ]] || return 1', runner)
        self.assertIn("[[ \"$metadata\" == 0:0:644 ]]", runner)
        self.assertNotIn("$SCRIPT_DIR/next-font-google", runner)

        guard = runner[
            runner.index("require_pinned_root_file() {") : runner.index("\nstart_frontend() {")
        ]
        expected_sha = hashlib.sha256(FONT_MOCK.read_bytes()).hexdigest()
        self.assertIn(f"NEXT_FONT_MOCK_SHA256={expected_sha}", runner)
        for expected_font_sha in expected_fonts.values():
            self.assertIn(expected_font_sha, runner)
        for path_variable, sha_variable in (
            ("NEXT_FONT_MOCK", "NEXT_FONT_MOCK_SHA256"),
            ("GEIST_FONT", "GEIST_FONT_SHA256"),
            ("GEIST_MONO_FONT", "GEIST_MONO_FONT_SHA256"),
            ("FRAGMENT_MONO_FONT", "FRAGMENT_MONO_FONT_SHA256"),
        ):
            self.assertIn(
                f'require_pinned_root_file "${path_variable}" "${sha_variable}"',
                guard,
            )

        def run_guard(candidate: Path, metadata: str = "0:0:644") -> subprocess.CompletedProcess[str]:
            command = f"""
set -euo pipefail
stat() {{ printf '%s\n' "$MOCK_METADATA"; }}
{guard}
require_pinned_root_file "$CANDIDATE" "$EXPECTED_SHA"
"""
            return subprocess.run(
                ["bash"],
                input=command,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "CANDIDATE": str(candidate),
                    "EXPECTED_SHA": expected_sha,
                    "MOCK_METADATA": metadata,
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exact = root / "mock.cjs"
            exact.write_bytes(FONT_MOCK.read_bytes())
            self.assertEqual(0, run_guard(exact).returncode)

            executable = root / "node"
            executable.write_bytes(b"pinned-node-entrypoint")
            executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
            executable_guard = f"""
set -euo pipefail
stat() {{ printf '%s\n' "$MOCK_METADATA"; }}
{guard}
require_pinned_root_executable "$CANDIDATE" "$EXPECTED_SHA"
"""
            for metadata, expected_status in (("0:0:755", 0), ("0:0:775", 1), ("1000:1000:755", 1)):
                result = subprocess.run(
                    ["bash"], input=executable_guard, capture_output=True, text=True,
                    env={
                        **os.environ,
                        "CANDIDATE": str(executable),
                        "EXPECTED_SHA": executable_sha,
                        "MOCK_METADATA": metadata,
                    },
                )
                self.assertEqual(expected_status, result.returncode, (metadata, result.stderr))
            exact.write_bytes(FONT_MOCK.read_bytes() + b"// drift\n")
            self.assertNotEqual(0, run_guard(exact).returncode)
            exact.write_bytes(FONT_MOCK.read_bytes())
            self.assertNotEqual(0, run_guard(exact, "0:0:664").returncode)
            self.assertNotEqual(0, run_guard(exact, "1000:1000:644").returncode)
            link = root / "link.cjs"
            link.symlink_to(exact)
            self.assertNotEqual(0, run_guard(link).returncode)
            self.assertNotEqual(0, run_guard(root).returncode)

    def test_next_16_font_loader_smoke_when_package_is_available(self):
        configured = os.environ.get("SELF_HOSTED_CI_NEXT_NODE_MODULES")
        candidates = [Path(configured)] if configured else []
        candidates.append(Path("/opt/self-hosted-ci/overworld-deps/frontend-node_modules"))
        node_modules = next(
            (
                candidate
                for candidate in candidates
                if (candidate / "next/package.json").is_file()
                and json.loads((candidate / "next/package.json").read_text()).get("version")
                == "16.2.3"
            ),
            None,
        )
        if node_modules is None:
            self.skipTest("Next 16.2.3 node_modules is not available")
        script = r"""
const crypto = require('node:crypto');
const path = require('node:path');
const modules = process.argv[1];
const mockPath = process.argv[2];
const { fetchCSSFromGoogleFonts } = require(path.join(modules, 'next/dist/compiled/@next/font/dist/google/fetch-css-from-google-fonts.js'));
const { findFontFilesInCss } = require(path.join(modules, 'next/dist/compiled/@next/font/dist/google/find-font-files-in-css.js'));
const { fetchFontFile } = require(path.join(modules, 'next/dist/compiled/@next/font/dist/google/fetch-font-file.js'));
const responses = require(mockPath);
(async () => {
  const result = [];
  for (const url of Object.keys(responses)) {
    const css = await fetchCSSFromGoogleFonts(url, 'reviewed font', true);
    const files = findFontFilesInCss(css, ['latin']);
    if (files.length !== 1 || !files[0].preloadFontFile || !path.isAbsolute(files[0].googleFontFileUrl)) process.exit(2);
    const bytes = await fetchFontFile(files[0].googleFontFileUrl, true);
    result.push({
      name: path.basename(files[0].googleFontFileUrl),
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    });
  }
  process.stdout.write(JSON.stringify(result));
})().catch(() => process.exit(3));
"""
        result = subprocess.run(
            ["node", "-e", script, str(node_modules), str(FONT_MOCK)],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "NODE_PATH": str(node_modules),
                "NEXT_FONT_GOOGLE_MOCKED_RESPONSES": str(FONT_MOCK),
            },
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            {
                ("FragmentMono-Regular.ttf", "0fe011f425873c2e0fc73a189e394e340ad48d2b9a99a576bdeec75cee000460"),
                ("Geist[wght].ttf", "73894e0448cae90a92b6c2f8732b7bb9acb7b94c418bff559dad4a18e1de9659"),
                ("GeistMono[wght].ttf", "d00e590b8eb3a59acc329b2d044fd143ae935090b7da33199ebee27cc7de8196"),
            },
            {(item["name"], item["sha256"]) for item in json.loads(result.stdout)},
        )

    def test_workflow_order_is_validator_checkout_scrub_then_pinned_profile_action(self):
        text = (ROOT / "templates/workflows/ci-jit-pilot-child.yml").read_text()
        validator = text.index("id: validate")
        checkout = text.index("uses: actions/checkout@")
        scrub = text.index("--unset-all http.https://github.com/.extraheader")
        action = text.index("uses: FacuVCanale/self-hosted-ci/actions/run-repository-profile@")
        self.assertLess(validator, checkout)
        self.assertLess(checkout, scrub)
        self.assertLess(scrub, action)
        self.assertIn("base-sha: ${{ steps.validate.outputs.base_sha }}", text)
        self.assertIn("tested-merge-sha: ${{ steps.validate.outputs.tested_merge_sha }}", text)
        self.assertNotIn("${{ inputs.repository", text)
        self.assertNotIn("${{ inputs.profile", text)


if __name__ == "__main__":
    unittest.main()
