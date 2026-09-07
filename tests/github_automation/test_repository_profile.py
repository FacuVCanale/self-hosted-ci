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
import sys

from jsonschema import Draft202012Validator

from github_automation.repository_profile import (
    RepositoryProfileError,
    load_profile,
    verify_image_marker,
    verify_source_workflow,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "repository_profiles/overworld/profile.json"
SCRIPT = ROOT / "repository_profiles/overworld/run-overworld-ci.sh"
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
            "memory.swap.peak", "pids.current", "memory.max", "memory.jsonl",
            "MEMORY_FIT_LIMIT_BYTES=3865470566", "oom_kill_delta",
            "! -w /sys/fs/cgroup/memory.peak", "sampler_status=0",
            "sampler_status=$?", "(( sampler_status == 0 ))",
            "-r /sys/fs/cgroup/memory.current", "-r /sys/fs/cgroup/pids.current",
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
        self.assertEqual(1, text.count("bun install --frozen-lockfile --offline"))
        self.assertIn('BUN_INSTALL_CACHE_DIR="$cache" TMPDIR="$temporary"', text)
        self.assertIn('cache="$STATE_ROOT/bun-cache-$component"', text)
        self.assertIn('temporary="$STATE_ROOT/bun-tmp-$component"', text)
        self.assertIn("install_prebaked_node_modules backend", text)
        self.assertIn("install_prebaked_node_modules frontend", text)
        self.assertIn("sha256sum \"$component/bun.lock\"", text)
        self.assertIn("/opt/ms-playwright/chromium-1217*", text)
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright", text)
        self.assertIn('[[ $(uv --version) == "uv 0.8.22" ]]', text)
        self.assertNotIn("--runInBand", text)
        self.assertNotIn("bun run build)", text)
        self.assertIn("bun run dev)", text)
        self.assertIn("start_postgres 16", text)
        self.assertIn("start_postgres 17", text)
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
