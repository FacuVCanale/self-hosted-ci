from __future__ import annotations

from pathlib import Path
import os
import subprocess
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / "templates" / "workflows"
ACTIVE_WORKFLOWS = ROOT / ".github" / "workflows"


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


class CoordinatorWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = read("ci-gate-coordinator.yml")

    def test_s12_s13_exact_tuple_is_owned_by_coordinator(self) -> None:
        self.assertIn("python -m github_automation.coordinator coordinate", self.text)
        self.assertIn("CI_GATE_EVENT_PATH: ${{ github.event_path }}", self.text)
        self.assertIn("cancel-in-progress: false", self.text)

    def test_s15_s45_dispatch_contract_is_explicit(self) -> None:
        self.assertIn('GITHUB_API_VERSION: "2026-03-10"', self.text)
        self.assertIn("CI_GATE_CHILD_WORKFLOW: ci-gate-child.yml", self.text)
        self.assertNotIn("RETURN_RUN_DETAILS", self.text)
        self.assertNotRegex(self.text, r"actions/runs|listWorkflowRuns|workflow-runs")

    def test_s43_automatic_check_has_distinct_name(self) -> None:
        self.assertIn("name: ci-gate coordinator control", self.text)
        self.assertIn("name: ci-gate coordinator (not the required gate)", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s*name:\s*ci-gate\s*$")

    def test_s44_untrusted_pr_data_is_never_executable(self) -> None:
        self.assertIn("pull_request_target:", self.text)
        self.assertNotIn("actions/checkout", self.text)
        for field in ("title", "body", "head.ref", "base.ref", "labels", "filename"):
            with self.subTest(field=field):
                self.assertNotIn("github.event.pull_request." + field, self.text)

    def test_s48_events_and_default_fail_closed_are_exact(self) -> None:
        self.assertIn(
            "types: [opened, reopened, ready_for_review, synchronize]", self.text
        )
        self.assertIn("if: vars.CI_GATE_COORDINATOR_ENABLED == 'true'", self.text)

    def test_s31_s32_coordinator_cannot_write_checks(self) -> None:
        permissions = self.text.split("permissions:", 1)[1].split("concurrency:", 1)[0]
        self.assertNotIn("checks: write", permissions)
        self.assertNotIn("secrets.", self.text)


class ChildWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = read("ci-gate-child.yml")

    def test_s14_s16_package_precedes_detached_checkout_and_head_check(self) -> None:
        validation = self.text.index("Validate package before checkout")
        checkout = self.text.index("Check out exact detached tested merge")
        verify = self.text.index("Verify exact checkout before quality")
        quality = self.text.index("Run canonical quality gate")
        self.assertLess(validation, checkout)
        self.assertLess(checkout, verify)
        self.assertLess(verify, quality)
        self.assertIn(
            "ref: ${{ needs.validate-package.outputs.tested_sha }}", self.text
        )
        self.assertIn(
            'test "$(git rev-parse HEAD)" = "$EXPECTED_TESTED_SHA"', self.text
        )

    def test_s15_supports_only_versioned_call_or_exact_dispatch_package(self) -> None:
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("workflow_call:", self.text)
        self.assertEqual(2, self.text.count("protocol_package:"))
        self.assertIn("python -m github_automation.coordinator child", self.text)

    def test_s32_s51_child_has_no_check_write_or_ci_gate_job_name(self) -> None:
        permissions = self.text.split("permissions:", 1)[1].split("jobs:", 1)[0]
        self.assertEqual("contents: read", permissions.strip())
        self.assertNotIn("checks: write", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s*name:\s*ci-gate\s*$")

    def test_s48_local_is_double_gated_and_hosted_is_default_backend(self) -> None:
        self.assertIn("needs.validate-package.outputs.backend == 'github'", self.text)
        self.assertIn("needs.validate-package.outputs.backend == 'local'", self.text)
        self.assertIn("vars.CI_GATE_LOCAL_AUTHORITY_ENABLED == 'true'", self.text)
        self.assertIn(
            "runs-on: ${{ needs.validate-package.outputs.runner_label }}", self.text
        )
        self.assertIn("name: local-quality", self.text)
        self.assertIn(
            "CI_GATE_TRUSTED_TESTED_SHA: ${{ needs.validate-package.outputs.tested_sha }}",
            self.text,
        )
        self.assertNotRegex(self.text, r"runs-on:\s*(?:wsl-jit|\[[^\]]*wsl-jit)")

    def test_s53_marker_precedes_project_dependent_command(self) -> None:
        marker = self.text.index("ACTIONS_RUNNER_HOOK_JOB_STARTED")
        command = self.text.rindex("run: make test")
        self.assertLess(marker, command)

    def test_s35_child_has_no_deploy_authority_or_secrets(self) -> None:
        self.assertNotIn("environment: production", self.text)
        self.assertNotIn("RAILWAY_", self.text)
        self.assertNotIn("secrets.", self.text)


class ReconcilerAndConsumerBoundaryTests(unittest.TestCase):
    def test_reconciler_has_schedule_and_workflow_run_recovery(self) -> None:
        text = read("ci-gate-reconciler.yml")
        self.assertIn('GITHUB_API_VERSION: "2026-03-10"', text)
        self.assertIn('cron: "*/5 * * * *"', text)
        self.assertIn("workflow_run:", text)
        self.assertIn(
            'workflows: ["ci-gate coordinator control", "ci-gate child attempt"]', text
        )
        self.assertIn("python -m github_automation.coordinator reconcile", text)
        self.assertNotIn("checks: write", text)
        self.assertNotIn("actions/checkout", text)

    def test_platform_does_not_own_consumer_push_main_or_deploy_workflows(self) -> None:
        names = {path.name for path in WORKFLOWS.glob("*.yml")}
        self.assertEqual(
            {
                "ci-gate-child.yml",
                "ci-gate-coordinator.yml",
                "ci-gate-reconciler.yml",
                "ci-jit-canary-child.yml",
                "ci-jit-pilot-child.yml",
            },
            names,
        )
        combined = "\n".join(read(name) for name in sorted(names))
        self.assertNotIn("deploy-production", combined)
        self.assertNotIn("RAILWAY_TOKEN", combined)
        self.assertNotRegex(combined, r"(?m)^\s*branches:\s*\[main\]\s*$")
        active = list((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(active)
        self.assertTrue(
            all("0" * 40 not in path.read_text(encoding="utf-8") for path in active)
        )

    def test_s52_platform_never_emits_commit_status(self) -> None:
        combined = "\n".join(
            read(name)
            for name in (
                "ci-gate-coordinator.yml",
                "ci-gate-child.yml",
                "ci-gate-reconciler.yml",
            )
        )
        self.assertNotRegex(
            combined, re.compile(r"statuses|commit status", re.IGNORECASE)
        )


class HostedReusableGateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (ACTIVE_WORKFLOWS / "ci-gate.yml").read_text(encoding="utf-8")

    def test_base_and_local_merge_policy_are_server_canonical_and_not_caller_inputs(
        self,
    ) -> None:
        inputs = self.text.split("jobs:", 1)[0]
        self.assertNotIn("tested_merge_sha:", inputs)
        self.assertNotIn("base_sha:", inputs)
        acquire_payload = self.text.split(
            "Prepare Check and acquire hosted gate generation atomically", 1
        )[1]
        acquire_payload = acquire_payload.split("  quality:", 1)[0]
        self.assertNotIn("--arg tested_merge_sha", acquire_payload)
        self.assertNotIn("--arg base_sha", acquire_payload)
        self.assertIn("printf 'base_sha=%s", acquire_payload)
        self.assertIn("printf 'head_sha=%s", acquire_payload)
        self.assertIn("printf 'merge_policy_version=%s", acquire_payload)
        self.assertIn("printf 'runner_image=%s", acquire_payload)

    def test_acquire_retries_only_retryable_canonical_unavailability(self) -> None:
        acquire = self.text.split(
            "Prepare Check and acquire hosted gate generation atomically", 1
        )[1]
        acquire = acquire.split("  quality:", 1)[0]
        self.assertIn("for attempt in 1 2", acquire)
        self.assertIn('"$status" == 503', acquire)
        self.assertIn("canonical_pull_request_unavailable", acquire)
        self.assertIn("/^retry-after:/", acquire)
        self.assertIn('sleep "$retry_after"', acquire)
        self.assertIn("--connect-timeout 5 --max-time 30", acquire)
        self.assertIn('"$retry_after" -gt 180', acquire)
        self.assertEqual(1, acquire.count('payload="$(jq'))

    def test_quality_builds_exact_local_ort_merge_without_oidc_or_file_protocol(
        self,
    ) -> None:
        quality = self.text.split("  quality:", 1)[1].split("  finalize:", 1)[0]
        self.assertIn("ref: ${{ needs.acquire.outputs.base_sha }}", quality)
        self.assertIn("refs/pull/${PR_NUMBER}/head:refs/ci-gate/head", quality)
        self.assertIn('git merge -s ort --no-ff --no-commit "$HEAD_SHA"', quality)
        self.assertIn('git_version="$(git --version)"', quality)
        self.assertNotIn("git version 2.51.0", quality)
        self.assertIn('test "$EXPECTED_RUNNER_IMAGE" = ubuntu-24.04', quality)
        self.assertIn(
            'git commit-tree "$tested_tree_sha" -p "$BASE_SHA" -p "$HEAD_SHA"', quality
        )
        self.assertIn(
            'merge_base_sha="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"', quality
        )
        self.assertIn('test "$(git rev-parse HEAD^1)" = "$BASE_SHA"', quality)
        self.assertIn('test "$(git rev-parse HEAD^2)" = "$HEAD_SHA"', quality)
        self.assertIn(
            'test "$(git rev-parse HEAD^{tree})" = "$tested_tree_sha"', quality
        )
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", quality)
        self.assertIn("GIT_ATTR_NOSYSTEM=1", quality)
        self.assertIn("core.attributesFile /dev/null", quality)
        self.assertIn(
            "ci-gate-toolchain-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}", quality
        )
        self.assertIn('test "$(git --version)" = "$EXPECTED_GIT_VERSION"', quality)
        self.assertIn('test ! -L "$TOOLCHAIN_SENTINEL"', quality)
        self.assertIn(
            "TOOLCHAIN_SENTINEL_DIGEST: ${{ steps.toolchain.outputs.sentinel_digest }}",
            quality,
        )
        self.assertIn("protocol.file.allow never", quality)
        self.assertNotIn("protocol.file.allow always", quality)
        self.assertNotIn("id-token: write", quality)
        self.assertNotIn("secrets.", quality)

    def test_host_attributes_are_disabled_by_the_executable_merge_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            hostile_attributes = repo / "host-attributes"
            hostile_attributes.write_text("*.txt merge=ours\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "config",
                    "--local",
                    "core.attributesFile",
                    str(hostile_attributes),
                ],
                cwd=repo,
                check=True,
            )
            before = subprocess.run(
                ["git", "check-attr", "merge", "--", "sample.txt"],
                cwd=repo,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            self.assertEqual("sample.txt: merge: ours", before)

            env = {
                **os.environ,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
            }
            subprocess.run(
                ["git", "config", "--local", "core.attributesFile", "/dev/null"],
                cwd=repo,
                check=True,
                env=env,
            )
            after = subprocess.run(
                ["git", "check-attr", "merge", "--", "sample.txt"],
                cwd=repo,
                check=True,
                text=True,
                capture_output=True,
                env=env,
            ).stdout.strip()
            self.assertEqual("sample.txt: merge: unspecified", after)

    def test_git_version_is_observed_dynamically_and_matches_evidence_contract(
        self,
    ) -> None:
        observed = subprocess.run(
            ["git", "--version"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.assertRegex(
            observed,
            r"^git version [0-9]+\.[0-9]+\.[0-9]+(?:\.[A-Za-z0-9.-]+)?(?: \(Apple Git-[0-9]+\))?$",
        )
        self.assertIn(
            "git_version: ${{ steps.toolchain.outputs.git_version }}", self.text
        )
        self.assertIn(
            "GIT_VERSION: ${{ needs.quality.outputs.git_version }}", self.text
        )

    def test_conflict_or_unrelated_history_fails_quality_without_running_command(
        self,
    ) -> None:
        quality = self.text.split("  quality:", 1)[1].split("  finalize:", 1)[0]
        self.assertIn("continue-on-error: true", quality)
        self.assertIn("if: steps.merge.outcome == 'success'", quality)
        self.assertIn(
            'if [[ "$CHECKOUT" == success && "$MERGE" == success && "$EXECUTE" == success ]]',
            quality,
        )
        self.assertIn('test "$conclusion" = success', quality)

    def test_finalize_binds_local_merge_evidence(self) -> None:
        finalize = self.text.split("  finalize:", 1)[1]
        for field in (
            "merge_policy_version",
            "merge_base_sha",
            "tested_tree_sha",
            "local_commit_sha",
            "command_digest",
            "git_version",
            "runner_image",
        ):
            self.assertIn(field, finalize)
        self.assertIn("ci-gate-local-ort-evidence-v1", finalize)
        self.assertNotIn("inputs.tested_merge_sha", self.text)


if __name__ == "__main__":
    unittest.main()
