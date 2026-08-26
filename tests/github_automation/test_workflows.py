from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / "templates" / "workflows"


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
        self.assertIn('GITHUB_API_VERSION: "2022-11-28"', self.text)
        self.assertIn("CI_GATE_CHILD_WORKFLOW: ci-gate-child.yml", self.text)
        self.assertIn('CI_GATE_RETURN_RUN_DETAILS: "true"', self.text)
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
        self.assertIn("types: [opened, reopened, ready_for_review, synchronize]", self.text)
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
        self.assertIn("ref: ${{ needs.validate-package.outputs.tested_sha }}", self.text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_TESTED_SHA"', self.text)

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
        self.assertIn("runs-on: [self-hosted, ci-gate-jit, linux, x64]", self.text)

    def test_s53_marker_precedes_project_dependent_command(self) -> None:
        marker = self.text.index("/opt/github-automation/bin/ci-gate-start --admit-and-mark")
        command = self.text.rindex("run: make test")
        self.assertLess(marker, command)

    def test_s35_child_has_no_deploy_authority_or_secrets(self) -> None:
        self.assertNotIn("environment: production", self.text)
        self.assertNotIn("RAILWAY_", self.text)
        self.assertNotIn("secrets.", self.text)


class ReconcilerAndConsumerBoundaryTests(unittest.TestCase):
    def test_reconciler_has_schedule_and_workflow_run_recovery(self) -> None:
        text = read("ci-gate-reconciler.yml")
        self.assertIn('cron: "*/5 * * * *"', text)
        self.assertIn("workflow_run:", text)
        self.assertIn('workflows: ["ci-gate coordinator control", "ci-gate child attempt"]', text)
        self.assertIn("python -m github_automation.coordinator reconcile", text)
        self.assertNotIn("checks: write", text)
        self.assertNotIn("actions/checkout", text)

    def test_platform_does_not_own_consumer_push_main_or_deploy_workflows(self) -> None:
        names = {path.name for path in WORKFLOWS.glob("*.yml")}
        self.assertEqual({
            "ci-gate-child.yml",
            "ci-gate-coordinator.yml",
            "ci-gate-reconciler.yml",
        }, names)
        combined = "\n".join(read(name) for name in sorted(names))
        self.assertNotIn("deploy-production", combined)
        self.assertNotIn("RAILWAY_TOKEN", combined)
        self.assertNotRegex(combined, r"(?m)^\s*branches:\s*\[main\]\s*$")
        active = list((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(active)
        self.assertTrue(all("0" * 40 not in path.read_text(encoding="utf-8") for path in active))

    def test_s52_platform_never_emits_commit_status(self) -> None:
        combined = "\n".join(
            read(name)
            for name in (
                "ci-gate-coordinator.yml",
                "ci-gate-child.yml",
                "ci-gate-reconciler.yml",
            )
        )
        self.assertNotRegex(combined, re.compile(r"statuses|commit status", re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
