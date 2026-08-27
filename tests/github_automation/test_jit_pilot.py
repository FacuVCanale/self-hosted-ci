from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from github_automation.jit_pilot import (
    JitPilotError,
    JitPilotPackageV1,
    PilotTerminalMonitor,
    parse_package_json,
    revalidate_package,
    validation_main,
)


NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]
ALLOCATION = "12345678-1234-4123-8123-123456789abc"
LABEL = "wsl-jit-" + "1" * 32


def package(**changes):
    value = {
        "jit_pilot_package_version": 1,
        "repository": "FacuVCanale/self-hosted-ci-sandbox",
        "repository_id": 123,
        "pr_number": 7,
        "base_branch": "main",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "tested_merge_sha": "c" * 40,
        "workflow_ref": "FacuVCanale/self-hosted-ci-sandbox/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
        "backend": "local",
        "allocation_id": ALLOCATION,
        "runner_label": LABEL,
        "issued_at": NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=10))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    value.update(changes)
    return value


class Reader:
    def __init__(self, mutate=None):
        self.mutate = mutate

    def repository(self):
        value = {
            "id": 123,
            "full_name": package()["repository"],
            "default_branch": "main",
        }
        if self.mutate:
            self.mutate("repository", value)
        return value

    def pull_request(self, number):
        value = {
            "number": 7,
            "state": "open",
            "head": {"sha": "b" * 40},
            "base": {"sha": "a" * 40, "ref": "main", "repo": {"id": 123}},
        }
        if self.mutate:
            self.mutate("pull", value)
        return value

    def workflow(self):
        value = {"path": ".github/workflows/ci-jit-pilot-child.yml", "state": "active"}
        if self.mutate:
            self.mutate("workflow", value)
        return value


class Observer:
    def __init__(self, jobs):
        self.observed_jobs = list(jobs)
        self.calls = 0

    def run(self, run_id):
        value = self.observed_jobs[min(self.calls, len(self.observed_jobs) - 1)]
        return {
            "id": run_id,
            "status": value["status"],
            "conclusion": value["conclusion"],
        }

    def jobs(self, run_id):
        value = self.observed_jobs[min(self.calls, len(self.observed_jobs) - 1)]
        self.calls += 1
        return {
            "total_count": 1,
            "jobs": [
                {
                    "id": 22,
                    "run_id": run_id,
                    "name": "local-quality",
                    "labels": [LABEL],
                    **value,
                }
            ],
        }


class Broker:
    def __init__(self):
        self.calls = []

    def finish(self, allocation_id, outcome):
        self.calls.append(("finish", allocation_id, outcome))

    def prove_clean(self, allocation_id, runner_label):
        self.calls.append(("prove", allocation_id, runner_label))
        return {
            "allocation_id": allocation_id,
            "runner_label": runner_label,
            "state": "cleaned",
            "scale_set_absent": True,
            "runtime_empty": True,
        }


class JitPilotTests(unittest.TestCase):
    def test_installed_terminal_monitor_uses_the_installed_broker_path(self):
        source = (ROOT / "scripts/host/jit-pilot-terminal-monitor.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("/usr/local/lib/self-hosted-ci/garm-allocation-broker.py", source)
        self.assertNotIn(
            "/usr/local/libexec/self-hosted-ci/garm-allocation-broker.py", source
        )
        self.assertIn('"runner_label": self.runner_label', source)

    def test_minimal_package_has_no_gatestore_or_check_claims(self):
        parsed = parse_package_json(json.dumps(package()), now=NOW)
        self.assertIsInstance(parsed, JitPilotPackageV1)
        forbidden = {
            "generation",
            "logical_key",
            "check_run_id",
            "attestation_id",
            "claim_deadline",
        }
        self.assertFalse(forbidden & set(package()))
        hosted = package(backend="github", allocation_id=None, runner_label=None)
        self.assertEqual(
            "github", parse_package_json(json.dumps(hosted), now=NOW).backend
        )

    def test_duplicate_expired_cross_backend_and_unknown_fields_fail_closed(self):
        invalid = (
            package(
                expires_at=NOW.isoformat(timespec="seconds").replace("+00:00", "Z")
            ),
            package(backend="github"),
            {**package(), "generation": 1},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(JitPilotError):
                parse_package_json(json.dumps(value), now=NOW)
        with self.assertRaisesRegex(JitPilotError, "duplicate"):
            parse_package_json(
                '{"jit_pilot_package_version":1,"jit_pilot_package_version":1}', now=NOW
            )

    def test_live_repository_pr_base_head_and_workflow_are_each_revalidated(self):
        parsed = JitPilotPackageV1.from_mapping(package(), now=NOW)
        revalidate_package(parsed, Reader())
        mutations = (
            lambda kind, value: value.update(id=999) if kind == "repository" else None,
            lambda kind, value: (
                value["head"].update(sha="d" * 40) if kind == "pull" else None
            ),
            lambda kind, value: (
                value["base"].update(sha="d" * 40) if kind == "pull" else None
            ),
            lambda kind, value: (
                value.update(path=".github/workflows/other.yml")
                if kind == "workflow"
                else None
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(JitPilotError):
                revalidate_package(parsed, Reader(mutate))

    def test_python_action_validator_writes_only_fixed_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            environment = {
                "JIT_PILOT_PACKAGE": json.dumps(package()),
                "GITHUB_REPOSITORY": package()["repository"],
                "GITHUB_REPOSITORY_ID": "123",
                "GITHUB_TOKEN": "token",
                "GITHUB_OUTPUT": str(output),
            }
            with patch(
                "github_automation.jit_pilot.GitHubApiReader", return_value=Reader()
            ):
                self.assertEqual(0, validation_main(environment, clock=lambda: NOW))
            lines = output.read_text().splitlines()
            self.assertEqual(
                {
                    "backend=local",
                    f"repository={package()['repository']}",
                    "pr_number=7",
                    "base_sha=" + "a" * 40,
                    "head_sha=" + "b" * 40,
                    "tested_merge_sha=" + "c" * 40,
                    f"runner_label={LABEL}",
                },
                set(lines),
            )

    def test_terminal_monitor_finishes_then_proves_exact_cleanup(self):
        broker = Broker()
        sleeps = []
        monitor = PilotTerminalMonitor(
            Observer(
                [
                    {"status": "in_progress", "conclusion": None},
                    {"status": "completed", "conclusion": "success"},
                ]
            ),
            broker,
            sleeps.append,
            lambda: 0,
            timeout_seconds=10,
            poll_seconds=0.5,
        )
        self.assertEqual(
            "success",
            monitor.monitor(
                allocation_id=ALLOCATION, runner_label=LABEL, run_id=11, job_id=22
            ),
        )
        self.assertEqual([0.5], sleeps)
        self.assertEqual(
            [("finish", ALLOCATION, "success"), ("prove", ALLOCATION, LABEL)],
            broker.calls,
        )

    def test_unexpected_terminal_conclusion_is_cleaned_as_failure_then_blocks(self):
        broker = Broker()
        monitor = PilotTerminalMonitor(
            Observer([{"status": "completed", "conclusion": "neutral"}]),
            broker,
            lambda _: None,
            lambda: 0,
        )
        with self.assertRaisesRegex(JitPilotError, "unexpected"):
            monitor.monitor(
                allocation_id=ALLOCATION, runner_label=LABEL, run_id=11, job_id=22
            )
        self.assertEqual(("finish", ALLOCATION, "failure"), broker.calls[0])
        self.assertEqual("prove", broker.calls[1][0])

    def test_workflow_is_separate_non_gating_python_only_and_uses_exact_job_name(self):
        root = Path(__file__).parents[2]
        text = (root / "templates/workflows/ci-jit-pilot-child.yml").read_text()
        self.assertIn("name: non-gating JIT pilot", text)
        self.assertIn("name: local-quality", text)
        self.assertIn(
            "runs-on: ${{ needs.validate-package.outputs.runner_label }}", text
        )
        self.assertIn(
            "actions/jit-pilot-validate@0000000000000000000000000000000000000000", text
        )
        self.assertEqual(
            2, text.count('"refs/pull/${PR_NUMBER}/merge:refs/ci-jit-pilot/merge"')
        )
        self.assertEqual(
            2,
            text.count(
                'test "$(git rev-parse refs/ci-jit-pilot/merge)" = "$EXPECTED_MERGE_SHA"'
            ),
        )
        self.assertEqual(
            2,
            text.count(
                'test "$(git rev-parse refs/ci-jit-pilot/merge^1)" = "$BASE_SHA"'
            ),
        )
        self.assertEqual(
            2,
            text.count(
                'test "$(git rev-parse refs/ci-jit-pilot/merge^2)" = "$HEAD_SHA"'
            ),
        )
        self.assertEqual(2, text.count("run: make test"))
        for forbidden in (
            "child-claim",
            "child-mark-started",
            "child-complete",
            "checks: write",
            "gh api",
            "jq ",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn("There is intentionally no fallback", text)


if __name__ == "__main__":
    unittest.main()
