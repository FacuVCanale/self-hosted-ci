from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from github_automation.observability import (
    AppendOnlyAuditLog, ReadinessCriterion, ReadinessMatrix, evidence_bundle,
    invariant_alerts, redact,
)
from github_automation.operator import (
    DISABLE_ORDER, ENABLE_ORDER, OperatorState, compatibility_readiness,
    plan_disable, plan_enable,
)


EXAMPLE_REPOSITORY = "example-org/example-repo"


T = datetime(2026, 8, 26, tzinfo=timezone.utc)


class ObservabilityTests(unittest.TestCase):
    def test_redaction_and_append_only_chain(self) -> None:
        log = AppendOnlyAuditLog()
        first = log.append("dispatch", "repo:pr", {"token": "github_pat_" + "a" * 30, "sha": "a" * 40}, occurred_at=T)
        second = log.append("winner", "repo:pr", {"authorization": "Bearer abc", "winner": "github"}, occurred_at=T)
        self.assertEqual("[REDACTED]", first.details["token"])
        self.assertEqual(first.digest, second.previous_digest)
        AppendOnlyAuditLog(log.as_dict()["records"])
        damaged = log.as_dict()["records"]
        damaged[0]["event"] = "tampered"
        with self.assertRaises(ValueError):
            AppendOnlyAuditLog(damaged)

    def test_invariant_alerts_cover_winner_outbox_authority_and_sla(self) -> None:
        alerts = invariant_alerts({
            "winner_records": [1, 2], "terminal_records": [1], "outbox_records": [],
            "admission_exists": True, "pre_marker_verified": False,
            "terminal_after_deadline_won": True, "success_proof_role": "historical_admission_for_failure",
            "wrong_app_source": True, "fallback_sla_breached": True,
        })
        self.assertEqual({
            "multiple_winners", "terminal_without_outbox", "admission_without_verification",
            "late_terminal_won", "success_from_historical_admission", "wrong_app_source",
            "fallback_sla_breached",
        }, {alert.code for alert in alerts})

    def test_evidence_bundle_is_machine_readable_and_redacted(self) -> None:
        log = AppendOnlyAuditLog()
        log.append("noop", "repo", {}, occurred_at=T)
        readiness = ReadinessMatrix(EXAMPLE_REPOSITORY, (
            ReadinessCriterion("local_unit", "pass", ("72 tests OK",)),
            ReadinessCriterion("github_ruleset", "unverified", blocker="credentials absent"),
        ))
        bundle = evidence_bundle(repository=EXAMPLE_REPOSITORY, audit=log, readiness=readiness,
                                 artifacts={"private_key": "oops", "path": "report.json"}, generated_at=T)
        self.assertFalse(bundle["readiness"]["ready"])
        self.assertEqual("[REDACTED]", bundle["artifacts"]["private_key"])
        json.dumps(bundle)


class OperatorTests(unittest.TestCase):
    def test_s01_s04_s25_absent_or_unverified_never_enables(self) -> None:
        matrix = compatibility_readiness({"repository": "outside/repo"})
        decision = plan_enable(OperatorState("outside/repo"), matrix)
        self.assertEqual("blocked", decision.status)
        self.assertFalse(matrix.ready)
        self.assertEqual(5, len(matrix.as_dict()["external_blockers"]))

    def test_enable_order_exact_and_idempotent(self) -> None:
        ready = compatibility_readiness({"repository": EXAMPLE_REPOSITORY, **{
            key: True for key in ("dedicated_app_required_check", "supply_chain_independent", "push_main_ci", "verify_release", "railway_isolated")
        }})
        state = OperatorState(EXAMPLE_REPOSITORY, external_facts={ENABLE_ORDER[0]: True})
        first = plan_enable(state, ready)
        self.assertEqual(("ready", ENABLE_ORDER[0]), (first.status, first.next_step))
        self.assertEqual(first, plan_enable(state, ready))
        for index, step in enumerate(ENABLE_ORDER):
            state = replace(state, enable_completed=ENABLE_ORDER[:index], external_facts={step: True})
            self.assertEqual(step, plan_enable(state, ready).next_step)
        complete = replace(state, enable_completed=ENABLE_ORDER)
        self.assertEqual("complete", plan_enable(complete, ready).status)

    def test_s26_disable_github_first_fence_smoke_revoke_reconcile(self) -> None:
        state = OperatorState(EXAMPLE_REPOSITORY, ci_mode="local-with-github-fallback")
        for index, step in enumerate(DISABLE_ORDER):
            current = replace(state, disable_completed=DISABLE_ORDER[:index], external_facts={step: True})
            self.assertEqual(step, plan_disable(current).next_step)
        self.assertEqual("complete", plan_disable(replace(state, disable_completed=DISABLE_ORDER)).status)
        with self.assertRaises(ValueError):
            plan_disable(replace(state, disable_completed=("fence_and_cancel_local",)))

    def test_s34_s35_push_main_release_railway_are_required_external_facts(self) -> None:
        matrix = compatibility_readiness({
            "repository": EXAMPLE_REPOSITORY, "dedicated_app_required_check": True,
            "supply_chain_independent": True, "push_main_ci": True,
            "verify_release": None, "railway_isolated": False,
        })
        self.assertFalse(matrix.ready)
        by_id = {item.criterion_id: item.status for item in matrix.criteria}
        self.assertEqual("unverified", by_id["verify_release"])
        self.assertEqual("fail", by_id["railway_isolated"])

    def test_bootstrap_warning_is_explicit(self) -> None:
        decision = plan_disable(OperatorState(EXAMPLE_REPOSITORY))
        self.assertIn("bootstrap repository", decision.warnings[0])

    def test_status_cli_reports_blocked_with_contractual_exit(self) -> None:
        path = Path(__file__).parents[2] / "scripts/github-automation-status.py"
        spec = importlib.util.spec_from_file_location("github_automation_status", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"repository": EXAMPLE_REPOSITORY}), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = module.main([str(state)])
            self.assertEqual(3, code)
            self.assertEqual("blocked", json.loads(output.getvalue())["operator"]["status"])


if __name__ == "__main__":
    unittest.main()
