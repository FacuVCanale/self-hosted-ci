from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

from github_automation.bakeoff import BakeoffError, HARD_GATES, SCOPED_WEIGHTS, UPSTREAMS, evaluate_bakeoff
from github_automation.host_security import (
    BLOCKED_NETWORK_CIDRS,
    REQUIRED_CHECKS,
    evaluate_host_security,
    evaluate_runner_lifecycle,
    inert_host_evidence,
    validate_wsl_conf,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-08-26T12:00:00Z"
APPROVER = "example-owner"
EXAMPLE_REPOSITORY = "example-org/example-repo"
DIGEST = "sha256:" + "a" * 64


def check(check_id: str, status: str = "pass") -> dict:
    return {"id": check_id, "status": status, "evidence_refs": [f"evidence/{check_id}.log"] if status == "pass" else [], "notes": ""}


def lifecycle(mode: str) -> dict:
    return {
        "jit": True,
        "ephemeral_registration": True,
        "jobs_started": 1,
        "registration_removed": True,
        "workspace_removed": True,
        "token_removed": True,
        "container_removed": True,
        "allocation_removed": True,
        "normal_cancel_attempted_before_force": mode == "force-cancel",
        "terminal_mode": mode,
        "orphan_registrations": 0,
    }


def host_evidence() -> dict:
    return {
        "host_security_schema_version": 1,
        "platform": "wsl2",
        "distro_name": "self-hosted-ci",
        "personal_distro_names": ["Ubuntu"],
        "wsl_conf": "[automount]\nenabled=false\nmountFsTab=false\n[interop]\nenabled=false\nappendWindowsPath=false\n",
        "checks": [check(identifier) for identifier in sorted(REQUIRED_CHECKS)],
        "observed_artifact_kinds": [],
        "network_policy": {
            "default_deny": True,
            "management_separated": True,
            "denied_cidrs": sorted(BLOCKED_NETWORK_CIDRS),
            "denied_service_classes": ["windows-host", "management", "reviewer", "control", "deploy", "local-sockets", "container-api"],
            "proxy_only_egress": True,
            "private_dns_fail_closed": True,
            "loaded_before_registration": True,
            "windows_reboot_verified": True,
            "wsl_reboot_verified": True,
        },
        "runner_lifecycle_runs": [lifecycle(mode) for mode in ("success", "failure", "cancel", "timeout", "force-cancel", "reboot")],
    }


def criterion(identifier: str, status: str) -> dict:
    cls = "hard_gate" if identifier in HARD_GATES else "scoped_capability"
    return {"id": identifier, "class": cls, "status": status, "evidence_refs": [f"evidence/{identifier}.log"] if status == "pass" else [], "notes": ""}


def candidate(candidate_id: str, *, passing: bool = True, score_ids: set[str] | None = None) -> dict:
    hard_status = "pass" if passing else "not_applicable"
    score_ids = score_ids or set()
    criteria = [criterion(identifier, hard_status) for identifier in sorted(HARD_GATES)]
    criteria += [criterion(identifier, "pass" if identifier in score_ids else "not_applicable") for identifier in sorted(SCOPED_WEIGHTS)]
    return {
        "candidate_id": candidate_id,
        "upstream": UPSTREAMS[candidate_id],
        "selected_artifact": {
            "version": "1.0.0", "tag": "v1.0.0", "image_digest": DIGEST, "evidence_digest": DIGEST,
            "signature_verified": True, "sbom_ref": "evidence/sbom.json", "provenance_ref": "evidence/provenance.json",
        } if passing else None,
        "rootful": False if passing else None,
        "rootful_risk_decision": None,
        "maintenance_security": {
            "archived": False, "selected_version_supported": True,
            "last_release_or_maintenance_at": "2026-08-01T00:00:00Z",
            "unmitigated_critical": False, "oldest_unmitigated_high_at": None,
            "upstream_fixed_pin_available": False,
        } if passing else None,
        "criteria": criteria,
        "eligible": passing,
        "scoped_score": sum(SCOPED_WEIGHTS[item] for item in score_ids),
    }


def bakeoff(*, selected: str | None = "fireactions") -> dict:
    candidates = [
        candidate("fireactions", score_ids={"rootless", "personal-jit"}),
        candidate("garm-incus", score_ids={"rootless", "personal-jit"}),
        candidate("myoung34-docker-github-actions-runner", passing=False),
    ]
    return {
        "runner_bakeoff_schema_version": 1,
        "selection_policy_version": 1,
        "evaluated_at": NOW,
        "candidates": candidates,
        "selection": {
            "result": "selected" if selected else "none-pass",
            "candidate_id": selected,
            "reason": "deterministic evaluation",
            "independent_verifier_signoff": {
                "verifier": "independent-reviewer", "signed_at": NOW, "evidence_digest": DIGEST,
            } if selected else None,
        },
    }


class HostSecurityTests(unittest.TestCase):
    def test_s29_exact_wsl_boundary_and_mac_are_fail_closed(self) -> None:
        self.assertEqual((), validate_wsl_conf(host_evidence()["wsl_conf"]))
        self.assertTrue(validate_wsl_conf("[automount]\nenabled=true\n"))
        result = evaluate_host_security(inert_host_evidence("darwin"))
        self.assertFalse(result.enabled)
        self.assertIn("platform-unverified-not-wsl2", result.blockers)

    def test_s27_s30_s55_s56_complete_evidence_enables(self) -> None:
        result = evaluate_host_security(host_evidence())
        self.assertTrue(result.enabled)
        self.assertEqual("verified", result.status)

    def test_s30_s55_prohibited_access_or_network_gap_blocks(self) -> None:
        for mutate, expected in (
            (lambda value: value["observed_artifact_kinds"].append("docker-desktop-socket"), "prohibited-artifact:docker-desktop-socket"),
            (lambda value: value["network_policy"]["denied_cidrs"].remove("100.64.0.0/10"), "network-policy:blocked-cidrs"),
            (lambda value: value["network_policy"].__setitem__("management_separated", False), "network-policy:management_separated"),
        ):
            value = host_evidence(); mutate(value)
            self.assertIn(expected, evaluate_host_security(value).blockers)

    def test_s56_registration_order_and_reboot_proof_are_mandatory(self) -> None:
        for field in ("loaded_before_registration", "windows_reboot_verified", "wsl_reboot_verified"):
            value = host_evidence(); value["network_policy"][field] = False
            self.assertFalse(evaluate_host_security(value).enabled)

    def test_s27_runner_cleanup_force_cancel_and_orphan_are_strict(self) -> None:
        run = lifecycle("force-cancel"); run["normal_cancel_attempted_before_force"] = False
        self.assertIn("runner-lifecycle:force-without-normal-cancel", evaluate_runner_lifecycle(run))
        run = lifecycle("reboot"); run["orphan_registrations"] = 1
        self.assertIn("runner-lifecycle:orphan-registration", evaluate_runner_lifecycle(run))
        run = lifecycle("success"); run["jobs_started"] = 2
        self.assertIn("runner-lifecycle:not-exactly-one-job", evaluate_runner_lifecycle(run))

    def test_inert_cli_is_non_enabling_on_this_host(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/verify-ci-host.py"], cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(3, completed.returncode)
        self.assertFalse(json.loads(completed.stdout)["enabled"])


class BakeoffTests(unittest.TestCase):
    def test_s57_s68_score_and_lexicographic_tie_break(self) -> None:
        result = evaluate_bakeoff(
            bakeoff(), target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
        )
        self.assertEqual("selected", result.result)
        self.assertEqual("fireactions", result.candidate_id)
        self.assertEqual(50, result.candidates[0].scoped_score)

    def test_s57_repository_none_pass_evidence_is_executable(self) -> None:
        document = bakeoff(selected=None)
        schema = json.loads(
            (ROOT / "schemas/runner-manager-bakeoff-v1.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(document)
        result = evaluate_bakeoff(
            document, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
        )
        self.assertEqual("none-pass", result.result)
        self.assertIsNone(result.candidate_id)

    def test_s68_hidden_waiver_and_stored_score_tampering_are_rejected(self) -> None:
        value = bakeoff(); value["candidates"][0]["hard_gate_waiver"] = True
        with self.assertRaises(BakeoffError):
            evaluate_bakeoff(
                value, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
            )
        value = bakeoff(); value["candidates"][0]["scoped_score"] = 99
        with self.assertRaises(BakeoffError):
            evaluate_bakeoff(
                value, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
            )

    def test_s68_stale_maintenance_and_old_high_are_ineligible(self) -> None:
        for changes in (
            {"last_release_or_maintenance_at": "2025-01-01T00:00:00Z"},
            {"oldest_unmitigated_high_at": "2026-01-01T00:00:00Z", "upstream_fixed_pin_available": False},
            {"unmitigated_critical": True},
        ):
            value = bakeoff(selected=None)
            target = value["candidates"][0]
            target["maintenance_security"].update(changes)
            target["eligible"] = False
            result = evaluate_bakeoff(
                value, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
            )
            self.assertFalse(result.candidates[0].eligible)
            self.assertIn("maintenance-security-threshold-invalid", result.candidates[0].blockers)

    def test_s68_rootful_requires_exact_unexpired_configured_approver(self) -> None:
        value = bakeoff(selected=None)
        target = value["candidates"][0]
        target["rootful"] = True
        target["eligible"] = False
        result = evaluate_bakeoff(
            value, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
        )
        self.assertFalse(result.candidates[0].eligible)
        self.assertIn("rootful-risk-decision-invalid", result.candidates[0].blockers)
        target["criteria"] = [
            ({**item, "status": "not_applicable", "evidence_refs": []} if item["id"] == "rootless" else item)
            for item in target["criteria"]
        ]
        target["scoped_score"] -= SCOPED_WEIGHTS["rootless"]
        target["rootful_risk_decision"] = {
            "decision_id": "rootful-runner-risk-v1", "approver": APPROVER, "candidate_id": "fireactions",
            "repositories": [EXAMPLE_REPOSITORY], "mitigations": ["dedicated host"],
            "expires_at": "2026-09-01T00:00:00Z", "revoked": False,
        }
        target["eligible"] = True
        # The other tied candidate wins without sign-off/selection mutation; the
        # point here is that the exact risk record restores candidate eligibility.
        result = evaluate_bakeoff(
            value, target_repository=EXAMPLE_REPOSITORY, required_approver=APPROVER
        )
        self.assertTrue(result.candidates[0].eligible)


if __name__ == "__main__":
    unittest.main()
