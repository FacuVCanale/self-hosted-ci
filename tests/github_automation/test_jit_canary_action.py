from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.canary_boundary import CANARY_SCENARIOS, sign_canary_authorization
from github_automation.canary_worker import CANARY_JOB_NAME
from github_automation.crypto import spki_fingerprint


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)
PRIVATE = ed25519.Ed25519PrivateKey.generate()
PUBLIC = PRIVATE.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
FINGERPRINT = spki_fingerprint(PRIVATE.public_key())


def authorization():
    return {
        "schema_version": 1, "purpose": "runner-lifecycle-proof-only",
        "production_activation_authorized": False, "outbound_worker_authorized": False,
        "required_check_authorized": False, "github_contact_authorized": True,
        "runner_registration_authorized": True,
        "repository": "FacuVCanale/self-hosted-ci-sandbox", "repository_id": 123,
        "pull_request": 7, "base_sha": "a" * 40, "head_sha": "b" * 40,
        "tested_merge_sha": "c" * 40,
        "workflow_ref": "FacuVCanale/self-hosted-ci-sandbox/.github/workflows/ci-jit-canary-child.yml@refs/heads/main",
        "dispatch_sha": "d" * 40,
        "garm_entity": {"authority_kind": "personal-repository", "entity_id": "12345678-1234-4123-8123-123456789abc", "entity_name": "sandbox", "runner_group": None},
        "image_alias": "ci-jit", "image_fingerprint": "1" * 64,
        "allocation_signer_fingerprint": "2" * 64, "github_app_config_digest": "3" * 64,
        "live_job_verifier_digest": "4" * 64, "network_policy_digest": "5" * 64,
        "bootstrap_install_receipt_digest": "6" * 64,
        "scenarios": list(CANARY_SCENARIOS), "max_allocations": 6,
        "max_concurrency": 1, "max_jobs_per_allocation": 1,
        "issued_at": NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "nonce": "7" * 32,
    }


def load_action():
    spec = importlib.util.spec_from_file_location("jit_canary_validate", ROOT / "actions/jit-canary-validate/run.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Api:
    def __call__(self, path, token):
        auth = authorization()
        if path.endswith("/pulls/7"):
            return {"number": 7, "state": "open", "base": {"sha": auth["base_sha"]}, "head": {"sha": auth["head_sha"]}, "merge_commit_sha": auth["tested_merge_sha"]}
        if "/actions/workflows/" in path:
            return {"path": ".github/workflows/ci-jit-canary-child.yml", "state": "active"}
        return {"id": 123, "full_name": auth["repository"]}


class JitCanaryActionTests(unittest.TestCase):
    def test_signed_package_binds_scenario_and_live_dispatch(self):
        module = load_action()
        auth = authorization()
        package = {"canary_package_version": 1, "scenario": "success", "runner_label": "wsl-jit-" + "8" * 32, "authorization": sign_canary_authorization(auth, PRIVATE)}
        env = {"GITHUB_REPOSITORY": auth["repository"], "GITHUB_REPOSITORY_ID": "123", "GITHUB_SHA": auth["dispatch_sha"], "GITHUB_WORKFLOW_REF": auth["workflow_ref"], "GITHUB_TOKEN": "token"}
        output = module.validate_package(json.dumps(package).encode(), public_key_pem=PUBLIC, pinned_fingerprint=FINGERPRINT, environment=env, api=Api(), now=lambda: NOW)
        self.assertEqual("success", output["scenario"])
        self.assertEqual(auth["tested_merge_sha"], output["tested_merge_sha"])

    def test_tampering_or_dispatch_drift_fails_closed(self):
        module = load_action()
        auth = authorization()
        signed = sign_canary_authorization(auth, PRIVATE)
        package = {"canary_package_version": 1, "scenario": "success", "runner_label": "wsl-jit-" + "8" * 32, "authorization": signed}
        env = {"GITHUB_REPOSITORY": auth["repository"], "GITHUB_REPOSITORY_ID": "123", "GITHUB_SHA": "e" * 40, "GITHUB_WORKFLOW_REF": auth["workflow_ref"], "GITHUB_TOKEN": "token"}
        with self.assertRaisesRegex(ValueError, "dispatch identity"):
            module.validate_package(json.dumps(package).encode(), public_key_pem=PUBLIC, pinned_fingerprint=FINGERPRINT, environment=env, api=Api(), now=lambda: NOW)
        package["authorization"]["head_sha"] = "f" * 40
        with self.assertRaises(ValueError):
            module.validate_package(json.dumps(package).encode(), public_key_pem=PUBLIC, pinned_fingerprint=FINGERPRINT, environment={**env, "GITHUB_SHA": auth["dispatch_sha"]}, api=Api(), now=lambda: NOW)

    def test_workflow_is_manual_local_six_scenario_and_never_gating(self):
        text = (ROOT / "templates/workflows/ci-jit-canary-child.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertEqual(1, text.count("canary_package:"))
        for scenario in CANARY_SCENARIOS:
            self.assertIn(scenario + ")", text)
        for forbidden in ("checks: write", "statuses: write", "name: ci-gate", "secrets.", "environment: production"):
            self.assertNotIn(forbidden, text)

    def test_workflow_display_job_name_matches_live_observer(self):
        text = (ROOT / "templates/workflows/ci-jit-canary-child.yml").read_text()
        local_job = text.split("  local-canary:\n", 1)[1]
        self.assertIn(f"    name: {CANARY_JOB_NAME}\n", local_job)
        self.assertNotIn("local-jit-canary-${{", local_job)

    def test_renderer_replaces_inert_action_placeholder_with_immutable_sha(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            sha = "9" * 40
            result = subprocess.run(
                [
                    str(ROOT / ".venv/bin/python"),
                    str(ROOT / "scripts/render-consumer-workflows.py"),
                    "--repository", "FacuVCanale/self-hosted-ci",
                    "--sha", sha,
                    "--output", directory,
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            rendered = (Path(directory) / "ci-jit-canary-child.yml").read_text()
            self.assertIn(f"actions/jit-canary-validate@{sha}", rendered)
            self.assertNotIn("@" + "0" * 40, rendered)


if __name__ == "__main__":
    unittest.main()
