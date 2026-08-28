from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from github_automation.canary_boundary import CANARY_SCENARIOS, authorization_digest, sign_canary_authorization
from github_automation.crypto import canonicalize_jcs
from tests.github_automation.test_canary_boundary import PRIVATE, authorization


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/build-wsl-jit-lifecycle-evidence.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_builder", SCRIPT)
BUILDER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BUILDER)


def digest_record(value):
    return hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def proof(auth, scenario, index):
    value = {
        "authorization_digest": authorization_digest(auth),
        "nonce": auth["nonce"],
        "scenario": scenario,
        "allocation_id": f"00000000-0000-4000-8000-{index:012d}",
        "scale_set_id": "42",
        "scale_set_name": f"canary-{scenario}",
        "run_id": 100 + index,
        "run_attempt": 1,
        "job_id": 200 + index,
        "runner_name": f"runner-{scenario}",
        "repository": auth["repository"],
        "repository_id": auth["repository_id"],
        "dispatch_sha": auth["dispatch_sha"],
        "head_sha": auth["head_sha"],
        "tested_merge_sha": auth["tested_merge_sha"],
        "image_fingerprint": auth["image_fingerprint"],
        "network_policy_digest": auth["network_policy_digest"],
        "github_app_config_digest": auth["github_app_config_digest"],
        "allocation_signer_fingerprint": auth["allocation_signer_fingerprint"],
        "reserved_at": "2026-08-28T12:00:00Z",
        "started_at": "2026-08-28T12:00:01Z",
        "finished_at": "2026-08-28T12:00:05Z",
        "jobs_started": 1,
        "conclusion": scenario,
        "normal_cancel_receipt": {"operation_id": "normal", "observed_at": "2026-08-28T12:00:02Z", "receipt_digest": "8" * 64} if scenario in {"cancel", "force-cancel"} else None,
        "force_cancel_receipt": {"operation_id": "force", "observed_at": "2026-08-28T12:00:03Z", "receipt_digest": "9" * 64} if scenario == "force-cancel" else None,
        "cleanup_record": {"registration_removed": True, "workspace_removed": True, "token_removed": True, "container_removed": True, "allocation_removed": True, "cleanup_digest": "a" * 64},
        "garm_inventory_post": {"remaining": 0, "inventory_digest": "b" * 64},
        "incus_inventory_post": {"remaining": 0, "inventory_digest": "c" * 64},
        "github_inventory_post": {"remaining": 0, "inventory_digest": "d" * 64},
    }
    value["proof_digest"] = digest_record(value)
    return value


class LifecycleProofBuilderTests(unittest.TestCase):
    def test_builds_exact_six_scenario_schema_valid_set(self):
        auth = sign_canary_authorization(authorization(), PRIVATE)
        proofs = [proof(auth, scenario, index) for index, scenario in enumerate(CANARY_SCENARIOS, 1)]
        result = BUILDER.build(auth, proofs)
        schema = json.loads((ROOT / "schemas/runner-lifecycle-proof-v1.schema.json").read_text())
        Draft202012Validator(schema).validate(result)
        self.assertEqual(list(CANARY_SCENARIOS), [item["scenario"] for item in result["proofs"]])

    def test_rejects_duplicates_cross_binding_dirty_cleanup_and_force_without_normal(self):
        auth = sign_canary_authorization(authorization(), PRIVATE)
        baseline = [proof(auth, scenario, index) for index, scenario in enumerate(CANARY_SCENARIOS, 1)]
        mutations = []
        duplicate = [dict(item) for item in baseline]; duplicate[1]["allocation_id"] = duplicate[0]["allocation_id"]; duplicate[1]["proof_digest"] = digest_record({k:v for k,v in duplicate[1].items() if k != "proof_digest"}); mutations.append(duplicate)
        crossed = [dict(item) for item in baseline]; crossed[0]["head_sha"] = "e" * 40; crossed[0]["proof_digest"] = digest_record({k:v for k,v in crossed[0].items() if k != "proof_digest"}); mutations.append(crossed)
        dirty = [dict(item) for item in baseline]; dirty[0] = {**dirty[0], "garm_inventory_post": {"remaining": 1, "inventory_digest": "b" * 64}}; dirty[0]["proof_digest"] = digest_record({k:v for k,v in dirty[0].items() if k != "proof_digest"}); mutations.append(dirty)
        missing_cancel = [dict(item) for item in baseline]; missing_cancel[4]["normal_cancel_receipt"] = None; missing_cancel[4]["proof_digest"] = digest_record({k:v for k,v in missing_cancel[4].items() if k != "proof_digest"}); mutations.append(missing_cancel)
        for records in mutations:
            with self.subTest(records=records), self.assertRaises(BUILDER.LifecycleProofError):
                BUILDER.build(auth, records)


if __name__ == "__main__":
    unittest.main()
