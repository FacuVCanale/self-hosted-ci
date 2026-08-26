from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SchemaConfigTests(unittest.TestCase):
    def test_all_json_and_json_compatible_policy_files_parse(self) -> None:
        files = list((ROOT / "schemas").glob("*.json"))
        files += list((ROOT / "policies").glob("*.yaml"))
        files += [ROOT / "decisions/reviewer-provider-v1.yaml", ROOT / "registry/repositories.json"]
        for path in files:
            with self.subTest(path=path):
                json.loads(path.read_text(encoding="utf-8"))

    def test_protocol_schema_is_spec_shape_not_prd_drift(self) -> None:
        schema = json.loads((ROOT / "schemas/execution-trust-protocol-v1.schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        required = set(schema["required"])
        self.assertIn("default_branch", required)
        self.assertIn("claim_deadline", required)
        self.assertIn("execution_deadline", required)
        self.assertNotIn("child_workflow_ref", required)
        self.assertNotIn("event_kind", required)
        self.assertNotIn("idempotency_key", required)

    def test_empty_registry_is_exact_and_hosted_by_absence(self) -> None:
        registry = json.loads((ROOT / "registry/repositories.json").read_text())
        self.assertEqual({}, registry["repositories"])

    def test_validator_checks_normative_spec_manifest_and_remains_non_enabling(self) -> None:
        path = ROOT / "scripts/validate-github-automation.py"
        spec = importlib.util.spec_from_file_location("validate_github_automation", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        report = module.validate(ROOT)
        self.assertTrue(report["valid"], report["errors"])
        self.assertFalse(report["activation_ready"])
        self.assertEqual("unverified", report["external_authority"])
        self.assertEqual("not_provided", report["evidence_bundle"])

    def test_validator_rejects_incompatible_local_merge_semantics(self) -> None:
        path = ROOT / "scripts/validate-github-automation.py"
        spec = importlib.util.spec_from_file_location("validate_github_automation_semantics", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        for incompatible in module.INCOMPATIBLE_LOCAL_MERGE_CLAIMS:
            with self.subTest(incompatible=incompatible):
                errors = module._normative_semantic_errors({"normative.md": incompatible})
                self.assertEqual(
                    [f"normative-local-merge-contradiction:normative.md:{incompatible}"],
                    errors,
                )


if __name__ == "__main__":
    unittest.main()
