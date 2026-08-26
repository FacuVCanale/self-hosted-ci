from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[2]


def load_module(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EvidenceValidationNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_module("scripts/validate-github-automation.py", "strict_validator")
        cls.builder = load_module("scripts/build-github-automation-evidence.py", "strict_builder")

    def test_each_schema_bound_instance_rejects_missing_required_field(self) -> None:
        for instance_name, schema_name in self.validator.INSTANCE_SCHEMAS.items():
            instance = json.loads((ROOT / instance_name).read_text(encoding="utf-8"))
            schema = json.loads((ROOT / schema_name).read_text(encoding="utf-8"))
            required = schema.get("required", [])
            self.assertTrue(required, schema_name)
            corrupted = copy.deepcopy(instance)
            corrupted.pop(required[0], None)
            with self.subTest(instance=instance_name), self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(corrupted)

    def _synthetic_evidence_instances(self) -> dict[str, dict]:
        scenarios = self.builder.parse_scenarios()
        digest = "a" * 64
        timestamp = "2026-01-01T00:00:00Z"
        return {
            "evidence/scenario-definitions-v1.json": {
                "schema_version": 1,
                "source": self.builder.TEST_SPEC,
                "source_sha256": digest,
                "scenario_count": 108,
                "scenarios": scenarios,
            },
            "evidence/gate-results-v1.json": {
                "schema_version": 1,
                "captured_at": timestamp,
                "gates": [{
                    "id": "github-automation-tests",
                    "command": ["python", "-m", "unittest"],
                    "cwd": ".",
                    "tool_version": "synthetic-test-tool 1",
                    "started_at": timestamp,
                    "finished_at": timestamp,
                    "exit_code": 0,
                    "result": "passed",
                    "output_path": "evidence/gate-outputs/github-automation-tests.txt",
                    "output_sha256": digest,
                }],
            },
            "evidence/scenario-proof-records-v1.json": {
                "schema_version": 1,
                "matrix_sha256": digest,
                "gate_results_sha256": digest,
                "records": [{
                    "scenario_id": "S01",
                    "selector": ["tests.github_automation.test_registry_policy.test_s01_synthetic"],
                    "result": "passed",
                    "gate_id": "github-automation-tests",
                    "gate_output_sha256": digest,
                    "evidence": [{
                        "path": "tests/github_automation/test_registry_policy.py",
                        "sha256": digest,
                    }],
                }],
            },
        }

    def test_synthetic_private_instances_keep_strict_schema_contracts(self) -> None:
        instances = self._synthetic_evidence_instances()
        for instance_name, instance in instances.items():
            schema_name = self.validator.EVIDENCE_INSTANCE_SCHEMAS[instance_name]
            schema = json.loads((ROOT / schema_name).read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(instance)
            corrupted = copy.deepcopy(instance)
            corrupted.pop(schema["required"][0])
            with self.subTest(instance=instance_name), self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(corrupted)

    def test_bootstrap_uninitialized_is_valid_but_signed_schema_rejects_it(self) -> None:
        instance = json.loads(
            (ROOT / "policies/execution-trust-key-manifest-v1.json").read_text(encoding="utf-8")
        )
        bootstrap = json.loads(
            (ROOT / "schemas/execution-trust-key-manifest-bootstrap-v1.schema.json").read_text(encoding="utf-8")
        )
        signed = json.loads(
            (ROOT / "schemas/execution-trust-key-manifest-v1.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(bootstrap).validate(instance)
        with self.assertRaises(ValidationError):
            Draft202012Validator(signed).validate(instance)

    def test_file_only_selector_and_missing_expected_are_rejected(self) -> None:
        proof_schema = json.loads(
            (ROOT / "schemas/scenario-proof-records-v1.schema.json").read_text(encoding="utf-8")
        )
        proofs = self._synthetic_evidence_instances()["evidence/scenario-proof-records-v1.json"]
        proofs["records"][0]["selector"] = ["tests/github_automation/test_registry_policy.py"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(proof_schema).validate(proofs)

        definition_schema = json.loads(
            (ROOT / "schemas/scenario-definitions-v1.schema.json").read_text(encoding="utf-8")
        )
        definitions = self._synthetic_evidence_instances()["evidence/scenario-definitions-v1.json"]
        definitions["scenarios"][0].pop("expected")
        with self.assertRaises(ValidationError):
            Draft202012Validator(definition_schema).validate(definitions)

    def test_stale_hash_promotion_without_pass_and_unsafe_paths_fail_closed(self) -> None:
        report = self.validator.validate(ROOT)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual("not_provided", report["evidence_bundle"])
        with tempfile.TemporaryDirectory() as directory:
            private_report = self.validator.validate(ROOT, evidence_root=Path(directory))
        self.assertFalse(private_report["valid"])
        self.assertEqual("invalid", private_report["evidence_bundle"])
        self.assertTrue(any(error.startswith("missing-evidence-file:") for error in private_report["errors"]))
        with self.assertRaises(ValueError):
            self.builder.safe_relative("../escape.json")
        with self.assertRaises(ValueError):
            self.builder.safe_relative("/absolute.json")

        proof_schema = json.loads(
            (ROOT / "schemas/scenario-proof-records-v1.schema.json").read_text(encoding="utf-8")
        )
        proofs = self._synthetic_evidence_instances()["evidence/scenario-proof-records-v1.json"]
        proofs["records"][0]["result"] = "failed"
        with self.assertRaises(ValidationError):
            Draft202012Validator(proof_schema).validate(proofs)
        proofs["records"][0]["result"] = "passed"
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "synthetic-proof.txt"
            artifact.write_text("synthetic evidence\n", encoding="utf-8")
            proofs["records"][0]["evidence"][0]["sha256"] = "0" * 64
            self.assertNotEqual(
                proofs["records"][0]["evidence"][0]["sha256"],
                self.validator._sha256(artifact),
            )

    def test_artifact_inventory_is_repo_local_and_excludes_consumer_files(self) -> None:
        paths = self.builder.expected_artifact_paths()
        self.assertIn(self.builder.TEST_SPEC, paths)
        self.assertIn(self.builder.SPEC_MANIFEST, paths)
        self.assertTrue(set(self.builder.NORMATIVE_SPEC_PATHS).issubset(paths))
        self.assertFalse(any(path.startswith(".omx/") for path in paths))
        self.assertNotIn(".github/workflows/ci.yml", paths)
        self.assertNotIn(".github/workflows/deploy-production.yml", paths)
        self.assertNotIn("scripts/verify-release.sh", paths)


if __name__ == "__main__":
    unittest.main()
