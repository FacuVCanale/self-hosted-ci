#!/usr/bin/env python3
"""Validate the public distribution and, when supplied, a private evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from github_automation.registry import Registry  # noqa: E402

FORMAT_CHECKER = FormatChecker()
EXPECTED_IDS = tuple(f"S{number:02d}" for number in range(1, 109))
SPEC_MANIFEST = "docs/spec/manifest-self-hosted-github-automation.json"
NORMATIVE_SPEC_PATHS = (
    "docs/spec/spec-self-hosted-github-automation.md",
    "docs/spec/prd-self-hosted-github-automation.md",
    "docs/spec/review-self-hosted-github-automation.md",
    "docs/spec/test-spec-self-hosted-github-automation.md",
)
INCOMPATIBLE_LOCAL_MERGE_CLAIMS = (
    "tested_sha=check_target_sha=head_sha",
    "check_target_sha == tested_merge_sha",
    "assert pr check target and tested sha both equal",
    "exact synthetic merge sha",
    "github deterministic local ort merge sha",
    "github's deterministic local ort merge sha",
    "github's mutable deterministic local ort merge sha",
    "ci-gate` routes only the canonical quality workload across local/fallback and targets the current deterministic local ort merge",
)

INSTANCE_SCHEMAS = {
    "registry/repositories.json": "schemas/repository-registry-v1.schema.json",
    "policies/execution-trust-key-manifest-v1.json": "schemas/execution-trust-key-manifest-bootstrap-v1.schema.json",
}

EVIDENCE_INSTANCE_SCHEMAS = {
    "evidence/runner-manager-bakeoff-v1.json": "schemas/runner-manager-bakeoff-v1.schema.json",
    "evidence/scenario-definitions-v1.json": "schemas/scenario-definitions-v1.schema.json",
    "evidence/gate-results-v1.json": "schemas/gate-results-v1.schema.json",
    "evidence/scenario-proof-records-v1.json": "schemas/scenario-proof-records-v1.schema.json",
}


def _normative_semantic_errors(documents: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for name, text in documents.items():
        lowered = text.lower()
        for claim in INCOMPATIBLE_LOCAL_MERGE_CLAIMS:
            if claim in lowered:
                errors.append(f"normative-local-merge-contradiction:{name}:{claim}")
    return errors

REQUIRED_FILES = (
    *INSTANCE_SCHEMAS,
    SPEC_MANIFEST, *NORMATIVE_SPEC_PATHS,
    "policies/execution-trust-attestation-authority-v1.yaml",
    "policies/ci-gate-authority-v1.yaml", "policies/runner-network-v1.yaml",
    "schemas/exact-sha-attestation-v1.schema.json",
    "schemas/execution-trust-key-manifest-v1.schema.json",
    "schemas/execution-trust-protocol-v1.schema.json",
    "runbooks/attestation-key-bootstrap.md", "runbooks/attestation-key-rotation.md",
    "runbooks/attestation-key-compromise.md", "evidence/README.md",
)

EVIDENCE_REQUIRED_FILES = (
    *EVIDENCE_INSTANCE_SCHEMAS,
    "evidence/runner-manager-bakeoff-v1.md", "evidence/scenario-matrix-v1.json",
    "evidence/manifest-v1.json", "evidence/adversarial-verification-v1.md",
    "evidence/adversarial-verification-v2.md", "evidence/secret-scan-triage-v1.json",
    "evidence/gitleaks-report-v1.json",
)


def _json(artifact_path: Path) -> Any:
    return json.loads(artifact_path.read_text(encoding="utf-8"))


def _sha256(artifact_path: Path) -> str:
    return hashlib.sha256(artifact_path.read_bytes()).hexdigest()


def _safe_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("path is not a string")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or value != candidate.as_posix():
        raise ValueError(f"unsafe path: {value!r}")
    return value


def _load_builder(root: Path):
    spec = importlib.util.spec_from_file_location("evidence_builder", root / "scripts/build-github-automation-evidence.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load evidence builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


def _schema_validate(instance: object, schema: object) -> None:
    Draft202012Validator(schema, format_checker=FORMAT_CHECKER).validate(instance)


def _artifact(root: Path, evidence_root: Path | None, name: str) -> Path:
    safe = _safe_path(name)
    if safe == "evidence" or safe.startswith("evidence/"):
        if evidence_root is None:
            raise ValueError("private evidence root was not provided")
        suffix = PurePosixPath(safe).relative_to("evidence")
        return evidence_root.joinpath(*suffix.parts)
    return root / safe


def validate(root: Path = ROOT, *, evidence_root: Path | None = None) -> dict[str, object]:
    root = root.resolve()
    evidence_root = evidence_root.resolve() if evidence_root is not None else None
    errors: list[str] = []
    errors.extend(f"missing-required-file:{name}" for name in REQUIRED_FILES if not (root / name).is_file())
    if evidence_root is not None:
        errors.extend(
            f"missing-evidence-file:{name}"
            for name in EVIDENCE_REQUIRED_FILES
            if not _artifact(root, evidence_root, name).is_file()
        )

    schemas: dict[str, object] = {}
    for schema_path in sorted((root / "schemas").glob("*.json")):
        relative = str(schema_path.relative_to(root))
        try:
            schema = _json(schema_path)
            Draft202012Validator.check_schema(schema)
            schemas[relative] = schema
        except (OSError, json.JSONDecodeError, SchemaError) as exc:
            errors.append(f"schema-invalid:{relative}:{exc}")

    for instance_name, schema_name in INSTANCE_SCHEMAS.items():
        try:
            _schema_validate(_json(root / instance_name), schemas[schema_name])
        except (OSError, json.JSONDecodeError, KeyError, ValidationError) as exc:
            errors.append(f"instance-schema:{instance_name}:{exc}")

    if evidence_root is not None:
        for instance_name, schema_name in EVIDENCE_INSTANCE_SCHEMAS.items():
            try:
                _schema_validate(_json(_artifact(root, evidence_root, instance_name)), schemas[schema_name])
            except (OSError, json.JSONDecodeError, KeyError, ValidationError) as exc:
                errors.append(f"evidence-instance-schema:{instance_name}:{exc}")

    for policy_name in (
        "policies/execution-trust-attestation-authority-v1.yaml",
        "policies/ci-gate-authority-v1.yaml", "policies/runner-network-v1.yaml",
    ):
        try:
            policy = _json(root / policy_name)
            if not isinstance(policy, dict) or policy.get("enabled") is not False:
                errors.append(f"bootstrap-policy-not-inert:{policy_name}")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"policy-invalid:{policy_name}:{exc}")

    try:
        Registry.load(root / "registry/repositories.json")
    except Exception as exc:
        errors.append(f"registry-invalid:{exc}")

    try:
        spec_manifest = _json(root / SPEC_MANIFEST)
        artifacts = spec_manifest["artifacts"]
        names = [_safe_path(artifact["path"]) for artifact in artifacts]
        if len(names) != len(set(names)) or set(names) != set(NORMATIVE_SPEC_PATHS):
            errors.append("spec-manifest-not-exact")
        for artifact in artifacts:
            name = _safe_path(artifact["path"])
            payload = (root / name).read_bytes()
            if len(payload) != artifact["bytes"]: errors.append(f"spec-manifest-bytes:{name}")
            if len(payload.splitlines()) != artifact["lines"]: errors.append(f"spec-manifest-lines:{name}")
            if hashlib.sha256(payload).hexdigest() != artifact["sha256"]: errors.append(f"spec-manifest-sha256:{name}")
        errors.extend(_normative_semantic_errors({
            name: (root / name).read_text(encoding="utf-8") for name in NORMATIVE_SPEC_PATHS
        }))
    except Exception as exc:
        errors.append(f"spec-manifest-invalid:{exc}")

    if evidence_root is None:
        return {
            "schema_version": 1, "valid": not errors, "activation_ready": False,
            "errors": errors, "external_authority": "unverified",
            "evidence_bundle": "not_provided",
        }

    try:
        builder = _load_builder(root)
        canonical = builder.parse_scenarios()
        definitions = _json(_artifact(root, evidence_root, "evidence/scenario-definitions-v1.json"))
        if definitions["source_sha256"] != _sha256(root / builder.TEST_SPEC) or definitions["scenarios"] != canonical:
            errors.append("scenario-definitions-not-canonical")
        matrix = _json(_artifact(root, evidence_root, "evidence/scenario-matrix-v1.json"))
        scenarios = matrix["scenarios"]
        if matrix.get("scenario_count") != 108 or tuple(item.get("id") for item in scenarios) != EXPECTED_IDS:
            errors.append("scenario-matrix-not-exact-s01-s108")
        if [{key: item.get(key) for key in ("id", "scenario", "expected")} for item in scenarios] != canonical:
            errors.append("scenario-matrix-definition-drift")

        gates = _json(_artifact(root, evidence_root, "evidence/gate-results-v1.json"))
        gate_map = {gate["id"]: gate for gate in gates["gates"]}
        if len(gate_map) != len(gates["gates"]) or set(gate_map) != {"github-automation-tests", "compileall", "diff-check", "gitleaks"}:
            errors.append("gate-results-not-exact")
        for gate_id, gate in gate_map.items():
            output_name = _safe_path(gate["output_path"])
            if _sha256(_artifact(root, evidence_root, output_name)) != gate["output_sha256"]:
                errors.append(f"gate-output-stale:{gate_id}")
        if any(gate_map[name]["result"] != "passed" or gate_map[name]["exit_code"] != 0 for name in ("github-automation-tests", "compileall", "diff-check")):
            errors.append("required-gate-not-passed")
        test_output = _artifact(root, evidence_root, gate_map["github-automation-tests"]["output_path"]).read_text(encoding="utf-8")
        if "\nOK\n" not in test_output or "skipped=" in test_output:
            errors.append("test-gate-output-not-clean-pass")

        proof_bundle = _json(_artifact(root, evidence_root, "evidence/scenario-proof-records-v1.json"))
        if proof_bundle["matrix_sha256"] != _sha256(_artifact(root, evidence_root, "evidence/scenario-matrix-v1.json")):
            errors.append("proof-matrix-stale")
        if proof_bundle["gate_results_sha256"] != _sha256(_artifact(root, evidence_root, "evidence/gate-results-v1.json")):
            errors.append("proof-gates-stale")
        records = proof_bundle["records"]
        record_map = {record["scenario_id"]: record for record in records}
        if len(record_map) != len(records): errors.append("proof-record-duplicate")
        local_ids = {item["id"] for item in scenarios if item.get("status") == "locally_proven"}
        if set(record_map) != local_ids: errors.append("proof-record-local-set-mismatch")
        for item in scenarios:
            scenario_id = item["id"]
            if item.get("status") not in {"locally_proven", "external_unverified"}:
                errors.append(f"scenario-status:{scenario_id}")
            if not item.get("evidence"): errors.append(f"scenario-evidence-empty:{scenario_id}")
            if item.get("status") == "locally_proven":
                if item.get("blocker") is not None or item.get("blocker_kind") is not None:
                    errors.append(f"local-scenario-has-blocker:{scenario_id}")
                record = record_map.get(scenario_id)
                if record:
                    if record["result"] != "passed" or record["gate_output_sha256"] != gate_map["github-automation-tests"]["output_sha256"]:
                        errors.append(f"proof-result:{scenario_id}")
                    evidence_names = {entry["path"] for entry in record["evidence"]}
                    if evidence_names != set(item["evidence"]): errors.append(f"proof-evidence-set:{scenario_id}")
                    for entry in record["evidence"]:
                        name = _safe_path(entry["path"])
                        if _sha256(_artifact(root, evidence_root, name)) != entry["sha256"]: errors.append(f"proof-evidence-stale:{scenario_id}:{name}")
                    for selector in record["selector"]:
                        if selector.rsplit(".", 1)[-1] not in test_output:
                            errors.append(f"proof-selector-not-executed:{scenario_id}:{selector}")
                        selector_path = selector.rsplit(".", 1)[0].replace(".", "/") + ".py"
                        if selector_path not in evidence_names:
                            errors.append(f"proof-selector-not-evidence:{scenario_id}:{selector}")
            else:
                if not item.get("blocker") or item.get("blocker_kind") not in {"local_proof_gap", "external_authority"}:
                    errors.append(f"scenario-blocker:{scenario_id}")
    except Exception as exc:
        errors.append(f"evidence-trace-invalid:{exc}")

    try:
        evidence_manifest = _json(_artifact(root, evidence_root, "evidence/manifest-v1.json"))
        builder = _load_builder(root)
        expected = builder.expected_artifact_paths(evidence_root)
        artifacts = evidence_manifest["artifacts"]
        names = [_safe_path(item["path"]) for item in artifacts]
        if len(names) != len(set(names)): errors.append("evidence-manifest-duplicate")
        if names != sorted(expected): errors.append("evidence-manifest-not-exact")
        for artifact in artifacts:
            name = artifact["path"]
            payload = _artifact(root, evidence_root, name).read_bytes()
            if len(payload) != artifact["bytes"] or hashlib.sha256(payload).hexdigest() != artifact["sha256"]:
                errors.append(f"evidence-manifest-hash:{name}")
        if evidence_manifest["gate_results_sha256"] != _sha256(_artifact(root, evidence_root, evidence_manifest["gate_results_path"])):
            errors.append("evidence-manifest-gates-stale")
    except Exception as exc:
        errors.append(f"evidence-manifest-invalid:{exc}")

    try:
        triage = _json(_artifact(root, evidence_root, "evidence/secret-scan-triage-v1.json"))
        report_path = _safe_path(triage["redacted_report_path"])
        report = _json(_artifact(root, evidence_root, report_path))
        if triage["redacted_report_sha256"] != _sha256(_artifact(root, evidence_root, report_path)) or triage["total_findings"] != len(report):
            errors.append("gitleaks-triage-stale")
        if triage.get("new_secrets_detected") is not False or not triage.get("baseline_limitation"):
            errors.append("gitleaks-triage-not-fail-closed")
        if "--report-path evidence/gitleaks-report-v1.json" not in triage.get("command", ""):
            errors.append("gitleaks-command-not-reproducible")
    except Exception as exc:
        errors.append(f"gitleaks-triage-invalid:{exc}")

    return {
        "schema_version": 1, "valid": not errors, "activation_ready": False,
        "errors": errors, "external_authority": "unverified",
        "evidence_bundle": "validated" if evidence_root is not None and not errors else (
            "invalid" if evidence_root is not None else "not_provided"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-root", type=Path,
        help="private directory containing the files that would live below evidence/",
    )
    args = parser.parse_args()
    report = validate(evidence_root=args.evidence_root)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
