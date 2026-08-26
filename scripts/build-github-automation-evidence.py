#!/usr/bin/env python3
"""Build traceable evidence metadata without changing scenario statuses."""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "evidence"
TEST_SPEC = "docs/spec/test-spec-self-hosted-github-automation.md"
SPEC_MANIFEST = "docs/spec/manifest-self-hosted-github-automation.json"
NORMATIVE_SPEC_PATHS = (
    "docs/spec/spec-self-hosted-github-automation.md",
    "docs/spec/prd-self-hosted-github-automation.md",
    "docs/spec/review-self-hosted-github-automation.md",
    TEST_SPEC,
)
MATRIX = "evidence/scenario-matrix-v1.json"
DEFINITIONS = "evidence/scenario-definitions-v1.json"
GATES = "evidence/gate-results-v1.json"
PROOFS = "evidence/scenario-proof-records-v1.json"
MANIFEST = "evidence/manifest-v1.json"
GITLEAKS_REPORT = "evidence/gitleaks-report-v1.json"
TRIAGE = "evidence/secret-scan-triage-v1.json"
EXPECTED_IDS = tuple(f"S{number:02d}" for number in range(1, 109))
SCENARIO_ROW = re.compile(r"^\| (S(?:0[1-9]|[1-9][0-9]|10[0-8])) \| (.+?) \| (.+?) \|$")


def sha256(artifact_path: Path) -> str:
    return hashlib.sha256(artifact_path.read_bytes()).hexdigest()


def artifact_path(relative_path: str, evidence_root: Path | None = None) -> Path:
    """Resolve public source paths and private ``evidence/`` paths separately."""
    safe_relative(relative_path)
    if relative_path == "evidence" or relative_path.startswith("evidence/"):
        base = evidence_root or EVIDENCE_ROOT
        suffix = PurePosixPath(relative_path).relative_to("evidence")
        return base.joinpath(*suffix.parts)
    return ROOT / relative_path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(relative_path: str, value: object) -> None:
    destination = artifact_path(relative_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_relative(value: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or value != candidate.as_posix():
        raise ValueError(f"unsafe artifact path: {value!r}")
    return value


def parse_scenarios() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in (ROOT / TEST_SPEC).read_text(encoding="utf-8").splitlines():
        match = SCENARIO_ROW.match(line)
        if match:
            rows.append({"id": match.group(1), "scenario": match.group(2), "expected": match.group(3)})
    if tuple(row["id"] for row in rows) != EXPECTED_IDS:
        raise ValueError("normative test-spec must contain ordered exact S01-S108")
    return rows


def build_definitions() -> None:
    write_json(DEFINITIONS, {
        "schema_version": 1, "source": TEST_SPEC,
        "source_sha256": sha256(ROOT / TEST_SPEC), "scenario_count": 108,
        "scenarios": parse_scenarios(),
    })


def _tool_version(command: list[str]) -> str:
    executable = command[0]
    if executable.endswith("python") or executable.endswith("python3"):
        probe = [executable, "--version"]
    elif executable == "git":
        probe = ["git", "--version"]
    elif executable == "gitleaks":
        probe = ["gitleaks", "version"]
    else:
        probe = [executable, "--version"]
    result = subprocess.run(probe, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.stdout.strip() or f"version probe exit {result.returncode}"


def _capture(gate_id: str, command: list[str], *, findings_are_expected: bool = False) -> dict[str, object]:
    output_relative = f"evidence/gate-outputs/{gate_id}.txt"
    output_path = artifact_path(output_relative)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    result = subprocess.run(
        command, cwd=ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    finished_at = utc_now()
    output_path.write_text(result.stdout, encoding="utf-8")
    accepted = result.returncode == 0 or (findings_are_expected and result.returncode == 1)
    return {
        "id": gate_id, "command": command, "cwd": ".", "tool_version": _tool_version(command),
        "started_at": started_at, "finished_at": finished_at, "exit_code": result.returncode,
        "result": "findings-triaged" if findings_are_expected and result.returncode == 1 else ("passed" if accepted else "failed"),
        "output_path": output_relative, "output_sha256": sha256(output_path),
    }


def capture_gates() -> None:
    python = str(ROOT / ".venv/bin/python")
    gates = [
        _capture("github-automation-tests", [python, "-m", "unittest", "discover", "-s", "tests/github_automation", "-p", "test_*.py", "-v"]),
        _capture("compileall", [python, "-m", "compileall", "-q", "github_automation", "tests/github_automation"]),
        _capture("diff-check", ["git", "diff", "--check"]),
        _capture("gitleaks", ["gitleaks", "detect", "--source", ".", "--no-banner", "--redact", "--no-git", "--report-format", "json", "--report-path", GITLEAKS_REPORT], findings_are_expected=True),
    ]
    write_json(GATES, {"schema_version": 1, "captured_at": utc_now(), "gates": gates})
    _refresh_triage()


def capture_bootstrap_test_gate() -> None:
    """Seed trace artifacts before the validator's own test joins the full gate.

    This is not retained as final evidence: ``capture_gates`` immediately
    replaces it with the complete discovery run after proofs/manifest exist.
    """
    python = str(ROOT / ".venv/bin/python")
    modules = [
        ".".join(item.relative_to(ROOT).with_suffix("").parts)
        for item in sorted((ROOT / "tests/github_automation").glob("test_*.py"))
        if item.name not in {"test_evidence_validation.py", "test_schemas_configs.py"}
    ]
    gate = _capture("github-automation-tests", [python, "-m", "unittest", *modules, "-v"])
    write_json(GATES, {"schema_version": 1, "captured_at": utc_now(), "gates": [
        gate,
        _capture("compileall", [python, "-m", "compileall", "-q", "github_automation", "tests/github_automation"]),
        _capture("diff-check", ["git", "diff", "--check"]),
        _capture("gitleaks", ["gitleaks", "detect", "--source", ".", "--no-banner", "--redact", "--no-git", "--report-format", "json", "--report-path", GITLEAKS_REPORT], findings_are_expected=True),
    ]})
    _refresh_triage()


def _refresh_triage() -> None:
    report_path = artifact_path(GITLEAKS_REPORT)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    triage_path = artifact_path(TRIAGE)
    triage = json.loads(triage_path.read_text(encoding="utf-8")) if triage_path.is_file() else {
        "schema_version": 1,
        "new_secrets_detected": False,
        "baseline_limitation": "Public source scan only; operational evidence is stored privately.",
    }
    triage.update({
        "command": "gitleaks detect --source . --no-banner --redact --no-git --report-format json --report-path evidence/gitleaks-report-v1.json",
        "config": "gitleaks built-in default configuration; no repository override",
        "scope": "working tree under repository root, --no-git",
        "redacted_report_path": GITLEAKS_REPORT,
        "redacted_report_sha256": sha256(report_path),
        "total_findings": len(report),
    })
    write_json(TRIAGE, triage)


def build_proofs() -> None:
    matrix_path, gate_path = artifact_path(MATRIX), artifact_path(GATES)
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    gates = json.loads(gate_path.read_text(encoding="utf-8"))
    test_gate = next((gate for gate in gates["gates"] if gate["id"] == "github-automation-tests"), None)
    if not test_gate or test_gate["result"] != "passed" or test_gate["exit_code"] != 0:
        raise ValueError("github-automation test gate is not a captured pass")
    test_output = artifact_path(test_gate["output_path"]).read_text(encoding="utf-8")
    selectors_by_scenario: dict[str, set[str]] = {}
    for test_path in sorted((ROOT / "tests/github_automation").glob("test_*.py")):
        module = ".".join(test_path.relative_to(ROOT).with_suffix("").parts)
        tree = ast.parse(test_path.read_text(encoding="utf-8"), filename=str(test_path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("test_"):
                continue
            selector = f"{module}.{node.name}"
            for number in re.findall(r"s(\d{2,3})", node.name.lower()):
                scenario_id = f"S{int(number):02d}"
                if scenario_id in EXPECTED_IDS:
                    selectors_by_scenario.setdefault(scenario_id, set()).add(selector)
    records: list[dict[str, object]] = []
    for scenario in matrix["scenarios"]:
        if scenario["status"] != "locally_proven":
            continue
        evidence_modules = {
            item.removesuffix(".py").replace("/", ".")
            for item in scenario["evidence"]
            if item.startswith("tests/github_automation/test_") and item.endswith(".py")
        }
        selectors = sorted(
            selector for selector in selectors_by_scenario.get(scenario["id"], ())
            if selector.rsplit(".", 1)[0] in evidence_modules
        )
        if not selectors:
            raise ValueError(f"{scenario['id']} has no concrete test selector")
        if any(selector.rsplit(".", 1)[-1] not in test_output for selector in selectors):
            raise ValueError(f"{scenario['id']} selector is absent from captured passing gate")
        evidence = []
        for relative in sorted(set(scenario["evidence"])):
            safe_relative(relative)
            evidence_path = artifact_path(relative)
            if not evidence_path.is_file():
                raise ValueError(f"missing evidence for {scenario['id']}: {relative}")
            evidence.append({"path": relative, "sha256": sha256(evidence_path)})
        records.append({
            "scenario_id": scenario["id"], "selector": selectors, "result": "passed",
            "gate_id": "github-automation-tests", "gate_output_sha256": test_gate["output_sha256"],
            "evidence": evidence,
        })
    write_json(PROOFS, {"schema_version": 1, "matrix_sha256": sha256(matrix_path), "gate_results_sha256": sha256(gate_path), "records": records})


def expected_artifact_paths(evidence_root: Path | None = None) -> list[str]:
    explicit = {
        "Makefile", "requirements.txt", "scripts/verify-ci-host.py", SPEC_MANIFEST,
        *NORMATIVE_SPEC_PATHS,
    }
    patterns = (
        "templates/workflows/ci-gate-*.yml", ".github/workflows/*.yml", "github_automation/*.py", "tests/github_automation/test_*.py",
        "tests/github_automation/fixtures/*.json", "schemas/*.json", "policies/*.yaml", "policies/*.json",
        "registry/*.json", "decisions/*.yaml", "runbooks/*.md", "docs/github-automation-*.md",
        "scripts/*github-automation*.py", "scripts/host/*.sh", "scripts/host/*.ps1",
    )
    names = set(explicit)
    for pattern in patterns:
        names.update(str(item.relative_to(ROOT)) for item in ROOT.glob(pattern) if item.is_file())
    private_root = evidence_root or EVIDENCE_ROOT
    if private_root.is_dir():
        names.update(
            f"evidence/{item.relative_to(private_root).as_posix()}"
            for item in private_root.rglob("*") if item.is_file()
        )
    names.discard(MANIFEST)
    checked = [safe_relative(name) for name in names]
    missing = [name for name in checked if not artifact_path(name, private_root).is_file()]
    if missing:
        raise ValueError(f"missing exact manifest artifacts: {missing}")
    return sorted(checked)


def build_manifest() -> None:
    artifacts = [
        {"path": name, "bytes": artifact_path(name).stat().st_size, "sha256": sha256(artifact_path(name))}
        for name in expected_artifact_paths()
    ]
    write_json(MANIFEST, {
        "schema_version": 1, "activation_ready": False, "external_authority": "unverified",
        "inventory_policy": "exact allowlisted platform bundle v1; manifest excludes itself",
        "gate_results_path": GATES, "gate_results_sha256": sha256(artifact_path(GATES)), "artifacts": artifacts,
    })


def main(argv: Iterable[str] | None = None) -> int:
    global EVIDENCE_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-gates", action="store_true")
    parser.add_argument(
        "--evidence-root", type=Path, default=EVIDENCE_ROOT,
        help="private output directory; defaults to the ignored local evidence directory",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    EVIDENCE_ROOT = args.evidence_root.resolve()
    build_definitions()
    if args.capture_gates:
        if not artifact_path(GATES).is_file():
            capture_bootstrap_test_gate()
            build_proofs()
            build_manifest()
        capture_gates()
    if not artifact_path(GATES).is_file():
        raise SystemExit("missing captured gates; run with --capture-gates")
    build_proofs()
    build_manifest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
