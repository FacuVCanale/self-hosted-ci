from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import canonicalize_jcs, spki_fingerprint
from github_automation.canary_boundary import CANARY_SCENARIOS, sign_canary_authorization
from github_automation.host_security import BLOCKED_NETWORK_CIDRS, REQUIRED_CHECKS
from github_automation.host_security import evaluate_runner_lifecycle
from github_automation.runner_boundary import (
    REQUIRED_COMPONENTS,
    evaluate_runner_boundary,
    sign_runner_boundary,
    verify_runner_boundary_attestation,
    verify_host_measurements,
)
from tests.github_automation.test_canary_boundary import authorization
from tests.github_automation.test_lifecycle_proof_builder import BUILDER, proof


ROOT = Path(__file__).resolve().parents[2]
PROVISION = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
VERIFY = ROOT / "scripts/host/verify-wsl-jit-readiness.py"
COLLECT = ROOT / "scripts/host/collect-wsl-jit-measurements.py"
REVIEWER_PRIVATE = ed25519.Ed25519PrivateKey.generate()
REVIEWER_FINGERPRINT = spki_fingerprint(REVIEWER_PRIVATE.public_key())


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
        "distro_name": "Ubuntu-24.04-CI",
        "personal_distro_names": ["Ubuntu-24.04"],
        "wsl_conf": "[automount]\nenabled=false\nmountFsTab=false\n[interop]\nenabled=false\nappendWindowsPath=false\n",
        "checks": [
            {
                "id": item,
                "status": "pass",
                "evidence_refs": [f"evidence/{item}.json"],
                "notes": "",
            }
            for item in sorted(REQUIRED_CHECKS)
        ],
        "observed_artifact_kinds": [],
        "network_policy": {
            "default_deny": True,
            "management_separated": True,
            "denied_cidrs": sorted(BLOCKED_NETWORK_CIDRS),
            "denied_service_classes": [
                "windows-host",
                "management",
                "reviewer",
                "control",
                "deploy",
                "local-sockets",
                "container-api",
            ],
            "proxy_only_egress": True,
            "private_dns_fail_closed": True,
            "loaded_before_registration": True,
            "windows_reboot_verified": True,
            "wsl_reboot_verified": True,
        },
    }


def boundary() -> dict:
    canary_authorization = sign_canary_authorization(authorization(), REVIEWER_PRIVATE)
    proof_set = BUILDER.build(
        canary_authorization,
        [proof(canary_authorization, scenario, index) for index, scenario in enumerate(CANARY_SCENARIOS, 1)],
    )
    value = {
        "runner_boundary_version": 2,
        "activation_requested": True,
        "components": [
            {
                "id": item,
                "status": "verified",
                "artifact_digest": "sha256:" + "a" * 64,
                "evidence_refs": [f"evidence/{item}.json"],
            }
            for item in sorted(REQUIRED_COMPONENTS)
        ],
        "host_security": host_evidence(),
        "jit_canary_authorization": canary_authorization,
        "runner_lifecycle_proof_set": proof_set,
        "network_policy": {
            "network_policy_version": 2,
            "enabled": True,
            "default_egress": "deny",
            "blocked_cidrs": sorted(BLOCKED_NETWORK_CIDRS),
            "blocked_endpoints": [
                "windows-host",
                "windows-gateway",
                "metadata",
                "management-plane",
                "reviewer",
                "control-plane",
                "deploy",
                "container-engine-sockets",
                "incus-api",
            ],
            "allowed_destinations": ["github-actions-egress-proxy"],
            "dns_private_or_rebound_resolution": "deny",
            "must_load_before_runner_registration": True,
            "must_survive_reboot": True,
            "on_install_or_verification_failure": "block-local-dispatch",
        },
        "measurements": {
            "host_measurement_version": 1,
            "measurement_set_digest": "sha256:" + "0" * 64,
            "artifacts": [
                {
                    "ref": "placeholder",
                    "sha256": "0" * 64,
                    "size": 0,
                    "mode": "0000",
                    "uid": 0,
                    "gid": 0,
                }
            ],
        },
    }
    return value


def materialize(directory: Path, *, activation: bool = True) -> tuple[dict, Path]:
    value = boundary()
    value["activation_requested"] = activation
    refs = {
        ref for component in value["components"] for ref in component["evidence_refs"]
    }
    refs.update(
        ref
        for check in value["host_security"]["checks"]
        for ref in check["evidence_refs"]
    )
    for ref in refs:
        path = directory / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        if ref == "evidence/network-policy.json":
            path.write_bytes(canonicalize_jcs(value["network_policy"]))
        else:
            path.write_text(
                json.dumps({"observed": ref, "version": "pinned-v1"}), encoding="utf-8"
            )
        path.chmod(0o640)
    template = directory / "template.json"
    output = directory / "boundary.json"
    template.write_text(json.dumps(value), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(COLLECT),
            "--input",
            str(template),
            "--output",
            str(output),
            "--measurement-root",
            str(directory),
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    measured = json.loads(output.read_text())
    signed = sign_runner_boundary(measured, REVIEWER_PRIVATE)
    output.write_text(json.dumps(signed), encoding="utf-8")
    (directory / "reviewer-public-key.pem").write_bytes(
        REVIEWER_PRIVATE.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return signed, output


def verifier_command(path: Path) -> list[str]:
    return [
        sys.executable,
        str(VERIFY),
        "--evidence",
        str(path),
        "--reviewer-public-key",
        str(path.parent / "reviewer-public-key.pem"),
        "--pinned-fingerprint",
        REVIEWER_FINGERPRINT,
    ]


class RunnerBoundaryV2Tests(unittest.TestCase):
    def test_complete_bundle_enables_and_schema_validates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value, _ = materialize(Path(directory))
            schema = json.loads(
                (ROOT / "schemas/runner-boundary-v2.schema.json").read_text()
            )
            Draft202012Validator(schema).validate(value)
            measured, blockers = verify_host_measurements(value, Path(directory))
            verify_runner_boundary_attestation(
                value,
                REVIEWER_PRIVATE.public_key(),
                pinned_fingerprint=REVIEWER_FINGERPRINT,
            )
            decision = evaluate_runner_boundary(
                value,
                measured_component_digests=measured,
                measurement_blockers=blockers,
                reviewer_public_key=REVIEWER_PRIVATE.public_key(),
                pinned_reviewer_fingerprint=REVIEWER_FINGERPRINT,
            )
            self.assertTrue(decision.enabled, decision.blockers)

    def test_lifecycle_is_bound_by_proof_digests_and_final_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value, _ = materialize(Path(directory))
            self.assertNotIn("runner_lifecycle_runs", value["host_security"])
            forged = json.loads(json.dumps(value)); forged.pop("attestation")
            forged["runner_lifecycle_proof_set"]["proofs"][0]["jobs_started"] = 0
            forged = sign_runner_boundary(forged, REVIEWER_PRIVATE)
            measured, blockers = verify_host_measurements(forged, Path(directory))
            decision = evaluate_runner_boundary(
                forged, measured_component_digests=measured,
                measurement_blockers=blockers,
                reviewer_public_key=REVIEWER_PRIVATE.public_key(),
                pinned_reviewer_fingerprint=REVIEWER_FINGERPRINT,
            )
            self.assertTrue(any("lifecycle-proof-invalid" in item for item in decision.blockers))

    def test_activation_component_network_and_host_gaps_block(self) -> None:
        mutations = (
            (
                lambda value: value.__setitem__("activation_requested", False),
                "activation-not-requested",
            ),
            (
                lambda value: value["components"][0].__setitem__(
                    "status", "unverified"
                ),
                "component-unverified",
            ),
            (
                lambda value: value["network_policy"].__setitem__("enabled", False),
                "network-policy-not-enabled",
            ),
            (
                lambda value: value["network_policy"]["blocked_endpoints"].remove(
                    "incus-api"
                ),
                "network-policy-blocked-endpoints-incomplete",
            ),
            (
                lambda value: next(
                    item
                    for item in value["components"]
                    if item["id"] == "network-policy"
                ).__setitem__("artifact_digest", "sha256:" + "f" * 64),
                "component-host-measurement-digest-mismatch:network-policy",
            ),
            (
                lambda value: value["host_security"]["checks"][0].__setitem__(
                    "status", "unverified"
                ),
                "host:check-unverified",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for mutate, expected in mutations:
                value, _ = materialize(Path(directory))
                value.pop("attestation")
                mutate(value)
                value = sign_runner_boundary(value, REVIEWER_PRIVATE)
                measured, measurement_blockers = verify_host_measurements(
                    value, Path(directory)
                )
                decision = evaluate_runner_boundary(
                    value,
                    measured_component_digests=measured,
                    measurement_blockers=measurement_blockers,
                    reviewer_public_key=REVIEWER_PRIVATE.public_key(),
                    pinned_reviewer_fingerprint=REVIEWER_FINGERPRINT,
                )
                self.assertTrue(any(expected in item for item in decision.blockers))

    def test_checked_in_policy_is_deliberately_inert(self) -> None:
        policy = json.loads((ROOT / "policies/runner-network-v2.yaml").read_text())
        self.assertFalse(policy["enabled"])
        self.assertEqual([], policy["allowed_destinations"])

    def test_reboot_cleanup_requires_exactly_one_started_job(self) -> None:
        run = lifecycle("reboot")
        self.assertEqual((), evaluate_runner_lifecycle(run))
        run = lifecycle("reboot")
        run["jobs_started"] = 0
        self.assertIn(
            "runner-lifecycle:not-exactly-one-job", evaluate_runner_lifecycle(run)
        )
        run = lifecycle("reboot")
        run["jobs_started"] = 2
        self.assertIn(
            "runner-lifecycle:not-exactly-one-job", evaluate_runner_lifecycle(run)
        )

    def test_readiness_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            blocked, path = materialize(Path(directory), activation=False)
            result = subprocess.run(
                verifier_command(path), text=True, capture_output=True
            )
            self.assertEqual(3, result.returncode, result.stdout + result.stderr)
            self.assertFalse(json.loads(result.stdout)["enabled"])
            _, path = materialize(Path(directory))
            result = subprocess.run(
                verifier_command(path), text=True, capture_output=True
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_host_measurements_fail_closed_on_bytes_version_acl_and_policy_drift(
        self,
    ) -> None:
        mutations = (
            lambda root: (root / "evidence/garm.json").write_text("mutated bytes"),
            lambda root: (root / "evidence/runner-image.json").write_text(
                '{"version":"changed"}'
            ),
            lambda root: (root / "evidence/incus.json").chmod(0o600),
            lambda root: (root / "evidence/network-policy.json").write_text(
                '{"enabled":false}'
            ),
        )
        for mutate in mutations:
            with (
                self.subTest(mutation=mutate),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                _, path = materialize(root)
                mutate(root)
                result = subprocess.run(
                    verifier_command(path),
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(3, result.returncode, result.stdout + result.stderr)
                self.assertTrue(
                    any(
                        "measurement" in blocker
                        for blocker in json.loads(result.stdout)["blockers"]
                    )
                )

    def test_arbitrary_status_files_cannot_enable_without_pinned_reviewer_signature(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value, path = materialize(root)
            value.pop("attestation")
            path.write_text(json.dumps(value), encoding="utf-8")
            result = subprocess.run(
                verifier_command(path), text=True, capture_output=True
            )
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)

            # Ambiguous/non-I-JSON encodings are rejected before signature
            # verification; the verifier never chooses one duplicate value.
            canonical = path.read_text(encoding="utf-8")
            path.write_text(
                '{"runner_boundary_version":2,' + canonical[1:], encoding="utf-8"
            )
            result = subprocess.run(
                verifier_command(path), text=True, capture_output=True
            )
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)

            # The library evaluator also performs the verification itself; a
            # caller cannot replace cryptographic proof with a truthy flag.
            forged = sign_runner_boundary(value, ed25519.Ed25519PrivateKey.generate())
            measured, blockers = verify_host_measurements(forged, root)
            decision = evaluate_runner_boundary(
                forged,
                measured_component_digests=measured,
                measurement_blockers=blockers,
            )
            self.assertFalse(decision.enabled)
            self.assertIn("boundary-attestation-not-verified", decision.blockers)
            self.assertEqual("invalid", json.loads(result.stdout)["status"])

            path.write_text(json.dumps(forged), encoding="utf-8")
            result = subprocess.run(
                verifier_command(path), text=True, capture_output=True
            )
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)

    def test_provisioning_is_plan_only_by_default_and_apply_is_guarded(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(PROVISION)], text=True, capture_output=True
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(["bash", str(PROVISION)], text=True, capture_output=True)
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("INERT PLAN ONLY", plan.stdout)
        apply = subprocess.run(
            ["bash", str(PROVISION), "--apply"], text=True, capture_output=True
        )
        self.assertNotEqual(0, apply.returncode)
        self.assertIn("both explicit acknowledgements", apply.stderr)
        source = PROVISION.read_text()
        self.assertIn("command -v garm", source)
        self.assertIn(
            "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py", source
        )
        self.assertIn('--reviewer-public-key "${reviewer_public_key}"', source)
        self.assertIn('--pinned-fingerprint "${reviewer_key_fingerprint}"', source)
        self.assertIn('"${TARGET_ROOT}/boundary-reviewer-public-key.pem"', source)
        self.assertIn('"${TARGET_ROOT}/boundary-reviewer-key.sha256"', source)
        self.assertIn("self-hosted-ci-network-policy.service", source)
        self.assertIn("self-hosted-ci-egress-proxy.service", source)
        self.assertIn("install-runner-network-runtime.sh", source)
        self.assertIn("activate-garm-jit.sh", source)
        self.assertIn("deactivate-garm-jit.sh", source)
        self.assertIn('rm -f "${TARGET_ROOT}/ACTIVATION_APPROVED"', source)
        self.assertIn(
            "systemctl enable --now self-hosted-ci-health-heartbeat.timer", source
        )
        self.assertNotIn('systemctl enable --now "${SERVICE_NAME}"', source)

    def test_systemd_units_require_boundary_and_activation_sentinels(self) -> None:
        verifier = (
            ROOT / "packaging/systemd/self-hosted-ci-boundary-verify.service"
        ).read_text()
        service = (ROOT / "packaging/systemd/self-hosted-ci-garm.service").read_text()
        self.assertIn("Before=self-hosted-ci-garm.service", verifier)
        self.assertNotIn("ConditionPathExists", verifier)
        self.assertIn(
            "--evidence /etc/self-hosted-ci/runner-boundary-v2.json", verifier
        )
        self.assertIn(
            "Requires=self-hosted-ci-boundary-verify.service incus.service", service
        )
        self.assertIn(
            "ExecStartPre=+/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py",
            service,
        )
        self.assertIn(
            "BindsTo=self-hosted-ci-network-policy.service self-hosted-ci-egress-proxy.service",
            service,
        )
        self.assertIn(
            "After=self-hosted-ci-boundary-verify.service incus.service network-online.target self-hosted-ci-network-policy.service self-hosted-ci-egress-proxy.service",
            service,
        )
        for unit in (
            "self-hosted-ci-network-policy.service",
            "self-hosted-ci-egress-proxy.service",
        ):
            unit_source = (ROOT / "packaging/systemd" / unit).read_text()
            self.assertNotIn("ExecStart=/usr/bin/false", unit_source)
            self.assertIn("ExecStart=/usr/local/lib/self-hosted-ci/", unit_source)
            self.assertIn(
                "ConditionPathExists=/etc/self-hosted-ci/ACTIVATION_APPROVED",
                unit_source,
            )
        self.assertIn(
            "ConditionPathExists=/etc/self-hosted-ci/ACTIVATION_APPROVED", service
        )
        self.assertNotIn("Environment=GITHUB_TOKEN", service)


if __name__ == "__main__":
    unittest.main()
