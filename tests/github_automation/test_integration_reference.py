"""Hermetic integration proof for the reference/sandbox control plane.

No test in this module contacts GitHub, a model provider, Windows, or WSL.
Runtime signing keys are ephemeral and never written to the repository.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import (
    ATTESTATION_DOMAIN,
    KEY_MANIFEST_DOMAIN,
    attestation_envelope_digest,
    authenticate_manifest_chain,
    manifest_digest,
    sign_detached,
    spki_fingerprint,
    verify_attestation,
)
from github_automation.gatestore import FencedError, GateStore
from github_automation.github import ProtocolPackage
from github_automation.inventory import classify_inventory
from github_automation.observability import (
    AppendOnlyAuditLog,
    ReadinessCriterion,
    ReadinessMatrix,
    evidence_bundle,
)
from github_automation.policy import evaluate_execution_trust
from github_automation.registry import Registry
from github_automation.reviewer import DecisionBlocked, ReviewerDecision
from github_automation.watchdog import ActionKind, ObservedState, reconcile


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests/github_automation/fixtures/reference-platform-v1.json"
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.value


class ReferencePlatformIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock(NOW)
        self.root_key = ed25519.Ed25519PrivateKey.generate()
        self.online_key = ed25519.Ed25519PrivateKey.generate()
        self.root_fingerprint = spki_fingerprint(self.root_key.public_key())
        self.online_fingerprint = spki_fingerprint(self.online_key.public_key())

        manifest_payload = {
            "execution_trust_key_manifest_version": 1,
            "manifest_generation": "1",
            "previous_manifest_digest": None,
            "issued_at": utc(NOW - timedelta(minutes=30)),
            "offline_root_public_fingerprint": self.root_fingerprint,
            "keys": [{
                "key_id": "runtime-online",
                "key_version": 1,
                "algorithm": "Ed25519",
                "public_key_fingerprint": self.online_fingerprint,
                "state": "active",
            }],
        }
        envelope = {
            "payload": manifest_payload,
            "signature": sign_detached(
                manifest_payload, self.root_key, domain=KEY_MANIFEST_DOMAIN
            ),
        }
        self.chain = authenticate_manifest_chain(
            [envelope],
            self.root_key.public_key(),
            pinned_root_fingerprint=self.root_fingerprint,
        )

        self.inventory = classify_inventory(
            ("branch-rules", "workflow-writers"),
            {
                "branch-rules": ({"principal": "example-owner", "kind": "user"},),
                "workflow-writers": ({"principal": "example-owner", "kind": "user"},),
            },
            NOW,
        )
        self.attestation = self._attestation()
        self.attestation_payload = verify_attestation(
            self.attestation,
            self.chain,
            {("runtime-online", 1): self.online_key.public_key()},
            now=NOW,
        )
        self.store = GateStore(
            Path(self.temp.name) / "gate.db", clock=self.clock
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _attestation(self) -> dict[str, object]:
        payload = {
            "attestation_schema_version": 1,
            "execution_trust_policy_version": 1,
            "execution_trust_attestation_authority_version": 1,
            "execution_trust_key_manifest_version": 1,
            "key_manifest_generation_at_issuance": "1",
            "key_manifest_digest_at_issuance": self.chain.current.digest,
            "attestation_id": "0198e7cf-6570-7000-8000-000000000001",
            "algorithm": "Ed25519",
            "key_id": "runtime-online",
            "key_version": 1,
            "public_key_fingerprint": self.online_fingerprint,
            "repository_id": self.fixture["repository_id"],
            "repository": self.fixture["repository"],
            "pr_number": self.fixture["pr_number"],
            "head_sha": self.fixture["head_sha"],
            "head_generation": "1",
            "inventory_guard_status": self.inventory.status,
            "missing_source_ids": list(self.inventory.missing_source_ids),
            "effective_writer_inventory_hash": self.inventory.semantic_hash,
            "inventory_guard_freshness_policy_version": 1,
            "inventory_observed_at_at_issuance": utc(NOW),
            "issued_at": utc(NOW - timedelta(minutes=5)),
            "expires_at": utc(NOW + timedelta(minutes=60)),
            "nonce": "A" * 43,
            "request_linkage_hash": "9" * 64,
        }
        return {
            "payload": payload,
            "signature": sign_detached(payload, self.online_key, domain=ATTESTATION_DOMAIN),
        }

    def _registry(self) -> Registry:
        return Registry.from_mapping({
            "registry_schema_version": 1,
            "repositories": {
                self.fixture["repository"]: {
                    "ci_runner": "local-with-github-fallback",
                    "ai_reviewer": "disabled",
                    "execution_trust": {
                        "policy_version": 1,
                        "mode": "exact-sha-attestation",
                        "attestation_authority_version": 1,
                        "key_manifest_version": 1,
                        "key_manifest_generation": 1,
                        "key_manifest_digest": self.chain.current.digest,
                        "offline_root_public_fingerprint": self.root_fingerprint,
                        "public_key_id": "runtime-online",
                        "public_key_fingerprint": self.online_fingerprint,
                        "inventory_drift_guard": "enabled",
                    },
                    "authority": {"kind": "personal-repository", "installation_id": 41},
                }
            },
        })

    def _protocol(self, *, generation: int, admission=None) -> ProtocolPackage:
        f = self.fixture
        envelope_digest = attestation_envelope_digest(self.attestation)
        values = {
            "protocol_version": 1,
            "timing_policy_version": 1,
            "execution_trust_policy_version": 1,
            "repository_id": int(f["repository_id"]),
            "repository": f["repository"],
            "pr_number": f["pr_number"],
            "logical_key": f["logical_key"],
            "generation": generation,
            "owner_run_id": 900,
            "owner_run_attempt": 1,
            "head_sha": f["head_sha"],
            "base_sha": f["base_sha"],
            "tested_merge_sha": f["tested_merge_sha"],
            "tested_sha": f["tested_merge_sha"],
            "check_target_sha": f["tested_merge_sha"],
            "default_branch": f["default_branch"],
            "backend": "local",
            "policy_version": f["policy_version"],
            "execution_trust_mode": "exact-sha-attestation",
            "execution_trust_attestation_authority_version": 1,
            "execution_trust_key_manifest_version": 1,
            "key_manifest_generation": 1,
            "key_manifest_digest": self.chain.current.digest,
            "key_manifest_generation_at_issuance": "1",
            "key_manifest_digest_at_issuance": self.chain.current.digest,
            "attestation_id": self.attestation_payload["attestation_id"],
            "attestation_key_id": "runtime-online",
            "attestation_key_version": 1,
            "attestation_public_key_fingerprint": self.online_fingerprint,
            "attestation_head_generation": 1,
            "attestation_expires_at": self.attestation_payload["expires_at"],
            "attestation_nonce_binding": "bound",
            "attestation_envelope_digest": envelope_digest,
            "attestation_request_linkage_hash": "9" * 64,
            "inventory_guard_status": self.inventory.status,
            "missing_source_ids": list(self.inventory.missing_source_ids),
            "effective_writer_inventory_hash": self.inventory.semantic_hash,
            "inventory_observed_at": utc(self.inventory.observed_at),
            "inventory_guard_freshness_policy_version": 1,
            "local_admission_id": admission.admission_id if admission else None,
            "local_admission_digest": admission.admission_digest if admission else None,
            "local_evidence_id": None,
            "local_evidence_digest": None,
            "local_result_kind": None,
            "local_child_run_id": f["child_run_id"],
            "local_child_job_id": f["child_job_id"],
            "started_test_marker_digest": admission.marker_digest if admission else None,
            "canonical_command_digest": f["canonical_command_digest"] if admission else None,
            "terminal_at": None,
            "ci_gate_check_run_id": f["check_run_id"],
            "check_outbox_idempotency_key": None,
            "claim_deadline": utc(NOW + timedelta(minutes=10)),
            "execution_deadline": utc(NOW + timedelta(minutes=40)),
        }
        return ProtocolPackage.from_mapping(values)

    def _gate_and_admission(self):
        f = self.fixture
        head_generation = self.store.observe_head(
            f["repository_id"], f["pr_number"], f["head_sha"]
        )
        gate = self.store.acquire(
            logical_key=f["logical_key"],
            head_generation=head_generation,
            base_sha=f["base_sha"],
            tested_merge_sha=f["tested_merge_sha"],
            owner=f["owner"],
            check_run_id=f["check_run_id"],
            lease_ttl=timedelta(hours=1),
        )
        envelope_digest = attestation_envelope_digest(self.attestation)
        self.assertEqual("bound", self.store.bind_attestation_nonce(
            attestation_id=self.attestation_payload["attestation_id"],
            nonce_hash=hashlib.sha256(self.attestation_payload["nonce"].encode()).hexdigest(),
            logical_key=gate.logical_key,
            generation=gate.generation,
            expected_head_generation=head_generation,
            envelope_digest=envelope_digest,
            target={key: self.attestation_payload[key] for key in (
                "repository_id", "repository", "pr_number", "head_sha", "head_generation"
            )},
        ))
        admission = self.store.create_local_admission_after_pre_marker_verify(
            logical_key=gate.logical_key,
            generation=gate.generation,
            owner=gate.owner,
            lease_epoch=gate.lease_epoch,
            verifier_decision={"valid": True, "boundary": "pre-marker", "decision_id": "verify-runtime-1"},
            authority={
                "attestation_id": self.attestation_payload["attestation_id"],
                "envelope_digest": envelope_digest,
                "manifest_digest": manifest_digest(self.chain.current.payload),
            },
            child_run_id=f["child_run_id"],
            child_job_id=f["child_job_id"],
            tested_merge_sha=f["tested_merge_sha"],
            canonical_command_digest=f["canonical_command_digest"],
            wrapper_digest=f["wrapper_digest"],
            execution_deadline=NOW + timedelta(minutes=40),
        )
        return gate, admission

    def test_s02_s14_s16_s65_reference_local_path_commits_atomic_success(self) -> None:
        config = self._registry().resolve(self.fixture["repository"])
        decision = evaluate_execution_trust(
            config, now=NOW, inventory=self.inventory, attestation_valid=True
        )
        self.assertEqual(("local", True), (decision.backend, decision.local_eligible))
        gate, admission = self._gate_and_admission()
        protocol = self._protocol(generation=gate.generation, admission=admission)
        protocol.assert_current_tuple(
            repository_id=int(self.fixture["repository_id"]),
            repository=self.fixture["repository"],
            pr_number=self.fixture["pr_number"],
            head_sha=self.fixture["head_sha"],
            base_sha=self.fixture["base_sha"],
            tested_merge_sha=self.fixture["tested_merge_sha"],
            generation=gate.generation,
        )
        protocol.assert_checkout(self.fixture["tested_merge_sha"])
        completion = self.store.complete_local_success_if_authorized(
            logical_key=gate.logical_key,
            generation=gate.generation,
            owner=gate.owner,
            lease_epoch=gate.lease_epoch,
            admission_id=admission.admission_id,
            admission_digest=admission.admission_digest,
            evidence={"conclusion": "success", "tested_sha": self.fixture["tested_merge_sha"]},
            attestation_valid=True,
            attestation_expires_at=NOW + timedelta(minutes=60),
        )
        self.assertEqual(("local", "success"), (completion.winner, completion.result_kind))
        self.assertEqual(1, len(self.store.pending_outbox()))

    def test_s01_s25_s48_s58_default_hosted_and_reviewer_remain_inert(self) -> None:
        absent = self._registry().resolve("outside/unregistered")
        decision = evaluate_execution_trust(
            absent,
            now=NOW,
            inventory=self.inventory,
            attestation_valid=True,
            external_contributor=True,
            dependabot=True,
        )
        self.assertEqual(("github", False), (decision.backend, decision.local_eligible))
        with self.assertRaises(DecisionBlocked):
            ReviewerDecision.validate(
                {"status": "BLOCKED", "activation_allowed": False},
                required_approver="example-owner",
            )

    def test_s05_s06_s21_watchdog_persists_hosted_winner_and_outbox(self) -> None:
        gate, _ = self._gate_and_admission()
        state = ObservedState(
            logical_key=gate.logical_key,
            generation=gate.generation,
            owner=gate.owner,
            lease_epoch=gate.lease_epoch,
            lease_expires_at=NOW + timedelta(hours=1),
            phase="LOCAL_DISPATCHED",
            claim_deadline=NOW,
            job_started_at=None,
        )
        self.assertEqual(ActionKind.NOOP, reconcile(state, now=NOW).kind)
        timed_out = reconcile(state, now=NOW + timedelta(seconds=1))
        self.assertEqual(ActionKind.SELECT_GITHUB, timed_out.kind)
        self.assertEqual("selected", self.store.select_github_winner(
            logical_key=gate.logical_key,
            generation=gate.generation,
            owner=gate.owner,
            lease_epoch=gate.lease_epoch,
            reason=timed_out.reason,
        ))
        completion = self.store.complete_hosted_winner(
            logical_key=gate.logical_key,
            generation=gate.generation,
            owner=gate.owner,
            lease_epoch=gate.lease_epoch,
            evidence={"conclusion": "success", "workflow_run_id": 9002},
            hosted_predicate_valid=True,
        )
        self.assertEqual("github", completion.winner)
        self.assertEqual(1, len(self.store.pending_outbox()))

    def test_s97_local_github_race_has_one_stable_winner_and_outbox(self) -> None:
        gate, admission = self._gate_and_admission()

        def local() -> str:
            try:
                return self.store.complete_local_success_if_authorized(
                    logical_key=gate.logical_key,
                    generation=gate.generation,
                    owner=gate.owner,
                    lease_epoch=gate.lease_epoch,
                    admission_id=admission.admission_id,
                    admission_digest=admission.admission_digest,
                    evidence={"conclusion": "success", "source": "local"},
                    attestation_valid=True,
                    attestation_expires_at=NOW + timedelta(minutes=10),
                ).winner
            except FencedError:
                return "fenced"

        def hosted() -> str:
            try:
                self.store.select_github_winner(
                    logical_key=gate.logical_key,
                    generation=gate.generation,
                    owner=gate.owner,
                    lease_epoch=gate.lease_epoch,
                    reason="timeout",
                )
                return self.store.complete_hosted_winner(
                    logical_key=gate.logical_key,
                    generation=gate.generation,
                    owner=gate.owner,
                    lease_epoch=gate.lease_epoch,
                    evidence={"conclusion": "success", "source": "github"},
                    hosted_predicate_valid=True,
                ).winner
            except FencedError:
                return "fenced"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = tuple(pool.map(lambda fn: fn(), (local, hosted)))
        winner = self.store.get_gate(gate.logical_key, gate.generation).winner
        self.assertIn(winner, {"local", "github"})
        self.assertIn(winner, outcomes)
        self.assertEqual(1, len(self.store.pending_outbox()))

    def test_readiness_bundle_marks_external_authority_unverified(self) -> None:
        audit = AppendOnlyAuditLog()
        audit.append(
            "reference_integration",
            self.fixture["logical_key"],
            {"result": "pass", "private_key": "never-exported"},
            occurred_at=NOW,
        )
        readiness = ReadinessMatrix(self.fixture["repository"], (
            ReadinessCriterion("reference_integration", "pass", ("hermetic integration passed",)),
            ReadinessCriterion(
                "github_sandbox",
                "unverified",
                blocker="GitHub App credentials and disposable private sandbox are absent",
            ),
            ReadinessCriterion(
                "dedicated_wsl",
                "unverified",
                blocker="dedicated Windows/WSL authority and host evidence are absent",
            ),
        ))
        bundle = evidence_bundle(
            repository=self.fixture["repository"],
            audit=audit,
            readiness=readiness,
            artifacts={"gate_store": "reference SQLite", "token": "not-present"},
            generated_at=NOW,
        )
        self.assertFalse(bundle["readiness"]["ready"])
        self.assertEqual(2, len(bundle["readiness"]["external_blockers"]))
        self.assertEqual("[REDACTED]", bundle["artifacts"]["token"])

    def test_external_launcher_blocks_every_unprovisioned_suite_instead_of_skipping(self) -> None:
        launcher = ROOT / "scripts/run-github-automation-external-tests.py"
        for suite in ("SANDBOX", "WSL", "PILOT"):
            with self.subTest(suite=suite):
                completed = subprocess.run(
                    [str(ROOT / ".venv/bin/python"), str(launcher), suite],
                    cwd=ROOT,
                    env={"PATH": "/usr/bin:/bin"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(3, completed.returncode)
                result = json.loads(completed.stdout)
                self.assertEqual((suite, "blocked"), (result["suite"], result["status"]))
                self.assertTrue(result["missing"])


if __name__ == "__main__":
    unittest.main()
