from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.approval import (
    ApprovalContractError,
    BoundedSigningRequest,
    ProceduralApprovalContext,
    evaluate_signing_request,
    opaque_request_linkage_hash,
    resolve_signing_target,
)
from github_automation.crypto import (
    ATTESTATION_DOMAIN,
    KEY_MANIFEST_DOMAIN,
    AttestationContractError,
    ExactAttestationTarget,
    NonceBindingStore,
    authenticate_manifest_chain,
    manifest_digest,
    sign_detached,
    spki_fingerprint,
    verify_attestation_authority,
)


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class AuthorityFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.root = ed25519.Ed25519PrivateKey.generate()
        self.online = ed25519.Ed25519PrivateKey.generate()
        self.root_fp = spki_fingerprint(self.root.public_key())
        self.online_fp = spki_fingerprint(self.online.public_key())
        manifest_payload = {
            "execution_trust_key_manifest_version": 1,
            "manifest_generation": "1",
            "previous_manifest_digest": None,
            "issued_at": utc(NOW - timedelta(hours=1)),
            "offline_root_public_fingerprint": self.root_fp,
            "keys": [{
                "key_id": "online",
                "key_version": 1,
                "algorithm": "Ed25519",
                "public_key_fingerprint": self.online_fp,
                "state": "active",
            }],
        }
        manifest = {
            "payload": manifest_payload,
            "signature": sign_detached(manifest_payload, self.root, domain=KEY_MANIFEST_DOMAIN),
        }
        self.chain = authenticate_manifest_chain(
            [manifest], self.root.public_key(), pinned_root_fingerprint=self.root_fp
        )
        self.payload = {
            "attestation_schema_version": 1,
            "execution_trust_policy_version": 1,
            "execution_trust_attestation_authority_version": 1,
            "execution_trust_key_manifest_version": 1,
            "key_manifest_generation_at_issuance": "1",
            "key_manifest_digest_at_issuance": manifest_digest(manifest_payload),
            "attestation_id": "0198e7cf-6570-7000-8000-000000000011",
            "algorithm": "Ed25519",
            "key_id": "online",
            "key_version": 1,
            "public_key_fingerprint": self.online_fp,
            "repository_id": "123",
            "repository": "owner/repo",
            "pr_number": 7,
            "head_sha": "a" * 40,
            "head_generation": "3",
            "inventory_guard_status": "partial",
            "missing_source_ids": ["apps"],
            "effective_writer_inventory_hash": "b" * 64,
            "inventory_guard_freshness_policy_version": 1,
            "inventory_observed_at_at_issuance": utc(NOW - timedelta(minutes=30)),
            "issued_at": utc(NOW - timedelta(minutes=20)),
            "expires_at": utc(NOW + timedelta(minutes=40)),
            "nonce": "A" * 43,
            "request_linkage_hash": "c" * 64,
        }
        self.envelope = {"payload": self.payload, "signature": sign_detached(self.payload, self.online)}
        self.target = ExactAttestationTarget("123", "owner/repo", 7, "a" * 40, "3", 9)
        self.store = NonceBindingStore()

    def verify(self, *, boundary: str = "pre-dispatch", **overrides):
        arguments = {
            "target": self.target,
            "inventory_status": "partial",
            "inventory_missing_source_ids": ["apps"],
            "inventory_semantic_hash": "b" * 64,
            "inventory_observed_at": NOW - timedelta(minutes=5),
            "now": NOW,
            "boundary": boundary,
            "nonce_store": self.store,
        }
        arguments.update(overrides)
        return verify_attestation_authority(
            self.envelope,
            self.chain,
            {("online", 1): self.online.public_key()},
            **arguments,
        )


class CompositeVerifierTests(AuthorityFixture):
    def test_s93_exact_target_partial_inventory_signature_manifest_and_nonce_all_pass(self) -> None:
        decision = self.verify()
        self.assertTrue(decision.valid)
        self.assertEqual("current_authority_for_success", decision.proof_role)
        self.assertEqual("bound", decision.nonce_binding_outcome)
        self.assertEqual("c" * 64, decision.request_linkage_hash)
        self.assertEqual("idempotent", self.verify().nonce_binding_outcome)
        self.assertEqual("idempotent", self.verify(boundary="pre-claim").nonce_binding_outcome)

    def test_s81_s82_repo_id_name_pr_head_and_head_generation_are_each_exact(self) -> None:
        targets = (
            ExactAttestationTarget("124", "owner/repo", 7, "a" * 40, "3", 9),
            ExactAttestationTarget("123", "other/repo", 7, "a" * 40, "3", 9),
            ExactAttestationTarget("123", "owner/repo", 8, "a" * 40, "3", 9),
            ExactAttestationTarget("123", "owner/repo", 7, "d" * 40, "3", 9),
            ExactAttestationTarget("123", "owner/repo", 7, "a" * 40, "4", 9),
        )
        for target in targets:
            with self.subTest(target=target), self.assertRaises(AttestationContractError):
                self.verify(target=target)

    def test_inventory_status_missing_hash_and_freshness_are_each_exact(self) -> None:
        cases = (
            {"inventory_status": "complete", "inventory_missing_source_ids": []},
            {"inventory_missing_source_ids": ["apps", "teams"]},
            {"inventory_semantic_hash": "d" * 64},
            {"inventory_observed_at": NOW - timedelta(minutes=5, microseconds=1)},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(AttestationContractError):
                self.verify(**arguments)
        self.assertTrue(self.verify(inventory_observed_at=NOW - timedelta(minutes=5)).valid)

    def test_s71_writer_or_team_drift_fences_every_current_authority_boundary(self) -> None:
        for boundary in ("pre-dispatch", "pre-claim", "pre-marker", "local-success"):
            store = NonceBindingStore()
            if boundary != "pre-dispatch":
                self.store = store
                self.verify(boundary="pre-dispatch")
            self.store = store
            with self.subTest(boundary=boundary), self.assertRaises(AttestationContractError):
                self.verify(boundary=boundary, inventory_semantic_hash="e" * 64)

    def test_later_gate_requires_prior_nonce_binding_and_other_generation_is_replay(self) -> None:
        with self.assertRaisesRegex(AttestationContractError, "unbound"):
            self.verify(boundary="pre-claim")
        self.verify(boundary="pre-dispatch")
        changed_run = ExactAttestationTarget("123", "owner/repo", 7, "a" * 40, "3", 10)
        with self.assertRaisesRegex(AttestationContractError, "generation_mismatch"):
            self.verify(boundary="pre-dispatch", target=changed_run)

    def test_expiry_signature_and_manifest_fail_closed(self) -> None:
        with self.assertRaises(AttestationContractError):
            self.verify(now=datetime.fromisoformat(self.payload["expires_at"].replace("Z", "+00:00")))
        tampered = copy.deepcopy(self.envelope)
        tampered["payload"]["request_linkage_hash"] = "f" * 64
        original = self.envelope
        try:
            self.envelope = tampered
            with self.assertRaises(AttestationContractError):
                self.verify()
        finally:
            self.envelope = original
        with self.assertRaises(AttestationContractError):
            verify_attestation_authority(
                self.envelope, self.chain, {}, target=self.target,
                inventory_status="partial", inventory_missing_source_ids=["apps"],
                inventory_semantic_hash="b" * 64, inventory_observed_at=NOW,
                now=NOW, boundary="pre-dispatch", nonce_store=self.store,
            )

    def test_s83_expiry_equality_and_later_fail_at_all_four_boundaries(self) -> None:
        expiry = datetime.fromisoformat(self.payload["expires_at"].replace("Z", "+00:00"))
        for boundary in ("pre-dispatch", "pre-claim", "pre-marker", "local-success"):
            for observed in (expiry, expiry + timedelta(microseconds=1)):
                self.store = NonceBindingStore()
                if boundary != "pre-dispatch":
                    self.verify(boundary="pre-dispatch")
                with self.subTest(boundary=boundary, observed=observed), self.assertRaises(
                    AttestationContractError
                ):
                    self.verify(boundary=boundary, now=observed)

    def test_s91_linkage_is_audit_only_but_still_signature_bound(self) -> None:
        changed = copy.deepcopy(self.payload)
        changed["request_linkage_hash"] = "d" * 64
        self.envelope = {"payload": changed, "signature": sign_detached(changed, self.online, domain=ATTESTATION_DOMAIN)}
        decision = self.verify()
        self.assertTrue(decision.valid)
        self.assertEqual("d" * 64, decision.request_linkage_hash)


class BoundedApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.linkage = opaque_request_linkage_hash("opaque-thread-1", "opaque-turn-4")
        self.request = {
            "repository_id": "123",
            "repository": "owner/repo",
            "pr_number": 7,
            "head_sha": "a" * 40,
            "expected_head_generation": "3",
            "request_linkage_hash": self.linkage,
        }
        self.context = ProceduralApprovalContext(True, 1, "exact-pr-head")

    def test_exact_same_thread_request_is_accepted_as_procedural_not_crypto_proof(self) -> None:
        decision = evaluate_signing_request(self.request, self.context)
        self.assertTrue(decision.allowed)
        self.assertIsInstance(decision.request, BoundedSigningRequest)
        self.assertEqual(self.linkage, decision.audit.request_linkage_hash)

    def test_helper_reresolves_exact_github_target_and_reads_generation_from_gatestore(self) -> None:
        request = BoundedSigningRequest.validate(self.request)
        resolved = resolve_signing_target(
            request,
            github_repository_id="123",
            github_repository="owner/repo",
            github_pr_number=7,
            github_head_sha="a" * 40,
            gatestore_head_generation="3",
        )
        self.assertEqual("3", resolved.head_generation)
        with self.assertRaises(ApprovalContractError):
            resolve_signing_target(
                request,
                github_repository_id="123",
                github_repository="owner/repo",
                github_pr_number=7,
                github_head_sha="d" * 40,
                gatestore_head_generation="3",
            )
        with self.assertRaises(ApprovalContractError):
            resolve_signing_target(
                request,
                github_repository_id="123",
                github_repository="owner/repo",
                github_pr_number=7,
                github_head_sha="a" * 40,
                gatestore_head_generation="4",
            )

    def test_s87_s88_no_same_thread_blanket_multiple_and_future_requests_are_denied(self) -> None:
        contexts = (
            ProceduralApprovalContext(False, 1, "exact-pr-head"),
            ProceduralApprovalContext(True, 1, "repository"),
            ProceduralApprovalContext(True, 2, "exact-pr-head"),
            ProceduralApprovalContext(True, 1, "exact-pr-head", references_future_head=True),
        )
        for context in contexts:
            with self.subTest(context=context):
                decision = evaluate_signing_request(self.request, context)
                self.assertFalse(decision.allowed)
                self.assertEqual("denied", decision.audit.outcome)

    def test_s86_arbitrary_payload_stdin_file_and_caller_nonce_are_forbidden(self) -> None:
        for forbidden in ("payload", "stdin", "file", "nonce", "branch", "future_head"):
            raw = {**self.request, forbidden: "CANARY_PRIVATE_OR_TRANSCRIPT"}
            with self.subTest(forbidden=forbidden):
                decision = evaluate_signing_request(raw, self.context)
                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.request)

    def test_audit_projection_is_opaque_and_excludes_transcript_and_secrets(self) -> None:
        raw = {**self.request, "transcript": "CANARY_TRANSCRIPT", "private_key": "CANARY_KEY"}
        denied = evaluate_signing_request(raw, self.context).audit.to_mapping()
        rendered = repr(denied)
        self.assertNotIn("CANARY_TRANSCRIPT", rendered)
        self.assertNotIn("CANARY_KEY", rendered)
        self.assertEqual({"request_linkage_hash", "target", "outcome", "reason"}, set(denied))

    def test_s89_accepted_audit_has_opaque_linkage_exact_target_outcome_and_no_secrets(self) -> None:
        decision = evaluate_signing_request(self.request, self.context)
        self.assertTrue(decision.allowed)
        audit = decision.audit.to_mapping()
        self.assertEqual(self.linkage, audit["request_linkage_hash"])
        self.assertEqual("accepted", audit["outcome"])
        self.assertEqual(
            {
                "repository_id": "123", "repository": "owner/repo", "pr_number": 7,
                "head_sha": "a" * 40, "expected_head_generation": "3",
            },
            audit["target"],
        )
        rendered = repr(audit)
        for canary in ("CANARY_TRANSCRIPT", "CANARY_PRIVATE_KEY", "CANARY_SHARED_PASSWORD"):
            self.assertNotIn(canary, rendered)


if __name__ == "__main__":
    unittest.main()
