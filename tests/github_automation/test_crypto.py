from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import base64
import copy
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes

from github_automation.crypto import (
    ATTESTATION_DOMAIN,
    KEY_MANIFEST_DOMAIN,
    P256_ORDER,
    AttestationContractError,
    CanonicalizationError,
    ManifestContractError,
    NonceBinding,
    NonceBindingStore,
    SignatureContractError,
    authenticate_manifest_chain,
    authorize_key_for_issuance,
    canonicalize_jcs,
    decode_base64url_raw64,
    domain_separated_payload,
    manifest_digest,
    parse_ijson,
    payload_digest,
    sign_detached,
    spki_fingerprint,
    verify_attestation,
    verify_detached,
)


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)


def utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class CanonicalizationTests(unittest.TestCase):
    def test_jcs_vector_orders_utf16_and_normalizes_numbers(self) -> None:
        value = {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            "\u0080": "Control",
            "ö": "Latin Small Letter O With Diaeresis",
            "numbers": [1.0, -0.0, 1e-7, 1e-6, 1e20, 1e21],
        }
        self.assertEqual(
            b'{"\\r":"Carriage Return","1":"One",'
            b'"numbers":[1,0,1e-7,0.000001,100000000000000000000,1e+21],'
            b'"\xc2\x80":"Control","\xc3\xb6":"Latin Small Letter O With Diaeresis","\xe2\x82\xac":"Euro Sign",'
            b'"\xf0\x9f\x98\x80":"Emoji: Grinning Face","\xef\xac\xb3":"Hebrew Letter Dalet With Dagesh"}',
            canonicalize_jcs(value),
        )

    def test_s78_duplicate_nonfinite_unsafe_and_surrogate_values_reject(self) -> None:
        invalid_json = ('{"a":1,"a":2}', '{"a":NaN}', b'"\xff"')
        for value in invalid_json:
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                parse_ijson(value)
        for value in (float("inf"), 1 << 54, "\ud800"):
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                canonicalize_jcs(value)

    def test_domains_and_manifest_digest_exclude_signature_envelope(self) -> None:
        payload = {"b": 2, "a": 1}
        self.assertEqual(ATTESTATION_DOMAIN + b'\x00{"a":1,"b":2}', domain_separated_payload(ATTESTATION_DOMAIN, payload))
        self.assertNotEqual(payload_digest(ATTESTATION_DOMAIN, payload), manifest_digest(payload))
        self.assertEqual(manifest_digest(payload), manifest_digest({"a": 1, "b": 2}))
        self.assertNotEqual(manifest_digest(payload), payload_digest(KEY_MANIFEST_DOMAIN, {"payload": payload, "signature": "x"}))


class SignatureTests(unittest.TestCase):
    def test_ed25519_requires_raw64_unpadded_base64url_and_exact_domain(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        payload = {"head_sha": "a" * 40, "generation": "4"}
        signature = sign_detached(payload, private)
        self.assertEqual(86, len(signature))
        self.assertNotIn("=", signature)
        verify_detached(payload, signature, private.public_key())
        with self.assertRaises(SignatureContractError):
            verify_detached(payload, signature + "=", private.public_key())
        with self.assertRaises(SignatureContractError):
            verify_detached(payload, signature, private.public_key(), domain=KEY_MANIFEST_DOMAIN)
        with self.assertRaises(SignatureContractError):
            verify_detached({**payload, "generation": "5"}, signature, private.public_key())

    def test_p256_accepts_only_low_s_p1363_and_rejects_der_or_high_s(self) -> None:
        private = ec.generate_private_key(ec.SECP256R1())
        payload = {"target": "owner/repo#1@" + "a" * 40}
        signature = sign_detached(payload, private)
        raw = decode_base64url_raw64(signature)
        s = int.from_bytes(raw[32:], "big")
        self.assertLessEqual(s, P256_ORDER // 2)
        verify_detached(payload, signature, private.public_key())

        high_s = raw[:32] + (P256_ORDER - s).to_bytes(32, "big")
        high_s_encoded = base64.urlsafe_b64encode(high_s).rstrip(b"=").decode()
        with self.assertRaises(SignatureContractError):
            verify_detached(payload, high_s_encoded, private.public_key())
        # A DER ECDSA signature is variable length and never accepted as raw64 input.
        der = private.sign(domain_separated_payload(ATTESTATION_DOMAIN, payload), ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(SignatureContractError):
            verify_detached(payload, base64.urlsafe_b64encode(der).rstrip(b"=").decode(), private.public_key())

    def test_spki_fingerprint_is_exact_der_sha256(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        fingerprint = spki_fingerprint(private.public_key())
        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
        self.assertEqual(fingerprint, spki_fingerprint(private.public_key()))


class ManifestAndAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = ed25519.Ed25519PrivateKey.generate()
        self.online = ed25519.Ed25519PrivateKey.generate()
        self.root_fp = spki_fingerprint(self.root.public_key())
        self.online_fp = spki_fingerprint(self.online.public_key())

    def envelope(self, generation: int, previous: str | None, state: str) -> dict:
        payload = {
            "execution_trust_key_manifest_version": 1,
            "manifest_generation": str(generation),
            "previous_manifest_digest": previous,
            "issued_at": utc(NOW + timedelta(minutes=generation * 10 - 30)),
            "offline_root_public_fingerprint": self.root_fp,
            "keys": [{
                "key_id": "online", "key_version": 1, "algorithm": "Ed25519",
                "public_key_fingerprint": self.online_fp, "state": state,
            }],
        }
        return {"payload": payload, "signature": sign_detached(payload, self.root, domain=KEY_MANIFEST_DOMAIN)}

    def chain(self, *states: str):
        envelopes = []
        previous = None
        for generation, state in enumerate(states, start=1):
            envelope = self.envelope(generation, previous, state)
            envelopes.append(envelope)
            previous = manifest_digest(envelope["payload"])
        return authenticate_manifest_chain(envelopes, self.root.public_key(), pinned_root_fingerprint=self.root_fp)

    def attestation(self, issuance, *, expires_at: datetime = NOW + timedelta(hours=1)) -> dict:
        payload = {
            "attestation_schema_version": 1,
            "execution_trust_policy_version": 1,
            "execution_trust_attestation_authority_version": 1,
            "execution_trust_key_manifest_version": 1,
            "key_manifest_generation_at_issuance": str(issuance.generation),
            "key_manifest_digest_at_issuance": issuance.digest,
            "attestation_id": "0198e7cf-6570-7000-8000-000000000001",
            "algorithm": "Ed25519",
            "key_id": "online",
            "key_version": 1,
            "public_key_fingerprint": self.online_fp,
            "repository_id": "123",
            "repository": "owner/repo",
            "pr_number": 7,
            "head_sha": "a" * 40,
            "head_generation": "3",
            "inventory_guard_status": "complete",
            "missing_source_ids": [],
            "effective_writer_inventory_hash": "b" * 64,
            "inventory_guard_freshness_policy_version": 1,
            "inventory_observed_at_at_issuance": utc(NOW),
            "issued_at": utc(NOW - timedelta(minutes=15)),
            "expires_at": utc(expires_at),
            "nonce": "A" * 43,
            "request_linkage_hash": "c" * 64,
        }
        return {"payload": payload, "signature": sign_detached(payload, self.online)}

    def test_s84_active_signs_and_verifies_retiring_only_verifies_old_proof(self) -> None:
        active = self.chain("active")
        self.assertEqual("active", authorize_key_for_issuance(active, "online", 1).state)
        proof = self.attestation(active.current)
        retiring = self.chain("active", "retiring")
        self.assertEqual(proof["payload"], verify_attestation(
            proof, retiring, {("online", 1): self.online.public_key()}, now=NOW + timedelta(minutes=30)
        ))
        with self.assertRaises(AttestationContractError):
            authorize_key_for_issuance(retiring, "online", 1)
        fabricated = self.attestation(retiring.current)
        with self.assertRaises(AttestationContractError):
            verify_attestation(fabricated, retiring, {("online", 1): self.online.public_key()}, now=NOW)

    def test_s79_revoked_unknown_expired_and_wrong_fingerprint_fail_closed(self) -> None:
        active = self.chain("active")
        proof = self.attestation(active.current)
        revoked = self.chain("active", "retiring", "revoked")
        with self.assertRaises(AttestationContractError):
            verify_attestation(proof, revoked, {("online", 1): self.online.public_key()}, now=NOW)
        with self.assertRaises(AttestationContractError):
            verify_attestation(proof, active, {}, now=NOW)
        with self.assertRaises(AttestationContractError):
            verify_attestation(proof, active, {("online", 1): self.online.public_key()}, now=NOW + timedelta(hours=1))
        wrong = copy.deepcopy(proof)
        wrong["payload"]["public_key_fingerprint"] = "0" * 64
        wrong["signature"] = sign_detached(wrong["payload"], self.online)
        with self.assertRaises(AttestationContractError):
            verify_attestation(wrong, active, {("online", 1): self.online.public_key()}, now=NOW)

    def test_s92_chain_rejects_bad_link_skip_rollback_and_state_reactivation(self) -> None:
        first = self.envelope(1, None, "active")
        bad_link = self.envelope(2, "0" * 64, "retiring")
        with self.assertRaises(ManifestContractError):
            authenticate_manifest_chain([first, bad_link], self.root.public_key(), pinned_root_fingerprint=self.root_fp)
        retiring = self.envelope(2, manifest_digest(first["payload"]), "retiring")
        reactivated = self.envelope(3, manifest_digest(retiring["payload"]), "active")
        with self.assertRaises(ManifestContractError):
            authenticate_manifest_chain([first, retiring, reactivated], self.root.public_key(), pinned_root_fingerprint=self.root_fp)
        with self.assertRaises(ManifestContractError):
            authenticate_manifest_chain([first], self.root.public_key(), pinned_root_fingerprint=self.root_fp, minimum_generation=2)


class NonceBindingTests(unittest.TestCase):
    def binding(self, generation: int = 1, *, logical_key: str = "repo:1:sha") -> NonceBinding:
        return NonceBinding("att-1", "nonce-hash", logical_key, generation, str(generation), "envelope-digest")

    def test_same_binding_is_idempotent_and_cross_binding_is_replay(self) -> None:
        store = NonceBindingStore()
        self.assertEqual("bound", store.bind(self.binding()))
        self.assertEqual("idempotent", store.bind(self.binding()))
        self.assertEqual("generation_mismatch", store.bind(self.binding(2)))
        self.assertEqual("replay", store.bind(NonceBinding("att-2", "nonce-hash", "other", 1, "1", "other")))

    def test_concurrent_binding_has_exactly_one_winner(self) -> None:
        store = NonceBindingStore()
        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(lambda _: store.bind(self.binding()), range(64)))
        self.assertEqual(1, outcomes.count("bound"))
        self.assertEqual(63, outcomes.count("idempotent"))


if __name__ == "__main__":
    unittest.main()
