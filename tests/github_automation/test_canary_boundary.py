from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jsonschema import Draft202012Validator

from github_automation.canary_boundary import (
    CANARY_SCENARIOS,
    CanaryBoundaryError,
    authorization_digest,
    sign_canary_authorization,
    verify_canary_authorization,
)
from github_automation.crypto import canonicalize_jcs, spki_fingerprint


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)
PRIVATE = ed25519.Ed25519PrivateKey.generate()
FINGERPRINT = spki_fingerprint(PRIVATE.public_key())


def authorization(**changes):
    value = {
        "schema_version": 1,
        "purpose": "runner-lifecycle-proof-only",
        "production_activation_authorized": False,
        "outbound_worker_authorized": False,
        "required_check_authorized": False,
        "github_contact_authorized": True,
        "runner_registration_authorized": True,
        "repository": "FacuVCanale/self-hosted-ci-sandbox",
        "repository_id": 123,
        "pull_request": 7,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "tested_merge_sha": "c" * 40,
        "workflow_ref": "FacuVCanale/self-hosted-ci-sandbox/.github/workflows/ci-jit-canary-child.yml@refs/heads/main",
        "dispatch_sha": "d" * 40,
        "garm_entity": {
            "authority_kind": "personal-repository",
            "entity_id": "12345678-1234-4123-8123-123456789abc",
            "entity_name": "FacuVCanale/self-hosted-ci-sandbox",
            "runner_group": None,
        },
        "image_alias": "github-runner-ubuntu-24.04-v1",
        "image_fingerprint": "1" * 64,
        "allocation_signer_fingerprint": "2" * 64,
        "github_app_config_digest": "3" * 64,
        "live_job_verifier_digest": "4" * 64,
        "network_policy_digest": "5" * 64,
        "bootstrap_install_receipt_digest": "6" * 64,
        "scenarios": list(CANARY_SCENARIOS),
        "max_allocations": 6,
        "max_concurrency": 1,
        "max_jobs_per_allocation": 1,
        "issued_at": NOW.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=90)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "nonce": "7" * 32,
    }
    value.update(changes)
    return value


class CanaryBoundaryTests(unittest.TestCase):
    def test_signed_exact_authorization_verifies_and_schema_validates(self):
        signed = sign_canary_authorization(authorization(), PRIVATE)
        schema = json.loads((ROOT / "schemas/jit-canary-authorization-v1.schema.json").read_text())
        Draft202012Validator(schema).validate(signed)
        decision = verify_canary_authorization(
            signed, PRIVATE.public_key(), pinned_fingerprint=FINGERPRINT, now=NOW
        )
        self.assertTrue(decision.authorized, decision.blockers)
        self.assertEqual("7" * 32, decision.nonce)
        self.assertEqual(64, len(authorization_digest(signed)))

    def test_scope_expansion_ttl_expiry_and_wrong_key_fail_closed(self):
        mutations = (
            {"production_activation_authorized": True},
            {"required_check_authorized": True},
            {"max_concurrency": 2},
            {"scenarios": list(reversed(CANARY_SCENARIOS))},
            {"expires_at": (NOW + timedelta(minutes=121)).isoformat(timespec="seconds").replace("+00:00", "Z")},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(CanaryBoundaryError):
                sign_canary_authorization(authorization(**mutation), PRIVATE)
        signed = sign_canary_authorization(authorization(), PRIVATE)
        expired = verify_canary_authorization(
            signed,
            PRIVATE.public_key(),
            pinned_fingerprint=FINGERPRINT,
            now=NOW + timedelta(hours=2),
        )
        self.assertFalse(expired.authorized)
        self.assertIn("canary-authorization:expired", expired.blockers)
        with self.assertRaisesRegex(CanaryBoundaryError, "pinned"):
            verify_canary_authorization(
                signed,
                ed25519.Ed25519PrivateKey.generate().public_key(),
                pinned_fingerprint=FINGERPRINT,
                now=NOW,
            )

    def test_organization_authority_is_bound_to_repository_owner_and_exact_group(self):
        org = authorization(
            repository="alethia-earth/Overworld",
            workflow_ref="alethia-earth/Overworld/.github/workflows/ci-jit-canary-child.yml@refs/heads/master",
            garm_entity={
                "authority_kind": "organization-runner-group",
                "entity_id": "12345678-1234-4123-8123-123456789abc",
                "entity_name": "alethia-earth",
                "runner_group": "overworld-ci-jit",
            },
        )
        signed = sign_canary_authorization(org, PRIVATE)
        decision = verify_canary_authorization(
            signed, PRIVATE.public_key(), pinned_fingerprint=FINGERPRINT, now=NOW
        )
        self.assertTrue(decision.authorized, decision.blockers)
        for entity_name, runner_group in (
            ("another-org", "overworld-ci-jit"),
            ("alethia-earth", "*"),
            ("alethia-earth", " padded"),
            ("alethia-earth", "padded "),
            ("alethia-earth", "line\nbreak"),
            ("alethia-earth", "x" * 101),
        ):
            invalid = dict(org)
            invalid["garm_entity"] = dict(
                org["garm_entity"],
                entity_name=entity_name,
                runner_group=runner_group,
            )
            with self.subTest(entity_name=entity_name, runner_group=runner_group):
                with self.assertRaises(CanaryBoundaryError):
                    sign_canary_authorization(invalid, PRIVATE)

    def test_sign_and_verify_clis_keep_private_key_external(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            unsigned, signed, private, public = (
                root / "unsigned.json", root / "signed.json", root / "private.pem", root / "public.pem"
            )
            unsigned.write_bytes(canonicalize_jcs(authorization()))
            private.write_bytes(PRIVATE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            public.write_bytes(PRIVATE.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            private.chmod(0o600)
            import subprocess, sys
            result = subprocess.run([sys.executable, str(ROOT / "scripts/host/sign-jit-canary-authorization.py"), "--input", str(unsigned), "--output", str(signed), "--reviewer-private-key", str(private)], text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)
            result = subprocess.run([sys.executable, str(ROOT / "scripts/host/verify-jit-canary-authorization.py"), "--authorization", str(signed), "--reviewer-public-key", str(public), "--pinned-fingerprint", FINGERPRINT], text=True, capture_output=True)
            # The fixture date may be expired at wall-clock verification, but the
            # verifier must distinguish a valid signed document from parse/key failure.
            self.assertEqual(3, result.returncode, result.stderr)
            self.assertIn("canary-authorization:expired", result.stdout)


if __name__ == "__main__":
    unittest.main()
