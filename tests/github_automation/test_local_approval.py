from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile, unittest
from github_automation.gatestore import GateStore
from github_automation.local_approval import (
    LocalApprovalStore,
    PilotWorkRequestBuilder,
    ResolvedApprovalTarget,
)
from github_automation.runner_jit import allocation_scale_set_name
from tests.github_automation.test_github_contracts import protocol

NOW = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)
REPO = "example-owner/example-repo"


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class Resolver:
    def __init__(self):
        self.head = "a" * 40
        self.fail = False
        self.calls = []

    def resolve(self, repository, pr):
        self.calls.append((repository, pr))
        if self.fail:
            raise RuntimeError("authority unavailable")
        return ResolvedApprovalTarget(
            "123",
            REPO,
            42,
            self.head,
            "main",
            f"{REPO}/.github/workflows/ci-gate-child.yml@refs/heads/main",
            "b" * 40,
            "c" * 40,
        )


class Builder:
    def __init__(self):
        self.calls = 0

    def build(self, target, *, head_generation, request_id, nonce, now, ttl):
        self.calls += 1
        reservation = {
            "allocation_reservation_version": 1,
            "allocation_id": "12345678-1234-4123-8123-123456789abc",
            "repository_id": target.repository_id,
            "repository": target.repository,
            "head_sha": target.head_sha,
            "workflow_ref": target.workflow_ref,
            "job_name": "local-quality",
            "authority_kind": "personal-repository",
            "runner_group": None,
            "scale_set_name": "",
            "labels": [],
            "image_fingerprint": "d" * 64,
            "nonce": nonce,
            "issued_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": (now + ttl)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "max_jobs": 1,
            "ephemeral": True,
        }
        reservation["scale_set_name"] = allocation_scale_set_name(reservation)
        reservation["labels"] = [reservation["scale_set_name"]]
        package = protocol()
        package.update(
            generation=head_generation,
            allocation_id=reservation["allocation_id"],
            allocation_nonce=nonce,
            runner_label=reservation["scale_set_name"],
        )
        return {
            "request_id": request_id,
            "protocol_package": package,
            "reservation": reservation,
        }


class LocalApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.clock = Clock()
        self.resolver = Resolver()
        self.builder = Builder()
        self.store = LocalApprovalStore(
            root / "approvals.sqlite3",
            GateStore(root / "gate.sqlite3", clock=self.clock),
            self.resolver,
            self.builder,
            clock=self.clock,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_approve_generates_internal_request_and_is_idempotent_for_live_head(self):
        first = self.store.approve(REPO, 42)
        second = self.store.approve(REPO, 42)
        self.assertEqual("pending", first["state"])
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["request_id"], second["request_id"])
        self.assertEqual(1, self.builder.calls)
        request = self.store.poll()
        self.assertEqual(first["request_id"], request["request_id"])
        self.assertEqual("claimed", self.store.status(REPO, 42)[0]["state"])

    def test_revoke_prevents_consumption_and_same_head_can_be_reapproved(self):
        first = self.store.approve(REPO, 42)
        self.assertEqual(1, self.store.revoke(REPO, 42)["revoked"])
        self.assertIsNone(self.store.poll())
        second = self.store.approve(REPO, 42)
        self.assertNotEqual(first["request_id"], second["request_id"])

    def test_moved_head_expires_exact_approval_without_dispatch(self):
        self.store.approve(REPO, 42)
        self.resolver.head = "b" * 40
        self.assertIsNone(self.store.poll())
        self.assertEqual("expired", self.store.status(REPO, 42)[0]["state"])

    def test_ttl_expiry_never_returns_work(self):
        self.store.approve(REPO, 42)
        self.clock.now = NOW + timedelta(minutes=4)
        self.assertIsNone(self.store.poll())
        self.assertEqual("expired", self.store.status(REPO, 42)[0]["state"])

    def test_reboot_recovers_only_expired_claim(self):
        self.store.approve(REPO, 42)
        self.store.poll()
        self.assertEqual(0, self.store.recover_claims())
        self.clock.now = NOW + timedelta(seconds=61)
        self.assertEqual(1, self.store.recover_claims())
        self.assertIsNotNone(self.store.poll())

    def test_durable_claim_survives_approval_ttl_and_resumes_exact_request(self):
        approved = self.store.approve(REPO, 42)
        request = self.store.poll()
        self.store.claim(approved["request_id"], request, lease_seconds=7200)
        self.clock.now = NOW + timedelta(minutes=10)
        self.assertEqual(0, self.store.recover_claims())
        self.assertEqual(
            request,
            self.store.resume(approved["request_id"], request, lease_seconds=7200),
        )
        self.store.retry(approved["request_id"], "transient")
        self.assertEqual("claimed", self.store.status()[0]["state"])

    def test_resume_rejects_crossed_durable_request(self):
        approved = self.store.approve(REPO, 42)
        request = self.store.poll()
        self.store.claim(approved["request_id"], request, lease_seconds=7200)
        crossed = dict(request)
        crossed["request_id"] = "other"
        with self.assertRaisesRegex(Exception, "cannot be resumed"):
            self.store.resume(approved["request_id"], crossed, lease_seconds=7200)

    def test_pilot_builder_needs_no_offline_manifest_and_is_exact(self):
        root = Path(self.temp.name)
        resolver = Resolver()
        resolver_target = resolver.resolve(REPO, 42)
        resolver_target = ResolvedApprovalTarget(
            resolver_target.repository_id,
            resolver_target.repository,
            resolver_target.pr_number,
            resolver_target.head_sha,
            resolver_target.default_branch,
            f"{REPO}/.github/workflows/ci-jit-pilot-child.yml@refs/heads/main",
            resolver_target.base_sha,
            resolver_target.tested_merge_sha,
        )

        class PilotResolver:
            def resolve(self, repository, pr):
                return resolver_target

        pilot = LocalApprovalStore(
            root / "pilot.sqlite3",
            GateStore(root / "pilot-gate.sqlite3", clock=self.clock),
            PilotResolver(),
            PilotWorkRequestBuilder("d" * 64),
            clock=self.clock,
        )
        approved = pilot.approve(REPO, 42)
        request = pilot.poll()
        self.assertEqual("pending", approved["state"])
        self.assertEqual("local", request["pilot_package"]["backend"])
        self.assertEqual(
            request["reservation"]["allocation_id"],
            request["pilot_package"]["allocation_id"],
        )

    def test_pilot_builder_preserves_explicit_organization_runner_authority(self):
        builder = PilotWorkRequestBuilder(
            "d" * 64,
            authority_kind="organization-runner-group",
            runner_group="overworld-ci-jit",
        )
        target = ResolvedApprovalTarget(
            "1172953958",
            "alethia-earth/Overworld",
            42,
            "a" * 40,
            "master",
            "alethia-earth/Overworld/.github/workflows/ci-jit-pilot-child.yml@refs/heads/master",
            "b" * 40,
            "c" * 40,
        )
        request = builder.build(
            target,
            head_generation=1,
            request_id="request-1",
            nonce="A" * 43,
            now=NOW,
            ttl=timedelta(minutes=4),
        )
        self.assertEqual(
            "organization-runner-group",
            request["reservation"]["authority_kind"],
        )
        self.assertEqual("overworld-ci-jit", request["reservation"]["runner_group"])


if __name__ == "__main__":
    unittest.main()
