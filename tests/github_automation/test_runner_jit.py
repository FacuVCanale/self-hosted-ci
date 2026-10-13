from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

from github_automation.crypto import spki_fingerprint
from github_automation.runner_jit import (
    AllocationClaimExpired,
    InvalidLifecycleTransition,
    RunnerJitError,
    SqliteAllocationLedger,
    allocation_scale_set_name,
    sign_allocation,
    validate_allocation_payload,
    validate_allocation_reservation,
    verify_allocation,
)


NOW = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)


def payload(
    *,
    allocation_id: str = "0198ef24-f800-7000-8000-000000000001",
    nonce: str = "A" * 43,
) -> dict:
    value = {
        "runner_allocation_version": 1,
        "allocation_id": allocation_id,
        "repository_id": "1347574115",
        "repository": "FacuVCanale/self-hosted-ci-sandbox",
        "head_sha": "a" * 40,
        "tested_sha": "c" * 40,
        "dispatch_sha": "f" * 40,
        "workflow_ref": "FacuVCanale/self-hosted-ci-sandbox/.github/workflows/ci-gate.yml@refs/heads/main",
        "run_id": "8001",
        "run_attempt": 1,
        "job_id": "8002",
        "job_name": "local-quality",
        "authority_kind": "personal-repository",
        "runner_group": None,
        "scale_set_name": "",
        "labels": [],
        "image_fingerprint": "b" * 64,
        "nonce": nonce,
        "issued_at": "2026-08-27T12:00:00Z",
        "expires_at": "2026-08-27T12:05:00Z",
        "max_jobs": 1,
        "ephemeral": True,
    }
    value["scale_set_name"] = allocation_scale_set_name(value)
    value["labels"] = [value["scale_set_name"]]
    return value


def reservation(**kwargs) -> dict:
    value = payload(**kwargs)
    for field in (
        "runner_allocation_version",
        "run_id",
        "run_attempt",
        "job_id",
        "dispatch_sha",
        "tested_sha",
    ):
        value.pop(field)
    value["allocation_reservation_version"] = 1
    return value


def payload_v2(
    *,
    allocation_id: str = "0198ef24-f800-7000-8000-000000000101",
    nonce: str = "V" * 43,
) -> dict:
    value = payload(allocation_id=allocation_id, nonce=nonce)
    value["runner_allocation_version"] = 2
    value["pr_number"] = 42
    value["base_sha"] = "b" * 40
    value["approval_issued_at"] = value["issued_at"]
    value["approval_expires_at"] = value.pop("expires_at")
    value["issued_at"] = "2026-08-27T12:09:00Z"
    value["claim_deadline"] = "2026-08-27T12:21:00Z"
    return value


def reservation_v2(**kwargs) -> dict:
    value = payload_v2(**kwargs)
    for field in (
        "runner_allocation_version",
        "run_id",
        "run_attempt",
        "job_id",
        "dispatch_sha",
        "tested_sha",
        "issued_at",
        "claim_deadline",
    ):
        value.pop(field)
    value["allocation_reservation_version"] = 2
    return value


class RunnerAllocationTests(unittest.TestCase):
    def test_ed25519_envelope_is_exact_pinned_and_head_bound(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        document = sign_allocation(payload(), private, now=NOW)
        verified = verify_allocation(
            document,
            private.public_key(),
            pinned_fingerprint=spki_fingerprint(private.public_key()),
            now=NOW,
        )
        self.assertEqual("a" * 40, verified["head_sha"])
        document["payload"]["head_sha"] = "c" * 40
        with self.assertRaises(RunnerJitError):
            verify_allocation(
                document,
                private.public_key(),
                pinned_fingerprint=spki_fingerprint(private.public_key()),
                now=NOW,
            )

    def test_unknown_fields_lifetime_labels_and_expiry_fail_closed(self) -> None:
        cases = []
        value = payload()
        value["extra"] = True
        cases.append(value)
        value = payload()
        value["expires_at"] = "2026-08-27T12:05:01Z"
        cases.append(value)
        value = payload()
        value["labels"] = ["wsl-jit"]
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(RunnerJitError):
                validate_allocation_payload(value, now=NOW)
        with self.assertRaises(RunnerJitError):
            validate_allocation_payload(payload(), now=NOW + timedelta(minutes=5))

    def test_personal_authority_is_exact_repository_scoped_without_group(self) -> None:
        value = payload()
        validate_allocation_payload(value, now=NOW)
        value["runner_group"] = "self-hosted-ci-jit"
        with self.assertRaisesRegex(RunnerJitError, "personal repository"):
            validate_allocation_payload(value, now=NOW)

    def test_organization_authority_requires_exact_selected_runner_group(self) -> None:
        value = payload()
        value["authority_kind"] = "organization-runner-group"
        value["runner_group"] = "selected-self-hosted-ci-jit"
        validate_allocation_payload(value, now=NOW)
        for runner_group in (None, "", " selected-group", "selected-group ", "*"):
            invalid = dict(value, runner_group=runner_group)
            with (
                self.subTest(runner_group=runner_group),
                self.assertRaisesRegex(RunnerJitError, "exact selected runner group"),
            ):
                validate_allocation_payload(invalid, now=NOW)

    def test_authority_kind_is_required_and_discriminated(self) -> None:
        missing = payload()
        missing.pop("authority_kind")
        with self.assertRaisesRegex(RunnerJitError, "exact v1 fields"):
            validate_allocation_payload(missing, now=NOW)
        invalid = payload()
        invalid["authority_kind"] = "repository-or-group"
        with self.assertRaisesRegex(RunnerJitError, "authority_kind is invalid"):
            validate_allocation_payload(invalid, now=NOW)

    def test_label_is_cryptographically_unique_and_not_caller_selected(self) -> None:
        first = payload()
        second = payload(
            allocation_id="0198ef24-f800-7000-8000-000000000002", nonce="B" * 43
        )
        self.assertNotEqual(first["scale_set_name"], second["scale_set_name"])
        self.assertRegex(first["scale_set_name"], r"^wsl-jit-[0-9a-f]{32}$")
        first["scale_set_name"] = "wsl-jit-" + "0" * 32
        first["labels"] = [first["scale_set_name"]]
        with self.assertRaisesRegex(RunnerJitError, "allocation-derived"):
            validate_allocation_payload(first, now=NOW)

    def test_reservation_excludes_unknown_run_and_job_ids(self) -> None:
        value = reservation()
        validate_allocation_reservation(value, now=NOW)
        value["job_id"] = "8002"
        with self.assertRaisesRegex(RunnerJitError, "reservation requires exact"):
            validate_allocation_reservation(value, now=NOW)

    def test_signed_finalization_must_match_prior_reservation(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        fingerprint = spki_fingerprint(private.public_key())
        with tempfile.TemporaryDirectory() as directory:
            ledger = SqliteAllocationLedger(Path(directory) / "ledger.sqlite3")
            value = payload()
            ledger.reserve(reservation(), now=NOW)
            self.assertEqual(
                "issued",
                ledger.finalize(
                    sign_allocation(value, private, now=NOW),
                    private.public_key(),
                    pinned_fingerprint=fingerprint,
                    now=NOW,
                ),
            )
            self.assertEqual("issued", ledger.get(value["allocation_id"]).state)

    def test_v2_keeps_short_approval_and_mints_claim_window_at_exact_job(self) -> None:
        private = ed25519.Ed25519PrivateKey.generate()
        fingerprint = spki_fingerprint(private.public_key())
        with tempfile.TemporaryDirectory() as directory:
            ledger = SqliteAllocationLedger(Path(directory) / "ledger.sqlite3")
            value = payload_v2()
            ledger.reserve(reservation_v2(), now=NOW + timedelta(minutes=3))
            ledger.finalize(
                sign_allocation(value, private, now=NOW + timedelta(minutes=9)),
                private.public_key(),
                pinned_fingerprint=fingerprint,
                now=NOW + timedelta(minutes=9),
            )
            record = ledger.transition(
                value["allocation_id"], "claim", now=NOW + timedelta(minutes=20)
            )
            self.assertEqual("claimed", record.state)
            self.assertEqual(
                NOW + timedelta(minutes=21), record.claim_deadline
            )

    def test_v2_claim_deadline_rejects_equality_and_later(self) -> None:
        for offset in (0, 1):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as directory:
                ledger = SqliteAllocationLedger(Path(directory) / "ledger.sqlite3")
                private = ed25519.Ed25519PrivateKey.generate()
                value = payload_v2(
                    allocation_id=f"0198ef24-f800-7000-8004-{offset + 1:012d}",
                    nonce=chr(87 + offset) * 43,
                )
                ledger.reserve(
                    reservation_v2(
                        allocation_id=value["allocation_id"], nonce=value["nonce"]
                    ),
                    now=NOW,
                )
                ledger.finalize(
                    sign_allocation(value, private, now=NOW + timedelta(minutes=9)),
                    private.public_key(),
                    pinned_fingerprint=spki_fingerprint(private.public_key()),
                    now=NOW + timedelta(minutes=9),
                )
                with self.assertRaises(AllocationClaimExpired):
                    ledger.transition(
                        value["allocation_id"],
                        "claim",
                        now=NOW + timedelta(minutes=21, seconds=offset),
                    )

    def test_recovery_never_reopens_a_v2_allocation_with_time_remaining(self) -> None:
        value = payload_v2()
        private = ed25519.Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            ledger = SqliteAllocationLedger(Path(directory) / "ledger.sqlite3")
            ledger.admit(
                sign_allocation(value, private, now=NOW + timedelta(minutes=9)),
                private.public_key(),
                pinned_fingerprint=spki_fingerprint(private.public_key()),
                now=NOW + timedelta(minutes=9),
            )
            ledger.transition(value["allocation_id"], "recover")
            with self.assertRaises(InvalidLifecycleTransition):
                ledger.transition(
                    value["allocation_id"],
                    "claim",
                    now=NOW + timedelta(minutes=10),
                )

    def test_v1_ledger_migration_preserves_legacy_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            db = sqlite3.connect(path)
            db.execute(
                """CREATE TABLE runner_allocations (
                allocation_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL UNIQUE,
                payload_digest TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT,
                jobs_started INTEGER NOT NULL DEFAULT 0,
                cleanup_complete INTEGER NOT NULL DEFAULT 0,
                issued_at TEXT, expires_at TEXT,
                recovery_required INTEGER NOT NULL DEFAULT 0,
                cleanup_pending INTEGER NOT NULL DEFAULT 0,
                cleanup_idempotency_key TEXT, cleanup_evidence_digest TEXT
                )"""
            )
            db.execute(
                """INSERT INTO runner_allocations(
                allocation_id,binding_digest,payload_digest,state,issued_at,expires_at
                ) VALUES(?,?,?,?,?,?)""",
                (
                    "0198ef24-f800-7000-8000-000000000999",
                    "a" * 64,
                    "b" * 64,
                    "issued",
                    "2026-08-27T12:00:00Z",
                    "2026-08-27T12:05:00Z",
                ),
            )
            db.execute("PRAGMA user_version=1")
            db.commit()
            db.close()

            ledger = SqliteAllocationLedger(path)
            record = ledger.get(
                "0198ef24-f800-7000-8000-000000000999"
            )
            self.assertEqual(record.expires_at, record.claim_deadline)
            event = {
                "event_key": "migration:v1", "cause_code": "claim-expired",
                "allocation_id": record.allocation_id, "run_id": None, "job_id": None,
                "repository": None, "pr_number": None, "head_sha": None,
                "prior_ledger_state": record.state,
                "issued_at": "2026-08-27T12:00:00Z",
                "claim_deadline": "2026-08-27T12:05:00Z", "now": NOW,
                "delay_bucket": ">5m", "executed": False, "success": False,
            }
            self.assertTrue(ledger.append_outcome(event))
            self.assertEqual("migration:v1", ledger.outcomes(since=NOW - timedelta(days=1), now=NOW)[0]["event_key"])
            migrated = sqlite3.connect(path)
            self.assertEqual(2, migrated.execute("PRAGMA user_version").fetchone()[0])
            self.assertIsNotNone(migrated.execute("SELECT name FROM sqlite_master WHERE name='allocation_outcomes'").fetchone())
            migrated.close()

    def test_future_ledger_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.sqlite3"
            db = sqlite3.connect(path)
            db.execute("PRAGMA user_version=99")
            db.close()
            with self.assertRaisesRegex(RunnerJitError, "newer than this binary"):
                SqliteAllocationLedger(path)


class RunnerLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.ledger = SqliteAllocationLedger(Path(self.tempdir.name) / "ledger.sqlite3")
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.fingerprint = spki_fingerprint(self.private.public_key())

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def admit(self, value: dict) -> str:
        return self.ledger.admit(
            sign_allocation(value, self.private, now=NOW),
            self.private.public_key(),
            pinned_fingerprint=self.fingerprint,
            now=NOW,
        )

    def test_outcome_migration_preserves_inflight_allocation_and_rejects_raw_payload(self):
        value = reservation_v2()
        self.ledger.reserve(value, now=NOW)
        before = self.ledger.get(value["allocation_id"])
        event = {
            "event_key": "test:expiry", "cause_code": "claim-expired",
            "allocation_id": value["allocation_id"], "run_id": "8001", "job_id": "8002",
            "repository": value["repository"], "pr_number": value["pr_number"],
            "head_sha": value["head_sha"], "prior_ledger_state": before.state,
            "issued_at": value["approval_issued_at"], "claim_deadline": None,
            "now": NOW, "delay_bucket": "unknown", "executed": False, "success": False,
        }
        self.assertTrue(self.ledger.append_outcome(event))
        self.assertFalse(self.ledger.append_outcome(event))
        self.assertFalse(self.ledger.append_outcome(dict(
            event, now=NOW + timedelta(seconds=1), prior_ledger_state="cleaned",
        )))
        with self.assertRaisesRegex(RunnerJitError, "different content"):
            self.ledger.append_outcome(dict(event, cause_code="claim-state-conflict"))
        self.assertEqual(before, self.ledger.get(value["allocation_id"]))
        with self.assertRaises(RunnerJitError):
            self.ledger.append_outcome(dict(event, raw_payload="ghp_secret-looking-value"))
        raw = Path(self.ledger.path).read_bytes()
        self.assertNotIn(b"ghp_secret-looking-value", raw)

    def test_outcome_fixture_counts_retain_exact_safe_ids(self):
        common = {"allocation_id": None, "job_id": None, "repository": "alethia-earth/Overworld",
                  "pr_number": 602, "head_sha": "a" * 40, "prior_ledger_state": None,
                  "issued_at": None, "claim_deadline": None, "now": NOW,
                  "delay_bucket": "unknown"}
        self.ledger.append_outcome({**common, "event_key": "run:A", "cause_code": "superseded-head",
                                    "run_id": "10", "executed": False, "success": False})
        self.ledger.append_outcome({**common, "event_key": "run:B", "cause_code": "success",
                                    "run_id": "11", "executed": True, "success": True})
        events = self.ledger.outcomes(since=NOW - timedelta(days=1), now=NOW)
        self.assertEqual(["superseded-head", "success"], [item["cause_code"] for item in events])
        self.assertEqual(["10", "11"], [item["run_id"] for item in events])

    def test_issue_is_transactional_idempotent_and_nonce_replay_fails(self) -> None:
        value = payload()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.admit(value), range(16)))
        self.assertEqual(1, results.count("issued"))
        self.assertEqual(15, results.count("idempotent"))
        other = payload(allocation_id="0198ef24-f800-7000-8000-000000000002")
        with self.assertRaises(RunnerJitError):
            self.admit(other)
        changed = dict(value)
        changed["head_sha"] = "c" * 40
        with self.assertRaises(RunnerJitError):
            self.admit(changed)

    def test_exactly_one_job_and_cleanup_all_terminal_outcomes(self) -> None:
        for index, outcome in enumerate(
            ("success", "failure", "cancel", "timeout", "force-cancel", "reboot"),
            start=1,
        ):
            allocation_id = f"0198ef24-f800-7000-8000-{index:012d}"
            value = payload(allocation_id=allocation_id, nonce=chr(64 + index) * 43)
            self.admit(value)
            self.ledger.transition(allocation_id, "claim", now=NOW)
            self.ledger.transition(allocation_id, "start", now=NOW)
            with self.assertRaises(RunnerJitError):
                self.ledger.transition(allocation_id, "start", now=NOW)
            self.ledger.transition(
                allocation_id,
                "finish",
                outcome=outcome,
                normal_cancel_attempted=outcome == "force-cancel",
            )
            record = self.ledger.transition(allocation_id, "cleanup")
            self.assertEqual("cleaned", record.state)
            self.assertTrue(record.cleanup_complete)
            self.assertEqual(1, record.jobs_started)
            self.assertEqual(record, self.ledger.transition(allocation_id, "cleanup"))

    def test_skip_and_invalid_outcome_are_rejected(self) -> None:
        value = payload()
        self.admit(value)
        with self.assertRaises(RunnerJitError):
            self.ledger.transition(value["allocation_id"], "start", now=NOW)
        self.ledger.transition(value["allocation_id"], "claim", now=NOW)
        self.ledger.transition(value["allocation_id"], "start", now=NOW)
        with self.assertRaises(RunnerJitError):
            self.ledger.transition(value["allocation_id"], "finish", outcome="unknown")
        with self.assertRaises(RunnerJitError):
            self.ledger.transition(
                value["allocation_id"], "finish", outcome="force-cancel"
            )

    def test_claim_revalidates_deadline_but_start_uses_durable_claim(self) -> None:
        for offset, accepted in ((-1, True), (0, False), (1, False)):
            allocation_id = f"0198ef24-f800-7000-8001-{offset + 2:012d}"
            value = payload(allocation_id=allocation_id, nonce=chr(70 + offset) * 43)
            self.admit(value)
            at_boundary = NOW + timedelta(minutes=5, seconds=offset)
            if accepted:
                claimed = self.ledger.transition(
                    allocation_id, "claim", now=at_boundary
                )
                self.assertEqual("claimed", claimed.state)
            else:
                with self.assertRaises(RunnerJitError):
                    self.ledger.transition(allocation_id, "claim", now=at_boundary)
                self.assertEqual("issued", self.ledger.get(allocation_id).state)

        value = payload(
            allocation_id="0198ef24-f800-7000-8002-000000000001", nonce="Z" * 43
        )
        self.admit(value)
        self.ledger.transition(
            value["allocation_id"],
            "claim",
            now=NOW + timedelta(minutes=4, seconds=59),
        )
        self.ledger.transition(
            value["allocation_id"],
            "start",
            now=NOW + timedelta(minutes=5, seconds=1),
        )
        record = self.ledger.get(value["allocation_id"])
        self.assertEqual(NOW, record.issued_at)
        self.assertEqual(NOW + timedelta(minutes=5), record.expires_at)
        self.assertEqual("running", record.state)

    def test_reboot_recovery_is_atomic_and_idempotent_from_all_live_states(
        self,
    ) -> None:
        for index, initial in enumerate(("issued", "claimed", "running"), start=1):
            allocation_id = f"0198ef24-f800-7000-8003-{index:012d}"
            value = payload(allocation_id=allocation_id, nonce=chr(74 + index) * 43)
            self.admit(value)
            if initial in {"claimed", "running"}:
                self.ledger.transition(allocation_id, "claim", now=NOW)
            if initial == "running":
                self.ledger.transition(allocation_id, "start", now=NOW)
            recovered = self.ledger.transition(allocation_id, "recover")
            self.assertEqual("recovery_required", recovered.state)
            self.assertEqual("reboot", recovered.outcome)
            self.assertEqual(1 if initial == "running" else 0, recovered.jobs_started)
            self.assertFalse(recovered.cleanup_complete)
            self.assertTrue(recovered.recovery_required)
            self.assertTrue(recovered.cleanup_pending)
            self.assertRegex(recovered.cleanup_idempotency_key or "", r"^[0-9a-f]{64}$")
            self.assertEqual(
                recovered, self.ledger.transition(allocation_id, "recover")
            )

            # Crash before the external cleanup effect: reopening the ledger
            # preserves the same pending operation and idempotency key.
            reopened = SqliteAllocationLedger(self.ledger.path)
            self.assertEqual(recovered, reopened.get(allocation_id))

            evidence = {
                "allocation_id": allocation_id,
                "cleanup_idempotency_key": recovered.cleanup_idempotency_key,
                "jobs_started": recovered.jobs_started,
                "registration_removed": True,
                "workspace_removed": True,
                "token_removed": True,
                "container_removed": True,
                "allocation_removed": True,
                "orphan_registrations": 0,
            }
            # Crash after the idempotent external effect but before the ledger
            # commit is recovered by acknowledging with the durable same key.
            cleaned = reopened.transition(
                allocation_id,
                "ack-recovery-cleanup",
                cleanup_idempotency_key=recovered.cleanup_idempotency_key,
                cleanup_evidence=evidence,
            )
            self.assertEqual("cleaned", cleaned.state)
            self.assertTrue(cleaned.cleanup_complete)
            self.assertFalse(cleaned.recovery_required)
            self.assertFalse(cleaned.cleanup_pending)
            self.assertRegex(cleaned.cleanup_evidence_digest or "", r"^[0-9a-f]{64}$")
            # Crash after commit: the exact acknowledgement is idempotent.
            self.assertEqual(
                cleaned,
                reopened.transition(
                    allocation_id,
                    "ack-recovery-cleanup",
                    cleanup_idempotency_key=recovered.cleanup_idempotency_key,
                    cleanup_evidence=evidence,
                ),
            )

    def test_recovery_cleanup_cannot_be_self_acknowledged_or_crossed(self) -> None:
        value = payload(
            allocation_id="0198ef24-f800-7000-8004-000000000001", nonce="Y" * 43
        )
        self.admit(value)
        pending = self.ledger.transition(value["allocation_id"], "recover")
        evidence = {
            "allocation_id": value["allocation_id"],
            "cleanup_idempotency_key": pending.cleanup_idempotency_key,
            "jobs_started": 0,
            "registration_removed": True,
            "workspace_removed": True,
            "token_removed": True,
            "container_removed": True,
            "allocation_removed": True,
            "orphan_registrations": 0,
        }
        for mutate in (
            lambda item: item.__setitem__("registration_removed", False),
            lambda item: item.__setitem__("jobs_started", 1),
            lambda item: item.__setitem__("cleanup_idempotency_key", "0" * 64),
        ):
            crossed = dict(evidence)
            mutate(crossed)
            with self.assertRaises(RunnerJitError):
                self.ledger.transition(
                    value["allocation_id"],
                    "ack-recovery-cleanup",
                    cleanup_idempotency_key=pending.cleanup_idempotency_key,
                    cleanup_evidence=crossed,
                )
        self.assertEqual(
            "recovery_required", self.ledger.get(value["allocation_id"]).state
        )


if __name__ == "__main__":
    unittest.main()
