from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from github_automation.github import (
    AppAuthorityV1,
    ControlFailure,
    DispatchRequest,
    FORBIDDEN_APP_PERMISSIONS,
    MINIMUM_APP_PERMISSIONS,
    MintRequest,
    ProtocolFailure,
    ProtocolPackage,
    RuntimeIdentity,
    hosted_conclusion_allowed,
    parse_dispatch_response,
    parse_observed_workflow_job,
    validate_ci_gate_source,
    validate_formal_claim,
)


SHA = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
DIGEST = "d" * 64
NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
OWNER = "example-owner"
REPOSITORY = f"{OWNER}/example-repo"
CONTROL_WORKFLOW = f"{OWNER}/ci-control/.github/workflows/coordinator.yml"


def authority(**changes) -> AppAuthorityV1:
    values = {
        "owner": OWNER,
        "app_id": 111,
        "app_slug": "self-hosted-ci-gate",
        "repository": REPOSITORY,
        "repository_id": 123,
        "installation_id": 222,
        "control_workflow_identity": CONTROL_WORKFLOW,
        "control_workflow_ref": "refs/heads/main",
        "key_fingerprint": DIGEST,
        "key_version": 1,
        "rotated_at": NOW,
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
    }
    values.update(changes)
    return AppAuthorityV1(**values)


def identity(role: str = "coordinator") -> RuntimeIdentity:
    return RuntimeIdentity(
        role=role,
        workflow_identity=CONTROL_WORKFLOW,
        workflow_ref="refs/heads/main",
    )


def mint_request(**changes) -> MintRequest:
    values = {
        "app_id": 111,
        "installation_id": 222,
        "repository": REPOSITORY,
        "repository_id": 123,
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
        "ttl_seconds": 3600,
    }
    values.update(changes)
    return MintRequest(**values)


def protocol(backend: str = "local") -> dict:
    local = backend == "local"
    data = {
        "protocol_version": 1,
        "timing_policy_version": 1,
        "execution_trust_policy_version": 1,
        "repository_id": 123,
        "repository": REPOSITORY,
        "pr_number": 42,
        "logical_key": f"123:42:{SHA}:ci-gate",
        "generation": 7,
        "owner_run_id": 900,
        "owner_run_attempt": 1,
        "head_sha": SHA,
        "base_sha": BASE,
        "tested_merge_sha": MERGE,
        "tested_sha": MERGE,
        "check_target_sha": MERGE,
        "default_branch": "main",
        "backend": backend,
        "policy_version": "e" * 40,
        "execution_trust_mode": "exact-sha-attestation" if local else "github-hosted",
        "execution_trust_attestation_authority_version": 1,
        "execution_trust_key_manifest_version": 1,
        "key_manifest_generation": 3,
        "key_manifest_digest": DIGEST,
        "key_manifest_generation_at_issuance": "3" if local else None,
        "key_manifest_digest_at_issuance": DIGEST if local else None,
        "attestation_id": "0198e000-0000-7000-8000-000000000001" if local else None,
        "attestation_key_id": "online-1" if local else None,
        "attestation_key_version": 1 if local else None,
        "attestation_public_key_fingerprint": DIGEST if local else None,
        "attestation_head_generation": 4 if local else None,
        "attestation_expires_at": "2026-08-26T13:00:00Z" if local else None,
        "attestation_nonce_binding": "nonce-ref" if local else None,
        "attestation_envelope_digest": DIGEST if local else None,
        "attestation_request_linkage_hash": DIGEST if local else None,
        "inventory_guard_status": "complete",
        "missing_source_ids": [],
        "effective_writer_inventory_hash": DIGEST if local else None,
        "inventory_observed_at": "2026-08-26T12:00:00Z" if local else None,
        "inventory_guard_freshness_policy_version": 1,
        "local_admission_id": None,
        "local_admission_digest": None,
        "local_evidence_id": None,
        "local_evidence_digest": None,
        "local_result_kind": None,
        "local_child_run_id": 444 if local else None,
        "local_child_job_id": 555 if local else None,
        "started_test_marker_digest": None,
        "canonical_command_digest": None,
        "terminal_at": None,
        "ci_gate_check_run_id": 333,
        "check_outbox_idempotency_key": None,
        "claim_deadline": "2026-08-26T12:10:00Z",
        "execution_deadline": "2026-08-26T12:45:00Z",
        "allocation_id": "12345678-1234-4123-8123-123456789abc" if local else None,
        "allocation_nonce": "A" * 43 if local else None,
        "runner_label": "wsl-jit-" + "1" * 32 if local else None,
    }
    return data


class AppAuthorityTests(unittest.TestCase):
    def test_s62_exact_positive_and_negative_permissions(self) -> None:
        auth = authority()
        self.assertTrue(auth.permits("checks:create", repository=auth.repository, installation_id=222))
        self.assertTrue(auth.permits("checks:update", repository=auth.repository, installation_id=222))
        for permission in FORBIDDEN_APP_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertFalse(auth.permits(f"{permission}:read", repository=auth.repository, installation_id=222))
                self.assertFalse(auth.permits(f"{permission}:write", repository=auth.repository, installation_id=222))
        self.assertFalse(auth.permits("checks:update", repository=f"{OWNER}/other", installation_id=222))

    def test_s62_authority_schema_is_exact_and_fail_closed(self) -> None:
        bad = (
            {"owner": "invalid_owner"}, {"app_id": 0}, {"installation_id": 0},
            {"repository": f"{OWNER}/*"}, {"key_fingerprint": "A" * 64},
            {"permissions": {"metadata": "read", "checks": "write", "contents": "read"}},
        )
        for changes in bad:
            with self.subTest(changes=changes), self.assertRaises(ControlFailure):
                authority(**changes)

    def test_s63_only_exact_control_identity_can_mint_narrow_memory_token(self) -> None:
        auth = authority()
        self.assertEqual(mint_request(), auth.mint(identity(), mint_request()))
        self.assertEqual(mint_request(ttl_seconds=3599), auth.mint(identity("reconciler"), mint_request(ttl_seconds=3599)))
        for bad_identity in (
            identity("child"),
            RuntimeIdentity("coordinator", "other/workflow", "refs/heads/main"),
            RuntimeIdentity("coordinator", identity().workflow_identity, "refs/pull/42/merge"),
            RuntimeIdentity("coordinator", identity().workflow_identity, "refs/heads/main", False),
        ):
            with self.subTest(identity=bad_identity), self.assertRaises(ControlFailure):
                auth.mint(bad_identity, mint_request())

    def test_s63_ttl_scope_permissions_and_storage_boundaries(self) -> None:
        auth = authority()
        for ttl in (3599, 3600):
            auth.mint(identity(), mint_request(ttl_seconds=ttl))
        invalid = (
            {"ttl_seconds": 3601}, {"repository": f"{OWNER}/other"}, {"installation_id": 223},
            {"permissions": {"checks": "write"}}, {"export_to_children": True},
            {"persist": True}, {"masked": False}, {"memory_only": False},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ControlFailure):
                auth.mint(identity(), mint_request(**changes))

    def test_s64_rotation_requires_new_key_then_old_revokes(self) -> None:
        old = authority()
        new = authority(key_version=2, key_fingerprint="f" * 64, rotated_at=NOW + timedelta(days=1))
        self.assertIs(new, old.rotated_to(new))
        revoked = old.revoked()
        self.assertFalse(revoked.permits("checks:update", repository=old.repository, installation_id=222))
        with self.assertRaises(ControlFailure):
            revoked.mint(identity(), mint_request())
        with self.assertRaises(ControlFailure):
            old.rotated_to(authority(key_version=2, key_fingerprint=DIGEST, rotated_at=NOW + timedelta(days=1)))


class DispatchAndProtocolTests(unittest.TestCase):
    def test_two_phase_observation_requires_exact_run_job_and_reserved_label(self) -> None:
        label = "wsl-jit-" + "1" * 32
        observed = parse_observed_workflow_job(777, label, {"id": 777, "run_attempt": 2, "head_sha": "f" * 40}, {"total_count": 2, "jobs": [
            {"id": 887, "run_id": 777, "name": "validate trusted dispatch package", "labels": ["ubuntu-24.04"]},
            {"id": 888, "run_id": 777, "name": "local-quality", "labels": ["self-hosted", label]},
        ]})
        self.assertEqual((777, 2, 888), (observed.run_id, observed.run_attempt, observed.job_id))
        invalid = (
            {"total_count": 0, "jobs": []},
            {"total_count": 1, "jobs": [{"id": 888, "run_id": 778, "name": "local-quality", "labels": [label]}]},
            {"total_count": 1, "jobs": [{"id": 888, "run_id": 777, "name": "local-quality", "labels": ["self-hosted"]}]},
        )
        for jobs in invalid:
            with self.assertRaises(ProtocolFailure):
                parse_observed_workflow_job(777, label, {"id": 777, "run_attempt": 2, "head_sha": "f" * 40}, jobs)

    def test_s45_dispatch_is_pinned_and_consumes_exact_http_200_run_id(self) -> None:
        request = DispatchRequest(REPOSITORY, "child.yml", "main", "main")
        receipt = {
            "workflow_run_id": 777,
            "run_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/777",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/777",
        }
        self.assertEqual(777, parse_dispatch_response(request, 200, receipt))
        invalid_requests = (
            {"api_version": "latest"}, {"ref": "feature"}, {"workflow_id": "dir/child.yml"},
        )
        for changes in invalid_requests:
            values = {"repository": REPOSITORY, "workflow_id": "child.yml", "ref": "main", "default_branch": "main"}
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ProtocolFailure):
                DispatchRequest(**values)
        invalid_responses = (
            (204, {}),
            (200, {}),
            (200, {**receipt, "other": 2}),
            (200, {**receipt, "workflow_run_id": "777"}),
            (200, {**receipt, "run_url": "https://api.github.com/repos/example-owner/other/actions/runs/777"}),
            (200, {**receipt, "html_url": f"https://github.com/{REPOSITORY}/actions/runs/778"}),
        )
        for status, body in invalid_responses:
            with self.subTest(status=status, body=body), self.assertRaises(ProtocolFailure):
                parse_dispatch_response(request, status, body)

    def test_protocol_rejects_unknown_missing_and_backend_crossing(self) -> None:
        ProtocolPackage.from_mapping(protocol("local"))
        ProtocolPackage.from_mapping(protocol("github"))
        cases = []
        missing = protocol(); missing.pop("generation"); cases.append(missing)
        unknown = protocol(); unknown["guess_run_from_list"] = True; cases.append(unknown)
        crossed = protocol("github"); crossed["execution_trust_mode"] = "exact-sha-attestation"; cases.append(crossed)
        leaked = protocol("github"); leaked["attestation_id"] = "foreign"; cases.append(leaked)
        for value in cases:
            with self.subTest(keys=set(value)), self.assertRaises(ProtocolFailure):
                ProtocolPackage.from_mapping(value)

    def test_s12_head_movement_invalidates_tuple(self) -> None:
        package = ProtocolPackage.from_mapping(protocol())
        with self.assertRaises(ProtocolFailure):
            package.assert_current_tuple(repository_id=123, repository=REPOSITORY, pr_number=42,
                                         head_sha="9" * 40, base_sha=BASE, tested_merge_sha=MERGE, generation=8)

    def test_s13_base_or_merge_movement_invalidates_same_head(self) -> None:
        package = ProtocolPackage.from_mapping(protocol())
        for base, merge in (("9" * 40, MERGE), (BASE, "9" * 40)):
            with self.subTest(base=base, merge=merge), self.assertRaises(ProtocolFailure):
                package.assert_current_tuple(repository_id=123, repository=REPOSITORY, pr_number=42,
                                             head_sha=SHA, base_sha=base, tested_merge_sha=merge, generation=8)

    def test_s14_and_s16_tested_sha_is_full_exact_merge_and_checkout(self) -> None:
        for tested in (SHA, "a" * 39, None):
            value = protocol(); value["tested_sha"] = tested
            with self.subTest(tested=tested), self.assertRaises(ProtocolFailure):
                ProtocolPackage.from_mapping(value)
        package = ProtocolPackage.from_mapping(protocol())
        package.assert_checkout(MERGE)
        with self.assertRaises(ProtocolFailure):
            package.assert_checkout(SHA)

    def test_s15_dispatch_ref_is_default_branch(self) -> None:
        value = protocol(); value["default_branch"] = ""
        with self.assertRaises(ProtocolFailure):
            ProtocolPackage.from_mapping(value)


class ClaimAndGateSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = authority()
        self.source = {
            "kind": "check_run", "explicit_custom_check": True, "name": "ci-gate",
            "app_id": 111, "app_slug": "self-hosted-ci-gate", "repository": REPOSITORY,
            "installation_id": 222, "head_sha": MERGE,
        }

    def test_s31_s43_s51_s52_only_dedicated_explicit_app_check_satisfies(self) -> None:
        self.assertTrue(validate_ci_gate_source(self.source, authority=self.auth, check_target_sha=MERGE))
        mutations = (
            {"app_id": 999}, {"kind": "commit_status"}, {"explicit_custom_check": False},
            {"name": "pull-request-target"}, {"head_sha": SHA}, {"installation_id": 999},
        )
        for mutation in mutations:
            event = {**self.source, **mutation}
            with self.subTest(mutation=mutation):
                self.assertFalse(validate_ci_gate_source(event, authority=self.auth, check_target_sha=MERGE))

    def test_s32_child_runtime_cannot_mint_check_writer(self) -> None:
        with self.assertRaises(ControlFailure):
            self.auth.mint(identity("child"), mint_request())

    def test_s33_main_ci_is_not_a_pr_gate_source(self) -> None:
        push_ci = {**self.source, "kind": "workflow_check", "name": "CI", "event": "push"}
        self.assertFalse(validate_ci_gate_source(push_ci, authority=self.auth, check_target_sha=MERGE))

    def test_s07_formal_claim_requires_exact_returned_run_started_job_labels_and_runner(self) -> None:
        package = ProtocolPackage.from_mapping(protocol())
        run = {"id": 444, "workflow_id": "child.yml", "repository": REPOSITORY,
               "workflow_ref": "main", "generation": 7, "backend": "local"}
        job = {"id": 555, "name": "local-attempt", "started_at": "2026-08-26T12:10:00Z",
               "labels": ["self-hosted", "jit-42"],
               "runner": {"id": "runner-unique", "ephemeral": True, "fresh": True, "online": True}}
        self.assertTrue(validate_formal_claim(package=package, dispatch_run_id=444, run=run, jobs=[job],
                                             expected_workflow_id="child.yml", expected_job_name="local-attempt",
                                             expected_labels=["jit-42", "self-hosted"], expected_runner_id="runner-unique"))
        invalid = []
        wrong_run = deepcopy(run); wrong_run["id"] = 999; invalid.append((wrong_run, [job], 444))
        queued = deepcopy(job); queued["started_at"] = None; invalid.append((run, [queued], 444))
        late = deepcopy(job); late["started_at"] = "2026-08-26T12:10:00.000001Z"; invalid.append((run, [late], 444))
        labels = deepcopy(job); labels["labels"] = ["self-hosted"]; invalid.append((run, [labels], 444))
        reused = deepcopy(job); reused["runner"]["fresh"] = False; invalid.append((run, [reused], 444))
        invalid.append((run, [job, job], 444))
        for bad_run, bad_jobs, receipt in invalid:
            with self.subTest(run=bad_run, jobs=bad_jobs), self.assertRaises(ProtocolFailure):
                validate_formal_claim(package=package, dispatch_run_id=receipt, run=bad_run, jobs=bad_jobs,
                                      expected_workflow_id="child.yml", expected_job_name="local-attempt",
                                      expected_labels=["jit-42", "self-hosted"], expected_runner_id="runner-unique")


class HostedConclusionTests(unittest.TestCase):
    def test_hosted_predicate_checks_winner_lease_tuple_command_job_deadline_and_app_not_attestation(self) -> None:
        package = ProtocolPackage.from_mapping(protocol("github"))
        auth = authority()
        gate = {
            "winner": "github", "owner": 900, "generation": 7,
            "logical_key": f"123:42:{SHA}:ci-gate", "repository_id": 123,
            "repository": REPOSITORY, "pr_number": 42, "head_sha": SHA,
            "base_sha": BASE, "tested_merge_sha": MERGE,
            "lease_expires_at": "2026-08-26T12:30:00Z",
            "canonical_command_digest": DIGEST, "hosted_workflow_id": "hosted.yml",
            "hosted_run_id": 700, "hosted_job_id": 701,
        }
        source = {"kind": "check_run", "explicit_custom_check": True, "name": "ci-gate",
                  "app_id": 111, "app_slug": "self-hosted-ci-gate", "repository": REPOSITORY,
                  "installation_id": 222, "head_sha": MERGE}
        hosted = {
            "tested_sha": MERGE, "check_target_sha": MERGE,
            "canonical_command_digest": DIGEST, "workflow_id": "hosted.yml",
            "workflow_ref": "main", "run_id": 700, "job_id": 701,
            "trustworthy_github_hosted": True, "terminal_at": "2026-08-26T12:20:00Z",
            "execution_deadline": "2026-08-26T12:20:00Z", "check_source": source,
            "attestation_valid": False, "attestation_revoked": True,
        }
        self.assertTrue(hosted_conclusion_allowed(package=package, gate=gate, hosted=hosted,
                                                  authority=auth, now=NOW))
        for target, key, value in (
            (gate, "winner", "local"), (gate, "owner", 901), (gate, "generation", 8),
            (hosted, "tested_sha", SHA), (hosted, "canonical_command_digest", "f" * 64),
            (hosted, "run_id", 999), (hosted, "terminal_at", "2026-08-26T12:20:00.000001Z"),
        ):
            changed_gate, changed_hosted = deepcopy(gate), deepcopy(hosted)
            (changed_gate if target is gate else changed_hosted)[key] = value
            with self.subTest(key=key):
                self.assertFalse(hosted_conclusion_allowed(package=package, gate=changed_gate,
                                                           hosted=changed_hosted, authority=auth, now=NOW))


if __name__ == "__main__":
    unittest.main()
