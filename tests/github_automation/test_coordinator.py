from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from github_automation.coordinator import (
    CoordinatorUnavailable, ReserveDefinitelyUnavailableBeforeEffect,
    ReservePartialFailure, github_hosted_fallback, main, outbound_local_dispatch,
)
from github_automation.github import ObservedWorkflowJob
from tests.github_automation.test_github_contracts import protocol


class CoordinatorCliTests(unittest.TestCase):
    @staticmethod
    def current_tuple(**changes):
        value = protocol()
        current = {
            "repository_id": value["repository_id"],
            "repository": value["repository"],
            "pr_number": value["pr_number"],
            "head_sha": value["head_sha"],
            "base_sha": value["base_sha"],
            "tested_merge_sha": value["tested_merge_sha"],
            "generation": value["generation"],
        }
        current.update(changes)
        return json.dumps(current)

    def test_coordinate_and_reconcile_are_inert_without_external_adapter(self) -> None:
        self.assertEqual(2, main(["coordinate"], {}))
        self.assertEqual(2, main(["reconcile"], {}))
        self.assertEqual(2, main(["coordinate"], {"CI_GATE_COORDINATOR_ENABLED": "true"}))

    def test_child_validates_before_emitting_fixed_scalar_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            environment = {
                "CI_GATE_PROTOCOL_PACKAGE": json.dumps(protocol()),
                "CI_GATE_CURRENT_TUPLE": self.current_tuple(),
                "GITHUB_OUTPUT": str(output),
            }
            self.assertEqual(0, main(["child"], environment))
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual("local", values["backend"])
            self.assertEqual("c" * 40, values["tested_sha"])

    def test_s12_child_rejects_missing_or_moved_head_generation_tuple(self) -> None:
        package = json.dumps(protocol())
        self.assertEqual(2, main(["child"], {"CI_GATE_PROTOCOL_PACKAGE": package}))
        for mutation in ({"head_sha": "9" * 40}, {"generation": 8}):
            with self.subTest(mutation=mutation):
                environment = {
                    "CI_GATE_PROTOCOL_PACKAGE": package,
                    "CI_GATE_CURRENT_TUPLE": self.current_tuple(**mutation),
                }
                self.assertEqual(2, main(["child"], environment))

    def test_s13_child_rejects_base_or_synthetic_merge_movement(self) -> None:
        package = json.dumps(protocol())
        for mutation in ({"base_sha": "8" * 40}, {"tested_merge_sha": "7" * 40}):
            with self.subTest(mutation=mutation):
                environment = {
                    "CI_GATE_PROTOCOL_PACKAGE": package,
                    "CI_GATE_CURRENT_TUPLE": self.current_tuple(**mutation),
                }
                self.assertEqual(2, main(["child"], environment))

    def test_invalid_or_privileged_child_action_fails_closed(self) -> None:
        self.assertEqual(2, main(["child"], {"CI_GATE_PROTOCOL_PACKAGE": "{}"}))
        environment = {"CI_GATE_PROTOCOL_PACKAGE": json.dumps(protocol())}
        self.assertEqual(2, main(["child", "--claim"], environment))
        self.assertEqual(2, main(["child", "--mark-started"], environment))
        self.assertEqual(2, main(["child", "--complete-hosted"], environment))

    def test_outbound_worker_reserves_dispatches_observes_signs_then_finalizes(self) -> None:
        calls = []
        reservation = {
            "allocation_reservation_version": 1,
            "allocation_id": "12345678-1234-4123-8123-123456789abc",
            "nonce": "A" * 43,
            "scale_set_name": "wsl-jit-" + "1" * 32,
            "repository_id": "123", "repository": "example-owner/example-repo",
            "head_sha": "a" * 40,
            "workflow_ref": "example-owner/example-repo/.github/workflows/ci-gate-child.yml@refs/heads/main",
            "job_name": "local-quality", "authority_kind": "personal-repository",
            "runner_group": None, "labels": ["wsl-jit-" + "1" * 32],
            "image_fingerprint": "d" * 64, "issued_at": "2026-08-26T12:00:00Z",
            "expires_at": "2026-08-26T12:05:00Z", "max_jobs": 1, "ephemeral": True,
        }
        class Allocation:
            def reserve(self, value): calls.append("reserve"); return {"allocation_id": value["allocation_id"], "scale_set_id": "9", "runner_label": value["scale_set_name"], "state": "reserved-disabled"}
            def finalize(self, envelope): calls.append(("finalize", envelope["payload"]["job_id"])); return {"allocation_id": reservation["allocation_id"], "state": "enabled-awaiting-claim"}
            def recover(self, allocation_id): calls.append(("recover", allocation_id))
        class GitHub:
            def dispatch_package(self, package): calls.append(("dispatch", package["runner_label"])); return 444
            def observe_exact_job(self, run_id, label): calls.append(("observe", run_id, label)); return ObservedWorkflowJob(444, 1, 555, "local-quality", "f" * 40)
        class Signer:
            def sign_allocation(self, payload): calls.append(("sign", payload["run_id"])); return {"payload": payload, "signature": "external"}
        package, observed = outbound_local_dispatch(protocol(), reservation, allocation=Allocation(), github=GitHub(), signer=Signer())
        self.assertEqual(reservation["scale_set_name"], package.values["runner_label"])
        self.assertEqual(555, observed.job_id)
        self.assertEqual(["reserve", ("dispatch", reservation["scale_set_name"]), ("observe", 444, reservation["scale_set_name"]), ("sign", "444"), ("finalize", "555")], calls)

    def test_local_unavailability_falls_back_before_dispatch_without_local_authority(self) -> None:
        fallback = github_hosted_fallback(protocol())
        self.assertEqual("github", fallback.values["backend"])
        for field in ("allocation_id", "allocation_nonce", "runner_label", "local_child_run_id", "local_child_job_id", "attestation_id"):
            self.assertIsNone(fallback.values[field])

    def test_reserve_unavailability_dispatches_hosted_without_local_authority(self) -> None:
        dispatched = []
        class Allocation:
            def reserve(self, value): raise ReserveDefinitelyUnavailableBeforeEffect("broker unavailable")
        class GitHub:
            def dispatch_package(self, package): dispatched.append(package); return 999
        hosted, observed = outbound_local_dispatch(protocol(), {}, allocation=Allocation(), github=GitHub(), signer=object())
        self.assertIsNone(observed)
        self.assertEqual("github", hosted.values["backend"])
        self.assertEqual([hosted.values], dispatched)

    def test_ambiguous_reserve_failure_blocks_without_hosted_dispatch(self) -> None:
        dispatched = []
        class Allocation:
            def reserve(self, value): raise OSError("connection dropped")
        class GitHub:
            def dispatch_package(self, package): dispatched.append(package); return 999
        with self.assertRaisesRegex(CoordinatorUnavailable, "ambiguous"):
            outbound_local_dispatch(protocol(), {}, allocation=Allocation(), github=GitHub(), signer=object())
        self.assertEqual([], dispatched)

    def test_partial_reserve_recovers_exact_allocation_before_hosted_fallback(self) -> None:
        value = {"allocation_id": "12345678-1234-4123-8123-123456789abc"}
        calls = []
        class Allocation:
            def reserve(self, reservation): raise ReservePartialFailure(reservation["allocation_id"])
            def recover(self, allocation_id):
                calls.append(("recover", allocation_id))
                return {"allocation_id": allocation_id, "state": "absent"}
        class GitHub:
            def dispatch_package(self, package): calls.append(("dispatch", package["backend"])); return 999
        hosted, observed = outbound_local_dispatch(protocol(), value, allocation=Allocation(), github=GitHub(), signer=object())
        self.assertIsNone(observed)
        self.assertEqual("github", hosted.values["backend"])
        self.assertEqual([("recover", value["allocation_id"]), ("dispatch", "github")], calls)

    def test_partial_reserve_without_exact_absence_proof_blocks_fallback(self) -> None:
        value = {"allocation_id": "12345678-1234-4123-8123-123456789abc"}
        dispatched = []
        class Allocation:
            def reserve(self, reservation): raise ReservePartialFailure(reservation["allocation_id"])
            def recover(self, allocation_id): return {"allocation_id": allocation_id, "state": "cleaned"}
        class GitHub:
            def dispatch_package(self, package): dispatched.append(package); return 999
        with self.assertRaisesRegex(CoordinatorUnavailable, "prove absence"):
            outbound_local_dispatch(protocol(), value, allocation=Allocation(), github=GitHub(), signer=object())
        self.assertEqual([], dispatched)


if __name__ == "__main__":
    unittest.main()
