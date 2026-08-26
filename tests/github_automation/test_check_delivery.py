from __future__ import annotations

import unittest

from github_automation.check_delivery import (
    AmbiguousCheckWrite,
    CheckDelivery,
    CheckDeliveryError,
    CheckEvidenceConflict,
    deliver_exact,
)


class Transport:
    def __init__(self, *, observed=None, ambiguous=False):
        self.observed = observed or {}
        self.ambiguous = ambiguous
        self.patches = 0
        self.gets = 0

    def patch_exact(self, check_run_id, payload):
        self.patches += 1
        if self.ambiguous:
            raise AmbiguousCheckWrite("connection reset")
        self.observed = {"id": check_run_id, **payload}

    def get_exact(self, check_run_id):
        self.gets += 1
        return self.observed


class CheckDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.delivery = CheckDelivery(91, "a" * 64, "failure", "b" * 40)

    def test_s100_s104_ambiguous_patch_exact_get_same_evidence_converges(self):
        transport = Transport(observed={
            "id": 91,
            "external_id": self.delivery.marker,
            "head_sha": "b" * 40,
            "conclusion": "failure",
        }, ambiguous=True)
        self.assertEqual("reconciled", deliver_exact(self.delivery, transport))
        self.assertEqual((1, 1), (transport.patches, transport.gets))

    def test_s100_s104_different_evidence_or_wrong_exact_check_conflicts(self):
        for observed, error in (
            ({"id": 91, "external_id": "github-automation-evidence:" + "c" * 64}, CheckEvidenceConflict),
            ({"id": 92, "external_id": self.delivery.marker}, CheckDeliveryError),
        ):
            with self.subTest(observed=observed), self.assertRaises(error):
                deliver_exact(self.delivery, Transport(observed=observed, ambiguous=True))

    def test_unresolved_ambiguity_remains_retryable_and_never_infers_success(self):
        with self.assertRaises(AmbiguousCheckWrite):
            deliver_exact(self.delivery, Transport(observed={"id": 91}, ambiguous=True))


if __name__ == "__main__":
    unittest.main()
