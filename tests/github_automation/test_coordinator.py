from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from github_automation.coordinator import main
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


if __name__ == "__main__":
    unittest.main()
