from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-local-only.py"
SPEC = importlib.util.spec_from_file_location("check_local_only", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LocalOnlyCapabilityTests(unittest.TestCase):
    def test_current_repository_has_no_forbidden_capability(self) -> None:
        self.assertEqual([], MODULE.violations(ROOT))

    def assert_fixture_is_rejected(self, name: str, contents: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            self.assertTrue(MODULE.violations(root))

    def test_cli_and_legacy_config_are_rejected(self) -> None:
        self.assert_fixture_is_rejected("deploy.sh", "wrang" + "ler deploy\n")
        self.assert_fixture_is_rejected("wrang" + "ler.jsonc", "{}\n")
        self.assert_fixture_is_rejected("config.json", '{"durable_' + 'objects": {}}\n')

    def test_every_case_variant_and_unlisted_context_is_rejected(self) -> None:
        provider = "cloud" + "flare"
        fixtures = {
            "runtime.ts": f'import value from "{provider}";\n',
            "package.json": f'{{"dependencies":{{"{provider}":"1"}}}}\n',
            "settings.toml": f"# use {provider.upper()} later\n",
            "config.yaml": f"provider: {provider.title()}Gateway\n",
            f"{provider}-deploy.yml": "name: inert\n",
        }
        for name, contents in fixtures.items():
            with self.subTest(name=name):
                self.assert_fixture_is_rejected(name, contents)

    def test_non_operational_documentation_does_not_create_runtime_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "decision.md").write_text("Cloud" + "flare is prohibited.\n", encoding="utf-8")
            self.assertEqual([], MODULE.violations(root))


if __name__ == "__main__":
    unittest.main()
