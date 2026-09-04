import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/install-agent-interfaces.py"


class InstallAgentInterfacesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.key = self.home / "id_ed25519"
        self.key.write_text("test", encoding="utf-8")
        os.chmod(self.key, 0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def run_installer(self, *extra: str) -> subprocess.CompletedProcess[str]:
        config = self.home / ".config/self-hosted-ci/config.json"
        argv = [
            "python3", str(INSTALLER),
            "--ssh-target", "selfhosted-ci-svc@100.117.46.21",
            "--ssh-key", str(self.key),
            "--public-sha", "d" * 40,
            "--config", str(config),
            "--bin-dir", str(self.home / ".local/bin"),
            *extra,
        ]
        return subprocess.run(
            argv, text=True, capture_output=True, check=False,
            env={**os.environ, "HOME": str(self.home)}, cwd=ROOT,
        )

    def test_installs_one_canonical_skill_for_codex_and_claude(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        codex = Path(payload["codex_skill"])
        claude = Path(payload["claude_skill"])
        cli = Path(payload["cli"])
        self.assertTrue(codex.is_symlink())
        self.assertTrue(claude.is_symlink())
        self.assertEqual(codex.resolve(), claude.resolve())
        self.assertTrue(cli.is_symlink())
        config = Path(payload["config"])
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(config.parent.stat().st_mode & 0o777, 0o700)

    def test_preflight_conflict_leaves_no_partial_installation(self):
        conflict = self.home / ".claude/skills/self-hosted-ci"
        conflict.mkdir(parents=True)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / ".codex/skills/self-hosted-ci").exists())
        self.assertFalse((self.home / ".local/bin/self-hosted-ci").exists())
        self.assertFalse((self.home / ".config/self-hosted-ci/config.json").exists())

    def test_rejects_distro_command_injection_before_writes(self):
        result = self.run_installer("--distro", "Ubuntu;whoami")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / ".config/self-hosted-ci/config.json").exists())

    def test_skill_forbids_ad_hoc_persistent_runner_fallbacks(self):
        skill = (ROOT / "skills/self-hosted-ci/SKILL.md").read_text(encoding="utf-8")
        for required in (
            "dedicated `Ubuntu-24.04-CI` distro",
            "Never register or launch a persistent/ad-hoc GitHub Actions runner",
            "`~/actions-runner-*`",
            "generic `runs-on: self-hosted` label",
            "allocation-specific JIT label",
            "dependencies belong in the versioned, pinned ephemeral runner image",
            "successful job on a non-conforming runner is diagnostic evidence only",
            "Do not improvise an alternate runner",
        ):
            with self.subTest(required=required):
                self.assertIn(required, skill)


if __name__ == "__main__":
    unittest.main()
