import json
import hashlib
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

    def test_canonical_installer_replaces_ceremony_and_receipts_previous_digest(self):
        target = self.home / ".local/share/self-hosted-ci/ceremony.sh"
        receipt = self.home / ".config/self-hosted-ci/rotation-ceremony-install.json"
        target.parent.mkdir(parents=True)
        previous = b"#!/bin/bash\nold ceremony\n"
        target.write_bytes(previous)
        sha = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        result = self.run_installer(
            "--public-sha", sha,
            "--install-rotation-ceremony",
            "--acknowledge-rotation-ceremony-replacement",
            "--rotation-ceremony-target", str(target),
            "--rotation-ceremony-receipt", str(receipt),
        )
        self.assertEqual(0, result.returncode, result.stderr)
        committed = subprocess.check_output([
            "git", "-C", str(ROOT), "show",
            f"{sha}:scripts/host/run-overworld-rotation-ceremony.sh",
        ])
        self.assertEqual(committed, target.read_bytes())
        value = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(previous).hexdigest(), value["previous_ceremony_sha256"])
        self.assertEqual(hashlib.sha256(committed).hexdigest(), value["installed_ceremony_sha256"])
        self.assertEqual(0o700, target.stat().st_mode & 0o777)
        self.assertEqual(0o600, receipt.stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
