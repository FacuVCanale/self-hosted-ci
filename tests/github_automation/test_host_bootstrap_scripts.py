from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH_SCRIPT = ROOT / "scripts/host/bootstrap-ubuntu-24.04-wsl.sh"
POWERSHELL_SCRIPT = ROOT / "scripts/host/bootstrap-ubuntu-24.04-wsl.ps1"


class HostBootstrapScriptTests(unittest.TestCase):
    def test_bash_is_syntactically_valid_and_renders_fail_closed_wsl_config(self) -> None:
        syntax = subprocess.run(["bash", "-n", str(BASH_SCRIPT)], text=True, capture_output=True, check=False)
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        rendered = subprocess.run(
            ["bash", str(BASH_SCRIPT), "--print-wsl-conf"], text=True, capture_output=True, check=False
        )
        self.assertEqual(0, rendered.returncode, rendered.stderr)
        self.assertIn("[boot]\nsystemd=true", rendered.stdout)
        self.assertIn("[automount]\nenabled=false\nmountFsTab=false", rendered.stdout)
        self.assertIn("[interop]\nenabled=false\nappendWindowsPath=false", rendered.stdout)

    def test_bootstrap_has_exact_platform_guards_and_no_runner_registration(self) -> None:
        source = BASH_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_DISTRO="Ubuntu-24.04-CI"', source)
        self.assertIn('VERSION_ID:-}" == "24.04"', source)
        self.assertIn('WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}"', source)
        self.assertIn("grep -qi 'wsl2' /proc/sys/kernel/osrelease", source)
        self.assertNotIn("grep -Eqi '(microsoft|wsl2)'", source)
        self.assertIn('runner_registered": false', source)
        self.assertIn('secrets_managed": false', source)
        forbidden = ("config.sh", "registration-token", "registration_token", "github_pat", "gh api")
        for token in forbidden:
            self.assertNotIn(token, source.lower())

    def test_bootstrap_declares_idempotent_accounts_directories_and_permissions(self) -> None:
        source = BASH_SCRIPT.read_text(encoding="utf-8")
        self.assertRegex(source, r'if ! getent passwd "\$\{RUNNER_USER\}"')
        self.assertIn('install -d -o root -g "${RUNNER_USER}" -m 0750 "${INSTALL_DIR}"', source)
        self.assertIn('install -d -o root -g "${RUNNER_USER}" -m 0750 "${STATE_DIR}"', source)
        state_guard = source.index('if [[ ! -d "${STATE_DIR}" ]]')
        state_install = source.index('install -d -o root -g "${RUNNER_USER}" -m 0750 "${STATE_DIR}"')
        state_guard_end = source.index("fi", state_install)
        self.assertLess(state_guard, state_install)
        self.assertLess(state_install, state_guard_end)
        self.assertIn('passwd --lock "${RUNNER_USER}"', source)
        self.assertIn('passwd --status "${RUNNER_USER}"', source)
        self.assertIn('must have a dedicated primary group', source)
        self.assertIn('must use /home/${RUNNER_USER}', source)
        self.assertIn("explicit sudoers authorization exists", source)

    def test_evidence_template_is_valid_non_secret_json(self) -> None:
        source = BASH_SCRIPT.read_text(encoding="utf-8")
        match = re.search(r'cat >"\$\{evidence_tmp\}" <<EOF\n(?P<body>.*?)\nEOF', source, re.DOTALL)
        self.assertIsNotNone(match)
        body = match.group("body")
        substitutions = {
            "${generated_at}": "2026-08-26T12:00:00Z",
            "${EXPECTED_DISTRO}": "Ubuntu-24.04-CI",
            "${RUNNER_USER}": "ci-runner",
            "${runner_uid}": "1000",
            "${INSTALL_DIR}": "/opt/self-hosted-ci",
            "${STATE_DIR}": "/var/lib/self-hosted-ci",
            "${wsl_conf_sha256}": "a" * 64,
        }
        for old, new in substitutions.items():
            body = body.replace(old, new)
        document = json.loads(body)
        self.assertEqual("bootstrapped-restart-required", document["status"])
        self.assertFalse(document["checks"]["runner_registered"])
        self.assertFalse(document["checks"]["secrets_managed"])
        self.assertFalse(any(word in body.lower() for word in ("token", "password_hash", "private_key")))

    def test_powershell_wrapper_is_pinned_and_streams_bootstrap_to_root(self) -> None:
        source = POWERSHELL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('[string]$DistroName = "Ubuntu-24.04-CI"', source)
        self.assertIn("[string]$BootstrapScript,", source)
        self.assertIn("if ([string]::IsNullOrWhiteSpace($BootstrapScript))", source)
        self.assertIn('$BootstrapScript = Join-Path $PSScriptRoot "bootstrap-ubuntu-24.04-wsl.sh"', source)
        self.assertIn("$DistroName -ne \"Ubuntu-24.04-CI\"", source)
        self.assertIn("[Convert]::ToBase64String", source)
        self.assertIn("base64 --decode | bash", source)
        self.assertIn("& wsl.exe --distribution $DistroName --user root -- bash -lc $wslCommand", source)
        self.assertIn("[switch]$TerminateAfterBootstrap", source)


if __name__ == "__main__":
    unittest.main()
