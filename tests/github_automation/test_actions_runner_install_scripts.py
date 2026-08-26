from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-actions-runner.sh"
VERIFIER = ROOT / "scripts/host/verify-actions-runner.sh"
POWERSHELL = ROOT / "scripts/host/install-actions-runner-wsl.ps1"


class ActionsRunnerInstallScriptTests(unittest.TestCase):
    def test_bash_scripts_are_valid_and_require_version_and_sha256(self) -> None:
        for script in (INSTALLER, VERIFIER):
            syntax = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True, check=False)
            self.assertEqual(0, syntax.returncode, syntax.stderr)
            missing = subprocess.run(["bash", str(script)], text=True, capture_output=True, check=False)
            self.assertEqual(1, missing.returncode)
            self.assertIn("--version", missing.stderr)

    def test_installer_uses_only_exact_official_release_url_and_checks_before_extract(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('RELEASE_BASE_URL="https://github.com/actions/runner/releases/download"', source)
        self.assertIn('archive_name="actions-runner-linux-x64-${version}.tar.gz"', source)
        self.assertIn('download_url="${RELEASE_BASE_URL}/v${version}/${archive_name}"', source)
        self.assertNotIn("api.github.com", source)
        self.assertLess(source.index("sha256sum --check --status"), source.index("tar --extract"))
        self.assertIn("--proto '=https' --tlsv1.2", source)

    def test_installer_is_idempotent_root_owned_and_does_not_register(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('installed_version}" == "${version}', source)
        self.assertIn('installed_sha256}" == "${expected_sha256}', source)
        self.assertIn('chown -R root:"${RUNNER_USER}"', source)
        self.assertIn('chmod -R u=rwX,g=rX,o=', source)
        self.assertIn('WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}"', source)
        self.assertIn("explicit sudoers authorization exists", source)
        self.assertIn('Registration was not performed.', source)
        forbidden = ("config.sh --", "registration_token", "registration-token", "remove-token", "github_pat", "sudo -u")
        for token in forbidden:
            self.assertNotIn(token, source.lower())

    def test_verifier_enforces_identity_source_permissions_and_exact_pin(self) -> None:
        source = VERIFIER.read_text(encoding="utf-8")
        self.assertIn('expected_url="${RELEASE_BASE_URL}/v${version}/actions-runner-linux-x64-${version}.tar.gz"', source)
        self.assertIn('installed_sha256}" == "${expected_sha256}', source)
        self.assertIn('root:${RUNNER_USER}:750', source)
        self.assertIn('find "${INSTALL_DIR}" ! -user root', source)
        self.assertIn('\\( -type f -o -type d \\) -perm /0020', source)
        self.assertIn('find "${INSTALL_DIR}" -type l -print0', source)
        self.assertIn('installation symlink escapes its root', source)
        self.assertIn('WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}"', source)
        self.assertIn("explicit sudoers authorization exists", source)
        self.assertIn("'^(sudo|admin|wheel)$'", source)

    def test_powershell_wrapper_requires_pins_and_runs_only_as_wsl_root(self) -> None:
        source = POWERSHELL.read_text(encoding="utf-8")
        self.assertEqual(2, source.count("[Parameter(Mandatory = $true)]"))
        self.assertIn('[string]$DistroName = "Ubuntu-24.04"', source)
        self.assertIn('Join-Path $PSScriptRoot "install-actions-runner.sh"', source)
        self.assertIn("[Convert]::ToBase64String", source)
        self.assertIn("--version '$Version' --sha256 '$normalizedSha256'", source)
        self.assertIn("& wsl.exe --distribution $DistroName --user root -- bash -lc $wslCommand", source)


if __name__ == "__main__":
    unittest.main()
