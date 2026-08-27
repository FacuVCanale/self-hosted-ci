from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-jit-prerequisites.ps1"
PAYLOAD = ROOT / "scripts/host/install-jit-prerequisites-wsl-payload.sh.in"


class JitPrerequisiteInstallerTests(unittest.TestCase):
    def test_plan_only_and_apply_are_explicit(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[switch]$Apply", "if (-not $Apply) { return }",
            "AcknowledgeHostPackageInstallation", "AcknowledgeOneTimePasswordRotation",
            "Apply requires both explicit acknowledgements", 'no_host_changes = (-not [bool]$Apply)',
        ):
            self.assertIn(token, source)
        self.assertLess(source.index("if (-not $Apply) { return }"), source.index("Set-LocalUser -Name $service.Name -Password $temporaryPassword"))

    def test_one_shot_uses_password_limited_and_rotates_finally(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "New-CryptographicAccountPassword", "RandomNumberGenerator", "New-Object byte[] 48",
            "SecureStringToBSTR", "ZeroFreeBSTR", "TASK_LOGON_PASSWORD", "TASK_RUNLEVEL_LUA",
            'Principal.LogonType -ne "Password"', 'Principal.RunLevel -ne "Limited"',
            "Unregister-ScheduledTask", "stored_task_credential_invalidated=$true",
        ):
            self.assertIn(token, source)
        final_rotate = source.index("Set-LocalUser -Name $service.Name -Password $finalPassword")
        unregister = source.index("Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop", final_rotate)
        self.assertLess(final_rotate, unregister)
        self.assertNotIn("Read-Host", source)
        self.assertNotIn("Export-Clixml", source)
        self.assertIn("WSL may contain reconciliable partial prerequisite state", source)
        self.assertIn("Save-FailureDiagnostics", source)
        self.assertIn("diagnostics\\jit-prerequisites", source)
        self.assertNotIn('Copy-Item -LiteralPath $WorkerPath', source)

    def test_payload_pins_prerequisites_and_remains_inert(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            "Ubuntu-24.04-CI", "@@INCUS_VERSION@@", 'garm_version=\'0.2.1\'',
            "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746",
            '"incus=${incus_version}"', "apt-mark hold incus", "sha256sum --check --status",
            "useradd --system", "garm-manager", "passwd --lock garm-manager",
            "/usr/local/bin/garm --version",
            "pgrep -x garm", "an enabled GARM-related unit remains",
            "systemctl disable --now garm.service self-hosted-ci-garm.service",
            'runner_registration_performed":false',
        ):
            self.assertIn(token, source)
        for forbidden in ("config.sh", "--url", "--token", "runner register"):
            self.assertNotIn(forbidden, source)

    def test_worker_is_exact_service_identity_and_bounded(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "worker service SID mismatch", "wsl.exe", "systemd-run --quiet --wait --pipe --collect",
            "RedirectStandardInput", "ReadToEndAsync()", "WaitForExit($TimeoutSeconds * 1000)",
            "$process.Kill()", "Stop-WslInstallUnit", "systemctl kill --kill-whom=all",
            "RuntimeMaxSec=600", "TimeoutStopSec=15", "KillMode=control-group",
            "--setenv=WSL_DISTRO_NAME=$DistroName",
            "WSL install unit termination state is unobservable", "cgroup.procs",
            "JIT prerequisite postcondition failed", "base64.b64decode(encoded, validate=True)",
            "payload sha256 mismatch", '["/bin/bash", "-n", path]',
        ):
            self.assertIn(token, source)

    def test_versions_and_deadlines_are_policy_pinned(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('$ExpectedIncusVersion = "6.0.0-1ubuntu0.3"', source)
        self.assertIn('if ($IncusVersion -ne $ExpectedIncusVersion)', source)
        self.assertIn('if ($TimeoutSeconds -ne 600)', source)
        self.assertIn('$failed = [string]$task.State -ne "Running"', source)

    def test_payload_is_valid_bash(self) -> None:
        result = subprocess.run(["bash", "-n", str(PAYLOAD)], text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_installer_parses_in_powershell(self) -> None:
        command = (
            "$errors=$null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{INSTALLER}',[ref]$null,[ref]$errors); "
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
        )
        result = subprocess.run(["pwsh", "-NoProfile", "-Command", command], text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
