from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-jit-prerequisites.ps1"
PAYLOAD = ROOT / "scripts/host/install-jit-prerequisites-wsl-payload.sh.in"
GARM_CONFIG = ROOT / "templates/garm/config.toml.example"


class JitPrerequisiteInstallerTests(unittest.TestCase):
    def test_plan_only_and_apply_are_explicit(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[switch]$Apply",
            "if (-not $Apply) { return }",
            "AcknowledgeHostPackageInstallation",
            "AcknowledgeOneTimePasswordRotation",
            "Apply requires both explicit acknowledgements",
            "no_host_changes = (-not [bool]$Apply)",
        ):
            self.assertIn(token, source)
        self.assertLess(
            source.index("if (-not $Apply) { return }"),
            source.index(
                "Set-LocalUser -Name $service.Name -Password $temporaryPassword"
            ),
        )

    def test_one_shot_uses_password_limited_and_rotates_finally(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "New-CryptographicAccountPassword",
            "RandomNumberGenerator",
            "New-Object byte[] 48",
            "SecureStringToBSTR",
            "ZeroFreeBSTR",
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA",
            'Principal.LogonType -ne "Password"',
            'Principal.RunLevel -ne "Limited"',
            "Unregister-ScheduledTask",
            "stored_task_credential_invalidated=$true",
        ):
            self.assertIn(token, source)
        final_rotate = source.index(
            "Set-LocalUser -Name $service.Name -Password $finalPassword"
        )
        unregister = source.index(
            "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop",
            final_rotate,
        )
        self.assertLess(final_rotate, unregister)
        self.assertNotIn("Read-Host", source)
        self.assertNotIn("Export-Clixml", source)
        self.assertIn(
            "WSL may contain reconciliable partial prerequisite state", source
        )
        self.assertIn("Save-FailureDiagnostics", source)
        self.assertIn("diagnostics\\jit-prerequisites", source)
        self.assertNotIn("Copy-Item -LiteralPath $WorkerPath", source)

    def test_payload_pins_prerequisites_and_remains_inert(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            "Ubuntu-24.04-CI",
            "@@INCUS_VERSION@@",
            "garm_version='0.2.1'",
            "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746",
            "garm_cli_version='0.2.1'",
            "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e",
            "a973c9061cf7962b4f90c8220ed6f6cc8abeeed20780ea8b9e31ce6dfc99bd9b",
            "garm-cli-linux-amd64.tgz",
            'tar -tzf "${tx}/garm-cli.tgz"',
            'printf \'%s  %s\\n\' "${garm_cli_binary_sha256}" /usr/local/bin/garm-cli',
            "/usr/local/bin/garm-cli --help",
            "root:root:755",
            "garm_provider_incus_version='0.1.5'",
            "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f",
            "garm-provider-incus-linux-amd64.tgz",
            'tar -tzf "${tx}/garm-provider-incus.tgz"',
            "/usr/local/libexec/garm/garm-provider-incus",
            '"incus=${incus_version}"',
            "cowsql_version='1.15.8-1'",
            "650da8a131d05d89d893e8e168f1be43913d9cdbd631a08dda2fc313a1d1939f",
            "libcowsql0_1.15.8-1_amd64.deb",
            'dpkg -i "${tx}/libcowsql0.deb"',
            "apt-mark hold incus libcowsql0",
            '"cowsql_held":true',
            "dnsmasq-base",
            "for package in e2fsprogs util-linux dnsmasq-base nftables squid",
            "apt-get remove -y dnsmasq",
            "for command in dnsmasq nft squid mkfs.ext4",
            "dnsmasq --version",
            "dnsmasq.service",
            "e2fsprogs",
            "util-linux",
            "mkfs.ext4 losetup tune2fs findmnt mountpoint truncate systemd-escape blockdev blkid",
            "grep -qw ext4 /proc/filesystems",
            "loop devices",
            "apt-mark hold incus",
            "sha256sum --check --status",
            "nftables",
            "squid",
            "make_service_inert squid.service false",
            "make_service_inert nftables.service false",
            '"dnsmasq_base_installed":true',
            '"dnsmasq_service_absent":true',
            '"nftables_installed":true',
            '"squid_installed":true',
            '"distribution_network_services_disabled":true',
            '"ext4_tools_installed":true',
            '"ext4_kernel_supported":true',
            '"loop_devices_supported":true',
            "useradd --system",
            "garm-manager",
            "passwd --lock garm-manager",
            "gpasswd --delete garm-manager incus-admin",
            "garm-manager retains forbidden incus-admin membership",
            '"garm_manager_incus_admin":false',
            "/usr/local/bin/garm --version",
            "pgrep -x garm",
            "an enabled GARM-related unit remains",
            "make_service_inert garm.service true",
            "make_service_inert self-hosted-ci-garm.service true",
            'runner_registration_performed":false',
        ):
            self.assertIn(token, source)
        for forbidden in ("config.sh", "--url", "--token", "runner register"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("/usr/local/bin/garm-cli version", source)

    def test_payload_failures_are_phase_diagnostic_and_service_checks_fail_closed(
        self,
    ) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            "set -Eeuo pipefail",
            "export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'",
            "trap 'report_error \"$?\" \"$LINENO\" \"$BASH_COMMAND\"' ERR",
            "phase='apt-installation'",
            "phase='package-postconditions'",
            "phase='garm-binary-installation'",
            "phase='garm-identity'",
            "phase='final-inertness'",
            "JIT prerequisite payload failed: phase=%s line=%s exit=%s command=%s",
            "JIT prerequisite postcondition failed: phase=%s detail=%s",
            "safe_command",
            "require_installed_package",
            "require_command",
            "require_service_absent dnsmasq.service",
            "make_service_inert squid.service false",
            "make_service_inert nftables.service false",
            "cannot establish enabled state for ${unit}",
            "${unit} has unsafe active state ${active_state}",
            "${unit} has unsafe enabled state ${enabled_state}",
        ):
            self.assertIn(token, source)
        self.assertNotIn("! systemctl", source)
        self.assertNotIn("systemctl disable --now", source)
        self.assertNotRegex(source, r"systemctl[^\n]+\|\| true")

    def test_garm_021_config_template_uses_current_schema_and_placeholders(
        self,
    ) -> None:
        source = GARM_CONFIG.read_text(encoding="utf-8")
        parsed = tomllib.loads(source)
        for token in (
            "[default]",
            "enable_webhook_management = false",
            "[logging]",
            "[metrics]",
            "[apiserver]",
            'bind = "127.0.0.1"',
            "[apiserver.webui]",
            "[database]",
            'backend = "sqlite3"',
            "[database.sqlite3]",
            'db_file = "/var/lib/self-hosted-ci/garm/garm.db"',
            "[[provider]]",
            'provider_type = "external"',
            "[provider.external]",
            'provider_executable = "/usr/local/libexec/garm/garm-provider-incus"',
            'config_file = "/etc/self-hosted-ci/garm/garm-provider-incus.toml"',
            'time_to_live = "24h"',
        ):
            self.assertIn(token, source)
        self.assertNotIn("[controller]", source)
        self.assertNotIn('time_to_live = "5m"', source)
        self.assertEqual(2, source.count('"REPLACE_ME_WITH_32_CHARS________"'))
        self.assertEqual(32, len("REPLACE_ME_WITH_32_CHARS________"))
        self.assertEqual("sqlite3", parsed["database"]["backend"])
        self.assertEqual(
            "/var/lib/self-hosted-ci/garm/garm.db",
            parsed["database"]["sqlite3"]["db_file"],
        )
        self.assertEqual("external", parsed["provider"][0]["provider_type"])

    def test_worker_is_exact_service_identity_and_bounded(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "worker service SID mismatch",
            "wsl.exe",
            "systemd-run --quiet --wait --pipe --collect",
            "RedirectStandardInput",
            "ReadToEndAsync()",
            "WaitForExit($TimeoutSeconds * 1000)",
            "$process.Kill()",
            "Stop-WslInstallUnit",
            "systemctl kill --kill-whom=all",
            "RuntimeMaxSec=600",
            "TimeoutStopSec=15",
            "KillMode=control-group",
            "--setenv=WSL_DISTRO_NAME=$DistroName",
            "WSL install unit termination state is unobservable",
            "cgroup.procs",
            "JIT prerequisite postcondition failed",
            "base64.b64decode(encoded, validate=True)",
            "payload sha256 mismatch",
            '["/bin/bash", "-n", path]',
        ):
            self.assertIn(token, source)
        for postcondition in (
            "$result.dnsmasq_base_installed -ne $true",
            "$result.dnsmasq_service_absent -ne $true",
            "$result.nftables_installed -ne $true",
            "$result.squid_installed -ne $true",
            "$result.distribution_network_services_disabled -ne $true",
            "$result.garm_enabled -ne $false",
            "$result.runner_registration_performed -ne $false",
        ):
            self.assertIn(postcondition, source)

    def test_versions_and_deadlines_are_policy_pinned(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('$ExpectedIncusVersion = "6.0.0-1ubuntu0.3"', source)
        self.assertIn('$ExpectedCowsqlVersion = "1.15.8-1"', source)
        self.assertIn('$result.cowsql_held -ne $true', source)
        self.assertIn(
            '$ExpectedGarmCliSha256 = "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e"',
            source,
        )
        self.assertIn(
            '$ExpectedGarmProviderIncusSha256 = "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f"',
            source,
        )
        self.assertIn("$result.garm_manager_incus_admin -ne $false", source)
        self.assertIn("if ($IncusVersion -ne $ExpectedIncusVersion)", source)
        self.assertIn("if ($TimeoutSeconds -ne 600)", source)
        self.assertIn('$failed = [string]$task.State -ne "Running"', source)

    def test_payload_is_valid_bash(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(PAYLOAD)], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_installer_parses_in_powershell(self) -> None:
        command = (
            "$errors=$null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{INSTALLER}',[ref]$null,[ref]$errors); "
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
        )
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", command], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
