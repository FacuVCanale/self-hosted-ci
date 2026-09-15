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
    def test_health_supervisor_has_boot_and_indefinite_five_minute_watchdog(self):
        source = (ROOT / "scripts/host/install-health-supervisor.ps1").read_text()
        self.assertEqual(1, source.count("$definition.Triggers.Create(8)"))
        self.assertEqual(1, source.count("$definition.Triggers.Create(2)"))
        for token in (
            '$watchdog.DaysInterval = 1',
            '$watchdog.Repetition.Interval = "PT5M"',
            '$watchdog.Repetition.StopAtDurationEnd = $false',
            '$definition.Settings.MultipleInstances = 2 # IgnoreNew',
            '$definition.Settings.RestartCount = 5',
            '$definition.Settings.RestartInterval = "PT1M"',
            '@($observed.Triggers).Count -ne 2',
            'MSFT_TaskBootTrigger', 'MSFT_TaskDailyTrigger',
            'task watchdog postcondition failed',
        ):
            self.assertIn(token, source)
        self.assertNotIn('$watchdog.Repetition.Duration =', source)
        self.assertNotIn('$watchdog.EndBoundary =', source)

    def test_watchdog_start_boundary_is_future_and_checked_before_manual_start(self):
        source = (ROOT / "scripts/host/install-health-supervisor.ps1").read_text()
        self.assertIn(
            '$watchdog.StartBoundary = [DateTime]::Now.AddMinutes(10).ToString("yyyy-MM-ddTHH:mm:ss")',
            source,
        )
        self.assertNotIn('[DateTime]::Today', source)
        captured = source.index('$taskRegistrationStartedAt = [DateTime]::Now')
        registration = source.index('$task = Register-PasswordSupervisorTask')
        verified = source.index('task watchdog future StartBoundary postcondition failed')
        started = source.index('Start-ScheduledTask -TaskName $TaskName')
        self.assertLess(captured, registration)
        self.assertLess(registration, verified)
        self.assertLess(verified, started)
        self.assertIn('[DateTime]::Parse([string]$watchdog.StartBoundary', source)
        self.assertIn('$watchdogStart -lt $taskRegistrationStartedAt.AddMinutes(9)', source)
        self.assertIn('$watchdogStart -gt $taskRegistrationStartedAt.AddMinutes(11)', source)

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


class SupervisorCredentialGuardTests(unittest.TestCase):
    GUARD = "Assert-SupervisorCredentialRotationAllowed"
    ROTATION = re.compile(r"\bSet-LocalUser\b[^\n;{}]*\s-Password\b")

    def rotators(self):
        scripts = {
            path: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "scripts/host").rglob("*.ps1"))
        }
        scripts = {path: source for path, source in scripts.items() if self.ROTATION.search(source)}
        # Keep discovery non-vacuous and catch removal of protection from any
        # newly added password rotator without maintaining a fixed allowlist.
        self.assertGreaterEqual(len(scripts), 12)
        return scripts

    def guard_source(self, source):
        match = re.search(r"^function " + self.GUARD + r" \{\n.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(match, "password rotator has no credential guard")
        return match.group()

    def test_every_rotator_declares_the_explicit_switch_and_same_fail_closed_guard(self):
        canonical = None
        for path, source in self.rotators().items():
            with self.subTest(script=path.name):
                header = source[:source.index("$ErrorActionPreference")]
                self.assertIn("[switch]$AcknowledgeSupervisorCredentialInvalidation", header)
                guard = self.guard_source(source)
                if canonical is None:
                    canonical = guard
                self.assertEqual(canonical, guard)
                self.assertIn("if ($AcknowledgeSupervisorCredentialInvalidation) { return }", guard)
                self.assertIn("Get-ScheduledTask -ErrorAction Stop", guard)
                self.assertIn('$_.TaskName -eq "SelfHostedCI-Health-Supervisor"', guard)
                self.assertIn("if ($supervisors.Count -gt 0)", guard)
                self.assertIn("health supervisor task exists; its stored credential would be invalidated", guard)
                self.assertIn("run uninstall-health-supervisor.ps1 first and reinstall it last", guard)
                self.assertNotIn("SilentlyContinue", guard)
                self.assertNotIn("catch", guard)

    def test_every_password_rotation_checks_guard_including_cleanup_and_rollback(self):
        for path, source in self.rotators().items():
            for rotation in self.ROTATION.finditer(source):
                line = source.count("\n", 0, rotation.start()) + 1
                with self.subTest(script=path.name, line=line):
                    self.assertTrue(
                        source[:rotation.start()].rstrip().endswith(self.GUARD + ";"),
                        f"{path.name}:{line}: password rotation lacks its immediate credential guard",
                    )

    def test_preflight_blocks_before_one_shot_staging_but_uninstaller_removes_task_first(self):
        for path, source in self.rotators().items():
            with self.subTest(script=path.name):
                body = source[source.index("if (-not $Apply)"):]
                if path.name == "uninstall-health-supervisor.ps1":
                    self.assertLess(body.index("Unregister-ScheduledTask"), body.index(self.GUARD))
                else:
                    preflight = re.search(r"^" + self.GUARD + r"$", body, re.M)
                    self.assertIsNotNone(preflight, "missing guard before staging")
                    mutations = re.search(r"\b(New-Item|Set-Acl|Grant-ExactBatchLogonRight|Set-LocalUser|WriteAllText|WriteAllBytes)\b", body)
                    self.assertIsNotNone(mutations)
                    self.assertLess(preflight.start(), mutations.start())

    def test_guard_runtime_when_powershell_available(self):
        import shutil
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is not installed; all rotators have textual coverage")
        source = next(iter(self.rotators().values()))
        harness = self.guard_source(source) + r"""
$ErrorActionPreference = 'Stop'
$script:AcknowledgeSupervisorCredentialInvalidation = $false
$script:scenario = 'absent'
$script:queries = 0
function Get-ScheduledTask {
    [CmdletBinding()] param()
    $script:queries++
    if ($script:scenario -eq 'error') { Write-Error 'scheduler unavailable'; return }
    if ($script:scenario -eq 'present') { return [pscustomobject]@{TaskName='SelfHostedCI-Health-Supervisor'} }
    return [pscustomobject]@{TaskName='UnrelatedTask'}
}
Assert-SupervisorCredentialRotationAllowed
$script:scenario = 'present'
$blocked = $false
try { Assert-SupervisorCredentialRotationAllowed } catch {
    if ($_.Exception.Message -notlike '*health supervisor task exists; its stored credential would be invalidated*') { throw }
    $blocked = $true
}
if (-not $blocked) { throw 'existing supervisor was not blocked' }
$script:scenario = 'error'
$blocked = $false
try { Assert-SupervisorCredentialRotationAllowed } catch { $blocked = $true }
if (-not $blocked) { throw 'unknown scheduler state was not blocked' }
$script:AcknowledgeSupervisorCredentialInvalidation = $true
$script:scenario = 'present'
$before = $script:queries
Assert-SupervisorCredentialRotationAllowed
if ($script:queries -ne $before) { throw 'explicit acknowledgement did not bypass guard' }
"""
        result = subprocess.run([powershell, "-NoProfile", "-Command", harness], text=True, capture_output=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
