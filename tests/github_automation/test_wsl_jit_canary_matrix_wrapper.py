from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/run-wsl-jit-canary-matrix.ps1"


class CanaryMatrixWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_exact_service_identity_limited_password_task_and_rotations(self):
        self.assertIn('ServiceAccount = "selfhosted-ci-svc"', self.source)
        self.assertIn('DistroName = "Ubuntu-24.04-CI"', self.source)
        self.assertIn("Assert-NonAdmin $service", self.source)
        self.assertIn("LogonType = 1", self.source)
        self.assertIn("RunLevel = 0", self.source)
        self.assertGreaterEqual(self.source.count("New-CryptographicAccountPassword"), 3)
        self.assertIn("New-ProtectedAcl", self.source)

    def test_bundle_crosses_only_stdin_and_never_drvfs(self):
        self.assertIn("RedirectStandardInput = `$true", self.source)
        self.assertIn("CopyTo(`$process.StandardInput.BaseStream)", self.source)
        self.assertIn('transport="Windows-to-WSL-stdin-no-drvfs"', self.source)
        self.assertNotIn("/mnt/c/", self.source.lower())

    def test_canary_executes_the_installed_runtime_from_receipt_targets(self):
        self.assertIn("export PYTHONPATH=/usr/local/lib/self-hosted-ci", self.source)
        self.assertIn(
            "/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py",
            self.source,
        )
        self.assertLess(
            self.source.index("export PYTHONPATH=/usr/local/lib/self-hosted-ci"),
            self.source.index(
                "/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py \"${args[@]}\""
            ),
        )
        self.assertNotIn("/opt/self-hosted-ci/source", self.source)

    def test_pre_live_canary_uses_the_bootstrap_reviewer_key(self):
        self.assertIn(
            "--reviewer-public-key /etc/self-hosted-ci/bootstrap/reviewer-public-key.pem",
            self.source,
        )
        worker = self.source.split("function Write-Worker", 1)[1].split(
            "function Wait-OneShot", 1
        )[0]
        self.assertNotIn("boundary-reviewer-public-key.pem", worker)
        self.assertIn(
            "install -d -o root -g garm-manager -m 0751 /etc/self-hosted-ci",
            worker,
        )

    def test_garm_config_access_is_reconciled_exactly_before_canary_execution(self):
        worker = self.source.split("function Write-Worker", 1)[1].split(
            "function Wait-OneShot", 1
        )[0]
        for contract in (
            "[[ -d /etc/self-hosted-ci && ! -L /etc/self-hosted-ci ]]",
            "[[ -d /etc/self-hosted-ci/garm && ! -L /etc/self-hosted-ci/garm ]]",
            "install -d -o root -g garm-manager -m 0751 /etc/self-hosted-ci",
            "install -d -o root -g garm-manager -m 0750 /etc/self-hosted-ci/garm",
            '[[ "$(stat -c \'%U:%G:%a\' /etc/self-hosted-ci)" == root:garm-manager:751 ]]',
            '[[ "$(stat -c \'%U:%G:%a\' /etc/self-hosted-ci/garm)" == root:garm-manager:750 ]]',
            '[[ "$(stat -c \'%U:%G:%a\' /etc/self-hosted-ci/garm/config.toml)" == root:garm-manager:640 ]]',
            "runuser -u garm-manager -- test -r /etc/self-hosted-ci/garm/config.toml",
            "[[ -d /var/lib/self-hosted-ci && ! -L /var/lib/self-hosted-ci ]]",
            "[[ -d /var/lib/self-hosted-ci/garm && ! -L /var/lib/self-hosted-ci/garm ]]",
            "install -d -o root -g garm-manager -m 0710 /var/lib/self-hosted-ci",
            "install -d -o garm-manager -g garm-manager -m 0700 /var/lib/self-hosted-ci/garm",
            '[[ "$(stat -c \'%U:%G:%a\' /var/lib/self-hosted-ci)" == root:garm-manager:710 ]]',
            '[[ "$(stat -c \'%U:%G:%a\' /var/lib/self-hosted-ci/garm)" == garm-manager:garm-manager:700 ]]',
            "runuser -u garm-manager -- test -x /var/lib/self-hosted-ci",
            "runuser -u garm-manager -- test -r /var/lib/self-hosted-ci/garm",
            "runuser -u garm-manager -- test -w /var/lib/self-hosted-ci/garm",
            "runuser -u garm-manager -- test -x /var/lib/self-hosted-ci/garm",
        ):
            self.assertIn(contract, worker)
        effective_read = worker.index(
            "runuser -u garm-manager -- test -x /var/lib/self-hosted-ci/garm"
        )
        execute = worker.index(
            "args=(execute --config /etc/self-hosted-ci/canary-runtime.json"
        )
        self.assertLess(effective_read, execute)
        self.assertNotIn("chmod 0755 /etc/self-hosted-ci/garm", worker)
        self.assertNotIn("chmod 0644 /etc/self-hosted-ci/garm/config.toml", worker)
        self.assertNotIn("chmod 0755 /var/lib/self-hosted-ci", worker)
        self.assertNotIn("chmod 0777 /var/lib/self-hosted-ci/garm", worker)

    def test_reboot_requires_checkpoint_then_resumes_same_nonce_and_bundle(self):
        checkpoint = self.source.index('status -ne "reboot-checkpoint"')
        terminate = self.source.index("--terminate $DistroName", checkpoint)
        resume = self.source.index('Write-Worker "resume"')
        self.assertLess(checkpoint, terminate)
        self.assertLess(terminate, resume)
        self.assertIn("args=(execute --config /etc/self-hosted-ci/canary-runtime.json", self.source)
        self.assertIn("$ExpectedCanaryNonce", self.source)

    def test_exact_six_scenarios_and_production_fence(self):
        terminal = re.search(r'scenarios=@\((?P<items>[^)]*)\)', self.source)
        self.assertIsNotNone(terminal)
        for scenario in ("success", "failure", "cancel", "timeout", "force-cancel", "reboot"):
            self.assertIn(f'"{scenario}"', terminal.group("items"))
        self.assertIn("production-fence", self.source)
        self.assertIn("runtime_empty=$true", self.source)
        self.assertIn("outbound_worker_started=$false", self.source)

    def test_success_is_emitted_only_after_fail_closed_cleanup_postconditions(self):
        finally_block = self.source.index("finally {")
        final_success = self.source.rindex("$successReceipt | ConvertTo-Json -Compress")
        self.assertLess(finally_block, final_success)
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop", self.source)
        self.assertIn('throw "scheduled task remains registered"', self.source)
        self.assertIn('throw "staging root remains present"', self.source)
        self.assertIn("JIT canary cleanup postconditions failed", self.source)
        self.assertIn("staging_absent=$true", self.source)

    def test_credential_cleanup_is_verified_and_diagnostics_are_sanitized(self):
        final_rotation = self.source.index("$rotatedService = Get-LocalUser")
        final_success = self.source.rindex("$successReceipt | ConvertTo-Json -Compress")
        self.assertLess(final_rotation, final_success)
        self.assertIn("Assert-NonAdmin $rotatedService", self.source)
        self.assertIn("$passwordApplied = $false", self.source)
        self.assertIn("Write-SanitizedDiagnosticCopy", self.source)
        self.assertIn("[REDACTED_PRIVATE_KEY]", self.source)
        self.assertIn("[REDACTED]", self.source)
        self.assertNotIn("Copy-Item -LiteralPath $entry.p", self.source)

    def test_finally_does_not_silence_destructive_cleanup_errors(self):
        final = self.source.rsplit("finally {", 1)[1]
        self.assertNotIn("Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue", final)
        self.assertNotIn("Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue", final)

    def test_running_task_is_stopped_and_observed_before_unregister(self):
        stop = self.source.index("function Stop-And-Wait-OneShot")
        unregister = self.source.rindex("Unregister-ScheduledTask -TaskName $TaskName")
        self.assertLess(stop, unregister)
        self.assertIn("Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop", self.source)
        self.assertIn("AddSeconds(30)", self.source)
        self.assertIn("scheduled task remained running after stop and exact WSL termination", self.source)
        self.assertIn('& "$env:SystemRoot\\System32\\wsl.exe" --terminate $DistroName', self.source)

    def test_cleanup_worker_proves_zero_runtime_and_active_quarantine(self):
        self.assertIn("function Write-CleanupWorker", self.source)
        self.assertIn("driver.recover_all()", self.source)
        self.assertIn("driver.prove_runtime_empty()", self.source)
        self.assertIn('"network_quarantine":"active"', self.source)
        self.assertIn('status -ne "cleanup-quarantined"', self.source)
        self.assertIn("rm -f -- /run/self-hosted-ci-canary-cleanup.py /run/self-hosted-ci-canary-worker.sh", self.source)
        cleanup = self.source.index("Write-CleanupWorker")
        unregister = self.source.rindex("Unregister-ScheduledTask -TaskName $TaskName")
        self.assertLess(cleanup, unregister)

    def test_task_wait_requires_observing_the_new_run(self):
        self.assertIn("$before = Get-ScheduledTaskInfo", self.source)
        self.assertIn("$runObserved = $false", self.source)
        self.assertIn("$info.LastRunTime -gt $before.LastRunTime", self.source)
        self.assertIn('$runObserved -and $task.State -ne "Running"', self.source)


if __name__ == "__main__":
    unittest.main()
