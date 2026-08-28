from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROVISION = ROOT / "scripts/host/provision-wsl-jit-contract.sh"


class InertBootstrapProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PROVISION.read_text(encoding="utf-8")

    def test_shell_parses_and_bootstrap_is_cryptographically_verified_first(self):
        subprocess.run(["bash", "-n", str(PROVISION)], check=True)
        verify = self.source.index('verify-wsl-jit-bootstrap.py')
        first_install = self.source.index('install -d -o root')
        self.assertLess(verify, first_install)
        for token in (
            '--bootstrap-evidence',
            '--windows-observation',
            '--wsl-observation',
            '--pinned-fingerprint',
            '--public-manifest',
            '--expected-bootstrap-nonce',
            '--expected-nonce "${expected_bootstrap_nonce}"',
            'bootstrap boundary does not authorize inert provisioning',
        ):
            self.assertIn(token, self.source)

    def test_bootstrap_and_final_contracts_are_mutually_exclusive(self):
        self.assertIn(
            'bootstrap apply requires exact readable bootstrap, observation, public manifest files, and a 128-bit lowercase-hex challenge, without runner evidence',
            self.source,
        )
        self.assertIn(
            'final apply requires only a readable --evidence bundle', self.source
        )
        self.assertIn('contract_mode="bootstrap-inert"', self.source)
        self.assertIn('contract_mode="runner-final"', self.source)

    def test_bootstrap_installs_inert_bytes_without_activation_or_registration(self):
        for token in (
            'bootstrap requires activation approval to be absent',
            'bootstrap requires runtime-ready state to be absent',
            'make_service_inert "${inert_service}"',
            'make_service_inert "${SERVICE_NAME}"',
            'for inert_service in garm.service',
            'could not stop ${service}',
            'could not observe load state for ${service}',
            'empty load state for ${service}',
            'could not observe enablement state for ${service}',
            '${service} remains active',
            '${service} remains enabled',
            'rm -f "${TARGET_ROOT}/ACTIVATION_APPROVED"',
        ):
            self.assertIn(token, self.source)
        bootstrap_branch = self.source.split(
            'if [[ "${contract_mode}" == "runner-final" ]]; then'
        )[-1]
        self.assertNotIn('ACTIVATION_APPROVED" >', bootstrap_branch)
        self.assertNotIn('outbound-worker.runtime-ready" >', bootstrap_branch)
        self.assertNotIn('garm-cli runner', self.source)
        first_stop = self.source.index('make_service_inert "${inert_service}"')
        first_install = self.source.index('install -d -o root')
        self.assertLess(first_stop, first_install)
        self.assertNotIn('systemctl disable --now "${inert_service}" >/dev/null 2>&1 || true', self.source)
        self.assertNotIn('systemctl show --property=LoadState --value "${service}" 2>/dev/null || true', self.source)

    def test_quarantine_is_enabled_now_and_ordered_before_incus(self):
        enabled = "systemctl enable --now self-hosted-ci-network-quarantine.service"
        self.assertIn(enabled, self.source)
        self.assertIn("network quarantine is not reboot-persistent", self.source)
        self.assertIn("network quarantine did not become active", self.source)
        self.assertLess(
            self.source.index(enabled),
            self.source.index('install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-boundary-verify.service"'),
        )
        unit = (ROOT / "packaging/systemd/self-hosted-ci-network-quarantine.service").read_text(encoding="utf-8")
        self.assertIn("DefaultDependencies=no", unit)
        self.assertIn("Before=incus.service self-hosted-ci-canary-network-policy.service", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        production = (ROOT / "packaging/systemd/self-hosted-ci-network-policy.service").read_text(encoding="utf-8")
        self.assertIn("Requires=self-hosted-ci-network-quarantine.service", production)
        self.assertIn("After=self-hosted-ci-network-quarantine.service", production)
        self.assertIn("ExecStartPre=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh quarantine", production)
        self.assertIn("ExecStart=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh apply", production)
        self.assertIn("ExecStartPost=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh verify", production)


if __name__ == "__main__":
    unittest.main()
