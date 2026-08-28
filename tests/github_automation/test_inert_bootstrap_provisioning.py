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


if __name__ == "__main__":
    unittest.main()
