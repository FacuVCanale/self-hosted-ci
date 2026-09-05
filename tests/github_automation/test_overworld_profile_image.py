from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "images/overworld-pr-v1"
BUILDER = ROOT / "scripts/host/build-repository-profile-image.sh"
PROVISION_CONTRACT = ROOT / "scripts/host/provision-wsl-jit-contract.sh"
STAGER = ROOT / "scripts/host/stage-wsl-jit-live-contract.py"
LIVE_VERIFIER = ROOT / "scripts/host/verify-live-artifact-contract.py"


class OverworldProfileImageTests(unittest.TestCase):
    def test_manifest_has_exact_profile_and_immutable_artifact_sources(self) -> None:
        manifest = json.loads((PROFILE / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual("overworld-pr-v1", manifest["profile"])
        self.assertEqual("alethia-earth/Overworld", manifest["repository"])
        self.assertEqual(
            {"bun", "uv", "pyright", "playwright", "playwright_core", "chromium", "chromium_headless_shell", "minio", "mc"},
            set(manifest["artifacts"]),
        )
        self.assertEqual("1.4.0", manifest["artifacts"]["bun"]["version"])
        self.assertEqual("1.1.408", manifest["artifacts"]["pyright"]["version"])
        self.assertEqual("1.59.1", manifest["artifacts"]["playwright"]["version"])
        self.assertEqual("1217", manifest["artifacts"]["chromium"]["revision"])
        self.assertEqual("1217", manifest["artifacts"]["chromium_headless_shell"]["revision"])
        for artifact in manifest["artifacts"].values():
            self.assertTrue(artifact["url"].startswith("https://"))
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            {
                "key_url": "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
                "key_fingerprint": "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
                "repository": "https://apt-archive.postgresql.org/pub/repos/apt",
                "suite": "noble-pgdg-archive",
            },
            manifest["pgdg"],
        )
        for package in (
            "postgresql-16=16.15-1.pgdg24.04+2",
            "postgresql-16-postgis-3=3.4.3+dfsg-2.pgdg24.04+1",
            "postgresql-17=17.11-1.pgdg24.04+2",
            "postgresql-17-postgis-3=3.5.3+dfsg-2.pgdg24.04+1",
        ):
            self.assertIn(package, manifest["apt_packages"])

    def test_plan_is_inert_and_machine_readable(self) -> None:
        result = subprocess.run(
            ["bash", str(BUILDER), "--plan"], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value["host_changes"])
        self.assertFalse(value["builder_privileged"])
        self.assertFalse(value["builder_nesting"])
        self.assertFalse(value["alias_reuse"])
        self.assertTrue(value["runtime_must_be_empty"])

    def test_builder_is_transactional_fenced_and_never_moves_an_alias(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        required = (
            "acquire_transaction_lock",
            "zero_runtime_state",
            "self-hosted-ci-outbound-worker.service",
            "self-hosted-ci-allocation-broker.service",
            "self-hosted-ci-garm.service",
            'squid -N -f "${profile_dir}/squid-build.conf"',
            'systemctl stop "${BUILD_PROXY_UNIT}"',
            'security.privileged=false security.nesting=false security.idmap.isolated=true',
            'set(d)!={"eth0","root"}',
            'd["eth0"].get("network")!="ci-jit-isolated"',
            'incus publish "${builder}"',
            'incus image alias delete "${candidate_alias}"',
            'incus image delete "${published_fingerprint}"',
            '--overworld-bundle',
            '--expected-overworld-commit',
            '--waterfall-bundle',
            '--expected-waterfall-commit',
            'git bundle list-heads "${overworld_bundle}"',
            'git bundle list-heads "${waterfall_bundle}"',
            'incus file push "${overworld_bundle}"',
            'incus file push "${waterfall_bundle}"',
            'credentials_persisted":false',
            'alias_moved":false',
        )
        for token in required:
            self.assertIn(token, source)
        for forbidden in ("--reuse", "--copy-aliases", "security.privileged=true", "security.nesting=true", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("SQUID_CONFIG", source)
        self.assertIn("10.254.0.1:8079", source)
        self.assertIn("RuntimeMaxSec=2h", source)
        self.assertIn("Conflicts=${FENCED_SERVICES[*]}", source)
        self.assertIn("--collect", source)
        self.assertIn("KillMode=control-group", source)
        self.assertIn("systemctl is-active --quiet \"${BUILD_PROXY_UNIT}\" && status=1", source)
        self.assertIn("grep -Eq '(^|:)8079$'", source)

    def test_build_egress_is_exact_and_not_a_general_wildcard(self) -> None:
        policy = (PROFILE / "squid-build.conf").read_text(encoding="utf-8")
        for domain in (
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "apt-archive.postgresql.org",
            "storage.googleapis.com",
            "www.postgresql.org",
            "github.com",
            "release-assets.githubusercontent.com",
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "dl.min.io",
        ):
            self.assertIn(domain, policy)
        self.assertNotIn("dstdomain .githubusercontent.com", policy)
        self.assertNotIn("dstdomain .com", policy)
        self.assertIn("http_access deny all", policy)

    def test_provisioner_emits_marker_inventory_and_rejects_credentials(self) -> None:
        source = (PROFILE / "provision.py").read_text(encoding="utf-8")
        for token in (
            "manifest_sha256",
            '"repository_profile_image_marker_version": 1',
            '"profile_digest": profile_digest',
            '"runner_memory_bytes": profile["runner_memory_bytes"]',
            '"toolchain": profile["toolchain"]',
            '"dependency_snapshots": profile["dependency_snapshots"]',
            "dpkg-query",
            "PLAYWRIGHT_BROWSERS_PATH",
            '"bun", "install", "--frozen-lockfile"',
            '"uv", "sync", "--frozen"',
            'downloaded["chromium"], Path("/opt/ms-playwright/chromium-1217")',
            'str(pyright_wrapper), str(pyright_target)',
            'sha256_file(lockfile)',
            'run("pg_dropcluster", "--stop", major, "main")',
            'waterfall / ".git"',
            'ROOT / "overworld.bundle"',
            "/root/.npmrc",
            "/root/.netrc",
            "/root/.config/gh/hosts.yml",
        ):
            self.assertIn(token, source)
        manifest = (PROFILE / "manifest.json").read_text(encoding="utf-8")
        self.assertIn("repository-profile-image-v1.json", manifest)
        self.assertNotIn("WATERFALL_CI_TOKEN", source)
        self.assertNotIn("GITHUB_TOKEN", source)
        self.assertNotIn('run("playwright", "install"', source)

    def test_verifier_enforces_exact_profile_marker_and_offline_dependencies(self) -> None:
        source = (PROFILE / "verify.py").read_text(encoding="utf-8")
        for field in (
            "repository_profile_image_marker_version",
            "repository",
            "profile_id",
            "profile_digest",
            "image_marker",
            "runner_memory_bytes",
            "toolchain",
            "dependency_snapshots",
        ):
            self.assertIn(f'"{field}"', source)
        for token in (
            "backend-node_modules",
            "frontend-node_modules",
            "waterfall/.self-hosted-ci-commit",
            "chromium_headless_shell-1217",
            "source-control metadata persisted",
            '("16", "3.4")',
            '("17", "3.5")',
            "default cluster persisted",
            "runner privilege boundary drifted",
            "runner finalizer ownership or mode drifted",
        ):
            self.assertIn(token, source)

    def test_scripts_parse_and_manifest_digest_is_stable(self) -> None:
        expected = hashlib.sha256((PROFILE / "manifest.json").read_bytes()).hexdigest()
        self.assertRegex(expected, r"^[0-9a-f]{64}$")
        shell = subprocess.run(["bash", "-n", str(BUILDER)], text=True, capture_output=True)
        self.assertEqual(0, shell.returncode, shell.stderr)
        python = subprocess.run(
            ["python3", "-m", "py_compile", str(PROFILE / "provision.py"), str(PROFILE / "verify.py")],
            text=True,
            capture_output=True,
        )
        self.assertEqual(0, python.returncode, python.stderr)

    def test_builder_and_profile_are_installed_under_signed_live_contract(self) -> None:
        provision = PROVISION_CONTRACT.read_text(encoding="utf-8")
        stager = STAGER.read_text(encoding="utf-8")
        verifier = LIVE_VERIFIER.read_text(encoding="utf-8")
        self.assertIn("build-repository-profile-image.sh", provision)
        for target in (
            "/usr/local/lib/self-hosted-ci/build-repository-profile-image.sh",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/manifest.json",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/squid-build.conf",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/provision.py",
            "/usr/local/share/self-hosted-ci/images/overworld-pr-v1/verify.py",
            "/usr/local/share/self-hosted-ci/repository-profiles/overworld/profile.json",
        ):
            self.assertIn(target, stager)
            self.assertIn(target, verifier)


if __name__ == "__main__":
    unittest.main()
