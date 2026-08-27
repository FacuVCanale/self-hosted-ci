from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/host/install-incus-boundary.ps1"
PAYLOAD = ROOT / "scripts/host/install-incus-boundary-wsl-payload.sh.in"


class IncusBoundaryInstallerTests(unittest.TestCase):
    def test_installer_is_plan_only_and_apply_requires_exact_acknowledgements(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[switch]$Apply", "if (-not $Apply) { return }",
            "AcknowledgeIncusBoundaryMutation", "AcknowledgeOneTimePasswordRotation",
            "Apply requires both explicit acknowledgements", 'no_host_changes = (-not [bool]$Apply)',
            'ServiceAccount = "selfhosted-ci-svc"', 'DistroName = "Ubuntu-24.04-CI"',
        ):
            self.assertIn(token, source)
        self.assertLess(source.index("if (-not $Apply) { return }"), source.index("Set-LocalUser -Name $service.Name -Password $temporaryPassword"))

    def test_task_is_one_shot_password_limited_and_credentials_are_rotated(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "New-CryptographicAccountPassword", "RandomNumberGenerator", "New-Object byte[] 48",
            "SecureStringToBSTR", "ZeroFreeBSTR", "TASK_LOGON_PASSWORD", "TASK_RUNLEVEL_LUA",
            'Principal.LogonType -ne "Password"', 'Principal.RunLevel -ne "Limited"',
            "one-shot task action postcondition failed", "one-shot task settings postcondition failed",
            "Unregister-ScheduledTask", "stored_task_credential_invalidated=$true",
            "Save-FailureDiagnostics", "worker.stdout.log", "worker.stderr.log", "failure.json",
        ):
            self.assertIn(token, source)
        rotate = source.index("Set-LocalUser -Name $service.Name -Password $finalPassword")
        unregister = source.index("Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop", rotate)
        self.assertLess(rotate, unregister)
        self.assertNotIn("Read-Host", source)
        self.assertNotIn("Export-Clixml", source)

    def test_full_payload_is_verified_in_run_and_bounded_by_systemd(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "sys.stdin.buffer.read()", "base64.b64decode(encoded, validate=True)",
            "hashlib.sha256(raw).hexdigest()", 'dir="/run"', "os.chmod(path, 0o600)",
            'subprocess.run(["/bin/bash", "-n", path], check=True)',
            'subprocess.run(["/bin/bash", path], check=True)',
            "systemd-run --quiet --wait --pipe --collect", "RuntimeMaxSec=300",
            "TimeoutStopSec=15", "KillMode=control-group", "Stop-WslInstallUnit",
            "cgroup still contains processes", "$process.Kill()",
            "WSL transport unavailable while terminating boundary unit",
            "systemctl kill failed with exit code", "systemctl stop failed with exit code",
        ):
            self.assertIn(token, source)

    def test_payload_initializes_once_and_builds_exact_dedicated_boundary(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        init_guard = source.index("if [[ ! -e /var/lib/incus/database/global/db.bin ]]")
        init = source.index("incus admin init --preseed", init_guard)
        project = source.index('incus project create "${project}"')
        self.assertLess(init_guard, init)
        self.assertLess(init, project)
        for token in (
            "ci-jit", "ci-jit-dedicated", "ci-jit-isolated",
            'truncate -s "${storage_bytes}" "${storage_staging}"',
            'mkfs.ext4 -q -F -O project,quota',
            'mv -T -- "${storage_staging}" "${storage_image}"',
            'storage staging file is unexpectedly loop-attached',
            'ext4 volume label drift',
            'mounted ext4 UUID drift',
            'storage image ownership, mode, size, or link-count drift',
            'incus storage create "${pool}" dir source="${storage_pool_path}"',
            'Options=loop,prjquota,nodev',
            'systemctl enable --now "${mount_unit}"',
            'RequiresMountsFor=${storage_mount}',
            'systemctl stop incus.socket incus.service',
            'Incus storage drop-in is not loaded',
            'losetup -n -O BACK-FILE',
            'storage loop backing file drift',
            'storage image has an ambiguous loop mapping',
            'storage mount ownership or mode drift',
            'limits.disk=12GiB',
            'restricted.containers.privilege=isolated',
            'ipv4.address=10.254.0.1/28', 'ipv4.dhcp.gateway=none',
            'ipv4.nat=false', 'ipv6.address=none',
            'systemctl start incus.service', 'systemctl is-active incus.service',
            '"security.privileged": "false"', '"security.nesting": "false"',
            '"security.idmap.isolated": "true"', '"limits.processes": "2048"',
            'restricted=true restricted.containers.privilege=isolated',
            'restricted.devices.disk=managed restricted.devices.nic=managed',
            'restricted.networks.access="${bridge}"',
            'limits.instances=1 limits.containers=1 limits.virtual-machines=0',
            'root disk path=/ pool="${pool}" size=12GiB', 'incus profile edit "${profile}"',
            'eth0 nic network="${bridge}" name=eth0',
            'incus list --all-projects', '"instances":0',
        ):
            self.assertIn(token, source)

    def test_payload_rejects_host_facing_devices_uplink_nat_and_extra_disks(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            'set(devices) != {"root", "eth0"}',
            'root != {"type": "disk", "path": "/", "pool": "ci-jit-dedicated", "size": "12GiB"}',
            '{"proxy", "unix-char", "unix-block"}',
            'network_config.get("bridge.external_interfaces") not in (None, "")',
            '"ipv4.nat": "false"', '"ipv6.nat": "false"',
            '"root_is_only_disk":true', '"forbidden_devices":false',
            '"bridge_uplink":false', '"ipv4_nat":false', '"ipv6_nat":false',
            '"project_restricted":true', '"project_instance_limit":1',
            '"storage_driver":"dir"', '"storage_filesystem":"ext4"',
            '"storage_filesystem_uuid":"%s"',
            '"storage_project_quota":true', '"storage_mount_persistent":true',
            '"storage_quota_canary_passed":true',
            '"storage_mount_unit_enabled":true', '"storage_mount_unit_active":true',
            '"incus_mount_ordering_verified":true',
            '"storage_mount_root_owned":true', '"storage_pool_size":"16GiB"',
            '"storage_image_apparent_bytes":%s', '"storage_image_allocated_bytes":%s',
            '"storage_filesystem_bytes":%s',
            '"negative_canaries_passed":true', '"storage_volumes":0',
        ):
            self.assertIn(token, source)

    def test_payload_proves_policy_with_negative_canaries_and_cleans_them(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            "expect_policy_rejection privileged", "security.privileged=true",
            "expect_policy_rejection nesting", "security.nesting=true",
            "expect_policy_rejection proxy", "type=proxy",
            "expect_policy_rejection idmap", "security.idmap.isolated=false",
            '-c limits.cpu=1 -c limits.memory=64MiB -c limits.processes=64',
            '-d root,type=disk,path=/,pool="${pool}",size=64MiB',
            "trap cleanup_canaries EXIT", "trap - EXIT",
            "cleanup_owned_canaries", "ci-jit-canary-privileged'",
            'incus storage volume list "${pool}" --all-projects',
            "preexisting default profile is not neutral",
        ):
            self.assertIn(token, source)
        self.assertNotIn("profile edit default", source)
        self.assertNotIn('ci-jit-canary-privileged-$$', source)

    def test_payload_proves_a_real_small_custom_volume_quota(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            'incus storage volume create "${pool}" "${canary_quota}" size=8MiB',
            'incus storage volume get "${pool}" "${canary_quota}" size',
            "== '8MiB'", 'vfs.f_bavail * vfs.f_frsize < 64 * mib',
            'write_exact(under, 7 * mib)', 'write_exact(over, 2 * mib)',
            'exc.errno != errno.EDQUOT',
            'incus storage volume delete "${pool}" "${canary_quota}"',
            'quota canary escaped the dedicated pool',
        ):
            self.assertIn(token, source)
        self.assertNotIn('no space left on device', source.lower())

    def test_systemd_owns_mount_persistence_and_pool_uses_empty_child(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            'readonly storage_pool_path="${storage_mount}/pool"',
            'Options=loop,prjquota,nodev',
            'systemctl enable --now "${mount_unit}"',
            'Requires=${mount_unit}', 'After=${mount_unit}',
            'RequiresMountsFor=${storage_mount}',
            'systemctl is-enabled "${mount_unit}"',
            'systemctl is-active "${mount_unit}"',
            'systemctl stop "${mount_unit}"',
            'systemctl start incus.service',
            'storage mount did not stop for the ordering canary',
            'legacy fstab storage mount configuration is present',
        ):
            self.assertIn(token, source)
        self.assertNotIn('>> /etc/fstab', source)
        self.assertNotIn('Options=loop,prjquota,nosuid,nodev', source)
        self.assertIn('"${mount_options}" != *,nosuid,*', source)

    def test_global_inventory_preflight_precedes_boundary_mutation(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        preflight = source.index('incus list --all-projects --format csv')
        for mutation in (
            'incus network create "${bridge}"',
            'incus project create "${project}"',
            'incus profile create "${profile}"',
        ):
            self.assertLess(preflight, source.index(mutation))

    def test_boundary_rejects_extra_networks_projects_and_canary_residue(self) -> None:
        source = PAYLOAD.read_text(encoding="utf-8")
        for token in (
            "unexpected Incus network inventory", "unexpected Incus project inventory",
            "negative canary left an instance", "negative canary left a storage volume",
            "ci-jit-canary-idmap",
        ):
            self.assertIn(token, source)
        self.assertLess(source.index("cleanup_owned_canaries\n"), source.index("preflight found an existing Incus instance"))

    def test_boundary_uses_only_the_ext4_loop_backend(self) -> None:
        combined = INSTALLER.read_text(encoding="utf-8") + PAYLOAD.read_text(encoding="utf-8")
        for token in (
            'storage_driver = "dir"', 'storage_filesystem = "ext4"',
            "storage_project_quota", "storage_mount_persistent", "storage_mount_root_owned",
        ):
            self.assertIn(token, combined)
        self.assertNotIn("btrfs", combined.lower())
        self.assertNotIn("--property=Requires --value", combined)
        self.assertNotIn("--property=After --value", combined)
        self.assertNotIn("--property=RequiresMountsFor --value", combined)
        self.assertNotIn("-c n", combined)
        self.assertNotIn("show default --project", combined)
        self.assertNotIn("show \"${pool}\" --format json", combined)
        self.assertIn('incus storage list --format json | json_names', combined)
        self.assertIn('incus query "/1.0/storage-pools/${pool}"', combined)

    def test_boundary_installer_has_no_external_product_or_runner_surface(self) -> None:
        combined = (INSTALLER.read_text(encoding="utf-8") + PAYLOAD.read_text(encoding="utf-8")).lower()
        for forbidden in (
            "cloud" + "flare", "github.com", "api.github", "config.sh", "actions-runner",
            "registration-token", "registration token", "runner registration",
        ):
            self.assertNotIn(forbidden, combined)

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
