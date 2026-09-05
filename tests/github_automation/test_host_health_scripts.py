from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "scripts/host"
WRAPPER = HOST / "check-self-hosted-ci-health.sh"
VALIDATOR = HOST / "validate-health-snapshot.py"
SUPERVISOR = HOST / "run-health-supervisor.ps1"
INSTALLER = HOST / "install-health-supervisor.ps1"
UNINSTALLER = HOST / "uninstall-health-supervisor.ps1"
PREREQUISITE_INSTALLER = HOST / "install-health-prerequisites.ps1"
PREREQUISITE_UNINSTALLER = HOST / "uninstall-health-prerequisites.ps1"
WSL_INSTALL_PAYLOAD = HOST / "install-health-wsl-payload.sh.in"
WSL_UNINSTALL_PAYLOAD = HOST / "uninstall-health-wsl-payload.sh.in"
SPEC = importlib.util.spec_from_file_location("health_validator", VALIDATOR)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SID = "S-1-5-21-1-2-3-1008"


def snapshot(now: datetime, *, eligible: bool = True) -> dict[str, object]:
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 2,
        "install_nonce": "12345678-1234-4123-8123-123456789abc",
        "generated_at": stamp(now),
        "expires_at": stamp(now + timedelta(seconds=180)),
        "producer": {
            "windows_sid": SID,
            "account": "selfhosted-ci-svc",
            "distro": "Ubuntu-24.04-CI",
        },
        "host": {
            "service_identity_verified": True,
            "services": {
                "sshd": {"installed": True, "status": "running"},
                "wsl": {"installed": True, "status": "running"},
                "lxss_manager": {"installed": False, "status": "absent"},
            },
        },
        "distro": {
            "name": "Ubuntu-24.04-CI",
            "platform": "wsl2",
            "os_id": "ubuntu",
            "os_version": "24.04",
        },
        "runner": {
            "mode": "garm-jit",
            "manager": {"configured": True, "state": "active"},
            "provider": {"configured": True},
            "image": {"configured": True},
            "broker": {"configured": True, "state": "active"},
            "transient_inventories_clean": True,
            "persistent_registration": False,
            "idle_instances": 0,
        },
        "services": {
            name: {"active": "active", "enabled": "enabled"}
            for name in (
                "incus.service",
                "self-hosted-ci-allocation-broker.service",
                "self-hosted-ci-boundary-verify.service",
                "self-hosted-ci-egress-proxy.service",
                "self-hosted-ci-garm.service",
                "self-hosted-ci-health-heartbeat.timer",
                "self-hosted-ci-network-policy.service",
            )
        },
        "heartbeat": {
            "status": "fresh",
            "observed_at": stamp(now),
            "age_seconds": 0,
            "max_age_seconds": 180,
        },
        "boundary": {
            "activation_approved": eligible,
            "network_policy_enabled": eligible,
        },
        "eligibility": {
            "eligible_for_local_ci": eligible,
            "blocking_reasons": []
            if eligible
            else ["activation_not_approved", "network_policy_not_enabled"],
        },
        "probe_error": None,
    }


class HostHealthScriptTests(unittest.TestCase):
    def test_powershell_scripts_parse_when_available(self) -> None:
        powershell = next(
            (
                name
                for name in ("pwsh", "powershell")
                if subprocess.run(
                    ["bash", "-lc", f"command -v {name}"], capture_output=True
                ).returncode
                == 0
            ),
            None,
        )
        if powershell is None:
            self.skipTest("PowerShell is not installed")
        for script in (
            SUPERVISOR,
            INSTALLER,
            UNINSTALLER,
            PREREQUISITE_INSTALLER,
            PREREQUISITE_UNINSTALLER,
        ):
            with self.subTest(script=script.name):
                command = f"$e=$null; [void][Management.Automation.Language.Parser]::ParseFile('{script}',[ref]$null,[ref]$e); if($e.Count){{$e|Out-String;exit 1}}"
                result = subprocess.run(
                    [powershell, "-NoProfile", "-Command", command],
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_reader_acl_canonical_rights_and_mutation_mask_when_powershell_is_available(
        self,
    ) -> None:
        powershell = next(
            (
                name
                for name in ("pwsh", "powershell")
                if subprocess.run(
                    ["bash", "-lc", f"command -v {name}"], capture_output=True
                ).returncode
                == 0
            ),
            None,
        )
        if powershell is None:
            self.skipTest("PowerShell is not installed")
        command = (
            "if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { exit 0 };"
            "$r=[Security.AccessControl.FileSystemRights];"
            "$expected=$r::ReadAndExecute -bor $r::Synchronize;"
            "$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18');"
            "$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;"
            "$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$r::ReadAndExecute,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);"
            "if([int]$expected -ne 1179817){exit 1};"
            "if([int]$rule.FileSystemRights -ne [int]$expected){exit 2};"
            "$m=$r::WriteData -bor $r::AppendData -bor $r::WriteExtendedAttributes -bor $r::WriteAttributes -bor "
            "$r::DeleteSubdirectoriesAndFiles -bor $r::Delete -bor $r::ChangePermissions -bor $r::TakeOwnership;"
            "if((([int]$rule.FileSystemRights)-band $m)-ne 0){exit 3};"
            "if((([int]$r::Write)-band $m)-eq 0){exit 4};"
            "if((([int]$r::Modify)-band $m)-eq 0){exit 5}"
        )
        result = subprocess.run(
            [powershell, "-NoProfile", "-Command", command],
            text=True,
            capture_output=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_validator_exit_codes_are_strict(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.assertEqual(
            (0, "healthy"), MODULE.validate(snapshot(now), SID, "Ubuntu-24.04-CI", now)
        )
        self.assertEqual(
            (3, "local_ci_ineligible"),
            MODULE.validate(snapshot(now, eligible=False), SID, "Ubuntu-24.04-CI", now),
        )
        self.assertEqual(
            (4, "snapshot_expired"),
            MODULE.validate(
                snapshot(now - timedelta(minutes=10)), SID, "Ubuntu-24.04-CI", now
            ),
        )
        crossed = snapshot(now)
        crossed["producer"]["windows_sid"] = "S-1-5-21-9-9-9-1008"
        self.assertEqual(
            (5, "invalid_snapshot_contract"),
            MODULE.validate(crossed, SID, "Ubuntu-24.04-CI", now),
        )
        unknown = snapshot(now)
        unknown["unexpected"] = True
        self.assertEqual(
            (5, "invalid_snapshot_schema"),
            MODULE.validate(unknown, SID, "Ubuntu-24.04-CI", now),
        )

    def test_validator_fails_closed_on_future_heartbeat_age_probe_and_service_boundaries(
        self,
    ) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cases = []
        future = snapshot(now)
        future_stamp = (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        future["generated_at"] = future_stamp
        future["heartbeat"]["observed_at"] = future_stamp
        cases.append((future, "snapshot_from_future"))
        age = snapshot(now)
        age["heartbeat"]["age_seconds"] = 99
        cases.append((age, "invalid_snapshot_contract"))
        probe = snapshot(now)
        probe["probe_error"] = "failed"
        cases.append((probe, "invalid_snapshot_contract"))
        active = snapshot(now)
        active["services"]["incus.service"]["active"] = "inactive"
        cases.append((active, "invalid_snapshot_contract"))
        enabled = snapshot(now)
        enabled["services"]["self-hosted-ci-garm.service"]["enabled"] = "disabled"
        cases.append((enabled, "invalid_snapshot_contract"))
        empty = snapshot(now, eligible=False)
        empty["eligibility"]["blocking_reasons"] = []
        cases.append((empty, "invalid_snapshot_contract"))
        stale = snapshot(now)
        stale["heartbeat"].update(
            status="stale",
            observed_at=(now - timedelta(seconds=181))
            .isoformat()
            .replace("+00:00", "Z"),
            age_seconds=181,
        )
        cases.append((stale, "invalid_snapshot_contract"))
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    expected, MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now)[1]
                )

    def test_validator_accepts_incus_indirect_enablement(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = snapshot(now)
        payload["services"]["incus.service"]["enabled"] = "indirect"
        self.assertEqual(
            (0, "healthy"), MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now)
        )

    def test_validator_fails_closed_on_each_garm_jit_boundary(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cases = (
            ("manager", "configured", False, "garm_manager_not_configured"),
            ("provider", "configured", False, "garm_provider_not_configured"),
            ("image", "configured", False, "runner_image_not_configured"),
            ("broker", "configured", False, "allocation_broker_not_configured"),
        )
        for section, key, value, blocker in cases:
            with self.subTest(blocker=blocker):
                payload = snapshot(now)
                payload["runner"][section][key] = value
                payload["eligibility"] = {
                    "eligible_for_local_ci": False,
                    "blocking_reasons": [blocker],
                }
                self.assertEqual(
                    (3, "local_ci_ineligible"),
                    MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now),
                )
        payload = snapshot(now)
        payload["runner"]["transient_inventories_clean"] = False
        payload["eligibility"] = {
            "eligible_for_local_ci": False,
            "blocking_reasons": ["transient_scale_sets_not_clean"],
        }
        self.assertEqual(
            (3, "local_ci_ineligible"),
            MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now),
        )
        for key, value, blocker in (
            (
                "persistent_registration",
                True,
                "persistent_runner_registration_not_clean",
            ),
            (
                "persistent_registration",
                None,
                "persistent_runner_registration_not_clean",
            ),
            ("idle_instances", 1, "idle_jit_instances_present"),
            ("idle_instances", None, "jit_instances_not_observable"),
        ):
            with self.subTest(blocker=blocker):
                payload = snapshot(now)
                payload["runner"][key] = value
                payload["eligibility"] = {
                    "eligible_for_local_ci": False,
                    "blocking_reasons": [blocker],
                }
                self.assertEqual(
                    (3, "local_ci_ineligible"),
                    MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now),
                )

    def test_validator_accepts_only_legacy_runner_shape_for_supervisor_probe_failure(
        self,
    ) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = snapshot(now)
        payload["runner"] = {
            "installed": None,
            "registered": None,
            "labels": ["linux", "self-hosted", "wsl-jit", "x64"],
        }
        payload["probe_error"] = "bounded probe failure"
        payload["eligibility"] = {
            "eligible_for_local_ci": False,
            "blocking_reasons": ["supervisor_probe_failed"],
        }
        self.assertEqual(
            (3, "local_ci_ineligible"),
            MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now),
        )
        payload["probe_error"] = None
        self.assertEqual(
            (5, "invalid_snapshot_contract"),
            MODULE.validate(payload, SID, "Ubuntu-24.04-CI", now),
        )

    def test_collector_systemd_state_executes_without_unbound_local_and_observe_deduplicates(
        self,
    ) -> None:
        collector_path = HOST / "collect-health-snapshot.py"
        spec = importlib.util.spec_from_file_location(
            "health_collector", collector_path
        )
        assert spec and spec.loader
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        responses = [
            subprocess.CompletedProcess([], 0, "active\n", ""),
            subprocess.CompletedProcess([], 0, "enabled\n", ""),
        ]
        with mock.patch.object(collector.subprocess, "run", side_effect=responses):
            self.assertEqual(
                {"active": "active", "enabled": "enabled"},
                collector.systemd_state("incus.service"),
            )

    def test_collector_garm_state_is_schema_closed_root_owned_and_credential_free(
        self,
    ) -> None:
        collector_path = HOST / "collect-health-snapshot.py"
        spec = importlib.util.spec_from_file_location(
            "health_collector_garm", collector_path
        )
        assert spec and spec.loader
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        target = {
            "authority_kind": "personal-repository",
            "entity_flag": "--repo",
            "entity_id": "12345678-1234-4123-8123-123456789abc",
            "entity_name": "FacuVCanale/example",
            "runner_group": None,
        }
        state = {
            "schema_version": 3,
            "manager_configured": True,
            "provider_configured": True,
            "image_configured": True,
            "broker_configured": True,
            "zero_scale_sets": True,
            "garm_cli_home": "/run/self-hosted-ci/garm-cli",
            "image": {"alias": "runner-pinned", "fingerprint": "a" * 64},
            "targets": {"123": target},
        }
        broker = {
            "allocation_signer_fingerprint": "b" * 64,
            "garm_cli_home": "/run/self-hosted-ci/garm-cli",
            "provider_name": "incus_ci_jit",
            "image_alias": "runner-pinned",
            "image_fingerprint": "a" * 64,
            "live_job_verifier": str(collector.LIVE_JOB_VERIFIER),
            "targets": {"123": target},
        }
        original_read_text = Path.read_text

        def read_state(path: Path, *args: object, **kwargs: object) -> str:
            if path == collector.GARM_HEALTH_STATE:
                return json.dumps(state)
            if path == collector.BROKER_CONFIG:
                return json.dumps(broker)
            return original_read_text(path, *args, **kwargs)

        responses = [
            {
                "callback_url": "http://10.254.0.1:8080/api/v1/callbacks",
                "metadata_url": "http://10.254.0.1:8080/api/v1/metadata",
            },
            [{"name": "incus_ci_jit", "type": "external", "description": "pinned"}],
            [],
            [{"fingerprint": "a" * 64, "aliases": [{"name": "runner-pinned"}]}],
        ]
        completed = [
            subprocess.CompletedProcess([], 0, json.dumps(value), "")
            for value in responses
        ]
        with (
            mock.patch.object(collector, "regular_root_file", return_value=True),
            mock.patch.object(collector, "root_secret_file", return_value=True),
            mock.patch.object(Path, "read_text", read_state),
            mock.patch.object(
                collector.subprocess, "run", side_effect=completed
            ) as run,
        ):
            self.assertEqual(
                {
                    "manager_configured": True,
                    "provider_configured": True,
                    "image_configured": True,
                    "broker_configured": True,
                    "zero_scale_sets": True,
                },
                collector.garm_configuration_state(),
            )
            self.assertEqual(4, run.call_count)
            self.assertTrue(
                all(
                    call.args[0][:3]
                    == [str(collector.GARM_SESSION_HELPER), "run", "--"]
                    for call in run.call_args_list[:3]
                )
            )
            self.assertEqual(
                [
                    "incus",
                    "image",
                    "list",
                    "runner-pinned",
                    "--project",
                    "ci-jit",
                    "--format",
                    "json",
                ],
                run.call_args_list[3].args[0],
            )
        drifted_responses = [responses[0], responses[1], [{"id": 9}], responses[3]]
        with (
            mock.patch.object(collector, "regular_root_file", return_value=True),
            mock.patch.object(collector, "root_secret_file", return_value=True),
            mock.patch.object(Path, "read_text", read_state),
            mock.patch.object(
                collector.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(value), "")
                    for value in drifted_responses
                ],
            ),
        ):
            self.assertTrue(
                all(
                    value is None
                    for value in collector.garm_configuration_state().values()
                )
            )
        state["token"] = "must-not-be-observable"
        with (
            mock.patch.object(collector, "regular_root_file", return_value=True),
            mock.patch.object(collector, "root_secret_file", return_value=True),
            mock.patch.object(Path, "read_text", read_state),
        ):
            self.assertTrue(
                all(
                    value is None
                    for value in collector.garm_configuration_state().values()
                )
            )
        source = collector_path.read_text(encoding="utf-8")
        for forbidden in ("github_token", "installation_token", "passphrase"):
            self.assertNotIn(forbidden, source.lower())

    def test_collector_observes_zero_idle_instances_and_rejects_unobservable_inventory(
        self,
    ) -> None:
        collector_path = HOST / "collect-health-snapshot.py"
        spec = importlib.util.spec_from_file_location(
            "health_collector_instances", collector_path
        )
        assert spec and spec.loader
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        with mock.patch.object(
            collector.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "[]", ""),
        ):
            self.assertEqual(0, collector.idle_instance_count())
        with mock.patch.object(
            collector.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", "denied"),
        ):
            self.assertIsNone(collector.idle_instance_count())

    def test_mac_checker_uses_only_fixed_sftp_get_and_preserves_validator_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fixture = tmp / "fixture.json"
            fixture.write_text(
                json.dumps(snapshot(datetime.now(timezone.utc))), encoding="utf-8"
            )
            fake = tmp / "sftp"
            fake.write_text(
                "#!/usr/bin/env python3\nimport os,pathlib,shutil,sys\n"
                "batch=pathlib.Path(sys.argv[sys.argv.index('-b')+1]).read_text().strip().split()\n"
                "assert batch[0]=='get' and batch[1]=='/C:/ProgramData/self-hosted-ci/health/current.json'\n"
                "shutil.copyfile(os.environ['HEALTH_FIXTURE'],batch[2])\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{tmp}:{env['PATH']}"
            env["HEALTH_FIXTURE"] = str(fixture)
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER),
                    "--ssh-target",
                    "desktop",
                    "--service-account-sid",
                    SID,
                ],
                text=True,
                capture_output=True,
                env=env,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("healthy", json.loads(result.stdout)["status"])
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("sftp -q -oBatchMode=yes", source)
        self.assertNotIn("ssh ", source)
        self.assertNotIn("powershell", source.lower())
        self.assertNotIn("put ", source)

    def test_mac_checker_usage_and_transport_have_stable_exit_codes(self) -> None:
        missing = subprocess.run(["bash", str(WRAPPER)], text=True, capture_output=True)
        self.assertEqual(2, missing.returncode)
        syntax = subprocess.run(
            ["bash", "-n", str(WRAPPER)], text=True, capture_output=True
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)

    def test_windows_supervisor_is_atomic_identity_bound_and_never_registers_runner(
        self,
    ) -> None:
        source = SUPERVISOR.read_text(encoding="utf-8")
        for token in (
            "Write-AtomicUtf8",
            "Move-Item -LiteralPath $temporary",
            "WindowsIdentity]::GetCurrent().User.Value",
            "service identity mismatch",
            "schema_version = 2",
            "supervisor_probe_failed",
            "Test-LocalTcpEndpoint 22",
            "Get-HostServices $true",
            "$WslProbeSucceeded -and $wsl.status -eq \"absent\"",
            "Get-CoherentHeartbeat",
            "WSL heartbeat timestamp is ahead of the Windows clock",
            'if ([string]$reason -ne "heartbeat_not_fresh")',
            'if ($heartbeat.status -ne "fresh")',
            '"--exec", "/bin/sleep", "infinity"',
            "dedicated distro keepalive exited before the supervisor started",
            "finally { Stop-WslKeepalive $keepalive }",
        ):
            self.assertIn(token, source)
        self.assertIn(
            '"incus.service", "self-hosted-ci-allocation-broker.service"', source
        )
        self.assertLess(
            source.index("$hostServices = Get-HostServices $true"),
            source.index("$generatedAt = [DateTimeOffset]::UtcNow"),
        )
        self.assertLess(
            source.index("$generatedAt = [DateTimeOffset]::UtcNow"),
            source.index("$heartbeat = Get-CoherentHeartbeat"),
        )
        self.assertIn(
            "return New-FailClosedSnapshot ([DateTimeOffset]::UtcNow)", source
        )
        for forbidden in (
            "config.sh",
            "Register-ScheduledTask",
            "github.com",
            "Invoke-WebRequest",
        ):
            self.assertNotIn(forbidden, source)

    def test_installer_is_plan_only_password_lua_acl_and_postcondition_bound(
        self,
    ) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[switch]$Apply",
            "AcknowledgePersistentPasswordTask",
            "Get-DedicatedReader",
            "Get-LocalUser",
            "Test-GroupContainsSid",
            "New-CryptographicAccountPassword",
            "SecureStringToBSTR",
            "ZeroFreeBSTR",
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA",
            "SetAccessRuleProtection($true, $false)",
            "GetOwner([Security.Principal.SecurityIdentifier])",
            "ACL inheritance protection is not exact",
            "ACL inherited-rule state is not exact",
            "ACL inheritance or propagation flags are not exact",
            "ReadAndExecute",
            "dedicated non-admin identity",
            "AuthorizedKeysFile C:/Users/selfhosted-ci-health/.ssh/authorized_keys",
            "ForceCommand internal-sftp",
            "DisableForwarding yes",
            "active sshd configuration does not contain the exact terminal SFTP-only block",
            'Principal.LogonType -ne "Password"',
            "previous snapshot could not be fenced",
            "two distinct post-install snapshots",
            "SCHED_S_TASK_RUNNING",
            "producer.windows_sid",
            "WSL heartbeat timer postcondition failed",
        ):
            self.assertIn(token, source)
        for primitive in (
            "WriteData",
            "AppendData",
            "WriteExtendedAttributes",
            "WriteAttributes",
            "DeleteSubdirectoriesAndFiles",
            "Delete",
            "ChangePermissions",
            "TakeOwnership",
        ):
            self.assertIn(f"FileSystemRights]::{primitive}", source)
        self.assertIn("FileSystemRights]::Synchronize", source)
        self.assertIn("$rule.FileSystemRights -ne $expectedReaderRights", source)
        reader_check = source[
            source.index(
                "if ($rule.IdentityReference.Value -eq $ReaderSid)"
            ) : source.index(
                "elseif ($rule.FileSystemRights -ne",
                source.index("if ($rule.IdentityReference.Value -eq $ReaderSid)"),
            )
        ]
        self.assertNotIn("FileSystemRights]::Modify", reader_check)
        self.assertNotIn("FileSystemRights]::Write -bor", reader_check)
        self.assertLess(
            source.index("if (-not $Apply) { return }"),
            source.index("Set-LocalUser -Name $account.Name -Password $password"),
        )
        self.assertNotIn("config.sh", source)

    def test_prerequisite_bootstrap_is_separate_plan_only_and_fail_closed(self) -> None:
        source = PREREQUISITE_INSTALLER.read_text(encoding="utf-8")
        for token in (
            "[switch]$Apply",
            "AcknowledgeCreateDisabledReader",
            "AcknowledgeOneTimePasswordRotation",
            'ReaderAccount = "selfhosted-ci-health"',
            'DistroName = "Ubuntu-24.04-CI"',
            "Disable-LocalUser -Name $ReaderAccount",
            "Set-ExactAuthorizedKey",
            "TASK_LOGON_PASSWORD",
            "TASK_RUNLEVEL_LUA",
            "SecureStringToBSTR",
            "ZeroFreeBSTR",
            "payload_sha256",
            "persistent supervisor must not exist; bootstrap must run first",
            "two-heartbeat postcondition failed",
            "Unregister-ScheduledTask",
            "stored_task_credential_invalidated=$true",
            '[ValidateSet("none", "host-after-reader", "worker-before-wsl", "payload-after-install", "payload-evidence-failure")]',
        ):
            self.assertIn(token, source)
        self.assertLess(
            source.index("if (-not $Apply) { return }"),
            source.index("New-LocalUser -Name $ReaderAccount"),
        )
        self.assertLess(
            source.index(
                "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; $registered = $false"
            ),
            source.index("$finalPassword = New-RandomPassword"),
        )
        for token in (
            "Test-GroupContainsSid",
            "cannot resolve nested administrator group",
            "preexisting health reader must be disabled and have exact managed provenance",
            "reader profile path is not canonical",
            "Assert-NoReparsePath",
            "Assert-NoReparseDescendants",
            "reparse descendant is forbidden",
            "one-shot task reappeared before completion evidence",
        ):
            self.assertIn(token, source)
        for token in (
            'FailureInjection -eq "host-after-reader"',
            "Remove-ExactManagedReaderProfile",
            "Assert-ExactManagedReaderProfile",
            "unexpected reader profile artifact blocks rollback",
            "New-AdminOnlyAcl",
            "worker.stdout.log",
            "worker.stderr.log",
            "worker-error.json",
            "Save-FailureEvidence",
            "last_task_result",
            "task-summary.json",
            "Evidence: $evidence",
            "RedirectStandardInput",
            "RedirectStandardOutput",
            "RedirectStandardError",
            "recover-orphan-create-disabled",
            "orphan health reader authorized key is not exact",
            "worker-context.json",
            "Get-ExactRegistration",
            "HKEY_CURRENT_USER",
            "HKEY_USERS\\$ExpectedServiceAccountSid",
            "process_session_id",
            "user_profile_environment",
            "exact_sid_hku_registration",
            "visibility_attempts",
            "exact_distro_visible",
            "exact WSL distro remained invisible after bounded preflight",
            "AllowDemandStart",
            "DisallowStartIfOnBatteries",
            "StopIfGoingOnBatteries",
            "TASK_INSTANCES_IGNORE_NEW",
            "one-shot task settings postcondition failed",
            "registration_validated",
            "selected_distribution_id",
            "WSL registration key is not a canonical GUID",
            "HKCU and exact-SID WSL registration GUIDs differ",
            "WSL registration name is not exact",
            "WSL registration version is not 2",
            "WSL registration BasePath is not exact",
            "exact WSL registry validation failed",
            "--distribution-id ",
            "ExpectedDistroBasePath",
            ".Replace([string][char]0, [string]::Empty)",
            "StringComparer]::Ordinal.Equals",
        ):
            self.assertIn(token, source)
        orphan_delete = source.index(
            "if ($orphanReaderProfile) { Remove-ExactManagedReaderProfile"
        )
        self.assertLess(
            orphan_delete, source.index("New-LocalUser -Name $ReaderAccount")
        )
        self.assertLess(
            source.index('FailureInjection -eq "host-after-reader"'),
            source.index("New-Item -ItemType Directory -Path $Root"),
        )
        evidence_save = source.index("Save-FailureEvidence $original")
        self.assertLess(
            evidence_save,
            source.index(
                "Remove-Item -LiteralPath $Root -Recurse -Force", evidence_save
            ),
        )
        context_write = source.index("[IO.File]::WriteAllText('$WorkerContextPath'")
        visibility_failure = source.index(
            "exact WSL distro remained invisible after bounded preflight"
        )
        payload_start = source.index("`$psi = [Diagnostics.ProcessStartInfo]::new()")
        self.assertLess(context_write, visibility_failure)
        self.assertLess(visibility_failure, payload_start)
        self.assertIn("for (`$attempt = 1; `$attempt -le 10; `$attempt++)", source)
        self.assertIn("if (`$attempt -lt 10) { Start-Sleep -Seconds 2 }", source)
        self.assertNotIn(".Replace([char]0, '')", source)
        self.assertNotIn("--import-in-place", source)
        self.assertNotIn('--distribution "$DistroName"', source)
        registry_validation = source.index("if (-not `$registrationValidated)")
        guid_launch = source.index("`$psi.Arguments = '--distribution-id '")
        self.assertLess(registry_validation, guid_launch)
        self.assertLess(
            source.index("HKCU and exact-SID WSL registration GUIDs differ"),
            guid_launch,
        )
        self.assertLess(
            source.index("WSL registration BasePath is not exact"), guid_launch
        )
        profile_cleanup = source.index("function Remove-ExactManagedReaderProfile")
        self.assertLess(
            source.index("Set-Acl -LiteralPath $entry[0]", profile_cleanup),
            source.index(
                "Remove-Item -LiteralPath $Profile -Recurse -Force", profile_cleanup
            ),
        )
        for token in (
            "health bootstrap staging root is not canonical",
            'Assert-NoReparsePath "C:\\ProgramData"',
            "Assert-NoReparsePath (Split-Path -Parent $Root) $true",
        ):
            self.assertIn(token, source)
        self.assertLess(
            source.index("Assert-NoReparsePath $Root $true"),
            source.index("New-Item -ItemType Directory -Path $Root"),
        )
        self.assertLess(
            source.index("New-Item -ItemType Directory -Path $Root"),
            source.index("Assert-NoReparseDescendants $Root"),
        )
        for forbidden in (
            "config.sh",
            "github.com",
            "Invoke-WebRequest",
            "incus",
            "garm",
            "boundary-verify",
        ):
            self.assertNotIn(forbidden, source.lower())

    def test_prerequisite_payload_is_bounded_hash_pinned_and_has_two_heartbeats(
        self,
    ) -> None:
        source = WSL_INSTALL_PAYLOAD.read_text(encoding="utf-8")
        syntax = subprocess.run(
            ["bash", "-n", str(WSL_INSTALL_PAYLOAD)], text=True, capture_output=True
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        for token in (
            "sha256sum --check --status",
            'systemctl enable --now "${timer}"',
            "first=",
            "second=",
            '[[ -n "${second}" && "${second}" != "${first}" ]]',
            "restore_previous",
            "snapshot_complete=true",
            "payload-after-install",
            ".restore.XXXXXX",
            ".install.XXXXXX",
        ):
            self.assertIn(token, source)
        for forbidden in ("/mnt/", "powershell.exe", "cmd.exe", "config.sh", "github"):
            self.assertNotIn(forbidden, source.lower())
        self.assertEqual(
            4,
            len(
                set(
                    __import__("re").findall(
                        r"@@(?:COLLECTOR|WRITER|SERVICE|TIMER)_B64@@", source
                    )
                )
            ),
        )
        self.assertLess(
            source.index("snapshot_complete=true"),
            source.index('install -d -o root -g root -m 0755 "${root}"'),
        )
        self.assertLess(
            source.index("restore_previous()"), source.index("payload-after-install")
        )
        self.assertIn("payload-evidence-failure", source)
        self.assertLess(
            source.index("payload-evidence-failure"), source.index("committed=true")
        )
        self.assertLess(
            source.index('printf \'{"status":"installed"'),
            source.index("committed=true"),
        )

    def test_exact_prerequisite_uninstall_requires_supervisor_first(self) -> None:
        source = PREREQUISITE_UNINSTALLER.read_text(encoding="utf-8")
        for token in (
            "persistent supervisor must be uninstalled first",
            "health reader must be disabled",
            "unexpected reader profile artifact blocks exact uninstall",
            "Remove-LocalUser",
            "stored_task_credential_invalidated=$true",
        ):
            self.assertIn(token, source)
        payload = WSL_UNINSTALL_PAYLOAD.read_text(encoding="utf-8")
        self.assertEqual(
            0,
            subprocess.run(
                ["bash", "-n", str(WSL_UNINSTALL_PAYLOAD)], capture_output=True
            ).returncode,
        )
        self.assertIn("expected managed file is absent or unsafe", payload)
        self.assertIn("sha256sum --check --status", payload)
        self.assertNotIn("config.sh", payload)
        for token in (
            "Cleanup failures:",
            "task absence postcondition failed",
            "health reader remains after exact uninstall",
            "one-shot task reappeared before completion evidence",
        ):
            self.assertIn(token, source)
        for token in (
            "health bootstrap staging root is not canonical",
            'Assert-NoReparsePath "C:\\ProgramData"',
            "Assert-NoReparsePath $Root $true",
            "Assert-NoReparseDescendants $Root\n    Remove-Item -LiteralPath $Root",
        ):
            self.assertIn(token, source)

    def test_prerequisite_reparse_fence_never_recurses_programdata_ancestors(
        self,
    ) -> None:
        for path in (PREREQUISITE_INSTALLER, PREREQUISITE_UNINSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                path_fence = source[
                    source.index("function Assert-NoReparsePath") : source.index(
                        "function Assert-NoReparseDescendants"
                    )
                ]
                descendant_fence = source[
                    source.index("function Assert-NoReparseDescendants") : source.index(
                        "function ",
                        source.index("function Assert-NoReparseDescendants") + 1,
                    )
                ]
                self.assertNotIn("Get-ChildItem", path_fence)
                self.assertNotIn("-Recurse", descendant_fence)
                self.assertIn("while ($cursor)", path_fence)
                self.assertIn("if (Test-Path -LiteralPath $cursor)", path_fence)
                self.assertIn('Assert-NoReparsePath "C:\\ProgramData"', source)
                self.assertNotIn('Get-ChildItem -LiteralPath "C:\\ProgramData"', source)
                create = source.index("New-Item -ItemType Directory -Path $Root")
                self.assertGreater(
                    source.index("Assert-NoReparseDescendants $Root", create), create
                )

    def test_supervisor_enables_reader_only_after_sftp_fence_and_uninstall_disables_it(
        self,
    ) -> None:
        install = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'if ($reader.Enabled) { throw "health reader must be disabled before SFTP activation" }',
            install,
        )
        stage = install.index("Set-SftpOnlyConfiguration $reader.Name")
        self.assertGreater(install.index("$sshdConfigured = $true", stage), stage)
        stop = install.index("Stop-Service -Name sshd -ErrorAction Stop", stage)
        enable = install.index("Enable-LocalUser -Name $reader.Name", stop)
        start = install.index("Start-Service -Name sshd -ErrorAction Stop", enable)
        verify = install.index("Assert-SftpOnlyConfiguration $reader.Name", start)
        self.assertLess(stage, stop)
        self.assertLess(stop, enable)
        self.assertLess(enable, start)
        self.assertLess(start, verify)
        verifier = install[
            install.index("function Assert-SftpOnlyConfiguration") : install.index(
                "if ($env:OS -ne",
                install.index("function Assert-SftpOnlyConfiguration"),
            )
        ]
        self.assertNotIn(" -T ", verifier)
        self.assertNotIn('-C "user=', verifier)
        self.assertIn("[IO.File]::ReadAllText($SshdConfig)", verifier)
        self.assertIn(
            '.EndsWith($expectedBlock + "`r`n", [StringComparison]::Ordinal)', verifier
        )
        self.assertIn("& $sshd -t -f $SshdConfig", verifier)
        self.assertEqual(
            2,
            install.count(
                "AuthorizedKeysFile C:/Users/selfhosted-ci-health/.ssh/authorized_keys"
            ),
        )
        self.assertNotIn("CreateProfile", install)
        rollback = install.index("catch {", verify)
        self.assertIn(
            "$sshdRollbackRequired = $sshdConfigured -or (Test-Path -LiteralPath $SshdBackup -PathType Leaf)",
            install[rollback:],
        )
        self.assertIn(
            "sshd rollback required but backup is missing; service remains stopped",
            install[rollback:],
        )
        rollback_stop = install.index(
            "Stop-Service -Name sshd -ErrorAction SilentlyContinue", rollback
        )
        rollback_disable = install.index(
            "Disable-LocalUser -Name $reader.Name", rollback_stop
        )
        rollback_restore = install.index(
            "Copy-Item -LiteralPath $SshdBackup -Destination $SshdConfig -Force",
            rollback_disable,
        )
        rollback_start = install.index(
            "Start-Service -Name sshd -ErrorAction Stop", rollback_restore
        )
        self.assertIn(
            "refusing to restore unrestricted sshd configuration while reader is enabled",
            install[rollback_disable:rollback_restore],
        )
        self.assertLess(rollback_stop, rollback_disable)
        self.assertLess(rollback_disable, rollback_restore)
        self.assertLess(rollback_restore, rollback_start)
        uninstall = UNINSTALLER.read_text(encoding="utf-8")
        self.assertIn('if ($ReaderAccount -ne "selfhosted-ci-health")', uninstall)
        self.assertLess(
            uninstall.rindex("Disable-LocalUser -Name $ReaderAccount"),
            uninstall.rindex("Remove-ManagedSftpConfiguration"),
        )

    def test_installer_checks_nested_admin_membership_for_both_accounts_independently(
        self,
    ) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("Test-GroupContainsSid $nested $TargetSid $Visited", source)
        self.assertIn(
            "Test-GroupContainsSid $administratorGroup $serviceSid.Value $serviceVisitedGroups",
            source,
        )
        self.assertIn(
            "Test-GroupContainsSid $administratorGroup $readerSid.Value $readerVisitedGroups",
            source,
        )
        self.assertEqual(
            1,
            source.count(
                "$serviceVisitedGroups = [Collections.Generic.HashSet[string]]::new"
            ),
        )
        self.assertEqual(
            1,
            source.count(
                "$readerVisitedGroups = [Collections.Generic.HashSet[string]]::new"
            ),
        )

    def test_uninstaller_deletes_task_rotates_then_removes_exact_artifacts(
        self,
    ) -> None:
        source = UNINSTALLER.read_text(encoding="utf-8")
        delete = source.index("Unregister-ScheduledTask")
        rotate = source.index("Set-LocalUser -Name $account.Name -Password $password")
        remove = source.index("Remove-Item -LiteralPath $path")
        self.assertLess(delete, rotate)
        self.assertLess(rotate, remove)
        self.assertIn("stored_task_credential_invalidated = $true", source)
        for token in (
            "task path/principal postcondition failed",
            "task action arguments are not exact",
            "task did not stop within the bounded deadline",
            "Assert-SafeArtifactTree",
            "artifact descendant is a reparse point",
            "unexpected artifact blocks uninstall",
            "Remove-ManagedSftpConfiguration",
        ):
            self.assertIn(token, source)

    def test_heartbeat_is_atomic_and_systemd_sandboxed(self) -> None:
        writer = (HOST / "update-health-heartbeat.py").read_text(encoding="utf-8")
        collector = (HOST / "collect-health-snapshot.py").read_text(encoding="utf-8")
        service = (
            ROOT / "packaging/systemd/self-hosted-ci-health-heartbeat.service"
        ).read_text(encoding="utf-8")
        timer = (
            ROOT / "packaging/systemd/self-hosted-ci-health-heartbeat.timer"
        ).read_text(encoding="utf-8")
        for token in ("tempfile.mkstemp", "os.fsync", "os.replace", "is_symlink"):
            self.assertIn(token, writer)
        self.assertIn("heartbeat_not_fresh", collector)
        for token in (
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/self-hosted-ci/health",
            "RestrictAddressFamilies=AF_UNIX",
            "UMask=0077",
        ):
            self.assertIn(token, service)
        self.assertIn("OnUnitActiveSec=30s", timer)
        self.assertIn("Persistent=true", timer)


if __name__ == "__main__":
    unittest.main()
