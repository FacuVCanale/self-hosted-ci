from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/host/check-self-hosted-ci-health.sh"
PROBE = ROOT / "scripts/host/get-self-hosted-ci-health.ps1"


class HostHealthScriptTests(unittest.TestCase):
    def test_probe_parses_in_powershell_when_available(self) -> None:
        powershell = next(
            (candidate for candidate in ("pwsh", "powershell") if subprocess.run(
                ["bash", "-lc", f"command -v {candidate}"], capture_output=True, check=False
            ).returncode == 0),
            None,
        )
        if powershell is None:
            self.skipTest("PowerShell is not installed")
        command = (
            "$errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{PROBE}', [ref]$null, [ref]$errors); if ($errors.Count) {{ $errors | Out-String; exit 1 }}"
        )
        parsed = subprocess.run([powershell, "-NoProfile", "-Command", command], text=True, capture_output=True)
        self.assertEqual(0, parsed.returncode, parsed.stdout + parsed.stderr)

    def test_wrapper_is_valid_requires_explicit_target_and_sid(self) -> None:
        syntax = subprocess.run(["bash", "-n", str(WRAPPER)], text=True, capture_output=True, check=False)
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        missing = subprocess.run(["bash", str(WRAPPER)], text=True, capture_output=True, check=False)
        self.assertEqual(2, missing.returncode)
        self.assertIn("--ssh-target", missing.stderr)

    def test_wrapper_transmits_probe_and_returns_remote_json_unchanged(self) -> None:
        expected = {
            "schema_version": 1,
            "mode": "read_only",
            "host": {"reachable": True},
            "eligibility": {"eligible_for_local_ci": False},
        }
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            capture = tmp / "args.json"
            fake_ssh = tmp / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "payload = sys.stdin.read()\n"
                "open(os.environ['SSH_CAPTURE'], 'w').write(json.dumps({'args': sys.argv[1:], 'stdin': payload}))\n"
                "print(os.environ['SSH_RESPONSE'])\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{tmp}:{env['PATH']}"
            env["SSH_CAPTURE"] = str(capture)
            env["SSH_RESPONSE"] = json.dumps(expected, separators=(",", ":"))
            result = subprocess.run(
                [
                    "bash",
                    str(WRAPPER),
                    "--ssh-target",
                    "desktop",
                    "--service-account-sid",
                    "S-1-5-21-1-2-3-1008",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected, json.loads(result.stdout))
            captured = json.loads(capture.read_text(encoding="utf-8"))
            args = captured["args"]
            self.assertEqual(["--", "desktop", "powershell.exe"], args[:3])
            self.assertEqual(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"], args[3:])
            transport = captured["stdin"]
            lines = transport.splitlines()
            self.assertEqual("$b=''", lines[0])
            self.assertEqual(
                "Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))",
                lines[-1],
            )
            chunks = []
            for line in lines[1:-1]:
                self.assertTrue(line.startswith("$b+='") and line.endswith("'"), line)
                chunk = line[len("$b+='"):-1]
                self.assertLessEqual(len(chunk), 2048)
                chunks.append(chunk)
            self.assertGreater(len(chunks), 1)
            payload = base64.b64decode("".join(chunks), validate=True).decode("utf-8")
            self.assertTrue(payload.startswith("& {\n[CmdletBinding()]"))
            self.assertIn("-ExpectedDistroName 'Ubuntu-24.04-CI'", payload)
            self.assertIn("-ExpectedServiceAccountSid 'S-1-5-21-1-2-3-1008'", payload)
            self.assertIn("eligible_for_local_ci", payload)

    def test_wrapper_never_uses_encoded_command_or_command_line_payload(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertNotIn("EncodedCommand", source)
        self.assertNotIn("-EncodedCommand", source)
        self.assertIn("FromBase64String", source)
        self.assertIn("fold -w 2048", source)
        self.assertIn("-Command -", source)
        self.assertIn('} | ssh -- "${ssh_target}"', source)

    def test_wrapper_rejects_sid_injection_before_ssh(self) -> None:
        result = subprocess.run(
            [
                "bash",
                str(WRAPPER),
                "--ssh-target",
                "desktop",
                "--service-account-sid",
                "S-1-5-21-1';Write-Host pwned;'",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("invalid Windows SID", result.stderr)

    def test_wrapper_rejects_distro_injection_before_ssh(self) -> None:
        result = subprocess.run(
            [
                "bash",
                str(WRAPPER),
                "--ssh-target",
                "desktop",
                "--service-account-sid",
                "S-1-5-21-1-2-3-1008",
                "--distro",
                "Ubuntu-24.04-CI';Write-Host pwned;'",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("invalid WSL distro name", result.stderr)

    def test_probe_is_read_only_and_fails_closed_when_not_observable(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('[string]$ExpectedDistroName = "Ubuntu-24.04-CI"', source)
        self.assertIn('@("linux", "self-hosted", "wsl-jit", "x64")', source)
        self.assertIn('status = "not_observable"', source)
        self.assertIn('service_identity_not_verified', source)
        self.assertIn('dedicated_distro_not_observable', source)
        self.assertIn('heartbeat_not_fresh', source)
        self.assertIn('eligible_for_local_ci = ($blockingReasons.Count -eq 0)', source)
        forbidden = (
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "Set-Service",
            "Start-Service",
            "config.sh --",
            "wsl.exe --import",
            "wsl.exe --unregister",
            "New-Item",
            "Set-Content",
        )
        for token in forbidden:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
