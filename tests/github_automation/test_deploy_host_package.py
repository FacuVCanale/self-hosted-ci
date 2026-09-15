from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("deploy_host_package", ROOT / "scripts/host/deploy-host-package.py")
assert SPEC and SPEC.loader
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)
SHA = "a" * 40


def archive_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in {"scripts/example.py": b"print('tracked')\n", "PACKAGE_SHA": b"old\n"}.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class DeployHostPackageTests(unittest.TestCase):
    def git_response(self, args, **kwargs):
        self.assertTrue(kwargs["check"])
        self.assertEqual(args[0], "git", "plan must never invoke ssh/scp")
        payload = {"rev-parse": SHA.encode(), "status": b"", "diff": b"", "archive": archive_bytes()}[args[1]]
        return subprocess.CompletedProcess(args, 0, payload, b"")

    def test_manifest_hashes_bytes_in_sorted_path_order(self):
        result = DEPLOY.build_manifest({"z": b"\x00\xff", "a": b"hello"})
        self.assertEqual(list(result), ["a", "z"])
        self.assertEqual(result["z"], hashlib.sha256(b"\x00\xff").hexdigest())

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_export_adds_commit_and_manifest_for_only_tracked_files(self, process):
        process.side_effect = self.git_response
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "package.tar"
            sha, manifest = DEPLOY.export_package("release", output)
            with tarfile.open(output) as archive:
                self.assertEqual(set(archive.getnames()), {"scripts/example.py", "PACKAGE_SHA", "PACKAGE_MANIFEST.json"})
                self.assertEqual(archive.extractfile("PACKAGE_SHA").read(), (SHA + "\n").encode())
                self.assertEqual(json.load(archive.extractfile("PACKAGE_MANIFEST.json")), manifest)
                for name, digest in manifest.items():
                    self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), digest)
            self.assertEqual(sha, SHA)
        self.assertEqual(process.call_args_list[0].args[0], ["git", "rev-parse", "--verify", "--end-of-options", "release^{commit}"])

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_ref_difference_and_dirty_status_both_block_before_archive(self, process):
        for status, diff in [(b"?? untracked\n", b""), (b"", b"tracked changes")]:
            with self.subTest(status=status, diff=diff), tempfile.TemporaryDirectory() as directory:
                process.reset_mock()
                process.side_effect = [subprocess.CompletedProcess([], 0, data) for data in [SHA.encode(), status, diff]]
                with self.assertRaisesRegex(ValueError, "working tree differs"):
                    DEPLOY.export_package("HEAD", Path(directory) / "package.tar")
                self.assertEqual(process.call_count, 3)

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_allow_dirty_still_archives_ref_without_working_tree_files(self, process):
        process.side_effect = self.git_response
        with tempfile.TemporaryDirectory() as directory:
            DEPLOY.export_package("HEAD", Path(directory) / "package.tar", allow_dirty=True)
        self.assertEqual([call.args[0][1] for call in process.call_args_list], ["rev-parse", "archive"])

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_default_and_dry_run_print_same_plan_without_transport(self, process):
        process.side_effect = self.git_response
        outputs = []
        for flags in [[], ["--dry-run"]]:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(DEPLOY.main(["--ssh-target", "admin-alias", *flags]), 0)
            outputs.append(json.loads(output.getvalue()))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0]["status"], "planned")
        self.assertEqual(outputs[0]["deployed_sha"], SHA)
        self.assertEqual(outputs[0]["expected_files"], 2)
        self.assertTrue(outputs[0]["requires_administrative_identity"])

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_apply_uses_mocked_transport_and_validates_result(self, process):
        expected = {"status": "deployed", "deployed_sha": SHA, "previous_sha": "unknown", "backup_path": r"C:\backup\package-before-unknown-20260915120000", "verified_files": 2}
        def response(args, **kwargs):
            if args[0] == "git":
                return self.git_response(args, **kwargs)
            return subprocess.CompletedProcess(args, 0, json.dumps(expected).encode() if args[0] == "ssh" else b"", b"")
        process.side_effect = response
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(DEPLOY.main(["--ssh-target", "admin-alias", "--apply"]), 0)
        self.assertEqual(json.loads(output.getvalue()), expected)
        calls = [call.args[0] for call in process.call_args_list]
        self.assertEqual([call[0] for call in calls[-2:]], ["scp", "ssh"])
        self.assertTrue(calls[-2][-1].startswith("admin-alias:self-hosted-ci-package-"))
        self.assertIn("-EncodedCommand", calls[-1])

    @mock.patch.object(DEPLOY.subprocess, "run")
    def test_remote_failure_reports_bounded_stderr_without_encoded_command(self, process):
        def response(args, **kwargs):
            if args[0] == "git":
                return self.git_response(args, **kwargs)
            if args[0] == "ssh":
                raise subprocess.CalledProcessError(1, args, stderr=b"manifest mismatch: scripts/example.py\n" + b"x" * 5000)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        process.side_effect = response
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(DEPLOY.main(["--ssh-target", "admin-alias", "--apply"]), 1)
        self.assertEqual(output.getvalue(), "")
        result = json.loads(errors.getvalue())
        self.assertEqual(result["command"], "ssh")
        self.assertEqual(result["stage"], "deploy")
        self.assertEqual(result["returncode"], 1)
        self.assertTrue(result["stderr"].startswith("manifest mismatch: scripts/example.py"))
        self.assertEqual(len(result["stderr"]), 4096)
        self.assertNotIn("EncodedCommand", errors.getvalue())
        self.assertNotIn("admin-alias", errors.getvalue())

    def test_parse_output_rejects_incomplete_or_unverified_results(self):
        good = {"status": "deployed", "deployed_sha": SHA, "previous_sha": None, "backup_path": None, "verified_files": 2}
        self.assertEqual(DEPLOY.parse_output(json.dumps(good).encode(), expected_sha=SHA, expected_files=2), good)
        bad = [{**good, "status": "planned"}, {**good, "deployed_sha": "b" * 40}, {**good, "verified_files": 1}, {**good, "verified_files": True}, {**good, "previous_sha": "invalid"}, {**good, "backup_path": "relative"}, {key: value for key, value in good.items() if key != "backup_path"}]
        for result in bad:
            with self.subTest(result=result), self.assertRaises(ValueError):
                DEPLOY.parse_output(json.dumps(result).encode(), expected_sha=SHA, expected_files=2)

    def test_plan_rejects_unsafe_targets_and_destinations(self):
        for target in ["-oProxyCommand=bad", "admin host", "host:path", "host;command", "$(command)"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                DEPLOY.build_plan(target, SHA, {}, DEPLOY.PACKAGE_PATH, DEPLOY.BACKUP_ROOT)
        for package, backup in [("relative", DEPLOY.BACKUP_ROOT), ("C:\\", DEPLOY.BACKUP_ROOT), (DEPLOY.PACKAGE_PATH, DEPLOY.PACKAGE_PATH + r"\backups"), (DEPLOY.PACKAGE_PATH, DEPLOY.BACKUP_ROOT + r"\other\..\package\backups")]:
            with self.subTest(package=package, backup=backup), self.assertRaises(ValueError):
                DEPLOY.validate_destination(package, backup)

    def test_remote_script_checks_admin_hashes_and_retains_backup(self):
        plan = DEPLOY.build_plan("admin-alias", SHA, {"a": "hash"}, DEPLOY.PACKAGE_PATH, DEPLOY.BACKUP_ROOT)
        script = DEPLOY.remote_script(plan, "upload.tar")
        self.assertIn("WindowsBuiltInRole]::Administrator", script)
        self.assertIn("Get-FileHash -LiteralPath $file -Algorithm SHA256", script)
        self.assertIn("'package-before-' + $previous", script)
        self.assertLess(script.index("manifest mismatch"), script.index("Move-Item -LiteralPath $package"))
        self.assertIn("finally", script)
        self.assertIn("Move-Item -LiteralPath $backup -Destination $package", script)


if __name__ == "__main__":
    unittest.main()
