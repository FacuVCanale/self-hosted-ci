#!/usr/bin/env python3
"""Export and deploy a versioned tracked package through an administrative SSH target."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_PATH = r"C:\ProgramData\self-hosted-ci\package"
BACKUP_ROOT = r"C:\ProgramData\self-hosted-ci"


def run(args: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def build_manifest(files: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}


def export_package(ref: str, output: Path, *, allow_dirty: bool = False) -> tuple[str, dict[str, str]]:
    sha = run(["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"]).stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise ValueError("git returned an invalid commit SHA")
    if not allow_dirty:
        status = run(["git", "status", "--porcelain"]).stdout
        diff = run(["git", "diff", sha, "--"]).stdout
        if status or diff:
            raise ValueError("working tree differs from ref; commit changes or use --allow-dirty")
    archive = run(["git", "archive", "--format=tar", sha]).stdout
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or ":" in member.name:
                raise ValueError(f"unsafe archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"Windows package requires regular files: {member.name}")
            stream = source.extractfile(member)
            assert stream is not None
            files[member.name] = stream.read()
            modes[member.name] = member.mode
    files.pop("PACKAGE_MANIFEST.json", None)
    files["PACKAGE_SHA"] = (sha + "\n").encode()
    manifest = build_manifest(files)
    files["PACKAGE_MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with tarfile.open(output, "w") as target:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = modes.get(name, 0o644)
            target.addfile(member, io.BytesIO(data))
    return sha, manifest


def validate_destination(package_path: str, backup_root: str) -> None:
    package, backup = PureWindowsPath(package_path), PureWindowsPath(backup_root)
    if ".." in package.parts or ".." in backup.parts:
        raise ValueError("Windows destinations cannot contain parent traversal")
    if not package.is_absolute() or not backup.is_absolute():
        raise ValueError("package-path and backup-root must be absolute Windows paths")
    if package == PureWindowsPath(package.anchor) or backup == package or package in backup.parents:
        raise ValueError("backup-root must be outside the package; package-path cannot be a drive root")


def build_plan(ssh_target: str, sha: str, manifest: dict[str, str], package_path: str, backup_root: str) -> dict:
    validate_destination(package_path, backup_root)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", ssh_target) or ssh_target.count("@") > 1:
        raise ValueError("ssh-target must be an SSH alias or user@host")
    return {"status": "planned", "deployed_sha": sha, "previous_sha": None,
            "backup_path": None, "verified_files": 0, "expected_files": len(manifest),
            "ssh_target": ssh_target, "package_path": package_path, "backup_root": backup_root,
            "backup_pattern": str(PureWindowsPath(backup_root) / "package-before-<previous-sha-or-unknown>-<yyyyMMddHHmmss>"),
            "requires_administrative_identity": True}


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def remote_script(plan: dict, upload_name: str) -> str:
    # Verify the staged tree before replacing the current package. A failed
    # verification preserves the current package and cleans up staging/upload.
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "$identity = [Security.Principal.WindowsIdentity]::GetCurrent()",
        "$principal = New-Object Security.Principal.WindowsPrincipal($identity)",
        "if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'SSH identity must be an administrator, not the service identity' }",
        "$package = " + ps_quote(plan["package_path"]),
        "$backupRoot = " + ps_quote(plan["backup_root"]),
        "$expectedSha = " + ps_quote(plan["deployed_sha"]),
        "$expectedFiles = " + str(plan["expected_files"]),
        "$upload = Join-Path $HOME " + ps_quote(upload_name),
        "$stage = $package + '.deploy-' + [guid]::NewGuid().ToString('N')",
        "$backup = $null; $previous = $null; $verified = 0",
        "try {",
        "  New-Item -ItemType Directory -Path $stage -Force | Out-Null",
        "  & tar.exe -xf $upload -C $stage",
        "  if ($LASTEXITCODE -ne 0) { throw 'tar extraction failed' }",
        "  $manifest = Get-Content -LiteralPath (Join-Path $stage 'PACKAGE_MANIFEST.json') -Raw | ConvertFrom-Json",
        "  foreach ($entry in $manifest.PSObject.Properties) {",
        "    $file = Join-Path $stage $entry.Name",
        "    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()",
        "    if ($hash -cne $entry.Value) { throw ('manifest mismatch: ' + $entry.Name) }",
        "    $verified++",
        "  }",
        "  if ($verified -ne $expectedFiles) { throw 'manifest file count mismatch' }",
        "  if ((Get-Content -LiteralPath (Join-Path $stage 'PACKAGE_SHA') -Raw).Trim() -cne $expectedSha) { throw 'package SHA mismatch' }",
        "  if (@(Get-ChildItem -LiteralPath $stage -File -Recurse -Force).Count -ne ($expectedFiles + 1)) { throw 'unexpected package files' }",
        "  New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null",
        "  if (Test-Path -LiteralPath $package) {",
        "    $previousFile = Join-Path $package 'PACKAGE_SHA'",
        "    if (Test-Path -LiteralPath $previousFile) { $previous = (Get-Content -LiteralPath $previousFile -Raw).Trim() }",
        "    if ($previous -notmatch '^[0-9a-f]{40,64}$') { $previous = 'unknown' }",
        "    $backup = Join-Path $backupRoot ('package-before-' + $previous + '-' + (Get-Date -Format 'yyyyMMddHHmmss'))",
        "    if (Test-Path -LiteralPath $backup) { throw 'backup already exists' }",
        "    Move-Item -LiteralPath $package -Destination $backup",
        "  }",
        "  try { Move-Item -LiteralPath $stage -Destination $package }",
        "  catch { if ($backup -and -not (Test-Path -LiteralPath $package)) { Move-Item -LiteralPath $backup -Destination $package }; throw }",
        "  @{ status = 'deployed'; deployed_sha = $expectedSha; previous_sha = $previous; backup_path = $backup; verified_files = $verified } | ConvertTo-Json -Compress",
        "} finally {",
        "  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }",
        "  if (Test-Path -LiteralPath $upload) { Remove-Item -LiteralPath $upload -Force }",
        "}",
    ])


def parse_output(output: bytes, *, expected_sha: str, expected_files: int) -> dict:
    result = json.loads(output.decode("utf-8-sig").strip())
    if not isinstance(result, dict) or result.get("status") != "deployed" or result.get("deployed_sha") != expected_sha:
        raise ValueError("invalid deployment result")
    if type(result.get("verified_files")) is not int or result["verified_files"] != expected_files:
        raise ValueError("invalid verified file count")
    previous = result.get("previous_sha")
    if previous is not None and previous != "unknown" and not re.fullmatch(r"[0-9a-f]{40,64}", str(previous)):
        raise ValueError("invalid previous SHA")
    if "previous_sha" not in result or "backup_path" not in result:
        raise ValueError("incomplete deployment result")
    if previous is None:
        if result["backup_path"] is not None:
            raise ValueError("unexpected backup without a previous package")
    elif not isinstance(result["backup_path"], str) or not PureWindowsPath(result["backup_path"]).is_absolute():
        raise ValueError("invalid backup path")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-target", required=True, help="administrative SSH alias or user@host")
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--package-path", default=PACKAGE_PATH)
    parser.add_argument("--backup-root", default=BACKUP_ROOT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--dry-run", action="store_true", help="alias for the default JSON plan")
    parser.add_argument("--allow-dirty", action="store_true", help="export only ref; exclude all working-tree edits")
    args = parser.parse_args(argv)
    stage = "validate"
    try:
        validate_destination(args.package_path, args.backup_root)
        with tempfile.TemporaryDirectory(prefix="self-hosted-ci-package-") as temporary:
            archive = Path(temporary) / "package.tar"
            stage = "export"
            sha, manifest = export_package(args.ref, archive, allow_dirty=args.allow_dirty)
            plan = build_plan(args.ssh_target, sha, manifest, args.package_path, args.backup_root)
            result = plan
            if args.apply:
                upload = "self-hosted-ci-package-" + uuid.uuid4().hex + ".tar"
                stage = "upload"
                run(["scp", str(archive), args.ssh_target + ":" + upload])
                encoded = base64.b64encode(remote_script(plan, upload).encode("utf-16le")).decode("ascii")
                stage = "deploy"
                response = run(["ssh", args.ssh_target, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
                stage = "parse_result"
                result = parse_output(response.stdout, expected_sha=sha, expected_files=len(manifest))
            print(json.dumps(result, sort_keys=True))
        return 0
    except subprocess.CalledProcessError as error:
        stderr = error.stderr or b""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        print(json.dumps({"status": "error", "error": "subprocess failed", "stage": stage,
                          "command": Path(error.cmd[0]).name, "returncode": error.returncode,
                          "stderr": stderr[:4096]}), file=sys.stderr)
        return 1
    except (ValueError, OSError, tarfile.TarError) as error:
        print(json.dumps({"status": "error", "stage": stage, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
