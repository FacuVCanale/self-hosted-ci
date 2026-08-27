#!/usr/bin/env python3
"""Outbound terminal monitor for one already-dispatched non-gating JIT pilot."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

from github_automation.jit_pilot import JitPilotError, PilotTerminalMonitor
from github_automation.worker_authority import (
    HTTPResponse, RootPrivateKeySigner, WorkerAppAuthorityV1,
    WorkerAuthorityError, WorkerGitHubClient,
)


CONFIG = Path("/etc/self-hosted-ci/worker-app-authority.json")
BROKER = Path("/usr/local/lib/self-hosted-ci/garm-allocation-broker.py")


def root_json(path: Path) -> dict:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 65_536:
        raise JitPilotError("unsafe pilot monitor configuration")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise JitPilotError("pilot monitor configuration must be an object")
    return value


class UrllibTransport:
    def request(self, method, url, *, headers, json_body=None):
        body = None if json_body is None else json.dumps(json_body, sort_keys=True, separators=(",", ":")).encode()
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return HTTPResponse(response.status, response.read(1_048_577))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise JitPilotError("pilot GitHub observation failed") from exc


class Observer:
    def __init__(self, client, token): self.client, self.token = client, token
    def _call(self, method, run_id):
        try:
            return method(run_id, self.token)
        except WorkerAuthorityError:
            self.token = self.client.authenticate()
            return method(run_id, self.token)
    def run(self, run_id): return self._call(self.client.run, run_id)
    def jobs(self, run_id): return self._call(self.client.jobs, run_id)


class Broker:
    def __init__(self, runner_label: str):
        self.runner_label = runner_label

    def finish(self, allocation_id: str, outcome: str) -> None:
        completed = subprocess.run(
            [str(BROKER), "finish", "--allocation-id", allocation_id, "--outcome", outcome],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=300, check=False,
        )
        if completed.returncode:
            raise JitPilotError("pilot broker finish failed")
        try:
            receipt = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise JitPilotError("pilot broker finish receipt is invalid") from exc
        if receipt != {"allocation_id": allocation_id, "runner_label": self.runner_label, "state": "cleaned"}:
            raise JitPilotError("pilot broker finish receipt is not exact")

    def prove_clean(self, allocation_id: str, runner_label: str):
        completed = subprocess.run(
            [str(BROKER), "prove-clean", "--allocation-id", allocation_id, "--runner-label", runner_label],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=300, check=False,
        )
        if completed.returncode:
            raise JitPilotError("pilot broker cleanup proof failed")
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise JitPilotError("pilot broker cleanup proof is invalid") from exc
        return value


def load_client():
    config = root_json(CONFIG)
    expected = {
        "schema_version", "app_id", "app_slug", "installation_id", "repository",
        "repository_id", "repository_selection", "default_branch", "workflow_id",
        "workflow_path", "permissions", "private_key_file",
    }
    if set(config) != expected or config.pop("schema_version") != 1:
        raise JitPilotError("pilot worker App config fields are not exact")
    private_key = config.pop("private_key_file")
    if not isinstance(private_key, str) or not private_key.startswith("/etc/self-hosted-ci/secrets/") or ".." in Path(private_key).parts:
        raise JitPilotError("pilot worker App private key path is unsafe")
    authority = WorkerAppAuthorityV1(**config)
    client = WorkerGitHubClient(authority, RootPrivateKeySigner.from_file(Path(private_key)), UrllibTransport())
    return client, client.authenticate()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allocation-id", required=True)
    parser.add_argument("--runner-label", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--job-id", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise JitPilotError("pilot terminal monitor must run as root")
        client, token = load_client()
        PilotTerminalMonitor(Observer(client, token), Broker(args.runner_label), time.sleep, time.monotonic).monitor(
            allocation_id=args.allocation_id, runner_label=args.runner_label,
            run_id=args.run_id, job_id=args.job_id,
        )
        return 0
    except (JitPilotError, WorkerAuthorityError, OSError, ValueError, subprocess.TimeoutExpired):
        print("JIT pilot terminal monitor blocked", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
