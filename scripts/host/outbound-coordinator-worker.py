#!/usr/bin/env python3
"""Operator-scoped outbound worker: no polling fan-out, ingress, or relay."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import stat
import sys
import time
from datetime import timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

repo_root = Path(__file__).resolve().parents[2]
if (repo_root / "github_automation").is_dir():
    sys.path.insert(0, str(repo_root))
from github_automation.gatestore import GateStore
from github_automation.github import ObservedWorkflowJob
from github_automation.local_approval import (
    ExternalAuthorityBuilder,
    LocalApprovalError,
    LocalApprovalStore,
    PilotWorkRequestBuilder,
    WorkerAuthorityResolver,
)
from github_automation.outbound_worker import (
    FileAllocationSigner,
    LocalBrokerCli,
    OutboundWorker,
    PilotWorker,
    WorkerError,
    WorkerState,
)
from github_automation.worker_authority import (
    HTTPResponse,
    RootPrivateKeySigner,
    WorkerAppAuthorityV1,
    WorkerAuthorityError,
    WorkerGitHubClient,
)


class HTTPS:
    def __init__(self, timeout):
        self.timeout = timeout

    def request(self, method, url, *, headers, json_body=None):
        data = (
            None
            if json_body is None
            else json.dumps(json_body, sort_keys=True, separators=(",", ":")).encode()
        )
        request = Request(
            url,
            data=data,
            headers={
                **headers,
                **({"Content-Type": "application/json"} if data else {}),
            },
            method=method,
        )
        try:
            with urlopen(
                request, timeout=self.timeout, context=ssl.create_default_context()
            ) as response:
                return HTTPResponse(response.status, response.read(1_048_577))
        except HTTPError as exc:
            return HTTPResponse(exc.code, exc.read(1_048_577))
        except (URLError, TimeoutError, OSError) as exc:
            raise WorkerAuthorityError("worker GitHub transport failed") from exc


def root_config(path: Path):
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 65536
    ):
        raise LocalApprovalError(
            "outbound worker config must be root-owned regular 0600"
        )
    value = json.loads(path.read_text())
    required = {
        "schema_version",
        "mode",
        "app_id",
        "app_slug",
        "installation_id",
        "repository",
        "repository_id",
        "repository_selection",
        "default_branch",
        "workflow_id",
        "workflow_path",
        "permissions",
        "github_app_private_key_file",
        "authority_helper_file",
        "authority_manifest_file",
        "authority_signer_key_file",
        "allocation_signer_key_file",
        "image_fingerprint",
        "gatestore_file",
        "approval_store_file",
        "worker_state_file",
        "broker_executable",
        "approval_ttl_seconds",
        "poll_seconds",
        "request_timeout_seconds",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value["schema_version"] != 1
        or value["mode"] not in {"ci-jit-pilot", "ci-gate-full"}
    ):
        raise LocalApprovalError("outbound worker config fields are not exact")
    return value


def runtime(config_path):
    c = root_config(Path(config_path))
    authority = WorkerAppAuthorityV1(
        c["app_id"],
        c["app_slug"],
        c["installation_id"],
        c["repository"],
        c["repository_id"],
        c["repository_selection"],
        c["default_branch"],
        c["workflow_id"],
        c["workflow_path"],
        c["permissions"],
    )
    client = WorkerGitHubClient(
        authority,
        RootPrivateKeySigner.from_file(Path(c["github_app_private_key_file"])),
        HTTPS(c["request_timeout_seconds"]),
    )
    builder = (
        PilotWorkRequestBuilder(c["image_fingerprint"])
        if c["mode"] == "ci-jit-pilot"
        else ExternalAuthorityBuilder(
            Path(c["authority_helper_file"]),
            Path(c["authority_manifest_file"]),
            Path(c["authority_signer_key_file"]),
        )
    )
    source = LocalApprovalStore(
        Path(c["approval_store_file"]),
        GateStore(c["gatestore_file"]),
        WorkerAuthorityResolver(client),
        builder,
        ttl=timedelta(seconds=c["approval_ttl_seconds"]),
    )

    class GitHub:
        def dispatch_package(self, package):
            self.package = package
            encoded = json.dumps(package, sort_keys=True, separators=(",", ":"))
            token = client.authenticate()
            return (
                client.dispatch_pilot(encoded, token)
                if "jit_pilot_package_version" in package
                else client.dispatch(encoded, token)
            )

        def observe_exact_job(self, run_id, label):
            request = source.current_request
            if request is None:
                raise LocalApprovalError("claimed approval context is absent")
            reservation = request["reservation"]
            deadline = time.monotonic() + c["request_timeout_seconds"]
            while True:
                token = client.authenticate()
                run = client.run(run_id, token)
                job_response = client.jobs(run_id, token)
                jobs = job_response.get("jobs")
                if (
                    run.get("id") not in {None, run_id}
                    or run.get("path") != authority.workflow_path
                    or run.get("event") != "workflow_dispatch"
                ):
                    raise LocalApprovalError("workflow run crossed approved workflow")
                if not isinstance(jobs, list):
                    raise LocalApprovalError("workflow jobs response is invalid")
                matches = [
                    job
                    for job in jobs
                    if isinstance(job, dict)
                    and job.get("run_id") in {None, run_id}
                    and job.get("name") == reservation["job_name"]
                    and isinstance(job.get("labels"), list)
                    and label in job["labels"]
                ]
                if len(matches) > 1:
                    raise LocalApprovalError("exact approved workflow job is ambiguous")
                if len(matches) == 1:
                    job = matches[0]
                    status = job.get("status")
                    conclusion = job.get("conclusion")
                    if status not in {"queued", "in_progress", "completed"} or (
                        status != "completed" and conclusion is not None
                    ):
                        raise LocalApprovalError(
                            "workflow job receipt has an invalid state"
                        )
                    attempt = run.get("run_attempt")
                    if (
                        isinstance(attempt, bool)
                        or not isinstance(attempt, int)
                        or attempt < 1
                        or isinstance(job.get("id"), bool)
                        or not isinstance(job.get("id"), int)
                        or job["id"] < 1
                    ):
                        raise LocalApprovalError("workflow job receipt is invalid")
                    dispatch_sha = run.get("head_sha")
                    if not isinstance(dispatch_sha, str) or not re.fullmatch(
                        r"[0-9a-f]{40}", dispatch_sha
                    ):
                        raise LocalApprovalError("workflow dispatch SHA is invalid")
                    return ObservedWorkflowJob(
                        run_id, attempt, job["id"], job["name"], dispatch_sha
                    )
                if time.monotonic() >= deadline:
                    raise LocalApprovalError(
                        "exact approved workflow job observation timed out"
                    )
                time.sleep(min(1, c["request_timeout_seconds"]))

        def run(self, run_id):
            return client.run(run_id, client.authenticate())

        def jobs(self, run_id):
            return client.jobs(run_id, client.authenticate())

    # GARM may need several minutes to drain an ephemeral GitHub runner after
    # its job reaches terminal. HTTP request timeouts are intentionally short,
    # but cleanup is a separate bounded transaction and must not be killed at
    # 30 seconds while resources still exist.
    broker = LocalBrokerCli(
        Path(c["broker_executable"]), max(1200, c["request_timeout_seconds"])
    )
    github = GitHub()
    state = WorkerState(Path(c["worker_state_file"]))
    signer = FileAllocationSigner(Path(c["allocation_signer_key_file"]))
    worker = (
        PilotWorker(state, source, broker, github, signer)
        if c["mode"] == "ci-jit-pilot"
        else OutboundWorker(state, source, broker, github, signer)
    )
    return c, source, worker


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="/etc/self-hosted-ci/outbound-worker.json")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    approve = sub.add_parser("approve")
    approve.add_argument("--repository", required=True)
    approve.add_argument("--pr", required=True, type=int)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--repository", required=True)
    revoke.add_argument("--pr", required=True, type=int)
    status = sub.add_parser("status")
    status.add_argument("--repository")
    status.add_argument("--pr", type=int)
    sub.add_parser("run-once")
    sub.add_parser("serve")
    a = p.parse_args(argv)
    if a.command == "plan":
        print(
            json.dumps(
                {
                    "mode": "plan",
                    "inbound_listener": False,
                    "external_relay": False,
                    "automatic_pr_polling": False,
                    "authority": "selected-repository-github-app-plus-local-authority-v1",
                    "approval": "operator-explicit",
                },
                sort_keys=True,
            )
        )
        return 0
    try:
        c, source, worker = runtime(a.config)
        if a.command == "approve":
            value = source.approve(a.repository, a.pr)
        elif a.command == "revoke":
            value = source.revoke(a.repository, a.pr)
        elif a.command == "status":
            value = {"approvals": source.status(a.repository, a.pr)}
        elif a.command == "run-once":
            worker.state.recover_running()
            source.recover_claims()
            value = worker.run_once()
        else:
            worker.state.recover_running()
            source.recover_claims()
            while True:
                source.recover_claims()
                worker.run_once()
                time.sleep(c["poll_seconds"])
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        LocalApprovalError,
        WorkerAuthorityError,
        WorkerError,
        ValueError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"outbound worker blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
