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
from github_automation.pr_autodispatch import AutoDispatchError, OpenPullRequest, plan
from github_automation.pilot_checks import (
    GateAppAuthorityV1,
    GateCheckClient,
    PilotCheckPublisher,
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

    def stream(self, url, *, headers, chunk_size=1 << 20):
        """Yield a redirect-followed response body in bounded chunks.

        Job logs are plain text far larger than any JSON this worker reads, and
        the phase evidence lives at the end, so they must never be truncated to
        the JSON bound. Nothing is parsed here; the caller scans for markers.
        """
        request = Request(url, headers=dict(headers), method="GET")
        with urlopen(
            request, timeout=self.timeout, context=ssl.create_default_context()
        ) as response:
            if response.status != 200:
                raise WorkerAuthorityError("worker GitHub log transport failed")
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    return
                yield chunk


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
        "authority_kind",
        "runner_group",
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
        or set(value) - {"gate", "auto_dispatch"} != required
        or value["schema_version"] != 1
        or value["mode"] not in {"ci-jit-pilot", "ci-gate-full"}
    ):
        raise LocalApprovalError("outbound worker config fields are not exact")
    if (
        value["authority_kind"] == "personal-repository"
        and value["runner_group"] is not None
    ) or (
        value["authority_kind"] == "organization-runner-group"
        and (
            not isinstance(value["runner_group"], str)
            or value["runner_group"] != value["runner_group"].strip()
            or not 1 <= len(value["runner_group"]) <= 100
            or "*" in value["runner_group"]
            or "\r" in value["runner_group"]
            or "\n" in value["runner_group"]
        )
    ):
        raise LocalApprovalError("outbound worker runner authority is invalid")
    if value["authority_kind"] not in {
        "personal-repository",
        "organization-runner-group",
    }:
        raise LocalApprovalError("outbound worker authority kind is invalid")
    gate = value.get("gate")
    if gate is not None and (
        not isinstance(gate, dict)
        or set(gate) != {"app_id", "app_slug", "installation_id", "private_key_file"}
        or any(
            isinstance(gate[field], bool)
            or not isinstance(gate[field], int)
            or gate[field] < 1
            for field in ("app_id", "installation_id")
        )
        or not isinstance(gate["app_slug"], str)
        or not isinstance(gate["private_key_file"], str)
        or gate["app_id"] == value["app_id"]
        or gate["private_key_file"] == value["github_app_private_key_file"]
    ):
        raise LocalApprovalError("outbound worker gate block is invalid")
    auto = value.get("auto_dispatch")
    if auto is not None and (
        not isinstance(auto, dict)
        or set(auto) != {"enabled", "poll_seconds"}
        or not isinstance(auto["enabled"], bool)
        or isinstance(auto["poll_seconds"], bool)
        or not isinstance(auto["poll_seconds"], int)
        or not 15 <= auto["poll_seconds"] <= 3600
    ):
        raise LocalApprovalError("outbound worker auto_dispatch block is invalid")
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
        PilotWorkRequestBuilder(
            c["image_fingerprint"],
            authority_kind=c["authority_kind"],
            runner_group=c["runner_group"],
        )
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
    checks = _gate_publisher(c, client)
    auto = c.get("auto_dispatch")
    dispatcher = (
        AutoDispatcher(client, source, c["repository"])
        if isinstance(auto, dict) and auto.get("enabled")
        else None
    )
    worker = (
        PilotWorker(
            state, source, broker, github, signer,
            checks=checks, repository=c["repository"],
        )
        if c["mode"] == "ci-jit-pilot"
        else OutboundWorker(state, source, broker, github, signer)
    )
    return c, source, worker


class AutoDispatcher:
    """Poll the exact repository and keep approvals aligned with its open PRs.

    This is the only automatic entry point into the control plane, and it is a
    poll: nothing listens, nothing is relayed, and its authority is the same
    selected-repository App the worker already holds. It never widens beyond the
    one configured repository and never cancels a different pull request's work.
    """

    def __init__(self, client, source, repository):
        self.client = client
        self.source = source
        self.repository = repository

    def reconcile_once(self):
        token = self.client.authenticate()
        listed = self.client.open_pull_requests(token)
        actions = plan(
            open_pull_requests=[
                OpenPullRequest(number, head) for number, head in listed
            ],
            approvals=self.source.status(self.repository),
        )
        applied = []
        for action in actions:
            try:
                if action.kind == "revoke":
                    self.source.revoke(self.repository, action.pr_number)
                else:
                    self.source.approve(self.repository, action.pr_number)
            except LocalApprovalError as exc:
                # One unapprovable pull request must never stop the others.
                applied.append({
                    "pr": action.pr_number, "kind": action.kind,
                    "result": "blocked", "code": type(exc).__name__,
                })
                continue
            applied.append({
                "pr": action.pr_number, "kind": action.kind,
                "head_sha": action.head_sha, "reason": action.reason,
            })
        return {
            "open_pull_requests": len(listed),
            "actions": applied,
        }


def _gate_publisher(c, dispatch_client):
    """Build the Check Run publisher, or None when no gate App is configured.

    The gate App holds `checks:write` and nothing else; the job log it reasons
    over is fetched with the dispatcher's own `actions` authority, so neither
    identity gains a capability the other has.
    """
    gate = c.get("gate")
    if gate is None:
        return None
    authority = GateAppAuthorityV1(
        gate["app_id"],
        gate["app_slug"],
        gate["installation_id"],
        c["repository"],
        c["repository_id"],
        "selected",
        {"checks": "write", "metadata": "read"},
    )
    transport = HTTPS(c["request_timeout_seconds"])
    client = GateCheckClient(
        authority, RootPrivateKeySigner.from_file(Path(gate["private_key_file"])),
        transport,
    )

    def job_log(job_id):
        token = dispatch_client.authenticate()
        url = (
            f"https://api.github.com/repos/{c['repository']}"
            f"/actions/jobs/{int(job_id)}/logs"
        )
        return transport.stream(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token.value}",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "self-hosted-ci-gate/1",
            },
        )

    return PilotCheckPublisher(client, job_log)


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
    sub.add_parser("auto-once")
    sub.add_parser("serve")
    a = p.parse_args(argv)
    if a.command == "plan":
        print(
            json.dumps(
                {
                    "mode": "plan",
                    "inbound_listener": False,
                    "external_relay": False,
                    "automatic_pr_polling": "opt-in-outbound-poll-of-one-repository",
                    "authority": "selected-repository-github-app-plus-local-authority-v1",
                    "approval": "operator-explicit",
                    "pull_request_checks": "gate-app-when-configured",
                },
                sort_keys=True,
            )
        )
        return 0
    try:
        c, source, worker, dispatcher = runtime(a.config)
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
        elif a.command == "auto-once":
            if dispatcher is None:
                raise LocalApprovalError("automatic dispatch is not enabled")
            source.recover_claims()
            value = dispatcher.reconcile_once()
        else:
            worker.state.recover_running()
            source.recover_claims()
            auto_interval = (
                c["auto_dispatch"]["poll_seconds"] if dispatcher is not None else 0
            )
            next_auto = 0.0
            while True:
                source.recover_claims()
                if dispatcher is not None and time.monotonic() >= next_auto:
                    # A polling failure must never stop the worker loop that is
                    # already carrying an approved run to its conclusion.
                    try:
                        dispatcher.reconcile_once()
                    except (
                        LocalApprovalError,
                        AutoDispatchError,
                        WorkerAuthorityError,
                        OSError,
                    ) as exc:
                        print(
                            f"automatic dispatch poll skipped: {type(exc).__name__}",
                            file=sys.stderr,
                        )
                    next_auto = time.monotonic() + auto_interval
                worker.run_once()
                time.sleep(c["poll_seconds"])
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        AutoDispatchError,
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
