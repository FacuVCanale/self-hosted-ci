"""Fail-closed runtime for the isolated pre-production JIT canary lane.

The canary lane is deliberately separate from the production activation path.
It may contact GitHub and create transient registrations only while a short-
lived signed authorization is valid; it never creates either production
activation sentinel.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .canary_boundary import authorization_digest, verify_canary_authorization
from .crypto import canonicalize_jcs
from .outbound_worker import FileAllocationSigner
from .runner_jit import allocation_scale_set_name
from .runner_jit_broker import AllocationBroker, JobStartedContext, utc_now
from .timing import POLICY_V1
from .worker_authority import (
    API_ROOT,
    API_VERSION,
    HTTPResponse,
    RootPrivateKeySigner,
    WorkerAppAuthorityV1,
    WorkerGitHubClient,
)


SCENARIOS = ("success", "failure", "cancel", "timeout", "force-cancel", "reboot")
CANARY_JOB_NAME = "local-canary"
CANARY_JOB_TIMEOUT_SECONDS = 180
NORMAL_CANCEL_GRACE_SECONDS = int(POLICY_V1.normal_cancel_grace.total_seconds())
CANARY_UNITS = (
    "self-hosted-ci-canary-network-policy.service",
    "self-hosted-ci-canary-egress-proxy.service",
    "self-hosted-ci-canary-garm.service",
    "self-hosted-ci-canary-broker.service",
)
PRODUCTION_UNITS = (
    "self-hosted-ci-outbound-worker.service",
    "self-hosted-ci-allocation-broker.service",
    "self-hosted-ci-garm.service",
    "self-hosted-ci-egress-proxy.service",
    "self-hosted-ci-network-policy.service",
)
ACTIVATION_SENTINEL = Path("/etc/self-hosted-ci/ACTIVATION_APPROVED")
RUNTIME_READY_SENTINEL = Path("/etc/self-hosted-ci/outbound-worker.runtime-ready")
CANARY_SENTINEL = Path("/run/self-hosted-ci/CANARY_APPROVED")
CANARY_SECRET_ROOT = Path("/run/self-hosted-ci/canary-secrets")
STATE_ROOT = Path("/var/lib/self-hosted-ci/canary")
LOCK_PATH = Path("/run/self-hosted-ci-garm-jit.lock")
_NONCE = re.compile(r"[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_DISTRO_BOOT_IDENTITY_V2 = re.compile(
    rf"v2:{_UUID.pattern}:[0-9]+"
)
PROOF_FIELDS = {
    "authorization_digest", "nonce", "scenario", "allocation_id", "scale_set_id",
    "scale_set_name", "run_id", "run_attempt", "job_id", "runner_name",
    "repository", "repository_id", "dispatch_sha", "head_sha", "tested_merge_sha",
    "image_fingerprint", "network_policy_digest", "github_app_config_digest",
    "allocation_signer_fingerprint", "reserved_at", "started_at", "finished_at",
    "jobs_started", "conclusion", "normal_cancel_receipt", "force_cancel_receipt",
    "cleanup_record", "garm_inventory_post", "incus_inventory_post",
    "github_inventory_post", "proof_digest",
}


class CanaryRuntimeError(RuntimeError):
    pass


class CanaryRebootRequired(CanaryRuntimeError):
    def __init__(self, allocation_id: str, runner_label: str, evidence: Mapping[str, Any]):
        super().__init__("canary WSL reboot checkpoint is durable")
        self.allocation_id = allocation_id
        self.runner_label = runner_label
        self.evidence = dict(evidence)


class CanaryScenarioDriver(Protocol):
    def run(self, scenario: str) -> Mapping[str, Any]: ...

    def recover_all(self) -> Sequence[str]: ...

    def prove_runtime_empty(self) -> Mapping[str, Any]: ...

    def resume_reboot(
        self, allocation_id: str, runner_label: str, evidence: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


class CanaryDispatchAdapter(Protocol):
    """Narrow GitHub lane; it has no production check or activation methods."""

    def reservation(self, scenario: str) -> Mapping[str, Any]: ...

    def dispatch_and_observe(
        self, scenario: str, runner_label: str
    ) -> tuple[Mapping[str, Any], JobStartedContext]: ...

    def await_terminal(self, scenario: str, context: JobStartedContext) -> str: ...

    def await_runner_claim(
        self, broker: AllocationBroker, allocation_id: str, context: JobStartedContext
    ) -> None: ...

    def reboot_host(self, allocation_id: str) -> None: ...

    def proof_evidence(self, runner_label: str) -> Mapping[str, Any]: ...

    def github_inventory(self, runner_label: str) -> Mapping[str, Any]: ...

    def transient_github_inventory(self) -> Mapping[str, Any]: ...

    def resume_reboot_evidence(
        self, evidence: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(self, argv: Sequence[str], *, timeout: int = 60) -> CommandResult:
        result = subprocess.run(
            list(argv), capture_output=True, text=True, check=False, timeout=timeout
        )
        return CommandResult(result.returncode, result.stdout, result.stderr)


class _HTTPS:
    def __init__(self, timeout: int):
        self.timeout = timeout

    def request(self, method, url, *, headers, json_body=None) -> HTTPResponse:
        data = (
            None
            if json_body is None
            else json.dumps(json_body, sort_keys=True, separators=(",", ":")).encode()
        )
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                **headers,
                **({"Content-Type": "application/json"} if data else {}),
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=ssl.create_default_context()
            ) as response:
                return HTTPResponse(response.status, response.read(1_048_577))
        except urllib.error.HTTPError as exc:
            return HTTPResponse(exc.code, exc.read(1_048_577))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CanaryRuntimeError("canary GitHub transport failed") from exc


class LiveCanaryDispatchAdapter:
    """Selected-repository GitHub App adapter for the six canary scenarios."""

    def __init__(
        self,
        authorization: Mapping[str, Any],
        app_config: Mapping[str, Any],
        signer: FileAllocationSigner,
        *,
        timeout_seconds: int,
        transport: Any | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        expected_app_fields = {
            "schema_version",
            "purpose",
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
            "private_key_file",
        }
        if (
            set(app_config) != expected_app_fields
            or app_config.get("schema_version") != 1
            or app_config.get("purpose") != "workflow-dispatch"
        ):
            raise CanaryRuntimeError("canary GitHub App config fields are not exact")
        if (
            app_config["repository"] != authorization["repository"]
            or app_config["repository_id"] != authorization["repository_id"]
            or app_config["workflow_id"] != "ci-jit-canary-child.yml"
            or app_config["workflow_path"]
            != ".github/workflows/ci-jit-canary-child.yml"
        ):
            raise CanaryRuntimeError("canary GitHub App authority crossed authorization")
        self.authorization = authorization
        self.signer = signer
        self.timeout_seconds = timeout_seconds
        self.sleeper = sleeper
        self.monotonic = monotonic
        self.transport = transport or _HTTPS(timeout_seconds)
        self.authority = WorkerAppAuthorityV1(
            app_config["app_id"],
            app_config["app_slug"],
            app_config["installation_id"],
            app_config["repository"],
            app_config["repository_id"],
            app_config["repository_selection"],
            app_config["default_branch"],
            app_config["workflow_id"],
            app_config["workflow_path"],
            app_config["permissions"],
        )
        self.client = WorkerGitHubClient(
            self.authority,
            RootPrivateKeySigner.from_file(Path(app_config["private_key_file"])),
            self.transport,
        )
        self._scenario: str | None = None
        self._reservation: Mapping[str, Any] | None = None
        self._run_id: int | None = None
        self._observed: dict[str, Any] = {}
        self._normal_cancel_receipt: Mapping[str, Any] | None = None
        self._force_cancel_receipt: Mapping[str, Any] | None = None

    @staticmethod
    def _stamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )

    @staticmethod
    def _live_stamp(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise CanaryRuntimeError(f"canary GitHub {field} timestamp is absent")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise CanaryRuntimeError(
                f"canary GitHub {field} timestamp is invalid"
            ) from exc
        if parsed.tzinfo is None:
            raise CanaryRuntimeError(f"canary GitHub {field} timestamp is invalid")
        return value

    def reservation(self, scenario: str) -> Mapping[str, Any]:
        if scenario not in SCENARIOS or self._reservation is not None:
            raise CanaryRuntimeError("canary allocations must be sequential and unique")
        now = datetime.now(timezone.utc)
        expires = min(
            now + timedelta(minutes=5),
            datetime.fromisoformat(self.authorization["expires_at"][:-1] + "+00:00"),
        )
        if expires <= now:
            raise CanaryRuntimeError("canary authorization expired before reservation")
        entity = self.authorization["garm_entity"]
        value = {
            "allocation_reservation_version": 1,
            "allocation_id": str(uuid4()),
            "repository_id": str(self.authorization["repository_id"]),
            "repository": self.authorization["repository"],
            "head_sha": self.authorization["head_sha"],
            "workflow_ref": self.authorization["workflow_ref"],
            "job_name": CANARY_JOB_NAME,
            "authority_kind": entity["authority_kind"],
            "runner_group": entity["runner_group"],
            "scale_set_name": "",
            "labels": [],
            "image_fingerprint": self.authorization["image_fingerprint"],
            "nonce": __import__("secrets").token_urlsafe(32),
            "issued_at": self._stamp(now),
            "expires_at": self._stamp(expires),
            "max_jobs": 1,
            "ephemeral": True,
        }
        value["scale_set_name"] = allocation_scale_set_name(value)
        value["labels"] = [value["scale_set_name"]]
        self._scenario = scenario
        self._reservation = value
        return value

    def _token_headers(self, token: Any) -> Mapping[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token.value}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "self-hosted-ci-canary/1",
        }

    def _post(self, path: str, token: Any, body: Mapping[str, Any] | None = None) -> HTTPResponse:
        response = self.transport.request(
            "POST", API_ROOT + path, headers=self._token_headers(token), json_body=body
        )
        return response

    def _receipt(self, operation_id: str, response: HTTPResponse) -> Mapping[str, Any]:
        observed_at = self._stamp(datetime.now(timezone.utc))
        core = {
            "operation_id": operation_id,
            "observed_at": observed_at,
            "status": response.status,
            "body_sha256": hashlib.sha256(response.body).hexdigest(),
        }
        return {
            "operation_id": operation_id,
            "observed_at": observed_at,
            "receipt_digest": hashlib.sha256(canonicalize_jcs(core)).hexdigest(),
        }

    def _revalidate_target(self, token: Any) -> None:
        repository = self.client.repository(token)
        pull = self.client.pull_request(self.authorization["pull_request"], token)
        workflow = self.client.workflow(token)
        if (
            repository.get("id") != self.authorization["repository_id"]
            or repository.get("full_name") != self.authorization["repository"]
            or pull.get("number") != self.authorization["pull_request"]
            or pull.get("state") != "open"
            or pull.get("head", {}).get("sha") != self.authorization["head_sha"]
            or pull.get("base", {}).get("sha") != self.authorization["base_sha"]
            or pull.get("merge_commit_sha")
            not in (None, self.authorization["tested_merge_sha"])
            or workflow.get("path") != self.authority.workflow_path
            or workflow.get("state") != "active"
        ):
            raise CanaryRuntimeError("live GitHub canary target crossed authorization")

    def dispatch_and_observe(
        self, scenario: str, runner_label: str
    ) -> tuple[Mapping[str, Any], JobStartedContext]:
        if scenario != self._scenario or self._reservation is None:
            raise CanaryRuntimeError("canary dispatch crossed reservation")
        token = self.client.authenticate()
        self._revalidate_target(token)
        package = {
            "canary_package_version": 1,
            "scenario": scenario,
            "authorization": self.authorization,
            "runner_label": runner_label,
        }
        response = self._post(
            f"/repos/{self.authority.repository}/actions/workflows/{self.authority.workflow_id}/dispatches",
            token,
            {
                "ref": self.authority.default_branch,
                "inputs": {
                    "canary_package": json.dumps(
                        package, sort_keys=True, separators=(",", ":")
                    )
                },
                "return_run_details": True,
            },
        )
        try:
            receipt = json.loads(response.body or b"{}")
        except json.JSONDecodeError as exc:
            raise CanaryRuntimeError("canary dispatch receipt is invalid") from exc
        run_id = receipt.get("workflow_run_id")
        if response.status != 200 or type(run_id) is not int or run_id < 1:
            raise CanaryRuntimeError("canary dispatch was not acknowledged exactly")
        self._run_id = run_id
        deadline = self.monotonic() + self.timeout_seconds
        while True:
            token = self.client.authenticate()
            run = self.client.run(run_id, token)
            jobs = self.client.jobs(run_id, token).get("jobs")
            if (
                run.get("path") != self.authority.workflow_path
                or run.get("event") != "workflow_dispatch"
                or run.get("head_sha") != self.authorization["dispatch_sha"]
            ):
                raise CanaryRuntimeError("canary run crossed workflow or dispatch SHA")
            matches = [
                job
                for job in jobs or []
                if isinstance(job, Mapping)
                and job.get("name") == CANARY_JOB_NAME
                and runner_label in job.get("labels", [])
            ]
            if len(matches) == 1:
                job = matches[0]
                attempt = run.get("run_attempt")
                if type(job.get("id")) is not int or type(attempt) is not int:
                    raise CanaryRuntimeError("canary job receipt is invalid")
                payload = dict(self._reservation)
                payload.pop("allocation_reservation_version")
                payload.update(
                    runner_allocation_version=1,
                    run_id=str(run_id),
                    run_attempt=attempt,
                    job_id=str(job["id"]),
                    dispatch_sha=self.authorization["dispatch_sha"],
                    tested_sha=self.authorization["tested_merge_sha"],
                )
                context = JobStartedContext.from_mapping(
                    {
                        "repository_id": payload["repository_id"],
                        "repository": payload["repository"],
                        "dispatch_sha": payload["dispatch_sha"],
                        "tested_sha": payload["tested_sha"],
                        "workflow_ref": payload["workflow_ref"],
                        "run_id": payload["run_id"],
                        "run_attempt": payload["run_attempt"],
                        "job_name": payload["job_name"],
                        "runner_name": job.get("runner_name") or runner_label,
                        "scale_set_name": runner_label,
                    }
                )
                self._observed = {
                    "run_id": run_id,
                    "run_attempt": attempt,
                    "job_id": job["id"],
                    "runner_name": job.get("runner_name") or runner_label,
                }
                return self.signer.sign_allocation(payload), context
            if self.monotonic() >= deadline:
                raise CanaryRuntimeError("canary exact job observation timed out")
            self.sleeper(1)

    def await_runner_claim(
        self, broker: AllocationBroker, allocation_id: str, context: JobStartedContext
    ) -> None:
        deadline = self.monotonic() + self.timeout_seconds
        while True:
            record = broker.ledger.get(allocation_id)
            if record.state == "running" and record.jobs_started == 1:
                jobs = self.client.jobs(self._run_id, self.client.authenticate()).get(
                    "jobs", []
                )
                exact = [
                    job
                    for job in jobs
                    if job.get("id") == self._observed["job_id"]
                ]
                if (
                    len(exact) != 1
                    or not exact[0].get("runner_name")
                    or exact[0].get("status") != "in_progress"
                ):
                    raise CanaryRuntimeError("claimed canary runner identity is absent")
                self._observed["runner_name"] = exact[0]["runner_name"]
                self._observed["started_at"] = self._live_stamp(
                    exact[0].get("started_at"), "job-started"
                )
                self._observed["runner_claimed"] = True
                return
            if record.state not in {"issued", "claimed"}:
                raise CanaryRuntimeError("canary allocation left claimable state")
            if self.monotonic() >= deadline:
                raise CanaryRuntimeError("canary runner claim timed out")
            self.sleeper(1)

    def await_terminal(self, scenario: str, context: JobStartedContext) -> str:
        if self._run_id is None or scenario != self._scenario:
            raise CanaryRuntimeError("canary terminal monitor crossed dispatch")
        token = self.client.authenticate()
        run_path = f"/repos/{self.authority.repository}/actions/runs/{self._run_id}"
        if scenario in {"cancel", "force-cancel"}:
            response = self._post(run_path + "/cancel", token)
            if response.status != 202:
                raise CanaryRuntimeError("normal canary cancellation was rejected")
            self._normal_cancel_receipt = self._receipt(
                f"github-run-{self._run_id}-cancel", response
            )
        if scenario == "force-cancel":
            grace_deadline = self.monotonic() + NORMAL_CANCEL_GRACE_SECONDS
            while True:
                run = self.client.run(self._run_id, self.client.authenticate())
                jobs = self.client.jobs(
                    self._run_id, self.client.authenticate()
                ).get("jobs")
                exact = [
                    job
                    for job in jobs or []
                    if isinstance(job, Mapping)
                    and job.get("id") == self._observed.get("job_id")
                ]
                if (
                    run.get("status") != "in_progress"
                    or len(exact) != 1
                    or exact[0].get("status") != "in_progress"
                    or exact[0].get("runner_name") != self._observed.get("runner_name")
                    or self._live_stamp(exact[0].get("started_at"), "job-started")
                    != self._observed.get("started_at")
                ):
                    raise CanaryRuntimeError(
                        "force-cancel canary did not survive normal cancellation"
                    )
                if self.monotonic() >= grace_deadline:
                    break
                self.sleeper(1)
            response = self._post(run_path + "/force-cancel", self.client.authenticate())
            if response.status != 202:
                raise CanaryRuntimeError("forced canary cancellation was rejected")
            self._force_cancel_receipt = self._receipt(
                f"github-run-{self._run_id}-force-cancel", response
            )
        deadline = self.monotonic() + self.timeout_seconds
        while True:
            run = self.client.run(self._run_id, self.client.authenticate())
            if run.get("status") == "completed":
                jobs = self.client.jobs(
                    self._run_id, self.client.authenticate()
                ).get("jobs")
                if not isinstance(jobs, list):
                    raise CanaryRuntimeError("terminal canary jobs receipt is invalid")
                exact = [
                    job
                    for job in jobs
                    if isinstance(job, Mapping)
                    and job.get("id") == self._observed.get("job_id")
                ]
                if len(exact) > 1:
                    raise CanaryRuntimeError("terminal canary job receipt is ambiguous")
                if not exact or exact[0].get("status") in {"queued", "in_progress"}:
                    if self.monotonic() >= deadline:
                        raise CanaryRuntimeError(
                            "terminal canary job receipt did not converge"
                        )
                    self.sleeper(1)
                    continue
                job = exact[0]
                if job.get("status") != "completed":
                    raise CanaryRuntimeError("terminal canary job receipt is invalid")
                expected_conclusion = {
                    "success": "success",
                    "failure": "failure",
                    "cancel": "cancelled",
                    "force-cancel": "cancelled",
                    "timeout": "cancelled",
                }[scenario]
                if (
                    run.get("conclusion") != expected_conclusion
                    or job.get("conclusion") != expected_conclusion
                ):
                    raise CanaryRuntimeError(
                        f"{scenario} canary terminal conclusion drifted"
                    )
                started_at = self._live_stamp(job.get("started_at"), "job-started")
                finished_at = self._live_stamp(
                    job.get("completed_at"), "job-finished"
                )
                if self._observed.get("started_at") != started_at:
                    raise CanaryRuntimeError("terminal canary job start timestamp drifted")
                if scenario == "timeout":
                    if (
                        self._normal_cancel_receipt is not None
                        or self._force_cancel_receipt is not None
                    ):
                        raise CanaryRuntimeError(
                            "timeout canary has an explicit cancellation receipt"
                        )
                    started = datetime.fromisoformat(started_at[:-1] + "+00:00")
                    finished = datetime.fromisoformat(finished_at[:-1] + "+00:00")
                    if (finished - started).total_seconds() < CANARY_JOB_TIMEOUT_SECONDS:
                        raise CanaryRuntimeError(
                            "timeout canary completed before its job deadline"
                        )
                self._observed["finished_at"] = finished_at
                return scenario
            if self.monotonic() >= deadline:
                raise CanaryRuntimeError("canary terminal monitor timed out")
            self.sleeper(1)

    def reboot_host(self, allocation_id: str) -> None:
        if self._reservation is None:
            raise CanaryRuntimeError("reboot canary has no durable reservation")
        runner_label = self._reservation["scale_set_name"]
        if self._run_id is None:
            raise CanaryRuntimeError("reboot canary has no exact GitHub run")
        response = self._post(
            f"/repos/{self.authority.repository}/actions/runs/{self._run_id}/cancel",
            self.client.authenticate(),
        )
        if response.status != 202:
            raise CanaryRuntimeError("reboot canary queued run cancellation was rejected")
        self._normal_cancel_receipt = self._receipt(
            f"github-run-{self._run_id}-reboot-cancel", response
        )
        raise CanaryRebootRequired(
            allocation_id, runner_label, self.proof_evidence(runner_label)
        )

    def proof_evidence(self, runner_label: str) -> Mapping[str, Any]:
        if self._reservation is None or not self._observed:
            raise CanaryRuntimeError("canary dispatch evidence is incomplete")
        return {
            **self._observed,
            "normal_cancel_receipt": self._normal_cancel_receipt,
            "force_cancel_receipt": self._force_cancel_receipt,
        }

    def _github_runner_inventory(self) -> tuple[list[Mapping[str, Any]], str]:
        runners: list[Mapping[str, Any]] = []
        total_count: int | None = None
        page = 1
        while True:
            response = None
            for attempt in range(5):
                token = self.client.authenticate()
                response = self.transport.request(
                    "GET",
                    API_ROOT
                    + f"/repos/{self.authority.repository}/actions/runners?per_page=100&page={page}",
                    headers=self._token_headers(token),
                )
                if response.status == 200:
                    break
                if attempt == 4:
                    raise CanaryRuntimeError("GitHub runner inventory was rejected")
                self.sleeper(1)
            assert response is not None
            try:
                value = json.loads(response.body)
            except json.JSONDecodeError as exc:
                raise CanaryRuntimeError("GitHub runner inventory is invalid") from exc
            if set(value) != {"total_count", "runners"} or type(
                value.get("total_count")
            ) is not int or not isinstance(value.get("runners"), list):
                raise CanaryRuntimeError("GitHub runner inventory is invalid")
            if total_count is None:
                total_count = value["total_count"]
            elif value["total_count"] != total_count:
                raise CanaryRuntimeError("GitHub runner inventory changed while paging")
            page_runners = value["runners"]
            if any(
                not isinstance(runner, Mapping)
                or type(runner.get("id")) is not int
                for runner in page_runners
            ):
                raise CanaryRuntimeError("GitHub runner inventory is invalid")
            runners.extend(page_runners)
            if len(runners) >= total_count:
                break
            if len(page_runners) != 100 or page > 1000:
                raise CanaryRuntimeError("GitHub runner inventory is truncated")
            page += 1
        if len(runners) != total_count or len({runner["id"] for runner in runners}) != len(
            runners
        ):
            raise CanaryRuntimeError("GitHub runner inventory is truncated or duplicated")
        inventory = {"total_count": total_count, "runners": runners}
        return runners, hashlib.sha256(canonicalize_jcs(inventory)).hexdigest()

    def github_inventory(self, runner_label: str) -> Mapping[str, Any]:
        runners, inventory_digest = self._github_runner_inventory()
        matching = [
            runner
            for runner in runners
            if runner.get("name") == self._observed.get("runner_name")
            or any(label.get("name") == runner_label for label in runner.get("labels", []))
        ]
        if matching:
            raise CanaryRuntimeError("GitHub canary registration survived cleanup")
        result = {
            "remaining": 0,
            "inventory_digest": inventory_digest,
        }
        self._scenario = None
        self._reservation = None
        self._run_id = None
        self._observed = {}
        self._normal_cancel_receipt = None
        self._force_cancel_receipt = None
        return result

    def transient_github_inventory(self) -> Mapping[str, Any]:
        runners, inventory_digest = self._github_runner_inventory()
        transient = [
            runner
            for runner in runners
            if _NONCE.fullmatch(str(runner.get("name", "")).removeprefix("wsl-jit-"))
            or any(
                _NONCE.fullmatch(str(label.get("name", "")).removeprefix("wsl-jit-"))
                for label in runner.get("labels", [])
                if isinstance(label, Mapping)
            )
        ]
        return {"remaining": len(transient), "inventory_digest": inventory_digest}

    def resume_reboot_evidence(
        self, evidence: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        required = {
            "run_id",
            "run_attempt",
            "job_id",
            "runner_name",
            "started_at",
            "runner_claimed",
            "normal_cancel_receipt",
            "force_cancel_receipt",
            "reboot_cancel_receipt",
            "reservation",
            "scale_set_id",
        }
        if set(evidence) != required or evidence.get("runner_claimed") is not True:
            raise CanaryRuntimeError("reboot checkpoint did not prove an active runner")
        self._run_id = evidence["run_id"]
        self._observed = {
            key: evidence[key]
            for key in (
                "run_id",
                "run_attempt",
                "job_id",
                "runner_name",
                "started_at",
                "runner_claimed",
            )
        }
        self._reservation = evidence["reservation"]
        self._normal_cancel_receipt = evidence["normal_cancel_receipt"]
        deadline = self.monotonic() + self.timeout_seconds
        while True:
            run = self.client.run(self._run_id, self.client.authenticate())
            if (
                run.get("head_sha") != self.authorization["dispatch_sha"]
                or run.get("run_attempt") != evidence["run_attempt"]
            ):
                raise CanaryRuntimeError("reboot GitHub run identity drifted")
            jobs = self.client.jobs(self._run_id, self.client.authenticate()).get(
                "jobs", []
            )
            exact = [job for job in jobs if job.get("id") == evidence["job_id"]]
            if len(exact) != 1 or exact[0].get("runner_name") != evidence["runner_name"]:
                raise CanaryRuntimeError("reboot GitHub job identity drifted")
            if run.get("status") == "completed" and exact[0].get("status") == "completed":
                self._observed["finished_at"] = self._live_stamp(
                    exact[0].get("completed_at"), "reboot-job-finished"
                )
                return {
                    **evidence,
                    "finished_at": self._observed["finished_at"],
                }
            if self.monotonic() >= deadline:
                raise CanaryRuntimeError("reboot GitHub cleanup observation timed out")
            self.sleeper(1)


class BrokerCanaryScenarioDriver:
    """Exercise the real AllocationBroker lifecycle with a canary-only dispatcher."""

    def __init__(
        self,
        broker: AllocationBroker,
        dispatch: CanaryDispatchAdapter,
        authorization: Mapping[str, Any],
    ) -> None:
        self.broker = broker
        self.dispatch = dispatch
        self.authorization = authorization

    @staticmethod
    def _stamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )

    def _proof(
        self,
        *,
        scenario: str,
        reservation: Mapping[str, Any],
        scale_set_id: str,
        evidence: Mapping[str, Any],
        jobs_started: int,
        started_at: str | None,
    ) -> Mapping[str, Any]:
        allocation_id = reservation["allocation_id"]
        runner_label = reservation["scale_set_name"]
        record = self.broker.ledger.get(allocation_id)
        measured = self.broker.driver.measure_cleanup(allocation_id, runner_label)
        cleanup = {
            key: measured[key]
            for key in (
                "registration_removed",
                "workspace_removed",
                "token_removed",
                "container_removed",
                "allocation_removed",
            )
        }
        cleanup["cleanup_digest"] = hashlib.sha256(
            canonicalize_jcs(cleanup)
        ).hexdigest()
        self.broker.driver.assert_no_persistent_scale_set()
        self.broker.driver.assert_runtime_empty()
        garm_inventory, incus_inventory = self._measure_runtime_inventories()
        if garm_inventory or incus_inventory:
            raise CanaryRuntimeError("post-cleanup runtime inventory is not empty")
        live_started_at = evidence.get("started_at")
        finished_at = evidence.get("finished_at")
        if (
            not isinstance(live_started_at, str)
            or live_started_at != started_at
            or not isinstance(finished_at, str)
        ):
            raise CanaryRuntimeError("canary live lifecycle timestamps are absent")
        proof = {
            "authorization_digest": authorization_digest(self.authorization),
            "nonce": self.authorization["nonce"],
            "scenario": scenario,
            "allocation_id": allocation_id,
            "scale_set_id": scale_set_id,
            "scale_set_name": runner_label,
            "run_id": evidence["run_id"],
            "run_attempt": evidence["run_attempt"],
            "job_id": evidence["job_id"],
            "runner_name": evidence["runner_name"],
            "repository": self.authorization["repository"],
            "repository_id": self.authorization["repository_id"],
            "dispatch_sha": self.authorization["dispatch_sha"],
            "head_sha": self.authorization["head_sha"],
            "tested_merge_sha": self.authorization["tested_merge_sha"],
            "image_fingerprint": self.authorization["image_fingerprint"],
            "network_policy_digest": self.authorization["network_policy_digest"],
            "github_app_config_digest": self.authorization[
                "github_app_config_digest"
            ],
            "allocation_signer_fingerprint": self.authorization[
                "allocation_signer_fingerprint"
            ],
            "reserved_at": reservation["issued_at"],
            "started_at": started_at,
            "finished_at": finished_at,
            "jobs_started": jobs_started,
            "conclusion": scenario,
            "normal_cancel_receipt": evidence.get("normal_cancel_receipt"),
            "force_cancel_receipt": evidence.get("force_cancel_receipt"),
            "cleanup_record": cleanup,
            "garm_inventory_post": {
                "remaining": len(garm_inventory),
                "inventory_digest": hashlib.sha256(
                    canonicalize_jcs(garm_inventory)
                ).hexdigest(),
            },
            "incus_inventory_post": {
                "remaining": len(incus_inventory),
                "inventory_digest": hashlib.sha256(
                    canonicalize_jcs(incus_inventory)
                ).hexdigest(),
            },
            "github_inventory_post": self.dispatch.github_inventory(runner_label),
        }
        if record.state != "cleaned" or record.jobs_started != jobs_started:
            raise CanaryRuntimeError("canary ledger proof state drifted")
        proof["proof_digest"] = hashlib.sha256(canonicalize_jcs(proof)).hexdigest()
        return proof

    def _measure_runtime_inventories(
        self,
    ) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
        driver = self.broker.driver
        custom = getattr(driver, "canary_runtime_inventory", None)
        if callable(custom):
            value = custom()
            if (
                not isinstance(value, Mapping)
                or set(value) != {"garm", "incus"}
                or not isinstance(value["garm"], list)
                or not isinstance(value["incus"], list)
            ):
                raise CanaryRuntimeError("canary runtime inventory receipt is invalid")
            return value["garm"], value["incus"]
        list_for = getattr(driver, "_list_for", None)
        incus_instances = getattr(driver, "_incus_instances", None)
        config = getattr(driver, "config", None)
        if (
            not callable(list_for)
            or not callable(incus_instances)
            or not isinstance(config, Mapping)
            or not isinstance(config.get("targets"), Mapping)
        ):
            raise CanaryRuntimeError("live runtime inventory is not measurable")
        garm: list[Mapping[str, Any]] = []
        for target_id in sorted(config["targets"]):
            observed = list_for(config["targets"][target_id])
            if not isinstance(observed, list) or any(
                not isinstance(item, Mapping) for item in observed
            ):
                raise CanaryRuntimeError("live GARM inventory is invalid")
            garm.extend(observed)
        incus = incus_instances()
        if not isinstance(incus, list) or any(
            not isinstance(item, Mapping) for item in incus
        ):
            raise CanaryRuntimeError("live Incus inventory is invalid")
        return garm, incus

    def run(self, scenario: str) -> Mapping[str, Any]:
        if scenario not in SCENARIOS:
            raise CanaryRuntimeError("unknown canary scenario")
        reservation = self.dispatch.reservation(scenario)
        reserved = self.broker.reserve(reservation, now=utc_now())
        allocation_id = reserved["allocation_id"]
        runner_label = reserved["runner_label"]
        scale_set_id = reserved["scale_set_id"]
        jobs_started = 0
        started_at: str | None = None
        try:
            if scenario == "reboot":
                envelope, context = self.dispatch.dispatch_and_observe(
                    scenario, runner_label
                )
                finalized = self.broker.finalize(envelope, now=utc_now())
                if finalized.get("state") != "enabled-awaiting-claim":
                    raise CanaryRuntimeError("reboot canary finalize receipt is not exact")
                self.dispatch.await_runner_claim(
                    self.broker, allocation_id, context
                )
                record = self.broker.ledger.get(allocation_id)
                if record.state != "running" or record.jobs_started != 1:
                    raise CanaryRuntimeError("reboot canary runner was not claimed")
                jobs_started = 1
                try:
                    self.dispatch.reboot_host(allocation_id)
                except CanaryRebootRequired:
                    refreshed = dict(self.dispatch.proof_evidence(runner_label))
                    reboot_cancel_receipt = refreshed["normal_cancel_receipt"]
                    if not isinstance(reboot_cancel_receipt, Mapping):
                        raise CanaryRuntimeError(
                            "reboot canary cancellation receipt is absent"
                        )
                    refreshed["normal_cancel_receipt"] = None
                    refreshed["reboot_cancel_receipt"] = reboot_cancel_receipt
                    refreshed["reservation"] = dict(reservation)
                    refreshed["scale_set_id"] = scale_set_id
                    raise CanaryRebootRequired(
                        allocation_id, runner_label, refreshed
                    )
            else:
                envelope, context = self.dispatch.dispatch_and_observe(
                    scenario, runner_label
                )
                finalized = self.broker.finalize(envelope, now=utc_now())
                if (
                    finalized.get("allocation_id") != allocation_id
                    or finalized.get("runner_label") != runner_label
                    or finalized.get("state") != "enabled-awaiting-claim"
                ):
                    raise CanaryRuntimeError("canary finalize receipt is not exact")
                self.dispatch.await_runner_claim(self.broker, allocation_id, context)
                if self.broker.ledger.get(allocation_id).state != "running":
                    raise CanaryRuntimeError("canary runner claim was not persisted")
                jobs_started = 1
                outcome = self.dispatch.await_terminal(scenario, context)
                if outcome != scenario:
                    raise CanaryRuntimeError("canary terminal outcome crossed scenario")
                self.broker.finish(
                    allocation_id,
                    outcome=outcome,
                    normal_cancel_attempted=scenario == "force-cancel",
                )
                evidence = self.dispatch.proof_evidence(runner_label)
                started_at = evidence.get("started_at")
            cleaned = self.broker.prove_clean(allocation_id, runner_label)
            if cleaned != {
                "allocation_id": allocation_id,
                "runner_label": runner_label,
                "state": "cleaned",
                "scale_set_absent": True,
                "runtime_empty": True,
            }:
                raise CanaryRuntimeError("canary broker cleanup proof is not exact")
            return self._proof(
                scenario=scenario,
                reservation=reservation,
                scale_set_id=scale_set_id,
                evidence=evidence,
                jobs_started=jobs_started,
                started_at=started_at,
            )
        except CanaryRebootRequired:
            raise
        except Exception:
            if self.broker.ledger.get(allocation_id).state != "cleaned":
                self.broker.recover(allocation_id)
            raise

    def recover_all(self) -> Sequence[str]:
        return self.broker.recover_all()

    def prove_runtime_empty(self) -> Mapping[str, Any]:
        self.broker.driver.assert_no_persistent_scale_set()
        self.broker.driver.assert_runtime_empty()
        deadline = time.monotonic() + 60
        while True:
            github = self.dispatch.transient_github_inventory()
            if github.get("remaining") == 0:
                break
            if time.monotonic() >= deadline:
                raise CanaryRuntimeError(
                    "GitHub transient runner inventory is not empty"
                )
            time.sleep(2)
        return {
            "scale_sets": 0,
            "instances": 0,
            "runners": 0,
            "registrations": 0,
        }

    def resume_reboot(
        self, allocation_id: str, runner_label: str, evidence: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if self.broker.ledger.get(allocation_id).state != "cleaned":
            recovered = self.broker.recover(allocation_id)
            if recovered != {"allocation_id": allocation_id, "state": "absent"}:
                raise CanaryRuntimeError("reboot recovery receipt is not exact")
        cleaned = self.broker.prove_clean(allocation_id, runner_label)
        if cleaned.get("runtime_empty") is not True:
            raise CanaryRuntimeError("reboot cleanup did not prove empty runtime")
        evidence = self.dispatch.resume_reboot_evidence(evidence)
        return self._proof(
            scenario="reboot",
            reservation=evidence["reservation"],
            scale_set_id=evidence["scale_set_id"],
            evidence=evidence,
            jobs_started=1,
            started_at=evidence["started_at"],
        )


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path: Path, maximum_size: int = 1_048_576) -> str:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 1
        or info.st_size > maximum_size
    ):
        raise CanaryRuntimeError(f"unsafe canary input: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, maximum_size: int = 131072) -> Mapping[str, Any]:
    _sha256_file(path, maximum_size)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryRuntimeError(f"invalid canary JSON: {path}") from exc
    if not isinstance(value, dict):
        raise CanaryRuntimeError(f"canary JSON is not an object: {path}")
    return value


def read_root_json(path: Path, maximum_size: int = 131072) -> Mapping[str, Any]:
    info = os.lstat(path)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise CanaryRuntimeError(f"canary root JSON permissions are unsafe: {path}")
    return _read_json(path, maximum_size)


def _atomic_json(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise CanaryRuntimeError("canary state parent is a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(_canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class CanaryStateStore:
    """Content-bound durable state and proof storage for one authorization nonce."""

    def __init__(self, root: Path, nonce: str):
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise CanaryRuntimeError("canary nonce is invalid")
        self.root = root / nonce
        self.state_path = self.root / "state.json"
        self.proof_root = self.root / "proofs"
        self.budget_path = root / ".allocation-budget-v1.json"

    def load(self) -> Mapping[str, Any] | None:
        if not self.state_path.exists():
            return None
        return _read_json(self.state_path)

    def initialize(self, authorization_digest: str, boot_id: str) -> Mapping[str, Any]:
        if not _SHA256.fullmatch(authorization_digest):
            raise CanaryRuntimeError("authorization digest is invalid")
        current = self.load()
        if current is not None:
            stored_boot_id = current.get("boot_id")
            reboot_resume = (
                current.get("state") == "running"
                and current.get("current_scenario") == "reboot"
                and current.get("completed_scenarios") == list(SCENARIOS[:-1])
                and isinstance(stored_boot_id, str)
                and _DISTRO_BOOT_IDENTITY_V2.fullmatch(stored_boot_id) is not None
                and _DISTRO_BOOT_IDENTITY_V2.fullmatch(boot_id) is not None
                and stored_boot_id != boot_id
            )
            if current.get("authorization_digest") != authorization_digest or (
                current.get("boot_id") != boot_id and not reboot_resume
            ) or current.get("state") in {
                "terminal",
                "failed-quarantined",
                "failed-quarantined-clean",
            }:
                raise CanaryRuntimeError(
                    "canary nonce cannot resume a different or terminal matrix"
                )
            if reboot_resume:
                current = dict(current)
                current["rebooted_from_boot_id"] = current["boot_id"]
                current["boot_id"] = boot_id
                _atomic_json(self.state_path, current)
            return current
        value = {
            "schema_version": 1,
            "authorization_digest": authorization_digest,
            "boot_id": boot_id,
            "state": "authorized",
            "completed_scenarios": [],
            "current_scenario": None,
            "runtime_empty": False,
        }
        _atomic_json(self.state_path, value)
        return value

    @staticmethod
    def _budget_scope(authorization: Mapping[str, Any]) -> str:
        excluded = {"attestation", "nonce", "issued_at", "expires_at"}
        stable = {
            key: value for key, value in authorization.items() if key not in excluded
        }
        return hashlib.sha256(canonicalize_jcs(stable)).hexdigest()

    def consume_allocation(
        self, authorization: Mapping[str, Any], scenario: str
    ) -> Mapping[str, Any]:
        if scenario not in SCENARIOS or authorization.get("max_allocations") != 6:
            raise CanaryRuntimeError("canary allocation budget contract drifted")
        scope = self._budget_scope(authorization)
        if self.budget_path.exists():
            ledger = dict(_read_json(self.budget_path))
        else:
            ledger = {"schema_version": 1, "scopes": {}}
        if set(ledger) != {"schema_version", "scopes"} or ledger.get(
            "schema_version"
        ) != 1 or not isinstance(ledger.get("scopes"), Mapping):
            raise CanaryRuntimeError("durable canary allocation budget is invalid")
        scopes = dict(ledger["scopes"])
        entry = dict(scopes.get(scope, {"max_allocations": 6, "claims": []}))
        if set(entry) != {"max_allocations", "claims"} or entry.get(
            "max_allocations"
        ) != 6 or not isinstance(entry.get("claims"), list):
            raise CanaryRuntimeError("durable canary allocation scope is invalid")
        claims = list(entry["claims"])
        if len(claims) >= 6:
            raise CanaryRuntimeError("signed canary allocation budget is exhausted")
        claim = {
            "claim_id": str(uuid4()),
            "nonce": authorization["nonce"],
            "scenario": scenario,
            "authorization_digest": authorization_digest(authorization),
        }
        claims.append(claim)
        entry["claims"] = claims
        scopes[scope] = entry
        ledger["scopes"] = scopes
        _atomic_json(self.budget_path, ledger)
        current = dict(self.load() or {})
        if current.get("schema_version") != 1:
            raise CanaryRuntimeError("canary durable state is absent")
        current["allocation_claims"] = list(
            current.get("allocation_claims", [])
        ) + [claim]
        _atomic_json(self.state_path, current)
        return claim

    def transition(self, state: str, **updates: Any) -> Mapping[str, Any]:
        current = dict(self.load() or {})
        if current.get("schema_version") != 1:
            raise CanaryRuntimeError("canary durable state is absent")
        current.update(updates)
        current["state"] = state
        _atomic_json(self.state_path, current)
        return current

    def proof(self, scenario: str, value: Mapping[str, Any]) -> Path:
        if scenario not in SCENARIOS:
            raise CanaryRuntimeError("unknown canary scenario")
        required = PROOF_FIELDS
        if set(value) != required or value.get("scenario") != scenario:
            raise CanaryRuntimeError("canary proof fields are not exact")
        if value.get("conclusion") != scenario:
            raise CanaryRuntimeError("canary proof outcome crossed scenario")
        if value.get("jobs_started") != 1:
            raise CanaryRuntimeError("canary proof did not prove one-job lifecycle")
        if value.get("cleanup_record", {}).get("allocation_removed") is not True:
            raise CanaryRuntimeError("canary cleanup proof is not exact")
        self.proof_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.proof_root / f"{scenario}.json"
        if path.exists() and _read_json(path) != value:
            raise CanaryRuntimeError("canary proof identity changed on resume")
        _atomic_json(path, value)
        return path


class CanaryRuntime:
    def __init__(
        self,
        config: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        runner: CommandRunner | None = None,
        state_root: Path = STATE_ROOT,
        canary_sentinel: Path = CANARY_SENTINEL,
        secret_root: Path = CANARY_SECRET_ROOT,
        activation_sentinel: Path = ACTIVATION_SENTINEL,
        runtime_ready_sentinel: Path = RUNTIME_READY_SENTINEL,
        lock_path: Path = LOCK_PATH,
        boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
        proc1_stat_path: Path = Path("/proc/1/stat"),
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.config = config
        self.authorization = authorization
        self.runner = runner or CommandRunner()
        self.state_root = state_root
        self.canary_sentinel = canary_sentinel
        self.secret_root = secret_root
        self.activation_sentinel = activation_sentinel
        self.runtime_ready_sentinel = runtime_ready_sentinel
        self.lock_path = lock_path
        self.boot_id_path = boot_id_path
        self.proc1_stat_path = proc1_stat_path
        self.now = now
        self._lock = None

    def _distro_boot_identity(self) -> str:
        """Identify this WSL distro start, not merely the shared WSL2 kernel."""

        kernel_boot_id = self.boot_id_path.read_text(encoding="ascii").strip()
        proc1_stat = self.proc1_stat_path.read_text(encoding="ascii").strip()
        closing_paren = proc1_stat.rfind(")")
        fields = proc1_stat[closing_paren + 1 :].split() if closing_paren > 0 else []
        if not _UUID.fullmatch(kernel_boot_id) or len(fields) < 20 or not fields[19].isdigit():
            raise CanaryRuntimeError("WSL distro boot identity is invalid")
        return f"v2:{kernel_boot_id}:{fields[19]}"

    def _run(self, *argv: str, timeout: int = 60) -> str:
        result = self.runner.run(argv, timeout=timeout)
        if result.returncode:
            raise CanaryRuntimeError(f"canary command failed: {argv[0]}")
        return result.stdout.strip()

    def _inactive(self, unit: str) -> bool:
        result = self.runner.run(("systemctl", "is-active", unit), timeout=10)
        return result.returncode != 0 and result.stdout.strip() in {
            "inactive",
            "failed",
            "unknown",
            "",
        }

    def acquire(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        self._lock = self.lock_path.open("a+")
        try:
            fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CanaryRuntimeError("production or canary transaction is active") from exc

    def verify_authorization(self) -> tuple[Any, str]:
        required_config = {
            "schema_version",
            "reviewer_public_key_file",
            "reviewer_fingerprint",
            "digested_files",
            "garm_health_file",
            "broker_config_file",
            "allocation_signer_private_key_file",
            "broker_executable",
            "request_timeout_seconds",
        }
        if set(self.config) != required_config or self.config.get("schema_version") != 1:
            raise CanaryRuntimeError("canary runtime config fields are not exact")
        if (
            self.config["broker_executable"]
            != "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py"
            or type(self.config["request_timeout_seconds"]) is not int
            or not 30 <= self.config["request_timeout_seconds"] <= 3600
        ):
            raise CanaryRuntimeError("canary runtime executable/timeout is not exact")
        public_key = serialization.load_pem_public_key(
            Path(self.config["reviewer_public_key_file"]).read_bytes()
        )
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise CanaryRuntimeError("canary reviewer key is not Ed25519")
        decision = verify_canary_authorization(
            self.authorization,
            public_key,
            pinned_fingerprint=self.config["reviewer_fingerprint"],
            now=self.now(),
        )
        if not decision.authorized:
            raise CanaryRuntimeError("signed canary authorization was rejected")
        digest = authorization_digest(self.authorization)
        expected = {
            "github_app_config": self.authorization["github_app_config_digest"],
            "live_job_verifier": self.authorization["live_job_verifier_digest"],
            "network_policy": self.authorization["network_policy_digest"],
            "bootstrap_install_receipt": self.authorization[
                "bootstrap_install_receipt_digest"
            ],
        }
        configured = self.config["digested_files"]
        if not isinstance(configured, Mapping) or set(configured) != set(expected):
            raise CanaryRuntimeError("canary digested-file config is not exact")
        for name, wanted in expected.items():
            path = Path(configured[name])
            if not _SHA256.fullmatch(wanted) or _sha256_file(path) != wanted:
                raise CanaryRuntimeError(f"canary {name} digest drifted")
        remeasurement = json.loads(
            self._run("/usr/local/lib/self-hosted-ci/verify-bootstrap-install.py")
        )
        if (
            set(remeasurement) != {
                "status",
                "receipt_digest",
                "installed_targets_digest",
            }
            or remeasurement.get("status") != "verified"
            or not _SHA256.fullmatch(str(remeasurement.get("receipt_digest", "")))
            or not _SHA256.fullmatch(
                str(remeasurement.get("installed_targets_digest", ""))
            )
        ):
            raise CanaryRuntimeError("bootstrap live remeasurement is not exact")
        health = _read_json(Path(self.config["garm_health_file"]))
        broker = _read_json(Path(self.config["broker_config_file"]))
        repository_id = str(self.authorization["repository_id"])
        expected_entity = dict(self.authorization["garm_entity"])
        expected_entity["entity_flag"] = (
            "--repo"
            if expected_entity["authority_kind"] == "personal-repository"
            else "--org"
        )
        expected_health = {
            "schema_version": 3,
            "garm_cli_home": broker.get("garm_cli_home"),
            "manager_configured": True,
            "provider_configured": True,
            "image_configured": True,
            "broker_configured": True,
            "zero_scale_sets": True,
            "image": {
                "alias": self.authorization["image_alias"],
                "fingerprint": self.authorization["image_fingerprint"],
            },
            "targets": {repository_id: expected_entity},
        }
        if health != expected_health:
            raise CanaryRuntimeError("canary GARM health/entity/image contract drifted")
        if (
            broker.get("allocation_signer_fingerprint")
            != self.authorization["allocation_signer_fingerprint"]
            or broker.get("image_alias") != self.authorization["image_alias"]
            or broker.get("image_fingerprint")
            != self.authorization["image_fingerprint"]
            or broker.get("targets") != {repository_id: expected_entity}
            or set(broker)
            != {
                "allocation_signer_fingerprint",
                "garm_cli_home",
                "provider_name",
                "image_alias",
                "image_fingerprint",
                "live_job_verifier",
                "targets",
            }
        ):
            raise CanaryRuntimeError("canary broker signer/image/entity contract drifted")
        return decision, digest

    def preflight(self) -> tuple[Any, CanaryStateStore]:
        if os.geteuid() != 0:
            raise CanaryRuntimeError("canary runtime must run as root")
        self.acquire()
        if self.activation_sentinel.exists() or self.runtime_ready_sentinel.exists():
            raise CanaryRuntimeError("production activation is present")
        if self.canary_sentinel.exists():
            raise CanaryRuntimeError("stale canary approval sentinel is present")
        if any(not self._inactive(unit) for unit in PRODUCTION_UNITS):
            raise CanaryRuntimeError("a production runtime unit is active")
        authorization, digest = self.verify_authorization()
        if tuple(authorization.scenarios) != SCENARIOS:
            raise CanaryRuntimeError("canary authorization scenario matrix drifted")
        if (
            self.authorization["max_allocations"] != 6
            or self.authorization["max_concurrency"] != 1
            or self.authorization["max_jobs_per_allocation"] != 1
        ):
            raise CanaryRuntimeError("canary authorization allocation bounds drifted")
        boot_id = self._distro_boot_identity()
        store = CanaryStateStore(self.state_root, authorization.nonce)
        current = store.load()
        reboot_resume = bool(
            current is not None
            and current.get("state") == "running"
            and current.get("current_scenario") == "reboot"
            and current.get("completed_scenarios") == list(SCENARIOS[:-1])
            and isinstance(current.get("boot_id"), str)
            and _DISTRO_BOOT_IDENTITY_V2.fullmatch(current["boot_id"]) is not None
            and current.get("boot_id") != boot_id
        )
        instances = json.loads(
            self._run("incus", "--project", "ci-jit", "list", "--format", "json")
        )
        if reboot_resume:
            assert current is not None
            reboot_label = current.get("reboot_runner_label")
            reboot_allocation_id = current.get("reboot_allocation_id")
            evidence = current.get("reboot_evidence")
            reservation = evidence.get("reservation") if isinstance(evidence, Mapping) else None
            runner_name = evidence.get("runner_name") if isinstance(evidence, Mapping) else None
            if (
                not isinstance(reboot_label, str)
                or not isinstance(reboot_allocation_id, str)
                or not isinstance(reservation, Mapping)
                or reservation.get("allocation_id") != reboot_allocation_id
                or reservation.get("scale_set_name") != reboot_label
                or allocation_scale_set_name(reservation) != reboot_label
                or not isinstance(runner_name, str)
                or not runner_name.startswith(reboot_label + "-")
                or len(instances) != 1
                or not isinstance(instances[0], Mapping)
                or instances[0].get("name") != runner_name
            ):
                raise CanaryRuntimeError(
                    "reboot resume inventory crossed the durable allocation"
                )
        elif instances != []:
            raise CanaryRuntimeError("initial canary runtime inventory is not empty")
        store.initialize(digest, boot_id)
        return authorization, store

    def verify_prepared(self) -> tuple[Any, CanaryStateStore]:
        """Revalidate a prepared lane without competing for its held lock."""

        if os.geteuid() != 0:
            raise CanaryRuntimeError("canary runtime must run as root")
        if self.activation_sentinel.exists() or self.runtime_ready_sentinel.exists():
            raise CanaryRuntimeError("production activation is present")
        if any(not self._inactive(unit) for unit in PRODUCTION_UNITS):
            raise CanaryRuntimeError("a production runtime unit is active")
        authorization, digest = self.verify_authorization()
        sentinel = _read_json(self.canary_sentinel)
        if sentinel != {
            "authorization_digest": digest,
            "purpose": "canary-only",
        }:
            raise CanaryRuntimeError("canary approval sentinel crossed authorization")
        store = CanaryStateStore(self.state_root, authorization.nonce)
        state = store.load()
        if (
            state is None
            or state.get("authorization_digest") != digest
            or state.get("state")
            not in {"services-starting", "ready", "running", "teardown"}
        ):
            raise CanaryRuntimeError("prepared canary durable state is not authorized")
        return authorization, store

    def prepare(self, store: CanaryStateStore, authorization_digest: str) -> None:
        initial_state = store.load() or {}
        reboot_allocation_id = (
            initial_state.get("reboot_allocation_id")
            if "rebooted_from_boot_id" in initial_state
            else None
        )
        self._run("systemctl", "start", "self-hosted-ci-network-quarantine.service")
        self.canary_sentinel.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        _atomic_json(
            self.canary_sentinel,
            {"authorization_digest": authorization_digest, "purpose": "canary-only"},
        )
        self.secret_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        store.transition("services-starting")
        self._run("systemctl", "start", "self-hosted-ci-canary.target", timeout=180)
        broker_inventory = json.loads(
            self._run(
                "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py", "recover"
            )
        )
        expected_recovered = [] if reboot_allocation_id is None else [reboot_allocation_id]
        if broker_inventory != {
            "recovered": expected_recovered,
            "runtime_empty": True,
        }:
            raise CanaryRuntimeError("prepared canary runtime inventory is not empty")
        store.transition("ready")

    def run_matrix(self, store: CanaryStateStore, driver: CanaryScenarioDriver) -> None:
        current = store.load() or {}
        completed = list(current.get("completed_scenarios", []))
        if any(item not in SCENARIOS for item in completed) or len(set(completed)) != len(completed):
            raise CanaryRuntimeError("durable canary scenario state is invalid")
        for scenario in SCENARIOS:
            if scenario in completed:
                continue
            current = store.load() or {}
            if (
                scenario == "reboot"
                and current.get("current_scenario") == "reboot"
                and "rebooted_from_boot_id" in current
            ):
                proof = driver.resume_reboot(
                    current["reboot_allocation_id"],
                    current["reboot_runner_label"],
                    current["reboot_evidence"],
                )
                store.proof(scenario, proof)
                completed.append(scenario)
                store.transition(
                    "ready", completed_scenarios=completed, current_scenario=None
                )
                continue
            store.transition("running", current_scenario=scenario)
            store.consume_allocation(self.authorization, scenario)
            try:
                proof = driver.run(scenario)
            except CanaryRebootRequired as reboot:
                store.transition(
                    "running",
                    current_scenario="reboot",
                    completed_scenarios=completed,
                    reboot_allocation_id=reboot.allocation_id,
                    reboot_runner_label=reboot.runner_label,
                    reboot_evidence=reboot.evidence,
                )
                raise
            store.proof(scenario, proof)
            completed.append(scenario)
            store.transition(
                "ready", completed_scenarios=completed, current_scenario=None
            )

    def teardown(
        self, store: CanaryStateStore, driver: CanaryScenarioDriver, *, failed: bool
    ) -> None:
        store.transition("teardown")
        recovery = list(driver.recover_all())
        empty = driver.prove_runtime_empty()
        if empty != {
            "scale_sets": 0,
            "instances": 0,
            "runners": 0,
            "registrations": 0,
        }:
            raise CanaryRuntimeError("final canary runtime inventory is not empty")
        for unit in reversed(CANARY_UNITS):
            self.runner.run(("systemctl", "stop", unit), timeout=60)
        self._run("systemctl", "start", "self-hosted-ci-network-quarantine.service")
        self.canary_sentinel.unlink(missing_ok=True)
        if self.secret_root.exists():
            shutil.rmtree(self.secret_root)
        store.transition(
            "failed-quarantined" if failed else "terminal",
            current_scenario=None,
            runtime_empty=True,
            recovered_allocations=recovery,
        )

    def quarantine_after_failure(self, store: CanaryStateStore | None) -> None:
        for unit in reversed(CANARY_UNITS):
            self.runner.run(("systemctl", "stop", unit), timeout=60)
        self.runner.run(
            ("systemctl", "start", "self-hosted-ci-network-quarantine.service"),
            timeout=60,
        )
        self.canary_sentinel.unlink(missing_ok=True)
        if self.secret_root.exists():
            shutil.rmtree(self.secret_root, ignore_errors=True)
        if store is not None:
            store.transition("failed-quarantined", runtime_empty=False)

    def recover_before_quarantine(
        self, store: CanaryStateStore, driver: CanaryScenarioDriver
    ) -> None:
        """Recover with GARM reachable, then converge to quarantine."""

        self.runner.run(
            ("systemctl", "stop", "self-hosted-ci-canary-broker.service"),
            timeout=60,
        )
        for unit in CANARY_UNITS[:-1]:
            self._run("systemctl", "start", unit, timeout=180)
        recovered = list(driver.recover_all())
        empty = driver.prove_runtime_empty()
        if empty != {
            "scale_sets": 0,
            "instances": 0,
            "runners": 0,
            "registrations": 0,
        }:
            raise CanaryRuntimeError("failed canary runtime inventory is not empty")
        self.quarantine_after_failure(None)
        store.transition(
            "failed-quarantined-clean",
            runtime_empty=True,
            recovered_allocations=recovered,
        )

    def execute(self, driver: CanaryScenarioDriver) -> Mapping[str, Any]:
        """Run the authorized matrix and always converge to quarantine."""

        store: CanaryStateStore | None = None
        try:
            authorization, store = self.preflight()
            digest = (store.load() or {}).get("authorization_digest")
            if not isinstance(digest, str):
                raise CanaryRuntimeError("canary authorization digest was not persisted")
            self.prepare(store, digest)
            self.run_matrix(store, driver)
            self.teardown(store, driver, failed=False)
            return {
                "status": "terminal",
                "nonce": authorization.nonce,
                "scenarios": list(SCENARIOS),
                "runtime_empty": True,
                "production_activation_changed": False,
                "outbound_worker_started": False,
            }
        except CanaryRebootRequired:
            for unit in reversed(CANARY_UNITS):
                self.runner.run(("systemctl", "stop", unit), timeout=60)
            self.runner.run(
                ("systemctl", "start", "self-hosted-ci-network-quarantine.service"),
                timeout=60,
            )
            self.canary_sentinel.unlink(missing_ok=True)
            if self.secret_root.exists():
                shutil.rmtree(self.secret_root, ignore_errors=True)
            raise
        except Exception:
            if store is not None:
                try:
                    self.recover_before_quarantine(store, driver)
                except Exception:
                    pass
            else:
                self.quarantine_after_failure(None)
            raise


def load_live_canary_driver(
    config: Mapping[str, Any], authorization: Mapping[str, Any]
) -> BrokerCanaryScenarioDriver:
    executable = Path(config["broker_executable"])
    spec = importlib.util.spec_from_file_location("self_hosted_ci_live_broker", executable)
    if spec is None or spec.loader is None:
        raise CanaryRuntimeError("canary broker executable cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    broker = module.load_broker()
    if not isinstance(broker, AllocationBroker):
        raise CanaryRuntimeError("canary broker loader did not return AllocationBroker")
    app_config = read_root_json(Path(config["digested_files"]["github_app_config"]))
    signer = FileAllocationSigner(Path(config["allocation_signer_private_key_file"]))
    if signer.fingerprint != authorization["allocation_signer_fingerprint"]:
        raise CanaryRuntimeError("canary allocation signer crossed authorization")
    dispatch = LiveCanaryDispatchAdapter(
        authorization,
        app_config,
        signer,
        timeout_seconds=config["request_timeout_seconds"],
    )
    return BrokerCanaryScenarioDriver(broker, dispatch, authorization)


def assert_production_fence(
    *,
    state_root: Path = STATE_ROOT,
    canary_sentinel: Path = CANARY_SENTINEL,
    runner: CommandRunner | None = None,
) -> None:
    """Block production activation while any canary uncertainty remains."""

    if canary_sentinel.exists():
        raise CanaryRuntimeError("canary approval sentinel is present")
    command = runner or CommandRunner()
    for unit in CANARY_UNITS:
        result = command.run(("systemctl", "is-active", unit), timeout=10)
        if result.returncode == 0:
            raise CanaryRuntimeError("a canary runtime unit is active")
    if state_root.exists():
        for path in state_root.glob("*/state.json"):
            state = _read_json(path)
            if state.get("state") not in {
                "terminal",
                "failed-quarantined-clean",
            } or state.get("runtime_empty") is not True:
                raise CanaryRuntimeError("a canary matrix is nonterminal or unclean")
