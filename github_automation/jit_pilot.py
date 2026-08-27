"""Non-gating JIT pilot package and terminal lifecycle contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Protocol
import urllib.error
import urllib.request
from uuid import UUID


_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA = re.compile(r"[0-9a-f]{40}")
_LABEL = re.compile(r"wsl-jit-[0-9a-f]{32}")
_WORKFLOW_REF = re.compile(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/ci-jit-pilot-child\.yml@refs/heads/([A-Za-z0-9._/-]+)")


class JitPilotError(ValueError):
    pass


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"


def parse_package_json(raw: str, *, now: datetime) -> "JitPilotPackageV1":
    def exact_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise JitPilotError("pilot package contains duplicate JSON keys")
            result[key] = value
        return result
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 65_536:
        raise JitPilotError("pilot package is absent or oversized")
    try:
        value = json.loads(raw, object_pairs_hook=exact_object)
    except json.JSONDecodeError as exc:
        raise JitPilotError("pilot package is invalid JSON") from exc
    return JitPilotPackageV1.from_mapping(value, now=now)


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise JitPilotError(f"{field} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise JitPilotError(f"{field} must be canonical UTC") from exc
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise JitPilotError(f"{field} must be canonical UTC seconds")
    return parsed


@dataclass(frozen=True)
class JitPilotPackageV1:
    repository: str
    repository_id: int
    pr_number: int
    base_branch: str
    base_sha: str
    head_sha: str
    tested_merge_sha: str
    workflow_ref: str
    backend: str
    allocation_id: str | None
    runner_label: str | None
    issued_at: str
    expires_at: str
    jit_pilot_package_version: int = 1

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, now: datetime) -> "JitPilotPackageV1":
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, Mapping) or set(value) != fields:
            raise JitPilotError("JIT pilot package requires exact fields")
        package = cls(**value)
        package.validate(now=now)
        return package

    def validate(self, *, now: datetime) -> None:
        if self.jit_pilot_package_version != 1:
            raise JitPilotError("unsupported JIT pilot package version")
        if not _REPOSITORY.fullmatch(self.repository):
            raise JitPilotError("pilot repository is invalid")
        for field, value in (("repository_id", self.repository_id), ("pr_number", self.pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise JitPilotError(f"{field} must be positive")
        if not isinstance(self.base_branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", self.base_branch):
            raise JitPilotError("pilot base branch is invalid")
        for field in ("base_sha", "head_sha", "tested_merge_sha"):
            if not isinstance(getattr(self, field), str) or not _SHA.fullmatch(getattr(self, field)):
                raise JitPilotError(f"{field} must be a full lowercase SHA")
        workflow = _WORKFLOW_REF.fullmatch(self.workflow_ref) if isinstance(self.workflow_ref, str) else None
        if workflow is None or workflow.group(1) != self.repository or workflow.group(2) != self.base_branch:
            raise JitPilotError("pilot workflow ref crossed repository/default branch")
        if self.backend == "local":
            try:
                allocation = UUID(self.allocation_id or "")
            except ValueError as exc:
                raise JitPilotError("local pilot allocation ID is invalid") from exc
            if str(allocation) != self.allocation_id or not _LABEL.fullmatch(self.runner_label or ""):
                raise JitPilotError("local pilot allocation binding is invalid")
        elif self.backend == "github":
            if self.allocation_id is not None or self.runner_label is not None:
                raise JitPilotError("hosted pilot cannot carry local allocation authority")
        else:
            raise JitPilotError("pilot backend must be local or github")
        issued, expires = _time(self.issued_at, "issued_at"), _time(self.expires_at, "expires_at")
        if now.tzinfo is None or not issued <= now < expires or expires <= issued or (expires - issued).total_seconds() > 900:
            raise JitPilotError("pilot package lifetime is invalid")


class PilotGitHubReader(Protocol):
    def repository(self) -> Mapping[str, Any]: ...
    def pull_request(self, number: int) -> Mapping[str, Any]: ...
    def workflow(self) -> Mapping[str, Any]: ...


class GitHubApiReader:
    """Workflow-token reader limited to the package's exact repository."""

    def __init__(self, package: JitPilotPackageV1, token: str, *, opener=urllib.request.urlopen) -> None:
        if not token or any(character.isspace() for character in token):
            raise JitPilotError("pilot workflow token is invalid")
        self.package, self._token, self._opener = package, token, opener

    def _get(self, path: str) -> Mapping[str, Any]:
        request = urllib.request.Request(API_ROOT + path, headers={
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION, "User-Agent": "self-hosted-ci-jit-pilot/1",
        })
        try:
            with self._opener(request, timeout=10) as response:
                body = response.read(1_048_577)
                if response.status != 200 or not body or len(body) > 1_048_576:
                    raise JitPilotError("pilot GitHub response is invalid")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise JitPilotError("pilot GitHub revalidation failed") from exc
        try:
            def exact_object(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise JitPilotError("pilot GitHub response contains duplicate keys")
                    result[key] = item
                return result
            value = json.loads(body, object_pairs_hook=exact_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JitPilotError("pilot GitHub response is invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise JitPilotError("pilot GitHub response is not an object")
        return value

    def repository(self): return self._get(f"/repos/{self.package.repository}")
    def pull_request(self, number): return self._get(f"/repos/{self.package.repository}/pulls/{number}")
    def workflow(self): return self._get(f"/repos/{self.package.repository}/actions/workflows/ci-jit-pilot-child.yml")


def revalidate_package(package: JitPilotPackageV1, github: PilotGitHubReader) -> None:
    repository = github.repository()
    if (
        repository.get("id") != package.repository_id
        or repository.get("full_name") != package.repository
        or repository.get("default_branch") != package.base_branch
    ):
        raise JitPilotError("live repository identity crossed the pilot package")
    pull = github.pull_request(package.pr_number)
    head, base = pull.get("head"), pull.get("base")
    if (
        pull.get("number") != package.pr_number or pull.get("state") != "open"
        or not isinstance(head, Mapping) or head.get("sha") != package.head_sha
        or not isinstance(base, Mapping) or base.get("sha") != package.base_sha
        or base.get("ref") != package.base_branch
        or not isinstance(base.get("repo"), Mapping) or base["repo"].get("id") != package.repository_id
    ):
        raise JitPilotError("live pull request identity crossed the pilot package")
    workflow = github.workflow()
    if workflow.get("path") != ".github/workflows/ci-jit-pilot-child.yml" or workflow.get("state") != "active":
        raise JitPilotError("live pilot workflow identity mismatch")


TERMINAL_CONCLUSIONS = {
    "success": "success", "failure": "failure", "cancelled": "cancel", "timed_out": "timeout",
}


class PilotRunObserver(Protocol):
    def run(self, run_id: int) -> Mapping[str, Any]: ...
    def jobs(self, run_id: int) -> Mapping[str, Any]: ...


class PilotBroker(Protocol):
    def finish(self, allocation_id: str, outcome: str) -> None: ...
    def prove_clean(self, allocation_id: str, runner_label: str) -> Mapping[str, Any]: ...


@dataclass
class PilotTerminalMonitor:
    github: PilotRunObserver
    broker: PilotBroker
    sleeper: Any
    monotonic: Any
    timeout_seconds: float = 3600
    poll_seconds: float = 5

    def monitor(self, *, allocation_id: str, runner_label: str, run_id: int, job_id: int) -> str:
        try:
            parsed_allocation = UUID(allocation_id)
        except ValueError as exc:
            raise JitPilotError("terminal monitor allocation ID is invalid") from exc
        if str(parsed_allocation) != allocation_id or not _LABEL.fullmatch(runner_label) or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (run_id, job_id)):
            raise JitPilotError("terminal monitor identity is invalid")
        deadline = self.monotonic() + self.timeout_seconds
        conclusion: str | None = None
        unexpected = False
        while conclusion is None:
            run = self.github.run(run_id)
            jobs = self.github.jobs(run_id)
            if run.get("id") != run_id or not isinstance(jobs.get("jobs"), list):
                raise JitPilotError("terminal monitor crossed the exact run")
            matches = [job for job in jobs["jobs"] if (
                isinstance(job, Mapping) and job.get("id") == job_id and job.get("run_id") == run_id
                and job.get("name") == "local-quality" and runner_label in job.get("labels", [])
            )]
            if len(matches) != 1:
                raise JitPilotError("terminal monitor cannot prove the exact local job")
            job = matches[0]
            if job.get("status") == "completed":
                raw = job.get("conclusion")
                if run.get("status") != "completed":
                    if run.get("status") not in {"queued", "in_progress"} or run.get("conclusion") is not None:
                        raise JitPilotError("terminal monitor observed an invalid run state")
                    if self.monotonic() >= deadline:
                        conclusion = "timeout"
                        break
                    self.sleeper(self.poll_seconds)
                    continue
                if run.get("conclusion") != raw:
                    raise JitPilotError("pilot run and exact job conclusions diverged")
                conclusion = TERMINAL_CONCLUSIONS.get(raw, "failure")
                unexpected = raw not in TERMINAL_CONCLUSIONS
                break
            if job.get("status") not in {"queued", "in_progress"} or job.get("conclusion") is not None:
                raise JitPilotError("terminal monitor observed an invalid nonterminal state")
            if run.get("status") not in {"queued", "in_progress"} or run.get("conclusion") is not None:
                raise JitPilotError("terminal monitor observed run completion before its exact job")
            if self.monotonic() >= deadline:
                conclusion = "timeout"
                break
            self.sleeper(self.poll_seconds)
        self.broker.finish(allocation_id, conclusion)
        cleanup = self.broker.prove_clean(allocation_id, runner_label)
        if cleanup != {
            "allocation_id": allocation_id, "runner_label": runner_label,
            "state": "cleaned", "scale_set_absent": True, "runtime_empty": True,
        }:
            raise JitPilotError("pilot terminal cleanup proof is not exact")
        if unexpected:
            raise JitPilotError("unexpected GitHub job conclusion was cleaned as failure")
        return conclusion


def validation_main(
    environment: Mapping[str, str] | None = None,
    *, clock: Any = lambda: datetime.now(timezone.utc),
) -> int:
    env = os.environ if environment is None else environment
    try:
        package = parse_package_json(env.get("JIT_PILOT_PACKAGE", ""), now=clock())
        if env.get("GITHUB_REPOSITORY") != package.repository or env.get("GITHUB_REPOSITORY_ID") != str(package.repository_id):
            raise JitPilotError("workflow event repository crossed the pilot package")
        revalidate_package(package, GitHubApiReader(package, env.get("GITHUB_TOKEN", "")))
        destination = env.get("GITHUB_OUTPUT")
        if not destination:
            raise JitPilotError("GITHUB_OUTPUT is absent")
        outputs = {
            "backend": package.backend, "repository": package.repository,
            "pr_number": str(package.pr_number), "base_sha": package.base_sha,
            "head_sha": package.head_sha, "tested_merge_sha": package.tested_merge_sha,
            "runner_label": package.runner_label or "",
        }
        with Path(destination).open("a", encoding="utf-8") as stream:
            for key, value in outputs.items():
                if "\n" in value or "\r" in value:
                    raise JitPilotError("pilot output contains a line break")
                stream.write(f"{key}={value}\n")
        return 0
    except (OSError, JitPilotError):
        print("JIT pilot validation blocked", file=sys.stderr)
        return 1
