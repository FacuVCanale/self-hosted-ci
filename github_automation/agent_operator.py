"""Local operator surface shared by Codex and Claude Code.

Natural language belongs in agent skills.  This module is the deterministic
authority boundary: exact repositories only, private state, atomic writes,
append-only audit, and no organization-wide enrollment.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$"
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
RUNNER_GROUP = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
DISTRO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SSH_TARGET = re.compile(r"^[A-Za-z0-9._@:-]+$")
MANAGED_WORKFLOW = ".github/workflows/ci-jit-pilot-child.yml"
HOSTED_WORKFLOW = re.compile(r"^\.github/workflows/[A-Za-z0-9._-]{1,100}\.ya?ml$")
# Exact GitHub-hosted workflows that publish the same quality signal the local
# runner produces.  While a repository is routed local they are suspended at the
# workflow level, never edited: the reviewed repository command profile pins the
# byte-exact sha256 of `.github/workflows/ci.yml`, so changing that file would
# break the very local run that is meant to replace it.  Suspension is exact,
# recorded, and undone by `use-github`.
HOSTED_DUPLICATE_WORKFLOWS: Mapping[str, tuple[str, ...]] = {
    "alethia-earth/Overworld": (".github/workflows/ci.yml",),
}
HOSTED_DISABLED_STATE = "disabled_manually"
HOSTED_ACTIVE_STATE = "active"
DEFAULT_PUBLIC_REPOSITORY = "FacuVCanale/self-hosted-ci"
REGISTRY_SCHEMA = "https://raw.githubusercontent.com/FacuVCanale/self-hosted-ci/main/schemas/operator-registry-v1.schema.json"


class AgentOperatorError(RuntimeError):
    """A safe, operator-actionable failure."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def exact_repository(value: str) -> str:
    candidate = value.strip()
    if not REPOSITORY.fullmatch(candidate) or "*" in candidate:
        raise AgentOperatorError(
            "invalid_repository",
            "repository must be one exact OWNER/REPO; wildcards and organizations are forbidden",
        )
    return candidate


def exact_pr(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AgentOperatorError("invalid_pr", "pull request must be a positive integer")
    return value


def run_checked(
    argv: Sequence[str],
    *,
    input_text: str | None = None,
    timeout: int = 45,
) -> str:
    try:
        result = subprocess.run(
            list(argv),
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentOperatorError("command_unavailable", f"command failed safely: {argv[0]}") from exc
    if result.returncode:
        message = (result.stderr or result.stdout or "command failed").strip()
        raise AgentOperatorError(
            "external_command_failed",
            message[:1000],
            details={"command": argv[0], "exit_code": result.returncode},
        )
    return result.stdout


@dataclass(frozen=True)
class OperatorPaths:
    root: Path

    @property
    def registry(self) -> Path:
        return self.root / "registry.json"

    @property
    def audit(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def lock(self) -> Path:
        return self.root / "operator.lock"


class PrivateOperatorStore:
    def __init__(self, paths: OperatorPaths):
        self.paths = paths

    def _secure_root(self) -> None:
        self.paths.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.paths.root, 0o700)

    @contextmanager
    def locked(self) -> Iterator[None]:
        self._secure_root()
        descriptor = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def load(self) -> dict[str, Any]:
        self._secure_root()
        if not self.paths.registry.exists():
            return {
                "$schema": REGISTRY_SCHEMA,
                "operator_registry_version": 1,
                "repositories": {},
            }
        info = self.paths.registry.stat()
        if info.st_mode & 0o077:
            raise AgentOperatorError("unsafe_registry_permissions", "private registry must not be group/world accessible")
        try:
            value = json.loads(self.paths.registry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentOperatorError("invalid_registry", "private registry is unreadable or invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"$schema", "operator_registry_version", "repositories"}
            or value["$schema"] != REGISTRY_SCHEMA
            or value["operator_registry_version"] != 1
            or not isinstance(value["repositories"], dict)
        ):
            raise AgentOperatorError("invalid_registry", "private registry schema is invalid")
        for repository, state in value["repositories"].items():
            exact_repository(repository)
            if not isinstance(state, dict) or state.get("ci_runner") not in {
                "github",
                "local-with-github-fallback",
            }:
                raise AgentOperatorError("invalid_registry", "repository routing state is invalid")
            allowed = {
                "ci_runner", "managed_workflow", "repository_id",
                "authority_installation_id", "workflow_blob_sha",
                "workflow_content_sha256", "public_sha", "updated_at", "pending",
                "hosted_workflows_disabled",
            }
            if set(state) - allowed:
                raise AgentOperatorError("invalid_registry", "repository routing state has unknown fields")
            suspended = state.get("hosted_workflows_disabled")
            if suspended is not None and (
                not isinstance(suspended, list)
                or len(set(suspended)) != len(suspended)
                or any(
                    not isinstance(path, str) or not HOSTED_WORKFLOW.fullmatch(path)
                    for path in suspended
                )
            ):
                raise AgentOperatorError(
                    "invalid_registry", "suspended hosted workflow record is invalid"
                )
            if (
                state.get("managed_workflow") not in {None, MANAGED_WORKFLOW}
                or (
                    state.get("repository_id") is not None
                    and (isinstance(state["repository_id"], bool) or not isinstance(state["repository_id"], int) or state["repository_id"] < 1)
                )
                or (
                    state.get("authority_installation_id") is not None
                    and (isinstance(state["authority_installation_id"], bool) or not isinstance(state["authority_installation_id"], int) or state["authority_installation_id"] < 1)
                )
                or (
                    state.get("workflow_blob_sha") is not None
                    and not FULL_SHA.fullmatch(str(state["workflow_blob_sha"]))
                )
                or (
                    state.get("workflow_content_sha256") is not None
                    and not re.fullmatch(r"[0-9a-f]{64}", str(state["workflow_content_sha256"]))
                )
                or (
                    state.get("public_sha") is not None
                    and not FULL_SHA.fullmatch(str(state["public_sha"]))
                )
            ):
                raise AgentOperatorError("invalid_registry", "repository routing metadata is invalid")
            pending = state.get("pending")
            if pending is not None and (
                not isinstance(pending, dict)
                or set(pending) != {
                    "operation", "started_at", "expected_workflow_sha256", "previous_ci_runner"
                }
                or pending.get("operation") not in {"use-local", "use-github"}
                or pending.get("previous_ci_runner") not in {"github", "local-with-github-fallback"}
                or (
                    pending.get("expected_workflow_sha256") is not None
                    and not re.fullmatch(r"[0-9a-f]{64}", str(pending.get("expected_workflow_sha256")))
                )
            ):
                raise AgentOperatorError("invalid_registry", "pending routing transaction is invalid")
        return value

    def save(self, value: Mapping[str, Any]) -> None:
        self._secure_root()
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        descriptor, name = tempfile.mkstemp(prefix="registry.", dir=self.paths.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.paths.registry)
            directory = os.open(self.paths.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def append_audit(self, event: Mapping[str, Any]) -> None:
        self._secure_root()
        descriptor = os.open(self.paths.audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            os.write(descriptor, line.encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class HostConfig:
    ssh_target: str
    ssh_key: Path
    distro: str = "Ubuntu-24.04-CI"
    public_repository: str = DEFAULT_PUBLIC_REPOSITORY
    public_sha: str = ""

    @classmethod
    def load(cls, path: Path) -> "HostConfig":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentOperatorError("host_config_missing", f"host config is unavailable: {path}") from exc
        required = {"ssh_target", "ssh_key", "distro", "public_repository", "public_sha"}
        if not isinstance(value, dict) or set(value) != required:
            raise AgentOperatorError("invalid_host_config", "host config fields are not exact")
        if not all(isinstance(value[name], str) for name in required):
            raise AgentOperatorError("invalid_host_config", "host config values must be strings")
        exact_repository(value["public_repository"])
        if not FULL_SHA.fullmatch(value["public_sha"]):
            raise AgentOperatorError("invalid_host_config", "public runtime SHA must be a full commit SHA")
        target = value["ssh_target"]
        if not SSH_TARGET.fullmatch(target):
            raise AgentOperatorError("invalid_host_config", "SSH target is invalid")
        if not DISTRO.fullmatch(value["distro"]):
            raise AgentOperatorError("invalid_host_config", "WSL distro name is invalid")
        key = Path(value["ssh_key"]).expanduser()
        if not key.is_file():
            raise AgentOperatorError("invalid_host_config", "SSH identity file is unavailable")
        return cls(target, key, value["distro"], value["public_repository"], value["public_sha"])


class AgentOperator:
    def __init__(self, store: PrivateOperatorStore, host: HostConfig):
        self.store = store
        self.host = host

    def _ssh(self, command: str, *, timeout: int = 45) -> str:
        return run_checked(
            [
                "ssh",
                "-i",
                str(self.host.ssh_key),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                self.host.ssh_target,
                command,
            ],
            timeout=timeout,
        )

    def _remote_worker_config(self) -> dict[str, Any]:
        raw = self._ssh(
            f'wsl.exe -d {self.host.distro} -u root -- cat /etc/self-hosted-ci/outbound-worker.json'
        )
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgentOperatorError("authority_unavailable", "host worker authority is invalid") from exc
        safe = {
            key: value.get(key)
            for key in (
                "repository",
                "repository_id",
                "installation_id",
                "repository_selection",
                "default_branch",
                "workflow_path",
                "mode",
                "authority_kind",
                "runner_group",
            )
        }
        try:
            repository = exact_repository(safe["repository"])
        except (AgentOperatorError, TypeError, AttributeError) as exc:
            raise AgentOperatorError("authority_unavailable", "host authority repository is invalid") from exc
        if (
            safe["repository_selection"] != "selected"
            or not isinstance(safe["repository_id"], int)
            or isinstance(safe["repository_id"], bool)
            or safe["repository_id"] < 1
            or not isinstance(safe["installation_id"], int)
            or isinstance(safe["installation_id"], bool)
            or safe["installation_id"] < 1
            or not isinstance(safe["default_branch"], str)
            or not re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", safe["default_branch"])
            or safe["workflow_path"] != MANAGED_WORKFLOW
            or safe["mode"] not in {"ci-jit-pilot", "ci-gate-full"}
            or safe["authority_kind"] not in {
                "personal-repository",
                "organization-runner-group",
            }
            or (
                safe["authority_kind"] == "personal-repository"
                and safe["runner_group"] is not None
            )
            or (
                safe["authority_kind"] == "organization-runner-group"
                and (
                    not isinstance(safe["runner_group"], str)
                    or RUNNER_GROUP.fullmatch(safe["runner_group"]) is None
                )
            )
        ):
            raise AgentOperatorError("authority_unavailable", "host authority is not selected-repository exact")
        safe["repository"] = repository
        return safe

    def _health(self) -> dict[str, Any]:
        raw = self._ssh('cmd.exe /d /c type C:\\ProgramData\\self-hosted-ci\\health\\current.json')
        try:
            snapshot = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgentOperatorError("health_unavailable", "health snapshot is invalid") from exc
        return {
            "eligible": snapshot.get("eligibility", {}).get("eligible_for_local_ci") is True,
            "blockers": snapshot.get("eligibility", {}).get("blocking_reasons", []),
            "generated_at": snapshot.get("generated_at"),
            "probe_error": snapshot.get("probe_error"),
        }

    def _github_repository(self, repository: str) -> dict[str, Any]:
        raw = run_checked(
            ["gh", "api", f"repos/{repository}", "--jq", "{id:.id,nameWithOwner:.full_name,defaultBranch:.default_branch}"],
            timeout=30,
        )
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgentOperatorError("github_repository_unavailable", "GitHub repository response is invalid") from exc
        if value.get("nameWithOwner", "").lower() != repository.lower() or not isinstance(value.get("id"), int):
            raise AgentOperatorError("github_repository_mismatch", "GitHub resolved a different repository")
        return value

    def _workflow(self, repository: str) -> dict[str, Any] | None:
        result = subprocess.run(
            ["gh", "api", f"repos/{repository}/contents/{MANAGED_WORKFLOW}"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            try:
                error = json.loads(result.stderr or result.stdout)
            except json.JSONDecodeError:
                error = {}
            if (
                error.get("status") == "404"
                or error.get("message") == "Not Found"
                or re.search(r"\(HTTP 404\)\s*$", result.stderr.strip())
            ):
                return None
            raise AgentOperatorError("github_workflow_unavailable", (result.stderr or result.stdout)[:1000])
        try:
            value = json.loads(result.stdout)
            content = base64.b64decode(value["content"], validate=False)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AgentOperatorError("github_workflow_unavailable", "GitHub workflow response is invalid") from exc
        if not FULL_SHA.fullmatch(str(value.get("sha", ""))):
            raise AgentOperatorError("github_workflow_unavailable", "GitHub workflow blob SHA is invalid")
        return {
            "sha": value["sha"],
            "content": content,
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }

    @staticmethod
    def hosted_duplicates(repository: str) -> tuple[str, ...]:
        """Exact hosted workflow paths that duplicate the local quality signal.

        Returns an empty tuple for every repository that has not been reviewed
        into the allowlist, so opting a new repository into local CI never
        suspends anything by accident.
        """
        return HOSTED_DUPLICATE_WORKFLOWS.get(repository, ())

    def _hosted_workflows(self, repository: str) -> dict[str, dict[str, Any]]:
        """Observe the live state of the exact hosted duplicates of a repository.

        Returns a mapping of workflow path to `{"id": int, "state": str}` for
        the allowlisted duplicates GitHub actually knows about.  Paths GitHub
        does not report are simply absent: there is nothing to suspend.
        """
        wanted = set(self.hosted_duplicates(repository))
        if not wanted:
            return {}
        raw = run_checked(
            ["gh", "api", f"repos/{repository}/actions/workflows?per_page=100"],
            timeout=30,
        )
        try:
            value = json.loads(raw)
            entries = value["workflows"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AgentOperatorError(
                "hosted_workflow_unavailable", "GitHub workflow listing is invalid"
            ) from exc
        observed: dict[str, dict[str, Any]] = {}
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or entry.get("path") not in wanted:
                continue
            identifier, state = entry.get("id"), entry.get("state")
            if (
                isinstance(identifier, bool)
                or not isinstance(identifier, int)
                or identifier < 1
                or not isinstance(state, str)
            ):
                raise AgentOperatorError(
                    "hosted_workflow_unavailable", "GitHub workflow entry is invalid"
                )
            if entry["path"] in observed:
                raise AgentOperatorError(
                    "hosted_workflow_unavailable", "GitHub reported an ambiguous workflow path"
                )
            observed[entry["path"]] = {"id": identifier, "state": state}
        return observed

    def _set_hosted_workflow(
        self, repository: str, workflow_id: int, *, enabled: bool
    ) -> None:
        """Suspend or restore one exact hosted workflow by its numeric identity.

        The workflow file itself is never read, edited or deleted; only its
        Actions enablement flag changes, which is what keeps the reviewed
        `source_workflow_sha256` of the repository command profile intact.
        """
        action = "enable" if enabled else "disable"
        run_checked(
            [
                "gh", "api", "--method", "PUT",
                f"repos/{repository}/actions/workflows/{workflow_id}/{action}",
            ],
            timeout=30,
        )

    def _converge_hosted_workflows(
        self, repository: str, *, enabled: bool, only: Sequence[str] | None = None
    ) -> list[str]:
        """Drive the exact hosted duplicates to one state and prove the result.

        `only` restricts the operation to paths this operator previously
        suspended, so restoring never enables a workflow somebody else turned
        off.  Returns the paths whose observed state is the requested one.
        """
        target = HOSTED_ACTIVE_STATE if enabled else HOSTED_DISABLED_STATE
        observed = self._hosted_workflows(repository)
        selected = {
            path: entry
            for path, entry in observed.items()
            if only is None or path in set(only)
        }
        transitioned = []
        for path, entry in sorted(selected.items()):
            if entry["state"] == target:
                continue
            self._set_hosted_workflow(repository, entry["id"], enabled=enabled)
            transitioned.append(path)
        confirmed = self._hosted_workflows(repository)
        for path in sorted(selected):
            if confirmed.get(path, {}).get("state") != target:
                raise AgentOperatorError(
                    "hosted_workflow_postcondition_failed",
                    "GitHub-hosted duplicate did not reach its requested state",
                    details={"workflow": path, "expected_state": target},
                )
        return transitioned

    def _render_workflow(self, authority: Mapping[str, Any]) -> bytes:
        organization = authority["authority_kind"] == "organization-runner-group"
        template_name = (
            "ci-jit-pilot-child.yml"
            if organization
            else "ci-jit-pilot-child-personal.yml"
        )
        template = Path(__file__).resolve().parents[1] / "templates/workflows" / template_name
        if not template.is_file():
            raise AgentOperatorError("distribution_incomplete", "managed workflow template is absent")
        rendered = template.read_text(encoding="utf-8").replace(
            f"{DEFAULT_PUBLIC_REPOSITORY}/", f"{self.host.public_repository}/"
        ).replace("@" + "0" * 40, "@" + self.host.public_sha)
        if organization:
            profile = (
                Path(__file__).resolve().parents[1]
                / "repository_profiles/overworld/profile.json"
            )
            if not profile.is_file():
                raise AgentOperatorError(
                    "distribution_incomplete", "Overworld command profile is absent"
                )
            rendered = rendered.replace(
                "__SELF_HOSTED_CI_EXACT_RUNNER_GROUP__", authority["runner_group"]
            ).replace(
                "__OVERWORLD_PROFILE_SHA256__",
                hashlib.sha256(profile.read_bytes()).hexdigest(),
            )
        if (
            "0" * 40 in rendered
            or "__SELF_HOSTED_CI_EXACT_RUNNER_GROUP__" in rendered
            or "__OVERWORLD_PROFILE_SHA256__" in rendered
            or f"{DEFAULT_PUBLIC_REPOSITORY}/" in rendered
            and self.host.public_repository != DEFAULT_PUBLIC_REPOSITORY
        ):
            raise AgentOperatorError("distribution_incomplete", "workflow rendering left a placeholder")
        return rendered.encode()

    def _github_pr(self, repository: str, pr: int) -> dict[str, Any]:
        raw = run_checked([
            "gh", "api", f"repos/{repository}/pulls/{pr}", "--jq",
            "{number:.number,state:.state,headSha:.head.sha,headRepo:.head.repo.full_name}",
        ], timeout=30)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgentOperatorError("github_pr_unavailable", "GitHub PR response is invalid") from exc
        if (
            value.get("number") != pr
            or value.get("state") != "open"
            or not FULL_SHA.fullmatch(str(value.get("headSha", "")))
            or not isinstance(value.get("headRepo"), str)
            or value["headRepo"].lower() != repository.lower()
        ):
            raise AgentOperatorError(
                "github_pr_unavailable",
                "PR must be an exact open target whose head belongs to the opted-in repository",
            )
        return value

    @staticmethod
    def _workflow_owned(state: Mapping[str, Any], workflow: Mapping[str, Any] | None) -> bool:
        return bool(
            workflow is not None
            and state.get("managed_workflow") == MANAGED_WORKFLOW
            and state.get("workflow_blob_sha") == workflow.get("sha")
            and state.get("workflow_content_sha256") == workflow.get("content_sha256")
        )

    def _reconcile_pending(
        self,
        repository: str,
        registry: dict[str, Any],
        workflow: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], bool]:
        state = registry["repositories"].get(repository)
        pending = state.get("pending") if isinstance(state, dict) else None
        if not isinstance(pending, dict):
            return registry, False
        operation = pending["operation"]
        if operation == "use-local":
            expected = pending["expected_workflow_sha256"]
            if workflow is None or workflow.get("content_sha256") != expected:
                return registry, False
            state.update({
                "ci_runner": "local-with-github-fallback",
                "managed_workflow": MANAGED_WORKFLOW,
                "workflow_blob_sha": workflow["sha"],
                "workflow_content_sha256": workflow["content_sha256"],
                "updated_at": utc_now(),
            })
        elif operation == "use-github":
            if workflow is not None:
                return registry, False
            state.clear()
            state.update({"ci_runner": "github", "updated_at": utc_now()})
        else:
            raise AgentOperatorError("invalid_registry", "unknown pending operation")
        state.pop("pending", None)
        self.store.save(registry)
        self.store.append_audit({
            "at": utc_now(), "operation": operation, "repository": repository,
            "result": "reconciled",
        })
        return registry, True

    def status(self, repository: str) -> dict[str, Any]:
        repository = exact_repository(repository)
        workflow = self._workflow(repository)
        with self.store.locked():
            registry = self.store.load()
            registry, reconciled = self._reconcile_pending(repository, registry, workflow)
            state = registry["repositories"].get(repository, {"ci_runner": "github"})
        try:
            authority = self._remote_worker_config()
            health = self._health()
            host_error = None
        except AgentOperatorError as exc:
            authority = {"repository": None}
            health = {
                "eligible": False,
                "blockers": ["host_status_unavailable"],
                "generated_at": None,
                "probe_error": exc.code,
            }
            host_error = {"code": exc.code, "message": str(exc)}
        owned = self._workflow_owned(state, workflow)
        recorded = set(state.get("hosted_workflows_disabled") or [])
        try:
            hosted = self._hosted_workflows(repository)
        except AgentOperatorError as exc:
            hosted = {}
            host_error = host_error or {"code": exc.code, "message": str(exc)}
        hosted_report = [
            {
                "path": path,
                "state": hosted.get(path, {}).get("state", "absent"),
                "suspended_by_operator": path in recorded,
            }
            for path in sorted(self.hosted_duplicates(repository))
        ]
        return {
            "status": "ok",
            "hosted_duplicates": hosted_report,
            "hosted_duplicates_suspended": all(
                entry["state"] == HOSTED_DISABLED_STATE for entry in hosted_report
            ) if hosted_report else None,
            "repository": repository,
            "desired_ci_runner": state["ci_runner"],
            "effective_local": (
                state["ci_runner"] == "local-with-github-fallback"
                and isinstance(authority["repository"], str)
                and authority["repository"].lower() == repository.lower()
                and owned
                and health["eligible"]
            ),
            "managed_workflow_present": workflow is not None,
            "managed_workflow_owned": owned,
            "pending_operation": state.get("pending", {}).get("operation"),
            "pending_reconciled_during_this_status_call": reconciled,
            "authority_repository": authority["repository"],
            "health": health,
            "host_error": host_error,
        }

    def use_local(self, repository: str, *, apply: bool) -> dict[str, Any]:
        repository = exact_repository(repository)
        github = self._github_repository(repository)
        authority = self._remote_worker_config()
        health = self._health()
        blockers: list[str] = []
        if authority["repository"].lower() != repository.lower() or authority["repository_id"] != github["id"]:
            blockers.append("selected_repository_authority_missing")
        if authority["default_branch"] != github["defaultBranch"]:
            blockers.append("default_branch_authority_mismatch")
        if not health["eligible"]:
            blockers.append("windows_host_ineligible")
        workflow = self._workflow(repository)
        rendered = self._render_workflow(authority)
        expected_digest = hashlib.sha256(rendered).hexdigest()
        with self.store.locked():
            registry = self.store.load()
            current = registry["repositories"].get(repository, {"ci_runner": "github"})
        if workflow is not None and not (
            workflow.get("content_sha256") == expected_digest
            or self._workflow_owned(current, workflow)
        ):
            blockers.append("managed_workflow_ownership_unverified")
        hosted = self._hosted_workflows(repository)
        changes = (
            [] if workflow is not None and workflow.get("content_sha256") == expected_digest
            else [f"install:{MANAGED_WORKFLOW}"]
        )
        changes += [
            f"suspend-hosted:{path}"
            for path, entry in sorted(hosted.items())
            if entry["state"] != HOSTED_DISABLED_STATE
        ]
        plan = {
            "operation": "use-local",
            "repository": repository,
            "apply_requested": apply,
            "blockers": blockers,
            "changes": changes,
            "hosted_duplicates": list(self.hosted_duplicates(repository)),
            "persistent_scope": "exact-repository-only",
        }
        if blockers or not apply:
            plan["status"] = "blocked" if blockers else "planned"
            return plan
        with self.store.locked():
            registry = self.store.load()
            previous = registry["repositories"].get(repository, {"ci_runner": "github"})
            if previous.get("pending") is not None:
                raise AgentOperatorError(
                    "routing_transaction_pending",
                    "an earlier routing transaction must reconcile before another mutation",
                )
            registry["repositories"][repository] = {
                **previous,
                "pending": {
                    "operation": "use-local",
                    "started_at": utc_now(),
                    "expected_workflow_sha256": expected_digest,
                    "previous_ci_runner": previous["ci_runner"],
                },
            }
            self.store.save(registry)
            self.store.append_audit({
                "at": utc_now(), "operation": "use-local", "repository": repository,
                "result": "intent-recorded", "public_sha": self.host.public_sha,
            })
        encoded = base64.b64encode(rendered).decode()
        fields = [
            "-f", f"message=chore: enable selected local JIT CI",
            "-f", f"content={encoded}",
            "-f", f"branch={github['defaultBranch']}",
        ]
        if workflow is not None:
            fields += ["-f", f"sha={workflow['sha']}"]
        run_checked(["gh", "api", "--method", "PUT", f"repos/{repository}/contents/{MANAGED_WORKFLOW}", *fields], timeout=45)
        installed = self._workflow(repository)
        if installed is None or installed.get("content_sha256") != expected_digest:
            raise AgentOperatorError("workflow_postcondition_failed", "managed workflow content did not converge")
        with self.store.locked():
            registry = self.store.load()
            state = registry["repositories"].get(repository, {})
            state.update({
                "repository_id": github["id"],
                "authority_installation_id": authority["installation_id"],
                "public_sha": self.host.public_sha,
            })
            registry, reconciled = self._reconcile_pending(repository, registry, installed)
            if not reconciled:
                raise AgentOperatorError("registry_postcondition_failed", "local routing transaction did not reconcile")
        # The hosted duplicates are suspended only after the local dispatch
        # surface exists, so the repository is never left with no CI at all.
        suspended = self._converge_hosted_workflows(repository, enabled=False)
        applied_changes = [f"installed:{MANAGED_WORKFLOW}"]
        applied_changes += [f"suspended-hosted:{path}" for path in suspended]
        with self.store.locked():
            registry = self.store.load()
            state = registry["repositories"].setdefault(repository, {"ci_runner": "github"})
            recorded = sorted(set(state.get("hosted_workflows_disabled") or []) | set(suspended))
            if recorded:
                state["hosted_workflows_disabled"] = recorded
                state["updated_at"] = utc_now()
                self.store.save(registry)
                self.store.append_audit({
                    "at": utc_now(), "operation": "use-local", "repository": repository,
                    "result": "hosted-duplicates-suspended", "workflows": recorded,
                })
        return {**plan, "status": "applied", "changes": applied_changes}

    def use_github(self, repository: str, *, apply: bool) -> dict[str, Any]:
        repository = exact_repository(repository)
        github = self._github_repository(repository)
        workflow = self._workflow(repository)
        with self.store.locked():
            registry = self.store.load()
            current = registry["repositories"].get(repository, {"ci_runner": "github"})
        if workflow is not None and not self._workflow_owned(current, workflow):
            return {
                "operation": "use-github", "repository": repository,
                "apply_requested": apply, "status": "blocked",
                "blockers": ["managed_workflow_ownership_unverified"],
                "resulting_ci_runner": "github",
            }
        restorable = sorted(set(current.get("hosted_workflows_disabled") or []))
        plan = {
            "operation": "use-github",
            "repository": repository,
            "apply_requested": apply,
            "changes": (
                ([] if workflow is None else [f"delete:{MANAGED_WORKFLOW}"])
                + [f"restore-hosted:{path}" for path in restorable]
            ),
            "resulting_ci_runner": "github",
        }
        if not apply:
            return {**plan, "status": "planned"}
        with self.store.locked():
            registry = self.store.load()
            previous = registry["repositories"].get(repository, {"ci_runner": "github"})
            if previous.get("pending") is not None:
                raise AgentOperatorError(
                    "routing_transaction_pending",
                    "an earlier routing transaction must reconcile before another mutation",
                )
            registry["repositories"][repository] = {
                **previous,
                "pending": {
                    "operation": "use-github",
                    "started_at": utc_now(),
                    "expected_workflow_sha256": None,
                    "previous_ci_runner": previous["ci_runner"],
                },
            }
            self.store.save(registry)
            self.store.append_audit({
                "at": utc_now(), "operation": "use-github", "repository": repository,
                "result": "intent-recorded",
            })
        # Restore the hosted duplicates this operator suspended before the local
        # dispatch surface disappears, so quality coverage is never interrupted.
        # Only recorded paths are touched: a workflow somebody else disabled by
        # hand stays disabled.
        if restorable:
            self._converge_hosted_workflows(repository, enabled=True, only=restorable)
            with self.store.locked():
                registry = self.store.load()
                state = registry["repositories"].get(repository)
                if isinstance(state, dict):
                    state.pop("hosted_workflows_disabled", None)
                    state["updated_at"] = utc_now()
                    self.store.save(registry)
            self.store.append_audit({
                "at": utc_now(), "operation": "use-github", "repository": repository,
                "result": "hosted-duplicates-restored", "workflows": restorable,
            })
        # GitHub-first: remove dispatch surface before changing local state.
        if workflow is not None:
            run_checked([
                "gh", "api", "--method", "DELETE", f"repos/{repository}/contents/{MANAGED_WORKFLOW}",
                "-f", "message=chore: return CI routing to GitHub-hosted",
                "-f", f"sha={workflow['sha']}", "-f", f"branch={github['defaultBranch']}",
            ], timeout=45)
        if self._workflow(repository) is not None:
            raise AgentOperatorError("workflow_postcondition_failed", "managed workflow still exists")
        with self.store.locked():
            registry = self.store.load()
            registry, reconciled = self._reconcile_pending(repository, registry, None)
            if not reconciled:
                raise AgentOperatorError("registry_postcondition_failed", "GitHub routing transaction did not reconcile")
        return {**plan, "status": "applied"}

    def run_local(self, repository: str, pr: int, *, apply: bool) -> dict[str, Any]:
        repository, pr = exact_repository(repository), exact_pr(pr)
        status = self.status(repository)
        if not status["effective_local"]:
            return {
                "status": "blocked",
                "operation": "run-local",
                "repository": repository,
                "pr": pr,
                "blockers": ["repository_not_effectively_local"],
            }
        target = self._github_pr(repository, pr)
        plan = {
            "status": "planned",
            "operation": "run-local",
            "repository": repository,
            "pr": pr,
            "head_sha": target["headSha"],
            "apply_requested": apply,
            "persistent_routing_changed": False,
        }
        if not apply:
            return plan
        command = (
            f'wsl.exe -d {self.host.distro} -u root -- '
            f'/usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py approve '
            f'--repository {repository} --pr {pr}'
        )
        raw = self._ssh(command)
        try:
            receipt = json.loads(raw)
        except json.JSONDecodeError:
            raise AgentOperatorError("approval_receipt_invalid", "host approval receipt is not JSON")
        request_id = receipt.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise AgentOperatorError("approval_receipt_invalid", "host approval receipt omitted request identity")
        status_raw = self._ssh(
            f'wsl.exe -d {self.host.distro} -u root -- '
            f'/usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py status '
            f'--repository {repository} --pr {pr}'
        )
        try:
            approvals = json.loads(status_raw).get("approvals")
        except (json.JSONDecodeError, AttributeError) as exc:
            raise AgentOperatorError("approval_receipt_invalid", "host approval status is invalid") from exc
        matches = [
            item for item in approvals or []
            if isinstance(item, dict)
            and item.get("request_id") == request_id
            and item.get("repository") == repository
            and item.get("pr_number") == pr
            and item.get("head_sha") == target["headSha"]
            and item.get("state") in {"pending", "claimed", "completed"}
        ]
        if len(matches) != 1:
            raise AgentOperatorError("approval_target_mismatch", "host approval did not bind the exact PR head")
        with self.store.locked():
            self.store.append_audit({
                "at": utc_now(), "operation": "run-local", "repository": repository,
                "pr": pr, "head_sha": target["headSha"], "request_id": request_id,
                "result": "approved-exact-target",
            })
        return {**plan, "status": "approved", "receipt": matches[0]}


def resolve_current_repository() -> str:
    raw = run_checked(["git", "remote", "get-url", "origin"], timeout=10).strip()
    match = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?$", raw)
    if not match:
        raise AgentOperatorError("repository_unresolved", "origin is not an exact GitHub repository")
    return exact_repository(f"{match.group(1)}/{match.group(2)}")
