"""Exact, repository-scoped GitHub App authority for the outbound worker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
WORKER_PERMISSIONS = {"metadata": "read", "pull_requests": "read", "actions": "write"}
MAX_TOKEN_TTL = timedelta(hours=1)
TOKEN_SAFETY_MARGIN = timedelta(seconds=30)
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA = re.compile(r"[0-9a-f]{40}")


class WorkerAuthorityError(RuntimeError):
    """A local or remote worker authority boundary could not be proven."""


@dataclass(frozen=True)
class WorkerAppAuthorityV1:
    app_id: int
    app_slug: str
    installation_id: int
    repository: str
    repository_id: int
    repository_selection: str
    default_branch: str
    workflow_id: str
    workflow_path: str
    permissions: Mapping[str, str]

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (
            self.app_id, self.installation_id, self.repository_id,
        )):
            raise WorkerAuthorityError("worker App numeric identities must be positive integers")
        if not _REPOSITORY.fullmatch(self.repository):
            raise WorkerAuthorityError("worker App repository is invalid")
        if self.repository_selection != "selected":
            raise WorkerAuthorityError("worker App must use selected repositories")
        if dict(self.permissions) != WORKER_PERMISSIONS:
            raise WorkerAuthorityError("worker App permissions are not exact")
        if not re.fullmatch(r"[A-Za-z0-9-]+", self.app_slug):
            raise WorkerAuthorityError("worker App slug is invalid")
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", self.default_branch) or self.default_branch.startswith("/"):
            raise WorkerAuthorityError("worker default branch is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", self.workflow_id):
            raise WorkerAuthorityError("worker workflow ID must be one fixed workflow filename")
        if self.workflow_path != f".github/workflows/{self.workflow_id}":
            raise WorkerAuthorityError("worker workflow path does not match its fixed ID")


@dataclass(frozen=True, repr=False)
class WorkerInstallationToken:
    value: str = field(repr=False)
    expires_at: datetime
    authority: WorkerAppAuthorityV1

    def assert_current(self, authority: WorkerAppAuthorityV1, now: datetime) -> None:
        if authority != self.authority or now.tzinfo is None or self.expires_at <= now:
            raise WorkerAuthorityError("worker installation token is expired or crossed authority")


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes


class HTTPTransport(Protocol):
    def request(
        self, method: str, url: str, *, headers: Mapping[str, str],
        json_body: Mapping[str, object] | None = None,
    ) -> HTTPResponse: ...


class RS256Signer(Protocol):
    def sign(self, value: bytes) -> bytes: ...


class RootPrivateKeySigner:
    """Load a root-owned 0600 RSA key directly into private memory."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._key = key

    @classmethod
    def from_file(cls, path: Path) -> "RootPrivateKeySigner":
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 65_536
                ):
                    raise WorkerAuthorityError("worker App private key must be root-owned regular 0600")
                key_bytes = os.read(descriptor, 65_537)
                if len(key_bytes) != info.st_size:
                    raise WorkerAuthorityError("worker App private key changed while reading")
            finally:
                os.close(descriptor)
            key = serialization.load_pem_private_key(key_bytes, password=None)
        except WorkerAuthorityError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise WorkerAuthorityError("worker App private key is invalid") from exc
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise WorkerAuthorityError("worker App private key must be RSA 2048-bit or stronger")
        return cls(key)

    def sign(self, value: bytes) -> bytes:
        return self._key.sign(value, padding.PKCS1v15(), hashes.SHA256())


class WorkerGitHubClient:
    """Minimal fixed-endpoint client for one selected repository."""

    def __init__(
        self, authority: WorkerAppAuthorityV1, signer: RS256Signer,
        transport: HTTPTransport, *, api_root: str = API_ROOT,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if api_root != API_ROOT:
            raise WorkerAuthorityError("worker GitHub API root is not fixed")
        self.authority = authority
        self._signer = signer
        self._transport = transport
        self._clock = clock

    def authenticate(self) -> WorkerInstallationToken:
        now = self._clock()
        if now.tzinfo is None:
            raise WorkerAuthorityError("worker clock must be timezone-aware")
        jwt = self._app_jwt(now)
        app_headers = self._headers(jwt)
        app = self._json(self._request("GET", "/app", app_headers), 200)
        if app.get("id") != self.authority.app_id or app.get("slug") != self.authority.app_slug:
            raise WorkerAuthorityError("GitHub App identity mismatch")
        installation = self._json(self._request(
            "GET", f"/repos/{self.authority.repository}/installation", app_headers,
        ), 200)
        expected_installation = {
            "id": self.authority.installation_id,
            "app_id": self.authority.app_id,
            "repository_selection": "selected",
            "permissions": WORKER_PERMISSIONS,
        }
        if any(installation.get(key) != value for key, value in expected_installation.items()):
            raise WorkerAuthorityError("GitHub App installation authority mismatch")
        token_data = self._json(self._request(
            "POST", f"/app/installations/{self.authority.installation_id}/access_tokens",
            app_headers, {
                "repository_ids": [self.authority.repository_id],
                "permissions": dict(WORKER_PERMISSIONS),
            },
        ), 201)
        return self._parse_token(token_data, now)

    def repository(self, token: WorkerInstallationToken) -> Mapping[str, Any]:
        value = self._token_json("GET", f"/repos/{self.authority.repository}", token, 200)
        if (
            value.get("id") != self.authority.repository_id
            or value.get("full_name") != self.authority.repository
            or value.get("default_branch") != self.authority.default_branch
        ):
            raise WorkerAuthorityError("selected repository identity mismatch")
        return value

    def pull_request(self, number: int, token: WorkerInstallationToken) -> Mapping[str, Any]:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise WorkerAuthorityError("pull request number must be positive")
        value = self._token_json("GET", f"/repos/{self.authority.repository}/pulls/{number}", token, 200)
        head, base = value.get("head"), value.get("base")
        if (
            value.get("number") != number or value.get("state") != "open"
            or not isinstance(head, Mapping) or not _SHA.fullmatch(str(head.get("sha", "")))
            or not isinstance(base, Mapping) or base.get("ref") != self.authority.default_branch
            or not isinstance(base.get("repo"), Mapping)
            or base["repo"].get("id") != self.authority.repository_id
        ):
            raise WorkerAuthorityError("pull request identity mismatch")
        return value

    def workflow(self, token: WorkerInstallationToken) -> Mapping[str, Any]:
        workflow = quote(self.authority.workflow_id, safe="")
        value = self._token_json(
            "GET", f"/repos/{self.authority.repository}/actions/workflows/{workflow}", token, 200,
        )
        if value.get("path") != self.authority.workflow_path or value.get("state") != "active":
            raise WorkerAuthorityError("fixed worker workflow identity mismatch")
        return value

    def dispatch(self, protocol_package: str, token: WorkerInstallationToken) -> int:
        return self._dispatch_exact("protocol_package", protocol_package, token)

    def dispatch_pilot(self, pilot_package: str, token: WorkerInstallationToken) -> int:
        """Dispatch only the fixed pilot workflow with its distinct input name."""
        if self.authority.workflow_id != "ci-jit-pilot-child.yml":
            raise WorkerAuthorityError("pilot dispatch requires the fixed pilot workflow")
        return self._dispatch_exact("pilot_package", pilot_package, token)

    def _dispatch_exact(self, input_name: str, package: str, token: WorkerInstallationToken) -> int:
        if input_name not in {"protocol_package", "pilot_package"}:
            raise WorkerAuthorityError("workflow dispatch input is not supported")
        if not isinstance(package, str) or not package or len(package.encode()) > 60_000:
            raise WorkerAuthorityError("workflow package is absent or oversized")
        workflow = quote(self.authority.workflow_id, safe="")
        value = self._token_json(
            "POST", f"/repos/{self.authority.repository}/actions/workflows/{workflow}/dispatches",
            token, 200, {
                "ref": self.authority.default_branch,
                "inputs": {input_name: package},
                "return_run_details": True,
            },
        )
        run_id = value.get("workflow_run_id")
        if (
            isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1
            or value.get("run_url") != f"{API_ROOT}/repos/{self.authority.repository}/actions/runs/{run_id}"
        ):
            raise WorkerAuthorityError("workflow dispatch receipt is not exact")
        return run_id

    def run(self, run_id: int, token: WorkerInstallationToken) -> Mapping[str, Any]:
        self._positive_id(run_id, "run")
        value = self._token_json("GET", f"/repos/{self.authority.repository}/actions/runs/{run_id}", token, 200)
        if (
            value.get("id") != run_id
            or not isinstance(value.get("repository"), Mapping)
            or value["repository"].get("id") != self.authority.repository_id
            or value.get("path") not in {
                self.authority.workflow_path,
                f"{self.authority.workflow_path}@refs/heads/{self.authority.default_branch}",
            }
            or value.get("head_branch") != self.authority.default_branch
        ):
            raise WorkerAuthorityError("workflow run crossed repository authority")
        return value

    def jobs(self, run_id: int, token: WorkerInstallationToken) -> Mapping[str, Any]:
        self._positive_id(run_id, "run")
        value = self._token_json(
            "GET", f"/repos/{self.authority.repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100",
            token, 200,
        )
        if set(value) != {"total_count", "jobs"} or not isinstance(value["total_count"], int) or not isinstance(value["jobs"], list):
            raise WorkerAuthorityError("workflow jobs response is invalid")
        if value["total_count"] != len(value["jobs"]) or any(not isinstance(job, Mapping) or job.get("run_id") != run_id for job in value["jobs"]):
            raise WorkerAuthorityError("workflow jobs crossed or truncated the exact run")
        return value

    def _token_json(self, method: str, path: str, token: WorkerInstallationToken, status: int, body: Mapping[str, object] | None = None) -> Mapping[str, Any]:
        token.assert_current(self.authority, self._clock())
        return self._json(self._request(method, path, self._headers(token.value), body), status)

    def _parse_token(self, value: Mapping[str, Any], now: datetime) -> WorkerInstallationToken:
        token = value.get("token")
        try:
            expires_at = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        except (AttributeError, KeyError, ValueError) as exc:
            raise WorkerAuthorityError("worker installation token expiry is invalid") from exc
        repositories = value.get("repositories")
        repository = repositories[0] if isinstance(repositories, list) and len(repositories) == 1 else None
        if (
            not isinstance(token, str) or not token or any(character.isspace() for character in token)
            or value.get("permissions") != WORKER_PERMISSIONS
            or not isinstance(repository, Mapping)
            or repository.get("id") != self.authority.repository_id
            or repository.get("full_name") != self.authority.repository
            or expires_at.tzinfo is None or not now < expires_at <= now + MAX_TOKEN_TTL
        ):
            raise WorkerAuthorityError("worker installation token authority mismatch")
        return WorkerInstallationToken(token, expires_at - TOKEN_SAFETY_MARGIN, self.authority)

    def _app_jwt(self, now: datetime) -> str:
        def b64(value: bytes) -> str:
            return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        header = b64(b'{"alg":"RS256","typ":"JWT"}')
        payload = b64(json.dumps({
            "exp": int(now.timestamp()) + 540,
            "iat": int(now.timestamp()) - 60,
            "iss": str(self.authority.app_id),
        }, sort_keys=True, separators=(",", ":")).encode("ascii"))
        signing_input = f"{header}.{payload}".encode("ascii")
        return f"{header}.{payload}.{b64(self._signer.sign(signing_input))}"

    def _request(self, method: str, path: str, headers: Mapping[str, str], body: Mapping[str, object] | None = None) -> HTTPResponse:
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise WorkerAuthorityError("unsafe worker GitHub API path")
        return self._transport.request(method, API_ROOT + path, headers=headers, json_body=body)

    @staticmethod
    def _headers(bearer: str) -> Mapping[str, str]:
        return {
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {bearer}",
            "X-GitHub-Api-Version": API_VERSION, "User-Agent": "self-hosted-ci-worker/1",
        }

    @staticmethod
    def _json(response: HTTPResponse, expected_status: int) -> Mapping[str, Any]:
        if response.status != expected_status or not response.body or len(response.body) > 1_048_576:
            raise WorkerAuthorityError("GitHub worker request failed")
        try:
            def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, item in pairs:
                    if key in result:
                        raise WorkerAuthorityError("GitHub worker response contains duplicate keys")
                    result[key] = item
                return result
            value = json.loads(response.body, object_pairs_hook=exact_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerAuthorityError("GitHub worker response is invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise WorkerAuthorityError("GitHub worker response is not an object")
        return value

    @staticmethod
    def _positive_id(value: int, name: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise WorkerAuthorityError(f"{name} ID must be positive")
