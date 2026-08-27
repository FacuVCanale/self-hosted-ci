"""Fail-closed HTTP adapters for the two GitHub control-plane authorities.

The trusted workflow ``GITHUB_TOKEN`` and the dedicated checks-only GitHub App
installation token are intentionally represented by different types and
accepted by different transports.  This makes credential crossing a local
control failure before an HTTP request can be emitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import base64
import http.client
import json
import os
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .check_delivery import AmbiguousCheckWrite
from .github import (
    AppAuthorityV1,
    ControlFailure,
    DispatchRequest,
    MINIMUM_APP_PERMISSIONS,
    MintRequest,
    PINNED_GITHUB_API_VERSION,
    ProtocolFailure,
    RuntimeIdentity,
    parse_dispatch_response,
    parse_observed_workflow_job,
    ObservedWorkflowJob,
    WorkflowJobPending,
)


GITHUB_API = "https://api.github.com"
ACTIONS_TOKEN_PERMISSIONS = {"actions": "write"}
INSTALLATION_TOKEN_MAX_TTL = timedelta(hours=1)
INSTALLATION_TOKEN_CLOCK_SKEW = timedelta(minutes=2)
INSTALLATION_TOKEN_SAFETY_MARGIN = timedelta(seconds=30)


class GitHubAdapterError(RuntimeError):
    """An HTTP response or local credential state cannot be trusted."""


class GitHubHTTPError(GitHubAdapterError):
    def __init__(self, status: int, message: str = "GitHub API request failed") -> None:
        super().__init__(f"{message}: HTTP {status}")
        self.status = status


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None = None,
    ) -> HTTPResponse: ...


class UrllibHTTPTransport:
    """Small production HTTP transport; policy remains in the typed clients."""

    def __init__(self, *, timeout_seconds: float = 15.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout = timeout_seconds

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        data = None
        request_headers = dict(headers)
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=request_headers, method=method)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                return HTTPResponse(response.status, response.read(), dict(response.headers.items()))
        except HTTPError as exc:
            try:
                return HTTPResponse(exc.code, exc.read(), dict(exc.headers.items()))
            except (
                URLError,
                TimeoutError,
                ConnectionResetError,
                http.client.HTTPException,
                OSError,
            ) as read_exc:
                raise GitHubAdapterError("GitHub API transport failed") from read_exc
        except (
            URLError,
            TimeoutError,
            ConnectionResetError,
            http.client.HTTPException,
            OSError,
        ) as exc:
            raise GitHubAdapterError("GitHub API transport failed") from exc


@dataclass(frozen=True, repr=False)
class GitHubActionsToken:
    value: str = field(repr=False)
    repository: str
    workflow_identity: str
    workflow_ref: str
    permissions: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.value or any(character.isspace() for character in self.value):
            raise ControlFailure("GITHUB_TOKEN is empty or malformed")
        if dict(self.permissions) != ACTIONS_TOKEN_PERMISSIONS:
            raise ControlFailure("GITHUB_TOKEN permissions must be exactly actions:write")


@dataclass(frozen=True, repr=False)
class InstallationToken:
    value: str = field(repr=False)
    expires_at: datetime
    repository: str
    repository_id: int
    installation_id: int
    permissions: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.value or any(character.isspace() for character in self.value):
            raise ControlFailure("installation token is empty or malformed")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ControlFailure("installation token expiry must be timezone-aware")
        if dict(self.permissions) != MINIMUM_APP_PERMISSIONS:
            raise ControlFailure("installation token permissions are not exactly checks-only")
        if isinstance(self.repository_id, bool) or self.repository_id < 1:
            raise ControlFailure("installation token repository_id must be positive")
        if isinstance(self.installation_id, bool) or self.installation_id < 1:
            raise ControlFailure("installation token installation_id must be positive")

    def assert_current(self, authority: AppAuthorityV1, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ControlFailure("current time must be timezone-aware")
        if (
            self.expires_at <= now
            or self.repository != authority.repository
            or self.repository_id != authority.repository_id
            or self.installation_id != authority.installation_id
            or dict(self.permissions) != dict(authority.permissions)
            or authority.key_state != "active"
        ):
            raise ControlFailure("installation token is expired or outside exact authority")


class RS256Signer(Protocol):
    def sign(self, signing_input: bytes) -> bytes: ...


class OpenSSLRS256Signer:
    """RS256 signer that passes the private key through an inherited pipe."""

    def __init__(self, private_key_pem: bytes, *, executable: str = "openssl") -> None:
        if b"PRIVATE KEY" not in private_key_pem:
            raise ControlFailure("GitHub App private key is malformed")
        self._private_key_pem = private_key_pem
        self._executable = executable

    def sign(self, signing_input: bytes) -> bytes:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, self._private_key_pem)
            os.close(write_fd)
            write_fd = -1
            completed = subprocess.run(
                [self._executable, "dgst", "-sha256", "-sign", f"/dev/fd/{read_fd}"],
                input=signing_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                pass_fds=(read_fd,),
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ControlFailure("GitHub App JWT signing failed") from exc
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
        if completed.returncode or not completed.stdout:
            raise ControlFailure("GitHub App JWT signing failed")
        return completed.stdout


class GitHubAppAuthenticator:
    """Validate exact App/install/repository authority and mint a memory token."""

    def __init__(
        self,
        authority: AppAuthorityV1,
        identity: RuntimeIdentity,
        signer: RS256Signer,
        http: HTTPTransport,
        *,
        api_url: str = GITHUB_API,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._api_url = _exact_api_url(api_url)
        self._authority = authority
        self._identity = identity
        self._signer = signer
        self._http = http
        self._clock = clock

    def mint(self, request: MintRequest) -> InstallationToken:
        self._authority.mint(self._identity, request)
        now = self._clock()
        jwt = self._app_jwt(now)
        app_headers = self._headers(jwt)

        app = self._json(self._request("GET", "/app", app_headers), expected_status=200)
        self._validate_app(app)
        installation = self._json(
            self._request(
                "GET",
                f"/repos/{self._authority.repository}/installation",
                app_headers,
            ),
            expected_status=200,
        )
        self._validate_installation(installation)

        token_response = self._json(
            self._request(
                "POST",
                f"/app/installations/{self._authority.installation_id}/access_tokens",
                app_headers,
                {
                    "repository_ids": [self._authority.repository_id],
                    "permissions": dict(MINIMUM_APP_PERMISSIONS),
                },
            ),
            expected_status=201,
        )
        token = self._parse_token(token_response, request, now)
        repository = self._json(
            self._request(
                "GET",
                f"/repos/{self._authority.repository}",
                self._headers(token.value),
            ),
            expected_status=200,
        )
        if repository.get("id") != self._authority.repository_id or repository.get("full_name") != self._authority.repository:
            raise ControlFailure("installation token repository identity mismatch")
        return token

    def _app_jwt(self, now: datetime) -> str:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ControlFailure("JWT clock must be timezone-aware")
        issued_at = int(now.timestamp()) - 60
        header = _b64json({"alg": "RS256", "typ": "JWT"})
        claims = _b64json({"iat": issued_at, "exp": issued_at + 600, "iss": str(self._authority.app_id)})
        signing_input = f"{header}.{claims}".encode("ascii")
        signature = _b64(self._signer.sign(signing_input))
        if not signature:
            raise ControlFailure("GitHub App JWT signature is empty")
        return f"{header}.{claims}.{signature}"

    def _validate_app(self, app: Mapping[str, Any]) -> None:
        if (
            app.get("id") != self._authority.app_id
            or app.get("slug") != self._authority.app_slug
            or app.get("owner", {}).get("login") != self._authority.owner
            or app.get("permissions") != dict(MINIMUM_APP_PERMISSIONS)
        ):
            raise ControlFailure("authenticated GitHub App authority mismatch")

    def _validate_installation(self, installation: Mapping[str, Any]) -> None:
        if (
            installation.get("id") != self._authority.installation_id
            or installation.get("app_id") != self._authority.app_id
            or installation.get("repository_selection") != "selected"
            or installation.get("permissions") != dict(MINIMUM_APP_PERMISSIONS)
            or installation.get("suspended_at") is not None
        ):
            raise ControlFailure("GitHub App installation authority mismatch")

    def _parse_token(
        self, response: Mapping[str, Any], request: MintRequest, now: datetime
    ) -> InstallationToken:
        if response.get("permissions") != dict(MINIMUM_APP_PERMISSIONS):
            raise ControlFailure("minted installation token permissions drifted")
        repositories = response.get("repositories")
        if not isinstance(repositories, list) or len(repositories) != 1:
            raise ControlFailure("minted installation token repository scope is not exact")
        repository = repositories[0]
        if not isinstance(repository, Mapping) or repository.get("id") != self._authority.repository_id or repository.get("full_name") != self._authority.repository:
            raise ControlFailure("minted installation token repository scope mismatch")
        value = response.get("token")
        server_expires_at = _parse_timestamp(response.get("expires_at"))
        if (
            not isinstance(value, str)
            or server_expires_at <= now + INSTALLATION_TOKEN_SAFETY_MARGIN
            or server_expires_at > now + INSTALLATION_TOKEN_MAX_TTL + INSTALLATION_TOKEN_CLOCK_SKEW
        ):
            raise ControlFailure("minted installation token value or TTL is invalid")
        usable_expires_at = min(
            server_expires_at - INSTALLATION_TOKEN_SAFETY_MARGIN,
            now + timedelta(seconds=request.ttl_seconds),
        )
        if usable_expires_at <= now:
            raise ControlFailure("minted installation token has no safe usable lifetime")
        return InstallationToken(
            value,
            usable_expires_at,
            self._authority.repository,
            self._authority.repository_id,
            self._authority.installation_id,
            dict(MINIMUM_APP_PERMISSIONS),
        )

    def _request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        return self._http.request(method, self._api_url + path, headers=headers, json_body=body)

    @staticmethod
    def _headers(token: str) -> Mapping[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": PINNED_GITHUB_API_VERSION,
        }

    @staticmethod
    def _json(response: HTTPResponse, *, expected_status: int) -> Mapping[str, Any]:
        if response.status != expected_status:
            raise GitHubHTTPError(response.status)
        return _json_mapping(response.body)


class ActionsDispatchTransport:
    """Dispatch with only the trusted workflow's actions:write token."""

    def __init__(
        self,
        token: GitHubActionsToken,
        identity: RuntimeIdentity,
        http: HTTPTransport,
        *,
        api_url: str = GITHUB_API,
        observation_timeout_seconds: float = 30.0,
        observation_poll_seconds: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_url = _exact_api_url(api_url)
        if not isinstance(token, GitHubActionsToken):
            raise ControlFailure("Actions transport requires GITHUB_TOKEN authority")
        if (
            identity.role not in {"coordinator", "reconciler"}
            or identity.workflow_identity != token.workflow_identity
            or identity.workflow_ref != token.workflow_ref
            or not identity.reviewed_default_branch_code
        ):
            raise ControlFailure("Actions transport runtime identity mismatch")
        self._token = token
        self._http = http
        if observation_timeout_seconds <= 0 or observation_poll_seconds <= 0:
            raise ValueError("job observation timing must be positive")
        self._observation_timeout = observation_timeout_seconds
        self._observation_poll = observation_poll_seconds
        self._monotonic = monotonic
        self._sleeper = sleeper

    def dispatch(self, request: DispatchRequest, inputs: Mapping[str, str]) -> int:
        if not isinstance(request, DispatchRequest):
            raise ProtocolFailure("productive dispatch requires DispatchRequest")
        if dict(self._token.permissions) != ACTIONS_TOKEN_PERMISSIONS:
            raise ControlFailure("GITHUB_TOKEN permissions drifted")
        if request.repository != self._token.repository:
            raise ControlFailure("dispatch repository is outside GITHUB_TOKEN authority")
        if not isinstance(inputs, Mapping) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in inputs.items()):
            raise ProtocolFailure("workflow dispatch inputs must be a string mapping")
        workflow = quote(request.workflow_id, safe="")
        response = self._http.request(
            "POST",
            f"{self._api_url}/repos/{request.repository}/actions/workflows/{workflow}/dispatches",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token.value}",
                "X-GitHub-Api-Version": request.api_version,
            },
            json_body={"ref": request.ref, "inputs": dict(inputs)},
        )
        if response.status != 200:
            raise ProtocolFailure("dispatch must return HTTP 200")
        body = _json_mapping(response.body)
        return parse_dispatch_response(request, response.status, body)

    def observe_exact_job(self, request: DispatchRequest, run_id: int, runner_label: str) -> ObservedWorkflowJob:
        """Poll the exact dispatch for a bounded interval and fail closed."""
        if request.repository != self._token.repository:
            raise ControlFailure("job observation repository is outside GITHUB_TOKEN authority")
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self._token.value}", "X-GitHub-Api-Version": request.api_version}
        base = f"{self._api_url}/repos/{request.repository}/actions/runs/{run_id}"
        deadline = self._monotonic() + self._observation_timeout
        while True:
            run_response = self._http.request("GET", base, headers=headers)
            jobs_response = self._http.request("GET", f"{base}/jobs?filter=latest&per_page=100", headers=headers)
            if run_response.status == 200 and jobs_response.status == 200:
                try:
                    return parse_observed_workflow_job(
                        run_id, runner_label, _json_mapping(run_response.body),
                        _json_mapping(jobs_response.body), expected_job_name="local-quality",
                    )
                except WorkflowJobPending:
                    pass
            elif run_response.status not in {200, 404, 409, 422} or jobs_response.status not in {200, 404, 409, 422}:
                raise ControlFailure("exact workflow run/job observation is unavailable")
            if self._monotonic() >= deadline:
                raise ControlFailure("exact workflow job observation timed out")
            self._sleeper(self._observation_poll)


class GitHubCheckTransport:
    """Concrete create/get/update transport pinned to one Check Run authority."""

    def __init__(
        self,
        token: InstallationToken,
        authority: AppAuthorityV1,
        http: HTTPTransport,
        *,
        api_url: str = GITHUB_API,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._api_url = _exact_api_url(api_url)
        if not isinstance(token, InstallationToken):
            raise ControlFailure("Check transport requires an App installation token")
        token.assert_current(authority, clock())
        self._token = token
        self._authority = authority
        self._http = http
        self._clock = clock

    def create_exact(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        observed = self._write("POST", "/check-runs", payload, expected_status=201)
        _check_id(observed.get("id"))
        return observed

    def patch_exact(self, check_run_id: int, payload: Mapping[str, object]) -> None:
        if set(payload) != {"conclusion", "head_sha", "external_id"}:
            raise ControlFailure("Check Run update payload fields are not exact")
        expected = {
            "id": _check_id(check_run_id),
            "head_sha": payload["head_sha"],
            "external_id": payload["external_id"],
            "conclusion": payload["conclusion"],
        }
        wire_payload = {
            "external_id": payload["external_id"],
            "conclusion": payload["conclusion"],
        }
        try:
            observed = self._write(
                "PATCH",
                f"/check-runs/{check_run_id}",
                wire_payload,
                expected_status=200,
            )
        except GitHubAdapterError as exc:
            raise AmbiguousCheckWrite("Check Run update outcome is ambiguous") from exc
        if any(observed.get(field) != value for field, value in expected.items()):
            raise AmbiguousCheckWrite("Check Run update response did not match exact evidence")

    def get_exact(self, check_run_id: int) -> Mapping[str, object]:
        self._authorize("metadata:read")
        response = self._http.request(
            "GET",
            self._url(f"/check-runs/{_check_id(check_run_id)}"),
            headers=self._headers(),
        )
        observed = _expected_json(response, 200)
        if observed.get("id") != check_run_id:
            raise GitHubAdapterError("Check Run read returned a different ID")
        return observed

    def _write(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object],
        *,
        expected_status: int,
    ) -> Mapping[str, object]:
        self._authorize("checks:create" if method == "POST" else "checks:update")
        if not isinstance(payload, Mapping):
            raise ControlFailure("Check Run payload must be a mapping")
        response = self._http.request(method, self._url(path), headers=self._headers(), json_body=dict(payload))
        return _expected_json(response, expected_status)

    def _authorize(self, operation: str) -> None:
        self._token.assert_current(self._authority, self._clock())
        if not self._authority.permits(
            operation,
            repository=self._token.repository,
            installation_id=self._token.installation_id,
        ):
            raise ControlFailure("GitHub App operation is outside exact authority")

    def _url(self, path: str) -> str:
        return f"{self._api_url}/repos/{self._authority.repository}{path}"

    def _headers(self) -> Mapping[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token.value}",
            "X-GitHub-Api-Version": PINNED_GITHUB_API_VERSION,
        }


def _expected_json(response: HTTPResponse, status: int) -> Mapping[str, Any]:
    if response.status != status:
        raise GitHubHTTPError(response.status)
    return _json_mapping(response.body)


def _json_mapping(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GitHubAdapterError("GitHub API response is not unambiguous JSON") from exc
    if not isinstance(value, Mapping):
        raise GitHubAdapterError("GitHub API response must be a JSON object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ControlFailure("installation token expiry is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlFailure("installation token expiry is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ControlFailure("installation token expiry must be timezone-aware")
    return parsed


def _b64json(value: Mapping[str, object]) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _check_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ControlFailure("check_run_id must be a positive integer")
    return value


def _exact_api_url(value: str) -> str:
    if value != GITHUB_API:
        raise ControlFailure("GitHub API URL must be exactly https://api.github.com")
    return value


__all__ = [
    "ACTIONS_TOKEN_PERMISSIONS",
    "ActionsDispatchTransport",
    "GitHubActionsToken",
    "GitHubAdapterError",
    "GitHubAppAuthenticator",
    "GitHubCheckTransport",
    "GitHubHTTPError",
    "HTTPResponse",
    "HTTPTransport",
    "InstallationToken",
    "OpenSSLRS256Signer",
    "RS256Signer",
    "UrllibHTTPTransport",
]
