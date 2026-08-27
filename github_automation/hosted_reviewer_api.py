"""HTTP and GitHub App adapter for the hosted Thermonuclear reviewer."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MARKER = "<!-- thermonuclear-review:clean-room-v1 -->"
TOKEN_MAX_TTL_SECONDS = 3600
TOKEN_EXPIRY_MARGIN_SECONDS = 60


class ConfigurationError(RuntimeError):
    """The reviewer is not configured with an exact, safe authority."""


class GitHubApiError(RuntimeError):
    """An API operation failed or returned an invalid contract."""


class PullRequestIdentityLike(Protocol):
    repository: str
    number: int


Transport = Callable[[str, str, Mapping[str, str], bytes | None, int], tuple[int, Mapping[str, str], bytes]]


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_app_jwt(app_id: int, private_key_pem: str, *, now: int | None = None) -> str:
    """Create a ten-minute RS256 GitHub App JWT using the hosted OpenSSL binary."""
    if app_id <= 0 or "PRIVATE KEY" not in private_key_pem:
        raise ConfigurationError("GitHub App id/private key is malformed")
    timestamp = int(time.time() if now is None else now)
    header = _b64url(_json_bytes({"alg": "RS256", "typ": "JWT"}))
    payload = _b64url(_json_bytes({"iat": timestamp - 30, "exp": timestamp + 540, "iss": str(app_id)}))
    signing_input = f"{header}.{payload}".encode("ascii")
    key_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as key:
            key.write(private_key_pem)
            key.flush()
            os.chmod(key.name, 0o600)
            key_path = key.name
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigurationError("GitHub App JWT signing failed") from exc
    finally:
        if key_path:
            Path(key_path).unlink(missing_ok=True)
    if result.returncode != 0 or not result.stdout:
        raise ConfigurationError("GitHub App private key was rejected by OpenSSL")
    return f"{header}.{payload}.{_b64url(result.stdout)}"


def urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: int,
) -> tuple[int, Mapping[str, str], bytes]:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as exc:
        response = exc.read(16_384)
        raise GitHubApiError(f"HTTP {exc.code}: {response.decode('utf-8', 'replace')[:500]}") from exc
    except (URLError, TimeoutError) as exc:
        raise GitHubApiError(f"network request failed: {type(exc).__name__}") from exc


def request_json(
    transport: Transport,
    method: str,
    url: str,
    headers: Mapping[str, str],
    *,
    body: object | None = None,
    timeout: int = 30,
) -> Any:
    payload = None if body is None else _json_bytes(body)
    status, _, raw = transport(method, url, headers, payload, timeout)
    if status < 200 or status >= 300:
        raise GitHubApiError(f"unexpected HTTP status {status}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubApiError("API returned invalid JSON") from exc


class GitHubAppClient:
    """Minimal GitHub App client with exact App/comment ownership checks."""

    def __init__(self, *, app_id: int, expected_app_id: int, installation_id: int,
                 private_key_pem: str, repository: str,
                 transport: Transport = urllib_transport,
                 api_url: str = "https://api.github.com",
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        if app_id != expected_app_id or min(app_id, installation_id) <= 0:
            raise ConfigurationError("dedicated GitHub App identity is not exact")
        if repository.count("/") != 1:
            raise ConfigurationError("repository must be owner/name")
        self.app_id = app_id
        self.installation_id = installation_id
        self.repository = repository
        self.transport = transport
        self.api_url = api_url.rstrip("/")
        self.clock = clock
        jwt = create_app_jwt(app_id, private_key_pem)
        app = self._api("GET", "/app", token=jwt)
        if not isinstance(app, dict) or app.get("id") != app_id:
            raise ConfigurationError("GitHub authenticated a different App")
        token_response = self._api(
            "POST", f"/app/installations/{installation_id}/access_tokens", token=jwt,
            body={"repositories": [repository], "permissions": {"pull_requests": "write"}},
        )
        token, token_repository_id = self._validate_token_response(token_response)
        self._token = token
        repo = self._api("GET", f"/repos/{repository}")
        if (
            not isinstance(repo, dict)
            or repo.get("full_name") != repository
            or repo.get("id") != token_repository_id
        ):
            raise ConfigurationError("App installation is not scoped to the exact repository")

    def _api(self, method: str, path: str, *, token: str | None = None, body: object | None = None) -> Any:
        if token is None and method in {"POST", "PATCH", "PUT", "DELETE"}:
            self._require_token_fresh()
        auth = token if token is not None else getattr(self, "_token", "")
        return request_json(
            self.transport, method, f"{self.api_url}{path}",
            {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {auth}",
             "Content-Type": "application/json", "User-Agent": "self-hosted-ci-thermonuclear-review/1",
             "X-GitHub-Api-Version": "2022-11-28"},
            body=body,
        )

    def canonical_pr(self, identity: PullRequestIdentityLike) -> Mapping[str, Any]:
        self._require_repository(identity)
        value = self._api("GET", f"/repos/{identity.repository}/pulls/{identity.number}")
        if not isinstance(value, dict):
            raise GitHubApiError("pull request response is not an object")
        return value

    def pull_files(self, identity: PullRequestIdentityLike) -> Sequence[Mapping[str, Any]]:
        self._require_repository(identity)
        files: list[Mapping[str, Any]] = []
        for page in range(1, 3):
            value = self._api("GET", f"/repos/{identity.repository}/pulls/{identity.number}/files?per_page=100&page={page}")
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                raise GitHubApiError("pull-request files response is malformed")
            files.extend(value)
            if len(value) < 100:
                break
        return files

    def upsert_comment(
        self,
        identity: PullRequestIdentityLike,
        body: str,
        *,
        before_write: Callable[[], object],
    ) -> int:
        self._require_repository(identity)
        path = f"/repos/{identity.repository}/issues/{identity.number}/comments"
        owned = self._owned_comments(path)
        if not owned:
            before_write()
            try:
                result = self._api("POST", path, body={"body": body})
            except GitHubApiError:
                # The transport cannot prove whether GitHub committed an
                # interrupted write. Reconciliation below resolves by state.
                result = None
            if result is not None and not self._is_owned_body(result, body):
                raise GitHubApiError("comment response is not owned by the dedicated App")

        # A concurrent workflow can observe no comment and create alongside us.
        # Reconcile to the lowest stable id, delete duplicates, then prove the
        # persisted exact App+marker body. Every mutation is separately fenced.
        for _ in range(3):
            owned = self._owned_comments(path)
            if not owned:
                raise GitHubApiError("App-owned Thermonuclear comment disappeared")
            canonical = min(owned, key=lambda item: item["id"])
            comment_id = canonical["id"]
            if canonical.get("body") != body:
                before_write()
                try:
                    result = self._api(
                        "PATCH", f"/repos/{identity.repository}/issues/comments/{comment_id}", body={"body": body},
                    )
                except GitHubApiError:
                    result = None
                if result is not None and not self._is_owned_body(result, body):
                    raise GitHubApiError("updated comment is not owned by the dedicated App")
            for duplicate in owned:
                duplicate_id = duplicate["id"]
                if duplicate_id == comment_id:
                    continue
                before_write()
                try:
                    self._api("DELETE", f"/repos/{identity.repository}/issues/comments/{duplicate_id}")
                except GitHubApiError:
                    pass

            try:
                verified = self._api("GET", f"/repos/{identity.repository}/issues/comments/{comment_id}")
            except GitHubApiError:
                verified = None
            final_owned = self._owned_comments(path)
            if self._is_owned_body(verified, body) and [item["id"] for item in final_owned] == [comment_id]:
                return comment_id
        raise GitHubApiError("App-owned Thermonuclear comment did not converge")

    def _owned_comments(self, path: str) -> list[Mapping[str, Any]]:
        owned: list[Mapping[str, Any]] = []
        for page in range(1, 11):
            comments = self._api("GET", f"{path}?per_page=100&page={page}")
            if not isinstance(comments, list) or not all(isinstance(item, dict) for item in comments):
                raise GitHubApiError("issue comments response is malformed")
            owned.extend(item for item in comments if self._is_owned_marker(item))
            if len(comments) < 100:
                break
            if page == 10:
                raise GitHubApiError("issue comment pagination exceeds the verification bound")
        if any(not isinstance(item.get("id"), int) or isinstance(item.get("id"), bool) for item in owned):
            raise GitHubApiError("owned comment has no numeric id")
        return sorted(owned, key=lambda item: item["id"])

    def _is_owned_marker(self, value: object) -> bool:
        if not isinstance(value, dict) or not str(value.get("body", "")).startswith(MARKER):
            return False
        performed = value.get("performed_via_github_app")
        return isinstance(performed, dict) and performed.get("id") == self.app_id

    def _is_owned_body(self, value: object, body: str) -> bool:
        return self._is_owned_marker(value) and value.get("body") == body

    def _validate_token_response(self, value: object) -> tuple[str, int]:
        if not isinstance(value, dict):
            raise ConfigurationError("GitHub App installation token response is malformed")
        token, expires_at = value.get("token"), value.get("expires_at")
        repositories = value.get("repositories")
        if (
            not isinstance(token, str)
            or not token
            or value.get("repository_selection") != "selected"
            or value.get("permissions") != {"pull_requests": "write"}
            or not isinstance(repositories, list)
            or len(repositories) != 1
            or not isinstance(repositories[0], dict)
            or not isinstance(repositories[0].get("id"), int)
            or isinstance(repositories[0].get("id"), bool)
            or repositories[0]["id"] <= 0
            or repositories[0].get("full_name") != self.repository
            or not isinstance(expires_at, str)
        ):
            raise ConfigurationError("GitHub App installation token authority is not exact")
        try:
            expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ConfigurationError("GitHub App installation token expiry is malformed") from exc
        if expiry.strftime("%Y-%m-%dT%H:%M:%SZ") != expires_at:
            raise ConfigurationError("GitHub App installation token expiry is not canonical UTC")
        now = self._utc_now()
        ttl = expiry - now
        if ttl > timedelta(seconds=TOKEN_MAX_TTL_SECONDS):
            raise ConfigurationError("GitHub App installation token TTL exceeds one hour")
        if ttl <= timedelta(seconds=TOKEN_EXPIRY_MARGIN_SECONDS):
            raise ConfigurationError("GitHub App installation token lacks the minimum usable margin")
        self._token_deadline = expiry - timedelta(seconds=TOKEN_EXPIRY_MARGIN_SECONDS)
        return token, repositories[0]["id"]

    def _utc_now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ConfigurationError("GitHub App token clock must be canonical UTC")
        return now

    def _require_token_fresh(self) -> None:
        deadline = getattr(self, "_token_deadline", None)
        if not isinstance(deadline, datetime) or self._utc_now() >= deadline:
            raise ConfigurationError("GitHub App installation token reached its usable deadline")

    def _require_repository(self, identity: PullRequestIdentityLike) -> None:
        if identity.repository != self.repository:
            raise ConfigurationError("requested repository differs from App scope")
