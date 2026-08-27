#!/usr/bin/env python3
"""Authenticate as the dedicated GitHub App and verify one live workflow job."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


API_ROOT = "https://api.github.com"
CONFIG_PATH = Path("/etc/self-hosted-ci/github-live-job-verifier.json")
MAX_REQUEST_BYTES = 16_384
MAX_RESPONSE_BYTES = 1_048_576
HTTP_TIMEOUT_SECONDS = 5
REQUEST_FIELDS = {
    "workflow_job_id", "run_id", "run_attempt", "repository_id", "repository",
    "dispatch_sha", "workflow_ref", "job_name", "runner_name", "runner_group",
    "labels", "required_status",
}
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA1 = re.compile(r"[0-9a-f]{40}")
_WORKFLOW_REF = re.compile(
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/"
    r"(?P<path>\.github/workflows/[A-Za-z0-9_.-]+)@"
    r"(?P<ref>refs/heads/[A-Za-z0-9._/-]+)"
)


class VerificationError(ValueError):
    pass


def _exact_json(data: bytes) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("invalid JSON") from exc


def _root_file(path: Path, maximum_size: int, *, private: bool) -> bytes:
    info = os.lstat(path)
    maximum_mode = 0o600 if private else 0o644
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise VerificationError("unsafe root-owned verifier file")
    if info.st_mode & ~maximum_mode & 0o777 or not 1 <= info.st_size <= maximum_size:
        raise VerificationError("unsafe verifier file mode or size")
    return path.read_bytes()


def load_credentials(path: Path = CONFIG_PATH) -> tuple[int, int, rsa.RSAPrivateKey]:
    config = _exact_json(_root_file(path, 16_384, private=True))
    if not isinstance(config, dict) or set(config) != {"app_id", "installation_id", "private_key_file"}:
        raise VerificationError("GitHub App config requires exact fields")
    app_id, installation_id, key_name = (
        config["app_id"], config["installation_id"], config["private_key_file"]
    )
    if (
        not isinstance(app_id, int) or isinstance(app_id, bool) or app_id < 1
        or not isinstance(installation_id, int) or isinstance(installation_id, bool) or installation_id < 1
        or not isinstance(key_name, str) or not key_name.startswith("/etc/self-hosted-ci/")
    ):
        raise VerificationError("GitHub App config values are invalid")
    key_path = Path(key_name)
    if ".." in key_path.parts:
        raise VerificationError("GitHub App private key path is unsafe")
    try:
        key = serialization.load_pem_private_key(
            _root_file(key_path, 65_536, private=True), password=None
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError("GitHub App private key is invalid") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise VerificationError("GitHub App private key must be RSA 2048-bit or stronger")
    return app_id, installation_id, key


def validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise VerificationError("live job request requires exact fields")
    for field in ("workflow_job_id", "run_id", "repository_id"):
        if not isinstance(value[field], str) or not _POSITIVE_INTEGER.fullmatch(value[field]):
            raise VerificationError(f"{field} must be a canonical positive integer string")
    if not isinstance(value["run_attempt"], int) or isinstance(value["run_attempt"], bool) or value["run_attempt"] < 1:
        raise VerificationError("run_attempt must be a positive integer")
    if not isinstance(value["repository"], str) or not _REPOSITORY.fullmatch(value["repository"]):
        raise VerificationError("repository is invalid")
    if not isinstance(value["dispatch_sha"], str) or not _SHA1.fullmatch(value["dispatch_sha"]):
        raise VerificationError("dispatch_sha is invalid")
    workflow = _WORKFLOW_REF.fullmatch(value["workflow_ref"]) if isinstance(value["workflow_ref"], str) else None
    if workflow is None or workflow.group("repository") != value["repository"]:
        raise VerificationError("workflow_ref is invalid or crosses the repository")
    for field in ("job_name", "runner_name"):
        if not isinstance(value[field], str) or not value[field] or value[field] != value[field].strip() or len(value[field]) > 255:
            raise VerificationError(f"{field} is invalid")
    if value["runner_group"] is not None and (
        not isinstance(value["runner_group"], str)
        or not value["runner_group"]
        or value["runner_group"] != value["runner_group"].strip()
        or len(value["runner_group"]) > 100
    ):
        raise VerificationError("runner_group is invalid")
    labels = value["labels"]
    if (
        not isinstance(labels, list) or not 1 <= len(labels) <= 16
        or any(not isinstance(label, str) or not label or len(label) > 63 for label in labels)
        or len(set(labels)) != len(labels)
    ):
        raise VerificationError("labels are invalid")
    if value["required_status"] != "in_progress":
        raise VerificationError("required_status must be in_progress")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_app_jwt(app_id: int, private_key: rsa.RSAPrivateKey, now: int) -> str:
    header = _b64url(b'{"alg":"RS256","typ":"JWT"}')
    payload = _b64url(json.dumps(
        {"exp": now + 540, "iat": now - 60, "iss": str(app_id)},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


class GitHubAPI:
    def __init__(self, opener: Callable[..., Any] = urllib.request.urlopen) -> None:
        self._opener = opener

    def json(self, method: str, path: str, bearer: str, body: Mapping[str, Any] | None = None) -> Any:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise VerificationError("unsafe GitHub API path")
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "self-hosted-ci-live-job-verifier/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(API_ROOT + path, data=encoded, method=method, headers=headers)
        try:
            with self._opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                if response.status < 200 or response.status >= 300:
                    raise VerificationError("GitHub API rejected verifier request")
                data = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise VerificationError("GitHub API request failed") from exc
        if not data or len(data) > MAX_RESPONSE_BYTES:
            raise VerificationError("GitHub API response size is invalid")
        return _exact_json(data)


def _require_exact_repository(value: Any, request: Mapping[str, Any]) -> None:
    if not isinstance(value, dict) or value.get("id") != int(request["repository_id"]) or value.get("full_name") != request["repository"]:
        raise VerificationError("GitHub API repository identity mismatch")


def verify_live_job(
    request: dict[str, Any], app_id: int, installation_id: int,
    private_key: rsa.RSAPrivateKey, *, api: GitHubAPI, now: int,
) -> dict[str, Any]:
    app_jwt = create_app_jwt(app_id, private_key, now)
    token_response = api.json(
        "POST", f"/app/installations/{installation_id}/access_tokens", app_jwt,
        {"permissions": {"actions": "read"}, "repository_ids": [int(request["repository_id"])]},
    )
    if not isinstance(token_response, dict) or set(token_response) < {"token", "expires_at", "permissions", "repositories"}:
        raise VerificationError("installation token response is incomplete")
    token = token_response["token"]
    if not isinstance(token, str) or not 20 <= len(token) <= 512:
        raise VerificationError("installation token is invalid")
    permissions = token_response["permissions"]
    if (
        not isinstance(permissions, dict)
        or permissions.get("actions") != "read"
        or set(permissions) not in ({"actions"}, {"actions", "metadata"})
        or permissions.get("metadata", "read") != "read"
    ):
        raise VerificationError("installation token permissions are not read-only Actions")
    repositories = token_response["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise VerificationError("installation token repository scope is not exact")
    _require_exact_repository(repositories[0], request)
    try:
        expiry = datetime.fromisoformat(token_response["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise VerificationError("installation token expiry is invalid") from exc
    if expiry.tzinfo is None or not now < int(expiry.timestamp()) <= now + 3600:
        raise VerificationError("installation token lifetime is invalid")

    repository = request["repository"]
    job = api.json("GET", f"/repos/{repository}/actions/jobs/{request['workflow_job_id']}", token)
    run = api.json("GET", f"/repos/{repository}/actions/runs/{request['run_id']}", token)
    if not isinstance(job, dict) or not isinstance(run, dict):
        raise VerificationError("GitHub live job/run response is invalid")
    expected_job = {
        "id": int(request["workflow_job_id"]), "run_id": int(request["run_id"]),
        "head_sha": request["dispatch_sha"],
        "name": request["job_name"], "labels": request["labels"],
        "runner_name": request["runner_name"], "runner_group_name": request["runner_group"],
        "status": request["required_status"],
    }
    if any(job.get(field) != expected for field, expected in expected_job.items()):
        raise VerificationError("GitHub workflow job identity mismatch")
    expected_run = {
        "id": int(request["run_id"]), "run_attempt": request["run_attempt"],
        "head_sha": request["dispatch_sha"],
    }
    if any(run.get(field) != expected for field, expected in expected_run.items()):
        raise VerificationError("GitHub workflow run identity mismatch")
    _require_exact_repository(run.get("repository"), request)
    workflow = _WORKFLOW_REF.fullmatch(request["workflow_ref"])
    assert workflow is not None
    expected_path, expected_ref = workflow.group("path"), workflow.group("ref")
    observed_path = run.get("path")
    if observed_path not in {expected_path, f"{expected_path}@{expected_ref}"}:
        raise VerificationError("GitHub workflow path mismatch")
    if run.get("head_branch") != expected_ref.removeprefix("refs/heads/"):
        raise VerificationError("GitHub workflow ref mismatch")

    result = dict(request)
    result.pop("required_status")
    result["status"] = "in_progress"
    result["verified"] = True
    return result


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise VerificationError("verifier must run as root")
        body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if not body or len(body) > MAX_REQUEST_BYTES:
            raise VerificationError("request size is invalid")
        request = validate_request(_exact_json(body))
        app_id, installation_id, private_key = load_credentials()
        result = verify_live_job(
            request, app_id, installation_id, private_key,
            api=GitHubAPI(), now=int(time.time()),
        )
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, VerificationError):
        # Do not echo exception data: HTTP and crypto errors may contain secrets.
        print("GitHub live workflow-job verification blocked", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
