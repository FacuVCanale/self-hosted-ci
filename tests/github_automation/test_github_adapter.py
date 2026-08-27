from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import http.client
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from github_automation.check_delivery import (
    AmbiguousCheckWrite,
    CheckDelivery,
    deliver_exact,
)
from github_automation.github import (
    AppAuthorityV1,
    ControlFailure,
    DispatchRequest,
    MINIMUM_APP_PERMISSIONS,
    MintRequest,
    ProtocolFailure,
    RuntimeIdentity,
)
from github_automation.github_adapter import (
    ACTIONS_TOKEN_PERMISSIONS,
    ActionsDispatchTransport,
    GitHubActionsToken,
    GitHubAdapterError,
    GitHubAppAuthenticator,
    GitHubCheckTransport,
    HTTPResponse,
    InstallationToken,
    UrllibHTTPTransport,
)


NOW = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
REPOSITORY = "example-owner/example-repo"
WORKFLOW = "example-owner/control/.github/workflows/coordinator.yml"


def authority(**changes: object) -> AppAuthorityV1:
    values = {
        "owner": "example-owner",
        "app_id": 111,
        "app_slug": "ci-gate",
        "repository": REPOSITORY,
        "repository_id": 123,
        "installation_id": 222,
        "control_workflow_identity": WORKFLOW,
        "control_workflow_ref": "refs/heads/main",
        "key_fingerprint": "d" * 64,
        "key_version": 1,
        "rotated_at": NOW - timedelta(days=1),
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
    }
    values.update(changes)
    return AppAuthorityV1(**values)


def identity(**changes: object) -> RuntimeIdentity:
    values = {
        "role": "coordinator",
        "workflow_identity": WORKFLOW,
        "workflow_ref": "refs/heads/main",
        "reviewed_default_branch_code": True,
    }
    values.update(changes)
    return RuntimeIdentity(**values)


def mint_request(**changes: object) -> MintRequest:
    values = {
        "app_id": 111,
        "installation_id": 222,
        "repository": REPOSITORY,
        "repository_id": 123,
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
        "ttl_seconds": 3600,
    }
    values.update(changes)
    return MintRequest(**values)


def installation_token(**changes: object) -> InstallationToken:
    values = {
        "value": "ghs_installation_secret",
        "expires_at": NOW + timedelta(hours=1),
        "repository": REPOSITORY,
        "repository_id": 123,
        "installation_id": 222,
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
    }
    values.update(changes)
    return InstallationToken(**values)


def actions_token(**changes: object) -> GitHubActionsToken:
    values = {
        "value": "ghs_actions_secret",
        "repository": REPOSITORY,
        "workflow_identity": WORKFLOW,
        "workflow_ref": "refs/heads/main",
        "permissions": dict(ACTIONS_TOKEN_PERMISSIONS),
    }
    values.update(changes)
    return GitHubActionsToken(**values)


def response(status: int, value: object) -> HTTPResponse:
    return HTTPResponse(status, json.dumps(value).encode())


class FakeHTTP:
    def __init__(self, *responses: HTTPResponse | Exception) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, str], object]] = []

    def request(self, method, url, *, headers, json_body=None):
        self.requests.append((method, url, dict(headers), json_body))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class FakeSigner:
    def __init__(self, signature: bytes = b"signed") -> None:
        self.signature = signature
        self.inputs: list[bytes] = []

    def sign(self, signing_input: bytes) -> bytes:
        self.inputs.append(signing_input)
        return self.signature


def successful_auth_http(**overrides: object) -> FakeHTTP:
    app = {
        "id": 111,
        "slug": "ci-gate",
        "owner": {"login": "example-owner"},
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
    }
    installation = {
        "id": 222,
        "app_id": 111,
        "repository_selection": "selected",
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
        "suspended_at": None,
    }
    token = {
        "token": "ghs_installation_secret",
        "expires_at": "2026-08-26T13:00:00Z",
        "permissions": dict(MINIMUM_APP_PERMISSIONS),
        "repositories": [{"id": 123, "full_name": REPOSITORY}],
    }
    repository = {"id": 123, "full_name": REPOSITORY}
    objects = {
        "app": app,
        "installation": installation,
        "token": token,
        "repository": repository,
    }
    for key, value in overrides.items():
        objects[key] = value
    return FakeHTTP(
        response(200, objects["app"]),
        response(200, objects["installation"]),
        response(201, objects["token"]),
        response(200, objects["repository"]),
    )


class GitHubAppAuthenticationTests(unittest.TestCase):
    def test_mints_exact_memory_token_after_full_authority_validation(self) -> None:
        http = successful_auth_http()
        signer = FakeSigner()
        token = GitHubAppAuthenticator(
            authority(), identity(), signer, http, clock=lambda: NOW
        ).mint(mint_request())

        self.assertEqual("ghs_installation_secret", token.value)
        self.assertEqual(REPOSITORY, token.repository)
        self.assertNotIn(token.value, repr(token))
        self.assertEqual(4, len(http.requests))
        self.assertEqual(("GET", "https://api.github.com/app"), http.requests[0][:2])
        self.assertEqual(
            ("GET", f"https://api.github.com/repos/{REPOSITORY}/installation"),
            http.requests[1][:2],
        )
        self.assertEqual(
            {
                "repository_ids": [123],
                "permissions": dict(MINIMUM_APP_PERMISSIONS),
            },
            http.requests[2][3],
        )
        self.assertEqual(
            ("GET", f"https://api.github.com/repos/{REPOSITORY}"),
            http.requests[3][:2],
        )
        self.assertIn(
            "Bearer ghs_installation_secret", http.requests[3][2]["Authorization"]
        )

        header, claims = signer.inputs[0].decode().split(".")
        decode = lambda part: json.loads(
            base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        )
        self.assertEqual({"alg": "RS256", "typ": "JWT"}, decode(header))
        self.assertEqual(
            {
                "iat": int(NOW.timestamp()) - 60,
                "exp": int(NOW.timestamp()) + 540,
                "iss": "111",
            },
            decode(claims),
        )

    def test_rejects_local_mint_scope_before_http(self) -> None:
        for request in (
            mint_request(repository_id=999),
            mint_request(
                permissions={"metadata": "read", "checks": "write", "actions": "write"}
            ),
        ):
            with self.subTest(request=request):
                http = FakeHTTP()
                with self.assertRaises(ControlFailure):
                    GitHubAppAuthenticator(
                        authority(), identity(), FakeSigner(), http, clock=lambda: NOW
                    ).mint(request)
                self.assertEqual([], http.requests)

    def test_rejects_each_remote_authority_drift_before_token_use(self) -> None:
        cases = {
            "app": {
                "id": 999,
                "slug": "ci-gate",
                "owner": {"login": "example-owner"},
                "permissions": dict(MINIMUM_APP_PERMISSIONS),
            },
            "installation": {
                "id": 222,
                "app_id": 111,
                "repository_selection": "all",
                "permissions": dict(MINIMUM_APP_PERMISSIONS),
                "suspended_at": None,
            },
            "token": {
                "token": "x",
                "expires_at": "2026-08-26T13:00:00Z",
                "permissions": dict(MINIMUM_APP_PERMISSIONS),
                "repositories": [{"id": 999, "full_name": REPOSITORY}],
            },
            "repository": {"id": 999, "full_name": REPOSITORY},
        }
        for boundary, bad in cases.items():
            with self.subTest(boundary=boundary):
                http = successful_auth_http(**{boundary: bad})
                with self.assertRaises(ControlFailure):
                    GitHubAppAuthenticator(
                        authority(), identity(), FakeSigner(), http, clock=lambda: NOW
                    ).mint(mint_request())

    def test_rejects_http_json_and_token_ttl_fail_closed(self) -> None:
        bad_ttl = {
            "token": "x",
            "expires_at": "2026-08-26T13:02:01Z",
            "permissions": dict(MINIMUM_APP_PERMISSIONS),
            "repositories": [{"id": 123, "full_name": REPOSITORY}],
        }
        with self.assertRaises(ControlFailure):
            GitHubAppAuthenticator(
                authority(),
                identity(),
                FakeSigner(),
                successful_auth_http(token=bad_ttl),
                clock=lambda: NOW,
            ).mint(mint_request())
        for first in (
            HTTPResponse(500, b"{}"),
            HTTPResponse(200, b'{"id":111,"id":111}'),
            HTTPResponse(200, b"[]"),
        ):
            with self.subTest(body=first.body):
                with self.assertRaises(GitHubAdapterError):
                    GitHubAppAuthenticator(
                        authority(),
                        identity(),
                        FakeSigner(),
                        FakeHTTP(first),
                        clock=lambda: NOW,
                    ).mint(mint_request())

    def test_server_one_hour_expiry_derives_shorter_local_usable_deadline(self) -> None:
        token_response = {
            "token": "x",
            "expires_at": "2026-08-26T13:01:30Z",
            "permissions": dict(MINIMUM_APP_PERMISSIONS),
            "repositories": [{"id": 123, "full_name": REPOSITORY}],
        }
        token = GitHubAppAuthenticator(
            authority(),
            identity(),
            FakeSigner(),
            successful_auth_http(token=token_response),
            clock=lambda: NOW,
        ).mint(mint_request(ttl_seconds=300))
        self.assertEqual(NOW + timedelta(minutes=5), token.expires_at)

        normal = GitHubAppAuthenticator(
            authority(),
            identity(),
            FakeSigner(),
            successful_auth_http(),
            clock=lambda: NOW,
        ).mint(mint_request())
        self.assertEqual(NOW + timedelta(minutes=59, seconds=30), normal.expires_at)

    def test_every_adapter_rejects_noncanonical_api_url_before_credentials_or_http(
        self,
    ) -> None:
        bad_urls = (
            "http://api.github.com",
            "https://api.github.com/",
            "https://api.github.com.evil.invalid",
        )
        for api_url in bad_urls:
            with self.subTest(api_url=api_url):
                signer = FakeSigner()
                http = FakeHTTP()
                with self.assertRaises(ControlFailure):
                    GitHubAppAuthenticator(
                        authority(), identity(), signer, http, api_url=api_url
                    )
                with self.assertRaises(ControlFailure):
                    ActionsDispatchTransport(
                        actions_token(), identity(), http, api_url=api_url
                    )
                with self.assertRaises(ControlFailure):
                    GitHubCheckTransport(
                        installation_token(),
                        authority(),
                        http,
                        api_url=api_url,
                        clock=lambda: NOW,
                    )
                self.assertEqual([], signer.inputs)
                self.assertEqual([], http.requests)


class DispatchTransportTests(unittest.TestCase):
    def test_observe_exact_job_polls_until_unique_named_labeled_job_exists(
        self,
    ) -> None:
        run = response(200, {"id": 777, "run_attempt": 2, "head_sha": "f" * 40})
        pending = response(
            200,
            {
                "total_count": 1,
                "jobs": [
                    {
                        "id": 1,
                        "run_id": 777,
                        "name": "validate trusted dispatch package",
                        "labels": ["ubuntu-24.04"],
                    },
                ],
            },
        )
        ready = response(
            200,
            {
                "total_count": 2,
                "jobs": [
                    {
                        "id": 1,
                        "run_id": 777,
                        "name": "validate trusted dispatch package",
                        "labels": ["ubuntu-24.04"],
                    },
                    {
                        "id": 888,
                        "run_id": 777,
                        "name": "local-quality",
                        "labels": ["self-hosted", "wsl-jit-" + "1" * 32],
                    },
                ],
            },
        )
        sleeps: list[float] = []
        http = FakeHTTP(run, pending, run, ready)
        adapter = ActionsDispatchTransport(
            actions_token(),
            identity(),
            http,
            observation_timeout_seconds=5,
            observation_poll_seconds=0.25,
            monotonic=lambda: 0,
            sleeper=sleeps.append,
        )
        observed = adapter.observe_exact_job(
            DispatchRequest(REPOSITORY, "child.yml", "main", "main"),
            777,
            "wsl-jit-" + "1" * 32,
        )
        self.assertEqual(
            (777, 2, 888, "local-quality"),
            (
                observed.run_id,
                observed.run_attempt,
                observed.job_id,
                observed.job_name,
            ),
        )
        self.assertEqual([0.25], sleeps)
        self.assertTrue(
            http.requests[-1][1].endswith("/jobs?filter=latest&per_page=100")
        )

    def test_observe_exact_job_has_a_hard_timeout(self) -> None:
        http = FakeHTTP(
            response(200, {"id": 777, "run_attempt": 1, "head_sha": "f" * 40}),
            response(200, {"total_count": 0, "jobs": []}),
        )
        clock = iter((0.0, 2.0))
        adapter = ActionsDispatchTransport(
            actions_token(),
            identity(),
            http,
            observation_timeout_seconds=1,
            monotonic=lambda: next(clock),
            sleeper=lambda _seconds: None,
        )
        with self.assertRaisesRegex(ControlFailure, "timed out"):
            adapter.observe_exact_job(
                DispatchRequest(REPOSITORY, "child.yml", "main", "main"),
                777,
                "wsl-jit-" + "1" * 32,
            )
        self.assertEqual(2, len(http.requests))

    def test_dispatch_uses_only_actions_token_and_consumes_exact_run_id(self) -> None:
        http = FakeHTTP(
            response(
                200,
                {
                    "workflow_run_id": 777,
                    "run_url": "https://api.github.com/repos/example-owner/example-repo/actions/runs/777",
                    "html_url": "https://github.com/example-owner/example-repo/actions/runs/777",
                },
            )
        )
        adapter = ActionsDispatchTransport(actions_token(), identity(), http)
        request = DispatchRequest(REPOSITORY, "child workflow.yml", "main", "main")
        self.assertEqual(777, adapter.dispatch(request, {"package": "signed"}))
        method, url, headers, body = http.requests[0]
        self.assertEqual("POST", method)
        self.assertTrue(
            url.endswith("/actions/workflows/child%20workflow.yml/dispatches")
        )
        self.assertEqual("Bearer ghs_actions_secret", headers["Authorization"])
        self.assertEqual(
            {
                "ref": "main",
                "inputs": {"package": "signed"},
                "return_run_details": True,
            },
            body,
        )
        self.assertEqual("2026-03-10", headers["X-GitHub-Api-Version"])

    def test_dispatch_rejects_crossed_token_identity_repo_inputs_and_response(
        self,
    ) -> None:
        with self.assertRaises(ControlFailure):
            ActionsDispatchTransport(installation_token(), identity(), FakeHTTP())  # type: ignore[arg-type]
        with self.assertRaises(ControlFailure):
            ActionsDispatchTransport(
                actions_token(), identity(workflow_ref="refs/heads/other"), FakeHTTP()
            )
        http = FakeHTTP()
        adapter = ActionsDispatchTransport(actions_token(), identity(), http)
        with self.assertRaises(ControlFailure):
            adapter.dispatch(
                DispatchRequest("example-owner/other", "child.yml", "main", "main"), {}
            )
        with self.assertRaises(ProtocolFailure):
            adapter.dispatch(
                DispatchRequest(REPOSITORY, "child.yml", "main", "main"), {"bad": 1}
            )  # type: ignore[dict-item]
        self.assertEqual([], http.requests)
        valid_urls = {
            "run_url": "https://api.github.com/repos/example-owner/example-repo/actions/runs/1",
            "html_url": "https://github.com/example-owner/example-repo/actions/runs/1",
        }
        for result in (
            HTTPResponse(204, b""),
            response(200, {}),
            response(200, {"workflow_run_id": 1, **valid_urls, "extra": True}),
            response(200, {"workflow_run_id": "1", **valid_urls}),
            response(
                200,
                {
                    "workflow_run_id": 1,
                    **valid_urls,
                    "html_url": "http://github.test/run/1",
                },
            ),
        ):
            with self.subTest(result=result):
                adapter = ActionsDispatchTransport(
                    actions_token(), identity(), FakeHTTP(result)
                )
                with self.assertRaises(ProtocolFailure):
                    adapter.dispatch(
                        DispatchRequest(REPOSITORY, "child.yml", "main", "main"), {}
                    )

    def test_productive_request_rejects_legacy_version_ref_and_path_workflow(
        self,
    ) -> None:
        for changes in (
            {"api_version": "2022-11-28"},
            {"ref": "feature"},
            {"workflow_id": ".github/workflows/child.yml"},
        ):
            values = {
                "repository": REPOSITORY,
                "workflow_id": "child.yml",
                "ref": "main",
                "default_branch": "main",
            }
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ProtocolFailure):
                DispatchRequest(**values)


class CheckTransportTests(unittest.TestCase):
    def test_create_get_and_update_are_exact_and_checks_only(self) -> None:
        http = FakeHTTP(
            response(201, {"id": 333, "name": "ci-gate"}),
            response(200, {"id": 333, "head_sha": "a" * 40}),
            response(
                200,
                {
                    "id": 333,
                    "head_sha": "a" * 40,
                    "external_id": "evidence",
                    "conclusion": "success",
                    "status": "completed",
                },
            ),
        )
        adapter = GitHubCheckTransport(
            installation_token(), authority(), http, clock=lambda: NOW
        )
        self.assertEqual(
            333, adapter.create_exact({"name": "ci-gate", "head_sha": "a" * 40})["id"]
        )
        self.assertEqual(333, adapter.get_exact(333)["id"])
        self.assertIsNone(
            adapter.patch_exact(
                333,
                {
                    "conclusion": "success",
                    "head_sha": "a" * 40,
                    "external_id": "evidence",
                },
            )
        )
        self.assertEqual(["POST", "GET", "PATCH"], [call[0] for call in http.requests])
        self.assertTrue(
            all(
                call[1].startswith(
                    f"https://api.github.com/repos/{REPOSITORY}/check-runs"
                )
                for call in http.requests
            )
        )
        self.assertTrue(
            all(
                call[2]["Authorization"] == "Bearer ghs_installation_secret"
                for call in http.requests
            )
        )
        self.assertEqual(
            {"conclusion": "success", "external_id": "evidence"},
            http.requests[2][3],
        )

    def test_check_transport_rejects_crossed_expired_drifted_and_revoked_authority(
        self,
    ) -> None:
        with self.assertRaises(ControlFailure):
            GitHubCheckTransport(
                actions_token(), authority(), FakeHTTP(), clock=lambda: NOW
            )  # type: ignore[arg-type]
        for token, auth in (
            (installation_token(expires_at=NOW), authority()),
            (installation_token(repository_id=999), authority()),
            (installation_token(), authority(key_state="revoked")),
        ):
            with (
                self.subTest(token=token, auth=auth),
                self.assertRaises(ControlFailure),
            ):
                GitHubCheckTransport(token, auth, FakeHTTP(), clock=lambda: NOW)

    def test_every_operation_rechecks_expiry_and_exact_ids(self) -> None:
        current = [NOW]
        http = FakeHTTP(response(200, {"id": 333}))
        adapter = GitHubCheckTransport(
            installation_token(), authority(), http, clock=lambda: current[0]
        )
        current[0] = NOW + timedelta(hours=1)
        with self.assertRaises(ControlFailure):
            adapter.get_exact(333)
        self.assertEqual([], http.requests)
        for check_id in (0, -1, True, "1"):
            with self.subTest(check_id=check_id), self.assertRaises(ControlFailure):
                GitHubCheckTransport(
                    installation_token(), authority(), FakeHTTP(), clock=lambda: NOW
                ).get_exact(check_id)  # type: ignore[arg-type]

    def test_read_and_patch_reject_wrong_id_or_ambiguous_write(self) -> None:
        adapter = GitHubCheckTransport(
            installation_token(),
            authority(),
            FakeHTTP(response(200, {"id": 999})),
            clock=lambda: NOW,
        )
        with self.assertRaises(GitHubAdapterError):
            adapter.get_exact(333)
        exact_payload = {
            "conclusion": "failure",
            "head_sha": "a" * 40,
            "external_id": "evidence",
        }
        mismatches = (
            {
                "id": 999,
                "head_sha": "a" * 40,
                "external_id": "evidence",
                "conclusion": "failure",
            },
            {
                "id": 333,
                "head_sha": "b" * 40,
                "external_id": "evidence",
                "conclusion": "failure",
            },
            {
                "id": 333,
                "head_sha": "a" * 40,
                "external_id": "other",
                "conclusion": "failure",
            },
            {
                "id": 333,
                "head_sha": "a" * 40,
                "external_id": "evidence",
                "conclusion": "success",
            },
        )
        results = [response(500, {}), HTTPResponse(200, b"not-json")]
        results.extend(response(200, value) for value in mismatches)
        for result in results:
            with self.subTest(result=result):
                adapter = GitHubCheckTransport(
                    installation_token(),
                    authority(),
                    FakeHTTP(result),
                    clock=lambda: NOW,
                )
                with self.assertRaises(AmbiguousCheckWrite):
                    adapter.patch_exact(333, exact_payload)

        http = FakeHTTP()
        adapter = GitHubCheckTransport(
            installation_token(), authority(), http, clock=lambda: NOW
        )
        with self.assertRaises(ControlFailure):
            adapter.patch_exact(333, {"conclusion": "failure", "head_sha": "a" * 40})
        self.assertEqual([], http.requests)

    def test_concrete_transport_supports_exact_ambiguous_write_reconciliation(
        self,
    ) -> None:
        digest = "d" * 64
        head_sha = "a" * 40
        http = FakeHTTP(
            response(502, {}),
            response(
                200,
                {
                    "id": 333,
                    "external_id": f"github-automation-evidence:{digest}",
                    "head_sha": head_sha,
                    "conclusion": "success",
                },
            ),
        )
        adapter = GitHubCheckTransport(
            installation_token(), authority(), http, clock=lambda: NOW
        )
        self.assertEqual(
            "reconciled",
            deliver_exact(CheckDelivery(333, digest, "success", head_sha), adapter),
        )
        self.assertEqual(["PATCH", "GET"], [call[0] for call in http.requests])


class TokenValidationTests(unittest.TestCase):
    def test_token_reprs_are_redacted_and_permission_sets_are_exact(self) -> None:
        self.assertNotIn("ghs_actions_secret", repr(actions_token()))
        self.assertNotIn("ghs_installation_secret", repr(installation_token()))
        with self.assertRaises(ControlFailure):
            actions_token(permissions={"actions": "write", "checks": "write"})
        with self.assertRaises(ControlFailure):
            installation_token(permissions={"checks": "write"})
        with self.assertRaises(ControlFailure):
            actions_token(value="contains whitespace")


class UrllibTransportTests(unittest.TestCase):
    def test_normalizes_timeout_reset_http_client_and_os_errors(self) -> None:
        failures = (
            TimeoutError("timeout"),
            ConnectionResetError("reset"),
            http.client.RemoteDisconnected("disconnected"),
            OSError("socket failure"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                patch("github_automation.github_adapter.urlopen", side_effect=failure),
            ):
                with self.assertRaises(GitHubAdapterError):
                    UrllibHTTPTransport().request(
                        "GET",
                        "https://api.github.com/app",
                        headers={"Accept": "application/vnd.github+json"},
                    )

    def test_normalizes_failure_while_reading_http_error_body(self) -> None:
        failure = HTTPError("https://api.github.com/app", 502, "bad gateway", {}, None)
        failure.read = lambda: (_ for _ in ()).throw(TimeoutError("read timeout"))
        try:
            with patch("github_automation.github_adapter.urlopen", side_effect=failure):
                with self.assertRaises(GitHubAdapterError):
                    UrllibHTTPTransport().request(
                        "PATCH",
                        "https://api.github.com/repos/example-owner/example-repo/check-runs/1",
                        headers={"Accept": "application/vnd.github+json"},
                    )
        finally:
            failure.close()


if __name__ == "__main__":
    unittest.main()
