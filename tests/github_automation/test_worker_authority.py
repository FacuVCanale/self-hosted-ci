from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from github_automation.worker_authority import (
    API_ROOT,
    API_VERSION,
    HTTPResponse,
    WORKER_PERMISSIONS,
    WorkerAppAuthorityV1,
    WorkerAuthorityError,
    WorkerGitHubClient,
)


NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)
REPOSITORY = "FacuVCanale/selected-repo"


def authority(**changes) -> WorkerAppAuthorityV1:
    values = {
        "app_id": 101,
        "app_slug": "self-hosted-ci-worker",
        "installation_id": 202,
        "repository": REPOSITORY,
        "repository_id": 303,
        "repository_selection": "selected",
        "default_branch": "main",
        "workflow_id": "ci-gate-child.yml",
        "workflow_path": ".github/workflows/ci-gate-child.yml",
        "permissions": dict(WORKER_PERMISSIONS),
    }
    values.update(changes)
    return WorkerAppAuthorityV1(**values)


def response(status: int, value: object) -> HTTPResponse:
    return HTTPResponse(status, json.dumps(value).encode())


class Signer:
    def __init__(self) -> None:
        self.inputs = []

    def sign(self, value: bytes) -> bytes:
        self.inputs.append(value)
        return b"signature"


class FakeTransport:
    def __init__(self, *responses: HTTPResponse) -> None:
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers, json_body=None):
        self.calls.append((method, url, dict(headers), json_body))
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


def auth_responses(**changes):
    app = {"id": 101, "slug": "self-hosted-ci-worker"}
    installation = {
        "id": 202,
        "app_id": 101,
        "repository_selection": "selected",
        "permissions": dict(WORKER_PERMISSIONS),
    }
    token = {
        "token": "ghs_" + "x" * 36,
        "expires_at": (NOW + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "permissions": dict(WORKER_PERMISSIONS),
        "repositories": [{"id": 303, "full_name": REPOSITORY}],
    }
    {"app": app, "installation": installation, "token": token}.update({})
    if "app" in changes:
        changes.pop("app")(app)
    if "installation" in changes:
        changes.pop("installation")(installation)
    if "token" in changes:
        changes.pop("token")(token)
    if changes:
        raise AssertionError(changes)
    return response(200, app), response(200, installation), response(201, token)


class WorkerAuthorityTests(unittest.TestCase):
    def authenticate(self, *responses_):
        transport = FakeTransport(*(responses_ or auth_responses()))
        signer = Signer()
        client = WorkerGitHubClient(authority(), signer, transport, clock=lambda: NOW)
        return client, client.authenticate(), transport, signer

    def test_exact_selected_repository_token_and_headers(self) -> None:
        client, token, transport, signer = self.authenticate()
        self.assertNotIn(token.value, repr(token))
        self.assertEqual(3, len(transport.calls))
        self.assertEqual(("GET", API_ROOT + "/app"), transport.calls[0][:2])
        self.assertEqual(
            ("GET", API_ROOT + f"/repos/{REPOSITORY}/installation"),
            transport.calls[1][:2],
        )
        mint = transport.calls[2]
        self.assertEqual(
            {
                "repository_ids": [303],
                "permissions": dict(WORKER_PERMISSIONS),
            },
            mint[3],
        )
        for call in transport.calls:
            self.assertEqual(API_VERSION, call[2]["X-GitHub-Api-Version"])
            self.assertTrue(call[2]["Authorization"].startswith("Bearer "))
        self.assertEqual(1, len(signer.inputs))

    def test_app_installation_and_token_drift_each_fail_closed(self) -> None:
        mutations = (
            {"app": lambda value: value.update(id=999)},
            {"installation": lambda value: value.update(repository_selection="all")},
            {
                "installation": lambda value: value["permissions"].update(
                    contents="read"
                )
            },
            {"token": lambda value: value["permissions"].update(actions="read")},
            {
                "token": lambda value: value["repositories"].append(
                    {"id": 1, "full_name": "x/y"}
                )
            },
            {"token": lambda value: value["repositories"][0].update(id=999)},
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(WorkerAuthorityError),
            ):
                self.authenticate(*auth_responses(**mutation))

    def test_token_expiry_allows_only_bounded_github_server_clock_skew(self) -> None:
        accepted = auth_responses(
            token=lambda value: value.update(
                expires_at=(NOW + timedelta(hours=1, seconds=60))
                .isoformat()
                .replace("+00:00", "Z")
            )
        )
        self.authenticate(*accepted)
        rejected = auth_responses(
            token=lambda value: value.update(
                expires_at=(NOW + timedelta(hours=1, seconds=61))
                .isoformat()
                .replace("+00:00", "Z")
            )
        )
        with self.assertRaises(WorkerAuthorityError):
            self.authenticate(*rejected)

    def test_minimal_client_uses_only_fixed_repository_workflow_run_and_jobs(
        self,
    ) -> None:
        pilot_authority = authority(
            workflow_id="ci-jit-pilot-child.yml",
            workflow_path=".github/workflows/ci-jit-pilot-child.yml",
        )
        auth = auth_responses()
        extra = (
            response(
                200, {"id": 303, "full_name": REPOSITORY, "default_branch": "main"}
            ),
            response(
                200,
                {
                    "number": 7,
                    "state": "open",
                    "head": {"sha": "a" * 40},
                    "base": {"ref": "main", "repo": {"id": 303}},
                },
            ),
            response(
                200,
                {
                    "id": 404,
                    "path": ".github/workflows/ci-jit-pilot-child.yml",
                    "state": "active",
                },
            ),
            response(
                200,
                {
                    "workflow_run_id": 505,
                    "run_url": API_ROOT + f"/repos/{REPOSITORY}/actions/runs/505",
                },
            ),
            response(
                200,
                {
                    "id": 505,
                    "repository": {"id": 303},
                    "path": ".github/workflows/ci-jit-pilot-child.yml",
                    "head_branch": "main",
                },
            ),
            response(
                200,
                {
                    "total_count": 2,
                    "jobs": [{"id": 1, "run_id": 505}, {"id": 2, "run_id": 505}],
                },
            ),
        )
        transport = FakeTransport(*auth, *extra)
        client = WorkerGitHubClient(
            pilot_authority, Signer(), transport, clock=lambda: NOW
        )
        token = client.authenticate()
        self.assertEqual(303, client.repository(token)["id"])
        self.assertEqual("a" * 40, client.pull_request(7, token)["head"]["sha"])
        self.assertEqual(404, client.workflow(token)["id"])
        self.assertEqual(505, client.dispatch_pilot("{}", token))
        self.assertEqual(505, client.run(505, token)["id"])
        self.assertEqual(2, client.jobs(505, token)["total_count"])
        urls = [call[1] for call in transport.calls[3:]]
        self.assertEqual(
            [
                API_ROOT + f"/repos/{REPOSITORY}",
                API_ROOT + f"/repos/{REPOSITORY}/pulls/7",
                API_ROOT
                + f"/repos/{REPOSITORY}/actions/workflows/ci-jit-pilot-child.yml",
                API_ROOT
                + f"/repos/{REPOSITORY}/actions/workflows/ci-jit-pilot-child.yml/dispatches",
                API_ROOT + f"/repos/{REPOSITORY}/actions/runs/505",
                API_ROOT
                + f"/repos/{REPOSITORY}/actions/runs/505/jobs?filter=latest&per_page=100",
            ],
            urls,
        )
        self.assertEqual(
            {
                "ref": "main",
                "inputs": {"pilot_package": "{}"},
                "return_run_details": True,
            },
            transport.calls[6][3],
        )

    def test_pilot_dispatch_cannot_cross_to_a_non_pilot_workflow(self) -> None:
        client, token, transport, _ = self.authenticate()
        crossed = WorkerGitHubClient(
            authority(
                workflow_id="ci-gate-child.yml",
                workflow_path=".github/workflows/ci-gate-child.yml",
            ),
            Signer(),
            transport,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(WorkerAuthorityError, "fixed pilot"):
            crossed.dispatch_pilot("{}", token)

    def test_authority_rejects_all_repositories_extra_permissions_and_workflow_drift(
        self,
    ) -> None:
        for changes in (
            {"repository_selection": "all"},
            {"permissions": {**WORKER_PERMISSIONS, "contents": "read"}},
            {"workflow_path": ".github/workflows/other.yml"},
        ):
            with self.subTest(changes=changes), self.assertRaises(WorkerAuthorityError):
                authority(**changes)

    def test_source_contract_has_no_secret_argv_environment_or_logging(self) -> None:
        source = (
            Path(__file__).parents[2] / "github_automation/worker_authority.py"
        ).read_text()
        self.assertIn("info.st_uid != 0", source)
        self.assertIn("stat.S_IMODE(info.st_mode) != 0o600", source)
        self.assertIn('"O_NOFOLLOW"', source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("logging", source)
        self.assertIn('API_ROOT = "https://api.github.com"', source)


if __name__ == "__main__":
    unittest.main()
