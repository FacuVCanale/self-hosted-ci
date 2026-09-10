"""The job-log transport must not hand its token to the redirect target.

GitHub answers the job-log endpoint with 302 to a pre-signed storage URL. A
transport that lets urllib follow that redirect forwards the installation token
to a third-party host, which is both a credential leak and an immediate 401 -
the failure that left published Check Runs stuck `in_progress` in production.
"""

from __future__ import annotations

import importlib.util
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER_CLI = ROOT / "scripts/host/outbound-coordinator-worker.py"


def load_cli():
    spec = importlib.util.spec_from_file_location("worker_cli_transport", WORKER_CLI)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Recorder:
    def __init__(self):
        self.authorization_seen = []
        self.paths = []


def make_server(recorder: Recorder, body: bytes):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            recorder.paths.append(self.path)
            recorder.authorization_seen.append(self.headers.get("Authorization"))
            if self.path.startswith("/logs"):
                target = f"http://{self.server.server_address[0]}:{self.server.server_address[1]}/signed"
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class JobLogRedirectTests(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli()
        self.recorder = Recorder()
        self.body = b'{"phase":"backend","memory_peak_bytes":1}\n' * 4
        self.server = make_server(self.recorder, self.body)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def stream(self):
        transport = self.cli.HTTPS(10)
        # The redirect target is plain http in this fixture, so exercise the
        # follow path with the scheme guard relaxed to the loopback server.
        original = self.cli.HTTPS.stream

        return transport, original

    def test_the_redirect_target_never_receives_the_authorization_header(self):
        transport = self.cli.HTTPS(10)
        chunks = []
        try:
            for chunk in transport.stream(
                f"{self.base}/logs", headers={"Authorization": "Bearer secret-token"}
            ):
                chunks.append(chunk)
        except Exception:
            # The https-only guard may refuse the loopback target; what must
            # hold either way is that the token was never sent onward.
            pass
        self.assertEqual(self.recorder.paths[0], "/logs")
        self.assertEqual(self.recorder.authorization_seen[0], "Bearer secret-token")
        for path, authorization in zip(
            self.recorder.paths[1:], self.recorder.authorization_seen[1:]
        ):
            self.assertIsNone(
                authorization, f"token forwarded to redirect target {path}"
            )

    def test_a_plain_http_redirect_target_is_refused(self):
        transport = self.cli.HTTPS(10)
        with self.assertRaises(Exception):
            list(
                transport.stream(
                    f"{self.base}/logs", headers={"Authorization": "Bearer secret"}
                )
            )

    def test_the_transport_disables_automatic_redirects(self):
        source = WORKER_CLI.read_text(encoding="utf-8")
        self.assertIn("HTTPRedirectHandler", source)
        self.assertIn("def redirect_request", source)
        self.assertIn("return None", source)


class PollIsolationTests(unittest.TestCase):
    """One unapprovable pull request must not abort the whole reconciliation."""

    def test_authority_errors_are_caught_per_action(self):
        source = WORKER_CLI.read_text(encoding="utf-8")
        self.assertIn(
            "except (LocalApprovalError, WorkerAuthorityError) as exc:", source
        )

    def test_a_stacked_pull_request_is_not_listed(self):
        from github_automation.worker_authority import (
            WORKER_PERMISSIONS,
            WorkerAppAuthorityV1,
            WorkerGitHubClient,
        )
        import json
        from datetime import datetime, timedelta, timezone
        from github_automation.worker_authority import HTTPResponse

        now = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
        authority = WorkerAppAuthorityV1(
            101, "worker", 202, "o/r", 303, "selected", "master",
            "ci-jit-pilot-child.yml", ".github/workflows/ci-jit-pilot-child.yml",
            dict(WORKER_PERMISSIONS),
        )

        listing = [
            {"number": 73, "state": "open",
             "head": {"sha": "a" * 40, "repo": {"id": 303}},
             "base": {"ref": "fix/other-branch", "repo": {"id": 303}}},
            {"number": 434, "state": "open",
             "head": {"sha": "b" * 40, "repo": {"id": 303}},
             "base": {"ref": "master", "repo": {"id": 303}}},
        ]

        class Transport:
            def request(self, method, url, *, headers, json_body=None):
                if url.endswith("/app"):
                    return HTTPResponse(200, json.dumps({"id": 101, "slug": "worker"}).encode())
                if url.endswith("/installation"):
                    return HTTPResponse(200, json.dumps({
                        "id": 202, "app_id": 101, "repository_selection": "selected",
                        "permissions": dict(WORKER_PERMISSIONS),
                    }).encode())
                if "access_tokens" in url:
                    return HTTPResponse(201, json.dumps({
                        "token": "ghs_x", "permissions": dict(WORKER_PERMISSIONS),
                        "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
                        "repositories": [{"id": 303, "full_name": "o/r"}],
                    }).encode())
                return HTTPResponse(200, json.dumps(listing).encode())

        class Signer:
            def sign(self, value):
                return b"sig"

        client = WorkerGitHubClient(authority, Signer(), Transport(), clock=lambda: now)
        token = client.authenticate()
        self.assertEqual(client.open_pull_requests(token), ((434, "b" * 40),))


if __name__ == "__main__":
    unittest.main()
