from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import unittest
import urllib.request

from cryptography.hazmat.primitives.asymmetric import rsa


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/host/github-live-job-verifier.py"
SPEC = importlib.util.spec_from_file_location("github_live_job_verifier", SCRIPT)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
NOW = 1_788_000_000


def request() -> dict:
    return {
        "workflow_job_id": "8002",
        "run_id": "8001",
        "run_attempt": 2,
        "repository_id": "1347574115",
        "repository": "FacuVCanale/self-hosted-ci-sandbox",
        "dispatch_sha": "a" * 40,
        "workflow_ref": "FacuVCanale/self-hosted-ci-sandbox/.github/workflows/ci-gate.yml@refs/heads/main",
        "job_name": "local-quality",
        "runner_name": "wsl-jit-runner-1",
        "runner_group": None,
        "labels": ["wsl-jit-0123456789abcdef0123456789abcdef"],
        "required_status": "in_progress",
    }


class Response:
    def __init__(self, value: dict, status: int = 200) -> None:
        self.status = status
        self._body = io.BytesIO(json.dumps(value).encode("utf-8"))

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, *, mutate_job=None, mutate_run=None, mutate_token=None) -> None:
        self.calls: list[tuple[str, str, dict, dict | None]] = []
        self.mutate_job = mutate_job
        self.mutate_run = mutate_run
        self.mutate_token = mutate_token

    def __call__(self, value: urllib.request.Request, timeout: int):
        body = json.loads(value.data) if value.data else None
        self.calls.append((value.method, value.full_url, dict(value.headers), body))
        expected = request()
        repository = {
            "id": int(expected["repository_id"]),
            "full_name": expected["repository"],
        }
        if value.full_url.endswith("/access_tokens"):
            response = {
                "token": "ghs_" + "x" * 36,
                "expires_at": datetime.fromtimestamp(NOW, timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "permissions": {"actions": "read", "metadata": "read"},
                "repositories": [repository],
            }
            response["expires_at"] = (
                (datetime.fromtimestamp(NOW, timezone.utc) + timedelta(minutes=30))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            if self.mutate_token:
                self.mutate_token(response)
            return Response(response)
        if "/actions/jobs/" in value.full_url:
            response = {
                "id": 8002,
                "run_id": 8001,
                "head_sha": "a" * 40,
                "name": "local-quality",
                "labels": expected["labels"],
                "runner_name": "wsl-jit-runner-1",
                "runner_group_name": None,
                "status": "in_progress",
            }
            if self.mutate_job:
                self.mutate_job(response)
            return Response(response)
        response = {
            "id": 8001,
            "run_attempt": 2,
            "head_sha": "a" * 40,
            "path": ".github/workflows/ci-gate.yml",
            "head_branch": "main",
            "repository": repository,
        }
        if self.mutate_run:
            self.mutate_run(response)
        return Response(response)


class GitHubLiveJobVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def verify(self, opener: FakeOpener, value: dict | None = None) -> dict:
        validated = VERIFIER.validate_request(value or request())
        return VERIFIER.verify_live_job(
            validated,
            123,
            456,
            self.private_key,
            api=VERIFIER.GitHubAPI(opener),
            now=NOW,
        )

    def test_exact_live_job_emits_only_broker_contract_json(self) -> None:
        opener = FakeOpener()
        result = self.verify(opener)
        expected = request()
        expected.pop("required_status")
        expected.update({"status": "in_progress", "verified": True})
        self.assertEqual(expected, result)
        self.assertEqual(3, len(opener.calls))
        token_call = opener.calls[0]
        self.assertEqual("POST", token_call[0])
        self.assertEqual(
            "https://api.github.com/app/installations/456/access_tokens", token_call[1]
        )
        self.assertEqual(
            {"permissions": {"actions": "read"}, "repository_ids": [1347574115]},
            token_call[3],
        )
        self.assertTrue(token_call[2]["Authorization"].startswith("Bearer eyJ"))
        self.assertEqual(
            "https://api.github.com/repos/FacuVCanale/self-hosted-ci-sandbox/actions/jobs/8002",
            opener.calls[1][1],
        )
        self.assertEqual(
            "https://api.github.com/repos/FacuVCanale/self-hosted-ci-sandbox/actions/runs/8001",
            opener.calls[2][1],
        )

    def test_every_live_binding_drift_fails_closed(self) -> None:
        job_drifts = {
            "job_id": lambda value: value.update(id=999),
            "run_id": lambda value: value.update(run_id=999),
            "sha": lambda value: value.update(head_sha="b" * 40),
            "name": lambda value: value.update(name="other"),
            "labels": lambda value: value.update(labels=["self-hosted"]),
            "runner": lambda value: value.update(runner_name="other"),
            "group": lambda value: value.update(runner_group_name="Default"),
            "status": lambda value: value.update(status="queued"),
        }
        for name, mutate in job_drifts.items():
            with self.subTest(name=name), self.assertRaises(VERIFIER.VerificationError):
                self.verify(FakeOpener(mutate_job=mutate))
        # GitHub's workflow-job endpoint does not contractually expose
        # run_attempt; attempt authority comes from the exact run endpoint.
        self.assertTrue(
            self.verify(
                FakeOpener(mutate_job=lambda value: value.update(run_attempt=999))
            )["verified"]
        )
        run_drifts = {
            "run": lambda value: value.update(id=999),
            "attempt": lambda value: value.update(run_attempt=3),
            "sha": lambda value: value.update(head_sha="b" * 40),
            "path": lambda value: value.update(path=".github/workflows/other.yml"),
            "ref": lambda value: value.update(head_branch="dev"),
            "repo": lambda value: value["repository"].update(id=999),
        }
        for name, mutate in run_drifts.items():
            with self.subTest(name=name), self.assertRaises(VERIFIER.VerificationError):
                self.verify(FakeOpener(mutate_run=mutate))

    def test_token_is_exact_repo_read_only_and_short_lived(self) -> None:
        mutations = {
            "write": lambda value: value["permissions"].update(actions="write"),
            "extra_read": lambda value: value["permissions"].update(contents="read"),
            "broad": lambda value: value["repositories"].append(
                {"id": 2, "full_name": "o/r"}
            ),
            "wrong_repo": lambda value: value["repositories"][0].update(id=2),
            "expired": lambda value: value.update(expires_at="2020-01-01T00:00:00Z"),
            "long": lambda value: value.update(expires_at="2030-01-01T00:00:00Z"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(VERIFIER.VerificationError):
                self.verify(FakeOpener(mutate_token=mutate))

    def test_request_schema_duplicate_keys_and_types_fail_closed(self) -> None:
        invalid = request()
        invalid["extra"] = True
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_request(invalid)
        invalid = request()
        invalid["labels"] = [["unhashable"]]
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_request(invalid)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "duplicate"):
            VERIFIER._exact_json(b'{"run_id":"1","run_id":"2"}')

    def test_endpoint_and_secret_surfaces_are_fixed(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('API_ROOT = "https://api.github.com"', source)
        self.assertIn(
            'CONFIG_PATH = Path("/etc/self-hosted-ci/github-live-job-verifier.json")',
            source,
        )
        self.assertNotIn("os.environ", source)
        self.assertNotIn("add_argument", source)
        self.assertIn("HTTP_TIMEOUT_SECONDS = 5", source)
        self.assertIn("MAX_RESPONSE_BYTES = 1_048_576", source)


if __name__ == "__main__":
    unittest.main()
