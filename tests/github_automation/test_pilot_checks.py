import json
import unittest
from datetime import datetime, timedelta, timezone

from github_automation.pilot_checks import (
    GateAppAuthorityV1,
    GateCheckClient,
    GateCheckError,
    GateToken,
    PHASE_CHECK_NAMES,
    PROFILE_PHASES,
    PhaseVerdict,
    PilotCheckPublisher,
    abandoned_verdicts,
    parse_phase_evidence,
    phase_verdicts,
)
from github_automation.worker_authority import HTTPResponse

DETAILS = "https://github.com/alethia-earth/Overworld/actions/runs/1/job/2"


def phase_line(phase):
    return json.dumps({
        "phase": phase, "memory_peak_bytes": 1, "oom_delta": 0,
    }, separators=(",", ":")).encode() + b"\n"


class PhaseEvidenceTests(unittest.TestCase):
    def test_reports_each_reviewed_phase_once_in_order(self):
        log = b"noise\n" + phase_line("backend") + b"more\n" + phase_line("frontend")
        self.assertEqual(parse_phase_evidence([log]), ("backend", "frontend"))

    def test_rejoins_a_marker_split_across_chunks(self):
        log = b"noise\n" + phase_line("backend")
        cut = len(log) - 30
        self.assertEqual(parse_phase_evidence([log[:cut], log[cut:]]), ("backend",))

    def test_ignores_a_phase_name_outside_the_reviewed_profile(self):
        self.assertEqual(parse_phase_evidence([phase_line("payload")]), ())

    def test_refuses_an_unbounded_log(self):
        with self.assertRaisesRegex(GateCheckError, "readable bound"):
            parse_phase_evidence([b"x" * (64 * 1024 * 1024 + 1)])


class PhaseVerdictTests(unittest.TestCase):
    def verdicts(self, conclusion, observed):
        return phase_verdicts(
            job_conclusion=conclusion, observed=observed, details_url=DETAILS
        )

    def test_a_green_job_passes_every_published_phase(self):
        result = self.verdicts("success", ("backend", "frontend", "e2e"))
        self.assertEqual(
            {phase: value.conclusion for phase, value in result.items()},
            {"backend": "success", "frontend": "success"},
        )

    def test_a_phase_line_alone_never_proves_that_phase_passed(self):
        # The cleanup trap emits the same line on failure, so backend evidence
        # without frontend evidence must not be read as a backend pass.
        result = self.verdicts("failure", ("backend",))
        self.assertEqual(result["backend"].conclusion, "failure")

    def test_evidence_for_the_next_phase_proves_the_previous_one_passed(self):
        result = self.verdicts("failure", ("backend", "frontend"))
        self.assertEqual(result["backend"].conclusion, "success")
        self.assertEqual(result["frontend"].conclusion, "failure")

    def test_a_failure_inside_the_unpublished_last_phase_keeps_both_green(self):
        result = self.verdicts("failure", ("backend", "frontend", "e2e"))
        self.assertEqual(result["backend"].conclusion, "success")
        self.assertEqual(result["frontend"].conclusion, "success")

    def test_a_phase_never_reached_is_skipped_not_failed(self):
        result = self.verdicts("failure", ())
        self.assertEqual(result["backend"].conclusion, "failure")
        self.assertEqual(result["frontend"].conclusion, "skipped")

    def test_cancellation_and_timeout_keep_their_own_conclusion(self):
        self.assertEqual(self.verdicts("cancelled", ())["backend"].conclusion, "cancelled")
        self.assertEqual(self.verdicts("timed_out", ())["backend"].conclusion, "timed_out")

    def test_inference_is_refused_if_the_profile_reorders_its_phases(self):
        with self.assertRaisesRegex(GateCheckError, "reviewed ordered phase list"):
            phase_verdicts(
                job_conclusion="success", observed=(),
                phases=("frontend", "backend", "e2e"), details_url=DETAILS,
            )

    def test_evidence_outside_the_profile_is_refused(self):
        with self.assertRaisesRegex(GateCheckError, "outside the reviewed profile"):
            self.verdicts("success", ("backend", "payload"))

    def test_every_summary_carries_the_evidence_link(self):
        for value in list(self.verdicts("failure", ()).values()) + list(
            abandoned_verdicts(reason="host lost", details_url=DETAILS).values()
        ):
            self.assertIn(DETAILS, value.summary)


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, method, url, *, headers, json_body=None):
        self.calls.append((method, url, json_body, headers.get("Authorization", "")))
        key = (method, url.split("api.github.com")[-1])
        value = self.responses.get(key)
        if value is None:
            raise AssertionError(f"unexpected request {key}")
        status, body = value
        return HTTPResponse(status, json.dumps(body).encode())


class FakeSigner:
    def sign(self, value):
        return b"signature"


AUTHORITY = GateAppAuthorityV1(
    4729014, "facu-ci-gate", 156799177, "alethia-earth/Overworld", 1172953958,
    "selected", {"checks": "write", "metadata": "read"},
)
NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def gate_responses(extra=None):
    responses = {
        ("GET", "/app"): (200, {"id": 4729014, "slug": "facu-ci-gate"}),
        ("GET", "/repos/alethia-earth/Overworld/installation"): (200, {
            "id": 156799177, "app_id": 4729014, "repository_selection": "selected",
            "permissions": {"checks": "write", "metadata": "read"},
        }),
        ("POST", "/app/installations/156799177/access_tokens"): (201, {
            "token": "ghs_example", "expires_at": "2026-09-10T13:00:00Z",
        }),
    }
    responses.update(extra or {})
    return responses


class GateAuthorityTests(unittest.TestCase):
    def test_permissions_must_be_exactly_checks_write_and_metadata_read(self):
        for permissions in (
            {"checks": "write"},
            {"checks": "write", "metadata": "read", "contents": "read"},
            {"checks": "read", "metadata": "read"},
        ):
            with self.subTest(permissions=permissions), self.assertRaises(GateCheckError):
                GateAppAuthorityV1(
                    1, "gate", 2, "o/r", 3, "selected", permissions
                )

    def test_all_repositories_selection_is_refused(self):
        with self.assertRaisesRegex(GateCheckError, "selected repositories"):
            GateAppAuthorityV1(
                1, "gate", 2, "o/r", 3, "all", {"checks": "write", "metadata": "read"}
            )

    def test_token_is_scoped_to_the_exact_repository_and_permissions(self):
        transport = FakeTransport(gate_responses())
        client = GateCheckClient(AUTHORITY, FakeSigner(), transport, clock=lambda: NOW)
        token = client.authenticate()
        self.assertEqual(token.value, "ghs_example")
        body = [call for call in transport.calls if call[0] == "POST"][0][2]
        self.assertEqual(body["repository_ids"], [1172953958])
        self.assertEqual(body["permissions"], {"checks": "write", "metadata": "read"})

    def test_a_different_app_answering_the_jwt_is_refused(self):
        responses = gate_responses()
        responses[("GET", "/app")] = (200, {"id": 999, "slug": "someone-else"})
        client = GateCheckClient(
            AUTHORITY, FakeSigner(), FakeTransport(responses), clock=lambda: NOW
        )
        with self.assertRaisesRegex(GateCheckError, "App identity mismatch"):
            client.authenticate()


class CheckRunWriteTests(unittest.TestCase):
    def client(self, extra):
        self.transport = FakeTransport(gate_responses(extra))
        return GateCheckClient(AUTHORITY, FakeSigner(), self.transport, clock=lambda: NOW)

    def test_check_is_opened_on_the_pull_request_head_not_the_dispatch_ref(self):
        head = "a" * 40
        client = self.client({("POST", "/repos/alethia-earth/Overworld/check-runs"): (
            201, {"id": 55, "head_sha": head, "name": "backend lint + test"}
        )})
        token = client.authenticate()
        identifier = client.create_in_progress(
            name="backend lint + test", head_sha=head, details_url=DETAILS,
            summary="running", token=token,
        )
        self.assertEqual(identifier, 55)
        body = [c for c in self.transport.calls if c[1].endswith("/check-runs")][0][2]
        self.assertEqual(body["head_sha"], head)
        self.assertEqual(body["status"], "in_progress")

    def test_a_receipt_for_another_commit_is_refused(self):
        client = self.client({("POST", "/repos/alethia-earth/Overworld/check-runs"): (
            201, {"id": 55, "head_sha": "b" * 40, "name": "backend lint + test"}
        )})
        token = client.authenticate()
        with self.assertRaisesRegex(GateCheckError, "receipt is not exact"):
            client.create_in_progress(
                name="backend lint + test", head_sha="a" * 40, details_url=DETAILS,
                summary="running", token=token,
            )

    def test_only_the_published_phase_names_may_be_written(self):
        client = self.client({})
        token = client.authenticate()
        for name in ("ci-gate", "local-quality", "frontend e2e (playwright)"):
            with self.subTest(name=name), self.assertRaisesRegex(GateCheckError, "phase names"):
                client.create_in_progress(
                    name=name, head_sha="a" * 40, details_url=DETAILS,
                    summary="running", token=token,
                )

    def test_a_short_head_sha_is_refused(self):
        client = self.client({})
        token = client.authenticate()
        with self.assertRaisesRegex(GateCheckError, "full commit SHA"):
            client.create_in_progress(
                name="backend lint + test", head_sha="abc", details_url=DETAILS,
                summary="running", token=token,
            )

    def test_conclusion_is_read_back_before_it_is_believed(self):
        client = self.client({("PATCH", "/repos/alethia-earth/Overworld/check-runs/55"): (
            200, {"id": 55, "conclusion": "success"}
        )})
        token = client.authenticate()
        client.conclude(
            check_run_id=55, details_url=DETAILS, token=token,
            verdict=PhaseVerdict("success", "t", "s"),
        )
        with self.assertRaisesRegex(GateCheckError, "did not read back exactly"):
            client.conclude(
                check_run_id=55, details_url=DETAILS, token=token,
                verdict=PhaseVerdict("failure", "t", "s"),
            )

    def test_an_invented_conclusion_never_reaches_github(self):
        client = self.client({})
        token = client.authenticate()
        with self.assertRaisesRegex(GateCheckError, "terminal value"):
            client.conclude(
                check_run_id=55, details_url=DETAILS, token=token,
                verdict=PhaseVerdict("passed", "t", "s"),
            )

    def test_an_expired_token_is_never_used(self):
        client = self.client({})
        expired = GateToken("ghs", NOW - timedelta(seconds=1))
        with self.assertRaisesRegex(GateCheckError, "expired before use"):
            client.conclude(
                check_run_id=55, details_url=DETAILS, token=expired,
                verdict=PhaseVerdict("success", "t", "s"),
            )


class RecordingClient:
    def __init__(self, log_failure=None):
        self.opened = []
        self.concluded = []
        self.tokens = 0

    def authenticate(self):
        self.tokens += 1
        return GateToken("ghs", NOW + timedelta(minutes=30))

    def create_in_progress(self, *, name, head_sha, details_url, summary, token):
        self.opened.append((name, head_sha, summary))
        return 100 + len(self.opened)

    def conclude(self, *, check_run_id, verdict, details_url, token):
        self.concluded.append((check_run_id, verdict.conclusion))


class PublisherTests(unittest.TestCase):
    def test_start_opens_exactly_the_two_published_names_on_the_head(self):
        client = RecordingClient()
        publisher = PilotCheckPublisher(client, lambda job_id: [b""])
        opened = publisher.start(head_sha="a" * 40, details_url=DETAILS)
        self.assertEqual(sorted(opened), ["backend lint + test", "frontend lint + test"])
        self.assertEqual({name for name, _, _ in client.opened}, set(PHASE_CHECK_NAMES.values()))
        self.assertTrue(all(sha == "a" * 40 for _, sha, _ in client.opened))

    def test_conclusions_come_from_the_job_log_evidence(self):
        client = RecordingClient()
        log = phase_line("backend") + phase_line("frontend") + phase_line("e2e")
        publisher = PilotCheckPublisher(client, lambda job_id: [log])
        opened = publisher.start(head_sha="a" * 40, details_url=DETAILS)
        applied = publisher.conclude(
            checks=opened, job_id=7, job_conclusion="failure", details_url=DETAILS
        )
        self.assertEqual(applied, {
            "backend lint + test": "success", "frontend lint + test": "success",
        })

    def test_an_unreadable_log_is_never_upgraded_to_a_pass(self):
        client = RecordingClient()

        def broken(_job_id):
            raise OSError("log gone")

        publisher = PilotCheckPublisher(client, broken)
        opened = publisher.start(head_sha="a" * 40, details_url=DETAILS)
        applied = publisher.conclude(
            checks=opened, job_id=7, job_conclusion="success", details_url=DETAILS
        )
        self.assertEqual(set(applied.values()), {"stale"})

    def test_abandon_closes_every_open_check_with_the_reason(self):
        client = RecordingClient()
        publisher = PilotCheckPublisher(client, lambda job_id: [b""])
        opened = publisher.start(head_sha="a" * 40, details_url=DETAILS)
        applied = publisher.abandon(
            checks=opened, reason="the host lost power", details_url=DETAILS
        )
        self.assertEqual(set(applied.values()), {"stale"})
        self.assertEqual(len(client.concluded), 2)

    def test_the_published_names_match_the_hosted_workflow_job_names(self):
        self.assertEqual(
            sorted(PHASE_CHECK_NAMES.values()),
            ["backend lint + test", "frontend lint + test"],
        )
        self.assertEqual(PROFILE_PHASES, ("backend", "frontend", "e2e"))


if __name__ == "__main__":
    unittest.main()
