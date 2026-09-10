"""Publish the local pilot's per-phase result as PR Check Runs.

The pilot workflow is dispatched on the default branch, so the Check Run
GitHub Actions creates by itself lands on the default branch head and can never
appear on a pull request.  A dedicated `checks:write` GitHub App is therefore
the only way to put the local result where the author reads it.

Granularity comes from the reviewed repository command profile.  Its runner
script executes a fixed, ordered phase list and prints one measurement line per
phase that finished, whether the phase passed or the cleanup trap emitted it.
The line alone is therefore ambiguous; what disambiguates it is the order: the
script runs under `set -e`, so evidence for phase N+1 proves phase N passed.
That inference is bound to the exact ordered phase list, and refuses to guess
if the profile ever changes it.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .worker_authority import (
    API_ROOT,
    API_VERSION,
    HTTPResponse,
    HTTPTransport,
    RS256Signer,
)

GATE_PERMISSIONS = {"checks": "write", "metadata": "read"}
#: The ordered phase list of the reviewed Overworld command profile.  Evidence
#: parsing is refused for any other ordering, because the "next phase proves the
#: previous one" inference is only valid for a fixed sequential pipeline.
PROFILE_PHASES: tuple[str, ...] = ("backend", "frontend", "e2e")
#: Published Check Run name per phase, using the exact names the repository's
#: GitHub-hosted workflow used, so the pull request reads the same as before.
PHASE_CHECK_NAMES: Mapping[str, str] = {
    "backend": "backend lint + test",
    "frontend": "frontend lint + test",
}
_PHASE_LINE = re.compile(rb'\{"phase":"([a-z0-9-]{1,32})","memory_peak_bytes":')
_SHA = re.compile(r"[0-9a-f]{40}")
_MAX_LOG_BYTES = 64 * 1024 * 1024
#: Conclusions GitHub accepts on a completed Check Run.
_TERMINAL = {"success", "failure", "cancelled", "timed_out", "stale", "skipped"}


class GateCheckError(RuntimeError):
    """One Check Run authority or publication boundary was not exact."""


@dataclass(frozen=True)
class PhaseVerdict:
    """The conclusion published for one phase, with the reason behind it."""

    conclusion: str
    title: str
    summary: str


def parse_phase_evidence(chunks: Iterable[bytes]) -> tuple[str, ...]:
    """Extract, in order, the phases whose measurement line reached the log.

    Accepts the job log as an iterable of byte chunks so a large log is never
    held in memory whole.  A phase is reported at most once, in the order it
    first appeared.  Unknown phase names are ignored rather than trusted.
    """
    observed: list[str] = []
    tail = b""
    total = 0
    for chunk in chunks:
        if not isinstance(chunk, (bytes, bytearray)):
            raise GateCheckError("job log chunk is not bytes")
        total += len(chunk)
        if total > _MAX_LOG_BYTES:
            raise GateCheckError("job log exceeded the readable bound")
        buffer = tail + bytes(chunk)
        for match in _PHASE_LINE.finditer(buffer):
            phase = match.group(1).decode("ascii")
            if phase in PROFILE_PHASES and phase not in observed:
                observed.append(phase)
        # Keep enough tail to rejoin a marker split across two chunks.
        tail = buffer[-64:]
    return tuple(observed)


def phase_verdicts(
    *,
    job_conclusion: str,
    observed: Sequence[str],
    phases: Sequence[str] = PROFILE_PHASES,
    details_url: str,
) -> dict[str, PhaseVerdict]:
    """Derive one published verdict per named phase from the run's evidence.

    `job_conclusion` is the terminal conclusion of the single local job.
    `observed` is the output of :func:`parse_phase_evidence`.  A phase counts as
    passed when the whole job passed, or when a later phase produced evidence,
    which under `set -e` is only reachable after the earlier phase succeeded.
    """
    ordered = tuple(phases)
    if ordered != PROFILE_PHASES:
        raise GateCheckError(
            "phase evidence inference requires the reviewed ordered phase list"
        )
    seen = set(observed)
    if not seen <= set(ordered):
        raise GateCheckError("job log reported a phase outside the reviewed profile")
    verdicts: dict[str, PhaseVerdict] = {}
    failed_before = False
    for index, phase in enumerate(ordered):
        if phase not in PHASE_CHECK_NAMES:
            # Still needed to reason about ordering, but not published.
            passed = job_conclusion == "success" or (
                index + 1 < len(ordered) and ordered[index + 1] in seen
            )
            failed_before = failed_before or not passed
            continue
        later = ordered[index + 1] if index + 1 < len(ordered) else None
        passed = job_conclusion == "success" or (later is not None and later in seen)
        if passed:
            verdicts[phase] = PhaseVerdict(
                "success",
                f"{phase} passed on the local runner",
                f"The `{phase}` phase of the reviewed Overworld CI profile completed "
                f"on the self-hosted Windows runner. Full job log: {details_url}",
            )
        elif failed_before:
            verdicts[phase] = PhaseVerdict(
                "skipped",
                f"{phase} never ran",
                "An earlier phase of the local run failed, so this phase was never "
                f"reached. Full job log: {details_url}",
            )
        elif job_conclusion in {"cancelled", "cancel"}:
            verdicts[phase] = PhaseVerdict(
                "cancelled",
                f"{phase} was cancelled",
                f"The local run was cancelled during the `{phase}` phase. "
                f"Full job log: {details_url}",
            )
        elif job_conclusion in {"timed_out", "timeout"}:
            verdicts[phase] = PhaseVerdict(
                "timed_out",
                f"{phase} timed out",
                f"The local run hit its time limit during the `{phase}` phase. "
                f"Full job log: {details_url}",
            )
        else:
            verdicts[phase] = PhaseVerdict(
                "failure",
                f"{phase} failed on the local runner",
                f"The `{phase}` phase of the reviewed Overworld CI profile failed on "
                f"the self-hosted Windows runner. Full job log: {details_url}",
            )
        failed_before = failed_before or not passed
    return verdicts


def abandoned_verdicts(*, reason: str, details_url: str) -> dict[str, PhaseVerdict]:
    """Verdicts for a run whose local owner disappeared before concluding.

    A Check Run left `in_progress` blocks its author forever, so every path out
    of the pilot lifecycle - including a host that lost power mid-run - resolves
    into an explicit `stale` conclusion that names what happened.
    """
    return {
        phase: PhaseVerdict(
            "stale",
            f"{phase} result was lost",
            "The self-hosted Windows runner stopped owning this run before it "
            f"could report a result ({reason}). Nothing was proven about this "
            f"phase; dispatch the pull request again. Job log, if any: {details_url}",
        )
        for phase in PHASE_CHECK_NAMES
    }


@dataclass(frozen=True)
class GateAppAuthorityV1:
    """The exact selected-repository identity allowed to write Check Runs."""

    app_id: int
    app_slug: str
    installation_id: int
    repository: str
    repository_id: int
    repository_selection: str
    permissions: Mapping[str, str]

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (self.app_id, self.installation_id, self.repository_id)
        ):
            raise GateCheckError("gate App numeric identities must be positive")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise GateCheckError("gate App repository is invalid")
        if self.repository_selection != "selected":
            raise GateCheckError("gate App must use selected repositories")
        if dict(self.permissions) != GATE_PERMISSIONS:
            raise GateCheckError("gate App permissions are not exact")
        if not re.fullmatch(r"[A-Za-z0-9-]+", self.app_slug):
            raise GateCheckError("gate App slug is invalid")


@dataclass(frozen=True, repr=False)
class GateToken:
    """A short-lived installation token scoped to the gate App alone."""

    value: str = field(repr=False)
    expires_at: datetime


class GateCheckClient:
    """Fixed-endpoint Check Runs client for one exact selected repository."""

    def __init__(
        self,
        authority: GateAppAuthorityV1,
        signer: RS256Signer,
        transport: HTTPTransport,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.authority = authority
        self._signer = signer
        self._transport = transport
        self._clock = clock

    def authenticate(self) -> GateToken:
        """Prove the App and installation identity, then mint a scoped token."""
        now = self._clock()
        if now.tzinfo is None:
            raise GateCheckError("gate clock must be timezone-aware")
        headers = _headers(_app_jwt(self.authority.app_id, self._signer, now))
        app = self._json(self._request("GET", "/app", headers), 200)
        if (
            app.get("id") != self.authority.app_id
            or app.get("slug") != self.authority.app_slug
        ):
            raise GateCheckError("gate App identity mismatch")
        installation = self._json(
            self._request(
                "GET", f"/repos/{self.authority.repository}/installation", headers
            ),
            200,
        )
        expected = {
            "id": self.authority.installation_id,
            "app_id": self.authority.app_id,
            "repository_selection": "selected",
            "permissions": GATE_PERMISSIONS,
        }
        if any(installation.get(key) != value for key, value in expected.items()):
            raise GateCheckError("gate App installation authority mismatch")
        token = self._json(
            self._request(
                "POST",
                f"/app/installations/{self.authority.installation_id}/access_tokens",
                headers,
                {
                    "repository_ids": [self.authority.repository_id],
                    "permissions": dict(GATE_PERMISSIONS),
                },
            ),
            201,
        )
        value, expires = token.get("token"), token.get("expires_at")
        if not isinstance(value, str) or not value or not isinstance(expires, str):
            raise GateCheckError("gate installation token is invalid")
        try:
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GateCheckError("gate token expiry is invalid") from exc
        if expires_at.tzinfo is None or expires_at <= now:
            raise GateCheckError("gate installation token is already expired")
        return GateToken(value, expires_at)

    def create_in_progress(
        self, *, name: str, head_sha: str, details_url: str, summary: str, token: GateToken
    ) -> int:
        """Open one Check Run on the exact pull request head being tested."""
        payload = {
            "name": _exact_name(name),
            "head_sha": _exact_sha(head_sha),
            "status": "in_progress",
            "details_url": details_url,
            "started_at": _stamp(self._clock()),
            "output": {"title": f"{name} is running on the local runner", "summary": summary},
        }
        value = self._token_json("POST", "/check-runs", token, 201, payload)
        identifier = value.get("id")
        if (
            isinstance(identifier, bool)
            or not isinstance(identifier, int)
            or identifier < 1
            or value.get("head_sha") != head_sha
            or value.get("name") != name
        ):
            raise GateCheckError("Check Run creation receipt is not exact")
        return identifier

    def conclude(
        self, *, check_run_id: int, verdict: PhaseVerdict, details_url: str, token: GateToken
    ) -> None:
        """Close one Check Run with its real conclusion and read the result back."""
        if verdict.conclusion not in _TERMINAL:
            raise GateCheckError("Check Run conclusion is not an accepted terminal value")
        if isinstance(check_run_id, bool) or not isinstance(check_run_id, int) or check_run_id < 1:
            raise GateCheckError("Check Run identity must be positive")
        payload = {
            "status": "completed",
            "conclusion": verdict.conclusion,
            "completed_at": _stamp(self._clock()),
            "details_url": details_url,
            "output": {"title": verdict.title, "summary": verdict.summary},
        }
        value = self._token_json(
            "PATCH", f"/check-runs/{check_run_id}", token, 200, payload
        )
        if value.get("id") != check_run_id or value.get("conclusion") != verdict.conclusion:
            raise GateCheckError("Check Run conclusion did not read back exactly")

    def _token_json(
        self,
        method: str,
        path: str,
        token: GateToken,
        status: int,
        body: Mapping[str, object] | None = None,
    ) -> Mapping[str, Any]:
        if token.expires_at <= self._clock():
            raise GateCheckError("gate installation token expired before use")
        return self._json(
            self._request(
                method, f"/repos/{self.authority.repository}{path}", _headers(token.value), body
            ),
            status,
        )

    def _request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise GateCheckError("unsafe gate GitHub API path")
        return self._transport.request(
            method, API_ROOT + path, headers=headers, json_body=body
        )

    @staticmethod
    def _json(response: HTTPResponse, expected_status: int) -> Mapping[str, Any]:
        if (
            response.status != expected_status
            or not response.body
            or len(response.body) > 1_048_576
        ):
            raise GateCheckError("gate GitHub request failed")
        try:
            value = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateCheckError("gate GitHub response is invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise GateCheckError("gate GitHub response is not an object")
        return value


class PilotCheckPublisher:
    """Own the published Check Runs for one local pilot assignment.

    Every exit from the pilot lifecycle goes through this object, so a Check Run
    it opened is always closed: with the phase verdicts derived from the job log
    when the run reached a terminal state, and with an explicit `stale`
    conclusion naming the reason when the local host stopped owning the run.
    """

    def __init__(
        self,
        client: GateCheckClient,
        job_log: Callable[[int], Iterable[bytes]],
    ) -> None:
        self.client = client
        self.job_log = job_log

    def start(self, *, head_sha: str, details_url: str) -> dict[str, int]:
        """Open one `in_progress` Check Run per published phase, on the PR head."""
        token = self.client.authenticate()
        opened: dict[str, int] = {}
        for phase, name in sorted(PHASE_CHECK_NAMES.items()):
            opened[name] = self.client.create_in_progress(
                name=name,
                head_sha=head_sha,
                details_url=details_url,
                summary=(
                    f"The `{phase}` phase of the reviewed Overworld CI profile is "
                    "running on the self-hosted Windows runner, against the exact "
                    f"merge of this pull request head ({head_sha[:8]})."
                ),
                token=token,
            )
        return opened

    def conclude(
        self,
        *,
        checks: Mapping[str, int],
        job_id: int,
        job_conclusion: str,
        details_url: str,
    ) -> dict[str, str]:
        """Close the opened Check Runs with the verdicts the job log supports."""
        try:
            observed = parse_phase_evidence(self.job_log(job_id))
            verdicts = phase_verdicts(
                job_conclusion=job_conclusion,
                observed=observed,
                details_url=details_url,
            )
        except (GateCheckError, OSError) as exc:
            # Evidence that cannot be read is never silently upgraded to a pass.
            verdicts = abandoned_verdicts(
                reason=f"the job log could not be read ({type(exc).__name__})",
                details_url=details_url,
            )
        return self._apply(checks, verdicts, details_url)

    def abandon(
        self, *, checks: Mapping[str, int], reason: str, details_url: str
    ) -> dict[str, str]:
        """Close the opened Check Runs as `stale`, naming what went wrong."""
        return self._apply(
            checks, abandoned_verdicts(reason=reason, details_url=details_url), details_url
        )

    def _apply(
        self,
        checks: Mapping[str, int],
        verdicts: Mapping[str, PhaseVerdict],
        details_url: str,
    ) -> dict[str, str]:
        token = self.client.authenticate()
        applied: dict[str, str] = {}
        for phase, name in sorted(PHASE_CHECK_NAMES.items()):
            check_run_id = checks.get(name)
            verdict = verdicts.get(phase)
            if check_run_id is None or verdict is None:
                continue
            self.client.conclude(
                check_run_id=check_run_id,
                verdict=verdict,
                details_url=details_url,
                token=token,
            )
            applied[name] = verdict.conclusion
        return applied


def _exact_sha(value: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise GateCheckError("Check Run head SHA must be a full commit SHA")
    return value


def _exact_name(value: str) -> str:
    if value not in set(PHASE_CHECK_NAMES.values()):
        raise GateCheckError("Check Run name is not one of the published phase names")
    return value


def _stamp(now: datetime) -> str:
    if now.tzinfo is None:
        raise GateCheckError("gate clock must be timezone-aware")
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _headers(bearer: str) -> Mapping[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {bearer}",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "self-hosted-ci-gate/1",
    }


def _app_jwt(app_id: int, signer: RS256Signer, now: datetime) -> str:
    def b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    header = b64(b'{"alg":"RS256","typ":"JWT"}')
    payload = b64(
        json.dumps(
            {"exp": int(now.timestamp()) + 540, "iat": int(now.timestamp()) - 60,
             "iss": str(app_id)},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    return f"{header}.{payload}.{b64(signer.sign(signing_input))}"


__all__ = [
    "GateAppAuthorityV1",
    "GateCheckClient",
    "GateCheckError",
    "GateToken",
    "PilotCheckPublisher",
    "PHASE_CHECK_NAMES",
    "PROFILE_PHASES",
    "PhaseVerdict",
    "abandoned_verdicts",
    "parse_phase_evidence",
    "phase_verdicts",
]
