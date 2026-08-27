# Thermonuclear hosted PR reviewer

Thermonuclear is an optional informational reviewer. It is separate from
`ci-gate`: it never runs repository code, never writes Checks or commit
statuses, and never approves or blocks a merge.

## Trust boundary

- The consumer starts the reusable workflow with `pull_request_target` and pins
  it to an immutable release SHA.
- The workflow does not use `actions/checkout`. It downloads only the four
  reviewer files co-located with the reusable workflow, from
  `job.workflow_repository` at the exact `job.workflow_sha` selected by the
  caller. Pull-request refs and artifacts are never downloaded.
- GitHub's API is the only source of PR metadata and patches. The canonical
  base and head SHAs are checked before the model call and at the immediate
  boundary of every comment create, update, or duplicate cleanup mutation.
- Every finding must name an exact canonical API file path and a new-side line
  present in one of its returned patch hunks. Ungrounded model output fails
  closed. Model-authored HTML, Markdown delimiters, links, backticks, and
  mentions are neutralized before the informational comment is rendered.
- PR title, body, paths, and patches are untrusted model input. The OpenAI
  Responses request sets `store: false`, `tools: []`, `tool_choice: none`, a
  strict JSON Schema, a 4,000-token output ceiling, and a 60-second timeout.
- Oversized or incomplete diffs skip the provider and update the informational
  comment with an omission reason.

The clean-room policy is
[`actions/thermonuclear-review/policy-v1.md`](../actions/thermonuclear-review/policy-v1.md).
Its local digest and the exact upstream page that inspired the category of
review are recorded in `provenance-v1.json`; no upstream skill text is bundled.

## Dedicated GitHub App

Create a separate App with webhooks disabled and install it only on selected
repositories. Grant only:

- Metadata: read (implicit);
- Pull requests: read and write.

Do not grant Contents, Checks, Actions, Workflows, Commit statuses,
Administration, Deployments, or repository hooks. Store its PKCS#8 private key
as `THERMONUCLEAR_APP_PRIVATE_KEY`. Configure both
`THERMONUCLEAR_APP_ID` and `THERMONUCLEAR_EXPECTED_APP_ID` to the same exact App
id; the reviewer authenticates the App and accepts existing/new comments only
when GitHub reports that exact `performed_via_github_app.id`.
The installation token request is narrowed again to the exact repository and
`pull_requests: write`; the returned repository selection, permissions,
repository list, and canonical UTC expiration are validated before the token is
used. A token must retain more than a 60-second safety margin, cannot advertise
a TTL beyond one hour, and is rejected at or after its persisted usable
deadline before every mutation.

GitHub Actions serializes runs by repository and pull request with
`cancel-in-progress: false`. This is an operational queue, not a durable CAS or
database lock. The API adapter still reconciles ambiguous writes and historical
duplicates to one lowest-id App-owned comment, then verifies observed persisted
state. If a runner is cancelled between an HTTP commit and that verification,
the next PR event or the example workflow's explicit manual reconciliation run
converges the comment again using current canonical base and head SHAs.

## OpenAI provider and budgets

The exact model is `gpt-5.6-terra`. The implementation uses the Responses API
and strict Structured Outputs. OpenAI's current model page documents Responses
and Structured Outputs support and lists $2.00 per million input tokens and
$12.00 per million output tokens:
<https://developers.openai.com/api/docs/models/gpt-5.6-terra>.

Use a project-scoped key in `THERMONUCLEAR_OPENAI_API_KEY` and configure the
project's monthly budget externally. The request is bounded to 60,000 input
UTF-8 bytes (a conservative token guard), 4,000 output tokens, 400,000 diff
bytes, 100 files, and 20,000 changed lines. At current published uncached token
prices, the configured token ceilings imply a maximum nominal request cost of
$0.168; retries can double provider spend.

## Activation

The product is disabled by default. Add the consumer workflow from
`examples/workflows/thermonuclear-review.yml`, replace its release placeholder
with an immutable commit SHA, configure the App variables/secrets, and set the
repository variable `THERMONUCLEAR_REVIEWER_ENABLED=true`. Removing or changing
that variable disables the job without exposing either credential.

The versioned provider-decision record remains `BLOCKED` in this public
distribution because repository variables, App installation scope, secret
rotation, provider data controls, and the project budget are operator-owned
external facts. Activation is therefore opt-in per selected repository rather
than a global repository default.
