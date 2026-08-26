# Gate Service

Minimal hosted-only Cloudflare control plane for CI gates. Every request for the
configured repository routes to one repository-scoped SQLite-backed Durable
Object; `RUNNER_POOL_ID` is an exact allowlisted route value, not a caller-chosen
namespace. This release never dispatches or accepts local execution.

## Security posture

- Mutations run only when `ACTIVATION_MODE` is exactly `active`. Missing,
  malformed, `inert`, or any future unknown value fails closed with `503`.
- `staging` and `production` are separate Wrangler environments and remain
  explicitly `inert`.
- Every caller authenticates with GitHub OIDC. There is no HMAC or runner-manager
  endpoint, identity, or mutation surface.
- The verifier requires the configured audience, repository name and immutable
  ID, caller workflow, reusable workflow, `workflow_call` event, and
  event name, and GitHub-hosted runner claims. `OIDC_EVENT_NAME` is explicit;
  the pilot uses `pull_request_target` rather than assuming the reusable
  workflow changes the caller event claim.
- `logical_key` is derived server-side as
  `repository_id:pr_number:head_sha:ci-gate`; callers cannot provide it.
- Generation, owner (`run_id:run_attempt`), and state are server-controlled.
  Exact tuple retries are idempotent; conflicting Check Run or owner data fail.
- A head, base or tested-merge movement creates its replacement generation atomically, concludes
  the older live generation as `hosted_failure`, persists its immutable terminal
  Check outbox, fails its pending hosted action, and releases its allocation.
  Terminal transitions and action ACKs independently
  require the latest generation, so late completion cannot revive old work.
- Acquire atomically creates `hosted_selected`, one `dispatch_hosted` control
  action, one GitHub-hosted allocation, and audit evidence.
- Only `hosted_success` or `hosted_failure` can become terminal, through a
  versioned compare-and-swap. Local states and local transitions do not exist in
  the contracts, schema, routes, or Durable Object methods.
- Control-action ACKs require the same OIDC coordinator authority. Manager-style
  headers grant nothing.
- Check preparation and terminal delivery are performed only by a dedicated checks-only GitHub
  App held by this Worker/DO boundary. The non-secret authority pins the App ID,
  selected installation ID, exact repository name and immutable ID, and the
  lowercase SHA-256 fingerprint of the App key's DER SubjectPublicKeyInfo.
- `GITHUB_APP_PRIVATE_KEY_PEM` is a Cloudflare secret. It is imported only in
  memory for RS256 App JWT signing and is fingerprint-checked before any GitHub
  request. Installation tokens are minted for exactly one repository with
  exactly `checks:write` and `metadata:read`, validated against App,
  installation, repository and token responses, and never persisted.

## Durable Check preparation and gate acquisition

The single `POST /v1/pools/:runner_pool_id/gates` operation accepts only the exact OIDC
coordinator plus repository, PR, expected head and expected base. The caller
cannot supply `tested_merge_sha`: the Worker re-reads the current pull request,
takes GitHub's current `merge_commit_sha`, and accepts it only when the public
commit object has exactly the ordered parents `[base_sha, head_sha]`. Acquire
returns that server-canonical SHA for exact checkout and terminal evidence. The
Durable Object derives a preparation
marker from that tuple plus the exact workflow run/attempt owner. Retries by the
same owner adopt the same durably bound Check. A legitimate rerun gets a new
marker, Check and gate generation only after the active owner terminates or its
durable deadline expires; an active owner is never preempted by a new caller.
Callers cannot choose the marker or provide a Check ID. The GitHub App
installation token never crosses the Worker boundary.

Before any Check POST, SQLite persists an exact `check_creation_intent` with
marker, tuple, owner, state, deadline and `post_attempted`. The flag commits
before the network call. Once set, every retry and alarm is list-only: a crash
or ambiguous response can never cause a second POST. The gate, allocation and
control action are created only after the exact Check is observed and bound to
that durable intent. Terminal reruns resolve the durable gate first; terminal
evidence found only by a GitHub listing is never adopted heuristically.

Before a new POST, the Worker re-reads the current public pull request
from GitHub and requires exact repository, PR, head and base plus the already
canonicalized synthetic merge identity and its ordered parents. This public
sandbox read deliberately does not broaden the checks-only
App; private repositories require a future separate read identity. The Worker
then lists `ci-gate` Check Runs on the exact
`tested_merge_sha` and reconciles the marker. It repeats that lookup after an
ambiguous create. During list-only reconciliation it first binds the exact
durable marker on the tested SHA, even if the PR has since moved, and then
concludes that obsolete Check as failure so it cannot remain orphaned. An exact
obsolete intent can materialize and conclude only its own historical gate; it
does so atomically as terminal failure with a released allocation and pending
outbox, never as `hosted_selected` and never with a dispatch action. It never
supersedes or mutates the active gate for the current tuple. An exact
same-App, in-progress match is idempotent; duplicate markers, another App,
another SHA, or malformed GitHub response fail closed. Every reported page is
scanned before deciding uniqueness.

The repository-scoped Durable Object serializes all concurrent acquisition for
the same pull request and rejects alternate pool aliases. In-flight retries
coalesce only when both owner and preparation marker are exact; a different
tuple waits and re-evaluates durable state. A marker records the single
generation that consumed it, preventing late-owner ABA reacquisition. It reconciles ambiguous
creation intents after eviction using its durable alarm. Once `post_attempted`
is committed every wake-up remains list-only, including after the observable
reconciliation alert threshold; the overdue error, one-time audit incident and
capped exponential-backoff wake time stay persisted until the possible POST is
accounted for. A hosted gate also persists a
35-minute deadline. Its alarm converts an
abandoned `hosted_selected` generation to `hosted_failure`, releases the
allocation, fails its pending action and emits the same durable Check outbox
used by ordinary terminal transitions.

Local execution stays structurally disabled until an independently reviewed
exact-SHA verifier v1 and its authority boundary exist.

## Effectively-once Check delivery

Terminal evidence is persisted atomically in `check_outbox` as `pending`, and a
repository-scoped Durable Object alarm processes it. Entries progress only to
`delivered` or `blocked`; transient failures retain attempts, bounded error
detail and an exponential-backoff `next_attempt_at`. The stable marker is
`github-automation-evidence:<evidence_digest>`.

Once terminal evidence is committed, a newer generation can never cancel or
block its outbox. Every generation's exact Check continues to terminal delivery
across reruns, tuple movement and Durable Object eviction.

Delivery pre-reads the exact Check Run. Matching evidence converges without a
write; different terminal evidence blocks permanently. The exact persisted
preparation marker gets a
minimal PATCH containing only `external_id` and `conclusion`. Transport failure
or an inexact response is ambiguous, so delivery reads the same Check Run back:
matching marker, SHA and conclusion reconcile; blank state retries; conflicting
evidence blocks. A crash after GitHub accepted the PATCH therefore converges on
the next alarm without a second logical mutation.

Cloudflare alarms are at-least-once, so repeated HTTP PATCH attempts remain
possible. The guarantee is effectively-once logical evidence, not exactly-once
network transmission.

There are no D1, KV, R2, Queue, external deployment, or manager-secret bindings.
OIDC and GitHub App authority values in `wrangler.jsonc` are non-secret
configuration. Before activation, set every exact OIDC and GitHub App authority value and add
the key interactively with `wrangler secret put GITHUB_APP_PRIVATE_KEY_PEM` for
the target environment. Never commit the PEM or place it in `vars`.

The default, staging and production configurations remain explicitly `inert`.
Inert HTTP mutations fail before authentication or DO invocation, and an inert
DO alarm performs no GitHub request; it only schedules a later inert recheck.

## Verification

```sh
npm ci
npm run check
```

The product compatibility date is `2026-08-26`. Vitest overrides only its local
Miniflare runtime to `2026-08-22`, the newest date supported by the currently
published bundled `workerd`; deployment artifacts retain `2026-08-26`.
