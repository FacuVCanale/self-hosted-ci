# Gate Service

Minimal hosted-only Cloudflare control plane for CI gates. Each
`runner_pool_id` deterministically maps to one SQLite-backed Durable Object, but
this release never dispatches or accepts local execution.

## Security posture

- Mutations run only when `ACTIVATION_MODE` is exactly `active`. Missing,
  malformed, `inert`, or any future unknown value fails closed with `503`.
- `staging` and `production` are separate Wrangler environments and remain
  explicitly `inert`.
- Every caller authenticates with GitHub OIDC. There is no HMAC or runner-manager
  endpoint, identity, or mutation surface.
- The verifier requires the configured audience, repository name and immutable
  ID, caller workflow, reusable workflow, `workflow_call` event, and
  GitHub-hosted runner claims.
- `logical_key` is derived server-side as
  `repository_id:pr_number:head_sha:ci-gate`; callers cannot provide it.
- Generation, owner (`run_id:run_attempt`), and state are server-controlled.
  Exact tuple retries are idempotent; conflicting Check Run or owner data fail.
- A base or tested-merge movement creates a new generation atomically, marks
  every older live generation `superseded`, fails its pending hosted action, and
  releases its allocation. Terminal transitions and action ACKs independently
  require the latest generation, so late completion cannot revive old work.
- Acquire atomically creates `hosted_selected`, one `dispatch_hosted` control
  action, one GitHub-hosted allocation, and audit evidence.
- Only `hosted_success` or `hosted_failure` can become terminal, through a
  versioned compare-and-swap. Local states and local transitions do not exist in
  the contracts, schema, routes, or Durable Object methods.
- Control-action ACKs require the same OIDC coordinator authority. Manager-style
  headers grant nothing.
- The pre-existing Check Run is updated only by a dedicated checks-only GitHub
  App held by this Worker/DO boundary. The non-secret authority pins the App ID,
  selected installation ID, exact repository name and immutable ID, and the
  lowercase SHA-256 fingerprint of the App key's DER SubjectPublicKeyInfo.
- `GITHUB_APP_PRIVATE_KEY_PEM` is a Cloudflare secret. It is imported only in
  memory for RS256 App JWT signing and is fingerprint-checked before any GitHub
  request. Installation tokens are minted for exactly one repository with
  exactly `checks:write` and `metadata:read`, validated against App,
  installation, repository and token responses, and never persisted.

Local execution stays structurally disabled until an independently reviewed
exact-SHA verifier v1 and its authority boundary exist.

## Effectively-once Check delivery

Terminal evidence is persisted atomically in `check_outbox` as `pending`, and a
per-pool Durable Object alarm processes it. Entries progress only to
`delivered` or `blocked`; transient failures retain attempts, bounded error
detail and an exponential-backoff `next_attempt_at`. The stable marker is
`github-automation-evidence:<evidence_digest>`.

Delivery pre-reads the exact Check Run. Matching evidence converges without a
write; different terminal evidence blocks permanently. A blank Check Run gets a
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
configuration. Before activation, set the five exact authority values and add
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
