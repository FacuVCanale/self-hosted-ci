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

Local execution stays structurally disabled until an independently reviewed
exact-SHA verifier v1 and its authority boundary exist.

## Deliberate outbox limitation

Terminal evidence is persisted atomically in `check_outbox`, but every entry is
marked `not_deliverable`. This slice has no GitHub Check writer, delivery claim,
retry, or read-back implementation and therefore makes no exactly-once delivery
claim. A later delivery slice must introduce and test that boundary before
activation.

There are no D1, KV, R2, Queue, external deployment, or manager-secret bindings.
OIDC trust values in `wrangler.jsonc` are non-secret configuration; credentials
must never be committed.

## Verification

```sh
npm ci
npm run check
```

The product compatibility date is `2026-08-26`. Vitest overrides only its local
Miniflare runtime to `2026-08-22`, the newest date supported by the currently
published bundled `workerd`; deployment artifacts retain `2026-08-26`.
