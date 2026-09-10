# Publishing the local result on the pull request

## Why a dedicated App is required

The pilot workflow is dispatched on the default branch. The Check Run GitHub
Actions creates for that run therefore lands on the default branch head and can
never appear on a pull request. Personal access tokens cannot create Check Runs
at all. A dedicated GitHub App holding `checks:write` and `metadata:read` on the
exact selected repository is the only way to put the local result where the
author reads it.

That App is a separate identity from the dispatcher. The installer refuses a
`gate` block that reuses the dispatcher's App ID, installation ID, or any other
managed secret, so the dispatch authority never gains the ability to write the
result it dispatched.

## Where the per-phase verdict comes from

The reviewed repository command profile runs a fixed, ordered phase list under
`set -e`, and prints one measurement line per phase that finished. The cleanup
trap prints the same line when a phase fails, so a phase's own line proves
nothing on its own. What disambiguates it is the order:

> evidence for phase N+1 exists only if phase N passed.

The published verdicts follow from that, plus the job's terminal conclusion:

| Situation | `backend lint + test` | `frontend lint + test` |
| --- | --- | --- |
| Job succeeded | success | success |
| Only `backend` evidence, job failed | failure | skipped |
| `backend` + `frontend` evidence, job failed | success | failure |
| All three phases' evidence, job failed | success | success |
| No evidence, job cancelled or timed out | cancelled / timed_out | skipped |
| Job log unreadable | stale | stale |

The inference is bound to the reviewed ordered phase list. If the profile ever
reorders or renames its phases, publication refuses rather than guessing.

## Never hung

Every exit from the pilot lifecycle closes the Check Runs it opened, including
the failure paths and the terminal reconcile path. A run whose local owner
disappears mid-flight concludes `stale` with a summary naming what happened and
stating that nothing was proven, so the author is told to dispatch again rather
than waiting on a Check Run that will never finish.

Publication is best effort in the other direction too: a gate App that cannot be
reached never fails a local run that is otherwise valid.

## Configuration

Add an optional `gate` block to `/etc/self-hosted-ci/outbound-worker.json` and
install its key through the managed installer:

```json
"gate": {
  "app_id": 0,
  "app_slug": "your-gate-app",
  "installation_id": 0,
  "private_key_file": "/etc/self-hosted-ci/secrets/gate-github-app.pem"
}
```

```bash
install-outbound-worker-runtime.py --apply \
  --config-source <config> \
  --github-app-private-key-source <dispatcher key> \
  --allocation-signer-key-source <allocation key> \
  --gate-app-private-key-source <gate key> \
  --acknowledge-install-root-only-worker-secrets \
  --acknowledge-local-smoke-has-no-github-proof
```

Omitting the block leaves publication off, which is the fail-closed default.
