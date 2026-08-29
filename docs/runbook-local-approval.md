# Local PR approval runbook

The outbound worker never scans repositories or pull requests. An operator must
approve one current PR head explicitly; GitHub remains the default when there is
no live local approval.

## Authority prerequisites

Install `/etc/self-hosted-ci/outbound-worker.json` from the example with mode
`0600`, owner `root:root`. The GitHub App must be installed only on the selected
repository with exactly `metadata:read`, `pull_requests:read`, and
`actions:write`, plus `administration:read`. The administration permission is
read-only and is used solely to list the selected repository's Actions runners
so cleanup can prove that no transient JIT runner registration remains.

For `mode: ci-jit-pilot`, the following files are mandatory and must be
root-owned `0600` regular files:

- the GitHub App RSA private key;
- the allocation Ed25519 signer key.

The pilot is observational and non-gating. It uses live selected-repository App
authority and internally generated allocation identity/nonce; it does not
require the offline authority-v1 manifest.

## Install and prove local runtime readiness

Keep the completed config and both private-key source files in a root-only
directory. Each source must be a root-owned, single-link regular file with mode
`0600`. The installer is inert unless `--apply` and both acknowledgements are
present:

```bash
sudo /usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py \
  --apply \
  --config-source /root/self-hosted-ci/outbound-worker.json \
  --github-app-private-key-source /root/self-hosted-ci/github-app.pem \
  --allocation-signer-key-source /root/self-hosted-ci/allocation-ed25519.pem \
  --acknowledge-install-root-only-worker-secrets \
  --acknowledge-local-smoke-has-no-github-proof
```

The apply path validates the exact `ci-jit-pilot` schema, selected-repository
permissions, fixed broker, managed database paths, RSA GitHub App key, Ed25519
allocation key, root ownership and modes. It then performs an isolated import
of the installed Python package, including `github_adapter` and
`check_delivery`. The smoke makes no external call and cannot dispatch a
workflow. Only after it passes does the installer atomically create the
root-owned `0600` sentinel
`/etc/self-hosted-ci/outbound-worker.runtime-ready`.

Any failed or interrupted apply leaves that sentinel absent. Re-running the
same successful command is idempotent. Verify the installed state without
mutation or external calls with:

```bash
sudo /usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py --verify
```

The systemd worker repeats this verification as an `ExecCondition` on every
start. Local readiness proves only files, keys, config and import closure; the
first explicit `approve` remains the live selected-repository GitHub authority
check.

For the separate `mode: ci-gate-full`, the authority-v1 manifest and signer are
also mandatory, and the authority helper must be root-owned mode `0700`. This repository does not
substitute or synthesize authority when the helper, manifest, or key is absent.
Install the approved authority-v1 helper at the exact configured path before
running `approve`; otherwise the command fails closed with the missing path.

## Commands

```bash
sudo /usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py approve --repository OWNER/REPO --pr 123
sudo /usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py status --repository OWNER/REPO --pr 123
sudo /usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py revoke --repository OWNER/REPO --pr 123
sudo /usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py run-once
```

`approve` accepts no SHA, nonce, pilot/protocol package, workflow path, runner label,
or allocation identifier. It authenticates the selected-repository GitHub App,
re-resolves the repository, open PR, current head, default branch, and fixed
workflow, then records the observed head generation in the local durable store.
Request and nonce are generated internally.

In `ci-jit-pilot` mode the worker builds the bounded non-gating package directly
from those live observations. In `ci-gate-full` mode, the separate authority-v1
helper must return a fully signed exact package that cross-validates against the
same observations; no helper is invoked by the pilot.

Approvals expire after at most five minutes. A moved head, changed GateStore
generation, revoked approval, expired approval, or failed GitHub authority check
prevents local dispatch. `serve` consumes only durable pending approvals and
uses outbound GitHub API calls; it exposes no listener and uses no relay.

On reboot, expired worker claims return to the pending queue. Completed,
revoked, failed, and expired approvals are never replayed.
