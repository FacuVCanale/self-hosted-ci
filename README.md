# self-hosted-ci

Fail-closed protocol and reference implementation for opt-in GitHub CI on ephemeral self-hosted runners,
with fail-closed fallback to GitHub-hosted execution and verifiable evidence per
commit, pull request, and execution generation.

The repository contains:

- coordination, execution, and reconciliation workflows;
- generic policy and repository-registry examples;
- transactional leases, admission, fencing, and Check Run publication;
- cryptographic execution attestations and authority controls;
- an independent, optional pull-request review lane;
- schemas, operational runbooks, and automated tests.

## Security boundary

This public repository contains no production inventory, installation IDs,
private-key material, host topology, or operational evidence. Operators must
keep those values in an external secret/configuration store and consume released
code by an immutable commit SHA.

The CI execution lane and the optional AI reviewer are separate products. CI may
execute untrusted repository code in an isolated ephemeral runner. The reviewer
consumes bounded pull-request data and must not share the CI App identity,
runner, or credentials.

The public Actions currently expose the validated protocol surface, but the
production GitHub/GateStore adapter is not implemented in this release. Control
commands therefore fail closed instead of pretending to coordinate a live
deployment.

Production activation remains fail-closed until an operator implements and
reviews that adapter and provisions their
own GitHub App, exact repository allowlist, runner group/JIT authority, signing
keys, and isolated host.

The control plane is deliberately limited to GitHub and the dedicated local
host. Cloudflare runtime code, deployment configuration, credentials, bindings,
dependencies, direct API calls, and deployment workflows are prohibited. The
repository CI enforces this boundary through `scripts/check-local-only.py`;
`make distribution-check` fails if any such capability is introduced.

## Desarrollo

```bash
make setup
make test
make validate
make distribution-check
```

To generate local evidence (ignored by Git):

```bash
make evidence
```

See [`docs/github-automation-operations.md`](docs/github-automation-operations.md)
for the generic operating model. Never commit generated operational evidence.

For the reproducible local sandbox bootstrap, prerequisites, rollback, and
return to GitHub-hosted execution, see
[`docs/runbook-bootstrap-local-ci.md`](docs/runbook-bootstrap-local-ci.md).

The inert WSL host contract, read-only Mac-to-Windows health command, and the
activation stop conditions are documented in
[`docs/wsl-jit-runner-mvp.md`](docs/wsl-jit-runner-mvp.md). The dedicated CI
distro is `Ubuntu-24.04-CI`; its canonical JIT labels are `linux`,
`self-hosted`, `wsl-jit`, and `x64`.
