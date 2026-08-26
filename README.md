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

## Desarrollo

```bash
make setup
make test
make validate
```

To generate local evidence (ignored by Git):

```bash
make evidence
```

See [`docs/github-automation-operations.md`](docs/github-automation-operations.md)
for the generic operating model. Never commit generated operational evidence.
