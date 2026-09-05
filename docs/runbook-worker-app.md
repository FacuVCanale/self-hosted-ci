# Outbound worker GitHub App

The outbound worker uses a dedicated GitHub App installed only on repositories explicitly selected by the operator. It is not a general organization credential and grants no AI-review authority.

## Exact authority

The App must have exactly these repository permissions:

- Metadata: read
- Contents: read
- Pull requests: read
- Actions: write
- Administration: read

Install it with **Only select repositories** and choose each CI repository explicitly. The runtime rejects `repository_selection: all`, extra permissions, a different App or installation, a token covering more than one repository, repository identity drift, and workflow drift.

The fixed API root is `https://api.github.com`; every request carries API version `2026-03-10`. The client only exposes App inspection, repository installation inspection, installation-token creation, exact repository and pull-request reads, the potential merge commit required to pin the tested merge identity, fixed workflow inspection and dispatch, and exact workflow run/job reads. `Contents: read` is required by GitHub's GraphQL authorization for `potentialMergeCommit`; it does not grant source writes.

## Local files

Copy `templates/garm/worker-app-authority.json.example` outside the repository, replace placeholders with one selected repository, and keep the resulting configuration root-owned. Store the downloaded private key at the configured absolute path:

```text
owner: root
mode: 0600
path: /etc/self-hosted-ci/secrets/worker-github-app.pem
```

The private key is read directly into memory. It is never accepted through command-line arguments or environment variables and must never be printed or copied into evidence bundles. Installation tokens are memory-only and are restricted at mint time with the exact single `repository_id` and exact permission map.

Use one configuration record per explicitly selected repository. Adding a repository is an operator authorization change: install the App on that repository and add its exact numeric repository and installation identities. Removing a repository requires removing the App installation selection and its local record before considering the worker fenced.

## Pre-activation checks

Before dispatch is enabled, the client must successfully prove, in order:

1. `/app` matches the configured App ID and slug.
2. The repository installation matches the configured App ID, installation ID, `selected` selection, and exact permissions.
3. The minted token contains exactly the selected repository and exact permissions.
4. The repository ID, full name, and default branch match.
5. The fixed workflow path is active.

Any mismatch blocks dispatch. The worker must not fall back by widening repository scope or permissions.
