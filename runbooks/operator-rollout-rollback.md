# Operator rollout and rollback

All steps are per exact repository. Persist evidence after every step. Repeating
a completed prefix is a no-op; a skipped or reordered prefix is invalid.

Enable order:

1. Prove exact App, repository/installation, runner and attestation authority.
2. Install the trusted default-branch PR workflow without PR checkout.
3. Prove the GitHub-hosted canonical smoke and pinned-source `ci-gate` path.
4. Add only the exact repository to the allowlist or restricted runner group.
5. Prove the local exact-tested-SHA smoke, cleanup and source binding.
6. Prove offline/lost-runner GitHub fallback and immutable single winner.

Disable/stop order (S26):

1. Set routing to GitHub-hosted first.
2. Fence ownership and cancel exact queued/running local attempts.
3. Prove the GitHub-hosted canonical smoke, push-main `CI`, required checks,
   `verify-release.sh`, and Railway isolation.
4. Revoke exact runner/App/attestation authority and clean registrations.
5. Reconcile gates, children, checks, registrations, workspace and outbox.

Global stop disables local dispatch, fences all current exact scopes, revokes
only platform identities, removes registrations/workspaces and proves GitHub
CI. Never touch deploy state or secrets. Reviewer stop switches to no-ingress or
disabled, drains durable work, then revokes its isolated identity if required.

Credentialed GitHub changes, repository creation, rulesets, App installation,
Windows ACLs, WSL/network enforcement and runner-manager selection remain
external blockers until independently evidenced. Do not substitute a local
fixture, synthetic success, or operator assertion for that proof.
