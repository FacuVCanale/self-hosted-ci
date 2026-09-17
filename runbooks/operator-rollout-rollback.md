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

## Repository profile rotation

Rotate a repository profile in this order: verify or build the candidate image
with the runtime active, deactivate through the canonical workflow, apply the
contract compare-and-swap, activate, and run the smoke. Build the image before
deactivation because the builder needs the build-egress proxy that canonical
deactivation stops.

With the runtime active, wait until both the GARM scale-set inventory and the
JIT instance inventory are empty. Wait 15 seconds, confirm both inventories are
still empty, and start the build in that same command. Keeping the second check
and build together prevents a pilot run from occupying the runtime between the
inventory gate and the builder start.

Close standard input at both ends of a remote builder invocation:

```bash
ssh -n selfhosted-ci-svc@HOST \
  'sudo /usr/local/lib/self-hosted-ci/build-repository-profile-image.sh --apply … < /dev/null' \
  < /dev/null
```

`HOST` and `…` are placeholders for the reviewed target and the complete,
profile-specific arguments; the `ssh -n` and both stdin redirects are literal.

When stdin is not a TTY, `incus init` may read instance YAML until EOF. An open
SSH pipe can therefore leave the builder waiting indefinitely.

When staging from macOS, create the tarball without AppleDouble metadata:

```bash
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata …
```

Without these settings, bsdtar may add `._*` entries and the remote tree no
longer matches the reviewed source manifest.

For the Overworld profile, `configure-garm-jit.sh` reads secrets from these
root-only files:

- `/root/self-hosted-ci-secrets/jwt`
- `/root/self-hosted-ci-secrets/db-passphrase`
- `/root/self-hosted-ci-secrets/admin-username`
- `/root/self-hosted-ci-secrets/admin-password`
- `/root/self-hosted-ci-secrets/allocation-public-key.pem`

It reads the repository-bound App configurations from:

- `/etc/self-hosted-ci/overworld-runner-manager-app.json`
- `/etc/self-hosted-ci/overworld-dispatcher-app.json`
- `/etc/self-hosted-ci/overworld-live-job-verifier-app.json`

Do not use the unprefixed App configurations for Overworld: they belong to a
different repository authority. Record only paths and verify bindings, modes,
and owners; never print secret contents.

Before building, resolve the candidate alias to its published fingerprint and
read the image marker with the canonical verifier. If the alias, fingerprint,
marker, and `profile_digest` all match the expected profile, skip the build and
continue directly to deactivation and compare-and-swap. The alias alone is not
sufficient proof of reusable image identity.

After activation returns to eligible health, apply
`self-hosted-ci use-local OWNER/REPO --apply` before the smoke. That command
installs the managed workflow by pushing a commit to the repository's default
branch, which makes open pull requests' merge refs stale until their branches
change. Use this exact order:

1. Apply `use-local`.
2. Merge the current default branch into the smoke PR branch and push without
   force.
3. Wait for GitHub to report `mergeable=MERGEABLE`, and verify that the merge
   ref parents are exactly the default-branch head and the PR head.
4. Run the `run-local` plan and apply for that PR.

If the smoke reaches the runner and fails because of the PR's own content, the
infrastructure rotation remains valid and does not trigger rollback. Roll back
when image, runtime, dispatch identity, or cleanup evidence fails; do not treat
a workload failure as an infrastructure failure.
