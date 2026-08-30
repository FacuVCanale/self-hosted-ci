---
name: self-hosted-ci
description: Operate Facu's selected-repository Windows self-hosted CI. Use when Facu asks to run CI on the Windows PC, use local CI for a PR, route a repository to local CI from now on, return it to GitHub-hosted CI, or asks about CI routing, health, or status.
argument-hint: "[status | run-local | use-local | use-github] [OWNER/REPO] [--pr N]"
allowed-tools: Bash(self-hosted-ci *) Bash(git remote get-url origin) Bash(gh repo view *)
metadata:
  short-description: Operate selected local Windows CI
---

# Selected-repository Windows CI

Use the installed `self-hosted-ci` CLI as the canonical fail-closed agent interface for routing and approvals. The skill translates the user's intent; it does not edit routing files, workflows, approvals, or host configuration directly.

## Intent mapping

- A one-off phrase such as “corré el CI en mi PC Windows”, “usá mi CI local para este PR”, or “corré este PR ahí” means `self-hosted-ci run-local [OWNER/REPO] --pr N --apply`.
- A persistent phrase such as “a partir de ahora corré este repo ahí”, “dejá este repo usando mi CI local”, or “hacé opt-in de este repo” means `self-hosted-ci use-local [OWNER/REPO] --apply`. In this release that installs the non-gating JIT pilot; it does not replace required CI checks.
- “Volvé este repo a GitHub”, “usá GitHub Actions de vuelta”, or “sacalo del self-hosted” means `self-hosted-ci use-github [OWNER/REPO] --apply`.
- Questions about routing or health mean `self-hosted-ci status [OWNER/REPO]` or `self-hosted-ci doctor [OWNER/REPO]`.

Resolve a missing repository from the current checkout. Resolve a missing PR only from an unambiguous current PR; otherwise ask for the PR number. Never translate a one-off run into persistent enrollment.

## Required behavior

1. Run the command without `--apply` first for `use-local`, `use-github`, or `run-local`; read its JSON plan.
2. When the user's message explicitly requests the mutation, immediately run the same exact command with `--apply`; the plan is evidence, not a permission handoff.
3. If `use-local` reports `selected_repository_authority_missing`, stop the mutation and explain that the exact repository still needs GitHub App selection plus host authority configuration. Do not claim success, select all repositories, or broaden authority to an organization.
4. Report the effective state from a final `self-hosted-ci status OWNER/REPO`, not merely the desired state or a successful file write.
5. Treat `run-local` approval as exact to repository, PR, and the head SHA resolved by the host. A new commit requires a new run request.
6. `pending_reconciled_during_this_status_call` is an event flag, not a health flag. `false` only means this particular read did not need to reconcile a pending transaction; it is not a warning when `pending_operation` is null.

## Boundaries

- GitHub-hosted is the default for absent, unhealthy, ambiguous, or unauthorized repositories.
- Never accept wildcards, an owner without a repository, or “all repositories”.
- Never expose, copy, print, or place GitHub App keys, signing keys, tokens, installation credentials, or private host evidence in a repository or chat.
- The CI lane and thermo-nuclear reviewer are separate. These commands do not enable or configure AI review.
- Do not use Cloudflare or Workers. This control plane is GitHub plus the dedicated Windows/WSL host only.
- In this release, `use-local` configures the verified non-gating JIT pilot. It does not replace a repository's required CI checks. Preserve that distinction in every report.

Explicit invocation is `$self-hosted-ci` in Codex and `/self-hosted-ci` in Claude Code.
