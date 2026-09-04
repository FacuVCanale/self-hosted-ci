---
name: self-hosted-ci
description: Operate Facu's selected-repository Windows self-hosted CI. Use when Facu asks to run CI on the Windows PC, use local CI for a PR, route a repository to local CI from now on, return it to GitHub-hosted CI, or asks about CI routing, health, or status.
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
7. If the installed `self-hosted-ci` CLI or its skill source is missing, broken, or unavailable, stop local dispatch and report the installation failure. Keep or restore GitHub-hosted routing. Do not improvise an alternate runner.

## Boundaries

- GitHub-hosted is the default for absent, unhealthy, ambiguous, or unauthorized repositories.
- The only valid local execution path is the managed JIT path in the dedicated `Ubuntu-24.04-CI` distro under the dedicated service identity, with GARM, a fresh unprivileged Incus container, one job, and verified cleanup.
- Never register or launch a persistent/ad-hoc GitHub Actions runner in a personal WSL distro, home directory, shell, `tmux`, `screen`, `nohup`, LaunchAgent, or manually managed service. In particular, paths such as `~/actions-runner-*` are not an acceptable fallback or canary.
- Never route work by setting a repository variable to a generic `runs-on: self-hosted` label. A local job must use the allocation-specific JIT label produced by the canonical control plane.
- Never install CI dependencies interactively or mutate the personal/dedicated WSL host to make one repository pass. Browser, Playwright, system, language, and build dependencies belong in the versioned, pinned ephemeral runner image or its reviewed provisioning contract.
- A runner that is merely promised to be unregistered later is non-conforming. Cleanup must be automatic, lifecycle-bound, and verified after success, failure, cancellation, timeout, agent loss, and reboot.
- A successful job on a non-conforming runner is diagnostic evidence only. Do not describe it as proof that `self-hosted-ci` is operational, do not use it to satisfy a required check, and do not merge on that basis.
- Never accept wildcards, an owner without a repository, or “all repositories”.
- Never expose, copy, print, or place GitHub App keys, signing keys, tokens, installation credentials, or private host evidence in a repository or chat.
- This product owns CI routing only. These commands do not enable, configure, or run AI review.
- Do not use Cloudflare or Workers. This control plane is GitHub plus the dedicated Windows/WSL host only.
- In this release, `use-local` configures the verified non-gating JIT pilot. It does not replace a repository's required CI checks. Preserve that distinction in every report.

Explicit invocation is `$self-hosted-ci` in Codex and `/self-hosted-ci` in Claude Code.
