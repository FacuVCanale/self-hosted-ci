# Non-gating JIT pilot

The JIT pilot proves the transient runner lifecycle before it is allowed to participate in the required `ci-gate`. It is a separate manually dispatched workflow and must not be configured as a required branch-protection check.

## What it proves

The pilot package binds one selected repository, open pull request, exact default branch, base SHA, head SHA, deterministic merge SHA, workflow, backend, and—only for local execution—one allocation ID and allocation-unique runner label. It contains no GateStore generation, admission, Check Run, approval, or merge authority.

Before checkout, the validation job uses `pull_requests:read` and re-reads the exact repository, PR base/head, and fixed active pilot workflow. Hosted execution uses `ubuntu-24.04`. Local execution uses only the allocation label and the normal fail-closed JIT job-started hook.

Both paths fetch GitHub's canonical `refs/pull/<number>/merge`, require its SHA to equal `tested_merge_sha`, require exactly two parents in the order `base_sha`, `head_sha`, and check it out detached before executing the dependency-free infrastructure smoke `python3 -m compileall -q .`. The worker obtains that same merge-ref SHA when building the package; it does not confuse it with a locally synthesized commit that has different metadata. Any ref movement or parent mismatch blocks the workload.

The dependency-free public-distribution check is the initial infrastructure smoke profile only for the `self-hosted-ci` sandbox. Before piloting the full suite, Overworld, or another selected repository, define and review that repository's bounded command profile, pre-baked toolchain and network allowlist; do not assume a project command is portable or allow package installation during an untrusted job.

## Terminal cleanup

Backend selection happens before dispatch. There is no hosted fallback after dispatch: an ambiguous or failed local attempt is a failed pilot, not permission to launch a second job.

The outbound terminal monitor polls the exact run and exact job ID/name/label until completion. Supported terminal conclusions map to broker outcomes as follows:

- `success` → `success`
- `failure` → `failure`
- `cancelled` → `cancel`
- `timed_out` → `timeout`

Any other conclusion is cleaned as failure and then reported as a fail-closed monitor error. After `broker.finish`, the monitor requires an exact cleanup receipt proving the allocation is cleaned, its scale set is absent, and the JIT runtime inventory is empty. Exit status from `finish` alone is not cleanup evidence.

The pilot stays non-gating until repeated live runs demonstrate exact claim, execution, terminal observation, cleanup, and reboot recovery. Promotion into required CI is a separate operator decision.

## Immutable workflow installation

The source template intentionally contains an all-zero Action SHA and is inert.
After publishing a reviewed release commit, render consumer workflows outside
this repository and install only the pilot file in the selected repository:

```bash
python3 scripts/render-consumer-workflows.py \
  --repository FacuVCanale/self-hosted-ci \
  --sha <reviewed-40-character-release-commit> \
  --output /tmp/self-hosted-ci-consumer-workflows
```

Never install the source template directly and never replace the placeholder
with a branch or tag. The active consumer workflow must pin the validation
Action to the exact reviewed release commit.
