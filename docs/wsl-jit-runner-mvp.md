# WSL JIT runner MVP

This repository contains an executable, fail-closed contract for a future
opt-in local runner pool. It does **not** register a runner, enable GARM, alter
WSL, or change any repository from GitHub-hosted execution.

## Security boundary

The supported boundary is a dedicated Ubuntu 24.04 WSL2 distro owned by a
dedicated non-admin Windows account. GARM is the management plane; each job
runs in a new unprivileged Incus container built from a pinned image. The
container receives one JIT registration, accepts exactly one job, and is
destroyed after success, failure, cancellation, timeout, force-cancellation,
or reboot reconciliation.

The personal Windows account/distro, Windows drives, WSL interop, Docker
Desktop, Incus API, host sockets, SSH agents, deploy keys, reviewer keys, and
control-plane credentials are outside the workload boundary.

## Preservative Windows-account migration

The checked-in migration helper imports the pinned export as
`Ubuntu-24.04-CI` under the dedicated local account `selfhosted-ci-svc`. It is
plan-only by default and must be started by the operator from an elevated,
interactive local PowerShell console. It never unregisters the personal
`Ubuntu-24.04` source distro and never deletes or rewrites its export.

First run the read-only plan. It hashes the complete export, reports its exact
byte length and the service account SID, checks that the account is local,
enabled and non-admin, confirms the source distro is still registered, and
checks conservative free-space headroom:

```powershell
Set-Location C:\path\to\self-hosted-ci
.\scripts\host\migrate-ci-wsl.ps1
```

Review the JSON, then bind Apply to the reported size and SID:

```powershell
.\scripts\host\migrate-ci-wsl.ps1 `
  -Apply `
  -ExpectedExportBytes <exact-export-bytes-from-plan> `
  -ExpectedServiceAccountSid '<exact-service-account-sid-from-plan>' `
  -AcknowledgeSourceAndExportWillBePreserved `
  -AcknowledgeImportRunsAsServiceIdentity `
  -AcknowledgeGrantBatchLogonRight
```

Apply protects the export, destination and task artifacts with explicit ACLs,
then uses the native Task Scheduler 2.0 API to run a one-time passwordless S4U
scheduled task as the non-admin account. The account must have the local
`Log on as a batch job` right and its SID must not have a direct
`Deny log on as a batch job` assignment. Apply requires a separate acknowledgement,
then uses the Windows LSA API to add only `SeBatchLogonRight`. It enumerates
the SID's rights before and after and continues only if the resulting set is
exactly the original set plus that single right. It never invokes `secedit`,
never removes or overrides a deny, and never rewrites the broader user-rights
policy. A registration rejection is terminal and WSL is not started.
That worker either imports the distro once or verifies an existing import. It
checks the worker SID and the service identity's own HKCU WSL registration,
including the exact distribution name, `BasePath`, and WSL version 2. The
operator process rechecks the source distro and the export's hash and size,
then removes the one-time task while preserving its logs under
`C:\ProgramData\self-hosted-ci\migration`.

Any identity, path, ACL, hash, size, disk, task, registry, or preservation
mismatch stops the migration. Re-running Apply is idempotent only when the
existing service-account registration points to the exact pinned destination.

## Allocation protocol

`github_automation.runner_jit` provides:

- a canonical allocation payload bound to repository ID, exact head SHA,
  default-branch workflow, pinned runner image, dedicated labels, and a
  five-minute maximum lifetime;
- Ed25519 signatures under a dedicated domain with a pinned SPKI fingerprint;
- a transactional SQLite replay ledger;
- persisted issuance/expiry timestamps revalidated atomically at claim and job
  start (`expires_at` is exclusive);
- strict `issued -> claimed -> running -> terminal -> cleaned` transitions;
- exactly one job and idempotent cleanup;
- two-phase reboot recovery from issued/claimed (`jobs_started=0`) and running
  (`jobs_started=1`) allocations: the ledger first records
  `recovery_required + cleanup_pending` with a stable idempotency key, and only
  records `cleaned` after the external cleanup effect returns complete
  evidence. An identical post-crash acknowledgement converges; different or
  incomplete evidence is rejected.

Broker and runner credentials never belong in the allocation or repository.

## Readiness and activation

`policies/runner-network-v2.yaml` is intentionally disabled. A deployed policy
must default-deny, block private/link-local/Tailnet ranges and management
services, fail closed on private/rebound DNS, and allow workload egress only to
the dedicated GitHub Actions egress proxy.

Run the read-only plan anywhere:

```bash
scripts/host/provision-wsl-jit-contract.sh --plan
```

Validate an evidence bundle without changing the host:

```bash
python3 scripts/host/verify-wsl-jit-readiness.py \
  --evidence /path/to/runner-boundary-v2.json \
  --measurement-root /path/to/host-evidence \
  --reviewer-public-key /path/to/reviewer-public-key.pem \
  --pinned-fingerprint <ed25519-spki-sha256>
```

The bundle cannot self-assert `verified` or `pass`. First capture the files
referenced by every component/check under a host-owned evidence directory,
then content-address them:

```bash
python3 scripts/host/collect-wsl-jit-measurements.py \
  --input /path/to/runner-boundary-template-v2.json \
  --output /path/to/runner-boundary-v2.json \
  --measurement-root /path/to/host-evidence
python3 scripts/host/verify-wsl-jit-readiness.py \
  --evidence /path/to/runner-boundary-v2.json \
  --measurement-root /path/to/host-evidence \
  --reviewer-public-key /path/to/reviewer-public-key.pem \
  --pinned-fingerprint <ed25519-spki-sha256>
```

The verifier independently rereads every referenced regular file and
recomputes its SHA-256, byte length, Unix owner/group, mode, aggregate
component pin, and the exact canonical network-policy bytes. Symlinks, path
escape, missing references, changed binary/version output, changed ACL-mode or
ownership, and policy drift all block activation. The collector never assigns
pass/verified status and does not activate or provision anything.
An independent reviewer signs the final canonical JCS payload with Ed25519;
the verifier pins the reviewer's SPKI fingerprint and performs that signature
check internally. Callers cannot replace cryptographic verification with a
boolean or an unsigned status file.

The verifier returns `0` only when every host-security v1 check, all six pinned
components, network policy v2, every terminal cleanup scenario, and explicit
activation intent are verified. `2` means invalid evidence; `3` means a valid
but blocked bundle.

The provisioning script is inert by default. `--apply` additionally requires
both acknowledgement flags, root inside the exact dedicated distro, installed
Incus/GARM binaries, a disabled GARM service, and a fully verified bundle. It
only installs templates and leaves GARM disabled. External registration and
activation are deliberately separate operations.

## Stop condition before live use

Do not enable the service or route a repository locally until all of these are
captured and independently reviewed:

1. dedicated non-admin Windows account and distro ownership/ACL evidence;
2. pinned GARM, Incus, and runner-image digests and compatibility evidence;
3. default-deny proxy-only policy loaded before registration and surviving
   Windows and WSL reboots;
4. destructive cleanup evidence for every terminal outcome, with zero orphan
   registrations and zero surviving containers/workspaces/tokens;
5. explicit per-repository opt-in with the GitHub-hosted workflow retained as
   fallback.
