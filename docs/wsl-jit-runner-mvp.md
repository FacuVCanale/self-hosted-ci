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
  -AcknowledgeGrantBatchLogonRight `
  -AcknowledgeOneTimePasswordRotation
```

Apply protects the export, destination and task artifacts with explicit ACLs.
Because the elevated operator and target local account are different
identities, Task Scheduler requires a password-backed registration. Apply
therefore requires a separate rotation acknowledgement, generates a
cryptographically random password only in memory, rotates the service account,
and registers a one-time `Password` task at LUA (`Limited`) run level. The
plaintext exists only for the COM registration call; its source BSTR is zeroed,
and password material is never written, logged, returned, or accepted as input.

The account must have the local
`Log on as a batch job` right and its SID must not have a direct
`Deny log on as a batch job` assignment. Apply requires a separate acknowledgement,
then uses the Windows LSA API to add only `SeBatchLogonRight`. It enumerates
the SID's rights before and after and continues only if the resulting set is
exactly the original set plus that single right. It never invokes `secedit`,
never removes or overrides a deny, and never rewrites the broader user-rights
policy. A registration rejection is terminal and WSL is not started.

In `finally`, after success or failure, the script first rotates the account to
a second independently generated unknown password and only then deletes the
one-time task. If task deletion fails, the stored credential is already
invalid. Any failure to perform the final rotation or delete the task is
reported as a fail-closed cleanup error containing only booleans, timestamps,
and the account SID. The final password is not retained anywhere.
That worker either imports the distro once or verifies an existing import. It
checks the worker SID and the service identity's own HKCU WSL registration,
including the exact distribution name, `BasePath`, and WSL version 2. The
operator process rechecks the source distro and the export's hash and size,
then removes the one-time task while preserving its logs under
`C:\ProgramData\self-hosted-ci\migration`.

Any identity, path, ACL, hash, size, disk, task, registry, or preservation
mismatch stops the migration. Re-running Apply is idempotent only when the
existing service-account registration points to the exact pinned destination.

## Read-only health from macOS

The dedicated runtime distro is `Ubuntu-24.04-CI`. The only canonical runner
labels are `linux`, `self-hosted`, `wsl-jit`, and `x64` (sorted in signed
allocations). The personal `Ubuntu-24.04` distro is migration source material,
not a CI target.

From the Mac, the health wrapper streams the checked-in PowerShell probe over
SSH stdin to `powershell.exe -Command -`. Windows PowerShell 5.1 consumes stdin
one command at a time, so the wrapper Base64-encodes the UTF-8 probe locally,
appends it to an in-memory PowerShell variable in bounded 2048-character
chunks, then decodes and invokes it. It does not install the probe, place it on
the Windows command line, write it to disk, or change the Windows host:

```bash
scripts/host/check-self-hosted-ci-health.sh \
  --ssh-target desktop \
  --service-account-sid 'S-1-5-21-...'
```

The command emits one stable JSON document. It reports SSH reachability,
Windows service state, the dedicated distro, the runner installation and
registration state, required systemd units, the workload heartbeat, and
fail-closed local-CI eligibility. It never registers a runner, starts a
service, creates a scheduled task, or writes a heartbeat.

WSL registrations are scoped to a Windows user. Consequently, a probe reached
through the personal Windows account normally reports the dedicated distro as
`not_observable`, even when that distro exists under `selfhosted-ci-svc`. This
is an expected fail-closed result, not permission to infer health from the old
migration evidence. A future read-only probe endpoint running as the service
identity may expose the same command; until then, the Mac check proves only
that Windows and SSH answer.

The workload heartbeat is the mtime of
`/var/lib/self-hosted-ci/health/heartbeat`. Its producer belongs to the future
coordinator/runtime and is deliberately absent from this inert layer. Missing,
stale, or unobservable heartbeat state blocks `eligible_for_local_ci`.

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
