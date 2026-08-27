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

## Local health supervisor and read-only macOS watchdog

The dedicated runtime distro is `Ubuntu-24.04-CI`. The only canonical runner
labels are `linux`, `self-hosted`, `wsl-jit`, and `x64` (sorted in signed
allocations). The personal `Ubuntu-24.04` distro is migration source material,
not a CI target.

The Windows supervisor is a persistent Scheduled Task running as
`selfhosted-ci-svc`, with `TASK_LOGON_PASSWORD`, LUA/Limited run level, a boot
trigger, bounded restart policy, and no administrative identity. Its installer
is plan-only unless all password-task, account-rotation, and protected-ACL
acknowledgements are supplied. It generates the account password
cryptographically in memory, exposes plaintext only to the Task Scheduler COM
registration call, zeroes the BSTR, and never logs or returns password
material. Unlike the one-time migration task, this password remains current so
the persistent task can restart; only Task Scheduler retains its protected
credential. Uninstall deletes the task first and then rotates the account to a
new unknown random password, invalidating that stored credential before it
removes the exact health/control artifacts.

Inside WSL, `self-hosted-ci-health-heartbeat.timer` invokes a sandboxed oneshot
every 30 seconds. The writer fsyncs a mode-0600 temporary file and atomically
replaces `/var/lib/self-hosted-ci/health/heartbeat.json`. The Windows supervisor
invokes the installed read-only collector as the service identity, binds the
result to that exact Windows SID and distro, and atomically replaces
`C:\ProgramData\self-hosted-ci\health\current.json`. Probe failures still
publish a short-lived, explicitly ineligible snapshot; they never preserve a
previous healthy decision.

The Windows health directory has protected ACL inheritance: SYSTEM,
Administrators, and the service SID have full control; one explicit watchdog
identity has read/execute only. The control directory excludes that reader.
The Mac wrapper does not execute a remote shell command. It downloads exactly
the fixed snapshot path with one batch-mode SFTP `get`, then performs strict
local schema, SID, distro, timestamp, label, heartbeat, and eligibility
validation:

The health prerequisites are deliberately separate from the persistent Windows
supervisor. Run their plan first from an elevated local console. The plan does
not create an account, mutate WSL, rotate a password, or register a task:

```powershell
.\scripts\host\install-health-prerequisites.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -AuthorizedKey 'ssh-ed25519 AAAA... mac-health-watchdog'
```

Apply creates or verifies only the pinned local `selfhosted-ci-health` reader,
stores one exact public key, and leaves the account disabled. It rotates the
service account to an in-memory random password, registers one LUA/Limited
`TASK_LOGON_PASSWORD` task, and streams a base64 payload to WSL stdin. The WSL
payload has exact SHA-256 pins and installs only the collector, heartbeat
writer, systemd service, and timer. It never uses `/mnt`, Windows interop,
personal files, GitHub, a runner, Incus, GARM, or boundary components. Apply
requires two distinct heartbeats, deletes the one-shot task, and then rotates
the service account again to invalidate Task Scheduler's stored credential:

```powershell
.\scripts\host\install-health-prerequisites.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -AuthorizedKey 'ssh-ed25519 AAAA... mac-health-watchdog' `
  -Apply `
  -AcknowledgeCreateDisabledReader `
  -AcknowledgeOneTimePasswordRotation
```

Only after that succeeds, install the persistent supervisor. It first applies
the SFTP-only sshd fence and only then enables the reader. This ordering is
mandatory: installing prerequisites after the persistent password task would
rotate and invalidate that task's credential, so the prerequisite installer
refuses when `SelfHostedCI-Health-Supervisor` exists. A missing collector,
stale heartbeat, inactive timer, or probe error rolls back the Windows task and
invalidates its credential:

```powershell
.\scripts\host\install-health-supervisor.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -ReaderAccount 'DESKTOP-NAME\selfhosted-ci-health'
```

The explicit Apply form requires all three acknowledgements:

```powershell
.\scripts\host\install-health-supervisor.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -ReaderAccount 'DESKTOP-NAME\selfhosted-ci-health' `
  -Apply `
  -AcknowledgePersistentPasswordTask `
  -AcknowledgeServiceAccountPasswordRotation `
  -AcknowledgeProtectedHealthAcls
```

Removal is independently plan-only. Apply deletes the exact task, rotates the
service account to invalidate its stored credential, and then removes only the
health/control artifacts. It also disables the reader before returning:

```powershell
.\scripts\host\uninstall-health-supervisor.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -Apply `
  -AcknowledgeTaskRemoval `
  -AcknowledgeFinalPasswordRotation `
  -AcknowledgeHealthArtifactRemoval
```

The final prerequisite uninstall must run after the persistent supervisor
uninstall. It refuses an enabled reader, a remaining persistent task, or any
unexpected reader-profile artifact; then it removes exactly the four WSL health
files through another one-shot service-identity task, invalidates that task's
credential, and deletes the disabled reader:

```powershell
.\scripts\host\uninstall-health-prerequisites.ps1 `
  -ExpectedServiceAccountSid 'S-1-5-21-...' `
  -Apply `
  -AcknowledgeRemoveDisabledReader `
  -AcknowledgeRemoveWslHealthPackage `
  -AcknowledgeOneTimePasswordRotation
```

```bash
scripts/host/check-self-hosted-ci-health.sh \
  --ssh-target desktop \
  --service-account-sid 'S-1-5-21-...'
```

Exit codes are stable: `0` healthy and locally eligible; `1` transport/tool
failure; `2` invalid invocation; `3` valid fresh snapshot but local CI is
ineligible; `4` expired snapshot; `5` malformed, crossed-identity, future-dated,
or internally inconsistent snapshot. SFTP, the validator, supervisor, and
heartbeat never register a runner or contact GitHub. The Windows installer is
the only mutating entry point and is not invoked by the checker.

Checked-in source remains inert. Installing the heartbeat package and Windows
task requires separate explicit Apply operations; no task, service, runner, or
repository is activated merely by cloning this repository.

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
