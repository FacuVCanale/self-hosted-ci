# Audited maintenance dispatcher

Status: proposed architecture; not implemented and not an activation authority.

This document defines the supported path for routine maintenance of the
dedicated `Ubuntu-24.04-CI` runtime without asking an administrator to paste a
new elevated PowerShell command for every WSL-side operation. It does not
bypass UAC. One reviewed elevated Windows installation establishes a narrow
transport boundary; subsequent requests are signed, allowlisted, durable,
auditable and executed by systemd inside the dedicated distro.

## Decision

Reuse the existing non-administrative Windows identity
`selfhosted-ci-svc`, because that identity owns the WSL registration for
`Ubuntu-24.04-CI`. Replace its general remote-shell access during cutover with
a Windows OpenSSH `ForceCommand` gateway. The gateway may only forward a
bounded frame on standard input to one fixed WSL ingress executable:

```text
Mac CLI
  |  SSH transport key + separately signed canonical request
  v
Windows OpenSSH: selfhosted-ci-svc, no PTY, no forwarding
  |  ForceCommand -> protected maintenance-gateway.ps1
  v
wsl.exe -d Ubuntu-24.04-CI -u selfhosted-ci-maint-ingress --exec /usr/local/libexec/self-hosted-ci/maintenance-ingress --cutover-id <pinned> --gateway-generation <pinned> --stdin
  |  unprivileged framing/spool; root controller re-verifies
  v
content-addressed inbox -> SQLite ledger
  v
self-hosted-ci-maintenance@<request-id>.service
  |  fixed operation adapter; no caller-controlled command line
  v
hash-chained, dispatcher-signed receipt
```

The existing `selfhosted-ci-health` account remains SFTP-only. It is not
extended into an administrative channel. No persistent LocalSystem service,
generic task runner, arbitrary shell, unreviewed caller-provided executable, or
caller-provided environment is introduced.

Windows OpenSSH only enforces `ForceCommand` for non-PTY sessions. Therefore
the product installation must also set `PermitTTY no`, validate the complete
`Match User` block with `sshd -t`, restart `sshd`, and prove both the positive
forced-command path and negative PTY/forwarding/shell probes before reporting
success. The relevant upstream behavior is documented in the
[Win32-OpenSSH sshd configuration reference](https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config)
and the
[Microsoft OpenSSH Server configuration reference](https://learn.microsoft.com/windows-server/administration/openssh/openssh-server-configuration).

This boundary constrains remote maintenance access; it is not a defense against
an attacker who already controls the Windows service-account token or Windows
administrator authority. Because WSL registrations are per Windows user, a
process already running as `selfhosted-ci-svc` can reach that user's distro.
The product therefore keeps that account non-interactive, password-rotated,
outside Administrators, without an unrestricted SSH key, and grants no
unrelated Windows workload to it.

## Security invariants

The implementation must preserve all of these properties:

1. The Windows transport identity is non-administrative and remains outside
   `Administrators`, directly and transitively.
2. The gateway, its configuration, `sshd_config`, authorized keys and all
   installed package files are protected from writes by the transport
   identity and ordinary users.
3. The online SSH key authenticates transport only. A distinct Ed25519
   maintenance key authorizes requests. Reviewer, allocation, GitHub App,
   host-receipt and maintenance keys are never reused.
4. WSL verifies the maintenance signature, key generation, time window,
   request digest, request ID, nonce, operation schema and referenced object
   digests before creating an execution unit.
5. A request contains no path, command, executable, argument vector,
   environment variable, unit name, shell text, URL or secret.
6. Every operation maps to one versioned adapter with fixed executable and
   fixed filesystem roots. Operation-specific values are schema fields, not
   command-line fragments.
   Caller-supplied code is executable only when it is part of a canonical
   artifact signed by the separate reviewer authority, passes the exact
   versioned preflight guard set and is bound to that preflight receipt.
7. Long-running work belongs to a systemd unit with a stable request ID. It
   survives SSH disconnects and agent loss. The gateway never owns the
   lifetime of the operation.
8. Same request ID plus same signed digest is idempotent. Same request ID plus
   a different digest is a permanent conflict. Expired, replayed against
   another host, or revoked-key requests fail closed.
9. Every mutating operation takes one product-wide maintenance transaction
   lock and revalidates compare-and-swap state while holding it, immediately
   before its first effect. Different request IDs cannot race activation,
   deactivation, installation, configuration or image publication.
10. External or irreversible boundaries use intent-before-effect and
   receipt-after-observation records. An ambiguous result is reconciled; it is
   never blindly repeated.
11. A successful receipt is issued only after operation-specific
    postconditions. Activation and deactivation additionally require empty
    GARM scale sets, an empty `ci-jit` inventory at their defined boundaries,
    and no unresolved cleanup.
12. No request can broaden repository authority, install a GitHub App, change
    Windows accounts or ACLs, alter OpenSSH, register a WSL distro, create a
    Scheduled Task, install a Windows component, or modify a Windows service.
13. Quarantine never claims GitHub-hosted fallback merely because a key or
    process disappeared. It closes the allocation gate, blocks new approvals,
    revokes existing approvals through their owning workflow, deactivates and
    proves empty runtime before reporting `github_hosted_fallback=true`.

## Transport contract

The forced gateway accepts exactly one length-delimited frame and EOF. A
request referencing objects must be accepted first; that durable row reserves
its exact object digests, byte counts, media types and quota before any object
upload is accepted:

```text
SHCI-MAINTENANCE/1 request <decimal-bytes> <lowercase-sha256>\n
<exact payload bytes>

SHCI-MAINTENANCE/1 object <request-id> <decimal-bytes> <lowercase-sha256>\n
<exact object bytes>
```

The header has a small fixed maximum, decimal length is canonical, and the
gateway rejects extra bytes, short reads, non-canonical hashes, unsupported
kinds and operation-specific size-limit violations. It writes no caller-
selected path. `request` frames submit a canonical signed envelope. An
`object` frame is accepted only for an `awaiting_objects` request signed by the
maintenance authority and only when all metadata matches that request. It
first lands in an expiring untrusted spool; promotion into the trusted CAS
occurs only after signature and request checks. Uploading an object has no
execution effect. Per-connection, per-request, per-authority-generation and
aggregate quotas apply; unpromoted objects expire automatically, while garbage
collection retains everything referenced by an active lease or ledger row.

The Windows gateway performs framing, size and SHA-256 checks, then streams to
the fixed distro and fixed ingress path. The WSL ingress repeats those checks
instead of trusting Windows. Objects are written with `O_CREAT|O_EXCL`,
`O_NOFOLLOW`, mode `0600`, root ownership and a temporary name on the same
filesystem, then atomically renamed to:

```text
/var/lib/self-hosted-ci/maintenance/objects/sha256/<digest>
```

An existing object is accepted only when its regular-file type, owner, mode,
size and digest are all exact. The final placement must be no-replace:
`renameat2(RENAME_NOREPLACE)` when available, or same-filesystem `linkat` to an
absent destination followed by unlink of the temporary inode. A normal rename
that can replace the digest path is forbidden. The file and containing
directory are `fsync`ed before success. Consumption reopens the final path with
`openat`/`O_NOFOLLOW`, requires one link, rechecks metadata and digest while the
operation lease is held, and never trusts an earlier file descriptor alone.
`EEXIST` is idempotent only after the same regular-file, single-link, owner,
mode, size and digest checks; otherwise it is a permanent CAS conflict.

Windows PowerShell 5.1 must treat the payload as bytes. The gateway reads
`Console.OpenStandardInput()` and copies to `StandardInput.BaseStream` of an
absolute `C:\Windows\System32\wsl.exe` launched with `ProcessStartInfo`; no
PowerShell text pipeline participates. It uses `-NoProfile -NonInteractive`,
an explicit minimal environment and absolute executables, and ignores the
user's `PATH`, `PATHEXT`, `COMSPEC`, `WSLENV` and PowerShell profile. The
one-time manifest separately pins the effective Win32-OpenSSH
`DefaultShell`, `DefaultShellCommandOption` and `DefaultShellEscapeArguments`
registry state. Version 1 accepts only the tested default `cmd.exe` chain with
no registry overrides; drift aborts and changing those values remains a UAC
operation.

The response is also length-delimited:

```text
SHCI-MAINTENANCE-RESPONSE/1 <accepted|state|receipt|error> <decimal-bytes> <lowercase-sha256>\n
<exact canonical JSON bytes>
```

It contains request ID/digest, durable state and a bounded error code. It never
contains a raw command, exception, journal or caller-controlled log. Repeating
the exact signed request polls the existing row and returns `state` or its one
terminal signed `receipt`; it cannot redispatch the operation.

## Signed request

The request envelope contains `payload` and a detached, unpadded base64url
Ed25519 `signature`. Signature input is:

```text
ASCII("self-hosted-ci/maintenance-request/v1") || 0x00 || JCS(payload)
```

The two local-PR control operations use a separate Ed25519 control authority
and domain `self-hosted-ci/local-ci-control-request/v1`. That authority is new;
it is not inferred from today's root shell, maintenance key, reviewer key or
allocation signer. Its exact payload additionally binds control-key generation,
repository and repository ID, PR number, expected head SHA, issued/expiry,
request ID and nonce. WSL re-resolves the selected repository and current head
with the installed App and rejects drift before calling the existing worker.
The forced gateway can transport both closed schemas, but their keys, domain
separators, replay namespaces and ledgers remain distinct. The control public
key and generation are installed in the pre-cutover manifest; the `0600`
private key and fingerprint are pinned in the Mac CLI configuration. Exact
request retries are idempotent, crossed nonce/target retries conflict, and
approve/revoke results use dispatcher receipts linked to the control request
digest and `LocalApprovalStore` row.

`payload` is I-JSON/JCS and has exactly these common fields:

```json
{
  "version": 1,
  "request_id": "lowercase-canonical-uuid",
  "host_id": "pinned-host-identity",
  "distro": "Ubuntu-24.04-CI",
  "issued_at": "canonical-utc-seconds",
  "expires_at": "canonical-utc-seconds",
  "nonce": "base64url-random-value",
  "authority_key_id": "maintenance-key-generation",
  "operation": "allowlisted-operation",
  "parameters": {},
  "objects": [],
  "expected_state": {}
}
```

The validity window is at most ten minutes. The host clock check fails closed.
`objects` contains only `{sha256, bytes, media_type}` records accepted by the
specific operation. `expected_state` supplies compare-and-swap preconditions,
such as current contract digest, configuration generation, image fingerprint
and expected activation state. Unknown and missing fields are rejected.

## Initial operation allowlist

The first release exposes only these versioned operations:

| Operation | Effect | Required postcondition |
| --- | --- | --- |
| `status-v1` | Read dispatcher/runtime state | Dispatcher-signed observation receipt; no mutation |
| `preflight-live-contract-v1` | Run every live-contract guard over one referenced bundle | `status=verified`, `host_mutated=false`, exact bundle digest and reviewer fingerprint |
| `install-live-contract-v1` | Install a bundle that has a matching unexpired preflight receipt | Installed contract digest exact; runtime remains inactive; staging absent |
| `configure-runtime-v1` | Reconcile fixed root-owned configuration sources already present on the host | Exact config generation and image fingerprint; GARM inactive; inventories empty |
| `activate-runtime-v1` | Execute the versioned activation transaction | Health eligible; expected config; services active; no preexisting allocation |
| `deactivate-runtime-v1` | Execute recovery and the versioned deactivation transaction | Services inactive; scale sets and `ci-jit` empty; approval absent |
| `build-profile-v1` | Build a versioned profile from an exact referenced source contract | Published alias resolves to the exact immutable image fingerprint; builder teardown clean |
| `approve-pr-v1` | Resolve and approve one selected repository/PR head through the installed worker | Exact repository, PR and server-resolved head; bounded TTL; durable approval receipt |
| `revoke-pr-v1` | Revoke one exact active approval | Approval terminal or already absent; no runner allocation created |
| `confirm-cutover-v1` | Bind the first permanent-key remote proof to the exact Windows/WSL cutover manifest | Exact committed status receipt, cutover challenge and all generations; activation fence lifted once |

There is deliberately no generic `run`, `exec`, `shell`, `powershell`, `bash`,
`systemctl`, `copy`, `delete`, `chmod`, `path`, `url` or arbitrary GitHub
operation. A local PR run remains a separate exact repository/PR/head approval
through the canonical `self-hosted-ci run-local` flow. Before forced-command
cutover, the CLI must implement that flow entirely through `approve-pr-v1`,
`revoke-pr-v1`, signed maintenance status and the existing read-only Health
channel. An inventory test must prove that no supported CLI command still
depends on the old general shell.

For the current CLI, signed `status-v1` replaces the remote read of
`outbound-worker.json`; the existing Health channel replaces the remote
`cmd.exe type ...health\\current.json`; and `approve-pr-v1` replaces direct
execution of `outbound-coordinator-worker.py approve/status`. Repository
workflow writes performed by `use-local` and `use-github` remain local `gh`
operations with their existing ownership transaction and are not proxied
through WSL.

Each adapter consumes a typed request object in memory and invokes fixed
product entrypoints. Secrets remain at fixed root-owned paths and are neither
uploaded nor named by the caller. A new operation requires a reviewed schema,
adapter, threat analysis and regression matrix; it is never introduced as a
new free-form parameter to an existing operation.

`preflight-live-contract-v1` receipts bind the bundle digest and bytes,
reviewer fingerprint and reviewer-key generation, verifier/package revision,
schema generation, exact guard-set digest, policy digest, host/distro identity,
observed runtime state, issuance and expiry. `install-live-contract-v1` resolves
that committed receipt from its ledger ID and rejects a caller-supplied copy,
an older validator generation or any state drift.

## Ledger and idempotency

`maintenance-ledger.sqlite3` is root-owned, mode `0600`, uses WAL plus explicit
transactions, and records:

- request ID, canonical request digest, authority generation and nonce hash;
- operation and object digests;
- received/verified/started/terminal timestamps from the host clock;
- state `received`, `awaiting_objects`, `verified`, `running`,
  `receipt_pending`, `succeeded`, `failed`, `indeterminate`, `quarantined`,
  `quarantine_unsafe`, `expired` or `conflict`;
- durable mutation lease with request ID, distro boot ID, systemd unit and
  invocation ID chosen by the dispatcher, not the caller;
- before/after state digests, external-effect intent and reconciliation data;
- terminal receipt digest and previous receipt digest.

Ingress uses `BEGIN IMMEDIATE` to bind a request ID and nonce before starting
the unit. A nonce binds once to exactly
`(request_id, request_digest, authority_generation)`: the same tuple is an
idempotent poll or resume, while any other tuple is a permanent conflict. A
request accepted before expiry may reconcile afterward; a request not accepted
before expiry can never start an effect. A conflicting digest, lower/revoked
key generation, missing CAS object or mismatched expected state is terminal and
cannot start a unit.

All mutating adapters are incompatible with one another in version 1. The
existing owning workflow is the sole owner of file locks; the controller never
pre-acquires a lock that a child would reacquire. The adapter takes
`/run/self-hosted-ci/maintenance-transaction.lock`, then its existing
operation-specific lock, and invokes a fixed committer with those file
descriptors inherited at fixed numbers. The committer verifies their canonical
device/inode and held-lock state, opens `BEGIN IMMEDIATE`, rereads authoritative
state, checks compare-and-swap values, acquires the durable lease, persists
intent and commits. Only its `effect-ready` result permits the owning workflow
to continue while retaining both locks. No adapter can read the ledger, no file
lock is acquired inside SQLite, and no owning script bypasses or reacquires its
canonical guard. After the effect, an independent observer/committer opens a
new transaction for receipt processing. The lease binds request, distro boot
ID, unit and Invocation ID. A reconciler clears an orphan only after
authoritative systemd evidence, never from timeout alone. `status-v1` may run
concurrently, but reports `mutation_in_progress` plus the active request digest
and never presents its observation as a stable postcondition. Every
irreversible boundary revalidates its relevant CAS values while both file locks
and the same durable lease are held.

Maintenance and local-PR control share that global lock. `enter-quarantine-v1`
is an internal owning transition, not a caller-selected escape hatch. It fences
the allocation broker first, makes new approvals ineligible, revokes each
active approval through `LocalApprovalStore`'s owning revoke workflow,
reconciles any claimed allocation, runs the versioned deactivation transaction
and independently proves zero GARM scale sets, zero `ci-jit` instances and no
runner processes. Only that complete sequence may report
`github_hosted_fallback=true`. A crash resumes from durable phase intent. If
any step cannot prove completion, state is `quarantine_unsafe` with
`manual_recovery_required=true`; it never reports successful fallback.

On boot, a reconciler inspects `verified`, `running`, `indeterminate` and
`quarantined` records. It resumes only operations whose adapter declares a safe
recovery procedure. A crash after intent but before conclusive observation is
`indeterminate`, not failed. If the external state cannot be reconciled, the
runtime becomes `quarantined` and rejects new mutations until bounded recovery
or console break-glass. Receipts include the last proven phase, intent digest
and observed facts; they never turn ambiguity into failure, success or a repeat
of the effect. The reconciler never invents a terminal result from the absence
of a process.

Systemd durability preserves state across SSH loss and WSL shutdown. Resuming
after a Windows reboot additionally depends on the already supported Health
Supervisor waking `Ubuntu-24.04-CI`; the dispatcher creates no new Scheduled
Task. `status` and `doctor` distinguish `state_preserved` from
`resumed_after_windows_boot`. If Health is unavailable, the truthful guarantee
is resume on the next distro start, not automatic Windows reboot recovery.

## systemd execution boundary

The Windows gateway enters WSL as a dedicated unprivileged
`selfhosted-ci-maint-ingress` user, not as root. That process can write only a
quota-bounded incoming spool. A root-owned path unit wakes a small controller,
which revalidates framing, digest, canonical request and signature before
moving content into the root CAS and ledger. Parsing twice is deliberate. The
ingress user cannot read the ledger, authority configuration, operation
outputs or receipt key.

`self-hosted-ci-maintenance@.service` receives only an escaped canonical UUID.
The fixed `ExecStart` is the controller with `--resume-request-id %i`; request
content is loaded from the root-owned ledger. The unit does not interpolate
request fields into `ExecStart`.

The baseline unit uses `UMask=0077`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
`ProtectHome=yes`, `ProtectSystem=strict`, explicit `ReadOnlyPaths` and
operation-specific `ReadWritePaths`. Capabilities and device access are empty
by default and added only in narrower adapter units when an existing product
operation proves they are required. `KillMode=control-group`, runtime and
startup deadlines, failure collection, journald identifiers and reboot
reconciliation are mandatory.

Controller, adapters and receipt signer are separate units and Unix
identities. Adapters receive one root-owned normalized request file and write
one bounded result directory; their mount namespace makes the maintenance
ledger and receipt private key inaccessible. The receipt signer accepts only a
committed terminal payload selected by ledger row ID. This separation limits
accidental key/ledger access by an adapter; it does not claim cryptographic
protection against a fully compromised WSL root or kernel.

Adapter units also close WSL interoperability. They have no Windows paths in
`PATH`, unset `WSL_INTEROP` and `WSLENV`, hide `/mnt`, `/init`, the WSL interop
socket and the `WSLInterop` binfmt registration in their private mount
namespace, and receive no Windows environment. Installation tests must prove
that an adapter cannot execute `*.exe`, reach DrvFs, change the service
account's HKCU/profile or select another WSL distro. The forced gateway itself
uses WSL interop only to enter the fixed distro and unprivileged ingress user.

The maintenance verifier, controller, signer, unit definitions, authority
manifests and receipt key are the dispatcher trust base. No allowlisted adapter,
including live-contract installation, may write or replace those paths. Updating
that trust base is a new reviewed bootstrap/cutover generation and remains a
Facu/UAC operation; the dispatcher cannot authorize its own replacement.

Profile builds receive their own persistent unit and resource limits; they do
not execute inside the ingress process. Activation/deactivation keep the
existing transaction lock and rollback primitives. The dispatcher does not
duplicate or weaken product guards and acknowledgements; its signed operation
schema is the bounded equivalent of those acknowledgements.

## Dispatcher-signed receipts

The dispatcher owns a distinct root-only Ed25519 receipt key. Its public key
and fingerprint are pinned by the one-time Windows installer and by the Mac
CLI configuration. This proves continuity of the installed dispatcher during
normal operation; it does not attest against a compromised WSL root or kernel.
A receipt signature covers:

```text
ASCII("self-hosted-ci/maintenance-receipt/v1") || 0x00 || JCS(receipt_payload)
```

The payload includes host/distro, monotonic receipt sequence, request ID and
digest, operation, terminal result, timestamps, unit invocation ID,
before/after state digests, sanitized evidence digests, previous receipt
digest, and receipt-key generation. Receipts contain no secret, raw token,
private evidence or caller-controlled log text.

Independent postcondition observation first commits `receipt_pending` with the
immutable payload, allocated sequence and previous chain digest. That state is
not externally terminal. The signer deterministically signs that exact payload;
a second transaction verifies the signer consumed only that immutable
`receipt_pending` payload, stores signature and envelope digest, advances the
chain head and only then publishes `succeeded`, `failed`, `indeterminate`,
`quarantined` or `quarantine_unsafe`. The last result always carries
`fallback_proven=false` and `manual_recovery_required=true`. No later sequence
can be allocated while its predecessor is `receipt_pending`. If signing or
atomic materialization is interrupted, reconciliation recreates the one exact
envelope from the committed payload before advancing the chain. The same
request never acquires a different terminal receipt.

The Mac CLI persists the latest accepted `(host_id, receipt_key_generation,
sequence, receipt_digest)` checkpoint in its protected local configuration. It
rejects a lower sequence, a different digest at the same sequence, a chain that
does not extend the checkpoint, or an unapproved receipt-key rotation. Asking
the host for a valid old prefix is therefore detected as rollback rather than
accepted as current state.

## Pre-cutover WSL proof

All WSL mutations happen before the elevated Windows cutover, while the current
supported `selfhosted-ci-svc` channel still works. A content-addressed systemd
installation creates the unprivileged ingress identity, controller, adapters,
units, maintenance and local-control public authorities, and WSL-local receipt
key. The independent reviewer signs an exact bootstrap manifest containing
every installed digest, owner, mode, both authority generations and public-key
fingerprints, and the receipt public-key fingerprint.

The Mac CLI pins that manifest and fingerprint, then proves a signed
`status-v1` request and dispatcher receipt end to end. It also proves parity for
all CLI calls that currently use the shell. The future elevated helper embeds
the same manifest digest and public fingerprints. It neither needs nor attempts
to discover another user's HKCU WSL registration. No Scheduled Task, stored
password, impersonation or second WSL installation is introduced.

## One-time elevated Windows authorization

One reviewed, plan-first installer performs the Windows cutover in one elevated
transaction:

1. Verify the exact Windows package, gateway and pins for the already-proven WSL
   bootstrap manifest, receipt key and maintenance authority.
2. Verify the exact SID for `selfhosted-ci-svc`, that it is non-admin, protected
   Windows ACLs and the exact supported Win32-OpenSSH default-shell registry
   state. Distro registration ownership was signed into the pre-cutover WSL
   proof and is deliberately not re-read from another user's HKCU here.
3. Stage the gateway below protected `C:\Program Files\self-hosted-ci` and a
   candidate authorized-keys/config set. The service identity receives read and
   execute only. A canonical Windows cutover manifest binds a fresh `cutover_id`
   challenge, gateway digest/generation, candidate `sshd_config` digest,
   permanent transport public-key fingerprint and effective default-shell
   registry digest. The gateway passes the ID and generation as fixed transport
   metadata to the absolute WSL ingress; neither comes from request bytes.
4. Validate the complete candidate with `sshd -t` and effective
   `sshd -T -C`. Launch a bounded alternate `sshd` child on loopback only, with
   a protected ephemeral transport key and the candidate ForceCommand. Prove
   gateway execution, exact rejection of an unsigned/invalid frame, and
   negative shell, PTY, forwarding, SFTP and subsystem behavior. Keep this
   loopback listener alive only for the stopped-listener measurement in the
   next step. This is an installer subprocess, not a persistent service or
   task.
5. Stop the production `sshd` listener before inspecting sessions. Wait for and
   terminate every preexisting `selfhosted-ci-svc` SSH child, prove none remain,
   and remeasure the protected Windows gateway/config while no new connection
   can enter. Through the loopback-only candidate listener and ephemeral key,
   invoke a fixed no-input bootstrap measurement mode that can only remeasure
   the reviewer-signed WSL manifest and return its dispatcher-signed digest; it
   accepts no operation or path. Stop that listener, delete and prove absence of
   its ephemeral private/public keys and staging, then verify no service-account
   SSH child remains. Any mismatch or unexpected process aborts to the old
   config with production `sshd` restarted. The elevated identity never opens
   another user's HKCU WSL registration directly.
6. With the listener still closed, atomically install the already-validated
   `Match User` forced-command config and permanent transport public key. Then
   start `sshd`; a synchronous parse/start failure restores the prior config and
   starts the prior service.
7. Return `installed_pending_remote_proof`, not success. The non-elevated Mac
   CLI immediately performs a real signed `status-v1` request with the permanent
   key, remeasures every WSL bootstrap target against the reviewer-signed
   manifest, and verifies the dispatcher receipt/chain/bootstrap pins plus the
   observed cutover ID and Windows manifest fields. It then submits
   `confirm-cutover-v1`, signed by the maintenance authority and bound to the
   exact status receipt, cutover challenge, gateway/config/transport/default-
   shell digests, bootstrap manifest digest and receipt-key generation. Under
   the global lock, the controller revalidates those values and atomically
   creates the root-owned cutover-proof sentinel. Exact retry is idempotent;
   any crossed, prior-generation or stale receipt conflicts. Only this
   transition lifts the activation fence, after which the CLI persists its
   local cutover receipt/checkpoint.

After the remote proof, there is no remotely reachable arbitrary shell for the
service identity. Break-glass recovery is Facu at the Windows console with UAC,
not a hidden unrestricted key, Scheduled Task or LocalSystem service.

Power loss cannot be treated as a normal PowerShell rollback. The installer is
ordered so a loss before stopping `sshd` leaves the old path; a loss while the
listener is stopped may require Facu to restart the prior service; and a loss
after config replacement leaves a prevalidated forced configuration. Until the
Mac proof, runtime activation remains fenced and status stays
`installed_pending_remote_proof`. Failure outside the synchronous rollback path
is an explicit console/UAC break-glass case; the design does not promise an
unprivileged Windows reconciler.

## What still requires Facu

The dispatcher intentionally cannot perform operations outside the dedicated
WSL product boundary. Facu remains required for:

- creating, deleting or changing Windows accounts, groups or LSA rights;
- registering, importing, unregistering or changing ownership of a WSL distro;
- changing protected Windows ACLs, OpenSSH configuration or authorized keys;
- installing/upgrading Windows OpenSSH, WSL or other Windows components;
- creating, changing or deleting Scheduled Tasks or Windows services;
- rotating Windows account passwords or repairing Health Supervisor;
- installing a new Windows package/gateway generation or changing the pinned
  maintenance/reviewer/receipt root authorities;
- destructive break-glass recovery after the forced gateway itself is lost.

Routine live-contract preflight/install, WSL runtime configuration,
activation/deactivation, profile builds, cleanup reconciliation and status can
run without repeated UAC once their adapters are implemented and the one-time
cutover is complete.

## Delivery plan

Implementation is split so no PR creates a partially privileged remote shell:

1. **WSL core and protocol.** Add canonical schemas, signature verification,
   CAS object store, maintenance ledger, host receipts, dispatcher/reconciler,
   template units and fake adapters. No Windows ingress and no production
   operation is reachable.
2. **Bounded real adapters.** Add one adapter at a time, beginning with
   `status-v1`, preflight and deactivation. Each adapter reuses existing
   product transactions and gets crash/reboot/idempotency tests before the
   next effectful operation is added.
3. **CLI and gateway readiness.** Add request signing, object upload, receipt
   verification, exact parity for every currently supported remote CLI call,
   status/doctor integration and key rotation/revocation. Build the Windows
   gateway and plan/apply installer, but do not change live OpenSSH yet.
4. **One-time Windows cutover and live proof.** After every artifact and CLI
   path preflights through the still-available old channel, run one elevated
   transaction to install the protected gateway, pin receipt authority and
   atomically enforce ForceCommand. Prove the new path and one real non-
   production maintenance operation before declaring the shell unsupported.

No phase enables local CI or changes repository routing by installation alone.

## Acceptance matrix

At minimum, tests must prove:

- canonical JCS equivalence and rejection of duplicate keys, unsafe I-JSON,
  invalid UTF-8, non-canonical UUID/time/length/hash and unknown fields;
- wrong host/distro/domain/key/fingerprint/signature, expired/future request,
  nonce replay and lower/revoked key generation all fail before unit creation;
- maintenance, local-control, reviewer, allocation and receipt keys cannot
  cross domains; control approve/revoke binds exact repo ID, PR and host-
  revalidated head and persists its replay linkage to `LocalApprovalStore`;
- same ID/same digest is idempotent, same ID/different digest conflicts, and a
  crash at every ledger/effect/receipt boundary converges without duplicate
  external effect;
- object traversal, symlink, hardlink, device, sparse/oversized file, short or
  extra stream, digest collision and quota exhaustion all fail closed;
- binary transport preserves all 256 byte values, NUL and CRLF and rejects a
  short read, extra byte or mid-frame disconnect without a text conversion;
- the gateway ignores/rejects original commands and cannot obtain a shell,
  PTY, forwarding, arbitrary WSL distro/user or alternate executable;
- `sshd -T -C` proves the effective matched configuration, and SFTP, SCP and
  subsystem requests cannot escape the forced protocol;
- hostile or drifted Win32-OpenSSH default-shell registry values abort before
  cutover, and the tested default quoting chain invokes only the pinned gateway;
- every existing `self-hosted-ci` command either uses the new bounded protocol
  or is explicitly unavailable before the general shell is removed;
- the service identity cannot modify gateway, package, `sshd_config`,
  authorized keys, WSL authority keys, ledger, units or receipts;
- unit names accept only canonical UUIDs and no request value reaches argv,
  environment or a shell;
- disconnect, timeout, process kill and reboot preserve the unit/ledger and
  yield a truthful signed receipt;
- a cold Windows reboot either wakes the distro through the existing Health
  dependency and reconciles, or reports `state_preserved` without claiming it
  resumed;
- concurrent pairs of all mutating operations serialize, revalidate expected
  state under the global durable lease and cannot deadlock by lock inversion;
- `approve-pr-v1` racing quarantine cannot cross the allocation fence; active
  approvals are revoked by their owner, and fallback is reported only after a
  fully empty runtime proof;
- an existing CAS object cannot be replaced, including on systems without
  `renameat2`, and crash injection around file/directory `fsync`, CAS promotion
  and ledger commit cannot accept a partial object;
- adapters cannot read or mutate the controller ledger or receipt key and
  cannot use WSL interop or DrvFs to cross back into Windows;
- activation/deactivation/profile-build failures execute their existing
  rollback/recovery paths and prove empty GARM and Incus inventories;
- receipt chain, sequence, signature, key rotation and deterministic
  re-materialization are verified independently by the Mac CLI, including
  rejection of a valid old prefix, truncation or fork;
- a crash around `receipt_pending`, signing, envelope materialization or chain-
  head advance blocks later sequences and deterministically converges to one
  terminal envelope;
- the one-time Windows installer is plan-only without `-Apply`, requires the
  exact acknowledgement, validates with Windows PowerShell 5.1, and restores
  the previous working OpenSSH configuration on a synchronous failed positive
  or negative probe; crash-point tests prove the old-or-prevalidated-new
  ordering around the atomic config commit;
- the production listener is stopped before session inventory, every prior
  service-account SSH child is gone before remeasurement, and a connection
  racing the cutover cannot retain an unrestricted shell;
- the alternate loopback preflight leaves no process, ephemeral key or staging
  after success, failure or crash, and the first permanent-key remote proof is
  required before activation can become eligible;
- `confirm-cutover-v1` rejects an old/crossed status receipt, manifest,
  receipt-key or gateway generation, is idempotent for one exact proof, and
  cannot race activation across its host-side fence commit.

Until these gates and the one-time cutover are complete, the current elevated
Windows workflow remains authoritative. This design is not permission to
delete guards, run ad-hoc tasks or treat an unrestricted SSH shell as the
finished product.
