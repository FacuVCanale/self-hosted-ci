# Self-hosted GitHub automation — execution-ready specification

> **Hosted MVP tuple amendment (`local-ort-v1`).** For the active Gate Service
> and reusable hosted workflow, this amendment supersedes older references in
> this document to mutable GitHub-generated merge SHAs, `mutable GitHub merge field`,
> `GitHub merge ref`, or a Check targeted at a merge SHA. The authoritative
> tuple is server-resolved `repository_id + pr_number + head_sha + base_sha +
> merge_policy_version(local-ort-v1)`; the Check targets `head_sha`, and the
> quality job constructs and records the deterministic local merge.
>
> Scope is public repositories with head-evaluated required Checks. Universal
> rulesets, private-repository reads, and `merge_queue`/merge-group semantics
> are outside this MVP. Ruleset activation remains off until a public sandbox
> proves the dedicated App source and head-target evaluation end to end.

## Goal

Provide an opt-in, reversible self-hosted GitHub CI platform for personal and organization repositories explicitly selected by the operator. AI review is a separate product and is outside this repository's scope.

## User-facing contract

- Every repository uses GitHub-hosted runners by default.
- The operator can enable or return one exact `owner/repo`; no operation implicitly enables an organization.
- Reviewer and local-CI enablement are independent.
- If local does not formally claim within the configured timeout, CI falls back automatically.
- Switching/fallback are observable, auditable, idempotent and never create an ambiguous required check.
- Untrusted fork, Dependabot, and external-contributor changes do not execute locally.

## Initial platform

- Host: a dedicated or repurposed operator-managed machine reached through an authenticated management network; real hostnames, users and addresses belong only in private configuration.
- Linux: a **dedicated CI WSL2 distribution**, not the personal Ubuntu distro.
- Initial isolation: disposable Linux containers, one job per JIT runner/container, concurrency one.
- Runner manager is not preselected: mandatory bake-off compares Fireactions, GARM+Incus and `myoung34/docker-github-actions-runner`; Fireactions is eligible only after functional KVM proof. If none passes, local CI remains disabled pending a stronger VM/dedicated Linux host.
- AI review: out of scope; maintained and installed separately.
- Config source: an operator-private configuration store; upstreams are pinned dependencies, not forks by default.

## Desired state

```yaml
repositories:
  owner/repo:
    ci_runner: github | local-with-github-fallback
    ai_reviewer: enabled | disabled
    execution_trust:
      policy_version: 1
      mode: github-hosted | exact-sha-attestation
      attestation_authority_version: 1
      key_manifest_version: 1
      key_manifest_generation: <monotonic generation>
      key_manifest_digest: <lowercase hex sha256>
      offline_root_public_fingerprint: <sha256>
      public_key_id: <id>
      public_key_fingerprint: <sha256>
      inventory_drift_guard: enabled
    authority:
      kind: personal-repository | organization-runner-group
      installation_id: <id>
      runner_group: <exact group or null>
```

Absence means GitHub-hosted and reviewer disabled. Wildcards are invalid.

## Execution trust policy v1

`execution_trust_policy_version: 1` is independent from runner registration/organization runner-group authority. Permission to schedule a repo on a runner does not establish that the code is trusted.

Default and fail-closed rule:

```yaml
default: github-hosted
local_eligible: false
on_unknown_or_drift: github-hosted_or_fenced
```

For the pilot, the **only positive proof** that enables new local execution or success is a valid signed `exact-sha-attestation`. `enumerated-writers` is disabled as a positive mode. Without valid current proof, use GitHub-hosted/fence at the four authority boundaries; an already-running exact timely failure may conclude only from authentic historical admission.

Never infer execution trust from repository privacy, `author_association`, `MEMBER`, `COLLABORATOR`, PR author, branch owner, same-repository PR, organization membership, collaborator status, or runner-group access.

### Immutable identity and effective-writer inventory

Inventory records IDs, not mutable names alone:

- users/bots: numeric GitHub user ID, node ID, account type and current login as display metadata;
- teams: organization ID + team ID, plus complete expanded member-ID snapshot/hash including child teams;
- GitHub Apps/integrations: App ID + installation ID + exact repository permissions;
- write deploy keys: deploy-key ID + fingerprint;
- ruleset/branch bypass actors: actor type + immutable actor ID, expanded to effective users when actor is a role/team;
- privileged Actions/workflows: GitHub Actions integration ID, workflow/ref/permission snapshot, and the effective writers who can change that trusted workflow/ref;
- repository collaborators/owners/default-role grants: complete effective user-ID list and permission level.

The guard is mechanical. Let `required_source_ids` be policy-pinned and sorted. A source is usable only after authenticated expected API/schema response and complete pagination. `complete` means all required usable; `partial` means at least one usable and exact non-empty sorted `missing_source_ids` known; `unavailable` means zero usable or required/missing set cannot be authenticated. Semantic hash is lowercase hex SHA-256 of JCS `{status, required_source_ids, missing_source_ids, normalized_usable_source_records}`. Records include only effective immutable actors/permissions and policy-relevant API/schema semantics; exclude `observed_at`, request IDs, latency and transport ETag. Issuance `observed_at` is a separate signed payload field; later `observed_at`/ETag are separate gate audit metadata. ETag change with identical normalized semantics does not drift. Freshness policy v1 requires every gate observation age `<=5m`; stale fails freshness, not drift.

GitHub does not expose one atomic, exhaustive “all identities able to update this ref” API. Collaborator listing reports effective highest repo roles but not the grant source; branch restriction APIs are distributed and restrictions are organization-only in some cases; rulesets, bypass actors, Apps, deploy keys and workflow token capabilities require separate queries. This is why inventory is negative-only and signed exact-SHA attestation is the pilot's sole positive proof.

### Exact-SHA attestation authority v1

`execution_trust_attestation_authority_version: 1` uses asymmetric signing; no shared password or secret ever enters model context, prompts, `AGENTS.md`, repository, logs or artifacts.

- Key: dedicated Ed25519 key, or platform-native asymmetric key such as non-exportable Secure Enclave P-256 when available. Private key is non-exportable where possible and stored under a restrictive macOS Keychain/secure local-store ACL. Public key, algorithm, key ID/version and fingerprint are pinned in control plane. The verifier needs no private material.
- Signing helper is installed outside the repo/model workspace and exposes a bounded command only. Caller supplies exact repo/PR/head plus optional `expected_head_generation`; `GateStore` reads the authoritative generation internally and the helper only compares the expectation, rejecting mismatch. Caller cannot set the signed generation. The helper re-resolves GitHub, generates nonce, and cannot sign stdin/files/arbitrary payload/caller nonce.
- The operator explicitly trusts a designated agent as the approval actor. The same-thread/exact-target rule is a **procedural TCB obligation**, not something the helper or verifier can cryptographically prove. The agent must invoke only after an explicit same-thread request naming the target or resolving one unambiguous repo+PR. It must not request blanket, branch-wide, repository-wide or future-head approval. A request-linkage value is audit metadata only: forging it cannot create authority without a valid signing-key signature.
- Audit stores an opaque thread/turn request-linkage ID/hash, normalized target and issuance result; it does not store transcript content or any signing secret.

Detached signature scheme:

- `payload` is I-JSON serialized with RFC 8785/JCS: UTF-8, no duplicate keys, no non-finite numbers, and stable field types. GitHub IDs, generations and timestamps use canonical strings where cross-language integer/date ambiguity could occur.
- Signed bytes are exactly `ASCII("github-automation/execution-trust-attestation/v1") || 0x00 || UTF8(JCS(payload))`. The detached `signature` is not a member of `payload`.
- Public-key fingerprint is lowercase hex SHA-256 of exact DER `SubjectPublicKeyInfo` bytes.
- Ed25519 uses the raw 32-byte public key represented by its SPKI, raw 64-byte signature, and unpadded base64url signature encoding.
- P-256 uses ECDSA-with-SHA-256, uncompressed SEC1 point inside SPKI, normalized low-S IEEE-P1363 `r||s` 64-byte signature, and unpadded base64url encoding. DER ECDSA signatures are rejected at the verifier boundary rather than accepted ambiguously.

Canonical signed payload:

```yaml
attestation_schema_version: 1
execution_trust_policy_version: 1
execution_trust_attestation_authority_version: 1
execution_trust_key_manifest_version: 1
key_manifest_generation_at_issuance: <canonical string>
key_manifest_digest_at_issuance: <sha256>
attestation_id: <UUIDv7>
algorithm: Ed25519 | platform-native-P256
key_id: <id>
key_version: <integer>
public_key_fingerprint: <sha256>
repository_id: <integer>
repository: owner/repo
pr_number: <integer>
head_sha: <40-char SHA>
head_generation: <GateStore observed-transition generation>
inventory_guard_status: complete | partial
missing_source_ids: [<stable source IDs>]
effective_writer_inventory_hash: <negative-guard snapshot>
inventory_guard_freshness_policy_version: 1
inventory_observed_at_at_issuance: <signed UTC metadata excluded from semantic hash>
issued_at: <control-plane UTC>
expires_at: <default 60m; maximum 90m>
nonce: <helper-generated 256-bit value>
request_linkage_hash: <opaque non-transcript hash>
```

- Helper signs only if the referenced key is `active` in the highest accepted manifest at issuance, and embeds that manifest version/generation/digest. Verifier proves the issuance manifest/digest is in the authenticated predecessor chain ending at the highest accepted manifest, proves the key was active there, then always applies the key's state in the highest accepted manifest.
- Verifier also checks domain/I-JSON/JCS/encoding, exact target/GateStore generation, inventory status/missing set/hash, issued/expiry and nonce. At every gate it obtains a new authenticated inventory observation with age `<=5m`, compares its semantic status/missing set/hash to the signed issuance values, and records fresh `observed_at`/ETag separately. The issuance timestamp itself may age; a fresh equal re-observation preserves authority. Request linkage is audit-only.
- First successful pre-dispatch verification atomically consumes/binds nonce to the exact local gate generation; repeated verification is idempotent only for that same generation. Reuse for another generation/repo/PR/head is replay and fails.
- `GateStore` is the sole source of `head_generation` and increments it only for transitions actually observed by the control plane. Observed A→B→A invalidates the prior A generation. An unobserved A→B→A is indistinguishable from unchanged A; that is safe for content identity because the exact SHA is again A, while nonce-to-local-gate-generation binding prevents reuse of a consumed attestation for a second local run.
- Attestation authority applies to local dispatch/JIT, claim, pre-marker admission and **local success** acceptance. Invalid proof routes GitHub/fences only at those four boundaries. After successful pre-marker verification, GateStore creates one immutable `local_admission_record`; a trustworthy timely terminal functional failure may rely on that historical admission even if the current proof later expires/is revoked/drifts. Historical admission is failure-only and can never authorize success.
- GateStore server clock is authoritative for `now < attestation_expires_at` at dispatch, claim, pre-marker admission and local success. Helper, coordinator, runner and GitHub job clocks are non-authoritative for attestation expiry. The historical-admission functional-failure transaction does not evaluate current proof expiry.
- V1 deliberately has no individual-attestation revocation API/list. A proof is invalidated by expiry, exact-head/head-generation drift, gate/nonce fencing, or revocation of its signing-key version; emergency key revocation invalidates every proof under that key.
- At dispatch, claim, pre-marker admission or local success, key manifest/helper unavailable, bad/fake signature, revoked or unknown/missing key, retiring key used for new proof, wrong target, expiry or nonce conflict means GitHub-hosted/fenced—not a password fallback. This rule does not erase a previously authentic admission's failure-only authority.

### Attestation key manifest and offline root authority v1

`execution_trust_key_manifest_version: 1` is the only source of accepted online signing keys.

- The security approver controls a separate offline Ed25519 root signing key in a user-presence-gated secure store/hardware-backed facility where available. Every initial pin, rotation or revocation requires an explicit local user-presence operation. The root private key is not accessible to the agent/helper/control plane; the bootstrap ceremony displays and explicitly pins SHA-256 of root DER SPKI before accepting manifest generation 1.
- Manifest payload is I-JSON/JCS and signed over `ASCII("github-automation/execution-trust-key-manifest/v1") || 0x00 || UTF8(JCS(payload))` with detached raw-64 Ed25519 signature encoded unpadded base64url. It contains manifest version, strictly monotonic `manifest_generation`, previous manifest digest, issued time, root fingerprint, and keys keyed by immutable key ID/version with algorithm, SPKI fingerprint and state `active|retiring|revoked`.
- `manifest_digest` is exactly lowercase hex SHA-256 of `ASCII("github-automation/execution-trust-key-manifest/v1") || 0x00 || UTF8(JCS(manifest_payload))`, excluding the detached signature and any envelope/transport fields. This exact value is used for `previous_manifest_digest`, `key_manifest_digest_at_issuance`, highest-accepted state, protocol and audit; no component hashes the signed envelope.
- Initial pin, every state transition and every new key require a valid offline-root signature. Rotation publishes a new `active` key and changes the old one to `retiring`; retiring keys verify already-issued proofs only until those proofs expire and cannot sign new proofs. Revocation is append-only: a revoked key/version can never return to retiring/active and remains listed in all successors.
- Control plane persists the highest accepted generation/digest plus the authenticated predecessor manifests needed by any unexpired proof. The exact same manifest is idempotent; lower/conflicting generation, skipped predecessor, missing revocation or state rollback is rejected. Missing required predecessor, accepted manifest or root-public verifier fails closed; offline root private need not be online for verification.

| Current key state | Sign new proof | Verify proof | Normative condition |
|---|---:|---:|---|
| `active` | yes | yes | issuance manifest is in accepted chain and shows this key active |
| `retiring` | no | yes | proof was issued while key was active, issuance manifest is in accepted chain, and proof is unexpired |
| `revoked` | no | no | reject immediately regardless of issuance or expiry |
| unknown/missing | no | no | reject; absence never means retiring |

## Required PR checks

- `ci-gate` is the single routed quality gate added by this platform.
- A dedicated private GitHub App named/slugged for `ci-gate` is the sole Check Run writer. Its App ID is the fixed expected source in the ruleset. The Action coordinator may orchestrate, but it obtains a short-lived installation token for this App; `GITHUB_TOKEN` and other Apps may not create/update `ci-gate`.
- For the hosted local-merge MVP, `ci-gate` targets the exact server-canonical PR `head_sha`. GitHub's mutable merge SHA is neither an input nor an authority.
- The logical PR key remains `repository_id+pr_number+head_sha+ci-gate`; each generation additionally binds the server-canonical `base_sha` and `merge_policy_version=local-ort-v1`.
- `supply-chain` stays an independent deterministic GitHub-hosted check and is not routed through the local fallback controller.
- Attempt jobs/checks have unique internal names and cannot satisfy `ci-gate`.
- Ruleset pins the expected App/source of `ci-gate`.
- A PR-controlled workflow/job/check/status named `ci-gate`, a commit status context collision, or a Check Run from any other App/source must not satisfy the gate.
- Pushes to `main` remain a separate GitHub-hosted workflow named `CI`; PR coordinator success never substitutes main-commit CI.
- On PR `opened`, `reopened`, `ready_for_review`, and `synchronize`, the coordinator resolves the current tuple/generation and routes only `ci-gate`; `supply-chain` runs independently in the ordinary unprivileged GitHub-hosted PR workflow. Old generations and native coordinator/attempt checks cannot substitute either result.

### Versioned `ci-gate` App authority contract

`ci_gate_authority_version: 1` is recorded in registry, protocol and evidence.

- Owner/security approver: an operator-designated human identity. Runtime token-mint authority: only the trusted `ci-gate` coordinator/reconciler control plane executing reviewed default-branch code. Children, runner manager, reviewer, deploy, PR code and ordinary repo workflows cannot access the App key or mint tokens.
- Non-secret authority record contains App ID, App slug, exact installation ID per exact repository, owner, allowed control workflow identity/ref, key fingerprint, rotation timestamp and version. App installations use selected repositories only; no all-account/all-org installation.
- Minimum App permissions: `Metadata: read` and `Checks: write`. Explicit negative permissions: no Contents read/write, Commit statuses write, Actions, Workflows, Administration, Pull requests write, Issues write, Deployments, Environments, Secrets, Members or org administration.
- Authorized private-key storage invariants: encrypted GitHub Actions secret scoped to the exact trusted control repository/environment, or root-only file/OS credential storage on the dedicated control host. No vendor-specific secret store is required. Plain repo files, runner images, child environments, caches, logs and artifacts are forbidden.
- Runtime minting: trusted control plane creates the App JWT, requests an installation token narrowed to exactly one repository and only `checks:write`/required metadata, and uses token TTL no greater than one hour. Token is memory-only, masked, never exported to child jobs or persisted in environment/artifact/log.
- Rotation: generate second key; store under the same invariants; validate positive Check Run write plus negative contents/status/admin tests; switch fingerprint; revoke old key; verify old minting/write fails; record audit. Compromise response: fence gates, restore GitHub-only routing, revoke all App keys/tokens, suspend/uninstall exact installations, rotate, repeat authority tests, then re-enable.
- Any App/installation/repository/permission/fingerprint mismatch is `CONTROL_FAILURE`; no check write occurs.

## Trusted coordinator protocol

- PR coordinator uses trusted base/default-branch `pull_request_target` code and never checks out, loads, imports, sources or evaluates PR-controlled content.
- The automatic workflow/job check emitted for `pull_request_target` has a different name and must not satisfy `ci-gate`; only the explicit custom Check Run may do so.
- PR title, body, labels, branch/ref names and filenames are untrusted data and never interpolate into shell/code/action references.
- Coordinator dispatches the child workflow definition from the trusted current default branch.
- Dispatch uses GitHub REST API version `2026-03-10` and must return HTTP 200 with the exact schema `workflow_run_id`, `run_url`, `html_url`. The URLs must bind the same repository and returned run ID. A 204/no-ID response, missing/extra field, cross-repository/run URL, ambiguous lookup, or unexpected schema is a protocol failure; list-and-guess correlation is forbidden.
- Child receives and validates the versioned package before checkout:

```yaml
protocol_version: 1
timing_policy_version: 1
execution_trust_policy_version: 1
repository_id: <id>
repository: owner/repo
pr_number: <number>
logical_key: <repo-id:pr:head:ci-gate>
generation: <monotonic generation binding base+local merge policy>
owner_run_id: <id>
owner_run_attempt: <number>
head_sha: <PR head>
base_sha: <PR base>
merge_policy_version: local-ort-v1
merge_base_sha: <merge base observed by the quality job>
tested_tree_sha: <tree produced by git merge -s ort --no-commit>
local_commit_sha: <deterministic two-parent commit created by commit-tree>
tested_sha: <local_commit_sha>
check_target_sha: <head_sha>
default_branch: <trusted branch>
backend: local | github
policy_version: <registry commit>
execution_trust_mode: github-hosted | exact-sha-attestation
execution_trust_attestation_authority_version: 1
execution_trust_key_manifest_version: 1
key_manifest_generation: <highest accepted monotonic generation>
key_manifest_digest: <highest accepted lowercase hex sha256>
key_manifest_generation_at_issuance: <signed canonical string or null>
key_manifest_digest_at_issuance: <signed sha256 or null>
attestation_id: <UUIDv7 or null>
attestation_key_id: <pinned key ID or null>
attestation_key_version: <integer or null>
attestation_public_key_fingerprint: <sha256 or null>
attestation_head_generation: <monotonic PR-head epoch or null>
attestation_expires_at: <UTC or null>
attestation_nonce_binding: <opaque GateStore reference/hash or null>
attestation_envelope_digest: <sha256 of canonical signed envelope or null>
attestation_request_linkage_hash: <opaque non-transcript hash or null>
inventory_guard_status: complete | partial | unavailable
missing_source_ids: [<stable policy source IDs>]
effective_writer_inventory_hash: <negative-guard sha256 or null>
inventory_observed_at: <signed/audited UTC metadata or null>
inventory_guard_freshness_policy_version: 1
local_admission_id: <GateStore-generated immutable ID or null>
local_admission_digest: <GateStore-computed canonical record sha256 or null>
local_evidence_id: <stable ID or null>
local_evidence_digest: <sha256 or null>
local_result_kind: success | functional_failure | null
local_child_run_id: <exact run ID or null>
local_child_job_id: <exact job ID or null>
started_test_marker_digest: <sha256 or null>
canonical_command_digest: <sha256 or null>
terminal_at: <authoritative GitHub API UTC or null>
ci_gate_check_run_id: <dedicated-App Check Run ID>
check_outbox_idempotency_key: <logical-key:generation:winner:evidence-digest or null>
claim_deadline: <UTC>
execution_deadline: <UTC>
```

Protocol invariant: `backend=local` requires `execution_trust_mode=exact-sha-attestation` and complete signed attestation fields. `backend=github` requires `execution_trust_mode=github-hosted`; attestation fields are null/evidence-only and are not an authority predicate for hosted execution or conclusion.

- Child re-queries PR tuple, performs only trusted bootstrap independent of PR content, checks out detached `tested_sha`, verifies `git HEAD==tested_sha`, then invokes a trusted start wrapper located outside and unwritable from the PR workspace. The wrapper persists `started_test_at` in the control-plane `GateStore` **before any operation whose behavior or inputs depend on PR content**, including dependency resolution/install (`npm ci`, pip), generated scripts, build, lint, tests, or project tooling. It revalidates before result.
- Trusted bootstrap is limited to runner identity/protocol validation and installation/verification of fixed, SHA/digest-pinned controller tooling that does not read the checkout or PR metadata. Once the checkout is read, any ordinary nonzero child result is functional unless GitHub independently proves transport loss.
- Immediately before marker creation, verifier must successfully revalidate the current proof. GateStore then creates `local_admission_record` exactly once and only from that successful decision. The immutable record binds attestation ID/envelope digest, nonce binding, policy/authority/manifest/key versions and digests, canonical base/head, local artifact, gate generation, exact child run/job, owner/lease epoch, verifier decision ID/time, persisted execution deadline and the marker-core digest it authorizes. Its canonical digest is computed by GateStore; caller metadata alone is not admission.
- `started_test_marker_digest` is the canonical digest of marker core fields excluding admission ID/digest, avoiding a circular hash. Start marker is timestamped by the authoritative control-plane clock and contains that core plus authentic `local_admission_id` and `local_admission_digest`. Admission binds the marker-core digest; the final marker binds the admission reference. Both persist atomically or the marker is unusable. PR files/processes cannot create, overwrite, backdate or delete either record. If admission/marker persistence cannot be confirmed, classify `CONTROL_FAILURE`, start no PR-dependent process, fail closed and let watchdog/reconciler repair; do not infer infrastructure fallback.
- A same-head base/merge change creates a new generation; older generation is fenced.

## Ownership, claim, fallback and cancellation

- `GateStore` owns acquire/heartbeat, GitHub-winner selection, atomic authorized local-success completion, atomic current-execution local-functional-failure completion, hosted completion, outbox/get/reconcile behind a replaceable provider interface. No generic API may select local outside these two transactions.
- `GateStore.bindAttestationNonce(attestation_id, nonce_hash, logical_key, generation, expected_head_generation, envelope_digest)` internally reads authoritative `head_generation`, rejects expectation mismatch, and atomically binds that internal value. Exact retry is idempotent; any differing tuple is replay/conflict.
- `GateStore.create_local_admission_after_pre_marker_verify(...)` accepts only a successful current verifier decision and atomically persists immutable admission+cross-bound marker. A crash exposes neither record or the complete pair; no PR-dependent process may start from a partial state.
- Pilot Action coordinator may use serialized Actions+Checks only if sandbox proves ownership; otherwise the dedicated host-local transactional SQLite provider must satisfy the atomic `GateStore` contract before requiring `ci-gate`.
- Same logical-key coordinators serialize; only current generation lease owner performs external side effects.
- After lease loss/fencing, the old owner may not dispatch, cancel, update a check, acknowledge a queue item, or post/update a comment.
- `complete_local_success_if_authorized(...)` uses GateStore clock, revalidates owner/lease/generation/evidence and valid attestation `now<expires_at`, then atomically commits `winner=local`, terminal success evidence and outbox. No local success Check mutation exists without this record.
- `complete_local_failure_if_current(...)` does **not** require a still-valid attestation. It resolves the authentic GateStore admission/marker and authoritative exact-job terminal observation; caller IDs, digests and `terminal_at` are expectation-only comparisons. It requires matching owner/lease/generation, exact child run/job, canonical base/head, local artifact and command, `terminal_at <= persisted execution_deadline`, terminal `FUNCTIONAL_FAILURE`, and no prior winner; then atomically commits local failure/evidence/outbox. Current proof invalidity is audit-only after valid historical admission. Missing/forged/mismatched admission is `CONTROL_FAILURE`: no winner/outbox/Check. This API cannot accept success or mutate failure into success.
- GitHub winner selection competes on the same linearization point. Exactly one of local completion or `winner=github` can commit; the loser is fenced/evidence-only.
- The transactional outbox targets the already-created exact `ci_gate_check_run_id` using dedicated-App authority and key `logical_key:generation:winner:evidence_digest`. Delivery updates that known Check Run; ambiguous response triggers GET/marker verification before retry. Same event is idempotent/convergent; different evidence conflicts. Thus at most one external logical gate mutation occurs even if PATCH delivery repeats.
- Formal local claim requires the exact returned run ID, expected workflow/ref/generation/backend, exactly one expected Jobs API job, timely non-null `started_at`, expected pool labels, and expected fresh ephemeral runner identity.
- `queued`, runner `online`, label presence, or a guessed run ID are not claim.
- Claim deadline begins at dispatch confirmation.
- Fallback selection persists immutable `winner=github`, then requests normal cancel of local. If local remains active after bounded grace, coordinator requests force-cancel. Reconciler resumes this sequence idempotently after interruption.
- Late local results after fallback selection are evidence only.
- After immutable `winner=github`, local is fenced and attestation expiry, signing-key revocation, manifest change or inventory drift is audited only; none may block a valid GitHub-hosted conclusion.
- GitHub winner conclusion requires: immutable winner and current lease owner; same logical key/generation/current PR tuple; exact `tested_sha=local_commit_sha` and `check_target_sha=head_sha`; canonical command/workflow contract; trustworthy hosted child/run/job identity and terminal timestamp within its persisted execution deadline; and dedicated `ci-gate` App authority. It does not require an attestation.
- Hosted completion also persists terminal evidence plus its outbox event atomically; same evidence is idempotent and different evidence conflicts. Both winner paths therefore mutate the dedicated-App Check only through the outbox.

Failure taxonomy:

- `PROTOCOL_FAILURE`: malformed tuple/package, wrong ref/source/API version/schema, ambiguous child, SHA mismatch. Blocking; no inferred fallback success.
- `INFRA_PRETEST`: dispatch/claim/platform/bootstrap failure before `started_test_at`, established by trusted wrapper/GitHub API. Eligible for one fallback.
- `FUNCTIONAL_FAILURE`: canonical command returns nonzero after `started_test_at` on the exact admitted child/run/job, canonical base/head, recorded local artifact and command, with authentic admission/marker and authoritative `terminal_at <= persisted execution_deadline`. It may commit without a still-valid current attestation if no winner exists. Final failure; no fallback and no later success conversion. A `terminal_at > execution_deadline` failure is late evidence only and triggers/resumes timeout fallback; it cannot win locally.
- `INFRA_TRANSPORT_LOSS`: GitHub-observed runner disappearance/platform cancel/hard timeout, even after start, without a trustworthy functional result. Eligible for one fallback.
- `STALE_INPUT`, `CONTROL_FAILURE`, `FALLBACK_FAILURE` remain blocking as defined in PRD.
- PR code cannot self-classify a failure as infrastructure.

A GitHub-hosted watchdog/reconciler repairs stale owner heartbeats, resumes cancel/force-cancel/fallback, fences old generations and blocks unrecoverable ambiguity while the laptop is offline.

Until a winner, reconciler validates attestation only at dispatch, claim, pre-marker admission and local-success acceptance. Invalid authority there selects GitHub/fences once. A timely authoritative functional failure with authentic historical admission may atomically win without a currently valid attestation; missing/mismatched admission is blocking `CONTROL_FAILURE`, while `terminal_at > execution_deadline` is evidence-only and selects/resumes timeout fallback. If GitHub already won, every local result is evidence-only.

## Normative timing policy

Timing policy is versioned as `timing_policy_version: 1`; any change requires plan/test evidence and a policy-version bump.

| Parameter | Initial value | Rationale / required behavior |
|---|---:|---|
| Coordinator heartbeat | 60 s | Detect loss without excessive Checks/store writes |
| Generation lease TTL | 5 min | Survives short API stalls; fences after five missed heartbeats |
| Watchdog interval | 5 min | GitHub scheduled-workflow practical floor; `workflow_run` may react sooner |
| GitHub API tolerance | 2 min | Bounded propagation/rate-limit allowance; never used to infer success |
| Inventory observation freshness | 5 min | Each trust gate re-observes; stale is freshness failure, not semantic drift |
| Local claim deadline | 10 min | User-approved offline fallback threshold |
| Local/fallback execution deadline | 40 min each | Current 35-minute quality job plus bounded margin |
| Normal-cancel grace | 90 s | Allows cooperative shutdown/cleanup |
| Force-cancel verification/reconcile | 2 min | Re-read exact run after force-cancel; watchdog resumes if interrupted |
| Dispatch/API retries | 3 total, backoff 2 s / 8 s / 32 s | Bounded transient recovery; protocol/schema errors are not retried as success |
| Poll cadence | 15 s, capped at 30 s with jitter | Timely claim/heartbeat without API thundering herd |
| Reviewer model timeout | 120 s/attempt | Safety ceiling; provider decision may choose lower, never higher without policy bump |
| Reviewer retries | 3 total, backoff 30 s / 2 min | Bounded outage/quota recovery; invalid output is not silently approved |
| Reviewer queue-age alert | 10 min | Detect unavailable consumer quickly |
| Reviewer max queue age | 24 h | Then dead-letter/block informational review and reconcile explicitly |
| Reviewer DLQ retention | 7 d, immediate alert | Incident evidence and bounded replay window |
| Pre-claim fallback dispatch SLA | ≤12 min from confirmed local dispatch | 10-minute claim plus 2-minute API tolerance |
| Total fallback gate SLA | ≤100 min worst-case | Covers full 40-minute local transport-loss window, cancellation/reconcile, 40-minute fallback and API tolerance |

Missing heartbeat or SLA breach blocks/alerts and is never converted to success.

### Timing oracle

- Persist absolute deadlines at their causal transition: claim deadline from API-confirmed dispatch time; execution deadline from control-plane-persisted `started_test_at`; lease expiry from GateStore clock; cancel/force-cancel timestamps from GateStore; reviewer queue age from queue-provider clock.
- Authoritative clocks: GitHub API timestamps for dispatch/run/job/terminal observations; GateStore server clock for lease, heartbeat, winner, start marker and cancel state; durable queue clock for enqueue/age/ACK. Runner/PR wall clock is evidence only and never decides a threshold.
- Claim is timely when `job.started_at <= claim_deadline`; claim timeout may transition only when authoritative `now > claim_deadline` and no timely claim exists.
- Lease is valid only while `now < lease_expires_at`; at `now >= lease_expires_at` the owner is fenced before any side effect.
- GateStore server clock evaluates attestation expiry at dispatch/claim/pre-marker-admission/local-success. Success requires transaction-time `now<T`; equality/later selects GitHub once unless a timely historically admitted failure transaction wins first. After GitHub winner, expiry is audit-only.
- Execution completion wins when authoritative GitHub API `terminal_at <= persisted execution_deadline`; timeout may win only when authoritative `now > execution_deadline` and no timely terminal completion exists. Equality wins. `terminal_at > execution_deadline` is evidence-only and selects/resumes fallback. Before timeout selection, re-read the exact job: an already-visible timely admitted failure must be offered to the failure transaction first; once either atomic winner linearizes, the loser remains evidence-only.
- Force-cancel becomes eligible at `now >= cancel_requested_at + 90s` if the exact run is still active. Queue alert/DLQ thresholds use `age >= threshold`. HTTP receiver meets the target only when durable enqueue completes and response duration is `<10s`.
- If completion and timeout observations race, re-read authoritative terminal state/deadline under the current lease before selecting; timely completion has precedence, otherwise timeout/transport policy applies once. Comparators are normative and tested at `T-1s`, `T`, `T+1s`.

Failure observability records admission ID/digest/validation, verifier decision ID/time, marker cross-binding, exact child run/job, authoritative `terminal_at`, persisted deadline/comparator, current-proof versus historical-admission role, winner/outbox and Check mutation. Alert on admission without successful pre-marker verify, missing/mismatch, success using admission, D+1 winner, or winning failure overwrite.

## Authority and trust boundaries

- Personal repos use repository-scoped JIT runners.
- Org repos use organization-owned runner groups restricted to explicitly selected repos after org-admin/App/Actions policy preflight.
- CI runner, reviewer, deploy and control plane have separate identities, credentials, filesystems and permissions.
- Reviewer has no shell, Docker socket, deploy secrets, broad filesystem or unrestricted network tools.
- Deploy credentials never enter PR CI or reviewer.
- No PAT, App key, webhook/model secret, registration token, deploy credential or mutable runtime state is committed.

## WSL/Windows boundary

- Dedicated Windows local service account, non-admin, owns/starts the CI WSL distro and has no interactive use beyond explicit management.
- NTFS ACL proof denies that account access to personal Windows profiles/data and unrelated service secrets; effective-access tests are mandatory.
- Dedicated CI WSL distro config:

```ini
[automount]
enabled=false
mountFsTab=false

[interop]
enabled=false
appendWindowsPath=false
```

- No Windows drives, fstab mounts, Windows binaries/PATH, WSL interop, Docker Desktop socket, personal distro mounts, SSH agent or deploy/reviewer credentials.
- If dedicated account ACLs, distro identity, automount, fstab and interop cannot all be proven, local PR CI fails closed and remains GitHub-hosted; claims are downgraded accurately, never waved through.
- Containers share the WSL kernel; hostile workloads stay GitHub-hosted.

### Network policy

- Management and workload networks/namespaces are separate. Only the management plane may accept SSH/Tailscale administration; runner workloads cannot route to it.
- Workload egress is default-deny and explicitly blocks the Windows host/gateway, Tailscale `100.64.0.0/10`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`), IPv4 link-local/metadata (`169.254/16`, especially `169.254.169.254`), IPv6 ULA/link-local (`fc00::/7`, `fe80::/10`), reviewer/control/deploy services, local sockets, and Docker/container APIs.
- Allowed egress uses an explicit domain/IP-aware proxy/allowlist for only required GitHub API/git/Actions artifact-cache endpoints, approved DNS resolvers, OS package mirrors, npm/PyPI, pinned runtime downloads and Playwright/browser downloads required by the selected repo. DNS rebinding/private resolution fails closed.
- Allowlist changes are reviewed/versioned per repo workload. Proxy logs destination/decision/correlation without credentials or secret-bearing URLs.
- Firewall/proxy policy must load before runner service, persist across WSL/Windows reboot, and be tested after reboot. Failure to install/verify policy prevents runner registration and local dispatch.

## Reviewer contract

Reviewer defaults to **dual/no-public-ingress mode**:

- Reviewer execution is explicitly **BLOCKED** until the operator selects provider, exact model and budget. Planning/provisioning may prepare inert config, but no model secret, webhook activation, PR processing or comments are enabled before the decision record is approved.
- Reviewer provider decisions and review-policy provenance belong to the separate AI-review product and are not configured here.
- Initial hard safety maxima pending that decision: 100 files, 1 MiB unified diff, 50,000 changed lines, 120 s/attempt and 3 total attempts. Cost/token ceilings have no inferred default and must be selected by the operator.

- Default availability path: trusted GitHub-hosted `pull_request_target` reviewer, no PR checkout, pinned reviewer/skill, API-only diff.
- Optional reviewer paths are outside the self-hosted CI product boundary.
- HTTP webhook ACK and queue ACK are distinct:
  - receiver returns HTTP 2xx only after durable enqueue, targeted under 10 seconds;
  - consumer ACKs/deletes the queue item only after GitHub comment/update succeeds **and** durable process/comment state is committed.
- Public receiver must not wait for the laptop/model/GitHub comment before HTTP ACK.
- Delivery key: webhook delivery ID + processing key.
- Processing key: `installation_id:repository_id:pr_number:head_sha:review_policy_version:generation`.
- Comment key: `installation_id:repository_id:pr_number:review_kind`; stable comment ID plus hidden marker.
- Out-of-order events are generation-fenced: only the newest current head/policy generation may post/update; older work becomes stale and ACKs without modifying GitHub after durable stale-state commit.
- Periodic reconciliation of selected open PRs recovers missed webhooks/events.
- Reviewer starts informational; required AI check needs calibration and explicit approval.

## Rollout

1. Prove protocol/API/source/ownership/watchdog in sandbox.
2. Create private `github-automation` repo and schemas/runbooks/tests.
3. Create/prove dedicated Windows account, ACLs, dedicated CI WSL distro and network policy.
4. Run mandatory phase-0 runner-manager bake-off and select/pin one candidate before any real repo can use local CI.
5. Bootstrap `example/repository` PR `ci-gate`; keep `supply-chain` independent and push-main `CI` intact.
6. Validate online, offline, lost-runner, cancellation, stale generation, duplicate prevention, cleanup and rollback.
7. Keep reviewer BLOCKED until provider/model/budget decision; then deploy default no-ingress and add durable public path only after separate ingress approval.
8. Configure deterministic ruleset only after proof; keep AI informational.
9. Onboard additional exact repos only when the operator names them.

## Success/stop criteria

- Non-onboarded repo stays unchanged.
- Execution trust defaults GitHub-hosted. In pilot, local runs only with a valid authority-v1 signature for the exact repo/PR/head/head-generation plus unchanged negative inventory guard; enumeration alone can never qualify and org runner authority never qualifies.
- Local/fallback test exact same deterministic local ort merge and only expected-source `ci-gate` determines routed quality.
- No duplicate/conflicting gate under retries, cancellation, stale SHA/base, lost lease or coordinator failure.
- Offline laptop triggers GitHub fallback and reviewer availability.
- No personal data/secrets/runtime residue.
- Disable restores GitHub first and revokes exact authority.
- Production deploy remains isolated and operational.

Before winner, invalid proof selects GitHub/fences only at dispatch, claim, pre-marker admission or local-success acceptance. A timely functional failure may ignore later proof expiry/revocation/drift only through an authentic matching historical admission. Missing/mismatched admission is `CONTROL_FAILURE`; post-deadline failure is evidence-only/fallback. A committed failure is final and can never become success; if GitHub wins first, later local failure is evidence-only.

## Mandatory runner-manager bake-off

Phase 0 compares only researched upstream candidates before implementation chooses one:

| Candidate | WSL applicability to prove |
|---|---|
| Fireactions | Eligible only if nested KVM/Firecracker, networking and teardown work end-to-end; otherwise mark inapplicable, not preferred by aspiration |
| GARM + Incus | Prove Incus/provider operation, JIT repo/org authority, one-job disposal and WSL compatibility without weakening network/filesystem boundary |
| `myoung34/docker-github-actions-runner` | Prove maintained/pinnable image, ephemeral/JIT behavior, rootless/no-socket operation, cleanup and required repo/org authority |

Normative criteria: upstream maintenance/release/security posture; license; immutable tag+digest/signature/SBOM provenance; WSL compatibility; personal JIT and org runner-group support; one-job lifecycle; normal/force cancel cleanup; rootless/no host socket; network-policy compatibility; observability; reboot recovery; resource use on 4C/16 GiB; upgrade/rollback. Prefer maintained upstream and minimal overlay; no bespoke scheduler.

Required evidence: `evidence/runner-manager-bakeoff-v1.md`, machine-readable `evidence/runner-manager-bakeoff-v1.json`, logs for every criterion, selected version/tag/digest, rejected-candidate rationale, threat/rollback note and independent verifier sign-off. No real repo—including the selected pilot repository—may be allowlisted until one candidate passes, is pinned by digest and the evidence gate is approved. If none passes, remain GitHub-hosted.

The JSON is normative under `runner_bakeoff_schema_version:1` and `selection_policy_version:1`:

```json
{
  "candidate_id": "fireactions|garm-incus|myoung34",
  "version": "...",
  "image_digest": "sha256:...",
  "evidence_digest": "sha256:...",
  "criteria": [
    {"id":"...","class":"hard_gate|scoped_capability|advisory","status":"pass|fail|not_applicable","evidence":["..."]}
  ],
  "rootful": false,
  "risk_acceptance_id": null,
  "eligible": true,
  "scoped_score": 0
}
```

- No hidden waiver fields exist. Every `hard_gate` must be `pass`; `fail` or `not_applicable` makes the candidate ineligible.
- Hard gates: immutable version+digest and verifiable provenance; true JIT one-job disposal; cleanup after success/failure/cancel/force-cancel/reboot; no host/container socket exposure; no network-policy bypass; resolved WSL compatibility; personal or scoped-org authority needed by the target; and maintenance/security threshold.
- Maintenance threshold: upstream is not archived, selected version is supported, and a release/maintenance/security response exists within the preceding 12 months. Security threshold: no known unmitigated Critical vulnerability and no selected-artifact High vulnerability older than 30 days without an upstream-fixed pinned version. Failure is ineligible.
- Rootful operation never waives a hard gate. A rootful candidate is additionally ineligible unless the operator explicitly approves versioned `decisions/rootful-runner-risk-v1.yaml` naming candidate, exact repo scope, mitigations, expiry and revocation. Without it, rootful yields none-pass.
- Versioned scoped-capability weights: rootless 30, personal JIT 20, org restricted groups 15, 4C/16-GiB fit 15, observability 10, reboot recovery 10. Advisory findings do not affect eligibility or score.
- Deterministic selection: filter eligible candidates; choose highest scoped score; ties resolve by lexicographically smallest stable `candidate_id`. Record all inputs and selected ID. If none are eligible, result is `none-pass` and GitHub-hosted remains active.

## Decision boundaries

The operator explicitly approves each org/repo, public ingress, production/deploy migration, AI required check, and destructive host/data migration. Low-risk reversible provisioning, compatible pins, tests, observability and rollback details may proceed within this specification.

Each local execution is separately authorized by the trusted agent following the operator's explicit same-thread request for one resolvable repo+PR current head, followed by authority-v1 signing. This is a procedural TCB rule and audit obligation, not a claim that cryptography proves the conversation. Repository onboarding, an earlier attestation or an instruction about future PRs is not standing execution approval.
