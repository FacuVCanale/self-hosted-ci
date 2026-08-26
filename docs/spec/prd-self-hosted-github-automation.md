# PRD — Self-hosted GitHub Automation

Status: **APPROVAL-READY Ralplan draft**, revised after Architect review; awaiting Critic lifecycle review.

Canonical requirements: `docs/spec/spec-self-hosted-github-automation.md`
Normative verification: `docs/spec/test-spec-self-hosted-github-automation.md`

## Outcome

Create private repo `self-hosted-ci` and a reversible platform that keeps GitHub-hosted CI as default, opts one exact personal/org `owner/repo` into local WSL2 CI, falls back automatically, adds one unambiguous required PR gate `ci-gate`, reviews selected PRs with PR-Agent plus thermo-nuclear, and pilots on a selected repository without taking ownership of that consumer's deploy or push-main workflows.

## Non-negotiable invariants

1. The privileged PR coordinator uses trusted base/default-branch code through `pull_request_target` and **never checks out, imports, sources, evaluates, or executes PR-controlled content**.
2. Coordinator and child exchange a versioned protocol package; unknown/missing fields fail closed.
3. Local and fallback test the same immutable `tested_sha`.
4. For PRs, `ci-gate` is attached to `check_target_sha=tested_merge_sha`, the exact synthetic merge actually tested; the logical key remains head-based while each generation binds base+merge.
5. Child workflow definition is dispatched from the current trusted default branch, receives `tested_sha`, and validates SHAs before/after checkout.
6. Child attempts lack `checks:write`; a dedicated private `ci-gate` GitHub App is the sole custom-check writer and fixed ruleset expected source. The Action coordinator may orchestrate only through a short-lived installation token for that App.
7. Pushes to `main` remain a separate, unprivileged, GitHub-hosted `CI` workflow.
8. Same-SHA coordinators serialize; only the current generation owner may dispatch, select a winner, or conclude.
9. A GitHub-side watchdog/reconciler repairs orphan coordinators and missed events without depending on the laptop.
10. Fork, Dependabot, and external-contributor code never runs locally in the initial platform.
11. Execution trust defaults GitHub-hosted and is proven for the exact head independently from runner/repository authority; privacy, authorship, collaborator/member labels and org membership never imply trust.

## RALPLAN-DR

### Principles

1. GitHub-hosted is canonical; local is an optimization.
2. Exact allowlists and least privilege; no org wildcards.
3. One generation owner and pinned App source conclude `ci-gate`.
4. Reviewer, CI, deploy, and control plane have separate identities and boundaries.
5. AI review is observed/calibrated before enforcement.

### Top drivers

1. Availability while Windows/WSL/laptop is offline.
2. Isolation from personal Windows data and production credentials.
3. Idempotent, auditable, reversible per-repo operations.

### Options

**A. GitHub-hosted Action coordinator — selected pilot.** Base-branch coordinator owns `ci-gate`, dispatches a default-branch child, applies the formal claim predicate and fallback. Pros: available while laptop is off; no new CI server. Cons: GitHub minutes; Check/Actions ownership needs proof and watchdog.

**B. Worker/Durable Object coordinator — replacement boundary.** Same protocol and `GateStore`, atomic leases/CAS. Pros: durable/event-driven/scalable. Cons: extra service, credentials, cost, operations.

**C. Static dynamic `runs-on` — rejected.** GitHub cannot migrate an already queued job and cannot fence late results.

Decision: A for the bounded pilot, with storage/ownership behind `GateStore` so B can replace it without changing child workflow, protocol, check name, policy, or operator commands.

## Architecture and trust package

```text
PR
└─ pull_request_target coordinator (GitHub-hosted, trusted base workflow)
   ├─ no PR checkout / PR-local action / PR-controlled shell interpolation
   ├─ reads tuple from GitHub API
   ├─ acquires generation ownership
   ├─ creates/updates ci-gate on tested_merge_sha
   ├─ dispatches default-branch child with tested_sha
   └─ observes Jobs API and concludes selected winner

Child, definition from default branch
├─ local: exact repo JIT or exact org runner-group pool
└─ fallback: ubuntu-24.04
   ├─ contents:read only
   ├─ validate tuple/current PR
   ├─ checkout detached tested_sha, persist-credentials:false
   ├─ assert git HEAD == tested_sha
   └─ run canonical quality command

push main
└─ existing GitHub-hosted CI workflow → verify-release.sh remains valid
```

The coordinator must be inline trusted code or a SHA-pinned trusted action. It may not call a local action/script from the PR merge tree, interpolate PR title/body/branch/ref/filename into shell, or download a PR artifact. Its automatic `pull_request_target` workflow/job check must have a distinct name and must not accidentally satisfy `ci-gate`; only the explicit custom Check Run may do so.

The sandbox must also prove that PR-controlled workflow/job/check names, commit status contexts, and Check Runs named `ci-gate` from another App/source cannot satisfy branch protection. `GITHUB_TOKEN` is not an accepted `ci-gate` writer.

### Versioned App authority v1

- Owner/security approver: an operator-designated human identity. Only the reviewed default-branch coordinator/reconciler control-plane identity may mint runtime installation tokens.
- Non-secret record pins App ID/slug, exact per-repo installation IDs, exact selected installations, owner, allowed control workflow/ref, key fingerprint, rotation time and `ci_gate_authority_version:1`.
- Minimum permissions: Metadata read and Checks write. Explicitly deny Contents read/write, Commit statuses write, Actions, Workflows, Administration, PR/Issues write, Deployments, Environments, Secrets, Members and org admin.
- Private key may live in an encrypted Actions secret scoped to the exact trusted control repo/environment or a root-only control-host credential file. No vendor secret store is mandated. Plain git, runner image, child env/cache/log/artifact are forbidden.
- Coordinator creates App JWT and mints a token narrowed to one exact repository and checks-write/required metadata, TTL ≤1 hour, memory-only and masked. Children/reviewer/deploy/runner manager/PR workflows never receive key/token.
- Rotation: add new key, positive check-write and negative contents/status/admin tests, switch fingerprint, revoke old, prove old failure, audit. Compromise: fence, GitHub-only, revoke keys/tokens, suspend/uninstall exact installs, rotate/retest before enable.
- Any authority-record/App/install/repo/permission/fingerprint mismatch is blocking `CONTROL_FAILURE` before check mutation.

## Execution trust policy v1

Runner authority answers “may this repo schedule this pool?”; execution trust separately answers “did the operator explicitly authorize this exact immutable PR head generation through the dedicated signing authority?” One never implies the other.

Default:

```yaml
execution_trust_policy_version: 1
mode: github-hosted
local_eligible: false
on_unknown_or_drift: github-hosted_or_fenced
```

Prohibited inference signals: private repo, PR author, branch owner, same-repo branch, `author_association`, `MEMBER`, `COLLABORATOR`, repository collaborator boolean, generic org membership, team membership alone, or org runner-group access.

### Viability and conservative implementation

GitHub offers useful but fragmented evidence:

- the [collaborators API](https://docs.github.com/en/rest/collaborators/collaborators) returns effective highest user permission, including team/default-role/owner paths for org repos, but does not distinguish the source of the grant;
- [branch protection restriction APIs](https://docs.github.com/en/rest/branches/branch-protection) enumerate users/teams/Apps for protected branches, but push restrictions have account/plan/repository-owner limitations and are organization-only on documented surfaces;
- [ruleset APIs](https://docs.github.com/en/rest/repos/rules) expose bypass actor types such as users, teams, integrations, roles and deploy keys;
- App installations, write deploy keys and privileged workflow token paths require separate APIs/config inspection.

There is no single atomic API proving all effective writers for an arbitrary ref. Cross-endpoint changes can race the inventory. Therefore `enumerated-writers` is disabled as a positive trust mode for the pilot. Inventory remains a negative drift guard only: it can fence a signed generation, but can never make it locally eligible.

The sole positive mode for new local execution and local success is `exact-sha-attestation`, signed by `execution_trust_attestation_authority_version: 1`. If current proof is absent/invalid, GitHub-hosted/fencing applies at the four authority boundaries; only an already-running exact timely failure with authentic historical admission is exempt.

### Immutable writer inventory

- User/bot: numeric user ID + node ID + type; login is display-only.
- Team: org ID + team ID + recursively expanded member-ID snapshot/hash. Team approval without matching member hash is invalid.
- App/integration: App ID + installation ID + exact Contents permission/repo scope.
- Write deploy key: key ID + fingerprint.
- Ruleset/branch bypass: actor type + immutable actor ID; roles/teams expand to effective user IDs or become unknown.
- Privileged Actions workflow: integration ID + workflow/ref/token-permission hash + effective writers of that workflow/ref.
- Collaborators/owners/default-role: complete user-ID list + effective permission.

Inventory classification is mechanical over sorted required sources. Semantic hash is lowercase hex SHA-256 of JCS `{status, required_source_ids, missing_source_ids, normalized_usable_source_records}` containing effective identities/permissions and policy-relevant API/schema semantics only. Exclude `observed_at`, request/latency and transport ETag; audit them separately, so ETag/timestamp-only change with identical semantics keeps the same hash. Freshness policy v1 requires a new authenticated observation age `<=5m` at every gate; stale is freshness failure, not drift. Signed partial may pass; unavailable stays GitHub.

### Exact-SHA attestation authority v1

`execution_trust_attestation_authority_version: 1` is asymmetric. No password/shared secret may enter model context, prompts, `AGENTS.md`, a repository, logs or artifacts.

- Use a dedicated Ed25519 signing key, or a platform-native asymmetric equivalent such as non-exportable Secure Enclave P-256. Keep the private key non-exportable where possible under restrictive macOS Keychain/secure local-store ACL. Pin public key, algorithm, key ID/version and fingerprint in the control plane.
- Install a bounded helper outside repository/model workspaces. Caller supplies exact repo/PR/head and at most `expected_head_generation`; `GateStore` reads authoritative generation internally and helper only compares/rejects mismatch. Caller cannot set signed generation. Helper re-resolves GitHub, generates nonce and cannot sign arbitrary payload/caller nonce.
- The operator explicitly trusts the designated agent as approval actor. Same-thread/exact-target behavior is a procedural TCB obligation, not cryptographically verified by helper/verifier. The agent must invoke only for an explicit same-thread exact target or one unambiguous repo+PR resolved from it; no blanket/repo/branch/future-head approval. Request linkage is non-authoritative audit metadata: forging it cannot authorize without the signing-key signature.
- Audit stores opaque linkage hash/ID, normalized target, helper/key version and outcome—not transcript or secret material.

Detached signature contract:

- `payload` is I-JSON serialized by RFC 8785/JCS, UTF-8, with no duplicate keys/non-finite values and canonical string representations for IDs/generations/timestamps that could lose cross-language precision.
- Signed bytes are `ASCII("github-automation/execution-trust-attestation/v1") || 0x00 || UTF8(JCS(payload))`; signature is detached.
- Fingerprint is lowercase hex SHA-256 over exact DER SPKI.
- Ed25519 signature is raw 64 bytes; P-256 is ECDSA-SHA-256 normalized low-S IEEE-P1363 `r||s` 64 bytes. Both use unpadded base64url. P-256 DER signatures are rejected at verifier input.
- Payload binds schema/policy/authority, issuance manifest generation/digest, exact target/GateStore generation, inventory status+missing set+semantic hash, freshness-policy version, issuance observation timestamp metadata, issued/expiry, nonce and audit linkage. Later gates use fresh observations and compare semantic fields; they do not require the issuance observation itself to remain young.

Verifier requirements:

- helper signs only with a key `active` in the highest accepted manifest at issuance. Verifier authenticates the embedded issuance manifest digest in the predecessor chain to the highest accepted manifest, proves key active at issuance, and applies current-state matrix before checking signature/target/inventory/expiry/nonce;
- atomically consume/bind the nonce at pre-dispatch to the exact local gate generation; repeated verification is idempotent only for that same generation, while reuse elsewhere is replay;
- take `head_generation` solely from `GateStore`, incrementing only on observed transitions. Observed A→B→A invalidates old A; unobserved ABA is indistinguishable from unchanged A but has identical exact content SHA, and consumed nonce-to-local-gate binding prevents reuse across runs;
- Attestation governs local dispatch/JIT, claim, pre-marker admission and local **success** acceptance. Functional failure uses authentic historical admission plus current timely execution evidence; later expiry/revoke/drift is audit-only for failure and never permits success.
- GateStore server time alone decides attestation expiry at dispatch, claim, pre-marker admission and local-success acceptance. Helper, runner, coordinator and request-start clocks are evidence only. The historical-admission failure transaction does not use current proof expiry.

V1 has no individual-attestation revocation list/API: invalidate via short expiry, exact-head/head-generation drift, gate/nonce fence, or signing-key-version revocation. This simpler contract avoids a second revocation authority.

### Offline-root key manifest v1

`execution_trust_key_manifest_version:1` authorizes online signing keys. The security approver holds a separate offline Ed25519 root in a user-presence-gated secure store/hardware facility where available; the agent/helper/control plane cannot use it. Bootstrap explicitly displays/pins SHA-256 of root DER SPKI before generation 1. The manifest is I-JSON/JCS signed over `ASCII("github-automation/execution-trust-key-manifest/v1") || 0x00 || UTF8(JCS(payload))` with detached raw-64 unpadded-base64url Ed25519 signature, and contains strictly monotonic `manifest_generation`, previous digest, root fingerprint and immutable key ID/version entries in `active|retiring|revoked` state.

`manifest_digest` is universally lowercase hex SHA-256 of `ASCII("github-automation/execution-trust-key-manifest/v1") || 0x00 || UTF8(JCS(manifest_payload))`, excluding detached signature/envelope. `previous_manifest_digest`, issuance digest, highest accepted digest, protocol and audit all use this value; hashing the envelope is invalid.

Initial pin and every change require the offline-root signature. Control plane retains highest manifest plus authenticated predecessors needed by unexpired proofs; missing link, rollback/conflict/skip/revocation omission fails. Matrix: active sign/verify yes; retiring sign no/verify only already-issued unexpired with active issuance; revoked/unknown sign/verify no. Current state always wins.

## Versioned protocol package and SHA semantics

```yaml
protocol_version: 1
timing_policy_version: 1
execution_trust_policy_version: 1
repository_id: 123456
repository: owner/repo
event_kind: pull_request
pr_number: 42
generation: 7
owner_run_id: 100200300
owner_run_attempt: 1
head_sha: <pull_request.head.sha>
base_sha: <pull_request.base.sha>
tested_merge_sha: <synthetic merge for this exact head/base>
tested_sha: <tested_merge_sha for PR>
check_target_sha: <tested_merge_sha>
default_branch: main
child_workflow_ref: main
backend: local | github
policy_version: <registry commit SHA>
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
inventory_observed_at: <UTC audit metadata excluded from semantic hash>
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
deadline_claim_at: <UTC>
deadline_execution_at: <UTC>
idempotency_key: <repository_id:pr:head_sha:generation:backend>
```

`backend=local` requires `execution_trust_mode=exact-sha-attestation` and full proof. `backend=github` requires `execution_trust_mode=github-hosted`; attestation fields are null/evidence-only and cannot gate hosted execution or conclusion.

- `head_sha`: visible PR head and stable logical-key component.
- `base_sha`: exact base tip used for the test target.
- `tested_merge_sha`: GitHub synthetic/test merge for the exact head/base pair.
- `tested_sha`: exactly `tested_merge_sha` for PRs.
- `check_target_sha`: exactly `tested_merge_sha` for PRs.

Coordinator fetches and verifies `(head_sha, base_sha, tested_merge_sha)` through GitHub API, then dispatches the child workflow using the trusted default branch as workflow `ref`. Dispatch uses a pinned REST API version plus `return_run_details:true` and must return HTTP 200 with the exact workflow run ID; HTTP 204/no run ID, list-and-guess matching, or an unexpected schema is `PROTOCOL_FAILURE`. Child validation: reject malformed/mismatched protocol; re-query current PR; perform only trusted bootstrap independent of checkout/PR metadata; resolve and checkout exact detached `tested_sha`; assert `git rev-parse HEAD == tested_sha`; invoke a digest-pinned trusted wrapper outside/unwritable from the PR workspace. Immediately before marker persistence the control plane revalidates authority, atomically creates the immutable admission plus cross-bound marker, and only then permits PR-dependent operations including npm/pip install, generated scripts, build, lint, tests, or project tooling. Marker core binds logical key, generation, child run/job, `tested_sha`, lease owner and wrapper version; final marker additionally contains admission ID/digest. PR cannot write/backdate/delete either record. Failure to persist is `CONTROL_FAILURE`: no PR-dependent process starts, fail closed, watchdog repairs, and no inferred fallback. Trusted bootstrap is limited to fixed controller/runtime verification that does not read PR content. Base movement producing a new synthetic merge increments generation and fences the previous `(base_sha,tested_merge_sha)` even when `head_sha` is unchanged.

## Gate ownership/storage interface

```text
acquire(logical_key, generation, owner, ttl) -> acquired|owned|terminal
heartbeat(logical_key, generation, owner, now) -> accepted|fenced
select_github_winner(logical_key, generation, owner, reason) -> accepted|idempotent|fenced
complete_hosted_winner(logical_key, generation, owner, conclusion, evidence) -> accepted|idempotent|fenced|conflict
get(logical_key) -> state
reconcile(logical_key, observed_state) -> action
bindAttestationNonce(attestation_id, nonce_hash, logical_key, generation, expected_head_generation, envelope_digest) -> bound|idempotent|replay|generation_mismatch
create_local_admission_after_pre_marker_verify(logical_key, generation, owner, verifier_decision_id, marker_core_digest) -> admitted|idempotent|fenced|invalid_authority|conflict
complete_local_success_if_authorized(logical_key, generation, owner, evidence_id, evidence_digest, attestation_ref, success_result) -> committed|idempotent|fenced|expired|conflict
complete_local_failure_if_current(logical_key, generation, owner, evidence_id, evidence_digest, admission_id, admission_digest, child_run_id, child_job_id, marker_digest, tested_merge_sha, command_digest, terminal_at, failure_result) -> committed|idempotent|fenced|late|control_failure|conflict
```

`bindAttestationNonce` reads authoritative head generation internally; caller expectation only compares. It atomically creates the first binding; exact retry is idempotent; different tuple is replay/conflict. Protocol metadata alone never establishes authority.

`create_local_admission_after_pre_marker_verify` exists only on a successful pre-marker verifier decision. GateStore creates an immutable `local_admission_record` binding attestation ID/envelope digest, nonce binding, policy/authority/manifest/key versions and digests, head/gate generation, exact child run/job, tested merge, owner/lease epoch, verifier decision ID/time, persisted execution deadline and `started_test_marker_digest`. That digest covers marker core excluding admission ID/digest; final marker adds returned admission ID/digest, avoiding circular hashing. Admission+marker persist atomically before PR-dependent work.

`complete_local_success_if_authorized` is the prior GateStore-clocked atomic success path: valid attestation at linearization, then local winner+success evidence+outbox.

`complete_local_failure_if_current` requires no still-valid current attestation, but resolves authentic GateStore admission/marker and authoritative exact-job terminal observation; caller admission fields and `terminal_at` are expectation-only. It atomically validates admission/marker, owner/lease/generation, child run/job, tested merge/command, `terminal_at <= persisted execution_deadline`, terminal functional failure and no winner, then writes local failure/evidence/outbox. Missing/mismatch is no-winner `CONTROL_FAILURE`; `terminal_at>D` is evidence-only/fallback. Success-shaped evidence rejects; same evidence is idempotent and different evidence conflicts.

Logical key: `repository_id + pr_number + head_sha + ci-gate`. Generation identity additionally binds `base_sha + tested_merge_sha + monotonic generation`. Same head with a refreshed base/merge is therefore a new generation under the same logical key.

Pilot provider:

- Actions `concurrency` serializes the same key with `cancel-in-progress:false`.
- `ci-gate` stores generation, owner run/attempt, heartbeat, state, winner, protocol/policy version and evidence links.
- Owner is re-read before every external side effect: dispatch, cancel, force-cancel, fallback selection, check update, queue ACK, and comment mutation. A fenced/lost-lease owner produces no external effect.
- Terminal valid gates make duplicate deliveries no-op; explicit rerun creates the next serialized generation.
- Older/fenced generations cannot update current ownership.
- No local Check update occurs before a committed local completion record. Transactional outbox delivery targets the pre-existing exact Check Run ID using dedicated-App credentials and `logical:generation:winner:evidence_digest`. On ambiguous response, read that Check Run and compare its embedded evidence marker before retry. Repeated PATCH may occur, but at most one logical conclusion/mutation exists; different evidence is conflict.

The sandbox must prove GitHub Check update/branch-protection semantics. If they cannot satisfy ownership without ambiguity, required-check rollout is blocked until an atomic provider (preferred Worker/Durable Object) implements `GateStore`; guarantees are not weakened.

## State machine, formal claim, and failure taxonomy

```text
ROUTING → LOCAL_DISPATCHED
LOCAL_DISPATCHED ─formal claim≤10m→ LOCAL_RUNNING
LOCAL_DISPATCHED ─no claim────────→ FALLBACK_SELECTED
LOCAL_RUNNING ─success + `complete_local_success_if_authorized`──→ winner=local success + outbox
LOCAL_RUNNING ─timely admitted functional failure + `complete_local_failure_if_current`──→ winner=local failure + outbox
LOCAL_RUNNING ─missing/mismatched admission─────────────────────────────→ CONTROL_FAILURE, no winner/check
LOCAL_RUNNING ─functional failure terminal_at>D────────────────────────→ evidence-only + FALLBACK_SELECTED
LOCAL_RUNNING ─infra loss/timeout─→ FALLBACK_SELECTED
LOCAL_* ─attestation invalid at dispatch/claim/pre-marker/local-success→ FALLBACK_SELECTED/fenced exactly once; historical admitted timely failure is the sole exception
FALLBACK_SELECTED: persist immutable winner=github; normal-cancel local; bounded wait; force-cancel if still active; dispatch/resume fallback
GITHUB_RUNNING ─valid hosted-winner predicate→ FINAL_SUCCESS|FINAL_FAILURE
Any state ─tuple stale────────────→ STALE (never approve)
```

Once `winner=github` is atomic and immutable, local is fenced/cancelled and every late local result is evidence-only. Subsequent attestation expiry, key revocation, manifest or inventory drift is audited but cannot block a valid hosted result.

Hosted-winner conclusion predicate requires all: immutable `winner=github`; current owner/lease; same logical key, generation and current PR tuple; `tested_sha=check_target_sha=tested_merge_sha`; canonical command/workflow; exact trustworthy GitHub-hosted child run/job and terminal result within persisted hosted deadline; and dedicated `ci-gate` App authority. No attestation predicate is evaluated.

`complete_hosted_winner` validates that predicate and atomically persists hosted terminal evidence plus the same-form outbox event. Same evidence retry is idempotent; different evidence conflicts. Neither backend writes `ci-gate` outside the outbox.

Success and GitHub share the prior expiry race. A timely admitted functional failure and GitHub/timeout also share the winner: failure linearized first is final failure even if the current attestation expired/revoked/drifted; GitHub linearized first makes later failure evidence-only. Before timeout selection, authoritative exact-job state is reread so an already-visible `terminal_at<=deadline` failure is offered first. A `terminal_at>D` failure never wins. No path converts functional failure to success.

Local is claimed iff all are true:

1. Pinned-version dispatch with `return_run_details:true` returned HTTP 200 and the exact child run ID; that run matches workflow ID, repository, trusted default-branch ref, generation, and local backend. Run-list correlation is forbidden.
2. Jobs API returns exactly one expected execution job.
3. Job `started_at` is non-null and status is `in_progress|completed`.
4. `started_at <= deadline_claim_at` by GitHub API timestamp.
5. Labels include the exact approved repo pool or org runner-group pool.
6. Runner identity matches the fresh ephemeral allocation and has not served a prior job.
7. Generation ownership and PR tuple still match.

Run creation, `queued`, runner `online`, or labels alone are not claim.

| Failure class | Examples | Outcome |
|---|---|---|
| `FUNCTIONAL_FAILURE` | authoritative exact admitted child/run/job canonical command nonzero after cross-bound marker on same tested merge, `terminal_at<=persisted deadline` | atomic local failure if current/no winner; later proof state audit-only; post-deadline evidence-only/fallback; never success after it wins |
| `STALE_INPUT` | head/base/merge/generation changed | stale/cancel, never approve |
| `INFRA_PRETEST` | trusted-wrapper/API dispatch, claim, platform or fixed bootstrap failure before checkout-dependent work/`started_test_at` | fallback once |
| `INFRA_TRANSPORT_LOSS` | GitHub-observed runner disappearance/platform cancel/hard timeout without trustworthy functional result | fallback once |
| `PROTOCOL_FAILURE` | malformed package, wrong ref/source/API version/status/schema, ambiguous/mismatched child or SHA | fail closed/alert; no inferred success |
| `CONTROL_FAILURE` | fenced owner, coordinator/API uncertainty, missing/forged/mismatched admission or marker cross-binding | blocking with no winner/check; watchdog repairs or blocks |
| `FALLBACK_FAILURE` | GitHub attempt fails/times out | final failure |

Generic child `failure` after `started_test_at` is functional by default. Only trusted wrapper/GitHub API evidence may establish pre-test infrastructure or transport loss; PR code cannot self-label failure as infrastructure.

Cancellation is two-stage and resumable: request normal cancel, wait a bounded grace period, request force-cancel if the exact child is still active, then continue the already-persisted fallback decision. The watchdog may resume at any stage idempotently.

## Normative timing policy v1

| Parameter | Initial value | Reason |
|---|---:|---|
| Heartbeat | 60 s | Fast detection without excessive writes |
| Lease TTL | 5 min | Five missed heartbeats; tolerates short API stalls |
| Watchdog interval | 5 min | Practical scheduled-Actions floor; event trigger may be faster |
| API tolerance | 2 min | Bounded propagation/rate-limit allowance |
| Inventory observation freshness | 5 min | Re-observe at every trust gate; classify stale separately from drift |
| Claim deadline | 10 min | User-selected offline fallback threshold |
| Execution deadline | 40 min per backend | Existing 35-minute quality timeout plus margin |
| Normal cancel grace | 90 s | Cooperative cleanup |
| Force-cancel verify/reconcile | 2 min | Confirm exact run state; resumable by watchdog |
| Dispatch/API retries | 3 total: 2 s, 8 s, 32 s | Bounded transient retry; protocol errors fail closed |
| Poll | 15 s→30 s cap+jitter | Timely claim with bounded API load |
| Reviewer model timeout/retries | ≤120 s; 3 total at 30 s/2 min | Hard safety ceiling pending provider decision |
| Reviewer queue alert/max age | 10 min / 24 h | Detect outage; then DLQ/block and reconcile |
| Reviewer DLQ retention | 7 d; immediate alert | Bounded incident/replay evidence |
| Pre-claim fallback dispatch SLA | ≤12 min | Claim deadline + API tolerance |
| Total fallback gate SLA | ≤100 min worst case | 40-minute local loss + cancellation/reconcile + 40-minute fallback + API tolerance |

`timing_policy_version:1` is carried in protocol/evidence. Changes require version bump and boundary tests. Breach blocks/alerts; never success.

### Timing oracle/comparator contract

- Absolute deadlines are persisted at causal transitions: dispatch→claim deadline; atomic admission/marker→execution deadline; GateStore acquire/heartbeat→lease expiry; cancel request→force-cancel eligibility; durable enqueue→reviewer ages.
- Authoritative clocks: GitHub API for run/job `terminal_at`; GateStore server clock for lease/winner/admission/start/cancel and attestation expiry at dispatch/claim/pre-marker-admission/local-success acceptance; queue clock for ACK. Helper/runner/coordinator/request clocks never decide thresholds. Historical-admission failure ignores current proof expiry but still linearizes against GateStore winner state.
- Claim accepted iff `started_at <= claim_deadline`; timeout only when `now > claim_deadline` and no timely claim.
- Lease valid iff `now < lease_expires_at`; `now >= lease_expires_at` fences before side effects.
- Completion wins iff authoritative GitHub API `terminal_at <= persisted execution_deadline`; timeout only when `now > execution_deadline` and no timely completion. Equality favors completion; `terminal_at>D` is evidence-only and selects/resumes fallback. Timeout selection rereads exact-job terminal state under lease and offers any already-visible timely admitted failure first; after atomic winner selection, late competing evidence cannot overturn it.
- Force-cancel eligible at `now >= cancel_requested_at+90s` while exact run active. Queue alert/DLQ uses `age >= threshold`. HTTP ACK target requires durable enqueue and duration `<10s`.
- Racing completion/timeout requires authoritative re-read under current lease; timely completion has precedence. Test all at `T-1s/T/T+1s`.
- Local-vs-GitHub winner race is decided only by GateStore transaction linearization. Attestation `now<expiry` is evaluated inside the local-success transaction, not at request creation; the local-failure transaction instead evaluates its exact current-execution predicate at that same linearization point.

## Watchdog/reconciler

A GitHub-hosted scheduled and/or `workflow_run` reconciler defined on trusted default code:

- finds in-progress `ci-gate` heartbeats older than TTL;
- validates owner run/generation and current tuple;
- fences stale ownership through `GateStore`;
- cancels exact orphan children;
- resumes an already-selected fallback or starts one recovery generation;
- marks unrecoverable control/protocol failures blocking, never successful;
- reconciles registry, expected App source, children, checks, and current PRs;
- before GitHub winner, validates attestation only at dispatch, claim, pre-marker admission and local-success acceptance and selects fallback/fences once on failure; preserves authentic historical admission for failure-only verification; after immutable `winner=github`, records later attestation/key/inventory drift audit-only and applies the hosted-winner predicate without attestation dependency;
- writes an audit artifact per repair.

Duplicate reconciler deliveries are idempotent. This runs off-laptop.

## Required checks and push-main compatibility

- Only newly added required gate: `ci-gate`.
- Fixed expected source: dedicated private `ci-gate` GitHub App ID, created for this platform and pinned in ruleset/evidence. The Action coordinator authenticates as this App for custom-check writes.
- Children cannot write checks; attempts have unique non-required names.
- Existing deterministic `supply-chain` remains required.
- Intended PR `quality` requirement is replaced by `ci-gate` only after proof; `quality` is not reused as cross-backend authority.
- A future Worker/DO coordinator reuses the same dedicated App/source where possible; any App source change requires explicit ruleset migration/rollback and operator approval.
- `pull_request_target` is PR-only. Push `main` continues the GitHub-hosted workflow named `CI`, including canonical `make test` and auxiliary release confidence. A coordinator success never substitutes main-commit CI.

### PR synchronize contract

On `opened`, `reopened`, `ready_for_review`, and especially `synchronize`:

- coordinator resolves the current head/base/synthetic-merge tuple;
- same head plus a changed base/merge increments generation under the same logical key;
- `ci-gate` routes only the canonical quality workload across local/fallback and targets the current synthetic merge;
- `supply-chain` runs independently in the ordinary unprivileged GitHub-hosted PR workflow;
- no native coordinator check, attempt check, old-generation gate, or push-main `CI` run may substitute either required PR result;
- Dependabot/fork/external contributor events select GitHub-hosted without requesting local authority.

## Registry and authority paths

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

Absence means GitHub/reviewer disabled; schema rejects wildcards.

- Personal repo: repository-scoped JIT registration, one allocation/job, exact installation.
- Org repo: org-admin preflight, org-owned runner group restricted to named repos, never personal registration or all-org group access.

Authority preflight proves actor/installation, repo admin, org runner admin where applicable, exact App and runner-group repo selection, Actions/self-hosted policy, trusted workflow/ref, expected check source, and registry/effective-state equality. This only authorizes runner scheduling; execution-trust proof is an additional independent gate. Otherwise fail closed.

## WSL boundary

Pilot requires a **dedicated CI WSL distro** owned/started by a dedicated non-admin Windows service account plus a dedicated Linux account/runtime, not a personal Linux distro. NTFS effective-access tests must prove that Windows account cannot read personal profiles/data or unrelated service secrets.

```ini
[automount]
enabled=false
mountFsTab=false
[interop]
enabled=false
appendWindowsPath=false
```

No `/mnt/c`, `/mnt/d`, fstab Windows mounts, Windows PATH/interop, Docker Desktop socket, personal distro mounts, deploy/reviewer secrets. Use Linux filesystem, one-job containers, rootless engine where compatible, CPU/memory/PID/capability limits and explicit SSH/Tailscale management.

If dedicated Windows account/ACL, distro identity, `automount`, `mountFsTab`, or interop cannot be proven, isolation is accurately downgraded to best-effort process isolation, which is **insufficient to enable local PR CI** absent explicit risk acceptance or a stronger VM/host. Containers still share the WSL kernel; hostile workloads remain GitHub-hosted.

### Network policy

- Separate management and workload namespaces/accounts. Only management accepts explicit SSH/Tailscale administration; workloads cannot route to management.
- Workload egress is default-deny and blocks Windows host/gateway, Tailscale `100.64.0.0/10`, RFC1918 `10/8`, `172.16/12`, `192.168/16`, IPv4 link-local/metadata `169.254/16` including `169.254.169.254`, IPv6 ULA/link-local `fc00::/7` and `fe80::/10`, reviewer/control/deploy endpoints, local service sockets and container APIs.
- Egress is only through a reviewed domain/IP-aware proxy/allowlist for required GitHub API/git/Actions artifacts/cache, approved DNS, OS mirrors, npm/PyPI, pinned runtimes and Playwright/browser downloads. Private/rebound DNS resolution fails closed.
- Allowlist is versioned per workload; proxy logs decision/destination/correlation without credentials or secret-bearing URLs.
- Firewall/proxy must load before runner registration, survive Windows/WSL reboot and pass post-reboot tests. Missing/unverifiable policy blocks local dispatch.

## PR-Agent durability and idempotency

Status: **BLOCKED pending an operator decision on provider, exact model and budget.** Provisioning may prepare inert templates, but no model secret, webhook activation, processing or PR comment is enabled before an approved versioned decision record exists.

Required `decisions/reviewer-provider-v1.yaml` fields: provider; exact model/version; per-PR and monthly cost ceilings; input/output/token ceilings; timeout ≤120 s; retry/backoff; max files/diff bytes/changed lines and oversize behavior; secret owner/storage/rotation; provider retention/residency; thermo-nuclear skill source URL, source commit, SHA-256 and policy version. Hard platform maxima are 100 files, 1 MiB unified diff, 50,000 changed lines, 120 s/attempt and three total attempts. Cost/token ceilings have no inferred default and must be selected by the operator.

After that decision, two modes exist:

1. **Durable self-hosted**, only after explicit public-ingress approval: GitHub App webhook → narrow public receiver → signature/timestamp/replay validation → durable Queue/DO → WSL PR-Agent worker → comment. Receiver returns HTTP 2xx only after durable enqueue, targeted under 10 seconds; it does not wait for laptop/model/comment. Consumer queue ACK/delete occurs only after GitHub comment/update succeeds and durable process/comment state commits. Laptop outage retains queued work; bounded retry/dead-letter applies.
2. **No-public-ingress default:** trusted GitHub-hosted `pull_request_target` reviewer, no PR checkout, pinned PR-Agent/review wrapper and API-only diff. This is the availability fallback, not described as self-hosted.

Keys:

- delivery: webhook delivery ID + process key;
- process: `installation_id:repository_id:pr_number:head_sha:review_policy_version:generation`;
- comment: `installation_id:repository_id:pr_number:review_kind`, persisted comment ID + hidden marker.

Only current process-lease/generation owner posts/updates. New SHA updates the same marked comment. Out-of-order older generation becomes stale and ACKs only after durable stale-state commit, without mutating GitHub. Periodic selected-open-PR reconciliation repairs missed webhook/event state. Reviewer defaults to the no-public-ingress GitHub-hosted mode and stays informational for ≥20 PRs or ≥30 days, whichever is later, with no shell/socket/deploy secrets/broad filesystem/tools.

## Implementation phases and gates

0. **Protocol/API/trust/host + mandatory runner-manager bake-off:** prove tuple, dedicated App source, negative writer-inventory limits, authority-v1 exact-SHA signing/verification/revocation and four-gate revalidation, ownership, watchdog, mergeability, WSL/Windows/network policy; compare runner candidates. If a valid attestation cannot be proven for a head generation, that run stays GitHub-hosted. If Check ownership fails, choose DO. If no runner manager passes, remain GitHub-hosted.
1. **Private control repo:** registry/schema, authority preflight, protocol schema, `GateStore`, coordinator/child/reconciler templates, runner/reviewer policy, tests, pins, runbooks, secret scanning. Attestation artifacts are `policies/execution-trust-attestation-authority-v1.yaml`, offline-root-signed `policies/execution-trust-key-manifest-v1.json`, `schemas/exact-sha-attestation-v1.schema.json`, `schemas/execution-trust-key-manifest-v1.schema.json`, `schemas/execution-trust-protocol-v1.schema.json`, `runbooks/attestation-key-bootstrap.md`, `runbooks/attestation-key-rotation.md`, `runbooks/attestation-key-compromise.md` and redacted `evidence/execution-trust-attestation-v1/`; root/online private keys and helper installation remain outside every repository/model workspace.
2. **Dedicated WSL CI distro:** dedicated Windows service account and ACL proof; automount/fstab/interop off; dedicated Linux account; default-deny network/proxy; selected pinned runner manager; rootless runtime where viable; JIT one-job containers; cleanup/metrics.
3. **Separate authority/trust paths:** personal repo JIT; org restricted runner groups after admin preflight; independent exact-SHA signing helper/public verifier, GateStore nonce binding, offline-root key manifest and negative inventory drift guard. Runner authority alone never enables local execution.
4. **Sandbox:** implement and pass normative state/race/watchdog scenarios.
5. **the selected pilot repository pilot:** PR `ci-gate`; identical local/fallback child; preserve PR auxiliary checks, separate push-main `CI`, Railway deploy.
6. **Operator controls:** enable order authority→workflow PR→GitHub smoke→allowlist/group→local/fallback smokes. Disable order GitHub first→fence/cancel→smoke→revoke→reconcile.
7. **Reviewer BLOCKED decision gate:** wait for the operator's provider/model/budget record; afterward no-ingress default, durable public ingress only after separate approval, then prove idempotency/reconciliation/provider limits.
8. **Ruleset/calibration:** require pinned-source `ci-gate` plus deterministic checks; AI remains informational pending calibration/approval.

### Phase-0 runner-manager bake-off gate

Candidates are limited to researched upstreams:

- Fireactions: only if nested KVM/Firecracker, networking and teardown work end-to-end in WSL; otherwise explicitly inapplicable.
- GARM+Incus: prove provider/Incus WSL operation, personal/org authority, one-job disposal and boundary compatibility.
- `myoung34/docker-github-actions-runner`: prove maintenance/pinning, ephemeral JIT, rootless/no-socket operation, cleanup and repo/org authority.

Criteria: maintenance/security/release posture; license; immutable version/tag/digest/signature/SBOM; WSL applicability; personal JIT and org restricted-group support; one job; cancel/force-cancel cleanup; rootless/no host socket; network-policy compatibility; observability; reboot recovery; 4C/16 GiB resource profile; upgrade/rollback. Prefer maintained upstream and minimal overlay; no bespoke scheduler.

Required evidence: `evidence/runner-manager-bakeoff-v1.md`, `evidence/runner-manager-bakeoff-v1.json`, per-criterion logs, selected tag/digest, rejection rationale, threat/rollback note, independent verifier sign-off. No real repo is allowlisted until this is approved and the image is digest-pinned.

The JSON decision is deterministic under `runner_bakeoff_schema_version:1` and `selection_policy_version:1`. Each criterion has exactly `class=hard_gate|scoped_capability|advisory`, `status=pass|fail|not_applicable`, and evidence refs; there are no waiver fields.

Hard gates all must pass: immutable pin/provenance; JIT one-job disposal; cleanup across every terminal/reboot mode; no host/container socket; no network bypass; resolved WSL compatibility; target authority capability; maintenance/security threshold. `fail` or `not_applicable` is ineligible. Maintenance means non-archived, supported selected version and release/maintenance/security response within 12 months. Security means no known unmitigated Critical and no selected-artifact High older than 30 days without an upstream-fixed pin.

Rootful never waives hard gates and is ineligible unless the operator approves `decisions/rootful-runner-risk-v1.yaml` with candidate, exact repos, mitigations, expiry and revocation; otherwise the result may be none-pass.

Scoped weights v1: rootless 30, personal JIT 20, org restricted groups 15, 4C/16-GiB fit 15, observability 10, reboot recovery 10. Advisory findings do not score. Select highest score among eligible; lexicographically smallest stable candidate ID breaks ties. If none eligible, emit `none-pass` and stay GitHub-hosted.

## Acceptance criteria

1. Unregistered repos remain GitHub-hosted; no wildcard org access.
2. Personal uses exact JIT; org uses exact restricted group after authority proof.
3. Coordinator runs `pull_request_target` without PR checkout/execution.
4. Package and child validate logical head key, base+merge generation, tested SHA, and `check_target_sha=tested_merge_sha` semantics.
5. Local/fallback execute identical `tested_sha` and command.
6. Formal claim requires the HTTP-200 exact run ID returned by pinned-version `return_run_details:true` dispatch plus matching Jobs API `started_at`, labels, identity, generation and tuple.
7. No claim in 10m triggers one fallback.
8. Functional failure never falls back; enumerated infrastructure failure can once.
9. Ownership fences duplicates, reruns, stale coordinators, late attempts.
10. Watchdog repairs/blocks orphan state off-laptop.
11. Only newly added required gate is `ci-gate` from the dedicated private App; same-name workflow/job/check/status collisions and attempts cannot satisfy it.
12. Push-main `CI`, `verify-release.sh`, deterministic checks, and Railway deploy remain valid.
13. Dedicated non-admin Windows account ACL and WSL/network tests cannot reach Windows/personal distro paths, Tailscale/RFC1918/link-local/metadata or reviewer/control/deploy; `mountFsTab=false`; policy survives reboot; otherwise local mode stays disabled.
14. Cleanup removes registration, checkout, workspace, container, credentials.
15. External/fork code never runs locally.
16. Reviewer stays BLOCKED until approved provider/model/budget/provenance decision; afterward it is durable or uses GitHub-hosted no-ingress default.
17. Reviewer HTTP ACK occurs only after durable enqueue under 10 seconds; queue ACK only after GitHub write plus durable state; generation-fenced process/comment writes are idempotent and missed/out-of-order events reconcile.
18. AI remains non-required pending calibration and approval.
19. Disable restores GitHub before revoking local.
20. No real repo uses local CI until one researched runner manager passes the bake-off, is digest-pinned, and has independent evidence; none-pass stays GitHub-hosted.
21. Timing policy v1 passes exact boundary/SLA tests; any heartbeat, lease, watchdog or total-SLA breach blocks and alerts.
22. Dedicated App authority v1 proves exact installs, minimum/negative permissions, coordinator-only ≤1h narrowed minting, no child leakage, and rotation/revocation recovery.
23. Trusted out-of-workspace wrapper performs successful pre-marker verification, then atomically persists immutable admission+control-clocked marker bound to attestation/nonce/policy/manifest/key/head/gate/run/job/tested merge/owner/lease/verifier decision before any PR-dependent process. Marker includes admission ID/digest; missing/mismatch is blocking `CONTROL_FAILURE` with zero winner/check.
24. Bake-off JSON has no hidden waivers and independently reproduces eligibility, weights, tie-break and none-pass; rootful requires the operator's scoped unexpired risk record.
25. Execution trust v1 defaults GitHub-hosted; the pilot's sole positive local-success proof is a valid authority-v1 detached signature for the exact repo/PR/head/GateStore head-generation, bound to one local gate generation and unchanged negative inventory status/hash. `partial` may pass without completeness claim. Dispatch, claim, pre-marker admission and local-success acceptance pass independently; historical admission preserves only timely failure authority.
26. The bounded signer enforces exact target shape and records non-authoritative same-thread linkage for procedural audit; tests never claim it verifies a real conversation. It rejects arbitrary/blanket input, excludes transcript/secrets, enforces 60m-default/90m-max expiry and nonce replay resistance.
27. Offline-root key manifest v1 requires security-approver user presence, monotonic predecessor chain and append-only revocations. Matrix: active sign/verify yes; retiring sign no/verify only chain-proven already-issued unexpired; revoked/unknown sign/verify no. Proof embeds issuance manifest generation/digest; current state always wins. V1 has no per-attestation revocation list.
28. Every component reproduces the same manifest payload digest and rejects envelope/signature hashing or generation/digest mismatch. Inventory semantic hash is invariant across observation time/ETag-only changes; gate freshness `<=5m` is enforced separately and stale data never masquerades as semantic drift.
29. Invalid proof routes GitHub/fences only at dispatch, claim, pre-marker admission and local-success acceptance. Success needs valid proof at linearization; failure instead needs authentic historical admission+marker, current owner/lease/generation, exact child/run/job, tested merge, canonical command and authoritative timely terminal failure. Failure can never become success.
30. Success, timely admitted failure and GitHub/timeout selection compete on one winner; each terminal commit atomically writes evidence+outbox. Failure-first is final failure; GitHub-first makes late failure evidence-only. Post-deadline failure never wins. Stable-key delivery yields at most one logical conclusion.
31. `local_admission_record` exists only after successful pre-marker verification and is immutable/cross-bound to marker. Missing, forged or mismatched admission is `CONTROL_FAILURE` with no winner/outbox/Check; current proof expiry/revocation/drift can preserve only a timely failure, never success.

## Deliberate pre-mortem

### Laptop sleeps; local finishes after fallback
Immutable winner, owner fencing, exact tuple, cancel and late-ignore prevent conflict. Alert `late_local_completion_total`; preserve fallback and auto-disable local on ambiguity.

### Attestation expires while GitHub fallback is running
Cause: short-lived local authority reaches expiry or its key is revoked after `winner=github`. Mitigation: authority separation—winner selection irreversibly fences local; hosted conclusion depends on its own tuple/merge/command/deadline/child/App/lease predicate. Detection: audit `post_github_winner_attestation_change` without changing gate state. Recovery: conclude trustworthy hosted result; investigate local authority separately and never reopen local winner.

### Functional failure races expiry/fallback
Cause: canonical tests fail after admission as the proof expires/revokes/drifts, the execution deadline passes, or GitHub/timeout selection races. Mitigation: immutable admission+marker proves historical authorization; failure transaction validates exact execution and authoritative `terminal_at<=deadline`, then competes on the shared winner. Missing/mismatched admission blocks as `CONTROL_FAILURE`; `terminal_at>D` is evidence-only/fallback. Recovery: timely admitted failure-first remains final; GitHub/timeout-first keeps fallback and marks failure late. Never reinterpret failure as success or erase a failure that already won.

### Coordinator crashes around winner/outbox/Check update
Cause: crash before selection, inside post-select/pre-complete transaction code, after atomic commit before outbox delivery, or after GitHub accepts Check PATCH before response. Mitigation: transaction rollback-or-full-commit, durable outbox, known Check ID, stable evidence key and read-after-ambiguity. Recovery: same evidence idempotent; different conflicts; winner stays fixed and logical conclusion converges once.

### PR reaches personal data/credentials
Dedicated non-admin Windows account and ACL proof, dedicated WSL, automount/fstab/interop off, exact trust, no fork/Dependabot/socket, JIT, cleanup and deploy separation. Canary/effective-access tests detect; restore GitHub-only, revoke/rotate/destroy. Residual shared-kernel risk excludes hostile code.

### Orphan coordinator leaves gate in progress
Lease/heartbeat, same-SHA serialization, TTL and GitHub-hosted watchdog. Detect stale heartbeat/owner; fence, cancel orphan, resume fallback or mark blocking—never guess success.

### Missed reviewer webhook during laptop outage
Use durable receiver/queue with early post-enqueue HTTP ACK or default GitHub-hosted no-ingress mode; reconcile selected open PR heads against generation-aware process/comment state. Recover exactly once under current process lease and fence out-of-order work.

### Reviewer spam/leak/bad judgment
Process/comment idempotency, limits, restricted mode, no tools, redaction, informational calibration. Disable repo/App and roll back pin/config on incident.

### Runner pivots laterally through WSL networking
Cause: dependency install or hostile project script scans the Windows gateway, Tailscale peers, RFC1918 services, metadata, reviewer/control/deploy endpoints, or exploits DNS rebinding. Mitigation: management/workload separation, default-deny egress, explicit proxy allowlist, private/link-local blocks, DNS fail-closed and no local sockets. Detection: denied-flow metrics, proxy decision logs, canary services and reboot-policy test. Recovery: fence runner pool, restore GitHub-only, revoke JIT credentials, inspect Windows/Tailscale/services and do not re-enable until policy evidence passes.

### Runner manager is stale or incompatible after selection
Cause: candidate looks simple but lacks true JIT/ephemeral cleanup, WSL support, current maintenance or safe cancel behavior. Mitigation: mandatory comparable bake-off, digest/SBOM/provenance, none-pass outcome, upgrade/rollback rehearsal and no bespoke scheduler. Detection: orphan registrations/containers, digest drift, upstream security/release alerts, reboot/cancel failures. Recovery: disable pool, restore GitHub-only, roll back pinned candidate or repeat bake-off.

### Reviewer provider outage/quota or budget runaway
Cause: selected provider is unavailable, rate-limited, returns invalid output or exceeds cost/token assumptions. Mitigation: reviewer remains blocked until explicit decision record; hard file/diff/time/retry limits, per-PR/monthly ceilings, informational-only posture and DLQ. Detection: timeout/quota/cost/schema/queue alerts. Recovery: stop processing, preserve/reconcile queue without duplicate comments, rotate/revoke secret if needed, select a new versioned decision before resuming.

### `ci-gate` App key leaks or authority broadens
Cause: key/token reaches child/log/artifact, installation expands, or permissions drift. Mitigation: exact authority record, encrypted/root-only storage, coordinator-only mint, one-repo ≤1h token, explicit negative permissions and canary scans. Detection: App audit/permission/install/fingerprint drift and secret scans. Recovery: fence gates, GitHub-only, revoke keys/tokens, suspend/uninstall, rotate, rerun positive/negative authority suite before enabling.

### Signed head changes or inventory drifts after authorization
Cause: collaborator/bot/App changes the head, a writer is added/removed, or observed A→B→A attempts reuse. Mitigation: exact SHA, GateStore generation, nonce binding, negative guard and four current-authority gates. Detection: target/generation/inventory mismatch. Recovery: dispatch/claim/pre-marker/local-success route/fence; head/generation mismatch invalidates admission too, while inventory/proof drift after authentic admission may preserve only exact timely failure. Fresh execution/success requires fresh signature.

### Attestation key/helper is stolen or abused
Cause: malware obtains signing capability or a caller tries to make the helper sign an arbitrary/blanket payload. Mitigation: non-exportable asymmetric key where possible, restrictive local ACL, helper outside repo/model workspace, exact typed target only, GitHub re-resolution, internally generated nonce, short expiry and no shared secret. Detection: key/helper audit anomalies, unknown request-linkage, invalid target or unexpected issuance. Recovery: immediately revoke key version and all proofs, restore GitHub-only, rotate/pin a new public key and require fresh explicit same-thread requests.

### Attestation replay or wrong-target substitution
Cause: a valid envelope is replayed for another generation/repo/PR/SHA, after expiry, or after key rotation/revocation. Mitigation: exact target/generation, nonce binding and `now < expires_at` at dispatch, claim, pre-marker admission and local-success acceptance; immutable admission cannot be retargeted. Recovery: invalid current proof selects GitHub/fences only at those boundaries. A timely functional failure needs authentic matching historical admission. After GitHub winner, record audit only.

### Key-manifest rollback or root authority unavailable
Cause: attacker restores an older manifest, omits a revoked key, reactivates a retired/revoked version, or the offline-root manifest cannot be verified. Mitigation: security-approver user-presence root signature, strictly monotonic predecessor-linked generation/digest, append-only revoked set and persisted highest accepted generation. Detection: rollback/conflict/skip/omission/root-verifier alerts. Recovery: fail closed to GitHub-hosted, preserve last accepted manifest, perform an offline-root-signed successor ceremony, and never accept a locally edited manifest.

## Execution-trust observability

Observability records `local_result_kind`, admission ID/digest and validation outcome, verifier decision ID/time, current-vs-historical attestation role, exact child run/job, marker/tested-merge/command digests, authoritative `terminal_at`, persisted execution deadline/comparator result, failure source, winner linearization, outbox and Check mutation. Alert on admission creation without successful pre-marker verify, missing/forged/mismatched admission, failure without marker cross-binding, `terminal_at>D` winning, failure path requiring currently valid proof, success using historical admission, or a winning failure being replaced; retain prior two-winner/outbox/logical-mutation alerts.

## Rollback/stop

Per repo: set GitHub first, fence/cancel local, smoke, revoke exact authority, reconcile. Global: disable local dispatch, revoke identities, clean registrations, prove GitHub; never touch deploy. Reviewer: switch to no-ingress or disable, stop/drain ingress/queue, revoke if needed.

Before winner, invalid proof selects GitHub/fences only at dispatch, claim, pre-marker admission or local-success acceptance. A timely admitted functional failure competes through its historical-admission transaction; missing/mismatch is no-winner `CONTROL_FAILURE`, D+1 is evidence-only/fallback. After GitHub winner, proof changes never stop hosted conclusion.

## ADR

**Decision:** Action coordinator pilot with versioned SHA protocol, `GateStore`, default-branch children, dedicated private `ci-gate` App, exact runner authority, and authority-v1 exact-SHA attestations as the sole proof for local dispatch/success. Pre-marker verification atomically creates a durable historical admission; only an authentic matching admission plus timely authoritative execution evidence can conclude local failure after current proof invalidation. Retain separate push-main `CI`, mandatory runner-manager bake-off, isolated WSL and reviewer decision gate.

**Drivers:** laptop availability, deterministic mergeability, personal-data isolation, exact cross-account scope, reviewer durability, release compatibility.

**Alternatives:** enumerated effective writers as positive trust (rejected: fragmented/non-atomic GitHub evidence); shared password/model-context secret (rejected: exportable/replayable secret exposure); unsigned/manual database flag (rejected: forgeable and weak target binding); Worker/DO, static `runs-on`, ARC, Fireactions, GARM/Incus, personal-distro containers, persistent runner, laptop-only webhook reviewer.

**Why:** Action pilot meets offline fallback without another CI server; protocol/`GateStore` permit migration. Asymmetric exact-SHA authorization lets the agent fulfill an explicit user request without learning a reusable secret, while repo/PR/head-generation, nonce and expiry prevent blanket/replay authority. Dedicated WSL avoids overstated isolation. Reviewer split removes laptop-uptime dependency.

**Consequences:** GitHub minutes whenever no fresh valid signature exists; trusted-agent procedure, bounded signer, offline-root ceremony, manifest rollback protection and four-gate verification become security-critical; inventory partiality is honestly tolerated only as a negative guard; App/ownership/status-collision semantics must be proven; org repos need their own authority/group; a bake-off can select no local manager; WSL isn't a hostile sandbox; reviewer/provider and public ingress remain explicit decisions.

**Follow-ups:** implement and independently threat-review the bounded signer/verifier before any local pilot; rehearse key theft/rotation/revocation; measure cost/incidents; migrate GateStore to DO if needed; evaluate VM/microVM; calibrate reviewer; audit pins/App source/groups quarterly.

## Future execution staffing

`architect` owns protocol/GateStore/trust; `dependency-expert` runner/PR-Agent/gh-aw pins; `researcher` official GitHub contracts; `executor` repo/workflows/provisioning/reviewer; `debugger` WSL/rootless runtime; `test-engineer` races/watchdog/E2E; `code-reviewer` privileged workflow/permissions/injection; `verifier` independent acceptance/rollback/source/release; `git-master` reversible PRs; `writer` runbooks.

After valid execution authorization, use `$ultragoal` ledger plus `$team`; sequence protocol sandbox → WSL → authority → coordinator/watchdog → pilot → reviewer → ruleset. `$ralph` only as sequential fallback.
