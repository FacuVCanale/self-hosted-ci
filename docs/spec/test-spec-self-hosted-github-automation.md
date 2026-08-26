# Test specification — Self-hosted GitHub Automation

Status: **APPROVAL-READY**, normative for `prd-self-hosted-github-automation.md`.

The active hosted MVP uses the `local-ort-v1` contract throughout this
document. GitHub merge fields/refs and merge-targeted Checks are not protocol
inputs or authorities.

## Proof sequence

1. Prove protocol, canonical head/base tuple, head-targeted Check source, default-branch dispatch, and local ort merge behavior in a disposable public sandbox.
2. Prove generation ownership, same-SHA serialization, formal claim, failure taxonomy, watchdog, and reconciliation.
3. Prove dedicated WSL distro isolation and one-job cleanup without production credentials.
4. Prove personal-repo JIT and organization runner-group authority separately.
5. Prove online local and offline/lost-runner fallback.
6. Pilot the selected pilot repository without ruleset change; preserve push-main `CI` and deploy verification.
7. Require `ci-gate` only after source/race evidence passes.
8. Add reviewer informatively; prove delivery, idempotency, allowlist, missed-event recovery, and prompt-injection boundaries.

## Protocol assertions

Every PR attempt proves:

```text
check_target_sha == server-canonical head_sha
logical_key binds head_sha; generation binds base_sha + merge_policy_version(local-ort-v1)
quality fetches refs/pull/<PR>/head separately and verifies exact head_sha
quality starts at exact base_sha and requires merge_base(base_sha, head_sha)
tested_tree_sha == tree(git merge -s ort --no-ff --no-commit head_sha)
local_commit_sha has exact parents [base_sha, head_sha], tested_tree_sha, fixed identity and fixed time
successful transition re-resolves the current head/base snapshot before CAS
head/base drift cannot conclude success; historical failure remains deliverable
dispatch ref == current trusted default branch
quality git HEAD == recorded local_commit_sha
child repository/pr/generation/backend == coordinator package
ci-gate source == dedicated ci-gate App ID
dispatch uses GitHub REST 2026-03-10 + HTTP 200 exact workflow_run_id/run_url/html_url receipt
execution_trust_policy_version == 1
execution_trust_attestation_authority_version == 1
execution_trust_key_manifest_version == 1
local success requires valid signed exact repo/PR/head/head-generation proof at pre-dispatch + pre-claim + pre-marker admission + local-success acceptance
effective-writer inventory is a negative drift guard, never positive authorization
request linkage is procedural audit metadata, never a cryptographic authorization predicate
all components use manifest_digest = lowercase_hex(SHA256(domain || 0x00 || UTF8(JCS(manifest_payload)))) excluding detached signature
inventory semantic hash excludes observed_at and transport ETag; freshness is checked separately under policy v1
attestation authorizes only local dispatch/claim/pre-marker admission/success; local functional failure requires authentic historical admission plus timely current execution evidence; immutable github winner uses independent hosted conclusion predicate
fallback protocol carries backend=github + execution_trust_mode=github-hosted
local success Check mutation requires committed complete_local_success_if_authorized; local failure Check mutation requires committed complete_local_failure_if_current; hosted Check mutation requires committed hosted completion; all require transactional outbox
local and GitHub winner selection share one GateStore linearization point
```

Coordinator evidence proves no PR checkout, PR-local action/script, PR artifact execution, or PR-controlled shell interpolation.

## Required scenarios

| ID | Scenario | Required result/evidence |
|---|---|---|
| S01 | Repo absent from registry | No local dispatch/App access; GitHub-hosted unchanged |
| S02 | Personal trusted repo, runner online | Repo-scoped JIT; one local child; exact canonical base/head and recorded local artifact; gate reflects local |
| S03 | Authorized org repo | Exact restricted org runner group; local child allowed |
| S04 | Org lacks admin/App/group authority | Preflight fails closed; GitHub path remains |
| S05 | Runner offline for 10m | Formal claim false; persist winner GitHub; one fallback |
| S06 | Run queued but job `started_at` null | Not claimed; fallback at deadline |
| S07 | Correct labels, wrong runner/allocation | Not claimed; protocol/control alert |
| S08 | Local canonical tests fail after `started_test_at` | Functional failure; gate fails; no fallback |
| S09 | Runner lost after formal claim | Infra post-claim; fallback exactly once |
| S10 | Late local success after fallback | `late_ignored`; gate/winner unchanged |
| S11 | Late local failure after fallback | `late_ignored`; fallback result unchanged |
| S12 | New head SHA during attempt | Old is stale; only new tuple/generation can pass |
| S13 | Base changes with same head | Old generation cannot satisfy gate; a new canonical base and local artifact are required |
| S14 | Wrong/unavailable canonical head or base | Reject before quality; never substitute an event-supplied merge SHA |
| S15 | Child dispatch uses PR/non-default ref | Reject and block |
| S16 | Final local HEAD/tree/parents differ from recorded local artifact | Stop before quality; never success |
| S17 | Duplicate synchronize/event delivery | One logical owned generation; duplicate no-op |
| S18 | Manual same-SHA rerun while active | Serialized; no concurrent owner; bounded generation |
| S19 | Coordinator dies after creating gate | Heartbeat TTL; watchdog fences/recovers or blocks within SLA |
| S20 | Coordinator dies after local dispatch | Watchdog finds exact child; at most one fallback |
| S21 | Dies after winner=fallback, before dispatch | Reconciler dispatches fallback exactly once |
| S22 | Multiple/ambiguous matching child runs | Protocol failure; no inferred result |
| S23 | Fenced coordinator updates gate | GateStore rejects; current generation unchanged |
| S24 | Fallback functionally fails | Final gate failure; late local ignored |
| S25 | Fork/external contributor | GitHub-hosted direct; no local registration/access |
| S26 | Disable during queued/running work | GitHub first; fence/cancel; smoke before revoke |
| S27 | Cleanup success/fail/cancel/timeout | No registration/workspace/token/container/allocation |
| S28 | Windows/WSL reboot/offline | Coordinator/watchdog/fallback work; local recovers safely |
| S29 | Dedicated WSL automount/interop enabled | Preflight blocks local; guarantee downgraded explicitly |
| S30 | Probe Windows/personal/reviewer/deploy paths | Access denied; any access blocks release |
| S31 | Wrong App/source writes `ci-gate` | Does not satisfy pinned-source ruleset; alert |
| S32 | Child tries to write `ci-gate` | Permission denied; gate unchanged |
| S33 | Push to `main` | Separate GitHub-hosted `CI`; no PR coordinator substitution |
| S34 | `selected repository` release SHA | `verify-release.sh` sees successful completed `CI` |
| S35 | Railway deploy | Still GitHub-hosted; deploy secrets absent elsewhere |
| S36 | Reviewer webhook replay/duplicate | Delivery/process dedup; one process |
| S37 | Reviewer event missed while laptop offline | Durable queue or no-ingress reviewer; reconciler repairs |
| S38 | Reviewer workers race | One process lease owner writes; others no-op |
| S39 | Reviewer new head SHA | Same marked comment updated with new SHA/policy |
| S40 | Prompt injection/huge/binary PR | No tools/secrets/fs; limits/redaction; bounded output |
| S41 | Reviewer repo outside allowlist | Denied; no comment/check |
| S42 | Comment succeeds, ack/state fails | Retry finds marker/comment; no duplicate |
| S43 | Automatic `pull_request_target` workflow/job check appears | Its distinct name/source cannot satisfy `ci-gate`; only explicit custom Check Run can |
| S44 | Hostile PR title/body/branch/ref/filename contains shell syntax | Treated as data; no command/action/path interpolation or execution |
| S45 | Dispatch API version/status/run-ID contract | Pinned API returns HTTP 200 plus exact run ID; 204/no-ID/wrong schema fails protocol; no list-and-guess |
| S46 | Normal cancel stalls, force-cancel/reconciler resumes | Winner already immutable; normal cancel then bounded force-cancel; restart resumes once |
| S47 | Coordinator/reviewer loses lease before side effect | No dispatch/cancel/check/ACK/comment mutation after lease loss; new owner alone proceeds |
| S48 | Dependabot PR | Classified untrusted; GitHub-hosted only; no local registration/access |
| S49 | Reviewer events arrive out of order | Older generation records stale and ACKs after durable state without GitHub mutation; newest alone updates |
| S50 | Durable receiver early HTTP ACK | HTTP 2xx only after durable enqueue and under 10s; queue item remains until GitHub write+state commit |
| S51 | PR workflow/job/check named `ci-gate` | Native same-name check cannot satisfy ruleset expected-source gate |
| S52 | Commit status and foreign-App Check Run named `ci-gate` collide | Neither satisfies dedicated-App required check; collision alerts |
| S53 | `started_test_at` install boundary | Marker exists before first checkout-dependent `npm ci`/pip/install/build/script; failure afterward is functional |
| S54 | Timing boundaries | Test every v1 deadline at `T-1s`, `T`, `T+1s`; actions match normative table and total SLA |
| S55 | Workload lateral network probe | Windows host, Tailscale, RFC1918, link-local/metadata, reviewer/control/deploy and sockets denied; approved proxy destinations work |
| S56 | Network policy reboot/persistence failure | Runner registration blocked until firewall/proxy/default-deny proof passes after reboot |
| S57 | Runner-manager bake-off | All three candidates receive comparable evidence; no real repo until one maintained candidate and digest pass; none-pass stays GitHub |
| S58 | Reviewer missing decision record | No webhook/model secret/processing/comment; phase remains BLOCKED |
| S59 | Reviewer provider outage or quota | Bounded timeout/retries/backoff, no approval/comment duplication; queue/DLQ age policy enforced |
| S60 | Reviewer oversize/invalid output | File/diff/line ceilings and schema fail closed to bounded informational result; never inferred approval |
| S61 | Reviewer skill provenance mismatch | Source commit/SHA-256 mismatch blocks activation/processing |
| S62 | Dedicated App authority positive/negative permissions | App token writes Check Run on exact install but cannot read contents, write status, dispatch Actions or access admin |
| S63 | Token mint narrowing/TTL/storage | Only control plane mints ≤1h one-repo checks token; child/env/cache/log/artifact see no key/token |
| S64 | App key rotation/revocation | New key passes positive/negative suite; old key/token mint/write fails; audit/fingerprint updated |
| S65 | Admission/start marker persistence fails | `CONTROL_FAILURE`; atomic pair absent/incomplete is unusable; no npm/pip/install/build/script/project process starts; watchdog repairs, no inferred fallback |
| S66 | Admission/start marker authority/immutability | Outside-workspace wrapper obtains successful pre-marker decision; GateStore atomically binds authority/execution/deadline plus marker admission ID/digest; PR cannot forge/backdate/delete |
| S67 | Timing oracle completion/timeout race | Absolute deadlines and authoritative clocks apply exact comparators; timely completion wins equality once |
| S68 | Deterministic bake-off JSON/rootful | Hard-gate fail is ineligible with no waiver; rootful needs an exact operator risk record; weights/tie-break reproduce winner or none-pass |
| S69 | Same-repo PR created by a collaborator, no signed exact-SHA attestation | GitHub-hosted; relationship signals and inventory cannot create local eligibility |
| S70 | Approver-authored PR branch updated by collaborator after signing | Head/generation and inventory proof changes; GitHub-hosted if pre-dispatch, otherwise allocation fenced/cancelled and result rejected |
| S71 | Bot/App with write permission updates signed head | Head/generation or inventory guard drifts; no later local gate succeeds |
| S72 | Collaborator/team/App added after local CI enablement | Effective-writer drift routes/fences at the next current-authority gate; after authentic admission only timely failure may conclude, never success |
| S73 | Writer removed/revoked while queued or running | Negative inventory drift fences before admission/success; an already-admitted exact timely failure remains failure-only, otherwise no local mutation |
| S74 | `author_association` reports MEMBER/COLLABORATOR without exact-SHA signature | Signal ignored; GitHub-hosted; no JIT/claim |
| S75 | Team membership changes between signing and a boundary | Drift detected at next current-authority gate; only an admission created before drift can support exact timely failure, not success |
| S76 | Effective branch writers cannot be enumerated completely | Inventory remains negative/unknown; only an otherwise valid exact-SHA signature may authorize, and any observable drift still fences; org authority/privacy/same-repo cannot override |
| S77 | GateStore observes ABA head sequence A→B→A and old A proof is presented | Rejected because GateStore head-generation differs; fresh signature required |
| S78 | Forged/corrupted signature or canonicalization mismatch | Verifier rejects before local/check effect; security alert contains proof hash only |
| S79 | Online signing key suspected stolen and offline-root manifest revokes version | Current proof immediately invalid at all four authority gates; GitHub-only for new work/success. Authentic pre-revocation admission may still conclude exact timely failure only |
| S80 | Nonce replay against another gate generation | Atomic binding conflicts; replay rejected and original generation remains unchanged |
| S81 | Attestation presented for wrong repository ID/name | Exact target verification rejects; no JIT/claim/check mutation |
| S82 | Attestation presented for wrong PR or head SHA | Exact target verification rejects; no JIT/claim/check mutation |
| S83 | Local attestation expiry boundary | Authority is valid only while `now < expires_at` at dispatch/claim/pre-marker admission/local-success; equality/later routes GitHub/fences there. A previously admitted timely functional failure follows S102/S108 and cannot authorize success |
| S84 | Normal root-signed key-manifest rotation boundaries | `active`: sign/verify yes. After transition, `retiring`: new sign no, pre-transition issued+unexpired verify yes, post-transition/fabricated issuance no. `revoked` or unknown: sign/verify no |
| S85 | Signing key/helper/root manifest unavailable | No password/shared-secret prompt or bypass; GitHub-hosted and availability alert |
| S86 | Caller asks helper to sign arbitrary payload/stdin/file or caller nonce | Bounded helper rejects; no signature/audit success emitted |
| S87 | Agent policy receives no explicit same-thread exact-target request | Procedural policy says do not invoke; audit records denial. Test does not claim helper can verify conversation truth |
| S88 | Agent policy receives blanket/repo/branch/future-head request | Agent resolves/rejects as non-exact; bounded helper accepts no blanket target shape; audit records denial |
| S89 | Attestation audit inspection | Opaque request-linkage hash, exact target and outcome exist; transcript/private key/shared password absent |
| S90 | Signature fails/drifts across current-authority gates | Dispatch/claim/pre-marker-admission/local-success failure routes GitHub/fences exactly once; historical-admission failure uses S101–S108; after `winner=github`, later drift is audit-only |
| S91 | Forged `request_linkage_hash` attached to unsigned or foreign-key payload | Grants no authority: signature/manifest validation fails. With a genuinely valid signature, linkage content is merely logged and never independently trusted |
| S92 | Manifest predecessor-chain/digest tamper | Lower/conflicting generation, correct generation with wrong defined payload digest, envelope digest substitution, broken predecessor or omitted revocation is rejected |
| S93 | Exact signature carries `inventory_guard_status: partial` | Current-authority gates may pass only with identical signed semantics; any transition/hash change fences them. Authentic prior admission preserves only timely failure |
| S94 | ABA A→B→A occurs entirely between control-plane observations | GateStore correctly cannot increment; exact content SHA A remains identical. A consumed nonce cannot bind a second local gate generation; fresh unconsumed signature is required for another run |
| S95 | Local success transaction linearizes at expiry `T-1`; GitHub selection arrives at `T` | Atomic local-success winner/result/outbox commits; GitHub loses/fences; one logical Check conclusion |
| S96 | GitHub selection linearizes at `T`; local success request observed T-1 arrives later | GitHub wins; local-success transaction evaluates GateStore time/state, fences as expired/loser; no local outbox |
| S97 | Local-success-at-T-1 and GitHub-at-T race simultaneously under both delivery orders | Serializable schedules yield exactly one stable winner; exhaustive interleavings never produce two terminal/outbox conclusions |
| S98 | Crash pre-select and inside post-select/pre-complete transaction | Pre-commit leaves no winner/result/outbox or atomically committed trio—never partial; retry converges according to winner |
| S99 | Crash after local transaction commit before outbox delivery/check mutation | Winner/result/outbox persist; reconciler delivers once effectively to exact Check Run; GitHub selection/local duplicate fence/idempotent |
| S100 | Dedicated-App Check response ambiguous, then same/different evidence retries | GET exact Check Run/evidence marker resolves ambiguity; same evidence idempotent, different evidence conflicts; at most one external logical mutation |
| S101 | Canonical local tests reach authoritative timely terminal functional failure after valid admission+marker | Failure API validates authentic admission/marker, current owner/lease/generation, exact child run/job, canonical base/head, local artifact/command and authoritative `terminal_at<=deadline`; atomically commits local failure/evidence/outbox |
| S102 | Current proof expires, is revoked or drifts after valid historical admission but before timely failure | Only failure may commit from the authentic admission; local success still fails current-proof validation. Admission/proof transition is audited and failure can never become success |
| S103 | Timely admitted local failure races GitHub/timeout winner in failure-first, GitHub-first and simultaneous schedules, with crashes before/inside/after transaction | Failure-first remains final failure; GitHub/timeout-first makes failure evidence-only; exact-job reread prevents timeout from ignoring already-visible timely failure; one immutable winner/terminal/outbox |
| S104 | Local-failure outbox delivery or dedicated-App response is ambiguous and is retried | Same failure evidence is idempotent; different evidence conflicts; success-shaped retry rejects; exact Check Run read-back converges to at most one logical failure mutation |
| S105 | Admission is absent/forged/mismatched/cross-bound incorrectly, or crash occurs between pre-marker verify/admission/marker persistence | Mismatch is `CONTROL_FAILURE` with no winner/outbox/Check. Crash exposes neither record or complete pair; zero PR work; retry converges atomically |
| S106 | Authoritative failure `terminal_at` is `D-1`, `D`, or `D+1` against persisted execution deadline | `D-1` and `D` may win with authentic admission; `D+1` is evidence-only and selects/resumes fallback; runner/coordinator clock skew cannot change result |
| S107 | Failure and timeout observations arrive in both orders around `D` | Timeout transaction rereads exact authoritative job state: already-visible timely failure is offered first; otherwise the first valid atomic winner is immutable and late evidence cannot overwrite it |
| S108 | Proof is invalid at each boundary with and without historical admission | Invalid at dispatch/claim/pre-marker/local-success routes GitHub/fences. Only a post-admission timely functional failure bypasses current proof validity; a missing admission or any success attempt is rejected |

## Unit tests

### Registry/authority

- Default absent repo to GitHub/reviewer disabled.
- Reject wildcard, malformed scope, implicit org expansion, inconsistent App/group.
- Personal selects repo-scoped JIT only; org selects restricted group only after admin/App/policy proof.
- External contributors always GitHub-hosted.
- Enable/disable/reconcile idempotent and order-safe.

### Execution trust policy v1

- Default/absence is `github-hosted`, `local_eligible=false`.
- Reject trust inferred from privacy, author, same repo, `author_association`, MEMBER, COLLABORATOR, collaborator boolean or org membership.
- `enumerated-writers` is schema-invalid as a positive mode; inventory alone always leaves `local_eligible=false`.
- Immutable-ID normalization for user/bot, team+org, App+installation, deploy key, bypass actor and privileged workflow supports the negative guard.
- Mechanically derive inventory status. Semantic hash excludes observation time, transport ETag, request ID and latency; identical semantics at t1/t2 hash identically, while relevant actor/permission/schema/status/missing-set change hashes differently.
- Fresh authenticated observation age `<=5m` is required at each gate. Stale equal semantics fails freshness without being labeled semantic drift; fresh equal re-observation preserves authority after issuance timestamp ages.
- Any observed normalized inventory change or status transition, including add/remove/reduction/source appearance/loss, changes the guard and fences.
- Org runner-group/JIT authority has no effect on execution-trust result.
- Authority-v1 canonicalization tests cover I-JSON/RFC8785, duplicate keys, non-finite/unsafe values, UTF-8, exact domain separator and detached signature/payload separation.
- Ed25519 accepts only raw-64 signature encoded unpadded base64url; P-256 accepts only low-S IEEE-P1363 `r||s` 64-byte ECDSA-SHA-256 and rejects DER/high-S/ambiguous encodings. Fingerprint is SHA-256 of exact DER SPKI.
- Payload binds manifest version plus issuance generation/digest, exact target/GateStore generation, inventory status/missing set/hash, issued/expiry, nonce and linkage; any mutation fails.
- Helper accepts typed exact target only, re-resolves GitHub state, reads head-generation solely from GateStore and cannot sign stdin/files/arbitrary JSON/caller nonce. Same-thread evidence is tested as agent procedural policy/audit, not helper-verifiable truth.
- Forged linkage alone has zero authority; a valid signature remains authoritative regardless of linkage semantics, which are audit-only.
- Expiry default is 60m, maximum 90m, and valid iff authoritative `now < expires_at`; equality is invalid.
- First pre-dispatch verification atomically binds nonce to exact gate generation; same-generation retry is idempotent, other use is replay.
- Observed A→B→A increments GateStore head-generation and invalidates old A. Unobserved ABA does not increment and is explicitly modeled as identical exact content; nonce-to-local-gate binding prevents consumed-proof reuse across runs.
- Wrong repo/PR/SHA, fake signature, expiry, signing-key revocation and helper/root-manifest/key unavailability fail closed. V1 exposes no individual-attestation revocation.
- Separate pre-dispatch, pre-claim, pre-marker-admission and pre-local-success calls gate current attestation authority. Only an authentic immutable historical admission created after successful pre-marker verification can support a later timely functional failure without a currently valid proof. Once `winner=github`, either verifier output is audit-only.
- Root-manifest matrix tests: active sign=yes verify=yes; retiring sign=no verify=yes only for already-issued/unexpired proof whose embedded issuance manifest is authenticated in predecessor chain; revoked/unknown sign=no verify=no. Tamper issuance generation/digest, chain link, current state and rotation time boundaries.
- Cross-component manifest digest vectors are shared by helper, control plane, GateStore/reconciler and verifier: reordered keys/whitespace serialize to same JCS digest; one payload field change changes digest; payload digest versus signed-envelope digest mismatch rejects; correct generation with wrong digest rejects. Assert lowercase hex SHA-256 over domain+`0x00`+JCS payload excluding detached signature.

### Protocol/SHA

- Reject unknown version, missing/short SHA, wrong repo ID, backend, workflow ref, or tuple relation.
- Assert the PR Check target equals the server-canonical head SHA; the tested artifact is the deterministic local commit/tree produced from the canonical base and head.
- Logical key binds head; generation binds base plus `merge_policy_version`; head/base movement invalidates the prior generation.
- Dispatch ref is trusted default; quality checks out the exact base, imports the exact PR head, constructs the local commit, and runs with `HEAD` at that local commit.
- Full exact SHA comparisons; no branch inference.
- Dedicated App ID is the only accepted `ci-gate` source; native workflow/job, commit status and foreign-App collisions reject.
- GitHub REST `2026-03-10` is required and the exact HTTP 200 `workflow_run_id`, `run_url`, `html_url` receipt is consumed directly; URLs bind the repository and run ID.
- Local package requires `execution_trust_mode=exact-sha-attestation`; it carries `local_result_kind`, admission ID/digest, exact child run/job, marker-core digest, canonical base/head plus local-merge evidence, canonical-command digest and authoritative `terminal_at`. Fallback package requires `backend=github` plus `execution_trust_mode=github-hosted` and null/evidence-only attestation/admission fields. Crossed result kinds, identities, digests or modes reject.
- Hosted conclusion predicate requires immutable GitHub winner, current lease, logical/generation/current tuple, exact head-targeted Check, canonical base/head and local-merge evidence, canonical command, trustworthy hosted child/deadline and dedicated App; no attestation input.

### `ci-gate` App authority v1

- Schema pins owner, App ID/slug, exact repo/installation IDs, workflow/ref, fingerprint, rotation and version.
- Only coordinator/reconciler runtime identity can mint; every other role is denied.
- Token request narrows one exact repo and checks-write/required metadata with TTL values at 59m59s, 60m and >60m; >1h rejected.
- Positive Check Run create/update; negative Contents read/write, commit status write, Actions/workflows, administration, PR/issues/deploy/environment/secrets/org access.
- Scan child env/cache/log/artifact/image/process for App key/JWT/installation token canaries.
- Rotation and compromise sequence proves new-before-old switch, old revocation, installation suspension/uninstall and GitHub-only recovery.

### GateStore/state machine

- All valid/invalid transitions.
- Acquire/heartbeat/select/complete reject wrong owner/generation.
- Winner immutable; same-SHA generations serialize.
- Attestation failure before winner calls the GitHub-only selector/fence idempotently once only at dispatch, claim, pre-marker admission or local success. There is no generic local completion selector.
- `create_local_admission_after_pre_marker_verify` rejects every non-success/currently-invalid verifier decision and atomically creates admission+marker only once. Record binds attestation/envelope/nonce, policy/manifest/key, canonical base/head and gate generation, exact child run/job, local artifact, owner/lease epoch, verifier decision ID/time, execution deadline and marker-core digest. Marker contains admission ID/digest; crash hooks prove neither-or-complete pair and zero PR work; caller metadata cannot forge either.
- `complete_local_success_if_authorized` covers wrong owner/lease/generation/evidence, GateStore-clock expiry, local/GitHub competing winner, same-evidence retry and different-evidence conflict. Winner+success terminal+outbox is all-or-nothing.
- `complete_local_failure_if_current` independently resolves stored admission/marker and authoritative exact-job terminal observation; caller IDs/digests/time are expectation-only. Reject absent/forged/mismatch, wrong execution tuple, `terminal_at>D`, nonfunctional/success-shaped evidence or prior winner. Admission failure is no-winner `CONTROL_FAILURE`; D+1 is evidence-only/fallback. Same evidence is idempotent; committed failure cannot become success.
- Outbox key is stable over logical key/generation/winner/evidence digest; only committed record may enqueue. Known Check Run read-back resolves ambiguous response and converges repeated delivery to one logical mutation.
- `complete_hosted_winner` atomically persists hosted terminal evidence+outbox only after the hosted predicate; same/different evidence semantics match local completion.
- GateStore is sole `head_generation` writer. Helper/bind APIs accept only optional expected comparison; mismatch rejects, and caller/protocol cannot set/advance/reset signed generation.
- Terminal duplicate no-op unless explicit rerun.
- Stale owner cannot update new generation.
- Lost lease before every external-effect boundary produces no effect.
- Crash recovery at every side-effect boundary.
- Retry/dispatch/cancel bounded and idempotent.
- `bindAttestationNonce` is atomic: first exact binding succeeds, same-tuple retry is idempotent, any different generation/head-generation/envelope/target is replay and causes no external effect.
- Signed envelope digest/reference must resolve immutably and match canonical bytes; copied protocol metadata without the envelope/signature never authorizes.
- Admission/marker create is owner-fenced, immutable, control-clocked and atomic. Marker core binds logical key/generation/run/job/canonical base/head/local artifact/wrapper; admission binds the full authority/execution tuple and marker-core digest; final marker binds admission ID/digest.
- Marker persist failure is `CONTROL_FAILURE` and blocks process spawn/fallback inference.

### Claim/taxonomy

- Exact workflow ID/ref/run-name/generation/backend and exactly one job.
- Non-null timely `started_at`, exact labels, fresh ephemeral runner identity.
- `queued`, online runner, or labels alone are false.
- Pinned dispatch API must return HTTP 200 and exact run ID; no run-list guessing.
- Trusted pre-`started_test_at` infrastructure may fallback; protocol failures block; command nonzero after marker is functional; platform-observed transport loss is separately eligible.
- Ambiguity is blocking protocol/control failure.
- `started_test_at` is persisted before any dependency install/resolution, generated script, build, lint, test, or project-tool execution.
- Only fixed tooling/protocol/identity steps that do not read checkout/PR metadata qualify as trusted bootstrap.
- Boundary tests classify checkout-dependent nonzero after admitted marker as functional only with authentic admission and authoritative `terminal_at<=D`; D+1 is late evidence/fallback. Independently observed platform transport loss remains infrastructure.

### Timing policy v1

Parameterized tests use `T-1s`, `T`, and `T+1s` for heartbeat, lease, watchdog, API tolerance, 5-minute inventory freshness, claim/execution, cancellation, retries, reviewer and total SLAs. Inventory age `<=5m` is fresh; `>5m` rejects as freshness failure without changing semantic hash.

- GitHub API clock controls exact child/job `terminal_at`; GateStore clock controls lease/winner/admission/start/cancel and attestation expiry at dispatch/claim/pre-marker-admission/local-success acceptance; queue clock controls ACK. Historical-admission failure ignores current proof expiry but must satisfy persisted deadline. Skew helper/runner/coordinator clocks ±24h with no outcome change.
- Claim: `started_at<=deadline` wins; timeout only `now>deadline` without timely claim.
- Lease: valid `now<expiry`; fenced at `now>=expiry` before side effect.
- Execution: terminal `<=deadline` wins; timeout only `now>deadline` without timely completion. Inject simultaneous observations in both delivery orders and require one identical result.
- GateStore transaction clock: local valid only when linearized `now<T`; request/coordinator clock is ignored. Run local-vs-GitHub at T-1/T in both orders and simultaneous schedules. With GitHub winner, T-1/T/T+1 attestation changes remain audit-only.
- Force cancel at `>=cancel+90s`; queue threshold at `age>=threshold`; HTTP ACK success only `<10s` after durable enqueue.

### Bake-off JSON

- JSON Schema permits only criterion classes `hard_gate|scoped_capability|advisory` and statuses `pass|fail|not_applicable`; reject waiver/override fields.
- Every hard fail/not-applicable yields `eligible=false`, including pin/provenance, JIT disposal, cleanup, socket, network, WSL and maintenance/security thresholds.
- Test maintenance boundary at 12 months and High-vulnerability boundary at 30 days.
- Rootful without an exact unexpired operator risk record is ineligible; acceptance cannot waive another hard gate.
- Reorder JSON/candidates/evidence and reproduce identical highest weighted score/tie-break/none-pass result.

### Reviewer

- Delivery/process/comment keys, generation lease, hidden marker, policy version.
- Ack-failure retry does not duplicate.
- New SHA updates same comment.
- Reconciliation enqueues missing work once.
- Out-of-order generation is fenced and cannot mutate GitHub.
- HTTP ACK after durable enqueue is distinct from queue ACK after GitHub write plus durable state.
- Missing/invalid provider decision, cost/token ceiling, secret ownership/rotation, or skill source commit/SHA-256 blocks reviewer activation.
- Provider timeout/outage/quota follows 120-second ceiling and 30-second/2-minute retries; no silent approval.
- Oversize/invalid output exercises 100-file, 1-MiB, 50,000-line and schema limits.
- Size/token/schema/redaction and prompt-injection-as-data.

## Integration tests

Use a disposable public personal sandbox and, when explicitly selected, a disposable public organization repository:

- Create/update `ci-gate` on the exact server-canonical head SHA using only a short-lived installation token from the dedicated App; inspect/pin App ID. Build and record the deterministic local ort artifact separately.
- Mint from authorized coordinator only, narrow token to exact installation/repo/permissions and ≤1h; call Contents, status and administration APIs and require denial while Check Run write succeeds.
- Verify key/JWT/token absent from child jobs, environments exposed to PR processes, logs, artifacts, caches and runner image.
- Execute offline-root-signed online-key rotation/revoke and compromise recovery; retiring cannot sign new proofs, revoked key/proofs fail, and no per-attestation revocation API exists in v1.
- Create malicious same-name PR workflow/job/native check, commit status and foreign-App Check Run; prove none satisfies expected-source protection.
- Prove base-trusted `pull_request_target` and absence of checkout.
- Prove its automatic workflow/job check has a distinct name and cannot satisfy `ci-gate`.
- Inject hostile title/body/branch/ref/filename strings and prove no executable interpolation.
- Dispatch the trusted default-branch child with the server-canonical base/head tuple; construct the local artifact inside the isolated quality job.
- Pin GitHub REST `2026-03-10`; require HTTP 200 exact `workflow_run_id`, `run_url`, `html_url`; reject 204/no-ID, missing/extra fields, crossed repository/run URLs and ambiguous schemas without listing/guessing runs.
- Construct the deterministic local ort artifact from the exact canonical base/head, then verify the resulting tree, parents and detached `HEAD`.
- Use wrapper outside PR workspace to successfully pre-marker verify and atomically persist admission+marker, then prove both precede the first intercepted npm/pip/install/build/script process. Deny verifier/admission/marker persistence separately and prove zero PR-dependent child processes.
- Observe formal claim through Runs/Jobs APIs.
- Cancel queued/running child; prove late fencing.
- Run S95–S108 with GateStore/GitHub authoritative clocks, transaction crash hooks and outbox/Check API fault injection. Enumerate success-first, timely-admitted-failure-first, GitHub/timeout-first and simultaneous schedules; admission missing/forged/mismatched; D-1/D/D+1; and pre-commit/post-commit/pre-delivery/ambiguous-response retries.
- For hosted conclusion, independently corrupt winner, lease, logical/generation/tuple, canonical base/head, local artifact, head-targeted Check, canonical command, hosted run/job identity, deadline and App source; each blocks. Changing only attestation after GitHub winner does not.
- Stall normal cancel, exercise bounded force-cancel, crash midway, and resume through reconciler once.
- Exercise pilot Check-backed GateStore, same-SHA serialization, stale rejection.
- Kill coordinator at each side-effect boundary; run watchdog/reconciler.
- Skew runner clock and race terminal completion/timeout observations around equality; authoritative result remains identical.
- Personal App installed in one repo gets denied elsewhere.
- Org group restricted to one repo; sibling repo cannot schedule.
- Independently vary runner authority and execution trust: an authorized org pool without a valid authority-v1 exact-SHA signature remains GitHub-hosted.
- Build the negative inventory guard from collaborators, teams/child teams, org owners/default role, branch restrictions, ruleset bypass actors, write Apps/installations, write deploy keys and privileged Actions workflow permissions/writers; verify immutable IDs and complete pagination, while proving it never positively authorizes.
- Exercise complete/partial/unavailable classifier and sorted missing-source set. t1/t2 with identical normalized semantics but different observation time/ETag yield same hash; actor/permission/relevant schema/status/missing-set change yields different hash. Stale observation rejects by freshness reason, not drift.
- Exercise bounded signer with a dedicated test key outside repo/model workspace: exact typed target produces detached JCS payload/signature; arbitrary/blanket input fails. Separately test agent procedural policy/audit for same-thread request without claiming cryptographic conversation verification.
- Verify public-key-only validation, exact SPKI fingerprint and signature encodings, domain separation, repo/PR/head/GateStore head-generation, expiry, nonce replay, observed and unobserved ABA, wrong target and fake signature.
- Bootstrap/rotate/revoke through offline-root test key; persist full authenticated predecessor chain. Run the same manifest digest vector fixture through signer/helper, registry loader, protocol encoder, reconciler and verifier; any component hashing signature/envelope fails the suite.
- Scan prompts, `AGENTS.md`, repo, process environment, logs, caches and artifacts for signer private-key/shared-password/transcript canaries; only opaque request-linkage hash may persist.
- Rotate/revoke credentials.
- Child token lacks checks write, deploy secrets, environments, admin.
- Coordinator `GITHUB_TOKEN` cannot write `ci-gate`; only dedicated App token can.
- Dependabot follows untrusted GitHub-hosted path.
- Push-main `CI` is distinct and successful.
- Test durable reviewer queue if approved; otherwise GitHub no-ingress path.
- Deliberately miss reviewer event; reconcile exactly once.

## WSL/security tests

- Runtime is dedicated CI distro, not personal Ubuntu.
- Dedicated non-admin Windows service account owns/starts CI distro; Windows effective-access/ACL tests deny personal profiles/data and unrelated secrets.
- `/etc/wsl.conf`: automount off, `mountFsTab=false`, interop off, Windows PATH off.
- `/mnt/c`, `/mnt/d`, Windows executables, Docker Desktop socket, personal distro data, reviewer/deploy homes, SSH agent and secrets unavailable.
- No container-engine socket in workload/reviewer.
- Rootless runtime where viable; capabilities/seccomp/PID/CPU/memory/read-only policy enforced.
- Tokens absent from env/process/log/artifact/cache/final filesystem.
- Cleanup passes all terminal modes and reboot.
- No orphan reusable runner registration.
- Any failure blocks local enablement; not waived as “container isolation.”
- Separate management/workload routes and namespaces; workload cannot reach management listener.
- Deny Windows gateway/host, `100.64.0.0/10`, RFC1918, `169.254/16`/metadata, `fc00::/7`, `fe80::/10`, reviewer/control/deploy canaries, local/container sockets.
- Allow only approved GitHub/DNS/OS mirror/npm/PyPI/runtime/Playwright destinations through the policy proxy; private/rebound DNS fails closed.
- Verify firewall/proxy loads before runner registration and persists after Windows and WSL reboot; deletion/corruption blocks registration.

## Runner-manager bake-off tests

For Fireactions, GARM+Incus and `myoung34/docker-github-actions-runner`, capture the same matrix: upstream release/maintenance/security/license; tag+digest/signature/SBOM; WSL startup; personal JIT; org restricted group; one-job teardown; success/failure/cancel/force-cancel/reboot cleanup; rootless/no socket; network policy; observability; 4C/16-GiB resource use; upgrade/rollback. Fireactions must prove KVM rather than assume `/dev/kvm`; GARM+Incus must prove actual Incus/provider viability; myoung34 must prove current maintenance and ephemeral behavior. Verify both selection and none-pass outcomes. Evidence files and independent sign-off are prerequisites to any real allowlist.

Validate the machine JSON against schema; independently recompute hard-gate eligibility, scoped weights and lexicographic tie-break. Inject hidden waiver, unresolved WSL, socket exposure, network bypass, cleanup failure, stale maintenance, vulnerability-threshold breach and rootful-without-risk-record; each deterministically becomes ineligible.

## End-to-end pilot

- Run S02, S05, S08–S13, S17–S35 in sandbox.
- On the selected pilot repository, require three consecutive local successes and three offline fallbacks.
- Before any local-success pilot, create a valid authority-v1 signed attestation for that exact repo/PR/head/head-generation in response to the explicit target request and pass all four verifier gates; otherwise expected result is GitHub-hosted. Inventory completeness/approval alone is never sufficient.
- Compare canonical `make test`, canonical base/head, local artifact, environment contract and conclusions across backends.
- Preserve GitHub-hosted `artifact-manifest`, `supply-chain`, `secret-scan`.
- Only `ci-gate` is newly required and expected source pinned; attempts cannot satisfy protection.
- Required source is the dedicated App; same-name checks/statuses cannot satisfy protection.
- Confirm push-main `CI`, `verify-release.sh`, and Railway deploy.
- Run disable twice and enable twice; second call is no-op with audit.

## Reviewer delivery tests

Durable mode, only after ingress approval:

- signature, timestamp, replay, rate, queue persistence, consumer outage/redelivery/dead letter/comment ack;
- HTTP response occurs only after durable enqueue and under 10 seconds, without waiting for laptop/model/comment;
- queue ACK/delete occurs only after GitHub write and durable process/comment-state commit;
- write-success/state-failure retry finds the same comment and does not duplicate;
- laptop offline past GitHub retry window still yields one review;
- receiver cannot invoke arbitrary repo/operation.

No-ingress mode:

- trusted GitHub-hosted workflow, no PR checkout, pinned reviewer/skill, API-only diff;
- completes while laptop offline;
- same process/comment idempotency.

Both modes: selected repo only; one marked comment per review kind; update for new head; processing key includes policy version+generation; out-of-order work is fenced; periodic missed-event reconciliation; informational AI only.

Before either mode, verify reviewer remains inert/BLOCKED without an approved `decisions/reviewer-provider-v1.yaml`. Validate every required field, selected cost/token ceilings, secret owner/storage/rotation, provider retention, and skill source URL+commit+SHA-256. Simulate outage, quota, 120-second timeout, both retry intervals, queue age/DLQ, oversize diff and invalid structured output; none may infer approval or duplicate comments.

## Observability/SLA

Record GateStore server decision time, winner transaction, `local_result_kind`, admission ID/digest/validation, verifier decision ID/time, exact child run/job, marker/canonical-base/head/local-artifact/canonical-command digests, authoritative `terminal_at`, persisted deadline/comparator result, terminal failure source, proof role (`current_authority_for_success|historical_admission_for_failure|audit_only`), outbox ID/key/state/attempt, Check Run ID, ambiguity/read-back and logical mutation digest. Never log secrets.

Alert on two winner records, admission without successful pre-marker decision, missing/forged/mismatched admission, terminal without outbox, outbox without terminal, different-evidence retry, Check marker mismatch, `terminal_at>D` winning, success using historical admission, timely admitted failure incorrectly requiring current proof, success-shaped evidence entering failure API, winning failure replaced, GitHub-first late failure mutating Check, or multiple logical conclusions.

Alert/test:

- stale coordinator heartbeat / gate without live owner;
- fallback missed after claim deadline+tolerance;
- multiple child matches/owners;
- late local result; wrong App source; stale merge/base; local result-kind/execution-evidence mismatch;
- cleanup/orphan runner; runner offline/disk pressure;
- reviewer queue age/dead letter/duplicate/missed-event repair/cost/error.
- network-policy load/persistence/default-deny failure or lateral canary access;
- runner-manager digest/provenance drift;
- App authority/install/fingerprint/permission drift, token TTL or scope violation;
- admission/start-marker persist/immutability/cross-binding failure or non-authoritative clock;
- timing-oracle comparator divergence;
- reviewer provider outage/quota/oversize/invalid output/provenance mismatch.
- invalid proof outside/inside dispatch/claim/pre-marker/local-success being scoped incorrectly; timely historically admitted failure blocked by current proof state; missing/mismatched admission producing a winner/check; post-deadline failure winning; post-GitHub-winner drift blocking hosted conclusion; or hosted conclusion missing its independent predicate.

Watchdog SLA: within one scheduled interval plus API tolerance, resume a valid owned generation, dispatch an already-selected fallback, or conclude blocking/action-required. Never success without selected-attempt evidence.

## Evidence bundle

Preserve without secrets: protocol package; GateStore ownership/transitions/heartbeats; admission record/digest and verifier decision; Check ID/name/source/head target; child run/job and claim proof; `git rev-parse HEAD`; marker/admission/canonical-base/head/local-artifact/command binding; authoritative terminal/deadline evidence; result kind/taxonomy/proof role; winner/terminal/outbox transaction; cancel/fallback/late events; cleanup/registration inventory; ruleset state; reviewer reconciliation.

## Critical blockers

- Coordinator executes/checks out PR-controlled content.
- Child tests wrong SHA or ignores tuple change.
- Check target/source wrong.
- Automatic `pull_request_target` check can satisfy `ci-gate`.
- Commit status or foreign-App/custom Check Run named `ci-gate` can satisfy it; dedicated App source is not fixed.
- App has broader than Metadata-read/Checks-write permissions, is installed beyond exact repos, or non-control identity can mint/access key/token.
- Installation token exceeds one hour, is not repository/permission narrowed, or appears in child/env/cache/log/artifact/image.
- Rotation/revocation cannot prove old key/token failure and GitHub-only recovery.
- Hostile metadata reaches executable context.
- Dispatch lacks pinned API version, HTTP 200, or exact returned run ID.
- Dispatch is not pinned to GitHub REST `2026-03-10`, or its HTTP 200 receipt omits/crosses any exact repository/run-bound URL field.
- `started_test_at` is recorded after any PR-dependent install/build/script/tooling operation.
- Admission/marker wrapper is PR-writable/in-workspace, admission exists without successful pre-marker verify, binding omits authority/execution fields, marker lacks admission ID/digest, hashes are circular/forgeable, uses runner clock, or persistence failure starts a PR process/fallback.
- Thresholds lack persisted absolute deadlines/authoritative clock/exact comparator, or timeout beats a completion exactly at deadline.
- Multiple generations/attempts can satisfy/contradict `ci-gate`.
- Claim inferred without formal Jobs API predicate.
- Functional failure hidden by fallback, conditioned on current proof despite authentic historical admission, admitted without exact authentic admission/current execution/timely terminal evidence, post-deadline but winning, or later converted to success.
- Watchdog cannot repair/block orphan state.
- Late local overwrites winner.
- Lost-lease owner performs any external effect.
- Dedicated Windows account/ACL or `mountFsTab=false` proof fails; Windows/personal data, Docker socket, reviewer/deploy credential reachable.
- Workload reaches management, Windows/Tailscale/RFC1918/link-local/metadata/reviewer/control/deploy, or network policy fails after reboot.
- Runner manager was selected without bake-off evidence, maintained upstream/digest pin, independent sign-off, or a candidate passes none of the required criteria.
- Bake-off admits hard-gate waiver/not-applicable, unresolved maintenance/security/WSL/socket/network/cleanup failure, nondeterministic tie-break, or rootful without the operator's scoped unexpired acceptance.
- Exact personal/org authority unproven.
- Execution trust inferred from repository/user relationship signals or conflated with runner/org authority.
- Enumerated writers, privacy, authorship, membership or runner authority is used as positive local authorization.
- A collaborator/team member/bot/App/deploy key/privileged workflow changes the signed head or negative inventory without routing/fencing, including writer removal.
- Exact-SHA proof is not revalidated at dispatch/claim/pre-marker/local-success; invalid proof is routed elsewhere incorrectly; success uses historical admission; or failure-only transaction accepts missing/mismatched admission, success-shaped or late/nonauthoritative evidence.
- Hosted fallback conclusion depends on attestation after immutable `winner=github`, or concludes without exact hosted-winner predicate.
- Local Check mutation occurs without the matching committed success-authorized or failure-current winner/result/outbox record; winner transaction can partially commit; winning failure can be overwritten; local and GitHub both win; different evidence is accepted idempotently; or ambiguous Check response creates a second logical conclusion.
- Agent procedural policy allows automatic/no-request, blanket/future/unresolved targets, or audit omits the non-authoritative linkage; helper/verifier falsely claims to cryptographically verify conversation provenance.
- Payload/signature lacks exact domain, I-JSON/JCS, detached encoding, SPKI fingerprint, exact repo/PR/head/GateStore head-generation/inventory status+hash/expiry/nonce; is replayable; or works under a revoked/non-manifest key.
- Key manifest lacks security-approver user-presence root signature, monotonic generation/predecessor digest, append-only revocations/state constraints, rollback rejection or fail-closed availability.
- Signer private key/shared password/transcript reaches model context, prompt, `AGENTS.md`, repo, child, environment, cache, log or artifact; helper signs arbitrary payload/caller nonce.
- At dispatch/claim/pre-marker/local-success, key/helper unavailability, fake signature, replay, wrong target or expiry offers password fallback or permits local/success effects; historical admission may permit only exact timely failure.
- Secret leakage or cleanup residue.
- Missed/out-of-order reviewer work, early pre-enqueue HTTP ACK, premature queue ACK, or duplicate comments.
- Reviewer activates without provider/model/budget decision, exceeds limits, lacks secret/skill provenance, or treats outage/quota/invalid output as approval.
- Push-main `CI`, `verify-release.sh`, or Railway semantics regress.
- Offline runner leaves a required gate pending indefinitely once a future repository explicitly enables that protection.
