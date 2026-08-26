# Ralplan review lifecycle — Self-hosted GitHub Automation

## Final local consensus — iteration 14

- Architect final verdict: `APPROVE`
- Critic final verdict: `OKAY / APPROVE`
- Material execution blockers: none found
- Local planning lifecycle: complete
- Durable execution handoff: pending documented host-issued consensus receipt

The final execution-trust design uses exact-SHA asymmetric attestations for local execution/success, negative inventory drift guards, a historical immutable admission record for timely functional failures, atomic local-vs-GitHub winner selection, a GateStore-authoritative clock, transactional outbox publication, and automatic GitHub-hosted fallback.

The reviewer remains blocked until the operator selects provider/model/budget. Public ingress, selected organization installations, required rulesets, production/deploy migration, rootful runner risk acceptance and AI merge enforcement remain explicit external authorization boundaries.

## Lifecycle result

- Planner iterations: 14 (durable historical local admission and authoritative failure deadline added)
- Architect final verdict: `APPROVE`
- Critic final verdict: `REJECT / ITERATE`
- Execution authorization: **not granted**
- Consensus gate: **incomplete**

## Architect approval evidence

Architect approved the versioned `ci-gate` App authority contract, immutable `started_test_at` marker and timing oracle, deterministic runner-manager bake-off, WSL filesystem/network boundary, personal-vs-organization authority split, reviewer decision gate, fallback protocol, watchdog and verification suite.

## Critic blocker and incorporated repair

Critic identified that repository-level trust did not prove which identities could modify the exact PR head. A private or same-repository PR is not inherently trusted: collaborators, teams, bots, deploy keys, privileged workflows or Apps with write access can update its branch.

The earlier repair attempted to prove every effective writer. Official GitHub APIs are fragmented and non-atomic, so that inventory cannot be a sound positive authorization primitive. The reference design therefore uses a per-exact-SHA attestation. The planning artifacts incorporate this replacement contract:

```yaml
execution_trust_policy_version: 1
execution_trust_attestation_authority_version: 1

default: github-hosted

sole_positive_local_proof:
  mode: exact-sha-attestation
  binds: repository_id + repository + pr_number + head_sha + head_generation
  signed_by: pinned dedicated asymmetric key
  valid_at: local-pre-dispatch + local-pre-claim + local-pre-marker-admission + local-success-acceptance

inventory_role: negative-drift-guard-only

on_unknown_or_drift: github-hosted_or_fenced
```

Implemented repair summary:

- dedicated Ed25519 or platform-native asymmetric key, non-exportable where possible under macOS Keychain/secure local-store ACL; private key never enters model context, prompts, `AGENTS.md`, repo, logs or artifacts;
- public key, algorithm, key ID/version and fingerprint pinned in control plane;
- bounded out-of-repo helper accepts an exact typed repo/PR/current head/expiry/policy target, re-resolves GitHub, reads head-generation only from GateStore, generates nonce and signs; it cannot sign arbitrary payload/stdin/file/caller nonce;
- agent invocation after an explicit same-thread exact-target request is a procedural TCB obligation. Helper/verifier cannot prove conversation provenance; linkage is non-authoritative audit metadata, and forged linkage grants no cryptographic authority;
- detached I-JSON/RFC8785 payload uses an exact domain separator, SPKI fingerprint and unambiguous Ed25519/P-256 encodings;
- signed payload binds exact repo/PR/content SHA, GateStore observed head-generation, inventory guard status/hash, expiry, nonce and opaque non-transcript linkage;
- verifier checks manifest-authorized signing key, signature/encoding/domain, exact target, expiry, negative guard and atomic nonce-to-local-gate-generation anti-replay;
- invalid proof routes GitHub/fences only at dispatch, claim, pre-marker admission and local-success acceptance;
- after immutable `winner=github`, local is fenced/late evidence-only and attestation changes are audit-only. Hosted conclusion uses independent winner+lease+tuple+tested-merge+canonical-command+trusted-child+deadline+dedicated-App predicate;
- `complete_local_success_if_authorized` uses GateStore server clock, requires a valid attestation at linearization, and atomically commits local success winner, evidence and transactional outbox;
- after successful pre-marker verification, GateStore atomically creates immutable `local_admission_record` plus marker before PR work. Admission binds attestation/envelope/nonce, policy/manifest/key, head/gate generation, exact child run/job, tested merge, owner/lease, verifier decision/time, execution deadline and marker-core digest; final marker contains admission ID/digest;
- `complete_local_failure_if_current` does not require a still-valid current proof, but requires authentic matching historical admission/marker, current execution tuple, canonical command, authoritative GitHub API `terminal_at<=persisted deadline`, terminal functional failure and no prior winner. Missing/mismatch is `CONTROL_FAILURE` with no winner/check; D+1 is evidence-only/fallback; it can never accept/produce success;
- success, authoritative failure and GitHub winner compete at the same linearization point. Failure-first remains final failure; GitHub-first makes late local failure evidence-only;
- neither backend mutates Check directly: local/hosted terminal evidence and outbox commit atomically, then stable outbox/evidence key plus exact Check Run read-back makes crashes/ambiguous responses effectively exactly-once;
- observed A→B→A is fenced by GateStore generation. Unobserved ABA is honestly indistinguishable from unchanged exact content A, while consumed nonce binding prevents a second local run;
- offline-root-signed key manifest requires security-approver user presence for pin/rotate/revoke, monotonic predecessor-linked generations, `active|retiring|revoked`, append-only revocations and rollback rejection;
- state matrix is explicit: active sign/verify yes; retiring sign no and verifies only chain-proven already-issued/unexpired proofs; revoked or unknown sign/verify no;
- signed payload embeds key-manifest version plus issuance generation/digest; helper requires active key in highest accepted issuance manifest, while verifier authenticates its predecessor chain and applies current state;
- manifest digest is one exact lowercase-hex SHA-256 over domain+NUL+JCS payload, excluding signature/envelope, reused by predecessor, issuance, highest state, protocol and audit;
- v1 intentionally has no individual-attestation revocation API: expiry, target/gate fencing or signing-key-version revocation invalidates;
- inventory classification is mechanical: complete=all required sources usable; partial=some usable plus known missing-source set; unavailable=none usable or set unauthenticated. Missing set is hashed/signed and any transition fences;
- inventory semantic hash excludes observation time and transport ETag; those are audit/freshness metadata. Every gate requires a fresh `<=5m` observation, so timestamp-only changes do not create false drift;
- GateStore supplies signed head-generation internally; callers may only provide an expected value for comparison;
- immutable-ID inventory remains useful only as negative drift evidence; add/remove/reduction/source-loss all fence, but no inventory state authorizes local;
- no inference from privacy, `author_association`, `MEMBER`, `COLLABORATOR`, author, same repo, org membership or runner authority;
- independent attestation checks at dispatch, claim, pre-marker admission and local-success acceptance; only timely failure may use historical admission, and after GitHub winner the reconciler records proof drift audit-only;
- at dispatch, claim, pre-marker admission or local success, missing/fake/expired/replayed/wrong-target proof, invalid key or manifest/helper unavailability routes GitHub-hosted/fenced without password fallback; authentic historical admission remains failure-only;
- offline-root-signed rotation makes old key `retiring` until proof expiry; root-signed revocation invalidates current proof authority immediately, while an authentic admission created before revocation remains narrowly failure-only until its execution deadline.

### GitHub API viability finding

GitHub exposes fragmented evidence, not one atomic exhaustive writer API:

- [repository collaborators](https://docs.github.com/en/rest/collaborators/collaborators) include effective highest permissions but do not identify the source of an org-level/team/default-role grant;
- [protected-branch restrictions](https://docs.github.com/en/rest/branches/branch-protection) can list users, teams and Apps, but documented push restrictions have owner/plan limitations and are organization-only on relevant surfaces;
- [rulesets](https://docs.github.com/en/rest/repos/rules) expose bypass actor types including Integration, Team, User, RepositoryRole and DeployKey;
- write-capable App installations, deploy keys and privileged workflow token paths require separate inspection.

Because these reads are non-atomic and not uniformly available, `enumerated-writers` is disabled as a positive pilot mode. The inventory is a negative drift guard only. The only local path is the operator's signed exact-head/head-generation attestation; until explicitly requested and created for that target, no local run occurs.

Earlier trust scenarios remain normatively as S69–S76:

1. Same-repo PR without a signed exact-SHA proof.
2. Approver-authored PR whose branch is updated after signing.
3. Bot/App with write permission updates the head.
4. Collaborator/team/App added after local CI is enabled.
5. Actor removed/revoked while queued or running.
6. `author_association` says member/collaborator without exact-SHA proof.
7. Team membership changes between dispatch, claim and conclusion.
8. Effective branch writers cannot be enumerated completely.

S95–S100 cover local-success-at-T-1 versus GitHub-at-T in both orders/simultaneously, transaction crashes and outbox ambiguity. S101–S108 cover durable admission, current-proof expiry/revocation/drift, missing/forged/mismatched admission, D-1/D/D+1, failure-vs-timeout/GitHub race orders, crash points, idempotent/conflicting retries and success-shaped rejection.

## User security decision

- Accepted: the operator explicitly trusts the approval agent to create one exact-SHA attestation when asked for local CI on that target.
- Rejected: a shared password or any reusable secret in conversational context.
- Selected: asymmetric capability issuance through the bounded helper; the agent requests a signature but never possesses or sees the private key.
- Clarified: same-thread compliance belongs to the trusted agent procedure and audit; neither helper nor signature proves that a human request occurred.
- Pilot rule: enumerated writers cannot positively enable local CI. The absence of a valid signed exact-target envelope always selects GitHub-hosted.

## Current review disposition

- Repair is present in spec, PRD, test spec and this review artifact.
- Prior Architect approval remains evidence for the earlier architecture; this user-selected authority replacement requires Architect then Critic re-review before any local consensus disposition can change.
- This artifact does not claim Critic approval or execution authorization.

## Iteration changelog

- Replaced the proposed positive `enumerated-writers` mode with signed `exact-sha-attestation` as the pilot's sole local authorization.
- Added `execution_trust_attestation_authority_version:1`, asymmetric key custody, bounded-helper invocation rules, canonical envelope, pinned public verifier, nonce anti-replay, head-generation ABA defense, expiry and revocation/rotation.
- Split attestation validation into pre-dispatch, pre-claim, pre-marker admission and local-success acceptance; the reconciler applies the same scope while timely functional failure follows historical-admission plus current-execution authority.
- Kept effective-writer inventory solely as a negative drift guard, including actor removal/reduction/source loss.
- Added S77–S90 plus unit/integration/E2E/observability/blocker coverage for fake proofs, theft, replay, wrong targets, expiry, rotation, unavailable helper/key, arbitrary/blanket requests and transcript-free audit.
- Iteration 8 corrected request-linkage overclaim, added offline-root manifest authority, formal detached-signature encodings, GateStore-only observed head generations, partial-inventory pure-negative semantics, no per-attestation revocation in v1, and adversarial S91–S94.
- Iteration 9 added exact key-state matrix, issuance-manifest binding/chain verification, rotation boundary and chain-tamper tests; made GateStore generation an internal value with expectation-only callers; and mechanically defined partial/unavailable plus hashed missing-source set.
- Iteration 10 fixed the universal manifest-digest byte definition and cross-component vectors, and split semantic inventory drift from observation freshness/transport metadata.
- Iteration 11 separated local attestation authority from hosted winner authority across protocol/state/reconciler/tests/acceptance/observability; fallback protocol explicitly uses `execution_trust_mode=github-hosted`.
- Iteration 12 added GateStore-clocked atomic local completion, shared winner linearization, transactional outbox and effectively-once dedicated-App Check mutation with exhaustive race/crash tests.
- Iteration 13 split local completion into attestation-authorized success and current-execution authoritative functional failure. The failure path remains valid after attestation expiry/revocation/drift only when its exact execution predicate holds and no winner exists; failure-first is final, GitHub-first fences late failure, and S101–S104 cover races, crashes, outbox ambiguity and impossible success conversion.
- Iteration 14 scoped invalid-proof fallback/fencing to the four current-authority boundaries, introduced immutable admission+marker creation after successful pre-marker verification, required authentic historical admission and authoritative `terminal_at<=deadline` for failure, classified admission mismatch as no-winner `CONTROL_FAILURE`, made D+1 evidence-only/fallback, and extended coverage through S108.

## Durable planning artifacts

- `docs/spec/spec-self-hosted-github-automation.md`
- `docs/spec/prd-self-hosted-github-automation.md`
- `docs/spec/test-spec-self-hosted-github-automation.md`
- `docs/spec/review-self-hosted-github-automation.md`

## Consensus receipt status

Even after local Architect/Critic approval, OMX requires a documented host-issued consensus receipt before execution handoff. No such verifier/receipt is available in this surface. The durable gate therefore remains incomplete with:

```text
blocked_reason=documented_host_consensus_receipt_unavailable
```
