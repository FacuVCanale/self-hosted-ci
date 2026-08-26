# Attestation key rotation

1. Fence new local dispatch while preserving GitHub fallback.
2. With explicit user presence, create a new online key outside the workspace and record only its public metadata.
3. Produce the next strictly monotonic offline-root-signed manifest: new key `active`, old key `retiring`, exact previous payload digest.
4. Verify the complete predecessor chain, absence of state rollback/revoked-key resurrection, exact JCS/domain digest, and offline-root signature.
5. Confirm the new active key signs exact targets and the retiring key cannot sign new proofs. Unexpired proofs issued while the old key was active may still verify.
6. Switch helper/control-plane public fingerprint, exercise all four verifier gates, and retain predecessor manifests required by unexpired proofs.
7. After the maximum 90-minute proof lifetime, publish another signed generation marking the old key `revoked`.
8. Prove old proofs reject immediately, new proofs pass, and lower/conflicting/skipped manifests reject; then restore eligible routing.

At any failure, retain the highest previously accepted manifest, keep local dispatch fenced, and use GitHub-hosted execution. Never delete a revoked key entry from successors.
