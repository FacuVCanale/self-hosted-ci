# Attestation key bootstrap

## Preconditions

- Local routing is disabled and the repository registry has no local-enabled entry.
- The offline Ed25519 root and online signing key are generated outside every repository/model workspace, preferably non-exportable and user-presence gated.
- The bounded helper accepts only typed repo/PR/head plus optional expected generation; it cannot sign stdin, files, arbitrary JSON or caller-chosen nonces.

## Ceremony

1. Generate the offline root with explicit local user presence; display SHA-256 of exact DER SPKI bytes.
2. The designated security approver independently verifies and explicitly pins that fingerprint. Do not infer or prefill it.
3. Generate an online Ed25519 or platform-native P-256 key in restrictive OS secure storage. Record only algorithm, immutable key ID/version and DER-SPKI SHA-256.
4. Build manifest generation `1`, with `previous_manifest_digest=null` and the online key `active`.
5. JCS-canonicalize the payload and compute the manifest digest over the exact manifest domain, NUL byte and payload—not the envelope.
6. Sign with the offline root using raw-64 Ed25519 and unpadded base64url; validate against `schemas/execution-trust-key-manifest-v1.schema.json`.
7. Import through the control plane, verify the root signature/fingerprint, persist generation/digest/predecessor chain, and read back exact accepted bytes.
8. Run positive public-key verification and negative tamper, unknown-key, wrong-digest, rollback and helper-arbitrary-input tests.
9. Update the non-secret authority policy only after all evidence passes; private material never enters this repository.

Any missing user-presence pin, schema/signature/digest mismatch, inaccessible secure store, or incomplete test leaves status `UNINITIALIZED` and routing GitHub-hosted.
