# Attestation key compromise

1. Immediately fence all local gates and select GitHub-hosted routing where no winner exists.
2. Revoke helper access and the compromised online key in its OS secure store. Preserve only redacted audit evidence.
3. With offline-root user presence, publish the next chained manifest marking the compromised key/version `revoked`; revoked is permanent.
4. Invalidate every proof under that key at dispatch, claim, pre-marker admission and local-success. There is no individual-attestation revocation API in v1.
5. Do not erase authentic historical admissions: only an exact timely functional failure may conclude from one; it can never authorize success.
6. Generate a replacement online key, publish it active in a later signed manifest, and repeat bootstrap negative/positive tests.
7. Audit nonce bindings, admission/marker records, winners, outbox mutations and unexpected verifier decisions. Rotate related credentials if exposure may extend beyond the signing key.
8. Re-enable only after independent verification; otherwise remain GitHub-only.

Never place private-key bytes, recovery phrases, tokens or transcript content in incident notes.
