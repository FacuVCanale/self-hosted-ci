# Operational evidence

This directory intentionally contains no evidence from a real installation.
`make evidence` may write local validation artifacts here, but `.gitignore`
excludes every generated file.

Before enabling a repository, an operator should retain private evidence for:

- the exact GitHub App identity, permission set, and selected installation;
- runner-group repository scoping and ephemeral deregistration;
- host isolation, mount/interop denial, and workload network policy;
- immutable workflow and runtime revisions;
- signing-key bootstrap, rotation, revocation, and manifest continuity;
- successful sandbox execution and fail-closed fallback behavior;
- secret scanning and adversarial validation.

Evidence commonly contains repository names, installation and run identifiers,
hostnames, network topology, local paths, and security decisions. Store it in an
access-controlled evidence system, not in this public repository.
