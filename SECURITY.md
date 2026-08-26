# Security policy

This repository contains public source code and synthetic examples only. Do
not report real credentials, installation identifiers, private repository
inventories, host addresses, network topology, or operational evidence in a
public issue.

For a suspected vulnerability, use GitHub's private vulnerability reporting
feature for this repository. Revoke or rotate affected credentials before
sharing diagnostic material.

The distributed workflows are inert by default. A deployment is not considered
safe merely because the source tree passes its tests: operators must separately
verify exact GitHub App permissions, repository selection, immutable Action
references, runner isolation, external state, and rollback behavior.
