# Runner network runtime

This runtime is installed inertly. Neither installer creates
`/etc/self-hosted-ci/ACTIVATION_APPROVED`, enables GARM, registers a runner, or
performs an external call.

When separately activated, `self-hosted-ci-network-policy.service` owns one
atomic nftables table. Traffic arriving from `ci-jit-isolated` can reach only
DHCP and the host-side ports `3128`, `8079`, and `8080`; forwarding in either direction
is dropped. Stopping the service atomically replaces those exceptions with a
bridge quarantine instead of removing the policy.

Port `3128` is a CONNECT-only Squid proxy. It accepts only TCP port 443 for the
GitHub domains documented for self-hosted runner operation. Destination-IP
ACLs are evaluated before the domain allow, so an allowed hostname resolving
to loopback, RFC1918, CGNAT, link-local, documentation, multicast, reserved,
or IPv6 local space is denied. Direct HTTP, arbitrary ports, arbitrary domains,
and direct IP targets are denied.

Port `8080` exposes only `GET/HEAD /api/v1/metadata[/...]` and
`POST /api/v1/callbacks[/...]` to the runner subnet. It forwards those requests
to GARM on `127.0.0.1:9997`; webhook, admin, controller, absolute-form and
oversized requests are rejected.

Port `8079` is the allocation broker's fixed host-only claim endpoint. It is
reachable only from `ci-jit-isolated`; the broker accepts only the bounded
`POST /v1/job-started` payload installed into the runner hook and revalidates
the signed allocation plus the live GitHub job before any workflow step runs.

GitHub can change its required domains. Before activation and at least weekly,
compare `packaging/network/squid.conf` with GitHub's self-hosted runner
communication requirements. Domain expansion is a reviewed source change;
the runtime never downloads or rewrites its own allowlist.

La allowlist no es una barrera general contra exfiltración: GitHub y Azure Blob
son servicios multi-tenant, por lo que un job no confiable puede comunicarse
con recursos del atacante dentro de dominios necesarios. Los jobs de pull
request reciben cero secretos reutilizables, claves privadas de la GitHub App,
credenciales del control plane o credenciales de deploy. Esos datos permanecen
fuera del container, su filesystem y su environment.
