# Relay Hub Feature Idea

The goal of podmgr was to make container isolation even more isolated and solid.
This helps with breakout mitigation by having each workload run under a least-privileged host system user.

This comes with trade-offs, such as: containers cannot share networks across different rootless users.
A practical solution is to stack components that need tight inter-communication in the same compose stack.
For example, Grafana, Loki, Prometheus, and Tempo can all run as separate images inside one compose file.

This should be the exception, not the rule. Overdoing it and putting all compose files and containers under the same user defeats the purpose of per-workload isolation at the host-user level (as many host system users as possible).

There are other cases, however, where one container needs to talk to many others, for example Traefik.
If a reverse proxy is needed, and you want Traefik to reach backends by DNS-style identity instead of publishing many host ports (and avoid port-conflict issues), that cannot happen directly when containers are split across different rootless users and isolated networks.

This is a valid niche. The exact size of this niche may not be known yet, but it is still valid.

podmgr can theoretically provide a relay-hub daemon to allow a packet path between isolated containers through sockets, without breaking either of these:

- keeping one container stack per isolated host system user
- rootless Podman

## Key architectural outline

1. Keep per-user isolation as the default:
	each tenant/workload still runs in its own rootless user and its own Podman network namespace.
2. Add a per-tenant relay sidecar/daemon (`podmgr-relay-tenantd`):
	it listens on a local Unix socket and forwards only to explicitly configured tenant-local upstreams.
3. Add one shared policy decision point (`podmgr-relay-hubd`):
	it receives relay queries on a Unix socket and returns ALLOW/DENY based on a generated runtime policy snapshot.
4. Generate runtime policy from declared intent + admin policy:
	use collector/merge/reconcile flow (`podmgr-relay-collect`, `podmgr-relay-merge`, `podmgr-relay-reconcile`) so requests are explicit, auditable, and default-deny.
5. Enforce explicit routing contracts:
	source tenant, target tenant, host/path matchers, and backend endpoint are all required for proxy actions.
6. Preserve least privilege:
	no shared podman network is introduced between tenants; communication is only through approved relay paths.
7. Keep revocation simple:
	removing or changing policy removes routes from runtime config, and the hub immediately denies unmatched traffic.

In short: relay hub should be an opt-in bridge for specific cross-tenant traffic, not a replacement for podmgr's isolation model.
