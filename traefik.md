# Relay Hub Implementation (Phase 1)

This starts implementation for the rootless multi-user relay model:
- one shared relay hub
- default deny
- explicit tenant opt-in
- label-driven enrollment requests
- policy-gated approvals

## What is implemented now

1. `bin/podmgr-relay-collect` (C binary)
- Reads compose JSON (`podman compose config --format json` output).
- Extracts relay label requests from service labels.
- Emits request lines for the reconciler.

2. `bin/podmgr-relay-reconcile` (C binary)
- Applies admin policy to enrollment requests.
- Produces approved tenant+route runtime snapshot.

3. `bin/podmgr-relay-hubd` (C binary)
- Unix socket relay hub skeleton.
- Loads runtime authorization snapshot.
- Answers ALLOW/DENY decisions for route queries.
- Supports `action=proxy` to tunnel traffic to approved backend endpoints.

4. `bin/podmgr-relay-tenantd` (C binary)
- Per-tenant local relay daemon.
- Listens on tenant-local Unix socket and forwards to tenant-local upstream.

5. `bin/podmgr-relay-merge` (C binary)
- Merges multiple per-tenant request files into one request snapshot.

3. Example inputs
- `assets/relay-policy.example.conf`
- `assets/relay-request.example.conf`
- `assets/relay-request.traefik.example.conf`
- `assets/relay-request.app1.example.conf`
- `assets/relay-compose.example.json`
- `assets/relay-runtime.example.conf`

## Label keys (request side)

Use these labels in compose services:

- `io.podmgr.relay.enabled=true|false`
- `io.podmgr.relay.mode=discoverable|discoverer`
- `io.podmgr.relay.groups=abc,ops`
- `io.podmgr.relay.source=<tenant>`
- `io.podmgr.relay.target=<tenant>`
- `io.podmgr.relay.host=<fqdn>`
- `io.podmgr.relay.path_prefix=/`
- `io.podmgr.relay.backend=http://service:port`

Notes:
- labels are requests only
- approval still requires policy allow

## Policy model (approval side)

Policy file (`assets/relay-policy.example.conf`) controls:

- `hub_enabled`
- tenant `allow_enroll`
- tenant `allowed_modes`
- tenant `allowed_groups`

If a request is not allowed by policy, it is denied.

## Group and mode rules currently enforced

1. Hub must be enabled in policy.
2. Tenant must be allowed in policy and request `enabled=true`.
3. Requested mode must be allowed for that tenant.
4. Requested groups must be subset of allowed groups.
5. Route source must be an approved `discoverer`.
6. Source and target must share at least one group.
7. No group overlap means deny.
8. Proxy mode requires backend endpoint in supported scheme (`tcp://host:port` or `unix:///path`).

## Quick start commands

Build binaries:

```sh
cd c/podmgr
make
```

Collect label request for a tenant from compose JSON:

```sh
./bin/podmgr-relay-collect \
  --tenant traefik \
  --compose-json assets/relay-compose.example.json \
  --out /tmp/traefik-request.conf
```

Reconcile against policy:

```sh
./bin/podmgr-relay-reconcile \
  --policy assets/relay-policy.example.conf \
  --request assets/relay-request.example.conf \
  --runtime-out /tmp/relay-runtime.conf
```

Merge per-tenant requests then reconcile:

```sh
./bin/podmgr-relay-merge \
  --out /tmp/relay-request.merged.conf \
  assets/relay-request.traefik.example.conf \
  assets/relay-request.app1.example.conf

./bin/podmgr-relay-reconcile \
  --policy assets/relay-policy.example.conf \
  --request /tmp/relay-request.merged.conf \
  --runtime-out /tmp/relay-runtime.conf
```

Run a tenant relay daemon example:

```sh
./bin/podmgr-relay-tenantd \
  --listen /tmp/podmgr-relay-app1.sock \
  --upstream tcp://127.0.0.1:19001
```

Run the hub daemon skeleton:

```sh
./bin/podmgr-relay-hubd \
  --runtime-conf /tmp/relay-runtime.conf \
  --socket /tmp/podmgr-relay-hub.sock
```

Query ALLOW decision example:

```sh
printf 'source=traefik target=app1 host=app1.localhost path=/\n' | nc -U /tmp/podmgr-relay-hub.sock
```

Query ALLOW and start proxy tunnel:

```sh
printf 'source=traefik target=app1 host=app1.localhost path=/ action=proxy\n' | nc -U /tmp/podmgr-relay-hub.sock
```

Query DENY example:

```sh
printf 'source=app1 target=traefik host=app1.localhost path=/\n' | nc -U /tmp/podmgr-relay-hub.sock
```

## Next implementation steps

1. Add a merger tool for per-tenant request files into one hub request snapshot.
2. Add policy versioning + atomic write for generated runtime config.
3. Add anti-enumeration response profile in the runtime proxy layer.
4. Add explicit approvals workflow (`requested -> approved -> active -> revoked`).
5. Add runtime reload behavior for hub and tenant relays (SIGHUP or file watcher).