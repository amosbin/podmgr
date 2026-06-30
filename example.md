# Relay Hub Usage Example

This file explains:
- current implementation status
- how to use what is already implemented
- how your original Traefik idea is achieved

## Current status

Implemented now:
- C collector: bin/podmgr-relay-collect
- C reconciler: bin/podmgr-relay-reconcile
- C hub daemon skeleton: bin/podmgr-relay-hubd
- C tenant relay daemon: bin/podmgr-relay-tenantd
- C request merger: bin/podmgr-relay-merge
- policy and enrollment examples

Not implemented yet:
- runtime reload workflow for conf changes
- systemd deployment integration in podmgr command surface

So the control plane is implemented, but the data plane is still pending.

## What this means for "does it work now"

- Enrollment and approval flow works now.
- Hub socket decision engine works now (ALLOW/DENY by policy snapshot).
- Hub can tunnel traffic in `action=proxy` mode to approved `tcp://` or `unix://` backends.
- Tenant relay process now exists and can be chained behind hub for cross-user data path.

## Build and test the current implementation

From project root:

```sh
cd c/podmgr
make
cd ../..
```

Collect an enrollment request from compose labels:

```sh
./bin/podmgr-relay-collect \
  --tenant traefik \
  --compose-json assets/relay-compose.example.json \
  --out /tmp/traefik-request.conf
```

Run policy reconciliation:

```sh
./bin/podmgr-relay-reconcile \
  --policy assets/relay-policy.example.conf \
  --request assets/relay-request.example.conf \
  --runtime-out /tmp/relay-runtime.conf
```

Merge per-tenant request files and generate runtime config:

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

Run tenant relay daemon (app1 example):

```sh
./bin/podmgr-relay-tenantd \
  --listen /tmp/podmgr-relay-app1.sock \
  --upstream tcp://127.0.0.1:19001
```

Run relay hub daemon skeleton:

```sh
./bin/podmgr-relay-hubd \
  --runtime-conf /tmp/relay-runtime.conf \
  --socket /tmp/podmgr-relay-hub.sock
```

Ask for a route decision (expected ALLOW):

```sh
printf 'source=traefik target=app1 host=app1.localhost path=/\n' | nc -U /tmp/podmgr-relay-hub.sock
```

Ask for proxy mode (expected first line `ALLOW`, then tunneled stream):

```sh
printf 'source=traefik target=app1 host=app1.localhost path=/ action=proxy\n' | nc -U /tmp/podmgr-relay-hub.sock
```

Ask for a denied decision (expected DENY):

```sh
printf 'source=app1 target=traefik host=app1.localhost path=/\n' | nc -U /tmp/podmgr-relay-hub.sock
```

Expected result:
- approved tenants appear in output
- approved routes appear in output
- denied list stays empty for valid sample data

## How your original Traefik goal is achieved

Original goal:
- Traefik can route to app containers by container DNS
- avoid broad host-port exposure
- keep per-user rootless isolation

Final architecture to achieve that:

1. Traefik runs under a dedicated podmgr user.
2. One hub daemon runs under a dedicated hub user and listens on one shared Unix socket.
3. Each workload user runs a local per-tenant relay process.
4. Per-tenant relay resolves local container DNS (inside that tenant boundary only).
5. Hub forwards only policy-approved routes to per-tenant relays.
6. Discoverers can discover/connect only to opted-in targets that share at least one group.
7. Discoverable-only tenants cannot discover peers.

This is how you preserve isolation while still enabling controlled cross-tenant routing.

## Label request example inside compose

Service labels in compose can request enrollment:

```yaml
services:
  traefik:
    image: traefik:v3.5
    labels:
      io.podmgr.relay.enabled: "true"
      io.podmgr.relay.mode: "discoverer"
      io.podmgr.relay.groups: "abc"
      io.podmgr.relay.source: "traefik"
      io.podmgr.relay.target: "app1"
      io.podmgr.relay.host: "app1.localhost"
      io.podmgr.relay.path_prefix: "/"
      io.podmgr.relay.backend: "http://app1:3000"
```

Important:
- labels are requests only
- policy file decides approval

## Policy example

```conf
hub_enabled=true
tenant traefik allow_enroll=true allowed_modes=discoverer allowed_groups=abc,ops
tenant app1 allow_enroll=true allowed_modes=discoverable allowed_groups=abc
```

## How to achieve the same routing right now (interim)

If you need working traffic today before relay daemons are added:

1. Run Traefik and app in the same podmgr user boundary.
2. Attach both to the same rootless network.
3. Route directly with container DNS (app1:3000).

Tradeoff:
- this gives immediate functionality
- but it does not keep strict per-user workload isolation

## Next implementation tasks (required for full multi-user runtime)

1. Add a hub runtime daemon in C (Unix socket server + forwarding engine).
2. Add a per-tenant relay runtime daemon in C.
3. Add a request merger for multiple tenant request files.
4. Add live apply pipeline from approved snapshot to runtime routes.
5. Add per-tenant relay runtime process and integrate hub proxy mode with those relay sockets.
6. Add anti-enumeration response behavior and audit logging.
7. Add runtime reload behavior for changed policy/runtime snapshots.
8. Add systemd user units for hub and per-tenant relays into podmgr lifecycle commands.
