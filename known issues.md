# known issues

## custom compose project network fails on some distro stacks

### issue

On some distro dependency stacks, `podmgr up` fails when Compose uses the default project network (for example `test_default`) with:

- `unable to find network with name or ID <project>_default: network not found`

### where it happens (dependency layer responsible)

This happens in the runtime dependency layer, not in podmgr compose parsing.

podmgr is not the component producing this failure.

- Podman rootless networking path
- netavark/aardvark network backend path
- compose provider behavior (`podman compose` delegating to `podman-compose` on affected systems)

### divergence

Expected:

- project default network is created and then usable by containers in the same run

Actual:

1. network create succeeds
2. network inspect succeeds
3. container start/attach fails with `network not found`

### workaround

Use an explicit external default network that maps to the rootless built-in `podman` network:

```yaml
services:
  web:
    image: docker.io/library/nginx:alpine
    ports:
      - "8080:80"
networks:
  default:
    external: true
    name: podman
```

  ### why no automatic patch in podmgr

  podmgr does not mutate user compose files.

  Reason:

  1. user file integrity and ownership
  2. clear, explicit user control over networking choices
  3. root cause is dependency/runtime behavior, not a user compose syntax defect

## unqualified image names fail when host registries are unset

### issue

On hosts with no unqualified-search registries configured, unqualified image
names (for example `nginx:alpine`) can fail to resolve.

### podmgr behavior

podmgr now writes a per-managed-user `registries.conf` default under the
managed user's container config directory. By default this sets unqualified
resolution to `docker.io` for podmgr-managed users only.

Compose files remain untouched. Fully-qualified image names in compose always
take precedence over defaults.

### recommendation

Use fully-qualified image names in compose when possible for explicit source
control and portability.
