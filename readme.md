# podmgr

[![GitHub Repo](https://img.shields.io/badge/GitHub-podmgr-181717?logo=github)](https://github.com/amosbin/podmgr)
[![Language: C](https://img.shields.io/badge/Language-C-A8B9CC?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-333333?logo=linux&logoColor=white)](https://kernel.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

`podmgr` provisions and operates dedicated, least-privileged host users, each
running its own rootless Podman instance. One host user per trust boundary, so
that a container escape is contained to a single unprivileged account rather
than the operator's primary user.

## Rationale

Isolation is a primary defense, and its weakest point is escape. Once a process
or container breaks out, the remaining mitigations are limited. Podman's
rootless model already reduces that blast radius, but a single rootless user
that hosts every workload still concentrates risk: an escape lands in an account
that can see everything that user can see.

The stronger position is a dedicated host user per workload. An escape is then
bounded by an account that owns nothing but that one workload. The difficulty is
that standing up such a user correctly is tedious and error-prone: a system
account, an `XDG_RUNTIME_DIR`, a committed subordinate UID/GID range, session
linger, and a `systemd` user unit, repeated identically for every workload and
torn down cleanly on removal.

`podmgr` owns that lifecycle. It treats per-user separation as the default unit
of isolation and makes creating, operating, and removing those users a single,
auditable command path. Subordinate ID allocation is delegated to
[`fsubid`](https://github.com/amosbin/fsubid), which is the authoritative owner
of `/etc/subuid` and `/etc/subgid`.

## Design

`podmgr` is plain C11 with no third-party library dependencies. It never calls
`system(3)` or `popen(3)`; every external program is invoked by absolute path
via `execvp` on an explicit argument vector, with a sanitized environment, so
user-controlled strings are never interpreted as shell syntax. Privileged
operations are serialized per user with advisory locks, and `setup` rolls back a
partially provisioned user if any step fails.

Each managed user is marked by a file under its home directory; operational and
teardown commands refuse to act on users that do not carry that marker. By
design there is exactly one workload — one compose stack or Quadlet set — per
user. Separate trust boundaries mean separate users.

Architecture and module notes live in [`c/ARCHITECTURE.md`](c/ARCHITECTURE.md).

## Installation

On Ubuntu, install from the project PPA, which also provides the required
`fsubid` package:

```sh
sudo add-apt-repository ppa:amen8/podmgr
sudo apt update
sudo apt install podmgr
```

To build from source, see [`c/README.md`](c/README.md). The runtime depends on
`podman >= 6.0.0`, `passwd >= 4.19.4`, `sudo >= 1.9.17p2`,
`systemd >= 261.1`, and `fsubid >= 1.0.0`.
On platforms where `podman compose` delegates to an external provider,
install the provider package as required by your distribution.

## Usage

The general form is `podmgr <command> [options]`, with flags provided as
`-k value` or `--key value`. Flags may appear before or after the command as
long as they use their declared key. Lifecycle commands (`setup`, `cleanup`,
`reinstall`) require root and re-exec under `sudo` when needed. A full
reference is available with `podmgr --help` and in `man podmgr`.

Provision a user, then bring its workload up explicitly:

```sh
sudo podmgr setup -u app1
podmgr up -u app1
```

Commands are grouped by concern:

| Group | Commands |
| --- | --- |
| User lifecycle | `setup`, `cleanup`, `reinstall`, `list`, `info`, `status` |
| Podman engine | `up`, `down`, `restart`, `ps`, `stats`, `prune` |
| User session | `shell`, `run`, `start`, `stop`, `kill`, `journal` |
| Container access | `exec`, `run-in`, `clogs`, `cp`, `top` |
| Subordinate IDs | `subid`, `subid-check`, `subid-reclaim` |
| Other | `version` |

The compose directory defaults to `PODMGR_BASE_DIR/compose/<user>` and must be
absolute and inside `PODMGR_BASE_DIR`. `setup` creates this directory and
assigns it to the managed user; the shared `PODMGR_BASE_DIR` and
`PODMGR_BASE_DIR/compose` directories are kept as `podmgr:podmgr` with group
write/execute access, and the sudo-invoking operator is added to the `podmgr`
group when that identity can be validated from `SUDO_USER`/`SUDO_UID`.
Everything after `--` is passed verbatim to the target command for `run`,
`run-in`, and `cp`. Host filesystem mounts and ACL preparation are out of scope;
the operator prepares any additional bind-mount sources before or immediately
after `setup`. `setup` provisions the user and installs the workload unit, but
it does not start the workload; use `up` or `start` after setup.

## Configuration

`podmgr` reads `/etc/podmgr.conf` if present. All keys are optional and fall
back to compiled-in defaults.

| Key | Default | Purpose |
| --- | --- | --- |
| `LOG_DEST` | `file` | `file`, `journal`, or `both` |
| `LOG_FILE` | `/var/log/podmgr.log` | Log file path |
| `PODMGR_BASE_DIR` | `/srv/podmgr` | Base directory for compose directories |
| `COMPOSE_FILE` | `compose.yaml` | Compose file name |
| `USE_QUADLET` | off | Prefer Podman Quadlet when available |

## fsubid integration

`podmgr` does not manage subordinate IDs itself. During `setup` it asks `fsubid`
to allocate a free range and commit it, and the `subid*` commands delegate to
`fsubid` for inspection, auditing, and reclamation. `fsubid` is treated as a
trusted privileged component and is the sole writer of `/etc/subuid` and
`/etc/subgid`. A minimum `fsubid` version is pinned in the package dependencies;
the two projects evolve together under backward-compatible contracts.

## Stable interface (1.x)

This section records the parts of `podmgr` that are frozen for the 1.x series.
Anything listed here is a compatibility contract: it will not change in a
breaking way within 1.x. Anything not listed is an implementation detail and may
change at any time.

### Command surface

The following commands and their semantics are stable. New commands and new
options may be added; existing ones will not be removed or repurposed in 1.x.

- User lifecycle: `setup`, `cleanup`, `reinstall`, `list`, `info`, `status`
- Podman engine: `up`, `down`, `restart`, `ps`, `stats`, `prune`
- User session: `shell`, `run`, `start`, `stop`, `kill`, `journal`
- Container access: `exec`, `run-in`, `clogs`, `cp`, `top`
- Subordinate IDs: `subid`, `subid-check`, `subid-reclaim`
- Other: `version`, `--help`

`kill` is a permanent alias of `stop`.

### Options

`-u`/`--user`, `-c`/`--compose-dir`, `-n`/`--container`, `-a`/`--all`,
`-w`/`--volumes`, `-d`/`--df`, `-j`/`--json`, `-f`/`--file`, `-h`/`--help`,
and the `--` passthrough behave as documented in `man podmgr`. Short and long
forms are both stable.

### Configuration keys

The `/etc/podmgr.conf` keys `LOG_DEST`, `LOG_FILE`, `PODMGR_BASE_DIR`,
`COMPOSE_FILE`, and `USE_QUADLET`, with their documented
defaults, are stable. Unknown keys are ignored.

### Exit status

`0` indicates success. Any non-zero status indicates failure. `podmgr` does not
assign distinct meanings to specific non-zero codes in 1.x; callers should test
for zero versus non-zero.

### On-disk conventions

- Managed-user marker file under the user's home directory.
- Per-user compose directory under `PODMGR_BASE_DIR/compose/<user>` by default.
- Advisory locks under `/run/podmgr/`.

These paths are stable for 1.x.

### fsubid dependency contract

`podmgr` delegates all subordinate ID work to `fsubid` and depends on the
following `fsubid` command-line contract:

- `fsubid allocate <user>` prints a free range as `START:UID_SIZE:GID_SIZE`
  (the legacy `START:SIZE` form is also accepted).
- `fsubid commit --start <START> <user>` commits the allocated range.
- `fsubid release --start <START>` releases a reservation without committing.
- `fsubid status --start <START>` reports the state of a range.
- `fsubid check` audits the subordinate ID files.
- `fsubid reclaim` garbage-collects deleted users and stale reservations.

A minimum compatible `fsubid` version is pinned in the package dependencies.
`fsubid` is the sole writer of `/etc/subuid` and `/etc/subgid`; `podmgr` never
re-validates its writes. The two projects are released together and maintain
backward-compatible contracts across versions.

## License

MIT. See [LICENSE](LICENSE).
