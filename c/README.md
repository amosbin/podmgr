# podmgr — C project

This directory contains the C implementation of `podmgr`.

`fsubid` is now maintained in a separate repository and is consumed as a
runtime dependency.

## Directory layout

```
c/
├── README.md           ← this file
├── ARCHITECTURE.md     ← module layout, data-flow, design choices
├── PLANNING.md         ← rewrite progress, decisions, outstanding work
└── podmgr/
    ├── main.c          ← argument parsing and command dispatch
    ├── config.{h,c}    ← /etc/podmgr.conf loader and global config struct
    ├── logging.{h,c}   ← log_info / log_warn / log_die
    ├── validation.{h,c}← username / path / managed-marker checks
    ├── util.{h,c}      ← process execution helpers, file utilities
    ├── commands.{h,c}  ← all do_* command implementations
    └── Makefile
```

## Building

```sh
cd podmgr && make && sudo make install
```

The Makefiles install:

| Artifact                          | Destination                            |
|-----------------------------------|----------------------------------------|
| `podmgr`                          | `/usr/local/bin/podmgr`                |
| `podman-workload.service.tpl`     | `/usr/lib/podmgr/`                     |

`podmgr setup` requires `fsubid` to be available in `PATH`.

After installation copy the template from the shell tree:

```sh
sudo mkdir -p /usr/lib/podmgr
sudo cp ../assets/podman-workload.service.tpl /usr/lib/podmgr/
```

## Runtime requirements

- Linux (uses `flock(2)`, `/proc`, systemd user-session conventions)
- GCC ≥ 9 or Clang ≥ 10, `make`
- At runtime: `podman >= 6.0.0` (with `podman compose` available),
  `systemd >= 261.1` (`systemctl`, `loginctl`, `journalctl`),
  `shadow >= 4.19.4` (`useradd`, `usermod`, `userdel`),
  `sudo >= 1.9.17p2`, `fsubid >= 1.0.0`

## Manual compose placement workflow

For the default layout (`/srv/podmgr/compose/<user>`), the expected flow is:

1. `sudo podmgr setup -u <user>`
2. Place `compose.yaml` or `compose.yml` into `/srv/podmgr/compose/<user>/`
    - Preferred helper: `sudo podmgr adopt -u <user> -i ./compose.yaml`
    - To choose a compose-relative destination: `sudo podmgr adopt -u <user> -i ./config -o app/config`
3. Ensure ownership remains `<user>:<user>` for the per-user directory and
    compose file
4. Run lifecycle commands such as `podmgr up -u <user>`

The shared directories (`/srv/podmgr` and `/srv/podmgr/compose`) are managed
as group-writable for the `podmgr` group. If operators still need `sudo` to
place files, verify that they are in the `podmgr` group and that the directory
modes were not changed.

When runtime preflight fails, fix ownership and mode first:

```sh
sudo chown -R <user>:<user> /srv/podmgr/compose/<user>
sudo chmod 750 /srv/podmgr/compose/<user>
sudo chmod 640 /srv/podmgr/compose/<user>/compose.yaml
# or compose.yml if you use that name
```
