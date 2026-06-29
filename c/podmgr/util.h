#ifndef PODMGR_UTIL_H
#define PODMGR_UTIL_H

#include <sys/types.h>
#include <stddef.h>

/* Directory hint for podmgr assets when needed by helper code. */
extern char g_exe_dir[4096];

/* Trusted absolute paths for root-run helpers. */
#define PODMGR_BIN_ENV        "/usr/bin/env"
#define PODMGR_BIN_RM         "/usr/bin/rm"
#define PODMGR_BIN_CP         "/usr/bin/cp"
#define PODMGR_BIN_SUDO       "/usr/bin/sudo"
#define PODMGR_BIN_CHOWN      "/usr/bin/chown"
#define PODMGR_BIN_JOURNALCTL "/usr/bin/journalctl"
#define PODMGR_BIN_LOGINCTL   "/usr/bin/loginctl"
#define PODMGR_BIN_TEST       "/usr/bin/test"
#define PODMGR_BIN_PKGREP     "/usr/bin/pgrep"
#define PODMGR_BIN_PKILL      "/usr/bin/pkill"
#define PODMGR_BIN_PODMAN     "/usr/bin/podman"
#define PODMGR_BIN_SYSTEMCTL  "/usr/bin/systemctl"
#define PODMGR_BIN_GROUPADD   (podmgr_bin_groupadd())
#define PODMGR_BIN_USERADD    (podmgr_bin_useradd())
#define PODMGR_BIN_USERDEL    (podmgr_bin_userdel())
#define PODMGR_BIN_USERMOD    (podmgr_bin_usermod())
#define PODMGR_BIN_FSUBID     (podmgr_bin_fsubid())

void podmgr_init_binary_paths(void);
const char *podmgr_bin_groupadd(void);
const char *podmgr_bin_useradd(void);
const char *podmgr_bin_userdel(void);
const char *podmgr_bin_usermod(void);
const char *podmgr_bin_fsubid(void);

/* ---- subprocess helpers ------------------------------------------------- */

/*
 * Fork + execvp argv as the current user (root).  Stdin/stdout/stderr are
 * inherited.  Returns the child exit code, or -1 on fork/exec failure.
 */
int run_command(char *const argv[]);

/*
 * Like run_command but captures stdout into buf[bufsz-1] (NUL-terminated).
 * Stderr is inherited.  Returns child exit code.
 */
int run_capture(char *const argv[], char *buf, size_t bufsz);

/*
 * Run argv as `user` via sudo, with XDG_RUNTIME_DIR set.
 * Working directory is set to compose_dir in the target user context.
 * If compose_dir is NULL the default /srv/podmgr/compose/<user> is used.
 * Returns child exit code.
 */
int run_as_user(const char *user, const char *compose_dir,
                char *const argv[]);

/*
 * Like run_as_user but working directory is the user's home (/var/lib/<user>).
 */
int run_as_user_home(const char *user, char *const argv[]);

/*
 * Like run_as_user_home but captures stdout into buf[bufsz-1].
 */
int run_as_user_home_capture(const char *user, char *const argv[],
                             char *buf, size_t bufsz);

/*
 * Like run_as_user_home_capture but captures the FULL stdout into a freshly
 * malloc'd, NUL-terminated buffer with no size cap. On success *out points to
 * the buffer (caller must free) and the child exit code is returned. On
 * allocation/spawn failure *out is set to NULL and -1 is returned.
 */
int run_as_user_home_capture_dyn(const char *user, char *const argv[],
                                  char **out);

/*
 * Replace the current process (execvp) with argv running as `user` via sudo,
 * with cwd = compose_dir in the target user context and podman env vars set.
 * Used for interactive commands (do_exec) so the terminal is attached directly.
 * Never returns on success; calls log_die on failure.
 */
void exec_as_user(const char *user, const char *compose_dir,
                  char *const argv[]);

/* ---- filesystem helpers ------------------------------------------------- */

/*
 * Recursively remove `path` only if it starts with `prefix/<something>`.
 * Dies rather than removing anything outside the expected prefix.
 * Silently returns if path is absent or not a directory.
 */
void safe_rmrf(const char *path, const char *prefix);

/* Create `path` and all missing parents (like mkdir -p).  Returns 0 on ok. */
int makedirs_p(const char *path, mode_t mode);

/*
 * Copy `tpl_path` to `dest_path`, replacing "$USER", "$COMPOSE_DIR", and
 * "$COMPOSE_FILE" placeholders.
 * Returns 0 on success, -1 on I/O error (warns but does not die).
 */
int write_service_file(const char *tpl_path, const char *dest_path,
                       const char *user, const char *compose_dir);

/*
 * Remove the line(s) matching "<user>:…" from both /etc/subuid and /etc/subgid.
 */
void subid_remove_user(const char *user);

/* ---- locking ------------------------------------------------------------ */

/*
 * Acquire an exclusive, non-blocking per-user lock serialising lifecycle
 * operations (setup/cleanup/reinstall) for the same user. Lock file lives at
 * /run/podmgr/locks/<user>.lock. Dies if another podmgr already holds it.
 * Returns the lock fd (held open for the process lifetime); release with
 * user_lock_release().
 */
int  user_lock_acquire(const char *user);
void user_lock_release(int lock_fd);

/* ---- privilege ---------------------------------------------------------- */

/*
 * Strip dangerous inherited environment state and force a safe PATH before
 * any subprocesses are spawned.
 */
void sanitize_process_environment(void);

/*
 * Ensure the process is running as root for a lifecycle command named `cmd`.
 * If already root, returns. Otherwise, if sudo is available, re-exec the whole
 * podmgr invocation under `sudo` (argv/argc supplied). If neither is possible,
 * dies with a clear message.
 */
void ensure_root_or_reexec_sudo(const char *cmd, int argc, char *argv[]);

#endif /* PODMGR_UTIL_H */
