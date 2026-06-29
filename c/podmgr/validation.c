#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "validation.h"
#include "logging.h"
#include "config.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>

char *managed_marker_path(const char *user, char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "/var/lib/podmgr/managed/%s", user);
    return buf;
}

void validate_user(const char *user)
{
    if (!user || user[0] == '\0')
        log_die("username is empty");

    /* Must start with [a-z_]. */
    if (!((user[0] >= 'a' && user[0] <= 'z') || user[0] == '_'))
        log_die("invalid username '%s' (must start with [a-z_])", user);

    size_t len = strlen(user);
    if (len > 32)
        log_die("invalid username '%s' (too long, max 32 characters)", user);

    for (size_t i = 1; i < len; i++) {
        char c = user[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            log_die("invalid username '%s' (allowed: [a-z_][a-z0-9_-]{0,31})",
                    user);
    }

    if (strcmp(user, "root") == 0)
        log_die("refusing to operate on root");
}

void ensure_managed_user(const char *user)
{
    char marker[PATH_MAX];
    managed_marker_path(user, marker, sizeof(marker));

    struct stat st;
    if (stat(marker, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0)
        log_die("refusing to operate: user '%s' is not managed by podmgr "
                "(missing %s)", user, marker);
}

void validate_compose_dir(const char *compose_dir)
{
    const char *base_dir = g_cfg.base_dir;

    if (base_dir[0] != '/')
        log_die("PODMGR_BASE_DIR must be an absolute path (got '%s')", base_dir);

    if (compose_dir[0] != '/')
        log_die("compose-dir must be an absolute path (got '%s')", compose_dir);

    /* Reject control characters to block template/systemctl injection. */
    for (const char *p = compose_dir; *p; p++) {
        if ((unsigned char)*p < 0x20)
            log_die("compose-dir contains control characters; refusing");
    }

    size_t base_len = strlen(base_dir);
    if (strncmp(compose_dir, base_dir, base_len) != 0 ||
        compose_dir[base_len] != '/' ||
        compose_dir[base_len + 1] == '\0')
        log_die("compose-dir '%s' must be under '%s'", compose_dir, base_dir);
}

void ensure_compose_dir_ownership_or_absence(const char *user,
                                             const char *compose_dir)
{
    struct stat st;
    if (stat(compose_dir, &st) != 0)
        return; /* absent is fine */

    if (!S_ISDIR(st.st_mode))
        log_die("compose-dir exists but is not a directory: %s", compose_dir);

    struct passwd *pw = getpwnam(user);
    if (!pw)
        log_die("user '%s' not found in passwd", user);

    if (st.st_uid != pw->pw_uid)
        log_die("compose-dir must not pre-exist unless owned by '%s': %s "
                "(current owner uid %u)", user, compose_dir,
                (unsigned)st.st_uid);
}

void ensure_compose_runtime_ready(const char *user,
                                  const char *compose_dir,
                                  int require_compose_file)
{
    struct passwd *pw = getpwnam(user);
    if (!pw)
        log_die("user '%s' not found in passwd", user);

    struct stat st;
    if (stat(compose_dir, &st) != 0) {
        if (errno == ENOENT)
            log_die("compose-dir does not exist: %s (run 'podmgr setup %s' first)",
                    compose_dir, user);
        if (errno == EACCES)
            log_die("compose-dir is not accessible: %s (check parent directory permissions)",
                    compose_dir);
        log_die("cannot stat compose-dir '%s': %s", compose_dir, strerror(errno));
    }

    if (!S_ISDIR(st.st_mode))
        log_die("compose-dir is not a directory: %s", compose_dir);

    if (st.st_uid != pw->pw_uid)
        log_die("compose-dir must be owned by '%s': %s (current owner uid %u)",
                user, compose_dir, (unsigned)st.st_uid);

    if ((st.st_mode & S_IXUSR) == 0)
        log_die("compose-dir is not traversable by owner '%s': %s (owner execute bit missing)",
                user, compose_dir);

    if (!require_compose_file)
        return;

    const char *primary_name = g_cfg.compose_file;
    const char *fallback_name = NULL;
    if (strcmp(primary_name, "compose.yaml") == 0)
        fallback_name = "compose.yml";
    else if (strcmp(primary_name, "compose.yml") == 0)
        fallback_name = "compose.yaml";

    char compose_path[PATH_MAX];
    if (snprintf(compose_path, sizeof(compose_path), "%s/%s",
                 compose_dir, primary_name) >= (int)sizeof(compose_path))
        log_die("compose file path is too long under compose-dir '%s'", compose_dir);

    /*
     * Preflight runs as the invoking operator. The per-user compose directory
     * is intentionally restrictive (owner-traversable), so a root-level stat
     * can report EACCES even though the target user can read the file. Probe
     * readability in the target user's context first.
     */
    char *probe_argv[] = { PODMGR_BIN_TEST, "-r", compose_path, NULL };
    int probe_ret = run_as_user(user, compose_dir, probe_argv);
    if (probe_ret != 0 && fallback_name) {
        char fallback_path[PATH_MAX];
        if (snprintf(fallback_path, sizeof(fallback_path), "%s/%s",
                     compose_dir, fallback_name) >= (int)sizeof(fallback_path))
            log_die("compose file path is too long under compose-dir '%s'", compose_dir);

        char *probe_fallback_argv[] = { PODMGR_BIN_TEST, "-r", fallback_path, NULL };
        int fallback_probe_ret = run_as_user(user, compose_dir, probe_fallback_argv);
        if (fallback_probe_ret == 0)
            snprintf(compose_path, sizeof(compose_path), "%s", fallback_path);
    }

    if (stat(compose_path, &st) != 0) {
        int primary_errno = errno;
        if (primary_errno != ENOENT) {
            if (primary_errno == EACCES) {
                if (probe_ret == 0)
                    return;
                log_die("compose file is not accessible: %s", compose_path);
            }
            log_die("cannot stat compose file '%s': %s", compose_path, strerror(primary_errno));
        }

        if (fallback_name) {
            char fallback_path[PATH_MAX];
            if (snprintf(fallback_path, sizeof(fallback_path), "%s/%s",
                         compose_dir, fallback_name) >= (int)sizeof(fallback_path))
                log_die("compose file path is too long under compose-dir '%s'", compose_dir);

            if (stat(fallback_path, &st) == 0) {
                snprintf(compose_path, sizeof(compose_path), "%s", fallback_path);
            } else {
                int fallback_errno = errno;
                if (fallback_errno == EACCES) {
                    char *probe_fallback_argv[] = { PODMGR_BIN_TEST, "-r", fallback_path, NULL };
                    if (run_as_user(user, compose_dir, probe_fallback_argv) == 0)
                        return;
                    log_die("compose file is not accessible: %s", fallback_path);
                }
                if (fallback_errno != ENOENT)
                    log_die("cannot stat compose file '%s': %s", fallback_path,
                            strerror(fallback_errno));
                log_die("compose file is missing in '%s' (expected '%s' or '%s')",
                        compose_dir, primary_name, fallback_name);
            }
        } else {
            log_die("compose file is missing: %s (expected '%s')",
                    compose_path, primary_name);
        }
    }

    if (!S_ISREG(st.st_mode))
        log_die("compose file is not a regular file: %s", compose_path);

    if (st.st_uid != pw->pw_uid)
        log_die("compose file must be owned by '%s': %s (current owner uid %u)",
                user, compose_path, (unsigned)st.st_uid);

    if ((st.st_mode & S_IRUSR) == 0)
        log_die("compose file is not readable by owner '%s': %s (owner read bit missing)",
                user, compose_path);
}
