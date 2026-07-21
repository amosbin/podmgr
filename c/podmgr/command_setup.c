#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "commands.h"
#include "config.h"
#include "logging.h"
#include "validation.h"
#include "util.h"
#include "command_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>

/* Setup/provisioning implementation and setup-scoped helpers. */
#ifndef PODMGR_VERSION
#error "PODMGR_VERSION not defined; build via the c/podmgr Makefile which sets -DPODMGR_VERSION=..."
#endif
/* A bare `-DPODMGR_VERSION=\"\"` (from `make` with no VERSION=) is just
 * as bad as no definition at all — it would print "podmgr " with no
 * version. sizeof is allowed in _Static_assert (it's a compile-time
 * constant expression), so we use it to reject the empty-string
 * case at compile time. A real version like "1.0.4" is 6 bytes
 * (5 chars + NUL); an empty "" is 1. */
_Static_assert(sizeof(PODMGR_VERSION) > 2,
    "PODMGR_VERSION is empty; pass VERSION=<x.y.z> to make "
    "(debian/rules does this via DEB_VERSION_UPSTREAM)");

typedef struct {
    int active;
    int created_user;
    char user[64];
    char compose_dir[PATH_MAX];
} setup_tx_t;

static setup_tx_t g_setup_tx;
static int g_setup_tx_registered = 0;

#define PODMGR_SHARED_USER  "podmgr"
#define PODMGR_SHARED_GROUP "podmgr"

static void setup_rollback_atexit(void)
{
    if (!g_setup_tx.active || !g_setup_tx.created_user)
        return;

    char marker[PATH_MAX];
    managed_marker_path(g_setup_tx.user, marker, sizeof(marker));
    unlink(marker);

    char *linger[] = { PODMGR_BIN_LOGINCTL, "disable-linger", g_setup_tx.user, NULL };
    run_command(linger);

    subid_remove_user(g_setup_tx.user);

    char *userdel[] = { (char *)PODMGR_BIN_USERDEL, "-r", g_setup_tx.user, NULL };
    run_command(userdel);
}

/* ---- internal helpers --------------------------------------------------- */

static int has_quadlet_suffix(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    return strcmp(dot, ".container") == 0 ||
           strcmp(dot, ".kube") == 0 ||
           strcmp(dot, ".pod") == 0 ||
           strcmp(dot, ".network") == 0 ||
           strcmp(dot, ".volume") == 0;
}

static int copy_regular_file(const char *src, const char *dst, mode_t mode)
{
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[8192];
    size_t n;
    int ok = 1;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = 0; break; }
    }
    if (ferror(in)) ok = 0;
    fclose(in);
    if (fclose(out) != 0) ok = 0;
    if (ok)
        chmod(dst, mode & 0777);
    return ok ? 0 : -1;
}

static int sync_quadlet_sources(const char *src_dir, const char *dst_dir)
{
    DIR *d = opendir(src_dir);
    if (!d) return 0;

    int copied = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.')
            continue;
        if (!has_quadlet_suffix(ent->d_name))
            continue;

        char src[PATH_MAX];
        char dst[PATH_MAX];
        struct stat st;
        if (snprintf(src, sizeof(src), "%s/%s", src_dir, ent->d_name) >= (int)sizeof(src) ||
            snprintf(dst, sizeof(dst), "%s/%s", dst_dir, ent->d_name) >= (int)sizeof(dst)) {
            log_warn("skipping Quadlet source '%s': resulting path too long", ent->d_name);
            continue;
        }
        if (stat(src, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (copy_regular_file(src, dst, st.st_mode) == 0)
            copied++;
        else
            log_warn("failed to sync Quadlet source '%s'", ent->d_name);
    }
    closedir(d);
    return copied;
}

static void ensure_dir_mode_owner(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
    struct stat st;

    if (stat(path, &st) != 0)
        log_die("cannot stat '%s': %s", path, strerror(errno));
    if (!S_ISDIR(st.st_mode))
        log_die("expected directory at '%s'", path);
    if (chown(path, uid, gid) != 0)
        log_die("cannot chown '%s' to %u:%u: %s",
                path, (unsigned)uid, (unsigned)gid, strerror(errno));
    if (chmod(path, mode) != 0)
        log_die("cannot chmod '%s' to %o: %s",
                path, (unsigned)mode, strerror(errno));
}

static const char *validated_invoking_user(void)
{
    const char *sudo_user = getenv("SUDO_USER");
    const char *sudo_uid = getenv("SUDO_UID");
    char *end = NULL;

    if (!sudo_user || !sudo_uid || sudo_user[0] == '\0' || sudo_uid[0] == '\0')
        return NULL;

    errno = 0;
    unsigned long uid_ul = strtoul(sudo_uid, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        log_warn("ignoring invalid SUDO_UID='%s' while checking podmgr group membership",
                 sudo_uid);
        return NULL;
    }

    struct passwd *pw = getpwuid((uid_t)uid_ul);
    if (!pw) {
        log_warn("ignoring SUDO_USER='%s': no passwd entry for uid %lu",
                 sudo_user, uid_ul);
        return NULL;
    }
    if (strcmp(pw->pw_name, sudo_user) != 0) {
        log_warn("ignoring mismatched sudo identity: SUDO_USER='%s' but uid %lu is '%s'",
                 sudo_user, uid_ul, pw->pw_name);
        return NULL;
    }
    if (strcmp(sudo_user, "root") == 0 || strcmp(sudo_user, PODMGR_SHARED_USER) == 0)
        return NULL;

    return sudo_user;
}

static void ensure_shared_base_access(void)
{
    struct group *grp = getgrnam(PODMGR_SHARED_GROUP);
    if (!grp) {
        char *groupadd[] = {
            (char *)PODMGR_BIN_GROUPADD, "-r", (char *)PODMGR_SHARED_GROUP, NULL
        };
        if (run_command(groupadd) != 0)
            log_die("failed to create system group '%s'", PODMGR_SHARED_GROUP);
        grp = getgrnam(PODMGR_SHARED_GROUP);
        if (!grp)
            log_die("group '%s' was not found after creation", PODMGR_SHARED_GROUP);
    }

    struct passwd *svc = getpwnam(PODMGR_SHARED_USER);
    if (!svc) {
        char *useradd[] = {
            (char *)PODMGR_BIN_USERADD,
            "-r", "-M",
            "-d", "/nonexistent",
            "-s", "/usr/sbin/nologin",
            "-g", (char *)PODMGR_SHARED_GROUP,
            (char *)PODMGR_SHARED_USER,
            NULL
        };
        if (run_command(useradd) != 0)
            log_die("failed to create system user '%s'", PODMGR_SHARED_USER);
        svc = getpwnam(PODMGR_SHARED_USER);
        if (!svc)
            log_die("user '%s' was not found after creation", PODMGR_SHARED_USER);
    }

    if (svc->pw_gid != grp->gr_gid) {
        char *usermod_primary[] = {
            (char *)PODMGR_BIN_USERMOD,
            "-g", (char *)PODMGR_SHARED_GROUP,
            (char *)PODMGR_SHARED_USER,
            NULL
        };
        if (run_command(usermod_primary) != 0)
            log_die("failed to set primary group '%s' for user '%s'",
                    PODMGR_SHARED_GROUP, PODMGR_SHARED_USER);
        svc = getpwnam(PODMGR_SHARED_USER);
        if (!svc || svc->pw_gid != grp->gr_gid)
            log_die("user '%s' is not using primary group '%s'",
                    PODMGR_SHARED_USER, PODMGR_SHARED_GROUP);
    }

    const char *invoking_user = validated_invoking_user();
    if (invoking_user) {
        char *usermod_group[] = {
            (char *)PODMGR_BIN_USERMOD,
            "-a", "-G", (char *)PODMGR_SHARED_GROUP,
            (char *)invoking_user,
            NULL
        };
        if (run_command(usermod_group) != 0)
            log_die("failed to add '%s' to group '%s'",
                    invoking_user, PODMGR_SHARED_GROUP);
    }

    if (makedirs_p(g_cfg.base_dir, 02775) != 0)
        log_die("cannot create base dir '%s': %s", g_cfg.base_dir, strerror(errno));

    char compose_root[PATH_MAX];
    snprintf(compose_root, sizeof(compose_root), "%s/compose", g_cfg.base_dir);
    if (makedirs_p(compose_root, 02775) != 0)
        log_die("cannot create compose root '%s': %s", compose_root, strerror(errno));

    ensure_dir_mode_owner(g_cfg.base_dir, svc->pw_uid, grp->gr_gid, 02775);
    ensure_dir_mode_owner(compose_root, svc->pw_uid, grp->gr_gid, 02775);
}

static int current_user_in_group(const char *group_name)
{
    struct group *gr = getgrnam(group_name);
    if (!gr) return 0;

    gid_t target = gr->gr_gid;
    if (getegid() == target)
        return 1;

    int ng = getgroups(0, NULL);
    if (ng <= 0)
        return 0;

    gid_t *groups = malloc((size_t)ng * sizeof(gid_t));
    if (!groups)
        return 0;

    int ok = 0;
    if (getgroups(ng, groups) == ng) {
        for (int i = 0; i < ng; i++) {
            if (groups[i] == target) { ok = 1; break; }
        }
    }
    free(groups);
    return ok;
}

static const char *path_basename_const(const char *path)
{
    if (!path || !*path)
        return path;

    const char *end = path + strlen(path);
    while (end > path && end[-1] == '/')
        end--;
    if (end == path)
        return "/";

    const char *p = end;
    while (p > path && p[-1] != '/')
        p--;
    return p;
}

static void alloc_subid_range(const char *user)
{
    char start_str[32] = {0};
    char output[128] = {0};
    char *fsubid_argv[] = { (char *)PODMGR_BIN_FSUBID, "allocate", (char *)user, NULL };
    if (run_capture(fsubid_argv, output, sizeof(output)) != 0)
        log_die("fsubid failed to allocate a range for '%s'", user);

    /* Trim trailing whitespace / newline. */
    size_t olen = strlen(output);
    while (olen > 0 && (output[olen-1] == '\n' || output[olen-1] == '\r' ||
                        output[olen-1] == ' '))
        output[--olen] = '\0';

    /*
     * Parse fsubid output.
     * Supported formats:
     *   START:SIZE                 (legacy)
     *   START:UID_SIZE:GID_SIZE    (current)
     */
    long start = 0;
    long uid_size = 0;
    long gid_size = 0;
    if (sscanf(output, "%ld:%ld:%ld", &start, &uid_size, &gid_size) == 3) {
        /* parsed current format */
    } else if (sscanf(output, "%ld:%ld", &start, &uid_size) == 2) {
        gid_size = uid_size;
    } else {
        log_die("fsubid returned invalid output: '%s'", output);
    }

    if (start <= 0 || uid_size <= 0 || gid_size <= 0)
        log_die("fsubid returned invalid range sizes: %ld:%ld:%ld",
                start, uid_size, gid_size);

    snprintf(start_str, sizeof(start_str), "%ld", start);

    /* Commit via fsubid so it owns the actual /etc/subuid + /etc/subgid writes. */
    char *commit_argv[] = { (char *)PODMGR_BIN_FSUBID, "commit", "--start", start_str,
                            (char *)user, NULL };
    if (run_command(commit_argv) != 0) {
        char *release_argv[] = { (char *)PODMGR_BIN_FSUBID, "release", "--start", start_str, NULL };
        run_command(release_argv);
        log_die("fsubid failed to commit the allocated range for '%s'", user);
    }
}

/*
 * Detect whether Podman's Quadlet generator is available on this host. Quadlet
 * ships as /usr/lib/systemd/user-generators/podman-system-generator (and the
 * libexec path on some distros). When present, podman generates user units
 * from *.container / *.kube files automatically, so podmgr can defer unit
 * generation to it instead of writing a raw .service.
 */
static int quadlet_available(void)
{
    const char *candidates[] = {
        "/usr/lib/systemd/user-generators/podman-user-generator",
        "/usr/libexec/podman/quadlet",
        "/usr/lib/systemd/system-generators/podman-system-generator",
        NULL
    };
    struct stat st;
    for (int i = 0; candidates[i]; i++)
        if (stat(candidates[i], &st) == 0)
            return 1;
    return 0;
}

/*
 * Check that a Quadlet source file contains the section header `section`
 * (e.g. "[Container]") and, somewhere after it, a non-empty assignment for the
 * mandatory key `key` (e.g. "Image"). Leading whitespace is tolerated. Returns
 * 1 if both are present, else 0. This is a lightweight sanity check, not a full
 * Quadlet parser: it catches the "empty / missing required field" case.
 */
static int quadlet_file_has(const char *path, const char *section, const char *key)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int in_section = 0, ok = 0;
    size_t key_len = strlen(key);
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        /* Skip leading whitespace. */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\0') continue;

        if (*p == '[') {
            in_section = (strncmp(p, section, strlen(section)) == 0);
            continue;
        }

        if (in_section && strncmp(p, key, key_len) == 0) {
            const char *q = p + key_len;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '=') {
                q++;
                while (*q == ' ' || *q == '\t') q++;
                if (*q != '\n' && *q != '\0' && *q != '\r') { ok = 1; break; }
            }
        }
    }
    fclose(f);
    return ok;
}

/*
 * Count the *valid* Quadlet source files in `dir`. A file is valid when its
 * type carries the mandatory key for that type:
 *   .container -> [Container] Image=...
 *   .kube      -> [Kube]      Yaml=...
 *   .pod/.network/.volume     (structural; accepted if present, they support
 *                              empty bodies and are only useful alongside a
 *                              .container/.kube which we validate strictly)
 * Returns the number of valid container/kube units found.
 */
static int count_valid_quadlet_units(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    int valid = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot) continue;

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

        if (strcmp(dot, ".container") == 0) {
            if (quadlet_file_has(full, "[Container]", "Image"))
                valid++;
            else
                log_warn("Quadlet file '%s' is missing a [Container] Image= key; ignoring",
                         ent->d_name);
        } else if (strcmp(dot, ".kube") == 0) {
            if (quadlet_file_has(full, "[Kube]", "Yaml"))
                valid++;
            else
                log_warn("Quadlet file '%s' is missing a [Kube] Yaml= key; ignoring",
                         ent->d_name);
        }
    }
    closedir(d);
    return valid;
}

/*
 * Render the per-user containers.conf content that pins the rootless
 * default log driver to k8s-file. Shared by the provisioning-time write
 * in do_setup (root, direct fopen) and the up-time self-heal (written
 * as the managed user via sudo).
 */
static void format_containers_conf(char *buf, size_t sz, const char *user)
{
    snprintf(buf, sz,
             "# Managed by podmgr. Do not edit by hand; rerun\n"
             "# `podmgr setup -u %s` (or cleanup+setup) to regenerate.\n"
             "#\n"
             "# Forces the rootless podman default log driver away from\n"
             "# `journald` to `k8s-file` so `podman logs` and `podmgr clogs`\n"
             "# work without the user systemd instance being started. See\n"
             "# `podmgr clogs --help` for the operational rationale.\n"
             "\n"
             "[containers]\n"
             "log_driver = \"k8s-file\"\n",
             user);
}

/*
 * TOML-escape a single string value for registries.conf output.
 */
static void toml_escape_string(const char *src, char *dst, size_t dstsz)
{
    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 1 < dstsz; si++) {
        char c = src[si];
        if ((c == '\\' || c == '"') && di + 2 < dstsz) {
            dst[di++] = '\\';
            dst[di++] = c;
            continue;
        }
        if (c == '\n' || c == '\r') {
            if (di + 2 < dstsz) {
                dst[di++] = '\\';
                dst[di++] = 'n';
            }
            continue;
        }
        dst[di++] = c;
    }
    dst[di] = '\0';
}

/*
 * Render the per-user registries.conf content that defines unqualified image
 * resolution defaults for managed users only. Compose files remain untouched;
 * fully-qualified image names in compose continue to be authoritative.
 */
static void format_registries_conf(char *buf, size_t sz, const char *user)
{
    char escaped_registry[512];
    toml_escape_string(g_cfg.default_unqualified_registry,
                       escaped_registry, sizeof(escaped_registry));

    snprintf(buf, sz,
             "# Managed by podmgr. Do not edit by hand; rerun\n"
             "# `podmgr setup -u %s` (or cleanup+setup) to regenerate.\n"
             "#\n"
             "# Provides managed-user defaults for unqualified image names\n"
             "# (for example `nginx:alpine`). Fully-qualified image names\n"
             "# in compose files always take precedence.\n"
             "\n"
             "unqualified-search-registries = [\"%s\"]\n",
             user, escaped_registry);
}

/*
 * Write the per-user containers.conf that pins the rootless default log
 * driver to k8s-file (see the rationale comment at the call site in
 * do_setup). Provisioning-time variant: do_setup runs privileged and the
 * user's home skeleton is root-owned at this point (the recursive chown
 * to the managed user happens later in do_setup), so a direct write plus
 * explicit chown is correct here — and only here.
 *
 * Idempotent: unconditionally rewrites the managed file. An explicit
 * `logging:` driver in a compose file still takes precedence; this only
 * sets podman's *default*. Note the driver is baked in at container
 * creation, so pre-existing journald containers need a down+up to pick
 * this up.
 */
static void write_user_containers_conf(const char *user, const char *home_dir,
                                       uid_t uid, gid_t gid)
{
    char conf_dir[PATH_MAX];
    snprintf(conf_dir, sizeof(conf_dir), "%s/.config/containers", home_dir);
    if (makedirs_p(conf_dir, 0755) != 0)
        log_die("makedirs_p '%s': %s", conf_dir, strerror(errno));

    char conf_path[PATH_MAX];
    snprintf(conf_path, sizeof(conf_path), "%s/containers.conf", conf_dir);
    FILE *cf = fopen(conf_path, "w");
    if (!cf)
        log_die("cannot write per-user containers.conf '%s': %s",
                conf_path, strerror(errno));
    char content[1024];
    format_containers_conf(content, sizeof(content), user);
    fputs(content, cf);
    fclose(cf);

    /* Rootless podman runs as the managed user; hand it the files. */
    if (chown(conf_dir, uid, gid) != 0)
        log_die("chown '%s': %s", conf_dir, strerror(errno));
    if (chown(conf_path, uid, gid) != 0)
        log_die("chown '%s': %s", conf_path, strerror(errno));
}

/*
 * Write the per-user registries.conf file (or remove it when defaults are
 * disabled). Setup-time variant: runs while the home skeleton is still
 * root-owned and then hands ownership back to the managed user.
 */
static void write_user_registries_conf(const char *user, const char *home_dir,
                                       uid_t uid, gid_t gid)
{
    char conf_dir[PATH_MAX];
    snprintf(conf_dir, sizeof(conf_dir), "%s/.config/containers", home_dir);
    if (makedirs_p(conf_dir, 0755) != 0)
        log_die("makedirs_p '%s': %s", conf_dir, strerror(errno));

    char conf_path[PATH_MAX];
    snprintf(conf_path, sizeof(conf_path), "%s/registries.conf", conf_dir);

    if (!g_cfg.default_registry_enable ||
        g_cfg.default_unqualified_registry[0] == '\0') {
        if (unlink(conf_path) != 0 && errno != ENOENT)
            log_die("cannot remove per-user registries.conf '%s': %s",
                    conf_path, strerror(errno));
        if (chown(conf_dir, uid, gid) != 0)
            log_die("chown '%s': %s", conf_dir, strerror(errno));
        return;
    }

    FILE *rf = fopen(conf_path, "w");
    if (!rf)
        log_die("cannot write per-user registries.conf '%s': %s",
                conf_path, strerror(errno));

    char content[2048];
    format_registries_conf(content, sizeof(content), user);
    fputs(content, rf);
    fclose(rf);

    if (chown(conf_dir, uid, gid) != 0)
        log_die("chown '%s': %s", conf_dir, strerror(errno));
    if (chown(conf_path, uid, gid) != 0)
        log_die("chown '%s': %s", conf_path, strerror(errno));
}

/*
 * Up-time self-heal variant. podmgr's operational commands are invoked
 * WITHOUT root: privilege only enters through the narrow sudo-as-user
 * path (build_sudo_prefix) that every per-user podman call already uses.
 * So the conf must be created *as the managed user* through that same
 * path — never with a direct root write from the caller's context. The
 * file then lands owned by the managed user with its own umask, which is
 * exactly what rootless podman expects; no chown, no root involvement.
 *
 * The content is passed as a positional argument to sh (not interpolated
 * into the script), so no shell-quoting of the payload is needed.
 *
 * Failure is a warning, not fatal: `up` must not be blocked by the
 * self-heal, but the operator is told logs may stay on journald.
 */
void ensure_user_containers_conf(const char *user)
{
    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);

    char content[1024];
    format_containers_conf(content, sizeof(content), user);

    char reg_content[2048];
    format_registries_conf(reg_content, sizeof(reg_content), user);

    const char *registry_enabled =
        (g_cfg.default_registry_enable &&
         g_cfg.default_unqualified_registry[0] != '\0') ? "1" : "0";

    char *argv[] = {
        "/bin/sh", "-c",
        "mkdir -p -- \"$HOME/.config/containers\" && "
        "printf '%s' \"$1\" > \"$HOME/.config/containers/containers.conf\" && "
        "if [ \"$2\" = \"1\" ]; then "
        "  printf '%s' \"$3\" > \"$HOME/.config/containers/registries.conf\"; "
        "else "
        "  rm -f -- \"$HOME/.config/containers/registries.conf\"; "
        "fi",
        "sh", content, (char *)registry_enabled, reg_content, NULL
    };
    if (run_as_user(user, home, argv) != 0) {
        log_warn("could not refresh containers.conf for '%s'; "
                 "containers may fall back to the journald log driver "
                 "(empty 'podmgr clogs' output)", user);
        if (registry_enabled[0] == '1')
            log_warn("could not refresh registries.conf for '%s'; "
                     "unqualified image pulls may fail", user);
    }
}

/* ---- do_setup ----------------------------------------------------------- */

void do_setup(const char *user, const char *compose_dir)
{
    if (!g_setup_tx_registered) {
        atexit(setup_rollback_atexit);
        g_setup_tx_registered = 1;
    }
    memset(&g_setup_tx, 0, sizeof(g_setup_tx));
    g_setup_tx.active = 1;
    snprintf(g_setup_tx.user, sizeof(g_setup_tx.user), "%s", user);
    snprintf(g_setup_tx.compose_dir, sizeof(g_setup_tx.compose_dir), "%s", compose_dir);

    char home_dir[256];
    snprintf(home_dir, sizeof(home_dir), "/var/lib/%s", user);

    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);

    /* Serialise lifecycle ops for this user against concurrent podmgr runs. */
    int lock_fd = user_lock_acquire(user);

    /* Hard-stop if the user already exists. */
    if (getpwnam(user)) {
        user_lock_release(lock_fd);
        log_die("user '%s' already exists; use 'reinstall' to reconfigure it",
                user);
    }

    log_info("creating system user '%s'", user);
    char *useradd[] = {
        (char *)PODMGR_BIN_USERADD, "-r", "-d", home_dir,
        "-s", "/usr/sbin/nologin", (char *)user, NULL
    };
    if (run_command(useradd) != 0)
        log_die("useradd failed for '%s'", user);
    g_setup_tx.created_user = 1;

    /* Re-read passwd after creation. */
    struct passwd *pw = getpwnam(user);
    if (!pw) log_die("user '%s' not found after creation", user);
    uid_t uid = pw->pw_uid;
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%u", (unsigned)uid);

    ensure_shared_base_access();
    ensure_compose_dir_ownership_or_absence(user, compose_dir);

    /* Create home subdirectories. */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.config/systemd/user", home_dir);
    if (makedirs_p(path, 0755) != 0) log_die("makedirs_p '%s': %s", path, strerror(errno));
    snprintf(path, sizeof(path), "%s/.config/environment.d", home_dir);
    if (makedirs_p(path, 0755) != 0) log_die("makedirs_p '%s': %s", path, strerror(errno));
    snprintf(path, sizeof(path), "%s/.local/share", home_dir);
    if (makedirs_p(path, 0755) != 0) log_die("makedirs_p '%s': %s", path, strerror(errno));

    /*
     * Write systemd environment.d (KEY=VALUE, no 'export').
     *
     * IMPORTANT: the rootless XDG env lives HERE, not in the per-service unit.
     * The systemd *user manager* (user@<uid>.service) reads environment.d and
     * applies it to EVERY unit in the user session. So whether the workload is
     * run by podmgr's compose .service or by a Quadlet-generated unit, both
     * inherit the same XDG_RUNTIME_DIR. Deferring unit generation to Quadlet
     * therefore does not lose the env.
     */
    char env_file[PATH_MAX];
    snprintf(env_file, sizeof(env_file), "%s/.config/environment.d/podman.conf", home_dir);
    FILE *ef = fopen(env_file, "w");
    if (!ef) log_die("cannot write environment.d file: %s", strerror(errno));
    fprintf(ef, "XDG_RUNTIME_DIR=/run/user/%u\n", (unsigned)uid);
    fclose(ef);

    /*
     * Force the per-user default log driver to k8s-file.
     *
     * Why: on Ubuntu 24.04 + podman 4.9.x the distro-shipped default in
     * /usr/share/containers/containers.conf is `journald`. With the journald
     * driver, `podman logs` only returns data when the managed user's
     * systemd --user instance is running and has a journal socket, so
     * journald-logged containers can appear to have empty logs and break
     * `podmgr clogs` for both live and post-mortem use cases.
     *
     * k8s-file writes to ~/.local/share/containers/storage/overlay-containers/
     * <id>/userdata/ctr.log, a regular file `podman logs` reads directly. No
     * user instance required. Survives container exit.
     *
     * Scoped to ~/.config/containers/containers.conf for this user only —
     * does NOT touch /etc/containers, so other consumers on the host are
     * unaffected.
     */
    write_user_containers_conf(user, home_dir, uid, pw->pw_gid);
    write_user_registries_conf(user, home_dir, uid, pw->pw_gid);

    /* Place managed marker. */
    char marker[PATH_MAX];
    managed_marker_path(user, marker, sizeof(marker));
    char marker_dir[PATH_MAX];
    snprintf(marker_dir, sizeof(marker_dir), "/var/lib/podmgr/managed");
    if (makedirs_p(marker_dir, 0755) != 0)
        log_die("cannot create managed marker dir '%s': %s", marker_dir, strerror(errno));
    FILE *mf = fopen(marker, "w");
    if (!mf)
        log_die("cannot write managed marker '%s': %s", marker, strerror(errno));
    fclose(mf);

    /* chown -R user:user /var/lib/<user> */
    char usercolon[128];
    snprintf(usercolon, sizeof(usercolon), "%s:%s", user, user);
    char *chown_home[] = { PODMGR_BIN_CHOWN, "-R", usercolon, home_dir, NULL };
    run_command(chown_home);

    /* Keep the management marker root-owned and outside the user's home. */
    char *chown_marker_dir[] = { PODMGR_BIN_CHOWN, "-R", "root:root", "/var/lib/podmgr", NULL };
    run_command(chown_marker_dir);

    /* loginctl enable-linger */
    char *linger[] = { PODMGR_BIN_LOGINCTL, "enable-linger", (char *)user, NULL };
    if (run_command(linger) != 0)
        log_die("failed to enable linger for '%s'", user);

    /* Allocate subuid/subgid via fsubid + usermod (under lock). */
    log_info("allocating subuid/subgid range for '%s'", user);
    alloc_subid_range(user);

    /*
     * Create the per-user compose dir if absent, then hand it to the user.
     * The shared base/compose directories stay owned by podmgr:podmgr with a
     * setgid bit so operators in the podmgr group can traverse them, while the
     * per-user leaf remains owned by the managed system user.
     */
    if (makedirs_p(compose_dir, 0750) != 0)
        log_die("cannot create compose dir '%s': %s", compose_dir, strerror(errno));
    char *chown_c[] = { PODMGR_BIN_CHOWN, "-R", usercolon, (char *)compose_dir, NULL };
    run_command(chown_c);

    /*
     * Unit generation: prefer Podman Quadlet when enabled and available, since
     * it natively generates user units from Quadlet source files. podmgr still
     * owns the per-user provisioning; only the unit generation is delegated.
     * Otherwise fall back to writing our compose-based .service.
     */
    int use_quadlet = 0;
    if (g_cfg.use_quadlet) {
        if (!quadlet_available()) {
            log_warn("USE_QUADLET is set but no Quadlet generator was found; "
                     "falling back to the compose .service template");
        } else {
            /*
             * Only defer to Quadlet if the compose dir contains at least one
             * *valid* unit (correct required keys). An empty or malformed
             * Quadlet file would otherwise make podman generate nothing while
             * setup still reported success.
             */
            int valid = count_valid_quadlet_units(compose_dir);
            if (valid > 0) {
                use_quadlet = 1;
            } else {
                log_warn("USE_QUADLET is set but no valid Quadlet units were "
                         "found in '%s'; falling back to the compose .service "
                         "template", compose_dir);
            }
        }
    }

    if (use_quadlet) {
        log_info("Quadlet enabled and valid units found; deferring unit "
                 "generation to podman for '%s' (skipping compose .service "
                 "template)", user);
        /* Quadlet units live in ~/.config/containers/systemd/. */
        char quadlet_dir[PATH_MAX];
        snprintf(quadlet_dir, sizeof(quadlet_dir),
                 "%s/.config/containers/systemd", home_dir);
        if (makedirs_p(quadlet_dir, 0755) != 0)
            log_warn("could not create Quadlet dir '%s': %s",
                     quadlet_dir, strerror(errno));
        char *chown_q[] = { PODMGR_BIN_CHOWN, "-R", usercolon, quadlet_dir, NULL };
        run_command(chown_q);

        int copied = sync_quadlet_sources(compose_dir, quadlet_dir);
        if (copied <= 0 || count_valid_quadlet_units(quadlet_dir) <= 0) {
            log_warn("Quadlet was requested but no valid source units were synced "
                     "to '%s'; falling back to compose service template", quadlet_dir);
            use_quadlet = 0;
        }
    }

    if (!use_quadlet) {
        /* Write systemd unit from template. */
        char tpl_path[PATH_MAX];
        snprintf(tpl_path, sizeof(tpl_path), "%s/podman-workload.service.tpl",
                 g_cfg.template_dir);

        struct stat tst;
        if (stat(tpl_path, &tst) != 0)
            log_die("service template not found at '%s'", tpl_path);

        char target_unit[PATH_MAX];
        snprintf(target_unit, sizeof(target_unit),
                 "%s/.config/systemd/user/%s", home_dir, service_name);

        if (write_service_file(tpl_path, target_unit, user, compose_dir) != 0)
            log_die("failed to write service unit file '%s'", target_unit);

        char *chown_unit[] = { PODMGR_BIN_CHOWN, usercolon, target_unit, NULL };
        run_command(chown_unit);
    }

    /* Start the per-user systemd instance. */
    char user_at_service[64];
    snprintf(user_at_service, sizeof(user_at_service), "user@%s.service", uid_str);
    char *start_user[] = { PODMGR_BIN_SYSTEMCTL, "start", user_at_service, NULL };
    if (run_command(start_user) != 0)
        log_die("failed to start %s", user_at_service);

    /* Wait up to 30 s for the runtime directory to appear. */
    char runtime_dir[64];
    snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%u", (unsigned)uid);
    int waited = 0;
    struct stat rst;
    while (stat(runtime_dir, &rst) != 0 && waited < 30) {
        char *failed_check[] = { PODMGR_BIN_SYSTEMCTL, "is-failed", user_at_service, NULL };
        if (run_command(failed_check) == 0)
            log_die("%s entered failed state while waiting for %s",
                    user_at_service, runtime_dir);
        sleep(1);
        waited++;
    }
    if (stat(runtime_dir, &rst) != 0)
        log_die("runtime dir %s never appeared after %ds", runtime_dir, waited);

    /* daemon-reload, install the workload unit, and enable podman.socket. */
    char *daemon_reload[] = { PODMGR_BIN_SYSTEMCTL, "--user", "daemon-reload", NULL };
    if (run_as_user_home(user, daemon_reload) != 0)
        log_die("systemctl --user daemon-reload failed for '%s'", user);

    /*
     * podman system migrate (best-effort). Deferred until here, after the
     * per-user systemd instance is started and /run/user/<uid> is confirmed,
     * so podman runs inside a live user session and uses the systemd cgroup
     * manager instead of warning and falling back to cgroupfs.
     */
    char *migrate[] = { PODMGR_BIN_PODMAN, "system", "migrate", NULL };
    if (run_as_user_home(user, migrate) != 0)
        log_warn("podman system migrate reported an issue (continuing)");

    if (use_quadlet) {
        /*
         * Quadlet-generated units are named after the *.container file, not
         * <user>.service. setup only provisions the user session and installs
         * the source files; it does not start the workload.
         *
         * Verify the generator actually produced at least one unit: after
         * daemon-reload, `systemctl --user list-unit-files` should report units
         * whose source is the Quadlet dir. If none appear, the source files
         * were structurally accepted by us but rejected by podman's generator,
         * so we warn loudly rather than report a misleading success.
         */
        char *list_units[] = {
            PODMGR_BIN_SYSTEMCTL, "--user", "list-units", "--all", "--type=service",
            "--no-legend", "--plain", NULL
        };
        char *units_out = NULL;
        run_as_user_home_capture_dyn(user, list_units, &units_out);
        if (!units_out || units_out[0] == '\0')
            log_warn("Quadlet was selected for '%s' but no user services are "
                     "present after daemon-reload; check the unit files with "
                     "'podman ... systemctl --user status'", user);
        else
            log_info("Quadlet units for '%s' were installed; start them explicitly after setup",
                     user);
        free(units_out);
    } else {
        char *enable_svc[] = { PODMGR_BIN_SYSTEMCTL, "--user", "enable",
                               service_name, NULL };
        if (run_as_user_home(user, enable_svc) != 0)
            log_die("failed to enable service '%s' for '%s'", service_name, user);
    }

    char *enable_sock[] = { PODMGR_BIN_SYSTEMCTL, "--user", "enable", "--now",
                            "podman.socket", NULL };
    if (run_as_user_home(user, enable_sock) != 0)
        log_warn("could not enable podman.socket for '%s' (continuing)", user);

    g_setup_tx.active = 0;
    user_lock_release(lock_fd);
    log_info("created user '%s'", user);
}

/* ---- do_cleanup --------------------------------------------------------- */

