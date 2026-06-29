#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "commands.h"
#include "config.h"
#include "logging.h"
#include "validation.h"
#include "util.h"
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
#include <dirent.h>
#include <limits.h>
#include <signal.h>

#ifndef PODMGR_VERSION
#define PODMGR_VERSION "1.0.1-dev"
#endif

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

void do_cleanup(const char *user, const char *compose_dir)
{
    char home_dir[256];
    snprintf(home_dir, sizeof(home_dir), "/var/lib/%s", user);

    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);

    /* Serialise lifecycle ops for this user against concurrent podmgr runs. */
    int lock_fd = user_lock_acquire(user);

    if (!getpwnam(user)) {
        user_lock_release(lock_fd);
        log_info("user '%s' does not exist; nothing to clean up", user);
        return;
    }

    ensure_managed_user(user);

    log_info("cleaning up user '%s'", user);

    struct passwd *pw = getpwnam(user);
    uid_t uid = pw ? pw->pw_uid : (uid_t)-1;
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%u", (unsigned)uid);

    char runtime_dir[64];
    snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%u", (unsigned)uid);

    /*
     * Graceful teardown of containers and user services. Each step is its own
     * argv-based exec (no shell), and all are best-effort: failures are warned
     * about but never abort the teardown.
     */
    struct stat rst;
    if (uid != (uid_t)-1 && stat(runtime_dir, &rst) == 0) {
        /* compose down (in the compose dir). */
        char *compose_down[] = {
            PODMGR_BIN_PODMAN, "compose", "down", "--remove-orphans", NULL
        };
        run_as_user(user, compose_dir, compose_down);

        /* Disable the user's service and the podman socket. */
        char *disable_svc[] = {
            PODMGR_BIN_SYSTEMCTL, "--user", "disable", "--now", service_name, NULL
        };
        run_as_user_home(user, disable_svc);
        char *disable_sock[] = {
            PODMGR_BIN_SYSTEMCTL, "--user", "disable", "--now", "podman.socket", NULL
        };
        run_as_user_home(user, disable_sock);

        /* Stop and remove containers, prune resources, reset storage. */
        char *stop_all[]  = { PODMGR_BIN_PODMAN, "stop", "-a", "-t", "10", NULL };
        run_as_user_home(user, stop_all);
        char *rm_all[]    = { PODMGR_BIN_PODMAN, "rm", "-a", "-f", NULL };
        run_as_user_home(user, rm_all);
        char *net_prune[] = { PODMGR_BIN_PODMAN, "network", "prune", "-f", NULL };
        run_as_user_home(user, net_prune);
        char *vol_prune[] = { PODMGR_BIN_PODMAN, "volume", "prune", "-f", NULL };
        run_as_user_home(user, vol_prune);
        char *img_prune[] = { PODMGR_BIN_PODMAN, "image", "prune", "-a", "-f", NULL };
        run_as_user_home(user, img_prune);
        char *reset[]     = { PODMGR_BIN_PODMAN, "system", "reset", "-f", NULL };
        run_as_user_home(user, reset);
    }

    char *disable_linger[] = { PODMGR_BIN_LOGINCTL, "disable-linger", (char *)user, NULL };
    if (run_command(disable_linger) != 0)
        log_warn("could not disable linger for '%s'", user);

    /* SIGTERM then SIGKILL remaining user processes. */
    if (uid != (uid_t)-1) {
        char *pkterm[] = { PODMGR_BIN_PKILL, "-TERM", "-u", uid_str, NULL };
        run_command(pkterm); /* ignore return; no processes is also success */

        /* Grace period: wait up to 10 s for processes to exit. */
        for (int grace = 0; grace < 10; grace++) {
            char *pgrep[] = { PODMGR_BIN_PKGREP, "-u", uid_str, NULL };
            char chk[16] = {0};
            if (run_capture((char *const *)pgrep, chk, sizeof(chk)) != 0)
                break; /* no processes left */
            sleep(1);
        }
        char *pkkill[] = { PODMGR_BIN_PKILL, "-KILL", "-u", uid_str, NULL };
        run_command(pkkill);

        char user_at_svc[64];
        snprintf(user_at_svc, sizeof(user_at_svc), "user@%s.service", uid_str);
        char *stop_u[] = { PODMGR_BIN_SYSTEMCTL, "stop", user_at_svc, NULL };
        run_command(stop_u);

        char runtime_svc[64];
        snprintf(runtime_svc, sizeof(runtime_svc),
                 "user-runtime-dir@%s.service", uid_str);
        char *stop_r[] = { PODMGR_BIN_SYSTEMCTL, "stop", runtime_svc, NULL };
        run_command(stop_r);
    }

    /* Remove subuid/subgid entries. */
    subid_remove_user(user);

    char marker[PATH_MAX];
    managed_marker_path(user, marker, sizeof(marker));
    unlink(marker);

    safe_rmrf(compose_dir, g_cfg.base_dir);

    /* Delete the user (userdel also removes its home). */
    char *userdel[] = { (char *)PODMGR_BIN_USERDEL, "-r", (char *)user, NULL };
    if (run_command(userdel) != 0)
        log_warn("userdel for '%s' reported an issue", user);

    safe_rmrf(home_dir,    "/var/lib");

    if (uid != (uid_t)-1) {
        safe_rmrf(runtime_dir, "/run/user");

        char tmp_path[128];
        snprintf(tmp_path, sizeof(tmp_path), "/tmp/podman-run-%u", (unsigned)uid);
        safe_rmrf(tmp_path, "/tmp");
        snprintf(tmp_path, sizeof(tmp_path), "/tmp/containers-user-%u", (unsigned)uid);
        safe_rmrf(tmp_path, "/tmp");
        snprintf(tmp_path, sizeof(tmp_path), "/var/tmp/containers-user-%u", (unsigned)uid);
        safe_rmrf(tmp_path, "/var/tmp");
    }

    user_lock_release(lock_fd);
    log_info("removed user '%s' and all associated data", user);
}

/* ---- do_reinstall ------------------------------------------------------- */

void do_reinstall(const char *user, const char *compose_dir)
{
    if (getpwnam(user))
        ensure_managed_user(user);

    do_cleanup(user, compose_dir);
    do_setup(user, compose_dir);
    log_info("reinstalled user '%s'", user);
}

/* ---- operational commands ----------------------------------------------- */

void do_up(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 1);
    char *argv[] = { PODMGR_BIN_PODMAN, "compose", "up", "-d", NULL };
    int ret = run_as_user(user, compose_dir, argv);
    if (ret != 0)
        log_die("compose up failed for '%s' (exit %d)", user, ret);
}

void do_down(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 1);
    char *argv[] = { PODMGR_BIN_PODMAN, "compose", "down", NULL };
    int ret = run_as_user(user, compose_dir, argv);
    if (ret != 0)
        log_die("compose down failed for '%s' (exit %d)", user, ret);
}

void do_restart(const char *user, const char *compose_dir)
{
    do_down(user, compose_dir);
    do_up(user, compose_dir);
}

void do_start(const char *user)
{
    ensure_managed_user(user);
    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);
    char *argv[] = { PODMGR_BIN_SYSTEMCTL, "--user", "start", service_name, NULL };
    if (run_as_user_home(user, argv) != 0)
        log_die("failed to start service '%s' for '%s'", service_name, user);
}

void do_stop(const char *user)
{
    ensure_managed_user(user);
    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);
    char *argv[] = { PODMGR_BIN_SYSTEMCTL, "--user", "stop", service_name, NULL };
    if (run_as_user_home(user, argv) != 0)
        log_warn("could not stop service for '%s' (it may not be running)", user);
}

void do_kill(const char *user)
{
    ensure_managed_user(user);
    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);
    char *argv[] = { PODMGR_BIN_SYSTEMCTL, "--user", "stop", service_name, NULL };
    if (run_as_user_home(user, argv) != 0)
        log_warn("could not stop service for '%s' (it may not be running)", user);
    log_info("stopped service for '%s'", user);
}

void do_ps(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    char *argv[] = { PODMGR_BIN_PODMAN, "ps", NULL };
    if (run_as_user(user, compose_dir, argv) != 0)
        log_die("podman ps failed for '%s'", user);
}

void do_stats(const char *user, const char *compose_dir, int show_df)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    char *stats_argv[] = { PODMGR_BIN_PODMAN, "stats", "--no-stream", NULL };
    if (run_as_user(user, compose_dir, stats_argv) != 0)
        log_die("podman stats failed for '%s'", user);

    if (show_df) {
        char *df_argv[] = { PODMGR_BIN_PODMAN, "system", "df", NULL };
        if (run_as_user(user, compose_dir, df_argv) != 0)
            log_die("podman system df failed for '%s'", user);
    }
}

void do_prune(const char *user, const char *compose_dir, int all_images,
              int volumes)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);

    char *argv[8];
    int i = 0;
    argv[i++] = PODMGR_BIN_PODMAN;
    argv[i++] = "system";
    argv[i++] = "prune";
    argv[i++] = "-f";
    if (all_images) argv[i++] = "-a";
    if (volumes) argv[i++] = "--volumes";
    argv[i] = NULL;

    if (run_as_user(user, compose_dir, argv) != 0)
        log_die("podman system prune failed for '%s'", user);
}

void do_shell(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    char *argv[] = { "/bin/sh", "-l", NULL };
    exec_as_user(user, compose_dir, argv);
}

void do_run(const char *user, const char *compose_dir, char *const argv[])
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    if (!argv || !argv[0])
        log_die("run requires a command after '--'");
    if (run_as_user(user, compose_dir, argv) != 0)
        log_die("run failed for '%s'", user);
}

static const char *resolve_container(const char *user, const char *requested,
                                     char *buf, size_t bufsz)
{
    if (requested && requested[0] != '\0')
        return requested;

    char *ps_argv[] = { PODMGR_BIN_PODMAN, "ps", "--format", "{{.Names}}", NULL };
    char output[4096] = {0};
    if (run_as_user_home_capture(user, ps_argv, output, sizeof(output)) != 0)
        log_die("failed to discover running containers for '%s'", user);

    char *nl = strchr(output, '\n');
    if (nl) *nl = '\0';
    if (output[0] == '\0')
        log_die("no running container found for user '%s'", user);

    snprintf(buf, bufsz, "%s", output);
    return buf;
}

void do_exec(const char *user, const char *compose_dir, const char *container)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);

    char found_container[256] = {0};
    container = resolve_container(user, container, found_container,
                                  sizeof(found_container));

    /*
     * Probe for a usable shell inside the container; prefer bash, fall back
     * to sh.  Use a non-interactive exec to test availability.
     */
    const char *shells[] = { "bash", "sh", NULL };
    const char *chosen_shell = NULL;

    for (int si = 0; shells[si]; si++) {
        char probe_script[64];
        snprintf(probe_script, sizeof(probe_script),
                 "command -v %s", shells[si]);
        char *probe[] = {
            PODMGR_BIN_PODMAN, "exec", (char *)container,
            "sh", "-c", probe_script, NULL
        };
        char out[64] = {0};
        if (run_as_user_home_capture(user, probe, out, sizeof(out)) == 0 &&
            out[0] != '\0') {
            chosen_shell = shells[si];
            break;
        }
    }

    if (!chosen_shell)
        log_die("no usable shell (bash/sh) found in container '%s'", container);

    log_info("exec into '%s' (user '%s') using '%s'",
             container, user, chosen_shell);

    /*
     * Replace the podmgr process with an interactive podman exec session so
     * the terminal is directly connected with no intermediary.
     */
    char *exec_argv[] = {
        PODMGR_BIN_PODMAN, "exec", "-it", (char *)container, (char *)chosen_shell, NULL
    };
    exec_as_user(user, compose_dir, exec_argv);
    /* exec_as_user never returns on success. */
}

void do_run_in(const char *user, const char *compose_dir, const char *container,
               char *const argv[])
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    if (!argv || !argv[0])
        log_die("run-in requires a command after '--'");

    char found_container[256] = {0};
    container = resolve_container(user, container, found_container,
                                  sizeof(found_container));

    int argc = 0;
    while (argv[argc]) argc++;

    char **cmd = malloc((size_t)(5 + argc + 1) * sizeof(char *));
    if (!cmd)
        log_die("out of memory");

    int i = 0;
    cmd[i++] = PODMGR_BIN_PODMAN;
    cmd[i++] = "exec";
    cmd[i++] = (char *)container;
    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_as_user(user, compose_dir, cmd);
    free(cmd);
    if (ret != 0)
        log_die("run-in failed for container '%s'", container);
}

void do_clogs(const char *user, const char *compose_dir, const char *container)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    char found_container[256] = {0};
    container = resolve_container(user, container, found_container,
                                  sizeof(found_container));
    char *argv[] = { PODMGR_BIN_PODMAN, "logs", "-f", (char *)container, NULL };
    exec_as_user(user, compose_dir, argv);
}

void do_cp(const char *user, const char *compose_dir, char *const argv[])
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    if (!argv || !argv[0] || !argv[1])
        log_die("cp requires source and destination after '--'");

    int argc = 0;
    while (argv[argc]) argc++;
    char **cmd = malloc((size_t)(3 + argc + 1) * sizeof(char *));
    if (!cmd)
        log_die("out of memory");

    int i = 0;
    cmd[i++] = PODMGR_BIN_PODMAN;
    cmd[i++] = "cp";
    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_as_user(user, compose_dir, cmd);
    free(cmd);
    if (ret != 0)
        log_die("podman cp failed for '%s'", user);
}

void do_top(const char *user, const char *compose_dir, const char *container)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);
    char found_container[256] = {0};
    container = resolve_container(user, container, found_container,
                                  sizeof(found_container));
    char *argv[] = { PODMGR_BIN_PODMAN, "top", (char *)container, NULL };
    if (run_as_user(user, compose_dir, argv) != 0)
        log_die("podman top failed for container '%s'", container);
}

void do_adopt(const char *user, const char *compose_dir, const char *src_path)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);

    if (!src_path || src_path[0] == '\0')
        log_die("adopt requires a source path");

    struct stat src_st;
    if (lstat(src_path, &src_st) != 0)
        log_die("cannot access source '%s': %s", src_path, strerror(errno));

    if (S_ISLNK(src_st.st_mode))
        log_die("refusing to adopt symlink source '%s'", src_path);

    if (!S_ISREG(src_st.st_mode) && !S_ISDIR(src_st.st_mode))
        log_die("adopt supports only regular files and directories: %s", src_path);

    const char *base = path_basename_const(src_path);
    if (!base || base[0] == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        log_die("invalid source path for adopt: %s", src_path);

    char dest_path[PATH_MAX];
    if (snprintf(dest_path, sizeof(dest_path), "%s/%s", compose_dir, base) >= (int)sizeof(dest_path))
        log_die("destination path too long under compose-dir '%s'", compose_dir);

    struct stat dst_st;
    if (lstat(dest_path, &dst_st) == 0)
        log_die("destination already exists in compose-dir: %s", dest_path);
    if (errno != ENOENT)
        log_die("cannot inspect destination '%s': %s", dest_path, strerror(errno));

    char *copy_argv[] = {
        PODMGR_BIN_CP, "-a", "--", (char *)src_path, (char *)compose_dir, NULL
    };
    if (run_command(copy_argv) != 0)
        log_die("failed to copy '%s' into '%s'", src_path, compose_dir);

    char owner[128];
    snprintf(owner, sizeof(owner), "%s:%s", user, user);
    char *chown_argv[] = {
        PODMGR_BIN_CHOWN, "-R", owner, dest_path, NULL
    };
    if (run_command(chown_argv) != 0)
        log_die("failed to set ownership on adopted path '%s'", dest_path);

    log_info("adopted '%s' into '%s' for user '%s'", src_path, dest_path, user);
}

void do_journal(const char *user)
{
    struct passwd *pw = getpwnam(user);
    if (!pw) log_die("user '%s' not found", user);

    uid_t uid = pw->pw_uid;
    char uid_filter[32];
    snprintf(uid_filter, sizeof(uid_filter), "_UID=%u", (unsigned)uid);

    if (geteuid() != 0 && !current_user_in_group("systemd-journal"))
        log_die("journal requires root or membership in the 'systemd-journal' group");

    /* Replace podmgr with journalctl so the terminal is directly connected. */
    char *argv[] = { PODMGR_BIN_JOURNALCTL, uid_filter, "-f", NULL };
    execv(PODMGR_BIN_JOURNALCTL, argv);
    log_die("exec journalctl failed: %s", strerror(errno));
}

void do_status(const char *user, const char *compose_dir)
{
    (void)compose_dir;
    ensure_managed_user(user);

    char service_name[128];
    snprintf(service_name, sizeof(service_name), "%s.service", user);

    char out[256] = {0};
    char *svc[] = { PODMGR_BIN_SYSTEMCTL, "--user", "is-active", service_name, NULL };
    char *sock[] = { PODMGR_BIN_SYSTEMCTL, "--user", "is-active", "podman.socket", NULL };
    int svc_ret = run_as_user_home_capture(user, svc, out, sizeof(out));
    char svc_state[64];
    snprintf(svc_state, sizeof(svc_state), "%s", out[0] ? out : "unknown");
    char *nl = strchr(svc_state, '\n');
    if (nl) *nl = '\0';

    memset(out, 0, sizeof(out));
    int sock_ret = run_as_user_home_capture(user, sock, out, sizeof(out));
    char sock_state[64];
    snprintf(sock_state, sizeof(sock_state), "%s", out[0] ? out : "unknown");
    nl = strchr(sock_state, '\n');
    if (nl) *nl = '\0';

    printf("user=%s\n", user);
    printf("service=%s (%s)\n", svc_state, svc_ret == 0 ? "ok" : "not-active");
    printf("podman.socket=%s (%s)\n", sock_state, sock_ret == 0 ? "ok" : "not-active");
}

void do_info(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);

    struct passwd *pw = getpwnam(user);
    if (!pw)
        log_die("user '%s' not found", user);

    char marker[PATH_MAX];
    managed_marker_path(user, marker, sizeof(marker));
    struct stat mst;
    int marker_ok = (stat(marker, &mst) == 0 && S_ISREG(mst.st_mode));

    char uid_line[512] = {0};
    char gid_line[512] = {0};
    FILE *f = fopen("/etc/subuid", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, user, strlen(user)) == 0 && line[strlen(user)] == ':') {
                snprintf(uid_line, sizeof(uid_line), "%s", line);
                break;
            }
        }
        fclose(f);
    }
    f = fopen("/etc/subgid", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, user, strlen(user)) == 0 && line[strlen(user)] == ':') {
                snprintf(gid_line, sizeof(gid_line), "%s", line);
                break;
            }
        }
        fclose(f);
    }

    char linger[64] = {0};
    char *linger_argv[] = { PODMGR_BIN_LOGINCTL, "show-user", (char *)user,
                            "-p", "Linger", "--value", NULL };
    run_capture(linger_argv, linger, sizeof(linger));
    char *nl = strchr(linger, '\n');
    if (nl) *nl = '\0';

    char count_buf[4096] = {0};
    char *count_argv[] = { PODMGR_BIN_PODMAN, "ps", "-a", "-q", NULL };
    run_as_user_home_capture(user, count_argv, count_buf, sizeof(count_buf));
    int containers = 0;
    for (char *p = count_buf; *p; p++) if (*p == '\n') containers++;
    if (count_buf[0] != '\0' && count_buf[strlen(count_buf) - 1] != '\n') containers++;

    printf("user=%s uid=%u gid=%u\n", user, (unsigned)pw->pw_uid, (unsigned)pw->pw_gid);
    printf("managed-marker=%s (%s)\n", marker, marker_ok ? "present" : "missing");
    printf("compose-dir=%s\n", compose_dir);
    printf("linger=%s\n", linger[0] ? linger : "unknown");
    printf("subuid=%s", uid_line[0] ? uid_line : "(none)\n");
    printf("subgid=%s", gid_line[0] ? gid_line : "(none)\n");
    printf("containers=%d\n", containers);
}

void do_subid(const char *user)
{
    validate_user(user);
    char subuid_line[512] = {0};
    FILE *f = fopen("/etc/subuid", "r");
    if (f) {
        size_t user_len = strlen(user);
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, user, user_len) == 0 && line[user_len] == ':') {
                snprintf(subuid_line, sizeof(subuid_line), "%s", line);
                break;
            }
        }
        fclose(f);
    }

    if (subuid_line[0] == '\0') {
        puts("(no committed subuid/subgid allocation found for user)");
        return;
    }

    char *first_colon = strchr(subuid_line, ':');
    char *second_colon = first_colon ? strchr(first_colon + 1, ':') : NULL;
    if (!first_colon || !second_colon || second_colon == first_colon + 1)
        log_die("unexpected /etc/subuid format for user '%s'", user);

    *second_colon = '\0';
    const char *start = first_colon + 1;
    char *argv[] = { (char *)PODMGR_BIN_FSUBID, "status", "--start", (char *)start, NULL };
    if (run_command(argv) != 0)
        log_die("fsubid status failed for user '%s' (start=%s)", user, start);
}

void do_subid_check(void)
{
    char *argv[] = { (char *)PODMGR_BIN_FSUBID, "check", NULL };
    if (run_command(argv) != 0)
        log_die("fsubid check reported issues");
}

void do_subid_reclaim(void)
{
    char *argv[] = { (char *)PODMGR_BIN_FSUBID, "reclaim", NULL };
    if (run_command(argv) != 0)
        log_die("fsubid reclaim failed");
}

void do_version(void)
{
    printf("podmgr %s\n", PODMGR_VERSION);
}

/* ---- do_list ------------------------------------------------------------ */

static int cmp_str(const void *a, const void *b)
{
    /* a and b point to (char *) elements of the users array. */
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

typedef struct {
    char *user;
    char *container;
    char *image;
    char *ports;
    char *status;
} list_row_t;

static const size_t g_list_min_widths[5] = { 12, 24, 26, 22, 6 };
static const size_t g_list_max_widths[5] = { 16, 32, 40, 32, 24 };

/* Helper: escape JSON string (minimal implementation). */
static void json_escape_print(const char *str)
{
    if (!str) return;
    for (const char *p = str; *p; p++) {
        switch (*p) {
        case '"':  printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:   fputc(*p, stdout); break;
        }
    }
}

static void free_list_rows(list_row_t *rows, size_t row_count)
{
    if (!rows) return;
    for (size_t i = 0; i < row_count; i++) {
        free(rows[i].user);
        free(rows[i].container);
        free(rows[i].image);
        free(rows[i].ports);
        free(rows[i].status);
    }
    free(rows);
}

static int append_list_row(list_row_t **rows, size_t *row_count, size_t *row_cap,
                           const char *user, const char *container,
                           const char *image, const char *ports,
                           const char *status)
{
    if (*row_count == *row_cap) {
        size_t newcap = *row_cap ? *row_cap * 2 : 16;
        list_row_t *tmp = realloc(*rows, newcap * sizeof(**rows));
        if (!tmp) {
            log_warn("out of memory collecting list rows");
            return -1;
        }
        *rows = tmp;
        *row_cap = newcap;
    }

    list_row_t *row = &(*rows)[*row_count];
    row->user = strdup(user ? user : "");
    row->container = strdup(container ? container : "");
    row->image = strdup(image ? image : "");
    row->ports = strdup(ports ? ports : "");
    row->status = strdup(status ? status : "");
    if (!row->user || !row->container || !row->image || !row->ports || !row->status) {
        free(row->user);
        free(row->container);
        free(row->image);
        free(row->ports);
        free(row->status);
        row->user = row->container = row->image = row->ports = row->status = NULL;
        log_warn("out of memory collecting list rows");
        return -1;
    }

    (*row_count)++;
    return 0;
}

static size_t wrapped_line_count(const char *value, size_t width)
{
    size_t len = value ? strlen(value) : 0;
    if (width == 0 || len == 0)
        return 1;
    return (len + width - 1) / width;
}

static void print_cell_segment(const char *value, size_t width, size_t line_index)
{
    size_t len = value ? strlen(value) : 0;
    size_t start = line_index * width;

    if (start >= len) {
        printf("%-*s", (int)width, "");
        return;
    }

    size_t chunk_len = len - start;
    if (chunk_len > width)
        chunk_len = width;

    printf("%-*.*s", (int)width, (int)chunk_len, value + start);
}

static void print_rule_segment(size_t width)
{
    for (size_t i = 0; i < width; i++)
        putchar('-');
}

static void print_list_table(const list_row_t *rows, size_t row_count)
{
    static const char *headers[5] = { "USER", "CONTAINER", "IMAGE", "PORTS", "STATUS" };
    size_t widths[5];

    for (size_t i = 0; i < 5; i++) {
        size_t header_len = strlen(headers[i]);
        widths[i] = g_list_min_widths[i];
        if (widths[i] < header_len)
            widths[i] = header_len;
    }

    for (size_t i = 0; i < row_count; i++) {
        const char *values[5] = {
            rows[i].user,
            rows[i].container,
            rows[i].image,
            rows[i].ports,
            rows[i].status
        };

        for (size_t col = 0; col < 5; col++) {
            size_t len = values[col] ? strlen(values[col]) : 0;
            if (len > widths[col])
                widths[col] = len;
            if (widths[col] > g_list_max_widths[col])
                widths[col] = g_list_max_widths[col];
        }
    }

    printf("%-*s | %-*s | %-*s | %-*s | %-*s\n",
           (int)widths[0], headers[0],
           (int)widths[1], headers[1],
           (int)widths[2], headers[2],
           (int)widths[3], headers[3],
           (int)widths[4], headers[4]);
    print_rule_segment(widths[0]); printf("-+-");
    print_rule_segment(widths[1]); printf("-+-");
    print_rule_segment(widths[2]); printf("-+-");
    print_rule_segment(widths[3]); printf("-+-");
    print_rule_segment(widths[4]); putchar('\n');

    for (size_t i = 0; i < row_count; i++) {
        const char *values[5] = {
            rows[i].user,
            rows[i].container,
            rows[i].image,
            rows[i].ports,
            rows[i].status
        };
        size_t line_count = 1;

        for (size_t col = 0; col < 5; col++) {
            size_t cell_lines = wrapped_line_count(values[col], widths[col]);
            if (cell_lines > line_count)
                line_count = cell_lines;
        }

        for (size_t line = 0; line < line_count; line++) {
            print_cell_segment(values[0], widths[0], line); printf(" | ");
            print_cell_segment(values[1], widths[1], line); printf(" | ");
            print_cell_segment(values[2], widths[2], line); printf(" | ");
            print_cell_segment(values[3], widths[3], line); printf(" | ");
            print_cell_segment(values[4], widths[4], line); putchar('\n');
        }
    }
}

void do_list(int show_all, int as_json)
{
    /*
     * Collect managed users by scanning /var/lib for the marker file, into a
     * growable array (no fixed cap on the number of users).
     */
    char **users = NULL;
    size_t user_count = 0, user_cap = 0;

    DIR *d = opendir("/var/lib/podmgr/managed");
    if (!d) {
        if (errno == ENOENT) {
            if (as_json) {
                printf("[]\n");
            } else {
                printf("No podmgr-managed users found.\n");
            }
            return;
        }
        log_warn("cannot open /var/lib/podmgr/managed: %s", strerror(errno));
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char marker[PATH_MAX];
        snprintf(marker, sizeof(marker), "/var/lib/podmgr/managed/%s",
                 ent->d_name);
        struct stat mst;
        if (stat(marker, &mst) == 0 && S_ISREG(mst.st_mode) && mst.st_uid == 0) {
            if (user_count == user_cap) {
                size_t newcap = user_cap ? user_cap * 2 : 16;
                char **tmp = realloc(users, newcap * sizeof(*users));
                if (!tmp) { log_warn("out of memory listing users"); break; }
                users = tmp;
                user_cap = newcap;
            }
            users[user_count] = strdup(ent->d_name);
            if (users[user_count]) user_count++;
        }
    }
    closedir(d);

    if (user_count == 0) {
        if (as_json) {
            printf("[]\n");
        } else {
            printf("No podmgr-managed users found.\n");
        }
        free(users);
        return;
    }

    qsort(users, user_count, sizeof(*users), cmp_str);

    int has_results = 0;
    list_row_t *rows = NULL;
    size_t row_count = 0, row_cap = 0;

    for (size_t ui = 0; ui < user_count; ui++) {
        const char *uname = users[ui];
        if (!getpwnam(uname)) continue; /* user no longer exists */
        int user_has_results = 0;

        char *ps_argv[8];
        int pi = 0;
        ps_argv[pi++] = PODMGR_BIN_PODMAN;
        ps_argv[pi++] = "ps";
        if (show_all) ps_argv[pi++] = "-a";
        ps_argv[pi++] = "--format";
        ps_argv[pi++] = "{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}";
        ps_argv[pi]   = NULL;

        /* Capture the FULL output (grows as needed; no row is dropped). */
        char *output = NULL;
        if (run_as_user_home_capture_dyn(uname, ps_argv, &output) < 0 || !output)
            continue;

        char *line = output;
        while (*line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';

            if (line[0] != '\0') {
                char name[256]={0}, image[256]={0}, ports[256]={0}, status[256]={0};
                char *p = line, *q;

                /* snprintf guarantees NUL termination, unlike strncpy. */
                q = strchr(p, '|');
                if (q) { *q = '\0'; snprintf(name,  sizeof(name),  "%s", p); p = q+1; }
                q = strchr(p, '|');
                if (q) { *q = '\0'; snprintf(image, sizeof(image), "%s", p); p = q+1; }
                q = strchr(p, '|');
                if (q) { *q = '\0'; snprintf(ports, sizeof(ports), "%s", p); p = q+1; }
                snprintf(status, sizeof(status), "%s", p);

                if (name[0]) {
                    has_results = 1;
                    user_has_results = 1;
                    if (append_list_row(&rows, &row_count, &row_cap,
                                        uname, name, image, ports, status) != 0) {
                        free(output);
                        free_list_rows(rows, row_count);
                        for (size_t i = 0; i < user_count; i++)
                            free(users[i]);
                        free(users);
                        return;
                    }
                }
            }

            if (!nl) break;
            line = nl + 1;
        }

        free(output);

        if (!user_has_results) {
            has_results = 1;
            if (append_list_row(&rows, &row_count, &row_cap,
                                uname, "(no containers)", "", "", "") != 0) {
                free_list_rows(rows, row_count);
                for (size_t i = 0; i < user_count; i++)
                    free(users[i]);
                free(users);
                return;
            }
        }
    }

    for (size_t ui = 0; ui < user_count; ui++)
        free(users[ui]);
    free(users);

    if (!has_results) {
        printf("No podmgr-managed users found.\n");
        free_list_rows(rows, row_count);
        return;
    }

    if (as_json) {
        printf("[");
        for (size_t i = 0; i < row_count; i++) {
            if (i != 0) printf(",");
            printf("{\"user\":\"");
            json_escape_print(rows[i].user);
            printf("\",\"container\":");
            if (rows[i].container[0] == '\0' || strcmp(rows[i].container, "(no containers)") == 0) {
                printf("null");
            } else {
                printf("\"");
                json_escape_print(rows[i].container);
                printf("\"");
            }
            printf(",\"image\":");
            if (rows[i].image[0] == '\0') printf("null");
            else { printf("\""); json_escape_print(rows[i].image); printf("\""); }
            printf(",\"ports\":");
            if (rows[i].ports[0] == '\0') printf("null");
            else { printf("\""); json_escape_print(rows[i].ports); printf("\""); }
            printf(",\"status\":");
            if (rows[i].status[0] == '\0') printf("null");
            else { printf("\""); json_escape_print(rows[i].status); printf("\""); }
            printf("}");
        }
        printf("]\n");
    } else {
        print_list_table(rows, row_count);
    }

    free_list_rows(rows, row_count);
}

void do_users(int as_json)
{
    char **users = NULL;
    size_t user_count = 0, user_cap = 0;

    DIR *d = opendir("/var/lib/podmgr/managed");
    if (!d) {
        if (errno == ENOENT) {
            if (as_json) {
                printf("[]\n");
            } else {
                printf("No podmgr-managed users found.\n");
            }
            return;
        }
        log_warn("cannot open /var/lib/podmgr/managed: %s", strerror(errno));
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char marker[PATH_MAX];
        snprintf(marker, sizeof(marker), "/var/lib/podmgr/managed/%s",
                 ent->d_name);
        struct stat mst;
        if (stat(marker, &mst) == 0 && S_ISREG(mst.st_mode) && mst.st_uid == 0) {
            if (user_count == user_cap) {
                size_t newcap = user_cap ? user_cap * 2 : 16;
                char **tmp = realloc(users, newcap * sizeof(*users));
                if (!tmp) { log_warn("out of memory listing users"); break; }
                users = tmp;
                user_cap = newcap;
            }
            users[user_count] = strdup(ent->d_name);
            if (users[user_count]) user_count++;
        }
    }
    closedir(d);

    if (user_count == 0) {
        if (as_json) {
            printf("[]\n");
        } else {
            printf("No podmgr-managed users found.\n");
        }
        free(users);
        return;
    }

    qsort(users, user_count, sizeof(*users), cmp_str);

    if (as_json) {
        printf("[");
    }

    int printed = 0;
    int json_first = 1;
    for (size_t ui = 0; ui < user_count; ui++) {
        if (!getpwnam(users[ui])) continue;
        if (as_json) {
            if (!json_first) printf(",");
            printf("\"");
            json_escape_print(users[ui]);
            printf("\"");
            json_first = 0;
        } else {
            puts(users[ui]);
        }
        printed = 1;
    }

    for (size_t ui = 0; ui < user_count; ui++)
        free(users[ui]);
    free(users);

    if (as_json) {
        printf("]\n");
    } else if (!printed) {
        printf("No podmgr-managed users found.\n");
    }
}
