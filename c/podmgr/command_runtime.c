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

/* Runtime/service/shell operations outside direct container exec flows. */
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

static void validate_adopt_output(const char *path)
{
    if (!path || path[0] == '\0')
        log_die("adopt output path must not be empty");
    if (path[0] == '/')
        log_die("adopt output path must be relative to the compose directory: %s", path);

    const char *component = path;
    for (const char *p = path;; p++) {
        if (*p == '/' || *p == '\0') {
            size_t len = (size_t)(p - component);
            if (len == 0 || (len == 1 && component[0] == '.') ||
                (len == 2 && component[0] == '.' && component[1] == '.'))
                log_die("adopt output path contains an invalid component: %s", path);
            if (*p == '\0')
                break;
            component = p + 1;
        }
    }
}

static void prepare_adopt_parent(const char *compose_dir, const char *dest_path,
                                 const char *owner)
{
    char parent_path[PATH_MAX];
    snprintf(parent_path, sizeof(parent_path), "%s", dest_path);
    char *slash = strrchr(parent_path, '/');
    if (!slash || slash == parent_path)
        return;
    *slash = '\0';
    if (strcmp(parent_path, compose_dir) == 0)
        return;

    size_t compose_len = strlen(compose_dir);
    for (char *p = parent_path + compose_len + 1;; p++) {
        if (*p != '/' && *p != '\0')
            continue;

        char saved = *p;
        *p = '\0';

        struct stat st;
        if (lstat(parent_path, &st) == 0) {
            if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
                log_die("adopt output parent is not a directory: %s", parent_path);
        } else if (errno == ENOENT) {
            if (mkdir(parent_path, 0755) != 0)
                log_die("failed to create output directory '%s': %s", parent_path, strerror(errno));
        } else {
            log_die("cannot inspect output directory '%s': %s", parent_path, strerror(errno));
        }

        char *chown_argv[] = { PODMGR_BIN_CHOWN, (char *)owner, parent_path, NULL };
        if (run_command(chown_argv) != 0)
            log_die("failed to set ownership on output directory '%s'", parent_path);

        *p = saved;
        if (saved == '\0')
            break;
    }
}

void do_up(const char *user, const char *compose_dir)
{
    ensure_managed_user(user);
    /*
     * Self-heal the per-user log-driver enforcement before starting the
     * stack: users provisioned before containers.conf enforcement existed
     * never got the file (setup refuses existing users), leaving their
     * containers on `journald` with empty `clogs` output. Written as the
     * managed user via the standard sudo-as-user path; see
     * ensure_user_containers_conf.
     */
    ensure_user_containers_conf(user);
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

void do_adopt(const char *user, const char *compose_dir,
              const char *input_path, const char *output_path)
{
    ensure_managed_user(user);
    ensure_compose_runtime_ready(user, compose_dir, 0);

    if (!input_path || input_path[0] == '\0')
        log_die("adopt requires an input path");

    struct stat src_st;
    if (lstat(input_path, &src_st) != 0)
        log_die("cannot access input '%s': %s", input_path, strerror(errno));

    if (S_ISLNK(src_st.st_mode))
        log_die("refusing to adopt symlink input '%s'", input_path);

    if (!S_ISREG(src_st.st_mode) && !S_ISDIR(src_st.st_mode))
        log_die("adopt supports only regular files and directories: %s", input_path);

    const char *base = path_basename_const(input_path);
    if (!base || base[0] == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        log_die("invalid input path for adopt: %s", input_path);

    const char *relative_output = output_path ? output_path : base;
    validate_adopt_output(relative_output);

    char dest_path[PATH_MAX];
    if (snprintf(dest_path, sizeof(dest_path), "%s/%s", compose_dir, relative_output) >= (int)sizeof(dest_path))
        log_die("destination path too long under compose-dir '%s'", compose_dir);

    char owner[128];
    snprintf(owner, sizeof(owner), "%s:%s", user, user);
    prepare_adopt_parent(compose_dir, dest_path, owner);

    struct stat dst_st;
    if (lstat(dest_path, &dst_st) == 0)
        log_die("destination already exists in compose-dir: %s", dest_path);
    if (errno != ENOENT)
        log_die("cannot inspect destination '%s': %s", dest_path, strerror(errno));

    char *copy_argv[] = {
        PODMGR_BIN_CP, "-a", "--", (char *)input_path, dest_path, NULL
    };
    if (run_command(copy_argv) != 0)
        log_die("failed to copy '%s' to '%s'", input_path, dest_path);

    char *chown_argv[] = {
        PODMGR_BIN_CHOWN, "-R", owner, dest_path, NULL
    };
    if (run_command(chown_argv) != 0)
        log_die("failed to set ownership on adopted path '%s'", dest_path);

    log_info("adopted '%s' into '%s' for user '%s'", input_path, dest_path, user);
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

