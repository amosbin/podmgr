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
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>

/* Cleanup/reinstall lifecycle implementation. */
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
