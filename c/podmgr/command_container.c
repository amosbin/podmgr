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

/* Container-targeted command implementations and helper resolution logic. */
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

