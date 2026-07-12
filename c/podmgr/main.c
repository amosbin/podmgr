#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include "logging.h"
#include "validation.h"
#include "util.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

typedef enum {
    CMD_NONE,
    CMD_SETUP,
    CMD_CLEANUP,
    CMD_REINSTALL,
    CMD_LIST,
    CMD_USERS,
    CMD_INFO,
    CMD_STATUS,
    CMD_UP,
    CMD_DOWN,
    CMD_RESTART,
    CMD_PS,
    CMD_STATS,
    CMD_PRUNE,
    CMD_SHELL,
    CMD_RUN,
    CMD_ENABLE,
    CMD_START,
    CMD_STOP,
    CMD_KILL,
    CMD_JOURNAL,
    CMD_EXEC,
    CMD_RUN_IN,
    CMD_CLOGS,
    CMD_CP,
    CMD_TOP,
    CMD_ADOPT,
    CMD_SUBID,
    CMD_SUBID_CHECK,
    CMD_SUBID_RECLAIM,
    CMD_AUTOSTART,
    CMD_VERSION
} cmd_t;

static int parse_command(const char *s, cmd_t *out)
{
    if (strcmp(s, "setup") == 0) *out = CMD_SETUP;
    else if (strcmp(s, "cleanup") == 0) *out = CMD_CLEANUP;
    else if (strcmp(s, "reinstall") == 0) *out = CMD_REINSTALL;
    else if (strcmp(s, "list") == 0) *out = CMD_LIST;
    else if (strcmp(s, "users") == 0) *out = CMD_USERS;
    else if (strcmp(s, "info") == 0) *out = CMD_INFO;
    else if (strcmp(s, "status") == 0) *out = CMD_STATUS;
    else if (strcmp(s, "up") == 0) *out = CMD_UP;
    else if (strcmp(s, "down") == 0) *out = CMD_DOWN;
    else if (strcmp(s, "restart") == 0) *out = CMD_RESTART;
    else if (strcmp(s, "ps") == 0) *out = CMD_PS;
    else if (strcmp(s, "stats") == 0) *out = CMD_STATS;
    else if (strcmp(s, "prune") == 0) *out = CMD_PRUNE;
    else if (strcmp(s, "shell") == 0) *out = CMD_SHELL;
    else if (strcmp(s, "run") == 0) *out = CMD_RUN;
    else if (strcmp(s, "enable") == 0) *out = CMD_ENABLE;
    else if (strcmp(s, "start") == 0) *out = CMD_START;
    else if (strcmp(s, "stop") == 0) *out = CMD_STOP;
    else if (strcmp(s, "kill") == 0) *out = CMD_KILL;
    else if (strcmp(s, "journal") == 0) *out = CMD_JOURNAL;
    else if (strcmp(s, "exec") == 0) *out = CMD_EXEC;
    else if (strcmp(s, "run-in") == 0) *out = CMD_RUN_IN;
    else if (strcmp(s, "clogs") == 0) *out = CMD_CLOGS;
    else if (strcmp(s, "cp") == 0) *out = CMD_CP;
    else if (strcmp(s, "top") == 0) *out = CMD_TOP;
    else if (strcmp(s, "adopt") == 0) *out = CMD_ADOPT;
    else if (strcmp(s, "subid") == 0) *out = CMD_SUBID;
    else if (strcmp(s, "subid-check") == 0) *out = CMD_SUBID_CHECK;
    else if (strcmp(s, "subid-reclaim") == 0) *out = CMD_SUBID_RECLAIM;
    else if (strcmp(s, "autostart") == 0) *out = CMD_AUTOSTART;
    else if (strcmp(s, "version") == 0) *out = CMD_VERSION;
    else return 0;
    return 1;
}

static int match_option(const char *arg, const char *short_opt,
                        const char *long_opt)
{
    return strcmp(arg, short_opt) == 0 || strcmp(arg, long_opt) == 0;
}

static const char *next_option_value(const char *arg, int argc, char *argv[],
                                     int *i)
{
    if (*i + 1 >= argc)
        log_die("missing value for %s", arg);
    (*i)++;
    return argv[*i];
}

static void show_usage(void)
{
    puts(
        "podmgr - Rootless Podman system user manager\n"
        "\n"
        "USAGE:\n"
        "  podmgr <command> [options]\n"
        "\n"
        "  Flags may appear before or after the command as long as each flag\n"
        "  uses its declared key.\n"
        "\n"
        "COMMANDS (grouped by category)\n"
        "\n"
        "  USER LIFECYCLE (the managed host user itself)\n"
        "    setup        Create system user and configure rootless podman\n"
        "    cleanup      Remove user and all traces\n"
        "    reinstall    Full cleanup then setup\n"
        "    list         List all containers across all users (default: running only)\n"
        "    users        List podmgr-managed users only (one per line)\n"
        "    info         Show one user's full provisioning state (uid, subid range,\n"
        "                 linger, compose dir, marker, quadlet vs template, container count)\n"
        "    status       Quick health: user session / service / socket active?\n"
        "\n"
        "  PODMAN ENGINE (the rootless podman inside the user)\n"
        "    up           Start containers (podman compose up -d)\n"
        "    down         Stop containers (podman compose down)\n"
        "    restart      Restart the user's stack (down then up)\n"
        "    ps           Show running containers\n"
        "    stats        Live resource table per container: CPU%, MEM, MEM%, NET/BLOCK\n"
        "                 I/O (podman stats --no-stream); use --df for disk usage\n"
        "    prune        Reclaim space: remove unused containers/images/networks\n"
        "                 (add --all --volumes to also drop unused images and volumes)\n"
        "\n"
        "  USER SESSION / SHELL (login-as-the-host-user)\n"
        "    shell        Open an interactive login shell AS the host user\n"
        "    run          Run an arbitrary command in the user's session (-- <cmd...>)\n"
        "    enable       Enable persistent autostart for the user's workload\n"
        "                 (enables linger, starts user manager, enables+starts service)\n"
        "    start        Start the user's workload service\n"
        "    stop         Stop the user's workload service\n"
        "    kill         Stop the user's systemd service (alias of stop)\n"
        "    journal      Follow journalctl logs for the user\n"
        "\n"
        "  CONTAINER SHELL / EXEC (inside a running container)\n"
        "    exec         Interactive shell into a running container (auto bash/sh)\n"
        "    run-in       Run a command in a container (-n c / --container c -- <cmd...>)\n"
        "    clogs        Follow a container's logs (-n c / --container c)\n"
        "    cp           Copy files to/from a container (podman cp)\n"
        "    top          Show processes running inside a container (-n c / --container c)\n"
        "\n"
        "  COMPOSE FILE MANAGEMENT\n"
        "    adopt        Copy a file or directory into the user's compose directory\n"
        "\n"
        "  SUBUID / SUBGID & IDENTITY\n"
        "    subid        Show the user's allocated subuid/subgid range\n"
        "    subid-check  Audit /etc/subuid + /etc/subgid for gaps/overlaps across users\n"
        "    subid-reclaim  Garbage-collect ranges of deleted users + stale reservations\n"
        "\n"
        "  GLOBAL / OPERATIONAL (no single user)\n"
        "    autostart    Scan managed users and run 'up' only for stacks\n"
        "                 opted in via service label podmgr.autostart=true\n"
        "    version      Print podmgr version\n"
        "\n"
        "OPTIONS:\n"
        "  -u, --user <name>        System username (required, except for list/users).\n"
        "                           Must match [a-z_][a-z0-9_-]{0,31}.\n"
        "  -c, --compose-dir <path> Compose directory (default: /srv/podmgr/compose/<user>)\n"
        "  -n, --container <name>   Target a specific container (exec/run-in/clogs/cp/top).\n"
        "  -a, --all                list: include stopped containers.\n"
        "                           prune: also remove all unused images.\n"
        "  -w, --volumes            prune: also remove unused volumes.\n"
        "  -d, --df                 stats: show disk usage (podman system df) too.\n"
        "  -j, --json               list/users: output JSON format (MCP/script-friendly).\n"
        "  -v, --verbose            Print INFO and WARN messages to stderr in addition\n"
        "                           to errors (useful when debugging interactively).\n"
        "  -q, --quiet              Suppress all stderr output, including errors.\n"
        "                           Exit code is the only signal (intended for MCP/scripts).\n"
        "  -h, --help               Show this help\n"
        "  --                       Everything after '--' is passed verbatim to the\n"
        "                           target command (run / run-in / cp / adopt).\n"
        "  -f, --file <path>        adopt: source path to copy into the compose dir.\n"
        "\n"
        "NOTES:\n"
        "  setup        Provisions the user and installs units; it does not\n"
        "               start the workload. Hard-fails if the user already\n"
        "               exists; use 'reinstall'.\n"
        "  setup/cleanup/reinstall/adopt/autostart must be run as root.\n"
        "  cleanup/reinstall only operate on users that carry podmgr's marker file.\n"
        "  journal      Requires root or membership in the 'systemd-journal' group.\n"
        "  kill         Kept as an alias of 'stop'.\n"
        "  Only ONE compose file per user is supported by design; up/down/kill/reinstall\n"
        "  all act on that single stack. Separate trust boundaries = separate users.\n"
        "  Host filesystem mounts and ACL preparation are out of scope for podmgr.\n"
        "  The installer/operator is responsible for preparing required directories,\n"
        "  bind mounts, and permissions before or immediately after setup.\n"
        "  compose-dir must be absolute and inside PODMGR_BASE_DIR.\n"
        "\n"
        "CONFIGURATION (/etc/podmgr.conf, optional):\n"
        "  LOG_DEST=file|journal|both   (default: file)\n"
        "  LOG_FILE=/var/log/podmgr.log (default)\n"
        "  PODMGR_BASE_DIR=/srv/podmgr   (default)\n"
    );
    exit(0);
}

int main(int argc, char *argv[])
{
    config_load();
    podmgr_init_binary_paths();
    sanitize_process_environment();
    umask(022);

    if (argc < 2) show_usage();

    /* Pre-scan for -v / -q so verbosity is set before any log_die calls. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_log_verbosity = LOG_V_VERBOSE;
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
            g_log_verbosity = LOG_V_QUIET;
    }

    cmd_t       cmd       = CMD_NONE;
    int         have_cmd  = 0;
    const char *user      = NULL;
    const char *compose   = NULL;
    const char *container = NULL;
    int         flag_all  = 0;
    int         flag_vols = 0;
    int         flag_df   = 0;
    int         flag_json = 0;
    const char *adopt_src = NULL;
    int         passthru_index = -1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            show_usage();
        }

        if (parse_command(a, &cmd)) {
            if (have_cmd)
                log_die("multiple commands specified (already had one, got '%s')", a);
            have_cmd = 1;
            continue;
        }

        if (strcmp(a, "--") == 0) {
            if (!have_cmd)
                log_die("'--' must appear after a command");
            passthru_index = i + 1;
            break;
        }

        if (match_option(a, "-u", "--user")) {
            user = next_option_value(a, argc, argv, &i);
        } else if (match_option(a, "-c", "--compose-dir")) {
            compose = next_option_value(a, argc, argv, &i);
        } else if (match_option(a, "-n", "--container")) {
            container = next_option_value(a, argc, argv, &i);
        } else if (match_option(a, "-f", "--file")) {
            adopt_src = next_option_value(a, argc, argv, &i);
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            /* already handled in pre-scan */
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            /* already handled in pre-scan */
        } else if (strcmp(a, "-a") == 0 || strcmp(a, "--all") == 0) {
            flag_all = 1;
        } else if (match_option(a, "-w", "--volumes")) {
            flag_vols = 1;
        } else if (match_option(a, "-d", "--df")) {
            flag_df = 1;
        } else if (match_option(a, "-j", "--json")) {
            flag_json = 1;
        } else {
            if (a[0] == '-')
                log_die("unknown option: %s", a);
            log_die("unexpected argument: %s", a);
        }
    }

    if (!have_cmd)
        log_die("missing command (see --help)");

    if (passthru_index >= 0 &&
        !(cmd == CMD_RUN || cmd == CMD_RUN_IN || cmd == CMD_CP || cmd == CMD_ADOPT))
        log_die("'--' passthrough is only valid for run, run-in, cp, and adopt");

    if (flag_df && cmd != CMD_STATS)
        log_die("-d/--df is only valid with the stats command");
    if (flag_vols && cmd != CMD_PRUNE)
        log_die("-w/--volumes is only valid with the prune command");
    if (flag_all && !(cmd == CMD_LIST || cmd == CMD_PRUNE))
        log_die("-a/--all is only valid with list or prune");
    if (flag_json && !(cmd == CMD_LIST || cmd == CMD_USERS))
        log_die("-j/--json is only valid with list or users");
    if (container && !(cmd == CMD_EXEC || cmd == CMD_RUN_IN ||
                       cmd == CMD_CLOGS || cmd == CMD_TOP))
        log_die("-n/--container is only valid with exec, run-in, clogs, or top");

    char **passthru_argv = NULL;
    if (passthru_index >= 0) {
        if (passthru_index >= argc)
            log_die("'--' requires at least one argument after it");
        passthru_argv = &argv[passthru_index];
    }

    /*
     * Lifecycle commands need root. If invoked by a non-root user that has
     * sudo rights, re-exec the whole command under sudo instead of failing.
     */
    if (cmd == CMD_SETUP || cmd == CMD_CLEANUP || cmd == CMD_REINSTALL ||
        cmd == CMD_ADOPT || cmd == CMD_AUTOSTART) {
        const char *cmd_name = cmd == CMD_SETUP   ? "setup"   :
                               cmd == CMD_CLEANUP ? "cleanup" :
                               cmd == CMD_REINSTALL ? "reinstall" :
                               cmd == CMD_ADOPT ? "adopt" : "autostart";
        ensure_root_or_reexec_sudo(cmd_name, argc, argv);
    }

    int need_user =
                    !(cmd == CMD_LIST || cmd == CMD_USERS || cmd == CMD_VERSION ||
          cmd == CMD_AUTOSTART ||
          cmd == CMD_SUBID_CHECK || cmd == CMD_SUBID_RECLAIM);

    int need_compose =
        (cmd == CMD_SETUP || cmd == CMD_CLEANUP || cmd == CMD_REINSTALL ||
         cmd == CMD_UP || cmd == CMD_DOWN || cmd == CMD_RESTART ||
         cmd == CMD_PS || cmd == CMD_STATS || cmd == CMD_PRUNE ||
         cmd == CMD_SHELL || cmd == CMD_RUN || cmd == CMD_EXEC ||
         cmd == CMD_RUN_IN || cmd == CMD_CLOGS || cmd == CMD_CP ||
         cmd == CMD_TOP || cmd == CMD_INFO || cmd == CMD_STATUS ||
         cmd == CMD_ADOPT);

    if (need_user) {
        if (!user || user[0] == '\0')
            log_die("-u/--user is required for this command");
        validate_user(user);

        if ((cmd == CMD_RUN_IN || cmd == CMD_CLOGS || cmd == CMD_TOP) &&
            (!container || container[0] == '\0'))
            log_die("--container is required for this command");

        if (cmd == CMD_RUN && !passthru_argv)
            log_die("run requires '-- <cmd...>'");
        if (cmd == CMD_RUN_IN && !passthru_argv)
            log_die("run-in requires '-- <cmd...>'");
        if (cmd == CMD_CP && !passthru_argv)
            log_die("cp requires '-- <src> <dst>'");
        if (cmd == CMD_CP && passthru_argv && (!passthru_argv[0] || !passthru_argv[1]))
            log_die("cp requires both source and destination arguments");

        if (cmd == CMD_ADOPT) {
            adopt_src = passthru_argv ? passthru_argv[0] : adopt_src;
            if (!adopt_src || adopt_src[0] == '\0')
                log_die("adopt requires a source path (use: podmgr adopt -u <user> -f <path>)");
            if (passthru_argv && passthru_argv[1])
                log_die("adopt accepts exactly one source path");
        }

        if (need_compose) {
            static char default_compose[PATH_MAX];
            if (!compose || compose[0] == '\0') {
                snprintf(default_compose, sizeof(default_compose),
                         "%s/compose/%s", g_cfg.base_dir, user);
                compose = default_compose;
            }
            validate_compose_dir(compose);
        }
    }

    switch (cmd) {
    case CMD_SETUP:       do_setup(user, compose);                          break;
    case CMD_CLEANUP:     do_cleanup(user, compose);                        break;
    case CMD_REINSTALL:   do_reinstall(user, compose);                      break;
    case CMD_LIST:        do_list(flag_all, flag_json);                     break;
    case CMD_USERS:       do_users(flag_json);                              break;
    case CMD_INFO:        do_info(user, compose);                           break;
    case CMD_STATUS:      do_status(user, compose);                         break;
    case CMD_UP:          do_up(user, compose);                             break;
    case CMD_DOWN:        do_down(user, compose);                           break;
    case CMD_RESTART:     do_restart(user, compose);                        break;
    case CMD_PS:          do_ps(user, compose);                             break;
    case CMD_STATS:       do_stats(user, compose, flag_df);                 break;
    case CMD_PRUNE:       do_prune(user, compose, flag_all, flag_vols);     break;
    case CMD_SHELL:       do_shell(user, compose);                          break;
    case CMD_RUN:         do_run(user, compose, passthru_argv);             break;
    case CMD_ENABLE:      do_enable(user);                                  break;
    case CMD_START:       do_start(user);                                   break;
    case CMD_STOP:        do_stop(user);                                    break;
    case CMD_KILL:        do_kill(user);                                    break;
    case CMD_JOURNAL:     do_journal(user);                                 break;
    case CMD_EXEC:        do_exec(user, compose, container);                break;
    case CMD_RUN_IN:      do_run_in(user, compose, container, passthru_argv); break;
    case CMD_CLOGS:       do_clogs(user, compose, container);               break;
    case CMD_CP:          do_cp(user, compose, passthru_argv);              break;
    case CMD_TOP:         do_top(user, compose, container);                 break;
    case CMD_ADOPT:       do_adopt(user, compose, adopt_src);               break;
    case CMD_SUBID:       do_subid(user);                                   break;
    case CMD_SUBID_CHECK: do_subid_check();                                 break;
    case CMD_SUBID_RECLAIM: do_subid_reclaim();                             break;
    case CMD_AUTOSTART:   do_autostart();                                   break;
    case CMD_VERSION:     do_version();                                     break;
    default:              log_die("unsupported command");
    }

    return 0;
}
