#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util.h"
#include "logging.h"
#include "config.h"
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
#include <limits.h>

char g_exe_dir[4096] = "/usr/lib/podmgr";

static const char *SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin";

static char g_groupadd_bin[PATH_MAX] = "/usr/sbin/groupadd";
static char g_useradd_bin[PATH_MAX] = "/usr/sbin/useradd";
static char g_userdel_bin[PATH_MAX] = "/usr/sbin/userdel";
static char g_usermod_bin[PATH_MAX] = "/usr/sbin/usermod";
static char g_fsubid_bin[PATH_MAX]  = "/usr/bin/fsubid";

static const char *resolve_first_existing(const char *const *candidates)
{
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    }
    return NULL;
}

void podmgr_init_binary_paths(void)
{
    const char *const groupadd_candidates[] = {
        "/usr/sbin/groupadd", "/usr/bin/groupadd", NULL
    };
    const char *const useradd_candidates[] = {
        "/usr/sbin/useradd", "/usr/bin/useradd", NULL
    };
    const char *const userdel_candidates[] = {
        "/usr/sbin/userdel", "/usr/bin/userdel", NULL
    };
    const char *const usermod_candidates[] = {
        "/usr/sbin/usermod", "/usr/bin/usermod", NULL
    };
    const char *const fsubid_candidates[] = {
        "/usr/bin/fsubid", "/usr/sbin/fsubid", NULL
    };

    const char *path = resolve_first_existing(groupadd_candidates);
    if (path)
        snprintf(g_groupadd_bin, sizeof(g_groupadd_bin), "%s", path);

    path = resolve_first_existing(useradd_candidates);
    if (path)
        snprintf(g_useradd_bin, sizeof(g_useradd_bin), "%s", path);

    path = resolve_first_existing(userdel_candidates);
    if (path)
        snprintf(g_userdel_bin, sizeof(g_userdel_bin), "%s", path);

    path = resolve_first_existing(usermod_candidates);
    if (path)
        snprintf(g_usermod_bin, sizeof(g_usermod_bin), "%s", path);

    path = resolve_first_existing(fsubid_candidates);
    if (path)
        snprintf(g_fsubid_bin, sizeof(g_fsubid_bin), "%s", path);
}

const char *podmgr_bin_groupadd(void) { return g_groupadd_bin; }
const char *podmgr_bin_useradd(void) { return g_useradd_bin; }
const char *podmgr_bin_userdel(void) { return g_userdel_bin; }
const char *podmgr_bin_usermod(void) { return g_usermod_bin; }
const char *podmgr_bin_fsubid(void)  { return g_fsubid_bin; }

/* ---- internal helpers --------------------------------------------------- */

/*
 * Replace every occurrence of `needle` in `src` with `replacement`,
 * writing the result into dst[dstsz].
 */
static void str_replace_all(const char *src, const char *needle,
                             const char *replacement,
                             char *dst, size_t dstsz)
{
    size_t needle_len = strlen(needle);
    size_t repl_len   = strlen(replacement);
    size_t di = 0;
    const char *p = src;

    while (*p && di < dstsz - 1) {
        if (needle_len > 0 && strncmp(p, needle, needle_len) == 0) {
            size_t copy = repl_len;
            if (di + copy >= dstsz) copy = dstsz - di - 1;
            memcpy(dst + di, replacement, copy);
            di += copy;
            p  += needle_len;
        } else {
            dst[di++] = *p++;
        }
    }
    dst[di] = '\0';
}

/*
 * Build the standard sudo + env prefix for running commands as `user`.
 * Writes into cmd[] starting at index *i_ptr.
 * Returns a pointer to a malloc'd buffer holding the xdg/dhost strings
 * (caller must free it), or NULL on error.
 */
static int build_sudo_prefix(const char *user,
                             char **cmd, int *i_ptr,
                             const char *home_var, const char *logname_var,
                             const char *user_var, const char *path_var,
                             const char *runtime_var)
{
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        log_warn("user '%s' not found in passwd", user);
        return 0;
    }

    int i = *i_ptr;
    cmd[i++] = PODMGR_BIN_SUDO;
    cmd[i++] = "-u"; cmd[i++] = (char *)user;
    cmd[i++] = "-H";
    cmd[i++] = PODMGR_BIN_ENV;
    cmd[i++] = "-i";
    cmd[i++] = (char *)home_var;
    cmd[i++] = (char *)logname_var;
    cmd[i++] = (char *)user_var;
    cmd[i++] = (char *)path_var;
    cmd[i++] = (char *)runtime_var;
    *i_ptr = i;
    return 1;
}

void sanitize_process_environment(void)
{
    setenv("PATH", SAFE_PATH, 1);
    unsetenv("BASH_ENV");
    unsetenv("ENV");
    unsetenv("CDPATH");
    unsetenv("GLOBIGNORE");
    unsetenv("IFS");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
}

/* ---- subprocess helpers ------------------------------------------------- */

/*
 * Like run_command but, when cwd is non-NULL, chdir into it in the child
 * before exec. podmgr runs as root on this path, so the chdir succeeds for any
 * existing directory and the working directory is then inherited across the
 * sudo privilege drop. This replaces the old `sudo -D`, which required a
 * non-default sudoers policy (runcwd) to permit the -D option.
 */
static int run_command_cwd(char *const argv[], const char *cwd)
{
    pid_t pid = fork();
    if (pid < 0) { log_warn("fork: %s", strerror(errno)); return -1; }

    if (pid == 0) {
        if (cwd && chdir(cwd) != 0) {
            fprintf(stderr, "podmgr: chdir %s: %s\n", cwd, strerror(errno));
            _exit(127);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "podmgr: execvp %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_command(char *const argv[])
{
    return run_command_cwd(argv, NULL);
}

static int run_capture_cwd(char *const argv[], char *buf, size_t bufsz,
                           const char *cwd)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) { log_warn("pipe: %s", strerror(errno)); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        log_warn("fork: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        if (cwd && chdir(cwd) != 0) {
            fprintf(stderr, "podmgr: chdir %s: %s\n", cwd, strerror(errno));
            _exit(127);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t total = 0;
    ssize_t n;
    while (total < bufsz - 1 &&
           (n = read(pipefd[0], buf + total, bufsz - 1 - total)) > 0)
        total += (size_t)n;
    buf[total] = '\0';

    /*
     * If we filled the buffer, drain the rest of the pipe so the child does not
     * block on a full pipe, and warn that the captured output was truncated.
     */
    int truncated = 0;
    if (total == bufsz - 1) {
        char drain[4096];
        while (read(pipefd[0], drain, sizeof(drain)) > 0)
            truncated = 1;
        if (truncated)
            log_warn("captured output of '%s' exceeded %zu bytes and was truncated",
                     argv[0], bufsz - 1);
    }
    close(pipefd[0]);

    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_capture(char *const argv[], char *buf, size_t bufsz)
{
    return run_capture_cwd(argv, buf, bufsz, NULL);
}

/*
 * Capture the full stdout of argv into a growable buffer (no size cap). On
 * success *out is a malloc'd NUL-terminated string the caller must free; the
 * child exit code is returned. On failure *out is NULL and -1 is returned.
 */
static int run_capture_dyn(char *const argv[], char **out, const char *cwd)
{
    *out = NULL;

    int pipefd[2];
    if (pipe(pipefd) != 0) { log_warn("pipe: %s", strerror(errno)); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        log_warn("fork: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        if (cwd && chdir(cwd) != 0) {
            fprintf(stderr, "podmgr: chdir %s: %s\n", cwd, strerror(errno));
            _exit(127);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);

    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        /* Drain the pipe so the child can finish, then reap it. */
        char drain[4096];
        while (read(pipefd[0], drain, sizeof(drain)) > 0) { }
        close(pipefd[0]);
        int st; waitpid(pid, &st, 0);
        log_warn("out of memory capturing output of '%s'", argv[0]);
        return -1;
    }

    ssize_t n;
    while ((n = read(pipefd[0], buf + len, cap - 1 - len)) > 0) {
        len += (size_t)n;
        if (len >= cap - 1) {
            size_t newcap = cap * 2;
            char *tmp = realloc(buf, newcap);
            if (!tmp) {
                char drain[4096];
                while (read(pipefd[0], drain, sizeof(drain)) > 0) { }
                free(buf);
                close(pipefd[0]);
                int st; waitpid(pid, &st, 0);
                log_warn("out of memory growing capture buffer for '%s'", argv[0]);
                return -1;
            }
            buf = tmp;
            cap = newcap;
        }
    }
    buf[len] = '\0';
    close(pipefd[0]);

    int status;
    if (waitpid(pid, &status, 0) < 0) { free(buf); return -1; }

    *out = buf;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_as_user(const char *user, const char *compose_dir, char *const argv[])
{
    /* Resolve default compose dir if caller passed NULL. */
    char default_compose[PATH_MAX];
    if (!compose_dir) {
        snprintf(default_compose, sizeof(default_compose),
                 "%s/compose/%s", g_cfg.base_dir, user);
        compose_dir = default_compose;
    }

    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);
    char runtime[64];
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)pw->pw_uid);
    char home_var[320];
    char logname_var[320];
    char user_var[320];
    char path_var[128];
    char runtime_var[128];
    snprintf(home_var, sizeof(home_var), "HOME=%s", home);
    snprintf(logname_var, sizeof(logname_var), "LOGNAME=%s", user);
    snprintf(user_var, sizeof(user_var), "USER=%s", user);
    snprintf(path_var, sizeof(path_var), "PATH=%s", SAFE_PATH);
    snprintf(runtime_var, sizeof(runtime_var), "XDG_RUNTIME_DIR=%s", runtime);

    int argc = 0;
    while (argv[argc]) argc++;

    /* sudo + env + fixed env vars + shell-wrapper + command + NULL */
    char **cmd = malloc((11 + 5 + argc + 1) * sizeof(char *));
    if (!cmd) return -1;

    int i = 0;
    if (!build_sudo_prefix(user, cmd, &i,
                           home_var, logname_var, user_var, path_var, runtime_var)) {
        free(cmd);
        return -1;
    }

    cmd[i++] = "/bin/sh";
    cmd[i++] = "-lc";
    cmd[i++] = "cd \"$1\" && shift && exec \"$@\"";
    cmd[i++] = "sh";
    cmd[i++] = (char *)compose_dir;

    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_command((char *const *)cmd);
    free(cmd);
    return ret;
}

int run_as_user_home(const char *user, char *const argv[])
{
    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;
    char runtime[64];
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)pw->pw_uid);
    char home_var[320];
    char logname_var[320];
    char user_var[320];
    char path_var[128];
    char runtime_var[128];
    snprintf(home_var, sizeof(home_var), "HOME=%s", home);
    snprintf(logname_var, sizeof(logname_var), "LOGNAME=%s", user);
    snprintf(user_var, sizeof(user_var), "USER=%s", user);
    snprintf(path_var, sizeof(path_var), "PATH=%s", SAFE_PATH);
    snprintf(runtime_var, sizeof(runtime_var), "XDG_RUNTIME_DIR=%s", runtime);

    int argc = 0;
    while (argv[argc]) argc++;

    char **cmd = malloc((11 + argc + 1) * sizeof(char *));
    if (!cmd) return -1;

    int i = 0;
    if (!build_sudo_prefix(user, cmd, &i,
                           home_var, logname_var, user_var, path_var, runtime_var)) {
        free(cmd);
        return -1;
    }
    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_command_cwd((char *const *)cmd, home);
    free(cmd);
    return ret;
}

int run_as_user_home_capture(const char *user, char *const argv[],
                             char *buf, size_t bufsz)
{
    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;
    char runtime[64];
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)pw->pw_uid);
    char home_var[320];
    char logname_var[320];
    char user_var[320];
    char path_var[128];
    char runtime_var[128];
    snprintf(home_var, sizeof(home_var), "HOME=%s", home);
    snprintf(logname_var, sizeof(logname_var), "LOGNAME=%s", user);
    snprintf(user_var, sizeof(user_var), "USER=%s", user);
    snprintf(path_var, sizeof(path_var), "PATH=%s", SAFE_PATH);
    snprintf(runtime_var, sizeof(runtime_var), "XDG_RUNTIME_DIR=%s", runtime);

    int argc = 0;
    while (argv[argc]) argc++;

    char **cmd = malloc((11 + argc + 1) * sizeof(char *));
    if (!cmd) return -1;

    int i = 0;
    if (!build_sudo_prefix(user, cmd, &i,
                           home_var, logname_var, user_var, path_var, runtime_var)) {
        free(cmd);
        return -1;
    }
    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_capture_cwd((char *const *)cmd, buf, bufsz, home);
    free(cmd);
    return ret;
}

int run_as_user_home_capture_dyn(const char *user, char *const argv[],
                                  char **out)
{
    *out = NULL;

    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;
    char runtime[64];
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)pw->pw_uid);
    char home_var[320];
    char logname_var[320];
    char user_var[320];
    char path_var[128];
    char runtime_var[128];
    snprintf(home_var, sizeof(home_var), "HOME=%s", home);
    snprintf(logname_var, sizeof(logname_var), "LOGNAME=%s", user);
    snprintf(user_var, sizeof(user_var), "USER=%s", user);
    snprintf(path_var, sizeof(path_var), "PATH=%s", SAFE_PATH);
    snprintf(runtime_var, sizeof(runtime_var), "XDG_RUNTIME_DIR=%s", runtime);

    int argc = 0;
    while (argv[argc]) argc++;

    char **cmd = malloc((11 + argc + 1) * sizeof(char *));
    if (!cmd) return -1;

    int i = 0;
    if (!build_sudo_prefix(user, cmd, &i,
                           home_var, logname_var, user_var, path_var, runtime_var)) {
        free(cmd);
        return -1;
    }
    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    int ret = run_capture_dyn((char *const *)cmd, out, home);
    free(cmd);
    return ret;
}

void exec_as_user(const char *user, const char *compose_dir,
                  char *const argv[])
{
    char default_compose[PATH_MAX];
    if (!compose_dir) {
        snprintf(default_compose, sizeof(default_compose),
                 "%s/compose/%s", g_cfg.base_dir, user);
        compose_dir = default_compose;
    }

    char home[256];
    snprintf(home, sizeof(home), "/var/lib/%s", user);
    struct passwd *pw = getpwnam(user);
    if (!pw) log_die("user '%s' not found", user);
    char runtime[64];
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)pw->pw_uid);
    char home_var[320];
    char logname_var[320];
    char user_var[320];
    char path_var[128];
    char runtime_var[128];
    snprintf(home_var, sizeof(home_var), "HOME=%s", home);
    snprintf(logname_var, sizeof(logname_var), "LOGNAME=%s", user);
    snprintf(user_var, sizeof(user_var), "USER=%s", user);
    snprintf(path_var, sizeof(path_var), "PATH=%s", SAFE_PATH);
    snprintf(runtime_var, sizeof(runtime_var), "XDG_RUNTIME_DIR=%s", runtime);

    int argc = 0;
    while (argv[argc]) argc++;

    char **cmd = malloc((11 + 5 + argc + 1) * sizeof(char *));
    if (!cmd) log_die("out of memory");

    int i = 0;
    if (!build_sudo_prefix(user, cmd, &i,
                           home_var, logname_var, user_var, path_var, runtime_var)) {
        free(cmd);
        log_die("user '%s' not found", user);
    }

    cmd[i++] = "/bin/sh";
    cmd[i++] = "-lc";
    cmd[i++] = "cd \"$1\" && shift && exec \"$@\"";
    cmd[i++] = "sh";
    cmd[i++] = (char *)compose_dir;

    for (int j = 0; j < argc; j++) cmd[i++] = argv[j];
    cmd[i] = NULL;

    execvp(cmd[0], (char *const *)cmd);
    log_die("execvp failed: %s", strerror(errno));
}

/* ---- filesystem helpers ------------------------------------------------- */

int makedirs_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len-1] == '/') tmp[len-1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

void safe_rmrf(const char *path, const char *prefix)
{
    if (!path || path[0] == '\0') return;

    struct stat st;
    if (stat(path, &st) != 0) return;     /* absent — nothing to do */
    if (!S_ISDIR(st.st_mode)) return;

    size_t pfx_len = strlen(prefix);
    if (strncmp(path, prefix, pfx_len) != 0 ||
        path[pfx_len] != '/' ||
        path[pfx_len + 1] == '\0')
        log_die("refusing to remove '%s' (outside expected prefix '%s')",
                path, prefix);

    char *const rm_argv[] = { PODMGR_BIN_RM, "-rf", (char *)path, NULL };
    if (run_command(rm_argv) != 0)
        log_warn("rm -rf '%s' reported an error", path);
}

int write_service_file(const char *tpl_path, const char *dest_path,
                       const char *user, const char *compose_dir)
{
    FILE *in = fopen(tpl_path, "r");
    if (!in) {
        log_warn("cannot open template '%s': %s", tpl_path, strerror(errno));
        return -1;
    }
    FILE *out = fopen(dest_path, "w");
    if (!out) {
        log_warn("cannot write service file '%s': %s", dest_path, strerror(errno));
        fclose(in);
        return -1;
    }

    char line[1024], tmp[2048];
    while (fgets(line, sizeof(line), in)) {
        /*
         * Replace longest/most-specific tokens first so "$COMPOSE_DIR" is not
         * partially eaten by a "$COMPOSE" match, etc. Order: COMPOSE_DIR,
         * COMPOSE_FILE, USER.
         */
        str_replace_all(line, "$COMPOSE_DIR",    compose_dir,        tmp,  sizeof(tmp));
        str_replace_all(tmp,  "$COMPOSE_FILE",   g_cfg.compose_file, line, sizeof(line));
        str_replace_all(line, "$USER",           user,               tmp,  sizeof(tmp));
        snprintf(line, sizeof(line), "%s", tmp);
        fputs(line, out);
    }

    fclose(in);
    fclose(out);
    return 0;
}

int user_lock_acquire(const char *user)
{
    if (makedirs_p("/run/podmgr/locks", 0700) != 0) {
        log_warn("cannot create lock dir /run/podmgr/locks: %s", strerror(errno));
        /* Continue without a lock rather than blocking entirely. */
        return -1;
    }

    char lock_path[PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "/run/podmgr/locks/%s.lock", user);

    int fd = open(lock_path, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0) {
        log_warn("cannot open per-user lock '%s': %s", lock_path, strerror(errno));
        return -1;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK)
            log_die("another podmgr operation is already running for user '%s'",
                    user);
        log_warn("cannot lock '%s': %s", lock_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

void user_lock_release(int lock_fd)
{
    if (lock_fd < 0) return;
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}

void ensure_root_or_reexec_sudo(const char *cmd, int argc, char *argv[])
{
    if (geteuid() == 0)
        return; /* already root */

    /* Look for sudo on PATH. */
    char *const probe[] = { "sudo", "-n", "true", NULL };
    /* We don't run probe here to avoid prompting; just check sudo exists. */
    (void)probe;

    /* Build: sudo <argv[0]> <argv[1..]> */
    char **new_argv = malloc((size_t)(argc + 2) * sizeof(char *));
    if (!new_argv)
        log_die("out of memory while escalating privileges");

    int i = 0;
    new_argv[i++] = PODMGR_BIN_SUDO;
    for (int j = 0; j < argc; j++)
        new_argv[i++] = argv[j];
    new_argv[i] = NULL;

    log_info("'%s' requires root; re-executing under sudo", cmd);
    execv(PODMGR_BIN_SUDO, new_argv);

    /* If we get here, sudo was not found or failed to exec. */
    free(new_argv);
    log_die("'%s' must be run as root and 'sudo' is unavailable", cmd);
}

void subid_remove_user(const char *user)
{
    const char *files[] = { "/etc/subuid", "/etc/subgid", NULL };
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "%s:", user);
    size_t prefix_len = strlen(prefix);

    if (makedirs_p("/run/fsubid", 0700) != 0) {
        log_warn("cannot create /run/fsubid: %s", strerror(errno));
        return;
    }

    int lock_fd = open("/run/fsubid/fsubid.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (lock_fd < 0) {
        log_warn("cannot open fsubid lock: %s", strerror(errno));
        return;
    }
    if (flock(lock_fd, LOCK_EX) != 0) {
        log_warn("cannot acquire fsubid lock: %s", strerror(errno));
        close(lock_fd);
        return;
    }

    for (int fi = 0; files[fi]; fi++) {
        const char *path = files[fi];
        FILE *f = fopen(path, "r");
        if (!f) continue;

        /* Preserve the original file's permissions for the replacement. */
        struct stat orig_st;
        mode_t mode = 0644;
        if (stat(path, &orig_st) == 0)
            mode = orig_st.st_mode & 07777;

        /*
         * Atomic replace: write to a temp file in the same directory, fsync,
         * then rename() over the original. A crash leaves either the old or
         * the new file intact, never a half-written one.
         */
        char tmp_path[PATH_MAX];
        snprintf(tmp_path, sizeof(tmp_path), "%s.podmgr.XXXXXX", path);

        int fd = mkstemp(tmp_path);
        if (fd < 0) {
            log_warn("cannot create temp file for '%s': %s", path, strerror(errno));
            fclose(f);
            continue;
        }
        (void)fchmod(fd, mode);
        FILE *out = fdopen(fd, "w");
        if (!out) {
            log_warn("cannot open temp stream for '%s': %s", path, strerror(errno));
            close(fd);
            unlink(tmp_path);
            fclose(f);
            continue;
        }

        int write_ok = 1;
        char *line = NULL;
        size_t line_cap = 0;
        ssize_t line_len;
        while ((line_len = getline(&line, &line_cap, f)) != -1) {
            (void)line_len;
            if (strncmp(line, prefix, prefix_len) != 0) {
                if (fputs(line, out) == EOF) { write_ok = 0; break; }
            }
        }
        free(line);
        fclose(f);

        if (write_ok && fflush(out) != 0) write_ok = 0;
        if (write_ok) {
            int outfd = fileno(out);
            if (outfd >= 0) (void)fsync(outfd);
        }
        fclose(out);

        if (!write_ok) {
            log_warn("failed writing temp file for '%s'; leaving original intact", path);
            unlink(tmp_path);
            continue;
        }

        if (rename(tmp_path, path) != 0) {
            log_warn("cannot atomically replace '%s': %s", path, strerror(errno));
            unlink(tmp_path);
        }
    }

    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}
