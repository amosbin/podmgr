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

/* Status/reporting/listing/autostart command implementations. */
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

static int is_true_token(const char *v)
{
    if (!v || !*v)
        return 0;

    char tok[16];
    size_t i = 0;
    while (v[i] && i < sizeof(tok) - 1) {
        if (isspace((unsigned char)v[i]) || v[i] == ',' || v[i] == '}' || v[i] == '#')
            break;
        tok[i] = (char)tolower((unsigned char)v[i]);
        i++;
    }
    tok[i] = '\0';

    if (strcmp(tok, "true") == 0)
        return 1;
    if (strcmp(tok, "\"true\"") == 0)
        return 1;
    if (strcmp(tok, "'true'") == 0)
        return 1;
    return 0;
}

static int service_line_has_autostart_label(const char *line)
{
    const char *key = "podmgr.autostart";
    const char *p = strstr(line, key);
    if (!p)
        return 0;

    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '"' || *p == '\'')
        p++;

    if (*p != ':' && *p != '=')
        return 0;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;

    return is_true_token(p);
}

static int parse_autostart_optin_from_compose_config(const char *cfg)
{
    int in_services = 0;
    const char *line = cfg;

    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);

        char buf[4096];
        size_t copy = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
        memcpy(buf, line, copy);
        buf[copy] = '\0';

        char *trim = buf;
        int indent = 0;
        while (*trim == ' ') {
            indent++;
            trim++;
        }

        if (*trim != '\0' && *trim != '#') {
            if (!in_services) {
                if (indent == 0 && strcmp(trim, "services:") == 0)
                    in_services = 1;
            } else {
                if (indent == 0)
                    break;
                if (service_line_has_autostart_label(trim))
                    return 1;
            }
        }

        if (!nl)
            break;
        line = nl + 1;
    }

    return 0;
}

static int resolve_compose_file_for_user(const char *user,
                                         const char *compose_dir,
                                         char *out,
                                         size_t outsz)
{
    const char *primary_name = g_cfg.compose_file;
    const char *fallback_name = NULL;
    if (strcmp(primary_name, "compose.yaml") == 0)
        fallback_name = "compose.yml";
    else if (strcmp(primary_name, "compose.yml") == 0)
        fallback_name = "compose.yaml";

    char primary_path[PATH_MAX];
    if (snprintf(primary_path, sizeof(primary_path), "%s/%s",
                 compose_dir, primary_name) >= (int)sizeof(primary_path))
        return 0;

    char *probe_primary[] = { PODMGR_BIN_TEST, "-r", primary_path, NULL };
    if (run_as_user(user, compose_dir, probe_primary) == 0) {
        snprintf(out, outsz, "%s", primary_path);
        return 1;
    }

    if (!fallback_name)
        return 0;

    char fallback_path[PATH_MAX];
    if (snprintf(fallback_path, sizeof(fallback_path), "%s/%s",
                 compose_dir, fallback_name) >= (int)sizeof(fallback_path))
        return 0;

    char *probe_fallback[] = { PODMGR_BIN_TEST, "-r", fallback_path, NULL };
    if (run_as_user(user, compose_dir, probe_fallback) == 0) {
        snprintf(out, outsz, "%s", fallback_path);
        return 1;
    }
    return 0;
}

static int user_has_autostart_label(const char *user,
                                    const char *compose_dir,
                                    int *had_error)
{
    *had_error = 0;

    char compose_file[PATH_MAX];
    if (!resolve_compose_file_for_user(user, compose_dir,
                                       compose_file, sizeof(compose_file))) {
        log_warn("autostart: skipping '%s': no readable compose file in '%s'",
                 user, compose_dir);
        return 0;
    }

    char *cfg_argv[] = {
        PODMGR_BIN_PODMAN, "compose", "-f", compose_file, "config", NULL
    };
    char *cfg = NULL;
    int rc = run_as_user_home_capture_dyn(user, cfg_argv, &cfg);
    if (rc != 0 || !cfg) {
        *had_error = 1;
        log_warn("autostart: skipping '%s': cannot inspect compose labels (exit %d)",
                 user, rc);
        free(cfg);
        return 0;
    }

    int opted_in = parse_autostart_optin_from_compose_config(cfg);
    free(cfg);
    return opted_in;
}

void do_autostart(void)
{
    char **users = NULL;
    size_t user_count = 0, user_cap = 0;

    DIR *d = opendir("/var/lib/podmgr/managed");
    if (!d) {
        if (errno == ENOENT) {
            printf("No podmgr-managed users found.\n");
            return;
        }
        log_die("cannot open /var/lib/podmgr/managed: %s", strerror(errno));
    }

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.')
            continue;

        char marker[PATH_MAX];
        snprintf(marker, sizeof(marker), "/var/lib/podmgr/managed/%s", ent->d_name);

        struct stat mst;
        if (stat(marker, &mst) != 0 || !S_ISREG(mst.st_mode) || mst.st_uid != 0)
            continue;

        if (user_count == user_cap) {
            size_t newcap = user_cap ? user_cap * 2 : 16;
            char **tmp = realloc(users, newcap * sizeof(*users));
            if (!tmp) {
                closedir(d);
                for (size_t i = 0; i < user_count; i++)
                    free(users[i]);
                free(users);
                log_die("out of memory collecting managed users");
            }
            users = tmp;
            user_cap = newcap;
        }

        users[user_count] = strdup(ent->d_name);
        if (!users[user_count]) {
            closedir(d);
            for (size_t i = 0; i < user_count; i++)
                free(users[i]);
            free(users);
            log_die("out of memory collecting managed users");
        }
        user_count++;
    }
    closedir(d);

    if (user_count == 0) {
        printf("No podmgr-managed users found.\n");
        free(users);
        return;
    }

    qsort(users, user_count, sizeof(*users), cmp_str);

    size_t scanned = 0, opted_in = 0, started = 0, skipped = 0, failed = 0;

    for (size_t i = 0; i < user_count; i++) {
        const char *user = users[i];
        if (!getpwnam(user)) {
            skipped++;
            continue;
        }

        scanned++;

        char compose_dir[PATH_MAX];
        if (snprintf(compose_dir, sizeof(compose_dir), "%s/compose/%s",
                     g_cfg.base_dir, user) >= (int)sizeof(compose_dir)) {
            failed++;
            log_warn("autostart: skipping '%s': compose path too long", user);
            continue;
        }

        int inspect_error = 0;
        if (!user_has_autostart_label(user, compose_dir, &inspect_error)) {
            if (inspect_error)
                failed++;
            else
                skipped++;
            continue;
        }

        opted_in++;

        ensure_user_containers_conf(user);
        char *up_argv[] = { PODMGR_BIN_PODMAN, "compose", "up", "-d", NULL };
        int up_rc = run_as_user(user, compose_dir, up_argv);
        if (up_rc != 0) {
            failed++;
            log_warn("autostart: compose up failed for '%s' (exit %d)", user, up_rc);
            continue;
        }

        started++;
    }

    for (size_t i = 0; i < user_count; i++)
        free(users[i]);
    free(users);

    printf("autostart summary: scanned=%zu opted_in=%zu started=%zu skipped=%zu failed=%zu\n",
           scanned, opted_in, started, skipped, failed);

    if (failed > 0)
        log_die("autostart completed with %zu failure(s)", failed);
}
