#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>

#define MAX_TENANTS 256
#define MAX_GROUPS 32
#define MAX_ROUTES 1024
#define LINE_SZ 2048

typedef struct {
    char name[64];
    char mode[32];
    char groups[MAX_GROUPS][64];
    int group_count;
} Tenant;

typedef struct {
    char source[64];
    char target[64];
    char host[256];
    char path_prefix[128];
    char backend[256];
} Route;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static void trim(char *s)
{
    char *p = s;
    char *e;

    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);

    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        e--;
    *e = '\0';
}

static void split_csv(const char *s, char out[MAX_GROUPS][64], int *count)
{
    char *tmp = strdup(s ? s : "");
    char *tok;
    int n = 0;

    if (!tmp)
        die("out of memory");

    tok = strtok(tmp, ",");
    while (tok && n < MAX_GROUPS) {
        trim(tok);
        if (tok[0] != '\0') {
            snprintf(out[n], 64, "%s", tok);
            n++;
        }
        tok = strtok(NULL, ",");
    }

    *count = n;
    free(tmp);
}

static const char *kv_value(const char *token)
{
    const char *eq = strchr(token, '=');
    if (!eq)
        return NULL;
    return eq + 1;
}

static Tenant *find_tenant(Tenant tenants[MAX_TENANTS], int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(tenants[i].name, name) == 0)
            return &tenants[i];
    return NULL;
}

static int has_group(const char *group, char groups[MAX_GROUPS][64], int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(groups[i], group) == 0)
            return 1;
    return 0;
}

static int groups_overlap(Tenant *a, Tenant *b)
{
    int i;
    for (i = 0; i < a->group_count; i++)
        if (has_group(a->groups[i], b->groups, b->group_count))
            return 1;
    return 0;
}

static int starts_with(const char *s, const char *prefix)
{
    size_t ps = strlen(prefix);
    return strncmp(s, prefix, ps) == 0;
}

static int parse_runtime_conf(const char *path,
                              Tenant tenants[MAX_TENANTS],
                              int *tenant_count,
                              Route routes[MAX_ROUTES],
                              int *route_count)
{
    FILE *f = fopen(path, "r");
    char line[LINE_SZ];
    int tcount = 0;
    int rcount = 0;

    if (!f) {
        fprintf(stderr, "error: cannot open runtime conf: %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *tok;
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "tenant ", 7) == 0) {
            Tenant t;
            char *rest = line + 7;
            memset(&t, 0, sizeof(t));

            tok = strtok(rest, " ");
            if (!tok)
                continue;
            snprintf(t.name, sizeof(t.name), "%s", tok);

            while ((tok = strtok(NULL, " ")) != NULL) {
                const char *v = kv_value(tok);
                if (!v)
                    continue;
                if (strncmp(tok, "mode=", 5) == 0)
                    snprintf(t.mode, sizeof(t.mode), "%s", v);
                else if (strncmp(tok, "groups=", 7) == 0)
                    split_csv(v, t.groups, &t.group_count);
            }

            if (tcount < MAX_TENANTS)
                tenants[tcount++] = t;
        } else if (strncmp(line, "route ", 6) == 0) {
            Route r;
            char *rest = line + 6;
            memset(&r, 0, sizeof(r));
            snprintf(r.path_prefix, sizeof(r.path_prefix), "/");

            tok = strtok(rest, " ");
            while (tok) {
                const char *v = kv_value(tok);
                if (v) {
                    if (strncmp(tok, "source=", 7) == 0)
                        snprintf(r.source, sizeof(r.source), "%s", v);
                    else if (strncmp(tok, "target=", 7) == 0)
                        snprintf(r.target, sizeof(r.target), "%s", v);
                    else if (strncmp(tok, "host=", 5) == 0)
                        snprintf(r.host, sizeof(r.host), "%s", v);
                    else if (strncmp(tok, "path_prefix=", 12) == 0)
                        snprintf(r.path_prefix, sizeof(r.path_prefix), "%s", v);
                    else if (strncmp(tok, "backend=", 8) == 0)
                        snprintf(r.backend, sizeof(r.backend), "%s", v);
                }
                tok = strtok(NULL, " ");
            }

            if (rcount < MAX_ROUTES)
                routes[rcount++] = r;
        }
    }

    fclose(f);
    *tenant_count = tcount;
    *route_count = rcount;
    return 0;
}

static int parse_query(const char *line,
                       char *source,
                       size_t source_sz,
                       char *target,
                       size_t target_sz,
                       char *host,
                       size_t host_sz,
                       char *path,
                       size_t path_sz,
                       char *action,
                       size_t action_sz)
{
    char buf[LINE_SZ];
    char *tok;

    snprintf(buf, sizeof(buf), "%s", line);
    trim(buf);

    source[0] = '\0';
    target[0] = '\0';
    host[0] = '\0';
    snprintf(path, path_sz, "/");
    snprintf(action, action_sz, "decide");

    tok = strtok(buf, " ");
    while (tok) {
        const char *v = kv_value(tok);
        if (v) {
            if (strncmp(tok, "source=", 7) == 0)
                snprintf(source, source_sz, "%s", v);
            else if (strncmp(tok, "target=", 7) == 0)
                snprintf(target, target_sz, "%s", v);
            else if (strncmp(tok, "host=", 5) == 0)
                snprintf(host, host_sz, "%s", v);
            else if (strncmp(tok, "path=", 5) == 0)
                snprintf(path, path_sz, "%s", v);
            else if (strncmp(tok, "action=", 7) == 0)
                snprintf(action, action_sz, "%s", v);
        }
        tok = strtok(NULL, " ");
    }

    return source[0] != '\0' && target[0] != '\0' && host[0] != '\0';
}

static int connect_unix_backend(const char *path)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int connect_tcp_backend(const char *hostport)
{
    char host[256];
    char port[32];
    const char *colon;
    size_t host_len;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    int fd = -1;

    colon = strrchr(hostport, ':');
    if (!colon || colon == hostport || colon[1] == '\0')
        return -1;

    host_len = (size_t)(colon - hostport);
    if (host_len >= sizeof(host))
        return -1;

    memcpy(host, hostport, host_len);
    host[host_len] = '\0';
    snprintf(port, sizeof(port), "%s", colon + 1);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int connect_backend(const char *backend)
{
    if (strncmp(backend, "unix://", 7) == 0)
        return connect_unix_backend(backend + 7);
    if (strncmp(backend, "tcp://", 6) == 0)
        return connect_tcp_backend(backend + 6);
    return -1;
}

static int pipe_once(int from_fd, int to_fd)
{
    char buf[4096];
    ssize_t n = read(from_fd, buf, sizeof(buf));
    ssize_t off = 0;

    if (n == 0)
        return 0;
    if (n < 0)
        return -1;

    while (off < n) {
        ssize_t w = write(to_fd, buf + off, (size_t)(n - off));
        if (w <= 0)
            return -1;
        off += w;
    }

    return 1;
}

static void tunnel_fds(int client_fd, int backend_fd)
{
    fd_set rfds;
    int maxfd = client_fd > backend_fd ? client_fd : backend_fd;
    int client_open = 1;
    int backend_open = 1;

    while (!g_stop && (client_open || backend_open)) {
        FD_ZERO(&rfds);
        if (client_open)
            FD_SET(client_fd, &rfds);
        if (backend_open)
            FD_SET(backend_fd, &rfds);

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) <= 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (client_open && FD_ISSET(client_fd, &rfds)) {
            int rc = pipe_once(client_fd, backend_fd);
            if (rc == 0) {
                shutdown(backend_fd, SHUT_WR);
                client_open = 0;
            } else if (rc < 0) {
                break;
            }
        }

        if (backend_open && FD_ISSET(backend_fd, &rfds)) {
            int rc = pipe_once(backend_fd, client_fd);
            if (rc == 0) {
                shutdown(client_fd, SHUT_WR);
                backend_open = 0;
            } else if (rc < 0) {
                break;
            }
        }
    }
}

static const Route *decide_route(Tenant tenants[MAX_TENANTS],
                                 int tenant_count,
                                 Route routes[MAX_ROUTES],
                                 int route_count,
                                 const char *source,
                                 const char *target,
                                 const char *host,
                                 const char *path,
                                 const char **deny_reason)
{
    Tenant *src = find_tenant(tenants, tenant_count, source);
    Tenant *tgt = find_tenant(tenants, tenant_count, target);
    int i;

    if (!src || !tgt) {
        *deny_reason = "not_authorized";
        return NULL;
    }

    if (strcmp(src->mode, "discoverer") != 0) {
        *deny_reason = "not_authorized";
        return NULL;
    }

    if (!groups_overlap(src, tgt)) {
        *deny_reason = "not_authorized";
        return NULL;
    }

    for (i = 0; i < route_count; i++) {
        if (strcmp(routes[i].source, source) != 0)
            continue;
        if (strcmp(routes[i].target, target) != 0)
            continue;
        if (strcmp(routes[i].host, host) != 0)
            continue;
        if (!starts_with(path, routes[i].path_prefix))
            continue;
        return &routes[i];
    }

    *deny_reason = "not_authorized";
    return NULL;
}

int main(int argc, char **argv)
{
    const char *runtime_conf = NULL;
    const char *socket_path = NULL;
    Tenant tenants[MAX_TENANTS];
    Route routes[MAX_ROUTES];
    int tenant_count = 0;
    int route_count = 0;
    int server_fd;
    struct sockaddr_un addr;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--runtime-conf") == 0 && i + 1 < argc)
            runtime_conf = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            socket_path = argv[++i];
        else
            die("usage: podmgr-relay-hubd --runtime-conf <path> --socket <path>");
    }

    if (!runtime_conf || !socket_path)
        die("missing required arguments");

    if (parse_runtime_conf(runtime_conf, tenants, &tenant_count, routes, &route_count) != 0)
        return 2;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0)
        die("cannot create unix socket");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path))
        die("socket path too long");
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    unlink(socket_path);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(server_fd);
        die("cannot bind unix socket");
    }

    chmod(socket_path, 0660);

    if (listen(server_fd, 64) != 0) {
        close(server_fd);
        unlink(socket_path);
        die("cannot listen on unix socket");
    }

    fprintf(stderr,
            "relay-hubd listening on %s (tenants=%d routes=%d)\n",
            socket_path,
            tenant_count,
            route_count);

    while (!g_stop) {
        int client_fd;
        char line[LINE_SZ];
        ssize_t n;
        char source[64], target[64], host[256], path[256], action[32];
        const char *deny_reason = "not_authorized";
        const Route *allow;

        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        n = read(client_fd, line, sizeof(line) - 1);
        if (n <= 0) {
            close(client_fd);
            continue;
        }
        line[n] = '\0';

        if (!parse_query(line, source, sizeof(source), target, sizeof(target), host,
                 sizeof(host), path, sizeof(path), action, sizeof(action))) {
            (void)write(client_fd, "DENY reason=invalid_request\n", 28);
            close(client_fd);
            continue;
        }

        allow = decide_route(tenants, tenant_count, routes, route_count, source,
                             target, host, path, &deny_reason);

        if (allow) {
            if (strcmp(action, "proxy") == 0) {
                int backend_fd = connect_backend(allow->backend);
                if (backend_fd < 0) {
                    const char *msg = "DENY reason=backend_connect_failed\n";
                    (void)write(client_fd, msg, strlen(msg));
                    close(client_fd);
                    continue;
                }
                (void)write(client_fd, "ALLOW\n", 6);
                tunnel_fds(client_fd, backend_fd);
                close(backend_fd);
            } else {
                char out[512];
                snprintf(out, sizeof(out), "ALLOW backend=%s\n", allow->backend);
                (void)write(client_fd, out, strlen(out));
            }
        } else {
            char out[256];
            snprintf(out, sizeof(out), "DENY reason=%s\n", deny_reason);
            (void)write(client_fd, out, strlen(out));
        }

        close(client_fd);
    }

    close(server_fd);
    unlink(socket_path);
    return 0;
}
