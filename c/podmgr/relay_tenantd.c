#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

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

static int connect_upstream(const char *upstream)
{
    if (strncmp(upstream, "unix://", 7) == 0)
        return connect_unix_backend(upstream + 7);
    if (strncmp(upstream, "tcp://", 6) == 0)
        return connect_tcp_backend(upstream + 6);
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

static void tunnel_fds(int client_fd, int upstream_fd)
{
    fd_set rfds;
    int maxfd = client_fd > upstream_fd ? client_fd : upstream_fd;
    int client_open = 1;
    int upstream_open = 1;

    while (!g_stop && (client_open || upstream_open)) {
        FD_ZERO(&rfds);
        if (client_open)
            FD_SET(client_fd, &rfds);
        if (upstream_open)
            FD_SET(upstream_fd, &rfds);

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) <= 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (client_open && FD_ISSET(client_fd, &rfds)) {
            int rc = pipe_once(client_fd, upstream_fd);
            if (rc == 0) {
                shutdown(upstream_fd, SHUT_WR);
                client_open = 0;
            } else if (rc < 0) {
                break;
            }
        }

        if (upstream_open && FD_ISSET(upstream_fd, &rfds)) {
            int rc = pipe_once(upstream_fd, client_fd);
            if (rc == 0) {
                shutdown(client_fd, SHUT_WR);
                upstream_open = 0;
            } else if (rc < 0) {
                break;
            }
        }
    }
}

int main(int argc, char **argv)
{
    const char *listen_path = NULL;
    const char *upstream = NULL;
    int server_fd;
    struct sockaddr_un addr;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc)
            listen_path = argv[++i];
        else if (strcmp(argv[i], "--upstream") == 0 && i + 1 < argc)
            upstream = argv[++i];
        else
            die("usage: podmgr-relay-tenantd --listen <unix-socket> --upstream <tcp://host:port|unix:///path>");
    }

    if (!listen_path || !upstream)
        die("missing required arguments");

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0)
        die("cannot create unix socket");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(listen_path) >= sizeof(addr.sun_path))
        die("listen path too long");
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", listen_path);

    unlink(listen_path);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(server_fd);
        die("cannot bind unix socket");
    }

    chmod(listen_path, 0660);

    if (listen(server_fd, 64) != 0) {
        close(server_fd);
        unlink(listen_path);
        die("cannot listen on unix socket");
    }

    fprintf(stderr, "relay-tenantd listening on %s upstream=%s\n", listen_path, upstream);

    while (!g_stop) {
        int client_fd = accept(server_fd, NULL, NULL);
        int upstream_fd;

        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        upstream_fd = connect_upstream(upstream);
        if (upstream_fd < 0) {
            const char *msg = "ERROR upstream_connect_failed\n";
            (void)write(client_fd, msg, strlen(msg));
            close(client_fd);
            continue;
        }

        tunnel_fds(client_fd, upstream_fd);
        close(upstream_fd);
        close(client_fd);
    }

    close(server_fd);
    unlink(listen_path);
    return 0;
}
