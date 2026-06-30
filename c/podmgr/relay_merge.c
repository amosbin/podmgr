#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TENANTS 512
#define MAX_ROUTES 2048
#define LINE_SZ 2048

typedef struct {
    char name[64];
    char line[LINE_SZ];
} TenantLine;

typedef struct {
    char line[LINE_SZ];
} RouteLine;

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

static int parse_tenant_name(const char *line, char *name, size_t name_sz)
{
    const char *p = line;
    const char *sp;
    size_t len;

    if (strncmp(p, "tenant ", 7) != 0)
        return 0;
    p += 7;
    sp = strchr(p, ' ');
    if (!sp)
        return 0;
    len = (size_t)(sp - p);
    if (len == 0 || len >= name_sz)
        return 0;
    memcpy(name, p, len);
    name[len] = '\0';
    return 1;
}

int main(int argc, char **argv)
{
    const char *out_path = NULL;
    TenantLine tenants[MAX_TENANTS];
    RouteLine routes[MAX_ROUTES];
    int tenant_count = 0;
    int route_count = 0;
    int i;
    FILE *out;

    if (argc < 4)
        goto usage;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
            continue;
        }
        break;
    }

    if (!out_path || i >= argc)
        goto usage;

    for (; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        char line[LINE_SZ];
        if (!f) {
            fprintf(stderr, "error: cannot open request file: %s\n", argv[i]);
            return 2;
        }

        while (fgets(line, sizeof(line), f)) {
            char tenant_name[64];
            int t;

            trim(line);
            if (line[0] == '\0' || line[0] == '#')
                continue;

            if (parse_tenant_name(line, tenant_name, sizeof(tenant_name))) {
                for (t = 0; t < tenant_count; t++) {
                    if (strcmp(tenants[t].name, tenant_name) == 0) {
                        snprintf(tenants[t].line, sizeof(tenants[t].line), "%s", line);
                        break;
                    }
                }
                if (t == tenant_count && tenant_count < MAX_TENANTS) {
                    snprintf(tenants[tenant_count].name, sizeof(tenants[tenant_count].name), "%s", tenant_name);
                    snprintf(tenants[tenant_count].line, sizeof(tenants[tenant_count].line), "%s", line);
                    tenant_count++;
                }
                continue;
            }

            if (strncmp(line, "route ", 6) == 0) {
                if (route_count < MAX_ROUTES) {
                    snprintf(routes[route_count].line, sizeof(routes[route_count].line), "%s", line);
                    route_count++;
                }
                continue;
            }
        }

        fclose(f);
    }

    out = fopen(out_path, "w");
    if (!out) {
        fprintf(stderr, "error: cannot open output file\n");
        return 2;
    }

    fprintf(out, "# merged by podmgr-relay-merge\n");
    for (i = 0; i < tenant_count; i++)
        fprintf(out, "%s\n", tenants[i].line);
    fprintf(out, "\n");
    for (i = 0; i < route_count; i++)
        fprintf(out, "%s\n", routes[i].line);

    fclose(out);
    return 0;

usage:
    fprintf(stderr, "usage: podmgr-relay-merge --out <merged-request.conf> <request1.conf> [request2.conf ...]\n");
    return 2;
}
