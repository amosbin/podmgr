#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TENANTS 128
#define MAX_GROUPS 32
#define MAX_ROUTES 512
#define MAX_DENIED 1024

typedef struct {
    char name[64];
    int allow_enroll;
    int allow_discoverable;
    int allow_discoverer;
    char groups[MAX_GROUPS][64];
    int group_count;
} PolicyTenant;

typedef struct {
    char name[64];
    int enabled;
    char mode[32];
    char groups[MAX_GROUPS][64];
    int group_count;
} RequestTenant;

typedef struct {
    char source[64];
    char target[64];
    char host[256];
    char path_prefix[128];
    char backend[256];
} Route;

typedef struct {
    char kind[16];
    char reason[128];
    char source[64];
    char target[64];
    char tenant[64];
} Denied;

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

static int truthy(const char *v)
{
    return strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "yes") == 0 || strcmp(v, "on") == 0;
}

static void split_csv(const char *s, char out[MAX_GROUPS][64], int *count)
{
    char *tmp = strdup(s ? s : "");
    char *tok;
    int n = 0;

    if (!tmp) {
        fprintf(stderr, "error: out of memory\n");
        exit(2);
    }

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

static int parse_policy(const char *path,
                        int *hub_enabled,
                        PolicyTenant tenants[MAX_TENANTS],
                        int *tenant_count)
{
    FILE *f = fopen(path, "r");
    char line[2048];
    int count = 0;

    if (!f) {
        fprintf(stderr, "error: cannot open policy file\n");
        return -1;
    }

    *hub_enabled = 0;

    while (fgets(line, sizeof(line), f)) {
        char *tok;
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "hub_enabled=", 12) == 0) {
            *hub_enabled = truthy(line + 12);
            continue;
        }

        if (strncmp(line, "tenant ", 7) == 0) {
            PolicyTenant t;
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
                if (strncmp(tok, "allow_enroll=", 13) == 0)
                    t.allow_enroll = truthy(v);
                else if (strncmp(tok, "allowed_modes=", 14) == 0) {
                    if (strstr(v, "discoverable"))
                        t.allow_discoverable = 1;
                    if (strstr(v, "discoverer"))
                        t.allow_discoverer = 1;
                } else if (strncmp(tok, "allowed_groups=", 15) == 0) {
                    split_csv(v, t.groups, &t.group_count);
                }
            }

            if (count < MAX_TENANTS)
                tenants[count++] = t;
        }
    }

    fclose(f);
    *tenant_count = count;
    return 0;
}

static int parse_request(const char *path,
                         RequestTenant tenants[MAX_TENANTS],
                         int *tenant_count,
                         Route routes[MAX_ROUTES],
                         int *route_count)
{
    FILE *f = fopen(path, "r");
    char line[2048];
    int tcount = 0;
    int rcount = 0;

    if (!f) {
        fprintf(stderr, "error: cannot open request file\n");
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *tok;
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "tenant ", 7) == 0) {
            RequestTenant t;
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
                if (strncmp(tok, "enabled=", 8) == 0)
                    t.enabled = truthy(v);
                else if (strncmp(tok, "mode=", 5) == 0)
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

static PolicyTenant *find_policy(PolicyTenant tenants[MAX_TENANTS], int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(tenants[i].name, name) == 0)
            return &tenants[i];
    return NULL;
}

static RequestTenant *find_request(RequestTenant tenants[MAX_TENANTS], int n, const char *name)
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

static int groups_subset(RequestTenant *req, PolicyTenant *pol)
{
    int i;
    for (i = 0; i < req->group_count; i++)
        if (!has_group(req->groups[i], pol->groups, pol->group_count))
            return 0;
    return 1;
}

static int groups_overlap(RequestTenant *a, RequestTenant *b)
{
    int i;
    for (i = 0; i < a->group_count; i++)
        if (has_group(a->groups[i], b->groups, b->group_count))
            return 1;
    return 0;
}

static void add_denied(Denied denied[MAX_DENIED], int *n,
                       const char *kind,
                       const char *reason,
                       const char *tenant,
                       const char *source,
                       const char *target)
{
    if (*n >= MAX_DENIED)
        return;
    snprintf(denied[*n].kind, sizeof(denied[*n].kind), "%s", kind ? kind : "");
    snprintf(denied[*n].reason, sizeof(denied[*n].reason), "%s", reason ? reason : "");
    snprintf(denied[*n].tenant, sizeof(denied[*n].tenant), "%s", tenant ? tenant : "");
    snprintf(denied[*n].source, sizeof(denied[*n].source), "%s", source ? source : "");
    snprintf(denied[*n].target, sizeof(denied[*n].target), "%s", target ? target : "");
    (*n)++;
}

static void print_json(FILE *out,
                       int hub_enabled,
                       RequestTenant approved_tenants[MAX_TENANTS],
                       int approved_tenant_count,
                       Route approved_routes[MAX_ROUTES],
                       int approved_route_count,
                       Denied denied[MAX_DENIED],
                       int denied_count)
{
    int i;
    int j;

    fprintf(out, "{\n");
    fprintf(out, "  \"hub_enabled\": %s,\n", hub_enabled ? "true" : "false");
    fprintf(out, "  \"approved\": {\n");
    fprintf(out, "    \"tenants\": {\n");

    for (i = 0; i < approved_tenant_count; i++) {
        fprintf(out, "      \"%s\": { \"mode\": \"%s\", \"groups\": [",
                approved_tenants[i].name,
                approved_tenants[i].mode);
        for (j = 0; j < approved_tenants[i].group_count; j++) {
            fprintf(out, "\"%s\"", approved_tenants[i].groups[j]);
            if (j + 1 < approved_tenants[i].group_count)
                fprintf(out, ", ");
        }
        fprintf(out, "] }");
        if (i + 1 < approved_tenant_count)
            fprintf(out, ",");
        fprintf(out, "\n");
    }

    fprintf(out, "    },\n");
    fprintf(out, "    \"routes\": [\n");

    for (i = 0; i < approved_route_count; i++) {
        fprintf(out,
                "      { \"source\": \"%s\", \"target\": \"%s\", \"host\": \"%s\", \"path_prefix\": \"%s\", \"backend\": \"%s\" }",
                approved_routes[i].source,
                approved_routes[i].target,
                approved_routes[i].host,
                approved_routes[i].path_prefix,
                approved_routes[i].backend);
        if (i + 1 < approved_route_count)
            fprintf(out, ",");
        fprintf(out, "\n");
    }

    fprintf(out, "    ]\n");
    fprintf(out, "  },\n");
    fprintf(out, "  \"denied\": [\n");

    for (i = 0; i < denied_count; i++) {
        fprintf(out, "    { \"kind\": \"%s\", \"reason\": \"%s\"",
                denied[i].kind,
                denied[i].reason);
        if (denied[i].tenant[0] != '\0')
            fprintf(out, ", \"tenant\": \"%s\"", denied[i].tenant);
        if (denied[i].source[0] != '\0')
            fprintf(out, ", \"source\": \"%s\"", denied[i].source);
        if (denied[i].target[0] != '\0')
            fprintf(out, ", \"target\": \"%s\"", denied[i].target);
        fprintf(out, " }");
        if (i + 1 < denied_count)
            fprintf(out, ",");
        fprintf(out, "\n");
    }

    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

static void print_runtime_conf(FILE *out,
                               RequestTenant approved_tenants[MAX_TENANTS],
                               int approved_tenant_count,
                               Route approved_routes[MAX_ROUTES],
                               int approved_route_count)
{
    int i;
    int j;

    fprintf(out, "# generated by podmgr-relay-reconcile\n");

    for (i = 0; i < approved_tenant_count; i++) {
        fprintf(out, "tenant %s mode=%s groups=",
                approved_tenants[i].name,
                approved_tenants[i].mode);
        for (j = 0; j < approved_tenants[i].group_count; j++) {
            fprintf(out, "%s", approved_tenants[i].groups[j]);
            if (j + 1 < approved_tenants[i].group_count)
                fprintf(out, ",");
        }
        fprintf(out, "\n");
    }

    fprintf(out, "\n");
    for (i = 0; i < approved_route_count; i++) {
        fprintf(out,
                "route source=%s target=%s host=%s path_prefix=%s backend=%s\n",
                approved_routes[i].source,
                approved_routes[i].target,
                approved_routes[i].host,
                approved_routes[i].path_prefix,
                approved_routes[i].backend);
    }
}

int main(int argc, char **argv)
{
    const char *policy_path = NULL;
    const char *request_path = NULL;
    const char *out_path = NULL;
    const char *runtime_out_path = NULL;
    PolicyTenant policy_tenants[MAX_TENANTS];
    RequestTenant request_tenants[MAX_TENANTS];
    RequestTenant approved_tenants[MAX_TENANTS];
    Route request_routes[MAX_ROUTES];
    Route approved_routes[MAX_ROUTES];
    Denied denied[MAX_DENIED];
    int hub_enabled = 0;
    int policy_count = 0;
    int request_tenant_count = 0;
    int request_route_count = 0;
    int approved_tenant_count = 0;
    int approved_route_count = 0;
    int denied_count = 0;
    FILE *out = stdout;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc)
            policy_path = argv[++i];
        else if (strcmp(argv[i], "--request") == 0 && i + 1 < argc)
            request_path = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (strcmp(argv[i], "--runtime-out") == 0 && i + 1 < argc)
            runtime_out_path = argv[++i];
        else {
            fprintf(stderr, "error: usage: podmgr-relay-reconcile --policy <path> --request <path> [--out <path>] [--runtime-out <path>]\n");
            return 2;
        }
    }

    if (!policy_path || !request_path) {
        fprintf(stderr, "error: missing required arguments\n");
        return 2;
    }

    if (parse_policy(policy_path, &hub_enabled, policy_tenants, &policy_count) != 0)
        return 2;
    if (parse_request(request_path, request_tenants, &request_tenant_count, request_routes, &request_route_count) != 0)
        return 2;

    if (!hub_enabled) {
        add_denied(denied, &denied_count, "hub", "hub disabled by policy", "", "", "");
    } else {
        for (i = 0; i < request_tenant_count; i++) {
            PolicyTenant *pol = find_policy(policy_tenants, policy_count, request_tenants[i].name);
            if (!pol) {
                add_denied(denied, &denied_count, "tenant", "tenant missing from policy", request_tenants[i].name, "", "");
                continue;
            }
            if (!pol->allow_enroll) {
                add_denied(denied, &denied_count, "tenant", "enrollment not allowed by policy", request_tenants[i].name, "", "");
                continue;
            }
            if (!request_tenants[i].enabled) {
                add_denied(denied, &denied_count, "tenant", "tenant not requesting enable", request_tenants[i].name, "", "");
                continue;
            }
            if (strcmp(request_tenants[i].mode, "discoverable") == 0 && !pol->allow_discoverable) {
                add_denied(denied, &denied_count, "tenant", "requested mode not allowed", request_tenants[i].name, "", "");
                continue;
            }
            if (strcmp(request_tenants[i].mode, "discoverer") == 0 && !pol->allow_discoverer) {
                add_denied(denied, &denied_count, "tenant", "requested mode not allowed", request_tenants[i].name, "", "");
                continue;
            }
            if (strcmp(request_tenants[i].mode, "discoverable") != 0 && strcmp(request_tenants[i].mode, "discoverer") != 0) {
                add_denied(denied, &denied_count, "tenant", "invalid requested mode", request_tenants[i].name, "", "");
                continue;
            }
            if (!groups_subset(&request_tenants[i], pol)) {
                add_denied(denied, &denied_count, "tenant", "requested groups not allowed", request_tenants[i].name, "", "");
                continue;
            }
            approved_tenants[approved_tenant_count++] = request_tenants[i];
        }

        for (i = 0; i < request_route_count; i++) {
            RequestTenant *src = find_request(approved_tenants, approved_tenant_count, request_routes[i].source);
            RequestTenant *tgt = find_request(approved_tenants, approved_tenant_count, request_routes[i].target);
            if (!src || !tgt) {
                add_denied(denied, &denied_count, "route", "source or target not approved", "", request_routes[i].source, request_routes[i].target);
                continue;
            }
            if (strcmp(src->mode, "discoverer") != 0) {
                add_denied(denied, &denied_count, "route", "source is not discoverer", "", request_routes[i].source, request_routes[i].target);
                continue;
            }
            if (!groups_overlap(src, tgt)) {
                add_denied(denied, &denied_count, "route", "no shared group", "", request_routes[i].source, request_routes[i].target);
                continue;
            }
            approved_routes[approved_route_count++] = request_routes[i];
        }
    }

    if (out_path) {
        out = fopen(out_path, "w");
        if (!out) {
            fprintf(stderr, "error: cannot open output file\n");
            return 2;
        }
    }

    print_json(out,
               hub_enabled,
               approved_tenants,
               approved_tenant_count,
               approved_routes,
               approved_route_count,
               denied,
               denied_count);

    if (out_path)
        fclose(out);

    if (runtime_out_path) {
        FILE *runtime_out = fopen(runtime_out_path, "w");
        if (!runtime_out) {
            fprintf(stderr, "error: cannot open runtime output file\n");
            return 2;
        }
        print_runtime_conf(runtime_out,
                           approved_tenants,
                           approved_tenant_count,
                           approved_routes,
                           approved_route_count);
        fclose(runtime_out);
    }

    return 0;
}
