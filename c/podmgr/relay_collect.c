#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SZ 8192

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static char *read_all(const char *path)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;

    if (!f)
        die("cannot open compose JSON input");

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        die("cannot seek compose JSON input");
    }

    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        die("cannot size compose JSON input");
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        die("cannot rewind compose JSON input");
    }

    buf = calloc((size_t)sz + 1, 1);
    if (!buf) {
        fclose(f);
        die("out of memory");
    }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        die("cannot read compose JSON input");
    }

    fclose(f);
    return buf;
}

static int str_ieq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static char *extract_label_value(const char *json, const char *key)
{
    char pattern[256];
    const char *p;
    const char *colon;
    const char *vstart;
    const char *vend;
    size_t len;
    char *out;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (!p)
        return NULL;

    colon = strchr(p + strlen(pattern), ':');
    if (!colon)
        return NULL;

    vstart = colon + 1;
    while (*vstart && isspace((unsigned char)*vstart))
        vstart++;

    if (*vstart == '\"') {
        vstart++;
        vend = strchr(vstart, '\"');
        if (!vend)
            return NULL;
    } else {
        vend = vstart;
        while (*vend && *vend != ',' && *vend != '\n' && *vend != '}' &&
               !isspace((unsigned char)*vend))
            vend++;
    }

    len = (size_t)(vend - vstart);
    out = calloc(len + 1, 1);
    if (!out)
        die("out of memory");

    memcpy(out, vstart, len);
    out[len] = '\0';
    return out;
}

static void write_output(const char *out_path,
                         const char *tenant,
                         const char *enabled,
                         const char *mode,
                         const char *groups,
                         const char *source,
                         const char *target,
                         const char *host,
                         const char *path_prefix,
                         const char *backend)
{
    FILE *out = stdout;

    if (out_path) {
        out = fopen(out_path, "w");
        if (!out)
            die("cannot open output path");
    }

    fprintf(out,
            "tenant %s enabled=%s mode=%s groups=%s\n",
            tenant,
            enabled ? enabled : "false",
            mode ? mode : "",
            groups ? groups : "");

    if (target && host && backend) {
        fprintf(out,
                "route source=%s target=%s host=%s path_prefix=%s backend=%s\n",
                source ? source : tenant,
                target,
                host,
                path_prefix ? path_prefix : "/",
                backend);
    }

    if (out_path)
        fclose(out);
}

int main(int argc, char **argv)
{
    const char *tenant = NULL;
    const char *compose_json = NULL;
    const char *out_path = NULL;
    char *json;
    char *enabled;
    const char *enabled_norm;
    char *mode;
    char *groups;
    char *source;
    char *target;
    char *host;
    char *path_prefix;
    char *backend;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tenant") == 0 && i + 1 < argc) {
            tenant = argv[++i];
        } else if (strcmp(argv[i], "--compose-json") == 0 && i + 1 < argc) {
            compose_json = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            die("usage: podmgr-relay-collect --tenant <name> --compose-json <path> [--out <path>]");
        }
    }

    if (!tenant || !compose_json)
        die("missing required arguments");

    json = read_all(compose_json);

    enabled = extract_label_value(json, "io.podmgr.relay.enabled");
    mode = extract_label_value(json, "io.podmgr.relay.mode");
    groups = extract_label_value(json, "io.podmgr.relay.groups");
    source = extract_label_value(json, "io.podmgr.relay.source");
    target = extract_label_value(json, "io.podmgr.relay.target");
    host = extract_label_value(json, "io.podmgr.relay.host");
    path_prefix = extract_label_value(json, "io.podmgr.relay.path_prefix");
    backend = extract_label_value(json, "io.podmgr.relay.backend");

    if (!enabled)
        enabled = strdup("false");
    if (!mode)
        mode = strdup("");
    if (!groups)
        groups = strdup("");

    if (!enabled || !mode || !groups)
        die("out of memory");

    if (str_ieq(enabled, "true") || str_ieq(enabled, "1") || str_ieq(enabled, "yes"))
        enabled_norm = "true";
    else
        enabled_norm = "false";

    write_output(out_path,
                 tenant,
                 enabled_norm,
                 mode,
                 groups,
                 source,
                 target,
                 host,
                 path_prefix,
                 backend);

    free(json);
    free(enabled);
    free(mode);
    free(groups);
    free(source);
    free(target);
    free(host);
    free(path_prefix);
    free(backend);

    return 0;
}
