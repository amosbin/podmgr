#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>

podmgr_config_t g_cfg;

static void trim_trailing(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' '  || s[len-1] == '\t'))
        s[--len] = '\0';
}

/*
 * Copy src into dst (size dstsz, always NUL-terminated). If src would not fit,
 * warn loudly: a truncated base_dir would weaken the compose-dir prefix check.
 */
static void set_field(const char *key, char *dst, size_t dstsz, const char *src)
{
    if (strlen(src) >= dstsz)
        log_warn("config value for %s is too long (max %zu chars); truncating",
                 key, dstsz - 1);
    snprintf(dst, dstsz, "%s", src);
}

void config_load(void)
{
    /* Apply defaults (snprintf always NUL-terminates). */
    snprintf(g_cfg.log_dest,       sizeof(g_cfg.log_dest),       "%s", DEFAULT_LOG_DEST);
    snprintf(g_cfg.log_file,       sizeof(g_cfg.log_file),       "%s", DEFAULT_LOG_FILE);
    snprintf(g_cfg.base_dir,       sizeof(g_cfg.base_dir),       "%s", DEFAULT_BASE_DIR);
    snprintf(g_cfg.marker_name,    sizeof(g_cfg.marker_name),    "%s", DEFAULT_MARKER_NAME);
    snprintf(g_cfg.template_dir,   sizeof(g_cfg.template_dir),   "%s", DEFAULT_TEMPLATE_DIR);
    snprintf(g_cfg.compose_file,   sizeof(g_cfg.compose_file),   "%s", DEFAULT_COMPOSE_FILE);
    g_cfg.use_quadlet = 0;

    FILE *f = fopen(CONF_FILE, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        trim_trailing(line);
        /* Skip blank lines and comments. */
        if (line[0] == '#' || line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if      (strcmp(key, "LOG_DEST")        == 0)
            set_field(key, g_cfg.log_dest,     sizeof(g_cfg.log_dest),     val);
        else if (strcmp(key, "LOG_FILE")        == 0)
            set_field(key, g_cfg.log_file,     sizeof(g_cfg.log_file),     val);
        else if (strcmp(key, "PODMGR_BASE_DIR") == 0)
            set_field(key, g_cfg.base_dir,     sizeof(g_cfg.base_dir),     val);
        else if (strcmp(key, "TEMPLATE_DIR")    == 0)
            set_field(key, g_cfg.template_dir, sizeof(g_cfg.template_dir), val);
        else if (strcmp(key, "COMPOSE_FILE")    == 0)
            set_field(key, g_cfg.compose_file,   sizeof(g_cfg.compose_file),   val);
        else if (strcmp(key, "USE_QUADLET")     == 0)
            g_cfg.use_quadlet = (strcmp(val, "1") == 0 || strcmp(val, "true") == 0 ||
                                 strcmp(val, "yes") == 0);
    }
    fclose(f);
}
