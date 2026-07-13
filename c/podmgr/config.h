#ifndef PODMGR_CONFIG_H
#define PODMGR_CONFIG_H

#define CONF_FILE              "/etc/podmgr.conf"
#define DEFAULT_LOG_DEST       "file"
#define DEFAULT_LOG_FILE       "/var/log/podmgr.log"
#define DEFAULT_BASE_DIR       "/srv/podmgr"
#define DEFAULT_MARKER_NAME    ".podmgr"
#define DEFAULT_TEMPLATE_DIR   "/usr/lib/podmgr"
#define DEFAULT_COMPOSE_FILE   "compose.yaml"
#define DEFAULT_UNQUALIFIED_REGISTRY "docker.io"

typedef struct {
    char log_dest[16];        /* "file" | "journal" | "both" */
    char log_file[256];
    char base_dir[256];
    char marker_name[64];
    char template_dir[256];   /* dir containing the workload service template */
    char compose_file[128];   /* compose file name (e.g. compose.yaml) */
    int  use_quadlet;         /* prefer Podman Quadlet for unit generation if available */
    int  default_registry_enable; /* write per-user unqualified registry defaults */
    char default_unqualified_registry[256];
} podmgr_config_t;

extern podmgr_config_t g_cfg;

/* Populate g_cfg from CONF_FILE, falling back to compile-time defaults. */
void config_load(void);

#endif /* PODMGR_CONFIG_H */
