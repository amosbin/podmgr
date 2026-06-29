#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "logging.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

log_verbosity_t g_log_verbosity = LOG_V_DEFAULT;

static void emit(const char *level, const char *msg)
{
    char ts[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    /* stderr gating:
     *   ERROR  → stderr unless -q (LOG_V_QUIET)
     *   WARN   → stderr only with -v (LOG_V_VERBOSE)
     *   INFO   → stderr only with -v (LOG_V_VERBOSE) */
    int is_error = (strcmp(level, "ERROR") == 0);
    int show_stderr = is_error ? (g_log_verbosity >= LOG_V_DEFAULT)
                               : (g_log_verbosity >= LOG_V_VERBOSE);
    if (show_stderr)
        fprintf(stderr, "%s podmgr[%d] %s: %s\n", ts, (int)getpid(), level, msg);

    if (strcmp(g_cfg.log_dest, "file") == 0 ||
        strcmp(g_cfg.log_dest, "both") == 0) {
        FILE *lf = fopen(g_cfg.log_file, "a");
        if (lf) {
            fprintf(lf, "%s podmgr[%d] %s: %s\n", ts, (int)getpid(), level, msg);
            fclose(lf);
        }
    }

    if (strcmp(g_cfg.log_dest, "journal") == 0 ||
        strcmp(g_cfg.log_dest, "both")    == 0) {
        int priority = LOG_INFO;
        if (strcmp(level, "WARN")  == 0) priority = LOG_WARNING;
        if (strcmp(level, "ERROR") == 0) priority = LOG_ERR;
        openlog("podmgr", LOG_PID, LOG_DAEMON);
        syslog(priority, "%s: %s", level, msg);
        closelog();
    }
}

static void vemit(const char *level, const char *fmt, va_list ap)
{
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    emit(level, msg);
}

void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vemit("INFO", fmt, ap);
    va_end(ap);
}

void log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vemit("WARN", fmt, ap);
    va_end(ap);
}

void log_die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vemit("ERROR", fmt, ap);
    va_end(ap);
    exit(1);
}
