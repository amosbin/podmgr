#ifndef PODMGR_LOGGING_H
#define PODMGR_LOGGING_H

/*
 * Verbosity level controlling what appears on stderr.
 *
 *   LOG_V_QUIET   (-q)  nothing on stderr, not even errors
 *   LOG_V_DEFAULT       errors only (default)
 *   LOG_V_VERBOSE (-v)  info + warnings + errors
 */
typedef enum {
    LOG_V_QUIET   = 0,
    LOG_V_DEFAULT = 1,
    LOG_V_VERBOSE = 2
} log_verbosity_t;

extern log_verbosity_t g_log_verbosity;

/* Emit a structured INFO line (log file / journal per config; stderr only with -v). */
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Same but at WARN level; does NOT exit. stderr only with -v. */
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Emit an ERROR line and call exit(1). Goes to stderr unless -q. */
void log_die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

#endif /* PODMGR_LOGGING_H */
