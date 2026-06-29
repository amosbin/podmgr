#ifndef PODMGR_VALIDATION_H
#define PODMGR_VALIDATION_H

#include <stddef.h>

/*
 * Build the managed-marker path into buf (size bufsz) and return buf.
 * Path: /var/lib/<user>/<marker_name>
 */
char *managed_marker_path(const char *user, char *buf, size_t bufsz);

/*
 * Validate that `user` matches [a-z_][a-z0-9_-]{0,31} and is not "root".
 * Calls log_die on failure.
 */
void validate_user(const char *user);

/*
 * Check that the managed-marker file exists for `user`.
 * Calls log_die if absent (user is not podmgr-managed).
 */
void ensure_managed_user(const char *user);

/*
 * Validate that compose_dir is absolute, contains no control characters,
 * and is located under g_cfg.base_dir.
 * Calls log_die on failure.
 */
void validate_compose_dir(const char *compose_dir);

/*
 * If compose_dir already exists on disk it must be a directory owned by user.
 * Calls log_die otherwise; returns silently if the path is absent.
 */
void ensure_compose_dir_ownership_or_absence(const char *user,
                                             const char *compose_dir);

/*
 * Runtime preflight for commands that use compose_dir as cwd.
 * Ensures compose_dir exists, is a directory, is owned by user, and has
 * owner execute permission. When require_compose_file is non-zero, also
 * validates that <compose_dir>/<compose_file> exists, is regular, is owned
 * by user, and is owner-readable. For compose.yaml/compose.yml, either
 * extension is accepted.
 */
void ensure_compose_runtime_ready(const char *user,
                                  const char *compose_dir,
                                  int require_compose_file);

#endif /* PODMGR_VALIDATION_H */
