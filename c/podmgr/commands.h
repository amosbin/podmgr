#ifndef PODMGR_COMMANDS_H
#define PODMGR_COMMANDS_H

/* Create system user, configure rootless podman, deploy systemd service. */
void do_setup(const char *user, const char *compose_dir);

/* Tear down and delete a podmgr-managed user and all its data. */
void do_cleanup(const char *user, const char *compose_dir);

/* Cleanup then setup (full reinstall). */
void do_reinstall(const char *user, const char *compose_dir);

/* podman compose up -d  (cwd = compose_dir). */
void do_up(const char *user, const char *compose_dir);

/* podman compose down. */
void do_down(const char *user, const char *compose_dir);

/* down then up. */
void do_restart(const char *user, const char *compose_dir);

/* systemctl --user start/stop <user>.service */
void do_enable(const char *user);
void do_start(const char *user);
void do_stop(const char *user);

/* systemctl --user stop <user>.service */
void do_kill(const char *user);

/* podman ps */
void do_ps(const char *user, const char *compose_dir);

/* podman stats --no-stream (optionally also podman system df). */
void do_stats(const char *user, const char *compose_dir, int show_df);

/* podman system prune (-a, --volumes). */
void do_prune(const char *user, const char *compose_dir, int all_images,
			  int volumes);

/* Start an interactive shell in the managed host user context. */
void do_shell(const char *user, const char *compose_dir);

/* Run an arbitrary command in the managed host user context. */
void do_run(const char *user, const char *compose_dir, char *const argv[]);

/*
 * Exec into a running container.
 * If container is NULL or empty, the first running container is used.
 * Replaces the podmgr process (execvp) for interactive use.
 */
void do_exec(const char *user, const char *compose_dir, const char *container);

/* Run a non-interactive command in a target container. */
void do_run_in(const char *user, const char *compose_dir, const char *container,
			   char *const argv[]);

/* Follow container logs and show container process table. */
void do_clogs(const char *user, const char *compose_dir, const char *container);
void do_cp(const char *user, const char *compose_dir, char *const argv[]);
void do_top(const char *user, const char *compose_dir, const char *container);

/* Copy a local file/dir into the user's compose directory with user ownership. */
void do_adopt(const char *user, const char *compose_dir, const char *src_path);

/* Follow the user's journal (replaces process with journalctl -f). */
void do_journal(const char *user);

/* Show managed-user status and full info. */
void do_status(const char *user, const char *compose_dir);
void do_info(const char *user, const char *compose_dir);

/* Subid and diagnostics helpers. */
void do_subid(const char *user);
void do_subid_check(void);
void do_subid_reclaim(void);

/* Print podmgr version. */
void do_version(void);

/* Print a table of containers across all managed users. */
void do_list(int show_all, int as_json);

/* Print managed users only, one per line. */
void do_users(int as_json);

#endif /* PODMGR_COMMANDS_H */
