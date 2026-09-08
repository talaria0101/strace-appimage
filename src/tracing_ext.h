/*
 * tracing_ext.h -- strace-appimage tracing extensions.
 *
 * Shared state and helpers for the packager-oriented extensions:
 *   --json               machine-readable (JSON Lines) event stream
 *   --report-files[=F]   end-of-run report of every path the tracees touched
 *   --anti-anti-debug    spoof ptrace(PTRACE_TRACEME) results and hide
 *                        TracerPid in reads of /proc/<pid>/status
 *   --keep-alive[=N]     suppress exit_group up to N times per process
 *   --packager           preset combining the above for AppImage work
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef STRACE_TRACING_EXT_H
# define STRACE_TRACING_EXT_H

# include "defs.h"

/* Global extension state, set up during option parsing. */
struct tracing_ext_state {
	bool json;		/* --json */
	bool report_files;	/* --report-files */
	bool anti_debug;	/* --anti-anti-debug */
	bool packager;		/* --packager (preset) */
	int keep_alive;		/* --keep-alive=N (0 = off) */
	bool keep_alive_set;	/* --keep-alive given explicitly */
	bool report_files_set;	/* --report-files given explicitly */
	FILE *report_fp;	/* report destination (NULL = shared log) */
};

extern struct tracing_ext_state ext;

static inline bool
extensions_active(void)
{
	return ext.json || ext.report_files || ext.anti_debug
	       || ext.keep_alive > 0;
}

/* Per-syscall path capture (fed from printpathn and friends). */
void ext_reset_paths(struct tcb *tcp);
void ext_note_path(struct tcb *tcp, const char *path);
/* Per-syscall human notes, emitted in JSON events and classic output. */
void ext_reset_notes(struct tcb *tcp);
void ext_add_note(struct tcb *tcp, const char *note);
const char *ext_notes_joined(struct tcb *tcp, char sep);
/* Per-tcb teardown; called from droptcb(). */
void ext_free_tcb(struct tcb *tcp);
/* Shared RFC 8259 string escaper (json events and file report). */
void ext_json_print_string(FILE *fp, const char *s);

/* json_out.c */
void json_emit_begin(int argc, char **argv);
void json_emit_syscall_event(struct tcb *tcp, const struct timespec *ts);
void json_emit_signal_event(struct tcb *tcp, const char *signame,
			    bool coredump);
void json_emit_stop_event(struct tcb *tcp, const char *signame);
void json_emit_exit_event(struct tcb *tcp, int code);
void json_emit_summary(void);
/* file_report.c */
void file_report_note_syscall(struct tcb *tcp);
void file_report_dump(FILE *out_fp);
void file_report_free(void);
/* anti_debug.c */
void anti_debug_syscall_exiting(struct tcb *tcp);

#endif /* !STRACE_TRACING_EXT_H */
