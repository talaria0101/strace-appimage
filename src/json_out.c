/*
 * json_out.c -- machine-readable (JSON Lines) output for strace-appimage.
 *
 * One self-contained JSON object per line, so that agents and ordinary
 * tooling (jq, grep, python) can consume the trace without a custom
 * parser.  The classic decoded line is preserved verbatim in the "line"
 * field; the interesting parts of it are additionally exposed as typed
 * fields (syscall name, paths, fd, return value, errno name, duration).
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "tracing_ext.h"

#include <limits.h>
#include <time.h>
#include <sys/utsname.h>

struct tracing_ext_state ext;

static unsigned long json_event_count;
static unsigned long json_error_events;

static void
json_print_string_strip_nl(FILE *fp, const char *s)
{
	char *copy = xstrdup(s);
	size_t len = strlen(copy);
	while (len > 0 && copy[len - 1] == '\n')
		copy[--len] = '\0';
	ext_json_print_string(fp, copy);
	free(copy);
}

/* Print a timespec duration in microseconds, without a trailing comma. */
static void
json_print_dur_us(FILE *fp, const struct timespec *ts)
{
	unsigned long long us = (unsigned long long) ts->tv_sec * 1000000
				+ ts->tv_nsec / 1000;
	fprintf(fp, "%llu", us);
}

void
json_emit_begin(int argc, char **argv)
{
	FILE *fp = shared_log;

	if (!ext.json)
		return;

	struct utsname uts;

	uname(&uts);
	fprintf(fp, "{\"type\":\"begin\",\"tool\":\"strace-appimage\","
		   "\"strace_version\":\"%s\",\"kernel\":\"%s\","
		   "\"argv\":[", PACKAGE_VERSION, uts.release);
	for (int i = 0; i < argc && argv[i]; ++i) {
		if (i)
			fputc(',', fp);
		ext_json_print_string(fp, argv[i]);
	}
	fputs("]}\n", fp);
}

/*
 * Emit one JSON event for the syscall that just finished.  Called from
 * syscall_exiting_trace() with the staged classic output still open, so
 * the full decoded line is available verbatim.  When the syscall failed
 * to decode (res != 1 in the caller), ts may be NULL.
 */
void
json_emit_syscall_event(struct tcb *tcp, const struct timespec *ts)
{
	FILE *fp = shared_log;
	const struct_sysent *ent = tcp_sysent(tcp);

	if (!ext.json)
		return;

	++json_event_count;
	if (tcp->u_error)
		++json_error_events;

	fprintf(fp, "{\"type\":\"syscall\",\"pid\":%d,\"syscall\":",
		tcp->pid);
	ext_json_print_string(fp, ent->sys_name);

	/* Raw syscall arguments, in order, as unsigned numbers. */
	fputs(",\"args\":[", fp);
	for (unsigned int i = 0; i < MAX_ARGS; ++i) {
		if (i)
			fputc(',', fp);
		fprintf(fp, "%" PRI_klu, tcp->u_arg[i]);
	}
	fputc(']', fp);

	/* Paths captured while decoding this syscall. */
	if (tcp->ext_npaths > 0) {
		fputs(",\"paths\":[", fp);
		for (unsigned int i = 0; i < tcp->ext_npaths; ++i) {
			if (i)
				fputc(',', fp);
			ext_json_print_string(fp, tcp->ext_paths[i]);
		}
		fputc(']', fp);
	}

	/* Return value and errno. */
	if (tcp->u_error) {
		const char *name = tcp->u_error < nerrnos
				   ? errnoent[tcp->u_error] : NULL;
		char buf[64];

		if (!name) {
			snprintf(buf, sizeof(buf), "ERRNO_%lu",
				 tcp->u_error);
			name = buf;
		}
		fprintf(fp, ",\"ret\":%" PRI_kld ",\"errno\":",
			(kernel_long_t) tcp->u_rval);
		ext_json_print_string(fp, name);
	} else {
		fprintf(fp, ",\"ret\":%" PRI_kld ",\"errno\":null",
			tcp->u_rval);
	}

	/* Duration, when it was measured. */
	if (ts) {
		struct timespec dur;

		ts_sub(&dur, ts, &tcp->etime);
		fputs(",\"dur_us\":", fp);
		json_print_dur_us(fp, &dur);
	}

	/* Wall-clock time of the event. */
	{
		struct timespec now;

		clock_gettime(CLOCK_REALTIME, &now);
		fprintf(fp, ",\"time\":%lld.%06ld",
			(long long) now.tv_sec, now.tv_nsec / 1000);
	}

	/*
	 * For syscalls whose decoder declared an fd return value
	 * (RVAL_FD), resolve the fresh fd to a path.
	 */
	if (!tcp->u_error && tcp->u_rval >= 0 &&
	    tcp->u_rval <= INT_MAX && tcp->ext_npaths > 0 &&
	    (tcp->sys_func_rval & RVAL_MASK) == RVAL_FD) {
		char fdpath[PATH_MAX + 1];

		if (getfdpath(tcp, (int) tcp->u_rval, fdpath,
			      sizeof(fdpath)) >= 0) {
			fputs(",\"fd\":", fp);
			fprintf(fp, "%" PRI_kld, tcp->u_rval);
			fputs(",\"fd_path\":", fp);
			ext_json_print_string(fp, fdpath);
		}
	}

	/* The classic strace line, verbatim minus the trailing newline. */
	{
		const char *staged = strace_staged_output(tcp);

		if (staged) {
			fputs(",\"line\":", fp);
			json_print_string_strip_nl(fp, staged);
		}
	}

	/* Extension notes (keep-alive, anti-debug actions, ...). */
	if (tcp->ext_nnotes > 0) {
		fputs(",\"notes\":[", fp);
		for (unsigned int i = 0; i < tcp->ext_nnotes; ++i) {
			if (i)
				fputc(',', fp);
			ext_json_print_string(fp, tcp->ext_notes[i]);
		}
		fputc(']', fp);
	}

	fputs("}\n", fp);
}

/*
 * Minimal process-lifecycle events, replacing the classic
 * "+++ killed by SIG... +++" / "+++ exited with N +++" lines so that a
 * --json stream stays parseable line by line.  The signal name is
 * resolved by the caller (strace.c owns sprintsigname()).
 */
void
json_emit_signal_event(struct tcb *tcp, const char *signame, bool coredump)
{
	FILE *fp = shared_log;

	if (!ext.json)
		return;

	++json_event_count;
	fprintf(fp, "{\"type\":\"signal\",\"pid\":%d,\"signal\":",
		tcp->pid);
	ext_json_print_string(fp, signame ?: "SIG?");
	fprintf(fp, ",\"core_dumped\":%s}\n", coredump ? "true" : "false");
}

/*
 * Signal-delivery-stop event (the classic "--- SIG... ---" line),
 * without the full siginfo decoding (kept minimal for the PoC).
 */
void
json_emit_stop_event(struct tcb *tcp, const char *signame)
{
	FILE *fp = shared_log;

	if (!ext.json)
		return;

	++json_event_count;
	fprintf(fp, "{\"type\":\"signal\",\"pid\":%d,\"signal\":",
		tcp->pid);
	ext_json_print_string(fp, signame ?: "SIG?");
	fputs(",\"stop\":true}\n", fp);
}

void
json_emit_exit_event(struct tcb *tcp, int code)
{
	FILE *fp = shared_log;

	if (!ext.json)
		return;

	++json_event_count;
	fprintf(fp, "{\"type\":\"exit\",\"pid\":%d,\"code\":%d}\n",
		tcp->pid, code);
}

void
json_emit_summary(void)
{
	FILE *fp = shared_log;

	if (!ext.json)
		return;

	fprintf(fp, "{\"type\":\"summary\",\"events\":%lu,"
		   "\"events_with_error\":%lu}\n",
		json_event_count, json_error_events);
}
