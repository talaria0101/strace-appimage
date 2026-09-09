/*
 * tracing_ext.c -- shared state and per-syscall capture helpers for the
 * strace-appimage tracing extensions (see tracing_ext.h).
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "tracing_ext.h"

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#ifndef AT_FDCWD
# define AT_FDCWD -100
#endif

/*
 * Print a JSON string literal (with the surrounding quotes) into fp,
 * escaping what must be escaped.  strace output can contain arbitrary
 * tracee bytes, so escape strictly per RFC 8259 and switch to \uXXXX
 * for anything not safely printable.  Shared by the --json event
 * emitter and the --report-files dump.
 */
void
ext_json_print_string(FILE *fp, const char *s)
{
	fputc('"', fp);
	for (const unsigned char *p = (const unsigned char *) s; *p; ++p) {
		switch (*p) {
		case '"':
			fputs("\\\"", fp);
			break;
		case '\\':
			fputs("\\\\", fp);
			break;
		case '\b':
			fputs("\\b", fp);
			break;
		case '\f':
			fputs("\\f", fp);
			break;
		case '\n':
			fputs("\\n", fp);
			break;
		case '\r':
			fputs("\\r", fp);
			break;
		case '\t':
			fputs("\\t", fp);
			break;
		default:
			if (*p < 0x20 || *p == 0x7f)
				fprintf(fp, "\\u%04x", *p);
			else
				fputc(*p, fp);
		}
	}
	fputc('"', fp);
}

/*
 * --keep-alive: a process that faulted right after a suppressed
 * exit_group did not really die by that fault; it fell off the end of
 * its own exit path (glibc ends _exit in hlt).  Callers report the
 * status of the last suppressed exit_group as the tracee's outcome
 * instead of propagating the fault signal, so scripted runs of
 * --keep-alive stay exit-status-clean.
 */
bool
ext_keepalive_fault_status(const struct tcb *tcp, unsigned int sig,
			   int *code_out)
{
	if (!tcp || !tcp->keepalive_any)
		return false;

	switch (sig) {
		case SIGILL:
		case SIGTRAP:
		case SIGBUS:
		case SIGSEGV:
			*code_out = tcp->keepalive_code;
			return true;
		default:
			return false;
	}
}

/*
 * Parse the --anti-anti-debug[=SPEC] feature list: comma-separated
 * features (traceme, status, wchan, all), each optionally suffixed
 * ":off" to disable it.  Returns false on an unknown feature.
 */
bool
ext_anti_debug_parse_spec(const char *spec)
{
	char copy[256];
	char *tok;

	if (strlen(spec) >= sizeof(copy))
		return false;
	strcpy(copy, spec);

	for (tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
		unsigned int bit;
		bool off = false;
		char *colon = strstr(tok, ":off");

		if (colon) {
			*colon = '\0';
			off = true;
		}
		if (strcmp(tok, "all") == 0)
			bit = AD_ALL;
		else if (strcmp(tok, "traceme") == 0)
			bit = AD_TRACEME;
		else if (strcmp(tok, "status") == 0)
			bit = AD_STATUS;
		else if (strcmp(tok, "wchan") == 0)
			bit = AD_WCHAN;
		else
			return false;

		if (off)
			ext.anti_debug_features &= ~bit;
		else
			ext.anti_debug_features |= bit;
	}
	ext.anti_debug = ext.anti_debug_features != 0;
	return true;
}

void
ext_reset_paths(struct tcb *tcp)
{
	for (unsigned int i = 0; i < tcp->ext_npaths && i < EXT_MAX_PATHS_PER_SYSCALL; ++i) {
		free(tcp->ext_paths[i]);
		tcp->ext_paths[i] = NULL;
	}
	tcp->ext_npaths = 0;
}

/*
 * dirfd context for *at syscalls: for each path argument ordinal, which
 * u_arg holds the dirfd it is relative to (0xff = path not covered).
 * Syscalls absent from this table resolve relative paths against the
 * tracee's cwd, which is what the plain-path syscalls mean.
 */
struct ext_at_entry {
	const char *name;
	unsigned char dirfd_arg[EXT_MAX_PATHS_PER_SYSCALL];
};

static const struct ext_at_entry ext_at_table[] = {
	{ "openat",	{ 0, 0xff, 0xff, 0xff } },
	{ "openat2",	{ 0, 0xff, 0xff, 0xff } },
	{ "execveat",	{ 0, 0xff, 0xff, 0xff } },
	{ "faccessat",	{ 0, 0xff, 0xff, 0xff } },
	{ "faccessat2",	{ 0, 0xff, 0xff, 0xff } },
	{ "newfstatat",	{ 0, 0xff, 0xff, 0xff } },
	{ "statx",	{ 0, 0xff, 0xff, 0xff } },
	{ "readlinkat",	{ 0, 0xff, 0xff, 0xff } },
	{ "unlinkat",	{ 0, 0xff, 0xff, 0xff } },
	{ "mkdirat",	{ 0, 0xff, 0xff, 0xff } },
	{ "mknodat",	{ 0, 0xff, 0xff, 0xff } },
	{ "fchmodat",	{ 0, 0xff, 0xff, 0xff } },
	{ "fchmodat2",	{ 0, 0xff, 0xff, 0xff } },
	{ "fchownat",	{ 0, 0xff, 0xff, 0xff } },
	{ "utimensat",	{ 0, 0xff, 0xff, 0xff } },
	{ "renameat",	{ 0, 0xff, 2, 0xff } },
	{ "renameat2",	{ 0, 0xff, 2, 0xff } },
	{ "linkat",	{ 0, 0xff, 2, 0xff } },
	{ "symlinkat",	{ 0xff, 1, 0xff, 0xff } },
};

/*
 * Resolve a decoded path the way the tracee would, for --report-files
 * and --json: relative paths are prefixed with the dirfd's path (read
 * from /proc/<pid>/fd/<dirfd>) or the tracee's cwd (AT_FDCWD, and every
 * syscall without a dirfd argument).  Absolute paths need no
 * resolution.  Returns false when nothing better than the raw path is
 * available (unreadable /proc, non-directory dirfd such as a socket). */
static bool
ext_resolve_path(struct tcb *tcp, const char *path, char *out, size_t outsz)
{
	int dirfd = AT_FDCWD;
	char base[PATH_MAX];

	if (path[0] == '/')
		return false;		/* already absolute */

	if (path[0] == '\0' && tcp->ext_npaths < EXT_MAX_PATHS_PER_SYSCALL) {
		/*
		 * Empty path with a real dirfd (AT_EMPTY_PATH users:
		 * fchownat, linkat, execveat, ...) refers to the dirfd
		 * itself; record what that fd points at.
		 */
		const struct ext_at_entry *e = NULL;

		for (size_t i = 0; i < ARRAY_SIZE(ext_at_table); ++i)
			if (strcmp(ext_at_table[i].name,
				   tcp_sysent(tcp)->sys_name) == 0)
				e = &ext_at_table[i];
		if (!e)
			return false;
		if (e->dirfd_arg[tcp->ext_npaths] == 0xff)
			return false;
		dirfd = (int) tcp->u_arg[e->dirfd_arg[tcp->ext_npaths]];
		if (dirfd == AT_FDCWD)
			return false;
		if (getfdpath(tcp, dirfd, base, sizeof(base)) < 0)
			return false;
		snprintf(out, outsz, "%s", base);
		return true;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ext_at_table); ++i)
		if (strcmp(ext_at_table[i].name,
			   tcp_sysent(tcp)->sys_name) == 0) {
			unsigned char d = ext_at_table[i].dirfd_arg[
				tcp->ext_npaths < EXT_MAX_PATHS_PER_SYSCALL
				? tcp->ext_npaths : 0];

			/* 0xff = this path has no dirfd (cwd-relative,
			 * e.g. symlinkat's oldpath): keep AT_FDCWD. */
			if (d != 0xff)
				dirfd = (int) tcp->u_arg[d];
			break;
		}

	if (dirfd == AT_FDCWD) {
		char link[64];
		int r;

		snprintf(link, sizeof(link), "/proc/%d/cwd", tcp->pid);
		r = readlink(link, base, sizeof(base) - 1);
		if (r < 0)
			return false;
		base[r] = '\0';
	} else {
		if (getfdpath(tcp, dirfd, base, sizeof(base)) < 0)
			return false;
	}

	/* Only prefix directory-looking results. */
	if (base[0] != '/')
		return false;

	int pr = snprintf(out, outsz, "%s/%s", base, path);

	return pr > 0 && (size_t) pr < outsz;
}

void
ext_note_path(struct tcb *tcp, const char *path)
{
	if (tcp->ext_npaths >= EXT_MAX_PATHS_PER_SYSCALL)
		return;

	char resolved[PATH_MAX];
	const char *store = path;

	if (ext_resolve_path(tcp, path, resolved, sizeof(resolved)))
		store = resolved;

	tcp->ext_paths[tcp->ext_npaths++] = xstrdup(store);
}

void
ext_reset_notes(struct tcb *tcp)
{
	for (unsigned int i = 0; i < tcp->ext_nnotes && i < EXT_MAX_NOTES_PER_SYSCALL; ++i) {
		free(tcp->ext_notes[i]);
		tcp->ext_notes[i] = NULL;
	}
	tcp->ext_nnotes = 0;
}

void
ext_add_note(struct tcb *tcp, const char *note)
{
	if (tcp->ext_nnotes >= EXT_MAX_NOTES_PER_SYSCALL)
		return;
	tcp->ext_notes[tcp->ext_nnotes++] = xstrdup(note);
}

const char *
ext_notes_joined(struct tcb *tcp, char sep)
{
	static char buf[256];
	size_t off = 0;

	buf[0] = '\0';
	for (unsigned int i = 0; i < tcp->ext_nnotes; ++i) {
		if (i) {
			if (off + 1 >= sizeof(buf))
				break;
			buf[off++] = sep;
			buf[off] = '\0';
		}
		size_t l = strlen(tcp->ext_notes[i]);
		if (off + l >= sizeof(buf))
			l = sizeof(buf) - 1 - off;
		memcpy(buf + off, tcp->ext_notes[i], l);
		off += l;
		buf[off] = '\0';
	}
	return buf;
}

/* Free everything a tcb holds for the extensions; called from droptcb(). */
void
ext_free_tcb(struct tcb *tcp)
{
	ext_reset_paths(tcp);
	ext_reset_notes(tcp);
}
