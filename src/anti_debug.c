/*
 * anti_debug.c -- countermeasures against tracee self-checks (--anti-anti-debug).
 *
 * Two mechanisms live here:
 *
 *  1. ptrace(PTRACE_TRACEME) self-checks: a tracee already being traced
 *     cannot TRACEME again, gets EPERM, and many programs treat that as
 *     proof of a debugger and quit.  The retval rewrite itself happens in
 *     syscall.c (it needs the static set_success() helper); this file
 *     provides the note bookkeeping.
 *
 *  2. /proc/<pid>/status TracerPid checks: after a successful read of a
 *     /proc/<pid>/status file, the bytes "TracerPid:<tab><pid>" in the
 *     tracee's buffer are rewritten digit-for-digit to zeroes, so the
 *     line still parses as an integer (0 = "not traced") and every
 *     following byte keeps its offset.
 *
 * Known limits (documented in strace-appimage.1): timing-based checks
 * (rdtsc around syscalls), /proc/<pid>/wchan ("ptrace_stop"), and
 * ptrace(PTRACE_ATTACH) self-checks (spoofing ATTACH would make the
 * caller block in wait() forever) are not covered.
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "sen.h"
#include "tracing_ext.h"

#include <limits.h>

#define TRACERPID_WINDOW 8192

static bool
path_is_proc_status(const char *path)
{
	static const char status_suffix[] = "/status";
	const size_t plen = strlen(path);

	if (plen <= sizeof(status_suffix) - 1)
		return false;
	if (strcmp(path + plen - (sizeof(status_suffix) - 1),
		   status_suffix) != 0)
		return false;

	/* ^/proc/(self|thread-self|\d+)(/task/\d+)?/status$ */
	if (strncmp(path, "/proc/", 6) != 0)
		return false;
	const char *rest = path + 6;

	if (strncmp(rest, "self", 4) == 0)
		rest += 4;
	else if (strncmp(rest, "thread-self", 11) == 0)
		rest += 11;
	else
		while (*rest >= '0' && *rest <= '9')
			++rest;

	if (strncmp(rest, "/task/", 6) == 0) {
		rest += 6;
		while (*rest >= '0' && *rest <= '9')
			++rest;
	}

	return strcmp(rest, "/status") == 0;
}

/*
 * Overwrite the digits after "TracerPid:\t" with '0' characters directly
 * in the tracee's address space.  Called at the syscall-exit stop of a
 * read-family syscall, before the tracee resumes and parses the buffer.
 */
static void
rewrite_tracerpid(struct tcb *tcp, kernel_ulong_t buf, size_t len)
{
	char local[TRACERPID_WINDOW];
	static const char needle[] = "TracerPid:";

	if (len == 0)
		return;
	if (len > sizeof(local))
		len = sizeof(local);
	if (umoven(tcp, buf, len, local) < 0)
		return;

	char *p = memmem(local, len, needle, sizeof(needle) - 1);
	if (!p)
		return;
	p += sizeof(needle) - 1;

	/* Skip whitespace between the colon and the value. */
	while (p < local + len && (*p == ' ' || *p == '\t'))
		++p;

	/* Rewrite every digit of the value to '0' (same length, so the
	 * rest of the buffer keeps its offsets). */
	kernel_ulong_t start = buf + (p - local);
	size_t n = 0;
	char zeros[32];

	while (p < local + len && *p >= '0' && *p <= '9' && n < sizeof(zeros)) {
		zeros[n++] = '0';
		++p;
	}
	if (n == 0)
		return;		/* value already 0 or unparsable */

	if (upoken(tcp, start, n, zeros) != n) {
		error_msg("anti-anti-debug: failed to rewrite TracerPid "
			  "in pid %d's status buffer", tcp->pid);
		return;
	}

	ext_add_note(tcp, "anti-debug: TracerPid rewritten to 0");
}

/* Called from ext_tamper_exiting() at the syscall-exit stop. */
void
anti_debug_syscall_exiting(struct tcb *tcp)
{
	if (!ext.anti_debug || syserror(tcp) || tcp->u_rval <= 0)
		return;

	kernel_ulong_t buf;
	size_t len;

	switch (tcp_sysent(tcp)->sen) {
		case SEN_read:
		case SEN_pread:
			buf = tcp->u_arg[1];
			len = tcp->u_rval;
			break;
		case SEN_readv: {
			/*
			 * Native-personality iovec layout only; compat
			 * (32-bit tracee) layouts are not rewritten.
			 */
			struct { kernel_ulong_t base; kernel_ulong_t len; } iov;

			if (umoven(tcp, tcp->u_arg[1], sizeof(iov), &iov) < 0)
				return;
			buf = iov.base;
			len = MIN((kernel_ulong_t) tcp->u_rval, iov.len);
			break;
		}
		default:
			return;
	}

	if (buf == 0 || len > UINT_MAX)
		return;

	char fdpath[PATH_MAX + 1];

	if (getfdpath(tcp, (int) tcp->u_arg[0], fdpath, sizeof(fdpath)) < 0)
		return;
	if (!path_is_proc_status(fdpath))
		return;

	rewrite_tracerpid(tcp, buf, len);
}
