/*
 * anti_debug.c -- countermeasures against tracee self-checks (--anti-anti-debug).
 *
 * Mechanisms living here, each selectable through
 * --anti-anti-debug[=feat[:off]{,feat[:off]}]:
 *
 *  1. AD_TRACEME: ptrace(PTRACE_TRACEME) self-checks.  A tracee already
 *     being traced cannot TRACEME again, gets EPERM, and many programs
 *     treat that as proof of a debugger and quit.  The retval rewrite
 *     itself happens in the tamper hooks (it needs set_success()); this
 *     file only contributes the note bookkeeping.
 *
 *  2. AD_STATUS: after a successful read of a /proc/<pid>/status file,
 *     the bytes "TracerPid:<tab><pid>" in the tracee's buffer are
 *     rewritten digit-for-digit to zeroes, so the line still parses as
 *     an integer (0 = "not traced") and every following byte keeps its
 *     offset.
 *
 *  3. AD_WCHAN: after a successful read of a /proc/<pid>/wchan file,
 *     the value in the tracee's buffer ("ptrace_stop" while stopped in
 *     the tracer) is rewritten digit-for-digit to zeroes, same
 *     length-preserving scheme.
 *
 * readv/preadv/preadv2 are rewritten iovec by iovec, with a carried
 * window so a needle split across two iovecs is still caught; compat
 * (32-bit tracee) iovec layouts are not rewritten.
 *
 * Known limits (documented in the man page): timing-based checks
 * (rdtsc around syscalls) and ptrace(PTRACE_ATTACH) self-checks
 * (spoofing ATTACH would make the caller block in wait() forever) are
 * not covered.  In the seccomp backend TracerPid is genuinely 0, so no
 * rewrite is needed there.
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "sen.h"
#include "tracing_ext.h"

#include <limits.h>

#define AD_WINDOW 8192

/* ^/proc/(self|thread-self|\d+)(/task/\d+)?/SUFFIX$ */
static bool
path_has_proc_suffix(const char *path, const char *suffix, size_t suffixlen)
{
	const size_t plen = strlen(path);

	if (plen <= suffixlen)
		return false;
	if (strcmp(path + plen - suffixlen, suffix) != 0)
		return false;

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

	return strcmp(rest, suffix) == 0;
}

static bool
path_is_proc_status(const char *path)
{
	static const char status_suffix[] = "/status";

	return path_has_proc_suffix(path, status_suffix,
				    sizeof(status_suffix) - 1);
}

static bool
path_is_proc_wchan(const char *path)
{
	static const char wchan_suffix[] = "/wchan";

	return path_has_proc_suffix(path, wchan_suffix,
				    sizeof(wchan_suffix) - 1);
}

/*
 * Overwrite the value with '0' characters directly in the tracee's
 * address space, preserving length and offsets.  needle != NULL: the
 * digit run following the needle ("TracerPid:" -> TracerPid value);
 * needle == NULL: the whole value up to the newline (wchan's symbol
 * name contains no digits, so it is zeroed in full).  Called at the
 * syscall-exit stop of a read-family syscall, before the tracee
 * resumes and parses the buffer.
 */
static void
rewrite_zeros(struct tcb *tcp, kernel_ulong_t buf, size_t len,
	      const char *needle, const char *note)
{
	char local[AD_WINDOW];

	if (len == 0)
		return;
	if (len > sizeof(local))
		len = sizeof(local);
	if (umoven(tcp, buf, len, local) < 0)
		return;

	const char *p = local;
	bool digits_only = needle != NULL;

	if (needle) {
		p = memmem(local, len, needle, strlen(needle));
		if (!p)
			return;
		p += strlen(needle);

		/* Skip whitespace between the colon and the value. */
		while (p < local + len && (*p == ' ' || *p == '\t'))
			++p;
	}

	kernel_ulong_t start = buf + (p - local);
	size_t n = 0;
	char zeros[32];

	while (p < local + len && n < sizeof(zeros)) {
		if (digits_only) {
			if (*p < '0' || *p > '9')
				break;
		} else {
			if (*p == '\n' || *p == '\0')
				break;
		}
		zeros[n++] = '0';
		++p;
	}
	if (n == 0)
		return;		/* value already 0 or unparsable */

	if (upoken(tcp, start, n, zeros) != n) {
		error_msg("anti-anti-debug: failed to rewrite %s "
			  "in pid %d's buffer", note, tcp->pid);
		return;
	}

	char note_buf[64];

	snprintf(note_buf, sizeof(note_buf), "anti-debug: %s rewritten to 0",
		 note);
	ext_add_note(tcp, note_buf);
}

/* Native iovec layout only; compat (32-bit) tracees are skipped. */
struct native_iovec {
	kernel_ulong_t base;
	kernel_ulong_t len;
};

/* Fetch up to max entries of the tracee's iovec array; false on error. */
static bool
fetch_iovec(struct tcb *tcp, kernel_ulong_t iov_addr, unsigned long iovcnt,
	    struct native_iovec *iov, unsigned int max)
{
	if (iov_addr == 0 || iovcnt == 0)
		return false;
	if (iovcnt > max)
		iovcnt = max;
	return umoven(tcp, iov_addr, iovcnt * sizeof(*iov), iov) == 0;
}

/*
 * Check whether needle ends in the previous iov's tail (head, head_len)
 * and its digit run continues into this iov's first bytes; if so,
 * overwrite the digits there.
 */
static void
rewrite_seam(struct tcb *tcp, const char *head, size_t head_len,
	     kernel_ulong_t next_addr, size_t next_len,
	     const char *needle, const char *note)
{
	const size_t nlen = strlen(needle);
	char tail[64];

	if (head_len < nlen - 1 || next_len == 0 || next_len > sizeof(tail))
		return;

	/* Number of needle bytes that could live in head. */
	const size_t overlap = nlen - 1 < head_len ? nlen - 1 : head_len;

	if (umoven(tcp, next_addr, next_len, tail) < 0)
		return;

	char joined[128];

	if (overlap + next_len > sizeof(joined))
		return;
	memcpy(joined, head + head_len - overlap, overlap);
	memcpy(joined + overlap, tail, next_len);

	const char *hit = memmem(joined, overlap + next_len, needle, nlen);

	if (!hit)
		return;

	/* Zero the digits of the run that fall inside the next iov. */
	size_t digit_off = (size_t) (hit - joined) + nlen;
	size_t next_off = digit_off < overlap ? 0 : digit_off - overlap;

	if (digit_off < overlap)
		return;		/* digits are all in head: nothing to do */

	size_t n = 0;

	while (next_off + n < next_len && n < sizeof(tail)
	       && tail[next_off + n] >= '0' && tail[next_off + n] <= '9')
		++n;
	if (n == 0)
		return;

	char zeros[64];

	memset(zeros, '0', n);
	if (upoken(tcp, next_addr + next_off, n, zeros) != n)
		error_msg("anti-anti-debug: failed to rewrite %s seam "
			  "in pid %d's buffer", note, tcp->pid);
}

/*
 * Walk the iovec array of a successful readv/preadv*, distributing
 * rval across the iov lengths, and rewrite each iov that contains
 * (part of) the needle.
 */
static void
rewrite_iovec(struct tcb *tcp, kernel_ulong_t iov_addr, unsigned long iovcnt,
	      size_t rval, const char *needle, const char *note)
{
	struct native_iovec iov[16];
	char carry[64];		/* tail of the previous iov, for matches
				 * crossing the boundary */
	size_t carry_len = 0;

	if (!fetch_iovec(tcp, iov_addr, iovcnt, iov, ARRAY_SIZE(iov)))
		return;

	for (unsigned int i = 0; i < ARRAY_SIZE(iov) && rval; ++i) {
		if (iov[i].base == 0 || iov[i].len == 0)
			continue;
		size_t chunk = iov[i].len < rval ? (size_t) iov[i].len : rval;

		chunk = chunk < rval ? chunk : rval;
		rval -= chunk;

		if (carry_len && needle)
			rewrite_seam(tcp, carry, carry_len, iov[i].base,
				     chunk, needle, note);

		rewrite_zeros(tcp, iov[i].base, chunk, needle, note);

		/* Remember this iov's tail for the next seam. */
		size_t keep = sizeof(carry);

		if (keep > chunk)
			keep = chunk;
		if (umoven(tcp, iov[i].base + chunk - keep, keep, carry) == 0)
			carry_len = keep;
		else
			carry_len = 0;
	}
}

/* Called from ext_syscall_exiting_tamper() at the syscall-exit stop. */
void
anti_debug_syscall_exiting(struct tcb *tcp)
{
	if (!ext.anti_debug || syserror(tcp) || tcp->u_rval <= 0)
		return;

	char fdpath[PATH_MAX + 1];
	const char *needle;
	const char *note;

	if (getfdpath(tcp, (int) tcp->u_arg[0], fdpath, sizeof(fdpath)) < 0)
		return;

	if (path_is_proc_status(fdpath)) {
		if (!(ext.anti_debug_features & AD_STATUS))
			return;
		needle = "TracerPid:";
		note = "TracerPid";
	} else if (path_is_proc_wchan(fdpath)) {
		if (!(ext.anti_debug_features & AD_WCHAN))
			return;
		needle = NULL;
		note = "wchan";
	} else {
		return;
	}

	switch (tcp_sysent(tcp)->sen) {
		case SEN_read:
		case SEN_pread:		/* also pread64 (same sen flavor) */
			/* fd, buf, ... */
			rewrite_zeros(tcp, tcp->u_arg[1], tcp->u_rval,
				      needle, note);
			break;
		case SEN_readv:
		case SEN_preadv:
		case SEN_preadv2:
			/* fd, iov, iovcnt, ... */
			rewrite_iovec(tcp, tcp->u_arg[1],
				      (unsigned long) tcp->u_arg[2],
				      tcp->u_rval, needle, note);
			break;
		default:
			break;
	}
}
