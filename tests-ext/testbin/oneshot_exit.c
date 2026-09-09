/*
 * oneshot_exit.c -- a target whose every exit attempt is the same:
 * exit_group(7) -- once directly, once by returning from main.  Under
 * --keep-alive both are suppressed and the process falls off its exit
 * path (glibc ends _exit in hlt) and faults; the tracer must then
 * report the suppressed exit_group's status (7), not the fault signal,
 * so the run stays exit-status-clean.
 *
 * Build: cc -O2 -o oneshot_exit oneshot_exit.c
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main(void)
{
	printf("[oneshot] first exit_group(7)\n");
	fflush(stdout);
	syscall(SYS_exit_group, 7);

	/* reachable only under --keep-alive */
	printf("[oneshot] still alive after suppressed exit\n");
	fflush(stdout);
	return 7;			/* glibc: exit_group(7) again */
}
