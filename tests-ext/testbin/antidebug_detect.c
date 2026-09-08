/* antidebug_detect.c -- minimal anti-debug target for A/B runs.
 *
 * Exits 42 when it detects a debugger (TRACEME fails or TracerPid != 0),
 * exits 0 when it believes it is untraced.
 *
 *   vanilla strace  ./antidebug_detect   -> exits 42
 *   ours --anti-anti-debug               -> exits 0
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int
main(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		puts("[detect] TRACEME failed: debugger!");
		return 42;
	}

	char buf[8192];
	int fd = open("/proc/self/status", O_RDONLY);
	int n = read(fd, buf, sizeof(buf) - 1);

	close(fd);
	if (n <= 0)
		return 42;
	buf[n] = '\0';

	char *p = strstr(buf, "TracerPid:");

	if (!p || atoi(p + strlen("TracerPid:")) != 0) {
		puts("[detect] TracerPid nonzero: debugger!");
		return 42;
	}

	puts("[detect] clean");
	return 0;
}
