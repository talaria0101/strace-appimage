/*
 * wchan_target.c -- exercises the /proc/<pid>/wchan rewrite: the
 * parent blocks in a syscall so the kernel would report ptrace_stop
 * for it while it sits in the tracer's stops; the child reads the
 * parent's wchan and reports what it saw.  Under a tracer without
 * --anti-anti-debug the child reads "ptrace_stop" (proof of a tracer
 * for real anti-debug code); with --anti-anti-debug the child's read
 * buffer has the value zeroed, same length, and it reads "clean".
 *
 * This check is only meaningful under a ptrace-based tracer: in the
 * seccomp backend the tracee never sits in a ptrace stop.
 *
 * Build: cc -O2 -o wchan_target wchan_target.c
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int
main(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		/* child: read the parent's wchan while it is stopped */
		char path[64];
		char buf[128];

		usleep(200000);	/* let the parent reach its stop */
		snprintf(path, sizeof(path), "/proc/%d/wchan", getppid());
		int fd = open(path, O_RDONLY);

		if (fd < 0) {
			perror("open wchan");
			_exit(1);
		}
		ssize_t n = read(fd, buf, sizeof(buf) - 1);

		close(fd);
		if (n <= 0)
			_exit(1);
		buf[n] = '\0';
		if (n > 0 && buf[n - 1] == '\n')
			buf[n - 1] = '\0';
		printf("[wchan] parent wchan: %s\n", buf);
		_exit(strstr(buf, "ptrace_stop") ? 42 : 0);
	}

	/* parent: park in a syscall so the tracer stops it */
	struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };

	nanosleep(&ts, NULL);
	waitpid(pid, NULL, 0);
	return 0;
}
