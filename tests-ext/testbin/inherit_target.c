/*
 * inherit_target.c -- exercises exec-time fd inheritance: the parent
 * opens handed.txt (no CLOEXEC), forks; the child inherits the fd and
 * execs /bin/true.  A --report-files run must record handed.txt in the
 * report with an `inherit` operation on the exec, even though no
 * traced process ever *opened* it at exec time.
 *
 * Build: cc -O2 -o inherit_target inherit_target.c
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(void)
{
	int fd = open("handed.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);

	if (fd < 0) {
		perror("open handed.txt");
		return 1;
	}
	write(fd, "handoff\n", 8);

	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		/* the fd crosses fork AND exec */
		execl("/bin/true", "true", (char *) 0);
		_exit(127);
	}
	waitpid(pid, NULL, 0);
	close(fd);
	printf("[inherit] done\n");
	return 0;
}
