/*
 * relpath_target.c -- exercises relative-path capture: the report must
 * contain resolved absolute paths for
 *   1. a plain relative open after chdir (cwd resolution),
 *   2. an openat through a dirfd (fd resolution),
 *   3. an openat with AT_FDCWD and a relative path.
 * Exits 0 on success (the opens worked), nonzero otherwise.
 *
 * Build: cc -O2 -o relpath_target relpath_target.c
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
	char cwd[4096];

	if (!getcwd(cwd, sizeof(cwd))) {
		perror("getcwd");
		return 1;
	}

	/* 1. relative open, cwd-relative */
	int fd = open("data.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);

	if (fd < 0) {
		perror("open data.txt");
		return 1;
	}
	close(fd);

	/* 2. openat through a real dirfd (the directory itself) */
	int dfd = open(".", O_RDONLY | O_DIRECTORY);

	if (dfd < 0) {
		perror("open .");
		return 1;
	}
	fd = openat(dfd, "data2.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);

	if (fd < 0) {
		perror("openat data2.txt");
		return 1;
	}
	close(fd);

	/* 3. openat with AT_FDCWD, relative path */
	fd = openat(AT_FDCWD, "data3.txt", O_CREAT | O_WRONLY | O_TRUNC,
		    0644);

	if (fd < 0) {
		perror("openat AT_FDCWD data3.txt");
		return 1;
	}
	close(fd);
	close(dfd);

	printf("[relpath] done in %s\n", cwd);
	return 0;
}
