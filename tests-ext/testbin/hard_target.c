/*
 * hard_target.c -- a deliberately hostile tracing target that exercises
 * every strace-appimage extension in one run.
 *
 * Behaviour, in order:
 *
 *  1. anti-debug check #1: ptrace(PTRACE_TRACEME) self-test.
 *     Under vanilla strace this returns EPERM (we are already traced)
 *     and a real anti-debug target would quit here.
 *  2. anti-debug check #2: read /proc/self/status with read(2) and
 *     parse TracerPid.  Under vanilla strace TracerPid is the tracer's
 *     pid (nonzero) and the target would quit here.
 *  3. display probe: connect(2) to /tmp/.X11-unix/X0.  Headless hosts
 *     fail with ENOENT, and GUI applications typically exit(3) right
 *     after; this target calls exit_group(2) directly so that
 *     --keep-alive can demonstrate what a suppressed exit reveals.
 *  4. fallback path (only reachable if the exit was suppressed):
 *     dlopen the software-rendering stack and open font/config paths
 *     that a packager would need to bundle.
 *  5. exec a child to exercise -f, and read /proc/self/status again
 *     (pread this time) to exercise both rewrite paths.
 *
 * Build: cc -O2 -o hard_target hard_target.c -ldl
 * Static: cc -static -O2 -o hard_target_static hard_target.c -ldl
 *   (static glibc dlopen needs the static libdl; falls back to a no-op)
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int detected;

static void
check_traceme(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		printf("[target] TRACEME self-check: EPERM -> debugger!"
		       " (vanilla strace stops here; --anti-anti-debug"
		       " spoofs success)\n");
		detected = 1;
	} else {
		printf("[target] TRACEME self-check: clean\n");
	}
}

static int
read_tracerpid_pread(void)
{
	char buf[8192];
	int fd = open("/proc/self/status", O_RDONLY);
	int n;

	if (fd < 0)
		return -1;
	n = pread(fd, buf, sizeof(buf) - 1, 0);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	{
		char *p = strstr(buf, "TracerPid:");

		if (!p)
			return -1;
		return atoi(p + strlen("TracerPid:"));
	}
}

static void
check_tracerpid(void)
{
	int tp = read_tracerpid_pread();

	if (tp < 0) {
		printf("[target] TracerPid check: unreadable\n");
	} else if (tp != 0) {
		printf("[target] TracerPid check: %d -> debugger!"
		       " (vanilla strace shows the real tracer;"
		       " --anti-anti-debug rewrites it to 0)\n", tp);
		detected = 1;
	} else {
		printf("[target] TracerPid check: clean (0)\n");
	}
}

static int
have_display(void)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return 0;
	strcpy(sa.sun_path, "/tmp/.X11-unix/X0");
	if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0) {
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

static void
fallback_path(void)
{
	/* What a packager needs to see from the fallback branch. */
	void *h = dlopen("libGL.so.1", RTLD_LAZY | RTLD_LOCAL);

	printf("[target] fallback: dlopen libGL.so.1 -> %s\n",
	       h ? "loaded" : dlerror() ?: "failed");
	if (h)
		dlclose(h);

	h = dlopen("libX11.so.6", RTLD_LAZY | RTLD_LOCAL);
	printf("[target] fallback: dlopen libX11.so.6 -> %s\n",
	       h ? "loaded" : dlerror() ?: "failed");
	if (h)
		dlclose(h);

	int fd = open("/usr/share/fonts/truetype/dejavu/"
		      "DejaVuSans.ttf", O_RDONLY);
	printf("[target] fallback: open DejaVuSans.ttf -> %s\n",
	       fd >= 0 ? "ok" : strerror(errno));
	if (fd >= 0)
		close(fd);
}

int
main(void)
{
	check_traceme();
	check_tracerpid();

	if (!have_display()) {
		printf("[target] no display; real apps exit() here;"
		       " exit_group(1) now (--keep-alive suppresses it)\n");
		fflush(stdout);
		syscall(SYS_exit_group, 1);
		/*
		 * Reached only when the tracer suppressed the exit.
		 */
		fallback_path();
	}

	{
		pid_t pid = fork();

		if (pid == 0)
			_exit(execl("/bin/true", "true", (char *) 0));
		if (pid > 0)
			waitpid(pid, NULL, 0);
	}

	check_tracerpid();
	printf("[target] done%s\n", detected ? " (anti-debug FIRED)" : "");
	return detected ? 42 : 0;
}
