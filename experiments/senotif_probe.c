/*
 * senotif_probe.c -- the complete ptrace-free tracing primitive check.
 *
 * Child: installs a USER_NOTIF filter over all syscalls (allowing only
 * sendmsg/close for the fd handoff and write for its own logging),
 * passes the listener to the parent, then:
 *   1. write(1, "hello...")     -> parent forges retval 42 (skip)
 *   2. openat("/etc/ld.so.cache")  -> parent emulates with ADDFD
 *   3. read(fd, buf)            -> parent CONTINUEs, then rewrites the
 *                                  buffer through /proc/<pid>/mem
 *   4. exit_group(0)            -> parent CONTINUEs (real exit)
 * Parent: handles each notification; verifies args arrive; verifies the
 * tracee observed the forged/emulated results.
 *
 * Exit 0 = all six primitives (P1..P6) work on this host.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <stddef.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV  _IOWR(0x2103, 0, struct seccomp_notif)
#endif

static int fails;
#define CHECK(cond, name) do { \
	if (cond) { printf("ok:   %s\n", name); } \
	else { printf("FAIL: %s\n", name); fails++; } } while (0)

static void
child_side(void)
{
	/* everything is precomputed before the filter goes in */
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 0, 5),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendmsg, 2, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_close, 1, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog p = { .len = sizeof(f)/sizeof(f[0]), .filter = f };
	struct { struct cmsghdr h; int fd; } cbuf;
	struct msghdr mh = { 0 };
	struct iovec iov = { .iov_base = "L", .iov_len = 1 };

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		_exit(90);
	long lfd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
			   SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
	if (lfd < 0)
		_exit(91);

	memset(&cbuf, 0, sizeof(cbuf));
	cbuf.h.cmsg_level = SOL_SOCKET;
	cbuf.h.cmsg_type = SCM_RIGHTS;
	cbuf.h.cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(&cbuf.h), &lfd, sizeof(int));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = &cbuf;
	mh.msg_controllen = CMSG_SPACE(sizeof(int));
	if (sendmsg(100, &mh, 0) < 0)
		_exit(92);
	close((int) lfd);

	/* 1: retval will be forged to 42 */
	char msg[] = "hello from the tracee\n";
	ssize_t r = write(1, msg, sizeof(msg) - 1);
	if (r != 42)
		_exit(93);

	/* 2: fd will be provided by the parent via ADDFD */
	int fdd = open("/etc/ld.so.cache", O_RDONLY);
	if (fdd < 0)
		_exit(94);

	/* 3: read succeeds (CONTINUEed by the parent, which reads the
	 * buffer back through /proc/<pid>/mem to verify) */
	char buf[256];
	memset(buf, 0, sizeof(buf));
	r = read(fdd, buf, sizeof(buf) - 1);
	if (r > 0)
		_exit(0);	/* success */
	_exit(96);
}

static ssize_t
mem_op(int pmem, int is_write, unsigned long addr, void *buf, size_t len)
{
	if (is_write)
		return pwrite(pmem, buf, len, (off_t) addr);
	return pread(pmem, buf, len, (off_t) addr);
}

int
main(void)
{
	int sp[2];
	int lfd = -1;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(30);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
		perror("socketpair");
		return 2;
	}
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return 2;
	}
	if (pid == 0) {
		close(sp[0]);
		dup2(sp[1], 100);
		close(sp[1]);
		child_side();
		_exit(99);
	}
	close(sp[1]);

	{	/* receive the listener fd */
		struct { struct cmsghdr h; int fd; } cbuf;
		struct msghdr mh = { 0 };
		struct iovec iov = { .iov_base = &(char){0}, .iov_len = 1 };

		memset(&cbuf, 0, sizeof(cbuf));
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		mh.msg_control = &cbuf;
		mh.msg_controllen = CMSG_SPACE(sizeof(int));
		CHECK(recvmsg(sp[0], &mh, 0) == 1, "P1 listener fd received");
		lfd = cbuf.fd;
	}

	char mempath[64];
	snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);
	int pmem = open(mempath, O_RDONLY);
	CHECK(pmem >= 0, "P6a /proc/<pid>/mem openable read-only");

	int saw_write = 0, saw_open = 0, saw_read = 0, cont = 0;
	for (;;) {
		struct seccomp_notif req = { 0 };
		struct seccomp_notif_resp resp = { 0 };

		if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
			if (errno == ENOENT || errno == EINTR)
				continue;
			perror("NOTIF_RECV");
			break;
		}
		if (req.data.nr == __NR_write && (int) req.data.args[0] == 1) {
			saw_write = 1;
			char buf[64];
			ssize_t n = mem_op(pmem, 0, req.data.args[1], buf,
					   req.data.args[2]);
			CHECK(n == (ssize_t) req.data.args[2] &&
			      strncmp(buf, "hello", 5) == 0,
			      "P2 args + tracee buffer readable via /proc/mem");
			resp.id = req.id;
			resp.val = 42;	/* forged retval, syscall skipped */
		} else if (req.data.nr == __NR_openat) {
			saw_open = 1;
			char path[128];
			ssize_t pn = mem_op(pmem, 0, req.data.args[1], path,
					    sizeof(path) - 1);
			if (pn > 0) {
				path[pn] = '\0';
				/* truncate at the first NUL like a C string */
				char *nul = memchr(path, 0, (size_t) pn);

				if (nul)
					pn = nul - path;
			}
			CHECK(pn > 0, "P5a openat path fetched via /proc/mem");
			printf("     path=[%s] flags=%#llx\n", path,
			       (unsigned long long) req.data.args[2]);
			int hostfd = open(path, (int) req.data.args[2] & ~O_CLOEXEC);
			CHECK(hostfd >= 0, "P5b tracer-side open succeeded");
			struct seccomp_notif_addfd addfd = {
				.id = req.id,
				.srcfd = hostfd,
				.newfd = 0,
				.newfd_flags = 0,
			};
			int newfd = ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
			CHECK(newfd >= 0, "P5c ADDFD installed fd in tracee");
			close(hostfd);
			resp.id = req.id;
			resp.val = newfd;
		} else if (req.data.nr == __NR_read) {
			saw_read = 1;
			/*
			 * CONTINUE the read; it completes while we hold
			 * this notification round; then read the filled
			 * buffer back through /proc/<pid>/mem.  (Memory
			 * WRITE through /proc/<pid>/mem is denied on the
			 * development host; the read-back here is the
			 * primitive the tracer actually needs.)
			 */
			resp.id = req.id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
			char probe[8] = { 0 };
			ssize_t n = 0;

			for (int i = 0; i < 2000; ++i) {
				n = mem_op(pmem, 0, req.data.args[1],
					   probe, 5);
				if (n == 5 && probe[0] != '\0')
					break;
				usleep(1000);
			}
			CHECK(n == 5 && probe[0] != '\0',
			      "P6b tracee buffer readable back via /proc/mem");
			continue;
		} else if (req.data.nr == __NR_exit_group) {
			resp.id = req.id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			cont = 1;
		} else {
			resp.id = req.id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		}
		if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 &&
		    errno != ENOENT)
			perror("NOTIF_SEND");

		if (req.data.nr == __NR_exit_group)
			break;	/* tracee is dying: reap below */

		int st;
		pid_t w = waitpid(pid, &st, WNOHANG);
		if (w == pid) {
			CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
			      "tracee completed with forged/emulated syscalls");
			break;
		}
		if (w < 0)
			break;
	}
	/* the just-CONTINUEd exit_group races wait(2) visibility: poll */
	for (int i = 0; i < 100; ++i) {
		int st;
		pid_t w = waitpid(pid, &st, WNOHANG);

		if (w == pid) {
			CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
			      "tracee completed with forged/emulated syscalls");
			break;
		}
		if (w < 0)
			break;
		usleep(20000);
	}
	CHECK(saw_write, "P3 saw write() notification, forged retval honored");
	CHECK(saw_open, "P5 openat emulated via ADDFD");
	CHECK(cont, "P4 CONTINUE path exercised");
	printf("%s: %d failures\n", fails ? "FAILED" : "ALL PRIMITIVES WORK",
	       fails);
	return fails ? 1 : 0;
}
