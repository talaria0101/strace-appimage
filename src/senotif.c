/*
 * senotif.c -- a ptrace-free tracing backend built on seccomp
 * user notification (SECCOMP_FILTER_FLAG_NEW_LISTENER) and
 * /proc/<pid>/mem.
 *
 * Why: on hosts where the ptrace syscall class is denied outright
 * (sandboxed CI, hardened environments: the ptrace syscall,
  * process_vm_readv/writev and friends all answer EPERM), "if you can
 * trace it" still holds -- a program can always seccomp *itself*.
 * The tracee installs a user-notify filter over every syscall before
 * exec and hands the listener fd to the tracer over a unix socket;
 * from then on every syscall of the tracee (and of anything it forks
 * or execs, since filters are inherited) is reported to the tracer as
 * a notification carrying the syscall number and the six arguments.
 *
 * What this backend does with each notification:
 *   - decodes and prints it through strace's regular decoders
 *     (memory arguments are fetched through /proc/<pid>/mem, which the
 *     tracee makes available by being blocked in the notification --
 *     stable memory, no TOCTOU window);
 *   - CONTINUEs the syscall (it executes normally), or
 *   - emulates it entirely in the tracer when the result matters:
 *       open/openat      -> tracer-side open + SECCOMP_IOCTL_NOTIF_ADDFD
 *                           installs the fd into the tracee, so open
 *                           results (including ENOENT -- the missing
 *                           libraries a packager cares about) are real;
 *       access/faccessat -> tracer-side check, error passed through;
 *       ptrace(TRACEME)  -> answered with success (anti-anti-debug);
 *       exit_group       -> answered with success up to N times
 *                           (--keep-alive).
 *
 * Limits (documented in doc/strace.1.in): no signal events, no exit
 * event for signals (the exit code comes from wait(2)), CONTINUEd
 * syscalls show ret=null in --json (the kernel does not report their
 * completion), and attaching to an already-running process (-p) is
 * impossible without ptrace.
 *
 * Copyright (c) 2026 The strace-appimage authors.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "number_set.h"
#include "native_defs.h"
#include "print_fields.h"
#include "tracing_ext.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
# define SECCOMP_IOCTL_NOTIF_RECV \
	_IOWR(0x2103, 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
# define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1U << 2)
#endif

/*
 * The backend decodes with the native syscall table, so the filter
 * pins the native audit arch.  Add a case here (plus verifying the
 * notification probe below) to extend backend support.
 */
#if defined(__x86_64__)
# define SENOTIF_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define SENOTIF_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

/* fds below HANDOFF_FD are never used for the handoff socket */
#define HANDOFF_FD 100

extern char **environ;

/* per-tracee state; deliberately decoupled from strace's tcb table */
struct st_tcb {
	struct tcb tcp;		/* reused for decoding (fields only) */
	bool in_use;
	bool fd_scan_pending;	/* exec CONTINUEd: scan the inherited fds
				 * on this tracee's next notification */
};

static struct st_tcb st_tcbs[64];
static int listener_fd = -1;

static struct st_tcb *
st_tcb_for(pid_t pid)
{
	for (size_t i = 0; i < ARRAY_SIZE(st_tcbs); ++i) {
		if (st_tcbs[i].in_use && st_tcbs[i].tcp.pid == pid)
			return &st_tcbs[i];
	}
	for (size_t i = 0; i < ARRAY_SIZE(st_tcbs); ++i) {
		if (!st_tcbs[i].in_use) {
			memset(&st_tcbs[i], 0, sizeof(st_tcbs[i]));
			st_tcbs[i].in_use = true;
			st_tcbs[i].tcp.pid = pid;
			st_tcbs[i].tcp.outf = shared_log;
			st_tcbs[i].tcp.qual_flg = DEFAULT_QUAL_FLAGS;
			st_tcbs[i].tcp.pmem_fd = -1;
			st_tcbs[i].tcp.keepalive_left = ext.keep_alive;
			return &st_tcbs[i];
		}
	}
	return NULL;		/* too many tracees for the PoC pool */
}

static void
st_tcb_release(struct st_tcb *st)
{
	if (!st)
		return;
	ext_reset_paths(&st->tcp);
	ext_reset_notes(&st->tcp);
	if (st->tcp.pmem_fd >= 0)
		close(st->tcp.pmem_fd);
	st->in_use = false;
	st->fd_scan_pending = false;
}

/*
 * The child side: install the filter, hand the listener to the parent,
 * exec.  Everything is precomputed before the filter goes in -- after
 * it, only sendmsg and close are permitted without a notification.
 */
static void __attribute__((noreturn))
st_child(int handoff_fd, char **argv)
{
#ifndef SENOTIF_AUDIT_ARCH
	(void) handoff_fd;
	(void) argv;
	_exit(93);		/* backend not built for this architecture */
#else
	static struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SENOTIF_AUDIT_ARCH, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	const struct sock_fprog prog = {
		.len = (unsigned short) ARRAY_SIZE(filter),
		.filter = filter,
	};
	struct {
		struct cmsghdr h;
		int fd;
	} cbuf;
	struct msghdr mh = { 0 };
	struct iovec iov = { .iov_base = (void *) "L", .iov_len = 1 };

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		_exit(90);
	long lfd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
			   SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
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
	if (sendmsg(handoff_fd, &mh, 0) < 0)
		_exit(92);
	close((int) lfd);
	close(handoff_fd);

	if (tracee_environ)
		environ = tracee_environ;
	execvp(argv[0], argv);
	_exit(errno == ENOENT ? 127 : 126);
#endif /* SENOTIF_AUDIT_ARCH */
}

/* Fork the tracee; returns the listener fd, -1 on failure. */
static int
st_startup(char **argv, pid_t *pid_out)
{
	int sp[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}
	if (pid == 0) {
		close(sp[0]);
		if (dup2(sp[1], HANDOFF_FD) < 0)
			_exit(89);
		close(sp[1]);
		st_child(HANDOFF_FD, argv);
	}
	close(sp[1]);

	struct {
		struct cmsghdr h;
		int fd;
	} cbuf;
	struct msghdr mh = { 0 };
	struct iovec iov = { .iov_base = &(char){0}, .iov_len = 1 };

	memset(&cbuf, 0, sizeof(cbuf));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = &cbuf;
	mh.msg_controllen = CMSG_SPACE(sizeof(int));
	if (recvmsg(sp[0], &mh, 0) != 1 || cbuf.fd < 0) {
		int st;

		close(sp[0]);
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		error_msg_and_die("tracee did not install its seccomp "
				  "filter (child exit status %d)",
				  WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	}
	close(sp[0]);
	*pid_out = pid;
	return cbuf.fd;
}

#ifndef AT_FDCWD
# define AT_FDCWD -100
#endif

/*
 * The tracer's fd table is not the tracee's: emulating openat in the
 * tracer requires resolving the tracee's dirfd to a path first (its
 * cwd for AT_FDCWD -- the tracee may have chdir'ed since the fork).
 * Returns false when the dirfd cannot be turned into a path (the
 * caller then CONTINUEs instead of emulating).
 */
static bool
st_resolve_dirfd(struct st_tcb *st, int dirfd, char *buf, size_t bufsz)
{
	char link[64];
	ssize_t r;

	if (dirfd == AT_FDCWD)
		snprintf(link, sizeof(link), "/proc/%d/cwd", st->tcp.pid);
	else
		snprintf(link, sizeof(link), "/proc/%d/fd/%d",
			 st->tcp.pid, dirfd);
	r = readlink(link, buf, bufsz - 1);
	if (r <= 0)
		return false;
	buf[r] = '\0';
	return buf[0] == '/';	/* directories only; sockets etc. CONTINUE */
}

/* Open in the tracer's space what the tracee would have opened. */
static int
st_open_in_tracee_space(struct st_tcb *st, int dirfd, const char *path,
			int flags, mode_t mode)
{
	char dirbuf[PATH_MAX];
	char full[PATH_MAX];

	if (!st_resolve_dirfd(st, dirfd, dirbuf, sizeof(dirbuf)))
		return -1;
	if (path[0] == '/')
		return open(path, flags, mode);
	if (snprintf(full, sizeof(full), "%s/%s", dirbuf, path)
	    >= (int) sizeof(full)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return open(full, flags, mode);
}

/* faccessat in the tracee's dirfd/cwd space (flags passed through). */
static int
st_faccessat_in_tracee_space(struct st_tcb *st, int dirfd, const char *path,
			     int mode, int flags)
{
	char dirbuf[PATH_MAX];
	char full[PATH_MAX];

	if (!st_resolve_dirfd(st, dirfd, dirbuf, sizeof(dirbuf)))
		return -1;
	if (path[0] == '/')
		return faccessat(AT_FDCWD, path, mode, flags);
	if (snprintf(full, sizeof(full), "%s/%s", dirbuf, path)
	    >= (int) sizeof(full)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return faccessat(AT_FDCWD, full, mode, flags);
}

/* Fetch a path argument (arg index given) through /proc/<pid>/mem. */
static bool
st_fetch_path(struct tcb *tcp, int arg, char *buf, size_t bufsz)
{
	kernel_ulong_t addr = tcp->u_arg[arg];

	if (!addr)
		return false;
	int r = pmem_read_str(tcp, addr, bufsz - 1, buf);

	if (r <= 0)
		return false;
	buf[r - 1 < (int) bufsz - 1 ? r - 1 : (int) bufsz - 1] = '\0';
	return buf[0] != '\0';
}

/*
 * Decide what to do with this notification; fills resp and adjusts
 * tcp->u_rval/u_error to what the tracee will observe.
 * Returns true when the response has already been sent (the caller
 * must not send again).
 */
enum st_action {
	ST_CONTINUE,
	ST_SKIP_VAL,		/* respond val, syscall not executed */
	ST_SKIP_ERR,		/* respond -errno */
};

static enum st_action
st_decide(struct st_tcb *st, struct seccomp_notif *req,
	  struct seccomp_notif_resp *resp, long *val, int *err)
{
	struct tcb *tcp = &st->tcp;
	const char *name = tcp_sysent(tcp)->sys_name;

	if (ext.keep_alive > 0 && tcp->keepalive_left > 0
	    && strcmp(name, "exit_group") == 0) {
		char note[64];

		--tcp->keepalive_left;
		tcp->keepalive_any = true;
		tcp->keepalive_code = (int) req->data.args[0];
		snprintf(note, sizeof(note),
			 "keep-alive: exit_group(%d) suppressed",
			 tcp->keepalive_code);
		ext_add_note(tcp, note);
		tcp->u_rval = 0;
		tcp->u_error = 0;
		*val = 0;
		return ST_SKIP_VAL;
	}

	if ((ext.anti_debug_features & AD_TRACEME)
	    && req->data.nr == __NR_ptrace
	    && req->data.args[0] == 0) {
		/* An untraced TRACEME returns 0; answer exactly that. */
		ext_add_note(tcp, "anti-debug: ptrace(PTRACE_TRACEME) "
			      "spoofed as successful");
		tcp->u_rval = 0;
		tcp->u_error = 0;
		*val = 0;
		return ST_SKIP_VAL;
	}

	if (req->data.nr == __NR_open || req->data.nr == __NR_openat) {
		char path[PATH_MAX];
		int path_arg = req->data.nr == __NR_open ? 0 : 1;
		int flags_arg = req->data.nr == __NR_open ? 1 : 2;
		int mode_arg = req->data.nr == __NR_open ? 2 : 3;

		if (!st_fetch_path(tcp, path_arg, path, sizeof(path)))
			return ST_CONTINUE;	/* unreadable: let it run */

		int flags = (int) req->data.args[flags_arg];
		int oflags = flags & ~O_CLOEXEC;
		int hostfd = st_open_in_tracee_space(
			st,
			req->data.nr == __NR_open
			? AT_FDCWD : (int) req->data.args[0],
			path, oflags, (mode_t) req->data.args[mode_arg]);

		if (hostfd < 0) {
			tcp->u_rval = -1;
			tcp->u_error = errno;
			*err = errno;
			return ST_SKIP_ERR;
		}
		struct seccomp_notif_addfd addfd = {
			.id = req->id,
			.srcfd = hostfd,
			.newfd = 0,
			.newfd_flags = (flags & O_CLOEXEC) ? O_CLOEXEC : 0,
		};
		int newfd = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD,
				  &addfd);
		close(hostfd);
		if (newfd < 0)
			return ST_CONTINUE;	/* raced with task exit */
		tcp->u_rval = newfd;
		tcp->u_error = 0;
		*val = newfd;
		return ST_SKIP_VAL;
	}

	if (req->data.nr == __NR_faccessat) {
		char path[PATH_MAX];

		if (!st_fetch_path(tcp, 1, path, sizeof(path)))
			return ST_CONTINUE;
		if (st_faccessat_in_tracee_space(
			    st, (int) req->data.args[0], path,
			    (int) req->data.args[2],
			    (int) req->data.args[3]) < 0) {
			tcp->u_rval = -1;
			tcp->u_error = errno;
			*err = errno;
			return ST_SKIP_ERR;
		}
		tcp->u_rval = 0;
		tcp->u_error = 0;
		*val = 0;
		return ST_SKIP_VAL;
	}

	if ((req->data.nr == __NR_execve || req->data.nr == __NR_execveat)
	    && !tcp->u_error)
		st->fd_scan_pending = true;

	return ST_CONTINUE;
}

/* Print the decoded syscall line (classic) using strace's printers. */
static void
st_decode_and_print(struct st_tcb *st, struct seccomp_notif *req,
		    struct timespec *ts)
{
	struct tcb *tcp = &st->tcp;

	tcp->scno = req->data.nr;
	tcp->s_ent = scno_in_range(tcp->scno)
		     ? &sysent[tcp->scno] : &stub_sysent;
	tcp->true_scno = tcp->scno;
	for (unsigned int i = 0; i < MAX_ARGS; ++i)
		tcp->u_arg[i] = req->data.args[i];
	/* decoders run at syscall-entry phase: entering(tcp) must be true
	 * (tfetch_mem64 refuses to fetch otherwise) */

	strace_open_memstream(tcp);
	printleader(tcp);
	tprints_arg_begin(tcp_sysent(tcp)->sys_name);
	fflush(tcp->outf);
	clock_gettime(CLOCK_MONOTONIC, &tcp->etime);
	tcp->sys_func_rval = tcp_sysent(tcp)->sys_func(tcp);
	fflush(tcp->outf);
	clock_gettime(CLOCK_MONOTONIC, ts);
}

/* Finish the classic line with the outcome and publish everything. */
static void
st_finish_line(struct st_tcb *st, enum st_action action, long val, int err,
	       struct timespec *ts)
{
	struct tcb *tcp = &st->tcp;

	tprint_arg_end();
	tprint_space();
	tabto();
	tprint_sysret_begin();
	tprints_sysret_next("retval");
	switch (action) {
		case ST_SKIP_VAL:
			PRINT_VAL_D(val);
			tcp->u_rval = val;
			tcp->u_error = 0;
			break;
		case ST_SKIP_ERR: {
			const char *n = err < (int) nerrnos ? errnoent[err] : NULL;

			PRINT_VAL_D(-1);
			tprints_sysret_next("error");
			tprints_string(n ? n : "E?");
			break;
		}
		case ST_CONTINUE:
			tprints_string("?");
			tprints_sysret_next("note");
			tprints_string("seccomp-continued");
			tcp->u_rval = 0;
			tcp->u_error = 0;	/* outcome unknown */
			tcp->ext_continued = true;
			break;
	}
	if (tcp->ext_nnotes > 0) {
		const char *notes = ext_notes_joined(tcp, ';');

		tprints_sysret_next("notes");
		tprints_string(notes);
	}
	tprint_sysret_end();
	tprint_newline();
	line_ended();

	/* extensions see the same publish point as the ptrace backend */
	if (ext.json) {
		json_emit_syscall_event(tcp, ts);
		strace_close_memstream(tcp, false);
	} else {
		strace_close_memstream(tcp, true);
	}
	file_report_note_syscall(tcp);
}

/*
 * One tracee was reaped: emit its lifecycle events, decide the exit
 * code when it is the main tracee, and release its state.  A tracee
 * that faulted after a suppressed exit_group reports the suppressed
 * exit_group's status instead of the fault signal (see
 * ext_keepalive_fault_status), so --keep-alive runs keep a clean exit
 * status; the fault itself stays visible as the signal event / the
 * "+++" notice line.
 */
static void
st_reap_one(pid_t w, int stt, pid_t child, bool *alive)
{
	struct st_tcb *st = NULL;
	int subst = 0;
	bool substituted = false;

	for (size_t i = 0; i < ARRAY_SIZE(st_tcbs); ++i)
		if (st_tcbs[i].in_use && st_tcbs[i].tcp.pid == w)
			st = &st_tcbs[i];

	if (WIFSIGNALED(stt) && st)
		substituted = ext_keepalive_fault_status(&st->tcp,
							 WTERMSIG(stt),
							 &subst);

	if (ext.json && st) {
		if (WIFEXITED(stt))
			json_emit_exit_event(&st->tcp, WEXITSTATUS(stt));
		else if (WIFSIGNALED(stt)) {
			char note[128] = "";

			if (substituted)
				snprintf(note, sizeof(note),
					 "keep-alive: exit_group(%d) was"
					 " suppressed and the tracee"
					 " faulted afterwards (%s);"
					 " reporting the suppressed exit"
					 " status", subst,
					 sprintsigname(WTERMSIG(stt)));
			json_emit_signal_event(&st->tcp,
					       sprintsigname(WTERMSIG(stt)),
					       false,
					       note[0] ? note : NULL);
		}
	}

	if (w == child) {
		if (WIFEXITED(stt))
			strace_set_exit_code(WEXITSTATUS(stt));
		else if (WIFSIGNALED(stt)) {
			if (substituted) {
				strace_set_exit_code(subst);
				if (!ext.json)
					fprintf(shared_log,
						"+++ keep-alive: exit_group(%d)"
						" was suppressed and the"
						" tracee faulted afterwards"
						" (%s); reporting the"
						" suppressed exit status +++\n",
						subst,
						sprintsigname(WTERMSIG(stt)));
			} else {
				strace_set_exit_code(0x100 | WTERMSIG(stt));
			}
		}
		*alive = false;
	}
	if (st)
		st_tcb_release(st);
}

/*
 * Receive one notification, decode it, decide, print, respond.
 * Returns false when no notification could be received (tracee died,
 * interrupted) and the caller may poll/reap again.
 */
static bool
st_handle_notification(void)
{
	struct seccomp_notif req = { 0 };
	struct seccomp_notif_resp resp = { 0 };
	struct timespec ts;

	if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0)
		return false;

	struct st_tcb *st = st_tcb_for(req.pid);

	if (!st) {
		/*
		 * Pool exhausted (or unknown pid): answer anyway, or the
		 * tracee would stay blocked in this syscall forever.
		 */
		memset(&resp, 0, sizeof(resp));
		resp.id = req.id;
		resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0
		    && errno != ENOENT)
			perror_msg("NOTIF_SEND");
		return true;
	}

	if (st->fd_scan_pending) {
		st->fd_scan_pending = false;
		/*
		 * The previous notification was a CONTINUEd exec: the
		 * fd table is now post-exec, so the inherited fds are
		 * real and can be recorded.
		 */
		file_report_note_inherited(&st->tcp);
	}

	ext_reset_paths(&st->tcp);
	ext_reset_notes(&st->tcp);
	st->tcp.ext_continued = false;
	st_decode_and_print(st, &req, &ts);

	long val = 0;
	int err = 0;
	enum st_action action = st_decide(st, &req, &resp, &val, &err);

	st_finish_line(st, action, val, err, &ts);
	fflush(shared_log);

	resp.id = req.id;
	switch (action) {
		case ST_SKIP_VAL:
			resp.val = val;
			break;
		case ST_SKIP_ERR:
			resp.error = err;
			break;
		case ST_CONTINUE:
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			break;
	}
	{
		int src_ = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND,
				  &resp);

		debug_msg("SEND nr=%d action=%d rc=%d errno=%d",
			  (int) req.data.nr, (int) action, src_, errno);
		if (src_ < 0 && errno != ENOENT)
			perror_msg("NOTIF_SEND");
	}
	return true;
}

int
senotif_backend_main(char **argv)
{
	pid_t child;

	setvbuf(shared_log, NULL, _IOLBF, 0);
	signal(SIGCHLD, SIG_DFL);

	listener_fd = st_startup(argv, &child);
	if (listener_fd < 0)
		error_msg_and_die("seccomp backend: could not start tracee");

	debug_msg("seccomp backend: tracee %d, listener fd %d", child,
		  listener_fd);

	bool tracees_alive = true;
	while (tracees_alive) {
		/*
		 * Reap on every iteration: a tracee that dies without a
		 * final notification (e.g. killed by a signal) produces
		 * no further events, and the seccomp listener does not
		 * reliably poll(2) HUP on task death.
		 */
		for (;;) {
			int stt;
			pid_t w = waitpid(-1, &stt, WNOHANG);

			if (w <= 0)
				break;
			debug_msg("seccomp backend: reaped %d", w);
			st_reap_one(w, stt, child, &tracees_alive);
		}
		if (!tracees_alive)
			break;

		struct pollfd pfd = { .fd = listener_fd,
				      .events = POLLIN, .revents = 0 };
		int pr = poll(&pfd, 1, 200);

		if (pr < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pr == 0)
			continue;
		if (pfd.revents & (POLLHUP | POLLERR)) {
			tracees_alive = 0;
			break;
		}
		if (!(pfd.revents & POLLIN))
			continue;

		if (!st_handle_notification())
			continue;
	}

	/*
	 * Final reap.  The tracee may still be mid-teardown when the
	 * listener reports HUP (a just-CONTINUEd exit_group races the
	 * wait(2)-visibility of the zombie), so poll briefly instead of
	 * sampling once and leaking the child as an orphan zombie.
	 */
	for (int i = 0; i < 200; ++i) {
		int stt;
		pid_t w = waitpid(-1, &stt, WNOHANG);

		if (w == 0) {
			/*
			 * Tracees still alive: the listener may have
			 * notifications queued for them; service those
			 * first, or a tracee blocked mid-syscall would
			 * never reach exit(2).
			 */
			struct pollfd pfd = { .fd = listener_fd,
					      .events = POLLIN };
			int pr = poll(&pfd, 1, 100);

			if (pr == 1 && (pfd.revents & POLLIN))
				st_handle_notification();
			continue;
		}
		if (w < 0)
			break;	/* ECHILD: everyone reaped */
		st_reap_one(w, stt, child, &tracees_alive);
		i = 0;	/* made progress: reset the grace counter */
	}
	if (listener_fd >= 0)
		close(listener_fd);
	return 0;
}

/* Is the seccomp user-notification facility usable on this host? */
bool
senotif_supported(void)
{
	int sp[2];
	pid_t pid;

#ifndef SENOTIF_AUDIT_ARCH
	return false;		/* backend not built for this architecture */
#endif
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0)
		return false;
	pid = fork();
	if (pid < 0) {
		close(sp[0]);
		close(sp[1]);
		return false;
	}
	if (pid == 0) {
		char *argv[2] = { (char *) "/bin/true", NULL };

		close(sp[0]);
		if (dup2(sp[1], HANDOFF_FD) < 0)
			_exit(89);
		close(sp[1]);
		st_child(HANDOFF_FD, argv);
	}
	close(sp[1]);
	struct {
		struct cmsghdr h;
		int fd;
	} cbuf;
	struct msghdr mh = { 0 };
	struct iovec iov = { .iov_base = &(char){0}, .iov_len = 1 };

	memset(&cbuf, 0, sizeof(cbuf));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = &cbuf;
	mh.msg_controllen = CMSG_SPACE(sizeof(int));

	/* the handoff must arrive on its own; never block forever */
	struct pollfd hpfd = { .fd = sp[0], .events = POLLIN };
	bool ok = poll(&hpfd, 1, 3000) == 1 && recvmsg(sp[0], &mh, 0) == 1
		  && cbuf.fd >= 0;
	int lfd = cbuf.fd;

	close(sp[0]);
	if (ok) {
		/*
		 * The child's execve must actually produce a
		 * notification: this is what distinguishes a working
		 * user-notification filter from one that silently
		 * allows everything (e.g. an arch mismatch, or an
		 * outer policy flattening USER_NOTIF).
		 */
		struct seccomp_notif req = { 0 };
		struct seccomp_notif_resp resp;
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };

		if (poll(&pfd, 1, 3000) != 1) {
			ok = false;	/* filter installed, but silent */
		} else if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &req) == 0) {
			memset(&resp, 0, sizeof(resp));
			resp.id = req.id;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
			if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0
			    && errno != ENOENT)
				ok = false;
		} else {
			ok = false;
		}
		close(lfd);
	}
	int st;

	waitpid(pid, &st, 0);
	return ok;
}
