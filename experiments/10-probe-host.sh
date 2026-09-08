#!/bin/sh
# 10-probe-host.sh
#
# Question: can this host run ptrace-based tracers at all, and what
# exactly denies it when it cannot?
#
# Method: fork a child, stop it, and issue every ptrace(2) request from
# the parent (including a bogus request number that the kernel would
# normally reject with EIO/ESRCH *after* argument validation).  A blanket
# EPERM, including for the bogus request, means the ptrace syscall is
# denied before the kernel ever looks at the arguments, i.e. a seccomp
# filter (not YAMA, not an LSM, which both answer after validation).
#
# Inputs: none.  Output: logs/10-ptrace-map.txt
# Exit codes: 0 ptrace works, 1 ptrace denied (evidence written), 2 cannot run.

cd "$(dirname "$0")" || exit 2
mkdir -p logs

cat > /tmp/ptrace_map.$$.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
int main(void){
  pid_t child = fork();
  if (!child) { raise(SIGSTOP); _exit(0); }
  int st; waitpid(child, &st, WUNTRACED);
  struct { unsigned long n; const char *name; } reqs[] = {
    {0,"TRACEME"},{16,"ATTACH"},{0x4206,"SEIZE"},{0x9999,"BOGUS_REQ"},
  };
  int eperm = 0;
  for (size_t i = 0; i < sizeof(reqs)/sizeof(reqs[0]); i++) {
    errno = 0;
    long r = reqs[i].n == 0
      ? ptrace((enum __ptrace_request)0, 0, 0, 0)
      : ptrace((enum __ptrace_request)reqs[i].n, child, (void*)0, 0);
    printf("%-10s (%#lx) -> ret=%ld errno=%d (%s)\n",
           reqs[i].name, reqs[i].n, r, errno, errno?strerror(errno):"-");
    if (errno == EPERM) eperm++;
  }
  kill(child, SIGKILL); waitpid(child, &st, 0);
  return eperm == 4 ? 1 : 0;
}
EOF
OUT=logs/10-ptrace-map.txt
{
	echo "# conditions"
	uname -a
	date -u
	echo "uid: $(id -u)  (uid_map: $(tr '\n' ' ' < /proc/self/uid_map))"
	grep -E 'Seccomp|NoNewPrivs|CapEff' /proc/self/status
	echo
} > "$OUT"

cc -o /tmp/ptrace_map.$$ /tmp/ptrace_map.$$.c 2>>"$OUT" || exit 2
/tmp/ptrace_map.$$ >> "$OUT"; rc=$?
rm -f /tmp/ptrace_map.$$ /tmp/ptrace_map.$$.c

if [ "$rc" = 0 ]; then
	echo "ptrace: WORKS on this host" | tee -a "$OUT"
	exit 0
fi
{
	echo
	echo "ptrace: DENIED (seccomp ERRNO(EPERM) on the syscall itself;"
	echo "even the bogus request answers EPERM, so the kernel never"
	echo "validates arguments -- this is a filter, not YAMA/LSM)."
	echo "Live-trace experiments (50-, 60-) will exit 2 on this host;"
	echo "run them on an unrestricted host."
} >> "$OUT"
tail -12 "$OUT"
exit 1
