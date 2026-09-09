#!/bin/sh
# 15-senotif-primitives.sh
#
# Question: on a host that denies the ptrace syscall class outright, can
# a ptrace-free tracer still be built from kernel facilities an
# unprivileged program controls?
#
# Six primitives must hold for the seccomp user-notification backend:
#   P1  the tracee can install a user-notify filter over all its
#       syscalls and hand the listener to the tracer over a socketpair
#   P2  the tracer receives notifications (nr + args) with no ptrace
#   P3  CONTINUE lets a syscall execute normally
#   P4  the tracer can skip a syscall and forge its return value
#   P5  SECCOMP_IOCTL_NOTIF_ADDFD installs a tracer-side fd into the
#       tracee (open/openat emulation with real results)
#   P6  /proc/<pid>/mem supplies tracee memory read-only (writes are
#       denied on the development host; the backend does not need them)
#
# Output: logs/15-senotif-primitives.log
# Exit codes: 0 all primitives hold, 1 a primitive failed, 2 cannot run.

cd "$(dirname "$0")" || exit 2
mkdir -p logs

cc -O2 -o /tmp/senotif_probe.$$ senotif_probe.c 2>>logs/15-senotif-primitives.log || exit 2
timeout 30 /tmp/senotif_probe.$$ > logs/15-senotif-primitives.log 2>&1
rc=$?
rm -f /tmp/senotif_probe.$$
cat logs/15-senotif-primitives.log
exit $rc
