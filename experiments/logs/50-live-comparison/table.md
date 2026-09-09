# live comparison (generated Wed Sep  9 02:57:08 UTC 2026, host 6.18.39-gentoo-dist-bin)

| scenario | LD_DEBUG=libs (status quo) | strace-appimage |
| --- | --- | --- |
| fallback dlopen(libGL.so.1) after early exit | 0 hits | 1 entries |
| static binary: loader activity seen | 0 lines | 3 paths reported |
| anti-debug target outcome | detects tracer (exit 42) | ours(--anti-anti-debug) exit: 42 ours(--anti-anti-debug) exit: 42 ours(--anti-anti-debug) exit: 42  |

Conditions: Linux 6.18.39-gentoo-dist-bin, patched tracer commit 07b986426.
On hosts where the ptrace syscall class is denied outright, the
anti-debug detector fires even untraced (TRACEME answers EPERM
for everyone) -- the spoof is asserted on normal hosts only
(tests-ext/validate.sh T1 environmental guard).
json events: 188 (1 with errno)
