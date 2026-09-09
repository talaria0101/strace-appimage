# experiments

Numbered in the order they were run. The number is the sequence, not a
priority. Every script prints its own conditions and keeps its evidence
in `logs/`; none of them delete their own output.

| # | script | question | status on the development host |
| --- | --- | --- | --- |
| 10 | `10-probe-host.sh` | can this host run ptrace-based tracers, and what exactly denies it? | answered: denied by seccomp (`ERRNO(EPERM)` on the `ptrace` syscall itself, even for a bogus request number, so argument validation is never reached — a filter, not YAMA/LSM) |
| 15 | `senotif_probe.c` (+ `logs/15-senotif-primitives.log`) | can a ptrace-free tracer be built at all here (user-notification listener, CONTINUE, forged retvals, ADDFD, /proc/pid/mem)? | **all six primitives proven** — this is the negative result that became a feature |
| 20 | `20-build-strace.sh` | does the patched vendored tree build cleanly (`-Werror`)? | passed |
| 30 | `30-unit-tests.sh` | do the ptrace-free units (JSON escaper, report collector) pass? | passed |
| 40 | `40-option-wiring.sh` | are the options wired (help, validation, preset)? | passed |
| 50 | `50-live-comparison.sh` | what does each extension change, observably, vs the status quo? | **run live on this host** (seccomp backend): table in `logs/50-live-comparison/table.md` — LD_DEBUG=libs 0 hits / static blind / this tracer records both |

## The negative result that became a feature

The development host (the operator's agent sandbox) denies `ptrace` via
seccomp, so vanilla strace — every ptrace-based tracer — cannot run
there (`logs/10-ptrace-map.txt` is the evidence). That constraint was
first treated as a limitation, then refuted: the tracee can always
seccomp *itself*, so `senotif_probe.c` proves the ptrace-free primitive
set (experiment 15) and `src/senotif.c` implements it. The host that
could not run any tracer now runs the full validation matrix live.

Residual environmental facts, documented where they bite:

* an outer `ERRNO(EPERM)` filter outranks `USER_NOTIF` (kernel action
  precedence), so syscalls the sandbox denies (the ptrace class) are
  invisible to every tracer, including this one — the anti-debug A/B
  (validate.sh T1) skips with an environmental guard there;
* `/proc/<pid>/mem` is readable but not writable on this host — the
  ptrace-mode TracerPid rewrite is exercised only on normal hosts, and
  the seccomp backend does not need it (TracerPid is genuinely 0);
* `validate.sh` still returns exit code 2, not failure, if *no* backend
  can run, so CI can tell "broken" from "cannot run here".

## Conditions

Development host: Linux 6.18 x86_64, gcc 15.3.0, one machine, one day
(see each log's header for the exact block). Live-trace numbers, once
produced by third parties on their hosts, carry their own conditions in
`logs/50-live-comparison/table.md`.
