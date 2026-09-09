# Review pass 4 — the seccomp user-notification backend

Scope: `src/senotif.c`, the ucopy.c pmem fallbacks, the `--backend`
wiring, and every live-trace defect surfaced while making the full
validation matrix pass **on the ptrace-denied development host**.
This pass exists because pass 1–3 reviewed code that could not run
here; this one reviewed code that runs.

| # | finding | severity | resolution |
| --- | --- | --- | --- |
| 1 | `/proc/<pid>/mem` pins the target's `mm` at **open** time: after the tracee's execve the cached fd read 0 bytes forever, so every post-exec path fetch failed (openat showed raw addresses, the report lost the libraries) | bug, data-destroying | fixed: `pmem_pread()` closes/reopens/retries once on failed read |
| 2 | the synthetic tcbs ran decoders with `TCB_INSYSCALL` set ("exiting" phase) — `tfetch_mem64()` refuses to fetch unless `entering(tcp)`, so sockaddr arguments (AF_UNIX connect paths) printed as raw addresses | bug | fixed: decoders run at entry phase; flag not set |
| 3 | synthetic tcbs had `qual_flg == 0` — `verbose(tcp)` false, so `tfetch_mem64` bailed again | bug | fixed: `DEFAULT_QUAL_FLAGS` applied at tcb creation |
| 4 | classic text lines leaked ` <unfinished ...>` prefixes: `line_ended()` was never called between synthesized lines | bug (cosmetic but corrupts the stream) | fixed |
| 5 | CONTINUEd syscalls printed `ret:0` in `--json` — a *lie* (outcome unknown, not zero) | bug, misleading data | fixed: `ret:null` + `"continued":true`, and the report counts them as attempts without outcomes (`ext_continued`) |
| 6 | the report JSON wrapped path keys in **two** quote pairs (`"/bin/true""`) — my earlier escaper refactor left the manual quoting around the shared one; every parser rejected the report | bug, breaks the primary consumer | fixed; jq/python asserted in validate |
| 7 | the tracer loop hung forever when a tracee died without a final notification: reaping only ran after notifications, and the seccomp listener does not reliably poll(2) HUP on task death | bug, hangs CI | fixed: reap every iteration, end the loop when the main child is reaped |
| 8 | the exit code was lost (strace exited 0 for `/bin/false`): the final `waitpid(WNOHANG)` raced the just-CONTINUEd `exit_group` teardown (task still state R for a moment → w=0) and bailed, leaking an orphan zombie | bug | fixed: bounded drain loop (≤2 s) until ECHILD; false→1, `sh -c 'exit 7'`→7, verified ×N |
| 9 | the probe harness (experiment 15) hung after all checks passed for the same teardown-race reason | harness bug | fixed: break on exit_group, then bounded poll-reap |
| 10 | `--backend=seccomp` cannot see syscalls an outer ERRNO filter denies (kernel precedence: ERRNO > USER_NOTIF), so the TRACEME spoof cannot un-deny a host that forbids ptrace outright | inherent limitation | documented (man page, experiments README); validate.sh T1 skips with an environmental guard: if an *untraced* run of the detector also fires, the spoof is not assertable on that host |
| 11 | in seccomp mode TracerPid is genuinely 0 (no tracer link exists) — the ptrace-mode buffer rewrite has nothing to do | by design | documented in the option table and man page |
| 12 | T3/T5 test preconditions assumed the ptrace-mode world (no `--keep-alive`, thresholds); T6 judged the preset by the tracee's exit code, which is a mirrored SIGSEGV after keep-alive exhaustion (documented behaviour) | test bugs | fixed: keep-alive added where the asserted data requires the fallback path, static target runs without keep-alive (post-suppressed-exit spin, also documented), T6 asserts on the report |
| 13 | `/proc/<pid>/mem` read-only open is required: the development host denies writes — the ptrace-mode TracerPid rewrite (upoken) therefore cannot be exercised there | environmental | documented; seccomp mode does not need writes |

Verdict: after this pass the seccomp backend is no longer "code that
should work" but a working tracer with committed evidence on the very
host class it was built for. Assume more remain.
