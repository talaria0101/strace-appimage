# Review pass 5 — the peer review that fixed what the e2e suite proved

Scope: a from-scratch peer review of every claim in the repository
(no prior session knowledge assumed), the two open issues (#2,
#3), the "Known limits" list, and a new end-to-end experiment
(60-e2e.sh) against six sha256-pinned real artefacts (3 static
binaries from pkgforge/bin, 3 AppImages from
pkgforge-dev/Anylinux-AppImages). Three passes over the final state:
(A) code, (B) docs-as-claims, (C) tests-as-claims. Host conditions:
ptrace denied by outer seccomp (live probe re-run), Linux 6.18
x86_64, gcc 15.3.0.

## Pass A — code (every custom file re-read, every defect reproduced first)

| # | finding | severity | resolution |
| --- | --- | --- | --- |
| A1 | `--keep-alive` corrupted semantics beyond the documented "may crash": every process got its own budget, so a **suppressed final `exit_group` made the tracee fault (glibc `hlt` → SIGSEGV), the tracer's `terminate()` then re-raised the fault signal into itself (upstream's "mimic the child" convention), and scripted runs died with status 139**; worse, helper processes spawned inside the tracee tree were observed by their parents as 139 (e2e: bash's `cat`/`mkdir` chain broke) | bug, data-destroying for scripts | fixed: the fault-death of a process with ≥1 suppressed exit is reported as **the suppressed exit_group's status** (both backends; `ext_keepalive_fault_status()`), with an explanatory note on the JSON signal event / a `+++` notice line; the fault itself stays visible in the trace |
| A2 | `--backend` was documented, helped, and had a full case handler — **but the `longopts` entry was missing**: the option was unparsable; the whole backend selection story was unreachable by flag | bug, feature unreachable | fixed: `{ "backend", required_argument, ... }` added; `--backend=bogus` rejected; `-p` and `--seccomp-bpf` guarded |
| A3 | `--seccomp-bpf` + `--backend=seccomp` ran upstream's `check_seccomp_filter()` ptrace probe **before** the backend decision, dying with confusing `PTRACE_TRACEME: Operation not permitted` noise instead of a clear rejection (the old guard sat too late and never fired) | bug, wrong diagnostics | fixed: backend decision + guards moved above `check_seccomp_filter()`; `--seccomp-bpf` now rejected explicitly under the seccomp backend |
| A4 | seccomp open/openat/faccessat emulation called the **tracer's** `openat(dirfd, ...)` with the **tracee's** dirfd number — two different fd tables, so a dirfd≠`AT_FDCWD` open resolved the wrong directory or EBADF; also `AT_FDCWD` used the tracer's cwd (the tracee may have `chdir`ed since fork) | bug, wrong results | fixed: `st_resolve_dirfd()` maps the tracee's dirfd via `/proc/<pid>/fd/<n>` (cwd via `/proc/<pid>/cwd`); unresolvable dirfds CONTINUE instead of guessing |
| A5 | `st_tcb_for()` pool exhaustion returned NULL and **silently dropped the notification — the tracee blocked in that syscall forever** (a hang by construction under load) | bug, hangs | fixed: unknown-pid notifications answered with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` |
| A6 | `senotif_supported()` accepted a filter that **never produces a notification** (e.g. an arch mismatch fell through the BPF to `RET ALLOW`, and the handoff `recvmsg` blocked unbounded): `auto` could select a backend that traces nothing | bug | fixed: the probe requires the handoff within 3 s **and** an actual execve notification within 3 s; non-native architectures excluded at compile time (x86_64/aarch64 built, others refuse `--backend=seccomp` at init) |
| A7 | seccomp backend emitted **no `exit`/`signal` JSON events** (ptrace/backend parity gap) and leaked debug `fprintf`s to stderr on every reap | bug, parity | fixed: `st_reap_one()` emits exit/signal events and propagates exit codes for every tracee; debug output moved to `debug_msg` |
| A8 | `--report-files` hints JSON interpolated paths with raw `%s` — a tracee-controlled path with `"`/`\` produced **invalid JSON** (the primary consumer is jq) | bug, breaks consumer | fixed: `ext_json_print_string()` for hint paths |
| A9 | `--json` emitted `MAX_ARGS` raw arguments for every syscall (trailing garbage from stale u_arg); the README example showed fewer | bug, data quality | fixed: emit `ent->nargs` arguments; validate.sh asserts the arity |
| A10 | relative path arguments reached the report unresolved (issue #3.1): AppImage payloads open nearly everything relative, so `du`/GUI runs lost most of the report | bug (issue #3.1) | fixed: capture resolves relative paths against the syscall's dirfd (19-entry *at*-syscall table incl. multi-path `renameat/linkat/symlinkat`) or `/proc/<pid>/cwd`; unresolvable paths recorded as-is; empty paths with `AT_EMPTY_PATH` resolve to the dirfd's target |
| A11 | fd inheritance across exec not captured (issue #3.2): the report reflected only what tracees opened themselves | gap (issue #3.2) | fixed: after a successful exec the new image's fds are enumerated and recorded as `inherit` ops; in seccomp mode the scan is deferred to the next notification (post-CLOEXEC fd table) — ptrace mode scans at the exec exit stop |
| A12 | `--anti-anti-debug` wchan vector uncovered (issue #2): `/proc/<pid>/wchan` reads still said `ptrace_stop` | gap (issue #2) | fixed: length-preserving zero rewrite of wchan values (the value contains no digits, so the TracerPid-style digit rewrite would have no-oped — whole value zeroed, newline preserved); feature-gated behind the new spec |
| A13 | `readv`/`preadv`/`preadv2` TracerPid reads unrewritten (only `read`/`pread64` were covered); a needle split across iovecs was missed entirely | bug, partial coverage | fixed: per-iovec rewrite with a carried seam window across iovec boundaries; compat personalities remain documented as skipped |
| A14 | `--anti-anti-debug` was all-or-nothing; issue #2 asked for a `traceme:off` escape hatch | gap (issue #2) | fixed: `--anti-anti-debug[=FEAT[:OFF],...]` (traceme/status/wchan/all), parsed by `ext_anti_debug_parse_spec()`, feature bits checked at every hook |
| A15 | the senotif main loop read `pfd.revents` after a failed (EINTR) `poll` — stale/garbage flags could spuriously terminate the loop | bug, latent | fixed: `revents` zero-initialized; `EINTR` handled before the revents checks |
| A16 | `-c/--summary` with `--json` was only rejected for `CFLAG_ONLY_STATS`; `CFLAG_BOTH` would splice classic summary text into the JSON stream | bug, breaks consumer | fixed: any `-c` rejected with `--json`; man page updated |

## Pass B — docs as claims (every sentence checked against the tree)

| # | finding | resolution |
| --- | --- | --- |
| B1 | README example `--json` event carried 5 args and a fabricated timestamp; the emitter writes table-arity args | replaced with a captured real event |
| B2 | man page still listed wchan, relative paths, exec-inheritance and the keep-alive crash as limits/omissions after the fixes | man page rewritten for all six options (spec syntax, inherit op, dirfd resolution, exit-status substitution, backend architectures, new rejections) |
| B3 | README "Known limits" contradicted the new behaviour in four places | rewritten; remaining limits (timing checks, PTRACE_ATTACH, compat iovec, outer-ERRNO precedence, fork-without-exec fd non-tracking, /tmp-size-class operational footguns) are the ones actually true |
| B4 | root `AGENTS.md`/`CLAUDE.md` were upstream's generic strace guide — they routed agents to upstream contribution flow, contradicting this repository's no-upstream-proposals rule | removed; new [`docs/AGENTS.md`](AGENTS.md) is a standalone router carrying the full working context |
| B5 | `NEWS` had no entries for this change set | entries added (fixes + new options semantics) |
| B6 | `patches/PATCHES.md` registry said "three patches" | updated for the derived series and this pass |

## Pass C — tests as claims (the gates re-derived from scratch)

| # | finding | resolution |
| --- | --- | --- |
| C1 | validate.sh never checked the strace process's own exit status — a tracer that **segfaulted after writing its artifacts** passed (observed: T3/T4/T6 runs exited 139 pre-A1) | fixed: exit-status assertions added (T8–T10); keep-alive runs now assert a clean propagated status |
| C2 | the "e2e" gap: no experiment ran real-world static binaries or real AppImages — the exact artefact classes the project targets | added `experiments/60-e2e.sh` + sha256 manifest: 6 artefacts, 41 assertions, all passing live on the ptrace-denied host (seccomp backend) |
| C3 | validate.sh asserted `keep-alive: exit_group suppressed` note text and JSONL shapes with jq idioms that silently mismatched the new formats (slurp vs per-line, text-vs-JSON reports, relative `$T8DIR`) | fixed assertions; new T8 (relative-path resolution ×3), T9 (inherit op), T10 (exit-status cleanliness + json arity + signal note), T11 (wchan rewrite, ptrace-gated; control vs vanilla) |
| C4 | unit tests stopped linking after the path-resolution helper began referencing util.c symbols; a sanitizer-instrumented tree also failed to link them | stubs added to the units; `run-unit-tests.sh` detects instrumented objects and links the sanitizer runtime |
| C5 | 60-e2e.sh's own first runs found three test-design bugs worth recording: multicall coreutils dispatches on argv[0] (applet-named copies required); the Anylinux shim layer rewrites library access through a `/KEK/` prefix (the report records exactly what the tracee requested); musl curl skips its own stderr diagnostics for file-redirected stderr even untraced (assert exit code instead) | all folded into the script; documented in the experiments README |
| C6 | a full `/tmp` tmpfs made every writer lose output silently — including two false "tracer hangs" and one false "tracer regression" during this pass | documented as an operational condition; artefact-heavy runs keep their work off tmpfs |

## Verdict

Both open issues are closed in code (#3.1 relative-path resolution,
#3.2 exec-time fd inheritance; #2 wchan rewrite + `traceme:off` spec),
the worst keep-alive defect (status corruption + tracer self-kill) is
fixed, and the end-to-end suite proves the option set on six real
pinned artefacts: **41/41 e2e assertions, 36/36 validate assertions
(+3 environment-guarded skips)** on a host where vanilla strace cannot
run at all. Assume more remain.
