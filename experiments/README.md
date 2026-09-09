# experiments

Numbered in the order they were first run. The number is the sequence,
not a priority. Every script prints its own conditions, keeps its
evidence in `logs/`, and is re-runnable from a clean clone; none of
them delete their own output.

| # | script | question | status |
| --- | --- | --- | --- |
| 10 | `10-probe-host.sh` | can this host run ptrace-based tracers, and what exactly denies it? | answered (see below) |
| 15 | `senotif_probe.c` (+ `logs/15-senotif-primitives.log`) | can a ptrace-free tracer be built at all here (user-notification listener, CONTINUE, forged retvals, ADDFD, /proc/pid/mem)? | **all six primitives proven** — this is the negative result that became a feature |
| 20 | `20-build-strace.sh` | does the patched vendored tree build cleanly (`-Werror`)? | passed |
| 30 | `30-unit-tests.sh` | do the ptrace-free units (JSON escaper, report collector) pass? | passed |
| 40 | `40-option-wiring.sh` | are the options wired (help, validation, preset)? | passed |
| 50 | `50-live-comparison.sh` | what does each extension change, observably, vs the status quo? | **run live on this host** (seccomp backend): table in `logs/50-live-comparison/table.md` |
| 60 | `60-e2e.sh` (+ `60-e2e.manifest.sh`) | do the extensions hold up end-to-end on real-world static binaries and real AppImages? | **41/41 assertions pass live on this host** (seccomp backend); see the detailed entry below |

## Experiment 10 — host ptrace probe

`10-probe-host.sh` walks every interesting ptrace request and records
the return/errno (`logs/10-ptrace-map.txt`). Findings on the
development host: even a bogus request number (`0x9999`) answers
`EPERM` before argument validation, i.e. the denial is an outer
seccomp `ERRNO(EPERM)` filter on the syscall itself, not YAMA/LSM
policy. Consequence: *vanilla* strace cannot run here, and the
`ptrace(PTRACE_TRACEME)` spoof of `--anti-anti-debug` cannot fire in
the seccomp backend on this host (kernel action precedence: `ERRNO`
outranks `USER_NOTIF`, so the ptrace syscall never reaches the tracee's
own filter). `/proc/<pid>/mem` reads work; writes do not.

## Experiment 15 — the ptrace-free primitive set

`senotif_probe.c` proves, in ~280 lines, everything the seccomp backend
needs: (1) a tracee can install `SECCOMP_FILTER_FLAG_NEW_LISTENER` on
itself; (2) the listener fd crosses a unix socket via `SCM_RIGHTS`;
(3) `SECCOMP_IOCTL_NOTIF_RECV`/`NOTIF_SEND` with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` let an unprivileged tracer shepherd
every syscall; (4) forged return values (SKIP) work;
(5) `SECCOMP_IOCTL_NOTIF_ADDFD` installs real fds into the tracee;
(6) `/proc/<pid>/mem` serves memory arguments while the tracee is
blocked in the notification (stable, no TOCTOU). Log with host block:
`logs/15-senotif-primitives.log`.

## Experiments 20/30/40 — build, units, wiring

* `20-build-strace.sh`: `./bootstrap && ./configure --enable-mpers=no
  && make` under `-Werror`; committed log from the development host.
* `30-unit-tests.sh`: `tests-ext/run-unit-tests.sh` — the JSON
  escaper (`unit_json_escape.c`) and the report collector
  (`unit_file_report.c`, synthetic tcbs) pass. The unit binaries are
  built from the same tree objects the tracer links.
* `40-option-wiring.sh`: `--help` carries all six options; `--json` vs
  `-ff` rejected; `--keep-alive=bogus` rejected; `--packager` preset
  resolves. Log: `logs/40-option-wiring.log`.

## Experiment 50 — live A/B against the status quo

`50-live-comparison.sh` runs the hostile target three ways —
`LD_DEBUG=libs`, vanilla strace (ptrace hosts only), this tracer — and
writes per-claim evidence into `logs/50-live-comparison/`. Headline
from the committed run on the ptrace-denied host: `LD_DEBUG=libs`
scores **0** hits on the post-early-exit `dlopen("libGL.so.1")`
fallback that the report records; the static binary is invisible to
`LD_DEBUG` (0 lines) while the report covers it (3+ paths); the
validation matrix passes with 2 environmental skips.

## Experiment 60 — end-to-end on real artefacts

`60-e2e.sh` is the third-party-reproducible proof: it fetches six real
artefacts pinned by sha256 in `60-e2e.manifest.sh`, traces each with
the packager preset, and asserts observable outcomes. Runs live on the
ptrace-denied host via the seccomp backend: **41 assertions, 0
failures** (committed summaries in `logs/60-e2e/<name>/`; bulky traces
for the largest runs are regenerable and gitignored).

Artefacts (all fetched + sha256-pinned by the manifest):

| class | artefact | version | why this one |
| --- | --- | --- | --- |
| static | `bash` (pkgforge/bin, musl) | 5.3.3 | script runner: forks, file I/O, redirections |
| static | `coreutils` (pkgforge/bin, musl static-PIE) | 9.6 | multicall; `du`/`sort` generate stat-heavy real workloads |
| static | `curl` (pkgforge/bin, musl) | 8.16.0 | network/openssl/file stack, error paths |
| AppImage | `gtk3-demo-x86_64` (Anylinux-AppImages, demo) | GTK 3.24.52 | 196 bundled libraries, GUI display probe |
| AppImage | `Qt6+dbus-demo-x86_64` (demo) | Qt 6 | 297 libraries, dbus dependency |
| AppImage | `sdl2-demo-x86_64` (demo) | SDL2 | 227 libraries, device probing |

Assertions per artefact (all pass): exit status propagated exactly
(0 for successful runs, 7 for curl's refused connect); every JSONL
line parses; event counts in the hundreds/thousands; file report
non-trivial; `.so`-library detection; headless `missing_display_or_device`
hint (AppImages); keep-alive suppression notes; report library count
versus `LD_DEBUG=libs` in the same budget (196/297/227 vs 2 — the
status quo's loader scraping sees only what init'd before the run was
killed).

Conditions and limits learned (each one drove a code fix or is
documented in the man page):

* **Relative paths**: `du -sb /usr/lib64` and the AppImage payloads open
  almost everything relative; before the dirfd/cwd resolution the
  report missed most of the run. Now resolved absolutely
  (`logs/60-e2e/coreutils/report2.json` sample).
* **Exec-time fd inheritance**: recorded as `inherit` ops on
  `execve`/`execveat` (`logs/60-e2e/*/report.json`); in the seccomp
  backend the scan is deferred to the tracee's next notification
  (post-exec fd table, CLOEXEC already applied).
* **Keep-alive exit-status corruption**: a glibc helper that faults
  after a suppressed `exit_group` is observed as status 139 by its
  parent *inside* the tracee tree — the tracer's own reported status is
  fixed (suppressed exit status + explanatory note), but scripted
  workloads must not depend on helper exit codes; the bash workload
  here is builtin-only for that reason (musl binaries loop on `exit`
  and stay clean).
* **The Anylinux shim layer**: these AppImages preload
  `cross-libc-dlopen.so`/`egl-fwd.so` and rewrite library access through
  a `/KEK/` prefix; the report records exactly what the tracee
  requested (`logs/60-e2e/*/report.json`), which is the packager-visible
  truth.
* **uruntime/DwarFS**: the AppImage runtime falls back from FUSE to
  extraction on this host; tracing the extraction storm through seccomp
  notify is minutes-slow, so the experiment extracts once untraced and
  traces the payload (`AppRun`), which is the packaging-relevant target.
* **Environment**: `/tmp` is a 64 MiB tmpfs on the development host;
  a full tmpfs makes *every* writer lose output silently (this bit the
  experiment author once — check `df /tmp` before doubting the tracer).

## The negative result that became a feature

The development host (the operator's agent sandbox) denies `ptrace` via
seccomp, so vanilla strace — every ptrace-based tracer — cannot run
there (`logs/10-ptrace-map.txt` is the evidence). That constraint was
first treated as a limitation, then refuted: the tracee can always
seccomp *itself*, so `senotif_probe.c` proves the ptrace-free primitive
set (experiment 15) and `src/senotif.c` implements it. The host that
could not run any tracer now runs the full validation matrix plus the
end-to-end suite live.

Residual environmental facts, documented where they bite:

* an outer `ERRNO(EPERM)` filter outranks `USER_NOTIF` (kernel action
  precedence), so syscalls the sandbox denies (the ptrace class) are
  invisible to every tracer, including this one — the anti-debug A/B
  (validate.sh T1, T11) skips with an environmental guard there;
* `/proc/<pid>/mem` is readable but not writable on this host — the
  ptrace-mode TracerPid/wchan rewrites are exercised only on normal
  hosts, and the seccomp backend does not need them (TracerPid is
  genuinely 0);
* `validate.sh` still returns exit code 2, not failure, if *no* backend
  can run, so CI can tell "broken" from "cannot run here".

## Conditions

Development host: Linux 6.18 x86_64 (Gentoo), gcc 15.3.0, one machine
(see each log's header for the exact block). E2E artefacts are pinned
by sha256, so the numbers above are reproducible byte-for-byte on any
x86_64 host with network access. Live-trace numbers produced by third
parties on their hosts carry their own conditions in
`logs/50-live-comparison/table.md`.
