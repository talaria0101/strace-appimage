# strace-appimage

`strace` + `LD_DEBUG=libs <app>` + `lib4bin`, in one tracer, for people
who package AppImages — and for the agents that help them.

This is a vendored strace tree (cloned from
[strace/strace](https://github.com/strace/strace) at
`32415d06a`, edited in place; **not** a GitHub fork, so it stays out of
the fork network) carrying a small patchset that adds five options:

| option | replaces | what it does |
| --- | --- | --- |
| `--json` | `strace \| grep/awk` parsing | one self-contained JSON object per line: syscall, args, decoded paths, fd paths, ret + errno name, duration, wall time, notes — plus `begin`/`signal`/`exit`/`summary` events. `jq`-ready |
| `--report-files[=FILE]` | `LD_DEBUG=libs` scraping + `lib4bin` | end-of-run report of every path every tracee touched, with per-operation counts and outcomes; `.so` paths marked as libraries; missing-display/device hints |
| `--anti-anti-debug` | hand-rolled ptrace dodges | `ptrace(PTRACE_TRACEME)` self-checks return success; in ptrace mode `TracerPid` in tracee reads of `/proc/<pid>/status` is rewritten digit-for-digit to zeroes (length- and offset-preserving); in seccomp mode TracerPid is genuinely 0 — there is no tracer link |
| `--keep-alive[=N]` | `sleep N; kill %1` guesswork | suppresses `exit_group` up to N times per process, returning success, so programs that give up early keep going and reveal more calls |
| `--packager` | the `xvfb-run` + `set -m` + env-var dance in packaging scripts | preset: `--follow-forks --decode-fds=all --report-files --keep-alive=3` |
| `--backend={auto,ptrace,seccomp}` | "strace needs ptrace" | `auto` (default) probes ptrace and **falls back to a seccomp user-notification backend** where the ptrace syscall class is denied: the tracee installs the filter on itself and hands the tracer the listener; `/proc/<pid>/mem` supplies memory arguments; open/openat are emulated with `SECCOMP_IOCTL_NOTIF_ADDFD` so their results are real |

Works on static and static-PIE binaries (it reads syscall arguments, not
the dynamic loader), needs no root and no eBPF/capabilities — **if you
can run the binary, you can trace it**, including inside environments
that ban ptrace outright (where plain strace cannot run at all).

```sh
./bootstrap && ./configure --enable-mpers=no && make
./src/strace --packager --json -o trace.jsonl --report-files=files.json ./Your.AppImage
jq -c 'select(.errno!=null)' trace.jsonl          # everything that failed, typed
jq -r '.entries | keys[] | select(test(".so"))' files.json   # libs it wanted
```

A `--json` event looks like:

```json
{"type":"syscall","pid":4242,"syscall":"openat","args":[-100,139867348693408,524288,0,0],"paths":["/usr/lib/libGL.so.1"],"ret":-1,"errno":"ENOENT","dur_us":3,"time":1757337601.123456,"line":"openat(AT_FDCWD, \"/usr/lib/libGL.so.1\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)"}
```

and a `--report-files` entry like:

```json
"entries":{"/usr/lib/libGL.so.1":{"library":true,"first_pid":4242,"ops":{"open":{"n":1,"ok":0,"last_errno":"ENOENT"}}}}
```

Full option documentation is in `doc/strace.1.in` (section
*Strace-appimage extension options*).

## Verify it yourself

Nothing here asks for trust. The whole claim set is executable:

```sh
experiments/10-probe-host.sh        # can this host ptrace at all?
experiments/15-senotif-primitives.sh # the ptrace-free primitives, proven
experiments/20-build-strace.sh      # patched tree builds (-Werror)
experiments/30-unit-tests.sh        # JSON escaper + report collector units
experiments/40-option-wiring.sh     # options wired and validated
tests-ext/validate.sh               # full A/B matrix
experiments/50-live-comparison.sh   # side-by-side evidence, per claim
```

`tests-ext/validate.sh` builds the deliberately hostile targets in
`tests-ext/testbin/` (an anti-debug detector that exits 42 when traced,
an early-exiting display prober with a hidden dlopen fallback path, and
a static variant that `LD_DEBUG=libs` cannot see into at all) and
asserts observable outcomes. Exit codes: 0 passed, 1 failed, 2 *cannot
run here* — never silent.

**These tests were run live, on the development host — a sandbox that
denies ptrace outright** (`experiments/logs/10-ptrace-map.txt`: every
`ptrace` request, including a bogus one, answers `EPERM` before
argument validation; `/proc/<pid>/mem` writes and `process_vm_*` are
denied the same way). Plain strace cannot trace there at all. The
patched tracer does, via the seccomp user-notification backend — the
last run recorded in `experiments/logs/50-live-comparison/table.md`
shows, on that host: `LD_DEBUG=libs` scoring **0 hits** on the
post-early-exit `dlopen("libGL.so.1")` that the report records, **0
lines** of loader activity for the static binary the report covers
(3 paths), and the validation matrix passing **25/25 assertions**
(2 environmental skips documented inline).

On ptrace-capable hosts everything additionally runs through the
classic engine, including the TracerPid rewrite and the vanilla-vs-
patched anti-debug A/B.

## Why these five, in particular

The packaging scripts this targets
([`quick-sharun.sh`](references/quick-sharun.sh) in
pkgforge-dev/Anylinux-AppImages) already do all of this the hard way,
and the file documents the pain in its own words:

| pain in the status quo | handled by |
| --- | --- |
| "`xvfb-run` is used in strace mode to provide a display ... GUI apps will not run without display!" (and hard `sleep 5` when missing) | `--report-files` records what a display-less run attempted *and* emits a `missing_display_or_device` hint; `--keep-alive` pushes past early exits |
| `STRACE_TIME` seconds to run the application, then `_kill_tree` | `--keep-alive[=N]` (bounded, per-process, visible in the trace) |
| `LD_DEBUG=libs` output scraped with `awk '/calling init/{print $NF}'` plus an ever-growing `sed` blacklist | `--report-files` (JSON or text), no post-processing, no blacklist |
| `ELECTRON_DISABLE_SANDBOX`/`WEBKIT_DISABLE_SANDBOX` exported so web apps survive `LD_DEBUG` mode | orthogonal (tracee environment), but the tracer no longer depends on the app surviving a full run to learn its library set |
| `LD_DEBUG` sees nothing for static binaries, nothing outside `ld.so`, nothing after an early exit | syscall-level capture sees all three |
| apps that detect ptrace and quit (upstream issue 227, closed as out of scope for a tracer) | `--anti-anti-debug` |

Upstream's own tracker has the standing asks these options answer:
machine-readable output (issues 169, 166, 51; changesets 228 and 286
were never merged), and anti-debug countermeasures (issue 227). This
tree patches them in place; see `patches/PATCHES.md` for the registry.

## Known limits (read before relying on a feature)

* `--anti-anti-debug` does **not** cover timing checks (`rdtsc` around
  syscalls), `/proc/<pid>/wchan` (reads `ptrace_stop` while stopped), or
  `PTRACE_ATTACH` self-checks (spoofing ATTACH success would hang the
  caller in `wait(2)` forever). Documented in the man page.
* `--keep-alive` returns success from a suppressed `exit_group`; what
  the program does *after* its own exit call is up to the program (glibc
  `_exit` ends in `hlt`, which faults). It reliably extends programs
  that probe-and-retry or call `exit_group` from handled paths; it is a
  diagnostic tool, not a display emulator.
* `--json` is a pragmatic event stream over the existing decoders, not
  the full structured-output driver upstream issue 169 envisions (no
  per-field types for every argument; the classic decoded line ships
  inside each event as `line`).
* `-ff`/`--output-separately` and `-c` are rejected with `--json`.

## About the vendored tree

The upstream strace README is preserved verbatim at
[README-strace.md](README-strace.md); this file is the repository's own
front page.

## Layout

| path | what |
| --- | --- |
| `src/`, `doc/`, `tests/`, ... | the vendored strace tree, patched in place |
| `src/tracing_ext.[ch]`, `src/json_out.c`, `src/file_report.c`, `src/anti_debug.c` | the extension implementation |
| `tests-ext/` | validation suite: hostile test targets, unit tests, `validate.sh` |
| `experiments/` | numbered, re-runnable experiment scripts + committed logs |
| `patches/PATCHES.md` | the patch registry (what/why/repro/upstream refs) and the derived series in `patches/series/` |
| `references/` | the study corpus: strace's tracker (fetched by `mine-repo.sh`, see its `PROVENANCE.md`), `quick-sharun.sh`, the Anylinux README |
| `docs/reviews/` | the three documented review passes |

## Licence

LGPL-2.1-or-later, as strace. The extension files carry the same
licence header. `references/quick-sharun.sh` is kept for study and
remains the property of its authors (see its own header).
