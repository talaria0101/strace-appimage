# Review pass 2 — behaviour and stream semantics

Scope: what each option *does* to a consumer of its output, walked
option by option, including interactions (`-z/-Z`, `-y/-yy`, `-f`,
`-c`, `-o pipe`, signals, interrupts).

| # | finding | severity | resolution |
| --- | --- | --- | --- |
| 1 | `--json` stream was polluted by classic lines: `--- SIGCHLD ... ---` signal-delivery stops, `+++ exited/killed ... +++`, `+++ superseded by execve +++` all print into `shared_log`, so `jq` over the whole file fails | bug, breaks the primary consumer | fixed: signal stops, exits and kills become JSON events (`type:signal` with `stop`/`core_dumped`, `type:exit` with `code`); the execve-superseded notice is suppressed in json mode |
| 2 | diagnostics (attach notices, errors) still interleave when `--json` output is stderr (no `-o`) | documented | man page: write the stream with `-o FILE` or redirect stderr |
| 3 | `--keep-alive` semantics: after a suppressed `exit_group` returns success, execution continues *after the syscall instruction*; glibc `_exit` ends in `hlt`, which faults | inherent | documented in the man page (it is a diagnostic, not a display emulator); the demo target uses a raw `SYS_exit_group` call whose fall-through is deliberate |
| 4 | spoofing TRACEME changes behaviour for tracees that use it *legitimately* (a debugger under strace now proceeds without its child stopping, instead of getting a clean error) → potential hang instead of error | edge, real | documented in the man page; `tests-ext/validate.sh` wraps every traced run in `timeout -k 2 30` |
| 5 | `-e inject=exit_group` combined with `--keep-alive` double-tampers the same call (inject's retval then overwritten by keep-alive's success) | edge, obscure | accepted (both flags explicitly requested); noted here |
| 6 | report/json note emission respects `-z/-Z` publishing exactly (events and report rows only for published syscalls) | verified | — |
| 7 | `--report-files` default destination is the shared log: text report lands after the classic trace in `-o` files; JSON report becomes the last JSONL line | verified, by design | — |
| 8 | `--packager` conflicts cleanly with `-y` and `--decode-fds` (dies with the upstream-style message) | verified | asserted in `40-option-wiring.sh` |
| 9 | report growth is unbounded (one entry per distinct path) | accepted for PoC (hash is chained, 8192 buckets) | noted |
| 10 | numbers in JSON: `args` are 64-bit unsigned; exact in `jq`/Python, lossy above 2^53 in JavaScript | documented | README note considered sufficient for the audience |

Verdict: after fix 1 the `--json` stream is line-by-line parseable by a
strict parser under all lifecycle events the tracee can produce.
