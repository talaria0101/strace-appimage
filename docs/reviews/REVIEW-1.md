# Review pass 1 — code correctness

Scope: every hunk touching upstream files (`git diff` at the time of
the pass) and the new extension files, read line by line against the
upstream mechanisms they hook into (staged output, inject/tamper,
print path, tcb lifecycle).

| # | finding | severity | resolution |
| --- | --- | --- | --- |
| 1 | `--json` fd resolution (`fd`/`fd_path` fields) fired for *any* successful syscall returning a small value with captured paths — a `stat` returning 0 would "resolve fd 0" to strace's own redirected stdin | bug, misleading data | fixed: gated on the decoder's `RVAL_FD` return-format hint (`tcp->sys_func_rval & RVAL_MASK) == RVAL_FD`) |
| 2 | comments and doc strings contained `/proc/*/status`, whose `*/` terminated the enclosing C block comment early; produced "unknown type name 'status'" compile errors | build bug (caught by the build, but a classic) | fixed: `/proc/<pid>/status` wording everywhere |
| 3 | file_report.c had its own hand-rolled JSON escaper next to the one in json_out.c | duplication hazard | fixed: single shared `ext_json_print_string()` in tracing_ext.c, unit-tested |
| 4 | `upoken()` returns `unsigned int`; the rewrite checked `< 0` | wrong error check | fixed: `!= n` |
| 5 | `SEN_pread64` does not exist (`pread64` maps to `SEN_pread` on x86_64) | build bug | fixed |
| 6 | TRACEME spoof and TracerPid rewrite ran even when the syscall-exit result could not be fetched (`res != 1`), i.e. on stale `u_error` | bug, spoof could fire on stale data | fixed: `ext_syscall_exiting_tamper(tcp, res)` gates both on `res == 1`; the keep-alive flag clear stays unconditional so it cannot leak into the next syscall |
| 7 | anti_debug readv iov fetch assumed the native iovec layout | limitation | documented in-code (compat tracees not rewritten) |
| 8 | `printpathn` capture only records absolute paths | limitation (dlopen/ld.so resolution is absolute; relative opens visible in trace, not in report) | documented in the man page |
| 9 | `--json -ff` guard ran before `-ff` set `output_separately`, so it never fired | bug | fixed: guard moved after the followfork block; asserted in `40-option-wiring.sh` |
| 10 | `shared_log` was static in strace.c but needed by the new event emitters | linkage | exported (`FILE *shared_log`, declared in defs.h) — one-word change to upstream |

Verdict: extension code is fit for PoC purpose; findings 1, 6, 9 were
the ones a greenfield rewrite would likely have shipped.
