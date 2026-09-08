# experiments

Numbered in the order they were run. The number is the sequence, not a
priority. Every script prints its own conditions and keeps its evidence
in `logs/`; none of them delete their own output.

| # | script | question | status on the development host |
| --- | --- | --- | --- |
| 10 | `10-probe-host.sh` | can this host run ptrace-based tracers, and what exactly denies it? | answered: denied by seccomp (`ERRNO(EPERM)` on the `ptrace` syscall itself, even for a bogus request number, so argument validation is never reached — a filter, not YAMA/LSM) |
| 20 | `20-build-strace.sh` | does the patched vendored tree build cleanly (`-Werror`)? | passed |
| 30 | `30-unit-tests.sh` | do the ptrace-free units (JSON escaper, report collector) pass? | passed |
| 40 | `40-option-wiring.sh` | are the five options wired (help, validation, preset)? | passed |
| 50 | `50-live-comparison.sh` | what does each extension change, observably, vs vanilla? | **not run here** — needs ptrace; run on an unrestricted host |

## The negative result that shaped this repository

The development host (the operator's agent sandbox) denies `ptrace` via
seccomp, so no tracer — vanilla strace included — can run there
(`logs/10-ptrace-map.txt` is the evidence). That constraint is why:

* every claim that needs a live trace is encoded as a script
  (`40-`, `50-`, and `tests-ext/validate.sh`) with assertions, so any
  third party can produce the evidence on an unrestricted host;
* the ptrace-free parts (build, option wiring, unit tests) are what this
  host pins down, and their logs are committed;
* `validate.sh` returns exit code 2, not failure, when it detects the
  restriction, so CI can tell "broken" from "cannot run here".

## Conditions

Development host: Linux 6.18 x86_64, gcc 15.3.0, one machine, one day
(see each log's header for the exact block). Live-trace numbers, once
produced by third parties on their hosts, carry their own conditions in
`logs/50-live-comparison/table.md`.
