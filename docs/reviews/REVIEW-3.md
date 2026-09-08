# Review pass 3 — claims, docs, reproducibility

Scope: README, man page, PATCHES.md, experiments, validate.sh, and the
claim-evidence mapping: can a distrusting third party re-run every
load-bearing claim, and does any doc overstate what was demonstrated
where?

| # | finding | severity | resolution |
| --- | --- | --- | --- |
| 1 | README claimed live A/B outcomes could be produced by anyone, but the development host cannot run them (ptrace denied by seccomp) — the claim needed its conditions attached | honesty of the record | fixed: README's "Verify it yourself" states exactly which layers are pinned on the development host (build, wiring, unit tests, with committed logs) and that the live matrix is third-party-runnable; `experiments/README.md` carries the negative result |
| 2 | `experiments/50-live-comparison.sh` originally duplicated logic now in `tests-ext/validate.sh` | drift risk | 50 stays as the *evidence producer* (markdown table + raw artifacts), validate.sh as the *gate* (assertions); overlap is intentional and both are committed |
| 3 | validate.sh exit code was 0/1/2 but nothing distinguished "live checks not run" from a pass in the summary line | reporting | prints `live checks: NOT RUN` and returns 2; CI can never read silence as success |
| 4 | the man page documented `--keep-alive` returning success but not what happens when the budget exhausts mid-run | doc gap | man page notes the note-field visibility and the post-exit behaviour caveat |
| 5 | PATCHES.md must answer "could a future upstream release retire this patch?" | vendoring rule | registry rows name the upstream issue numbers to watch (169/166/51/228/286/227) and say what to check |
| 6 | `references/` corpus: PROVENANCE.md said "no source was kept" although this repository's own tree is the source | provenance accuracy | PROVENANCE.md amended: the tree read is this repo's vendored copy, at the base commit named in PATCHES.md |
| 7 | upstream README.md was overwritten rather than preserved | attribution | preserved verbatim as README-strace.md; front page links to it |
| 8 | validate.sh grep-based assertions on localized strace messages could break under non-C locales | portability | strace messages are not localized in-tree; accepted |
| 9 | experiments scripts must print conditions and keep evidence | methodology | each log carries uname/date/commit; no script deletes its output |
| 10 | the demo static target's `dlopen` under static glibc prints a dlerror rather than loading | expected (static-glibc dl limitation) | report still records the attempted path — which is exactly what a packager needs; noted in the target's header |

Verdict: every claim now carries either a committed log (ptrace-free
layers) or a committed, asserting script (live layers); nothing in the
docs asserts a live outcome as *observed here*.

Assume more remain.
