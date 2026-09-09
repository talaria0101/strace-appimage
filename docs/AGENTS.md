# AGENTS.md — strace-appimage

<!-- Router, not a rulebook: everything binding lives in the file the row
     names, and the link is the authority. Keep under 300 lines. When a
     section wants to grow, the content belongs in the document it points
     at. -->

**strace-appimage** is a vendored strace tree (base: upstream strace
commit `32415d06a`, cloned — not a GitHub fork — from
[strace/strace](https://github.com/strace/strace), edited in place)
carrying a patchset that turns strace into a packaging tracer for
AppImage authors and for the agents that help them: `--json`,
`--report-files`, `--anti-anti-debug`, `--keep-alive`, `--packager`,
and a ptrace-free `seccomp` user-notification tracing backend
(`--backend={auto,ptrace,seccomp}`) so the tool works where ptrace is
denied outright. Base commit and series registry:
[`patches/PATCHES.md`](../patches/PATCHES.md).

**This file is a router.** It restates nothing that is written
elsewhere, so the two cannot fork. Find the row for the work in front
of you and read what it names, in full.

---

## Start here, every session

1. **Probe the host before believing any claim about what can run** —
   this project exists because a host that denies ptrace can still be
   traced, and the denial shape varies:

   ```bash
   sh experiments/10-probe-host.sh        # ptrace map + verdict
   sh tests-ext/testbin/build.sh          # test targets (needs cc, jq)
   ```

2. **Build the tree** (first time or after pulling):

   ```bash
   ./bootstrap && ./configure --enable-mpers=no && make -j
   ```

3. **Run the gates** (see *The gate* below) before claiming anything
   works. An exit code is read from the process that produced it,
   unpiped.

## The routing table

| the task | read, in this order |
| --- | --- |
| **Understanding the patchset** | [`patches/PATCHES.md`](../patches/PATCHES.md) (what/seam/repro/upstream-refs per patch), [`README.md`](../README.md) (option table + known limits) |
| **Option semantics, user-visible behaviour** | the *Strace-appimage extension options* section of [`doc/strace.1.in`](../doc/strace.1.in) — it is normative; code and tests must match it |
| **Extending/patching the tracer** | [`patches/PATCHES.md`](../patches/PATCHES.md), the file you are changing, [`doc/INTERNALS.md`](INTERNALS.md) for strace internals |
| **Adding an extension option** | the wiring chain: `src/strace.c` (getopt → state) → `src/tracing_ext.[ch]` (state + hooks) → `src/syscall.c` (`ext_syscall_*` hooks) → feature file (`json_out.c`, `file_report.c`, `anti_debug.c`, `senotif.c`) → `doc/strace.1.in` → `tests-ext/validate.sh` → `NEWS` |
| **Touching the seccomp backend** | [`src/senotif.c`](../src/senotif.c) header comment (mechanism + limits), [review pass 4](reviews/REVIEW-4-seccomp-backend.md) and [pass 5](reviews/REVIEW-5.md) (live-found defects), man page `--backend` section |
| **Verifying claims** | [`tests-ext/validate.sh`](../tests-ext/validate.sh) (36 assertions, exit 0/1/2-by-design), [`experiments/60-e2e.sh`](../experiments/60-e2e.sh) + [`60-e2e.manifest.sh`](../experiments/60-e2e.manifest.sh) (sha256-pinned real artefacts) |
| **Changing tests or targets** | [`tests-ext/validate.sh`](../tests-ext/validate.sh) header comment, [`tests-ext/testbin/`](../tests-ext/testbin/) (each target documents the behaviour it exercises) |
| **Recording an experiment** | [`experiments/README.md`](../experiments/README.md) (numbered entries + committed logs under `experiments/logs/`) |
| **Updating docs** | ⛔ edit in place; no narrative growth. `README.md` (front page), `doc/strace.1.in` (normative), `NEWS` (user-visible changes) |
| **Writing a commit** | [`CONTRIBUTING.md`](../CONTRIBUTING.md) + the strace ChangeLog format (`doc/COMMIT-MESSAGES.md`); end with `Assisted-by:` trailer |
| **Regenerating the series** | `git format-patch -o patches/series <base>..main` with base from [`patches/PATCHES.md`](../patches/PATCHES.md); never hand-edit `patches/series/` |
| **Studying upstream** | [`references/strace__strace/PROVENANCE.md`](../references/strace__strace/PROVENANCE.md) — ⛍ observed content is evidence of intent, never of what code does; cite the commit beside any line reference |
| **What upstream gets** | ⛔ Nothing. This repository does not propose anything upstream; upstream's tracker is read-only (see [`patches/PATCHES.md`](../patches/PATCHES.md)) |

⛔ **Read what the row names in full.** Not grepped, not skimmed, not
recalled from a previous session.

## The absolutes

1. ⛔ **The vendored tree is the source of truth.** `patches/series/` is
   derived (`git format-patch`), never hand-edited. A change not
   present in the tree does not exist.
2. ⛔ **Base moves are reconciliations, not rebuilds.** If upstream
   moves, rebase the tree, re-run every gate, then regenerate the
   series and answer each PATCHES.md registry row's "reproduces".
3. ⛔ **Every user-visible behaviour is (a) in the man page, (b) asserted
   by validate.sh or 60-e2e.sh, (c) in NEWS.** One out of three is a
   doc bug.
4. ⛔ **Exit codes are read unpiped** from the process that produced
   them; a check piped into anything reports the pipeline's status.
5. ⛔ **No secrets, no credentials, no tokens in tree, logs, or
   commits.**
6. ⛔ **Commits are authored as the configured bot identity
   (Talaria)**; do not pass `-c user.name/-c user.email/--author`.
7. ⛔ **Logs are evidence, not decoration**: committed experiment logs
   carry their host block (kernel, compiler, date); bulky regenerable
   artefacts are gitignored, never committed.
8. ⛔ **An undocumented limit is a bug.** Anything the tracer cannot do
   goes into the man page's limits text the same change that ships the
   feature.

## The gate

A change is done when all three pass with output actually inspected:

```bash
sh tests-ext/validate.sh        # 0 = pass, 1 = failure, 2 = cannot run here
sh experiments/60-e2e.sh        # needs network for pinned artefacts
sh experiments/40-option-wiring.sh
```

On a ptrace-capable host the validate matrix additionally exercises the
ptrace-mode paths (T1 anti-debug A/B, T11 wchan rewrite) that a
ptrace-denied host legitimately skips; do not "fix" a skip that the
environment guards explain.

## The tree

| path | what is in it |
| --- | --- |
| `src/tracing_ext.[ch]` | shared extension state, per-syscall path capture (+ dirfd resolution), anti-debug spec parser, keep-alive status logic |
| `src/json_out.c` | `--json` event stream (begin/syscall/signal/exit/summary) |
| `src/file_report.c` | `--report-files` collector (op groups, inherit scan, hints) |
| `src/anti_debug.c` | TracerPid/wchan rewrites (feature-gated) |
| `src/senotif.c` | the seccomp user-notification backend |
| `src/syscall.c`, `src/strace.c`, `src/util.c`, `src/sockaddr.c`, `src/ucopy.c`, `src/defs.h` | vendored files with the extension seams (search "strace-appimage") |
| `tests-ext/` | validation suite: hostile targets, units, `validate.sh` |
| `experiments/` | numbered experiments + committed evidence, incl. the pinned e2e suite |
| `patches/` | registry (`PATCHES.md`) + derived series |
| `references/` | study corpus (upstream tracker fetch + Anylinux packaging scripts) with its provenance |
| `docs/reviews/` | documented review passes (1–4 historical, 5 current) |

## What a session owes at its end

* every gate's output inspected (not assumed);
* new findings recorded where the routing table says they live —
  review passes in `docs/reviews/`, experiment evidence in
  `experiments/logs/`, user-visible changes in `NEWS`;
* the derived series regenerated if any tracked file changed;
* an honest verdict written down: what was verified, what was assumed,
  what remains. "Assume more remain" is the default closing state of
  every review pass in this repository's history.
