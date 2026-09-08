# patches/ — the strace-appimage patch series

The vendored strace tree in this repository **is** the source of truth
(edited in place). This directory holds only what a working tree cannot
say: the derived series for review and attribution, regenerated with:

```sh
git format-patch -o patches/series <base>..main
```

Base (upstream strace commit the series applies to):

```
32415d06a00d984f187ef90f7da0146d2401b970
```

Upstream repository: https://github.com/strace/strace (cloned, not a
GitHub fork, so this repository does not appear in the fork network).
Nothing here is proposed upstream; upstream's tracker is used read-only.

## Registry

| patch | what it is | the seam it needs | reproduces | upstream refs (bare) |
| --- | --- | --- | --- | --- |
| `0001-add-tracing-extensions` | `--json`, `--report-files`, `--anti-anti-debug`, `--keep-alive`, `--packager`: five packager-facing options built on a small per-tcb capture state (`struct tcb` extension fields), the staged-output memstream (already used by `-z`/`-Z`), the print_fields print path (`printpathn`, `print_sockaddr_data_un`), and the tamper machinery (`set_scno(-1)` skip + `set_success`) already exercised by `-e inject=` | none of these seams are exposed by a published interface (no plugin/output-driver API exists), so the change cannot live outside the tree | `experiments/40-option-wiring.sh` (wiring) and `tests-ext/validate.sh` (behaviour, needs ptrace); both self-asserting | 169, 166, 51 (structured/machine-readable output asks); 228, 286 (prior changesets, unmerged); 227 (anti-debug detection) |
| `0002-tests-and-experiments` | the self-contained validation suite (`tests-ext/`), the experiment scripts (`experiments/`), and the reference corpus (`references/`) | n/a (repository-side) | `experiments/README.md` | — |

Could a future upstream release retire a patch? Only 0001's components
could be, individually, if upstream merged a structured-output driver
(169/286) or an anti-debug mode; the registry rows above name the
numbers to check in each release's changelog. Until then, both patches
exist because this project needs them.

## Rules for changing this directory

* never edit files in `series/` by hand — regenerate them;
* every new patch gets a registry row: what, seam, reproduction,
  upstream references as bare numbers;
* a superseded patch stays in `series/` (history) until the base moves,
  then the reconciliation question is answered per row.
