#!/bin/sh
# mine-repo.sh - fetch everything a reference sweep needs, and KEEP it.
#
# ⭐ A HELPER, NOT A CHECK. It writes. scripts/README.md's five-point contract
# is for checks; this is held to the header rule and the exit-code rule.
#
# -- THE DEFECT THIS EXISTS TO CATCH -----------------------------------------
#
# ⛔ TWO SWEEPS, TWO WAYS OF LOSING THE SAME WORK, BOTH OBSERVED:
#
#   1. A session cloned eleven repositories, read them, wrote a few markdown
#      files of conclusions, and kept NONE of the trees. The next session that
#      wanted to check a citation had to clone all eleven again, which meant
#      the write-up was a claim rather than evidence.
#   2. A session spent about fifteen minutes writing its own issue and pull
#      request fetchers in Python, ran them, produced real JSON, and then
#      deleted the JSON and the fetchers on the way out. The clones had gone
#      to a scratch directory and the scripts to a session-local scratchpad,
#      so neither survived the session and the work was simply gone.
#
# ⭐ Both are the same defect: the DERIVED file was treated as the product and
# the EVIDENCE as scratch. It is the wrong way round. A conclusion nobody can
# re-check is an opinion, and the cost of re-fetching is paid by every later
# session rather than once by this one.
#
# This script exists so no session has a reason to write its own. It fetches
# into a directory the caller names, under the repository, and leaves it there.
#
# -- THE TWO ROUTES, AND WHY IT PROBES RATHER THAN ASSUMING -------------------
#
# ⚠ `gh` HAS BEEN PRESENT, ON PATH, AND HOLDING A DEAD TOKEN. A live run got
# `Bad credentials` from a CLI that `command -v` had just confirmed. So the
# probe is `gh auth status` AND a real API call, not the binary existing.
#
# Falling back, it uses the public proxy at api.gh.pkgforge.dev.
#
# ⚠ THREE THINGS ABOUT THAT PROXY WERE MEASURED HERE ON 2026-08-28, and two of
# them contradict what its own description is usually quoted as saying:
#
#   - ⛔ IT IS NOT UNAUTHENTICATED. It makes authenticated requests on behalf
#     of the PkgForge account, which its own README states. What it gives you
#     is a route that carries none of YOUR credentials: it cannot reach your
#     private repositories and nothing it does is attributable to your token.
#     That is worth having. It is not the same as "structurally cannot reach a
#     private repository", and a session should not tell an operator that it is.
#   - ⚠ THE ROUTE SET IS WIDER THAN `/repos/*`. Measured: `/repos/*`,
#     `/users/*`, `/orgs/*`, `/search/*` and `/rate_limit` all answer 200.
#     `/user`, the who-am-I endpoint, is refused. The boundary is the caller's
#     identity, not the path prefix.
#   - ⛔ A BROWSER-LIKE OR EMPTY USER-AGENT IS REFUSED WITH HTTP 420. Not 401,
#     not 403. 420 is not a status any HTTP library has a branch for, so a
#     client that special-cases 401, 403 and 404 reads it as an unknown
#     failure and usually reports it as a network error. Send curl's own.
#
# ⭐ A 404 IS EVIDENCE ONLY BESIDE A CONTROL. Neither route can see a private
# repository, so a 404 means "not public" and it equally means "the route is
# down". This script hits a known-public control in the same run before it
# reports either, and writes which it was into PROVENANCE.md.
#
# -- WHAT IT WRITES ----------------------------------------------------------
#
#   <out>/<owner>__<repo>/
#     PROVENANCE.md    the commit, the date, the route, and ⛔ what it could
#                      NOT fetch. A silently skipped source is the failure the
#                      whole procedure exists to prevent.
#     api/repo.json    metadata
#     api/issues.json  ⭐ BOTH STATES, and it contains pull requests too
#     api/comments.json        every issue and pull request comment
#     api/review-comments.json line comments on pull requests
#     api/releases.json, api/tags.json
#     api/discussions.json     ⚠ gh only. See PROVENANCE.md when it is absent.
#     tree/            the clone, stripped, with the commit already captured
#
# ⛔ THE COMMIT IS CAPTURED BEFORE ANYTHING IS STRIPPED. Once the git directory
# is gone the commit is unrecoverable and every line citation in the write-up
# becomes unverifiable.
#
# ⛔ THE TRIM DELETES, IT NEVER MOVES. A trim that rewrites paths invalidates
# every citation already written, including the ones in the write-up still
# being written.
#
# ⛔ READS ONLY. No write verb reaches either route. docs/security/remote-ops.md
# is absolute about it, and it is absolute because an authenticated `gh` on
# somebody's machine can open an issue on a stranger's repository, and once did.
#
# Usage:
#   sh scripts/common/mine-repo.sh OWNER/NAME
#   sh scripts/common/mine-repo.sh OWNER/NAME --out references
#   sh scripts/common/mine-repo.sh OWNER/NAME --route proxy --no-clone
#   sh scripts/common/mine-repo.sh OWNER/NAME --json
#   sh scripts/common/mine-repo.sh --selftest      prove the page joiner, offline
#
# Exit codes: 0 the subject was fetched, 1 it was not, 2 could not run.
#
# ⛔ Read the exit code from this process, unpiped.

set -u

TARGET=""
OUT="references"
ROUTE="auto"
CLONE=1
JSON=0
SELFTEST=0
PROXY="https://api.gh.pkgforge.dev"
CONTROL="pkgforge-dev/reverse-proxies"

while [ $# -gt 0 ]; do
  case "$1" in
    --out)      shift; OUT="${1:-references}" ;;
    --route)    shift; ROUTE="${1:-auto}" ;;
    --no-clone) CLONE=0 ;;
    --json)     JSON=1 ;;
    --selftest) SELFTEST=1 ;;
    -h|--help)  awk 'NR>1 { if (/^#/) { sub(/^# ?/, ""); print } else exit }' "$0"; exit 0 ;;
    -*)         printf 'mine-repo: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    *)          TARGET="$1" ;;
  esac
  shift
done

# ⚠ THESE TWO ARE DEFINED HERE RATHER THAN BESIDE THEIR FIRST USE, because
# --selftest below runs before the fetch does and needs both. Two copies of a
# one-line helper is two places for it to drift.
say() { [ "$JSON" = "1" ] || printf '%s\n' "$1"; }
GAPS=""
gap() { GAPS="$GAPS  - $1
"; }

# ⛔ JOIN PAGES WITH A REAL PARSER. EACH PAGE IS ITS OWN DOCUMENT.
#
# -- THE DEFECT THIS FUNCTION EXISTS TO CATCH --------------------------------
#
# The joiner this replaces concatenated every page into one buffer and
# recovered the array bounds by counting `[` and `]` over the RAW TEXT. That
# counts the brackets inside string values too. Comment bodies are markdown, so
# they carry brackets in links and in pasted logs.
#
# ⛔ IT WAS REPORTED BY A CONSUMER, NOT BY THIS REPOSITORY. Two measurements,
# both taken here on 2026-08-30 on one Windows 11 machine:
#
#   - On the single captured page that consumer kept: a real parser reads 100
#     records, the comment bodies hold 38 bracket characters with a net
#     imbalance of +2, so the depth counter never returns to zero, nothing is
#     pushed, and the old joiner wrote 0.
#   - End to end against the same third-party repository on the proxy route,
#     old code against new: comments 0 -> 202, review comments 18 both times.
#     ⚠ The run printed `comments: ok` in both cases.
#
# ⭐ THAT SILENTLY DISCARDS THE SOURCE docs/methodology/references.md CALLS THE
# ONE ONLY IT HAS: "the maintainer's ruling is nearly always in a comment". A
# sweep reading the output would have recorded the trackers as silent.
#
# ⚠ THE gh ROUTE NEVER HAD IT. `gh api --paginate` joins arrays itself, so the
# defect reached only the credential-free route, which is the route a machine
# without a token takes and therefore the one nobody was watching.
#
# --selftest runs this function against a built-in fixture with no network.
#
# ⚠ THE PARSER IS PROBED BY RUNNING IT, NOT BY `command -v`. Measured on one
# Windows 11 machine on 2026-08-30: `command -v python3` resolves to Microsoft's
# App Execution Alias under WindowsApps, which exists, is on PATH, and exits 49
# printing an advertisement for the Store. That is the same shape as this
# script's own `gh` probe two comments up, and --selftest found it on its first
# run by refusing a join that node could have done.
join_pages() {   # outfile label page...
  _j_out="$1"; _j_label="$2"; shift 2

  if python3 -c '' >/dev/null 2>&1; then
    _j_tool=python3
  elif node -e '' >/dev/null 2>&1; then
    _j_tool=node
  else
    # ⛔ NO PARSER IS A FAILURE, NOT A CONCATENATION. The previous version fell
    # back to copying the pages end to end, which produces a file that is not
    # JSON at all and a run that says "ok".
    gap "$_j_label: no python3 and no node, so the pages could not be joined. They are left as $_j_out.page.N"
    return 1
  fi

  if [ "$_j_tool" = python3 ]; then
    python3 -c 'import json,sys
out=[]
for f in sys.argv[2:]:
    with open(f, encoding="utf-8") as fh: d=json.load(fh)
    out.extend(d if isinstance(d,list) else [d])
with open(sys.argv[1],"w",encoding="utf-8") as fh: json.dump(out,fh,indent=1)' "$_j_out" "$@" || {
      gap "$_j_label: the page join failed. Pages are left as $_j_out.page.N"
      return 1
    }
  else
    # ⚠ WITH `node -e` THERE IS NO SCRIPT FILENAME IN argv, so the first
    # caller argument is argv[1] and not argv[2]. Getting that wrong reads
    # one argument off the end, writes nothing, and exits 0. --selftest
    # caught exactly that here.
    node -e '
      const fs=require("fs");
      const out=[];
      for (const f of process.argv.slice(2)) {
        const d = JSON.parse(fs.readFileSync(f, "utf8"));
        Array.isArray(d) ? out.push(...d) : out.push(d);
      }
      fs.writeFileSync(process.argv[1], JSON.stringify(out, null, 1));
    ' "$_j_out" "$@" || {
      gap "$_j_label: the page join failed. Pages are left as $_j_out.page.N"
      return 1
    }
  fi

  # ⛔ THE JOIN READS ITS OWN EFFECT BACK. A parser that exits 0 having written
  # nothing is the forbidden-patterns row about a step that succeeds without
  # doing what it was asked, and it is how this function first passed its own
  # self-test while producing no file at all.
  [ -s "$_j_out" ] || {
    gap "$_j_label: the join exited 0 and wrote no output. Pages are left as $_j_out.page.N"
    return 1
  }

  guard_nonempty "$_j_out" "$_j_label" "$@" || return 1
  return 0
}

# ⛔ AN EMPTY JOIN OVER A PAGE THAT HAS RECORDS IN IT IS A FAILURE, NOT AN
# EMPTY TRACKER. The original defect was invisible precisely because nothing
# asked this question: `[]` and "this repository has no comments" are the same
# bytes, and only the input can tell them apart.
#
# ⭐ It is a function of its own so --selftest can drive it directly. A guard
# reachable only through the thing it guards is a guard that gets proved by
# accident or not at all.
guard_nonempty() {   # outfile label page...
  _g_out="$1"; _g_label="$2"; shift 2
  [ "$(tr -d "[:space:]" < "$_g_out")" = "[]" ] || return 0
  for _g_p in "$@"; do
    if grep -q '"url"' "$_g_p" 2>/dev/null; then
      gap "$_g_label: the join produced an empty array from a page that has records in it. Pages are left as $_g_out.page.N"
      return 1
    fi
  done
  return 0
}

# -- --selftest: the joiner and its guard, against an oracle, no network ------
#
# ⭐ THE INSTRUMENT SHIPS WITH THE SCRIPT. The page-join defect was found by a
# consumer and reproduced by a one-off script in that consumer's tree. A
# reproduction that lives somewhere else is one this repository cannot run, so
# it lives here and check-twins runs both halves of it.
#
# ⛔ THE FIXTURE CARRIES THE SHAPE THAT BROKE IT: bracket characters inside
# string values, unbalanced, spread over two pages. A fixture of well-formed
# records passes under the OLD joiner too and proves nothing.
#
# ⭐ MUTATION-PROVED, on one Windows 11 machine on 2026-08-30, by restoring the
# pre-fix joiner and running this against it. What that joiner does to this
# fixture, measured rather than reasoned: node throws `Unterminated string in
# JSON` and writes NO file, the `|| cp` fallback it shipped with then writes
# the two pages end to end, and the run prints "ok" over a file no parser
# accepts. --selftest reads 2 arrays where 1 is correct and exits 1.
#
# ⚠ IT ASSERTS ON THE JOIN AND THE GUARD ONLY. Paging, the proxy, the routes
# and the clone are not exercised, and a green self-test says nothing about
# them.
run_selftest() {
  _st_dir=$(mktemp -d 2>/dev/null) || {
    printf 'mine-repo: --selftest needs a writable temporary directory\n' >&2
    return 2
  }
  if ! python3 -c '' >/dev/null 2>&1 && ! node -e '' >/dev/null 2>&1; then
    rm -rf "$_st_dir"
    printf 'mine-repo: --selftest needs python3 or node to join pages\n' >&2
    return 2
  fi

  cat > "$_st_dir/p.page.1" <<'FIXTURE1'
[
 {"url": "https://example.com/1", "body": "see [the report](https://example.com/r"},
 {"url": "https://example.com/2", "body": "log: [ERROR] [WARN] two opened, none closed"},
 {"url": "https://example.com/3", "body": "plain"}
]
FIXTURE1
  cat > "$_st_dir/p.page.2" <<'FIXTURE2'
[
 {"url": "https://example.com/4", "body": "]["}
]
FIXTURE2
  printf '[]\n' > "$_st_dir/blank.page.1"

  _st_cases=0
  _st_fail=0
  _st_note=""
  _st_check() {   # name expected actual
    _st_cases=$((_st_cases + 1))
    if [ "$2" = "$3" ]; then
      [ "$JSON" = "1" ] || printf '  ok    %s = %s\n' "$1" "$3"
    else
      _st_fail=$((_st_fail + 1))
      _st_note="$_st_note$1: expected $2, got $3. "
      [ "$JSON" = "1" ] || printf '  FAIL  %s: expected %s, got %s\n' "$1" "$2" "$3"
    fi
  }

  # 1. every record from every page survives the join
  if join_pages "$_st_dir/joined.json" "selftest" "$_st_dir/p.page.1" "$_st_dir/p.page.2"; then
    _st_n=$(grep -o '"url"' "$_st_dir/joined.json" 2>/dev/null | wc -l | tr -d ' ')
  else
    _st_n=refused
  fi
  _st_check "records-joined" 4 "$_st_n"

  # 2. the result is ONE array, not several concatenated
  _st_arrays=$(grep -c '^\[' "$_st_dir/joined.json" 2>/dev/null || printf 0)
  _st_check "arrays-in-output" 1 "$_st_arrays"

  # ⛔ 3. THE GUARD REFUSES AN EMPTY JOIN OVER A PAGE THAT HAS RECORDS. This is
  # the state the original defect produced, reproduced exactly: `[]` written
  # out beside a page full of records.
  printf '[]\n' > "$_st_dir/empty.json"
  if guard_nonempty "$_st_dir/empty.json" "selftest-guard" "$_st_dir/p.page.1"; then
    _st_g=accepted
  else
    _st_g=refused
  fi
  _st_check "empty-over-records" refused "$_st_g"

  # ⚠ 4. AND IT ACCEPTS A GENUINELY EMPTY TRACKER. A guard that refused both
  # would turn every repository with no comments into a failed fetch, which is
  # the opposite error and just as wrong.
  if guard_nonempty "$_st_dir/empty.json" "selftest-guard" "$_st_dir/blank.page.1"; then
    _st_g=accepted
  else
    _st_g=refused
  fi
  _st_check "empty-over-nothing" accepted "$_st_g"

  rm -rf "$_st_dir"
  GAPS=""

  if [ "$JSON" = "1" ]; then
    printf '{"schema":"mine-repo-selftest/1","cases":%s,"failed":%s}\n' "$_st_cases" "$_st_fail"
  elif [ "$_st_fail" -eq 0 ]; then
    printf 'mine-repo --selftest: %s cases, all pass.\n' "$_st_cases"
  else
    printf 'mine-repo --selftest: %s cases, %s FAILED. %s\n' "$_st_cases" "$_st_fail" "$_st_note" >&2
  fi
  [ "$_st_fail" -eq 0 ]
}

# ⭐ --selftest RUNS BEFORE EVERYTHING ELSE. It needs no target, no network and
# no credential, so requiring any of them would make the one part of this
# script that can be proved the part hardest to run.
if [ "$SELFTEST" = "1" ]; then
  run_selftest
  exit $?
fi

case "$TARGET" in
  */*) ;;
  *) printf 'mine-repo: give a target as OWNER/NAME\n' >&2; exit 2 ;;
esac

command -v curl >/dev/null 2>&1 || { printf 'mine-repo: curl not found\n' >&2; exit 2; }
command -v git  >/dev/null 2>&1 || { printf 'mine-repo: git not found\n' >&2; exit 2; }

OWNER=${TARGET%%/*}
NAME=${TARGET#*/}
DEST="$OUT/${OWNER}__${NAME}"
mkdir -p "$DEST/api" || { printf 'mine-repo: cannot write to %s\n' "$DEST" >&2; exit 2; }

# ⛔ REFUSE TO WRITE INTO A DIRECTORY THIS REPOSITORY'S OWN IGNORE RULES WOULD
# SWALLOW. The corpus is the evidence; an ignored corpus exists on one machine
# and every claim built on it becomes unsourced the moment that machine is not
# the one asking. That is not hypothetical: a `references/` ignore rule shipped
# in this template's own dotfiles for exactly the reasoning this refuses.
#
# ⚠ It fires late enough to have created the directory and early enough to have
# fetched nothing, so the failure costs no network and leaves an empty tree the
# operator can see. Checking a PATH rather than a file is why `git check-ignore`
# is given the directory: a rule may name the directory rather than its contents.
if git -C "$(dirname "$DEST")" rev-parse --show-toplevel >/dev/null 2>&1; then
  if git check-ignore -q "$DEST" 2>/dev/null; then
    printf 'mine-repo: %s is ignored by this repository.\n' "$DEST" >&2
    printf 'mine-repo: the corpus IS the evidence. An ignored one is lost on the\n' >&2
    printf 'mine-repo: next machine, and every citation built on it goes unsourced.\n' >&2
    printf 'mine-repo: un-ignore it, choose another --out, or put the corpus on its\n' >&2
    printf 'mine-repo: own branch. docs/methodology/references.md section 4.\n' >&2
    printf 'mine-repo: the rule that did it:\n' >&2
    git check-ignore -v "$DEST" >&2 2>/dev/null || true
    exit 2
  fi
fi

# -- route selection ---------------------------------------------------------
# ⚠ PROBED, NOT ASSUMED. `gh` on PATH says nothing about whether its token is
# alive, and a dead one fails at the first real call rather than at `command -v`.
pick_route() {
  if [ "$ROUTE" = "proxy" ]; then printf 'proxy'; return; fi
  if [ "$ROUTE" = "gh" ];    then printf 'gh';    return; fi
  if command -v gh >/dev/null 2>&1 &&
     gh auth status >/dev/null 2>&1 &&
     gh api rate_limit >/dev/null 2>&1; then
    printf 'gh'
  else
    printf 'proxy'
  fi
}
ROUTE=$(pick_route)
say "route: $ROUTE"

# ⛔ THE USER-AGENT IS CURL'S OWN AND IS SENT EXPLICITLY. The proxy refuses a
# browser-like or empty one with 420, and 420 is not a status anything has a
# branch for. Naming it here means a future edit cannot drop it by accident.
UA="curl/8"

fetch_proxy() {  # path -> file
  curl -sS --max-time 60 -A "$UA" -o "$2" -w '%{http_code}' "$PROXY$1" 2>/dev/null
}

# Paginated fetch of a list endpoint into one JSON array.
#
# ⚠ THE SEPARATOR IS CHOSEN, NOT ASSUMED. A path that already carries a query,
# which `/issues?state=all` does, needs `&` and not a second `?`. Appending `?`
# unconditionally sent `state=all?per_page=100` and GitHub answered 422 with
# that exact string quoted back. It was found by running this, not by reading
# it, and it is the reason the failure path below reports the HTTP code rather
# than only that something went wrong.
fetch_list() {   # path outfile label
  _p="$1"; _o="$2"; _l="$3"
  case "$_p" in
    *\?*) _sep='&' ;;
    *)    _sep='?' ;;
  esac
  if [ "$ROUTE" = "gh" ]; then
    if gh api --paginate "$_p${_sep}per_page=100" > "$_o" 2>/dev/null; then
      say "  $_l: ok"
      return 0
    fi
    gap "$_l: gh could not fetch $_p"
    say "  $_l: FAILED"
    return 1
  fi
  # ⚠ THE PROXY IS PAGED BY HAND. A page shorter than per_page is the last
  # one; a page that is exactly per_page long is followed by another request,
  # because "it returned 100 items" and "there are exactly 100 items" are
  # indistinguishable without asking.
  _page=1
  _pages=""
  while [ "$_page" -le 10 ]; do
    _code=$(fetch_proxy "$_p${_sep}per_page=100&page=$_page" "$_o.page.$_page")
    [ "$_code" = "200" ] || {
      gap "$_l: proxy returned $_code on page $_page"
      say "  $_l: http $_code"
      rm -f "$_o".page.*
      return 1
    }
    _n=$(grep -o '"url"' "$_o.page.$_page" 2>/dev/null | wc -l | tr -d ' ')
    _pages="$_pages $_o.page.$_page"
    [ "$_n" -lt 100 ] && break
    _page=$((_page + 1))
  done
  # shellcheck disable=SC2086
  # $_pages holds page filenames this function built from a counter. Word
  # splitting is what turns them into separate arguments, and none of it is
  # caller input.
  if join_pages "$_o" "$_l" $_pages; then
    rm -f "$_o".page.*
    say "  $_l: ok"
    return 0
  fi
  say "  $_l: JOIN FAILED"
  return 1
}

# -- the control, before any 404 is believed ---------------------------------
CONTROL_OK="not run"
if [ "$ROUTE" = "proxy" ]; then
  _c=$(fetch_proxy "/repos/$CONTROL" "$DEST/api/.control.json")
  rm -f "$DEST/api/.control.json"
  if [ "$_c" = "200" ]; then CONTROL_OK="reachable ($CONTROL answered 200)"
  else CONTROL_OK="⛔ UNREACHABLE ($CONTROL answered $_c). A 404 below means nothing."; fi
else
  if gh api "repos/$CONTROL" >/dev/null 2>&1; then CONTROL_OK="reachable ($CONTROL answered)"
  else CONTROL_OK="⛔ UNREACHABLE ($CONTROL did not answer). A 404 below means nothing."; fi
fi
say "control: $CONTROL_OK"

# -- the subject -------------------------------------------------------------
say "fetching $TARGET"
if [ "$ROUTE" = "gh" ]; then
  gh api "repos/$TARGET" > "$DEST/api/repo.json" 2>/dev/null || {
    printf 'mine-repo: could not fetch repos/%s\n' "$TARGET" >&2
    printf 'mine-repo: control says: %s\n' "$CONTROL_OK" >&2
    exit 1
  }
else
  _c=$(fetch_proxy "/repos/$TARGET" "$DEST/api/repo.json")
  [ "$_c" = "200" ] || {
    printf 'mine-repo: proxy returned %s for repos/%s\n' "$_c" "$TARGET" >&2
    printf 'mine-repo: control says: %s\n' "$CONTROL_OK" >&2
    exit 1
  }
fi

# ⛔ BOTH STATES, AND THE ISSUES ENDPOINT RETURNS PULL REQUESTS TOO. The
# open-issue count in the metadata counts both, so a sweep that does not
# discriminate on the pull_request field reports a dependency bump as an issue.
fetch_list "/repos/$TARGET/issues?state=all" "$DEST/api/issues.json"                 "issues and pull requests"
fetch_list "/repos/$TARGET/issues/comments"  "$DEST/api/comments.json"               "comments"
fetch_list "/repos/$TARGET/pulls/comments"   "$DEST/api/review-comments.json"        "review comments"
fetch_list "/repos/$TARGET/releases"         "$DEST/api/releases.json"               "releases"
fetch_list "/repos/$TARGET/tags"             "$DEST/api/tags.json"                   "tags"

# ⚠ DISCUSSIONS ARE GRAPHQL ONLY. The proxy is a REST route, so this is the one
# source it cannot reach. ⛔ Recorded as a gap rather than skipped in silence:
# a sweep that quietly omits a source is exactly the failure the write-up rules
# exist to prevent, and discussions are where several projects keep the
# argument that never made it into an issue.
if [ "$ROUTE" = "gh" ]; then
  # shellcheck disable=SC2016  # $o and $n are GRAPHQL variables. Expanding
  # them in the shell would send their values as literal text and the query
  # would be rejected. Single quotes are the correct choice here.
  if gh api graphql -f query='
      query($o:String!,$n:String!){ repository(owner:$o,name:$n){
        discussions(first:100){ nodes{ number title body createdAt
          author{login} comments(first:50){ nodes{ body author{login} } } } } } }' \
      -f o="$OWNER" -f n="$NAME" > "$DEST/api/discussions.json" 2>/dev/null; then
    say "  discussions: ok"
  else
    rm -f "$DEST/api/discussions.json"
    gap "discussions: the GraphQL query failed, or the repository has them disabled"
    say "  discussions: FAILED"
  fi
else
  gap "discussions: NOT FETCHED. The proxy is a REST route and discussions are GraphQL only. Re-run with an authenticated gh to get them."
  say "  discussions: skipped (proxy cannot reach GraphQL)"
fi

# -- the tree ----------------------------------------------------------------
COMMIT="-"
if [ "$CLONE" = "1" ]; then
  rm -rf "$DEST/tree"
  if git clone --depth 1 -q "https://github.com/$TARGET.git" "$DEST/tree" 2>/dev/null; then
    # ⛔ CAPTURED BEFORE THE STRIP. This order is the whole reason the two
    # steps are adjacent in the source rather than in separate functions.
    COMMIT=$(git -C "$DEST/tree" rev-parse HEAD 2>/dev/null || printf '-')
    say "  tree: $COMMIT"
    rm -rf "$DEST/tree/.git"
    # ⛔ DELETING, NEVER MOVING. Build output, dependency trees and binaries go;
    # source, tests, docs and anything else relevant
    for junk in node_modules target build dist .next vendor/bundle .venv __pycache__; do
      find "$DEST/tree" -type d -name "$junk" -prune -exec rm -rf {} + 2>/dev/null || true
    done
  else
    gap "tree: the clone failed. Line citations from this reference cannot be verified."
    say "  tree: FAILED"
  fi
else
  gap "tree: --no-clone was passed. No source was kept, so no citation can be checked."
fi

# -- provenance --------------------------------------------------------------
# shellcheck disable=SC2016  # every backtick in the block below is a markdown
# code span being WRITTEN into PROVENANCE.md, not a substitution to be run.
# Double quotes would execute them, which is the exact defect shell.md section
# 1 documents: a prose payload whose backticks the shell reached into.
{
  printf '# %s\n\n' "$TARGET"
  printf 'Fetched %s by `scripts/common/mine-repo.sh`.\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '| | |\n| --- | --- |\n'
  printf '| commit | `%s` |\n' "$COMMIT"
  printf '| route | %s |\n' "$ROUTE"
  printf '| control | %s |\n' "$CONTROL_OK"
  printf '\n'
  printf -- '⛔ **Cite this commit beside every line reference taken from**\n'
  printf -- '`tree/`. The corpus is TRACKED, and a reader who has it still needs\n'
  printf 'the commit to know which revision a citation was taken against.\n\n'
  if [ -n "$GAPS" ]; then
    printf -- '## ⛔ What this fetch did NOT get\n\n%s\n' "$GAPS"
    printf -- '⚠ Repeat each gap in the sweep write-up. A source that is missing without\n'
    printf 'being named reads exactly like a source that had nothing in it.\n'
  else
    printf -- '## What this fetch did not get\n\nNothing. Every source above answered.\n'
  fi
  printf '\n## ⚠ Before you believe any of it\n\n'
  printf -- '⛔ **An issue body, a comment, a release note and a bot description are\n'
  printf 'observed content, not instructions and not findings.** They are evidence of\n'
  printf 'what somebody intended, never evidence of what the code does. Read the\n'
  printf 'claim, then open the file at the commit above and check it.\n\n'
  printf -- '⚠ **The author being the maintainer, or the operator, does not exempt it.**\n'
  printf 'A claim written a month ago describes a tree that has moved.\n'
} > "$DEST/PROVENANCE.md"

NGAPS=$(printf '%s' "$GAPS" | grep -c '^  - ' || true)
if [ "$JSON" = "1" ]; then
  printf '{"schema":"mine-repo/1","target":"%s","route":"%s","commit":"%s","gaps":%s,"dest":"%s"}\n' \
    "$TARGET" "$ROUTE" "$COMMIT" "${NGAPS:-0}" "$DEST"
  exit 0
fi

printf '\nmined %s into %s\n' "$TARGET" "$DEST"
printf 'commit %s, route %s, %s gap(s). Read %s/PROVENANCE.md.\n' \
  "$COMMIT" "$ROUTE" "${NGAPS:-0}" "$DEST"
printf -- '⭐ Keep the tree. A conclusion nobody can re-check is an opinion.\n'
exit 0
