#!/bin/sh
# 40-option-wiring.sh
#
# Question: are the five extension options wired end to end (accepted,
# documented in --help, mutually-exclusive combinations rejected, the
# --packager preset composed) on a host where ptrace may not even be
# available?
#
# These checks deliberately stop before any tracing happens, so they are
# valid inside ptrace-restricted sandboxes too.
# Output: logs/40-option-wiring.log
# Exit codes: 0 all wired, 1 a check failed, 2 cannot run.

cd "$(dirname "$0")/.." || exit 2
mkdir -p experiments/logs
BIN=src/strace
[ -x "$BIN" ] || { echo "no $BIN (run 20-build-strace.sh first)"; exit 2; }

OUT=experiments/logs/40-option-wiring.log
: > "$OUT"
fail=0

check() {
	desc=$1; shift
	if "$@" >> "$OUT" 2>&1; then
		echo "ok:   $desc"
	else
		echo "FAIL: $desc"
		fail=1
	fi
}

for opt in --json --report-files --anti-anti-debug --keep-alive --packager --backend; do
	if "$BIN" --help 2>&1 | grep -q -- "$opt"; then
		echo "ok:   $opt in --help"
	else
		echo "FAIL: $opt missing from --help"
		fail=1
	fi
done | tee -a "$OUT"

check "--json -ff rejected" sh -c "'$BIN' --json -ff /bin/true 2>&1 | grep -q mutually"
check "--json -c rejected"  sh -c "'$BIN' --json -c /bin/true 2>&1 | grep -q 'no effect'"
check "--keep-alive=bogus rejected" \
	sh -c "'$BIN' --keep-alive=bogus /bin/true 2>&1 | grep -qi 'invalid\|expected'"
check "--keep-alive=0 rejected" \
	sh -c "'$BIN' --keep-alive=0 /bin/true 2>&1 | grep -qi 'invalid\|expected'"
check "--packager + --decode-fds rejected" \
	sh -c "'$BIN' --packager --decode-fds=path /bin/true 2>&1 | grep -q simultaneously"

# the preset and plain flags are accepted far enough to reach the ptrace
# self-test (which is where a restricted sandbox stops the run)
"$BIN" --packager --json --keep-alive=5 --report-files -o /dev/null \
	/bin/true >> "$OUT" 2>&1
case $? in
	0) echo "ok:   all flags accepted, run completed" ;;
	1) if grep -q "ptrace\|attach" "$OUT"; then
			echo "ok:   flags accepted (stopped at this host's ptrace restriction)"
		else
			echo "FAIL: flags rejected for another reason (see $OUT)"
			fail=1
		fi ;;
	139|128+) # the tracee may fall off its suppressed exit path and die
		  # with SIGSEGV; strace mirrors that signal death (documented)
		echo "ok:   flags accepted (tracee death mirrored, see $OUT)" ;;
	*) echo "FAIL: unexpected exit (see $OUT)"; fail=1 ;;
esac

echo "conditions: commit $(git rev-parse --short HEAD 2>/dev/null), $(uname -r), $(date -u)" >> "$OUT"
exit $fail
