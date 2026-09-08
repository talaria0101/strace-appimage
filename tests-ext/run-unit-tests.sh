#!/bin/sh
# run-unit-tests.sh -- compile and run the ptrace-free unit tests of the
# strace-appimage extensions against a configured (built) strace tree.
#
# unit_json_escape includes src/tracing_ext.c as a single translation
# unit (so the escaper is tested directly) and must not also link the
# compiled object; unit_file_report includes src/file_report.c and links
# the compiled tracing_ext object for ext_note_path()/ext_* helpers.
#
# Exit codes: 0 passed, 1 a test failed, 2 cannot run.
# Part of the strace-appimage validation suite.

set -u
cd "$(dirname "$0")"

SRC=../src
[ -f "$SRC/config.h" ] || { echo "no $SRC/config.h: configure the strace tree first"; exit 2; }

CC=${CC:-cc}
CFLAGS="-DHAVE_CONFIG_H -I$SRC -I$SRC/linux/x86_64"
OBJS="$SRC/libstrace_a-xmalloc.o $SRC/libstrace_a-error_prints.o"
fail=0

run() {
	t=$1; objs=$2
	printf '%s: ' "$t"
	# shellcheck disable=SC2086
	if $CC $CFLAGS -o "$t.bin" "$t.c" $objs 2> "$t.buildlog"; then
		if "./$t.bin" > "$t.log" 2>&1; then
			echo PASS
		else
			echo "FAIL (runtime, see $t.log)"
			fail=1
		fi
	else
		echo "FAIL (build, see $t.buildlog)"
		fail=1
	fi
}

run unit_json_escape "$OBJS"
run unit_file_report "$OBJS $SRC/libstrace_a-tracing_ext.o"

exit $fail
