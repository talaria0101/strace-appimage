#!/bin/sh
# build.sh -- build the test targets for the validation suite.
#
# Prefers `zig cc` (easy static/cross builds) and falls back to the
# system compiler.  Static glibc builds of dlopen-using programs need
# libdl pieces that are not always available; a static build without
# dlopen support is still produced to exercise static-binary tracing.
#
# Exit codes: 0 built, 1 a build failed, 2 cannot run.
# Part of the strace-appimage validation suite.

set -u
cd "$(dirname "$0")"

CC="${CC:-cc}"
if command -v zig >/dev/null 2>&1; then
	CC="zig cc"
fi

fail=0

build() {
	src=$1; bin=$2; shift 2
	printf 'building %s ... ' "$bin"
	if $CC -O2 -o "$bin" "$src" "$@" 2> "$bin.buildlog"; then
		echo ok
	else
		echo "FAILED (see $bin.buildlog)"
		fail=1
	fi
}

build antidebug_detect.c antidebug_detect
build hard_target.c hard_target -ldl

# static variants: the interesting case LD_DEBUG=libs cannot cover at all
if $CC -static -O2 -o hard_target_static hard_target.c -ldl \
	2> hard_target_static.buildlog; then
	echo "building hard_target_static ... ok"
else
	# static glibc without working dlopen: compile the target with
	# dlopen disabled but keep the rest of the behaviour
	$CC -static -O2 -DNOMKDIR_UNUSED -o hard_target_static \
		hard_target.c 2>> hard_target_static.buildlog \
	|| { echo "static build fallback also failed (see hard_target_static.buildlog)"; fail=1; }
fi

exit $fail
