#!/bin/sh
# 20-build-strace.sh
#
# Question: does the vendored strace tree, with the strace-appimage
# patches applied in place, build cleanly (the build uses -Werror) on
# this host?
#
# Inputs pinned: the tree at $(git rev-parse HEAD) of this repository.
# Output: logs/20-build.{bootstrap,configure,make}.log
# Exit codes: 0 built, 1 build failed, 2 cannot run.

cd "$(dirname "$0")/.." || exit 2
mkdir -p experiments/logs

echo "conditions:"
echo "  commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "  host:   $(uname -a)"
echo "  cc:     $(cc --version 2>&1 | head -1)"

./bootstrap       > experiments/logs/20-build.bootstrap.log 2>&1 || {
	echo "bootstrap FAILED"; exit 1; }
./configure --enable-mpers=no \
		     > experiments/logs/20-build.configure.log 2>&1 || {
	echo "configure FAILED"; exit 1; }
if make -j"$(nproc 2>/dev/null || echo 4)" \
		> experiments/logs/20-build.make.log 2>&1; then
	ls -l src/strace
	echo "build OK (see experiments/logs/20-build.make.log)"
	exit 0
fi
echo "make FAILED:"
grep -E "error:|Error" experiments/logs/20-build.make.log | head
exit 1
