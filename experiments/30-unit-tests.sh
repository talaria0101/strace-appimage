#!/bin/sh
# 30-unit-tests.sh
#
# Question: do the ptrace-free units of the extensions (the shared JSON
# escaper, the report classifier/collector) pass their unit tests on
# this host?
#
# Delegates to tests-ext/run-unit-tests.sh and keeps the log here.
# Exit codes: 0 passed, 1 failed, 2 cannot run.

cd "$(dirname "$0")/.." || exit 2
mkdir -p experiments/logs

set -o pipefail
sh tests-ext/run-unit-tests.sh 2>&1 | tee experiments/logs/30-unit-tests.log
