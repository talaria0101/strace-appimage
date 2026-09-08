#!/bin/sh
# validate.sh -- self-contained validation of the strace-appimage
# extensions.  Designed to need zero trust in the author: it builds and
# runs only what is in this repository, drives both a vanilla strace and
# the patched one, and asserts observable outcomes.
#
# Usage:
#   ./validate.sh [STRACE_BIN] [VANILLA_BIN]
#
#   STRACE_BIN   patched strace (default: ../../src/strace, i.e. an
#                in-tree build; build with ./bootstrap && ./configure
#                && make)
#   VANILLA_BIN  vanilla strace used as the baseline (default:
#                /usr/bin/strace if present)
#
# Requirements: cc, jq.  Exits 0 when all live tests pass, 1 when any
# fails, 2 when the host cannot run the live part (ptrace restricted,
# e.g. inside some sandboxes) -- unit and option checks still run.
#
# Part of the strace-appimage validation suite.
# SPDX-License-Identifier: LGPL-2.1-or-later

set -u
cd "$(dirname "$0")"

ROOT=..
PATCHED=${1:-$ROOT/src/strace}
VANILLA=${2:-/usr/bin/strace}
ART=artifacts
PASS=0; FAIL=0; SKIP=0; NORUN=0

ok()   { PASS=$((PASS+1)); printf 'PASS: %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP: %s\n' "$1"; }

mkdir -p "$ART"

# guard every traced run with a timeout so a hung tracee can never hang
# the validator (see the PTRACE_TRACEME caveat in doc/strace.1.in)
RUN=""
if command -v timeout >/dev/null 2>&1; then
	RUN="timeout -k 2 30"
fi

# --- 0. prerequisites -----------------------------------------------------
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }

if [ ! -x "$PATCHED" ]; then
	echo "patched strace not found at $PATCHED"
	echo "build it first:  ./bootstrap && ./configure --enable-mpers=no && make"
	exit 2
fi
"$PATCHED" --version > "$ART/patched.version" 2>&1
[ -x "$VANILLA" ] && "$VANILLA" --version > "$ART/vanilla.version" 2>&1

# --- 1. build the test targets -------------------------------------------
( cd testbin && ./build.sh ) > "$ART/testbin.build" 2>&1 \
	|| { echo "test targets failed to build:"; cat "$ART/testbin.build"; exit 2; }
for b in testbin/antidebug_detect testbin/hard_target \
	 testbin/hard_target_static; do
	[ -x "$b" ] || { echo "missing $b"; exit 2; }
done

# --- 2. option wiring (works even without ptrace) -------------------------
for opt in --json --report-files --anti-anti-debug --keep-alive --packager; do
	if "$PATCHED" --help 2>&1 | grep -q -- "$opt"; then
		ok "option $opt present in --help"
	else
		bad "option $opt missing from --help"
	fi
done
if "$PATCHED" --json -ff /bin/true 2>&1 | grep -q "mutually.*exclusive"; then
	ok "--json vs -ff rejected"
else
	bad "--json vs -ff not rejected"
fi
if "$PATCHED" --keep-alive=bogus /bin/true 2>&1 | grep -qi "invalid\|expected"; then
	ok "--keep-alive=bogus rejected"
else
	# strace prints 'invalid --keep-alive argument' style message
	bad "--keep-alive=bogus not rejected"
fi

# --- 3. unit tests (ptrace-free) ------------------------------------------
if sh run-unit-tests.sh > "$ART/unit.log" 2>&1; then
	ok "unit tests (json escape, file report)"
else
	bad "unit tests (see $ART/unit.log)"
fi

# --- 4. live tests need ptrace --------------------------------------------
if ! "$PATCHED" -o "$ART/canary.txt" /bin/true 2>"$ART/canary.err"; then
	echo "cannot run live validation on this host (ptrace restricted?):"
	head -3 "$ART/canary.err"
	echo "unit and option checks: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
	echo "live checks: NOT RUN"
	exit 2
fi

# --- T1: anti-anti-debug A/B ----------------------------------------------
if [ -x "$VANILLA" ]; then
	"$VANILLA" -o "$ART/t1.vanilla.txt" ./testbin/antidebug_detect \
		> "$ART/t1.vanilla.out" 2>&1
	vrc=$?
	if [ "$vrc" = 42 ]; then
		ok "T1 vanilla strace is detected by the target (exit 42)"
	else
		bad "T1 vanilla strace NOT detected (exit $vrc)"
	fi
fi
$RUN "$PATCHED" --anti-anti-debug -o "$ART/t1.ours.txt" \
	./testbin/antidebug_detect > "$ART/t1.ours.out" 2>&1
if [ $? = 0 ] && grep -q clean "$ART/t1.ours.out"; then
	ok "T1 --anti-anti-debug defeats both checks (exit 0)"
else
	bad "T1 --anti-anti-debug failed (see $ART/t1.ours.out)"
fi

# --- T2: --json stream -----------------------------------------------------
$RUN "$PATCHED" --json -f -o "$ART/t2.json" ./testbin/hard_target \
	> "$ART/t2.out" 2>&1
if jq -c . "$ART/t2.json" > /dev/null 2>"$ART/t2.jq.err"; then
	ok "T2 every --json line is valid JSON"
else
	bad "T2 invalid JSON lines (see $ART/t2.jq.err)"
fi
jq -e 'select(.type=="begin") | .argv[0] != ""' "$ART/t2.json" \
	> /dev/null 2>&1 && ok "T2 begin event" || bad "T2 begin event"
jq -e 'select(.type=="summary") | .events > 0' "$ART/t2.json" \
	> /dev/null 2>&1 && ok "T2 summary event" || bad "T2 summary event"
jq -e 'select(.syscall=="openat") | select(.paths[0]=="/proc/self/status")' \
	"$ART/t2.json" > /dev/null 2>&1 \
	&& ok "T2 openat event carries /proc/self/status path" \
	|| bad "T2 openat /proc/self/status event"
jq -e 'select(.errno=="ENOENT")' "$ART/t2.json" > /dev/null 2>&1 \
	&& ok "T2 errno names decoded (ENOENT present)" \
	|| bad "T2 errno names missing"
jq -e 'select(.dur_us != null) and (.dur_us >= 0)' "$ART/t2.json" \
	> /dev/null 2>&1 && ok "T2 durations present" || bad "T2 durations"

# --- T3: --report-files ----------------------------------------------------
$RUN "$PATCHED" --json -f --report-files="$ART/t3.report.json" \
	./testbin/hard_target > "$ART/t3.out" 2>&1
jq -e '.entries | has("/bin/true")' "$ART/t3.report.json" \
	> /dev/null 2>&1 && ok "T3 report: child exec of /bin/true" \
	|| bad "T3 report: child exec of /bin/true"
jq -e '.entries | to_entries[] | select(.key | test("libGL.so.1"))' \
	"$ART/t3.report.json" > /dev/null 2>&1 \
	&& ok "T3 report: dlopen-probed libGL.so.1 recorded" \
	|| bad "T3 report: libGL.so.1 not recorded"
jq -e '.hints[] | select(.hint=="missing_display_or_device")' \
	"$ART/t3.report.json" > /dev/null 2>&1 \
	&& ok "T3 report: missing-display hint" || bad "T3 report: hint missing"

# --- T4: --keep-alive reveals the fallback path ----------------------------
$RUN "$PATCHED" --json -f --keep-alive=3 -o "$ART/t4.json" \
	./testbin/hard_target > "$ART/t4.out" 2>&1
jq -e 'select(.notes != null) | select(.notes[] | test("keep-alive"))' \
	"$ART/t4.json" > /dev/null 2>&1 \
	&& ok "T4 keep-alive suppression note in events" \
	|| bad "T4 keep-alive note missing"
grep -q "fallback: dlopen libGL" "$ART/t4.out" \
	&& ok "T4 post-exit fallback path observed" \
	|| bad "T4 fallback path not observed (see $ART/t4.out)"
# contrast: without keep-alive the fallback never runs
$RUN "$PATCHED" -o "$ART/t4b.txt" ./testbin/hard_target > "$ART/t4b.out" 2>&1
grep -q "fallback: dlopen libGL" "$ART/t4b.out" \
	&& bad "T4 control: fallback ran without --keep-alive?!" \
	|| ok "T4 control: no fallback without --keep-alive"

# --- T5: static binary (the LD_DEBUG=libs blind spot) ----------------------
$RUN "$PATCHED" --json --report-files="$ART/t5.report.json" \
	-o "$ART/t5.json" ./testbin/hard_target_static > "$ART/t5.out" 2>&1
jq -e '.entries | length > 5' "$ART/t5.report.json" > /dev/null 2>&1 \
	&& ok "T5 report covers a static binary" \
	|| bad "T5 report empty for static binary"
LD_DEBUG=libs ./testbin/hard_target_static > "$ART/t5.lddebug.out" 2>&1
if grep -q "calling init" "$ART/t5.lddebug.out"; then
	bad "T5 LD_DEBUG unexpectedly worked on static binary"
else
	ok "T5 control: LD_DEBUG=libs sees nothing on a static binary"
fi

# --- T6: --packager preset -------------------------------------------------
$RUN "$PATCHED" --packager -o "$ART/t6.txt" ./testbin/hard_target \
	> "$ART/t6.out" 2>&1 && ok "T6 --packager runs" || bad "T6 --packager"
grep -q "file report" "$ART/t6.txt" && ok "T6 preset includes the report" \
	|| bad "T6 preset missing report"

# --- T7: the quick-sharun scenario (LD_DEBUG=libs vs ours) -----------------
# Run the target the way quick-sharun's "strace mode" does: LD_DEBUG=libs
# with a fixed sleep, then compare against our packager preset.
LD_DEBUG=libs ./testbin/hard_target > /dev/null 2> "$ART/t7.lddebug.txt" &
lpid=$!
sleep 2
	kill "$lpid" 2>/dev/null
	wait "$lpid" 2>/dev/null
if grep -q "libGL.so.1" "$ART/t7.lddebug.txt"; then
	bad "T7 LD_DEBUG saw libGL (should have exited before the dlopen)"
else
	ok "T7 control: LD_DEBUG=libs misses the fallback libs (early exit)"
fi
grep -q "libGL.so.1" "$ART/t6.txt" \
	&& ok "T7 ours (--packager --keep-alive) captures the fallback libs" \
	|| bad "T7 ours misses the fallback libs"

# --- summary ----------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
printf 'artifacts in %s/\n' "$ART"
[ "$FAIL" = 0 ]
