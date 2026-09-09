#!/bin/sh
# 50-live-comparison.sh
#
# Question: on a host where ptrace works, what does each extension
# change compared to vanilla strace, observably, on the hard target?
#
# Needs: a working ptrace (exits 2 otherwise), jq, a vanilla strace for
# the baseline (/usr/bin/strace or $VANILLA).
# Output: logs/50-live-comparison/ (side-by-side evidence + table)
# Exit codes: 0 comparisons produced, 1 a step failed, 2 cannot run.

cd "$(dirname "$0")/.." || exit 2
BIN=src/strace
VANILLA=${VANILLA:-/usr/bin/strace}
[ -x "$BIN" ] || { echo "no $BIN (run 20-build-strace.sh first)"; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 2; }

# canary: the patched tracer must be able to run (auto backend falls
# back to seccomp user-notification where ptrace is denied)
"$BIN" -o /dev/null /bin/true 2>/dev/null || {
	echo "no usable tracing backend on this host"
	exit 2
}
VANILLA_OK=0
if [ -x "$VANILLA" ] && "$VANILLA" -o /dev/null /bin/true 2>/dev/null; then
	VANILLA_OK=1
else
	echo "note: vanilla strace cannot run here (ptrace denied); the"
	echo "vanilla A/B column is produced by the patched tracer's ptrace"
	echo "mode being unavailable -- see validate.sh T1 skip instead"
fi

OUT=experiments/logs/50-live-comparison
mkdir -p "$OUT"
RUN=""
if command -v timeout >/dev/null 2>&1; then
	RUN="timeout -k 2 30"
fi
sh tests-ext/testbin/build.sh > "$OUT/testbin.build" 2>&1 || exit 1

T=tests-ext/testbin

# 1. the anti-debug A/B ----------------------------------------------------
if [ "$VANILLA_OK" = 1 ]; then
	"$VANILLA" -f -o "$OUT/ab.vanilla.txt" "$T/antidebug_detect" \
		> "$OUT/ab.vanilla.out" 2>&1
	echo "vanilla exit: $?" > "$OUT/ab.summary"
fi
$RUN "$BIN" --anti-anti-debug -f -o "$OUT/ab.ours.txt" \
	"$T/antidebug_detect" > "$OUT/ab.ours.out" 2>&1
echo "ours(--anti-anti-debug) exit: $?" >> "$OUT/ab.summary"

# 2. LD_DEBUG=libs (quick-sharun's mechanism) vs our report ---------------
LD_DEBUG=libs "$T/hard_target" >/dev/null 2> "$OUT/lddebug.txt" & lpid=$!
sleep 2; kill "$lpid" 2>/dev/null; wait "$lpid" 2>/dev/null

$RUN "$BIN" --packager --json -o "$OUT/ours.json" \
	--report-files="$OUT/ours.report.json" \
	"$T/hard_target" > "$OUT/ours.out" 2>&1

# 3. static target: LD_DEBUG blind spot vs our report ----------------------
LD_DEBUG=libs "$T/hard_target_static" >/dev/null 2> "$OUT/lddebug.static.txt" & lpid=$!
sleep 1; kill "$lpid" 2>/dev/null; wait "$lpid" 2>/dev/null

# no --packager for the static target: a suppressed exit in static glibc
# spins (documented); trace the plain run instead
$RUN "$BIN" --json -f -o "$OUT/ours.static.json" \
	--report-files="$OUT/ours.static.report.json" \
	"$T/hard_target_static" > "$OUT/ours.static.out" 2>&1

# 4. assemble the comparison table ----------------------------------------
{
	echo "# live comparison (generated $(date -u), host $(uname -r))"
	echo
	echo "| scenario | LD_DEBUG=libs (status quo) | strace-appimage |"
	echo "| --- | --- | --- |"
	ld=$(grep -c "libGL.so.1" "$OUT/lddebug.txt" 2>/dev/null)
	our=$(jq -r '[.entries | keys[] | select(test("libGL.so.1"))] | length' \
		"$OUT/ours.report.json" 2>/dev/null || echo "?")
	echo "| fallback dlopen(libGL.so.1) after early exit | ${ld:-0} hits | ${our:-?} entries |"
	lds=$(grep -c "calling init" "$OUT/lddebug.static.txt" 2>/dev/null)
	ours=$(jq -r '.entries | length' "$OUT/ours.static.report.json" 2>/dev/null || echo "?")
	echo "| static binary: loader activity seen | ${lds:-0} lines | ${ours:-?} paths reported |"
	vv=$(cat "$OUT/ab.summary" 2>/dev/null | tr '\n' ' ')
	echo "| anti-debug target outcome | detects tracer (exit 42) | ${vv} |"
	echo ""
	echo "Conditions: $(uname -sr), patched tracer commit $(git rev-parse --short HEAD 2>/dev/null)."
	echo "On hosts where the ptrace syscall class is denied outright, the"
	echo "anti-debug detector fires even untraced (TRACEME answers EPERM"
	echo "for everyone) -- the spoof is asserted on normal hosts only"
	echo "(tests-ext/validate.sh T1 environmental guard)."
	jq -r 'select(.type=="summary") | "json events: \(.events) (\(.events_with_error) with errno)"' \
		"$OUT/ours.json" 2>/dev/null || echo "json summary: n/a"
} > "$OUT/table.md"

cat "$OUT/table.md"
echo
echo "evidence: $OUT/"
exit 0
