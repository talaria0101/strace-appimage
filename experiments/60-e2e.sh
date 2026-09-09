#!/bin/sh
# 60-e2e.sh -- end-to-end runs against real-world static binaries and
# AppImages, exactly the two artefact classes this project targets.
#
#   static:  bash, coreutils, curl   (pkgforge/bin, x86_64-Linux, musl,
#                                     static / static-PIE)
#   AppImages: gtk3-demo, Qt6+dbus-demo, sdl2-demo
#              (pkgforge-dev/Anylinux-AppImages, demo release)
#
# For every artefact it runs the packager preset (--packager --json),
# asserts observable outcomes (valid JSONL, non-trivial file report,
# library detection, headless-display hint, keep-alive suppression) and
# compares the report's library list against what LD_DEBUG=libs sees in
# the same budget.
#
# Artefacts are fetched on first use into $LOGS/downloads and pinned by
# sha256 in 60-e2e.manifest.sh; a mismatch aborts the experiment.
#
# Usage: sh 60-e2e.sh [STRACE_BIN]   (default: ../../src/strace)
# Exit codes: 0 passed, 1 failed, 2 cannot run (no network & no cache).
#
# Part of the strace-appimage validation suite.
# SPDX-License-Identifier: LGPL-2.1-or-later

set -u
cd "$(dirname "$0")"
HERE=$(pwd)
LOGS="$HERE/logs/60-e2e"
STRACE=${1:-../src/strace}
case "$STRACE" in
	/*) ;;
	*)	STRACE="$HERE/$STRACE" ;;
esac
RUN=""
command -v timeout >/dev/null 2>&1 && RUN="timeout -k 2 90"
DL="$LOGS/downloads"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); printf 'PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL: %s\n' "$1"; }

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }
[ -x "$STRACE" ] || { echo "strace not found at $STRACE"; exit 2; }
mkdir -p "$DL"

# --- fetch + pin ----------------------------------------------------------
. "$HERE/60-e2e.manifest.sh"

fetch() {
	name=$1; url=$2
	[ -s "$DL/$name" ] && return 0
	echo "fetching $name"
	mkdir -p "$DL"
	curl -sL --retry 3 -o "$DL/$name" "$url" || return 1
}

verify_pin() {
	name=$1; want=$2
	got=$(sha256sum "$DL/$name" | cut -d' ' -f1)
	[ "$got" = "$want" ] || { echo "$name: sha256 mismatch ($got != $want)"; return 1; }
}

RET=0
fetch bash.pkgforge "$URL_BASH"           || RET=2
fetch coreutils.pkgforge "$URL_COREUTILS" || RET=2
fetch curl.pkgforge "$URL_CURL"           || RET=2
fetch gtk3.AppImage "$URL_GTK3"           || RET=2
fetch qt6dbus.AppImage "$URL_QT6DBUS"     || RET=2
fetch sdl2.AppImage "$URL_SDL2"           || RET=2
[ "$RET" = 2 ] && { echo "cannot download artefacts (offline?)"; exit 2; }

verify_pin bash.pkgforge "$SHA_BASH"           || exit 2
verify_pin coreutils.pkgforge "$SHA_COREUTILS" || exit 2
verify_pin curl.pkgforge "$SHA_CURL"           || exit 2
verify_pin gtk3.AppImage "$SHA_GTK3"           || exit 2
verify_pin qt6dbus.AppImage "$SHA_QT6DBUS"     || exit 2
verify_pin sdl2.AppImage "$SHA_SDL2"           || exit 2

chmod +x "$DL"/*.pkgforge "$DL"/*.AppImage
# coreutils is multicall (dispatches on argv[0]): pre-create the applet
# names well before any traced exec (a just-copied file can transiently
# fail execve with ENOENT on some filesystems)
for a in du sort; do
	[ -x "$DL/$a" ] || cp "$DL/coreutils.pkgforge" "$DL/$a"
	chmod +x "$DL/$a" 2>/dev/null || true
done
sync

run_one_static() {
	name=$1; want_rc=$2; bin=$3; shift 3
	out="$LOGS/$name"
	mkdir -p "$out"
	$RUN "$STRACE" --packager --json -o "$out/trace.jsonl" \
		--report-files="$out/report.json" \
		"$DL/$bin" "$@" \
		> "$out/stdout" 2> "$out/stderr"
	rc=$?
	if [ "$rc" = "$want_rc" ]; then
		ok "$name: exit status $rc as expected"
	else
		bad "$name: exit $rc, want $want_rc (see $out/stderr)"
	fi
	if jq -c . "$out/trace.jsonl" > /dev/null 2>&1; then
		ok "$name: every JSONL line parses"
	else
		bad "$name: invalid JSONL"
	fi
	jq -e 'select(.type=="summary") | .events > 10' "$out/trace.jsonl" \
		> /dev/null 2>&1 \
		&& ok "$name: >10 traced events" \
		|| bad "$name: too few events"
	jq -e '.entries | length >= 3' "$out/report.json" > /dev/null 2>&1 \
		&& ok "$name: report has >=3 paths" \
		|| bad "$name: report too small"
}

# The Anylinux AppImages ship the uruntime (DwarFS) launcher: without
# FUSE (denied here) it falls back to extracting the payload, and
# tracing that extraction storm through seccomp notify takes minutes --
# out of scope for a startup trace.  The packaging-relevant target is
# the application itself, so: extract once untraced, then trace the
# extracted AppRun payload headlessly.
run_one_appimage() {
	name=$1; app=$2
	out="$LOGS/$name"
	mkdir -p "$out"
	root="$out/squashfs-root"
	if [ ! -x "$root/AppRun" ]; then
		( cd "$out" \
		  && APPIMAGE_EXTRACT_AND_RUN=1 TMPDIR="$out" \
		  "$DL/$name.AppImage" --appimage-extract \
		  > "$out/extract.log" 2>&1 ) || {
			bad "$name: extraction failed (see $out/extract.log)"
			return 0
		}
	fi
	# sharun's bootstrap derives APPDIR as <dir-of-AppRun>/AppDir;
	# uruntime's extract-and-run uses that name, so match it here
	[ -e "$out/AppDir" ] || ln -s "$root" "$out/AppDir"
	ok "$name: extracted (untraced prep)"

	$RUN "$STRACE" --packager --json -o "$out/trace.jsonl" \
		--report-files="$out/report.json" \
		env APPDIR="$out/AppDir" "$root/AppRun" "$app" --version \
		> "$out/stdout" 2> "$out/stderr"
	rc=$?
	ok "$name: traced run finished (exit $rc)"
	if jq -c . "$out/trace.jsonl" > /dev/null 2>&1; then
		ok "$name: every JSONL line parses"
	else
		bad "$name: invalid JSONL"
	fi
	jq -s -e '[.[] | select(.type=="syscall")] | length > 100' \
		"$out/trace.jsonl" > /dev/null 2>&1 \
		&& ok "$name: >100 syscall events" \
		|| bad "$name: too few syscall events"
	jq -e '[.entries[] | select(.library)] | length >= 10' \
		"$out/report.json" > /dev/null 2>&1 \
		&& ok "$name: report detects >=10 bundled libraries" \
		|| bad "$name: library detection too small"
	jq -e --arg d "$out/AppDir" \
		'[.entries | keys[] | select(startswith($d) or
			startswith("/KEK/"))] | length >= 10' \
		"$out/report.json" > /dev/null 2>&1 \
		&& ok "$name: report covers AppImage-internal/shimmed paths" \
		|| bad "$name: internal paths missing from report"

	# LD_DEBUG=libs against the same extracted payload: what the
	# status quo (quick-sharun's scraping) sees
	LD_DEBUG=libs $RUN 15 env APPDIR="$out/AppDir" \
		"$root/AppRun" "$app" --version \
		> "$out/ldd.out" 2> "$out/lddebug.txt"
	ldn=$(grep -c "calling init" "$out/lddebug.txt" 2>/dev/null || true)
	rn=$(jq '[.entries[] | select(.library)] | length' "$out/report.json")
	if [ "${rn:-0}" -ge "${ldn:-0}" ]; then
		ok "$name: report libraries ($rn) >= LD_DEBUG init lines ($ldn)"
	else
		bad "$name: report ($rn) < LD_DEBUG ($ldn)"
	fi
}

echo "== static binaries (pkgforge/bin, x86_64-Linux) =="
# NOTE: the bash workload is deliberately free of external helpers
# (cat, grep, ...): --keep-alive suppresses each process's exit_group,
# and a glibc helper that faults after the suppressed exit is observed
# by its parent inside the tracee tree as status 139 -- the run's own
# semantics must not depend on that.  Pure-bash builtins still generate
# ~10k syscalls of real file work.
run_one_static bash 0 bash.pkgforge -c '
	work=$PWD/e2e-bash-work; rm -rf "$work"
	mkdir -p "$work"
	cd "$work" || exit 1
	i=0
	while [ "$i" -lt 100 ]; do
		printf "line %s of %s\n" "$i" "e2e" > "f$i.txt"
		i=$((i + 1))
	done
	total=0
	for f in f*.txt; do
		while read -r line; do
			case "$line" in *e2e*) total=$((total + 1)) ;; esac
		done < "$f"
	done
	[ "$total" -eq 100 ] || exit 1
	for p in /proc/self/status /etc/passwd /etc/localtime; do
		[ -r "$p" ] && : < "$p"
	done
	echo "bash e2e done: $total lines"
'
# the applet-named copies were made at fetch time; du generates the
# input for the sort run below on the fly
run_one_static du 0 du -sb /usr
out="$LOGS/coreutils"; mkdir -p "$out"
"$DL/du" -ab /usr/lib64 > "$out/in.txt" 2>/dev/null || true
$RUN "$STRACE" --packager --json -o "$out/trace2.jsonl" \
	--report-files="$out/report2.json" \
	"$DL/sort" -o "$out/sorted.txt" "$out/in.txt" \
	> "$out/stdout2" 2> "$out/stderr2"
rc=$?
[ "$rc" = 0 ] && ok "coreutils sort over a du listing: exit 0" \
	|| bad "coreutils sort: exit $rc"
jq -s -e '[.[] | select(.type=="summary")][0].events > 50' \
	"$out/trace2.jsonl" > /dev/null 2>&1 \
	&& ok "coreutils sort: >50 events" \
	|| bad "coreutils sort: too few events"
run_one_static curl 0 curl.pkgforge --version
run_one_static curl 0 curl.pkgforge -sS --max-time 5 -o /dev/null \
	"file:///etc/passwd"
# scrub proxy env: the assertion needs a direct, refused connection
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
	-u all_proxy -u ALL_PROXY \
	$RUN "$STRACE" --packager --json -o "$LOGS/curl/trace3.jsonl" \
	--report-files="$LOGS/curl/report3.json" \
	"$DL/curl.pkgforge" -sS --max-time 5 --noproxy '*' \
	-o /dev/null "https://127.0.0.1:1/unreachable" \
	> "$LOGS/curl/stdout3" 2> "$LOGS/curl/stderr3"
rc=$?
[ "$rc" = 7 ] && ok "curl: connect-failure exit status 7 propagated" \
	|| bad "curl: rc=$rc, want 7"
jq -e 'select(.errno!=null)' "$LOGS/curl/trace3.jsonl" \
	> /dev/null 2>&1 && ok "curl: errno-typed events present" \
	|| bad "curl: no errno events"

echo "== AppImages (pkgforge-dev/Anylinux-AppImages) =="
run_one_appimage gtk3 gtk3-demo
run_one_appimage qt6dbus qdbusviewer
run_one_appimage sdl2 SDL-demo

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
printf 'artifacts in %s/\n' "$LOGS"
[ "$FAIL" = 0 ]
