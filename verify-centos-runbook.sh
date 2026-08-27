#!/bin/sh
# Run a non-destructive static portion of the CentOS 6.7 test runbook.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FAIL=0
pass() { echo "RUNBOOK PASS: $*"; }
bad() { echo "RUNBOOK FAIL: $*"; FAIL=$((FAIL+1)); }

[ -s "$HERE/CENTOS-6.7-TEST.md" ] && pass "runbook present" || bad "runbook missing"
for f in el68-smoke.sh nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh install-oldkernel.sh; do
    [ -s "$HERE/$f" ] && pass "kit file present: $f" || bad "kit file missing: $f"
done
sh -n "$HERE/el68-smoke.sh" "$HERE/install-oldkernel.sh" "$HERE/nt-run-cpp.sh" "$HERE/build-firstrun.sh" || bad "shell syntax"
if command -v python3 >/dev/null 2>&1; then
    python3 -m py_compile "$HERE/nt-sniff.py" "$HERE/nt-ship.py" && pass "Python 3 compatibility shim compiles" || bad "Python syntax"
fi
if command -v make >/dev/null 2>&1; then
    make -C "$HERE" clean all && pass "native C++ build" || bad "native C++ build"
fi
printf 'RUNBOOK SUMMARY: %d failure(s)\n' "$FAIL"
[ "$FAIL" -eq 0 ]
