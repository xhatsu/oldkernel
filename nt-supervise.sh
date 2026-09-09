#!/bin/sh
# Bounded crash recovery for the legacy capture pipeline.
# Five short-lived failures open the circuit instead of creating a restart
# storm. The service manager/operator must explicitly start it again.
set -u

GUARD=${1:-}
CPU_CORE=${2:-}
[ $# -ge 2 ] || exit 70
shift 2
[ -x "$GUARD" ] || exit 70
[ $# -gt 0 ] || exit 70

child_pid=""
stopping=0

stop_supervisor() {
    stopping=1
    if [ -n "$child_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    exit 0
}
trap 'stop_supervisor' TERM INT HUP

failures=0
delay=1
while [ "$stopping" -eq 0 ]; do
    started=$(date +%s)
    "$GUARD" "$CPU_CORE" "$@" &
    child_pid=$!
    wait "$child_pid"
    status=$?
    child_pid=""
    [ "$stopping" -eq 0 ] || exit 0
    # A clean exit includes an intentional remote-control stop. Do not undo it.
    [ "$status" -ne 0 ] || exit 0

    ended=$(date +%s)
    runtime=$((ended - started))
    if [ "$runtime" -ge 60 ]; then
        failures=0
        delay=1
    fi
    failures=$((failures + 1))
    if [ "$failures" -ge 5 ]; then
        echo "nt-supervise: crash-loop circuit open after $failures failures (last status=$status)" >&2
        exit 75
    fi
    echo "nt-supervise: child exited status=$status; restart in ${delay}s ($failures/5)" >&2
    sleep "$delay" &
    child_pid=$!
    wait "$child_pid" 2>/dev/null || true
    child_pid=""
    [ "$delay" -ge 8 ] || delay=$((delay * 2))
done
exit 0
