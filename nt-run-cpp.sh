#!/bin/sh
# Run native C++ capture and the proven Python 2.6-compatible shipper.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENDPOINT=${NT_HUB_ENDPOINT:-}
SPOOL=${NT_SPOOL:-/var/lib/networktracing/sniff-spool.jsonl}
if [ -z "$ENDPOINT" ]; then
    echo "NT_HUB_ENDPOINT is required" >&2
    exit 2
fi
exec "$HERE/nt-sniff-cpp" "$@" | exec python "$HERE/nt-ship.py" --endpoint "$ENDPOINT" --spool "$SPOOL"
