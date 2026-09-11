#!/bin/sh
# Run Python capture piped into separated native C++ shipper.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENDPOINT=${NT_HUB_ENDPOINT:-}
SHIP_RATE=${NT_SHIP_RATE_KBPS:-1024}
STATS_INTERVAL=${NT_STATS_INTERVAL_SEC:-30}
if [ -z "$ENDPOINT" ]; then
    echo "NT_HUB_ENDPOINT is required" >&2
    exit 2
fi
PYBIN="$HERE/python-capnetraw"
[ -x "$PYBIN" ] || PYBIN="python"
"$PYBIN" -u "$HERE/nt-sniff.py" "$@" | exec "$HERE/nt-ship-cpp" --endpoint "$ENDPOINT" \
    --ship-rate-kbps "$SHIP_RATE" --stats-interval-sec "$STATS_INTERVAL"
