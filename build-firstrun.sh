#!/bin/sh
# build-firstrun.sh — produce the single-file first-run installer:
# install-oldkernel.sh + embedded (patched) nt-sniff.py / nt-ship.py
set -e
cd "$(dirname "$0")"

OUT=install-firstrun-el68.sh
cp install-oldkernel.sh "$OUT"

{
    printf '\nexit 0\n'
    printf '#__SNIFF_B64__\n'
    base64 nt-sniff.py
    printf '#__END_SNIFF__\n'
    printf '#__SHIP_B64__\n'
    base64 nt-ship.py
    printf '#__END_SHIP__\n'
} >> "$OUT"

chmod 755 "$OUT"
echo "built $OUT ($(wc -c < "$OUT") bytes)"
