#!/bin/sh
# build-firstrun.sh — produce the single-file first-run installer bundle.
# Includes Python remote control and native C++ payloads.
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
    printf '#__CONTROL_B64__\n'
    base64 nt_control.py
    printf '#__END_CONTROL__\n'
    printf '#__CONTROL_RUN_B64__\n'
    base64 nt-control.py
    printf '#__END_CONTROL_RUN__\n'
    printf '#__CPP_SHIP_B64__\n'
    base64 nt-ship-cpp.cpp
    printf '#__END_CPP_SHIP__\n'
    printf '#__CPP_B64__\n'
    base64 nt-sniff-cpp.cpp
    printf '#__END_CPP__\n'
    printf '#__CPP_MAKE_B64__\n'
    base64 Makefile
    printf '#__END_CPP_MAKE__\n'
    printf '#__CPP_RUN_B64__\n'
    base64 nt-run-cpp.sh
    printf '#__END_CPP_RUN__\n'
} >> "$OUT"
chmod 755 "$OUT"
echo "built $OUT ($(wc -c < "$OUT") bytes)"
