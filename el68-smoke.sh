#!/bin/sh
# el68-smoke.sh — NetworkTracing old-kernel prerequisite test (CentOS 6.8 /
# kernel 2.6.32-642.el6). Run AS ROOT on the target node, from this dir:
#   sudo sh el68-smoke.sh
# One NT-SMOKE line per check. Exit 0 = all green.
set -u
PASS=0; FAIL=0
ok()   { echo "NT-SMOKE PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "NT-SMOKE FAIL: $*"; FAIL=$((FAIL+1)); }
info() { echo "NT-SMOKE INFO: $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "NT-SMOKE node: $(uname -sr) $(uname -m)"

case "$(uname -r)" in
    2.6.32*) ok "kernel 2.6.32 family ($(uname -r))" ;;
    *) bad "unexpected kernel $(uname -r) — kit targets 2.6.32" ;;
esac

have python || bad "python missing (2.6/2.7 required)"
python -c 'import sys; assert sys.version_info >= (2,6) and sys.version_info < (3,)' 2>/dev/null \
    && ok "python version OK ($(python -V 2>&1))" \
    || bad "python not 2.6/2.7"

( have curl || have wget ) && ok "downloader present" || bad "no curl/wget"

if have getenforce; then info "selinux=$(getenforce)"; else info "selinux absent/disabled"; fi

TD=""
for c in /usr/sbin/tcpdump /usr/bin/tcpdump tcpdump; do
    [ -x "$c" ] && TD="$c" && break
done
[ -n "$TD" ] || bad "tcpdump absent — install it (yum install tcpdump) for capture proof"

if [ -n "$TD" ] && have setcap; then
    TMPD=/tmp/nt-smoke.$$
    mkdir -p "$TMPD"
    cp "$TD" "$TMPD/td"
    if setcap cap_net_raw+ep "$TMPD/td" 2>/dev/null; then
        IFACE=$(awk 'NR==2{print $1}' /proc/net/route)
        if su -s /bin/sh nobody -c "$TMPD/td -c 1 -p -i $IFACE -nn >/dev/null 2>&1"; then
            ok "non-root CAP_NET_RAW capture works (setcap path viable)"
        else
            bad "non-root capture failed — SELinux or VFS caps issue"
        fi
    else
        bad "setcap refused on $TMPD"
    fi
    rm -rf "$TMPD"
else
    bad "setcap or tcpdump missing — cannot prove rootless capture"
fi

# AF_PACKET openable by a non-root user via a capped interpreter copy
if have python && have setcap; then
    TMPD=/tmp/nt-smoke-py.$$
    mkdir -p "$TMPD"
    cp "$(command -v python)" "$TMPD/py-cap"
    if setcap cap_net_raw+ep "$TMPD/py-cap" 2>/dev/null \
       && su -s /bin/sh nobody -c "$TMPD/py-cap -c 'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800)); print(42)'" 2>/dev/null | grep -q 42; then
        ok "AF_PACKET openable under capped interpreter (sniffer will run rootless)"
    else
        bad "AF_PACKET denied for capped non-root interpreter"
    fi
    rm -rf "$TMPD"
else
    bad "cannot test capped-interpreter AF_PACKET"
fi

# sniffer script itself parses with the NODE's python (py2.6 on el6)
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python -m py_compile "$HERE/nt-sniff.py" 2>/dev/null \
    && ok "nt-sniff.py compiles under node python ($(python -V 2>&1))" \
    || bad "nt-sniff.py syntax error under node python"

echo "NT-SMOKE done: $PASS pass, $FAIL fail"
[ "$FAIL" = 0 ]
