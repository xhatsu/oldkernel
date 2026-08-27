#!/bin/sh
# install-oldkernel.sh — NetworkTracing legacy installer (CentOS 6.x / 2.6.32)
#
# Installs the pcap-based HTTP/SOAP sniffer + python2.6 shipper as a SysV
# service. NO eBPF, NO systemd, NO kernel modules. Prefers rootless capture
# via file capability (cap_net_raw on a private interpreter copy); falls
# back to root only if setcap is unavailable or SELinux refuses.
#
# FIRST RUN — works standalone on a bare node; missing kit files are
# fetched automatically from the hub bootstrap server:
#
#   curl -sSf http://HUB:30105/oldkernel/install-oldkernel.sh | sh -s -- \
#        --endpoint http://HUB:31115
#
# Local bundle usage:
#   sh install-oldkernel.sh --endpoint http://hub:31115
#   sh install-oldkernel.sh --check [--endpoint ...]
#   sh install-oldkernel.sh --uninstall
#
# Env overrides: NT_IFACE=eth1  NT_PORTS=80,...  NT_HUB=http://HUB:30105/oldkernel
set -u

PREFIX=/opt/networktracing-legacy
INIT=/etc/init.d/networktracing-legacy
SNIFF_USER=ntsniff
MODE=install
ENDPOINT=""
IFACE="${NT_IFACE:-}"
PORTS="${NT_PORTS:-80,8003,8005,8007,8009,8010,8011}"
WORKERS="${NT_WORKERS:-1}"   # PACKET_FANOUT workers (needs kernel>=3.1)
SHIPPERS="${NT_SHIP_THREADS:-8}"  # concurrent hub POST threads
KIT_URLS="${NT_HUB:-}"

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --hub)      KIT_URLS="$2"; shift 2 ;;
        --check)    MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        *) die "unknown arg: $1" ;;
    esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || SCRIPT_DIR=""

have_root() { [ "$(id -u)" = "0" ]; }

fetch() { # fetch <url> <dest>
    if have curl; then curl -sSf --max-time 30 "$1" -o "$2"
    elif have wget; then wget -q -T 30 "$1" -O "$2"
    else return 127; fi
}

# ------------------------------------------------------- first-run kit pull
# A bare node may receive ONLY this script (piped over ssh/curl). Kit files
# are resolved in order:
#   1. already next to the script (local bundle)
#   2. embedded base64 payload inside this file (single-file build — no
#      network needed; preferred because hub mirrors can lag behind fixes)
#   3. fetched from the hub bootstrap server (--hub / derived from endpoint)
# Uninstall never needs the kit.
need_kit=0
for f in nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh; do
    [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$f" ] || need_kit=1
done

if [ "$need_kit" = 1 ] && [ "$MODE" != uninstall ]; then
    WORKDIR=/tmp/ntkit
    mkdir -p "$WORKDIR" || die "cannot create $WORKDIR"

    # --- source 2: embedded payload -------------------------------------
    SELF="$0"
    [ -f "$SELF" ] || SELF=""
    if [ -z "$SELF" ] && [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
        HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
        [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
    fi
    if [ -z "$SELF" ] && [ -n "$KIT_URLS" ]; then
        fetch "$KIT_URLS/install-firstrun-el68.sh" "$WORKDIR/nt-self.sh" 2>/dev/null && SELF="$WORKDIR/nt-self.sh"
    fi
    if [ -n "$SELF" ] && grep -q '^#__SNIFF_B64__$' "$SELF" 2>/dev/null; then
        log "first run: extracting embedded kit -> $WORKDIR"
        sed -n '/^#__SNIFF_B64__$/,/^#__END_SNIFF__$/p' "$SELF" | sed '1d;$d' \
            | base64 -d > "$WORKDIR/nt-sniff.py" 2>/dev/null
        sed -n '/^#__SHIP_B64__$/,/^#__END_SHIP__$/p' "$SELF" | sed '1d;$d' \
            | base64 -d > "$WORKDIR/nt-ship.py" 2>/dev/null
        sed -n '/^#__CPP_SHIP_B64__$/,/^#__END_CPP_SHIP__$/p' "$SELF" | sed '1d;$d' \
            | base64 -d > "$WORKDIR/nt-ship-cpp.cpp" 2>/dev/null
        sed -n '/^#__CPP_B64__$/,/^#__END_CPP__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-sniff-cpp.cpp" 2>/dev/null
        sed -n '/^#__CPP_MAKE_B64__$/,/^#__END_CPP_MAKE__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/Makefile" 2>/dev/null
        sed -n '/^#__CPP_RUN_B64__$/,/^#__END_CPP_RUN__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-run-cpp.sh" 2>/dev/null
    fi

    # --- source 3: hub bootstrap server ---------------------------------
    if [ ! -s "$WORKDIR/nt-sniff.py" ] || [ ! -s "$WORKDIR/nt-ship.py" ] || [ ! -s "$WORKDIR/nt-sniff-cpp.cpp" ] || [ ! -s "$WORKDIR/Makefile" ]; then
        if [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
            HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
            [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
        fi
        [ -n "$KIT_URLS" ] || die "kit files missing, no embedded payload, cannot derive hub URL — pass --hub http://HUB:30105/oldkernel"
        log "first run: fetching kit from $KIT_URLS -> $WORKDIR"
        have curl || have wget || die "neither curl nor wget present and no embedded payload"
        for f in nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh el68-smoke.sh README.md DEBUG-NOTES.md; do
            fetch "$KIT_URLS/$f" "$WORKDIR/$f.new" || die "cannot download $f from $KIT_URLS"
            mv "$WORKDIR/$f.new" "$WORKDIR/$f"
        done
    fi

    chmod 755 "$WORKDIR"/nt-*.py "$WORKDIR"/nt-run-cpp.sh 2>/dev/null || true
    python -m py_compile "$WORKDIR/nt-sniff.py" 2>/dev/null \
        || die "nt-sniff.py does not compile under node python"
    python -m py_compile "$WORKDIR/nt-ship.py" 2>/dev/null \
        || die "nt-ship.py does not compile under node python"
    # version sentinel: reject stale pre-py2.6-fix kits (they py_compile fine
    # but crash on first packet — silent capture loss)
    grep -q "def b2i" "$WORKDIR/nt-sniff.py" \
        || die "stale kit from mirror (missing py2.6 fix). Use the two-step form so the embedded payload is used:
  curl -sSf \$URL -o /tmp/nt-install.sh && sh /tmp/nt-install.sh --endpoint $ENDPOINT"
    SCRIPT_DIR="$WORKDIR"
    log "kit ready in $SCRIPT_DIR"
fi

# ---------------------------------------------------------------- uninstall
if [ "$MODE" = "uninstall" ]; then
    log "stopping service..."
    [ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1 || true
    if have chkconfig; then chkconfig networktracing-legacy off >/dev/null 2>&1 || true; fi
    rm -f "$INIT"
    for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py"; do
        for p in $(pgrep -f "$pattern" 2>/dev/null || true); do
            [ "$p" = "$$" ] || kill "$p" 2>/dev/null || true
        done
    done
    rm -rf "$PREFIX"
    RESIDUE=""
    for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py"; do
        pgrep -f "$pattern" >/dev/null 2>&1 && RESIDUE="$RESIDUE procs-alive"
    done
    [ -e "$INIT" ] && RESIDUE="$RESIDUE init-script-present"
    [ -d "$PREFIX" ] && RESIDUE="$RESIDUE install-dir-present"
    if [ -n "$RESIDUE" ]; then
        die "uninstall incomplete:$RESIDUE"
    fi
    log "uninstall verified clean."
    exit 0
fi

# ---------------------------------------------------------------- preflight
[ "$(uname -s)" = "Linux" ] || die "not Linux"
case "$(uname -r)" in
    2.6.*) : ;;
    *) log "WARN: kernel $(uname -r) — kit targets 2.6.32; may still work" ;;
esac

# C++ native mode uses the shipped binary; do not require Python 2.6.
if [ "${NT_CAPTURE_MODE:-python}" = "cpp" ]; then
    have g++ || die "NT_CAPTURE_MODE=cpp requires g++ on target"
    have python || die "python shipper required on target"
else
    have python || die "python (2.6/2.7) required on the node"
    python -c 'import sys; assert sys.version_info >= (2,6) and sys.version_info < (3,)' \
        || die "python 2.6/2.7 required"
fi

[ -n "$ENDPOINT" ] || die "--endpoint http://hub:port required"

if have curl; then
    PROBE=$(curl -s --max-time 5 -X POST -H 'Content-Type: application/json' \
        -d '{"node":"legacy-compat-probe","events":[]}' \
        "$ENDPOINT/api/ingest" 2>/dev/null) || PROBE=""
    case "$PROBE" in
        *'"ok"'*) log "hub protocol OK ($ENDPOINT)" ;;
        "") die "hub $ENDPOINT unreachable" ;;
        *)  log "WARN: unexpected hub reply '$PROBE' — continuing" ;;
    esac
else
    log "WARN: curl absent — cannot probe hub before installing"
fi

IFACE="${IFACE:-$(awk 'NR==2{print $1}' /proc/net/route)}"
[ -n "$IFACE" ] || die "cannot detect default interface (set NT_IFACE)"

if [ "$MODE" = "check" ]; then
    log "preflight OK ($IFACE, $(uname -r), endpoint=$ENDPOINT) — no changes made"
    exit 0
fi

have_root || die "must run as root (try: sudo sh $0 ...)"

# ---------------------------------------------------------------- install
mkdir -p "$PREFIX" || die "mkdir $PREFIX failed"
for f in nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh; do
    [ -f "$SCRIPT_DIR/$f" ] || die "bundle incomplete: missing $f"
done
cp "$SCRIPT_DIR"/nt-sniff.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship.py  "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship-cpp.cpp "$PREFIX/"
cp "$SCRIPT_DIR"/nt-sniff-cpp.cpp "$PREFIX/"
cp "$SCRIPT_DIR"/Makefile "$PREFIX/"
cp "$SCRIPT_DIR"/nt-run-cpp.sh "$PREFIX/"
chmod 755 "$PREFIX"/nt-*.py "$PREFIX"/nt-run-cpp.sh

# privilege model: copy the interpreter, grant IT cap_net_raw, run sniffer
# as a locked account. Falls back to root when setcap/SELinux refuses.
SNIFF_AS=root
PYBIN=$(command -v python)
if have setcap && have useradd; then
    id "$SNIFF_USER" >/dev/null 2>&1 || useradd -r -s /sbin/nologin "$SNIFF_USER" 2>/dev/null || true
    cp "$PYBIN" "$PREFIX/python-capnetraw" 2>/dev/null || true
    # NOTE: chown BEFORE setcap — chown clears file capabilities
    # (proven on el6: setcap-then-chown left getcap empty -> EPERM)
    if [ -f "$PREFIX/python-capnetraw" ] \
       && chown "$SNIFF_USER" "$PREFIX"/python-capnetraw 2>/dev/null \
       && setcap cap_net_raw+ep "$PREFIX/python-capnetraw" 2>/dev/null; then
        SNIFF_AS="$SNIFF_USER"
        log "rootless mode: cap_net_raw on private interpreter, user=$SNIFF_USER"
    else
        rm -f "$PREFIX/python-capnetraw"
        log "WARN: setcap path failed — sniffer will run as root"
    fi
else
    log "WARN: setcap/useradd absent — sniffer will run as root"
fi

mkdir -p /var/lib/networktracing
if [ "$SNIFF_AS" != root ]; then
    chown "$SNIFF_USER" /var/lib/networktracing 2>/dev/null || true
fi

# sniff.log is appended by $SNIFF_USER inside su -c; pre-create it or the
# redirect fails with EACCES on a root-owned 755 PREFIX (proven on el6)
touch "$PREFIX/sniff.log"
chmod 644 "$PREFIX/sniff.log"
if [ "$SNIFF_AS" != root ]; then
    chown "$SNIFF_USER" "$PREFIX/sniff.log" 2>/dev/null || true
fi

# sniffer stdout must FEED the shipper's stdin; starting them separately
# leaves events stranded in sniff.log (proven on el6). Build one pipeline.
# Choose native C++ only when explicitly requested; Python remains default.
CAPTURE_MODE="${NT_CAPTURE_MODE:-python}"
# Native C++ builds from the copied source and uses the native C++ shipper.
# The default capture mode remains Python for compatibility.
if [ "$CAPTURE_MODE" = "cpp" ]; then
    CXXSTD=$(g++ -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra $CXXSTD nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra $CXXSTD nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
    SNIFF_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS"
    SHIP_CMD="exec $PREFIX/nt-ship-cpp --endpoint $ENDPOINT --spool /var/lib/networktracing/sniff-spool.jsonl"
    log "native C++ capture + shipper selected"
else
    if [ "$SNIFF_AS" != root ]; then
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec python $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
    fi
    SHIP_CMD="exec python $PREFIX/nt-ship.py --endpoint $ENDPOINT"
fi

cat > "$INIT" <<EOF
#!/bin/sh
# networktracing-legacy — pcap sniffer + shipper (SysV, el6)
# chkconfig: 2345 90 10
# description: NetworkTracing passive HTTP/SOAP capture (old-kernel kit)

PREFIX=$PREFIX
SNIFF_USER=$SNIFF_AS
export NT_SHIP_THREADS=$SHIPPERS
PIDFILE=/var/run/networktracing-legacy.pid

case "\$1" in
    start)
        if pgrep -f "\\\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\\\$PREFIX/nt-sniff-cpp" >/dev/null; then
            echo "already running"; exit 0
        fi
        nohup sh -c "$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1" >/dev/null 2>&1 &
        echo \$! > "\$PIDFILE"
        sleep 1
        pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null || { echo "sniffer failed to start"; exit 1; }
        echo "networktracing-legacy started"
        ;;
    stop)
        for pattern in "\$PREFIX/nt-sniff.py" "\$PREFIX/nt-sniff-cpp" "\$PREFIX/nt-ship.py"; do
            for p in \$(pgrep -f "\$pattern" 2>/dev/null || true); do
                [ "\$p" = "\$\$" ] || kill "\$p" 2>/dev/null || true
            done
        done
        rm -f "\$PIDFILE"
        echo "networktracing-legacy stopped"
        ;;
    status)
        if pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null; then
            echo "running"; exit 0
        fi
        echo "stopped"; exit 3
        ;;
    restart)
        \$0 stop; sleep 1; \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|status|restart}"; exit 2
        ;;
esac
exit 0
EOF
chmod 755 "$INIT"

if have chkconfig; then
    chkconfig --add networktracing-legacy 2>/dev/null || true
    chkconfig networktracing-legacy on 2>/dev/null || true
fi

"$INIT" start || die "service failed to start"
sleep 3
pgrep -f "$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null || die "sniffer not running after start"

log "DONE. Sniffer iface=$IFACE ports=$PORTS -> hub $ENDPOINT (capture-as=$SNIFF_AS)"
log "Logs: $PREFIX/sniff.log $PREFIX/ship.log"
log "Uninstall: sh $SCRIPT_DIR/install-oldkernel.sh --uninstall"

exit 0
#__SNIFF_B64__
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMgLSotIGNvZGluZzogdXRmLTggLSotCiIiIm50LXNuaWZm
LnB5IOKAlCBwYXNzaXZlIEFGX1BBQ0tFVCBIVFRQL1NPQVAgc25pZmZlciBmb3Igb2xkIGtlcm5l
bHMuCgpUYXJnZXQ6IENlbnRPUyA2LnggLyBrZXJuZWwgMi42LjMyIChubyBlQlBGLCBubyBzeXN0
ZW1kLCBweXRob24gMi42KS4KUmVhZHMgcGFja2V0cyBvZmYgdGhlIHdpcmUgKENBUF9ORVRfUkFX
KSwgcmVhc3NlbWJsZXMgcGxhaW4tSFRUUCByZXF1ZXN0cywKZXh0cmFjdHMgQmFzaWMtYXV0aCB1
c2VybmFtZXMgKHNhbWUgc2VtYW50aWNzIGFzIG50X2F1dGhsaWIuZXh0cmFjdCksCmVtaXRzIE5l
dHdvcmtUcmFjaW5nIGV2ZW50IEpTT05MIG9uIHN0ZG91dC4KClRMUyBpcyBOT1QgcmVhZGFibGUg
KGJ5IGRlc2lnbiDigJQgdGhhdCB0aWVyIHN0YXlzIG9uIHRoZSBlQlBGIGFnZW50KS4KU09BUCBX
U1NFIHVzZXJuYW1lcyBhcmUgTk9UIGV4dHJhY3RlZCAocHJvZHVjdCBkZWNpc2lvbjogQmFzaWMt
b25seSkuCgpQZXJmb3JtYW5jZToKICAqIGtlcm5lbCBCUEYgZmlsdGVyIChTT19BVFRBQ0hfRklM
VEVSKTogb25seSBJUHY0L1RDUCByZXF1ZXN0cyBkZXN0aW5lZAogICAgdG8gbW9uaXRvcmVkIHBv
cnRzIGFyZSBjb3BpZWQgdXAg4oCUIHJlc3BvbnNlcy9ub2lzZSBuZXZlciByZWFjaCBweXRob24K
ICAqIEhFQURFUi1PTkxZIGNhcHR1cmU6IGV2ZW50cyBlbWl0IGF0IFxyXG5cclxuOyBib2RpZXMg
YXJlIG5vdCBidWZmZXJlZAogICogUEFDS0VUX0ZBTk9VVCAoLWogTik6IE4gZm9ya2VkIHdvcmtl
cnMgc2hhcmUgdGhlIE5JQyBhY3Jvc3MgY29yZXMKVXNhZ2U6ICBweXRob24gbnQtc25pZmYucHkg
Wy1pIGV0aDBdIFstcCA4MCw4MDAzLC4uLl0gWy1qIHdvcmtlcnNdClN0ZG91dDogb25lIEpTT04g
ZXZlbnQgcGVyIGxpbmUgLT4gcGlwZSBpbnRvIG50LXNoaXAucHkuCiIiIgpmcm9tIF9fZnV0dXJl
X18gaW1wb3J0IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBiaW5hc2NpaSwgZXJybm8s
IGpzb24sIG9zLCBzaWduYWwsIHNvY2tldCwgc3RydWN0LCBzeXMsIHRpbWUKCkVUSF9QX0FMTCA9
IDB4MDAwMwpFVEhfUF9JUCA9IDB4MDgwMApFVEhfUF9WTEFOID0gMHg4MTAwCgojIHB5Mi42IHN0
ci1pbmRleGluZyB5aWVsZHMgMS1jaGFyIHN0ciwgbm90IGludCAocHJvdmVuIG9uIHJlYWwgZWw2
IFZNKTsKIyBub3JtYWxpemUgc28gYnl0ZS1hdC1pbmRleCB3b3JrcyBpZGVudGljYWxseSB1bmRl
ciBweXRob24gMiBhbmQgMwpQWTIgPSBzeXMudmVyc2lvbl9pbmZvWzBdID09IDIKCgpkZWYgYjJp
KGMpOgogICAgcmV0dXJuIG9yZChjKSBpZiBQWTIgZWxzZSBjCgpNRVRIT0RTID0gKCJHRVQiLCAi
UE9TVCIsICJQVVQiLCAiREVMRVRFIiwgIlBBVENIIiwgIkhFQUQiLCAiT1BUSU9OUyIpCgpNQVhf
RkxPV1MgPSA4MTkyICAgICAgICAgICAgIyBjb25jdXJyZW50IHRyYWNrZWQgaGFsZi1mbG93cyAo
cGVyIGRpcmVjdGlvbikKTUFYX0hEUlMgPSAyNjIxNDQgICAgICAgICAgICMgbWF4IGJ5dGVzIGJ1
ZmZlcmVkIHdhaXRpbmcgZm9yIFxyXG5cclxuCkZMT1dfVFRMID0gMzAwICAgICAgICAgICAgICAj
IHNlY29uZHMgYmVmb3JlIGlkbGUgZmxvdyBidWZmZXJzIGFyZSBkcm9wcGVkCgoKZGVmIGxvZyht
c2cpOgogICAgc3lzLnN0ZGVyci53cml0ZSgibnQtc25pZmY6ICVzXG4iICUgbXNnKQogICAgc3lz
LnN0ZGVyci5mbHVzaCgpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHBlcmY6IGNCUEYKIyBBdHRhY2ggYSBjbGFzc2lj
IEJQRiBwcm9ncmFtIHNvIHRoZSBLRVJORUwgZHJvcHMgZXZlcnl0aGluZyB0aGF0IGlzIG5vdAoj
IElQdjQgVENQIGRlc3RpbmVkIFRPIGEgbW9uaXRvcmVkIHBvcnQuIFJlcXVlc3RzIGFsb25lIGRy
aXZlIGV2ZW50cwojIChoZWFkZXItb25seSBjYXB0dXJlKTsgcmVzcG9uc2VzLCBBQ0tzIGFuZCB1
bnJlbGF0ZWQgdHJhZmZpYyBuZXZlciBnZXQKIyBjb3BpZWQgdG8gdXNlcnNwYWNlIGF0IGFsbC4K
U09fQVRUQUNIX0ZJTFRFUiA9IDI2CgpkZWYgYnVpbGRfYnBmKHBvcnRzKToKICAgICIiIkNsYXNz
aWMgQlBGOiBldGhlcnR5cGU9PUlQICYmIHByb3RvPT1UQ1AgJiYgZHBvcnQgaW4gcG9ydHMuCiAg
ICBSZXR1cm5zIChmcHJvZ19zdHJ1Y3QsIGZpbHRlcl9hcnJheSkgZm9yIHRoZSBsaWJjIHNldHNv
Y2tvcHQgY2FsbCwKICAgIG9yIE5vbmUgb24gZmFpbHVyZS4gTk9URTogc29ja19mcHJvZyBjYXJy
aWVzIGEgUE9JTlRFUiB0byB0aGUgZmlsdGVyCiAgICBhcnJheSwgc28gaXQgbXVzdCBzdGF5IGFs
aXZlIHVudGlsIHRoZSBzeXNjYWxsIOKAlCBweXRob24ncwogICAgc29ja2V0LnNldHNvY2tvcHQo
c3RyKSBmbGF0dGVuaW5nIGNhbm5vdCBwcmVzZXJ2ZSBpdC4iIiIKCiAgICBMREhfQUJTID0gMHgy
OCAgICMgbGQgW2tdOmgKICAgIExEQl9BQlMgPSAweDMwICAgIyBsZCBba106YgogICAgSkVRX0sg
PSAweDE1ICAgICAjIGplcSBrCiAgICBMRFhfTVNIID0gMHhCMSAgICMgeCA9IDQqKFtrXSYweGYp
ICAoaWhsIGJ5dGVzKQogICAgTERIX0lORCA9IDB4NDggICAjIGxkIFt4K2tdOmgKICAgIFJFVF9L
ID0gMHgwNgoKICAgICMgUFJPVkVOIGRwb3J0IGJsb2NrICsgc3BvcnQgYmxvY2sgYXQgWCsxNCAo
Y2FsaWJyYXRlZCBFTVBJUklDQUxMWSBvbgogICAgIyBhIGxpdmUga2VybmVsOiBrPTE0IGRlbGl2
ZXJzIHJlc3BvbnNlIHBhY2tldHM7IHRoZSBjb3JyZWxhdGlvbiB0aGVuCiAgICAjIHlpZWxkcyBz
dGF0dXMvZHVyYXRpb25fbXMvcmVzcF9ieXRlcyBlbmQtdG8tZW5kKS4gUmVxdWlyZXMgdGhlIDFz
CiAgICAjIHJlY3YgdGltZW91dCBpbiBtYWluKCkg4oCUIGJsb2NraW5nIHJlY3YgKyBCUEYgc3Rh
cnZlcyBhZnRlciBvbmUgcGt0LgogICAgc2sgPSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NOSUZG
X1NQT1JUX0siLCAiMTQiKSkKICAgIHBzID0gc29ydGVkKHBvcnRzKQogICAgbiA9IGxlbihwcykK
ICAgIHJldF9yZWogPSA1ICsgKDQgaWYgc2sgZWxzZSAyKSAqIG4KICAgIHJldF9hY2MgPSByZXRf
cmVqICsgMQogICAgcHJvZyA9IFtdCiAgICBwcm9nLmFwcGVuZCgoTERIX0FCUywgMCwgMCwgMTIp
KSAgICAgICAgICAgICAgICAgIyBldGhlcnR5cGUgPT0gSVA/CiAgICBwcm9nLmFwcGVuZCgoSkVR
X0ssIDAsIHJldF9yZWogLSAyLCAweDA4MDApKQogICAgcHJvZy5hcHBlbmQoKExEQl9BQlMsIDAs
IDAsIDIzKSkgICAgICAgICAgICAgICAgICMgcHJvdG8gPT0gVENQPwogICAgcHJvZy5hcHBlbmQo
KEpFUV9LLCAwLCByZXRfcmVqIC0gNCwgNikpCiAgICBwcm9nLmFwcGVuZCgoTERYX01TSCwgMCwg
MCwgMTQpKSAgICAgICAgICAgICAgICAgIyBYID0gaWhsKjQKICAgIGZvciBpLCBwIGluIGVudW1l
cmF0ZShwcyk6ICAgICAgICAgICAgICAgICAgICAgICAjIEE6IGRwb3J0IEAgWCsxNgogICAgICAg
IHByb2cuYXBwZW5kKChMREhfSU5ELCAwLCAwLCAxNikpCiAgICAgICAganQgPSByZXRfYWNjIC0g
KGxlbihwcm9nKSArIDEpCiAgICAgICAgamYgPSAwIGlmIChpIDwgbiAtIDEgb3Igc2spIGVsc2Ug
KHJldF9yZWogLSAobGVuKHByb2cpICsgMSkpCiAgICAgICAgcHJvZy5hcHBlbmQoKEpFUV9LLCBq
dCwgamYsIHApKQogICAgaWYgc2s6ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICMgQjogc3BvcnQgQCBYK3NrCiAgICAgICAgZm9yIGksIHAgaW4gZW51bWVyYXRlKHBz
KToKICAgICAgICAgICAgcHJvZy5hcHBlbmQoKExESF9JTkQsIDAsIDAsIHNrKSkKICAgICAgICAg
ICAganQgPSByZXRfYWNjIC0gKGxlbihwcm9nKSArIDEpCiAgICAgICAgICAgIGpmID0gMCBpZiBp
IDwgbiAtIDEgZWxzZSAocmV0X3JlaiAtIChsZW4ocHJvZykgKyAxKSkKICAgICAgICAgICAgcHJv
Zy5hcHBlbmQoKEpFUV9LLCBqdCwgamYsIHApKQogICAgcHJvZy5hcHBlbmQoKFJFVF9LLCAwLCAw
LCAwKSkgICAgICAgICAgICAgICAgICAgICMgcmVqZWN0CiAgICBwcm9nLmFwcGVuZCgoUkVUX0ss
IDAsIDAsIDB4NDAwMDApKSAgICAgICAgICAgICAgIyBhY2NlcHQKCiAgICB0cnk6CiAgICAgICAg
aW1wb3J0IGN0eXBlcwoKICAgICAgICBjbGFzcyBTb2NrRmlsdGVyKGN0eXBlcy5TdHJ1Y3R1cmUp
OgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImNvZGUiLCBjdHlwZXMuY191aW50MTYpLCAoImp0
IiwgY3R5cGVzLmNfdWludDgpLAogICAgICAgICAgICAgICAgICAgICAgICAoImpmIiwgY3R5cGVz
LmNfdWludDgpLCAoImsiLCBjdHlwZXMuY191aW50MzIpXQoKICAgICAgICBjbGFzcyBTb2NrRnBy
b2coY3R5cGVzLlN0cnVjdHVyZSk6CiAgICAgICAgICAgICMgbWlycm9ycyBzdHJ1Y3Qgc29ja19m
cHJvZyB7dTE2IGxlbjsgc29ja19maWx0ZXIgKmZpbHRlcn07CiAgICAgICAgICAgICMgY3R5cGVz
IGFwcGxpZXMgdGhlIHNhbWUgcG9pbnRlciBhbGlnbm1lbnQgYXMgdGhlIGNvbXBpbGVyCiAgICAg
ICAgICAgIF9maWVsZHNfID0gWygibGVuIiwgY3R5cGVzLmNfdWludDE2KSwKICAgICAgICAgICAg
ICAgICAgICAgICAgKCJmaWx0ZXIiLCBjdHlwZXMuUE9JTlRFUihTb2NrRmlsdGVyKSldCgogICAg
ICAgIGFyciA9IChTb2NrRmlsdGVyICogbGVuKHByb2cpKSgpCiAgICAgICAgZm9yIGksIChjb2Rl
LCBqdCwgamYsIGspIGluIGVudW1lcmF0ZShwcm9nKToKICAgICAgICAgICAgYXJyW2ldLmNvZGUg
PSBjb2RlOyBhcnJbaV0uanQgPSBqdAogICAgICAgICAgICBhcnJbaV0uamYgPSBqZjsgYXJyW2ld
LmsgPSBrCiAgICAgICAgcmV0dXJuIFNvY2tGcHJvZyhsZW4ocHJvZyksIGFyciksIGFycgogICAg
ZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBhcHBseV9wZXJmX29w
dHMoc29jaywgcG9ydHMpOgogICAgIiIiQmVzdC1lZmZvcnQga2VybmVsIGFzc2lzdDogQlBGIHBv
cnQgZmlsdGVyICsgYmlnIHJjdmJ1Zi4KICAgIE5UX1NOSUZGX05PX0JQRj0xIGRpc2FibGVzIHRo
ZSBmaWx0ZXIgKGRlYnVnZ2luZykuIiIiCiAgICBidWlsdCA9IE5vbmUKICAgIGlmIG9zLmVudmly
b24uZ2V0KCJOVF9TTklGRl9OT19CUEYiKSA9PSAiMSI6CiAgICAgICAgbG9nKCJOVF9TTklGRl9O
T19CUEYgc2V0IOKAlCBza2lwcGluZyBrZXJuZWwgZmlsdGVyIikKICAgIGVsc2U6CiAgICAgICAg
YnVpbHQgPSBidWlsZF9icGYocG9ydHMpCiAgICBpZiBidWlsdCBpcyBub3QgTm9uZToKICAgICAg
ICB0cnk6CiAgICAgICAgICAgIGltcG9ydCBjdHlwZXMKICAgICAgICAgICAgbGliYyA9IGN0eXBl
cy5DRExMKCJsaWJjLnNvLjYiKQogICAgICAgICAgICBmcHJvZywgYXJyID0gYnVpbHQgICAgICAg
ICAgICAgICAgICAgICAgIyBrZWVwIGFyciByZWZlcmVuY2VkIQogICAgICAgICAgICByZXQgPSBs
aWJjLnNldHNvY2tvcHQoc29jay5maWxlbm8oKSwgc29ja2V0LlNPTF9TT0NLRVQsCiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBTT19BVFRBQ0hfRklMVEVSLAogICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLmJ5cmVmKGZwcm9nKSwKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgIGN0eXBlcy5zaXplb2YoZnByb2cpKQogICAgICAgICAgICBpZiBy
ZXQgPT0gMDoKICAgICAgICAgICAgICAgIGxvZygia2VybmVsIEJQRiBmaWx0ZXIgYXR0YWNoZWQg
KCVkIG1vbml0b3JlZCBwb3J0cykiCiAgICAgICAgICAgICAgICAgICAgJSBsZW4ocG9ydHMpKQog
ICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiBCUEYgYXR0YWNoIHJl
amVjdGVkIGJ5IGtlcm5lbCAocmV0PSVkKSAiCiAgICAgICAgICAgICAgICAgICAgIuKAlCBydW5u
aW5nIHVuZmlsdGVyZWQiICUgcmV0KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAg
ICAgICAgICAgbG9nKCJXQVJOOiBCUEYgZmlsdGVyIGF0dGFjaCBmYWlsZWQgKCVzKSDigJQgcnVu
bmluZyB1bmZpbHRlcmVkIgogICAgICAgICAgICAgICAgJSBlKQogICAgZWxzZToKICAgICAgICBs
b2coIldBUk46IGN0eXBlcyB1bmF2YWlsYWJsZSDigJQgcnVubmluZyB3aXRob3V0IEJQRiBmaWx0
ZXIiKQogICAgdHJ5OgogICAgICAgIHdhbnQgPSA4ICogMTAyNCAqIDEwMjQKICAgICAgICBzb2Nr
LnNldHNvY2tvcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SQ1ZCVUYsIHdhbnQpCiAg
ICAgICAgZ290ID0gc29jay5nZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09f
UkNWQlVGKQogICAgICAgIGxvZygicmN2YnVmOiAlZCBieXRlcyIgJSBnb3QpCiAgICBleGNlcHQg
RXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nKCJXQVJOOiBTT19SQ1ZCVUYgcmFpc2UgZmFpbGVk
OiAlcyIgJSBlKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBwZXJmOiBmYW5vdXQKU09MX1BBQ0tFVCA9IDI2MwpQQUNL
RVRfRkFOT1VUID0gMTgKCmRlZiBhcHBseV9mYW5vdXQoc29jaywgZ3JvdXBfaWQpOgogICAgIiIi
S2VybmVsIGxvYWQtYmFsYW5jZXMgcGFja2V0cyBhY3Jvc3MgYWxsIHNvY2tldHMgc2hhcmluZyB0
aGUgZ3JvdXAuCiAgICBIYXNoaW5nIGlzIHBlci1mbG93LWRpcmVjdGlvbmFsOyByZXF1ZXN0IGRp
cmVjdGlvbiBhbG9uZSBkcml2ZXMgZXZlbnQKICAgIGVtaXNzaW9uLCBzbyBkaXJlY3Rpb25hbCBz
cGxpdHMgYXJlIHNhZmUuIFJldHVybnMgVHJ1ZSBvbiBzdWNjZXNzLiIiIgogICAgdHJ5OgogICAg
ICAgIHNvY2suc2V0c29ja29wdChTT0xfUEFDS0VULCBQQUNLRVRfRkFOT1VULAogICAgICAgICAg
ICAgICAgICAgICAgICBzdHJ1Y3QucGFjaygiSSIsIGdyb3VwX2lkICYgMHhGRkZGKSkKICAgICAg
ICByZXR1cm4gVHJ1ZQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZygiV0FS
TjogUEFDS0VUX0ZBTk9VVCBmYWlsZWQgKCVzKSDigJQgc2luZ2xlLXByb2Nlc3MgY2FwdHVyZSIg
JSBlKQogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBwYXJzZV9hcmdzKGFyZ3YpOgogICAgaWZh
Y2UgPSBOb25lCiAgICBwb3J0cyA9IFs4MCwgODAwMywgODAwNSwgODAwNywgODAwOSwgODAxMCwg
ODAxMV0KICAgIHZlcmJvc2UgPSBGYWxzZQogICAgd29ya2VycyA9IDEKICAgIGkgPSAwCiAgICB3
aGlsZSBpIDwgbGVuKGFyZ3YpOgogICAgICAgIGEgPSBhcmd2W2ldCiAgICAgICAgaWYgYSA9PSAi
LWkiOgogICAgICAgICAgICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICBy
YWlzZSBTeXN0ZW1FeGl0KCItaSByZXF1aXJlcyBhbiBpbnRlcmZhY2UiKQogICAgICAgICAgICBp
ICs9IDE7IGlmYWNlID0gYXJndltpXQogICAgICAgIGVsaWYgYSA9PSAiLXAiOgogICAgICAgICAg
ICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0
KCItcCByZXF1aXJlcyBhIGNvbW1hLXNlcGFyYXRlZCBwb3J0IGxpc3QiKQogICAgICAgICAgICBp
ICs9IDEKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcG9ydHMgPSBbaW50KHgpIGZv
ciB4IGluIGFyZ3ZbaV0uc3BsaXQoIiwiKSBpZiB4LnN0cmlwKCldCiAgICAgICAgICAgIGV4Y2Vw
dCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiaW52YWxpZCBw
b3J0IGxpc3QiKQogICAgICAgICAgICBpZiBub3QgcG9ydHMgb3IgYW55KG5vdCB2YWxpZF9wb3J0
KHgpIGZvciB4IGluIHBvcnRzKToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoInBv
cnRzIG11c3QgYmUgaW4gcmFuZ2UgMS4uNjU1MzUiKQogICAgICAgIGVsaWYgYSA9PSAiLWoiOgog
ICAgICAgICAgICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCItaiByZXF1aXJlcyBhIHdvcmtlciBjb3VudCIpCiAgICAgICAgICAgIGkgKz0g
MQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB3b3JrZXJzID0gbWF4KDEsIGludChh
cmd2W2ldKSkKICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICBy
YWlzZSBTeXN0ZW1FeGl0KCJpbnZhbGlkIHdvcmtlciBjb3VudCIpCiAgICAgICAgZWxpZiBhID09
ICItdiI6CiAgICAgICAgICAgIHZlcmJvc2UgPSBUcnVlCiAgICAgICAgZWxpZiBhIGluICgiLWgi
LCAiLS1oZWxwIik6CiAgICAgICAgICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0ZW1FeGl0
KDApCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5rbm93biBh
cmc6ICVzIiAlIGEpCiAgICAgICAgaSArPSAxCiAgICByZXR1cm4gaWZhY2UsIHNldChwb3J0cyks
IHZlcmJvc2UsIHdvcmtlcnMKCgpjbGFzcyBGbG93KG9iamVjdCk6CiAgICBfX3Nsb3RzX18gPSAo
ImJ1ZiIsICJoZHJzIiwgInRvdWNoZWQiKQogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAg
IHNlbGYuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICBzZWxmLmhkcnMgPSB7fQogICAgICAgIHNl
bGYudG91Y2hlZCA9IHRpbWUudGltZSgpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tIHJlc3BvbnNlIGNvcnJlbGF0aW9uIC0tLS0KUEVORElOR19U
VEwgPSA1LjAgICAgICAgICMgZmx1c2ggdW5tYXRjaGVkIHJlcXVlc3RzIGFmdGVyIHRoaXMgbWFu
eSBzZWNvbmRzClBFTkRJTkdfTUFYID0gODE5MiAgICAgICAjIGhhcmQgY2FwOyBvdmVyZmxvdyBm
bHVzaGVzIG9sZGVzdCBmaXJzdAoKIyBwZW5kaW5nWyhzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRw
b3J0KV0gIC0tIGtleSBpcyB0aGUgUkVTUE9OU0UgdHVwbGU6CiMgc2VydmVyLT5jbGllbnQuIFZh
bHVlOiBbZXZlbnQsIHJlcV90c10uIEEgbGlzdCBwZXIga2V5IGhhbmRsZXMgSFRUUAojIGtlZXAt
YWxpdmUgcGlwZWxpbmluZyAoc2V2ZXJhbCByZXF1ZXN0cyBiZWZvcmUgcmVzcG9uc2VzIGFycml2
ZSkuCnBlbmRpbmcgPSB7fQoKCmRlZiBwZW5kaW5nX2RlbChyayk6CiAgICBwZW5kaW5nLnBvcChy
aywgTm9uZSkKCgpkZWYgcGVuZGluZ19wb3AocmssIG91dCk6CiAgICAiIiJGbHVzaCB0aGUgb2xk
ZXN0IHBlbmRpbmcgZXZlbnQgZm9yIHRoaXMgcmVzcG9uc2UgdHVwbGUgKEZJTi9SU1Qgb3IKICAg
IG92ZXJmbG93IHBhdGgpLiBFbWl0cyB3aGF0ZXZlciB0aGUgZXZlbnQgaGFzIOKAlCBzdGF0dXMg
c3RheXMgbnVsbC4iIiIKICAgIGxzdCA9IHBlbmRpbmcuZ2V0KHJrKQogICAgaWYgbm90IGxzdDoK
ICAgICAgICByZXR1cm4gTm9uZQogICAgZXYsIF8gPSBsc3QucG9wKDApCiAgICBpZiBub3QgbHN0
OgogICAgICAgIHBlbmRpbmdfZGVsKHJrKQogICAgb3V0LmFwcGVuZChldikKICAgIHJldHVybiBl
dgoKCmRlZiBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxvYWQpOgogICAgIiIiRmlyc3QgbGluZSAn
SFRUUC8xLnggTk5OIC4uLicgLT4gKHN0YXR1c19pbnR8Tm9uZSwgY29udGVudF9sZW58Tm9uZSku
CiAgICBPbmx5IGxvb2tzIGF0IHdoYXQncyBpbiB0aGlzIHNlZ21lbnQ7IGhlYWRlcnMgZml0IG9u
ZSBzZWdtZW50IGZvciBhbGwKICAgIHJlYWxpc3RpYyBBUEkgcmVzcG9uc2VzLiIiIgogICAgdHJ5
OgogICAgICAgIGhlYWQgPSBwYXlsb2FkLnNwbGl0KGIiXHJcblxyXG4iLCAxKVswXQogICAgICAg
IGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxpdChiIlxuIikKICAgICAg
ICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAgICBpZiBsZW4oZmlyc3QpIDwgMiBvciBu
b3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6CiAgICAgICAgICAgIHJldHVybiBOb25l
LCBOb25lCiAgICAgICAgc3QgPSBpbnQoZmlyc3RbMV0pCiAgICBleGNlcHQgKFZhbHVlRXJyb3Is
IEluZGV4RXJyb3IpOgogICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBjbGVuID0gTm9uZQog
ICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBsb3cgPSBsbi5sb3dlcigpCiAgICAgICAg
aWYgbG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0aDoiKToKICAgICAgICAgICAgdHJ5Ogog
ICAgICAgICAgICAgICAgY2xlbiA9IGludChsbi5zcGxpdChiIjoiLCAxKVsxXS5zdHJpcCgpKQog
ICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIHBhc3MKICAgICAg
ICAgICAgYnJlYWsKICAgIHJldHVybiBzdCwgY2xlbgoKCmRlZiB2YWxpZF9wb3J0KHApOgogICAg
dHJ5OgogICAgICAgIHJldHVybiAxIDw9IGludChwKSA8PSA2NTUzNQogICAgZXhjZXB0IChUeXBl
RXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBiYXNpY191c2Vy
KHZhbHVlKToKICAgICIiIkF1dGhvcml6YXRpb24gaGVhZGVyIHZhbHVlIC0+ICh1c2VyfE5vbmUs
IHNjaGVtZXxOb25lKS4gQmFzaWMgb25seS4iIiIKICAgIHBhcnRzID0gdmFsdWUuc3RyaXAoKS5z
cGxpdChOb25lLCAxKQogICAgaWYgbGVuKHBhcnRzKSAhPSAyOgogICAgICAgIHJldHVybiBOb25l
LCBOb25lCiAgICBzY2hlbWUgPSBwYXJ0c1swXS5sb3dlcigpCiAgICBpZiBzY2hlbWUgPT0gImJh
c2ljIjoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBhZCA9IHBhcnRzWzFdLnN0cmlwKCkKICAg
ICAgICAgICAgaWYgbGVuKHBhZCkgPiAxMDI0OgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUs
IE5vbmUKICAgICAgICAgICAgcGFkICs9ICI9IiAqICgtbGVuKHBhZCkgJSA0KQogICAgICAgICAg
ICByYXcgPSBiYXNlNjQuYjY0ZGVjb2RlKHBhZCkKICAgICAgICAgICAgaWYgbGVuKHJhdykgPiA1
MTI6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBpZiBiIjoi
IGluIHJhdzoKICAgICAgICAgICAgICAgIHVzZXIgPSByYXcuc3BsaXQoYiI6IiwgMSlbMF0KICAg
ICAgICAgICAgICAgIHJldHVybiB1c2VyLmRlY29kZSgidXRmLTgiLCAicmVwbGFjZSIpWzo2NF0s
ICJiYXNpYyIKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICByZXR1cm4gTm9u
ZSwgTm9uZQogICAgZWxpZiBzY2hlbWUgPT0gImJlYXJlciI6CiAgICAgICAgcmV0dXJuIE5vbmUs
ICJiZWFyZXIiCiAgICByZXR1cm4gTm9uZSwgTm9uZQoKCmRlZiBmaW5pc2hfZXZlbnQoZmxvdywg
a2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KToKICAg
IGggPSBmbG93LmhkcnMKICAgIHVzZXIgPSBzY2hlbWUgPSBOb25lCiAgICBhdXRoeiA9IGguZ2V0
KCJhdXRob3JpemF0aW9uIikKICAgIGlmIGF1dGh6OgogICAgICAgIHVzZXIsIHNjaGVtZSA9IGJh
c2ljX3VzZXIoYXV0aHopCiAgICAjIFczQyB0cmFjZSBjb250ZXh0OiBob25vciBpbmNvbWluZyB0
cmFjZXBhcmVudCwgZWxzZSBnZW5lcmF0ZSBvbmUgc28KICAgICMgZXZlcnkgdHJhbnNhY3Rpb24g
Y2FycmllcyBhIHRyYWNlX2lkIGZvciBodWItc2lkZSBjb3JyZWxhdGlvbi4KICAgICMgTk9URSBw
eTIuNjogYnl0ZXMgaGFzIG5vIC5oZXgoKSDigJQgdXNlIGJpbmFzY2lpLmhleGxpZnkuCiAgICB0
cCA9IGguZ2V0KCJ0cmFjZXBhcmVudCIpCiAgICB0cmFjZV9pZCA9IE5vbmUKICAgIGlmIHRwOgog
ICAgICAgIHBhcnRzID0gdHAuc3BsaXQoIi0iKQogICAgICAgIGlmIGxlbihwYXJ0cykgPT0gNCBh
bmQgbGVuKHBhcnRzWzFdKSA9PSAzMjoKICAgICAgICAgICAgdHJhY2VfaWQgPSBwYXJ0c1sxXS5s
b3dlcigpCiAgICBpZiBub3QgdHJhY2VfaWQ6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBybmQg
PSBiaW5hc2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oMTYpKQogICAgICAgICAgICBybmQgPSBybmQu
ZGVjb2RlKCJhc2NpaSIpIGlmIGhhc2F0dHIocm5kLCAiZGVjb2RlIikgZWxzZSBybmQKICAgICAg
ICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBybmQgPSAoIiUwMzJ4IiAlIChpbnQodGlt
ZS50aW1lKCkgKiAxMDAwKSkpWy0zMjpdCiAgICAgICAgcGlkOCA9IGJpbmFzY2lpLmhleGxpZnko
b3MudXJhbmRvbSg4KSkKICAgICAgICBwaWQ4ID0gcGlkOC5kZWNvZGUoImFzY2lpIikgaWYgaGFz
YXR0cihwaWQ4LCAiZGVjb2RlIikgZWxzZSBwaWQ4CiAgICAgICAgdHAgPSAiMDAtJXMtJXMtMDEi
ICUgKHJuZCwgcGlkOCkKICAgICAgICB0cmFjZV9pZCA9IHJuZAogICAgZXYgPSB7CiAgICAgICAg
InRzIjogaW50KHRpbWUudGltZSgpKSwKICAgICAgICAiaG9zdCI6IG5vZGVfaG9zdCwKICAgICAg
ICAic3JjIjogInBjYXAiLAogICAgICAgICJzZXJ2aWNlIjogInBvcnQ6JWQiICUgZHBvcnQsCiAg
ICAgICAgIm1ldGhvZCI6IGguZ2V0KCJfbWV0aG9kIikgb3IgIi0iLAogICAgICAgICJwYXRoIjog
KGguZ2V0KCJfcGF0aCIpIG9yICItIikuc3BsaXQoIj8iLCAxKVswXVs6MTIwXSwKICAgICAgICAi
dXNlciI6IHVzZXIsCiAgICAgICAgInNjaGVtZSI6IHNjaGVtZSwKICAgICAgICAicGlkIjogTm9u
ZSwKICAgICAgICAic291cmNlX3Byb2JlIjogInBjYXAtaHR0cCIsCiAgICAgICAgImhvc3RfaGRy
IjogaC5nZXQoImhvc3QiKSwKICAgICAgICAidXNlcl9hZ2VudCI6IGguZ2V0KCJ1c2VyLWFnZW50
IiksCiAgICAgICAgInhfZm9yd2FyZGVkX2ZvciI6IGguZ2V0KCJ4LWZvcndhcmRlZC1mb3IiKSwK
ICAgICAgICAiY2FsbGVyIjogc3JjX2lwLAogICAgICAgICJjYWxsZXJfcG9ydCI6IHNwb3J0LAog
ICAgICAgICJkc3RfaXAiOiBkc3RfaXAsCiAgICAgICAgImRzdF9wb3J0IjogZHBvcnQsCiAgICAg
ICAgIyAtLS0tIG1vbml0b3Jpbmcgc2NoZW1hIChvcHMgQVBJLWxvZyBmb3JtYXQpIC0tLS0KICAg
ICAgICAjIHN0YXR1cy9kdXJhdGlvbl9tcy9yZXNwX2J5dGVzIGFyZSByZXNwb25zZS1zaWRlOiBw
YXNzaXZlIHJlcXVlc3Qtb25seQogICAgICAgICMgY2FwdHVyZSBjYW5ub3Qgc2VlIHRoZW07IGxl
ZnQgbnVsbCBmb3IgdGhlIGh1YiB0byBlbnJpY2ggb3IgbGVhdmUuCiAgICAgICAgInRyYWNlcGFy
ZW50IjogdHBbOjgwXSwKICAgICAgICAidHJhY2VfaWQiOiB0cmFjZV9pZCwKICAgICAgICAic2Vy
dmljZV9pZCI6IE5vbmUsICAgICAgICAgICMgaHViIG1hcHMgcG9ydC0+c2VydmljZSB2aWEgcG9s
aWN5IGxhdGVyCiAgICAgICAgIm1vZHVsZV9pZCI6ICJwY2FwLWh0dHAiLAogICAgfQogICAgIyBQ
cmVzZXJ2ZSByZXNwb25zZSBjb3JyZWxhdGlvbiBvbmx5IGZvciBtb25pdG9yZWQgZGVzdGluYXRp
b25zLiBUaGUKICAgICMgcmVzcG9uc2Utc2lkZSBmaWx0ZXIgbWF5IHN0aWxsIGFkbWl0IGEgY2xp
ZW50IGVwaGVtZXJhbCBzcG9ydCBlcXVhbCB0byBhCiAgICAjIG1vbml0b3JlZCBwb3J0OyB0aGlz
IGlzIGhhcm1sZXNzIGJlY2F1c2UgcGFyc2VfcmVzcG9uc2VfaGVhZCByZWplY3RzIGl0LgogICAg
cmV0dXJuIGV2IGlmIChkcG9ydCBpbiBwb3J0cyBvciBoLmdldCgiX21ldGhvZCIpKSBlbHNlIE5v
bmUKCgpkZWYgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2X2tleSwgcGF5bG9hZCwgbWV0
YSwgcG9ydHMsIG5vZGVfaG9zdCwgb3V0LAogICAgICAgICAgICAgICAgICAgcGVuZGluZ190Ymw9
Tm9uZSwgbm93PU5vbmUpOgogICAgIiIiRmVlZCBvbmUgZGlyZWN0aW9uJ3MgcGF5bG9hZDsgZW1p
dCBmaW5pc2hlZCBldmVudHMgdG8gb3V0KGxpc3QpLgoKICAgIEhFQURFUi1PTkxZIGNhcHR1cmU6
IHRoZSByZXF1ZXN0IGV2ZW50IGlzIGJ1aWx0IHRoZSBtb21lbnQgXFxyXFxuXFxyXFxuIGlzCiAg
ICBzZWVuLiBXaXRoIHJlc3BvbnNlIGNvcnJlbGF0aW9uIGVuYWJsZWQgKHBlbmRpbmdfdGJsKSwg
dGhlIGZpbmlzaGVkCiAgICBldmVudCBnb2VzIGludG8gdGhlIHBlbmRpbmcgdGFibGUgaW5zdGVh
ZCBvZiBvdXQg4oCUIGl0IGlzIGVtaXR0ZWQgd2hlbgogICAgdGhlIG1hdGNoaW5nIHJlc3BvbnNl
IGhlYWQgYXJyaXZlcywgb3Igb24gVFRML3RlYXJkb3duIGZhbGxiYWNrLgogICAgUmVxdWVzdCBi
b2RpZXMgYXJlIE5PVCBidWZmZXJlZCDigJQgQmFzaWMgYXV0aCAoYWxsIHdlIG1pbmUpIHJpZGVz
IGhlYWRlcnMsCiAgICBzbyBib2R5IGJ5dGVzIGNvc3QgbWVtb3J5IGFuZCBkZWxheSBldmVudHMg
Zm9yIHplcm8gaW5mb3JtYXRpb24uIEEgbGF0ZXIKICAgIHNlZ21lbnQgb24gdGhlIHNhbWUgY29u
bmVjdGlvbiBzaW1wbHkgZmFpbHMgdGhlIHJlcXVlc3QtbGluZSBjaGVjayBhbmQKICAgIGlzIGRp
c2NhcmRlZC4iIiIKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBp
ZiBub3QgdmFsaWRfcG9ydChkcG9ydCkgb3Igbm90IHZhbGlkX3BvcnQoc3BvcnQpOgogICAgICAg
IHJldHVybgogICAgZmwgPSBmbG93cy5nZXQoa2V5KQogICAgaWYgZmwgaXMgTm9uZToKICAgICAg
ICBmbCA9IEZsb3coKQogICAgICAgIGZsb3dzW2tleV0gPSBmbAogICAgICAgIGlmIGxlbihmbG93
cykgPiBNQVhfRkxPV1M6CiAgICAgICAgICAgIGVuZm9yY2VfbGltaXQoZmxvd3MsIHRpbWUudGlt
ZSgpKQogICAgZmwudG91Y2hlZCA9IHRpbWUudGltZSgpCiAgICBmbC5idWYuZXh0ZW5kKGJ5dGVh
cnJheShwYXlsb2FkKSkKCiAgICBpZHggPSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgIGlm
IGlkeCA8IDA6CiAgICAgICAgaWYgbGVuKGZsLmJ1ZikgPiBNQVhfSERSUzoKICAgICAgICAgICAg
Zmxvd3MucG9wKGtleSwgTm9uZSkKICAgICAgICByZXR1cm4KICAgIGhlYWQgPSBieXRlcyhmbC5i
dWZbOmlkeF0pCiAgICBsaW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQo
YiJcbiIpCiAgICBoZHJzID0ge30KICAgIGZpcnN0ID0gbGluZXNbMF0uc3RyaXAoKS5zcGxpdCgp
CiAgICBpZiBsZW4oZmlyc3QpID49IDIgYW5kIGZpcnN0WzBdIGluIFsKICAgICAgICAgICAgbS5l
bmNvZGUoKSBmb3IgbSBpbiBNRVRIT0RTXToKICAgICAgICBoZHJzWyJfbWV0aG9kIl0gPSBmaXJz
dFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgICAgIGhkcnNbIl9wYXRoIl0gPSBm
aXJzdFsxXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgZWxzZToKICAgICAgICBmbG93
cy5wb3Aoa2V5LCBOb25lKSAgICAgICAjIG5vdCBhIHJlcXVlc3Qgc3RhcnQKICAgICAgICByZXR1
cm4KICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAgICAgICAgaWYgYiI6IiBub3QgaW4gbG46CiAg
ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAga24sIGt2ID0gbG4uc3BsaXQoYiI6IiwgMSkKICAg
ICAgICBoZHJzW2tuLnN0cmlwKCkubG93ZXIoKS5kZWNvZGUoCiAgICAgICAgICAgICJhc2NpaSIs
ICJyZXBsYWNlIildID0ga3Yuc3RyaXAoKS5kZWNvZGUoCiAgICAgICAgICAgICAgICAidXRmLTgi
LCAicmVwbGFjZSIpWzoxODBdCiAgICBmbC5oZHJzID0gaGRycwogICAgZXYgPSBmaW5pc2hfZXZl
bnQoZmwsIGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCwKICAgICAgICAgICAgICAg
ICAgICAgIHBvcnRzLCBub2RlX2hvc3QpCiAgICBkZWwgZmxvd3Nba2V5XQogICAgaWYgbm90IGV2
OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gaWR4ICsgNCAgICAgICAgICAj
IGNhcHR1cmVkIHJlcXVlc3QgaGVhZCArIHRlcm1pbmF0b3IKICAgIGlmIHBlbmRpbmdfdGJsIGlz
IE5vbmU6CiAgICAgICAgb3V0LmFwcGVuZChldikgICAgICAgICAgICAgICAgICMgY29ycmVsYXRp
b24gZGlzYWJsZWQgKGxlZ2FjeSBwYXRoKQogICAgICAgIHJldHVybgogICAgIyBxdWV1ZSBmb3Ig
cmVzcG9uc2UgY29ycmVsYXRpb247IGtleSBpcyB0aGUgUkVTUE9OU0UgdHVwbGUKICAgIHJrID0g
KGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpCiAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQo
cmspCiAgICBpZiBlbnQgaXMgTm9uZToKICAgICAgICBpZiBsZW4ocGVuZGluZ190YmwpID49IFBF
TkRJTkdfTUFYOgogICAgICAgICAgICBfZmx1c2hfb2xkZXN0X3BlbmRpbmcocGVuZGluZ190Ymws
IG91dCkKICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10gPSBbXQogICAgZW50LmFwcGVuZChb
ZXYsIG5vdyBpZiBub3cgaXMgbm90IE5vbmUgZWxzZSB0aW1lLnRpbWUoKV0pCgoKZGVmIHN3ZWVw
X2lkbGUoZmxvd3MsIG5vdyk6CiAgICBzdGFsZSA9IFtdCiAgICBmb3IgaywgZmwgaW4gZmxvd3Mu
aXRlbXMoKToKICAgICAgICBpZiBub3cgLSBmbC50b3VjaGVkID4gRkxPV19UVEw6CiAgICAgICAg
ICAgIHN0YWxlLmFwcGVuZChrKQogICAgZm9yIGsgaW4gc3RhbGU6CiAgICAgICAgZGVsIGZsb3dz
W2tdCgoKZGVmIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToKICAgICIi
Ik92ZXJmbG93IGd1YXJkOiBlbWl0IHRoZSBzaW5nbGUgb2xkZXN0IHBlbmRpbmcgZXZlbnQgYXMt
aXMuIiIiCiAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSBOb25lLCBOb25lCiAgICBmb3Igcmss
IGxzdCBpbiBwZW5kaW5nX3RibC5pdGVtcygpOgogICAgICAgIHRzID0gbHN0WzBdWzFdCiAgICAg
ICAgaWYgb2xkZXN0X3RzIGlzIE5vbmUgb3IgdHMgPCBvbGRlc3RfdHM6CiAgICAgICAgICAgIG9s
ZGVzdF9rZXksIG9sZGVzdF90cyA9IHJrLCB0cwogICAgaWYgb2xkZXN0X2tleSBpcyBub3QgTm9u
ZToKICAgICAgICBwZW5kaW5nX3BvcChvbGRlc3Rfa2V5LCBvdXQpCgoKZGVmIHN3ZWVwX3BlbmRp
bmcocGVuZGluZ190YmwsIG5vdywgb3V0KToKICAgICIiIlRUTCBmbHVzaDogZW1pdCByZXF1ZXN0
cyB3aG9zZSByZXNwb25zZXMgbmV2ZXIgc2hvd2VkIHVwLiIiIgogICAgc3RhbGUgPSBbXQogICAg
Zm9yIHJrLCBsc3QgaW4gcGVuZGluZ190YmwuaXRlbXMoKToKICAgICAgICBpZiBub3cgLSBsc3Rb
MF1bMV0gPiBQRU5ESU5HX1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKHJrKQogICAgZm9y
IHJrIGluIHN0YWxlOgogICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQpCgoKZGVmIGVuZm9yY2Vf
bGltaXQoZmxvd3MsIG5vdyk6CiAgICAiIiJDYXAgZmxvdy10YWJsZSBzaXplIChweTIuNjogbm8g
T3JkZXJlZERpY3Qg4oCUIHN3ZWVwIHN0YWxlLCB0aGVuIEZJRk8KICAgIGJ5IGluc2VydGlvbiBv
cmRlciwgd2hpY2ggcGxhaW4gZGljdHMgcHJlc2VydmUgaW4gQ1B5dGhvbikuIiIiCiAgICBzd2Vl
cF9pZGxlKGZsb3dzLCBub3cpCiAgICB3aGlsZSBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAg
ICAgIGZsb3dzLnBvcGl0ZW0oKSAgICAgICAgICAjIG9sZGVzdC1pbnNlcnRlZCBrZXkgb24gQ1B5
dGhvbiAyLjYvMi43CgoKZGVmIG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwgd29y
a2VycyA9IHBhcnNlX2FyZ3Moc3lzLmFyZ3ZbMTpdKQogICAgbm9kZV9ob3N0ID0gc29ja2V0Lmdl
dGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQoKICAgIHRyeToKICAgICAgICAjIHByb3RvY29sIE1V
U1QgYmUgaHRvbnMoRVRIX1BfQUxMKSB0byByZWNlaXZlIGJvdGggSU5HUkVTUyAocmVxKSBhbmQK
ICAgICAgICAjIEVHUkVTUyAocmVzcCkgcGFja2V0cyBvbiBMaW51eCBrZXJuZWwgcGFja2V0IHNv
Y2tldHMuCiAgICAgICAgcyA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX1BBQ0tFVCwgc29ja2V0
LlNPQ0tfUkFXLAogICAgICAgICAgICAgICAgICAgICAgICAgIHNvY2tldC5odG9ucyhFVEhfUF9B
TEwpKQogICAgZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQo
IkFGX1BBQ0tFVCB1bmF2YWlsYWJsZSBvbiB0aGlzIHBsYXRmb3JtIikKICAgIGV4Y2VwdCBzb2Nr
ZXQuZXJyb3IgYXMgZToKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5ub3Qgb3BlbiBBRl9Q
QUNLRVQgc29ja2V0ICglcykg4oCUIG5lZWQgIgogICAgICAgICAgICAgICAgICAgICAgICAgIkNB
UF9ORVRfUkFXIC8gcm9vdCIgJSBlKQogICAgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKQogICAg
dHJ5OgogICAgICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIsIHNvY2tldC5odG9ucyhFVEhfUF9BTEwp
KSkKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3I6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzLmJp
bmQoKCIiLCBzb2NrZXQuaHRvbnMoRVRIX1BfQUxMKSkpCiAgICAgICAgZXhjZXB0IHNvY2tldC5l
cnJvcjoKICAgICAgICAgICAgcGFzcwogICAgZmFub3V0X29rID0gRmFsc2UKICAgIGlmIHdvcmtl
cnMgPiAxOgogICAgICAgIGZhbm91dF9vayA9IGFwcGx5X2Zhbm91dChzLCAweEYwMEQpCiAgICAg
ICAgaWYgZmFub3V0X29rOgogICAgICAgICAgICBsb2coImZhbm91dCBncm91cCAweEYwMEQ6IHNw
YXduaW5nICVkIHdvcmtlcnMiICUgd29ya2VycykKCiAgICAjIHByZWNvbXBpbGVkIHN0cnVjdCBy
ZWFkZXJzIOKAlCB1bnBhY2tfZnJvbSByZWFkcyBzdHJhaWdodCBvdXQgb2YgdGhlCiAgICAjIHBh
Y2tldCBidWZmZXIgKG5vIHNsaWNlIGNvcGllcykgYW5kIHlpZWxkcyBpbnRzIHVuZGVyIHB5MiBB
TkQgcHkzCiAgICB1MTYgPSBzdHJ1Y3QuU3RydWN0KCIhSCIpLnVucGFja19mcm9tCiAgICB1aCA9
IHN0cnVjdC5TdHJ1Y3QoIiFISCIpLnVucGFja19mcm9tICAgIyBzcG9ydCxkcG9ydCBpbiBvbmUg
cmVhZAogICAgdWIgPSBzdHJ1Y3QuU3RydWN0KCIhQkIiKS51bnBhY2tfZnJvbQogICAgbnRvYSA9
IHNvY2tldC5pbmV0X250b2EKCiAgICBmbG93cyA9IHt9CiAgICBydW5uaW5nID0gW1RydWVdCgog
ICAgZGVmIHN0b3Aoc2lnbnVtLCBmcmFtZSk6CiAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAg
ICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChz
aWduYWwuU0lHSU5ULCBzdG9wKQoKICAgIGxhc3Rfc3dlZXAgPSB0aW1lLnRpbWUoKQogICAgbG9n
KCJsaXN0ZW5pbmcgb24gJXMgcG9ydHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8
YWxsPiIsIHNvcnRlZChwb3J0cyksIG9zLmdldHBpZCgpKSkKCiAgICAjIGZvcmsgZXh0cmEgY2Fw
dHVyZSB3b3JrZXJzIEFGVEVSIGZhbm91dCBhdHRhY2g7IFdJVEhPVVQgYSB3b3JraW5nCiAgICAj
IGZhbm91dCBncm91cCBldmVyeSBwcm9jZXNzIHdvdWxkIHJlY2VpdmUgRVZFUlkgcGFja2V0IChk
dXBsaWNhdGVzKSwKICAgICMgc28gc2luZ2xlLXByb2Nlc3MgbW9kZSBpcyBmb3JjZWQgd2hlbiB0
aGUga2VybmVsIGxhY2tzIHN1cHBvcnQKICAgICMgKFBBQ0tFVF9GQU5PVVQgbmVlZHMga2VybmVs
ID49IDMuMTsgZWw2IDIuNi4zMiBkb2VzIG5vdCBoYXZlIGl0KQogICAgaWYgZmFub3V0X29rOgog
ICAgICAgIGZvciBfIGluIHJhbmdlKHdvcmtlcnMgLSAxKToKICAgICAgICAgICAgaWYgb3MuZm9y
aygpID09IDA6CiAgICAgICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAgIyBjaGlsZDog
ZmFsbCB0aHJvdWdoIGludG8gaXRzIG93biBsb29wCgogICAgIyAxcyByZWN2IHRpbWVvdXQ6IChh
KSBsZXRzIHRoZSBwZW5kaW5nL2Zsb3cgc3dlZXBzIGFjdHVhbGx5IGZpcmUg4oCUCiAgICAjIHdp
dGhvdXQgaXQgYGV4Y2VwdCBzb2NrZXQudGltZW91dGAgbmV2ZXIgcnVuczsgKGIpIGVtcGlyaWNh
bGx5IFJFUVVJUkVECiAgICAjIHdpdGggdGhlIEJQRiBmaWx0ZXIgYXR0YWNoZWQ6IGEgZnVsbHkt
YmxvY2tpbmcgcmVjdiBvbiB0aGlzIGtlcm5lbAogICAgIyBzdGFydmVzIGFmdGVyIHRoZSBmaXJz
dCBwYWNrZXQsIHdoaWxlIHRoZSB0aW1lb3V0J2QgcmVjdiBkZWxpdmVycwogICAgIyBjb250aW51
b3VzbHkgKHZlcmlmaWVkIGJ5IEEvQjogcng9MSB2cyByeD0yOSBpZGVudGljYWwgb3RoZXJ3aXNl
KS4KICAgIHMuc2V0dGltZW91dCgxLjApCgogICAgZGJnID0gb3MuZW52aXJvbi5nZXQoIk5UX1NO
SUZGX0RFQlVHIikgPT0gIjEiCiAgICBkYmdfcnggPSAwCiAgICBkYmdfbGFzdCA9IHRpbWUudGlt
ZSgpCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGt0ID0g
cy5yZWN2KDY1NTM1KQogICAgICAgICAgICBkYmdfcnggKz0gMQogICAgICAgICAgICBpZiBkYmcg
YW5kIHRpbWUudGltZSgpIC0gZGJnX2xhc3QgPiA1OgogICAgICAgICAgICAgICAgbG9nKCJERUJV
RyByeD0lZCIgJSBkYmdfcngpCiAgICAgICAgICAgICAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgp
CiAgICAgICAgZXhjZXB0IHNvY2tldC50aW1lb3V0OgogICAgICAgICAgICBpZiBkYmc6CiAgICAg
ICAgICAgICAgICBsb2coIkRFQlVHIHRpbWVvdXQgcng9JWQiICUgZGJnX3J4KQogICAgICAgICAg
ICAgICAgZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAgICAgICBub3cgPSB0aW1lLnRpbWUo
KQogICAgICAgICAgICBpZiBub3cgLSBsYXN0X3N3ZWVwID4gMzA6CiAgICAgICAgICAgICAgICBz
d2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAg
ICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0X3MpCiAgICAgICAgICAgICAg
ICBmb3IgZXYgaW4gb3V0X3M6CiAgICAgICAgICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0ZShq
c29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgICAgICBpZiBvdXRfczoKICAgICAgICAg
ICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICAgICAgICAgIGxhc3Rfc3dlZXAg
PSBub3cKICAgICAgICAgICAgY29udGludWUKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9yIGFz
IGU6CiAgICAgICAgICAgIGlmIGUuZXJybm8gPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAg
ICBjb250aW51ZQogICAgICAgICAgICByYWlzZQogICAgICAgIG4gPSBsZW4ocGt0KQogICAgICAg
IGlmIG4gPCAzNDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBvdXQgPSBbXQogICAgICAg
IG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRoZXJuZXQgaGVhZGVyCiAgICAgICAg
ZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBldHlwZSA9PSBFVEhfUF9WTEFOOgog
ICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQogICAgICAgICAgICBvZmYgPSAxOAog
ICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAgICAgICAgIGNvbnRpbnVlICAgICAg
ICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlzIHJhcmUKICAgICAgICBpcDAg
PSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4gNCAhPSA0IG9yIHViKHBrdCwgb2Zm
ICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAgY29udGludWUKICAg
ICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAgZnJhZyA9IHUxNihwa3QsIG9mZiAr
IDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAgICAgICAgICAgICAgICAgICAgICAg
IyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzcmNfaXAg
PSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAgICAgZHN0X2lwID0gbnRvYShwa3Rb
b2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYgPSBvZmYgKyBpaGwKICAgICAgICBz
cG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAgICAgZG9mZl9mbGFncyA9IHViKHBr
dCwgdGNwX29mZiArIDEyKQogICAgICAgIGRvZmYgPSAoZG9mZl9mbGFnc1swXSA+PiA0KSAqIDQK
ICAgICAgICBwYXlfc3RhcnQgPSB0Y3Bfb2ZmICsgZG9mZgogICAgICAgIGlmIG4gPD0gcGF5X3N0
YXJ0OgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICMg
bm8gcGF5bG9hZCBpbiBzZWdtZW50CiAgICAgICAgcGF5bG9hZCA9IHBrdFtwYXlfc3RhcnQ6XQog
ICAgICAgIGZsYWdzID0gZG9mZl9mbGFnc1sxXQogICAgICAgIG5vdyA9IHRpbWUudGltZSgpCgog
ICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLSBSRVNQT05TRSBkaXJlY3Rpb24gKHNlcnZlciAtPiBj
bGllbnQpIC0tLS0tLS0tLS0KICAgICAgICBpZiBzcG9ydCBpbiBwb3J0cyBhbmQgZHBvcnQgbm90
IGluIHBvcnRzOgogICAgICAgICAgICAjIHBlbmRpbmcga2V5IHdhcyBzdG9yZWQgYXMgKHNlcnZl
cl9pcCwgc2VydmVyX3BvcnQsIGNsaWVudF9pcCwKICAgICAgICAgICAgIyBjbGllbnRfcG9ydCkg
PT0gKHNyYywgc3BvcnQsIGRzdCwgZHBvcnQpIE9GIFRISVMgcmVzcG9uc2UgcGt0CiAgICAgICAg
ICAgIHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgICAgIGlmIHBh
eWxvYWRbOjVdID09IGIiSFRUUC8iOgogICAgICAgICAgICAgICAgc3QsIGNsZW4gPSBwYXJzZV9y
ZXNwb25zZV9oZWFkKHBheWxvYWQpCiAgICAgICAgICAgICAgICBlbnQgPSBwZW5kaW5nLmdldChy
aykKICAgICAgICAgICAgICAgIGlmIGVudCBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAg
ICBldiA9IGVudFswXVswXQogICAgICAgICAgICAgICAgICAgIGV2WyJzdGF0dXMiXSA9IHN0CiAg
ICAgICAgICAgICAgICAgICAgZXZbImR1cmF0aW9uX21zIl0gPSBpbnQoKG5vdyAtIGVudFswXVsx
XSkgKiAxMDAwKQogICAgICAgICAgICAgICAgICAgIGlmIGNsZW4gaXMgbm90IE5vbmU6CiAgICAg
ICAgICAgICAgICAgICAgICAgIGV2WyJyZXNwX2J5dGVzIl0gPSBjbGVuCiAgICAgICAgICAgICAg
ICAgICAgcGVuZGluZ19kZWwocmspCiAgICAgICAgICAgICAgICAgICAgb3V0LmFwcGVuZChldikK
ICAgICAgICAgICAgZWxpZiBmbGFncyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgRklO
fFJTVDogZmx1c2ggdW5tYXRjaGVkCiAgICAgICAgICAgICAgICBldiA9IHBlbmRpbmdfcG9wKHJr
LCBvdXQpCiAgICAgICAgIyAtLS0tLS0tLS0tLS0tLS0tIFJFUVVFU1QgZGlyZWN0aW9uIChjbGll
bnQgLT4gc2VydmVyKSAtLS0tLS0tLS0tLQogICAgICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAg
ICAgICAgICAgIGlmIGZsYWdzICYgMHgwNTogICAgICAgICAgICAgICAgICAgICAgIyB0ZWFyZG93
biB3L28gcmVzcG9uc2Ugc2VlbgogICAgICAgICAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwg
c3JjX2lwLCBzcG9ydCkKICAgICAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAg
ICAgICAgIGtleSA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBo
YW5kbGVfcGF5bG9hZChmbG93cywga2V5LCBOb25lLCBwYXlsb2FkLAogICAgICAgICAgICAgICAg
ICAgICAgICAgICAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgIHBvcnRzLCBub2RlX2hvc3QsIG91dCwgcGVuZGluZywgbm93KQogICAgICAg
IGlmIG91dDoKICAgICAgICAgICAgdyA9IHN5cy5zdGRvdXQud3JpdGUKICAgICAgICAgICAgZm9y
IGV2IGluIG91dDoKICAgICAgICAgICAgICAgIHcoanNvbi5kdW1wcyhldikgKyAiXG4iKQogICAg
ICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKCiAgICBsb2coInN0b3BwZWQiKQoKCmlmIF9fbmFt
ZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
#__END_SNIFF__
#__SHIP_B64__
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMgLSotIGNvZGluZzogdXRmLTggLSotCiIiIm50LXNoaXAu
cHkg4oCUIGV2ZW50IHNoaXBwZXIgZm9yIG9sZC1rZXJuZWwgbm9kZXMgKHB5dGhvbiAyLjYgY29t
cGF0aWJsZSkuCgpSZWFkcyBOZXR3b3JrVHJhY2luZyBKU09OTCBldmVudHMgb24gc3RkaW4sIGJh
dGNoZXMgdGhlbSwgUE9TVHMgdG8gdGhlIGh1YgovYXBpL2luZ2VzdC4gU3Bvb2xzIHVuZGVsaXZl
cmVkIGJhdGNoZXMgdG8gYSBkaXNrIGZpbGUgYW5kIHJldHJpZXMgd2l0aApiYWNrb2ZmIOKAlCBz
YW1lIGF0LWxlYXN0LW9uY2Ugc2VtYW50aWNzIGFzIG50LWFnZW50LnB5IC8gR28gYWdlbnQuCgpV
c2FnZToKICBweXRob24gbnQtc2hpcC5weSAtLWVuZHBvaW50IGh0dHA6Ly9odWI6MzExMTUgWy0t
c3Bvb2wgL3Zhci9saWIvbnQvc3Bvb2wuanNvbmxdCiIiIgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0
IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBlcnJubywganNvbiwgb3MsIHNlbGVjdCwg
c2lnbmFsLCBzb2NrZXQsIHN5cwoKIyBweTIuNi9lbDYgbmFtZXMgZmlyc3Q7IHB5MyBmYWxsYmFj
a3MgZm9yIGRldi1ib3ggdGVzdGluZy4gVGhlIHVybGxpYjIKIyBzdHItdnMtYnl0ZXMgZW5jb2Rl
IGd1YXJkIGluIGZsdXNoKCkgc3RheXMg4oCUIGRvIG5vdCByZW1vdmUuCnRyeToKICAgIGltcG9y
dCBRdWV1ZSAgICAgICAgICAgICAgICAgICAgICAjIHB5MjogUXVldWUgbW9kdWxlLCBjbGFzcyBR
dWV1ZS5RdWV1ZQogICAgaW1wb3J0IHVybGxpYjIKZXhjZXB0IEltcG9ydEVycm9yOiAgICAgICAg
ICAgICAgICAgICAjIHB5MwogICAgaW1wb3J0IHF1ZXVlIGFzIFF1ZXVlCiAgICBpbXBvcnQgdXJs
bGliLnJlcXVlc3QgYXMgdXJsbGliMgppbXBvcnQgdGhyZWFkaW5nLCB0aW1lCgpNQVhfQkFUQ0gg
PSA0MDAKRkxVU0hfU0VDID0gNS4wClJFVFJZX01BWCA9IDg2NDAwLjAgICAgICAgICMga2VlcCBz
cG9vbC1yZXRyeWluZyBmb3IgYSBkYXkgYmVmb3JlIGdpdmluZyB1cAoKCmRlZiBsb2cobXNnKToK
ICAgIHN5cy5zdGRlcnIud3JpdGUoIm50LXNoaXA6ICVzXG4iICUgbXNnKQogICAgc3lzLnN0ZGVy
ci5mbHVzaCgpCgoKZGVmIG1haW4oKToKICAgIGVuZHBvaW50ID0gTm9uZQogICAgc3Bvb2wgPSAi
L3Zhci9saWIvbmV0d29ya3RyYWNpbmcvc25pZmYtc3Bvb2wuanNvbmwiCiAgICBhcmd2ID0gc3lz
LmFyZ3ZbMTpdCiAgICBpID0gMAogICAgd2hpbGUgaSA8IGxlbihhcmd2KToKICAgICAgICBhID0g
YXJndltpXQogICAgICAgIGlmIGEgPT0gIi0tZW5kcG9pbnQiOgogICAgICAgICAgICBpICs9IDE7
IGVuZHBvaW50ID0gYXJndltpXS5yc3RyaXAoIi8iKQogICAgICAgIGVsaWYgYSA9PSAiLS1zcG9v
bCI6CiAgICAgICAgICAgIGkgKz0gMTsgc3Bvb2wgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhIGlu
ICgiLWgiLCAiLS1oZWxwIik6CiAgICAgICAgICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0
ZW1FeGl0KDApCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5r
bm93biBhcmc6ICVzIiAlIGEpCiAgICAgICAgaSArPSAxCiAgICBpZiBub3QgZW5kcG9pbnQ6CiAg
ICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLS1lbmRwb2ludCByZXF1aXJlZCIpCgogICAgbm9kZSA9
IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICAjIHJlcGxheSBzcG9vbGVk
IGV2ZW50cyBmaXJzdCAoYXQtbGVhc3Qtb25jZSkKICAgIHBlbmRpbmcgPSBbXQogICAgaWYgb3Mu
cGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcGVuKHNw
b29sKSBhcyBmOgogICAgICAgICAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAg
ICAgICBsaW5lID0gbGluZS5zdHJpcCgpCiAgICAgICAgICAgICAgICAgICAgaWYgbGluZToKICAg
ICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVu
ZGluZy5hcHBlbmQoanNvbi5sb2FkcyhsaW5lKSkKICAgICAgICAgICAgICAgICAgICAgICAgZXhj
ZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAg
ICAgIG9zLnJlbW92ZShzcG9vbCkKICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpIGFz
IGU6CiAgICAgICAgICAgIGxvZygic3Bvb2wgcmVhZCBmYWlsZWQ6ICVzIiAlIGUpCgogICAgcnVu
bmluZyA9IFtUcnVlXQoKICAgIGRlZiBzdG9wKHNpZ251bSwgZnJhbWUpOgogICAgICAgIHJ1bm5p
bmdbMF0gPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgc3RvcCkKICAg
IHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0lOVCwgc3RvcCkKCiAgICBkZWYgZmx1c2goYmF0Y2gp
OgogICAgICAgIGlmIG5vdCBiYXRjaDoKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBi
b2R5ID0ganNvbi5kdW1wcyh7Im5vZGUiOiBub2RlLCAiZXZlbnRzIjogYmF0Y2h9KQogICAgICAg
ICMgcHkyIHVybGxpYjIgYWNjZXB0cyBzdHI7IHB5MyBzaGltL3Rlc3QgbmVlZHMgYnl0ZXMg4oCU
IGVuY29kZSB3aGVuCiAgICAgICAgIyB0aGUgcnVudGltZSBleHBvc2VzIGl0IChweTIgc3RyIGhh
cyBubyAuZW5jb2RlIG9uIGFsbCBidWlsZHMsIHNvCiAgICAgICAgIyBndWFyZCB3aXRoIGhhc2F0
dHIpCiAgICAgICAgaWYgaGFzYXR0cihib2R5LCAiZW5jb2RlIik6CiAgICAgICAgICAgIGJvZHkg
PSBib2R5LmVuY29kZSgidXRmLTgiKQogICAgICAgIHJlcSA9IHVybGxpYjIuUmVxdWVzdChlbmRw
b2ludCArICIvYXBpL2luZ2VzdCIsIGRhdGE9Ym9keSwKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgaGVhZGVycz17IkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAg
ICAgdHJ5OgogICAgICAgICAgICByZXNwID0gdXJsbGliMi51cmxvcGVuKHJlcSwgdGltZW91dD0x
MCkKICAgICAgICAgICAgb2sgPSAocmVzcC5nZXRjb2RlKCkgPT0gMjAwKQogICAgICAgICAgICBy
ZXNwLnJlYWQoKQogICAgICAgICAgICByZXNwLmNsb3NlKCkKICAgICAgICAgICAgaWYgb2s6CiAg
ICAgICAgICAgICAgICBsb2coImZsdXNoZWQgJWQgZXZlbnRzIiAlIGxlbihiYXRjaCkpCiAgICAg
ICAgICAgIHJldHVybiBvawogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAg
ICAgbG9nKCJzaGlwIGZhaWxlZDogJXMiICUgZSkKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgog
ICAgIyAtLS0tIGNvbmN1cnJlbnQgc2hpcHBpbmcgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLQogICAgIyBodWIgaW5nZXN0IGxhdGVuY3kgKH4zMDAtNTAwbXMgcGVy
IDQwMC1ldmVudCBQT1NUIG92ZXIgV0FOKSBtYWtlcwogICAgIyBzZXF1ZW50aWFsIHBvc3Rpbmcg
YSB+MTAwMCBldi9zIGNlaWxpbmc7IE4gcG9zdGVyIHRocmVhZHMgcG9zdGluZwogICAgIyBpbmRl
cGVuZGVudCBiYXRjaGVzIG11bHRpcGx5IHRoYXQgYnkgTlRfU0hJUF9USFJFQURTCiAgICBxID0g
UXVldWUuUXVldWUobWF4c2l6ZT0xMjgpCiAgICBzcG9vbF9sb2NrID0gdGhyZWFkaW5nLkxvY2so
KQogICAgbnRocmVhZHMgPSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NISVBfVEhSRUFEUyIsICI0
IikpCgogICAgZGVmIHBvc3RlcigpOgogICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgIGJh
dGNoID0gcS5nZXQoKQogICAgICAgICAgICBpZiBiYXRjaCBpcyBOb25lOgogICAgICAgICAgICAg
ICAgcS50YXNrX2RvbmUoKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIGZs
dXNoKGJhdGNoKToKICAgICAgICAgICAgICAgIGJhY2tvZmZfYm94WzBdID0gMQogICAgICAgICAg
ICBlbHNlOgogICAgICAgICAgICAgICAgd2l0aCBzcG9vbF9sb2NrOgogICAgICAgICAgICAgICAg
ICAgIF9zcG9vbF9hcHBlbmQoc3Bvb2wsIGJhdGNoKQogICAgICAgICAgICBxLnRhc2tfZG9uZSgp
CgogICAgYmFja29mZl9ib3ggPSBbMV0KICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAg
ICAgICB0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgIHQuZGFlbW9u
ID0gVHJ1ZQogICAgICAgIHQuc3RhcnQoKQoKICAgIGJ1ZiA9IGxpc3QocGVuZGluZykKICAgIGxh
c3RfZmx1c2ggPSB0aW1lLnRpbWUoKQogICAgbGFzdF9zcG9vbF90cnkgPSB0aW1lLnRpbWUoKQoK
ICAgIGRlZiBmb2xkX3Nwb29sKCk6CiAgICAgICAgIiIiUmUtcXVldWUgc3Bvb2xlZCBldmVudHMg
KG1pZC1ydW4gcmV0cnkpOyByZXR1cm5zIGNvdW50IGZvbGRlZC4iIiIKICAgICAgICBuID0gMAog
ICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcGVuKHNwb29sKSBhcyBmOgogICAgICAgICAg
ICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAgICAgICBsaW5lID0gbGluZS5zdHJp
cCgpCiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGxpbmU6CiAgICAgICAgICAgICAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAg
ICAgICBldiA9IGpzb24ubG9hZHMobGluZSkKICAgICAgICAgICAgICAgICAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAg
ICAgICBpZiBpc2luc3RhbmNlKGV2LCBkaWN0KToKICAgICAgICAgICAgICAgICAgICAgICAgYnVm
LmFwcGVuZChldikKICAgICAgICAgICAgICAgICAgICAgICAgbiArPSAxCiAgICAgICAgICAgIG9z
LnJlbW92ZShzcG9vbCkKICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpOgogICAgICAg
ICAgICBwYXNzCiAgICAgICAgcmV0dXJuIG4KCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAg
IHRyeToKICAgICAgICAgICAgciwgXywgXyA9IHNlbGVjdC5zZWxlY3QoW3N5cy5zdGRpbl0sIFtd
LCBbXSwgMS4wKQogICAgICAgIGV4Y2VwdCBzZWxlY3QuZXJyb3IgYXMgZToKICAgICAgICAgICAg
aWYgZVswXSA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAg
ICAgIGJyZWFrCgogICAgICAgIGlmIHI6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAg
IHJhdyA9IHN5cy5zdGRpbi5yZWFkbGluZSgpCiAgICAgICAgICAgIGV4Y2VwdCAoSU9FcnJvciwg
T1NFcnJvcikgYXMgZToKICAgICAgICAgICAgICAgIGlmIGdldGF0dHIoZSwgJ2Vycm5vJywgTm9u
ZSkgPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgIGlmIG5vdCByYXc6CiAgICAgICAgICAgICAgICBicmVh
ayAgICAgICAgICAgICAgICAgICMgRU9GCiAgICAgICAgICAgIHJhdyA9IHJhdy5zdHJpcCgpCiAg
ICAgICAgICAgIGlmIHJhdzoKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAg
ICBldiA9IGpzb24ubG9hZHMocmF3KQogICAgICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2Uo
ZXYsIGRpY3QpOgogICAgICAgICAgICAgICAgICAgICAgICBidWYuYXBwZW5kKGV2KQogICAgICAg
ICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgcGFzcwoKICAg
ICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIHdoaWxlIGxlbihidWYpID49IE1BWF9CQVRD
SCBvciAoYnVmIGFuZCBub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyk6CiAgICAgICAgICAg
IGxhc3RfZmx1c2ggPSBub3cKICAgICAgICAgICAgaWYgbm93IC0gbGFzdF9zcG9vbF90cnkgPj0g
NjAgYW5kIG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAgICAgICAgICAgIGxhc3Rfc3Bvb2xf
dHJ5ID0gbm93CiAgICAgICAgICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICAgICAgcS5wdXQo
YnVmWzpNQVhfQkFUQ0hdKQogICAgICAgICAgICBkZWwgYnVmWzpNQVhfQkFUQ0hdCgogICAgIyBz
dGRpbiBjbG9zZWQgKHNuaWZmZXIgc3RvcHBlZCkg4oCUIGRyYWluIHF1ZXVlLCB0aGVuIGtlZXAg
cmV0cnlpbmcKICAgICMgYW55dGhpbmcgc3Bvb2xlZCB1bnRpbCBpdCBsYW5kcyBvciBSRVRSWV9N
QVggZWxhcHNlcwogICAgZGVhZGxpbmUgPSB0aW1lLnRpbWUoKSArIFJFVFJZX01BWAogICAgcS5q
b2luKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF0gYW5kIHRpbWUudGltZSgpIDwgZGVhZGxpbmUgYW5k
IG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICBpZiBu
b3QgYnVmOgogICAgICAgICAgICBicmVhawogICAgICAgIGlmIGZsdXNoKGJ1Zik6CiAgICAgICAg
ICAgIGRlbCBidWZbOl0KICAgICAgICBlbHNlOgogICAgICAgICAgICB3aXRoIHNwb29sX2xvY2s6
CiAgICAgICAgICAgICAgICBfc3Bvb2xfYXBwZW5kKHNwb29sLCBidWYpCiAgICAgICAgICAgICAg
ICBkZWwgYnVmWzpdCiAgICAgICAgdGltZS5zbGVlcChtaW4oYmFja29mZl9ib3hbMF0sIDYwKSkK
ICAgICAgICBiYWNrb2ZmX2JveFswXSAqPSAyCiAgICAgICAgaWYgb3MucGF0aC5leGlzdHMoc3Bv
b2wpOgogICAgICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICBpZiBub3QgYnVmIGFuZCBub3Qg
b3MucGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgICAgICBicmVhawogICAgbG9nKCJzdG9wcGVk
ICglZCBldmVudHMgcGVuZGluZyBvbiBleGl0KSIgJSBsZW4oYnVmKSkKCiAgICBsb2coInN0b3Bw
ZWQgKCVkIGV2ZW50cyBwZW5kaW5nIG9uIGV4aXQpIiAlIGxlbihidWYpKQoKCmRlZiBfc3Bvb2xf
YXBwZW5kKHBhdGgsIGJhdGNoKToKICAgIGQgPSBvcy5wYXRoLmRpcm5hbWUocGF0aCkKICAgIHRy
eToKICAgICAgICBpZiBkIGFuZCBub3Qgb3MucGF0aC5pc2RpcihkKToKICAgICAgICAgICAgb3Mu
bWFrZWRpcnMoZCkKICAgICAgICB3aXRoIG9wZW4ocGF0aCwgImEiKSBhcyBmOgogICAgICAgICAg
ICBmb3IgZXYgaW4gYmF0Y2g6CiAgICAgICAgICAgICAgICBmLndyaXRlKGpzb24uZHVtcHMoZXYp
ICsgIlxuIikKICAgICAgICBkZWwgYmF0Y2hbOl0KICAgIGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJv
cikgYXMgZToKICAgICAgICBsb2coIkZBVEFMOiBjYW5ub3Qgd3JpdGUgc3Bvb2wgJXM6ICVzIiAl
IChwYXRoLCBlKSkKICAgICAgICBvcy5fZXhpdCgzKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5f
XyI6CiAgICBtYWluKCkK
#__END_SHIP__
#__CPP_SHIP_B64__
I2luY2x1ZGUgPHN0cmluZz4KI2luY2x1ZGUgPHZlY3Rvcj4KI2luY2x1ZGUgPGlvc3RyZWFtPgoj
aW5jbHVkZSA8ZnN0cmVhbT4KI2luY2x1ZGUgPHNzdHJlYW0+CiNpbmNsdWRlIDxjc3RkbGliPgoj
aW5jbHVkZSA8Y3N0ZGlvPgojaW5jbHVkZSA8Y3N0cmluZz4KI2luY2x1ZGUgPGNlcnJubz4KI2lu
Y2x1ZGUgPGN0aW1lPgojaW5jbHVkZSA8c3lzL3R5cGVzLmg+CiNpbmNsdWRlIDxzeXMvd2FpdC5o
PgojaW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxzaWduYWwuaD4KCnN0YXRpYyBjb25zdCBz
aXplX3QgTUFYX0JBVENIID0gNDAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9RVUVVRSA9IDEy
ODsKc3RhdGljIGNvbnN0IGludCBGTFVTSF9TRUMgPSA1OwpzdGF0aWMgY29uc3QgaW50IFJFVFJZ
X1NFQyA9IDYwOwpzdGF0aWMgdm9sYXRpbGUgc2lnX2F0b21pY190IHJ1bm5pbmcgPSAxOwpzdGF0
aWMgdm9pZCBzdG9wX3NpZ25hbChpbnQpIHsgcnVubmluZyA9IDA7IH0Kc3RhdGljIHZvaWQgbG9n
bXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7IHN0ZDo6Y2VyciA8PCAibnQtc2hpcC1jcHA6ICIg
PDwgcyA8PCBzdGQ6OmVuZGw7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIHNoZWxscShjb25zdCBzdGQ6
OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIG8gPSAiJyI7CiAgZm9yIChzaXplX3QgaT0wO2k8
cy5zaXplKCk7KytpKSB7IGlmIChzW2ldPT0nXCcnKSBvICs9ICInXFwnJyI7IGVsc2UgbyArPSBz
W2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGljIGJvb2wgcmVhZF9maWxlKGNvbnN0IHN0
ZDo6c3RyaW5nICZwLCBzdGQ6OnN0cmluZyAqb3V0KSB7CiAgc3RkOjppZnN0cmVhbSBmKHAuY19z
dHIoKSk7IGlmICghZikgcmV0dXJuIGZhbHNlOwogIHN0ZDo6b3N0cmluZ3N0cmVhbSBzczsgc3Mg
PDwgZi5yZGJ1ZigpOyAqb3V0ID0gc3Muc3RyKCk7IHJldHVybiB0cnVlOwp9CnN0YXRpYyBib29s
IHdyaXRlX2FwcGVuZChjb25zdCBzdGQ6OnN0cmluZyAmcCwgY29uc3Qgc3RkOjpzdHJpbmcgJmRh
dGEpIHsKICBzdGQ6OnN0cmluZyBkaXI9cC5zdWJzdHIoMCxwLmZpbmRfbGFzdF9vZignLycpKTsK
ICBpZiAoIWRpci5lbXB0eSgpKSB7IHN0ZDo6c3RyaW5nIGNtZD0ibWtkaXIgLXAgIitzaGVsbHEo
ZGlyKTsgaWYgKHN5c3RlbShjbWQuY19zdHIoKSkgIT0gMCkgcmV0dXJuIGZhbHNlOyB9CiAgc3Rk
OjpvZnN0cmVhbSBmKHAuY19zdHIoKSwgc3RkOjppb3M6Om91dHxzdGQ6Omlvczo6YXBwKTsgaWYg
KCFmKSByZXR1cm4gZmFsc2U7CiAgZiA8PCBkYXRhOyByZXR1cm4gZi5nb29kKCk7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIG51bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFt
IG87IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25fYXJy
YXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcgbz0i
WyI7IGZvcihzaXplX3QgaT0wO2k8YS5zaXplKCk7KytpKXtpZihpKW8rPSIsIjtvKz1hW2ldO30g
cmV0dXJuIG8rIl0iOwp9CnN0YXRpYyBib29sIHBvc3QoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBv
aW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwKICAgICAgICAgICAgICAgICBjb25zdCBzdGQ6
OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNoKSB7CiAgc3RkOjpzdHJpbmcgYm9keT0ie1wibm9k
ZVwiOlwiIitub2RlKyJcIixcImV2ZW50c1wiOiIranNvbl9hcnJheShiYXRjaCkrIn0iOwogIHN0
ZDo6c3RyaW5nIGNvZGVfZmlsZSA9ICIvdG1wL250X2NvZGUuIiArIG51bWJlcl9zdHJpbmcoZ2V0
cGlkKCkpOwogIHN0ZDo6c3RyaW5nIGNtZD0iY3VybCAtc1MgLS1tYXgtdGltZSAxNSAtbyAvZGV2
L251bGwgLXcgJyV7aHR0cF9jb2RlfScgLUggJ0NvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNv
bicgLS1kYXRhLWJpbmFyeSBALSAiK3NoZWxscShlbmRwb2ludCsiL2FwaS9pbmdlc3QiKSsiID4g
IitzaGVsbHEoY29kZV9maWxlKTsKICBGSUxFICpmcD1wb3BlbihjbWQuY19zdHIoKSwidyIpOyBp
ZighZnApcmV0dXJuIGZhbHNlOwogIGZ3cml0ZShib2R5LmRhdGEoKSwgMSwgYm9keS5zaXplKCks
IGZwKTsKICBpbnQgcmM9cGNsb3NlKGZwKTsKICBzdGQ6OnN0cmluZyBjb2RlOwogIHJlYWRfZmls
ZShjb2RlX2ZpbGUsICZjb2RlKTsKICB1bmxpbmsoY29kZV9maWxlLmNfc3RyKCkpOwogIHdoaWxl
ICghY29kZS5lbXB0eSgpICYmIChjb2RlW2NvZGUuc2l6ZSgpLTFdPT0nXHInIHx8IGNvZGVbY29k
ZS5zaXplKCktMV09PSdcbicgfHwgY29kZVtjb2RlLnNpemUoKS0xXT09JyAnKSkgY29kZS5lcmFz
ZShjb2RlLnNpemUoKS0xKTsKICByZXR1cm4gcmM9PTAgJiYgY29kZT09IjIwMCI7Cn0Kc3RhdGlj
IHZvaWQgc3Bvb2woY29uc3Qgc3RkOjpzdHJpbmcgJnBhdGgsIGNvbnN0IHN0ZDo6dmVjdG9yPHN0
ZDo6c3RyaW5nPiAmYmF0Y2gpIHsKICBzdGQ6OnN0cmluZyBkYXRhOyBmb3Ioc2l6ZV90IGk9MDtp
PGJhdGNoLnNpemUoKTsrK2kpZGF0YSs9YmF0Y2hbaV0rIlxuIjsKICBpZighd3JpdGVfYXBwZW5k
KHBhdGgsZGF0YSkpIHsgbG9nbXNnKCJGQVRBTDogY2Fubm90IHdyaXRlIHNwb29sIik7IGV4aXQo
Myk7IH0KfQpzdGF0aWMgdm9pZCBsb2FkX3Nwb29sKGNvbnN0IHN0ZDo6c3RyaW5nICZwYXRoLCBz
dGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gKmJ1ZikgewogIHN0ZDo6c3RyaW5nIGRhdGE7IGlmKCFy
ZWFkX2ZpbGUocGF0aCwmZGF0YSkpcmV0dXJuOwogIHN0ZDo6aXN0cmluZ3N0cmVhbSBpbihkYXRh
KTsgc3RkOjpzdHJpbmcgbGluZTsgd2hpbGUoc3RkOjpnZXRsaW5lKGluLGxpbmUpKSBpZighbGlu
ZS5lbXB0eSgpKSBidWYtPnB1c2hfYmFjayhsaW5lKTsKICB1bmxpbmsocGF0aC5jX3N0cigpKTsK
fQpzdGF0aWMgdm9pZCBzZW5kX2JhdGNoZXMoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LGNv
bnN0IHN0ZDo6c3RyaW5nICZub2RlLGNvbnN0IHN0ZDo6c3RyaW5nICZzcG9vbF9wYXRoLAogICAg
ICAgICAgICAgICAgICAgICAgICAgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICpidWYsIGJvb2wg
Zmx1c2hfYWxsKSB7CiAgd2hpbGUgKCFidWYtPmVtcHR5KCkgJiYgKGZsdXNoX2FsbCB8fCBidWYt
PnNpemUoKSA+PSBNQVhfQkFUQ0gpKSB7CiAgICBzaXplX3Qgbj1idWYtPnNpemUoKT49TUFYX0JB
VENIP01BWF9CQVRDSDpidWYtPnNpemUoKTsKICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBi
YXRjaChidWYtPmJlZ2luKCksYnVmLT5iZWdpbigpK24pOwogICAgaWYocG9zdChlbmRwb2ludCxu
b2RlLGJhdGNoKSkgeyBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7IGxv
Z21zZygiZmx1c2hlZCAiK251bWJlcl9zdHJpbmcobikrIiBldmVudHMiKTsgfQogICAgZWxzZSB7
IHNwb29sKHNwb29sX3BhdGgsYmF0Y2gpOyBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSxidWYtPmJl
Z2luKCkrbik7IGxvZ21zZygic3Bvb2xlZCAiK251bWJlcl9zdHJpbmcobikrIiBldmVudHMiKTsg
YnJlYWs7IH0KICB9Cn0KaW50IG1haW4oaW50IGFyZ2MsY2hhciAqKmFyZ3YpIHsKICBzdGQ6OnN0
cmluZyBlbmRwb2ludCwgc3Bvb2xfcGF0aD0iL3Zhci9saWIvbmV0d29ya3RyYWNpbmcvc25pZmYt
c3Bvb2wuanNvbmwiOyBpbnQgaTsKICBmb3IoaT0xO2k8YXJnYzsrK2kpe3N0ZDo6c3RyaW5nIGE9
YXJndltpXTsgaWYoYT09Ii0tZW5kcG9pbnQiJiZpKzE8YXJnYyllbmRwb2ludD1hcmd2WysraV07
IGVsc2UgaWYoYT09Ii0tc3Bvb2wiJiZpKzE8YXJnYylzcG9vbF9wYXRoPWFyZ3ZbKytpXTsgZWxz
ZSBpZihhPT0iLWgifHxhPT0iLS1oZWxwIil7c3RkOjpjb3V0PDwidXNhZ2U6IG50LXNoaXAtY3Bw
IC0tZW5kcG9pbnQgVVJMIFstLXNwb29sIFBBVEhdXG4iO3JldHVybiAwO30gZWxzZSB7c3RkOjpj
ZXJyPDwidW5rbm93biBhcmc6ICI8PGE8PCJcbiI7cmV0dXJuIDI7fX0KICBpZihlbmRwb2ludC5l
bXB0eSgpKXtzdGQ6OmNlcnI8PCItLWVuZHBvaW50IHJlcXVpcmVkXG4iO3JldHVybiAyO30KICBz
aWduYWwoU0lHVEVSTSxzdG9wX3NpZ25hbCk7IHNpZ25hbChTSUdJTlQsc3RvcF9zaWduYWwpOwog
IGNoYXIgaG9zdFsyNTZdOyBnZXRob3N0bmFtZShob3N0LHNpemVvZihob3N0KSk7IGhvc3Rbc2l6
ZW9mKGhvc3QpLTFdPTA7CiAgY29uc3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYoIk5UX05PREVf
TkFNRSIpOwogIHN0ZDo6c3RyaW5nIG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVfZW52KSA/IG5v
ZGVfZW52IDogaG9zdDsKICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gYnVmOyBsb2FkX3Nwb29s
KHNwb29sX3BhdGgsJmJ1Zik7IHRpbWVfdCBsYXN0PXRpbWUoTlVMTCksIGxhc3RfcmV0cnk9bGFz
dDsKICBzdGQ6OnN0cmluZyBsaW5lOwogIHdoaWxlKHJ1bm5pbmcpIHsKICAgIGZkX3NldCByOyBG
RF9aRVJPKCZyKTsgRkRfU0VUKDAsICZyKTsKICAgIHN0cnVjdCB0aW1ldmFsIHR2OyB0di50dl9z
ZWMgPSAxOyB0di50dl91c2VjID0gMDsKICAgIGludCByYyA9IHNlbGVjdCgxLCAmciwgTlVMTCwg
TlVMTCwgJnR2KTsKICAgIGlmIChyYyA+IDAgJiYgRkRfSVNTRVQoMCwgJnIpKSB7CiAgICAgIGlm
ICghc3RkOjpnZXRsaW5lKHN0ZDo6Y2luLCBsaW5lKSkgYnJlYWs7CiAgICAgIGlmICghbGluZS5l
bXB0eSgpKSBidWYucHVzaF9iYWNrKGxpbmUpOwogICAgfQogICAgdGltZV90IG5vdyA9IHRpbWUo
TlVMTCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSBGTFVTSF9TRUMgfHwgYnVmLnNpemUoKSA+PSBN
QVhfQkFUQ0gpIHsKICAgICAgaWYgKCFidWYuZW1wdHkoKSkgc2VuZF9iYXRjaGVzKGVuZHBvaW50
LCBub2RlLCBzcG9vbF9wYXRoLCAmYnVmLCB0cnVlKTsKICAgICAgbGFzdCA9IG5vdzsKICAgIH0K
ICAgIGlmIChub3cgLSBsYXN0X3JldHJ5ID49IFJFVFJZX1NFQykgewogICAgICBsb2FkX3Nwb29s
KHNwb29sX3BhdGgsICZidWYpOwogICAgICBsYXN0X3JldHJ5ID0gbm93OwogICAgfQogIH0KICBz
ZW5kX2JhdGNoZXMoZW5kcG9pbnQsbm9kZSxzcG9vbF9wYXRoLCZidWYsdHJ1ZSk7IGxvZ21zZygi
c3RvcHBlZCIpOyByZXR1cm4gMDsKfQo=
#__END_CPP_SHIP__
#__CPP_B64__
LyoKICogbnQtc25pZmYtY3BwLmNwcCAtIEMrKzAzLWNvbXBhdGlibGUgb2xkLWtlcm5lbCBIVFRQ
IGNhcHR1cmUgYWdlbnQuCiAqCiAqIFJlcGxhY2VzIHRoZSBQeXRob24gaG90IGxvb3Agd2hpbGUg
cmV0YWluaW5nIHRoZSBvbGRrZXJuZWwgSlNPTkwgY29udHJhY3Q6CiAqIEFGX1BBQ0tFVCAtPiBj
bGFzc2ljIEJQRiAtPiBib3VuZGVkIEhUVFAgaGVhZGVyIGZsb3cgdGFibGUgLT4gcmVzcG9uc2UK
ICogY29ycmVsYXRpb24gLT4gSlNPTkwgc3Rkb3V0IC0+IG50LXNoaXAucHkuCiAqCiAqIEJ1aWxk
IHRhcmdldDogQ2VudE9TIDYgLyBHQ0MgNC40LCBMaW51eCAyLjYuMzIuIE5vIHRoaXJkLXBhcnR5
IGRlcHMuCiAqIFRoaXMgaXMgaW50ZW50aW9uYWxseSBIVFRQIGhlYWRlci1vbmx5LiBUTFMgcmVt
YWlucyBlY2FwdHVyZSdzIGNvbmNlcm4uCiAqLwojaW5jbHVkZSA8YXJwYS9pbmV0Lmg+CiNpbmNs
dWRlIDxjdHlwZS5oPgojaW5jbHVkZSA8ZXJybm8uaD4KI2luY2x1ZGUgPGZjbnRsLmg+CiNpbmNs
dWRlIDxuZXQvaWYuaD4KI2luY2x1ZGUgPHNpZ25hbC5oPgojaW5jbHVkZSA8c3RkaW50Lmg+CiNp
bmNsdWRlIDxzdGRpby5oPgojaW5jbHVkZSA8c3RkbGliLmg+CiNpbmNsdWRlIDxzdHJpbmcuaD4K
I2luY2x1ZGUgPHN5cy9pb2N0bC5oPgojaW5jbHVkZSA8c3lzL3NlbGVjdC5oPgojaW5jbHVkZSA8
c3lzL3RpbWUuaD4KI2luY2x1ZGUgPHN5cy9zb2NrZXQuaD4KI2luY2x1ZGUgPHN5cy90eXBlcy5o
PgojaW5jbHVkZSA8dGltZS5oPgojaW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxsaW51eC9m
aWx0ZXIuaD4KI2luY2x1ZGUgPGxpbnV4L2lmX3BhY2tldC5oPgojaW5jbHVkZSA8bGludXgvaWZf
ZXRoZXIuaD4KI2luY2x1ZGUgPGlvc3RyZWFtPgoKI2luY2x1ZGUgPG1hcD4KI2luY2x1ZGUgPHNz
dHJlYW0+CiNpbmNsdWRlIDxzdHJpbmc+CiNpbmNsdWRlIDx2ZWN0b3I+CgpzdGF0aWMgdm9sYXRp
bGUgc2lnX2F0b21pY190IGdfcnVubmluZyA9IDE7CnN0YXRpYyB2b2lkIHN0b3Bfc2lnbmFsKGlu
dCkgeyBnX3J1bm5pbmcgPSAwOyB9CgpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9GTE9XUyA9IDgx
OTI7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BFTkRJTkcgPSA4MTkyOwpzdGF0aWMgY29uc3Qg
c2l6ZV90IE1BWF9IRUFERVIgPSAyNjIxNDQ7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RU
TCA9IDMwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIFBFTkRJTkdfVFRMID0gNTsKc3RhdGljIGNv
bnN0IHVuc2lnbmVkIEFDQ0VQVCA9IDB4NDAwMDA7CnN0YXRpYyBjb25zdCBpbnQgU09fQVRUQUNI
X0ZJTFRFUl9PTEQgPSAyNjsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNob3J0IEVUSF9QX0lQX0hP
U1QgPSAweDA4MDA7CgpzdGF0aWMgc3RkOjpzdHJpbmcgdHJpbShjb25zdCBzdGQ6OnN0cmluZyAm
cykgewogIHNpemVfdCBhID0gMCwgYiA9IHMuc2l6ZSgpOwogIHdoaWxlIChhIDwgYiAmJiBpc3Nw
YWNlKCh1bnNpZ25lZCBjaGFyKXNbYV0pKSArK2E7CiAgd2hpbGUgKGIgPiBhICYmIGlzc3BhY2Uo
KHVuc2lnbmVkIGNoYXIpc1tiIC0gMV0pKSAtLWI7CiAgcmV0dXJuIHMuc3Vic3RyKGEsIGIgLSBh
KTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbG93ZXIoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBz
dGQ6OnN0cmluZyB4ID0gczsKICBzaXplX3QgaTsgZm9yIChpID0gMDsgaSA8IHguc2l6ZSgpOyAr
K2kpIHhbaV0gPSAoY2hhcil0b2xvd2VyKCh1bnNpZ25lZCBjaGFyKXhbaV0pOwogIHJldHVybiB4
Owp9CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29ucShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0
ZDo6c3RyaW5nIHggPSAiXCIiOyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgcy5zaXplKCk7
ICsraSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIGlm
IChjID09ICdcXCcgfHwgYyA9PSAnIicpIHsgeCArPSAnXFwnOyB4ICs9IChjaGFyKWM7IH0KICAg
IGVsc2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1xyJykg
eCArPSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0JykgeCArPSAiXFx0IjsKICAgIGVsc2Ug
aWYgKGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0gKGNoYXIpYzsKICB9CiAgeCArPSAn
Iic7IHJldHVybiB4Owp9CnN0YXRpYyBsb25nIGxvbmcgbm93X21zKCkgewogIHN0cnVjdCB0aW1l
dmFsIHR2OyBnZXR0aW1lb2ZkYXkoJnR2LCBOVUxMKTsKICByZXR1cm4gKGxvbmcgbG9uZyl0di50
dl9zZWMgKiAxMDAwTEwgKyB0di50dl91c2VjIC8gMTAwMDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcg
bnVtKGxvbmcgdikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsgbyA8PCB2OyByZXR1cm4gby5zdHIo
KTsgfQpzdGF0aWMgYm9vbCB2YWxpZF9wb3J0KHVuc2lnbmVkIHApIHsgcmV0dXJuIHAgPiAwICYm
IHAgPD0gNjU1MzU7IH0Kc3RhdGljIGJvb2wgaGFzX21ldGhvZChjb25zdCBzdGQ6OnN0cmluZyAm
bSkgewogIHJldHVybiBtID09ICJHRVQiIHx8IG0gPT0gIlBPU1QiIHx8IG0gPT0gIlBVVCIgfHwg
bSA9PSAiREVMRVRFIiB8fAogICAgICAgICBtID09ICJQQVRDSCIgfHwgbSA9PSAiSEVBRCIgfHwg
bSA9PSAiT1BUSU9OUyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGhvc3RfbmFtZSgpIHsKICBjaGFy
IGJbMjU2XTsgaWYgKGdldGhvc3RuYW1lKGIsIHNpemVvZihiKSAtIDEpICE9IDApIHJldHVybiAi
dW5rbm93bi1ub2RlIjsKICBiW3NpemVvZihiKSAtIDFdID0gMDsgY2hhciAqcCA9IHN0cmNocihi
LCAnLicpOyBpZiAocCkgKnAgPSAwOyByZXR1cm4gYjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgYjY0
ZGVjb2RlX3VzZXIoY29uc3Qgc3RkOjpzdHJpbmcgJnYpIHsKICBzdGQ6OnN0cmluZyBpbiA9IHRy
aW0odiksIG91dDsgaW50IHZhbCA9IDAsIGJpdHMgPSAtODsgc2l6ZV90IGk7CiAgZm9yIChpID0g
MDsgaSA8IGluLnNpemUoKTsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQg
Y2hhcilpbltpXTsgaW50IGQgPSAtMTsKICAgIGlmIChjID49ICdBJyAmJiBjIDw9ICdaJykgZCA9
IGMgLSAnQSc7CiAgICBlbHNlIGlmIChjID49ICdhJyAmJiBjIDw9ICd6JykgZCA9IGMgLSAnYScg
KyAyNjsKICAgIGVsc2UgaWYgKGMgPj0gJzAnICYmIGMgPD0gJzknKSBkID0gYyAtICcwJyArIDUy
OwogICAgZWxzZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsKICAgIGVsc2UgaWYgKGMgPT0gJy8nKSBk
ID0gNjM7CiAgICBlbHNlIGlmIChjID09ICc9JykgYnJlYWs7CiAgICBpZiAoZCA8IDApIGNvbnRp
bnVlOwogICAgdmFsID0gKHZhbCA8PCA2KSArIGQ7CiAgICBiaXRzICs9IDY7CiAgICBpZiAoYml0
cyA+PSAwKSB7CiAgICAgIG91dCArPSAoY2hhcikoKHZhbCA+PiBiaXRzKSAmIDB4ZmYpOwogICAg
ICBiaXRzIC09IDg7CiAgICAgIGlmIChvdXQuc2l6ZSgpID4gNTEyKSByZXR1cm4gIiI7CiAgICB9
CiAgfQogIHNpemVfdCBwID0gb3V0LmZpbmQoJzonKTsKICBpZiAocCA9PSBzdGQ6OnN0cmluZzo6
bnBvcykgcmV0dXJuICIiOwogIHJldHVybiBvdXQuc3Vic3RyKDAsIHAgPiA2NCA/IDY0IDogcCk7
Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGhlYWRlcl92YWx1ZShjb25zdCBzdGQ6OnN0cmluZyAmaGVh
ZCwgY29uc3Qgc3RkOjpzdHJpbmcgJndhbnQpIHsKICBzdGQ6OmlzdHJpbmdzdHJlYW0gaW4oaGVh
ZCk7IHN0ZDo6c3RyaW5nIGxpbmUsIHcgPSBsb3dlcih3YW50KTsKICB3aGlsZSAoc3RkOjpnZXRs
aW5lKGluLCBsaW5lKSkgewogICAgaWYgKCFsaW5lLmVtcHR5KCkgJiYgbGluZVtsaW5lLnNpemUo
KSAtIDFdID09ICdccicpIGxpbmUuZXJhc2UobGluZS5zaXplKCkgLSAxKTsKICAgIHNpemVfdCBw
ID0gbGluZS5maW5kKCc6Jyk7IGlmIChwID09IHN0ZDo6c3RyaW5nOjpucG9zKSBjb250aW51ZTsK
ICAgIGlmIChsb3dlcih0cmltKGxpbmUuc3Vic3RyKDAsIHApKSkgPT0gdykgcmV0dXJuIHRyaW0o
bGluZS5zdWJzdHIocCArIDEpKTsKICB9CiAgcmV0dXJuICIiOwp9CnN0YXRpYyBzdGQ6OnN0cmlu
ZyB0cmFjZV9pZF9mcm9tX3BhcmVudChjb25zdCBzdGQ6OnN0cmluZyAmdHApIHsKICBzdGQ6OnN0
cmluZyB4ID0gdHJpbSh0cCk7CiAgaWYgKHguc2l6ZSgpID09IDU1ICYmIHhbMl0gPT0gJy0nICYm
IHhbMzVdID09ICctJyAmJiB4WzUyXSA9PSAnLScpIHJldHVybiBsb3dlcih4LnN1YnN0cigzLCAz
MikpOwogIHJldHVybiAiIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbWFrZV90cmFjZXBhcmVudChz
dGQ6OnN0cmluZyAqdGlkKSB7CiAgdW5zaWduZWQgY2hhciBiWzI0XTsgc2l6ZV90IGk7IEZJTEUg
KmYgPSBmb3BlbigiL2Rldi91cmFuZG9tIiwgInJiIik7CiAgaWYgKGYpIHsgc2l6ZV90IGdvdCA9
IGZyZWFkKGIsIDEsIHNpemVvZihiKSwgZik7ICh2b2lkKWdvdDsgZmNsb3NlKGYpOyB9CiAgZWxz
ZSB7IHVuc2lnbmVkIGxvbmcgdCA9ICh1bnNpZ25lZCBsb25nKXRpbWUoTlVMTCkgXiAodW5zaWdu
ZWQgbG9uZylnZXRwaWQoKTsgZm9yIChpID0gMDsgaSA8IHNpemVvZihiKTsgKytpKSBiW2ldID0g
KHVuc2lnbmVkIGNoYXIpKHQgPSB0ICogMTEwMzUxNTI0NVVMICsgMTIzNDVVTCk7IH0KICBzdGF0
aWMgY29uc3QgY2hhciAqaGV4ID0gIjAxMjM0NTY3ODlhYmNkZWYiOyBzdGQ6OnN0cmluZyBhLCBj
OwogIGZvciAoaSA9IDA7IGkgPCAxNjsgKytpKSB7IGEgKz0gaGV4W2JbaV0gPj4gNF07IGEgKz0g
aGV4W2JbaV0gJiAxNV07IH0KICBmb3IgKGkgPSAxNjsgaSA8IDI0OyArK2kpIHsgYyArPSBoZXhb
YltpXSA+PiA0XTsgYyArPSBoZXhbYltpXSAmIDE1XTsgfQogICp0aWQgPSBhOyByZXR1cm4gIjAw
LSIgKyBhICsgIi0iICsgYyArICItMDEiOwp9CgpzdHJ1Y3QgRXZlbnQgewogIGxvbmcgdHM7IHN0
ZDo6c3RyaW5nIGhvc3QsIHNyYywgc2VydmljZSwgbWV0aG9kLCBwYXRoLCB1c2VyLCBzY2hlbWUs
IHByb2JlOwogIHN0ZDo6c3RyaW5nIGhvc3RfaGRyLCB1c2VyX2FnZW50LCB4ZmYsIGNhbGxlciwg
ZHN0X2lwLCB0cmFjZXBhcmVudCwgdHJhY2VfaWQ7CiAgdW5zaWduZWQgY2FsbGVyX3BvcnQsIGRz
dF9wb3J0LCByZXFfYnl0ZXMsIHJlc3BfYnl0ZXM7IGludCBzdGF0dXM7IGxvbmcgZHVyYXRpb25f
bXM7CiAgYm9vbCBoYXNfc3RhdHVzLCBoYXNfZHVyYXRpb24sIGhhc19yZXNwOwogIEV2ZW50KCkg
OiB0cygwKSwgY2FsbGVyX3BvcnQoMCksIGRzdF9wb3J0KDApLCByZXFfYnl0ZXMoMCksIHJlc3Bf
Ynl0ZXMoMCksIHN0YXR1cygwKSwgZHVyYXRpb25fbXMoMCksIGhhc19zdGF0dXMoZmFsc2UpLCBo
YXNfZHVyYXRpb24oZmFsc2UpLCBoYXNfcmVzcChmYWxzZSkge30KfTsKc3RydWN0IEZsb3cgeyBz
dGQ6OnN0cmluZyBidWY7IHRpbWVfdCB0b3VjaGVkOyBGbG93KCkgOiB0b3VjaGVkKHRpbWUoTlVM
TCkpIHt9IH07CnN0cnVjdCBQZW5kaW5nIHsKICBFdmVudCBldjsKICBsb25nIGxvbmcgc3RhcnRl
ZF9tczsKICBQZW5kaW5nKCkgOiBzdGFydGVkX21zKDApIHt9CiAgUGVuZGluZyhjb25zdCBFdmVu
dCAmZSwgbG9uZyBsb25nIHQpIDogZXYoZSksIHN0YXJ0ZWRfbXModCkge30KfTsKc3RydWN0IFBh
Y2tldEtleSB7IHN0ZDo6c3RyaW5nIHNyYzsgdW5zaWduZWQgc3BvcnQ7IHN0ZDo6c3RyaW5nIGRz
dDsgdW5zaWduZWQgZHBvcnQ7IGJvb2wgb3BlcmF0b3I8KGNvbnN0IFBhY2tldEtleSAmeCkgY29u
c3QgeyByZXR1cm4gc3JjICE9IHguc3JjID8gc3JjIDwgeC5zcmMgOiBzcG9ydCAhPSB4LnNwb3J0
ID8gc3BvcnQgPCB4LnNwb3J0IDogZHN0ICE9IHguZHN0ID8gZHN0IDwgeC5kc3QgOiBkcG9ydCA8
IHguZHBvcnQ7IH0gfTsKCnN0YXRpYyBzdGQ6OnN0cmluZyBrZXlfc3RyaW5nKGNvbnN0IHN0ZDo6
c3RyaW5nICZhLCB1bnNpZ25lZCBhcCwgY29uc3Qgc3RkOjpzdHJpbmcgJmIsIHVuc2lnbmVkIGJw
KSB7IHJldHVybiBhICsgIjoiICsgbnVtKGFwKSArICItPiIgKyBiICsgIjoiICsgbnVtKGJwKTsg
fQpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsgZnByaW50ZihzdGRl
cnIsICJudC1zbmlmZi1jcHA6ICVzXG4iLCBzLmNfc3RyKCkpOyBmZmx1c2goc3RkZXJyKTsgfQoK
c3RhdGljIGJvb2wgcGFyc2VfcmVxdWVzdChjb25zdCBzdGQ6OnN0cmluZyAmaGVhZCwgRXZlbnQg
KmUpIHsKICBzdGQ6OnN0cmluZyBmaXJzdDsgc3RkOjppc3RyaW5nc3RyZWFtIGluKGhlYWQpOyBp
ZiAoIXN0ZDo6Z2V0bGluZShpbiwgZmlyc3QpKSByZXR1cm4gZmFsc2U7CiAgc3RkOjppc3RyaW5n
c3RyZWFtIHAodHJpbShmaXJzdCkpOyBpZiAoIShwID4+IGUtPm1ldGhvZCA+PiBlLT5wYXRoKSkg
cmV0dXJuIGZhbHNlOwogIGlmICghaGFzX21ldGhvZChlLT5tZXRob2QpKSByZXR1cm4gZmFsc2U7
CiAgc2l6ZV90IHEgPSBlLT5wYXRoLmZpbmQoJz8nKTsgaWYgKHEgIT0gc3RkOjpzdHJpbmc6Om5w
b3MpIGUtPnBhdGguZXJhc2UocSk7CiAgaWYgKGUtPnBhdGguc2l6ZSgpID4gMTIwKSBlLT5wYXRo
LmVyYXNlKDEyMCk7CiAgc3RkOjpzdHJpbmcgYXV0aCA9IGhlYWRlcl92YWx1ZShoZWFkLCAiYXV0
aG9yaXphdGlvbiIpOwogIGlmIChsb3dlcihhdXRoKS5maW5kKCJiYXNpYyAiKSA9PSAwKSB7IGUt
PnVzZXIgPSBiNjRkZWNvZGVfdXNlcihhdXRoLnN1YnN0cig2KSk7IGUtPnNjaGVtZSA9ICJiYXNp
YyI7IH0KICBlbHNlIGlmIChsb3dlcihhdXRoKS5maW5kKCJiZWFyZXIgIikgPT0gMCkgZS0+c2No
ZW1lID0gImJlYXJlciI7CiAgc3RkOjpzdHJpbmcgeCA9IGhlYWRlcl92YWx1ZShoZWFkLCAidHJh
Y2VwYXJlbnQiKTsgZS0+dHJhY2VfaWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVudCh4KTsgZS0+dHJh
Y2VwYXJlbnQgPSBlLT50cmFjZV9pZC5lbXB0eSgpID8gbWFrZV90cmFjZXBhcmVudCgmZS0+dHJh
Y2VfaWQpIDogeDsKICBlLT5ob3N0X2hkciA9IGhlYWRlcl92YWx1ZShoZWFkLCAiaG9zdCIpOwog
IGUtPnVzZXJfYWdlbnQgPSBoZWFkZXJfdmFsdWUoaGVhZCwgInVzZXItYWdlbnQiKTsKICBlLT54
ZmYgPSBoZWFkZXJfdmFsdWUoaGVhZCwgIngtZm9yd2FyZGVkLWZvciIpOwogIGlmIChlLT51c2Vy
LmVtcHR5KCkpIHsKICAgIGUtPnVzZXIgPSAiLWFub255bW91cy0iOwogIH0KICBpZiAoZS0+c2No
ZW1lLmVtcHR5KCkpIHsKICAgIGUtPnNjaGVtZSA9ICJub25lIjsKICB9CiAgcmV0dXJuIHRydWU7
Cn0Kc3RhdGljIGJvb2wgcGFyc2VfcmVzcG9uc2UoY29uc3Qgc3RkOjpzdHJpbmcgJnBheWxvYWQs
IGludCAqc3RhdHVzLCB1bnNpZ25lZCAqY2xlbikgewogIHNpemVfdCBlbmQgPSBwYXlsb2FkLmZp
bmQoIlxyXG5cclxuIik7CiAgc3RkOjpzdHJpbmcgaCA9IHBheWxvYWQuc3Vic3RyKDAsIGVuZCA9
PSBzdGQ6OnN0cmluZzo6bnBvcyA/IHBheWxvYWQuc2l6ZSgpIDogZW5kKTsKICBpZiAoaC5zaXpl
KCkgPiBNQVhfSEVBREVSKSByZXR1cm4gZmFsc2U7CiAgc3RkOjppc3RyaW5nc3RyZWFtIGluKGgp
OwogIHN0ZDo6c3RyaW5nIGZpcnN0OwogIGlmICghc3RkOjpnZXRsaW5lKGluLCBmaXJzdCkpIHJl
dHVybiBmYWxzZTsKICBzdGQ6OmlzdHJpbmdzdHJlYW0gcChmaXJzdCk7CiAgc3RkOjpzdHJpbmcg
cHJvdG87CiAgaWYgKCEocCA+PiBwcm90byA+PiAqc3RhdHVzKSkgcmV0dXJuIGZhbHNlOwogIGlm
IChwcm90by5maW5kKCJIVFRQLyIpICE9IDAgfHwgKnN0YXR1cyA8IDEwMCB8fCAqc3RhdHVzID4g
NTk5KSByZXR1cm4gZmFsc2U7CiAgKmNsZW4gPSAwOyBzdGQ6OnN0cmluZyBsaW5lOwogIHdoaWxl
IChzdGQ6OmdldGxpbmUoaW4sIGxpbmUpKSB7IHNpemVfdCB4ID0gbGluZS5maW5kKCc6Jyk7IGlm
ICh4ICE9IHN0ZDo6c3RyaW5nOjpucG9zICYmIGxvd2VyKHRyaW0obGluZS5zdWJzdHIoMCwgeCkp
KSA9PSAiY29udGVudC1sZW5ndGgiKSB7IGxvbmcgbiA9IGF0b2wodHJpbShsaW5lLnN1YnN0cih4
ICsgMSkpLmNfc3RyKCkpOyBpZiAobiA+PSAwICYmIG4gPD0gMHg3ZmZmZmZmZikgKmNsZW4gPSAo
dW5zaWduZWQpbjsgfSB9CiAgcmV0dXJuIHRydWU7Cn0Kc3RhdGljIHZvaWQgZW1pdF9ldmVudChj
b25zdCBFdmVudCAmZSkgewogIHN0ZDo6Y291dCA8PCAie1widHNcIjoiIDw8IGUudHMgPDwgIixc
Imhvc3RcIjoiIDw8IGpzb25xKGUuaG9zdCkgPDwgIixcInNyY1wiOlwicGNhcFwiLFwic2Vydmlj
ZVwiOiIgPDwganNvbnEoZS5zZXJ2aWNlKQogICAgICAgICAgICA8PCAiLFwibWV0aG9kXCI6IiA8
PCBqc29ucShlLm1ldGhvZCkgPDwgIixcInBhdGhcIjoiIDw8IGpzb25xKGUucGF0aCkgPDwgIixc
InVzZXJcIjoiIDw8IGpzb25xKGUudXNlcikKICAgICAgICAgICAgPDwgIixcInNjaGVtZVwiOiIg
PDwganNvbnEoZS5zY2hlbWUpIDw8ICIsXCJzb3VyY2VfcHJvYmVcIjpcInBjYXAtaHR0cC1jcHBc
IixcImhvc3RfaGRyXCI6IiA8PCBqc29ucShlLmhvc3RfaGRyKQogICAgICAgICAgICA8PCAiLFwi
dXNlcl9hZ2VudFwiOiIgPDwganNvbnEoZS51c2VyX2FnZW50KSA8PCAiLFwieF9mb3J3YXJkZWRf
Zm9yXCI6IiA8PCBqc29ucShlLnhmZikKICAgICAgICAgICAgPDwgIixcImNhbGxlclwiOiIgPDwg
anNvbnEoZS5jYWxsZXIpIDw8ICIsXCJjYWxsZXJfcG9ydFwiOiIgPDwgZS5jYWxsZXJfcG9ydCA8
PCAiLFwiZHN0X2lwXCI6IiA8PCBqc29ucShlLmRzdF9pcCkKICAgICAgICAgICAgPDwgIixcImRz
dF9wb3J0XCI6IiA8PCBlLmRzdF9wb3J0IDw8ICIsXCJ0cmFjZXBhcmVudFwiOiIgPDwganNvbnEo
ZS50cmFjZXBhcmVudCkgPDwgIixcInRyYWNlX2lkXCI6IiA8PCBqc29ucShlLnRyYWNlX2lkKQog
ICAgICAgICAgICA8PCAiLFwic2VydmljZV9pZFwiOm51bGwsXCJtb2R1bGVfaWRcIjpcInBjYXAt
aHR0cC1jcHBcIixcInJlcV9ieXRlc1wiOiIgPDwgZS5yZXFfYnl0ZXM7CiAgaWYgKGUuaGFzX3N0
YXR1cykgc3RkOjpjb3V0IDw8ICIsXCJzdGF0dXNcIjoiIDw8IGUuc3RhdHVzOyBlbHNlIHN0ZDo6
Y291dCA8PCAiLFwic3RhdHVzXCI6bnVsbCI7CiAgaWYgKGUuaGFzX2R1cmF0aW9uKSBzdGQ6OmNv
dXQgPDwgIixcImR1cmF0aW9uX21zXCI6IiA8PCBlLmR1cmF0aW9uX21zOyBlbHNlIHN0ZDo6Y291
dCA8PCAiLFwiZHVyYXRpb25fbXNcIjpudWxsIjsKICBpZiAoZS5oYXNfcmVzcCkgc3RkOjpjb3V0
IDw8ICIsXCJyZXNwX2J5dGVzXCI6IiA8PCBlLnJlc3BfYnl0ZXM7IGVsc2Ugc3RkOjpjb3V0IDw8
ICIsXCJyZXNwX2J5dGVzXCI6bnVsbCI7CiAgc3RkOjpjb3V0IDw8ICJ9XG4iOyBzdGQ6OmNvdXQu
Zmx1c2goKTsKfQoKc3RhdGljIHZvaWQgZmx1c2hfb2xkZXN0KHN0ZDo6bWFwPFBhY2tldEtleSwg
c3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIHN0ZDo6bWFwPFBhY2tldEtleSwg
c3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgYmVzdCA9IHBlbmRpbmcuZW5kKCk7IGxv
bmcgbG9uZyBidCA9IDA7IGJvb2wgZm91bmQgPSBmYWxzZTsKICBzdGQ6Om1hcDxQYWNrZXRLZXks
IHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIGk7CiAgZm9yIChpID0gcGVuZGluZy5i
ZWdpbigpOyBpICE9IHBlbmRpbmcuZW5kKCk7ICsraSkgaWYgKCFpLT5zZWNvbmQuZW1wdHkoKSAm
JiAoIWZvdW5kIHx8IGktPnNlY29uZFswXS5zdGFydGVkX21zIDwgYnQpKSB7IGJlc3QgPSBpOyBi
dCA9IGktPnNlY29uZFswXS5zdGFydGVkX21zOyBmb3VuZCA9IHRydWU7IH0KICBpZiAoZm91bmQp
IHsgZW1pdF9ldmVudChiZXN0LT5zZWNvbmRbMF0uZXYpOyBiZXN0LT5zZWNvbmQuZXJhc2UoYmVz
dC0+c2Vjb25kLmJlZ2luKCkpOyBpZiAoYmVzdC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJh
c2UoYmVzdCk7IH0KfQpzdGF0aWMgdm9pZCBzd2VlcChzdGQ6Om1hcDxzdGQ6OnN0cmluZywgRmxv
dz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBl
bmRpbmcsIHRpbWVfdCBub3cpIHsKICBzdGQ6Om1hcDxzdGQ6OnN0cmluZywgRmxvdz46Oml0ZXJh
dG9yIGYsIGZuOwogIGZvciAoZiA9IGZsb3dzLmJlZ2luKCk7IGYgIT0gZmxvd3MuZW5kKCk7KSB7
CiAgICBmbiA9IGY7ICsrZm47CiAgICBpZiAoKHVuc2lnbmVkKShub3cgLSBmLT5zZWNvbmQudG91
Y2hlZCkgPiBGTE9XX1RUTCkgZmxvd3MuZXJhc2UoZik7CiAgICBmID0gZm47CiAgfQogIGxvbmcg
bG9uZyBjdXJyZW50X21zID0gKGxvbmcgbG9uZylub3cgKiAxMDAwTEw7CiAgc3RkOjptYXA8UGFj
a2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwLCBwbjsKICBmb3IgKHAg
PSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTspIHsKICAgIHBuID0gcDsgKytw
bjsKICAgIGlmICghcC0+c2Vjb25kLmVtcHR5KCkgJiYgY3VycmVudF9tcyAtIHAtPnNlY29uZFsw
XS5zdGFydGVkX21zID4gKGxvbmcgbG9uZylQRU5ESU5HX1RUTCAqIDEwMDBMTCkgewogICAgICBl
bWl0X2V2ZW50KHAtPnNlY29uZFswXS5ldik7IHBlbmRpbmcuZXJhc2UocCk7CiAgICB9CiAgICBw
ID0gcG47CiAgfQp9CnN0YXRpYyBib29sIGhhbmRsZV9wYWNrZXQoY29uc3QgdW5zaWduZWQgY2hh
ciAqYnVmLCBzaXplX3QgbiwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsIGNvbnN0IHN0ZDo6dmVj
dG9yPHVuc2lnbmVkPiAmcG9ydHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8
c3RkOjpzdHJpbmcsIEZsb3c+ICZmbG93cywgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3Rv
cjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgaWYgKG4gPCAzNCkgcmV0dXJuIGZhbHNlOwogIHNp
emVfdCBvZmYgPSAxNDsKICB1bnNpZ25lZCBzaG9ydCBldCA9IG50b2hzKCooY29uc3QgdW5zaWdu
ZWQgc2hvcnQgKikoYnVmICsgMTIpKTsKICBpZiAoZXQgPT0gRVRIX1BfODAyMVEpIHsgaWYgKG4g
PCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9IG50b2hzKCooY29uc3QgdW5zaWduZWQgc2hvcnQgKiko
YnVmICsgMTYpKTsgb2ZmID0gMTg7IH0KICBpZiAoZXQgIT0gRVRIX1BfSVAgfHwgbiA8IG9mZiAr
IDIwKSByZXR1cm4gZmFsc2U7CiAgdW5zaWduZWQgY2hhciBpaGwgPSAodW5zaWduZWQgY2hhciko
YnVmW29mZl0gJiAxNSkgKiA0OwogIGlmICgoYnVmW29mZl0gPj4gNCkgIT0gNCB8fCBidWZbb2Zm
ICsgOV0gIT0gNiB8fCBuIDwgb2ZmICsgaWhsICsgMjApIHJldHVybiBmYWxzZTsKICBjaGFyIGFb
SU5FVF9BRERSU1RSTEVOXSwgYltJTkVUX0FERFJTVFJMRU5dOyBpbmV0X250b3AoQUZfSU5FVCwg
YnVmICsgb2ZmICsgMTIsIGEsIHNpemVvZihhKSk7IGluZXRfbnRvcChBRl9JTkVULCBidWYgKyBv
ZmYgKyAxNiwgYiwgc2l6ZW9mKGIpKTsKICBzaXplX3QgdG8gPSBvZmYgKyBpaGw7IHVuc2lnbmVk
IHNwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0bykpOyB1bnNp
Z25lZCBkcG9ydCA9IG50b2hzKCooY29uc3QgdW5zaWduZWQgc2hvcnQgKikoYnVmICsgdG8gKyAy
KSk7IHVuc2lnbmVkIGRvZmYgPSAoYnVmW3RvICsgMTJdID4+IDQpICogNDsgaWYgKG4gPCB0byAr
IGRvZmYpIHJldHVybiBmYWxzZTsgY29uc3QgY2hhciAqcGF5bG9hZCA9IChjb25zdCBjaGFyICop
KGJ1ZiArIHRvICsgZG9mZik7IHNpemVfdCBwbGVuID0gbiAtIHRvIC0gZG9mZjsgaWYgKCFwbGVu
KSByZXR1cm4gZmFsc2U7CiAgdGltZV90IG5vdyA9IHRpbWUoTlVMTCk7CiAgYm9vbCBkc3RfbW9u
ID0gZmFsc2UsIHNyY19tb24gPSBmYWxzZTsKICBzaXplX3QgajsKICBmb3IgKGogPSAwOyBqIDwg
cG9ydHMuc2l6ZSgpOyArK2opIHsKICAgIGlmIChkcG9ydCA9PSBwb3J0c1tqXSkgZHN0X21vbiA9
IHRydWU7CiAgICBpZiAoc3BvcnQgPT0gcG9ydHNbal0pIHNyY19tb24gPSB0cnVlOwogIH0KICBp
ZiAoc3JjX21vbiAmJiAhZHN0X21vbiAmJiBwbGVuID49IDUgJiYgbWVtY21wKHBheWxvYWQsICJI
VFRQLyIsIDUpID09IDApIHsKICAgIFBhY2tldEtleSBrOwogICAgay5zcmMgPSBhOyBrLnNwb3J0
ID0gc3BvcnQ7IGsuZHN0ID0gYjsgay5kcG9ydCA9IGRwb3J0OwogICAgc3RkOjptYXA8UGFja2V0
S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKGsp
OwogICAgaWYgKHAgIT0gcGVuZGluZy5lbmQoKSAmJiAhcC0+c2Vjb25kLmVtcHR5KCkpIHsKICAg
ICAgaW50IHN0OyB1bnNpZ25lZCBjbDsKICAgICAgaWYgKHBhcnNlX3Jlc3BvbnNlKHN0ZDo6c3Ry
aW5nKHBheWxvYWQsIHBsZW4pLCAmc3QsICZjbCkpIHsKICAgICAgICBFdmVudCBlID0gcC0+c2Vj
b25kWzBdLmV2OwogICAgICAgIGUuc3RhdHVzID0gc3Q7IGUuaGFzX3N0YXR1cyA9IHRydWU7CiAg
ICAgICAgZS5kdXJhdGlvbl9tcyA9IChsb25nKShub3dfbXMoKSAtIHAtPnNlY29uZFswXS5zdGFy
dGVkX21zKTsKICAgICAgICBpZiAoZS5kdXJhdGlvbl9tcyA8IDApIGUuZHVyYXRpb25fbXMgPSAw
OwogICAgICAgIGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsKICAgICAgICBpZiAoY2wpIHsgZS5yZXNw
X2J5dGVzID0gY2w7IGUuaGFzX3Jlc3AgPSB0cnVlOyB9CiAgICAgICAgZW1pdF9ldmVudChlKTsK
ICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkpOwogICAgICAgIGlmIChw
LT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgfQogICAgfQogICAgcmV0
dXJuIHRydWU7CiAgfQogIGlmICghZHN0X21vbikgcmV0dXJuIGZhbHNlOwogIHN0ZDo6c3RyaW5n
IGZrID0ga2V5X3N0cmluZyhhLCBzcG9ydCwgYiwgZHBvcnQpOyBGbG93ICZmbCA9IGZsb3dzW2Zr
XTsgZmwudG91Y2hlZCA9IG5vdzsgZmwuYnVmLmFwcGVuZChwYXlsb2FkLCBwbGVuKTsKICBpZiAo
ZmwuYnVmLnNpemUoKSA+IE1BWF9IRUFERVIpIHsgZmxvd3MuZXJhc2UoZmspOyByZXR1cm4gZmFs
c2U7IH0KICBzaXplX3QgZW5kID0gZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7IGlmIChlbmQgPT0g
c3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiBmYWxzZTsKICBFdmVudCBlOyBlLnRzID0gbm93OyBl
Lmhvc3QgPSBub2RlOyBlLnNlcnZpY2UgPSAicG9ydDoiICsgbnVtKGRwb3J0KTsgZS5jYWxsZXIg
PSBhOyBlLmNhbGxlcl9wb3J0ID0gc3BvcnQ7IGUuZHN0X2lwID0gYjsgZS5kc3RfcG9ydCA9IGRw
b3J0OyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZCkoZW5kICsgNCk7CiAgaWYgKCFwYXJzZV9yZXF1
ZXN0KGZsLmJ1Zi5zdWJzdHIoMCwgZW5kKSwgJmUpKSB7IGZsb3dzLmVyYXNlKGZrKTsgcmV0dXJu
IGZhbHNlOyB9IGZsb3dzLmVyYXNlKGZrKTsKICBQYWNrZXRLZXkgcms7IHJrLnNyYyA9IGI7IHJr
LnNwb3J0ID0gZHBvcnQ7IHJrLmRzdCA9IGE7IHJrLmRwb3J0ID0gc3BvcnQ7IGlmIChwZW5kaW5n
LnNpemUoKSA+PSBNQVhfUEVORElORykgZmx1c2hfb2xkZXN0KHBlbmRpbmcpOyBwZW5kaW5nW3Jr
XS5wdXNoX2JhY2soUGVuZGluZyhlLCBub3dfbXMoKSkpOyByZXR1cm4gdHJ1ZTsKfQoKc3RhdGlj
IGJvb2wgYXR0YWNoX2JwZihpbnQgZmQsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAmcG9y
dHMpIHsKICAvKiBCUEYgaXMgb3B0aW9uYWwgYXQgc3RhcnR1cDogdGhlIHBhcnNlciBzdGlsbCBw
ZXJmb3JtcyB0aGUgc2FtZSBjaGVja3MKICAgICBhZnRlciBiaW5kLiBUaGlzIGtlZXBzIHRoZSBi
aW5hcnkgdXNhYmxlIG9uIGtlcm5lbHMgcmVqZWN0aW5nIHRoZQogICAgIGdlbmVyYXRlZCBmaWx0
ZXIsIHdoaWxlIGxvZ2dpbmcgdGhlIGRlZ3JhZGVkIG1vZGUuICovCiAgc3RkOjp2ZWN0b3I8c3Ry
dWN0IHNvY2tfZmlsdGVyPiBmOyBzaXplX3QgaTsgdW5zaWduZWQgcmVqZWN0ID0gMCwgYWNjZXB0
OwogIC8qIEV0aGVybmV0IElQdjQsIFRDUCwgdGhlbiBkZXN0aW5hdGlvbiBPUiBzb3VyY2UgbW9u
aXRvcmVkIHBvcnQuICovCiAgcmVqZWN0ID0gNCArICh1bnNpZ25lZClwb3J0cy5zaXplKCkgKiA0
ICsgMTsgYWNjZXB0ID0gcmVqZWN0ICsgMTsKICBzdHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmlu
ZSBBREQoQyxKLFQsSykgZG8geyB4LmNvZGU9KEMpOyB4Lmp0PShKKTsgeC5qZj0oVCk7IHguaz0o
Syk7IGYucHVzaF9iYWNrKHgpOyB9IHdoaWxlKDApCiAgQUREKEJQRl9MRHxCUEZfSHxCUEZfQUJT
LDAsMCwxMik7IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssMCxyZWplY3QtMixFVEhfUF9JUF9I
T1NUKTsKICBBREQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsMCwwLDIzKTsgQUREKEJQRl9KTVB8QlBG
X0pFUXxCUEZfSywwLHJlamVjdC00LElQUFJPVE9fVENQKTsKICBBREQoQlBGX0xEfEJQRl9CfEJQ
Rl9NU0gsMCwwLDE0KTsKICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAg
IEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTYpOwogICAgdW5zaWduZWQganQgPSBh
Y2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAwOwogICAg
QUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQogIGZvciAo
aSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZf
SU5ELCAwLCAwLCAxNCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNp
emUoKSAtIDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwgcG9ydHMuc2l6ZSgpIC0gMSkgPyAwIDog
KHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpOwogICAgQUREKEJQRl9KTVB8QlBGX0pF
UXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQogIEFERChCUEZfUkVUfEJQRl9LLDAsMCww
KTsgQUREKEJQRl9SRVR8QlBGX0ssMCwwLEFDQ0VQVCk7CiN1bmRlZiBBREQKICBpZiAoZi5zaXpl
KCkgPiA0MDk2KSByZXR1cm4gZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5s
ZW4gPSAodW5zaWduZWQgc2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07IHJldHVy
biBzZXRzb2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19BVFRBQ0hfRklMVEVSX09MRCwgJnByb2cs
IHNpemVvZihwcm9nKSkgPT0gMDsKfQoKc3RhdGljIGludCBydW5fZml4dHVyZSgpIHsKICBzdGQ6
OnN0cmluZyByZXEgPSAiR0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJcbkhvc3Q6IGFwaS5s
b2NhbFxyXG5BdXRob3JpemF0aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYwXHJcblRyYWNlcGFy
ZW50OiAwMC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIzNDU2Nzg5YWJjZGVm
LTAxXHJcblxyXG4iOwogIEV2ZW50IGU7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAiY3Bw
LW5vZGUiOyBlLnNlcnZpY2UgPSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjkiOyBl
LmNhbGxlcl9wb3J0ID0gNTEwMDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9ydCA9
IDgwODA7IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVlc3Qo
cmVxLnN1YnN0cigwLCByZXEuc2l6ZSgpIC0gNCksICZlKTsgZS5zdGF0dXMgPSAyMDA7IGUuaGFz
X3N0YXR1cyA9IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlvbiA9IHRydWU7
IGUucmVzcF9ieXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVudChlKTsgcmV0
dXJuIDA7Cn0KaW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKiphcmd2KSB7CiAgaWYgKGFyZ2MgPiAx
ICYmICFzdHJjbXAoYXJndlsxXSwgIi0tZml4dHVyZSIpKSByZXR1cm4gcnVuX2ZpeHR1cmUoKTsK
ICBzdGQ6OnN0cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBvcnRzOyBpbnQgaTsg
aW50IHdvcmtlcnMgPSAxOwogIGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAgIGlmICgh
c3RyY21wKGFyZ3ZbaV0sICItaSIpICYmIGkgKyAxIDwgYXJnYykgaWZhY2UgPSBhcmd2WysraV07
CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItcCIpICYmIGkgKyAxIDwgYXJnYykgewog
ICAgICB3aGlsZSAoaSArIDEgPCBhcmdjICYmIGFyZ3ZbaSArIDFdWzBdICE9ICctJykgewogICAg
ICAgIGNoYXIgKnEgPSBzdHJ0b2soYXJndlsrK2ldLCAiLCAiKTsKICAgICAgICB3aGlsZSAocSkg
eyBsb25nIHAgPSBhdG9sKHEpOyBpZiAodmFsaWRfcG9ydCgodW5zaWduZWQpcCkpIHBvcnRzLnB1
c2hfYmFjaygodW5zaWduZWQpcCk7IHEgPSBzdHJ0b2soTlVMTCwgIiwgIik7IH0KICAgICAgfQog
ICAgfQogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWoiKSAmJiBpICsgMSA8IGFyZ2Mp
IHdvcmtlcnMgPSBhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0s
ICItaCIpKSB7IGZwcmludGYoc3RkZXJyLCAidXNhZ2U6IG50LXNuaWZmLWNwcCBbLWkgaWZhY2Vd
IFstcCBwb3J0c10gWy1qIHdvcmtlcnNdXG4iKTsgcmV0dXJuIDA7IH0KICB9CiAgaWYgKHBvcnRz
LmVtcHR5KCkpIHsgcG9ydHMucHVzaF9iYWNrKDgwKTsgcG9ydHMucHVzaF9iYWNrKDgwMDMpOyBw
b3J0cy5wdXNoX2JhY2soODAwNSk7IHBvcnRzLnB1c2hfYmFjayg4MDA3KTsgcG9ydHMucHVzaF9i
YWNrKDgwMDkpOyBwb3J0cy5wdXNoX2JhY2soODAxMCk7IHBvcnRzLnB1c2hfYmFjayg4MDExKTsg
fQogICh2b2lkKXdvcmtlcnM7IHN0ZDo6c3RyaW5nIG5vZGUgPSBob3N0X25hbWUoKTsgaW50IGZk
ID0gc29ja2V0KEFGX1BBQ0tFVCwgU09DS19SQVcsIGh0b25zKDMpKTsgaWYgKGZkIDwgMCkgeyBw
ZXJyb3IoIkFGX1BBQ0tFVCIpOyByZXR1cm4gMjsgfQogIGludCByYiA9IDggKiAxMDI0ICogMTAy
NDsKICBzZXRzb2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19SQ1ZCVUYsICZyYiwgc2l6ZW9mKHJi
KSk7CiAgaWYgKCFhdHRhY2hfYnBmKGZkLCBwb3J0cykpIGxvZ21zZygiV0FSTjogQlBGIGF0dGFj
aCBmYWlsZWQ7IGNvbnRpbnVpbmcgdW5maWx0ZXJlZCIpOwogIHN0cnVjdCBzb2NrYWRkcl9sbCBz
YTsgbWVtc2V0KCZzYSwgMCwgc2l6ZW9mKHNhKSk7IHNhLnNsbF9mYW1pbHkgPSBBRl9QQUNLRVQ7
IHNhLnNsbF9wcm90b2NvbCA9IGh0b25zKDMpOyBpZiAoIWlmYWNlLmVtcHR5KCkpIHsgc2Euc2xs
X2lmaW5kZXggPSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3RyKCkpOyBpZiAoIXNhLnNs
bF9pZmluZGV4KSB7IGxvZ21zZygiYmFkIGludGVyZmFjZSIpOyBjbG9zZShmZCk7IHJldHVybiAy
OyB9IH0gaWYgKGJpbmQoZmQsIChzdHJ1Y3Qgc29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkpIDwg
MCkgeyBwZXJyb3IoImJpbmQiKTsgY2xvc2UoZmQpOyByZXR1cm4gMjsgfQogIHNpZ25hbChTSUdU
RVJNLCBzdG9wX3NpZ25hbCk7CiAgc2lnbmFsKFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHN0ZDo6
bWFwPHN0ZDo6c3RyaW5nLCBGbG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID4gcGVuZGluZzsKICBsb2dtc2coImxpc3RlbmluZyIpOwogIHRpbWVf
dCBsYXN0ID0gdGltZShOVUxMKTsKICB1bnNpZ25lZCBjaGFyICpidWYgPSAodW5zaWduZWQgY2hh
ciAqKW1hbGxvYyg2NTUzNik7CiAgaWYgKCFidWYpIHsKICAgIGNsb3NlKGZkKTsKICAgIGxvZ21z
ZygiYnVmZmVyIGFsbG9jYXRpb24gZmFpbGVkIik7CiAgICByZXR1cm4gMjsKICB9CiAgd2hpbGUg
KGdfcnVubmluZykgewogICAgZmRfc2V0IHI7CiAgICBGRF9aRVJPKCZyKTsKICAgIEZEX1NFVChm
ZCwgJnIpOwogICAgc3RydWN0IHRpbWV2YWwgdHY7CiAgICB0di50dl9zZWMgPSAxOwogICAgdHYu
dHZfdXNlYyA9IDA7CiAgICBpbnQgcmMgPSBzZWxlY3QoZmQgKyAxLCAmciwgTlVMTCwgTlVMTCwg
JnR2KTsKICAgIGlmIChyYyA+IDAgJiYgRkRfSVNTRVQoZmQsICZyKSkgewogICAgICBzc2l6ZV90
IG4gPSByZWN2KGZkLCBidWYsIDY1NTM2LCAwKTsKICAgICAgaWYgKG4gPiAwKSBoYW5kbGVfcGFj
a2V0KGJ1ZiwgKHNpemVfdCluLCBub2RlLCBwb3J0cywgZmxvd3MsIHBlbmRpbmcpOwogICAgfQog
ICAgdGltZV90IG5vdyA9IHRpbWUoTlVMTCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAg
ICAgIHN3ZWVwKGZsb3dzLCBwZW5kaW5nLCBub3cpOwogICAgICBsYXN0ID0gbm93OwogICAgfQog
IH0KICBmcmVlKGJ1Zik7IGNsb3NlKGZkKTsgbG9nbXNnKCJzdG9wcGVkIik7IHJldHVybiAwOwp9
Cg==
#__END_CPP__
#__CPP_MAKE_B64__
IyBHQ0MgNC40IC8gQ2VudE9TIDYgY29tcGF0aWJsZTogQysrMDMsIGdudSsrMDMgb3IgZ251Kys5
OC4KQ1hYID89IGcrKwpDWFhTVEQgPz0gJChzaGVsbCAkKENYWCkgLXN0ZD1nbnUrKzAzIC14IGMr
KyAtRSAvZGV2L251bGwgPi9kZXYvbnVsbCAyPiYxICYmIGVjaG8gLXN0ZD1nbnUrKzAzIHx8IGVj
aG8gLXN0ZD1nbnUrKzk4KQpDWFhGTEFHUyA/PSAtTzIgLVdhbGwgLVdleHRyYSAkKENYWFNURCkK
Ci5QSE9OWTogYWxsIGNwcCBjcHAtc2hpcCBjcHAtZGVidWcgZml4dHVyZSBjbGVhbgoKYWxsOiBj
cHAgY3BwLXNoaXAKCmNwcDoKCSQoQ1hYKSAkKENYWEZMQUdTKSBudC1zbmlmZi1jcHAuY3BwIC1v
IG50LXNuaWZmLWNwcAoKY3BwLXNoaXA6CgkkKENYWCkgJChDWFhGTEFHUykgbnQtc2hpcC1jcHAu
Y3BwIC1vIG50LXNoaXAtY3BwCgpjcHAtZGVidWc6CgkkKENYWCkgLU8wIC1nIC1XYWxsIC1XZXh0
cmEgLXN0ZD1nbnUrKzAzIG50LXNuaWZmLWNwcC5jcHAgLW8gbnQtc25pZmYtY3BwLWRlYnVnCgpm
aXh0dXJlOiBjcHAKCS4vbnQtc25pZmYtY3BwIC0tZml4dHVyZQoKY2xlYW46CglybSAtZiBudC1z
bmlmZi1jcHAgbnQtc25pZmYtY3BwLWRlYnVnIG50LXNoaXAtY3BwCg==
#__END_CPP_MAKE__
#__CPP_RUN_B64__
IyEvYmluL3NoCiMgUnVuIG5hdGl2ZSBDKysgY2FwdHVyZSBhbmQgdGhlIHByb3ZlbiBQeXRob24g
Mi42LWNvbXBhdGlibGUgc2hpcHBlci4Kc2V0IC11CkhFUkU9JChDRFBBVEg9IGNkIC0tICIkKGRp
cm5hbWUgLS0gIiQwIikiICYmIHB3ZCkKRU5EUE9JTlQ9JHtOVF9IVUJfRU5EUE9JTlQ6LX0KU1BP
T0w9JHtOVF9TUE9PTDotL3Zhci9saWIvbmV0d29ya3RyYWNpbmcvc25pZmYtc3Bvb2wuanNvbmx9
CmlmIFsgLXogIiRFTkRQT0lOVCIgXTsgdGhlbgogICAgZWNobyAiTlRfSFVCX0VORFBPSU5UIGlz
IHJlcXVpcmVkIiA+JjIKICAgIGV4aXQgMgpmaQpleGVjICIkSEVSRS9udC1zbmlmZi1jcHAiICIk
QCIgfCBleGVjIHB5dGhvbiAiJEhFUkUvbnQtc2hpcC5weSIgLS1lbmRwb2ludCAiJEVORFBPSU5U
IiAtLXNwb29sICIkU1BPT0wiCg==
#__END_CPP_RUN__
