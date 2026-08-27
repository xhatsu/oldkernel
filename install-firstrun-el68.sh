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
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra -std=gnu++03 nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra -std=gnu++03 nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
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
IGpzb24sIG9zLCBzaWduYWwsIHNvY2tldCwgc3RydWN0LCBzeXMsIHRpbWUKCkVUSF9QX0lQID0g
MHgwODAwCkVUSF9QX1ZMQU4gPSAweDgxMDAKCiMgcHkyLjYgc3RyLWluZGV4aW5nIHlpZWxkcyAx
LWNoYXIgc3RyLCBub3QgaW50IChwcm92ZW4gb24gcmVhbCBlbDYgVk0pOwojIG5vcm1hbGl6ZSBz
byBieXRlLWF0LWluZGV4IHdvcmtzIGlkZW50aWNhbGx5IHVuZGVyIHB5dGhvbiAyIGFuZCAzClBZ
MiA9IHN5cy52ZXJzaW9uX2luZm9bMF0gPT0gMgoKCmRlZiBiMmkoYyk6CiAgICByZXR1cm4gb3Jk
KGMpIGlmIFBZMiBlbHNlIGMKCk1FVEhPRFMgPSAoIkdFVCIsICJQT1NUIiwgIlBVVCIsICJERUxF
VEUiLCAiUEFUQ0giLCAiSEVBRCIsICJPUFRJT05TIikKCk1BWF9GTE9XUyA9IDgxOTIgICAgICAg
ICAgICAjIGNvbmN1cnJlbnQgdHJhY2tlZCBoYWxmLWZsb3dzIChwZXIgZGlyZWN0aW9uKQpNQVhf
SERSUyA9IDI2MjE0NCAgICAgICAgICAgIyBtYXggYnl0ZXMgYnVmZmVyZWQgd2FpdGluZyBmb3Ig
XHJcblxyXG4KRkxPV19UVEwgPSAzMDAgICAgICAgICAgICAgICMgc2Vjb25kcyBiZWZvcmUgaWRs
ZSBmbG93IGJ1ZmZlcnMgYXJlIGRyb3BwZWQKCgpkZWYgbG9nKG1zZyk6CiAgICBzeXMuc3RkZXJy
LndyaXRlKCJudC1zbmlmZjogJXNcbiIgJSBtc2cpCiAgICBzeXMuc3RkZXJyLmZsdXNoKCkKCgoj
IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0gcGVyZjogY0JQRgojIEF0dGFjaCBhIGNsYXNzaWMgQlBGIHByb2dyYW0gc28gdGhl
IEtFUk5FTCBkcm9wcyBldmVyeXRoaW5nIHRoYXQgaXMgbm90CiMgSVB2NCBUQ1AgZGVzdGluZWQg
VE8gYSBtb25pdG9yZWQgcG9ydC4gUmVxdWVzdHMgYWxvbmUgZHJpdmUgZXZlbnRzCiMgKGhlYWRl
ci1vbmx5IGNhcHR1cmUpOyByZXNwb25zZXMsIEFDS3MgYW5kIHVucmVsYXRlZCB0cmFmZmljIG5l
dmVyIGdldAojIGNvcGllZCB0byB1c2Vyc3BhY2UgYXQgYWxsLgpTT19BVFRBQ0hfRklMVEVSID0g
MjYKCmRlZiBidWlsZF9icGYocG9ydHMpOgogICAgIiIiQ2xhc3NpYyBCUEY6IGV0aGVydHlwZT09
SVAgJiYgcHJvdG89PVRDUCAmJiBkcG9ydCBpbiBwb3J0cy4KICAgIFJldHVybnMgKGZwcm9nX3N0
cnVjdCwgZmlsdGVyX2FycmF5KSBmb3IgdGhlIGxpYmMgc2V0c29ja29wdCBjYWxsLAogICAgb3Ig
Tm9uZSBvbiBmYWlsdXJlLiBOT1RFOiBzb2NrX2Zwcm9nIGNhcnJpZXMgYSBQT0lOVEVSIHRvIHRo
ZSBmaWx0ZXIKICAgIGFycmF5LCBzbyBpdCBtdXN0IHN0YXkgYWxpdmUgdW50aWwgdGhlIHN5c2Nh
bGwg4oCUIHB5dGhvbidzCiAgICBzb2NrZXQuc2V0c29ja29wdChzdHIpIGZsYXR0ZW5pbmcgY2Fu
bm90IHByZXNlcnZlIGl0LiIiIgoKICAgIExESF9BQlMgPSAweDI4ICAgIyBsZCBba106aAogICAg
TERCX0FCUyA9IDB4MzAgICAjIGxkIFtrXTpiCiAgICBKRVFfSyA9IDB4MTUgICAgICMgamVxIGsK
ICAgIExEWF9NU0ggPSAweEIxICAgIyB4ID0gNCooW2tdJjB4ZikgIChpaGwgYnl0ZXMpCiAgICBM
REhfSU5EID0gMHg0OCAgICMgbGQgW3gra106aAogICAgUkVUX0sgPSAweDA2CgogICAgIyBQUk9W
RU4gZHBvcnQgYmxvY2sgKyBzcG9ydCBibG9jayBhdCBYKzE0IChjYWxpYnJhdGVkIEVNUElSSUNB
TExZIG9uCiAgICAjIGEgbGl2ZSBrZXJuZWw6IGs9MTQgZGVsaXZlcnMgcmVzcG9uc2UgcGFja2V0
czsgdGhlIGNvcnJlbGF0aW9uIHRoZW4KICAgICMgeWllbGRzIHN0YXR1cy9kdXJhdGlvbl9tcy9y
ZXNwX2J5dGVzIGVuZC10by1lbmQpLiBSZXF1aXJlcyB0aGUgMXMKICAgICMgcmVjdiB0aW1lb3V0
IGluIG1haW4oKSDigJQgYmxvY2tpbmcgcmVjdiArIEJQRiBzdGFydmVzIGFmdGVyIG9uZSBwa3Qu
CiAgICBzayA9IGludChvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfU1BPUlRfSyIsICIxNCIpKQog
ICAgcHMgPSBzb3J0ZWQocG9ydHMpCiAgICBuID0gbGVuKHBzKQogICAgcmV0X3JlaiA9IDUgKyAo
NCBpZiBzayBlbHNlIDIpICogbgogICAgcmV0X2FjYyA9IHJldF9yZWogKyAxCiAgICBwcm9nID0g
W10KICAgIHByb2cuYXBwZW5kKChMREhfQUJTLCAwLCAwLCAxMikpICAgICAgICAgICAgICAgICAj
IGV0aGVydHlwZSA9PSBJUD8KICAgIHByb2cuYXBwZW5kKChKRVFfSywgMCwgcmV0X3JlaiAtIDIs
IDB4MDgwMCkpCiAgICBwcm9nLmFwcGVuZCgoTERCX0FCUywgMCwgMCwgMjMpKSAgICAgICAgICAg
ICAgICAgIyBwcm90byA9PSBUQ1A/CiAgICBwcm9nLmFwcGVuZCgoSkVRX0ssIDAsIHJldF9yZWog
LSA0LCA2KSkKICAgIHByb2cuYXBwZW5kKChMRFhfTVNILCAwLCAwLCAxNCkpICAgICAgICAgICAg
ICAgICAjIFggPSBpaGwqNAogICAgZm9yIGksIHAgaW4gZW51bWVyYXRlKHBzKTogICAgICAgICAg
ICAgICAgICAgICAgICMgQTogZHBvcnQgQCBYKzE2CiAgICAgICAgcHJvZy5hcHBlbmQoKExESF9J
TkQsIDAsIDAsIDE2KSkKICAgICAgICBqdCA9IHJldF9hY2MgLSAobGVuKHByb2cpICsgMSkKICAg
ICAgICBqZiA9IDEgaWYgaSA8IG4gLSAxIGVsc2UgcmV0X3JlaiAtIChsZW4ocHJvZykgKyAxKQog
ICAgICAgIHByb2cuYXBwZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIGlmIHNrOiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIEI6IHNwb3J0IEAgWCtzawogICAg
ICAgIGZvciBpLCBwIGluIGVudW1lcmF0ZShwcyk6CiAgICAgICAgICAgIHByb2cuYXBwZW5kKChM
REhfSU5ELCAwLCAwLCBzaykpCiAgICAgICAgICAgIGp0ID0gcmV0X2FjYyAtIChsZW4ocHJvZykg
KyAxKQogICAgICAgICAgICBqZiA9IDEgaWYgaSA8IG4gLSAxIGVsc2UgcmV0X3JlaiAtIChsZW4o
cHJvZykgKyAxKQogICAgICAgICAgICBwcm9nLmFwcGVuZCgoSkVRX0ssIGp0LCBqZiwgcCkpCiAg
ICBwcm9nLmFwcGVuZCgoUkVUX0ssIDAsIDAsIDApKSAgICAgICAgICAgICAgICAgICAgIyByZWpl
Y3QKICAgIHByb2cuYXBwZW5kKChSRVRfSywgMCwgMCwgMHg0MDAwMCkpICAgICAgICAgICAgICAj
IGFjY2VwdAoKICAgIHRyeToKICAgICAgICBpbXBvcnQgY3R5cGVzCgogICAgICAgIGNsYXNzIFNv
Y2tGaWx0ZXIoY3R5cGVzLlN0cnVjdHVyZSk6CiAgICAgICAgICAgIF9maWVsZHNfID0gWygiY29k
ZSIsIGN0eXBlcy5jX3VpbnQxNiksICgianQiLCBjdHlwZXMuY191aW50OCksCiAgICAgICAgICAg
ICAgICAgICAgICAgICgiamYiLCBjdHlwZXMuY191aW50OCksICgiayIsIGN0eXBlcy5jX3VpbnQz
MildCgogICAgICAgIGNsYXNzIFNvY2tGcHJvZyhjdHlwZXMuU3RydWN0dXJlKToKICAgICAgICAg
ICAgIyBtaXJyb3JzIHN0cnVjdCBzb2NrX2Zwcm9nIHt1MTYgbGVuOyBzb2NrX2ZpbHRlciAqZmls
dGVyfTsKICAgICAgICAgICAgIyBjdHlwZXMgYXBwbGllcyB0aGUgc2FtZSBwb2ludGVyIGFsaWdu
bWVudCBhcyB0aGUgY29tcGlsZXIKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJsZW4iLCBjdHlw
ZXMuY191aW50MTYpLAogICAgICAgICAgICAgICAgICAgICAgICAoImZpbHRlciIsIGN0eXBlcy5Q
T0lOVEVSKFNvY2tGaWx0ZXIpKV0KCiAgICAgICAgYXJyID0gKFNvY2tGaWx0ZXIgKiBsZW4ocHJv
ZykpKCkKICAgICAgICBmb3IgaSwgKGNvZGUsIGp0LCBqZiwgaykgaW4gZW51bWVyYXRlKHByb2cp
OgogICAgICAgICAgICBhcnJbaV0uY29kZSA9IGNvZGU7IGFycltpXS5qdCA9IGp0CiAgICAgICAg
ICAgIGFycltpXS5qZiA9IGpmOyBhcnJbaV0uayA9IGsKICAgICAgICByZXR1cm4gU29ja0Zwcm9n
KGxlbihwcm9nKSwgYXJyKSwgYXJyCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVy
biBOb25lCgoKZGVmIGFwcGx5X3BlcmZfb3B0cyhzb2NrLCBwb3J0cyk6CiAgICAiIiJCZXN0LWVm
Zm9ydCBrZXJuZWwgYXNzaXN0OiBCUEYgcG9ydCBmaWx0ZXIgKyBiaWcgcmN2YnVmLgogICAgTlRf
U05JRkZfTk9fQlBGPTEgZGlzYWJsZXMgdGhlIGZpbHRlciAoZGVidWdnaW5nKS4iIiIKICAgIGJ1
aWx0ID0gTm9uZQogICAgaWYgb3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX05PX0JQRiIpID09ICIx
IjoKICAgICAgICBsb2coIk5UX1NOSUZGX05PX0JQRiBzZXQg4oCUIHNraXBwaW5nIGtlcm5lbCBm
aWx0ZXIiKQogICAgZWxzZToKICAgICAgICBidWlsdCA9IGJ1aWxkX2JwZihwb3J0cykKICAgIGlm
IGJ1aWx0IGlzIG5vdCBOb25lOgogICAgICAgIHRyeToKICAgICAgICAgICAgaW1wb3J0IGN0eXBl
cwogICAgICAgICAgICBsaWJjID0gY3R5cGVzLkNETEwoImxpYmMuc28uNiIpCiAgICAgICAgICAg
IGZwcm9nLCBhcnIgPSBidWlsdCAgICAgICAgICAgICAgICAgICAgICAjIGtlZXAgYXJyIHJlZmVy
ZW5jZWQhCiAgICAgICAgICAgIHJldCA9IGxpYmMuc2V0c29ja29wdChzb2NrLmZpbGVubygpLCBz
b2NrZXQuU09MX1NPQ0tFVCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNPX0FU
VEFDSF9GSUxURVIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuYnly
ZWYoZnByb2cpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLnNpemVv
ZihmcHJvZykpCiAgICAgICAgICAgIGlmIHJldCA9PSAwOgogICAgICAgICAgICAgICAgbG9nKCJr
ZXJuZWwgQlBGIGZpbHRlciBhdHRhY2hlZCAoJWQgbW9uaXRvcmVkIHBvcnRzKSIKICAgICAgICAg
ICAgICAgICAgICAlIGxlbihwb3J0cykpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAg
ICBsb2coIldBUk46IEJQRiBhdHRhY2ggcmVqZWN0ZWQgYnkga2VybmVsIChyZXQ9JWQpICIKICAg
ICAgICAgICAgICAgICAgICAi4oCUIHJ1bm5pbmcgdW5maWx0ZXJlZCIgJSByZXQpCiAgICAgICAg
ZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IEJQRiBmaWx0ZXIg
YXR0YWNoIGZhaWxlZCAoJXMpIOKAlCBydW5uaW5nIHVuZmlsdGVyZWQiCiAgICAgICAgICAgICAg
ICAlIGUpCiAgICBlbHNlOgogICAgICAgIGxvZygiV0FSTjogY3R5cGVzIHVuYXZhaWxhYmxlIOKA
lCBydW5uaW5nIHdpdGhvdXQgQlBGIGZpbHRlciIpCiAgICB0cnk6CiAgICAgICAgd2FudCA9IDgg
KiAxMDI0ICogMTAyNAogICAgICAgIHNvY2suc2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCwg
c29ja2V0LlNPX1JDVkJVRiwgd2FudCkKICAgICAgICBnb3QgPSBzb2NrLmdldHNvY2tvcHQoc29j
a2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SQ1ZCVUYpCiAgICAgICAgbG9nKCJyY3ZidWY6ICVk
IGJ5dGVzIiAlIGdvdCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2coIldB
Uk46IFNPX1JDVkJVRiByYWlzZSBmYWlsZWQ6ICVzIiAlIGUpCgoKIyAtLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHBlcmY6IGZh
bm91dApTT0xfUEFDS0VUID0gMjYzClBBQ0tFVF9GQU5PVVQgPSAxOAoKZGVmIGFwcGx5X2Zhbm91
dChzb2NrLCBncm91cF9pZCk6CiAgICAiIiJLZXJuZWwgbG9hZC1iYWxhbmNlcyBwYWNrZXRzIGFj
cm9zcyBhbGwgc29ja2V0cyBzaGFyaW5nIHRoZSBncm91cC4KICAgIEhhc2hpbmcgaXMgcGVyLWZs
b3ctZGlyZWN0aW9uYWw7IHJlcXVlc3QgZGlyZWN0aW9uIGFsb25lIGRyaXZlcyBldmVudAogICAg
ZW1pc3Npb24sIHNvIGRpcmVjdGlvbmFsIHNwbGl0cyBhcmUgc2FmZS4gUmV0dXJucyBUcnVlIG9u
IHN1Y2Nlc3MuIiIiCiAgICB0cnk6CiAgICAgICAgc29jay5zZXRzb2Nrb3B0KFNPTF9QQUNLRVQs
IFBBQ0tFVF9GQU5PVVQsCiAgICAgICAgICAgICAgICAgICAgICAgIHN0cnVjdC5wYWNrKCJJIiwg
Z3JvdXBfaWQgJiAweEZGRkYpKQogICAgICAgIHJldHVybiBUcnVlCiAgICBleGNlcHQgRXhjZXB0
aW9uIGFzIGU6CiAgICAgICAgbG9nKCJXQVJOOiBQQUNLRVRfRkFOT1VUIGZhaWxlZCAoJXMpIOKA
lCBzaW5nbGUtcHJvY2VzcyBjYXB0dXJlIiAlIGUpCiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVm
IHBhcnNlX2FyZ3MoYXJndik6CiAgICBpZmFjZSA9IE5vbmUKICAgIHBvcnRzID0gWzgwLCA4MDAz
LCA4MDA1LCA4MDA3LCA4MDA5LCA4MDEwLCA4MDExXQogICAgdmVyYm9zZSA9IEZhbHNlCiAgICB3
b3JrZXJzID0gMQogICAgaSA9IDAKICAgIHdoaWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9
IGFyZ3ZbaV0KICAgICAgICBpZiBhID09ICItaSI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxl
bihhcmd2KToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1pIHJlcXVpcmVzIGFu
IGludGVyZmFjZSIpCiAgICAgICAgICAgIGkgKz0gMTsgaWZhY2UgPSBhcmd2W2ldCiAgICAgICAg
ZWxpZiBhID09ICItcCI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAg
ICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1wIHJlcXVpcmVzIGEgY29tbWEtc2VwYXJhdGVk
IHBvcnQgbGlzdCIpCiAgICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICB0cnk6CiAgICAgICAg
ICAgICAgICBwb3J0cyA9IFtpbnQoeCkgZm9yIHggaW4gYXJndltpXS5zcGxpdCgiLCIpIGlmIHgu
c3RyaXAoKV0KICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICBy
YWlzZSBTeXN0ZW1FeGl0KCJpbnZhbGlkIHBvcnQgbGlzdCIpCiAgICAgICAgICAgIGlmIG5vdCBw
b3J0cyBvciBhbnkobm90IHZhbGlkX3BvcnQoeCkgZm9yIHggaW4gcG9ydHMpOgogICAgICAgICAg
ICAgICAgcmFpc2UgU3lzdGVtRXhpdCgicG9ydHMgbXVzdCBiZSBpbiByYW5nZSAxLi42NTUzNSIp
CiAgICAgICAgZWxpZiBhID09ICItaiI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2
KToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1qIHJlcXVpcmVzIGEgd29ya2Vy
IGNvdW50IikKICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAg
ICAgIHdvcmtlcnMgPSBtYXgoMSwgaW50KGFyZ3ZbaV0pKQogICAgICAgICAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImludmFsaWQgd29ya2Vy
IGNvdW50IikKICAgICAgICBlbGlmIGEgPT0gIi12IjoKICAgICAgICAgICAgdmVyYm9zZSA9IFRy
dWUKICAgICAgICBlbGlmIGEgaW4gKCItaCIsICItLWhlbHAiKToKICAgICAgICAgICAgcHJpbnQo
X19kb2NfXyk7IHJhaXNlIFN5c3RlbUV4aXQoMCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBy
YWlzZSBTeXN0ZW1FeGl0KCJ1bmtub3duIGFyZzogJXMiICUgYSkKICAgICAgICBpICs9IDEKICAg
IHJldHVybiBpZmFjZSwgc2V0KHBvcnRzKSwgdmVyYm9zZSwgd29ya2VycwoKCmNsYXNzIEZsb3co
b2JqZWN0KToKICAgIF9fc2xvdHNfXyA9ICgiYnVmIiwgImhkcnMiLCAidG91Y2hlZCIpCiAgICBk
ZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5idWYgPSBieXRlYXJyYXkoKQogICAgICAg
IHNlbGYuaGRycyA9IHt9CiAgICAgICAgc2VsZi50b3VjaGVkID0gdGltZS50aW1lKCkKCgojIC0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gcmVzcG9uc2Ug
Y29ycmVsYXRpb24gLS0tLQpQRU5ESU5HX1RUTCA9IDUuMCAgICAgICAgIyBmbHVzaCB1bm1hdGNo
ZWQgcmVxdWVzdHMgYWZ0ZXIgdGhpcyBtYW55IHNlY29uZHMKUEVORElOR19NQVggPSA4MTkyICAg
ICAgICMgaGFyZCBjYXA7IG92ZXJmbG93IGZsdXNoZXMgb2xkZXN0IGZpcnN0CgojIHBlbmRpbmdb
KHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpXSAgLS0ga2V5IGlzIHRoZSBSRVNQT05TRSB0
dXBsZToKIyBzZXJ2ZXItPmNsaWVudC4gVmFsdWU6IFtldmVudCwgcmVxX3RzXS4gQSBsaXN0IHBl
ciBrZXkgaGFuZGxlcyBIVFRQCiMga2VlcC1hbGl2ZSBwaXBlbGluaW5nIChzZXZlcmFsIHJlcXVl
c3RzIGJlZm9yZSByZXNwb25zZXMgYXJyaXZlKS4KcGVuZGluZyA9IHt9CgoKZGVmIHBlbmRpbmdf
ZGVsKHJrKToKICAgIHBlbmRpbmcucG9wKHJrLCBOb25lKQoKCmRlZiBwZW5kaW5nX3BvcChyaywg
b3V0KToKICAgICIiIkZsdXNoIHRoZSBvbGRlc3QgcGVuZGluZyBldmVudCBmb3IgdGhpcyByZXNw
b25zZSB0dXBsZSAoRklOL1JTVCBvcgogICAgb3ZlcmZsb3cgcGF0aCkuIEVtaXRzIHdoYXRldmVy
IHRoZSBldmVudCBoYXMg4oCUIHN0YXR1cyBzdGF5cyBudWxsLiIiIgogICAgbHN0ID0gcGVuZGlu
Zy5nZXQocmspCiAgICBpZiBub3QgbHN0OgogICAgICAgIHJldHVybiBOb25lCiAgICBldiwgXyA9
IGxzdC5wb3AoMCkKICAgIGlmIG5vdCBsc3Q6CiAgICAgICAgcGVuZGluZ19kZWwocmspCiAgICBv
dXQuYXBwZW5kKGV2KQogICAgcmV0dXJuIGV2CgoKZGVmIHBhcnNlX3Jlc3BvbnNlX2hlYWQocGF5
bG9hZCk6CiAgICAiIiJGaXJzdCBsaW5lICdIVFRQLzEueCBOTk4gLi4uJyAtPiAoc3RhdHVzX2lu
dHxOb25lLCBjb250ZW50X2xlbnxOb25lKS4KICAgIE9ubHkgbG9va3MgYXQgd2hhdCdzIGluIHRo
aXMgc2VnbWVudDsgaGVhZGVycyBmaXQgb25lIHNlZ21lbnQgZm9yIGFsbAogICAgcmVhbGlzdGlj
IEFQSSByZXNwb25zZXMuIiIiCiAgICB0cnk6CiAgICAgICAgaGVhZCA9IHBheWxvYWQuc3BsaXQo
YiJcclxuXHJcbiIsIDEpWzBdCiAgICAgICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwg
YiJcbiIpLnNwbGl0KGIiXG4iKQogICAgICAgIGZpcnN0ID0gbGluZXNbMF0uc3BsaXQoKQogICAg
ICAgIGlmIGxlbihmaXJzdCkgPCAyIG9yIG5vdCBmaXJzdFswXS5zdGFydHN3aXRoKGIiSFRUUC8i
KToKICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAgICBzdCA9IGludChmaXJzdFsx
XSkKICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgSW5kZXhFcnJvcik6CiAgICAgICAgcmV0dXJuIE5v
bmUsIE5vbmUKICAgIGNsZW4gPSBOb25lCiAgICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAg
IGxvdyA9IGxuLmxvd2VyKCkKICAgICAgICBpZiBsb3cuc3RhcnRzd2l0aChiImNvbnRlbnQtbGVu
Z3RoOiIpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjbGVuID0gaW50KGxuLnNw
bGl0KGIiOiIsIDEpWzFdLnN0cmlwKCkpCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgog
ICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICBicmVhawogICAgcmV0dXJuIHN0LCBjbGVu
CgoKZGVmIHZhbGlkX3BvcnQocCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIDEgPD0gaW50KHAp
IDw9IDY1NTM1CiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0
dXJuIEZhbHNlCgoKZGVmIGJhc2ljX3VzZXIodmFsdWUpOgogICAgIiIiQXV0aG9yaXphdGlvbiBo
ZWFkZXIgdmFsdWUgLT4gKHVzZXJ8Tm9uZSwgc2NoZW1lfE5vbmUpLiBCYXNpYyBvbmx5LiIiIgog
ICAgcGFydHMgPSB2YWx1ZS5zdHJpcCgpLnNwbGl0KE5vbmUsIDEpCiAgICBpZiBsZW4ocGFydHMp
ICE9IDI6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIHNjaGVtZSA9IHBhcnRzWzBdLmxv
d2VyKCkKICAgIGlmIHNjaGVtZSA9PSAiYmFzaWMiOgogICAgICAgIHRyeToKICAgICAgICAgICAg
cGFkID0gcGFydHNbMV0uc3RyaXAoKQogICAgICAgICAgICBpZiBsZW4ocGFkKSA+IDEwMjQ6CiAg
ICAgICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBwYWQgKz0gIj0iICog
KC1sZW4ocGFkKSAlIDQpCiAgICAgICAgICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNvZGUocGFkKQog
ICAgICAgICAgICBpZiBsZW4ocmF3KSA+IDUxMjoKICAgICAgICAgICAgICAgIHJldHVybiBOb25l
LCBOb25lCiAgICAgICAgICAgIGlmIGIiOiIgaW4gcmF3OgogICAgICAgICAgICAgICAgdXNlciA9
IHJhdy5zcGxpdChiIjoiLCAxKVswXQogICAgICAgICAgICAgICAgcmV0dXJuIHVzZXIuZGVjb2Rl
KCJ1dGYtOCIsICJyZXBsYWNlIilbOjY0XSwgImJhc2ljIgogICAgICAgIGV4Y2VwdCBFeGNlcHRp
b246CiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBlbGlmIHNjaGVtZSA9PSAiYmVh
cmVyIjoKICAgICAgICByZXR1cm4gTm9uZSwgImJlYXJlciIKICAgIHJldHVybiBOb25lLCBOb25l
CgoKZGVmIGZpbmlzaF9ldmVudChmbG93LCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3Bv
cnQsIHBvcnRzLCBub2RlX2hvc3QpOgogICAgaCA9IGZsb3cuaGRycwogICAgdXNlciA9IHNjaGVt
ZSA9IE5vbmUKICAgIGF1dGh6ID0gaC5nZXQoImF1dGhvcml6YXRpb24iKQogICAgaWYgYXV0aHo6
CiAgICAgICAgdXNlciwgc2NoZW1lID0gYmFzaWNfdXNlcihhdXRoeikKICAgICMgVzNDIHRyYWNl
IGNvbnRleHQ6IGhvbm9yIGluY29taW5nIHRyYWNlcGFyZW50LCBlbHNlIGdlbmVyYXRlIG9uZSBz
bwogICAgIyBldmVyeSB0cmFuc2FjdGlvbiBjYXJyaWVzIGEgdHJhY2VfaWQgZm9yIGh1Yi1zaWRl
IGNvcnJlbGF0aW9uLgogICAgIyBOT1RFIHB5Mi42OiBieXRlcyBoYXMgbm8gLmhleCgpIOKAlCB1
c2UgYmluYXNjaWkuaGV4bGlmeS4KICAgIHRwID0gaC5nZXQoInRyYWNlcGFyZW50IikKICAgIHRy
YWNlX2lkID0gTm9uZQogICAgaWYgdHA6CiAgICAgICAgcGFydHMgPSB0cC5zcGxpdCgiLSIpCiAg
ICAgICAgaWYgbGVuKHBhcnRzKSA9PSA0IGFuZCBsZW4ocGFydHNbMV0pID09IDMyOgogICAgICAg
ICAgICB0cmFjZV9pZCA9IHBhcnRzWzFdLmxvd2VyKCkKICAgIGlmIG5vdCB0cmFjZV9pZDoKICAg
ICAgICB0cnk6CiAgICAgICAgICAgIHJuZCA9IGJpbmFzY2lpLmhleGxpZnkob3MudXJhbmRvbSgx
NikpCiAgICAgICAgICAgIHJuZCA9IHJuZC5kZWNvZGUoImFzY2lpIikgaWYgaGFzYXR0cihybmQs
ICJkZWNvZGUiKSBlbHNlIHJuZAogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAg
IHJuZCA9ICgiJTAzMngiICUgKGludCh0aW1lLnRpbWUoKSAqIDEwMDApKSlbLTMyOl0KICAgICAg
ICBwaWQ4ID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDgpKQogICAgICAgIHBpZDggPSBw
aWQ4LmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHBpZDgsICJkZWNvZGUiKSBlbHNlIHBpZDgK
ICAgICAgICB0cCA9ICIwMC0lcy0lcy0wMSIgJSAocm5kLCBwaWQ4KQogICAgICAgIHRyYWNlX2lk
ID0gcm5kCiAgICBldiA9IHsKICAgICAgICAidHMiOiBpbnQodGltZS50aW1lKCkpLAogICAgICAg
ICJob3N0Ijogbm9kZV9ob3N0LAogICAgICAgICJzcmMiOiAicGNhcCIsCiAgICAgICAgInNlcnZp
Y2UiOiAicG9ydDolZCIgJSBkcG9ydCwKICAgICAgICAibWV0aG9kIjogaC5nZXQoIl9tZXRob2Qi
KSBvciAiLSIsCiAgICAgICAgInBhdGgiOiAoaC5nZXQoIl9wYXRoIikgb3IgIi0iKS5zcGxpdCgi
PyIsIDEpWzBdWzoxMjBdLAogICAgICAgICJ1c2VyIjogdXNlciwKICAgICAgICAic2NoZW1lIjog
c2NoZW1lLAogICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJzb3VyY2VfcHJvYmUiOiAicGNh
cC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIpLAogICAgICAgICJ1c2Vy
X2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAieF9mb3J3YXJkZWRfZm9yIjog
aC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIiOiBzcmNfaXAsCiAgICAg
ICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6IGRzdF9pcCwKICAgICAg
ICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRvcmluZyBzY2hlbWEgKG9w
cyBBUEktbG9nIGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3Bf
Ynl0ZXMgYXJlIHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1vbmx5CiAgICAgICAgIyBj
YXB0dXJlIGNhbm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUgaHViIHRvIGVucmljaCBv
ciBsZWF2ZS4KICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAogICAgICAgICJ0cmFjZV9p
ZCI6IHRyYWNlX2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwgICAgICAgICAgIyBodWIg
bWFwcyBwb3J0LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAgICAibW9kdWxlX2lkIjog
InBjYXAtaHR0cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNlIGNvcnJlbGF0aW9uIG9u
bHkgZm9yIG1vbml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyByZXNwb25zZS1zaWRlIGZp
bHRlciBtYXkgc3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNwb3J0IGVxdWFsIHRvIGEK
ICAgICMgbW9uaXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVjYXVzZSBwYXJzZV9yZXNw
b25zZV9oZWFkIHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRwb3J0IGluIHBvcnRzIG9y
IGguZ2V0KCJfbWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBoYW5kbGVfcGF5bG9hZChmbG93cywg
a2V5LCByZXZfa2V5LCBwYXlsb2FkLCBtZXRhLCBwb3J0cywgbm9kZV9ob3N0LCBvdXQsCiAgICAg
ICAgICAgICAgICAgICBwZW5kaW5nX3RibD1Ob25lLCBub3c9Tm9uZSk6CiAgICAiIiJGZWVkIG9u
ZSBkaXJlY3Rpb24ncyBwYXlsb2FkOyBlbWl0IGZpbmlzaGVkIGV2ZW50cyB0byBvdXQobGlzdCku
CgogICAgSEVBREVSLU9OTFkgY2FwdHVyZTogdGhlIHJlcXVlc3QgZXZlbnQgaXMgYnVpbHQgdGhl
IG1vbWVudCBcXHJcXG5cXHJcXG4gaXMKICAgIHNlZW4uIFdpdGggcmVzcG9uc2UgY29ycmVsYXRp
b24gZW5hYmxlZCAocGVuZGluZ190YmwpLCB0aGUgZmluaXNoZWQKICAgIGV2ZW50IGdvZXMgaW50
byB0aGUgcGVuZGluZyB0YWJsZSBpbnN0ZWFkIG9mIG91dCDigJQgaXQgaXMgZW1pdHRlZCB3aGVu
CiAgICB0aGUgbWF0Y2hpbmcgcmVzcG9uc2UgaGVhZCBhcnJpdmVzLCBvciBvbiBUVEwvdGVhcmRv
d24gZmFsbGJhY2suCiAgICBSZXF1ZXN0IGJvZGllcyBhcmUgTk9UIGJ1ZmZlcmVkIOKAlCBCYXNp
YyBhdXRoIChhbGwgd2UgbWluZSkgcmlkZXMgaGVhZGVycywKICAgIHNvIGJvZHkgYnl0ZXMgY29z
dCBtZW1vcnkgYW5kIGRlbGF5IGV2ZW50cyBmb3IgemVybyBpbmZvcm1hdGlvbi4gQSBsYXRlcgog
ICAgc2VnbWVudCBvbiB0aGUgc2FtZSBjb25uZWN0aW9uIHNpbXBseSBmYWlscyB0aGUgcmVxdWVz
dC1saW5lIGNoZWNrIGFuZAogICAgaXMgZGlzY2FyZGVkLiIiIgogICAgZHN0X2lwLCBkcG9ydCwg
c3JjX2lwLCBzcG9ydCA9IG1ldGEKICAgIGlmIG5vdCB2YWxpZF9wb3J0KGRwb3J0KSBvciBub3Qg
dmFsaWRfcG9ydChzcG9ydCk6CiAgICAgICAgcmV0dXJuCiAgICBmbCA9IGZsb3dzLmdldChrZXkp
CiAgICBpZiBmbCBpcyBOb25lOgogICAgICAgIGZsID0gRmxvdygpCiAgICAgICAgZmxvd3Nba2V5
XSA9IGZsCiAgICAgICAgaWYgbGVuKGZsb3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICAgICAgZW5m
b3JjZV9saW1pdChmbG93cywgdGltZS50aW1lKCkpCiAgICBmbC50b3VjaGVkID0gdGltZS50aW1l
KCkKICAgIGZsLmJ1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWQpKQoKICAgIGlkeCA9IGZsLmJ1
Zi5maW5kKGIiXHJcblxyXG4iKQogICAgaWYgaWR4IDwgMDoKICAgICAgICBpZiBsZW4oZmwuYnVm
KSA+IE1BWF9IRFJTOgogICAgICAgICAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgICAgIHJl
dHVybgogICAgaGVhZCA9IGJ5dGVzKGZsLmJ1Zls6aWR4XSkKICAgIGxpbmVzID0gaGVhZC5yZXBs
YWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxpdChiIlxuIikKICAgIGhkcnMgPSB7fQogICAgZmlyc3Qg
PSBsaW5lc1swXS5zdHJpcCgpLnNwbGl0KCkKICAgIGlmIGxlbihmaXJzdCkgPj0gMiBhbmQgZmly
c3RbMF0gaW4gWwogICAgICAgICAgICBtLmVuY29kZSgpIGZvciBtIGluIE1FVEhPRFNdOgogICAg
ICAgIGhkcnNbIl9tZXRob2QiXSA9IGZpcnN0WzBdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIp
CiAgICAgICAgaGRyc1siX3BhdGgiXSA9IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFj
ZSIpCiAgICBlbHNlOgogICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpICAgICAgICMgbm90IGEg
cmVxdWVzdCBzdGFydAogICAgICAgIHJldHVybgogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAg
ICAgICBpZiBiIjoiIG5vdCBpbiBsbjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBrbiwg
a3YgPSBsbi5zcGxpdChiIjoiLCAxKQogICAgICAgIGhkcnNba24uc3RyaXAoKS5sb3dlcigpLmRl
Y29kZSgKICAgICAgICAgICAgImFzY2lpIiwgInJlcGxhY2UiKV0gPSBrdi5zdHJpcCgpLmRlY29k
ZSgKICAgICAgICAgICAgICAgICJ1dGYtOCIsICJyZXBsYWNlIilbOjE4MF0KICAgIGZsLmhkcnMg
PSBoZHJzCiAgICBldiA9IGZpbmlzaF9ldmVudChmbCwga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNf
aXAsIHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgcG9ydHMsIG5vZGVfaG9zdCkKICAgIGRl
bCBmbG93c1trZXldCiAgICBpZiBub3QgZXY6CiAgICAgICAgcmV0dXJuCiAgICBldlsicmVxX2J5
dGVzIl0gPSBpZHggKyA0ICAgICAgICAgICMgY2FwdHVyZWQgcmVxdWVzdCBoZWFkICsgdGVybWlu
YXRvcgogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KSAg
ICAgICAgICAgICAgICAgIyBjb3JyZWxhdGlvbiBkaXNhYmxlZCAobGVnYWN5IHBhdGgpCiAgICAg
ICAgcmV0dXJuCiAgICAjIHF1ZXVlIGZvciByZXNwb25zZSBjb3JyZWxhdGlvbjsga2V5IGlzIHRo
ZSBSRVNQT05TRSB0dXBsZQogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkK
ICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAg
IGlmIGxlbihwZW5kaW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9v
bGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJs
W3JrXSA9IFtdCiAgICBlbnQuYXBwZW5kKFtldiwgbm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNl
IHRpbWUudGltZSgpXSkKCgpkZWYgc3dlZXBfaWRsZShmbG93cywgbm93KToKICAgIHN0YWxlID0g
W10KICAgIGZvciBrLCBmbCBpbiBmbG93cy5pdGVtcygpOgogICAgICAgIGlmIG5vdyAtIGZsLnRv
dWNoZWQgPiBGTE9XX1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKGspCiAgICBmb3IgayBp
biBzdGFsZToKICAgICAgICBkZWwgZmxvd3Nba10KCgpkZWYgX2ZsdXNoX29sZGVzdF9wZW5kaW5n
KHBlbmRpbmdfdGJsLCBvdXQpOgogICAgIiIiT3ZlcmZsb3cgZ3VhcmQ6IGVtaXQgdGhlIHNpbmds
ZSBvbGRlc3QgcGVuZGluZyBldmVudCBhcy1pcy4iIiIKICAgIG9sZGVzdF9rZXksIG9sZGVzdF90
cyA9IE5vbmUsIE5vbmUKICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJsLml0ZW1zKCk6CiAg
ICAgICAgdHMgPSBsc3RbMF1bMV0KICAgICAgICBpZiBvbGRlc3RfdHMgaXMgTm9uZSBvciB0cyA8
IG9sZGVzdF90czoKICAgICAgICAgICAgb2xkZXN0X2tleSwgb2xkZXN0X3RzID0gcmssIHRzCiAg
ICBpZiBvbGRlc3Rfa2V5IGlzIG5vdCBOb25lOgogICAgICAgIHBlbmRpbmdfcG9wKG9sZGVzdF9r
ZXksIG91dCkKCgpkZWYgc3dlZXBfcGVuZGluZyhwZW5kaW5nX3RibCwgbm93LCBvdXQpOgogICAg
IiIiVFRMIGZsdXNoOiBlbWl0IHJlcXVlc3RzIHdob3NlIHJlc3BvbnNlcyBuZXZlciBzaG93ZWQg
dXAuIiIiCiAgICBzdGFsZSA9IFtdCiAgICBmb3IgcmssIGxzdCBpbiBwZW5kaW5nX3RibC5pdGVt
cygpOgogICAgICAgIGlmIG5vdyAtIGxzdFswXVsxXSA+IFBFTkRJTkdfVFRMOgogICAgICAgICAg
ICBzdGFsZS5hcHBlbmQocmspCiAgICBmb3IgcmsgaW4gc3RhbGU6CiAgICAgICAgcGVuZGluZ19w
b3AocmssIG91dCkKCgpkZWYgZW5mb3JjZV9saW1pdChmbG93cywgbm93KToKICAgICIiIkNhcCBm
bG93LXRhYmxlIHNpemUgKHB5Mi42OiBubyBPcmRlcmVkRGljdCDigJQgc3dlZXAgc3RhbGUsIHRo
ZW4gRklGTwogICAgYnkgaW5zZXJ0aW9uIG9yZGVyLCB3aGljaCBwbGFpbiBkaWN0cyBwcmVzZXJ2
ZSBpbiBDUHl0aG9uKS4iIiIKICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdykKICAgIHdoaWxlIGxl
bihmbG93cykgPiBNQVhfRkxPV1M6CiAgICAgICAgZmxvd3MucG9waXRlbSgpICAgICAgICAgICMg
b2xkZXN0LWluc2VydGVkIGtleSBvbiBDUHl0aG9uIDIuNi8yLjcKCgpkZWYgbWFpbigpOgogICAg
aWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0p
CiAgICBub2RlX2hvc3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCgogICAg
dHJ5OgogICAgICAgICMgcHJvdG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9JUCk6IGEgMC1wcm90
b2NvbCBzb2NrZXQgcmVjZWl2ZXMKICAgICAgICAjIE5PVEhJTkcgKGtlcm5lbCBkZWxpdmVycyBv
bmx5IG1hdGNoaW5nIGV0aGVydHlwZTsgMCBtYXRjaGVzIG5vbmUpLgogICAgICAgICMgc29ja2V0
Lmh0b25zIGlzIGNvcnJlY3Qgb24gZXZlcnkgcGxhdGZvcm0g4oCUIGRvIE5PVCB1c2UgbnRvaHMg
aGVyZS4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfUEFDS0VULCBzb2NrZXQu
U09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29ja2V0Lmh0b25zKEVUSF9QX0lQ
KSkKICAgIGV4Y2VwdCBBdHRyaWJ1dGVFcnJvcjoKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJB
Rl9QQUNLRVQgdW5hdmFpbGFibGUgb24gdGhpcyBwbGF0Zm9ybSIpCiAgICBleGNlcHQgc29ja2V0
LmVycm9yIGFzIGU6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IG9wZW4gQUZfUEFD
S0VUIHNvY2tldCAoJXMpIOKAlCBuZWVkICIKICAgICAgICAgICAgICAgICAgICAgICAgICJDQVBf
TkVUX1JBVyAvIHJvb3QiICUgZSkKICAgICMga2VybmVsIGFzc2lzdCBCRUZPUkUgYmluZDogQlBG
IHBvcnQgZmlsdGVyICsgYmlnIHJjdmJ1Zi4gV2l0aCB0aGUKICAgICMgZmlsdGVyIGF0dGFjaGVk
IHRoZSBrZXJuZWwgZHJvcHMgbm9uLW1vbml0b3JlZCB0cmFmZmljIGZvciB1cywgd2hpY2gKICAg
ICMgaXMgd2hhdCBsaWZ0cyB0aGUgY2FwdHVyZSBjZWlsaW5nIGZyb20gfjcyMCBldi9zIHRvIHdp
cmUgcmF0ZS4KICAgIGFwcGx5X3BlcmZfb3B0cyhzLCBwb3J0cykKICAgIHRyeToKICAgICAgICBz
LmJpbmQoKGlmYWNlIG9yICIiLCAwKSkKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3I6CiAgICAgICAg
IyBiaW5kaW5nIHRvIGEgc3BlY2lmaWMgaWZhY2UgZmFpbGVkIOKAlCBmYWxsIGJhY2sgdG8gYWxs
IGludGVyZmFjZXMKICAgICAgICB0cnk6CiAgICAgICAgICAgIHMuYmluZCgoIiIsIDApKQogICAg
ICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3I6CiAgICAgICAgICAgIHBhc3MgICAgICAgICAgIyB1bmJv
dW5kIHNvY2tldCBzdGlsbCByZWNlaXZlcyBvbiBhbGwgaW50ZXJmYWNlcwogICAgZmFub3V0X29r
ID0gRmFsc2UKICAgIGlmIHdvcmtlcnMgPiAxOgogICAgICAgIGZhbm91dF9vayA9IGFwcGx5X2Zh
bm91dChzLCAweEYwMEQpCiAgICAgICAgaWYgZmFub3V0X29rOgogICAgICAgICAgICBsb2coImZh
bm91dCBncm91cCAweEYwMEQ6IHNwYXduaW5nICVkIHdvcmtlcnMiICUgd29ya2VycykKCiAgICAj
IHByZWNvbXBpbGVkIHN0cnVjdCByZWFkZXJzIOKAlCB1bnBhY2tfZnJvbSByZWFkcyBzdHJhaWdo
dCBvdXQgb2YgdGhlCiAgICAjIHBhY2tldCBidWZmZXIgKG5vIHNsaWNlIGNvcGllcykgYW5kIHlp
ZWxkcyBpbnRzIHVuZGVyIHB5MiBBTkQgcHkzCiAgICB1MTYgPSBzdHJ1Y3QuU3RydWN0KCIhSCIp
LnVucGFja19mcm9tCiAgICB1aCA9IHN0cnVjdC5TdHJ1Y3QoIiFISCIpLnVucGFja19mcm9tICAg
IyBzcG9ydCxkcG9ydCBpbiBvbmUgcmVhZAogICAgdWIgPSBzdHJ1Y3QuU3RydWN0KCIhQkIiKS51
bnBhY2tfZnJvbQogICAgbnRvYSA9IHNvY2tldC5pbmV0X250b2EKCiAgICBmbG93cyA9IHt9CiAg
ICBydW5uaW5nID0gW1RydWVdCgogICAgZGVmIHN0b3Aoc2lnbnVtLCBmcmFtZSk6CiAgICAgICAg
cnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLCBzdG9w
KQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9wKQoKICAgIGxhc3Rfc3dlZXAg
PSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcgb24gJXMgcG9ydHM9JXMgcGlkPSVkIiAl
CiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRlZChwb3J0cyksIG9zLmdldHBpZCgpKSkK
CiAgICAjIGZvcmsgZXh0cmEgY2FwdHVyZSB3b3JrZXJzIEFGVEVSIGZhbm91dCBhdHRhY2g7IFdJ
VEhPVVQgYSB3b3JraW5nCiAgICAjIGZhbm91dCBncm91cCBldmVyeSBwcm9jZXNzIHdvdWxkIHJl
Y2VpdmUgRVZFUlkgcGFja2V0IChkdXBsaWNhdGVzKSwKICAgICMgc28gc2luZ2xlLXByb2Nlc3Mg
bW9kZSBpcyBmb3JjZWQgd2hlbiB0aGUga2VybmVsIGxhY2tzIHN1cHBvcnQKICAgICMgKFBBQ0tF
VF9GQU5PVVQgbmVlZHMga2VybmVsID49IDMuMTsgZWw2IDIuNi4zMiBkb2VzIG5vdCBoYXZlIGl0
KQogICAgaWYgZmFub3V0X29rOgogICAgICAgIGZvciBfIGluIHJhbmdlKHdvcmtlcnMgLSAxKToK
ICAgICAgICAgICAgaWYgb3MuZm9yaygpID09IDA6CiAgICAgICAgICAgICAgICBicmVhayAgICAg
ICAgICAgICAgICAgIyBjaGlsZDogZmFsbCB0aHJvdWdoIGludG8gaXRzIG93biBsb29wCgogICAg
IyAxcyByZWN2IHRpbWVvdXQ6IChhKSBsZXRzIHRoZSBwZW5kaW5nL2Zsb3cgc3dlZXBzIGFjdHVh
bGx5IGZpcmUg4oCUCiAgICAjIHdpdGhvdXQgaXQgYGV4Y2VwdCBzb2NrZXQudGltZW91dGAgbmV2
ZXIgcnVuczsgKGIpIGVtcGlyaWNhbGx5IFJFUVVJUkVECiAgICAjIHdpdGggdGhlIEJQRiBmaWx0
ZXIgYXR0YWNoZWQ6IGEgZnVsbHktYmxvY2tpbmcgcmVjdiBvbiB0aGlzIGtlcm5lbAogICAgIyBz
dGFydmVzIGFmdGVyIHRoZSBmaXJzdCBwYWNrZXQsIHdoaWxlIHRoZSB0aW1lb3V0J2QgcmVjdiBk
ZWxpdmVycwogICAgIyBjb250aW51b3VzbHkgKHZlcmlmaWVkIGJ5IEEvQjogcng9MSB2cyByeD0y
OSBpZGVudGljYWwgb3RoZXJ3aXNlKS4KICAgIHMuc2V0dGltZW91dCgxLjApCgogICAgZGJnID0g
b3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX0RFQlVHIikgPT0gIjEiCiAgICBkYmdfcnggPSAwCiAg
ICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAgIHRy
eToKICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQogICAgICAgICAgICBkYmdfcnggKz0g
MQogICAgICAgICAgICBpZiBkYmcgYW5kIHRpbWUudGltZSgpIC0gZGJnX2xhc3QgPiA1OgogICAg
ICAgICAgICAgICAgbG9nKCJERUJVRyByeD0lZCIgJSBkYmdfcngpCiAgICAgICAgICAgICAgICBk
YmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgZXhjZXB0IHNvY2tldC50aW1lb3V0OgogICAg
ICAgICAgICBpZiBkYmc6CiAgICAgICAgICAgICAgICBsb2coIkRFQlVHIHRpbWVvdXQgcng9JWQi
ICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAg
ICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgICAgICBpZiBub3cgLSBsYXN0X3N3ZWVwID4g
MzA6CiAgICAgICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICAgICAgICAgICAg
ICBvdXRfcyA9IFtdCiAgICAgICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywg
b3V0X3MpCiAgICAgICAgICAgICAgICBmb3IgZXYgaW4gb3V0X3M6CiAgICAgICAgICAgICAgICAg
ICAgc3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgICAg
ICBpZiBvdXRfczoKICAgICAgICAgICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAg
ICAgICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKICAgICAgICAgICAgY29udGludWUKICAgICAgICBl
eGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgICAgIGlmIGUuZXJybm8gPT0gZXJybm8u
RUlOVFI6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICByYWlzZQogICAgICAg
IG4gPSBsZW4ocGt0KQogICAgICAgIGlmIG4gPCAzNDoKICAgICAgICAgICAgY29udGludWUKICAg
ICAgICBvdXQgPSBbXQogICAgICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRo
ZXJuZXQgaGVhZGVyCiAgICAgICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBl
dHlwZSA9PSBFVEhfUF9WTEFOOgogICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQog
ICAgICAgICAgICBvZmYgPSAxOAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAg
ICAgICAgIGNvbnRpbnVlICAgICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlz
IGlzIHJhcmUKICAgICAgICBpcDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4g
NCAhPSA0IG9yIHViKHBrdCwgb2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAg
ICAgICAgICAgY29udGludWUKICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAg
ZnJhZyA9IHUxNihwa3QsIG9mZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAg
ICAgICAgICAgICAgICAgICAgICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29u
dGludWUKICAgICAgICBzcmNfaXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAg
ICAgZHN0X2lwID0gbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYg
PSBvZmYgKyBpaGwKICAgICAgICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAg
ICAgZG9mZl9mbGFncyA9IHViKHBrdCwgdGNwX29mZiArIDEyKQogICAgICAgIGRvZmYgPSAoZG9m
Zl9mbGFnc1swXSA+PiA0KSAqIDQKICAgICAgICBwYXlfc3RhcnQgPSB0Y3Bfb2ZmICsgZG9mZgog
ICAgICAgIGlmIG4gPD0gcGF5X3N0YXJ0OgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICMgbm8gcGF5bG9hZCBpbiBzZWdtZW50CiAgICAgICAgcGF5bG9h
ZCA9IHBrdFtwYXlfc3RhcnQ6XQogICAgICAgIGZsYWdzID0gZG9mZl9mbGFnc1sxXQogICAgICAg
IG5vdyA9IHRpbWUudGltZSgpCgogICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLSBSRVNQT05TRSBk
aXJlY3Rpb24gKHNlcnZlciAtPiBjbGllbnQpIC0tLS0tLS0tLS0KICAgICAgICBpZiBzcG9ydCBp
biBwb3J0cyBhbmQgZHBvcnQgbm90IGluIHBvcnRzOgogICAgICAgICAgICAjIHBlbmRpbmcga2V5
IHdhcyBzdG9yZWQgYXMgKHNlcnZlcl9pcCwgc2VydmVyX3BvcnQsIGNsaWVudF9pcCwKICAgICAg
ICAgICAgIyBjbGllbnRfcG9ydCkgPT0gKHNyYywgc3BvcnQsIGRzdCwgZHBvcnQpIE9GIFRISVMg
cmVzcG9uc2UgcGt0CiAgICAgICAgICAgIHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBv
cnQpCiAgICAgICAgICAgIGlmIGZsYWdzICYgMHgwNTogICAgICAgICAgICAgICAgICAgICAgIyBG
SU58UlNUOiBmbHVzaCB1bm1hdGNoZWQKICAgICAgICAgICAgICAgIGV2ID0gcGVuZGluZ19wb3Ao
cmssIG91dCkKICAgICAgICAgICAgZWxpZiBwYXlsb2FkWzo1XSA9PSBiIkhUVFAvIjoKICAgICAg
ICAgICAgICAgIHN0LCBjbGVuID0gcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2FkKQogICAgICAg
ICAgICAgICAgZW50ID0gcGVuZGluZy5nZXQocmspCiAgICAgICAgICAgICAgICBpZiBlbnQgaXMg
bm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgZXYgPSBlbnRbMF1bMF0KICAgICAgICAgICAg
ICAgICAgICBldlsic3RhdHVzIl0gPSBzdAogICAgICAgICAgICAgICAgICAgIGV2WyJkdXJhdGlv
bl9tcyJdID0gaW50KChub3cgLSBlbnRbMF1bMV0pICogMTAwMCkKICAgICAgICAgICAgICAgICAg
ICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAgICAgICBldlsicmVzcF9i
eXRlcyJdID0gY2xlbgogICAgICAgICAgICAgICAgICAgIHBlbmRpbmdfZGVsKHJrKQogICAgICAg
ICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgIyAtLS0tLS0tLS0tLS0tLS0tIFJF
UVVFU1QgZGlyZWN0aW9uIChjbGllbnQgLT4gc2VydmVyKSAtLS0tLS0tLS0tLQogICAgICAgIGVs
aWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAgICAgIGlmIGZsYWdzICYgMHgwNTogICAgICAgICAg
ICAgICAgICAgICAgIyB0ZWFyZG93biB3L28gcmVzcG9uc2Ugc2VlbgogICAgICAgICAgICAgICAg
cmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgICAgICAgICAgICAgIHBlbmRp
bmdfcG9wKHJrLCBvdXQpCiAgICAgICAgICAgIGtleSA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAs
IGRwb3J0KQogICAgICAgICAgICBoYW5kbGVfcGF5bG9hZChmbG93cywga2V5LCBOb25lLCBwYXls
b2FkLAogICAgICAgICAgICAgICAgICAgICAgICAgICAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBz
cG9ydCksCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRzLCBub2RlX2hvc3QsIG91dCwg
cGVuZGluZywgbm93KQogICAgICAgIGlmIG91dDoKICAgICAgICAgICAgdyA9IHN5cy5zdGRvdXQu
d3JpdGUKICAgICAgICAgICAgZm9yIGV2IGluIG91dDoKICAgICAgICAgICAgICAgIHcoanNvbi5k
dW1wcyhldikgKyAiXG4iKQogICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKCiAgICBsb2co
InN0b3BwZWQiKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
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
IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBqc29uLCBvcywgc2lnbmFsLCBzb2NrZXQs
IHN5cwoKIyBweTIuNi9lbDYgbmFtZXMgZmlyc3Q7IHB5MyBmYWxsYmFja3MgZm9yIGRldi1ib3gg
dGVzdGluZy4gVGhlIHVybGxpYjIKIyBzdHItdnMtYnl0ZXMgZW5jb2RlIGd1YXJkIGluIGZsdXNo
KCkgc3RheXMg4oCUIGRvIG5vdCByZW1vdmUuCnRyeToKICAgIGltcG9ydCBRdWV1ZSAgICAgICAg
ICAgICAgICAgICAgICAjIHB5MjogUXVldWUgbW9kdWxlLCBjbGFzcyBRdWV1ZS5RdWV1ZQogICAg
aW1wb3J0IHVybGxpYjIKZXhjZXB0IEltcG9ydEVycm9yOiAgICAgICAgICAgICAgICAgICAjIHB5
MwogICAgaW1wb3J0IHF1ZXVlIGFzIFF1ZXVlCiAgICBpbXBvcnQgdXJsbGliLnJlcXVlc3QgYXMg
dXJsbGliMgppbXBvcnQgdGhyZWFkaW5nLCB0aW1lCgpNQVhfQkFUQ0ggPSA0MDAKRkxVU0hfU0VD
ID0gNS4wClJFVFJZX01BWCA9IDg2NDAwLjAgICAgICAgICMga2VlcCBzcG9vbC1yZXRyeWluZyBm
b3IgYSBkYXkgYmVmb3JlIGdpdmluZyB1cAoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIu
d3JpdGUoIm50LXNoaXA6ICVzXG4iICUgbXNnKQogICAgc3lzLnN0ZGVyci5mbHVzaCgpCgoKZGVm
IG1haW4oKToKICAgIGVuZHBvaW50ID0gTm9uZQogICAgc3Bvb2wgPSAiL3Zhci9saWIvbmV0d29y
a3RyYWNpbmcvc25pZmYtc3Bvb2wuanNvbmwiCiAgICBhcmd2ID0gc3lzLmFyZ3ZbMTpdCiAgICBp
ID0gMAogICAgd2hpbGUgaSA8IGxlbihhcmd2KToKICAgICAgICBhID0gYXJndltpXQogICAgICAg
IGlmIGEgPT0gIi0tZW5kcG9pbnQiOgogICAgICAgICAgICBpICs9IDE7IGVuZHBvaW50ID0gYXJn
dltpXS5yc3RyaXAoIi8iKQogICAgICAgIGVsaWYgYSA9PSAiLS1zcG9vbCI6CiAgICAgICAgICAg
IGkgKz0gMTsgc3Bvb2wgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhIGluICgiLWgiLCAiLS1oZWxw
Iik6CiAgICAgICAgICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0ZW1FeGl0KDApCiAgICAg
ICAgZWxzZToKICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5rbm93biBhcmc6ICVzIiAl
IGEpCiAgICAgICAgaSArPSAxCiAgICBpZiBub3QgZW5kcG9pbnQ6CiAgICAgICAgcmFpc2UgU3lz
dGVtRXhpdCgiLS1lbmRwb2ludCByZXF1aXJlZCIpCgogICAgbm9kZSA9IHNvY2tldC5nZXRob3N0
bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICAjIHJlcGxheSBzcG9vbGVkIGV2ZW50cyBmaXJzdCAo
YXQtbGVhc3Qtb25jZSkKICAgIHBlbmRpbmcgPSBbXQogICAgaWYgb3MucGF0aC5leGlzdHMoc3Bv
b2wpOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcGVuKHNwb29sKSBhcyBmOgogICAg
ICAgICAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAgICAgICBsaW5lID0gbGlu
ZS5zdHJpcCgpCiAgICAgICAgICAgICAgICAgICAgaWYgbGluZToKICAgICAgICAgICAgICAgICAg
ICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVuZGluZy5hcHBlbmQoanNv
bi5sb2FkcyhsaW5lKSkKICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgIG9zLnJlbW92ZShz
cG9vbCkKICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpIGFzIGU6CiAgICAgICAgICAg
IGxvZygic3Bvb2wgcmVhZCBmYWlsZWQ6ICVzIiAlIGUpCgogICAgcnVubmluZyA9IFtUcnVlXQoK
ICAgIGRlZiBzdG9wKHNpZ251bSwgZnJhbWUpOgogICAgICAgIHJ1bm5pbmdbMF0gPSBGYWxzZQog
ICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgc3RvcCkKICAgIHNpZ25hbC5zaWduYWwo
c2lnbmFsLlNJR0lOVCwgc3RvcCkKCiAgICBkZWYgZmx1c2goYmF0Y2gpOgogICAgICAgIGlmIG5v
dCBiYXRjaDoKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBib2R5ID0ganNvbi5kdW1w
cyh7Im5vZGUiOiBub2RlLCAiZXZlbnRzIjogYmF0Y2h9KQogICAgICAgICMgcHkyIHVybGxpYjIg
YWNjZXB0cyBzdHI7IHB5MyBzaGltL3Rlc3QgbmVlZHMgYnl0ZXMg4oCUIGVuY29kZSB3aGVuCiAg
ICAgICAgIyB0aGUgcnVudGltZSBleHBvc2VzIGl0IChweTIgc3RyIGhhcyBubyAuZW5jb2RlIG9u
IGFsbCBidWlsZHMsIHNvCiAgICAgICAgIyBndWFyZCB3aXRoIGhhc2F0dHIpCiAgICAgICAgaWYg
aGFzYXR0cihib2R5LCAiZW5jb2RlIik6CiAgICAgICAgICAgIGJvZHkgPSBib2R5LmVuY29kZSgi
dXRmLTgiKQogICAgICAgIHJlcSA9IHVybGxpYjIuUmVxdWVzdChlbmRwb2ludCArICIvYXBpL2lu
Z2VzdCIsIGRhdGE9Ym9keSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVycz17
IkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAgICAgdHJ5OgogICAgICAg
ICAgICByZXNwID0gdXJsbGliMi51cmxvcGVuKHJlcSwgdGltZW91dD0xMCkKICAgICAgICAgICAg
b2sgPSAocmVzcC5nZXRjb2RlKCkgPT0gMjAwKQogICAgICAgICAgICByZXNwLnJlYWQoKQogICAg
ICAgICAgICByZXNwLmNsb3NlKCkKICAgICAgICAgICAgaWYgb2s6CiAgICAgICAgICAgICAgICBs
b2coImZsdXNoZWQgJWQgZXZlbnRzIiAlIGxlbihiYXRjaCkpCiAgICAgICAgICAgIHJldHVybiBv
awogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgbG9nKCJzaGlwIGZh
aWxlZDogJXMiICUgZSkKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgIyAtLS0tIGNvbmN1
cnJlbnQgc2hpcHBpbmcgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LQogICAgIyBodWIgaW5nZXN0IGxhdGVuY3kgKH4zMDAtNTAwbXMgcGVyIDQwMC1ldmVudCBQT1NU
IG92ZXIgV0FOKSBtYWtlcwogICAgIyBzZXF1ZW50aWFsIHBvc3RpbmcgYSB+MTAwMCBldi9zIGNl
aWxpbmc7IE4gcG9zdGVyIHRocmVhZHMgcG9zdGluZwogICAgIyBpbmRlcGVuZGVudCBiYXRjaGVz
IG11bHRpcGx5IHRoYXQgYnkgTlRfU0hJUF9USFJFQURTCiAgICBxID0gUXVldWUuUXVldWUobWF4
c2l6ZT0xMjgpCiAgICBzcG9vbF9sb2NrID0gdGhyZWFkaW5nLkxvY2soKQogICAgbnRocmVhZHMg
PSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NISVBfVEhSRUFEUyIsICI0IikpCgogICAgZGVmIHBv
c3RlcigpOgogICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgIGJhdGNoID0gcS5nZXQoKQog
ICAgICAgICAgICBpZiBiYXRjaCBpcyBOb25lOgogICAgICAgICAgICAgICAgcS50YXNrX2RvbmUo
KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIGZsdXNoKGJhdGNoKToKICAg
ICAgICAgICAgICAgIGJhY2tvZmZfYm94WzBdID0gMQogICAgICAgICAgICBlbHNlOgogICAgICAg
ICAgICAgICAgd2l0aCBzcG9vbF9sb2NrOgogICAgICAgICAgICAgICAgICAgIF9zcG9vbF9hcHBl
bmQoc3Bvb2wsIGJhdGNoKQogICAgICAgICAgICBxLnRhc2tfZG9uZSgpCgogICAgYmFja29mZl9i
b3ggPSBbMV0KICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAgICAgICB0ID0gdGhyZWFk
aW5nLlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgIHQuZGFlbW9uID0gVHJ1ZQogICAgICAg
IHQuc3RhcnQoKQoKICAgIGJ1ZiA9IGxpc3QocGVuZGluZykKICAgIGxhc3RfZmx1c2ggPSB0aW1l
LnRpbWUoKQogICAgbGFzdF9zcG9vbF90cnkgPSB0aW1lLnRpbWUoKQoKICAgIGRlZiBmb2xkX3Nw
b29sKCk6CiAgICAgICAgIiIiUmUtcXVldWUgc3Bvb2xlZCBldmVudHMgKG1pZC1ydW4gcmV0cnkp
OyByZXR1cm5zIGNvdW50IGZvbGRlZC4iIiIKICAgICAgICBuID0gMAogICAgICAgIHRyeToKICAg
ICAgICAgICAgd2l0aCBvcGVuKHNwb29sKSBhcyBmOgogICAgICAgICAgICAgICAgZm9yIGxpbmUg
aW4gZjoKICAgICAgICAgICAgICAgICAgICBsaW5lID0gbGluZS5zdHJpcCgpCiAgICAgICAgICAg
ICAgICAgICAgaWYgbm90IGxpbmU6CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAg
ICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICBldiA9IGpzb24u
bG9hZHMobGluZSkKICAgICAgICAgICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAg
ICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgICAgICBpZiBpc2luc3Rh
bmNlKGV2LCBkaWN0KToKICAgICAgICAgICAgICAgICAgICAgICAgYnVmLmFwcGVuZChldikKICAg
ICAgICAgICAgICAgICAgICAgICAgbiArPSAxCiAgICAgICAgICAgIG9zLnJlbW92ZShzcG9vbCkK
ICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpOgogICAgICAgICAgICBwYXNzCiAgICAg
ICAgcmV0dXJuIG4KCiAgICBmb3IgcmF3IGluIGl0ZXIoc3lzLnN0ZGluLnJlYWRsaW5lLCAiIik6
CiAgICAgICAgaWYgbm90IHJ1bm5pbmdbMF06CiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgcmF3
ID0gcmF3LnN0cmlwKCkKICAgICAgICBpZiBub3QgcmF3OgogICAgICAgICAgICBjb250aW51ZQog
ICAgICAgIHRyeToKICAgICAgICAgICAgZXYgPSBqc29uLmxvYWRzKHJhdykKICAgICAgICBleGNl
cHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgY29udGludWUgICAgICAgICAgICAgICAgICAgICAg
IyBnYXJiYWdlIGluLCBzaWxlbnRseSBkcm9wcGVkCiAgICAgICAgaWYgaXNpbnN0YW5jZShldiwg
ZGljdCk6CiAgICAgICAgICAgIGJ1Zi5hcHBlbmQoZXYpCiAgICAgICAgbm93ID0gdGltZS50aW1l
KCkKICAgICAgICB3aGlsZSBsZW4oYnVmKSA+PSBNQVhfQkFUQ0ggb3IgKGJ1ZiBhbmQgbm93IC0g
bGFzdF9mbHVzaCA+PSBGTFVTSF9TRUMpOgogICAgICAgICAgICBsYXN0X2ZsdXNoID0gbm93CiAg
ICAgICAgICAgICMgcmV0cnkgc3Bvb2xlZCBldmVudHMgYWhlYWQgb2YgZnJlc2ggb25lcyAofm9u
Y2UgYSBtaW51dGUpCiAgICAgICAgICAgIGlmIG5vdyAtIGxhc3Rfc3Bvb2xfdHJ5ID49IDYwIGFu
ZCBvcy5wYXRoLmV4aXN0cyhzcG9vbCk6CiAgICAgICAgICAgICAgICBsYXN0X3Nwb29sX3RyeSA9
IG5vdwogICAgICAgICAgICAgICAgZm9sZF9zcG9vbCgpCiAgICAgICAgICAgIHEucHV0KGJ1Zls6
TUFYX0JBVENIXSkgICAgICAgICMgYmxvY2tzIHdoZW4gcG9zdGVycyBmYWxsIGJlaGluZCDigJQK
ICAgICAgICAgICAgZGVsIGJ1Zls6TUFYX0JBVENIXSAgICAgICAgICAgIyB0aGF0IElTIG91ciBi
YWNrcHJlc3N1cmUgc2lnbmFsCgogICAgIyBzdGRpbiBjbG9zZWQgKHNuaWZmZXIgc3RvcHBlZCkg
4oCUIGRyYWluIHF1ZXVlLCB0aGVuIGtlZXAgcmV0cnlpbmcKICAgICMgYW55dGhpbmcgc3Bvb2xl
ZCB1bnRpbCBpdCBsYW5kcyBvciBSRVRSWV9NQVggZWxhcHNlcwogICAgZGVhZGxpbmUgPSB0aW1l
LnRpbWUoKSArIFJFVFJZX01BWAogICAgcS5qb2luKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF0gYW5k
IHRpbWUudGltZSgpIDwgZGVhZGxpbmUgYW5kIG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAg
ICBmb2xkX3Nwb29sKCkKICAgICAgICBpZiBub3QgYnVmOgogICAgICAgICAgICBicmVhawogICAg
ICAgIGlmIGZsdXNoKGJ1Zik6CiAgICAgICAgICAgIGRlbCBidWZbOl0KICAgICAgICBlbHNlOgog
ICAgICAgICAgICB3aXRoIHNwb29sX2xvY2s6CiAgICAgICAgICAgICAgICBfc3Bvb2xfYXBwZW5k
KHNwb29sLCBidWYpCiAgICAgICAgICAgICAgICBkZWwgYnVmWzpdCiAgICAgICAgdGltZS5zbGVl
cChtaW4oYmFja29mZl9ib3hbMF0sIDYwKSkKICAgICAgICBiYWNrb2ZmX2JveFswXSAqPSAyCiAg
ICAgICAgaWYgb3MucGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgICAgICBmb2xkX3Nwb29sKCkK
ICAgICAgICBpZiBub3QgYnVmIGFuZCBub3Qgb3MucGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAg
ICAgICBicmVhawogICAgbG9nKCJzdG9wcGVkICglZCBldmVudHMgcGVuZGluZyBvbiBleGl0KSIg
JSBsZW4oYnVmKSkKCiAgICBsb2coInN0b3BwZWQgKCVkIGV2ZW50cyBwZW5kaW5nIG9uIGV4aXQp
IiAlIGxlbihidWYpKQoKCmRlZiBfc3Bvb2xfYXBwZW5kKHBhdGgsIGJhdGNoKToKICAgIGQgPSBv
cy5wYXRoLmRpcm5hbWUocGF0aCkKICAgIHRyeToKICAgICAgICBpZiBkIGFuZCBub3Qgb3MucGF0
aC5pc2RpcihkKToKICAgICAgICAgICAgb3MubWFrZWRpcnMoZCkKICAgICAgICB3aXRoIG9wZW4o
cGF0aCwgImEiKSBhcyBmOgogICAgICAgICAgICBmb3IgZXYgaW4gYmF0Y2g6CiAgICAgICAgICAg
ICAgICBmLndyaXRlKGpzb24uZHVtcHMoZXYpICsgIlxuIikKICAgICAgICBkZWwgYmF0Y2hbOl0K
ICAgIGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJvcikgYXMgZToKICAgICAgICBsb2coIkZBVEFMOiBj
YW5ub3Qgd3JpdGUgc3Bvb2wgJXM6ICVzIiAlIChwYXRoLCBlKSkKICAgICAgICBvcy5fZXhpdCgz
KQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
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
IHN0ZDo6c3RyaW5nIGpzb25fYXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZh
KSB7CiAgc3RkOjpzdHJpbmcgbz0iWyI7IGZvcihzaXplX3QgaT0wO2k8YS5zaXplKCk7KytpKXtp
ZihpKW8rPSIsIjtvKz1hW2ldO30gcmV0dXJuIG8rIl0iOwp9CnN0YXRpYyBib29sIHBvc3QoY29u
c3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwKICAgICAg
ICAgICAgICAgICBjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNoKSB7CiAgc3Rk
OjpzdHJpbmcgYm9keT0ie1wibm9kZVwiOlwiIitub2RlKyJcIixcImV2ZW50c1wiOiIranNvbl9h
cnJheShiYXRjaCkrIn0iOwogIHN0ZDo6c3RyaW5nIGNtZD0iY3VybCAtc1MgLS1tYXgtdGltZSAx
NSAtbyAvZGV2L251bGwgLXcgJyV7aHR0cF9jb2RlfScgLUggJ0NvbnRlbnQtVHlwZTogYXBwbGlj
YXRpb24vanNvbicgLS1kYXRhLWJpbmFyeSAiK3NoZWxscShib2R5KSsiICIrc2hlbGxxKGVuZHBv
aW50KyIvYXBpL2luZ2VzdCIpOwogIEZJTEUgKmZwPXBvcGVuKGNtZC5jX3N0cigpLCJyIik7IGlm
KCFmcClyZXR1cm4gZmFsc2U7IGNoYXIgYlszMl07IHNpemVfdCBuPWZyZWFkKGIsMSxzaXplb2Yo
YiktMSxmcCk7IGJbbl09MDsgaW50IHJjPXBjbG9zZShmcCk7CiAgcmV0dXJuIHJjPT0wICYmIHN0
ZDo6c3RyaW5nKGIsbik9PSIyMDAiOwp9CnN0YXRpYyB2b2lkIHNwb29sKGNvbnN0IHN0ZDo6c3Ry
aW5nICZwYXRoLCBjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNoKSB7CiAgc3Rk
OjpzdHJpbmcgZGF0YTsgZm9yKHNpemVfdCBpPTA7aTxiYXRjaC5zaXplKCk7KytpKWRhdGErPWJh
dGNoW2ldKyJcbiI7CiAgaWYoIXdyaXRlX2FwcGVuZChwYXRoLGRhdGEpKSB7IGxvZ21zZygiRkFU
QUw6IGNhbm5vdCB3cml0ZSBzcG9vbCIpOyBleGl0KDMpOyB9Cn0Kc3RhdGljIHZvaWQgbG9hZF9z
cG9vbChjb25zdCBzdGQ6OnN0cmluZyAmcGF0aCwgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICpi
dWYpIHsKICBzdGQ6OnN0cmluZyBkYXRhOyBpZighcmVhZF9maWxlKHBhdGgsJmRhdGEpKXJldHVy
bjsKICBzdGQ6OmlzdHJpbmdzdHJlYW0gaW4oZGF0YSk7IHN0ZDo6c3RyaW5nIGxpbmU7IHdoaWxl
KHN0ZDo6Z2V0bGluZShpbixsaW5lKSkgaWYoIWxpbmUuZW1wdHkoKSkgYnVmLT5wdXNoX2JhY2so
bGluZSk7CiAgdW5saW5rKHBhdGguY19zdHIoKSk7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIG51bWJl
cl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgbjsgcmV0dXJu
IG8uc3RyKCk7IH0Kc3RhdGljIHZvaWQgc2VuZF9iYXRjaGVzKGNvbnN0IHN0ZDo6c3RyaW5nICZl
bmRwb2ludCxjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSxjb25zdCBzdGQ6OnN0cmluZyAmc3Bvb2xf
cGF0aCwKICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAq
YnVmLCBib29sIGZpbmFsKSB7CiAgd2hpbGUgKGJ1Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCB8fCAo
ZmluYWwgJiYgIWJ1Zi0+ZW1wdHkoKSkpIHsKICAgIHNpemVfdCBuPWJ1Zi0+c2l6ZSgpPj1NQVhf
QkFUQ0g/TUFYX0JBVENIOmJ1Zi0+c2l6ZSgpOwogICAgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+
IGJhdGNoKGJ1Zi0+YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7CiAgICBpZihwb3N0KGVuZHBvaW50
LG5vZGUsYmF0Y2gpKSB7IGJ1Zi0+ZXJhc2UoYnVmLT5iZWdpbigpLGJ1Zi0+YmVnaW4oKStuKTsg
bG9nbXNnKCJmbHVzaGVkICIrbnVtYmVyX3N0cmluZyhuKSsiIGV2ZW50cyIpOyB9CiAgICBlbHNl
IHsgc3Bvb2woc3Bvb2xfcGF0aCxiYXRjaCk7IGJ1Zi0+ZXJhc2UoYnVmLT5iZWdpbigpLGJ1Zi0+
YmVnaW4oKStuKTsgbG9nbXNnKCJzcG9vbGVkICIrbnVtYmVyX3N0cmluZyhuKSsiIGV2ZW50cyIp
OyBicmVhazsgfQogIH0KfQppbnQgbWFpbihpbnQgYXJnYyxjaGFyICoqYXJndikgewogIHN0ZDo6
c3RyaW5nIGVuZHBvaW50LCBzcG9vbF9wYXRoPSIvdmFyL2xpYi9uZXR3b3JrdHJhY2luZy9zbmlm
Zi1zcG9vbC5qc29ubCI7IGludCBpOwogIGZvcihpPTE7aTxhcmdjOysraSl7c3RkOjpzdHJpbmcg
YT1hcmd2W2ldOyBpZihhPT0iLS1lbmRwb2ludCImJmkrMTxhcmdjKWVuZHBvaW50PWFyZ3ZbKytp
XTsgZWxzZSBpZihhPT0iLS1zcG9vbCImJmkrMTxhcmdjKXNwb29sX3BhdGg9YXJndlsrK2ldOyBl
bHNlIGlmKGE9PSItaCJ8fGE9PSItLWhlbHAiKXtzdGQ6OmNvdXQ8PCJ1c2FnZTogbnQtc2hpcC1j
cHAgLS1lbmRwb2ludCBVUkwgWy0tc3Bvb2wgUEFUSF1cbiI7cmV0dXJuIDA7fSBlbHNlIHtzdGQ6
OmNlcnI8PCJ1bmtub3duIGFyZzogIjw8YTw8IlxuIjtyZXR1cm4gMjt9fQogIGlmKGVuZHBvaW50
LmVtcHR5KCkpe3N0ZDo6Y2Vycjw8Ii0tZW5kcG9pbnQgcmVxdWlyZWRcbiI7cmV0dXJuIDI7fQog
IHNpZ25hbChTSUdURVJNLHN0b3Bfc2lnbmFsKTsgc2lnbmFsKFNJR0lOVCxzdG9wX3NpZ25hbCk7
CiAgY2hhciBob3N0WzI1Nl07IGdldGhvc3RuYW1lKGhvc3Qsc2l6ZW9mKGhvc3QpKTsgaG9zdFtz
aXplb2YoaG9zdCktMV09MDsKICBjb25zdCBjaGFyICpub2RlX2VudiA9IGdldGVudigiTlRfTk9E
RV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2RlX2VudiAmJiAqbm9kZV9lbnYpID8g
bm9kZV9lbnYgOiBob3N0OwogIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBidWY7IGxvYWRfc3Bv
b2woc3Bvb2xfcGF0aCwmYnVmKTsgdGltZV90IGxhc3Q9dGltZShOVUxMKSwgbGFzdF9yZXRyeT1s
YXN0OwogIHN0ZDo6c3RyaW5nIGxpbmU7CiAgd2hpbGUocnVubmluZyAmJiBzdGQ6OmdldGxpbmUo
c3RkOjpjaW4sbGluZSkpIHsgaWYobGluZS5lbXB0eSgpKWNvbnRpbnVlOyBidWYucHVzaF9iYWNr
KGxpbmUpOyB0aW1lX3Qgbm93PXRpbWUoTlVMTCk7IGlmKG5vdy1sYXN0Pj1GTFVTSF9TRUMgfHwg
YnVmLnNpemUoKT49TUFYX0JBVENIKXtzZW5kX2JhdGNoZXMoZW5kcG9pbnQsbm9kZSxzcG9vbF9w
YXRoLCZidWYsZmFsc2UpO2xhc3Q9bm93O30gaWYobm93LWxhc3RfcmV0cnk+PVJFVFJZX1NFQyl7
bG9hZF9zcG9vbChzcG9vbF9wYXRoLCZidWYpO2xhc3RfcmV0cnk9bm93O30gfQogIHNlbmRfYmF0
Y2hlcyhlbmRwb2ludCxub2RlLHNwb29sX3BhdGgsJmJ1Zix0cnVlKTsgbG9nbXNnKCJzdG9wcGVk
Iik7IHJldHVybiAwOwp9Cg==
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
Rl9NU0gsMCwwLDE0KTsKICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsgQURE
KEJQRl9MRHxCUEZfSHxCUEZfSU5ELDAsMCwxNik7IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ss
YWNjZXB0LSh1bnNpZ25lZClmLnNpemUoKS0xLDEscG9ydHNbaV0pOyB9CiAgZm9yIChpID0gMDsg
aSA8IHBvcnRzLnNpemUoKTsgKytpKSB7IEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwwLDAsMTQp
OyBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLGFjY2VwdC0odW5zaWduZWQpZi5zaXplKCktMSwx
LHBvcnRzW2ldKTsgfQogIEFERChCUEZfUkVUfEJQRl9LLDAsMCwwKTsgQUREKEJQRl9SRVR8QlBG
X0ssMCwwLEFDQ0VQVCk7CiN1bmRlZiBBREQKICBpZiAoZi5zaXplKCkgPiA0MDk2KSByZXR1cm4g
ZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5sZW4gPSAodW5zaWduZWQgc2hv
cnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07IHJldHVybiBzZXRzb2Nrb3B0KGZkLCBT
T0xfU09DS0VULCBTT19BVFRBQ0hfRklMVEVSX09MRCwgJnByb2csIHNpemVvZihwcm9nKSkgPT0g
MDsKfQoKc3RhdGljIGludCBydW5fZml4dHVyZSgpIHsKICBzdGQ6OnN0cmluZyByZXEgPSAiR0VU
IC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJcbkhvc3Q6IGFwaS5sb2NhbFxyXG5BdXRob3JpemF0
aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYwXHJcblRyYWNlcGFyZW50OiAwMC0wMTIzNDU2Nzg5
YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIzNDU2Nzg5YWJjZGVmLTAxXHJcblxyXG4iOwogIEV2
ZW50IGU7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAiY3BwLW5vZGUiOyBlLnNlcnZpY2Ug
PSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjkiOyBlLmNhbGxlcl9wb3J0ID0gNTEw
MDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9ydCA9IDgwODA7IGUucmVxX2J5dGVz
ID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVlc3QocmVxLnN1YnN0cigwLCByZXEu
c2l6ZSgpIC0gNCksICZlKTsgZS5zdGF0dXMgPSAyMDA7IGUuaGFzX3N0YXR1cyA9IHRydWU7IGUu
ZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlvbiA9IHRydWU7IGUucmVzcF9ieXRlcyA9IDQy
OyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVudChlKTsgcmV0dXJuIDA7Cn0KaW50IG1haW4o
aW50IGFyZ2MsIGNoYXIgKiphcmd2KSB7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsx
XSwgIi0tZml4dHVyZSIpKSByZXR1cm4gcnVuX2ZpeHR1cmUoKTsKICBzdGQ6OnN0cmluZyBpZmFj
ZTsgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBvcnRzOyBpbnQgaTsgaW50IHdvcmtlcnMgPSAxOwog
IGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1pIikg
JiYgaSArIDEgPCBhcmdjKSBpZmFjZSA9IGFyZ3ZbKytpXTsgZWxzZSBpZiAoIXN0cmNtcChhcmd2
W2ldLCAiLXAiKSAmJiBpICsgMSA8IGFyZ2MpIHsgY2hhciAqcSA9IHN0cnRvayhhcmd2WysraV0s
ICIsIik7IHdoaWxlIChxKSB7IGxvbmcgcCA9IGF0b2wocSk7IGlmICh2YWxpZF9wb3J0KCh1bnNp
Z25lZClwKSkgcG9ydHMucHVzaF9iYWNrKCh1bnNpZ25lZClwKTsgcSA9IHN0cnRvayhOVUxMLCAi
LCIpOyB9IH0gZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWoiKSAmJiBpICsgMSA8IGFyZ2Mp
IHdvcmtlcnMgPSBhdG9pKGFyZ3ZbKytpXSk7IGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1o
IikpIHsgZnByaW50ZihzdGRlcnIsICJ1c2FnZTogbnQtc25pZmYtY3BwIFstaSBpZmFjZV0gWy1w
IHBvcnRzXSBbLWogd29ya2Vyc11cbiIpOyByZXR1cm4gMDsgfSB9CiAgaWYgKHBvcnRzLmVtcHR5
KCkpIHsgcG9ydHMucHVzaF9iYWNrKDgwKTsgcG9ydHMucHVzaF9iYWNrKDgwMDMpOyBwb3J0cy5w
dXNoX2JhY2soODAwNSk7IHBvcnRzLnB1c2hfYmFjayg4MDA3KTsgcG9ydHMucHVzaF9iYWNrKDgw
MDkpOyBwb3J0cy5wdXNoX2JhY2soODAxMCk7IHBvcnRzLnB1c2hfYmFjayg4MDExKTsgfQogICh2
b2lkKXdvcmtlcnM7IHN0ZDo6c3RyaW5nIG5vZGUgPSBob3N0X25hbWUoKTsgaW50IGZkID0gc29j
a2V0KEFGX1BBQ0tFVCwgU09DS19SQVcsIGh0b25zKEVUSF9QX0lQKSk7IGlmIChmZCA8IDApIHsg
cGVycm9yKCJBRl9QQUNLRVQiKTsgcmV0dXJuIDI7IH0KICBpbnQgcmIgPSA4ICogMTAyNCAqIDEw
MjQ7CiAgc2V0c29ja29wdChmZCwgU09MX1NPQ0tFVCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihy
YikpOwogIGlmICghYXR0YWNoX2JwZihmZCwgcG9ydHMpKSBsb2dtc2coIldBUk46IEJQRiBhdHRh
Y2ggZmFpbGVkOyBjb250aW51aW5nIHVuZmlsdGVyZWQiKTsKICBzdHJ1Y3Qgc29ja2FkZHJfbGwg
c2E7IG1lbXNldCgmc2EsIDAsIHNpemVvZihzYSkpOyBzYS5zbGxfZmFtaWx5ID0gQUZfUEFDS0VU
OyBpZiAoIWlmYWNlLmVtcHR5KCkpIHsgc2Euc2xsX2lmaW5kZXggPSAoaW50KWlmX25hbWV0b2lu
ZGV4KGlmYWNlLmNfc3RyKCkpOyBpZiAoIXNhLnNsbF9pZmluZGV4KSB7IGxvZ21zZygiYmFkIGlu
dGVyZmFjZSIpOyBjbG9zZShmZCk7IHJldHVybiAyOyB9IH0gaWYgKGJpbmQoZmQsIChzdHJ1Y3Qg
c29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkpIDwgMCkgeyBwZXJyb3IoImJpbmQiKTsgY2xvc2Uo
ZmQpOyByZXR1cm4gMjsgfQogIHNpZ25hbChTSUdURVJNLCBzdG9wX3NpZ25hbCk7CiAgc2lnbmFs
KFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBGbG93PiBmbG93
czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gcGVuZGluZzsK
ICBsb2dtc2coImxpc3RlbmluZyIpOwogIHRpbWVfdCBsYXN0ID0gdGltZShOVUxMKTsKICB1bnNp
Z25lZCBjaGFyICpidWYgPSAodW5zaWduZWQgY2hhciAqKW1hbGxvYyg2NTUzNik7CiAgaWYgKCFi
dWYpIHsKICAgIGNsb3NlKGZkKTsKICAgIGxvZ21zZygiYnVmZmVyIGFsbG9jYXRpb24gZmFpbGVk
Iik7CiAgICByZXR1cm4gMjsKICB9CiAgd2hpbGUgKGdfcnVubmluZykgewogICAgZmRfc2V0IHI7
CiAgICBGRF9aRVJPKCZyKTsKICAgIEZEX1NFVChmZCwgJnIpOwogICAgc3RydWN0IHRpbWV2YWwg
dHY7CiAgICB0di50dl9zZWMgPSAxOwogICAgdHYudHZfdXNlYyA9IDA7CiAgICBpbnQgcmMgPSBz
ZWxlY3QoZmQgKyAxLCAmciwgTlVMTCwgTlVMTCwgJnR2KTsKICAgIGlmIChyYyA+IDAgJiYgRkRf
SVNTRVQoZmQsICZyKSkgewogICAgICBzc2l6ZV90IG4gPSByZWN2KGZkLCBidWYsIDY1NTM2LCAw
KTsKICAgICAgaWYgKG4gPiAwKSBoYW5kbGVfcGFja2V0KGJ1ZiwgKHNpemVfdCluLCBub2RlLCBw
b3J0cywgZmxvd3MsIHBlbmRpbmcpOwogICAgfQogICAgdGltZV90IG5vdyA9IHRpbWUoTlVMTCk7
CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVwKGZsb3dzLCBwZW5kaW5nLCBu
b3cpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogIH0KICBmcmVlKGJ1Zik7IGNsb3NlKGZkKTsg
bG9nbXNnKCJzdG9wcGVkIik7IHJldHVybiAwOwp9Cg==
#__END_CPP__
#__CPP_MAKE_B64__
IyBCdWlsZCB0YXJnZXRzIGZvciB0aGUgbmF0aXZlIG9sZC1rZXJuZWwgY2FwdHVyZSBwYXRoLgoj
IEdDQyA0LjQgLyBDZW50T1MgNiBjb21wYXRpYmxlOiBDKyswMywgbm8gdGhpcmQtcGFydHkgbGli
cmFyaWVzLgpDWFggPz0gZysrCkNYWEZMQUdTID89IC1PMiAtV2FsbCAtV2V4dHJhIC1zdGQ9Z251
KyswMwoKLlBIT05ZOiBhbGwgY3BwIGNwcC1zaGlwIGNwcC1kZWJ1ZyBmaXh0dXJlIGNsZWFuCgph
bGw6IGNwcCBjcHAtc2hpcAoKY3BwOgoJJChDWFgpICQoQ1hYRkxBR1MpIG50LXNuaWZmLWNwcC5j
cHAgLW8gbnQtc25pZmYtY3BwCgpjcHAtc2hpcDoKCSQoQ1hYKSAkKENYWEZMQUdTKSBudC1zaGlw
LWNwcC5jcHAgLW8gbnQtc2hpcC1jcHAKCmNwcC1kZWJ1ZzoKCSQoQ1hYKSAtTzAgLWcgLVdhbGwg
LVdleHRyYSAtc3RkPWdudSsrMDMgbnQtc25pZmYtY3BwLmNwcCAtbyBudC1zbmlmZi1jcHAtZGVi
dWcKCmZpeHR1cmU6IGNwcAoJLi9udC1zbmlmZi1jcHAgLS1maXh0dXJlCgpjbGVhbjoKCXJtIC1m
IG50LXNuaWZmLWNwcCBudC1zbmlmZi1jcHAtZGVidWcgbnQtc2hpcC1jcHAK
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
