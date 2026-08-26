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
for f in nt-sniff.py nt-ship.py; do
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
    fi

    # --- source 3: hub bootstrap server ---------------------------------
    if [ ! -s "$WORKDIR/nt-sniff.py" ] || [ ! -s "$WORKDIR/nt-ship.py" ]; then
        if [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
            HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
            [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
        fi
        [ -n "$KIT_URLS" ] || die "kit files missing, no embedded payload, cannot derive hub URL — pass --hub http://HUB:30105/oldkernel"
        log "first run: fetching kit from $KIT_URLS -> $WORKDIR"
        have curl || have wget || die "neither curl nor wget present and no embedded payload"
        for f in nt-sniff.py nt-ship.py el68-smoke.sh README.md DEBUG-NOTES.md; do
            fetch "$KIT_URLS/$f" "$WORKDIR/$f.new" || die "cannot download $f from $KIT_URLS"
            mv "$WORKDIR/$f.new" "$WORKDIR/$f"
        done
    fi

    chmod 755 "$WORKDIR"/nt-*.py 2>/dev/null || true
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
    [ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1
    if have chkconfig; then chkconfig networktracing-legacy off >/dev/null 2>&1 || true; fi
    rm -f "$INIT"
    pkill -f "$PREFIX/nt-sniff.py" 2>/dev/null || true
    pkill -f "$PREFIX/nt-ship.py" 2>/dev/null || true
    rm -rf "$PREFIX"
    RESIDUE=""
    pgrep -f "$PREFIX/" >/dev/null 2>&1 && RESIDUE="$RESIDUE procs-alive"
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

have python || die "python (2.6/2.7) required on the node"
python -c 'import sys; assert sys.version_info >= (2,6) and sys.version_info < (3,)' \
    || die "python 2.6/2.7 required"

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
for f in nt-sniff.py nt-ship.py; do
    [ -f "$SCRIPT_DIR/$f" ] || die "bundle incomplete: missing $f"
done
cp "$SCRIPT_DIR"/nt-sniff.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship.py  "$PREFIX/"
chmod 755 "$PREFIX"/nt-*.py

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
if [ "$SNIFF_AS" != root ]; then
    SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
else
    SNIFF_CMD="exec python $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
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
        if pgrep -f "\\\$PREFIX/nt-sniff.py" >/dev/null; then
            echo "already running"; exit 0
        fi
        nohup sh -c "$SNIFF_CMD 2>>\$PREFIX/sniff.log | python \$PREFIX/nt-ship.py --endpoint $ENDPOINT >>\$PREFIX/ship.log 2>&1" >/dev/null 2>&1 &
        sleep 1
        pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || { echo "sniffer failed to start"; exit 1; }
        echo "networktracing-legacy started"
        ;;
    stop)
        pkill -f "\$PREFIX/nt-sniff.py" 2>/dev/null
        pkill -f "\$PREFIX/nt-ship.py" 2>/dev/null
        rm -f "\$PIDFILE"
        echo "networktracing-legacy stopped"
        ;;
    status)
        if pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null; then
            echo "running (pid \$(pgrep -f "\$PREFIX/nt-sniff.py"))"; exit 0
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
pgrep -f "$PREFIX/nt-sniff.py" >/dev/null || die "sniffer not running after start"

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
REhfSU5EID0gMHg0OCAgICMgbGQgW3gra106aAogICAgUkVUX0sgPSAweDA2CgogICAgcHJvZyA9
IFtdCiAgICByZWplY3RfaWR4ID0gNSArIDIgKiBsZW4ocG9ydHMpCiAgICBhY2NlcHRfaWR4ID0g
cmVqZWN0X2lkeCArIDEKICAgIHByb2cuYXBwZW5kKChMREhfQUJTLCAwLCAwLCAxMikpICAgICAg
ICAgICAgIyBldGhlcnR5cGUKICAgIHByb2cuYXBwZW5kKChKRVFfSywgMCwgcmVqZWN0X2lkeCAt
IDIsIDB4MDgwMCkpICAgIyA9PSBJUCAtPiBmYWxsIHRocnUKICAgIHByb2cuYXBwZW5kKChMREJf
QUJTLCAwLCAwLCAyMykpICAgICAgICAgICAgIyBpcCBwcm90byBieXRlIChmaXhlZCBvZmYpCiAg
ICBwcm9nLmFwcGVuZCgoSkVRX0ssIDAsIHJlamVjdF9pZHggLSA0LCA2KSkgICAgICAgICMgPT0g
VENQIC0+IGZhbGwgdGhydQogICAgcHJvZy5hcHBlbmQoKExEWF9NU0gsIDAsIDAsIDE0KSkgICAg
ICAgICAgICAjIFggPSBpaGwqNAogICAgZm9yIGksIHAgaW4gZW51bWVyYXRlKHNvcnRlZChwb3J0
cykpOgogICAgICAgIGIgPSA1ICsgMiAqIGkKICAgICAgICAjIGRzdCBwb3J0IGF0IGlwX3N0YXJ0
ICsgWCArIDE2CiAgICAgICAgcHJvZy5hcHBlbmQoKExESF9JTkQsIDAsIDAsIDE2KSkKICAgICAg
ICBwcm9nLmFwcGVuZCgoSkVRX0ssIGFjY2VwdF9pZHggLSAoYiArIDIpLCAxIGlmIGkgPCBsZW4o
cG9ydHMpIC0gMQogICAgICAgICAgICAgICAgICAgICBlbHNlIHJlamVjdF9pZHggLSAoYiArIDIp
LCBwKSkKICAgIHByb2cuYXBwZW5kKChSRVRfSywgMCwgMCwgMCkpICAgICAgICAgICAgICAgIyBy
ZWplY3QKICAgIHByb2cuYXBwZW5kKChSRVRfSywgMCwgMCwgMHg0MDAwMCkpICAgICAgICAgIyBh
Y2NlcHQgKDI1NktCKQoKICAgIHRyeToKICAgICAgICBpbXBvcnQgY3R5cGVzCgogICAgICAgIGNs
YXNzIFNvY2tGaWx0ZXIoY3R5cGVzLlN0cnVjdHVyZSk6CiAgICAgICAgICAgIF9maWVsZHNfID0g
WygiY29kZSIsIGN0eXBlcy5jX3VpbnQxNiksICgianQiLCBjdHlwZXMuY191aW50OCksCiAgICAg
ICAgICAgICAgICAgICAgICAgICgiamYiLCBjdHlwZXMuY191aW50OCksICgiayIsIGN0eXBlcy5j
X3VpbnQzMildCgogICAgICAgIGNsYXNzIFNvY2tGcHJvZyhjdHlwZXMuU3RydWN0dXJlKToKICAg
ICAgICAgICAgIyBtaXJyb3JzIHN0cnVjdCBzb2NrX2Zwcm9nIHt1MTYgbGVuOyBzb2NrX2ZpbHRl
ciAqZmlsdGVyfTsKICAgICAgICAgICAgIyBjdHlwZXMgYXBwbGllcyB0aGUgc2FtZSBwb2ludGVy
IGFsaWdubWVudCBhcyB0aGUgY29tcGlsZXIKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJsZW4i
LCBjdHlwZXMuY191aW50MTYpLAogICAgICAgICAgICAgICAgICAgICAgICAoImZpbHRlciIsIGN0
eXBlcy5QT0lOVEVSKFNvY2tGaWx0ZXIpKV0KCiAgICAgICAgYXJyID0gKFNvY2tGaWx0ZXIgKiBs
ZW4ocHJvZykpKCkKICAgICAgICBmb3IgaSwgKGNvZGUsIGp0LCBqZiwgaykgaW4gZW51bWVyYXRl
KHByb2cpOgogICAgICAgICAgICBhcnJbaV0uY29kZSA9IGNvZGU7IGFycltpXS5qdCA9IGp0CiAg
ICAgICAgICAgIGFycltpXS5qZiA9IGpmOyBhcnJbaV0uayA9IGsKICAgICAgICByZXR1cm4gU29j
a0Zwcm9nKGxlbihwcm9nKSwgYXJyKSwgYXJyCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAg
IHJldHVybiBOb25lCgoKZGVmIGFwcGx5X3BlcmZfb3B0cyhzb2NrLCBwb3J0cyk6CiAgICAiIiJC
ZXN0LWVmZm9ydCBrZXJuZWwgYXNzaXN0OiBCUEYgcG9ydCBmaWx0ZXIgKyBiaWcgcmN2YnVmLiIi
IgogICAgYnVpbHQgPSBidWlsZF9icGYocG9ydHMpCiAgICBpZiBidWlsdCBpcyBub3QgTm9uZToK
ICAgICAgICB0cnk6CiAgICAgICAgICAgIGltcG9ydCBjdHlwZXMKICAgICAgICAgICAgbGliYyA9
IGN0eXBlcy5DRExMKCJsaWJjLnNvLjYiKQogICAgICAgICAgICBmcHJvZywgYXJyID0gYnVpbHQg
ICAgICAgICAgICAgICAgICAgICAgIyBrZWVwIGFyciByZWZlcmVuY2VkIQogICAgICAgICAgICBy
ZXQgPSBsaWJjLnNldHNvY2tvcHQoc29jay5maWxlbm8oKSwgc29ja2V0LlNPTF9TT0NLRVQsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBTT19BVFRBQ0hfRklMVEVSLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLmJ5cmVmKGZwcm9nKSwKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgIGN0eXBlcy5zaXplb2YoZnByb2cpKQogICAgICAgICAg
ICBpZiByZXQgPT0gMDoKICAgICAgICAgICAgICAgIGxvZygia2VybmVsIEJQRiBmaWx0ZXIgYXR0
YWNoZWQgKCVkIG1vbml0b3JlZCBwb3J0cykiCiAgICAgICAgICAgICAgICAgICAgJSBsZW4ocG9y
dHMpKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiBCUEYgYXR0
YWNoIHJlamVjdGVkIGJ5IGtlcm5lbCAocmV0PSVkKSAiCiAgICAgICAgICAgICAgICAgICAgIuKA
lCBydW5uaW5nIHVuZmlsdGVyZWQiICUgcmV0KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMg
ZToKICAgICAgICAgICAgbG9nKCJXQVJOOiBCUEYgZmlsdGVyIGF0dGFjaCBmYWlsZWQgKCVzKSDi
gJQgcnVubmluZyB1bmZpbHRlcmVkIgogICAgICAgICAgICAgICAgJSBlKQogICAgZWxzZToKICAg
ICAgICBsb2coIldBUk46IGN0eXBlcyB1bmF2YWlsYWJsZSDigJQgcnVubmluZyB3aXRob3V0IEJQ
RiBmaWx0ZXIiKQogICAgdHJ5OgogICAgICAgIHdhbnQgPSA4ICogMTAyNCAqIDEwMjQKICAgICAg
ICBzb2NrLnNldHNvY2tvcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SQ1ZCVUYsIHdh
bnQpCiAgICAgICAgZ290ID0gc29jay5nZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2Nr
ZXQuU09fUkNWQlVGKQogICAgICAgIGxvZygicmN2YnVmOiAlZCBieXRlcyIgJSBnb3QpCiAgICBl
eGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nKCJXQVJOOiBTT19SQ1ZCVUYgcmFpc2Ug
ZmFpbGVkOiAlcyIgJSBlKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBwZXJmOiBmYW5vdXQKU09MX1BBQ0tFVCA9IDI2
MwpQQUNLRVRfRkFOT1VUID0gMTgKCmRlZiBhcHBseV9mYW5vdXQoc29jaywgZ3JvdXBfaWQpOgog
ICAgIiIiS2VybmVsIGxvYWQtYmFsYW5jZXMgcGFja2V0cyBhY3Jvc3MgYWxsIHNvY2tldHMgc2hh
cmluZyB0aGUgZ3JvdXAuCiAgICBIYXNoaW5nIGlzIHBlci1mbG93LWRpcmVjdGlvbmFsOyByZXF1
ZXN0IGRpcmVjdGlvbiBhbG9uZSBkcml2ZXMgZXZlbnQKICAgIGVtaXNzaW9uLCBzbyBkaXJlY3Rp
b25hbCBzcGxpdHMgYXJlIHNhZmUuIFJldHVybnMgVHJ1ZSBvbiBzdWNjZXNzLiIiIgogICAgdHJ5
OgogICAgICAgIHNvY2suc2V0c29ja29wdChTT0xfUEFDS0VULCBQQUNLRVRfRkFOT1VULAogICAg
ICAgICAgICAgICAgICAgICAgICBzdHJ1Y3QucGFjaygiSSIsIGdyb3VwX2lkICYgMHhGRkZGKSkK
ICAgICAgICByZXR1cm4gVHJ1ZQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxv
ZygiV0FSTjogUEFDS0VUX0ZBTk9VVCBmYWlsZWQgKCVzKSDigJQgc2luZ2xlLXByb2Nlc3MgY2Fw
dHVyZSIgJSBlKQogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBwYXJzZV9hcmdzKGFyZ3YpOgog
ICAgaWZhY2UgPSBOb25lCiAgICBwb3J0cyA9IFs4MCwgODAwMywgODAwNSwgODAwNywgODAwOSwg
ODAxMCwgODAxMV0KICAgIHZlcmJvc2UgPSBGYWxzZQogICAgd29ya2VycyA9IDEKICAgIGkgPSAw
CiAgICB3aGlsZSBpIDwgbGVuKGFyZ3YpOgogICAgICAgIGEgPSBhcmd2W2ldCiAgICAgICAgaWYg
YSA9PSAiLWkiOgogICAgICAgICAgICBpICs9IDE7IGlmYWNlID0gYXJndltpXQogICAgICAgIGVs
aWYgYSA9PSAiLXAiOgogICAgICAgICAgICBpICs9IDE7IHBvcnRzID0gW2ludCh4KSBmb3IgeCBp
biBhcmd2W2ldLnNwbGl0KCIsIikgaWYgeC5zdHJpcCgpXQogICAgICAgIGVsaWYgYSA9PSAiLWoi
OgogICAgICAgICAgICBpICs9IDE7IHdvcmtlcnMgPSBtYXgoMSwgaW50KGFyZ3ZbaV0pKQogICAg
ICAgIGVsaWYgYSA9PSAiLXYiOgogICAgICAgICAgICB2ZXJib3NlID0gVHJ1ZQogICAgICAgIGVs
aWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFp
c2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0dXJuIGlmYWNl
LCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzCgoKY2xhc3MgRmxvdyhvYmplY3QpOgogICAg
X19zbG90c19fID0gKCJidWYiLCAiaGRycyIsICJ0b3VjaGVkIikKICAgIGRlZiBfX2luaXRfXyhz
ZWxmKToKICAgICAgICBzZWxmLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgc2VsZi5oZHJzID0g
e30KICAgICAgICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQoKCmRlZiBiYXNpY191c2VyKHZh
bHVlKToKICAgICIiIkF1dGhvcml6YXRpb24gaGVhZGVyIHZhbHVlIC0+ICh1c2VyfE5vbmUsIHNj
aGVtZXxOb25lKS4gQmFzaWMgb25seS4iIiIKICAgIHBhcnRzID0gdmFsdWUuc3RyaXAoKS5zcGxp
dChOb25lLCAxKQogICAgaWYgbGVuKHBhcnRzKSAhPSAyOgogICAgICAgIHJldHVybiBOb25lLCBO
b25lCiAgICBzY2hlbWUgPSBwYXJ0c1swXS5sb3dlcigpCiAgICBpZiBzY2hlbWUgPT0gImJhc2lj
IjoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBhZCA9IHBhcnRzWzFdLnN0cmlwKCkKICAgICAg
ICAgICAgcGFkICs9ICI9IiAqICgtbGVuKHBhZCkgJSA0KQogICAgICAgICAgICByYXcgPSBiYXNl
NjQuYjY0ZGVjb2RlKHBhZCkKICAgICAgICAgICAgaWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAg
ICAgICB1c2VyID0gcmF3LnNwbGl0KGIiOiIsIDEpWzBdCiAgICAgICAgICAgICAgICAjIG5ldmVy
IHJldHVybiB0aGUgcGFzc3dvcmQ7IHVzZXIgb25seQogICAgICAgICAgICAgICAgcmV0dXJuIHVz
ZXIuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjY0XSwgImJhc2ljIgogICAgICAgIGV4Y2Vw
dCBFeGNlcHRpb246CiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBlbGlmIHNjaGVt
ZSA9PSAiYmVhcmVyIjoKICAgICAgICByZXR1cm4gTm9uZSwgImJlYXJlciIgICAgICAgIyB0b2tl
biBvcGFxdWU7IHVzZXIgbWFwcGluZyBpcyBodWItc2lkZQogICAgcmV0dXJuIE5vbmUsIE5vbmUK
CgpkZWYgZmluaXNoX2V2ZW50KGZsb3csIGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9y
dCwgcG9ydHMsIG5vZGVfaG9zdCk6CiAgICBoID0gZmxvdy5oZHJzCiAgICB1c2VyID0gc2NoZW1l
ID0gTm9uZQogICAgYXV0aHogPSBoLmdldCgiYXV0aG9yaXphdGlvbiIpCiAgICBpZiBhdXRoejoK
ICAgICAgICB1c2VyLCBzY2hlbWUgPSBiYXNpY191c2VyKGF1dGh6KQogICAgIyBXM0MgdHJhY2Ug
Y29udGV4dDogaG9ub3IgaW5jb21pbmcgdHJhY2VwYXJlbnQsIGVsc2UgZ2VuZXJhdGUgb25lIHNv
CiAgICAjIGV2ZXJ5IHRyYW5zYWN0aW9uIGNhcnJpZXMgYSB0cmFjZV9pZCBmb3IgaHViLXNpZGUg
Y29ycmVsYXRpb24uCiAgICAjIE5PVEUgcHkyLjY6IGJ5dGVzIGhhcyBubyAuaGV4KCkg4oCUIHVz
ZSBiaW5hc2NpaS5oZXhsaWZ5LgogICAgdHAgPSBoLmdldCgidHJhY2VwYXJlbnQiKQogICAgdHJh
Y2VfaWQgPSBOb25lCiAgICBpZiB0cDoKICAgICAgICBwYXJ0cyA9IHRwLnNwbGl0KCItIikKICAg
ICAgICBpZiBsZW4ocGFydHMpID09IDQgYW5kIGxlbihwYXJ0c1sxXSkgPT0gMzI6CiAgICAgICAg
ICAgIHRyYWNlX2lkID0gcGFydHNbMV0ubG93ZXIoKQogICAgaWYgbm90IHRyYWNlX2lkOgogICAg
ICAgIHRyeToKICAgICAgICAgICAgcm5kID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDE2
KSkKICAgICAgICAgICAgcm5kID0gcm5kLmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHJuZCwg
ImRlY29kZSIpIGVsc2Ugcm5kCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAg
cm5kID0gKCIlMDMyeCIgJSAoaW50KHRpbWUudGltZSgpICogMTAwMCkpKVstMzI6XQogICAgICAg
IHBpZDggPSBiaW5hc2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oOCkpCiAgICAgICAgcGlkOCA9IHBp
ZDguZGVjb2RlKCJhc2NpaSIpIGlmIGhhc2F0dHIocGlkOCwgImRlY29kZSIpIGVsc2UgcGlkOAog
ICAgICAgIHRwID0gIjAwLSVzLSVzLTAxIiAlIChybmQsIHBpZDgpCiAgICAgICAgdHJhY2VfaWQg
PSBybmQKICAgIGV2ID0gewogICAgICAgICJ0cyI6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAg
Imhvc3QiOiBub2RlX2hvc3QsCiAgICAgICAgInNyYyI6ICJwY2FwIiwKICAgICAgICAic2Vydmlj
ZSI6ICJwb3J0OiVkIiAlIGRwb3J0LAogICAgICAgICJtZXRob2QiOiBoLmdldCgiX21ldGhvZCIp
IG9yICItIiwKICAgICAgICAicGF0aCI6IChoLmdldCgiX3BhdGgiKSBvciAiLSIpLnNwbGl0KCI/
IiwgMSlbMF1bOjEyMF0sCiAgICAgICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBz
Y2hlbWUsCiAgICAgICAgInBpZCI6IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6ICJwY2Fw
LWh0dHAiLAogICAgICAgICJob3N0X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAgInVzZXJf
YWdlbnQiOiBoLmdldCgidXNlci1hZ2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9mb3IiOiBo
LmdldCgieC1mb3J3YXJkZWQtZm9yIiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwKICAgICAg
ICAiY2FsbGVyX3BvcnQiOiBzcG9ydCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAogICAgICAg
ICJkc3RfcG9ydCI6IGRwb3J0LAogICAgICAgICMgLS0tLSBtb25pdG9yaW5nIHNjaGVtYSAob3Bz
IEFQSS1sb2cgZm9ybWF0KSAtLS0tCiAgICAgICAgIyBzdGF0dXMvZHVyYXRpb25fbXMvcmVzcF9i
eXRlcyBhcmUgcmVzcG9uc2Utc2lkZTogcGFzc2l2ZSByZXF1ZXN0LW9ubHkKICAgICAgICAjIGNh
cHR1cmUgY2Fubm90IHNlZSB0aGVtOyBsZWZ0IG51bGwgZm9yIHRoZSBodWIgdG8gZW5yaWNoIG9y
IGxlYXZlLgogICAgICAgICJ0cmFjZXBhcmVudCI6IHRwWzo4MF0sCiAgICAgICAgInRyYWNlX2lk
IjogdHJhY2VfaWQsCiAgICAgICAgInNlcnZpY2VfaWQiOiBOb25lLCAgICAgICAgICAjIGh1YiBt
YXBzIHBvcnQtPnNlcnZpY2UgdmlhIHBvbGljeSBsYXRlcgogICAgICAgICJtb2R1bGVfaWQiOiAi
cGNhcC1odHRwIiwKICAgIH0KICAgIHJldHVybiBldiBpZiAoZHBvcnQgaW4gcG9ydHMgb3IgaC5n
ZXQoIl9tZXRob2QiKSkgZWxzZSBOb25lCgoKZGVmIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXks
IHJldl9rZXksIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCk6CiAgICAiIiJG
ZWVkIG9uZSBkaXJlY3Rpb24ncyBwYXlsb2FkOyBlbWl0IGZpbmlzaGVkIGV2ZW50cyB0byBvdXQo
bGlzdCkuCgogICAgSEVBREVSLU9OTFkgY2FwdHVyZTogdGhlIGV2ZW50IGlzIGVtaXR0ZWQgdGhl
IG1vbWVudCBcclxuXHJcbiBpcyBzZWVuLgogICAgUmVxdWVzdCBib2RpZXMgYXJlIE5PVCBidWZm
ZXJlZCDigJQgQmFzaWMgYXV0aCAoYWxsIHdlIG1pbmUpIHJpZGVzIGhlYWRlcnMsCiAgICBzbyBi
b2R5IGJ5dGVzIGNvc3QgbWVtb3J5IGFuZCBkZWxheSBldmVudHMgZm9yIHplcm8gaW5mb3JtYXRp
b24uIEEgbGF0ZXIKICAgIHNlZ21lbnQgb24gdGhlIHNhbWUgY29ubmVjdGlvbiBzaW1wbHkgZmFp
bHMgdGhlIHJlcXVlc3QtbGluZSBjaGVjayBhbmQKICAgIGlzIGRpc2NhcmRlZC4iIiIKICAgIGRz
dF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBmbCA9IGZsb3dzLmdldChrZXkp
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
bCBmbG93c1trZXldCiAgICBpZiBldjoKICAgICAgICBvdXQuYXBwZW5kKGV2KQoKCmRlZiBzd2Vl
cF9pZGxlKGZsb3dzLCBub3cpOgogICAgc3RhbGUgPSBbXQogICAgZm9yIGssIGZsIGluIGZsb3dz
Lml0ZW1zKCk6CiAgICAgICAgaWYgbm93IC0gZmwudG91Y2hlZCA+IEZMT1dfVFRMOgogICAgICAg
ICAgICBzdGFsZS5hcHBlbmQoaykKICAgIGZvciBrIGluIHN0YWxlOgogICAgICAgIGRlbCBmbG93
c1trXQoKCmRlZiBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFi
bGUgc2l6ZSAocHkyLjY6IG5vIE9yZGVyZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZP
CiAgICBieSBpbnNlcnRpb24gb3JkZXIsIHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQ
eXRob24pLiIiIgogICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dz
KSA+IE1BWF9GTE9XUzoKICAgICAgICBmbG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3Qt
aW5zZXJ0ZWQga2V5IG9uIENQeXRob24gMi42LzIuNwoKCmRlZiBtYWluKCk6CiAgICBpZmFjZSwg
cG9ydHMsIHZlcmJvc2UsIHdvcmtlcnMgPSBwYXJzZV9hcmdzKHN5cy5hcmd2WzE6XSkKICAgIG5v
ZGVfaG9zdCA9IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICB0cnk6CiAg
ICAgICAgIyBwcm90b2NvbCBNVVNUIGJlIGh0b25zKEVUSF9QX0lQKTogYSAwLXByb3RvY29sIHNv
Y2tldCByZWNlaXZlcwogICAgICAgICMgTk9USElORyAoa2VybmVsIGRlbGl2ZXJzIG9ubHkgbWF0
Y2hpbmcgZXRoZXJ0eXBlOyAwIG1hdGNoZXMgbm9uZSkuCiAgICAgICAgIyBzb2NrZXQuaHRvbnMg
aXMgY29ycmVjdCBvbiBldmVyeSBwbGF0Zm9ybSDigJQgZG8gTk9UIHVzZSBudG9ocyBoZXJlLgog
ICAgICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9QQUNLRVQsIHNvY2tldC5TT0NLX1JB
VywKICAgICAgICAgICAgICAgICAgICAgICAgICBzb2NrZXQuaHRvbnMoRVRIX1BfSVApKQogICAg
ZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIkFGX1BBQ0tF
VCB1bmF2YWlsYWJsZSBvbiB0aGlzIHBsYXRmb3JtIikKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3Ig
YXMgZToKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5ub3Qgb3BlbiBBRl9QQUNLRVQgc29j
a2V0ICglcykg4oCUIG5lZWQgIgogICAgICAgICAgICAgICAgICAgICAgICAgIkNBUF9ORVRfUkFX
IC8gcm9vdCIgJSBlKQogICAgIyBrZXJuZWwgYXNzaXN0IEJFRk9SRSBiaW5kOiBCUEYgcG9ydCBm
aWx0ZXIgKyBiaWcgcmN2YnVmLiBXaXRoIHRoZQogICAgIyBmaWx0ZXIgYXR0YWNoZWQgdGhlIGtl
cm5lbCBkcm9wcyBub24tbW9uaXRvcmVkIHRyYWZmaWMgZm9yIHVzLCB3aGljaAogICAgIyBpcyB3
aGF0IGxpZnRzIHRoZSBjYXB0dXJlIGNlaWxpbmcgZnJvbSB+NzIwIGV2L3MgdG8gd2lyZSByYXRl
LgogICAgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKQogICAgdHJ5OgogICAgICAgIHMuYmluZCgo
aWZhY2Ugb3IgIiIsIDApKQogICAgZXhjZXB0IHNvY2tldC5lcnJvcjoKICAgICAgICAjIGJpbmRp
bmcgdG8gYSBzcGVjaWZpYyBpZmFjZSBmYWlsZWQg4oCUIGZhbGwgYmFjayB0byBhbGwgaW50ZXJm
YWNlcwogICAgICAgIHRyeToKICAgICAgICAgICAgcy5iaW5kKCgiIiwgMCkpCiAgICAgICAgZXhj
ZXB0IHNvY2tldC5lcnJvcjoKICAgICAgICAgICAgcGFzcyAgICAgICAgICAjIHVuYm91bmQgc29j
a2V0IHN0aWxsIHJlY2VpdmVzIG9uIGFsbCBpbnRlcmZhY2VzCiAgICBmYW5vdXRfb2sgPSBGYWxz
ZQogICAgaWYgd29ya2VycyA+IDE6CiAgICAgICAgZmFub3V0X29rID0gYXBwbHlfZmFub3V0KHMs
IDB4RjAwRCkKICAgICAgICBpZiBmYW5vdXRfb2s6CiAgICAgICAgICAgIGxvZygiZmFub3V0IGdy
b3VwIDB4RjAwRDogc3Bhd25pbmcgJWQgd29ya2VycyIgJSB3b3JrZXJzKQoKICAgICMgcHJlY29t
cGlsZWQgc3RydWN0IHJlYWRlcnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBv
ZiB0aGUKICAgICMgcGFja2V0IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGlu
dHMgdW5kZXIgcHkyIEFORCBweTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNr
X2Zyb20KICAgIHVoID0gc3RydWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0
LGRwb3J0IGluIG9uZSByZWFkCiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19m
cm9tCiAgICBudG9hID0gc29ja2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5p
bmcgPSBbVHJ1ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5n
WzBdID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBz
aWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUu
dGltZSgpCiAgICBsb2coImxpc3RlbmluZyBvbiAlcyBwb3J0cz0lcyBwaWQ9JWQiICUKICAgICAg
ICAoaWZhY2Ugb3IgIjxhbGw+Iiwgc29ydGVkKHBvcnRzKSwgb3MuZ2V0cGlkKCkpKQoKICAgICMg
Zm9yayBleHRyYSBjYXB0dXJlIHdvcmtlcnMgQUZURVIgZmFub3V0IGF0dGFjaDsgV0lUSE9VVCBh
IHdvcmtpbmcKICAgICMgZmFub3V0IGdyb3VwIGV2ZXJ5IHByb2Nlc3Mgd291bGQgcmVjZWl2ZSBF
VkVSWSBwYWNrZXQgKGR1cGxpY2F0ZXMpLAogICAgIyBzbyBzaW5nbGUtcHJvY2VzcyBtb2RlIGlz
IGZvcmNlZCB3aGVuIHRoZSBrZXJuZWwgbGFja3Mgc3VwcG9ydAogICAgIyAoUEFDS0VUX0ZBTk9V
VCBuZWVkcyBrZXJuZWwgPj0gMy4xOyBlbDYgMi42LjMyIGRvZXMgbm90IGhhdmUgaXQpCiAgICBp
ZiBmYW5vdXRfb2s6CiAgICAgICAgZm9yIF8gaW4gcmFuZ2Uod29ya2VycyAtIDEpOgogICAgICAg
ICAgICBpZiBvcy5mb3JrKCkgPT0gMDoKICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAg
ICAgICAjIGNoaWxkOiBmYWxsIHRocm91Z2ggaW50byBpdHMgb3duIGxvb3AKCiAgICB3aGlsZSBy
dW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQog
ICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICAgICAgbm93ID0gdGltZS50aW1l
KCkKICAgICAgICAgICAgaWYgbm93IC0gbGFzdF9zd2VlcCA+IDMwOgogICAgICAgICAgICAgICAg
c3dlZXBfaWRsZShmbG93cywgbm93KQogICAgICAgICAgICAgICAgbGFzdF9zd2VlcCA9IG5vdwog
ICAgICAgICAgICBjb250aW51ZQogICAgICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAg
ICAgICAgICAgaWYgZS5lcnJubyA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRp
bnVlCiAgICAgICAgICAgIHJhaXNlCiAgICAgICAgbiA9IGxlbihwa3QpCiAgICAgICAgaWYgbiA8
IDM0OgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAg
ICAgICAgICMgZXRoZXJuZXQgaGVhZGVyCiAgICAgICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0K
ICAgICAgICBpZiBldHlwZSA9PSBFVEhfUF9WTEFOOgogICAgICAgICAgICBldHlwZSA9IHUxNihw
a3QsIDE2KVswXQogICAgICAgICAgICBvZmYgPSAxOAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRI
X1BfSVA6CiAgICAgICAgICAgIGNvbnRpbnVlICAgICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBh
dHRhY2hlZCB0aGlzIGlzIHJhcmUKICAgICAgICBpcDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAg
ICBpZiBpcDAgPj4gNCAhPSA0IG9yIHViKHBrdCwgb2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQg
VENQIG9ubHkKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikg
KiA0CiAgICAgICAgZnJhZyA9IHUxNihwa3QsIG9mZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAm
IDB4MUZGRjogICAgICAgICAgICAgICAgICAgICAgICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAg
ICAgICAgICAgY29udGludWUKICAgICAgICBzcmNfaXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYg
KyAxNl0pCiAgICAgICAgZHN0X2lwID0gbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAg
ICAgIHRjcF9vZmYgPSBvZmYgKyBpaGwKICAgICAgICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRj
cF9vZmYpCiAgICAgICAgIyBIRUFERVItT05MWSBjYXB0dXJlOiByZXF1ZXN0IGRpcmVjdGlvbiBk
cml2ZXMgZXZlbnRzOyByZXNwb25zZQogICAgICAgICMgcGFja2V0cyBhcmUgdXNlbGVzcyB0byB1
cyBub3csIHNvIG9ubHkgZHBvcnQgcGFja2V0cyBjYXJyeSBwYXlsb2FkCiAgICAgICAgaWYgZHBv
cnQgbm90IGluIHBvcnRzOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGRvZmZfZmxhZ3Mg
PSB1Yihwa3QsIHRjcF9vZmYgKyAxMikKICAgICAgICBkb2ZmID0gKGRvZmZfZmxhZ3NbMF0gPj4g
NCkgKiA0CiAgICAgICAgcGF5X3N0YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgICAgICBpZiBuIDw9
IHBheV9zdGFydDoKICAgICAgICAgICAgY29udGludWUgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAjIG5vIHBheWxvYWQgaW4gc2VnbWVudAogICAgICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0
YXJ0Ol0gICAgICAgICAgICAgICAgICMgc2luZ2xlIGNvcHkgcGVyIGV2ZW50IHNlZwogICAgICAg
IGtleSA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgIG91dCA9IFtdCiAg
ICAgICAgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgTm9uZSwgcGF5bG9hZCwKICAgICAgICAg
ICAgICAgICAgICAgICAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAg
ICAgICAgICAgICAgcG9ydHMsIG5vZGVfaG9zdCwgb3V0KQogICAgICAgIGlmIG91dDoKICAgICAg
ICAgICAgdyA9IHN5cy5zdGRvdXQud3JpdGUKICAgICAgICAgICAgZm9yIGV2IGluIG91dDoKICAg
ICAgICAgICAgICAgIHcoanNvbi5kdW1wcyhldikgKyAiXG4iKQogICAgICAgICAgICBzeXMuc3Rk
b3V0LmZsdXNoKCkKCiAgICBsb2coInN0b3BwZWQiKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5f
XyI6CiAgICBtYWluKCkK
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
IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBqc29uLCBvcywgUXVldWUsIHNpZ25hbCwg
c29ja2V0LCBzeXMKaW1wb3J0IHRocmVhZGluZywgdGltZSwgdXJsbGliMgoKTUFYX0JBVENIID0g
NDAwCkZMVVNIX1NFQyA9IDUuMApSRVRSWV9NQVggPSA4NjQwMC4wICAgICAgICAjIGtlZXAgc3Bv
b2wtcmV0cnlpbmcgZm9yIGEgZGF5IGJlZm9yZSBnaXZpbmcgdXAKCgpkZWYgbG9nKG1zZyk6CiAg
ICBzeXMuc3RkZXJyLndyaXRlKCJudC1zaGlwOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIu
Zmx1c2goKQoKCmRlZiBtYWluKCk6CiAgICBlbmRwb2ludCA9IE5vbmUKICAgIHNwb29sID0gIi92
YXIvbGliL25ldHdvcmt0cmFjaW5nL3NuaWZmLXNwb29sLmpzb25sIgogICAgYXJndiA9IHN5cy5h
cmd2WzE6XQogICAgaSA9IDAKICAgIHdoaWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFy
Z3ZbaV0KICAgICAgICBpZiBhID09ICItLWVuZHBvaW50IjoKICAgICAgICAgICAgaSArPSAxOyBl
bmRwb2ludCA9IGFyZ3ZbaV0ucnN0cmlwKCIvIikKICAgICAgICBlbGlmIGEgPT0gIi0tc3Bvb2wi
OgogICAgICAgICAgICBpICs9IDE7IHNwb29sID0gYXJndltpXQogICAgICAgIGVsaWYgYSBpbiAo
Ii1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFpc2UgU3lzdGVt
RXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoInVua25v
d24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgaWYgbm90IGVuZHBvaW50OgogICAg
ICAgIHJhaXNlIFN5c3RlbUV4aXQoIi0tZW5kcG9pbnQgcmVxdWlyZWQiKQoKICAgIG5vZGUgPSBz
b2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCgogICAgIyByZXBsYXkgc3Bvb2xlZCBl
dmVudHMgZmlyc3QgKGF0LWxlYXN0LW9uY2UpCiAgICBwZW5kaW5nID0gW10KICAgIGlmIG9zLnBh
dGguZXhpc3RzKHNwb29sKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHdpdGggb3BlbihzcG9v
bCkgYXMgZjoKICAgICAgICAgICAgICAgIGZvciBsaW5lIGluIGY6CiAgICAgICAgICAgICAgICAg
ICAgbGluZSA9IGxpbmUuc3RyaXAoKQogICAgICAgICAgICAgICAgICAgIGlmIGxpbmU6CiAgICAg
ICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlbmRp
bmcuYXBwZW5kKGpzb24ubG9hZHMobGluZSkpCiAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2Vw
dCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAg
ICBvcy5yZW1vdmUoc3Bvb2wpCiAgICAgICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yKSBhcyBl
OgogICAgICAgICAgICBsb2coInNwb29sIHJlYWQgZmFpbGVkOiAlcyIgJSBlKQoKICAgIHJ1bm5p
bmcgPSBbVHJ1ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5n
WzBdID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBz
aWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgZGVmIGZsdXNoKGJhdGNoKToK
ICAgICAgICBpZiBub3QgYmF0Y2g6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgYm9k
eSA9IGpzb24uZHVtcHMoeyJub2RlIjogbm9kZSwgImV2ZW50cyI6IGJhdGNofSkKICAgICAgICAj
IHB5MiB1cmxsaWIyIGFjY2VwdHMgc3RyOyBweTMgc2hpbS90ZXN0IG5lZWRzIGJ5dGVzIOKAlCBl
bmNvZGUgd2hlbgogICAgICAgICMgdGhlIHJ1bnRpbWUgZXhwb3NlcyBpdCAocHkyIHN0ciBoYXMg
bm8gLmVuY29kZSBvbiBhbGwgYnVpbGRzLCBzbwogICAgICAgICMgZ3VhcmQgd2l0aCBoYXNhdHRy
KQogICAgICAgIGlmIGhhc2F0dHIoYm9keSwgImVuY29kZSIpOgogICAgICAgICAgICBib2R5ID0g
Ym9keS5lbmNvZGUoInV0Zi04IikKICAgICAgICByZXEgPSB1cmxsaWIyLlJlcXVlc3QoZW5kcG9p
bnQgKyAiL2FwaS9pbmdlc3QiLCBkYXRhPWJvZHksCiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIGhlYWRlcnM9eyJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiJ9KQogICAgICAg
IHRyeToKICAgICAgICAgICAgcmVzcCA9IHVybGxpYjIudXJsb3BlbihyZXEsIHRpbWVvdXQ9MTAp
CiAgICAgICAgICAgIG9rID0gKHJlc3AuZ2V0Y29kZSgpID09IDIwMCkKICAgICAgICAgICAgcmVz
cC5yZWFkKCkKICAgICAgICAgICAgcmVzcC5jbG9zZSgpCiAgICAgICAgICAgIGlmIG9rOgogICAg
ICAgICAgICAgICAgbG9nKCJmbHVzaGVkICVkIGV2ZW50cyIgJSBsZW4oYmF0Y2gpKQogICAgICAg
ICAgICByZXR1cm4gb2sKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAg
IGxvZygic2hpcCBmYWlsZWQ6ICVzIiAlIGUpCiAgICAgICAgICAgIHJldHVybiBGYWxzZQoKICAg
ICMgLS0tLSBjb25jdXJyZW50IHNoaXBwaW5nIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0KICAgICMgaHViIGluZ2VzdCBsYXRlbmN5ICh+MzAwLTUwMG1zIHBlciA0
MDAtZXZlbnQgUE9TVCBvdmVyIFdBTikgbWFrZXMKICAgICMgc2VxdWVudGlhbCBwb3N0aW5nIGEg
fjEwMDAgZXYvcyBjZWlsaW5nOyBOIHBvc3RlciB0aHJlYWRzIHBvc3RpbmcKICAgICMgaW5kZXBl
bmRlbnQgYmF0Y2hlcyBtdWx0aXBseSB0aGF0IGJ5IE5UX1NISVBfVEhSRUFEUwogICAgcSA9IFF1
ZXVlLlF1ZXVlKG1heHNpemU9MTI4KQogICAgc3Bvb2xfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkK
ICAgIG50aHJlYWRzID0gaW50KG9zLmVudmlyb24uZ2V0KCJOVF9TSElQX1RIUkVBRFMiLCAiNCIp
KQoKICAgIGRlZiBwb3N0ZXIoKToKICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBiYXRj
aCA9IHEuZ2V0KCkKICAgICAgICAgICAgaWYgYmF0Y2ggaXMgTm9uZToKICAgICAgICAgICAgICAg
IHEudGFza19kb25lKCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBmbHVz
aChiYXRjaCk6CiAgICAgICAgICAgICAgICBiYWNrb2ZmX2JveFswXSA9IDEKICAgICAgICAgICAg
ZWxzZToKICAgICAgICAgICAgICAgIHdpdGggc3Bvb2xfbG9jazoKICAgICAgICAgICAgICAgICAg
ICBfc3Bvb2xfYXBwZW5kKHNwb29sLCBiYXRjaCkKICAgICAgICAgICAgcS50YXNrX2RvbmUoKQoK
ICAgIGJhY2tvZmZfYm94ID0gWzFdCiAgICBmb3IgXyBpbiByYW5nZShudGhyZWFkcyk6CiAgICAg
ICAgdCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXBvc3RlcikKICAgICAgICB0LmRhZW1vbiA9
IFRydWUKICAgICAgICB0LnN0YXJ0KCkKCiAgICBidWYgPSBsaXN0KHBlbmRpbmcpCiAgICBsYXN0
X2ZsdXNoID0gdGltZS50aW1lKCkKICAgIGxhc3Rfc3Bvb2xfdHJ5ID0gdGltZS50aW1lKCkKCiAg
ICBkZWYgZm9sZF9zcG9vbCgpOgogICAgICAgICIiIlJlLXF1ZXVlIHNwb29sZWQgZXZlbnRzICht
aWQtcnVuIHJldHJ5KTsgcmV0dXJucyBjb3VudCBmb2xkZWQuIiIiCiAgICAgICAgbiA9IDAKICAg
ICAgICB0cnk6CiAgICAgICAgICAgIHdpdGggb3BlbihzcG9vbCkgYXMgZjoKICAgICAgICAgICAg
ICAgIGZvciBsaW5lIGluIGY6CiAgICAgICAgICAgICAgICAgICAgbGluZSA9IGxpbmUuc3RyaXAo
KQogICAgICAgICAgICAgICAgICAgIGlmIG5vdCBsaW5lOgogICAgICAgICAgICAgICAgICAgICAg
ICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAg
ICAgZXYgPSBqc29uLmxvYWRzKGxpbmUpCiAgICAgICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVl
RXJyb3I6CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAg
ICAgaWYgaXNpbnN0YW5jZShldiwgZGljdCk6CiAgICAgICAgICAgICAgICAgICAgICAgIGJ1Zi5h
cHBlbmQoZXYpCiAgICAgICAgICAgICAgICAgICAgICAgIG4gKz0gMQogICAgICAgICAgICBvcy5y
ZW1vdmUoc3Bvb2wpCiAgICAgICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yKToKICAgICAgICAg
ICAgcGFzcwogICAgICAgIHJldHVybiBuCgogICAgZm9yIHJhdyBpbiBpdGVyKHN5cy5zdGRpbi5y
ZWFkbGluZSwgIiIpOgogICAgICAgIGlmIG5vdCBydW5uaW5nWzBdOgogICAgICAgICAgICBicmVh
awogICAgICAgIHJhdyA9IHJhdy5zdHJpcCgpCiAgICAgICAgaWYgbm90IHJhdzoKICAgICAgICAg
ICAgY29udGludWUKICAgICAgICB0cnk6CiAgICAgICAgICAgIGV2ID0ganNvbi5sb2FkcyhyYXcp
CiAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgIGNvbnRpbnVlICAgICAgICAg
ICAgICAgICAgICAgICMgZ2FyYmFnZSBpbiwgc2lsZW50bHkgZHJvcHBlZAogICAgICAgIGlmIGlz
aW5zdGFuY2UoZXYsIGRpY3QpOgogICAgICAgICAgICBidWYuYXBwZW5kKGV2KQogICAgICAgIG5v
dyA9IHRpbWUudGltZSgpCiAgICAgICAgd2hpbGUgbGVuKGJ1ZikgPj0gTUFYX0JBVENIIG9yIChi
dWYgYW5kIG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDKToKICAgICAgICAgICAgbGFzdF9m
bHVzaCA9IG5vdwogICAgICAgICAgICAjIHJldHJ5IHNwb29sZWQgZXZlbnRzIGFoZWFkIG9mIGZy
ZXNoIG9uZXMgKH5vbmNlIGEgbWludXRlKQogICAgICAgICAgICBpZiBub3cgLSBsYXN0X3Nwb29s
X3RyeSA+PSA2MCBhbmQgb3MucGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgICAgICAgICAgbGFz
dF9zcG9vbF90cnkgPSBub3cKICAgICAgICAgICAgICAgIGZvbGRfc3Bvb2woKQogICAgICAgICAg
ICBxLnB1dChidWZbOk1BWF9CQVRDSF0pICAgICAgICAjIGJsb2NrcyB3aGVuIHBvc3RlcnMgZmFs
bCBiZWhpbmQg4oCUCiAgICAgICAgICAgIGRlbCBidWZbOk1BWF9CQVRDSF0gICAgICAgICAgICMg
dGhhdCBJUyBvdXIgYmFja3ByZXNzdXJlIHNpZ25hbAoKICAgICMgc3RkaW4gY2xvc2VkIChzbmlm
ZmVyIHN0b3BwZWQpIOKAlCBkcmFpbiBxdWV1ZSwgdGhlbiBrZWVwIHJldHJ5aW5nCiAgICAjIGFu
eXRoaW5nIHNwb29sZWQgdW50aWwgaXQgbGFuZHMgb3IgUkVUUllfTUFYIGVsYXBzZXMKICAgIGRl
YWRsaW5lID0gdGltZS50aW1lKCkgKyBSRVRSWV9NQVgKICAgIHEuam9pbigpCiAgICB3aGlsZSBy
dW5uaW5nWzBdIGFuZCB0aW1lLnRpbWUoKSA8IGRlYWRsaW5lIGFuZCBvcy5wYXRoLmV4aXN0cyhz
cG9vbCk6CiAgICAgICAgZm9sZF9zcG9vbCgpCiAgICAgICAgaWYgbm90IGJ1ZjoKICAgICAgICAg
ICAgYnJlYWsKICAgICAgICBpZiBmbHVzaChidWYpOgogICAgICAgICAgICBkZWwgYnVmWzpdCiAg
ICAgICAgZWxzZToKICAgICAgICAgICAgd2l0aCBzcG9vbF9sb2NrOgogICAgICAgICAgICAgICAg
X3Nwb29sX2FwcGVuZChzcG9vbCwgYnVmKQogICAgICAgICAgICAgICAgZGVsIGJ1Zls6XQogICAg
ICAgIHRpbWUuc2xlZXAobWluKGJhY2tvZmZfYm94WzBdLCA2MCkpCiAgICAgICAgYmFja29mZl9i
b3hbMF0gKj0gMgogICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAgICAgICAg
Zm9sZF9zcG9vbCgpCiAgICAgICAgaWYgbm90IGJ1ZiBhbmQgbm90IG9zLnBhdGguZXhpc3RzKHNw
b29sKToKICAgICAgICAgICAgYnJlYWsKICAgIGxvZygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRp
bmcgb24gZXhpdCkiICUgbGVuKGJ1ZikpCgogICAgbG9nKCJzdG9wcGVkICglZCBldmVudHMgcGVu
ZGluZyBvbiBleGl0KSIgJSBsZW4oYnVmKSkKCgpkZWYgX3Nwb29sX2FwcGVuZChwYXRoLCBiYXRj
aCk6CiAgICBkID0gb3MucGF0aC5kaXJuYW1lKHBhdGgpCiAgICB0cnk6CiAgICAgICAgaWYgZCBh
bmQgbm90IG9zLnBhdGguaXNkaXIoZCk6CiAgICAgICAgICAgIG9zLm1ha2VkaXJzKGQpCiAgICAg
ICAgd2l0aCBvcGVuKHBhdGgsICJhIikgYXMgZjoKICAgICAgICAgICAgZm9yIGV2IGluIGJhdGNo
OgogICAgICAgICAgICAgICAgZi53cml0ZShqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAg
ZGVsIGJhdGNoWzpdCiAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpIGFzIGU6CiAgICAgICAg
bG9nKCJGQVRBTDogY2Fubm90IHdyaXRlIHNwb29sICVzOiAlcyIgJSAocGF0aCwgZSkpCiAgICAg
ICAgb3MuX2V4aXQoMykKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg==
#__END_SHIP__
