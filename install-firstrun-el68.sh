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
X18gaW1wb3J0IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBlcnJubywganNvbiwgb3Ms
IHNpZ25hbCwgc29ja2V0LCBzdHJ1Y3QsIHN5cywgdGltZQoKRVRIX1BfSVAgPSAweDA4MDAKRVRI
X1BfVkxBTiA9IDB4ODEwMAoKIyBweTIuNiBzdHItaW5kZXhpbmcgeWllbGRzIDEtY2hhciBzdHIs
IG5vdCBpbnQgKHByb3ZlbiBvbiByZWFsIGVsNiBWTSk7CiMgbm9ybWFsaXplIHNvIGJ5dGUtYXQt
aW5kZXggd29ya3MgaWRlbnRpY2FsbHkgdW5kZXIgcHl0aG9uIDIgYW5kIDMKUFkyID0gc3lzLnZl
cnNpb25faW5mb1swXSA9PSAyCgoKZGVmIGIyaShjKToKICAgIHJldHVybiBvcmQoYykgaWYgUFky
IGVsc2UgYwoKTUVUSE9EUyA9ICgiR0VUIiwgIlBPU1QiLCAiUFVUIiwgIkRFTEVURSIsICJQQVRD
SCIsICJIRUFEIiwgIk9QVElPTlMiKQoKTUFYX0ZMT1dTID0gODE5MiAgICAgICAgICAgICMgY29u
Y3VycmVudCB0cmFja2VkIGhhbGYtZmxvd3MgKHBlciBkaXJlY3Rpb24pCk1BWF9IRFJTID0gMjYy
MTQ0ICAgICAgICAgICAjIG1heCBieXRlcyBidWZmZXJlZCB3YWl0aW5nIGZvciBcclxuXHJcbgpG
TE9XX1RUTCA9IDMwMCAgICAgICAgICAgICAgIyBzZWNvbmRzIGJlZm9yZSBpZGxlIGZsb3cgYnVm
ZmVycyBhcmUgZHJvcHBlZAoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUoIm50
LXNuaWZmOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCiMgLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBw
ZXJmOiBjQlBGCiMgQXR0YWNoIGEgY2xhc3NpYyBCUEYgcHJvZ3JhbSBzbyB0aGUgS0VSTkVMIGRy
b3BzIGV2ZXJ5dGhpbmcgdGhhdCBpcyBub3QKIyBJUHY0IFRDUCBkZXN0aW5lZCBUTyBhIG1vbml0
b3JlZCBwb3J0LiBSZXF1ZXN0cyBhbG9uZSBkcml2ZSBldmVudHMKIyAoaGVhZGVyLW9ubHkgY2Fw
dHVyZSk7IHJlc3BvbnNlcywgQUNLcyBhbmQgdW5yZWxhdGVkIHRyYWZmaWMgbmV2ZXIgZ2V0CiMg
Y29waWVkIHRvIHVzZXJzcGFjZSBhdCBhbGwuClNPX0FUVEFDSF9GSUxURVIgPSAyNgoKZGVmIGJ1
aWxkX2JwZihwb3J0cyk6CiAgICAiIiJDbGFzc2ljIEJQRjogZXRoZXJ0eXBlPT1JUCAmJiBwcm90
bz09VENQICYmIGRwb3J0IGluIHBvcnRzLgogICAgUmV0dXJucyAoZnByb2dfc3RydWN0LCBmaWx0
ZXJfYXJyYXkpIGZvciB0aGUgbGliYyBzZXRzb2Nrb3B0IGNhbGwsCiAgICBvciBOb25lIG9uIGZh
aWx1cmUuIE5PVEU6IHNvY2tfZnByb2cgY2FycmllcyBhIFBPSU5URVIgdG8gdGhlIGZpbHRlcgog
ICAgYXJyYXksIHNvIGl0IG11c3Qgc3RheSBhbGl2ZSB1bnRpbCB0aGUgc3lzY2FsbCDigJQgcHl0
aG9uJ3MKICAgIHNvY2tldC5zZXRzb2Nrb3B0KHN0cikgZmxhdHRlbmluZyBjYW5ub3QgcHJlc2Vy
dmUgaXQuIiIiCgogICAgTERIX0FCUyA9IDB4MjggICAjIGxkIFtrXTpoCiAgICBMREJfQUJTID0g
MHgzMCAgICMgbGQgW2tdOmIKICAgIEpFUV9LID0gMHgxNSAgICAgIyBqZXEgawogICAgTERYX01T
SCA9IDB4QjEgICAjIHggPSA0Kihba10mMHhmKSAgKGlobCBieXRlcykKICAgIExESF9JTkQgPSAw
eDQ4ICAgIyBsZCBbeCtrXTpoCiAgICBSRVRfSyA9IDB4MDYKCiAgICBwcm9nID0gW10KICAgIHJl
amVjdF9pZHggPSA1ICsgMiAqIGxlbihwb3J0cykKICAgIGFjY2VwdF9pZHggPSByZWplY3RfaWR4
ICsgMQogICAgcHJvZy5hcHBlbmQoKExESF9BQlMsIDAsIDAsIDEyKSkgICAgICAgICAgICAjIGV0
aGVydHlwZQogICAgcHJvZy5hcHBlbmQoKEpFUV9LLCAwLCByZWplY3RfaWR4IC0gMiwgMHgwODAw
KSkgICAjID09IElQIC0+IGZhbGwgdGhydQogICAgcHJvZy5hcHBlbmQoKExEQl9BQlMsIDAsIDAs
IDIzKSkgICAgICAgICAgICAjIGlwIHByb3RvIGJ5dGUgKGZpeGVkIG9mZikKICAgIHByb2cuYXBw
ZW5kKChKRVFfSywgMCwgcmVqZWN0X2lkeCAtIDQsIDYpKSAgICAgICAgIyA9PSBUQ1AgLT4gZmFs
bCB0aHJ1CiAgICBwcm9nLmFwcGVuZCgoTERYX01TSCwgMCwgMCwgMTQpKSAgICAgICAgICAgICMg
WCA9IGlobCo0CiAgICBmb3IgaSwgcCBpbiBlbnVtZXJhdGUoc29ydGVkKHBvcnRzKSk6CiAgICAg
ICAgYiA9IDUgKyAyICogaQogICAgICAgICMgZHN0IHBvcnQgYXQgaXBfc3RhcnQgKyBYICsgMTYK
ICAgICAgICBwcm9nLmFwcGVuZCgoTERIX0lORCwgMCwgMCwgMTYpKQogICAgICAgIHByb2cuYXBw
ZW5kKChKRVFfSywgYWNjZXB0X2lkeCAtIChiICsgMiksIDEgaWYgaSA8IGxlbihwb3J0cykgLSAx
CiAgICAgICAgICAgICAgICAgICAgIGVsc2UgcmVqZWN0X2lkeCAtIChiICsgMiksIHApKQogICAg
cHJvZy5hcHBlbmQoKFJFVF9LLCAwLCAwLCAwKSkgICAgICAgICAgICAgICAjIHJlamVjdAogICAg
cHJvZy5hcHBlbmQoKFJFVF9LLCAwLCAwLCAweDQwMDAwKSkgICAgICAgICAjIGFjY2VwdCAoMjU2
S0IpCgogICAgdHJ5OgogICAgICAgIGltcG9ydCBjdHlwZXMKCiAgICAgICAgY2xhc3MgU29ja0Zp
bHRlcihjdHlwZXMuU3RydWN0dXJlKToKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJjb2RlIiwg
Y3R5cGVzLmNfdWludDE2KSwgKCJqdCIsIGN0eXBlcy5jX3VpbnQ4KSwKICAgICAgICAgICAgICAg
ICAgICAgICAgKCJqZiIsIGN0eXBlcy5jX3VpbnQ4KSwgKCJrIiwgY3R5cGVzLmNfdWludDMyKV0K
CiAgICAgICAgY2xhc3MgU29ja0Zwcm9nKGN0eXBlcy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICAj
IG1pcnJvcnMgc3RydWN0IHNvY2tfZnByb2cge3UxNiBsZW47IHNvY2tfZmlsdGVyICpmaWx0ZXJ9
OwogICAgICAgICAgICAjIGN0eXBlcyBhcHBsaWVzIHRoZSBzYW1lIHBvaW50ZXIgYWxpZ25tZW50
IGFzIHRoZSBjb21waWxlcgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImxlbiIsIGN0eXBlcy5j
X3VpbnQxNiksCiAgICAgICAgICAgICAgICAgICAgICAgICgiZmlsdGVyIiwgY3R5cGVzLlBPSU5U
RVIoU29ja0ZpbHRlcikpXQoKICAgICAgICBhcnIgPSAoU29ja0ZpbHRlciAqIGxlbihwcm9nKSko
KQogICAgICAgIGZvciBpLCAoY29kZSwganQsIGpmLCBrKSBpbiBlbnVtZXJhdGUocHJvZyk6CiAg
ICAgICAgICAgIGFycltpXS5jb2RlID0gY29kZTsgYXJyW2ldLmp0ID0ganQKICAgICAgICAgICAg
YXJyW2ldLmpmID0gamY7IGFycltpXS5rID0gawogICAgICAgIHJldHVybiBTb2NrRnByb2cobGVu
KHByb2cpLCBhcnIpLCBhcnIKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5v
bmUKCgpkZWYgYXBwbHlfcGVyZl9vcHRzKHNvY2ssIHBvcnRzKToKICAgICIiIkJlc3QtZWZmb3J0
IGtlcm5lbCBhc3Npc3Q6IEJQRiBwb3J0IGZpbHRlciArIGJpZyByY3ZidWYuIiIiCiAgICBidWls
dCA9IGJ1aWxkX2JwZihwb3J0cykKICAgIGlmIGJ1aWx0IGlzIG5vdCBOb25lOgogICAgICAgIHRy
eToKICAgICAgICAgICAgaW1wb3J0IGN0eXBlcwogICAgICAgICAgICBsaWJjID0gY3R5cGVzLkNE
TEwoImxpYmMuc28uNiIpCiAgICAgICAgICAgIGZwcm9nLCBhcnIgPSBidWlsdCAgICAgICAgICAg
ICAgICAgICAgICAjIGtlZXAgYXJyIHJlZmVyZW5jZWQhCiAgICAgICAgICAgIHJldCA9IGxpYmMu
c2V0c29ja29wdChzb2NrLmZpbGVubygpLCBzb2NrZXQuU09MX1NPQ0tFVCwKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIFNPX0FUVEFDSF9GSUxURVIsCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBjdHlwZXMuYnlyZWYoZnByb2cpLAogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgY3R5cGVzLnNpemVvZihmcHJvZykpCiAgICAgICAgICAgIGlmIHJldCA9
PSAwOgogICAgICAgICAgICAgICAgbG9nKCJrZXJuZWwgQlBGIGZpbHRlciBhdHRhY2hlZCAoJWQg
bW9uaXRvcmVkIHBvcnRzKSIKICAgICAgICAgICAgICAgICAgICAlIGxlbihwb3J0cykpCiAgICAg
ICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBsb2coIldBUk46IEJQRiBhdHRhY2ggcmVqZWN0
ZWQgYnkga2VybmVsIChyZXQ9JWQpICIKICAgICAgICAgICAgICAgICAgICAi4oCUIHJ1bm5pbmcg
dW5maWx0ZXJlZCIgJSByZXQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAg
ICAgICBsb2coIldBUk46IEJQRiBmaWx0ZXIgYXR0YWNoIGZhaWxlZCAoJXMpIOKAlCBydW5uaW5n
IHVuZmlsdGVyZWQiCiAgICAgICAgICAgICAgICAlIGUpCiAgICBlbHNlOgogICAgICAgIGxvZygi
V0FSTjogY3R5cGVzIHVuYXZhaWxhYmxlIOKAlCBydW5uaW5nIHdpdGhvdXQgQlBGIGZpbHRlciIp
CiAgICB0cnk6CiAgICAgICAgd2FudCA9IDggKiAxMDI0ICogMTAyNAogICAgICAgIHNvY2suc2V0
c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCwgc29ja2V0LlNPX1JDVkJVRiwgd2FudCkKICAgICAg
ICBnb3QgPSBzb2NrLmdldHNvY2tvcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SQ1ZC
VUYpCiAgICAgICAgbG9nKCJyY3ZidWY6ICVkIGJ5dGVzIiAlIGdvdCkKICAgIGV4Y2VwdCBFeGNl
cHRpb24gYXMgZToKICAgICAgICBsb2coIldBUk46IFNPX1JDVkJVRiByYWlzZSBmYWlsZWQ6ICVz
IiAlIGUpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tIHBlcmY6IGZhbm91dApTT0xfUEFDS0VUID0gMjYzClBBQ0tFVF9G
QU5PVVQgPSAxOAoKZGVmIGFwcGx5X2Zhbm91dChzb2NrLCBncm91cF9pZCk6CiAgICAiIiJLZXJu
ZWwgbG9hZC1iYWxhbmNlcyBwYWNrZXRzIGFjcm9zcyBhbGwgc29ja2V0cyBzaGFyaW5nIHRoZSBn
cm91cC4KICAgIEhhc2hpbmcgaXMgcGVyLWZsb3ctZGlyZWN0aW9uYWw7IHJlcXVlc3QgZGlyZWN0
aW9uIGFsb25lIGRyaXZlcyBldmVudAogICAgZW1pc3Npb24sIHNvIGRpcmVjdGlvbmFsIHNwbGl0
cyBhcmUgc2FmZS4gUmV0dXJucyBUcnVlIG9uIHN1Y2Nlc3MuIiIiCiAgICB0cnk6CiAgICAgICAg
c29jay5zZXRzb2Nrb3B0KFNPTF9QQUNLRVQsIFBBQ0tFVF9GQU5PVVQsCiAgICAgICAgICAgICAg
ICAgICAgICAgIHN0cnVjdC5wYWNrKCJJIiwgZ3JvdXBfaWQgJiAweEZGRkYpKQogICAgICAgIHJl
dHVybiBUcnVlCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nKCJXQVJOOiBQ
QUNLRVRfRkFOT1VUIGZhaWxlZCAoJXMpIOKAlCBzaW5nbGUtcHJvY2VzcyBjYXB0dXJlIiAlIGUp
CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIHBhcnNlX2FyZ3MoYXJndik6CiAgICBpZmFjZSA9
IE5vbmUKICAgIHBvcnRzID0gWzgwLCA4MDAzLCA4MDA1LCA4MDA3LCA4MDA5LCA4MDEwLCA4MDEx
XQogICAgdmVyYm9zZSA9IEZhbHNlCiAgICB3b3JrZXJzID0gMQogICAgaSA9IDAKICAgIHdoaWxl
IGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFyZ3ZbaV0KICAgICAgICBpZiBhID09ICItaSI6
CiAgICAgICAgICAgIGkgKz0gMTsgaWZhY2UgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhID09ICIt
cCI6CiAgICAgICAgICAgIGkgKz0gMTsgcG9ydHMgPSBbaW50KHgpIGZvciB4IGluIGFyZ3ZbaV0u
c3BsaXQoIiwiKSBpZiB4LnN0cmlwKCldCiAgICAgICAgZWxpZiBhID09ICItaiI6CiAgICAgICAg
ICAgIGkgKz0gMTsgd29ya2VycyA9IG1heCgxLCBpbnQoYXJndltpXSkpCiAgICAgICAgZWxpZiBh
ID09ICItdiI6CiAgICAgICAgICAgIHZlcmJvc2UgPSBUcnVlCiAgICAgICAgZWxpZiBhIGluICgi
LWgiLCAiLS1oZWxwIik6CiAgICAgICAgICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0ZW1F
eGl0KDApCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5rbm93
biBhcmc6ICVzIiAlIGEpCiAgICAgICAgaSArPSAxCiAgICByZXR1cm4gaWZhY2UsIHNldChwb3J0
cyksIHZlcmJvc2UsIHdvcmtlcnMKCgpjbGFzcyBGbG93KG9iamVjdCk6CiAgICBfX3Nsb3RzX18g
PSAoImJ1ZiIsICJoZHJzIiwgInRvdWNoZWQiKQogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAg
ICAgIHNlbGYuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICBzZWxmLmhkcnMgPSB7fQogICAgICAg
IHNlbGYudG91Y2hlZCA9IHRpbWUudGltZSgpCgoKZGVmIGJhc2ljX3VzZXIodmFsdWUpOgogICAg
IiIiQXV0aG9yaXphdGlvbiBoZWFkZXIgdmFsdWUgLT4gKHVzZXJ8Tm9uZSwgc2NoZW1lfE5vbmUp
LiBCYXNpYyBvbmx5LiIiIgogICAgcGFydHMgPSB2YWx1ZS5zdHJpcCgpLnNwbGl0KE5vbmUsIDEp
CiAgICBpZiBsZW4ocGFydHMpICE9IDI6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIHNj
aGVtZSA9IHBhcnRzWzBdLmxvd2VyKCkKICAgIGlmIHNjaGVtZSA9PSAiYmFzaWMiOgogICAgICAg
IHRyeToKICAgICAgICAgICAgcGFkID0gcGFydHNbMV0uc3RyaXAoKQogICAgICAgICAgICBwYWQg
Kz0gIj0iICogKC1sZW4ocGFkKSAlIDQpCiAgICAgICAgICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNv
ZGUocGFkKQogICAgICAgICAgICBpZiBiIjoiIGluIHJhdzoKICAgICAgICAgICAgICAgIHVzZXIg
PSByYXcuc3BsaXQoYiI6IiwgMSlbMF0KICAgICAgICAgICAgICAgICMgbmV2ZXIgcmV0dXJuIHRo
ZSBwYXNzd29yZDsgdXNlciBvbmx5CiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci5kZWNvZGUo
InV0Zi04IiwgInJlcGxhY2UiKVs6NjRdLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlv
bjoKICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFy
ZXIiOgogICAgICAgIHJldHVybiBOb25lLCAiYmVhcmVyIiAgICAgICAjIHRva2VuIG9wYXF1ZTsg
dXNlciBtYXBwaW5nIGlzIGh1Yi1zaWRlCiAgICByZXR1cm4gTm9uZSwgTm9uZQoKCmRlZiBmaW5p
c2hfZXZlbnQoZmxvdywga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LCBwb3J0cywg
bm9kZV9ob3N0KToKICAgIGggPSBmbG93LmhkcnMKICAgIHVzZXIgPSBzY2hlbWUgPSBOb25lCiAg
ICBhdXRoeiA9IGguZ2V0KCJhdXRob3JpemF0aW9uIikKICAgIGlmIGF1dGh6OgogICAgICAgIHVz
ZXIsIHNjaGVtZSA9IGJhc2ljX3VzZXIoYXV0aHopCiAgICBldiA9IHsKICAgICAgICAidHMiOiBp
bnQodGltZS50aW1lKCkpLAogICAgICAgICJob3N0Ijogbm9kZV9ob3N0LAogICAgICAgICJzcmMi
OiAicGNhcCIsCiAgICAgICAgInNlcnZpY2UiOiAicG9ydDolZCIgJSBkcG9ydCwKICAgICAgICAi
bWV0aG9kIjogaC5nZXQoIl9tZXRob2QiKSBvciAiLSIsCiAgICAgICAgInBhdGgiOiAoaC5nZXQo
Il9wYXRoIikgb3IgIi0iKS5zcGxpdCgiPyIsIDEpWzBdWzoxMjBdLAogICAgICAgICJ1c2VyIjog
dXNlciwKICAgICAgICAic2NoZW1lIjogc2NoZW1lLAogICAgICAgICJwaWQiOiBOb25lLAogICAg
ICAgICJzb3VyY2VfcHJvYmUiOiAicGNhcC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdl
dCgiaG9zdCIpLAogICAgICAgICJ1c2VyX2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAg
ICAgICAieF9mb3J3YXJkZWRfZm9yIjogaC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAg
ICJjYWxsZXIiOiBzcmNfaXAsCiAgICAgICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAg
ImRzdF9pcCI6IGRzdF9pcCwKICAgICAgICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgIH0KICAgIHJl
dHVybiBldiBpZiAoZHBvcnQgaW4gcG9ydHMgb3IgaC5nZXQoIl9tZXRob2QiKSkgZWxzZSBOb25l
CgoKZGVmIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIHJldl9rZXksIHBheWxvYWQsIG1ldGEs
IHBvcnRzLCBub2RlX2hvc3QsIG91dCk6CiAgICAiIiJGZWVkIG9uZSBkaXJlY3Rpb24ncyBwYXls
b2FkOyBlbWl0IGZpbmlzaGVkIGV2ZW50cyB0byBvdXQobGlzdCkuCgogICAgSEVBREVSLU9OTFkg
Y2FwdHVyZTogdGhlIGV2ZW50IGlzIGVtaXR0ZWQgdGhlIG1vbWVudCBcclxuXHJcbiBpcyBzZWVu
LgogICAgUmVxdWVzdCBib2RpZXMgYXJlIE5PVCBidWZmZXJlZCDigJQgQmFzaWMgYXV0aCAoYWxs
IHdlIG1pbmUpIHJpZGVzIGhlYWRlcnMsCiAgICBzbyBib2R5IGJ5dGVzIGNvc3QgbWVtb3J5IGFu
ZCBkZWxheSBldmVudHMgZm9yIHplcm8gaW5mb3JtYXRpb24uIEEgbGF0ZXIKICAgIHNlZ21lbnQg
b24gdGhlIHNhbWUgY29ubmVjdGlvbiBzaW1wbHkgZmFpbHMgdGhlIHJlcXVlc3QtbGluZSBjaGVj
ayBhbmQKICAgIGlzIGRpc2NhcmRlZC4iIiIKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3Bv
cnQgPSBtZXRhCiAgICBmbCA9IGZsb3dzLmdldChrZXkpCiAgICBpZiBmbCBpcyBOb25lOgogICAg
ICAgIGZsID0gRmxvdygpCiAgICAgICAgZmxvd3Nba2V5XSA9IGZsCiAgICAgICAgaWYgbGVuKGZs
b3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICAgICAgZW5mb3JjZV9saW1pdChmbG93cywgdGltZS50
aW1lKCkpCiAgICBmbC50b3VjaGVkID0gdGltZS50aW1lKCkKICAgIGZsLmJ1Zi5leHRlbmQoYnl0
ZWFycmF5KHBheWxvYWQpKQoKICAgIGlkeCA9IGZsLmJ1Zi5maW5kKGIiXHJcblxyXG4iKQogICAg
aWYgaWR4IDwgMDoKICAgICAgICBpZiBsZW4oZmwuYnVmKSA+IE1BWF9IRFJTOgogICAgICAgICAg
ICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgICAgIHJldHVybgogICAgaGVhZCA9IGJ5dGVzKGZs
LmJ1Zls6aWR4XSkKICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxp
dChiIlxuIikKICAgIGhkcnMgPSB7fQogICAgZmlyc3QgPSBsaW5lc1swXS5zdHJpcCgpLnNwbGl0
KCkKICAgIGlmIGxlbihmaXJzdCkgPj0gMiBhbmQgZmlyc3RbMF0gaW4gWwogICAgICAgICAgICBt
LmVuY29kZSgpIGZvciBtIGluIE1FVEhPRFNdOgogICAgICAgIGhkcnNbIl9tZXRob2QiXSA9IGZp
cnN0WzBdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAgICAgICAgaGRyc1siX3BhdGgiXSA9
IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAgICBlbHNlOgogICAgICAgIGZs
b3dzLnBvcChrZXksIE5vbmUpICAgICAgICMgbm90IGEgcmVxdWVzdCBzdGFydAogICAgICAgIHJl
dHVybgogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBpZiBiIjoiIG5vdCBpbiBsbjoK
ICAgICAgICAgICAgY29udGludWUKICAgICAgICBrbiwga3YgPSBsbi5zcGxpdChiIjoiLCAxKQog
ICAgICAgIGhkcnNba24uc3RyaXAoKS5sb3dlcigpLmRlY29kZSgKICAgICAgICAgICAgImFzY2lp
IiwgInJlcGxhY2UiKV0gPSBrdi5zdHJpcCgpLmRlY29kZSgKICAgICAgICAgICAgICAgICJ1dGYt
OCIsICJyZXBsYWNlIilbOjE4MF0KICAgIGZsLmhkcnMgPSBoZHJzCiAgICBldiA9IGZpbmlzaF9l
dmVudChmbCwga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LAogICAgICAgICAgICAg
ICAgICAgICAgcG9ydHMsIG5vZGVfaG9zdCkKICAgIGRlbCBmbG93c1trZXldCiAgICBpZiBldjoK
ICAgICAgICBvdXQuYXBwZW5kKGV2KQoKCmRlZiBzd2VlcF9pZGxlKGZsb3dzLCBub3cpOgogICAg
c3RhbGUgPSBbXQogICAgZm9yIGssIGZsIGluIGZsb3dzLml0ZW1zKCk6CiAgICAgICAgaWYgbm93
IC0gZmwudG91Y2hlZCA+IEZMT1dfVFRMOgogICAgICAgICAgICBzdGFsZS5hcHBlbmQoaykKICAg
IGZvciBrIGluIHN0YWxlOgogICAgICAgIGRlbCBmbG93c1trXQoKCmRlZiBlbmZvcmNlX2xpbWl0
KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFibGUgc2l6ZSAocHkyLjY6IG5vIE9yZGVy
ZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZPCiAgICBieSBpbnNlcnRpb24gb3JkZXIs
IHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQeXRob24pLiIiIgogICAgc3dlZXBfaWRs
ZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICBm
bG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3QtaW5zZXJ0ZWQga2V5IG9uIENQeXRob24g
Mi42LzIuNwoKCmRlZiBtYWluKCk6CiAgICBpZmFjZSwgcG9ydHMsIHZlcmJvc2UsIHdvcmtlcnMg
PSBwYXJzZV9hcmdzKHN5cy5hcmd2WzE6XSkKICAgIG5vZGVfaG9zdCA9IHNvY2tldC5nZXRob3N0
bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICB0cnk6CiAgICAgICAgIyBwcm90b2NvbCBNVVNUIGJl
IGh0b25zKEVUSF9QX0lQKTogYSAwLXByb3RvY29sIHNvY2tldCByZWNlaXZlcwogICAgICAgICMg
Tk9USElORyAoa2VybmVsIGRlbGl2ZXJzIG9ubHkgbWF0Y2hpbmcgZXRoZXJ0eXBlOyAwIG1hdGNo
ZXMgbm9uZSkuCiAgICAgICAgIyBzb2NrZXQuaHRvbnMgaXMgY29ycmVjdCBvbiBldmVyeSBwbGF0
Zm9ybSDigJQgZG8gTk9UIHVzZSBudG9ocyBoZXJlLgogICAgICAgIHMgPSBzb2NrZXQuc29ja2V0
KHNvY2tldC5BRl9QQUNLRVQsIHNvY2tldC5TT0NLX1JBVywKICAgICAgICAgICAgICAgICAgICAg
ICAgICBzb2NrZXQuaHRvbnMoRVRIX1BfSVApKQogICAgZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgog
ICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIkFGX1BBQ0tFVCB1bmF2YWlsYWJsZSBvbiB0aGlzIHBs
YXRmb3JtIikKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAgICAgICByYWlzZSBTeXN0
ZW1FeGl0KCJjYW5ub3Qgb3BlbiBBRl9QQUNLRVQgc29ja2V0ICglcykg4oCUIG5lZWQgIgogICAg
ICAgICAgICAgICAgICAgICAgICAgIkNBUF9ORVRfUkFXIC8gcm9vdCIgJSBlKQogICAgIyBrZXJu
ZWwgYXNzaXN0IEJFRk9SRSBiaW5kOiBCUEYgcG9ydCBmaWx0ZXIgKyBiaWcgcmN2YnVmLiBXaXRo
IHRoZQogICAgIyBmaWx0ZXIgYXR0YWNoZWQgdGhlIGtlcm5lbCBkcm9wcyBub24tbW9uaXRvcmVk
IHRyYWZmaWMgZm9yIHVzLCB3aGljaAogICAgIyBpcyB3aGF0IGxpZnRzIHRoZSBjYXB0dXJlIGNl
aWxpbmcgZnJvbSB+NzIwIGV2L3MgdG8gd2lyZSByYXRlLgogICAgYXBwbHlfcGVyZl9vcHRzKHMs
IHBvcnRzKQogICAgdHJ5OgogICAgICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIsIDApKQogICAgZXhj
ZXB0IHNvY2tldC5lcnJvcjoKICAgICAgICAjIGJpbmRpbmcgdG8gYSBzcGVjaWZpYyBpZmFjZSBm
YWlsZWQg4oCUIGZhbGwgYmFjayB0byBhbGwgaW50ZXJmYWNlcwogICAgICAgIHRyeToKICAgICAg
ICAgICAgcy5iaW5kKCgiIiwgMCkpCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvcjoKICAgICAg
ICAgICAgcGFzcyAgICAgICAgICAjIHVuYm91bmQgc29ja2V0IHN0aWxsIHJlY2VpdmVzIG9uIGFs
bCBpbnRlcmZhY2VzCiAgICBmYW5vdXRfb2sgPSBGYWxzZQogICAgaWYgd29ya2VycyA+IDE6CiAg
ICAgICAgZmFub3V0X29rID0gYXBwbHlfZmFub3V0KHMsIDB4RjAwRCkKICAgICAgICBpZiBmYW5v
dXRfb2s6CiAgICAgICAgICAgIGxvZygiZmFub3V0IGdyb3VwIDB4RjAwRDogc3Bhd25pbmcgJWQg
d29ya2VycyIgJSB3b3JrZXJzKQoKICAgICMgcHJlY29tcGlsZWQgc3RydWN0IHJlYWRlcnMg4oCU
IHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBvZiB0aGUKICAgICMgcGFja2V0IGJ1ZmZl
ciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGludHMgdW5kZXIgcHkyIEFORCBweTMKICAg
IHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNrX2Zyb20KICAgIHVoID0gc3RydWN0LlN0
cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0LGRwb3J0IGluIG9uZSByZWFkCiAgICB1
YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19mcm9tCiAgICBudG9hID0gc29ja2V0Lmlu
ZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5pbmcgPSBbVHJ1ZV0KCiAgICBkZWYgc3Rv
cChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgIHNpZ25hbC5z
aWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJ
TlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGltZSgpCiAgICBsb2coImxpc3Rlbmlu
ZyBvbiAlcyBwb3J0cz0lcyBwaWQ9JWQiICUKICAgICAgICAoaWZhY2Ugb3IgIjxhbGw+Iiwgc29y
dGVkKHBvcnRzKSwgb3MuZ2V0cGlkKCkpKQoKICAgICMgZm9yayBleHRyYSBjYXB0dXJlIHdvcmtl
cnMgQUZURVIgZmFub3V0IGF0dGFjaDsgV0lUSE9VVCBhIHdvcmtpbmcKICAgICMgZmFub3V0IGdy
b3VwIGV2ZXJ5IHByb2Nlc3Mgd291bGQgcmVjZWl2ZSBFVkVSWSBwYWNrZXQgKGR1cGxpY2F0ZXMp
LAogICAgIyBzbyBzaW5nbGUtcHJvY2VzcyBtb2RlIGlzIGZvcmNlZCB3aGVuIHRoZSBrZXJuZWwg
bGFja3Mgc3VwcG9ydAogICAgIyAoUEFDS0VUX0ZBTk9VVCBuZWVkcyBrZXJuZWwgPj0gMy4xOyBl
bDYgMi42LjMyIGRvZXMgbm90IGhhdmUgaXQpCiAgICBpZiBmYW5vdXRfb2s6CiAgICAgICAgZm9y
IF8gaW4gcmFuZ2Uod29ya2VycyAtIDEpOgogICAgICAgICAgICBpZiBvcy5mb3JrKCkgPT0gMDoK
ICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAgICAgICAjIGNoaWxkOiBmYWxsIHRocm91
Z2ggaW50byBpdHMgb3duIGxvb3AKCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAgIHRyeToK
ICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGlt
ZW91dDoKICAgICAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgaWYgbm93IC0g
bGFzdF9zd2VlcCA+IDMwOgogICAgICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93KQog
ICAgICAgICAgICAgICAgbGFzdF9zd2VlcCA9IG5vdwogICAgICAgICAgICBjb250aW51ZQogICAg
ICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAgICAgICAgICAgaWYgZS5lcnJubyA9PSBl
cnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHJhaXNlCiAg
ICAgICAgbiA9IGxlbihwa3QpCiAgICAgICAgaWYgbiA8IDM0OgogICAgICAgICAgICBjb250aW51
ZQogICAgICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRoZXJuZXQgaGVhZGVy
CiAgICAgICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBldHlwZSA9PSBFVEhf
UF9WTEFOOgogICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQogICAgICAgICAgICBv
ZmYgPSAxOAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAgICAgICAgIGNvbnRp
bnVlICAgICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlzIHJhcmUKICAg
ICAgICBpcDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4gNCAhPSA0IG9yIHVi
KHBrdCwgb2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAgY29u
dGludWUKICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAgZnJhZyA9IHUxNihw
a3QsIG9mZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAgICAgICAgICAgICAg
ICAgICAgICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29udGludWUKICAgICAg
ICBzcmNfaXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAgICAgZHN0X2lwID0g
bnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYgPSBvZmYgKyBpaGwK
ICAgICAgICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAgICAgIyBIRUFERVIt
T05MWSBjYXB0dXJlOiByZXF1ZXN0IGRpcmVjdGlvbiBkcml2ZXMgZXZlbnRzOyByZXNwb25zZQog
ICAgICAgICMgcGFja2V0cyBhcmUgdXNlbGVzcyB0byB1cyBub3csIHNvIG9ubHkgZHBvcnQgcGFj
a2V0cyBjYXJyeSBwYXlsb2FkCiAgICAgICAgaWYgZHBvcnQgbm90IGluIHBvcnRzOgogICAgICAg
ICAgICBjb250aW51ZQogICAgICAgIGRvZmZfZmxhZ3MgPSB1Yihwa3QsIHRjcF9vZmYgKyAxMikK
ICAgICAgICBkb2ZmID0gKGRvZmZfZmxhZ3NbMF0gPj4gNCkgKiA0CiAgICAgICAgcGF5X3N0YXJ0
ID0gdGNwX29mZiArIGRvZmYKICAgICAgICBpZiBuIDw9IHBheV9zdGFydDoKICAgICAgICAgICAg
Y29udGludWUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIG5vIHBheWxvYWQgaW4gc2Vn
bWVudAogICAgICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Ol0gICAgICAgICAgICAgICAgICMg
c2luZ2xlIGNvcHkgcGVyIGV2ZW50IHNlZwogICAgICAgIGtleSA9IChzcmNfaXAsIHNwb3J0LCBk
c3RfaXAsIGRwb3J0KQogICAgICAgIG91dCA9IFtdCiAgICAgICAgaGFuZGxlX3BheWxvYWQoZmxv
d3MsIGtleSwgTm9uZSwgcGF5bG9hZCwKICAgICAgICAgICAgICAgICAgICAgICAoZHN0X2lwLCBk
cG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAgICAgICAgICAgcG9ydHMsIG5vZGVf
aG9zdCwgb3V0KQogICAgICAgIGlmIG91dDoKICAgICAgICAgICAgdyA9IHN5cy5zdGRvdXQud3Jp
dGUKICAgICAgICAgICAgZm9yIGV2IGluIG91dDoKICAgICAgICAgICAgICAgIHcoanNvbi5kdW1w
cyhldikgKyAiXG4iKQogICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKCiAgICBsb2coInN0
b3BwZWQiKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
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
