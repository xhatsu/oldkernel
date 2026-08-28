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
CONTROL_TOKEN_FILE=/var/lib/networktracing/control.token

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
        sed -n '/^#__CPP_SHIP_B64__$/,/^#__END_CPP_SHIP__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-ship-cpp.cpp" 2>/dev/null
        sed -n '/^#__CONTROL_B64__$/,/^#__END_CONTROL__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt_control.py" 2>/dev/null
        sed -n '/^#__CONTROL_RUN_B64__$/,/^#__END_CONTROL_RUN__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-control.py" 2>/dev/null
        # Control client is optional at runtime; missing token keeps it disabled.
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
        for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh el68-smoke.sh README.md DEBUG-NOTES.md; do
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
    for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-control.py"; do
        for p in $(pgrep -f "$pattern" 2>/dev/null || true); do
            [ "$p" = "$$" ] || kill "$p" 2>/dev/null || true
        done
    done
    rm -f "$INIT" "$CONTROL_TOKEN_FILE" /var/run/networktracing-legacy.pid
    rm -rf "$PREFIX" /tmp/ntkit
    RESIDUE=""
    for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-control.py"; do
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
    have python || die "python (2.6+) required on the node"
    python -c 'import sys; assert sys.version_info >= (2,6)' \
        || die "python 2.6+ required"
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
# Python control client is bundled for CentOS 6.x nodes.
for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh; do
    [ -f "$SCRIPT_DIR/$f" ] || die "bundle incomplete: missing $f"
done
cp "$SCRIPT_DIR"/nt-sniff.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship.py  "$PREFIX/"
cp "$SCRIPT_DIR"/nt_control.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-control.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship-cpp.cpp "$PREFIX/"
cp "$SCRIPT_DIR"/nt-sniff-cpp.cpp "$PREFIX/"
cp "$SCRIPT_DIR"/Makefile "$PREFIX/"
cp "$SCRIPT_DIR"/nt-run-cpp.sh "$PREFIX/"
if [ -f "$SCRIPT_DIR/install-oldkernel.sh" ]; then
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install-oldkernel.sh"
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install.sh"
elif [ -n "${SELF:-}" ] && [ -f "$SELF" ]; then
    cp "$SELF" "$PREFIX/install-oldkernel.sh"
    cp "$SELF" "$PREFIX/install.sh"
fi
chmod 755 "$PREFIX"/nt-*.py "$PREFIX"/nt-control.py "$PREFIX"/nt_control.py "$PREFIX"/nt-run-cpp.sh "$PREFIX"/install*.sh 2>/dev/null || true

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
if [ -n "${NT_CONTROL_TOKEN:-}" ]; then
    umask 077
    printf '%s' "$NT_CONTROL_TOKEN" > "$CONTROL_TOKEN_FILE"
    unset NT_CONTROL_TOKEN
    chmod 600 "$CONTROL_TOKEN_FILE"
fi
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
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
    fi
    SHIP_CMD="exec python -u $PREFIX/nt-ship.py --endpoint $ENDPOINT"
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
CONTROL_FILE=/var/lib/networktracing/remote-desired.json
CONTROL_TOKEN_FILE=/var/lib/networktracing/control.token
CONTROL_RUN=/var/lib/networktracing

case "\$1" in
    start)
        if pgrep -f "\\\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\\\$PREFIX/nt-sniff-cpp" >/dev/null; then
            echo "already running"; exit 0
        fi
        if [ -s "\$CONTROL_TOKEN_FILE" ]; then
            export NT_CONTROL_TOKEN_FILE="\$CONTROL_TOKEN_FILE"
            export NT_CONTROL_ENDPOINT="$ENDPOINT"
            export NT_CONTROL_RUN="\$CONTROL_RUN"
            export NT_NODE_NAME="\${NT_NODE_NAME:-\$(hostname -s)}"
        fi
        nohup sh -c "$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1" >/dev/null 2>&1 &
        echo \$! > "\$PIDFILE"
        sleep 1
        pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null || { echo "sniffer failed to start"; exit 1; }
        echo "networktracing-legacy started"
        ;;
    reload)
        "\$0" restart
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
    uninstall)
        \$0 stop
        if [ -f "\$PREFIX/install-oldkernel.sh" ]; then
            sh "\$PREFIX/install-oldkernel.sh" --uninstall
        elif [ -f "\$PREFIX/install.sh" ]; then
            sh "\$PREFIX/install.sh" --uninstall
        else
            if command -v chkconfig >/dev/null 2>&1; then chkconfig networktracing-legacy off >/dev/null 2>&1 || true; fi
            rm -f "\$INIT" "\$PIDFILE"
            rm -rf "\$PREFIX" /tmp/ntkit
            echo "networktracing-legacy uninstalled"
        fi
        ;;
    restart)
        \$0 stop; sleep 1; \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|status|restart|reload|uninstall}"; exit 2
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
log "Uninstall: sudo -n sh $PREFIX/install-oldkernel.sh --uninstall"
log "       or: sudo -n service networktracing-legacy uninstall"
exit 0

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
IDB4MDAwMwpFVEhfUF9JUCA9IDB4MDgwMApFVEhfUF9WTEFOID0gMHg4MTAwCgp0cnk6CiAgICBp
bXBvcnQgbnRfY29udHJvbApleGNlcHQgSW1wb3J0RXJyb3I6CiAgICBudF9jb250cm9sID0gTm9u
ZQoKIyBweTIuNiBzdHItaW5kZXhpbmcgeWllbGRzIDEtY2hhciBzdHIsIG5vdCBpbnQgKHByb3Zl
biBvbiByZWFsIGVsNiBWTSk7CiMgbm9ybWFsaXplIHNvIGJ5dGUtYXQtaW5kZXggd29ya3MgaWRl
bnRpY2FsbHkgdW5kZXIgcHl0aG9uIDIgYW5kIDMKUFkyID0gc3lzLnZlcnNpb25faW5mb1swXSA9
PSAyCgoKZGVmIGIyaShjKToKICAgIHJldHVybiBvcmQoYykgaWYgUFkyIGVsc2UgYwoKTUVUSE9E
UyA9ICgiR0VUIiwgIlBPU1QiLCAiUFVUIiwgIkRFTEVURSIsICJQQVRDSCIsICJIRUFEIiwgIk9Q
VElPTlMiKQoKTUFYX0ZMT1dTID0gODE5MiAgICAgICAgICAgICMgY29uY3VycmVudCB0cmFja2Vk
IGhhbGYtZmxvd3MgKHBlciBkaXJlY3Rpb24pCk1BWF9IRFJTID0gMjYyMTQ0ICAgICAgICAgICAj
IG1heCBieXRlcyBidWZmZXJlZCB3YWl0aW5nIGZvciBcclxuXHJcbgpGTE9XX1RUTCA9IDMwMCAg
ICAgICAgICAgICAgIyBzZWNvbmRzIGJlZm9yZSBpZGxlIGZsb3cgYnVmZmVycyBhcmUgZHJvcHBl
ZAoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUoIm50LXNuaWZmOiAlc1xuIiAl
IG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBwZXJmOiBjQlBGCiMgQXR0
YWNoIGEgY2xhc3NpYyBCUEYgcHJvZ3JhbSBzbyB0aGUgS0VSTkVMIGRyb3BzIGV2ZXJ5dGhpbmcg
dGhhdCBpcyBub3QKIyBJUHY0IFRDUCBkZXN0aW5lZCBUTyBhIG1vbml0b3JlZCBwb3J0LiBSZXF1
ZXN0cyBhbG9uZSBkcml2ZSBldmVudHMKIyAoaGVhZGVyLW9ubHkgY2FwdHVyZSk7IHJlc3BvbnNl
cywgQUNLcyBhbmQgdW5yZWxhdGVkIHRyYWZmaWMgbmV2ZXIgZ2V0CiMgY29waWVkIHRvIHVzZXJz
cGFjZSBhdCBhbGwuClNPX0FUVEFDSF9GSUxURVIgPSAyNgoKZGVmIGJ1aWxkX2JwZihwb3J0cyk6
CiAgICAiIiJDbGFzc2ljIEJQRjogZXRoZXJ0eXBlPT1JUCAmJiBwcm90bz09VENQICYmIGRwb3J0
IGluIHBvcnRzLgogICAgUmV0dXJucyAoZnByb2dfc3RydWN0LCBmaWx0ZXJfYXJyYXkpIGZvciB0
aGUgbGliYyBzZXRzb2Nrb3B0IGNhbGwsCiAgICBvciBOb25lIG9uIGZhaWx1cmUuIE5PVEU6IHNv
Y2tfZnByb2cgY2FycmllcyBhIFBPSU5URVIgdG8gdGhlIGZpbHRlcgogICAgYXJyYXksIHNvIGl0
IG11c3Qgc3RheSBhbGl2ZSB1bnRpbCB0aGUgc3lzY2FsbCDigJQgcHl0aG9uJ3MKICAgIHNvY2tl
dC5zZXRzb2Nrb3B0KHN0cikgZmxhdHRlbmluZyBjYW5ub3QgcHJlc2VydmUgaXQuIiIiCgogICAg
TERIX0FCUyA9IDB4MjggICAjIGxkIFtrXTpoCiAgICBMREJfQUJTID0gMHgzMCAgICMgbGQgW2td
OmIKICAgIEpFUV9LID0gMHgxNSAgICAgIyBqZXEgawogICAgTERYX01TSCA9IDB4QjEgICAjIHgg
PSA0Kihba10mMHhmKSAgKGlobCBieXRlcykKICAgIExESF9JTkQgPSAweDQ4ICAgIyBsZCBbeCtr
XTpoCiAgICBSRVRfSyA9IDB4MDYKCiAgICAjIFBST1ZFTiBkcG9ydCBibG9jayArIHNwb3J0IGJs
b2NrIGF0IFgrMTQgKGNhbGlicmF0ZWQgRU1QSVJJQ0FMTFkgb24KICAgICMgYSBsaXZlIGtlcm5l
bDogaz0xNCBkZWxpdmVycyByZXNwb25zZSBwYWNrZXRzOyB0aGUgY29ycmVsYXRpb24gdGhlbgog
ICAgIyB5aWVsZHMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgZW5kLXRvLWVuZCkuIFJl
cXVpcmVzIHRoZSAxcwogICAgIyByZWN2IHRpbWVvdXQgaW4gbWFpbigpIOKAlCBibG9ja2luZyBy
ZWN2ICsgQlBGIHN0YXJ2ZXMgYWZ0ZXIgb25lIHBrdC4KICAgIHNrID0gaW50KG9zLmVudmlyb24u
Z2V0KCJOVF9TTklGRl9TUE9SVF9LIiwgIjE0IikpCiAgICBwcyA9IHNvcnRlZChwb3J0cykKICAg
IG4gPSBsZW4ocHMpCiAgICByZXRfcmVqID0gNSArICg0IGlmIHNrIGVsc2UgMikgKiBuCiAgICBy
ZXRfYWNjID0gcmV0X3JlaiArIDEKICAgIHByb2cgPSBbXQogICAgcHJvZy5hcHBlbmQoKExESF9B
QlMsIDAsIDAsIDEyKSkgICAgICAgICAgICAgICAgICMgZXRoZXJ0eXBlID09IElQPwogICAgcHJv
Zy5hcHBlbmQoKEpFUV9LLCAwLCByZXRfcmVqIC0gMiwgMHgwODAwKSkKICAgIHByb2cuYXBwZW5k
KChMREJfQUJTLCAwLCAwLCAyMykpICAgICAgICAgICAgICAgICAjIHByb3RvID09IFRDUD8KICAg
IHByb2cuYXBwZW5kKChKRVFfSywgMCwgcmV0X3JlaiAtIDQsIDYpKQogICAgcHJvZy5hcHBlbmQo
KExEWF9NU0gsIDAsIDAsIDE0KSkgICAgICAgICAgICAgICAgICMgWCA9IGlobCo0CiAgICBmb3Ig
aSwgcCBpbiBlbnVtZXJhdGUocHMpOiAgICAgICAgICAgICAgICAgICAgICAgIyBBOiBkcG9ydCBA
IFgrMTYKICAgICAgICBwcm9nLmFwcGVuZCgoTERIX0lORCwgMCwgMCwgMTYpKQogICAgICAgIGp0
ID0gcmV0X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgIGpmID0gMCBpZiAoaSA8IG4gLSAx
IG9yIHNrKSBlbHNlIChyZXRfcmVqIC0gKGxlbihwcm9nKSArIDEpKQogICAgICAgIHByb2cuYXBw
ZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIGlmIHNrOiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAjIEI6IHNwb3J0IEAgWCtzawogICAgICAgIGZvciBpLCBwIGlu
IGVudW1lcmF0ZShwcyk6CiAgICAgICAgICAgIHByb2cuYXBwZW5kKChMREhfSU5ELCAwLCAwLCBz
aykpCiAgICAgICAgICAgIGp0ID0gcmV0X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgICAg
ICBqZiA9IDAgaWYgaSA8IG4gLSAxIGVsc2UgKHJldF9yZWogLSAobGVuKHByb2cpICsgMSkpCiAg
ICAgICAgICAgIHByb2cuYXBwZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIHByb2cuYXBwZW5k
KChSRVRfSywgMCwgMCwgMCkpICAgICAgICAgICAgICAgICAgICAjIHJlamVjdAogICAgcHJvZy5h
cHBlbmQoKFJFVF9LLCAwLCAwLCAweDQwMDAwKSkgICAgICAgICAgICAgICMgYWNjZXB0CgogICAg
dHJ5OgogICAgICAgIGltcG9ydCBjdHlwZXMKCiAgICAgICAgY2xhc3MgU29ja0ZpbHRlcihjdHlw
ZXMuU3RydWN0dXJlKToKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJjb2RlIiwgY3R5cGVzLmNf
dWludDE2KSwgKCJqdCIsIGN0eXBlcy5jX3VpbnQ4KSwKICAgICAgICAgICAgICAgICAgICAgICAg
KCJqZiIsIGN0eXBlcy5jX3VpbnQ4KSwgKCJrIiwgY3R5cGVzLmNfdWludDMyKV0KCiAgICAgICAg
Y2xhc3MgU29ja0Zwcm9nKGN0eXBlcy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICAjIG1pcnJvcnMg
c3RydWN0IHNvY2tfZnByb2cge3UxNiBsZW47IHNvY2tfZmlsdGVyICpmaWx0ZXJ9OwogICAgICAg
ICAgICAjIGN0eXBlcyBhcHBsaWVzIHRoZSBzYW1lIHBvaW50ZXIgYWxpZ25tZW50IGFzIHRoZSBj
b21waWxlcgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImxlbiIsIGN0eXBlcy5jX3VpbnQxNiks
CiAgICAgICAgICAgICAgICAgICAgICAgICgiZmlsdGVyIiwgY3R5cGVzLlBPSU5URVIoU29ja0Zp
bHRlcikpXQoKICAgICAgICBhcnIgPSAoU29ja0ZpbHRlciAqIGxlbihwcm9nKSkoKQogICAgICAg
IGZvciBpLCAoY29kZSwganQsIGpmLCBrKSBpbiBlbnVtZXJhdGUocHJvZyk6CiAgICAgICAgICAg
IGFycltpXS5jb2RlID0gY29kZTsgYXJyW2ldLmp0ID0ganQKICAgICAgICAgICAgYXJyW2ldLmpm
ID0gamY7IGFycltpXS5rID0gawogICAgICAgIHJldHVybiBTb2NrRnByb2cobGVuKHByb2cpLCBh
cnIpLCBhcnIKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYg
YXBwbHlfcGVyZl9vcHRzKHNvY2ssIHBvcnRzKToKICAgICIiIkJlc3QtZWZmb3J0IGtlcm5lbCBh
c3Npc3Q6IEJQRiBwb3J0IGZpbHRlciArIGJpZyByY3ZidWYuCiAgICBOVF9TTklGRl9OT19CUEY9
MSBkaXNhYmxlcyB0aGUgZmlsdGVyIChkZWJ1Z2dpbmcpLiIiIgogICAgYnVpbHQgPSBOb25lCiAg
ICBpZiBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfTk9fQlBGIikgPT0gIjEiOgogICAgICAgIGxv
ZygiTlRfU05JRkZfTk9fQlBGIHNldCDigJQgc2tpcHBpbmcga2VybmVsIGZpbHRlciIpCiAgICBl
bHNlOgogICAgICAgIGJ1aWx0ID0gYnVpbGRfYnBmKHBvcnRzKQogICAgaWYgYnVpbHQgaXMgbm90
IE5vbmU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpbXBvcnQgY3R5cGVzCiAgICAgICAgICAg
IGxpYmMgPSBjdHlwZXMuQ0RMTCgibGliYy5zby42IikKICAgICAgICAgICAgZnByb2csIGFyciA9
IGJ1aWx0ICAgICAgICAgICAgICAgICAgICAgICMga2VlcCBhcnIgcmVmZXJlbmNlZCEKICAgICAg
ICAgICAgcmV0ID0gbGliYy5zZXRzb2Nrb3B0KHNvY2suZmlsZW5vKCksIHNvY2tldC5TT0xfU09D
S0VULAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgU09fQVRUQUNIX0ZJTFRFUiwK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN0eXBlcy5ieXJlZihmcHJvZyksCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuc2l6ZW9mKGZwcm9nKSkKICAg
ICAgICAgICAgaWYgcmV0ID09IDA6CiAgICAgICAgICAgICAgICBsb2coImtlcm5lbCBCUEYgZmls
dGVyIGF0dGFjaGVkICglZCBtb25pdG9yZWQgcG9ydHMpIgogICAgICAgICAgICAgICAgICAgICUg
bGVuKHBvcnRzKSkKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGxvZygiV0FSTjog
QlBGIGF0dGFjaCByZWplY3RlZCBieSBrZXJuZWwgKHJldD0lZCkgIgogICAgICAgICAgICAgICAg
ICAgICLigJQgcnVubmluZyB1bmZpbHRlcmVkIiAlIHJldCkKICAgICAgICBleGNlcHQgRXhjZXB0
aW9uIGFzIGU6CiAgICAgICAgICAgIGxvZygiV0FSTjogQlBGIGZpbHRlciBhdHRhY2ggZmFpbGVk
ICglcykg4oCUIHJ1bm5pbmcgdW5maWx0ZXJlZCIKICAgICAgICAgICAgICAgICUgZSkKICAgIGVs
c2U6CiAgICAgICAgbG9nKCJXQVJOOiBjdHlwZXMgdW5hdmFpbGFibGUg4oCUIHJ1bm5pbmcgd2l0
aG91dCBCUEYgZmlsdGVyIikKICAgIHRyeToKICAgICAgICB3YW50ID0gOCAqIDEwMjQgKiAxMDI0
CiAgICAgICAgc29jay5zZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fUkNW
QlVGLCB3YW50KQogICAgICAgIGdvdCA9IHNvY2suZ2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tF
VCwgc29ja2V0LlNPX1JDVkJVRikKICAgICAgICBsb2coInJjdmJ1ZjogJWQgYnl0ZXMiICUgZ290
KQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZygiV0FSTjogU09fUkNWQlVG
IHJhaXNlIGZhaWxlZDogJXMiICUgZSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gcGVyZjogZmFub3V0ClNPTF9QQUNL
RVQgPSAyNjMKUEFDS0VUX0ZBTk9VVCA9IDE4CgpkZWYgYXBwbHlfZmFub3V0KHNvY2ssIGdyb3Vw
X2lkKToKICAgICIiIktlcm5lbCBsb2FkLWJhbGFuY2VzIHBhY2tldHMgYWNyb3NzIGFsbCBzb2Nr
ZXRzIHNoYXJpbmcgdGhlIGdyb3VwLgogICAgSGFzaGluZyBpcyBwZXItZmxvdy1kaXJlY3Rpb25h
bDsgcmVxdWVzdCBkaXJlY3Rpb24gYWxvbmUgZHJpdmVzIGV2ZW50CiAgICBlbWlzc2lvbiwgc28g
ZGlyZWN0aW9uYWwgc3BsaXRzIGFyZSBzYWZlLiBSZXR1cm5zIFRydWUgb24gc3VjY2Vzcy4iIiIK
ICAgIHRyeToKICAgICAgICBzb2NrLnNldHNvY2tvcHQoU09MX1BBQ0tFVCwgUEFDS0VUX0ZBTk9V
VCwKICAgICAgICAgICAgICAgICAgICAgICAgc3RydWN0LnBhY2soIkkiLCBncm91cF9pZCAmIDB4
RkZGRikpCiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAg
ICAgICBsb2coIldBUk46IFBBQ0tFVF9GQU5PVVQgZmFpbGVkICglcykg4oCUIHNpbmdsZS1wcm9j
ZXNzIGNhcHR1cmUiICUgZSkKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgcGFyc2VfYXJncyhh
cmd2KToKICAgIGlmYWNlID0gTm9uZQogICAgcG9ydHMgPSBbODAsIDgwMDMsIDgwMDUsIDgwMDcs
IDgwMDksIDgwMTAsIDgwMTFdCiAgICB2ZXJib3NlID0gRmFsc2UKICAgIHdvcmtlcnMgPSAxCiAg
ICBpID0gMAogICAgd2hpbGUgaSA8IGxlbihhcmd2KToKICAgICAgICBhID0gYXJndltpXQogICAg
ICAgIGlmIGEgPT0gIi1pIjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAg
ICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLWkgcmVxdWlyZXMgYW4gaW50ZXJmYWNlIikK
ICAgICAgICAgICAgaSArPSAxOyBpZmFjZSA9IGFyZ3ZbaV0KICAgICAgICBlbGlmIGEgPT0gIi1w
IjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAgICAgICAgcmFp
c2UgU3lzdGVtRXhpdCgiLXAgcmVxdWlyZXMgYSBjb21tYS1zZXBhcmF0ZWQgcG9ydCBsaXN0IikK
ICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBvcnRz
ID0gW2ludCh4KSBmb3IgeCBpbiBhcmd2W2ldLnNwbGl0KCIsIikgaWYgeC5zdHJpcCgpXQogICAg
ICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoImludmFsaWQgcG9ydCBsaXN0IikKICAgICAgICAgICAgaWYgbm90IHBvcnRzIG9yIGFueShu
b3QgdmFsaWRfcG9ydCh4KSBmb3IgeCBpbiBwb3J0cyk6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCJwb3J0cyBtdXN0IGJlIGluIHJhbmdlIDEuLjY1NTM1IikKICAgICAgICBlbGlm
IGEgPT0gIi1qIjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAg
ICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLWogcmVxdWlyZXMgYSB3b3JrZXIgY291bnQiKQogICAg
ICAgICAgICBpICs9IDEKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd29ya2VycyA9
IG1heCgxLCBpbnQoYXJndltpXSkpCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAg
ICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiaW52YWxpZCB3b3JrZXIgY291bnQiKQogICAg
ICAgIGVsaWYgYSA9PSAiLXYiOgogICAgICAgICAgICB2ZXJib3NlID0gVHJ1ZQogICAgICAgIGVs
aWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFp
c2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0dXJuIGlmYWNl
LCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzCgoKY2xhc3MgRmxvdyhvYmplY3QpOgogICAg
X19zbG90c19fID0gKCJidWYiLCAiaGRycyIsICJ0b3VjaGVkIikKICAgIGRlZiBfX2luaXRfXyhz
ZWxmKToKICAgICAgICBzZWxmLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgc2VsZi5oZHJzID0g
e30KICAgICAgICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQoKCiMgLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAt
LS0tClBFTkRJTkdfVFRMID0gNS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBh
ZnRlciB0aGlzIG1hbnkgc2Vjb25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNh
cDsgb3ZlcmZsb3cgZmx1c2hlcyBvbGRlc3QgZmlyc3QKCiMgcGVuZGluZ1soc3JjX2lwLCBzcG9y
dCwgZHN0X2lwLCBkcG9ydCldICAtLSBrZXkgaXMgdGhlIFJFU1BPTlNFIHR1cGxlOgojIHNlcnZl
ci0+Y2xpZW50LiBWYWx1ZTogW2V2ZW50LCByZXFfdHNdLiBBIGxpc3QgcGVyIGtleSBoYW5kbGVz
IEhUVFAKIyBrZWVwLWFsaXZlIHBpcGVsaW5pbmcgKHNldmVyYWwgcmVxdWVzdHMgYmVmb3JlIHJl
c3BvbnNlcyBhcnJpdmUpLgpwZW5kaW5nID0ge30KCgpkZWYgcGVuZGluZ19kZWwocmspOgogICAg
cGVuZGluZy5wb3AocmssIE5vbmUpCgoKZGVmIHBlbmRpbmdfcG9wKHJrLCBvdXQpOgogICAgIiIi
Rmx1c2ggdGhlIG9sZGVzdCBwZW5kaW5nIGV2ZW50IGZvciB0aGlzIHJlc3BvbnNlIHR1cGxlIChG
SU4vUlNUIG9yCiAgICBvdmVyZmxvdyBwYXRoKS4gRW1pdHMgd2hhdGV2ZXIgdGhlIGV2ZW50IGhh
cyDigJQgc3RhdHVzIHN0YXlzIG51bGwuIiIiCiAgICBsc3QgPSBwZW5kaW5nLmdldChyaykKICAg
IGlmIG5vdCBsc3Q6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGV2LCBfID0gbHN0LnBvcCgwKQog
ICAgaWYgbm90IGxzdDoKICAgICAgICBwZW5kaW5nX2RlbChyaykKICAgIG91dC5hcHBlbmQoZXYp
CiAgICByZXR1cm4gZXYKCgpkZWYgcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2FkKToKICAgICIi
IkZpcnN0IGxpbmUgJ0hUVFAvMS54IE5OTiAuLi4nIC0+IChzdGF0dXNfaW50fE5vbmUsIGNvbnRl
bnRfbGVufE5vbmUpLgogICAgT25seSBsb29rcyBhdCB3aGF0J3MgaW4gdGhpcyBzZWdtZW50OyBo
ZWFkZXJzIGZpdCBvbmUgc2VnbWVudCBmb3IgYWxsCiAgICByZWFsaXN0aWMgQVBJIHJlc3BvbnNl
cy4iIiIKICAgIHRyeToKICAgICAgICBoZWFkID0gcGF5bG9hZC5zcGxpdChiIlxyXG5cclxuIiwg
MSlbMF0KICAgICAgICBsaW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQo
YiJcbiIpCiAgICAgICAgZmlyc3QgPSBsaW5lc1swXS5zcGxpdCgpCiAgICAgICAgaWYgbGVuKGZp
cnN0KSA8IDIgb3Igbm90IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLyIpOgogICAgICAgICAg
ICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgIHN0ID0gaW50KGZpcnN0WzFdKQogICAgZXhjZXB0
IChWYWx1ZUVycm9yLCBJbmRleEVycm9yKToKICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAg
Y2xlbiA9IE5vbmUKICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAgICAgICAgbG93ID0gbG4ubG93
ZXIoKQogICAgICAgIGlmIGxvdy5zdGFydHN3aXRoKGIiY29udGVudC1sZW5ndGg6Iik6CiAgICAg
ICAgICAgIHRyeToKICAgICAgICAgICAgICAgIGNsZW4gPSBpbnQobG4uc3BsaXQoYiI6IiwgMSlb
MV0uc3RyaXAoKSkKICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAg
ICBwYXNzCiAgICAgICAgICAgIGJyZWFrCiAgICByZXR1cm4gc3QsIGNsZW4KCgpkZWYgdmFsaWRf
cG9ydChwKToKICAgIHRyeToKICAgICAgICByZXR1cm4gMSA8PSBpbnQocCkgPD0gNjU1MzUKICAg
IGV4Y2VwdCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UKCgpk
ZWYgYmFzaWNfdXNlcih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRlciB2YWx1ZSAt
PiAodXNlcnxOb25lLCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBwYXJ0cyA9IHZh
bHVlLnN0cmlwKCkuc3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0gMjoKICAgICAg
ICByZXR1cm4gTm9uZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAgaWYg
c2NoZW1lID09ICJiYXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQgPSBwYXJ0c1sx
XS5zdHJpcCgpCiAgICAgICAgICAgIGlmIGxlbihwYWQpID4gMTAyNDoKICAgICAgICAgICAgICAg
IHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxlbihwYWQpICUg
NCkKICAgICAgICAgICAgcmF3ID0gYmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAgICAgICAgIGlm
IGxlbihyYXcpID4gNTEyOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAg
ICAgICAgaWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAgICAgICB1c2VyID0gcmF3LnNwbGl0KGIi
OiIsIDEpWzBdCiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci5kZWNvZGUoInV0Zi04IiwgInJl
cGxhY2UiKVs6NjRdLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAg
ICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFyZXIiOgogICAgICAg
IHJldHVybiBOb25lLCAiYmVhcmVyIgogICAgcmV0dXJuIE5vbmUsIE5vbmUKCgpkZWYgZmluaXNo
X2V2ZW50KGZsb3csIGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCwgcG9ydHMsIG5v
ZGVfaG9zdCk6CiAgICBoID0gZmxvdy5oZHJzCiAgICB1c2VyID0gc2NoZW1lID0gTm9uZQogICAg
YXV0aHogPSBoLmdldCgiYXV0aG9yaXphdGlvbiIpCiAgICBpZiBhdXRoejoKICAgICAgICB1c2Vy
LCBzY2hlbWUgPSBiYXNpY191c2VyKGF1dGh6KQogICAgIyBXM0MgdHJhY2UgY29udGV4dDogaG9u
b3IgaW5jb21pbmcgdHJhY2VwYXJlbnQsIGVsc2UgZ2VuZXJhdGUgb25lIHNvCiAgICAjIGV2ZXJ5
IHRyYW5zYWN0aW9uIGNhcnJpZXMgYSB0cmFjZV9pZCBmb3IgaHViLXNpZGUgY29ycmVsYXRpb24u
CiAgICAjIE5PVEUgcHkyLjY6IGJ5dGVzIGhhcyBubyAuaGV4KCkg4oCUIHVzZSBiaW5hc2NpaS5o
ZXhsaWZ5LgogICAgdHAgPSBoLmdldCgidHJhY2VwYXJlbnQiKQogICAgdHJhY2VfaWQgPSBOb25l
CiAgICBpZiB0cDoKICAgICAgICBwYXJ0cyA9IHRwLnNwbGl0KCItIikKICAgICAgICBpZiBsZW4o
cGFydHMpID09IDQgYW5kIGxlbihwYXJ0c1sxXSkgPT0gMzI6CiAgICAgICAgICAgIHRyYWNlX2lk
ID0gcGFydHNbMV0ubG93ZXIoKQogICAgaWYgbm90IHRyYWNlX2lkOgogICAgICAgIHRyeToKICAg
ICAgICAgICAgcm5kID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDE2KSkKICAgICAgICAg
ICAgcm5kID0gcm5kLmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHJuZCwgImRlY29kZSIpIGVs
c2Ugcm5kCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcm5kID0gKCIlMDMy
eCIgJSAoaW50KHRpbWUudGltZSgpICogMTAwMCkpKVstMzI6XQogICAgICAgIHBpZDggPSBiaW5h
c2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oOCkpCiAgICAgICAgcGlkOCA9IHBpZDguZGVjb2RlKCJh
c2NpaSIpIGlmIGhhc2F0dHIocGlkOCwgImRlY29kZSIpIGVsc2UgcGlkOAogICAgICAgIHRwID0g
IjAwLSVzLSVzLTAxIiAlIChybmQsIHBpZDgpCiAgICAgICAgdHJhY2VfaWQgPSBybmQKICAgIGV2
ID0gewogICAgICAgICJ0cyI6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAgImhvc3QiOiBub2Rl
X2hvc3QsCiAgICAgICAgInNyYyI6ICJwY2FwIiwKICAgICAgICAic2VydmljZSI6ICJwb3J0OiVk
IiAlIGRwb3J0LAogICAgICAgICJtZXRob2QiOiBoLmdldCgiX21ldGhvZCIpIG9yICItIiwKICAg
ICAgICAicGF0aCI6IChoLmdldCgiX3BhdGgiKSBvciAiLSIpLnNwbGl0KCI/IiwgMSlbMF1bOjEy
MF0sCiAgICAgICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBzY2hlbWUsCiAgICAg
ICAgInBpZCI6IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6ICJwY2FwLWh0dHAiLAogICAg
ICAgICJob3N0X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAgInVzZXJfYWdlbnQiOiBoLmdl
dCgidXNlci1hZ2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9mb3IiOiBoLmdldCgieC1mb3J3
YXJkZWQtZm9yIiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwKICAgICAgICAiY2FsbGVyX3Bv
cnQiOiBzcG9ydCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAogICAgICAgICJkc3RfcG9ydCI6
IGRwb3J0LAogICAgICAgICMgLS0tLSBtb25pdG9yaW5nIHNjaGVtYSAob3BzIEFQSS1sb2cgZm9y
bWF0KSAtLS0tCiAgICAgICAgIyBzdGF0dXMvZHVyYXRpb25fbXMvcmVzcF9ieXRlcyBhcmUgcmVz
cG9uc2Utc2lkZTogcGFzc2l2ZSByZXF1ZXN0LW9ubHkKICAgICAgICAjIGNhcHR1cmUgY2Fubm90
IHNlZSB0aGVtOyBsZWZ0IG51bGwgZm9yIHRoZSBodWIgdG8gZW5yaWNoIG9yIGxlYXZlLgogICAg
ICAgICJ0cmFjZXBhcmVudCI6IHRwWzo4MF0sCiAgICAgICAgInRyYWNlX2lkIjogdHJhY2VfaWQs
CiAgICAgICAgInNlcnZpY2VfaWQiOiBOb25lLCAgICAgICAgICAjIGh1YiBtYXBzIHBvcnQtPnNl
cnZpY2UgdmlhIHBvbGljeSBsYXRlcgogICAgICAgICJtb2R1bGVfaWQiOiAicGNhcC1odHRwIiwK
ICAgIH0KICAgICMgUHJlc2VydmUgcmVzcG9uc2UgY29ycmVsYXRpb24gb25seSBmb3IgbW9uaXRv
cmVkIGRlc3RpbmF0aW9ucy4gVGhlCiAgICAjIHJlc3BvbnNlLXNpZGUgZmlsdGVyIG1heSBzdGls
bCBhZG1pdCBhIGNsaWVudCBlcGhlbWVyYWwgc3BvcnQgZXF1YWwgdG8gYQogICAgIyBtb25pdG9y
ZWQgcG9ydDsgdGhpcyBpcyBoYXJtbGVzcyBiZWNhdXNlIHBhcnNlX3Jlc3BvbnNlX2hlYWQgcmVq
ZWN0cyBpdC4KICAgIHJldHVybiBldiBpZiAoZHBvcnQgaW4gcG9ydHMgb3IgaC5nZXQoIl9tZXRo
b2QiKSkgZWxzZSBOb25lCgoKZGVmIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIHJldl9rZXks
IHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAgICAgICAgICAgICAg
IHBlbmRpbmdfdGJsPU5vbmUsIG5vdz1Ob25lKToKICAgICIiIkZlZWQgb25lIGRpcmVjdGlvbidz
IHBheWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0KS4KCiAgICBIRUFERVIt
T05MWSBjYXB0dXJlOiB0aGUgcmVxdWVzdCBldmVudCBpcyBidWlsdCB0aGUgbW9tZW50IFxcclxc
blxcclxcbiBpcwogICAgc2Vlbi4gV2l0aCByZXNwb25zZSBjb3JyZWxhdGlvbiBlbmFibGVkIChw
ZW5kaW5nX3RibCksIHRoZSBmaW5pc2hlZAogICAgZXZlbnQgZ29lcyBpbnRvIHRoZSBwZW5kaW5n
IHRhYmxlIGluc3RlYWQgb2Ygb3V0IOKAlCBpdCBpcyBlbWl0dGVkIHdoZW4KICAgIHRoZSBtYXRj
aGluZyByZXNwb25zZSBoZWFkIGFycml2ZXMsIG9yIG9uIFRUTC90ZWFyZG93biBmYWxsYmFjay4K
ICAgIFJlcXVlc3QgYm9kaWVzIGFyZSBOT1QgYnVmZmVyZWQg4oCUIEJhc2ljIGF1dGggKGFsbCB3
ZSBtaW5lKSByaWRlcyBoZWFkZXJzLAogICAgc28gYm9keSBieXRlcyBjb3N0IG1lbW9yeSBhbmQg
ZGVsYXkgZXZlbnRzIGZvciB6ZXJvIGluZm9ybWF0aW9uLiBBIGxhdGVyCiAgICBzZWdtZW50IG9u
IHRoZSBzYW1lIGNvbm5lY3Rpb24gc2ltcGx5IGZhaWxzIHRoZSByZXF1ZXN0LWxpbmUgY2hlY2sg
YW5kCiAgICBpcyBkaXNjYXJkZWQuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0
ID0gbWV0YQogICAgaWYgbm90IHZhbGlkX3BvcnQoZHBvcnQpIG9yIG5vdCB2YWxpZF9wb3J0KHNw
b3J0KToKICAgICAgICByZXR1cm4KICAgIGZsID0gZmxvd3MuZ2V0KGtleSkKICAgIGlmIGZsIGlz
IE5vbmU6CiAgICAgICAgZmwgPSBGbG93KCkKICAgICAgICBmbG93c1trZXldID0gZmwKICAgICAg
ICBpZiBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgICAgICBlbmZvcmNlX2xpbWl0KGZs
b3dzLCB0aW1lLnRpbWUoKSkKICAgIGZsLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQogICAgZmwuYnVm
LmV4dGVuZChieXRlYXJyYXkocGF5bG9hZCkpCgogICAgaWR4ID0gZmwuYnVmLmZpbmQoYiJcclxu
XHJcbiIpCiAgICBpZiBpZHggPCAwOgogICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6
CiAgICAgICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBoZWFk
ID0gYnl0ZXMoZmwuYnVmWzppZHhdKQogICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwg
YiJcbiIpLnNwbGl0KGIiXG4iKQogICAgaGRycyA9IHt9CiAgICBmaXJzdCA9IGxpbmVzWzBdLnN0
cmlwKCkuc3BsaXQoKQogICAgaWYgbGVuKGZpcnN0KSA+PSAyIGFuZCBmaXJzdFswXSBpbiBbCiAg
ICAgICAgICAgIG0uZW5jb2RlKCkgZm9yIG0gaW4gTUVUSE9EU106CiAgICAgICAgaGRyc1siX21l
dGhvZCJdID0gZmlyc3RbMF0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAgICBoZHJz
WyJfcGF0aCJdID0gZmlyc3RbMV0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgIGVsc2U6
CiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkgICAgICAgIyBub3QgYSByZXF1ZXN0IHN0YXJ0
CiAgICAgICAgcmV0dXJuCiAgICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgIGlmIGIiOiIg
bm90IGluIGxuOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGtuLCBrdiA9IGxuLnNwbGl0
KGIiOiIsIDEpCiAgICAgICAgaGRyc1trbi5zdHJpcCgpLmxvd2VyKCkuZGVjb2RlKAogICAgICAg
ICAgICAiYXNjaWkiLCAicmVwbGFjZSIpXSA9IGt2LnN0cmlwKCkuZGVjb2RlKAogICAgICAgICAg
ICAgICAgInV0Zi04IiwgInJlcGxhY2UiKVs6MTgwXQogICAgZmwuaGRycyA9IGhkcnMKICAgIGV2
ID0gZmluaXNoX2V2ZW50KGZsLCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsCiAg
ICAgICAgICAgICAgICAgICAgICBwb3J0cywgbm9kZV9ob3N0KQogICAgZGVsIGZsb3dzW2tleV0K
ICAgIGlmIG5vdCBldjoKICAgICAgICByZXR1cm4KICAgIGV2WyJyZXFfYnl0ZXMiXSA9IGlkeCAr
IDQgICAgICAgICAgIyBjYXB0dXJlZCByZXF1ZXN0IGhlYWQgKyB0ZXJtaW5hdG9yCiAgICBpZiBw
ZW5kaW5nX3RibCBpcyBOb25lOgogICAgICAgIG91dC5hcHBlbmQoZXYpICAgICAgICAgICAgICAg
ICAjIGNvcnJlbGF0aW9uIGRpc2FibGVkIChsZWdhY3kgcGF0aCkKICAgICAgICByZXR1cm4KICAg
ICMgcXVldWUgZm9yIHJlc3BvbnNlIGNvcnJlbGF0aW9uOyBrZXkgaXMgdGhlIFJFU1BPTlNFIHR1
cGxlCiAgICByayA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgZW50ID0gcGVu
ZGluZ190YmwuZ2V0KHJrKQogICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgaWYgbGVuKHBlbmRp
bmdfdGJsKSA+PSBQRU5ESU5HX01BWDoKICAgICAgICAgICAgX2ZsdXNoX29sZGVzdF9wZW5kaW5n
KHBlbmRpbmdfdGJsLCBvdXQpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmxbcmtdID0gW10KICAg
IGVudC5hcHBlbmQoW2V2LCBub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGltZS50aW1lKCld
KQoKCmRlZiBzd2VlcF9pZGxlKGZsb3dzLCBub3cpOgogICAgc3RhbGUgPSBbXQogICAgZm9yIGss
IGZsIGluIGZsb3dzLml0ZW1zKCk6CiAgICAgICAgaWYgbm93IC0gZmwudG91Y2hlZCA+IEZMT1df
VFRMOgogICAgICAgICAgICBzdGFsZS5hcHBlbmQoaykKICAgIGZvciBrIGluIHN0YWxlOgogICAg
ICAgIGRlbCBmbG93c1trXQoKCmRlZiBfZmx1c2hfb2xkZXN0X3BlbmRpbmcocGVuZGluZ190Ymws
IG91dCk6CiAgICAiIiJPdmVyZmxvdyBndWFyZDogZW1pdCB0aGUgc2luZ2xlIG9sZGVzdCBwZW5k
aW5nIGV2ZW50IGFzLWlzLiIiIgogICAgb2xkZXN0X2tleSwgb2xkZXN0X3RzID0gTm9uZSwgTm9u
ZQogICAgZm9yIHJrLCBsc3QgaW4gcGVuZGluZ190YmwuaXRlbXMoKToKICAgICAgICB0cyA9IGxz
dFswXVsxXQogICAgICAgIGlmIG9sZGVzdF90cyBpcyBOb25lIG9yIHRzIDwgb2xkZXN0X3RzOgog
ICAgICAgICAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSByaywgdHMKICAgIGlmIG9sZGVzdF9r
ZXkgaXMgbm90IE5vbmU6CiAgICAgICAgcGVuZGluZ19wb3Aob2xkZXN0X2tleSwgb3V0KQoKCmRl
ZiBzd2VlcF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBub3csIG91dCk6CiAgICAiIiJUVEwgZmx1c2g6
IGVtaXQgcmVxdWVzdHMgd2hvc2UgcmVzcG9uc2VzIG5ldmVyIHNob3dlZCB1cC4iIiIKICAgIHN0
YWxlID0gW10KICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJsLml0ZW1zKCk6CiAgICAgICAg
aWYgbm93IC0gbHN0WzBdWzFdID4gUEVORElOR19UVEw6CiAgICAgICAgICAgIHN0YWxlLmFwcGVu
ZChyaykKICAgIGZvciByayBpbiBzdGFsZToKICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0KQoK
CmRlZiBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFibGUgc2l6
ZSAocHkyLjY6IG5vIE9yZGVyZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZPCiAgICBi
eSBpbnNlcnRpb24gb3JkZXIsIHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQeXRob24p
LiIiIgogICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dzKSA+IE1B
WF9GTE9XUzoKICAgICAgICBmbG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3QtaW5zZXJ0
ZWQga2V5IG9uIENQeXRob24gMi42LzIuNwoKCmRlZiBfY29udHJvbF9jb25maWcoKToKICAgICIi
IlJlYWQgb3B0aW9uYWwgY29udHJvbCBzZXR0aW5ncyB3aXRob3V0IGV4cG9zaW5nIHRoZSBiZWFy
ZXIgdG9rZW4uIiIiCiAgICBlbmRwb2ludCA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX0VO
RFBPSU5UIikgb3Igb3MuZW52aXJvbi5nZXQoIk5UX0VORFBPSU5UIikKICAgIHRva2VuX2ZpbGUg
PSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTl9GSUxFIiwgIiIpCiAgICB0b2tlbiA9
IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOIiwgIiIpCiAgICBpZiB0b2tlbl9maWxl
OgogICAgICAgIHRyeToKICAgICAgICAgICAgZiA9IG9wZW4odG9rZW5fZmlsZSwgInIiKQogICAg
ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB0b2tlbiA9IGYucmVhZCgpLnN0cmlwKCkKICAg
ICAgICAgICAgZmluYWxseToKICAgICAgICAgICAgICAgIGYuY2xvc2UoKQogICAgICAgIGV4Y2Vw
dCBJT0Vycm9yOgogICAgICAgICAgICB0b2tlbiA9ICIiCiAgICBub2RlID0gb3MuZW52aXJvbi5n
ZXQoIk5UX05PREVfTkFNRSIpIG9yIHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0K
ICAgIHJ1bl9kaXIgPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9SVU4iLCAiL3Zhci9saWIv
bmV0d29ya3RyYWNpbmciKQogICAgdHJ5OgogICAgICAgIGludGVydmFsID0gbWF4KDUsIG1pbihp
bnQob3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfU0VDIiwgIjMwIikpLCAzMDApKQogICAgZXhj
ZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgaW50ZXJ2YWwgPSAzMAogICAgcmV0dXJuIGVuZHBvaW50
LCB0b2tlbiwgbm9kZSwgcnVuX2RpciwgaW50ZXJ2YWwKCgpkZWYgX3J1bl9jb250cm9sX3RpY2so
cG9ydHMsIGlmYWNlLCBydW5fZGlyLCBjbGllbnQpOgogICAgcmVwbHkgPSBjbGllbnQucG9sbCgp
CiAgICBpZiBub3QgcmVwbHk6CiAgICAgICAgcmV0dXJuIHBvcnRzLCBpZmFjZSwgRmFsc2UsICJw
b2xsIGZhaWxlZCIKICAgIGRlc2lyZWQgPSByZXBseS5nZXQoImRlc2lyZWQiKSBvciB7fQogICAg
Z2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0aW9uIiwgMCkKICAgIHJlc3RhcnRfcmVx
dWVzdGVkID0gRmFsc2UKICAgIGlmIGRlc2lyZWQuZ2V0KCJwb3J0cyIpOgogICAgICAgIG5ld19w
b3J0cyA9IHNldChkZXNpcmVkWyJwb3J0cyJdKQogICAgICAgIGlmIG5ld19wb3J0cyAhPSBwb3J0
czoKICAgICAgICAgICAgcG9ydHMgPSBuZXdfcG9ydHMKICAgIGlmIGRlc2lyZWQuZ2V0KCJpZmFj
ZSIpOgogICAgICAgIGlmYWNlID0gZGVzaXJlZFsiaWZhY2UiXQogICAgbnRfY29udHJvbC53cml0
ZV9zdGF0ZShvcy5wYXRoLmpvaW4ocnVuX2RpciwgInJlbW90ZS1kZXNpcmVkLmpzb24iKSwgZGVz
aXJlZCwgInJlc3RhcnQgcmVxdWlyZWQiKQogICAgZm9yIHRhc2sgaW4gcmVwbHkuZ2V0KCJ0YXNr
cyIsIFtdKToKICAgICAgICBhY3Rpb24gPSB0YXNrLmdldCgiYWN0aW9uIikKICAgICAgICBpZiBh
Y3Rpb24gPT0gImhlYWx0aCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAiaGVhbHRoeSIKICAgICAg
ICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgZWxpZiBhY3Rpb24gaW4gKCJyZXN0YXJ0Iiwg
InJlbG9hZCIsICJzZXRfcG9ydHMiKToKICAgICAgICAgICAgbWVzc2FnZSA9ICJhY2NlcHRlZDsg
Y2FwdHVyZSByZXN0YXJ0IHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAg
ICAgICAgICAgIHJlc3RhcnRfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAgICAgICBpZiBhY3Rpb24g
PT0gInNldF9wb3J0cyI6CiAgICAgICAgICAgICAgICBhcmdzID0gdGFzay5nZXQoImFyZ3MiKSBv
ciB7fQogICAgICAgICAgICAgICAgaWYgYXJncy5nZXQoInBvcnRzIik6CiAgICAgICAgICAgICAg
ICAgICAgcG9ydHMgPSBzZXQoYXJnc1sicG9ydHMiXSkKICAgICAgICAgICAgICAgICAgICBudF9j
b250cm9sLndyaXRlX3N0YXRlKG9zLnBhdGguam9pbihydW5fZGlyLCAicmVtb3RlLWRlc2lyZWQu
anNvbiIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeyJwb3J0
cyI6IHNvcnRlZChwb3J0cyksICJtb2RlIjogInB5dGhvbiIsCiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgImdlbmVyYXRpb24iOiBnZW5lcmF0aW9ufSwgbWVzc2Fn
ZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAic3RvcCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAi
c3RvcCByZXF1ZXN0ZWQiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgICAgICBy
ZXN0YXJ0X3JlcXVlc3RlZCA9IEZhbHNlCiAgICAgICAgZWxzZToKICAgICAgICAgICAgbWVzc2Fn
ZSA9ICJ1bnN1cHBvcnRlZCBieSBkaXJlY3Qgc25pZmZlciIKICAgICAgICAgICAgc3RhdHVzID0g
ImZhaWxlZCIKICAgICAgICBjbGllbnQucmVwb3J0KHRhc2suZ2V0KCJpZCIpLCBzdGF0dXMsIG1l
c3NhZ2UpCiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sICJyZXN0YXJ0IHJlcXVpcmVk
IiBpZiByZXN0YXJ0X3JlcXVlc3RlZCBlbHNlICJwb2xsIG9rIikKICAgIHJldHVybiBwb3J0cywg
aWZhY2UsIHJlc3RhcnRfcmVxdWVzdGVkLCAicG9sbCBvayIKCgpkZWYgbWFpbigpOgogICAgaWZh
Y2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAg
ICBub2RlX2hvc3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250
cm9sX2NsaWVudCA9IE5vbmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250
cm9sX3J1biwgY29udHJvbF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9j
b250cm9sIGlzIG5vdCBOb25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5Ogog
ICAgICAgICAgICBjb250cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRw
b2ludCwgdG9rZW4sIGNvbnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNk
aXIoY29udHJvbF9ydW4pOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4p
CiAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0
IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRp
c2FibGVkICglcykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAg
ICAgICMgcHJvdG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJ
TkdSRVNTIChyZXEpIGFuZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4
IGtlcm5lbCBwYWNrZXQgc29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQu
QUZfUEFDS0VULCBzb2NrZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29j
a2V0Lmh0b25zKEVUSF9QX0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAg
cmFpc2UgU3lzdGVtRXhpdCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0i
KQogICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQo
ImNhbm5vdCBvcGVuIEFGX1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAg
ICAgICAgICAgICAgICAiQ0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQo
MS4wKQogICAgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKQogICAgdHJ5OgogICAgICAgIHMuYmlu
ZCgoaWZhY2Ugb3IgIiIsIEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yOgogICAg
ICAgIHRyeToKICAgICAgICAgICAgcy5iaW5kKCgiIiwgRVRIX1BfQUxMKSkKICAgICAgICBleGNl
cHQgc29ja2V0LmVycm9yOgogICAgICAgICAgICBwYXNzCiAgICBmYW5vdXRfb2sgPSBGYWxzZQog
ICAgaWYgd29ya2VycyA+IDE6CiAgICAgICAgZmFub3V0X29rID0gYXBwbHlfZmFub3V0KHMsIDB4
RjAwRCkKICAgICAgICBpZiBmYW5vdXRfb2s6CiAgICAgICAgICAgIGxvZygiZmFub3V0IGdyb3Vw
IDB4RjAwRDogc3Bhd25pbmcgJWQgd29ya2VycyIgJSB3b3JrZXJzKQoKICAgICMgcHJlY29tcGls
ZWQgc3RydWN0IHJlYWRlcnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBvZiB0
aGUKICAgICMgcGFja2V0IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGludHMg
dW5kZXIgcHkyIEFORCBweTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNrX2Zy
b20KICAgIHVoID0gc3RydWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0LGRw
b3J0IGluIG9uZSByZWFkCiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19mcm9t
CiAgICBudG9hID0gc29ja2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5pbmcg
PSBbVHJ1ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBd
ID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWdu
YWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGlt
ZSgpCiAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcgb24g
JXMgcG9ydHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRlZChw
b3J0cyksIG9zLmdldHBpZCgpKSkKCiAgICAjIGZvcmsgZXh0cmEgY2FwdHVyZSB3b3JrZXJzIEFG
VEVSIGZhbm91dCBhdHRhY2g7IFdJVEhPVVQgYSB3b3JraW5nCiAgICAjIGZhbm91dCBncm91cCBl
dmVyeSBwcm9jZXNzIHdvdWxkIHJlY2VpdmUgRVZFUlkgcGFja2V0IChkdXBsaWNhdGVzKSwKICAg
ICMgc28gc2luZ2xlLXByb2Nlc3MgbW9kZSBpcyBmb3JjZWQgd2hlbiB0aGUga2VybmVsIGxhY2tz
IHN1cHBvcnQKICAgICMgKFBBQ0tFVF9GQU5PVVQgbmVlZHMga2VybmVsID49IDMuMTsgZWw2IDIu
Ni4zMiBkb2VzIG5vdCBoYXZlIGl0KQogICAgaWYgZmFub3V0X29rOgogICAgICAgIGZvciBfIGlu
IHJhbmdlKHdvcmtlcnMgLSAxKToKICAgICAgICAgICAgaWYgb3MuZm9yaygpID09IDA6CiAgICAg
ICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAgIyBjaGlsZDogZmFsbCB0aHJvdWdoIGlu
dG8gaXRzIG93biBsb29wCgogICAgIyAxcyByZWN2IHRpbWVvdXQ6IChhKSBsZXRzIHRoZSBwZW5k
aW5nL2Zsb3cgc3dlZXBzIGFjdHVhbGx5IGZpcmUg4oCUCiAgICAjIHdpdGhvdXQgaXQgYGV4Y2Vw
dCBzb2NrZXQudGltZW91dGAgbmV2ZXIgcnVuczsgKGIpIGVtcGlyaWNhbGx5IFJFUVVJUkVECiAg
ICAjIHdpdGggdGhlIEJQRiBmaWx0ZXIgYXR0YWNoZWQ6IGEgZnVsbHktYmxvY2tpbmcgcmVjdiBv
biB0aGlzIGtlcm5lbAogICAgIyBzdGFydmVzIGFmdGVyIHRoZSBmaXJzdCBwYWNrZXQsIHdoaWxl
IHRoZSB0aW1lb3V0J2QgcmVjdiBkZWxpdmVycwogICAgIyBjb250aW51b3VzbHkgKHZlcmlmaWVk
IGJ5IEEvQjogcng9MSB2cyByeD0yOSBpZGVudGljYWwgb3RoZXJ3aXNlKS4KICAgIHMuc2V0dGlt
ZW91dCgxLjApCgogICAgZGJnID0gb3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX0RFQlVHIikgPT0g
IjEiCiAgICBkYmdfcnggPSAwCiAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICB3aGlsZSBy
dW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQog
ICAgICAgICAgICBkYmdfcnggKz0gMQogICAgICAgICAgICBpZiBkYmcgYW5kIHRpbWUudGltZSgp
IC0gZGJnX2xhc3QgPiA1OgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyByeD0lZCIgJSBkYmdf
cngpCiAgICAgICAgICAgICAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgZXhjZXB0
IHNvY2tldC50aW1lb3V0OgogICAgICAgICAgICBpZiBjb250cm9sX2NsaWVudCBpcyBub3QgTm9u
ZSBhbmQgdGltZS50aW1lKCkgPj0gY29udHJvbF9uZXh0OgogICAgICAgICAgICAgICAgdHJ5Ogog
ICAgICAgICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwgcmVzdGFydF9yZXF1ZXN0ZWQsIGNvbnRy
b2xfc3RhdHVzID0gX3J1bl9jb250cm9sX3RpY2soCiAgICAgICAgICAgICAgICAgICAgICAgIHBv
cnRzLCBpZmFjZSwgY29udHJvbF9ydW4sIGNvbnRyb2xfY2xpZW50KQogICAgICAgICAgICAgICAg
ICAgIGxvZygicmVtb3RlIGNvbnRyb2w6ICVzIiAlIGNvbnRyb2xfc3RhdHVzKQogICAgICAgICAg
ICAgICAgICAgIGlmIHJlc3RhcnRfcmVxdWVzdGVkOgogICAgICAgICAgICAgICAgICAgICAgICBs
b2coInJlbW90ZSBjb250cm9sOiByZXN0YXJ0IHJlcXVpcmVkOyBleGl0aW5nIGZvciBTeXNWIHdy
YXBwZXIiKQogICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgICAg
ICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgICAgICBsb2co
IldBUk46IHJlbW90ZSBjb250cm9sIHRpY2sgZmFpbGVkICglcykiICUgbnRfY29udHJvbC5zYWZl
X21lc3NhZ2UoZSkpCiAgICAgICAgICAgICAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSAr
IGNvbnRyb2xfaW50ZXJ2YWwKICAgICAgICAgICAgaWYgZGJnOgogICAgICAgICAgICAgICAgbG9n
KCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0
ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAg
aWYgbm93IC0gbGFzdF9zd2VlcCA+IDMwOgogICAgICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93
cywgbm93KQogICAgICAgICAgICAgICAgb3V0X3MgPSBbXQogICAgICAgICAgICAgICAgc3dlZXBf
cGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICAgICAgZm9yIGV2IGluIG91
dF9zOgogICAgICAgICAgICAgICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1wcyhldikg
KyAiXG4iKQogICAgICAgICAgICAgICAgaWYgb3V0X3M6CiAgICAgICAgICAgICAgICAgICAgc3lz
LnN0ZG91dC5mbHVzaCgpCiAgICAgICAgICAgICAgICBsYXN0X3N3ZWVwID0gbm93CiAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgICAg
ICBpZiBlLmVycm5vID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAgY29udGludWUKICAg
ICAgICAgICAgcmFpc2UKICAgICAgICBuID0gbGVuKHBrdCkKICAgICAgICBpZiBuIDwgMzQ6CiAg
ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgb3V0ID0gW10KICAgICAgICBvZmYgPSAxNCAgICAg
ICAgICAgICAgICAgICAgICAjIGV0aGVybmV0IGhlYWRlcgogICAgICAgIGV0eXBlID0gdTE2KHBr
dCwgMTIpWzBdCiAgICAgICAgaWYgZXR5cGUgPT0gRVRIX1BfVkxBTjoKICAgICAgICAgICAgZXR5
cGUgPSB1MTYocGt0LCAxNilbMF0KICAgICAgICAgICAgb2ZmID0gMTgKICAgICAgICBlbGlmIGV0
eXBlICE9IEVUSF9QX0lQOgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAgICAgICMg
d2l0aCBCUEYgYXR0YWNoZWQgdGhpcyBpcyByYXJlCiAgICAgICAgaXAwID0gdWIocGt0LCBvZmYp
WzBdCiAgICAgICAgaWYgaXAwID4+IDQgIT0gNCBvciB1Yihwa3QsIG9mZiArIDkpWzBdICE9IDY6
ICAgIyBJUHY0IFRDUCBvbmx5CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWhsID0gKGlw
MCAmIDB4MEYpICogNAogICAgICAgIGZyYWcgPSB1MTYocGt0LCBvZmYgKyA2KVswXQogICAgICAg
IGlmIGZyYWcgJiAweDFGRkY6ICAgICAgICAgICAgICAgICAgICAgICAgICMgbm9uLWZpcnN0IGZy
YWdtZW50CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgc3JjX2lwID0gbnRvYShwa3Rbb2Zm
ICsgMTI6b2ZmICsgMTZdKQogICAgICAgIGRzdF9pcCA9IG50b2EocGt0W29mZiArIDE2Om9mZiAr
IDIwXSkKICAgICAgICB0Y3Bfb2ZmID0gb2ZmICsgaWhsCiAgICAgICAgc3BvcnQsIGRwb3J0ID0g
dWgocGt0LCB0Y3Bfb2ZmKQogICAgICAgIGRvZmZfZmxhZ3MgPSB1Yihwa3QsIHRjcF9vZmYgKyAx
MikKICAgICAgICBkb2ZmID0gKGRvZmZfZmxhZ3NbMF0gPj4gNCkgKiA0CiAgICAgICAgcGF5X3N0
YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgICAgICBpZiBuIDw9IHBheV9zdGFydDoKICAgICAgICAg
ICAgY29udGludWUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIG5vIHBheWxvYWQgaW4g
c2VnbWVudAogICAgICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Ol0KICAgICAgICBmbGFncyA9
IGRvZmZfZmxhZ3NbMV0KICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQoKICAgICAgICAjIC0tLS0t
LS0tLS0tLS0tLS0gUkVTUE9OU0UgZGlyZWN0aW9uIChzZXJ2ZXIgLT4gY2xpZW50KSAtLS0tLS0t
LS0tCiAgICAgICAgaWYgc3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0czoKICAg
ICAgICAgICAgIyBwZW5kaW5nIGtleSB3YXMgc3RvcmVkIGFzIChzZXJ2ZXJfaXAsIHNlcnZlcl9w
b3J0LCBjbGllbnRfaXAsCiAgICAgICAgICAgICMgY2xpZW50X3BvcnQpID09IChzcmMsIHNwb3J0
LCBkc3QsIGRwb3J0KSBPRiBUSElTIHJlc3BvbnNlIHBrdAogICAgICAgICAgICByayA9IChzcmNf
aXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBpZiBwYXlsb2FkWzo1XSA9PSBi
IkhUVFAvIjoKICAgICAgICAgICAgICAgIHN0LCBjbGVuID0gcGFyc2VfcmVzcG9uc2VfaGVhZChw
YXlsb2FkKQogICAgICAgICAgICAgICAgZW50ID0gcGVuZGluZy5nZXQocmspCiAgICAgICAgICAg
ICAgICBpZiBlbnQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgZXYgPSBlbnRbMF1b
MF0KICAgICAgICAgICAgICAgICAgICBldlsic3RhdHVzIl0gPSBzdAogICAgICAgICAgICAgICAg
ICAgIGV2WyJkdXJhdGlvbl9tcyJdID0gaW50KChub3cgLSBlbnRbMF1bMV0pICogMTAwMCkKICAg
ICAgICAgICAgICAgICAgICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAg
ICAgICBldlsicmVzcF9ieXRlcyJdID0gY2xlbgogICAgICAgICAgICAgICAgICAgIHBlbmRpbmdf
ZGVsKHJrKQogICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgICAgIGVs
aWYgZmxhZ3MgJiAweDA1OiAgICAgICAgICAgICAgICAgICAgICAjIEZJTnxSU1Q6IGZsdXNoIHVu
bWF0Y2hlZAogICAgICAgICAgICAgICAgZXYgPSBwZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAg
ICMgLS0tLS0tLS0tLS0tLS0tLSBSRVFVRVNUIGRpcmVjdGlvbiAoY2xpZW50IC0+IHNlcnZlcikg
LS0tLS0tLS0tLS0KICAgICAgICBlbGlmIGRwb3J0IGluIHBvcnRzOgogICAgICAgICAgICBpZiBm
bGFncyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgdGVhcmRvd24gdy9vIHJlc3BvbnNl
IHNlZW4KICAgICAgICAgICAgICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQp
CiAgICAgICAgICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAgICAgICBrZXkgPSAo
c3JjX2lwLCBzcG9ydCwgZHN0X2lwLCBkcG9ydCkKICAgICAgICAgICAgaGFuZGxlX3BheWxvYWQo
Zmxvd3MsIGtleSwgTm9uZSwgcGF5bG9hZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKGRz
dF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICBw
b3J0cywgbm9kZV9ob3N0LCBvdXQsIHBlbmRpbmcsIG5vdykKICAgICAgICBpZiBvdXQ6CiAgICAg
ICAgICAgIHcgPSBzeXMuc3Rkb3V0LndyaXRlCiAgICAgICAgICAgIGZvciBldiBpbiBvdXQ6CiAg
ICAgICAgICAgICAgICB3KGpzb24uZHVtcHMoZXYpICsgIlxuIikKICAgICAgICAgICAgc3lzLnN0
ZG91dC5mbHVzaCgpCgogICAgbG9nKCJzdG9wcGVkIikKCgppZiBfX25hbWVfXyA9PSAiX19tYWlu
X18iOgogICAgbWFpbigpCg==
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
#__CONTROL_B64__
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMgLSotIGNvZGluZzogdXRmLTggLSotCiIiIkJvdW5kZWQg
UHl0aG9uIDIuNi1jb21wYXRpYmxlIGNvbnRyb2wgY2xpZW50IGZvciBvbGRrZXJuZWwgY2FwdHVy
ZS4KVXNlcyBvbmx5IHN0YW5kYXJkLWxpYnJhcnkgSFRUUCBhbmQgYXRvbWljIGxvY2FsIHN0YXRl
LiIiIgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IHByaW50X2Z1bmN0aW9uCgppbXBvcnQganNvbgpp
bXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN5cwppbXBvcnQgdGltZQoK
dHJ5OgogICAgZnJvbSB1cmxsaWIgaW1wb3J0IHF1b3RlCiAgICBpbXBvcnQgdXJsbGliMgpleGNl
cHQgSW1wb3J0RXJyb3I6CiAgICBmcm9tIHVybGxpYi5wYXJzZSBpbXBvcnQgcXVvdGUKICAgIGlt
cG9ydCB1cmxsaWIucmVxdWVzdCBhcyB1cmxsaWIyCgp0cnk6CiAgICBKU09OX0VSUk9SUyA9IChW
YWx1ZUVycm9yLCBqc29uLkpTT05EZWNvZGVFcnJvcikKZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgog
ICAgSlNPTl9FUlJPUlMgPSAoVmFsdWVFcnJvciwpCgp0cnk6CiAgICBzdHJpbmdfdHlwZXMgPSAo
c3RyLCB1bmljb2RlKQpleGNlcHQgTmFtZUVycm9yOgogICAgc3RyaW5nX3R5cGVzID0gKHN0ciwp
CnRyeToKICAgIGJ5dGVfdHlwZXMgPSAoYnl0ZXMsIGJ5dGVhcnJheSkKZXhjZXB0IE5hbWVFcnJv
cjoKICAgIGJ5dGVfdHlwZXMgPSAoYnl0ZWFycmF5LCkKCnRyeToKICAgIGludGVnZXJfdHlwZXMg
PSAoaW50LCBsb25nKQpleGNlcHQgTmFtZUVycm9yOgogICAgaW50ZWdlcl90eXBlcyA9IChpbnQs
KQoKTUFYX1BPUlRTID0gMTI4Ck1BWF9UQVNLUyA9IDMyCk1BWF9NRVNTQUdFID0gMjU2CkFDVElP
TlMgPSAoImhlYWx0aCIsICJyZWxvYWQiLCAicmVzdGFydCIsICJzdG9wIiwgInN0YXJ0IiwgInNl
dF9wb3J0cyIpCl9TRUNSRVRfUkUgPSByZS5jb21waWxlKHIiKD9pKShiZWFyZXJccytcUyt8YXV0
aG9yaXphdGlvblxzKls6PV1ccypcUyt8cGFzc3dvcmRccypbOj1dXHMqXFMrfHRva2VuXHMqWzo9
XVxzKlxTK3xhcGlbXy1dP2tleVxzKls6PV1ccypcUyt8c2VjcmV0XHMqWzo9XVxzKlxTKykiKQoK
CmRlZiBzYWZlX21lc3NhZ2UodmFsdWUpOgogICAgdGV4dCA9IF9TRUNSRVRfUkUuc3ViKCJbUkVE
QUNURURdIiwgc3RyKHZhbHVlIG9yICIiKSkKICAgIHJldHVybiB0ZXh0WzpNQVhfTUVTU0FHRV0K
CgpkZWYgX3BvcnRzKHZhbHVlKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVlLCBsaXN0KSBv
ciBub3QgdmFsdWUgb3IgbGVuKHZhbHVlKSA+IE1BWF9QT1JUUzoKICAgICAgICByYWlzZSBWYWx1
ZUVycm9yKCJwb3J0cyBtdXN0IGNvbnRhaW4gMS4uMTI4IGludGVnZXJzIikKICAgIHJlc3VsdCA9
IFtdCiAgICBmb3IgcG9ydCBpbiB2YWx1ZToKICAgICAgICBpZiAoaXNpbnN0YW5jZShwb3J0LCBi
b29sKSBvciBub3QgaXNpbnN0YW5jZShwb3J0LCBpbnRlZ2VyX3R5cGVzKSBvciBwb3J0IDwgMSBv
ciBwb3J0ID4gNjU1MzUpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIHRh
cmdldCBwb3J0IikKICAgICAgICBpZiBwb3J0IG5vdCBpbiByZXN1bHQ6CiAgICAgICAgICAgIHJl
c3VsdC5hcHBlbmQocG9ydCkKICAgIHJldHVybiByZXN1bHQKCgpkZWYgX2lmYWNlKHZhbHVlKToK
ICAgIGlmIChpc2luc3RhbmNlKHZhbHVlLCBieXRlX3R5cGVzKSBvciBub3QgaXNpbnN0YW5jZSh2
YWx1ZSwgc3RyaW5nX3R5cGVzKSkgb3Igbm90IHZhbHVlIG9yIGxlbih2YWx1ZSkgPiAzMiBvciAi
LyIgaW4gdmFsdWUgb3IgdmFsdWUgaW4gKCIuIiwgIi4uIik6CiAgICAgICAgcmFpc2UgVmFsdWVF
cnJvcigiaW52YWxpZCBpbnRlcmZhY2UiKQogICAgcmV0dXJuIHZhbHVlCgoKZGVmIHZhbGlkYXRl
X2Rlc2lyZWQoZGF0YSk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShkYXRhLCBkaWN0KToKICAgICAg
ICByYWlzZSBWYWx1ZUVycm9yKCJkZXNpcmVkIHN0YXRlIG11c3QgYmUgYW4gb2JqZWN0IikKICAg
IG91dCA9IHt9CiAgICBpZiAiZ2VuZXJhdGlvbiIgaW4gZGF0YToKICAgICAgICBnZW5lcmF0aW9u
ID0gZGF0YVsiZ2VuZXJhdGlvbiJdCiAgICAgICAgaWYgaXNpbnN0YW5jZShnZW5lcmF0aW9uLCBi
b29sKSBvciBub3QgaXNpbnN0YW5jZShnZW5lcmF0aW9uLCBpbnRlZ2VyX3R5cGVzKSBvciBnZW5l
cmF0aW9uIDwgMDoKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiaW52YWxpZCBnZW5lcmF0
aW9uIikKICAgICAgICBvdXRbImdlbmVyYXRpb24iXSA9IGdlbmVyYXRpb24KICAgIGlmICJwb3J0
cyIgaW4gZGF0YSBhbmQgZGF0YVsicG9ydHMiXSBpcyBub3QgTm9uZToKICAgICAgICBvdXRbInBv
cnRzIl0gPSBfcG9ydHMoZGF0YVsicG9ydHMiXSkKICAgIGlmICJpZmFjZSIgaW4gZGF0YSBhbmQg
ZGF0YVsiaWZhY2UiXSBpcyBub3QgTm9uZToKICAgICAgICBvdXRbImlmYWNlIl0gPSBfaWZhY2Uo
ZGF0YVsiaWZhY2UiXSkKICAgIGlmICJtb2RlIiBpbiBkYXRhIGFuZCBkYXRhWyJtb2RlIl0gaXMg
bm90IE5vbmU6CiAgICAgICAgaWYgZGF0YVsibW9kZSJdICE9ICJweXRob24iOgogICAgICAgICAg
ICByYWlzZSBWYWx1ZUVycm9yKCJvbGRrZXJuZWwgUHl0aG9uIGFnZW50IGFjY2VwdHMgbW9kZT1w
eXRob24gb25seSIpCiAgICAgICAgb3V0WyJtb2RlIl0gPSAicHl0aG9uIgogICAgcmV0dXJuIG91
dAoKCmRlZiB2YWxpZGF0ZV90YXNrKHRhc2ssIG5vZGUpOgogICAgaWYgbm90IGlzaW5zdGFuY2Uo
dGFzaywgZGljdCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigidGFzayBtdXN0IGJlIGFuIG9i
amVjdCIpCiAgICB0YXNrX2lkID0gdGFzay5nZXQoImlkIikKICAgIGlmIHRhc2tfaWQgaXMgTm9u
ZSBvciBpc2luc3RhbmNlKHRhc2tfaWQsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHRhc2tfaWQs
IGludGVnZXJfdHlwZXMpIG9yIHRhc2tfaWQgPCAxOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3Io
ImludmFsaWQgdGFzayBpZCIpCiAgICBhY3Rpb24gPSB0YXNrLmdldCgiYWN0aW9uIikKICAgIGlm
IGFjdGlvbiBub3QgaW4gQUNUSU9OUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJ1bnN1cHBv
cnRlZCBhY3Rpb24iKQogICAgdGFza19ub2RlID0gdGFzay5nZXQoIm5vZGUiLCBub2RlKQogICAg
aWYgdGFza19ub2RlIG5vdCBpbiAobm9kZSwgIioiKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9y
KCJ0YXNrIG5vZGUgbWlzbWF0Y2giKQogICAgaWYgbm90IGlzaW5zdGFuY2Uobm9kZSwgc3RyaW5n
X3R5cGVzKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIG5vZGUiKQogICAgYXJn
cyA9IHRhc2suZ2V0KCJhcmdzIikgb3Ige30KICAgIGlmIG5vdCBpc2luc3RhbmNlKGFyZ3MsIGRp
Y3QpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoInRhc2sgYXJncyBtdXN0IGJlIGFuIG9iamVj
dCIpCiAgICBpZiBhY3Rpb24gPT0gInNldF9wb3J0cyI6CiAgICAgICAgYXJncyA9IHsicG9ydHMi
OiBfcG9ydHMoYXJncy5nZXQoInBvcnRzIikpfQogICAgZWxpZiBhcmdzOgogICAgICAgIHJhaXNl
IFZhbHVlRXJyb3IoInRhc2sgYXJndW1lbnRzIG5vdCBhbGxvd2VkIikKICAgIHJldHVybiB7Imlk
IjogdGFza19pZCwgImFjdGlvbiI6IGFjdGlvbiwgImFyZ3MiOiBhcmdzfQoKCmRlZiB3cml0ZV9z
dGF0ZShwYXRoLCBkZXNpcmVkLCBsYXN0X2FwcGx5KToKICAgIHBhcmVudCA9IG9zLnBhdGguZGly
bmFtZShwYXRoKQogICAgaWYgcGFyZW50IGFuZCBub3Qgb3MucGF0aC5pc2RpcihwYXJlbnQpOgog
ICAgICAgIG9zLm1ha2VkaXJzKHBhcmVudCkKICAgIGRhdGEgPSBkaWN0KGRlc2lyZWQpCiAgICBk
YXRhWyJ1cGRhdGVkX2F0Il0gPSBpbnQodGltZS50aW1lKCkpCiAgICBkYXRhWyJsYXN0X2FwcGx5
Il0gPSBzYWZlX21lc3NhZ2UobGFzdF9hcHBseSkKICAgIHRtcCA9IHBhdGggKyAiLnRtcCIKICAg
IGYgPSBvcGVuKHRtcCwgInciKQogICAgdHJ5OgogICAgICAgIGpzb24uZHVtcChkYXRhLCBmLCBz
b3J0X2tleXM9VHJ1ZSkKICAgICAgICBmLmZsdXNoKCkKICAgICAgICB0cnk6CiAgICAgICAgICAg
IG9zLmZzeW5jKGYuZmlsZW5vKCkpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAg
IHBhc3MKICAgIGZpbmFsbHk6CiAgICAgICAgZi5jbG9zZSgpCiAgICB0cnk6CiAgICAgICAgb3Mu
Y2htb2QodG1wLCBpbnQoIjYwMCIsIDgpKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcGFz
cwogICAgb3MucmVuYW1lKHRtcCwgcGF0aCkKCgpkZWYgYXBwbHlfdGFzayh0YXNrLCBub2RlLCBz
dGF0ZV9wYXRoLCByZXN0YXJ0LCBzdG9wKToKICAgIHRhc2sgPSB2YWxpZGF0ZV90YXNrKHRhc2ss
IG5vZGUpCiAgICBhY3Rpb24gPSB0YXNrWyJhY3Rpb24iXQogICAgaWYgYWN0aW9uID09ICJoZWFs
dGgiOgogICAgICAgIHJldHVybiAiaGVhbHRoeSIKICAgIGlmIGFjdGlvbiA9PSAic3RvcCI6CiAg
ICAgICAgc3RvcCgpCiAgICAgICAgcmV0dXJuICJhZ2VudCBzdG9wIHJlcXVlc3RlZCIKICAgIGlm
IGFjdGlvbiBpbiAoInJlbG9hZCIsICJyZXN0YXJ0IiwgInN0YXJ0Iik6CiAgICAgICAgcmVzdGFy
dCgpCiAgICAgICAgcmV0dXJuICJhZ2VudCByZXN0YXJ0IHJlcXVlc3RlZCIKICAgIGRlc2lyZWQg
PSB7InBvcnRzIjogdGFza1siYXJncyJdWyJwb3J0cyJdLCAibW9kZSI6ICJweXRob24ifQogICAg
d3JpdGVfc3RhdGUoc3RhdGVfcGF0aCwgZGVzaXJlZCwgInJlc3RhcnQgcmVxdWVzdGVkIikKICAg
IHJlc3RhcnQoKQogICAgcmV0dXJuICJ0YXJnZXQgcG9ydHMgd3JpdHRlbjsgcmVzdGFydCByZXF1
ZXN0ZWQiCgoKY2xhc3MgQ29udHJvbENsaWVudChvYmplY3QpOgogICAgZGVmIF9faW5pdF9fKHNl
bGYsIGVuZHBvaW50LCB0b2tlbiwgbm9kZSwgdGltZW91dD0xMCk6CiAgICAgICAgaWYgbm90IHRv
a2VuOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJjb250cm9sIHRva2VuIHJlcXVpcmVk
IikKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShub2RlLCBzdHJpbmdfdHlwZXMpIG9yIG5vdCBu
b2RlIG9yIGxlbihub2RlKSA+IDEyODoKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiaW52
YWxpZCBub2RlIikKICAgICAgICBzZWxmLmVuZHBvaW50ID0gZW5kcG9pbnQucnN0cmlwKCIvIikK
ICAgICAgICBzZWxmLnRva2VuID0gdG9rZW4KICAgICAgICBzZWxmLm5vZGUgPSBub2RlCiAgICAg
ICAgc2VsZi50aW1lb3V0ID0gbWF4KDEsIG1pbihpbnQodGltZW91dCksIDMwKSkKCiAgICBkZWYg
X3JlcXVlc3Qoc2VsZiwgbWV0aG9kLCBwYXRoLCBwYXlsb2FkPU5vbmUpOgogICAgICAgIHVybCA9
IHNlbGYuZW5kcG9pbnQgKyBwYXRoCiAgICAgICAgYm9keSA9IE5vbmUKICAgICAgICBoZWFkZXJz
ID0geyJBdXRob3JpemF0aW9uIjogIkJlYXJlciAiICsgc2VsZi50b2tlbn0KICAgICAgICBpZiBw
YXlsb2FkIGlzIG5vdCBOb25lOgogICAgICAgICAgICBib2R5ID0ganNvbi5kdW1wcyhwYXlsb2Fk
KQogICAgICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShib2R5LCBieXRlcyk6CiAgICAgICAgICAg
ICAgICBib2R5ID0gYm9keS5lbmNvZGUoInV0Zi04IikKICAgICAgICAgICAgaGVhZGVyc1siQ29u
dGVudC1UeXBlIl0gPSAiYXBwbGljYXRpb24vanNvbiIKICAgICAgICByZXF1ZXN0ID0gdXJsbGli
Mi5SZXF1ZXN0KHVybCwgYm9keSwgaGVhZGVycykKICAgICAgICBpZiBtZXRob2QgIT0gIlBPU1Qi
OgogICAgICAgICAgICByZXF1ZXN0LmdldF9tZXRob2QgPSBsYW1iZGE6IG1ldGhvZAogICAgICAg
IHRyeToKICAgICAgICAgICAgcmVzcG9uc2UgPSB1cmxsaWIyLnVybG9wZW4ocmVxdWVzdCwgdGlt
ZW91dD1zZWxmLnRpbWVvdXQpCiAgICAgICAgICAgIHJhdyA9IHJlc3BvbnNlLnJlYWQoKQogICAg
ICAgICAgICByZXR1cm4ganNvbi5sb2FkcyhyYXcpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoK
ICAgICAgICAgICAgcmV0dXJuIE5vbmUKCiAgICBkZWYgcG9sbChzZWxmKToKICAgICAgICByZXBs
eSA9IHNlbGYuX3JlcXVlc3QoIkdFVCIsICIvYXBpL2NvbnRyb2wvcG9sbC8iICsgcXVvdGUoc2Vs
Zi5ub2RlLCBzYWZlPSIiKSkKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShyZXBseSwgZGljdCk6
CiAgICAgICAgICAgIHJldHVybiBOb25lCiAgICAgICAgZGVzaXJlZCA9IHZhbGlkYXRlX2Rlc2ly
ZWQocmVwbHkuZ2V0KCJkZXNpcmVkIikgb3Ige30pCiAgICAgICAgdGFza3MgPSByZXBseS5nZXQo
InRhc2tzIikgb3IgW10KICAgICAgICBpZiBub3QgaXNpbnN0YW5jZSh0YXNrcywgbGlzdCkgb3Ig
bGVuKHRhc2tzKSA+IE1BWF9UQVNLUzoKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiaW52
YWxpZCB0YXNrIGxpc3QiKQogICAgICAgIHJldHVybiB7ImRlc2lyZWQiOiBkZXNpcmVkLAogICAg
ICAgICAgICAgICAgInRhc2tzIjogW3ZhbGlkYXRlX3Rhc2soaXRlbSwgc2VsZi5ub2RlKSBmb3Ig
aXRlbSBpbiB0YXNrc119CgogICAgZGVmIHJlcG9ydChzZWxmLCB0YXNrX2lkLCBzdGF0dXMsIG1l
c3NhZ2UpOgogICAgICAgIGlmIHN0YXR1cyBub3QgaW4gKCJkb25lIiwgImZhaWxlZCIpOgogICAg
ICAgICAgICBzdGF0dXMgPSAiZmFpbGVkIgogICAgICAgIHJldHVybiBzZWxmLl9yZXF1ZXN0KCJQ
T1NUIiwgIi9hcGkvY29udHJvbC90YXNrcy8lZC9yZXN1bHQiICUgaW50KHRhc2tfaWQpLCB7CiAg
ICAgICAgICAgICJub2RlIjogc2VsZi5ub2RlLCAic3RhdHVzIjogc3RhdHVzLCAibWVzc2FnZSI6
IHNhZmVfbWVzc2FnZShtZXNzYWdlKX0pCgogICAgZGVmIGhlYXJ0YmVhdChzZWxmLCBnZW5lcmF0
aW9uLCBhcHBsaWVkKToKICAgICAgICByZXR1cm4gc2VsZi5fcmVxdWVzdCgiUE9TVCIsICIvYXBp
L2NvbnRyb2wvaGVhcnRiZWF0IiwgewogICAgICAgICAgICAibm9kZSI6IHNlbGYubm9kZSwgImdl
bmVyYXRpb24iOiBnZW5lcmF0aW9uLAogICAgICAgICAgICAiYXBwbGllZCI6IHNhZmVfbWVzc2Fn
ZShhcHBsaWVkKX0pCg==
#__END_CONTROL__
#__CONTROL_RUN_B64__
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMgLSotIGNvZGluZzogdXRmLTggLSotCiIiIlJ1biB0aGUg
b2xka2VybmVsIFB5dGhvbiBjb250cm9sIGNsaWVudCBhcyBhIGJvdW5kZWQgU3lzViBjaGlsZC4K
ClRoZSBwYXJlbnQvc2VydmljZSB3cmFwcGVyIG93bnMgY2FwdHVyZSByZXN0YXJ0LiBUaGlzIHBy
b2Nlc3Mgb25seSBwb2xscyBodWIsCnVwZGF0ZXMgZGVzaXJlZCBzdGF0ZSwgYW5kIHJlcG9ydHMg
dGFza3M7IGl0IG5ldmVyIGV4ZWN1dGVzIGh1Yi1wcm92aWRlZCBzaGVsbC4KIiIiCmZyb20gX19m
dXR1cmVfXyBpbXBvcnQgcHJpbnRfZnVuY3Rpb24KCmltcG9ydCBqc29uCmltcG9ydCBvcwppbXBv
cnQgc2lnbmFsCmltcG9ydCBzeXMKaW1wb3J0IHRpbWUKCkhFUkUgPSBvcy5wYXRoLmRpcm5hbWUo
b3MucGF0aC5hYnNwYXRoKF9fZmlsZV9fKSkKc3lzLnBhdGguaW5zZXJ0KDAsIEhFUkUpCmltcG9y
dCBudF9jb250cm9sCgpydW5uaW5nID0gW1RydWVdCgpkZWYgc3RvcChzaWdudW0sIGZyYW1lKToK
ICAgIHJ1bm5pbmdbMF0gPSBGYWxzZQoKZGVmIG1haW4oKToKICAgIGVuZHBvaW50ID0gb3MuZW52
aXJvbi5nZXQoIk5UX0NPTlRST0xfRU5EUE9JTlQiKSBvciBvcy5lbnZpcm9uLmdldCgiTlRfRU5E
UE9JTlQiKQogICAgdG9rZW4gPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTiIsICIi
KQogICAgbm9kZSA9IG9zLmVudmlyb24uZ2V0KCJOVF9OT0RFX05BTUUiKSBvciBvcy5lbnZpcm9u
LmdldCgiTlRfTk9ERSIpCiAgICBydW5fZGlyID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xf
UlVOIiwgIi92YXIvbGliL25ldHdvcmt0cmFjaW5nIikKICAgIGludGVydmFsID0gaW50KG9zLmVu
dmlyb24uZ2V0KCJOVF9DT05UUk9MX1NFQyIsICIzMCIpKQogICAgaW50ZXJ2YWwgPSBtYXgoNSwg
bWluKGludGVydmFsLCAzMDApKQogICAgaWYgbm90IGVuZHBvaW50IG9yIG5vdCB0b2tlbiBvciBu
b3Qgbm9kZToKICAgICAgICBwcmludCgibnQtY29udHJvbDogZW5kcG9pbnQsIHRva2VuLCBhbmQg
bm9kZSBhcmUgcmVxdWlyZWQiLCBmaWxlPXN5cy5zdGRlcnIpCiAgICAgICAgcmV0dXJuIDIKICAg
IGNsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRwb2ludCwgdG9rZW4sIG5vZGUp
CiAgICBzdGF0ZV9wYXRoID0gb3MucGF0aC5qb2luKHJ1bl9kaXIsICJyZW1vdGUtZGVzaXJlZC5q
c29uIikKICAgIGxhc3RfZ2VuZXJhdGlvbiA9IC0xCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5T
SUdURVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9wKQogICAg
d2hpbGUgcnVubmluZ1swXToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJlcGx5ID0gY2xpZW50
LnBvbGwoKQogICAgICAgICAgICBpZiByZXBseSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAg
IGRlc2lyZWQgPSByZXBseS5nZXQoImRlc2lyZWQiLCB7fSkKICAgICAgICAgICAgICAgIGdlbmVy
YXRpb24gPSBkZXNpcmVkLmdldCgiZ2VuZXJhdGlvbiIsIDApCiAgICAgICAgICAgICAgICBpZiBn
ZW5lcmF0aW9uICE9IGxhc3RfZ2VuZXJhdGlvbjoKICAgICAgICAgICAgICAgICAgICBudF9jb250
cm9sLndyaXRlX3N0YXRlKHN0YXRlX3BhdGgsIGRlc2lyZWQsICJyZXN0YXJ0IHJlcXVpcmVkIikK
ICAgICAgICAgICAgICAgICAgICBsYXN0X2dlbmVyYXRpb24gPSBnZW5lcmF0aW9uCiAgICAgICAg
ICAgICAgICAgICAgY2xpZW50LmhlYXJ0YmVhdChnZW5lcmF0aW9uLCAicmVzdGFydCByZXF1aXJl
ZCIpCiAgICAgICAgICAgICAgICBmb3IgdGFzayBpbiByZXBseS5nZXQoInRhc2tzIiwgW10pOgog
ICAgICAgICAgICAgICAgICAgICMgVGhlIHNlcnZpY2Ugd3JhcHBlciBjYW4gd2F0Y2ggdGhpcyBi
b3VuZGVkIHJlcXVlc3QgbWFya2VyLgogICAgICAgICAgICAgICAgICAgIG1hcmtlciA9IG9zLnBh
dGguam9pbihydW5fZGlyLCAicmVtb3RlLXRhc2stJWQuanNvbiIgJSB0YXNrWyJpZCJdKQogICAg
ICAgICAgICAgICAgICAgIG50X2NvbnRyb2wud3JpdGVfc3RhdGUobWFya2VyLCB0YXNrLCAicXVl
dWVkIikKICAgICAgICAgICAgICAgICAgICBjbGllbnQucmVwb3J0KHRhc2tbImlkIl0sICJkb25l
IiwgInRhc2sgYWNjZXB0ZWQ7IHNlcnZpY2Ugd3JhcHBlciBhY3Rpb24gcmVxdWlyZWQiKQogICAg
ICAgICAgICAgICAgY2xpZW50LmhlYXJ0YmVhdChsYXN0X2dlbmVyYXRpb24sICJwb2xsIG9rIikK
ICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgcHJpbnQoIm50LWNv
bnRyb2w6IHBvbGwgZmFpbGVkOiAlcyIgJSBudF9jb250cm9sLnNhZmVfbWVzc2FnZShleGMpLCBm
aWxlPXN5cy5zdGRlcnIpCiAgICAgICAgZm9yIHVudXNlZCBpbiByYW5nZShpbnRlcnZhbCk6CiAg
ICAgICAgICAgIGlmIG5vdCBydW5uaW5nWzBdOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAg
ICAgICAgdGltZS5zbGVlcCgxKQogICAgcmV0dXJuIDAKCmlmIF9fbmFtZV9fID09ICJfX21haW5f
XyI6CiAgICBzeXMuZXhpdChtYWluKCkpCg==
#__END_CONTROL_RUN__
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
ID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmluZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6c3Ry
aW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwg
IkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIHNpemVfdCBiZXN0
ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCA3OyArK2kpIHsK
ICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7CiAgICBpZiAocG9zICE9IHN0ZDo6c3RyaW5n
OjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHBvcyA8IGJlc3QpKSBiZXN0
ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChj
b25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9k
ZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAgICAg
ICAgICAgICBzdGQ6Om1hcDxzdGQ6OnN0cmluZywgRmxvdz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNr
ZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBpZiAobiA8IDM0KSBy
ZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRv
aHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyAxMikpOwogIGlmIChldCA9PSBFVEhf
UF84MDIxUSkgeyBpZiAobiA8IDM4KSByZXR1cm4gZmFsc2U7IGV0ID0gbnRvaHMoKihjb25zdCB1
bnNpZ25lZCBzaG9ydCAqKShidWYgKyAxNikpOyBvZmYgPSAxODsgfQogIGlmIChldCAhPSBFVEhf
UF9JUCB8fCBuIDwgb2ZmICsgMjApIHJldHVybiBmYWxzZTsKICB1bnNpZ25lZCBjaGFyIGlobCA9
ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAqIDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0
KSAhPSA0IHx8IGJ1ZltvZmYgKyA5XSAhPSA2IHx8IG4gPCBvZmYgKyBpaGwgKyAyMCkgcmV0dXJu
IGZhbHNlOwogIGNoYXIgYVtJTkVUX0FERFJTVFJMRU5dLCBiW0lORVRfQUREUlNUUkxFTl07IGlu
ZXRfbnRvcChBRl9JTkVULCBidWYgKyBvZmYgKyAxMiwgYSwgc2l6ZW9mKGEpKTsgaW5ldF9udG9w
KEFGX0lORVQsIGJ1ZiArIG9mZiArIDE2LCBiLCBzaXplb2YoYikpOwogIHNpemVfdCB0byA9IG9m
ZiArIGlobDsgdW5zaWduZWQgc3BvcnQgPSBudG9ocygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICop
KGJ1ZiArIHRvKSk7IHVuc2lnbmVkIGRwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9y
dCAqKShidWYgKyB0byArIDIpKTsgdW5zaWduZWQgZG9mZiA9IChidWZbdG8gKyAxMl0gPj4gNCkg
KiA0OyBpZiAobiA8IHRvICsgZG9mZikgcmV0dXJuIGZhbHNlOyBjb25zdCBjaGFyICpwYXlsb2Fk
ID0gKGNvbnN0IGNoYXIgKikoYnVmICsgdG8gKyBkb2ZmKTsgc2l6ZV90IHBsZW4gPSBuIC0gdG8g
LSBkb2ZmOyBpZiAoIXBsZW4pIHJldHVybiBmYWxzZTsKICB0aW1lX3Qgbm93ID0gdGltZShOVUxM
KTsKICBib29sIGRzdF9tb24gPSBmYWxzZSwgc3JjX21vbiA9IGZhbHNlOwogIHNpemVfdCBqOwog
IGZvciAoaiA9IDA7IGogPCBwb3J0cy5zaXplKCk7ICsraikgewogICAgaWYgKGRwb3J0ID09IHBv
cnRzW2pdKSBkc3RfbW9uID0gdHJ1ZTsKICAgIGlmIChzcG9ydCA9PSBwb3J0c1tqXSkgc3JjX21v
biA9IHRydWU7CiAgfQogIGlmIChzcmNfbW9uICYmICFkc3RfbW9uICYmIHBsZW4gPj0gNSkgewog
ICAgc3RkOjpzdHJpbmcgc19wYXkocGF5bG9hZCwgcGxlbik7CiAgICBzaXplX3QgaHBvcyA9IHNf
cGF5LmZpbmQoIkhUVFAvIik7CiAgICBpZiAoaHBvcyAhPSBzdGQ6OnN0cmluZzo6bnBvcykgewog
ICAgICBQYWNrZXRLZXkgazsKICAgICAgay5zcmMgPSBhOyBrLnNwb3J0ID0gc3BvcnQ7IGsuZHN0
ID0gYjsgay5kcG9ydCA9IGRwb3J0OwogICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVj
dG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHAgPSBwZW5kaW5nLmZpbmQoayk7CiAgICAgIGlmIChw
ICE9IHBlbmRpbmcuZW5kKCkgJiYgIXAtPnNlY29uZC5lbXB0eSgpKSB7CiAgICAgICAgaW50IHN0
OyB1bnNpZ25lZCBjbDsKICAgICAgICBpZiAocGFyc2VfcmVzcG9uc2Uoc19wYXkuc3Vic3RyKGhw
b3MpLCAmc3QsICZjbCkpIHsKICAgICAgICAgIEV2ZW50IGUgPSBwLT5zZWNvbmRbMF0uZXY7CiAg
ICAgICAgICBlLnN0YXR1cyA9IHN0OyBlLmhhc19zdGF0dXMgPSB0cnVlOwogICAgICAgICAgZS5k
dXJhdGlvbl9tcyA9IChsb25nKShub3dfbXMoKSAtIHAtPnNlY29uZFswXS5zdGFydGVkX21zKTsK
ICAgICAgICAgIGlmIChlLmR1cmF0aW9uX21zIDwgMCkgZS5kdXJhdGlvbl9tcyA9IDA7CiAgICAg
ICAgICBlLmhhc19kdXJhdGlvbiA9IHRydWU7CiAgICAgICAgICBpZiAoY2wpIHsgZS5yZXNwX2J5
dGVzID0gY2w7IGUuaGFzX3Jlc3AgPSB0cnVlOyB9CiAgICAgICAgICBlbWl0X2V2ZW50KGUpOwog
ICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgIGlm
IChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICB9CiAgICAgIH0K
ICAgIH0KICAgIHJldHVybiB0cnVlOwogIH0KICBpZiAoIWRzdF9tb24pIHJldHVybiBmYWxzZTsK
ICBzdGQ6OnN0cmluZyBmayA9IGtleV9zdHJpbmcoYSwgc3BvcnQsIGIsIGRwb3J0KTsgRmxvdyAm
ZmwgPSBmbG93c1tma107IGZsLnRvdWNoZWQgPSBub3c7IGZsLmJ1Zi5hcHBlbmQocGF5bG9hZCwg
cGxlbik7CiAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSKSB7IGZsb3dzLmVyYXNlKGZr
KTsgcmV0dXJuIGZhbHNlOyB9CiAgd2hpbGUgKHRydWUpIHsKICAgIHNpemVfdCBzdGFydCA9IGZp
bmRfaHR0cF9zdGFydChmbC5idWYpOwogICAgaWYgKHN0YXJ0ID09IHN0ZDo6c3RyaW5nOjpucG9z
KSB7IGZsLmJ1Zi5jbGVhcigpOyBicmVhazsgfQogICAgaWYgKHN0YXJ0ID4gMCkgZmwuYnVmLmVy
YXNlKDAsIHN0YXJ0KTsKICAgIHNpemVfdCBlbmQgPSBmbC5idWYuZmluZCgiXHJcblxyXG4iKTsK
ICAgIGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgRXZlbnQgZTsgZS50
cyA9IG5vdzsgZS5ob3N0ID0gbm9kZTsgZS5zZXJ2aWNlID0gInBvcnQ6IiArIG51bShkcG9ydCk7
IGUuY2FsbGVyID0gYTsgZS5jYWxsZXJfcG9ydCA9IHNwb3J0OyBlLmRzdF9pcCA9IGI7IGUuZHN0
X3BvcnQgPSBkcG9ydDsgZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQpKGVuZCArIDQpOwogICAgaWYg
KCFwYXJzZV9yZXF1ZXN0KGZsLmJ1Zi5zdWJzdHIoMCwgZW5kKSwgJmUpKSB7IGZsLmJ1Zi5lcmFz
ZSgwLCBlbmQgKyA0KTsgY29udGludWU7IH0KICAgIGZsLmJ1Zi5lcmFzZSgwLCBlbmQgKyA0KTsK
ICAgIFBhY2tldEtleSByazsgcmsuc3JjID0gYjsgcmsuc3BvcnQgPSBkcG9ydDsgcmsuZHN0ID0g
YTsgcmsuZHBvcnQgPSBzcG9ydDsKICAgIGlmIChwZW5kaW5nLnNpemUoKSA+PSBNQVhfUEVORElO
RykgZmx1c2hfb2xkZXN0KHBlbmRpbmcpOwogICAgcGVuZGluZ1tya10ucHVzaF9iYWNrKFBlbmRp
bmcoZSwgbm93X21zKCkpKTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIGF0dGFj
aF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgLyog
QlBGIGlzIG9wdGlvbmFsIGF0IHN0YXJ0dXA6IHRoZSBwYXJzZXIgc3RpbGwgcGVyZm9ybXMgdGhl
IHNhbWUgY2hlY2tzCiAgICAgYWZ0ZXIgYmluZC4gVGhpcyBrZWVwcyB0aGUgYmluYXJ5IHVzYWJs
ZSBvbiBrZXJuZWxzIHJlamVjdGluZyB0aGUKICAgICBnZW5lcmF0ZWQgZmlsdGVyLCB3aGlsZSBs
b2dnaW5nIHRoZSBkZWdyYWRlZCBtb2RlLiAqLwogIHN0ZDo6dmVjdG9yPHN0cnVjdCBzb2NrX2Zp
bHRlcj4gZjsgc2l6ZV90IGk7IHVuc2lnbmVkIHJlamVjdCA9IDAsIGFjY2VwdDsKICAvKiBFdGhl
cm5ldCBJUHY0LCBUQ1AsIHRoZW4gZGVzdGluYXRpb24gT1Igc291cmNlIG1vbml0b3JlZCBwb3J0
LiAqLwogIHJlamVjdCA9IDQgKyAodW5zaWduZWQpcG9ydHMuc2l6ZSgpICogNCArIDE7IGFjY2Vw
dCA9IHJlamVjdCArIDE7CiAgc3RydWN0IHNvY2tfZmlsdGVyIHg7CiNkZWZpbmUgQUREKEMsSixU
LEspIGRvIHsgeC5jb2RlPShDKTsgeC5qdD0oSik7IHguamY9KFQpOyB4Lms9KEspOyBmLnB1c2hf
YmFjayh4KTsgfSB3aGlsZSgwKQogIEFERChCUEZfTER8QlBGX0h8QlBGX0FCUywwLDAsMTIpOyBB
REQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLDAscmVqZWN0LTIsRVRIX1BfSVBfSE9TVCk7CiAgQURE
KEJQRl9MRHxCUEZfQnxCUEZfQUJTLDAsMCwyMyk7IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ss
MCxyZWplY3QtNCxJUFBST1RPX1RDUCk7CiAgQUREKEJQRl9MRHxCUEZfQnxCUEZfTVNILDAsMCwx
NCk7CiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xE
fEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE2KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVu
c2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gMDsKICAgIEFERChCUEZfSk1Q
fEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KICBmb3IgKGkgPSAwOyBpIDwg
cG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwg
MTQpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwog
ICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAo
dW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0
LCBqZiwgcG9ydHNbaV0pOwogIH0KICBBREQoQlBGX1JFVHxCUEZfSywwLDAsMCk7IEFERChCUEZf
UkVUfEJQRl9LLDAsMCxBQ0NFUFQpOwojdW5kZWYgQURECiAgaWYgKGYuc2l6ZSgpID4gNDA5Nikg
cmV0dXJuIGZhbHNlOwogIHN0cnVjdCBzb2NrX2Zwcm9nIHByb2c7IHByb2cubGVuID0gKHVuc2ln
bmVkIHNob3J0KWYuc2l6ZSgpOyBwcm9nLmZpbHRlciA9ICZmWzBdOyByZXR1cm4gc2V0c29ja29w
dChmZCwgU09MX1NPQ0tFVCwgU09fQVRUQUNIX0ZJTFRFUl9PTEQsICZwcm9nLCBzaXplb2YocHJv
ZykpID09IDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2ZpeHR1cmUoKSB7CiAgc3RkOjpzdHJpbmcgcmVx
ID0gIkdFVCAvYXBpL2l0ZW1zP3g9MSBIVFRQLzEuMVxyXG5Ib3N0OiBhcGkubG9jYWxcclxuQXV0
aG9yaXphdGlvbjogQmFzaWMgWVd4cFkyVTZjMlZqY21WMFxyXG5UcmFjZXBhcmVudDogMDAtMDEy
MzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYtMDEyMzQ1Njc4OWFiY2RlZi0wMVxyXG5cclxu
IjsKICBFdmVudCBlOyBlLnRzID0gMTcwMDAwMDAwMDsgZS5ob3N0ID0gImNwcC1ub2RlIjsgZS5z
ZXJ2aWNlID0gInBvcnQ6ODA4MCI7IGUuY2FsbGVyID0gIjEwLjAuMC45IjsgZS5jYWxsZXJfcG9y
dCA9IDUxMDAwOyBlLmRzdF9pcCA9ICIxMC4wLjAuMiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBlLnJl
cV9ieXRlcyA9ICh1bnNpZ25lZClyZXEuc2l6ZSgpOyBwYXJzZV9yZXF1ZXN0KHJlcS5zdWJzdHIo
MCwgcmVxLnNpemUoKSAtIDQpLCAmZSk7IGUuc3RhdHVzID0gMjAwOyBlLmhhc19zdGF0dXMgPSB0
cnVlOyBlLmR1cmF0aW9uX21zID0gMzsgZS5oYXNfZHVyYXRpb24gPSB0cnVlOyBlLnJlc3BfYnl0
ZXMgPSA0MjsgZS5oYXNfcmVzcCA9IHRydWU7IGVtaXRfZXZlbnQoZSk7IHJldHVybiAwOwp9Cmlu
dCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikgewogIGlmIChhcmdjID4gMSAmJiAhc3RyY21w
KGFyZ3ZbMV0sICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7CiAgc3RkOjpzdHJp
bmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0czsgaW50IGk7IGludCB3b3JrZXJz
ID0gMTsKICBmb3IgKGkgPSAxOyBpIDwgYXJnYzsgKytpKSB7CiAgICBpZiAoIXN0cmNtcChhcmd2
W2ldLCAiLWkiKSAmJiBpICsgMSA8IGFyZ2MpIGlmYWNlID0gYXJndlsrK2ldOwogICAgZWxzZSBp
ZiAoIXN0cmNtcChhcmd2W2ldLCAiLXAiKSAmJiBpICsgMSA8IGFyZ2MpIHsKICAgICAgd2hpbGUg
KGkgKyAxIDwgYXJnYyAmJiBhcmd2W2kgKyAxXVswXSAhPSAnLScpIHsKICAgICAgICBjaGFyICpx
ID0gc3RydG9rKGFyZ3ZbKytpXSwgIiwgIik7CiAgICAgICAgd2hpbGUgKHEpIHsgbG9uZyBwID0g
YXRvbChxKTsgaWYgKHZhbGlkX3BvcnQoKHVuc2lnbmVkKXApKSBwb3J0cy5wdXNoX2JhY2soKHVu
c2lnbmVkKXApOyBxID0gc3RydG9rKE5VTEwsICIsICIpOyB9CiAgICAgIH0KICAgIH0KICAgIGVs
c2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1qIikgJiYgaSArIDEgPCBhcmdjKSB3b3JrZXJzID0g
YXRvaShhcmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWgiKSkgeyBm
cHJpbnRmKHN0ZGVyciwgInVzYWdlOiBudC1zbmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAgcG9ydHNd
IFstaiB3b3JrZXJzXVxuIik7IHJldHVybiAwOyB9CiAgfQogIGlmIChwb3J0cy5lbXB0eSgpKSB7
IHBvcnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9ydHMucHVzaF9i
YWNrKDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFjayg4MDA5KTsg
cG9ydHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0KICAodm9pZCl3
b3JrZXJzOyBzdGQ6OnN0cmluZyBub2RlID0gaG9zdF9uYW1lKCk7IGludCBmZCA9IHNvY2tldChB
Rl9QQUNLRVQsIFNPQ0tfUkFXLCBodG9ucygzKSk7IGlmIChmZCA8IDApIHsgcGVycm9yKCJBRl9Q
QUNLRVQiKTsgcmV0dXJuIDI7IH0KICBpbnQgcmIgPSA4ICogMTAyNCAqIDEwMjQ7CiAgc2V0c29j
a29wdChmZCwgU09MX1NPQ0tFVCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihyYikpOwogIGlmICgh
YXR0YWNoX2JwZihmZCwgcG9ydHMpKSBsb2dtc2coIldBUk46IEJQRiBhdHRhY2ggZmFpbGVkOyBj
b250aW51aW5nIHVuZmlsdGVyZWQiKTsKICBzdHJ1Y3Qgc29ja2FkZHJfbGwgc2E7IG1lbXNldCgm
c2EsIDAsIHNpemVvZihzYSkpOyBzYS5zbGxfZmFtaWx5ID0gQUZfUEFDS0VUOyBzYS5zbGxfcHJv
dG9jb2wgPSBodG9ucygzKTsgaWYgKCFpZmFjZS5lbXB0eSgpKSB7IHNhLnNsbF9pZmluZGV4ID0g
KGludClpZl9uYW1ldG9pbmRleChpZmFjZS5jX3N0cigpKTsgaWYgKCFzYS5zbGxfaWZpbmRleCkg
eyBsb2dtc2coImJhZCBpbnRlcmZhY2UiKTsgY2xvc2UoZmQpOyByZXR1cm4gMjsgfSB9IGlmIChi
aW5kKGZkLCAoc3RydWN0IHNvY2thZGRyICopJnNhLCBzaXplb2Yoc2EpKSA8IDApIHsgcGVycm9y
KCJiaW5kIik7IGNsb3NlKGZkKTsgcmV0dXJuIDI7IH0KICBzaWduYWwoU0lHVEVSTSwgc3RvcF9z
aWduYWwpOwogIHNpZ25hbChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsKICBzdGQ6Om1hcDxzdGQ6OnN0
cmluZywgRmxvdz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5k
aW5nPiA+IHBlbmRpbmc7CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKICB0aW1lX3QgbGFzdCA9IHRp
bWUoTlVMTCk7CiAgdW5zaWduZWQgY2hhciAqYnVmID0gKHVuc2lnbmVkIGNoYXIgKiltYWxsb2Mo
NjU1MzYpOwogIGlmICghYnVmKSB7CiAgICBjbG9zZShmZCk7CiAgICBsb2dtc2coImJ1ZmZlciBh
bGxvY2F0aW9uIGZhaWxlZCIpOwogICAgcmV0dXJuIDI7CiAgfQogIHdoaWxlIChnX3J1bm5pbmcp
IHsKICAgIGZkX3NldCByOwogICAgRkRfWkVSTygmcik7CiAgICBGRF9TRVQoZmQsICZyKTsKICAg
IHN0cnVjdCB0aW1ldmFsIHR2OwogICAgdHYudHZfc2VjID0gMTsKICAgIHR2LnR2X3VzZWMgPSAw
OwogICAgaW50IHJjID0gc2VsZWN0KGZkICsgMSwgJnIsIE5VTEwsIE5VTEwsICZ0dik7CiAgICBp
ZiAocmMgPiAwICYmIEZEX0lTU0VUKGZkLCAmcikpIHsKICAgICAgc3NpemVfdCBuID0gcmVjdihm
ZCwgYnVmLCA2NTUzNiwgMCk7CiAgICAgIGlmIChuID4gMCkgaGFuZGxlX3BhY2tldChidWYsIChz
aXplX3Qpbiwgbm9kZSwgcG9ydHMsIGZsb3dzLCBwZW5kaW5nKTsKICAgIH0KICAgIHRpbWVfdCBu
b3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAtIGxhc3QgPj0gMSkgewogICAgICBzd2VlcChm
bG93cywgcGVuZGluZywgbm93KTsKICAgICAgbGFzdCA9IG5vdzsKICAgIH0KICB9CiAgZnJlZShi
dWYpOyBjbG9zZShmZCk7IGxvZ21zZygic3RvcHBlZCIpOyByZXR1cm4gMDsKfQo=
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
