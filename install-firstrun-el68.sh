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
CAPTURE_MODE="${NT_CAPTURE_MODE:-python}"

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --hub)      KIT_URLS="$2"; shift 2 ;;
        --mode)     CAPTURE_MODE="$2"; shift 2 ;;
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
    WORKDIR=$(mktemp -d /tmp/ntkit.XXXXXX 2>/dev/null || mktemp -d -t 'ntkit')
    [ -d "$WORKDIR" ] || die "cannot create temporary workdir"

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
    PYBIN=""
    for c in python python2 python3; do
        if have "$c"; then PYBIN=$(command -v "$c"); break; fi
    done
    if [ "$CAPTURE_MODE" != "cpp" ]; then
        [ -n "$PYBIN" ] || die "python (2.6+) missing on target node — pass --mode cpp if g++ is available"
        "$PYBIN" -m py_compile "$WORKDIR/nt-sniff.py" 2>/dev/null \
            || die "nt-sniff.py does not compile under node python"
        "$PYBIN" -m py_compile "$WORKDIR/nt-ship.py" 2>/dev/null \
            || die "nt-ship.py does not compile under node python"
    fi
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
    rm -f "$CONTROL_TOKEN_FILE" /var/run/networktracing-legacy.pid
    rm -rf "$PREFIX" /tmp/ntkit*
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
if [ "$CAPTURE_MODE" = "cpp" ]; then
    have g++ || die "--mode cpp requires g++ on target node"
else
    PYBIN=""
    for c in python python2 python3; do
        if have "$c"; then PYBIN=$(command -v "$c"); break; fi
    done
    [ -n "$PYBIN" ] || die "python (2.6+) required on target node"
    "$PYBIN" -c 'import sys; assert sys.version_info >= (2,6)' 2>/dev/null \
        || die "python 2.6+ required on target node"
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
# Stop existing service and terminate any old running processes
[ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1 || true
for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-ship-cpp"; do
    for p in $(pgrep -f "$pattern" 2>/dev/null || true); do
        [ "$p" = "$$" ] || kill -9 "$p" 2>/dev/null || true
    done
done
rm -f "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship-cpp"

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

# privilege model: copy the interpreter or native binary, grant IT cap_net_raw
SNIFF_AS=root
PYBIN=""
for c in python python2 python3; do
    if have "$c"; then PYBIN=$(command -v "$c"); break; fi
done
if have setcap && have useradd; then
    id "$SNIFF_USER" >/dev/null 2>&1 || useradd -r -s /sbin/nologin "$SNIFF_USER" 2>/dev/null || true
    if [ "$CAPTURE_MODE" != "cpp" ] && [ -n "$PYBIN" ]; then
        cp "$PYBIN" "$PREFIX/python-capnetraw" 2>/dev/null || true
        # NOTE: chown BEFORE setcap — chown clears file capabilities
        if [ -f "$PREFIX/python-capnetraw" ] \
           && chown "$SNIFF_USER" "$PREFIX"/python-capnetraw 2>/dev/null \
           && setcap cap_net_raw+ep "$PREFIX/python-capnetraw" 2>/dev/null; then
            SNIFF_AS="$SNIFF_USER"
            log "rootless mode: cap_net_raw on private interpreter, user=$SNIFF_USER"
        else
            rm -f "$PREFIX/python-capnetraw"
            log "WARN: setcap path failed — sniffer will run as root"
        fi
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
if [ "$CAPTURE_MODE" = "cpp" ]; then
    CXXSTD=$(g++ -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra $CXXSTD nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra $CXXSTD nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
    if [ -f "$PREFIX/nt-sniff-cpp" ] && have setcap && have useradd; then
        chown "$SNIFF_USER" "$PREFIX/nt-sniff-cpp" 2>/dev/null || true
        if setcap cap_net_raw+ep "$PREFIX/nt-sniff-cpp" 2>/dev/null \
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/nt-sniff-cpp --fixture" >/dev/null 2>&1; then
            SNIFF_AS="$SNIFF_USER"
            log "rootless mode: cap_net_raw on native C++ binary, user=$SNIFF_USER"
        else
            SNIFF_AS=root
            log "WARN: rootless capability execution failed — sniffer will run as root"
        fi
    fi
    if [ "$SNIFF_AS" != root ]; then
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS"
    fi
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
# networktracing-legacy — pcap sniffer + shipper (SysV, el6/debian/ubuntu)
# chkconfig: 2345 90 10
# description: NetworkTracing passive HTTP/SOAP capture (old-kernel kit)
### BEGIN INIT INFO
# Provides:          networktracing-legacy
# Required-Start:    \$network \$local_fs \$remote_fs
# Required-Stop:     \$network \$local_fs \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: NetworkTracing passive HTTP/SOAP capture
# Description:       NetworkTracing legacy capture agent
### END INIT INFO

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
                if [ -n "\$p" ] && [ "\$p" != "\$\$" ]; then
                    kill "\$p" 2>/dev/null || true
                    _w=0
                    while [ \$_w -lt 3 ] && kill -0 "\$p" 2>/dev/null; do
                        sleep 1
                        _w=\$((_w + 1))
                    done
                    kill -0 "\$p" 2>/dev/null && kill -9 "\$p" 2>/dev/null || true
                fi
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
            if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f networktracing-legacy remove >/dev/null 2>&1 || true; fi
            rm -f "\$INIT" "\$PIDFILE"
            rm -rf "\$PREFIX" /tmp/ntkit*
            if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
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
if have update-rc.d; then
    update-rc.d networktracing-legacy defaults 2>/dev/null || true
fi
if have systemctl; then
    systemctl daemon-reload 2>/dev/null || true
fi

"$INIT" start || {
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "service failed to start"
}
sleep 2
if ! pgrep -f "$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null; then
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "sniffer not running after start"
fi

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
ICglZCBldmVudHMgcGVuZGluZyBvbiBleGl0KSIgJSBsZW4oYnVmKSkKCgpkZWYgX3Nwb29sX2Fw
cGVuZChwYXRoLCBiYXRjaCk6CiAgICBkID0gb3MucGF0aC5kaXJuYW1lKHBhdGgpCiAgICB0cnk6
CiAgICAgICAgaWYgZCBhbmQgbm90IG9zLnBhdGguaXNkaXIoZCk6CiAgICAgICAgICAgIG9zLm1h
a2VkaXJzKGQpCiAgICAgICAgd2l0aCBvcGVuKHBhdGgsICJhIikgYXMgZjoKICAgICAgICAgICAg
Zm9yIGV2IGluIGJhdGNoOgogICAgICAgICAgICAgICAgZi53cml0ZShqc29uLmR1bXBzKGV2KSAr
ICJcbiIpCiAgICAgICAgZGVsIGJhdGNoWzpdCiAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3Ip
IGFzIGU6CiAgICAgICAgbG9nKCJGQVRBTDogY2Fubm90IHdyaXRlIHNwb29sICVzOiAlcyIgJSAo
cGF0aCwgZSkpCiAgICAgICAgb3MuX2V4aXQoMykKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18i
OgogICAgbWFpbigpCg==
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
aXplX3QgTUFYX0JBVENIID0gNDAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9RVUVVRSA9IDQw
MDA7CnN0YXRpYyBjb25zdCBpbnQgRkxVU0hfU0VDID0gNTsKc3RhdGljIGNvbnN0IGludCBSRVRS
WV9TRUMgPSA2MDsKc3RhdGljIHZvbGF0aWxlIHNpZ19hdG9taWNfdCBydW5uaW5nID0gMTsKc3Rh
dGljIHZvaWQgc3RvcF9zaWduYWwoaW50KSB7IHJ1bm5pbmcgPSAwOyB9CnN0YXRpYyB2b2lkIGxv
Z21zZyhjb25zdCBzdGQ6OnN0cmluZyAmcykgeyBzdGQ6OmNlcnIgPDwgIm50LXNoaXAtY3BwOiAi
IDw8IHMgPDwgc3RkOjplbmRsOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29ucShjb25zdCBzdGQ6
OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSAiXCIiOwogIGZvciAoc2l6ZV90IGkgPSAw
OyBpIDwgcy5zaXplKCk7ICsraSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNo
YXIpc1tpXTsKICAgIGlmIChjID09ICdcXCcgfHwgYyA9PSAnIicpIHsgeCArPSAnXFwnOyB4ICs9
IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAgIGVsc2Ug
aWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0JykgeCArPSAi
XFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0gKGNoYXIp
YzsKICB9CiAgcmV0dXJuIHggKyAiXCIiOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBzaGVsbHEoY29u
c3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZvciAoc2l6ZV90
IGk9MDtpPHMuc2l6ZSgpOysraSkgeyBpZiAoc1tpXT09J1wnJykgbyArPSAiJ1xcJyciOyBlbHNl
IG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIiciOwp9CnN0YXRpYyBib29sIHJlYWRfZmlsZShj
b25zdCBzdGQ6OnN0cmluZyAmcCwgc3RkOjpzdHJpbmcgKm91dCkgewogIHN0ZDo6aWZzdHJlYW0g
ZihwLmNfc3RyKCkpOyBpZiAoIWYpIHJldHVybiBmYWxzZTsKICBzdGQ6Om9zdHJpbmdzdHJlYW0g
c3M7IHNzIDw8IGYucmRidWYoKTsgKm91dCA9IHNzLnN0cigpOyByZXR1cm4gdHJ1ZTsKfQpzdGF0
aWMgYm9vbCB3cml0ZV9hcHBlbmQoY29uc3Qgc3RkOjpzdHJpbmcgJnAsIGNvbnN0IHN0ZDo6c3Ry
aW5nICZkYXRhKSB7CiAgc3RkOjpzdHJpbmcgZGlyPXAuc3Vic3RyKDAscC5maW5kX2xhc3Rfb2Yo
Jy8nKSk7CiAgaWYgKCFkaXIuZW1wdHkoKSkgeyBzdGQ6OnN0cmluZyBjbWQ9Im1rZGlyIC1wICIr
c2hlbGxxKGRpcik7IGlmIChzeXN0ZW0oY21kLmNfc3RyKCkpICE9IDApIHJldHVybiBmYWxzZTsg
fQogIHN0ZDo6b2ZzdHJlYW0gZihwLmNfc3RyKCksIHN0ZDo6aW9zOjpvdXR8c3RkOjppb3M6OmFw
cCk7IGlmICghZikgcmV0dXJuIGZhbHNlOwogIGYgPDwgZGF0YTsgcmV0dXJuIGYuZ29vZCgpOwp9
CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1iZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0ZDo6b3N0cmlu
Z3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBq
c29uX2FycmF5KGNvbnN0IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAmYSkgewogIHN0ZDo6c3Ry
aW5nIG89IlsiOyBmb3Ioc2l6ZV90IGk9MDtpPGEuc2l6ZSgpOysraSl7aWYoaSlvKz0iLCI7bys9
YVtpXTt9IHJldHVybiBvKyJdIjsKfQpzdGF0aWMgYm9vbCBwb3N0KGNvbnN0IHN0ZDo6c3RyaW5n
ICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgY29u
c3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHk9
IntcIm5vZGVcIjoiK2pzb25xKG5vZGUpKyIsXCJldmVudHNcIjoiK2pzb25fYXJyYXkoYmF0Y2gp
KyJ9IjsKICBjaGFyIGNvZGVfdG1wbFtdID0gIi90bXAvbnRfY29kZV9YWFhYWFgiOwogIGludCB0
bXBfZmQgPSBta3N0ZW1wKGNvZGVfdG1wbCk7CiAgaWYgKHRtcF9mZCA8IDApIHJldHVybiBmYWxz
ZTsKICBjbG9zZSh0bXBfZmQpOwogIHN0ZDo6c3RyaW5nIGNvZGVfZmlsZSA9IGNvZGVfdG1wbDsK
ICBzdGQ6OnN0cmluZyBjbWQ9ImN1cmwgLXNTIC0tbWF4LXRpbWUgMTUgLW8gL2Rldi9udWxsIC13
ICcle2h0dHBfY29kZX0nIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0
YS1iaW5hcnkgQC0gIitzaGVsbHEoZW5kcG9pbnQrIi9hcGkvaW5nZXN0IikrIiA+ICIrc2hlbGxx
KGNvZGVfZmlsZSk7CiAgRklMRSAqZnA9cG9wZW4oY21kLmNfc3RyKCksInciKTsgaWYoIWZwKXsg
dW5saW5rKGNvZGVfZmlsZS5jX3N0cigpKTsgcmV0dXJuIGZhbHNlOyB9CiAgZndyaXRlKGJvZHku
ZGF0YSgpLCAxLCBib2R5LnNpemUoKSwgZnApOwogIGludCByYz1wY2xvc2UoZnApOwogIHN0ZDo6
c3RyaW5nIGNvZGU7CiAgcmVhZF9maWxlKGNvZGVfZmlsZSwgJmNvZGUpOwogIHVubGluayhjb2Rl
X2ZpbGUuY19zdHIoKSk7CiAgd2hpbGUgKCFjb2RlLmVtcHR5KCkgJiYgKGNvZGVbY29kZS5zaXpl
KCktMV09PSdccicgfHwgY29kZVtjb2RlLnNpemUoKS0xXT09J1xuJyB8fCBjb2RlW2NvZGUuc2l6
ZSgpLTFdPT0nICcpKSBjb2RlLmVyYXNlKGNvZGUuc2l6ZSgpLTEpOwogIHJldHVybiByYz09MCAm
JiBjb2RlPT0iMjAwIjsKfQpzdGF0aWMgdm9pZCBzcG9vbChjb25zdCBzdGQ6OnN0cmluZyAmcGF0
aCwgY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5n
IGRhdGE7IGZvcihzaXplX3QgaT0wO2k8YmF0Y2guc2l6ZSgpOysraSlkYXRhKz1iYXRjaFtpXSsi
XG4iOwogIGlmKCF3cml0ZV9hcHBlbmQocGF0aCxkYXRhKSkgeyBsb2dtc2coIkZBVEFMOiBjYW5u
b3Qgd3JpdGUgc3Bvb2wiKTsgZXhpdCgzKTsgfQp9CnN0YXRpYyB2b2lkIGxvYWRfc3Bvb2woY29u
c3Qgc3RkOjpzdHJpbmcgJnBhdGgsIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAqYnVmKSB7CiAg
c3RkOjpzdHJpbmcgZGF0YTsgaWYoIXJlYWRfZmlsZShwYXRoLCZkYXRhKSlyZXR1cm47CiAgc3Rk
Ojppc3RyaW5nc3RyZWFtIGluKGRhdGEpOyBzdGQ6OnN0cmluZyBsaW5lOyB3aGlsZShzdGQ6Omdl
dGxpbmUoaW4sbGluZSkpIGlmKCFsaW5lLmVtcHR5KCkpIGJ1Zi0+cHVzaF9iYWNrKGxpbmUpOwog
IHVubGluayhwYXRoLmNfc3RyKCkpOwp9CnN0YXRpYyB2b2lkIHNlbmRfYmF0Y2hlcyhjb25zdCBz
dGQ6OnN0cmluZyAmZW5kcG9pbnQsY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsY29uc3Qgc3RkOjpz
dHJpbmcgJnNwb29sX3BhdGgsCiAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6OnZlY3Rvcjxz
dGQ6OnN0cmluZz4gKmJ1ZiwgYm9vbCBmbHVzaF9hbGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1wdHko
KSAmJiAoZmx1c2hfYWxsIHx8IGJ1Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCkpIHsKICAgIHNpemVf
dCBuPWJ1Zi0+c2l6ZSgpPj1NQVhfQkFUQ0g/TUFYX0JBVENIOmJ1Zi0+c2l6ZSgpOwogICAgc3Rk
Ojp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoKGJ1Zi0+YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7
CiAgICBpZihwb3N0KGVuZHBvaW50LG5vZGUsYmF0Y2gpKSB7IGJ1Zi0+ZXJhc2UoYnVmLT5iZWdp
bigpLGJ1Zi0+YmVnaW4oKStuKTsgbG9nbXNnKCJmbHVzaGVkICIrbnVtYmVyX3N0cmluZyhuKSsi
IGV2ZW50cyIpOyB9CiAgICBlbHNlIHsgc3Bvb2woc3Bvb2xfcGF0aCxiYXRjaCk7IGJ1Zi0+ZXJh
c2UoYnVmLT5iZWdpbigpLGJ1Zi0+YmVnaW4oKStuKTsgbG9nbXNnKCJzcG9vbGVkICIrbnVtYmVy
X3N0cmluZyhuKSsiIGV2ZW50cyIpOyBicmVhazsgfQogIH0KfQppbnQgbWFpbihpbnQgYXJnYyxj
aGFyICoqYXJndikgewogIHN0ZDo6c3RyaW5nIGVuZHBvaW50LCBzcG9vbF9wYXRoPSIvdmFyL2xp
Yi9uZXR3b3JrdHJhY2luZy9zbmlmZi1zcG9vbC5qc29ubCI7IGludCBpOwogIGZvcihpPTE7aTxh
cmdjOysraSl7c3RkOjpzdHJpbmcgYT1hcmd2W2ldOyBpZihhPT0iLS1lbmRwb2ludCImJmkrMTxh
cmdjKWVuZHBvaW50PWFyZ3ZbKytpXTsgZWxzZSBpZihhPT0iLS1zcG9vbCImJmkrMTxhcmdjKXNw
b29sX3BhdGg9YXJndlsrK2ldOyBlbHNlIGlmKGE9PSItaCJ8fGE9PSItLWhlbHAiKXtzdGQ6OmNv
dXQ8PCJ1c2FnZTogbnQtc2hpcC1jcHAgLS1lbmRwb2ludCBVUkwgWy0tc3Bvb2wgUEFUSF1cbiI7
cmV0dXJuIDA7fSBlbHNlIHtzdGQ6OmNlcnI8PCJ1bmtub3duIGFyZzogIjw8YTw8IlxuIjtyZXR1
cm4gMjt9fQogIGlmKGVuZHBvaW50LmVtcHR5KCkpe3N0ZDo6Y2Vycjw8Ii0tZW5kcG9pbnQgcmVx
dWlyZWRcbiI7cmV0dXJuIDI7fQogIHNpZ25hbChTSUdURVJNLHN0b3Bfc2lnbmFsKTsgc2lnbmFs
KFNJR0lOVCxzdG9wX3NpZ25hbCk7CiAgY2hhciBob3N0WzI1Nl07IGdldGhvc3RuYW1lKGhvc3Qs
c2l6ZW9mKGhvc3QpKTsgaG9zdFtzaXplb2YoaG9zdCktMV09MDsKICBjb25zdCBjaGFyICpub2Rl
X2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2Rl
X2VudiAmJiAqbm9kZV9lbnYpID8gbm9kZV9lbnYgOiBob3N0OwogIHN0ZDo6dmVjdG9yPHN0ZDo6
c3RyaW5nPiBidWY7IGxvYWRfc3Bvb2woc3Bvb2xfcGF0aCwmYnVmKTsgdGltZV90IGxhc3Q9dGlt
ZShOVUxMKSwgbGFzdF9yZXRyeT1sYXN0OwogIHN0ZDo6c3RyaW5nIGxpbmU7CiAgd2hpbGUocnVu
bmluZykgewogICAgZmRfc2V0IHI7IEZEX1pFUk8oJnIpOyBGRF9TRVQoMCwgJnIpOwogICAgc3Ry
dWN0IHRpbWV2YWwgdHY7IHR2LnR2X3NlYyA9IDE7IHR2LnR2X3VzZWMgPSAwOwogICAgaW50IHJj
ID0gc2VsZWN0KDEsICZyLCBOVUxMLCBOVUxMLCAmdHYpOwogICAgaWYgKHJjID4gMCAmJiBGRF9J
U1NFVCgwLCAmcikpIHsKICAgICAgaWYgKCFzdGQ6OmdldGxpbmUoc3RkOjpjaW4sIGxpbmUpKSBi
cmVhazsKICAgICAgaWYgKCFsaW5lLmVtcHR5KCkpIHsKICAgICAgICBidWYucHVzaF9iYWNrKGxp
bmUpOwogICAgICAgIGlmIChidWYuc2l6ZSgpID49IE1BWF9RVUVVRSkgewogICAgICAgICAgc2Vu
ZF9iYXRjaGVzKGVuZHBvaW50LCBub2RlLCBzcG9vbF9wYXRoLCAmYnVmLCBmYWxzZSk7CiAgICAg
ICAgfQogICAgICB9CiAgICB9CiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICAgIGlmIChu
b3cgLSBsYXN0ID49IEZMVVNIX1NFQyB8fCBidWYuc2l6ZSgpID49IE1BWF9CQVRDSCkgewogICAg
ICBpZiAoIWJ1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMoZW5kcG9pbnQsIG5vZGUsIHNwb29sX3Bh
dGgsICZidWYsIHRydWUpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogICAgaWYgKG5vdyAtIGxh
c3RfcmV0cnkgPj0gUkVUUllfU0VDKSB7CiAgICAgIGxvYWRfc3Bvb2woc3Bvb2xfcGF0aCwgJmJ1
Zik7CiAgICAgIGxhc3RfcmV0cnkgPSBub3c7CiAgICB9CiAgfQogIHNlbmRfYmF0Y2hlcyhlbmRw
b2ludCxub2RlLHNwb29sX3BhdGgsJmJ1Zix0cnVlKTsgbG9nbXNnKCJzdG9wcGVkIik7IHJldHVy
biAwOwp9Cg==
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
I2luY2x1ZGUgPHBvbGwuaD4KI2luY2x1ZGUgPHN5cy9pb2N0bC5oPgojaW5jbHVkZSA8c3lzL21t
YW4uaD4KI2luY2x1ZGUgPHN5cy9zZWxlY3QuaD4KI2luY2x1ZGUgPHN5cy90aW1lLmg+CiNpbmNs
dWRlIDxzeXMvc29ja2V0Lmg+CiNpbmNsdWRlIDxzeXMvdHlwZXMuaD4KI2luY2x1ZGUgPHRpbWUu
aD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8bGludXgvZmlsdGVyLmg+CiNpbmNsdWRl
IDxsaW51eC9pZl9wYWNrZXQuaD4KI2luY2x1ZGUgPGxpbnV4L2lmX2V0aGVyLmg+CiNpbmNsdWRl
IDxpb3N0cmVhbT4KCiNpbmNsdWRlIDxtYXA+CiNpbmNsdWRlIDxzc3RyZWFtPgojaW5jbHVkZSA8
c3RyaW5nPgojaW5jbHVkZSA8dmVjdG9yPgoKc3RhdGljIHZvbGF0aWxlIHNpZ19hdG9taWNfdCBn
X3J1bm5pbmcgPSAxOwpzdGF0aWMgdm9pZCBzdG9wX3NpZ25hbChpbnQpIHsgZ19ydW5uaW5nID0g
MDsgfQoKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfRkxPV1MgPSA4MTkyOwpzdGF0aWMgY29uc3Qg
c2l6ZV90IE1BWF9QRU5ESU5HID0gODE5MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfSEVBREVS
ID0gMjYyMTQ0OwpzdGF0aWMgY29uc3QgdW5zaWduZWQgRkxPV19UVEwgPSAzMDA7CnN0YXRpYyBj
b25zdCB1bnNpZ25lZCBQRU5ESU5HX1RUTCA9IDU7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBBQ0NF
UFQgPSAyMDQ4OwpzdGF0aWMgY29uc3QgaW50IFNPX0FUVEFDSF9GSUxURVJfT0xEID0gMjY7CnN0
YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBFVEhfUF9JUF9IT1NUID0gMHgwODAwOwpzdGF0aWMg
Y29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfODAyMVFfSE9TVCA9IDB4ODEwMDsKCnN0YXRpYyBz
dGQ6OnN0cmluZyB0cmltKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc2l6ZV90IGEgPSAwLCBi
ID0gcy5zaXplKCk7CiAgd2hpbGUgKGEgPCBiICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1th
XSkpICsrYTsKICB3aGlsZSAoYiA+IGEgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilzW2IgLSAx
XSkpIC0tYjsKICByZXR1cm4gcy5zdWJzdHIoYSwgYiAtIGEpOwp9CnN0YXRpYyBzdGQ6OnN0cmlu
ZyBsb3dlcihjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSBzOwogIHNp
emVfdCBpOyBmb3IgKGkgPSAwOyBpIDwgeC5zaXplKCk7ICsraSkgeFtpXSA9IChjaGFyKXRvbG93
ZXIoKHVuc2lnbmVkIGNoYXIpeFtpXSk7CiAgcmV0dXJuIHg7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5n
IGpzb25xKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpzdHJpbmcgeCA9ICJcIiI7IHNp
emVfdCBpOwogIGZvciAoaSA9IDA7IGkgPCBzLnNpemUoKTsgKytpKSB7CiAgICB1bnNpZ25lZCBj
aGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgaWYgKGMgPT0gJ1xcJyB8fCBjID09ICci
JykgeyB4ICs9ICdcXCc7IHggKz0gKGNoYXIpYzsgfQogICAgZWxzZSBpZiAoYyA9PSAnXG4nKSB4
ICs9ICJcXG4iOwogICAgZWxzZSBpZiAoYyA9PSAnXHInKSB4ICs9ICJcXHIiOwogICAgZWxzZSBp
ZiAoYyA9PSAnXHQnKSB4ICs9ICJcXHQiOwogICAgZWxzZSBpZiAoYyA8IDMyKSB4ICs9ICc/JzsK
ICAgIGVsc2UgeCArPSAoY2hhciljOwogIH0KICB4ICs9ICciJzsgcmV0dXJuIHg7Cn0Kc3RhdGlj
IGxvbmcgbG9uZyBub3dfbXMoKSB7CiAgc3RydWN0IHRpbWV2YWwgdHY7IGdldHRpbWVvZmRheSgm
dHYsIE5VTEwpOwogIHJldHVybiAobG9uZyBsb25nKXR2LnR2X3NlYyAqIDEwMDBMTCArIHR2LnR2
X3VzZWMgLyAxMDAwOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW0obG9uZyB2KSB7IHN0ZDo6b3N0
cmluZ3N0cmVhbSBvOyBvIDw8IHY7IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBib29sIHZhbGlk
X3BvcnQodW5zaWduZWQgcCkgeyByZXR1cm4gcCA+IDAgJiYgcCA8PSA2NTUzNTsgfQpzdGF0aWMg
Ym9vbCBoYXNfbWV0aG9kKGNvbnN0IHN0ZDo6c3RyaW5nICZtKSB7CiAgcmV0dXJuIG0gPT0gIkdF
VCIgfHwgbSA9PSAiUE9TVCIgfHwgbSA9PSAiUFVUIiB8fCBtID09ICJERUxFVEUiIHx8CiAgICAg
ICAgIG0gPT0gIlBBVENIIiB8fCBtID09ICJIRUFEIiB8fCBtID09ICJPUFRJT05TIjsKfQpzdGF0
aWMgc3RkOjpzdHJpbmcgaG9zdF9uYW1lKCkgewogIGNoYXIgYlsyNTZdOyBpZiAoZ2V0aG9zdG5h
bWUoYiwgc2l6ZW9mKGIpIC0gMSkgIT0gMCkgcmV0dXJuICJ1bmtub3duLW5vZGUiOwogIGJbc2l6
ZW9mKGIpIC0gMV0gPSAwOyBjaGFyICpwID0gc3RyY2hyKGIsICcuJyk7IGlmIChwKSAqcCA9IDA7
IHJldHVybiBiOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBiNjRkZWNvZGVfdXNlcihjb25zdCBzdGQ6
OnN0cmluZyAmdikgewogIHN0ZDo6c3RyaW5nIGluID0gdHJpbSh2KSwgb3V0OyBpbnQgdmFsID0g
MCwgYml0cyA9IC04OyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgaW4uc2l6ZSgpOyArK2kp
IHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWluW2ldOyBpbnQgZCA9IC0x
OwogICAgaWYgKGMgPj0gJ0EnICYmIGMgPD0gJ1onKSBkID0gYyAtICdBJzsKICAgIGVsc2UgaWYg
KGMgPj0gJ2EnICYmIGMgPD0gJ3onKSBkID0gYyAtICdhJyArIDI2OwogICAgZWxzZSBpZiAoYyA+
PSAnMCcgJiYgYyA8PSAnOScpIGQgPSBjIC0gJzAnICsgNTI7CiAgICBlbHNlIGlmIChjID09ICcr
JykgZCA9IDYyOwogICAgZWxzZSBpZiAoYyA9PSAnLycpIGQgPSA2MzsKICAgIGVsc2UgaWYgKGMg
PT0gJz0nKSBicmVhazsKICAgIGlmIChkIDwgMCkgY29udGludWU7CiAgICB2YWwgPSAodmFsIDw8
IDYpICsgZDsKICAgIGJpdHMgKz0gNjsKICAgIGlmIChiaXRzID49IDApIHsKICAgICAgb3V0ICs9
IChjaGFyKSgodmFsID4+IGJpdHMpICYgMHhmZik7CiAgICAgIGJpdHMgLT0gODsKICAgICAgaWYg
KG91dC5zaXplKCkgPiA1MTIpIHJldHVybiAiIjsKICAgIH0KICB9CiAgc2l6ZV90IHAgPSBvdXQu
ZmluZCgnOicpOwogIGlmIChwID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CiAgcmV0
dXJuIG91dC5zdWJzdHIoMCwgcCA+IDY0ID8gNjQgOiBwKTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcg
aGVhZGVyX3ZhbHVlKGNvbnN0IHN0ZDo6c3RyaW5nICZoZWFkLCBjb25zdCBzdGQ6OnN0cmluZyAm
d2FudCkgewogIHN0ZDo6aXN0cmluZ3N0cmVhbSBpbihoZWFkKTsgc3RkOjpzdHJpbmcgbGluZSwg
dyA9IGxvd2VyKHdhbnQpOwogIHdoaWxlIChzdGQ6OmdldGxpbmUoaW4sIGxpbmUpKSB7CiAgICBp
ZiAoIWxpbmUuZW1wdHkoKSAmJiBsaW5lW2xpbmUuc2l6ZSgpIC0gMV0gPT0gJ1xyJykgbGluZS5l
cmFzZShsaW5lLnNpemUoKSAtIDEpOwogICAgc2l6ZV90IHAgPSBsaW5lLmZpbmQoJzonKTsgaWYg
KHAgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGNvbnRpbnVlOwogICAgaWYgKGxvd2VyKHRyaW0obGlu
ZS5zdWJzdHIoMCwgcCkpKSA9PSB3KSByZXR1cm4gdHJpbShsaW5lLnN1YnN0cihwICsgMSkpOwog
IH0KICByZXR1cm4gIiI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIHRyYWNlX2lkX2Zyb21fcGFyZW50
KGNvbnN0IHN0ZDo6c3RyaW5nICZ0cCkgewogIHN0ZDo6c3RyaW5nIHggPSB0cmltKHRwKTsKICBp
ZiAoeC5zaXplKCkgPT0gNTUgJiYgeFsyXSA9PSAnLScgJiYgeFszNV0gPT0gJy0nICYmIHhbNTJd
ID09ICctJykgcmV0dXJuIGxvd2VyKHguc3Vic3RyKDMsIDMyKSk7CiAgcmV0dXJuICIiOwp9CnN0
YXRpYyBzdGQ6OnN0cmluZyBtYWtlX3RyYWNlcGFyZW50KHN0ZDo6c3RyaW5nICp0aWQpIHsKICB1
bnNpZ25lZCBjaGFyIGJbMjRdOyBzaXplX3QgaTsgRklMRSAqZiA9IGZvcGVuKCIvZGV2L3VyYW5k
b20iLCAicmIiKTsKICBpZiAoZikgeyBzaXplX3QgZ290ID0gZnJlYWQoYiwgMSwgc2l6ZW9mKGIp
LCBmKTsgKHZvaWQpZ290OyBmY2xvc2UoZik7IH0KICBlbHNlIHsgdW5zaWduZWQgbG9uZyB0ID0g
KHVuc2lnbmVkIGxvbmcpdGltZShOVUxMKSBeICh1bnNpZ25lZCBsb25nKWdldHBpZCgpOyBmb3Ig
KGkgPSAwOyBpIDwgc2l6ZW9mKGIpOyArK2kpIGJbaV0gPSAodW5zaWduZWQgY2hhcikodCA9IHQg
KiAxMTAzNTE1MjQ1VUwgKyAxMjM0NVVMKTsgfQogIHN0YXRpYyBjb25zdCBjaGFyICpoZXggPSAi
MDEyMzQ1Njc4OWFiY2RlZiI7IHN0ZDo6c3RyaW5nIGEsIGM7CiAgZm9yIChpID0gMDsgaSA8IDE2
OyArK2kpIHsgYSArPSBoZXhbYltpXSA+PiA0XTsgYSArPSBoZXhbYltpXSAmIDE1XTsgfQogIGZv
ciAoaSA9IDE2OyBpIDwgMjQ7ICsraSkgeyBjICs9IGhleFtiW2ldID4+IDRdOyBjICs9IGhleFti
W2ldICYgMTVdOyB9CiAgKnRpZCA9IGE7IHJldHVybiAiMDAtIiArIGEgKyAiLSIgKyBjICsgIi0w
MSI7Cn0KCnN0cnVjdCBFdmVudCB7CiAgbG9uZyB0czsgc3RkOjpzdHJpbmcgaG9zdCwgc3JjLCBz
ZXJ2aWNlLCBtZXRob2QsIHBhdGgsIHVzZXIsIHNjaGVtZSwgcHJvYmU7CiAgc3RkOjpzdHJpbmcg
aG9zdF9oZHIsIHVzZXJfYWdlbnQsIHhmZiwgY2FsbGVyLCBkc3RfaXAsIHRyYWNlcGFyZW50LCB0
cmFjZV9pZDsKICB1bnNpZ25lZCBjYWxsZXJfcG9ydCwgZHN0X3BvcnQsIHJlcV9ieXRlcywgcmVz
cF9ieXRlczsgaW50IHN0YXR1czsgbG9uZyBkdXJhdGlvbl9tczsKICBib29sIGhhc19zdGF0dXMs
IGhhc19kdXJhdGlvbiwgaGFzX3Jlc3A7CiAgRXZlbnQoKSA6IHRzKDApLCBjYWxsZXJfcG9ydCgw
KSwgZHN0X3BvcnQoMCksIHJlcV9ieXRlcygwKSwgcmVzcF9ieXRlcygwKSwgc3RhdHVzKDApLCBk
dXJhdGlvbl9tcygwKSwgaGFzX3N0YXR1cyhmYWxzZSksIGhhc19kdXJhdGlvbihmYWxzZSksIGhh
c19yZXNwKGZhbHNlKSB7fQp9OwpzdHJ1Y3QgRmxvdyB7IHN0ZDo6c3RyaW5nIGJ1ZjsgdGltZV90
IHRvdWNoZWQ7IEZsb3coKSA6IHRvdWNoZWQodGltZShOVUxMKSkge30gfTsKc3RydWN0IFBlbmRp
bmcgewogIEV2ZW50IGV2OwogIGxvbmcgbG9uZyBzdGFydGVkX21zOwogIFBlbmRpbmcoKSA6IHN0
YXJ0ZWRfbXMoMCkge30KICBQZW5kaW5nKGNvbnN0IEV2ZW50ICZlLCBsb25nIGxvbmcgdCkgOiBl
dihlKSwgc3RhcnRlZF9tcyh0KSB7fQp9OwpzdHJ1Y3QgUGFja2V0S2V5IHsgc3RkOjpzdHJpbmcg
c3JjOyB1bnNpZ25lZCBzcG9ydDsgc3RkOjpzdHJpbmcgZHN0OyB1bnNpZ25lZCBkcG9ydDsgYm9v
bCBvcGVyYXRvcjwoY29uc3QgUGFja2V0S2V5ICZ4KSBjb25zdCB7IHJldHVybiBzcmMgIT0geC5z
cmMgPyBzcmMgPCB4LnNyYyA6IHNwb3J0ICE9IHguc3BvcnQgPyBzcG9ydCA8IHguc3BvcnQgOiBk
c3QgIT0geC5kc3QgPyBkc3QgPCB4LmRzdCA6IGRwb3J0IDwgeC5kcG9ydDsgfSB9OwoKc3RhdGlj
IHN0ZDo6c3RyaW5nIGtleV9zdHJpbmcoY29uc3Qgc3RkOjpzdHJpbmcgJmEsIHVuc2lnbmVkIGFw
LCBjb25zdCBzdGQ6OnN0cmluZyAmYiwgdW5zaWduZWQgYnApIHsgcmV0dXJuIGEgKyAiOiIgKyBu
dW0oYXApICsgIi0+IiArIGIgKyAiOiIgKyBudW0oYnApOyB9CnN0YXRpYyB2b2lkIGxvZ21zZyhj
b25zdCBzdGQ6OnN0cmluZyAmcykgeyBmcHJpbnRmKHN0ZGVyciwgIm50LXNuaWZmLWNwcDogJXNc
biIsIHMuY19zdHIoKSk7IGZmbHVzaChzdGRlcnIpOyB9CgpzdGF0aWMgYm9vbCBwYXJzZV9yZXF1
ZXN0KGNvbnN0IHN0ZDo6c3RyaW5nICZoZWFkLCBFdmVudCAqZSkgewogIHN0ZDo6c3RyaW5nIGZp
cnN0OyBzdGQ6OmlzdHJpbmdzdHJlYW0gaW4oaGVhZCk7IGlmICghc3RkOjpnZXRsaW5lKGluLCBm
aXJzdCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OmlzdHJpbmdzdHJlYW0gcCh0cmltKGZpcnN0KSk7
IGlmICghKHAgPj4gZS0+bWV0aG9kID4+IGUtPnBhdGgpKSByZXR1cm4gZmFsc2U7CiAgaWYgKCFo
YXNfbWV0aG9kKGUtPm1ldGhvZCkpIHJldHVybiBmYWxzZTsKICBzaXplX3QgcSA9IGUtPnBhdGgu
ZmluZCgnPycpOyBpZiAocSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgZS0+cGF0aC5lcmFzZShxKTsK
ICBpZiAoZS0+cGF0aC5zaXplKCkgPiAxMjApIGUtPnBhdGguZXJhc2UoMTIwKTsKICBzdGQ6OnN0
cmluZyBhdXRoID0gaGVhZGVyX3ZhbHVlKGhlYWQsICJhdXRob3JpemF0aW9uIik7CiAgaWYgKGxv
d2VyKGF1dGgpLmZpbmQoImJhc2ljICIpID09IDApIHsgZS0+dXNlciA9IGI2NGRlY29kZV91c2Vy
KGF1dGguc3Vic3RyKDYpKTsgZS0+c2NoZW1lID0gImJhc2ljIjsgfQogIGVsc2UgaWYgKGxvd2Vy
KGF1dGgpLmZpbmQoImJlYXJlciAiKSA9PSAwKSBlLT5zY2hlbWUgPSAiYmVhcmVyIjsKICBzdGQ6
OnN0cmluZyB4ID0gaGVhZGVyX3ZhbHVlKGhlYWQsICJ0cmFjZXBhcmVudCIpOyBlLT50cmFjZV9p
ZCA9IHRyYWNlX2lkX2Zyb21fcGFyZW50KHgpOyBlLT50cmFjZXBhcmVudCA9IGUtPnRyYWNlX2lk
LmVtcHR5KCkgPyBtYWtlX3RyYWNlcGFyZW50KCZlLT50cmFjZV9pZCkgOiB4OwogIGUtPmhvc3Rf
aGRyID0gaGVhZGVyX3ZhbHVlKGhlYWQsICJob3N0Iik7CiAgZS0+dXNlcl9hZ2VudCA9IGhlYWRl
cl92YWx1ZShoZWFkLCAidXNlci1hZ2VudCIpOwogIGUtPnhmZiA9IGhlYWRlcl92YWx1ZShoZWFk
LCAieC1mb3J3YXJkZWQtZm9yIik7CiAgaWYgKGUtPnVzZXIuZW1wdHkoKSkgewogICAgZS0+dXNl
ciA9ICItYW5vbnltb3VzLSI7CiAgfQogIGlmIChlLT5zY2hlbWUuZW1wdHkoKSkgewogICAgZS0+
c2NoZW1lID0gIm5vbmUiOwogIH0KICByZXR1cm4gdHJ1ZTsKfQpzdGF0aWMgYm9vbCBwYXJzZV9y
ZXNwb25zZShjb25zdCBzdGQ6OnN0cmluZyAmcGF5bG9hZCwgaW50ICpzdGF0dXMsIHVuc2lnbmVk
ICpjbGVuKSB7CiAgc2l6ZV90IGVuZCA9IHBheWxvYWQuZmluZCgiXHJcblxyXG4iKTsKICBzdGQ6
OnN0cmluZyBoID0gcGF5bG9hZC5zdWJzdHIoMCwgZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zID8g
cGF5bG9hZC5zaXplKCkgOiBlbmQpOwogIGlmIChoLnNpemUoKSA+IE1BWF9IRUFERVIpIHJldHVy
biBmYWxzZTsKICBzdGQ6OmlzdHJpbmdzdHJlYW0gaW4oaCk7CiAgc3RkOjpzdHJpbmcgZmlyc3Q7
CiAgaWYgKCFzdGQ6OmdldGxpbmUoaW4sIGZpcnN0KSkgcmV0dXJuIGZhbHNlOwogIHN0ZDo6aXN0
cmluZ3N0cmVhbSBwKGZpcnN0KTsKICBzdGQ6OnN0cmluZyBwcm90bzsKICBpZiAoIShwID4+IHBy
b3RvID4+ICpzdGF0dXMpKSByZXR1cm4gZmFsc2U7CiAgaWYgKHByb3RvLmZpbmQoIkhUVFAvIikg
IT0gMCB8fCAqc3RhdHVzIDwgMTAwIHx8ICpzdGF0dXMgPiA1OTkpIHJldHVybiBmYWxzZTsKICAq
Y2xlbiA9IDA7IHN0ZDo6c3RyaW5nIGxpbmU7CiAgd2hpbGUgKHN0ZDo6Z2V0bGluZShpbiwgbGlu
ZSkpIHsgc2l6ZV90IHggPSBsaW5lLmZpbmQoJzonKTsgaWYgKHggIT0gc3RkOjpzdHJpbmc6Om5w
b3MgJiYgbG93ZXIodHJpbShsaW5lLnN1YnN0cigwLCB4KSkpID09ICJjb250ZW50LWxlbmd0aCIp
IHsgbG9uZyBuID0gYXRvbCh0cmltKGxpbmUuc3Vic3RyKHggKyAxKSkuY19zdHIoKSk7IGlmIChu
ID49IDAgJiYgbiA8PSAweDdmZmZmZmZmKSAqY2xlbiA9ICh1bnNpZ25lZCluOyB9IH0KICByZXR1
cm4gdHJ1ZTsKfQpzdGF0aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0IEV2ZW50ICZlKSB7CiAgc3Rk
Ojpjb3V0IDw8ICJ7XCJ0c1wiOiIgPDwgZS50cyA8PCAiLFwiaG9zdFwiOiIgPDwganNvbnEoZS5o
b3N0KSA8PCAiLFwic3JjXCI6XCJwY2FwXCIsXCJzZXJ2aWNlXCI6IiA8PCBqc29ucShlLnNlcnZp
Y2UpCiAgICAgICAgICAgIDw8ICIsXCJtZXRob2RcIjoiIDw8IGpzb25xKGUubWV0aG9kKSA8PCAi
LFwicGF0aFwiOiIgPDwganNvbnEoZS5wYXRoKSA8PCAiLFwidXNlclwiOiIgPDwganNvbnEoZS51
c2VyKQogICAgICAgICAgICA8PCAiLFwic2NoZW1lXCI6IiA8PCBqc29ucShlLnNjaGVtZSkgPDwg
IixcInNvdXJjZV9wcm9iZVwiOlwicGNhcC1odHRwLWNwcFwiLFwiaG9zdF9oZHJcIjoiIDw8IGpz
b25xKGUuaG9zdF9oZHIpCiAgICAgICAgICAgIDw8ICIsXCJ1c2VyX2FnZW50XCI6IiA8PCBqc29u
cShlLnVzZXJfYWdlbnQpIDw8ICIsXCJ4X2ZvcndhcmRlZF9mb3JcIjoiIDw8IGpzb25xKGUueGZm
KQogICAgICAgICAgICA8PCAiLFwiY2FsbGVyXCI6IiA8PCBqc29ucShlLmNhbGxlcikgPDwgIixc
ImNhbGxlcl9wb3J0XCI6IiA8PCBlLmNhbGxlcl9wb3J0IDw8ICIsXCJkc3RfaXBcIjoiIDw8IGpz
b25xKGUuZHN0X2lwKQogICAgICAgICAgICA8PCAiLFwiZHN0X3BvcnRcIjoiIDw8IGUuZHN0X3Bv
cnQgPDwgIixcInRyYWNlcGFyZW50XCI6IiA8PCBqc29ucShlLnRyYWNlcGFyZW50KSA8PCAiLFwi
dHJhY2VfaWRcIjoiIDw8IGpzb25xKGUudHJhY2VfaWQpCiAgICAgICAgICAgIDw8ICIsXCJzZXJ2
aWNlX2lkXCI6bnVsbCxcIm1vZHVsZV9pZFwiOlwicGNhcC1odHRwLWNwcFwiLFwicmVxX2J5dGVz
XCI6IiA8PCBlLnJlcV9ieXRlczsKICBpZiAoZS5oYXNfc3RhdHVzKSBzdGQ6OmNvdXQgPDwgIixc
InN0YXR1c1wiOiIgPDwgZS5zdGF0dXM7IGVsc2Ugc3RkOjpjb3V0IDw8ICIsXCJzdGF0dXNcIjpu
dWxsIjsKICBpZiAoZS5oYXNfZHVyYXRpb24pIHN0ZDo6Y291dCA8PCAiLFwiZHVyYXRpb25fbXNc
IjoiIDw8IGUuZHVyYXRpb25fbXM7IGVsc2Ugc3RkOjpjb3V0IDw8ICIsXCJkdXJhdGlvbl9tc1wi
Om51bGwiOwogIGlmIChlLmhhc19yZXNwKSBzdGQ6OmNvdXQgPDwgIixcInJlc3BfYnl0ZXNcIjoi
IDw8IGUucmVzcF9ieXRlczsgZWxzZSBzdGQ6OmNvdXQgPDwgIixcInJlc3BfYnl0ZXNcIjpudWxs
IjsKICBzdGQ6OmNvdXQgPDwgIn1cbiI7IHN0ZDo6Y291dC5mbHVzaCgpOwp9CgpzdGF0aWMgdm9p
ZCBmbHVzaF9vbGRlc3Qoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
ICZwZW5kaW5nKSB7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
OjppdGVyYXRvciBiZXN0ID0gcGVuZGluZy5lbmQoKTsgbG9uZyBsb25nIGJ0ID0gMDsgYm9vbCBm
b3VuZCA9IGZhbHNlOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4g
Pjo6aXRlcmF0b3IgaTsKICBmb3IgKGkgPSBwZW5kaW5nLmJlZ2luKCk7IGkgIT0gcGVuZGluZy5l
bmQoKTsgKytpKSBpZiAoIWktPnNlY29uZC5lbXB0eSgpICYmICghZm91bmQgfHwgaS0+c2Vjb25k
WzBdLnN0YXJ0ZWRfbXMgPCBidCkpIHsgYmVzdCA9IGk7IGJ0ID0gaS0+c2Vjb25kWzBdLnN0YXJ0
ZWRfbXM7IGZvdW5kID0gdHJ1ZTsgfQogIGlmIChmb3VuZCkgeyBlbWl0X2V2ZW50KGJlc3QtPnNl
Y29uZFswXS5ldik7IGJlc3QtPnNlY29uZC5lcmFzZShiZXN0LT5zZWNvbmQuYmVnaW4oKSk7IGlm
IChiZXN0LT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShiZXN0KTsgfQp9CnN0YXRpYyB2
b2lkIHN3ZWVwKHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBh
Y2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywgdGltZV90IG5vdykgewog
IHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBGbG93Pjo6aXRlcmF0b3IgZiwgZm47CiAgZm9yIChmID0g
Zmxvd3MuYmVnaW4oKTsgZiAhPSBmbG93cy5lbmQoKTspIHsKICAgIGZuID0gZjsgKytmbjsKICAg
IGlmICgodW5zaWduZWQpKG5vdyAtIGYtPnNlY29uZC50b3VjaGVkKSA+IEZMT1dfVFRMKSBmbG93
cy5lcmFzZShmKTsKICAgIGYgPSBmbjsKICB9CiAgbG9uZyBsb25nIGN1cnJlbnRfbXMgPSAobG9u
ZyBsb25nKW5vdyAqIDEwMDBMTDsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBl
bmRpbmc+ID46Oml0ZXJhdG9yIHAsIHBuOwogIGZvciAocCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAh
PSBwZW5kaW5nLmVuZCgpOykgewogICAgcG4gPSBwOyArK3BuOwogICAgc2l6ZV90IGkgPSAwOwog
ICAgd2hpbGUgKGkgPCBwLT5zZWNvbmQuc2l6ZSgpKSB7CiAgICAgIGlmIChjdXJyZW50X21zIC0g
cC0+c2Vjb25kW2ldLnN0YXJ0ZWRfbXMgPiAobG9uZyBsb25nKVBFTkRJTkdfVFRMICogMTAwMExM
KSB7CiAgICAgICAgZW1pdF9ldmVudChwLT5zZWNvbmRbaV0uZXYpOwogICAgICAgIHAtPnNlY29u
ZC5lcmFzZShwLT5zZWNvbmQuYmVnaW4oKSArIGkpOwogICAgICB9IGVsc2UgewogICAgICAgICsr
aTsKICAgICAgfQogICAgfQogICAgaWYgKHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNl
KHApOwogICAgcCA9IHBuOwogIH0KfQpzdGF0aWMgc2l6ZV90IGZpbmRfaHR0cF9zdGFydChjb25z
dCBzdGQ6OnN0cmluZyAmcykgewogIGNvbnN0IGNoYXIgKm1bXSA9IHsgIkdFVCAiLCAiUE9TVCAi
LCAiUFVUICIsICJERUxFVEUgIiwgIlBBVENIICIsICJIRUFEICIsICJPUFRJT05TICIgfTsKICBz
aXplX3QgYmVzdCA9IHN0ZDo6c3RyaW5nOjpucG9zOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwg
NzsgKytpKSB7CiAgICBzaXplX3QgcG9zID0gcy5maW5kKG1baV0pOwogICAgaWYgKHBvcyAhPSBz
dGQ6OnN0cmluZzo6bnBvcyAmJiAoYmVzdCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBwb3MgPCBi
ZXN0KSkgYmVzdCA9IHBvczsKICB9CiAgcmV0dXJuIGJlc3Q7Cn0KCnN0YXRpYyBib29sIGhhbmRs
ZV9wYWNrZXQoY29uc3QgdW5zaWduZWQgY2hhciAqYnVmLCBzaXplX3QgbiwgY29uc3Qgc3RkOjpz
dHJpbmcgJm5vZGUsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAmcG9ydHMsCiAgICAgICAg
ICAgICAgICAgICAgICAgICAgc3RkOjptYXA8c3RkOjpzdHJpbmcsIEZsb3c+ICZmbG93cywgc3Rk
OjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgaWYg
KG4gPCAzNCkgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBvZmYgPSAxNDsKICB1bnNpZ25lZCBzaG9y
dCBldCA9IG50b2hzKCooY29uc3QgdW5zaWduZWQgc2hvcnQgKikoYnVmICsgMTIpKTsKICBpZiAo
ZXQgPT0gRVRIX1BfODAyMVEpIHsgaWYgKG4gPCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9IG50b2hz
KCooY29uc3QgdW5zaWduZWQgc2hvcnQgKikoYnVmICsgMTYpKTsgb2ZmID0gMTg7IH0KICBpZiAo
ZXQgIT0gRVRIX1BfSVAgfHwgbiA8IG9mZiArIDIwKSByZXR1cm4gZmFsc2U7CiAgdW5zaWduZWQg
Y2hhciBpaGwgPSAodW5zaWduZWQgY2hhcikoYnVmW29mZl0gJiAxNSkgKiA0OwogIGlmICgoYnVm
W29mZl0gPj4gNCkgIT0gNCB8fCBidWZbb2ZmICsgOV0gIT0gNiB8fCBuIDwgb2ZmICsgaWhsICsg
MjApIHJldHVybiBmYWxzZTsKICBjaGFyIGFbSU5FVF9BRERSU1RSTEVOXSwgYltJTkVUX0FERFJT
VFJMRU5dOyBpbmV0X250b3AoQUZfSU5FVCwgYnVmICsgb2ZmICsgMTIsIGEsIHNpemVvZihhKSk7
IGluZXRfbnRvcChBRl9JTkVULCBidWYgKyBvZmYgKyAxNiwgYiwgc2l6ZW9mKGIpKTsKICBzaXpl
X3QgdG8gPSBvZmYgKyBpaGw7IHVuc2lnbmVkIHNwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25l
ZCBzaG9ydCAqKShidWYgKyB0bykpOyB1bnNpZ25lZCBkcG9ydCA9IG50b2hzKCooY29uc3QgdW5z
aWduZWQgc2hvcnQgKikoYnVmICsgdG8gKyAyKSk7IHVuc2lnbmVkIGRvZmYgPSAoYnVmW3RvICsg
MTJdID4+IDQpICogNDsgaWYgKG4gPCB0byArIGRvZmYpIHJldHVybiBmYWxzZTsgY29uc3QgY2hh
ciAqcGF5bG9hZCA9IChjb25zdCBjaGFyICopKGJ1ZiArIHRvICsgZG9mZik7IHNpemVfdCBwbGVu
ID0gbiAtIHRvIC0gZG9mZjsgaWYgKCFwbGVuKSByZXR1cm4gZmFsc2U7CiAgdGltZV90IG5vdyA9
IHRpbWUoTlVMTCk7CiAgYm9vbCBkc3RfbW9uID0gZmFsc2UsIHNyY19tb24gPSBmYWxzZTsKICBz
aXplX3QgajsKICBmb3IgKGogPSAwOyBqIDwgcG9ydHMuc2l6ZSgpOyArK2opIHsKICAgIGlmIChk
cG9ydCA9PSBwb3J0c1tqXSkgZHN0X21vbiA9IHRydWU7CiAgICBpZiAoc3BvcnQgPT0gcG9ydHNb
al0pIHNyY19tb24gPSB0cnVlOwogIH0KICBpZiAoc3JjX21vbiAmJiAhZHN0X21vbiAmJiBwbGVu
ID49IDUpIHsKICAgIHN0ZDo6c3RyaW5nIHNfcGF5KHBheWxvYWQsIHBsZW4pOwogICAgc2l6ZV90
IGhwb3MgPSBzX3BheS5maW5kKCJIVFRQLyIpOwogICAgaWYgKGhwb3MgIT0gc3RkOjpzdHJpbmc6
Om5wb3MpIHsKICAgICAgUGFja2V0S2V5IGs7CiAgICAgIGsuc3JjID0gYTsgay5zcG9ydCA9IHNw
b3J0OyBrLmRzdCA9IGI7IGsuZHBvcnQgPSBkcG9ydDsKICAgICAgc3RkOjptYXA8UGFja2V0S2V5
LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKGspOwog
ICAgICBpZiAocCAhPSBwZW5kaW5nLmVuZCgpICYmICFwLT5zZWNvbmQuZW1wdHkoKSkgewogICAg
ICAgIGludCBzdDsgdW5zaWduZWQgY2w7CiAgICAgICAgaWYgKHBhcnNlX3Jlc3BvbnNlKHNfcGF5
LnN1YnN0cihocG9zKSwgJnN0LCAmY2wpKSB7CiAgICAgICAgICBFdmVudCBlID0gcC0+c2Vjb25k
WzBdLmV2OwogICAgICAgICAgZS5zdGF0dXMgPSBzdDsgZS5oYXNfc3RhdHVzID0gdHJ1ZTsKICAg
ICAgICAgIGUuZHVyYXRpb25fbXMgPSAobG9uZykobm93X21zKCkgLSBwLT5zZWNvbmRbMF0uc3Rh
cnRlZF9tcyk7CiAgICAgICAgICBpZiAoZS5kdXJhdGlvbl9tcyA8IDApIGUuZHVyYXRpb25fbXMg
PSAwOwogICAgICAgICAgZS5oYXNfZHVyYXRpb24gPSB0cnVlOwogICAgICAgICAgaWYgKGNsKSB7
IGUucmVzcF9ieXRlcyA9IGNsOyBlLmhhc19yZXNwID0gdHJ1ZTsgfQogICAgICAgICAgZW1pdF9l
dmVudChlKTsKICAgICAgICAgIHAtPnNlY29uZC5lcmFzZShwLT5zZWNvbmQuYmVnaW4oKSk7CiAg
ICAgICAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICAgICAg
fQogICAgICB9CiAgICB9CiAgICByZXR1cm4gdHJ1ZTsKICB9CiAgaWYgKCFkc3RfbW9uKSByZXR1
cm4gZmFsc2U7CiAgc3RkOjpzdHJpbmcgZmsgPSBrZXlfc3RyaW5nKGEsIHNwb3J0LCBiLCBkcG9y
dCk7CiAgaWYgKGZsb3dzLmZpbmQoZmspID09IGZsb3dzLmVuZCgpICYmIGZsb3dzLnNpemUoKSA+
PSBNQVhfRkxPV1MpIHsKICAgIHRpbWVfdCBvbGRlc3RfdCA9IG5vdyArIDE7CiAgICBzdGQ6Om1h
cDxzdGQ6OnN0cmluZywgRmxvdz46Oml0ZXJhdG9yIG9sZGVzdF9pdCA9IGZsb3dzLmJlZ2luKCk7
CiAgICBmb3IgKHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBGbG93Pjo6aXRlcmF0b3IgZmkgPSBmbG93
cy5iZWdpbigpOyBmaSAhPSBmbG93cy5lbmQoKTsgKytmaSkgewogICAgICBpZiAoZmktPnNlY29u
ZC50b3VjaGVkIDwgb2xkZXN0X3QpIHsKICAgICAgICBvbGRlc3RfdCA9IGZpLT5zZWNvbmQudG91
Y2hlZDsKICAgICAgICBvbGRlc3RfaXQgPSBmaTsKICAgICAgfQogICAgfQogICAgaWYgKG9sZGVz
dF9pdCAhPSBmbG93cy5lbmQoKSkgZmxvd3MuZXJhc2Uob2xkZXN0X2l0KTsKICB9CiAgRmxvdyAm
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
aF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgaWYg
KHBvcnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OnZlY3RvcjxzdHJ1Y3Qgc29ja19m
aWx0ZXI+IGY7IHNpemVfdCBpOwogIC8qIER1YWwtcGF0aCBjQlBGOiBQYXRoIEEgKHN0YW5kYXJk
IElQdjQpIGFuZCBQYXRoIEIgKDgwMi4xUSBWTEFOIHRhZ2dlZCBJUHY0KS4gKi8KICB1bnNpZ25l
ZCBOID0gKHVuc2lnbmVkKXBvcnRzLnNpemUoKTsKICB1bnNpZ25lZCByZWplY3QgPSAxMSArIE4g
KiA4OwogIHVuc2lnbmVkIGFjY2VwdCA9IHJlamVjdCArIDE7CiAgc3RydWN0IHNvY2tfZmlsdGVy
IHg7CiNkZWZpbmUgQUREKEMsSixULEspIGRvIHsgeC5jb2RlPShDKTsgeC5qdD0oSik7IHguamY9
KFQpOyB4Lms9KEspOyBmLnB1c2hfYmFjayh4KTsgfSB3aGlsZSgwKQogIC8qIFswXSBMb2FkIEV0
aGVyVHlwZSBhdCBvZmZzZXQgMTIgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAs
IDEyKTsKICAvKiBbMV0gSWYgc3RhbmRhcmQgSVB2NCAoMHgwODAwKSwganVtcCBvdmVyIFBhdGgg
QiAoNiArIDQqTiBpbnN0cnVjdGlvbnMpIHRvIFBhdGggQSAqLwogIEFERChCUEZfSk1QfEJQRl9K
RVF8QlBGX0ssICh1bnNpZ25lZCkoNiArIDQgKiBOKSwgMCwgRVRIX1BfSVBfSE9TVCk7CgogIC8q
IC0tLSBQYXRoIEI6IDgwMi4xUSBWTEFOIChpbmRleCAyKSAtLS0gKi8KICAvKiBbMl0gSWYgbm90
IDgwMi4xUSAoMHg4MTAwKSwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywg
MCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRIX1BfODAy
MVFfSE9TVCk7CiAgLyogWzNdIExvYWQgZW5jYXBzdWxhdGVkIEV0aGVyVHlwZSBhdCBvZmZzZXQg
MTYgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAsIDE2KTsKICAvKiBbNF0gSWYg
ZW5jYXBzdWxhdGVkICE9IElQdjQsIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBG
X0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9Q
X0lQX0hPU1QpOwogIC8qIFs1XSBMb2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyNyAoMjMgKyA0
KSAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjcpOwogIC8qIFs2XSBJZiBu
b3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWdu
ZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJUFBST1RPX1RDUCk7CiAgLyog
WzddIExvYWQgSUhMIGF0IG9mZnNldCAxOCAoMTQgKyA0KSAqLwogIEFERChCUEZfTERYfEJQRl9C
fEJQRl9NU0gsIDAsIDAsIDE4KTsKICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNrcyBmb3IgVkxB
TiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9M
RHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAyMCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1
bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwg
MCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVja3MgZm9yIFZMQU4gKi8KICBm
b3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8
QlBGX0lORCwgMCwgMCwgMTgpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQp
Zi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8g
MCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQ
Rl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgLyogLS0tIFBhdGggQTogU3Rh
bmRhcmQgSVB2NCAtLS0gKi8KICAvKiBMb2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyMyAqLwog
IEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjMpOwogIC8qIElmIG5vdCBUQ1AsIHJl
amVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0
IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICAvKiBMb2FkIElITCBh
dCBvZmZzZXQgMTQgKi8KICBBREQoQlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxNCk7CiAg
LyogRGVzdGluYXRpb24gcG9ydCBjaGVja3MgZm9yIHN0YW5kYXJkIElQdjQgKi8KICBmb3IgKGkg
PSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lO
RCwgMCwgMCwgMTYpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXpl
KCkgLSAxOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIDAsIHBvcnRzW2ldKTsK
ICB9CiAgLyogU291cmNlIHBvcnQgY2hlY2tzIGZvciBzdGFuZGFyZCBJUHY0ICovCiAgZm9yIChp
ID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9J
TkQsIDAsIDAsIDE0KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6
ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gKGkgPCBwb3J0cy5zaXplKCkgLSAxKSA/IDAgOiAo
cmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSk7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVR
fEJQRl9LLCBqdCwgamYsIHBvcnRzW2ldKTsKICB9CgogIC8qIFtyZWplY3RdIERyb3AgcGFja2V0
ICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIDApOwogIC8qIFthY2NlcHRdIEFjY2VwdCBw
YWNrZXQgKDIwNDggYnl0ZXMpICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIEFDQ0VQVCk7
CiN1bmRlZiBBREQKICBpZiAoZi5zaXplKCkgPiA0MDk2KSByZXR1cm4gZmFsc2U7CiAgc3RydWN0
IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5sZW4gPSAodW5zaWduZWQgc2hvcnQpZi5zaXplKCk7IHBy
b2cuZmlsdGVyID0gJmZbMF07CiNpZm5kZWYgU09fQVRUQUNIX0ZJTFRFUgojZGVmaW5lIFNPX0FU
VEFDSF9GSUxURVIgMjYKI2VuZGlmCiAgcmV0dXJuIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQs
IFNPX0FUVEFDSF9GSUxURVIsICZwcm9nLCBzaXplb2YocHJvZykpID09IDA7Cn0KCnN0cnVjdCBN
bWFwUmluZyB7CiAgdm9pZCAqcmluZzsKICBzaXplX3QgcmluZ19zaXplOwogIHVuc2lnbmVkIGJs
b2NrX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfbnI7CiAgdW5zaWduZWQgZnJhbWVfc2l6ZTsKICB1
bnNpZ25lZCBmcmFtZV9ucjsKICB1bnNpZ25lZCBmcmFtZXNfcGVyX2Jsb2NrOwogIHVuc2lnbmVk
IGZyYW1lX2lkeDsKCiAgTW1hcFJpbmcoKSA6IHJpbmcoTUFQX0ZBSUxFRCksIHJpbmdfc2l6ZSgw
KSwgYmxvY2tfc2l6ZSg2NTUzNiksIGJsb2NrX25yKDY0KSwKICAgICAgICAgICAgICAgZnJhbWVf
c2l6ZSgyMDQ4KSwgZnJhbWVfbnIoMjA0OCksIGZyYW1lc19wZXJfYmxvY2soMzIpLCBmcmFtZV9p
ZHgoMCkge30KfTsKCnN0YXRpYyBib29sIHNldHVwX21tYXBfcmluZyhpbnQgZmQsIE1tYXBSaW5n
ICZtcikgewogIGludCB2ZXIgPSBUUEFDS0VUX1YyOwogIGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xf
UEFDS0VULCBQQUNLRVRfVkVSU0lPTiwgJnZlciwgc2l6ZW9mKHZlcikpIDwgMCkgewogICAgcmV0
dXJuIGZhbHNlOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9yZXEgcmVxOwogIG1lbXNldCgmcmVxLCAw
LCBzaXplb2YocmVxKSk7CiAgcmVxLnRwX2Jsb2NrX3NpemUgPSA2NTUzNjsKICByZXEudHBfYmxv
Y2tfbnIgPSA2NDsgICAgICAgLyogNE1CIHNoYXJlZCBtZW1vcnkgcmluZyBidWZmZXIgKi8KICBy
ZXEudHBfZnJhbWVfc2l6ZSA9IDIwNDg7ICAgLyogMktCIHBlciBmcmFtZSAqLwogIHJlcS50cF9m
cmFtZV9uciA9IChyZXEudHBfYmxvY2tfc2l6ZSAqIHJlcS50cF9ibG9ja19ucikgLyByZXEudHBf
ZnJhbWVfc2l6ZTsgLyogMjA0OCBmcmFtZXMgKi8KCiAgaWYgKHNldHNvY2tvcHQoZmQsIFNPTF9Q
QUNLRVQsIFBBQ0tFVF9SWF9SSU5HLCAmcmVxLCBzaXplb2YocmVxKSkgPCAwKSB7CiAgICByZXR1
cm4gZmFsc2U7CiAgfQogIG1yLnJpbmdfc2l6ZSA9IChzaXplX3QpcmVxLnRwX2Jsb2NrX3NpemUg
KiByZXEudHBfYmxvY2tfbnI7CiAgbXIuYmxvY2tfc2l6ZSA9IHJlcS50cF9ibG9ja19zaXplOwog
IG1yLmJsb2NrX25yID0gcmVxLnRwX2Jsb2NrX25yOwogIG1yLmZyYW1lX3NpemUgPSByZXEudHBf
ZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9uciA9IHJlcS50cF9mcmFtZV9ucjsKICBtci5mcmFtZXNf
cGVyX2Jsb2NrID0gcmVxLnRwX2Jsb2NrX3NpemUgLyByZXEudHBfZnJhbWVfc2l6ZTsKICBtci5m
cmFtZV9pZHggPSAwOwoKICBtci5yaW5nID0gbW1hcChOVUxMLCBtci5yaW5nX3NpemUsIFBST1Rf
UkVBRCB8IFBST1RfV1JJVEUsIE1BUF9TSEFSRUQsIGZkLCAwKTsKICBpZiAobXIucmluZyA9PSBN
QVBfRkFJTEVEKSB7CiAgICBtci5yaW5nX3NpemUgPSAwOwogICAgcmV0dXJuIGZhbHNlOwogIH0K
ICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGludCBydW5fZml4dHVyZSgpIHsKICBzdGQ6OnN0cmlu
ZyByZXEgPSAiR0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJcbkhvc3Q6IGFwaS5sb2NhbFxy
XG5BdXRob3JpemF0aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYwXHJcblRyYWNlcGFyZW50OiAw
MC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIzNDU2Nzg5YWJjZGVmLTAxXHJc
blxyXG4iOwogIEV2ZW50IGU7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAiY3BwLW5vZGUi
OyBlLnNlcnZpY2UgPSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjkiOyBlLmNhbGxl
cl9wb3J0ID0gNTEwMDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9ydCA9IDgwODA7
IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVlc3QocmVxLnN1
YnN0cigwLCByZXEuc2l6ZSgpIC0gNCksICZlKTsgZS5zdGF0dXMgPSAyMDA7IGUuaGFzX3N0YXR1
cyA9IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlvbiA9IHRydWU7IGUucmVz
cF9ieXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVudChlKTsgcmV0dXJuIDA7
Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikgewogIGlmIChhcmdjID4gMSAmJiAh
c3RyY21wKGFyZ3ZbMV0sICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7CiAgc3Rk
OjpzdHJpbmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0czsgaW50IGk7IGludCB3
b3JrZXJzID0gMTsKICBmb3IgKGkgPSAxOyBpIDwgYXJnYzsgKytpKSB7CiAgICBpZiAoIXN0cmNt
cChhcmd2W2ldLCAiLWkiKSAmJiBpICsgMSA8IGFyZ2MpIGlmYWNlID0gYXJndlsrK2ldOwogICAg
ZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLXAiKSAmJiBpICsgMSA8IGFyZ2MpIHsKICAgICAg
d2hpbGUgKGkgKyAxIDwgYXJnYyAmJiBhcmd2W2kgKyAxXVswXSAhPSAnLScpIHsKICAgICAgICBj
aGFyICpxID0gc3RydG9rKGFyZ3ZbKytpXSwgIiwgIik7CiAgICAgICAgd2hpbGUgKHEpIHsgbG9u
ZyBwID0gYXRvbChxKTsgaWYgKHZhbGlkX3BvcnQoKHVuc2lnbmVkKXApKSBwb3J0cy5wdXNoX2Jh
Y2soKHVuc2lnbmVkKXApOyBxID0gc3RydG9rKE5VTEwsICIsICIpOyB9CiAgICAgIH0KICAgIH0K
ICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1qIikgJiYgaSArIDEgPCBhcmdjKSB3b3Jr
ZXJzID0gYXRvaShhcmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWgi
KSkgeyBmcHJpbnRmKHN0ZGVyciwgInVzYWdlOiBudC1zbmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAg
cG9ydHNdIFstaiB3b3JrZXJzXVxuIik7IHJldHVybiAwOyB9CiAgfQogIGlmIChwb3J0cy5lbXB0
eSgpKSB7IHBvcnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9ydHMu
cHVzaF9iYWNrKDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFjayg4
MDA5KTsgcG9ydHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0KICAo
dm9pZCl3b3JrZXJzOwogIHN0ZDo6c3RyaW5nIG5vZGUgPSBob3N0X25hbWUoKTsKICBpbnQgZmQg
PSBzb2NrZXQoQUZfUEFDS0VULCBTT0NLX1JBVywgaHRvbnMoMykpOwogIGlmIChmZCA8IDApIHsg
cGVycm9yKCJBRl9QQUNLRVQiKTsgcmV0dXJuIDI7IH0KICBpbnQgcmIgPSA4ICogMTAyNCAqIDEw
MjQ7CiAgc2V0c29ja29wdChmZCwgU09MX1NPQ0tFVCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihy
YikpOwogIGlmICghYXR0YWNoX2JwZihmZCwgcG9ydHMpKSBsb2dtc2coIldBUk46IEJQRiBhdHRh
Y2ggZmFpbGVkOyBjb250aW51aW5nIHVuZmlsdGVyZWQiKTsKCiAgTW1hcFJpbmcgcmluZzsKICBi
b29sIHVzZV9tbWFwID0gc2V0dXBfbW1hcF9yaW5nKGZkLCByaW5nKTsKCiAgc3RydWN0IHNvY2th
ZGRyX2xsIHNhOwogIG1lbXNldCgmc2EsIDAsIHNpemVvZihzYSkpOwogIHNhLnNsbF9mYW1pbHkg
PSBBRl9QQUNLRVQ7CiAgc2Euc2xsX3Byb3RvY29sID0gaHRvbnMoMyk7CiAgaWYgKCFpZmFjZS5l
bXB0eSgpKSB7CiAgICBzYS5zbGxfaWZpbmRleCA9IChpbnQpaWZfbmFtZXRvaW5kZXgoaWZhY2Uu
Y19zdHIoKSk7CiAgICBpZiAoIXNhLnNsbF9pZmluZGV4KSB7IGxvZ21zZygiYmFkIGludGVyZmFj
ZSIpOyBjbG9zZShmZCk7IHJldHVybiAyOyB9CiAgfQogIGlmIChiaW5kKGZkLCAoc3RydWN0IHNv
Y2thZGRyICopJnNhLCBzaXplb2Yoc2EpKSA8IDApIHsgcGVycm9yKCJiaW5kIik7IGNsb3NlKGZk
KTsgcmV0dXJuIDI7IH0KCiAgc2lnbmFsKFNJR1RFUk0sIHN0b3Bfc2lnbmFsKTsKICBzaWduYWwo
U0lHSU5ULCBzdG9wX3NpZ25hbCk7CiAgc3RkOjptYXA8c3RkOjpzdHJpbmcsIEZsb3c+IGZsb3dz
OwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiBwZW5kaW5nOwoK
ICBpZiAodXNlX21tYXApIHsKICAgIGxvZ21zZygiUEFDS0VUX01NQVAgKFRQQUNLRVRfVjIpIHpl
cm8tY29weSByaW5nIGVuYWJsZWQgKDRNQiwgMjA0OCBmcmFtZXMpIik7CiAgfSBlbHNlIHsKICAg
IGxvZ21zZygiV0FSTjogUEFDS0VUX01NQVAgc2V0dXAgZmFpbGVkLCBmYWxsaW5nIGJhY2sgdG8g
c3RhbmRhcmQgc29ja2V0IHJlY3YiKTsKICB9CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKCiAgdGlt
ZV90IGxhc3QgPSB0aW1lKE5VTEwpOwogIHVuc2lnbmVkIGNoYXIgKmZhbGxiYWNrX2J1ZiA9IE5V
TEw7CiAgaWYgKCF1c2VfbW1hcCkgewogICAgZmFsbGJhY2tfYnVmID0gKHVuc2lnbmVkIGNoYXIg
KiltYWxsb2MoNjU1MzYpOwogICAgaWYgKCFmYWxsYmFja19idWYpIHsKICAgICAgY2xvc2UoZmQp
OwogICAgICBsb2dtc2coImJ1ZmZlciBhbGxvY2F0aW9uIGZhaWxlZCIpOwogICAgICByZXR1cm4g
MjsKICAgIH0KICB9CgogIHN0cnVjdCBwb2xsZmQgcGZkOwogIHBmZC5mZCA9IGZkOwogIHBmZC5l
dmVudHMgPSBQT0xMSU4gfCBQT0xMRVJSOwogIHBmZC5yZXZlbnRzID0gMDsKCiAgd2hpbGUgKGdf
cnVubmluZykgewogICAgaW50IHJjID0gcG9sbCgmcGZkLCAxLCAxMDAwKTsKICAgIGlmIChyYyA8
IDAgJiYgZXJybm8gPT0gRUlOVFIpIHsKICAgICAgLyogU2lnbmFsIGhhbmRsZWQsIGxvb3AgY29u
ZGl0aW9uIHdpbGwgY2hlY2sgZ19ydW5uaW5nICovCiAgICB9IGVsc2UgaWYgKHJjID49IDApIHsK
ICAgICAgaWYgKHVzZV9tbWFwKSB7CiAgICAgICAgLyogRHJhaW4gYWxsIHJlYWR5IGZyYW1lcyBp
biB0aGUgcmluZyB3aXRob3V0IGV4dHJhIHN5c2NhbGxzICovCiAgICAgICAgd2hpbGUgKGdfcnVu
bmluZykgewogICAgICAgICAgdW5zaWduZWQgYl9pZHggPSByaW5nLmZyYW1lX2lkeCAvIHJpbmcu
ZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICAgIHVuc2lnbmVkIGZfaW5fYiA9IHJpbmcuZnJhbWVf
aWR4ICUgcmluZy5mcmFtZXNfcGVyX2Jsb2NrOwogICAgICAgICAgdWludDhfdCAqZnJhbWVfcHRy
ID0gKCh1aW50OF90ICopcmluZy5yaW5nKSArIChiX2lkeCAqIHJpbmcuYmxvY2tfc2l6ZSkgKyAo
Zl9pbl9iICogcmluZy5mcmFtZV9zaXplKTsKICAgICAgICAgIHN0cnVjdCB0cGFja2V0Ml9oZHIg
KmhkciA9IChzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVfcHRyOwoKICAgICAgICAgIGlmICgh
KGhkci0+dHBfc3RhdHVzICYgVFBfU1RBVFVTX1VTRVIpKSB7CiAgICAgICAgICAgIGJyZWFrOyAv
KiBObyBtb3JlIGtlcm5lbC1wb3B1bGF0ZWQgZnJhbWVzIGluIHJpbmcgcmlnaHQgbm93ICovCiAg
ICAgICAgICB9CgogICAgICAgICAgaWYgKGhkci0+dHBfc25hcGxlbiA+IDApIHsKICAgICAgICAg
ICAgY29uc3QgdW5zaWduZWQgY2hhciAqcGt0ID0gKChjb25zdCB1bnNpZ25lZCBjaGFyICopaGRy
KSArIGhkci0+dHBfbWFjOwogICAgICAgICAgICBoYW5kbGVfcGFja2V0KHBrdCwgKHNpemVfdClo
ZHItPnRwX3NuYXBsZW4sIG5vZGUsIHBvcnRzLCBmbG93cywgcGVuZGluZyk7CiAgICAgICAgICB9
CgogICAgICAgICAgaGRyLT50cF9zdGF0dXMgPSBUUF9TVEFUVVNfS0VSTkVMOyAvKiBSZXR1cm4g
ZnJhbWUgb3duZXJzaGlwIHRvIGtlcm5lbCAqLwogICAgICAgICAgcmluZy5mcmFtZV9pZHggPSAo
cmluZy5mcmFtZV9pZHggKyAxKSAlIHJpbmcuZnJhbWVfbnI7CiAgICAgICAgfQogICAgICB9IGVs
c2UgewogICAgICAgIGlmIChwZmQucmV2ZW50cyAmIFBPTExJTikgewogICAgICAgICAgc3NpemVf
dCBuID0gcmVjdihmZCwgZmFsbGJhY2tfYnVmLCA2NTUzNiwgMCk7CiAgICAgICAgICBpZiAobiA+
IDApIGhhbmRsZV9wYWNrZXQoZmFsbGJhY2tfYnVmLCAoc2l6ZV90KW4sIG5vZGUsIHBvcnRzLCBm
bG93cywgcGVuZGluZyk7CiAgICAgICAgfQogICAgICB9CiAgICB9CgogICAgdGltZV90IG5vdyA9
IHRpbWUoTlVMTCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVwKGZsb3dz
LCBwZW5kaW5nLCBub3cpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogIH0KCiAgaWYgKHVzZV9t
bWFwICYmIHJpbmcucmluZyAhPSBNQVBfRkFJTEVEKSB7CiAgICBtdW5tYXAocmluZy5yaW5nLCBy
aW5nLnJpbmdfc2l6ZSk7CiAgfQogIGlmIChmYWxsYmFja19idWYpIGZyZWUoZmFsbGJhY2tfYnVm
KTsKICBjbG9zZShmZCk7CiAgbG9nbXNnKCJzdG9wcGVkIik7CiAgcmV0dXJuIDA7Cn0K
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
