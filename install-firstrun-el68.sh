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
        RUN_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT' >>\$PREFIX/sniff.log 2>&1"
    else
        RUN_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT >>\$PREFIX/sniff.log 2>&1"
    fi
    log "native C++ single-binary capture + shipping selected"
else
    if [ "$SNIFF_AS" != root ]; then
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
    fi
    SHIP_CMD="exec python -u $PREFIX/nt-ship.py --endpoint $ENDPOINT"
    RUN_CMD="$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1"
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
        nohup sh -c "$RUN_CMD" >/dev/null 2>&1 &
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
IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KICAgIHJ1bm5pbmcgPSBbVHJ1ZV0K
CiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UK
ICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2lnbmFs
KHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgZGVmIGZsdXNoKGJhdGNoKToKICAgICAgICBpZiBu
b3QgYmF0Y2g6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgYm9keSA9IGpzb24uZHVt
cHMoeyJub2RlIjogbm9kZSwgImV2ZW50cyI6IGJhdGNofSkKICAgICAgICAjIHB5MiB1cmxsaWIy
IGFjY2VwdHMgc3RyOyBweTMgc2hpbS90ZXN0IG5lZWRzIGJ5dGVzIOKAlCBlbmNvZGUgd2hlbgog
ICAgICAgICMgdGhlIHJ1bnRpbWUgZXhwb3NlcyBpdCAocHkyIHN0ciBoYXMgbm8gLmVuY29kZSBv
biBhbGwgYnVpbGRzLCBzbwogICAgICAgICMgZ3VhcmQgd2l0aCBoYXNhdHRyKQogICAgICAgIGlm
IGhhc2F0dHIoYm9keSwgImVuY29kZSIpOgogICAgICAgICAgICBib2R5ID0gYm9keS5lbmNvZGUo
InV0Zi04IikKICAgICAgICByZXEgPSB1cmxsaWIyLlJlcXVlc3QoZW5kcG9pbnQgKyAiL2FwaS9p
bmdlc3QiLCBkYXRhPWJvZHksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9
eyJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiJ9KQogICAgICAgIHRyeToKICAgICAg
ICAgICAgcmVzcCA9IHVybGxpYjIudXJsb3BlbihyZXEsIHRpbWVvdXQ9MTApCiAgICAgICAgICAg
IG9rID0gKHJlc3AuZ2V0Y29kZSgpID09IDIwMCkKICAgICAgICAgICAgcmVzcC5yZWFkKCkKICAg
ICAgICAgICAgcmVzcC5jbG9zZSgpCiAgICAgICAgICAgIGlmIG9rOgogICAgICAgICAgICAgICAg
bG9nKCJmbHVzaGVkICVkIGV2ZW50cyIgJSBsZW4oYmF0Y2gpKQogICAgICAgICAgICByZXR1cm4g
b2sKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIGxvZygic2hpcCBm
YWlsZWQ6ICVzIiAlIGUpCiAgICAgICAgICAgIHJldHVybiBGYWxzZQoKICAgICMgLS0tLSBjb25j
dXJyZW50IHNoaXBwaW5nIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0KICAgICMgaHViIGluZ2VzdCBsYXRlbmN5ICh+MzAwLTUwMG1zIHBlciA0MDAtZXZlbnQgUE9T
VCBvdmVyIFdBTikgbWFrZXMKICAgICMgc2VxdWVudGlhbCBwb3N0aW5nIGEgfjEwMDAgZXYvcyBj
ZWlsaW5nOyBOIHBvc3RlciB0aHJlYWRzIHBvc3RpbmcKICAgICMgaW5kZXBlbmRlbnQgYmF0Y2hl
cyBtdWx0aXBseSB0aGF0IGJ5IE5UX1NISVBfVEhSRUFEUwogICAgcSA9IFF1ZXVlLlF1ZXVlKG1h
eHNpemU9MTI4KQogICAgc3Bvb2xfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkKICAgIG50aHJlYWRz
ID0gaW50KG9zLmVudmlyb24uZ2V0KCJOVF9TSElQX1RIUkVBRFMiLCAiNCIpKQoKICAgIGRlZiBw
b3N0ZXIoKToKICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBiYXRjaCA9IHEuZ2V0KCkK
ICAgICAgICAgICAgaWYgYmF0Y2ggaXMgTm9uZToKICAgICAgICAgICAgICAgIHEudGFza19kb25l
KCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBub3QgZmx1c2goYmF0Y2gp
OgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiBIdWIgdW5yZWFjaGFibGUsIGRyb3BwZWQgJWQg
ZXZlbnRzIChpbi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTykiICUgbGVuKGJhdGNoKSkKICAgICAg
ICAgICAgcS50YXNrX2RvbmUoKQoKICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAgICAg
ICB0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgIHQuZGFlbW9uID0g
VHJ1ZQogICAgICAgIHQuc3RhcnQoKQoKICAgIGJ1ZiA9IFtdCiAgICBsYXN0X2ZsdXNoID0gdGlt
ZS50aW1lKCkKCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAg
ciwgXywgXyA9IHNlbGVjdC5zZWxlY3QoW3N5cy5zdGRpbl0sIFtdLCBbXSwgMS4wKQogICAgICAg
IGV4Y2VwdCBzZWxlY3QuZXJyb3IgYXMgZToKICAgICAgICAgICAgaWYgZVswXSA9PSBlcnJuby5F
SU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGJyZWFrCgogICAgICAg
IGlmIHI6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHJhdyA9IHN5cy5zdGRpbi5y
ZWFkbGluZSgpCiAgICAgICAgICAgIGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJvcikgYXMgZToKICAg
ICAgICAgICAgICAgIGlmIGdldGF0dHIoZSwgJ2Vycm5vJywgTm9uZSkgPT0gZXJybm8uRUlOVFI6
CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAg
ICAgICAgIGlmIG5vdCByYXc6CiAgICAgICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAg
ICMgRU9GCiAgICAgICAgICAgIHJhdyA9IHJhdy5zdHJpcCgpCiAgICAgICAgICAgIGlmIHJhdzoK
ICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBldiA9IGpzb24ubG9hZHMo
cmF3KQogICAgICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2UoZXYsIGRpY3QpOgogICAgICAg
ICAgICAgICAgICAgICAgICBpZiBsZW4oYnVmKSA+PSA0MDAwOgogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgZGVsIGJ1ZlswXQogICAgICAgICAgICAgICAgICAgICAgICBidWYuYXBwZW5kKGV2
KQogICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAg
cGFzcwoKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIHdoaWxlIGxlbihidWYpID49
IE1BWF9CQVRDSCBvciAoYnVmIGFuZCBub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyk6CiAg
ICAgICAgICAgIGxhc3RfZmx1c2ggPSBub3cKICAgICAgICAgICAgcS5wdXQoYnVmWzpNQVhfQkFU
Q0hdKQogICAgICAgICAgICBkZWwgYnVmWzpNQVhfQkFUQ0hdCgogICAgIyBzdGRpbiBjbG9zZWQg
KHNuaWZmZXIgc3RvcHBlZCkg4oCUIGRyYWluIGluLW1lbW9yeSBxdWV1ZQogICAgcS5qb2luKCkK
ICAgIGxvZygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRpbmcgb24gZXhpdCkiICUgbGVuKGJ1Zikp
CgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQo=
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
IG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIiciOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1i
ZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVy
biBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29uX2FycmF5KGNvbnN0IHN0ZDo6dmVj
dG9yPHN0ZDo6c3RyaW5nPiAmYSkgewogIHN0ZDo6c3RyaW5nIG89IlsiOyBmb3Ioc2l6ZV90IGk9
MDtpPGEuc2l6ZSgpOysraSl7aWYoaSlvKz0iLCI7bys9YVtpXTt9IHJldHVybiBvKyJdIjsKfQpz
dGF0aWMgYm9vbCBwb3N0KGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCwgY29uc3Qgc3RkOjpz
dHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJp
bmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHk9IntcIm5vZGVcIjoiK2pzb25xKG5vZGUp
KyIsXCJldmVudHNcIjoiK2pzb25fYXJyYXkoYmF0Y2gpKyJ9IjsKICBzdGQ6OnN0cmluZyBjbWQ9
ImN1cmwgLXNTZiAtLW1heC10aW1lIDEwIC1vIC9kZXYvbnVsbCAtSCAnQ29udGVudC1UeXBlOiBh
cHBsaWNhdGlvbi9qc29uJyAtLWRhdGEtYmluYXJ5IEAtICIrc2hlbGxxKGVuZHBvaW50KyIvYXBp
L2luZ2VzdCIpOwogIEZJTEUgKmZwPXBvcGVuKGNtZC5jX3N0cigpLCJ3Iik7IGlmKCFmcCkgcmV0
dXJuIGZhbHNlOwogIGZ3cml0ZShib2R5LmRhdGEoKSwgMSwgYm9keS5zaXplKCksIGZwKTsKICBp
bnQgcmM9cGNsb3NlKGZwKTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRVUyhy
YykgPT0gMDsKfQpzdGF0aWMgdm9pZCBzZW5kX2JhdGNoZXMoY29uc3Qgc3RkOjpzdHJpbmcgJmVu
ZHBvaW50LGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlLAogICAgICAgICAgICAgICAgICAgICAgICAg
c3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICpidWYsIGJvb2wgZmx1c2hfYWxsKSB7CiAgd2hpbGUg
KCFidWYtPmVtcHR5KCkgJiYgKGZsdXNoX2FsbCB8fCBidWYtPnNpemUoKSA+PSBNQVhfQkFUQ0gp
KSB7CiAgICBzaXplX3Qgbj1idWYtPnNpemUoKT49TUFYX0JBVENIP01BWF9CQVRDSDpidWYtPnNp
emUoKTsKICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBiYXRjaChidWYtPmJlZ2luKCksYnVm
LT5iZWdpbigpK24pOwogICAgaWYocG9zdChlbmRwb2ludCxub2RlLGJhdGNoKSkgewogICAgICBi
dWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7CiAgICAgIGxvZ21zZygiZmx1
c2hlZCAiK251bWJlcl9zdHJpbmcobikrIiBldmVudHMiKTsKICAgIH0gZWxzZSB7CiAgICAgIGJ1
Zi0+ZXJhc2UoYnVmLT5iZWdpbigpLGJ1Zi0+YmVnaW4oKStuKTsKICAgICAgbG9nbXNnKCJXQVJO
OiBIdWIgdW5yZWFjaGFibGUsIGRyb3BwZWQgIitudW1iZXJfc3RyaW5nKG4pKyIgZXZlbnRzIChp
bi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTykiKTsKICAgICAgYnJlYWs7CiAgICB9CiAgfQp9Cmlu
dCBtYWluKGludCBhcmdjLGNoYXIgKiphcmd2KSB7CiAgc3RkOjpzdHJpbmcgZW5kcG9pbnQ7IGlu
dCBpOwogIGZvcihpPTE7aTxhcmdjOysraSl7c3RkOjpzdHJpbmcgYT1hcmd2W2ldOyBpZihhPT0i
LS1lbmRwb2ludCImJmkrMTxhcmdjKWVuZHBvaW50PWFyZ3ZbKytpXTsgZWxzZSBpZihhPT0iLS1z
cG9vbCImJmkrMTxhcmdjKSsraTsgZWxzZSBpZihhPT0iLWgifHxhPT0iLS1oZWxwIil7c3RkOjpj
b3V0PDwidXNhZ2U6IG50LXNoaXAtY3BwIC0tZW5kcG9pbnQgVVJMXG4iO3JldHVybiAwO30gZWxz
ZSB7c3RkOjpjZXJyPDwidW5rbm93biBhcmc6ICI8PGE8PCJcbiI7cmV0dXJuIDI7fX0KICBpZihl
bmRwb2ludC5lbXB0eSgpKXtzdGQ6OmNlcnI8PCItLWVuZHBvaW50IHJlcXVpcmVkXG4iO3JldHVy
biAyO30KICBzaWduYWwoU0lHVEVSTSxzdG9wX3NpZ25hbCk7IHNpZ25hbChTSUdJTlQsc3RvcF9z
aWduYWwpOwogIGNoYXIgaG9zdFsyNTZdOyBnZXRob3N0bmFtZShob3N0LHNpemVvZihob3N0KSk7
IGhvc3Rbc2l6ZW9mKGhvc3QpLTFdPTA7CiAgY29uc3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYo
Ik5UX05PREVfTkFNRSIpOwogIHN0ZDo6c3RyaW5nIG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVf
ZW52KSA/IG5vZGVfZW52IDogaG9zdDsKICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gYnVmOyB0
aW1lX3QgbGFzdD10aW1lKE5VTEwpOwogIHN0ZDo6c3RyaW5nIGxpbmU7CiAgd2hpbGUocnVubmlu
ZykgewogICAgZmRfc2V0IHI7IEZEX1pFUk8oJnIpOyBGRF9TRVQoMCwgJnIpOwogICAgc3RydWN0
IHRpbWV2YWwgdHY7IHR2LnR2X3NlYyA9IDE7IHR2LnR2X3VzZWMgPSAwOwogICAgaW50IHJjID0g
c2VsZWN0KDEsICZyLCBOVUxMLCBOVUxMLCAmdHYpOwogICAgaWYgKHJjID4gMCAmJiBGRF9JU1NF
VCgwLCAmcikpIHsKICAgICAgd2hpbGUgKHJ1bm5pbmcgJiYgc3RkOjpjaW4gJiYgYnVmLnNpemUo
KSA8IE1BWF9RVUVVRSkgewogICAgICAgIGlmICghc3RkOjpnZXRsaW5lKHN0ZDo6Y2luLCBsaW5l
KSkgYnJlYWs7CiAgICAgICAgaWYgKCFsaW5lLmVtcHR5KCkpIHsKICAgICAgICAgIGlmIChidWYu
c2l6ZSgpID49IE1BWF9RVUVVRSkgYnVmLmVyYXNlKGJ1Zi5iZWdpbigpKTsKICAgICAgICAgIGJ1
Zi5wdXNoX2JhY2sobGluZSk7CiAgICAgICAgfQogICAgICAgIGlmIChidWYuc2l6ZSgpID49IE1B
WF9CQVRDSCkgewogICAgICAgICAgc2VuZF9iYXRjaGVzKGVuZHBvaW50LCBub2RlLCAmYnVmLCBm
YWxzZSk7CiAgICAgICAgfQogICAgICAgIGlmIChzdGQ6OmNpbi5yZGJ1ZigpLT5pbl9hdmFpbCgp
IDw9IDApIGJyZWFrOwogICAgICB9CiAgICB9CiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsK
ICAgIGlmIChub3cgLSBsYXN0ID49IEZMVVNIX1NFQyB8fCBidWYuc2l6ZSgpID49IE1BWF9CQVRD
SCkgewogICAgICBpZiAoIWJ1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMoZW5kcG9pbnQsIG5vZGUs
ICZidWYsIHRydWUpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogIH0KICBpZiAoIWJ1Zi5lbXB0
eSgpKSBzZW5kX2JhdGNoZXMoZW5kcG9pbnQsbm9kZSwmYnVmLHRydWUpOwogIGxvZ21zZygic3Rv
cHBlZCIpOyByZXR1cm4gMDsKfQo=
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
IDxpb3N0cmVhbT4KI2luY2x1ZGUgPGZzdHJlYW0+CiNpbmNsdWRlIDxtYXA+CiNpbmNsdWRlIDxz
c3RyZWFtPgojaW5jbHVkZSA8c3RyaW5nPgojaW5jbHVkZSA8dmVjdG9yPgoKc3RhdGljIHZvbGF0
aWxlIHNpZ19hdG9taWNfdCBnX3J1bm5pbmcgPSAxOwpzdGF0aWMgdm9pZCBzdG9wX3NpZ25hbChp
bnQpIHsgZ19ydW5uaW5nID0gMDsgfQoKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfRkxPV1MgPSA4
MTkyOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QRU5ESU5HID0gODE5MjsKc3RhdGljIGNvbnN0
IHNpemVfdCBNQVhfSEVBREVSID0gMjYyMTQ0OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9CQVRD
SCA9IDQwMDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUVVFVUUgPSA0MDAwOwpzdGF0aWMgY29u
c3QgaW50IEZMVVNIX1NFQyA9IDU7CnN0YXRpYyBjb25zdCBpbnQgUkVUUllfU0VDID0gNjA7CnN0
YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RUTCA9IDE1OwpzdGF0aWMgY29uc3QgdW5zaWduZWQg
UEVORElOR19UVEwgPSAzOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgQUNDRVBUID0gMjA0ODsKc3Rh
dGljIGNvbnN0IGludCBTT19BVFRBQ0hfRklMVEVSX09MRCA9IDI2OwpzdGF0aWMgY29uc3QgdW5z
aWduZWQgc2hvcnQgRVRIX1BfSVBfSE9TVCA9IDB4MDgwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVk
IHNob3J0IEVUSF9QXzgwMjFRX0hPU1QgPSAweDgxMDA7CgpzdGF0aWMgc3RkOjpzdHJpbmcgdHJp
bShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHNpemVfdCBhID0gMCwgYiA9IHMuc2l6ZSgpOwog
IHdoaWxlIChhIDwgYiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKXNbYV0pKSArK2E7CiAgd2hp
bGUgKGIgPiBhICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1tiIC0gMV0pKSAtLWI7CiAgcmV0
dXJuIHMuc3Vic3RyKGEsIGIgLSBhKTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbG93ZXIoY29uc3Qg
c3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyB4ID0gczsKICBzaXplX3QgaTsgZm9yIChp
ID0gMDsgaSA8IHguc2l6ZSgpOyArK2kpIHhbaV0gPSAoY2hhcil0b2xvd2VyKCh1bnNpZ25lZCBj
aGFyKXhbaV0pOwogIHJldHVybiB4Owp9CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29ucShjb25zdCBz
dGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSAiXCIiOyBzaXplX3QgaTsKICBmb3Ig
KGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2ln
bmVkIGNoYXIpc1tpXTsKICAgIGlmIChjID09ICdcXCcgfHwgYyA9PSAnIicpIHsgeCArPSAnXFwn
OyB4ICs9IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAg
IGVsc2UgaWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0Jykg
eCArPSAiXFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0g
KGNoYXIpYzsKICB9CiAgeCArPSAnIic7IHJldHVybiB4Owp9CnN0YXRpYyBsb25nIGxvbmcgbm93
X21zKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2OyBnZXR0aW1lb2ZkYXkoJnR2LCBOVUxMKTsKICBy
ZXR1cm4gKGxvbmcgbG9uZyl0di50dl9zZWMgKiAxMDAwTEwgKyB0di50dl91c2VjIC8gMTAwMDsK
fQpzdGF0aWMgc3RkOjpzdHJpbmcgbnVtKGxvbmcgdikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsg
byA8PCB2OyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgYm9vbCB2YWxpZF9wb3J0KHVuc2lnbmVk
IHApIHsgcmV0dXJuIHAgPiAwICYmIHAgPD0gNjU1MzU7IH0Kc3RhdGljIGJvb2wgaGFzX21ldGhv
ZChjb25zdCBzdGQ6OnN0cmluZyAmbSkgewogIHJldHVybiBtID09ICJHRVQiIHx8IG0gPT0gIlBP
U1QiIHx8IG0gPT0gIlBVVCIgfHwgbSA9PSAiREVMRVRFIiB8fAogICAgICAgICBtID09ICJQQVRD
SCIgfHwgbSA9PSAiSEVBRCIgfHwgbSA9PSAiT1BUSU9OUyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5n
IGhvc3RfbmFtZSgpIHsKICBjaGFyIGJbMjU2XTsgaWYgKGdldGhvc3RuYW1lKGIsIHNpemVvZihi
KSAtIDEpICE9IDApIHJldHVybiAidW5rbm93bi1ub2RlIjsKICBiW3NpemVvZihiKSAtIDFdID0g
MDsgY2hhciAqcCA9IHN0cmNocihiLCAnLicpOyBpZiAocCkgKnAgPSAwOyByZXR1cm4gYjsKfQpz
dGF0aWMgc3RkOjpzdHJpbmcgYjY0ZGVjb2RlX3VzZXIoY29uc3Qgc3RkOjpzdHJpbmcgJnYpIHsK
ICBzdGQ6OnN0cmluZyBpbiA9IHRyaW0odiksIG91dDsgaW50IHZhbCA9IDAsIGJpdHMgPSAtODsg
c2l6ZV90IGk7CiAgZm9yIChpID0gMDsgaSA8IGluLnNpemUoKTsgKytpKSB7CiAgICB1bnNpZ25l
ZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilpbltpXTsgaW50IGQgPSAtMTsKICAgIGlmIChjID49
ICdBJyAmJiBjIDw9ICdaJykgZCA9IGMgLSAnQSc7CiAgICBlbHNlIGlmIChjID49ICdhJyAmJiBj
IDw9ICd6JykgZCA9IGMgLSAnYScgKyAyNjsKICAgIGVsc2UgaWYgKGMgPj0gJzAnICYmIGMgPD0g
JzknKSBkID0gYyAtICcwJyArIDUyOwogICAgZWxzZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsKICAg
IGVsc2UgaWYgKGMgPT0gJy8nKSBkID0gNjM7CiAgICBlbHNlIGlmIChjID09ICc9JykgYnJlYWs7
CiAgICBpZiAoZCA8IDApIGNvbnRpbnVlOwogICAgdmFsID0gKHZhbCA8PCA2KSArIGQ7CiAgICBi
aXRzICs9IDY7CiAgICBpZiAoYml0cyA+PSAwKSB7CiAgICAgIG91dCArPSAoY2hhcikoKHZhbCA+
PiBiaXRzKSAmIDB4ZmYpOwogICAgICBiaXRzIC09IDg7CiAgICAgIGlmIChvdXQuc2l6ZSgpID4g
NTEyKSByZXR1cm4gIiI7CiAgICB9CiAgfQogIHNpemVfdCBwID0gb3V0LmZpbmQoJzonKTsKICBp
ZiAocCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuICIiOwogIHJldHVybiBvdXQuc3Vic3Ry
KDAsIHAgPiA2NCA/IDY0IDogcCk7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGlwX3RvX3N0cih1aW50
MzJfdCBpcF9iZSkgewogIGNoYXIgYltJTkVUX0FERFJTVFJMRU5dOwogIGluZXRfbnRvcChBRl9J
TkVULCAmaXBfYmUsIGIsIHNpemVvZihiKSk7CiAgcmV0dXJuIGI7Cn0KCnN0YXRpYyBzdGQ6OnN0
cmluZyB0cmFjZV9pZF9mcm9tX3BhcmVudChjb25zdCBzdGQ6OnN0cmluZyAmdHApIHsKICBzdGQ6
OnN0cmluZyB4ID0gdHJpbSh0cCk7CiAgaWYgKHguc2l6ZSgpID09IDU1ICYmIHhbMl0gPT0gJy0n
ICYmIHhbMzVdID09ICctJyAmJiB4WzUyXSA9PSAnLScpIHJldHVybiBsb3dlcih4LnN1YnN0cigz
LCAzMikpOwogIHJldHVybiAiIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbWFrZV90cmFjZXBhcmVu
dChzdGQ6OnN0cmluZyAqdGlkKSB7CiAgdW5zaWduZWQgY2hhciBiWzI0XTsgc2l6ZV90IGk7IEZJ
TEUgKmYgPSBmb3BlbigiL2Rldi91cmFuZG9tIiwgInJiIik7CiAgaWYgKGYpIHsgc2l6ZV90IGdv
dCA9IGZyZWFkKGIsIDEsIHNpemVvZihiKSwgZik7ICh2b2lkKWdvdDsgZmNsb3NlKGYpOyB9CiAg
ZWxzZSB7IHVuc2lnbmVkIGxvbmcgdCA9ICh1bnNpZ25lZCBsb25nKXRpbWUoTlVMTCkgXiAodW5z
aWduZWQgbG9uZylnZXRwaWQoKTsgZm9yIChpID0gMDsgaSA8IHNpemVvZihiKTsgKytpKSBiW2ld
ID0gKHVuc2lnbmVkIGNoYXIpKHQgPSB0ICogMTEwMzUxNTI0NVVMICsgMTIzNDVVTCk7IH0KICBz
dGF0aWMgY29uc3QgY2hhciAqaGV4ID0gIjAxMjM0NTY3ODlhYmNkZWYiOyBzdGQ6OnN0cmluZyBh
LCBjOwogIGZvciAoaSA9IDA7IGkgPCAxNjsgKytpKSB7IGEgKz0gaGV4W2JbaV0gPj4gNF07IGEg
Kz0gaGV4W2JbaV0gJiAxNV07IH0KICBmb3IgKGkgPSAxNjsgaSA8IDI0OyArK2kpIHsgYyArPSBo
ZXhbYltpXSA+PiA0XTsgYyArPSBoZXhbYltpXSAmIDE1XTsgfQogICp0aWQgPSBhOyByZXR1cm4g
IjAwLSIgKyBhICsgIi0iICsgYyArICItMDEiOwp9CgpzdHJ1Y3QgRXZlbnQgewogIGxvbmcgdHM7
IHN0ZDo6c3RyaW5nIGhvc3QsIHNyYywgc2VydmljZSwgbWV0aG9kLCBwYXRoLCB1c2VyLCBzY2hl
bWUsIHByb2JlOwogIHN0ZDo6c3RyaW5nIGhvc3RfaGRyLCB1c2VyX2FnZW50LCB4ZmYsIGNhbGxl
ciwgZHN0X2lwLCB0cmFjZXBhcmVudCwgdHJhY2VfaWQ7CiAgdW5zaWduZWQgY2FsbGVyX3BvcnQs
IGRzdF9wb3J0LCByZXFfYnl0ZXMsIHJlc3BfYnl0ZXM7IGludCBzdGF0dXM7IGxvbmcgZHVyYXRp
b25fbXM7CiAgYm9vbCBoYXNfc3RhdHVzLCBoYXNfZHVyYXRpb24sIGhhc19yZXNwOwogIEV2ZW50
KCkgOiB0cygwKSwgY2FsbGVyX3BvcnQoMCksIGRzdF9wb3J0KDApLCByZXFfYnl0ZXMoMCksIHJl
c3BfYnl0ZXMoMCksIHN0YXR1cygwKSwgZHVyYXRpb25fbXMoMCksIGhhc19zdGF0dXMoZmFsc2Up
LCBoYXNfZHVyYXRpb24oZmFsc2UpLCBoYXNfcmVzcChmYWxzZSkge30KfTsKc3RydWN0IEZsb3cg
eyBzdGQ6OnN0cmluZyBidWY7IHRpbWVfdCB0b3VjaGVkOyBGbG93KCkgOiB0b3VjaGVkKHRpbWUo
TlVMTCkpIHt9IH07CnN0cnVjdCBQZW5kaW5nIHsKICBFdmVudCBldjsKICBsb25nIGxvbmcgc3Rh
cnRlZF9tczsKICBQZW5kaW5nKCkgOiBzdGFydGVkX21zKDApIHt9CiAgUGVuZGluZyhjb25zdCBF
dmVudCAmZSwgbG9uZyBsb25nIHQpIDogZXYoZSksIHN0YXJ0ZWRfbXModCkge30KfTsKc3RydWN0
IEZsb3dLZXkgewogIHVpbnQzMl90IHNfaXA7CiAgdWludDE2X3Qgc3BvcnQ7CiAgdWludDMyX3Qg
ZF9pcDsKICB1aW50MTZfdCBkcG9ydDsKICBib29sIG9wZXJhdG9yPChjb25zdCBGbG93S2V5ICZ4
KSBjb25zdCB7CiAgICBpZiAoc19pcCAhPSB4LnNfaXApIHJldHVybiBzX2lwIDwgeC5zX2lwOwog
ICAgaWYgKHNwb3J0ICE9IHguc3BvcnQpIHJldHVybiBzcG9ydCA8IHguc3BvcnQ7CiAgICBpZiAo
ZF9pcCAhPSB4LmRfaXApIHJldHVybiBkX2lwIDwgeC5kX2lwOwogICAgcmV0dXJuIGRwb3J0IDwg
eC5kcG9ydDsKICB9Cn07CnR5cGVkZWYgRmxvd0tleSBQYWNrZXRLZXk7CgpzdGF0aWMgdm9pZCBs
b2dtc2coY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsgZnByaW50ZihzdGRlcnIsICJudC1zbmlmZi1j
cHA6ICVzXG4iLCBzLmNfc3RyKCkpOyBmZmx1c2goc3RkZXJyKTsgfQoKc3RhdGljIGJvb2wgcGFy
c2VfcmVxdWVzdChjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuLCBFdmVudCAqZSkgewogIGNv
bnN0IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7CiAgY29u
c3QgY2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAg
aWYgKCFlb2wpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hhciAq
KW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAgZS0+
bWV0aG9kLmFzc2lnbihwLCBzcDEgLSBwKTsKICBpZiAoIWhhc19tZXRob2QoZS0+bWV0aG9kKSkg
cmV0dXJuIGZhbHNlOwoKICBjb25zdCBjaGFyICpwYXRoX3N0YXJ0ID0gc3AxICsgMTsKICB3aGls
ZSAocGF0aF9zdGFydCA8IGVvbCAmJiAqcGF0aF9zdGFydCA9PSAnICcpICsrcGF0aF9zdGFydDsK
ICBjb25zdCBjaGFyICpzcDIgPSAoY29uc3QgY2hhciAqKW1lbWNocihwYXRoX3N0YXJ0LCAnICcs
IGVvbCAtIHBhdGhfc3RhcnQpOwogIGlmICghc3AyKSBzcDIgPSAoZW9sID4gZGF0YSAmJiAqKGVv
bCAtIDEpID09ICdccicpID8gZW9sIC0gMSA6IGVvbDsKICBjb25zdCBjaGFyICpxbWFyayA9IChj
b25zdCBjaGFyICopbWVtY2hyKHBhdGhfc3RhcnQsICc/Jywgc3AyIC0gcGF0aF9zdGFydCk7CiAg
c2l6ZV90IHBhdGhfbGVuID0gKHFtYXJrID8gcW1hcmsgOiBzcDIpIC0gcGF0aF9zdGFydDsKICBp
ZiAocGF0aF9sZW4gPiAxMjApIHBhdGhfbGVuID0gMTIwOwogIGUtPnBhdGguYXNzaWduKHBhdGhf
c3RhcnQsIHBhdGhfbGVuKTsKCiAgcCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBlbmQpIHsKICAg
IGlmICgqcCA9PSAnXHInIHx8ICpwID09ICdcbicpIGJyZWFrOwogICAgY29uc3QgY2hhciAqbGlu
ZV9lbmQgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICAgIGlmICgh
bGluZV9lbmQpIGxpbmVfZW5kID0gZW5kOwogICAgY29uc3QgY2hhciAqY29sb24gPSAoY29uc3Qg
Y2hhciAqKW1lbWNocihwLCAnOicsIGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29sb24pIHsKICAg
ICAgc2l6ZV90IGhuYW1lX2xlbiA9IGNvbG9uIC0gcDsKICAgICAgY29uc3QgY2hhciAqdmFsX3N0
YXJ0ID0gY29sb24gKyAxOwogICAgICB3aGlsZSAodmFsX3N0YXJ0IDwgbGluZV9lbmQgJiYgKCp2
YWxfc3RhcnQgPT0gJyAnIHx8ICp2YWxfc3RhcnQgPT0gJ1x0JykpICsrdmFsX3N0YXJ0OwogICAg
ICBjb25zdCBjaGFyICp2YWxfZW5kID0gbGluZV9lbmQ7CiAgICAgIHdoaWxlICh2YWxfZW5kID4g
dmFsX3N0YXJ0ICYmICh2YWxfZW5kWy0xXSA9PSAnXHInIHx8IHZhbF9lbmRbLTFdID09ICdcbicg
fHwgdmFsX2VuZFstMV0gPT0gJyAnIHx8IHZhbF9lbmRbLTFdID09ICdcdCcpKSAtLXZhbF9lbmQ7
CiAgICAgIHNpemVfdCB2YWxfbGVuID0gdmFsX2VuZCAtIHZhbF9zdGFydDsKCiAgICAgIGlmICho
bmFtZV9sZW4gPT0gMTMgJiYgIXN0cm5jYXNlY21wKHAsICJhdXRob3JpemF0aW9uIiwgMTMpKSB7
CiAgICAgICAgaWYgKHZhbF9sZW4gPiA2ICYmICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQsICJCYXNp
YyAiLCA2KSkgewogICAgICAgICAgZS0+dXNlciA9IGI2NGRlY29kZV91c2VyKHN0ZDo6c3RyaW5n
KHZhbF9zdGFydCArIDYsIHZhbF9sZW4gLSA2KSk7CiAgICAgICAgICBlLT5zY2hlbWUgPSAiYmFz
aWMiOwogICAgICAgIH0gZWxzZSBpZiAodmFsX2xlbiA+IDcgJiYgIXN0cm5jYXNlY21wKHZhbF9z
dGFydCwgIkJlYXJlciAiLCA3KSkgewogICAgICAgICAgZS0+c2NoZW1lID0gImJlYXJlciI7CiAg
ICAgICAgfQogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xlbiA9PSAxMSAmJiAhc3RybmNhc2VjbXAo
cCwgInRyYWNlcGFyZW50IiwgMTEpKSB7CiAgICAgICAgZS0+dHJhY2VwYXJlbnQuYXNzaWduKHZh
bF9zdGFydCwgdmFsX2xlbik7CiAgICAgICAgZS0+dHJhY2VfaWQgPSB0cmFjZV9pZF9mcm9tX3Bh
cmVudChlLT50cmFjZXBhcmVudCk7CiAgICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDQgJiYg
IXN0cm5jYXNlY21wKHAsICJob3N0IiwgNCkpIHsKICAgICAgICBlLT5ob3N0X2hkci5hc3NpZ24o
dmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTAgJiYg
IXN0cm5jYXNlY21wKHAsICJ1c2VyLWFnZW50IiwgMTApKSB7CiAgICAgICAgZS0+dXNlcl9hZ2Vu
dC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4g
PT0gMTUgJiYgIXN0cm5jYXNlY21wKHAsICJ4LWZvcndhcmRlZC1mb3IiLCAxNSkpIHsKICAgICAg
ICBlLT54ZmYuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0KICAgIH0KICAgIHAg
PSBsaW5lX2VuZCArIDE7CiAgfQoKICBpZiAoZS0+dXNlci5lbXB0eSgpKSBlLT51c2VyID0gIi1h
bm9ueW1vdXMtIjsKICBpZiAoZS0+c2NoZW1lLmVtcHR5KCkpIGUtPnNjaGVtZSA9ICJub25lIjsK
ICBpZiAoZS0+dHJhY2VfaWQuZW1wdHkoKSkgZS0+dHJhY2VwYXJlbnQgPSBtYWtlX3RyYWNlcGFy
ZW50KCZlLT50cmFjZV9pZCk7CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3Jl
c3BvbnNlKGNvbnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4sIGludCAqc3RhdHVzLCB1bnNpZ25l
ZCAqY2xlbikgewogIGNvbnN0IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAq
cCA9IGRhdGE7CiAgY29uc3QgY2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xu
JywgZW5kIC0gcCk7CiAgaWYgKCFlb2wpIHJldHVybiBmYWxzZTsKICBpZiAoc3RybmNtcChwLCAi
SFRUUC8iLCA1KSAhPSAwKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0
IGNoYXIgKiltZW1jaHIocCwgJyAnLCBlb2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNl
OwogIGNvbnN0IGNoYXIgKnNjX3N0YXJ0ID0gc3AxICsgMTsKICB3aGlsZSAoc2Nfc3RhcnQgPCBl
b2wgJiYgKnNjX3N0YXJ0ID09ICcgJykgKytzY19zdGFydDsKICAqc3RhdHVzID0gYXRvaShzY19z
dGFydCk7CiAgaWYgKCpzdGF0dXMgPCAxMDAgfHwgKnN0YXR1cyA+IDU5OSkgcmV0dXJuIGZhbHNl
OwogICpjbGVuID0gMDsKICBwID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYg
KCpwID09ICdccicgfHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2Vu
ZCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5l
X2VuZCkgbGluZV9lbmQgPSBlbmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFy
ICopbWVtY2hyKHAsICc6JywgbGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBz
aXplX3QgaGxlbiA9IGNvbG9uIC0gcDsKICAgICAgaWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNl
Y21wKHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewogICAgICAgIGNvbnN0IGNoYXIgKnYgPSBj
b2xvbiArIDE7CiAgICAgICAgd2hpbGUgKHYgPCBsaW5lX2VuZCAmJiAoKnYgPT0gJyAnIHx8ICp2
ID09ICdcdCcpKSArK3Y7CiAgICAgICAgbG9uZyBuID0gYXRvbCh2KTsKICAgICAgICBpZiAobiA+
PSAwICYmIG4gPD0gMHg3ZmZmZmZmZikgKmNsZW4gPSAodW5zaWduZWQpbjsKICAgICAgfQogICAg
fQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6
OnN0cmluZyBnX2VuZHBvaW50OwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRp
YyBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gZ19zaGlwX2J1ZjsKCnN0YXRpYyBzdGQ6OnN0cmlu
ZyBzaGVsbHEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwog
IGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcn
KSBvICs9ICInXFwnJyI7IGVsc2UgbyArPSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3Rh
dGljIHN0ZDo6c3RyaW5nIG51bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3Ry
ZWFtIG87IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25f
YXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcg
byA9ICJbIjsgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBv
ICs9ICIsIjsgbyArPSBhW2ldOyB9IHJldHVybiBvICsgIl0iOwp9CnN0YXRpYyBib29sIHBvc3Qo
Y29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29u
c3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHkg
PSAie1wibm9kZVwiOiIgKyBqc29ucShub2RlKSArICIsXCJldmVudHNcIjoiICsganNvbl9hcnJh
eShiYXRjaCkgKyAifSI7CiAgc3RkOjpzdHJpbmcgY21kID0gImN1cmwgLXNTZiAtLW1heC10aW1l
IDEwIC1vIC9kZXYvbnVsbCAtSCAnQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uJyAtLWRh
dGEtYmluYXJ5IEAtICIgKyBzaGVsbHEoZW5kcG9pbnQgKyAiL2FwaS9pbmdlc3QiKTsKICBGSUxF
ICpmcCA9IHBvcGVuKGNtZC5jX3N0cigpLCAidyIpOyBpZiAoIWZwKSByZXR1cm4gZmFsc2U7CiAg
ZndyaXRlKGJvZHkuZGF0YSgpLCAxLCBib2R5LnNpemUoKSwgZnApOwogIGludCByYyA9IHBjbG9z
ZShmcCk7CiAgcmV0dXJuIFdJRkVYSVRFRChyYykgJiYgV0VYSVRTVEFUVVMocmMpID09IDA7Cn0K
c3RhdGljIHZvaWQgc2VuZF9iYXRjaGVzKGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCwgY29u
c3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6OnZlY3Rv
cjxzdGQ6OnN0cmluZz4gKmJ1ZiwgYm9vbCBmbHVzaF9hbGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1w
dHkoKSAmJiAoZmx1c2hfYWxsIHx8IGJ1Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCkpIHsKICAgIHNp
emVfdCBuID0gYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIID8gTUFYX0JBVENIIDogYnVmLT5zaXpl
KCk7CiAgICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gYmF0Y2goYnVmLT5iZWdpbigpLCBidWYt
PmJlZ2luKCkgKyBuKTsKICAgIGlmIChwb3N0KGVuZHBvaW50LCBub2RlLCBiYXRjaCkpIHsKICAg
ICAgYnVmLT5lcmFzZShidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4oKSArIG4pOwogICAgICBsb2dt
c2coImZsdXNoZWQgIiArIG51bWJlcl9zdHJpbmcobikgKyAiIGV2ZW50cyIpOwogICAgfSBlbHNl
IHsKICAgICAgLyogUHVyZSBpbi1tZW1vcnkgZHJvcCB3aGVuIEh1YiB1bnJlYWNoYWJsZSAoemVy
byBkaXNrIEkvTykgKi8KICAgICAgYnVmLT5lcmFzZShidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4o
KSArIG4pOwogICAgICBsb2dtc2coIldBUk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAiICsg
bnVtYmVyX3N0cmluZyhuKSArICIgZXZlbnRzIChpbi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTyki
KTsKICAgICAgYnJlYWs7CiAgICB9CiAgfQp9CgpzdGF0aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0
IEV2ZW50ICZlKSB7CiAgc3RkOjpvc3RyaW5nc3RyZWFtIHNzOwogIHNzIDw8ICJ7XCJ0c1wiOiIg
PDwgZS50cyA8PCAiLFwiaG9zdFwiOiIgPDwganNvbnEoZS5ob3N0KSA8PCAiLFwic3JjXCI6XCJw
Y2FwXCIsXCJzZXJ2aWNlXCI6IiA8PCBqc29ucShlLnNlcnZpY2UpCiAgICAgPDwgIixcIm1ldGhv
ZFwiOiIgPDwganNvbnEoZS5tZXRob2QpIDw8ICIsXCJwYXRoXCI6IiA8PCBqc29ucShlLnBhdGgp
IDw8ICIsXCJ1c2VyXCI6IiA8PCBqc29ucShlLnVzZXIpCiAgICAgPDwgIixcInNjaGVtZVwiOiIg
PDwganNvbnEoZS5zY2hlbWUpIDw8ICIsXCJzb3VyY2VfcHJvYmVcIjpcInBjYXAtaHR0cC1jcHBc
IixcImhvc3RfaGRyXCI6IiA8PCBqc29ucShlLmhvc3RfaGRyKQogICAgIDw8ICIsXCJ1c2VyX2Fn
ZW50XCI6IiA8PCBqc29ucShlLnVzZXJfYWdlbnQpIDw8ICIsXCJ4X2ZvcndhcmRlZF9mb3JcIjoi
IDw8IGpzb25xKGUueGZmKQogICAgIDw8ICIsXCJjYWxsZXJcIjoiIDw8IGpzb25xKGUuY2FsbGVy
KSA8PCAiLFwiY2FsbGVyX3BvcnRcIjoiIDw8IGUuY2FsbGVyX3BvcnQgPDwgIixcImRzdF9pcFwi
OiIgPDwganNvbnEoZS5kc3RfaXApCiAgICAgPDwgIixcImRzdF9wb3J0XCI6IiA8PCBlLmRzdF9w
b3J0IDw8ICIsXCJ0cmFjZXBhcmVudFwiOiIgPDwganNvbnEoZS50cmFjZXBhcmVudCkgPDwgIixc
InRyYWNlX2lkXCI6IiA8PCBqc29ucShlLnRyYWNlX2lkKQogICAgIDw8ICIsXCJzZXJ2aWNlX2lk
XCI6bnVsbCxcIm1vZHVsZV9pZFwiOlwicGNhcC1odHRwLWNwcFwiLFwicmVxX2J5dGVzXCI6IiA8
PCBlLnJlcV9ieXRlczsKICBpZiAoZS5oYXNfc3RhdHVzKSBzcyA8PCAiLFwic3RhdHVzXCI6IiA8
PCBlLnN0YXR1czsgZWxzZSBzcyA8PCAiLFwic3RhdHVzXCI6bnVsbCI7CiAgaWYgKGUuaGFzX2R1
cmF0aW9uKSBzcyA8PCAiLFwiZHVyYXRpb25fbXNcIjoiIDw8IGUuZHVyYXRpb25fbXM7IGVsc2Ug
c3MgPDwgIixcImR1cmF0aW9uX21zXCI6bnVsbCI7CiAgaWYgKGUuaGFzX3Jlc3ApIHNzIDw8ICIs
XCJyZXNwX2J5dGVzXCI6IiA8PCBlLnJlc3BfYnl0ZXM7IGVsc2Ugc3MgPDwgIixcInJlc3BfYnl0
ZXNcIjpudWxsIjsKICBzcyA8PCAifSI7CgogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAg
ICBpZiAoZ19zaGlwX2J1Zi5zaXplKCkgPj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9idWYu
ZXJhc2UoZ19zaGlwX2J1Zi5iZWdpbigpKTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNr
KHNzLnN0cigpKTsKICB9IGVsc2UgewogICAgc3RkOjpjb3V0IDw8IHNzLnN0cigpIDw8ICJcbiI7
CiAgfQp9CgpzdGF0aWMgdm9pZCBmbHVzaF9vbGRlc3Qoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgaWYgKHBlbmRpbmcuZW1wdHkoKSkgcmV0
dXJuOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0
b3IgaXQgPSBwZW5kaW5nLmJlZ2luKCk7CiAgaWYgKCFpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAg
IGVtaXRfZXZlbnQoaXQtPnNlY29uZFswXS5ldik7CiAgICBpdC0+c2Vjb25kLmVyYXNlKGl0LT5z
ZWNvbmQuYmVnaW4oKSk7CiAgfQogIGlmIChpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgIHBlbmRp
bmcuZXJhc2UoaXQpOwogIH0KfQpzdGF0aWMgdm9pZCBzd2VlcChzdGQ6Om1hcDxGbG93S2V5LCBG
bG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAm
cGVuZGluZywgdGltZV90IG5vdykgewogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRv
ciBmLCBmbjsKICBmb3IgKGYgPSBmbG93cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewog
ICAgZm4gPSBmOyArK2ZuOwogICAgaWYgKCh1bnNpZ25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNo
ZWQpID4gRkxPV19UVEwpIGZsb3dzLmVyYXNlKGYpOwogICAgZiA9IGZuOwogIH0KICBsb25nIGxv
bmcgY3VycmVudF9tcyA9IChsb25nIGxvbmcpbm93ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tl
dEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0g
cGVuZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcuZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47
CiAgICBzaXplX3QgaSA9IDA7CiAgICB3aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAg
ICAgaWYgKGN1cnJlbnRfbXMgLSBwLT5zZWNvbmRbaV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcp
UEVORElOR19UVEwgKiAxMDAwTEwpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5l
dik7CiAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAg
IH0gZWxzZSB7CiAgICAgICAgKytpOwogICAgICB9CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVt
cHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICBwID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3Qg
ZmluZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtd
ID0geyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQg
IiwgIk9QVElPTlMgIiB9OwogIHNpemVfdCBiZXN0ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9y
IChzaXplX3QgaSA9IDA7IGkgPCA3OyArK2kpIHsKICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtp
XSk7CiAgICBpZiAocG9zICE9IHN0ZDo6c3RyaW5nOjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3Ry
aW5nOjpucG9zIHx8IHBvcyA8IGJlc3QpKSBiZXN0ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsK
fQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNp
emVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWdu
ZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxGbG93S2V5LCBG
bG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAm
cGVuZGluZykgewogIGlmIChuIDwgMzQpIHJldHVybiBmYWxzZTsKICBzaXplX3Qgb2ZmID0gMTQ7
CiAgdW5zaWduZWQgc2hvcnQgZXQgPSBudG9ocygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1
ZiArIDEyKSk7CiAgaWYgKGV0ID09IEVUSF9QXzgwMjFRKSB7IGlmIChuIDwgMzgpIHJldHVybiBm
YWxzZTsgZXQgPSBudG9ocygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIDE2KSk7IG9m
ZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZh
bHNlOwogIHVuc2lnbmVkIGNoYXIgaWhsID0gKHVuc2lnbmVkIGNoYXIpKGJ1ZltvZmZdICYgMTUp
ICogNDsKICBpZiAoKGJ1ZltvZmZdID4+IDQpICE9IDQgfHwgYnVmW29mZiArIDldICE9IDYgfHwg
biA8IG9mZiArIGlobCArIDIwKSByZXR1cm4gZmFsc2U7CgogIHVpbnQzMl90IHNfaXAgPSAqKGNv
bnN0IHVpbnQzMl90ICopKGJ1ZiArIG9mZiArIDEyKTsKICB1aW50MzJfdCBkX2lwID0gKihjb25z
dCB1aW50MzJfdCAqKShidWYgKyBvZmYgKyAxNik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwog
IHVuc2lnbmVkIHNwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0
bykpOwogIHVuc2lnbmVkIGRwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShi
dWYgKyB0byArIDIpKTsKICB1bnNpZ25lZCBkb2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7
CiAgaWYgKG4gPCB0byArIGRvZmYpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpwYXlsb2Fk
ID0gKGNvbnN0IGNoYXIgKikoYnVmICsgdG8gKyBkb2ZmKTsKICBzaXplX3QgcGxlbiA9IG4gLSB0
byAtIGRvZmY7CiAgaWYgKCFwbGVuKSByZXR1cm4gZmFsc2U7CgogIHRpbWVfdCBub3cgPSB0aW1l
KE5VTEwpOwogIGJvb2wgZHN0X21vbiA9IGZhbHNlLCBzcmNfbW9uID0gZmFsc2U7CiAgc2l6ZV90
IGo7CiAgZm9yIChqID0gMDsgaiA8IHBvcnRzLnNpemUoKTsgKytqKSB7CiAgICBpZiAoZHBvcnQg
PT0gcG9ydHNbal0pIGRzdF9tb24gPSB0cnVlOwogICAgaWYgKHNwb3J0ID09IHBvcnRzW2pdKSBz
cmNfbW9uID0gdHJ1ZTsKICB9CgogIGlmIChzcmNfbW9uICYmICFkc3RfbW9uICYmIHBsZW4gPj0g
NSkgewogICAgaWYgKG1lbWNtcChwYXlsb2FkLCAiSFRUUC8iLCA1KSA9PSAwKSB7CiAgICAgIFBh
Y2tldEtleSBrOwogICAgICBrLnNfaXAgPSBzX2lwOyBrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0
OyBrLmRfaXAgPSBkX2lwOyBrLmRwb3J0ID0gKHVpbnQxNl90KWRwb3J0OwogICAgICBzdGQ6Om1h
cDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHAgPSBwZW5kaW5n
LmZpbmQoayk7CiAgICAgIGlmIChwICE9IHBlbmRpbmcuZW5kKCkgJiYgIXAtPnNlY29uZC5lbXB0
eSgpKSB7CiAgICAgICAgaW50IHN0OyB1bnNpZ25lZCBjbDsKICAgICAgICBpZiAocGFyc2VfcmVz
cG9uc2UocGF5bG9hZCwgcGxlbiwgJnN0LCAmY2wpKSB7CiAgICAgICAgICBFdmVudCBlID0gcC0+
c2Vjb25kWzBdLmV2OwogICAgICAgICAgZS5zdGF0dXMgPSBzdDsgZS5oYXNfc3RhdHVzID0gdHJ1
ZTsKICAgICAgICAgIGUuZHVyYXRpb25fbXMgPSAobG9uZykobm93X21zKCkgLSBwLT5zZWNvbmRb
MF0uc3RhcnRlZF9tcyk7CiAgICAgICAgICBpZiAoZS5kdXJhdGlvbl9tcyA8IDApIGUuZHVyYXRp
b25fbXMgPSAwOwogICAgICAgICAgZS5oYXNfZHVyYXRpb24gPSB0cnVlOwogICAgICAgICAgaWYg
KGNsKSB7IGUucmVzcF9ieXRlcyA9IGNsOyBlLmhhc19yZXNwID0gdHJ1ZTsgfQogICAgICAgICAg
ZW1pdF9ldmVudChlKTsKICAgICAgICAgIHAtPnNlY29uZC5lcmFzZShwLT5zZWNvbmQuYmVnaW4o
KSk7CiAgICAgICAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAg
ICAgICAgfQogICAgICB9CiAgICB9CiAgICByZXR1cm4gdHJ1ZTsKICB9CiAgdW5zaWduZWQgY2hh
ciB0Y3BfZmxhZ3MgPSBidWZbdG8gKyAxM107CiAgaWYgKCFkc3RfbW9uKSB7CiAgICBpZiAodGNw
X2ZsYWdzICYgMHgwNSkgeyAvKiBGSU4gb3IgUlNUICovCiAgICAgIEZsb3dLZXkgcmZrOyByZmsu
c19pcCA9IGRfaXA7IHJmay5zcG9ydCA9ICh1aW50MTZfdClkcG9ydDsgcmZrLmRfaXAgPSBzX2lw
OyByZmsuZHBvcnQgPSAodWludDE2X3Qpc3BvcnQ7CiAgICAgIGZsb3dzLmVyYXNlKHJmayk7CiAg
ICB9CiAgICByZXR1cm4gZmFsc2U7CiAgfQoKICBGbG93S2V5IGZrOwogIGZrLnNfaXAgPSBzX2lw
OyBmay5zcG9ydCA9ICh1aW50MTZfdClzcG9ydDsgZmsuZF9pcCA9IGRfaXA7IGZrLmRwb3J0ID0g
KHVpbnQxNl90KWRwb3J0OwogIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7IC8qIEZJTiBvciBSU1Qg
Ki8KICAgIGZsb3dzLmVyYXNlKGZrKTsKICAgIHJldHVybiB0cnVlOwogIH0KCiAgaWYgKGZsb3dz
LmZpbmQoZmspID09IGZsb3dzLmVuZCgpICYmIGZsb3dzLnNpemUoKSA+PSBNQVhfRkxPV1MpIHsK
ICAgIGZsb3dzLmVyYXNlKGZsb3dzLmJlZ2luKCkpOwogIH0KICBGbG93ICZmbCA9IGZsb3dzW2Zr
XTsgZmwudG91Y2hlZCA9IG5vdzsgZmwuYnVmLmFwcGVuZChwYXlsb2FkLCBwbGVuKTsKICBpZiAo
ZmwuYnVmLnNpemUoKSA+IE1BWF9IRUFERVIpIHsgZmxvd3MuZXJhc2UoZmspOyByZXR1cm4gZmFs
c2U7IH0KICB3aGlsZSAodHJ1ZSkgewogICAgc2l6ZV90IHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0
KGZsLmJ1Zik7CiAgICBpZiAoc3RhcnQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsgZmwuYnVmLmNs
ZWFyKCk7IGJyZWFrOyB9CiAgICBpZiAoc3RhcnQgPiAwKSBmbC5idWYuZXJhc2UoMCwgc3RhcnQp
OwogICAgc2l6ZV90IGVuZCA9IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgaWYgKGVuZCA9
PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICBFdmVudCBlOyBlLnRzID0gbm93OyBlLmhv
c3QgPSBub2RlOyBlLnNlcnZpY2UgPSAicG9ydDoiICsgbnVtKGRwb3J0KTsgZS5jYWxsZXIgPSBp
cF90b19zdHIoc19pcCk7IGUuY2FsbGVyX3BvcnQgPSBzcG9ydDsgZS5kc3RfaXAgPSBpcF90b19z
dHIoZF9pcCk7IGUuZHN0X3BvcnQgPSBkcG9ydDsgZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQpKGVu
ZCArIDQpOwogICAgaWYgKCFwYXJzZV9yZXF1ZXN0KGZsLmJ1Zi5kYXRhKCksIGVuZCwgJmUpKSB7
IGZsLmJ1Zi5lcmFzZSgwLCBlbmQgKyA0KTsgY29udGludWU7IH0KICAgIGZsLmJ1Zi5lcmFzZSgw
LCBlbmQgKyA0KTsKICAgIFBhY2tldEtleSByazsgcmsuc19pcCA9IGRfaXA7IHJrLnNwb3J0ID0g
KHVpbnQxNl90KWRwb3J0OyByay5kX2lwID0gc19pcDsgcmsuZHBvcnQgPSAodWludDE2X3Qpc3Bv
cnQ7CiAgICBpZiAocGVuZGluZy5zaXplKCkgPj0gTUFYX1BFTkRJTkcpIGZsdXNoX29sZGVzdChw
ZW5kaW5nKTsKICAgIHBlbmRpbmdbcmtdLnB1c2hfYmFjayhQZW5kaW5nKGUsIG5vd19tcygpKSk7
CiAgfQogIGlmIChmbC5idWYuZW1wdHkoKSkgewogICAgZmxvd3MuZXJhc2UoZmspOwogIH0KICBy
ZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgYXR0YWNoX2JwZihpbnQgZmQsIGNvbnN0IHN0ZDo6
dmVjdG9yPHVuc2lnbmVkPiAmcG9ydHMpIHsKICBpZiAocG9ydHMuZW1wdHkoKSkgcmV0dXJuIGZh
bHNlOwogIHN0ZDo6dmVjdG9yPHN0cnVjdCBzb2NrX2ZpbHRlcj4gZjsgc2l6ZV90IGk7CiAgLyog
RHVhbC1wYXRoIGNCUEY6IFBhdGggQSAoc3RhbmRhcmQgSVB2NCkgYW5kIFBhdGggQiAoODAyLjFR
IFZMQU4gdGFnZ2VkIElQdjQpLiAqLwogIHVuc2lnbmVkIE4gPSAodW5zaWduZWQpcG9ydHMuc2l6
ZSgpOwogIHVuc2lnbmVkIHJlamVjdCA9IDExICsgTiAqIDg7CiAgdW5zaWduZWQgYWNjZXB0ID0g
cmVqZWN0ICsgMTsKICBzdHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmluZSBBREQoQyxKLFQsSykg
ZG8geyB4LmNvZGU9KEMpOyB4Lmp0PShKKTsgeC5qZj0oVCk7IHguaz0oSyk7IGYucHVzaF9iYWNr
KHgpOyB9IHdoaWxlKDApCiAgLyogWzBdIExvYWQgRXRoZXJUeXBlIGF0IG9mZnNldCAxMiAqLwog
IEFERChCUEZfTER8QlBGX0h8QlBGX0FCUywgMCwgMCwgMTIpOwogIC8qIFsxXSBJZiBzdGFuZGFy
ZCBJUHY0ICgweDA4MDApLCBqdW1wIG92ZXIgUGF0aCBCICg2ICsgNCpOIGluc3RydWN0aW9ucykg
dG8gUGF0aCBBICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgKHVuc2lnbmVkKSg2ICsg
NCAqIE4pLCAwLCBFVEhfUF9JUF9IT1NUKTsKCiAgLyogLS0tIFBhdGggQjogODAyLjFRIFZMQU4g
KGluZGV4IDIpIC0tLSAqLwogIC8qIFsyXSBJZiBub3QgODAyLjFRICgweDgxMDApLCByZWplY3Qg
Ki8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1
bnNpZ25lZClmLnNpemUoKSAtIDEpLCBFVEhfUF84MDIxUV9IT1NUKTsKICAvKiBbM10gTG9hZCBl
bmNhcHN1bGF0ZWQgRXRoZXJUeXBlIGF0IG9mZnNldCAxNiAqLwogIEFERChCUEZfTER8QlBGX0h8
QlBGX0FCUywgMCwgMCwgMTYpOwogIC8qIFs0XSBJZiBlbmNhcHN1bGF0ZWQgIT0gSVB2NCwgcmVq
ZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3Qg
LSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRIX1BfSVBfSE9TVCk7CiAgLyogWzVdIExvYWQg
SVAgcHJvdG9jb2wgYXQgb2Zmc2V0IDI3ICgyMyArIDQpICovCiAgQUREKEJQRl9MRHxCUEZfQnxC
UEZfQUJTLCAwLCAwLCAyNyk7CiAgLyogWzZdIElmIG5vdCBUQ1AsIHJlamVjdCAqLwogIEFERChC
UEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICAvKiBbN10gTG9hZCBJSEwgYXQgb2Zmc2V0IDE4
ICgxNCArIDQpICovCiAgQUREKEJQRl9MRFh8QlBGX0J8QlBGX01TSCwgMCwgMCwgMTgpOwogIC8q
IERlc3RpbmF0aW9uIHBvcnQgY2hlY2tzIGZvciBWTEFOICovCiAgZm9yIChpID0gMDsgaSA8IHBv
cnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDIw
KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAg
IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCAwLCBwb3J0c1tpXSk7CiAgfQogIC8qIFNv
dXJjZSBwb3J0IGNoZWNrcyBmb3IgVkxBTiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXpl
KCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAxOCk7CiAgICB1
bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICB1bnNpZ25l
ZCBqZiA9IChpIDwgcG9ydHMuc2l6ZSgpIC0gMSkgPyAwIDogKHJlamVjdCAtICh1bnNpZ25lZClm
LnNpemUoKSAtIDEpOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIGpmLCBwb3J0
c1tpXSk7CiAgfQoKICAvKiAtLS0gUGF0aCBBOiBTdGFuZGFyZCBJUHY0IC0tLSAqLwogIC8qIExv
YWQgSVAgcHJvdG9jb2wgYXQgb2Zmc2V0IDIzICovCiAgQUREKEJQRl9MRHxCUEZfQnxCUEZfQUJT
LCAwLCAwLCAyMyk7CiAgLyogSWYgbm90IFRDUCwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBG
X0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAx
KSwgSVBQUk9UT19UQ1ApOwogIC8qIExvYWQgSUhMIGF0IG9mZnNldCAxNCAqLwogIEFERChCUEZf
TERYfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE0KTsKICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNr
cyBmb3Igc3RhbmRhcmQgSVB2NCAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsr
aSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAxNik7CiAgICB1bnNpZ25l
ZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxC
UEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVj
a3MgZm9yIHN0YW5kYXJkIElQdjQgKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyAr
K2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTQpOwogICAgdW5zaWdu
ZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYg
PSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXpl
KCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0p
OwogIH0KCiAgLyogW3JlamVjdF0gRHJvcCBwYWNrZXQgKi8KICBBREQoQlBGX1JFVHxCUEZfSywg
MCwgMCwgMCk7CiAgLyogW2FjY2VwdF0gQWNjZXB0IHBhY2tldCAoMjA0OCBieXRlcykgKi8KICBB
REQoQlBGX1JFVHxCUEZfSywgMCwgMCwgQUNDRVBUKTsKI3VuZGVmIEFERAogIGlmIChmLnNpemUo
KSA+IDQwOTYpIHJldHVybiBmYWxzZTsKICBzdHJ1Y3Qgc29ja19mcHJvZyBwcm9nOyBwcm9nLmxl
biA9ICh1bnNpZ25lZCBzaG9ydClmLnNpemUoKTsgcHJvZy5maWx0ZXIgPSAmZlswXTsKI2lmbmRl
ZiBTT19BVFRBQ0hfRklMVEVSCiNkZWZpbmUgU09fQVRUQUNIX0ZJTFRFUiAyNgojZW5kaWYKICBy
ZXR1cm4gc2V0c29ja29wdChmZCwgU09MX1NPQ0tFVCwgU09fQVRUQUNIX0ZJTFRFUiwgJnByb2cs
IHNpemVvZihwcm9nKSkgPT0gMDsKfQoKc3RydWN0IE1tYXBSaW5nIHsKICB2b2lkICpyaW5nOwog
IHNpemVfdCByaW5nX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfc2l6ZTsKICB1bnNpZ25lZCBibG9j
a19ucjsKICB1bnNpZ25lZCBmcmFtZV9zaXplOwogIHVuc2lnbmVkIGZyYW1lX25yOwogIHVuc2ln
bmVkIGZyYW1lc19wZXJfYmxvY2s7CiAgdW5zaWduZWQgZnJhbWVfaWR4OwoKICBNbWFwUmluZygp
IDogcmluZyhNQVBfRkFJTEVEKSwgcmluZ19zaXplKDApLCBibG9ja19zaXplKDY1NTM2KSwgYmxv
Y2tfbnIoNjQpLAogICAgICAgICAgICAgICBmcmFtZV9zaXplKDIwNDgpLCBmcmFtZV9ucigyMDQ4
KSwgZnJhbWVzX3Blcl9ibG9jaygzMiksIGZyYW1lX2lkeCgwKSB7fQp9OwoKc3RhdGljIGJvb2wg
c2V0dXBfbW1hcF9yaW5nKGludCBmZCwgTW1hcFJpbmcgJm1yKSB7CiAgaW50IHZlciA9IFRQQUNL
RVRfVjI7CiAgaWYgKHNldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9WRVJTSU9OLCAm
dmVyLCBzaXplb2YodmVyKSkgPCAwKSB7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIHN0cnVjdCB0
cGFja2V0X3JlcSByZXE7CiAgbWVtc2V0KCZyZXEsIDAsIHNpemVvZihyZXEpKTsKICByZXEudHBf
YmxvY2tfc2l6ZSA9IDY1NTM2OwogIHJlcS50cF9ibG9ja19uciA9IDY0OyAgICAgICAvKiA0TUIg
c2hhcmVkIG1lbW9yeSByaW5nIGJ1ZmZlciAqLwogIHJlcS50cF9mcmFtZV9zaXplID0gMjA0ODsg
ICAvKiAyS0IgcGVyIGZyYW1lICovCiAgcmVxLnRwX2ZyYW1lX25yID0gKHJlcS50cF9ibG9ja19z
aXplICogcmVxLnRwX2Jsb2NrX25yKSAvIHJlcS50cF9mcmFtZV9zaXplOyAvKiAyMDQ4IGZyYW1l
cyAqLwoKICBpZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tFVCwgUEFDS0VUX1JYX1JJTkcsICZy
ZXEsIHNpemVvZihyZXEpKSA8IDApIHsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgbXIucmluZ19z
aXplID0gKHNpemVfdClyZXEudHBfYmxvY2tfc2l6ZSAqIHJlcS50cF9ibG9ja19ucjsKICBtci5i
bG9ja19zaXplID0gcmVxLnRwX2Jsb2NrX3NpemU7CiAgbXIuYmxvY2tfbnIgPSByZXEudHBfYmxv
Y2tfbnI7CiAgbXIuZnJhbWVfc2l6ZSA9IHJlcS50cF9mcmFtZV9zaXplOwogIG1yLmZyYW1lX25y
ID0gcmVxLnRwX2ZyYW1lX25yOwogIG1yLmZyYW1lc19wZXJfYmxvY2sgPSByZXEudHBfYmxvY2tf
c2l6ZSAvIHJlcS50cF9mcmFtZV9zaXplOwogIG1yLmZyYW1lX2lkeCA9IDA7CgogIG1yLnJpbmcg
PSBtbWFwKE5VTEwsIG1yLnJpbmdfc2l6ZSwgUFJPVF9SRUFEIHwgUFJPVF9XUklURSwgTUFQX1NI
QVJFRCwgZmQsIDApOwogIGlmIChtci5yaW5nID09IE1BUF9GQUlMRUQpIHsKICAgIG1yLnJpbmdf
c2l6ZSA9IDA7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMg
aW50IHJ1bl9maXh0dXJlKCkgewogIHN0ZDo6c3RyaW5nIHJlcSA9ICJHRVQgL2FwaS9pdGVtcz94
PTEgSFRUUC8xLjFcclxuSG9zdDogYXBpLmxvY2FsXHJcbkF1dGhvcml6YXRpb246IEJhc2ljIFlX
eHBZMlU2YzJWamNtVjBcclxuVHJhY2VwYXJlbnQ6IDAwLTAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2
Nzg5YWJjZGVmLTAxMjM0NTY3ODlhYmNkZWYtMDFcclxuXHJcbiI7CiAgRXZlbnQgZTsgZS50cyA9
IDE3MDAwMDAwMDA7IGUuaG9zdCA9ICJjcHAtbm9kZSI7IGUuc2VydmljZSA9ICJwb3J0OjgwODAi
OyBlLmNhbGxlciA9ICIxMC4wLjAuOSI7IGUuY2FsbGVyX3BvcnQgPSA1MTAwMDsgZS5kc3RfaXAg
PSAiMTAuMC4wLjIiOyBlLmRzdF9wb3J0ID0gODA4MDsgZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQp
cmVxLnNpemUoKTsgcGFyc2VfcmVxdWVzdChyZXEuZGF0YSgpLCByZXEuc2l6ZSgpIC0gNCwgJmUp
OyBlLnN0YXR1cyA9IDIwMDsgZS5oYXNfc3RhdHVzID0gdHJ1ZTsgZS5kdXJhdGlvbl9tcyA9IDM7
IGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsgZS5yZXNwX2J5dGVzID0gNDI7IGUuaGFzX3Jlc3AgPSB0
cnVlOyBlbWl0X2V2ZW50KGUpOyByZXR1cm4gMDsKfQoKaW50IG1haW4oaW50IGFyZ2MsIGNoYXIg
Kiphcmd2KSB7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0tZml4dHVyZSIp
KSByZXR1cm4gcnVuX2ZpeHR1cmUoKTsKICBzdGQ6OnN0cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8
dW5zaWduZWQ+IHBvcnRzOyBpbnQgaTsgaW50IHdvcmtlcnMgPSAxOwogIHN0ZDo6c3RyaW5nIGVu
ZHBvaW50OwogIGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAgIGlmICghc3RyY21wKGFy
Z3ZbaV0sICItaSIpICYmIGkgKyAxIDwgYXJnYykgaWZhY2UgPSBhcmd2WysraV07CiAgICBlbHNl
IGlmICghc3RyY21wKGFyZ3ZbaV0sICItcCIpICYmIGkgKyAxIDwgYXJnYykgewogICAgICB3aGls
ZSAoaSArIDEgPCBhcmdjICYmIGFyZ3ZbaSArIDFdWzBdICE9ICctJykgewogICAgICAgIGNoYXIg
KnEgPSBzdHJ0b2soYXJndlsrK2ldLCAiLCAiKTsKICAgICAgICB3aGlsZSAocSkgeyBsb25nIHAg
PSBhdG9sKHEpOyBpZiAodmFsaWRfcG9ydCgodW5zaWduZWQpcCkpIHBvcnRzLnB1c2hfYmFjaygo
dW5zaWduZWQpcCk7IHEgPSBzdHJ0b2soTlVMTCwgIiwgIik7IH0KICAgICAgfQogICAgfQogICAg
ZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1lbmRwb2ludCIpICYmIGkgKyAxIDwgYXJnYykg
ZW5kcG9pbnQgPSBhcmd2WysraV07CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItLXNw
b29sIikgJiYgaSArIDEgPCBhcmdjKSArK2k7IC8qIGlnbm9yZWQ6IDAgZGlzayB3cml0ZSAqLwog
ICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWoiKSAmJiBpICsgMSA8IGFyZ2MpIHdvcmtl
cnMgPSBhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaCIp
IHx8ICFzdHJjbXAoYXJndltpXSwgIi0taGVscCIpKSB7CiAgICAgIGZwcmludGYoc3RkZXJyLCAi
dXNhZ2U6IG50LXNuaWZmLWNwcCBbLWkgaWZhY2VdIFstcCBwb3J0c10gWy0tZW5kcG9pbnQgVVJM
XSBbLWogd29ya2Vyc11cbiIpOwogICAgICByZXR1cm4gMDsKICAgIH0KICB9CiAgaWYgKHBvcnRz
LmVtcHR5KCkpIHsgcG9ydHMucHVzaF9iYWNrKDgwKTsgcG9ydHMucHVzaF9iYWNrKDgwMDMpOyBw
b3J0cy5wdXNoX2JhY2soODAwNSk7IHBvcnRzLnB1c2hfYmFjayg4MDA3KTsgcG9ydHMucHVzaF9i
YWNrKDgwMDkpOyBwb3J0cy5wdXNoX2JhY2soODAxMCk7IHBvcnRzLnB1c2hfYmFjayg4MDExKTsg
fQogICh2b2lkKXdvcmtlcnM7CgogIGNvbnN0IGNoYXIgKm5vZGVfZW52ID0gZ2V0ZW52KCJOVF9O
T0RFX05BTUUiKTsKICBzdGQ6OnN0cmluZyBub2RlID0gKG5vZGVfZW52ICYmICpub2RlX2Vudikg
PyBub2RlX2VudiA6IGhvc3RfbmFtZSgpOwoKICBnX2VuZHBvaW50ID0gZW5kcG9pbnQ7CiAgZ19z
aGlwX25vZGUgPSBub2RlOwoKICBpbnQgZmQgPSBzb2NrZXQoQUZfUEFDS0VULCBTT0NLX1JBVywg
aHRvbnMoMykpOwogIGlmIChmZCA8IDApIHsgcGVycm9yKCJBRl9QQUNLRVQiKTsgcmV0dXJuIDI7
IH0KICBpbnQgcmIgPSA4ICogMTAyNCAqIDEwMjQ7CiAgc2V0c29ja29wdChmZCwgU09MX1NPQ0tF
VCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihyYikpOwogIGlmICghYXR0YWNoX2JwZihmZCwgcG9y
dHMpKSBsb2dtc2coIldBUk46IEJQRiBhdHRhY2ggZmFpbGVkOyBjb250aW51aW5nIHVuZmlsdGVy
ZWQiKTsKCiAgTW1hcFJpbmcgcmluZzsKICBib29sIHVzZV9tbWFwID0gc2V0dXBfbW1hcF9yaW5n
KGZkLCByaW5nKTsKCiAgc3RydWN0IHNvY2thZGRyX2xsIHNhOwogIG1lbXNldCgmc2EsIDAsIHNp
emVvZihzYSkpOwogIHNhLnNsbF9mYW1pbHkgPSBBRl9QQUNLRVQ7CiAgc2Euc2xsX3Byb3RvY29s
ID0gaHRvbnMoMyk7CiAgaWYgKCFpZmFjZS5lbXB0eSgpKSB7CiAgICBzYS5zbGxfaWZpbmRleCA9
IChpbnQpaWZfbmFtZXRvaW5kZXgoaWZhY2UuY19zdHIoKSk7CiAgICBpZiAoIXNhLnNsbF9pZmlu
ZGV4KSB7IGxvZ21zZygiYmFkIGludGVyZmFjZSIpOyBjbG9zZShmZCk7IHJldHVybiAyOyB9CiAg
fQogIGlmIChiaW5kKGZkLCAoc3RydWN0IHNvY2thZGRyICopJnNhLCBzaXplb2Yoc2EpKSA8IDAp
IHsgcGVycm9yKCJiaW5kIik7IGNsb3NlKGZkKTsgcmV0dXJuIDI7IH0KCiAgc2lnbmFsKFNJR1RF
Uk0sIHN0b3Bfc2lnbmFsKTsKICBzaWduYWwoU0lHSU5ULCBzdG9wX3NpZ25hbCk7CiAgc2V0dmJ1
ZihzdGRvdXQsIE5VTEwsIF9JT0xCRiwgNjU1MzYpOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+
IGZsb3dzOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiBwZW5k
aW5nOwoKICBpZiAodXNlX21tYXApIHsKICAgIGxvZ21zZygiUEFDS0VUX01NQVAgKFRQQUNLRVRf
VjIpIHplcm8tY29weSByaW5nIGVuYWJsZWQgKDRNQiwgMjA0OCBmcmFtZXMpIik7CiAgfSBlbHNl
IHsKICAgIGxvZ21zZygiV0FSTjogUEFDS0VUX01NQVAgc2V0dXAgZmFpbGVkLCBmYWxsaW5nIGJh
Y2sgdG8gc3RhbmRhcmQgc29ja2V0IHJlY3YiKTsKICB9CiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5
KCkpIHsKICAgIGxvZ21zZygic2luZ2xlLWJpbmFyeSBpbi1tZW1vcnkgbW9kZTogc2hpcHBpbmcg
ZGlyZWN0bHkgdG8gIiArIGdfZW5kcG9pbnQgKyAiICgwIGRpc2sgSS9PKSIpOwogIH0KICBsb2dt
c2coImxpc3RlbmluZyIpOwoKICB0aW1lX3QgbGFzdCA9IHRpbWUoTlVMTCksIGxhc3RfZmx1c2gg
PSBsYXN0OwogIHVuc2lnbmVkIGNoYXIgKmZhbGxiYWNrX2J1ZiA9IE5VTEw7CiAgaWYgKCF1c2Vf
bW1hcCkgewogICAgZmFsbGJhY2tfYnVmID0gKHVuc2lnbmVkIGNoYXIgKiltYWxsb2MoNjU1MzYp
OwogICAgaWYgKCFmYWxsYmFja19idWYpIHsKICAgICAgY2xvc2UoZmQpOwogICAgICBsb2dtc2co
ImJ1ZmZlciBhbGxvY2F0aW9uIGZhaWxlZCIpOwogICAgICByZXR1cm4gMjsKICAgIH0KICB9Cgog
IHN0cnVjdCBwb2xsZmQgcGZkOwogIHBmZC5mZCA9IGZkOwogIHBmZC5ldmVudHMgPSBQT0xMSU4g
fCBQT0xMRVJSOwogIHBmZC5yZXZlbnRzID0gMDsKCiAgd2hpbGUgKGdfcnVubmluZykgewogICAg
aW50IHJjID0gcG9sbCgmcGZkLCAxLCAxMDAwKTsKICAgIGlmIChyYyA8IDAgJiYgZXJybm8gPT0g
RUlOVFIpIHsKICAgICAgLyogU2lnbmFsIGhhbmRsZWQsIGxvb3AgY29uZGl0aW9uIHdpbGwgY2hl
Y2sgZ19ydW5uaW5nICovCiAgICB9IGVsc2UgaWYgKHJjID49IDApIHsKICAgICAgaWYgKHVzZV9t
bWFwKSB7CiAgICAgICAgLyogRHJhaW4gYWxsIHJlYWR5IGZyYW1lcyBpbiB0aGUgcmluZyB3aXRo
b3V0IGV4dHJhIHN5c2NhbGxzICovCiAgICAgICAgd2hpbGUgKGdfcnVubmluZykgewogICAgICAg
ICAgdW5zaWduZWQgYl9pZHggPSByaW5nLmZyYW1lX2lkeCAvIHJpbmcuZnJhbWVzX3Blcl9ibG9j
azsKICAgICAgICAgIHVuc2lnbmVkIGZfaW5fYiA9IHJpbmcuZnJhbWVfaWR4ICUgcmluZy5mcmFt
ZXNfcGVyX2Jsb2NrOwogICAgICAgICAgdWludDhfdCAqZnJhbWVfcHRyID0gKCh1aW50OF90ICop
cmluZy5yaW5nKSArIChiX2lkeCAqIHJpbmcuYmxvY2tfc2l6ZSkgKyAoZl9pbl9iICogcmluZy5m
cmFtZV9zaXplKTsKICAgICAgICAgIHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciA9IChzdHJ1Y3Qg
dHBhY2tldDJfaGRyICopZnJhbWVfcHRyOwoKICAgICAgICAgIGlmICghKGhkci0+dHBfc3RhdHVz
ICYgVFBfU1RBVFVTX1VTRVIpKSB7CiAgICAgICAgICAgIGJyZWFrOyAvKiBObyBtb3JlIGtlcm5l
bC1wb3B1bGF0ZWQgZnJhbWVzIGluIHJpbmcgcmlnaHQgbm93ICovCiAgICAgICAgICB9CgogICAg
ICAgICAgaWYgKGhkci0+dHBfc25hcGxlbiA+IDApIHsKICAgICAgICAgICAgY29uc3QgdW5zaWdu
ZWQgY2hhciAqcGt0ID0gKChjb25zdCB1bnNpZ25lZCBjaGFyICopaGRyKSArIGhkci0+dHBfbWFj
OwogICAgICAgICAgICBoYW5kbGVfcGFja2V0KHBrdCwgKHNpemVfdCloZHItPnRwX3NuYXBsZW4s
IG5vZGUsIHBvcnRzLCBmbG93cywgcGVuZGluZyk7CiAgICAgICAgICB9CgogICAgICAgICAgaGRy
LT50cF9zdGF0dXMgPSBUUF9TVEFUVVNfS0VSTkVMOyAvKiBSZXR1cm4gZnJhbWUgb3duZXJzaGlw
IHRvIGtlcm5lbCAqLwogICAgICAgICAgcmluZy5mcmFtZV9pZHggPSAocmluZy5mcmFtZV9pZHgg
KyAxKSAlIHJpbmcuZnJhbWVfbnI7CiAgICAgICAgfQogICAgICAgIGlmIChnX2VuZHBvaW50LmVt
cHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgpOwogICAgICB9IGVsc2UgewogICAgICAgIGlmIChwZmQu
cmV2ZW50cyAmIFBPTExJTikgewogICAgICAgICAgc3NpemVfdCBuID0gcmVjdihmZCwgZmFsbGJh
Y2tfYnVmLCA2NTUzNiwgMCk7CiAgICAgICAgICBpZiAobiA+IDApIHsKICAgICAgICAgICAgaGFu
ZGxlX3BhY2tldChmYWxsYmFja19idWYsIChzaXplX3Qpbiwgbm9kZSwgcG9ydHMsIGZsb3dzLCBw
ZW5kaW5nKTsKICAgICAgICAgICAgaWYgKGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZs
dXNoKCk7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAgICB9CgogICAgdGltZV90IG5v
dyA9IHRpbWUoTlVMTCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVwKGZs
b3dzLCBwZW5kaW5nLCBub3cpOwogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNv
dXQuZmx1c2goKTsKICAgICAgbGFzdCA9IG5vdzsKICAgIH0KCiAgICBpZiAoIWdfZW5kcG9pbnQu
ZW1wdHkoKSkgewogICAgICBpZiAobm93IC0gbGFzdF9mbHVzaCA+PSBGTFVTSF9TRUMgfHwgZ19z
aGlwX2J1Zi5zaXplKCkgPj0gTUFYX0JBVENIKSB7CiAgICAgICAgaWYgKCFnX3NoaXBfYnVmLmVt
cHR5KCkpIHNlbmRfYmF0Y2hlcyhnX2VuZHBvaW50LCBnX3NoaXBfbm9kZSwgJmdfc2hpcF9idWYs
IHRydWUpOwogICAgICAgIGxhc3RfZmx1c2ggPSBub3c7CiAgICAgIH0KICAgIH0KICB9CgogIGlm
ICghZ19lbmRwb2ludC5lbXB0eSgpICYmICFnX3NoaXBfYnVmLmVtcHR5KCkpIHsKICAgIHNlbmRf
YmF0Y2hlcyhnX2VuZHBvaW50LCBnX3NoaXBfbm9kZSwgJmdfc2hpcF9idWYsIHRydWUpOwogIH0K
CiAgaWYgKHVzZV9tbWFwICYmIHJpbmcucmluZyAhPSBNQVBfRkFJTEVEKSB7CiAgICBtdW5tYXAo
cmluZy5yaW5nLCByaW5nLnJpbmdfc2l6ZSk7CiAgfQogIGlmIChmYWxsYmFja19idWYpIGZyZWUo
ZmFsbGJhY2tfYnVmKTsKICBjbG9zZShmZCk7CiAgbG9nbXNnKCJzdG9wcGVkIik7CiAgcmV0dXJu
IDA7Cn0K
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
