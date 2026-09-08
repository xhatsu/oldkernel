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
#        --endpoint http://HUB:30102
#
# Local bundle usage:
#   sh install-oldkernel.sh --endpoint http://hub:30102
#   sh install-oldkernel.sh --check [--endpoint ...]
#   sh install-oldkernel.sh --uninstall
#
# Env overrides: NT_IFACE=eth1 NT_PORTS=80,... NT_HUB=http://HUB:30105/oldkernel
#                NT_WSSE_BODY_BYTES=0..65536 (Python mode only; default 0)
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
WSSE_BODY_BYTES="${NT_WSSE_BODY_BYTES:-0}"

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --hub)      KIT_URLS="$2"; shift 2 ;;
        --mode)     CAPTURE_MODE="$2"; shift 2 ;;
        --wsse-body-bytes) WSSE_BODY_BYTES="$2"; shift 2 ;;
        --check)    MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        *) die "unknown arg: $1" ;;
    esac
done

case "$WSSE_BODY_BYTES" in
    ''|*[!0-9]*) die "WSSE body byte window must be an integer 0..65536" ;;
esac
[ "$WSSE_BODY_BYTES" -le 65536 ] \
    || die "WSSE body byte window must be in range 0..65536"
if [ "$CAPTURE_MODE" = "cpp" ] && [ "$WSSE_BODY_BYTES" -ne 0 ]; then
    die "WSSE body capture is supported only in Python mode; C++03 remains header-only"
fi

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
    if [ -x "$INIT" ]; then
        if have service; then
            service networktracing-legacy stop >/dev/null 2>&1 || true
        fi
        # Also invoke the script directly: an older install may have been
        # started outside the service manager, leaving it unaware of PIDs.
        "$INIT" stop >/dev/null 2>&1 || true
    fi
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
        *'"ok"'*|*'"success"'*) log "hub protocol OK ($ENDPOINT)" ;;
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
if [ -x "$INIT" ]; then
    if have service; then
        service networktracing-legacy stop >/dev/null 2>&1 || true
    fi
    "$INIT" stop >/dev/null 2>&1 || true
fi
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
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS --wsse-body-bytes $WSSE_BODY_BYTES'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS --wsse-body-bytes $WSSE_BODY_BYTES"
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
export NT_WSSE_BODY_BYTES=$WSSE_BODY_BYTES
PIDFILE=/var/run/networktracing-legacy.pid
CONTROL_FILE=/var/lib/networktracing/remote-desired.json
CONTROL_TOKEN_FILE=/var/lib/networktracing/control.token
CONTROL_RUN=/var/lib/networktracing

case "\$1" in
    start)
        if pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null; then
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

if have service; then
    service networktracing-legacy start
    START_RC=$?
else
    "$INIT" start
    START_RC=$?
fi
if [ "$START_RC" -ne 0 ]; then
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "service failed to start"
fi
sleep 2
if ! pgrep -f "$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null; then
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "sniffer not running after start"
fi

log "DONE. Sniffer iface=$IFACE ports=$PORTS -> hub $ENDPOINT (capture-as=$SNIFF_AS)"
if [ "$WSSE_BODY_BYTES" -ne 0 ]; then
    log "WSSE UsernameToken inspection: Python-only, bounded to $WSSE_BODY_BYTES bytes/request"
else
    log "WSSE UsernameToken inspection: disabled (header-only default)"
fi
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
U1NFIFVzZXJuYW1lVG9rZW4gZXh0cmFjdGlvbiBpcyBhdmFpbGFibGUgb25seSB3aGVuIGV4cGxp
Y2l0bHkgZW5hYmxlZAp3aXRoIE5UX1dTU0VfQk9EWV9CWVRFUyBvciAtLXdzc2UtYm9keS1ieXRl
cy4gVGhlIGRlZmF1bHQgcmVtYWlucyBoZWFkZXItb25seS4KClBlcmZvcm1hbmNlOgogICoga2Vy
bmVsIEJQRiBmaWx0ZXIgKFNPX0FUVEFDSF9GSUxURVIpOiBJUHY0L1RDUCByZXF1ZXN0cyBhbmQg
cmVzcG9uc2VzCiAgICBmb3IgbW9uaXRvcmVkIHBvcnRzIGFyZSBjb3BpZWQgdXA7IHVucmVsYXRl
ZCB0cmFmZmljIHN0YXlzIGluIGtlcm5lbAogICogSEVBREVSLU9OTFkgYnkgZGVmYXVsdDsgb3B0
LWluIFdTU0UgcGFyc2luZyBoYXMgc3RyaWN0IHBlci1mbG93L2dsb2JhbCBib3VuZHMKICAqIFBB
Q0tFVF9GQU5PVVQgKC1qIE4pOiBOIGZvcmtlZCB3b3JrZXJzIHNoYXJlIHRoZSBOSUMgYWNyb3Nz
IGNvcmVzClVzYWdlOiAgcHl0aG9uIG50LXNuaWZmLnB5IFstaSBldGgwXSBbLXAgODAsODAwMywu
Li5dIFstaiB3b3JrZXJzXQogICAgICAgICAgICAgICAgICAgICAgICAgICBbLS13c3NlLWJvZHkt
Ynl0ZXMgMC4uNjU1MzZdClN0ZG91dDogb25lIEpTT04gZXZlbnQgcGVyIGxpbmUgLT4gcGlwZSBp
bnRvIG50LXNoaXAucHkuCiIiIgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IHByaW50X2Z1bmN0aW9u
CgppbXBvcnQgYmFzZTY0LCBiaW5hc2NpaSwgZXJybm8sIGpzb24sIG9zLCBzaWduYWwsIHNvY2tl
dCwgc3RydWN0LCBzeXMsIHRpbWUKaW1wb3J0IHVuaWNvZGVkYXRhCmZyb20geG1sLnBhcnNlcnMg
aW1wb3J0IGV4cGF0CgpFVEhfUF9BTEwgPSAweDAwMDMKRVRIX1BfSVAgPSAweDA4MDAKRVRIX1Bf
VkxBTiA9IDB4ODEwMAoKdHJ5OgogICAgaW1wb3J0IG50X2NvbnRyb2wKZXhjZXB0IEltcG9ydEVy
cm9yOgogICAgbnRfY29udHJvbCA9IE5vbmUKCiMgcHkyLjYgc3RyLWluZGV4aW5nIHlpZWxkcyAx
LWNoYXIgc3RyLCBub3QgaW50IChwcm92ZW4gb24gcmVhbCBlbDYgVk0pOwojIG5vcm1hbGl6ZSBz
byBieXRlLWF0LWluZGV4IHdvcmtzIGlkZW50aWNhbGx5IHVuZGVyIHB5dGhvbiAyIGFuZCAzClBZ
MiA9IHN5cy52ZXJzaW9uX2luZm9bMF0gPT0gMgoKCmRlZiBiMmkoYyk6CiAgICByZXR1cm4gb3Jk
KGMpIGlmIFBZMiBlbHNlIGMKCk1FVEhPRFMgPSAoIkdFVCIsICJQT1NUIiwgIlBVVCIsICJERUxF
VEUiLCAiUEFUQ0giLCAiSEVBRCIsICJPUFRJT05TIikKCk1BWF9GTE9XUyA9IDgxOTIgICAgICAg
ICAgICAjIGNvbmN1cnJlbnQgdHJhY2tlZCBoYWxmLWZsb3dzIChwZXIgZGlyZWN0aW9uKQpNQVhf
SERSUyA9IDI2MjE0NCAgICAgICAgICAgIyBtYXggYnl0ZXMgYnVmZmVyZWQgd2FpdGluZyBmb3Ig
XHJcblxyXG4KRkxPV19UVEwgPSAzMDAgICAgICAgICAgICAgICMgc2Vjb25kcyBiZWZvcmUgaWRs
ZSBmbG93IGJ1ZmZlcnMgYXJlIGRyb3BwZWQKTUFYX1dTU0VfQk9EWV9CWVRFUyA9IDY1NTM2ICMg
aGFyZCBjZWlsaW5nIGV2ZW4gaWYgY29uZmlndXJhdGlvbiBpcyBsYXJnZXIKTUFYX1dTU0VfQk9E
WV9GTE9XUyA9IDI1NiAgICMgYXQgbW9zdCAxNiBNaUIgb2Ygb3B0LWluIGJvZHkgYnVmZmVycyBn
bG9iYWxseQpNQVhfV1NTRV9VU0VSTkFNRSA9IDIwMAoKV1NTRV9OQU1FU1BBQ0VTID0gc2V0KCgK
ICAgICJodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEt
d3NzLXdzc2VjdXJpdHktc2VjZXh0LTEuMC54c2QiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNv
YXAub3JnL3dzLzIwMDIvMDcvc2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9y
Zy93cy8yMDAyLzEyL3NlY2V4dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3Mv
MjAwMy8wNi9zZWNleHQiLAopKQoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUo
Im50LXNuaWZmOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCiMgLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LSBwZXJmOiBjQlBGCiMgQXR0YWNoIGEgY2xhc3NpYyBCUEYgcHJvZ3JhbSBzbyB0aGUgS0VSTkVM
IGRyb3BzIGV2ZXJ5dGhpbmcgdGhhdCBpcyBub3QKIyBJUHY0IFRDUCB0byBvciBmcm9tIGEgbW9u
aXRvcmVkIHBvcnQuIFJlcXVlc3QgaGVhZGVycyBkcml2ZSBldmVudHMgYW5kCiMgcmVzcG9uc2Ug
aGVhZGVycyBlbnJpY2ggdGhlbTsgdW5yZWxhdGVkIHRyYWZmaWMgbmV2ZXIgcmVhY2hlcyB1c2Vy
c3BhY2UuClNPX0FUVEFDSF9GSUxURVIgPSAyNgoKZGVmIGJ1aWxkX2JwZihwb3J0cyk6CiAgICAi
IiJDbGFzc2ljIEJQRjogZXRoZXJ0eXBlPT1JUCAmJiBwcm90bz09VENQICYmIGRwb3J0IGluIHBv
cnRzLgogICAgUmV0dXJucyAoZnByb2dfc3RydWN0LCBmaWx0ZXJfYXJyYXkpIGZvciB0aGUgbGli
YyBzZXRzb2Nrb3B0IGNhbGwsCiAgICBvciBOb25lIG9uIGZhaWx1cmUuIE5PVEU6IHNvY2tfZnBy
b2cgY2FycmllcyBhIFBPSU5URVIgdG8gdGhlIGZpbHRlcgogICAgYXJyYXksIHNvIGl0IG11c3Qg
c3RheSBhbGl2ZSB1bnRpbCB0aGUgc3lzY2FsbCDigJQgcHl0aG9uJ3MKICAgIHNvY2tldC5zZXRz
b2Nrb3B0KHN0cikgZmxhdHRlbmluZyBjYW5ub3QgcHJlc2VydmUgaXQuIiIiCgogICAgTERIX0FC
UyA9IDB4MjggICAjIGxkIFtrXTpoCiAgICBMREJfQUJTID0gMHgzMCAgICMgbGQgW2tdOmIKICAg
IEpFUV9LID0gMHgxNSAgICAgIyBqZXEgawogICAgTERYX01TSCA9IDB4QjEgICAjIHggPSA0Kihb
a10mMHhmKSAgKGlobCBieXRlcykKICAgIExESF9JTkQgPSAweDQ4ICAgIyBsZCBbeCtrXTpoCiAg
ICBSRVRfSyA9IDB4MDYKCiAgICAjIFBST1ZFTiBkcG9ydCBibG9jayArIHNwb3J0IGJsb2NrIGF0
IFgrMTQgKGNhbGlicmF0ZWQgRU1QSVJJQ0FMTFkgb24KICAgICMgYSBsaXZlIGtlcm5lbDogaz0x
NCBkZWxpdmVycyByZXNwb25zZSBwYWNrZXRzOyB0aGUgY29ycmVsYXRpb24gdGhlbgogICAgIyB5
aWVsZHMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgZW5kLXRvLWVuZCkuIFJlcXVpcmVz
IHRoZSAxcwogICAgIyByZWN2IHRpbWVvdXQgaW4gbWFpbigpIOKAlCBibG9ja2luZyByZWN2ICsg
QlBGIHN0YXJ2ZXMgYWZ0ZXIgb25lIHBrdC4KICAgIHNrID0gaW50KG9zLmVudmlyb24uZ2V0KCJO
VF9TTklGRl9TUE9SVF9LIiwgIjE0IikpCiAgICBwcyA9IHNvcnRlZChwb3J0cykKICAgIG4gPSBs
ZW4ocHMpCiAgICByZXRfcmVqID0gNSArICg0IGlmIHNrIGVsc2UgMikgKiBuCiAgICByZXRfYWNj
ID0gcmV0X3JlaiArIDEKICAgIHByb2cgPSBbXQogICAgcHJvZy5hcHBlbmQoKExESF9BQlMsIDAs
IDAsIDEyKSkgICAgICAgICAgICAgICAgICMgZXRoZXJ0eXBlID09IElQPwogICAgcHJvZy5hcHBl
bmQoKEpFUV9LLCAwLCByZXRfcmVqIC0gMiwgMHgwODAwKSkKICAgIHByb2cuYXBwZW5kKChMREJf
QUJTLCAwLCAwLCAyMykpICAgICAgICAgICAgICAgICAjIHByb3RvID09IFRDUD8KICAgIHByb2cu
YXBwZW5kKChKRVFfSywgMCwgcmV0X3JlaiAtIDQsIDYpKQogICAgcHJvZy5hcHBlbmQoKExEWF9N
U0gsIDAsIDAsIDE0KSkgICAgICAgICAgICAgICAgICMgWCA9IGlobCo0CiAgICBmb3IgaSwgcCBp
biBlbnVtZXJhdGUocHMpOiAgICAgICAgICAgICAgICAgICAgICAgIyBBOiBkcG9ydCBAIFgrMTYK
ICAgICAgICBwcm9nLmFwcGVuZCgoTERIX0lORCwgMCwgMCwgMTYpKQogICAgICAgIGp0ID0gcmV0
X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgIGpmID0gMCBpZiAoaSA8IG4gLSAxIG9yIHNr
KSBlbHNlIChyZXRfcmVqIC0gKGxlbihwcm9nKSArIDEpKQogICAgICAgIHByb2cuYXBwZW5kKChK
RVFfSywganQsIGpmLCBwKSkKICAgIGlmIHNrOiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAjIEI6IHNwb3J0IEAgWCtzawogICAgICAgIGZvciBpLCBwIGluIGVudW1l
cmF0ZShwcyk6CiAgICAgICAgICAgIHByb2cuYXBwZW5kKChMREhfSU5ELCAwLCAwLCBzaykpCiAg
ICAgICAgICAgIGp0ID0gcmV0X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgICAgICBqZiA9
IDAgaWYgaSA8IG4gLSAxIGVsc2UgKHJldF9yZWogLSAobGVuKHByb2cpICsgMSkpCiAgICAgICAg
ICAgIHByb2cuYXBwZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIHByb2cuYXBwZW5kKChSRVRf
SywgMCwgMCwgMCkpICAgICAgICAgICAgICAgICAgICAjIHJlamVjdAogICAgcHJvZy5hcHBlbmQo
KFJFVF9LLCAwLCAwLCAweDQwMDAwKSkgICAgICAgICAgICAgICMgYWNjZXB0CgogICAgdHJ5Ogog
ICAgICAgIGltcG9ydCBjdHlwZXMKCiAgICAgICAgY2xhc3MgU29ja0ZpbHRlcihjdHlwZXMuU3Ry
dWN0dXJlKToKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJjb2RlIiwgY3R5cGVzLmNfdWludDE2
KSwgKCJqdCIsIGN0eXBlcy5jX3VpbnQ4KSwKICAgICAgICAgICAgICAgICAgICAgICAgKCJqZiIs
IGN0eXBlcy5jX3VpbnQ4KSwgKCJrIiwgY3R5cGVzLmNfdWludDMyKV0KCiAgICAgICAgY2xhc3Mg
U29ja0Zwcm9nKGN0eXBlcy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICAjIG1pcnJvcnMgc3RydWN0
IHNvY2tfZnByb2cge3UxNiBsZW47IHNvY2tfZmlsdGVyICpmaWx0ZXJ9OwogICAgICAgICAgICAj
IGN0eXBlcyBhcHBsaWVzIHRoZSBzYW1lIHBvaW50ZXIgYWxpZ25tZW50IGFzIHRoZSBjb21waWxl
cgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImxlbiIsIGN0eXBlcy5jX3VpbnQxNiksCiAgICAg
ICAgICAgICAgICAgICAgICAgICgiZmlsdGVyIiwgY3R5cGVzLlBPSU5URVIoU29ja0ZpbHRlcikp
XQoKICAgICAgICBhcnIgPSAoU29ja0ZpbHRlciAqIGxlbihwcm9nKSkoKQogICAgICAgIGZvciBp
LCAoY29kZSwganQsIGpmLCBrKSBpbiBlbnVtZXJhdGUocHJvZyk6CiAgICAgICAgICAgIGFycltp
XS5jb2RlID0gY29kZTsgYXJyW2ldLmp0ID0ganQKICAgICAgICAgICAgYXJyW2ldLmpmID0gamY7
IGFycltpXS5rID0gawogICAgICAgIHJldHVybiBTb2NrRnByb2cobGVuKHByb2cpLCBhcnIpLCBh
cnIKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYgYXBwbHlf
cGVyZl9vcHRzKHNvY2ssIHBvcnRzKToKICAgICIiIkJlc3QtZWZmb3J0IGtlcm5lbCBhc3Npc3Q6
IEJQRiBwb3J0IGZpbHRlciArIGJpZyByY3ZidWYuCiAgICBOVF9TTklGRl9OT19CUEY9MSBkaXNh
YmxlcyB0aGUgZmlsdGVyIChkZWJ1Z2dpbmcpLiIiIgogICAgYnVpbHQgPSBOb25lCiAgICBpZiBv
cy5lbnZpcm9uLmdldCgiTlRfU05JRkZfTk9fQlBGIikgPT0gIjEiOgogICAgICAgIGxvZygiTlRf
U05JRkZfTk9fQlBGIHNldCDigJQgc2tpcHBpbmcga2VybmVsIGZpbHRlciIpCiAgICBlbHNlOgog
ICAgICAgIGJ1aWx0ID0gYnVpbGRfYnBmKHBvcnRzKQogICAgaWYgYnVpbHQgaXMgbm90IE5vbmU6
CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpbXBvcnQgY3R5cGVzCiAgICAgICAgICAgIGxpYmMg
PSBjdHlwZXMuQ0RMTCgibGliYy5zby42IikKICAgICAgICAgICAgZnByb2csIGFyciA9IGJ1aWx0
ICAgICAgICAgICAgICAgICAgICAgICMga2VlcCBhcnIgcmVmZXJlbmNlZCEKICAgICAgICAgICAg
cmV0ID0gbGliYy5zZXRzb2Nrb3B0KHNvY2suZmlsZW5vKCksIHNvY2tldC5TT0xfU09DS0VULAog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgU09fQVRUQUNIX0ZJTFRFUiwKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN0eXBlcy5ieXJlZihmcHJvZyksCiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuc2l6ZW9mKGZwcm9nKSkKICAgICAgICAg
ICAgaWYgcmV0ID09IDA6CiAgICAgICAgICAgICAgICBsb2coImtlcm5lbCBCUEYgZmlsdGVyIGF0
dGFjaGVkICglZCBtb25pdG9yZWQgcG9ydHMpIgogICAgICAgICAgICAgICAgICAgICUgbGVuKHBv
cnRzKSkKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGxvZygiV0FSTjogQlBGIGF0
dGFjaCByZWplY3RlZCBieSBrZXJuZWwgKHJldD0lZCkgIgogICAgICAgICAgICAgICAgICAgICLi
gJQgcnVubmluZyB1bmZpbHRlcmVkIiAlIHJldCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFz
IGU6CiAgICAgICAgICAgIGxvZygiV0FSTjogQlBGIGZpbHRlciBhdHRhY2ggZmFpbGVkICglcykg
4oCUIHJ1bm5pbmcgdW5maWx0ZXJlZCIKICAgICAgICAgICAgICAgICUgZSkKICAgIGVsc2U6CiAg
ICAgICAgbG9nKCJXQVJOOiBjdHlwZXMgdW5hdmFpbGFibGUg4oCUIHJ1bm5pbmcgd2l0aG91dCBC
UEYgZmlsdGVyIikKICAgIHRyeToKICAgICAgICB3YW50ID0gOCAqIDEwMjQgKiAxMDI0CiAgICAg
ICAgc29jay5zZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fUkNWQlVGLCB3
YW50KQogICAgICAgIGdvdCA9IHNvY2suZ2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCwgc29j
a2V0LlNPX1JDVkJVRikKICAgICAgICBsb2coInJjdmJ1ZjogJWQgYnl0ZXMiICUgZ290KQogICAg
ZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZygiV0FSTjogU09fUkNWQlVGIHJhaXNl
IGZhaWxlZDogJXMiICUgZSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gcGVyZjogZmFub3V0ClNPTF9QQUNLRVQgPSAy
NjMKUEFDS0VUX0ZBTk9VVCA9IDE4CgpkZWYgYXBwbHlfZmFub3V0KHNvY2ssIGdyb3VwX2lkKToK
ICAgICIiIktlcm5lbCBsb2FkLWJhbGFuY2VzIHBhY2tldHMgYWNyb3NzIGFsbCBzb2NrZXRzIHNo
YXJpbmcgdGhlIGdyb3VwLgogICAgSGFzaGluZyBpcyBwZXItZmxvdy1kaXJlY3Rpb25hbDsgcmVx
dWVzdCBkaXJlY3Rpb24gYWxvbmUgZHJpdmVzIGV2ZW50CiAgICBlbWlzc2lvbiwgc28gZGlyZWN0
aW9uYWwgc3BsaXRzIGFyZSBzYWZlLiBSZXR1cm5zIFRydWUgb24gc3VjY2Vzcy4iIiIKICAgIHRy
eToKICAgICAgICBzb2NrLnNldHNvY2tvcHQoU09MX1BBQ0tFVCwgUEFDS0VUX0ZBTk9VVCwKICAg
ICAgICAgICAgICAgICAgICAgICAgc3RydWN0LnBhY2soIkkiLCBncm91cF9pZCAmIDB4RkZGRikp
CiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBs
b2coIldBUk46IFBBQ0tFVF9GQU5PVVQgZmFpbGVkICglcykg4oCUIHNpbmdsZS1wcm9jZXNzIGNh
cHR1cmUiICUgZSkKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgcGFyc2Vfd3NzZV9ib2R5X2J5
dGVzKHZhbHVlKToKICAgICIiIlZhbGlkYXRlIHRoZSBvcHQtaW4gYm9keSB3aW5kb3cgd2l0aG91
dCBhbGxvd2luZyB1bmJvdW5kZWQgYnVmZmVycy4iIiIKICAgIHRyeToKICAgICAgICBzaXplID0g
aW50KHZhbHVlIG9yIDApCiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAg
ICAgcmFpc2UgU3lzdGVtRXhpdCgid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgYW4gaW50ZWdlciIp
CiAgICBpZiBzaXplIDwgMCBvciBzaXplID4gTUFYX1dTU0VfQk9EWV9CWVRFUzoKICAgICAgICBy
YWlzZSBTeXN0ZW1FeGl0KCJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi4lZCIg
JQogICAgICAgICAgICAgICAgICAgICAgICAgTUFYX1dTU0VfQk9EWV9CWVRFUykKICAgIHJldHVy
biBzaXplCgoKZGVmIHBhcnNlX2FyZ3MoYXJndik6CiAgICBpZmFjZSA9IE5vbmUKICAgIHBvcnRz
ID0gWzgwLCA4MDAzLCA4MDA1LCA4MDA3LCA4MDA5LCA4MDEwLCA4MDExXQogICAgdmVyYm9zZSA9
IEZhbHNlCiAgICB3b3JrZXJzID0gMQogICAgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2Vfd3NzZV9i
b2R5X2J5dGVzKAogICAgICAgIG9zLmVudmlyb24uZ2V0KCJOVF9XU1NFX0JPRFlfQllURVMiLCAi
MCIpKQogICAgaSA9IDAKICAgIHdoaWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFyZ3Zb
aV0KICAgICAgICBpZiBhID09ICItaSI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2
KToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1pIHJlcXVpcmVzIGFuIGludGVy
ZmFjZSIpCiAgICAgICAgICAgIGkgKz0gMTsgaWZhY2UgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBh
ID09ICItcCI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAgICAgICAg
ICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1wIHJlcXVpcmVzIGEgY29tbWEtc2VwYXJhdGVkIHBvcnQg
bGlzdCIpCiAgICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAg
ICBwb3J0cyA9IFtpbnQoeCkgZm9yIHggaW4gYXJndltpXS5zcGxpdCgiLCIpIGlmIHguc3RyaXAo
KV0KICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCJpbnZhbGlkIHBvcnQgbGlzdCIpCiAgICAgICAgICAgIGlmIG5vdCBwb3J0cyBv
ciBhbnkobm90IHZhbGlkX3BvcnQoeCkgZm9yIHggaW4gcG9ydHMpOgogICAgICAgICAgICAgICAg
cmFpc2UgU3lzdGVtRXhpdCgicG9ydHMgbXVzdCBiZSBpbiByYW5nZSAxLi42NTUzNSIpCiAgICAg
ICAgZWxpZiBhID09ICItaiI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAg
ICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1qIHJlcXVpcmVzIGEgd29ya2VyIGNvdW50
IikKICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdv
cmtlcnMgPSBtYXgoMSwgaW50KGFyZ3ZbaV0pKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJv
cjoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImludmFsaWQgd29ya2VyIGNvdW50
IikKICAgICAgICBlbGlmIGEgPT0gIi12IjoKICAgICAgICAgICAgdmVyYm9zZSA9IFRydWUKICAg
ICAgICBlbGlmIGEgPT0gIi0td3NzZS1ib2R5LWJ5dGVzIjoKICAgICAgICAgICAgaWYgaSArIDEg
Pj0gbGVuKGFyZ3YpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLS13c3NlLWJv
ZHktYnl0ZXMgcmVxdWlyZXMgYSBieXRlIGNvdW50IikKICAgICAgICAgICAgaSArPSAxCiAgICAg
ICAgICAgIHdzc2VfYm9keV9ieXRlcyA9IHBhcnNlX3dzc2VfYm9keV9ieXRlcyhhcmd2W2ldKQog
ICAgICAgIGVsaWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2Rv
Y19fKTsgcmFpc2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNl
IFN5c3RlbUV4aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0
dXJuIGlmYWNlLCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXMK
CgpjbGFzcyBGbG93KG9iamVjdCk6CiAgICBfX3Nsb3RzX18gPSAoImJ1ZiIsICJoZHJzIiwgInRv
dWNoZWQiLCAiZXZlbnQiLCAiYm9keV9nb2FsIiwKICAgICAgICAgICAgICAgICAiaGVhZF9ieXRl
cyIpCiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5idWYgPSBieXRlYXJyYXko
KQogICAgICAgIHNlbGYuaGRycyA9IE5vbmUKICAgICAgICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRp
bWUoKQogICAgICAgIHNlbGYuZXZlbnQgPSBOb25lCiAgICAgICAgc2VsZi5ib2R5X2dvYWwgPSAw
CiAgICAgICAgc2VsZi5oZWFkX2J5dGVzID0gMAoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAtLS0tClBFTkRJ
TkdfVFRMID0gNS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBhZnRlciB0aGlz
IG1hbnkgc2Vjb25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNhcDsgb3ZlcmZs
b3cgZmx1c2hlcyBvbGRlc3QgZmlyc3QKUEVORElOR19QRVJfRkxPVyA9IDMyICAgICMgYm91bmQg
YSBzaW5nbGUgcGlwZWxpbmVkL2hvc3RpbGUga2VlcC1hbGl2ZSBmbG93ClNXRUVQX0lOVEVSVkFM
ID0gMS4wICAgICAjIGhvbm9yIFBFTkRJTkdfVFRMIGV2ZW4gd2hlbiB0aGUgc29ja2V0IGdvZXMg
aWRsZQoKIyBwZW5kaW5nWyhzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KV0gIC0tIGtleSBp
cyB0aGUgUkVTUE9OU0UgdHVwbGU6CiMgc2VydmVyLT5jbGllbnQuIFZhbHVlOiBbZXZlbnQsIHJl
cV90c10uIEEgbGlzdCBwZXIga2V5IGhhbmRsZXMgSFRUUAojIGtlZXAtYWxpdmUgcGlwZWxpbmlu
ZyAoc2V2ZXJhbCByZXF1ZXN0cyBiZWZvcmUgcmVzcG9uc2VzIGFycml2ZSkuCnBlbmRpbmcgPSB7
fQoKCmRlZiBwZW5kaW5nX2RlbChyayk6CiAgICBwZW5kaW5nLnBvcChyaywgTm9uZSkKCgpkZWYg
cGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190Ymw9Tm9uZSk6CiAgICAiIiJGbHVzaCB0aGUg
b2xkZXN0IHBlbmRpbmcgZXZlbnQgZm9yIHRoaXMgcmVzcG9uc2UgdHVwbGUgKEZJTi9SU1Qgb3IK
ICAgIG92ZXJmbG93IHBhdGgpLiBFbWl0cyB3aGF0ZXZlciB0aGUgZXZlbnQgaGFzIOKAlCBzdGF0
dXMgc3RheXMgbnVsbC4iIiIKICAgIGlmIHBlbmRpbmdfdGJsIGlzIE5vbmU6CiAgICAgICAgcGVu
ZGluZ190YmwgPSBwZW5kaW5nCiAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBu
b3QgbHN0OgogICAgICAgIHJldHVybiBOb25lCiAgICBldiwgXyA9IGxzdC5wb3AoMCkKICAgIGlm
IG5vdCBsc3Q6CiAgICAgICAgcGVuZGluZ190YmwucG9wKHJrLCBOb25lKQogICAgb3V0LmFwcGVu
ZChldikKICAgIHJldHVybiBldgoKCmRlZiBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxvYWQpOgog
ICAgIiIiRmlyc3QgbGluZSAnSFRUUC8xLnggTk5OIC4uLicgLT4gKHN0YXR1c19pbnR8Tm9uZSwg
Y29udGVudF9sZW58Tm9uZSkuCiAgICBPbmx5IGxvb2tzIGF0IHdoYXQncyBpbiB0aGlzIHNlZ21l
bnQ7IGhlYWRlcnMgZml0IG9uZSBzZWdtZW50IGZvciBhbGwKICAgIHJlYWxpc3RpYyBBUEkgcmVz
cG9uc2VzLiIiIgogICAgdHJ5OgogICAgICAgIGhlYWQgPSBwYXlsb2FkLnNwbGl0KGIiXHJcblxy
XG4iLCAxKVswXQogICAgICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5z
cGxpdChiIlxuIikKICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAgICBpZiBs
ZW4oZmlyc3QpIDwgMiBvciBub3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6CiAgICAg
ICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgc3QgPSBpbnQoZmlyc3RbMV0pCiAgICBl
eGNlcHQgKFZhbHVlRXJyb3IsIEluZGV4RXJyb3IpOgogICAgICAgIHJldHVybiBOb25lLCBOb25l
CiAgICBjbGVuID0gTm9uZQogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBsb3cgPSBs
bi5sb3dlcigpCiAgICAgICAgaWYgbG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0aDoiKToK
ICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY2xlbiA9IGludChsbi5zcGxpdChiIjoi
LCAxKVsxXS5zdHJpcCgpKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAg
ICAgICAgIHBhc3MKICAgICAgICAgICAgYnJlYWsKICAgIHJldHVybiBzdCwgY2xlbgoKCmRlZiBj
b3JyZWxhdGVfcmVzcG9uc2UocGVuZGluZ190YmwsIHJrLCBwYXlsb2FkLCBub3csIG91dCk6CiAg
ICAiIiJBdHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhlIG9sZGVzdCByZXF1ZXN0IG9uIGEg
Y29ubmVjdGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5nIGNhbiBsZWF2ZSBzZXZlcmFsIHJl
cXVlc3RzIHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXItdHVwbGUuICBDb25zdW1lIGV4YWN0
bHkgb25lIGVudHJ5OyBkZWxldGluZyB0aGUgd2hvbGUga2V5IGhlcmUgbG9zZXMKICAgIGV2ZXJ5
IHJlcXVlc3QgYWZ0ZXIgdGhlIGZpcnN0IHJlc3BvbnNlLgogICAgIiIiCiAgICBzdCwgY2xlbiA9
IHBhcnNlX3Jlc3BvbnNlX2hlYWQocGF5bG9hZCkKICAgIGlmIHN0IGlzIE5vbmU6CiAgICAgICAg
cmV0dXJuIEZhbHNlCiAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBub3QgZW50
OgogICAgICAgIHJldHVybiBGYWxzZQogICAgZXYsIHN0YXJ0ZWQgPSBlbnQucG9wKDApCiAgICBp
ZiBub3QgZW50OgogICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgIGV2WyJzdGF0
dXMiXSA9IHN0CiAgICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgwLCBpbnQoKG5vdyAtIHN0YXJ0
ZWQpICogMTAwMCkpCiAgICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgIGV2WyJyZXNwX2J5
dGVzIl0gPSBjbGVuCiAgICBvdXQuYXBwZW5kKGV2KQogICAgcmV0dXJuIFRydWUKCgpkZWYgdmFs
aWRfcG9ydChwKToKICAgIHRyeToKICAgICAgICByZXR1cm4gMSA8PSBpbnQocCkgPD0gNjU1MzUK
ICAgIGV4Y2VwdCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UK
CgpkZWYgYmFzaWNfdXNlcih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRlciB2YWx1
ZSAtPiAodXNlcnxOb25lLCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBwYXJ0cyA9
IHZhbHVlLnN0cmlwKCkuc3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0gMjoKICAg
ICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAg
aWYgc2NoZW1lID09ICJiYXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQgPSBwYXJ0
c1sxXS5zdHJpcCgpCiAgICAgICAgICAgIGlmIGxlbihwYWQpID4gMTAyNDoKICAgICAgICAgICAg
ICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxlbihwYWQp
ICUgNCkKICAgICAgICAgICAgcmF3ID0gYmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAgICAgICAg
IGlmIGxlbihyYXcpID4gNTEyOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAg
ICAgICAgICAgaWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAgICAgICB1c2VyID0gcmF3LnNwbGl0
KGIiOiIsIDEpWzBdCiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci5kZWNvZGUoInV0Zi04Iiwg
InJlcGxhY2UiKVs6NjRdLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAg
ICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFyZXIiOgogICAg
ICAgIHJldHVybiBOb25lLCAiYmVhcmVyIgogICAgcmV0dXJuIE5vbmUsIE5vbmUKCgpkZWYgbm9y
bWFsaXplX3dzc2VfdXNlcm5hbWUodmFsdWUpOgogICAgIiIiUmV0dXJuIGEgc21hbGwsIHByaW50
YWJsZSB1c2VybmFtZSBvciBOb25lOyBuZXZlciByZXR1cm4gdG9rZW4gZGF0YS4iIiIKICAgIGlm
IHZhbHVlIGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToKICAgICAgICB1c2Vy
bmFtZSA9IHZhbHVlLnN0cmlwKCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJu
IE5vbmUKICAgIGlmIG5vdCB1c2VybmFtZSBvciBsZW4odXNlcm5hbWUpID4gTUFYX1dTU0VfVVNF
Uk5BTUU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGZvciBjaGFyIGluIHVzZXJuYW1lOgogICAg
ICAgIGlmIHVuaWNvZGVkYXRhLmNhdGVnb3J5KGNoYXIpLnN0YXJ0c3dpdGgoIkMiKToKICAgICAg
ICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVybiB1c2VybmFtZQoKCmRlZiBleHRyYWN0X3dzc2Vf
dXNlcm5hbWUoYm9keSk6CiAgICAiIiJQYXJzZSBhIGJvdW5kZWQsIHBvc3NpYmx5IHBhcnRpYWwg
U09BUCBwcmVmaXggYW5kIHJldHVybiBvbmx5IFVzZXJuYW1lLgoKICAgIEV4cGF0IGlzIHJ1biBp
bmNyZW1lbnRhbGx5IHNvIGEgVXNlcm5hbWVUb2tlbiBpbiB0aGUgU09BUCBIZWFkZXIgY2FuIGJl
CiAgICByZWNvZ25pemVkIHdpdGhvdXQgcmV0YWluaW5nIG9yIHJlcXVpcmluZyB0aGUgY29tcGxl
dGUgcmVxdWVzdCBib2R5LgogICAgRFREL2VudGl0eSBkZWNsYXJhdGlvbnMgYXJlIHJlamVjdGVk
IGJlZm9yZSBwYXJzaW5nLgogICAgIiIiCiAgICBpZiBub3QgYm9keSBvciBsZW4oYm9keSkgPiBN
QVhfV1NTRV9CT0RZX0JZVEVTIG9yIGIiXHgwMCIgaW4gYm9keToKICAgICAgICByZXR1cm4gTm9u
ZQogICAgbG93ZXJlZCA9IGJ5dGVzKGJvZHkpLmxvd2VyKCkKICAgIGlmIGIiPCFkb2N0eXBlIiBp
biBsb3dlcmVkIG9yIGIiPCFlbnRpdHkiIGluIGxvd2VyZWQ6CiAgICAgICAgcmV0dXJuIE5vbmUK
CiAgICBzdGF0ZSA9IHsic3RhY2siOiBbXSwgInRva2VuX2RlcHRoIjogMCwgInVzZXJuYW1lX2Rl
cHRoIjogMCwKICAgICAgICAgICAgICJjaGFycyI6IFtdLCAidG9vX2xvbmciOiBGYWxzZSwgInJl
c3VsdCI6IE5vbmV9CgogICAgZGVmIHNwbGl0X25hbWUobmFtZSk6CiAgICAgICAgaWYgIn0iIG5v
dCBpbiBuYW1lOgogICAgICAgICAgICByZXR1cm4gIiIsIG5hbWUKICAgICAgICByZXR1cm4gbmFt
ZS5yc3BsaXQoIn0iLCAxKQoKICAgIGRlZiBzdGFydChuYW1lLCBhdHRycyk6CiAgICAgICAgbmFt
ZXNwYWNlLCBsb2NhbF9uYW1lID0gc3BsaXRfbmFtZShuYW1lKQogICAgICAgIHN0YXRlWyJzdGFj
ayJdLmFwcGVuZCgobmFtZXNwYWNlLCBsb2NhbF9uYW1lKSkKICAgICAgICBkZXB0aCA9IGxlbihz
dGF0ZVsic3RhY2siXSkKICAgICAgICBpZiAobm90IHN0YXRlWyJ0b2tlbl9kZXB0aCJdIGFuZCBs
b2NhbF9uYW1lID09ICJVc2VybmFtZVRva2VuIiBhbmQKICAgICAgICAgICAgICAgIG5hbWVzcGFj
ZSBpbiBXU1NFX05BTUVTUEFDRVMpOgogICAgICAgICAgICBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9
IGRlcHRoCiAgICAgICAgZWxpZiAoc3RhdGVbInRva2VuX2RlcHRoIl0gYW5kCiAgICAgICAgICAg
ICAgZGVwdGggPT0gc3RhdGVbInRva2VuX2RlcHRoIl0gKyAxIGFuZAogICAgICAgICAgICAgIGxv
Y2FsX25hbWUgPT0gIlVzZXJuYW1lIiBhbmQKICAgICAgICAgICAgICBuYW1lc3BhY2UgPT0gc3Rh
dGVbInN0YWNrIl1bc3RhdGVbInRva2VuX2RlcHRoIl0gLSAxXVswXSk6CiAgICAgICAgICAgIHN0
YXRlWyJ1c2VybmFtZV9kZXB0aCJdID0gZGVwdGgKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0g
PSBbXQogICAgICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IEZhbHNlCgogICAgZGVmIGNoYXJz
KHZhbHVlKToKICAgICAgICBpZiBub3Qgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gb3Igc3RhdGVb
InRvb19sb25nIl06CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHN0YXRlWyJjaGFycyJdLmFw
cGVuZCh2YWx1ZSkKICAgICAgICBpZiBzdW0oW2xlbihwYXJ0KSBmb3IgcGFydCBpbiBzdGF0ZVsi
Y2hhcnMiXV0pID4gTUFYX1dTU0VfVVNFUk5BTUUgKyAyOgogICAgICAgICAgICBzdGF0ZVsiY2hh
cnMiXSA9IFtdCiAgICAgICAgICAgIHN0YXRlWyJ0b29fbG9uZyJdID0gVHJ1ZQoKICAgIGRlZiBl
bmQobmFtZSk6CiAgICAgICAgZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0pCiAgICAgICAgaWYg
c3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIGlmIG5vdCBzdGF0
ZVsidG9vX2xvbmciXSBhbmQgc3RhdGVbInJlc3VsdCJdIGlzIE5vbmU6CiAgICAgICAgICAgICAg
ICBzdGF0ZVsicmVzdWx0Il0gPSBub3JtYWxpemVfd3NzZV91c2VybmFtZSgKICAgICAgICAgICAg
ICAgICAgICB1IiIuam9pbihzdGF0ZVsiY2hhcnMiXSkpCiAgICAgICAgICAgIHN0YXRlWyJ1c2Vy
bmFtZV9kZXB0aCJdID0gMAogICAgICAgICAgICBzdGF0ZVsiY2hhcnMiXSA9IFtdCiAgICAgICAg
aWYgc3RhdGVbInRva2VuX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIHN0YXRlWyJ0b2tl
bl9kZXB0aCJdID0gMAogICAgICAgIGlmIHN0YXRlWyJzdGFjayJdOgogICAgICAgICAgICBzdGF0
ZVsic3RhY2siXS5wb3AoKQoKICAgIHRyeToKICAgICAgICBwYXJzZXIgPSBleHBhdC5QYXJzZXJD
cmVhdGUoTm9uZSwgIn0iKQogICAgICAgIGlmIGhhc2F0dHIocGFyc2VyLCAicmV0dXJuc191bmlj
b2RlIik6CiAgICAgICAgICAgIHBhcnNlci5yZXR1cm5zX3VuaWNvZGUgPSBUcnVlCiAgICAgICAg
cGFyc2VyLlN0YXJ0RWxlbWVudEhhbmRsZXIgPSBzdGFydAogICAgICAgIHBhcnNlci5DaGFyYWN0
ZXJEYXRhSGFuZGxlciA9IGNoYXJzCiAgICAgICAgcGFyc2VyLkVuZEVsZW1lbnRIYW5kbGVyID0g
ZW5kCiAgICAgICAgaWYgKGhhc2F0dHIocGFyc2VyLCAiU2V0UGFyYW1FbnRpdHlQYXJzaW5nIikg
YW5kCiAgICAgICAgICAgICAgICBoYXNhdHRyKGV4cGF0LCAiWE1MX1BBUkFNX0VOVElUWV9QQVJT
SU5HX05FVkVSIikpOgogICAgICAgICAgICBwYXJzZXIuU2V0UGFyYW1FbnRpdHlQYXJzaW5nKGV4
cGF0LlhNTF9QQVJBTV9FTlRJVFlfUEFSU0lOR19ORVZFUikKICAgICAgICBwYXJzZXIuUGFyc2Uo
Ynl0ZXMoYm9keSksIEZhbHNlKQogICAgZXhjZXB0IChleHBhdC5FeHBhdEVycm9yLCBWYWx1ZUVy
cm9yLCBUeXBlRXJyb3IpOgogICAgICAgICMgQSBib3VuZGVkIHByZWZpeCBpcyBjb21tb25seSBp
bmNvbXBsZXRlLiBBIHVzZXJuYW1lIGZ1bGx5IGNsb3NlZAogICAgICAgICMgYmVmb3JlIHRoZSB0
cnVuY2F0aW9uIHBvaW50IGlzIHN0aWxsIHNhZmUgdG8gdXNlLgogICAgICAgIHBhc3MKICAgIHJl
dHVybiBzdGF0ZVsicmVzdWx0Il0KCgpkZWYgaXNfc29hcF9jb250ZW50X3R5cGUodmFsdWUpOgog
ICAgaWYgbm90IHZhbHVlOgogICAgICAgIHJldHVybiBGYWxzZQogICAgbWVkaWFfdHlwZSA9IHZh
bHVlLnNwbGl0KCI7IiwgMSlbMF0uc3RyaXAoKS5sb3dlcigpCiAgICByZXR1cm4gKG1lZGlhX3R5
cGUgaW4gKCJ0ZXh0L3htbCIsICJhcHBsaWNhdGlvbi94bWwiLAogICAgICAgICAgICAgICAgICAg
ICAgICAgICAiYXBwbGljYXRpb24vc29hcCt4bWwiKSBvcgogICAgICAgICAgICBtZWRpYV90eXBl
LmVuZHN3aXRoKCIreG1sIikpCgoKZGVmIGZpbmlzaF9ldmVudChmbG93LCBrZXksIGRzdF9pcCwg
ZHBvcnQsIHNyY19pcCwgc3BvcnQsIHBvcnRzLCBub2RlX2hvc3QpOgogICAgaCA9IGZsb3cuaGRy
cwogICAgdXNlciA9IHNjaGVtZSA9IE5vbmUKICAgIGF1dGh6ID0gaC5nZXQoImF1dGhvcml6YXRp
b24iKQogICAgaWYgYXV0aHo6CiAgICAgICAgdXNlciwgc2NoZW1lID0gYmFzaWNfdXNlcihhdXRo
eikKICAgICMgVzNDIHRyYWNlIGNvbnRleHQ6IGhvbm9yIGluY29taW5nIHRyYWNlcGFyZW50LCBl
bHNlIGdlbmVyYXRlIG9uZSBzbwogICAgIyBldmVyeSB0cmFuc2FjdGlvbiBjYXJyaWVzIGEgdHJh
Y2VfaWQgZm9yIGh1Yi1zaWRlIGNvcnJlbGF0aW9uLgogICAgIyBOT1RFIHB5Mi42OiBieXRlcyBo
YXMgbm8gLmhleCgpIOKAlCB1c2UgYmluYXNjaWkuaGV4bGlmeS4KICAgIHRwID0gaC5nZXQoInRy
YWNlcGFyZW50IikKICAgIHRyYWNlX2lkID0gTm9uZQogICAgaWYgdHA6CiAgICAgICAgcGFydHMg
PSB0cC5zcGxpdCgiLSIpCiAgICAgICAgaWYgbGVuKHBhcnRzKSA9PSA0IGFuZCBsZW4ocGFydHNb
MV0pID09IDMyOgogICAgICAgICAgICB0cmFjZV9pZCA9IHBhcnRzWzFdLmxvd2VyKCkKICAgIGlm
IG5vdCB0cmFjZV9pZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJuZCA9IGJpbmFzY2lpLmhl
eGxpZnkob3MudXJhbmRvbSgxNikpCiAgICAgICAgICAgIHJuZCA9IHJuZC5kZWNvZGUoImFzY2lp
IikgaWYgaGFzYXR0cihybmQsICJkZWNvZGUiKSBlbHNlIHJuZAogICAgICAgIGV4Y2VwdCBFeGNl
cHRpb246CiAgICAgICAgICAgIHJuZCA9ICgiJTAzMngiICUgKGludCh0aW1lLnRpbWUoKSAqIDEw
MDApKSlbLTMyOl0KICAgICAgICBwaWQ4ID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDgp
KQogICAgICAgIHBpZDggPSBwaWQ4LmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHBpZDgsICJk
ZWNvZGUiKSBlbHNlIHBpZDgKICAgICAgICB0cCA9ICIwMC0lcy0lcy0wMSIgJSAocm5kLCBwaWQ4
KQogICAgICAgIHRyYWNlX2lkID0gcm5kCiAgICBldiA9IHsKICAgICAgICAidHMiOiBpbnQodGlt
ZS50aW1lKCkpLAogICAgICAgICJob3N0Ijogbm9kZV9ob3N0LAogICAgICAgICJzcmMiOiAicGNh
cCIsCiAgICAgICAgInNlcnZpY2UiOiAicG9ydDolZCIgJSBkcG9ydCwKICAgICAgICAibWV0aG9k
IjogaC5nZXQoIl9tZXRob2QiKSBvciAiLSIsCiAgICAgICAgInBhdGgiOiAoaC5nZXQoIl9wYXRo
Iikgb3IgIi0iKS5zcGxpdCgiPyIsIDEpWzBdWzoxMjBdLAogICAgICAgICJ1c2VyIjogdXNlciwK
ICAgICAgICAic2NoZW1lIjogc2NoZW1lLAogICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJz
b3VyY2VfcHJvYmUiOiAicGNhcC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9z
dCIpLAogICAgICAgICJ1c2VyX2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAi
eF9mb3J3YXJkZWRfZm9yIjogaC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxs
ZXIiOiBzcmNfaXAsCiAgICAgICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9p
cCI6IGRzdF9pcCwKICAgICAgICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9u
aXRvcmluZyBzY2hlbWEgKG9wcyBBUEktbG9nIGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVz
L2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgYXJlIHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVz
dC1vbmx5CiAgICAgICAgIyBjYXB0dXJlIGNhbm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0
aGUgaHViIHRvIGVucmljaCBvciBsZWF2ZS4KICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBd
LAogICAgICAgICJ0cmFjZV9pZCI6IHRyYWNlX2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9u
ZSwgICAgICAgICAgIyBodWIgbWFwcyBwb3J0LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAg
ICAgICAibW9kdWxlX2lkIjogInBjYXAtaHR0cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3Bv
bnNlIGNvcnJlbGF0aW9uIG9ubHkgZm9yIG1vbml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAg
IyByZXNwb25zZS1zaWRlIGZpbHRlciBtYXkgc3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFs
IHNwb3J0IGVxdWFsIHRvIGEKICAgICMgbW9uaXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3Mg
YmVjYXVzZSBwYXJzZV9yZXNwb25zZV9oZWFkIHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYg
KGRwb3J0IGluIHBvcnRzIG9yIGguZ2V0KCJfbWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBfZW1p
dF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgog
ICAgIiIiRGlzY2FyZCBjYXB0dXJlIGJ1ZmZlcnMsIHRoZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRp
emVkIGV2ZW50IG9ubHkuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0
YQogICAgZXYgPSBmbC5ldmVudAogICAgZmxvd3MucG9wKGtleSwgTm9uZSkKICAgIGlmIG5vdCBl
djoKICAgICAgICByZXR1cm4KICAgIGV2WyJyZXFfYnl0ZXMiXSA9IGZsLmhlYWRfYnl0ZXMKICAg
IGlmIHBlbmRpbmdfdGJsIGlzIE5vbmU6CiAgICAgICAgb3V0LmFwcGVuZChldikKICAgICAgICBy
ZXR1cm4KICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpCiAgICBlbnQgPSBw
ZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBlbnQgaXMgTm9uZToKICAgICAgICBpZiBsZW4ocGVu
ZGluZ190YmwpID49IFBFTkRJTkdfTUFYOgogICAgICAgICAgICBfZmx1c2hfb2xkZXN0X3BlbmRp
bmcocGVuZGluZ190YmwsIG91dCkKICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10gPSBbXQog
ICAgZWxpZiBsZW4oZW50KSA+PSBQRU5ESU5HX1BFUl9GTE9XOgogICAgICAgIHBlbmRpbmdfcG9w
KHJrLCBvdXQsIHBlbmRpbmdfdGJsKQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykK
ICAgICAgICBpZiBlbnQgaXMgTm9uZToKICAgICAgICAgICAgZW50ID0gcGVuZGluZ190Ymxbcmtd
ID0gW10KICAgIGVudC5hcHBlbmQoW2V2LCBub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGlt
ZS50aW1lKCldKQoKCmRlZiBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwgcGF5bG9hZCwg
bWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KToKICAgICIiIkFwcGVuZCBubyBtb3JlIHRoYW4g
Ym9keV9nb2FsIGJ5dGVzIGFuZCBmaW5pc2ggYXMgc29vbiBhcyBwb3NzaWJsZS4iIiIKICAgIHJl
bWFpbmluZyA9IGZsLmJvZHlfZ29hbCAtIGxlbihmbC5idWYpCiAgICBpZiByZW1haW5pbmcgPiAw
IGFuZCBwYXlsb2FkOgogICAgICAgIGZsLmJ1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWRbOnJl
bWFpbmluZ10pKQogICAgdXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwuYnVmKQog
ICAgaWYgdXNlcm5hbWU6CiAgICAgICAgZmwuZXZlbnRbInVzZXIiXSA9IHVzZXJuYW1lCiAgICAg
ICAgZmwuZXZlbnRbInNjaGVtZSJdID0gIndzc2UiCiAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwu
YnVmKSA+PSBmbC5ib2R5X2dvYWw6CiAgICAgICAgX2VtaXRfcmVxdWVzdChmbG93cywga2V5LCBm
bCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVybiBUcnVlCiAgICBy
ZXR1cm4gRmFsc2UKCgpkZWYgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2X2tleSwgcGF5
bG9hZCwgbWV0YSwgcG9ydHMsIG5vZGVfaG9zdCwgb3V0LAogICAgICAgICAgICAgICAgICAgcGVu
ZGluZ190Ymw9Tm9uZSwgbm93PU5vbmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgICIiIkZlZWQg
b25lIGRpcmVjdGlvbidzIHBheWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0
KS4KCiAgICBCb2RpZXMgYXJlIGlnbm9yZWQgdW5sZXNzIHdzc2VfYm9keV9ieXRlcyBpcyBub24t
emVyby4gSW4gb3B0LWluIG1vZGUsCiAgICBvbmx5IFhNTCByZXF1ZXN0cyB3aXRoIENvbnRlbnQt
TGVuZ3RoIGFyZSBpbnNwZWN0ZWQsIGVhY2ggYnVmZmVyIGlzCiAgICBib3VuZGVkIGJ5IHdzc2Vf
Ym9keV9ieXRlcywgYW5kIG9ubHkgYSByZWNvZ25pemVkIFdTU0UgdXNlcm5hbWUgcmVhY2hlcwog
ICAgdGhlIGV2ZW50LiBUaGUgYm9keSBhbmQgYWxsIG90aGVyIFVzZXJuYW1lVG9rZW4gbWF0ZXJp
YWwgYXJlIGRpc2NhcmRlZC4KICAgICIiIgogICAgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9y
dCA9IG1ldGEKICAgIGlmIG5vdCB2YWxpZF9wb3J0KGRwb3J0KSBvciBub3QgdmFsaWRfcG9ydChz
cG9ydCk6CiAgICAgICAgcmV0dXJuCiAgICBmbCA9IGZsb3dzLmdldChrZXkpCiAgICBpZiBmbCBp
cyBOb25lOgogICAgICAgIGZsID0gRmxvdygpCiAgICAgICAgZmxvd3Nba2V5XSA9IGZsCiAgICAg
ICAgaWYgbGVuKGZsb3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICAgICAgZW5mb3JjZV9saW1pdChm
bG93cywgdGltZS50aW1lKCkpCiAgICBmbC50b3VjaGVkID0gdGltZS50aW1lKCkKCiAgICBpZiBm
bC5ldmVudCBpcyBub3QgTm9uZToKICAgICAgICBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBm
bCwgcGF5bG9hZCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVybgoK
ICAgIGZsLmJ1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWQpKQogICAgaWR4ID0gZmwuYnVmLmZp
bmQoYiJcclxuXHJcbiIpCiAgICBpZiBpZHggPCAwOgogICAgICAgIGlmIGxlbihmbC5idWYpID4g
TUFYX0hEUlM6CiAgICAgICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJu
CiAgICBoZWFkID0gYnl0ZXMoZmwuYnVmWzppZHhdKQogICAgbGluZXMgPSBoZWFkLnJlcGxhY2Uo
YiJcclxuIiwgYiJcbiIpLnNwbGl0KGIiXG4iKQogICAgaGRycyA9IHt9CiAgICBmaXJzdCA9IGxp
bmVzWzBdLnN0cmlwKCkuc3BsaXQoKQogICAgaWYgbGVuKGZpcnN0KSA+PSAyIGFuZCBmaXJzdFsw
XSBpbiBbbS5lbmNvZGUoKSBmb3IgbSBpbiBNRVRIT0RTXToKICAgICAgICBoZHJzWyJfbWV0aG9k
Il0gPSBmaXJzdFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgICAgIGhkcnNbIl9w
YXRoIl0gPSBmaXJzdFsxXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgZWxzZToKICAg
ICAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgICAgIHJldHVybgogICAgZm9yIGxuIGluIGxp
bmVzWzE6XToKICAgICAgICBpZiBiIjoiIG5vdCBpbiBsbjoKICAgICAgICAgICAgY29udGludWUK
ICAgICAgICBrbiwga3YgPSBsbi5zcGxpdChiIjoiLCAxKQogICAgICAgIGhkcnNba24uc3RyaXAo
KS5sb3dlcigpLmRlY29kZSgKICAgICAgICAgICAgImFzY2lpIiwgInJlcGxhY2UiKV0gPSBrdi5z
dHJpcCgpLmRlY29kZSgKICAgICAgICAgICAgICAgICJ1dGYtOCIsICJyZXBsYWNlIilbOjE4MF0K
ICAgIGZsLmhkcnMgPSBoZHJzCiAgICBmbC5ldmVudCA9IGZpbmlzaF9ldmVudChmbCwga2V5LCBk
c3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgICAg
cG9ydHMsIG5vZGVfaG9zdCkKICAgIGlmIG5vdCBmbC5ldmVudDoKICAgICAgICBmbG93cy5wb3Ao
a2V5LCBOb25lKQogICAgICAgIHJldHVybgogICAgZmwuaGVhZF9ieXRlcyA9IGlkeCArIDQKICAg
IGluaXRpYWxfYm9keSA9IGJ5dGVzKGZsLmJ1ZltpZHggKyA0Ol0pCiAgICBmbC5idWYgPSBieXRl
YXJyYXkoKQoKICAgIGlmIChmbC5ldmVudC5nZXQoInVzZXIiKSBvciBub3Qgd3NzZV9ib2R5X2J5
dGVzIG9yCiAgICAgICAgICAgIG5vdCBpc19zb2FwX2NvbnRlbnRfdHlwZShoZHJzLmdldCgiY29u
dGVudC10eXBlIikpKToKICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRh
LCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAgICAgcmV0dXJuCiAgICB0cnk6CiAgICAgICAg
Y29udGVudF9sZW5ndGggPSBpbnQoaGRycy5nZXQoImNvbnRlbnQtbGVuZ3RoIiwgIiIpKQogICAg
ZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIGNvbnRlbnRfbGVuZ3RoID0g
MAogICAgYWN0aXZlX2JvZHlfZmxvd3MgPSBzdW0oWzEgZm9yIGNhbmRpZGF0ZSBpbiBmbG93cy52
YWx1ZXMoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGNhbmRpZGF0ZS5ldmVudCBp
cyBub3QgTm9uZSBhbmQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYW5kaWRhdGUuYm9k
eV9nb2FsID4gMF0pCiAgICBpZiAoY29udGVudF9sZW5ndGggPD0gMCBvciBhY3RpdmVfYm9keV9m
bG93cyA+PSBNQVhfV1NTRV9CT0RZX0ZMT1dTIG9yCiAgICAgICAgICAgICJjaHVua2VkIiBpbiBo
ZHJzLmdldCgidHJhbnNmZXItZW5jb2RpbmciLCAiIikubG93ZXIoKSk6CiAgICAgICAgX2VtaXRf
cmVxdWVzdChmbG93cywga2V5LCBmbCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAg
ICAgIHJldHVybgogICAgZmwuYm9keV9nb2FsID0gbWluKGNvbnRlbnRfbGVuZ3RoLCB3c3NlX2Jv
ZHlfYnl0ZXMsIE1BWF9XU1NFX0JPRFlfQllURVMpCiAgICBfdHJ5X3dzc2VfYm9keShmbG93cywg
a2V5LCBmbCwgaW5pdGlhbF9ib2R5LCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCgoKZGVm
IHN3ZWVwX2lkbGUoZmxvd3MsIG5vdyk6CiAgICBzdGFsZSA9IFtdCiAgICBmb3IgaywgZmwgaW4g
Zmxvd3MuaXRlbXMoKToKICAgICAgICBpZiBub3cgLSBmbC50b3VjaGVkID4gRkxPV19UVEw6CiAg
ICAgICAgICAgIHN0YWxlLmFwcGVuZChrKQogICAgZm9yIGsgaW4gc3RhbGU6CiAgICAgICAgZGVs
IGZsb3dzW2tdCgoKZGVmIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToK
ICAgICIiIk92ZXJmbG93IGd1YXJkOiBlbWl0IHRoZSBzaW5nbGUgb2xkZXN0IHBlbmRpbmcgZXZl
bnQgYXMtaXMuIiIiCiAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSBOb25lLCBOb25lCiAgICBm
b3IgcmssIGxzdCBpbiBwZW5kaW5nX3RibC5pdGVtcygpOgogICAgICAgIHRzID0gbHN0WzBdWzFd
CiAgICAgICAgaWYgb2xkZXN0X3RzIGlzIE5vbmUgb3IgdHMgPCBvbGRlc3RfdHM6CiAgICAgICAg
ICAgIG9sZGVzdF9rZXksIG9sZGVzdF90cyA9IHJrLCB0cwogICAgaWYgb2xkZXN0X2tleSBpcyBu
b3QgTm9uZToKICAgICAgICBwZW5kaW5nX3BvcChvbGRlc3Rfa2V5LCBvdXQsIHBlbmRpbmdfdGJs
KQoKCmRlZiBzd2VlcF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBub3csIG91dCk6CiAgICAiIiJUVEwg
Zmx1c2g6IGVtaXQgcmVxdWVzdHMgd2hvc2UgcmVzcG9uc2VzIG5ldmVyIHNob3dlZCB1cC4iIiIK
ICAgIGZvciByayBpbiBsaXN0KHBlbmRpbmdfdGJsLmtleXMoKSk6CiAgICAgICAgbHN0ID0gcGVu
ZGluZ190YmwuZ2V0KHJrKQogICAgICAgIHdoaWxlIGxzdCBhbmQgbm93IC0gbHN0WzBdWzFdID4g
UEVORElOR19UVEw6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQsIHBlbmRpbmdfdGJs
KQogICAgICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCgoKZGVmIGRyYWluX3BlbmRp
bmcocGVuZGluZ190YmwsIG91dCk6CiAgICAiIiJFbWl0IGV2ZXJ5IGNhcHR1cmVkIHJlcXVlc3Qg
YmVmb3JlIGNhcHR1cmUgc2h1dGRvd24uCgogICAgUmVzcG9uc2VzIGFyZSBvcHRpb25hbCBlbnJp
Y2htZW50LiBBIHN0b3AvcmVzdGFydCBtdXN0IG5vdCBkaXNjYXJkIGEKICAgIHJlcXVlc3QgbWVy
ZWx5IGJlY2F1c2UgaXRzIHJlc3BvbnNlIHdhcyBmaWx0ZXJlZCwgc3BsaXQsIG9yIHN0aWxsIGlu
CiAgICBmbGlnaHQgd2hlbiB0aGUgcHJvY2VzcyByZWNlaXZlZCBTSUdURVJNLgogICAgIiIiCiAg
ICBmb3IgcmsgaW4gbGlzdChwZW5kaW5nX3RibC5rZXlzKCkpOgogICAgICAgIHdoaWxlIHBlbmRp
bmdfdGJsLmdldChyayk6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQsIHBlbmRpbmdf
dGJsKQoKCmRlZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAgIHJldHVybiBu
b3cgLSBsYXN0X3N3ZWVwID49IFNXRUVQX0lOVEVSVkFMCgoKZGVmIGVuZm9yY2VfbGltaXQoZmxv
d3MsIG5vdyk6CiAgICAiIiJDYXAgZmxvdy10YWJsZSBzaXplIChweTIuNjogbm8gT3JkZXJlZERp
Y3Qg4oCUIHN3ZWVwIHN0YWxlLCB0aGVuIEZJRk8KICAgIGJ5IGluc2VydGlvbiBvcmRlciwgd2hp
Y2ggcGxhaW4gZGljdHMgcHJlc2VydmUgaW4gQ1B5dGhvbikuIiIiCiAgICBzd2VlcF9pZGxlKGZs
b3dzLCBub3cpCiAgICB3aGlsZSBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgIGZsb3dz
LnBvcGl0ZW0oKSAgICAgICAgICAjIG9sZGVzdC1pbnNlcnRlZCBrZXkgb24gQ1B5dGhvbiAyLjYv
Mi43CgoKZGVmIF9jb250cm9sX2NvbmZpZygpOgogICAgIiIiUmVhZCBvcHRpb25hbCBjb250cm9s
IHNldHRpbmdzIHdpdGhvdXQgZXhwb3NpbmcgdGhlIGJlYXJlciB0b2tlbi4iIiIKICAgIGVuZHBv
aW50ID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfRU5EUE9JTlQiKSBvciBvcy5lbnZpcm9u
LmdldCgiTlRfRU5EUE9JTlQiKQogICAgdG9rZW5fZmlsZSA9IG9zLmVudmlyb24uZ2V0KCJOVF9D
T05UUk9MX1RPS0VOX0ZJTEUiLCAiIikKICAgIHRva2VuID0gb3MuZW52aXJvbi5nZXQoIk5UX0NP
TlRST0xfVE9LRU4iLCAiIikKICAgIGlmIHRva2VuX2ZpbGU6CiAgICAgICAgdHJ5OgogICAgICAg
ICAgICBmID0gb3Blbih0b2tlbl9maWxlLCAiciIpCiAgICAgICAgICAgIHRyeToKICAgICAgICAg
ICAgICAgIHRva2VuID0gZi5yZWFkKCkuc3RyaXAoKQogICAgICAgICAgICBmaW5hbGx5OgogICAg
ICAgICAgICAgICAgZi5jbG9zZSgpCiAgICAgICAgZXhjZXB0IElPRXJyb3I6CiAgICAgICAgICAg
IHRva2VuID0gIiIKICAgIG5vZGUgPSBvcy5lbnZpcm9uLmdldCgiTlRfTk9ERV9OQU1FIikgb3Ig
c29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQogICAgcnVuX2RpciA9IG9zLmVudmly
b24uZ2V0KCJOVF9DT05UUk9MX1JVTiIsICIvdmFyL2xpYi9uZXR3b3JrdHJhY2luZyIpCiAgICB0
cnk6CiAgICAgICAgaW50ZXJ2YWwgPSBtYXgoNSwgbWluKGludChvcy5lbnZpcm9uLmdldCgiTlRf
Q09OVFJPTF9TRUMiLCAiMzAiKSksIDMwMCkpCiAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAg
ICBpbnRlcnZhbCA9IDMwCiAgICByZXR1cm4gZW5kcG9pbnQsIHRva2VuLCBub2RlLCBydW5fZGly
LCBpbnRlcnZhbAoKCmRlZiBfcnVuX2NvbnRyb2xfdGljayhwb3J0cywgaWZhY2UsIHJ1bl9kaXIs
IGNsaWVudCk6CiAgICByZXBseSA9IGNsaWVudC5wb2xsKCkKICAgIGlmIG5vdCByZXBseToKICAg
ICAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBOb25lLCAicG9sbCBmYWlsZWQiCiAgICBkZXNpcmVk
ID0gcmVwbHkuZ2V0KCJkZXNpcmVkIikgb3Ige30KICAgIHN0YXRlID0gZGljdChkZXNpcmVkKQog
ICAgZ2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0aW9uIiwgMCkKICAgIGNvbnRyb2xf
YWN0aW9uID0gTm9uZQogICAgc3RvcF9yZXF1ZXN0ZWQgPSBGYWxzZQogICAgaWYgZGVzaXJlZC5n
ZXQoInBvcnRzIik6CiAgICAgICAgbmV3X3BvcnRzID0gc2V0KGRlc2lyZWRbInBvcnRzIl0pCiAg
ICAgICAgaWYgbmV3X3BvcnRzICE9IHBvcnRzOgogICAgICAgICAgICBwb3J0cyA9IG5ld19wb3J0
cwogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0IgogICAgaWYgZGVzaXJlZC5n
ZXQoImlmYWNlIik6CiAgICAgICAgbmV3X2lmYWNlID0gZGVzaXJlZFsiaWZhY2UiXQogICAgICAg
IGlmIG5ld19pZmFjZSAhPSBpZmFjZToKICAgICAgICAgICAgaWZhY2UgPSBuZXdfaWZhY2UKICAg
ICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAicmVzdGFydCIKICAgIGZvciB0YXNrIGluIHJlcGx5
LmdldCgidGFza3MiLCBbXSk6CiAgICAgICAgYWN0aW9uID0gdGFzay5nZXQoImFjdGlvbiIpCiAg
ICAgICAgaWYgYWN0aW9uID09ICJoZWFsdGgiOgogICAgICAgICAgICBtZXNzYWdlID0gImhlYWx0
aHkiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgIGVsaWYgYWN0aW9uIGluICgi
cmVzdGFydCIsICJyZWxvYWQiLCAic2V0X3BvcnRzIik6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAi
YWNjZXB0ZWQ7IGNhcHR1cmUgcmVzdGFydCByZXF1ZXN0ZWQiCiAgICAgICAgICAgIHN0YXR1cyA9
ICJkb25lIgogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0IgogICAgICAgICAg
ICBpZiBhY3Rpb24gPT0gInNldF9wb3J0cyI6CiAgICAgICAgICAgICAgICBhcmdzID0gdGFzay5n
ZXQoImFyZ3MiKSBvciB7fQogICAgICAgICAgICAgICAgaWYgYXJncy5nZXQoInBvcnRzIik6CiAg
ICAgICAgICAgICAgICAgICAgcG9ydHMgPSBzZXQoYXJnc1sicG9ydHMiXSkKICAgICAgICAgICAg
ICAgICAgICBzdGF0ZS51cGRhdGUoeyJwb3J0cyI6IHNvcnRlZChwb3J0cyksICJtb2RlIjogInB5
dGhvbiIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZ2VuZXJhdGlvbiI6IGdl
bmVyYXRpb259KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgbWVz
c2FnZSA9ICJzdG9wIHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAg
ICAgICAgIHN0b3BfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIG1l
c3NhZ2UgPSAidW5zdXBwb3J0ZWQgYnkgZGlyZWN0IHNuaWZmZXIiCiAgICAgICAgICAgIHN0YXR1
cyA9ICJmYWlsZWQiCiAgICAgICAgY2xpZW50LnJlcG9ydCh0YXNrLmdldCgiaWQiKSwgc3RhdHVz
LCBtZXNzYWdlKQogICAgaWYgc3RvcF9yZXF1ZXN0ZWQ6CiAgICAgICAgY29udHJvbF9hY3Rpb24g
PSAic3RvcCIKICAgIGFwcGxpZWQgPSAoInN0b3AgcmVxdWVzdGVkIiBpZiBjb250cm9sX2FjdGlv
biA9PSAic3RvcCIgZWxzZQogICAgICAgICAgICAgICAicmVzdGFydCByZXF1aXJlZCIgaWYgY29u
dHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiIGVsc2UKICAgICAgICAgICAgICAgInBvbGwgb2siKQog
ICAgbnRfY29udHJvbC53cml0ZV9zdGF0ZShvcy5wYXRoLmpvaW4ocnVuX2RpciwgInJlbW90ZS1k
ZXNpcmVkLmpzb24iKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdGUsIGFwcGxpZWQp
CiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sIGFwcGxpZWQpCiAgICByZXR1cm4gcG9y
dHMsIGlmYWNlLCBjb250cm9sX2FjdGlvbiwgYXBwbGllZAoKCmRlZiBfcmVzdGFydF9hcmdzKHNj
cmlwdCwgaWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXM9MCk6
CiAgICAiIiJCdWlsZCBhIGZyZXNoIGFyZ3YgZm9yIGFuIGluLXBsYWNlIHJlLWV4ZWMgYWZ0ZXIg
YSBjb250cm9sIHVwZGF0ZS4iIiIKICAgICMgUHJlc2VydmUgdW5idWZmZXJlZCBKU09OTCBkZWxp
dmVyeTsgdGhlIGluc3RhbGxlciBzdGFydHMgUHl0aG9uIHdpdGggLXUuCiAgICBhcmdzID0gW3N5
cy5leGVjdXRhYmxlLCAiLXUiLCBvcy5wYXRoLmFic3BhdGgoc2NyaXB0KV0KICAgIGlmIGlmYWNl
OgogICAgICAgIGFyZ3MuZXh0ZW5kKFsiLWkiLCBpZmFjZV0pCiAgICBhcmdzLmV4dGVuZChbIi1w
IiwgIiwiLmpvaW4oW3N0cihwKSBmb3IgcCBpbiBzb3J0ZWQocG9ydHMpXSldKQogICAgYXJncy5l
eHRlbmQoWyItaiIsIHN0cih3b3JrZXJzKV0pCiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6CiAgICAg
ICAgYXJncy5leHRlbmQoWyItLXdzc2UtYm9keS1ieXRlcyIsIHN0cih3c3NlX2JvZHlfYnl0ZXMp
XSkKICAgIGlmIHZlcmJvc2U6CiAgICAgICAgYXJncy5hcHBlbmQoIi12IikKICAgIHJldHVybiBh
cmdzCgoKZGVmIG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwgd29ya2Vycywgd3Nz
ZV9ib2R5X2J5dGVzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAgICBub2RlX2hvc3QgPSBz
b2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250cm9sX2NsaWVudCA9IE5v
bmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250cm9sX3J1biwgY29udHJv
bF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9jb250cm9sIGlzIG5vdCBO
b25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5OgogICAgICAgICAgICBjb250
cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRwb2ludCwgdG9rZW4sIGNv
bnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIoY29udHJvbF9ydW4p
OgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4pCiAgICAgICAgICAgIGxv
ZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBl
OgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRpc2FibGVkICglcykiICUg
bnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAgICAgICMgcHJvdG9jb2wg
TVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJTkdSRVNTIChyZXEpIGFu
ZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4IGtlcm5lbCBwYWNrZXQg
c29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfUEFDS0VULCBzb2Nr
ZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29ja2V0Lmh0b25zKEVUSF9Q
X0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhp
dCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0iKQogICAgZXhjZXB0IHNv
Y2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBvcGVuIEFG
X1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAi
Q0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQoMS4wKQogICAgYXBwbHlf
cGVyZl9vcHRzKHMsIHBvcnRzKQogICAgdHJ5OgogICAgICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIs
IEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yOgogICAgICAgIHRyeToKICAgICAg
ICAgICAgcy5iaW5kKCgiIiwgRVRIX1BfQUxMKSkKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9y
OgogICAgICAgICAgICBwYXNzCiAgICBmYW5vdXRfb2sgPSBGYWxzZQogICAgaWYgd29ya2VycyA+
IDE6CiAgICAgICAgZmFub3V0X29rID0gYXBwbHlfZmFub3V0KHMsIDB4RjAwRCkKICAgICAgICBp
ZiBmYW5vdXRfb2s6CiAgICAgICAgICAgIGxvZygiZmFub3V0IGdyb3VwIDB4RjAwRDogc3Bhd25p
bmcgJWQgd29ya2VycyIgJSB3b3JrZXJzKQoKICAgICMgcHJlY29tcGlsZWQgc3RydWN0IHJlYWRl
cnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBvZiB0aGUKICAgICMgcGFja2V0
IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGludHMgdW5kZXIgcHkyIEFORCBw
eTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNrX2Zyb20KICAgIHVoID0gc3Ry
dWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0LGRwb3J0IGluIG9uZSByZWFk
CiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19mcm9tCiAgICBudG9hID0gc29j
a2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5pbmcgPSBbVHJ1ZV0KCiAgICBk
ZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgIHNp
Z25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2lnbmFsKHNpZ25h
bC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGltZSgpCiAgICBjb250cm9s
X25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcgb24gJXMgcG9ydHM9JXMgcGlk
PSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRlZChwb3J0cyksIG9zLmdldHBp
ZCgpKSkKICAgIGlmIHdzc2VfYm9keV9ieXRlczoKICAgICAgICBsb2coIldTU0UgVXNlcm5hbWVU
b2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5kZWQgdG8gJWQgYnl0ZXMvcmVxdWVzdCkiICUK
ICAgICAgICAgICAgd3NzZV9ib2R5X2J5dGVzKQoKICAgICMgZm9yayBleHRyYSBjYXB0dXJlIHdv
cmtlcnMgQUZURVIgZmFub3V0IGF0dGFjaDsgV0lUSE9VVCBhIHdvcmtpbmcKICAgICMgZmFub3V0
IGdyb3VwIGV2ZXJ5IHByb2Nlc3Mgd291bGQgcmVjZWl2ZSBFVkVSWSBwYWNrZXQgKGR1cGxpY2F0
ZXMpLAogICAgIyBzbyBzaW5nbGUtcHJvY2VzcyBtb2RlIGlzIGZvcmNlZCB3aGVuIHRoZSBrZXJu
ZWwgbGFja3Mgc3VwcG9ydAogICAgIyAoUEFDS0VUX0ZBTk9VVCBuZWVkcyBrZXJuZWwgPj0gMy4x
OyBlbDYgMi42LjMyIGRvZXMgbm90IGhhdmUgaXQpCiAgICBpZiBmYW5vdXRfb2s6CiAgICAgICAg
Zm9yIF8gaW4gcmFuZ2Uod29ya2VycyAtIDEpOgogICAgICAgICAgICBpZiBvcy5mb3JrKCkgPT0g
MDoKICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAgICAgICAjIGNoaWxkOiBmYWxsIHRo
cm91Z2ggaW50byBpdHMgb3duIGxvb3AKCiAgICAjIDFzIHJlY3YgdGltZW91dDogKGEpIGxldHMg
dGhlIHBlbmRpbmcvZmxvdyBzd2VlcHMgYWN0dWFsbHkgZmlyZSDigJQKICAgICMgd2l0aG91dCBp
dCBgZXhjZXB0IHNvY2tldC50aW1lb3V0YCBuZXZlciBydW5zOyAoYikgZW1waXJpY2FsbHkgUkVR
VUlSRUQKICAgICMgd2l0aCB0aGUgQlBGIGZpbHRlciBhdHRhY2hlZDogYSBmdWxseS1ibG9ja2lu
ZyByZWN2IG9uIHRoaXMga2VybmVsCiAgICAjIHN0YXJ2ZXMgYWZ0ZXIgdGhlIGZpcnN0IHBhY2tl
dCwgd2hpbGUgdGhlIHRpbWVvdXQnZCByZWN2IGRlbGl2ZXJzCiAgICAjIGNvbnRpbnVvdXNseSAo
dmVyaWZpZWQgYnkgQS9COiByeD0xIHZzIHJ4PTI5IGlkZW50aWNhbCBvdGhlcndpc2UpLgogICAg
cy5zZXR0aW1lb3V0KDEuMCkKCiAgICBkYmcgPSBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfREVC
VUciKSA9PSAiMSIKICAgIGRiZ19yeCA9IDAKICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAg
IHdoaWxlIHJ1bm5pbmdbMF06CiAgICAgICAgIyBQb2xsIGluZGVwZW5kZW50bHkgb2Ygc29ja2V0
IGlkbGUgdGltZS4gQSBidXN5IG1vbml0b3JlZCBpbnRlcmZhY2UKICAgICAgICAjIG1heSBuZXZl
ciByYWlzZSBzb2NrZXQudGltZW91dCwgYnV0IGNvbnRyb2wgY2hhbmdlcyBtdXN0IHN0aWxsIGFw
cGx5LgogICAgICAgIGlmIGNvbnRyb2xfY2xpZW50IGlzIG5vdCBOb25lIGFuZCB0aW1lLnRpbWUo
KSA+PSBjb250cm9sX25leHQ6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBvcnRz
LCBpZmFjZSwgY29udHJvbF9hY3Rpb24sIGNvbnRyb2xfc3RhdHVzID0gX3J1bl9jb250cm9sX3Rp
Y2soCiAgICAgICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBjb250cm9sX3J1biwgY29udHJv
bF9jbGllbnQpCiAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiAlcyIgJSBjb250
cm9sX3N0YXR1cykKICAgICAgICAgICAgICAgIGlmIGNvbnRyb2xfYWN0aW9uID09ICJyZXN0YXJ0
IjoKICAgICAgICAgICAgICAgICAgICBhcmdzID0gX3Jlc3RhcnRfYXJncyhzeXMuYXJndlswXSwg
aWZhY2UsIHBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZl
cmJvc2UsIHdvcmtlcnMsIHdzc2VfYm9keV9ieXRlcykKICAgICAgICAgICAgICAgICAgICBsb2co
InJlbW90ZSBjb250cm9sOiByZS1leGVjdXRpbmcgY2FwdHVyZSB3aXRoIHVwZGF0ZWQgY29uZmln
dXJhdGlvbiIpCiAgICAgICAgICAgICAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgICAgICAgICAg
ICAgb3MuZXhlY3Yoc3lzLmV4ZWN1dGFibGUsIGFyZ3MpCiAgICAgICAgICAgICAgICBlbGlmIGNv
bnRyb2xfYWN0aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBj
b250cm9sOiBzdG9wIHJlcXVlc3RlZDsgZXhpdGluZyIpCiAgICAgICAgICAgICAgICAgICAgcnVu
bmluZ1swXSA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAg
ZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiByZW1vdGUg
Y29udHJvbCB0aWNrIGZhaWxlZCAoJXMpIiAlIG50X2NvbnRyb2wuc2FmZV9tZXNzYWdlKGUpKQog
ICAgICAgICAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSArIGNvbnRyb2xfaW50ZXJ2YWwK
ICAgICAgICB0cnk6CiAgICAgICAgICAgIHBrdCA9IHMucmVjdig2NTUzNSkKICAgICAgICAgICAg
ZGJnX3J4ICs9IDEKICAgICAgICAgICAgaWYgZGJnIGFuZCB0aW1lLnRpbWUoKSAtIGRiZ19sYXN0
ID4gNToKICAgICAgICAgICAgICAgIGxvZygiREVCVUcgcng9JWQiICUgZGJnX3J4KQogICAgICAg
ICAgICAgICAgZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGlt
ZW91dDoKICAgICAgICAgICAgaWYgZGJnOgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyB0aW1l
b3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1l
KCkKICAgICAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgaWYgbWFpbnRlbmFu
Y2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6CiAgICAgICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dz
LCBub3cpCiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgICAgICBzd2VlcF9w
ZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0X3MpCiAgICAgICAgICAgICAgICBmb3IgZXYgaW4gb3V0
X3M6CiAgICAgICAgICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKGV2KSAr
ICJcbiIpCiAgICAgICAgICAgICAgICBpZiBvdXRfczoKICAgICAgICAgICAgICAgICAgICBzeXMu
c3Rkb3V0LmZsdXNoKCkKICAgICAgICAgICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKICAgICAgICAg
ICAgY29udGludWUKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgICAg
IGlmIGUuZXJybm8gPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAg
ICAgICAgICByYWlzZQogICAgICAgIG4gPSBsZW4ocGt0KQogICAgICAgIGlmIG4gPCAzNDoKICAg
ICAgICAgICAgY29udGludWUKICAgICAgICBvdXQgPSBbXQogICAgICAgIG9mZiA9IDE0ICAgICAg
ICAgICAgICAgICAgICAgICMgZXRoZXJuZXQgaGVhZGVyCiAgICAgICAgZXR5cGUgPSB1MTYocGt0
LCAxMilbMF0KICAgICAgICBpZiBldHlwZSA9PSBFVEhfUF9WTEFOOgogICAgICAgICAgICBldHlw
ZSA9IHUxNihwa3QsIDE2KVswXQogICAgICAgICAgICBvZmYgPSAxOAogICAgICAgIGVsaWYgZXR5
cGUgIT0gRVRIX1BfSVA6CiAgICAgICAgICAgIGNvbnRpbnVlICAgICAgICAgICAgICAgICAgIyB3
aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlzIHJhcmUKICAgICAgICBpcDAgPSB1Yihwa3QsIG9mZilb
MF0KICAgICAgICBpZiBpcDAgPj4gNCAhPSA0IG9yIHViKHBrdCwgb2ZmICsgOSlbMF0gIT0gNjog
ICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpaGwgPSAoaXAw
ICYgMHgwRikgKiA0CiAgICAgICAgZnJhZyA9IHUxNihwa3QsIG9mZiArIDYpWzBdCiAgICAgICAg
aWYgZnJhZyAmIDB4MUZGRjogICAgICAgICAgICAgICAgICAgICAgICAgIyBub24tZmlyc3QgZnJh
Z21lbnQKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzcmNfaXAgPSBudG9hKHBrdFtvZmYg
KyAxMjpvZmYgKyAxNl0pCiAgICAgICAgZHN0X2lwID0gbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsg
MjBdKQogICAgICAgIHRjcF9vZmYgPSBvZmYgKyBpaGwKICAgICAgICBzcG9ydCwgZHBvcnQgPSB1
aChwa3QsIHRjcF9vZmYpCiAgICAgICAgZG9mZl9mbGFncyA9IHViKHBrdCwgdGNwX29mZiArIDEy
KQogICAgICAgIGRvZmYgPSAoZG9mZl9mbGFnc1swXSA+PiA0KSAqIDQKICAgICAgICBwYXlfc3Rh
cnQgPSB0Y3Bfb2ZmICsgZG9mZgogICAgICAgIGlmIG4gPD0gcGF5X3N0YXJ0OgogICAgICAgICAg
ICBjb250aW51ZSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICMgbm8gcGF5bG9hZCBpbiBz
ZWdtZW50CiAgICAgICAgcGF5bG9hZCA9IHBrdFtwYXlfc3RhcnQ6XQogICAgICAgIGZsYWdzID0g
ZG9mZl9mbGFnc1sxXQogICAgICAgIG5vdyA9IHRpbWUudGltZSgpCgogICAgICAgICMgLS0tLS0t
LS0tLS0tLS0tLSBSRVNQT05TRSBkaXJlY3Rpb24gKHNlcnZlciAtPiBjbGllbnQpIC0tLS0tLS0t
LS0KICAgICAgICBpZiBzcG9ydCBpbiBwb3J0cyBhbmQgZHBvcnQgbm90IGluIHBvcnRzOgogICAg
ICAgICAgICAjIHBlbmRpbmcga2V5IHdhcyBzdG9yZWQgYXMgKHNlcnZlcl9pcCwgc2VydmVyX3Bv
cnQsIGNsaWVudF9pcCwKICAgICAgICAgICAgIyBjbGllbnRfcG9ydCkgPT0gKHNyYywgc3BvcnQs
IGRzdCwgZHBvcnQpIE9GIFRISVMgcmVzcG9uc2UgcGt0CiAgICAgICAgICAgIHJrID0gKHNyY19p
cCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgICAgIGlmIHBheWxvYWRbOjVdID09IGIi
SFRUUC8iOgogICAgICAgICAgICAgICAgY29ycmVsYXRlX3Jlc3BvbnNlKHBlbmRpbmcsIHJrLCBw
YXlsb2FkLCBub3csIG91dCkKICAgICAgICAgICAgZWxpZiBmbGFncyAmIDB4MDU6ICAgICAgICAg
ICAgICAgICAgICAgICMgRklOfFJTVDogZmx1c2ggdW5tYXRjaGVkCiAgICAgICAgICAgICAgICBl
diA9IHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAgICAgIyAtLS0tLS0tLS0tLS0tLS0tIFJFUVVF
U1QgZGlyZWN0aW9uIChjbGllbnQgLT4gc2VydmVyKSAtLS0tLS0tLS0tLQogICAgICAgIGVsaWYg
ZHBvcnQgaW4gcG9ydHM6CiAgICAgICAgICAgIGlmIGZsYWdzICYgMHgwNTogICAgICAgICAgICAg
ICAgICAgICAgIyB0ZWFyZG93biB3L28gcmVzcG9uc2Ugc2VlbgogICAgICAgICAgICAgICAgcmsg
PSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgICAgICAgICAgICAgIHBlbmRpbmdf
cG9wKHJrLCBvdXQpCiAgICAgICAgICAgIGtleSA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRw
b3J0KQogICAgICAgICAgICBoYW5kbGVfcGF5bG9hZChmbG93cywga2V5LCBOb25lLCBwYXlsb2Fk
LAogICAgICAgICAgICAgICAgICAgICAgICAgICAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9y
dCksCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRzLCBub2RlX2hvc3QsIG91dCwgcGVu
ZGluZywgbm93LAogICAgICAgICAgICAgICAgICAgICAgICAgICB3c3NlX2JvZHlfYnl0ZXMpCiAg
ICAgICAgaWYgb3V0OgogICAgICAgICAgICB3ID0gc3lzLnN0ZG91dC53cml0ZQogICAgICAgICAg
ICBmb3IgZXYgaW4gb3V0OgogICAgICAgICAgICAgICAgdyhqc29uLmR1bXBzKGV2KSArICJcbiIp
CiAgICAgICAgICAgIHN5cy5zdGRvdXQuZmx1c2goKQoKICAgICAgICBpZiBtYWludGVuYW5jZV9k
dWUobm93LCBsYXN0X3N3ZWVwKToKICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93KQog
ICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgIHN3ZWVwX3BlbmRpbmcocGVuZGluZywg
bm93LCBvdXRfcykKICAgICAgICAgICAgZm9yIGV2IGluIG91dF9zOgogICAgICAgICAgICAgICAg
c3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgIGlmIG91
dF9zOgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAgICAgIGxhc3Rf
c3dlZXAgPSBub3cKCiAgICBvdXRfcyA9IFtdCiAgICBkcmFpbl9wZW5kaW5nKHBlbmRpbmcsIG91
dF9zKQogICAgZm9yIGV2IGluIG91dF9zOgogICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5k
dW1wcyhldikgKyAiXG4iKQogICAgaWYgb3V0X3M6CiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgp
CiAgICBsb2coInN0b3BwZWQgKCVkIHBlbmRpbmcgcmVxdWVzdHMgZmx1c2hlZCkiICUgbGVuKG91
dF9zKSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg==
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
eHNpemU9MTI4KQogICAgc3Bvb2xfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkKICAgIHRyeToKICAg
ICAgICBudGhyZWFkcyA9IGludChvcy5lbnZpcm9uLmdldCgiTlRfU0hJUF9USFJFQURTIiwgIjQi
KSkKICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgIG50aHJlYWRzID0gNAogICAgbnRocmVh
ZHMgPSBtYXgoMSwgbWluKG50aHJlYWRzLCAzMikpCgogICAgZGVmIHBvc3RlcigpOgogICAgICAg
IHdoaWxlIFRydWU6CiAgICAgICAgICAgIGJhdGNoID0gcS5nZXQoKQogICAgICAgICAgICBpZiBi
YXRjaCBpcyBOb25lOgogICAgICAgICAgICAgICAgcS50YXNrX2RvbmUoKQogICAgICAgICAgICAg
ICAgcmV0dXJuCiAgICAgICAgICAgIGlmIG5vdCBmbHVzaChiYXRjaCk6CiAgICAgICAgICAgICAg
ICBsb2coIldBUk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAlZCBldmVudHMgKGluLW1lbW9y
eSBkcm9wLCAwIGRpc2sgSS9PKSIgJSBsZW4oYmF0Y2gpKQogICAgICAgICAgICBxLnRhc2tfZG9u
ZSgpCgogICAgZm9yIF8gaW4gcmFuZ2UobnRocmVhZHMpOgogICAgICAgIHQgPSB0aHJlYWRpbmcu
VGhyZWFkKHRhcmdldD1wb3N0ZXIpCiAgICAgICAgdC5kYWVtb24gPSBUcnVlCiAgICAgICAgdC5z
dGFydCgpCgogICAgYnVmID0gW10KICAgIGxhc3RfZmx1c2ggPSB0aW1lLnRpbWUoKQoKICAgIHdo
aWxlIHJ1bm5pbmdbMF06CiAgICAgICAgdHJ5OgogICAgICAgICAgICByLCBfLCBfID0gc2VsZWN0
LnNlbGVjdChbc3lzLnN0ZGluXSwgW10sIFtdLCAxLjApCiAgICAgICAgZXhjZXB0IHNlbGVjdC5l
cnJvciBhcyBlOgogICAgICAgICAgICBpZiBlWzBdID09IGVycm5vLkVJTlRSOgogICAgICAgICAg
ICAgICAgY29udGludWUKICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgaWYgcjoKICAgICAgICAg
ICAgdHJ5OgogICAgICAgICAgICAgICAgcmF3ID0gc3lzLnN0ZGluLnJlYWRsaW5lKCkKICAgICAg
ICAgICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yKSBhcyBlOgogICAgICAgICAgICAgICAgaWYg
Z2V0YXR0cihlLCAnZXJybm8nLCBOb25lKSA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAg
ICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYgbm90IHJh
dzoKICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAgICAgICAgIyBFT0YKICAgICAgICAg
ICAgcmF3ID0gcmF3LnN0cmlwKCkKICAgICAgICAgICAgaWYgcmF3OgogICAgICAgICAgICAgICAg
dHJ5OgogICAgICAgICAgICAgICAgICAgIGV2ID0ganNvbi5sb2FkcyhyYXcpCiAgICAgICAgICAg
ICAgICAgICAgaWYgaXNpbnN0YW5jZShldiwgZGljdCk6CiAgICAgICAgICAgICAgICAgICAgICAg
IGlmIGxlbihidWYpID49IDQwMDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgYnVm
WzBdCiAgICAgICAgICAgICAgICAgICAgICAgIGJ1Zi5hcHBlbmQoZXYpCiAgICAgICAgICAgICAg
ICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgIG5v
dyA9IHRpbWUudGltZSgpCiAgICAgICAgd2hpbGUgbGVuKGJ1ZikgPj0gTUFYX0JBVENIIG9yIChi
dWYgYW5kIG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDKToKICAgICAgICAgICAgbGFzdF9m
bHVzaCA9IG5vdwogICAgICAgICAgICBxLnB1dChidWZbOk1BWF9CQVRDSF0pCiAgICAgICAgICAg
IGRlbCBidWZbOk1BWF9CQVRDSF0KCiAgICAjIHN0ZGluIGNsb3NlZCAoc25pZmZlciBzdG9wcGVk
KSDigJQgZW5xdWV1ZSB0aGUgZmluYWwgcGFydGlhbCBiYXRjaCBiZWZvcmUKICAgICMgd2FpdGlu
ZyBmb3IgcG9zdGVyIHRocmVhZHMuIFByZXZpb3VzbHkgZXZlcnkgc2h1dGRvd24gbG9zdCAxLi4z
OTkgZXZlbnRzLgogICAgaWYgYnVmOgogICAgICAgIHEucHV0KGJ1Zls6XSkKICAgICAgICBidWYg
PSBbXQogICAgcS5qb2luKCkKICAgIGxvZygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRpbmcgb24g
ZXhpdCkiICUgbGVuKGJ1ZikpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4o
KQo=
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
IHNpemVfdCBNQVhfUEVORElOR19QRVJfRkxPVyA9IDMyOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1B
WF9IRUFERVIgPSAyNjIxNDQ7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0JBVENIID0gNDAwOwpz
dGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9RVUVVRSA9IDQwMDA7CnN0YXRpYyBjb25zdCBpbnQgRkxV
U0hfU0VDID0gNTsKc3RhdGljIGNvbnN0IGludCBSRVRSWV9TRUMgPSA2MDsKc3RhdGljIGNvbnN0
IHVuc2lnbmVkIEZMT1dfVFRMID0gMTU7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBQRU5ESU5HX1RU
TCA9IDM7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBBQ0NFUFQgPSAyMDQ4OwpzdGF0aWMgY29uc3Qg
aW50IFNPX0FUVEFDSF9GSUxURVJfT0xEID0gMjY7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9y
dCBFVEhfUF9JUF9IT1NUID0gMHgwODAwOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRI
X1BfODAyMVFfSE9TVCA9IDB4ODEwMDsKCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmltKGNvbnN0IHN0
ZDo6c3RyaW5nICZzKSB7CiAgc2l6ZV90IGEgPSAwLCBiID0gcy5zaXplKCk7CiAgd2hpbGUgKGEg
PCBiICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1thXSkpICsrYTsKICB3aGlsZSAoYiA+IGEg
JiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilzW2IgLSAxXSkpIC0tYjsKICByZXR1cm4gcy5zdWJz
dHIoYSwgYiAtIGEpOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBsb3dlcihjb25zdCBzdGQ6OnN0cmlu
ZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSBzOwogIHNpemVfdCBpOyBmb3IgKGkgPSAwOyBpIDwg
eC5zaXplKCk7ICsraSkgeFtpXSA9IChjaGFyKXRvbG93ZXIoKHVuc2lnbmVkIGNoYXIpeFtpXSk7
CiAgcmV0dXJuIHg7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25xKGNvbnN0IHN0ZDo6c3RyaW5n
ICZzKSB7CiAgc3RkOjpzdHJpbmcgeCA9ICJcIiI7IHNpemVfdCBpOwogIGZvciAoaSA9IDA7IGkg
PCBzLnNpemUoKTsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilz
W2ldOwogICAgaWYgKGMgPT0gJ1xcJyB8fCBjID09ICciJykgeyB4ICs9ICdcXCc7IHggKz0gKGNo
YXIpYzsgfQogICAgZWxzZSBpZiAoYyA9PSAnXG4nKSB4ICs9ICJcXG4iOwogICAgZWxzZSBpZiAo
YyA9PSAnXHInKSB4ICs9ICJcXHIiOwogICAgZWxzZSBpZiAoYyA9PSAnXHQnKSB4ICs9ICJcXHQi
OwogICAgZWxzZSBpZiAoYyA8IDMyKSB4ICs9ICc/JzsKICAgIGVsc2UgeCArPSAoY2hhciljOwog
IH0KICB4ICs9ICciJzsgcmV0dXJuIHg7Cn0Kc3RhdGljIGxvbmcgbG9uZyBub3dfbXMoKSB7CiAg
c3RydWN0IHRpbWV2YWwgdHY7IGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVybiAobG9u
ZyBsb25nKXR2LnR2X3NlYyAqIDEwMDBMTCArIHR2LnR2X3VzZWMgLyAxMDAwOwp9CnN0YXRpYyBz
dGQ6OnN0cmluZyBudW0obG9uZyB2KSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IHY7IHJl
dHVybiBvLnN0cigpOyB9CnN0YXRpYyBib29sIHZhbGlkX3BvcnQodW5zaWduZWQgcCkgeyByZXR1
cm4gcCA+IDAgJiYgcCA8PSA2NTUzNTsgfQpzdGF0aWMgYm9vbCBoYXNfbWV0aG9kKGNvbnN0IHN0
ZDo6c3RyaW5nICZtKSB7CiAgcmV0dXJuIG0gPT0gIkdFVCIgfHwgbSA9PSAiUE9TVCIgfHwgbSA9
PSAiUFVUIiB8fCBtID09ICJERUxFVEUiIHx8CiAgICAgICAgIG0gPT0gIlBBVENIIiB8fCBtID09
ICJIRUFEIiB8fCBtID09ICJPUFRJT05TIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgaG9zdF9uYW1l
KCkgewogIGNoYXIgYlsyNTZdOyBpZiAoZ2V0aG9zdG5hbWUoYiwgc2l6ZW9mKGIpIC0gMSkgIT0g
MCkgcmV0dXJuICJ1bmtub3duLW5vZGUiOwogIGJbc2l6ZW9mKGIpIC0gMV0gPSAwOyBjaGFyICpw
ID0gc3RyY2hyKGIsICcuJyk7IGlmIChwKSAqcCA9IDA7IHJldHVybiBiOwp9CnN0YXRpYyBzdGQ6
OnN0cmluZyBiNjRkZWNvZGVfdXNlcihjb25zdCBjaGFyICppbiwgc2l6ZV90IGluX2xlbikgewog
IHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpKmluKSkgeyArK2lu
OyAtLWluX2xlbjsgfQogIHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNo
YXIpaW5baW5fbGVuIC0gMV0pKSB7IC0taW5fbGVuOyB9CiAgc3RkOjpzdHJpbmcgb3V0OyBpbnQg
dmFsID0gMCwgYml0cyA9IC04OyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgaW5fbGVuOyAr
K2kpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWluW2ldOyBpbnQgZCA9
IC0xOwogICAgaWYgKGMgPj0gJ0EnICYmIGMgPD0gJ1onKSBkID0gYyAtICdBJzsKICAgIGVsc2Ug
aWYgKGMgPj0gJ2EnICYmIGMgPD0gJ3onKSBkID0gYyAtICdhJyArIDI2OwogICAgZWxzZSBpZiAo
YyA+PSAnMCcgJiYgYyA8PSAnOScpIGQgPSBjIC0gJzAnICsgNTI7CiAgICBlbHNlIGlmIChjID09
ICcrJykgZCA9IDYyOwogICAgZWxzZSBpZiAoYyA9PSAnLycpIGQgPSA2MzsKICAgIGVsc2UgaWYg
KGMgPT0gJz0nKSBicmVhazsKICAgIGlmIChkIDwgMCkgY29udGludWU7CiAgICB2YWwgPSAodmFs
IDw8IDYpICsgZDsKICAgIGJpdHMgKz0gNjsKICAgIGlmIChiaXRzID49IDApIHsKICAgICAgb3V0
ICs9IChjaGFyKSgodmFsID4+IGJpdHMpICYgMHhmZik7CiAgICAgIGJpdHMgLT0gODsKICAgICAg
aWYgKG91dC5zaXplKCkgPiA1MTIpIHJldHVybiAiIjsKICAgIH0KICB9CiAgc2l6ZV90IHAgPSBv
dXQuZmluZCgnOicpOwogIGlmIChwID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CiAg
cmV0dXJuIG91dC5zdWJzdHIoMCwgcCA+IDY0ID8gNjQgOiBwKTsKfQpzdGF0aWMgc3RkOjpzdHJp
bmcgaXBfdG9fc3RyKHVpbnQzMl90IGlwX2JlKSB7CiAgY2hhciBiW0lORVRfQUREUlNUUkxFTl07
CiAgaW5ldF9udG9wKEFGX0lORVQsICZpcF9iZSwgYiwgc2l6ZW9mKGIpKTsKICByZXR1cm4gYjsK
fQoKc3RhdGljIHN0ZDo6c3RyaW5nIHRyYWNlX2lkX2Zyb21fcGFyZW50KGNvbnN0IHN0ZDo6c3Ry
aW5nICZ0cCkgewogIHN0ZDo6c3RyaW5nIHggPSB0cmltKHRwKTsKICBpZiAoeC5zaXplKCkgPT0g
NTUgJiYgeFsyXSA9PSAnLScgJiYgeFszNV0gPT0gJy0nICYmIHhbNTJdID09ICctJykgcmV0dXJu
IGxvd2VyKHguc3Vic3RyKDMsIDMyKSk7CiAgcmV0dXJuICIiOwp9CgpzdGF0aWMgdWludDY0X3Qg
Z19ybmdfc3RhdGUgPSAwOwpzdGF0aWMgdm9pZCBpbml0X3JuZygpIHsKICBGSUxFICpmID0gZm9w
ZW4oIi9kZXYvdXJhbmRvbSIsICJyYiIpOwogIGlmIChmKSB7CiAgICBzaXplX3QgbiA9IGZyZWFk
KCZnX3JuZ19zdGF0ZSwgMSwgc2l6ZW9mKGdfcm5nX3N0YXRlKSwgZik7CiAgICAodm9pZCluOwog
ICAgZmNsb3NlKGYpOwogIH0KICBpZiAoIWdfcm5nX3N0YXRlKSB7CiAgICBnX3JuZ19zdGF0ZSA9
ICgodWludDY0X3QpdGltZShOVUxMKSA8PCAzMikgXiAodWludDY0X3QpZ2V0cGlkKCk7CiAgfQp9
CnN0YXRpYyBpbmxpbmUgdWludDY0X3QgbmV4dF9ybmcoKSB7CiAgdWludDY0X3QgeCA9IGdfcm5n
X3N0YXRlOwogIHggXj0geCA8PCAxMzsgeCBePSB4ID4+IDc7IHggXj0geCA8PCAxNzsKICByZXR1
cm4gZ19ybmdfc3RhdGUgPSAoeCA/IHggOiAweDg1M2M0OWU2NzQ4ZmVhOWJVTEwpOwp9CgpzdGF0
aWMgc3RkOjpzdHJpbmcgbWFrZV90cmFjZXBhcmVudChzdGQ6OnN0cmluZyAqdGlkKSB7CiAgdWlu
dDY0X3QgcjEgPSBuZXh0X3JuZygpOwogIHVpbnQ2NF90IHIyID0gbmV4dF9ybmcoKTsKICB1aW50
NjRfdCByMyA9IG5leHRfcm5nKCk7CiAgY2hhciBidWZbNjRdOwogIHNucHJpbnRmKGJ1Ziwgc2l6
ZW9mKGJ1ZiksICIwMC0lMDE2bGx4JTAxNmxseC0lMDE2bGx4LTAxIiwKICAgICAgICAgICAodW5z
aWduZWQgbG9uZyBsb25nKXIxLCAodW5zaWduZWQgbG9uZyBsb25nKXIyLCAodW5zaWduZWQgbG9u
ZyBsb25nKXIzKTsKICBjaGFyIHRpZF9idWZbMzNdOwogIHNucHJpbnRmKHRpZF9idWYsIHNpemVv
Zih0aWRfYnVmKSwgIiUwMTZsbHglMDE2bGx4IiwKICAgICAgICAgICAodW5zaWduZWQgbG9uZyBs
b25nKXIxLCAodW5zaWduZWQgbG9uZyBsb25nKXIyKTsKICAqdGlkID0gdGlkX2J1ZjsKICByZXR1
cm4gYnVmOwp9CgpzdHJ1Y3QgRXZlbnQgewogIGxvbmcgdHM7IHN0ZDo6c3RyaW5nIGhvc3QsIHNy
Yywgc2VydmljZSwgbWV0aG9kLCBwYXRoLCB1c2VyLCBzY2hlbWUsIHByb2JlOwogIHN0ZDo6c3Ry
aW5nIGhvc3RfaGRyLCB1c2VyX2FnZW50LCB4ZmYsIGNhbGxlciwgZHN0X2lwLCB0cmFjZXBhcmVu
dCwgdHJhY2VfaWQ7CiAgdW5zaWduZWQgY2FsbGVyX3BvcnQsIGRzdF9wb3J0LCByZXFfYnl0ZXMs
IHJlc3BfYnl0ZXM7IGludCBzdGF0dXM7IGxvbmcgZHVyYXRpb25fbXM7CiAgYm9vbCBoYXNfc3Rh
dHVzLCBoYXNfZHVyYXRpb24sIGhhc19yZXNwOwogIEV2ZW50KCkgOiB0cygwKSwgY2FsbGVyX3Bv
cnQoMCksIGRzdF9wb3J0KDApLCByZXFfYnl0ZXMoMCksIHJlc3BfYnl0ZXMoMCksIHN0YXR1cygw
KSwgZHVyYXRpb25fbXMoMCksIGhhc19zdGF0dXMoZmFsc2UpLCBoYXNfZHVyYXRpb24oZmFsc2Up
LCBoYXNfcmVzcChmYWxzZSkge30KfTsKc3RydWN0IEZsb3cgeyBzdGQ6OnN0cmluZyBidWY7IHRp
bWVfdCB0b3VjaGVkOyBGbG93KCkgOiB0b3VjaGVkKHRpbWUoTlVMTCkpIHt9IH07CnN0cnVjdCBQ
ZW5kaW5nIHsKICBFdmVudCBldjsKICBsb25nIGxvbmcgc3RhcnRlZF9tczsKICBQZW5kaW5nKCkg
OiBzdGFydGVkX21zKDApIHt9CiAgUGVuZGluZyhjb25zdCBFdmVudCAmZSwgbG9uZyBsb25nIHQp
IDogZXYoZSksIHN0YXJ0ZWRfbXModCkge30KfTsKc3RydWN0IEZsb3dLZXkgewogIHVpbnQzMl90
IHNfaXA7CiAgdWludDE2X3Qgc3BvcnQ7CiAgdWludDMyX3QgZF9pcDsKICB1aW50MTZfdCBkcG9y
dDsKICBib29sIG9wZXJhdG9yPChjb25zdCBGbG93S2V5ICZ4KSBjb25zdCB7CiAgICBpZiAoc19p
cCAhPSB4LnNfaXApIHJldHVybiBzX2lwIDwgeC5zX2lwOwogICAgaWYgKHNwb3J0ICE9IHguc3Bv
cnQpIHJldHVybiBzcG9ydCA8IHguc3BvcnQ7CiAgICBpZiAoZF9pcCAhPSB4LmRfaXApIHJldHVy
biBkX2lwIDwgeC5kX2lwOwogICAgcmV0dXJuIGRwb3J0IDwgeC5kcG9ydDsKICB9Cn07CnR5cGVk
ZWYgRmxvd0tleSBQYWNrZXRLZXk7CgpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qgc3RkOjpzdHJp
bmcgJnMpIHsgZnByaW50ZihzdGRlcnIsICJudC1zbmlmZi1jcHA6ICVzXG4iLCBzLmNfc3RyKCkp
OyBmZmx1c2goc3RkZXJyKTsgfQoKc3RhdGljIGJvb2wgcGFyc2VfcmVxdWVzdChjb25zdCBjaGFy
ICpkYXRhLCBzaXplX3QgbGVuLCBFdmVudCAqZSkgewogIGNvbnN0IGNoYXIgKmVuZCA9IGRhdGEg
KyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7CiAgY29uc3QgY2hhciAqZW9sID0gKGNvbnN0
IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgaWYgKCFlb2wpIHJldHVybiBmYWxz
ZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAt
IHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAgZS0+bWV0aG9kLmFzc2lnbihwLCBzcDEg
LSBwKTsKICBpZiAoIWhhc19tZXRob2QoZS0+bWV0aG9kKSkgcmV0dXJuIGZhbHNlOwoKICBjb25z
dCBjaGFyICpwYXRoX3N0YXJ0ID0gc3AxICsgMTsKICB3aGlsZSAocGF0aF9zdGFydCA8IGVvbCAm
JiAqcGF0aF9zdGFydCA9PSAnICcpICsrcGF0aF9zdGFydDsKICBjb25zdCBjaGFyICpzcDIgPSAo
Y29uc3QgY2hhciAqKW1lbWNocihwYXRoX3N0YXJ0LCAnICcsIGVvbCAtIHBhdGhfc3RhcnQpOwog
IGlmICghc3AyKSBzcDIgPSAoZW9sID4gZGF0YSAmJiAqKGVvbCAtIDEpID09ICdccicpID8gZW9s
IC0gMSA6IGVvbDsKICBjb25zdCBjaGFyICpxbWFyayA9IChjb25zdCBjaGFyICopbWVtY2hyKHBh
dGhfc3RhcnQsICc/Jywgc3AyIC0gcGF0aF9zdGFydCk7CiAgc2l6ZV90IHBhdGhfbGVuID0gKHFt
YXJrID8gcW1hcmsgOiBzcDIpIC0gcGF0aF9zdGFydDsKICBpZiAocGF0aF9sZW4gPiAxMjApIHBh
dGhfbGVuID0gMTIwOwogIGUtPnBhdGguYXNzaWduKHBhdGhfc3RhcnQsIHBhdGhfbGVuKTsKCiAg
cCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBlbmQpIHsKICAgIGlmICgqcCA9PSAnXHInIHx8ICpw
ID09ICdcbicpIGJyZWFrOwogICAgY29uc3QgY2hhciAqbGluZV9lbmQgPSAoY29uc3QgY2hhciAq
KW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICAgIGlmICghbGluZV9lbmQpIGxpbmVfZW5kID0g
ZW5kOwogICAgY29uc3QgY2hhciAqY29sb24gPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnOics
IGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29sb24pIHsKICAgICAgc2l6ZV90IGhuYW1lX2xlbiA9
IGNvbG9uIC0gcDsKICAgICAgY29uc3QgY2hhciAqdmFsX3N0YXJ0ID0gY29sb24gKyAxOwogICAg
ICB3aGlsZSAodmFsX3N0YXJ0IDwgbGluZV9lbmQgJiYgKCp2YWxfc3RhcnQgPT0gJyAnIHx8ICp2
YWxfc3RhcnQgPT0gJ1x0JykpICsrdmFsX3N0YXJ0OwogICAgICBjb25zdCBjaGFyICp2YWxfZW5k
ID0gbGluZV9lbmQ7CiAgICAgIHdoaWxlICh2YWxfZW5kID4gdmFsX3N0YXJ0ICYmICh2YWxfZW5k
Wy0xXSA9PSAnXHInIHx8IHZhbF9lbmRbLTFdID09ICdcbicgfHwgdmFsX2VuZFstMV0gPT0gJyAn
IHx8IHZhbF9lbmRbLTFdID09ICdcdCcpKSAtLXZhbF9lbmQ7CiAgICAgIHNpemVfdCB2YWxfbGVu
ID0gdmFsX2VuZCAtIHZhbF9zdGFydDsKCiAgICAgIGlmIChobmFtZV9sZW4gPT0gMTMgJiYgIXN0
cm5jYXNlY21wKHAsICJhdXRob3JpemF0aW9uIiwgMTMpKSB7CiAgICAgICAgaWYgKHZhbF9sZW4g
PiA2ICYmICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQsICJCYXNpYyAiLCA2KSkgewogICAgICAgICAg
ZS0+dXNlciA9IGI2NGRlY29kZV91c2VyKHZhbF9zdGFydCArIDYsIHZhbF9sZW4gLSA2KTsKICAg
ICAgICAgIGUtPnNjaGVtZSA9ICJiYXNpYyI7CiAgICAgICAgfSBlbHNlIGlmICh2YWxfbGVuID4g
NyAmJiAhc3RybmNhc2VjbXAodmFsX3N0YXJ0LCAiQmVhcmVyICIsIDcpKSB7CiAgICAgICAgICBl
LT5zY2hlbWUgPSAiYmVhcmVyIjsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVu
ID09IDExICYmICFzdHJuY2FzZWNtcChwLCAidHJhY2VwYXJlbnQiLCAxMSkpIHsKICAgICAgICBl
LT50cmFjZXBhcmVudC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgICBlLT50cmFj
ZV9pZCA9IHRyYWNlX2lkX2Zyb21fcGFyZW50KGUtPnRyYWNlcGFyZW50KTsKICAgICAgfSBlbHNl
IGlmIChobmFtZV9sZW4gPT0gNCAmJiAhc3RybmNhc2VjbXAocCwgImhvc3QiLCA0KSkgewogICAg
ICAgIGUtPmhvc3RfaGRyLmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2Ug
aWYgKGhuYW1lX2xlbiA9PSAxMCAmJiAhc3RybmNhc2VjbXAocCwgInVzZXItYWdlbnQiLCAxMCkp
IHsKICAgICAgICBlLT51c2VyX2FnZW50LmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAg
ICB9IGVsc2UgaWYgKGhuYW1lX2xlbiA9PSAxNSAmJiAhc3RybmNhc2VjbXAocCwgIngtZm9yd2Fy
ZGVkLWZvciIsIDE1KSkgewogICAgICAgIGUtPnhmZi5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVu
KTsKICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CgogIGlmIChlLT51c2Vy
LmVtcHR5KCkpIGUtPnVzZXIgPSAiLWFub255bW91cy0iOwogIGlmIChlLT5zY2hlbWUuZW1wdHko
KSkgZS0+c2NoZW1lID0gIm5vbmUiOwogIGlmIChlLT50cmFjZV9pZC5lbXB0eSgpKSBlLT50cmFj
ZXBhcmVudCA9IG1ha2VfdHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lkKTsKICByZXR1cm4gdHJ1ZTsK
fQoKc3RhdGljIGJvb2wgcGFyc2VfcmVzcG9uc2UoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxl
biwgaW50ICpzdGF0dXMsIHVuc2lnbmVkICpjbGVuKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0
YSArIGxlbjsKICBjb25zdCBjaGFyICpwID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29u
c3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZh
bHNlOwogIGlmIChzdHJuY21wKHAsICJIVFRQLyIsIDUpICE9IDApIHJldHVybiBmYWxzZTsKICBj
b25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwog
IGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEgKyAx
OwogIHdoaWxlIChzY19zdGFydCA8IGVvbCAmJiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0YXJ0
OwogICpzdGF0dXMgPSBhdG9pKHNjX3N0YXJ0KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAqc3Rh
dHVzID4gNTk5KSByZXR1cm4gZmFsc2U7CiAgKmNsZW4gPSAwOwogIHAgPSBlb2wgKyAxOwogIHdo
aWxlIChwIDwgZW5kKSB7CiAgICBpZiAoKnAgPT0gJ1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsK
ICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5kID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywg
ZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVfZW5kKSBsaW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNo
YXIgKmNvbG9uID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwog
ICAgaWYgKGNvbG9uKSB7CiAgICAgIHNpemVfdCBobGVuID0gY29sb24gLSBwOwogICAgICBpZiAo
aGxlbiA9PSAxNCAmJiAhc3RybmNhc2VjbXAocCwgImNvbnRlbnQtbGVuZ3RoIiwgMTQpKSB7CiAg
ICAgICAgY29uc3QgY2hhciAqdiA9IGNvbG9uICsgMTsKICAgICAgICB3aGlsZSAodiA8IGxpbmVf
ZW5kICYmICgqdiA9PSAnICcgfHwgKnYgPT0gJ1x0JykpICsrdjsKICAgICAgICBsb25nIG4gPSBh
dG9sKHYpOwogICAgICAgIGlmIChuID49IDAgJiYgbiA8PSAweDdmZmZmZmZmKSAqY2xlbiA9ICh1
bnNpZ25lZCluOwogICAgICB9CiAgICB9CiAgICBwID0gbGluZV9lbmQgKyAxOwogIH0KICByZXR1
cm4gdHJ1ZTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIGdfZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0
cmluZyBnX3NoaXBfbm9kZTsKc3RhdGljIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBnX3NoaXBf
YnVmOwoKc3RhdGljIHN0ZDo6c3RyaW5nIHNoZWxscShjb25zdCBzdGQ6OnN0cmluZyAmcykgewog
IHN0ZDo6c3RyaW5nIG8gPSAiJyI7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBzLnNpemUoKTsg
KytpKSB7IGlmIChzW2ldID09ICdcJycpIG8gKz0gIidcXCcnIjsgZWxzZSBvICs9IHNbaV07IH0K
ICByZXR1cm4gbyArICInIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbnVtYmVyX3N0cmluZyhzaXpl
X3QgbikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsgbyA8PCBuOyByZXR1cm4gby5zdHIoKTsgfQpz
dGF0aWMgc3RkOjpzdHJpbmcganNvbl9hcnJheShjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmlu
Zz4gJmEpIHsKICBzdGQ6OnN0cmluZyBvID0gIlsiOyBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGEu
c2l6ZSgpOyArK2kpIHsgaWYgKGkpIG8gKz0gIiwiOyBvICs9IGFbaV07IH0gcmV0dXJuIG8gKyAi
XSI7Cn0Kc3RhdGljIGJvb2wgcG9zdChjb25zdCBzdGQ6OnN0cmluZyAmZW5kcG9pbnQsIGNvbnN0
IHN0ZDo6c3RyaW5nICZub2RlLCBjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNo
KSB7CiAgc3RkOjpzdHJpbmcgYm9keSA9ICJ7XCJub2RlXCI6IiArIGpzb25xKG5vZGUpICsgIixc
ImV2ZW50c1wiOiIgKyBqc29uX2FycmF5KGJhdGNoKSArICJ9IjsKICBzdGQ6OnN0cmluZyBjbWQg
PSAiY3VybCAtc1NmIC0tbWF4LXRpbWUgMTAgLW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6
IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1iaW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCAr
ICIvYXBpL2luZ2VzdCIpOwogIEZJTEUgKmZwID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7IGlm
ICghZnApIHJldHVybiBmYWxzZTsKICBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgp
LCBmcCk7CiAgaW50IHJjID0gcGNsb3NlKGZwKTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBX
RVhJVFNUQVRVUyhyYykgPT0gMDsKfQpzdGF0aWMgdm9pZCBzZW5kX2JhdGNoZXMoY29uc3Qgc3Rk
OjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwKICAgICAgICAgICAg
ICAgICAgICAgICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAqYnVmLCBib29sIGZsdXNoX2Fs
bCkgewogIHdoaWxlICghYnVmLT5lbXB0eSgpICYmIChmbHVzaF9hbGwgfHwgYnVmLT5zaXplKCkg
Pj0gTUFYX0JBVENIKSkgewogICAgc2l6ZV90IG4gPSBidWYtPnNpemUoKSA+PSBNQVhfQkFUQ0gg
PyBNQVhfQkFUQ0ggOiBidWYtPnNpemUoKTsKICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBi
YXRjaChidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4oKSArIG4pOwogICAgaWYgKHBvc3QoZW5kcG9p
bnQsIG5vZGUsIGJhdGNoKSkgewogICAgICBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSwgYnVmLT5i
ZWdpbigpICsgbik7CiAgICAgIGxvZ21zZygiZmx1c2hlZCAiICsgbnVtYmVyX3N0cmluZyhuKSAr
ICIgZXZlbnRzIik7CiAgICB9IGVsc2UgewogICAgICAvKiBQdXJlIGluLW1lbW9yeSBkcm9wIHdo
ZW4gSHViIHVucmVhY2hhYmxlICh6ZXJvIGRpc2sgSS9PKSAqLwogICAgICBidWYtPmVyYXNlKGJ1
Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigpICsgbik7CiAgICAgIGxvZ21zZygiV0FSTjogSHViIHVu
cmVhY2hhYmxlLCBkcm9wcGVkICIgKyBudW1iZXJfc3RyaW5nKG4pICsgIiBldmVudHMgKGluLW1l
bW9yeSBkcm9wLCAwIGRpc2sgSS9PKSIpOwogICAgICBicmVhazsKICAgIH0KICB9Cn0KCnN0YXRp
YyB2b2lkIGVtaXRfZXZlbnQoY29uc3QgRXZlbnQgJmUpIHsKICBzdGQ6Om9zdHJpbmdzdHJlYW0g
c3M7CiAgc3MgPDwgIntcInRzXCI6IiA8PCBlLnRzIDw8ICIsXCJob3N0XCI6IiA8PCBqc29ucShl
Lmhvc3QpIDw8ICIsXCJzcmNcIjpcInBjYXBcIixcInNlcnZpY2VcIjoiIDw8IGpzb25xKGUuc2Vy
dmljZSkKICAgICA8PCAiLFwibWV0aG9kXCI6IiA8PCBqc29ucShlLm1ldGhvZCkgPDwgIixcInBh
dGhcIjoiIDw8IGpzb25xKGUucGF0aCkgPDwgIixcInVzZXJcIjoiIDw8IGpzb25xKGUudXNlcikK
ICAgICA8PCAiLFwic2NoZW1lXCI6IiA8PCBqc29ucShlLnNjaGVtZSkgPDwgIixcInNvdXJjZV9w
cm9iZVwiOlwicGNhcC1odHRwLWNwcFwiLFwiaG9zdF9oZHJcIjoiIDw8IGpzb25xKGUuaG9zdF9o
ZHIpCiAgICAgPDwgIixcInVzZXJfYWdlbnRcIjoiIDw8IGpzb25xKGUudXNlcl9hZ2VudCkgPDwg
IixcInhfZm9yd2FyZGVkX2ZvclwiOiIgPDwganNvbnEoZS54ZmYpCiAgICAgPDwgIixcImNhbGxl
clwiOiIgPDwganNvbnEoZS5jYWxsZXIpIDw8ICIsXCJjYWxsZXJfcG9ydFwiOiIgPDwgZS5jYWxs
ZXJfcG9ydCA8PCAiLFwiZHN0X2lwXCI6IiA8PCBqc29ucShlLmRzdF9pcCkKICAgICA8PCAiLFwi
ZHN0X3BvcnRcIjoiIDw8IGUuZHN0X3BvcnQgPDwgIixcInRyYWNlcGFyZW50XCI6IiA8PCBqc29u
cShlLnRyYWNlcGFyZW50KSA8PCAiLFwidHJhY2VfaWRcIjoiIDw8IGpzb25xKGUudHJhY2VfaWQp
CiAgICAgPDwgIixcInNlcnZpY2VfaWRcIjpudWxsLFwibW9kdWxlX2lkXCI6XCJwY2FwLWh0dHAt
Y3BwXCIsXCJyZXFfYnl0ZXNcIjoiIDw8IGUucmVxX2J5dGVzOwogIGlmIChlLmhhc19zdGF0dXMp
IHNzIDw8ICIsXCJzdGF0dXNcIjoiIDw8IGUuc3RhdHVzOyBlbHNlIHNzIDw8ICIsXCJzdGF0dXNc
IjpudWxsIjsKICBpZiAoZS5oYXNfZHVyYXRpb24pIHNzIDw8ICIsXCJkdXJhdGlvbl9tc1wiOiIg
PDwgZS5kdXJhdGlvbl9tczsgZWxzZSBzcyA8PCAiLFwiZHVyYXRpb25fbXNcIjpudWxsIjsKICBp
ZiAoZS5oYXNfcmVzcCkgc3MgPDwgIixcInJlc3BfYnl0ZXNcIjoiIDw8IGUucmVzcF9ieXRlczsg
ZWxzZSBzcyA8PCAiLFwicmVzcF9ieXRlc1wiOm51bGwiOwogIHNzIDw8ICJ9IjsKCiAgaWYgKCFn
X2VuZHBvaW50LmVtcHR5KCkpIHsKICAgIGlmIChnX3NoaXBfYnVmLnNpemUoKSA+PSBNQVhfUVVF
VUUpIHsKICAgICAgZ19zaGlwX2J1Zi5lcmFzZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgfQog
ICAgZ19zaGlwX2J1Zi5wdXNoX2JhY2soc3Muc3RyKCkpOwogIH0gZWxzZSB7CiAgICBzdGQ6OmNv
dXQgPDwgc3Muc3RyKCkgPDwgIlxuIjsKICB9Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX29sZGVzdChz
dGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBp
ZiAocGVuZGluZy5lbXB0eSgpKSByZXR1cm47CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZl
Y3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9IHBlbmRpbmcuYmVnaW4oKTsKICBpZiAoIWl0
LT5zZWNvbmQuZW1wdHkoKSkgewogICAgZW1pdF9ldmVudChpdC0+c2Vjb25kWzBdLmV2KTsKICAg
IGl0LT5zZWNvbmQuZXJhc2UoaXQtPnNlY29uZC5iZWdpbigpKTsKICB9CiAgaWYgKGl0LT5zZWNv
bmQuZW1wdHkoKSkgewogICAgcGVuZGluZy5lcmFzZShpdCk7CiAgfQp9CnN0YXRpYyB2b2lkIGZs
dXNoX2FsbF9wZW5kaW5nKHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4g
PiAmcGVuZGluZykgewogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4g
Pjo6aXRlcmF0b3IgcDsKICBmb3IgKHAgPSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5l
bmQoKTsgKytwKSB7CiAgICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHAtPnNlY29uZC5zaXplKCk7
ICsraSkgewogICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICB9CiAgfQogIHBl
bmRpbmcuY2xlYXIoKTsKfQpzdGF0aWMgdm9pZCBzd2VlcChzdGQ6Om1hcDxGbG93S2V5LCBGbG93
PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVu
ZGluZywgdGltZV90IG5vdykgewogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBm
LCBmbjsKICBmb3IgKGYgPSBmbG93cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAg
Zm4gPSBmOyArK2ZuOwogICAgaWYgKCh1bnNpZ25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNoZWQp
ID4gRkxPV19UVEwpIGZsb3dzLmVyYXNlKGYpOwogICAgZiA9IGZuOwogIH0KICBsb25nIGxvbmcg
Y3VycmVudF9tcyA9IChsb25nIGxvbmcpbm93ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tldEtl
eSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0gcGVu
ZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcuZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47CiAg
ICBzaXplX3QgaSA9IDA7CiAgICB3aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAg
aWYgKGN1cnJlbnRfbXMgLSBwLT5zZWNvbmRbaV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcpUEVO
RElOR19UVEwgKiAxMDAwTEwpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7
CiAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgIH0g
ZWxzZSB7CiAgICAgICAgKytpOwogICAgICB9CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVtcHR5
KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICBwID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmlu
ZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0g
eyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwg
Ik9QVElPTlMgIiB9OwogIHNpemVfdCBiZXN0ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChz
aXplX3QgaSA9IDA7IGkgPCA3OyArK2kpIHsKICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7
CiAgICBpZiAocG9zICE9IHN0ZDo6c3RyaW5nOjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5n
OjpucG9zIHx8IHBvcyA8IGJlc3QpKSBiZXN0ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoK
c3RhdGljIGJvb2wgZ19tb25pdG9yZWRfcG9ydHNbNjU1MzZdOwoKc3RhdGljIGJvb2wgaGFuZGxl
X3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0
cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAg
ICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFw
PFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogICh2b2lkKXBv
cnRzOwogIGlmIChuIDwgMzQpIHJldHVybiBmYWxzZTsKICBzaXplX3Qgb2ZmID0gMTQ7CiAgdW5z
aWduZWQgc2hvcnQgZXQgPSBudG9ocygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIDEy
KSk7CiAgaWYgKGV0ID09IEVUSF9QXzgwMjFRKSB7IGlmIChuIDwgMzgpIHJldHVybiBmYWxzZTsg
ZXQgPSBudG9ocygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIDE2KSk7IG9mZiA9IDE4
OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNlOwog
IHVuc2lnbmVkIGNoYXIgaWhsID0gKHVuc2lnbmVkIGNoYXIpKGJ1ZltvZmZdICYgMTUpICogNDsK
ICBpZiAoKGJ1ZltvZmZdID4+IDQpICE9IDQgfHwgYnVmW29mZiArIDldICE9IDYgfHwgbiA8IG9m
ZiArIGlobCArIDIwKSByZXR1cm4gZmFsc2U7CgogIHVpbnQzMl90IHNfaXAgPSAqKGNvbnN0IHVp
bnQzMl90ICopKGJ1ZiArIG9mZiArIDEyKTsKICB1aW50MzJfdCBkX2lwID0gKihjb25zdCB1aW50
MzJfdCAqKShidWYgKyBvZmYgKyAxNik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwogIHVuc2ln
bmVkIHNwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0bykpOwog
IHVuc2lnbmVkIGRwb3J0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0
byArIDIpKTsKICB1bnNpZ25lZCBkb2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYg
KG4gPCB0byArIGRvZmYpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpwYXlsb2FkID0gKGNv
bnN0IGNoYXIgKikoYnVmICsgdG8gKyBkb2ZmKTsKICBzaXplX3QgcGxlbiA9IG4gLSB0byAtIGRv
ZmY7CiAgaWYgKCFwbGVuKSByZXR1cm4gZmFsc2U7CgogIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwp
OwogIGJvb2wgZHN0X21vbiA9IChkcG9ydCA8IDY1NTM2KSA/IGdfbW9uaXRvcmVkX3BvcnRzW2Rw
b3J0XSA6IGZhbHNlOwogIGJvb2wgc3JjX21vbiA9IChzcG9ydCA8IDY1NTM2KSA/IGdfbW9uaXRv
cmVkX3BvcnRzW3Nwb3J0XSA6IGZhbHNlOwoKICBpZiAoc3JjX21vbiAmJiAhZHN0X21vbiAmJiBw
bGVuID49IDUpIHsKICAgIGlmIChtZW1jbXAocGF5bG9hZCwgIkhUVFAvIiwgNSkgPT0gMCkgewog
ICAgICBQYWNrZXRLZXkgazsKICAgICAgay5zX2lwID0gc19pcDsgay5zcG9ydCA9ICh1aW50MTZf
dClzcG9ydDsgay5kX2lwID0gZF9pcDsgay5kcG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICAgICAg
c3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0g
cGVuZGluZy5maW5kKGspOwogICAgICBpZiAocCAhPSBwZW5kaW5nLmVuZCgpICYmICFwLT5zZWNv
bmQuZW1wdHkoKSkgewogICAgICAgIGludCBzdDsgdW5zaWduZWQgY2w7CiAgICAgICAgaWYgKHBh
cnNlX3Jlc3BvbnNlKHBheWxvYWQsIHBsZW4sICZzdCwgJmNsKSkgewogICAgICAgICAgRXZlbnQg
ZSA9IHAtPnNlY29uZFswXS5ldjsKICAgICAgICAgIGUuc3RhdHVzID0gc3Q7IGUuaGFzX3N0YXR1
cyA9IHRydWU7CiAgICAgICAgICBlLmR1cmF0aW9uX21zID0gKGxvbmcpKG5vd19tcygpIC0gcC0+
c2Vjb25kWzBdLnN0YXJ0ZWRfbXMpOwogICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBl
LmR1cmF0aW9uX21zID0gMDsKICAgICAgICAgIGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsKICAgICAg
ICAgIGlmIChjbCkgeyBlLnJlc3BfYnl0ZXMgPSBjbDsgZS5oYXNfcmVzcCA9IHRydWU7IH0KICAg
ICAgICAgIGVtaXRfZXZlbnQoZSk7CiAgICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25k
LmJlZ2luKCkpOwogICAgICAgICAgaWYgKHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNl
KHApOwogICAgICAgIH0KICAgICAgfQogICAgfQogICAgcmV0dXJuIHRydWU7CiAgfQogIHVuc2ln
bmVkIGNoYXIgdGNwX2ZsYWdzID0gYnVmW3RvICsgMTNdOwogIGlmICghZHN0X21vbikgewogICAg
aWYgKHRjcF9mbGFncyAmIDB4MDUpIHsgLyogRklOIG9yIFJTVCAqLwogICAgICBGbG93S2V5IHJm
azsgcmZrLnNfaXAgPSBkX2lwOyByZmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7IHJmay5kX2lw
ID0gc19pcDsgcmZrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICBmbG93cy5lcmFzZShy
ZmspOwogICAgfQogICAgcmV0dXJuIGZhbHNlOwogIH0KCiAgRmxvd0tleSBmazsKICBmay5zX2lw
ID0gc19pcDsgZmsuc3BvcnQgPSAodWludDE2X3Qpc3BvcnQ7IGZrLmRfaXAgPSBkX2lwOyBmay5k
cG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICBpZiAodGNwX2ZsYWdzICYgMHgwNSkgeyAvKiBGSU4g
b3IgUlNUICovCiAgICBmbG93cy5lcmFzZShmayk7CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIGlm
IChmbG93cy5maW5kKGZrKSA9PSBmbG93cy5lbmQoKSAmJiBmbG93cy5zaXplKCkgPj0gTUFYX0ZM
T1dTKSB7CiAgICBmbG93cy5lcmFzZShmbG93cy5iZWdpbigpKTsKICB9CiAgRmxvdyAmZmwgPSBm
bG93c1tma107IGZsLnRvdWNoZWQgPSBub3c7IGZsLmJ1Zi5hcHBlbmQocGF5bG9hZCwgcGxlbik7
CiAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSKSB7IGZsb3dzLmVyYXNlKGZrKTsgcmV0
dXJuIGZhbHNlOyB9CiAgd2hpbGUgKHRydWUpIHsKICAgIHNpemVfdCBzdGFydCA9IGZpbmRfaHR0
cF9zdGFydChmbC5idWYpOwogICAgaWYgKHN0YXJ0ID09IHN0ZDo6c3RyaW5nOjpucG9zKSB7IGZs
LmJ1Zi5jbGVhcigpOyBicmVhazsgfQogICAgaWYgKHN0YXJ0ID4gMCkgZmwuYnVmLmVyYXNlKDAs
IHN0YXJ0KTsKICAgIHNpemVfdCBlbmQgPSBmbC5idWYuZmluZCgiXHJcblxyXG4iKTsKICAgIGlm
IChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgRXZlbnQgZTsgZS50cyA9IG5v
dzsgZS5ob3N0ID0gbm9kZTsgZS5zZXJ2aWNlID0gInBvcnQ6IiArIG51bShkcG9ydCk7IGUuY2Fs
bGVyID0gaXBfdG9fc3RyKHNfaXApOyBlLmNhbGxlcl9wb3J0ID0gc3BvcnQ7IGUuZHN0X2lwID0g
aXBfdG9fc3RyKGRfaXApOyBlLmRzdF9wb3J0ID0gZHBvcnQ7IGUucmVxX2J5dGVzID0gKHVuc2ln
bmVkKShlbmQgKyA0KTsKICAgIGlmICghcGFyc2VfcmVxdWVzdChmbC5idWYuZGF0YSgpLCBlbmQs
ICZlKSkgeyBmbC5idWYuZXJhc2UoMCwgZW5kICsgNCk7IGNvbnRpbnVlOyB9CiAgICBmbC5idWYu
ZXJhc2UoMCwgZW5kICsgNCk7CiAgICBQYWNrZXRLZXkgcms7IHJrLnNfaXAgPSBkX2lwOyByay5z
cG9ydCA9ICh1aW50MTZfdClkcG9ydDsgcmsuZF9pcCA9IHNfaXA7IHJrLmRwb3J0ID0gKHVpbnQx
Nl90KXNwb3J0OwogICAgaWYgKHBlbmRpbmcuZmluZChyaykgPT0gcGVuZGluZy5lbmQoKSAmJiBw
ZW5kaW5nLnNpemUoKSA+PSBNQVhfUEVORElORykgewogICAgICBmbHVzaF9vbGRlc3QocGVuZGlu
Zyk7CiAgICB9CiAgICBzdGQ6OnZlY3RvcjxQZW5kaW5nPiAmcXVldWUgPSBwZW5kaW5nW3JrXTsK
ICAgIGlmIChxdWV1ZS5zaXplKCkgPj0gTUFYX1BFTkRJTkdfUEVSX0ZMT1cpIHsKICAgICAgZW1p
dF9ldmVudChxdWV1ZVswXS5ldik7CiAgICAgIHF1ZXVlLmVyYXNlKHF1ZXVlLmJlZ2luKCkpOwog
ICAgfQogICAgcXVldWUucHVzaF9iYWNrKFBlbmRpbmcoZSwgbm93X21zKCkpKTsKICB9CiAgaWYg
KGZsLmJ1Zi5lbXB0eSgpKSB7CiAgICBmbG93cy5lcmFzZShmayk7CiAgfQogIHJldHVybiB0cnVl
Owp9CgpzdGF0aWMgYm9vbCBhdHRhY2hfYnBmKGludCBmZCwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5z
aWduZWQ+ICZwb3J0cykgewogIGlmIChwb3J0cy5lbXB0eSgpKSByZXR1cm4gZmFsc2U7CiAgc3Rk
Ojp2ZWN0b3I8c3RydWN0IHNvY2tfZmlsdGVyPiBmOyBzaXplX3QgaTsKICAvKiBEdWFsLXBhdGgg
Y0JQRjogUGF0aCBBIChzdGFuZGFyZCBJUHY0KSBhbmQgUGF0aCBCICg4MDIuMVEgVkxBTiB0YWdn
ZWQgSVB2NCkuICovCiAgdW5zaWduZWQgTiA9ICh1bnNpZ25lZClwb3J0cy5zaXplKCk7CiAgdW5z
aWduZWQgcmVqZWN0ID0gMTEgKyBOICogODsKICB1bnNpZ25lZCBhY2NlcHQgPSByZWplY3QgKyAx
OwogIHN0cnVjdCBzb2NrX2ZpbHRlciB4OwojZGVmaW5lIEFERChDLEosVCxLKSBkbyB7IHguY29k
ZT0oQyk7IHguanQ9KEopOyB4LmpmPShUKTsgeC5rPShLKTsgZi5wdXNoX2JhY2soeCk7IH0gd2hp
bGUoMCkKICAvKiBbMF0gTG9hZCBFdGhlclR5cGUgYXQgb2Zmc2V0IDEyICovCiAgQUREKEJQRl9M
RHxCUEZfSHxCUEZfQUJTLCAwLCAwLCAxMik7CiAgLyogWzFdIElmIHN0YW5kYXJkIElQdjQgKDB4
MDgwMCksIGp1bXAgb3ZlciBQYXRoIEIgKDYgKyA0Kk4gaW5zdHJ1Y3Rpb25zKSB0byBQYXRoIEEg
Ki8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAodW5zaWduZWQpKDYgKyA0ICogTiksIDAs
IEVUSF9QX0lQX0hPU1QpOwoKICAvKiAtLS0gUGF0aCBCOiA4MDIuMVEgVkxBTiAoaW5kZXggMikg
LS0tICovCiAgLyogWzJdIElmIG5vdCA4MDIuMVEgKDB4ODEwMCksIHJlamVjdCAqLwogIEFERChC
UEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMSksIEVUSF9QXzgwMjFRX0hPU1QpOwogIC8qIFszXSBMb2FkIGVuY2Fwc3VsYXRl
ZCBFdGhlclR5cGUgYXQgb2Zmc2V0IDE2ICovCiAgQUREKEJQRl9MRHxCUEZfSHxCUEZfQUJTLCAw
LCAwLCAxNik7CiAgLyogWzRdIElmIGVuY2Fwc3VsYXRlZCAhPSBJUHY0LCByZWplY3QgKi8KICBB
REQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25l
ZClmLnNpemUoKSAtIDEpLCBFVEhfUF9JUF9IT1NUKTsKICAvKiBbNV0gTG9hZCBJUCBwcm90b2Nv
bCBhdCBvZmZzZXQgMjcgKDIzICsgNCkgKi8KICBBREQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsIDAs
IDAsIDI3KTsKICAvKiBbNl0gSWYgbm90IFRDUCwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBG
X0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAx
KSwgSVBQUk9UT19UQ1ApOwogIC8qIFs3XSBMb2FkIElITCBhdCBvZmZzZXQgMTggKDE0ICsgNCkg
Ki8KICBBREQoQlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxOCk7CiAgLyogRGVzdGluYXRp
b24gcG9ydCBjaGVja3MgZm9yIFZMQU4gKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgp
OyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMjApOwogICAgdW5z
aWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgQUREKEJQRl9K
TVB8QlBGX0pFUXxCUEZfSywganQsIDAsIHBvcnRzW2ldKTsKICB9CiAgLyogU291cmNlIHBvcnQg
Y2hlY2tzIGZvciBWTEFOICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7
CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE4KTsKICAgIHVuc2lnbmVkIGp0
ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gKGkg
PCBwb3J0cy5zaXplKCkgLSAxKSA/IDAgOiAocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0g
MSk7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgamYsIHBvcnRzW2ldKTsKICB9
CgogIC8qIC0tLSBQYXRoIEE6IFN0YW5kYXJkIElQdjQgLS0tICovCiAgLyogTG9hZCBJUCBwcm90
b2NvbCBhdCBvZmZzZXQgMjMgKi8KICBBREQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsIDAsIDAsIDIz
KTsKICAvKiBJZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9L
LCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJUFBST1RP
X1RDUCk7CiAgLyogTG9hZCBJSEwgYXQgb2Zmc2V0IDE0ICovCiAgQUREKEJQRl9MRFh8QlBGX0J8
QlBGX01TSCwgMCwgMCwgMTQpOwogIC8qIERlc3RpbmF0aW9uIHBvcnQgY2hlY2tzIGZvciBzdGFu
ZGFyZCBJUHY0ICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBB
REQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE2KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNj
ZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBG
X0ssIGp0LCAwLCBwb3J0c1tpXSk7CiAgfQogIC8qIFNvdXJjZSBwb3J0IGNoZWNrcyBmb3Igc3Rh
bmRhcmQgSVB2NCAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAg
QUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAxNCk7CiAgICB1bnNpZ25lZCBqdCA9IGFj
Y2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwgcG9y
dHMuc2l6ZSgpIC0gMSkgPyAwIDogKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpOwog
ICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQoKICAv
KiBbcmVqZWN0XSBEcm9wIHBhY2tldCAqLwogIEFERChCUEZfUkVUfEJQRl9LLCAwLCAwLCAwKTsK
ICAvKiBbYWNjZXB0XSBBY2NlcHQgcGFja2V0ICgyMDQ4IGJ5dGVzKSAqLwogIEFERChCUEZfUkVU
fEJQRl9LLCAwLCAwLCBBQ0NFUFQpOwojdW5kZWYgQURECiAgaWYgKGYuc2l6ZSgpID4gNDA5Nikg
cmV0dXJuIGZhbHNlOwogIHN0cnVjdCBzb2NrX2Zwcm9nIHByb2c7IHByb2cubGVuID0gKHVuc2ln
bmVkIHNob3J0KWYuc2l6ZSgpOyBwcm9nLmZpbHRlciA9ICZmWzBdOwojaWZuZGVmIFNPX0FUVEFD
SF9GSUxURVIKI2RlZmluZSBTT19BVFRBQ0hfRklMVEVSIDI2CiNlbmRpZgogIHJldHVybiBzZXRz
b2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19BVFRBQ0hfRklMVEVSLCAmcHJvZywgc2l6ZW9mKHBy
b2cpKSA9PSAwOwp9CgpzdHJ1Y3QgTW1hcFJpbmcgewogIHZvaWQgKnJpbmc7CiAgc2l6ZV90IHJp
bmdfc2l6ZTsKICB1bnNpZ25lZCBibG9ja19zaXplOwogIHVuc2lnbmVkIGJsb2NrX25yOwogIHVu
c2lnbmVkIGZyYW1lX3NpemU7CiAgdW5zaWduZWQgZnJhbWVfbnI7CiAgdW5zaWduZWQgZnJhbWVz
X3Blcl9ibG9jazsKICB1bnNpZ25lZCBmcmFtZV9pZHg7CgogIE1tYXBSaW5nKCkgOiByaW5nKE1B
UF9GQUlMRUQpLCByaW5nX3NpemUoMCksIGJsb2NrX3NpemUoNjU1MzYpLCBibG9ja19ucig2NCks
CiAgICAgICAgICAgICAgIGZyYW1lX3NpemUoMjA0OCksIGZyYW1lX25yKDIwNDgpLCBmcmFtZXNf
cGVyX2Jsb2NrKDMyKSwgZnJhbWVfaWR4KDApIHt9Cn07CgpzdGF0aWMgYm9vbCBzZXR1cF9tbWFw
X3JpbmcoaW50IGZkLCBNbWFwUmluZyAmbXIpIHsKICBpbnQgdmVyID0gVFBBQ0tFVF9WMjsKICBp
ZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tFVCwgUEFDS0VUX1ZFUlNJT04sICZ2ZXIsIHNpemVv
Zih2ZXIpKSA8IDApIHsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgc3RydWN0IHRwYWNrZXRfcmVx
IHJlcTsKICBtZW1zZXQoJnJlcSwgMCwgc2l6ZW9mKHJlcSkpOwogIHJlcS50cF9ibG9ja19zaXpl
ID0gNjU1MzY7CiAgcmVxLnRwX2Jsb2NrX25yID0gNjQ7ICAgICAgIC8qIDRNQiBzaGFyZWQgbWVt
b3J5IHJpbmcgYnVmZmVyICovCiAgcmVxLnRwX2ZyYW1lX3NpemUgPSAyMDQ4OyAgIC8qIDJLQiBw
ZXIgZnJhbWUgKi8KICByZXEudHBfZnJhbWVfbnIgPSAocmVxLnRwX2Jsb2NrX3NpemUgKiByZXEu
dHBfYmxvY2tfbnIpIC8gcmVxLnRwX2ZyYW1lX3NpemU7IC8qIDIwNDggZnJhbWVzICovCgogIGlm
IChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfUlhfUklORywgJnJlcSwgc2l6ZW9m
KHJlcSkpIDwgMCkgewogICAgcmV0dXJuIGZhbHNlOwogIH0KICBtci5yaW5nX3NpemUgPSAoc2l6
ZV90KXJlcS50cF9ibG9ja19zaXplICogcmVxLnRwX2Jsb2NrX25yOwogIG1yLmJsb2NrX3NpemUg
PSByZXEudHBfYmxvY2tfc2l6ZTsKICBtci5ibG9ja19uciA9IHJlcS50cF9ibG9ja19ucjsKICBt
ci5mcmFtZV9zaXplID0gcmVxLnRwX2ZyYW1lX3NpemU7CiAgbXIuZnJhbWVfbnIgPSByZXEudHBf
ZnJhbWVfbnI7CiAgbXIuZnJhbWVzX3Blcl9ibG9jayA9IHJlcS50cF9ibG9ja19zaXplIC8gcmVx
LnRwX2ZyYW1lX3NpemU7CiAgbXIuZnJhbWVfaWR4ID0gMDsKCiAgbXIucmluZyA9IG1tYXAoTlVM
TCwgbXIucmluZ19zaXplLCBQUk9UX1JFQUQgfCBQUk9UX1dSSVRFLCBNQVBfU0hBUkVELCBmZCwg
MCk7CiAgaWYgKG1yLnJpbmcgPT0gTUFQX0ZBSUxFRCkgewogICAgbXIucmluZ19zaXplID0gMDsK
ICAgIHJldHVybiBmYWxzZTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBpbnQgcnVuX2Zp
eHR1cmUoKSB7CiAgc3RkOjpzdHJpbmcgcmVxID0gIkdFVCAvYXBpL2l0ZW1zP3g9MSBIVFRQLzEu
MVxyXG5Ib3N0OiBhcGkubG9jYWxcclxuQXV0aG9yaXphdGlvbjogQmFzaWMgWVd4cFkyVTZjMlZq
Y21WMFxyXG5UcmFjZXBhcmVudDogMDAtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYt
MDEyMzQ1Njc4OWFiY2RlZi0wMVxyXG5cclxuIjsKICBFdmVudCBlOyBlLnRzID0gMTcwMDAwMDAw
MDsgZS5ob3N0ID0gImNwcC1ub2RlIjsgZS5zZXJ2aWNlID0gInBvcnQ6ODA4MCI7IGUuY2FsbGVy
ID0gIjEwLjAuMC45IjsgZS5jYWxsZXJfcG9ydCA9IDUxMDAwOyBlLmRzdF9pcCA9ICIxMC4wLjAu
MiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZClyZXEuc2l6ZSgp
OyBwYXJzZV9yZXF1ZXN0KHJlcS5kYXRhKCksIHJlcS5zaXplKCkgLSA0LCAmZSk7IGUuc3RhdHVz
ID0gMjAwOyBlLmhhc19zdGF0dXMgPSB0cnVlOyBlLmR1cmF0aW9uX21zID0gMzsgZS5oYXNfZHVy
YXRpb24gPSB0cnVlOyBlLnJlc3BfYnl0ZXMgPSA0MjsgZS5oYXNfcmVzcCA9IHRydWU7IGVtaXRf
ZXZlbnQoZSk7IHJldHVybiAwOwp9CgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqKmFyZ3YpIHsK
ICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2WzFdLCAiLS1maXh0dXJlIikpIHJldHVybiBy
dW5fZml4dHVyZSgpOwogIHN0ZDo6c3RyaW5nIGlmYWNlOyBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4g
cG9ydHM7IGludCBpOyBpbnQgd29ya2VycyA9IDE7CiAgc3RkOjpzdHJpbmcgZW5kcG9pbnQ7CiAg
Zm9yIChpID0gMTsgaSA8IGFyZ2M7ICsraSkgewogICAgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1p
IikgJiYgaSArIDEgPCBhcmdjKSBpZmFjZSA9IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJj
bXAoYXJndltpXSwgIi1wIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIHdoaWxlIChpICsgMSA8
IGFyZ2MgJiYgYXJndltpICsgMV1bMF0gIT0gJy0nKSB7CiAgICAgICAgY2hhciAqcSA9IHN0cnRv
ayhhcmd2WysraV0sICIsICIpOwogICAgICAgIHdoaWxlIChxKSB7IGxvbmcgcCA9IGF0b2wocSk7
IGlmICh2YWxpZF9wb3J0KCh1bnNpZ25lZClwKSkgcG9ydHMucHVzaF9iYWNrKCh1bnNpZ25lZClw
KTsgcSA9IHN0cnRvayhOVUxMLCAiLCAiKTsgfQogICAgICB9CiAgICB9CiAgICBlbHNlIGlmICgh
c3RyY21wKGFyZ3ZbaV0sICItLWVuZHBvaW50IikgJiYgaSArIDEgPCBhcmdjKSBlbmRwb2ludCA9
IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tc3Bvb2wiKSAmJiBp
ICsgMSA8IGFyZ2MpICsraTsgLyogaWdub3JlZDogMCBkaXNrIHdyaXRlICovCiAgICBlbHNlIGlm
ICghc3RyY21wKGFyZ3ZbaV0sICItaiIpICYmIGkgKyAxIDwgYXJnYykgd29ya2VycyA9IGF0b2ko
YXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1oIikgfHwgIXN0cmNt
cChhcmd2W2ldLCAiLS1oZWxwIikpIHsKICAgICAgZnByaW50ZihzdGRlcnIsICJ1c2FnZTogbnQt
c25pZmYtY3BwIFstaSBpZmFjZV0gWy1wIHBvcnRzXSBbLS1lbmRwb2ludCBVUkxdIFstaiB3b3Jr
ZXJzXVxuIik7CiAgICAgIHJldHVybiAwOwogICAgfQogIH0KICBpZiAocG9ydHMuZW1wdHkoKSkg
eyBwb3J0cy5wdXNoX2JhY2soODApOyBwb3J0cy5wdXNoX2JhY2soODAwMyk7IHBvcnRzLnB1c2hf
YmFjayg4MDA1KTsgcG9ydHMucHVzaF9iYWNrKDgwMDcpOyBwb3J0cy5wdXNoX2JhY2soODAwOSk7
IHBvcnRzLnB1c2hfYmFjayg4MDEwKTsgcG9ydHMucHVzaF9iYWNrKDgwMTEpOyB9CiAgKHZvaWQp
d29ya2VyczsKCiAgaW5pdF9ybmcoKTsKICBtZW1zZXQoZ19tb25pdG9yZWRfcG9ydHMsIDAsIHNp
emVvZihnX21vbml0b3JlZF9wb3J0cykpOwogIGZvciAoc2l6ZV90IGsgPSAwOyBrIDwgcG9ydHMu
c2l6ZSgpOyArK2spIHsKICAgIGlmIChwb3J0c1trXSA8IDY1NTM2KSBnX21vbml0b3JlZF9wb3J0
c1twb3J0c1trXV0gPSB0cnVlOwogIH0KCiAgY29uc3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYo
Ik5UX05PREVfTkFNRSIpOwogIHN0ZDo6c3RyaW5nIG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVf
ZW52KSA/IG5vZGVfZW52IDogaG9zdF9uYW1lKCk7CgogIGdfZW5kcG9pbnQgPSBlbmRwb2ludDsK
ICBnX3NoaXBfbm9kZSA9IG5vZGU7CgogIGludCBmZCA9IHNvY2tldChBRl9QQUNLRVQsIFNPQ0tf
UkFXLCBodG9ucygzKSk7CiAgaWYgKGZkIDwgMCkgeyBwZXJyb3IoIkFGX1BBQ0tFVCIpOyByZXR1
cm4gMjsgfQogIGludCByYiA9IDggKiAxMDI0ICogMTAyNDsKICBzZXRzb2Nrb3B0KGZkLCBTT0xf
U09DS0VULCBTT19SQ1ZCVUYsICZyYiwgc2l6ZW9mKHJiKSk7CiAgaWYgKCFhdHRhY2hfYnBmKGZk
LCBwb3J0cykpIGxvZ21zZygiV0FSTjogQlBGIGF0dGFjaCBmYWlsZWQ7IGNvbnRpbnVpbmcgdW5m
aWx0ZXJlZCIpOwoKICBNbWFwUmluZyByaW5nOwogIGJvb2wgdXNlX21tYXAgPSBzZXR1cF9tbWFw
X3JpbmcoZmQsIHJpbmcpOwoKICBzdHJ1Y3Qgc29ja2FkZHJfbGwgc2E7CiAgbWVtc2V0KCZzYSwg
MCwgc2l6ZW9mKHNhKSk7CiAgc2Euc2xsX2ZhbWlseSA9IEFGX1BBQ0tFVDsKICBzYS5zbGxfcHJv
dG9jb2wgPSBodG9ucygzKTsKICBpZiAoIWlmYWNlLmVtcHR5KCkpIHsKICAgIHNhLnNsbF9pZmlu
ZGV4ID0gKGludClpZl9uYW1ldG9pbmRleChpZmFjZS5jX3N0cigpKTsKICAgIGlmICghc2Euc2xs
X2lmaW5kZXgpIHsgbG9nbXNnKCJiYWQgaW50ZXJmYWNlIik7IGNsb3NlKGZkKTsgcmV0dXJuIDI7
IH0KICB9CiAgaWYgKGJpbmQoZmQsIChzdHJ1Y3Qgc29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkp
IDwgMCkgeyBwZXJyb3IoImJpbmQiKTsgY2xvc2UoZmQpOyByZXR1cm4gMjsgfQoKICBzaWduYWwo
U0lHVEVSTSwgc3RvcF9zaWduYWwpOwogIHNpZ25hbChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsKICBz
ZXR2YnVmKHN0ZG91dCwgTlVMTCwgX0lPTEJGLCA2NTUzNik7CiAgc3RkOjptYXA8Rmxvd0tleSwg
Rmxvdz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
IHBlbmRpbmc7CgogIGlmICh1c2VfbW1hcCkgewogICAgbG9nbXNnKCJQQUNLRVRfTU1BUCAoVFBB
Q0tFVF9WMikgemVyby1jb3B5IHJpbmcgZW5hYmxlZCAoNE1CLCAyMDQ4IGZyYW1lcykiKTsKICB9
IGVsc2UgewogICAgbG9nbXNnKCJXQVJOOiBQQUNLRVRfTU1BUCBzZXR1cCBmYWlsZWQsIGZhbGxp
bmcgYmFjayB0byBzdGFuZGFyZCBzb2NrZXQgcmVjdiIpOwogIH0KICBpZiAoIWdfZW5kcG9pbnQu
ZW1wdHkoKSkgewogICAgbG9nbXNnKCJzaW5nbGUtYmluYXJ5IGluLW1lbW9yeSBtb2RlOiBzaGlw
cGluZyBkaXJlY3RseSB0byAiICsgZ19lbmRwb2ludCArICIgKDAgZGlzayBJL08pIik7CiAgfQog
IGxvZ21zZygibGlzdGVuaW5nIik7CgogIHRpbWVfdCBsYXN0ID0gdGltZShOVUxMKSwgbGFzdF9m
bHVzaCA9IGxhc3Q7CiAgdW5zaWduZWQgY2hhciAqZmFsbGJhY2tfYnVmID0gTlVMTDsKICBpZiAo
IXVzZV9tbWFwKSB7CiAgICBmYWxsYmFja19idWYgPSAodW5zaWduZWQgY2hhciAqKW1hbGxvYyg2
NTUzNik7CiAgICBpZiAoIWZhbGxiYWNrX2J1ZikgewogICAgICBjbG9zZShmZCk7CiAgICAgIGxv
Z21zZygiYnVmZmVyIGFsbG9jYXRpb24gZmFpbGVkIik7CiAgICAgIHJldHVybiAyOwogICAgfQog
IH0KCiAgc3RydWN0IHBvbGxmZCBwZmQ7CiAgcGZkLmZkID0gZmQ7CiAgcGZkLmV2ZW50cyA9IFBP
TExJTiB8IFBPTExFUlI7CiAgcGZkLnJldmVudHMgPSAwOwoKICB3aGlsZSAoZ19ydW5uaW5nKSB7
CiAgICBpbnQgcmMgPSBwb2xsKCZwZmQsIDEsIDEwMDApOwogICAgaWYgKHJjIDwgMCAmJiBlcnJu
byA9PSBFSU5UUikgewogICAgICAvKiBTaWduYWwgaGFuZGxlZCwgbG9vcCBjb25kaXRpb24gd2ls
bCBjaGVjayBnX3J1bm5pbmcgKi8KICAgIH0gZWxzZSBpZiAocmMgPj0gMCkgewogICAgICBpZiAo
dXNlX21tYXApIHsKICAgICAgICAvKiBEcmFpbiBhbGwgcmVhZHkgZnJhbWVzIGluIHRoZSByaW5n
IHdpdGhvdXQgZXh0cmEgc3lzY2FsbHMgKi8KICAgICAgICB3aGlsZSAoZ19ydW5uaW5nKSB7CiAg
ICAgICAgICB1bnNpZ25lZCBiX2lkeCA9IHJpbmcuZnJhbWVfaWR4IC8gcmluZy5mcmFtZXNfcGVy
X2Jsb2NrOwogICAgICAgICAgdW5zaWduZWQgZl9pbl9iID0gcmluZy5mcmFtZV9pZHggJSByaW5n
LmZyYW1lc19wZXJfYmxvY2s7CiAgICAgICAgICB1aW50OF90ICpmcmFtZV9wdHIgPSAoKHVpbnQ4
X3QgKilyaW5nLnJpbmcpICsgKGJfaWR4ICogcmluZy5ibG9ja19zaXplKSArIChmX2luX2IgKiBy
aW5nLmZyYW1lX3NpemUpOwogICAgICAgICAgc3RydWN0IHRwYWNrZXQyX2hkciAqaGRyID0gKHN0
cnVjdCB0cGFja2V0Ml9oZHIgKilmcmFtZV9wdHI7CgogICAgICAgICAgaWYgKCEoaGRyLT50cF9z
dGF0dXMgJiBUUF9TVEFUVVNfVVNFUikpIHsKICAgICAgICAgICAgYnJlYWs7IC8qIE5vIG1vcmUg
a2VybmVsLXBvcHVsYXRlZCBmcmFtZXMgaW4gcmluZyByaWdodCBub3cgKi8KICAgICAgICAgIH0K
CiAgICAgICAgICBpZiAoaGRyLT50cF9zbmFwbGVuID4gMCkgewogICAgICAgICAgICBjb25zdCB1
bnNpZ25lZCBjaGFyICpwa3QgPSAoKGNvbnN0IHVuc2lnbmVkIGNoYXIgKiloZHIpICsgaGRyLT50
cF9tYWM7CiAgICAgICAgICAgIGhhbmRsZV9wYWNrZXQocGt0LCAoc2l6ZV90KWhkci0+dHBfc25h
cGxlbiwgbm9kZSwgcG9ydHMsIGZsb3dzLCBwZW5kaW5nKTsKICAgICAgICAgIH0KCiAgICAgICAg
ICBoZHItPnRwX3N0YXR1cyA9IFRQX1NUQVRVU19LRVJORUw7IC8qIFJldHVybiBmcmFtZSBvd25l
cnNoaXAgdG8ga2VybmVsICovCiAgICAgICAgICByaW5nLmZyYW1lX2lkeCA9IChyaW5nLmZyYW1l
X2lkeCArIDEpICUgcmluZy5mcmFtZV9ucjsKICAgICAgICB9CiAgICAgICAgaWYgKGdfZW5kcG9p
bnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgaWYg
KHBmZC5yZXZlbnRzICYgUE9MTElOKSB7CiAgICAgICAgICBzc2l6ZV90IG4gPSByZWN2KGZkLCBm
YWxsYmFja19idWYsIDY1NTM2LCAwKTsKICAgICAgICAgIGlmIChuID4gMCkgewogICAgICAgICAg
ICBoYW5kbGVfcGFja2V0KGZhbGxiYWNrX2J1ZiwgKHNpemVfdCluLCBub2RlLCBwb3J0cywgZmxv
d3MsIHBlbmRpbmcpOwogICAgICAgICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNv
dXQuZmx1c2goKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0KICAgIH0KCiAgICB0aW1l
X3Qgbm93ID0gdGltZShOVUxMKTsKICAgIGlmIChub3cgLSBsYXN0ID49IDEpIHsKICAgICAgc3dl
ZXAoZmxvd3MsIHBlbmRpbmcsIG5vdyk7CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0
ZDo6Y291dC5mbHVzaCgpOwogICAgICBsYXN0ID0gbm93OwogICAgfQoKICAgIGlmICghZ19lbmRw
b2ludC5lbXB0eSgpKSB7CiAgICAgIGlmIChub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyB8
fCBnX3NoaXBfYnVmLnNpemUoKSA+PSBNQVhfQkFUQ0gpIHsKICAgICAgICBpZiAoIWdfc2hpcF9i
dWYuZW1wdHkoKSkgc2VuZF9iYXRjaGVzKGdfZW5kcG9pbnQsIGdfc2hpcF9ub2RlLCAmZ19zaGlw
X2J1ZiwgdHJ1ZSk7CiAgICAgICAgbGFzdF9mbHVzaCA9IG5vdzsKICAgICAgfQogICAgfQogIH0K
CiAgLyogQSByZXNwb25zZSBpcyBvcHRpb25hbCBlbnJpY2htZW50LiBQcmVzZXJ2ZSByZXF1ZXN0
cyBzdGlsbCBhd2FpdGluZyBhCiAgICogcmVzcG9uc2Ugd2hlbiBTSUdURVJNL3Jlc3RhcnQgZW5k
cyBjYXB0dXJlLiAqLwogIGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwogIGlmIChnX2VuZHBv
aW50LmVtcHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgpOwoKICBpZiAoIWdfZW5kcG9pbnQuZW1wdHko
KSAmJiAhZ19zaGlwX2J1Zi5lbXB0eSgpKSB7CiAgICBzZW5kX2JhdGNoZXMoZ19lbmRwb2ludCwg
Z19zaGlwX25vZGUsICZnX3NoaXBfYnVmLCB0cnVlKTsKICB9CgogIGlmICh1c2VfbW1hcCAmJiBy
aW5nLnJpbmcgIT0gTUFQX0ZBSUxFRCkgewogICAgbXVubWFwKHJpbmcucmluZywgcmluZy5yaW5n
X3NpemUpOwogIH0KICBpZiAoZmFsbGJhY2tfYnVmKSBmcmVlKGZhbGxiYWNrX2J1Zik7CiAgY2xv
c2UoZmQpOwogIGxvZ21zZygic3RvcHBlZCIpOwogIHJldHVybiAwOwp9Cg==
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
