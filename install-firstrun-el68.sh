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
#                NT_WSSE_BODY_BYTES=0..65536 (Python/C++ modes; default 0)
#                NT_CPU_CORE=N (default: first CPU allowed for the installer)
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
CPU_CORE="${NT_CPU_CORE:-}"

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
[ "$WORKERS" = 1 ] || {
    log "WARN: NT_WORKERS=$WORKERS overridden to 1 by the host safety boundary"
    WORKERS=1
}
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
for f in nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh; do
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
        sed -n '/^#__RESOURCE_GUARD_B64__$/,/^#__END_RESOURCE_GUARD__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-resource-guard.sh" 2>/dev/null
    fi

    # --- source 3: hub bootstrap server ---------------------------------
    if [ ! -s "$WORKDIR/nt-sniff.py" ] || [ ! -s "$WORKDIR/nt-ship.py" ] || [ ! -s "$WORKDIR/nt-sniff-cpp.cpp" ] || [ ! -s "$WORKDIR/Makefile" ] || [ ! -s "$WORKDIR/nt-resource-guard.sh" ]; then
        if [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
            HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
            [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
        fi
        [ -n "$KIT_URLS" ] || die "kit files missing, no embedded payload, cannot derive hub URL — pass --hub http://HUB:30105/oldkernel"
        log "first run: fetching kit from $KIT_URLS -> $WORKDIR"
        have curl || have wget || die "neither curl nor wget present and no embedded payload"
        for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh el68-smoke.sh README.md DEBUG-NOTES.md; do
            fetch "$KIT_URLS/$f" "$WORKDIR/$f.new" || die "cannot download $f from $KIT_URLS"
            mv "$WORKDIR/$f.new" "$WORKDIR/$f"
        done
    fi

    chmod 755 "$WORKDIR"/nt-*.py "$WORKDIR"/nt-run-cpp.sh "$WORKDIR"/nt-resource-guard.sh 2>/dev/null || true
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

# Runtime containment is mandatory. Pick the first CPU from the installer's
# allowed cpuset unless explicitly selected, then prove it is bindable before
# making any host changes. Missing taskset therefore fails closed.
have taskset || die "taskset required for the one-core runtime safety boundary"
if [ -z "$CPU_CORE" ]; then
    CPU_CORE=$(awk '/^Cpus_allowed_list:/ { gsub(/[,-].*/, "", $2); print $2; exit }' /proc/self/status 2>/dev/null)
fi
case "$CPU_CORE" in
    ''|*[!0-9]*) die "cannot select an allowed CPU core (set NT_CPU_CORE=N)" ;;
esac
taskset -c "$CPU_CORE" true >/dev/null 2>&1 \
    || die "CPU core $CPU_CORE is outside this host/process cpuset"

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
for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh; do
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
cp "$SCRIPT_DIR"/nt-resource-guard.sh "$PREFIX/"
if [ -f "$SCRIPT_DIR/install-oldkernel.sh" ]; then
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install-oldkernel.sh"
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install.sh"
elif [ -n "${SELF:-}" ] && [ -f "$SELF" ]; then
    cp "$SELF" "$PREFIX/install-oldkernel.sh"
    cp "$SELF" "$PREFIX/install.sh"
fi
chmod 755 "$PREFIX"/nt-*.py "$PREFIX"/nt-control.py "$PREFIX"/nt_control.py "$PREFIX"/nt-run-cpp.sh "$PREFIX"/nt-resource-guard.sh "$PREFIX"/install*.sh 2>/dev/null || true

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
        RUN_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT --wsse-body-bytes $WSSE_BODY_BYTES' >>\$PREFIX/sniff.log 2>&1"
    else
        RUN_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT --wsse-body-bytes $WSSE_BODY_BYTES >>\$PREFIX/sniff.log 2>&1"
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
CPU_CORE=$CPU_CORE
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
        # Fail closed behind one inherited CPU affinity and finite host limits.
        nohup "\$PREFIX/nt-resource-guard.sh" "\$CPU_CORE" sh -c "$RUN_CMD" >/dev/null 2>&1 &
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
log "Safety: cpu=$CPU_CORE (one logical core), memory=256MiB, fds=1024, output-file=32MiB, core-dumps=off"
if [ "$WSSE_BODY_BYTES" -ne 0 ]; then
    log "WSSE UsernameToken inspection: bounded to $WSSE_BODY_BYTES bytes/request"
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
IGRlcHMuCiAqIFNPQVAgYm9keSBpbnNwZWN0aW9uIGlzIGV4cGxpY2l0bHkgb3B0LWluIGFuZCBi
b3VuZGVkLiBUTFMgcmVtYWlucwogKiBlY2FwdHVyZSdzIGNvbmNlcm4uCiAqLwojaW5jbHVkZSA8
YXJwYS9pbmV0Lmg+CiNpbmNsdWRlIDxjdHlwZS5oPgojaW5jbHVkZSA8ZXJybm8uaD4KI2luY2x1
ZGUgPGZjbnRsLmg+CiNpbmNsdWRlIDxuZXQvaWYuaD4KI2luY2x1ZGUgPHNpZ25hbC5oPgojaW5j
bHVkZSA8c3RkaW50Lmg+CiNpbmNsdWRlIDxzdGRpby5oPgojaW5jbHVkZSA8c3RkbGliLmg+CiNp
bmNsdWRlIDxzdHJpbmcuaD4KI2luY2x1ZGUgPHBvbGwuaD4KI2luY2x1ZGUgPHN5cy9pb2N0bC5o
PgojaW5jbHVkZSA8c3lzL21tYW4uaD4KI2luY2x1ZGUgPHN5cy9zZWxlY3QuaD4KI2luY2x1ZGUg
PHN5cy90aW1lLmg+CiNpbmNsdWRlIDxzeXMvc29ja2V0Lmg+CiNpbmNsdWRlIDxzeXMvdHlwZXMu
aD4KI2luY2x1ZGUgPHRpbWUuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8bGludXgv
ZmlsdGVyLmg+CiNpbmNsdWRlIDxsaW51eC9pZl9wYWNrZXQuaD4KI2luY2x1ZGUgPGxpbnV4L2lm
X2V0aGVyLmg+CiNpbmNsdWRlIDxpb3N0cmVhbT4KI2luY2x1ZGUgPGZzdHJlYW0+CiNpbmNsdWRl
IDxtYXA+CiNpbmNsdWRlIDxzc3RyZWFtPgojaW5jbHVkZSA8c3RyaW5nPgojaW5jbHVkZSA8dmVj
dG9yPgoKc3RhdGljIHZvbGF0aWxlIHNpZ19hdG9taWNfdCBnX3J1bm5pbmcgPSAxOwpzdGF0aWMg
dm9pZCBzdG9wX3NpZ25hbChpbnQpIHsgZ19ydW5uaW5nID0gMDsgfQoKc3RhdGljIGNvbnN0IHNp
emVfdCBNQVhfRkxPV1MgPSA4MTkyOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QRU5ESU5HID0g
ODE5MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUEVORElOR19QRVJfRkxPVyA9IDMyOwpzdGF0
aWMgY29uc3Qgc2l6ZV90IE1BWF9IRUFERVIgPSAyNjIxNDQ7CnN0YXRpYyBjb25zdCBzaXplX3Qg
TUFYX1dTU0VfQk9EWV9CWVRFUyA9IDY1NTM2OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NF
X0JPRFlfRkxPV1MgPSAyNTY7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1dTU0VfVVNFUk5BTUUg
PSAyMDA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0JBVENIID0gNDAwOwpzdGF0aWMgY29uc3Qg
c2l6ZV90IE1BWF9RVUVVRSA9IDQwMDA7CnN0YXRpYyBjb25zdCBpbnQgRkxVU0hfU0VDID0gNTsK
c3RhdGljIGNvbnN0IGludCBSRVRSWV9TRUMgPSA2MDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIEZM
T1dfVFRMID0gMTU7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBQRU5ESU5HX1RUTCA9IDM7CnN0YXRp
YyBjb25zdCB1bnNpZ25lZCBBQ0NFUFQgPSAyMDQ4OwpzdGF0aWMgY29uc3QgaW50IFNPX0FUVEFD
SF9GSUxURVJfT0xEID0gMjY7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBFVEhfUF9JUF9I
T1NUID0gMHgwODAwOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfODAyMVFfSE9T
VCA9IDB4ODEwMDsKCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmltKGNvbnN0IHN0ZDo6c3RyaW5nICZz
KSB7CiAgc2l6ZV90IGEgPSAwLCBiID0gcy5zaXplKCk7CiAgd2hpbGUgKGEgPCBiICYmIGlzc3Bh
Y2UoKHVuc2lnbmVkIGNoYXIpc1thXSkpICsrYTsKICB3aGlsZSAoYiA+IGEgJiYgaXNzcGFjZSgo
dW5zaWduZWQgY2hhcilzW2IgLSAxXSkpIC0tYjsKICByZXR1cm4gcy5zdWJzdHIoYSwgYiAtIGEp
Owp9CnN0YXRpYyBzdGQ6OnN0cmluZyBsb3dlcihjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0
ZDo6c3RyaW5nIHggPSBzOwogIHNpemVfdCBpOyBmb3IgKGkgPSAwOyBpIDwgeC5zaXplKCk7ICsr
aSkgeFtpXSA9IChjaGFyKXRvbG93ZXIoKHVuc2lnbmVkIGNoYXIpeFtpXSk7CiAgcmV0dXJuIHg7
Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25xKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3Rk
OjpzdHJpbmcgeCA9ICJcIiI7IHNpemVfdCBpOwogIGZvciAoaSA9IDA7IGkgPCBzLnNpemUoKTsg
KytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgaWYg
KGMgPT0gJ1xcJyB8fCBjID09ICciJykgeyB4ICs9ICdcXCc7IHggKz0gKGNoYXIpYzsgfQogICAg
ZWxzZSBpZiAoYyA9PSAnXG4nKSB4ICs9ICJcXG4iOwogICAgZWxzZSBpZiAoYyA9PSAnXHInKSB4
ICs9ICJcXHIiOwogICAgZWxzZSBpZiAoYyA9PSAnXHQnKSB4ICs9ICJcXHQiOwogICAgZWxzZSBp
ZiAoYyA8IDMyKSB4ICs9ICc/JzsKICAgIGVsc2UgeCArPSAoY2hhciljOwogIH0KICB4ICs9ICci
JzsgcmV0dXJuIHg7Cn0Kc3RhdGljIGxvbmcgbG9uZyBub3dfbXMoKSB7CiAgc3RydWN0IHRpbWV2
YWwgdHY7IGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVybiAobG9uZyBsb25nKXR2LnR2
X3NlYyAqIDEwMDBMTCArIHR2LnR2X3VzZWMgLyAxMDAwOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBu
dW0obG9uZyB2KSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IHY7IHJldHVybiBvLnN0cigp
OyB9CnN0YXRpYyBib29sIHZhbGlkX3BvcnQodW5zaWduZWQgcCkgeyByZXR1cm4gcCA+IDAgJiYg
cCA8PSA2NTUzNTsgfQpzdGF0aWMgYm9vbCBoYXNfbWV0aG9kKGNvbnN0IHN0ZDo6c3RyaW5nICZt
KSB7CiAgcmV0dXJuIG0gPT0gIkdFVCIgfHwgbSA9PSAiUE9TVCIgfHwgbSA9PSAiUFVUIiB8fCBt
ID09ICJERUxFVEUiIHx8CiAgICAgICAgIG0gPT0gIlBBVENIIiB8fCBtID09ICJIRUFEIiB8fCBt
ID09ICJPUFRJT05TIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgaG9zdF9uYW1lKCkgewogIGNoYXIg
YlsyNTZdOyBpZiAoZ2V0aG9zdG5hbWUoYiwgc2l6ZW9mKGIpIC0gMSkgIT0gMCkgcmV0dXJuICJ1
bmtub3duLW5vZGUiOwogIGJbc2l6ZW9mKGIpIC0gMV0gPSAwOyBjaGFyICpwID0gc3RyY2hyKGIs
ICcuJyk7IGlmIChwKSAqcCA9IDA7IHJldHVybiBiOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBiNjRk
ZWNvZGVfdXNlcihjb25zdCBjaGFyICppbiwgc2l6ZV90IGluX2xlbikgewogIHdoaWxlIChpbl9s
ZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpKmluKSkgeyArK2luOyAtLWluX2xlbjsg
fQogIHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpaW5baW5fbGVu
IC0gMV0pKSB7IC0taW5fbGVuOyB9CiAgc3RkOjpzdHJpbmcgb3V0OyBpbnQgdmFsID0gMCwgYml0
cyA9IC04OyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgaW5fbGVuOyArK2kpIHsKICAgIHVu
c2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWluW2ldOyBpbnQgZCA9IC0xOwogICAgaWYg
KGMgPj0gJ0EnICYmIGMgPD0gJ1onKSBkID0gYyAtICdBJzsKICAgIGVsc2UgaWYgKGMgPj0gJ2En
ICYmIGMgPD0gJ3onKSBkID0gYyAtICdhJyArIDI2OwogICAgZWxzZSBpZiAoYyA+PSAnMCcgJiYg
YyA8PSAnOScpIGQgPSBjIC0gJzAnICsgNTI7CiAgICBlbHNlIGlmIChjID09ICcrJykgZCA9IDYy
OwogICAgZWxzZSBpZiAoYyA9PSAnLycpIGQgPSA2MzsKICAgIGVsc2UgaWYgKGMgPT0gJz0nKSBi
cmVhazsKICAgIGlmIChkIDwgMCkgY29udGludWU7CiAgICB2YWwgPSAodmFsIDw8IDYpICsgZDsK
ICAgIGJpdHMgKz0gNjsKICAgIGlmIChiaXRzID49IDApIHsKICAgICAgb3V0ICs9IChjaGFyKSgo
dmFsID4+IGJpdHMpICYgMHhmZik7CiAgICAgIGJpdHMgLT0gODsKICAgICAgaWYgKG91dC5zaXpl
KCkgPiA1MTIpIHJldHVybiAiIjsKICAgIH0KICB9CiAgc2l6ZV90IHAgPSBvdXQuZmluZCgnOicp
OwogIGlmIChwID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CiAgcmV0dXJuIG91dC5z
dWJzdHIoMCwgcCA+IDY0ID8gNjQgOiBwKTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgaXBfdG9fc3Ry
KHVpbnQzMl90IGlwX2JlKSB7CiAgY2hhciBiW0lORVRfQUREUlNUUkxFTl07CiAgaW5ldF9udG9w
KEFGX0lORVQsICZpcF9iZSwgYiwgc2l6ZW9mKGIpKTsKICByZXR1cm4gYjsKfQoKc3RhdGljIHN0
ZDo6c3RyaW5nIHRyYWNlX2lkX2Zyb21fcGFyZW50KGNvbnN0IHN0ZDo6c3RyaW5nICZ0cCkgewog
IHN0ZDo6c3RyaW5nIHggPSB0cmltKHRwKTsKICBpZiAoeC5zaXplKCkgPT0gNTUgJiYgeFsyXSA9
PSAnLScgJiYgeFszNV0gPT0gJy0nICYmIHhbNTJdID09ICctJykgcmV0dXJuIGxvd2VyKHguc3Vi
c3RyKDMsIDMyKSk7CiAgcmV0dXJuICIiOwp9CgpzdGF0aWMgdWludDY0X3QgZ19ybmdfc3RhdGUg
PSAwOwpzdGF0aWMgdm9pZCBpbml0X3JuZygpIHsKICBGSUxFICpmID0gZm9wZW4oIi9kZXYvdXJh
bmRvbSIsICJyYiIpOwogIGlmIChmKSB7CiAgICBzaXplX3QgbiA9IGZyZWFkKCZnX3JuZ19zdGF0
ZSwgMSwgc2l6ZW9mKGdfcm5nX3N0YXRlKSwgZik7CiAgICAodm9pZCluOwogICAgZmNsb3NlKGYp
OwogIH0KICBpZiAoIWdfcm5nX3N0YXRlKSB7CiAgICBnX3JuZ19zdGF0ZSA9ICgodWludDY0X3Qp
dGltZShOVUxMKSA8PCAzMikgXiAodWludDY0X3QpZ2V0cGlkKCk7CiAgfQp9CnN0YXRpYyBpbmxp
bmUgdWludDY0X3QgbmV4dF9ybmcoKSB7CiAgdWludDY0X3QgeCA9IGdfcm5nX3N0YXRlOwogIHgg
Xj0geCA8PCAxMzsgeCBePSB4ID4+IDc7IHggXj0geCA8PCAxNzsKICByZXR1cm4gZ19ybmdfc3Rh
dGUgPSAoeCA/IHggOiAweDg1M2M0OWU2NzQ4ZmVhOWJVTEwpOwp9CgpzdGF0aWMgc3RkOjpzdHJp
bmcgbWFrZV90cmFjZXBhcmVudChzdGQ6OnN0cmluZyAqdGlkKSB7CiAgdWludDY0X3QgcjEgPSBu
ZXh0X3JuZygpOwogIHVpbnQ2NF90IHIyID0gbmV4dF9ybmcoKTsKICB1aW50NjRfdCByMyA9IG5l
eHRfcm5nKCk7CiAgY2hhciBidWZbNjRdOwogIHNucHJpbnRmKGJ1Ziwgc2l6ZW9mKGJ1ZiksICIw
MC0lMDE2bGx4JTAxNmxseC0lMDE2bGx4LTAxIiwKICAgICAgICAgICAodW5zaWduZWQgbG9uZyBs
b25nKXIxLCAodW5zaWduZWQgbG9uZyBsb25nKXIyLCAodW5zaWduZWQgbG9uZyBsb25nKXIzKTsK
ICBjaGFyIHRpZF9idWZbMzNdOwogIHNucHJpbnRmKHRpZF9idWYsIHNpemVvZih0aWRfYnVmKSwg
IiUwMTZsbHglMDE2bGx4IiwKICAgICAgICAgICAodW5zaWduZWQgbG9uZyBsb25nKXIxLCAodW5z
aWduZWQgbG9uZyBsb25nKXIyKTsKICAqdGlkID0gdGlkX2J1ZjsKICByZXR1cm4gYnVmOwp9Cgpz
dHJ1Y3QgRXZlbnQgewogIGxvbmcgdHM7IHN0ZDo6c3RyaW5nIGhvc3QsIHNyYywgc2VydmljZSwg
bWV0aG9kLCBwYXRoLCB1c2VyLCBzY2hlbWUsIHByb2JlOwogIHN0ZDo6c3RyaW5nIGhvc3RfaGRy
LCB1c2VyX2FnZW50LCB4ZmYsIGNhbGxlciwgZHN0X2lwLCB0cmFjZXBhcmVudCwgdHJhY2VfaWQ7
CiAgdW5zaWduZWQgY2FsbGVyX3BvcnQsIGRzdF9wb3J0LCByZXFfYnl0ZXMsIHJlc3BfYnl0ZXM7
IGludCBzdGF0dXM7IGxvbmcgZHVyYXRpb25fbXM7CiAgYm9vbCBoYXNfc3RhdHVzLCBoYXNfZHVy
YXRpb24sIGhhc19yZXNwOwogIEV2ZW50KCkgOiB0cygwKSwgY2FsbGVyX3BvcnQoMCksIGRzdF9w
b3J0KDApLCByZXFfYnl0ZXMoMCksIHJlc3BfYnl0ZXMoMCksIHN0YXR1cygwKSwgZHVyYXRpb25f
bXMoMCksIGhhc19zdGF0dXMoZmFsc2UpLCBoYXNfZHVyYXRpb24oZmFsc2UpLCBoYXNfcmVzcChm
YWxzZSkge30KfTsKc3RydWN0IFJlcXVlc3RNZXRhIHsKICBzdGQ6OnN0cmluZyBjb250ZW50X3R5
cGUsIHRyYW5zZmVyX2VuY29kaW5nOwogIHNpemVfdCBjb250ZW50X2xlbmd0aDsKICBib29sIGhh
c19jb250ZW50X2xlbmd0aDsKICBSZXF1ZXN0TWV0YSgpIDogY29udGVudF9sZW5ndGgoMCksIGhh
c19jb250ZW50X2xlbmd0aChmYWxzZSkge30KfTsKc3RydWN0IEZsb3cgewogIHN0ZDo6c3RyaW5n
IGJ1ZjsKICB0aW1lX3QgdG91Y2hlZDsKICBFdmVudCBldmVudDsKICBzaXplX3QgYm9keV9nb2Fs
OwogIGJvb2wgYXdhaXRpbmdfYm9keTsKICBGbG93KCkgOiB0b3VjaGVkKHRpbWUoTlVMTCkpLCBi
b2R5X2dvYWwoMCksIGF3YWl0aW5nX2JvZHkoZmFsc2UpIHt9Cn07CnN0cnVjdCBQZW5kaW5nIHsK
ICBFdmVudCBldjsKICBsb25nIGxvbmcgc3RhcnRlZF9tczsKICBQZW5kaW5nKCkgOiBzdGFydGVk
X21zKDApIHt9CiAgUGVuZGluZyhjb25zdCBFdmVudCAmZSwgbG9uZyBsb25nIHQpIDogZXYoZSks
IHN0YXJ0ZWRfbXModCkge30KfTsKc3RydWN0IEZsb3dLZXkgewogIHVpbnQzMl90IHNfaXA7CiAg
dWludDE2X3Qgc3BvcnQ7CiAgdWludDMyX3QgZF9pcDsKICB1aW50MTZfdCBkcG9ydDsKICBib29s
IG9wZXJhdG9yPChjb25zdCBGbG93S2V5ICZ4KSBjb25zdCB7CiAgICBpZiAoc19pcCAhPSB4LnNf
aXApIHJldHVybiBzX2lwIDwgeC5zX2lwOwogICAgaWYgKHNwb3J0ICE9IHguc3BvcnQpIHJldHVy
biBzcG9ydCA8IHguc3BvcnQ7CiAgICBpZiAoZF9pcCAhPSB4LmRfaXApIHJldHVybiBkX2lwIDwg
eC5kX2lwOwogICAgcmV0dXJuIGRwb3J0IDwgeC5kcG9ydDsKICB9Cn07CnR5cGVkZWYgRmxvd0tl
eSBQYWNrZXRLZXk7CgpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsg
ZnByaW50ZihzdGRlcnIsICJudC1zbmlmZi1jcHA6ICVzXG4iLCBzLmNfc3RyKCkpOyBmZmx1c2go
c3RkZXJyKTsgfQoKc3RhdGljIGJvb2wgcGFyc2VfZGVjaW1hbF9zaXplKGNvbnN0IGNoYXIgKnAs
IHNpemVfdCBuLCBzaXplX3QgKm91dCkgewogIHdoaWxlIChuICYmIGlzc3BhY2UoKHVuc2lnbmVk
IGNoYXIpKnApKSB7ICsrcDsgLS1uOyB9CiAgd2hpbGUgKG4gJiYgaXNzcGFjZSgodW5zaWduZWQg
Y2hhcilwW24gLSAxXSkpIC0tbjsKICBpZiAoIW4pIHJldHVybiBmYWxzZTsKICBzaXplX3QgdmFs
dWUgPSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgbjsgKytpKSB7CiAgICBpZiAocFtpXSA8
ICcwJyB8fCBwW2ldID4gJzknKSByZXR1cm4gZmFsc2U7CiAgICB1bnNpZ25lZCBkaWdpdCA9ICh1
bnNpZ25lZCkocFtpXSAtICcwJyk7CiAgICBpZiAodmFsdWUgPiAoc2l6ZV90KS0xIC8gMTAgfHwg
dmFsdWUgKiAxMCA+IChzaXplX3QpLTEgLSBkaWdpdCkgcmV0dXJuIGZhbHNlOwogICAgdmFsdWUg
PSB2YWx1ZSAqIDEwICsgZGlnaXQ7CiAgfQogICpvdXQgPSB2YWx1ZTsKICByZXR1cm4gdHJ1ZTsK
fQoKc3RhdGljIGJvb2wgcGFyc2VfcmVxdWVzdChjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVu
LCBFdmVudCAqZSwgUmVxdWVzdE1ldGEgKm1ldGEpIHsKICBjb25zdCBjaGFyICplbmQgPSBkYXRh
ICsgbGVuOwogIGNvbnN0IGNoYXIgKnAgPSBkYXRhOwogIGNvbnN0IGNoYXIgKmVvbCA9IChjb25z
dCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogIGlmICghZW9sKSByZXR1cm4gZmFs
c2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJyAnLCBlb2wg
LSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGUtPm1ldGhvZC5hc3NpZ24ocCwgc3Ax
IC0gcCk7CiAgaWYgKCFoYXNfbWV0aG9kKGUtPm1ldGhvZCkpIHJldHVybiBmYWxzZTsKCiAgY29u
c3QgY2hhciAqcGF0aF9zdGFydCA9IHNwMSArIDE7CiAgd2hpbGUgKHBhdGhfc3RhcnQgPCBlb2wg
JiYgKnBhdGhfc3RhcnQgPT0gJyAnKSArK3BhdGhfc3RhcnQ7CiAgY29uc3QgY2hhciAqc3AyID0g
KGNvbnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJyAnLCBlb2wgLSBwYXRoX3N0YXJ0KTsK
ICBpZiAoIXNwMikgc3AyID0gKGVvbCA+IGRhdGEgJiYgKihlb2wgLSAxKSA9PSAnXHInKSA/IGVv
bCAtIDEgOiBlb2w7CiAgY29uc3QgY2hhciAqcW1hcmsgPSAoY29uc3QgY2hhciAqKW1lbWNocihw
YXRoX3N0YXJ0LCAnPycsIHNwMiAtIHBhdGhfc3RhcnQpOwogIHNpemVfdCBwYXRoX2xlbiA9IChx
bWFyayA/IHFtYXJrIDogc3AyKSAtIHBhdGhfc3RhcnQ7CiAgaWYgKHBhdGhfbGVuID4gMTIwKSBw
YXRoX2xlbiA9IDEyMDsKICBlLT5wYXRoLmFzc2lnbihwYXRoX3N0YXJ0LCBwYXRoX2xlbik7Cgog
IHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBpZiAoKnAgPT0gJ1xyJyB8fCAq
cCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5kID0gKGNvbnN0IGNoYXIg
KiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVfZW5kKSBsaW5lX2VuZCA9
IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJzon
LCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAgIHNpemVfdCBobmFtZV9sZW4g
PSBjb2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9zdGFydCA9IGNvbG9uICsgMTsKICAg
ICAgd2hpbGUgKHZhbF9zdGFydCA8IGxpbmVfZW5kICYmICgqdmFsX3N0YXJ0ID09ICcgJyB8fCAq
dmFsX3N0YXJ0ID09ICdcdCcpKSArK3ZhbF9zdGFydDsKICAgICAgY29uc3QgY2hhciAqdmFsX2Vu
ZCA9IGxpbmVfZW5kOwogICAgICB3aGlsZSAodmFsX2VuZCA+IHZhbF9zdGFydCAmJiAodmFsX2Vu
ZFstMV0gPT0gJ1xyJyB8fCB2YWxfZW5kWy0xXSA9PSAnXG4nIHx8IHZhbF9lbmRbLTFdID09ICcg
JyB8fCB2YWxfZW5kWy0xXSA9PSAnXHQnKSkgLS12YWxfZW5kOwogICAgICBzaXplX3QgdmFsX2xl
biA9IHZhbF9lbmQgLSB2YWxfc3RhcnQ7CgogICAgICBpZiAoaG5hbWVfbGVuID09IDEzICYmICFz
dHJuY2FzZWNtcChwLCAiYXV0aG9yaXphdGlvbiIsIDEzKSkgewogICAgICAgIGlmICh2YWxfbGVu
ID4gNiAmJiAhc3RybmNhc2VjbXAodmFsX3N0YXJ0LCAiQmFzaWMgIiwgNikpIHsKICAgICAgICAg
IGUtPnVzZXIgPSBiNjRkZWNvZGVfdXNlcih2YWxfc3RhcnQgKyA2LCB2YWxfbGVuIC0gNik7CiAg
ICAgICAgICBlLT5zY2hlbWUgPSAiYmFzaWMiOwogICAgICAgIH0gZWxzZSBpZiAodmFsX2xlbiA+
IDcgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJlYXJlciAiLCA3KSkgewogICAgICAgICAg
ZS0+c2NoZW1lID0gImJlYXJlciI7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xl
biA9PSAxMSAmJiAhc3RybmNhc2VjbXAocCwgInRyYWNlcGFyZW50IiwgMTEpKSB7CiAgICAgICAg
ZS0+dHJhY2VwYXJlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgICAgZS0+dHJh
Y2VfaWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVudChlLT50cmFjZXBhcmVudCk7CiAgICAgIH0gZWxz
ZSBpZiAoaG5hbWVfbGVuID09IDQgJiYgIXN0cm5jYXNlY21wKHAsICJob3N0IiwgNCkpIHsKICAg
ICAgICBlLT5ob3N0X2hkci5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNl
IGlmIChobmFtZV9sZW4gPT0gMTAgJiYgIXN0cm5jYXNlY21wKHAsICJ1c2VyLWFnZW50IiwgMTAp
KSB7CiAgICAgICAgZS0+dXNlcl9hZ2VudC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAg
ICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTUgJiYgIXN0cm5jYXNlY21wKHAsICJ4LWZvcndh
cmRlZC1mb3IiLCAxNSkpIHsKICAgICAgICBlLT54ZmYuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xl
bik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFtZV9sZW4gPT0gMTIgJiYgIXN0cm5jYXNl
Y21wKHAsICJjb250ZW50LXR5cGUiLCAxMikpIHsKICAgICAgICBtZXRhLT5jb250ZW50X3R5cGUu
YXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFt
ZV9sZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewog
ICAgICAgIG1ldGEtPmhhc19jb250ZW50X2xlbmd0aCA9IHBhcnNlX2RlY2ltYWxfc2l6ZSh2YWxf
c3RhcnQsIHZhbF9sZW4sICZtZXRhLT5jb250ZW50X2xlbmd0aCk7CiAgICAgIH0gZWxzZSBpZiAo
bWV0YSAmJiBobmFtZV9sZW4gPT0gMTcgJiYgIXN0cm5jYXNlY21wKHAsICJ0cmFuc2Zlci1lbmNv
ZGluZyIsIDE3KSkgewogICAgICAgIG1ldGEtPnRyYW5zZmVyX2VuY29kaW5nLmFzc2lnbih2YWxf
c3RhcnQsIHZhbF9sZW4pOwogICAgICB9CiAgICB9CiAgICBwID0gbGluZV9lbmQgKyAxOwogIH0K
CiAgaWYgKGUtPnVzZXIuZW1wdHkoKSkgZS0+dXNlciA9ICItYW5vbnltb3VzLSI7CiAgaWYgKGUt
PnNjaGVtZS5lbXB0eSgpKSBlLT5zY2hlbWUgPSAibm9uZSI7CiAgaWYgKGUtPnRyYWNlX2lkLmVt
cHR5KCkpIGUtPnRyYWNlcGFyZW50ID0gbWFrZV90cmFjZXBhcmVudCgmZS0+dHJhY2VfaWQpOwog
IHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBpc193c3NlX25hbWVzcGFjZShjb25zdCBzdGQ6
OnN0cmluZyAmdXJpKSB7CiAgcmV0dXJuIHVyaSA9PSAiaHR0cDovL2RvY3Mub2FzaXMtb3Blbi5v
cmcvd3NzLzIwMDQvMDEvb2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNk
IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIv
MDcvc2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3Jn
L3dzLzIwMDIvMTIvc2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnht
bHNvYXAub3JnL3dzLzIwMDMvMDYvc2VjZXh0IjsKfQoKc3RhdGljIGJvb2wgaXNfc29hcF9jb250
ZW50X3R5cGUoY29uc3Qgc3RkOjpzdHJpbmcgJnZhbHVlKSB7CiAgc3RkOjpzdHJpbmcgbWVkaWEg
PSBsb3dlcih2YWx1ZSk7CiAgc2l6ZV90IHNlbWkgPSBtZWRpYS5maW5kKCc7Jyk7CiAgaWYgKHNl
bWkgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIG1lZGlhLmVyYXNlKHNlbWkpOwogIG1lZGlhID0gdHJp
bShtZWRpYSk7CiAgcmV0dXJuIG1lZGlhID09ICJ0ZXh0L3htbCIgfHwgbWVkaWEgPT0gImFwcGxp
Y2F0aW9uL3htbCIgfHwKICAgICAgICAgbWVkaWEgPT0gImFwcGxpY2F0aW9uL3NvYXAreG1sIiB8
fAogICAgICAgICAobWVkaWEuc2l6ZSgpID4gNCAmJiBtZWRpYS5jb21wYXJlKG1lZGlhLnNpemUo
KSAtIDQsIDQsICIreG1sIikgPT0gMCk7Cn0KCnN0YXRpYyB2b2lkIHNwbGl0X3FuYW1lKGNvbnN0
IHN0ZDo6c3RyaW5nICZuYW1lLCBzdGQ6OnN0cmluZyAqcHJlZml4LCBzdGQ6OnN0cmluZyAqbG9j
YWwpIHsKICBzaXplX3QgY29sb24gPSBuYW1lLmZpbmQoJzonKTsKICBpZiAoY29sb24gPT0gc3Rk
OjpzdHJpbmc6Om5wb3MpIHsgcHJlZml4LT5jbGVhcigpOyAqbG9jYWwgPSBuYW1lOyB9CiAgZWxz
ZSB7ICpwcmVmaXggPSBuYW1lLnN1YnN0cigwLCBjb2xvbik7ICpsb2NhbCA9IG5hbWUuc3Vic3Ry
KGNvbG9uICsgMSk7IH0KfQoKc3RhdGljIGJvb2wgYXBwZW5kX3V0ZjgodW5zaWduZWQgbG9uZyBj
cCwgc3RkOjpzdHJpbmcgKm91dCkgewogIGlmIChjcCA9PSAwIHx8IGNwID4gMHgxMGZmZmZVTCB8
fCAoY3AgPj0gMHhkODAwVUwgJiYgY3AgPD0gMHhkZmZmVUwpKSByZXR1cm4gZmFsc2U7CiAgaWYg
KGNwIDwgMHg4MCkgb3V0LT5wdXNoX2JhY2soKGNoYXIpY3ApOwogIGVsc2UgaWYgKGNwIDwgMHg4
MDApIHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGMwIHwgKGNwID4+IDYpKSk7CiAgICBv
dXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfSBlbHNlIGlmIChj
cCA8IDB4MTAwMDApIHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGUwIHwgKGNwID4+IDEy
KSkpOwogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoKGNwID4+IDYpICYgMHgzZikp
KTsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKGNwICYgMHgzZikpKTsKICB9IGVs
c2UgewogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ZjAgfCAoY3AgPj4gMTgpKSk7CiAgICBv
dXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgoY3AgPj4gMTIpICYgMHgzZikpKTsKICAgIG91
dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKChjcCA+PiA2KSAmIDB4M2YpKSk7CiAgICBvdXQt
PnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfQogIHJldHVybiB0cnVl
Owp9CgpzdGF0aWMgYm9vbCB4bWxfdW5lc2NhcGUoY29uc3Qgc3RkOjpzdHJpbmcgJnRleHQsIHN0
ZDo6c3RyaW5nICpvdXQpIHsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHRleHQuc2l6ZSgpOykg
ewogICAgaWYgKHRleHRbaV0gIT0gJyYnKSB7IG91dC0+cHVzaF9iYWNrKHRleHRbaSsrXSk7IGNv
bnRpbnVlOyB9CiAgICBzaXplX3Qgc2VtaSA9IHRleHQuZmluZCgnOycsIGkgKyAxKTsKICAgIGlm
IChzZW1pID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHNlbWkgLSBpID4gMTIpIHJldHVybiBmYWxz
ZTsKICAgIHN0ZDo6c3RyaW5nIGVudCA9IHRleHQuc3Vic3RyKGkgKyAxLCBzZW1pIC0gaSAtIDEp
OwogICAgaWYgKGVudCA9PSAiYW1wIikgb3V0LT5wdXNoX2JhY2soJyYnKTsKICAgIGVsc2UgaWYg
KGVudCA9PSAibHQiKSBvdXQtPnB1c2hfYmFjaygnPCcpOwogICAgZWxzZSBpZiAoZW50ID09ICJn
dCIpIG91dC0+cHVzaF9iYWNrKCc+Jyk7CiAgICBlbHNlIGlmIChlbnQgPT0gInF1b3QiKSBvdXQt
PnB1c2hfYmFjaygnIicpOwogICAgZWxzZSBpZiAoZW50ID09ICJhcG9zIikgb3V0LT5wdXNoX2Jh
Y2soJ1wnJyk7CiAgICBlbHNlIGlmICghZW50LmVtcHR5KCkgJiYgZW50WzBdID09ICcjJykgewog
ICAgICBjaGFyICplbmRwID0gTlVMTDsKICAgICAgdW5zaWduZWQgbG9uZyBjcCA9IHN0cnRvdWwo
ZW50LmNfc3RyKCkgKyAoKGVudC5zaXplKCkgPiAxICYmIChlbnRbMV0gPT0gJ3gnIHx8IGVudFsx
XSA9PSAnWCcpKSA/IDIgOiAxKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJmVu
ZHAsIChlbnQuc2l6ZSgpID4gMSAmJiAoZW50WzFdID09ICd4JyB8fCBlbnRbMV0gPT0gJ1gnKSkg
PyAxNiA6IDEwKTsKICAgICAgaWYgKCFlbmRwIHx8ICplbmRwIHx8ICFhcHBlbmRfdXRmOChjcCwg
b3V0KSkgcmV0dXJuIGZhbHNlOwogICAgfSBlbHNlIHJldHVybiBmYWxzZTsKICAgIGkgPSBzZW1p
ICsgMTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHZhbGlkX3V0ZjhfdXNlcm5h
bWUoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBpZiAocy5lbXB0eSgpIHx8IHMuc2l6ZSgpID4g
TUFYX1dTU0VfVVNFUk5BTUUgKiA0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IGNoYXJhY3RlcnMg
PSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7KSB7CiAgICB1bnNpZ25lZCBj
aGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgdW5zaWduZWQgbG9uZyBjcCA9IGM7CiAg
ICBpZiAoYyA8IDB4ODApIHsgKytpOyB9CiAgICBlbHNlIHsKICAgIHNpemVfdCBuZWVkID0gKGMg
Pj0gMHhjMiAmJiBjIDw9IDB4ZGYpID8gMSA6CiAgICAgICAgICAgICAgICAgIChjID49IDB4ZTAg
JiYgYyA8PSAweGVmKSA/IDIgOgogICAgICAgICAgICAgICAgICAoYyA+PSAweGYwICYmIGMgPD0g
MHhmNCkgPyAzIDogOTk7CiAgICBpZiAobmVlZCA9PSA5OSB8fCBpICsgbmVlZCA+PSBzLnNpemUo
KSkgcmV0dXJuIGZhbHNlOwogICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0gbmVlZDsgKytqKQog
ICAgICBpZiAoKCh1bnNpZ25lZCBjaGFyKXNbaSArIGpdICYgMHhjMCkgIT0gMHg4MCkgcmV0dXJu
IGZhbHNlOwogICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4ZTAgJiYgKHVuc2lnbmVkIGNoYXIp
c1tpICsgMV0gPCAweGEwKSByZXR1cm4gZmFsc2U7CiAgICBpZiAobmVlZCA9PSAyICYmIGMgPT0g
MHhlZCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA+PSAweGEwKSByZXR1cm4gZmFsc2U7CiAg
ICBpZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmMCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA8
IDB4OTApIHJldHVybiBmYWxzZTsKICAgIGlmIChuZWVkID09IDMgJiYgYyA9PSAweGY0ICYmICh1
bnNpZ25lZCBjaGFyKXNbaSArIDFdID49IDB4OTApIHJldHVybiBmYWxzZTsKICAgIGNwID0gYyAm
ICgoMVUgPDwgKDcgLSBuZWVkIC0gMSkpIC0gMSk7CiAgICBmb3IgKHNpemVfdCBqID0gMTsgaiA8
PSBuZWVkOyArK2opIGNwID0gKGNwIDw8IDYpIHwgKCh1bnNpZ25lZCBjaGFyKXNbaSArIGpdICYg
MHgzZik7CiAgICBpICs9IG5lZWQgKyAxOwogICAgfQogICAgaWYgKCsrY2hhcmFjdGVycyA+IE1B
WF9XU1NFX1VTRVJOQU1FKSByZXR1cm4gZmFsc2U7CiAgICBpZiAoY3AgPCAweDIwIHx8IChjcCA+
PSAweDdmICYmIGNwIDw9IDB4OWYpIHx8CiAgICAgICAgKGNwID49IDB4ZTAwMCAmJiBjcCA8PSAw
eGY4ZmYpIHx8CiAgICAgICAgKGNwID49IDB4ZjAwMDAgJiYgY3AgPD0gMHhmZmZmZCkgfHwKICAg
ICAgICAoY3AgPj0gMHgxMDAwMDAgJiYgY3AgPD0gMHgxMGZmZmQpIHx8CiAgICAgICAgKGNwID49
IDB4ZmRkMCAmJiBjcCA8PSAweGZkZWYpIHx8IChjcCAmIDB4ZmZmZlVMKSA+PSAweGZmZmVVTCB8
fAogICAgICAgIGNwID09IDB4MDBhZCB8fCBjcCA9PSAweDA2MWMgfHwgY3AgPT0gMHgwNmRkIHx8
IGNwID09IDB4MDcwZiB8fAogICAgICAgIGNwID09IDB4MTgwZSB8fCAoY3AgPj0gMHgyMDBiICYm
IGNwIDw9IDB4MjAwZikgfHwKICAgICAgICAoY3AgPj0gMHgyMDJhICYmIGNwIDw9IDB4MjAyZSkg
fHwgKGNwID49IDB4MjA2MCAmJiBjcCA8PSAweDIwNmYpIHx8CiAgICAgICAgY3AgPT0gMHhmZWZm
KSByZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdHJ1Y3QgWG1sRnJhbWUgewog
IHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz4gbnM7CiAgc3RkOjpzdHJpbmcgcW5h
bWUsIHVyaSwgbG9jYWw7Cn07CgpzdGF0aWMgYm9vbCBwYXJzZV94bWxfbmFtZShjb25zdCBzdGQ6
OnN0cmluZyAmYm9keSwgc2l6ZV90IGxpbWl0LCBzaXplX3QgKnBvcywKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgc3RkOjpzdHJpbmcgKm5hbWUpIHsKICBzaXplX3Qgc3RhcnQgPSAqcG9zOwog
IHdoaWxlICgqcG9zIDwgbGltaXQpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBj
aGFyKWJvZHlbKnBvc107CiAgICBpZiAoIShpc2FsbnVtKGMpIHx8IGMgPT0gJ18nIHx8IGMgPT0g
Jy0nIHx8IGMgPT0gJy4nIHx8IGMgPT0gJzonKSkgYnJlYWs7CiAgICArKypwb3M7CiAgfQogIGlm
ICgqcG9zID09IHN0YXJ0IHx8ICpwb3MgLSBzdGFydCA+IDI1NikgcmV0dXJuIGZhbHNlOwogIG5h
bWUtPmFzc2lnbihib2R5LCBzdGFydCwgKnBvcyAtIHN0YXJ0KTsKICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIHN0ZDo6c3RyaW5nIGV4dHJhY3Rfd3NzZV91c2VybmFtZShjb25zdCBzdGQ6OnN0cmlu
ZyAmYm9keSkgewogIGlmIChib2R5LmVtcHR5KCkgfHwgYm9keS5zaXplKCkgPiBNQVhfV1NTRV9C
T0RZX0JZVEVTIHx8CiAgICAgIGJvZHkuZmluZCgnXDAnKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykg
cmV0dXJuICIiOwogIHN0ZDo6c3RyaW5nIGxvd2VyZWQgPSBsb3dlcihib2R5KTsKICBpZiAobG93
ZXJlZC5maW5kKCI8IWRvY3R5cGUiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAgICBsb3dl
cmVkLmZpbmQoIjwhZW50aXR5IikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiAiIjsKCiAg
c3RkOjp2ZWN0b3I8WG1sRnJhbWU+IHN0YWNrOwogIHNpemVfdCB0b2tlbl9kZXB0aCA9IDAsIHVz
ZXJuYW1lX2RlcHRoID0gMCwgcG9zID0gMDsKICBzdGQ6OnN0cmluZyB0b2tlbl91cmksIGNoYXJz
LCByZXN1bHQ7CiAgYm9vbCB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICB3aGlsZSAocG9zIDwgYm9k
eS5zaXplKCkpIHsKICAgIHNpemVfdCBsdCA9IGJvZHkuZmluZCgnPCcsIHBvcyk7CiAgICBpZiAo
bHQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1
c2VybmFtZV9iYWQgJiYgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cihwb3MpLCAmY2hhcnMpKSB1
c2VybmFtZV9iYWQgPSB0cnVlOwogICAgICBicmVhazsgLyogYSBib3VuZGVkIHByZWZpeCBpcyBj
b21tb25seSBpbmNvbXBsZXRlICovCiAgICB9CiAgICBpZiAodXNlcm5hbWVfZGVwdGggJiYgIXVz
ZXJuYW1lX2JhZCAmJiBsdCA+IHBvcyAmJgogICAgICAgICF4bWxfdW5lc2NhcGUoYm9keS5zdWJz
dHIocG9zLCBsdCAtIHBvcyksICZjaGFycykpIHVzZXJuYW1lX2JhZCA9IHRydWU7CiAgICBpZiAo
Y2hhcnMuc2l6ZSgpID4gTUFYX1dTU0VfVVNFUk5BTUUgKiA0ICsgMikgeyBjaGFycy5jbGVhcigp
OyB1c2VybmFtZV9iYWQgPSB0cnVlOyB9CgogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgNCwgIjwh
LS0iKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIi0tPiIsIGx0ICsgNCk7
IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBwb3MgPSBlbmQgKyAz
OyBjb250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDksICI8IVtDREFUQVsi
KSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIl1dPiIsIGx0ICsgOSk7IGlm
IChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBpZiAodXNlcm5hbWVfZGVw
dGggJiYgIXVzZXJuYW1lX2JhZCkgY2hhcnMuYXBwZW5kKGJvZHksIGx0ICsgOSwgZW5kIC0gbHQg
LSA5KTsKICAgICAgcG9zID0gZW5kICsgMzsgY29udGludWU7CiAgICB9CiAgICBpZiAoYm9keS5j
b21wYXJlKGx0LCAyLCAiPD8iKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQo
Ij8+IiwgbHQgKyAyKTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICAg
IHBvcyA9IGVuZCArIDI7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29tcGFyZShsdCwg
MiwgIjwhIikgPT0gMCkgcmV0dXJuICIiOwoKICAgIGJvb2wgY2xvc2luZyA9IChsdCArIDEgPCBi
b2R5LnNpemUoKSAmJiBib2R5W2x0ICsgMV0gPT0gJy8nKTsKICAgIHNpemVfdCBwID0gbHQgKyAo
Y2xvc2luZyA/IDIgOiAxKTsKICAgIHN0ZDo6c3RyaW5nIHFuYW1lOwogICAgaWYgKCFwYXJzZV94
bWxfbmFtZShib2R5LCBib2R5LnNpemUoKSwgJnAsICZxbmFtZSkpIGJyZWFrOwogICAgaWYgKGNs
b3NpbmcpIHsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNpZ25l
ZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8IGJvZHlb
cF0gIT0gJz4nKSBicmVhazsKICAgICAgaWYgKHN0YWNrLmVtcHR5KCkpIGJyZWFrOwogICAgICBz
dGQ6OnN0cmluZyBwcmVmaXgsIGxvY2FsOyBzcGxpdF9xbmFtZShxbmFtZSwgJnByZWZpeCwgJmxv
Y2FsKTsKICAgICAgWG1sRnJhbWUgJnRvcCA9IHN0YWNrLmJhY2soKTsKICAgICAgaWYgKHRvcC5x
bmFtZSAhPSBxbmFtZSB8fCB0b3AubG9jYWwgIT0gbG9jYWwpIGJyZWFrOwogICAgICBzaXplX3Qg
ZGVwdGggPSBzdGFjay5zaXplKCk7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBkZXB0aCkg
ewogICAgICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0gdHJpbShjaGFycyk7CiAgICAgICAgaWYg
KCF1c2VybmFtZV9iYWQgJiYgdmFsaWRfdXRmOF91c2VybmFtZSh1c2VybmFtZSkgJiYgcmVzdWx0
LmVtcHR5KCkpIHJlc3VsdCA9IHVzZXJuYW1lOwogICAgICAgIHVzZXJuYW1lX2RlcHRoID0gMDsg
Y2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICAgIH0KICAgICAgaWYgKHRv
a2VuX2RlcHRoID09IGRlcHRoKSB7IHRva2VuX2RlcHRoID0gMDsgdG9rZW5fdXJpLmNsZWFyKCk7
IH0KICAgICAgc3RhY2sucG9wX2JhY2soKTsgcG9zID0gcCArIDE7CiAgICAgIGlmICghcmVzdWx0
LmVtcHR5KCkpIHJldHVybiByZXN1bHQ7CiAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIFhtbEZy
YW1lIGZyYW1lOwogICAgaWYgKHN0YWNrLnNpemUoKSA+PSA2NCkgcmV0dXJuICIiOwogICAgaWYg
KCFzdGFjay5lbXB0eSgpKSBmcmFtZS5ucyA9IHN0YWNrLmJhY2soKS5uczsKICAgIGJvb2wgc2Vs
Zl9jbG9zaW5nID0gZmFsc2UsIGNvbXBsZXRlID0gZmFsc2U7CiAgICBzaXplX3QgYXR0cl9jb3Vu
dCA9IDA7CiAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpKSB7CiAgICAgIHdoaWxlIChwIDwgYm9k
eS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBp
ZiAocCA+PSBib2R5LnNpemUoKSkgYnJlYWs7CiAgICAgIGlmIChib2R5W3BdID09ICc+JykgeyAr
K3A7IGNvbXBsZXRlID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgaWYgKGJvZHlbcF0gPT0gJy8nICYm
IHAgKyAxIDwgYm9keS5zaXplKCkgJiYgYm9keVtwICsgMV0gPT0gJz4nKSB7CiAgICAgICAgcCAr
PSAyOyBzZWxmX2Nsb3NpbmcgPSB0cnVlOyBjb21wbGV0ZSA9IHRydWU7IGJyZWFrOwogICAgICB9
CiAgICAgIHN0ZDo6c3RyaW5nIGFuYW1lOwogICAgICBpZiAoIXBhcnNlX3htbF9uYW1lKGJvZHks
IGJvZHkuc2l6ZSgpLCAmcCwgJmFuYW1lKSkgYnJlYWs7CiAgICAgIGlmICgrK2F0dHJfY291bnQg
PiAxMjgpIHJldHVybiAiIjsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNl
KCh1bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgp
IHx8IGJvZHlbcCsrXSAhPSAnPScpIGJyZWFrOwogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgp
ICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0g
Ym9keS5zaXplKCkgfHwgKGJvZHlbcF0gIT0gJ1wnJyAmJiBib2R5W3BdICE9ICciJykpIGJyZWFr
OwogICAgICBjaGFyIHF1b3RlID0gYm9keVtwKytdOyBzaXplX3QgdmFsdWVfc3RhcnQgPSBwOwog
ICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbcF0gIT0gcXVvdGUpICsrcDsKICAg
ICAgaWYgKHAgPj0gYm9keS5zaXplKCkpIGJyZWFrOwogICAgICBzdGQ6OnN0cmluZyB2YWx1ZTsK
ICAgICAgaWYgKCF4bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIodmFsdWVfc3RhcnQsIHAgLSB2YWx1
ZV9zdGFydCksICZ2YWx1ZSkpIHJldHVybiAiIjsKICAgICAgKytwOwogICAgICBpZiAoYW5hbWUg
PT0gInhtbG5zIikgZnJhbWUubnNbIiJdID0gdmFsdWU7CiAgICAgIGVsc2UgaWYgKGFuYW1lLmNv
bXBhcmUoMCwgNiwgInhtbG5zOiIpID09IDApIGZyYW1lLm5zW2FuYW1lLnN1YnN0cig2KV0gPSB2
YWx1ZTsKICAgICAgaWYgKGZyYW1lLm5zLnNpemUoKSA+IDY0KSByZXR1cm4gIiI7CiAgICB9CiAg
ICBpZiAoIWNvbXBsZXRlKSBicmVhazsKICAgIHN0ZDo6c3RyaW5nIHByZWZpeCwgbG9jYWw7IHNw
bGl0X3FuYW1lKHFuYW1lLCAmcHJlZml4LCAmbG9jYWwpOwogICAgc3RkOjptYXA8c3RkOjpzdHJp
bmcsIHN0ZDo6c3RyaW5nPjo6Y29uc3RfaXRlcmF0b3IgbnMgPSBmcmFtZS5ucy5maW5kKHByZWZp
eCk7CiAgICBmcmFtZS51cmkgPSAobnMgPT0gZnJhbWUubnMuZW5kKCkpID8gIiIgOiBucy0+c2Vj
b25kOwogICAgZnJhbWUucW5hbWUgPSBxbmFtZTsKICAgIGZyYW1lLmxvY2FsID0gbG9jYWw7CiAg
ICBzdGFjay5wdXNoX2JhY2soZnJhbWUpOwogICAgc2l6ZV90IGRlcHRoID0gc3RhY2suc2l6ZSgp
OwogICAgaWYgKCF0b2tlbl9kZXB0aCAmJiBsb2NhbCA9PSAiVXNlcm5hbWVUb2tlbiIgJiYgaXNf
d3NzZV9uYW1lc3BhY2UoZnJhbWUudXJpKSkgewogICAgICB0b2tlbl9kZXB0aCA9IGRlcHRoOyB0
b2tlbl91cmkgPSBmcmFtZS51cmk7CiAgICB9IGVsc2UgaWYgKHRva2VuX2RlcHRoICYmIGRlcHRo
ID09IHRva2VuX2RlcHRoICsgMSAmJgogICAgICAgICAgICAgICBsb2NhbCA9PSAiVXNlcm5hbWUi
ICYmIGZyYW1lLnVyaSA9PSB0b2tlbl91cmkpIHsKICAgICAgdXNlcm5hbWVfZGVwdGggPSBkZXB0
aDsgY2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICB9CiAgICBpZiAoc2Vs
Zl9jbG9zaW5nKSB7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBkZXB0aCkgdXNlcm5hbWVf
ZGVwdGggPSAwOwogICAgICBpZiAodG9rZW5fZGVwdGggPT0gZGVwdGgpIHsgdG9rZW5fZGVwdGgg
PSAwOyB0b2tlbl91cmkuY2xlYXIoKTsgfQogICAgICBzdGFjay5wb3BfYmFjaygpOwogICAgfQog
ICAgcG9zID0gcDsKICB9CiAgcmV0dXJuIHJlc3VsdDsKfQoKc3RhdGljIGJvb2wgcGFyc2VfcmVz
cG9uc2UoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgaW50ICpzdGF0dXMsIHVuc2lnbmVk
ICpjbGVuKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSArIGxlbjsKICBjb25zdCBjaGFyICpw
ID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4n
LCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNlOwogIGlmIChzdHJuY21wKHAsICJI
VFRQLyIsIDUpICE9IDApIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3Qg
Y2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7
CiAgY29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChzY19zdGFydCA8IGVv
bCAmJiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0YXJ0OwogICpzdGF0dXMgPSBhdG9pKHNjX3N0
YXJ0KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAqc3RhdHVzID4gNTk5KSByZXR1cm4gZmFsc2U7
CiAgKmNsZW4gPSAwOwogIHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBpZiAo
KnAgPT0gJ1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5k
ID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVf
ZW5kKSBsaW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNoYXIg
KiltZW1jaHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAgIHNp
emVfdCBobGVuID0gY29sb24gLSBwOwogICAgICBpZiAoaGxlbiA9PSAxNCAmJiAhc3RybmNhc2Vj
bXAocCwgImNvbnRlbnQtbGVuZ3RoIiwgMTQpKSB7CiAgICAgICAgY29uc3QgY2hhciAqdiA9IGNv
bG9uICsgMTsKICAgICAgICB3aGlsZSAodiA8IGxpbmVfZW5kICYmICgqdiA9PSAnICcgfHwgKnYg
PT0gJ1x0JykpICsrdjsKICAgICAgICBsb25nIG4gPSBhdG9sKHYpOwogICAgICAgIGlmIChuID49
IDAgJiYgbiA8PSAweDdmZmZmZmZmKSAqY2xlbiA9ICh1bnNpZ25lZCluOwogICAgICB9CiAgICB9
CiAgICBwID0gbGluZV9lbmQgKyAxOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIHN0ZDo6
c3RyaW5nIGdfZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX3NoaXBfbm9kZTsKc3RhdGlj
IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBnX3NoaXBfYnVmOwoKc3RhdGljIHN0ZDo6c3RyaW5n
IHNoZWxscShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIG8gPSAiJyI7CiAg
Zm9yIChzaXplX3QgaSA9IDA7IGkgPCBzLnNpemUoKTsgKytpKSB7IGlmIChzW2ldID09ICdcJycp
IG8gKz0gIidcXCcnIjsgZWxzZSBvICs9IHNbaV07IH0KICByZXR1cm4gbyArICInIjsKfQpzdGF0
aWMgc3RkOjpzdHJpbmcgbnVtYmVyX3N0cmluZyhzaXplX3QgbikgeyBzdGQ6Om9zdHJpbmdzdHJl
YW0gbzsgbyA8PCBuOyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgc3RkOjpzdHJpbmcganNvbl9h
cnJheShjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmEpIHsKICBzdGQ6OnN0cmluZyBv
ID0gIlsiOyBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGEuc2l6ZSgpOyArK2kpIHsgaWYgKGkpIG8g
Kz0gIiwiOyBvICs9IGFbaV07IH0gcmV0dXJuIG8gKyAiXSI7Cn0Kc3RhdGljIGJvb2wgcG9zdChj
b25zdCBzdGQ6OnN0cmluZyAmZW5kcG9pbnQsIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlLCBjb25z
dCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNoKSB7CiAgc3RkOjpzdHJpbmcgYm9keSA9
ICJ7XCJub2RlXCI6IiArIGpzb25xKG5vZGUpICsgIixcImV2ZW50c1wiOiIgKyBqc29uX2FycmF5
KGJhdGNoKSArICJ9IjsKICBzdGQ6OnN0cmluZyBjbWQgPSAiY3VybCAtc1NmIC0tbWF4LXRpbWUg
MTAgLW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0
YS1iaW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCArICIvYXBpL2luZ2VzdCIpOwogIEZJTEUg
KmZwID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7IGlmICghZnApIHJldHVybiBmYWxzZTsKICBm
d3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAgaW50IHJjID0gcGNsb3Nl
KGZwKTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRVUyhyYykgPT0gMDsKfQpz
dGF0aWMgdm9pZCBzZW5kX2JhdGNoZXMoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25z
dCBzdGQ6OnN0cmluZyAmbm9kZSwKICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6dmVjdG9y
PHN0ZDo6c3RyaW5nPiAqYnVmLCBib29sIGZsdXNoX2FsbCkgewogIHdoaWxlICghYnVmLT5lbXB0
eSgpICYmIChmbHVzaF9hbGwgfHwgYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIKSkgewogICAgc2l6
ZV90IG4gPSBidWYtPnNpemUoKSA+PSBNQVhfQkFUQ0ggPyBNQVhfQkFUQ0ggOiBidWYtPnNpemUo
KTsKICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBiYXRjaChidWYtPmJlZ2luKCksIGJ1Zi0+
YmVnaW4oKSArIG4pOwogICAgaWYgKHBvc3QoZW5kcG9pbnQsIG5vZGUsIGJhdGNoKSkgewogICAg
ICBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigpICsgbik7CiAgICAgIGxvZ21z
ZygiZmx1c2hlZCAiICsgbnVtYmVyX3N0cmluZyhuKSArICIgZXZlbnRzIik7CiAgICB9IGVsc2Ug
ewogICAgICAvKiBQdXJlIGluLW1lbW9yeSBkcm9wIHdoZW4gSHViIHVucmVhY2hhYmxlICh6ZXJv
IGRpc2sgSS9PKSAqLwogICAgICBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigp
ICsgbik7CiAgICAgIGxvZ21zZygiV0FSTjogSHViIHVucmVhY2hhYmxlLCBkcm9wcGVkICIgKyBu
dW1iZXJfc3RyaW5nKG4pICsgIiBldmVudHMgKGluLW1lbW9yeSBkcm9wLCAwIGRpc2sgSS9PKSIp
OwogICAgICBicmVhazsKICAgIH0KICB9Cn0KCnN0YXRpYyB2b2lkIGVtaXRfZXZlbnQoY29uc3Qg
RXZlbnQgJmUpIHsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gc3M7CiAgc3MgPDwgIntcInRzXCI6IiA8
PCBlLnRzIDw8ICIsXCJob3N0XCI6IiA8PCBqc29ucShlLmhvc3QpIDw8ICIsXCJzcmNcIjpcInBj
YXBcIixcInNlcnZpY2VcIjoiIDw8IGpzb25xKGUuc2VydmljZSkKICAgICA8PCAiLFwibWV0aG9k
XCI6IiA8PCBqc29ucShlLm1ldGhvZCkgPDwgIixcInBhdGhcIjoiIDw8IGpzb25xKGUucGF0aCkg
PDwgIixcInVzZXJcIjoiIDw8IGpzb25xKGUudXNlcikKICAgICA8PCAiLFwic2NoZW1lXCI6IiA8
PCBqc29ucShlLnNjaGVtZSkgPDwgIixcInNvdXJjZV9wcm9iZVwiOlwicGNhcC1odHRwLWNwcFwi
LFwiaG9zdF9oZHJcIjoiIDw8IGpzb25xKGUuaG9zdF9oZHIpCiAgICAgPDwgIixcInVzZXJfYWdl
bnRcIjoiIDw8IGpzb25xKGUudXNlcl9hZ2VudCkgPDwgIixcInhfZm9yd2FyZGVkX2ZvclwiOiIg
PDwganNvbnEoZS54ZmYpCiAgICAgPDwgIixcImNhbGxlclwiOiIgPDwganNvbnEoZS5jYWxsZXIp
IDw8ICIsXCJjYWxsZXJfcG9ydFwiOiIgPDwgZS5jYWxsZXJfcG9ydCA8PCAiLFwiZHN0X2lwXCI6
IiA8PCBqc29ucShlLmRzdF9pcCkKICAgICA8PCAiLFwiZHN0X3BvcnRcIjoiIDw8IGUuZHN0X3Bv
cnQgPDwgIixcInRyYWNlcGFyZW50XCI6IiA8PCBqc29ucShlLnRyYWNlcGFyZW50KSA8PCAiLFwi
dHJhY2VfaWRcIjoiIDw8IGpzb25xKGUudHJhY2VfaWQpCiAgICAgPDwgIixcInNlcnZpY2VfaWRc
IjpudWxsLFwibW9kdWxlX2lkXCI6XCJwY2FwLWh0dHAtY3BwXCIsXCJyZXFfYnl0ZXNcIjoiIDw8
IGUucmVxX2J5dGVzOwogIGlmIChlLmhhc19zdGF0dXMpIHNzIDw8ICIsXCJzdGF0dXNcIjoiIDw8
IGUuc3RhdHVzOyBlbHNlIHNzIDw8ICIsXCJzdGF0dXNcIjpudWxsIjsKICBpZiAoZS5oYXNfZHVy
YXRpb24pIHNzIDw8ICIsXCJkdXJhdGlvbl9tc1wiOiIgPDwgZS5kdXJhdGlvbl9tczsgZWxzZSBz
cyA8PCAiLFwiZHVyYXRpb25fbXNcIjpudWxsIjsKICBpZiAoZS5oYXNfcmVzcCkgc3MgPDwgIixc
InJlc3BfYnl0ZXNcIjoiIDw8IGUucmVzcF9ieXRlczsgZWxzZSBzcyA8PCAiLFwicmVzcF9ieXRl
c1wiOm51bGwiOwogIHNzIDw8ICJ9IjsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAg
IGlmIChnX3NoaXBfYnVmLnNpemUoKSA+PSBNQVhfUVVFVUUpIHsKICAgICAgZ19zaGlwX2J1Zi5l
cmFzZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgfQogICAgZ19zaGlwX2J1Zi5wdXNoX2JhY2so
c3Muc3RyKCkpOwogIH0gZWxzZSB7CiAgICBzdGQ6OmNvdXQgPDwgc3Muc3RyKCkgPDwgIlxuIjsK
ICB9Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX29sZGVzdChzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBpZiAocGVuZGluZy5lbXB0eSgpKSByZXR1
cm47CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRv
ciBpdCA9IHBlbmRpbmcuYmVnaW4oKTsKICBpZiAoIWl0LT5zZWNvbmQuZW1wdHkoKSkgewogICAg
ZW1pdF9ldmVudChpdC0+c2Vjb25kWzBdLmV2KTsKICAgIGl0LT5zZWNvbmQuZXJhc2UoaXQtPnNl
Y29uZC5iZWdpbigpKTsKICB9CiAgaWYgKGl0LT5zZWNvbmQuZW1wdHkoKSkgewogICAgcGVuZGlu
Zy5lcmFzZShpdCk7CiAgfQp9CnN0YXRpYyB2b2lkIGZsdXNoX2FsbF9wZW5kaW5nKHN0ZDo6bWFw
PFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIHN0ZDo6bWFw
PFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcDsKICBmb3IgKHAg
PSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTsgKytwKSB7CiAgICBmb3IgKHNp
emVfdCBpID0gMDsgaSA8IHAtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICBlbWl0X2V2ZW50
KHAtPnNlY29uZFtpXS5ldik7CiAgICB9CiAgfQogIHBlbmRpbmcuY2xlYXIoKTsKfQpzdGF0aWMg
dm9pZCBzd2VlcChzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tl
dEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywgdGltZV90IG5vdykgewogIHN0
ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBmLCBmbjsKICBmb3IgKGYgPSBmbG93cy5i
ZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAgZm4gPSBmOyArK2ZuOwogICAgaWYgKCh1
bnNpZ25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNoZWQpID4gRkxPV19UVEwpIGZsb3dzLmVyYXNl
KGYpOwogICAgZiA9IGZuOwogIH0KICBsb25nIGxvbmcgY3VycmVudF9tcyA9IChsb25nIGxvbmcp
bm93ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4g
Pjo6aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0gcGVuZGluZy5iZWdpbigpOyBwICE9IHBlbmRp
bmcuZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47CiAgICBzaXplX3QgaSA9IDA7CiAgICB3aGls
ZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAgaWYgKGN1cnJlbnRfbXMgLSBwLT5zZWNv
bmRbaV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcpUEVORElOR19UVEwgKiAxMDAwTEwpIHsKICAg
ICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAgICAgcC0+c2Vjb25kLmVyYXNl
KHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgKytpOwogICAg
ICB9CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAg
ICBwID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmluZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6
c3RyaW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQVVQg
IiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIHNpemVfdCBi
ZXN0ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCA3OyArK2kp
IHsKICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7CiAgICBpZiAocG9zICE9IHN0ZDo6c3Ry
aW5nOjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHBvcyA8IGJlc3QpKSBi
ZXN0ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoKc3RhdGljIGJvb2wgZ19tb25pdG9yZWRf
cG9ydHNbNjU1MzZdOwpzdGF0aWMgc2l6ZV90IGdfd3NzZV9ib2R5X2J5dGVzID0gMDsKCnN0YXRp
YyB2b2lkIHF1ZXVlX3JlcXVlc3QoY29uc3QgRXZlbnQgJmUsIHVpbnQzMl90IHNfaXAsIHVuc2ln
bmVkIHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgIHVpbnQzMl90IGRfaXAsIHVuc2ln
bmVkIGRwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwg
c3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIFBhY2tldEtleSByazsKICByay5z
X2lwID0gZF9pcDsgcmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgcmsuZF9pcCA9IHNfaXA7
IHJrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogIGlmIChwZW5kaW5nLmZpbmQocmspID09IHBl
bmRpbmcuZW5kKCkgJiYgcGVuZGluZy5zaXplKCkgPj0gTUFYX1BFTkRJTkcpIHsKICAgIGZsdXNo
X29sZGVzdChwZW5kaW5nKTsKICB9CiAgc3RkOjp2ZWN0b3I8UGVuZGluZz4gJnF1ZXVlID0gcGVu
ZGluZ1tya107CiAgaWYgKHF1ZXVlLnNpemUoKSA+PSBNQVhfUEVORElOR19QRVJfRkxPVykgewog
ICAgZW1pdF9ldmVudChxdWV1ZVswXS5ldik7CiAgICBxdWV1ZS5lcmFzZShxdWV1ZS5iZWdpbigp
KTsKICB9CiAgcXVldWUucHVzaF9iYWNrKFBlbmRpbmcoZSwgbm93X21zKCkpKTsKfQoKc3RhdGlj
IHNpemVfdCBhY3RpdmVfd3NzZV9mbG93cyhjb25zdCBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAm
Zmxvd3MpIHsKICBzaXplX3QgY291bnQgPSAwOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+Ojpj
b25zdF9pdGVyYXRvciBpdDsKICBmb3IgKGl0ID0gZmxvd3MuYmVnaW4oKTsgaXQgIT0gZmxvd3Mu
ZW5kKCk7ICsraXQpCiAgICBpZiAoaXQtPnNlY29uZC5hd2FpdGluZ19ib2R5KSArK2NvdW50Owog
IHJldHVybiBjb3VudDsKfQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25l
ZCBjaGFyICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3Rk
Ojp2ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6
Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0
b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogICh2b2lkKXBvcnRzOwogIGlmIChuIDwgMzQpIHJl
dHVybiBmYWxzZTsKICBzaXplX3Qgb2ZmID0gMTQ7CiAgdW5zaWduZWQgc2hvcnQgZXQgPSBudG9o
cygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIDEyKSk7CiAgaWYgKGV0ID09IEVUSF9Q
XzgwMjFRKSB7IGlmIChuIDwgMzgpIHJldHVybiBmYWxzZTsgZXQgPSBudG9ocygqKGNvbnN0IHVu
c2lnbmVkIHNob3J0ICopKGJ1ZiArIDE2KSk7IG9mZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9Q
X0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNlOwogIHVuc2lnbmVkIGNoYXIgaWhsID0g
KHVuc2lnbmVkIGNoYXIpKGJ1ZltvZmZdICYgMTUpICogNDsKICBpZiAoKGJ1ZltvZmZdID4+IDQp
ICE9IDQgfHwgYnVmW29mZiArIDldICE9IDYgfHwgbiA8IG9mZiArIGlobCArIDIwKSByZXR1cm4g
ZmFsc2U7CgogIHVpbnQzMl90IHNfaXAgPSAqKGNvbnN0IHVpbnQzMl90ICopKGJ1ZiArIG9mZiAr
IDEyKTsKICB1aW50MzJfdCBkX2lwID0gKihjb25zdCB1aW50MzJfdCAqKShidWYgKyBvZmYgKyAx
Nik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwogIHVuc2lnbmVkIHNwb3J0ID0gbnRvaHMoKihj
b25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0bykpOwogIHVuc2lnbmVkIGRwb3J0ID0gbnRv
aHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0byArIDIpKTsKICB1bnNpZ25lZCBk
b2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYgKG4gPCB0byArIGRvZmYpIHJldHVy
biBmYWxzZTsKICBjb25zdCBjaGFyICpwYXlsb2FkID0gKGNvbnN0IGNoYXIgKikoYnVmICsgdG8g
KyBkb2ZmKTsKICBzaXplX3QgcGxlbiA9IG4gLSB0byAtIGRvZmY7CiAgaWYgKCFwbGVuKSByZXR1
cm4gZmFsc2U7CgogIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogIGJvb2wgZHN0X21vbiA9IChk
cG9ydCA8IDY1NTM2KSA/IGdfbW9uaXRvcmVkX3BvcnRzW2Rwb3J0XSA6IGZhbHNlOwogIGJvb2wg
c3JjX21vbiA9IChzcG9ydCA8IDY1NTM2KSA/IGdfbW9uaXRvcmVkX3BvcnRzW3Nwb3J0XSA6IGZh
bHNlOwoKICBpZiAoc3JjX21vbiAmJiAhZHN0X21vbiAmJiBwbGVuID49IDUpIHsKICAgIGlmICht
ZW1jbXAocGF5bG9hZCwgIkhUVFAvIiwgNSkgPT0gMCkgewogICAgICBQYWNrZXRLZXkgazsKICAg
ICAgay5zX2lwID0gc19pcDsgay5zcG9ydCA9ICh1aW50MTZfdClzcG9ydDsgay5kX2lwID0gZF9p
cDsgay5kcG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBz
dGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKGspOwogICAg
ICBpZiAocCAhPSBwZW5kaW5nLmVuZCgpICYmICFwLT5zZWNvbmQuZW1wdHkoKSkgewogICAgICAg
IGludCBzdDsgdW5zaWduZWQgY2w7CiAgICAgICAgaWYgKHBhcnNlX3Jlc3BvbnNlKHBheWxvYWQs
IHBsZW4sICZzdCwgJmNsKSkgewogICAgICAgICAgRXZlbnQgZSA9IHAtPnNlY29uZFswXS5ldjsK
ICAgICAgICAgIGUuc3RhdHVzID0gc3Q7IGUuaGFzX3N0YXR1cyA9IHRydWU7CiAgICAgICAgICBl
LmR1cmF0aW9uX21zID0gKGxvbmcpKG5vd19tcygpIC0gcC0+c2Vjb25kWzBdLnN0YXJ0ZWRfbXMp
OwogICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBlLmR1cmF0aW9uX21zID0gMDsKICAg
ICAgICAgIGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsKICAgICAgICAgIGlmIChjbCkgeyBlLnJlc3Bf
Ynl0ZXMgPSBjbDsgZS5oYXNfcmVzcCA9IHRydWU7IH0KICAgICAgICAgIGVtaXRfZXZlbnQoZSk7
CiAgICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkpOwogICAgICAgICAg
aWYgKHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgIH0KICAgICAg
fQogICAgfQogICAgcmV0dXJuIHRydWU7CiAgfQogIHVuc2lnbmVkIGNoYXIgdGNwX2ZsYWdzID0g
YnVmW3RvICsgMTNdOwogIGlmICghZHN0X21vbikgewogICAgaWYgKHRjcF9mbGFncyAmIDB4MDUp
IHsgLyogRklOIG9yIFJTVCAqLwogICAgICBGbG93S2V5IHJmazsgcmZrLnNfaXAgPSBkX2lwOyBy
Zmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7IHJmay5kX2lwID0gc19pcDsgcmZrLmRwb3J0ID0g
KHVpbnQxNl90KXNwb3J0OwogICAgICBmbG93cy5lcmFzZShyZmspOwogICAgfQogICAgcmV0dXJu
IGZhbHNlOwogIH0KCiAgRmxvd0tleSBmazsKICBmay5zX2lwID0gc19pcDsgZmsuc3BvcnQgPSAo
dWludDE2X3Qpc3BvcnQ7IGZrLmRfaXAgPSBkX2lwOyBmay5kcG9ydCA9ICh1aW50MTZfdClkcG9y
dDsKICBpZiAodGNwX2ZsYWdzICYgMHgwNSkgeyAvKiBGSU4gb3IgUlNUICovCiAgICBmbG93cy5l
cmFzZShmayk7CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIGlmIChmbG93cy5maW5kKGZrKSA9PSBm
bG93cy5lbmQoKSAmJiBmbG93cy5zaXplKCkgPj0gTUFYX0ZMT1dTKSB7CiAgICBmbG93cy5lcmFz
ZShmbG93cy5iZWdpbigpKTsKICB9CiAgRmxvdyAmZmwgPSBmbG93c1tma107IGZsLnRvdWNoZWQg
PSBub3c7CiAgaWYgKGZsLmF3YWl0aW5nX2JvZHkpIHsKICAgIHNpemVfdCByZW1haW5pbmcgPSBm
bC5ib2R5X2dvYWwgPiBmbC5idWYuc2l6ZSgpID8gZmwuYm9keV9nb2FsIC0gZmwuYnVmLnNpemUo
KSA6IDA7CiAgICBpZiAocmVtYWluaW5nKSBmbC5idWYuYXBwZW5kKHBheWxvYWQsIHBsZW4gPCBy
ZW1haW5pbmcgPyBwbGVuIDogcmVtYWluaW5nKTsKICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0g
ZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLmJ1Zik7CiAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkg
fHwgZmwuYnVmLnNpemUoKSA+PSBmbC5ib2R5X2dvYWwpIHsKICAgICAgRXZlbnQgZXZlbnQgPSBm
bC5ldmVudDsKICAgICAgaWYgKCF1c2VybmFtZS5lbXB0eSgpKSB7IGV2ZW50LnVzZXIgPSB1c2Vy
bmFtZTsgZXZlbnQuc2NoZW1lID0gIndzc2UiOyB9CiAgICAgIGZsb3dzLmVyYXNlKGZrKTsKICAg
ICAgcXVldWVfcmVxdWVzdChldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5n
KTsKICAgIH0KICAgIHJldHVybiB0cnVlOwogIH0KICBmbC5idWYuYXBwZW5kKHBheWxvYWQsIHBs
ZW4pOwogIGlmIChmbC5idWYuc2l6ZSgpID4gTUFYX0hFQURFUikgeyBmbG93cy5lcmFzZShmayk7
IHJldHVybiBmYWxzZTsgfQogIHdoaWxlICh0cnVlKSB7CiAgICBzaXplX3Qgc3RhcnQgPSBmaW5k
X2h0dHBfc3RhcnQoZmwuYnVmKTsKICAgIGlmIChzdGFydCA9PSBzdGQ6OnN0cmluZzo6bnBvcykg
eyBmbC5idWYuY2xlYXIoKTsgYnJlYWs7IH0KICAgIGlmIChzdGFydCA+IDApIGZsLmJ1Zi5lcmFz
ZSgwLCBzdGFydCk7CiAgICBzaXplX3QgZW5kID0gZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAg
ICBpZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAgIEV2ZW50IGU7IFJlcXVl
c3RNZXRhIG1ldGE7IGUudHMgPSBub3c7IGUuaG9zdCA9IG5vZGU7IGUuc2VydmljZSA9ICJwb3J0
OiIgKyBudW0oZHBvcnQpOyBlLmNhbGxlciA9IGlwX3RvX3N0cihzX2lwKTsgZS5jYWxsZXJfcG9y
dCA9IHNwb3J0OyBlLmRzdF9pcCA9IGlwX3RvX3N0cihkX2lwKTsgZS5kc3RfcG9ydCA9IGRwb3J0
OyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZCkoZW5kICsgNCk7CiAgICBpZiAoIXBhcnNlX3JlcXVl
c3QoZmwuYnVmLmRhdGEoKSwgZW5kLCAmZSwgJm1ldGEpKSB7IGZsLmJ1Zi5lcmFzZSgwLCBlbmQg
KyA0KTsgY29udGludWU7IH0KICAgIGZsLmJ1Zi5lcmFzZSgwLCBlbmQgKyA0KTsKICAgIGlmIChl
LnVzZXIgPT0gIi1hbm9ueW1vdXMtIiAmJiBnX3dzc2VfYm9keV9ieXRlcyAmJgogICAgICAgIGlz
X3NvYXBfY29udGVudF90eXBlKG1ldGEuY29udGVudF90eXBlKSAmJiBtZXRhLmhhc19jb250ZW50
X2xlbmd0aCAmJgogICAgICAgIG1ldGEuY29udGVudF9sZW5ndGggPiAwICYmCiAgICAgICAgbG93
ZXIobWV0YS50cmFuc2Zlcl9lbmNvZGluZykuZmluZCgiY2h1bmtlZCIpID09IHN0ZDo6c3RyaW5n
OjpucG9zICYmCiAgICAgICAgYWN0aXZlX3dzc2VfZmxvd3MoZmxvd3MpIDwgTUFYX1dTU0VfQk9E
WV9GTE9XUykgewogICAgICBmbC5ldmVudCA9IGU7CiAgICAgIGZsLmF3YWl0aW5nX2JvZHkgPSB0
cnVlOwogICAgICBmbC5ib2R5X2dvYWwgPSBtZXRhLmNvbnRlbnRfbGVuZ3RoIDwgZ193c3NlX2Jv
ZHlfYnl0ZXMgPyBtZXRhLmNvbnRlbnRfbGVuZ3RoIDogZ193c3NlX2JvZHlfYnl0ZXM7CiAgICAg
IGlmIChmbC5ib2R5X2dvYWwgPiBNQVhfV1NTRV9CT0RZX0JZVEVTKSBmbC5ib2R5X2dvYWwgPSBN
QVhfV1NTRV9CT0RZX0JZVEVTOwogICAgICBpZiAoZmwuYnVmLnNpemUoKSA+IGZsLmJvZHlfZ29h
bCkgZmwuYnVmLnJlc2l6ZShmbC5ib2R5X2dvYWwpOwogICAgICBzdGQ6OnN0cmluZyB1c2VybmFt
ZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC5idWYpOwogICAgICBpZiAoIXVzZXJuYW1lLmVt
cHR5KCkgfHwgZmwuYnVmLnNpemUoKSA+PSBmbC5ib2R5X2dvYWwpIHsKICAgICAgICBFdmVudCBl
dmVudCA9IGZsLmV2ZW50OwogICAgICAgIGlmICghdXNlcm5hbWUuZW1wdHkoKSkgeyBldmVudC51
c2VyID0gdXNlcm5hbWU7IGV2ZW50LnNjaGVtZSA9ICJ3c3NlIjsgfQogICAgICAgIGZsb3dzLmVy
YXNlKGZrKTsKICAgICAgICBxdWV1ZV9yZXF1ZXN0KGV2ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwg
ZHBvcnQsIHBlbmRpbmcpOwogICAgICB9CiAgICAgIHJldHVybiB0cnVlOwogICAgfQogICAgcXVl
dWVfcmVxdWVzdChlLCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcpOwogIH0KICBp
ZiAoZmwuYnVmLmVtcHR5KCkpIHsKICAgIGZsb3dzLmVyYXNlKGZrKTsKICB9CiAgcmV0dXJuIHRy
dWU7Cn0KCnN0YXRpYyBib29sIGF0dGFjaF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1
bnNpZ25lZD4gJnBvcnRzKSB7CiAgaWYgKHBvcnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBz
dGQ6OnZlY3RvcjxzdHJ1Y3Qgc29ja19maWx0ZXI+IGY7IHNpemVfdCBpOwogIC8qIER1YWwtcGF0
aCBjQlBGOiBQYXRoIEEgKHN0YW5kYXJkIElQdjQpIGFuZCBQYXRoIEIgKDgwMi4xUSBWTEFOIHRh
Z2dlZCBJUHY0KS4gKi8KICB1bnNpZ25lZCBOID0gKHVuc2lnbmVkKXBvcnRzLnNpemUoKTsKICB1
bnNpZ25lZCByZWplY3QgPSAxMSArIE4gKiA4OwogIHVuc2lnbmVkIGFjY2VwdCA9IHJlamVjdCAr
IDE7CiAgc3RydWN0IHNvY2tfZmlsdGVyIHg7CiNkZWZpbmUgQUREKEMsSixULEspIGRvIHsgeC5j
b2RlPShDKTsgeC5qdD0oSik7IHguamY9KFQpOyB4Lms9KEspOyBmLnB1c2hfYmFjayh4KTsgfSB3
aGlsZSgwKQogIC8qIFswXSBMb2FkIEV0aGVyVHlwZSBhdCBvZmZzZXQgMTIgKi8KICBBREQoQlBG
X0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAsIDEyKTsKICAvKiBbMV0gSWYgc3RhbmRhcmQgSVB2NCAo
MHgwODAwKSwganVtcCBvdmVyIFBhdGggQiAoNiArIDQqTiBpbnN0cnVjdGlvbnMpIHRvIFBhdGgg
QSAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssICh1bnNpZ25lZCkoNiArIDQgKiBOKSwg
MCwgRVRIX1BfSVBfSE9TVCk7CgogIC8qIC0tLSBQYXRoIEI6IDgwMi4xUSBWTEFOIChpbmRleCAy
KSAtLS0gKi8KICAvKiBbMl0gSWYgbm90IDgwMi4xUSAoMHg4MTAwKSwgcmVqZWN0ICovCiAgQURE
KEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQp
Zi5zaXplKCkgLSAxKSwgRVRIX1BfODAyMVFfSE9TVCk7CiAgLyogWzNdIExvYWQgZW5jYXBzdWxh
dGVkIEV0aGVyVHlwZSBhdCBvZmZzZXQgMTYgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMs
IDAsIDAsIDE2KTsKICAvKiBbNF0gSWYgZW5jYXBzdWxhdGVkICE9IElQdjQsIHJlamVjdCAqLwog
IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2ln
bmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9QX0lQX0hPU1QpOwogIC8qIFs1XSBMb2FkIElQIHByb3Rv
Y29sIGF0IG9mZnNldCAyNyAoMjMgKyA0KSAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywg
MCwgMCwgMjcpOwogIC8qIFs2XSBJZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxC
UEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAt
IDEpLCBJUFBST1RPX1RDUCk7CiAgLyogWzddIExvYWQgSUhMIGF0IG9mZnNldCAxOCAoMTQgKyA0
KSAqLwogIEFERChCUEZfTERYfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE4KTsKICAvKiBEZXN0aW5h
dGlvbiBwb3J0IGNoZWNrcyBmb3IgVkxBTiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXpl
KCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAyMCk7CiAgICB1
bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBG
X0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9y
dCBjaGVja3MgZm9yIFZMQU4gKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kp
IHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTgpOwogICAgdW5zaWduZWQg
anQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAo
aSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkg
LSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwog
IH0KCiAgLyogLS0tIFBhdGggQTogU3RhbmRhcmQgSVB2NCAtLS0gKi8KICAvKiBMb2FkIElQIHBy
b3RvY29sIGF0IG9mZnNldCAyMyAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwg
MjMpOwogIC8qIElmIG5vdCBUQ1AsIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBG
X0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJP
VE9fVENQKTsKICAvKiBMb2FkIElITCBhdCBvZmZzZXQgMTQgKi8KICBBREQoQlBGX0xEWHxCUEZf
QnxCUEZfTVNILCAwLCAwLCAxNCk7CiAgLyogRGVzdGluYXRpb24gcG9ydCBjaGVja3MgZm9yIHN0
YW5kYXJkIElQdjQgKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAg
IEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTYpOwogICAgdW5zaWduZWQganQgPSBh
Y2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxC
UEZfSywganQsIDAsIHBvcnRzW2ldKTsKICB9CiAgLyogU291cmNlIHBvcnQgY2hlY2tzIGZvciBz
dGFuZGFyZCBJUHY0ICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAg
ICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE0KTsKICAgIHVuc2lnbmVkIGp0ID0g
YWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gKGkgPCBw
b3J0cy5zaXplKCkgLSAxKSA/IDAgOiAocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSk7
CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgamYsIHBvcnRzW2ldKTsKICB9Cgog
IC8qIFtyZWplY3RdIERyb3AgcGFja2V0ICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIDAp
OwogIC8qIFthY2NlcHRdIEFjY2VwdCBwYWNrZXQgKDIwNDggYnl0ZXMpICovCiAgQUREKEJQRl9S
RVR8QlBGX0ssIDAsIDAsIEFDQ0VQVCk7CiN1bmRlZiBBREQKICBpZiAoZi5zaXplKCkgPiA0MDk2
KSByZXR1cm4gZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5sZW4gPSAodW5z
aWduZWQgc2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07CiNpZm5kZWYgU09fQVRU
QUNIX0ZJTFRFUgojZGVmaW5lIFNPX0FUVEFDSF9GSUxURVIgMjYKI2VuZGlmCiAgcmV0dXJuIHNl
dHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX0FUVEFDSF9GSUxURVIsICZwcm9nLCBzaXplb2Yo
cHJvZykpID09IDA7Cn0KCnN0cnVjdCBNbWFwUmluZyB7CiAgdm9pZCAqcmluZzsKICBzaXplX3Qg
cmluZ19zaXplOwogIHVuc2lnbmVkIGJsb2NrX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfbnI7CiAg
dW5zaWduZWQgZnJhbWVfc2l6ZTsKICB1bnNpZ25lZCBmcmFtZV9ucjsKICB1bnNpZ25lZCBmcmFt
ZXNfcGVyX2Jsb2NrOwogIHVuc2lnbmVkIGZyYW1lX2lkeDsKCiAgTW1hcFJpbmcoKSA6IHJpbmco
TUFQX0ZBSUxFRCksIHJpbmdfc2l6ZSgwKSwgYmxvY2tfc2l6ZSg2NTUzNiksIGJsb2NrX25yKDY0
KSwKICAgICAgICAgICAgICAgZnJhbWVfc2l6ZSgyMDQ4KSwgZnJhbWVfbnIoMjA0OCksIGZyYW1l
c19wZXJfYmxvY2soMzIpLCBmcmFtZV9pZHgoMCkge30KfTsKCnN0YXRpYyBib29sIHNldHVwX21t
YXBfcmluZyhpbnQgZmQsIE1tYXBSaW5nICZtcikgewogIGludCB2ZXIgPSBUUEFDS0VUX1YyOwog
IGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfVkVSU0lPTiwgJnZlciwgc2l6
ZW9mKHZlcikpIDwgMCkgewogICAgcmV0dXJuIGZhbHNlOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9y
ZXEgcmVxOwogIG1lbXNldCgmcmVxLCAwLCBzaXplb2YocmVxKSk7CiAgcmVxLnRwX2Jsb2NrX3Np
emUgPSA2NTUzNjsKICByZXEudHBfYmxvY2tfbnIgPSA2NDsgICAgICAgLyogNE1CIHNoYXJlZCBt
ZW1vcnkgcmluZyBidWZmZXIgKi8KICByZXEudHBfZnJhbWVfc2l6ZSA9IDIwNDg7ICAgLyogMktC
IHBlciBmcmFtZSAqLwogIHJlcS50cF9mcmFtZV9uciA9IChyZXEudHBfYmxvY2tfc2l6ZSAqIHJl
cS50cF9ibG9ja19ucikgLyByZXEudHBfZnJhbWVfc2l6ZTsgLyogMjA0OCBmcmFtZXMgKi8KCiAg
aWYgKHNldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9SWF9SSU5HLCAmcmVxLCBzaXpl
b2YocmVxKSkgPCAwKSB7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIG1yLnJpbmdfc2l6ZSA9IChz
aXplX3QpcmVxLnRwX2Jsb2NrX3NpemUgKiByZXEudHBfYmxvY2tfbnI7CiAgbXIuYmxvY2tfc2l6
ZSA9IHJlcS50cF9ibG9ja19zaXplOwogIG1yLmJsb2NrX25yID0gcmVxLnRwX2Jsb2NrX25yOwog
IG1yLmZyYW1lX3NpemUgPSByZXEudHBfZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9uciA9IHJlcS50
cF9mcmFtZV9ucjsKICBtci5mcmFtZXNfcGVyX2Jsb2NrID0gcmVxLnRwX2Jsb2NrX3NpemUgLyBy
ZXEudHBfZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9pZHggPSAwOwoKICBtci5yaW5nID0gbW1hcChO
VUxMLCBtci5yaW5nX3NpemUsIFBST1RfUkVBRCB8IFBST1RfV1JJVEUsIE1BUF9TSEFSRUQsIGZk
LCAwKTsKICBpZiAobXIucmluZyA9PSBNQVBfRkFJTEVEKSB7CiAgICBtci5yaW5nX3NpemUgPSAw
OwogICAgcmV0dXJuIGZhbHNlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGludCBydW5f
Zml4dHVyZSgpIHsKICBzdGQ6OnN0cmluZyByZXEgPSAiR0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAv
MS4xXHJcbkhvc3Q6IGFwaS5sb2NhbFxyXG5BdXRob3JpemF0aW9uOiBCYXNpYyBZV3hwWTJVNmMy
VmpjbVYwXHJcblRyYWNlcGFyZW50OiAwMC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2Rl
Zi0wMTIzNDU2Nzg5YWJjZGVmLTAxXHJcblxyXG4iOwogIEV2ZW50IGU7IFJlcXVlc3RNZXRhIG1l
dGE7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAiY3BwLW5vZGUiOyBlLnNlcnZpY2UgPSAi
cG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjkiOyBlLmNhbGxlcl9wb3J0ID0gNTEwMDA7
IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9ydCA9IDgwODA7IGUucmVxX2J5dGVzID0g
KHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVlc3QocmVxLmRhdGEoKSwgcmVxLnNpemUo
KSAtIDQsICZlLCAmbWV0YSk7IGUuc3RhdHVzID0gMjAwOyBlLmhhc19zdGF0dXMgPSB0cnVlOyBl
LmR1cmF0aW9uX21zID0gMzsgZS5oYXNfZHVyYXRpb24gPSB0cnVlOyBlLnJlc3BfYnl0ZXMgPSA0
MjsgZS5oYXNfcmVzcCA9IHRydWU7IGVtaXRfZXZlbnQoZSk7IHJldHVybiAwOwp9CgpzdGF0aWMg
aW50IHJ1bl93c3NlX2ZpeHR1cmUoKSB7CiAgY29uc3QgY2hhciAqbmFtZXNwYWNlc1tdID0gewog
ICAgImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxL29hc2lzLTIwMDQwMS13
c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29h
cC5vcmcvd3MvMjAwMi8wNy9zZWNleHQiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3Jn
L3dzLzIwMDIvMTIvc2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8y
MDAzLzA2L3NlY2V4dCIKICB9OwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNDsgKytpKSB7CiAg
ICBzdGQ6OnN0cmluZyBib2R5ID0gIjxzOkVudmVsb3BlIHhtbG5zOnM9J3Vybjpzb2FwJyB4bWxu
czp3PSciICsgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1tpXSkgKwogICAgICAiJz48czpIZWFkZXI+
PHc6VXNlcm5hbWVUb2tlbj48dzpVc2VybmFtZT5uYXRpdmUuZml4dHVyZTwvdzpVc2VybmFtZT4i
CiAgICAgICI8dzpQYXNzd29yZD5TRU5TSVRJVkVfUEFTU1dPUkQ8L3c6UGFzc3dvcmQ+PC93OlVz
ZXJuYW1lVG9rZW4+PC9zOkhlYWRlcj4iOwogICAgc3RkOjpzdHJpbmcgdXNlciA9IGV4dHJhY3Rf
d3NzZV91c2VybmFtZShib2R5KTsKICAgIGlmICh1c2VyICE9ICJuYXRpdmUuZml4dHVyZSIpIHJl
dHVybiAzOwogICAgc3RkOjpjb3V0IDw8IHVzZXIgPDwgIlxuIjsKICB9CiAgc3RkOjpzdHJpbmcg
bWFsaWNpb3VzID0gIjwhRE9DVFlQRSB4IFs8IUVOVElUWSBwdyAnc2VjcmV0Jz5dPjx3OlVzZXJu
YW1lVG9rZW4geG1sbnM6dz0nIiArCiAgICBzdGQ6OnN0cmluZyhuYW1lc3BhY2VzWzBdKSArICIn
Pjx3OlVzZXJuYW1lPiZwdzs8L3c6VXNlcm5hbWU+PC93OlVzZXJuYW1lVG9rZW4+IjsKICBpZiAo
IWV4dHJhY3Rfd3NzZV91c2VybmFtZShtYWxpY2lvdXMpLmVtcHR5KCkpIHJldHVybiA0OwogIHN0
ZDo6c3RyaW5nIHdyb25nX25zID0gIjx3OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0ndXJuOm5vdC13
c3NlJz48dzpVc2VybmFtZT53cm9uZzwvdzpVc2VybmFtZT48L3c6VXNlcm5hbWVUb2tlbj4iOwog
IGlmICghZXh0cmFjdF93c3NlX3VzZXJuYW1lKHdyb25nX25zKS5lbXB0eSgpKSByZXR1cm4gNTsK
ICBzdGQ6OnN0cmluZyB1bm5hbWVzcGFjZWQgPSAiPFVzZXJuYW1lVG9rZW4+PFVzZXJuYW1lPndy
b25nPC9Vc2VybmFtZT48L1VzZXJuYW1lVG9rZW4+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91c2Vy
bmFtZSh1bm5hbWVzcGFjZWQpLmVtcHR5KCkpIHJldHVybiA2OwogIHN0ZDo6c3RyaW5nIGVzY2Fw
ZWQgPSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSciICsgc3RkOjpzdHJpbmcobmFtZXNwYWNl
c1swXSkgKwogICAgIic+PHc6VXNlcm5hbWU+bmF0aXZlJmFtcDtmaXh0dXJlPC93OlVzZXJuYW1l
PiI7CiAgaWYgKGV4dHJhY3Rfd3NzZV91c2VybmFtZShlc2NhcGVkKSAhPSAibmF0aXZlJmZpeHR1
cmUiKSByZXR1cm4gNzsKICBzdGQ6OnN0cmluZyB0b29fbG9uZyA9ICI8dzpVc2VybmFtZVRva2Vu
IHhtbG5zOnc9JyIgKyBzdGQ6OnN0cmluZyhuYW1lc3BhY2VzWzBdKSArCiAgICAiJz48dzpVc2Vy
bmFtZT4iICsgc3RkOjpzdHJpbmcoTUFYX1dTU0VfVVNFUk5BTUUgKyAxLCAneCcpICsgIjwvdzpV
c2VybmFtZT4iOwogIGlmICghZXh0cmFjdF93c3NlX3VzZXJuYW1lKHRvb19sb25nKS5lbXB0eSgp
KSByZXR1cm4gODsKICByZXR1cm4gMDsKfQoKc3RhdGljIGJvb2wgcGFyc2Vfd3NzZV9zaXplKGNv
bnN0IGNoYXIgKnZhbHVlLCBzaXplX3QgKnJlc3VsdCkgewogIGlmICghdmFsdWUgfHwgISp2YWx1
ZSkgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBuID0gMDsKICBpZiAoIXBhcnNlX2RlY2ltYWxfc2l6
ZSh2YWx1ZSwgc3RybGVuKHZhbHVlKSwgJm4pIHx8IG4gPiBNQVhfV1NTRV9CT0RZX0JZVEVTKSBy
ZXR1cm4gZmFsc2U7CiAgKnJlc3VsdCA9IG47CiAgcmV0dXJuIHRydWU7Cn0KCmludCBtYWluKGlu
dCBhcmdjLCBjaGFyICoqYXJndikgewogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0s
ICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFz
dHJjbXAoYXJndlsxXSwgIi0td3NzZS1maXh0dXJlIikpIHJldHVybiBydW5fd3NzZV9maXh0dXJl
KCk7CiAgc3RkOjpzdHJpbmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0czsgaW50
IGk7IGludCB3b3JrZXJzID0gMTsKICBzdGQ6OnN0cmluZyBlbmRwb2ludDsKICBjb25zdCBjaGFy
ICp3c3NlX2VudiA9IGdldGVudigiTlRfV1NTRV9CT0RZX0JZVEVTIik7CiAgaWYgKHdzc2VfZW52
ICYmICFwYXJzZV93c3NlX3NpemUod3NzZV9lbnYsICZnX3dzc2VfYm9keV9ieXRlcykpIHsKICAg
IGZwcmludGYoc3RkZXJyLCAid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4uNjU1
MzZcbiIpOyByZXR1cm4gMjsKICB9CiAgZm9yIChpID0gMTsgaSA8IGFyZ2M7ICsraSkgewogICAg
aWYgKCFzdHJjbXAoYXJndltpXSwgIi1pIikgJiYgaSArIDEgPCBhcmdjKSBpZmFjZSA9IGFyZ3Zb
KytpXTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1wIikgJiYgaSArIDEgPCBhcmdj
KSB7CiAgICAgIHdoaWxlIChpICsgMSA8IGFyZ2MgJiYgYXJndltpICsgMV1bMF0gIT0gJy0nKSB7
CiAgICAgICAgY2hhciAqcSA9IHN0cnRvayhhcmd2WysraV0sICIsICIpOwogICAgICAgIHdoaWxl
IChxKSB7IGxvbmcgcCA9IGF0b2wocSk7IGlmICh2YWxpZF9wb3J0KCh1bnNpZ25lZClwKSkgcG9y
dHMucHVzaF9iYWNrKCh1bnNpZ25lZClwKTsgcSA9IHN0cnRvayhOVUxMLCAiLCAiKTsgfQogICAg
ICB9CiAgICB9CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItLWVuZHBvaW50IikgJiYg
aSArIDEgPCBhcmdjKSBlbmRwb2ludCA9IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJjbXAo
YXJndltpXSwgIi0tc3Bvb2wiKSAmJiBpICsgMSA8IGFyZ2MpICsraTsgLyogaWdub3JlZDogMCBk
aXNrIHdyaXRlICovCiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaiIpICYmIGkgKyAx
IDwgYXJnYykgd29ya2VycyA9IGF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAo
YXJndltpXSwgIi0td3NzZS1ib2R5LWJ5dGVzIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIGlm
ICghcGFyc2Vfd3NzZV9zaXplKGFyZ3ZbKytpXSwgJmdfd3NzZV9ib2R5X2J5dGVzKSkgewogICAg
ICAgIGZwcmludGYoc3RkZXJyLCAid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4u
NjU1MzZcbiIpOyByZXR1cm4gMjsKICAgICAgfQogICAgfQogICAgZWxzZSBpZiAoIXN0cmNtcChh
cmd2W2ldLCAiLWgiKSB8fCAhc3RyY21wKGFyZ3ZbaV0sICItLWhlbHAiKSkgewogICAgICBmcHJp
bnRmKHN0ZGVyciwgInVzYWdlOiBudC1zbmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAgcG9ydHNdIFst
LWVuZHBvaW50IFVSTF0gWy1qIHdvcmtlcnNdIFstLXdzc2UtYm9keS1ieXRlcyAwLi42NTUzNl1c
biIpOwogICAgICByZXR1cm4gMDsKICAgIH0KICAgIGVsc2UgeyBmcHJpbnRmKHN0ZGVyciwgInVu
a25vd24gb3IgaW5jb21wbGV0ZSBhcmd1bWVudDogJXNcbiIsIGFyZ3ZbaV0pOyByZXR1cm4gMjsg
fQogIH0KICBpZiAocG9ydHMuZW1wdHkoKSkgeyBwb3J0cy5wdXNoX2JhY2soODApOyBwb3J0cy5w
dXNoX2JhY2soODAwMyk7IHBvcnRzLnB1c2hfYmFjayg4MDA1KTsgcG9ydHMucHVzaF9iYWNrKDgw
MDcpOyBwb3J0cy5wdXNoX2JhY2soODAwOSk7IHBvcnRzLnB1c2hfYmFjayg4MDEwKTsgcG9ydHMu
cHVzaF9iYWNrKDgwMTEpOyB9CiAgKHZvaWQpd29ya2VyczsKCiAgaW5pdF9ybmcoKTsKICBtZW1z
ZXQoZ19tb25pdG9yZWRfcG9ydHMsIDAsIHNpemVvZihnX21vbml0b3JlZF9wb3J0cykpOwogIGZv
ciAoc2l6ZV90IGsgPSAwOyBrIDwgcG9ydHMuc2l6ZSgpOyArK2spIHsKICAgIGlmIChwb3J0c1tr
XSA8IDY1NTM2KSBnX21vbml0b3JlZF9wb3J0c1twb3J0c1trXV0gPSB0cnVlOwogIH0KCiAgY29u
c3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYoIk5UX05PREVfTkFNRSIpOwogIHN0ZDo6c3RyaW5n
IG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVfZW52KSA/IG5vZGVfZW52IDogaG9zdF9uYW1lKCk7
CgogIGdfZW5kcG9pbnQgPSBlbmRwb2ludDsKICBnX3NoaXBfbm9kZSA9IG5vZGU7CgogIGludCBm
ZCA9IHNvY2tldChBRl9QQUNLRVQsIFNPQ0tfUkFXLCBodG9ucygzKSk7CiAgaWYgKGZkIDwgMCkg
eyBwZXJyb3IoIkFGX1BBQ0tFVCIpOyByZXR1cm4gMjsgfQogIGludCByYiA9IDggKiAxMDI0ICog
MTAyNDsKICBzZXRzb2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19SQ1ZCVUYsICZyYiwgc2l6ZW9m
KHJiKSk7CiAgaWYgKCFhdHRhY2hfYnBmKGZkLCBwb3J0cykpIGxvZ21zZygiV0FSTjogQlBGIGF0
dGFjaCBmYWlsZWQ7IGNvbnRpbnVpbmcgdW5maWx0ZXJlZCIpOwoKICBNbWFwUmluZyByaW5nOwog
IGJvb2wgdXNlX21tYXAgPSBzZXR1cF9tbWFwX3JpbmcoZmQsIHJpbmcpOwoKICBzdHJ1Y3Qgc29j
a2FkZHJfbGwgc2E7CiAgbWVtc2V0KCZzYSwgMCwgc2l6ZW9mKHNhKSk7CiAgc2Euc2xsX2ZhbWls
eSA9IEFGX1BBQ0tFVDsKICBzYS5zbGxfcHJvdG9jb2wgPSBodG9ucygzKTsKICBpZiAoIWlmYWNl
LmVtcHR5KCkpIHsKICAgIHNhLnNsbF9pZmluZGV4ID0gKGludClpZl9uYW1ldG9pbmRleChpZmFj
ZS5jX3N0cigpKTsKICAgIGlmICghc2Euc2xsX2lmaW5kZXgpIHsgbG9nbXNnKCJiYWQgaW50ZXJm
YWNlIik7IGNsb3NlKGZkKTsgcmV0dXJuIDI7IH0KICB9CiAgaWYgKGJpbmQoZmQsIChzdHJ1Y3Qg
c29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkpIDwgMCkgeyBwZXJyb3IoImJpbmQiKTsgY2xvc2Uo
ZmQpOyByZXR1cm4gMjsgfQoKICBzaWduYWwoU0lHVEVSTSwgc3RvcF9zaWduYWwpOwogIHNpZ25h
bChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsKICBzZXR2YnVmKHN0ZG91dCwgTlVMTCwgX0lPTEJGLCA2
NTUzNik7CiAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0
S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+IHBlbmRpbmc7CgogIGlmICh1c2VfbW1hcCkgewog
ICAgbG9nbXNnKCJQQUNLRVRfTU1BUCAoVFBBQ0tFVF9WMikgemVyby1jb3B5IHJpbmcgZW5hYmxl
ZCAoNE1CLCAyMDQ4IGZyYW1lcykiKTsKICB9IGVsc2UgewogICAgbG9nbXNnKCJXQVJOOiBQQUNL
RVRfTU1BUCBzZXR1cCBmYWlsZWQsIGZhbGxpbmcgYmFjayB0byBzdGFuZGFyZCBzb2NrZXQgcmVj
diIpOwogIH0KICBpZiAoZ193c3NlX2JvZHlfYnl0ZXMpIHsKICAgIGxvZ21zZygiV1NTRSBVc2Vy
bmFtZVRva2VuIGluc3BlY3Rpb24gZW5hYmxlZCAoYm91bmRlZCB0byAiICsgbnVtYmVyX3N0cmlu
ZyhnX3dzc2VfYm9keV9ieXRlcykgKyAiIGJ5dGVzL3JlcXVlc3QpIik7CiAgfQogIGlmICghZ19l
bmRwb2ludC5lbXB0eSgpKSB7CiAgICBsb2dtc2coInNpbmdsZS1iaW5hcnkgaW4tbWVtb3J5IG1v
ZGU6IHNoaXBwaW5nIGRpcmVjdGx5IHRvICIgKyBnX2VuZHBvaW50ICsgIiAoMCBkaXNrIEkvTyki
KTsKICB9CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKCiAgdGltZV90IGxhc3QgPSB0aW1lKE5VTEwp
LCBsYXN0X2ZsdXNoID0gbGFzdDsKICB1bnNpZ25lZCBjaGFyICpmYWxsYmFja19idWYgPSBOVUxM
OwogIGlmICghdXNlX21tYXApIHsKICAgIGZhbGxiYWNrX2J1ZiA9ICh1bnNpZ25lZCBjaGFyICop
bWFsbG9jKDY1NTM2KTsKICAgIGlmICghZmFsbGJhY2tfYnVmKSB7CiAgICAgIGNsb3NlKGZkKTsK
ICAgICAgbG9nbXNnKCJidWZmZXIgYWxsb2NhdGlvbiBmYWlsZWQiKTsKICAgICAgcmV0dXJuIDI7
CiAgICB9CiAgfQoKICBzdHJ1Y3QgcG9sbGZkIHBmZDsKICBwZmQuZmQgPSBmZDsKICBwZmQuZXZl
bnRzID0gUE9MTElOIHwgUE9MTEVSUjsKICBwZmQucmV2ZW50cyA9IDA7CgogIHdoaWxlIChnX3J1
bm5pbmcpIHsKICAgIGludCByYyA9IHBvbGwoJnBmZCwgMSwgMTAwMCk7CiAgICBpZiAocmMgPCAw
ICYmIGVycm5vID09IEVJTlRSKSB7CiAgICAgIC8qIFNpZ25hbCBoYW5kbGVkLCBsb29wIGNvbmRp
dGlvbiB3aWxsIGNoZWNrIGdfcnVubmluZyAqLwogICAgfSBlbHNlIGlmIChyYyA+PSAwKSB7CiAg
ICAgIGlmICh1c2VfbW1hcCkgewogICAgICAgIC8qIERyYWluIGFsbCByZWFkeSBmcmFtZXMgaW4g
dGhlIHJpbmcgd2l0aG91dCBleHRyYSBzeXNjYWxscyAqLwogICAgICAgIHdoaWxlIChnX3J1bm5p
bmcpIHsKICAgICAgICAgIHVuc2lnbmVkIGJfaWR4ID0gcmluZy5mcmFtZV9pZHggLyByaW5nLmZy
YW1lc19wZXJfYmxvY2s7CiAgICAgICAgICB1bnNpZ25lZCBmX2luX2IgPSByaW5nLmZyYW1lX2lk
eCAlIHJpbmcuZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICAgIHVpbnQ4X3QgKmZyYW1lX3B0ciA9
ICgodWludDhfdCAqKXJpbmcucmluZykgKyAoYl9pZHggKiByaW5nLmJsb2NrX3NpemUpICsgKGZf
aW5fYiAqIHJpbmcuZnJhbWVfc2l6ZSk7CiAgICAgICAgICBzdHJ1Y3QgdHBhY2tldDJfaGRyICpo
ZHIgPSAoc3RydWN0IHRwYWNrZXQyX2hkciAqKWZyYW1lX3B0cjsKCiAgICAgICAgICBpZiAoISho
ZHItPnRwX3N0YXR1cyAmIFRQX1NUQVRVU19VU0VSKSkgewogICAgICAgICAgICBicmVhazsgLyog
Tm8gbW9yZSBrZXJuZWwtcG9wdWxhdGVkIGZyYW1lcyBpbiByaW5nIHJpZ2h0IG5vdyAqLwogICAg
ICAgICAgfQoKICAgICAgICAgIGlmIChoZHItPnRwX3NuYXBsZW4gPiAwKSB7CiAgICAgICAgICAg
IGNvbnN0IHVuc2lnbmVkIGNoYXIgKnBrdCA9ICgoY29uc3QgdW5zaWduZWQgY2hhciAqKWhkcikg
KyBoZHItPnRwX21hYzsKICAgICAgICAgICAgaGFuZGxlX3BhY2tldChwa3QsIChzaXplX3QpaGRy
LT50cF9zbmFwbGVuLCBub2RlLCBwb3J0cywgZmxvd3MsIHBlbmRpbmcpOwogICAgICAgICAgfQoK
ICAgICAgICAgIGhkci0+dHBfc3RhdHVzID0gVFBfU1RBVFVTX0tFUk5FTDsgLyogUmV0dXJuIGZy
YW1lIG93bmVyc2hpcCB0byBrZXJuZWwgKi8KICAgICAgICAgIHJpbmcuZnJhbWVfaWR4ID0gKHJp
bmcuZnJhbWVfaWR4ICsgMSkgJSByaW5nLmZyYW1lX25yOwogICAgICAgIH0KICAgICAgICBpZiAo
Z19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKICAgICAgfSBlbHNlIHsKICAg
ICAgICBpZiAocGZkLnJldmVudHMgJiBQT0xMSU4pIHsKICAgICAgICAgIHNzaXplX3QgbiA9IHJl
Y3YoZmQsIGZhbGxiYWNrX2J1ZiwgNjU1MzYsIDApOwogICAgICAgICAgaWYgKG4gPiAwKSB7CiAg
ICAgICAgICAgIGhhbmRsZV9wYWNrZXQoZmFsbGJhY2tfYnVmLCAoc2l6ZV90KW4sIG5vZGUsIHBv
cnRzLCBmbG93cywgcGVuZGluZyk7CiAgICAgICAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkp
IHN0ZDo6Y291dC5mbHVzaCgpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfQogICAgfQoK
ICAgIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAtIGxhc3QgPj0gMSkgewog
ICAgICBzd2VlcChmbG93cywgcGVuZGluZywgbm93KTsKICAgICAgaWYgKGdfZW5kcG9pbnQuZW1w
dHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgIGxhc3QgPSBub3c7CiAgICB9CgogICAgaWYg
KCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgICAgaWYgKG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxV
U0hfU0VDIHx8IGdfc2hpcF9idWYuc2l6ZSgpID49IE1BWF9CQVRDSCkgewogICAgICAgIGlmICgh
Z19zaGlwX2J1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMoZ19lbmRwb2ludCwgZ19zaGlwX25vZGUs
ICZnX3NoaXBfYnVmLCB0cnVlKTsKICAgICAgICBsYXN0X2ZsdXNoID0gbm93OwogICAgICB9CiAg
ICB9CiAgfQoKICAvKiBBIHJlc3BvbnNlIGlzIG9wdGlvbmFsIGVucmljaG1lbnQuIFByZXNlcnZl
IHJlcXVlc3RzIHN0aWxsIGF3YWl0aW5nIGEKICAgKiByZXNwb25zZSB3aGVuIFNJR1RFUk0vcmVz
dGFydCBlbmRzIGNhcHR1cmUuICovCiAgZmx1c2hfYWxsX3BlbmRpbmcocGVuZGluZyk7CiAgaWYg
KGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CgogIGlmICghZ19lbmRwb2lu
dC5lbXB0eSgpICYmICFnX3NoaXBfYnVmLmVtcHR5KCkpIHsKICAgIHNlbmRfYmF0Y2hlcyhnX2Vu
ZHBvaW50LCBnX3NoaXBfbm9kZSwgJmdfc2hpcF9idWYsIHRydWUpOwogIH0KCiAgaWYgKHVzZV9t
bWFwICYmIHJpbmcucmluZyAhPSBNQVBfRkFJTEVEKSB7CiAgICBtdW5tYXAocmluZy5yaW5nLCBy
aW5nLnJpbmdfc2l6ZSk7CiAgfQogIGlmIChmYWxsYmFja19idWYpIGZyZWUoZmFsbGJhY2tfYnVm
KTsKICBjbG9zZShmZCk7CiAgbG9nbXNnKCJzdG9wcGVkIik7CiAgcmV0dXJuIDA7Cn0K
#__END_CPP__
#__CPP_MAKE_B64__
IyBHQ0MgNC40IC8gQ2VudE9TIDYgY29tcGF0aWJsZTogQysrMDMsIGdudSsrMDMgb3IgZ251Kys5
OC4KQ1hYID89IGcrKwpDWFhTVEQgPz0gJChzaGVsbCAkKENYWCkgLXN0ZD1nbnUrKzAzIC14IGMr
KyAtRSAvZGV2L251bGwgPi9kZXYvbnVsbCAyPiYxICYmIGVjaG8gLXN0ZD1nbnUrKzAzIHx8IGVj
aG8gLXN0ZD1nbnUrKzk4KQpDWFhGTEFHUyA/PSAtTzIgLVdhbGwgLVdleHRyYSAkKENYWFNURCkK
Ci5QSE9OWTogYWxsIGNwcCBjcHAtc2hpcCBjcHAtZGVidWcgZml4dHVyZSBwY2FwLWZpeHR1cmUg
Y2xlYW4KCmFsbDogY3BwIGNwcC1zaGlwCgpjcHA6CgkkKENYWCkgJChDWFhGTEFHUykgbnQtc25p
ZmYtY3BwLmNwcCAtbyBudC1zbmlmZi1jcHAKCmNwcC1zaGlwOgoJJChDWFgpICQoQ1hYRkxBR1Mp
IG50LXNoaXAtY3BwLmNwcCAtbyBudC1zaGlwLWNwcAoKY3BwLWRlYnVnOgoJJChDWFgpIC1PMCAt
ZyAtV2FsbCAtV2V4dHJhIC1zdGQ9Z251KyswMyBudC1zbmlmZi1jcHAuY3BwIC1vIG50LXNuaWZm
LWNwcC1kZWJ1ZwoKZml4dHVyZTogY3BwCgkuL250LXNuaWZmLWNwcCAtLWZpeHR1cmUKCnBjYXAt
Zml4dHVyZTogcGNhcF90ZXN0X2NwcAoKcGNhcF90ZXN0X2NwcDogcGNhcF90ZXN0X2NwcC5jcHAg
bnQtc25pZmYtY3BwLmNwcAoJJChDWFgpICQoQ1hYRkxBR1MpIHBjYXBfdGVzdF9jcHAuY3BwIC1v
IHBjYXBfdGVzdF9jcHAKCmNsZWFuOgoJcm0gLWYgbnQtc25pZmYtY3BwIG50LXNuaWZmLWNwcC1k
ZWJ1ZyBudC1zaGlwLWNwcCBwY2FwX3Rlc3RfY3BwCg==
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
#__RESOURCE_GUARD_B64__
IyEvYmluL3NoCiMgSGFyZCBydW50aW1lIHNhZmV0eSBib3VuZGFyeSBmb3IgdGhlIGxlZ2FjeSBh
Z2VudCBwcm9jZXNzIHRyZWUuCiMgQ1BVIGFmZmluaXR5IGFuZCBhbGwgbGltaXRzIGFyZSBpbmhl
cml0ZWQgYnkgZXZlcnkgdGhyZWFkIGFuZCBjaGlsZC4Kc2V0IC11CgpDUFVfQ09SRT0kezE6LX0K
WyAkIyAtZ3QgMCBdICYmIHNoaWZ0CgpjYXNlICIkQ1BVX0NPUkUiIGluCiAgICAnJ3wqWyEwLTld
KikKICAgICAgICBlY2hvICJudC1yZXNvdXJjZS1ndWFyZDogaW52YWxpZCBDUFUgY29yZTogJENQ
VV9DT1JFIiA+JjIKICAgICAgICBleGl0IDcwCiAgICAgICAgOzsKZXNhYwpbICQjIC1ndCAwIF0g
fHwgewogICAgZWNobyAibnQtcmVzb3VyY2UtZ3VhcmQ6IGNvbW1hbmQgcmVxdWlyZWQiID4mMgog
ICAgZXhpdCA3MAp9CmNvbW1hbmQgLXYgdGFza3NldCA+L2Rldi9udWxsIDI+JjEgfHwgewogICAg
ZWNobyAibnQtcmVzb3VyY2UtZ3VhcmQ6IHRhc2tzZXQgaXMgcmVxdWlyZWQiID4mMgogICAgZXhp
dCA3MAp9CgojIDI1NiBNaUIgYWRkcmVzcyBzcGFjZSwgMSwwMjQgZGVzY3JpcHRvcnMsIDMyIE1p
QiBwZXIgcmVndWxhciBvdXRwdXQgZmlsZSwKIyBhbmQgbm8gY29yZSBkdW1wcy4gVGhlIHByb2Nl
c3MgbGltaXQgZXhpc3RzIGluIGJhc2ggb24gRUw2LCBidXQgbm90IGluIGV2ZXJ5CiMgUE9TSVgg
c2hlbGwsIHNvIGFwcGx5IGl0IG9ubHkgd2hlbiB0aGUgdGFyZ2V0IC9iaW4vc2ggc3VwcG9ydHMg
aXQuCnVsaW1pdCAtUyAtYyAwICYmIHVsaW1pdCAtSCAtYyAwIHx8IGV4aXQgNzAKdWxpbWl0IC1T
IC1mIDY1NTM2ICYmIHVsaW1pdCAtSCAtZiA2NTUzNiB8fCBleGl0IDcwCnVsaW1pdCAtUyAtbiAx
MDI0ICYmIHVsaW1pdCAtSCAtbiAxMDI0IHx8IGV4aXQgNzAKdWxpbWl0IC1TIC12IDI2MjE0NCAm
JiB1bGltaXQgLUggLXYgMjYyMTQ0IHx8IGV4aXQgNzAKaWYgKHVsaW1pdCAtdSA+L2Rldi9udWxs
IDI+JjEpOyB0aGVuCiAgICB1bGltaXQgLVMgLXUgNjQgJiYgdWxpbWl0IC1IIC11IDY0IHx8IGV4
aXQgNzAKZmkKCiMgTG93ZXIgc2NoZWR1bGluZyBwcmlvcml0eSB0b28uIHRhc2tzZXQgcHJvdmlk
ZXMgdGhlIGhhcmQgb25lLWxvZ2ljYWwtQ1BVCiMgY2VpbGluZyBmb3IgdGhlIGNvbXBsZXRlIGRl
c2NlbmRhbnQgcHJvY2VzcyB0cmVlLgpleGVjIHRhc2tzZXQgLWMgIiRDUFVfQ09SRSIgbmljZSAt
biAxMCAiJEAiCg==
#__END_RESOURCE_GUARD__
