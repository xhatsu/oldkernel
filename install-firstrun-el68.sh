#!/bin/sh
# install-oldkernel.sh — NetworkTracing legacy installer (CentOS 6.x / 2.6.32)
#
# Installs the pcap-based HTTP/SOAP sniffer + python2.6 shipper as a SysV
# service. NO eBPF, NO systemd, NO kernel modules. Prefers rootless capture
# via file capability (cap_net_raw on a private interpreter copy); fails
# closed rather than running capture as root when this cannot be enforced.
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
for f in nt-sniff.py nt-ship.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh nt-supervise.sh; do
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
        sed -n '/^#__SUPERVISOR_B64__$/,/^#__END_SUPERVISOR__$/p' "$SELF" | sed '1d;$d' | base64 -d > "$WORKDIR/nt-supervise.sh" 2>/dev/null
    fi

    # --- source 3: hub bootstrap server ---------------------------------
    if [ ! -s "$WORKDIR/nt-sniff.py" ] || [ ! -s "$WORKDIR/nt-ship.py" ] || [ ! -s "$WORKDIR/nt-sniff-cpp.cpp" ] || [ ! -s "$WORKDIR/Makefile" ] || [ ! -s "$WORKDIR/nt-resource-guard.sh" ] || [ ! -s "$WORKDIR/nt-supervise.sh" ]; then
        if [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
            HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
            [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
        fi
        [ -n "$KIT_URLS" ] || die "kit files missing, no embedded payload, cannot derive hub URL — pass --hub http://HUB:30105/oldkernel"
        log "first run: fetching kit from $KIT_URLS -> $WORKDIR"
        have curl || have wget || die "neither curl nor wget present and no embedded payload"
        for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh nt-supervise.sh el68-smoke.sh README.md DEBUG-NOTES.md; do
            fetch "$KIT_URLS/$f" "$WORKDIR/$f.new" || die "cannot download $f from $KIT_URLS"
            mv "$WORKDIR/$f.new" "$WORKDIR/$f"
        done
    fi

    chmod 755 "$WORKDIR"/nt-*.py "$WORKDIR"/nt-run-cpp.sh "$WORKDIR"/nt-resource-guard.sh "$WORKDIR"/nt-supervise.sh 2>/dev/null || true
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
for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-control.py" "$PREFIX/nt-supervise.sh"; do
        for p in $(pgrep -f "$pattern" 2>/dev/null || true); do
            [ "$p" = "$$" ] || kill "$p" 2>/dev/null || true
        done
    done
    rm -f "$CONTROL_TOKEN_FILE" /var/run/networktracing-legacy.pid
    rm -rf "$PREFIX" /tmp/ntkit*
    RESIDUE=""
    for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-control.py" "$PREFIX/nt-supervise.sh"; do
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
for pattern in "$PREFIX/nt-sniff.py" "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship.py" "$PREFIX/nt-ship-cpp" "$PREFIX/nt-supervise.sh"; do
    for p in $(pgrep -f "$pattern" 2>/dev/null || true); do
        [ "$p" = "$$" ] || kill -9 "$p" 2>/dev/null || true
    done
done
rm -f "$PREFIX/nt-sniff-cpp" "$PREFIX/nt-ship-cpp"

mkdir -p "$PREFIX" || die "mkdir $PREFIX failed"
# Python control client is bundled for CentOS 6.x nodes.
for f in nt-sniff.py nt-ship.py nt_control.py nt-control.py nt-ship-cpp.cpp nt-sniff-cpp.cpp Makefile nt-run-cpp.sh nt-resource-guard.sh nt-supervise.sh; do
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
cp "$SCRIPT_DIR"/nt-supervise.sh "$PREFIX/"
if [ -f "$SCRIPT_DIR/install-oldkernel.sh" ]; then
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install-oldkernel.sh"
    cp "$SCRIPT_DIR/install-oldkernel.sh" "$PREFIX/install.sh"
elif [ -n "${SELF:-}" ] && [ -f "$SELF" ]; then
    cp "$SELF" "$PREFIX/install-oldkernel.sh"
    cp "$SELF" "$PREFIX/install.sh"
fi
chmod 755 "$PREFIX"/nt-*.py "$PREFIX"/nt-control.py "$PREFIX"/nt_control.py "$PREFIX"/nt-run-cpp.sh "$PREFIX"/nt-resource-guard.sh "$PREFIX"/nt-supervise.sh "$PREFIX"/install*.sh 2>/dev/null || true

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
           && chmod 750 "$PREFIX/python-capnetraw" 2>/dev/null \
           && setcap cap_net_raw+ep "$PREFIX/python-capnetraw" 2>/dev/null \
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/python-capnetraw -c 'import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()'" >/dev/null 2>&1; then
            SNIFF_AS="$SNIFF_USER"
            log "rootless mode: cap_net_raw on private interpreter, user=$SNIFF_USER"
        else
            rm -f "$PREFIX/python-capnetraw"
            log "WARN: setcap path failed — safe runtime boundary unavailable"
        fi
    fi
else
    log "WARN: setcap/useradd absent"
fi

if [ "$CAPTURE_MODE" != "cpp" ] && [ "$SNIFF_AS" = root ]; then
    die "safe rootless Python capture unavailable; refusing to run the agent as root"
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
touch "$PREFIX/ship.log"
chmod 644 "$PREFIX/sniff.log"
chmod 644 "$PREFIX/ship.log"
if [ "$SNIFF_AS" != root ]; then
    chown "$SNIFF_USER" "$PREFIX/sniff.log" 2>/dev/null || true
    chown "$SNIFF_USER" "$PREFIX/ship.log" 2>/dev/null || true
fi

# sniffer stdout must FEED the shipper's stdin; starting them separately
# leaves events stranded in sniff.log (proven on el6). Build one pipeline.
if [ "$CAPTURE_MODE" = "cpp" ]; then
    CXXSTD=$(g++ -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra $CXXSTD nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra $CXXSTD nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
    if [ -f "$PREFIX/nt-sniff-cpp" ] && have setcap && have useradd; then
        chown "$SNIFF_USER" "$PREFIX/nt-sniff-cpp" 2>/dev/null || true
        chmod 750 "$PREFIX/nt-sniff-cpp" 2>/dev/null || true
        if setcap cap_net_raw+ep "$PREFIX/nt-sniff-cpp" 2>/dev/null \
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/nt-sniff-cpp --capability-probe" >/dev/null 2>&1; then
            SNIFF_AS="$SNIFF_USER"
            log "rootless mode: cap_net_raw on native C++ binary, user=$SNIFF_USER"
        else
            SNIFF_AS=root
            log "WARN: rootless capability execution failed — safe runtime boundary unavailable"
        fi
    fi
    [ "$SNIFF_AS" != root ] \
        || die "safe rootless C++ capture unavailable; refusing to run the agent as root"
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
    SHIP_CMD="exec su -s /bin/sh $SNIFF_AS -c 'exec python -u $PREFIX/nt-ship.py --endpoint $ENDPOINT'"
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
        nohup "\$PREFIX/nt-resource-guard.sh" "\$CPU_CORE" \
            "\$PREFIX/nt-supervise.sh" "\$PREFIX/nt-resource-guard.sh" "\$CPU_CORE" \
            sh -c "$RUN_CMD" >/dev/null 2>&1 &
        supervisor_pid=\$!
        echo "\$supervisor_pid" > "\$PIDFILE"
        sleep 1
        if ! pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null; then
            kill "\$supervisor_pid" 2>/dev/null || true
            rm -f "\$PIDFILE"
            echo "sniffer failed safe startup checks"
            exit 1
        fi
        echo "networktracing-legacy started"
        ;;
    reload)
        "\$0" restart
        ;;
    stop)
        if [ -s "\$PIDFILE" ]; then
            supervisor=$(cat "\$PIDFILE" 2>/dev/null || true)
            case "\$supervisor" in
                ''|*[!0-9]*) : ;;
                *)
                    kill "\$supervisor" 2>/dev/null || true
                    _sw=0
                    while [ \$_sw -lt 5 ] && kill -0 "\$supervisor" 2>/dev/null; do
                        sleep 1
                        _sw=$((_sw + 1))
                    done
                    kill -0 "\$supervisor" 2>/dev/null && kill -9 "\$supervisor" 2>/dev/null || true
                    ;;
            esac
        fi
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
log "Safety: rootless, cpu=$CPU_CORE (one logical core/nice 19), memory=256MiB, fds=1024, output-file=32MiB, crash circuit=5"
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
Im50LXNuaWZmOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCmRlZiBkcm9w
X2NhcHR1cmVfY2FwYWJpbGl0aWVzKCk6CiAgICAiIiJJcnJldmVyc2libHkgY2xlYXIgQ0FQX05F
VF9SQVcgYWZ0ZXIgdGhlIHBhY2tldCBzb2NrZXQgaXMgcmVhZHkuIiIiCiAgICB0cnk6CiAgICAg
ICAgaW1wb3J0IGN0eXBlcwogICAgICAgIGxpYmNhcCA9IGN0eXBlcy5DRExMKCJsaWJjYXAuc28u
MiIpCiAgICAgICAgbGliY2FwLmNhcF9pbml0LnJlc3R5cGUgPSBjdHlwZXMuY192b2lkX3AKICAg
ICAgICBlbXB0eSA9IGxpYmNhcC5jYXBfaW5pdCgpCiAgICAgICAgaWYgbm90IGVtcHR5OgogICAg
ICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJldHVybiBsaWJj
YXAuY2FwX3NldF9wcm9jKGN0eXBlcy5jX3ZvaWRfcChlbXB0eSkpID09IDAKICAgICAgICBmaW5h
bGx5OgogICAgICAgICAgICBsaWJjYXAuY2FwX2ZyZWUoY3R5cGVzLmNfdm9pZF9wKGVtcHR5KSkK
ICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKIyAtLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHBl
cmY6IGNCUEYKIyBBdHRhY2ggYSBjbGFzc2ljIEJQRiBwcm9ncmFtIHNvIHRoZSBLRVJORUwgZHJv
cHMgZXZlcnl0aGluZyB0aGF0IGlzIG5vdAojIElQdjQgVENQIHRvIG9yIGZyb20gYSBtb25pdG9y
ZWQgcG9ydC4gUmVxdWVzdCBoZWFkZXJzIGRyaXZlIGV2ZW50cyBhbmQKIyByZXNwb25zZSBoZWFk
ZXJzIGVucmljaCB0aGVtOyB1bnJlbGF0ZWQgdHJhZmZpYyBuZXZlciByZWFjaGVzIHVzZXJzcGFj
ZS4KU09fQVRUQUNIX0ZJTFRFUiA9IDI2CgpkZWYgYnVpbGRfYnBmKHBvcnRzKToKICAgICIiIkNs
YXNzaWMgQlBGOiBldGhlcnR5cGU9PUlQICYmIHByb3RvPT1UQ1AgJiYgZHBvcnQgaW4gcG9ydHMu
CiAgICBSZXR1cm5zIChmcHJvZ19zdHJ1Y3QsIGZpbHRlcl9hcnJheSkgZm9yIHRoZSBsaWJjIHNl
dHNvY2tvcHQgY2FsbCwKICAgIG9yIE5vbmUgb24gZmFpbHVyZS4gTk9URTogc29ja19mcHJvZyBj
YXJyaWVzIGEgUE9JTlRFUiB0byB0aGUgZmlsdGVyCiAgICBhcnJheSwgc28gaXQgbXVzdCBzdGF5
IGFsaXZlIHVudGlsIHRoZSBzeXNjYWxsIOKAlCBweXRob24ncwogICAgc29ja2V0LnNldHNvY2tv
cHQoc3RyKSBmbGF0dGVuaW5nIGNhbm5vdCBwcmVzZXJ2ZSBpdC4iIiIKCiAgICBMREhfQUJTID0g
MHgyOCAgICMgbGQgW2tdOmgKICAgIExEQl9BQlMgPSAweDMwICAgIyBsZCBba106YgogICAgSkVR
X0sgPSAweDE1ICAgICAjIGplcSBrCiAgICBMRFhfTVNIID0gMHhCMSAgICMgeCA9IDQqKFtrXSYw
eGYpICAoaWhsIGJ5dGVzKQogICAgTERIX0lORCA9IDB4NDggICAjIGxkIFt4K2tdOmgKICAgIFJF
VF9LID0gMHgwNgoKICAgICMgUFJPVkVOIGRwb3J0IGJsb2NrICsgc3BvcnQgYmxvY2sgYXQgWCsx
NCAoY2FsaWJyYXRlZCBFTVBJUklDQUxMWSBvbgogICAgIyBhIGxpdmUga2VybmVsOiBrPTE0IGRl
bGl2ZXJzIHJlc3BvbnNlIHBhY2tldHM7IHRoZSBjb3JyZWxhdGlvbiB0aGVuCiAgICAjIHlpZWxk
cyBzdGF0dXMvZHVyYXRpb25fbXMvcmVzcF9ieXRlcyBlbmQtdG8tZW5kKS4gUmVxdWlyZXMgdGhl
IDFzCiAgICAjIHJlY3YgdGltZW91dCBpbiBtYWluKCkg4oCUIGJsb2NraW5nIHJlY3YgKyBCUEYg
c3RhcnZlcyBhZnRlciBvbmUgcGt0LgogICAgc2sgPSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NO
SUZGX1NQT1JUX0siLCAiMTQiKSkKICAgIHBzID0gc29ydGVkKHBvcnRzKQogICAgbiA9IGxlbihw
cykKICAgIHJldF9yZWogPSA1ICsgKDQgaWYgc2sgZWxzZSAyKSAqIG4KICAgIHJldF9hY2MgPSBy
ZXRfcmVqICsgMQogICAgcHJvZyA9IFtdCiAgICBwcm9nLmFwcGVuZCgoTERIX0FCUywgMCwgMCwg
MTIpKSAgICAgICAgICAgICAgICAgIyBldGhlcnR5cGUgPT0gSVA/CiAgICBwcm9nLmFwcGVuZCgo
SkVRX0ssIDAsIHJldF9yZWogLSAyLCAweDA4MDApKQogICAgcHJvZy5hcHBlbmQoKExEQl9BQlMs
IDAsIDAsIDIzKSkgICAgICAgICAgICAgICAgICMgcHJvdG8gPT0gVENQPwogICAgcHJvZy5hcHBl
bmQoKEpFUV9LLCAwLCByZXRfcmVqIC0gNCwgNikpCiAgICBwcm9nLmFwcGVuZCgoTERYX01TSCwg
MCwgMCwgMTQpKSAgICAgICAgICAgICAgICAgIyBYID0gaWhsKjQKICAgIGZvciBpLCBwIGluIGVu
dW1lcmF0ZShwcyk6ICAgICAgICAgICAgICAgICAgICAgICAjIEE6IGRwb3J0IEAgWCsxNgogICAg
ICAgIHByb2cuYXBwZW5kKChMREhfSU5ELCAwLCAwLCAxNikpCiAgICAgICAganQgPSByZXRfYWNj
IC0gKGxlbihwcm9nKSArIDEpCiAgICAgICAgamYgPSAwIGlmIChpIDwgbiAtIDEgb3Igc2spIGVs
c2UgKHJldF9yZWogLSAobGVuKHByb2cpICsgMSkpCiAgICAgICAgcHJvZy5hcHBlbmQoKEpFUV9L
LCBqdCwgamYsIHApKQogICAgaWYgc2s6ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICMgQjogc3BvcnQgQCBYK3NrCiAgICAgICAgZm9yIGksIHAgaW4gZW51bWVyYXRl
KHBzKToKICAgICAgICAgICAgcHJvZy5hcHBlbmQoKExESF9JTkQsIDAsIDAsIHNrKSkKICAgICAg
ICAgICAganQgPSByZXRfYWNjIC0gKGxlbihwcm9nKSArIDEpCiAgICAgICAgICAgIGpmID0gMCBp
ZiBpIDwgbiAtIDEgZWxzZSAocmV0X3JlaiAtIChsZW4ocHJvZykgKyAxKSkKICAgICAgICAgICAg
cHJvZy5hcHBlbmQoKEpFUV9LLCBqdCwgamYsIHApKQogICAgcHJvZy5hcHBlbmQoKFJFVF9LLCAw
LCAwLCAwKSkgICAgICAgICAgICAgICAgICAgICMgcmVqZWN0CiAgICBwcm9nLmFwcGVuZCgoUkVU
X0ssIDAsIDAsIDB4NDAwMDApKSAgICAgICAgICAgICAgIyBhY2NlcHQKCiAgICB0cnk6CiAgICAg
ICAgaW1wb3J0IGN0eXBlcwoKICAgICAgICBjbGFzcyBTb2NrRmlsdGVyKGN0eXBlcy5TdHJ1Y3R1
cmUpOgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImNvZGUiLCBjdHlwZXMuY191aW50MTYpLCAo
Imp0IiwgY3R5cGVzLmNfdWludDgpLAogICAgICAgICAgICAgICAgICAgICAgICAoImpmIiwgY3R5
cGVzLmNfdWludDgpLCAoImsiLCBjdHlwZXMuY191aW50MzIpXQoKICAgICAgICBjbGFzcyBTb2Nr
RnByb2coY3R5cGVzLlN0cnVjdHVyZSk6CiAgICAgICAgICAgICMgbWlycm9ycyBzdHJ1Y3Qgc29j
a19mcHJvZyB7dTE2IGxlbjsgc29ja19maWx0ZXIgKmZpbHRlcn07CiAgICAgICAgICAgICMgY3R5
cGVzIGFwcGxpZXMgdGhlIHNhbWUgcG9pbnRlciBhbGlnbm1lbnQgYXMgdGhlIGNvbXBpbGVyCiAg
ICAgICAgICAgIF9maWVsZHNfID0gWygibGVuIiwgY3R5cGVzLmNfdWludDE2KSwKICAgICAgICAg
ICAgICAgICAgICAgICAgKCJmaWx0ZXIiLCBjdHlwZXMuUE9JTlRFUihTb2NrRmlsdGVyKSldCgog
ICAgICAgIGFyciA9IChTb2NrRmlsdGVyICogbGVuKHByb2cpKSgpCiAgICAgICAgZm9yIGksIChj
b2RlLCBqdCwgamYsIGspIGluIGVudW1lcmF0ZShwcm9nKToKICAgICAgICAgICAgYXJyW2ldLmNv
ZGUgPSBjb2RlOyBhcnJbaV0uanQgPSBqdAogICAgICAgICAgICBhcnJbaV0uamYgPSBqZjsgYXJy
W2ldLmsgPSBrCiAgICAgICAgcmV0dXJuIFNvY2tGcHJvZyhsZW4ocHJvZyksIGFyciksIGFycgog
ICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBhcHBseV9wZXJm
X29wdHMoc29jaywgcG9ydHMpOgogICAgIiIiQXR0YWNoIHRoZSBtYW5kYXRvcnkga2VybmVsIHBv
cnQgZmlsdGVyIGFuZCB0dW5lIHRoZSByZWNlaXZlIGJ1ZmZlci4iIiIKICAgIGJ1aWx0ID0gYnVp
bGRfYnBmKHBvcnRzKQogICAgZmlsdGVyX29rID0gRmFsc2UKICAgIGlmIGJ1aWx0IGlzIG5vdCBO
b25lOgogICAgICAgIHRyeToKICAgICAgICAgICAgaW1wb3J0IGN0eXBlcwogICAgICAgICAgICBs
aWJjID0gY3R5cGVzLkNETEwoImxpYmMuc28uNiIpCiAgICAgICAgICAgIGZwcm9nLCBhcnIgPSBi
dWlsdCAgICAgICAgICAgICAgICAgICAgICAjIGtlZXAgYXJyIHJlZmVyZW5jZWQhCiAgICAgICAg
ICAgIHJldCA9IGxpYmMuc2V0c29ja29wdChzb2NrLmZpbGVubygpLCBzb2NrZXQuU09MX1NPQ0tF
VCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNPX0FUVEFDSF9GSUxURVIsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuYnlyZWYoZnByb2cpLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLnNpemVvZihmcHJvZykpCiAgICAg
ICAgICAgIGlmIHJldCA9PSAwOgogICAgICAgICAgICAgICAgbG9nKCJrZXJuZWwgQlBGIGZpbHRl
ciBhdHRhY2hlZCAoJWQgbW9uaXRvcmVkIHBvcnRzKSIKICAgICAgICAgICAgICAgICAgICAlIGxl
bihwb3J0cykpCiAgICAgICAgICAgICAgICBmaWx0ZXJfb2sgPSBUcnVlCiAgICAgICAgICAgIGVs
c2U6CiAgICAgICAgICAgICAgICBsb2coIkJQRiBhdHRhY2ggcmVqZWN0ZWQgYnkga2VybmVsIChy
ZXQ9JWQpIiAlIHJldCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAg
IGxvZygiQlBGIGZpbHRlciBhdHRhY2ggZmFpbGVkICglcykiICUgZSkKICAgIGVsc2U6CiAgICAg
ICAgbG9nKCJCUEYgY29uc3RydWN0aW9uIHVuYXZhaWxhYmxlIikKICAgIHRyeToKICAgICAgICB3
YW50ID0gOCAqIDEwMjQgKiAxMDI0CiAgICAgICAgc29jay5zZXRzb2Nrb3B0KHNvY2tldC5TT0xf
U09DS0VULCBzb2NrZXQuU09fUkNWQlVGLCB3YW50KQogICAgICAgIGdvdCA9IHNvY2suZ2V0c29j
a29wdChzb2NrZXQuU09MX1NPQ0tFVCwgc29ja2V0LlNPX1JDVkJVRikKICAgICAgICBsb2coInJj
dmJ1ZjogJWQgYnl0ZXMiICUgZ290KQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAg
IGxvZygiV0FSTjogU09fUkNWQlVGIHJhaXNlIGZhaWxlZDogJXMiICUgZSkKICAgIHJldHVybiBm
aWx0ZXJfb2sKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0gcGVyZjogZmFub3V0ClNPTF9QQUNLRVQgPSAyNjMKUEFDS0VU
X0ZBTk9VVCA9IDE4CgpkZWYgYXBwbHlfZmFub3V0KHNvY2ssIGdyb3VwX2lkKToKICAgICIiIktl
cm5lbCBsb2FkLWJhbGFuY2VzIHBhY2tldHMgYWNyb3NzIGFsbCBzb2NrZXRzIHNoYXJpbmcgdGhl
IGdyb3VwLgogICAgSGFzaGluZyBpcyBwZXItZmxvdy1kaXJlY3Rpb25hbDsgcmVxdWVzdCBkaXJl
Y3Rpb24gYWxvbmUgZHJpdmVzIGV2ZW50CiAgICBlbWlzc2lvbiwgc28gZGlyZWN0aW9uYWwgc3Bs
aXRzIGFyZSBzYWZlLiBSZXR1cm5zIFRydWUgb24gc3VjY2Vzcy4iIiIKICAgIHRyeToKICAgICAg
ICBzb2NrLnNldHNvY2tvcHQoU09MX1BBQ0tFVCwgUEFDS0VUX0ZBTk9VVCwKICAgICAgICAgICAg
ICAgICAgICAgICAgc3RydWN0LnBhY2soIkkiLCBncm91cF9pZCAmIDB4RkZGRikpCiAgICAgICAg
cmV0dXJuIFRydWUKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2coIldBUk46
IFBBQ0tFVF9GQU5PVVQgZmFpbGVkICglcykg4oCUIHNpbmdsZS1wcm9jZXNzIGNhcHR1cmUiICUg
ZSkKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgcGFyc2Vfd3NzZV9ib2R5X2J5dGVzKHZhbHVl
KToKICAgICIiIlZhbGlkYXRlIHRoZSBvcHQtaW4gYm9keSB3aW5kb3cgd2l0aG91dCBhbGxvd2lu
ZyB1bmJvdW5kZWQgYnVmZmVycy4iIiIKICAgIHRyeToKICAgICAgICBzaXplID0gaW50KHZhbHVl
IG9yIDApCiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmFpc2Ug
U3lzdGVtRXhpdCgid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgYW4gaW50ZWdlciIpCiAgICBpZiBz
aXplIDwgMCBvciBzaXplID4gTUFYX1dTU0VfQk9EWV9CWVRFUzoKICAgICAgICByYWlzZSBTeXN0
ZW1FeGl0KCJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi4lZCIgJQogICAgICAg
ICAgICAgICAgICAgICAgICAgTUFYX1dTU0VfQk9EWV9CWVRFUykKICAgIHJldHVybiBzaXplCgoK
ZGVmIHBhcnNlX2FyZ3MoYXJndik6CiAgICBpZmFjZSA9IE5vbmUKICAgIHBvcnRzID0gWzgwLCA4
MDAzLCA4MDA1LCA4MDA3LCA4MDA5LCA4MDEwLCA4MDExXQogICAgdmVyYm9zZSA9IEZhbHNlCiAg
ICB3b3JrZXJzID0gMQogICAgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2Vfd3NzZV9ib2R5X2J5dGVz
KAogICAgICAgIG9zLmVudmlyb24uZ2V0KCJOVF9XU1NFX0JPRFlfQllURVMiLCAiMCIpKQogICAg
aSA9IDAKICAgIHdoaWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFyZ3ZbaV0KICAgICAg
ICBpZiBhID09ICItaSI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAg
ICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1pIHJlcXVpcmVzIGFuIGludGVyZmFjZSIpCiAg
ICAgICAgICAgIGkgKz0gMTsgaWZhY2UgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhID09ICItcCI6
CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAgICAgICAgICAgIHJhaXNl
IFN5c3RlbUV4aXQoIi1wIHJlcXVpcmVzIGEgY29tbWEtc2VwYXJhdGVkIHBvcnQgbGlzdCIpCiAg
ICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBwb3J0cyA9
IFtpbnQoeCkgZm9yIHggaW4gYXJndltpXS5zcGxpdCgiLCIpIGlmIHguc3RyaXAoKV0KICAgICAg
ICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0
KCJpbnZhbGlkIHBvcnQgbGlzdCIpCiAgICAgICAgICAgIGlmIG5vdCBwb3J0cyBvciBhbnkobm90
IHZhbGlkX3BvcnQoeCkgZm9yIHggaW4gcG9ydHMpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lz
dGVtRXhpdCgicG9ydHMgbXVzdCBiZSBpbiByYW5nZSAxLi42NTUzNSIpCiAgICAgICAgZWxpZiBh
ID09ICItaiI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAgICAgICAg
ICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1qIHJlcXVpcmVzIGEgd29ya2VyIGNvdW50IikKICAgICAg
ICAgICAgaSArPSAxCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdvcmtlcnMgPSBt
YXgoMSwgaW50KGFyZ3ZbaV0pKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAg
ICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImludmFsaWQgd29ya2VyIGNvdW50IikKICAgICAg
ICBlbGlmIGEgPT0gIi12IjoKICAgICAgICAgICAgdmVyYm9zZSA9IFRydWUKICAgICAgICBlbGlm
IGEgPT0gIi0td3NzZS1ib2R5LWJ5dGVzIjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFy
Z3YpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLS13c3NlLWJvZHktYnl0ZXMg
cmVxdWlyZXMgYSBieXRlIGNvdW50IikKICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIHdz
c2VfYm9keV9ieXRlcyA9IHBhcnNlX3dzc2VfYm9keV9ieXRlcyhhcmd2W2ldKQogICAgICAgIGVs
aWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFp
c2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0dXJuIGlmYWNl
LCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXMKCgpjbGFzcyBG
bG93KG9iamVjdCk6CiAgICBfX3Nsb3RzX18gPSAoImJ1ZiIsICJoZHJzIiwgInRvdWNoZWQiLCAi
ZXZlbnQiLCAiYm9keV9nb2FsIiwKICAgICAgICAgICAgICAgICAiaGVhZF9ieXRlcyIpCiAgICBk
ZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5idWYgPSBieXRlYXJyYXkoKQogICAgICAg
IHNlbGYuaGRycyA9IE5vbmUKICAgICAgICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQogICAg
ICAgIHNlbGYuZXZlbnQgPSBOb25lCiAgICAgICAgc2VsZi5ib2R5X2dvYWwgPSAwCiAgICAgICAg
c2VsZi5oZWFkX2J5dGVzID0gMAoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAtLS0tClBFTkRJTkdfVFRMID0g
NS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBhZnRlciB0aGlzIG1hbnkgc2Vj
b25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNhcDsgb3ZlcmZsb3cgZmx1c2hl
cyBvbGRlc3QgZmlyc3QKUEVORElOR19QRVJfRkxPVyA9IDMyICAgICMgYm91bmQgYSBzaW5nbGUg
cGlwZWxpbmVkL2hvc3RpbGUga2VlcC1hbGl2ZSBmbG93ClNXRUVQX0lOVEVSVkFMID0gMS4wICAg
ICAjIGhvbm9yIFBFTkRJTkdfVFRMIGV2ZW4gd2hlbiB0aGUgc29ja2V0IGdvZXMgaWRsZQoKIyBw
ZW5kaW5nWyhzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KV0gIC0tIGtleSBpcyB0aGUgUkVT
UE9OU0UgdHVwbGU6CiMgc2VydmVyLT5jbGllbnQuIFZhbHVlOiBbZXZlbnQsIHJlcV90c10uIEEg
bGlzdCBwZXIga2V5IGhhbmRsZXMgSFRUUAojIGtlZXAtYWxpdmUgcGlwZWxpbmluZyAoc2V2ZXJh
bCByZXF1ZXN0cyBiZWZvcmUgcmVzcG9uc2VzIGFycml2ZSkuCnBlbmRpbmcgPSB7fQoKCmRlZiBw
ZW5kaW5nX2RlbChyayk6CiAgICBwZW5kaW5nLnBvcChyaywgTm9uZSkKCgpkZWYgcGVuZGluZ19w
b3AocmssIG91dCwgcGVuZGluZ190Ymw9Tm9uZSk6CiAgICAiIiJGbHVzaCB0aGUgb2xkZXN0IHBl
bmRpbmcgZXZlbnQgZm9yIHRoaXMgcmVzcG9uc2UgdHVwbGUgKEZJTi9SU1Qgb3IKICAgIG92ZXJm
bG93IHBhdGgpLiBFbWl0cyB3aGF0ZXZlciB0aGUgZXZlbnQgaGFzIOKAlCBzdGF0dXMgc3RheXMg
bnVsbC4iIiIKICAgIGlmIHBlbmRpbmdfdGJsIGlzIE5vbmU6CiAgICAgICAgcGVuZGluZ190Ymwg
PSBwZW5kaW5nCiAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBub3QgbHN0Ogog
ICAgICAgIHJldHVybiBOb25lCiAgICBldiwgXyA9IGxzdC5wb3AoMCkKICAgIGlmIG5vdCBsc3Q6
CiAgICAgICAgcGVuZGluZ190YmwucG9wKHJrLCBOb25lKQogICAgb3V0LmFwcGVuZChldikKICAg
IHJldHVybiBldgoKCmRlZiBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxvYWQpOgogICAgIiIiRmly
c3QgbGluZSAnSFRUUC8xLnggTk5OIC4uLicgLT4gKHN0YXR1c19pbnR8Tm9uZSwgY29udGVudF9s
ZW58Tm9uZSkuCiAgICBPbmx5IGxvb2tzIGF0IHdoYXQncyBpbiB0aGlzIHNlZ21lbnQ7IGhlYWRl
cnMgZml0IG9uZSBzZWdtZW50IGZvciBhbGwKICAgIHJlYWxpc3RpYyBBUEkgcmVzcG9uc2VzLiIi
IgogICAgdHJ5OgogICAgICAgIGhlYWQgPSBwYXlsb2FkLnNwbGl0KGIiXHJcblxyXG4iLCAxKVsw
XQogICAgICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxpdChiIlxu
IikKICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAgICBpZiBsZW4oZmlyc3Qp
IDwgMiBvciBub3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6CiAgICAgICAgICAgIHJl
dHVybiBOb25lLCBOb25lCiAgICAgICAgc3QgPSBpbnQoZmlyc3RbMV0pCiAgICBleGNlcHQgKFZh
bHVlRXJyb3IsIEluZGV4RXJyb3IpOgogICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBjbGVu
ID0gTm9uZQogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBsb3cgPSBsbi5sb3dlcigp
CiAgICAgICAgaWYgbG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0aDoiKToKICAgICAgICAg
ICAgdHJ5OgogICAgICAgICAgICAgICAgY2xlbiA9IGludChsbi5zcGxpdChiIjoiLCAxKVsxXS5z
dHJpcCgpKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIHBh
c3MKICAgICAgICAgICAgYnJlYWsKICAgIHJldHVybiBzdCwgY2xlbgoKCmRlZiBjb3JyZWxhdGVf
cmVzcG9uc2UocGVuZGluZ190YmwsIHJrLCBwYXlsb2FkLCBub3csIG91dCk6CiAgICAiIiJBdHRh
Y2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhlIG9sZGVzdCByZXF1ZXN0IG9uIGEgY29ubmVjdGlv
bi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5nIGNhbiBsZWF2ZSBzZXZlcmFsIHJlcXVlc3RzIHF1
ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXItdHVwbGUuICBDb25zdW1lIGV4YWN0bHkgb25lIGVu
dHJ5OyBkZWxldGluZyB0aGUgd2hvbGUga2V5IGhlcmUgbG9zZXMKICAgIGV2ZXJ5IHJlcXVlc3Qg
YWZ0ZXIgdGhlIGZpcnN0IHJlc3BvbnNlLgogICAgIiIiCiAgICBzdCwgY2xlbiA9IHBhcnNlX3Jl
c3BvbnNlX2hlYWQocGF5bG9hZCkKICAgIGlmIHN0IGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIEZh
bHNlCiAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBub3QgZW50OgogICAgICAg
IHJldHVybiBGYWxzZQogICAgZXYsIHN0YXJ0ZWQgPSBlbnQucG9wKDApCiAgICBpZiBub3QgZW50
OgogICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgIGV2WyJzdGF0dXMiXSA9IHN0
CiAgICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgwLCBpbnQoKG5vdyAtIHN0YXJ0ZWQpICogMTAw
MCkpCiAgICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgIGV2WyJyZXNwX2J5dGVzIl0gPSBj
bGVuCiAgICBvdXQuYXBwZW5kKGV2KQogICAgcmV0dXJuIFRydWUKCgpkZWYgdmFsaWRfcG9ydChw
KToKICAgIHRyeToKICAgICAgICByZXR1cm4gMSA8PSBpbnQocCkgPD0gNjU1MzUKICAgIGV4Y2Vw
dCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgYmFz
aWNfdXNlcih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRlciB2YWx1ZSAtPiAodXNl
cnxOb25lLCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBwYXJ0cyA9IHZhbHVlLnN0
cmlwKCkuc3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0gMjoKICAgICAgICByZXR1
cm4gTm9uZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAgaWYgc2NoZW1l
ID09ICJiYXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQgPSBwYXJ0c1sxXS5zdHJp
cCgpCiAgICAgICAgICAgIGlmIGxlbihwYWQpID4gMTAyNDoKICAgICAgICAgICAgICAgIHJldHVy
biBOb25lLCBOb25lCiAgICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxlbihwYWQpICUgNCkKICAg
ICAgICAgICAgcmF3ID0gYmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAgICAgICAgIGlmIGxlbihy
YXcpID4gNTEyOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAgICAgICAg
aWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAgICAgICB1c2VyID0gcmF3LnNwbGl0KGIiOiIsIDEp
WzBdCiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci5kZWNvZGUoInV0Zi04IiwgInJlcGxhY2Ui
KVs6NjRdLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcmV0
dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFyZXIiOgogICAgICAgIHJldHVy
biBOb25lLCAiYmVhcmVyIgogICAgcmV0dXJuIE5vbmUsIE5vbmUKCgpkZWYgbm9ybWFsaXplX3dz
c2VfdXNlcm5hbWUodmFsdWUpOgogICAgIiIiUmV0dXJuIGEgc21hbGwsIHByaW50YWJsZSB1c2Vy
bmFtZSBvciBOb25lOyBuZXZlciByZXR1cm4gdG9rZW4gZGF0YS4iIiIKICAgIGlmIHZhbHVlIGlz
IE5vbmU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToKICAgICAgICB1c2VybmFtZSA9IHZh
bHVlLnN0cmlwKCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKICAg
IGlmIG5vdCB1c2VybmFtZSBvciBsZW4odXNlcm5hbWUpID4gTUFYX1dTU0VfVVNFUk5BTUU6CiAg
ICAgICAgcmV0dXJuIE5vbmUKICAgIGZvciBjaGFyIGluIHVzZXJuYW1lOgogICAgICAgIGlmIHVu
aWNvZGVkYXRhLmNhdGVnb3J5KGNoYXIpLnN0YXJ0c3dpdGgoIkMiKToKICAgICAgICAgICAgcmV0
dXJuIE5vbmUKICAgIHJldHVybiB1c2VybmFtZQoKCmRlZiBleHRyYWN0X3dzc2VfdXNlcm5hbWUo
Ym9keSk6CiAgICAiIiJQYXJzZSBhIGJvdW5kZWQsIHBvc3NpYmx5IHBhcnRpYWwgU09BUCBwcmVm
aXggYW5kIHJldHVybiBvbmx5IFVzZXJuYW1lLgoKICAgIEV4cGF0IGlzIHJ1biBpbmNyZW1lbnRh
bGx5IHNvIGEgVXNlcm5hbWVUb2tlbiBpbiB0aGUgU09BUCBIZWFkZXIgY2FuIGJlCiAgICByZWNv
Z25pemVkIHdpdGhvdXQgcmV0YWluaW5nIG9yIHJlcXVpcmluZyB0aGUgY29tcGxldGUgcmVxdWVz
dCBib2R5LgogICAgRFREL2VudGl0eSBkZWNsYXJhdGlvbnMgYXJlIHJlamVjdGVkIGJlZm9yZSBw
YXJzaW5nLgogICAgIiIiCiAgICBpZiBub3QgYm9keSBvciBsZW4oYm9keSkgPiBNQVhfV1NTRV9C
T0RZX0JZVEVTIG9yIGIiXHgwMCIgaW4gYm9keToKICAgICAgICByZXR1cm4gTm9uZQogICAgbG93
ZXJlZCA9IGJ5dGVzKGJvZHkpLmxvd2VyKCkKICAgIGlmIGIiPCFkb2N0eXBlIiBpbiBsb3dlcmVk
IG9yIGIiPCFlbnRpdHkiIGluIGxvd2VyZWQ6CiAgICAgICAgcmV0dXJuIE5vbmUKCiAgICBzdGF0
ZSA9IHsic3RhY2siOiBbXSwgInRva2VuX2RlcHRoIjogMCwgInVzZXJuYW1lX2RlcHRoIjogMCwK
ICAgICAgICAgICAgICJjaGFycyI6IFtdLCAidG9vX2xvbmciOiBGYWxzZSwgInJlc3VsdCI6IE5v
bmV9CgogICAgZGVmIHNwbGl0X25hbWUobmFtZSk6CiAgICAgICAgaWYgIn0iIG5vdCBpbiBuYW1l
OgogICAgICAgICAgICByZXR1cm4gIiIsIG5hbWUKICAgICAgICByZXR1cm4gbmFtZS5yc3BsaXQo
In0iLCAxKQoKICAgIGRlZiBzdGFydChuYW1lLCBhdHRycyk6CiAgICAgICAgbmFtZXNwYWNlLCBs
b2NhbF9uYW1lID0gc3BsaXRfbmFtZShuYW1lKQogICAgICAgIHN0YXRlWyJzdGFjayJdLmFwcGVu
ZCgobmFtZXNwYWNlLCBsb2NhbF9uYW1lKSkKICAgICAgICBkZXB0aCA9IGxlbihzdGF0ZVsic3Rh
Y2siXSkKICAgICAgICBpZiAobm90IHN0YXRlWyJ0b2tlbl9kZXB0aCJdIGFuZCBsb2NhbF9uYW1l
ID09ICJVc2VybmFtZVRva2VuIiBhbmQKICAgICAgICAgICAgICAgIG5hbWVzcGFjZSBpbiBXU1NF
X05BTUVTUEFDRVMpOgogICAgICAgICAgICBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9IGRlcHRoCiAg
ICAgICAgZWxpZiAoc3RhdGVbInRva2VuX2RlcHRoIl0gYW5kCiAgICAgICAgICAgICAgZGVwdGgg
PT0gc3RhdGVbInRva2VuX2RlcHRoIl0gKyAxIGFuZAogICAgICAgICAgICAgIGxvY2FsX25hbWUg
PT0gIlVzZXJuYW1lIiBhbmQKICAgICAgICAgICAgICBuYW1lc3BhY2UgPT0gc3RhdGVbInN0YWNr
Il1bc3RhdGVbInRva2VuX2RlcHRoIl0gLSAxXVswXSk6CiAgICAgICAgICAgIHN0YXRlWyJ1c2Vy
bmFtZV9kZXB0aCJdID0gZGVwdGgKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAg
ICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IEZhbHNlCgogICAgZGVmIGNoYXJzKHZhbHVlKToK
ICAgICAgICBpZiBub3Qgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gb3Igc3RhdGVbInRvb19sb25n
Il06CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHN0YXRlWyJjaGFycyJdLmFwcGVuZCh2YWx1
ZSkKICAgICAgICBpZiBzdW0oW2xlbihwYXJ0KSBmb3IgcGFydCBpbiBzdGF0ZVsiY2hhcnMiXV0p
ID4gTUFYX1dTU0VfVVNFUk5BTUUgKyAyOgogICAgICAgICAgICBzdGF0ZVsiY2hhcnMiXSA9IFtd
CiAgICAgICAgICAgIHN0YXRlWyJ0b29fbG9uZyJdID0gVHJ1ZQoKICAgIGRlZiBlbmQobmFtZSk6
CiAgICAgICAgZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0pCiAgICAgICAgaWYgc3RhdGVbInVz
ZXJuYW1lX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIGlmIG5vdCBzdGF0ZVsidG9vX2xv
bmciXSBhbmQgc3RhdGVbInJlc3VsdCJdIGlzIE5vbmU6CiAgICAgICAgICAgICAgICBzdGF0ZVsi
cmVzdWx0Il0gPSBub3JtYWxpemVfd3NzZV91c2VybmFtZSgKICAgICAgICAgICAgICAgICAgICB1
IiIuam9pbihzdGF0ZVsiY2hhcnMiXSkpCiAgICAgICAgICAgIHN0YXRlWyJ1c2VybmFtZV9kZXB0
aCJdID0gMAogICAgICAgICAgICBzdGF0ZVsiY2hhcnMiXSA9IFtdCiAgICAgICAgaWYgc3RhdGVb
InRva2VuX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIHN0YXRlWyJ0b2tlbl9kZXB0aCJd
ID0gMAogICAgICAgIGlmIHN0YXRlWyJzdGFjayJdOgogICAgICAgICAgICBzdGF0ZVsic3RhY2si
XS5wb3AoKQoKICAgIHRyeToKICAgICAgICBwYXJzZXIgPSBleHBhdC5QYXJzZXJDcmVhdGUoTm9u
ZSwgIn0iKQogICAgICAgIGlmIGhhc2F0dHIocGFyc2VyLCAicmV0dXJuc191bmljb2RlIik6CiAg
ICAgICAgICAgIHBhcnNlci5yZXR1cm5zX3VuaWNvZGUgPSBUcnVlCiAgICAgICAgcGFyc2VyLlN0
YXJ0RWxlbWVudEhhbmRsZXIgPSBzdGFydAogICAgICAgIHBhcnNlci5DaGFyYWN0ZXJEYXRhSGFu
ZGxlciA9IGNoYXJzCiAgICAgICAgcGFyc2VyLkVuZEVsZW1lbnRIYW5kbGVyID0gZW5kCiAgICAg
ICAgaWYgKGhhc2F0dHIocGFyc2VyLCAiU2V0UGFyYW1FbnRpdHlQYXJzaW5nIikgYW5kCiAgICAg
ICAgICAgICAgICBoYXNhdHRyKGV4cGF0LCAiWE1MX1BBUkFNX0VOVElUWV9QQVJTSU5HX05FVkVS
IikpOgogICAgICAgICAgICBwYXJzZXIuU2V0UGFyYW1FbnRpdHlQYXJzaW5nKGV4cGF0LlhNTF9Q
QVJBTV9FTlRJVFlfUEFSU0lOR19ORVZFUikKICAgICAgICBwYXJzZXIuUGFyc2UoYnl0ZXMoYm9k
eSksIEZhbHNlKQogICAgZXhjZXB0IChleHBhdC5FeHBhdEVycm9yLCBWYWx1ZUVycm9yLCBUeXBl
RXJyb3IpOgogICAgICAgICMgQSBib3VuZGVkIHByZWZpeCBpcyBjb21tb25seSBpbmNvbXBsZXRl
LiBBIHVzZXJuYW1lIGZ1bGx5IGNsb3NlZAogICAgICAgICMgYmVmb3JlIHRoZSB0cnVuY2F0aW9u
IHBvaW50IGlzIHN0aWxsIHNhZmUgdG8gdXNlLgogICAgICAgIHBhc3MKICAgIHJldHVybiBzdGF0
ZVsicmVzdWx0Il0KCgpkZWYgaXNfc29hcF9jb250ZW50X3R5cGUodmFsdWUpOgogICAgaWYgbm90
IHZhbHVlOgogICAgICAgIHJldHVybiBGYWxzZQogICAgbWVkaWFfdHlwZSA9IHZhbHVlLnNwbGl0
KCI7IiwgMSlbMF0uc3RyaXAoKS5sb3dlcigpCiAgICByZXR1cm4gKG1lZGlhX3R5cGUgaW4gKCJ0
ZXh0L3htbCIsICJhcHBsaWNhdGlvbi94bWwiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAi
YXBwbGljYXRpb24vc29hcCt4bWwiKSBvcgogICAgICAgICAgICBtZWRpYV90eXBlLmVuZHN3aXRo
KCIreG1sIikpCgoKZGVmIGZpbmlzaF9ldmVudChmbG93LCBrZXksIGRzdF9pcCwgZHBvcnQsIHNy
Y19pcCwgc3BvcnQsIHBvcnRzLCBub2RlX2hvc3QpOgogICAgaCA9IGZsb3cuaGRycwogICAgdXNl
ciA9IHNjaGVtZSA9IE5vbmUKICAgIGF1dGh6ID0gaC5nZXQoImF1dGhvcml6YXRpb24iKQogICAg
aWYgYXV0aHo6CiAgICAgICAgdXNlciwgc2NoZW1lID0gYmFzaWNfdXNlcihhdXRoeikKICAgICMg
VzNDIHRyYWNlIGNvbnRleHQ6IGhvbm9yIGluY29taW5nIHRyYWNlcGFyZW50LCBlbHNlIGdlbmVy
YXRlIG9uZSBzbwogICAgIyBldmVyeSB0cmFuc2FjdGlvbiBjYXJyaWVzIGEgdHJhY2VfaWQgZm9y
IGh1Yi1zaWRlIGNvcnJlbGF0aW9uLgogICAgIyBOT1RFIHB5Mi42OiBieXRlcyBoYXMgbm8gLmhl
eCgpIOKAlCB1c2UgYmluYXNjaWkuaGV4bGlmeS4KICAgIHRwID0gaC5nZXQoInRyYWNlcGFyZW50
IikKICAgIHRyYWNlX2lkID0gTm9uZQogICAgaWYgdHA6CiAgICAgICAgcGFydHMgPSB0cC5zcGxp
dCgiLSIpCiAgICAgICAgaWYgbGVuKHBhcnRzKSA9PSA0IGFuZCBsZW4ocGFydHNbMV0pID09IDMy
OgogICAgICAgICAgICB0cmFjZV9pZCA9IHBhcnRzWzFdLmxvd2VyKCkKICAgIGlmIG5vdCB0cmFj
ZV9pZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJuZCA9IGJpbmFzY2lpLmhleGxpZnkob3Mu
dXJhbmRvbSgxNikpCiAgICAgICAgICAgIHJuZCA9IHJuZC5kZWNvZGUoImFzY2lpIikgaWYgaGFz
YXR0cihybmQsICJkZWNvZGUiKSBlbHNlIHJuZAogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAg
ICAgICAgICAgIHJuZCA9ICgiJTAzMngiICUgKGludCh0aW1lLnRpbWUoKSAqIDEwMDApKSlbLTMy
Ol0KICAgICAgICBwaWQ4ID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDgpKQogICAgICAg
IHBpZDggPSBwaWQ4LmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHBpZDgsICJkZWNvZGUiKSBl
bHNlIHBpZDgKICAgICAgICB0cCA9ICIwMC0lcy0lcy0wMSIgJSAocm5kLCBwaWQ4KQogICAgICAg
IHRyYWNlX2lkID0gcm5kCiAgICBldiA9IHsKICAgICAgICAidHMiOiBpbnQodGltZS50aW1lKCkp
LAogICAgICAgICJob3N0Ijogbm9kZV9ob3N0LAogICAgICAgICJzcmMiOiAicGNhcCIsCiAgICAg
ICAgInNlcnZpY2UiOiAicG9ydDolZCIgJSBkcG9ydCwKICAgICAgICAibWV0aG9kIjogaC5nZXQo
Il9tZXRob2QiKSBvciAiLSIsCiAgICAgICAgInBhdGgiOiAoaC5nZXQoIl9wYXRoIikgb3IgIi0i
KS5zcGxpdCgiPyIsIDEpWzBdWzoxMjBdLAogICAgICAgICJ1c2VyIjogdXNlciwKICAgICAgICAi
c2NoZW1lIjogc2NoZW1lLAogICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJzb3VyY2VfcHJv
YmUiOiAicGNhcC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIpLAogICAg
ICAgICJ1c2VyX2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAieF9mb3J3YXJk
ZWRfZm9yIjogaC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIiOiBzcmNf
aXAsCiAgICAgICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6IGRzdF9p
cCwKICAgICAgICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRvcmluZyBz
Y2hlbWEgKG9wcyBBUEktbG9nIGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1cmF0aW9u
X21zL3Jlc3BfYnl0ZXMgYXJlIHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1vbmx5CiAg
ICAgICAgIyBjYXB0dXJlIGNhbm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUgaHViIHRv
IGVucmljaCBvciBsZWF2ZS4KICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAogICAgICAg
ICJ0cmFjZV9pZCI6IHRyYWNlX2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwgICAgICAg
ICAgIyBodWIgbWFwcyBwb3J0LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAgICAibW9k
dWxlX2lkIjogInBjYXAtaHR0cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNlIGNvcnJl
bGF0aW9uIG9ubHkgZm9yIG1vbml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyByZXNwb25z
ZS1zaWRlIGZpbHRlciBtYXkgc3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNwb3J0IGVx
dWFsIHRvIGEKICAgICMgbW9uaXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVjYXVzZSBw
YXJzZV9yZXNwb25zZV9oZWFkIHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRwb3J0IGlu
IHBvcnRzIG9yIGguZ2V0KCJfbWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBfZW1pdF9yZXF1ZXN0
KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiRGlz
Y2FyZCBjYXB0dXJlIGJ1ZmZlcnMsIHRoZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRpemVkIGV2ZW50
IG9ubHkuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAgZXYg
PSBmbC5ldmVudAogICAgZmxvd3MucG9wKGtleSwgTm9uZSkKICAgIGlmIG5vdCBldjoKICAgICAg
ICByZXR1cm4KICAgIGV2WyJyZXFfYnl0ZXMiXSA9IGZsLmhlYWRfYnl0ZXMKICAgIGlmIHBlbmRp
bmdfdGJsIGlzIE5vbmU6CiAgICAgICAgb3V0LmFwcGVuZChldikKICAgICAgICByZXR1cm4KICAg
IHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpCiAgICBlbnQgPSBwZW5kaW5nX3Ri
bC5nZXQocmspCiAgICBpZiBlbnQgaXMgTm9uZToKICAgICAgICBpZiBsZW4ocGVuZGluZ190Ymwp
ID49IFBFTkRJTkdfTUFYOgogICAgICAgICAgICBfZmx1c2hfb2xkZXN0X3BlbmRpbmcocGVuZGlu
Z190YmwsIG91dCkKICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10gPSBbXQogICAgZWxpZiBs
ZW4oZW50KSA+PSBQRU5ESU5HX1BFUl9GTE9XOgogICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQs
IHBlbmRpbmdfdGJsKQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgICAgICBp
ZiBlbnQgaXMgTm9uZToKICAgICAgICAgICAgZW50ID0gcGVuZGluZ190YmxbcmtdID0gW10KICAg
IGVudC5hcHBlbmQoW2V2LCBub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGltZS50aW1lKCld
KQoKCmRlZiBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwgcGF5bG9hZCwgbWV0YSwgb3V0
LCBwZW5kaW5nX3RibCwgbm93KToKICAgICIiIkFwcGVuZCBubyBtb3JlIHRoYW4gYm9keV9nb2Fs
IGJ5dGVzIGFuZCBmaW5pc2ggYXMgc29vbiBhcyBwb3NzaWJsZS4iIiIKICAgIHJlbWFpbmluZyA9
IGZsLmJvZHlfZ29hbCAtIGxlbihmbC5idWYpCiAgICBpZiByZW1haW5pbmcgPiAwIGFuZCBwYXls
b2FkOgogICAgICAgIGZsLmJ1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWRbOnJlbWFpbmluZ10p
KQogICAgdXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwuYnVmKQogICAgaWYgdXNl
cm5hbWU6CiAgICAgICAgZmwuZXZlbnRbInVzZXIiXSA9IHVzZXJuYW1lCiAgICAgICAgZmwuZXZl
bnRbInNjaGVtZSJdID0gIndzc2UiCiAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwuYnVmKSA+PSBm
bC5ib2R5X2dvYWw6CiAgICAgICAgX2VtaXRfcmVxdWVzdChmbG93cywga2V5LCBmbCwgbWV0YSwg
b3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFs
c2UKCgpkZWYgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2X2tleSwgcGF5bG9hZCwgbWV0
YSwgcG9ydHMsIG5vZGVfaG9zdCwgb3V0LAogICAgICAgICAgICAgICAgICAgcGVuZGluZ190Ymw9
Tm9uZSwgbm93PU5vbmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgICIiIkZlZWQgb25lIGRpcmVj
dGlvbidzIHBheWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0KS4KCiAgICBC
b2RpZXMgYXJlIGlnbm9yZWQgdW5sZXNzIHdzc2VfYm9keV9ieXRlcyBpcyBub24temVyby4gSW4g
b3B0LWluIG1vZGUsCiAgICBvbmx5IFhNTCByZXF1ZXN0cyB3aXRoIENvbnRlbnQtTGVuZ3RoIGFy
ZSBpbnNwZWN0ZWQsIGVhY2ggYnVmZmVyIGlzCiAgICBib3VuZGVkIGJ5IHdzc2VfYm9keV9ieXRl
cywgYW5kIG9ubHkgYSByZWNvZ25pemVkIFdTU0UgdXNlcm5hbWUgcmVhY2hlcwogICAgdGhlIGV2
ZW50LiBUaGUgYm9keSBhbmQgYWxsIG90aGVyIFVzZXJuYW1lVG9rZW4gbWF0ZXJpYWwgYXJlIGRp
c2NhcmRlZC4KICAgICIiIgogICAgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCA9IG1ldGEK
ICAgIGlmIG5vdCB2YWxpZF9wb3J0KGRwb3J0KSBvciBub3QgdmFsaWRfcG9ydChzcG9ydCk6CiAg
ICAgICAgcmV0dXJuCiAgICBmbCA9IGZsb3dzLmdldChrZXkpCiAgICBpZiBmbCBpcyBOb25lOgog
ICAgICAgIGZsID0gRmxvdygpCiAgICAgICAgZmxvd3Nba2V5XSA9IGZsCiAgICAgICAgaWYgbGVu
KGZsb3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICAgICAgZW5mb3JjZV9saW1pdChmbG93cywgdGlt
ZS50aW1lKCkpCiAgICBmbC50b3VjaGVkID0gdGltZS50aW1lKCkKCiAgICBpZiBmbC5ldmVudCBp
cyBub3QgTm9uZToKICAgICAgICBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwgcGF5bG9h
ZCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVybgoKICAgIGZsLmJ1
Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWQpKQogICAgaWR4ID0gZmwuYnVmLmZpbmQoYiJcclxu
XHJcbiIpCiAgICBpZiBpZHggPCAwOgogICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6
CiAgICAgICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBoZWFk
ID0gYnl0ZXMoZmwuYnVmWzppZHhdKQogICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwg
YiJcbiIpLnNwbGl0KGIiXG4iKQogICAgaGRycyA9IHt9CiAgICBmaXJzdCA9IGxpbmVzWzBdLnN0
cmlwKCkuc3BsaXQoKQogICAgaWYgbGVuKGZpcnN0KSA+PSAyIGFuZCBmaXJzdFswXSBpbiBbbS5l
bmNvZGUoKSBmb3IgbSBpbiBNRVRIT0RTXToKICAgICAgICBoZHJzWyJfbWV0aG9kIl0gPSBmaXJz
dFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgICAgIGhkcnNbIl9wYXRoIl0gPSBm
aXJzdFsxXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgZWxzZToKICAgICAgICBmbG93
cy5wb3Aoa2V5LCBOb25lKQogICAgICAgIHJldHVybgogICAgZm9yIGxuIGluIGxpbmVzWzE6XToK
ICAgICAgICBpZiBiIjoiIG5vdCBpbiBsbjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBr
biwga3YgPSBsbi5zcGxpdChiIjoiLCAxKQogICAgICAgIGhkcnNba24uc3RyaXAoKS5sb3dlcigp
LmRlY29kZSgKICAgICAgICAgICAgImFzY2lpIiwgInJlcGxhY2UiKV0gPSBrdi5zdHJpcCgpLmRl
Y29kZSgKICAgICAgICAgICAgICAgICJ1dGYtOCIsICJyZXBsYWNlIilbOjE4MF0KICAgIGZsLmhk
cnMgPSBoZHJzCiAgICBmbC5ldmVudCA9IGZpbmlzaF9ldmVudChmbCwga2V5LCBkc3RfaXAsIGRw
b3J0LCBzcmNfaXAsIHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgcG9ydHMsIG5v
ZGVfaG9zdCkKICAgIGlmIG5vdCBmbC5ldmVudDoKICAgICAgICBmbG93cy5wb3Aoa2V5LCBOb25l
KQogICAgICAgIHJldHVybgogICAgZmwuaGVhZF9ieXRlcyA9IGlkeCArIDQKICAgIGluaXRpYWxf
Ym9keSA9IGJ5dGVzKGZsLmJ1ZltpZHggKyA0Ol0pCiAgICBmbC5idWYgPSBieXRlYXJyYXkoKQoK
ICAgIGlmIChmbC5ldmVudC5nZXQoInVzZXIiKSBvciBub3Qgd3NzZV9ib2R5X2J5dGVzIG9yCiAg
ICAgICAgICAgIG5vdCBpc19zb2FwX2NvbnRlbnRfdHlwZShoZHJzLmdldCgiY29udGVudC10eXBl
IikpKToKICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBl
bmRpbmdfdGJsLCBub3cpCiAgICAgICAgcmV0dXJuCiAgICB0cnk6CiAgICAgICAgY29udGVudF9s
ZW5ndGggPSBpbnQoaGRycy5nZXQoImNvbnRlbnQtbGVuZ3RoIiwgIiIpKQogICAgZXhjZXB0IChU
eXBlRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIGNvbnRlbnRfbGVuZ3RoID0gMAogICAgYWN0
aXZlX2JvZHlfZmxvd3MgPSBzdW0oWzEgZm9yIGNhbmRpZGF0ZSBpbiBmbG93cy52YWx1ZXMoKQog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGNhbmRpZGF0ZS5ldmVudCBpcyBub3QgTm9u
ZSBhbmQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYW5kaWRhdGUuYm9keV9nb2FsID4g
MF0pCiAgICBpZiAoY29udGVudF9sZW5ndGggPD0gMCBvciBhY3RpdmVfYm9keV9mbG93cyA+PSBN
QVhfV1NTRV9CT0RZX0ZMT1dTIG9yCiAgICAgICAgICAgICJjaHVua2VkIiBpbiBoZHJzLmdldCgi
dHJhbnNmZXItZW5jb2RpbmciLCAiIikubG93ZXIoKSk6CiAgICAgICAgX2VtaXRfcmVxdWVzdChm
bG93cywga2V5LCBmbCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVy
bgogICAgZmwuYm9keV9nb2FsID0gbWluKGNvbnRlbnRfbGVuZ3RoLCB3c3NlX2JvZHlfYnl0ZXMs
IE1BWF9XU1NFX0JPRFlfQllURVMpCiAgICBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwg
aW5pdGlhbF9ib2R5LCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCgoKZGVmIHN3ZWVwX2lk
bGUoZmxvd3MsIG5vdyk6CiAgICBzdGFsZSA9IFtdCiAgICBmb3IgaywgZmwgaW4gZmxvd3MuaXRl
bXMoKToKICAgICAgICBpZiBub3cgLSBmbC50b3VjaGVkID4gRkxPV19UVEw6CiAgICAgICAgICAg
IHN0YWxlLmFwcGVuZChrKQogICAgZm9yIGsgaW4gc3RhbGU6CiAgICAgICAgZGVsIGZsb3dzW2td
CgoKZGVmIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToKICAgICIiIk92
ZXJmbG93IGd1YXJkOiBlbWl0IHRoZSBzaW5nbGUgb2xkZXN0IHBlbmRpbmcgZXZlbnQgYXMtaXMu
IiIiCiAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSBOb25lLCBOb25lCiAgICBmb3IgcmssIGxz
dCBpbiBwZW5kaW5nX3RibC5pdGVtcygpOgogICAgICAgIHRzID0gbHN0WzBdWzFdCiAgICAgICAg
aWYgb2xkZXN0X3RzIGlzIE5vbmUgb3IgdHMgPCBvbGRlc3RfdHM6CiAgICAgICAgICAgIG9sZGVz
dF9rZXksIG9sZGVzdF90cyA9IHJrLCB0cwogICAgaWYgb2xkZXN0X2tleSBpcyBub3QgTm9uZToK
ICAgICAgICBwZW5kaW5nX3BvcChvbGRlc3Rfa2V5LCBvdXQsIHBlbmRpbmdfdGJsKQoKCmRlZiBz
d2VlcF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBub3csIG91dCk6CiAgICAiIiJUVEwgZmx1c2g6IGVt
aXQgcmVxdWVzdHMgd2hvc2UgcmVzcG9uc2VzIG5ldmVyIHNob3dlZCB1cC4iIiIKICAgIGZvciBy
ayBpbiBsaXN0KHBlbmRpbmdfdGJsLmtleXMoKSk6CiAgICAgICAgbHN0ID0gcGVuZGluZ190Ymwu
Z2V0KHJrKQogICAgICAgIHdoaWxlIGxzdCBhbmQgbm93IC0gbHN0WzBdWzFdID4gUEVORElOR19U
VEw6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQsIHBlbmRpbmdfdGJsKQogICAgICAg
ICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCgoKZGVmIGRyYWluX3BlbmRpbmcocGVuZGlu
Z190YmwsIG91dCk6CiAgICAiIiJFbWl0IGV2ZXJ5IGNhcHR1cmVkIHJlcXVlc3QgYmVmb3JlIGNh
cHR1cmUgc2h1dGRvd24uCgogICAgUmVzcG9uc2VzIGFyZSBvcHRpb25hbCBlbnJpY2htZW50LiBB
IHN0b3AvcmVzdGFydCBtdXN0IG5vdCBkaXNjYXJkIGEKICAgIHJlcXVlc3QgbWVyZWx5IGJlY2F1
c2UgaXRzIHJlc3BvbnNlIHdhcyBmaWx0ZXJlZCwgc3BsaXQsIG9yIHN0aWxsIGluCiAgICBmbGln
aHQgd2hlbiB0aGUgcHJvY2VzcyByZWNlaXZlZCBTSUdURVJNLgogICAgIiIiCiAgICBmb3Igcmsg
aW4gbGlzdChwZW5kaW5nX3RibC5rZXlzKCkpOgogICAgICAgIHdoaWxlIHBlbmRpbmdfdGJsLmdl
dChyayk6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQsIHBlbmRpbmdfdGJsKQoKCmRl
ZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAgIHJldHVybiBub3cgLSBsYXN0
X3N3ZWVwID49IFNXRUVQX0lOVEVSVkFMCgoKZGVmIGVuZm9yY2VfbGltaXQoZmxvd3MsIG5vdyk6
CiAgICAiIiJDYXAgZmxvdy10YWJsZSBzaXplIChweTIuNjogbm8gT3JkZXJlZERpY3Qg4oCUIHN3
ZWVwIHN0YWxlLCB0aGVuIEZJRk8KICAgIGJ5IGluc2VydGlvbiBvcmRlciwgd2hpY2ggcGxhaW4g
ZGljdHMgcHJlc2VydmUgaW4gQ1B5dGhvbikuIiIiCiAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3cp
CiAgICB3aGlsZSBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgIGZsb3dzLnBvcGl0ZW0o
KSAgICAgICAgICAjIG9sZGVzdC1pbnNlcnRlZCBrZXkgb24gQ1B5dGhvbiAyLjYvMi43CgoKZGVm
IF9jb250cm9sX2NvbmZpZygpOgogICAgIiIiUmVhZCBvcHRpb25hbCBjb250cm9sIHNldHRpbmdz
IHdpdGhvdXQgZXhwb3NpbmcgdGhlIGJlYXJlciB0b2tlbi4iIiIKICAgIGVuZHBvaW50ID0gb3Mu
ZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfRU5EUE9JTlQiKSBvciBvcy5lbnZpcm9uLmdldCgiTlRf
RU5EUE9JTlQiKQogICAgdG9rZW5fZmlsZSA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RP
S0VOX0ZJTEUiLCAiIikKICAgIHRva2VuID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9L
RU4iLCAiIikKICAgIGlmIHRva2VuX2ZpbGU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBmID0g
b3Blbih0b2tlbl9maWxlLCAiciIpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRv
a2VuID0gZi5yZWFkKCkuc3RyaXAoKQogICAgICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAg
ICAgZi5jbG9zZSgpCiAgICAgICAgZXhjZXB0IElPRXJyb3I6CiAgICAgICAgICAgIHRva2VuID0g
IiIKICAgIG5vZGUgPSBvcy5lbnZpcm9uLmdldCgiTlRfTk9ERV9OQU1FIikgb3Igc29ja2V0Lmdl
dGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQogICAgcnVuX2RpciA9IG9zLmVudmlyb24uZ2V0KCJO
VF9DT05UUk9MX1JVTiIsICIvdmFyL2xpYi9uZXR3b3JrdHJhY2luZyIpCiAgICB0cnk6CiAgICAg
ICAgaW50ZXJ2YWwgPSBtYXgoNSwgbWluKGludChvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9T
RUMiLCAiMzAiKSksIDMwMCkpCiAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICBpbnRlcnZh
bCA9IDMwCiAgICByZXR1cm4gZW5kcG9pbnQsIHRva2VuLCBub2RlLCBydW5fZGlyLCBpbnRlcnZh
bAoKCmRlZiBfcnVuX2NvbnRyb2xfdGljayhwb3J0cywgaWZhY2UsIHJ1bl9kaXIsIGNsaWVudCk6
CiAgICByZXBseSA9IGNsaWVudC5wb2xsKCkKICAgIGlmIG5vdCByZXBseToKICAgICAgICByZXR1
cm4gcG9ydHMsIGlmYWNlLCBOb25lLCAicG9sbCBmYWlsZWQiCiAgICBkZXNpcmVkID0gcmVwbHku
Z2V0KCJkZXNpcmVkIikgb3Ige30KICAgIHN0YXRlID0gZGljdChkZXNpcmVkKQogICAgZ2VuZXJh
dGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0aW9uIiwgMCkKICAgIGNvbnRyb2xfYWN0aW9uID0g
Tm9uZQogICAgc3RvcF9yZXF1ZXN0ZWQgPSBGYWxzZQogICAgaWYgZGVzaXJlZC5nZXQoInBvcnRz
Iik6CiAgICAgICAgbmV3X3BvcnRzID0gc2V0KGRlc2lyZWRbInBvcnRzIl0pCiAgICAgICAgaWYg
bmV3X3BvcnRzICE9IHBvcnRzOgogICAgICAgICAgICBwb3J0cyA9IG5ld19wb3J0cwogICAgICAg
ICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0IgogICAgaWYgZGVzaXJlZC5nZXQoImlmYWNl
Iik6CiAgICAgICAgbmV3X2lmYWNlID0gZGVzaXJlZFsiaWZhY2UiXQogICAgICAgIGlmIG5ld19p
ZmFjZSAhPSBpZmFjZToKICAgICAgICAgICAgaWZhY2UgPSBuZXdfaWZhY2UKICAgICAgICAgICAg
Y29udHJvbF9hY3Rpb24gPSAicmVzdGFydCIKICAgIGZvciB0YXNrIGluIHJlcGx5LmdldCgidGFz
a3MiLCBbXSk6CiAgICAgICAgYWN0aW9uID0gdGFzay5nZXQoImFjdGlvbiIpCiAgICAgICAgaWYg
YWN0aW9uID09ICJoZWFsdGgiOgogICAgICAgICAgICBtZXNzYWdlID0gImhlYWx0aHkiCiAgICAg
ICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgIGVsaWYgYWN0aW9uIGluICgicmVzdGFydCIs
ICJyZWxvYWQiLCAic2V0X3BvcnRzIik6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAiYWNjZXB0ZWQ7
IGNhcHR1cmUgcmVzdGFydCByZXF1ZXN0ZWQiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgog
ICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0IgogICAgICAgICAgICBpZiBhY3Rp
b24gPT0gInNldF9wb3J0cyI6CiAgICAgICAgICAgICAgICBhcmdzID0gdGFzay5nZXQoImFyZ3Mi
KSBvciB7fQogICAgICAgICAgICAgICAgaWYgYXJncy5nZXQoInBvcnRzIik6CiAgICAgICAgICAg
ICAgICAgICAgcG9ydHMgPSBzZXQoYXJnc1sicG9ydHMiXSkKICAgICAgICAgICAgICAgICAgICBz
dGF0ZS51cGRhdGUoeyJwb3J0cyI6IHNvcnRlZChwb3J0cyksICJtb2RlIjogInB5dGhvbiIsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZ2VuZXJhdGlvbiI6IGdlbmVyYXRpb259
KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgbWVzc2FnZSA9ICJz
dG9wIHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgICAgIHN0
b3BfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAi
dW5zdXBwb3J0ZWQgYnkgZGlyZWN0IHNuaWZmZXIiCiAgICAgICAgICAgIHN0YXR1cyA9ICJmYWls
ZWQiCiAgICAgICAgY2xpZW50LnJlcG9ydCh0YXNrLmdldCgiaWQiKSwgc3RhdHVzLCBtZXNzYWdl
KQogICAgaWYgc3RvcF9yZXF1ZXN0ZWQ6CiAgICAgICAgY29udHJvbF9hY3Rpb24gPSAic3RvcCIK
ICAgIGFwcGxpZWQgPSAoInN0b3AgcmVxdWVzdGVkIiBpZiBjb250cm9sX2FjdGlvbiA9PSAic3Rv
cCIgZWxzZQogICAgICAgICAgICAgICAicmVzdGFydCByZXF1aXJlZCIgaWYgY29udHJvbF9hY3Rp
b24gPT0gInJlc3RhcnQiIGVsc2UKICAgICAgICAgICAgICAgInBvbGwgb2siKQogICAgbnRfY29u
dHJvbC53cml0ZV9zdGF0ZShvcy5wYXRoLmpvaW4ocnVuX2RpciwgInJlbW90ZS1kZXNpcmVkLmpz
b24iKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdGUsIGFwcGxpZWQpCiAgICBjbGll
bnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sIGFwcGxpZWQpCiAgICByZXR1cm4gcG9ydHMsIGlmYWNl
LCBjb250cm9sX2FjdGlvbiwgYXBwbGllZAoKCmRlZiBfcmVzdGFydF9hcmdzKHNjcmlwdCwgaWZh
Y2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXM9MCk6CiAgICAiIiJC
dWlsZCBhIGZyZXNoIGFyZ3YgZm9yIGFuIGluLXBsYWNlIHJlLWV4ZWMgYWZ0ZXIgYSBjb250cm9s
IHVwZGF0ZS4iIiIKICAgICMgUHJlc2VydmUgdW5idWZmZXJlZCBKU09OTCBkZWxpdmVyeTsgdGhl
IGluc3RhbGxlciBzdGFydHMgUHl0aG9uIHdpdGggLXUuCiAgICBhcmdzID0gW3N5cy5leGVjdXRh
YmxlLCAiLXUiLCBvcy5wYXRoLmFic3BhdGgoc2NyaXB0KV0KICAgIGlmIGlmYWNlOgogICAgICAg
IGFyZ3MuZXh0ZW5kKFsiLWkiLCBpZmFjZV0pCiAgICBhcmdzLmV4dGVuZChbIi1wIiwgIiwiLmpv
aW4oW3N0cihwKSBmb3IgcCBpbiBzb3J0ZWQocG9ydHMpXSldKQogICAgYXJncy5leHRlbmQoWyIt
aiIsIHN0cih3b3JrZXJzKV0pCiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6CiAgICAgICAgYXJncy5l
eHRlbmQoWyItLXdzc2UtYm9keS1ieXRlcyIsIHN0cih3c3NlX2JvZHlfYnl0ZXMpXSkKICAgIGlm
IHZlcmJvc2U6CiAgICAgICAgYXJncy5hcHBlbmQoIi12IikKICAgIHJldHVybiBhcmdzCgoKZGVm
IG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwgd29ya2Vycywgd3NzZV9ib2R5X2J5
dGVzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAgICBub2RlX2hvc3QgPSBzb2NrZXQuZ2V0
aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250cm9sX2NsaWVudCA9IE5vbmUKICAgIGVu
ZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250cm9sX3J1biwgY29udHJvbF9pbnRlcnZh
bCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9jb250cm9sIGlzIG5vdCBOb25lIGFuZCBl
bmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5OgogICAgICAgICAgICBjb250cm9sX2NsaWVu
dCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRwb2ludCwgdG9rZW4sIGNvbnRyb2xfbm9k
ZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIoY29udHJvbF9ydW4pOgogICAgICAg
ICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4pCiAgICAgICAgICAgIGxvZygicmVtb3Rl
IGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAg
ICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRpc2FibGVkICglcykiICUgbnRfY29udHJv
bC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAgICAgICMgcHJvdG9jb2wgTVVTVCBiZSBo
dG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJTkdSRVNTIChyZXEpIGFuZAogICAgICAg
ICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4IGtlcm5lbCBwYWNrZXQgc29ja2V0cy4K
ICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfUEFDS0VULCBzb2NrZXQuU09DS19S
QVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29ja2V0Lmh0b25zKEVUSF9QX0FMTCkpCiAg
ICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiQUZfUEFD
S0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0iKQogICAgZXhjZXB0IHNvY2tldC5lcnJv
ciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBvcGVuIEFGX1BBQ0tFVCBz
b2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAgICAgICAgICAgICAgICAiQ0FQX05FVF9S
QVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQoMS4wKQogICAgaWYgbm90IGFwcGx5X3Bl
cmZfb3B0cyhzLCBwb3J0cyk6CiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVt
RXhpdCgia2VybmVsIEJQRiBzYWZldHkgZmlsdGVyIHVuYXZhaWxhYmxlOyByZWZ1c2luZyB1bmZp
bHRlcmVkIGNhcHR1cmUiKQogICAgdHJ5OgogICAgICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIsIEVU
SF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgcy5jbG9zZSgp
CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IGJpbmQgQUZfUEFDS0VUIHRvICVzICgl
cykiICUKICAgICAgICAgICAgICAgICAgICAgICAgIChpZmFjZSBvciAiPGFsbD4iLCBlKSkKICAg
IGZhbm91dF9vayA9IEZhbHNlCiAgICBpZiB3b3JrZXJzID4gMToKICAgICAgICBmYW5vdXRfb2sg
PSBhcHBseV9mYW5vdXQocywgMHhGMDBEKQogICAgICAgIGlmIGZhbm91dF9vazoKICAgICAgICAg
ICAgbG9nKCJmYW5vdXQgZ3JvdXAgMHhGMDBEOiBzcGF3bmluZyAlZCB3b3JrZXJzIiAlIHdvcmtl
cnMpCiAgICBpZiBub3QgZHJvcF9jYXB0dXJlX2NhcGFiaWxpdGllcygpOgogICAgICAgIHMuY2xv
c2UoKQogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBkcm9wIENBUF9ORVRfUkFXIGFm
dGVyIHNvY2tldCBzZXR1cDsgcmVmdXNpbmcgdW5zYWZlIGNhcHR1cmUiKQoKICAgICMgcHJlY29t
cGlsZWQgc3RydWN0IHJlYWRlcnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBv
ZiB0aGUKICAgICMgcGFja2V0IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGlu
dHMgdW5kZXIgcHkyIEFORCBweTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNr
X2Zyb20KICAgIHVoID0gc3RydWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0
LGRwb3J0IGluIG9uZSByZWFkCiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19m
cm9tCiAgICBudG9hID0gc29ja2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5p
bmcgPSBbVHJ1ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5n
WzBdID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBz
aWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUu
dGltZSgpCiAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcg
b24gJXMgcG9ydHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRl
ZChwb3J0cyksIG9zLmdldHBpZCgpKSkKICAgIGlmIHdzc2VfYm9keV9ieXRlczoKICAgICAgICBs
b2coIldTU0UgVXNlcm5hbWVUb2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5kZWQgdG8gJWQg
Ynl0ZXMvcmVxdWVzdCkiICUKICAgICAgICAgICAgd3NzZV9ib2R5X2J5dGVzKQoKICAgICMgZm9y
ayBleHRyYSBjYXB0dXJlIHdvcmtlcnMgQUZURVIgZmFub3V0IGF0dGFjaDsgV0lUSE9VVCBhIHdv
cmtpbmcKICAgICMgZmFub3V0IGdyb3VwIGV2ZXJ5IHByb2Nlc3Mgd291bGQgcmVjZWl2ZSBFVkVS
WSBwYWNrZXQgKGR1cGxpY2F0ZXMpLAogICAgIyBzbyBzaW5nbGUtcHJvY2VzcyBtb2RlIGlzIGZv
cmNlZCB3aGVuIHRoZSBrZXJuZWwgbGFja3Mgc3VwcG9ydAogICAgIyAoUEFDS0VUX0ZBTk9VVCBu
ZWVkcyBrZXJuZWwgPj0gMy4xOyBlbDYgMi42LjMyIGRvZXMgbm90IGhhdmUgaXQpCiAgICBpZiBm
YW5vdXRfb2s6CiAgICAgICAgZm9yIF8gaW4gcmFuZ2Uod29ya2VycyAtIDEpOgogICAgICAgICAg
ICBpZiBvcy5mb3JrKCkgPT0gMDoKICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAgICAg
ICAjIGNoaWxkOiBmYWxsIHRocm91Z2ggaW50byBpdHMgb3duIGxvb3AKCiAgICAjIDFzIHJlY3Yg
dGltZW91dDogKGEpIGxldHMgdGhlIHBlbmRpbmcvZmxvdyBzd2VlcHMgYWN0dWFsbHkgZmlyZSDi
gJQKICAgICMgd2l0aG91dCBpdCBgZXhjZXB0IHNvY2tldC50aW1lb3V0YCBuZXZlciBydW5zOyAo
YikgZW1waXJpY2FsbHkgUkVRVUlSRUQKICAgICMgd2l0aCB0aGUgQlBGIGZpbHRlciBhdHRhY2hl
ZDogYSBmdWxseS1ibG9ja2luZyByZWN2IG9uIHRoaXMga2VybmVsCiAgICAjIHN0YXJ2ZXMgYWZ0
ZXIgdGhlIGZpcnN0IHBhY2tldCwgd2hpbGUgdGhlIHRpbWVvdXQnZCByZWN2IGRlbGl2ZXJzCiAg
ICAjIGNvbnRpbnVvdXNseSAodmVyaWZpZWQgYnkgQS9COiByeD0xIHZzIHJ4PTI5IGlkZW50aWNh
bCBvdGhlcndpc2UpLgogICAgcy5zZXR0aW1lb3V0KDEuMCkKCiAgICBkYmcgPSBvcy5lbnZpcm9u
LmdldCgiTlRfU05JRkZfREVCVUciKSA9PSAiMSIKICAgIGRiZ19yeCA9IDAKICAgIGRiZ19sYXN0
ID0gdGltZS50aW1lKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF06CiAgICAgICAgIyBQb2xsIGluZGVw
ZW5kZW50bHkgb2Ygc29ja2V0IGlkbGUgdGltZS4gQSBidXN5IG1vbml0b3JlZCBpbnRlcmZhY2UK
ICAgICAgICAjIG1heSBuZXZlciByYWlzZSBzb2NrZXQudGltZW91dCwgYnV0IGNvbnRyb2wgY2hh
bmdlcyBtdXN0IHN0aWxsIGFwcGx5LgogICAgICAgIGlmIGNvbnRyb2xfY2xpZW50IGlzIG5vdCBO
b25lIGFuZCB0aW1lLnRpbWUoKSA+PSBjb250cm9sX25leHQ6CiAgICAgICAgICAgIHRyeToKICAg
ICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwgY29udHJvbF9hY3Rpb24sIGNvbnRyb2xfc3RhdHVz
ID0gX3J1bl9jb250cm9sX3RpY2soCiAgICAgICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBj
b250cm9sX3J1biwgY29udHJvbF9jbGllbnQpCiAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBj
b250cm9sOiAlcyIgJSBjb250cm9sX3N0YXR1cykKICAgICAgICAgICAgICAgIGlmIGNvbnRyb2xf
YWN0aW9uID09ICJyZXN0YXJ0IjoKICAgICAgICAgICAgICAgICAgICBhcmdzID0gX3Jlc3RhcnRf
YXJncyhzeXMuYXJndlswXSwgaWZhY2UsIHBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIHZlcmJvc2UsIHdvcmtlcnMsIHdzc2VfYm9keV9ieXRlcykKICAgICAg
ICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiByZS1leGVjdXRpbmcgY2FwdHVyZSB3
aXRoIHVwZGF0ZWQgY29uZmlndXJhdGlvbiIpCiAgICAgICAgICAgICAgICAgICAgcy5jbG9zZSgp
CiAgICAgICAgICAgICAgICAgICAgb3MuZXhlY3Yoc3lzLmV4ZWN1dGFibGUsIGFyZ3MpCiAgICAg
ICAgICAgICAgICBlbGlmIGNvbnRyb2xfYWN0aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgICAg
ICAgICBsb2coInJlbW90ZSBjb250cm9sOiBzdG9wIHJlcXVlc3RlZDsgZXhpdGluZyIpCiAgICAg
ICAgICAgICAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29u
dGludWUKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAg
bG9nKCJXQVJOOiByZW1vdGUgY29udHJvbCB0aWNrIGZhaWxlZCAoJXMpIiAlIG50X2NvbnRyb2wu
c2FmZV9tZXNzYWdlKGUpKQogICAgICAgICAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSAr
IGNvbnRyb2xfaW50ZXJ2YWwKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBrdCA9IHMucmVjdig2
NTUzNSkKICAgICAgICAgICAgZGJnX3J4ICs9IDEKICAgICAgICAgICAgaWYgZGJnIGFuZCB0aW1l
LnRpbWUoKSAtIGRiZ19sYXN0ID4gNToKICAgICAgICAgICAgICAgIGxvZygiREVCVUcgcng9JWQi
ICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAg
IGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICAgICAgaWYgZGJnOgogICAgICAgICAgICAg
ICAgbG9nKCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRi
Z19sYXN0ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAg
ICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6CiAgICAgICAgICAgICAg
ICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAg
ICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0X3MpCiAgICAgICAgICAg
ICAgICBmb3IgZXYgaW4gb3V0X3M6CiAgICAgICAgICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0
ZShqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgICAgICBpZiBvdXRfczoKICAgICAg
ICAgICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICAgICAgICAgIGxhc3Rfc3dl
ZXAgPSBub3cKICAgICAgICAgICAgY29udGludWUKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9y
IGFzIGU6CiAgICAgICAgICAgIGlmIGUuZXJybm8gPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAg
ICAgICBjb250aW51ZQogICAgICAgICAgICByYWlzZQogICAgICAgIG4gPSBsZW4ocGt0KQogICAg
ICAgIGlmIG4gPCAzNDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBvdXQgPSBbXQogICAg
ICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRoZXJuZXQgaGVhZGVyCiAgICAg
ICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBldHlwZSA9PSBFVEhfUF9WTEFO
OgogICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQogICAgICAgICAgICBvZmYgPSAx
OAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAgICAgICAgIGNvbnRpbnVlICAg
ICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlzIHJhcmUKICAgICAgICBp
cDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4gNCAhPSA0IG9yIHViKHBrdCwg
b2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAgY29udGludWUK
ICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAgZnJhZyA9IHUxNihwa3QsIG9m
ZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAgICAgICAgICAgICAgICAgICAg
ICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzcmNf
aXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAgICAgZHN0X2lwID0gbnRvYShw
a3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYgPSBvZmYgKyBpaGwKICAgICAg
ICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAgICAgZG9mZl9mbGFncyA9IHVi
KHBrdCwgdGNwX29mZiArIDEyKQogICAgICAgIGRvZmYgPSAoZG9mZl9mbGFnc1swXSA+PiA0KSAq
IDQKICAgICAgICBwYXlfc3RhcnQgPSB0Y3Bfb2ZmICsgZG9mZgogICAgICAgIGlmIG4gPD0gcGF5
X3N0YXJ0OgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICMgbm8gcGF5bG9hZCBpbiBzZWdtZW50CiAgICAgICAgcGF5bG9hZCA9IHBrdFtwYXlfc3RhcnQ6
XQogICAgICAgIGZsYWdzID0gZG9mZl9mbGFnc1sxXQogICAgICAgIG5vdyA9IHRpbWUudGltZSgp
CgogICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLSBSRVNQT05TRSBkaXJlY3Rpb24gKHNlcnZlciAt
PiBjbGllbnQpIC0tLS0tLS0tLS0KICAgICAgICBpZiBzcG9ydCBpbiBwb3J0cyBhbmQgZHBvcnQg
bm90IGluIHBvcnRzOgogICAgICAgICAgICAjIHBlbmRpbmcga2V5IHdhcyBzdG9yZWQgYXMgKHNl
cnZlcl9pcCwgc2VydmVyX3BvcnQsIGNsaWVudF9pcCwKICAgICAgICAgICAgIyBjbGllbnRfcG9y
dCkgPT0gKHNyYywgc3BvcnQsIGRzdCwgZHBvcnQpIE9GIFRISVMgcmVzcG9uc2UgcGt0CiAgICAg
ICAgICAgIHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgICAgIGlm
IHBheWxvYWRbOjVdID09IGIiSFRUUC8iOgogICAgICAgICAgICAgICAgY29ycmVsYXRlX3Jlc3Bv
bnNlKHBlbmRpbmcsIHJrLCBwYXlsb2FkLCBub3csIG91dCkKICAgICAgICAgICAgZWxpZiBmbGFn
cyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgRklOfFJTVDogZmx1c2ggdW5tYXRjaGVk
CiAgICAgICAgICAgICAgICBldiA9IHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAgICAgIyAtLS0t
LS0tLS0tLS0tLS0tIFJFUVVFU1QgZGlyZWN0aW9uIChjbGllbnQgLT4gc2VydmVyKSAtLS0tLS0t
LS0tLQogICAgICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAgICAgIGlmIGZsYWdzICYg
MHgwNTogICAgICAgICAgICAgICAgICAgICAgIyB0ZWFyZG93biB3L28gcmVzcG9uc2Ugc2Vlbgog
ICAgICAgICAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgICAg
ICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAgICAgICAgIGtleSA9IChzcmNfaXAs
IHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBoYW5kbGVfcGF5bG9hZChmbG93cywg
a2V5LCBOb25lLCBwYXlsb2FkLAogICAgICAgICAgICAgICAgICAgICAgICAgICAoZHN0X2lwLCBk
cG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRzLCBu
b2RlX2hvc3QsIG91dCwgcGVuZGluZywgbm93LAogICAgICAgICAgICAgICAgICAgICAgICAgICB3
c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgaWYgb3V0OgogICAgICAgICAgICB3ID0gc3lzLnN0ZG91
dC53cml0ZQogICAgICAgICAgICBmb3IgZXYgaW4gb3V0OgogICAgICAgICAgICAgICAgdyhqc29u
LmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgIHN5cy5zdGRvdXQuZmx1c2goKQoKICAgICAg
ICBpZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAgICAgICAgICAgc3dlZXBf
aWRsZShmbG93cywgbm93KQogICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgIHN3ZWVw
X3BlbmRpbmcocGVuZGluZywgbm93LCBvdXRfcykKICAgICAgICAgICAgZm9yIGV2IGluIG91dF9z
OgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKGV2KSArICJcbiIp
CiAgICAgICAgICAgIGlmIG91dF9zOgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgp
CiAgICAgICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKCiAgICBvdXRfcyA9IFtdCiAgICBkcmFpbl9w
ZW5kaW5nKHBlbmRpbmcsIG91dF9zKQogICAgZm9yIGV2IGluIG91dF9zOgogICAgICAgIHN5cy5z
dGRvdXQud3JpdGUoanNvbi5kdW1wcyhldikgKyAiXG4iKQogICAgaWYgb3V0X3M6CiAgICAgICAg
c3lzLnN0ZG91dC5mbHVzaCgpCiAgICBsb2coInN0b3BwZWQgKCVkIHBlbmRpbmcgcmVxdWVzdHMg
Zmx1c2hlZCkiICUgbGVuKG91dF9zKSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAg
bWFpbigpCg==
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
PgojaW5jbHVkZSA8c3lzL3N5c2NhbGwuaD4KI2luY2x1ZGUgPHN5cy9tbWFuLmg+CiNpbmNsdWRl
IDxzeXMvc2VsZWN0Lmg+CiNpbmNsdWRlIDxzeXMvdGltZS5oPgojaW5jbHVkZSA8c3lzL3NvY2tl
dC5oPgojaW5jbHVkZSA8c3lzL3R5cGVzLmg+CiNpbmNsdWRlIDx0aW1lLmg+CiNpbmNsdWRlIDx1
bmlzdGQuaD4KI2luY2x1ZGUgPGxpbnV4L2ZpbHRlci5oPgojaW5jbHVkZSA8bGludXgvY2FwYWJp
bGl0eS5oPgojaW5jbHVkZSA8bGludXgvaWZfcGFja2V0Lmg+CiNpbmNsdWRlIDxsaW51eC9pZl9l
dGhlci5oPgojaW5jbHVkZSA8aW9zdHJlYW0+CiNpbmNsdWRlIDxmc3RyZWFtPgojaW5jbHVkZSA8
bWFwPgojaW5jbHVkZSA8c3N0cmVhbT4KI2luY2x1ZGUgPHN0cmluZz4KI2luY2x1ZGUgPHZlY3Rv
cj4KCnN0YXRpYyB2b2xhdGlsZSBzaWdfYXRvbWljX3QgZ19ydW5uaW5nID0gMTsKc3RhdGljIHZv
aWQgc3RvcF9zaWduYWwoaW50KSB7IGdfcnVubmluZyA9IDA7IH0KCnN0YXRpYyBjb25zdCBzaXpl
X3QgTUFYX0ZMT1dTID0gODE5MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUEVORElORyA9IDgx
OTI7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BFTkRJTkdfUEVSX0ZMT1cgPSAzMjsKc3RhdGlj
IGNvbnN0IHNpemVfdCBNQVhfSEVBREVSID0gMjYyMTQ0OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1B
WF9XU1NFX0JPRFlfQllURVMgPSA2NTUzNjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfV1NTRV9C
T0RZX0ZMT1dTID0gMjU2OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NFX1VTRVJOQU1FID0g
MjAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9CQVRDSCA9IDQwMDsKc3RhdGljIGNvbnN0IHNp
emVfdCBNQVhfUVVFVUUgPSA0MDAwOwpzdGF0aWMgY29uc3QgaW50IEZMVVNIX1NFQyA9IDU7CnN0
YXRpYyBjb25zdCBpbnQgUkVUUllfU0VDID0gNjA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9X
X1RUTCA9IDE1OwpzdGF0aWMgY29uc3QgdW5zaWduZWQgUEVORElOR19UVEwgPSAzOwpzdGF0aWMg
Y29uc3QgdW5zaWduZWQgQUNDRVBUID0gMjA0ODsKc3RhdGljIGNvbnN0IGludCBTT19BVFRBQ0hf
RklMVEVSX09MRCA9IDI2OwpzdGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfSVBfSE9T
VCA9IDB4MDgwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNob3J0IEVUSF9QXzgwMjFRX0hPU1Qg
PSAweDgxMDA7CgpzdGF0aWMgc3RkOjpzdHJpbmcgdHJpbShjb25zdCBzdGQ6OnN0cmluZyAmcykg
ewogIHNpemVfdCBhID0gMCwgYiA9IHMuc2l6ZSgpOwogIHdoaWxlIChhIDwgYiAmJiBpc3NwYWNl
KCh1bnNpZ25lZCBjaGFyKXNbYV0pKSArK2E7CiAgd2hpbGUgKGIgPiBhICYmIGlzc3BhY2UoKHVu
c2lnbmVkIGNoYXIpc1tiIC0gMV0pKSAtLWI7CiAgcmV0dXJuIHMuc3Vic3RyKGEsIGIgLSBhKTsK
fQpzdGF0aWMgc3RkOjpzdHJpbmcgbG93ZXIoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6
OnN0cmluZyB4ID0gczsKICBzaXplX3QgaTsgZm9yIChpID0gMDsgaSA8IHguc2l6ZSgpOyArK2kp
IHhbaV0gPSAoY2hhcil0b2xvd2VyKCh1bnNpZ25lZCBjaGFyKXhbaV0pOwogIHJldHVybiB4Owp9
CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29ucShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6
c3RyaW5nIHggPSAiXCIiOyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgcy5zaXplKCk7ICsr
aSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIGlmIChj
ID09ICdcXCcgfHwgYyA9PSAnIicpIHsgeCArPSAnXFwnOyB4ICs9IChjaGFyKWM7IH0KICAgIGVs
c2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1xyJykgeCAr
PSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0JykgeCArPSAiXFx0IjsKICAgIGVsc2UgaWYg
KGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0gKGNoYXIpYzsKICB9CiAgeCArPSAnIic7
IHJldHVybiB4Owp9CnN0YXRpYyBsb25nIGxvbmcgbm93X21zKCkgewogIHN0cnVjdCB0aW1ldmFs
IHR2OyBnZXR0aW1lb2ZkYXkoJnR2LCBOVUxMKTsKICByZXR1cm4gKGxvbmcgbG9uZyl0di50dl9z
ZWMgKiAxMDAwTEwgKyB0di50dl91c2VjIC8gMTAwMDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbnVt
KGxvbmcgdikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsgbyA8PCB2OyByZXR1cm4gby5zdHIoKTsg
fQpzdGF0aWMgYm9vbCB2YWxpZF9wb3J0KHVuc2lnbmVkIHApIHsgcmV0dXJuIHAgPiAwICYmIHAg
PD0gNjU1MzU7IH0Kc3RhdGljIGJvb2wgaGFzX21ldGhvZChjb25zdCBzdGQ6OnN0cmluZyAmbSkg
ewogIHJldHVybiBtID09ICJHRVQiIHx8IG0gPT0gIlBPU1QiIHx8IG0gPT0gIlBVVCIgfHwgbSA9
PSAiREVMRVRFIiB8fAogICAgICAgICBtID09ICJQQVRDSCIgfHwgbSA9PSAiSEVBRCIgfHwgbSA9
PSAiT1BUSU9OUyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGhvc3RfbmFtZSgpIHsKICBjaGFyIGJb
MjU2XTsgaWYgKGdldGhvc3RuYW1lKGIsIHNpemVvZihiKSAtIDEpICE9IDApIHJldHVybiAidW5r
bm93bi1ub2RlIjsKICBiW3NpemVvZihiKSAtIDFdID0gMDsgY2hhciAqcCA9IHN0cmNocihiLCAn
LicpOyBpZiAocCkgKnAgPSAwOyByZXR1cm4gYjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgYjY0ZGVj
b2RlX3VzZXIoY29uc3QgY2hhciAqaW4sIHNpemVfdCBpbl9sZW4pIHsKICB3aGlsZSAoaW5fbGVu
ID4gMCAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKSppbikpIHsgKytpbjsgLS1pbl9sZW47IH0K
ICB3aGlsZSAoaW5fbGVuID4gMCAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKWluW2luX2xlbiAt
IDFdKSkgeyAtLWluX2xlbjsgfQogIHN0ZDo6c3RyaW5nIG91dDsgaW50IHZhbCA9IDAsIGJpdHMg
PSAtODsgc2l6ZV90IGk7CiAgZm9yIChpID0gMDsgaSA8IGluX2xlbjsgKytpKSB7CiAgICB1bnNp
Z25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilpbltpXTsgaW50IGQgPSAtMTsKICAgIGlmIChj
ID49ICdBJyAmJiBjIDw9ICdaJykgZCA9IGMgLSAnQSc7CiAgICBlbHNlIGlmIChjID49ICdhJyAm
JiBjIDw9ICd6JykgZCA9IGMgLSAnYScgKyAyNjsKICAgIGVsc2UgaWYgKGMgPj0gJzAnICYmIGMg
PD0gJzknKSBkID0gYyAtICcwJyArIDUyOwogICAgZWxzZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsK
ICAgIGVsc2UgaWYgKGMgPT0gJy8nKSBkID0gNjM7CiAgICBlbHNlIGlmIChjID09ICc9JykgYnJl
YWs7CiAgICBpZiAoZCA8IDApIGNvbnRpbnVlOwogICAgdmFsID0gKHZhbCA8PCA2KSArIGQ7CiAg
ICBiaXRzICs9IDY7CiAgICBpZiAoYml0cyA+PSAwKSB7CiAgICAgIG91dCArPSAoY2hhcikoKHZh
bCA+PiBiaXRzKSAmIDB4ZmYpOwogICAgICBiaXRzIC09IDg7CiAgICAgIGlmIChvdXQuc2l6ZSgp
ID4gNTEyKSByZXR1cm4gIiI7CiAgICB9CiAgfQogIHNpemVfdCBwID0gb3V0LmZpbmQoJzonKTsK
ICBpZiAocCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuICIiOwogIHJldHVybiBvdXQuc3Vi
c3RyKDAsIHAgPiA2NCA/IDY0IDogcCk7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGlwX3RvX3N0cih1
aW50MzJfdCBpcF9iZSkgewogIGNoYXIgYltJTkVUX0FERFJTVFJMRU5dOwogIGluZXRfbnRvcChB
Rl9JTkVULCAmaXBfYmUsIGIsIHNpemVvZihiKSk7CiAgcmV0dXJuIGI7Cn0KCnN0YXRpYyBzdGQ6
OnN0cmluZyB0cmFjZV9pZF9mcm9tX3BhcmVudChjb25zdCBzdGQ6OnN0cmluZyAmdHApIHsKICBz
dGQ6OnN0cmluZyB4ID0gdHJpbSh0cCk7CiAgaWYgKHguc2l6ZSgpID09IDU1ICYmIHhbMl0gPT0g
Jy0nICYmIHhbMzVdID09ICctJyAmJiB4WzUyXSA9PSAnLScpIHJldHVybiBsb3dlcih4LnN1YnN0
cigzLCAzMikpOwogIHJldHVybiAiIjsKfQoKc3RhdGljIHVpbnQ2NF90IGdfcm5nX3N0YXRlID0g
MDsKc3RhdGljIHZvaWQgaW5pdF9ybmcoKSB7CiAgRklMRSAqZiA9IGZvcGVuKCIvZGV2L3VyYW5k
b20iLCAicmIiKTsKICBpZiAoZikgewogICAgc2l6ZV90IG4gPSBmcmVhZCgmZ19ybmdfc3RhdGUs
IDEsIHNpemVvZihnX3JuZ19zdGF0ZSksIGYpOwogICAgKHZvaWQpbjsKICAgIGZjbG9zZShmKTsK
ICB9CiAgaWYgKCFnX3JuZ19zdGF0ZSkgewogICAgZ19ybmdfc3RhdGUgPSAoKHVpbnQ2NF90KXRp
bWUoTlVMTCkgPDwgMzIpIF4gKHVpbnQ2NF90KWdldHBpZCgpOwogIH0KfQpzdGF0aWMgaW5saW5l
IHVpbnQ2NF90IG5leHRfcm5nKCkgewogIHVpbnQ2NF90IHggPSBnX3JuZ19zdGF0ZTsKICB4IF49
IHggPDwgMTM7IHggXj0geCA+PiA3OyB4IF49IHggPDwgMTc7CiAgcmV0dXJuIGdfcm5nX3N0YXRl
ID0gKHggPyB4IDogMHg4NTNjNDllNjc0OGZlYTliVUxMKTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5n
IG1ha2VfdHJhY2VwYXJlbnQoc3RkOjpzdHJpbmcgKnRpZCkgewogIHVpbnQ2NF90IHIxID0gbmV4
dF9ybmcoKTsKICB1aW50NjRfdCByMiA9IG5leHRfcm5nKCk7CiAgdWludDY0X3QgcjMgPSBuZXh0
X3JuZygpOwogIGNoYXIgYnVmWzY0XTsKICBzbnByaW50ZihidWYsIHNpemVvZihidWYpLCAiMDAt
JTAxNmxseCUwMTZsbHgtJTAxNmxseC0wMSIsCiAgICAgICAgICAgKHVuc2lnbmVkIGxvbmcgbG9u
ZylyMSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMiwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMyk7CiAg
Y2hhciB0aWRfYnVmWzMzXTsKICBzbnByaW50Zih0aWRfYnVmLCBzaXplb2YodGlkX2J1ZiksICIl
MDE2bGx4JTAxNmxseCIsCiAgICAgICAgICAgKHVuc2lnbmVkIGxvbmcgbG9uZylyMSwgKHVuc2ln
bmVkIGxvbmcgbG9uZylyMik7CiAgKnRpZCA9IHRpZF9idWY7CiAgcmV0dXJuIGJ1ZjsKfQoKc3Ry
dWN0IEV2ZW50IHsKICBsb25nIHRzOyBzdGQ6OnN0cmluZyBob3N0LCBzcmMsIHNlcnZpY2UsIG1l
dGhvZCwgcGF0aCwgdXNlciwgc2NoZW1lLCBwcm9iZTsKICBzdGQ6OnN0cmluZyBob3N0X2hkciwg
dXNlcl9hZ2VudCwgeGZmLCBjYWxsZXIsIGRzdF9pcCwgdHJhY2VwYXJlbnQsIHRyYWNlX2lkOwog
IHVuc2lnbmVkIGNhbGxlcl9wb3J0LCBkc3RfcG9ydCwgcmVxX2J5dGVzLCByZXNwX2J5dGVzOyBp
bnQgc3RhdHVzOyBsb25nIGR1cmF0aW9uX21zOwogIGJvb2wgaGFzX3N0YXR1cywgaGFzX2R1cmF0
aW9uLCBoYXNfcmVzcDsKICBFdmVudCgpIDogdHMoMCksIGNhbGxlcl9wb3J0KDApLCBkc3RfcG9y
dCgwKSwgcmVxX2J5dGVzKDApLCByZXNwX2J5dGVzKDApLCBzdGF0dXMoMCksIGR1cmF0aW9uX21z
KDApLCBoYXNfc3RhdHVzKGZhbHNlKSwgaGFzX2R1cmF0aW9uKGZhbHNlKSwgaGFzX3Jlc3AoZmFs
c2UpIHt9Cn07CnN0cnVjdCBSZXF1ZXN0TWV0YSB7CiAgc3RkOjpzdHJpbmcgY29udGVudF90eXBl
LCB0cmFuc2Zlcl9lbmNvZGluZzsKICBzaXplX3QgY29udGVudF9sZW5ndGg7CiAgYm9vbCBoYXNf
Y29udGVudF9sZW5ndGg7CiAgUmVxdWVzdE1ldGEoKSA6IGNvbnRlbnRfbGVuZ3RoKDApLCBoYXNf
Y29udGVudF9sZW5ndGgoZmFsc2UpIHt9Cn07CnN0cnVjdCBGbG93IHsKICBzdGQ6OnN0cmluZyBi
dWY7CiAgdGltZV90IHRvdWNoZWQ7CiAgRXZlbnQgZXZlbnQ7CiAgc2l6ZV90IGJvZHlfZ29hbDsK
ICBib29sIGF3YWl0aW5nX2JvZHk7CiAgRmxvdygpIDogdG91Y2hlZCh0aW1lKE5VTEwpKSwgYm9k
eV9nb2FsKDApLCBhd2FpdGluZ19ib2R5KGZhbHNlKSB7fQp9OwpzdHJ1Y3QgUGVuZGluZyB7CiAg
RXZlbnQgZXY7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbXM7CiAgUGVuZGluZygpIDogc3RhcnRlZF9t
cygwKSB7fQogIFBlbmRpbmcoY29uc3QgRXZlbnQgJmUsIGxvbmcgbG9uZyB0KSA6IGV2KGUpLCBz
dGFydGVkX21zKHQpIHt9Cn07CnN0cnVjdCBGbG93S2V5IHsKICB1aW50MzJfdCBzX2lwOwogIHVp
bnQxNl90IHNwb3J0OwogIHVpbnQzMl90IGRfaXA7CiAgdWludDE2X3QgZHBvcnQ7CiAgYm9vbCBv
cGVyYXRvcjwoY29uc3QgRmxvd0tleSAmeCkgY29uc3QgewogICAgaWYgKHNfaXAgIT0geC5zX2lw
KSByZXR1cm4gc19pcCA8IHguc19pcDsKICAgIGlmIChzcG9ydCAhPSB4LnNwb3J0KSByZXR1cm4g
c3BvcnQgPCB4LnNwb3J0OwogICAgaWYgKGRfaXAgIT0geC5kX2lwKSByZXR1cm4gZF9pcCA8IHgu
ZF9pcDsKICAgIHJldHVybiBkcG9ydCA8IHguZHBvcnQ7CiAgfQp9Owp0eXBlZGVmIEZsb3dLZXkg
UGFja2V0S2V5OwoKc3RhdGljIHZvaWQgbG9nbXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7IGZw
cmludGYoc3RkZXJyLCAibnQtc25pZmYtY3BwOiAlc1xuIiwgcy5jX3N0cigpKTsgZmZsdXNoKHN0
ZGVycik7IH0KCnN0YXRpYyBib29sIHBhcnNlX2RlY2ltYWxfc2l6ZShjb25zdCBjaGFyICpwLCBz
aXplX3Qgbiwgc2l6ZV90ICpvdXQpIHsKICB3aGlsZSAobiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBj
aGFyKSpwKSkgeyArK3A7IC0tbjsgfQogIHdoaWxlIChuICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNo
YXIpcFtuIC0gMV0pKSAtLW47CiAgaWYgKCFuKSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IHZhbHVl
ID0gMDsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IG47ICsraSkgewogICAgaWYgKHBbaV0gPCAn
MCcgfHwgcFtpXSA+ICc5JykgcmV0dXJuIGZhbHNlOwogICAgdW5zaWduZWQgZGlnaXQgPSAodW5z
aWduZWQpKHBbaV0gLSAnMCcpOwogICAgaWYgKHZhbHVlID4gKHNpemVfdCktMSAvIDEwIHx8IHZh
bHVlICogMTAgPiAoc2l6ZV90KS0xIC0gZGlnaXQpIHJldHVybiBmYWxzZTsKICAgIHZhbHVlID0g
dmFsdWUgKiAxMCArIGRpZ2l0OwogIH0KICAqb3V0ID0gdmFsdWU7CiAgcmV0dXJuIHRydWU7Cn0K
CnN0YXRpYyBib29sIHBhcnNlX3JlcXVlc3QoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwg
RXZlbnQgKmUsIFJlcXVlc3RNZXRhICptZXRhKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSAr
IGxlbjsKICBjb25zdCBjaGFyICpwID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3Qg
Y2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNl
OwogIGNvbnN0IGNoYXIgKnNwMSA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICcgJywgZW9sIC0g
cCk7CiAgaWYgKCFzcDEpIHJldHVybiBmYWxzZTsKICBlLT5tZXRob2QuYXNzaWduKHAsIHNwMSAt
IHApOwogIGlmICghaGFzX21ldGhvZChlLT5tZXRob2QpKSByZXR1cm4gZmFsc2U7CgogIGNvbnN0
IGNoYXIgKnBhdGhfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChwYXRoX3N0YXJ0IDwgZW9sICYm
ICpwYXRoX3N0YXJ0ID09ICcgJykgKytwYXRoX3N0YXJ0OwogIGNvbnN0IGNoYXIgKnNwMiA9IChj
b25zdCBjaGFyICopbWVtY2hyKHBhdGhfc3RhcnQsICcgJywgZW9sIC0gcGF0aF9zdGFydCk7CiAg
aWYgKCFzcDIpIHNwMiA9IChlb2wgPiBkYXRhICYmICooZW9sIC0gMSkgPT0gJ1xyJykgPyBlb2wg
LSAxIDogZW9sOwogIGNvbnN0IGNoYXIgKnFtYXJrID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocGF0
aF9zdGFydCwgJz8nLCBzcDIgLSBwYXRoX3N0YXJ0KTsKICBzaXplX3QgcGF0aF9sZW4gPSAocW1h
cmsgPyBxbWFyayA6IHNwMikgLSBwYXRoX3N0YXJ0OwogIGlmIChwYXRoX2xlbiA+IDEyMCkgcGF0
aF9sZW4gPSAxMjA7CiAgZS0+cGF0aC5hc3NpZ24ocGF0aF9zdGFydCwgcGF0aF9sZW4pOwoKICBw
ID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYgKCpwID09ICdccicgfHwgKnAg
PT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2VuZCA9IChjb25zdCBjaGFyICop
bWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5lX2VuZCkgbGluZV9lbmQgPSBl
bmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICc6Jywg
bGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBzaXplX3QgaG5hbWVfbGVuID0g
Y29sb24gLSBwOwogICAgICBjb25zdCBjaGFyICp2YWxfc3RhcnQgPSBjb2xvbiArIDE7CiAgICAg
IHdoaWxlICh2YWxfc3RhcnQgPCBsaW5lX2VuZCAmJiAoKnZhbF9zdGFydCA9PSAnICcgfHwgKnZh
bF9zdGFydCA9PSAnXHQnKSkgKyt2YWxfc3RhcnQ7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9lbmQg
PSBsaW5lX2VuZDsKICAgICAgd2hpbGUgKHZhbF9lbmQgPiB2YWxfc3RhcnQgJiYgKHZhbF9lbmRb
LTFdID09ICdccicgfHwgdmFsX2VuZFstMV0gPT0gJ1xuJyB8fCB2YWxfZW5kWy0xXSA9PSAnICcg
fHwgdmFsX2VuZFstMV0gPT0gJ1x0JykpIC0tdmFsX2VuZDsKICAgICAgc2l6ZV90IHZhbF9sZW4g
PSB2YWxfZW5kIC0gdmFsX3N0YXJ0OwoKICAgICAgaWYgKGhuYW1lX2xlbiA9PSAxMyAmJiAhc3Ry
bmNhc2VjbXAocCwgImF1dGhvcml6YXRpb24iLCAxMykpIHsKICAgICAgICBpZiAodmFsX2xlbiA+
IDYgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJhc2ljICIsIDYpKSB7CiAgICAgICAgICBl
LT51c2VyID0gYjY0ZGVjb2RlX3VzZXIodmFsX3N0YXJ0ICsgNiwgdmFsX2xlbiAtIDYpOwogICAg
ICAgICAgZS0+c2NoZW1lID0gImJhc2ljIjsKICAgICAgICB9IGVsc2UgaWYgKHZhbF9sZW4gPiA3
ICYmICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQsICJCZWFyZXIgIiwgNykpIHsKICAgICAgICAgIGUt
PnNjaGVtZSA9ICJiZWFyZXIiOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4g
PT0gMTEgJiYgIXN0cm5jYXNlY21wKHAsICJ0cmFjZXBhcmVudCIsIDExKSkgewogICAgICAgIGUt
PnRyYWNlcGFyZW50LmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICAgIGUtPnRyYWNl
X2lkID0gdHJhY2VfaWRfZnJvbV9wYXJlbnQoZS0+dHJhY2VwYXJlbnQpOwogICAgICB9IGVsc2Ug
aWYgKGhuYW1lX2xlbiA9PSA0ICYmICFzdHJuY2FzZWNtcChwLCAiaG9zdCIsIDQpKSB7CiAgICAg
ICAgZS0+aG9zdF9oZHIuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBp
ZiAoaG5hbWVfbGVuID09IDEwICYmICFzdHJuY2FzZWNtcChwLCAidXNlci1hZ2VudCIsIDEwKSkg
ewogICAgICAgIGUtPnVzZXJfYWdlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAg
IH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDE1ICYmICFzdHJuY2FzZWNtcChwLCAieC1mb3J3YXJk
ZWQtZm9yIiwgMTUpKSB7CiAgICAgICAgZS0+eGZmLmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4p
OwogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVuID09IDEyICYmICFzdHJuY2FzZWNt
cChwLCAiY29udGVudC10eXBlIiwgMTIpKSB7CiAgICAgICAgbWV0YS0+Y29udGVudF90eXBlLmFz
c2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVf
bGVuID09IDE0ICYmICFzdHJuY2FzZWNtcChwLCAiY29udGVudC1sZW5ndGgiLCAxNCkpIHsKICAg
ICAgICBtZXRhLT5oYXNfY29udGVudF9sZW5ndGggPSBwYXJzZV9kZWNpbWFsX3NpemUodmFsX3N0
YXJ0LCB2YWxfbGVuLCAmbWV0YS0+Y29udGVudF9sZW5ndGgpOwogICAgICB9IGVsc2UgaWYgKG1l
dGEgJiYgaG5hbWVfbGVuID09IDE3ICYmICFzdHJuY2FzZWNtcChwLCAidHJhbnNmZXItZW5jb2Rp
bmciLCAxNykpIHsKICAgICAgICBtZXRhLT50cmFuc2Zlcl9lbmNvZGluZy5hc3NpZ24odmFsX3N0
YXJ0LCB2YWxfbGVuKTsKICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9Cgog
IGlmIChlLT51c2VyLmVtcHR5KCkpIGUtPnVzZXIgPSAiLWFub255bW91cy0iOwogIGlmIChlLT5z
Y2hlbWUuZW1wdHkoKSkgZS0+c2NoZW1lID0gIm5vbmUiOwogIGlmIChlLT50cmFjZV9pZC5lbXB0
eSgpKSBlLT50cmFjZXBhcmVudCA9IG1ha2VfdHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lkKTsKICBy
ZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgaXNfd3NzZV9uYW1lc3BhY2UoY29uc3Qgc3RkOjpz
dHJpbmcgJnVyaSkgewogIHJldHVybiB1cmkgPT0gImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3Jn
L3dzcy8yMDA0LzAxL29hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIg
fHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3
L3NlY2V4dCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93
cy8yMDAyLzEyL3NlY2V4dCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxz
b2FwLm9yZy93cy8yMDAzLzA2L3NlY2V4dCI7Cn0KCnN0YXRpYyBib29sIGlzX3NvYXBfY29udGVu
dF90eXBlKGNvbnN0IHN0ZDo6c3RyaW5nICZ2YWx1ZSkgewogIHN0ZDo6c3RyaW5nIG1lZGlhID0g
bG93ZXIodmFsdWUpOwogIHNpemVfdCBzZW1pID0gbWVkaWEuZmluZCgnOycpOwogIGlmIChzZW1p
ICE9IHN0ZDo6c3RyaW5nOjpucG9zKSBtZWRpYS5lcmFzZShzZW1pKTsKICBtZWRpYSA9IHRyaW0o
bWVkaWEpOwogIHJldHVybiBtZWRpYSA9PSAidGV4dC94bWwiIHx8IG1lZGlhID09ICJhcHBsaWNh
dGlvbi94bWwiIHx8CiAgICAgICAgIG1lZGlhID09ICJhcHBsaWNhdGlvbi9zb2FwK3htbCIgfHwK
ICAgICAgICAgKG1lZGlhLnNpemUoKSA+IDQgJiYgbWVkaWEuY29tcGFyZShtZWRpYS5zaXplKCkg
LSA0LCA0LCAiK3htbCIpID09IDApOwp9CgpzdGF0aWMgdm9pZCBzcGxpdF9xbmFtZShjb25zdCBz
dGQ6OnN0cmluZyAmbmFtZSwgc3RkOjpzdHJpbmcgKnByZWZpeCwgc3RkOjpzdHJpbmcgKmxvY2Fs
KSB7CiAgc2l6ZV90IGNvbG9uID0gbmFtZS5maW5kKCc6Jyk7CiAgaWYgKGNvbG9uID09IHN0ZDo6
c3RyaW5nOjpucG9zKSB7IHByZWZpeC0+Y2xlYXIoKTsgKmxvY2FsID0gbmFtZTsgfQogIGVsc2Ug
eyAqcHJlZml4ID0gbmFtZS5zdWJzdHIoMCwgY29sb24pOyAqbG9jYWwgPSBuYW1lLnN1YnN0cihj
b2xvbiArIDEpOyB9Cn0KCnN0YXRpYyBib29sIGFwcGVuZF91dGY4KHVuc2lnbmVkIGxvbmcgY3As
IHN0ZDo6c3RyaW5nICpvdXQpIHsKICBpZiAoY3AgPT0gMCB8fCBjcCA+IDB4MTBmZmZmVUwgfHwg
KGNwID49IDB4ZDgwMFVMICYmIGNwIDw9IDB4ZGZmZlVMKSkgcmV0dXJuIGZhbHNlOwogIGlmIChj
cCA8IDB4ODApIG91dC0+cHVzaF9iYWNrKChjaGFyKWNwKTsKICBlbHNlIGlmIChjcCA8IDB4ODAw
KSB7CiAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHhjMCB8IChjcCA+PiA2KSkpOwogICAgb3V0
LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoY3AgJiAweDNmKSkpOwogIH0gZWxzZSBpZiAoY3Ag
PCAweDEwMDAwKSB7CiAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHhlMCB8IChjcCA+PiAxMikp
KTsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKChjcCA+PiA2KSAmIDB4M2YpKSk7
CiAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfSBlbHNl
IHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGYwIHwgKGNwID4+IDE4KSkpOwogICAgb3V0
LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoKGNwID4+IDEyKSAmIDB4M2YpKSk7CiAgICBvdXQt
PnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgoY3AgPj4gNikgJiAweDNmKSkpOwogICAgb3V0LT5w
dXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoY3AgJiAweDNmKSkpOwogIH0KICByZXR1cm4gdHJ1ZTsK
fQoKc3RhdGljIGJvb2wgeG1sX3VuZXNjYXBlKGNvbnN0IHN0ZDo6c3RyaW5nICZ0ZXh0LCBzdGQ6
OnN0cmluZyAqb3V0KSB7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCB0ZXh0LnNpemUoKTspIHsK
ICAgIGlmICh0ZXh0W2ldICE9ICcmJykgeyBvdXQtPnB1c2hfYmFjayh0ZXh0W2krK10pOyBjb250
aW51ZTsgfQogICAgc2l6ZV90IHNlbWkgPSB0ZXh0LmZpbmQoJzsnLCBpICsgMSk7CiAgICBpZiAo
c2VtaSA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBzZW1pIC0gaSA+IDEyKSByZXR1cm4gZmFsc2U7
CiAgICBzdGQ6OnN0cmluZyBlbnQgPSB0ZXh0LnN1YnN0cihpICsgMSwgc2VtaSAtIGkgLSAxKTsK
ICAgIGlmIChlbnQgPT0gImFtcCIpIG91dC0+cHVzaF9iYWNrKCcmJyk7CiAgICBlbHNlIGlmIChl
bnQgPT0gImx0Iikgb3V0LT5wdXNoX2JhY2soJzwnKTsKICAgIGVsc2UgaWYgKGVudCA9PSAiZ3Qi
KSBvdXQtPnB1c2hfYmFjaygnPicpOwogICAgZWxzZSBpZiAoZW50ID09ICJxdW90Iikgb3V0LT5w
dXNoX2JhY2soJyInKTsKICAgIGVsc2UgaWYgKGVudCA9PSAiYXBvcyIpIG91dC0+cHVzaF9iYWNr
KCdcJycpOwogICAgZWxzZSBpZiAoIWVudC5lbXB0eSgpICYmIGVudFswXSA9PSAnIycpIHsKICAg
ICAgY2hhciAqZW5kcCA9IE5VTEw7CiAgICAgIHVuc2lnbmVkIGxvbmcgY3AgPSBzdHJ0b3VsKGVu
dC5jX3N0cigpICsgKChlbnQuc2l6ZSgpID4gMSAmJiAoZW50WzFdID09ICd4JyB8fCBlbnRbMV0g
PT0gJ1gnKSkgPyAyIDogMSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICZlbmRw
LCAoZW50LnNpemUoKSA+IDEgJiYgKGVudFsxXSA9PSAneCcgfHwgZW50WzFdID09ICdYJykpID8g
MTYgOiAxMCk7CiAgICAgIGlmICghZW5kcCB8fCAqZW5kcCB8fCAhYXBwZW5kX3V0ZjgoY3AsIG91
dCkpIHJldHVybiBmYWxzZTsKICAgIH0gZWxzZSByZXR1cm4gZmFsc2U7CiAgICBpID0gc2VtaSAr
IDE7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCB2YWxpZF91dGY4X3VzZXJuYW1l
KGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgaWYgKHMuZW1wdHkoKSB8fCBzLnNpemUoKSA+IE1B
WF9XU1NFX1VTRVJOQU1FICogNCkgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBjaGFyYWN0ZXJzID0g
MDsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOykgewogICAgdW5zaWduZWQgY2hh
ciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIHVuc2lnbmVkIGxvbmcgY3AgPSBjOwogICAg
aWYgKGMgPCAweDgwKSB7ICsraTsgfQogICAgZWxzZSB7CiAgICBzaXplX3QgbmVlZCA9IChjID49
IDB4YzIgJiYgYyA8PSAweGRmKSA/IDEgOgogICAgICAgICAgICAgICAgICAoYyA+PSAweGUwICYm
IGMgPD0gMHhlZikgPyAyIDoKICAgICAgICAgICAgICAgICAgKGMgPj0gMHhmMCAmJiBjIDw9IDB4
ZjQpID8gMyA6IDk5OwogICAgaWYgKG5lZWQgPT0gOTkgfHwgaSArIG5lZWQgPj0gcy5zaXplKCkp
IHJldHVybiBmYWxzZTsKICAgIGZvciAoc2l6ZV90IGogPSAxOyBqIDw9IG5lZWQ7ICsraikKICAg
ICAgaWYgKCgodW5zaWduZWQgY2hhcilzW2kgKyBqXSAmIDB4YzApICE9IDB4ODApIHJldHVybiBm
YWxzZTsKICAgIGlmIChuZWVkID09IDIgJiYgYyA9PSAweGUwICYmICh1bnNpZ25lZCBjaGFyKXNb
aSArIDFdIDwgMHhhMCkgcmV0dXJuIGZhbHNlOwogICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4
ZWQgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPj0gMHhhMCkgcmV0dXJuIGZhbHNlOwogICAg
aWYgKG5lZWQgPT0gMyAmJiBjID09IDB4ZjAgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPCAw
eDkwKSByZXR1cm4gZmFsc2U7CiAgICBpZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmNCAmJiAodW5z
aWduZWQgY2hhcilzW2kgKyAxXSA+PSAweDkwKSByZXR1cm4gZmFsc2U7CiAgICBjcCA9IGMgJiAo
KDFVIDw8ICg3IC0gbmVlZCAtIDEpKSAtIDEpOwogICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0g
bmVlZDsgKytqKSBjcCA9IChjcCA8PCA2KSB8ICgodW5zaWduZWQgY2hhcilzW2kgKyBqXSAmIDB4
M2YpOwogICAgaSArPSBuZWVkICsgMTsKICAgIH0KICAgIGlmICgrK2NoYXJhY3RlcnMgPiBNQVhf
V1NTRV9VU0VSTkFNRSkgcmV0dXJuIGZhbHNlOwogICAgaWYgKGNwIDwgMHgyMCB8fCAoY3AgPj0g
MHg3ZiAmJiBjcCA8PSAweDlmKSB8fAogICAgICAgIChjcCA+PSAweGUwMDAgJiYgY3AgPD0gMHhm
OGZmKSB8fAogICAgICAgIChjcCA+PSAweGYwMDAwICYmIGNwIDw9IDB4ZmZmZmQpIHx8CiAgICAg
ICAgKGNwID49IDB4MTAwMDAwICYmIGNwIDw9IDB4MTBmZmZkKSB8fAogICAgICAgIChjcCA+PSAw
eGZkZDAgJiYgY3AgPD0gMHhmZGVmKSB8fCAoY3AgJiAweGZmZmZVTCkgPj0gMHhmZmZlVUwgfHwK
ICAgICAgICBjcCA9PSAweDAwYWQgfHwgY3AgPT0gMHgwNjFjIHx8IGNwID09IDB4MDZkZCB8fCBj
cCA9PSAweDA3MGYgfHwKICAgICAgICBjcCA9PSAweDE4MGUgfHwgKGNwID49IDB4MjAwYiAmJiBj
cCA8PSAweDIwMGYpIHx8CiAgICAgICAgKGNwID49IDB4MjAyYSAmJiBjcCA8PSAweDIwMmUpIHx8
IChjcCA+PSAweDIwNjAgJiYgY3AgPD0gMHgyMDZmKSB8fAogICAgICAgIGNwID09IDB4ZmVmZikg
cmV0dXJuIGZhbHNlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RydWN0IFhtbEZyYW1lIHsKICBz
dGQ6Om1hcDxzdGQ6OnN0cmluZywgc3RkOjpzdHJpbmc+IG5zOwogIHN0ZDo6c3RyaW5nIHFuYW1l
LCB1cmksIGxvY2FsOwp9OwoKc3RhdGljIGJvb2wgcGFyc2VfeG1sX25hbWUoY29uc3Qgc3RkOjpz
dHJpbmcgJmJvZHksIHNpemVfdCBsaW1pdCwgc2l6ZV90ICpwb3MsCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgIHN0ZDo6c3RyaW5nICpuYW1lKSB7CiAgc2l6ZV90IHN0YXJ0ID0gKnBvczsKICB3
aGlsZSAoKnBvcyA8IGxpbWl0KSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hh
cilib2R5Wypwb3NdOwogICAgaWYgKCEoaXNhbG51bShjKSB8fCBjID09ICdfJyB8fCBjID09ICct
JyB8fCBjID09ICcuJyB8fCBjID09ICc6JykpIGJyZWFrOwogICAgKysqcG9zOwogIH0KICBpZiAo
KnBvcyA9PSBzdGFydCB8fCAqcG9zIC0gc3RhcnQgPiAyNTYpIHJldHVybiBmYWxzZTsKICBuYW1l
LT5hc3NpZ24oYm9keSwgc3RhcnQsICpwb3MgLSBzdGFydCk7CiAgcmV0dXJuIHRydWU7Cn0KCnN0
YXRpYyBzdGQ6OnN0cmluZyBleHRyYWN0X3dzc2VfdXNlcm5hbWUoY29uc3Qgc3RkOjpzdHJpbmcg
JmJvZHkpIHsKICBpZiAoYm9keS5lbXB0eSgpIHx8IGJvZHkuc2l6ZSgpID4gTUFYX1dTU0VfQk9E
WV9CWVRFUyB8fAogICAgICBib2R5LmZpbmQoJ1wwJykgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJl
dHVybiAiIjsKICBzdGQ6OnN0cmluZyBsb3dlcmVkID0gbG93ZXIoYm9keSk7CiAgaWYgKGxvd2Vy
ZWQuZmluZCgiPCFkb2N0eXBlIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwKICAgICAgbG93ZXJl
ZC5maW5kKCI8IWVudGl0eSIpICE9IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CgogIHN0
ZDo6dmVjdG9yPFhtbEZyYW1lPiBzdGFjazsKICBzaXplX3QgdG9rZW5fZGVwdGggPSAwLCB1c2Vy
bmFtZV9kZXB0aCA9IDAsIHBvcyA9IDA7CiAgc3RkOjpzdHJpbmcgdG9rZW5fdXJpLCBjaGFycywg
cmVzdWx0OwogIGJvb2wgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgd2hpbGUgKHBvcyA8IGJvZHku
c2l6ZSgpKSB7CiAgICBzaXplX3QgbHQgPSBib2R5LmZpbmQoJzwnLCBwb3MpOwogICAgaWYgKGx0
ID09IHN0ZDo6c3RyaW5nOjpucG9zKSB7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCAmJiAhdXNl
cm5hbWVfYmFkICYmICF4bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIocG9zKSwgJmNoYXJzKSkgdXNl
cm5hbWVfYmFkID0gdHJ1ZTsKICAgICAgYnJlYWs7IC8qIGEgYm91bmRlZCBwcmVmaXggaXMgY29t
bW9ubHkgaW5jb21wbGV0ZSAqLwogICAgfQogICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2Vy
bmFtZV9iYWQgJiYgbHQgPiBwb3MgJiYKICAgICAgICAheG1sX3VuZXNjYXBlKGJvZHkuc3Vic3Ry
KHBvcywgbHQgLSBwb3MpLCAmY2hhcnMpKSB1c2VybmFtZV9iYWQgPSB0cnVlOwogICAgaWYgKGNo
YXJzLnNpemUoKSA+IE1BWF9XU1NFX1VTRVJOQU1FICogNCArIDIpIHsgY2hhcnMuY2xlYXIoKTsg
dXNlcm5hbWVfYmFkID0gdHJ1ZTsgfQoKICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDQsICI8IS0t
IikgPT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5maW5kKCItLT4iLCBsdCArIDQpOyBp
ZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAgICAgcG9zID0gZW5kICsgMzsg
Y29udGludWU7CiAgICB9CiAgICBpZiAoYm9keS5jb21wYXJlKGx0LCA5LCAiPCFbQ0RBVEFbIikg
PT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5maW5kKCJdXT4iLCBsdCArIDkpOyBpZiAo
ZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRo
ICYmICF1c2VybmFtZV9iYWQpIGNoYXJzLmFwcGVuZChib2R5LCBsdCArIDksIGVuZCAtIGx0IC0g
OSk7CiAgICAgIHBvcyA9IGVuZCArIDM7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29t
cGFyZShsdCwgMiwgIjw/IikgPT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5maW5kKCI/
PiIsIGx0ICsgMik7IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBw
b3MgPSBlbmQgKyAyOyBjb250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDIs
ICI8ISIpID09IDApIHJldHVybiAiIjsKCiAgICBib29sIGNsb3NpbmcgPSAobHQgKyAxIDwgYm9k
eS5zaXplKCkgJiYgYm9keVtsdCArIDFdID09ICcvJyk7CiAgICBzaXplX3QgcCA9IGx0ICsgKGNs
b3NpbmcgPyAyIDogMSk7CiAgICBzdGQ6OnN0cmluZyBxbmFtZTsKICAgIGlmICghcGFyc2VfeG1s
X25hbWUoYm9keSwgYm9keS5zaXplKCksICZwLCAmcW5hbWUpKSBicmVhazsKICAgIGlmIChjbG9z
aW5nKSB7CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQg
Y2hhcilib2R5W3BdKSkgKytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSB8fCBib2R5W3Bd
ICE9ICc+JykgYnJlYWs7CiAgICAgIGlmIChzdGFjay5lbXB0eSgpKSBicmVhazsKICAgICAgc3Rk
OjpzdHJpbmcgcHJlZml4LCBsb2NhbDsgc3BsaXRfcW5hbWUocW5hbWUsICZwcmVmaXgsICZsb2Nh
bCk7CiAgICAgIFhtbEZyYW1lICZ0b3AgPSBzdGFjay5iYWNrKCk7CiAgICAgIGlmICh0b3AucW5h
bWUgIT0gcW5hbWUgfHwgdG9wLmxvY2FsICE9IGxvY2FsKSBicmVhazsKICAgICAgc2l6ZV90IGRl
cHRoID0gc3RhY2suc2l6ZSgpOwogICAgICBpZiAodXNlcm5hbWVfZGVwdGggPT0gZGVwdGgpIHsK
ICAgICAgICBzdGQ6OnN0cmluZyB1c2VybmFtZSA9IHRyaW0oY2hhcnMpOwogICAgICAgIGlmICgh
dXNlcm5hbWVfYmFkICYmIHZhbGlkX3V0ZjhfdXNlcm5hbWUodXNlcm5hbWUpICYmIHJlc3VsdC5l
bXB0eSgpKSByZXN1bHQgPSB1c2VybmFtZTsKICAgICAgICB1c2VybmFtZV9kZXB0aCA9IDA7IGNo
YXJzLmNsZWFyKCk7IHVzZXJuYW1lX2JhZCA9IGZhbHNlOwogICAgICB9CiAgICAgIGlmICh0b2tl
bl9kZXB0aCA9PSBkZXB0aCkgeyB0b2tlbl9kZXB0aCA9IDA7IHRva2VuX3VyaS5jbGVhcigpOyB9
CiAgICAgIHN0YWNrLnBvcF9iYWNrKCk7IHBvcyA9IHAgKyAxOwogICAgICBpZiAoIXJlc3VsdC5l
bXB0eSgpKSByZXR1cm4gcmVzdWx0OwogICAgICBjb250aW51ZTsKICAgIH0KCiAgICBYbWxGcmFt
ZSBmcmFtZTsKICAgIGlmIChzdGFjay5zaXplKCkgPj0gNjQpIHJldHVybiAiIjsKICAgIGlmICgh
c3RhY2suZW1wdHkoKSkgZnJhbWUubnMgPSBzdGFjay5iYWNrKCkubnM7CiAgICBib29sIHNlbGZf
Y2xvc2luZyA9IGZhbHNlLCBjb21wbGV0ZSA9IGZhbHNlOwogICAgc2l6ZV90IGF0dHJfY291bnQg
PSAwOwogICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSkgewogICAgICB3aGlsZSAocCA8IGJvZHku
c2l6ZSgpICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYg
KHAgPj0gYm9keS5zaXplKCkpIGJyZWFrOwogICAgICBpZiAoYm9keVtwXSA9PSAnPicpIHsgKytw
OyBjb21wbGV0ZSA9IHRydWU7IGJyZWFrOyB9CiAgICAgIGlmIChib2R5W3BdID09ICcvJyAmJiBw
ICsgMSA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbcCArIDFdID09ICc+JykgewogICAgICAgIHAgKz0g
Mjsgc2VsZl9jbG9zaW5nID0gdHJ1ZTsgY29tcGxldGUgPSB0cnVlOyBicmVhazsKICAgICAgfQog
ICAgICBzdGQ6OnN0cmluZyBhbmFtZTsKICAgICAgaWYgKCFwYXJzZV94bWxfbmFtZShib2R5LCBi
b2R5LnNpemUoKSwgJnAsICZhbmFtZSkpIGJyZWFrOwogICAgICBpZiAoKythdHRyX2NvdW50ID4g
MTI4KSByZXR1cm4gIiI7CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgo
dW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSB8
fCBib2R5W3ArK10gIT0gJz0nKSBicmVhazsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAm
JiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJv
ZHkuc2l6ZSgpIHx8IChib2R5W3BdICE9ICdcJycgJiYgYm9keVtwXSAhPSAnIicpKSBicmVhazsK
ICAgICAgY2hhciBxdW90ZSA9IGJvZHlbcCsrXTsgc2l6ZV90IHZhbHVlX3N0YXJ0ID0gcDsKICAg
ICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBib2R5W3BdICE9IHF1b3RlKSArK3A7CiAgICAg
IGlmIChwID49IGJvZHkuc2l6ZSgpKSBicmVhazsKICAgICAgc3RkOjpzdHJpbmcgdmFsdWU7CiAg
ICAgIGlmICgheG1sX3VuZXNjYXBlKGJvZHkuc3Vic3RyKHZhbHVlX3N0YXJ0LCBwIC0gdmFsdWVf
c3RhcnQpLCAmdmFsdWUpKSByZXR1cm4gIiI7CiAgICAgICsrcDsKICAgICAgaWYgKGFuYW1lID09
ICJ4bWxucyIpIGZyYW1lLm5zWyIiXSA9IHZhbHVlOwogICAgICBlbHNlIGlmIChhbmFtZS5jb21w
YXJlKDAsIDYsICJ4bWxuczoiKSA9PSAwKSBmcmFtZS5uc1thbmFtZS5zdWJzdHIoNildID0gdmFs
dWU7CiAgICAgIGlmIChmcmFtZS5ucy5zaXplKCkgPiA2NCkgcmV0dXJuICIiOwogICAgfQogICAg
aWYgKCFjb21wbGV0ZSkgYnJlYWs7CiAgICBzdGQ6OnN0cmluZyBwcmVmaXgsIGxvY2FsOyBzcGxp
dF9xbmFtZShxbmFtZSwgJnByZWZpeCwgJmxvY2FsKTsKICAgIHN0ZDo6bWFwPHN0ZDo6c3RyaW5n
LCBzdGQ6OnN0cmluZz46OmNvbnN0X2l0ZXJhdG9yIG5zID0gZnJhbWUubnMuZmluZChwcmVmaXgp
OwogICAgZnJhbWUudXJpID0gKG5zID09IGZyYW1lLm5zLmVuZCgpKSA/ICIiIDogbnMtPnNlY29u
ZDsKICAgIGZyYW1lLnFuYW1lID0gcW5hbWU7CiAgICBmcmFtZS5sb2NhbCA9IGxvY2FsOwogICAg
c3RhY2sucHVzaF9iYWNrKGZyYW1lKTsKICAgIHNpemVfdCBkZXB0aCA9IHN0YWNrLnNpemUoKTsK
ICAgIGlmICghdG9rZW5fZGVwdGggJiYgbG9jYWwgPT0gIlVzZXJuYW1lVG9rZW4iICYmIGlzX3dz
c2VfbmFtZXNwYWNlKGZyYW1lLnVyaSkpIHsKICAgICAgdG9rZW5fZGVwdGggPSBkZXB0aDsgdG9r
ZW5fdXJpID0gZnJhbWUudXJpOwogICAgfSBlbHNlIGlmICh0b2tlbl9kZXB0aCAmJiBkZXB0aCA9
PSB0b2tlbl9kZXB0aCArIDEgJiYKICAgICAgICAgICAgICAgbG9jYWwgPT0gIlVzZXJuYW1lIiAm
JiBmcmFtZS51cmkgPT0gdG9rZW5fdXJpKSB7CiAgICAgIHVzZXJuYW1lX2RlcHRoID0gZGVwdGg7
IGNoYXJzLmNsZWFyKCk7IHVzZXJuYW1lX2JhZCA9IGZhbHNlOwogICAgfQogICAgaWYgKHNlbGZf
Y2xvc2luZykgewogICAgICBpZiAodXNlcm5hbWVfZGVwdGggPT0gZGVwdGgpIHVzZXJuYW1lX2Rl
cHRoID0gMDsKICAgICAgaWYgKHRva2VuX2RlcHRoID09IGRlcHRoKSB7IHRva2VuX2RlcHRoID0g
MDsgdG9rZW5fdXJpLmNsZWFyKCk7IH0KICAgICAgc3RhY2sucG9wX2JhY2soKTsKICAgIH0KICAg
IHBvcyA9IHA7CiAgfQogIHJldHVybiByZXN1bHQ7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3Jlc3Bv
bnNlKGNvbnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4sIGludCAqc3RhdHVzLCB1bnNpZ25lZCAq
Y2xlbikgewogIGNvbnN0IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9
IGRhdGE7CiAgY29uc3QgY2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywg
ZW5kIC0gcCk7CiAgaWYgKCFlb2wpIHJldHVybiBmYWxzZTsKICBpZiAoc3RybmNtcChwLCAiSFRU
UC8iLCA1KSAhPSAwKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNo
YXIgKiltZW1jaHIocCwgJyAnLCBlb2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwog
IGNvbnN0IGNoYXIgKnNjX3N0YXJ0ID0gc3AxICsgMTsKICB3aGlsZSAoc2Nfc3RhcnQgPCBlb2wg
JiYgKnNjX3N0YXJ0ID09ICcgJykgKytzY19zdGFydDsKICAqc3RhdHVzID0gYXRvaShzY19zdGFy
dCk7CiAgaWYgKCpzdGF0dXMgPCAxMDAgfHwgKnN0YXR1cyA+IDU5OSkgcmV0dXJuIGZhbHNlOwog
ICpjbGVuID0gMDsKICBwID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYgKCpw
ID09ICdccicgfHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2VuZCA9
IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5lX2Vu
ZCkgbGluZV9lbmQgPSBlbmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFyICop
bWVtY2hyKHAsICc6JywgbGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBzaXpl
X3QgaGxlbiA9IGNvbG9uIC0gcDsKICAgICAgaWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21w
KHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewogICAgICAgIGNvbnN0IGNoYXIgKnYgPSBjb2xv
biArIDE7CiAgICAgICAgd2hpbGUgKHYgPCBsaW5lX2VuZCAmJiAoKnYgPT0gJyAnIHx8ICp2ID09
ICdcdCcpKSArK3Y7CiAgICAgICAgbG9uZyBuID0gYXRvbCh2KTsKICAgICAgICBpZiAobiA+PSAw
ICYmIG4gPD0gMHg3ZmZmZmZmZikgKmNsZW4gPSAodW5zaWduZWQpbjsKICAgICAgfQogICAgfQog
ICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6OnN0
cmluZyBnX2VuZHBvaW50OwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRpYyBz
dGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gZ19zaGlwX2J1ZjsKCnN0YXRpYyBzdGQ6OnN0cmluZyBz
aGVsbHEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZv
ciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcnKSBv
ICs9ICInXFwnJyI7IGVsc2UgbyArPSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIG51bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFt
IG87IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25fYXJy
YXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcgbyA9
ICJbIjsgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBvICs9
ICIsIjsgbyArPSBhW2ldOyB9IHJldHVybiBvICsgIl0iOwp9CnN0YXRpYyBib29sIHBvc3QoY29u
c3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qg
c3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHkgPSAi
e1wibm9kZVwiOiIgKyBqc29ucShub2RlKSArICIsXCJldmVudHNcIjoiICsganNvbl9hcnJheShi
YXRjaCkgKyAifSI7CiAgc3RkOjpzdHJpbmcgY21kID0gImN1cmwgLXNTZiAtLW1heC10aW1lIDEw
IC1vIC9kZXYvbnVsbCAtSCAnQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uJyAtLWRhdGEt
YmluYXJ5IEAtICIgKyBzaGVsbHEoZW5kcG9pbnQgKyAiL2FwaS9pbmdlc3QiKTsKICBGSUxFICpm
cCA9IHBvcGVuKGNtZC5jX3N0cigpLCAidyIpOyBpZiAoIWZwKSByZXR1cm4gZmFsc2U7CiAgZndy
aXRlKGJvZHkuZGF0YSgpLCAxLCBib2R5LnNpemUoKSwgZnApOwogIGludCByYyA9IHBjbG9zZShm
cCk7CiAgcmV0dXJuIFdJRkVYSVRFRChyYykgJiYgV0VYSVRTVEFUVVMocmMpID09IDA7Cn0Kc3Rh
dGljIHZvaWQgc2VuZF9iYXRjaGVzKGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCwgY29uc3Qg
c3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6OnZlY3Rvcjxz
dGQ6OnN0cmluZz4gKmJ1ZiwgYm9vbCBmbHVzaF9hbGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1wdHko
KSAmJiAoZmx1c2hfYWxsIHx8IGJ1Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCkpIHsKICAgIHNpemVf
dCBuID0gYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIID8gTUFYX0JBVENIIDogYnVmLT5zaXplKCk7
CiAgICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gYmF0Y2goYnVmLT5iZWdpbigpLCBidWYtPmJl
Z2luKCkgKyBuKTsKICAgIGlmIChwb3N0KGVuZHBvaW50LCBub2RlLCBiYXRjaCkpIHsKICAgICAg
YnVmLT5lcmFzZShidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4oKSArIG4pOwogICAgICBsb2dtc2co
ImZsdXNoZWQgIiArIG51bWJlcl9zdHJpbmcobikgKyAiIGV2ZW50cyIpOwogICAgfSBlbHNlIHsK
ICAgICAgLyogUHVyZSBpbi1tZW1vcnkgZHJvcCB3aGVuIEh1YiB1bnJlYWNoYWJsZSAoemVybyBk
aXNrIEkvTykgKi8KICAgICAgYnVmLT5lcmFzZShidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4oKSAr
IG4pOwogICAgICBsb2dtc2coIldBUk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAiICsgbnVt
YmVyX3N0cmluZyhuKSArICIgZXZlbnRzIChpbi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTykiKTsK
ICAgICAgYnJlYWs7CiAgICB9CiAgfQp9CgpzdGF0aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0IEV2
ZW50ICZlKSB7CiAgc3RkOjpvc3RyaW5nc3RyZWFtIHNzOwogIHNzIDw8ICJ7XCJ0c1wiOiIgPDwg
ZS50cyA8PCAiLFwiaG9zdFwiOiIgPDwganNvbnEoZS5ob3N0KSA8PCAiLFwic3JjXCI6XCJwY2Fw
XCIsXCJzZXJ2aWNlXCI6IiA8PCBqc29ucShlLnNlcnZpY2UpCiAgICAgPDwgIixcIm1ldGhvZFwi
OiIgPDwganNvbnEoZS5tZXRob2QpIDw8ICIsXCJwYXRoXCI6IiA8PCBqc29ucShlLnBhdGgpIDw8
ICIsXCJ1c2VyXCI6IiA8PCBqc29ucShlLnVzZXIpCiAgICAgPDwgIixcInNjaGVtZVwiOiIgPDwg
anNvbnEoZS5zY2hlbWUpIDw8ICIsXCJzb3VyY2VfcHJvYmVcIjpcInBjYXAtaHR0cC1jcHBcIixc
Imhvc3RfaGRyXCI6IiA8PCBqc29ucShlLmhvc3RfaGRyKQogICAgIDw8ICIsXCJ1c2VyX2FnZW50
XCI6IiA8PCBqc29ucShlLnVzZXJfYWdlbnQpIDw8ICIsXCJ4X2ZvcndhcmRlZF9mb3JcIjoiIDw8
IGpzb25xKGUueGZmKQogICAgIDw8ICIsXCJjYWxsZXJcIjoiIDw8IGpzb25xKGUuY2FsbGVyKSA8
PCAiLFwiY2FsbGVyX3BvcnRcIjoiIDw8IGUuY2FsbGVyX3BvcnQgPDwgIixcImRzdF9pcFwiOiIg
PDwganNvbnEoZS5kc3RfaXApCiAgICAgPDwgIixcImRzdF9wb3J0XCI6IiA8PCBlLmRzdF9wb3J0
IDw8ICIsXCJ0cmFjZXBhcmVudFwiOiIgPDwganNvbnEoZS50cmFjZXBhcmVudCkgPDwgIixcInRy
YWNlX2lkXCI6IiA8PCBqc29ucShlLnRyYWNlX2lkKQogICAgIDw8ICIsXCJzZXJ2aWNlX2lkXCI6
bnVsbCxcIm1vZHVsZV9pZFwiOlwicGNhcC1odHRwLWNwcFwiLFwicmVxX2J5dGVzXCI6IiA8PCBl
LnJlcV9ieXRlczsKICBpZiAoZS5oYXNfc3RhdHVzKSBzcyA8PCAiLFwic3RhdHVzXCI6IiA8PCBl
LnN0YXR1czsgZWxzZSBzcyA8PCAiLFwic3RhdHVzXCI6bnVsbCI7CiAgaWYgKGUuaGFzX2R1cmF0
aW9uKSBzcyA8PCAiLFwiZHVyYXRpb25fbXNcIjoiIDw8IGUuZHVyYXRpb25fbXM7IGVsc2Ugc3Mg
PDwgIixcImR1cmF0aW9uX21zXCI6bnVsbCI7CiAgaWYgKGUuaGFzX3Jlc3ApIHNzIDw8ICIsXCJy
ZXNwX2J5dGVzXCI6IiA8PCBlLnJlc3BfYnl0ZXM7IGVsc2Ugc3MgPDwgIixcInJlc3BfYnl0ZXNc
IjpudWxsIjsKICBzcyA8PCAifSI7CgogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBp
ZiAoZ19zaGlwX2J1Zi5zaXplKCkgPj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9idWYuZXJh
c2UoZ19zaGlwX2J1Zi5iZWdpbigpKTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNrKHNz
LnN0cigpKTsKICB9IGVsc2UgewogICAgc3RkOjpjb3V0IDw8IHNzLnN0cigpIDw8ICJcbiI7CiAg
fQp9CgpzdGF0aWMgdm9pZCBmbHVzaF9vbGRlc3Qoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZl
Y3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgaWYgKHBlbmRpbmcuZW1wdHkoKSkgcmV0dXJu
OwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3Ig
aXQgPSBwZW5kaW5nLmJlZ2luKCk7CiAgaWYgKCFpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgIGVt
aXRfZXZlbnQoaXQtPnNlY29uZFswXS5ldik7CiAgICBpdC0+c2Vjb25kLmVyYXNlKGl0LT5zZWNv
bmQuYmVnaW4oKSk7CiAgfQogIGlmIChpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgIHBlbmRpbmcu
ZXJhc2UoaXQpOwogIH0KfQpzdGF0aWMgdm9pZCBmbHVzaF9hbGxfcGVuZGluZyhzdGQ6Om1hcDxQ
YWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBzdGQ6Om1hcDxQ
YWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHA7CiAgZm9yIChwID0g
cGVuZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcuZW5kKCk7ICsrcCkgewogICAgZm9yIChzaXpl
X3QgaSA9IDA7IGkgPCBwLT5zZWNvbmQuc2l6ZSgpOyArK2kpIHsKICAgICAgZW1pdF9ldmVudChw
LT5zZWNvbmRbaV0uZXYpOwogICAgfQogIH0KICBwZW5kaW5nLmNsZWFyKCk7Cn0Kc3RhdGljIHZv
aWQgc3dlZXAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcsIHRpbWVfdCBub3cpIHsKICBzdGQ6
Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgZiwgZm47CiAgZm9yIChmID0gZmxvd3MuYmVn
aW4oKTsgZiAhPSBmbG93cy5lbmQoKTspIHsKICAgIGZuID0gZjsgKytmbjsKICAgIGlmICgodW5z
aWduZWQpKG5vdyAtIGYtPnNlY29uZC50b3VjaGVkKSA+IEZMT1dfVFRMKSBmbG93cy5lcmFzZShm
KTsKICAgIGYgPSBmbjsKICB9CiAgbG9uZyBsb25nIGN1cnJlbnRfbXMgPSAobG9uZyBsb25nKW5v
dyAqIDEwMDBMTDsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46
Oml0ZXJhdG9yIHAsIHBuOwogIGZvciAocCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5n
LmVuZCgpOykgewogICAgcG4gPSBwOyArK3BuOwogICAgc2l6ZV90IGkgPSAwOwogICAgd2hpbGUg
KGkgPCBwLT5zZWNvbmQuc2l6ZSgpKSB7CiAgICAgIGlmIChjdXJyZW50X21zIC0gcC0+c2Vjb25k
W2ldLnN0YXJ0ZWRfbXMgPiAobG9uZyBsb25nKVBFTkRJTkdfVFRMICogMTAwMExMKSB7CiAgICAg
ICAgZW1pdF9ldmVudChwLT5zZWNvbmRbaV0uZXYpOwogICAgICAgIHAtPnNlY29uZC5lcmFzZShw
LT5zZWNvbmQuYmVnaW4oKSArIGkpOwogICAgICB9IGVsc2UgewogICAgICAgICsraTsKICAgICAg
fQogICAgfQogICAgaWYgKHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAg
cCA9IHBuOwogIH0KfQpzdGF0aWMgc2l6ZV90IGZpbmRfaHR0cF9zdGFydChjb25zdCBzdGQ6OnN0
cmluZyAmcykgewogIGNvbnN0IGNoYXIgKm1bXSA9IHsgIkdFVCAiLCAiUE9TVCAiLCAiUFVUICIs
ICJERUxFVEUgIiwgIlBBVENIICIsICJIRUFEICIsICJPUFRJT05TICIgfTsKICBzaXplX3QgYmVz
dCA9IHN0ZDo6c3RyaW5nOjpucG9zOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNzsgKytpKSB7
CiAgICBzaXplX3QgcG9zID0gcy5maW5kKG1baV0pOwogICAgaWYgKHBvcyAhPSBzdGQ6OnN0cmlu
Zzo6bnBvcyAmJiAoYmVzdCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBwb3MgPCBiZXN0KSkgYmVz
dCA9IHBvczsKICB9CiAgcmV0dXJuIGJlc3Q7Cn0KCnN0YXRpYyBib29sIGdfbW9uaXRvcmVkX3Bv
cnRzWzY1NTM2XTsKc3RhdGljIHNpemVfdCBnX3dzc2VfYm9keV9ieXRlcyA9IDA7CgpzdGF0aWMg
dm9pZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1aW50MzJfdCBzX2lwLCB1bnNpZ25l
ZCBzcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1aW50MzJfdCBkX2lwLCB1bnNpZ25l
ZCBkcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0
ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBQYWNrZXRLZXkgcms7CiAgcmsuc19p
cCA9IGRfaXA7IHJrLnNwb3J0ID0gKHVpbnQxNl90KWRwb3J0OwogIHJrLmRfaXAgPSBzX2lwOyBy
ay5kcG9ydCA9ICh1aW50MTZfdClzcG9ydDsKICBpZiAocGVuZGluZy5maW5kKHJrKSA9PSBwZW5k
aW5nLmVuZCgpICYmIHBlbmRpbmcuc2l6ZSgpID49IE1BWF9QRU5ESU5HKSB7CiAgICBmbHVzaF9v
bGRlc3QocGVuZGluZyk7CiAgfQogIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ICZxdWV1ZSA9IHBlbmRp
bmdbcmtdOwogIGlmIChxdWV1ZS5zaXplKCkgPj0gTUFYX1BFTkRJTkdfUEVSX0ZMT1cpIHsKICAg
IGVtaXRfZXZlbnQocXVldWVbMF0uZXYpOwogICAgcXVldWUuZXJhc2UocXVldWUuYmVnaW4oKSk7
CiAgfQogIHF1ZXVlLnB1c2hfYmFjayhQZW5kaW5nKGUsIG5vd19tcygpKSk7Cn0KCnN0YXRpYyBz
aXplX3QgYWN0aXZlX3dzc2VfZmxvd3MoY29uc3Qgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZs
b3dzKSB7CiAgc2l6ZV90IGNvdW50ID0gMDsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6Y29u
c3RfaXRlcmF0b3IgaXQ7CiAgZm9yIChpdCA9IGZsb3dzLmJlZ2luKCk7IGl0ICE9IGZsb3dzLmVu
ZCgpOyArK2l0KQogICAgaWYgKGl0LT5zZWNvbmQuYXdhaXRpbmdfYm9keSkgKytjb3VudDsKICBy
ZXR1cm4gY291bnQ7Cn0KCnN0YXRpYyBib29sIGhhbmRsZV9wYWNrZXQoY29uc3QgdW5zaWduZWQg
Y2hhciAqYnVmLCBzaXplX3QgbiwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsIGNvbnN0IHN0ZDo6
dmVjdG9yPHVuc2lnbmVkPiAmcG9ydHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjpt
YXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9y
PFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICAodm9pZClwb3J0czsKICBpZiAobiA8IDM0KSByZXR1
cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRvaHMo
Kihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyAxMikpOwogIGlmIChldCA9PSBFVEhfUF84
MDIxUSkgeyBpZiAobiA8IDM4KSByZXR1cm4gZmFsc2U7IGV0ID0gbnRvaHMoKihjb25zdCB1bnNp
Z25lZCBzaG9ydCAqKShidWYgKyAxNikpOyBvZmYgPSAxODsgfQogIGlmIChldCAhPSBFVEhfUF9J
UCB8fCBuIDwgb2ZmICsgMjApIHJldHVybiBmYWxzZTsKICB1bnNpZ25lZCBjaGFyIGlobCA9ICh1
bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAqIDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0KSAh
PSA0IHx8IGJ1ZltvZmYgKyA5XSAhPSA2IHx8IG4gPCBvZmYgKyBpaGwgKyAyMCkgcmV0dXJuIGZh
bHNlOwoKICB1aW50MzJfdCBzX2lwID0gKihjb25zdCB1aW50MzJfdCAqKShidWYgKyBvZmYgKyAx
Mik7CiAgdWludDMyX3QgZF9pcCA9ICooY29uc3QgdWludDMyX3QgKikoYnVmICsgb2ZmICsgMTYp
OwogIHNpemVfdCB0byA9IG9mZiArIGlobDsKICB1bnNpZ25lZCBzcG9ydCA9IG50b2hzKCooY29u
c3QgdW5zaWduZWQgc2hvcnQgKikoYnVmICsgdG8pKTsKICB1bnNpZ25lZCBkcG9ydCA9IG50b2hz
KCooY29uc3QgdW5zaWduZWQgc2hvcnQgKikoYnVmICsgdG8gKyAyKSk7CiAgdW5zaWduZWQgZG9m
ZiA9IChidWZbdG8gKyAxMl0gPj4gNCkgKiA0OwogIGlmIChuIDwgdG8gKyBkb2ZmKSByZXR1cm4g
ZmFsc2U7CiAgY29uc3QgY2hhciAqcGF5bG9hZCA9IChjb25zdCBjaGFyICopKGJ1ZiArIHRvICsg
ZG9mZik7CiAgc2l6ZV90IHBsZW4gPSBuIC0gdG8gLSBkb2ZmOwogIGlmICghcGxlbikgcmV0dXJu
IGZhbHNlOwoKICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICBib29sIGRzdF9tb24gPSAoZHBv
cnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tkcG9ydF0gOiBmYWxzZTsKICBib29sIHNy
Y19tb24gPSAoc3BvcnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tzcG9ydF0gOiBmYWxz
ZTsKCiAgaWYgKHNyY19tb24gJiYgIWRzdF9tb24gJiYgcGxlbiA+PSA1KSB7CiAgICBpZiAobWVt
Y21wKHBheWxvYWQsICJIVFRQLyIsIDUpID09IDApIHsKICAgICAgUGFja2V0S2V5IGs7CiAgICAg
IGsuc19pcCA9IHNfaXA7IGsuc3BvcnQgPSAodWludDE2X3Qpc3BvcnQ7IGsuZF9pcCA9IGRfaXA7
IGsuZHBvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwgc3Rk
Ojp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCA9IHBlbmRpbmcuZmluZChrKTsKICAgICAg
aWYgKHAgIT0gcGVuZGluZy5lbmQoKSAmJiAhcC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgICAgICBp
bnQgc3Q7IHVuc2lnbmVkIGNsOwogICAgICAgIGlmIChwYXJzZV9yZXNwb25zZShwYXlsb2FkLCBw
bGVuLCAmc3QsICZjbCkpIHsKICAgICAgICAgIEV2ZW50IGUgPSBwLT5zZWNvbmRbMF0uZXY7CiAg
ICAgICAgICBlLnN0YXR1cyA9IHN0OyBlLmhhc19zdGF0dXMgPSB0cnVlOwogICAgICAgICAgZS5k
dXJhdGlvbl9tcyA9IChsb25nKShub3dfbXMoKSAtIHAtPnNlY29uZFswXS5zdGFydGVkX21zKTsK
ICAgICAgICAgIGlmIChlLmR1cmF0aW9uX21zIDwgMCkgZS5kdXJhdGlvbl9tcyA9IDA7CiAgICAg
ICAgICBlLmhhc19kdXJhdGlvbiA9IHRydWU7CiAgICAgICAgICBpZiAoY2wpIHsgZS5yZXNwX2J5
dGVzID0gY2w7IGUuaGFzX3Jlc3AgPSB0cnVlOyB9CiAgICAgICAgICBlbWl0X2V2ZW50KGUpOwog
ICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgIGlm
IChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICB9CiAgICAgIH0K
ICAgIH0KICAgIHJldHVybiB0cnVlOwogIH0KICB1bnNpZ25lZCBjaGFyIHRjcF9mbGFncyA9IGJ1
Zlt0byArIDEzXTsKICBpZiAoIWRzdF9tb24pIHsKICAgIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7
IC8qIEZJTiBvciBSU1QgKi8KICAgICAgRmxvd0tleSByZms7IHJmay5zX2lwID0gZF9pcDsgcmZr
LnNwb3J0ID0gKHVpbnQxNl90KWRwb3J0OyByZmsuZF9pcCA9IHNfaXA7IHJmay5kcG9ydCA9ICh1
aW50MTZfdClzcG9ydDsKICAgICAgZmxvd3MuZXJhc2UocmZrKTsKICAgIH0KICAgIHJldHVybiBm
YWxzZTsKICB9CgogIEZsb3dLZXkgZms7CiAgZmsuc19pcCA9IHNfaXA7IGZrLnNwb3J0ID0gKHVp
bnQxNl90KXNwb3J0OyBmay5kX2lwID0gZF9pcDsgZmsuZHBvcnQgPSAodWludDE2X3QpZHBvcnQ7
CiAgaWYgKHRjcF9mbGFncyAmIDB4MDUpIHsgLyogRklOIG9yIFJTVCAqLwogICAgZmxvd3MuZXJh
c2UoZmspOwogICAgcmV0dXJuIHRydWU7CiAgfQoKICBpZiAoZmxvd3MuZmluZChmaykgPT0gZmxv
d3MuZW5kKCkgJiYgZmxvd3Muc2l6ZSgpID49IE1BWF9GTE9XUykgewogICAgZmxvd3MuZXJhc2Uo
Zmxvd3MuYmVnaW4oKSk7CiAgfQogIEZsb3cgJmZsID0gZmxvd3NbZmtdOyBmbC50b3VjaGVkID0g
bm93OwogIGlmIChmbC5hd2FpdGluZ19ib2R5KSB7CiAgICBzaXplX3QgcmVtYWluaW5nID0gZmwu
Ym9keV9nb2FsID4gZmwuYnVmLnNpemUoKSA/IGZsLmJvZHlfZ29hbCAtIGZsLmJ1Zi5zaXplKCkg
OiAwOwogICAgaWYgKHJlbWFpbmluZykgZmwuYnVmLmFwcGVuZChwYXlsb2FkLCBwbGVuIDwgcmVt
YWluaW5nID8gcGxlbiA6IHJlbWFpbmluZyk7CiAgICBzdGQ6OnN0cmluZyB1c2VybmFtZSA9IGV4
dHJhY3Rfd3NzZV91c2VybmFtZShmbC5idWYpOwogICAgaWYgKCF1c2VybmFtZS5lbXB0eSgpIHx8
IGZsLmJ1Zi5zaXplKCkgPj0gZmwuYm9keV9nb2FsKSB7CiAgICAgIEV2ZW50IGV2ZW50ID0gZmwu
ZXZlbnQ7CiAgICAgIGlmICghdXNlcm5hbWUuZW1wdHkoKSkgeyBldmVudC51c2VyID0gdXNlcm5h
bWU7IGV2ZW50LnNjaGVtZSA9ICJ3c3NlIjsgfQogICAgICBmbG93cy5lcmFzZShmayk7CiAgICAg
IHF1ZXVlX3JlcXVlc3QoZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZyk7
CiAgICB9CiAgICByZXR1cm4gdHJ1ZTsKICB9CiAgZmwuYnVmLmFwcGVuZChwYXlsb2FkLCBwbGVu
KTsKICBpZiAoZmwuYnVmLnNpemUoKSA+IE1BWF9IRUFERVIpIHsgZmxvd3MuZXJhc2UoZmspOyBy
ZXR1cm4gZmFsc2U7IH0KICB3aGlsZSAodHJ1ZSkgewogICAgc2l6ZV90IHN0YXJ0ID0gZmluZF9o
dHRwX3N0YXJ0KGZsLmJ1Zik7CiAgICBpZiAoc3RhcnQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsg
ZmwuYnVmLmNsZWFyKCk7IGJyZWFrOyB9CiAgICBpZiAoc3RhcnQgPiAwKSBmbC5idWYuZXJhc2Uo
MCwgc3RhcnQpOwogICAgc2l6ZV90IGVuZCA9IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAg
aWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICBFdmVudCBlOyBSZXF1ZXN0
TWV0YSBtZXRhOyBlLnRzID0gbm93OyBlLmhvc3QgPSBub2RlOyBlLnNlcnZpY2UgPSAicG9ydDoi
ICsgbnVtKGRwb3J0KTsgZS5jYWxsZXIgPSBpcF90b19zdHIoc19pcCk7IGUuY2FsbGVyX3BvcnQg
PSBzcG9ydDsgZS5kc3RfaXAgPSBpcF90b19zdHIoZF9pcCk7IGUuZHN0X3BvcnQgPSBkcG9ydDsg
ZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQpKGVuZCArIDQpOwogICAgaWYgKCFwYXJzZV9yZXF1ZXN0
KGZsLmJ1Zi5kYXRhKCksIGVuZCwgJmUsICZtZXRhKSkgeyBmbC5idWYuZXJhc2UoMCwgZW5kICsg
NCk7IGNvbnRpbnVlOyB9CiAgICBmbC5idWYuZXJhc2UoMCwgZW5kICsgNCk7CiAgICBpZiAoZS51
c2VyID09ICItYW5vbnltb3VzLSIgJiYgZ193c3NlX2JvZHlfYnl0ZXMgJiYKICAgICAgICBpc19z
b2FwX2NvbnRlbnRfdHlwZShtZXRhLmNvbnRlbnRfdHlwZSkgJiYgbWV0YS5oYXNfY29udGVudF9s
ZW5ndGggJiYKICAgICAgICBtZXRhLmNvbnRlbnRfbGVuZ3RoID4gMCAmJgogICAgICAgIGxvd2Vy
KG1ldGEudHJhbnNmZXJfZW5jb2RpbmcpLmZpbmQoImNodW5rZWQiKSA9PSBzdGQ6OnN0cmluZzo6
bnBvcyAmJgogICAgICAgIGFjdGl2ZV93c3NlX2Zsb3dzKGZsb3dzKSA8IE1BWF9XU1NFX0JPRFlf
RkxPV1MpIHsKICAgICAgZmwuZXZlbnQgPSBlOwogICAgICBmbC5hd2FpdGluZ19ib2R5ID0gdHJ1
ZTsKICAgICAgZmwuYm9keV9nb2FsID0gbWV0YS5jb250ZW50X2xlbmd0aCA8IGdfd3NzZV9ib2R5
X2J5dGVzID8gbWV0YS5jb250ZW50X2xlbmd0aCA6IGdfd3NzZV9ib2R5X2J5dGVzOwogICAgICBp
ZiAoZmwuYm9keV9nb2FsID4gTUFYX1dTU0VfQk9EWV9CWVRFUykgZmwuYm9keV9nb2FsID0gTUFY
X1dTU0VfQk9EWV9CWVRFUzsKICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBmbC5ib2R5X2dvYWwp
IGZsLmJ1Zi5yZXNpemUoZmwuYm9keV9nb2FsKTsKICAgICAgc3RkOjpzdHJpbmcgdXNlcm5hbWUg
PSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwuYnVmKTsKICAgICAgaWYgKCF1c2VybmFtZS5lbXB0
eSgpIHx8IGZsLmJ1Zi5zaXplKCkgPj0gZmwuYm9keV9nb2FsKSB7CiAgICAgICAgRXZlbnQgZXZl
bnQgPSBmbC5ldmVudDsKICAgICAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkpIHsgZXZlbnQudXNl
ciA9IHVzZXJuYW1lOyBldmVudC5zY2hlbWUgPSAid3NzZSI7IH0KICAgICAgICBmbG93cy5lcmFz
ZShmayk7CiAgICAgICAgcXVldWVfcmVxdWVzdChldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRw
b3J0LCBwZW5kaW5nKTsKICAgICAgfQogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KICAgIHF1ZXVl
X3JlcXVlc3QoZSwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nKTsKICB9CiAgaWYg
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
MDEyMzQ1Njc4OWFiY2RlZi0wMVxyXG5cclxuIjsKICBFdmVudCBlOyBSZXF1ZXN0TWV0YSBtZXRh
OyBlLnRzID0gMTcwMDAwMDAwMDsgZS5ob3N0ID0gImNwcC1ub2RlIjsgZS5zZXJ2aWNlID0gInBv
cnQ6ODA4MCI7IGUuY2FsbGVyID0gIjEwLjAuMC45IjsgZS5jYWxsZXJfcG9ydCA9IDUxMDAwOyBl
LmRzdF9pcCA9ICIxMC4wLjAuMiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBlLnJlcV9ieXRlcyA9ICh1
bnNpZ25lZClyZXEuc2l6ZSgpOyBwYXJzZV9yZXF1ZXN0KHJlcS5kYXRhKCksIHJlcS5zaXplKCkg
LSA0LCAmZSwgJm1ldGEpOyBlLnN0YXR1cyA9IDIwMDsgZS5oYXNfc3RhdHVzID0gdHJ1ZTsgZS5k
dXJhdGlvbl9tcyA9IDM7IGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsgZS5yZXNwX2J5dGVzID0gNDI7
IGUuaGFzX3Jlc3AgPSB0cnVlOyBlbWl0X2V2ZW50KGUpOyByZXR1cm4gMDsKfQoKc3RhdGljIGlu
dCBydW5fd3NzZV9maXh0dXJlKCkgewogIGNvbnN0IGNoYXIgKm5hbWVzcGFjZXNbXSA9IHsKICAg
ICJodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEtd3Nz
LXdzc2VjdXJpdHktc2VjZXh0LTEuMC54c2QiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAu
b3JnL3dzLzIwMDIvMDcvc2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93
cy8yMDAyLzEyL3NlY2V4dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAw
My8wNi9zZWNleHQiCiAgfTsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDQ7ICsraSkgewogICAg
c3RkOjpzdHJpbmcgYm9keSA9ICI8czpFbnZlbG9wZSB4bWxuczpzPSd1cm46c29hcCcgeG1sbnM6
dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbaV0pICsKICAgICAgIic+PHM6SGVhZGVyPjx3
OlVzZXJuYW1lVG9rZW4+PHc6VXNlcm5hbWU+bmF0aXZlLmZpeHR1cmU8L3c6VXNlcm5hbWU+Igog
ICAgICAiPHc6UGFzc3dvcmQ+U0VOU0lUSVZFX1BBU1NXT1JEPC93OlBhc3N3b3JkPjwvdzpVc2Vy
bmFtZVRva2VuPjwvczpIZWFkZXI+IjsKICAgIHN0ZDo6c3RyaW5nIHVzZXIgPSBleHRyYWN0X3dz
c2VfdXNlcm5hbWUoYm9keSk7CiAgICBpZiAodXNlciAhPSAibmF0aXZlLmZpeHR1cmUiKSByZXR1
cm4gMzsKICAgIHN0ZDo6Y291dCA8PCB1c2VyIDw8ICJcbiI7CiAgfQogIHN0ZDo6c3RyaW5nIG1h
bGljaW91cyA9ICI8IURPQ1RZUEUgeCBbPCFFTlRJVFkgcHcgJ3NlY3JldCc+XT48dzpVc2VybmFt
ZVRva2VuIHhtbG5zOnc9JyIgKwogICAgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKyAiJz48
dzpVc2VybmFtZT4mcHc7PC93OlVzZXJuYW1lPjwvdzpVc2VybmFtZVRva2VuPiI7CiAgaWYgKCFl
eHRyYWN0X3dzc2VfdXNlcm5hbWUobWFsaWNpb3VzKS5lbXB0eSgpKSByZXR1cm4gNDsKICBzdGQ6
OnN0cmluZyB3cm9uZ19ucyA9ICI8dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9J3Vybjpub3Qtd3Nz
ZSc+PHc6VXNlcm5hbWU+d3Jvbmc8L3c6VXNlcm5hbWU+PC93OlVzZXJuYW1lVG9rZW4+IjsKICBp
ZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZSh3cm9uZ19ucykuZW1wdHkoKSkgcmV0dXJuIDU7CiAg
c3RkOjpzdHJpbmcgdW5uYW1lc3BhY2VkID0gIjxVc2VybmFtZVRva2VuPjxVc2VybmFtZT53cm9u
ZzwvVXNlcm5hbWU+PC9Vc2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5h
bWUodW5uYW1lc3BhY2VkKS5lbXB0eSgpKSByZXR1cm4gNjsKICBzdGQ6OnN0cmluZyBlc2NhcGVk
ID0gIjx3OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNb
MF0pICsKICAgICInPjx3OlVzZXJuYW1lPm5hdGl2ZSZhbXA7Zml4dHVyZTwvdzpVc2VybmFtZT4i
OwogIGlmIChleHRyYWN0X3dzc2VfdXNlcm5hbWUoZXNjYXBlZCkgIT0gIm5hdGl2ZSZmaXh0dXJl
IikgcmV0dXJuIDc7CiAgc3RkOjpzdHJpbmcgdG9vX2xvbmcgPSAiPHc6VXNlcm5hbWVUb2tlbiB4
bWxuczp3PSciICsgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKwogICAgIic+PHc6VXNlcm5h
bWU+IiArIHN0ZDo6c3RyaW5nKE1BWF9XU1NFX1VTRVJOQU1FICsgMSwgJ3gnKSArICI8L3c6VXNl
cm5hbWU+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZSh0b29fbG9uZykuZW1wdHkoKSkg
cmV0dXJuIDg7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3dzc2Vfc2l6ZShjb25z
dCBjaGFyICp2YWx1ZSwgc2l6ZV90ICpyZXN1bHQpIHsKICBpZiAoIXZhbHVlIHx8ICEqdmFsdWUp
IHJldHVybiBmYWxzZTsKICBzaXplX3QgbiA9IDA7CiAgaWYgKCFwYXJzZV9kZWNpbWFsX3NpemUo
dmFsdWUsIHN0cmxlbih2YWx1ZSksICZuKSB8fCBuID4gTUFYX1dTU0VfQk9EWV9CWVRFUykgcmV0
dXJuIGZhbHNlOwogICpyZXN1bHQgPSBuOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgaW50IHJ1
bl9jYXBhYmlsaXR5X3Byb2JlKCkgewogIGludCBmZCA9IHNvY2tldChBRl9QQUNLRVQsIFNPQ0tf
UkFXLCBodG9ucygzKSk7CiAgaWYgKGZkIDwgMCkgeyBwZXJyb3IoIkFGX1BBQ0tFVCBjYXBhYmls
aXR5IHByb2JlIik7IHJldHVybiAyOyB9CiAgY2xvc2UoZmQpOwogIHJldHVybiAwOwp9CgpzdGF0
aWMgYm9vbCBkcm9wX2FsbF9jYXBhYmlsaXRpZXMoKSB7CiAgc3RydWN0IF9fdXNlcl9jYXBfaGVh
ZGVyX3N0cnVjdCBoZWFkZXI7CiAgc3RydWN0IF9fdXNlcl9jYXBfZGF0YV9zdHJ1Y3QgZGF0YVsy
XTsKICBtZW1zZXQoJmhlYWRlciwgMCwgc2l6ZW9mKGhlYWRlcikpOwogIG1lbXNldChkYXRhLCAw
LCBzaXplb2YoZGF0YSkpOwogIGhlYWRlci52ZXJzaW9uID0gX0xJTlVYX0NBUEFCSUxJVFlfVkVS
U0lPTl8zOwogIGhlYWRlci5waWQgPSAwOwogIHJldHVybiBzeXNjYWxsKFNZU19jYXBzZXQsICZo
ZWFkZXIsIGRhdGEpID09IDA7Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikgewog
IGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1
bl9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0td3NzZS1m
aXh0dXJlIikpIHJldHVybiBydW5fd3NzZV9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFz
dHJjbXAoYXJndlsxXSwgIi0tY2FwYWJpbGl0eS1wcm9iZSIpKSByZXR1cm4gcnVuX2NhcGFiaWxp
dHlfcHJvYmUoKTsKICBzdGQ6OnN0cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBv
cnRzOyBpbnQgaTsgaW50IHdvcmtlcnMgPSAxOwogIHN0ZDo6c3RyaW5nIGVuZHBvaW50OwogIGNv
bnN0IGNoYXIgKndzc2VfZW52ID0gZ2V0ZW52KCJOVF9XU1NFX0JPRFlfQllURVMiKTsKICBpZiAo
d3NzZV9lbnYgJiYgIXBhcnNlX3dzc2Vfc2l6ZSh3c3NlX2VudiwgJmdfd3NzZV9ib2R5X2J5dGVz
KSkgewogICAgZnByaW50ZihzdGRlcnIsICJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5n
ZSAwLi42NTUzNlxuIik7IHJldHVybiAyOwogIH0KICBmb3IgKGkgPSAxOyBpIDwgYXJnYzsgKytp
KSB7CiAgICBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWkiKSAmJiBpICsgMSA8IGFyZ2MpIGlmYWNl
ID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLXAiKSAmJiBpICsg
MSA8IGFyZ2MpIHsKICAgICAgd2hpbGUgKGkgKyAxIDwgYXJnYyAmJiBhcmd2W2kgKyAxXVswXSAh
PSAnLScpIHsKICAgICAgICBjaGFyICpxID0gc3RydG9rKGFyZ3ZbKytpXSwgIiwgIik7CiAgICAg
ICAgd2hpbGUgKHEpIHsgbG9uZyBwID0gYXRvbChxKTsgaWYgKHZhbGlkX3BvcnQoKHVuc2lnbmVk
KXApKSBwb3J0cy5wdXNoX2JhY2soKHVuc2lnbmVkKXApOyBxID0gc3RydG9rKE5VTEwsICIsICIp
OyB9CiAgICAgIH0KICAgIH0KICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tZW5kcG9p
bnQiKSAmJiBpICsgMSA8IGFyZ2MpIGVuZHBvaW50ID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAo
IXN0cmNtcChhcmd2W2ldLCAiLS1zcG9vbCIpICYmIGkgKyAxIDwgYXJnYykgKytpOyAvKiBpZ25v
cmVkOiAwIGRpc2sgd3JpdGUgKi8KICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1qIikg
JiYgaSArIDEgPCBhcmdjKSB3b3JrZXJzID0gYXRvaShhcmd2WysraV0pOwogICAgZWxzZSBpZiAo
IXN0cmNtcChhcmd2W2ldLCAiLS13c3NlLWJvZHktYnl0ZXMiKSAmJiBpICsgMSA8IGFyZ2MpIHsK
ICAgICAgaWYgKCFwYXJzZV93c3NlX3NpemUoYXJndlsrK2ldLCAmZ193c3NlX2JvZHlfYnl0ZXMp
KSB7CiAgICAgICAgZnByaW50ZihzdGRlcnIsICJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiBy
YW5nZSAwLi42NTUzNlxuIik7IHJldHVybiAyOwogICAgICB9CiAgICB9CiAgICBlbHNlIGlmICgh
c3RyY21wKGFyZ3ZbaV0sICItaCIpIHx8ICFzdHJjbXAoYXJndltpXSwgIi0taGVscCIpKSB7CiAg
ICAgIGZwcmludGYoc3RkZXJyLCAidXNhZ2U6IG50LXNuaWZmLWNwcCBbLWkgaWZhY2VdIFstcCBw
b3J0c10gWy0tZW5kcG9pbnQgVVJMXSBbLWogd29ya2Vyc10gWy0td3NzZS1ib2R5LWJ5dGVzIDAu
LjY1NTM2XVxuIik7CiAgICAgIHJldHVybiAwOwogICAgfQogICAgZWxzZSB7IGZwcmludGYoc3Rk
ZXJyLCAidW5rbm93biBvciBpbmNvbXBsZXRlIGFyZ3VtZW50OiAlc1xuIiwgYXJndltpXSk7IHJl
dHVybiAyOyB9CiAgfQogIGlmIChwb3J0cy5lbXB0eSgpKSB7IHBvcnRzLnB1c2hfYmFjayg4MCk7
IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9ydHMucHVzaF9iYWNrKDgwMDUpOyBwb3J0cy5wdXNo
X2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFjayg4MDA5KTsgcG9ydHMucHVzaF9iYWNrKDgwMTAp
OyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0KICAodm9pZCl3b3JrZXJzOwoKICBpbml0X3JuZygp
OwogIG1lbXNldChnX21vbml0b3JlZF9wb3J0cywgMCwgc2l6ZW9mKGdfbW9uaXRvcmVkX3BvcnRz
KSk7CiAgZm9yIChzaXplX3QgayA9IDA7IGsgPCBwb3J0cy5zaXplKCk7ICsraykgewogICAgaWYg
KHBvcnRzW2tdIDwgNjU1MzYpIGdfbW9uaXRvcmVkX3BvcnRzW3BvcnRzW2tdXSA9IHRydWU7CiAg
fQoKICBjb25zdCBjaGFyICpub2RlX2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1FIik7CiAgc3Rk
OjpzdHJpbmcgbm9kZSA9IChub2RlX2VudiAmJiAqbm9kZV9lbnYpID8gbm9kZV9lbnYgOiBob3N0
X25hbWUoKTsKCiAgZ19lbmRwb2ludCA9IGVuZHBvaW50OwogIGdfc2hpcF9ub2RlID0gbm9kZTsK
CiAgaW50IGZkID0gc29ja2V0KEFGX1BBQ0tFVCwgU09DS19SQVcsIGh0b25zKDMpKTsKICBpZiAo
ZmQgPCAwKSB7IHBlcnJvcigiQUZfUEFDS0VUIik7IHJldHVybiAyOyB9CiAgaW50IHJiID0gOCAq
IDEwMjQgKiAxMDI0OwogIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX1JDVkJVRiwgJnJi
LCBzaXplb2YocmIpKTsKICBpZiAoIWF0dGFjaF9icGYoZmQsIHBvcnRzKSkgewogICAgbG9nbXNn
KCJCUEYgYXR0YWNoIGZhaWxlZDsgcmVmdXNpbmcgdW5maWx0ZXJlZCBjYXB0dXJlIik7CiAgICBj
bG9zZShmZCk7CiAgICByZXR1cm4gMjsKICB9CgogIE1tYXBSaW5nIHJpbmc7CiAgYm9vbCB1c2Vf
bW1hcCA9IHNldHVwX21tYXBfcmluZyhmZCwgcmluZyk7CgogIHN0cnVjdCBzb2NrYWRkcl9sbCBz
YTsKICBtZW1zZXQoJnNhLCAwLCBzaXplb2Yoc2EpKTsKICBzYS5zbGxfZmFtaWx5ID0gQUZfUEFD
S0VUOwogIHNhLnNsbF9wcm90b2NvbCA9IGh0b25zKDMpOwogIGlmICghaWZhY2UuZW1wdHkoKSkg
ewogICAgc2Euc2xsX2lmaW5kZXggPSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3RyKCkp
OwogICAgaWYgKCFzYS5zbGxfaWZpbmRleCkgeyBsb2dtc2coImJhZCBpbnRlcmZhY2UiKTsgY2xv
c2UoZmQpOyByZXR1cm4gMjsgfQogIH0KICBpZiAoYmluZChmZCwgKHN0cnVjdCBzb2NrYWRkciAq
KSZzYSwgc2l6ZW9mKHNhKSkgPCAwKSB7IHBlcnJvcigiYmluZCIpOyBjbG9zZShmZCk7IHJldHVy
biAyOyB9CiAgaWYgKCFkcm9wX2FsbF9jYXBhYmlsaXRpZXMoKSkgewogICAgbG9nbXNnKCJjYXBh
YmlsaXR5IGRyb3AgZmFpbGVkOyByZWZ1c2luZyB1bnNhZmUgY2FwdHVyZSIpOwogICAgaWYgKHVz
ZV9tbWFwICYmIHJpbmcucmluZyAhPSBNQVBfRkFJTEVEKSBtdW5tYXAocmluZy5yaW5nLCByaW5n
LnJpbmdfc2l6ZSk7CiAgICBjbG9zZShmZCk7CiAgICByZXR1cm4gMjsKICB9CgogIHNpZ25hbChT
SUdURVJNLCBzdG9wX3NpZ25hbCk7CiAgc2lnbmFsKFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHNl
dHZidWYoc3Rkb3V0LCBOVUxMLCBfSU9MQkYsIDY1NTM2KTsKICBzdGQ6Om1hcDxGbG93S2V5LCBG
bG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4g
cGVuZGluZzsKCiAgaWYgKHVzZV9tbWFwKSB7CiAgICBsb2dtc2coIlBBQ0tFVF9NTUFQIChUUEFD
S0VUX1YyKSB6ZXJvLWNvcHkgcmluZyBlbmFibGVkICg0TUIsIDIwNDggZnJhbWVzKSIpOwogIH0g
ZWxzZSB7CiAgICBsb2dtc2coIldBUk46IFBBQ0tFVF9NTUFQIHNldHVwIGZhaWxlZCwgZmFsbGlu
ZyBiYWNrIHRvIHN0YW5kYXJkIHNvY2tldCByZWN2Iik7CiAgfQogIGlmIChnX3dzc2VfYm9keV9i
eXRlcykgewogICAgbG9nbXNnKCJXU1NFIFVzZXJuYW1lVG9rZW4gaW5zcGVjdGlvbiBlbmFibGVk
IChib3VuZGVkIHRvICIgKyBudW1iZXJfc3RyaW5nKGdfd3NzZV9ib2R5X2J5dGVzKSArICIgYnl0
ZXMvcmVxdWVzdCkiKTsKICB9CiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgIGxvZ21z
Zygic2luZ2xlLWJpbmFyeSBpbi1tZW1vcnkgbW9kZTogc2hpcHBpbmcgZGlyZWN0bHkgdG8gIiAr
IGdfZW5kcG9pbnQgKyAiICgwIGRpc2sgSS9PKSIpOwogIH0KICBsb2dtc2coImxpc3RlbmluZyIp
OwoKICB0aW1lX3QgbGFzdCA9IHRpbWUoTlVMTCksIGxhc3RfZmx1c2ggPSBsYXN0OwogIHVuc2ln
bmVkIGNoYXIgKmZhbGxiYWNrX2J1ZiA9IE5VTEw7CiAgaWYgKCF1c2VfbW1hcCkgewogICAgZmFs
bGJhY2tfYnVmID0gKHVuc2lnbmVkIGNoYXIgKiltYWxsb2MoNjU1MzYpOwogICAgaWYgKCFmYWxs
YmFja19idWYpIHsKICAgICAgY2xvc2UoZmQpOwogICAgICBsb2dtc2coImJ1ZmZlciBhbGxvY2F0
aW9uIGZhaWxlZCIpOwogICAgICByZXR1cm4gMjsKICAgIH0KICB9CgogIHN0cnVjdCBwb2xsZmQg
cGZkOwogIHBmZC5mZCA9IGZkOwogIHBmZC5ldmVudHMgPSBQT0xMSU4gfCBQT0xMRVJSOwogIHBm
ZC5yZXZlbnRzID0gMDsKCiAgd2hpbGUgKGdfcnVubmluZykgewogICAgaW50IHJjID0gcG9sbCgm
cGZkLCAxLCAxMDAwKTsKICAgIGlmIChyYyA8IDAgJiYgZXJybm8gPT0gRUlOVFIpIHsKICAgICAg
LyogU2lnbmFsIGhhbmRsZWQsIGxvb3AgY29uZGl0aW9uIHdpbGwgY2hlY2sgZ19ydW5uaW5nICov
CiAgICB9IGVsc2UgaWYgKHJjID49IDApIHsKICAgICAgaWYgKHVzZV9tbWFwKSB7CiAgICAgICAg
LyogRHJhaW4gYWxsIHJlYWR5IGZyYW1lcyBpbiB0aGUgcmluZyB3aXRob3V0IGV4dHJhIHN5c2Nh
bGxzICovCiAgICAgICAgd2hpbGUgKGdfcnVubmluZykgewogICAgICAgICAgdW5zaWduZWQgYl9p
ZHggPSByaW5nLmZyYW1lX2lkeCAvIHJpbmcuZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICAgIHVu
c2lnbmVkIGZfaW5fYiA9IHJpbmcuZnJhbWVfaWR4ICUgcmluZy5mcmFtZXNfcGVyX2Jsb2NrOwog
ICAgICAgICAgdWludDhfdCAqZnJhbWVfcHRyID0gKCh1aW50OF90ICopcmluZy5yaW5nKSArIChi
X2lkeCAqIHJpbmcuYmxvY2tfc2l6ZSkgKyAoZl9pbl9iICogcmluZy5mcmFtZV9zaXplKTsKICAg
ICAgICAgIHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciA9IChzdHJ1Y3QgdHBhY2tldDJfaGRyICop
ZnJhbWVfcHRyOwoKICAgICAgICAgIGlmICghKGhkci0+dHBfc3RhdHVzICYgVFBfU1RBVFVTX1VT
RVIpKSB7CiAgICAgICAgICAgIGJyZWFrOyAvKiBObyBtb3JlIGtlcm5lbC1wb3B1bGF0ZWQgZnJh
bWVzIGluIHJpbmcgcmlnaHQgbm93ICovCiAgICAgICAgICB9CgogICAgICAgICAgaWYgKGhkci0+
dHBfc25hcGxlbiA+IDApIHsKICAgICAgICAgICAgY29uc3QgdW5zaWduZWQgY2hhciAqcGt0ID0g
KChjb25zdCB1bnNpZ25lZCBjaGFyICopaGRyKSArIGhkci0+dHBfbWFjOwogICAgICAgICAgICBo
YW5kbGVfcGFja2V0KHBrdCwgKHNpemVfdCloZHItPnRwX3NuYXBsZW4sIG5vZGUsIHBvcnRzLCBm
bG93cywgcGVuZGluZyk7CiAgICAgICAgICB9CgogICAgICAgICAgaGRyLT50cF9zdGF0dXMgPSBU
UF9TVEFUVVNfS0VSTkVMOyAvKiBSZXR1cm4gZnJhbWUgb3duZXJzaGlwIHRvIGtlcm5lbCAqLwog
ICAgICAgICAgcmluZy5mcmFtZV9pZHggPSAocmluZy5mcmFtZV9pZHggKyAxKSAlIHJpbmcuZnJh
bWVfbnI7CiAgICAgICAgfQogICAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291
dC5mbHVzaCgpOwogICAgICB9IGVsc2UgewogICAgICAgIGlmIChwZmQucmV2ZW50cyAmIFBPTExJ
TikgewogICAgICAgICAgc3NpemVfdCBuID0gcmVjdihmZCwgZmFsbGJhY2tfYnVmLCA2NTUzNiwg
MCk7CiAgICAgICAgICBpZiAobiA+IDApIHsKICAgICAgICAgICAgaGFuZGxlX3BhY2tldChmYWxs
YmFja19idWYsIChzaXplX3Qpbiwgbm9kZSwgcG9ydHMsIGZsb3dzLCBwZW5kaW5nKTsKICAgICAg
ICAgICAgaWYgKGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgICAg
ICB9CiAgICAgICAgfQogICAgICB9CiAgICB9CgogICAgdGltZV90IG5vdyA9IHRpbWUoTlVMTCk7
CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVwKGZsb3dzLCBwZW5kaW5nLCBu
b3cpOwogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKICAg
ICAgbGFzdCA9IG5vdzsKICAgIH0KCiAgICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSkgewogICAg
ICBpZiAobm93IC0gbGFzdF9mbHVzaCA+PSBGTFVTSF9TRUMgfHwgZ19zaGlwX2J1Zi5zaXplKCkg
Pj0gTUFYX0JBVENIKSB7CiAgICAgICAgaWYgKCFnX3NoaXBfYnVmLmVtcHR5KCkpIHNlbmRfYmF0
Y2hlcyhnX2VuZHBvaW50LCBnX3NoaXBfbm9kZSwgJmdfc2hpcF9idWYsIHRydWUpOwogICAgICAg
IGxhc3RfZmx1c2ggPSBub3c7CiAgICAgIH0KICAgIH0KICB9CgogIC8qIEEgcmVzcG9uc2UgaXMg
b3B0aW9uYWwgZW5yaWNobWVudC4gUHJlc2VydmUgcmVxdWVzdHMgc3RpbGwgYXdhaXRpbmcgYQog
ICAqIHJlc3BvbnNlIHdoZW4gU0lHVEVSTS9yZXN0YXJ0IGVuZHMgY2FwdHVyZS4gKi8KICBmbHVz
aF9hbGxfcGVuZGluZyhwZW5kaW5nKTsKICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNv
dXQuZmx1c2goKTsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkgJiYgIWdfc2hpcF9idWYuZW1w
dHkoKSkgewogICAgc2VuZF9iYXRjaGVzKGdfZW5kcG9pbnQsIGdfc2hpcF9ub2RlLCAmZ19zaGlw
X2J1ZiwgdHJ1ZSk7CiAgfQoKICBpZiAodXNlX21tYXAgJiYgcmluZy5yaW5nICE9IE1BUF9GQUlM
RUQpIHsKICAgIG11bm1hcChyaW5nLnJpbmcsIHJpbmcucmluZ19zaXplKTsKICB9CiAgaWYgKGZh
bGxiYWNrX2J1ZikgZnJlZShmYWxsYmFja19idWYpOwogIGNsb3NlKGZkKTsKICBsb2dtc2coInN0
b3BwZWQiKTsKICByZXR1cm4gMDsKfQo=
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
dCA3MAp9CgojIDI1NiBNaUIgYWRkcmVzcyBzcGFjZSwgOCBNaUIgc3RhY2ssIDY0IEtpQiBsb2Nr
ZWQgbWVtb3J5LCAxLDAyNCBkZXNjcmlwdG9ycywKIyAzMiBNaUIgcGVyIHJlZ3VsYXIgb3V0cHV0
IGZpbGUsIGFuZCBubyBjb3JlIGR1bXBzLiBUaGUgcHJvY2VzcyBsaW1pdCBleGlzdHMKIyBpbiBi
YXNoIG9uIEVMNiwgYnV0IG5vdCBldmVyeSBQT1NJWCBzaGVsbCwgc28gYXBwbHkgaXQgd2hlbiBz
dXBwb3J0ZWQuCnVsaW1pdCAtUyAtYyAwICYmIHVsaW1pdCAtSCAtYyAwIHx8IGV4aXQgNzAKdWxp
bWl0IC1TIC1mIDY1NTM2ICYmIHVsaW1pdCAtSCAtZiA2NTUzNiB8fCBleGl0IDcwCnVsaW1pdCAt
UyAtbiAxMDI0ICYmIHVsaW1pdCAtSCAtbiAxMDI0IHx8IGV4aXQgNzAKdWxpbWl0IC1TIC12IDI2
MjE0NCAmJiB1bGltaXQgLUggLXYgMjYyMTQ0IHx8IGV4aXQgNzAKdWxpbWl0IC1TIC1zIDgxOTIg
JiYgdWxpbWl0IC1IIC1zIDgxOTIgfHwgZXhpdCA3MAp1bGltaXQgLVMgLWwgNjQgJiYgdWxpbWl0
IC1IIC1sIDY0IHx8IGV4aXQgNzAKaWYgKHVsaW1pdCAtdSA+L2Rldi9udWxsIDI+JjEpOyB0aGVu
CiAgICB1bGltaXQgLVMgLXUgNjQgJiYgdWxpbWl0IC1IIC11IDY0IHx8IGV4aXQgNzAKZmkKCiMg
TG93ZXN0IHNjaGVkdWxpbmcgcHJpb3JpdHkgdG9vLiB0YXNrc2V0IHByb3ZpZGVzIHRoZSBoYXJk
IG9uZS1sb2dpY2FsLUNQVQojIGNlaWxpbmcgZm9yIHRoZSBjb21wbGV0ZSBkZXNjZW5kYW50IHBy
b2Nlc3MgdHJlZS4KZXhlYyB0YXNrc2V0IC1jICIkQ1BVX0NPUkUiIG5pY2UgLW4gMTkgIiRAIgo=
#__END_RESOURCE_GUARD__
#__SUPERVISOR_B64__
IyEvYmluL3NoCiMgQm91bmRlZCBjcmFzaCByZWNvdmVyeSBmb3IgdGhlIGxlZ2FjeSBjYXB0dXJl
IHBpcGVsaW5lLgojIEZpdmUgc2hvcnQtbGl2ZWQgZmFpbHVyZXMgb3BlbiB0aGUgY2lyY3VpdCBp
bnN0ZWFkIG9mIGNyZWF0aW5nIGEgcmVzdGFydAojIHN0b3JtLiBUaGUgc2VydmljZSBtYW5hZ2Vy
L29wZXJhdG9yIG11c3QgZXhwbGljaXRseSBzdGFydCBpdCBhZ2Fpbi4Kc2V0IC11CgpHVUFSRD0k
ezE6LX0KQ1BVX0NPUkU9JHsyOi19ClsgJCMgLWdlIDIgXSB8fCBleGl0IDcwCnNoaWZ0IDIKWyAt
eCAiJEdVQVJEIiBdIHx8IGV4aXQgNzAKWyAkIyAtZ3QgMCBdIHx8IGV4aXQgNzAKCmNoaWxkX3Bp
ZD0iIgpzdG9wcGluZz0wCgpzdG9wX3N1cGVydmlzb3IoKSB7CiAgICBzdG9wcGluZz0xCiAgICBp
ZiBbIC1uICIkY2hpbGRfcGlkIiBdOyB0aGVuCiAgICAgICAga2lsbCAiJGNoaWxkX3BpZCIgMj4v
ZGV2L251bGwgfHwgdHJ1ZQogICAgICAgIHdhaXQgIiRjaGlsZF9waWQiIDI+L2Rldi9udWxsIHx8
IHRydWUKICAgIGZpCiAgICBleGl0IDAKfQp0cmFwICdzdG9wX3N1cGVydmlzb3InIFRFUk0gSU5U
IEhVUAoKZmFpbHVyZXM9MApkZWxheT0xCndoaWxlIFsgIiRzdG9wcGluZyIgLWVxIDAgXTsgZG8K
ICAgIHN0YXJ0ZWQ9JChkYXRlICslcykKICAgICIkR1VBUkQiICIkQ1BVX0NPUkUiICIkQCIgJgog
ICAgY2hpbGRfcGlkPSQhCiAgICB3YWl0ICIkY2hpbGRfcGlkIgogICAgc3RhdHVzPSQ/CiAgICBj
aGlsZF9waWQ9IiIKICAgIFsgIiRzdG9wcGluZyIgLWVxIDAgXSB8fCBleGl0IDAKICAgICMgQSBj
bGVhbiBleGl0IGluY2x1ZGVzIGFuIGludGVudGlvbmFsIHJlbW90ZS1jb250cm9sIHN0b3AuIERv
IG5vdCB1bmRvIGl0LgogICAgWyAiJHN0YXR1cyIgLW5lIDAgXSB8fCBleGl0IDAKCiAgICBlbmRl
ZD0kKGRhdGUgKyVzKQogICAgcnVudGltZT0kKChlbmRlZCAtIHN0YXJ0ZWQpKQogICAgaWYgWyAi
JHJ1bnRpbWUiIC1nZSA2MCBdOyB0aGVuCiAgICAgICAgZmFpbHVyZXM9MAogICAgICAgIGRlbGF5
PTEKICAgIGZpCiAgICBmYWlsdXJlcz0kKChmYWlsdXJlcyArIDEpKQogICAgaWYgWyAiJGZhaWx1
cmVzIiAtZ2UgNSBdOyB0aGVuCiAgICAgICAgZWNobyAibnQtc3VwZXJ2aXNlOiBjcmFzaC1sb29w
IGNpcmN1aXQgb3BlbiBhZnRlciAkZmFpbHVyZXMgZmFpbHVyZXMgKGxhc3Qgc3RhdHVzPSRzdGF0
dXMpIiA+JjIKICAgICAgICBleGl0IDc1CiAgICBmaQogICAgZWNobyAibnQtc3VwZXJ2aXNlOiBj
aGlsZCBleGl0ZWQgc3RhdHVzPSRzdGF0dXM7IHJlc3RhcnQgaW4gJHtkZWxheX1zICgkZmFpbHVy
ZXMvNSkiID4mMgogICAgc2xlZXAgIiRkZWxheSIgJgogICAgY2hpbGRfcGlkPSQhCiAgICB3YWl0
ICIkY2hpbGRfcGlkIiAyPi9kZXYvbnVsbCB8fCB0cnVlCiAgICBjaGlsZF9waWQ9IiIKICAgIFsg
IiRkZWxheSIgLWdlIDggXSB8fCBkZWxheT0kKChkZWxheSAqIDIpKQpkb25lCmV4aXQgMAo=
#__END_SUPERVISOR__
