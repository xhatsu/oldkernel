#!/bin/sh
# install-oldkernel.sh — NetworkTracing legacy installer (CentOS 6.x / 2.6.32)
#
# Installs the pcap-based HTTP/SOAP sniffer + python2.6 shipper as a SysV
# service. NO eBPF, NO systemd, NO kernel modules. Prefers rootless capture
# via file capability (cap_net_raw on a private interpreter copy); fails
# closed rather than running capture as root when this cannot be enforced.
#
# FIRST RUN — works standalone on a bare node. The saved first-run bundle uses
# its embedded kit; a plain installer fetches only from explicit --kit-url:
#
#   curl -sSf http://KIT_HOST:KIT_PORT/oldkernel/install-firstrun-el68.sh \
#        -o install-firstrun-el68.sh && \
#        sudo sh install-firstrun-el68.sh --server http://HUB_HOST:HUB_PORT
#
# Local bundle usage:
#   sh install-oldkernel.sh --server http://HUB_HOST:HUB_PORT
#   sh install-oldkernel.sh --check [--endpoint ...]
#   sh install-oldkernel.sh --uninstall
#
# Env overrides: NT_IFACE=eth1 NT_PORTS=80,... NT_HUB=http://KIT:PORT/oldkernel
#                NT_WSSE_BODY_BYTES=0..65536 (Python/C++ modes; default 0)
#                NT_CPU_CORE=N (default: first CPU allowed for the installer)
#                NT_SHIP_THREADS=1..8 NT_SHIP_RATE_KBPS=64..10000
#                NT_STATS_INTERVAL_SEC=10..300 (default: 30)
set -u

PREFIX=/opt/networktracing-legacy
INIT=/etc/init.d/networktracing-legacy
SNIFF_USER=ntsniff
MODE=install
ENDPOINT=""
IFACE="${NT_IFACE:-}"
PORTS="${NT_PORTS:-80,8003,8005,8007,8009,8010,8011}"
WORKERS="${NT_WORKERS:-1}"   # compatibility input; capture is always single-worker
SHIPPERS="${NT_SHIP_THREADS:-4}"  # bounded concurrent Hub POST threads
SHIP_RATE_KBPS="${NT_SHIP_RATE_KBPS:-1024}" # aggregate application egress ceiling
STATS_INTERVAL_SEC="${NT_STATS_INTERVAL_SEC:-30}"
KIT_URLS="${NT_HUB:-}"
CONTROL_TOKEN_FILE=/var/lib/networktracing/control.token
CAPTURE_MODE="${NT_CAPTURE_MODE:-python}"
WSSE_BODY_BYTES="${NT_WSSE_BODY_BYTES:-0}"
CPU_CORE="${NT_CPU_CORE:-}"
TOKEN_INPUT_FILE=""
ALLOW_KIT_FETCH=1

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'EOF'
Usage: install-firstrun-el68.sh --server URL [options]

  --server URL              Hub ingest URL, including its actual port
  --endpoint URL            Alias for --server
  --kit-url URL             Exact bootstrap-kit URL
  --iface IFACE             Capture interface, for example eth0
  --ports LIST              Comma-separated ports, for example 80,8001,8080
  --mode python|cpp         Capture engine (default: python)
  --wsse-bytes N            SOAP prefix window, 0..65536 (default: 0)
  --cpu N                   One allowed logical CPU number
  --ship-threads N          Python poster threads, 1..8 (default: 4)
  --ship-rate-kbps N        Egress ceiling, 64..10000 kbit/s (default: 1024)
  --stats-interval-sec N    Agent statistics interval, 10..300s (default: 30)
  --control-token-file FILE Read the control token from FILE
  --offline                 Use only local/embedded kit; never fetch fallback
  --check                   Preflight only; make no installation changes
  --uninstall               Remove the installed agent
EOF
}

need_value() { [ "$#" -ge 2 ] || die "$1 requires a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --server)   need_value "$@"; ENDPOINT="$2"; shift 2 ;;
        --endpoint) need_value "$@"; ENDPOINT="$2"; shift 2 ;;
        --hub|--kit-url) need_value "$@"; KIT_URLS="$2"; shift 2 ;;
        --iface)    need_value "$@"; IFACE="$2"; shift 2 ;;
        --ports)    need_value "$@"; PORTS="$2"; shift 2 ;;
        --mode)     need_value "$@"; CAPTURE_MODE="$2"; shift 2 ;;
        --wsse-body-bytes|--wsse-bytes) need_value "$@"; WSSE_BODY_BYTES="$2"; shift 2 ;;
        --cpu)      need_value "$@"; CPU_CORE="$2"; shift 2 ;;
        --ship-threads) need_value "$@"; SHIPPERS="$2"; shift 2 ;;
        --ship-rate-kbps) need_value "$@"; SHIP_RATE_KBPS="$2"; shift 2 ;;
        --stats-interval-sec) need_value "$@"; STATS_INTERVAL_SEC="$2"; shift 2 ;;
        --control-token-file) need_value "$@"; TOKEN_INPUT_FILE="$2"; shift 2 ;;
        --offline)  ALLOW_KIT_FETCH=0; shift ;;
        --install)  MODE=install; shift ;;
        --check)    MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
done

for url_value in "$ENDPOINT" "$KIT_URLS"; do
    [ -z "$url_value" ] && continue
    case "$url_value" in http://*|https://*) : ;; *) die "URLs must start with http:// or https://" ;; esac
    case "$url_value" in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/._-]*)
            die "URL contains unsupported characters" ;;
    esac
done
case "$IFACE" in
    '' ) : ;;
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-]*) die "invalid interface name" ;;
esac
[ ${#IFACE} -le 32 ] || die "interface name is too long"
case "$PORTS" in ''|,*|*,|*,,*|*[!0-9,]*) die "ports must be comma-separated integers" ;; esac
old_ifs=$IFS
IFS=,
set -- $PORTS
IFS=$old_ifs
PORT_COUNT=0
for port_value do
    PORT_COUNT=$((PORT_COUNT + 1))
    [ "$port_value" -ge 1 ] 2>/dev/null && [ "$port_value" -le 65535 ] 2>/dev/null \
        || die "each port must be in range 1..65535"
done
[ "$PORT_COUNT" -le 30 ] || die "at most 30 monitored ports are allowed by the safe cBPF program"
case "$CAPTURE_MODE" in python|cpp) : ;; *) die "mode must be python or cpp" ;; esac
case "$SHIPPERS" in ''|*[!0-9]*) die "ship threads must be an integer 1..8" ;; esac
[ "$SHIPPERS" -ge 1 ] && [ "$SHIPPERS" -le 8 ] || die "ship threads must be in range 1..8"
case "$SHIP_RATE_KBPS" in ''|*[!0-9]*) die "ship rate must be an integer 64..10000" ;; esac
[ "$SHIP_RATE_KBPS" -ge 64 ] && [ "$SHIP_RATE_KBPS" -le 10000 ] \
    || die "ship rate must be in range 64..10000 kbit/s"
case "$STATS_INTERVAL_SEC" in ''|*[!0-9]*) die "stats interval must be an integer 10..300" ;; esac
[ "$STATS_INTERVAL_SEC" -ge 10 ] && [ "$STATS_INTERVAL_SEC" -le 300 ] \
    || die "stats interval must be in range 10..300 seconds"

case "$WSSE_BODY_BYTES" in
    ''|*[!0-9]*) die "WSSE body byte window must be an integer 0..65536" ;;
esac
[ "$WSSE_BODY_BYTES" -le 65536 ] \
    || die "WSSE body byte window must be in range 0..65536"
if [ -n "$TOKEN_INPUT_FILE" ]; then
    [ -f "$TOKEN_INPUT_FILE" ] && [ -r "$TOKEN_INPUT_FILE" ] \
        || die "control token file is not readable"
    TOKEN_SIZE=$(wc -c < "$TOKEN_INPUT_FILE" | tr -d ' ')
    case "$TOKEN_SIZE" in ''|*[!0-9]*) die "cannot measure control token file" ;; esac
    [ "$TOKEN_SIZE" -ge 1 ] && [ "$TOKEN_SIZE" -le 4096 ] \
        || die "control token file must contain 1..4096 bytes"
    NT_CONTROL_TOKEN=$(sed -n '1p' "$TOKEN_INPUT_FILE")
    [ -n "$NT_CONTROL_TOKEN" ] || die "control token file is empty"
    export NT_CONTROL_TOKEN
fi
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
#   3. fetched from an explicitly configured bootstrap URL (--kit-url)
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
        [ "$ALLOW_KIT_FETCH" = 1 ] \
            || die "offline mode: local or embedded kit is incomplete"
        [ -n "$KIT_URLS" ] || die "kit files missing and no embedded payload — pass --kit-url http://KIT_HOST:KIT_PORT/oldkernel"
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
case "$(uname -r)" in
    2.6.32-642.el6*)
        log "WARN: kernel $(uname -r) predates later vendor AF_PACKET errata; strict TPACKET_V2 avoids V3-only configuration paths but cannot patch kernel defects"
        ;;
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
have chrt || die "chrt required for the lowest-priority SCHED_IDLE boundary"
if [ -z "$CPU_CORE" ]; then
    CPU_CORE=$(awk '/^Cpus_allowed_list:/ { gsub(/[,-].*/, "", $2); print $2; exit }' /proc/self/status 2>/dev/null)
fi
case "$CPU_CORE" in
    ''|*[!0-9]*) die "cannot select an allowed CPU core (set NT_CPU_CORE=N)" ;;
esac
taskset -c "$CPU_CORE" true >/dev/null 2>&1 \
    || die "CPU core $CPU_CORE is outside this host/process cpuset"
taskset -c "$CPU_CORE" chrt -i 0 nice -n 19 true >/dev/null 2>&1 \
    || die "cannot enforce SCHED_IDLE, nice 19, and CPU affinity"

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
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/python-capnetraw -c 'import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()'" >/dev/null 2>&1; then
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
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra $CXXSTD nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra $CXXSTD -pthread nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
    if [ -f "$PREFIX/nt-sniff-cpp" ] && have setcap && have useradd; then
        chown "$SNIFF_USER" "$PREFIX/nt-sniff-cpp" 2>/dev/null || true
        chmod 750 "$PREFIX/nt-sniff-cpp" 2>/dev/null || true
        if setcap cap_net_raw+ep "$PREFIX/nt-sniff-cpp" 2>/dev/null \
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/nt-sniff-cpp --capability-probe -i $IFACE -p $PORTS" >/dev/null 2>&1; then
            SNIFF_AS="$SNIFF_USER"
            log "rootless mode: cap_net_raw on native C++ binary, user=$SNIFF_USER"
        else
            SNIFF_AS=root
            log "WARN: rootless capability execution failed — safe runtime boundary unavailable"
        fi
    fi
    [ "$SNIFF_AS" != root ] \
        || die "safe rootless C++ capture unavailable; refusing to run the agent as root"
    SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --stats-interval-sec $STATS_INTERVAL_SEC --wsse-body-bytes $WSSE_BODY_BYTES'"
    SHIP_CMD="exec su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/nt-ship-cpp --endpoint $ENDPOINT --ship-rate-kbps $SHIP_RATE_KBPS --stats-interval-sec $STATS_INTERVAL_SEC'"
    RUN_CMD="$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1"
    EXPECTED_SHIP=nt-ship-cpp
    log "native C++ nonblocking capture + bounded shipper pipeline selected"
else
    if [ "$SNIFF_AS" != root ]; then
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS --wsse-body-bytes $WSSE_BODY_BYTES'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS --wsse-body-bytes $WSSE_BODY_BYTES"
    fi
    SHIP_CMD="exec su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE python -u $PREFIX/nt-ship.py --endpoint $ENDPOINT'"
    RUN_CMD="$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1"
    EXPECTED_SHIP=nt-ship.py
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
export NT_SHIP_RATE_KBPS=$SHIP_RATE_KBPS
export NT_STATS_INTERVAL_SEC=$STATS_INTERVAL_SEC
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
        # EL6 can need about two seconds to traverse guard -> supervisor ->
        # su -> interpreter/native startup. Keep this bounded but avoid a
        # false failed-start result on otherwise healthy nodes.
        sleep 3
        if { ! pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "\$PREFIX/nt-sniff-cpp" >/dev/null; } \
           || ! pgrep -f "\$PREFIX/$EXPECTED_SHIP" >/dev/null; then
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
            supervisor=\$(cat "\$PIDFILE" 2>/dev/null || true)
            case "\$supervisor" in
                ''|*[!0-9]*) : ;;
                *)
                    kill "\$supervisor" 2>/dev/null || true
                    _sw=0
                    while [ \$_sw -lt 5 ] && kill -0 "\$supervisor" 2>/dev/null; do
                        sleep 1
                        _sw=\$((_sw + 1))
                    done
                    kill -0 "\$supervisor" 2>/dev/null && kill -9 "\$supervisor" 2>/dev/null || true
                    ;;
            esac
        fi
        for pattern in "\$PREFIX/nt-sniff.py" "\$PREFIX/nt-sniff-cpp" "\$PREFIX/nt-ship.py" "\$PREFIX/nt-ship-cpp"; do
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
if { ! pgrep -f "$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null; } \
   || ! pgrep -f "$PREFIX/$EXPECTED_SHIP" >/dev/null; then
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "capture/ship pipeline not running after start"
fi

log "DONE. Sniffer iface=$IFACE ports=$PORTS -> hub $ENDPOINT (capture-as=$SNIFF_AS)"
log "Safety: rootless, cpu=$CPU_CORE (one logical core/SCHED_IDLE/nice 19), memory=256MiB, fds=1024, output-file=32MiB, crash circuit=5"
log "Network egress: aggregate application payload limit=${SHIP_RATE_KBPS}kbit/s, HTTP body cap=65536 bytes"
log "Agent statistics: $ENDPOINT/api/agent/stats every ${STATS_INTERVAL_SEC}s, body cap=16384 bytes"
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
LWluIFdTU0UgcGFyc2luZyBoYXMgc3RyaWN0IHBlci1mbG93L2dsb2JhbCBib3VuZHMKVXNhZ2U6
ICBweXRob24gbnQtc25pZmYucHkgWy1pIGV0aDBdIFstcCA4MCw4MDAzLC4uLl0gWy1qIHdvcmtl
cnNdCiAgICAgICAgICAgICAgICAgICAgICAgICAgIFstLXdzc2UtYm9keS1ieXRlcyAwLi42NTUz
Nl0KU3Rkb3V0OiBvbmUgSlNPTiBldmVudCBwZXIgbGluZSAtPiBwaXBlIGludG8gbnQtc2hpcC5w
eS4KIiIiCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgcHJpbnRfZnVuY3Rpb24KCmltcG9ydCBiYXNl
NjQsIGJpbmFzY2lpLCBlcnJubywganNvbiwgb3MsIHNpZ25hbCwgc29ja2V0LCBzdHJ1Y3QsIHN5
cywgdGltZQppbXBvcnQgdW5pY29kZWRhdGEKZnJvbSB4bWwucGFyc2VycyBpbXBvcnQgZXhwYXQK
CkVUSF9QX0FMTCA9IDB4MDAwMwpFVEhfUF9JUCA9IDB4MDgwMApFVEhfUF9WTEFOID0gMHg4MTAw
ClNPTF9QQUNLRVQgPSAyNjMKUEFDS0VUX1NUQVRJU1RJQ1MgPSA2CkRFRkFVTFRfU1RBVFNfSU5U
RVJWQUwgPSAzMAoKdHJ5OgogICAgaW1wb3J0IG50X2NvbnRyb2wKZXhjZXB0IEltcG9ydEVycm9y
OgogICAgbnRfY29udHJvbCA9IE5vbmUKCiMgcHkyLjYgc3RyLWluZGV4aW5nIHlpZWxkcyAxLWNo
YXIgc3RyLCBub3QgaW50IChwcm92ZW4gb24gcmVhbCBlbDYgVk0pOwojIG5vcm1hbGl6ZSBzbyBi
eXRlLWF0LWluZGV4IHdvcmtzIGlkZW50aWNhbGx5IHVuZGVyIHB5dGhvbiAyIGFuZCAzClBZMiA9
IHN5cy52ZXJzaW9uX2luZm9bMF0gPT0gMgoKCmRlZiBiMmkoYyk6CiAgICByZXR1cm4gb3JkKGMp
IGlmIFBZMiBlbHNlIGMKCk1FVEhPRFMgPSAoIkdFVCIsICJQT1NUIiwgIlBVVCIsICJERUxFVEUi
LCAiUEFUQ0giLCAiSEVBRCIsICJPUFRJT05TIikKCk1BWF9GTE9XUyA9IDgxOTIgICAgICAgICAg
ICAjIGNvbmN1cnJlbnQgdHJhY2tlZCBoYWxmLWZsb3dzIChwZXIgZGlyZWN0aW9uKQpNQVhfSERS
UyA9IDI2MjE0NCAgICAgICAgICAgIyBtYXggYnl0ZXMgYnVmZmVyZWQgd2FpdGluZyBmb3IgXHJc
blxyXG4KRkxPV19UVEwgPSAzMDAgICAgICAgICAgICAgICMgc2Vjb25kcyBiZWZvcmUgaWRsZSBm
bG93IGJ1ZmZlcnMgYXJlIGRyb3BwZWQKTUFYX1dTU0VfQk9EWV9CWVRFUyA9IDY1NTM2ICMgaGFy
ZCBjZWlsaW5nIGV2ZW4gaWYgY29uZmlndXJhdGlvbiBpcyBsYXJnZXIKTUFYX1dTU0VfQk9EWV9G
TE9XUyA9IDI1NiAgICMgYXQgbW9zdCAxNiBNaUIgb2Ygb3B0LWluIGJvZHkgYnVmZmVycyBnbG9i
YWxseQpNQVhfV1NTRV9VU0VSTkFNRSA9IDIwMAoKV1NTRV9OQU1FU1BBQ0VTID0gc2V0KCgKICAg
ICJodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEtd3Nz
LXdzc2VjdXJpdHktc2VjZXh0LTEuMC54c2QiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAu
b3JnL3dzLzIwMDIvMDcvc2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93
cy8yMDAyLzEyL3NlY2V4dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAw
My8wNi9zZWNleHQiLAopKQoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUoIm50
LXNuaWZmOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCmRlZiBzdGF0c19p
bnRlcnZhbF9zZWNvbmRzKCk6CiAgICB0cnk6CiAgICAgICAgdmFsdWUgPSBpbnQob3MuZW52aXJv
bi5nZXQoIk5UX1NUQVRTX0lOVEVSVkFMX1NFQyIsCiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgc3RyKERFRkFVTFRfU1RBVFNfSU5URVJWQUwpKSkKICAgIGV4Y2VwdCBWYWx1ZUVy
cm9yOgogICAgICAgIHZhbHVlID0gREVGQVVMVF9TVEFUU19JTlRFUlZBTAogICAgcmV0dXJuIG1h
eCgxMCwgbWluKHZhbHVlLCAzMDApKQoKCmRlZiBkcm9wX2NhcHR1cmVfY2FwYWJpbGl0aWVzKCk6
CiAgICAiIiJJcnJldmVyc2libHkgY2xlYXIgQ0FQX05FVF9SQVcgYWZ0ZXIgdGhlIHBhY2tldCBz
b2NrZXQgaXMgcmVhZHkuIiIiCiAgICB0cnk6CiAgICAgICAgaW1wb3J0IGN0eXBlcwogICAgICAg
IGxpYmNhcCA9IGN0eXBlcy5DRExMKCJsaWJjYXAuc28uMiIpCiAgICAgICAgbGliY2FwLmNhcF9p
bml0LnJlc3R5cGUgPSBjdHlwZXMuY192b2lkX3AKICAgICAgICBlbXB0eSA9IGxpYmNhcC5jYXBf
aW5pdCgpCiAgICAgICAgaWYgbm90IGVtcHR5OgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAg
ICAgICB0cnk6CiAgICAgICAgICAgIHJldHVybiBsaWJjYXAuY2FwX3NldF9wcm9jKGN0eXBlcy5j
X3ZvaWRfcChlbXB0eSkpID09IDAKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBsaWJjYXAu
Y2FwX2ZyZWUoY3R5cGVzLmNfdm9pZF9wKGVtcHR5KSkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAg
ICAgICAgcmV0dXJuIEZhbHNlCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHBlcmY6IGNCUEYKIyBBdHRhY2ggYSBjbGFz
c2ljIEJQRiBwcm9ncmFtIHNvIHRoZSBLRVJORUwgZHJvcHMgZXZlcnl0aGluZyB0aGF0IGlzIG5v
dAojIElQdjQgVENQIHRvIG9yIGZyb20gYSBtb25pdG9yZWQgcG9ydC4gUmVxdWVzdCBoZWFkZXJz
IGRyaXZlIGV2ZW50cyBhbmQKIyByZXNwb25zZSBoZWFkZXJzIGVucmljaCB0aGVtOyB1bnJlbGF0
ZWQgdHJhZmZpYyBuZXZlciByZWFjaGVzIHVzZXJzcGFjZS4KU09fQVRUQUNIX0ZJTFRFUiA9IDI2
CgpkZWYgYnVpbGRfYnBmKHBvcnRzKToKICAgICIiIkNsYXNzaWMgQlBGOiBldGhlcnR5cGU9PUlQ
ICYmIHByb3RvPT1UQ1AgJiYgZHBvcnQgaW4gcG9ydHMuCiAgICBSZXR1cm5zIChmcHJvZ19zdHJ1
Y3QsIGZpbHRlcl9hcnJheSkgZm9yIHRoZSBsaWJjIHNldHNvY2tvcHQgY2FsbCwKICAgIG9yIE5v
bmUgb24gZmFpbHVyZS4gTk9URTogc29ja19mcHJvZyBjYXJyaWVzIGEgUE9JTlRFUiB0byB0aGUg
ZmlsdGVyCiAgICBhcnJheSwgc28gaXQgbXVzdCBzdGF5IGFsaXZlIHVudGlsIHRoZSBzeXNjYWxs
IOKAlCBweXRob24ncwogICAgc29ja2V0LnNldHNvY2tvcHQoc3RyKSBmbGF0dGVuaW5nIGNhbm5v
dCBwcmVzZXJ2ZSBpdC4iIiIKCiAgICBMREhfQUJTID0gMHgyOCAgICMgbGQgW2tdOmgKICAgIExE
Ql9BQlMgPSAweDMwICAgIyBsZCBba106YgogICAgSkVRX0sgPSAweDE1ICAgICAjIGplcSBrCiAg
ICBMRFhfTVNIID0gMHhCMSAgICMgeCA9IDQqKFtrXSYweGYpICAoaWhsIGJ5dGVzKQogICAgTERI
X0lORCA9IDB4NDggICAjIGxkIFt4K2tdOmgKICAgIFJFVF9LID0gMHgwNgoKICAgICMgUFJPVkVO
IGRwb3J0IGJsb2NrICsgc3BvcnQgYmxvY2sgYXQgWCsxNCAoY2FsaWJyYXRlZCBFTVBJUklDQUxM
WSBvbgogICAgIyBhIGxpdmUga2VybmVsOiBrPTE0IGRlbGl2ZXJzIHJlc3BvbnNlIHBhY2tldHM7
IHRoZSBjb3JyZWxhdGlvbiB0aGVuCiAgICAjIHlpZWxkcyBzdGF0dXMvZHVyYXRpb25fbXMvcmVz
cF9ieXRlcyBlbmQtdG8tZW5kKS4gUmVxdWlyZXMgdGhlIDFzCiAgICAjIHJlY3YgdGltZW91dCBp
biBtYWluKCkg4oCUIGJsb2NraW5nIHJlY3YgKyBCUEYgc3RhcnZlcyBhZnRlciBvbmUgcGt0Lgog
ICAgc2sgPSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX1NQT1JUX0siLCAiMTQiKSkKICAg
IHBzID0gc29ydGVkKHBvcnRzKQogICAgbiA9IGxlbihwcykKICAgIHJldF9yZWogPSA1ICsgKDQg
aWYgc2sgZWxzZSAyKSAqIG4KICAgIHJldF9hY2MgPSByZXRfcmVqICsgMQogICAgcHJvZyA9IFtd
CiAgICBwcm9nLmFwcGVuZCgoTERIX0FCUywgMCwgMCwgMTIpKSAgICAgICAgICAgICAgICAgIyBl
dGhlcnR5cGUgPT0gSVA/CiAgICBwcm9nLmFwcGVuZCgoSkVRX0ssIDAsIHJldF9yZWogLSAyLCAw
eDA4MDApKQogICAgcHJvZy5hcHBlbmQoKExEQl9BQlMsIDAsIDAsIDIzKSkgICAgICAgICAgICAg
ICAgICMgcHJvdG8gPT0gVENQPwogICAgcHJvZy5hcHBlbmQoKEpFUV9LLCAwLCByZXRfcmVqIC0g
NCwgNikpCiAgICBwcm9nLmFwcGVuZCgoTERYX01TSCwgMCwgMCwgMTQpKSAgICAgICAgICAgICAg
ICAgIyBYID0gaWhsKjQKICAgIGZvciBpLCBwIGluIGVudW1lcmF0ZShwcyk6ICAgICAgICAgICAg
ICAgICAgICAgICAjIEE6IGRwb3J0IEAgWCsxNgogICAgICAgIHByb2cuYXBwZW5kKChMREhfSU5E
LCAwLCAwLCAxNikpCiAgICAgICAganQgPSByZXRfYWNjIC0gKGxlbihwcm9nKSArIDEpCiAgICAg
ICAgamYgPSAwIGlmIChpIDwgbiAtIDEgb3Igc2spIGVsc2UgKHJldF9yZWogLSAobGVuKHByb2cp
ICsgMSkpCiAgICAgICAgcHJvZy5hcHBlbmQoKEpFUV9LLCBqdCwgamYsIHApKQogICAgaWYgc2s6
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICMgQjogc3BvcnQgQCBY
K3NrCiAgICAgICAgZm9yIGksIHAgaW4gZW51bWVyYXRlKHBzKToKICAgICAgICAgICAgcHJvZy5h
cHBlbmQoKExESF9JTkQsIDAsIDAsIHNrKSkKICAgICAgICAgICAganQgPSByZXRfYWNjIC0gKGxl
bihwcm9nKSArIDEpCiAgICAgICAgICAgIGpmID0gMCBpZiBpIDwgbiAtIDEgZWxzZSAocmV0X3Jl
aiAtIChsZW4ocHJvZykgKyAxKSkKICAgICAgICAgICAgcHJvZy5hcHBlbmQoKEpFUV9LLCBqdCwg
amYsIHApKQogICAgcHJvZy5hcHBlbmQoKFJFVF9LLCAwLCAwLCAwKSkgICAgICAgICAgICAgICAg
ICAgICMgcmVqZWN0CiAgICBwcm9nLmFwcGVuZCgoUkVUX0ssIDAsIDAsIDB4NDAwMDApKSAgICAg
ICAgICAgICAgIyBhY2NlcHQKICAgIGlmIGFueShqdCA+IDI1NSBvciBqZiA+IDI1NSBmb3IgXywg
anQsIGpmLCBfIGluIHByb2cpOgogICAgICAgIHJldHVybiBOb25lCgogICAgdHJ5OgogICAgICAg
IGltcG9ydCBjdHlwZXMKCiAgICAgICAgY2xhc3MgU29ja0ZpbHRlcihjdHlwZXMuU3RydWN0dXJl
KToKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJjb2RlIiwgY3R5cGVzLmNfdWludDE2KSwgKCJq
dCIsIGN0eXBlcy5jX3VpbnQ4KSwKICAgICAgICAgICAgICAgICAgICAgICAgKCJqZiIsIGN0eXBl
cy5jX3VpbnQ4KSwgKCJrIiwgY3R5cGVzLmNfdWludDMyKV0KCiAgICAgICAgY2xhc3MgU29ja0Zw
cm9nKGN0eXBlcy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICAjIG1pcnJvcnMgc3RydWN0IHNvY2tf
ZnByb2cge3UxNiBsZW47IHNvY2tfZmlsdGVyICpmaWx0ZXJ9OwogICAgICAgICAgICAjIGN0eXBl
cyBhcHBsaWVzIHRoZSBzYW1lIHBvaW50ZXIgYWxpZ25tZW50IGFzIHRoZSBjb21waWxlcgogICAg
ICAgICAgICBfZmllbGRzXyA9IFsoImxlbiIsIGN0eXBlcy5jX3VpbnQxNiksCiAgICAgICAgICAg
ICAgICAgICAgICAgICgiZmlsdGVyIiwgY3R5cGVzLlBPSU5URVIoU29ja0ZpbHRlcikpXQoKICAg
ICAgICBhcnIgPSAoU29ja0ZpbHRlciAqIGxlbihwcm9nKSkoKQogICAgICAgIGZvciBpLCAoY29k
ZSwganQsIGpmLCBrKSBpbiBlbnVtZXJhdGUocHJvZyk6CiAgICAgICAgICAgIGFycltpXS5jb2Rl
ID0gY29kZTsgYXJyW2ldLmp0ID0ganQKICAgICAgICAgICAgYXJyW2ldLmpmID0gamY7IGFycltp
XS5rID0gawogICAgICAgIHJldHVybiBTb2NrRnByb2cobGVuKHByb2cpLCBhcnIpLCBhcnIKICAg
IGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYgYXBwbHlfcGVyZl9v
cHRzKHNvY2ssIHBvcnRzKToKICAgICIiIkF0dGFjaCB0aGUgbWFuZGF0b3J5IGtlcm5lbCBwb3J0
IGZpbHRlciBhbmQgdHVuZSB0aGUgcmVjZWl2ZSBidWZmZXIuIiIiCiAgICBidWlsdCA9IGJ1aWxk
X2JwZihwb3J0cykKICAgIGZpbHRlcl9vayA9IEZhbHNlCiAgICBpZiBidWlsdCBpcyBub3QgTm9u
ZToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGltcG9ydCBjdHlwZXMKICAgICAgICAgICAgbGli
YyA9IGN0eXBlcy5DRExMKCJsaWJjLnNvLjYiKQogICAgICAgICAgICBmcHJvZywgYXJyID0gYnVp
bHQgICAgICAgICAgICAgICAgICAgICAgIyBrZWVwIGFyciByZWZlcmVuY2VkIQogICAgICAgICAg
ICByZXQgPSBsaWJjLnNldHNvY2tvcHQoc29jay5maWxlbm8oKSwgc29ja2V0LlNPTF9TT0NLRVQs
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBTT19BVFRBQ0hfRklMVEVSLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLmJ5cmVmKGZwcm9nKSwKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN0eXBlcy5zaXplb2YoZnByb2cpKQogICAgICAg
ICAgICBpZiByZXQgPT0gMDoKICAgICAgICAgICAgICAgIGxvZygia2VybmVsIEJQRiBmaWx0ZXIg
YXR0YWNoZWQgKCVkIG1vbml0b3JlZCBwb3J0cykiCiAgICAgICAgICAgICAgICAgICAgJSBsZW4o
cG9ydHMpKQogICAgICAgICAgICAgICAgZmlsdGVyX29rID0gVHJ1ZQogICAgICAgICAgICBlbHNl
OgogICAgICAgICAgICAgICAgbG9nKCJCUEYgYXR0YWNoIHJlamVjdGVkIGJ5IGtlcm5lbCAocmV0
PSVkKSIgJSByZXQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBs
b2coIkJQRiBmaWx0ZXIgYXR0YWNoIGZhaWxlZCAoJXMpIiAlIGUpCiAgICBlbHNlOgogICAgICAg
IGxvZygiQlBGIGNvbnN0cnVjdGlvbiB1bmF2YWlsYWJsZSIpCiAgICB0cnk6CiAgICAgICAgd2Fu
dCA9IDggKiAxMDI0ICogMTAyNAogICAgICAgIHNvY2suc2V0c29ja29wdChzb2NrZXQuU09MX1NP
Q0tFVCwgc29ja2V0LlNPX1JDVkJVRiwgd2FudCkKICAgICAgICBnb3QgPSBzb2NrLmdldHNvY2tv
cHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SQ1ZCVUYpCiAgICAgICAgbG9nKCJyY3Zi
dWY6ICVkIGJ5dGVzIiAlIGdvdCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBs
b2coIldBUk46IFNPX1JDVkJVRiByYWlzZSBmYWlsZWQ6ICVzIiAlIGUpCiAgICByZXR1cm4gZmls
dGVyX29rCgoKZGVmIHBhcnNlX3dzc2VfYm9keV9ieXRlcyh2YWx1ZSk6CiAgICAiIiJWYWxpZGF0
ZSB0aGUgb3B0LWluIGJvZHkgd2luZG93IHdpdGhvdXQgYWxsb3dpbmcgdW5ib3VuZGVkIGJ1ZmZl
cnMuIiIiCiAgICB0cnk6CiAgICAgICAgc2l6ZSA9IGludCh2YWx1ZSBvciAwKQogICAgZXhjZXB0
IChUeXBlRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIndzc2Ug
Ym9keSBieXRlcyBtdXN0IGJlIGFuIGludGVnZXIiKQogICAgaWYgc2l6ZSA8IDAgb3Igc2l6ZSA+
IE1BWF9XU1NFX0JPRFlfQllURVM6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgid3NzZSBib2R5
IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4uJWQiICUKICAgICAgICAgICAgICAgICAgICAgICAg
IE1BWF9XU1NFX0JPRFlfQllURVMpCiAgICByZXR1cm4gc2l6ZQoKCmRlZiBwYXJzZV9hcmdzKGFy
Z3YpOgogICAgaWZhY2UgPSBOb25lCiAgICBwb3J0cyA9IFs4MCwgODAwMywgODAwNSwgODAwNywg
ODAwOSwgODAxMCwgODAxMV0KICAgIHZlcmJvc2UgPSBGYWxzZQogICAgd29ya2VycyA9IDEKICAg
IHdzc2VfYm9keV9ieXRlcyA9IHBhcnNlX3dzc2VfYm9keV9ieXRlcygKICAgICAgICBvcy5lbnZp
cm9uLmdldCgiTlRfV1NTRV9CT0RZX0JZVEVTIiwgIjAiKSkKICAgIGkgPSAwCiAgICB3aGlsZSBp
IDwgbGVuKGFyZ3YpOgogICAgICAgIGEgPSBhcmd2W2ldCiAgICAgICAgaWYgYSA9PSAiLWkiOgog
ICAgICAgICAgICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCItaSByZXF1aXJlcyBhbiBpbnRlcmZhY2UiKQogICAgICAgICAgICBpICs9IDE7
IGlmYWNlID0gYXJndltpXQogICAgICAgIGVsaWYgYSA9PSAiLXAiOgogICAgICAgICAgICBpZiBp
ICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCItcCBy
ZXF1aXJlcyBhIGNvbW1hLXNlcGFyYXRlZCBwb3J0IGxpc3QiKQogICAgICAgICAgICBpICs9IDEK
ICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcG9ydHMgPSBbaW50KHgpIGZvciB4IGlu
IGFyZ3ZbaV0uc3BsaXQoIiwiKSBpZiB4LnN0cmlwKCldCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1
ZUVycm9yOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiaW52YWxpZCBwb3J0IGxp
c3QiKQogICAgICAgICAgICBpZiBub3QgcG9ydHMgb3IgYW55KG5vdCB2YWxpZF9wb3J0KHgpIGZv
ciB4IGluIHBvcnRzKToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoInBvcnRzIG11
c3QgYmUgaW4gcmFuZ2UgMS4uNjU1MzUiKQogICAgICAgICAgICBpZiBsZW4ocG9ydHMpID4gMzA6
CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJhdCBtb3N0IDMwIG1vbml0b3JlZCBw
b3J0cyBhcmUgc3VwcG9ydGVkIikKICAgICAgICBlbGlmIGEgPT0gIi1qIjoKICAgICAgICAgICAg
aWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgi
LWogcmVxdWlyZXMgYSB3b3JrZXIgY291bnQiKQogICAgICAgICAgICBpICs9IDEKICAgICAgICAg
ICAgdHJ5OgogICAgICAgICAgICAgICAgd29ya2VycyA9IGludChhcmd2W2ldKQogICAgICAgICAg
ICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImlu
dmFsaWQgd29ya2VyIGNvdW50IikKICAgICAgICAgICAgaWYgd29ya2VycyAhPSAxOgogICAgICAg
ICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgib25seSBvbmUgY2FwdHVyZSB3b3JrZXIgaXMgcGVy
bWl0dGVkIikKICAgICAgICBlbGlmIGEgPT0gIi12IjoKICAgICAgICAgICAgdmVyYm9zZSA9IFRy
dWUKICAgICAgICBlbGlmIGEgPT0gIi0td3NzZS1ib2R5LWJ5dGVzIjoKICAgICAgICAgICAgaWYg
aSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLS13
c3NlLWJvZHktYnl0ZXMgcmVxdWlyZXMgYSBieXRlIGNvdW50IikKICAgICAgICAgICAgaSArPSAx
CiAgICAgICAgICAgIHdzc2VfYm9keV9ieXRlcyA9IHBhcnNlX3dzc2VfYm9keV9ieXRlcyhhcmd2
W2ldKQogICAgICAgIGVsaWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmlu
dChfX2RvY19fKTsgcmFpc2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAg
IHJhaXNlIFN5c3RlbUV4aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQog
ICAgcmV0dXJuIGlmYWNlLCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlf
Ynl0ZXMKCgpjbGFzcyBGbG93KG9iamVjdCk6CiAgICBfX3Nsb3RzX18gPSAoImJ1ZiIsICJoZHJz
IiwgInRvdWNoZWQiLCAiZXZlbnQiLCAiYm9keV9nb2FsIiwKICAgICAgICAgICAgICAgICAiaGVh
ZF9ieXRlcyIpCiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5idWYgPSBieXRl
YXJyYXkoKQogICAgICAgIHNlbGYuaGRycyA9IE5vbmUKICAgICAgICBzZWxmLnRvdWNoZWQgPSB0
aW1lLnRpbWUoKQogICAgICAgIHNlbGYuZXZlbnQgPSBOb25lCiAgICAgICAgc2VsZi5ib2R5X2dv
YWwgPSAwCiAgICAgICAgc2VsZi5oZWFkX2J5dGVzID0gMAoKCiMgLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAtLS0t
ClBFTkRJTkdfVFRMID0gNS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBhZnRl
ciB0aGlzIG1hbnkgc2Vjb25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNhcDsg
b3ZlcmZsb3cgZmx1c2hlcyBvbGRlc3QgZmlyc3QKUEVORElOR19QRVJfRkxPVyA9IDMyICAgICMg
Ym91bmQgYSBzaW5nbGUgcGlwZWxpbmVkL2hvc3RpbGUga2VlcC1hbGl2ZSBmbG93ClNXRUVQX0lO
VEVSVkFMID0gMS4wICAgICAjIGhvbm9yIFBFTkRJTkdfVFRMIGV2ZW4gd2hlbiB0aGUgc29ja2V0
IGdvZXMgaWRsZQoKIyBwZW5kaW5nWyhzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KV0gIC0t
IGtleSBpcyB0aGUgUkVTUE9OU0UgdHVwbGU6CiMgc2VydmVyLT5jbGllbnQuIFZhbHVlOiBbZXZl
bnQsIHJlcV90c10uIEEgbGlzdCBwZXIga2V5IGhhbmRsZXMgSFRUUAojIGtlZXAtYWxpdmUgcGlw
ZWxpbmluZyAoc2V2ZXJhbCByZXF1ZXN0cyBiZWZvcmUgcmVzcG9uc2VzIGFycml2ZSkuCnBlbmRp
bmcgPSB7fQoKCmRlZiBwZW5kaW5nX2RlbChyayk6CiAgICBwZW5kaW5nLnBvcChyaywgTm9uZSkK
CgpkZWYgcGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190Ymw9Tm9uZSk6CiAgICAiIiJGbHVz
aCB0aGUgb2xkZXN0IHBlbmRpbmcgZXZlbnQgZm9yIHRoaXMgcmVzcG9uc2UgdHVwbGUgKEZJTi9S
U1Qgb3IKICAgIG92ZXJmbG93IHBhdGgpLiBFbWl0cyB3aGF0ZXZlciB0aGUgZXZlbnQgaGFzIOKA
lCBzdGF0dXMgc3RheXMgbnVsbC4iIiIKICAgIGlmIHBlbmRpbmdfdGJsIGlzIE5vbmU6CiAgICAg
ICAgcGVuZGluZ190YmwgPSBwZW5kaW5nCiAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAg
ICBpZiBub3QgbHN0OgogICAgICAgIHJldHVybiBOb25lCiAgICBldiwgXyA9IGxzdC5wb3AoMCkK
ICAgIGlmIG5vdCBsc3Q6CiAgICAgICAgcGVuZGluZ190YmwucG9wKHJrLCBOb25lKQogICAgb3V0
LmFwcGVuZChldikKICAgIHJldHVybiBldgoKCmRlZiBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxv
YWQpOgogICAgIiIiRmlyc3QgbGluZSAnSFRUUC8xLnggTk5OIC4uLicgLT4gKHN0YXR1c19pbnR8
Tm9uZSwgY29udGVudF9sZW58Tm9uZSkuCiAgICBPbmx5IGxvb2tzIGF0IHdoYXQncyBpbiB0aGlz
IHNlZ21lbnQ7IGhlYWRlcnMgZml0IG9uZSBzZWdtZW50IGZvciBhbGwKICAgIHJlYWxpc3RpYyBB
UEkgcmVzcG9uc2VzLiIiIgogICAgdHJ5OgogICAgICAgIGhlYWQgPSBwYXlsb2FkLnNwbGl0KGIi
XHJcblxyXG4iLCAxKVswXQogICAgICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIi
XG4iKS5zcGxpdChiIlxuIikKICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAg
ICBpZiBsZW4oZmlyc3QpIDwgMiBvciBub3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6
CiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgc3QgPSBpbnQoZmlyc3RbMV0p
CiAgICBleGNlcHQgKFZhbHVlRXJyb3IsIEluZGV4RXJyb3IpOgogICAgICAgIHJldHVybiBOb25l
LCBOb25lCiAgICBjbGVuID0gTm9uZQogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBs
b3cgPSBsbi5sb3dlcigpCiAgICAgICAgaWYgbG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0
aDoiKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY2xlbiA9IGludChsbi5zcGxp
dChiIjoiLCAxKVsxXS5zdHJpcCgpKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAg
ICAgICAgICAgICAgIHBhc3MKICAgICAgICAgICAgYnJlYWsKICAgIHJldHVybiBzdCwgY2xlbgoK
CmRlZiBjb3JyZWxhdGVfcmVzcG9uc2UocGVuZGluZ190YmwsIHJrLCBwYXlsb2FkLCBub3csIG91
dCk6CiAgICAiIiJBdHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhlIG9sZGVzdCByZXF1ZXN0
IG9uIGEgY29ubmVjdGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5nIGNhbiBsZWF2ZSBzZXZl
cmFsIHJlcXVlc3RzIHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXItdHVwbGUuICBDb25zdW1l
IGV4YWN0bHkgb25lIGVudHJ5OyBkZWxldGluZyB0aGUgd2hvbGUga2V5IGhlcmUgbG9zZXMKICAg
IGV2ZXJ5IHJlcXVlc3QgYWZ0ZXIgdGhlIGZpcnN0IHJlc3BvbnNlLgogICAgIiIiCiAgICBzdCwg
Y2xlbiA9IHBhcnNlX3Jlc3BvbnNlX2hlYWQocGF5bG9hZCkKICAgIGlmIHN0IGlzIE5vbmU6CiAg
ICAgICAgcmV0dXJuIEZhbHNlCiAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBu
b3QgZW50OgogICAgICAgIHJldHVybiBGYWxzZQogICAgZXYsIHN0YXJ0ZWQgPSBlbnQucG9wKDAp
CiAgICBpZiBub3QgZW50OgogICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgIGV2
WyJzdGF0dXMiXSA9IHN0CiAgICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgwLCBpbnQoKG5vdyAt
IHN0YXJ0ZWQpICogMTAwMCkpCiAgICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgIGV2WyJy
ZXNwX2J5dGVzIl0gPSBjbGVuCiAgICBvdXQuYXBwZW5kKGV2KQogICAgcmV0dXJuIFRydWUKCgpk
ZWYgdmFsaWRfcG9ydChwKToKICAgIHRyeToKICAgICAgICByZXR1cm4gMSA8PSBpbnQocCkgPD0g
NjU1MzUKICAgIGV4Y2VwdCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4g
RmFsc2UKCgpkZWYgYmFzaWNfdXNlcih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRl
ciB2YWx1ZSAtPiAodXNlcnxOb25lLCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBw
YXJ0cyA9IHZhbHVlLnN0cmlwKCkuc3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0g
MjoKICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIo
KQogICAgaWYgc2NoZW1lID09ICJiYXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQg
PSBwYXJ0c1sxXS5zdHJpcCgpCiAgICAgICAgICAgIGlmIGxlbihwYWQpID4gMTAyNDoKICAgICAg
ICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxl
bihwYWQpICUgNCkKICAgICAgICAgICAgcmF3ID0gYmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAg
ICAgICAgIGlmIGxlbihyYXcpID4gNTEyOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5v
bmUKICAgICAgICAgICAgaWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAgICAgICB1c2VyID0gcmF3
LnNwbGl0KGIiOiIsIDEpWzBdCiAgICAgICAgICAgICAgICB1c2VyID0gdXNlci5kZWNvZGUoInV0
Zi04IiwgInJlcGxhY2UiKVs6NjRdCiAgICAgICAgICAgICAgICBpZiB1c2VyOgogICAgICAgICAg
ICAgICAgICAgIHJldHVybiB1c2VyLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoK
ICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFyZXIi
OgogICAgICAgIHJldHVybiBOb25lLCAiYmVhcmVyIgogICAgcmV0dXJuIE5vbmUsIE5vbmUKCgpk
ZWYgbm9ybWFsaXplX3dzc2VfdXNlcm5hbWUodmFsdWUpOgogICAgIiIiUmV0dXJuIGEgc21hbGws
IHByaW50YWJsZSB1c2VybmFtZSBvciBOb25lOyBuZXZlciByZXR1cm4gdG9rZW4gZGF0YS4iIiIK
ICAgIGlmIHZhbHVlIGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToKICAgICAg
ICB1c2VybmFtZSA9IHZhbHVlLnN0cmlwKCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAg
cmV0dXJuIE5vbmUKICAgIGlmIG5vdCB1c2VybmFtZSBvciBsZW4odXNlcm5hbWUpID4gTUFYX1dT
U0VfVVNFUk5BTUU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGZvciBjaGFyIGluIHVzZXJuYW1l
OgogICAgICAgIGlmIHVuaWNvZGVkYXRhLmNhdGVnb3J5KGNoYXIpLnN0YXJ0c3dpdGgoIkMiKToK
ICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVybiB1c2VybmFtZQoKCmRlZiBleHRyYWN0
X3dzc2VfdXNlcm5hbWUoYm9keSk6CiAgICAiIiJQYXJzZSBhIGJvdW5kZWQsIHBvc3NpYmx5IHBh
cnRpYWwgU09BUCBwcmVmaXggYW5kIHJldHVybiBvbmx5IFVzZXJuYW1lLgoKICAgIEV4cGF0IGlz
IHJ1biBpbmNyZW1lbnRhbGx5IHNvIGEgVXNlcm5hbWVUb2tlbiBpbiB0aGUgU09BUCBIZWFkZXIg
Y2FuIGJlCiAgICByZWNvZ25pemVkIHdpdGhvdXQgcmV0YWluaW5nIG9yIHJlcXVpcmluZyB0aGUg
Y29tcGxldGUgcmVxdWVzdCBib2R5LgogICAgRFREL2VudGl0eSBkZWNsYXJhdGlvbnMgYXJlIHJl
amVjdGVkIGJlZm9yZSBwYXJzaW5nLgogICAgIiIiCiAgICBpZiBub3QgYm9keSBvciBsZW4oYm9k
eSkgPiBNQVhfV1NTRV9CT0RZX0JZVEVTIG9yIGIiXHgwMCIgaW4gYm9keToKICAgICAgICByZXR1
cm4gTm9uZQogICAgbG93ZXJlZCA9IGJ5dGVzKGJvZHkpLmxvd2VyKCkKICAgIGlmIGIiPCFkb2N0
eXBlIiBpbiBsb3dlcmVkIG9yIGIiPCFlbnRpdHkiIGluIGxvd2VyZWQ6CiAgICAgICAgcmV0dXJu
IE5vbmUKCiAgICBzdGF0ZSA9IHsic3RhY2siOiBbXSwgInRva2VuX2RlcHRoIjogMCwgInVzZXJu
YW1lX2RlcHRoIjogMCwKICAgICAgICAgICAgICJjaGFycyI6IFtdLCAidG9vX2xvbmciOiBGYWxz
ZSwgInJlc3VsdCI6IE5vbmV9CgogICAgZGVmIHNwbGl0X25hbWUobmFtZSk6CiAgICAgICAgaWYg
In0iIG5vdCBpbiBuYW1lOgogICAgICAgICAgICByZXR1cm4gIiIsIG5hbWUKICAgICAgICByZXR1
cm4gbmFtZS5yc3BsaXQoIn0iLCAxKQoKICAgIGRlZiBzdGFydChuYW1lLCBhdHRycyk6CiAgICAg
ICAgbmFtZXNwYWNlLCBsb2NhbF9uYW1lID0gc3BsaXRfbmFtZShuYW1lKQogICAgICAgIHN0YXRl
WyJzdGFjayJdLmFwcGVuZCgobmFtZXNwYWNlLCBsb2NhbF9uYW1lKSkKICAgICAgICBkZXB0aCA9
IGxlbihzdGF0ZVsic3RhY2siXSkKICAgICAgICBpZiAobm90IHN0YXRlWyJ0b2tlbl9kZXB0aCJd
IGFuZCBsb2NhbF9uYW1lID09ICJVc2VybmFtZVRva2VuIiBhbmQKICAgICAgICAgICAgICAgIG5h
bWVzcGFjZSBpbiBXU1NFX05BTUVTUEFDRVMpOgogICAgICAgICAgICBzdGF0ZVsidG9rZW5fZGVw
dGgiXSA9IGRlcHRoCiAgICAgICAgZWxpZiAoc3RhdGVbInRva2VuX2RlcHRoIl0gYW5kCiAgICAg
ICAgICAgICAgZGVwdGggPT0gc3RhdGVbInRva2VuX2RlcHRoIl0gKyAxIGFuZAogICAgICAgICAg
ICAgIGxvY2FsX25hbWUgPT0gIlVzZXJuYW1lIiBhbmQKICAgICAgICAgICAgICBuYW1lc3BhY2Ug
PT0gc3RhdGVbInN0YWNrIl1bc3RhdGVbInRva2VuX2RlcHRoIl0gLSAxXVswXSk6CiAgICAgICAg
ICAgIHN0YXRlWyJ1c2VybmFtZV9kZXB0aCJdID0gZGVwdGgKICAgICAgICAgICAgc3RhdGVbImNo
YXJzIl0gPSBbXQogICAgICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IEZhbHNlCgogICAgZGVm
IGNoYXJzKHZhbHVlKToKICAgICAgICBpZiBub3Qgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gb3Ig
c3RhdGVbInRvb19sb25nIl06CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHN0YXRlWyJjaGFy
cyJdLmFwcGVuZCh2YWx1ZSkKICAgICAgICBpZiBzdW0oW2xlbihwYXJ0KSBmb3IgcGFydCBpbiBz
dGF0ZVsiY2hhcnMiXV0pID4gTUFYX1dTU0VfVVNFUk5BTUUgKyAyOgogICAgICAgICAgICBzdGF0
ZVsiY2hhcnMiXSA9IFtdCiAgICAgICAgICAgIHN0YXRlWyJ0b29fbG9uZyJdID0gVHJ1ZQoKICAg
IGRlZiBlbmQobmFtZSk6CiAgICAgICAgZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0pCiAgICAg
ICAgaWYgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIGlmIG5v
dCBzdGF0ZVsidG9vX2xvbmciXSBhbmQgc3RhdGVbInJlc3VsdCJdIGlzIE5vbmU6CiAgICAgICAg
ICAgICAgICBzdGF0ZVsicmVzdWx0Il0gPSBub3JtYWxpemVfd3NzZV91c2VybmFtZSgKICAgICAg
ICAgICAgICAgICAgICB1IiIuam9pbihzdGF0ZVsiY2hhcnMiXSkpCiAgICAgICAgICAgIHN0YXRl
WyJ1c2VybmFtZV9kZXB0aCJdID0gMAogICAgICAgICAgICBzdGF0ZVsiY2hhcnMiXSA9IFtdCiAg
ICAgICAgaWYgc3RhdGVbInRva2VuX2RlcHRoIl0gPT0gZGVwdGg6CiAgICAgICAgICAgIHN0YXRl
WyJ0b2tlbl9kZXB0aCJdID0gMAogICAgICAgIGlmIHN0YXRlWyJzdGFjayJdOgogICAgICAgICAg
ICBzdGF0ZVsic3RhY2siXS5wb3AoKQoKICAgIHRyeToKICAgICAgICBwYXJzZXIgPSBleHBhdC5Q
YXJzZXJDcmVhdGUoTm9uZSwgIn0iKQogICAgICAgIGlmIGhhc2F0dHIocGFyc2VyLCAicmV0dXJu
c191bmljb2RlIik6CiAgICAgICAgICAgIHBhcnNlci5yZXR1cm5zX3VuaWNvZGUgPSBUcnVlCiAg
ICAgICAgcGFyc2VyLlN0YXJ0RWxlbWVudEhhbmRsZXIgPSBzdGFydAogICAgICAgIHBhcnNlci5D
aGFyYWN0ZXJEYXRhSGFuZGxlciA9IGNoYXJzCiAgICAgICAgcGFyc2VyLkVuZEVsZW1lbnRIYW5k
bGVyID0gZW5kCiAgICAgICAgaWYgKGhhc2F0dHIocGFyc2VyLCAiU2V0UGFyYW1FbnRpdHlQYXJz
aW5nIikgYW5kCiAgICAgICAgICAgICAgICBoYXNhdHRyKGV4cGF0LCAiWE1MX1BBUkFNX0VOVElU
WV9QQVJTSU5HX05FVkVSIikpOgogICAgICAgICAgICBwYXJzZXIuU2V0UGFyYW1FbnRpdHlQYXJz
aW5nKGV4cGF0LlhNTF9QQVJBTV9FTlRJVFlfUEFSU0lOR19ORVZFUikKICAgICAgICBwYXJzZXIu
UGFyc2UoYnl0ZXMoYm9keSksIEZhbHNlKQogICAgZXhjZXB0IChleHBhdC5FeHBhdEVycm9yLCBW
YWx1ZUVycm9yLCBUeXBlRXJyb3IpOgogICAgICAgICMgQSBib3VuZGVkIHByZWZpeCBpcyBjb21t
b25seSBpbmNvbXBsZXRlLiBBIHVzZXJuYW1lIGZ1bGx5IGNsb3NlZAogICAgICAgICMgYmVmb3Jl
IHRoZSB0cnVuY2F0aW9uIHBvaW50IGlzIHN0aWxsIHNhZmUgdG8gdXNlLgogICAgICAgIHBhc3MK
ICAgIHJldHVybiBzdGF0ZVsicmVzdWx0Il0KCgpkZWYgaXNfc29hcF9jb250ZW50X3R5cGUodmFs
dWUpOgogICAgaWYgbm90IHZhbHVlOgogICAgICAgIHJldHVybiBGYWxzZQogICAgbWVkaWFfdHlw
ZSA9IHZhbHVlLnNwbGl0KCI7IiwgMSlbMF0uc3RyaXAoKS5sb3dlcigpCiAgICByZXR1cm4gKG1l
ZGlhX3R5cGUgaW4gKCJ0ZXh0L3htbCIsICJhcHBsaWNhdGlvbi94bWwiLAogICAgICAgICAgICAg
ICAgICAgICAgICAgICAiYXBwbGljYXRpb24vc29hcCt4bWwiKSBvcgogICAgICAgICAgICBtZWRp
YV90eXBlLmVuZHN3aXRoKCIreG1sIikpCgoKZGVmIGZpbmlzaF9ldmVudChmbG93LCBrZXksIGRz
dF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsIHBvcnRzLCBub2RlX2hvc3QpOgogICAgaCA9IGZs
b3cuaGRycwogICAgdXNlciA9IHNjaGVtZSA9IE5vbmUKICAgIGF1dGh6ID0gaC5nZXQoImF1dGhv
cml6YXRpb24iKQogICAgaWYgYXV0aHo6CiAgICAgICAgdXNlciwgc2NoZW1lID0gYmFzaWNfdXNl
cihhdXRoeikKICAgICMgVzNDIHRyYWNlIGNvbnRleHQ6IGhvbm9yIGluY29taW5nIHRyYWNlcGFy
ZW50LCBlbHNlIGdlbmVyYXRlIG9uZSBzbwogICAgIyBldmVyeSB0cmFuc2FjdGlvbiBjYXJyaWVz
IGEgdHJhY2VfaWQgZm9yIGh1Yi1zaWRlIGNvcnJlbGF0aW9uLgogICAgIyBOT1RFIHB5Mi42OiBi
eXRlcyBoYXMgbm8gLmhleCgpIOKAlCB1c2UgYmluYXNjaWkuaGV4bGlmeS4KICAgIHRwID0gaC5n
ZXQoInRyYWNlcGFyZW50IikKICAgIHRyYWNlX2lkID0gTm9uZQogICAgaWYgdHA6CiAgICAgICAg
cGFydHMgPSB0cC5zcGxpdCgiLSIpCiAgICAgICAgaWYgbGVuKHBhcnRzKSA9PSA0IGFuZCBsZW4o
cGFydHNbMV0pID09IDMyOgogICAgICAgICAgICB0cmFjZV9pZCA9IHBhcnRzWzFdLmxvd2VyKCkK
ICAgIGlmIG5vdCB0cmFjZV9pZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJuZCA9IGJpbmFz
Y2lpLmhleGxpZnkob3MudXJhbmRvbSgxNikpCiAgICAgICAgICAgIHJuZCA9IHJuZC5kZWNvZGUo
ImFzY2lpIikgaWYgaGFzYXR0cihybmQsICJkZWNvZGUiKSBlbHNlIHJuZAogICAgICAgIGV4Y2Vw
dCBFeGNlcHRpb246CiAgICAgICAgICAgIHJuZCA9ICgiJTAzMngiICUgKGludCh0aW1lLnRpbWUo
KSAqIDEwMDApKSlbLTMyOl0KICAgICAgICBwaWQ4ID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFu
ZG9tKDgpKQogICAgICAgIHBpZDggPSBwaWQ4LmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHBp
ZDgsICJkZWNvZGUiKSBlbHNlIHBpZDgKICAgICAgICB0cCA9ICIwMC0lcy0lcy0wMSIgJSAocm5k
LCBwaWQ4KQogICAgICAgIHRyYWNlX2lkID0gcm5kCiAgICBldiA9IHsKICAgICAgICAidHMiOiBp
bnQodGltZS50aW1lKCkpLAogICAgICAgICJob3N0Ijogbm9kZV9ob3N0LAogICAgICAgICJzcmMi
OiAicGNhcCIsCiAgICAgICAgInNlcnZpY2UiOiAicG9ydDolZCIgJSBkcG9ydCwKICAgICAgICAi
bWV0aG9kIjogaC5nZXQoIl9tZXRob2QiKSBvciAiLSIsCiAgICAgICAgInBhdGgiOiAoaC5nZXQo
Il9wYXRoIikgb3IgIi0iKS5zcGxpdCgiPyIsIDEpWzBdWzoxMjBdLAogICAgICAgICJ1c2VyIjog
dXNlciwKICAgICAgICAic2NoZW1lIjogc2NoZW1lLAogICAgICAgICJiYXNpY191c2VyIjogdXNl
ciBpZiBzY2hlbWUgPT0gImJhc2ljIiBhbmQgdXNlciBlbHNlIE5vbmUsCiAgICAgICAgIndzc2Vf
dXNlciI6IE5vbmUsCiAgICAgICAgInBpZCI6IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6
ICJwY2FwLWh0dHAiLAogICAgICAgICJob3N0X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAg
InVzZXJfYWdlbnQiOiBoLmdldCgidXNlci1hZ2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9m
b3IiOiBoLmdldCgieC1mb3J3YXJkZWQtZm9yIiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwK
ICAgICAgICAiY2FsbGVyX3BvcnQiOiBzcG9ydCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAog
ICAgICAgICJkc3RfcG9ydCI6IGRwb3J0LAogICAgICAgICMgLS0tLSBtb25pdG9yaW5nIHNjaGVt
YSAob3BzIEFQSS1sb2cgZm9ybWF0KSAtLS0tCiAgICAgICAgIyBzdGF0dXMvZHVyYXRpb25fbXMv
cmVzcF9ieXRlcyBhcmUgcmVzcG9uc2Utc2lkZTogcGFzc2l2ZSByZXF1ZXN0LW9ubHkKICAgICAg
ICAjIGNhcHR1cmUgY2Fubm90IHNlZSB0aGVtOyBsZWZ0IG51bGwgZm9yIHRoZSBodWIgdG8gZW5y
aWNoIG9yIGxlYXZlLgogICAgICAgICJ0cmFjZXBhcmVudCI6IHRwWzo4MF0sCiAgICAgICAgInRy
YWNlX2lkIjogdHJhY2VfaWQsCiAgICAgICAgInNlcnZpY2VfaWQiOiBOb25lLCAgICAgICAgICAj
IGh1YiBtYXBzIHBvcnQtPnNlcnZpY2UgdmlhIHBvbGljeSBsYXRlcgogICAgICAgICJtb2R1bGVf
aWQiOiAicGNhcC1odHRwIiwKICAgIH0KICAgICMgUHJlc2VydmUgcmVzcG9uc2UgY29ycmVsYXRp
b24gb25seSBmb3IgbW9uaXRvcmVkIGRlc3RpbmF0aW9ucy4gVGhlCiAgICAjIHJlc3BvbnNlLXNp
ZGUgZmlsdGVyIG1heSBzdGlsbCBhZG1pdCBhIGNsaWVudCBlcGhlbWVyYWwgc3BvcnQgZXF1YWwg
dG8gYQogICAgIyBtb25pdG9yZWQgcG9ydDsgdGhpcyBpcyBoYXJtbGVzcyBiZWNhdXNlIHBhcnNl
X3Jlc3BvbnNlX2hlYWQgcmVqZWN0cyBpdC4KICAgIHJldHVybiBldiBpZiAoZHBvcnQgaW4gcG9y
dHMgb3IgaC5nZXQoIl9tZXRob2QiKSkgZWxzZSBOb25lCgoKZGVmIF9lbWl0X3JlcXVlc3QoZmxv
d3MsIGtleSwgZmwsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdyk6CiAgICAiIiJEaXNjYXJk
IGNhcHR1cmUgYnVmZmVycywgdGhlbiBlbWl0L3F1ZXVlIHRoZSBzYW5pdGl6ZWQgZXZlbnQgb25s
eS4iIiIKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBldiA9IGZs
LmV2ZW50CiAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgaWYgbm90IGV2OgogICAgICAgIHJl
dHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gZmwuaGVhZF9ieXRlcwogICAgaWYgcGVuZGluZ190
YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgIHJldHVybgogICAgcmsg
PSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgIGVudCA9IHBlbmRpbmdfdGJsLmdl
dChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgIGlmIGxlbihwZW5kaW5nX3RibCkgPj0g
UEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3Ri
bCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3JrXSA9IFtdCiAgICBlbGlmIGxlbihl
bnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAgICAgICAgcGVuZGluZ19wb3AocmssIG91dCwgcGVu
ZGluZ190YmwpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQogICAgICAgIGlmIGVu
dCBpcyBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10gPSBbXQogICAgZW50
LmFwcGVuZChbZXYsIG5vdyBpZiBub3cgaXMgbm90IE5vbmUgZWxzZSB0aW1lLnRpbWUoKV0pCgoK
ZGVmIF90cnlfd3NzZV9ib2R5KGZsb3dzLCBrZXksIGZsLCBwYXlsb2FkLCBtZXRhLCBvdXQsIHBl
bmRpbmdfdGJsLCBub3cpOgogICAgIiIiQXBwZW5kIG5vIG1vcmUgdGhhbiBib2R5X2dvYWwgYnl0
ZXMgYW5kIGZpbmlzaCBhcyBzb29uIGFzIHBvc3NpYmxlLiIiIgogICAgcmVtYWluaW5nID0gZmwu
Ym9keV9nb2FsIC0gbGVuKGZsLmJ1ZikKICAgIGlmIHJlbWFpbmluZyA+IDAgYW5kIHBheWxvYWQ6
CiAgICAgICAgZmwuYnVmLmV4dGVuZChieXRlYXJyYXkocGF5bG9hZFs6cmVtYWluaW5nXSkpCiAg
ICB1c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC5idWYpCiAgICBpZiB1c2VybmFt
ZToKICAgICAgICBmbC5ldmVudFsid3NzZV91c2VyIl0gPSB1c2VybmFtZQogICAgICAgIGZsLmV2
ZW50WyJ1c2VyIl0gPSB1c2VybmFtZQogICAgICAgIGZsLmV2ZW50WyJzY2hlbWUiXSA9ICJ3c3Nl
IgogICAgaWYgdXNlcm5hbWUgb3IgbGVuKGZsLmJ1ZikgPj0gZmwuYm9keV9nb2FsOgogICAgICAg
IF9lbWl0X3JlcXVlc3QoZmxvd3MsIGtleSwgZmwsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5v
dykKICAgICAgICByZXR1cm4gVHJ1ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhhbmRsZV9wYXls
b2FkKGZsb3dzLCBrZXksIHJldl9rZXksIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3Qs
IG91dCwKICAgICAgICAgICAgICAgICAgIHBlbmRpbmdfdGJsPU5vbmUsIG5vdz1Ob25lLCB3c3Nl
X2JvZHlfYnl0ZXM9MCk6CiAgICAiIiJGZWVkIG9uZSBkaXJlY3Rpb24ncyBwYXlsb2FkOyBlbWl0
IGZpbmlzaGVkIGV2ZW50cyB0byBvdXQobGlzdCkuCgogICAgQm9kaWVzIGFyZSBpZ25vcmVkIHVu
bGVzcyB3c3NlX2JvZHlfYnl0ZXMgaXMgbm9uLXplcm8uIEluIG9wdC1pbiBtb2RlLAogICAgb25s
eSBYTUwgcmVxdWVzdHMgd2l0aCBDb250ZW50LUxlbmd0aCBhcmUgaW5zcGVjdGVkLCBlYWNoIGJ1
ZmZlciBpcwogICAgYm91bmRlZCBieSB3c3NlX2JvZHlfYnl0ZXMsIGFuZCBvbmx5IGEgcmVjb2du
aXplZCBXU1NFIHVzZXJuYW1lIHJlYWNoZXMKICAgIHRoZSBldmVudC4gVGhlIGJvZHkgYW5kIGFs
bCBvdGhlciBVc2VybmFtZVRva2VuIG1hdGVyaWFsIGFyZSBkaXNjYXJkZWQuCiAgICAiIiIKICAg
IGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBpZiBub3QgdmFsaWRfcG9y
dChkcG9ydCkgb3Igbm90IHZhbGlkX3BvcnQoc3BvcnQpOgogICAgICAgIHJldHVybgogICAgZmwg
PSBmbG93cy5nZXQoa2V5KQogICAgaWYgZmwgaXMgTm9uZToKICAgICAgICBmbCA9IEZsb3coKQog
ICAgICAgIGZsb3dzW2tleV0gPSBmbAogICAgICAgIGlmIGxlbihmbG93cykgPiBNQVhfRkxPV1M6
CiAgICAgICAgICAgIGVuZm9yY2VfbGltaXQoZmxvd3MsIHRpbWUudGltZSgpKQogICAgZmwudG91
Y2hlZCA9IHRpbWUudGltZSgpCgogICAgaWYgKGZsLmV2ZW50IGlzIG5vdCBOb25lIGFuZCBmbC5l
dmVudC5nZXQoImJhc2ljX3VzZXIiKSBhbmQKICAgICAgICAgICAgYW55KHBheWxvYWQuc3RhcnRz
d2l0aChtZXRob2QuZW5jb2RlKCJhc2NpaSIpICsgYiIgIikKICAgICAgICAgICAgICAgIGZvciBt
ZXRob2QgaW4gTUVUSE9EUykpOgogICAgICAgICMgQSBuZXcga2VlcC1hbGl2ZSByZXF1ZXN0IHN0
YXJ0ZWQgYmVmb3JlIHRoZSBib3VuZGVkIFdTU0Ugd2luZG93CiAgICAgICAgIyBjb21wbGV0ZWQu
IFByZXNlcnZlIHRoZSBCYXNpYyBldmVudCwgdGhlbiBwYXJzZSB0aGUgbmV3IHJlcXVlc3QuCiAg
ICAgICAgX2VtaXRfcmVxdWVzdChmbG93cywga2V5LCBmbCwgbWV0YSwgb3V0LCBwZW5kaW5nX3Ri
bCwgbm93KQogICAgICAgIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIHJldl9rZXksIHBheWxv
YWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsCiAgICAgICAgICAgICAgICAgICAgICAgb3V0LCBw
ZW5kaW5nX3RibCwgbm93LCB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgcmV0dXJuCiAgICBpZiBm
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
YXJyYXkoKQoKICAgIGlmIChub3Qgd3NzZV9ib2R5X2J5dGVzIG9yCiAgICAgICAgICAgIG5vdCBp
c19zb2FwX2NvbnRlbnRfdHlwZShoZHJzLmdldCgiY29udGVudC10eXBlIikpKToKICAgICAgICBf
ZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cp
CiAgICAgICAgcmV0dXJuCiAgICB0cnk6CiAgICAgICAgY29udGVudF9sZW5ndGggPSBpbnQoaGRy
cy5nZXQoImNvbnRlbnQtbGVuZ3RoIiwgIiIpKQogICAgZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVl
RXJyb3IpOgogICAgICAgIGNvbnRlbnRfbGVuZ3RoID0gMAogICAgYWN0aXZlX2JvZHlfZmxvd3Mg
PSBzdW0oWzEgZm9yIGNhbmRpZGF0ZSBpbiBmbG93cy52YWx1ZXMoKQogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIGlmIGNhbmRpZGF0ZS5ldmVudCBpcyBub3QgTm9uZSBhbmQKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBjYW5kaWRhdGUuYm9keV9nb2FsID4gMF0pCiAgICBpZiAoY29u
dGVudF9sZW5ndGggPD0gMCBvciBhY3RpdmVfYm9keV9mbG93cyA+PSBNQVhfV1NTRV9CT0RZX0ZM
T1dTIG9yCiAgICAgICAgICAgICJjaHVua2VkIiBpbiBoZHJzLmdldCgidHJhbnNmZXItZW5jb2Rp
bmciLCAiIikubG93ZXIoKSk6CiAgICAgICAgX2VtaXRfcmVxdWVzdChmbG93cywga2V5LCBmbCwg
bWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIHJldHVybgogICAgZmwuYm9keV9n
b2FsID0gbWluKGNvbnRlbnRfbGVuZ3RoLCB3c3NlX2JvZHlfYnl0ZXMsIE1BWF9XU1NFX0JPRFlf
QllURVMpCiAgICBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwgaW5pdGlhbF9ib2R5LCBt
ZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCgoKZGVmIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdywg
b3V0PU5vbmUsIHBlbmRpbmdfdGJsPU5vbmUpOgogICAgc3RhbGUgPSBbXQogICAgZm9yIGssIGZs
IGluIGZsb3dzLml0ZW1zKCk6CiAgICAgICAgaWYgbm93IC0gZmwudG91Y2hlZCA+IEZMT1dfVFRM
OgogICAgICAgICAgICBzdGFsZS5hcHBlbmQoaykKICAgIGZvciBrIGluIHN0YWxlOgogICAgICAg
IGZsID0gZmxvd3MuZ2V0KGspCiAgICAgICAgaWYgKG91dCBpcyBub3QgTm9uZSBhbmQgZmwgaXMg
bm90IE5vbmUgYW5kIGZsLmV2ZW50IGlzIG5vdCBOb25lIGFuZAogICAgICAgICAgICAgICAgZmwu
ZXZlbnQuZ2V0KCJiYXNpY191c2VyIikpOgogICAgICAgICAgICBzcmNfaXAsIHNwb3J0LCBkc3Rf
aXAsIGRwb3J0ID0gawogICAgICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrLCBmbCwgKGRz
dF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAgIG91
dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICBlbHNlOgogICAgICAgICAgICBmbG93cy5wb3Ao
aywgTm9uZSkKCgpkZWYgZHJhaW5faW5jb21wbGV0ZV93c3NlKGZsb3dzLCBvdXQsIHBlbmRpbmdf
dGJsLCBub3c9Tm9uZSk6CiAgICAiIiJGYWxsIGJhY2sgdG8gdGhlIHJldGFpbmVkIHByZS1XU1NF
IGlkZW50aXR5IGR1cmluZyBjbGVhbiBzaHV0ZG93bi4iIiIKICAgIGZvciBrZXkgaW4gbGlzdChm
bG93cy5rZXlzKCkpOgogICAgICAgIGZsID0gZmxvd3MuZ2V0KGtleSkKICAgICAgICBpZiAoZmwg
aXMgTm9uZSBvciBmbC5ldmVudCBpcyBOb25lIG9yCiAgICAgICAgICAgICAgICBub3QgZmwuZXZl
bnQuZ2V0KCJiYXNpY191c2VyIikpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHNyY19p
cCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQgPSBrZXkKICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dz
LCBrZXksIGZsLCAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAg
ICAgICAgICBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCgoKZGVmIF9mbHVzaF9vbGRlc3RfcGVuZGlu
ZyhwZW5kaW5nX3RibCwgb3V0KToKICAgICIiIk92ZXJmbG93IGd1YXJkOiBlbWl0IHRoZSBzaW5n
bGUgb2xkZXN0IHBlbmRpbmcgZXZlbnQgYXMtaXMuIiIiCiAgICBvbGRlc3Rfa2V5LCBvbGRlc3Rf
dHMgPSBOb25lLCBOb25lCiAgICBmb3IgcmssIGxzdCBpbiBwZW5kaW5nX3RibC5pdGVtcygpOgog
ICAgICAgIHRzID0gbHN0WzBdWzFdCiAgICAgICAgaWYgb2xkZXN0X3RzIGlzIE5vbmUgb3IgdHMg
PCBvbGRlc3RfdHM6CiAgICAgICAgICAgIG9sZGVzdF9rZXksIG9sZGVzdF90cyA9IHJrLCB0cwog
ICAgaWYgb2xkZXN0X2tleSBpcyBub3QgTm9uZToKICAgICAgICBwZW5kaW5nX3BvcChvbGRlc3Rf
a2V5LCBvdXQsIHBlbmRpbmdfdGJsKQoKCmRlZiBzd2VlcF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBu
b3csIG91dCk6CiAgICAiIiJUVEwgZmx1c2g6IGVtaXQgcmVxdWVzdHMgd2hvc2UgcmVzcG9uc2Vz
IG5ldmVyIHNob3dlZCB1cC4iIiIKICAgIGZvciByayBpbiBsaXN0KHBlbmRpbmdfdGJsLmtleXMo
KSk6CiAgICAgICAgbHN0ID0gcGVuZGluZ190YmwuZ2V0KHJrKQogICAgICAgIHdoaWxlIGxzdCBh
bmQgbm93IC0gbHN0WzBdWzFdID4gUEVORElOR19UVEw6CiAgICAgICAgICAgIHBlbmRpbmdfcG9w
KHJrLCBvdXQsIHBlbmRpbmdfdGJsKQogICAgICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQo
cmspCgoKZGVmIGRyYWluX3BlbmRpbmcocGVuZGluZ190YmwsIG91dCk6CiAgICAiIiJFbWl0IGV2
ZXJ5IGNhcHR1cmVkIHJlcXVlc3QgYmVmb3JlIGNhcHR1cmUgc2h1dGRvd24uCgogICAgUmVzcG9u
c2VzIGFyZSBvcHRpb25hbCBlbnJpY2htZW50LiBBIHN0b3AvcmVzdGFydCBtdXN0IG5vdCBkaXNj
YXJkIGEKICAgIHJlcXVlc3QgbWVyZWx5IGJlY2F1c2UgaXRzIHJlc3BvbnNlIHdhcyBmaWx0ZXJl
ZCwgc3BsaXQsIG9yIHN0aWxsIGluCiAgICBmbGlnaHQgd2hlbiB0aGUgcHJvY2VzcyByZWNlaXZl
ZCBTSUdURVJNLgogICAgIiIiCiAgICBmb3IgcmsgaW4gbGlzdChwZW5kaW5nX3RibC5rZXlzKCkp
OgogICAgICAgIHdoaWxlIHBlbmRpbmdfdGJsLmdldChyayk6CiAgICAgICAgICAgIHBlbmRpbmdf
cG9wKHJrLCBvdXQsIHBlbmRpbmdfdGJsKQoKCmRlZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0
X3N3ZWVwKToKICAgIHJldHVybiBub3cgLSBsYXN0X3N3ZWVwID49IFNXRUVQX0lOVEVSVkFMCgoK
ZGVmIGVuZm9yY2VfbGltaXQoZmxvd3MsIG5vdyk6CiAgICAiIiJDYXAgZmxvdy10YWJsZSBzaXpl
IChweTIuNjogbm8gT3JkZXJlZERpY3Qg4oCUIHN3ZWVwIHN0YWxlLCB0aGVuIEZJRk8KICAgIGJ5
IGluc2VydGlvbiBvcmRlciwgd2hpY2ggcGxhaW4gZGljdHMgcHJlc2VydmUgaW4gQ1B5dGhvbiku
IiIiCiAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICB3aGlsZSBsZW4oZmxvd3MpID4gTUFY
X0ZMT1dTOgogICAgICAgIGZsb3dzLnBvcGl0ZW0oKSAgICAgICAgICAjIG9sZGVzdC1pbnNlcnRl
ZCBrZXkgb24gQ1B5dGhvbiAyLjYvMi43CgoKZGVmIF9jb250cm9sX2NvbmZpZygpOgogICAgIiIi
UmVhZCBvcHRpb25hbCBjb250cm9sIHNldHRpbmdzIHdpdGhvdXQgZXhwb3NpbmcgdGhlIGJlYXJl
ciB0b2tlbi4iIiIKICAgIGVuZHBvaW50ID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfRU5E
UE9JTlQiKSBvciBvcy5lbnZpcm9uLmdldCgiTlRfRU5EUE9JTlQiKQogICAgdG9rZW5fZmlsZSA9
IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOX0ZJTEUiLCAiIikKICAgIHRva2VuID0g
b3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9LRU4iLCAiIikKICAgIGlmIHRva2VuX2ZpbGU6
CiAgICAgICAgdHJ5OgogICAgICAgICAgICBmID0gb3Blbih0b2tlbl9maWxlLCAiciIpCiAgICAg
ICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRva2VuID0gZi5yZWFkKCkuc3RyaXAoKQogICAg
ICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgZi5jbG9zZSgpCiAgICAgICAgZXhjZXB0
IElPRXJyb3I6CiAgICAgICAgICAgIHRva2VuID0gIiIKICAgIG5vZGUgPSBvcy5lbnZpcm9uLmdl
dCgiTlRfTk9ERV9OQU1FIikgb3Igc29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQog
ICAgcnVuX2RpciA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1JVTiIsICIvdmFyL2xpYi9u
ZXR3b3JrdHJhY2luZyIpCiAgICB0cnk6CiAgICAgICAgaW50ZXJ2YWwgPSBtYXgoNSwgbWluKGlu
dChvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9TRUMiLCAiMzAiKSksIDMwMCkpCiAgICBleGNl
cHQgVmFsdWVFcnJvcjoKICAgICAgICBpbnRlcnZhbCA9IDMwCiAgICByZXR1cm4gZW5kcG9pbnQs
IHRva2VuLCBub2RlLCBydW5fZGlyLCBpbnRlcnZhbAoKCmRlZiBfcnVuX2NvbnRyb2xfdGljayhw
b3J0cywgaWZhY2UsIHJ1bl9kaXIsIGNsaWVudCk6CiAgICByZXBseSA9IGNsaWVudC5wb2xsKCkK
ICAgIGlmIG5vdCByZXBseToKICAgICAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBOb25lLCAicG9s
bCBmYWlsZWQiCiAgICBkZXNpcmVkID0gcmVwbHkuZ2V0KCJkZXNpcmVkIikgb3Ige30KICAgIHN0
YXRlID0gZGljdChkZXNpcmVkKQogICAgZ2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0
aW9uIiwgMCkKICAgIGNvbnRyb2xfYWN0aW9uID0gTm9uZQogICAgc3RvcF9yZXF1ZXN0ZWQgPSBG
YWxzZQogICAgaWYgZGVzaXJlZC5nZXQoInBvcnRzIik6CiAgICAgICAgbmV3X3BvcnRzID0gc2V0
KGRlc2lyZWRbInBvcnRzIl0pCiAgICAgICAgaWYgbmV3X3BvcnRzICE9IHBvcnRzOgogICAgICAg
ICAgICBwb3J0cyA9IG5ld19wb3J0cwogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0
YXJ0IgogICAgaWYgZGVzaXJlZC5nZXQoImlmYWNlIik6CiAgICAgICAgbmV3X2lmYWNlID0gZGVz
aXJlZFsiaWZhY2UiXQogICAgICAgIGlmIG5ld19pZmFjZSAhPSBpZmFjZToKICAgICAgICAgICAg
aWZhY2UgPSBuZXdfaWZhY2UKICAgICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAicmVzdGFydCIK
ICAgIGZvciB0YXNrIGluIHJlcGx5LmdldCgidGFza3MiLCBbXSk6CiAgICAgICAgYWN0aW9uID0g
dGFzay5nZXQoImFjdGlvbiIpCiAgICAgICAgaWYgYWN0aW9uID09ICJoZWFsdGgiOgogICAgICAg
ICAgICBtZXNzYWdlID0gImhlYWx0aHkiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAg
ICAgIGVsaWYgYWN0aW9uIGluICgicmVzdGFydCIsICJyZWxvYWQiLCAic2V0X3BvcnRzIik6CiAg
ICAgICAgICAgIG1lc3NhZ2UgPSAiYWNjZXB0ZWQ7IGNhcHR1cmUgcmVzdGFydCByZXF1ZXN0ZWQi
CiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9
ICJyZXN0YXJ0IgogICAgICAgICAgICBpZiBhY3Rpb24gPT0gInNldF9wb3J0cyI6CiAgICAgICAg
ICAgICAgICBhcmdzID0gdGFzay5nZXQoImFyZ3MiKSBvciB7fQogICAgICAgICAgICAgICAgaWYg
YXJncy5nZXQoInBvcnRzIik6CiAgICAgICAgICAgICAgICAgICAgcG9ydHMgPSBzZXQoYXJnc1si
cG9ydHMiXSkKICAgICAgICAgICAgICAgICAgICBzdGF0ZS51cGRhdGUoeyJwb3J0cyI6IHNvcnRl
ZChwb3J0cyksICJtb2RlIjogInB5dGhvbiIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAiZ2VuZXJhdGlvbiI6IGdlbmVyYXRpb259KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJz
dG9wIjoKICAgICAgICAgICAgbWVzc2FnZSA9ICJzdG9wIHJlcXVlc3RlZCIKICAgICAgICAgICAg
c3RhdHVzID0gImRvbmUiCiAgICAgICAgICAgIHN0b3BfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAg
IGVsc2U6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAidW5zdXBwb3J0ZWQgYnkgZGlyZWN0IHNuaWZm
ZXIiCiAgICAgICAgICAgIHN0YXR1cyA9ICJmYWlsZWQiCiAgICAgICAgY2xpZW50LnJlcG9ydCh0
YXNrLmdldCgiaWQiKSwgc3RhdHVzLCBtZXNzYWdlKQogICAgaWYgc3RvcF9yZXF1ZXN0ZWQ6CiAg
ICAgICAgY29udHJvbF9hY3Rpb24gPSAic3RvcCIKICAgIGFwcGxpZWQgPSAoInN0b3AgcmVxdWVz
dGVkIiBpZiBjb250cm9sX2FjdGlvbiA9PSAic3RvcCIgZWxzZQogICAgICAgICAgICAgICAicmVz
dGFydCByZXF1aXJlZCIgaWYgY29udHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiIGVsc2UKICAgICAg
ICAgICAgICAgInBvbGwgb2siKQogICAgbnRfY29udHJvbC53cml0ZV9zdGF0ZShvcy5wYXRoLmpv
aW4ocnVuX2RpciwgInJlbW90ZS1kZXNpcmVkLmpzb24iKSwKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgc3RhdGUsIGFwcGxpZWQpCiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sIGFw
cGxpZWQpCiAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBjb250cm9sX2FjdGlvbiwgYXBwbGllZAoK
CmRlZiBfcmVzdGFydF9hcmdzKHNjcmlwdCwgaWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJz
LCB3c3NlX2JvZHlfYnl0ZXM9MCk6CiAgICAiIiJCdWlsZCBhIGZyZXNoIGFyZ3YgZm9yIGFuIGlu
LXBsYWNlIHJlLWV4ZWMgYWZ0ZXIgYSBjb250cm9sIHVwZGF0ZS4iIiIKICAgICMgUHJlc2VydmUg
dW5idWZmZXJlZCBKU09OTCBkZWxpdmVyeTsgdGhlIGluc3RhbGxlciBzdGFydHMgUHl0aG9uIHdp
dGggLXUuCiAgICBhcmdzID0gW3N5cy5leGVjdXRhYmxlLCAiLXUiLCBvcy5wYXRoLmFic3BhdGgo
c2NyaXB0KV0KICAgIGlmIGlmYWNlOgogICAgICAgIGFyZ3MuZXh0ZW5kKFsiLWkiLCBpZmFjZV0p
CiAgICBhcmdzLmV4dGVuZChbIi1wIiwgIiwiLmpvaW4oW3N0cihwKSBmb3IgcCBpbiBzb3J0ZWQo
cG9ydHMpXSldKQogICAgYXJncy5leHRlbmQoWyItaiIsICIxIl0pCiAgICBpZiB3c3NlX2JvZHlf
Ynl0ZXM6CiAgICAgICAgYXJncy5leHRlbmQoWyItLXdzc2UtYm9keS1ieXRlcyIsIHN0cih3c3Nl
X2JvZHlfYnl0ZXMpXSkKICAgIGlmIHZlcmJvc2U6CiAgICAgICAgYXJncy5hcHBlbmQoIi12IikK
ICAgIHJldHVybiBhcmdzCgoKZGVmIG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwg
d29ya2Vycywgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAgICBu
b2RlX2hvc3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250cm9s
X2NsaWVudCA9IE5vbmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250cm9s
X3J1biwgY29udHJvbF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9jb250
cm9sIGlzIG5vdCBOb25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5OgogICAg
ICAgICAgICBjb250cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRwb2lu
dCwgdG9rZW4sIGNvbnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIo
Y29udHJvbF9ydW4pOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4pCiAg
ICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0IEV4
Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRpc2Fi
bGVkICglcykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAgICAg
ICMgcHJvdG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJTkdS
RVNTIChyZXEpIGFuZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4IGtl
cm5lbCBwYWNrZXQgc29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZf
UEFDS0VULCBzb2NrZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29ja2V0
Lmh0b25zKEVUSF9QX0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAgcmFp
c2UgU3lzdGVtRXhpdCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0iKQog
ICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNh
bm5vdCBvcGVuIEFGX1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAgICAg
ICAgICAgICAgICAiQ0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQoMS4w
KQogICAgaWYgbm90IGFwcGx5X3BlcmZfb3B0cyhzLCBwb3J0cyk6CiAgICAgICAgcy5jbG9zZSgp
CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgia2VybmVsIEJQRiBzYWZldHkgZmlsdGVyIHVuYXZh
aWxhYmxlOyByZWZ1c2luZyB1bmZpbHRlcmVkIGNhcHR1cmUiKQogICAgdHJ5OgogICAgICAgIHMu
YmluZCgoaWZhY2Ugb3IgIiIsIEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yIGFz
IGU6CiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IGJp
bmQgQUZfUEFDS0VUIHRvICVzICglcykiICUKICAgICAgICAgICAgICAgICAgICAgICAgIChpZmFj
ZSBvciAiPGFsbD4iLCBlKSkKICAgIGlmIG5vdCBkcm9wX2NhcHR1cmVfY2FwYWJpbGl0aWVzKCk6
CiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IGRyb3Ag
Q0FQX05FVF9SQVcgYWZ0ZXIgc29ja2V0IHNldHVwOyByZWZ1c2luZyB1bnNhZmUgY2FwdHVyZSIp
CgogICAgIyBwcmVjb21waWxlZCBzdHJ1Y3QgcmVhZGVycyDigJQgdW5wYWNrX2Zyb20gcmVhZHMg
c3RyYWlnaHQgb3V0IG9mIHRoZQogICAgIyBwYWNrZXQgYnVmZmVyIChubyBzbGljZSBjb3BpZXMp
IGFuZCB5aWVsZHMgaW50cyB1bmRlciBweTIgQU5EIHB5MwogICAgdTE2ID0gc3RydWN0LlN0cnVj
dCgiIUgiKS51bnBhY2tfZnJvbQogICAgdWggPSBzdHJ1Y3QuU3RydWN0KCIhSEgiKS51bnBhY2tf
ZnJvbSAgICMgc3BvcnQsZHBvcnQgaW4gb25lIHJlYWQKICAgIHViID0gc3RydWN0LlN0cnVjdCgi
IUJCIikudW5wYWNrX2Zyb20KICAgIG50b2EgPSBzb2NrZXQuaW5ldF9udG9hCgogICAgZmxvd3Mg
PSB7fQogICAgcnVubmluZyA9IFtUcnVlXQogICAgc3RhdHNfaW50ZXJ2YWwgPSBzdGF0c19pbnRl
cnZhbF9zZWNvbmRzKCkKICAgIHN0YXRzX3N0YXRlID0geyJwYWNrZXRzX3RvdGFsIjogMCwgInBh
Y2tldF9ieXRlc190b3RhbCI6IDAsCiAgICAgICAgICAgICAgICAgICAiZXZlbnRzX2VtaXR0ZWRf
dG90YWwiOiAwLCAia2VybmVsX2Ryb3BzX3RvdGFsIjogMCwKICAgICAgICAgICAgICAgICAgICJs
YXN0X3BhY2tldHMiOiAwLCAibGFzdF9wYWNrZXRfYnl0ZXMiOiAwLAogICAgICAgICAgICAgICAg
ICAgImxhc3RfZXZlbnRzIjogMCwgImxhc3RfYXQiOiB0aW1lLnRpbWUoKX0KCiAgICBkZWYgd3Jp
dGVfZXZlbnRzKGl0ZW1zKToKICAgICAgICBpZiBub3QgaXRlbXM6CiAgICAgICAgICAgIHJldHVy
bgogICAgICAgIHcgPSBzeXMuc3Rkb3V0LndyaXRlCiAgICAgICAgZm9yIGl0ZW0gaW4gaXRlbXM6
CiAgICAgICAgICAgIHcoanNvbi5kdW1wcyhpdGVtKSArICJcbiIpCiAgICAgICAgc3lzLnN0ZG91
dC5mbHVzaCgpCiAgICAgICAgc3RhdHNfc3RhdGVbImV2ZW50c19lbWl0dGVkX3RvdGFsIl0gKz0g
bGVuKGl0ZW1zKQoKICAgIGRlZiBlbWl0X2NhcHR1cmVfc3RhdHMoZm9yY2U9RmFsc2UpOgogICAg
ICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAgZWxhcHNlZCA9IG5vdyAtIHN0YXRzX3N0YXRl
WyJsYXN0X2F0Il0KICAgICAgICBpZiBub3QgZm9yY2UgYW5kIGVsYXBzZWQgPCBzdGF0c19pbnRl
cnZhbDoKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgZHJvcHBlZF9kZWx0YSA9IDAKICAgICAg
ICB0cnk6CiAgICAgICAgICAgIHJhd19zdGF0cyA9IHMuZ2V0c29ja29wdChTT0xfUEFDS0VULCBQ
QUNLRVRfU1RBVElTVElDUywgOCkKICAgICAgICAgICAgXywgZHJvcHBlZF9kZWx0YSA9IHN0cnVj
dC51bnBhY2soIklJIiwgcmF3X3N0YXRzWzo4XSkKICAgICAgICBleGNlcHQgKHNvY2tldC5lcnJv
ciwgc3RydWN0LmVycm9yKToKICAgICAgICAgICAgZHJvcHBlZF9kZWx0YSA9IDAKICAgICAgICBz
dGF0c19zdGF0ZVsia2VybmVsX2Ryb3BzX3RvdGFsIl0gKz0gZHJvcHBlZF9kZWx0YQogICAgICAg
IHBhY2tldHNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXSAtCiAgICAgICAg
ICAgICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9wYWNrZXRzIl0pCiAgICAgICAgYnl0
ZXNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbInBhY2tldF9ieXRlc190b3RhbCJdIC0KICAgICAgICAg
ICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9wYWNrZXRfYnl0ZXMiXSkKICAgICAgICBl
dmVudHNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbImV2ZW50c19lbWl0dGVkX3RvdGFsIl0gLQogICAg
ICAgICAgICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9ldmVudHMiXSkKICAgICAgICB3
YWl0aW5nX3dzc2UgPSAwCiAgICAgICAgZm9yIGZsb3cgaW4gZmxvd3MudmFsdWVzKCk6CiAgICAg
ICAgICAgIGlmIGZsb3cuZXZlbnQgaXMgbm90IE5vbmUgYW5kIGZsb3cuYm9keV9nb2FsOgogICAg
ICAgICAgICAgICAgd2FpdGluZ193c3NlICs9IDEKICAgICAgICBwZW5kaW5nX2NvdW50ID0gc3Vt
KGxlbihpdGVtcykgZm9yIGl0ZW1zIGluIHBlbmRpbmcudmFsdWVzKCkpCiAgICAgICAgZHJvcF9w
Y3QgPSAxMDAuMCAqIGRyb3BwZWRfZGVsdGEgLyBtYXgoMSwgcGFja2V0c19kZWx0YSkKICAgICAg
ICBjYXB0dXJlID0gewogICAgICAgICAgICAicGFja2V0c190b3RhbCI6IHN0YXRzX3N0YXRlWyJw
YWNrZXRzX3RvdGFsIl0sCiAgICAgICAgICAgICJwYWNrZXRzX2RlbHRhIjogcGFja2V0c19kZWx0
YSwKICAgICAgICAgICAgInBhY2tldF9ieXRlc190b3RhbCI6IHN0YXRzX3N0YXRlWyJwYWNrZXRf
Ynl0ZXNfdG90YWwiXSwKICAgICAgICAgICAgInBhY2tldF9ieXRlc19kZWx0YSI6IGJ5dGVzX2Rl
bHRhLAogICAgICAgICAgICAia2VybmVsX2Ryb3BzX3RvdGFsIjogc3RhdHNfc3RhdGVbImtlcm5l
bF9kcm9wc190b3RhbCJdLAogICAgICAgICAgICAia2VybmVsX2Ryb3BzX2RlbHRhIjogZHJvcHBl
ZF9kZWx0YSwKICAgICAgICAgICAgImtlcm5lbF9kcm9wX3BlcmNlbnQiOiByb3VuZChkcm9wX3Bj
dCwgNCksCiAgICAgICAgICAgICJpbnZhbGlkX2ZyYW1lc190b3RhbCI6IDAsCiAgICAgICAgICAg
ICJldmVudHNfZW1pdHRlZF90b3RhbCI6IHN0YXRzX3N0YXRlWyJldmVudHNfZW1pdHRlZF90b3Rh
bCJdLAogICAgICAgICAgICAiZXZlbnRzX2VtaXR0ZWRfZGVsdGEiOiBldmVudHNfZGVsdGEsCiAg
ICAgICAgICAgICJmbG93c19hY3RpdmUiOiBsZW4oZmxvd3MpLAogICAgICAgICAgICAicGVuZGlu
Z19yZXF1ZXN0cyI6IHBlbmRpbmdfY291bnQsCiAgICAgICAgICAgICJ3c3NlX2JvZHlfZmxvd3Nf
YWN0aXZlIjogd2FpdGluZ193c3NlfQogICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1w
cyh7Il9udF9pbnRlcm5hbCI6ICJjYXB0dXJlX3N0YXRzX3YxIiwKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICJjYXB0dXJlIjogY2FwdHVyZX0sCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgIHNlcGFyYXRvcnM9KCIsIiwgIjoiKSkgKyAiXG4iKQogICAgICAg
IHN5cy5zdGRvdXQuZmx1c2goKQogICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X3BhY2tldHMiXSA9
IHN0YXRzX3N0YXRlWyJwYWNrZXRzX3RvdGFsIl0KICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9w
YWNrZXRfYnl0ZXMiXSA9IHN0YXRzX3N0YXRlWyJwYWNrZXRfYnl0ZXNfdG90YWwiXQogICAgICAg
IHN0YXRzX3N0YXRlWyJsYXN0X2V2ZW50cyJdID0gc3RhdHNfc3RhdGVbImV2ZW50c19lbWl0dGVk
X3RvdGFsIl0KICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9hdCJdID0gbm93CgogICAgZGVmIHN0
b3Aoc2lnbnVtLCBmcmFtZSk6CiAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwu
c2lnbmFsKHNpZ25hbC5TSUdURVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lH
SU5ULCBzdG9wKQoKICAgIGxhc3Rfc3dlZXAgPSB0aW1lLnRpbWUoKQogICAgY29udHJvbF9uZXh0
ID0gdGltZS50aW1lKCkKICAgIGxvZygibGlzdGVuaW5nIG9uICVzIHBvcnRzPSVzIHBpZD0lZCIg
JQogICAgICAgIChpZmFjZSBvciAiPGFsbD4iLCBzb3J0ZWQocG9ydHMpLCBvcy5nZXRwaWQoKSkp
CiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6CiAgICAgICAgbG9nKCJXU1NFIFVzZXJuYW1lVG9rZW4g
aW5zcGVjdGlvbiBlbmFibGVkIChib3VuZGVkIHRvICVkIGJ5dGVzL3JlcXVlc3QpIiAlCiAgICAg
ICAgICAgIHdzc2VfYm9keV9ieXRlcykKCiAgICAjIDFzIHJlY3YgdGltZW91dDogKGEpIGxldHMg
dGhlIHBlbmRpbmcvZmxvdyBzd2VlcHMgYWN0dWFsbHkgZmlyZSDigJQKICAgICMgd2l0aG91dCBp
dCBgZXhjZXB0IHNvY2tldC50aW1lb3V0YCBuZXZlciBydW5zOyAoYikgZW1waXJpY2FsbHkgUkVR
VUlSRUQKICAgICMgd2l0aCB0aGUgQlBGIGZpbHRlciBhdHRhY2hlZDogYSBmdWxseS1ibG9ja2lu
ZyByZWN2IG9uIHRoaXMga2VybmVsCiAgICAjIHN0YXJ2ZXMgYWZ0ZXIgdGhlIGZpcnN0IHBhY2tl
dCwgd2hpbGUgdGhlIHRpbWVvdXQnZCByZWN2IGRlbGl2ZXJzCiAgICAjIGNvbnRpbnVvdXNseSAo
dmVyaWZpZWQgYnkgQS9COiByeD0xIHZzIHJ4PTI5IGlkZW50aWNhbCBvdGhlcndpc2UpLgogICAg
cy5zZXR0aW1lb3V0KDEuMCkKCiAgICBkYmcgPSBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfREVC
VUciKSA9PSAiMSIKICAgIGRiZ19yeCA9IDAKICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAg
IHdoaWxlIHJ1bm5pbmdbMF06CiAgICAgICAgZW1pdF9jYXB0dXJlX3N0YXRzKCkKICAgICAgICAj
IFBvbGwgaW5kZXBlbmRlbnRseSBvZiBzb2NrZXQgaWRsZSB0aW1lLiBBIGJ1c3kgbW9uaXRvcmVk
IGludGVyZmFjZQogICAgICAgICMgbWF5IG5ldmVyIHJhaXNlIHNvY2tldC50aW1lb3V0LCBidXQg
Y29udHJvbCBjaGFuZ2VzIG11c3Qgc3RpbGwgYXBwbHkuCiAgICAgICAgaWYgY29udHJvbF9jbGll
bnQgaXMgbm90IE5vbmUgYW5kIHRpbWUudGltZSgpID49IGNvbnRyb2xfbmV4dDoKICAgICAgICAg
ICAgdHJ5OgogICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBjb250cm9sX2FjdGlvbiwgY29u
dHJvbF9zdGF0dXMgPSBfcnVuX2NvbnRyb2xfdGljaygKICAgICAgICAgICAgICAgICAgICBwb3J0
cywgaWZhY2UsIGNvbnRyb2xfcnVuLCBjb250cm9sX2NsaWVudCkKICAgICAgICAgICAgICAgIGxv
ZygicmVtb3RlIGNvbnRyb2w6ICVzIiAlIGNvbnRyb2xfc3RhdHVzKQogICAgICAgICAgICAgICAg
aWYgY29udHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiOgogICAgICAgICAgICAgICAgICAgIGFyZ3Mg
PSBfcmVzdGFydF9hcmdzKHN5cy5hcmd2WzBdLCBpZmFjZSwgcG9ydHMsCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyYm9zZSwgd29ya2Vycywgd3NzZV9ib2R5X2J5
dGVzKQogICAgICAgICAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2w6IHJlLWV4ZWN1dGlu
ZyBjYXB0dXJlIHdpdGggdXBkYXRlZCBjb25maWd1cmF0aW9uIikKICAgICAgICAgICAgICAgICAg
ICBzLmNsb3NlKCkKICAgICAgICAgICAgICAgICAgICBvcy5leGVjdihzeXMuZXhlY3V0YWJsZSwg
YXJncykKICAgICAgICAgICAgICAgIGVsaWYgY29udHJvbF9hY3Rpb24gPT0gInN0b3AiOgogICAg
ICAgICAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2w6IHN0b3AgcmVxdWVzdGVkOyBleGl0
aW5nIikKICAgICAgICAgICAgICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgICAgICAgICAg
ICAgICAgICBjb250aW51ZQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAg
ICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIHRpY2sgZmFpbGVkICglcykiICUg
bnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCiAgICAgICAgICAgIGNvbnRyb2xfbmV4dCA9IHRp
bWUudGltZSgpICsgY29udHJvbF9pbnRlcnZhbAogICAgICAgIHRyeToKICAgICAgICAgICAgcGt0
ID0gcy5yZWN2KDY1NTM1KQogICAgICAgICAgICBkYmdfcnggKz0gMQogICAgICAgICAgICBzdGF0
c19zdGF0ZVsicGFja2V0c190b3RhbCJdICs9IDEKICAgICAgICAgICAgc3RhdHNfc3RhdGVbInBh
Y2tldF9ieXRlc190b3RhbCJdICs9IGxlbihwa3QpCiAgICAgICAgICAgIGlmIGRiZyBhbmQgdGlt
ZS50aW1lKCkgLSBkYmdfbGFzdCA+IDU6CiAgICAgICAgICAgICAgICBsb2coIkRFQlVHIHJ4PSVk
IiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgICAg
ICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6CiAgICAgICAgICAgIGlmIGRiZzoKICAgICAgICAgICAg
ICAgIGxvZygiREVCVUcgdGltZW91dCByeD0lZCIgJSBkYmdfcngpCiAgICAgICAgICAgICAgICBk
YmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAg
ICAgICAgIGlmIG1haW50ZW5hbmNlX2R1ZShub3csIGxhc3Rfc3dlZXApOgogICAgICAgICAgICAg
ICAgb3V0X3MgPSBbXQogICAgICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93LCBvdXRf
cywgcGVuZGluZykKICAgICAgICAgICAgICAgIHN3ZWVwX3BlbmRpbmcocGVuZGluZywgbm93LCBv
dXRfcykKICAgICAgICAgICAgICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgICAgICAgICAgICAg
IGxhc3Rfc3dlZXAgPSBub3cKICAgICAgICAgICAgY29udGludWUKICAgICAgICBleGNlcHQgc29j
a2V0LmVycm9yIGFzIGU6CiAgICAgICAgICAgIGlmIGUuZXJybm8gPT0gZXJybm8uRUlOVFI6CiAg
ICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICByYWlzZQogICAgICAgIG4gPSBsZW4o
cGt0KQogICAgICAgIGlmIG4gPCAzNDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBvdXQg
PSBbXQogICAgICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRoZXJuZXQgaGVh
ZGVyCiAgICAgICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBldHlwZSA9PSBF
VEhfUF9WTEFOOgogICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQogICAgICAgICAg
ICBvZmYgPSAxOAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAgICAgICAgIGNv
bnRpbnVlICAgICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlzIHJhcmUK
ICAgICAgICBpcDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4gNCAhPSA0IG9y
IHViKHBrdCwgb2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAg
Y29udGludWUKICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAgZnJhZyA9IHUx
Nihwa3QsIG9mZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAgICAgICAgICAg
ICAgICAgICAgICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29udGludWUKICAg
ICAgICBzcmNfaXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAgICAgZHN0X2lw
ID0gbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYgPSBvZmYgKyBp
aGwKICAgICAgICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAgICAgZG9mZl9m
bGFncyA9IHViKHBrdCwgdGNwX29mZiArIDEyKQogICAgICAgIGRvZmYgPSAoZG9mZl9mbGFnc1sw
XSA+PiA0KSAqIDQKICAgICAgICBwYXlfc3RhcnQgPSB0Y3Bfb2ZmICsgZG9mZgogICAgICAgIGlm
IG4gPD0gcGF5X3N0YXJ0OgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICMgbm8gcGF5bG9hZCBpbiBzZWdtZW50CiAgICAgICAgcGF5bG9hZCA9IHBrdFtw
YXlfc3RhcnQ6XQogICAgICAgIGZsYWdzID0gZG9mZl9mbGFnc1sxXQogICAgICAgIG5vdyA9IHRp
bWUudGltZSgpCgogICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLSBSRVNQT05TRSBkaXJlY3Rpb24g
KHNlcnZlciAtPiBjbGllbnQpIC0tLS0tLS0tLS0KICAgICAgICBpZiBzcG9ydCBpbiBwb3J0cyBh
bmQgZHBvcnQgbm90IGluIHBvcnRzOgogICAgICAgICAgICAjIHBlbmRpbmcga2V5IHdhcyBzdG9y
ZWQgYXMgKHNlcnZlcl9pcCwgc2VydmVyX3BvcnQsIGNsaWVudF9pcCwKICAgICAgICAgICAgIyBj
bGllbnRfcG9ydCkgPT0gKHNyYywgc3BvcnQsIGRzdCwgZHBvcnQpIE9GIFRISVMgcmVzcG9uc2Ug
cGt0CiAgICAgICAgICAgIHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAg
ICAgICAgIGlmIHBheWxvYWRbOjVdID09IGIiSFRUUC8iOgogICAgICAgICAgICAgICAgY29ycmVs
YXRlX3Jlc3BvbnNlKHBlbmRpbmcsIHJrLCBwYXlsb2FkLCBub3csIG91dCkKICAgICAgICAgICAg
ZWxpZiBmbGFncyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgRklOfFJTVDogZmx1c2gg
dW5tYXRjaGVkCiAgICAgICAgICAgICAgICBldiA9IHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAg
ICAgIyAtLS0tLS0tLS0tLS0tLS0tIFJFUVVFU1QgZGlyZWN0aW9uIChjbGllbnQgLT4gc2VydmVy
KSAtLS0tLS0tLS0tLQogICAgICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAgICAgIGlm
IGZsYWdzICYgMHgwNTogICAgICAgICAgICAgICAgICAgICAgIyB0ZWFyZG93biB3L28gcmVzcG9u
c2Ugc2VlbgogICAgICAgICAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9y
dCkKICAgICAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAgICAgICAgIGtleSA9
IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBoYW5kbGVfcGF5bG9h
ZChmbG93cywga2V5LCBOb25lLCBwYXlsb2FkLAogICAgICAgICAgICAgICAgICAgICAgICAgICAo
ZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAgICAgICAgICAgICAg
IHBvcnRzLCBub2RlX2hvc3QsIG91dCwgcGVuZGluZywgbm93LAogICAgICAgICAgICAgICAgICAg
ICAgICAgICB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgaWYgb3V0OgogICAgICAgICAgICB3cml0
ZV9ldmVudHMob3V0KQoKICAgICAgICBpZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVw
KToKICAgICAgICAgICAgb3V0X3MgPSBbXQogICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dzLCBu
b3csIG91dF9zLCBwZW5kaW5nKQogICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5v
dywgb3V0X3MpCiAgICAgICAgICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgICAgICAgICAgbGFz
dF9zd2VlcCA9IG5vdwoKICAgIG91dF9zID0gW10KICAgIGRyYWluX2luY29tcGxldGVfd3NzZShm
bG93cywgb3V0X3MsIHBlbmRpbmcsIHRpbWUudGltZSgpKQogICAgZHJhaW5fcGVuZGluZyhwZW5k
aW5nLCBvdXRfcykKICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgIGVtaXRfY2FwdHVyZV9zdGF0
cyhmb3JjZT1UcnVlKQogICAgbG9nKCJzdG9wcGVkICglZCBwZW5kaW5nIHJlcXVlc3RzIGZsdXNo
ZWQpIiAlIGxlbihvdXRfcykpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4o
KQo=
#__END_SNIFF__
#__SHIP_B64__
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiMgLSotIGNvZGluZzogdXRmLTggLSotCiIiIm50LXNoaXAu
cHkg4oCUIGV2ZW50IHNoaXBwZXIgZm9yIG9sZC1rZXJuZWwgbm9kZXMgKHB5dGhvbiAyLjYgY29t
cGF0aWJsZSkuCgpSZWFkcyBOZXR3b3JrVHJhY2luZyBKU09OTCBldmVudHMgb24gc3RkaW4sIGJh
dGNoZXMgdGhlbSwgYW5kIFBPU1RzIHRvIHRoZSBIdWIKL2FwaS9pbmdlc3QuIFVwbG9hZHMgdXNl
IGJvdW5kZWQgbWVtb3J5IGFuZCBkcm9wIG9uIG92ZXJsb2FkIG9yIEh1YiBmYWlsdXJlOwp0aGUg
Y29tcGF0aWJpbGl0eSAtLXNwb29sIG9wdGlvbiBkb2VzIG5vdCBlbmFibGUgZGlzayB3cml0ZXMu
CgpVc2FnZToKICBOVF9TSElQX1JBVEVfS0JQUz0xMDI0IHB5dGhvbiBudC1zaGlwLnB5IC0tZW5k
cG9pbnQgaHR0cDovL2h1YjozMTExNQoiIiIKZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBwcmludF9m
dW5jdGlvbgoKaW1wb3J0IGVycm5vLCBqc29uLCBvcywgc2VsZWN0LCBzaWduYWwsIHNvY2tldCwg
c3lzCgojIHB5Mi42L2VsNiBuYW1lcyBmaXJzdDsgcHkzIGZhbGxiYWNrcyBmb3IgZGV2LWJveCB0
ZXN0aW5nLiBUaGUgdXJsbGliMgojIHN0ci12cy1ieXRlcyBlbmNvZGUgZ3VhcmQgaW4gZmx1c2go
KSBzdGF5cyDigJQgZG8gbm90IHJlbW92ZS4KdHJ5OgogICAgaW1wb3J0IFF1ZXVlICAgICAgICAg
ICAgICAgICAgICAgICMgcHkyOiBRdWV1ZSBtb2R1bGUsIGNsYXNzIFF1ZXVlLlF1ZXVlCiAgICBp
bXBvcnQgdXJsbGliMgpleGNlcHQgSW1wb3J0RXJyb3I6ICAgICAgICAgICAgICAgICAgICMgcHkz
CiAgICBpbXBvcnQgcXVldWUgYXMgUXVldWUKICAgIGltcG9ydCB1cmxsaWIucmVxdWVzdCBhcyB1
cmxsaWIyCmltcG9ydCB0aHJlYWRpbmcsIHRpbWUKCk1BWF9CQVRDSCA9IDQwMApNQVhfUE9TVF9C
WVRFUyA9IDY1NTM2Ck1BWF9TVEFUU19CWVRFUyA9IDE2Mzg0Ck1BWF9RVUVVRV9CQVRDSEVTID0g
MTYKTUFYX1NISVBfVEhSRUFEUyA9IDgKVEhSRUFEX1NUQUNLX0JZVEVTID0gMjYyMTQ0CkRFRkFV
TFRfUkFURV9LQlBTID0gMTAyNApNSU5fUkFURV9LQlBTID0gNjQKTUFYX1JBVEVfS0JQUyA9IDEw
MDAwCkZMVVNIX1NFQyA9IDUuMAoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUo
Im50LXNoaXA6ICVzXG4iICUgbXNnKQogICAgc3lzLnN0ZGVyci5mbHVzaCgpCgoKY2xhc3MgUmF0
ZUxpbWl0ZXIob2JqZWN0KToKICAgICIiIlJlc2VydmUgYWdncmVnYXRlIHVwbG9hZCBzbG90cyBh
Y3Jvc3MgYWxsIHBvc3RlciB0aHJlYWRzLiIiIgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGticHMp
OgogICAgICAgIHNlbGYuYnl0ZXNfcGVyX3NlYyA9IG1heCgxLCAoa2JwcyAqIDEwMDApIC8vIDgp
CiAgICAgICAgc2VsZi5uZXh0X3Nsb3QgPSAwLjAKICAgICAgICBzZWxmLmxvY2sgPSB0aHJlYWRp
bmcuTG9jaygpCgogICAgZGVmIHdhaXQoc2VsZiwgc2l6ZSk6CiAgICAgICAgbm93ID0gdGltZS50
aW1lKCkKICAgICAgICBzZWxmLmxvY2suYWNxdWlyZSgpCiAgICAgICAgdHJ5OgogICAgICAgICAg
ICBpZiBzZWxmLm5leHRfc2xvdCA8IG5vdyBvciBzZWxmLm5leHRfc2xvdCAtIG5vdyA+IDYwLjA6
CiAgICAgICAgICAgICAgICBzZWxmLm5leHRfc2xvdCA9IG5vdwogICAgICAgICAgICBzbG90ID0g
c2VsZi5uZXh0X3Nsb3QKICAgICAgICAgICAgc2VsZi5uZXh0X3Nsb3QgKz0gZmxvYXQoc2l6ZSkg
LyBzZWxmLmJ5dGVzX3Blcl9zZWMKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLmxv
Y2sucmVsZWFzZSgpCiAgICAgICAgZGVsYXkgPSBzbG90IC0gbm93CiAgICAgICAgaWYgZGVsYXkg
PiAwOgogICAgICAgICAgICB0aW1lLnNsZWVwKGRlbGF5KQoKCmRlZiByZWFkX2JvdW5kZWRfaW50
KG5hbWUsIGRlZmF1bHQsIG1pbmltdW0sIG1heGltdW0pOgogICAgdHJ5OgogICAgICAgIHZhbHVl
ID0gaW50KG9zLmVudmlyb24uZ2V0KG5hbWUsIHN0cihkZWZhdWx0KSkpCiAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICB2YWx1ZSA9IGRlZmF1bHQKICAgIHJldHVybiBtYXgobWluaW11bSwg
bWluKHZhbHVlLCBtYXhpbXVtKSkKCgpkZWYgY29uZmlndXJlX3RocmVhZF9zdGFjaygpOgogICAg
IiIiQm91bmQgdmlydHVhbCBzdGFjayByZXNlcnZhdGlvbiBmb3IgZnV0dXJlIFB5dGhvbiBwb3N0
ZXIgdGhyZWFkcy4iIiIKICAgIHRyeToKICAgICAgICB0aHJlYWRpbmcuc3RhY2tfc2l6ZShUSFJF
QURfU1RBQ0tfQllURVMpCiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCAoVmFsdWVFcnJv
ciwgUnVudGltZUVycm9yKToKICAgICAgICBsb2coIldBUk46IGNhbm5vdCBzZXQgJWQtYnl0ZSBw
b3N0ZXIgc3RhY2s7IHRocmVhZCBzdGFydHVwIHJlbWFpbnMgYWRhcHRpdmUiICUKICAgICAgICAg
ICAgVEhSRUFEX1NUQUNLX0JZVEVTKQogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiB0YWtlX2Jv
dW5kZWRfYmF0Y2goYnVmLCBub2RlLCBvbl9kcm9wPU5vbmUpOgogICAgIiIiUmVtb3ZlIG9uZSA8
PTY0IEtpQiBlbmNvZGVkIGJhdGNoLCBkcm9wcGluZyBpbXBvc3NpYmxlIGdpYW50IGV2ZW50cy4i
IiIKICAgIHdoaWxlIGJ1ZjoKICAgICAgICBiYXRjaCA9IFtdCiAgICAgICAgZW1wdHlfc2l6ZSA9
IGxlbihqc29uLmR1bXBzKHsibm9kZSI6IG5vZGUsICJldmVudHMiOiBbXX0sCiAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgIHNlcGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCJ1
dGYtOCIpKQogICAgICAgIGVuY29kZWRfc2l6ZSA9IGVtcHR5X3NpemUKICAgICAgICBmb3IgZXZl
bnQgaW4gYnVmWzpNQVhfQkFUQ0hdOgogICAgICAgICAgICBldmVudF9zaXplID0gbGVuKGpzb24u
ZHVtcHMoZXZlbnQsIHNlcGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCJ1dGYtOCIpKQogICAg
ICAgICAgICBjYW5kaWRhdGVfc2l6ZSA9IGVuY29kZWRfc2l6ZSArIGV2ZW50X3NpemUgKyAoMSBp
ZiBiYXRjaCBlbHNlIDApCiAgICAgICAgICAgIGlmIGNhbmRpZGF0ZV9zaXplID4gTUFYX1BPU1Rf
QllURVM6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBiYXRjaC5hcHBlbmQoZXZl
bnQpCiAgICAgICAgICAgIGVuY29kZWRfc2l6ZSA9IGNhbmRpZGF0ZV9zaXplCiAgICAgICAgaWYg
YmF0Y2g6CiAgICAgICAgICAgIGRlbCBidWZbOmxlbihiYXRjaCldCiAgICAgICAgICAgIHJldHVy
biBiYXRjaAogICAgICAgIGRlbCBidWZbMF0KICAgICAgICBpZiBvbl9kcm9wIGlzIG5vdCBOb25l
OgogICAgICAgICAgICBvbl9kcm9wKCJvdmVyc2l6ZWQiLCAxKQogICAgICAgIGxvZygiV0FSTjog
ZHJvcHBlZCBvdmVyc2l6ZWQgZXZlbnQ7IGVuY29kZWQgYm9keSBleGNlZWRzICVkIGJ5dGVzIiAl
CiAgICAgICAgICAgIE1BWF9QT1NUX0JZVEVTKQogICAgcmV0dXJuIFtdCgoKY2xhc3MgU2hpcFN0
YXRzKG9iamVjdCk6CiAgICAiIiJTbWFsbCBsb2NrZWQgY291bnRlciBzZXQgc2hhcmVkIGJ5IHRo
ZSBib3VuZGVkIHBvc3RlciB0aHJlYWRzLiIiIgogICAgS0VZUyA9ICgiZXZlbnRzX2luIiwgImV2
ZW50c19wdXNoZWQiLCAiZXZlbnRzX2Ryb3BwZWQiLAogICAgICAgICAgICAiYmF0Y2hlc19wdXNo
ZWQiLCAiYmF0Y2hlc19mYWlsZWQiLCAiYnl0ZXNfcHVzaGVkIiwKICAgICAgICAgICAgInF1ZXVl
X2Z1bGwiLCAiaHViX2ZhaWx1cmUiLCAib3ZlcnNpemVkIiwKICAgICAgICAgICAgInN0YXRzX3Nh
bXBsZXNfZHJvcHBlZCIpCgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYubG9j
ayA9IHRocmVhZGluZy5Mb2NrKCkKICAgICAgICBzZWxmLnRvdGFsID0gZGljdCgoa2V5LCAwKSBm
b3Iga2V5IGluIHNlbGYuS0VZUykKICAgICAgICBzZWxmLnByZXZpb3VzID0gZGljdChzZWxmLnRv
dGFsKQogICAgICAgIHNlbGYubGFzdF9hdCA9IHRpbWUudGltZSgpCiAgICAgICAgc2VsZi5sYXN0
X2NwdSA9IE5vbmUKICAgICAgICBzZWxmLnNlcXVlbmNlID0gMAogICAgICAgIHNlbGYucXVldWVk
X2V2ZW50cyA9IDAKICAgICAgICBzZWxmLnF1ZXVlX2hpZ2hfd2F0ZXIgPSAwCiAgICAgICAgc2Vs
Zi5pbnN0YW5jZV9pZCA9ICIlZC0lZCIgJSAoaW50KHNlbGYubGFzdF9hdCksIG9zLmdldHBpZCgp
KQogICAgICAgIHNlbGYubGFzdF9wdXNoX2h0dHBfc3RhdHVzID0gMAogICAgICAgIHNlbGYubGFz
dF9zdWNjZXNzX2F0ID0gMAogICAgICAgIHNlbGYuY29uc2VjdXRpdmVfZmFpbHVyZXMgPSAwCiAg
ICAgICAgc2VsZi5wZW5kaW5nX3NhbXBsZSA9IE5vbmUKCiAgICBkZWYgYWRkKHNlbGYsIGtleSwg
dmFsdWU9MSk6CiAgICAgICAgc2VsZi5sb2NrLmFjcXVpcmUoKQogICAgICAgIHRyeToKICAgICAg
ICAgICAgc2VsZi50b3RhbFtrZXldICs9IGludCh2YWx1ZSkKICAgICAgICBmaW5hbGx5OgogICAg
ICAgICAgICBzZWxmLmxvY2sucmVsZWFzZSgpCgogICAgZGVmIGRyb3BwZWQoc2VsZiwgY2F1c2Us
IGNvdW50KToKICAgICAgICBzZWxmLmxvY2suYWNxdWlyZSgpCiAgICAgICAgdHJ5OgogICAgICAg
ICAgICBzZWxmLnRvdGFsWyJldmVudHNfZHJvcHBlZCJdICs9IGludChjb3VudCkKICAgICAgICAg
ICAgc2VsZi50b3RhbFtjYXVzZV0gKz0gaW50KGNvdW50KQogICAgICAgIGZpbmFsbHk6CiAgICAg
ICAgICAgIHNlbGYubG9jay5yZWxlYXNlKCkKCiAgICBkZWYgYmF0Y2hfc3VjY2VzcyhzZWxmLCBj
b3VudCwgYm9keV9ieXRlcyk6CiAgICAgICAgc2VsZi5sb2NrLmFjcXVpcmUoKQogICAgICAgIHRy
eToKICAgICAgICAgICAgc2VsZi50b3RhbFsiZXZlbnRzX3B1c2hlZCJdICs9IGludChjb3VudCkK
ICAgICAgICAgICAgc2VsZi50b3RhbFsiYmF0Y2hlc19wdXNoZWQiXSArPSAxCiAgICAgICAgICAg
IHNlbGYudG90YWxbImJ5dGVzX3B1c2hlZCJdICs9IGludChib2R5X2J5dGVzKQogICAgICAgICAg
ICBzZWxmLmxhc3RfcHVzaF9odHRwX3N0YXR1cyA9IDIwMAogICAgICAgICAgICBzZWxmLmxhc3Rf
c3VjY2Vzc19hdCA9IGludCh0aW1lLnRpbWUoKSkKICAgICAgICAgICAgc2VsZi5jb25zZWN1dGl2
ZV9mYWlsdXJlcyA9IDAKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLmxvY2sucmVs
ZWFzZSgpCgogICAgZGVmIGJhdGNoX2ZhaWx1cmUoc2VsZiwgY291bnQpOgogICAgICAgIHNlbGYu
bG9jay5hY3F1aXJlKCkKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYudG90YWxbImJhdGNo
ZXNfZmFpbGVkIl0gKz0gMQogICAgICAgICAgICBzZWxmLnRvdGFsWyJldmVudHNfZHJvcHBlZCJd
ICs9IGludChjb3VudCkKICAgICAgICAgICAgc2VsZi50b3RhbFsiaHViX2ZhaWx1cmUiXSArPSBp
bnQoY291bnQpCiAgICAgICAgICAgIHNlbGYubGFzdF9wdXNoX2h0dHBfc3RhdHVzID0gMAogICAg
ICAgICAgICBzZWxmLmNvbnNlY3V0aXZlX2ZhaWx1cmVzICs9IDEKICAgICAgICBmaW5hbGx5Ogog
ICAgICAgICAgICBzZWxmLmxvY2sucmVsZWFzZSgpCgogICAgZGVmIHF1ZXVlZChzZWxmLCBkZWx0
YSk6CiAgICAgICAgc2VsZi5sb2NrLmFjcXVpcmUoKQogICAgICAgIHRyeToKICAgICAgICAgICAg
c2VsZi5xdWV1ZWRfZXZlbnRzID0gbWF4KDAsIHNlbGYucXVldWVkX2V2ZW50cyArIGludChkZWx0
YSkpCiAgICAgICAgICAgIGlmIHNlbGYucXVldWVkX2V2ZW50cyA+IHNlbGYucXVldWVfaGlnaF93
YXRlcjoKICAgICAgICAgICAgICAgIHNlbGYucXVldWVfaGlnaF93YXRlciA9IHNlbGYucXVldWVk
X2V2ZW50cwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNlbGYubG9jay5yZWxlYXNlKCkK
CiAgICBkZWYgb2ZmZXJfc3RhdHMoc2VsZiwgc2FtcGxlKToKICAgICAgICAiIiJDb2FsZXNjZSBz
dGF0cyB0byBvbmUgbGF0ZXN0IGluLW1lbW9yeSBzYW1wbGUuIiIiCiAgICAgICAgc2VsZi5sb2Nr
LmFjcXVpcmUoKQogICAgICAgIHRyeToKICAgICAgICAgICAgbmVlZHNfcXVldWVfaXRlbSA9IHNl
bGYucGVuZGluZ19zYW1wbGUgaXMgTm9uZQogICAgICAgICAgICBpZiBub3QgbmVlZHNfcXVldWVf
aXRlbToKICAgICAgICAgICAgICAgIHNlbGYudG90YWxbInN0YXRzX3NhbXBsZXNfZHJvcHBlZCJd
ICs9IDEKICAgICAgICAgICAgc2VsZi5wZW5kaW5nX3NhbXBsZSA9IHNhbXBsZQogICAgICAgICAg
ICByZXR1cm4gbmVlZHNfcXVldWVfaXRlbQogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNl
bGYubG9jay5yZWxlYXNlKCkKCiAgICBkZWYgdGFrZV9zdGF0cyhzZWxmKToKICAgICAgICBzZWxm
LmxvY2suYWNxdWlyZSgpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzYW1wbGUgPSBzZWxmLnBl
bmRpbmdfc2FtcGxlCiAgICAgICAgICAgIHNlbGYucGVuZGluZ19zYW1wbGUgPSBOb25lCiAgICAg
ICAgICAgIHJldHVybiBzYW1wbGUKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLmxv
Y2sucmVsZWFzZSgpCgogICAgZGVmIF9yZXNvdXJjZXMoc2VsZiwgZWxhcHNlZCk6CiAgICAgICAg
dGltZXMgPSBvcy50aW1lcygpCiAgICAgICAgY3B1X3RvdGFsID0gZmxvYXQodGltZXNbMF0gKyB0
aW1lc1sxXSkKICAgICAgICBjcHVfcGVyY2VudCA9IDAuMAogICAgICAgIGlmIHNlbGYubGFzdF9j
cHUgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIGNwdV9wZXJjZW50ID0gMTAwLjAgKiBtYXgoMC4w
LCBjcHVfdG90YWwgLSBzZWxmLmxhc3RfY3B1KSAvIGVsYXBzZWQKICAgICAgICBzZWxmLmxhc3Rf
Y3B1ID0gY3B1X3RvdGFsCiAgICAgICAgcnNzID0gMAogICAgICAgIHZpcnR1YWwgPSAwCiAgICAg
ICAgdHJ5OgogICAgICAgICAgICBmb3IgbGluZSBpbiBvcGVuKCIvcHJvYy9zZWxmL3N0YXR1cyIs
ICJyIik6CiAgICAgICAgICAgICAgICBpZiBsaW5lLnN0YXJ0c3dpdGgoIlZtUlNTOiIpOgogICAg
ICAgICAgICAgICAgICAgIHJzcyA9IGludChsaW5lLnNwbGl0KClbMV0pICogMTAyNAogICAgICAg
ICAgICAgICAgZWxpZiBsaW5lLnN0YXJ0c3dpdGgoIlZtU2l6ZToiKToKICAgICAgICAgICAgICAg
ICAgICB2aXJ0dWFsID0gaW50KGxpbmUuc3BsaXQoKVsxXSkgKiAxMDI0CiAgICAgICAgZXhjZXB0
IChJT0Vycm9yLCBPU0Vycm9yLCBWYWx1ZUVycm9yLCBJbmRleEVycm9yKToKICAgICAgICAgICAg
cGFzcwogICAgICAgIHRyeToKICAgICAgICAgICAgb3Blbl9mZHMgPSBsZW4ob3MubGlzdGRpcigi
L3Byb2Mvc2VsZi9mZCIpKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICBvcGVu
X2ZkcyA9IDAKICAgICAgICBhY3RpdmVfY291bnQgPSBnZXRhdHRyKHRocmVhZGluZywgImFjdGl2
ZV9jb3VudCIsIHRocmVhZGluZy5hY3RpdmVDb3VudCkKICAgICAgICByZXR1cm4geyJjcHVfdXNl
cl9zZWNvbmRzIjogcm91bmQoZmxvYXQodGltZXNbMF0pLCAzKSwKICAgICAgICAgICAgICAgICJj
cHVfc3lzdGVtX3NlY29uZHMiOiByb3VuZChmbG9hdCh0aW1lc1sxXSksIDMpLAogICAgICAgICAg
ICAgICAgImNwdV9wZXJjZW50X29uZV9jb3JlIjogcm91bmQoY3B1X3BlcmNlbnQsIDQpLAogICAg
ICAgICAgICAgICAgInJzc19ieXRlcyI6IHJzcywgInZpcnR1YWxfYnl0ZXMiOiB2aXJ0dWFsLAog
ICAgICAgICAgICAgICAgIm9wZW5fZmRzIjogb3Blbl9mZHMsCiAgICAgICAgICAgICAgICAidGhy
ZWFkcyI6IGFjdGl2ZV9jb3VudCgpfQoKICAgIGRlZiBzbmFwc2hvdChzZWxmLCBjYXB0dXJlLCBu
b2RlLCBtb2RlLCByYXRlX2ticHMsIHNoaXBfdGhyZWFkcywKICAgICAgICAgICAgICAgICB3c3Nl
X2JvZHlfYnl0ZXMsIGJ1ZmZlcmVkX2V2ZW50cywgcXVldWVfY2FwYWNpdHkpOgogICAgICAgIG5v
dyA9IHRpbWUudGltZSgpCiAgICAgICAgZWxhcHNlZCA9IG1heCgwLjAwMSwgbm93IC0gc2VsZi5s
YXN0X2F0KQogICAgICAgIHNlbGYubG9jay5hY3F1aXJlKCkKICAgICAgICB0cnk6CiAgICAgICAg
ICAgIHRvdGFscyA9IGRpY3Qoc2VsZi50b3RhbCkKICAgICAgICAgICAgZGVsdGFzID0gZGljdCgo
a2V5LCB0b3RhbHNba2V5XSAtIHNlbGYucHJldmlvdXNba2V5XSkKICAgICAgICAgICAgICAgICAg
ICAgICAgICBmb3Iga2V5IGluIHNlbGYuS0VZUykKICAgICAgICAgICAgc2VsZi5wcmV2aW91cyA9
IGRpY3QodG90YWxzKQogICAgICAgICAgICBzZWxmLnNlcXVlbmNlICs9IDEKICAgICAgICAgICAg
c2VxdWVuY2UgPSBzZWxmLnNlcXVlbmNlCiAgICAgICAgICAgIHF1ZXVlZF9ldmVudHMgPSBzZWxm
LnF1ZXVlZF9ldmVudHMKICAgICAgICAgICAgcXVldWVfaGlnaF93YXRlciA9IHNlbGYucXVldWVf
aGlnaF93YXRlcgogICAgICAgICAgICBsYXN0X3B1c2hfaHR0cF9zdGF0dXMgPSBzZWxmLmxhc3Rf
cHVzaF9odHRwX3N0YXR1cwogICAgICAgICAgICBsYXN0X3N1Y2Nlc3NfYXQgPSBzZWxmLmxhc3Rf
c3VjY2Vzc19hdAogICAgICAgICAgICBjb25zZWN1dGl2ZV9mYWlsdXJlcyA9IHNlbGYuY29uc2Vj
dXRpdmVfZmFpbHVyZXMKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLmxvY2sucmVs
ZWFzZSgpCiAgICAgICAgc2VsZi5sYXN0X2F0ID0gbm93CiAgICAgICAgZHJvcF9wZXJjZW50ID0g
KDEwMC4wICogZGVsdGFzWyJldmVudHNfZHJvcHBlZCJdIC8KICAgICAgICAgICAgICAgICAgICAg
ICAgbWF4KDEsIGRlbHRhc1siZXZlbnRzX2luIl0pKQogICAgICAgIHJlYXNvbnMgPSBbXQogICAg
ICAgIGlmIGNhcHR1cmUuZ2V0KCJrZXJuZWxfZHJvcHNfZGVsdGEiLCAwKTogcmVhc29ucy5hcHBl
bmQoImtlcm5lbF9kcm9wIikKICAgICAgICBpZiBkZWx0YXNbImV2ZW50c19kcm9wcGVkIl06IHJl
YXNvbnMuYXBwZW5kKCJzaGlwX2Ryb3AiKQogICAgICAgIGlmIGRlbHRhc1siaHViX2ZhaWx1cmUi
XTogcmVhc29ucy5hcHBlbmQoImh1Yl91bnJlYWNoYWJsZSIpCiAgICAgICAgaWYgZGVsdGFzWyJx
dWV1ZV9mdWxsIl06IHJlYXNvbnMuYXBwZW5kKCJxdWV1ZV9wcmVzc3VyZSIpCiAgICAgICAgc2hp
cHBpbmcgPSB7CiAgICAgICAgICAgICJldmVudHNfaW5fdG90YWwiOiB0b3RhbHNbImV2ZW50c19p
biJdLAogICAgICAgICAgICAiZXZlbnRzX2luX2RlbHRhIjogZGVsdGFzWyJldmVudHNfaW4iXSwK
ICAgICAgICAgICAgImV2ZW50c19wdXNoZWRfdG90YWwiOiB0b3RhbHNbImV2ZW50c19wdXNoZWQi
XSwKICAgICAgICAgICAgImV2ZW50c19wdXNoZWRfZGVsdGEiOiBkZWx0YXNbImV2ZW50c19wdXNo
ZWQiXSwKICAgICAgICAgICAgImV2ZW50c19kcm9wcGVkX3RvdGFsIjogdG90YWxzWyJldmVudHNf
ZHJvcHBlZCJdLAogICAgICAgICAgICAiZXZlbnRzX2Ryb3BwZWRfZGVsdGEiOiBkZWx0YXNbImV2
ZW50c19kcm9wcGVkIl0sCiAgICAgICAgICAgICJkcm9wX2NhdXNlcyI6IHsKICAgICAgICAgICAg
ICAgICJxdWV1ZV9mdWxsX3RvdGFsIjogdG90YWxzWyJxdWV1ZV9mdWxsIl0sCiAgICAgICAgICAg
ICAgICAicXVldWVfZnVsbF9kZWx0YSI6IGRlbHRhc1sicXVldWVfZnVsbCJdLAogICAgICAgICAg
ICAgICAgImh1Yl9mYWlsdXJlX3RvdGFsIjogdG90YWxzWyJodWJfZmFpbHVyZSJdLAogICAgICAg
ICAgICAgICAgImh1Yl9mYWlsdXJlX2RlbHRhIjogZGVsdGFzWyJodWJfZmFpbHVyZSJdLAogICAg
ICAgICAgICAgICAgIm92ZXJzaXplZF90b3RhbCI6IHRvdGFsc1sib3ZlcnNpemVkIl0sCiAgICAg
ICAgICAgICAgICAib3ZlcnNpemVkX2RlbHRhIjogZGVsdGFzWyJvdmVyc2l6ZWQiXX0sCiAgICAg
ICAgICAgICJiYXRjaGVzX3B1c2hlZF90b3RhbCI6IHRvdGFsc1siYmF0Y2hlc19wdXNoZWQiXSwK
ICAgICAgICAgICAgImJhdGNoZXNfcHVzaGVkX2RlbHRhIjogZGVsdGFzWyJiYXRjaGVzX3B1c2hl
ZCJdLAogICAgICAgICAgICAiYmF0Y2hlc19mYWlsZWRfdG90YWwiOiB0b3RhbHNbImJhdGNoZXNf
ZmFpbGVkIl0sCiAgICAgICAgICAgICJiYXRjaGVzX2ZhaWxlZF9kZWx0YSI6IGRlbHRhc1siYmF0
Y2hlc19mYWlsZWQiXSwKICAgICAgICAgICAgImJ5dGVzX3B1c2hlZF90b3RhbCI6IHRvdGFsc1si
Ynl0ZXNfcHVzaGVkIl0sCiAgICAgICAgICAgICJieXRlc19wdXNoZWRfZGVsdGEiOiBkZWx0YXNb
ImJ5dGVzX3B1c2hlZCJdLAogICAgICAgICAgICAicHVzaF9ldmVudHNfcGVyX3NlY29uZCI6IHJv
dW5kKGRlbHRhc1siZXZlbnRzX3B1c2hlZCJdIC8gZWxhcHNlZCwgNCksCiAgICAgICAgICAgICJw
dXNoX2ticHMiOiByb3VuZCg4LjAgKiBkZWx0YXNbImJ5dGVzX3B1c2hlZCJdIC8gKDEwMDAuMCAq
IGVsYXBzZWQpLCA0KSwKICAgICAgICAgICAgImRyb3BfZXZlbnRzX3Blcl9zZWNvbmQiOiByb3Vu
ZChkZWx0YXNbImV2ZW50c19kcm9wcGVkIl0gLyBlbGFwc2VkLCA0KSwKICAgICAgICAgICAgImRy
b3BfcGVyY2VudCI6IHJvdW5kKGRyb3BfcGVyY2VudCwgNCksCiAgICAgICAgICAgICJxdWV1ZV9k
ZXB0aF9ldmVudHMiOiBpbnQoYnVmZmVyZWRfZXZlbnRzKSArIHF1ZXVlZF9ldmVudHMsCiAgICAg
ICAgICAgICJxdWV1ZV9jYXBhY2l0eV9ldmVudHMiOiBxdWV1ZV9jYXBhY2l0eSwKICAgICAgICAg
ICAgInF1ZXVlX2hpZ2hfd2F0ZXJfZXZlbnRzIjogcXVldWVfaGlnaF93YXRlciwKICAgICAgICAg
ICAgImxhc3RfcHVzaF9odHRwX3N0YXR1cyI6IGxhc3RfcHVzaF9odHRwX3N0YXR1cywKICAgICAg
ICAgICAgImxhc3Rfc3VjY2Vzc19hdCI6IGxhc3Rfc3VjY2Vzc19hdCwKICAgICAgICAgICAgImNv
bnNlY3V0aXZlX2ZhaWx1cmVzIjogY29uc2VjdXRpdmVfZmFpbHVyZXMsCiAgICAgICAgICAgICJz
dGF0c19zYW1wbGVzX2Ryb3BwZWRfdG90YWwiOiB0b3RhbHNbInN0YXRzX3NhbXBsZXNfZHJvcHBl
ZCJdfQogICAgICAgIHJldHVybiB7InNjaGVtYV92ZXJzaW9uIjogMSwgInR5cGUiOiAiYWdlbnRf
c3RhdHMiLCAibm9kZSI6IG5vZGUsCiAgICAgICAgICAgICAgICAiaW5zdGFuY2VfaWQiOiBzZWxm
Lmluc3RhbmNlX2lkLCAic2VxdWVuY2UiOiBzZXF1ZW5jZSwKICAgICAgICAgICAgICAgICJvYnNl
cnZlZF9hdCI6IGludChub3cpLCAid2luZG93X3NlY29uZHMiOiByb3VuZChlbGFwc2VkLCAzKSwK
ICAgICAgICAgICAgICAgICJtb2RlIjogbW9kZSwgInN0YXR1cyI6ICJkZWdyYWRlZCIgaWYgcmVh
c29ucyBlbHNlICJvayIsCiAgICAgICAgICAgICAgICAicmVhc29ucyI6IHJlYXNvbnMsICJjYXB0
dXJlIjogY2FwdHVyZSwKICAgICAgICAgICAgICAgICJzaGlwcGluZyI6IHNoaXBwaW5nLCAicmVz
b3VyY2VzIjogc2VsZi5fcmVzb3VyY2VzKGVsYXBzZWQpLAogICAgICAgICAgICAgICAgImxpbWl0
cyI6IHsiY3B1X2NvcmUiOiBhbGxvd2VkX2NwdSgpLAogICAgICAgICAgICAgICAgICAgICAgICAg
ICAiYWRkcmVzc19zcGFjZV9ieXRlcyI6IDI2ODQzNTQ1NiwKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgInNoaXBfcmF0ZV9rYnBzIjogcmF0ZV9rYnBzLAogICAgICAgICAgICAgICAgICAgICAg
ICAgICAiaHR0cF9ib2R5X21heF9ieXRlcyI6IE1BWF9QT1NUX0JZVEVTLAogICAgICAgICAgICAg
ICAgICAgICAgICAgICAic2hpcF90aHJlYWRzX21heCI6IE1BWF9TSElQX1RIUkVBRFMsCiAgICAg
ICAgICAgICAgICAgICAgICAgICAgICJ3c3NlX2JvZHlfYnl0ZXMiOiB3c3NlX2JvZHlfYnl0ZXN9
fQoKCmRlZiBhbGxvd2VkX2NwdSgpOgogICAgdHJ5OgogICAgICAgIGZvciBsaW5lIGluIG9wZW4o
Ii9wcm9jL3NlbGYvc3RhdHVzIiwgInIiKToKICAgICAgICAgICAgaWYgbGluZS5zdGFydHN3aXRo
KCJDcHVzX2FsbG93ZWRfbGlzdDoiKToKICAgICAgICAgICAgICAgIHJldHVybiBsaW5lLnNwbGl0
KCI6IiwgMSlbMV0uc3RyaXAoKQogICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yLCBJbmRleEVy
cm9yKToKICAgICAgICBwYXNzCiAgICByZXR1cm4gInVua25vd24iCgoKZGVmIG1haW4oKToKICAg
IGVuZHBvaW50ID0gTm9uZQogICAgc3Bvb2wgPSAiL3Zhci9saWIvbmV0d29ya3RyYWNpbmcvc25p
ZmYtc3Bvb2wuanNvbmwiCiAgICBhcmd2ID0gc3lzLmFyZ3ZbMTpdCiAgICBpID0gMAogICAgd2hp
bGUgaSA8IGxlbihhcmd2KToKICAgICAgICBhID0gYXJndltpXQogICAgICAgIGlmIGEgPT0gIi0t
ZW5kcG9pbnQiOgogICAgICAgICAgICBpICs9IDE7IGVuZHBvaW50ID0gYXJndltpXS5yc3RyaXAo
Ii8iKQogICAgICAgIGVsaWYgYSA9PSAiLS1zcG9vbCI6CiAgICAgICAgICAgIGkgKz0gMTsgc3Bv
b2wgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhIGluICgiLWgiLCAiLS1oZWxwIik6CiAgICAgICAg
ICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0ZW1FeGl0KDApCiAgICAgICAgZWxzZToKICAg
ICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5rbm93biBhcmc6ICVzIiAlIGEpCiAgICAgICAg
aSArPSAxCiAgICBpZiBub3QgZW5kcG9pbnQ6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLS1l
bmRwb2ludCByZXF1aXJlZCIpCgogICAgbm9kZSA9IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0
KCIuIilbMF0KICAgIHJhdGVfa2JwcyA9IHJlYWRfYm91bmRlZF9pbnQoIk5UX1NISVBfUkFURV9L
QlBTIiwgREVGQVVMVF9SQVRFX0tCUFMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
IE1JTl9SQVRFX0tCUFMsIE1BWF9SQVRFX0tCUFMpCiAgICBsaW1pdGVyID0gUmF0ZUxpbWl0ZXIo
cmF0ZV9rYnBzKQogICAgc3RhdHMgPSBTaGlwU3RhdHMoKQogICAgY2FwdHVyZV9sYXRlc3QgPSB7
fQogICAgd3NzZV9ib2R5X2J5dGVzID0gcmVhZF9ib3VuZGVkX2ludCgiTlRfV1NTRV9CT0RZX0JZ
VEVTIiwgMCwgMCwgNjU1MzYpCiAgICBydW5uaW5nID0gW1RydWVdCgogICAgZGVmIHN0b3Aoc2ln
bnVtLCBmcmFtZSk6CiAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFs
KHNpZ25hbC5TSUdURVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBz
dG9wKQoKICAgIGRlZiByZXF1ZXN0KHBhdGgsIGJvZHksIHRpbWVvdXQpOgogICAgICAgIGxpbWl0
ZXIud2FpdChsZW4oYm9keSkpCiAgICAgICAgcmVxID0gdXJsbGliMi5SZXF1ZXN0KGVuZHBvaW50
ICsgcGF0aCwgZGF0YT1ib2R5LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJz
PXsiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifSkKICAgICAgICB0cnk6CiAgICAg
ICAgICAgIHJlc3AgPSB1cmxsaWIyLnVybG9wZW4ocmVxLCB0aW1lb3V0PXRpbWVvdXQpCiAgICAg
ICAgICAgIG9rID0gKHJlc3AuZ2V0Y29kZSgpID09IDIwMCkKICAgICAgICAgICAgcmVzcC5yZWFk
KCkKICAgICAgICAgICAgcmVzcC5jbG9zZSgpCiAgICAgICAgICAgIHJldHVybiBvawogICAgICAg
IGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgbG9nKCJzaGlwIGZhaWxlZDogJXMi
ICUgZSkKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgZGVmIGZsdXNoKGJhdGNoKToKICAg
ICAgICBpZiBub3QgYmF0Y2g6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgYm9keSA9
IGpzb24uZHVtcHMoeyJub2RlIjogbm9kZSwgImV2ZW50cyI6IGJhdGNofSwKICAgICAgICAgICAg
ICAgICAgICAgICAgICBzZXBhcmF0b3JzPSgiLCIsICI6IikpCiAgICAgICAgIyBweTIgdXJsbGli
MiBhY2NlcHRzIHN0cjsgcHkzIHNoaW0vdGVzdCBuZWVkcyBieXRlcyDigJQgZW5jb2RlIHdoZW4K
ICAgICAgICAjIHRoZSBydW50aW1lIGV4cG9zZXMgaXQgKHB5MiBzdHIgaGFzIG5vIC5lbmNvZGUg
b24gYWxsIGJ1aWxkcywgc28KICAgICAgICAjIGd1YXJkIHdpdGggaGFzYXR0cikKICAgICAgICBp
ZiBoYXNhdHRyKGJvZHksICJlbmNvZGUiKToKICAgICAgICAgICAgYm9keSA9IGJvZHkuZW5jb2Rl
KCJ1dGYtOCIpCiAgICAgICAgaWYgbGVuKGJvZHkpID4gTUFYX1BPU1RfQllURVM6CiAgICAgICAg
ICAgIGxvZygiV0FSTjogcmVmdXNpbmcgb3ZlcnNpemVkIHVwbG9hZCBib2R5ICglZCBieXRlcyki
ICUgbGVuKGJvZHkpKQogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBvayA9IHJlcXVl
c3QoIi9hcGkvaW5nZXN0IiwgYm9keSwgMTApCiAgICAgICAgaWYgb2s6CiAgICAgICAgICAgIHN0
YXRzLmJhdGNoX3N1Y2Nlc3MobGVuKGJhdGNoKSwgbGVuKGJvZHkpKQogICAgICAgICAgICBsb2co
ImZsdXNoZWQgJWQgZXZlbnRzIiAlIGxlbihiYXRjaCkpCiAgICAgICAgcmV0dXJuIG9rCgogICAg
ZGVmIGZsdXNoX3N0YXRzKHNhbXBsZSk6CiAgICAgICAgYm9keSA9IGpzb24uZHVtcHMoc2FtcGxl
LCBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29kZSgidXRmLTgiKQogICAgICAgIGlmIGxlbihi
b2R5KSA+IE1BWF9TVEFUU19CWVRFUzoKICAgICAgICAgICAgc3RhdHMuYWRkKCJzdGF0c19zYW1w
bGVzX2Ryb3BwZWQiKQogICAgICAgICAgICBsb2coIldBUk46IGRyb3BwZWQgb3ZlcnNpemVkIGFn
ZW50IHN0YXRzIHNhbXBsZSIpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGlmIG5vdCByZXF1
ZXN0KCIvYXBpL2FnZW50L3N0YXRzIiwgYm9keSwgNSk6CiAgICAgICAgICAgIHN0YXRzLmFkZCgi
c3RhdHNfc2FtcGxlc19kcm9wcGVkIikKCiAgICAjIC0tLS0gY29uY3VycmVudCBzaGlwcGluZyAt
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAjIGh1YiBpbmdl
c3QgbGF0ZW5jeSAofjMwMC01MDBtcyBwZXIgNDAwLWV2ZW50IFBPU1Qgb3ZlciBXQU4pIG1ha2Vz
CiAgICAjIHNlcXVlbnRpYWwgcG9zdGluZyBhIH4xMDAwIGV2L3MgY2VpbGluZzsgTiBwb3N0ZXIg
dGhyZWFkcyBwb3N0aW5nCiAgICAjIGluZGVwZW5kZW50IGJhdGNoZXMgbXVsdGlwbHkgdGhhdCBi
eSBOVF9TSElQX1RIUkVBRFMKICAgIGNvbmZpZ3VyZV90aHJlYWRfc3RhY2soKQogICAgbnRocmVh
ZHMgPSByZWFkX2JvdW5kZWRfaW50KCJOVF9TSElQX1RIUkVBRFMiLCA0LCAxLCBNQVhfU0hJUF9U
SFJFQURTKQogICAgcSA9IFF1ZXVlLlF1ZXVlKG1heHNpemU9bWluKE1BWF9RVUVVRV9CQVRDSEVT
LCBtYXgoMiwgbnRocmVhZHMgKiAyKSkpCgogICAgZGVmIHBvc3RlcigpOgogICAgICAgIHdoaWxl
IFRydWU6CiAgICAgICAgICAgIGtpbmQsIGl0ZW0gPSBxLmdldCgpCiAgICAgICAgICAgIGlmIGtp
bmQgPT0gInN0YXRzIjoKICAgICAgICAgICAgICAgIHNhbXBsZSA9IHN0YXRzLnRha2Vfc3RhdHMo
KQogICAgICAgICAgICAgICAgaWYgc2FtcGxlIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAg
ICAgIGZsdXNoX3N0YXRzKHNhbXBsZSkKICAgICAgICAgICAgICAgIHEudGFza19kb25lKCkKICAg
ICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHN0YXRzLnF1ZXVlZCgtbGVuKGl0ZW0p
KQogICAgICAgICAgICBpZiBub3QgZmx1c2goaXRlbSk6CiAgICAgICAgICAgICAgICBzdGF0cy5i
YXRjaF9mYWlsdXJlKGxlbihpdGVtKSkKICAgICAgICAgICAgICAgIGxvZygiV0FSTjogSHViIHVu
cmVhY2hhYmxlLCBkcm9wcGVkICVkIGV2ZW50cyAoaW4tbWVtb3J5IGRyb3AsIDAgZGlzayBJL08p
IiAlIGxlbihpdGVtKSkKICAgICAgICAgICAgcS50YXNrX2RvbmUoKQoKICAgIHN0YXJ0ZWRfdGhy
ZWFkcyA9IDAKICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAgICAgICB0cnk6CiAgICAg
ICAgICAgIHQgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1wb3N0ZXIpCiAgICAgICAgICAgIHQu
ZGFlbW9uID0gVHJ1ZQogICAgICAgICAgICB0LnN0YXJ0KCkKICAgICAgICAgICAgc3RhcnRlZF90
aHJlYWRzICs9IDEKICAgICAgICBleGNlcHQgKFJ1bnRpbWVFcnJvciwgdGhyZWFkaW5nLlRocmVh
ZEVycm9yKToKICAgICAgICAgICAgbG9nKCJXQVJOOiB0aHJlYWQgYWxsb2NhdGlvbiBzdG9wcGVk
IGF0ICVkIHBvc3RlcihzKSIgJQogICAgICAgICAgICAgICAgc3RhcnRlZF90aHJlYWRzKQogICAg
ICAgICAgICBicmVhawogICAgaWYgc3RhcnRlZF90aHJlYWRzID09IDA6CiAgICAgICAgcmFpc2Ug
U3lzdGVtRXhpdCgiY2Fubm90IHN0YXJ0IGFueSBzaGlwcGVyIHRocmVhZCIpCiAgICBsb2coImVn
cmVzcyBsaW1pdDogJWQga2JpdC9zLCAlZCBwb3N0ZXIocyksICVkLWJ5dGUgSFRUUCBib2R5IGNh
cCIgJQogICAgICAgIChyYXRlX2ticHMsIHN0YXJ0ZWRfdGhyZWFkcywgTUFYX1BPU1RfQllURVMp
KQoKICAgIGJ1ZiA9IFtdCiAgICBsYXN0X2ZsdXNoID0gdGltZS50aW1lKCkKCiAgICB3aGlsZSBy
dW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAgciwgXywgXyA9IHNlbGVjdC5zZWxl
Y3QoW3N5cy5zdGRpbl0sIFtdLCBbXSwgMS4wKQogICAgICAgIGV4Y2VwdCBzZWxlY3QuZXJyb3Ig
YXMgZToKICAgICAgICAgICAgaWYgZVswXSA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAg
IGNvbnRpbnVlCiAgICAgICAgICAgIGJyZWFrCgogICAgICAgIGlmIHI6CiAgICAgICAgICAgIHRy
eToKICAgICAgICAgICAgICAgIHJhdyA9IHN5cy5zdGRpbi5yZWFkbGluZSgpCiAgICAgICAgICAg
IGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJvcikgYXMgZToKICAgICAgICAgICAgICAgIGlmIGdldGF0
dHIoZSwgJ2Vycm5vJywgTm9uZSkgPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICAgICAg
Y29udGludWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGlmIG5vdCByYXc6CiAg
ICAgICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAgICMgRU9GCiAgICAgICAgICAgIHJh
dyA9IHJhdy5zdHJpcCgpCiAgICAgICAgICAgIGlmIHJhdzoKICAgICAgICAgICAgICAgIHRyeToK
ICAgICAgICAgICAgICAgICAgICBldiA9IGpzb24ubG9hZHMocmF3KQogICAgICAgICAgICAgICAg
ICAgIGlmIGlzaW5zdGFuY2UoZXYsIGRpY3QpOgogICAgICAgICAgICAgICAgICAgICAgICBpZiBl
di5nZXQoIl9udF9pbnRlcm5hbCIpID09ICJjYXB0dXJlX3N0YXRzX3YxIjoKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGNhcHR1cmVfbGF0ZXN0ID0gZXYuZ2V0KCJjYXB0dXJlIikgb3Ige30K
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhbXBsZSA9IHN0YXRzLnNuYXBzaG90KAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhcHR1cmVfbGF0ZXN0LCBub2RlLCAicHl0aG9u
IiwgcmF0ZV9rYnBzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXJ0ZWRfdGhy
ZWFkcywgd3NzZV9ib2R5X2J5dGVzLCBsZW4oYnVmKSwKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICA0MDAwICsgcS5tYXhzaXplICogTUFYX0JBVENIKQogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgaWYgc3RhdHMub2ZmZXJfc3RhdHMoc2FtcGxlKToKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHEu
cHV0X25vd2FpdCgoInN0YXRzIiwgTm9uZSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgZXhjZXB0IFF1ZXVlLkZ1bGw6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
IHN0YXRzLnRha2Vfc3RhdHMoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBz
dGF0cy5hZGQoInN0YXRzX3NhbXBsZXNfZHJvcHBlZCIpCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgICAgICBzdGF0cy5hZGQoImV2ZW50c19p
biIpCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGxlbihidWYpID49IDQwMDA6CiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBkZWwgYnVmWzBdCiAgICAgICAgICAgICAgICAgICAgICAgICAg
ICBzdGF0cy5kcm9wcGVkKCJxdWV1ZV9mdWxsIiwgMSkKICAgICAgICAgICAgICAgICAgICAgICAg
YnVmLmFwcGVuZChldikKICAgICAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAg
ICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICB3aGls
ZSBsZW4oYnVmKSA+PSBNQVhfQkFUQ0ggb3IgKGJ1ZiBhbmQgbm93IC0gbGFzdF9mbHVzaCA+PSBG
TFVTSF9TRUMpOgogICAgICAgICAgICBsYXN0X2ZsdXNoID0gbm93CiAgICAgICAgICAgIGJhdGNo
ID0gdGFrZV9ib3VuZGVkX2JhdGNoKGJ1Ziwgbm9kZSwgc3RhdHMuZHJvcHBlZCkKICAgICAgICAg
ICAgaWYgbm90IGJhdGNoOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgdHJ5Ogog
ICAgICAgICAgICAgICAgcS5wdXRfbm93YWl0KCgiZXZlbnRzIiwgYmF0Y2gpKQogICAgICAgICAg
ICAgICAgc3RhdHMucXVldWVkKGxlbihiYXRjaCkpCiAgICAgICAgICAgIGV4Y2VwdCBRdWV1ZS5G
dWxsOgogICAgICAgICAgICAgICAgc3RhdHMuZHJvcHBlZCgicXVldWVfZnVsbCIsIGxlbihiYXRj
aCkpCiAgICAgICAgICAgICAgICBsb2coIldBUk46IGVncmVzcyBxdWV1ZSBmdWxsLCBkcm9wcGVk
ICVkIGV2ZW50cyIgJSBsZW4oYmF0Y2gpKQoKICAgICMgc3RkaW4gY2xvc2VkIChzbmlmZmVyIHN0
b3BwZWQpIOKAlCBlbnF1ZXVlIHRoZSBmaW5hbCBwYXJ0aWFsIGJhdGNoIGJlZm9yZQogICAgIyB3
YWl0aW5nIGZvciBwb3N0ZXIgdGhyZWFkcy4gUHJldmlvdXNseSBldmVyeSBzaHV0ZG93biBsb3N0
IDEuLjM5OSBldmVudHMuCiAgICBpZiBidWY6CiAgICAgICAgd2hpbGUgYnVmOgogICAgICAgICAg
ICBiYXRjaCA9IHRha2VfYm91bmRlZF9iYXRjaChidWYsIG5vZGUsIHN0YXRzLmRyb3BwZWQpCiAg
ICAgICAgICAgIGlmIG5vdCBiYXRjaDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAg
IHRyeToKICAgICAgICAgICAgICAgIHEucHV0X25vd2FpdCgoImV2ZW50cyIsIGJhdGNoKSkKICAg
ICAgICAgICAgICAgIHN0YXRzLnF1ZXVlZChsZW4oYmF0Y2gpKQogICAgICAgICAgICBleGNlcHQg
UXVldWUuRnVsbDoKICAgICAgICAgICAgICAgIHN0YXRzLmRyb3BwZWQoInF1ZXVlX2Z1bGwiLCBs
ZW4oYmF0Y2gpKQogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiBlZ3Jlc3MgcXVldWUgZnVsbCBh
dCBzaHV0ZG93biwgZHJvcHBlZCAlZCBldmVudHMiICUKICAgICAgICAgICAgICAgICAgICBsZW4o
YmF0Y2gpKQogICAgcS5qb2luKCkKICAgIGxvZygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRpbmcg
b24gZXhpdCkiICUgbGVuKGJ1ZikpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1h
aW4oKQo=
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
I2luY2x1ZGUgPHN0cmluZz4KI2luY2x1ZGUgPHZlY3Rvcj4KI2luY2x1ZGUgPGRlcXVlPgojaW5j
bHVkZSA8aW9zdHJlYW0+CiNpbmNsdWRlIDxzc3RyZWFtPgojaW5jbHVkZSA8Y3N0ZGxpYj4KI2lu
Y2x1ZGUgPGNzdGRpbz4KI2luY2x1ZGUgPGNzdHJpbmc+CiNpbmNsdWRlIDxjZXJybm8+CiNpbmNs
dWRlIDxjdGltZT4KI2luY2x1ZGUgPHB0aHJlYWQuaD4KI2luY2x1ZGUgPGRpcmVudC5oPgojaW5j
bHVkZSA8c3lzL3Jlc291cmNlLmg+CiNpbmNsdWRlIDxzeXMvc2VsZWN0Lmg+CiNpbmNsdWRlIDxz
eXMvdHlwZXMuaD4KI2luY2x1ZGUgPHN5cy93YWl0Lmg+CiNpbmNsdWRlIDxzeXMvdGltZS5oPgoj
aW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxzaWduYWwuaD4KCnN0YXRpYyBjb25zdCBzaXpl
X3QgTUFYX0JBVENIID0gNDAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9RVUVVRSA9IDQwMDA7
CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BPU1RfQllURVMgPSA2NTUzNjsKc3RhdGljIGNvbnN0
IHNpemVfdCBNQVhfU1RBVFNfQllURVMgPSAxNjM4NDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhf
SU5QVVRfTElORSA9IDY1NTM1OwpzdGF0aWMgY29uc3QgaW50IEZMVVNIX1NFQyA9IDU7CgpzdGF0
aWMgdm9sYXRpbGUgc2lnX2F0b21pY190IGdfcnVubmluZyA9IDE7CnN0YXRpYyB2b2xhdGlsZSBz
aWdfYXRvbWljX3QgZ19zdG9wcGVkX2J5X3NpZ25hbCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBnX3No
aXBfcmF0ZV9rYnBzID0gMTAyNDsKc3RhdGljIHVuc2lnbmVkIGdfc3RhdHNfaW50ZXJ2YWxfc2Vj
ID0gMzA7CnN0YXRpYyBkb3VibGUgZ19uZXh0X3NoaXBfc2xvdCA9IDAuMDsKc3RhdGljIGRvdWJs
ZSBnX25leHRfZXZlbnRfYXR0ZW1wdCA9IDAuMDsKc3RhdGljIHB0aHJlYWRfbXV0ZXhfdCBnX2xv
Y2sgPSBQVEhSRUFEX01VVEVYX0lOSVRJQUxJWkVSOwpzdGF0aWMgc3RkOjpkZXF1ZTxzdGQ6OnN0
cmluZz4gZ19xdWV1ZTsKc3RhdGljIGJvb2wgZ19pbnB1dF9kb25lID0gZmFsc2U7CnN0YXRpYyBz
dGQ6OnN0cmluZyBnX2NhcHR1cmVfanNvbiA9ICJ7fSI7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxv
bmcgZ19jYXB0dXJlX2dlbmVyYXRpb24gPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdf
c3RhdHNfZ2VuZXJhdGlvbl9zZW50ID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2lu
cHV0X3RvdGFsID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3Bvc3RlZF90b3RhbCA9
IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19kcm9wcGVkX3RvdGFsID0gMDsKc3RhdGlj
IHVuc2lnbmVkIGxvbmcgbG9uZyBnX292ZXJzaXplZF90b3RhbCA9IDA7CnN0YXRpYyB1bnNpZ25l
ZCBsb25nIGxvbmcgZ19iYXRjaGVzX3RvdGFsID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9u
ZyBnX2JhdGNoZXNfZmFpbGVkX3RvdGFsID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBn
X2J5dGVzX3Bvc3RlZF90b3RhbCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19xdWV1
ZV9kcm9wc190b3RhbCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19odWJfZHJvcHNf
dG90YWwgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfc3RhdHNfZHJvcHNfdG90YWwg
PSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9pbnB1dCA9IDA7CnN0YXRpYyB1
bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X3Bvc3RlZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25n
IGxvbmcgZ19wcmV2X2Ryb3BwZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJl
dl9ieXRlc19wb3N0ZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9xdWV1
ZV9kcm9wcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X2h1Yl9kcm9wcyA9
IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X292ZXJzaXplZCA9IDA7CnN0YXRp
YyB1bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X2JhdGNoZXNfdG90YWwgPSAwOwpzdGF0aWMgdW5z
aWduZWQgbG9uZyBsb25nIGdfcHJldl9iYXRjaGVzX2ZhaWxlZCA9IDA7CnN0YXRpYyB1bnNpZ25l
ZCBsb25nIGxvbmcgZ19xdWV1ZV9oaWdoX3dhdGVyID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcg
bG9uZyBnX3NlcXVlbmNlID0gMDsKc3RhdGljIHVuc2lnbmVkIGdfY29uc2VjdXRpdmVfZmFpbHVy
ZXMgPSAwOwpzdGF0aWMgaW50IGdfbGFzdF9odHRwX3N0YXR1cyA9IDA7CnN0YXRpYyB0aW1lX3Qg
Z19sYXN0X3N1Y2Nlc3NfZXBvY2ggPSAwOwpzdGF0aWMgdGltZV90IGdfc3RhcnRlZF9lcG9jaCA9
IDA7CnN0YXRpYyBkb3VibGUgZ19sYXN0X3N0YXRzX2F0ID0gMC4wOwpzdGF0aWMgZG91YmxlIGdf
bGFzdF9zdGF0c19jcHUgPSAwLjA7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX2VuZHBvaW50OwpzdGF0
aWMgc3RkOjpzdHJpbmcgZ19ub2RlOwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19pbnN0YW5jZV9pZDsK
CnN0YXRpYyB2b2lkIHN0b3Bfc2lnbmFsKGludCkgeyBnX3N0b3BwZWRfYnlfc2lnbmFsID0gMTsg
Z19ydW5uaW5nID0gMDsgfQpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qgc3RkOjpzdHJpbmcgJnMp
IHsgc3RkOjpjZXJyIDw8ICJudC1zaGlwLWNwcDogIiA8PCBzIDw8IHN0ZDo6ZW5kbDsgfQpzdGF0
aWMgc3RkOjpzdHJpbmcgdWxscyh1bnNpZ25lZCBsb25nIGxvbmcgbikgeyBzdGQ6Om9zdHJpbmdz
dHJlYW0gbzsgbyA8PCBuOyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgc3RkOjpzdHJpbmcganNv
bnEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyB4ID0gIlwiIjsKICBmb3Ig
KHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOyArK2kpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9
ICh1bnNpZ25lZCBjaGFyKXNbaV07CiAgICBpZiAoYyA9PSAnXFwnIHx8IGMgPT0gJyInKSB7IHgg
Kz0gJ1xcJzsgeCArPSAoY2hhciljOyB9CiAgICBlbHNlIGlmIChjID09ICdcbicpIHggKz0gIlxc
biI7CiAgICBlbHNlIGlmIChjID09ICdccicpIHggKz0gIlxcciI7CiAgICBlbHNlIGlmIChjID09
ICdcdCcpIHggKz0gIlxcdCI7CiAgICBlbHNlIGlmIChjIDwgMzIpIHggKz0gJz8nOwogICAgZWxz
ZSB4ICs9IChjaGFyKWM7CiAgfQogIHJldHVybiB4ICsgIlwiIjsKfQpzdGF0aWMgc3RkOjpzdHJp
bmcgc2hlbGxxKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICInIjsK
ICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOyArK2kpIHsgaWYgKHNbaV0gPT0gJ1wn
JykgbyArPSAiJ1xcJyciOyBlbHNlIG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIiciOwp9CnN0
YXRpYyBkb3VibGUgd2FsbF9zZWNvbmRzKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2OyBnZXR0aW1l
b2ZkYXkoJnR2LCBOVUxMKTsKICByZXR1cm4gKGRvdWJsZSl0di50dl9zZWMgKyAoZG91YmxlKXR2
LnR2X3VzZWMgLyAxMDAwMDAwLjA7Cn0Kc3RhdGljIHZvaWQgcGFjZV91cGxvYWQoc2l6ZV90IGJ5
dGVzKSB7CiAgZG91YmxlIHJhdGUgPSAoZG91YmxlKWdfc2hpcF9yYXRlX2ticHMgKiAxMDAwLjAg
LyA4LjAsIG5vdyA9IHdhbGxfc2Vjb25kcygpOwogIGlmIChnX25leHRfc2hpcF9zbG90IDwgbm93
IHx8IGdfbmV4dF9zaGlwX3Nsb3QgLSBub3cgPiA2MC4wKSBnX25leHRfc2hpcF9zbG90ID0gbm93
OwogIGRvdWJsZSBzbG90ID0gZ19uZXh0X3NoaXBfc2xvdDsKICBnX25leHRfc2hpcF9zbG90ICs9
IChkb3VibGUpYnl0ZXMgLyByYXRlOwogIHdoaWxlIChnX3J1bm5pbmcgJiYgc2xvdCA+IChub3cg
PSB3YWxsX3NlY29uZHMoKSkpIHsKICAgIGRvdWJsZSBsZWZ0ID0gc2xvdCAtIG5vdzsKICAgIHVz
ZWNvbmRzX3QgZGVsYXkgPSAodXNlY29uZHNfdCkobGVmdCA+IDAuMSA/IDEwMDAwMCA6IGxlZnQg
KiAxMDAwMDAwLjApOwogICAgaWYgKGRlbGF5KSB1c2xlZXAoZGVsYXkpOwogIH0KfQpzdGF0aWMg
c3RkOjpzdHJpbmcganNvbl9hcnJheShjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmEp
IHsKICBzdGQ6OnN0cmluZyBvID0gIlsiOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgYS5zaXpl
KCk7ICsraSkgeyBpZiAoaSkgbyArPSAiLCI7IG8gKz0gYVtpXTsgfQogIHJldHVybiBvICsgIl0i
Owp9CnN0YXRpYyBzaXplX3QgYm91bmRlZF9iYXRjaF9jb3VudChjb25zdCBzdGQ6OmRlcXVlPHN0
ZDo6c3RyaW5nPiAmYnVmLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSkgewogIHNpemVfdCBzaXpl
ID0gc3RkOjpzdHJpbmcoIntcIm5vZGVcIjoiKS5zaXplKCkgKyBqc29ucShub2RlKS5zaXplKCkg
KyBzdGQ6OnN0cmluZygiLFwiZXZlbnRzXCI6W119Iikuc2l6ZSgpOwogIHNpemVfdCBuID0gMCwg
bGltaXQgPSBidWYuc2l6ZSgpIDwgTUFYX0JBVENIID8gYnVmLnNpemUoKSA6IE1BWF9CQVRDSDsK
ICB3aGlsZSAobiA8IGxpbWl0KSB7CiAgICBzaXplX3QgZXh0cmEgPSBidWZbbl0uc2l6ZSgpICsg
KG4gPyAxIDogMCk7CiAgICBpZiAoZXh0cmEgPiBNQVhfUE9TVF9CWVRFUyAtIHNpemUpIGJyZWFr
OwogICAgc2l6ZSArPSBleHRyYTsgKytuOwogIH0KICByZXR1cm4gbjsKfQpzdGF0aWMgaW50IHBv
c3RfanNvbihjb25zdCBzdGQ6OnN0cmluZyAmdXJsLCBjb25zdCBzdGQ6OnN0cmluZyAmYm9keSwg
dW5zaWduZWQgdGltZW91dF9zZWMpIHsKICBpZiAoYm9keS5zaXplKCkgPiBNQVhfUE9TVF9CWVRF
UykgcmV0dXJuIDA7CiAgcGFjZV91cGxvYWQoYm9keS5zaXplKCkpOwogIHN0ZDo6c3RyaW5nIGNt
ZCA9ICJjdXJsIC1zU2YgLS1tYXgtdGltZSAiICsgdWxscyh0aW1lb3V0X3NlYykgKwogICAgIiAt
LWxpbWl0LXJhdGUgIiArIHVsbHMoKHVuc2lnbmVkIGxvbmcgbG9uZylnX3NoaXBfcmF0ZV9rYnBz
ICogMTAwMFVMTCAvIDhVTEwpICsKICAgICIgLW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6
IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1iaW5hcnkgQC0gIiArIHNoZWxscSh1cmwpOwogIEZJ
TEUgKmZwID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7CiAgaWYgKCFmcCkgcmV0dXJuIDA7CiAg
c2l6ZV90IHdyaXR0ZW4gPSBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7
CiAgaW50IHJjID0gcGNsb3NlKGZwKTsKICBpZiAod3JpdHRlbiAhPSBib2R5LnNpemUoKSB8fCAh
V0lGRVhJVEVEKHJjKSB8fCBXRVhJVFNUQVRVUyhyYykgIT0gMCkgcmV0dXJuIDA7CiAgLyogY3Vy
bCAtZiBtYXBzIEhUVFAgNHh4LzV4eCB0byBmYWlsdXJlLiBFeGFjdCBzdWNjZXNzIHN0YXR1cyBp
cyBub3QgZXhwb3NlZAogICAgIGJ5IHRoaXMgd3JpdGUtb25seSBwaXBlLCBzbyB0aGUgc3RhYmxl
IHYxIHN1Y2Nlc3MgdmFsdWUgaXMgMjAwLiAqLwogIHJldHVybiAyMDA7Cn0Kc3RhdGljIHVuc2ln
bmVkIGxvbmcgbG9uZyBqc29uX3VpbnQoY29uc3Qgc3RkOjpzdHJpbmcgJnMsIGNvbnN0IGNoYXIg
KmtleSkgewogIHN0ZDo6c3RyaW5nIG5lZWRsZSA9IHN0ZDo6c3RyaW5nKCJcIiIpICsga2V5ICsg
IlwiOiI7CiAgc2l6ZV90IHAgPSBzLmZpbmQobmVlZGxlKTsKICBpZiAocCA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcykgcmV0dXJuIDA7CiAgcCArPSBuZWVkbGUuc2l6ZSgpOwogIHdoaWxlIChwIDwgcy5z
aXplKCkgJiYgKHNbcF0gPT0gJyAnIHx8IHNbcF0gPT0gJ1x0JykpICsrcDsKICB1bnNpZ25lZCBs
b25nIGxvbmcgdiA9IDA7CiAgd2hpbGUgKHAgPCBzLnNpemUoKSAmJiBzW3BdID49ICcwJyAmJiBz
W3BdIDw9ICc5JykgeyB2ID0gdiAqIDEwVUxMICsgKHVuc2lnbmVkKShzW3BdIC0gJzAnKTsgKytw
OyB9CiAgcmV0dXJuIHY7Cn0Kc3RhdGljIHVuc2lnbmVkIHRocmVhZF9jb3VudCgpIHsKICBESVIg
KmQgPSBvcGVuZGlyKCIvcHJvYy9zZWxmL3Rhc2siKTsgaWYgKCFkKSByZXR1cm4gMDsKICB1bnNp
Z25lZCBuID0gMDsgc3RydWN0IGRpcmVudCAqZTsKICB3aGlsZSAoKGUgPSByZWFkZGlyKGQpKSAh
PSBOVUxMKSBpZiAoZS0+ZF9uYW1lWzBdID49ICcwJyAmJiBlLT5kX25hbWVbMF0gPD0gJzknKSAr
K247CiAgY2xvc2VkaXIoZCk7IHJldHVybiBuOwp9CnN0YXRpYyB2b2lkIHByb2Nlc3NfbWVtb3J5
KHVuc2lnbmVkIGxvbmcgbG9uZyAqcnNzLCB1bnNpZ25lZCBsb25nIGxvbmcgKnZpcnQpIHsKICBG
SUxFICpmID0gZm9wZW4oIi9wcm9jL3NlbGYvc3RhdG0iLCAiciIpOyB1bnNpZ25lZCBsb25nIHBh
Z2VzID0gMCwgcmVzaWRlbnQgPSAwOwogIGlmIChmKSB7IGlmIChmc2NhbmYoZiwgIiVsdSAlbHUi
LCAmcGFnZXMsICZyZXNpZGVudCkgIT0gMikgcGFnZXMgPSByZXNpZGVudCA9IDA7IGZjbG9zZShm
KTsgfQogIHVuc2lnbmVkIGxvbmcgbG9uZyBwYWdlID0gKHVuc2lnbmVkIGxvbmcgbG9uZylzeXNj
b25mKF9TQ19QQUdFU0laRSk7CiAgKnJzcyA9ICh1bnNpZ25lZCBsb25nIGxvbmcpcmVzaWRlbnQg
KiBwYWdlOyAqdmlydCA9ICh1bnNpZ25lZCBsb25nIGxvbmcpcGFnZXMgKiBwYWdlOwp9CnN0YXRp
YyB1bnNpZ25lZCBvcGVuX2ZkX2NvdW50KCkgewogIERJUiAqZCA9IG9wZW5kaXIoIi9wcm9jL3Nl
bGYvZmQiKTsgaWYgKCFkKSByZXR1cm4gMDsKICB1bnNpZ25lZCBuID0gMDsgc3RydWN0IGRpcmVu
dCAqZTsKICB3aGlsZSAoKGUgPSByZWFkZGlyKGQpKSAhPSBOVUxMKSBpZiAoZS0+ZF9uYW1lWzBd
ID49ICcwJyAmJiBlLT5kX25hbWVbMF0gPD0gJzknKSArK247CiAgY2xvc2VkaXIoZCk7IHJldHVy
biBuOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBhbGxvd2VkX2NwdSgpIHsKICBGSUxFICpmID0gZm9w
ZW4oIi9wcm9jL3NlbGYvc3RhdHVzIiwgInIiKTsgaWYgKCFmKSByZXR1cm4gIjAiOwogIGNoYXIg
bGluZVs1MTJdOyBzdGQ6OnN0cmluZyByZXN1bHQgPSAiMCI7CiAgd2hpbGUgKGZnZXRzKGxpbmUs
IHNpemVvZihsaW5lKSwgZikpIHsKICAgIGlmIChzdHJuY21wKGxpbmUsICJDcHVzX2FsbG93ZWRf
bGlzdDoiLCAxOCkgPT0gMCkgewogICAgICBjaGFyICpwID0gbGluZSArIDE4OyB3aGlsZSAoKnAg
PT0gJyAnIHx8ICpwID09ICdcdCcpICsrcDsKICAgICAgY2hhciAqZW5kID0gcCArIHN0cmxlbihw
KTsgd2hpbGUgKGVuZCA+IHAgJiYgKGVuZFstMV0gPT0gJ1xuJyB8fCBlbmRbLTFdID09ICdccicp
KSAtLWVuZDsKICAgICAgcmVzdWx0LmFzc2lnbihwLCBlbmQgLSBwKTsgYnJlYWs7CiAgICB9CiAg
fQogIGZjbG9zZShmKTsgcmV0dXJuIHJlc3VsdDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgc2hpcHBp
bmdfc3RhdHNfYm9keShjb25zdCBzdGQ6OnN0cmluZyAmY2FwdHVyZSkgewogIGRvdWJsZSBub3df
d2FsbCA9IHdhbGxfc2Vjb25kcygpLCBlbGFwc2VkID0gbm93X3dhbGwgLSBnX2xhc3Rfc3RhdHNf
YXQ7CiAgaWYgKGVsYXBzZWQgPCAwLjAwMSkgZWxhcHNlZCA9IDAuMDAxOwogIHVuc2lnbmVkIGxv
bmcgbG9uZyBub3cgPSAodW5zaWduZWQgbG9uZyBsb25nKW5vd193YWxsLCBpbiwgcG9zdGVkLCBk
cm9wcGVkLCBxaHcsIHFkZXB0aCwgc2VxOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBieXRlc19wb3N0
ZWQsIHF1ZXVlX2Ryb3BzLCBodWJfZHJvcHMsIG92ZXJzaXplZCwgYmF0Y2hlcywgYmF0Y2hlc19m
YWlsZWQsIHN0YXRzX2Ryb3BzOwogIHVuc2lnbmVkIGZhaWx1cmVzLCBzdGF0dXM7IHRpbWVfdCBz
dWNjZXNzOwogIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19sb2NrKTsKICBpbiA9IGdfaW5wdXRfdG90
YWw7IHBvc3RlZCA9IGdfcG9zdGVkX3RvdGFsOwogIGRyb3BwZWQgPSBnX2Ryb3BwZWRfdG90YWw7
IHFodyA9IGdfcXVldWVfaGlnaF93YXRlcjsgcWRlcHRoID0gZ19xdWV1ZS5zaXplKCk7CiAgYnl0
ZXNfcG9zdGVkID0gZ19ieXRlc19wb3N0ZWRfdG90YWw7IHF1ZXVlX2Ryb3BzID0gZ19xdWV1ZV9k
cm9wc190b3RhbDsKICBodWJfZHJvcHMgPSBnX2h1Yl9kcm9wc190b3RhbDsgb3ZlcnNpemVkID0g
Z19vdmVyc2l6ZWRfdG90YWw7CiAgYmF0Y2hlcyA9IGdfYmF0Y2hlc190b3RhbDsgYmF0Y2hlc19m
YWlsZWQgPSBnX2JhdGNoZXNfZmFpbGVkX3RvdGFsOyBzdGF0c19kcm9wcyA9IGdfc3RhdHNfZHJv
cHNfdG90YWw7CiAgZmFpbHVyZXMgPSBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzOyBzdGF0dXMgPSAo
dW5zaWduZWQpZ19sYXN0X2h0dHBfc3RhdHVzOwogIHN1Y2Nlc3MgPSBnX2xhc3Rfc3VjY2Vzc19l
cG9jaDsgc2VxID0gKytnX3NlcXVlbmNlOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBpbl9kZWx0YSA9
IGluIC0gZ19wcmV2X2lucHV0LCBwb3N0X2RlbHRhID0gcG9zdGVkIC0gZ19wcmV2X3Bvc3RlZDsK
ICB1bnNpZ25lZCBsb25nIGxvbmcgZHJvcF9kZWx0YSA9IGRyb3BwZWQgLSBnX3ByZXZfZHJvcHBl
ZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgYnl0ZXNfZGVsdGEgPSBieXRlc19wb3N0ZWQgLSBnX3By
ZXZfYnl0ZXNfcG9zdGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBxdWV1ZV9kZWx0YSA9IHF1ZXVl
X2Ryb3BzIC0gZ19wcmV2X3F1ZXVlX2Ryb3BzOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBodWJfZGVs
dGEgPSBodWJfZHJvcHMgLSBnX3ByZXZfaHViX2Ryb3BzOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBv
dmVyc2l6ZWRfZGVsdGEgPSBvdmVyc2l6ZWQgLSBnX3ByZXZfb3ZlcnNpemVkOwogIHVuc2lnbmVk
IGxvbmcgbG9uZyBiYXRjaGVzX2RlbHRhID0gYmF0Y2hlcyAtIGdfcHJldl9iYXRjaGVzX3RvdGFs
OwogIHVuc2lnbmVkIGxvbmcgbG9uZyBiYXRjaGVzX2ZhaWxlZF9kZWx0YSA9IGJhdGNoZXNfZmFp
bGVkIC0gZ19wcmV2X2JhdGNoZXNfZmFpbGVkOwogIGdfcHJldl9pbnB1dCA9IGluOyBnX3ByZXZf
cG9zdGVkID0gcG9zdGVkOyBnX3ByZXZfZHJvcHBlZCA9IGRyb3BwZWQ7CiAgZ19wcmV2X2J5dGVz
X3Bvc3RlZCA9IGJ5dGVzX3Bvc3RlZDsgZ19wcmV2X3F1ZXVlX2Ryb3BzID0gcXVldWVfZHJvcHM7
CiAgZ19wcmV2X2h1Yl9kcm9wcyA9IGh1Yl9kcm9wczsgZ19wcmV2X292ZXJzaXplZCA9IG92ZXJz
aXplZDsKICBnX3ByZXZfYmF0Y2hlc190b3RhbCA9IGJhdGNoZXM7IGdfcHJldl9iYXRjaGVzX2Zh
aWxlZCA9IGJhdGNoZXNfZmFpbGVkOwogIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX2xvY2spOwog
IHN0cnVjdCBydXNhZ2UgdXNhZ2U7IG1lbXNldCgmdXNhZ2UsIDAsIHNpemVvZih1c2FnZSkpOyBn
ZXRydXNhZ2UoUlVTQUdFX1NFTEYsICZ1c2FnZSk7CiAgZG91YmxlIGNwdSA9IHVzYWdlLnJ1X3V0
aW1lLnR2X3NlYyArIHVzYWdlLnJ1X3V0aW1lLnR2X3VzZWMgLyAxMDAwMDAwLjAgKyB1c2FnZS5y
dV9zdGltZS50dl9zZWMgKyB1c2FnZS5ydV9zdGltZS50dl91c2VjIC8gMTAwMDAwMC4wOwogIGRv
dWJsZSBjcHVfcGN0ID0gMTAwLjAgKiAoY3B1IC0gZ19sYXN0X3N0YXRzX2NwdSkgLyBlbGFwc2Vk
OyBpZiAoY3B1X3BjdCA8IDApIGNwdV9wY3QgPSAwOwogIHVuc2lnbmVkIGxvbmcgbG9uZyByc3Mg
PSAwLCB2aXJ0ID0gMDsgcHJvY2Vzc19tZW1vcnkoJnJzcywgJnZpcnQpOwogIHN0ZDo6c3RyaW5n
IHJlYXNvbnM7CiAgaWYgKGpzb25fdWludChjYXB0dXJlLCAia2VybmVsX2Ryb3BzX2RlbHRhIikp
IHJlYXNvbnMgKz0gIlwia2VybmVsX2Ryb3BcIiI7CiAgaWYgKGRyb3BfZGVsdGEpIHsgaWYgKCFy
ZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcInNoaXBfZHJvcFwi
IjsgfQogIGlmIChodWJfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0g
IiwiOyByZWFzb25zICs9ICJcImh1Yl91bnJlYWNoYWJsZVwiIjsgfQogIGlmIChxdWV1ZV9kZWx0
YSB8fCBqc29uX3VpbnQoY2FwdHVyZSwgIm91dHB1dF9waXBlX2Ryb3BzX2RlbHRhIikpIHsgaWYg
KCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcInF1ZXVlX3By
ZXNzdXJlXCIiOyB9CiAgc3RkOjpvc3RyaW5nc3RyZWFtIG87CiAgbyA8PCAie1wic2NoZW1hX3Zl
cnNpb25cIjoxLFwibm9kZVwiOiIgPDwganNvbnEoZ19ub2RlKQogICAgPDwgIixcInR5cGVcIjpc
ImFnZW50X3N0YXRzXCIsXCJpbnN0YW5jZV9pZFwiOiIgPDwganNvbnEoZ19pbnN0YW5jZV9pZCkK
ICAgIDw8ICIsXCJzZXF1ZW5jZVwiOiIgPDwgc2VxIDw8ICIsXCJvYnNlcnZlZF9hdFwiOiIgPDwg
bm93CiAgICA8PCAiLFwid2luZG93X3NlY29uZHNcIjoiIDw8IGVsYXBzZWQKICAgIDw8ICIsXCJt
b2RlXCI6XCJjcHBcIixcInN0YXR1c1wiOiIgPDwgKHJlYXNvbnMuZW1wdHkoKSA/ICJcIm9rXCIi
IDogIlwiZGVncmFkZWRcIiIpCiAgICA8PCAiLFwicmVhc29uc1wiOlsiIDw8IHJlYXNvbnMgPDwg
Il0sXCJjYXB0dXJlXCI6IiA8PCBjYXB0dXJlCiAgICA8PCAiLFwic2hpcHBpbmdcIjp7XCJldmVu
dHNfaW5fdG90YWxcIjoiIDw8IGluCiAgICA8PCAiLFwiZXZlbnRzX2luX2RlbHRhXCI6IiA8PCBp
bl9kZWx0YQogICAgPDwgIixcImV2ZW50c19wdXNoZWRfdG90YWxcIjoiIDw8IHBvc3RlZAogICAg
PDwgIixcImV2ZW50c19wdXNoZWRfZGVsdGFcIjoiIDw8IHBvc3RfZGVsdGEKICAgIDw8ICIsXCJl
dmVudHNfZHJvcHBlZF90b3RhbFwiOiIgPDwgZHJvcHBlZAogICAgPDwgIixcImV2ZW50c19kcm9w
cGVkX2RlbHRhXCI6IiA8PCBkcm9wX2RlbHRhCiAgICA8PCAiLFwiZHJvcF9jYXVzZXNcIjp7XCJx
dWV1ZV9mdWxsX3RvdGFsXCI6IiA8PCBxdWV1ZV9kcm9wcyA8PCAiLFwicXVldWVfZnVsbF9kZWx0
YVwiOiIgPDwgcXVldWVfZGVsdGEKICAgIDw8ICIsXCJodWJfZmFpbHVyZV90b3RhbFwiOiIgPDwg
aHViX2Ryb3BzIDw8ICIsXCJodWJfZmFpbHVyZV9kZWx0YVwiOiIgPDwgaHViX2RlbHRhCiAgICA8
PCAiLFwib3ZlcnNpemVkX3RvdGFsXCI6IiA8PCBvdmVyc2l6ZWQgPDwgIixcIm92ZXJzaXplZF9k
ZWx0YVwiOiIgPDwgb3ZlcnNpemVkX2RlbHRhIDw8ICJ9IgogICAgPDwgIixcImJhdGNoZXNfcHVz
aGVkX3RvdGFsXCI6IiA8PCBiYXRjaGVzIDw8ICIsXCJiYXRjaGVzX3B1c2hlZF9kZWx0YVwiOiIg
PDwgYmF0Y2hlc19kZWx0YQogICAgPDwgIixcImJhdGNoZXNfZmFpbGVkX3RvdGFsXCI6IiA8PCBi
YXRjaGVzX2ZhaWxlZCA8PCAiLFwiYmF0Y2hlc19mYWlsZWRfZGVsdGFcIjoiIDw8IGJhdGNoZXNf
ZmFpbGVkX2RlbHRhCiAgICA8PCAiLFwiYnl0ZXNfcHVzaGVkX3RvdGFsXCI6IiA8PCBieXRlc19w
b3N0ZWQgPDwgIixcImJ5dGVzX3B1c2hlZF9kZWx0YVwiOiIgPDwgYnl0ZXNfZGVsdGEKICAgIDw8
ICIsXCJwdXNoX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCAoKGRvdWJsZSlwb3N0X2RlbHRhIC8g
ZWxhcHNlZCkKICAgIDw8ICIsXCJwdXNoX2ticHNcIjoiIDw8ICg4LjAgKiBieXRlc19kZWx0YSAv
ICgxMDAwLjAgKiBlbGFwc2VkKSkKICAgIDw8ICIsXCJkcm9wX2V2ZW50c19wZXJfc2Vjb25kXCI6
IiA8PCAoKGRvdWJsZSlkcm9wX2RlbHRhIC8gZWxhcHNlZCkKICAgIDw8ICIsXCJkcm9wX3BlcmNl
bnRcIjoiIDw8ICgxMDAuMCAqIGRyb3BfZGVsdGEgLyAoaW5fZGVsdGEgPyBpbl9kZWx0YSA6IDEp
KQogICAgPDwgIixcInF1ZXVlX2RlcHRoX2V2ZW50c1wiOiIgPDwgcWRlcHRoIDw8ICIsXCJxdWV1
ZV9oaWdoX3dhdGVyX2V2ZW50c1wiOiIgPDwgcWh3CiAgICA8PCAiLFwicXVldWVfY2FwYWNpdHlf
ZXZlbnRzXCI6IiA8PCBNQVhfUVVFVUUKICAgIDw8ICIsXCJjb25zZWN1dGl2ZV9mYWlsdXJlc1wi
OiIgPDwgZmFpbHVyZXMKICAgIDw8ICIsXCJsYXN0X3B1c2hfaHR0cF9zdGF0dXNcIjoiIDw8IHN0
YXR1cwogICAgPDwgIixcImxhc3Rfc3VjY2Vzc19hdFwiOiIgPDwgKHVuc2lnbmVkIGxvbmcgbG9u
ZylzdWNjZXNzCiAgICA8PCAiLFwic3RhdHNfc2FtcGxlc19kcm9wcGVkX3RvdGFsXCI6IiA8PCBz
dGF0c19kcm9wcwogICAgPDwgIn0sXCJyZXNvdXJjZXNcIjp7XCJjcHVfdXNlcl9zZWNvbmRzXCI6
IiA8PCAodXNhZ2UucnVfdXRpbWUudHZfc2VjICsgdXNhZ2UucnVfdXRpbWUudHZfdXNlYyAvIDEw
MDAwMDAuMCkKICAgIDw8ICIsXCJjcHVfc3lzdGVtX3NlY29uZHNcIjoiIDw8ICh1c2FnZS5ydV9z
dGltZS50dl9zZWMgKyB1c2FnZS5ydV9zdGltZS50dl91c2VjIC8gMTAwMDAwMC4wKQogICAgPDwg
IixcImNwdV9wZXJjZW50X29uZV9jb3JlXCI6IiA8PCBjcHVfcGN0IDw8ICIsXCJyc3NfYnl0ZXNc
IjoiIDw8IHJzcwogICAgPDwgIixcInZpcnR1YWxfYnl0ZXNcIjoiIDw8IHZpcnQgPDwgIixcIm9w
ZW5fZmRzXCI6IiA8PCBvcGVuX2ZkX2NvdW50KCkgPDwgIixcInRocmVhZHNcIjoiIDw8IHRocmVh
ZF9jb3VudCgpCiAgICA8PCAifSxcImxpbWl0c1wiOntcImNwdV9jb3JlXCI6IiA8PCBqc29ucShh
bGxvd2VkX2NwdSgpKSA8PCAiLFwiYWRkcmVzc19zcGFjZV9ieXRlc1wiOjI2ODQzNTQ1NiIKICAg
IDw8ICIsXCJzaGlwX3JhdGVfa2Jwc1wiOiIgPDwgZ19zaGlwX3JhdGVfa2JwcyA8PCAiLFwiaHR0
cF9ib2R5X21heF9ieXRlc1wiOiIgPDwgTUFYX1BPU1RfQllURVMgPDwgIixcInNoaXBfdGhyZWFk
c19tYXhcIjoxIgogICAgPDwgIixcIndzc2VfYm9keV9ieXRlc1wiOiIgPDwganNvbl91aW50KGNh
cHR1cmUsICJ3c3NlX2JvZHlfYnl0ZXMiKQogICAgPDwgIn19IjsKICBnX2xhc3Rfc3RhdHNfYXQg
PSBub3dfd2FsbDsgZ19sYXN0X3N0YXRzX2NwdSA9IGNwdTsKICByZXR1cm4gby5zdHIoKTsKfQpz
dGF0aWMgYm9vbCBwYXJzZV9jYXB0dXJlX3N0YXRzKGNvbnN0IHN0ZDo6c3RyaW5nICZsaW5lLCBz
dGQ6OnN0cmluZyAqY2FwdHVyZSkgewogIGlmIChsaW5lLnNpemUoKSA+IE1BWF9TVEFUU19CWVRF
UyB8fCBsaW5lLmZpbmQoIlwiX250X2ludGVybmFsXCI6XCJjYXB0dXJlX3N0YXRzX3YxXCIiKSA9
PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBwID0gbGluZS5maW5k
KCJcImNhcHR1cmVcIjoiKTsgaWYgKHAgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiBmYWxz
ZTsKICBwICs9IHN0cmxlbigiXCJjYXB0dXJlXCI6Iik7CiAgc2l6ZV90IHN0YXJ0ID0gbGluZS5m
aW5kKCd7JywgcCk7IGlmIChzdGFydCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIGZhbHNl
OwogIGludCBkZXB0aCA9IDA7IGJvb2wgcXVvdGVkID0gZmFsc2UsIGVzY2FwZWQgPSBmYWxzZTsK
ICBmb3IgKHNpemVfdCBpID0gc3RhcnQ7IGkgPCBsaW5lLnNpemUoKTsgKytpKSB7CiAgICBjaGFy
IGMgPSBsaW5lW2ldOwogICAgaWYgKHF1b3RlZCkgeyBpZiAoZXNjYXBlZCkgZXNjYXBlZCA9IGZh
bHNlOyBlbHNlIGlmIChjID09ICdcXCcpIGVzY2FwZWQgPSB0cnVlOyBlbHNlIGlmIChjID09ICci
JykgcXVvdGVkID0gZmFsc2U7IGNvbnRpbnVlOyB9CiAgICBpZiAoYyA9PSAnIicpIHF1b3RlZCA9
IHRydWU7CiAgICBlbHNlIGlmIChjID09ICd7JykgKytkZXB0aDsKICAgIGVsc2UgaWYgKGMgPT0g
J30nICYmIC0tZGVwdGggPT0gMCkgeyAqY2FwdHVyZSA9IGxpbmUuc3Vic3RyKHN0YXJ0LCBpIC0g
c3RhcnQgKyAxKTsgcmV0dXJuIHRydWU7IH0KICB9CiAgcmV0dXJuIGZhbHNlOwp9CnN0YXRpYyB2
b2lkICp1cGxvYWRlcl9tYWluKHZvaWQgKikgewogIHRpbWVfdCBsYXN0X2ZsdXNoID0gdGltZShO
VUxMKTsKICB3aGlsZSAodHJ1ZSkgewogICAgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNo
OwogICAgc3RkOjpzdHJpbmcgY2FwdHVyZTsgdW5zaWduZWQgbG9uZyBsb25nIGNhcHR1cmVfZ2Vu
ID0gMDsKICAgIGJvb2wgZG9uZSwgZW1wdHk7CiAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfbG9j
ayk7CiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICAgIGJvb2wgcmV0cnlfcmVhZHkgPSB3
YWxsX3NlY29uZHMoKSA+PSBnX25leHRfZXZlbnRfYXR0ZW1wdDsKICAgIGJvb2wgZmx1c2ggPSBy
ZXRyeV9yZWFkeSAmJiAoZ19xdWV1ZS5zaXplKCkgPj0gTUFYX0JBVENIIHx8IChub3cgLSBsYXN0
X2ZsdXNoID49IEZMVVNIX1NFQykgfHwgZ19pbnB1dF9kb25lIHx8ICFnX3J1bm5pbmcpOwogICAg
aWYgKGZsdXNoICYmICFnX3F1ZXVlLmVtcHR5KCkpIHsKICAgICAgc2l6ZV90IG4gPSBib3VuZGVk
X2JhdGNoX2NvdW50KGdfcXVldWUsIGdfbm9kZSk7CiAgICAgIGlmICghbikgeyBnX3F1ZXVlLnBv
cF9mcm9udCgpOyArK2dfZHJvcHBlZF90b3RhbDsgKytnX292ZXJzaXplZF90b3RhbDsgfQogICAg
ICBlbHNlIHsgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBuOyArK2kpIHsgYmF0Y2gucHVzaF9iYWNr
KGdfcXVldWUuZnJvbnQoKSk7IGdfcXVldWUucG9wX2Zyb250KCk7IH0gfQogICAgICBsYXN0X2Zs
dXNoID0gbm93OwogICAgfQogICAgaWYgKGdfY2FwdHVyZV9nZW5lcmF0aW9uICE9IGdfc3RhdHNf
Z2VuZXJhdGlvbl9zZW50KSB7IGNhcHR1cmUgPSBnX2NhcHR1cmVfanNvbjsgY2FwdHVyZV9nZW4g
PSBnX2NhcHR1cmVfZ2VuZXJhdGlvbjsgfQogICAgZG9uZSA9IGdfaW5wdXRfZG9uZSB8fCAhZ19y
dW5uaW5nOyBlbXB0eSA9IGdfcXVldWUuZW1wdHkoKTsKICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2Nr
KCZnX2xvY2spOwoKICAgIGlmICghYmF0Y2guZW1wdHkoKSkgewogICAgICBzdGQ6OnN0cmluZyBi
b2R5ID0gIntcIm5vZGVcIjoiICsganNvbnEoZ19ub2RlKSArICIsXCJldmVudHNcIjoiICsganNv
bl9hcnJheShiYXRjaCkgKyAifSI7CiAgICAgIGludCBzdGF0dXMgPSBwb3N0X2pzb24oZ19lbmRw
b2ludCArICIvYXBpL2luZ2VzdCIsIGJvZHksIDEwKTsKICAgICAgcHRocmVhZF9tdXRleF9sb2Nr
KCZnX2xvY2spOwogICAgICBpZiAoc3RhdHVzKSB7IGdfcG9zdGVkX3RvdGFsICs9IGJhdGNoLnNp
emUoKTsgZ19ieXRlc19wb3N0ZWRfdG90YWwgKz0gYm9keS5zaXplKCk7ICsrZ19iYXRjaGVzX3Rv
dGFsOyBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzID0gMDsgZ19uZXh0X2V2ZW50X2F0dGVtcHQgPSAw
LjA7IGdfbGFzdF9odHRwX3N0YXR1cyA9IHN0YXR1czsgZ19sYXN0X3N1Y2Nlc3NfZXBvY2ggPSB0
aW1lKE5VTEwpOyB9CiAgICAgIGVsc2UgewogICAgICAgIGdfaHViX2Ryb3BzX3RvdGFsICs9IGJh
dGNoLnNpemUoKTsgZ19kcm9wcGVkX3RvdGFsICs9IGJhdGNoLnNpemUoKTsgKytnX2JhdGNoZXNf
ZmFpbGVkX3RvdGFsOwogICAgICAgIHVuc2lnbmVkIHNoaWZ0ID0gZ19jb25zZWN1dGl2ZV9mYWls
dXJlcyA8IDYgPyBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzIDogNjsKICAgICAgICArK2dfY29uc2Vj
dXRpdmVfZmFpbHVyZXM7IGdfbmV4dF9ldmVudF9hdHRlbXB0ID0gd2FsbF9zZWNvbmRzKCkgKyAo
ZG91YmxlKSgxVSA8PCBzaGlmdCk7IGdfbGFzdF9odHRwX3N0YXR1cyA9IDA7CiAgICAgIH0KICAg
ICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfbG9jayk7CiAgICB9CiAgICBpZiAoIWNhcHR1cmUu
ZW1wdHkoKSkgewogICAgICBzdGQ6OnN0cmluZyBib2R5ID0gc2hpcHBpbmdfc3RhdHNfYm9keShj
YXB0dXJlKTsKICAgICAgaW50IHN0YXR1cyA9IGJvZHkuc2l6ZSgpIDw9IE1BWF9TVEFUU19CWVRF
UyA/IHBvc3RfanNvbihnX2VuZHBvaW50ICsgIi9hcGkvYWdlbnQvc3RhdHMiLCBib2R5LCAyKSA6
IDA7CiAgICAgIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19sb2NrKTsKICAgICAgZ19zdGF0c19nZW5l
cmF0aW9uX3NlbnQgPSBjYXB0dXJlX2dlbjsKICAgICAgaWYgKCFzdGF0dXMpICsrZ19zdGF0c19k
cm9wc190b3RhbDsKICAgICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfbG9jayk7CiAgICB9CiAg
ICBpZiAoZG9uZSAmJiBlbXB0eSAmJiBiYXRjaC5lbXB0eSgpKSBicmVhazsKICAgIHVzbGVlcCgx
MDAwMDApOwogIH0KICByZXR1cm4gTlVMTDsKfQppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqKmFy
Z3YpIHsKICBib29sIHN0YXRzX2ZpeHR1cmUgPSBmYWxzZTsKICBjb25zdCBjaGFyICpyYXRlX2Vu
diA9IGdldGVudigiTlRfU0hJUF9SQVRFX0tCUFMiKTsKICBjb25zdCBjaGFyICpzdGF0c19lbnYg
PSBnZXRlbnYoIk5UX1NUQVRTX0lOVEVSVkFMX1NFQyIpOwogIGlmIChyYXRlX2VudiAmJiAqcmF0
ZV9lbnYpIGdfc2hpcF9yYXRlX2ticHMgPSAodW5zaWduZWQpYXRvaShyYXRlX2Vudik7CiAgaWYg
KHN0YXRzX2VudiAmJiAqc3RhdHNfZW52KSBnX3N0YXRzX2ludGVydmFsX3NlYyA9ICh1bnNpZ25l
ZClhdG9pKHN0YXRzX2Vudik7CiAgZm9yIChpbnQgaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAg
IHN0ZDo6c3RyaW5nIGEgPSBhcmd2W2ldOwogICAgaWYgKGEgPT0gIi0tZW5kcG9pbnQiICYmIGkg
KyAxIDwgYXJnYykgZ19lbmRwb2ludCA9IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKGEgPT0gIi0t
c2hpcC1yYXRlLWticHMiICYmIGkgKyAxIDwgYXJnYykgZ19zaGlwX3JhdGVfa2JwcyA9ICh1bnNp
Z25lZClhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmIChhID09ICItLXN0YXRzLWludGVydmFs
LXNlYyIgJiYgaSArIDEgPCBhcmdjKSBnX3N0YXRzX2ludGVydmFsX3NlYyA9ICh1bnNpZ25lZClh
dG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmIChhID09ICItLXNwb29sIiAmJiBpICsgMSA8IGFy
Z2MpICsraTsKICAgIGVsc2UgaWYgKGEgPT0gIi0tc3RhdHMtZml4dHVyZSIpIHN0YXRzX2ZpeHR1
cmUgPSB0cnVlOwogICAgZWxzZSBpZiAoYSA9PSAiLWgiIHx8IGEgPT0gIi0taGVscCIpIHsgc3Rk
Ojpjb3V0IDw8ICJ1c2FnZTogbnQtc2hpcC1jcHAgLS1lbmRwb2ludCBVUkwgWy0tc2hpcC1yYXRl
LWticHMgNjQuLjEwMDAwXSBbLS1zdGF0cy1pbnRlcnZhbC1zZWMgMTAuLjM2MDBdXG4iOyByZXR1
cm4gMDsgfQogICAgZWxzZSB7IHN0ZDo6Y2VyciA8PCAidW5rbm93biBhcmc6ICIgPDwgYSA8PCAi
XG4iOyByZXR1cm4gMjsgfQogIH0KICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpICYmICFzdGF0c19m
aXh0dXJlKSB7IHN0ZDo6Y2VyciA8PCAiLS1lbmRwb2ludCByZXF1aXJlZFxuIjsgcmV0dXJuIDI7
IH0KICBpZiAoZ19zaGlwX3JhdGVfa2JwcyA8IDY0IHx8IGdfc2hpcF9yYXRlX2ticHMgPiAxMDAw
MCkgeyBzdGQ6OmNlcnIgPDwgInNoaXAgcmF0ZSBtdXN0IGJlIGluIHJhbmdlIDY0Li4xMDAwMCBr
Yml0L3NcbiI7IHJldHVybiAyOyB9CiAgaWYgKGdfc3RhdHNfaW50ZXJ2YWxfc2VjIDwgMTAgfHwg
Z19zdGF0c19pbnRlcnZhbF9zZWMgPiAzNjAwKSB7IHN0ZDo6Y2VyciA8PCAic3RhdHMgaW50ZXJ2
YWwgbXVzdCBiZSBpbiByYW5nZSAxMC4uMzYwMCBzZWNvbmRzXG4iOyByZXR1cm4gMjsgfQogIHNp
Z25hbChTSUdURVJNLCBzdG9wX3NpZ25hbCk7IHNpZ25hbChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsg
c2lnbmFsKFNJR1BJUEUsIFNJR19JR04pOwogIGNoYXIgaG9zdFsyNTZdOyBnZXRob3N0bmFtZSho
b3N0LCBzaXplb2YoaG9zdCkpOyBob3N0W3NpemVvZihob3N0KSAtIDFdID0gMDsKICBjb25zdCBj
aGFyICpub2RlX2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1FIik7IGdfbm9kZSA9IChub2RlX2Vu
diAmJiAqbm9kZV9lbnYpID8gbm9kZV9lbnYgOiBob3N0OwogIGdfc3RhcnRlZF9lcG9jaCA9IHRp
bWUoTlVMTCk7IGdfaW5zdGFuY2VfaWQgPSB1bGxzKCh1bnNpZ25lZCBsb25nIGxvbmcpZ19zdGFy
dGVkX2Vwb2NoKSArICItIiArIHVsbHMoKHVuc2lnbmVkIGxvbmcgbG9uZylnZXRwaWQoKSk7CiAg
Z19sYXN0X3N0YXRzX2F0ID0gd2FsbF9zZWNvbmRzKCk7CiAgaWYgKHN0YXRzX2ZpeHR1cmUpIHsK
ICAgIGdfbGFzdF9zdGF0c19hdCAtPSAzMC4wOyBnX2lucHV0X3RvdGFsID0gMTA7IGdfcG9zdGVk
X3RvdGFsID0gODsKICAgIGdfZHJvcHBlZF90b3RhbCA9IGdfcXVldWVfZHJvcHNfdG90YWwgPSAy
OyBnX2J5dGVzX3Bvc3RlZF90b3RhbCA9IDY0MDA7CiAgICBzdGQ6OmNvdXQgPDwgc2hpcHBpbmdf
c3RhdHNfYm9keSgie1wicGFja2V0c190b3RhbFwiOjEwMCxcInBhY2tldHNfZGVsdGFcIjoxMDAs
XCJrZXJuZWxfZHJvcHNfdG90YWxcIjowLFwia2VybmVsX2Ryb3BzX2RlbHRhXCI6MCxcIm91dHB1
dF9waXBlX2Ryb3BzX2RlbHRhXCI6MCxcIndzc2VfYm9keV9ieXRlc1wiOjgxOTJ9IikgPDwgIlxu
IjsKICAgIHJldHVybiAwOwogIH0KICBwdGhyZWFkX2F0dHJfdCBhdHRyOwogIGlmIChwdGhyZWFk
X2F0dHJfaW5pdCgmYXR0cikgIT0gMCkgeyBsb2dtc2coImNhbm5vdCBpbml0aWFsaXplIHVwbG9h
ZGVyIGxpbWl0czsgcmVmdXNpbmcgdW5zYWZlIHN0YXJ0dXAiKTsgcmV0dXJuIDcwOyB9CiAgaWYg
KHB0aHJlYWRfYXR0cl9zZXRzdGFja3NpemUoJmF0dHIsIDUxMlUgKiAxMDI0VSkgIT0gMCkgewog
ICAgcHRocmVhZF9hdHRyX2Rlc3Ryb3koJmF0dHIpOyBsb2dtc2coImNhbm5vdCBlbmZvcmNlIDUx
MiBLaUIgdXBsb2FkZXIgc3RhY2s7IHJlZnVzaW5nIHVuc2FmZSBzdGFydHVwIik7IHJldHVybiA3
MDsKICB9CiAgcHRocmVhZF90IHVwbG9hZGVyOwogIGlmIChwdGhyZWFkX2NyZWF0ZSgmdXBsb2Fk
ZXIsICZhdHRyLCB1cGxvYWRlcl9tYWluLCBOVUxMKSAhPSAwKSB7IHB0aHJlYWRfYXR0cl9kZXN0
cm95KCZhdHRyKTsgbG9nbXNnKCJmYWlsZWQgdG8gc3RhcnQgYm91bmRlZCB1cGxvYWRlciB0aHJl
YWQiKTsgcmV0dXJuIDcwOyB9CiAgcHRocmVhZF9hdHRyX2Rlc3Ryb3koJmF0dHIpOwoKICBzdGQ6
OnN0cmluZyBsaW5lOwogIHdoaWxlIChnX3J1bm5pbmcpIHsKICAgIGZkX3NldCByOyBGRF9aRVJP
KCZyKTsgRkRfU0VUKDAsICZyKTsKICAgIHN0cnVjdCB0aW1ldmFsIHR2OyB0di50dl9zZWMgPSAx
OyB0di50dl91c2VjID0gMDsKICAgIGludCByYyA9IHNlbGVjdCgxLCAmciwgTlVMTCwgTlVMTCwg
JnR2KTsKICAgIGlmIChyYyA8IDApIHsgaWYgKGVycm5vID09IEVJTlRSKSBjb250aW51ZTsgbG9n
bXNnKCJzdGRpbiBzZWxlY3QgZmFpbGVkIik7IGJyZWFrOyB9CiAgICBpZiAocmMgPT0gMCkgY29u
dGludWU7CiAgICBpZiAoIXN0ZDo6Z2V0bGluZShzdGQ6OmNpbiwgbGluZSkpIGJyZWFrOwogICAg
aWYgKGxpbmUuZW1wdHkoKSkgY29udGludWU7CiAgICBzdGQ6OnN0cmluZyBjYXB0dXJlOwogICAg
aWYgKHBhcnNlX2NhcHR1cmVfc3RhdHMobGluZSwgJmNhcHR1cmUpKSB7CiAgICAgIHB0aHJlYWRf
bXV0ZXhfbG9jaygmZ19sb2NrKTsgZ19jYXB0dXJlX2pzb24gPSBjYXB0dXJlOyArK2dfY2FwdHVy
ZV9nZW5lcmF0aW9uOyBwdGhyZWFkX211dGV4X3VubG9jaygmZ19sb2NrKTsKICAgICAgY29udGlu
dWU7CiAgICB9CiAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfbG9jayk7CiAgICArK2dfaW5wdXRf
dG90YWw7CiAgICBpZiAobGluZS5zaXplKCkgPiBNQVhfSU5QVVRfTElORSkgeyArK2dfZHJvcHBl
ZF90b3RhbDsgKytnX292ZXJzaXplZF90b3RhbDsgfQogICAgZWxzZSB7IGlmIChnX3F1ZXVlLnNp
emUoKSA+PSBNQVhfUVVFVUUpIHsgZ19xdWV1ZS5wb3BfZnJvbnQoKTsgKytnX2Ryb3BwZWRfdG90
YWw7ICsrZ19xdWV1ZV9kcm9wc190b3RhbDsgfSBnX3F1ZXVlLnB1c2hfYmFjayhsaW5lKTsgaWYg
KGdfcXVldWUuc2l6ZSgpID4gZ19xdWV1ZV9oaWdoX3dhdGVyKSBnX3F1ZXVlX2hpZ2hfd2F0ZXIg
PSBnX3F1ZXVlLnNpemUoKTsgfQogICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfbG9jayk7CiAg
fQogIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19sb2NrKTsKICB3aGlsZSAoZ19xdWV1ZS5zaXplKCkg
PiBNQVhfQkFUQ0gpIHsKICAgIGdfcXVldWUucG9wX2Zyb250KCk7ICsrZ19kcm9wcGVkX3RvdGFs
OyArK2dfcXVldWVfZHJvcHNfdG90YWw7CiAgfQogIC8qIEVPRiBtYXkgbWVhbiBjYXB0dXJlIGZh
aWxlZC4gUGVybWl0IGF0IG1vc3Qgb25lIGZpbmFsIGJvdW5kZWQgdXBsb2FkLCBzbwogICAgIHN1
cGVydmlzZWQgcmVzdGFydCBjYW5ub3QgYmUgZGVsYXllZCBieSBhIGZ1bGwgNCwwMDAtZXZlbnQg
YmFja2xvZy4gKi8KICBnX25leHRfZXZlbnRfYXR0ZW1wdCA9IDAuMDsKICBnX2lucHV0X2RvbmUg
PSB0cnVlOwogIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX2xvY2spOwogIHB0aHJlYWRfam9pbih1
cGxvYWRlciwgTlVMTCk7CiAgaWYgKGdfc3RvcHBlZF9ieV9zaWduYWwpIHsgbG9nbXNnKCJzdG9w
cGVkIik7IHJldHVybiAwOyB9CiAgbG9nbXNnKCJjYXB0dXJlIGlucHV0IGNsb3NlZCB1bmV4cGVj
dGVkbHk7IHJlcXVlc3Rpbmcgc3VwZXJ2aXNlZCBwaXBlbGluZSByZXN0YXJ0Iik7CiAgcmV0dXJu
IDc0Owp9Cg==
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
ZGUgPGZjbnRsLmg+CiNpbmNsdWRlIDxsaW1pdHMuaD4KI2luY2x1ZGUgPG5ldC9pZi5oPgojaW5j
bHVkZSA8c2lnbmFsLmg+CiNpbmNsdWRlIDxzdGRpbnQuaD4KI2luY2x1ZGUgPHN0ZGlvLmg+CiNp
bmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHN0cmluZy5oPgojaW5jbHVkZSA8cG9sbC5oPgoj
aW5jbHVkZSA8c3lzL2lvY3RsLmg+CiNpbmNsdWRlIDxzeXMvc3lzY2FsbC5oPgojaW5jbHVkZSA8
c3lzL21tYW4uaD4KI2luY2x1ZGUgPHN5cy9zZWxlY3QuaD4KI2luY2x1ZGUgPHN5cy90aW1lLmg+
CiNpbmNsdWRlIDxzeXMvcmVzb3VyY2UuaD4KI2luY2x1ZGUgPHN5cy9zb2NrZXQuaD4KI2luY2x1
ZGUgPHN5cy90eXBlcy5oPgojaW5jbHVkZSA8dGltZS5oPgojaW5jbHVkZSA8dW5pc3RkLmg+CiNp
bmNsdWRlIDxkaXJlbnQuaD4KI2luY2x1ZGUgPGxpbnV4L2ZpbHRlci5oPgojaW5jbHVkZSA8bGlu
dXgvY2FwYWJpbGl0eS5oPgojaW5jbHVkZSA8bGludXgvaWZfcGFja2V0Lmg+CiNpbmNsdWRlIDxs
aW51eC9pZl9ldGhlci5oPgojaW5jbHVkZSA8aW9zdHJlYW0+CiNpbmNsdWRlIDxmc3RyZWFtPgoj
aW5jbHVkZSA8bWFwPgojaW5jbHVkZSA8c3N0cmVhbT4KI2luY2x1ZGUgPHN0cmluZz4KI2luY2x1
ZGUgPHZlY3Rvcj4KCnN0YXRpYyB2b2xhdGlsZSBzaWdfYXRvbWljX3QgZ19ydW5uaW5nID0gMTsK
c3RhdGljIHZvaWQgc3RvcF9zaWduYWwoaW50KSB7IGdfcnVubmluZyA9IDA7IH0KCnN0YXRpYyBj
b25zdCBzaXplX3QgTUFYX0ZMT1dTID0gODE5MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUEVO
RElORyA9IDgxOTI7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BFTkRJTkdfUEVSX0ZMT1cgPSAz
MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUE9SVFMgPSAzMDsKc3RhdGljIGNvbnN0IHNpemVf
dCBNQVhfSEVBREVSID0gMjYyMTQ0OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NFX0JPRFlf
QllURVMgPSA2NTUzNjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfV1NTRV9CT0RZX0ZMT1dTID0g
MjU2OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NFX1VTRVJOQU1FID0gMjAwOwpzdGF0aWMg
Y29uc3Qgc2l6ZV90IE1BWF9CQVRDSCA9IDQwMDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUVVF
VUUgPSA0MDAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QT1NUX0JZVEVTID0gNjU1MzY7CnN0
YXRpYyBjb25zdCBzaXplX3QgTUFYX1NUQVRTX0JZVEVTID0gMTYzODQ7CnN0YXRpYyBjb25zdCB1
bnNpZ25lZCBERUZBVUxUX1NISVBfUkFURV9LQlBTID0gMTAyNDsKc3RhdGljIGNvbnN0IGludCBG
TFVTSF9TRUMgPSA1OwpzdGF0aWMgY29uc3QgaW50IFJFVFJZX1NFQyA9IDYwOwpzdGF0aWMgY29u
c3QgdW5zaWduZWQgRkxPV19UVEwgPSAxNTsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIFBFTkRJTkdf
VFRMID0gMzsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIEFDQ0VQVCA9IDIwNDg7CnN0YXRpYyBjb25z
dCBpbnQgU09fQVRUQUNIX0ZJTFRFUl9PTEQgPSAyNjsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNo
b3J0IEVUSF9QX0lQX0hPU1QgPSAweDA4MDA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBF
VEhfUF84MDIxUV9IT1NUID0gMHg4MTAwOwoKc3RhdGljIHN0ZDo6c3RyaW5nIHRyaW0oY29uc3Qg
c3RkOjpzdHJpbmcgJnMpIHsKICBzaXplX3QgYSA9IDAsIGIgPSBzLnNpemUoKTsKICB3aGlsZSAo
YSA8IGIgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilzW2FdKSkgKythOwogIHdoaWxlIChiID4g
YSAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKXNbYiAtIDFdKSkgLS1iOwogIHJldHVybiBzLnN1
YnN0cihhLCBiIC0gYSk7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGxvd2VyKGNvbnN0IHN0ZDo6c3Ry
aW5nICZzKSB7CiAgc3RkOjpzdHJpbmcgeCA9IHM7CiAgc2l6ZV90IGk7IGZvciAoaSA9IDA7IGkg
PCB4LnNpemUoKTsgKytpKSB4W2ldID0gKGNoYXIpdG9sb3dlcigodW5zaWduZWQgY2hhcil4W2ld
KTsKICByZXR1cm4geDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcganNvbnEoY29uc3Qgc3RkOjpzdHJp
bmcgJnMpIHsKICBzdGQ6OnN0cmluZyB4ID0gIlwiIjsgc2l6ZV90IGk7CiAgZm9yIChpID0gMDsg
aSA8IHMuc2l6ZSgpOyArK2kpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFy
KXNbaV07CiAgICBpZiAoYyA9PSAnXFwnIHx8IGMgPT0gJyInKSB7IHggKz0gJ1xcJzsgeCArPSAo
Y2hhciljOyB9CiAgICBlbHNlIGlmIChjID09ICdcbicpIHggKz0gIlxcbiI7CiAgICBlbHNlIGlm
IChjID09ICdccicpIHggKz0gIlxcciI7CiAgICBlbHNlIGlmIChjID09ICdcdCcpIHggKz0gIlxc
dCI7CiAgICBlbHNlIGlmIChjIDwgMzIpIHggKz0gJz8nOwogICAgZWxzZSB4ICs9IChjaGFyKWM7
CiAgfQogIHggKz0gJyInOyByZXR1cm4geDsKfQpzdGF0aWMgbG9uZyBsb25nIG5vd19tcygpIHsK
ICBzdHJ1Y3QgdGltZXZhbCB0djsgZ2V0dGltZW9mZGF5KCZ0diwgTlVMTCk7CiAgcmV0dXJuIChs
b25nIGxvbmcpdHYudHZfc2VjICogMTAwMExMICsgdHYudHZfdXNlYyAvIDEwMDA7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIG51bShsb25nIHYpIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgdjsg
cmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIGJvb2wgdmFsaWRfcG9ydCh1bnNpZ25lZCBwKSB7IHJl
dHVybiBwID4gMCAmJiBwIDw9IDY1NTM1OyB9CgpzdGF0aWMgdWludDE2X3QgcmVhZF91MTYoY29u
c3QgdW5zaWduZWQgY2hhciAqcCkgewogIHVpbnQxNl90IHZhbHVlOwogIG1lbWNweSgmdmFsdWUs
IHAsIHNpemVvZih2YWx1ZSkpOwogIHJldHVybiB2YWx1ZTsKfQoKc3RhdGljIHVpbnQzMl90IHJl
YWRfdTMyKGNvbnN0IHVuc2lnbmVkIGNoYXIgKnApIHsKICB1aW50MzJfdCB2YWx1ZTsKICBtZW1j
cHkoJnZhbHVlLCBwLCBzaXplb2YodmFsdWUpKTsKICByZXR1cm4gdmFsdWU7Cn0Kc3RhdGljIGJv
b2wgaGFzX21ldGhvZChjb25zdCBzdGQ6OnN0cmluZyAmbSkgewogIHJldHVybiBtID09ICJHRVQi
IHx8IG0gPT0gIlBPU1QiIHx8IG0gPT0gIlBVVCIgfHwgbSA9PSAiREVMRVRFIiB8fAogICAgICAg
ICBtID09ICJQQVRDSCIgfHwgbSA9PSAiSEVBRCIgfHwgbSA9PSAiT1BUSU9OUyI7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIGhvc3RfbmFtZSgpIHsKICBjaGFyIGJbMjU2XTsgaWYgKGdldGhvc3RuYW1l
KGIsIHNpemVvZihiKSAtIDEpICE9IDApIHJldHVybiAidW5rbm93bi1ub2RlIjsKICBiW3NpemVv
ZihiKSAtIDFdID0gMDsgY2hhciAqcCA9IHN0cmNocihiLCAnLicpOyBpZiAocCkgKnAgPSAwOyBy
ZXR1cm4gYjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgYjY0ZGVjb2RlX3VzZXIoY29uc3QgY2hhciAq
aW4sIHNpemVfdCBpbl9sZW4pIHsKICB3aGlsZSAoaW5fbGVuID4gMCAmJiBpc3NwYWNlKCh1bnNp
Z25lZCBjaGFyKSppbikpIHsgKytpbjsgLS1pbl9sZW47IH0KICB3aGlsZSAoaW5fbGVuID4gMCAm
JiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKWluW2luX2xlbiAtIDFdKSkgeyAtLWluX2xlbjsgfQog
IHN0ZDo6c3RyaW5nIG91dDsgaW50IHZhbCA9IDAsIGJpdHMgPSAtODsgc2l6ZV90IGk7CiAgZm9y
IChpID0gMDsgaSA8IGluX2xlbjsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWdu
ZWQgY2hhcilpbltpXTsgaW50IGQgPSAtMTsKICAgIGlmIChjID49ICdBJyAmJiBjIDw9ICdaJykg
ZCA9IGMgLSAnQSc7CiAgICBlbHNlIGlmIChjID49ICdhJyAmJiBjIDw9ICd6JykgZCA9IGMgLSAn
YScgKyAyNjsKICAgIGVsc2UgaWYgKGMgPj0gJzAnICYmIGMgPD0gJzknKSBkID0gYyAtICcwJyAr
IDUyOwogICAgZWxzZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsKICAgIGVsc2UgaWYgKGMgPT0gJy8n
KSBkID0gNjM7CiAgICBlbHNlIGlmIChjID09ICc9JykgYnJlYWs7CiAgICBpZiAoZCA8IDApIGNv
bnRpbnVlOwogICAgdmFsID0gKHZhbCA8PCA2KSArIGQ7CiAgICBiaXRzICs9IDY7CiAgICBpZiAo
Yml0cyA+PSAwKSB7CiAgICAgIG91dCArPSAoY2hhcikoKHZhbCA+PiBiaXRzKSAmIDB4ZmYpOwog
ICAgICBiaXRzIC09IDg7CiAgICAgIGlmIChvdXQuc2l6ZSgpID4gNTEyKSByZXR1cm4gIiI7CiAg
ICB9CiAgfQogIHNpemVfdCBwID0gb3V0LmZpbmQoJzonKTsKICBpZiAocCA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcykgcmV0dXJuICIiOwogIHJldHVybiBvdXQuc3Vic3RyKDAsIHAgPiA2NCA/IDY0IDog
cCk7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGlwX3RvX3N0cih1aW50MzJfdCBpcF9iZSkgewogIGNo
YXIgYltJTkVUX0FERFJTVFJMRU5dOwogIGluZXRfbnRvcChBRl9JTkVULCAmaXBfYmUsIGIsIHNp
emVvZihiKSk7CiAgcmV0dXJuIGI7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmFjZV9pZF9mcm9t
X3BhcmVudChjb25zdCBzdGQ6OnN0cmluZyAmdHApIHsKICBzdGQ6OnN0cmluZyB4ID0gdHJpbSh0
cCk7CiAgaWYgKHguc2l6ZSgpID09IDU1ICYmIHhbMl0gPT0gJy0nICYmIHhbMzVdID09ICctJyAm
JiB4WzUyXSA9PSAnLScpIHJldHVybiBsb3dlcih4LnN1YnN0cigzLCAzMikpOwogIHJldHVybiAi
IjsKfQoKc3RhdGljIHVpbnQ2NF90IGdfcm5nX3N0YXRlID0gMDsKc3RhdGljIHZvaWQgaW5pdF9y
bmcoKSB7CiAgRklMRSAqZiA9IGZvcGVuKCIvZGV2L3VyYW5kb20iLCAicmIiKTsKICBpZiAoZikg
ewogICAgc2l6ZV90IG4gPSBmcmVhZCgmZ19ybmdfc3RhdGUsIDEsIHNpemVvZihnX3JuZ19zdGF0
ZSksIGYpOwogICAgKHZvaWQpbjsKICAgIGZjbG9zZShmKTsKICB9CiAgaWYgKCFnX3JuZ19zdGF0
ZSkgewogICAgZ19ybmdfc3RhdGUgPSAoKHVpbnQ2NF90KXRpbWUoTlVMTCkgPDwgMzIpIF4gKHVp
bnQ2NF90KWdldHBpZCgpOwogIH0KfQpzdGF0aWMgaW5saW5lIHVpbnQ2NF90IG5leHRfcm5nKCkg
ewogIHVpbnQ2NF90IHggPSBnX3JuZ19zdGF0ZTsKICB4IF49IHggPDwgMTM7IHggXj0geCA+PiA3
OyB4IF49IHggPDwgMTc7CiAgcmV0dXJuIGdfcm5nX3N0YXRlID0gKHggPyB4IDogMHg4NTNjNDll
Njc0OGZlYTliVUxMKTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIG1ha2VfdHJhY2VwYXJlbnQoc3Rk
OjpzdHJpbmcgKnRpZCkgewogIHVpbnQ2NF90IHIxID0gbmV4dF9ybmcoKTsKICB1aW50NjRfdCBy
MiA9IG5leHRfcm5nKCk7CiAgdWludDY0X3QgcjMgPSBuZXh0X3JuZygpOwogIGNoYXIgYnVmWzY0
XTsKICBzbnByaW50ZihidWYsIHNpemVvZihidWYpLCAiMDAtJTAxNmxseCUwMTZsbHgtJTAxNmxs
eC0wMSIsCiAgICAgICAgICAgKHVuc2lnbmVkIGxvbmcgbG9uZylyMSwgKHVuc2lnbmVkIGxvbmcg
bG9uZylyMiwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMyk7CiAgY2hhciB0aWRfYnVmWzMzXTsKICBz
bnByaW50Zih0aWRfYnVmLCBzaXplb2YodGlkX2J1ZiksICIlMDE2bGx4JTAxNmxseCIsCiAgICAg
ICAgICAgKHVuc2lnbmVkIGxvbmcgbG9uZylyMSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMik7CiAg
KnRpZCA9IHRpZF9idWY7CiAgcmV0dXJuIGJ1ZjsKfQoKc3RydWN0IEV2ZW50IHsKICBsb25nIHRz
OyBzdGQ6OnN0cmluZyBob3N0LCBzcmMsIHNlcnZpY2UsIG1ldGhvZCwgcGF0aCwgdXNlciwgc2No
ZW1lLCBwcm9iZTsKICBzdGQ6OnN0cmluZyBiYXNpY191c2VyLCB3c3NlX3VzZXI7CiAgc3RkOjpz
dHJpbmcgaG9zdF9oZHIsIHVzZXJfYWdlbnQsIHhmZiwgY2FsbGVyLCBkc3RfaXAsIHRyYWNlcGFy
ZW50LCB0cmFjZV9pZDsKICB1bnNpZ25lZCBjYWxsZXJfcG9ydCwgZHN0X3BvcnQsIHJlcV9ieXRl
cywgcmVzcF9ieXRlczsgaW50IHN0YXR1czsgbG9uZyBkdXJhdGlvbl9tczsKICBib29sIGhhc19z
dGF0dXMsIGhhc19kdXJhdGlvbiwgaGFzX3Jlc3A7CiAgRXZlbnQoKSA6IHRzKDApLCBjYWxsZXJf
cG9ydCgwKSwgZHN0X3BvcnQoMCksIHJlcV9ieXRlcygwKSwgcmVzcF9ieXRlcygwKSwgc3RhdHVz
KDApLCBkdXJhdGlvbl9tcygwKSwgaGFzX3N0YXR1cyhmYWxzZSksIGhhc19kdXJhdGlvbihmYWxz
ZSksIGhhc19yZXNwKGZhbHNlKSB7fQp9OwpzdHJ1Y3QgUmVxdWVzdE1ldGEgewogIHN0ZDo6c3Ry
aW5nIGNvbnRlbnRfdHlwZSwgdHJhbnNmZXJfZW5jb2Rpbmc7CiAgc2l6ZV90IGNvbnRlbnRfbGVu
Z3RoOwogIGJvb2wgaGFzX2NvbnRlbnRfbGVuZ3RoOwogIFJlcXVlc3RNZXRhKCkgOiBjb250ZW50
X2xlbmd0aCgwKSwgaGFzX2NvbnRlbnRfbGVuZ3RoKGZhbHNlKSB7fQp9OwpzdHJ1Y3QgRmxvdyB7
CiAgc3RkOjpzdHJpbmcgYnVmOwogIHRpbWVfdCB0b3VjaGVkOwogIEV2ZW50IGV2ZW50OwogIHNp
emVfdCBib2R5X2dvYWw7CiAgYm9vbCBhd2FpdGluZ19ib2R5OwogIEZsb3coKSA6IHRvdWNoZWQo
dGltZShOVUxMKSksIGJvZHlfZ29hbCgwKSwgYXdhaXRpbmdfYm9keShmYWxzZSkge30KfTsKc3Ry
dWN0IFBlbmRpbmcgewogIEV2ZW50IGV2OwogIGxvbmcgbG9uZyBzdGFydGVkX21zOwogIFBlbmRp
bmcoKSA6IHN0YXJ0ZWRfbXMoMCkge30KICBQZW5kaW5nKGNvbnN0IEV2ZW50ICZlLCBsb25nIGxv
bmcgdCkgOiBldihlKSwgc3RhcnRlZF9tcyh0KSB7fQp9OwpzdHJ1Y3QgRmxvd0tleSB7CiAgdWlu
dDMyX3Qgc19pcDsKICB1aW50MTZfdCBzcG9ydDsKICB1aW50MzJfdCBkX2lwOwogIHVpbnQxNl90
IGRwb3J0OwogIGJvb2wgb3BlcmF0b3I8KGNvbnN0IEZsb3dLZXkgJngpIGNvbnN0IHsKICAgIGlm
IChzX2lwICE9IHguc19pcCkgcmV0dXJuIHNfaXAgPCB4LnNfaXA7CiAgICBpZiAoc3BvcnQgIT0g
eC5zcG9ydCkgcmV0dXJuIHNwb3J0IDwgeC5zcG9ydDsKICAgIGlmIChkX2lwICE9IHguZF9pcCkg
cmV0dXJuIGRfaXAgPCB4LmRfaXA7CiAgICByZXR1cm4gZHBvcnQgPCB4LmRwb3J0OwogIH0KfTsK
dHlwZWRlZiBGbG93S2V5IFBhY2tldEtleTsKCnN0YXRpYyB2b2lkIGxvZ21zZyhjb25zdCBzdGQ6
OnN0cmluZyAmcykgeyBmcHJpbnRmKHN0ZGVyciwgIm50LXNuaWZmLWNwcDogJXNcbiIsIHMuY19z
dHIoKSk7IGZmbHVzaChzdGRlcnIpOyB9CgpzdGF0aWMgYm9vbCBwYXJzZV9kZWNpbWFsX3NpemUo
Y29uc3QgY2hhciAqcCwgc2l6ZV90IG4sIHNpemVfdCAqb3V0KSB7CiAgd2hpbGUgKG4gJiYgaXNz
cGFjZSgodW5zaWduZWQgY2hhcikqcCkpIHsgKytwOyAtLW47IH0KICB3aGlsZSAobiAmJiBpc3Nw
YWNlKCh1bnNpZ25lZCBjaGFyKXBbbiAtIDFdKSkgLS1uOwogIGlmICghbikgcmV0dXJuIGZhbHNl
OwogIHNpemVfdCB2YWx1ZSA9IDA7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBuOyArK2kpIHsK
ICAgIGlmIChwW2ldIDwgJzAnIHx8IHBbaV0gPiAnOScpIHJldHVybiBmYWxzZTsKICAgIHVuc2ln
bmVkIGRpZ2l0ID0gKHVuc2lnbmVkKShwW2ldIC0gJzAnKTsKICAgIGlmICh2YWx1ZSA+IChzaXpl
X3QpLTEgLyAxMCB8fCB2YWx1ZSAqIDEwID4gKHNpemVfdCktMSAtIGRpZ2l0KSByZXR1cm4gZmFs
c2U7CiAgICB2YWx1ZSA9IHZhbHVlICogMTAgKyBkaWdpdDsKICB9CiAgKm91dCA9IHZhbHVlOwog
IHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBwYXJzZV9yZXF1ZXN0KGNvbnN0IGNoYXIgKmRh
dGEsIHNpemVfdCBsZW4sIEV2ZW50ICplLCBSZXF1ZXN0TWV0YSAqbWV0YSkgewogIGNvbnN0IGNo
YXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7CiAgY29uc3QgY2hh
ciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgaWYgKCFl
b2wpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hhciAqKW1lbWNo
cihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAgZS0+bWV0aG9k
LmFzc2lnbihwLCBzcDEgLSBwKTsKICBpZiAoIWhhc19tZXRob2QoZS0+bWV0aG9kKSkgcmV0dXJu
IGZhbHNlOwoKICBjb25zdCBjaGFyICpwYXRoX3N0YXJ0ID0gc3AxICsgMTsKICB3aGlsZSAocGF0
aF9zdGFydCA8IGVvbCAmJiAqcGF0aF9zdGFydCA9PSAnICcpICsrcGF0aF9zdGFydDsKICBjb25z
dCBjaGFyICpzcDIgPSAoY29uc3QgY2hhciAqKW1lbWNocihwYXRoX3N0YXJ0LCAnICcsIGVvbCAt
IHBhdGhfc3RhcnQpOwogIGlmICghc3AyKSBzcDIgPSAoZW9sID4gZGF0YSAmJiAqKGVvbCAtIDEp
ID09ICdccicpID8gZW9sIC0gMSA6IGVvbDsKICBjb25zdCBjaGFyICpxbWFyayA9IChjb25zdCBj
aGFyICopbWVtY2hyKHBhdGhfc3RhcnQsICc/Jywgc3AyIC0gcGF0aF9zdGFydCk7CiAgc2l6ZV90
IHBhdGhfbGVuID0gKHFtYXJrID8gcW1hcmsgOiBzcDIpIC0gcGF0aF9zdGFydDsKICBpZiAocGF0
aF9sZW4gPiAxMjApIHBhdGhfbGVuID0gMTIwOwogIGUtPnBhdGguYXNzaWduKHBhdGhfc3RhcnQs
IHBhdGhfbGVuKTsKCiAgcCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBlbmQpIHsKICAgIGlmICgq
cCA9PSAnXHInIHx8ICpwID09ICdcbicpIGJyZWFrOwogICAgY29uc3QgY2hhciAqbGluZV9lbmQg
PSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICAgIGlmICghbGluZV9l
bmQpIGxpbmVfZW5kID0gZW5kOwogICAgY29uc3QgY2hhciAqY29sb24gPSAoY29uc3QgY2hhciAq
KW1lbWNocihwLCAnOicsIGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29sb24pIHsKICAgICAgc2l6
ZV90IGhuYW1lX2xlbiA9IGNvbG9uIC0gcDsKICAgICAgY29uc3QgY2hhciAqdmFsX3N0YXJ0ID0g
Y29sb24gKyAxOwogICAgICB3aGlsZSAodmFsX3N0YXJ0IDwgbGluZV9lbmQgJiYgKCp2YWxfc3Rh
cnQgPT0gJyAnIHx8ICp2YWxfc3RhcnQgPT0gJ1x0JykpICsrdmFsX3N0YXJ0OwogICAgICBjb25z
dCBjaGFyICp2YWxfZW5kID0gbGluZV9lbmQ7CiAgICAgIHdoaWxlICh2YWxfZW5kID4gdmFsX3N0
YXJ0ICYmICh2YWxfZW5kWy0xXSA9PSAnXHInIHx8IHZhbF9lbmRbLTFdID09ICdcbicgfHwgdmFs
X2VuZFstMV0gPT0gJyAnIHx8IHZhbF9lbmRbLTFdID09ICdcdCcpKSAtLXZhbF9lbmQ7CiAgICAg
IHNpemVfdCB2YWxfbGVuID0gdmFsX2VuZCAtIHZhbF9zdGFydDsKCiAgICAgIGlmIChobmFtZV9s
ZW4gPT0gMTMgJiYgIXN0cm5jYXNlY21wKHAsICJhdXRob3JpemF0aW9uIiwgMTMpKSB7CiAgICAg
ICAgaWYgKHZhbF9sZW4gPiA2ICYmICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQsICJCYXNpYyAiLCA2
KSkgewogICAgICAgICAgc3RkOjpzdHJpbmcgYmFzaWNfdXNlciA9IGI2NGRlY29kZV91c2VyKHZh
bF9zdGFydCArIDYsIHZhbF9sZW4gLSA2KTsKICAgICAgICAgIGlmICghYmFzaWNfdXNlci5lbXB0
eSgpKSB7CiAgICAgICAgICAgIGUtPmJhc2ljX3VzZXIgPSBiYXNpY191c2VyOwogICAgICAgICAg
ICBlLT51c2VyID0gYmFzaWNfdXNlcjsKICAgICAgICAgICAgZS0+c2NoZW1lID0gImJhc2ljIjsK
ICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgaWYgKHZhbF9sZW4gPiA3ICYmICFzdHJuY2FzZWNt
cCh2YWxfc3RhcnQsICJCZWFyZXIgIiwgNykpIHsKICAgICAgICAgIGUtPnNjaGVtZSA9ICJiZWFy
ZXIiOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTEgJiYgIXN0cm5j
YXNlY21wKHAsICJ0cmFjZXBhcmVudCIsIDExKSkgewogICAgICAgIGUtPnRyYWNlcGFyZW50LmFz
c2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICAgIGUtPnRyYWNlX2lkID0gdHJhY2VfaWRf
ZnJvbV9wYXJlbnQoZS0+dHJhY2VwYXJlbnQpOwogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xlbiA9
PSA0ICYmICFzdHJuY2FzZWNtcChwLCAiaG9zdCIsIDQpKSB7CiAgICAgICAgZS0+aG9zdF9oZHIu
YXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVuID09
IDEwICYmICFzdHJuY2FzZWNtcChwLCAidXNlci1hZ2VudCIsIDEwKSkgewogICAgICAgIGUtPnVz
ZXJfYWdlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAoaG5h
bWVfbGVuID09IDE1ICYmICFzdHJuY2FzZWNtcChwLCAieC1mb3J3YXJkZWQtZm9yIiwgMTUpKSB7
CiAgICAgICAgZS0+eGZmLmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2Ug
aWYgKG1ldGEgJiYgaG5hbWVfbGVuID09IDEyICYmICFzdHJuY2FzZWNtcChwLCAiY29udGVudC10
eXBlIiwgMTIpKSB7CiAgICAgICAgbWV0YS0+Y29udGVudF90eXBlLmFzc2lnbih2YWxfc3RhcnQs
IHZhbF9sZW4pOwogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVuID09IDE0ICYmICFz
dHJuY2FzZWNtcChwLCAiY29udGVudC1sZW5ndGgiLCAxNCkpIHsKICAgICAgICBtZXRhLT5oYXNf
Y29udGVudF9sZW5ndGggPSBwYXJzZV9kZWNpbWFsX3NpemUodmFsX3N0YXJ0LCB2YWxfbGVuLCAm
bWV0YS0+Y29udGVudF9sZW5ndGgpOwogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVu
ID09IDE3ICYmICFzdHJuY2FzZWNtcChwLCAidHJhbnNmZXItZW5jb2RpbmciLCAxNykpIHsKICAg
ICAgICBtZXRhLT50cmFuc2Zlcl9lbmNvZGluZy5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsK
ICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CgogIGlmIChlLT51c2VyLmVt
cHR5KCkpIGUtPnVzZXIgPSAiLWFub255bW91cy0iOwogIGlmIChlLT5zY2hlbWUuZW1wdHkoKSkg
ZS0+c2NoZW1lID0gIm5vbmUiOwogIGlmIChlLT50cmFjZV9pZC5lbXB0eSgpKSBlLT50cmFjZXBh
cmVudCA9IG1ha2VfdHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lkKTsKICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIGJvb2wgaXNfd3NzZV9uYW1lc3BhY2UoY29uc3Qgc3RkOjpzdHJpbmcgJnVyaSkgewog
IHJldHVybiB1cmkgPT0gImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxL29h
c2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIgfHwKICAgICAgICAgdXJp
ID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3L3NlY2V4dCIgfHwKICAg
ICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzEyL3NlY2V4
dCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAz
LzA2L3NlY2V4dCI7Cn0KCnN0YXRpYyBib29sIGlzX3NvYXBfY29udGVudF90eXBlKGNvbnN0IHN0
ZDo6c3RyaW5nICZ2YWx1ZSkgewogIHN0ZDo6c3RyaW5nIG1lZGlhID0gbG93ZXIodmFsdWUpOwog
IHNpemVfdCBzZW1pID0gbWVkaWEuZmluZCgnOycpOwogIGlmIChzZW1pICE9IHN0ZDo6c3RyaW5n
OjpucG9zKSBtZWRpYS5lcmFzZShzZW1pKTsKICBtZWRpYSA9IHRyaW0obWVkaWEpOwogIHJldHVy
biBtZWRpYSA9PSAidGV4dC94bWwiIHx8IG1lZGlhID09ICJhcHBsaWNhdGlvbi94bWwiIHx8CiAg
ICAgICAgIG1lZGlhID09ICJhcHBsaWNhdGlvbi9zb2FwK3htbCIgfHwKICAgICAgICAgKG1lZGlh
LnNpemUoKSA+IDQgJiYgbWVkaWEuY29tcGFyZShtZWRpYS5zaXplKCkgLSA0LCA0LCAiK3htbCIp
ID09IDApOwp9CgpzdGF0aWMgdm9pZCBzcGxpdF9xbmFtZShjb25zdCBzdGQ6OnN0cmluZyAmbmFt
ZSwgc3RkOjpzdHJpbmcgKnByZWZpeCwgc3RkOjpzdHJpbmcgKmxvY2FsKSB7CiAgc2l6ZV90IGNv
bG9uID0gbmFtZS5maW5kKCc6Jyk7CiAgaWYgKGNvbG9uID09IHN0ZDo6c3RyaW5nOjpucG9zKSB7
IHByZWZpeC0+Y2xlYXIoKTsgKmxvY2FsID0gbmFtZTsgfQogIGVsc2UgeyAqcHJlZml4ID0gbmFt
ZS5zdWJzdHIoMCwgY29sb24pOyAqbG9jYWwgPSBuYW1lLnN1YnN0cihjb2xvbiArIDEpOyB9Cn0K
CnN0YXRpYyBib29sIGFwcGVuZF91dGY4KHVuc2lnbmVkIGxvbmcgY3AsIHN0ZDo6c3RyaW5nICpv
dXQpIHsKICBpZiAoY3AgPT0gMCB8fCBjcCA+IDB4MTBmZmZmVUwgfHwgKGNwID49IDB4ZDgwMFVM
ICYmIGNwIDw9IDB4ZGZmZlVMKSkgcmV0dXJuIGZhbHNlOwogIGlmIChjcCA8IDB4ODApIG91dC0+
cHVzaF9iYWNrKChjaGFyKWNwKTsKICBlbHNlIGlmIChjcCA8IDB4ODAwKSB7CiAgICBvdXQtPnB1
c2hfYmFjaygoY2hhcikoMHhjMCB8IChjcCA+PiA2KSkpOwogICAgb3V0LT5wdXNoX2JhY2soKGNo
YXIpKDB4ODAgfCAoY3AgJiAweDNmKSkpOwogIH0gZWxzZSBpZiAoY3AgPCAweDEwMDAwKSB7CiAg
ICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHhlMCB8IChjcCA+PiAxMikpKTsKICAgIG91dC0+cHVz
aF9iYWNrKChjaGFyKSgweDgwIHwgKChjcCA+PiA2KSAmIDB4M2YpKSk7CiAgICBvdXQtPnB1c2hf
YmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfSBlbHNlIHsKICAgIG91dC0+cHVz
aF9iYWNrKChjaGFyKSgweGYwIHwgKGNwID4+IDE4KSkpOwogICAgb3V0LT5wdXNoX2JhY2soKGNo
YXIpKDB4ODAgfCAoKGNwID4+IDEyKSAmIDB4M2YpKSk7CiAgICBvdXQtPnB1c2hfYmFjaygoY2hh
cikoMHg4MCB8ICgoY3AgPj4gNikgJiAweDNmKSkpOwogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIp
KDB4ODAgfCAoY3AgJiAweDNmKSkpOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wg
eG1sX3VuZXNjYXBlKGNvbnN0IHN0ZDo6c3RyaW5nICZ0ZXh0LCBzdGQ6OnN0cmluZyAqb3V0KSB7
CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCB0ZXh0LnNpemUoKTspIHsKICAgIGlmICh0ZXh0W2ld
ICE9ICcmJykgeyBvdXQtPnB1c2hfYmFjayh0ZXh0W2krK10pOyBjb250aW51ZTsgfQogICAgc2l6
ZV90IHNlbWkgPSB0ZXh0LmZpbmQoJzsnLCBpICsgMSk7CiAgICBpZiAoc2VtaSA9PSBzdGQ6OnN0
cmluZzo6bnBvcyB8fCBzZW1pIC0gaSA+IDEyKSByZXR1cm4gZmFsc2U7CiAgICBzdGQ6OnN0cmlu
ZyBlbnQgPSB0ZXh0LnN1YnN0cihpICsgMSwgc2VtaSAtIGkgLSAxKTsKICAgIGlmIChlbnQgPT0g
ImFtcCIpIG91dC0+cHVzaF9iYWNrKCcmJyk7CiAgICBlbHNlIGlmIChlbnQgPT0gImx0Iikgb3V0
LT5wdXNoX2JhY2soJzwnKTsKICAgIGVsc2UgaWYgKGVudCA9PSAiZ3QiKSBvdXQtPnB1c2hfYmFj
aygnPicpOwogICAgZWxzZSBpZiAoZW50ID09ICJxdW90Iikgb3V0LT5wdXNoX2JhY2soJyInKTsK
ICAgIGVsc2UgaWYgKGVudCA9PSAiYXBvcyIpIG91dC0+cHVzaF9iYWNrKCdcJycpOwogICAgZWxz
ZSBpZiAoIWVudC5lbXB0eSgpICYmIGVudFswXSA9PSAnIycpIHsKICAgICAgY2hhciAqZW5kcCA9
IE5VTEw7CiAgICAgIHVuc2lnbmVkIGxvbmcgY3AgPSBzdHJ0b3VsKGVudC5jX3N0cigpICsgKChl
bnQuc2l6ZSgpID4gMSAmJiAoZW50WzFdID09ICd4JyB8fCBlbnRbMV0gPT0gJ1gnKSkgPyAyIDog
MSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICZlbmRwLCAoZW50LnNpemUoKSA+
IDEgJiYgKGVudFsxXSA9PSAneCcgfHwgZW50WzFdID09ICdYJykpID8gMTYgOiAxMCk7CiAgICAg
IGlmICghZW5kcCB8fCAqZW5kcCB8fCAhYXBwZW5kX3V0ZjgoY3AsIG91dCkpIHJldHVybiBmYWxz
ZTsKICAgIH0gZWxzZSByZXR1cm4gZmFsc2U7CiAgICBpID0gc2VtaSArIDE7CiAgfQogIHJldHVy
biB0cnVlOwp9CgpzdGF0aWMgYm9vbCB2YWxpZF91dGY4X3VzZXJuYW1lKGNvbnN0IHN0ZDo6c3Ry
aW5nICZzKSB7CiAgaWYgKHMuZW1wdHkoKSB8fCBzLnNpemUoKSA+IE1BWF9XU1NFX1VTRVJOQU1F
ICogNCkgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBjaGFyYWN0ZXJzID0gMDsKICBmb3IgKHNpemVf
dCBpID0gMDsgaSA8IHMuc2l6ZSgpOykgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVk
IGNoYXIpc1tpXTsKICAgIHVuc2lnbmVkIGxvbmcgY3AgPSBjOwogICAgaWYgKGMgPCAweDgwKSB7
ICsraTsgfQogICAgZWxzZSB7CiAgICBzaXplX3QgbmVlZCA9IChjID49IDB4YzIgJiYgYyA8PSAw
eGRmKSA/IDEgOgogICAgICAgICAgICAgICAgICAoYyA+PSAweGUwICYmIGMgPD0gMHhlZikgPyAy
IDoKICAgICAgICAgICAgICAgICAgKGMgPj0gMHhmMCAmJiBjIDw9IDB4ZjQpID8gMyA6IDk5Owog
ICAgaWYgKG5lZWQgPT0gOTkgfHwgaSArIG5lZWQgPj0gcy5zaXplKCkpIHJldHVybiBmYWxzZTsK
ICAgIGZvciAoc2l6ZV90IGogPSAxOyBqIDw9IG5lZWQ7ICsraikKICAgICAgaWYgKCgodW5zaWdu
ZWQgY2hhcilzW2kgKyBqXSAmIDB4YzApICE9IDB4ODApIHJldHVybiBmYWxzZTsKICAgIGlmIChu
ZWVkID09IDIgJiYgYyA9PSAweGUwICYmICh1bnNpZ25lZCBjaGFyKXNbaSArIDFdIDwgMHhhMCkg
cmV0dXJuIGZhbHNlOwogICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4ZWQgJiYgKHVuc2lnbmVk
IGNoYXIpc1tpICsgMV0gPj0gMHhhMCkgcmV0dXJuIGZhbHNlOwogICAgaWYgKG5lZWQgPT0gMyAm
JiBjID09IDB4ZjAgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPCAweDkwKSByZXR1cm4gZmFs
c2U7CiAgICBpZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmNCAmJiAodW5zaWduZWQgY2hhcilzW2kg
KyAxXSA+PSAweDkwKSByZXR1cm4gZmFsc2U7CiAgICBjcCA9IGMgJiAoKDFVIDw8ICg3IC0gbmVl
ZCAtIDEpKSAtIDEpOwogICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0gbmVlZDsgKytqKSBjcCA9
IChjcCA8PCA2KSB8ICgodW5zaWduZWQgY2hhcilzW2kgKyBqXSAmIDB4M2YpOwogICAgaSArPSBu
ZWVkICsgMTsKICAgIH0KICAgIGlmICgrK2NoYXJhY3RlcnMgPiBNQVhfV1NTRV9VU0VSTkFNRSkg
cmV0dXJuIGZhbHNlOwogICAgaWYgKGNwIDwgMHgyMCB8fCAoY3AgPj0gMHg3ZiAmJiBjcCA8PSAw
eDlmKSB8fAogICAgICAgIChjcCA+PSAweGUwMDAgJiYgY3AgPD0gMHhmOGZmKSB8fAogICAgICAg
IChjcCA+PSAweGYwMDAwICYmIGNwIDw9IDB4ZmZmZmQpIHx8CiAgICAgICAgKGNwID49IDB4MTAw
MDAwICYmIGNwIDw9IDB4MTBmZmZkKSB8fAogICAgICAgIChjcCA+PSAweGZkZDAgJiYgY3AgPD0g
MHhmZGVmKSB8fCAoY3AgJiAweGZmZmZVTCkgPj0gMHhmZmZlVUwgfHwKICAgICAgICBjcCA9PSAw
eDAwYWQgfHwgY3AgPT0gMHgwNjFjIHx8IGNwID09IDB4MDZkZCB8fCBjcCA9PSAweDA3MGYgfHwK
ICAgICAgICBjcCA9PSAweDE4MGUgfHwgKGNwID49IDB4MjAwYiAmJiBjcCA8PSAweDIwMGYpIHx8
CiAgICAgICAgKGNwID49IDB4MjAyYSAmJiBjcCA8PSAweDIwMmUpIHx8IChjcCA+PSAweDIwNjAg
JiYgY3AgPD0gMHgyMDZmKSB8fAogICAgICAgIGNwID09IDB4ZmVmZikgcmV0dXJuIGZhbHNlOwog
IH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RydWN0IFhtbEZyYW1lIHsKICBzdGQ6Om1hcDxzdGQ6OnN0
cmluZywgc3RkOjpzdHJpbmc+IG5zOwogIHN0ZDo6c3RyaW5nIHFuYW1lLCB1cmksIGxvY2FsOwp9
OwoKc3RhdGljIGJvb2wgcGFyc2VfeG1sX25hbWUoY29uc3Qgc3RkOjpzdHJpbmcgJmJvZHksIHNp
emVfdCBsaW1pdCwgc2l6ZV90ICpwb3MsCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6
c3RyaW5nICpuYW1lKSB7CiAgc2l6ZV90IHN0YXJ0ID0gKnBvczsKICB3aGlsZSAoKnBvcyA8IGxp
bWl0KSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilib2R5Wypwb3NdOwog
ICAgaWYgKCEoaXNhbG51bShjKSB8fCBjID09ICdfJyB8fCBjID09ICctJyB8fCBjID09ICcuJyB8
fCBjID09ICc6JykpIGJyZWFrOwogICAgKysqcG9zOwogIH0KICBpZiAoKnBvcyA9PSBzdGFydCB8
fCAqcG9zIC0gc3RhcnQgPiAyNTYpIHJldHVybiBmYWxzZTsKICBuYW1lLT5hc3NpZ24oYm9keSwg
c3RhcnQsICpwb3MgLSBzdGFydCk7CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6OnN0cmlu
ZyBleHRyYWN0X3dzc2VfdXNlcm5hbWUoY29uc3Qgc3RkOjpzdHJpbmcgJmJvZHkpIHsKICBpZiAo
Ym9keS5lbXB0eSgpIHx8IGJvZHkuc2l6ZSgpID4gTUFYX1dTU0VfQk9EWV9CWVRFUyB8fAogICAg
ICBib2R5LmZpbmQoJ1wwJykgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiAiIjsKICBzdGQ6
OnN0cmluZyBsb3dlcmVkID0gbG93ZXIoYm9keSk7CiAgaWYgKGxvd2VyZWQuZmluZCgiPCFkb2N0
eXBlIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwKICAgICAgbG93ZXJlZC5maW5kKCI8IWVudGl0
eSIpICE9IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CgogIHN0ZDo6dmVjdG9yPFhtbEZy
YW1lPiBzdGFjazsKICBzaXplX3QgdG9rZW5fZGVwdGggPSAwLCB1c2VybmFtZV9kZXB0aCA9IDAs
IHBvcyA9IDA7CiAgc3RkOjpzdHJpbmcgdG9rZW5fdXJpLCBjaGFycywgcmVzdWx0OwogIGJvb2wg
dXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgd2hpbGUgKHBvcyA8IGJvZHkuc2l6ZSgpKSB7CiAgICBz
aXplX3QgbHQgPSBib2R5LmZpbmQoJzwnLCBwb3MpOwogICAgaWYgKGx0ID09IHN0ZDo6c3RyaW5n
OjpucG9zKSB7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCAmJiAhdXNlcm5hbWVfYmFkICYmICF4
bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIocG9zKSwgJmNoYXJzKSkgdXNlcm5hbWVfYmFkID0gdHJ1
ZTsKICAgICAgYnJlYWs7IC8qIGEgYm91bmRlZCBwcmVmaXggaXMgY29tbW9ubHkgaW5jb21wbGV0
ZSAqLwogICAgfQogICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2VybmFtZV9iYWQgJiYgbHQg
PiBwb3MgJiYKICAgICAgICAheG1sX3VuZXNjYXBlKGJvZHkuc3Vic3RyKHBvcywgbHQgLSBwb3Mp
LCAmY2hhcnMpKSB1c2VybmFtZV9iYWQgPSB0cnVlOwogICAgaWYgKGNoYXJzLnNpemUoKSA+IE1B
WF9XU1NFX1VTRVJOQU1FICogNCArIDIpIHsgY2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0g
dHJ1ZTsgfQoKICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDQsICI8IS0tIikgPT0gMCkgewogICAg
ICBzaXplX3QgZW5kID0gYm9keS5maW5kKCItLT4iLCBsdCArIDQpOyBpZiAoZW5kID09IHN0ZDo6
c3RyaW5nOjpucG9zKSBicmVhazsKICAgICAgcG9zID0gZW5kICsgMzsgY29udGludWU7CiAgICB9
CiAgICBpZiAoYm9keS5jb21wYXJlKGx0LCA5LCAiPCFbQ0RBVEFbIikgPT0gMCkgewogICAgICBz
aXplX3QgZW5kID0gYm9keS5maW5kKCJdXT4iLCBsdCArIDkpOyBpZiAoZW5kID09IHN0ZDo6c3Ry
aW5nOjpucG9zKSBicmVhazsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2VybmFtZV9i
YWQpIGNoYXJzLmFwcGVuZChib2R5LCBsdCArIDksIGVuZCAtIGx0IC0gOSk7CiAgICAgIHBvcyA9
IGVuZCArIDM7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgMiwgIjw/
IikgPT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5maW5kKCI/PiIsIGx0ICsgMik7IGlm
IChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBwb3MgPSBlbmQgKyAyOyBj
b250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDIsICI8ISIpID09IDApIHJl
dHVybiAiIjsKCiAgICBib29sIGNsb3NpbmcgPSAobHQgKyAxIDwgYm9keS5zaXplKCkgJiYgYm9k
eVtsdCArIDFdID09ICcvJyk7CiAgICBzaXplX3QgcCA9IGx0ICsgKGNsb3NpbmcgPyAyIDogMSk7
CiAgICBzdGQ6OnN0cmluZyBxbmFtZTsKICAgIGlmICghcGFyc2VfeG1sX25hbWUoYm9keSwgYm9k
eS5zaXplKCksICZwLCAmcW5hbWUpKSBicmVhazsKICAgIGlmIChjbG9zaW5nKSB7CiAgICAgIHdo
aWxlIChwIDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkg
KytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSB8fCBib2R5W3BdICE9ICc+JykgYnJlYWs7
CiAgICAgIGlmIChzdGFjay5lbXB0eSgpKSBicmVhazsKICAgICAgc3RkOjpzdHJpbmcgcHJlZml4
LCBsb2NhbDsgc3BsaXRfcW5hbWUocW5hbWUsICZwcmVmaXgsICZsb2NhbCk7CiAgICAgIFhtbEZy
YW1lICZ0b3AgPSBzdGFjay5iYWNrKCk7CiAgICAgIGlmICh0b3AucW5hbWUgIT0gcW5hbWUgfHwg
dG9wLmxvY2FsICE9IGxvY2FsKSBicmVhazsKICAgICAgc2l6ZV90IGRlcHRoID0gc3RhY2suc2l6
ZSgpOwogICAgICBpZiAodXNlcm5hbWVfZGVwdGggPT0gZGVwdGgpIHsKICAgICAgICBzdGQ6OnN0
cmluZyB1c2VybmFtZSA9IHRyaW0oY2hhcnMpOwogICAgICAgIGlmICghdXNlcm5hbWVfYmFkICYm
IHZhbGlkX3V0ZjhfdXNlcm5hbWUodXNlcm5hbWUpICYmIHJlc3VsdC5lbXB0eSgpKSByZXN1bHQg
PSB1c2VybmFtZTsKICAgICAgICB1c2VybmFtZV9kZXB0aCA9IDA7IGNoYXJzLmNsZWFyKCk7IHVz
ZXJuYW1lX2JhZCA9IGZhbHNlOwogICAgICB9CiAgICAgIGlmICh0b2tlbl9kZXB0aCA9PSBkZXB0
aCkgeyB0b2tlbl9kZXB0aCA9IDA7IHRva2VuX3VyaS5jbGVhcigpOyB9CiAgICAgIHN0YWNrLnBv
cF9iYWNrKCk7IHBvcyA9IHAgKyAxOwogICAgICBpZiAoIXJlc3VsdC5lbXB0eSgpKSByZXR1cm4g
cmVzdWx0OwogICAgICBjb250aW51ZTsKICAgIH0KCiAgICBYbWxGcmFtZSBmcmFtZTsKICAgIGlm
IChzdGFjay5zaXplKCkgPj0gNjQpIHJldHVybiAiIjsKICAgIGlmICghc3RhY2suZW1wdHkoKSkg
ZnJhbWUubnMgPSBzdGFjay5iYWNrKCkubnM7CiAgICBib29sIHNlbGZfY2xvc2luZyA9IGZhbHNl
LCBjb21wbGV0ZSA9IGZhbHNlOwogICAgc2l6ZV90IGF0dHJfY291bnQgPSAwOwogICAgd2hpbGUg
KHAgPCBib2R5LnNpemUoKSkgewogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGlzc3Bh
Y2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0gYm9keS5zaXpl
KCkpIGJyZWFrOwogICAgICBpZiAoYm9keVtwXSA9PSAnPicpIHsgKytwOyBjb21wbGV0ZSA9IHRy
dWU7IGJyZWFrOyB9CiAgICAgIGlmIChib2R5W3BdID09ICcvJyAmJiBwICsgMSA8IGJvZHkuc2l6
ZSgpICYmIGJvZHlbcCArIDFdID09ICc+JykgewogICAgICAgIHAgKz0gMjsgc2VsZl9jbG9zaW5n
ID0gdHJ1ZTsgY29tcGxldGUgPSB0cnVlOyBicmVhazsKICAgICAgfQogICAgICBzdGQ6OnN0cmlu
ZyBhbmFtZTsKICAgICAgaWYgKCFwYXJzZV94bWxfbmFtZShib2R5LCBib2R5LnNpemUoKSwgJnAs
ICZhbmFtZSkpIGJyZWFrOwogICAgICBpZiAoKythdHRyX2NvdW50ID4gMTI4KSByZXR1cm4gIiI7
CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcili
b2R5W3BdKSkgKytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSB8fCBib2R5W3ArK10gIT0g
Jz0nKSBicmVhazsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNp
Z25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8IChi
b2R5W3BdICE9ICdcJycgJiYgYm9keVtwXSAhPSAnIicpKSBicmVhazsKICAgICAgY2hhciBxdW90
ZSA9IGJvZHlbcCsrXTsgc2l6ZV90IHZhbHVlX3N0YXJ0ID0gcDsKICAgICAgd2hpbGUgKHAgPCBi
b2R5LnNpemUoKSAmJiBib2R5W3BdICE9IHF1b3RlKSArK3A7CiAgICAgIGlmIChwID49IGJvZHku
c2l6ZSgpKSBicmVhazsKICAgICAgc3RkOjpzdHJpbmcgdmFsdWU7CiAgICAgIGlmICgheG1sX3Vu
ZXNjYXBlKGJvZHkuc3Vic3RyKHZhbHVlX3N0YXJ0LCBwIC0gdmFsdWVfc3RhcnQpLCAmdmFsdWUp
KSByZXR1cm4gIiI7CiAgICAgICsrcDsKICAgICAgaWYgKGFuYW1lID09ICJ4bWxucyIpIGZyYW1l
Lm5zWyIiXSA9IHZhbHVlOwogICAgICBlbHNlIGlmIChhbmFtZS5jb21wYXJlKDAsIDYsICJ4bWxu
czoiKSA9PSAwKSBmcmFtZS5uc1thbmFtZS5zdWJzdHIoNildID0gdmFsdWU7CiAgICAgIGlmIChm
cmFtZS5ucy5zaXplKCkgPiA2NCkgcmV0dXJuICIiOwogICAgfQogICAgaWYgKCFjb21wbGV0ZSkg
YnJlYWs7CiAgICBzdGQ6OnN0cmluZyBwcmVmaXgsIGxvY2FsOyBzcGxpdF9xbmFtZShxbmFtZSwg
JnByZWZpeCwgJmxvY2FsKTsKICAgIHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz46
OmNvbnN0X2l0ZXJhdG9yIG5zID0gZnJhbWUubnMuZmluZChwcmVmaXgpOwogICAgZnJhbWUudXJp
ID0gKG5zID09IGZyYW1lLm5zLmVuZCgpKSA/ICIiIDogbnMtPnNlY29uZDsKICAgIGZyYW1lLnFu
YW1lID0gcW5hbWU7CiAgICBmcmFtZS5sb2NhbCA9IGxvY2FsOwogICAgc3RhY2sucHVzaF9iYWNr
KGZyYW1lKTsKICAgIHNpemVfdCBkZXB0aCA9IHN0YWNrLnNpemUoKTsKICAgIGlmICghdG9rZW5f
ZGVwdGggJiYgbG9jYWwgPT0gIlVzZXJuYW1lVG9rZW4iICYmIGlzX3dzc2VfbmFtZXNwYWNlKGZy
YW1lLnVyaSkpIHsKICAgICAgdG9rZW5fZGVwdGggPSBkZXB0aDsgdG9rZW5fdXJpID0gZnJhbWUu
dXJpOwogICAgfSBlbHNlIGlmICh0b2tlbl9kZXB0aCAmJiBkZXB0aCA9PSB0b2tlbl9kZXB0aCAr
IDEgJiYKICAgICAgICAgICAgICAgbG9jYWwgPT0gIlVzZXJuYW1lIiAmJiBmcmFtZS51cmkgPT0g
dG9rZW5fdXJpKSB7CiAgICAgIHVzZXJuYW1lX2RlcHRoID0gZGVwdGg7IGNoYXJzLmNsZWFyKCk7
IHVzZXJuYW1lX2JhZCA9IGZhbHNlOwogICAgfQogICAgaWYgKHNlbGZfY2xvc2luZykgewogICAg
ICBpZiAodXNlcm5hbWVfZGVwdGggPT0gZGVwdGgpIHVzZXJuYW1lX2RlcHRoID0gMDsKICAgICAg
aWYgKHRva2VuX2RlcHRoID09IGRlcHRoKSB7IHRva2VuX2RlcHRoID0gMDsgdG9rZW5fdXJpLmNs
ZWFyKCk7IH0KICAgICAgc3RhY2sucG9wX2JhY2soKTsKICAgIH0KICAgIHBvcyA9IHA7CiAgfQog
IHJldHVybiByZXN1bHQ7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3Jlc3BvbnNlKGNvbnN0IGNoYXIg
KmRhdGEsIHNpemVfdCBsZW4sIGludCAqc3RhdHVzLCB1bnNpZ25lZCAqY2xlbikgewogIGNvbnN0
IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7CiAgY29uc3Qg
Y2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgaWYg
KCFlb2wpIHJldHVybiBmYWxzZTsKICBpZiAoc3RybmNtcChwLCAiSFRUUC8iLCA1KSAhPSAwKSBy
ZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwg
JyAnLCBlb2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNoYXIgKnNj
X3N0YXJ0ID0gc3AxICsgMTsKICB3aGlsZSAoc2Nfc3RhcnQgPCBlb2wgJiYgKnNjX3N0YXJ0ID09
ICcgJykgKytzY19zdGFydDsKICAqc3RhdHVzID0gYXRvaShzY19zdGFydCk7CiAgaWYgKCpzdGF0
dXMgPCAxMDAgfHwgKnN0YXR1cyA+IDU5OSkgcmV0dXJuIGZhbHNlOwogICpjbGVuID0gMDsKICBw
ID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYgKCpwID09ICdccicgfHwgKnAg
PT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2VuZCA9IChjb25zdCBjaGFyICop
bWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5lX2VuZCkgbGluZV9lbmQgPSBl
bmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICc6Jywg
bGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBzaXplX3QgaGxlbiA9IGNvbG9u
IC0gcDsKICAgICAgaWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxl
bmd0aCIsIDE0KSkgewogICAgICAgIGNvbnN0IGNoYXIgKnYgPSBjb2xvbiArIDE7CiAgICAgICAg
d2hpbGUgKHYgPCBsaW5lX2VuZCAmJiAoKnYgPT0gJyAnIHx8ICp2ID09ICdcdCcpKSArK3Y7CiAg
ICAgICAgbG9uZyBuID0gYXRvbCh2KTsKICAgICAgICBpZiAobiA+PSAwICYmIG4gPD0gMHg3ZmZm
ZmZmZikgKmNsZW4gPSAodW5zaWduZWQpbjsKICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5k
ICsgMTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyBnX2VuZHBvaW50
OwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRpYyBzdGQ6OnZlY3RvcjxzdGQ6
OnN0cmluZz4gZ19zaGlwX2J1ZjsKc3RhdGljIHVuc2lnbmVkIGdfc2hpcF9yYXRlX2ticHMgPSBE
RUZBVUxUX1NISVBfUkFURV9LQlBTOwpzdGF0aWMgdW5zaWduZWQgZ19zdGF0c19pbnRlcnZhbF9z
ZWMgPSAzMDsKc3RhdGljIHNpemVfdCBnX3dzc2VfYm9keV9ieXRlcyA9IDA7CnN0YXRpYyBkb3Vi
bGUgZ19uZXh0X3NoaXBfc2xvdCA9IDAuMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2Nh
cHR1cmVfcGFja2V0cyA9IDAsIGdfY2FwdHVyZV9ieXRlcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBs
b25nIGxvbmcgZ19rZXJuZWxfZHJvcHMgPSAwLCBnX2ludmFsaWRfZnJhbWVzID0gMDsKc3RhdGlj
IHVuc2lnbmVkIGxvbmcgbG9uZyBnX2V2ZW50c19lbWl0dGVkID0gMCwgZ19ldmVudHNfaW4gPSAw
OwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfZXZlbnRzX3B1c2hlZCA9IDAsIGdfZXZlbnRz
X2Ryb3BwZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfZHJvcF9xdWV1ZSA9IDAs
IGdfZHJvcF9odWIgPSAwLCBnX2Ryb3Bfb3ZlcnNpemVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxv
bmcgbG9uZyBnX2JhdGNoZXNfcHVzaGVkID0gMCwgZ19iYXRjaGVzX2ZhaWxlZCA9IDA7CnN0YXRp
YyB1bnNpZ25lZCBsb25nIGxvbmcgZ19ieXRlc19wdXNoZWQgPSAwLCBnX3N0YXRzX2Ryb3BwZWQg
PSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfb3V0cHV0X3BpcGVfZHJvcHMgPSAwLCBn
X3ByZXZfb3V0cHV0X3BpcGVfZHJvcHMgPSAwOwpzdGF0aWMgc2l6ZV90IGdfcXVldWVfaGlnaF93
YXRlciA9IDA7CnN0YXRpYyB1bnNpZ25lZCBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzID0gMCwgZ19s
YXN0X3B1c2hfc3RhdHVzID0gMDsKc3RhdGljIHRpbWVfdCBnX2xhc3Rfc3VjY2Vzc19hdCA9IDA7
CnN0YXRpYyBkb3VibGUgZ19zdGF0c19sYXN0X2F0ID0gMC4wLCBnX3N0YXRzX2xhc3RfY3B1ID0g
MC4wOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9jYXB0dXJlX3BhY2tldHMgPSAw
LCBnX3ByZXZfY2FwdHVyZV9ieXRlcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19w
cmV2X2V2ZW50c19lbWl0dGVkID0gMCwgZ19wcmV2X2V2ZW50c19pbiA9IDA7CnN0YXRpYyB1bnNp
Z25lZCBsb25nIGxvbmcgZ19wcmV2X2V2ZW50c19wdXNoZWQgPSAwLCBnX3ByZXZfZXZlbnRzX2Ry
b3BwZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9iYXRjaGVzX3B1c2hl
ZCA9IDAsIGdfcHJldl9iYXRjaGVzX2ZhaWxlZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxv
bmcgZ19wcmV2X2J5dGVzX3B1c2hlZCA9IDAsIGdfcHJldl9kcm9wX3F1ZXVlID0gMDsKc3RhdGlj
IHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfZHJvcF9odWIgPSAwLCBnX3ByZXZfZHJvcF9vdmVy
c2l6ZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfc3RhdHNfc2VxdWVuY2UgPSAw
OwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19pbnN0YW5jZV9pZDsKCnN0YXRpYyBzdGQ6OnN0cmluZyBz
aGVsbHEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZv
ciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcnKSBv
ICs9ICInXFwnJyI7IGVsc2UgbyArPSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIG51bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFt
IG87IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIHVsbF9zdHJp
bmcodW5zaWduZWQgbG9uZyBsb25nIG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgbjsg
cmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGRvdWJsZV9zdHJpbmcoZG91Ymxl
IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8uc2V0ZihzdGQ6Omlvczo6Zml4ZWQpOyBvLnBy
ZWNpc2lvbig0KTsgbyA8PCBuOyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgc3RkOjpzdHJpbmcg
anNvbl9hcnJheShjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmEpIHsKICBzdGQ6OnN0
cmluZyBvID0gIlsiOyBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGEuc2l6ZSgpOyArK2kpIHsgaWYg
KGkpIG8gKz0gIiwiOyBvICs9IGFbaV07IH0gcmV0dXJuIG8gKyAiXSI7Cn0Kc3RhdGljIGRvdWJs
ZSB3YWxsX3NlY29uZHMoKSB7CiAgc3RydWN0IHRpbWV2YWwgdHY7CiAgZ2V0dGltZW9mZGF5KCZ0
diwgTlVMTCk7CiAgcmV0dXJuIChkb3VibGUpdHYudHZfc2VjICsgKGRvdWJsZSl0di50dl91c2Vj
IC8gMTAwMDAwMC4wOwp9CnN0YXRpYyB2b2lkIHBhY2VfdXBsb2FkKHNpemVfdCBieXRlcykgewog
IGNvbnN0IGRvdWJsZSBieXRlc19wZXJfc2VjID0gKGRvdWJsZSlnX3NoaXBfcmF0ZV9rYnBzICog
MTAwMC4wIC8gOC4wOwogIGRvdWJsZSBub3cgPSB3YWxsX3NlY29uZHMoKTsKICBpZiAoZ19uZXh0
X3NoaXBfc2xvdCA8IG5vdyB8fCBnX25leHRfc2hpcF9zbG90IC0gbm93ID4gNjAuMCkgZ19uZXh0
X3NoaXBfc2xvdCA9IG5vdzsKICBkb3VibGUgc2xvdCA9IGdfbmV4dF9zaGlwX3Nsb3Q7CiAgZ19u
ZXh0X3NoaXBfc2xvdCArPSAoZG91YmxlKWJ5dGVzIC8gYnl0ZXNfcGVyX3NlYzsKICB3aGlsZSAo
c2xvdCA+IChub3cgPSB3YWxsX3NlY29uZHMoKSkpIHsKICAgIGRvdWJsZSByZW1haW5pbmcgPSBz
bG90IC0gbm93OwogICAgdXNlY29uZHNfdCBkZWxheSA9ICh1c2Vjb25kc190KShyZW1haW5pbmcg
PiAwLjUgPyA1MDAwMDAgOiByZW1haW5pbmcgKiAxMDAwMDAwLjApOwogICAgaWYgKGRlbGF5KSB1
c2xlZXAoZGVsYXkpOwogIH0KfQpzdGF0aWMgc2l6ZV90IGJvdW5kZWRfYmF0Y2hfY291bnQoY29u
c3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZidWYsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSkgewogIHNpemVfdCBzaXplID0gc3Rk
OjpzdHJpbmcoIntcIm5vZGVcIjoiKS5zaXplKCkgKyBqc29ucShub2RlKS5zaXplKCkgKwogICAg
ICAgICAgICAgICAgc3RkOjpzdHJpbmcoIixcImV2ZW50c1wiOltdfSIpLnNpemUoKTsKICBzaXpl
X3QgbiA9IDAsIGxpbWl0ID0gYnVmLnNpemUoKSA8IE1BWF9CQVRDSCA/IGJ1Zi5zaXplKCkgOiBN
QVhfQkFUQ0g7CiAgd2hpbGUgKG4gPCBsaW1pdCkgewogICAgc2l6ZV90IGV4dHJhID0gYnVmW25d
LnNpemUoKSArIChuID8gMSA6IDApOwogICAgaWYgKGV4dHJhID4gTUFYX1BPU1RfQllURVMgLSBz
aXplKSBicmVhazsKICAgIHNpemUgKz0gZXh0cmE7CiAgICArK247CiAgfQogIHJldHVybiBuOwp9
CnN0YXRpYyBpbnQgcnVuX3NoaXBfcmF0ZV9maXh0dXJlKCkgewogIHN0ZDo6dmVjdG9yPHN0ZDo6
c3RyaW5nPiBldmVudHM7CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyg0MDAwMCwgJ3gn
KSk7CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyg0MDAwMCwgJ3knKSk7CiAgaWYgKGJv
dW5kZWRfYmF0Y2hfY291bnQoZXZlbnRzLCAiZml4dHVyZSIpICE9IDEpIHJldHVybiAzMDsKICBl
dmVudHMuY2xlYXIoKTsKICBldmVudHMucHVzaF9iYWNrKHN0ZDo6c3RyaW5nKE1BWF9QT1NUX0JZ
VEVTICsgMSwgJ3gnKSk7CiAgaWYgKGJvdW5kZWRfYmF0Y2hfY291bnQoZXZlbnRzLCAiZml4dHVy
ZSIpICE9IDApIHJldHVybiAzMTsKICByZXR1cm4gMDsKfQpzdGF0aWMgYm9vbCBwb3N0X2JvZHko
Y29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmcGF0aCwKICAg
ICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6c3RyaW5nICZib2R5LCB1bnNpZ25lZCB0aW1l
b3V0X3NlYykgewogIHBhY2VfdXBsb2FkKGJvZHkuc2l6ZSgpKTsKICBzdGQ6OnN0cmluZyBjbWQg
PSAiY3VybCAtc1NmIC0tbWF4LXRpbWUgIiArIG51bWJlcl9zdHJpbmcodGltZW91dF9zZWMpICsg
IiAtLWxpbWl0LXJhdGUgIiArCiAgICBudW1iZXJfc3RyaW5nKChzaXplX3QpZ19zaGlwX3JhdGVf
a2JwcyAqIDEwMDBVIC8gOFUpICsKICAgICIgLW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6
IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1iaW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCAr
IHBhdGgpOwogIEZJTEUgKmZwID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7IGlmICghZnApIHJl
dHVybiBmYWxzZTsKICBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAg
aW50IHJjID0gcGNsb3NlKGZwKTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRV
UyhyYykgPT0gMDsKfQpzdGF0aWMgYm9vbCBwb3N0KGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2lu
dCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsIGNvbnN0IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5n
PiAmYmF0Y2gpIHsKICBzdGQ6OnN0cmluZyBib2R5ID0gIntcIm5vZGVcIjoiICsganNvbnEobm9k
ZSkgKyAiLFwiZXZlbnRzXCI6IiArIGpzb25fYXJyYXkoYmF0Y2gpICsgIn0iOwogIGlmIChib2R5
LnNpemUoKSA+IE1BWF9QT1NUX0JZVEVTKSByZXR1cm4gZmFsc2U7CiAgYm9vbCBvayA9IHBvc3Rf
Ym9keShlbmRwb2ludCwgIi9hcGkvaW5nZXN0IiwgYm9keSwgMTApOwogIGlmIChvaykgewogICAg
Z19ldmVudHNfcHVzaGVkICs9IGJhdGNoLnNpemUoKTsKICAgICsrZ19iYXRjaGVzX3B1c2hlZDsK
ICAgIGdfYnl0ZXNfcHVzaGVkICs9IGJvZHkuc2l6ZSgpOwogICAgZ19jb25zZWN1dGl2ZV9mYWls
dXJlcyA9IDA7CiAgICBnX2xhc3RfcHVzaF9zdGF0dXMgPSAyMDA7CiAgICBnX2xhc3Rfc3VjY2Vz
c19hdCA9IHRpbWUoTlVMTCk7CiAgfQogIHJldHVybiBvazsKfQpzdGF0aWMgdm9pZCBzZW5kX2Jh
dGNoZXMoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9k
ZSwKICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAqYnVm
LCBib29sIGZsdXNoX2FsbCkgewogIHdoaWxlICghYnVmLT5lbXB0eSgpICYmIChmbHVzaF9hbGwg
fHwgYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIKSkgewogICAgc2l6ZV90IG4gPSBib3VuZGVkX2Jh
dGNoX2NvdW50KCpidWYsIG5vZGUpOwogICAgaWYgKCFuKSB7CiAgICAgIGJ1Zi0+ZXJhc2UoYnVm
LT5iZWdpbigpKTsKICAgICAgKytnX2V2ZW50c19kcm9wcGVkOwogICAgICArK2dfZHJvcF9vdmVy
c2l6ZWQ7CiAgICAgIGxvZ21zZygiV0FSTjogZHJvcHBlZCBvdmVyc2l6ZWQgZXZlbnQ7IGVuY29k
ZWQgYm9keSBleGNlZWRzIDY1NTM2IGJ5dGVzIik7CiAgICAgIGNvbnRpbnVlOwogICAgfQogICAg
c3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigp
ICsgbik7CiAgICBpZiAocG9zdChlbmRwb2ludCwgbm9kZSwgYmF0Y2gpKSB7CiAgICAgIGJ1Zi0+
ZXJhc2UoYnVmLT5iZWdpbigpLCBidWYtPmJlZ2luKCkgKyBuKTsKICAgICAgbG9nbXNnKCJmbHVz
aGVkICIgKyBudW1iZXJfc3RyaW5nKG4pICsgIiBldmVudHMiKTsKICAgIH0gZWxzZSB7CiAgICAg
IC8qIFB1cmUgaW4tbWVtb3J5IGRyb3Agd2hlbiBIdWIgdW5yZWFjaGFibGUgKHplcm8gZGlzayBJ
L08pICovCiAgICAgIGJ1Zi0+ZXJhc2UoYnVmLT5iZWdpbigpLCBidWYtPmJlZ2luKCkgKyBuKTsK
ICAgICAgZ19ldmVudHNfZHJvcHBlZCArPSBuOwogICAgICBnX2Ryb3BfaHViICs9IG47CiAgICAg
ICsrZ19iYXRjaGVzX2ZhaWxlZDsKICAgICAgKytnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzOwogICAg
ICBnX2xhc3RfcHVzaF9zdGF0dXMgPSAwOwogICAgICBsb2dtc2coIldBUk46IEh1YiB1bnJlYWNo
YWJsZSwgZHJvcHBlZCAiICsgbnVtYmVyX3N0cmluZyhuKSArICIgZXZlbnRzIChpbi1tZW1vcnkg
ZHJvcCwgMCBkaXNrIEkvTykiKTsKICAgICAgYnJlYWs7CiAgICB9CiAgfQp9CgpzdGF0aWMgdW5z
aWduZWQgY291bnRfb3Blbl9mZHMoKSB7CiAgRElSICpkaXIgPSBvcGVuZGlyKCIvcHJvYy9zZWxm
L2ZkIik7CiAgaWYgKCFkaXIpIHJldHVybiAwOwogIHVuc2lnbmVkIGNvdW50ID0gMDsKICBzdHJ1
Y3QgZGlyZW50ICplbnRyeTsKICB3aGlsZSAoKGVudHJ5ID0gcmVhZGRpcihkaXIpKSAhPSBOVUxM
KSB7CiAgICBpZiAoc3RyY21wKGVudHJ5LT5kX25hbWUsICIuIikgJiYgc3RyY21wKGVudHJ5LT5k
X25hbWUsICIuLiIpKSArK2NvdW50OwogIH0KICBjbG9zZWRpcihkaXIpOwogIHJldHVybiBjb3Vu
dDsKfQoKc3RhdGljIHZvaWQgcHJvY19zdGF0dXMoc2l6ZV90ICpyc3MsIHNpemVfdCAqdmlydCwg
dW5zaWduZWQgKnRocmVhZHMsCiAgICAgICAgICAgICAgICAgICAgICAgIHVuc2lnbmVkICpjcHVf
Y29yZSkgewogICpyc3MgPSAwOyAqdmlydCA9IDA7ICp0aHJlYWRzID0gMTsgKmNwdV9jb3JlID0g
MDsKICBzdGQ6Omlmc3RyZWFtIGluKCIvcHJvYy9zZWxmL3N0YXR1cyIpOwogIHN0ZDo6c3RyaW5n
IGxpbmU7CiAgd2hpbGUgKHN0ZDo6Z2V0bGluZShpbiwgbGluZSkpIHsKICAgIHVuc2lnbmVkIGxv
bmcgdmFsdWUgPSAwOwogICAgaWYgKHNzY2FuZihsaW5lLmNfc3RyKCksICJWbVJTUzogJWx1IGtC
IiwgJnZhbHVlKSA9PSAxKSAqcnNzID0gKHNpemVfdCl2YWx1ZSAqIDEwMjRVOwogICAgZWxzZSBp
ZiAoc3NjYW5mKGxpbmUuY19zdHIoKSwgIlZtU2l6ZTogJWx1IGtCIiwgJnZhbHVlKSA9PSAxKSAq
dmlydCA9IChzaXplX3QpdmFsdWUgKiAxMDI0VTsKICAgIGVsc2UgaWYgKHNzY2FuZihsaW5lLmNf
c3RyKCksICJUaHJlYWRzOiAlbHUiLCAmdmFsdWUpID09IDEpICp0aHJlYWRzID0gKHVuc2lnbmVk
KXZhbHVlOwogICAgZWxzZSBpZiAoc3NjYW5mKGxpbmUuY19zdHIoKSwgIkNwdXNfYWxsb3dlZF9s
aXN0OiAlbHUiLCAmdmFsdWUpID09IDEpICpjcHVfY29yZSA9ICh1bnNpZ25lZCl2YWx1ZTsKICB9
Cn0KCnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgdXBkYXRlX2tlcm5lbF9kcm9wcyhpbnQgZmQp
IHsKICBpZiAoZmQgPCAwKSByZXR1cm4gMDsKICBzdHJ1Y3QgdHBhY2tldF9zdGF0cyBwYWNrZXRf
c3RhdHM7CiAgc29ja2xlbl90IHBhY2tldF9zdGF0c19sZW4gPSBzaXplb2YocGFja2V0X3N0YXRz
KTsKICBtZW1zZXQoJnBhY2tldF9zdGF0cywgMCwgc2l6ZW9mKHBhY2tldF9zdGF0cykpOwogIGlm
IChnZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfU1RBVElTVElDUywKICAgICAgICAg
ICAgICAgICAmcGFja2V0X3N0YXRzLCAmcGFja2V0X3N0YXRzX2xlbikgIT0gMCkgcmV0dXJuIDA7
CiAgZ19rZXJuZWxfZHJvcHMgKz0gcGFja2V0X3N0YXRzLnRwX2Ryb3BzOwogIHJldHVybiBwYWNr
ZXRfc3RhdHMudHBfZHJvcHM7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyBhZ2VudF9zdGF0c19ib2R5
KGludCBmZCwgc2l6ZV90IGZsb3dzX2FjdGl2ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgc2l6ZV90IHBlbmRpbmdfcmVxdWVzdHMsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIHNpemVfdCB3c3NlX2JvZHlfZmxvd3MpIHsKICBkb3VibGUgbm93ID0gd2Fs
bF9zZWNvbmRzKCk7CiAgZG91YmxlIGVsYXBzZWQgPSBub3cgLSBnX3N0YXRzX2xhc3RfYXQ7CiAg
aWYgKGVsYXBzZWQgPCAwLjAwMSkgZWxhcHNlZCA9IDAuMDAxOwogIHVuc2lnbmVkIGxvbmcgbG9u
ZyBrZXJuZWxfZHJvcF9kZWx0YSA9IHVwZGF0ZV9rZXJuZWxfZHJvcHMoZmQpOwogIHVuc2lnbmVk
IGxvbmcgbG9uZyBwYWNrZXRfZGVsdGEgPSBnX2NhcHR1cmVfcGFja2V0cyAtIGdfcHJldl9jYXB0
dXJlX3BhY2tldHM7CiAgdW5zaWduZWQgbG9uZyBsb25nIHBhY2tldF9ieXRlc19kZWx0YSA9IGdf
Y2FwdHVyZV9ieXRlcyAtIGdfcHJldl9jYXB0dXJlX2J5dGVzOwogIHVuc2lnbmVkIGxvbmcgbG9u
ZyBlbWl0dGVkX2RlbHRhID0gZ19ldmVudHNfZW1pdHRlZCAtIGdfcHJldl9ldmVudHNfZW1pdHRl
ZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgaW5fZGVsdGEgPSBnX2V2ZW50c19pbiAtIGdfcHJldl9l
dmVudHNfaW47CiAgdW5zaWduZWQgbG9uZyBsb25nIHB1c2hlZF9kZWx0YSA9IGdfZXZlbnRzX3B1
c2hlZCAtIGdfcHJldl9ldmVudHNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBkcm9wcGVk
X2RlbHRhID0gZ19ldmVudHNfZHJvcHBlZCAtIGdfcHJldl9ldmVudHNfZHJvcHBlZDsKICB1bnNp
Z25lZCBsb25nIGxvbmcgYmF0Y2hlc19wdXNoZWRfZGVsdGEgPSBnX2JhdGNoZXNfcHVzaGVkIC0g
Z19wcmV2X2JhdGNoZXNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBiYXRjaGVzX2ZhaWxl
ZF9kZWx0YSA9IGdfYmF0Y2hlc19mYWlsZWQgLSBnX3ByZXZfYmF0Y2hlc19mYWlsZWQ7CiAgdW5z
aWduZWQgbG9uZyBsb25nIGJ5dGVzX2RlbHRhID0gZ19ieXRlc19wdXNoZWQgLSBnX3ByZXZfYnl0
ZXNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBxdWV1ZV9kZWx0YSA9IGdfZHJvcF9xdWV1
ZSAtIGdfcHJldl9kcm9wX3F1ZXVlOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBodWJfZGVsdGEgPSBn
X2Ryb3BfaHViIC0gZ19wcmV2X2Ryb3BfaHViOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBvdmVyc2l6
ZWRfZGVsdGEgPSBnX2Ryb3Bfb3ZlcnNpemVkIC0gZ19wcmV2X2Ryb3Bfb3ZlcnNpemVkOwogIHVu
c2lnbmVkIGxvbmcgbG9uZyBwaXBlX2Ryb3BfZGVsdGEgPSBnX291dHB1dF9waXBlX2Ryb3BzIC0g
Z19wcmV2X291dHB1dF9waXBlX2Ryb3BzOwogIHN0cnVjdCBydXNhZ2UgdXNhZ2U7CiAgbWVtc2V0
KCZ1c2FnZSwgMCwgc2l6ZW9mKHVzYWdlKSk7CiAgZ2V0cnVzYWdlKFJVU0FHRV9TRUxGLCAmdXNh
Z2UpOwogIGRvdWJsZSB1c2VyX2NwdSA9IHVzYWdlLnJ1X3V0aW1lLnR2X3NlYyArIHVzYWdlLnJ1
X3V0aW1lLnR2X3VzZWMgLyAxMDAwMDAwLjA7CiAgZG91YmxlIHN5c19jcHUgPSB1c2FnZS5ydV9z
dGltZS50dl9zZWMgKyB1c2FnZS5ydV9zdGltZS50dl91c2VjIC8gMTAwMDAwMC4wOwogIGRvdWJs
ZSBjcHVfdG90YWwgPSB1c2VyX2NwdSArIHN5c19jcHU7CiAgZG91YmxlIGNwdV9wY3QgPSAxMDAu
MCAqIChjcHVfdG90YWwgLSBnX3N0YXRzX2xhc3RfY3B1KSAvIGVsYXBzZWQ7CiAgaWYgKGNwdV9w
Y3QgPCAwKSBjcHVfcGN0ID0gMDsKICBzaXplX3QgcnNzID0gMCwgdmlydCA9IDA7CiAgdW5zaWdu
ZWQgdGhyZWFkcyA9IDEsIGNwdV9jb3JlID0gMDsKICBwcm9jX3N0YXR1cygmcnNzLCAmdmlydCwg
JnRocmVhZHMsICZjcHVfY29yZSk7CiAgc3RkOjpzdHJpbmcgcmVhc29uczsKICBpZiAoa2VybmVs
X2Ryb3BfZGVsdGEpIHJlYXNvbnMgKz0gIlwia2VybmVsX2Ryb3BcIiI7CiAgaWYgKGRyb3BwZWRf
ZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9
ICJcInNoaXBfZHJvcFwiIjsgfQogIGlmIChodWJfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5
KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcImh1Yl91bnJlYWNoYWJsZVwiIjsgfQog
IGlmIChxdWV1ZV9kZWx0YSB8fCBwaXBlX2Ryb3BfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5
KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcInF1ZXVlX3ByZXNzdXJlXCIiOyB9CiAg
c3RkOjpvc3RyaW5nc3RyZWFtIG91dDsKICBvdXQgPDwgIntcInNjaGVtYV92ZXJzaW9uXCI6MSxc
InR5cGVcIjpcImFnZW50X3N0YXRzXCIsXCJub2RlXCI6IiA8PCBqc29ucShnX3NoaXBfbm9kZSkK
ICAgICAgPDwgIixcImluc3RhbmNlX2lkXCI6IiA8PCBqc29ucShnX2luc3RhbmNlX2lkKSA8PCAi
LFwic2VxdWVuY2VcIjoiIDw8ICsrZ19zdGF0c19zZXF1ZW5jZQogICAgICA8PCAiLFwib2JzZXJ2
ZWRfYXRcIjoiIDw8ICh1bnNpZ25lZCBsb25nKW5vdyA8PCAiLFwid2luZG93X3NlY29uZHNcIjoi
IDw8IGRvdWJsZV9zdHJpbmcoZWxhcHNlZCkKICAgICAgPDwgIixcIm1vZGVcIjpcImNwcFwiLFwi
c3RhdHVzXCI6IiA8PCAocmVhc29ucy5lbXB0eSgpID8gIlwib2tcIiIgOiAiXCJkZWdyYWRlZFwi
IikKICAgICAgPDwgIixcInJlYXNvbnNcIjpbIiA8PCByZWFzb25zIDw8ICJdLFwiY2FwdHVyZVwi
OnsiCiAgICAgIDw8ICJcInBhY2tldHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19jYXB0dXJl
X3BhY2tldHMpIDw8ICIsXCJwYWNrZXRzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHBhY2tldF9k
ZWx0YSkKICAgICAgPDwgIixcInBhY2tldF9ieXRlc190b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhn
X2NhcHR1cmVfYnl0ZXMpIDw8ICIsXCJwYWNrZXRfYnl0ZXNfZGVsdGFcIjoiIDw8IHVsbF9zdHJp
bmcocGFja2V0X2J5dGVzX2RlbHRhKQogICAgICA8PCAiLFwia2VybmVsX2Ryb3BzX3RvdGFsXCI6
IiA8PCB1bGxfc3RyaW5nKGdfa2VybmVsX2Ryb3BzKSA8PCAiLFwia2VybmVsX2Ryb3BzX2RlbHRh
XCI6IiA8PCB1bGxfc3RyaW5nKGtlcm5lbF9kcm9wX2RlbHRhKQogICAgICA8PCAiLFwia2VybmVs
X2Ryb3BfcGVyY2VudFwiOiIgPDwgZG91YmxlX3N0cmluZygxMDAuMCAqIGtlcm5lbF9kcm9wX2Rl
bHRhIC8gKHBhY2tldF9kZWx0YSA/IHBhY2tldF9kZWx0YSA6IDEpKQogICAgICA8PCAiLFwiaW52
YWxpZF9mcmFtZXNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19pbnZhbGlkX2ZyYW1lcykKICAg
ICAgPDwgIixcImV2ZW50c19lbWl0dGVkX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfZXZlbnRz
X2VtaXR0ZWQpIDw8ICIsXCJldmVudHNfZW1pdHRlZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhl
bWl0dGVkX2RlbHRhKQogICAgICA8PCAiLFwiZmxvd3NfYWN0aXZlXCI6IiA8PCBmbG93c19hY3Rp
dmUgPDwgIixcInBlbmRpbmdfcmVxdWVzdHNcIjoiIDw8IHBlbmRpbmdfcmVxdWVzdHMKICAgICAg
PDwgIixcIndzc2VfYm9keV9mbG93c19hY3RpdmVcIjoiIDw8IHdzc2VfYm9keV9mbG93cwogICAg
ICA8PCAiLFwid3NzZV9ib2R5X2J5dGVzXCI6IiA8PCBnX3dzc2VfYm9keV9ieXRlcwogICAgICA8
PCAiLFwib3V0cHV0X3BpcGVfZHJvcHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19vdXRwdXRf
cGlwZV9kcm9wcykKICAgICAgPDwgIixcIm91dHB1dF9waXBlX2Ryb3BzX2RlbHRhXCI6IiA8PCB1
bGxfc3RyaW5nKHBpcGVfZHJvcF9kZWx0YSkgPDwgIn0sXCJzaGlwcGluZ1wiOnsiCiAgICAgIDw8
ICJcImV2ZW50c19pbl90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19pbikgPDwgIixc
ImV2ZW50c19pbl9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhpbl9kZWx0YSkKICAgICAgPDwgIixc
ImV2ZW50c19wdXNoZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVudHNfcHVzaGVkKSA8
PCAiLFwiZXZlbnRzX3B1c2hlZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwdXNoZWRfZGVsdGEp
CiAgICAgIDw8ICIsXCJldmVudHNfZHJvcHBlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2
ZW50c19kcm9wcGVkKSA8PCAiLFwiZXZlbnRzX2Ryb3BwZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJp
bmcoZHJvcHBlZF9kZWx0YSkKICAgICAgPDwgIixcImRyb3BfY2F1c2VzXCI6e1wicXVldWVfZnVs
bF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2Ryb3BfcXVldWUpIDw8ICIsXCJxdWV1ZV9mdWxs
X2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHF1ZXVlX2RlbHRhKQogICAgICA8PCAiLFwiaHViX2Zh
aWx1cmVfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19kcm9wX2h1YikgPDwgIixcImh1Yl9mYWls
dXJlX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGh1Yl9kZWx0YSkKICAgICAgPDwgIixcIm92ZXJz
aXplZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2Ryb3Bfb3ZlcnNpemVkKSA8PCAiLFwib3Zl
cnNpemVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKG92ZXJzaXplZF9kZWx0YSkgPDwgIn0iCiAg
ICAgIDw8ICIsXCJiYXRjaGVzX3B1c2hlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2JhdGNo
ZXNfcHVzaGVkKSA8PCAiLFwiYmF0Y2hlc19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmco
YmF0Y2hlc19wdXNoZWRfZGVsdGEpCiAgICAgIDw8ICIsXCJiYXRjaGVzX2ZhaWxlZF90b3RhbFwi
OiIgPDwgdWxsX3N0cmluZyhnX2JhdGNoZXNfZmFpbGVkKSA8PCAiLFwiYmF0Y2hlc19mYWlsZWRf
ZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYmF0Y2hlc19mYWlsZWRfZGVsdGEpCiAgICAgIDw8ICIs
XCJieXRlc19wdXNoZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ieXRlc19wdXNoZWQpIDw8
ICIsXCJieXRlc19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYnl0ZXNfZGVsdGEpCiAg
ICAgIDw8ICIsXCJwdXNoX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3RyaW5nKHB1
c2hlZF9kZWx0YSAvIGVsYXBzZWQpCiAgICAgIDw8ICIsXCJwdXNoX2ticHNcIjoiIDw8IGRvdWJs
ZV9zdHJpbmcoOC4wICogYnl0ZXNfZGVsdGEgLyAoMTAwMC4wICogZWxhcHNlZCkpCiAgICAgIDw8
ICIsXCJkcm9wX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3RyaW5nKGRyb3BwZWRf
ZGVsdGEgLyBlbGFwc2VkKQogICAgICA8PCAiLFwiZHJvcF9wZXJjZW50XCI6IiA8PCBkb3VibGVf
c3RyaW5nKDEwMC4wICogZHJvcHBlZF9kZWx0YSAvIChpbl9kZWx0YSA/IGluX2RlbHRhIDogMSkp
CiAgICAgIDw8ICIsXCJxdWV1ZV9kZXB0aF9ldmVudHNcIjoiIDw8IGdfc2hpcF9idWYuc2l6ZSgp
IDw8ICIsXCJxdWV1ZV9jYXBhY2l0eV9ldmVudHNcIjoiIDw8IE1BWF9RVUVVRQogICAgICA8PCAi
LFwicXVldWVfaGlnaF93YXRlcl9ldmVudHNcIjoiIDw8IGdfcXVldWVfaGlnaF93YXRlciA8PCAi
LFwibGFzdF9wdXNoX2h0dHBfc3RhdHVzXCI6IiA8PCBnX2xhc3RfcHVzaF9zdGF0dXMKICAgICAg
PDwgIixcImxhc3Rfc3VjY2Vzc19hdFwiOiIgPDwgKHVuc2lnbmVkIGxvbmcpZ19sYXN0X3N1Y2Nl
c3NfYXQgPDwgIixcImNvbnNlY3V0aXZlX2ZhaWx1cmVzXCI6IiA8PCBnX2NvbnNlY3V0aXZlX2Zh
aWx1cmVzCiAgICAgIDw8ICIsXCJzdGF0c19zYW1wbGVzX2Ryb3BwZWRfdG90YWxcIjoiIDw8IHVs
bF9zdHJpbmcoZ19zdGF0c19kcm9wcGVkKSA8PCAifSxcInJlc291cmNlc1wiOnsiCiAgICAgIDw8
ICJcImNwdV91c2VyX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcodXNlcl9jcHUpIDw8ICIs
XCJjcHVfc3lzdGVtX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcoc3lzX2NwdSkKICAgICAg
PDwgIixcImNwdV9wZXJjZW50X29uZV9jb3JlXCI6IiA8PCBkb3VibGVfc3RyaW5nKGNwdV9wY3Qp
IDw8ICIsXCJyc3NfYnl0ZXNcIjoiIDw8IHJzcwogICAgICA8PCAiLFwidmlydHVhbF9ieXRlc1wi
OiIgPDwgdmlydCA8PCAiLFwib3Blbl9mZHNcIjoiIDw8IGNvdW50X29wZW5fZmRzKCkgPDwgIixc
InRocmVhZHNcIjoiIDw8IHRocmVhZHMKICAgICAgPDwgIn0sXCJsaW1pdHNcIjp7XCJjcHVfY29y
ZVwiOiIgPDwgY3B1X2NvcmUgPDwgIixcImFkZHJlc3Nfc3BhY2VfYnl0ZXNcIjoyNjg0MzU0NTYi
CiAgICAgIDw8ICIsXCJzaGlwX3JhdGVfa2Jwc1wiOiIgPDwgZ19zaGlwX3JhdGVfa2JwcyA8PCAi
LFwiaHR0cF9ib2R5X21heF9ieXRlc1wiOiIgPDwgTUFYX1BPU1RfQllURVMKICAgICAgPDwgIixc
InNoaXBfdGhyZWFkc19tYXhcIjoxLFwid3NzZV9ib2R5X2J5dGVzXCI6IiA8PCBnX3dzc2VfYm9k
eV9ieXRlcyA8PCAifX0iOwogIGdfcHJldl9jYXB0dXJlX3BhY2tldHMgPSBnX2NhcHR1cmVfcGFj
a2V0czsgZ19wcmV2X2NhcHR1cmVfYnl0ZXMgPSBnX2NhcHR1cmVfYnl0ZXM7CiAgZ19wcmV2X2V2
ZW50c19lbWl0dGVkID0gZ19ldmVudHNfZW1pdHRlZDsgZ19wcmV2X2V2ZW50c19pbiA9IGdfZXZl
bnRzX2luOwogIGdfcHJldl9ldmVudHNfcHVzaGVkID0gZ19ldmVudHNfcHVzaGVkOyBnX3ByZXZf
ZXZlbnRzX2Ryb3BwZWQgPSBnX2V2ZW50c19kcm9wcGVkOwogIGdfcHJldl9iYXRjaGVzX3B1c2hl
ZCA9IGdfYmF0Y2hlc19wdXNoZWQ7IGdfcHJldl9iYXRjaGVzX2ZhaWxlZCA9IGdfYmF0Y2hlc19m
YWlsZWQ7CiAgZ19wcmV2X2J5dGVzX3B1c2hlZCA9IGdfYnl0ZXNfcHVzaGVkOyBnX3ByZXZfZHJv
cF9xdWV1ZSA9IGdfZHJvcF9xdWV1ZTsKICBnX3ByZXZfZHJvcF9odWIgPSBnX2Ryb3BfaHViOyBn
X3ByZXZfZHJvcF9vdmVyc2l6ZWQgPSBnX2Ryb3Bfb3ZlcnNpemVkOwogIGdfcHJldl9vdXRwdXRf
cGlwZV9kcm9wcyA9IGdfb3V0cHV0X3BpcGVfZHJvcHM7CiAgZ19zdGF0c19sYXN0X2NwdSA9IGNw
dV90b3RhbDsgZ19zdGF0c19sYXN0X2F0ID0gbm93OwogIHJldHVybiBvdXQuc3RyKCk7Cn0KCnN0
YXRpYyB2b2lkIHNlbmRfYWdlbnRfc3RhdHMoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0aXZlLAog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCBwZW5kaW5nX3JlcXVlc3RzLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCB3c3NlX2JvZHlfZmxvd3MpIHsKICBzdGQ6
OnN0cmluZyBib2R5ID0gYWdlbnRfc3RhdHNfYm9keShmZCwgZmxvd3NfYWN0aXZlLCBwZW5kaW5n
X3JlcXVlc3RzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdzc2VfYm9k
eV9mbG93cyk7CiAgaWYgKGJvZHkuc2l6ZSgpID4gTUFYX1NUQVRTX0JZVEVTIHx8CiAgICAgICFw
b3N0X2JvZHkoZ19lbmRwb2ludCwgIi9hcGkvYWdlbnQvc3RhdHMiLCBib2R5LCAyKSkgewogICAg
KytnX3N0YXRzX2Ryb3BwZWQ7CiAgfQp9CgpzdGF0aWMgYm9vbCB3cml0ZV9ub25ibG9ja2luZ19s
aW5lKGNvbnN0IHN0ZDo6c3RyaW5nICZsaW5lKSB7CiAgaWYgKGxpbmUuc2l6ZSgpICsgMSA+IFBJ
UEVfQlVGKSB7CiAgICArK2dfb3V0cHV0X3BpcGVfZHJvcHM7CiAgICByZXR1cm4gdHJ1ZTsKICB9
CiAgc3RkOjpzdHJpbmcgZnJhbWVkID0gbGluZSArICJcbiI7CiAgc3NpemVfdCB3cml0dGVuOwog
IGRvIHsgd3JpdHRlbiA9IHdyaXRlKFNURE9VVF9GSUxFTk8sIGZyYW1lZC5kYXRhKCksIGZyYW1l
ZC5zaXplKCkpOyB9CiAgd2hpbGUgKHdyaXR0ZW4gPCAwICYmIGVycm5vID09IEVJTlRSICYmIGdf
cnVubmluZyk7CiAgaWYgKHdyaXR0ZW4gPT0gKHNzaXplX3QpZnJhbWVkLnNpemUoKSkgcmV0dXJu
IHRydWU7CiAgaWYgKHdyaXR0ZW4gPCAwICYmIChlcnJubyA9PSBFQUdBSU4gfHwgZXJybm8gPT0g
RVdPVUxEQkxPQ0spKSB7CiAgICArK2dfb3V0cHV0X3BpcGVfZHJvcHM7CiAgICByZXR1cm4gdHJ1
ZTsKICB9CiAgaWYgKHdyaXR0ZW4gPCAwICYmIGVycm5vID09IEVQSVBFKSB7CiAgICBsb2dtc2co
InNoaXBwZXIgcGlwZSBjbG9zZWQ7IHN0b3BwaW5nIGNhcHR1cmUgZm9yIHN1cGVydmlzZWQgcmVz
dGFydCIpOwogIH0gZWxzZSB7CiAgICBsb2dtc2coInNoaXBwZXIgcGlwZSB3cml0ZSBmYWlsZWQ7
IHN0b3BwaW5nIGNhcHR1cmUgZm9yIHN1cGVydmlzZWQgcmVzdGFydCIpOwogIH0KICBnX3J1bm5p
bmcgPSAwOwogIHJldHVybiBmYWxzZTsKfQoKc3RhdGljIHZvaWQgZW1pdF9jYXB0dXJlX3N0YXRz
X2ludGVybmFsKGludCBmZCwgc2l6ZV90IGZsb3dzX2FjdGl2ZSwKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90IHdzc2VfYm9keV9mbG93cykgewog
IHN0ZDo6c3RyaW5nIGZ1bGwgPSBhZ2VudF9zdGF0c19ib2R5KGZkLCBmbG93c19hY3RpdmUsIHBl
bmRpbmdfcmVxdWVzdHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3Nz
ZV9ib2R5X2Zsb3dzKTsKICBjb25zdCBzdGQ6OnN0cmluZyBtYXJrZXIgPSAiXCJjYXB0dXJlXCI6
IjsKICBzaXplX3Qgc3RhcnQgPSBmdWxsLmZpbmQobWFya2VyKTsKICBzaXplX3QgZW5kID0gZnVs
bC5maW5kKCIsXCJzaGlwcGluZ1wiOiIsIHN0YXJ0KTsKICBpZiAoc3RhcnQgPT0gc3RkOjpzdHJp
bmc6Om5wb3MgfHwgZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSB7CiAgICArK2dfb3V0cHV0X3Bp
cGVfZHJvcHM7CiAgICByZXR1cm47CiAgfQogIHN0YXJ0ICs9IG1hcmtlci5zaXplKCk7CiAgd3Jp
dGVfbm9uYmxvY2tpbmdfbGluZSgie1wiX250X2ludGVybmFsXCI6XCJjYXB0dXJlX3N0YXRzX3Yx
XCIsXCJjYXB0dXJlXCI6IiArCiAgICAgICAgICAgICAgICAgICAgICAgICBmdWxsLnN1YnN0cihz
dGFydCwgZW5kIC0gc3RhcnQpICsgIn0iKTsKfQoKc3RhdGljIGludCBydW5fc3RhdHNfZml4dHVy
ZSgpIHsKICBnX3NoaXBfbm9kZSA9ICJmaXh0dXJlLW5vZGUiOwogIGdfaW5zdGFuY2VfaWQgPSAi
Zml4dHVyZS0xIjsKICBnX3N0YXRzX2xhc3RfYXQgPSB3YWxsX3NlY29uZHMoKSAtIDMwLjA7CiAg
Z19jYXB0dXJlX3BhY2tldHMgPSAxMDA7CiAgZ19jYXB0dXJlX2J5dGVzID0gNjQwMDsKICBnX2V2
ZW50c19lbWl0dGVkID0gZ19ldmVudHNfaW4gPSAxMDsKICBnX2V2ZW50c19wdXNoZWQgPSA4Owog
IGdfZXZlbnRzX2Ryb3BwZWQgPSBnX2Ryb3BfcXVldWUgPSAyOwogIHN0ZDo6c3RyaW5nIGJvZHkg
PSBhZ2VudF9zdGF0c19ib2R5KC0xLCAzLCAyLCAxKTsKICBpZiAoYm9keS5zaXplKCkgPiBNQVhf
U1RBVFNfQllURVMpIHJldHVybiA0MDsKICBpZiAoYm9keS5maW5kKCJcInR5cGVcIjpcImFnZW50
X3N0YXRzXCIiKSA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIDQxOwogIGlmIChib2R5LmZp
bmQoIlwiZHJvcF9wZXJjZW50XCI6MjAuMDAwMCIpID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1
cm4gNDI7CiAgaWYgKGJvZHkuZmluZCgiXCJtb2RlXCI6XCJjcHBcIiIpID09IHN0ZDo6c3RyaW5n
OjpucG9zKSByZXR1cm4gNDM7CiAgc3RkOjpjb3V0IDw8IGJvZHkgPDwgIlxuIjsKICByZXR1cm4g
MDsKfQoKc3RhdGljIHZvaWQgZW1pdF9ldmVudChjb25zdCBFdmVudCAmZSkgewogIHN0ZDo6b3N0
cmluZ3N0cmVhbSBzczsKICBzcyA8PCAie1widHNcIjoiIDw8IGUudHMgPDwgIixcImhvc3RcIjoi
IDw8IGpzb25xKGUuaG9zdCkgPDwgIixcInNyY1wiOlwicGNhcFwiLFwic2VydmljZVwiOiIgPDwg
anNvbnEoZS5zZXJ2aWNlKQogICAgIDw8ICIsXCJtZXRob2RcIjoiIDw8IGpzb25xKGUubWV0aG9k
KSA8PCAiLFwicGF0aFwiOiIgPDwganNvbnEoZS5wYXRoKSA8PCAiLFwidXNlclwiOiIgPDwganNv
bnEoZS51c2VyKQogICAgIDw8ICIsXCJzY2hlbWVcIjoiIDw8IGpzb25xKGUuc2NoZW1lKQogICAg
IDw8ICIsXCJiYXNpY191c2VyXCI6IiA8PCAoZS5iYXNpY191c2VyLmVtcHR5KCkgPyAibnVsbCIg
OiBqc29ucShlLmJhc2ljX3VzZXIpKQogICAgIDw8ICIsXCJ3c3NlX3VzZXJcIjoiIDw8IChlLndz
c2VfdXNlci5lbXB0eSgpID8gIm51bGwiIDoganNvbnEoZS53c3NlX3VzZXIpKQogICAgIDw8ICIs
XCJzb3VyY2VfcHJvYmVcIjpcInBjYXAtaHR0cC1jcHBcIixcImhvc3RfaGRyXCI6IiA8PCBqc29u
cShlLmhvc3RfaGRyKQogICAgIDw8ICIsXCJ1c2VyX2FnZW50XCI6IiA8PCBqc29ucShlLnVzZXJf
YWdlbnQpIDw8ICIsXCJ4X2ZvcndhcmRlZF9mb3JcIjoiIDw8IGpzb25xKGUueGZmKQogICAgIDw8
ICIsXCJjYWxsZXJcIjoiIDw8IGpzb25xKGUuY2FsbGVyKSA8PCAiLFwiY2FsbGVyX3BvcnRcIjoi
IDw8IGUuY2FsbGVyX3BvcnQgPDwgIixcImRzdF9pcFwiOiIgPDwganNvbnEoZS5kc3RfaXApCiAg
ICAgPDwgIixcImRzdF9wb3J0XCI6IiA8PCBlLmRzdF9wb3J0IDw8ICIsXCJ0cmFjZXBhcmVudFwi
OiIgPDwganNvbnEoZS50cmFjZXBhcmVudCkgPDwgIixcInRyYWNlX2lkXCI6IiA8PCBqc29ucShl
LnRyYWNlX2lkKQogICAgIDw8ICIsXCJzZXJ2aWNlX2lkXCI6bnVsbCxcIm1vZHVsZV9pZFwiOlwi
cGNhcC1odHRwLWNwcFwiLFwicmVxX2J5dGVzXCI6IiA8PCBlLnJlcV9ieXRlczsKICBpZiAoZS5o
YXNfc3RhdHVzKSBzcyA8PCAiLFwic3RhdHVzXCI6IiA8PCBlLnN0YXR1czsgZWxzZSBzcyA8PCAi
LFwic3RhdHVzXCI6bnVsbCI7CiAgaWYgKGUuaGFzX2R1cmF0aW9uKSBzcyA8PCAiLFwiZHVyYXRp
b25fbXNcIjoiIDw8IGUuZHVyYXRpb25fbXM7IGVsc2Ugc3MgPDwgIixcImR1cmF0aW9uX21zXCI6
bnVsbCI7CiAgaWYgKGUuaGFzX3Jlc3ApIHNzIDw8ICIsXCJyZXNwX2J5dGVzXCI6IiA8PCBlLnJl
c3BfYnl0ZXM7IGVsc2Ugc3MgPDwgIixcInJlc3BfYnl0ZXNcIjpudWxsIjsKICBzcyA8PCAifSI7
CiAgKytnX2V2ZW50c19lbWl0dGVkOwoKICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSkgewogICAg
KytnX2V2ZW50c19pbjsKICAgIGlmIChnX3NoaXBfYnVmLnNpemUoKSA+PSBNQVhfUVVFVUUpIHsK
ICAgICAgZ19zaGlwX2J1Zi5lcmFzZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgICArK2dfZXZl
bnRzX2Ryb3BwZWQ7CiAgICAgICsrZ19kcm9wX3F1ZXVlOwogICAgfQogICAgZ19zaGlwX2J1Zi5w
dXNoX2JhY2soc3Muc3RyKCkpOwogICAgaWYgKGdfc2hpcF9idWYuc2l6ZSgpID4gZ19xdWV1ZV9o
aWdoX3dhdGVyKSBnX3F1ZXVlX2hpZ2hfd2F0ZXIgPSBnX3NoaXBfYnVmLnNpemUoKTsKICB9IGVs
c2UgewogICAgd3JpdGVfbm9uYmxvY2tpbmdfbGluZShzcy5zdHIoKSk7CiAgfQp9CgpzdGF0aWMg
dm9pZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1aW50MzJfdCBzX2lwLCB1bnNpZ25l
ZCBzcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1aW50MzJfdCBkX2lwLCB1bnNpZ25l
ZCBkcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0
ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpOwoKc3RhdGljIHZvaWQgZmx1c2hfb2xkZXN0
KHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewog
IGlmIChwZW5kaW5nLmVtcHR5KCkpIHJldHVybjsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIGl0ID0gcGVuZGluZy5iZWdpbigpOwogIGlmICgh
aXQtPnNlY29uZC5lbXB0eSgpKSB7CiAgICBlbWl0X2V2ZW50KGl0LT5zZWNvbmRbMF0uZXYpOwog
ICAgaXQtPnNlY29uZC5lcmFzZShpdC0+c2Vjb25kLmJlZ2luKCkpOwogIH0KICBpZiAoaXQtPnNl
Y29uZC5lbXB0eSgpKSB7CiAgICBwZW5kaW5nLmVyYXNlKGl0KTsKICB9Cn0Kc3RhdGljIHZvaWQg
Zmx1c2hfYWxsX3BlbmRpbmcoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5n
PiA+ICZwZW5kaW5nKSB7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5n
PiA+OjppdGVyYXRvciBwOwogIGZvciAocCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5n
LmVuZCgpOyArK3ApIHsKICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcC0+c2Vjb25kLnNpemUo
KTsgKytpKSB7CiAgICAgIGVtaXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgIH0KICB9CiAg
cGVuZGluZy5jbGVhcigpOwp9CnN0YXRpYyB2b2lkIGZsdXNoX2luY29tcGxldGVfd3NzZShzdGQ6
Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcp
IHsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgZjsKICBmb3IgKGYgPSBmbG93
cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOyArK2YpIHsKICAgIGlmIChmLT5zZWNvbmQuYXdh
aXRpbmdfYm9keSAmJiAhZi0+c2Vjb25kLmV2ZW50LmJhc2ljX3VzZXIuZW1wdHkoKSkgewogICAg
ICBxdWV1ZV9yZXF1ZXN0KGYtPnNlY29uZC5ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+Zmlyc3Qu
c3BvcnQsCiAgICAgICAgICAgICAgICAgICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3QuZHBvcnQs
IHBlbmRpbmcpOwogICAgfQogIH0KICBmbG93cy5jbGVhcigpOwp9CnN0YXRpYyB2b2lkIHN3ZWVw
KHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cywgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nLCB0aW1lX3Qgbm93KSB7CiAgc3RkOjptYXA8Rmxv
d0tleSwgRmxvdz46Oml0ZXJhdG9yIGYsIGZuOwogIGZvciAoZiA9IGZsb3dzLmJlZ2luKCk7IGYg
IT0gZmxvd3MuZW5kKCk7KSB7CiAgICBmbiA9IGY7ICsrZm47CiAgICBpZiAoKHVuc2lnbmVkKShu
b3cgLSBmLT5zZWNvbmQudG91Y2hlZCkgPiBGTE9XX1RUTCkgewogICAgICBpZiAoZi0+c2Vjb25k
LmF3YWl0aW5nX2JvZHkgJiYgIWYtPnNlY29uZC5ldmVudC5iYXNpY191c2VyLmVtcHR5KCkpIHsK
ICAgICAgICBxdWV1ZV9yZXF1ZXN0KGYtPnNlY29uZC5ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+
Zmlyc3Quc3BvcnQsCiAgICAgICAgICAgICAgICAgICAgICBmLT5maXJzdC5kX2lwLCBmLT5maXJz
dC5kcG9ydCwgcGVuZGluZyk7CiAgICAgIH0KICAgICAgZmxvd3MuZXJhc2UoZik7CiAgICB9CiAg
ICBmID0gZm47CiAgfQogIGxvbmcgbG9uZyBjdXJyZW50X21zID0gKGxvbmcgbG9uZylub3cgKiAx
MDAwTEw7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVy
YXRvciBwLCBwbjsKICBmb3IgKHAgPSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQo
KTspIHsKICAgIHBuID0gcDsgKytwbjsKICAgIHNpemVfdCBpID0gMDsKICAgIHdoaWxlIChpIDwg
cC0+c2Vjb25kLnNpemUoKSkgewogICAgICBpZiAoY3VycmVudF9tcyAtIHAtPnNlY29uZFtpXS5z
dGFydGVkX21zID4gKGxvbmcgbG9uZylQRU5ESU5HX1RUTCAqIDEwMDBMTCkgewogICAgICAgIGVt
aXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vj
b25kLmJlZ2luKCkgKyBpKTsKICAgICAgfSBlbHNlIHsKICAgICAgICArK2k7CiAgICAgIH0KICAg
IH0KICAgIGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgIHAgPSBw
bjsKICB9Cn0Kc3RhdGljIHNpemVfdCBmaW5kX2h0dHBfc3RhcnQoY29uc3Qgc3RkOjpzdHJpbmcg
JnMpIHsKICBjb25zdCBjaGFyICptW10gPSB7ICJHRVQgIiwgIlBPU1QgIiwgIlBVVCAiLCAiREVM
RVRFICIsICJQQVRDSCAiLCAiSEVBRCAiLCAiT1BUSU9OUyAiIH07CiAgc2l6ZV90IGJlc3QgPSBz
dGQ6OnN0cmluZzo6bnBvczsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDc7ICsraSkgewogICAg
c2l6ZV90IHBvcyA9IHMuZmluZChtW2ldKTsKICAgIGlmIChwb3MgIT0gc3RkOjpzdHJpbmc6Om5w
b3MgJiYgKGJlc3QgPT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwgcG9zIDwgYmVzdCkpIGJlc3QgPSBw
b3M7CiAgfQogIHJldHVybiBiZXN0Owp9CgpzdGF0aWMgYm9vbCBnX21vbml0b3JlZF9wb3J0c1s2
NTUzNl07CgpzdGF0aWMgdm9pZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1aW50MzJf
dCBzX2lwLCB1bnNpZ25lZCBzcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1aW50MzJf
dCBkX2lwLCB1bnNpZ25lZCBkcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1h
cDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBQYWNrZXRL
ZXkgcms7CiAgcmsuc19pcCA9IGRfaXA7IHJrLnNwb3J0ID0gKHVpbnQxNl90KWRwb3J0OwogIHJr
LmRfaXAgPSBzX2lwOyByay5kcG9ydCA9ICh1aW50MTZfdClzcG9ydDsKICBpZiAocGVuZGluZy5m
aW5kKHJrKSA9PSBwZW5kaW5nLmVuZCgpICYmIHBlbmRpbmcuc2l6ZSgpID49IE1BWF9QRU5ESU5H
KSB7CiAgICBmbHVzaF9vbGRlc3QocGVuZGluZyk7CiAgfQogIHN0ZDo6dmVjdG9yPFBlbmRpbmc+
ICZxdWV1ZSA9IHBlbmRpbmdbcmtdOwogIGlmIChxdWV1ZS5zaXplKCkgPj0gTUFYX1BFTkRJTkdf
UEVSX0ZMT1cpIHsKICAgIGVtaXRfZXZlbnQocXVldWVbMF0uZXYpOwogICAgcXVldWUuZXJhc2Uo
cXVldWUuYmVnaW4oKSk7CiAgfQogIHF1ZXVlLnB1c2hfYmFjayhQZW5kaW5nKGUsIG5vd19tcygp
KSk7Cn0KCnN0YXRpYyBzaXplX3QgYWN0aXZlX3dzc2VfZmxvd3MoY29uc3Qgc3RkOjptYXA8Rmxv
d0tleSwgRmxvdz4gJmZsb3dzKSB7CiAgc2l6ZV90IGNvdW50ID0gMDsKICBzdGQ6Om1hcDxGbG93
S2V5LCBGbG93Pjo6Y29uc3RfaXRlcmF0b3IgaXQ7CiAgZm9yIChpdCA9IGZsb3dzLmJlZ2luKCk7
IGl0ICE9IGZsb3dzLmVuZCgpOyArK2l0KQogICAgaWYgKGl0LT5zZWNvbmQuYXdhaXRpbmdfYm9k
eSkgKytjb3VudDsKICByZXR1cm4gY291bnQ7Cn0KCnN0YXRpYyBib29sIGhhbmRsZV9wYWNrZXQo
Y29uc3QgdW5zaWduZWQgY2hhciAqYnVmLCBzaXplX3QgbiwgY29uc3Qgc3RkOjpzdHJpbmcgJm5v
ZGUsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAmcG9ydHMsCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICAodm9pZClwb3J0czsKICBp
ZiAobiA8IDM0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNo
b3J0IGV0ID0gbnRvaHMocmVhZF91MTYoYnVmICsgMTIpKTsKICBpZiAoZXQgPT0gRVRIX1BfODAy
MVEpIHsgaWYgKG4gPCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiAr
IDE2KSk7IG9mZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkg
cmV0dXJuIGZhbHNlOwogIHVuc2lnbmVkIGNoYXIgaWhsID0gKHVuc2lnbmVkIGNoYXIpKGJ1Zltv
ZmZdICYgMTUpICogNDsKICBpZiAoKGJ1ZltvZmZdID4+IDQpICE9IDQgfHwgYnVmW29mZiArIDld
ICE9IDYgfHwgbiA8IG9mZiArIGlobCArIDIwKSByZXR1cm4gZmFsc2U7CgogIHVpbnQzMl90IHNf
aXAgPSByZWFkX3UzMihidWYgKyBvZmYgKyAxMik7CiAgdWludDMyX3QgZF9pcCA9IHJlYWRfdTMy
KGJ1ZiArIG9mZiArIDE2KTsKICBzaXplX3QgdG8gPSBvZmYgKyBpaGw7CiAgdW5zaWduZWQgc3Bv
cnQgPSBudG9ocyhyZWFkX3UxNihidWYgKyB0bykpOwogIHVuc2lnbmVkIGRwb3J0ID0gbnRvaHMo
cmVhZF91MTYoYnVmICsgdG8gKyAyKSk7CiAgdW5zaWduZWQgZG9mZiA9IChidWZbdG8gKyAxMl0g
Pj4gNCkgKiA0OwogIGlmIChuIDwgdG8gKyBkb2ZmKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hh
ciAqcGF5bG9hZCA9IChjb25zdCBjaGFyICopKGJ1ZiArIHRvICsgZG9mZik7CiAgc2l6ZV90IHBs
ZW4gPSBuIC0gdG8gLSBkb2ZmOwogIGlmICghcGxlbikgcmV0dXJuIGZhbHNlOwoKICB0aW1lX3Qg
bm93ID0gdGltZShOVUxMKTsKICBib29sIGRzdF9tb24gPSAoZHBvcnQgPCA2NTUzNikgPyBnX21v
bml0b3JlZF9wb3J0c1tkcG9ydF0gOiBmYWxzZTsKICBib29sIHNyY19tb24gPSAoc3BvcnQgPCA2
NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tzcG9ydF0gOiBmYWxzZTsKCiAgaWYgKHNyY19tb24g
JiYgIWRzdF9tb24gJiYgcGxlbiA+PSA1KSB7CiAgICBpZiAobWVtY21wKHBheWxvYWQsICJIVFRQ
LyIsIDUpID09IDApIHsKICAgICAgUGFja2V0S2V5IGs7CiAgICAgIGsuc19pcCA9IHNfaXA7IGsu
c3BvcnQgPSAodWludDE2X3Qpc3BvcnQ7IGsuZF9pcCA9IGRfaXA7IGsuZHBvcnQgPSAodWludDE2
X3QpZHBvcnQ7CiAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4g
Pjo6aXRlcmF0b3IgcCA9IHBlbmRpbmcuZmluZChrKTsKICAgICAgaWYgKHAgIT0gcGVuZGluZy5l
bmQoKSAmJiAhcC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgICAgICBpbnQgc3Q7IHVuc2lnbmVkIGNs
OwogICAgICAgIGlmIChwYXJzZV9yZXNwb25zZShwYXlsb2FkLCBwbGVuLCAmc3QsICZjbCkpIHsK
ICAgICAgICAgIEV2ZW50IGUgPSBwLT5zZWNvbmRbMF0uZXY7CiAgICAgICAgICBlLnN0YXR1cyA9
IHN0OyBlLmhhc19zdGF0dXMgPSB0cnVlOwogICAgICAgICAgZS5kdXJhdGlvbl9tcyA9IChsb25n
KShub3dfbXMoKSAtIHAtPnNlY29uZFswXS5zdGFydGVkX21zKTsKICAgICAgICAgIGlmIChlLmR1
cmF0aW9uX21zIDwgMCkgZS5kdXJhdGlvbl9tcyA9IDA7CiAgICAgICAgICBlLmhhc19kdXJhdGlv
biA9IHRydWU7CiAgICAgICAgICBpZiAoY2wpIHsgZS5yZXNwX2J5dGVzID0gY2w7IGUuaGFzX3Jl
c3AgPSB0cnVlOyB9CiAgICAgICAgICBlbWl0X2V2ZW50KGUpOwogICAgICAgICAgcC0+c2Vjb25k
LmVyYXNlKHAtPnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgIGlmIChwLT5zZWNvbmQuZW1wdHko
KSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICB9CiAgICAgIH0KICAgIH0KICAgIHJldHVybiB0
cnVlOwogIH0KICB1bnNpZ25lZCBjaGFyIHRjcF9mbGFncyA9IGJ1Zlt0byArIDEzXTsKICBpZiAo
IWRzdF9tb24pIHsKICAgIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7IC8qIEZJTiBvciBSU1QgKi8K
ICAgICAgRmxvd0tleSByZms7IHJmay5zX2lwID0gZF9pcDsgcmZrLnNwb3J0ID0gKHVpbnQxNl90
KWRwb3J0OyByZmsuZF9pcCA9IHNfaXA7IHJmay5kcG9ydCA9ICh1aW50MTZfdClzcG9ydDsKICAg
ICAgZmxvd3MuZXJhc2UocmZrKTsKICAgIH0KICAgIHJldHVybiBmYWxzZTsKICB9CgogIEZsb3dL
ZXkgZms7CiAgZmsuc19pcCA9IHNfaXA7IGZrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OyBmay5k
X2lwID0gZF9pcDsgZmsuZHBvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgaWYgKHRjcF9mbGFncyAm
IDB4MDUpIHsgLyogRklOIG9yIFJTVCAqLwogICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0
ZXJhdG9yIGV4aXN0aW5nID0gZmxvd3MuZmluZChmayk7CiAgICBpZiAoZXhpc3RpbmcgIT0gZmxv
d3MuZW5kKCkgJiYgZXhpc3RpbmctPnNlY29uZC5hd2FpdGluZ19ib2R5ICYmCiAgICAgICAgIWV4
aXN0aW5nLT5zZWNvbmQuZXZlbnQuYmFzaWNfdXNlci5lbXB0eSgpKSB7CiAgICAgIHF1ZXVlX3Jl
cXVlc3QoZXhpc3RpbmctPnNlY29uZC5ldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBw
ZW5kaW5nKTsKICAgIH0KICAgIGZsb3dzLmVyYXNlKGZrKTsKICAgIHJldHVybiB0cnVlOwogIH0K
CiAgaWYgKGZsb3dzLmZpbmQoZmspID09IGZsb3dzLmVuZCgpICYmIGZsb3dzLnNpemUoKSA+PSBN
QVhfRkxPV1MpIHsKICAgIGZsb3dzLmVyYXNlKGZsb3dzLmJlZ2luKCkpOwogIH0KICBGbG93ICZm
bCA9IGZsb3dzW2ZrXTsgZmwudG91Y2hlZCA9IG5vdzsKICBpZiAoZmwuYXdhaXRpbmdfYm9keSkg
ewogICAgc3RkOjpzdHJpbmcgbmV4dF9zZWdtZW50KHBheWxvYWQsIHBsZW4pOwogICAgaWYgKCFm
bC5ldmVudC5iYXNpY191c2VyLmVtcHR5KCkgJiYgZmluZF9odHRwX3N0YXJ0KG5leHRfc2VnbWVu
dCkgPT0gMCkgewogICAgICBFdmVudCBwcmV2aW91cyA9IGZsLmV2ZW50OwogICAgICBmbCA9IEZs
b3coKTsKICAgICAgZmwudG91Y2hlZCA9IG5vdzsKICAgICAgcXVldWVfcmVxdWVzdChwcmV2aW91
cywgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nKTsKICAgIH0gZWxzZSB7CiAgICAg
IHNpemVfdCByZW1haW5pbmcgPSBmbC5ib2R5X2dvYWwgPiBmbC5idWYuc2l6ZSgpID8gZmwuYm9k
eV9nb2FsIC0gZmwuYnVmLnNpemUoKSA6IDA7CiAgICAgIGlmIChyZW1haW5pbmcpIGZsLmJ1Zi5h
cHBlbmQocGF5bG9hZCwgcGxlbiA8IHJlbWFpbmluZyA/IHBsZW4gOiByZW1haW5pbmcpOwogICAg
ICBzdGQ6OnN0cmluZyB1c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC5idWYpOwog
ICAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkgfHwgZmwuYnVmLnNpemUoKSA+PSBmbC5ib2R5X2dv
YWwpIHsKICAgICAgICBFdmVudCBldmVudCA9IGZsLmV2ZW50OwogICAgICAgIGlmICghdXNlcm5h
bWUuZW1wdHkoKSkgewogICAgICAgICAgZXZlbnQud3NzZV91c2VyID0gdXNlcm5hbWU7IGV2ZW50
LnVzZXIgPSB1c2VybmFtZTsgZXZlbnQuc2NoZW1lID0gIndzc2UiOwogICAgICAgIH0KICAgICAg
ICBmbG93cy5lcmFzZShmayk7CiAgICAgICAgcXVldWVfcmVxdWVzdChldmVudCwgc19pcCwgc3Bv
cnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nKTsKICAgICAgfQogICAgICByZXR1cm4gdHJ1ZTsKICAg
IH0KICB9CiAgZmwuYnVmLmFwcGVuZChwYXlsb2FkLCBwbGVuKTsKICBpZiAoZmwuYnVmLnNpemUo
KSA+IE1BWF9IRUFERVIpIHsgZmxvd3MuZXJhc2UoZmspOyByZXR1cm4gZmFsc2U7IH0KICB3aGls
ZSAodHJ1ZSkgewogICAgc2l6ZV90IHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0KGZsLmJ1Zik7CiAg
ICBpZiAoc3RhcnQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsgZmwuYnVmLmNsZWFyKCk7IGJyZWFr
OyB9CiAgICBpZiAoc3RhcnQgPiAwKSBmbC5idWYuZXJhc2UoMCwgc3RhcnQpOwogICAgc2l6ZV90
IGVuZCA9IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgaWYgKGVuZCA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcykgYnJlYWs7CiAgICBFdmVudCBlOyBSZXF1ZXN0TWV0YSBtZXRhOyBlLnRzID0gbm93
OyBlLmhvc3QgPSBub2RlOyBlLnNlcnZpY2UgPSAicG9ydDoiICsgbnVtKGRwb3J0KTsgZS5jYWxs
ZXIgPSBpcF90b19zdHIoc19pcCk7IGUuY2FsbGVyX3BvcnQgPSBzcG9ydDsgZS5kc3RfaXAgPSBp
cF90b19zdHIoZF9pcCk7IGUuZHN0X3BvcnQgPSBkcG9ydDsgZS5yZXFfYnl0ZXMgPSAodW5zaWdu
ZWQpKGVuZCArIDQpOwogICAgaWYgKCFwYXJzZV9yZXF1ZXN0KGZsLmJ1Zi5kYXRhKCksIGVuZCwg
JmUsICZtZXRhKSkgeyBmbC5idWYuZXJhc2UoMCwgZW5kICsgNCk7IGNvbnRpbnVlOyB9CiAgICBm
bC5idWYuZXJhc2UoMCwgZW5kICsgNCk7CiAgICBpZiAoZ193c3NlX2JvZHlfYnl0ZXMgJiYKICAg
ICAgICBpc19zb2FwX2NvbnRlbnRfdHlwZShtZXRhLmNvbnRlbnRfdHlwZSkgJiYgbWV0YS5oYXNf
Y29udGVudF9sZW5ndGggJiYKICAgICAgICBtZXRhLmNvbnRlbnRfbGVuZ3RoID4gMCAmJgogICAg
ICAgIGxvd2VyKG1ldGEudHJhbnNmZXJfZW5jb2RpbmcpLmZpbmQoImNodW5rZWQiKSA9PSBzdGQ6
OnN0cmluZzo6bnBvcyAmJgogICAgICAgIGFjdGl2ZV93c3NlX2Zsb3dzKGZsb3dzKSA8IE1BWF9X
U1NFX0JPRFlfRkxPV1MpIHsKICAgICAgZmwuZXZlbnQgPSBlOwogICAgICBmbC5hd2FpdGluZ19i
b2R5ID0gdHJ1ZTsKICAgICAgZmwuYm9keV9nb2FsID0gbWV0YS5jb250ZW50X2xlbmd0aCA8IGdf
d3NzZV9ib2R5X2J5dGVzID8gbWV0YS5jb250ZW50X2xlbmd0aCA6IGdfd3NzZV9ib2R5X2J5dGVz
OwogICAgICBpZiAoZmwuYm9keV9nb2FsID4gTUFYX1dTU0VfQk9EWV9CWVRFUykgZmwuYm9keV9n
b2FsID0gTUFYX1dTU0VfQk9EWV9CWVRFUzsKICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBmbC5i
b2R5X2dvYWwpIGZsLmJ1Zi5yZXNpemUoZmwuYm9keV9nb2FsKTsKICAgICAgc3RkOjpzdHJpbmcg
dXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwuYnVmKTsKICAgICAgaWYgKCF1c2Vy
bmFtZS5lbXB0eSgpIHx8IGZsLmJ1Zi5zaXplKCkgPj0gZmwuYm9keV9nb2FsKSB7CiAgICAgICAg
RXZlbnQgZXZlbnQgPSBmbC5ldmVudDsKICAgICAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkpIHsK
ICAgICAgICAgIGV2ZW50Lndzc2VfdXNlciA9IHVzZXJuYW1lOyBldmVudC51c2VyID0gdXNlcm5h
bWU7IGV2ZW50LnNjaGVtZSA9ICJ3c3NlIjsKICAgICAgICB9CiAgICAgICAgZmxvd3MuZXJhc2Uo
ZmspOwogICAgICAgIHF1ZXVlX3JlcXVlc3QoZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9y
dCwgcGVuZGluZyk7CiAgICAgIH0KICAgICAgcmV0dXJuIHRydWU7CiAgICB9CiAgICBxdWV1ZV9y
ZXF1ZXN0KGUsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZyk7CiAgfQogIGlmIChm
bC5idWYuZW1wdHkoKSkgewogICAgZmxvd3MuZXJhc2UoZmspOwogIH0KICByZXR1cm4gdHJ1ZTsK
fQoKc3RhdGljIGJvb2wgYXR0YWNoX2JwZihpbnQgZmQsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2ln
bmVkPiAmcG9ydHMpIHsKICBpZiAocG9ydHMuZW1wdHkoKSkgcmV0dXJuIGZhbHNlOwogIHN0ZDo6
dmVjdG9yPHN0cnVjdCBzb2NrX2ZpbHRlcj4gZjsgc2l6ZV90IGk7CiAgLyogRHVhbC1wYXRoIGNC
UEY6IFBhdGggQSAoc3RhbmRhcmQgSVB2NCkgYW5kIFBhdGggQiAoODAyLjFRIFZMQU4gdGFnZ2Vk
IElQdjQpLiAqLwogIHVuc2lnbmVkIE4gPSAodW5zaWduZWQpcG9ydHMuc2l6ZSgpOwogIHVuc2ln
bmVkIHJlamVjdCA9IDExICsgTiAqIDg7CiAgdW5zaWduZWQgYWNjZXB0ID0gcmVqZWN0ICsgMTsK
ICBzdHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmluZSBBREQoQyxKLFQsSykgZG8geyBcCiAgdW5z
aWduZWQgX2p0ID0gKHVuc2lnbmVkKShKKSwgX2pmID0gKHVuc2lnbmVkKShUKTsgXAogIGlmIChf
anQgPiBVQ0hBUl9NQVggfHwgX2pmID4gVUNIQVJfTUFYKSByZXR1cm4gZmFsc2U7IFwKICB4LmNv
ZGU9KEMpOyB4Lmp0PSh1bnNpZ25lZCBjaGFyKV9qdDsgeC5qZj0odW5zaWduZWQgY2hhcilfamY7
IHguaz0oSyk7IFwKICBmLnB1c2hfYmFjayh4KTsgXAp9IHdoaWxlKDApCiAgLyogWzBdIExvYWQg
RXRoZXJUeXBlIGF0IG9mZnNldCAxMiAqLwogIEFERChCUEZfTER8QlBGX0h8QlBGX0FCUywgMCwg
MCwgMTIpOwogIC8qIFsxXSBJZiBzdGFuZGFyZCBJUHY0ICgweDA4MDApLCBqdW1wIG92ZXIgUGF0
aCBCICg2ICsgNCpOIGluc3RydWN0aW9ucykgdG8gUGF0aCBBICovCiAgQUREKEJQRl9KTVB8QlBG
X0pFUXxCUEZfSywgKHVuc2lnbmVkKSg2ICsgNCAqIE4pLCAwLCBFVEhfUF9JUF9IT1NUKTsKCiAg
LyogLS0tIFBhdGggQjogODAyLjFRIFZMQU4gKGluZGV4IDIpIC0tLSAqLwogIC8qIFsyXSBJZiBu
b3QgODAyLjFRICgweDgxMDApLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9L
LCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBFVEhfUF84
MDIxUV9IT1NUKTsKICAvKiBbM10gTG9hZCBlbmNhcHN1bGF0ZWQgRXRoZXJUeXBlIGF0IG9mZnNl
dCAxNiAqLwogIEFERChCUEZfTER8QlBGX0h8QlBGX0FCUywgMCwgMCwgMTYpOwogIC8qIFs0XSBJ
ZiBlbmNhcHN1bGF0ZWQgIT0gSVB2NCwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxC
UEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRI
X1BfSVBfSE9TVCk7CiAgLyogWzVdIExvYWQgSVAgcHJvdG9jb2wgYXQgb2Zmc2V0IDI3ICgyMyAr
IDQpICovCiAgQUREKEJQRl9MRHxCUEZfQnxCUEZfQUJTLCAwLCAwLCAyNyk7CiAgLyogWzZdIElm
IG5vdCBUQ1AsIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNp
Z25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICAv
KiBbN10gTG9hZCBJSEwgYXQgb2Zmc2V0IDE4ICgxNCArIDQpICovCiAgQUREKEJQRl9MRFh8QlBG
X0J8QlBGX01TSCwgMCwgMCwgMTgpOwogIC8qIERlc3RpbmF0aW9uIHBvcnQgY2hlY2tzIGZvciBW
TEFOICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBG
X0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDIwKTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0g
KHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0
LCAwLCBwb3J0c1tpXSk7CiAgfQogIC8qIFNvdXJjZSBwb3J0IGNoZWNrcyBmb3IgVkxBTiAqLwog
IGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZf
SHxCUEZfSU5ELCAwLCAwLCAxOCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25l
ZClmLnNpemUoKSAtIDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwgcG9ydHMuc2l6ZSgpIC0gMSkg
PyAwIDogKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpOwogICAgQUREKEJQRl9KTVB8
QlBGX0pFUXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQoKICAvKiAtLS0gUGF0aCBBOiBT
dGFuZGFyZCBJUHY0IC0tLSAqLwogIC8qIExvYWQgSVAgcHJvdG9jb2wgYXQgb2Zmc2V0IDIzICov
CiAgQUREKEJQRl9MRHxCUEZfQnxCUEZfQUJTLCAwLCAwLCAyMyk7CiAgLyogSWYgbm90IFRDUCwg
cmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWpl
Y3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgSVBQUk9UT19UQ1ApOwogIC8qIExvYWQgSUhM
IGF0IG9mZnNldCAxNCAqLwogIEFERChCUEZfTERYfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE0KTsK
ICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNrcyBmb3Igc3RhbmRhcmQgSVB2NCAqLwogIGZvciAo
aSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZf
SU5ELCAwLCAwLCAxNik7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNp
emUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0p
OwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVja3MgZm9yIHN0YW5kYXJkIElQdjQgKi8KICBmb3Ig
KGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBG
X0lORCwgMCwgMCwgMTQpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5z
aXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6
IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9K
RVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgLyogW3JlamVjdF0gRHJvcCBwYWNr
ZXQgKi8KICBBREQoQlBGX1JFVHxCUEZfSywgMCwgMCwgMCk7CiAgLyogW2FjY2VwdF0gQWNjZXB0
IHBhY2tldCAoMjA0OCBieXRlcykgKi8KICBBREQoQlBGX1JFVHxCUEZfSywgMCwgMCwgQUNDRVBU
KTsKI3VuZGVmIEFERAogIGlmIChmLnNpemUoKSA+IDQwOTYpIHJldHVybiBmYWxzZTsKICBzdHJ1
Y3Qgc29ja19mcHJvZyBwcm9nOyBwcm9nLmxlbiA9ICh1bnNpZ25lZCBzaG9ydClmLnNpemUoKTsg
cHJvZy5maWx0ZXIgPSAmZlswXTsKI2lmbmRlZiBTT19BVFRBQ0hfRklMVEVSCiNkZWZpbmUgU09f
QVRUQUNIX0ZJTFRFUiAyNgojZW5kaWYKICByZXR1cm4gc2V0c29ja29wdChmZCwgU09MX1NPQ0tF
VCwgU09fQVRUQUNIX0ZJTFRFUiwgJnByb2csIHNpemVvZihwcm9nKSkgPT0gMDsKfQoKc3RydWN0
IE1tYXBSaW5nIHsKICB2b2lkICpyaW5nOwogIHNpemVfdCByaW5nX3NpemU7CiAgdW5zaWduZWQg
YmxvY2tfc2l6ZTsKICB1bnNpZ25lZCBibG9ja19ucjsKICB1bnNpZ25lZCBmcmFtZV9zaXplOwog
IHVuc2lnbmVkIGZyYW1lX25yOwogIHVuc2lnbmVkIGZyYW1lc19wZXJfYmxvY2s7CiAgdW5zaWdu
ZWQgZnJhbWVfaWR4OwoKICBNbWFwUmluZygpIDogcmluZyhNQVBfRkFJTEVEKSwgcmluZ19zaXpl
KDApLCBibG9ja19zaXplKDY1NTM2KSwgYmxvY2tfbnIoNjQpLAogICAgICAgICAgICAgICBmcmFt
ZV9zaXplKDIwNDgpLCBmcmFtZV9ucigyMDQ4KSwgZnJhbWVzX3Blcl9ibG9jaygzMiksIGZyYW1l
X2lkeCgwKSB7fQp9OwoKc3RhdGljIGJvb2wgdmFsaWRfcmluZ19nZW9tZXRyeShjb25zdCBNbWFw
UmluZyAmbXIpIHsKICBjb25zdCBzaXplX3Qgc2l6ZV9tYXggPSAoc2l6ZV90KS0xOwogIGxvbmcg
cGFnZV9zaXplID0gc3lzY29uZihfU0NfUEFHRVNJWkUpOwogIGlmIChwYWdlX3NpemUgPD0gMCkg
cmV0dXJuIGZhbHNlOwogIGlmIChtci5ibG9ja19zaXplID09IDAgfHwgbXIuYmxvY2tfc2l6ZSAl
ICh1bnNpZ25lZCBsb25nKXBhZ2Vfc2l6ZSAhPSAwKSByZXR1cm4gZmFsc2U7CiAgaWYgKG1yLmZy
YW1lX3NpemUgPCBUUEFDS0VUMl9IRFJMRU4gfHwKICAgICAgbXIuZnJhbWVfc2l6ZSAlIFRQQUNL
RVRfQUxJR05NRU5UICE9IDApIHJldHVybiBmYWxzZTsKICBpZiAobXIuYmxvY2tfc2l6ZSAlIG1y
LmZyYW1lX3NpemUgIT0gMCkgcmV0dXJuIGZhbHNlOwogIHVuc2lnbmVkIGZyYW1lc19wZXJfYmxv
Y2sgPSBtci5ibG9ja19zaXplIC8gbXIuZnJhbWVfc2l6ZTsKICBpZiAoZnJhbWVzX3Blcl9ibG9j
ayA9PSAwIHx8IG1yLmJsb2NrX25yID09IDApIHJldHVybiBmYWxzZTsKICBpZiAoZnJhbWVzX3Bl
cl9ibG9jayA+IFVJTlRfTUFYIC8gbXIuYmxvY2tfbnIpIHJldHVybiBmYWxzZTsKICBpZiAoZnJh
bWVzX3Blcl9ibG9jayAqIG1yLmJsb2NrX25yICE9IG1yLmZyYW1lX25yKSByZXR1cm4gZmFsc2U7
CiAgaWYgKChzaXplX3QpbXIuYmxvY2tfc2l6ZSA+IHNpemVfbWF4IC8gKHNpemVfdCltci5ibG9j
a19ucikgcmV0dXJuIGZhbHNlOwogIGlmICgoc2l6ZV90KW1yLmJsb2NrX3NpemUgKiAoc2l6ZV90
KW1yLmJsb2NrX25yICE9IDRVICogMTAyNFUgKiAxMDI0VSkgcmV0dXJuIGZhbHNlOwogIHJldHVy
biB0cnVlOwp9CgpzdGF0aWMgYm9vbCBzZXR1cF9tbWFwX3JpbmcoaW50IGZkLCBNbWFwUmluZyAm
bXIpIHsKICBpZiAoIXZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSB7CiAgICBsb2dtc2coImludmFs
aWQgZml4ZWQgVFBBQ0tFVF9WMiByaW5nIGdlb21ldHJ5Iik7CiAgICByZXR1cm4gZmFsc2U7CiAg
fQogIGludCB2ZXIgPSBUUEFDS0VUX1YyOwogIGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VU
LCBQQUNLRVRfVkVSU0lPTiwgJnZlciwgc2l6ZW9mKHZlcikpIDwgMCkgewogICAgcmV0dXJuIGZh
bHNlOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9yZXEgcmVxOwogIG1lbXNldCgmcmVxLCAwLCBzaXpl
b2YocmVxKSk7CiAgcmVxLnRwX2Jsb2NrX3NpemUgPSBtci5ibG9ja19zaXplOwogIHJlcS50cF9i
bG9ja19uciA9IG1yLmJsb2NrX25yOwogIHJlcS50cF9mcmFtZV9zaXplID0gbXIuZnJhbWVfc2l6
ZTsKICByZXEudHBfZnJhbWVfbnIgPSBtci5mcmFtZV9ucjsKCiAgaWYgKHNldHNvY2tvcHQoZmQs
IFNPTF9QQUNLRVQsIFBBQ0tFVF9SWF9SSU5HLCAmcmVxLCBzaXplb2YocmVxKSkgPCAwKSB7CiAg
ICByZXR1cm4gZmFsc2U7CiAgfQogIG1yLnJpbmdfc2l6ZSA9IChzaXplX3QpcmVxLnRwX2Jsb2Nr
X3NpemUgKiAoc2l6ZV90KXJlcS50cF9ibG9ja19ucjsKICBtci5mcmFtZXNfcGVyX2Jsb2NrID0g
cmVxLnRwX2Jsb2NrX3NpemUgLyByZXEudHBfZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9pZHggPSAw
OwoKICBtci5yaW5nID0gbW1hcChOVUxMLCBtci5yaW5nX3NpemUsIFBST1RfUkVBRCB8IFBST1Rf
V1JJVEUsIE1BUF9TSEFSRUQsIGZkLCAwKTsKICBpZiAobXIucmluZyA9PSBNQVBfRkFJTEVEKSB7
CiAgICBtci5yaW5nX3NpemUgPSAwOwogICAgcmV0dXJuIGZhbHNlOwogIH0KICByZXR1cm4gdHJ1
ZTsKfQoKc3RhdGljIGJvb2wgcmVsZWFzZV9tbWFwX3JpbmcoaW50IGZkLCBNbWFwUmluZyAmbXIp
IHsKICBib29sIG9rID0gdHJ1ZTsKICBpZiAobXIucmluZyAhPSBNQVBfRkFJTEVEKSB7CiAgICBp
ZiAobXVubWFwKG1yLnJpbmcsIG1yLnJpbmdfc2l6ZSkgIT0gMCkgb2sgPSBmYWxzZTsKICAgIG1y
LnJpbmcgPSBNQVBfRkFJTEVEOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9yZXEgZW1wdHlfcmVxOwog
IG1lbXNldCgmZW1wdHlfcmVxLCAwLCBzaXplb2YoZW1wdHlfcmVxKSk7CiAgaWYgKHNldHNvY2tv
cHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9SWF9SSU5HLAogICAgICAgICAgICAgICAgICZlbXB0
eV9yZXEsIHNpemVvZihlbXB0eV9yZXEpKSAhPSAwKSBvayA9IGZhbHNlOwogIG1yLnJpbmdfc2l6
ZSA9IDA7CiAgcmV0dXJuIG9rOwp9CgpzdGF0aWMgYm9vbCB2YWxpZF9yaW5nX2ZyYW1lKGNvbnN0
IHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1
bnNpZ25lZCBmcmFtZV9zaXplLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCAq
cGFja2V0X29mZnNldCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3QgKnBhY2tl
dF9sZW5ndGgpIHsKICBjb25zdCB1bnNpZ25lZCBtYWMgPSBoZHItPnRwX21hYzsKICBjb25zdCB1
bnNpZ25lZCBuZXQgPSBoZHItPnRwX25ldDsKICBjb25zdCB1bnNpZ25lZCBzbmFwbGVuID0gaGRy
LT50cF9zbmFwbGVuOwogIGNvbnN0IHVuc2lnbmVkIHdpcmVfbGVuID0gaGRyLT50cF9sZW47CiAg
aWYgKG1hYyA8IFRQQUNLRVQyX0hEUkxFTiB8fCBtYWMgPiBmcmFtZV9zaXplKSByZXR1cm4gZmFs
c2U7CiAgaWYgKHNuYXBsZW4gPiB3aXJlX2xlbiB8fCBzbmFwbGVuID4gZnJhbWVfc2l6ZSAtIG1h
YykgcmV0dXJuIGZhbHNlOwogIGlmIChuZXQgPCBtYWMgfHwgbmV0ID4gbWFjICsgc25hcGxlbikg
cmV0dXJuIGZhbHNlOwogICpwYWNrZXRfb2Zmc2V0ID0gbWFjOwogICpwYWNrZXRfbGVuZ3RoID0g
c25hcGxlbjsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGludCBydW5fcmluZ19maXh0dXJlKCkg
ewogIE1tYXBSaW5nIG1yOwogIGlmICghdmFsaWRfcmluZ19nZW9tZXRyeShtcikpIHJldHVybiAy
MDsKICB1bnNpZ25lZCBjaGFyIGZyYW1lWzIwNDhdOwogIG1lbXNldChmcmFtZSwgMCwgc2l6ZW9m
KGZyYW1lKSk7CiAgc3RydWN0IHRwYWNrZXQyX2hkciAqaGRyID0gKHN0cnVjdCB0cGFja2V0Ml9o
ZHIgKilmcmFtZTsKICBzaXplX3Qgb2ZmID0gMCwgbGVuID0gMDsKICBoZHItPnRwX21hYyA9IFRQ
QUNLRVQyX0hEUkxFTjsKICBoZHItPnRwX25ldCA9IFRQQUNLRVQyX0hEUkxFTiArIDE0OwogIGhk
ci0+dHBfc25hcGxlbiA9IDEyODsKICBoZHItPnRwX2xlbiA9IDEyODsKICBpZiAoIXZhbGlkX3Jp
bmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSB8fAogICAgICBvZmYgIT0g
VFBBQ0tFVDJfSERSTEVOIHx8IGxlbiAhPSAxMjgpIHJldHVybiAyMTsKICBoZHItPnRwX21hYyA9
IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2Yo
ZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDIyOwogIGhkci0+dHBfbWFjID0gVFBBQ0tFVDJf
SERSTEVOOwogIGhkci0+dHBfc25hcGxlbiA9IHNpemVvZihmcmFtZSk7CiAgaGRyLT50cF9sZW4g
PSBzaXplb2YoZnJhbWUpOwogIGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1l
KSwgJm9mZiwgJmxlbikpIHJldHVybiAyMzsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjk7CiAgaGRy
LT50cF9sZW4gPSAxMjg7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUp
LCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDI0OwogIGhkci0+dHBfc25hcGxlbiA9IDEyODsKICBoZHIt
PnRwX2xlbiA9IDEyODsKICBoZHItPnRwX25ldCA9IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAgaWYg
KHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJu
IDI1OwogIG1yLmZyYW1lX25yKys7CiAgaWYgKHZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSByZXR1
cm4gMjY7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2ZpeHR1cmUoKSB7CiAgc3RkOjpz
dHJpbmcgcmVxID0gIkdFVCAvYXBpL2l0ZW1zP3g9MSBIVFRQLzEuMVxyXG5Ib3N0OiBhcGkubG9j
YWxcclxuQXV0aG9yaXphdGlvbjogQmFzaWMgWVd4cFkyVTZjMlZqY21WMFxyXG5UcmFjZXBhcmVu
dDogMDAtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYtMDEyMzQ1Njc4OWFiY2RlZi0w
MVxyXG5cclxuIjsKICBFdmVudCBlOyBSZXF1ZXN0TWV0YSBtZXRhOyBlLnRzID0gMTcwMDAwMDAw
MDsgZS5ob3N0ID0gImNwcC1ub2RlIjsgZS5zZXJ2aWNlID0gInBvcnQ6ODA4MCI7IGUuY2FsbGVy
ID0gIjEwLjAuMC45IjsgZS5jYWxsZXJfcG9ydCA9IDUxMDAwOyBlLmRzdF9pcCA9ICIxMC4wLjAu
MiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZClyZXEuc2l6ZSgp
OyBwYXJzZV9yZXF1ZXN0KHJlcS5kYXRhKCksIHJlcS5zaXplKCkgLSA0LCAmZSwgJm1ldGEpOyBl
LnN0YXR1cyA9IDIwMDsgZS5oYXNfc3RhdHVzID0gdHJ1ZTsgZS5kdXJhdGlvbl9tcyA9IDM7IGUu
aGFzX2R1cmF0aW9uID0gdHJ1ZTsgZS5yZXNwX2J5dGVzID0gNDI7IGUuaGFzX3Jlc3AgPSB0cnVl
OyBlbWl0X2V2ZW50KGUpOyByZXR1cm4gMDsKfQoKc3RhdGljIGludCBydW5fd3NzZV9maXh0dXJl
KCkgewogIGNvbnN0IGNoYXIgKm5hbWVzcGFjZXNbXSA9IHsKICAgICJodHRwOi8vZG9jcy5vYXNp
cy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEtd3NzLXdzc2VjdXJpdHktc2VjZXh0
LTEuMC54c2QiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMDcvc2Vj
ZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzEyL3NlY2V4dCIs
CiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwMy8wNi9zZWNleHQiCiAgfTsK
ICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDQ7ICsraSkgewogICAgc3RkOjpzdHJpbmcgYm9keSA9
ICI8czpFbnZlbG9wZSB4bWxuczpzPSd1cm46c29hcCcgeG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5n
KG5hbWVzcGFjZXNbaV0pICsKICAgICAgIic+PHM6SGVhZGVyPjx3OlVzZXJuYW1lVG9rZW4+PHc6
VXNlcm5hbWU+bmF0aXZlLmZpeHR1cmU8L3c6VXNlcm5hbWU+IgogICAgICAiPHc6UGFzc3dvcmQ+
U0VOU0lUSVZFX1BBU1NXT1JEPC93OlBhc3N3b3JkPjwvdzpVc2VybmFtZVRva2VuPjwvczpIZWFk
ZXI+IjsKICAgIHN0ZDo6c3RyaW5nIHVzZXIgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoYm9keSk7
CiAgICBpZiAodXNlciAhPSAibmF0aXZlLmZpeHR1cmUiKSByZXR1cm4gMzsKICAgIHN0ZDo6Y291
dCA8PCB1c2VyIDw8ICJcbiI7CiAgfQogIHN0ZDo6c3RyaW5nIG1hbGljaW91cyA9ICI8IURPQ1RZ
UEUgeCBbPCFFTlRJVFkgcHcgJ3NlY3JldCc+XT48dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9JyIg
KwogICAgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKyAiJz48dzpVc2VybmFtZT4mcHc7PC93
OlVzZXJuYW1lPjwvdzpVc2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5h
bWUobWFsaWNpb3VzKS5lbXB0eSgpKSByZXR1cm4gNDsKICBzdGQ6OnN0cmluZyB3cm9uZ19ucyA9
ICI8dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9J3Vybjpub3Qtd3NzZSc+PHc6VXNlcm5hbWU+d3Jv
bmc8L3c6VXNlcm5hbWU+PC93OlVzZXJuYW1lVG9rZW4+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91
c2VybmFtZSh3cm9uZ19ucykuZW1wdHkoKSkgcmV0dXJuIDU7CiAgc3RkOjpzdHJpbmcgdW5uYW1l
c3BhY2VkID0gIjxVc2VybmFtZVRva2VuPjxVc2VybmFtZT53cm9uZzwvVXNlcm5hbWU+PC9Vc2Vy
bmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5hbWUodW5uYW1lc3BhY2VkKS5l
bXB0eSgpKSByZXR1cm4gNjsKICBzdGQ6OnN0cmluZyBlc2NhcGVkID0gIjx3OlVzZXJuYW1lVG9r
ZW4geG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbMF0pICsKICAgICInPjx3OlVz
ZXJuYW1lPm5hdGl2ZSZhbXA7Zml4dHVyZTwvdzpVc2VybmFtZT4iOwogIGlmIChleHRyYWN0X3dz
c2VfdXNlcm5hbWUoZXNjYXBlZCkgIT0gIm5hdGl2ZSZmaXh0dXJlIikgcmV0dXJuIDc7CiAgc3Rk
OjpzdHJpbmcgdG9vX2xvbmcgPSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSciICsgc3RkOjpz
dHJpbmcobmFtZXNwYWNlc1swXSkgKwogICAgIic+PHc6VXNlcm5hbWU+IiArIHN0ZDo6c3RyaW5n
KE1BWF9XU1NFX1VTRVJOQU1FICsgMSwgJ3gnKSArICI8L3c6VXNlcm5hbWU+IjsKICBpZiAoIWV4
dHJhY3Rfd3NzZV91c2VybmFtZSh0b29fbG9uZykuZW1wdHkoKSkgcmV0dXJuIDg7CiAgcmV0dXJu
IDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2R1YWxfYXV0aF9maXh0dXJlKCkgewogIGNvbnN0IHN0ZDo6
c3RyaW5nIGJvZHkgPQogICAgIjxzOkVudmVsb3BlIHhtbG5zOnM9J3Vybjpzb2FwJyB4bWxuczp3
PSdodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS8iCiAgICAib2FzaXMtMjAw
NDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNkJz48czpIZWFkZXI+PHc6VXNlcm5hbWVU
b2tlbj4iCiAgICAiPHc6VXNlcm5hbWU+c29hcC51c2VyPC93OlVzZXJuYW1lPjx3OlBhc3N3b3Jk
PlNFTlNJVElWRV9QQVNTV09SRDwvdzpQYXNzd29yZD4iCiAgICAiPC93OlVzZXJuYW1lVG9rZW4+
PC9zOkhlYWRlcj48L3M6RW52ZWxvcGU+IjsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gcmVxdWVzdDsK
ICByZXF1ZXN0IDw8ICJQT1NUIC9zb2FwIEhUVFAvMS4xXHJcbkhvc3Q6IGZpeHR1cmVcclxuIgog
ICAgICAgICAgPDwgIkF1dGhvcml6YXRpb246IEJhc2ljIFltRnphV011ZFhObGNqcHdZWE56ZDI5
eVpBPT1cclxuIgogICAgICAgICAgPDwgIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vc29hcCt4
bWxcclxuQ29udGVudC1MZW5ndGg6ICIKICAgICAgICAgIDw8IGJvZHkuc2l6ZSgpIDw8ICJcclxu
XHJcbiIgPDwgYm9keTsKICBjb25zdCBzdGQ6OnN0cmluZyBwYXlsb2FkID0gcmVxdWVzdC5zdHIo
KTsKCiAgc3RkOjp2ZWN0b3I8dW5zaWduZWQgY2hhcj4gcGFja2V0KDE0ICsgMjAgKyAyMCArIHBh
eWxvYWQuc2l6ZSgpLCAwKTsKICBwYWNrZXRbMTJdID0gMHgwODsgcGFja2V0WzEzXSA9IDB4MDA7
CiAgcGFja2V0WzE0XSA9IDB4NDU7IHBhY2tldFsyM10gPSBJUFBST1RPX1RDUDsKICBwYWNrZXRb
MjZdID0gMTkyOyBwYWNrZXRbMjddID0gMDsgcGFja2V0WzI4XSA9IDI7IHBhY2tldFsyOV0gPSAy
OwogIHBhY2tldFszMF0gPSAxOTI7IHBhY2tldFszMV0gPSAwOyBwYWNrZXRbMzJdID0gMjsgcGFj
a2V0WzMzXSA9IDE7CiAgdW5zaWduZWQgc2hvcnQgc3BvcnQgPSBodG9ucyg1MTAwMCksIGRwb3J0
ID0gaHRvbnMoODA4MCk7CiAgbWVtY3B5KCZwYWNrZXRbMzRdLCAmc3BvcnQsIHNpemVvZihzcG9y
dCkpOwogIG1lbWNweSgmcGFja2V0WzM2XSwgJmRwb3J0LCBzaXplb2YoZHBvcnQpKTsKICBwYWNr
ZXRbNDZdID0gNVUgPDwgNDsgcGFja2V0WzQ3XSA9IDB4MTg7CiAgbWVtY3B5KCZwYWNrZXRbNTRd
LCBwYXlsb2FkLmRhdGEoKSwgcGF5bG9hZC5zaXplKCkpOwoKICBnX3dzc2VfYm9keV9ieXRlcyA9
IDgxOTI7CiAgbWVtc2V0KGdfbW9uaXRvcmVkX3BvcnRzLCAwLCBzaXplb2YoZ19tb25pdG9yZWRf
cG9ydHMpKTsKICBnX21vbml0b3JlZF9wb3J0c1s4MDgwXSA9IHRydWU7CiAgZ19lbmRwb2ludC5j
bGVhcigpOwogIGluaXRfcm5nKCk7CiAgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBvcnRzKDEsIDgw
ODApOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+IGZsb3dzOwogIHN0ZDo6bWFwPFBhY2tldEtl
eSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiBwZW5kaW5nOwogIGlmICghaGFuZGxlX3BhY2tldCgm
cGFja2V0WzBdLCBwYWNrZXQuc2l6ZSgpLCAiY3BwLWR1YWwtZml4dHVyZSIsCiAgICAgICAgICAg
ICAgICAgICAgIHBvcnRzLCBmbG93cywgcGVuZGluZykpIHJldHVybiA5OwogIGlmICghZmxvd3Mu
ZW1wdHkoKSB8fCBwZW5kaW5nLnNpemUoKSAhPSAxKSByZXR1cm4gMTA7CiAgZmx1c2hfYWxsX3Bl
bmRpbmcocGVuZGluZyk7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3dzc2Vfc2l6
ZShjb25zdCBjaGFyICp2YWx1ZSwgc2l6ZV90ICpyZXN1bHQpIHsKICBpZiAoIXZhbHVlIHx8ICEq
dmFsdWUpIHJldHVybiBmYWxzZTsKICBzaXplX3QgbiA9IDA7CiAgaWYgKCFwYXJzZV9kZWNpbWFs
X3NpemUodmFsdWUsIHN0cmxlbih2YWx1ZSksICZuKSB8fCBuID4gTUFYX1dTU0VfQk9EWV9CWVRF
UykgcmV0dXJuIGZhbHNlOwogICpyZXN1bHQgPSBuOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMg
Ym9vbCBkcm9wX2FsbF9jYXBhYmlsaXRpZXMoKSB7CiAgc3RydWN0IF9fdXNlcl9jYXBfaGVhZGVy
X3N0cnVjdCBoZWFkZXI7CiAgc3RydWN0IF9fdXNlcl9jYXBfZGF0YV9zdHJ1Y3QgZGF0YVsyXTsK
ICBtZW1zZXQoJmhlYWRlciwgMCwgc2l6ZW9mKGhlYWRlcikpOwogIG1lbXNldChkYXRhLCAwLCBz
aXplb2YoZGF0YSkpOwogIGhlYWRlci52ZXJzaW9uID0gX0xJTlVYX0NBUEFCSUxJVFlfVkVSU0lP
Tl8zOwogIGhlYWRlci5waWQgPSAwOwogIHJldHVybiBzeXNjYWxsKFNZU19jYXBzZXQsICZoZWFk
ZXIsIGRhdGEpID09IDA7Cn0KCnN0YXRpYyBpbnQgb3Blbl9jYXB0dXJlX3NvY2tldChjb25zdCBz
dGQ6OnN0cmluZyAmaWZhY2UsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBz
dGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgTW1hcFJpbmcgJnJpbmcpIHsKICBpbnQgZmQgPSBzb2NrZXQoQUZfUEFDS0VULCBTT0NLX1JB
VywgaHRvbnMoRVRIX1BfQUxMKSk7CiAgaWYgKGZkIDwgMCkgeyBwZXJyb3IoIkFGX1BBQ0tFVCIp
OyByZXR1cm4gLTE7IH0KICBpbnQgcmIgPSA4ICogMTAyNCAqIDEwMjQ7CiAgc2V0c29ja29wdChm
ZCwgU09MX1NPQ0tFVCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihyYikpOwogIGlmICghYXR0YWNo
X2JwZihmZCwgcG9ydHMpKSB7CiAgICBsb2dtc2coIkJQRiBhdHRhY2ggZmFpbGVkOyByZWZ1c2lu
ZyB1bmZpbHRlcmVkIGNhcHR1cmUiKTsKICAgIGNsb3NlKGZkKTsKICAgIHJldHVybiAtMTsKICB9
CgogIHN0cnVjdCBzb2NrYWRkcl9sbCBzYTsKICBtZW1zZXQoJnNhLCAwLCBzaXplb2Yoc2EpKTsK
ICBzYS5zbGxfZmFtaWx5ID0gQUZfUEFDS0VUOwogIHNhLnNsbF9wcm90b2NvbCA9IGh0b25zKEVU
SF9QX0FMTCk7CiAgaWYgKCFpZmFjZS5lbXB0eSgpKSB7CiAgICBzYS5zbGxfaWZpbmRleCA9IChp
bnQpaWZfbmFtZXRvaW5kZXgoaWZhY2UuY19zdHIoKSk7CiAgICBpZiAoIXNhLnNsbF9pZmluZGV4
KSB7CiAgICAgIGxvZ21zZygiYmFkIGludGVyZmFjZSIpOwogICAgICBjbG9zZShmZCk7CiAgICAg
IHJldHVybiAtMTsKICAgIH0KICB9CiAgaWYgKGJpbmQoZmQsIChzdHJ1Y3Qgc29ja2FkZHIgKikm
c2EsIHNpemVvZihzYSkpIDwgMCkgewogICAgcGVycm9yKCJiaW5kIik7CiAgICBjbG9zZShmZCk7
CiAgICByZXR1cm4gLTE7CiAgfQogIGlmICghc2V0dXBfbW1hcF9yaW5nKGZkLCByaW5nKSkgewog
ICAgbG9nbXNnKCJUUEFDS0VUX1YyIHNldHVwIGZhaWxlZDsgcmVmdXNpbmcgbm9uLXJpbmcgZmFs
bGJhY2siKTsKICAgIGNsb3NlKGZkKTsKICAgIHJldHVybiAtMTsKICB9CiAgaWYgKCFkcm9wX2Fs
bF9jYXBhYmlsaXRpZXMoKSkgewogICAgbG9nbXNnKCJjYXBhYmlsaXR5IGRyb3AgZmFpbGVkOyBy
ZWZ1c2luZyB1bnNhZmUgY2FwdHVyZSIpOwogICAgcmVsZWFzZV9tbWFwX3JpbmcoZmQsIHJpbmcp
OwogICAgY2xvc2UoZmQpOwogICAgcmV0dXJuIC0xOwogIH0KICByZXR1cm4gZmQ7Cn0KCnN0YXRp
YyBpbnQgcnVuX2NhcGFiaWxpdHlfcHJvYmUoY29uc3Qgc3RkOjpzdHJpbmcgJmlmYWNlLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAm
cG9ydHMpIHsKICBNbWFwUmluZyByaW5nOwogIGludCBmZCA9IG9wZW5fY2FwdHVyZV9zb2NrZXQo
aWZhY2UsIHBvcnRzLCByaW5nKTsKICBpZiAoZmQgPCAwKSByZXR1cm4gMjsKCiAgYm9vbCByZWxl
YXNlZCA9IHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5nKTsKICBjbG9zZShmZCk7CiAgaWYgKCFy
ZWxlYXNlZCkgewogICAgbG9nbXNnKCJUUEFDS0VUX1YyIHByb2JlIGNsZWFudXAgZmFpbGVkIik7
CiAgICByZXR1cm4gMjsKICB9CiAgcmV0dXJuIDA7Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFy
ICoqYXJndikgewogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLWZpeHR1cmUi
KSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsx
XSwgIi0td3NzZS1maXh0dXJlIikpIHJldHVybiBydW5fd3NzZV9maXh0dXJlKCk7CiAgaWYgKGFy
Z2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0tZHVhbC1hdXRoLWZpeHR1cmUiKSkgcmV0dXJu
IHJ1bl9kdWFsX2F1dGhfZml4dHVyZSgpOwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3Zb
MV0sICItLXJpbmctZml4dHVyZSIpKSByZXR1cm4gcnVuX3JpbmdfZml4dHVyZSgpOwogIGlmIChh
cmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLXNoaXAtcmF0ZS1maXh0dXJlIikpIHJldHVy
biBydW5fc2hpcF9yYXRlX2ZpeHR1cmUoKTsKICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2
WzFdLCAiLS1zdGF0cy1maXh0dXJlIikpIHJldHVybiBydW5fc3RhdHNfZml4dHVyZSgpOwogIHN0
ZDo6c3RyaW5nIGlmYWNlOyBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gcG9ydHM7IGludCBpOyBpbnQg
d29ya2VycyA9IDE7CiAgc3RkOjpzdHJpbmcgZW5kcG9pbnQ7CiAgYm9vbCBjYXBhYmlsaXR5X3By
b2JlID0gZmFsc2U7CiAgY29uc3QgY2hhciAqd3NzZV9lbnYgPSBnZXRlbnYoIk5UX1dTU0VfQk9E
WV9CWVRFUyIpOwogIGlmICh3c3NlX2VudiAmJiAhcGFyc2Vfd3NzZV9zaXplKHdzc2VfZW52LCAm
Z193c3NlX2JvZHlfYnl0ZXMpKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgIndzc2UgYm9keSBieXRl
cyBtdXN0IGJlIGluIHJhbmdlIDAuLjY1NTM2XG4iKTsgcmV0dXJuIDI7CiAgfQogIGNvbnN0IGNo
YXIgKnJhdGVfZW52ID0gZ2V0ZW52KCJOVF9TSElQX1JBVEVfS0JQUyIpOwogIGlmIChyYXRlX2Vu
diAmJiAqcmF0ZV9lbnYpIGdfc2hpcF9yYXRlX2ticHMgPSAodW5zaWduZWQpYXRvaShyYXRlX2Vu
dik7CiAgY29uc3QgY2hhciAqc3RhdHNfZW52ID0gZ2V0ZW52KCJOVF9TVEFUU19JTlRFUlZBTF9T
RUMiKTsKICBpZiAoc3RhdHNfZW52ICYmICpzdGF0c19lbnYpIGdfc3RhdHNfaW50ZXJ2YWxfc2Vj
ID0gKHVuc2lnbmVkKWF0b2koc3RhdHNfZW52KTsKICBmb3IgKGkgPSAxOyBpIDwgYXJnYzsgKytp
KSB7CiAgICBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWkiKSAmJiBpICsgMSA8IGFyZ2MpIGlmYWNl
ID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLXAiKSAmJiBpICsg
MSA8IGFyZ2MpIHsKICAgICAgd2hpbGUgKGkgKyAxIDwgYXJnYyAmJiBhcmd2W2kgKyAxXVswXSAh
PSAnLScpIHsKICAgICAgICBjaGFyICpxID0gc3RydG9rKGFyZ3ZbKytpXSwgIiwgIik7CiAgICAg
ICAgd2hpbGUgKHEpIHsgbG9uZyBwID0gYXRvbChxKTsgaWYgKHZhbGlkX3BvcnQoKHVuc2lnbmVk
KXApKSBwb3J0cy5wdXNoX2JhY2soKHVuc2lnbmVkKXApOyBxID0gc3RydG9rKE5VTEwsICIsICIp
OyB9CiAgICAgIH0KICAgIH0KICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tZW5kcG9p
bnQiKSAmJiBpICsgMSA8IGFyZ2MpIGVuZHBvaW50ID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAo
IXN0cmNtcChhcmd2W2ldLCAiLS1zaGlwLXJhdGUta2JwcyIpICYmIGkgKyAxIDwgYXJnYykgZ19z
aGlwX3JhdGVfa2JwcyA9ICh1bnNpZ25lZClhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICgh
c3RyY21wKGFyZ3ZbaV0sICItLXN0YXRzLWludGVydmFsLXNlYyIpICYmIGkgKyAxIDwgYXJnYykg
Z19zdGF0c19pbnRlcnZhbF9zZWMgPSAodW5zaWduZWQpYXRvaShhcmd2WysraV0pOwogICAgZWxz
ZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1jYXBhYmlsaXR5LXByb2JlIikpIGNhcGFiaWxpdHlf
cHJvYmUgPSB0cnVlOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1zcG9vbCIpICYm
IGkgKyAxIDwgYXJnYykgKytpOyAvKiBpZ25vcmVkOiAwIGRpc2sgd3JpdGUgKi8KICAgIGVsc2Ug
aWYgKCFzdHJjbXAoYXJndltpXSwgIi1qIikgJiYgaSArIDEgPCBhcmdjKSB3b3JrZXJzID0gYXRv
aShhcmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS13c3NlLWJvZHkt
Ynl0ZXMiKSAmJiBpICsgMSA8IGFyZ2MpIHsKICAgICAgaWYgKCFwYXJzZV93c3NlX3NpemUoYXJn
dlsrK2ldLCAmZ193c3NlX2JvZHlfYnl0ZXMpKSB7CiAgICAgICAgZnByaW50ZihzdGRlcnIsICJ3
c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi42NTUzNlxuIik7IHJldHVybiAyOwog
ICAgICB9CiAgICB9CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaCIpIHx8ICFzdHJj
bXAoYXJndltpXSwgIi0taGVscCIpKSB7CiAgICAgIGZwcmludGYoc3RkZXJyLCAidXNhZ2U6IG50
LXNuaWZmLWNwcCBbLWkgaWZhY2VdIFstcCBwb3J0c10gWy0tZW5kcG9pbnQgVVJMXSBbLS1zaGlw
LXJhdGUta2JwcyA2NC4uMTAwMDBdIFstLXN0YXRzLWludGVydmFsLXNlYyAxMC4uMzAwXSBbLWog
d29ya2Vyc10gWy0td3NzZS1ib2R5LWJ5dGVzIDAuLjY1NTM2XVxuIik7CiAgICAgIHJldHVybiAw
OwogICAgfQogICAgZWxzZSB7IGZwcmludGYoc3RkZXJyLCAidW5rbm93biBvciBpbmNvbXBsZXRl
IGFyZ3VtZW50OiAlc1xuIiwgYXJndltpXSk7IHJldHVybiAyOyB9CiAgfQogIGlmIChwb3J0cy5l
bXB0eSgpKSB7IHBvcnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9y
dHMucHVzaF9iYWNrKDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFj
ayg4MDA5KTsgcG9ydHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0K
ICBpZiAoZ19zaGlwX3JhdGVfa2JwcyA8IDY0IHx8IGdfc2hpcF9yYXRlX2ticHMgPiAxMDAwMCkg
ewogICAgZnByaW50ZihzdGRlcnIsICJzaGlwIHJhdGUgbXVzdCBiZSBpbiByYW5nZSA2NC4uMTAw
MDAga2JpdC9zXG4iKTsKICAgIHJldHVybiAyOwogIH0KICBpZiAoZ19zdGF0c19pbnRlcnZhbF9z
ZWMgPCAxMCB8fCBnX3N0YXRzX2ludGVydmFsX3NlYyA+IDMwMCkgewogICAgZnByaW50ZihzdGRl
cnIsICJzdGF0cyBpbnRlcnZhbCBtdXN0IGJlIGluIHJhbmdlIDEwLi4zMDAgc2Vjb25kc1xuIik7
CiAgICByZXR1cm4gMjsKICB9CiAgaWYgKHBvcnRzLnNpemUoKSA+IE1BWF9QT1JUUykgewogICAg
ZnByaW50ZihzdGRlcnIsICJhdCBtb3N0IDMwIG1vbml0b3JlZCBwb3J0cyBhcmUgc3VwcG9ydGVk
IGJ5IHRoZSBzYWZlIGNCUEYgcHJvZ3JhbVxuIik7CiAgICByZXR1cm4gMjsKICB9CiAgaWYgKHdv
cmtlcnMgIT0gMSkgewogICAgZnByaW50ZihzdGRlcnIsICJvbmx5IG9uZSBjYXB0dXJlIHdvcmtl
ciBpcyBwZXJtaXR0ZWRcbiIpOwogICAgcmV0dXJuIDI7CiAgfQogICh2b2lkKXdvcmtlcnM7Cgog
IGlmIChjYXBhYmlsaXR5X3Byb2JlKSByZXR1cm4gcnVuX2NhcGFiaWxpdHlfcHJvYmUoaWZhY2Us
IHBvcnRzKTsKCiAgaW5pdF9ybmcoKTsKICBtZW1zZXQoZ19tb25pdG9yZWRfcG9ydHMsIDAsIHNp
emVvZihnX21vbml0b3JlZF9wb3J0cykpOwogIGZvciAoc2l6ZV90IGsgPSAwOyBrIDwgcG9ydHMu
c2l6ZSgpOyArK2spIHsKICAgIGlmIChwb3J0c1trXSA8IDY1NTM2KSBnX21vbml0b3JlZF9wb3J0
c1twb3J0c1trXV0gPSB0cnVlOwogIH0KCiAgY29uc3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYo
Ik5UX05PREVfTkFNRSIpOwogIHN0ZDo6c3RyaW5nIG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVf
ZW52KSA/IG5vZGVfZW52IDogaG9zdF9uYW1lKCk7CgogIGdfZW5kcG9pbnQgPSBlbmRwb2ludDsK
ICBnX3NoaXBfbm9kZSA9IG5vZGU7CiAgZ19pbnN0YW5jZV9pZCA9IG51bWJlcl9zdHJpbmcoKHNp
emVfdCl0aW1lKE5VTEwpKSArICItIiArIG51bWJlcl9zdHJpbmcoKHNpemVfdClnZXRwaWQoKSk7
CiAgZ19zdGF0c19sYXN0X2F0ID0gd2FsbF9zZWNvbmRzKCk7CgogIE1tYXBSaW5nIHJpbmc7CiAg
aW50IGZkID0gb3Blbl9jYXB0dXJlX3NvY2tldChpZmFjZSwgcG9ydHMsIHJpbmcpOwogIGlmIChm
ZCA8IDApIHJldHVybiAyOwoKICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBpbnQgb3V0
cHV0X2ZsYWdzID0gZmNudGwoU1RET1VUX0ZJTEVOTywgRl9HRVRGTCwgMCk7CiAgICBpZiAob3V0
cHV0X2ZsYWdzIDwgMCB8fAogICAgICAgIGZjbnRsKFNURE9VVF9GSUxFTk8sIEZfU0VURkwsIG91
dHB1dF9mbGFncyB8IE9fTk9OQkxPQ0spIDwgMCkgewogICAgICBsb2dtc2coImNhbm5vdCBtYWtl
IHNoaXBwZXIgcGlwZSBub24tYmxvY2tpbmc7IHJlZnVzaW5nIHVuc2FmZSBwaXBlbGluZSIpOwog
ICAgICByZWxlYXNlX21tYXBfcmluZyhmZCwgcmluZyk7CiAgICAgIGNsb3NlKGZkKTsKICAgICAg
cmV0dXJuIDI7CiAgICB9CiAgICBzaWduYWwoU0lHUElQRSwgU0lHX0lHTik7CiAgfQoKICBzaWdu
YWwoU0lHVEVSTSwgc3RvcF9zaWduYWwpOwogIHNpZ25hbChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsK
ICBzZXR2YnVmKHN0ZG91dCwgTlVMTCwgX0lPTEJGLCA2NTUzNik7CiAgc3RkOjptYXA8Rmxvd0tl
eSwgRmxvdz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5n
PiA+IHBlbmRpbmc7CgogIGxvZ21zZygiUEFDS0VUX01NQVAgKFRQQUNLRVRfVjIpIHN0cmljdCBS
WCByaW5nIGVuYWJsZWQgKDRNQiwgMjA0OCBmcmFtZXMpIik7CiAgaWYgKGdfd3NzZV9ib2R5X2J5
dGVzKSB7CiAgICBsb2dtc2coIldTU0UgVXNlcm5hbWVUb2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQg
KGJvdW5kZWQgdG8gIiArIG51bWJlcl9zdHJpbmcoZ193c3NlX2JvZHlfYnl0ZXMpICsgIiBieXRl
cy9yZXF1ZXN0KSIpOwogIH0KICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSkgewogICAgbG9nbXNn
KCJzaW5nbGUtYmluYXJ5IGluLW1lbW9yeSBtb2RlOiBzaGlwcGluZyBkaXJlY3RseSB0byAiICsg
Z19lbmRwb2ludCArICIgKDAgZGlzayBJL08pIik7CiAgfSBlbHNlIHsKICAgIGxvZ21zZygibm9u
LWJsb2NraW5nIG5hdGl2ZSBwaXBlbGluZSBtb2RlIGVuYWJsZWQ7IFdBTiBJL08gaXNvbGF0ZWQg
aW4gbnQtc2hpcC1jcHAiKTsKICB9CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKCiAgdGltZV90IGxh
c3QgPSB0aW1lKE5VTEwpLCBsYXN0X2ZsdXNoID0gbGFzdDsKICBib29sIHJpbmdfaW50ZWdyaXR5
X2ZhaWx1cmUgPSBmYWxzZTsKCiAgc3RydWN0IHBvbGxmZCBwZmQ7CiAgcGZkLmZkID0gZmQ7CiAg
cGZkLmV2ZW50cyA9IFBPTExJTiB8IFBPTExFUlI7CiAgcGZkLnJldmVudHMgPSAwOwoKICB3aGls
ZSAoZ19ydW5uaW5nKSB7CiAgICBpbnQgcmMgPSBwb2xsKCZwZmQsIDEsIDEwMDApOwogICAgaWYg
KHJjIDwgMCAmJiBlcnJubyA9PSBFSU5UUikgewogICAgICAvKiBTaWduYWwgaGFuZGxlZCwgbG9v
cCBjb25kaXRpb24gd2lsbCBjaGVjayBnX3J1bm5pbmcgKi8KICAgIH0gZWxzZSBpZiAocmMgPj0g
MCkgewogICAgICAvKiBEcmFpbiBhbGwgcmVhZHkgZnJhbWVzIGluIHRoZSByaW5nIHdpdGhvdXQg
ZXh0cmEgc3lzY2FsbHMuICovCiAgICAgIHdoaWxlIChnX3J1bm5pbmcpIHsKICAgICAgICAgIHVu
c2lnbmVkIGJfaWR4ID0gcmluZy5mcmFtZV9pZHggLyByaW5nLmZyYW1lc19wZXJfYmxvY2s7CiAg
ICAgICAgICB1bnNpZ25lZCBmX2luX2IgPSByaW5nLmZyYW1lX2lkeCAlIHJpbmcuZnJhbWVzX3Bl
cl9ibG9jazsKICAgICAgICAgIHVpbnQ4X3QgKmZyYW1lX3B0ciA9ICgodWludDhfdCAqKXJpbmcu
cmluZykgKyAoYl9pZHggKiByaW5nLmJsb2NrX3NpemUpICsgKGZfaW5fYiAqIHJpbmcuZnJhbWVf
c2l6ZSk7CiAgICAgICAgICB2b2xhdGlsZSBzdHJ1Y3QgdHBhY2tldDJfaGRyICp2b2xhdGlsZV9o
ZHIgPQogICAgICAgICAgICAgICh2b2xhdGlsZSBzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVf
cHRyOwoKICAgICAgICAgIGlmICghKHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzICYgVFBfU1RBVFVT
X1VTRVIpKSB7CiAgICAgICAgICAgIGJyZWFrOyAvKiBObyBtb3JlIGtlcm5lbC1wb3B1bGF0ZWQg
ZnJhbWVzIGluIHJpbmcgcmlnaHQgbm93ICovCiAgICAgICAgICB9CiAgICAgICAgICBfX3N5bmNf
c3luY2hyb25pemUoKTsgLyogYWNxdWlyZSBrZXJuZWwtb3duZWQgZnJhbWUgY29udGVudHMgKi8K
CiAgICAgICAgICBjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRyICpoZHIgPQogICAgICAgICAgICAg
IChjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVfcHRyOwogICAgICAgICAgc2l6ZV90
IHBhY2tldF9vZmZzZXQgPSAwLCBwYWNrZXRfbGVuZ3RoID0gMDsKICAgICAgICAgIGlmICghdmFs
aWRfcmluZ19mcmFtZShoZHIsIHJpbmcuZnJhbWVfc2l6ZSwKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAmcGFja2V0X29mZnNldCwgJnBhY2tldF9sZW5ndGgpKSB7CiAgICAgICAgICAg
IF9fc3luY19zeW5jaHJvbml6ZSgpOwogICAgICAgICAgICB2b2xhdGlsZV9oZHItPnRwX3N0YXR1
cyA9IFRQX1NUQVRVU19LRVJORUw7CiAgICAgICAgICAgIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUg
PSB0cnVlOwogICAgICAgICAgICArK2dfaW52YWxpZF9mcmFtZXM7CiAgICAgICAgICAgIGdfcnVu
bmluZyA9IDA7CiAgICAgICAgICAgIGxvZ21zZygiaW52YWxpZCBUUEFDS0VUX1YyIGZyYW1lIG1l
dGFkYXRhOyBzdG9wcGluZyBjYXB0dXJlIik7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAg
fQogICAgICAgICAgaWYgKHBhY2tldF9sZW5ndGggPiAwKSB7CiAgICAgICAgICAgIGNvbnN0IHVu
c2lnbmVkIGNoYXIgKnBrdCA9IGZyYW1lX3B0ciArIHBhY2tldF9vZmZzZXQ7CiAgICAgICAgICAg
ICsrZ19jYXB0dXJlX3BhY2tldHM7CiAgICAgICAgICAgIGdfY2FwdHVyZV9ieXRlcyArPSBwYWNr
ZXRfbGVuZ3RoOwogICAgICAgICAgICBoYW5kbGVfcGFja2V0KHBrdCwgcGFja2V0X2xlbmd0aCwg
bm9kZSwgcG9ydHMsIGZsb3dzLCBwZW5kaW5nKTsKICAgICAgICAgIH0KCiAgICAgICAgICBfX3N5
bmNfc3luY2hyb25pemUoKTsgLyogcmVsZWFzZSBhbGwgcmVhZHMgYmVmb3JlIHJldHVybmluZyBv
d25lcnNoaXAgKi8KICAgICAgICAgIHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzID0gVFBfU1RBVFVT
X0tFUk5FTDsKICAgICAgICAgIHJpbmcuZnJhbWVfaWR4ID0gKHJpbmcuZnJhbWVfaWR4ICsgMSkg
JSByaW5nLmZyYW1lX25yOwogICAgICB9CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0
ZDo6Y291dC5mbHVzaCgpOwogICAgfQoKICAgIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogICAg
aWYgKG5vdyAtIGxhc3QgPj0gMSkgewogICAgICBzd2VlcChmbG93cywgcGVuZGluZywgbm93KTsK
ICAgICAgaWYgKGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgIGxh
c3QgPSBub3c7CiAgICB9CgogICAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgICAgaWYg
KG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDIHx8IGdfc2hpcF9idWYuc2l6ZSgpID49IE1B
WF9CQVRDSCkgewogICAgICAgIGlmICghZ19zaGlwX2J1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMo
Z19lbmRwb2ludCwgZ19zaGlwX25vZGUsICZnX3NoaXBfYnVmLCB0cnVlKTsKICAgICAgICBsYXN0
X2ZsdXNoID0gbm93OwogICAgICB9CiAgICB9CiAgICBpZiAod2FsbF9zZWNvbmRzKCkgLSBnX3N0
YXRzX2xhc3RfYXQgPj0gZ19zdGF0c19pbnRlcnZhbF9zZWMpIHsKICAgICAgc2l6ZV90IHBlbmRp
bmdfY291bnQgPSAwLCB3c3NlX2NvdW50ID0gMDsKICAgICAgZm9yIChzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHBpID0gcGVuZGluZy5iZWdpbigp
OyBwaSAhPSBwZW5kaW5nLmVuZCgpOyArK3BpKQogICAgICAgIHBlbmRpbmdfY291bnQgKz0gcGkt
PnNlY29uZC5zaXplKCk7CiAgICAgIGZvciAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJh
dG9yIGZpID0gZmxvd3MuYmVnaW4oKTsgZmkgIT0gZmxvd3MuZW5kKCk7ICsrZmkpCiAgICAgICAg
aWYgKGZpLT5zZWNvbmQuYXdhaXRpbmdfYm9keSkgKyt3c3NlX2NvdW50OwogICAgICBpZiAoIWdf
ZW5kcG9pbnQuZW1wdHkoKSkKICAgICAgICBzZW5kX2FnZW50X3N0YXRzKGZkLCBmbG93cy5zaXpl
KCksIHBlbmRpbmdfY291bnQsIHdzc2VfY291bnQpOwogICAgICBlbHNlCiAgICAgICAgZW1pdF9j
YXB0dXJlX3N0YXRzX2ludGVybmFsKGZkLCBmbG93cy5zaXplKCksIHBlbmRpbmdfY291bnQsIHdz
c2VfY291bnQpOwogICAgfQogIH0KCiAgLyogQSByZXNwb25zZSBpcyBvcHRpb25hbCBlbnJpY2ht
ZW50LiBQcmVzZXJ2ZSByZXF1ZXN0cyBzdGlsbCBhd2FpdGluZyBhCiAgICogcmVzcG9uc2Ugd2hl
biBTSUdURVJNL3Jlc3RhcnQgZW5kcyBjYXB0dXJlLiAqLwogIGZsdXNoX2luY29tcGxldGVfd3Nz
ZShmbG93cywgcGVuZGluZyk7CiAgZmx1c2hfYWxsX3BlbmRpbmcocGVuZGluZyk7CiAgaWYgKGdf
ZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CgogIGlmICghZ19lbmRwb2ludC5l
bXB0eSgpICYmICFnX3NoaXBfYnVmLmVtcHR5KCkpIHsKICAgIHNlbmRfYmF0Y2hlcyhnX2VuZHBv
aW50LCBnX3NoaXBfbm9kZSwgJmdfc2hpcF9idWYsIHRydWUpOwogIH0gZWxzZSBpZiAoZ19lbmRw
b2ludC5lbXB0eSgpKSB7CiAgICBzaXplX3QgcGVuZGluZ19jb3VudCA9IDA7CiAgICBlbWl0X2Nh
cHR1cmVfc3RhdHNfaW50ZXJuYWwoZmQsIDAsIHBlbmRpbmdfY291bnQsIDApOwogIH0KCiAgdXBk
YXRlX2tlcm5lbF9kcm9wcyhmZCk7CiAgbG9nbXNnKCJwYWNrZXQgc3RhdHM6IHJlY2VpdmVkPSIg
KyB1bGxfc3RyaW5nKGdfY2FwdHVyZV9wYWNrZXRzKSArCiAgICAgICAgICIgZHJvcHBlZD0iICsg
dWxsX3N0cmluZyhnX2tlcm5lbF9kcm9wcykpOwogIGlmICghcmVsZWFzZV9tbWFwX3JpbmcoZmQs
IHJpbmcpKSB7CiAgICBsb2dtc2coIlRQQUNLRVRfVjIgY2xlYW51cCBmYWlsZWQiKTsKICAgIHJp
bmdfaW50ZWdyaXR5X2ZhaWx1cmUgPSB0cnVlOwogIH0KICBjbG9zZShmZCk7CiAgbG9nbXNnKCJz
dG9wcGVkIik7CiAgcmV0dXJuIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPyAyIDogMDsKfQo=
#__END_CPP__
#__CPP_MAKE_B64__
IyBHQ0MgNC40IC8gQ2VudE9TIDYgY29tcGF0aWJsZTogQysrMDMsIGdudSsrMDMgb3IgZ251Kys5
OC4KQ1hYID89IGcrKwpDWFhTVEQgPz0gJChzaGVsbCAkKENYWCkgLXN0ZD1nbnUrKzAzIC14IGMr
KyAtRSAvZGV2L251bGwgPi9kZXYvbnVsbCAyPiYxICYmIGVjaG8gLXN0ZD1nbnUrKzAzIHx8IGVj
aG8gLXN0ZD1nbnUrKzk4KQpDWFhGTEFHUyA/PSAtTzIgLVdhbGwgLVdleHRyYSAkKENYWFNURCkg
LXB0aHJlYWQKCi5QSE9OWTogYWxsIGNwcCBjcHAtc2hpcCBjcHAtZGVidWcgZml4dHVyZSBwY2Fw
LWZpeHR1cmUgY2xlYW4KCmFsbDogY3BwIGNwcC1zaGlwCgpjcHA6CgkkKENYWCkgJChDWFhGTEFH
UykgbnQtc25pZmYtY3BwLmNwcCAtbyBudC1zbmlmZi1jcHAKCmNwcC1zaGlwOgoJJChDWFgpICQo
Q1hYRkxBR1MpIG50LXNoaXAtY3BwLmNwcCAtbyBudC1zaGlwLWNwcAoKY3BwLWRlYnVnOgoJJChD
WFgpIC1PMCAtZyAtV2FsbCAtV2V4dHJhIC1zdGQ9Z251KyswMyBudC1zbmlmZi1jcHAuY3BwIC1v
IG50LXNuaWZmLWNwcC1kZWJ1ZwoKZml4dHVyZTogY3BwCgkuL250LXNuaWZmLWNwcCAtLWZpeHR1
cmUKCS4vbnQtc25pZmYtY3BwIC0tcmluZy1maXh0dXJlCgkuL250LXNuaWZmLWNwcCAtLXNoaXAt
cmF0ZS1maXh0dXJlCgkuL250LXNuaWZmLWNwcCAtLXN0YXRzLWZpeHR1cmUKCnBjYXAtZml4dHVy
ZTogcGNhcF90ZXN0X2NwcAoKcGNhcF90ZXN0X2NwcDogcGNhcF90ZXN0X2NwcC5jcHAgbnQtc25p
ZmYtY3BwLmNwcAoJJChDWFgpICQoQ1hYRkxBR1MpIHBjYXBfdGVzdF9jcHAuY3BwIC1vIHBjYXBf
dGVzdF9jcHAKCmNsZWFuOgoJcm0gLWYgbnQtc25pZmYtY3BwIG50LXNuaWZmLWNwcC1kZWJ1ZyBu
dC1zaGlwLWNwcCBwY2FwX3Rlc3RfY3BwCg==
#__END_CPP_MAKE__
#__CPP_RUN_B64__
IyEvYmluL3NoCiMgUnVuIHRoZSBzZXBhcmF0ZWQgbmF0aXZlIEMrKyBjYXB0dXJlIGFuZCBib3Vu
ZGVkIG5hdGl2ZSBDKysgc2hpcHBlci4Kc2V0IC11CkhFUkU9JChDRFBBVEg9IGNkIC0tICIkKGRp
cm5hbWUgLS0gIiQwIikiICYmIHB3ZCkKRU5EUE9JTlQ9JHtOVF9IVUJfRU5EUE9JTlQ6LX0KU0hJ
UF9SQVRFPSR7TlRfU0hJUF9SQVRFX0tCUFM6LTEwMjR9ClNUQVRTX0lOVEVSVkFMPSR7TlRfU1RB
VFNfSU5URVJWQUxfU0VDOi0zMH0KaWYgWyAteiAiJEVORFBPSU5UIiBdOyB0aGVuCiAgICBlY2hv
ICJOVF9IVUJfRU5EUE9JTlQgaXMgcmVxdWlyZWQiID4mMgogICAgZXhpdCAyCmZpCiIkSEVSRS9u
dC1zbmlmZi1jcHAiICIkQCIgfCBleGVjICIkSEVSRS9udC1zaGlwLWNwcCIgLS1lbmRwb2ludCAi
JEVORFBPSU5UIiBcCiAgICAtLXNoaXAtcmF0ZS1rYnBzICIkU0hJUF9SQVRFIiAtLXN0YXRzLWlu
dGVydmFsLXNlYyAiJFNUQVRTX0lOVEVSVkFMIgo=
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
dCA3MAp9CmNvbW1hbmQgLXYgY2hydCA+L2Rldi9udWxsIDI+JjEgfHwgewogICAgZWNobyAibnQt
cmVzb3VyY2UtZ3VhcmQ6IGNocnQgaXMgcmVxdWlyZWQiID4mMgogICAgZXhpdCA3MAp9CgojIDI1
NiBNaUIgYWRkcmVzcyBzcGFjZSwgOCBNaUIgc3RhY2ssIDY0IEtpQiBsb2NrZWQgbWVtb3J5LCAx
LDAyNCBkZXNjcmlwdG9ycywKIyAzMiBNaUIgcGVyIHJlZ3VsYXIgb3V0cHV0IGZpbGUsIGFuZCBu
byBjb3JlIGR1bXBzLiBUaGUgcHJvY2VzcyBsaW1pdCBleGlzdHMKIyBpbiBiYXNoIG9uIEVMNiwg
YnV0IG5vdCBldmVyeSBQT1NJWCBzaGVsbCwgc28gYXBwbHkgaXQgd2hlbiBzdXBwb3J0ZWQuCnVs
aW1pdCAtUyAtYyAwICYmIHVsaW1pdCAtSCAtYyAwIHx8IGV4aXQgNzAKdWxpbWl0IC1TIC1mIDY1
NTM2ICYmIHVsaW1pdCAtSCAtZiA2NTUzNiB8fCBleGl0IDcwCnVsaW1pdCAtUyAtbiAxMDI0ICYm
IHVsaW1pdCAtSCAtbiAxMDI0IHx8IGV4aXQgNzAKdWxpbWl0IC1TIC12IDI2MjE0NCAmJiB1bGlt
aXQgLUggLXYgMjYyMTQ0IHx8IGV4aXQgNzAKdWxpbWl0IC1TIC1zIDgxOTIgJiYgdWxpbWl0IC1I
IC1zIDgxOTIgfHwgZXhpdCA3MAp1bGltaXQgLVMgLWwgNjQgJiYgdWxpbWl0IC1IIC1sIDY0IHx8
IGV4aXQgNzAKaWYgKHVsaW1pdCAtdSA+L2Rldi9udWxsIDI+JjEpOyB0aGVuCiAgICB1bGltaXQg
LVMgLXUgNjQgJiYgdWxpbWl0IC1IIC11IDY0IHx8IGV4aXQgNzAKZmkKCiMgU0NIRURfSURMRSBp
cyBiZWxvdyBldmVyeSBub3JtYWwgU0NIRURfT1RIRVIgdGFzazsgbmljZSAxOSByZW1haW5zIGFu
CiMgYWRkaXRpb25hbCBpbmhlcml0ZWQgc2FmZWd1YXJkLiBBZmZpbml0eSBjb25maW5lcyB0aGUg
ZnVsbCBkZXNjZW5kYW50IHRyZWUuCmV4ZWMgdGFza3NldCAtYyAiJENQVV9DT1JFIiBjaHJ0IC1p
IDAgbmljZSAtbiAxOSAiJEAiCg==
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
