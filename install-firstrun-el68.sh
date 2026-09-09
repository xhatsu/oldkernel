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
Ynl0ZXMKCgpIVFRQX1NUQVRFX0hFQURFUiA9IDAKSFRUUF9TVEFURV9CT0RZID0gMQpIVFRQX1NU
QVRFX0NIVU5LID0gMgpIVFRQX1NUQVRFX0NMT1NFX0JPRFkgPSAzCgpNQVhfT09PX1NFR01FTlRT
ID0gNApNQVhfT09PX0JZVEVTID0gMTYzODQKTUFYX1RPVEFMX0JVRkZFUl9CWVRFUyA9IDE2ICog
MTAyNCAqIDEwMjQKCgpkZWYgc2VxX2RpZmYoYSwgYik6CiAgICBkaWZmID0gKGEgLSBiKSAmIDB4
RkZGRkZGRkYKICAgIGlmIGRpZmYgPj0gMHg4MDAwMDAwMDoKICAgICAgICBkaWZmIC09IDB4MTAw
MDAwMDAwCiAgICByZXR1cm4gZGlmZgoKCmRlZiBpc19tZXRob2Rfb3JfcHJlZml4KHBheWxvYWQp
OgogICAgaWYgbm90IHBheWxvYWQ6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBwID0gYnl0ZXMo
cGF5bG9hZFs6OF0pCiAgICBmb3IgbSBpbiAoYiJHRVQgIiwgYiJQT1NUICIsIGIiUFVUICIsIGIi
REVMRVRFICIsIGIiUEFUQ0ggIiwgYiJIRUFEICIsIGIiT1BUSU9OUyAiKToKICAgICAgICBjaGVj
a19sZW4gPSBtaW4obGVuKHApLCBsZW4obSkpCiAgICAgICAgaWYgcFs6Y2hlY2tfbGVuXSA9PSBt
WzpjaGVja19sZW5dOgogICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgcmV0dXJuIEZhbHNlCgoK
ZGVmIGZpbmRfaHR0cF9zdGFydChidWYpOgogICAgYiA9IGJ5dGVzKGJ1ZikKICAgIGJlc3QgPSAt
MQogICAgZm9yIG0gaW4gKGIiR0VUICIsIGIiUE9TVCAiLCBiIlBVVCAiLCBiIkRFTEVURSAiLCBi
IlBBVENIICIsIGIiSEVBRCAiLCBiIk9QVElPTlMgIik6CiAgICAgICAgcG9zID0gYi5maW5kKG0p
CiAgICAgICAgaWYgcG9zICE9IC0xIGFuZCAoYmVzdCA9PSAtMSBvciBwb3MgPCBiZXN0KToKICAg
ICAgICAgICAgYmVzdCA9IHBvcwogICAgcmV0dXJuIGJlc3QKCgpjbGFzcyBGbG93KG9iamVjdCk6
CiAgICBfX3Nsb3RzX18gPSAoIm5leHRfc2VxIiwgImhhc19zZXEiLCAiaXNfYnJva2VuIiwgInRv
dWNoZWQiLCAiZmlyc3RfYnl0ZV90cyIsCiAgICAgICAgICAgICAgICAgImJ1ZiIsICJvb28iLCAi
c3RhdGUiLCAiYm9keV9yZW1haW5pbmciLCAiY2h1bmtfcmVtYWluaW5nIiwKICAgICAgICAgICAg
ICAgICAiY2h1bmtfcGF5bG9hZF9yZW1haW5pbmciLCAiY2h1bmtfcmVhZGluZ19sZW4iLCAiY2h1
bmtfcmVhZGluZ19jcmxmIiwKICAgICAgICAgICAgICAgICAiY2h1bmtfcmVhZGluZ190cmFpbGVy
IiwgImF3YWl0aW5nX3dzc2UiLCAid3NzZV9ldmVudCIsICJ3c3NlX2J1ZiIsCiAgICAgICAgICAg
ICAgICAgIndzc2VfZ29hbCIsICJldmVudCIsICJoZHJzIiwgImhlYWRfYnl0ZXMiLCAiYm9keV9n
b2FsIiwgImdlbmVyYXRpb24iKQoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxm
Lm5leHRfc2VxID0gMAogICAgICAgIHNlbGYuaGFzX3NlcSA9IEZhbHNlCiAgICAgICAgc2VsZi5p
c19icm9rZW4gPSBGYWxzZQogICAgICAgIHNlbGYudG91Y2hlZCA9IHRpbWUudGltZSgpCiAgICAg
ICAgc2VsZi5maXJzdF9ieXRlX3RzID0gMC4wCiAgICAgICAgc2VsZi5idWYgPSBieXRlYXJyYXko
KQogICAgICAgIHNlbGYub29vID0gW10KICAgICAgICBzZWxmLnN0YXRlID0gSFRUUF9TVEFURV9I
RUFERVIKICAgICAgICBzZWxmLmJvZHlfcmVtYWluaW5nID0gMAogICAgICAgIHNlbGYuY2h1bmtf
cmVtYWluaW5nID0gMAogICAgICAgIHNlbGYuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPSAwCiAg
ICAgICAgc2VsZi5jaHVua19yZWFkaW5nX2xlbiA9IFRydWUKICAgICAgICBzZWxmLmNodW5rX3Jl
YWRpbmdfY3JsZiA9IEZhbHNlCiAgICAgICAgc2VsZi5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBG
YWxzZQogICAgICAgIHNlbGYuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICAgICAgc2VsZi53c3Nl
X2V2ZW50ID0gTm9uZQogICAgICAgIHNlbGYud3NzZV9idWYgPSBieXRlYXJyYXkoKQogICAgICAg
IHNlbGYud3NzZV9nb2FsID0gMAogICAgICAgIHNlbGYuZXZlbnQgPSBOb25lCiAgICAgICAgc2Vs
Zi5oZHJzID0gTm9uZQogICAgICAgIHNlbGYuaGVhZF9ieXRlcyA9IDAKICAgICAgICBzZWxmLmJv
ZHlfZ29hbCA9IDAKICAgICAgICBzZWxmLmdlbmVyYXRpb24gPSAwCgoKZGVmIF9kcmFpbl9vb28o
ZmwpOgogICAgZHJhaW5lZCA9IFRydWUKICAgIHdoaWxlIGRyYWluZWQgYW5kIGZsLm9vbzoKICAg
ICAgICBkcmFpbmVkID0gRmFsc2UKICAgICAgICBmb3IgaSwgKG9zZXEsIG9kYXRhKSBpbiBlbnVt
ZXJhdGUoZmwub29vKToKICAgICAgICAgICAgb2RpZmYgPSBzZXFfZGlmZihvc2VxLCBmbC5uZXh0
X3NlcSkKICAgICAgICAgICAgaWYgb2RpZmYgPT0gMDoKICAgICAgICAgICAgICAgIGZsLmJ1Zi5l
eHRlbmQob2RhdGEpCiAgICAgICAgICAgICAgICBmbC5uZXh0X3NlcSA9IChmbC5uZXh0X3NlcSAr
IGxlbihvZGF0YSkpICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgZmwub29vLnBvcChpKQog
ICAgICAgICAgICAgICAgZHJhaW5lZCA9IFRydWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAg
ICAgICAgIGVsaWYgb2RpZmYgPCAwOgogICAgICAgICAgICAgICAgb19vdmVybGFwID0gLW9kaWZm
CiAgICAgICAgICAgICAgICBpZiBvX292ZXJsYXAgPCBsZW4ob2RhdGEpOgogICAgICAgICAgICAg
ICAgICAgIGZsLmJ1Zi5leHRlbmQob2RhdGFbb19vdmVybGFwOl0pCiAgICAgICAgICAgICAgICAg
ICAgZmwubmV4dF9zZXEgPSAoZmwubmV4dF9zZXEgKyBsZW4ob2RhdGEpIC0gb19vdmVybGFwKSAm
IDB4RkZGRkZGRkYKICAgICAgICAgICAgICAgIGZsLm9vby5wb3AoaSkKICAgICAgICAgICAgICAg
IGRyYWluZWQgPSBUcnVlCiAgICAgICAgICAgICAgICBicmVhawoKCiMgLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAt
LS0tClBFTkRJTkdfVFRMID0gNS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBh
ZnRlciB0aGlzIG1hbnkgc2Vjb25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNh
cDsgb3ZlcmZsb3cgZmx1c2hlcyBvbGRlc3QgZmlyc3QKUEVORElOR19QRVJfRkxPVyA9IDMyICAg
ICMgYm91bmQgYSBzaW5nbGUgcGlwZWxpbmVkL2hvc3RpbGUga2VlcC1hbGl2ZSBmbG93ClNXRUVQ
X0lOVEVSVkFMID0gMS4wICAgICAjIGhvbm9yIFBFTkRJTkdfVFRMIGV2ZW4gd2hlbiB0aGUgc29j
a2V0IGdvZXMgaWRsZQoKIyBwZW5kaW5nWyhzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KV0g
IC0tIGtleSBpcyB0aGUgUkVTUE9OU0UgdHVwbGU6CiMgc2VydmVyLT5jbGllbnQuIFZhbHVlOiBb
ZXZlbnQsIHJlcV90c10uIEEgbGlzdCBwZXIga2V5IGhhbmRsZXMgSFRUUAojIGtlZXAtYWxpdmUg
cGlwZWxpbmluZyAoc2V2ZXJhbCByZXF1ZXN0cyBiZWZvcmUgcmVzcG9uc2VzIGFycml2ZSkuCnBl
bmRpbmcgPSB7fQpNQVhfQ09SUl9ESVNBQkxFRCA9IDIwNDgKY29ycl9kaXNhYmxlZCA9IHNldCgp
CmNvcnJfZGlzYWJsZWRfZmlmbyA9IFtdCmNvcnJfY2FwYWNpdHlfcmVhY2hlZCA9IEZhbHNlCgoK
ZGVmIGNvcnJfZGlzYWJsZWRfaW5zZXJ0KHJrKToKICAgIGdsb2JhbCBjb3JyX2NhcGFjaXR5X3Jl
YWNoZWQKICAgIGlmIHJrIGluIGNvcnJfZGlzYWJsZWQ6CiAgICAgICAgcmV0dXJuCiAgICB3aGls
ZSBsZW4oY29ycl9kaXNhYmxlZCkgPj0gTUFYX0NPUlJfRElTQUJMRUQgYW5kIGNvcnJfZGlzYWJs
ZWRfZmlmbzoKICAgICAgICBjb3JyX2NhcGFjaXR5X3JlYWNoZWQgPSBUcnVlCiAgICAgICAgb2xk
X2sgPSBjb3JyX2Rpc2FibGVkX2ZpZm8ucG9wKDApCiAgICAgICAgY29ycl9kaXNhYmxlZC5kaXNj
YXJkKG9sZF9rKQogICAgY29ycl9kaXNhYmxlZC5hZGQocmspCiAgICBjb3JyX2Rpc2FibGVkX2Zp
Zm8uYXBwZW5kKHJrKQoKCmRlZiBjb3JyX2Rpc2FibGVkX2VyYXNlKHJrKToKICAgIGlmIHJrIGlu
IGNvcnJfZGlzYWJsZWQ6CiAgICAgICAgY29ycl9kaXNhYmxlZC5kaXNjYXJkKHJrKQogICAgICAg
IHRyeToKICAgICAgICAgICAgY29ycl9kaXNhYmxlZF9maWZvLnJlbW92ZShyaykKICAgICAgICBl
eGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgcGFzcwoKCmRlZiBjb3JyX2Rpc2FibGVkX2Ns
ZWFyKCk6CiAgICBnbG9iYWwgY29ycl9jYXBhY2l0eV9yZWFjaGVkCiAgICBjb3JyX2Rpc2FibGVk
LmNsZWFyKCkKICAgIGRlbCBjb3JyX2Rpc2FibGVkX2ZpZm9bOl0KICAgIGNvcnJfY2FwYWNpdHlf
cmVhY2hlZCA9IEZhbHNlCgoKZGVmIGlzX2NvcnJlbGF0aW9uX2Rpc2FibGVkKHJrLCBzeW5fc2Vl
bik6CiAgICBpZiByayBpbiBjb3JyX2Rpc2FibGVkOgogICAgICAgIHJldHVybiBUcnVlCiAgICBp
ZiBjb3JyX2NhcGFjaXR5X3JlYWNoZWQgYW5kIG5vdCBzeW5fc2VlbjoKICAgICAgICByZXR1cm4g
VHJ1ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIHBlbmRpbmdfZGVsKHJrKToKICAgIHBlbmRpbmcu
cG9wKHJrLCBOb25lKQogICAgY29ycl9kaXNhYmxlZF9lcmFzZShyaykKCgoKCmRlZiBwZW5kaW5n
X3BvcChyaywgb3V0LCBwZW5kaW5nX3RibD1Ob25lKToKICAgICIiIkZsdXNoIHRoZSBvbGRlc3Qg
cGVuZGluZyBldmVudCBmb3IgdGhpcyByZXNwb25zZSB0dXBsZSAoRklOL1JTVCBvcgogICAgb3Zl
cmZsb3cgcGF0aCkuIEVtaXRzIHdoYXRldmVyIHRoZSBldmVudCBoYXMg4oCUIHN0YXR1cyBzdGF5
cyBudWxsLiIiIgogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBwZW5kaW5nX3Ri
bCA9IHBlbmRpbmcKICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIG5vdCBsc3Q6
CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGl0ZW0gPSBsc3QucG9wKDApCiAgICBpZiBub3QgbHN0
OgogICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgIGlzX3RvbWJzdG9uZSA9IGl0
ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZhbHNlCiAgICBpZiBub3QgaXNfdG9tYnN0b25l
OgogICAgICAgIG91dC5hcHBlbmQoaXRlbVswXSkKICAgICAgICByZXR1cm4gaXRlbVswXQogICAg
cmV0dXJuIE5vbmUKCgpkZWYgcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2FkKToKICAgICIiIkZp
cnN0IGxpbmUgJ0hUVFAvMS54IE5OTiAuLi4nIC0+IChzdGF0dXNfaW50fE5vbmUsIGNvbnRlbnRf
bGVufE5vbmUsIGhlYWRfZW5kX2lkeHxOb25lLCBpc19jaHVua2VkLCBpc19jbG9zZSkuIiIiCiAg
ICB0cnk6CiAgICAgICAgcmF3ID0gYnl0ZXMocGF5bG9hZCkKICAgICAgICBpZHggPSByYXcuZmlu
ZChiIlxyXG5cclxuIikKICAgICAgICBpZiBpZHggPCAwOgogICAgICAgICAgICByZXR1cm4gTm9u
ZSwgTm9uZSwgTm9uZSwgRmFsc2UsIEZhbHNlCiAgICAgICAgaGVhZCA9IHJhd1s6aWR4XQogICAg
ICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxpdChiIlxuIikKICAg
ICAgICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAgICBpZiBsZW4oZmlyc3QpIDwgMiBv
ciBub3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6CiAgICAgICAgICAgIHJldHVybiBO
b25lLCBOb25lLCBpZHggKyA0LCBGYWxzZSwgRmFsc2UKICAgICAgICBzdCA9IGludChmaXJzdFsx
XSkKICAgICAgICBpZiBzdCA8IDEwMCBvciBzdCA+IDU5OToKICAgICAgICAgICAgcmV0dXJuIE5v
bmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBGYWxzZQogICAgZXhjZXB0IChWYWx1ZUVycm9yLCBJbmRl
eEVycm9yKToKICAgICAgICByZXR1cm4gTm9uZSwgTm9uZSwgTm9uZSwgRmFsc2UsIEZhbHNlCiAg
ICBjbGVuID0gTm9uZQogICAgaGFzX2NsZW4gPSBGYWxzZQogICAgaGFzX2NvbmZsaWN0X2NsID0g
RmFsc2UKICAgIGlzX2NodW5rZWQgPSBGYWxzZQogICAgaXNfY2xvc2UgPSBGYWxzZQogICAgaXNf
aHR0cF8xMCA9IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLzEuMCIpCiAgICBjb25uX2Nsb3Nl
ID0gRmFsc2UKICAgIGNvbm5fa2VlcF9hbGl2ZSA9IEZhbHNlCiAgICBmb3IgbG4gaW4gbGluZXNb
MTpdOgogICAgICAgIGxvdyA9IGxuLmxvd2VyKCkKICAgICAgICBpZiBsb3cuc3RhcnRzd2l0aChi
ImNvbnRlbnQtbGVuZ3RoOiIpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB2YWwg
PSBpbnQobG4uc3BsaXQoYiI6IiwgMSlbMV0uc3RyaXAoKSkKICAgICAgICAgICAgICAgIGlmIHZh
bCA8IDA6CiAgICAgICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAg
ICAgICAgICAgZWxpZiBoYXNfY2xlbiBhbmQgY2xlbiAhPSB2YWw6CiAgICAgICAgICAgICAgICAg
ICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAgICAgICAgICAgY2xlbiA9IHZhbAogICAg
ICAgICAgICAgICAgaGFzX2NsZW4gPSBUcnVlCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9y
OgogICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAgIGVsaWYgbG93
LnN0YXJ0c3dpdGgoYiJ0cmFuc2Zlci1lbmNvZGluZzoiKToKICAgICAgICAgICAgaWYgYiJjaHVu
a2VkIiBpbiBsb3c6CiAgICAgICAgICAgICAgICBpc19jaHVua2VkID0gVHJ1ZQogICAgICAgIGVs
aWYgbG93LnN0YXJ0c3dpdGgoYiJjb25uZWN0aW9uOiIpOgogICAgICAgICAgICBpZiBiImNsb3Nl
IiBpbiBsb3c6CiAgICAgICAgICAgICAgICBjb25uX2Nsb3NlID0gVHJ1ZQogICAgICAgICAgICBl
bGlmIGIia2VlcC1hbGl2ZSIgaW4gbG93OgogICAgICAgICAgICAgICAgY29ubl9rZWVwX2FsaXZl
ID0gVHJ1ZQogICAgaWYgaGFzX2NvbmZsaWN0X2NsIG9yIChoYXNfY2xlbiBhbmQgaXNfY2h1bmtl
ZCk6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBGYWxzZQogICAgaWYg
aXNfaHR0cF8xMCBhbmQgbm90IGNvbm5fa2VlcF9hbGl2ZToKICAgICAgICBpc19jbG9zZSA9IFRy
dWUKICAgIGVsaWYgY29ubl9jbG9zZToKICAgICAgICBpc19jbG9zZSA9IFRydWUKICAgIHJldHVy
biBzdCwgY2xlbiwgaWR4ICsgNCwgaXNfY2h1bmtlZCwgaXNfY2xvc2UKCgoKZGVmIGhhbmRsZV9y
ZXNwb25zZShyZXNwX2Zsb3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBlbmRpbmdfdGJsLCBz
ZXE9Tm9uZSwgZmxhZ3M9MCwgaXNfdHJ1bmNhdGVkPUZhbHNlKToKICAgIGlmIGZsYWdzICYgMHgw
MiBhbmQgc2VxIGlzIG5vdCBOb25lOgogICAgICAgIHJmbCA9IHJlc3BfZmxvd3NbcmtdID0gRmxv
dygpCiAgICAgICAgcmZsLmhhc19zZXEgPSBUcnVlCiAgICAgICAgcmZsLm5leHRfc2VxID0gKHNl
cSArIDEpICYgMHhGRkZGRkZGRgogICAgICAgIHJmbC50b3VjaGVkID0gbm93CiAgICAgICAgcmV0
dXJuCgogICAgcmZsID0gcmVzcF9mbG93cy5nZXQocmspCiAgICBpZiByZmwgaXMgTm9uZToKICAg
ICAgICByZmwgPSBGbG93KCkKICAgICAgICByZXNwX2Zsb3dzW3JrXSA9IHJmbAogICAgcmZsLnRv
dWNoZWQgPSBub3cKCiAgICBwbGVuID0gbGVuKHBheWxvYWQpIGlmIHBheWxvYWQgZWxzZSAwCiAg
ICBpZiBwbGVuID4gMDoKICAgICAgICBpZiBzZXEgaXMgTm9uZToKICAgICAgICAgICAgcmZsLmJ1
Zi5leHRlbmQocGF5bG9hZCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBpZiBub3QgcmZsLmhh
c19zZXE6CiAgICAgICAgICAgICAgICBpZiAocGxlbiA+PSA1IGFuZCBwYXlsb2FkWzo1XSA9PSBi
IkhUVFAvIikgb3IgKHBsZW4gPCA1IGFuZCBiIkhUVFAvIi5zdGFydHN3aXRoKHBheWxvYWQpKToK
ICAgICAgICAgICAgICAgICAgICByZmwuaGFzX3NlcSA9IFRydWUKICAgICAgICAgICAgICAgICAg
ICByZmwubmV4dF9zZXEgPSBzZXEKICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0g
RmFsc2UKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKHJm
bC5vb28pIDwgTUFYX09PT19TRUdNRU5UUyBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAg
ICAgICAgICAgICAgICAgaWYgbm90IGFueShzID09IHNlcSBmb3IgcywgXyBpbiByZmwub29vKToK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBh
eWxvYWQpKSkKICAgICAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAgICAgIGRpZmYgPSBz
ZXFfZGlmZihzZXEsIHJmbC5uZXh0X3NlcSkKICAgICAgICAgICAgaWYgZGlmZiA9PSAwOgogICAg
ICAgICAgICAgICAgaWYgaXNfdHJ1bmNhdGVkOgogICAgICAgICAgICAgICAgICAgIHJmbC5pc19i
cm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHJm
bC5idWYuZXh0ZW5kKHBheWxvYWQpCiAgICAgICAgICAgICAgICAgICAgcmZsLm5leHRfc2VxID0g
KHJmbC5uZXh0X3NlcSArIHBsZW4pICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgIF9k
cmFpbl9vb28ocmZsKQogICAgICAgICAgICBlbGlmIGRpZmYgPCAwOgogICAgICAgICAgICAgICAg
b3ZlcmxhcCA9IC1kaWZmCiAgICAgICAgICAgICAgICBpZiBvdmVybGFwIDwgcGxlbiBhbmQgbm90
IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICByZmwuYnVmLmV4dGVuZChwYXlsb2Fk
W292ZXJsYXA6XSkKICAgICAgICAgICAgICAgICAgICByZmwubmV4dF9zZXEgPSAocmZsLm5leHRf
c2VxICsgcGxlbiAtIG92ZXJsYXApICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgIF9k
cmFpbl9vb28ocmZsKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgaWYgbGVuKHJm
bC5vb28pIDwgTUFYX09PT19TRUdNRU5UUyBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAg
ICAgICAgICAgICBpZiBub3QgYW55KHMgPT0gc2VxIGZvciBzLCBfIGluIHJmbC5vb28pOgogICAg
ICAgICAgICAgICAgICAgICAgICByZmwub29vLmFwcGVuZCgoc2VxLCBieXRlcyhwYXlsb2FkKSkp
CiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4g
PSBUcnVlCgogICAgIyBQYXJzZSBjb21wbGV0ZSByZXNwb25zZXMgZnJvbSByZWFzc2VtYmxlZCBi
dWZmZXIgdXNpbmcgSFRUUCBmcmFtaW5nCiAgICB3aGlsZSByZmwuYnVmIGFuZCBub3QgcmZsLmlz
X2Jyb2tlbjoKICAgICAgICBpZiByZmwuc3RhdGUgPT0gSFRUUF9TVEFURV9IRUFERVI6CiAgICAg
ICAgICAgIHN0LCBjbGVuLCBoZWFkX2xlbiwgaXNfY2h1bmtlZCwgaXNfY2xvc2UgPSBwYXJzZV9y
ZXNwb25zZV9oZWFkKHJmbC5idWYpCiAgICAgICAgICAgIGlmIHN0IGlzIE5vbmU6CiAgICAgICAg
ICAgICAgICBpZiBoZWFkX2xlbiBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICBkZWwg
cmZsLmJ1Zls6aGVhZF9sZW5dCiAgICAgICAgICAgICAgICBlbGlmIHJmbC5idWYuZmluZChiIlxy
XG5cclxuIikgIT0gLTE6CiAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgp
CiAgICAgICAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAg
IGJyZWFrCgogICAgICAgICAgICBpZiAxMDAgPD0gc3QgPD0gMTk5IGFuZCBzdCAhPSAxMDE6CiAg
ICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6aGVhZF9sZW5dCiAgICAgICAgICAgICAgICBjb250
aW51ZQoKICAgICAgICAgICAgdmVyaWZpZWQgPSAocmZsLmdlbmVyYXRpb24gPiAwKQogICAgICAg
ICAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQocmspIGlmIG5vdCBpc19jb3JyZWxhdGlvbl9kaXNh
YmxlZChyaywgdmVyaWZpZWQpIGVsc2UgTm9uZQogICAgICAgICAgICBpc19oZWFkID0gRmFsc2UK
CiAgICAgICAgICAgIGlmIGVudDoKICAgICAgICAgICAgICAgIGl0ZW0gPSBlbnRbMF0KICAgICAg
ICAgICAgICAgIGlzX3RvbWJzdG9uZSA9IGl0ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZh
bHNlCiAgICAgICAgICAgICAgICBnZW4gPSBpdGVtWzRdIGlmIGxlbihpdGVtKSA+IDQgZWxzZSAw
CiAgICAgICAgICAgICAgICBpZiByZmwuZ2VuZXJhdGlvbiAhPSAwIGFuZCBnZW4gIT0gMCBhbmQg
Z2VuICE9IHJmbC5nZW5lcmF0aW9uOgogICAgICAgICAgICAgICAgICAgIGV2ID0gaXRlbVswXQog
ICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgICAgICAgICAgICAgZW50
LnBvcCgwKQogICAgICAgICAgICAgICAgICAgIGlmIG5vdCBlbnQ6CiAgICAgICAgICAgICAgICAg
ICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgICAgICAgICAgICAgIGVsaWYgaXNf
dG9tYnN0b25lOgogICAgICAgICAgICAgICAgICAgIGVudC5wb3AoMCkKICAgICAgICAgICAgICAg
ICAgICBpZiBub3QgZW50OgogICAgICAgICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibC5wb3Ao
cmssIE5vbmUpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIGV2LCBz
dGFydGVkID0gaXRlbVswXSwgaXRlbVsxXQogICAgICAgICAgICAgICAgICAgIGVudC5wb3AoMCkK
ICAgICAgICAgICAgICAgICAgICBpZiBub3QgZW50OgogICAgICAgICAgICAgICAgICAgICAgICBw
ZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAgICAgICAgICAgICAgaWYgZXYuZ2V0KCJt
ZXRob2QiKSA9PSAiSEVBRCI6CiAgICAgICAgICAgICAgICAgICAgICAgIGlzX2hlYWQgPSBUcnVl
CiAgICAgICAgICAgICAgICAgICAgZXZbInN0YXR1cyJdID0gc3QKICAgICAgICAgICAgICAgICAg
ICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgwLCBpbnQoKG5vdyAtIHN0YXJ0ZWQpICogMTAwMCkp
CiAgICAgICAgICAgICAgICAgICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAg
ICAgICAgICAgZXZbInJlc3BfYnl0ZXMiXSA9IGNsZW4KICAgICAgICAgICAgICAgICAgICBvdXQu
YXBwZW5kKGV2KQoKICAgICAgICAgICAgZGVsIHJmbC5idWZbOmhlYWRfbGVuXQoKICAgICAgICAg
ICAgaWYgaXNfaGVhZCBvciBzdCA9PSAyMDQgb3Igc3QgPT0gMzA0OgogICAgICAgICAgICAgICAg
cmZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgZWxpZiBpc19jaHVua2Vk
OgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9DSFVOSwogICAgICAgICAg
ICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0gVHJ1ZQogICAgICAgICAgICAgICAgcmZsLmNo
dW5rX3JlYWRpbmdfY3JsZiA9IEZhbHNlCiAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGlu
Z190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFp
bmluZyA9IDAKICAgICAgICAgICAgZWxpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgICAgICAg
ICAgaWYgY2xlbiA+IDA6CiAgICAgICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFU
RV9CT0RZCiAgICAgICAgICAgICAgICAgICAgcmZsLmJvZHlfcmVtYWluaW5nID0gY2xlbgogICAg
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICByZmwuc3RhdGUgPSBIVFRQX1NU
QVRFX0hFQURFUgogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0g
SFRUUF9TVEFURV9DTE9TRV9CT0RZCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIGlmIHJm
bC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0JPRFk6CiAgICAgICAgICAgIGlmIG5vdCByZmwuYnVmOgog
ICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgdG9fY29uc3VtZSA9IG1pbihsZW4ocmZs
LmJ1ZiksIHJmbC5ib2R5X3JlbWFpbmluZykKICAgICAgICAgICAgZGVsIHJmbC5idWZbOnRvX2Nv
bnN1bWVdCiAgICAgICAgICAgIHJmbC5ib2R5X3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAg
ICAgICAgIGlmIHJmbC5ib2R5X3JlbWFpbmluZyA9PSAwOgogICAgICAgICAgICAgICAgcmZsLnN0
YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgaWYg
cmZsLnN0YXRlID09IEhUVFBfU1RBVEVfQ0hVTks6CiAgICAgICAgICAgIGlmIG5vdCByZmwuYnVm
OgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYgcmZsLmNodW5rX3JlYWRpbmdf
dHJhaWxlcjoKICAgICAgICAgICAgICAgIGlmIGxlbihyZmwuYnVmKSA+PSAyIGFuZCByZmwuYnVm
WzoyXSA9PSBiIlxyXG4iOgogICAgICAgICAgICAgICAgICAgIGRlbCByZmwuYnVmWzoyXQogICAg
ICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQogICAgICAg
ICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgICAg
ICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIHRyX2VuZCA9IHJmbC5idWYuZmluZChiIlxy
XG5cclxuIikKICAgICAgICAgICAgICAgIGlmIHRyX2VuZCAhPSAtMToKICAgICAgICAgICAgICAg
ICAgICBkZWwgcmZsLmJ1Zls6dHJfZW5kICsgNF0KICAgICAgICAgICAgICAgICAgICByZmwuY2h1
bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICByZmwuc3RhdGUg
PSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAg
ICAgICAgICBpZiBsZW4ocmZsLmJ1ZikgPiBNQVhfSERSUzoKICAgICAgICAgICAgICAgICAgICBy
ZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0g
VHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYgcmZsLmNodW5rX3JlYWRp
bmdfbGVuOgogICAgICAgICAgICAgICAgY3JsZiA9IHJmbC5idWYuZmluZChiIlxyXG4iKQogICAg
ICAgICAgICAgICAgaWYgY3JsZiA9PSAtMToKICAgICAgICAgICAgICAgICAgICBpZiBsZW4ocmZs
LmJ1ZikgPiA2NDoKICAgICAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgp
CiAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAg
ICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGxpbmUgPSBieXRlcyhyZmwuYnVmWzpjcmxm
XSkuc3RyaXAoKQogICAgICAgICAgICAgICAgc2VtaSA9IGxpbmUuZmluZChiIjsiKQogICAgICAg
ICAgICAgICAgaGV4X3N0ciA9IGxpbmVbOnNlbWldLnN0cmlwKCkgaWYgc2VtaSAhPSAtMSBlbHNl
IGxpbmUKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBjaHVua19sZW4g
PSBpbnQoaGV4X3N0ciwgMTYpCiAgICAgICAgICAgICAgICAgICAgaWYgY2h1bmtfbGVuIDwgMCBv
ciBjaHVua19sZW4gPiAxNjc3NzIxNjoKICAgICAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9
IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVl
CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICByZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAg
ICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGJy
ZWFrCiAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6Y3JsZiArIDJdCiAgICAgICAgICAgICAg
ICBpZiBjaHVua19sZW4gPT0gMDoKICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGlu
Z190cmFpbGVyID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xl
biA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGVs
c2U6CiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gY2h1
bmtfbGVuCiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UK
ICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gRmFsc2UKICAgICAg
ICAgICAgZWxpZiBnZXRhdHRyKHJmbCwgImNodW5rX3JlYWRpbmdfY3JsZiIsIEZhbHNlKToKICAg
ICAgICAgICAgICAgIGlmIGxlbihyZmwuYnVmKSA8IDI6CiAgICAgICAgICAgICAgICAgICAgYnJl
YWsKICAgICAgICAgICAgICAgIGlmIHJmbC5idWZbOjJdICE9IGIiXHJcbiI6CiAgICAgICAgICAg
ICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgcmZsLmlz
X2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAg
ZGVsIHJmbC5idWZbOjJdCiAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0g
RmFsc2UKICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IFRydWUKICAgICAg
ICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4obGVuKHJmbC5idWYp
LCByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcpCiAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1
Zls6dG9fY29uc3VtZV0KICAgICAgICAgICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmlu
ZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAgICAgICBpZiByZmwuY2h1bmtfcGF5bG9hZF9yZW1h
aW5pbmcgPT0gMDoKICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0g
VHJ1ZQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBpZiByZmwuc3RhdGUgPT0gSFRUUF9T
VEFURV9DTE9TRV9CT0RZOgogICAgICAgICAgICBkZWwgcmZsLmJ1Zls6XQogICAgICAgICAgICBi
cmVhawoKICAgIGlmIGZsYWdzICYgMHgwNToKICAgICAgICByZXNwX2Zsb3dzLnBvcChyaywgTm9u
ZSkKICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibCkKCgpkZWYgY29ycmVs
YXRlX3Jlc3BvbnNlKHBlbmRpbmdfdGJsLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHJlc3BfZmxv
d3M9Tm9uZSwgc2VxPU5vbmUsIGZsYWdzPTAsIGlzX3RydW5jYXRlZD1GYWxzZSk6CiAgICAiIiJB
dHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhlIG9sZGVzdCByZXF1ZXN0IG9uIGEgY29ubmVj
dGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5nIGNhbiBsZWF2ZSBzZXZlcmFsIHJlcXVlc3Rz
IHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXItdHVwbGUuIENvbnN1bWUgZXhhY3RseSBvbmUg
ZW50cnk7IGRlbGV0aW5nIHRoZSB3aG9sZSBrZXkgaGVyZSBsb3NlcwogICAgZXZlcnkgcmVxdWVz
dCBhZnRlciB0aGUgZmlyc3QgcmVzcG9uc2UuCiAgICAiIiIKICAgIGlmIHJlc3BfZmxvd3MgaXMg
bm90IE5vbmU6CiAgICAgICAgaGFuZGxlX3Jlc3BvbnNlKHJlc3BfZmxvd3MsIHJrLCBwYXlsb2Fk
LCBub3csIG91dCwgcGVuZGluZ190YmwsCiAgICAgICAgICAgICAgICAgICAgICAgIHNlcT1zZXEs
IGZsYWdzPWZsYWdzLCBpc190cnVuY2F0ZWQ9aXNfdHJ1bmNhdGVkKQogICAgICAgIHJldHVybiBU
cnVlCiAgICByZXMgPSBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxvYWQpCiAgICBpZiByZXNbMF0g
aXMgTm9uZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHN0LCBjbGVuLCBoZWFkX2xlbiA9IHJl
c1swXSwgcmVzWzFdLCByZXNbMl0KICAgIGlmIDEwMCA8PSBzdCA8PSAxOTkgYW5kIHN0ICE9IDEw
MToKICAgICAgICBpZiBoZWFkX2xlbiBpcyBub3QgTm9uZSBhbmQgbGVuKHBheWxvYWQpID4gaGVh
ZF9sZW46CiAgICAgICAgICAgIHJldHVybiBjb3JyZWxhdGVfcmVzcG9uc2UocGVuZGluZ190Ymws
IHJrLCBwYXlsb2FkW2hlYWRfbGVuOl0sIG5vdywgb3V0KQogICAgICAgIHJldHVybiBGYWxzZQog
ICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQogICAgaWYgbm90IGVudDoKICAgICAgICByZXR1
cm4gRmFsc2UKICAgIGV2LCBzdGFydGVkID0gZW50LnBvcCgwKQogICAgaWYgbm90IGVudDoKICAg
ICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICBldlsic3RhdHVzIl0gPSBzdAogICAg
ZXZbImR1cmF0aW9uX21zIl0gPSBtYXgoMCwgaW50KChub3cgLSBzdGFydGVkKSAqIDEwMDApKQog
ICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAgICBldlsicmVzcF9ieXRlcyJdID0gY2xlbgog
ICAgb3V0LmFwcGVuZChldikKICAgIHJldHVybiBUcnVlCgoKZGVmIHZhbGlkX3BvcnQocCk6CiAg
ICB0cnk6CiAgICAgICAgcmV0dXJuIDEgPD0gaW50KHApIDw9IDY1NTM1CiAgICBleGNlcHQgKFR5
cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGJhc2ljX3Vz
ZXIodmFsdWUpOgogICAgIiIiQXV0aG9yaXphdGlvbiBoZWFkZXIgdmFsdWUgLT4gKHVzZXJ8Tm9u
ZSwgc2NoZW1lfE5vbmUpLiBCYXNpYyBvbmx5LiIiIgogICAgcGFydHMgPSB2YWx1ZS5zdHJpcCgp
LnNwbGl0KE5vbmUsIDEpCiAgICBpZiBsZW4ocGFydHMpICE9IDI6CiAgICAgICAgcmV0dXJuIE5v
bmUsIE5vbmUKICAgIHNjaGVtZSA9IHBhcnRzWzBdLmxvd2VyKCkKICAgIGlmIHNjaGVtZSA9PSAi
YmFzaWMiOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGFkID0gcGFydHNbMV0uc3RyaXAoKQog
ICAgICAgICAgICBpZiBsZW4ocGFkKSA+IDEwMjQ6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9u
ZSwgTm9uZQogICAgICAgICAgICBwYWQgKz0gIj0iICogKC1sZW4ocGFkKSAlIDQpCiAgICAgICAg
ICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNvZGUocGFkKQogICAgICAgICAgICBpZiBsZW4ocmF3KSA+
IDUxMjoKICAgICAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAgIGlmIGIi
OiIgaW4gcmF3OgogICAgICAgICAgICAgICAgdXNlciA9IHJhdy5zcGxpdChiIjoiLCAxKVswXQog
ICAgICAgICAgICAgICAgdXNlciA9IHVzZXIuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjY0
XQogICAgICAgICAgICAgICAgaWYgdXNlcjoKICAgICAgICAgICAgICAgICAgICByZXR1cm4gdXNl
ciwgImJhc2ljIgogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHJldHVybiBO
b25lLCBOb25lCiAgICBlbGlmIHNjaGVtZSA9PSAiYmVhcmVyIjoKICAgICAgICByZXR1cm4gTm9u
ZSwgImJlYXJlciIKICAgIHJldHVybiBOb25lLCBOb25lCgoKZGVmIG5vcm1hbGl6ZV93c3NlX3Vz
ZXJuYW1lKHZhbHVlKToKICAgICIiIlJldHVybiBhIHNtYWxsLCBwcmludGFibGUgdXNlcm5hbWUg
b3IgTm9uZTsgbmV2ZXIgcmV0dXJuIHRva2VuIGRhdGEuIiIiCiAgICBpZiB2YWx1ZSBpcyBOb25l
OgogICAgICAgIHJldHVybiBOb25lCiAgICB0cnk6CiAgICAgICAgdXNlcm5hbWUgPSB2YWx1ZS5z
dHJpcCgpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBOb25lCiAgICBpZiBu
b3QgdXNlcm5hbWUgb3IgbGVuKHVzZXJuYW1lKSA+IE1BWF9XU1NFX1VTRVJOQU1FOgogICAgICAg
IHJldHVybiBOb25lCiAgICBmb3IgY2hhciBpbiB1c2VybmFtZToKICAgICAgICBpZiB1bmljb2Rl
ZGF0YS5jYXRlZ29yeShjaGFyKS5zdGFydHN3aXRoKCJDIik6CiAgICAgICAgICAgIHJldHVybiBO
b25lCiAgICByZXR1cm4gdXNlcm5hbWUKCgpkZWYgZXh0cmFjdF93c3NlX3VzZXJuYW1lKGJvZHkp
OgogICAgIiIiUGFyc2UgYSBib3VuZGVkLCBwb3NzaWJseSBwYXJ0aWFsIFNPQVAgcHJlZml4IGFu
ZCByZXR1cm4gb25seSBVc2VybmFtZS4KCiAgICBFeHBhdCBpcyBydW4gaW5jcmVtZW50YWxseSBz
byBhIFVzZXJuYW1lVG9rZW4gaW4gdGhlIFNPQVAgSGVhZGVyIGNhbiBiZQogICAgcmVjb2duaXpl
ZCB3aXRob3V0IHJldGFpbmluZyBvciByZXF1aXJpbmcgdGhlIGNvbXBsZXRlIHJlcXVlc3QgYm9k
eS4KICAgIERURC9lbnRpdHkgZGVjbGFyYXRpb25zIGFyZSByZWplY3RlZCBiZWZvcmUgcGFyc2lu
Zy4KICAgICIiIgogICAgaWYgbm90IGJvZHkgb3IgbGVuKGJvZHkpID4gTUFYX1dTU0VfQk9EWV9C
WVRFUyBvciBiIlx4MDAiIGluIGJvZHk6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGxvd2VyZWQg
PSBieXRlcyhib2R5KS5sb3dlcigpCiAgICBpZiBiIjwhZG9jdHlwZSIgaW4gbG93ZXJlZCBvciBi
IjwhZW50aXR5IiBpbiBsb3dlcmVkOgogICAgICAgIHJldHVybiBOb25lCgogICAgc3RhdGUgPSB7
InN0YWNrIjogW10sICJ0b2tlbl9kZXB0aCI6IDAsICJ1c2VybmFtZV9kZXB0aCI6IDAsCiAgICAg
ICAgICAgICAiY2hhcnMiOiBbXSwgInRvb19sb25nIjogRmFsc2UsICJyZXN1bHQiOiBOb25lfQoK
ICAgIGRlZiBzcGxpdF9uYW1lKG5hbWUpOgogICAgICAgIGlmICJ9IiBub3QgaW4gbmFtZToKICAg
ICAgICAgICAgcmV0dXJuICIiLCBuYW1lCiAgICAgICAgcmV0dXJuIG5hbWUucnNwbGl0KCJ9Iiwg
MSkKCiAgICBkZWYgc3RhcnQobmFtZSwgYXR0cnMpOgogICAgICAgIG5hbWVzcGFjZSwgbG9jYWxf
bmFtZSA9IHNwbGl0X25hbWUobmFtZSkKICAgICAgICBzdGF0ZVsic3RhY2siXS5hcHBlbmQoKG5h
bWVzcGFjZSwgbG9jYWxfbmFtZSkpCiAgICAgICAgZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0p
CiAgICAgICAgaWYgKG5vdCBzdGF0ZVsidG9rZW5fZGVwdGgiXSBhbmQgbG9jYWxfbmFtZSA9PSAi
VXNlcm5hbWVUb2tlbiIgYW5kCiAgICAgICAgICAgICAgICBuYW1lc3BhY2UgaW4gV1NTRV9OQU1F
U1BBQ0VTKToKICAgICAgICAgICAgc3RhdGVbInRva2VuX2RlcHRoIl0gPSBkZXB0aAogICAgICAg
IGVsaWYgKHN0YXRlWyJ0b2tlbl9kZXB0aCJdIGFuZAogICAgICAgICAgICAgIGRlcHRoID09IHN0
YXRlWyJ0b2tlbl9kZXB0aCJdICsgMSBhbmQKICAgICAgICAgICAgICBsb2NhbF9uYW1lID09ICJV
c2VybmFtZSIgYW5kCiAgICAgICAgICAgICAgbmFtZXNwYWNlID09IHN0YXRlWyJzdGFjayJdW3N0
YXRlWyJ0b2tlbl9kZXB0aCJdIC0gMV1bMF0pOgogICAgICAgICAgICBzdGF0ZVsidXNlcm5hbWVf
ZGVwdGgiXSA9IGRlcHRoCiAgICAgICAgICAgIHN0YXRlWyJjaGFycyJdID0gW10KICAgICAgICAg
ICAgc3RhdGVbInRvb19sb25nIl0gPSBGYWxzZQoKICAgIGRlZiBjaGFycyh2YWx1ZSk6CiAgICAg
ICAgaWYgbm90IHN0YXRlWyJ1c2VybmFtZV9kZXB0aCJdIG9yIHN0YXRlWyJ0b29fbG9uZyJdOgog
ICAgICAgICAgICByZXR1cm4KICAgICAgICBzdGF0ZVsiY2hhcnMiXS5hcHBlbmQodmFsdWUpCiAg
ICAgICAgaWYgc3VtKFtsZW4ocGFydCkgZm9yIHBhcnQgaW4gc3RhdGVbImNoYXJzIl1dKSA+IE1B
WF9XU1NFX1VTRVJOQU1FICsgMjoKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAg
ICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IFRydWUKCiAgICBkZWYgZW5kKG5hbWUpOgogICAg
ICAgIGRlcHRoID0gbGVuKHN0YXRlWyJzdGFjayJdKQogICAgICAgIGlmIHN0YXRlWyJ1c2VybmFt
ZV9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAgICBpZiBub3Qgc3RhdGVbInRvb19sb25nIl0g
YW5kIHN0YXRlWyJyZXN1bHQiXSBpcyBOb25lOgogICAgICAgICAgICAgICAgc3RhdGVbInJlc3Vs
dCJdID0gbm9ybWFsaXplX3dzc2VfdXNlcm5hbWUoCiAgICAgICAgICAgICAgICAgICAgdSIiLmpv
aW4oc3RhdGVbImNoYXJzIl0pKQogICAgICAgICAgICBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9
IDAKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAgICAgIGlmIHN0YXRlWyJ0b2tl
bl9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAgICBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9IDAK
ICAgICAgICBpZiBzdGF0ZVsic3RhY2siXToKICAgICAgICAgICAgc3RhdGVbInN0YWNrIl0ucG9w
KCkKCiAgICB0cnk6CiAgICAgICAgcGFyc2VyID0gZXhwYXQuUGFyc2VyQ3JlYXRlKE5vbmUsICJ9
IikKICAgICAgICBpZiBoYXNhdHRyKHBhcnNlciwgInJldHVybnNfdW5pY29kZSIpOgogICAgICAg
ICAgICBwYXJzZXIucmV0dXJuc191bmljb2RlID0gVHJ1ZQogICAgICAgIHBhcnNlci5TdGFydEVs
ZW1lbnRIYW5kbGVyID0gc3RhcnQKICAgICAgICBwYXJzZXIuQ2hhcmFjdGVyRGF0YUhhbmRsZXIg
PSBjaGFycwogICAgICAgIHBhcnNlci5FbmRFbGVtZW50SGFuZGxlciA9IGVuZAogICAgICAgIGlm
IChoYXNhdHRyKHBhcnNlciwgIlNldFBhcmFtRW50aXR5UGFyc2luZyIpIGFuZAogICAgICAgICAg
ICAgICAgaGFzYXR0cihleHBhdCwgIlhNTF9QQVJBTV9FTlRJVFlfUEFSU0lOR19ORVZFUiIpKToK
ICAgICAgICAgICAgcGFyc2VyLlNldFBhcmFtRW50aXR5UGFyc2luZyhleHBhdC5YTUxfUEFSQU1f
RU5USVRZX1BBUlNJTkdfTkVWRVIpCiAgICAgICAgcGFyc2VyLlBhcnNlKGJ5dGVzKGJvZHkpLCBG
YWxzZSkKICAgIGV4Y2VwdCAoZXhwYXQuRXhwYXRFcnJvciwgVmFsdWVFcnJvciwgVHlwZUVycm9y
KToKICAgICAgICAjIEEgYm91bmRlZCBwcmVmaXggaXMgY29tbW9ubHkgaW5jb21wbGV0ZS4gQSB1
c2VybmFtZSBmdWxseSBjbG9zZWQKICAgICAgICAjIGJlZm9yZSB0aGUgdHJ1bmNhdGlvbiBwb2lu
dCBpcyBzdGlsbCBzYWZlIHRvIHVzZS4KICAgICAgICBwYXNzCiAgICByZXR1cm4gc3RhdGVbInJl
c3VsdCJdCgoKZGVmIGlzX3NvYXBfY29udGVudF90eXBlKHZhbHVlKToKICAgIGlmIG5vdCB2YWx1
ZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIG1lZGlhX3R5cGUgPSB2YWx1ZS5zcGxpdCgiOyIs
IDEpWzBdLnN0cmlwKCkubG93ZXIoKQogICAgcmV0dXJuIChtZWRpYV90eXBlIGluICgidGV4dC94
bWwiLCAiYXBwbGljYXRpb24veG1sIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgImFwcGxp
Y2F0aW9uL3NvYXAreG1sIikgb3IKICAgICAgICAgICAgbWVkaWFfdHlwZS5lbmRzd2l0aCgiK3ht
bCIpKQoKCmRlZiBmaW5pc2hfZXZlbnQoZmxvdywga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAs
IHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KToKICAgIGggPSBmbG93LmhkcnMKICAgIHVzZXIgPSBz
Y2hlbWUgPSBOb25lCiAgICBhdXRoeiA9IGguZ2V0KCJhdXRob3JpemF0aW9uIikKICAgIGlmIGF1
dGh6OgogICAgICAgIHVzZXIsIHNjaGVtZSA9IGJhc2ljX3VzZXIoYXV0aHopCiAgICAjIFczQyB0
cmFjZSBjb250ZXh0OiBob25vciBpbmNvbWluZyB0cmFjZXBhcmVudCwgZWxzZSBnZW5lcmF0ZSBv
bmUgc28KICAgICMgZXZlcnkgdHJhbnNhY3Rpb24gY2FycmllcyBhIHRyYWNlX2lkIGZvciBodWIt
c2lkZSBjb3JyZWxhdGlvbi4KICAgICMgTk9URSBweTIuNjogYnl0ZXMgaGFzIG5vIC5oZXgoKSDi
gJQgdXNlIGJpbmFzY2lpLmhleGxpZnkuCiAgICB0cCA9IGguZ2V0KCJ0cmFjZXBhcmVudCIpCiAg
ICB0cmFjZV9pZCA9IE5vbmUKICAgIGlmIHRwOgogICAgICAgIHBhcnRzID0gdHAuc3BsaXQoIi0i
KQogICAgICAgIGlmIGxlbihwYXJ0cykgPT0gNCBhbmQgbGVuKHBhcnRzWzFdKSA9PSAzMjoKICAg
ICAgICAgICAgdHJhY2VfaWQgPSBwYXJ0c1sxXS5sb3dlcigpCiAgICBpZiBub3QgdHJhY2VfaWQ6
CiAgICAgICAgdHJ5OgogICAgICAgICAgICBybmQgPSBiaW5hc2NpaS5oZXhsaWZ5KG9zLnVyYW5k
b20oMTYpKQogICAgICAgICAgICBybmQgPSBybmQuZGVjb2RlKCJhc2NpaSIpIGlmIGhhc2F0dHIo
cm5kLCAiZGVjb2RlIikgZWxzZSBybmQKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAg
ICAgICBybmQgPSAoIiUwMzJ4IiAlIChpbnQodGltZS50aW1lKCkgKiAxMDAwKSkpWy0zMjpdCiAg
ICAgICAgcGlkOCA9IGJpbmFzY2lpLmhleGxpZnkob3MudXJhbmRvbSg4KSkKICAgICAgICBwaWQ4
ID0gcGlkOC5kZWNvZGUoImFzY2lpIikgaWYgaGFzYXR0cihwaWQ4LCAiZGVjb2RlIikgZWxzZSBw
aWQ4CiAgICAgICAgdHAgPSAiMDAtJXMtJXMtMDEiICUgKHJuZCwgcGlkOCkKICAgICAgICB0cmFj
ZV9pZCA9IHJuZAogICAgZXYgPSB7CiAgICAgICAgInRzIjogaW50KHRpbWUudGltZSgpKSwKICAg
ICAgICAiaG9zdCI6IG5vZGVfaG9zdCwKICAgICAgICAic3JjIjogInBjYXAiLAogICAgICAgICJz
ZXJ2aWNlIjogInBvcnQ6JWQiICUgZHBvcnQsCiAgICAgICAgIm1ldGhvZCI6IGguZ2V0KCJfbWV0
aG9kIikgb3IgIi0iLAogICAgICAgICJwYXRoIjogKGguZ2V0KCJfcGF0aCIpIG9yICItIikuc3Bs
aXQoIj8iLCAxKVswXVs6MTIwXSwKICAgICAgICAidXNlciI6IHVzZXIsCiAgICAgICAgInNjaGVt
ZSI6IHNjaGVtZSwKICAgICAgICAiYmFzaWNfdXNlciI6IHVzZXIgaWYgc2NoZW1lID09ICJiYXNp
YyIgYW5kIHVzZXIgZWxzZSBOb25lLAogICAgICAgICJ3c3NlX3VzZXIiOiBOb25lLAogICAgICAg
ICJwaWQiOiBOb25lLAogICAgICAgICJzb3VyY2VfcHJvYmUiOiAicGNhcC1odHRwIiwKICAgICAg
ICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIpLAogICAgICAgICJ1c2VyX2FnZW50IjogaC5nZXQo
InVzZXItYWdlbnQiKSwKICAgICAgICAieF9mb3J3YXJkZWRfZm9yIjogaC5nZXQoIngtZm9yd2Fy
ZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIiOiBzcmNfaXAsCiAgICAgICAgImNhbGxlcl9wb3J0
Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6IGRzdF9pcCwKICAgICAgICAiZHN0X3BvcnQiOiBk
cG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRvcmluZyBzY2hlbWEgKG9wcyBBUEktbG9nIGZvcm1h
dCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgYXJlIHJlc3Bv
bnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1vbmx5CiAgICAgICAgIyBjYXB0dXJlIGNhbm5vdCBz
ZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUgaHViIHRvIGVucmljaCBvciBsZWF2ZS4KICAgICAg
ICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAogICAgICAgICJ0cmFjZV9pZCI6IHRyYWNlX2lkLAog
ICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwgICAgICAgICAgIyBodWIgbWFwcyBwb3J0LT5zZXJ2
aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAgICAibW9kdWxlX2lkIjogInBjYXAtaHR0cCIsCiAg
ICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNlIGNvcnJlbGF0aW9uIG9ubHkgZm9yIG1vbml0b3Jl
ZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyByZXNwb25zZS1zaWRlIGZpbHRlciBtYXkgc3RpbGwg
YWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNwb3J0IGVxdWFsIHRvIGEKICAgICMgbW9uaXRvcmVk
IHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVjYXVzZSBwYXJzZV9yZXNwb25zZV9oZWFkIHJlamVj
dHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRwb3J0IGluIHBvcnRzIG9yIGguZ2V0KCJfbWV0aG9k
IikpIGVsc2UgTm9uZQoKCmRlZiBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBv
dXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiRGlzY2FyZCBjYXB0dXJlIGJ1ZmZlcnMsIHRo
ZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRpemVkIGV2ZW50IG9ubHkuIiIiCiAgICBkc3RfaXAsIGRw
b3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAgZXYgPSBmbC53c3NlX2V2ZW50IGlmIGZsLmF3
YWl0aW5nX3dzc2UgZWxzZSBmbC5ldmVudAogICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAg
ICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgaWYgbm90IGV2OgogICAgICAgIHJldHVybgogICAg
ZXZbInJlcV9ieXRlcyJdID0gZmwuaGVhZF9ieXRlcwogICAgaWYgcGVuZGluZ190YmwgaXMgTm9u
ZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgIHJldHVybgogICAgcmsgPSAoZHN0X2lw
LCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgIHZlcmlmaWVkID0gKGZsLmdlbmVyYXRpb24gPiAw
KQogICAgaWYgaXNfY29ycmVsYXRpb25fZGlzYWJsZWQocmssIHZlcmlmaWVkKToKICAgICAgICBv
dXQuYXBwZW5kKGV2KQogICAgICAgIHJldHVybgogICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJr
KQogICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgaWYgbGVuKHBlbmRpbmdfdGJsKSA+PSBQRU5E
SU5HX01BWDoKICAgICAgICAgICAgX2ZsdXNoX29sZGVzdF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBv
dXQpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmxbcmtdID0gW10KICAgIGVsaWYgbGVuKGVudCkg
Pj0gUEVORElOR19QRVJfRkxPVzoKICAgICAgICB3aGlsZSBwZW5kaW5nX3RibC5nZXQocmspOgog
ICAgICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibCkKICAgICAgICBjb3Jy
X2Rpc2FibGVkX2luc2VydChyaykKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgIHJldHVy
bgogICAgc3RhcnRlZCA9IGZsLmZpcnN0X2J5dGVfdHMgaWYgZmwuZmlyc3RfYnl0ZV90cyA+IDAg
ZWxzZSAobm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNlIHRpbWUudGltZSgpKQogICAgZW50LmFw
cGVuZChbZXYsIHN0YXJ0ZWRdKQoKCmRlZiBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZXYsIGhl
YWRfYnl0ZXMsIGZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdywgZ2Vu
ZXJhdGlvbj0wKToKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBp
ZiBub3QgZXY6CiAgICAgICAgcmV0dXJuCiAgICBldlsicmVxX2J5dGVzIl0gPSBoZWFkX2J5dGVz
CiAgICBpZiBwZW5kaW5nX3RibCBpcyBOb25lOgogICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAg
ICAgcmV0dXJuCiAgICByayA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgdmVy
aWZpZWQgPSAoZ2VuZXJhdGlvbiA+IDApCiAgICBpZiBpc19jb3JyZWxhdGlvbl9kaXNhYmxlZChy
aywgdmVyaWZpZWQpOgogICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgcmV0dXJuCiAgICBl
bnQgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICBpZiBlbnQgaXMgTm9uZToKICAgICAgICBpZiBs
ZW4ocGVuZGluZ190YmwpID49IFBFTkRJTkdfTUFYOgogICAgICAgICAgICBfZmx1c2hfb2xkZXN0
X3BlbmRpbmcocGVuZGluZ190YmwsIG91dCkKICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10g
PSBbXQogICAgZWxpZiBsZW4oZW50KSA+PSBQRU5ESU5HX1BFUl9GTE9XOgogICAgICAgIHdoaWxl
IHBlbmRpbmdfdGJsLmdldChyayk6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQsIHBl
bmRpbmdfdGJsKQogICAgICAgIGNvcnJfZGlzYWJsZWRfaW5zZXJ0KHJrKQogICAgICAgIG91dC5h
cHBlbmQoZXYpCiAgICAgICAgcmV0dXJuCiAgICBzdGFydGVkID0gZmlyc3RfYnl0ZV90cyBpZiBm
aXJzdF9ieXRlX3RzID4gMCBlbHNlIChub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGltZS50
aW1lKCkpCiAgICBlbnQuYXBwZW5kKFtldiwgc3RhcnRlZCwgRmFsc2UsIDAuMCwgZ2VuZXJhdGlv
bl0pCgoKCgpkZWYgX3RyeV93c3NlX2JvZHkoZmxvd3MsIGtleSwgZmwsIHBheWxvYWQsIG1ldGEs
IG91dCwgcGVuZGluZ190YmwsIG5vdyk6CiAgICAiIiJBcHBlbmQgbm8gbW9yZSB0aGFuIGJvZHlf
Z29hbCBieXRlcyBhbmQgZmluaXNoIGFzIHNvb24gYXMgcG9zc2libGUuIiIiCiAgICByZW1haW5p
bmcgPSBmbC53c3NlX2dvYWwgLSBsZW4oZmwud3NzZV9idWYpCiAgICBpZiByZW1haW5pbmcgPiAw
IGFuZCBwYXlsb2FkOgogICAgICAgIGNvcHlfbGVuID0gbWluKHJlbWFpbmluZywgbGVuKHBheWxv
YWQpKQogICAgICAgIGZsLndzc2VfYnVmLmV4dGVuZChieXRlYXJyYXkocGF5bG9hZFs6Y29weV9s
ZW5dKSkKICAgIHVzZXJuYW1lID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLndzc2VfYnVmKQog
ICAgaWYgdXNlcm5hbWU6CiAgICAgICAgZmwud3NzZV9ldmVudFsid3NzZV91c2VyIl0gPSB1c2Vy
bmFtZQogICAgICAgIGZsLndzc2VfZXZlbnRbInVzZXIiXSA9IHVzZXJuYW1lCiAgICAgICAgZmwu
d3NzZV9ldmVudFsic2NoZW1lIl0gPSAid3NzZSIKICAgIGlmIHVzZXJuYW1lIG9yIGxlbihmbC53
c3NlX2J1ZikgPj0gZmwud3NzZV9nb2FsOgogICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGlu
ZyhmbC53c3NlX2V2ZW50LCBmbC5oZWFkX2J5dGVzLCBmbC5maXJzdF9ieXRlX3RzLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3csIGdl
bmVyYXRpb249ZmwuZ2VuZXJhdGlvbikKICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gRmFsc2UK
ICAgICAgICByZXR1cm4gVHJ1ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhhbmRsZV9wYXlsb2Fk
KGZsb3dzLCBrZXksIHJldl9rZXksIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91
dCwKICAgICAgICAgICAgICAgICAgIHBlbmRpbmdfdGJsPU5vbmUsIG5vdz1Ob25lLCB3c3NlX2Jv
ZHlfYnl0ZXM9MCwKICAgICAgICAgICAgICAgICAgIHNlcT1Ob25lLCBmbGFncz0wLCBpc190cnVu
Y2F0ZWQ9RmFsc2UsIHJlc3BfZmxvd3M9Tm9uZSk6CiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAs
IHNwb3J0ID0gbWV0YQogICAgaWYgbm90IHZhbGlkX3BvcnQoZHBvcnQpIG9yIG5vdCB2YWxpZF9w
b3J0KHNwb3J0KToKICAgICAgICByZXR1cm4KICAgIGlmIG5vdyBpcyBOb25lOgogICAgICAgIG5v
dyA9IHRpbWUudGltZSgpCgogICAgIyBTWU4gaGFuZGxpbmc6IHJlc2V0IGZsb3cgYW5kIHN0YXJ0
IHNlcXVlbmNlIHRyYWNraW5nCiAgICBpZiBmbGFncyAmIDB4MDIgYW5kIHNlcSBpcyBub3QgTm9u
ZToKICAgICAgICBmbCA9IGZsb3dzLmdldChrZXkpCiAgICAgICAgaWYgZmwgaXMgbm90IE5vbmUg
YW5kIGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQ6CiAgICAgICAgICAgIG91dC5h
cHBlbmQoZmwud3NzZV9ldmVudCkKICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNl
CiAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgICAgICBjb3Jy
X2Rpc2FibGVkX2VyYXNlKHJrKQoKICAgICAgICBpZiBwZW5kaW5nX3RibCBpcyBub3QgTm9uZToK
ICAgICAgICAgICAgZW50ID0gcGVuZGluZ190YmwucG9wKHJrLCBOb25lKQogICAgICAgICAgICBp
ZiBlbnQ6CiAgICAgICAgICAgICAgICBmb3IgaXRlbSBpbiBlbnQ6CiAgICAgICAgICAgICAgICAg
ICAgaXNfdG9tYiA9IGl0ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZhbHNlCiAgICAgICAg
ICAgICAgICAgICAgaWYgbm90IGlzX3RvbWI6CiAgICAgICAgICAgICAgICAgICAgICAgIG91dC5h
cHBlbmQoaXRlbVswXSkKCiAgICAgICAgaWYgcmVzcF9mbG93cyBpcyBub3QgTm9uZSBhbmQgcmsg
aW4gcmVzcF9mbG93czoKICAgICAgICAgICAgcmVzcF9mbG93cy5wb3AocmssIE5vbmUpCiAgICAg
ICAgaWYgcmV2X2tleSBpcyBub3QgTm9uZSBhbmQgcmV2X2tleSBpbiBmbG93czoKICAgICAgICAg
ICAgZmxvd3MucG9wKHJldl9rZXksIE5vbmUpCgogICAgICAgIG9sZF9nZW4gPSBmbC5nZW5lcmF0
aW9uIGlmIGZsIGlzIG5vdCBOb25lIGVsc2UgMAogICAgICAgIGZsID0gRmxvdygpCiAgICAgICAg
ZmwuZ2VuZXJhdGlvbiA9IG9sZF9nZW4gKyAxCiAgICAgICAgZmwuaGFzX3NlcSA9IFRydWUKICAg
ICAgICBmbC5uZXh0X3NlcSA9IChzZXEgKyAxKSAmIDB4RkZGRkZGRkYKICAgICAgICBmbC50b3Vj
aGVkID0gbm93CiAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IDAuMAogICAgICAgIGZsb3dzW2tl
eV0gPSBmbAogICAgICAgIHJldHVybgoKICAgIGZsID0gZmxvd3MuZ2V0KGtleSkKICAgIGlmIGZs
IGlzIE5vbmU6CiAgICAgICAgZmwgPSBGbG93KCkKICAgICAgICBmbG93c1trZXldID0gZmwKICAg
ICAgICBpZiBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgICAgICBlbmZvcmNlX2xpbWl0
KGZsb3dzLCBub3cpCiAgICBmbC50b3VjaGVkID0gbm93CgogICAgIyBDaGVjayBrZWVwLWFsaXZl
IHJlcXVlc3QgdHJhbnNpdGlvbiB3aGlsZSB3YWl0aW5nIGZvciBib2R5IGluIGRpcmVjdCB0ZXN0
IGZlZWQgbW9kZQogICAgaWYgc2VxIGlzIE5vbmUgYW5kIGZsLmF3YWl0aW5nX3dzc2UgYW5kIHBh
eWxvYWQgYW5kIGlzX21ldGhvZF9vcl9wcmVmaXgocGF5bG9hZCk6CiAgICAgICAgX2VtaXRfcmVx
dWVzdF90b19wZW5kaW5nKGZsLndzc2VfZXZlbnQsIGZsLmhlYWRfYnl0ZXMsIGZsLmZpcnN0X2J5
dGVfdHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1ldGEsIG91dCwgcGVuZGlu
Z190YmwsIG5vdykKICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gRmFsc2UKICAgICAgICBmbC5z
dGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKCiAg
ICBwbGVuID0gbGVuKHBheWxvYWQpIGlmIHBheWxvYWQgZWxzZSAwCiAgICBpZiBwbGVuID4gMDoK
ICAgICAgICBpZiBzZXEgaXMgTm9uZToKICAgICAgICAgICAgZmwuYnVmLmV4dGVuZChwYXlsb2Fk
KQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGlmIG5vdCBmbC5oYXNfc2VxOgogICAgICAgICAg
ICAgICAgaWYgaXNfbWV0aG9kX29yX3ByZWZpeChwYXlsb2FkKToKICAgICAgICAgICAgICAgICAg
ICBmbC5oYXNfc2VxID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGZsLm5leHRfc2VxID0gc2Vx
CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gRmFsc2UKICAgICAgICAgICAgICAg
IGVsc2U6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKGZsLm9vbykgPCBNQVhfT09PX1NFR01F
TlRTIGFuZCBub3QgaXNfdHJ1bmNhdGVkOgogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qg
YW55KHMgPT0gc2VxIGZvciBzLCBfIGluIGZsLm9vbyk6CiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBheWxvYWQpKSkKICAgICAgICAgICAgICAg
ICAgICByZXR1cm4KCiAgICAgICAgICAgIGRpZmYgPSBzZXFfZGlmZihzZXEsIGZsLm5leHRfc2Vx
KQogICAgICAgICAgICBpZiBkaWZmID09IDA6CiAgICAgICAgICAgICAgICBpZiBpc190cnVuY2F0
ZWQ6CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAg
ICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBmbC5idWYuZXh0ZW5kKHBheWxvYWQpCiAgICAg
ICAgICAgICAgICAgICAgZmwubmV4dF9zZXEgPSAoZmwubmV4dF9zZXEgKyBwbGVuKSAmIDB4RkZG
RkZGRkYKICAgICAgICAgICAgICAgICAgICBfZHJhaW5fb29vKGZsKQogICAgICAgICAgICBlbGlm
IGRpZmYgPCAwOgogICAgICAgICAgICAgICAgb3ZlcmxhcCA9IC1kaWZmCiAgICAgICAgICAgICAg
ICBpZiBvdmVybGFwIDwgcGxlbiBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAg
ICAgICBmbC5idWYuZXh0ZW5kKHBheWxvYWRbb3ZlcmxhcDpdKQogICAgICAgICAgICAgICAgICAg
IGZsLm5leHRfc2VxID0gKGZsLm5leHRfc2VxICsgcGxlbiAtIG92ZXJsYXApICYgMHhGRkZGRkZG
RgogICAgICAgICAgICAgICAgICAgIF9kcmFpbl9vb28oZmwpCiAgICAgICAgICAgIGVsc2U6CiAg
ICAgICAgICAgICAgICBpZiBsZW4oZmwub29vKSA8IE1BWF9PT09fU0VHTUVOVFMgYW5kIG5vdCBp
c190cnVuY2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGFueShzID09IHNlcSBmb3Ig
cywgXyBpbiBmbC5vb28pOgogICAgICAgICAgICAgICAgICAgICAgICBmbC5vb28uYXBwZW5kKChz
ZXEsIGJ5dGVzKHBheWxvYWQpKSkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAg
ICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQoKICAgICMgSFRUUCBmcmFtaW5nIHN0YXRlIG1hY2hp
bmUKICAgIHdoaWxlIGxlbihmbC5idWYpID4gMCBhbmQgbm90IGZsLmlzX2Jyb2tlbjoKICAgICAg
ICBpZiBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0hFQURFUjoKICAgICAgICAgICAgaWYgbm90IGZs
LmZpcnN0X2J5dGVfdHM6CiAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gbm93Cgog
ICAgICAgICAgICBpZHggPSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgICAgICAgICAgaWYg
aWR4IDwgMDoKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6CiAgICAg
ICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICBm
bC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBzdGFy
dCA9IGZpbmRfaHR0cF9zdGFydChmbC5idWYpCiAgICAgICAgICAgIGlmIHN0YXJ0IDwgMCBvciBz
dGFydCA+IGlkeDoKICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOmlkeCArIDRdCiAgICAgICAg
ICAgICAgICBjb250aW51ZQogICAgICAgICAgICBpZiBzdGFydCA+IDA6CiAgICAgICAgICAgICAg
ICBkZWwgZmwuYnVmWzpzdGFydF0KICAgICAgICAgICAgICAgIGlkeCAtPSBzdGFydAoKICAgICAg
ICAgICAgaGVhZCA9IGJ5dGVzKGZsLmJ1Zls6aWR4XSkKICAgICAgICAgICAgbGluZXMgPSBoZWFk
LnJlcGxhY2UoYiJcclxuIiwgYiJcbiIpLnNwbGl0KGIiXG4iKQogICAgICAgICAgICBmaXJzdCA9
IGxpbmVzWzBdLnN0cmlwKCkuc3BsaXQoKQogICAgICAgICAgICBpZiBsZW4oZmlyc3QpIDwgMiBv
ciBmaXJzdFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKSBub3QgaW4gTUVUSE9EUzoKICAg
ICAgICAgICAgICAgIGRlbCBmbC5idWZbOmlkeCArIDRdCiAgICAgICAgICAgICAgICBjb250aW51
ZQogICAgICAgICAgICBoZHJzID0ge30KICAgICAgICAgICAgaGRyc1siX21ldGhvZCJdID0gZmly
c3RbMF0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAgICAgICAgaGRyc1siX3BhdGgi
XSA9IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAgICAgICAgICAgIGhhc19j
b25mbGljdF9jbCA9IEZhbHNlCiAgICAgICAgICAgIGZpcnN0X2NsID0gTm9uZQogICAgICAgICAg
ICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgICAgICAgICAgaWYgYiI6IiBub3QgaW4gbG46
CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGtuLCBrdiA9IGxu
LnNwbGl0KGIiOiIsIDEpCiAgICAgICAgICAgICAgICBrX25vcm0gPSBrbi5zdHJpcCgpLmxvd2Vy
KCkuZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAgICAgICAgICAgIHZfbm9ybSA9IGt2
LnN0cmlwKCkuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjE4MF0KICAgICAgICAgICAgICAg
IGlmIGtfbm9ybSA9PSAiY29udGVudC1sZW5ndGgiOgogICAgICAgICAgICAgICAgICAgIHRyeToK
ICAgICAgICAgICAgICAgICAgICAgICAgcGFyc2VkX2NsID0gaW50KHZfbm9ybSkKICAgICAgICAg
ICAgICAgICAgICAgICAgaWYgcGFyc2VkX2NsIDwgMDoKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUKICAgICAgICAgICAgICAgICAgICAgICAgZWxpZiBm
aXJzdF9jbCBpcyBOb25lOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3RfY2wgPSBw
YXJzZWRfY2wKICAgICAgICAgICAgICAgICAgICAgICAgZWxpZiBmaXJzdF9jbCAhPSBwYXJzZWRf
Y2w6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYXNfY29uZmxpY3RfY2wgPSBUcnVlCiAg
ICAgICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAg
ICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUKICAgICAgICAgICAgICAgIGhkcnNba19ub3JtXSA9
IHZfbm9ybQogICAgICAgICAgICBmbC5oZHJzID0gaGRycwogICAgICAgICAgICBmbC5ldmVudCA9
IGZpbmlzaF9ldmVudChmbCwga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LCBwb3J0
cywgbm9kZV9ob3N0KQogICAgICAgICAgICBmbC5oZWFkX2J5dGVzID0gaWR4ICsgNAogICAgICAg
ICAgICBkZWwgZmwuYnVmWzppZHggKyA0XQoKICAgICAgICAgICAgaWYgbm90IGZsLmV2ZW50Ogog
ICAgICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAg
IGNvbnRlbnRfbGVuZ3RoID0gaW50KGhkcnMuZ2V0KCJjb250ZW50LWxlbmd0aCIsICIwIikpCiAg
ICAgICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAgICAgICAgICAgICAg
IGNvbnRlbnRfbGVuZ3RoID0gMAogICAgICAgICAgICB0ZSA9IGhkcnMuZ2V0KCJ0cmFuc2Zlci1l
bmNvZGluZyIsICIiKS5sb3dlcigpCiAgICAgICAgICAgIGlzX2NodW5rZWQgPSAiY2h1bmtlZCIg
aW4gdGUKCiAgICAgICAgICAgIGlmIGhhc19jb25mbGljdF9jbCBvciAoY29udGVudF9sZW5ndGgg
PiAwIGFuZCBpc19jaHVua2VkKSBvciAoImNvbnRlbnQtbGVuZ3RoIiBpbiBoZHJzIGFuZCBpc19j
aHVua2VkKToKICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAg
ICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAg
ICAgYWN0aXZlX2JvZHlfZmxvd3MgPSBzdW0oMSBmb3IgY2FuZCBpbiBmbG93cy52YWx1ZXMoKSBp
ZiBjYW5kLmF3YWl0aW5nX3dzc2Ugb3IgKGNhbmQuZXZlbnQgaXMgbm90IE5vbmUgYW5kIGdldGF0
dHIoY2FuZCwgImJvZHlfZ29hbCIsIDApID4gMCkpCiAgICAgICAgICAgIHdzc2VfZWxpZ2libGUg
PSAod3NzZV9ib2R5X2J5dGVzID4gMCBhbmQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBp
c19zb2FwX2NvbnRlbnRfdHlwZShoZHJzLmdldCgiY29udGVudC10eXBlIikpIGFuZAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIGNvbnRlbnRfbGVuZ3RoID4gMCBhbmQKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBub3QgaXNfY2h1bmtlZCBhbmQKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICBhY3RpdmVfYm9keV9mbG93cyA8IE1BWF9XU1NFX0JPRFlfRkxPV1MpCgogICAgICAg
ICAgICBpZiB3c3NlX2VsaWdpYmxlOgogICAgICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9
IFRydWUKICAgICAgICAgICAgICAgIGZsLndzc2VfZXZlbnQgPSBmbC5ldmVudAogICAgICAgICAg
ICAgICAgZmwud3NzZV9idWYgPSBieXRlYXJyYXkoKQogICAgICAgICAgICAgICAgZmwud3NzZV9n
b2FsID0gbWluKGNvbnRlbnRfbGVuZ3RoLCB3c3NlX2JvZHlfYnl0ZXMsIE1BWF9XU1NFX0JPRFlf
QllURVMpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBfZW1pdF9yZXF1ZXN0X3Rv
X3BlbmRpbmcoZmwuZXZlbnQsIGZsLmhlYWRfYnl0ZXMsIGZsLmZpcnN0X2J5dGVfdHMsIG1ldGEs
IG91dCwgcGVuZGluZ190YmwsIG5vdywgZ2VuZXJhdGlvbj1mbC5nZW5lcmF0aW9uKQogICAgICAg
ICAgICBmbC5ldmVudCA9IE5vbmUKCiAgICAgICAgICAgIGlmIGNvbnRlbnRfbGVuZ3RoID4gMDoK
ICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9CT0RZCiAgICAgICAgICAgICAg
ICBmbC5ib2R5X3JlbWFpbmluZyA9IGNvbnRlbnRfbGVuZ3RoCiAgICAgICAgICAgIGVsaWYgaXNf
Y2h1bmtlZDoKICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9DSFVOSwogICAg
ICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBm
bC5jaHVua19yZWFkaW5nX2NybGYgPSBGYWxzZQogICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVh
ZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgIGZsLmNodW5rX3BheWxvYWRfcmVt
YWluaW5nID0gMAogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBI
VFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IG5vdyBp
ZiBmbC5idWYgZWxzZSAwLjAKICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgZWxpZiBmbC5z
dGF0ZSA9PSBIVFRQX1NUQVRFX0JPRFk6CiAgICAgICAgICAgIGlmIG5vdCBmbC5idWY6CiAgICAg
ICAgICAgICAgICBicmVhawogICAgICAgICAgICB0b19jb25zdW1lID0gbWluKGxlbihmbC5idWYp
LCBmbC5ib2R5X3JlbWFpbmluZykKICAgICAgICAgICAgaWYgZmwuYXdhaXRpbmdfd3NzZToKICAg
ICAgICAgICAgICAgIHdzc2VfbmVlZCA9IGZsLndzc2VfZ29hbCAtIGxlbihmbC53c3NlX2J1ZikK
ICAgICAgICAgICAgICAgIGlmIHdzc2VfbmVlZCA+IDA6CiAgICAgICAgICAgICAgICAgICAgY29w
eV9sZW4gPSBtaW4odG9fY29uc3VtZSwgd3NzZV9uZWVkKQogICAgICAgICAgICAgICAgICAgIGZs
Lndzc2VfYnVmLmV4dGVuZChmbC5idWZbOmNvcHlfbGVuXSkKICAgICAgICAgICAgICAgIHVzZXJu
YW1lID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLndzc2VfYnVmKQogICAgICAgICAgICAgICAg
aWYgdXNlcm5hbWUgb3IgbGVuKGZsLndzc2VfYnVmKSA+PSBmbC53c3NlX2dvYWw6CiAgICAgICAg
ICAgICAgICAgICAgZXYgPSBmbC53c3NlX2V2ZW50CiAgICAgICAgICAgICAgICAgICAgaWYgdXNl
cm5hbWU6CiAgICAgICAgICAgICAgICAgICAgICAgIGV2WyJ3c3NlX3VzZXIiXSA9IHVzZXJuYW1l
CiAgICAgICAgICAgICAgICAgICAgICAgIGV2WyJ1c2VyIl0gPSB1c2VybmFtZQogICAgICAgICAg
ICAgICAgICAgICAgICBldlsic2NoZW1lIl0gPSAid3NzZSIKICAgICAgICAgICAgICAgICAgICBf
ZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZXYsIGZsLmhlYWRfYnl0ZXMsIGZsLmZpcnN0X2J5dGVf
dHMsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdywgZ2VuZXJhdGlvbj1mbC5nZW5lcmF0aW9u
KQogICAgICAgICAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQoKICAgICAgICAg
ICAgZGVsIGZsLmJ1Zls6dG9fY29uc3VtZV0KICAgICAgICAgICAgZmwuYm9keV9yZW1haW5pbmcg
LT0gdG9fY29uc3VtZQogICAgICAgICAgICBpZiBmbC5ib2R5X3JlbWFpbmluZyA9PSAwOgogICAg
ICAgICAgICAgICAgaWYgZmwuYXdhaXRpbmdfd3NzZToKICAgICAgICAgICAgICAgICAgICBfZW1p
dF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywgZmwuZmly
c3RfYnl0ZV90cywgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93LCBnZW5lcmF0aW9uPWZsLmdl
bmVyYXRpb24pCiAgICAgICAgICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAg
ICAgICAgICAgICAgICBmbC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgICAg
ICBmbC5maXJzdF9ieXRlX3RzID0gbm93IGlmIGZsLmJ1ZiBlbHNlIDAuMAogICAgICAgICAgICBj
b250aW51ZQoKICAgICAgICBlbGlmIGZsLnN0YXRlID09IEhUVFBfU1RBVEVfQ0hVTks6CiAgICAg
ICAgICAgIGlmIG5vdCBmbC5idWY6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBp
ZiBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXI6CiAgICAgICAgICAgICAgICBpZiBsZW4oZmwuYnVm
KSA+PSAyIGFuZCBmbC5idWZbOjJdID09IGIiXHJcbiI6CiAgICAgICAgICAgICAgICAgICAgZGVs
IGZsLmJ1Zls6Ml0KICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIg
PSBGYWxzZQogICAgICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIK
ICAgICAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gbm93IGlmIGZsLmJ1ZiBlbHNl
IDAuMAogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICB0cl9lbmQg
PSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgICAgICAgICAgICAgIGlmIHRyX2VuZCAhPSAt
MToKICAgICAgICAgICAgICAgICAgICBkZWwgZmwuYnVmWzp0cl9lbmQgKyA0XQogICAgICAgICAg
ICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IEZhbHNlCiAgICAgICAgICAgICAg
ICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAgICAgIGZs
LmZpcnN0X2J5dGVfdHMgPSBub3cgaWYgZmwuYnVmIGVsc2UgMC4wCiAgICAgICAgICAgICAgICAg
ICAgY29udGludWUKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6CiAg
ICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAg
ICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBp
ZiBmbC5jaHVua19yZWFkaW5nX2xlbjoKICAgICAgICAgICAgICAgIGNybGYgPSBmbC5idWYuZmlu
ZChiIlxyXG4iKQogICAgICAgICAgICAgICAgaWYgY3JsZiA8IDA6CiAgICAgICAgICAgICAgICAg
ICAgaWYgbGVuKGZsLmJ1ZikgPiA2NDoKICAgICAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0g
Ynl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQog
ICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBsaW5lID0gYnl0ZXMoZmwu
YnVmWzpjcmxmXSkuc3RyaXAoKQogICAgICAgICAgICAgICAgc2VtaSA9IGxpbmUuZmluZChiIjsi
KQogICAgICAgICAgICAgICAgaGV4X3N0ciA9IGxpbmVbOnNlbWldLnN0cmlwKCkgaWYgc2VtaSAh
PSAtMSBlbHNlIGxpbmUKICAgICAgICAgICAgICAgIGlmIGxlbihoZXhfc3RyKSA+IDE2OgogICAg
ICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAg
ZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAg
ICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgY2h1bmtfbGVuID0gaW50KGhleF9zdHIsIDE2
KQogICAgICAgICAgICAgICAgICAgIGlmIGNodW5rX2xlbiA8IDAgb3IgY2h1bmtfbGVuID4gMHg3
RkZGRkZGRjoKICAgICAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAg
ICAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAg
ICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAg
ICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICBmbC5p
c19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAg
IGRlbCBmbC5idWZbOmNybGYgKyAyXQogICAgICAgICAgICAgICAgaWYgY2h1bmtfbGVuID09IDA6
CiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gVHJ1ZQogICAg
ICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UKICAgICAgICAgICAg
ICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAg
ICBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IGNodW5rX2xlbgogICAgICAgICAgICAgICAg
ICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICBmbC5j
aHVua19yZWFkaW5nX2NybGYgPSBGYWxzZQogICAgICAgICAgICBlbGlmIGZsLmNodW5rX3JlYWRp
bmdfY3JsZjoKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5idWYpIDwgMjoKICAgICAgICAgICAg
ICAgICAgICBicmVhawogICAgICAgICAgICAgICAgaWYgZmwuYnVmWzoyXSAhPSBiIlxyXG4iOgog
ICAgICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAg
ICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAg
ICAgICAgICBkZWwgZmwuYnVmWzoyXQogICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19j
cmxmID0gRmFsc2UKICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gVHJ1ZQog
ICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgdG9fY29uc3VtZSA9IG1pbihsZW4oZmwu
YnVmKSwgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcpCiAgICAgICAgICAgICAgICBkZWwgZmwu
YnVmWzp0b19jb25zdW1lXQogICAgICAgICAgICAgICAgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5p
bmcgLT0gdG9fY29uc3VtZQogICAgICAgICAgICAgICAgaWYgZmwuY2h1bmtfcGF5bG9hZF9yZW1h
aW5pbmcgPT0gMDoKICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2NybGYgPSBU
cnVlCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgaWYgZmxhZ3MgJiAweDA1OgogICAgICAgIGlm
IGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQ6CiAgICAgICAgICAgIF9lbWl0X3Jl
cXVlc3RfdG9fcGVuZGluZyhmbC53c3NlX2V2ZW50LCBmbC5oZWFkX2J5dGVzLCBmbC5maXJzdF9i
eXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAgICAgICAgIGZsLmF3YWl0
aW5nX3dzc2UgPSBGYWxzZQogICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICBlbGlmIHNl
cSBpcyBOb25lIGFuZCBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0hFQURFUiBhbmQgbm90IGZsLmJ1
ZiBhbmQgbm90IGZsLm9vbyBhbmQgbm90IGZsLmF3YWl0aW5nX3dzc2U6CiAgICAgICAgZmxvd3Mu
cG9wKGtleSwgTm9uZSkKCgpkZWYgc3dlZXBfaWRsZShmbG93cywgbm93LCBvdXQ9Tm9uZSwgcGVu
ZGluZ190Ymw9Tm9uZSwgcmVzcF9mbG93cz1Ob25lKToKICAgIHN0YWxlID0gW10KICAgIGZvciBr
LCBmbCBpbiBmbG93cy5pdGVtcygpOgogICAgICAgIGlmIG5vdyAtIGZsLnRvdWNoZWQgPiBGTE9X
X1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKGspCiAgICBmb3IgayBpbiBzdGFsZToKICAg
ICAgICBmbCA9IGZsb3dzLmdldChrKQogICAgICAgIGlmIGZsIGlzIG5vdCBOb25lIGFuZCBmbC5h
d2FpdGluZ193c3NlIGFuZCBmbC53c3NlX2V2ZW50IGlzIG5vdCBOb25lOgogICAgICAgICAgICBp
ZiBvdXQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBvdXQuYXBwZW5kKGZsLndzc2VfZXZl
bnQpCiAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQogICAgICAgIGZsb3dzLnBv
cChrLCBOb25lKQogICAgaWYgcmVzcF9mbG93cyBpcyBub3QgTm9uZToKICAgICAgICByc3RhbGUg
PSBbayBmb3IgaywgcmZsIGluIHJlc3BfZmxvd3MuaXRlbXMoKSBpZiBub3cgLSByZmwudG91Y2hl
ZCA+IEZMT1dfVFRMXQogICAgICAgIGZvciBrIGluIHJzdGFsZToKICAgICAgICAgICAgcmVzcF9m
bG93cy5wb3AoaywgTm9uZSkKCgpkZWYgZHJhaW5faW5jb21wbGV0ZV93c3NlKGZsb3dzLCBvdXQs
IHBlbmRpbmdfdGJsLCBub3c9Tm9uZSk6CiAgICAiIiJGYWxsIGJhY2sgdG8gZW1pdHRpbmcgdGhl
IHJlcXVlc3QgZXZlbnQgaWYgV1NTRSBpbnNwZWN0aW9uIHdhcyBpbmNvbXBsZXRlLiIiIgogICAg
aWYgbm93IGlzIE5vbmU6CiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgIGZvciBrZXkgaW4g
bGlzdChmbG93cy5rZXlzKCkpOgogICAgICAgIGZsID0gZmxvd3MuZ2V0KGtleSkKICAgICAgICBp
ZiBmbCBpcyBOb25lOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIGZsLmF3YWl0aW5n
X3dzc2UgYW5kIGZsLndzc2VfZXZlbnQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIG91dC5hcHBl
bmQoZmwud3NzZV9ldmVudCkKICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAg
ICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKCgpkZWYgcHJvY2Vzc19wYWNrZXQocGt0LCBwb3J0
cywgbm9kZV9ob3N0LCBmbG93cywgcmVzcF9mbG93cywgcGVuZGluZ190YmwsIG91dCwgbm93PU5v
bmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgIG4gPSBsZW4ocGt0KQogICAgaWYgbiA8IDM0Ogog
ICAgICAgIHJldHVybiBGYWxzZQogICAgaWYgbm93IGlzIE5vbmU6CiAgICAgICAgbm93ID0gdGlt
ZS50aW1lKCkKICAgIG9mZiA9IDE0CiAgICBldHlwZSA9IHN0cnVjdC51bnBhY2soIiFIIiwgcGt0
WzEyOjE0XSlbMF0KICAgIGlmIGV0eXBlID09IEVUSF9QX1ZMQU46CiAgICAgICAgaWYgbiA8IDM4
OgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBldHlwZSA9IHN0cnVjdC51bnBhY2so
IiFIIiwgcGt0WzE2OjE4XSlbMF0KICAgICAgICBvZmYgPSAxOAogICAgZWxpZiBldHlwZSAhPSBF
VEhfUF9JUDoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBpcDAgPSBiMmkocGt0W29mZl0pCiAg
ICBpZiAoaXAwID4+IDQpICE9IDQgb3IgYjJpKHBrdFtvZmYgKyA5XSkgIT0gNjoKICAgICAgICBy
ZXR1cm4gRmFsc2UKICAgIGlobCA9IChpcDAgJiAweDBGKSAqIDQKICAgIGlmIGlobCA8IDIwIG9y
IG4gPCBvZmYgKyBpaGwgKyAyMDoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBmcmFnID0gc3Ry
dWN0LnVucGFjaygiIUgiLCBwa3Rbb2ZmICsgNjpvZmYgKyA4XSlbMF0KICAgIGlmIGZyYWcgJiAw
eDFGRkY6CiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgaXBfdG90YWxfbGVuID0gc3RydWN0LnVu
cGFjaygiIUgiLCBwa3Rbb2ZmICsgMjpvZmYgKyA0XSlbMF0KICAgIGlzX3RydW5jYXRlZCA9IEZh
bHNlCiAgICBpZiBpcF90b3RhbF9sZW4gPiAwOgogICAgICAgIGlmIGlwX3RvdGFsX2xlbiA8IGlo
bCArIDIwOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBpZiBuIC0gb2ZmIDwgaXBf
dG90YWxfbGVuOgogICAgICAgICAgICBpc190cnVuY2F0ZWQgPSBUcnVlCiAgICAgICAgZWxpZiBu
IC0gb2ZmID4gaXBfdG90YWxfbGVuOgogICAgICAgICAgICBuID0gb2ZmICsgaXBfdG90YWxfbGVu
CgogICAgc3JjX2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rbb2ZmICsgMTI6b2ZmICsgMTZdKQog
ICAgZHN0X2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAg
dGNwX29mZiA9IG9mZiArIGlobAogICAgc3BvcnQsIGRwb3J0ID0gc3RydWN0LnVucGFjaygiIUhI
IiwgcGt0W3RjcF9vZmY6dGNwX29mZiArIDRdKQogICAgc2VxID0gc3RydWN0LnVucGFjaygiIUki
LCBwa3RbdGNwX29mZiArIDQ6dGNwX29mZiArIDhdKVswXQogICAgZG9mZl9ieXRlID0gYjJpKHBr
dFt0Y3Bfb2ZmICsgMTJdKQogICAgZG9mZiA9IChkb2ZmX2J5dGUgPj4gNCkgKiA0CiAgICBpZiBk
b2ZmIDwgMjAgb3IgbiA8IHRjcF9vZmYgKyBkb2ZmOgogICAgICAgIHJldHVybiBGYWxzZQoKICAg
IGZsYWdzID0gYjJpKHBrdFt0Y3Bfb2ZmICsgMTNdKQogICAgcGF5X3N0YXJ0ID0gdGNwX29mZiAr
IGRvZmYKICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Om5dIGlmIG4gPiBwYXlfc3RhcnQgZWxz
ZSBiIiIKCiAgICAjIFJlc3BvbnNlIGRpcmVjdGlvbjogU2VydmVyIC0+IENsaWVudAogICAgaWYg
c3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0czoKICAgICAgICByayA9IChzcmNf
aXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgIGhhbmRsZV9yZXNwb25zZShyZXNwX2Zs
b3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBlbmRpbmdfdGJsLAogICAgICAgICAgICAgICAg
ICAgICAgICBzZXE9c2VxLCBmbGFncz1mbGFncywgaXNfdHJ1bmNhdGVkPWlzX3RydW5jYXRlZCkK
ICAgICAgICByZXR1cm4gVHJ1ZQoKICAgICMgUmVxdWVzdCBkaXJlY3Rpb246IENsaWVudCAtPiBT
ZXJ2ZXIKICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAga2V5ID0gKHNyY19pcCwgc3Bv
cnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgbWV0YSA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAs
IHNwb3J0KQogICAgICAgIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIE5vbmUsIHBheWxvYWQs
IG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAgICAgICAgICAgICAgICAgICBwZW5k
aW5nX3RibCwgbm93LCB3c3NlX2JvZHlfYnl0ZXMsCiAgICAgICAgICAgICAgICAgICAgICAgc2Vx
PXNlcSwgZmxhZ3M9ZmxhZ3MsIGlzX3RydW5jYXRlZD1pc190cnVuY2F0ZWQsCiAgICAgICAgICAg
ICAgICAgICAgICAgcmVzcF9mbG93cz1yZXNwX2Zsb3dzKQoKICAgICAgICByZXR1cm4gVHJ1ZQoK
ICAgIHJldHVybiBGYWxzZQoKCmRlZiBfZmx1c2hfb2xkZXN0X3BlbmRpbmcocGVuZGluZ190Ymws
IG91dCk6CiAgICAiIiJPdmVyZmxvdyBndWFyZDogZW1pdCBhbGwgZXZlbnRzIGZvciB0aGUgb2xk
ZXN0IHBlbmRpbmcga2V5IGFuZCBsb2NrIGl0IG91dC4iIiIKICAgIG9sZGVzdF9rZXksIG9sZGVz
dF90cyA9IE5vbmUsIE5vbmUKICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJsLml0ZW1zKCk6
CiAgICAgICAgaWYgbm90IGxzdDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICB0cyA9IGxz
dFswXVsxXQogICAgICAgIGlmIG9sZGVzdF90cyBpcyBOb25lIG9yIHRzIDwgb2xkZXN0X3RzOgog
ICAgICAgICAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSByaywgdHMKICAgIGlmIG9sZGVzdF9r
ZXkgaXMgbm90IE5vbmU6CiAgICAgICAgd2hpbGUgcGVuZGluZ190YmwuZ2V0KG9sZGVzdF9rZXkp
OgogICAgICAgICAgICBwZW5kaW5nX3BvcChvbGRlc3Rfa2V5LCBvdXQsIHBlbmRpbmdfdGJsKQog
ICAgICAgIGNvcnJfZGlzYWJsZWRfaW5zZXJ0KG9sZGVzdF9rZXkpCiAgICAgICAgcGVuZGluZ190
YmwucG9wKG9sZGVzdF9rZXksIE5vbmUpCgoKZGVmIHN3ZWVwX3BlbmRpbmcocGVuZGluZ190Ymws
IG5vdywgb3V0KToKICAgICIiIlRUTCBmbHVzaDogZW1pdCByZXF1ZXN0cyB3aG9zZSByZXNwb25z
ZXMgbmV2ZXIgc2hvd2VkIHVwLiIiIgogICAgZm9yIHJrIGluIGxpc3QocGVuZGluZ190Ymwua2V5
cygpKToKICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICAgICAgaWYgbm90IGxz
dDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpID0gMAogICAgICAgIHdoaWxlIGkgPCBs
ZW4obHN0KToKICAgICAgICAgICAgaXRlbSA9IGxzdFtpXQogICAgICAgICAgICBpc190b21iID0g
aXRlbVsyXSBpZiBsZW4oaXRlbSkgPiAyIGVsc2UgRmFsc2UKICAgICAgICAgICAgdG9tYl90cyA9
IGl0ZW1bM10gaWYgbGVuKGl0ZW0pID4gMyBlbHNlIDAuMAogICAgICAgICAgICBpZiBpc190b21i
OgogICAgICAgICAgICAgICAgaWYgbm93IC0gdG9tYl90cyA+IDEwLjA6CiAgICAgICAgICAgICAg
ICAgICAgIyBUb21ic3RvbmUgZXhwaXJlZCB1bi1jb25zdW1lZDogb3JkZXJpbmcgaXMgbm93IGFt
YmlndW91cy4KICAgICAgICAgICAgICAgICAgICAjIEZsdXNoIGFsbCByZW1haW5pbmcgZW50cmll
cyBpbW1lZGlhdGVseSBhbmQgcGVyc2lzdGVudGx5CiAgICAgICAgICAgICAgICAgICAgIyBkaXNh
YmxlIHJlc3BvbnNlIGNvcnJlbGF0aW9uIGZvciB0aGlzIGNvbm5lY3Rpb24gdW50aWwgU1lOLgog
ICAgICAgICAgICAgICAgICAgIGxzdC5wb3AoaSkKICAgICAgICAgICAgICAgICAgICB3aGlsZSBp
IDwgbGVuKGxzdCk6CiAgICAgICAgICAgICAgICAgICAgICAgIHRhaWwgPSBsc3RbaV0KICAgICAg
ICAgICAgICAgICAgICAgICAgdGFpbF90b21iID0gdGFpbFsyXSBpZiBsZW4odGFpbCkgPiAyIGVs
c2UgRmFsc2UKICAgICAgICAgICAgICAgICAgICAgICAgaWYgbm90IHRhaWxfdG9tYjoKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQodGFpbFswXSkKICAgICAgICAgICAgICAg
ICAgICAgICAgbHN0LnBvcChpKQogICAgICAgICAgICAgICAgICAgIGNvcnJfZGlzYWJsZWRfaW5z
ZXJ0KHJrKQogICAgICAgICAgICAgICAgICAgICMgTGVhdmUgaSB1bmNoYW5nZWQ7IHRoZSB3aGls
ZSBjb25kaXRpb24gd2lsbCBleGl0IG5hdHVyYWxseQogICAgICAgICAgICAgICAgZWxzZToKICAg
ICAgICAgICAgICAgICAgICBpICs9IDEKICAgICAgICAgICAgZWxpZiBub3cgLSBpdGVtWzFdID4g
UEVORElOR19UVEw6CiAgICAgICAgICAgICAgICBvdXQuYXBwZW5kKGl0ZW1bMF0pCiAgICAgICAg
ICAgICAgICBpZiBsZW4oaXRlbSkgPiAzOgogICAgICAgICAgICAgICAgICAgIGl0ZW1bMl0gPSBU
cnVlCiAgICAgICAgICAgICAgICAgICAgaXRlbVszXSA9IG5vdwogICAgICAgICAgICAgICAgZWxz
ZToKICAgICAgICAgICAgICAgICAgICBpdGVtLmV4dGVuZChbVHJ1ZSwgbm93LCAwXSkKICAgICAg
ICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgaSArPSAx
CiAgICAgICAgaWYgbm90IGxzdDoKICAgICAgICAgICAgcGVuZGluZ190YmwucG9wKHJrLCBOb25l
KQoKCgpkZWYgZHJhaW5fcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToKICAgICIiIkVtaXQgZXZl
cnkgY2FwdHVyZWQgcmVxdWVzdCBiZWZvcmUgY2FwdHVyZSBzaHV0ZG93bi4KCiAgICBSZXNwb25z
ZXMgYXJlIG9wdGlvbmFsIGVucmljaG1lbnQuIEEgc3RvcC9yZXN0YXJ0IG11c3Qgbm90IGRpc2Nh
cmQgYQogICAgcmVxdWVzdCBtZXJlbHkgYmVjYXVzZSBpdHMgcmVzcG9uc2Ugd2FzIGZpbHRlcmVk
LCBzcGxpdCwgb3Igc3RpbGwgaW4KICAgIGZsaWdodCB3aGVuIHRoZSBwcm9jZXNzIHJlY2VpdmVk
IFNJR1RFUk0uCiAgICAiIiIKICAgIGZvciByayBpbiBsaXN0KHBlbmRpbmdfdGJsLmtleXMoKSk6
CiAgICAgICAgbHN0ID0gcGVuZGluZ190YmwucG9wKHJrLCBOb25lKQogICAgICAgIGlmIGxzdDoK
ICAgICAgICAgICAgZm9yIGl0ZW0gaW4gbHN0OgogICAgICAgICAgICAgICAgaXNfdG9tYiA9IGl0
ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZhbHNlCiAgICAgICAgICAgICAgICBpZiBub3Qg
aXNfdG9tYjoKICAgICAgICAgICAgICAgICAgICBvdXQuYXBwZW5kKGl0ZW1bMF0pCiAgICBjb3Jy
X2Rpc2FibGVkX2NsZWFyKCkKCgoKCmRlZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVw
KToKICAgIHJldHVybiBub3cgLSBsYXN0X3N3ZWVwID49IFNXRUVQX0lOVEVSVkFMCgoKZGVmIGVu
Zm9yY2VfbGltaXQoZmxvd3MsIG5vdyk6CiAgICAiIiJDYXAgZmxvdy10YWJsZSBzaXplIChweTIu
Njogbm8gT3JkZXJlZERpY3Qg4oCUIHN3ZWVwIHN0YWxlLCB0aGVuIEZJRk8KICAgIGJ5IGluc2Vy
dGlvbiBvcmRlciwgd2hpY2ggcGxhaW4gZGljdHMgcHJlc2VydmUgaW4gQ1B5dGhvbikuIiIiCiAg
ICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICB3aGlsZSBsZW4oZmxvd3MpID4gTUFYX0ZMT1dT
OgogICAgICAgIGZsb3dzLnBvcGl0ZW0oKSAgICAgICAgICAjIG9sZGVzdC1pbnNlcnRlZCBrZXkg
b24gQ1B5dGhvbiAyLjYvMi43CgoKZGVmIF9jb250cm9sX2NvbmZpZygpOgogICAgIiIiUmVhZCBv
cHRpb25hbCBjb250cm9sIHNldHRpbmdzIHdpdGhvdXQgZXhwb3NpbmcgdGhlIGJlYXJlciB0b2tl
bi4iIiIKICAgIGVuZHBvaW50ID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfRU5EUE9JTlQi
KSBvciBvcy5lbnZpcm9uLmdldCgiTlRfRU5EUE9JTlQiKQogICAgdG9rZW5fZmlsZSA9IG9zLmVu
dmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOX0ZJTEUiLCAiIikKICAgIHRva2VuID0gb3MuZW52
aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9LRU4iLCAiIikKICAgIGlmIHRva2VuX2ZpbGU6CiAgICAg
ICAgdHJ5OgogICAgICAgICAgICBmID0gb3Blbih0b2tlbl9maWxlLCAiciIpCiAgICAgICAgICAg
IHRyeToKICAgICAgICAgICAgICAgIHRva2VuID0gZi5yZWFkKCkuc3RyaXAoKQogICAgICAgICAg
ICBmaW5hbGx5OgogICAgICAgICAgICAgICAgZi5jbG9zZSgpCiAgICAgICAgZXhjZXB0IElPRXJy
b3I6CiAgICAgICAgICAgIHRva2VuID0gIiIKICAgIG5vZGUgPSBvcy5lbnZpcm9uLmdldCgiTlRf
Tk9ERV9OQU1FIikgb3Igc29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQogICAgcnVu
X2RpciA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1JVTiIsICIvdmFyL2xpYi9uZXR3b3Jr
dHJhY2luZyIpCiAgICB0cnk6CiAgICAgICAgaW50ZXJ2YWwgPSBtYXgoNSwgbWluKGludChvcy5l
bnZpcm9uLmdldCgiTlRfQ09OVFJPTF9TRUMiLCAiMzAiKSksIDMwMCkpCiAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICBpbnRlcnZhbCA9IDMwCiAgICByZXR1cm4gZW5kcG9pbnQsIHRva2Vu
LCBub2RlLCBydW5fZGlyLCBpbnRlcnZhbAoKCmRlZiBfcnVuX2NvbnRyb2xfdGljayhwb3J0cywg
aWZhY2UsIHJ1bl9kaXIsIGNsaWVudCk6CiAgICByZXBseSA9IGNsaWVudC5wb2xsKCkKICAgIGlm
IG5vdCByZXBseToKICAgICAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBOb25lLCAicG9sbCBmYWls
ZWQiCiAgICBkZXNpcmVkID0gcmVwbHkuZ2V0KCJkZXNpcmVkIikgb3Ige30KICAgIHN0YXRlID0g
ZGljdChkZXNpcmVkKQogICAgZ2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0aW9uIiwg
MCkKICAgIGNvbnRyb2xfYWN0aW9uID0gTm9uZQogICAgc3RvcF9yZXF1ZXN0ZWQgPSBGYWxzZQog
ICAgaWYgZGVzaXJlZC5nZXQoInBvcnRzIik6CiAgICAgICAgbmV3X3BvcnRzID0gc2V0KGRlc2ly
ZWRbInBvcnRzIl0pCiAgICAgICAgaWYgbmV3X3BvcnRzICE9IHBvcnRzOgogICAgICAgICAgICBw
b3J0cyA9IG5ld19wb3J0cwogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0Igog
ICAgaWYgZGVzaXJlZC5nZXQoImlmYWNlIik6CiAgICAgICAgbmV3X2lmYWNlID0gZGVzaXJlZFsi
aWZhY2UiXQogICAgICAgIGlmIG5ld19pZmFjZSAhPSBpZmFjZToKICAgICAgICAgICAgaWZhY2Ug
PSBuZXdfaWZhY2UKICAgICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAicmVzdGFydCIKICAgIGZv
ciB0YXNrIGluIHJlcGx5LmdldCgidGFza3MiLCBbXSk6CiAgICAgICAgYWN0aW9uID0gdGFzay5n
ZXQoImFjdGlvbiIpCiAgICAgICAgaWYgYWN0aW9uID09ICJoZWFsdGgiOgogICAgICAgICAgICBt
ZXNzYWdlID0gImhlYWx0aHkiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgIGVs
aWYgYWN0aW9uIGluICgicmVzdGFydCIsICJyZWxvYWQiLCAic2V0X3BvcnRzIik6CiAgICAgICAg
ICAgIG1lc3NhZ2UgPSAiYWNjZXB0ZWQ7IGNhcHR1cmUgcmVzdGFydCByZXF1ZXN0ZWQiCiAgICAg
ICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0
YXJ0IgogICAgICAgICAgICBpZiBhY3Rpb24gPT0gInNldF9wb3J0cyI6CiAgICAgICAgICAgICAg
ICBhcmdzID0gdGFzay5nZXQoImFyZ3MiKSBvciB7fQogICAgICAgICAgICAgICAgaWYgYXJncy5n
ZXQoInBvcnRzIik6CiAgICAgICAgICAgICAgICAgICAgcG9ydHMgPSBzZXQoYXJnc1sicG9ydHMi
XSkKICAgICAgICAgICAgICAgICAgICBzdGF0ZS51cGRhdGUoeyJwb3J0cyI6IHNvcnRlZChwb3J0
cyksICJtb2RlIjogInB5dGhvbiIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAi
Z2VuZXJhdGlvbiI6IGdlbmVyYXRpb259KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJzdG9wIjoK
ICAgICAgICAgICAgbWVzc2FnZSA9ICJzdG9wIHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVz
ID0gImRvbmUiCiAgICAgICAgICAgIHN0b3BfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAgIGVsc2U6
CiAgICAgICAgICAgIG1lc3NhZ2UgPSAidW5zdXBwb3J0ZWQgYnkgZGlyZWN0IHNuaWZmZXIiCiAg
ICAgICAgICAgIHN0YXR1cyA9ICJmYWlsZWQiCiAgICAgICAgY2xpZW50LnJlcG9ydCh0YXNrLmdl
dCgiaWQiKSwgc3RhdHVzLCBtZXNzYWdlKQogICAgaWYgc3RvcF9yZXF1ZXN0ZWQ6CiAgICAgICAg
Y29udHJvbF9hY3Rpb24gPSAic3RvcCIKICAgIGFwcGxpZWQgPSAoInN0b3AgcmVxdWVzdGVkIiBp
ZiBjb250cm9sX2FjdGlvbiA9PSAic3RvcCIgZWxzZQogICAgICAgICAgICAgICAicmVzdGFydCBy
ZXF1aXJlZCIgaWYgY29udHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiIGVsc2UKICAgICAgICAgICAg
ICAgInBvbGwgb2siKQogICAgbnRfY29udHJvbC53cml0ZV9zdGF0ZShvcy5wYXRoLmpvaW4ocnVu
X2RpciwgInJlbW90ZS1kZXNpcmVkLmpzb24iKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
c3RhdGUsIGFwcGxpZWQpCiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sIGFwcGxpZWQp
CiAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBjb250cm9sX2FjdGlvbiwgYXBwbGllZAoKCmRlZiBf
cmVzdGFydF9hcmdzKHNjcmlwdCwgaWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzLCB3c3Nl
X2JvZHlfYnl0ZXM9MCk6CiAgICAiIiJCdWlsZCBhIGZyZXNoIGFyZ3YgZm9yIGFuIGluLXBsYWNl
IHJlLWV4ZWMgYWZ0ZXIgYSBjb250cm9sIHVwZGF0ZS4iIiIKICAgICMgUHJlc2VydmUgdW5idWZm
ZXJlZCBKU09OTCBkZWxpdmVyeTsgdGhlIGluc3RhbGxlciBzdGFydHMgUHl0aG9uIHdpdGggLXUu
CiAgICBhcmdzID0gW3N5cy5leGVjdXRhYmxlLCAiLXUiLCBvcy5wYXRoLmFic3BhdGgoc2NyaXB0
KV0KICAgIGlmIGlmYWNlOgogICAgICAgIGFyZ3MuZXh0ZW5kKFsiLWkiLCBpZmFjZV0pCiAgICBh
cmdzLmV4dGVuZChbIi1wIiwgIiwiLmpvaW4oW3N0cihwKSBmb3IgcCBpbiBzb3J0ZWQocG9ydHMp
XSldKQogICAgYXJncy5leHRlbmQoWyItaiIsICIxIl0pCiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6
CiAgICAgICAgYXJncy5leHRlbmQoWyItLXdzc2UtYm9keS1ieXRlcyIsIHN0cih3c3NlX2JvZHlf
Ynl0ZXMpXSkKICAgIGlmIHZlcmJvc2U6CiAgICAgICAgYXJncy5hcHBlbmQoIi12IikKICAgIHJl
dHVybiBhcmdzCgoKZGVmIG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwgd29ya2Vy
cywgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAgICBub2RlX2hv
c3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250cm9sX2NsaWVu
dCA9IE5vbmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250cm9sX3J1biwg
Y29udHJvbF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9jb250cm9sIGlz
IG5vdCBOb25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5OgogICAgICAgICAg
ICBjb250cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRwb2ludCwgdG9r
ZW4sIGNvbnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIoY29udHJv
bF9ydW4pOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4pCiAgICAgICAg
ICAgIGxvZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlv
biBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRpc2FibGVkICgl
cykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAgICAgICMgcHJv
dG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJTkdSRVNTIChy
ZXEpIGFuZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4IGtlcm5lbCBw
YWNrZXQgc29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfUEFDS0VU
LCBzb2NrZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29ja2V0Lmh0b25z
KEVUSF9QX0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAgcmFpc2UgU3lz
dGVtRXhpdCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0iKQogICAgZXhj
ZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBv
cGVuIEFGX1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAgICAgICAgICAg
ICAgICAiQ0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQoMS4wKQogICAg
aWYgbm90IGFwcGx5X3BlcmZfb3B0cyhzLCBwb3J0cyk6CiAgICAgICAgcy5jbG9zZSgpCiAgICAg
ICAgcmFpc2UgU3lzdGVtRXhpdCgia2VybmVsIEJQRiBzYWZldHkgZmlsdGVyIHVuYXZhaWxhYmxl
OyByZWZ1c2luZyB1bmZpbHRlcmVkIGNhcHR1cmUiKQogICAgdHJ5OgogICAgICAgIHMuYmluZCgo
aWZhY2Ugb3IgIiIsIEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAg
ICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IGJpbmQgQUZf
UEFDS0VUIHRvICVzICglcykiICUKICAgICAgICAgICAgICAgICAgICAgICAgIChpZmFjZSBvciAi
PGFsbD4iLCBlKSkKICAgIGlmIG5vdCBkcm9wX2NhcHR1cmVfY2FwYWJpbGl0aWVzKCk6CiAgICAg
ICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90IGRyb3AgQ0FQX05F
VF9SQVcgYWZ0ZXIgc29ja2V0IHNldHVwOyByZWZ1c2luZyB1bnNhZmUgY2FwdHVyZSIpCgogICAg
IyBwcmVjb21waWxlZCBzdHJ1Y3QgcmVhZGVycyDigJQgdW5wYWNrX2Zyb20gcmVhZHMgc3RyYWln
aHQgb3V0IG9mIHRoZQogICAgIyBwYWNrZXQgYnVmZmVyIChubyBzbGljZSBjb3BpZXMpIGFuZCB5
aWVsZHMgaW50cyB1bmRlciBweTIgQU5EIHB5MwogICAgdTE2ID0gc3RydWN0LlN0cnVjdCgiIUgi
KS51bnBhY2tfZnJvbQogICAgdWggPSBzdHJ1Y3QuU3RydWN0KCIhSEgiKS51bnBhY2tfZnJvbSAg
ICMgc3BvcnQsZHBvcnQgaW4gb25lIHJlYWQKICAgIHViID0gc3RydWN0LlN0cnVjdCgiIUJCIiku
dW5wYWNrX2Zyb20KICAgIG50b2EgPSBzb2NrZXQuaW5ldF9udG9hCgogICAgZmxvd3MgPSB7fQog
ICAgcmVzcF9mbG93cyA9IHt9CiAgICBydW5uaW5nID0gW1RydWVdCiAgICBzdGF0c19pbnRlcnZh
bCA9IHN0YXRzX2ludGVydmFsX3NlY29uZHMoKQogICAgc3RhdHNfc3RhdGUgPSB7InBhY2tldHNf
dG90YWwiOiAwLCAicGFja2V0X2J5dGVzX3RvdGFsIjogMCwKICAgICAgICAgICAgICAgICAgICJl
dmVudHNfZW1pdHRlZF90b3RhbCI6IDAsICJrZXJuZWxfZHJvcHNfdG90YWwiOiAwLAogICAgICAg
ICAgICAgICAgICAgImxhc3RfcGFja2V0cyI6IDAsICJsYXN0X3BhY2tldF9ieXRlcyI6IDAsCiAg
ICAgICAgICAgICAgICAgICAibGFzdF9ldmVudHMiOiAwLCAibGFzdF9hdCI6IHRpbWUudGltZSgp
fQoKICAgIGRlZiB3cml0ZV9ldmVudHMoaXRlbXMpOgogICAgICAgIGlmIG5vdCBpdGVtczoKICAg
ICAgICAgICAgcmV0dXJuCiAgICAgICAgdyA9IHN5cy5zdGRvdXQud3JpdGUKICAgICAgICBmb3Ig
aXRlbSBpbiBpdGVtczoKICAgICAgICAgICAgdyhqc29uLmR1bXBzKGl0ZW0pICsgIlxuIikKICAg
ICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICBzdGF0c19zdGF0ZVsiZXZlbnRzX2VtaXR0
ZWRfdG90YWwiXSArPSBsZW4oaXRlbXMpCgogICAgZGVmIGVtaXRfY2FwdHVyZV9zdGF0cyhmb3Jj
ZT1GYWxzZSk6CiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICBlbGFwc2VkID0gbm93
IC0gc3RhdHNfc3RhdGVbImxhc3RfYXQiXQogICAgICAgIGlmIG5vdCBmb3JjZSBhbmQgZWxhcHNl
ZCA8IHN0YXRzX2ludGVydmFsOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBkcm9wcGVkX2Rl
bHRhID0gMAogICAgICAgIHRyeToKICAgICAgICAgICAgcmF3X3N0YXRzID0gcy5nZXRzb2Nrb3B0
KFNPTF9QQUNLRVQsIFBBQ0tFVF9TVEFUSVNUSUNTLCA4KQogICAgICAgICAgICBfLCBkcm9wcGVk
X2RlbHRhID0gc3RydWN0LnVucGFjaygiSUkiLCByYXdfc3RhdHNbOjhdKQogICAgICAgIGV4Y2Vw
dCAoc29ja2V0LmVycm9yLCBzdHJ1Y3QuZXJyb3IpOgogICAgICAgICAgICBkcm9wcGVkX2RlbHRh
ID0gMAogICAgICAgIHN0YXRzX3N0YXRlWyJrZXJuZWxfZHJvcHNfdG90YWwiXSArPSBkcm9wcGVk
X2RlbHRhCiAgICAgICAgcGFja2V0c19kZWx0YSA9IChzdGF0c19zdGF0ZVsicGFja2V0c190b3Rh
bCJdIC0KICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X3BhY2tldHMi
XSkKICAgICAgICBieXRlc19kZWx0YSA9IChzdGF0c19zdGF0ZVsicGFja2V0X2J5dGVzX3RvdGFs
Il0gLQogICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X3BhY2tldF9ieXRl
cyJdKQogICAgICAgIGV2ZW50c19kZWx0YSA9IChzdGF0c19zdGF0ZVsiZXZlbnRzX2VtaXR0ZWRf
dG90YWwiXSAtCiAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X2V2ZW50
cyJdKQogICAgICAgIHdhaXRpbmdfd3NzZSA9IDAKICAgICAgICBmb3IgZmxvdyBpbiBmbG93cy52
YWx1ZXMoKToKICAgICAgICAgICAgaWYgZmxvdy5ldmVudCBpcyBub3QgTm9uZSBhbmQgZmxvdy5i
b2R5X2dvYWw6CiAgICAgICAgICAgICAgICB3YWl0aW5nX3dzc2UgKz0gMQogICAgICAgIHBlbmRp
bmdfY291bnQgPSBzdW0obGVuKGl0ZW1zKSBmb3IgaXRlbXMgaW4gcGVuZGluZy52YWx1ZXMoKSkK
ICAgICAgICBkcm9wX3BjdCA9IDEwMC4wICogZHJvcHBlZF9kZWx0YSAvIG1heCgxLCBwYWNrZXRz
X2RlbHRhKQogICAgICAgIGNhcHR1cmUgPSB7CiAgICAgICAgICAgICJwYWNrZXRzX3RvdGFsIjog
c3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXSwKICAgICAgICAgICAgInBhY2tldHNfZGVsdGEi
OiBwYWNrZXRzX2RlbHRhLAogICAgICAgICAgICAicGFja2V0X2J5dGVzX3RvdGFsIjogc3RhdHNf
c3RhdGVbInBhY2tldF9ieXRlc190b3RhbCJdLAogICAgICAgICAgICAicGFja2V0X2J5dGVzX2Rl
bHRhIjogYnl0ZXNfZGVsdGEsCiAgICAgICAgICAgICJrZXJuZWxfZHJvcHNfdG90YWwiOiBzdGF0
c19zdGF0ZVsia2VybmVsX2Ryb3BzX3RvdGFsIl0sCiAgICAgICAgICAgICJrZXJuZWxfZHJvcHNf
ZGVsdGEiOiBkcm9wcGVkX2RlbHRhLAogICAgICAgICAgICAia2VybmVsX2Ryb3BfcGVyY2VudCI6
IHJvdW5kKGRyb3BfcGN0LCA0KSwKICAgICAgICAgICAgImludmFsaWRfZnJhbWVzX3RvdGFsIjog
MCwKICAgICAgICAgICAgImV2ZW50c19lbWl0dGVkX3RvdGFsIjogc3RhdHNfc3RhdGVbImV2ZW50
c19lbWl0dGVkX3RvdGFsIl0sCiAgICAgICAgICAgICJldmVudHNfZW1pdHRlZF9kZWx0YSI6IGV2
ZW50c19kZWx0YSwKICAgICAgICAgICAgImZsb3dzX2FjdGl2ZSI6IGxlbihmbG93cyksCiAgICAg
ICAgICAgICJwZW5kaW5nX3JlcXVlc3RzIjogcGVuZGluZ19jb3VudCwKICAgICAgICAgICAgIndz
c2VfYm9keV9mbG93c19hY3RpdmUiOiB3YWl0aW5nX3dzc2V9CiAgICAgICAgc3lzLnN0ZG91dC53
cml0ZShqc29uLmR1bXBzKHsiX250X2ludGVybmFsIjogImNhcHR1cmVfc3RhdHNfdjEiLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNhcHR1cmUiOiBjYXB0dXJlfSwKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKSAr
ICJcbiIpCiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAgc3RhdHNfc3RhdGVbImxh
c3RfcGFja2V0cyJdID0gc3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXQogICAgICAgIHN0YXRz
X3N0YXRlWyJsYXN0X3BhY2tldF9ieXRlcyJdID0gc3RhdHNfc3RhdGVbInBhY2tldF9ieXRlc190
b3RhbCJdCiAgICAgICAgc3RhdHNfc3RhdGVbImxhc3RfZXZlbnRzIl0gPSBzdGF0c19zdGF0ZVsi
ZXZlbnRzX2VtaXR0ZWRfdG90YWwiXQogICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X2F0Il0gPSBu
b3cKCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFs
c2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2ln
bmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGltZSgpCiAg
ICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcgb24gJXMgcG9y
dHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRlZChwb3J0cyks
IG9zLmdldHBpZCgpKSkKICAgIGlmIHdzc2VfYm9keV9ieXRlczoKICAgICAgICBsb2coIldTU0Ug
VXNlcm5hbWVUb2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5kZWQgdG8gJWQgYnl0ZXMvcmVx
dWVzdCkiICUKICAgICAgICAgICAgd3NzZV9ib2R5X2J5dGVzKQoKICAgICMgMXMgcmVjdiB0aW1l
b3V0OiAoYSkgbGV0cyB0aGUgcGVuZGluZy9mbG93IHN3ZWVwcyBhY3R1YWxseSBmaXJlIOKAlAog
ICAgIyB3aXRob3V0IGl0IGBleGNlcHQgc29ja2V0LnRpbWVvdXRgIG5ldmVyIHJ1bnM7IChiKSBl
bXBpcmljYWxseSBSRVFVSVJFRAogICAgIyB3aXRoIHRoZSBCUEYgZmlsdGVyIGF0dGFjaGVkOiBh
IGZ1bGx5LWJsb2NraW5nIHJlY3Ygb24gdGhpcyBrZXJuZWwKICAgICMgc3RhcnZlcyBhZnRlciB0
aGUgZmlyc3QgcGFja2V0LCB3aGlsZSB0aGUgdGltZW91dCdkIHJlY3YgZGVsaXZlcnMKICAgICMg
Y29udGludW91c2x5ICh2ZXJpZmllZCBieSBBL0I6IHJ4PTEgdnMgcng9MjkgaWRlbnRpY2FsIG90
aGVyd2lzZSkuCiAgICBzLnNldHRpbWVvdXQoMS4wKQoKICAgIGRiZyA9IG9zLmVudmlyb24uZ2V0
KCJOVF9TTklGRl9ERUJVRyIpID09ICIxIgogICAgZGJnX3J4ID0gMAogICAgZGJnX2xhc3QgPSB0
aW1lLnRpbWUoKQogICAgd2hpbGUgcnVubmluZ1swXToKICAgICAgICBlbWl0X2NhcHR1cmVfc3Rh
dHMoKQogICAgICAgICMgUG9sbCBpbmRlcGVuZGVudGx5IG9mIHNvY2tldCBpZGxlIHRpbWUuIEEg
YnVzeSBtb25pdG9yZWQgaW50ZXJmYWNlCiAgICAgICAgIyBtYXkgbmV2ZXIgcmFpc2Ugc29ja2V0
LnRpbWVvdXQsIGJ1dCBjb250cm9sIGNoYW5nZXMgbXVzdCBzdGlsbCBhcHBseS4KICAgICAgICBp
ZiBjb250cm9sX2NsaWVudCBpcyBub3QgTm9uZSBhbmQgdGltZS50aW1lKCkgPj0gY29udHJvbF9u
ZXh0OgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBwb3J0cywgaWZhY2UsIGNvbnRy
b2xfYWN0aW9uLCBjb250cm9sX3N0YXR1cyA9IF9ydW5fY29udHJvbF90aWNrKAogICAgICAgICAg
ICAgICAgICAgIHBvcnRzLCBpZmFjZSwgY29udHJvbF9ydW4sIGNvbnRyb2xfY2xpZW50KQogICAg
ICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29udHJvbDogJXMiICUgY29udHJvbF9zdGF0dXMpCiAg
ICAgICAgICAgICAgICBpZiBjb250cm9sX2FjdGlvbiA9PSAicmVzdGFydCI6CiAgICAgICAgICAg
ICAgICAgICAgYXJncyA9IF9yZXN0YXJ0X2FyZ3Moc3lzLmFyZ3ZbMF0sIGlmYWNlLCBwb3J0cywK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJib3NlLCB3b3JrZXJz
LCB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29udHJv
bDogcmUtZXhlY3V0aW5nIGNhcHR1cmUgd2l0aCB1cGRhdGVkIGNvbmZpZ3VyYXRpb24iKQogICAg
ICAgICAgICAgICAgICAgIHMuY2xvc2UoKQogICAgICAgICAgICAgICAgICAgIG9zLmV4ZWN2KHN5
cy5leGVjdXRhYmxlLCBhcmdzKQogICAgICAgICAgICAgICAgZWxpZiBjb250cm9sX2FjdGlvbiA9
PSAic3RvcCI6CiAgICAgICAgICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29udHJvbDogc3RvcCBy
ZXF1ZXN0ZWQ7IGV4aXRpbmciKQogICAgICAgICAgICAgICAgICAgIHJ1bm5pbmdbMF0gPSBGYWxz
ZQogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRp
b24gYXMgZToKICAgICAgICAgICAgICAgIGxvZygiV0FSTjogcmVtb3RlIGNvbnRyb2wgdGljayBm
YWlsZWQgKCVzKSIgJSBudF9jb250cm9sLnNhZmVfbWVzc2FnZShlKSkKICAgICAgICAgICAgY29u
dHJvbF9uZXh0ID0gdGltZS50aW1lKCkgKyBjb250cm9sX2ludGVydmFsCiAgICAgICAgdHJ5Ogog
ICAgICAgICAgICBwa3QgPSBzLnJlY3YoNjU1MzUpCiAgICAgICAgICAgIGRiZ19yeCArPSAxCiAg
ICAgICAgICAgIHN0YXRzX3N0YXRlWyJwYWNrZXRzX3RvdGFsIl0gKz0gMQogICAgICAgICAgICBz
dGF0c19zdGF0ZVsicGFja2V0X2J5dGVzX3RvdGFsIl0gKz0gbGVuKHBrdCkKICAgICAgICAgICAg
aWYgZGJnIGFuZCB0aW1lLnRpbWUoKSAtIGRiZ19sYXN0ID4gNToKICAgICAgICAgICAgICAgIGxv
ZygiREVCVUcgcng9JWQiICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJnX2xhc3QgPSB0aW1l
LnRpbWUoKQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICAgICAgaWYgZGJn
OgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAg
ICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgbm93ID0gdGlt
ZS50aW1lKCkKICAgICAgICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6
CiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgICAgICBzd2VlcF9pZGxlKGZs
b3dzLCBub3csIG91dF9zLCBwZW5kaW5nLCByZXNwX2Zsb3dzKQogICAgICAgICAgICAgICAgc3dl
ZXBfcGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICAgICAgd3JpdGVfZXZl
bnRzKG91dF9zKQogICAgICAgICAgICAgICAgbGFzdF9zd2VlcCA9IG5vdwogICAgICAgICAgICBj
b250aW51ZQogICAgICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAgICAgICAgICAgaWYg
ZS5lcnJubyA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAg
ICAgIHJhaXNlCgogICAgICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAgb3V0ID0gW10KICAg
ICAgICBwcm9jZXNzX3BhY2tldChwa3QsIHBvcnRzLCBub2RlX2hvc3QsIGZsb3dzLCByZXNwX2Zs
b3dzLCBwZW5kaW5nLAogICAgICAgICAgICAgICAgICAgICAgIG91dCwgbm93LCB3c3NlX2JvZHlf
Ynl0ZXMpCiAgICAgICAgaWYgb3V0OgogICAgICAgICAgICB3cml0ZV9ldmVudHMob3V0KQoKICAg
ICAgICBpZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAgICAgICAgICAgb3V0
X3MgPSBbXQogICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3csIG91dF9zLCBwZW5kaW5n
LCByZXNwX2Zsb3dzKQogICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0
X3MpCiAgICAgICAgICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgICAgICAgICAgbGFzdF9zd2Vl
cCA9IG5vdwoKICAgIG91dF9zID0gW10KICAgIGRyYWluX2luY29tcGxldGVfd3NzZShmbG93cywg
b3V0X3MsIHBlbmRpbmcsIHRpbWUudGltZSgpKQogICAgZHJhaW5fcGVuZGluZyhwZW5kaW5nLCBv
dXRfcykKICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgIGVtaXRfY2FwdHVyZV9zdGF0cyhmb3Jj
ZT1UcnVlKQogICAgbG9nKCJzdG9wcGVkICglZCBwZW5kaW5nIHJlcXVlc3RzIGZsdXNoZWQpIiAl
IGxlbihvdXRfcykpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQo=
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
b2wgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhID09ICItLXNoaXAtcmF0ZS1rYnBzIjoKICAgICAg
ICAgICAgaSArPSAxOyBvcy5lbnZpcm9uWyJOVF9TSElQX1JBVEVfS0JQUyJdID0gYXJndltpXQog
ICAgICAgIGVsaWYgYSA9PSAiLS1zdGF0cy1pbnRlcnZhbC1zZWMiOgogICAgICAgICAgICBpICs9
IDE7IG9zLmVudmlyb25bIk5UX1NUQVRTX0lOVEVSVkFMX1NFQyJdID0gYXJndltpXQogICAgICAg
IGVsaWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsg
cmFpc2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3Rl
bUV4aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgaWYgbm90IGVu
ZHBvaW50OgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi0tZW5kcG9pbnQgcmVxdWlyZWQiKQoK
ICAgIG5vZGUgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICByYXRlX2ti
cHMgPSByZWFkX2JvdW5kZWRfaW50KCJOVF9TSElQX1JBVEVfS0JQUyIsIERFRkFVTFRfUkFURV9L
QlBTLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBNSU5fUkFURV9LQlBTLCBNQVhf
UkFURV9LQlBTKQogICAgbGltaXRlciA9IFJhdGVMaW1pdGVyKHJhdGVfa2JwcykKICAgIHN0YXRz
ID0gU2hpcFN0YXRzKCkKICAgIGNhcHR1cmVfbGF0ZXN0ID0ge30KICAgIHdzc2VfYm9keV9ieXRl
cyA9IHJlYWRfYm91bmRlZF9pbnQoIk5UX1dTU0VfQk9EWV9CWVRFUyIsIDAsIDAsIDY1NTM2KQog
ICAgcnVubmluZyA9IFtUcnVlXQoKICAgIGRlZiBzdG9wKHNpZ251bSwgZnJhbWUpOgogICAgICAg
IHJ1bm5pbmdbMF0gPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgc3Rv
cCkKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0lOVCwgc3RvcCkKCiAgICBkZWYgcmVxdWVz
dChwYXRoLCBib2R5LCB0aW1lb3V0KToKICAgICAgICBsaW1pdGVyLndhaXQobGVuKGJvZHkpKQog
ICAgICAgIHJlcSA9IHVybGxpYjIuUmVxdWVzdChlbmRwb2ludCArIHBhdGgsIGRhdGE9Ym9keSwK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVycz17IkNvbnRlbnQtVHlwZSI6ICJh
cHBsaWNhdGlvbi9qc29uIn0pCiAgICAgICAgdHJ5OgogICAgICAgICAgICByZXNwID0gdXJsbGli
Mi51cmxvcGVuKHJlcSwgdGltZW91dD10aW1lb3V0KQogICAgICAgICAgICBvayA9IChyZXNwLmdl
dGNvZGUoKSA9PSAyMDApCiAgICAgICAgICAgIHJlc3AucmVhZCgpCiAgICAgICAgICAgIHJlc3Au
Y2xvc2UoKQogICAgICAgICAgICByZXR1cm4gb2sKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFz
IGU6CiAgICAgICAgICAgIGxvZygic2hpcCBmYWlsZWQ6ICVzIiAlIGUpCiAgICAgICAgICAgIHJl
dHVybiBGYWxzZQoKICAgIGRlZiBmbHVzaChiYXRjaCk6CiAgICAgICAgaWYgbm90IGJhdGNoOgog
ICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgICAgIGJvZHkgPSBqc29uLmR1bXBzKHsibm9kZSI6
IG5vZGUsICJldmVudHMiOiBiYXRjaH0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgc2VwYXJh
dG9ycz0oIiwiLCAiOiIpKQogICAgICAgICMgcHkyIHVybGxpYjIgYWNjZXB0cyBzdHI7IHB5MyBz
aGltL3Rlc3QgbmVlZHMgYnl0ZXMg4oCUIGVuY29kZSB3aGVuCiAgICAgICAgIyB0aGUgcnVudGlt
ZSBleHBvc2VzIGl0IChweTIgc3RyIGhhcyBubyAuZW5jb2RlIG9uIGFsbCBidWlsZHMsIHNvCiAg
ICAgICAgIyBndWFyZCB3aXRoIGhhc2F0dHIpCiAgICAgICAgaWYgaGFzYXR0cihib2R5LCAiZW5j
b2RlIik6CiAgICAgICAgICAgIGJvZHkgPSBib2R5LmVuY29kZSgidXRmLTgiKQogICAgICAgIGlm
IGxlbihib2R5KSA+IE1BWF9QT1NUX0JZVEVTOgogICAgICAgICAgICBsb2coIldBUk46IHJlZnVz
aW5nIG92ZXJzaXplZCB1cGxvYWQgYm9keSAoJWQgYnl0ZXMpIiAlIGxlbihib2R5KSkKICAgICAg
ICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgb2sgPSByZXF1ZXN0KCIvYXBpL2luZ2VzdCIsIGJv
ZHksIDEwKQogICAgICAgIGlmIG9rOgogICAgICAgICAgICBzdGF0cy5iYXRjaF9zdWNjZXNzKGxl
bihiYXRjaCksIGxlbihib2R5KSkKICAgICAgICAgICAgbG9nKCJmbHVzaGVkICVkIGV2ZW50cyIg
JSBsZW4oYmF0Y2gpKQogICAgICAgIHJldHVybiBvawoKICAgIGRlZiBmbHVzaF9zdGF0cyhzYW1w
bGUpOgogICAgICAgIGJvZHkgPSBqc29uLmR1bXBzKHNhbXBsZSwgc2VwYXJhdG9ycz0oIiwiLCAi
OiIpKS5lbmNvZGUoInV0Zi04IikKICAgICAgICBpZiBsZW4oYm9keSkgPiBNQVhfU1RBVFNfQllU
RVM6CiAgICAgICAgICAgIHN0YXRzLmFkZCgic3RhdHNfc2FtcGxlc19kcm9wcGVkIikKICAgICAg
ICAgICAgbG9nKCJXQVJOOiBkcm9wcGVkIG92ZXJzaXplZCBhZ2VudCBzdGF0cyBzYW1wbGUiKQog
ICAgICAgICAgICByZXR1cm4KICAgICAgICBpZiBub3QgcmVxdWVzdCgiL2FwaS9hZ2VudC9zdGF0
cyIsIGJvZHksIDUpOgogICAgICAgICAgICBzdGF0cy5hZGQoInN0YXRzX3NhbXBsZXNfZHJvcHBl
ZCIpCgogICAgIyAtLS0tIGNvbmN1cnJlbnQgc2hpcHBpbmcgLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgIyBodWIgaW5nZXN0IGxhdGVuY3kgKH4zMDAtNTAw
bXMgcGVyIDQwMC1ldmVudCBQT1NUIG92ZXIgV0FOKSBtYWtlcwogICAgIyBzZXF1ZW50aWFsIHBv
c3RpbmcgYSB+MTAwMCBldi9zIGNlaWxpbmc7IE4gcG9zdGVyIHRocmVhZHMgcG9zdGluZwogICAg
IyBpbmRlcGVuZGVudCBiYXRjaGVzIG11bHRpcGx5IHRoYXQgYnkgTlRfU0hJUF9USFJFQURTCiAg
ICBjb25maWd1cmVfdGhyZWFkX3N0YWNrKCkKICAgIG50aHJlYWRzID0gcmVhZF9ib3VuZGVkX2lu
dCgiTlRfU0hJUF9USFJFQURTIiwgNCwgMSwgTUFYX1NISVBfVEhSRUFEUykKICAgIHEgPSBRdWV1
ZS5RdWV1ZShtYXhzaXplPW1pbihNQVhfUVVFVUVfQkFUQ0hFUywgbWF4KDIsIG50aHJlYWRzICog
MikpKQoKICAgIGRlZiBwb3N0ZXIoKToKICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBr
aW5kLCBpdGVtID0gcS5nZXQoKQogICAgICAgICAgICBpZiBraW5kID09ICJzdGF0cyI6CiAgICAg
ICAgICAgICAgICBzYW1wbGUgPSBzdGF0cy50YWtlX3N0YXRzKCkKICAgICAgICAgICAgICAgIGlm
IHNhbXBsZSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICBmbHVzaF9zdGF0cyhzYW1w
bGUpCiAgICAgICAgICAgICAgICBxLnRhc2tfZG9uZSgpCiAgICAgICAgICAgICAgICBjb250aW51
ZQogICAgICAgICAgICBzdGF0cy5xdWV1ZWQoLWxlbihpdGVtKSkKICAgICAgICAgICAgaWYgbm90
IGZsdXNoKGl0ZW0pOgogICAgICAgICAgICAgICAgc3RhdHMuYmF0Y2hfZmFpbHVyZShsZW4oaXRl
bSkpCiAgICAgICAgICAgICAgICBsb2coIldBUk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAl
ZCBldmVudHMgKGluLW1lbW9yeSBkcm9wLCAwIGRpc2sgSS9PKSIgJSBsZW4oaXRlbSkpCiAgICAg
ICAgICAgIHEudGFza19kb25lKCkKCiAgICBzdGFydGVkX3RocmVhZHMgPSAwCiAgICBmb3IgXyBp
biByYW5nZShudGhyZWFkcyk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICB0ID0gdGhyZWFkaW5n
LlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgICAgICB0LmRhZW1vbiA9IFRydWUKICAgICAg
ICAgICAgdC5zdGFydCgpCiAgICAgICAgICAgIHN0YXJ0ZWRfdGhyZWFkcyArPSAxCiAgICAgICAg
ZXhjZXB0IChSdW50aW1lRXJyb3IsIHRocmVhZGluZy5UaHJlYWRFcnJvcik6CiAgICAgICAgICAg
IGxvZygiV0FSTjogdGhyZWFkIGFsbG9jYXRpb24gc3RvcHBlZCBhdCAlZCBwb3N0ZXIocykiICUK
ICAgICAgICAgICAgICAgIHN0YXJ0ZWRfdGhyZWFkcykKICAgICAgICAgICAgYnJlYWsKICAgIGlm
IHN0YXJ0ZWRfdGhyZWFkcyA9PSAwOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBz
dGFydCBhbnkgc2hpcHBlciB0aHJlYWQiKQogICAgbG9nKCJlZ3Jlc3MgbGltaXQ6ICVkIGtiaXQv
cywgJWQgcG9zdGVyKHMpLCAlZC1ieXRlIEhUVFAgYm9keSBjYXAiICUKICAgICAgICAocmF0ZV9r
YnBzLCBzdGFydGVkX3RocmVhZHMsIE1BWF9QT1NUX0JZVEVTKSkKCiAgICBidWYgPSBbXQogICAg
bGFzdF9mbHVzaCA9IHRpbWUudGltZSgpCgogICAgd2hpbGUgcnVubmluZ1swXToKICAgICAgICB0
cnk6CiAgICAgICAgICAgIHIsIF8sIF8gPSBzZWxlY3Quc2VsZWN0KFtzeXMuc3RkaW5dLCBbXSwg
W10sIDEuMCkKICAgICAgICBleGNlcHQgc2VsZWN0LmVycm9yIGFzIGU6CiAgICAgICAgICAgIGlm
IGVbMF0gPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAg
ICBicmVhawoKICAgICAgICBpZiByOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBy
YXcgPSBzeXMuc3RkaW4ucmVhZGxpbmUoKQogICAgICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9T
RXJyb3IpIGFzIGU6CiAgICAgICAgICAgICAgICBpZiBnZXRhdHRyKGUsICdlcnJubycsIE5vbmUp
ID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAg
ICAgICBicmVhawogICAgICAgICAgICBpZiBub3QgcmF3OgogICAgICAgICAgICAgICAgYnJlYWsg
ICAgICAgICAgICAgICAgICAjIEVPRgogICAgICAgICAgICByYXcgPSByYXcuc3RyaXAoKQogICAg
ICAgICAgICBpZiByYXc6CiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAg
ZXYgPSBqc29uLmxvYWRzKHJhdykKICAgICAgICAgICAgICAgICAgICBpZiBpc2luc3RhbmNlKGV2
LCBkaWN0KToKICAgICAgICAgICAgICAgICAgICAgICAgaWYgZXYuZ2V0KCJfbnRfaW50ZXJuYWwi
KSA9PSAiY2FwdHVyZV9zdGF0c192MSI6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXB0
dXJlX2xhdGVzdCA9IGV2LmdldCgiY2FwdHVyZSIpIG9yIHt9CiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICBzYW1wbGUgPSBzdGF0cy5zbmFwc2hvdCgKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICBjYXB0dXJlX2xhdGVzdCwgbm9kZSwgInB5dGhvbiIsIHJhdGVfa2JwcywKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBzdGFydGVkX3RocmVhZHMsIHdzc2VfYm9keV9ieXRl
cywgbGVuKGJ1ZiksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgNDAwMCArIHEubWF4
c2l6ZSAqIE1BWF9CQVRDSCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIHN0YXRzLm9m
ZmVyX3N0YXRzKHNhbXBsZSk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5Ogog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBxLnB1dF9ub3dhaXQoKCJzdGF0cyIs
IE5vbmUpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBRdWV1ZS5GdWxs
OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGF0cy50YWtlX3N0YXRzKCkK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHMuYWRkKCJzdGF0c19zYW1w
bGVzX2Ryb3BwZWQiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAg
ICAgICAgICAgICAgICAgICAgc3RhdHMuYWRkKCJldmVudHNfaW4iKQogICAgICAgICAgICAgICAg
ICAgICAgICBpZiBsZW4oYnVmKSA+PSA0MDAwOgogICAgICAgICAgICAgICAgICAgICAgICAgICAg
ZGVsIGJ1ZlswXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHMuZHJvcHBlZCgicXVl
dWVfZnVsbCIsIDEpCiAgICAgICAgICAgICAgICAgICAgICAgIGJ1Zi5hcHBlbmQoZXYpCiAgICAg
ICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICBwYXNzCgog
ICAgICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAgd2hpbGUgbGVuKGJ1ZikgPj0gTUFYX0JB
VENIIG9yIChidWYgYW5kIG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDKToKICAgICAgICAg
ICAgbGFzdF9mbHVzaCA9IG5vdwogICAgICAgICAgICBiYXRjaCA9IHRha2VfYm91bmRlZF9iYXRj
aChidWYsIG5vZGUsIHN0YXRzLmRyb3BwZWQpCiAgICAgICAgICAgIGlmIG5vdCBiYXRjaDoKICAg
ICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHEucHV0
X25vd2FpdCgoImV2ZW50cyIsIGJhdGNoKSkKICAgICAgICAgICAgICAgIHN0YXRzLnF1ZXVlZChs
ZW4oYmF0Y2gpKQogICAgICAgICAgICBleGNlcHQgUXVldWUuRnVsbDoKICAgICAgICAgICAgICAg
IHN0YXRzLmRyb3BwZWQoInF1ZXVlX2Z1bGwiLCBsZW4oYmF0Y2gpKQogICAgICAgICAgICAgICAg
bG9nKCJXQVJOOiBlZ3Jlc3MgcXVldWUgZnVsbCwgZHJvcHBlZCAlZCBldmVudHMiICUgbGVuKGJh
dGNoKSkKCiAgICAjIHN0ZGluIGNsb3NlZCAoc25pZmZlciBzdG9wcGVkKSDigJQgZW5xdWV1ZSB0
aGUgZmluYWwgcGFydGlhbCBiYXRjaCBiZWZvcmUKICAgICMgd2FpdGluZyBmb3IgcG9zdGVyIHRo
cmVhZHMuIFByZXZpb3VzbHkgZXZlcnkgc2h1dGRvd24gbG9zdCAxLi4zOTkgZXZlbnRzLgogICAg
aWYgYnVmOgogICAgICAgIHdoaWxlIGJ1ZjoKICAgICAgICAgICAgYmF0Y2ggPSB0YWtlX2JvdW5k
ZWRfYmF0Y2goYnVmLCBub2RlLCBzdGF0cy5kcm9wcGVkKQogICAgICAgICAgICBpZiBub3QgYmF0
Y2g6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAg
ICBxLnB1dF9ub3dhaXQoKCJldmVudHMiLCBiYXRjaCkpCiAgICAgICAgICAgICAgICBzdGF0cy5x
dWV1ZWQobGVuKGJhdGNoKSkKICAgICAgICAgICAgZXhjZXB0IFF1ZXVlLkZ1bGw6CiAgICAgICAg
ICAgICAgICBzdGF0cy5kcm9wcGVkKCJxdWV1ZV9mdWxsIiwgbGVuKGJhdGNoKSkKICAgICAgICAg
ICAgICAgIGxvZygiV0FSTjogZWdyZXNzIHF1ZXVlIGZ1bGwgYXQgc2h1dGRvd24sIGRyb3BwZWQg
JWQgZXZlbnRzIiAlCiAgICAgICAgICAgICAgICAgICAgbGVuKGJhdGNoKSkKICAgIHEuam9pbigp
CiAgICBsb2coInN0b3BwZWQgKCVkIGV2ZW50cyBwZW5kaW5nIG9uIGV4aXQpIiAlIGxlbihidWYp
KQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
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
bmNsdWRlIDxkaXJlbnQuaD4KI2luY2x1ZGUgPHB0aHJlYWQuaD4KI2luY2x1ZGUgPGxpbnV4L2Zp
bHRlci5oPgojaW5jbHVkZSA8bGludXgvY2FwYWJpbGl0eS5oPgojaW5jbHVkZSA8bGludXgvaWZf
cGFja2V0Lmg+CiNpbmNsdWRlIDxsaW51eC9pZl9ldGhlci5oPgojaW5jbHVkZSA8aW9zdHJlYW0+
CiNpbmNsdWRlIDxmc3RyZWFtPgojaW5jbHVkZSA8bWFwPgojaW5jbHVkZSA8c2V0PgojaW5jbHVk
ZSA8bGlzdD4KI2luY2x1ZGUgPHNzdHJlYW0+CiNpbmNsdWRlIDxzdHJpbmc+CgojaW5jbHVkZSA8
dmVjdG9yPgojaW5jbHVkZSA8YWxnb3JpdGhtPgoKc3RhdGljIHZvbGF0aWxlIHNpZ19hdG9taWNf
dCBnX3J1bm5pbmcgPSAxOwpzdGF0aWMgdm9pZCBzdG9wX3NpZ25hbChpbnQpIHsgZ19ydW5uaW5n
ID0gMDsgfQoKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfRkxPV1MgPSA0MDk2OwpzdGF0aWMgY29u
c3Qgc2l6ZV90IE1BWF9UT1RBTF9CVUZGRVJfQllURVMgPSAxNiAqIDEwMjQgKiAxMDI0OyAvLyAx
NiBNaUIgYWdncmVnYXRlIGJ1ZGdldApzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QRU5ESU5HX1RP
VEFMID0gNDA5NjsgICAgICAgICAgICAgICAgICAgLy8gNDA5NiBnbG9iYWwgcGVuZGluZyByZXF1
ZXN0cwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QRU5ESU5HX1BFUl9GTE9XID0gMzI7CnN0YXRp
YyBjb25zdCBzaXplX3QgTUFYX1BPUlRTID0gMzA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0hF
QURFUl9CWVRFUyA9IDMyNzY4OyAgICAgICAgICAgICAgICAgICAvLyAzMiBLaUIKc3RhdGljIGNv
bnN0IHNpemVfdCBNQVhfRkxPV19CVUZGRVJfQllURVMgPSA2NTUzNjsgICAgICAgICAgICAgIC8v
IDY0IEtpQgpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NFX0JPRFlfQllURVMgPSA2NTUzNjsK
c3RhdGljIGNvbnN0IHNpemVfdCBNQVhfV1NTRV9CT0RZX0ZMT1dTID0gMjU2OwpzdGF0aWMgY29u
c3Qgc2l6ZV90IE1BWF9XU1NFX1VTRVJOQU1FID0gMjAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1B
WF9CQVRDSCA9IDQwMDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUVVFVUUgPSA0MDAwOwpzdGF0
aWMgY29uc3Qgc2l6ZV90IE1BWF9QT1NUX0JZVEVTID0gNjU1MzY7CnN0YXRpYyBjb25zdCBzaXpl
X3QgTUFYX1NUQVRTX0JZVEVTID0gMTYzODQ7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBERUZBVUxU
X1NISVBfUkFURV9LQlBTID0gMTAyNDsKc3RhdGljIGNvbnN0IGludCBGTFVTSF9TRUMgPSA1Owpz
dGF0aWMgY29uc3QgaW50IFJFVFJZX1NFQyA9IDYwOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgRkxP
V19UVEwgPSAxNTsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIERFRkFVTFRfUEVORElOR19UVEwgPSAz
MDsKc3RhdGljIHVuc2lnbmVkIGdfcGVuZGluZ190dGxfc2VjID0gREVGQVVMVF9QRU5ESU5HX1RU
TDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIEFDQ0VQVCA9IDIwNDg7CnN0YXRpYyBjb25zdCBpbnQg
U09fQVRUQUNIX0ZJTFRFUl9PTEQgPSAyNjsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNob3J0IEVU
SF9QX0lQX0hPU1QgPSAweDA4MDA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBFVEhfUF84
MDIxUV9IT1NUID0gMHg4MTAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9PT09fU0VHTUVOVFMg
PSA0OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9EUkFJTl9QRVJfUEFTUyA9IDI1NjsKCnN0YXRp
YyBpbmxpbmUgbG9uZyBsb25nIG5vd19tb25vdG9uaWNfbXMoKSB7CiAgc3RydWN0IHRpbWVzcGVj
IHRzOwogIGNsb2NrX2dldHRpbWUoQ0xPQ0tfTU9OT1RPTklDLCAmdHMpOwogIHJldHVybiAobG9u
ZyBsb25nKXRzLnR2X3NlYyAqIDEwMDBMTCArIHRzLnR2X25zZWMgLyAxMDAwMDAwTEw7Cn0KCnN0
YXRpYyBpbmxpbmUgaW50MzJfdCBzZXFfZGlmZih1aW50MzJfdCBhLCB1aW50MzJfdCBiKSB7CiAg
cmV0dXJuIChpbnQzMl90KShhIC0gYik7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmltKGNvbnN0
IHN0ZDo6c3RyaW5nICZzKSB7CiAgc2l6ZV90IGEgPSAwLCBiID0gcy5zaXplKCk7CiAgd2hpbGUg
KGEgPCBiICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1thXSkpICsrYTsKICB3aGlsZSAoYiA+
IGEgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilzW2IgLSAxXSkpIC0tYjsKICByZXR1cm4gcy5z
dWJzdHIoYSwgYiAtIGEpOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBsb3dlcihjb25zdCBzdGQ6OnN0
cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSBzOwogIHNpemVfdCBpOyBmb3IgKGkgPSAwOyBp
IDwgeC5zaXplKCk7ICsraSkgeFtpXSA9IChjaGFyKXRvbG93ZXIoKHVuc2lnbmVkIGNoYXIpeFtp
XSk7CiAgcmV0dXJuIHg7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25xKGNvbnN0IHN0ZDo6c3Ry
aW5nICZzKSB7CiAgc3RkOjpzdHJpbmcgeCA9ICJcIiI7IHNpemVfdCBpOwogIGZvciAoaSA9IDA7
IGkgPCBzLnNpemUoKTsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hh
cilzW2ldOwogICAgaWYgKGMgPT0gJ1xcJyB8fCBjID09ICdcIicpIHsgeCArPSAnXFwnOyB4ICs9
IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAgIGVsc2Ug
aWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0JykgeCArPSAi
XFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0gKGNoYXIp
YzsKICB9CiAgeCArPSAnXCInOyByZXR1cm4geDsKfQpzdGF0aWMgbG9uZyBsb25nIG5vd19tcygp
IHsKICBzdHJ1Y3QgdGltZXZhbCB0djsgZ2V0dGltZW9mZGF5KCZ0diwgTlVMTCk7CiAgcmV0dXJu
IChsb25nIGxvbmcpdHYudHZfc2VjICogMTAwMExMICsgdHYudHZfdXNlYyAvIDEwMDA7Cn0Kc3Rh
dGljIHN0ZDo6c3RyaW5nIG51bShsb25nIHYpIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwg
djsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIGJvb2wgdmFsaWRfcG9ydCh1bnNpZ25lZCBwKSB7
IHJldHVybiBwID4gMCAmJiBwIDw9IDY1NTM1OyB9CgpzdGF0aWMgdWludDE2X3QgcmVhZF91MTYo
Y29uc3QgdW5zaWduZWQgY2hhciAqcCkgewogIHVpbnQxNl90IHZhbHVlOwogIG1lbWNweSgmdmFs
dWUsIHAsIHNpemVvZih2YWx1ZSkpOwogIHJldHVybiB2YWx1ZTsKfQoKc3RhdGljIHVpbnQzMl90
IHJlYWRfdTMyKGNvbnN0IHVuc2lnbmVkIGNoYXIgKnApIHsKICB1aW50MzJfdCB2YWx1ZTsKICBt
ZW1jcHkoJnZhbHVlLCBwLCBzaXplb2YodmFsdWUpKTsKICByZXR1cm4gdmFsdWU7Cn0Kc3RhdGlj
IGJvb2wgaGFzX21ldGhvZChjb25zdCBzdGQ6OnN0cmluZyAmbSkgewogIHJldHVybiBtID09ICJH
RVQiIHx8IG0gPT0gIlBPU1QiIHx8IG0gPT0gIlBVVCIgfHwgbSA9PSAiREVMRVRFIiB8fAogICAg
ICAgICBtID09ICJQQVRDSCIgfHwgbSA9PSAiSEVBRCIgfHwgbSA9PSAiT1BUSU9OUyI7Cn0Kc3Rh
dGljIHN0ZDo6c3RyaW5nIGhvc3RfbmFtZSgpIHsKICBjaGFyIGJbMjU2XTsgaWYgKGdldGhvc3Ru
YW1lKGIsIHNpemVvZihiKSAtIDEpICE9IDApIHJldHVybiAidW5rbm93bi1ub2RlIjsKICBiW3Np
emVvZihiKSAtIDFdID0gMDsgY2hhciAqcCA9IHN0cmNocihiLCAnLicpOyBpZiAocCkgKnAgPSAw
OyByZXR1cm4gYjsKfQoKLyogU3RyaWN0IEJhc2U2NCBkZWNvZGVyIHdpdGggdWludDMyIGFjY3Vt
dWxhdG9yLCBpbW1lZGlhdGUgc3RvcCBhdCAnOicsIGFuZCBpbnZhbGlkIGNoYXIgcmVqZWN0aW9u
ICovCnN0YXRpYyBzdGQ6OnN0cmluZyBiNjRkZWNvZGVfdXNlcihjb25zdCBjaGFyICppbiwgc2l6
ZV90IGluX2xlbikgewogIHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNo
YXIpKmluKSkgeyArK2luOyAtLWluX2xlbjsgfQogIHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3Bh
Y2UoKHVuc2lnbmVkIGNoYXIpaW5baW5fbGVuIC0gMV0pKSB7IC0taW5fbGVuOyB9CiAgc3RkOjpz
dHJpbmcgb3V0OwogIHVpbnQzMl90IHZhbCA9IDA7CiAgaW50IGJpdHMgPSAtODsKICBmb3IgKHNp
emVfdCBpID0gMDsgaSA8IGluX2xlbjsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5z
aWduZWQgY2hhcilpbltpXTsKICAgIGludCBkID0gLTE7CiAgICBpZiAoYyA+PSAnQScgJiYgYyA8
PSAnWicpIGQgPSBjIC0gJ0EnOwogICAgZWxzZSBpZiAoYyA+PSAnYScgJiYgYyA8PSAneicpIGQg
PSBjIC0gJ2EnICsgMjY7CiAgICBlbHNlIGlmIChjID49ICcwJyAmJiBjIDw9ICc5JykgZCA9IGMg
LSAnMCcgKyA1MjsKICAgIGVsc2UgaWYgKGMgPT0gJysnKSBkID0gNjI7CiAgICBlbHNlIGlmIChj
ID09ICcvJykgZCA9IDYzOwogICAgZWxzZSBpZiAoYyA9PSAnPScpIGJyZWFrOwogICAgZWxzZSBp
ZiAoaXNzcGFjZShjKSkgY29udGludWU7CiAgICBlbHNlIHJldHVybiAiIjsKICAgIHZhbCA9ICh2
YWwgPDwgNikgfCAodWludDMyX3QpZDsKICAgIGJpdHMgKz0gNjsKICAgIGlmIChiaXRzID49IDAp
IHsKICAgICAgY2hhciBjaCA9IChjaGFyKSgodmFsID4+IGJpdHMpICYgMHhmZik7CiAgICAgIGJp
dHMgLT0gODsKICAgICAgaWYgKGNoID09ICc6JykgYnJlYWs7CiAgICAgIG91dCArPSBjaDsKICAg
ICAgaWYgKG91dC5zaXplKCkgPiA2NCkgYnJlYWs7CiAgICB9CiAgfQogIHJldHVybiBvdXQ7Cn0K
CnN0YXRpYyBzdGQ6OnN0cmluZyBpcF90b19zdHIodWludDMyX3QgaXBfYmUpIHsKICBjaGFyIGJb
SU5FVF9BRERSU1RSTEVOXTsKICBpbmV0X250b3AoQUZfSU5FVCwgJmlwX2JlLCBiLCBzaXplb2Yo
YikpOwogIHJldHVybiBiOwp9CgpzdGF0aWMgaW5saW5lIGJvb2wgaXNfaGV4KGNoYXIgYykgewog
IHJldHVybiAoYyA+PSAnMCcgJiYgYyA8PSAnOScpIHx8IChjID49ICdhJyAmJiBjIDw9ICdmJykg
fHwgKGMgPj0gJ0EnICYmIGMgPD0gJ0YnKTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIHRyYWNlX2lk
X2Zyb21fcGFyZW50KGNvbnN0IHN0ZDo6c3RyaW5nICZ0cCkgewogIHN0ZDo6c3RyaW5nIHggPSB0
cmltKHRwKTsKICBpZiAoeC5zaXplKCkgIT0gNTUgfHwgeFsyXSAhPSAnLScgfHwgeFszNV0gIT0g
Jy0nIHx8IHhbNTJdICE9ICctJykgcmV0dXJuICIiOwogIGlmICh4WzBdICE9ICcwJyB8fCB4WzFd
ICE9ICcwJykgcmV0dXJuICIiOwogIGJvb2wgYWxsX3plcm9zID0gdHJ1ZTsKICBmb3IgKHNpemVf
dCBpID0gMzsgaSA8IDM1OyArK2kpIHsKICAgIGlmICghaXNfaGV4KHhbaV0pKSByZXR1cm4gIiI7
CiAgICBpZiAoeFtpXSAhPSAnMCcpIGFsbF96ZXJvcyA9IGZhbHNlOwogIH0KICBpZiAoYWxsX3pl
cm9zKSByZXR1cm4gIiI7CiAgYm9vbCBzcGFuX3plcm9zID0gdHJ1ZTsKICBmb3IgKHNpemVfdCBp
ID0gMzY7IGkgPCA1MjsgKytpKSB7CiAgICBpZiAoIWlzX2hleCh4W2ldKSkgcmV0dXJuICIiOwog
ICAgaWYgKHhbaV0gIT0gJzAnKSBzcGFuX3plcm9zID0gZmFsc2U7CiAgfQogIGlmIChzcGFuX3pl
cm9zKSByZXR1cm4gIiI7CiAgcmV0dXJuIGxvd2VyKHguc3Vic3RyKDMsIDMyKSk7Cn0KCnN0YXRp
YyB1aW50NjRfdCBnX3JuZ19zdGF0ZSA9IDA7CnN0YXRpYyB2b2lkIGluaXRfcm5nKCkgewogIEZJ
TEUgKmYgPSBmb3BlbigiL2Rldi91cmFuZG9tIiwgInJiIik7CiAgaWYgKGYpIHsKICAgIHNpemVf
dCBuID0gZnJlYWQoJmdfcm5nX3N0YXRlLCAxLCBzaXplb2YoZ19ybmdfc3RhdGUpLCBmKTsKICAg
ICh2b2lkKW47CiAgICBmY2xvc2UoZik7CiAgfQogIGlmICghZ19ybmdfc3RhdGUpIHsKICAgIGdf
cm5nX3N0YXRlID0gKCh1aW50NjRfdCl0aW1lKE5VTEwpIDw8IDMyKSBeICh1aW50NjRfdClnZXRw
aWQoKTsKICB9Cn0Kc3RhdGljIGlubGluZSB1aW50NjRfdCBuZXh0X3JuZygpIHsKICB1aW50NjRf
dCB4ID0gZ19ybmdfc3RhdGU7CiAgeCBePSB4IDw8IDEzOyB4IF49IHggPj4gNzsgeCBePSB4IDw8
IDE3OwogIHJldHVybiBnX3JuZ19zdGF0ZSA9ICh4ID8geCA6IDB4ODUzYzQ5ZTY3NDhmZWE5YlVM
TCk7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyBtYWtlX3RyYWNlcGFyZW50KHN0ZDo6c3RyaW5nICp0
aWQpIHsKICB1aW50NjRfdCByMSA9IG5leHRfcm5nKCk7CiAgdWludDY0X3QgcjIgPSBuZXh0X3Ju
ZygpOwogIHVpbnQ2NF90IHIzID0gbmV4dF9ybmcoKTsKICBjaGFyIGJ1Zls2NF07CiAgc25wcmlu
dGYoYnVmLCBzaXplb2YoYnVmKSwgIjAwLSUwMTZsbHglMDE2bGx4LSUwMTZsbHgtMDEiLAogICAg
ICAgICAgICh1bnNpZ25lZCBsb25nIGxvbmcpcjEsICh1bnNpZ25lZCBsb25nIGxvbmcpcjIsICh1
bnNpZ25lZCBsb25nIGxvbmcpcjMpOwogIGNoYXIgdGlkX2J1ZlszM107CiAgc25wcmludGYodGlk
X2J1Ziwgc2l6ZW9mKHRpZF9idWYpLCAiJTAxNmxseCUwMTZsbHgiLAogICAgICAgICAgICh1bnNp
Z25lZCBsb25nIGxvbmcpcjEsICh1bnNpZ25lZCBsb25nIGxvbmcpcjIpOwogICp0aWQgPSB0aWRf
YnVmOwogIHJldHVybiBidWY7Cn0KCnN0cnVjdCBFdmVudCB7CiAgbG9uZyB0czsgc3RkOjpzdHJp
bmcgaG9zdCwgc3JjLCBzZXJ2aWNlLCBtZXRob2QsIHBhdGgsIHVzZXIsIHNjaGVtZSwgcHJvYmU7
CiAgc3RkOjpzdHJpbmcgYmFzaWNfdXNlciwgd3NzZV91c2VyOwogIHN0ZDo6c3RyaW5nIGhvc3Rf
aGRyLCB1c2VyX2FnZW50LCB4ZmYsIGNhbGxlciwgZHN0X2lwLCB0cmFjZXBhcmVudCwgdHJhY2Vf
aWQ7CiAgdW5zaWduZWQgY2FsbGVyX3BvcnQsIGRzdF9wb3J0LCByZXFfYnl0ZXMsIHJlc3BfYnl0
ZXM7IGludCBzdGF0dXM7IGxvbmcgZHVyYXRpb25fbXM7CiAgYm9vbCBoYXNfc3RhdHVzLCBoYXNf
ZHVyYXRpb24sIGhhc19yZXNwOwogIEV2ZW50KCkgOiB0cygwKSwgY2FsbGVyX3BvcnQoMCksIGRz
dF9wb3J0KDApLCByZXFfYnl0ZXMoMCksIHJlc3BfYnl0ZXMoMCksIHN0YXR1cygwKSwgZHVyYXRp
b25fbXMoMCksIGhhc19zdGF0dXMoZmFsc2UpLCBoYXNfZHVyYXRpb24oZmFsc2UpLCBoYXNfcmVz
cChmYWxzZSkge30KfTsKc3RydWN0IFJlcXVlc3RNZXRhIHsKICBzdGQ6OnN0cmluZyBjb250ZW50
X3R5cGUsIHRyYW5zZmVyX2VuY29kaW5nOwogIHNpemVfdCBjb250ZW50X2xlbmd0aDsKICBib29s
IGhhc19jb250ZW50X2xlbmd0aDsKICBib29sIGhhc19jb25mbGljdF9jbDsKICBSZXF1ZXN0TWV0
YSgpIDogY29udGVudF9sZW5ndGgoMCksIGhhc19jb250ZW50X2xlbmd0aChmYWxzZSksIGhhc19j
b25mbGljdF9jbChmYWxzZSkge30KfTsKCnN0cnVjdCBUY3BTZWdtZW50IHsKICB1aW50MzJfdCBz
ZXE7CiAgc3RkOjpzdHJpbmcgZGF0YTsKfTsKCnN0YXRpYyBzaXplX3QgZ190b3RhbF9mbG93X2J5
dGVzID0gMDsKc3RhdGljIGlubGluZSB2b2lkIGZsb3dfYnl0ZXNfYWRkKHNpemVfdCBuKSB7CiAg
Z190b3RhbF9mbG93X2J5dGVzICs9IG47Cn0Kc3RhdGljIGlubGluZSB2b2lkIGZsb3dfYnl0ZXNf
c3ViKHNpemVfdCBuKSB7CiAgaWYgKGdfdG90YWxfZmxvd19ieXRlcyA+PSBuKSBnX3RvdGFsX2Zs
b3dfYnl0ZXMgLT0gbjsKICBlbHNlIGdfdG90YWxfZmxvd19ieXRlcyA9IDA7Cn0KCnN0cnVjdCBG
bG93IHsKICB1aW50MzJfdCBuZXh0X3NlcTsKICBib29sIGhhc19zZXE7CiAgYm9vbCBpc19icm9r
ZW47CiAgYm9vbCBjb3JyZWxhdGlvbl9kaXNhYmxlZDsKICBib29sIHN5bl9zZWVuOwogIHRpbWVf
dCB0b3VjaGVkOwogIGxvbmcgbG9uZyBmaXJzdF9ieXRlX21vbm9fbXM7CiAgdWludDMyX3QgZ2Vu
ZXJhdGlvbjsKICBzdGQ6OnN0cmluZyBidWY7CiAgc3RkOjp2ZWN0b3I8VGNwU2VnbWVudD4gb29v
OwoKICBlbnVtIEh0dHBTdGF0ZSB7CiAgICBIVFRQX1NUQVRFX0hFQURFUiwKICAgIEhUVFBfU1RB
VEVfQk9EWSwKICAgIEhUVFBfU1RBVEVfQ0hVTkssCiAgICBIVFRQX1NUQVRFX0NMT1NFX0JPRFkK
ICB9IHN0YXRlOwoKICBzaXplX3QgYm9keV9yZW1haW5pbmc7CiAgc2l6ZV90IGNodW5rX3BheWxv
YWRfcmVtYWluaW5nOwogIGJvb2wgY2h1bmtfcmVhZGluZ19sZW47CiAgYm9vbCBjaHVua19yZWFk
aW5nX2NybGY7CiAgYm9vbCBjaHVua19yZWFkaW5nX3RyYWlsZXI7CgogIGJvb2wgYXdhaXRpbmdf
d3NzZTsKICBFdmVudCB3c3NlX2V2ZW50OwogIHN0ZDo6c3RyaW5nIHdzc2VfYnVmOwogIHNpemVf
dCB3c3NlX2dvYWw7CgogIEZsb3coKSA6IG5leHRfc2VxKDApLCBoYXNfc2VxKGZhbHNlKSwgaXNf
YnJva2VuKGZhbHNlKSwgY29ycmVsYXRpb25fZGlzYWJsZWQoZmFsc2UpLAogICAgICAgICAgIHN5
bl9zZWVuKGZhbHNlKSwgdG91Y2hlZCh0aW1lKE5VTEwpKSwgZmlyc3RfYnl0ZV9tb25vX21zKDAp
LCBnZW5lcmF0aW9uKDApLAogICAgICAgICAgIHN0YXRlKEhUVFBfU1RBVEVfSEVBREVSKSwgYm9k
eV9yZW1haW5pbmcoMCksIGNodW5rX3BheWxvYWRfcmVtYWluaW5nKDApLAogICAgICAgICAgIGNo
dW5rX3JlYWRpbmdfbGVuKHRydWUpLCBjaHVua19yZWFkaW5nX2NybGYoZmFsc2UpLCBjaHVua19y
ZWFkaW5nX3RyYWlsZXIoZmFsc2UpLAogICAgICAgICAgIGF3YWl0aW5nX3dzc2UoZmFsc2UpLCB3
c3NlX2dvYWwoMCkge30KCgogIHZvaWQgY2xlYXJfYnVmZmVycygpIHsKICAgIGZsb3dfYnl0ZXNf
c3ViKGJ1Zi5zaXplKCkpOwogICAgYnVmLmNsZWFyKCk7CiAgICBmbG93X2J5dGVzX3N1Yih3c3Nl
X2J1Zi5zaXplKCkpOwogICAgd3NzZV9idWYuY2xlYXIoKTsKICAgIGZvciAoc2l6ZV90IGkgPSAw
OyBpIDwgb29vLnNpemUoKTsgKytpKSB7CiAgICAgIGZsb3dfYnl0ZXNfc3ViKG9vb1tpXS5kYXRh
LnNpemUoKSk7CiAgICB9CiAgICBvb28uY2xlYXIoKTsKICB9CgogIGJvb2wgYnVmX2FwcGVuZChj
b25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuKSB7CiAgICBpZiAoYnVmLnNpemUoKSArIGxlbiA+
IE1BWF9GTE9XX0JVRkZFUl9CWVRFUykgewogICAgICBjbGVhcl9idWZmZXJzKCk7CiAgICAgIGlz
X2Jyb2tlbiA9IHRydWU7CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KICAgIGJ1Zi5hcHBlbmQo
ZGF0YSwgbGVuKTsKICAgIGZsb3dfYnl0ZXNfYWRkKGxlbik7CiAgICByZXR1cm4gdHJ1ZTsKICB9
CgogIHZvaWQgYnVmX2VyYXNlKHNpemVfdCBvZmYsIHNpemVfdCBsZW4pIHsKICAgIGlmIChvZmYg
Pj0gYnVmLnNpemUoKSkgcmV0dXJuOwogICAgaWYgKGxlbiA+IGJ1Zi5zaXplKCkgLSBvZmYpIGxl
biA9IGJ1Zi5zaXplKCkgLSBvZmY7CiAgICBidWYuZXJhc2Uob2ZmLCBsZW4pOwogICAgZmxvd19i
eXRlc19zdWIobGVuKTsKICB9CgogIHZvaWQgd3NzZV9hcHBlbmQoY29uc3QgY2hhciAqZGF0YSwg
c2l6ZV90IGxlbikgewogICAgd3NzZV9idWYuYXBwZW5kKGRhdGEsIGxlbik7CiAgICBmbG93X2J5
dGVzX2FkZChsZW4pOwogIH0KCiAgYm9vbCBvb29fcHVzaCh1aW50MzJfdCBzZXEsIGNvbnN0IGNo
YXIgKmRhdGEsIHNpemVfdCBsZW4pIHsKICAgIGlmIChvb28uc2l6ZSgpID49IE1BWF9PT09fU0VH
TUVOVFMpIHJldHVybiBmYWxzZTsKICAgIFRjcFNlZ21lbnQgc2VnOwogICAgc2VnLnNlcSA9IHNl
cTsKICAgIHNlZy5kYXRhLmFzc2lnbihkYXRhLCBsZW4pOwogICAgb29vLnB1c2hfYmFjayhzZWcp
OwogICAgZmxvd19ieXRlc19hZGQobGVuKTsKICAgIHJldHVybiB0cnVlOwogIH0KCiAgdm9pZCBv
b29fZXJhc2Uoc2l6ZV90IGlkeCkgewogICAgaWYgKGlkeCA8IG9vby5zaXplKCkpIHsKICAgICAg
Zmxvd19ieXRlc19zdWIob29vW2lkeF0uZGF0YS5zaXplKCkpOwogICAgICBvb28uZXJhc2Uob29v
LmJlZ2luKCkgKyBpZHgpOwogICAgfQogIH0KfTsKCnN0cnVjdCBGbG93S2V5IHsKICB1aW50MzJf
dCBzX2lwOwogIHVpbnQxNl90IHNwb3J0OwogIHVpbnQzMl90IGRfaXA7CiAgdWludDE2X3QgZHBv
cnQ7CiAgYm9vbCBvcGVyYXRvcjwoY29uc3QgRmxvd0tleSAmeCkgY29uc3QgewogICAgaWYgKHNf
aXAgIT0geC5zX2lwKSByZXR1cm4gc19pcCA8IHguc19pcDsKICAgIGlmIChzcG9ydCAhPSB4LnNw
b3J0KSByZXR1cm4gc3BvcnQgPCB4LnNwb3J0OwogICAgaWYgKGRfaXAgIT0geC5kX2lwKSByZXR1
cm4gZF9pcCA8IHguZF9pcDsKICAgIHJldHVybiBkcG9ydCA8IHguZHBvcnQ7CiAgfQogIGJvb2wg
b3BlcmF0b3I9PShjb25zdCBGbG93S2V5ICZ4KSBjb25zdCB7CiAgICByZXR1cm4gc19pcCA9PSB4
LnNfaXAgJiYgc3BvcnQgPT0geC5zcG9ydCAmJiBkX2lwID09IHguZF9pcCAmJiBkcG9ydCA9PSB4
LmRwb3J0OwogIH0KfTsKCnR5cGVkZWYgRmxvd0tleSBQYWNrZXRLZXk7CgpzdGF0aWMgdWludDY0
X3QgZ19yZXFfaWRfc2VxID0gMDsKCnN0cnVjdCBQZW5kaW5nIHsKICB1aW50NjRfdCByZXFfaWQ7
CiAgdWludDMyX3QgZ2VuZXJhdGlvbjsKICBFdmVudCBldjsKICBsb25nIGxvbmcgc3RhcnRlZF93
YWxsX21zOwogIGxvbmcgbG9uZyBzdGFydGVkX21vbm9fbXM7CiAgYm9vbCBpc190b21ic3RvbmU7
CiAgbG9uZyBsb25nIHRvbWJzdG9uZV9tb25vX21zOwogIFBlbmRpbmcoKSA6IHJlcV9pZCgwKSwg
Z2VuZXJhdGlvbigwKSwgc3RhcnRlZF93YWxsX21zKDApLCBzdGFydGVkX21vbm9fbXMoMCksCiAg
ICAgICAgICAgICAgaXNfdG9tYnN0b25lKGZhbHNlKSwgdG9tYnN0b25lX21vbm9fbXMoMCkge30K
ICBQZW5kaW5nKHVpbnQ2NF90IGlkLCB1aW50MzJfdCBnZW4sIGNvbnN0IEV2ZW50ICZlLCBsb25n
IGxvbmcgd2FsbF90LCBsb25nIGxvbmcgbW9ub190KQogICAgOiByZXFfaWQoaWQpLCBnZW5lcmF0
aW9uKGdlbiksIGV2KGUpLCBzdGFydGVkX3dhbGxfbXMod2FsbF90KSwgc3RhcnRlZF9tb25vX21z
KG1vbm9fdCksCiAgICAgIGlzX3RvbWJzdG9uZShmYWxzZSksIHRvbWJzdG9uZV9tb25vX21zKDAp
IHt9Cn07CgpzdHJ1Y3QgUGVuZGluZ1F1ZXVlUmVmIHsKICB1aW50NjRfdCByZXFfaWQ7CiAgdWlu
dDMyX3QgZ2VuZXJhdGlvbjsKICBQYWNrZXRLZXkga2V5OwogIGxvbmcgbG9uZyBzdGFydGVkX21v
bm9fbXM7Cn07CgpzdGF0aWMgc2l6ZV90IGdfdG90YWxfcGVuZGluZ19jb3VudCA9IDA7CnN0YXRp
YyBzdGQ6Omxpc3Q8UGVuZGluZ1F1ZXVlUmVmPiBnX3BlbmRpbmdfZmlmbzsKCi8vIFBhY2tldEtl
eSBlbnRyaWVzIChyZXNwb25zZS1kaXJlY3Rpb246IHNlcnZlcuKGkmNsaWVudCkgZm9yIHdoaWNo
IHJlc3BvbnNlCgovLyBjb3JyZWxhdGlvbiBpcyBwZXJtYW5lbnRseSBkaXNhYmxlZCB1bnRpbCBh
IHZlcmlmaWVkIG5ldyBTWU4gYXJyaXZlcy4KLy8gQm91bmRlZCB0byBNQVhfQ09SUl9ESVNBQkxF
RCBlbnRyaWVzIHRvIHByZXZlbnQgbWVtb3J5IGdyb3d0aCB1bmRlciBtYW55Ci8vIHRpbWVkLW91
dCBjb25uZWN0aW9ucy4gV2hlbiBjYXBhY2l0eSBpcyByZWFjaGVkLCBvcmRlcmluZyBmb3IgdW50
cmFja2VkCi8vIGNvbm5lY3Rpb25zIGNhbm5vdCBiZSB2ZXJpZmllZCwgZmFsbGluZyBiYWNrIHRv
IGVtaXR0aW5nIHdpdGhvdXQgY29ycmVsYXRpb24uCnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0NP
UlJfRElTQUJMRUQgPSAyMDQ4OwpzdGF0aWMgc3RkOjpzZXQ8UGFja2V0S2V5PiBnX2NvcnJfZGlz
YWJsZWQ7CnN0YXRpYyBzdGQ6Omxpc3Q8UGFja2V0S2V5PiBnX2NvcnJfZGlzYWJsZWRfZmlmbzsK
c3RhdGljIGJvb2wgZ19jb3JyX2NhcGFjaXR5X3JlYWNoZWQgPSBmYWxzZTsKCnN0YXRpYyB2b2lk
IGNvcnJfZGlzYWJsZWRfaW5zZXJ0KGNvbnN0IFBhY2tldEtleSAma2V5KSB7CiAgaWYgKGdfY29y
cl9kaXNhYmxlZC5jb3VudChrZXkpKSByZXR1cm47CiAgd2hpbGUgKGdfY29ycl9kaXNhYmxlZC5z
aXplKCkgPj0gTUFYX0NPUlJfRElTQUJMRUQgJiYgIWdfY29ycl9kaXNhYmxlZF9maWZvLmVtcHR5
KCkpIHsKICAgIGdfY29ycl9jYXBhY2l0eV9yZWFjaGVkID0gdHJ1ZTsKICAgIFBhY2tldEtleSBv
bGRfa2V5ID0gZ19jb3JyX2Rpc2FibGVkX2ZpZm8uZnJvbnQoKTsKICAgIGdfY29ycl9kaXNhYmxl
ZF9maWZvLnBvcF9mcm9udCgpOwogICAgZ19jb3JyX2Rpc2FibGVkLmVyYXNlKG9sZF9rZXkpOwog
IH0KICBnX2NvcnJfZGlzYWJsZWQuaW5zZXJ0KGtleSk7CiAgZ19jb3JyX2Rpc2FibGVkX2ZpZm8u
cHVzaF9iYWNrKGtleSk7Cn0KCnN0YXRpYyB2b2lkIGNvcnJfZGlzYWJsZWRfZXJhc2UoY29uc3Qg
UGFja2V0S2V5ICZrZXkpIHsKICBpZiAoZ19jb3JyX2Rpc2FibGVkLmVyYXNlKGtleSkpIHsKICAg
IGZvciAoc3RkOjpsaXN0PFBhY2tldEtleT46Oml0ZXJhdG9yIGl0ID0gZ19jb3JyX2Rpc2FibGVk
X2ZpZm8uYmVnaW4oKTsKICAgICAgICAgaXQgIT0gZ19jb3JyX2Rpc2FibGVkX2ZpZm8uZW5kKCk7
ICsraXQpIHsKICAgICAgaWYgKCppdCA9PSBrZXkpIHsKICAgICAgICBnX2NvcnJfZGlzYWJsZWRf
Zmlmby5lcmFzZShpdCk7CiAgICAgICAgYnJlYWs7CiAgICAgIH0KICAgIH0KICB9Cn0KCnN0YXRp
YyB2b2lkIGNvcnJfZGlzYWJsZWRfY2xlYXIoKSB7CiAgZ19jb3JyX2Rpc2FibGVkLmNsZWFyKCk7
CiAgZ19jb3JyX2Rpc2FibGVkX2ZpZm8uY2xlYXIoKTsKICBnX2NvcnJfY2FwYWNpdHlfcmVhY2hl
ZCA9IGZhbHNlOwp9CgpzdGF0aWMgYm9vbCBpc19jb3JyZWxhdGlvbl9kaXNhYmxlZChjb25zdCBQ
YWNrZXRLZXkgJmtleSwgYm9vbCBzeW5fc2VlbikgewogIGlmIChnX2NvcnJfZGlzYWJsZWQuY291
bnQoa2V5KSkgcmV0dXJuIHRydWU7CiAgaWYgKGdfY29ycl9jYXBhY2l0eV9yZWFjaGVkICYmICFz
eW5fc2VlbikgcmV0dXJuIHRydWU7CiAgcmV0dXJuIGZhbHNlOwp9CgoKc3RhdGljIHZvaWQgbG9n
bXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7IGZwcmludGYoc3RkZXJyLCAibnQtc25pZmYtY3Bw
OiAlc1xuIiwgcy5jX3N0cigpKTsgZmZsdXNoKHN0ZGVycik7IH0KCnN0YXRpYyBib29sIHBhcnNl
X2RlY2ltYWxfc2l6ZShjb25zdCBjaGFyICpwLCBzaXplX3Qgbiwgc2l6ZV90ICpvdXQpIHsKICB3
aGlsZSAobiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKSpwKSkgeyArK3A7IC0tbjsgfQogIHdo
aWxlIChuICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpcFtuIC0gMV0pKSAtLW47CiAgaWYgKCFu
KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IHZhbHVlID0gMDsKICBmb3IgKHNpemVfdCBpID0gMDsg
aSA8IG47ICsraSkgewogICAgaWYgKHBbaV0gPCAnMCcgfHwgcFtpXSA+ICc5JykgcmV0dXJuIGZh
bHNlOwogICAgdW5zaWduZWQgZGlnaXQgPSAodW5zaWduZWQpKHBbaV0gLSAnMCcpOwogICAgaWYg
KHZhbHVlID4gKHNpemVfdCktMSAvIDEwIHx8IHZhbHVlICogMTAgPiAoc2l6ZV90KS0xIC0gZGln
aXQpIHJldHVybiBmYWxzZTsKICAgIHZhbHVlID0gdmFsdWUgKiAxMCArIGRpZ2l0OwogIH0KICAq
b3V0ID0gdmFsdWU7CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3JlcXVlc3Qo
Y29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgRXZlbnQgKmUsIFJlcXVlc3RNZXRhICptZXRh
KSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSArIGxlbjsKICBjb25zdCBjaGFyICpwID0gZGF0
YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQg
LSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNoYXIgKnNwMSA9IChjb25z
dCBjaGFyICopbWVtY2hyKHAsICcgJywgZW9sIC0gcCk7CiAgaWYgKCFzcDEpIHJldHVybiBmYWxz
ZTsKICBlLT5tZXRob2QuYXNzaWduKHAsIHNwMSAtIHApOwogIGlmICghaGFzX21ldGhvZChlLT5t
ZXRob2QpKSByZXR1cm4gZmFsc2U7CgogIGNvbnN0IGNoYXIgKnBhdGhfc3RhcnQgPSBzcDEgKyAx
OwogIHdoaWxlIChwYXRoX3N0YXJ0IDwgZW9sICYmICpwYXRoX3N0YXJ0ID09ICcgJykgKytwYXRo
X3N0YXJ0OwogIGNvbnN0IGNoYXIgKnNwMiA9IChjb25zdCBjaGFyICopbWVtY2hyKHBhdGhfc3Rh
cnQsICcgJywgZW9sIC0gcGF0aF9zdGFydCk7CiAgaWYgKCFzcDIpIHNwMiA9IChlb2wgPiBkYXRh
ICYmICooZW9sIC0gMSkgPT0gJ1xyJykgPyBlb2wgLSAxIDogZW9sOwogIGNvbnN0IGNoYXIgKnFt
YXJrID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJz8nLCBzcDIgLSBwYXRoX3N0
YXJ0KTsKICBzaXplX3QgcGF0aF9sZW4gPSAocW1hcmsgPyBxbWFyayA6IHNwMikgLSBwYXRoX3N0
YXJ0OwogIGlmIChwYXRoX2xlbiA+IDEyMCkgcGF0aF9sZW4gPSAxMjA7CiAgZS0+cGF0aC5hc3Np
Z24ocGF0aF9zdGFydCwgcGF0aF9sZW4pOwoKICBwID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVu
ZCkgewogICAgaWYgKCpwID09ICdccicgfHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBj
aGFyICpsaW5lX2VuZCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwog
ICAgaWYgKCFsaW5lX2VuZCkgbGluZV9lbmQgPSBlbmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9
IChjb25zdCBjaGFyICopbWVtY2hyKHAsICc6JywgbGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xv
bikgewogICAgICBzaXplX3QgaG5hbWVfbGVuID0gY29sb24gLSBwOwogICAgICBjb25zdCBjaGFy
ICp2YWxfc3RhcnQgPSBjb2xvbiArIDE7CiAgICAgIHdoaWxlICh2YWxfc3RhcnQgPCBsaW5lX2Vu
ZCAmJiAoKnZhbF9zdGFydCA9PSAnICcgfHwgKnZhbF9zdGFydCA9PSAnXHQnKSkgKyt2YWxfc3Rh
cnQ7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9lbmQgPSBsaW5lX2VuZDsKICAgICAgd2hpbGUgKHZh
bF9lbmQgPiB2YWxfc3RhcnQgJiYgKHZhbF9lbmRbLTFdID09ICdccicgfHwgdmFsX2VuZFstMV0g
PT0gJ1xuJyB8fCB2YWxfZW5kWy0xXSA9PSAnICcgfHwgdmFsX2VuZFstMV0gPT0gJ1x0JykpIC0t
dmFsX2VuZDsKICAgICAgc2l6ZV90IHZhbF9sZW4gPSB2YWxfZW5kIC0gdmFsX3N0YXJ0OwoKICAg
ICAgaWYgKGhuYW1lX2xlbiA9PSAxMyAmJiAhc3RybmNhc2VjbXAocCwgImF1dGhvcml6YXRpb24i
LCAxMykpIHsKICAgICAgICBpZiAodmFsX2xlbiA+IDYgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFy
dCwgIkJhc2ljICIsIDYpKSB7CiAgICAgICAgICBzdGQ6OnN0cmluZyBiYXNpY191c2VyID0gYjY0
ZGVjb2RlX3VzZXIodmFsX3N0YXJ0ICsgNiwgdmFsX2xlbiAtIDYpOwogICAgICAgICAgaWYgKCFi
YXNpY191c2VyLmVtcHR5KCkpIHsKICAgICAgICAgICAgZS0+YmFzaWNfdXNlciA9IGJhc2ljX3Vz
ZXI7CiAgICAgICAgICAgIGUtPnVzZXIgPSBiYXNpY191c2VyOwogICAgICAgICAgICBlLT5zY2hl
bWUgPSAiYmFzaWMiOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSBpZiAodmFsX2xlbiA+IDcg
JiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJlYXJlciAiLCA3KSkgewogICAgICAgICAgZS0+
c2NoZW1lID0gImJlYXJlciI7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xlbiA9
PSAxMSAmJiAhc3RybmNhc2VjbXAocCwgInRyYWNlcGFyZW50IiwgMTEpKSB7CiAgICAgICAgZS0+
dHJhY2VwYXJlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgICAgZS0+dHJhY2Vf
aWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVudChlLT50cmFjZXBhcmVudCk7CiAgICAgIH0gZWxzZSBp
ZiAoaG5hbWVfbGVuID09IDQgJiYgIXN0cm5jYXNlY21wKHAsICJob3N0IiwgNCkpIHsKICAgICAg
ICBlLT5ob3N0X2hkci5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlm
IChobmFtZV9sZW4gPT0gMTAgJiYgIXN0cm5jYXNlY21wKHAsICJ1c2VyLWFnZW50IiwgMTApKSB7
CiAgICAgICAgZS0+dXNlcl9hZ2VudC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAg
fSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTUgJiYgIXN0cm5jYXNlY21wKHAsICJ4LWZvcndhcmRl
ZC1mb3IiLCAxNSkpIHsKICAgICAgICBlLT54ZmYuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7
CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFtZV9sZW4gPT0gMTIgJiYgIXN0cm5jYXNlY21w
KHAsICJjb250ZW50LXR5cGUiLCAxMikpIHsKICAgICAgICBtZXRhLT5jb250ZW50X3R5cGUuYXNz
aWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFtZV9s
ZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewogICAg
ICAgIHNpemVfdCBjbGVuX3ZhbCA9IDA7CiAgICAgICAgaWYgKHBhcnNlX2RlY2ltYWxfc2l6ZSh2
YWxfc3RhcnQsIHZhbF9sZW4sICZjbGVuX3ZhbCkpIHsKICAgICAgICAgIGlmIChtZXRhLT5oYXNf
Y29udGVudF9sZW5ndGggJiYgbWV0YS0+Y29udGVudF9sZW5ndGggIT0gY2xlbl92YWwpIHsKICAg
ICAgICAgICAgbWV0YS0+aGFzX2NvbmZsaWN0X2NsID0gdHJ1ZTsKICAgICAgICAgIH0KICAgICAg
ICAgIG1ldGEtPmNvbnRlbnRfbGVuZ3RoID0gY2xlbl92YWw7CiAgICAgICAgICBtZXRhLT5oYXNf
Y29udGVudF9sZW5ndGggPSB0cnVlOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBtZXRhLT5o
YXNfY29uZmxpY3RfY2wgPSB0cnVlOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChtZXRhICYm
IGhuYW1lX2xlbiA9PSAxNyAmJiAhc3RybmNhc2VjbXAocCwgInRyYW5zZmVyLWVuY29kaW5nIiwg
MTcpKSB7CiAgICAgICAgbWV0YS0+dHJhbnNmZXJfZW5jb2RpbmcuYXNzaWduKHZhbF9zdGFydCwg
dmFsX2xlbik7CiAgICAgIH0KICAgIH0KICAgIHAgPSBsaW5lX2VuZCArIDE7CiAgfQoKCgogIGlm
IChlLT51c2VyLmVtcHR5KCkpIGUtPnVzZXIgPSAiLWFub255bW91cy0iOwogIGlmIChlLT5zY2hl
bWUuZW1wdHkoKSkgZS0+c2NoZW1lID0gIm5vbmUiOwogIGlmIChlLT50cmFjZV9pZC5lbXB0eSgp
KSBlLT50cmFjZXBhcmVudCA9IG1ha2VfdHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lkKTsKICByZXR1
cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgaXNfd3NzZV9uYW1lc3BhY2UoY29uc3Qgc3RkOjpzdHJp
bmcgJnVyaSkgewogIHJldHVybiB1cmkgPT0gImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dz
cy8yMDA0LzAxL29hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIgfHwK
ICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3L3Nl
Y2V4dCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8y
MDAyLzEyL3NlY2V4dCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2Fw
Lm9yZy93cy8yMDAzLzA2L3NlY2V4dCI7Cn0KCnN0YXRpYyBib29sIGlzX3NvYXBfY29udGVudF90
eXBlKGNvbnN0IHN0ZDo6c3RyaW5nICZjdCkgewogIHN0ZDo6c3RyaW5nIHggPSBsb3dlcihjdCk7
CiAgcmV0dXJuIHguZmluZCgidGV4dC94bWwiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAg
ICAgICB4LmZpbmQoImFwcGxpY2F0aW9uL3NvYXAreG1sIikgIT0gc3RkOjpzdHJpbmc6Om5wb3Mg
fHwKICAgICAgICAgeC5maW5kKCIreG1sIikgIT0gc3RkOjpzdHJpbmc6Om5wb3M7Cn0KCnN0YXRp
YyB2b2lkIHNwbGl0X3FuYW1lKGNvbnN0IHN0ZDo6c3RyaW5nICZxbmFtZSwgc3RkOjpzdHJpbmcg
KnByZWZpeCwgc3RkOjpzdHJpbmcgKmxvY2FsKSB7CiAgc2l6ZV90IHAgPSBxbmFtZS5maW5kKCc6
Jyk7CiAgaWYgKHAgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsgcHJlZml4LT5jbGVhcigpOyAqbG9j
YWwgPSBxbmFtZTsgfQogIGVsc2UgeyAqcHJlZml4ID0gcW5hbWUuc3Vic3RyKDAsIHApOyAqbG9j
YWwgPSBxbmFtZS5zdWJzdHIocCArIDEpOyB9Cn0KCnN0YXRpYyBib29sIHhtbF91bmVzY2FwZShj
b25zdCBzdGQ6OnN0cmluZyAmaW4sIHN0ZDo6c3RyaW5nICpvdXQpIHsKICBvdXQtPmNsZWFyKCk7
CiAgb3V0LT5yZXNlcnZlKGluLnNpemUoKSk7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBpbi5z
aXplKCk7ICsraSkgewogICAgaWYgKGluW2ldICE9ICcmJykgeyBvdXQtPnB1c2hfYmFjayhpbltp
XSk7IGNvbnRpbnVlOyB9CiAgICBzaXplX3Qgc2VtaSA9IGluLmZpbmQoJzsnLCBpICsgMSk7CiAg
ICBpZiAoc2VtaSA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIGZhbHNlOwogICAgc3RkOjpz
dHJpbmcgcmVmID0gaW4uc3Vic3RyKGkgKyAxLCBzZW1pIC0gaSAtIDEpOwogICAgaWYgKHJlZiA9
PSAiYW1wIikgb3V0LT5wdXNoX2JhY2soJyYnKTsKICAgIGVsc2UgaWYgKHJlZiA9PSAibHQiKSBv
dXQtPnB1c2hfYmFjaygnPCcpOwogICAgZWxzZSBpZiAocmVmID09ICJndCIpIG91dC0+cHVzaF9i
YWNrKCc+Jyk7CiAgICBlbHNlIGlmIChyZWYgPT0gInF1b3QiKSBvdXQtPnB1c2hfYmFjaygnIicp
OwogICAgZWxzZSBpZiAocmVmID09ICJhcG9zIikgb3V0LT5wdXNoX2JhY2soJ1wnJyk7CiAgICBl
bHNlIGlmICghcmVmLmVtcHR5KCkgJiYgcmVmWzBdID09ICcjJykgewogICAgICB1bnNpZ25lZCBs
b25nIHZhbCA9IDA7CiAgICAgIGNoYXIgKmVuZHAgPSBOVUxMOwogICAgICBpZiAocmVmLnNpemUo
KSA+IDIgJiYgKHJlZlsxXSA9PSAneCcgfHwgcmVmWzFdID09ICdYJykpIHsKICAgICAgICB2YWwg
PSBzdHJ0b3VsKHJlZi5jX3N0cigpICsgMiwgJmVuZHAsIDE2KTsKICAgICAgfSBlbHNlIHsKICAg
ICAgICB2YWwgPSBzdHJ0b3VsKHJlZi5jX3N0cigpICsgMSwgJmVuZHAsIDEwKTsKICAgICAgfQog
ICAgICBpZiAoIWVuZHAgfHwgKmVuZHAgIT0gJ1wwJyB8fCB2YWwgPiAweDEwZmZmZlVMKSByZXR1
cm4gZmFsc2U7CiAgICAgIGlmICh2YWwgPCAweDgwKSB7CiAgICAgICAgb3V0LT5wdXNoX2JhY2so
KGNoYXIpdmFsKTsKICAgICAgfSBlbHNlIGlmICh2YWwgPCAweDgwMCkgewogICAgICAgIG91dC0+
cHVzaF9iYWNrKChjaGFyKSgweGMwIHwgKHZhbCA+PiA2KSkpOwogICAgICAgIG91dC0+cHVzaF9i
YWNrKChjaGFyKSgweDgwIHwgKHZhbCAmIDB4M2YpKSk7CiAgICAgIH0gZWxzZSBpZiAodmFsIDwg
MHgxMDAwMCkgewogICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGUwIHwgKHZhbCA+PiAx
MikpKTsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgodmFsID4+IDYpICYg
MHgzZikpKTsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICh2YWwgJiAweDNm
KSkpOwogICAgICB9IGVsc2UgewogICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGYwIHwg
KHZhbCA+PiAxOCkpKTsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgodmFs
ID4+IDEyKSAmIDB4M2YpKSk7CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAo
KHZhbCA+PiA2KSAmIDB4M2YpKSk7CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAg
fCAodmFsICYgMHgzZikpKTsKICAgICAgfQogICAgfSBlbHNlIHsKICAgICAgcmV0dXJuIGZhbHNl
OwogICAgfQogICAgaSA9IHNlbWk7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCB2
YWxpZF91dGY4X3VzZXJuYW1lKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgaWYgKHMuZW1wdHko
KSB8fCBzLnNpemUoKSA+IE1BWF9XU1NFX1VTRVJOQU1FICogNCkgcmV0dXJuIGZhbHNlOwogIHNp
emVfdCBjaGFyYWN0ZXJzID0gMDsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOykg
ewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIHVuc2lnbmVk
IGxvbmcgY3AgPSAwOwogICAgc2l6ZV90IG5lZWQgPSAwOwogICAgaWYgKGMgPCAweDgwKSB7IGNw
ID0gYzsgbmVlZCA9IDA7ICsraTsgfQogICAgZWxzZSBpZiAoKGMgJiAweGUwKSA9PSAweGMwKSB7
IG5lZWQgPSAxOyB9CiAgICBlbHNlIGlmICgoYyAmIDB4ZjApID09IDB4ZTApIHsgbmVlZCA9IDI7
IH0KICAgIGVsc2UgaWYgKChjICYgMHhmOCkgPT0gMHhmMCkgeyBuZWVkID0gMzsgfQogICAgZWxz
ZSByZXR1cm4gZmFsc2U7CgogICAgaWYgKG5lZWQpIHsKICAgICAgaWYgKGkgKyBuZWVkID49IHMu
c2l6ZSgpKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChuZWVkID09IDEgJiYgYyA8IDB4YzIpIHJl
dHVybiBmYWxzZTsKICAgICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4ZTAgJiYgKHVuc2lnbmVk
IGNoYXIpc1tpICsgMV0gPCAweGEwKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChuZWVkID09IDIg
JiYgYyA9PSAweGVkICYmICh1bnNpZ25lZCBjaGFyKXNbaSArIDFdID49IDB4YTApIHJldHVybiBm
YWxzZTsKICAgICAgaWYgKG5lZWQgPT0gMyAmJiBjID09IDB4ZjAgJiYgKHVuc2lnbmVkIGNoYXIp
c1tpICsgMV0gPCAweDkwKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChuZWVkID09IDMgJiYgYyA9
PSAweGY0ICYmICh1bnNpZ25lZCBjaGFyKXNbaSArIDFdID49IDB4OTApIHJldHVybiBmYWxzZTsK
ICAgICAgY3AgPSBjICYgKCgxVSA8PCAoNyAtIG5lZWQgLSAxKSkgLSAxKTsKICAgICAgZm9yIChz
aXplX3QgaiA9IDE7IGogPD0gbmVlZDsgKytqKSBjcCA9IChjcCA8PCA2KSB8ICgodW5zaWduZWQg
Y2hhcilzW2kgKyBqXSAmIDB4M2YpOwogICAgICBpICs9IG5lZWQgKyAxOwogICAgfQogICAgaWYg
KCsrY2hhcmFjdGVycyA+IE1BWF9XU1NFX1VTRVJOQU1FKSByZXR1cm4gZmFsc2U7CiAgICBpZiAo
Y3AgPCAweDIwIHx8IChjcCA+PSAweDdmICYmIGNwIDw9IDB4OWYpIHx8CiAgICAgICAgKGNwID49
IDB4ZTAwMCAmJiBjcCA8PSAweGY4ZmYpIHx8CiAgICAgICAgKGNwID49IDB4ZjAwMDAgJiYgY3Ag
PD0gMHhmZmZmZCkgfHwKICAgICAgICAoY3AgPj0gMHgxMDAwMDAgJiYgY3AgPD0gMHgxMGZmZmQp
IHx8CiAgICAgICAgKGNwID49IDB4ZmRkMCAmJiBjcCA8PSAweGZkZWYpIHx8IChjcCAmIDB4ZmZm
ZlVMKSA+PSAweGZmZmVVTCB8fAogICAgICAgIGNwID09IDB4MDBhZCB8fCBjcCA9PSAweDA2MWMg
fHwgY3AgPT0gMHgwNmRkIHx8IGNwID09IDB4MDcwZiB8fAogICAgICAgIGNwID09IDB4MTgwZSB8
fCAoY3AgPj0gMHgyMDBiICYmIGNwIDw9IDB4MjAwZikgfHwKICAgICAgICAoY3AgPj0gMHgyMDJh
ICYmIGNwIDw9IDB4MjAyZSkgfHwgKGNwID49IDB4MjA2MCAmJiBjcCA8PSAweDIwNmYpIHx8CiAg
ICAgICAgY3AgPT0gMHhmZWZmKSByZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9Cgpz
dHJ1Y3QgWG1sRnJhbWUgewogIHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz4gbnM7
CiAgc3RkOjpzdHJpbmcgcW5hbWUsIHVyaSwgbG9jYWw7Cn07CgpzdGF0aWMgYm9vbCBwYXJzZV94
bWxfbmFtZShjb25zdCBzdGQ6OnN0cmluZyAmYm9keSwgc2l6ZV90IGxpbWl0LCBzaXplX3QgKnBv
cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjpzdHJpbmcgKm5hbWUpIHsKICBzaXpl
X3Qgc3RhcnQgPSAqcG9zOwogIHdoaWxlICgqcG9zIDwgbGltaXQpIHsKICAgIHVuc2lnbmVkIGNo
YXIgYyA9ICh1bnNpZ25lZCBjaGFyKWJvZHlbKnBvc107CiAgICBpZiAoIShpc2FsbnVtKGMpIHx8
IGMgPT0gJ18nIHx8IGMgPT0gJy0nIHx8IGMgPT0gJy4nIHx8IGMgPT0gJzonKSkgYnJlYWs7CiAg
ICArKypwb3M7CiAgfQogIGlmICgqcG9zID09IHN0YXJ0IHx8ICpwb3MgLSBzdGFydCA+IDI1Nikg
cmV0dXJuIGZhbHNlOwogIG5hbWUtPmFzc2lnbihib2R5LCBzdGFydCwgKnBvcyAtIHN0YXJ0KTsK
ICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIGV4dHJhY3Rfd3NzZV91c2VybmFt
ZShjb25zdCBzdGQ6OnN0cmluZyAmYm9keSkgewogIGlmIChib2R5LmVtcHR5KCkgfHwgYm9keS5z
aXplKCkgPiBNQVhfV1NTRV9CT0RZX0JZVEVTIHx8CiAgICAgIGJvZHkuZmluZCgnXDAnKSAhPSBz
dGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuICIiOwogIHN0ZDo6c3RyaW5nIGxvd2VyZWQgPSBsb3dl
cihib2R5KTsKICBpZiAobG93ZXJlZC5maW5kKCI8IWRvY3R5cGUiKSAhPSBzdGQ6OnN0cmluZzo6
bnBvcyB8fAogICAgICBsb3dlcmVkLmZpbmQoIjwhZW50aXR5IikgIT0gc3RkOjpzdHJpbmc6Om5w
b3MpIHJldHVybiAiIjsKCiAgc3RkOjp2ZWN0b3I8WG1sRnJhbWU+IHN0YWNrOwogIHNpemVfdCB0
b2tlbl9kZXB0aCA9IDAsIHVzZXJuYW1lX2RlcHRoID0gMCwgcG9zID0gMDsKICBzdGQ6OnN0cmlu
ZyB0b2tlbl91cmksIGNoYXJzLCByZXN1bHQ7CiAgYm9vbCB1c2VybmFtZV9iYWQgPSBmYWxzZTsK
ICB3aGlsZSAocG9zIDwgYm9keS5zaXplKCkpIHsKICAgIHNpemVfdCBsdCA9IGJvZHkuZmluZCgn
PCcsIHBvcyk7CiAgICBpZiAobHQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgaWYgKHVz
ZXJuYW1lX2RlcHRoICYmICF1c2VybmFtZV9iYWQgJiYgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0
cihwb3MpLCAmY2hhcnMpKSB1c2VybmFtZV9iYWQgPSB0cnVlOwogICAgICBicmVhazsKICAgIH0K
ICAgIGlmICh1c2VybmFtZV9kZXB0aCAmJiAhdXNlcm5hbWVfYmFkICYmIGx0ID4gcG9zICYmCiAg
ICAgICAgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cihwb3MsIGx0IC0gcG9zKSwgJmNoYXJzKSkg
dXNlcm5hbWVfYmFkID0gdHJ1ZTsKICAgIGlmIChjaGFycy5zaXplKCkgPiBNQVhfV1NTRV9VU0VS
TkFNRSAqIDQgKyAyKSB7IGNoYXJzLmNsZWFyKCk7IHVzZXJuYW1lX2JhZCA9IHRydWU7IH0KCiAg
ICBpZiAoYm9keS5jb21wYXJlKGx0LCA0LCAiPCEtLSIpID09IDApIHsKICAgICAgc2l6ZV90IGVu
ZCA9IGJvZHkuZmluZCgiLS0+IiwgbHQgKyA0KTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBv
cykgYnJlYWs7CiAgICAgIHBvcyA9IGVuZCArIDM7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJv
ZHkuY29tcGFyZShsdCwgOSwgIjwhW0NEQVRBWyIpID09IDApIHsKICAgICAgc2l6ZV90IGVuZCA9
IGJvZHkuZmluZCgiXV0+IiwgbHQgKyA5KTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykg
YnJlYWs7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCAmJiAhdXNlcm5hbWVfYmFkKSBjaGFycy5h
cHBlbmQoYm9keSwgbHQgKyA5LCBlbmQgLSBsdCAtIDkpOwogICAgICBwb3MgPSBlbmQgKyAzOyBj
b250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDIsICI8PyIpID09IDApIHsK
ICAgICAgc2l6ZV90IGVuZCA9IGJvZHkuZmluZCgiPz4iLCBsdCArIDIpOyBpZiAoZW5kID09IHN0
ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAgICAgcG9zID0gZW5kICsgMjsgY29udGludWU7CiAg
ICB9CiAgICBpZiAoYm9keS5jb21wYXJlKGx0LCAyLCAiPCEiKSA9PSAwKSByZXR1cm4gIiI7Cgog
ICAgYm9vbCBjbG9zaW5nID0gKGx0ICsgMSA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbbHQgKyAxXSA9
PSAnLycpOwogICAgc2l6ZV90IHAgPSBsdCArIChjbG9zaW5nID8gMiA6IDEpOwogICAgc3RkOjpz
dHJpbmcgcW5hbWU7CiAgICBpZiAoIXBhcnNlX3htbF9uYW1lKGJvZHksIGJvZHkuc2l6ZSgpLCAm
cCwgJnFuYW1lKSkgYnJlYWs7CiAgICBpZiAoY2xvc2luZykgewogICAgICB3aGlsZSAocCA8IGJv
ZHkuc2l6ZSgpICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAg
aWYgKHAgPj0gYm9keS5zaXplKCkgfHwgYm9keVtwXSAhPSAnPicpIGJyZWFrOwogICAgICBpZiAo
c3RhY2suZW1wdHkoKSkgYnJlYWs7CiAgICAgIHN0ZDo6c3RyaW5nIHByZWZpeCwgbG9jYWw7IHNw
bGl0X3FuYW1lKHFuYW1lLCAmcHJlZml4LCAmbG9jYWwpOwogICAgICBYbWxGcmFtZSAmdG9wID0g
c3RhY2suYmFjaygpOwogICAgICBpZiAodG9wLnFuYW1lICE9IHFuYW1lIHx8IHRvcC5sb2NhbCAh
PSBsb2NhbCkgYnJlYWs7CiAgICAgIHNpemVfdCBkZXB0aCA9IHN0YWNrLnNpemUoKTsKICAgICAg
aWYgKHVzZXJuYW1lX2RlcHRoID09IGRlcHRoKSB7CiAgICAgICAgc3RkOjpzdHJpbmcgdXNlcm5h
bWUgPSB0cmltKGNoYXJzKTsKICAgICAgICBpZiAoIXVzZXJuYW1lX2JhZCAmJiB2YWxpZF91dGY4
X3VzZXJuYW1lKHVzZXJuYW1lKSAmJiByZXN1bHQuZW1wdHkoKSkgcmVzdWx0ID0gdXNlcm5hbWU7
CiAgICAgICAgdXNlcm5hbWVfZGVwdGggPSAwOyBjaGFycy5jbGVhcigpOyB1c2VybmFtZV9iYWQg
PSBmYWxzZTsKICAgICAgfQogICAgICBpZiAodG9rZW5fZGVwdGggPT0gZGVwdGgpIHsgdG9rZW5f
ZGVwdGggPSAwOyB0b2tlbl91cmkuY2xlYXIoKTsgfQogICAgICBzdGFjay5wb3BfYmFjaygpOyBw
b3MgPSBwICsgMTsKICAgICAgaWYgKCFyZXN1bHQuZW1wdHkoKSkgcmV0dXJuIHJlc3VsdDsKICAg
ICAgY29udGludWU7CiAgICB9CgogICAgWG1sRnJhbWUgZnJhbWU7CiAgICBpZiAoc3RhY2suc2l6
ZSgpID49IDY0KSByZXR1cm4gIiI7CiAgICBpZiAoIXN0YWNrLmVtcHR5KCkpIGZyYW1lLm5zID0g
c3RhY2suYmFjaygpLm5zOwogICAgYm9vbCBzZWxmX2Nsb3NpbmcgPSBmYWxzZSwgY29tcGxldGUg
PSBmYWxzZTsKICAgIHNpemVfdCBhdHRyX2NvdW50ID0gMDsKICAgIHdoaWxlIChwIDwgYm9keS5z
aXplKCkpIHsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNpZ25l
ZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpKSBicmVhazsK
ICAgICAgaWYgKGJvZHlbcF0gPT0gJz4nKSB7ICsrcDsgY29tcGxldGUgPSB0cnVlOyBicmVhazsg
fQogICAgICBpZiAoYm9keVtwXSA9PSAnLycgJiYgcCArIDEgPCBib2R5LnNpemUoKSAmJiBib2R5
W3AgKyAxXSA9PSAnPicpIHsKICAgICAgICBwICs9IDI7IHNlbGZfY2xvc2luZyA9IHRydWU7IGNv
bXBsZXRlID0gdHJ1ZTsgYnJlYWs7CiAgICAgIH0KICAgICAgc3RkOjpzdHJpbmcgYW5hbWU7CiAg
ICAgIGlmICghcGFyc2VfeG1sX25hbWUoYm9keSwgYm9keS5zaXplKCksICZwLCAmYW5hbWUpKSBi
cmVhazsKICAgICAgaWYgKCsrYXR0cl9jb3VudCA+IDEyOCkgcmV0dXJuICIiOwogICAgICB3aGls
ZSAocCA8IGJvZHkuc2l6ZSgpICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsr
cDsKICAgICAgaWYgKHAgPj0gYm9keS5zaXplKCkgfHwgYm9keVtwKytdICE9ICc9JykgYnJlYWs7
CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcili
b2R5W3BdKSkgKytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSB8fCAoYm9keVtwXSAhPSAn
XCcnICYmIGJvZHlbcF0gIT0gJyInKSkgYnJlYWs7CiAgICAgIGNoYXIgcXVvdGUgPSBib2R5W3Ar
K107IHNpemVfdCB2YWx1ZV9zdGFydCA9IHA7CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkg
JiYgYm9keVtwXSAhPSBxdW90ZSkgKytwOwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSkgYnJl
YWs7CiAgICAgIHN0ZDo6c3RyaW5nIHZhbHVlOwogICAgICBpZiAoIXhtbF91bmVzY2FwZShib2R5
LnN1YnN0cih2YWx1ZV9zdGFydCwgcCAtIHZhbHVlX3N0YXJ0KSwgJnZhbHVlKSkgcmV0dXJuICIi
OwogICAgICArK3A7CiAgICAgIGlmIChhbmFtZSA9PSAieG1sbnMiKSBmcmFtZS5uc1siIl0gPSB2
YWx1ZTsKICAgICAgZWxzZSBpZiAoYW5hbWUuY29tcGFyZSgwLCA2LCAieG1sbnM6IikgPT0gMCkg
ZnJhbWUubnNbYW5hbWUuc3Vic3RyKDYpXSA9IHZhbHVlOwogICAgICBpZiAoZnJhbWUubnMuc2l6
ZSgpID4gNjQpIHJldHVybiAiIjsKICAgIH0KICAgIGlmICghY29tcGxldGUpIGJyZWFrOwogICAg
c3RkOjpzdHJpbmcgcHJlZml4LCBsb2NhbDsgc3BsaXRfcW5hbWUocW5hbWUsICZwcmVmaXgsICZs
b2NhbCk7CiAgICBzdGQ6Om1hcDxzdGQ6OnN0cmluZywgc3RkOjpzdHJpbmc+Ojpjb25zdF9pdGVy
YXRvciBucyA9IGZyYW1lLm5zLmZpbmQocHJlZml4KTsKICAgIGZyYW1lLnVyaSA9IChucyA9PSBm
cmFtZS5ucy5lbmQoKSkgPyAiIiA6IG5zLT5zZWNvbmQ7CiAgICBmcmFtZS5xbmFtZSA9IHFuYW1l
OwogICAgZnJhbWUubG9jYWwgPSBsb2NhbDsKICAgIHN0YWNrLnB1c2hfYmFjayhmcmFtZSk7CiAg
ICBzaXplX3QgZGVwdGggPSBzdGFjay5zaXplKCk7CiAgICBpZiAoIXRva2VuX2RlcHRoICYmIGxv
Y2FsID09ICJVc2VybmFtZVRva2VuIiAmJiBpc193c3NlX25hbWVzcGFjZShmcmFtZS51cmkpKSB7
CiAgICAgIHRva2VuX2RlcHRoID0gZGVwdGg7IHRva2VuX3VyaSA9IGZyYW1lLnVyaTsKICAgIH0g
ZWxzZSBpZiAodG9rZW5fZGVwdGggJiYgZGVwdGggPT0gdG9rZW5fZGVwdGggKyAxICYmCiAgICAg
ICAgICAgICAgIGxvY2FsID09ICJVc2VybmFtZSIgJiYgZnJhbWUudXJpID09IHRva2VuX3VyaSkg
ewogICAgICB1c2VybmFtZV9kZXB0aCA9IGRlcHRoOyBjaGFycy5jbGVhcigpOyB1c2VybmFtZV9i
YWQgPSBmYWxzZTsKICAgIH0KICAgIGlmIChzZWxmX2Nsb3NpbmcpIHsKICAgICAgaWYgKHVzZXJu
YW1lX2RlcHRoID09IGRlcHRoKSB1c2VybmFtZV9kZXB0aCA9IDA7CiAgICAgIGlmICh0b2tlbl9k
ZXB0aCA9PSBkZXB0aCkgeyB0b2tlbl9kZXB0aCA9IDA7IHRva2VuX3VyaS5jbGVhcigpOyB9CiAg
ICAgIHN0YWNrLnBvcF9iYWNrKCk7CiAgICB9CiAgICBwb3MgPSBwOwogIH0KICByZXR1cm4gcmVz
dWx0Owp9CgpzdGF0aWMgYm9vbCBwYXJzZV9yZXNwb25zZShjb25zdCBjaGFyICpkYXRhLCBzaXpl
X3QgbGVuLCBpbnQgKnN0YXR1cywgc2l6ZV90ICpjbGVuLAogICAgICAgICAgICAgICAgICAgICAg
ICAgICBib29sICpoYXNfY2xlbiwgYm9vbCAqaXNfY2h1bmtlZCwgYm9vbCAqaXNfY2xvc2UpIHsK
ICAqaGFzX2NsZW4gPSBmYWxzZTsKICAqY2xlbiA9IDA7CiAgKmlzX2NodW5rZWQgPSBmYWxzZTsK
ICAqaXNfY2xvc2UgPSBmYWxzZTsKICBjb25zdCBjaGFyICplbmQgPSBkYXRhICsgbGVuOwogIGNv
bnN0IGNoYXIgKnAgPSBkYXRhOwogIGNvbnN0IGNoYXIgKmVvbCA9IChjb25zdCBjaGFyICopbWVt
Y2hyKHAsICdcbicsIGVuZCAtIHApOwogIGlmICghZW9sKSByZXR1cm4gZmFsc2U7CiAgaWYgKHN0
cm5jbXAocCwgIkhUVFAvIiwgNSkgIT0gMCkgcmV0dXJuIGZhbHNlOwogIGJvb2wgaXNfaHR0cF8x
MCA9IChlb2wgLSBwID49IDggJiYgc3RybmNtcChwLCAiSFRUUC8xLjAiLCA4KSA9PSAwKTsKICBi
b29sIGNvbm5fY2xvc2UgPSBmYWxzZTsKICBib29sIGNvbm5fa2VlcF9hbGl2ZSA9IGZhbHNlOwoK
ICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHAp
OwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEg
KyAxOwogIHdoaWxlIChzY19zdGFydCA8IGVvbCAmJiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0
YXJ0OwogICpzdGF0dXMgPSBhdG9pKHNjX3N0YXJ0KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAq
c3RhdHVzID4gNTk5KSByZXR1cm4gZmFsc2U7CiAgcCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBl
bmQpIHsKICAgIGlmICgqcCA9PSAnXHInIHx8ICpwID09ICdcbicpIGJyZWFrOwogICAgY29uc3Qg
Y2hhciAqbGluZV9lbmQgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsK
ICAgIGlmICghbGluZV9lbmQpIGxpbmVfZW5kID0gZW5kOwogICAgY29uc3QgY2hhciAqY29sb24g
PSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnOicsIGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29s
b24pIHsKICAgICAgc2l6ZV90IGhsZW4gPSBjb2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnYg
PSBjb2xvbiArIDE7CiAgICAgIHdoaWxlICh2IDwgbGluZV9lbmQgJiYgKCp2ID09ICcgJyB8fCAq
diA9PSAnXHQnKSkgKyt2OwogICAgICBjb25zdCBjaGFyICp2ZSA9IGxpbmVfZW5kOwogICAgICB3
aGlsZSAodmUgPiB2ICYmICh2ZVstMV0gPT0gJ1xyJyB8fCB2ZVstMV0gPT0gJ1xuJyB8fCB2ZVst
MV0gPT0gJyAnIHx8IHZlWy0xXSA9PSAnXHQnKSkgLS12ZTsKICAgICAgc2l6ZV90IHZsZW4gPSAo
c2l6ZV90KSh2ZSAtIHYpOwoKICAgICAgaWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAs
ICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewogICAgICAgIHNpemVfdCBuID0gMDsKICAgICAgICBp
ZiAocGFyc2VfZGVjaW1hbF9zaXplKHYsIHZsZW4sICZuKSkgewogICAgICAgICAgaWYgKCpoYXNf
Y2xlbiAmJiAqY2xlbiAhPSBuKSB7CiAgICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICAg
IH0KICAgICAgICAgICpjbGVuID0gbjsKICAgICAgICAgICpoYXNfY2xlbiA9IHRydWU7CiAgICAg
ICAgfSBlbHNlIHsKICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgIH0gZWxz
ZSBpZiAoaGxlbiA9PSAxNyAmJiAhc3RybmNhc2VjbXAocCwgInRyYW5zZmVyLWVuY29kaW5nIiwg
MTcpKSB7CiAgICAgICAgc3RkOjpzdHJpbmcgdGUodiwgdmxlbik7CiAgICAgICAgaWYgKGxvd2Vy
KHRlKS5maW5kKCJjaHVua2VkIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICpp
c19jaHVua2VkID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAoaGxlbiA9PSAxMCAm
JiAhc3RybmNhc2VjbXAocCwgImNvbm5lY3Rpb24iLCAxMCkpIHsKICAgICAgICBzdGQ6OnN0cmlu
ZyBjb25uKHYsIHZsZW4pOwogICAgICAgIGlmIChsb3dlcihjb25uKS5maW5kKCJjbG9zZSIpICE9
IHN0ZDo6c3RyaW5nOjpucG9zKSB7CiAgICAgICAgICBjb25uX2Nsb3NlID0gdHJ1ZTsKICAgICAg
ICB9IGVsc2UgaWYgKGxvd2VyKGNvbm4pLmZpbmQoImtlZXAtYWxpdmUiKSAhPSBzdGQ6OnN0cmlu
Zzo6bnBvcykgewogICAgICAgICAgY29ubl9rZWVwX2FsaXZlID0gdHJ1ZTsKICAgICAgICB9CiAg
ICAgIH0KICAgIH0KICAgIHAgPSBsaW5lX2VuZCArIDE7CiAgfQogIGlmICgqaGFzX2NsZW4gJiYg
KmlzX2NodW5rZWQpIHJldHVybiBmYWxzZTsKICBpZiAoaXNfaHR0cF8xMCAmJiAhY29ubl9rZWVw
X2FsaXZlKSB7CiAgICAqaXNfY2xvc2UgPSB0cnVlOwogIH0gZWxzZSBpZiAoY29ubl9jbG9zZSkg
ewogICAgKmlzX2Nsb3NlID0gdHJ1ZTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6
OnN0cmluZyBnX2VuZHBvaW50OwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRp
YyB1bnNpZ25lZCBnX3NoaXBfcmF0ZV9rYnBzID0gREVGQVVMVF9TSElQX1JBVEVfS0JQUzsKc3Rh
dGljIHVuc2lnbmVkIGdfc3RhdHNfaW50ZXJ2YWxfc2VjID0gMzA7CnN0YXRpYyBzaXplX3QgZ193
c3NlX2JvZHlfYnl0ZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfY2FwdHVyZV9w
YWNrZXRzID0gMCwgZ19jYXB0dXJlX2J5dGVzID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9u
ZyBnX2tlcm5lbF9kcm9wcyA9IDAsIGdfaW52YWxpZF9mcmFtZXMgPSAwOwpzdGF0aWMgdW5zaWdu
ZWQgbG9uZyBsb25nIGdfZXZlbnRzX2VtaXR0ZWQgPSAwLCBnX2V2ZW50c19pbiA9IDA7CnN0YXRp
YyB1bnNpZ25lZCBsb25nIGxvbmcgZ19ldmVudHNfcHVzaGVkID0gMCwgZ19ldmVudHNfZHJvcHBl
ZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19kcm9wX3F1ZXVlID0gMCwgZ19kcm9w
X2h1YiA9IDAsIGdfZHJvcF9vdmVyc2l6ZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25n
IGdfYmF0Y2hlc19wdXNoZWQgPSAwLCBnX2JhdGNoZXNfZmFpbGVkID0gMDsKc3RhdGljIHVuc2ln
bmVkIGxvbmcgbG9uZyBnX2J5dGVzX3B1c2hlZCA9IDAsIGdfc3RhdHNfZHJvcHBlZCA9IDA7CnN0
YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19vdXRwdXRfcGlwZV9kcm9wcyA9IDAsIGdfcHJldl9v
dXRwdXRfcGlwZV9kcm9wcyA9IDA7CnN0YXRpYyBzaXplX3QgZ19xdWV1ZV9oaWdoX3dhdGVyID0g
MDsKc3RhdGljIHVuc2lnbmVkIGdfY29uc2VjdXRpdmVfZmFpbHVyZXMgPSAwLCBnX2xhc3RfcHVz
aF9zdGF0dXMgPSAwOwpzdGF0aWMgdGltZV90IGdfbGFzdF9zdWNjZXNzX2F0ID0gMDsKc3RhdGlj
IGRvdWJsZSBnX3N0YXRzX2xhc3RfYXQgPSAwLjAsIGdfc3RhdHNfbGFzdF9jcHUgPSAwLjA7CnN0
YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X2NhcHR1cmVfcGFja2V0cyA9IDAsIGdfcHJl
dl9jYXB0dXJlX2J5dGVzID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfZXZl
bnRzX2VtaXR0ZWQgPSAwLCBnX3ByZXZfZXZlbnRzX2luID0gMDsKc3RhdGljIHVuc2lnbmVkIGxv
bmcgbG9uZyBnX3ByZXZfZXZlbnRzX3B1c2hlZCA9IDAsIGdfcHJldl9ldmVudHNfZHJvcHBlZCA9
IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X2JhdGNoZXNfcHVzaGVkID0gMCwg
Z19wcmV2X2JhdGNoZXNfZmFpbGVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3By
ZXZfYnl0ZXNfcHVzaGVkID0gMCwgZ19wcmV2X2Ryb3BfcXVldWUgPSAwOwpzdGF0aWMgdW5zaWdu
ZWQgbG9uZyBsb25nIGdfcHJldl9kcm9wX2h1YiA9IDAsIGdfcHJldl9kcm9wX292ZXJzaXplZCA9
IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19zdGF0c19zZXF1ZW5jZSA9IDA7CnN0YXRp
YyBzdGQ6OnN0cmluZyBnX2luc3RhbmNlX2lkOwoKc3RhdGljIHB0aHJlYWRfdCBnX3NoaXBfd29y
a2VyX3RpZDsKc3RhdGljIHB0aHJlYWRfbXV0ZXhfdCBnX3NoaXBfcXVldWVfbXV0ZXggPSBQVEhS
RUFEX01VVEVYX0lOSVRJQUxJWkVSOwpzdGF0aWMgcHRocmVhZF9jb25kX3QgZ19zaGlwX3F1ZXVl
X2NvbmQgPSBQVEhSRUFEX0NPTkRfSU5JVElBTElaRVI7CnN0YXRpYyBzdGQ6OnZlY3RvcjxzdGQ6
OnN0cmluZz4gZ19zaGlwX2J1ZjsKc3RhdGljIGJvb2wgZ19zaGlwX3dvcmtlcl9hY3RpdmUgPSBm
YWxzZTsKc3RhdGljIGJvb2wgZ19wcm9kdWNlcl9maW5pc2hlZCA9IGZhbHNlOwpzdGF0aWMgc3Rk
OjpzdHJpbmcgZ19wZW5kaW5nX3N0YXRzX2JvZHk7CgpzdGF0aWMgc3RkOjpzdHJpbmcgc2hlbGxx
KGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICInIjsKICBmb3IgKHNp
emVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOyArK2kpIHsgaWYgKHNbaV0gPT0gJ1wnJykgbyArPSAi
J1xcJyciOyBlbHNlIG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIiciOwp9CnN0YXRpYyBzdGQ6
OnN0cmluZyBudW1iZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBv
IDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyB1bGxfc3RyaW5nKHVu
c2lnbmVkIGxvbmcgbG9uZyBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVy
biBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBkb3VibGVfc3RyaW5nKGRvdWJsZSBuKSB7
IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvLnNldGYoc3RkOjppb3M6OmZpeGVkKTsgby5wcmVjaXNp
b24oNCk7IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25f
YXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcg
byA9ICJbIjsgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBv
ICs9ICIsIjsgbyArPSBhW2ldOyB9IHJldHVybiBvICsgIl0iOwp9CnN0YXRpYyBkb3VibGUgd2Fs
bF9zZWNvbmRzKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2OwogIGdldHRpbWVvZmRheSgmdHYsIE5V
TEwpOwogIHJldHVybiAoZG91YmxlKXR2LnR2X3NlYyArIChkb3VibGUpdHYudHZfdXNlYyAvIDEw
MDAwMDAuMDsKfQpzdGF0aWMgdm9pZCBwYWNlX3VwbG9hZChzaXplX3QgYnl0ZXMsIGRvdWJsZSAq
bmV4dF9zbG90KSB7CiAgaWYgKCFnX3NoaXBfcmF0ZV9rYnBzKSByZXR1cm47CiAgZG91YmxlIGJ5
dGVzX3Blcl9zZWMgPSAoZG91YmxlKWdfc2hpcF9yYXRlX2ticHMgKiAxMDAwLjAgLyA4LjA7CiAg
ZG91YmxlIG5vdyA9IHdhbGxfc2Vjb25kcygpOwogIGlmICgqbmV4dF9zbG90IDwgbm93KSAqbmV4
dF9zbG90ID0gbm93OwogIGRvdWJsZSBzbG90ID0gKm5leHRfc2xvdDsKICAqbmV4dF9zbG90ICs9
IChkb3VibGUpYnl0ZXMgLyBieXRlc19wZXJfc2VjOwogIHdoaWxlIChzbG90ID4gKG5vdyA9IHdh
bGxfc2Vjb25kcygpKSkgewogICAgZG91YmxlIHJlbWFpbmluZyA9IHNsb3QgLSBub3c7CiAgICB1
c2Vjb25kc190IGRlbGF5ID0gKHVzZWNvbmRzX3QpKHJlbWFpbmluZyA+IDAuNSA/IDUwMDAwMCA6
IHJlbWFpbmluZyAqIDEwMDAwMDAuMCk7CiAgICBpZiAoZGVsYXkpIHVzbGVlcChkZWxheSk7CiAg
fQp9CnN0YXRpYyBzaXplX3QgYm91bmRlZF9iYXRjaF9jb3VudChjb25zdCBzdGQ6OnZlY3Rvcjxz
dGQ6OnN0cmluZz4gJmJ1ZiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0
IHN0ZDo6c3RyaW5nICZub2RlKSB7CiAgc2l6ZV90IHNpemUgPSBzdGQ6OnN0cmluZygie1wibm9k
ZVwiOiIpLnNpemUoKSArIGpzb25xKG5vZGUpLnNpemUoKSArCiAgICAgICAgICAgICAgICBzdGQ6
OnN0cmluZygiLFwiZXZlbnRzXCI6W119Iikuc2l6ZSgpOwogIHNpemVfdCBuID0gMCwgbGltaXQg
PSBidWYuc2l6ZSgpIDwgTUFYX0JBVENIID8gYnVmLnNpemUoKSA6IE1BWF9CQVRDSDsKICB3aGls
ZSAobiA8IGxpbWl0KSB7CiAgICBzaXplX3QgZXh0cmEgPSBidWZbbl0uc2l6ZSgpICsgKG4gPyAx
IDogMCk7CiAgICBpZiAoZXh0cmEgPiBNQVhfUE9TVF9CWVRFUyAtIHNpemUpIGJyZWFrOwogICAg
c2l6ZSArPSBleHRyYTsKICAgICsrbjsKICB9CiAgcmV0dXJuIG47Cn0KCnN0YXRpYyBib29sIHBv
c3RfYm9keShjb25zdCBzdGQ6OnN0cmluZyAmZW5kcG9pbnQsIGNvbnN0IHN0ZDo6c3RyaW5nICZw
YXRoLAogICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6c3RyaW5nICZib2R5LCB1bnNp
Z25lZCB0aW1lb3V0X3NlYywgZG91YmxlICpuZXh0X3Nsb3QpIHsKICBpZiAobmV4dF9zbG90KSBw
YWNlX3VwbG9hZChib2R5LnNpemUoKSwgbmV4dF9zbG90KTsKICBzdGQ6OnN0cmluZyBjbWQgPSAi
Y3VybCAtc1NmIC0tbWF4LXRpbWUgIiArIG51bWJlcl9zdHJpbmcodGltZW91dF9zZWMpICsgIiAt
LWxpbWl0LXJhdGUgIiArCiAgICBudW1iZXJfc3RyaW5nKChzaXplX3QpZ19zaGlwX3JhdGVfa2Jw
cyAqIDEwMDBVIC8gOFUpICsKICAgICIgLW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6IGFw
cGxpY2F0aW9uL2pzb24nIC0tZGF0YS1iaW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCArIHBh
dGgpOwogIEZJTEUgKmZwID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7IGlmICghZnApIHJldHVy
biBmYWxzZTsKICBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAgaW50
IHJjID0gcGNsb3NlKGZwKTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRVUyhy
YykgPT0gMDsKfQoKc3RhdGljIHZvaWQgKnNoaXBfd29ya2VyX3RocmVhZCh2b2lkICopIHsKICBk
b3VibGUgbmV4dF9zbG90ID0gd2FsbF9zZWNvbmRzKCk7CiAgZG91YmxlIG5leHRfc3RhdHNfc2xv
dCA9IHdhbGxfc2Vjb25kcygpOwogIGRvdWJsZSBzaHV0ZG93bl9kZWFkbGluZSA9IDAuMDsKICB3
aGlsZSAodHJ1ZSkgewogICAgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoOwogICAgc3Rk
OjpzdHJpbmcgc3RhdHNfYm9keTsKICAgIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVl
X211dGV4KTsKICAgIHdoaWxlIChnX3J1bm5pbmcgJiYgIWdfcHJvZHVjZXJfZmluaXNoZWQgJiYg
Z19zaGlwX2J1Zi5lbXB0eSgpICYmIGdfcGVuZGluZ19zdGF0c19ib2R5LmVtcHR5KCkpIHsKICAg
ICAgc3RydWN0IHRpbWVzcGVjIHRzOwogICAgICBjbG9ja19nZXR0aW1lKENMT0NLX1JFQUxUSU1F
LCAmdHMpOwogICAgICB0cy50dl9zZWMgKz0gMTsKICAgICAgcHRocmVhZF9jb25kX3RpbWVkd2Fp
dCgmZ19zaGlwX3F1ZXVlX2NvbmQsICZnX3NoaXBfcXVldWVfbXV0ZXgsICZ0cyk7CiAgICB9CiAg
ICBpZiAoIWdfcnVubmluZyAmJiBzaHV0ZG93bl9kZWFkbGluZSA9PSAwLjApIHsKICAgICAgc2h1
dGRvd25fZGVhZGxpbmUgPSB3YWxsX3NlY29uZHMoKSArIDEwLjA7CiAgICB9CiAgICBpZiAoZ19w
cm9kdWNlcl9maW5pc2hlZCAmJiBnX3NoaXBfYnVmLmVtcHR5KCkgJiYgZ19wZW5kaW5nX3N0YXRz
X2JvZHkuZW1wdHkoKSkgewogICAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVl
X211dGV4KTsKICAgICAgYnJlYWs7CiAgICB9CiAgICBpZiAoc2h1dGRvd25fZGVhZGxpbmUgPiAw
LjAgJiYgd2FsbF9zZWNvbmRzKCkgPiBzaHV0ZG93bl9kZWFkbGluZSkgewogICAgICBnX2V2ZW50
c19kcm9wcGVkICs9IGdfc2hpcF9idWYuc2l6ZSgpOwogICAgICBnX2Ryb3BfaHViICs9IGdfc2hp
cF9idWYuc2l6ZSgpOwogICAgICBnX3NoaXBfYnVmLmNsZWFyKCk7CiAgICAgIGdfcGVuZGluZ19z
dGF0c19ib2R5LmNsZWFyKCk7CiAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVl
dWVfbXV0ZXgpOwogICAgICBicmVhazsKICAgIH0KICAgIGlmICghZ19wZW5kaW5nX3N0YXRzX2Jv
ZHkuZW1wdHkoKSkgewogICAgICBzdGF0c19ib2R5LnN3YXAoZ19wZW5kaW5nX3N0YXRzX2JvZHkp
OwogICAgfQogICAgaWYgKCFnX3NoaXBfYnVmLmVtcHR5KCkpIHsKICAgICAgc2l6ZV90IG4gPSBi
b3VuZGVkX2JhdGNoX2NvdW50KGdfc2hpcF9idWYsIGdfc2hpcF9ub2RlKTsKICAgICAgaWYgKCFu
KSB7CiAgICAgICAgZ19zaGlwX2J1Zi5lcmFzZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgICAg
ICsrZ19ldmVudHNfZHJvcHBlZDsKICAgICAgICArK2dfZHJvcF9vdmVyc2l6ZWQ7CiAgICAgIH0g
ZWxzZSB7CiAgICAgICAgYmF0Y2guYXNzaWduKGdfc2hpcF9idWYuYmVnaW4oKSwgZ19zaGlwX2J1
Zi5iZWdpbigpICsgbik7CiAgICAgICAgZ19zaGlwX2J1Zi5lcmFzZShnX3NoaXBfYnVmLmJlZ2lu
KCksIGdfc2hpcF9idWYuYmVnaW4oKSArIG4pOwogICAgICB9CiAgICB9CiAgICBwdGhyZWFkX211
dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKCiAgICBpZiAoIXN0YXRzX2JvZHkuZW1w
dHkoKSkgewogICAgICBpZiAoIXBvc3RfYm9keShnX2VuZHBvaW50LCAiL2FwaS9hZ2VudC9zdGF0
cyIsIHN0YXRzX2JvZHksIDIsICZuZXh0X3N0YXRzX3Nsb3QpKSB7CiAgICAgICAgcHRocmVhZF9t
dXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICAgICsrZ19zdGF0c19kcm9wcGVk
OwogICAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAg
ICB9CiAgICB9CgogICAgaWYgKCFiYXRjaC5lbXB0eSgpKSB7CiAgICAgIHN0ZDo6c3RyaW5nIGJv
ZHkgPSAie1wibm9kZVwiOiIgKyBqc29ucShnX3NoaXBfbm9kZSkgKyAiLFwiZXZlbnRzXCI6IiAr
IGpzb25fYXJyYXkoYmF0Y2gpICsgIn0iOwogICAgICBpZiAocG9zdF9ib2R5KGdfZW5kcG9pbnQs
ICIvYXBpL2luZ2VzdCIsIGJvZHksIDEwLCAmbmV4dF9zbG90KSkgewogICAgICAgIHB0aHJlYWRf
bXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgICBnX2V2ZW50c19wdXNoZWQg
Kz0gYmF0Y2guc2l6ZSgpOwogICAgICAgICsrZ19iYXRjaGVzX3B1c2hlZDsKICAgICAgICBnX2J5
dGVzX3B1c2hlZCArPSBib2R5LnNpemUoKTsKICAgICAgICBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVz
ID0gMDsKICAgICAgICBnX2xhc3RfcHVzaF9zdGF0dXMgPSAyMDA7CiAgICAgICAgZ19sYXN0X3N1
Y2Nlc3NfYXQgPSB0aW1lKE5VTEwpOwogICAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3No
aXBfcXVldWVfbXV0ZXgpOwogICAgICB9IGVsc2UgewogICAgICAgIHB0aHJlYWRfbXV0ZXhfbG9j
aygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgICBnX2V2ZW50c19kcm9wcGVkICs9IGJhdGNo
LnNpemUoKTsKICAgICAgICBnX2Ryb3BfaHViICs9IGJhdGNoLnNpemUoKTsKICAgICAgICArK2df
YmF0Y2hlc19mYWlsZWQ7CiAgICAgICAgKytnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzOwogICAgICAg
IGdfbGFzdF9wdXNoX3N0YXR1cyA9IDA7CiAgICAgICAgaWYgKHNodXRkb3duX2RlYWRsaW5lID4g
MC4wICYmIGdfY29uc2VjdXRpdmVfZmFpbHVyZXMgPj0gMykgewogICAgICAgICAgZ19ldmVudHNf
ZHJvcHBlZCArPSBnX3NoaXBfYnVmLnNpemUoKTsKICAgICAgICAgIGdfZHJvcF9odWIgKz0gZ19z
aGlwX2J1Zi5zaXplKCk7CiAgICAgICAgICBnX3NoaXBfYnVmLmNsZWFyKCk7CiAgICAgICAgICBn
X3BlbmRpbmdfc3RhdHNfYm9keS5jbGVhcigpOwogICAgICAgICAgcHRocmVhZF9tdXRleF91bmxv
Y2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICAg
ICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgIH0KICAg
IH0KICB9CiAgcmV0dXJuIE5VTEw7Cn0KCnN0YXRpYyB1bnNpZ25lZCBjb3VudF9vcGVuX2Zkcygp
IHsKICBESVIgKmRpciA9IG9wZW5kaXIoIi9wcm9jL3NlbGYvZmQiKTsKICBpZiAoIWRpcikgcmV0
dXJuIDA7CiAgdW5zaWduZWQgY291bnQgPSAwOwogIHN0cnVjdCBkaXJlbnQgKmVudHJ5OwogIHdo
aWxlICgoZW50cnkgPSByZWFkZGlyKGRpcikpICE9IE5VTEwpIHsKICAgIGlmIChzdHJjbXAoZW50
cnktPmRfbmFtZSwgIi4iKSAmJiBzdHJjbXAoZW50cnktPmRfbmFtZSwgIi4uIikpICsrY291bnQ7
CiAgfQogIGNsb3NlZGlyKGRpcik7CiAgcmV0dXJuIGNvdW50Owp9CgpzdGF0aWMgdm9pZCBwcm9j
X3N0YXR1cyhzaXplX3QgKnJzcywgc2l6ZV90ICp2aXJ0LCB1bnNpZ25lZCAqdGhyZWFkcywKICAg
ICAgICAgICAgICAgICAgICAgICAgdW5zaWduZWQgKmNwdV9jb3JlKSB7CiAgKnJzcyA9IDA7ICp2
aXJ0ID0gMDsgKnRocmVhZHMgPSAxOyAqY3B1X2NvcmUgPSAwOwogIHN0ZDo6aWZzdHJlYW0gaW4o
Ii9wcm9jL3NlbGYvc3RhdHVzIik7CiAgc3RkOjpzdHJpbmcgbGluZTsKICB3aGlsZSAoc3RkOjpn
ZXRsaW5lKGluLCBsaW5lKSkgewogICAgdW5zaWduZWQgbG9uZyB2YWx1ZSA9IDA7CiAgICBpZiAo
c3NjYW5mKGxpbmUuY19zdHIoKSwgIlZtUlNTOiAlbHUga0IiLCAmdmFsdWUpID09IDEpICpyc3Mg
PSAoc2l6ZV90KXZhbHVlICogMTAyNFU7CiAgICBlbHNlIGlmIChzc2NhbmYobGluZS5jX3N0cigp
LCAiVm1TaXplOiAlbHUga0IiLCAmdmFsdWUpID09IDEpICp2aXJ0ID0gKHNpemVfdCl2YWx1ZSAq
IDEwMjRVOwogICAgZWxzZSBpZiAoc3NjYW5mKGxpbmUuY19zdHIoKSwgIlRocmVhZHM6ICVsdSIs
ICZ2YWx1ZSkgPT0gMSkgKnRocmVhZHMgPSAodW5zaWduZWQpdmFsdWU7CiAgICBlbHNlIGlmIChz
c2NhbmYobGluZS5jX3N0cigpLCAiQ3B1c19hbGxvd2VkX2xpc3Q6ICVsdSIsICZ2YWx1ZSkgPT0g
MSkgKmNwdV9jb3JlID0gKHVuc2lnbmVkKXZhbHVlOwogIH0KfQoKc3RhdGljIHVuc2lnbmVkIGxv
bmcgbG9uZyB1cGRhdGVfa2VybmVsX2Ryb3BzKGludCBmZCkgewogIGlmIChmZCA8IDApIHJldHVy
biAwOwogIHN0cnVjdCB0cGFja2V0X3N0YXRzIHBhY2tldF9zdGF0czsKICBzb2NrbGVuX3QgcGFj
a2V0X3N0YXRzX2xlbiA9IHNpemVvZihwYWNrZXRfc3RhdHMpOwogIG1lbXNldCgmcGFja2V0X3N0
YXRzLCAwLCBzaXplb2YocGFja2V0X3N0YXRzKSk7CiAgaWYgKGdldHNvY2tvcHQoZmQsIFNPTF9Q
QUNLRVQsIFBBQ0tFVF9TVEFUSVNUSUNTLAogICAgICAgICAgICAgICAgICZwYWNrZXRfc3RhdHMs
ICZwYWNrZXRfc3RhdHNfbGVuKSAhPSAwKSByZXR1cm4gMDsKICBnX2tlcm5lbF9kcm9wcyArPSBw
YWNrZXRfc3RhdHMudHBfZHJvcHM7CiAgcmV0dXJuIHBhY2tldF9zdGF0cy50cF9kcm9wczsKfQoK
c3RhdGljIHN0ZDo6c3RyaW5nIGFnZW50X3N0YXRzX2JvZHkoaW50IGZkLCBzaXplX3QgZmxvd3Nf
YWN0aXZlLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3QgcGVuZGlu
Z19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90IHdz
c2VfYm9keV9mbG93cykgewogIGRvdWJsZSBub3cgPSB3YWxsX3NlY29uZHMoKTsKICBkb3VibGUg
ZWxhcHNlZCA9IG5vdyAtIGdfc3RhdHNfbGFzdF9hdDsKICBpZiAoZWxhcHNlZCA8IDAuMDAxKSBl
bGFwc2VkID0gMC4wMDE7CiAgdW5zaWduZWQgbG9uZyBsb25nIGtlcm5lbF9kcm9wX2RlbHRhID0g
dXBkYXRlX2tlcm5lbF9kcm9wcyhmZCk7CiAgdW5zaWduZWQgbG9uZyBsb25nIHBhY2tldF9kZWx0
YSA9IGdfY2FwdHVyZV9wYWNrZXRzIC0gZ19wcmV2X2NhcHR1cmVfcGFja2V0czsKICB1bnNpZ25l
ZCBsb25nIGxvbmcgcGFja2V0X2J5dGVzX2RlbHRhID0gZ19jYXB0dXJlX2J5dGVzIC0gZ19wcmV2
X2NhcHR1cmVfYnl0ZXM7CiAgdW5zaWduZWQgbG9uZyBsb25nIGVtaXR0ZWRfZGVsdGEgPSBnX2V2
ZW50c19lbWl0dGVkIC0gZ19wcmV2X2V2ZW50c19lbWl0dGVkOwoKICBwdGhyZWFkX211dGV4X2xv
Y2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgdW5zaWduZWQgbG9uZyBsb25nIGluX2RlbHRhID0g
Z19ldmVudHNfaW4gLSBnX3ByZXZfZXZlbnRzX2luOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBwdXNo
ZWRfZGVsdGEgPSBnX2V2ZW50c19wdXNoZWQgLSBnX3ByZXZfZXZlbnRzX3B1c2hlZDsKICB1bnNp
Z25lZCBsb25nIGxvbmcgZHJvcHBlZF9kZWx0YSA9IGdfZXZlbnRzX2Ryb3BwZWQgLSBnX3ByZXZf
ZXZlbnRzX2Ryb3BwZWQ7CiAgdW5zaWduZWQgbG9uZyBsb25nIGJhdGNoZXNfcHVzaGVkX2RlbHRh
ID0gZ19iYXRjaGVzX3B1c2hlZCAtIGdfcHJldl9iYXRjaGVzX3B1c2hlZDsKICB1bnNpZ25lZCBs
b25nIGxvbmcgYmF0Y2hlc19mYWlsZWRfZGVsdGEgPSBnX2JhdGNoZXNfZmFpbGVkIC0gZ19wcmV2
X2JhdGNoZXNfZmFpbGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBieXRlc19kZWx0YSA9IGdfYnl0
ZXNfcHVzaGVkIC0gZ19wcmV2X2J5dGVzX3B1c2hlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgcXVl
dWVfZGVsdGEgPSBnX2Ryb3BfcXVldWUgLSBnX3ByZXZfZHJvcF9xdWV1ZTsKICB1bnNpZ25lZCBs
b25nIGxvbmcgaHViX2RlbHRhID0gZ19kcm9wX2h1YiAtIGdfcHJldl9kcm9wX2h1YjsKICB1bnNp
Z25lZCBsb25nIGxvbmcgb3ZlcnNpemVkX2RlbHRhID0gZ19kcm9wX292ZXJzaXplZCAtIGdfcHJl
dl9kcm9wX292ZXJzaXplZDsKICBzaXplX3Qgc2hpcF9idWZfc2l6ZSA9IGdfc2hpcF9idWYuc2l6
ZSgpOwogIHNpemVfdCBxdWV1ZV9oaWdoID0gZ19xdWV1ZV9oaWdoX3dhdGVyOwogIHVuc2lnbmVk
IGxhc3Rfc3RhdHVzID0gZ19sYXN0X3B1c2hfc3RhdHVzOwogIHRpbWVfdCBsYXN0X3N1Y2MgPSBn
X2xhc3Rfc3VjY2Vzc19hdDsKICB1bnNpZ25lZCBjb25zZWNfZmFpbHMgPSBnX2NvbnNlY3V0aXZl
X2ZhaWx1cmVzOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBzdGF0c19kcm9wID0gZ19zdGF0c19kcm9w
cGVkOwogIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwoKICB1bnNp
Z25lZCBsb25nIGxvbmcgcGlwZV9kcm9wX2RlbHRhID0gZ19vdXRwdXRfcGlwZV9kcm9wcyAtIGdf
cHJldl9vdXRwdXRfcGlwZV9kcm9wczsKICBzdHJ1Y3QgcnVzYWdlIHVzYWdlOwogIG1lbXNldCgm
dXNhZ2UsIDAsIHNpemVvZih1c2FnZSkpOwogIGdldHJ1c2FnZShSVVNBR0VfU0VMRiwgJnVzYWdl
KTsKICBkb3VibGUgdXNlcl9jcHUgPSB1c2FnZS5ydV91dGltZS50dl9zZWMgKyB1c2FnZS5ydV91
dGltZS50dl91c2VjIC8gMTAwMDAwMC4wOwogIGRvdWJsZSBzeXNfY3B1ID0gdXNhZ2UucnVfc3Rp
bWUudHZfc2VjICsgdXNhZ2UucnVfc3RpbWUudHZfdXNlYyAvIDEwMDAwMDAuMDsKICBkb3VibGUg
Y3B1X3RvdGFsID0gdXNlcl9jcHUgKyBzeXNfY3B1OwogIGRvdWJsZSBjcHVfcGN0ID0gMTAwLjAg
KiAoY3B1X3RvdGFsIC0gZ19zdGF0c19sYXN0X2NwdSkgLyBlbGFwc2VkOwogIGlmIChjcHVfcGN0
IDwgMCkgY3B1X3BjdCA9IDA7CiAgc2l6ZV90IHJzcyA9IDAsIHZpcnQgPSAwOwogIHVuc2lnbmVk
IHRocmVhZHMgPSAxLCBjcHVfY29yZSA9IDA7CiAgcHJvY19zdGF0dXMoJnJzcywgJnZpcnQsICZ0
aHJlYWRzLCAmY3B1X2NvcmUpOwogIHN0ZDo6c3RyaW5nIHJlYXNvbnM7CiAgaWYgKGtlcm5lbF9k
cm9wX2RlbHRhKSByZWFzb25zICs9ICJcImtlcm5lbF9kcm9wXCIiOwogIGlmIChkcm9wcGVkX2Rl
bHRhKSB7IGlmICghcmVhc29ucy5lbXB0eSgpKSByZWFzb25zICs9ICIsIjsgcmVhc29ucyArPSAi
XCJzaGlwX2Ryb3BcIiI7IH0KICBpZiAoaHViX2RlbHRhKSB7IGlmICghcmVhc29ucy5lbXB0eSgp
KSByZWFzb25zICs9ICIsIjsgcmVhc29ucyArPSAiXCJodWJfdW5yZWFjaGFibGVcIiI7IH0KICBp
ZiAocXVldWVfZGVsdGEgfHwgcGlwZV9kcm9wX2RlbHRhKSB7IGlmICghcmVhc29ucy5lbXB0eSgp
KSByZWFzb25zICs9ICIsIjsgcmVhc29ucyArPSAiXCJxdWV1ZV9wcmVzc3VyZVwiIjsgfQogIHN0
ZDo6b3N0cmluZ3N0cmVhbSBvdXQ7CiAgb3V0IDw8ICJ7XCJzY2hlbWFfdmVyc2lvblwiOjEsXCJ0
eXBlXCI6XCJhZ2VudF9zdGF0c1wiLFwibm9kZVwiOiIgPDwganNvbnEoZ19zaGlwX25vZGUpCiAg
ICAgIDw8ICIsXCJpbnN0YW5jZV9pZFwiOiIgPDwganNvbnEoZ19pbnN0YW5jZV9pZCkgPDwgIixc
InNlcXVlbmNlXCI6IiA8PCArK2dfc3RhdHNfc2VxdWVuY2UKICAgICAgPDwgIixcIm9ic2VydmVk
X2F0XCI6IiA8PCAodW5zaWduZWQgbG9uZylub3cgPDwgIixcIndpbmRvd19zZWNvbmRzXCI6IiA8
PCBkb3VibGVfc3RyaW5nKGVsYXBzZWQpCiAgICAgIDw8ICIsXCJtb2RlXCI6XCJjcHBcIixcInN0
YXR1c1wiOiIgPDwgKHJlYXNvbnMuZW1wdHkoKSA/ICJcIm9rXCIiIDogIlwiZGVncmFkZWRcIiIp
CiAgICAgIDw8ICIsXCJyZWFzb25zXCI6WyIgPDwgcmVhc29ucyA8PCAiXSxcImNhcHR1cmVcIjp7
IgogICAgICA8PCAiXCJwYWNrZXRzX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfY2FwdHVyZV9w
YWNrZXRzKSA8PCAiLFwicGFja2V0c19kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwYWNrZXRfZGVs
dGEpCiAgICAgIDw8ICIsXCJwYWNrZXRfYnl0ZXNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19j
YXB0dXJlX2J5dGVzKSA8PCAiLFwicGFja2V0X2J5dGVzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5n
KHBhY2tldF9ieXRlc19kZWx0YSkKICAgICAgPDwgIixcImtlcm5lbF9kcm9wc190b3RhbFwiOiIg
PDwgdWxsX3N0cmluZyhnX2tlcm5lbF9kcm9wcykgPDwgIixcImtlcm5lbF9kcm9wc19kZWx0YVwi
OiIgPDwgdWxsX3N0cmluZyhrZXJuZWxfZHJvcF9kZWx0YSkKICAgICAgPDwgIixcImtlcm5lbF9k
cm9wX3BlcmNlbnRcIjoiIDw8IGRvdWJsZV9zdHJpbmcoMTAwLjAgKiBrZXJuZWxfZHJvcF9kZWx0
YSAvIChwYWNrZXRfZGVsdGEgPyBwYWNrZXRfZGVsdGEgOiAxKSkKICAgICAgPDwgIixcImludmFs
aWRfZnJhbWVzX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfaW52YWxpZF9mcmFtZXMpCiAgICAg
IDw8ICIsXCJldmVudHNfZW1pdHRlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19l
bWl0dGVkKSA8PCAiLFwiZXZlbnRzX2VtaXR0ZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoZW1p
dHRlZF9kZWx0YSkKICAgICAgPDwgIixcImZsb3dzX2FjdGl2ZVwiOiIgPDwgZmxvd3NfYWN0aXZl
IDw8ICIsXCJwZW5kaW5nX3JlcXVlc3RzXCI6IiA8PCBwZW5kaW5nX3JlcXVlc3RzCiAgICAgIDw8
ICIsXCJ3c3NlX2JvZHlfZmxvd3NfYWN0aXZlXCI6IiA8PCB3c3NlX2JvZHlfZmxvd3MKICAgICAg
PDwgIixcIndzc2VfYm9keV9ieXRlc1wiOiIgPDwgZ193c3NlX2JvZHlfYnl0ZXMKICAgICAgPDwg
IixcIm91dHB1dF9waXBlX2Ryb3BzX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfb3V0cHV0X3Bp
cGVfZHJvcHMpCiAgICAgIDw8ICIsXCJvdXRwdXRfcGlwZV9kcm9wc19kZWx0YVwiOiIgPDwgdWxs
X3N0cmluZyhwaXBlX2Ryb3BfZGVsdGEpIDw8ICJ9LFwic2hpcHBpbmdcIjp7IgogICAgICA8PCAi
XCJldmVudHNfaW5fdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVudHNfaW4pIDw8ICIsXCJl
dmVudHNfaW5fZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoaW5fZGVsdGEpCiAgICAgIDw8ICIsXCJl
dmVudHNfcHVzaGVkX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfZXZlbnRzX3B1c2hlZCkgPDwg
IixcImV2ZW50c19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcocHVzaGVkX2RlbHRhKQog
ICAgICA8PCAiLFwiZXZlbnRzX2Ryb3BwZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVu
dHNfZHJvcHBlZCkgPDwgIixcImV2ZW50c19kcm9wcGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5n
KGRyb3BwZWRfZGVsdGEpCiAgICAgIDw8ICIsXCJkcm9wX2NhdXNlc1wiOntcInF1ZXVlX2Z1bGxf
dG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19kcm9wX3F1ZXVlKSA8PCAiLFwicXVldWVfZnVsbF9k
ZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhxdWV1ZV9kZWx0YSkKICAgICAgPDwgIixcImh1Yl9mYWls
dXJlX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfZHJvcF9odWIpIDw8ICIsXCJodWJfZmFpbHVy
ZV9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhodWJfZGVsdGEpCiAgICAgIDw8ICIsXCJvdmVyc2l6
ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19kcm9wX292ZXJzaXplZCkgPDwgIixcIm92ZXJz
aXplZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhvdmVyc2l6ZWRfZGVsdGEpIDw8ICJ9IgogICAg
ICA8PCAiLFwiYmF0Y2hlc19wdXNoZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19iYXRjaGVz
X3B1c2hlZCkgPDwgIixcImJhdGNoZXNfcHVzaGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGJh
dGNoZXNfcHVzaGVkX2RlbHRhKQogICAgICA8PCAiLFwiYmF0Y2hlc19mYWlsZWRfdG90YWxcIjoi
IDw8IHVsbF9zdHJpbmcoZ19iYXRjaGVzX2ZhaWxlZCkgPDwgIixcImJhdGNoZXNfZmFpbGVkX2Rl
bHRhXCI6IiA8PCB1bGxfc3RyaW5nKGJhdGNoZXNfZmFpbGVkX2RlbHRhKQogICAgICA8PCAiLFwi
Ynl0ZXNfcHVzaGVkX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfYnl0ZXNfcHVzaGVkKSA8PCAi
LFwiYnl0ZXNfcHVzaGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGJ5dGVzX2RlbHRhKQogICAg
ICA8PCAiLFwicHVzaF9ldmVudHNfcGVyX3NlY29uZFwiOiIgPDwgZG91YmxlX3N0cmluZyhwdXNo
ZWRfZGVsdGEgLyBlbGFwc2VkKQogICAgICA8PCAiLFwicHVzaF9rYnBzXCI6IiA8PCBkb3VibGVf
c3RyaW5nKDguMCAqIGJ5dGVzX2RlbHRhIC8gKDEwMDAuMCAqIGVsYXBzZWQpKQogICAgICA8PCAi
LFwiZHJvcF9ldmVudHNfcGVyX3NlY29uZFwiOiIgPDwgZG91YmxlX3N0cmluZyhkcm9wcGVkX2Rl
bHRhIC8gZWxhcHNlZCkKICAgICAgPDwgIixcImRyb3BfcGVyY2VudFwiOiIgPDwgZG91YmxlX3N0
cmluZygxMDAuMCAqIGRyb3BwZWRfZGVsdGEgLyAoaW5fZGVsdGEgPyBpbl9kZWx0YSA6IDEpKQog
ICAgICA8PCAiLFwicXVldWVfZGVwdGhfZXZlbnRzXCI6IiA8PCBzaGlwX2J1Zl9zaXplIDw8ICIs
XCJxdWV1ZV9jYXBhY2l0eV9ldmVudHNcIjoiIDw8IE1BWF9RVUVVRQogICAgICA8PCAiLFwicXVl
dWVfaGlnaF93YXRlcl9ldmVudHNcIjoiIDw8IHF1ZXVlX2hpZ2ggPDwgIixcImxhc3RfcHVzaF9o
dHRwX3N0YXR1c1wiOiIgPDwgbGFzdF9zdGF0dXMKICAgICAgPDwgIixcImxhc3Rfc3VjY2Vzc19h
dFwiOiIgPDwgKHVuc2lnbmVkIGxvbmcpbGFzdF9zdWNjIDw8ICIsXCJjb25zZWN1dGl2ZV9mYWls
dXJlc1wiOiIgPDwgY29uc2VjX2ZhaWxzCiAgICAgIDw8ICIsXCJzdGF0c19zYW1wbGVzX2Ryb3Bw
ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoc3RhdHNfZHJvcCkgPDwgIn0sXCJyZXNvdXJjZXNc
Ijp7IgogICAgICA8PCAiXCJjcHVfdXNlcl9zZWNvbmRzXCI6IiA8PCBkb3VibGVfc3RyaW5nKHVz
ZXJfY3B1KSA8PCAiLFwiY3B1X3N5c3RlbV9zZWNvbmRzXCI6IiA8PCBkb3VibGVfc3RyaW5nKHN5
c19jcHUpCiAgICAgIDw8ICIsXCJjcHVfcGVyY2VudF9vbmVfY29yZVwiOiIgPDwgZG91YmxlX3N0
cmluZyhjcHVfcGN0KSA8PCAiLFwicnNzX2J5dGVzXCI6IiA8PCByc3MKICAgICAgPDwgIixcInZp
cnR1YWxfYnl0ZXNcIjoiIDw8IHZpcnQgPDwgIixcIm9wZW5fZmRzXCI6IiA8PCBjb3VudF9vcGVu
X2ZkcygpIDw8ICIsXCJ0aHJlYWRzXCI6IiA8PCB0aHJlYWRzCiAgICAgIDw8ICJ9LFwibGltaXRz
XCI6e1wiY3B1X2NvcmVcIjoiIDw8IGNwdV9jb3JlIDw8ICIsXCJhZGRyZXNzX3NwYWNlX2J5dGVz
XCI6MjY4NDM1NDU2IgogICAgICA8PCAiLFwic2hpcF9yYXRlX2ticHNcIjoiIDw8IGdfc2hpcF9y
YXRlX2ticHMgPDwgIixcImh0dHBfYm9keV9tYXhfYnl0ZXNcIjoiIDw8IE1BWF9QT1NUX0JZVEVT
CiAgICAgIDw8ICIsXCJzaGlwX3RocmVhZHNfbWF4XCI6MSxcIndzc2VfYm9keV9ieXRlc1wiOiIg
PDwgZ193c3NlX2JvZHlfYnl0ZXMgPDwgIn19IjsKICBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzID0g
Z19jYXB0dXJlX3BhY2tldHM7IGdfcHJldl9jYXB0dXJlX2J5dGVzID0gZ19jYXB0dXJlX2J5dGVz
OwogIGdfcHJldl9ldmVudHNfZW1pdHRlZCA9IGdfZXZlbnRzX2VtaXR0ZWQ7CiAgcHRocmVhZF9t
dXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogIGdfcHJldl9ldmVudHNfaW4gPSBnX2V2
ZW50c19pbjsKICBnX3ByZXZfZXZlbnRzX3B1c2hlZCA9IGdfZXZlbnRzX3B1c2hlZDsgZ19wcmV2
X2V2ZW50c19kcm9wcGVkID0gZ19ldmVudHNfZHJvcHBlZDsKICBnX3ByZXZfYmF0Y2hlc19wdXNo
ZWQgPSBnX2JhdGNoZXNfcHVzaGVkOyBnX3ByZXZfYmF0Y2hlc19mYWlsZWQgPSBnX2JhdGNoZXNf
ZmFpbGVkOwogIGdfcHJldl9ieXRlc19wdXNoZWQgPSBnX2J5dGVzX3B1c2hlZDsgZ19wcmV2X2Ry
b3BfcXVldWUgPSBnX2Ryb3BfcXVldWU7CiAgZ19wcmV2X2Ryb3BfaHViID0gZ19kcm9wX2h1Yjsg
Z19wcmV2X2Ryb3Bfb3ZlcnNpemVkID0gZ19kcm9wX292ZXJzaXplZDsKICBwdGhyZWFkX211dGV4
X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICBnX3ByZXZfb3V0cHV0X3BpcGVfZHJvcHMg
PSBnX291dHB1dF9waXBlX2Ryb3BzOwogIGdfc3RhdHNfbGFzdF9jcHUgPSBjcHVfdG90YWw7IGdf
c3RhdHNfbGFzdF9hdCA9IG5vdzsKICByZXR1cm4gb3V0LnN0cigpOwp9CgpzdGF0aWMgdm9pZCBz
ZW5kX2FnZW50X3N0YXRzKGludCBmZCwgc2l6ZV90IGZsb3dzX2FjdGl2ZSwKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBzaXplX3QgcGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBzaXplX3Qgd3NzZV9ib2R5X2Zsb3dzKSB7CiAgc3RkOjpzdHJpbmcgYm9k
eSA9IGFnZW50X3N0YXRzX2JvZHkoZmQsIGZsb3dzX2FjdGl2ZSwgcGVuZGluZ19yZXF1ZXN0cywK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3c3NlX2JvZHlfZmxvd3MpOwog
IGlmIChib2R5LnNpemUoKSA+IE1BWF9TVEFUU19CWVRFUykgewogICAgcHRocmVhZF9tdXRleF9s
b2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgKytnX3N0YXRzX2Ryb3BwZWQ7CiAgICBwdGhy
ZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgIHJldHVybjsKICB9CiAg
cHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogIGdfcGVuZGluZ19zdGF0
c19ib2R5ID0gYm9keTsKICBwdGhyZWFkX2NvbmRfc2lnbmFsKCZnX3NoaXBfcXVldWVfY29uZCk7
CiAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7Cn0KCnN0YXRpYyBi
b29sIHdyaXRlX25vbmJsb2NraW5nX2xpbmUoY29uc3Qgc3RkOjpzdHJpbmcgJmxpbmUpIHsKICBp
ZiAobGluZS5zaXplKCkgKyAxID4gUElQRV9CVUYpIHsKICAgICsrZ19vdXRwdXRfcGlwZV9kcm9w
czsKICAgIHJldHVybiB0cnVlOwogIH0KICBzdGQ6OnN0cmluZyBmcmFtZWQgPSBsaW5lICsgIlxu
IjsKICBzc2l6ZV90IHdyaXR0ZW47CiAgZG8geyB3cml0dGVuID0gd3JpdGUoU1RET1VUX0ZJTEVO
TywgZnJhbWVkLmRhdGEoKSwgZnJhbWVkLnNpemUoKSk7IH0KICB3aGlsZSAod3JpdHRlbiA8IDAg
JiYgZXJybm8gPT0gRUlOVFIgJiYgZ19ydW5uaW5nKTsKICBpZiAod3JpdHRlbiA9PSAoc3NpemVf
dClmcmFtZWQuc2l6ZSgpKSByZXR1cm4gdHJ1ZTsKICBpZiAod3JpdHRlbiA8IDAgJiYgKGVycm5v
ID09IEVBR0FJTiB8fCBlcnJubyA9PSBFV09VTERCTE9DSykpIHsKICAgICsrZ19vdXRwdXRfcGlw
ZV9kcm9wczsKICAgIHJldHVybiB0cnVlOwogIH0KICBpZiAod3JpdHRlbiA8IDAgJiYgZXJybm8g
PT0gRVBJUEUpIHsKICAgIGxvZ21zZygic2hpcHBlciBwaXBlIGNsb3NlZDsgc3RvcHBpbmcgY2Fw
dHVyZSBmb3Igc3VwZXJ2aXNlZCByZXN0YXJ0Iik7CiAgfSBlbHNlIHsKICAgIGxvZ21zZygic2hp
cHBlciBwaXBlIHdyaXRlIGZhaWxlZDsgc3RvcHBpbmcgY2FwdHVyZSBmb3Igc3VwZXJ2aXNlZCBy
ZXN0YXJ0Iik7CiAgfQogIGdfcnVubmluZyA9IDA7CiAgcmV0dXJuIGZhbHNlOwp9CgpzdGF0aWMg
dm9pZCBlbWl0X2NhcHR1cmVfc3RhdHNfaW50ZXJuYWwoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0
aXZlLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90IHBlbmRp
bmdfcmVxdWVzdHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXpl
X3Qgd3NzZV9ib2R5X2Zsb3dzKSB7CiAgc3RkOjpzdHJpbmcgZnVsbCA9IGFnZW50X3N0YXRzX2Jv
ZHkoZmQsIGZsb3dzX2FjdGl2ZSwgcGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICB3c3NlX2JvZHlfZmxvd3MpOwogIGNvbnN0IHN0ZDo6c3RyaW5n
IG1hcmtlciA9ICJcImNhcHR1cmVcIjoiOwogIHNpemVfdCBzdGFydCA9IGZ1bGwuZmluZChtYXJr
ZXIpOwogIHNpemVfdCBlbmQgPSBmdWxsLmZpbmQoIixcInNoaXBwaW5nXCI6Iiwgc3RhcnQpOwog
IGlmIChzdGFydCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBlbmQgPT0gc3RkOjpzdHJpbmc6Om5w
b3MpIHsKICAgICsrZ19vdXRwdXRfcGlwZV9kcm9wczsKICAgIHJldHVybjsKICB9CiAgc3RhcnQg
Kz0gbWFya2VyLnNpemUoKTsKICB3cml0ZV9ub25ibG9ja2luZ19saW5lKCJ7XCJfbnRfaW50ZXJu
YWxcIjpcImNhcHR1cmVfc3RhdHNfdjFcIixcImNhcHR1cmVcIjoiICsKICAgICAgICAgICAgICAg
ICAgICAgICAgIGZ1bGwuc3Vic3RyKHN0YXJ0LCBlbmQgLSBzdGFydCkgKyAifSIpOwp9CgpzdGF0
aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0IEV2ZW50ICZlKSB7CiAgc3RkOjpvc3RyaW5nc3RyZWFt
IHNzOwogIHNzIDw8ICJ7XCJ0c1wiOiIgPDwgZS50cyA8PCAiLFwiaG9zdFwiOiIgPDwganNvbnEo
ZS5ob3N0KSA8PCAiLFwic3JjXCI6XCJwY2FwXCIsXCJzZXJ2aWNlXCI6IiA8PCBqc29ucShlLnNl
cnZpY2UpCiAgICAgPDwgIixcIm1ldGhvZFwiOiIgPDwganNvbnEoZS5tZXRob2QpIDw8ICIsXCJw
YXRoXCI6IiA8PCBqc29ucShlLnBhdGgpIDw8ICIsXCJ1c2VyXCI6IiA8PCBqc29ucShlLnVzZXIp
CiAgICAgPDwgIixcInNjaGVtZVwiOiIgPDwganNvbnEoZS5zY2hlbWUpCiAgICAgPDwgIixcImJh
c2ljX3VzZXJcIjoiIDw8IChlLmJhc2ljX3VzZXIuZW1wdHkoKSA/ICJudWxsIiA6IGpzb25xKGUu
YmFzaWNfdXNlcikpCiAgICAgPDwgIixcIndzc2VfdXNlclwiOiIgPDwgKGUud3NzZV91c2VyLmVt
cHR5KCkgPyAibnVsbCIgOiBqc29ucShlLndzc2VfdXNlcikpCiAgICAgPDwgIixcInNvdXJjZV9w
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
ZWxzZSBzcyA8PCAiLFwicmVzcF9ieXRlc1wiOm51bGwiOwogIHNzIDw8ICJ9IjsKICArK2dfZXZl
bnRzX2VtaXR0ZWQ7CgogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICArK2dfZXZlbnRz
X2luOwogICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgaWYg
KGdfc2hpcF9idWYuc2l6ZSgpID49IE1BWF9RVUVVRSkgewogICAgICBnX3NoaXBfYnVmLmVyYXNl
KGdfc2hpcF9idWYuYmVnaW4oKSk7CiAgICAgICsrZ19ldmVudHNfZHJvcHBlZDsKICAgICAgKytn
X2Ryb3BfcXVldWU7CiAgICB9CiAgICBnX3NoaXBfYnVmLnB1c2hfYmFjayhzcy5zdHIoKSk7CiAg
ICBpZiAoZ19zaGlwX2J1Zi5zaXplKCkgPiBnX3F1ZXVlX2hpZ2hfd2F0ZXIpIGdfcXVldWVfaGln
aF93YXRlciA9IGdfc2hpcF9idWYuc2l6ZSgpOwogICAgcHRocmVhZF9jb25kX3NpZ25hbCgmZ19z
aGlwX3F1ZXVlX2NvbmQpOwogICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9t
dXRleCk7CiAgfSBlbHNlIHsKICAgIHdyaXRlX25vbmJsb2NraW5nX2xpbmUoc3Muc3RyKCkpOwog
IH0KfQoKc3RhdGljIHZvaWQgcXVldWVfcmVxdWVzdChjb25zdCBFdmVudCAmZSwgdWludDMyX3Qg
c19pcCwgdW5zaWduZWQgc3BvcnQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgdWludDMyX3Qg
ZF9pcCwgdW5zaWduZWQgZHBvcnQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8
UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nLAogICAgICAgICAgICAg
ICAgICAgICAgICAgIGxvbmcgbG9uZyBmaXJzdF9ieXRlX21vbm9fbXMgPSAwLAogICAgICAgICAg
ICAgICAgICAgICAgICAgIHVpbnQzMl90IGdlbiA9IDAsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgYm9vbCBzeW5fc2VlbiA9IGZhbHNlKSB7CiAgUGFja2V0S2V5IHJrOwogIHJrLnNfaXAgPSBk
X2lwOyByay5zcG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICByay5kX2lwID0gc19pcDsgcmsuZHBv
cnQgPSAodWludDE2X3Qpc3BvcnQ7CgogIGxvbmcgbG9uZyBtb25vX25vdyA9IG5vd19tb25vdG9u
aWNfbXMoKTsKICBsb25nIGxvbmcgc3RhcnRlZF9tb25vID0gKGZpcnN0X2J5dGVfbW9ub19tcyA+
IDApID8gZmlyc3RfYnl0ZV9tb25vX21zIDogbW9ub19ub3c7CgogIGJvb2wgdmVyaWZpZWQgPSBz
eW5fc2VlbiB8fCAoZ2VuID4gMCk7CiAgaWYgKGlzX2NvcnJlbGF0aW9uX2Rpc2FibGVkKHJrLCB2
ZXJpZmllZCkpIHsKICAgIGVtaXRfZXZlbnQoZSk7CiAgICByZXR1cm47CiAgfQoKICB3aGlsZSAo
Z190b3RhbF9wZW5kaW5nX2NvdW50ID49IE1BWF9QRU5ESU5HX1RPVEFMICYmICFnX3BlbmRpbmdf
Zmlmby5lbXB0eSgpKSB7CiAgICBQZW5kaW5nUXVldWVSZWYgcmVmID0gZ19wZW5kaW5nX2ZpZm8u
ZnJvbnQoKTsKICAgIGdfcGVuZGluZ19maWZvLnBvcF9mcm9udCgpOwogICAgc3RkOjptYXA8UGFj
a2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9IHBlbmRpbmcuZmlu
ZChyZWYua2V5KTsKICAgIGlmIChpdCAhPSBwZW5kaW5nLmVuZCgpKSB7CiAgICAgIGZvciAoc2l6
ZV90IGkgPSAwOyBpIDwgaXQtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICAgIGlmIChpdC0+
c2Vjb25kW2ldLnJlcV9pZCA9PSByZWYucmVxX2lkKSB7CiAgICAgICAgICAvLyBHbG9iYWwgZXZp
Y3Rpb24gZGlzcnVwdHMgb3JkZXJpbmcgZm9yIHRoaXMga2V5OiBmbHVzaCBhbGwgYW5kIGxvY2sg
b3V0LgogICAgICAgICAgd2hpbGUgKCFpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgICAgICAgICAg
aWYgKCFpdC0+c2Vjb25kLmZyb250KCkuaXNfdG9tYnN0b25lKSB7CiAgICAgICAgICAgICAgZW1p
dF9ldmVudChpdC0+c2Vjb25kLmZyb250KCkuZXYpOwogICAgICAgICAgICAgIGlmIChnX3RvdGFs
X3BlbmRpbmdfY291bnQgPiAwKSAtLWdfdG90YWxfcGVuZGluZ19jb3VudDsKICAgICAgICAgICAg
fQogICAgICAgICAgICBpdC0+c2Vjb25kLmVyYXNlKGl0LT5zZWNvbmQuYmVnaW4oKSk7CiAgICAg
ICAgICB9CiAgICAgICAgICBwZW5kaW5nLmVyYXNlKGl0KTsKICAgICAgICAgIGNvcnJfZGlzYWJs
ZWRfaW5zZXJ0KHJlZi5rZXkpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICB9CiAg
ICB9CiAgfQoKICBpZiAoaXNfY29ycmVsYXRpb25fZGlzYWJsZWQocmssIHZlcmlmaWVkKSkgewog
ICAgZW1pdF9ldmVudChlKTsKICAgIHJldHVybjsKICB9CgogIHN0ZDo6dmVjdG9yPFBlbmRpbmc+
ICZxdWV1ZSA9IHBlbmRpbmdbcmtdOwogIGlmIChxdWV1ZS5zaXplKCkgPj0gTUFYX1BFTkRJTkdf
UEVSX0ZMT1cpIHsKICAgIC8vIFBlci1mbG93IG92ZXJmbG93OiBmbHVzaCBhbGwgZW50cmllcyBm
b3IgdGhpcyA0LXR1cGxlLCBwZXJtYW5lbnRseSBsb2NrIG91dC4KICAgIHdoaWxlICghcXVldWUu
ZW1wdHkoKSkgewogICAgICBpZiAoIXF1ZXVlLmZyb250KCkuaXNfdG9tYnN0b25lKSB7CiAgICAg
ICAgZW1pdF9ldmVudChxdWV1ZS5mcm9udCgpLmV2KTsKICAgICAgICBpZiAoZ190b3RhbF9wZW5k
aW5nX2NvdW50ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgIH0KICAgICAgcXVl
dWUuZXJhc2UocXVldWUuYmVnaW4oKSk7CiAgICB9CiAgICBwZW5kaW5nLmVyYXNlKHJrKTsKICAg
IGNvcnJfZGlzYWJsZWRfaW5zZXJ0KHJrKTsKICAgIGVtaXRfZXZlbnQoZSk7CiAgICByZXR1cm47
CiAgfQoKICB1aW50NjRfdCByZXFfaWQgPSArK2dfcmVxX2lkX3NlcTsKICBxdWV1ZS5wdXNoX2Jh
Y2soUGVuZGluZyhyZXFfaWQsIGdlbiwgZSwgbm93X21zKCksIHN0YXJ0ZWRfbW9ubykpOwogICsr
Z190b3RhbF9wZW5kaW5nX2NvdW50OwoKCiAgUGVuZGluZ1F1ZXVlUmVmIG5ld19yZWY7CiAgbmV3
X3JlZi5yZXFfaWQgPSByZXFfaWQ7CiAgbmV3X3JlZi5nZW5lcmF0aW9uID0gZ2VuOwogIG5ld19y
ZWYua2V5ID0gcms7CiAgbmV3X3JlZi5zdGFydGVkX21vbm9fbXMgPSBzdGFydGVkX21vbm87CiAg
Z19wZW5kaW5nX2ZpZm8ucHVzaF9iYWNrKG5ld19yZWYpOwoKICBpZiAoZ19wZW5kaW5nX2ZpZm8u
c2l6ZSgpID4gTUFYX1BFTkRJTkdfVE9UQUwgKiAyKSB7CiAgICBzdGQ6Omxpc3Q8UGVuZGluZ1F1
ZXVlUmVmPjo6aXRlcmF0b3IgZmkgPSBnX3BlbmRpbmdfZmlmby5iZWdpbigpOwogICAgd2hpbGUg
KGZpICE9IGdfcGVuZGluZ19maWZvLmVuZCgpKSB7CiAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwg
c3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgaXQgPSBwZW5kaW5nLmZpbmQoZmktPmtl
eSk7CiAgICAgIGJvb2wgYWxpdmUgPSBmYWxzZTsKICAgICAgaWYgKGl0ICE9IHBlbmRpbmcuZW5k
KCkpIHsKICAgICAgICBmb3IgKHNpemVfdCBqID0gMDsgaiA8IGl0LT5zZWNvbmQuc2l6ZSgpOyAr
K2opIHsKICAgICAgICAgIGlmIChpdC0+c2Vjb25kW2pdLnJlcV9pZCA9PSBmaS0+cmVxX2lkKSB7
CiAgICAgICAgICAgIGFsaXZlID0gdHJ1ZTsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9
CiAgICAgICAgfQogICAgICB9CiAgICAgIGlmICghYWxpdmUpIHsKICAgICAgICBmaSA9IGdfcGVu
ZGluZ19maWZvLmVyYXNlKGZpKTsKICAgICAgfSBlbHNlIHsKICAgICAgICArK2ZpOwogICAgICB9
CiAgICB9CiAgfQp9CgpzdGF0aWMgdm9pZCBmbHVzaF9pbmNvbXBsZXRlX3dzc2Uoc3RkOjptYXA8
Rmxvd0tleSwgRmxvdz4gJmZsb3dzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
c3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAg
Zm9yIChzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgZiA9IGZsb3dzLmJlZ2luKCk7
IGYgIT0gZmxvd3MuZW5kKCk7ICsrZikgewogICAgaWYgKGYtPnNlY29uZC5hd2FpdGluZ193c3Nl
KSB7CiAgICAgIHF1ZXVlX3JlcXVlc3QoZi0+c2Vjb25kLndzc2VfZXZlbnQsIGYtPmZpcnN0LnNf
aXAsIGYtPmZpcnN0LnNwb3J0LAogICAgICAgICAgICAgICAgICAgIGYtPmZpcnN0LmRfaXAsIGYt
PmZpcnN0LmRwb3J0LCBwZW5kaW5nLCBmLT5zZWNvbmQuZmlyc3RfYnl0ZV9tb25vX21zLAogICAg
ICAgICAgICAgICAgICAgIGYtPnNlY29uZC5nZW5lcmF0aW9uLCBmLT5zZWNvbmQuc3luX3NlZW4p
OwoKICAgICAgZi0+c2Vjb25kLmF3YWl0aW5nX3dzc2UgPSBmYWxzZTsKICAgIH0KICAgIGYtPnNl
Y29uZC5jbGVhcl9idWZmZXJzKCk7CiAgfQogIGZsb3dzLmNsZWFyKCk7CiAgZ190b3RhbF9mbG93
X2J5dGVzID0gMDsKfQoKc3RhdGljIHZvaWQgZmx1c2hfYWxsX3BlbmRpbmcoc3RkOjptYXA8UGFj
a2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgZm9yIChzdGQ6Om1h
cDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHAgPSBwZW5kaW5n
LmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTsgKytwKSB7CiAgICBmb3IgKHNpemVfdCBpID0g
MDsgaSA8IHAtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICBpZiAoIXAtPnNlY29uZFtpXS5p
c190b21ic3RvbmUpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAg
IH0KICAgIH0KICB9CiAgcGVuZGluZy5jbGVhcigpOwogIGdfcGVuZGluZ19maWZvLmNsZWFyKCk7
CiAgZ190b3RhbF9wZW5kaW5nX2NvdW50ID0gMDsKICBjb3JyX2Rpc2FibGVkX2NsZWFyKCk7Cn0K
CgoKc3RhdGljIHZvaWQgc3dlZXAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLAogICAg
ICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4g
JnBlbmRpbmcsCiAgICAgICAgICAgICAgICAgIHRpbWVfdCBub3csIHVuc2lnbmVkIHBlbmRpbmdf
dHRsX3NlYywKICAgICAgICAgICAgICAgICAgbG9uZyBsb25nIG5vd19tb25vID0gMCkgewogIGZv
ciAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGYgPSBmbG93cy5iZWdpbigpOyBm
ICE9IGZsb3dzLmVuZCgpOykgewogICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9y
IGZuID0gZjsgKytmbjsKICAgIGlmICgodW5zaWduZWQpKG5vdyAtIGYtPnNlY29uZC50b3VjaGVk
KSA+IEZMT1dfVFRMKSB7CiAgICAgIGlmIChmLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSkgewogICAg
ICAgIGVtaXRfZXZlbnQoZi0+c2Vjb25kLndzc2VfZXZlbnQpOwogICAgICAgIGYtPnNlY29uZC5h
d2FpdGluZ193c3NlID0gZmFsc2U7CiAgICAgIH0KICAgICAgZi0+c2Vjb25kLmNsZWFyX2J1ZmZl
cnMoKTsKICAgICAgZmxvd3MuZXJhc2UoZik7CiAgICB9CiAgICBmID0gZm47CiAgfQoKICBpZiAo
bm93X21vbm8gPD0gMCkgbm93X21vbm8gPSBub3dfbW9ub3RvbmljX21zKCk7CiAgbG9uZyBsb25n
IHR0bF9tcyA9IChsb25nIGxvbmcpcGVuZGluZ190dGxfc2VjICogMTAwMExMOwogIGZvciAoc3Rk
OjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVu
ZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcuZW5kKCk7KSB7CiAgICBzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHBuID0gcDsgKytwbjsKICAgIHNp
emVfdCBpID0gMDsKICAgIHdoaWxlIChpIDwgcC0+c2Vjb25kLnNpemUoKSkgewogICAgICBQZW5k
aW5nICZlbnRyeSA9IHAtPnNlY29uZFtpXTsKICAgICAgaWYgKGVudHJ5LmlzX3RvbWJzdG9uZSkg
ewogICAgICAgIGlmIChub3dfbW9ubyAtIGVudHJ5LnRvbWJzdG9uZV9tb25vX21zID4gMTAwMDBM
TCkgewogICAgICAgICAgLy8gVG9tYnN0b25lIGV4cGlyZWQgdW4tY29uc3VtZWQ6IGZsdXNoIGFs
bCByZW1haW5pbmcgZW50cmllcyBpbiB0aGlzCiAgICAgICAgICAvLyBxdWV1ZSBpbW1lZGlhdGVs
eSAob3JkZXJpbmcgaXMgbm93IGFtYmlndW91cykuIFRoZW4gcGVybWFuZW50bHkKICAgICAgICAg
IC8vIGRpc2FibGUgcmVzcG9uc2UgY29ycmVsYXRpb24gZm9yIHRoaXMgNC10dXBsZSB1bnRpbCBh
IG5ldyBTWU4uCiAgICAgICAgICBQYWNrZXRLZXkgZGlzYWJsZWRfa2V5ID0gcC0+Zmlyc3Q7CiAg
ICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkgKyBpKTsKICAgICAgICAg
IHdoaWxlIChpIDwgcC0+c2Vjb25kLnNpemUoKSkgewogICAgICAgICAgICBQZW5kaW5nICZ0YWls
ID0gcC0+c2Vjb25kW2ldOwogICAgICAgICAgICBpZiAoIXRhaWwuaXNfdG9tYnN0b25lKSB7CiAg
ICAgICAgICAgICAgZW1pdF9ldmVudCh0YWlsLmV2KTsKICAgICAgICAgICAgICBpZiAoZ190b3Rh
bF9wZW5kaW5nX2NvdW50ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgICAgICAg
IH0KICAgICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAg
ICAgICAgICB9CiAgICAgICAgICBjb3JyX2Rpc2FibGVkX2luc2VydChkaXNhYmxlZF9rZXkpOwog
ICAgICAgICAgLy8gTGVhdmUgaSB1bmNoYW5nZWQ7IGlubmVyIHdoaWxlIGV4aXRzIG9uIG5leHQg
Y2hlY2sKCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICsraTsKICAgICAgICB9CiAgICAgIH0g
ZWxzZSBpZiAobm93X21vbm8gLSBlbnRyeS5zdGFydGVkX21vbm9fbXMgPiB0dGxfbXMpIHsKICAg
ICAgICBlbWl0X2V2ZW50KGVudHJ5LmV2KTsKICAgICAgICBpZiAoZ190b3RhbF9wZW5kaW5nX2Nv
dW50ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgICAgZW50cnkuaXNfdG9tYnN0
b25lID0gdHJ1ZTsKICAgICAgICBlbnRyeS50b21ic3RvbmVfbW9ub19tcyA9IG5vd19tb25vOwog
ICAgICAgICsraTsKICAgICAgfSBlbHNlIHsKICAgICAgICArK2k7CiAgICAgIH0KICAgIH0KICAg
IGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgIHAgPSBwbjsKICB9
CgogIHdoaWxlICghZ19wZW5kaW5nX2ZpZm8uZW1wdHkoKSAmJgogICAgICAgICAobm93X21vbm8g
LSBnX3BlbmRpbmdfZmlmby5mcm9udCgpLnN0YXJ0ZWRfbW9ub19tcyA+IHR0bF9tcyAqIDJMTCkp
IHsKICAgIGdfcGVuZGluZ19maWZvLnBvcF9mcm9udCgpOwogIH0KfQoKCnN0YXRpYyBib29sIGRy
YWluX29vb19zZWdtZW50cyhGbG93ICZmbCkgewogIGJvb2wgZHJhaW5lZCA9IHRydWU7CiAgd2hp
bGUgKGRyYWluZWQgJiYgIWZsLm9vby5lbXB0eSgpKSB7CiAgICBkcmFpbmVkID0gZmFsc2U7CiAg
ICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGZsLm9vby5zaXplKCk7ICsraSkgewogICAgICBpbnQz
Ml90IG9kaWZmID0gc2VxX2RpZmYoZmwub29vW2ldLnNlcSwgZmwubmV4dF9zZXEpOwogICAgICBp
ZiAob2RpZmYgPT0gMCkgewogICAgICAgIGlmICghZmwuYnVmX2FwcGVuZChmbC5vb29baV0uZGF0
YS5kYXRhKCksIGZsLm9vb1tpXS5kYXRhLnNpemUoKSkpIHJldHVybiBmYWxzZTsKICAgICAgICBm
bC5uZXh0X3NlcSArPSAodWludDMyX3QpZmwub29vW2ldLmRhdGEuc2l6ZSgpOwogICAgICAgIGZs
Lm9vb19lcmFzZShpKTsKICAgICAgICBkcmFpbmVkID0gdHJ1ZTsgYnJlYWs7CiAgICAgIH0gZWxz
ZSBpZiAob2RpZmYgPCAwKSB7CiAgICAgICAgaW50MzJfdCBvX292ZXJsYXAgPSAtb2RpZmY7CiAg
ICAgICAgaWYgKChzaXplX3Qpb19vdmVybGFwIDwgZmwub29vW2ldLmRhdGEuc2l6ZSgpKSB7CiAg
ICAgICAgICBzaXplX3QgZmxlbiA9IGZsLm9vb1tpXS5kYXRhLnNpemUoKSAtIG9fb3ZlcmxhcDsK
ICAgICAgICAgIGlmICghZmwuYnVmX2FwcGVuZChmbC5vb29baV0uZGF0YS5kYXRhKCkgKyBvX292
ZXJsYXAsIGZsZW4pKSByZXR1cm4gZmFsc2U7CiAgICAgICAgICBmbC5uZXh0X3NlcSArPSAodWlu
dDMyX3QpZmxlbjsKICAgICAgICB9CiAgICAgICAgZmwub29vX2VyYXNlKGkpOwogICAgICAgIGRy
YWluZWQgPSB0cnVlOyBicmVhazsKICAgICAgfQogICAgfQogIH0KICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIHNpemVfdCBmaW5kX2h0dHBfc3RhcnQoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBj
b25zdCBjaGFyICptW10gPSB7ICJHRVQgIiwgIlBPU1QgIiwgIlBVVCAiLCAiREVMRVRFICIsICJQ
QVRDSCAiLCAiSEVBRCAiLCAiT1BUSU9OUyAiIH07CiAgc2l6ZV90IGJlc3QgPSBzdGQ6OnN0cmlu
Zzo6bnBvczsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDc7ICsraSkgewogICAgc2l6ZV90IHBv
cyA9IHMuZmluZChtW2ldKTsKICAgIGlmIChwb3MgIT0gc3RkOjpzdHJpbmc6Om5wb3MgJiYgKGJl
c3QgPT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwgcG9zIDwgYmVzdCkpIGJlc3QgPSBwb3M7CiAgfQog
IHJldHVybiBiZXN0Owp9CgpzdGF0aWMgYm9vbCBpc19tZXRob2Rfb3JfcHJlZml4KGNvbnN0IGNo
YXIgKnAsIHNpemVfdCBsZW4pIHsKICBpZiAoIWxlbikgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNo
YXIgKm1bXSA9IHsgIkdFVCAiLCAiUE9TVCAiLCAiUFVUICIsICJERUxFVEUgIiwgIlBBVENIICIs
ICJIRUFEICIsICJPUFRJT05TICIgfTsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDc7ICsraSkg
ewogICAgc2l6ZV90IG1sZW4gPSBzdHJsZW4obVtpXSk7CiAgICBzaXplX3QgY2hlY2tfbGVuID0g
bGVuIDwgbWxlbiA/IGxlbiA6IG1sZW47CiAgICBpZiAobWVtY21wKHAsIG1baV0sIGNoZWNrX2xl
bikgPT0gMCkgcmV0dXJuIHRydWU7CiAgfQogIHJldHVybiBmYWxzZTsKfQoKc3RhdGljIGJvb2wg
Z19tb25pdG9yZWRfcG9ydHNbNjU1MzZdOwoKc3RhdGljIHNpemVfdCBhY3RpdmVfd3NzZV9mbG93
cyhjb25zdCBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MpIHsKICBzaXplX3QgY291bnQg
PSAwOwogIGZvciAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46OmNvbnN0X2l0ZXJhdG9yIGl0ID0g
Zmxvd3MuYmVnaW4oKTsgaXQgIT0gZmxvd3MuZW5kKCk7ICsraXQpCiAgICBpZiAoaXQtPnNlY29u
ZC5hd2FpdGluZ193c3NlKSArK2NvdW50OwogIHJldHVybiBjb3VudDsKfQoKc3RhdGljIHZvaWQg
ZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVkKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93
cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6bWFwPFBhY2tl
dEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIHdoaWxlICghZmxvd3Mu
ZW1wdHkoKSAmJiAoZmxvd3Muc2l6ZSgpID49IE1BWF9GTE9XUyB8fCBnX3RvdGFsX2Zsb3dfYnl0
ZXMgPj0gTUFYX1RPVEFMX0JVRkZFUl9CWVRFUykpIHsKICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZs
b3c+OjppdGVyYXRvciBvbGRlc3QgPSBmbG93cy5iZWdpbigpOwogICAgZm9yIChzdGQ6Om1hcDxG
bG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgaXQgPSBmbG93cy5iZWdpbigpOyBpdCAhPSBmbG93cy5l
bmQoKTsgKytpdCkgewogICAgICBpZiAoaXQtPnNlY29uZC50b3VjaGVkIDwgb2xkZXN0LT5zZWNv
bmQudG91Y2hlZCkgb2xkZXN0ID0gaXQ7CiAgICB9CiAgICBpZiAob2xkZXN0LT5zZWNvbmQuYXdh
aXRpbmdfd3NzZSkgewogICAgICBxdWV1ZV9yZXF1ZXN0KG9sZGVzdC0+c2Vjb25kLndzc2VfZXZl
bnQsIG9sZGVzdC0+Zmlyc3Quc19pcCwgb2xkZXN0LT5maXJzdC5zcG9ydCwKICAgICAgICAgICAg
ICAgICAgICBvbGRlc3QtPmZpcnN0LmRfaXAsIG9sZGVzdC0+Zmlyc3QuZHBvcnQsIHBlbmRpbmcs
IG9sZGVzdC0+c2Vjb25kLmZpcnN0X2J5dGVfbW9ub19tcywKICAgICAgICAgICAgICAgICAgICBv
bGRlc3QtPnNlY29uZC5nZW5lcmF0aW9uLCBvbGRlc3QtPnNlY29uZC5zeW5fc2Vlbik7CgogICAg
ICBvbGRlc3QtPnNlY29uZC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICB9CiAgICBvbGRlc3Qt
PnNlY29uZC5jbGVhcl9idWZmZXJzKCk7CiAgICBmbG93cy5lcmFzZShvbGRlc3QpOwogIH0KfQoK
c3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVf
dCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+
ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93
PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVu
ZGluZywKICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lX3QgcGNhcF9ub3cgPSAwLCBsb25n
IGxvbmcgcGNhcF9tb25vX25vdyA9IDApIHsKICAodm9pZClwb3J0czsKICBpZiAobiA8IDM0KSBy
ZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRv
aHMocmVhZF91MTYoYnVmICsgMTIpKTsKICBpZiAoZXQgPT0gRVRIX1BfODAyMVEpIHsgaWYgKG4g
PCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIDE2KSk7IG9mZiA9
IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNl
OwoKICB1bnNpZ25lZCBjaGFyIGlobCA9ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAq
IDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0KSAhPSA0IHx8IGlobCA8IDIwIHx8IGJ1ZltvZmYgKyA5
XSAhPSA2KSByZXR1cm4gZmFsc2U7CgogIC8vIFJlamVjdCBmcmFnbWVudGVkIElQIHBhY2tldHMg
KG5vbi1maXJzdCBmcmFnbWVudCBoYXMgZnJhZyBvZmZzZXQgPiAwKQogIHVpbnQxNl90IGZyYWcg
PSBudG9ocyhyZWFkX3UxNihidWYgKyBvZmYgKyA2KSk7CiAgaWYgKGZyYWcgJiAweDFmZmYpIHJl
dHVybiBmYWxzZTsKCiAgLy8gSVB2NCB0b3RhbCBsZW5ndGggdmFsaWRhdGlvbiBhbmQgdHJ1bmNh
dGlvbiBjaGVjawogIHVpbnQxNl90IGlwX3RvdGFsX2xlbiA9IG50b2hzKHJlYWRfdTE2KGJ1ZiAr
IG9mZiArIDIpKTsKICBib29sIGlzX3RydW5jYXRlZCA9IGZhbHNlOwogIGlmIChpcF90b3RhbF9s
ZW4gPiAwKSB7CiAgICBpZiAoaXBfdG90YWxfbGVuIDwgaWhsICsgMjApIHJldHVybiBmYWxzZTsK
ICAgIGlmIChuIC0gb2ZmIDwgaXBfdG90YWxfbGVuKSB7CiAgICAgIGlzX3RydW5jYXRlZCA9IHRy
dWU7CiAgICB9IGVsc2UgaWYgKG4gLSBvZmYgPiBpcF90b3RhbF9sZW4pIHsKICAgICAgbiA9IG9m
ZiArIGlwX3RvdGFsX2xlbjsgLy8gRXhjbHVkZSBFdGhlcm5ldCBwYWRkaW5nCiAgICB9CiAgfQoK
ICB1aW50MzJfdCBzX2lwID0gcmVhZF91MzIoYnVmICsgb2ZmICsgMTIpOwogIHVpbnQzMl90IGRf
aXAgPSByZWFkX3UzMihidWYgKyBvZmYgKyAxNik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwog
IGlmIChuIDwgdG8gKyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1bnNpZ25lZCBzcG9ydCA9IG50b2hz
KHJlYWRfdTE2KGJ1ZiArIHRvKSk7CiAgdW5zaWduZWQgZHBvcnQgPSBudG9ocyhyZWFkX3UxNihi
dWYgKyB0byArIDIpKTsKICB1aW50MzJfdCBzZXEgPSBudG9obChyZWFkX3UzMihidWYgKyB0byAr
IDQpKTsKICB1bnNpZ25lZCBkb2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYgKGRv
ZmYgPCAyMCB8fCBuIDwgdG8gKyBkb2ZmKSByZXR1cm4gZmFsc2U7CgogIHVuc2lnbmVkIGNoYXIg
dGNwX2ZsYWdzID0gYnVmW3RvICsgMTNdOwogIGNvbnN0IGNoYXIgKnBheWxvYWQgPSAoY29uc3Qg
Y2hhciAqKShidWYgKyB0byArIGRvZmYpOwogIHNpemVfdCBwbGVuID0gbiAtIHRvIC0gZG9mZjsK
CiAgdGltZV90IG5vdyA9IChwY2FwX25vdyA+IDApID8gcGNhcF9ub3cgOiB0aW1lKE5VTEwpOwog
IGxvbmcgbG9uZyBtb25vX25vdyA9IChwY2FwX21vbm9fbm93ID4gMCkgPyBwY2FwX21vbm9fbm93
IDogbm93X21vbm90b25pY19tcygpOwoKICBib29sIGRzdF9tb24gPSAoZHBvcnQgPCA2NTUzNikg
PyBnX21vbml0b3JlZF9wb3J0c1tkcG9ydF0gOiBmYWxzZTsKICBib29sIHNyY19tb24gPSAoc3Bv
cnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tzcG9ydF0gOiBmYWxzZTsKCiAgLy8gRGly
ZWN0aW9uIEE6IFNlcnZlciAtPiBDbGllbnQgUmVzcG9uc2UgUmVhc3NlbWJseQogIGlmIChzcmNf
bW9uICYmICFkc3RfbW9uKSB7CiAgICBGbG93S2V5IHJmazsKICAgIHJmay5zX2lwID0gc19pcDsg
cmZrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgcmZrLmRfaXAgPSBkX2lwOyByZmsuZHBv
cnQgPSAodWludDE2X3QpZHBvcnQ7CgogICAgaWYgKHRjcF9mbGFncyAmIDB4MDIpIHsgLy8gU1lO
IGZyb20gc2VydmVyCiAgICAgIGV2aWN0X29sZGVzdF9mbG93X2lmX25lZWRlZChmbG93cywgcGVu
ZGluZyk7CiAgICAgIEZsb3cgJnJmbCA9IGZsb3dzW3Jma107CiAgICAgIHJmbC5jbGVhcl9idWZm
ZXJzKCk7CiAgICAgIHJmbCA9IEZsb3coKTsKICAgICAgcmZsLmhhc19zZXEgPSB0cnVlOwogICAg
ICByZmwubmV4dF9zZXEgPSBzZXEgKyAxOwogICAgICByZmwuaXNfYnJva2VuID0gZmFsc2U7CiAg
ICAgIHJmbC50b3VjaGVkID0gbm93OwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICBpZiAo
cGxlbiA+IDApIHsKICAgICAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVkKGZsb3dzLCBwZW5k
aW5nKTsKICAgICAgRmxvdyAmcmZsID0gZmxvd3NbcmZrXTsKICAgICAgcmZsLnRvdWNoZWQgPSBu
b3c7CgogICAgICBpZiAoIXJmbC5oYXNfc2VxKSB7CiAgICAgICAgaWYgKChwbGVuID49IDUgJiYg
bWVtY21wKHBheWxvYWQsICJIVFRQLyIsIDUpID09IDApIHx8CiAgICAgICAgICAgIChwbGVuIDwg
NSAmJiBtZW1jbXAocGF5bG9hZCwgIkhUVFAvIiwgcGxlbikgPT0gMCkpIHsKICAgICAgICAgIHJm
bC5oYXNfc2VxID0gdHJ1ZTsKICAgICAgICAgIHJmbC5uZXh0X3NlcSA9IHNlcTsKICAgICAgICAg
IHJmbC5pc19icm9rZW4gPSBmYWxzZTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgaWYgKHJm
bC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAg
ICAgICAgIGJvb2wgZHVwID0gZmFsc2U7CiAgICAgICAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBp
IDwgcmZsLm9vby5zaXplKCk7ICsraSkgewogICAgICAgICAgICAgIGlmIChyZmwub29vW2ldLnNl
cSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgICAgICAgfQogICAgICAgICAg
ICBpZiAoIWR1cCkgewogICAgICAgICAgICAgIHJmbC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBs
ZW4pOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICByZXR1cm4gdHJ1ZTsKICAg
ICAgICB9CiAgICAgIH0KCiAgICAgIGludDMyX3QgZGlmZiA9IHNlcV9kaWZmKHNlcSwgcmZsLm5l
eHRfc2VxKTsKICAgICAgaWYgKGRpZmYgPT0gMCkgewogICAgICAgIGlmIChpc190cnVuY2F0ZWQp
IHsKICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgIH0gZWxzZSB7CiAgICAg
ICAgICBpZiAoIXJmbC5idWZfYXBwZW5kKHBheWxvYWQsIHBsZW4pKSByZXR1cm4gdHJ1ZTsKICAg
ICAgICAgIHJmbC5uZXh0X3NlcSArPSAodWludDMyX3QpcGxlbjsKICAgICAgICAgIGlmICghZHJh
aW5fb29vX3NlZ21lbnRzKHJmbCkpIHJldHVybiB0cnVlOwogICAgICAgIH0KICAgICAgfSBlbHNl
IGlmIChkaWZmIDwgMCkgewogICAgICAgIGludDMyX3Qgb3ZlcmxhcCA9IC1kaWZmOwogICAgICAg
IGlmICgoc2l6ZV90KW92ZXJsYXAgPCBwbGVuICYmICFpc190cnVuY2F0ZWQpIHsKICAgICAgICAg
IHNpemVfdCBmbGVuID0gcGxlbiAtIG92ZXJsYXA7CiAgICAgICAgICBpZiAoIXJmbC5idWZfYXBw
ZW5kKHBheWxvYWQgKyBvdmVybGFwLCBmbGVuKSkgcmV0dXJuIHRydWU7CiAgICAgICAgICByZmwu
bmV4dF9zZXEgKz0gKHVpbnQzMl90KWZsZW47CiAgICAgICAgICBpZiAoIWRyYWluX29vb19zZWdt
ZW50cyhyZmwpKSByZXR1cm4gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0gZWxzZSB7IC8vIGRpZmYg
PiAwCiAgICAgICAgaWYgKHJmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNf
dHJ1bmNhdGVkKSB7CiAgICAgICAgICBib29sIGR1cCA9IGZhbHNlOwogICAgICAgICAgZm9yIChz
aXplX3QgaSA9IDA7IGkgPCByZmwub29vLnNpemUoKTsgKytpKSB7CiAgICAgICAgICAgIGlmIChy
Zmwub29vW2ldLnNlcSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgICAgIH0K
ICAgICAgICAgIGlmICghZHVwKSB7CiAgICAgICAgICAgIHJmbC5vb29fcHVzaChzZXEsIHBheWxv
YWQsIHBsZW4pOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICByZmwuaXNf
YnJva2VuID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIC8vIFBhcnNlIGNvbXBsZXRl
IHJlc3BvbnNlcyBmcm9tIHJlYXNzZW1ibGVkIGJ1ZmZlciB1c2luZyBIVFRQIGZyYW1pbmcKICAg
ICAgd2hpbGUgKCFyZmwuYnVmLmVtcHR5KCkgJiYgIXJmbC5pc19icm9rZW4pIHsKICAgICAgICBp
ZiAocmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSKSB7CiAgICAgICAgICBzaXpl
X3QgZW5kID0gcmZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAgICAgaWYgKGVuZCA9PSBz
dGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPiBNQVhf
SEVBREVSX0JZVEVTKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAg
ICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBi
cmVhazsKICAgICAgICAgIH0KCiAgICAgICAgICBpZiAocmZsLmJ1Zi5jb21wYXJlKDAsIDUsICJI
VFRQLyIpICE9IDApIHsKICAgICAgICAgICAgc2l6ZV90IGhwb3MgPSByZmwuYnVmLmZpbmQoIkhU
VFAvIik7CiAgICAgICAgICAgIGlmIChocG9zID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IGhwb3Mg
PiBlbmQpIHsKICAgICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIGVuZCArIDQpOwogICAgICAg
ICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJmbC5idWZfZXJhc2Uo
MCwgaHBvcyk7CiAgICAgICAgICAgIGVuZCAtPSBocG9zOwogICAgICAgICAgfQoKICAgICAgICAg
IGludCBzdCA9IDA7IHNpemVfdCBjbCA9IDA7IGJvb2wgaGFzX2NsID0gZmFsc2UsIGlzX2NodW5r
ZWQgPSBmYWxzZSwgaXNfY2xvc2UgPSBmYWxzZTsKICAgICAgICAgIGlmICghcGFyc2VfcmVzcG9u
c2UocmZsLmJ1Zi5kYXRhKCksIGVuZCArIDIsICZzdCwgJmNsLCAmaGFzX2NsLCAmaXNfY2h1bmtl
ZCwgJmlzX2Nsb3NlKSkgewogICAgICAgICAgICAvLyBBbWJpZ3VvdXMgZnJhbWluZyAoY29uZmxp
Y3RpbmcgQ29udGVudC1MZW5ndGgsIGJhZCBzdGF0dXMsIGV0Yy4pLgogICAgICAgICAgICAvLyBE
aXNjYXJkIHRoZSBoZWFkZXIgYW5kIG1hcmsgdGhlIHN0cmVhbSBicm9rZW4gc28gYm9keSBieXRl
cyBhcmUKICAgICAgICAgICAgLy8gbm90IHJlLXNjYW5uZWQgYXMgYSBuZXcgcmVzcG9uc2Ug4oCT
IHByZXZlbnRzIGZhYnJpY2F0ZWQgc3RhdHVzZXMuCiAgICAgICAgICAgIHJmbC5jbGVhcl9idWZm
ZXJzKCk7CiAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVh
azsKICAgICAgICAgIH0KCiAgICAgICAgICBpZiAoc3QgPj0gMTAwICYmIHN0IDw9IDE5OSAmJiBz
dCAhPSAxMDEpIHsKICAgICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAg
ICAgICAgY29udGludWU7CiAgICAgICAgICB9CgogICAgICAgICAgUGFja2V0S2V5IHBrOwogICAg
ICAgICAgcGsuc19pcCA9IHNfaXA7IHBrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICAg
ICAgcGsuZF9pcCA9IGRfaXA7IHBrLmRwb3J0ID0gKHVpbnQxNl90KWRwb3J0OwogICAgICAgICAg
Ym9vbCB2ZXJpZmllZCA9IHJmbC5zeW5fc2VlbiB8fCAocmZsLmdlbmVyYXRpb24gPiAwKTsKICAg
ICAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0
b3IgcCA9CiAgICAgICAgICAgICAgaXNfY29ycmVsYXRpb25fZGlzYWJsZWQocGssIHZlcmlmaWVk
KSA/IHBlbmRpbmcuZW5kKCkgOiBwZW5kaW5nLmZpbmQocGspOwogICAgICAgICAgYm9vbCBpc19o
ZWFkID0gZmFsc2U7CgogICAgICAgICAgaWYgKHAgIT0gcGVuZGluZy5lbmQoKSAmJiAhcC0+c2Vj
b25kLmVtcHR5KCkpIHsKICAgICAgICAgICAgaWYgKHJmbC5nZW5lcmF0aW9uICE9IDAgJiYgcC0+
c2Vjb25kWzBdLmdlbmVyYXRpb24gIT0gMCAmJiBwLT5zZWNvbmRbMF0uZ2VuZXJhdGlvbiAhPSBy
ZmwuZ2VuZXJhdGlvbikgewogICAgICAgICAgICAgIC8vIEdlbmVyYXRpb24gbWlzbWF0Y2ghIFN0
YWxlIHJlcXVlc3QgZnJvbSBwcmV2aW91cyBjb25uZWN0aW9uLgogICAgICAgICAgICAgIGVtaXRf
ZXZlbnQocC0+c2Vjb25kWzBdLmV2KTsKICAgICAgICAgICAgICBpZiAoIXAtPnNlY29uZFswXS5p
c190b21ic3RvbmUgJiYgZ190b3RhbF9wZW5kaW5nX2NvdW50ID4gMCkgLS1nX3RvdGFsX3BlbmRp
bmdfY291bnQ7CiAgICAgICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigp
KTsKICAgICAgICAgICAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7
CiAgICAgICAgICAgIH0gZWxzZSBpZiAocC0+c2Vjb25kWzBdLmlzX3RvbWJzdG9uZSkgewogICAg
ICAgICAgICAgIC8vIExhdGUgcmVzcG9uc2UgZm9yIGV4cGlyZWQgcmVxdWVzdDogY29uc3VtZSB0
b21ic3RvbmUsIGRvIG5vdCBhdHRhY2ggdG8gbmV3ZXIgcmVxdWVzdHMKICAgICAgICAgICAgICBw
LT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkpOwogICAgICAgICAgICAgIGlmIChwLT5z
ZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICAgICAgfSBlbHNlIHsKICAg
ICAgICAgICAgICBFdmVudCBlID0gcC0+c2Vjb25kWzBdLmV2OwogICAgICAgICAgICAgIGlmIChl
Lm1ldGhvZCA9PSAiSEVBRCIpIGlzX2hlYWQgPSB0cnVlOwogICAgICAgICAgICAgIGUuc3RhdHVz
ID0gc3Q7CiAgICAgICAgICAgICAgZS5oYXNfc3RhdHVzID0gdHJ1ZTsKICAgICAgICAgICAgICBl
LmR1cmF0aW9uX21zID0gKGxvbmcpKG1vbm9fbm93IC0gcC0+c2Vjb25kWzBdLnN0YXJ0ZWRfbW9u
b19tcyk7CiAgICAgICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBlLmR1cmF0aW9uX21z
ID0gMDsKICAgICAgICAgICAgICBlLmhhc19kdXJhdGlvbiA9IHRydWU7CiAgICAgICAgICAgICAg
aWYgKGhhc19jbCkgewogICAgICAgICAgICAgICAgZS5yZXNwX2J5dGVzID0gKHVuc2lnbmVkKWNs
OwogICAgICAgICAgICAgICAgZS5oYXNfcmVzcCA9IHRydWU7CiAgICAgICAgICAgICAgfQogICAg
ICAgICAgICAgIGVtaXRfZXZlbnQoZSk7CiAgICAgICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAt
PnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgICAgICBpZiAoZ190b3RhbF9wZW5kaW5nX2NvdW50
ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgICAgICAgICAgaWYgKHAtPnNlY29u
ZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgICAgICB9CiAgICAgICAgICB9Cgog
ICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKCiAgICAgICAgICBpZiAoaXNfaGVh
ZCB8fCBzdCA9PSAyMDQgfHwgc3QgPT0gMzA0KSB7CiAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZs
b3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgfSBlbHNlIGlmIChpc19jaHVua2VkKSB7
CiAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTks7CiAgICAgICAg
ICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IHRydWU7CiAgICAgICAgICAgIHJmbC5jaHVua19y
ZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxl
ciA9IGZhbHNlOwogICAgICAgICAgICByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPSAwOwog
ICAgICAgICAgfSBlbHNlIGlmIChoYXNfY2wpIHsKICAgICAgICAgICAgaWYgKGNsID4gMCkgewog
ICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQk9EWTsKICAgICAgICAg
ICAgICByZmwuYm9keV9yZW1haW5pbmcgPSBjbDsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAg
ICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgICAg
fQogICAgICAgICAgfSBlbHNlIGlmIChpc19jbG9zZSkgewogICAgICAgICAgICByZmwuc3RhdGUg
PSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAg
ICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFk7CiAgICAgICAgICB9
CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CgogICAgICAgIGlmIChyZmwuc3RhdGUgPT0g
Rmxvdzo6SFRUUF9TVEFURV9CT0RZKSB7CiAgICAgICAgICBpZiAocmZsLmJ1Zi5lbXB0eSgpKSBi
cmVhazsKICAgICAgICAgIHNpemVfdCB0b19jb25zdW1lID0gKHJmbC5idWYuc2l6ZSgpIDwgcmZs
LmJvZHlfcmVtYWluaW5nKSA/IHJmbC5idWYuc2l6ZSgpIDogcmZsLmJvZHlfcmVtYWluaW5nOwog
ICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCB0b19jb25zdW1lKTsKICAgICAgICAgIHJmbC5ib2R5
X3JlbWFpbmluZyAtPSB0b19jb25zdW1lOwogICAgICAgICAgaWYgKHJmbC5ib2R5X3JlbWFpbmlu
ZyA9PSAwKSB7CiAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVS
OwogICAgICAgICAgfQogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQoKICAgICAgICBpZiAo
cmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTkspIHsKICAgICAgICAgIGlmIChyZmwu
YnVmLmVtcHR5KCkpIGJyZWFrOwogICAgICAgICAgaWYgKHJmbC5jaHVua19yZWFkaW5nX3RyYWls
ZXIpIHsKICAgICAgICAgICAgaWYgKHJmbC5idWYuc2l6ZSgpID49IDIgJiYgcmZsLmJ1ZlswXSA9
PSAnXHInICYmIHJmbC5idWZbMV0gPT0gJ1xuJykgewogICAgICAgICAgICAgIHJmbC5idWZfZXJh
c2UoMCwgMik7CiAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IGZhbHNl
OwogICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAg
ICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHNpemVfdCB0cl9l
bmQgPSByZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAgICAgICAgICAgIGlmICh0cl9lbmQgIT0g
c3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIHRyX2Vu
ZCArIDQpOwogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxzZTsK
ICAgICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAg
ICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAocmZsLmJ1Zi5z
aXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZl
cnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgfQog
ICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICAgIGlmIChyZmwuY2h1bmtfcmVh
ZGluZ19sZW4pIHsKICAgICAgICAgICAgc2l6ZV90IGNybGYgPSByZmwuYnVmLmZpbmQoIlxyXG4i
KTsKICAgICAgICAgICAgaWYgKGNybGYgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAg
ICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPiA2NCkgewogICAgICAgICAgICAgICAgcmZsLmNsZWFy
X2J1ZmZlcnMoKTsKICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAg
ICAgICAgIH0KICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgfQogICAgICAgICAgICBz
dGQ6OnN0cmluZyBsaW5lID0gdHJpbShyZmwuYnVmLnN1YnN0cigwLCBjcmxmKSk7CiAgICAgICAg
ICAgIHNpemVfdCBzZW1pID0gbGluZS5maW5kKCc7Jyk7CiAgICAgICAgICAgIHN0ZDo6c3RyaW5n
IGhleF9zdHIgPSAoc2VtaSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgPyB0cmltKGxpbmUuc3Vic3Ry
KDAsIHNlbWkpKSA6IGxpbmU7CiAgICAgICAgICAgIGlmIChoZXhfc3RyLmVtcHR5KCkgfHwgaGV4
X3N0ci5zaXplKCkgPiAxNikgewogICAgICAgICAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAg
ICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgICAgYnJlYWs7CiAg
ICAgICAgICAgIH0KICAgICAgICAgICAgYm9vbCB2YWxpZF9oZXggPSB0cnVlOwogICAgICAgICAg
ICBmb3IgKHNpemVfdCBoaSA9IDA7IGhpIDwgaGV4X3N0ci5zaXplKCk7ICsraGkpIHsKICAgICAg
ICAgICAgICBpZiAoIWlzeGRpZ2l0KCh1bnNpZ25lZCBjaGFyKWhleF9zdHJbaGldKSkgeyB2YWxp
ZF9oZXggPSBmYWxzZTsgYnJlYWs7IH0KICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIXZh
bGlkX2hleCkgewogICAgICAgICAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAg
ICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAg
IH0KICAgICAgICAgICAgY2hhciAqZW5kcHRyID0gTlVMTDsKICAgICAgICAgICAgZXJybm8gPSAw
OwogICAgICAgICAgICB1bnNpZ25lZCBsb25nIGxvbmcgcGFyc2VkX2xlbiA9IHN0cnRvdWxsKGhl
eF9zdHIuY19zdHIoKSwgJmVuZHB0ciwgMTYpOwogICAgICAgICAgICBpZiAoZXJybm8gIT0gMCB8
fCBlbmRwdHIgIT0gaGV4X3N0ci5jX3N0cigpICsgaGV4X3N0ci5zaXplKCkgfHwgcGFyc2VkX2xl
biA+IDE2Nzc3MjE2VUxMKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAg
ICAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgICBicmVhazsKICAg
ICAgICAgICAgfQogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIGNybGYgKyAyKTsKICAgICAg
ICAgICAgaWYgKHBhcnNlZF9sZW4gPT0gMCkgewogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFk
aW5nX3RyYWlsZXIgPSB0cnVlOwogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9
IGZhbHNlOwogICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9IGVsc2UgewogICAg
ICAgICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IChzaXplX3QpcGFyc2VkX2xl
bjsKICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsKICAgICAgICAg
ICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFsc2U7CiAgICAgICAgICAgIH0KICAgICAg
ICAgIH0gZWxzZSBpZiAocmZsLmNodW5rX3JlYWRpbmdfY3JsZikgewogICAgICAgICAgICBpZiAo
cmZsLmJ1Zi5zaXplKCkgPCAyKSBicmVhazsKICAgICAgICAgICAgaWYgKHJmbC5idWZbMF0gIT0g
J1xyJyB8fCByZmwuYnVmWzFdICE9ICdcbicpIHsKICAgICAgICAgICAgICByZmwuY2xlYXJfYnVm
ZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICAg
IGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgMik7CiAg
ICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgICAgcmZs
LmNodW5rX3JlYWRpbmdfbGVuID0gdHJ1ZTsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAg
IHNpemVfdCB0b19jb25zdW1lID0gKHJmbC5idWYuc2l6ZSgpIDwgcmZsLmNodW5rX3BheWxvYWRf
cmVtYWluaW5nKSA/IHJmbC5idWYuc2l6ZSgpIDogcmZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5n
OwogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIHRvX2NvbnN1bWUpOwogICAgICAgICAgICBy
ZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgLT0gdG9fY29uc3VtZTsKICAgICAgICAgICAgaWYg
KHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9PSAwKSB7CiAgICAgICAgICAgICAgcmZsLmNo
dW5rX3JlYWRpbmdfY3JsZiA9IHRydWU7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAg
ICAgIGNvbnRpbnVlOwogICAgICAgIH0KCiAgICAgICAgaWYgKHJmbC5zdGF0ZSA9PSBGbG93OjpI
VFRQX1NUQVRFX0NMT1NFX0JPRFkpIHsKICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgcmZsLmJ1
Zi5zaXplKCkpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICB9CiAgICB9CgogICAg
aWYgKHRjcF9mbGFncyAmIDB4MDUpIHsgLy8gU2VydmVyIEZJTiBvciBSU1QKICAgICAgc3RkOjpt
YXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGl0ID0gZmxvd3MuZmluZChyZmspOwogICAgICBp
ZiAoaXQgIT0gZmxvd3MuZW5kKCkpIHsKICAgICAgICBpdC0+c2Vjb25kLmNsZWFyX2J1ZmZlcnMo
KTsKICAgICAgICBmbG93cy5lcmFzZShpdCk7CiAgICAgIH0KICAgIH0KICAgIHJldHVybiB0cnVl
OwogIH0KCiAgLy8gRGlyZWN0aW9uIEI6IENsaWVudCAtPiBTZXJ2ZXIgUmVxdWVzdCBSZWFzc2Vt
Ymx5CiAgaWYgKCFkc3RfbW9uKSB7CiAgICBpZiAodGNwX2ZsYWdzICYgMHgwNSkgewogICAgICBG
bG93S2V5IHJmazsgcmZrLnNfaXAgPSBkX2lwOyByZmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7
IHJmay5kX2lwID0gc19pcDsgcmZrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICBzdGQ6
Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgaXQgPSBmbG93cy5maW5kKHJmayk7CiAgICAg
IGlmIChpdCAhPSBmbG93cy5lbmQoKSkgewogICAgICAgIGl0LT5zZWNvbmQuY2xlYXJfYnVmZmVy
cygpOwogICAgICAgIGZsb3dzLmVyYXNlKGl0KTsKICAgICAgfQogICAgfQogICAgcmV0dXJuIGZh
bHNlOwogIH0KCiAgRmxvd0tleSBmazsKICBmay5zX2lwID0gc19pcDsgZmsuc3BvcnQgPSAodWlu
dDE2X3Qpc3BvcnQ7IGZrLmRfaXAgPSBkX2lwOyBmay5kcG9ydCA9ICh1aW50MTZfdClkcG9ydDsK
CiAgaWYgKHRjcF9mbGFncyAmIDB4MDIpIHsgLy8gU1lOIGZyb20gY2xpZW50OiBuZXcgY29ubmVj
dGlvbiBnZW5lcmF0aW9uIQogICAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVkKGZsb3dzLCBw
ZW5kaW5nKTsKICAgIFBhY2tldEtleSByazsgcmsuc19pcCA9IGRfaXA7IHJrLnNwb3J0ID0gKHVp
bnQxNl90KWRwb3J0OyByay5kX2lwID0gc19pcDsgcmsuZHBvcnQgPSAodWludDE2X3Qpc3BvcnQ7
CgogICAgLy8gUHVyZ2UgcHJldmlvdXMgZ2VuZXJhdGlvbidzIHBlbmRpbmcgcmVxdWVzdHMgZm9y
IHRoaXMgNC10dXBsZQogICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5n
PiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKHJrKTsKICAgIGlmIChwICE9IHBlbmRpbmcu
ZW5kKCkpIHsKICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBwLT5zZWNvbmQuc2l6ZSgpOyAr
K2kpIHsKICAgICAgICBpZiAoIXAtPnNlY29uZFtpXS5pc190b21ic3RvbmUpIHsKICAgICAgICAg
IGVtaXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgICAgICAgIGlmIChnX3RvdGFsX3BlbmRp
bmdfY291bnQgPiAwKSAtLWdfdG90YWxfcGVuZGluZ19jb3VudDsKICAgICAgICB9CiAgICAgIH0K
ICAgICAgcGVuZGluZy5lcmFzZShwKTsKICAgIH0KICAgIC8vIFJlLWVuYWJsZSBjb3JyZWxhdGlv
biBmb3IgdGhpcyA0LXR1cGxlOiBTWU4gcHJvdmVzIGEgZnJlc2ggVENQIGNvbm5lY3Rpb24KICAg
IC8vIHdpdGggbm8gYW1iaWd1b3VzIG9yZGVyaW5nIHN0YXRlIGZyb20gdGhlIHByZXZpb3VzIHN0
cmVhbS4KICAgIGNvcnJfZGlzYWJsZWRfZXJhc2UocmspOwoKICAgIEZsb3cgJmZsID0gZmxvd3Nb
ZmtdOwogICAgaWYgKGZsLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgaWYgKCFmbC53c3NlX2V2ZW50
Lm1ldGhvZC5lbXB0eSgpKSB7CiAgICAgICAgZW1pdF9ldmVudChmbC53c3NlX2V2ZW50KTsKICAg
ICAgfQogICAgICBmbC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICB9CiAgICB1aW50MzJfdCBu
ZXh0X2dlbiA9IGZsLmdlbmVyYXRpb24gKyAxOwogICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAg
ZmwgPSBGbG93KCk7CiAgICBmbC5nZW5lcmF0aW9uID0gbmV4dF9nZW47CiAgICBmbC5zeW5fc2Vl
biA9IHRydWU7CiAgICBmbC5oYXNfc2VxID0gdHJ1ZTsKICAgIGZsLm5leHRfc2VxID0gc2VxICsg
MTsKICAgIGZsLnRvdWNoZWQgPSBub3c7CiAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSAwOwoK
ICAgIC8vIFJlc2V0IHNlcnZlciByZXNwb25zZSBmbG93IGZvciB0aGlzIDQtdHVwbGUgYW5kIGNh
cnJ5IGZvcndhcmQgbmV3IGdlbmVyYXRpb24KICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+Ojpp
dGVyYXRvciByZml0ID0gZmxvd3MuZmluZChyayk7CiAgICBpZiAocmZpdCAhPSBmbG93cy5lbmQo
KSkgewogICAgICByZml0LT5zZWNvbmQuY2xlYXJfYnVmZmVycygpOwogICAgfQogICAgRmxvdyAm
cmVzcF9mbCA9IGZsb3dzW3JrXTsKICAgIHJlc3BfZmwgPSBGbG93KCk7CiAgICByZXNwX2ZsLmdl
bmVyYXRpb24gPSBuZXh0X2dlbjsKICAgIHJlc3BfZmwuc3luX3NlZW4gPSB0cnVlOwogICAgcmV0
dXJuIHRydWU7CgogIH0KCiAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVkKGZsb3dzLCBwZW5k
aW5nKTsKICBGbG93ICZmbCA9IGZsb3dzW2ZrXTsKICBmbC50b3VjaGVkID0gbm93OwoKICBpZiAo
cGxlbiA+IDApIHsKICAgIGlmICghZmwuaGFzX3NlcSkgewogICAgICBpZiAoaXNfbWV0aG9kX29y
X3ByZWZpeChwYXlsb2FkLCBwbGVuKSkgewogICAgICAgIGZsLmhhc19zZXEgPSB0cnVlOwogICAg
ICAgIGZsLm5leHRfc2VxID0gc2VxOwogICAgICAgIGZsLmlzX2Jyb2tlbiA9IGZhbHNlOwogICAg
ICB9IGVsc2UgewogICAgICAgIGlmIChmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAm
JiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICBib29sIGR1cCA9IGZhbHNlOwogICAgICAgICAg
Zm9yIChzaXplX3QgaSA9IDA7IGkgPCBmbC5vb28uc2l6ZSgpOyArK2kpIHsKICAgICAgICAgICAg
aWYgKGZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9IHRydWU7IGJyZWFrOyB9CiAgICAgICAg
ICB9CiAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAgICBmbC5vb29fcHVzaChzZXEsIHBh
eWxvYWQsIHBsZW4pOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICByZXR1cm4gdHJ1ZTsK
ICAgICAgfQogICAgfQoKICAgIGludDMyX3QgZGlmZiA9IHNlcV9kaWZmKHNlcSwgZmwubmV4dF9z
ZXEpOwogICAgaWYgKGRpZmYgPT0gMCkgewogICAgICBpZiAoaXNfdHJ1bmNhdGVkKSB7CiAgICAg
ICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgfSBlbHNlIHsKICAgICAgICBpZiAoIWZsLmJ1
Zl9hcHBlbmQocGF5bG9hZCwgcGxlbikpIHJldHVybiB0cnVlOwogICAgICAgIGZsLm5leHRfc2Vx
ICs9ICh1aW50MzJfdClwbGVuOwogICAgICAgIGlmICghZHJhaW5fb29vX3NlZ21lbnRzKGZsKSkg
cmV0dXJuIHRydWU7CiAgICAgIH0KICAgIH0gZWxzZSBpZiAoZGlmZiA8IDApIHsKICAgICAgaW50
MzJfdCBvdmVybGFwID0gLWRpZmY7CiAgICAgIGlmICgoc2l6ZV90KW92ZXJsYXAgPCBwbGVuICYm
ICFpc190cnVuY2F0ZWQpIHsKICAgICAgICBzaXplX3QgZmxlbiA9IHBsZW4gLSBvdmVybGFwOwog
ICAgICAgIGlmICghZmwuYnVmX2FwcGVuZChwYXlsb2FkICsgb3ZlcmxhcCwgZmxlbikpIHJldHVy
biB0cnVlOwogICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClmbGVuOwogICAgICAgIGlm
ICghZHJhaW5fb29vX3NlZ21lbnRzKGZsKSkgcmV0dXJuIHRydWU7CiAgICAgIH0KICAgIH0gZWxz
ZSB7IC8vIGRpZmYgPiAwIChvdXQgb2Ygb3JkZXIgZ2FwKQogICAgICBpZiAoZmwub29vLnNpemUo
KSA8IE1BWF9PT09fU0VHTUVOVFMgJiYgIWlzX3RydW5jYXRlZCkgewogICAgICAgIGJvb2wgZHVw
ID0gZmFsc2U7CiAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBmbC5vb28uc2l6ZSgpOyAr
K2kpIHsKICAgICAgICAgIGlmIChmbC5vb29baV0uc2VxID09IHNlcSkgeyBkdXAgPSB0cnVlOyBi
cmVhazsgfQogICAgICAgIH0KICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAgZmwub29vX3B1
c2goc2VxLCBwYXlsb2FkLCBwbGVuKTsKICAgICAgICB9CiAgICAgIH0gZWxzZSB7CiAgICAgICAg
ZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgfQogICAgfQoKICAgIC8vIEhUVFAgRnJhbWluZyBT
dGF0ZSBNYWNoaW5lIGZvciByZXF1ZXN0cwogICAgd2hpbGUgKCFmbC5idWYuZW1wdHkoKSAmJiAh
ZmwuaXNfYnJva2VuKSB7CiAgICAgIGlmIChmbC5zdGF0ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0hF
QURFUikgewogICAgICAgIGlmICghZmwuZmlyc3RfYnl0ZV9tb25vX21zKSBmbC5maXJzdF9ieXRl
X21vbm9fbXMgPSBtb25vX25vdzsKCiAgICAgICAgc2l6ZV90IGVuZCA9IGZsLmJ1Zi5maW5kKCJc
clxuXHJcbiIpOwogICAgICAgIGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAg
ICAgIGlmIChmbC5idWYuc2l6ZSgpID4gTUFYX0hFQURFUl9CWVRFUykgewogICAgICAgICAgICBm
bC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAg
ICAgICB9CiAgICAgICAgICBicmVhazsKICAgICAgICB9CgogICAgICAgIHNpemVfdCBzdGFydCA9
IGZpbmRfaHR0cF9zdGFydChmbC5idWYpOwogICAgICAgIGlmIChzdGFydCA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcyB8fCBzdGFydCA+IGVuZCkgewogICAgICAgICAgZmwuYnVmX2VyYXNlKDAsIGVuZCAr
IDQpOwogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQogICAgICAgIGlmIChzdGFydCA+IDAp
IHsKICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBzdGFydCk7CiAgICAgICAgICBlbmQgLT0gc3Rh
cnQ7CiAgICAgICAgfQoKICAgICAgICBFdmVudCBlOyBSZXF1ZXN0TWV0YSBtZXRhOwogICAgICAg
IGUudHMgPSBub3c7IGUuaG9zdCA9IG5vZGU7IGUuc2VydmljZSA9ICJwb3J0OiIgKyBudW0oZHBv
cnQpOwogICAgICAgIGUuY2FsbGVyID0gaXBfdG9fc3RyKHNfaXApOyBlLmNhbGxlcl9wb3J0ID0g
c3BvcnQ7CiAgICAgICAgZS5kc3RfaXAgPSBpcF90b19zdHIoZF9pcCk7IGUuZHN0X3BvcnQgPSBk
cG9ydDsKICAgICAgICBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZCkoZW5kICsgNCk7CgogICAgICAg
IGlmICghcGFyc2VfcmVxdWVzdChmbC5idWYuZGF0YSgpLCBlbmQgKyAyLCAmZSwgJm1ldGEpKSB7
CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgZW5kICsgNCk7CiAgICAgICAgICBjb250aW51ZTsK
ICAgICAgICB9CgogICAgICAgIC8vIFJlamVjdCBjb25mbGljdGluZyBDb250ZW50LUxlbmd0aCAr
IGNodW5rZWQgZW5jb2RpbmcgKFJGQyA3MjMwIHJlcXVlc3Qgc211Z2dsaW5nIHByZXZlbnRpb24p
CiAgICAgICAgYm9vbCBoYXNfY2h1bmtlZCA9IChsb3dlcihtZXRhLnRyYW5zZmVyX2VuY29kaW5n
KS5maW5kKCJjaHVua2VkIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpOwogICAgICAgIGlmIChtZXRh
Lmhhc19jb25mbGljdF9jbCB8fCAobWV0YS5oYXNfY29udGVudF9sZW5ndGggJiYgaGFzX2NodW5r
ZWQpKSB7CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgZW5kICsgNCk7CiAgICAgICAgICBmbC5j
bGVhcl9idWZmZXJzKCk7CiAgICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAg
YnJlYWs7CiAgICAgICAgfQoKICAgICAgICBmbC5idWZfZXJhc2UoMCwgZW5kICsgNCk7CgogICAg
ICAgIGJvb2wgd3NzZV9lbGlnaWJsZSA9IChnX3dzc2VfYm9keV9ieXRlcyA+IDAgJiYKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgaXNfc29hcF9jb250ZW50X3R5cGUobWV0YS5jb250ZW50
X3R5cGUpICYmCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1ldGEuaGFzX2NvbnRlbnRf
bGVuZ3RoICYmCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1ldGEuY29udGVudF9sZW5n
dGggPiAwICYmCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICFoYXNfY2h1bmtlZCAmJgog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3RpdmVfd3NzZV9mbG93cyhmbG93cykgPCBN
QVhfV1NTRV9CT0RZX0ZMT1dTKTsKCiAgICAgICAgaWYgKHdzc2VfZWxpZ2libGUpIHsKICAgICAg
ICAgIGZsLmF3YWl0aW5nX3dzc2UgPSB0cnVlOwogICAgICAgICAgZmwud3NzZV9ldmVudCA9IGU7
CiAgICAgICAgICBmbG93X2J5dGVzX3N1YihmbC53c3NlX2J1Zi5zaXplKCkpOwogICAgICAgICAg
Zmwud3NzZV9idWYuY2xlYXIoKTsKICAgICAgICAgIGZsLndzc2VfZ29hbCA9IG1ldGEuY29udGVu
dF9sZW5ndGggPCBnX3dzc2VfYm9keV9ieXRlcyA/IG1ldGEuY29udGVudF9sZW5ndGggOiBnX3dz
c2VfYm9keV9ieXRlczsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgcXVldWVfcmVxdWVzdChl
LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcsIGZsLmZpcnN0X2J5dGVfbW9ub19t
cywgZmwuZ2VuZXJhdGlvbiwgZmwuc3luX3NlZW4pOwogICAgICAgIH0KCiAgICAgICAgaWYgKG1l
dGEuaGFzX2NvbnRlbnRfbGVuZ3RoICYmIG1ldGEuY29udGVudF9sZW5ndGggPiAwKSB7CiAgICAg
ICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQk9EWTsKICAgICAgICAgIGZsLmJvZHlf
cmVtYWluaW5nID0gbWV0YS5jb250ZW50X2xlbmd0aDsKICAgICAgICB9IGVsc2UgaWYgKGhhc19j
aHVua2VkKSB7CiAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTks7CiAg
ICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xlbiA9IHRydWU7CiAgICAgICAgICBmbC5jaHVua19y
ZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9
IGZhbHNlOwogICAgICAgICAgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPSAwOwogICAgICAg
IH0gZWxzZSB7CiAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwog
ICAgICAgICAgZmwuZmlyc3RfYnl0ZV9tb25vX21zID0gZmwuYnVmLmVtcHR5KCkgPyAwIDogbW9u
b19ub3c7CiAgICAgICAgfQogICAgICAgIGNvbnRpbnVlOwogICAgICB9CgogICAgICBpZiAoZmwu
c3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFURV9CT0RZKSB7CiAgICAgICAgaWYgKGZsLmJ1Zi5lbXB0
eSgpKSBicmVhazsKICAgICAgICBzaXplX3QgdG9fY29uc3VtZSA9IChmbC5idWYuc2l6ZSgpIDwg
ZmwuYm9keV9yZW1haW5pbmcpID8gZmwuYnVmLnNpemUoKSA6IGZsLmJvZHlfcmVtYWluaW5nOwoK
ICAgICAgICBpZiAoZmwuYXdhaXRpbmdfd3NzZSkgewogICAgICAgICAgc2l6ZV90IHdzc2VfbmVl
ZCA9IGZsLndzc2VfZ29hbCA+IGZsLndzc2VfYnVmLnNpemUoKSA/IGZsLndzc2VfZ29hbCAtIGZs
Lndzc2VfYnVmLnNpemUoKSA6IDA7CiAgICAgICAgICBpZiAod3NzZV9uZWVkID4gMCkgewogICAg
ICAgICAgICBzaXplX3QgY29weV9sZW4gPSAodG9fY29uc3VtZSA8IHdzc2VfbmVlZCkgPyB0b19j
b25zdW1lIDogd3NzZV9uZWVkOwogICAgICAgICAgICBmbC53c3NlX2FwcGVuZChmbC5idWYuZGF0
YSgpLCBjb3B5X2xlbik7CiAgICAgICAgICB9CiAgICAgICAgICBzdGQ6OnN0cmluZyB1c2VybmFt
ZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC53c3NlX2J1Zik7CiAgICAgICAgICBpZiAoIXVz
ZXJuYW1lLmVtcHR5KCkgfHwgZmwud3NzZV9idWYuc2l6ZSgpID49IGZsLndzc2VfZ29hbCkgewog
ICAgICAgICAgICBFdmVudCBldiA9IGZsLndzc2VfZXZlbnQ7CiAgICAgICAgICAgIGlmICghdXNl
cm5hbWUuZW1wdHkoKSkgewogICAgICAgICAgICAgIGV2Lndzc2VfdXNlciA9IHVzZXJuYW1lOyBl
di51c2VyID0gdXNlcm5hbWU7IGV2LnNjaGVtZSA9ICJ3c3NlIjsKICAgICAgICAgICAgfQogICAg
ICAgICAgICBxdWV1ZV9yZXF1ZXN0KGV2LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRp
bmcsIGZsLmZpcnN0X2J5dGVfbW9ub19tcywgZmwuZ2VuZXJhdGlvbiwgZmwuc3luX3NlZW4pOwog
ICAgICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICAgICAgICB9CiAgICAgICAg
fQoKICAgICAgICBmbC5idWZfZXJhc2UoMCwgdG9fY29uc3VtZSk7CiAgICAgICAgZmwuYm9keV9y
ZW1haW5pbmcgLT0gdG9fY29uc3VtZTsKICAgICAgICBpZiAoZmwuYm9keV9yZW1haW5pbmcgPT0g
MCkgewogICAgICAgICAgaWYgKGZsLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgICAgICAgcXVldWVf
cmVxdWVzdChmbC53c3NlX2V2ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcs
IGZsLmZpcnN0X2J5dGVfbW9ub19tcywgZmwuZ2VuZXJhdGlvbiwgZmwuc3luX3NlZW4pOwogICAg
ICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICAgICAgICB9CiAgICAgICAgICBm
bC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwoKICAgICAgICAgIGZsLmZpcnN0X2J5
dGVfbW9ub19tcyA9IGZsLmJ1Zi5lbXB0eSgpID8gMCA6IG1vbm9fbm93OwogICAgICAgIH0KICAg
ICAgICBjb250aW51ZTsKICAgICAgfQoKICAgICAgaWYgKGZsLnN0YXRlID09IEZsb3c6OkhUVFBf
U1RBVEVfQ0hVTkspIHsKICAgICAgICBpZiAoZmwuYnVmLmVtcHR5KCkpIGJyZWFrOwogICAgICAg
IGlmIChmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIpIHsKICAgICAgICAgIGlmIChmbC5idWYuc2l6
ZSgpID49IDIgJiYgZmwuYnVmWzBdID09ICdccicgJiYgZmwuYnVmWzFdID09ICdcbicpIHsKICAg
ICAgICAgICAgZmwuYnVmX2VyYXNlKDAsIDIpOwogICAgICAgICAgICBmbC5jaHVua19yZWFkaW5n
X3RyYWlsZXIgPSBmYWxzZTsKICAgICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRF
X0hFQURFUjsKICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV9tb25vX21zID0gZmwuYnVmLmVtcHR5
KCkgPyAwIDogbW9ub19ub3c7CiAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgfQogICAg
ICAgICAgc2l6ZV90IHRyX2VuZCA9IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAgICAg
aWYgKHRyX2VuZCAhPSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgICBmbC5idWZfZXJh
c2UoMCwgdHJfZW5kICsgNCk7CiAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9
IGZhbHNlOwogICAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwog
ICAgICAgICAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSBmbC5idWYuZW1wdHkoKSA/IDAgOiBt
b25vX25vdzsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICB9CiAgICAgICAgICBpZiAo
ZmwuYnVmLnNpemUoKSA+IE1BWF9IRUFERVJfQllURVMpIHsKICAgICAgICAgICAgZmwuY2xlYXJf
YnVmZmVycygpOwogICAgICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgfQog
ICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICAgIGlmIChmbC5jaHVua19yZWFkaW5nX2xl
bikgewogICAgICAgICAgc2l6ZV90IGNybGYgPSBmbC5idWYuZmluZCgiXHJcbiIpOwogICAgICAg
ICAgaWYgKGNybGYgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgaWYgKGZsLmJ1
Zi5zaXplKCkgPiA2NCkgewogICAgICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAg
ICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGJy
ZWFrOwogICAgICAgICAgfQogICAgICAgICAgc3RkOjpzdHJpbmcgbGluZSA9IHRyaW0oZmwuYnVm
LnN1YnN0cigwLCBjcmxmKSk7CiAgICAgICAgICBzaXplX3Qgc2VtaSA9IGxpbmUuZmluZCgnOycp
OwogICAgICAgICAgc3RkOjpzdHJpbmcgaGV4X3N0ciA9IChzZW1pICE9IHN0ZDo6c3RyaW5nOjpu
cG9zKSA/IHRyaW0obGluZS5zdWJzdHIoMCwgc2VtaSkpIDogbGluZTsKICAgICAgICAgIGlmICho
ZXhfc3RyLmVtcHR5KCkgfHwgaGV4X3N0ci5zaXplKCkgPiAxNikgewogICAgICAgICAgICBmbC5j
bGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAg
ICAgIGJyZWFrOwogICAgICAgICAgfQogICAgICAgICAgYm9vbCB2YWxpZF9oZXggPSB0cnVlOwog
ICAgICAgICAgZm9yIChzaXplX3QgaGkgPSAwOyBoaSA8IGhleF9zdHIuc2l6ZSgpOyArK2hpKSB7
CiAgICAgICAgICAgIGlmICghaXN4ZGlnaXQoKHVuc2lnbmVkIGNoYXIpaGV4X3N0cltoaV0pKSB7
IHZhbGlkX2hleCA9IGZhbHNlOyBicmVhazsgfQogICAgICAgICAgfQogICAgICAgICAgaWYgKCF2
YWxpZF9oZXgpIHsKICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICBm
bC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAg
ICAgIGNoYXIgKmVuZHB0ciA9IE5VTEw7CiAgICAgICAgICBlcnJubyA9IDA7CiAgICAgICAgICB1
bnNpZ25lZCBsb25nIGxvbmcgcGFyc2VkX2xlbiA9IHN0cnRvdWxsKGhleF9zdHIuY19zdHIoKSwg
JmVuZHB0ciwgMTYpOwogICAgICAgICAgaWYgKGVycm5vICE9IDAgfHwgZW5kcHRyICE9IGhleF9z
dHIuY19zdHIoKSArIGhleF9zdHIuc2l6ZSgpIHx8IHBhcnNlZF9sZW4gPiAxNjc3NzIxNlVMTCkg
ewogICAgICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZsLmlzX2Jyb2tl
biA9IHRydWU7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgfQogICAgICAgICAgZmwuYnVm
X2VyYXNlKDAsIGNybGYgKyAyKTsKICAgICAgICAgIGlmIChwYXJzZWRfbGVuID09IDApIHsKICAg
ICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gdHJ1ZTsKICAgICAgICAgICAgZmwu
Y2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAg
ICB9IGVsc2UgewogICAgICAgICAgICBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IChzaXpl
X3QpcGFyc2VkX2xlbjsKICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsK
ICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFsc2U7CiAgICAgICAgICB9CiAg
ICAgICAgfSBlbHNlIGlmIChmbC5jaHVua19yZWFkaW5nX2NybGYpIHsKICAgICAgICAgIGlmIChm
bC5idWYuc2l6ZSgpIDwgMikgYnJlYWs7CiAgICAgICAgICBpZiAoZmwuYnVmWzBdICE9ICdccicg
fHwgZmwuYnVmWzFdICE9ICdcbicpIHsKICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwog
ICAgICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAg
ICAgIH0KICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCAyKTsKICAgICAgICAgIGZsLmNodW5rX3Jl
YWRpbmdfY3JsZiA9IGZhbHNlOwogICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSB0cnVl
OwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzaXplX3QgdG9fY29uc3VtZSA9IChmbC5idWYu
c2l6ZSgpIDwgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcpID8gZmwuYnVmLnNpemUoKSA6IGZs
LmNodW5rX3BheWxvYWRfcmVtYWluaW5nOwogICAgICAgICAgZmwuYnVmX2VyYXNlKDAsIHRvX2Nv
bnN1bWUpOwogICAgICAgICAgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgLT0gdG9fY29uc3Vt
ZTsKICAgICAgICAgIGlmIChmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9PSAwKSB7CiAgICAg
ICAgICAgIGZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IHRydWU7CiAgICAgICAgICB9CiAgICAgICAg
fQogICAgICAgIGNvbnRpbnVlOwogICAgICB9CiAgICB9CiAgfQoKICAvLyBGSU4gLyBSU1QgTGlm
ZWN5Y2xlOiBwcm9jZXNzIGFmdGVyIHBheWxvYWQKICBpZiAodGNwX2ZsYWdzICYgMHgwNSkgewog
ICAgaWYgKGZsLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgcXVldWVfcmVxdWVzdChmbC53c3NlX2V2
ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcsIGZsLmZpcnN0X2J5dGVfbW9u
b19tcywgZmwuZ2VuZXJhdGlvbiwgZmwuc3luX3NlZW4pOwogICAgICBmbC5hd2FpdGluZ193c3Nl
ID0gZmFsc2U7CiAgICB9CgogICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgZmxvd3MuZXJhc2Uo
ZmspOwogIH0KCiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIGF0dGFjaF9icGYoaW50IGZk
LCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgaWYgKHBvcnRzLmVtcHR5
KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OnZlY3RvcjxzdHJ1Y3Qgc29ja19maWx0ZXI+IGY7IHNp
emVfdCBpOwogIHVuc2lnbmVkIE4gPSAodW5zaWduZWQpcG9ydHMuc2l6ZSgpOwogIHVuc2lnbmVk
IHJlamVjdCA9IDExICsgTiAqIDg7CiAgdW5zaWduZWQgYWNjZXB0ID0gcmVqZWN0ICsgMTsKICBz
dHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmluZSBBREQoQyxKLFQsSykgZG8geyBcCiAgdW5zaWdu
ZWQgX2p0ID0gKHVuc2lnbmVkKShKKSwgX2pmID0gKHVuc2lnbmVkKShUKTsgXAogIGlmIChfanQg
PiBVQ0hBUl9NQVggfHwgX2pmID4gVUNIQVJfTUFYKSByZXR1cm4gZmFsc2U7IFwKICB4LmNvZGU9
KEMpOyB4Lmp0PSh1bnNpZ25lZCBjaGFyKV9qdDsgeC5qZj0odW5zaWduZWQgY2hhcilfamY7IHgu
az0oSyk7IFwKICBmLnB1c2hfYmFjayh4KTsgXAp9IHdoaWxlKDApCiAgQUREKEJQRl9MRHxCUEZf
SHxCUEZfQUJTLCAwLCAwLCAxMik7CiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgKHVuc2ln
bmVkKSg2ICsgNCAqIE4pLCAwLCBFVEhfUF9JUF9IT1NUKTsKCiAgLy8gUGF0aCBCOiA4MDIuMVEg
VkxBTgogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0g
KHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9QXzgwMjFRX0hPU1QpOwogIEFERChCUEZfTER8
QlBGX0h8QlBGX0FCUywgMCwgMCwgMTYpOwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAs
ICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9QX0lQX0hP
U1QpOwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjcpOwogIEFERChCUEZfSk1Q
fEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgp
IC0gMSksIElQUFJPVE9fVENQKTsKICBBREQoQlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAx
OCk7CiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xE
fEJQRl9IfEJQRl9JTkQsIDAsIDAsIDIwKTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVu
c2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCAw
LCBwb3J0c1tpXSk7CiAgfQogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewog
ICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAxOCk7CiAgICB1bnNpZ25lZCBqdCA9
IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwg
cG9ydHMuc2l6ZSgpIC0gMSkgPyAwIDogKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEp
OwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQoK
ICAvLyBQYXRoIEE6IFN0YW5kYXJkIElQdjQKICBBREQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsIDAs
IDAsIDIzKTsKICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVj
dCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJUFBST1RPX1RDUCk7CiAgQUREKEJQRl9MRFh8
QlBGX0J8QlBGX01TSCwgMCwgMCwgMTQpOwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7
ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAxNik7CiAgICB1bnNp
Z25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pN
UHxCUEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICBmb3IgKGkgPSAwOyBpIDwg
cG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwg
MTQpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwog
ICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAo
dW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0
LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIDApOwogIEFE
RChCUEZfUkVUfEJQRl9LLCAwLCAwLCBBQ0NFUFQpOwojdW5kZWYgQURECiAgaWYgKGYuc2l6ZSgp
ID4gNDA5NikgcmV0dXJuIGZhbHNlOwogIHN0cnVjdCBzb2NrX2Zwcm9nIHByb2c7IHByb2cubGVu
ID0gKHVuc2lnbmVkIHNob3J0KWYuc2l6ZSgpOyBwcm9nLmZpbHRlciA9ICZmWzBdOwogIHJldHVy
biBzZXRzb2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19BVFRBQ0hfRklMVEVSX09MRCwgJnByb2cs
IHNpemVvZihwcm9nKSkgPT0gMDsKfQoKc3RydWN0IE1tYXBSaW5nIHsKICB2b2lkICpyaW5nOwog
IHNpemVfdCByaW5nX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfc2l6ZTsKICB1bnNpZ25lZCBibG9j
a19ucjsKICB1bnNpZ25lZCBmcmFtZV9zaXplOwogIHVuc2lnbmVkIGZyYW1lX25yOwogIHVuc2ln
bmVkIGZyYW1lc19wZXJfYmxvY2s7CiAgdW5zaWduZWQgZnJhbWVfaWR4OwoKICBNbWFwUmluZygp
IDogcmluZyhNQVBfRkFJTEVEKSwgcmluZ19zaXplKDApLCBibG9ja19zaXplKDY1NTM2KSwgYmxv
Y2tfbnIoNjQpLAogICAgICAgICAgICAgICBmcmFtZV9zaXplKDIwNDgpLCBmcmFtZV9ucigyMDQ4
KSwgZnJhbWVzX3Blcl9ibG9jaygzMiksIGZyYW1lX2lkeCgwKSB7fQp9OwoKc3RhdGljIGJvb2wg
dmFsaWRfcmluZ19nZW9tZXRyeShjb25zdCBNbWFwUmluZyAmbXIpIHsKICBjb25zdCBzaXplX3Qg
c2l6ZV9tYXggPSAoc2l6ZV90KS0xOwogIGxvbmcgcGFnZV9zaXplID0gc3lzY29uZihfU0NfUEFH
RVNJWkUpOwogIGlmIChwYWdlX3NpemUgPD0gMCkgcmV0dXJuIGZhbHNlOwogIGlmIChtci5ibG9j
a19zaXplID09IDAgfHwgbXIuYmxvY2tfc2l6ZSAlICh1bnNpZ25lZCBsb25nKXBhZ2Vfc2l6ZSAh
PSAwKSByZXR1cm4gZmFsc2U7CiAgaWYgKG1yLmZyYW1lX3NpemUgPCBUUEFDS0VUMl9IRFJMRU4g
fHwKICAgICAgbXIuZnJhbWVfc2l6ZSAlIFRQQUNLRVRfQUxJR05NRU5UICE9IDApIHJldHVybiBm
YWxzZTsKICBpZiAobXIuYmxvY2tfc2l6ZSAlIG1yLmZyYW1lX3NpemUgIT0gMCkgcmV0dXJuIGZh
bHNlOwogIHVuc2lnbmVkIGZyYW1lc19wZXJfYmxvY2sgPSBtci5ibG9ja19zaXplIC8gbXIuZnJh
bWVfc2l6ZTsKICBpZiAoZnJhbWVzX3Blcl9ibG9jayA9PSAwIHx8IG1yLmJsb2NrX25yID09IDAp
IHJldHVybiBmYWxzZTsKICBpZiAoZnJhbWVzX3Blcl9ibG9jayA+IFVJTlRfTUFYIC8gbXIuYmxv
Y2tfbnIpIHJldHVybiBmYWxzZTsKICBpZiAoZnJhbWVzX3Blcl9ibG9jayAqIG1yLmJsb2NrX25y
ICE9IG1yLmZyYW1lX25yKSByZXR1cm4gZmFsc2U7CiAgaWYgKChzaXplX3QpbXIuYmxvY2tfc2l6
ZSA+IHNpemVfbWF4IC8gKHNpemVfdCltci5ibG9ja19ucikgcmV0dXJuIGZhbHNlOwogIGlmICgo
c2l6ZV90KW1yLmJsb2NrX3NpemUgKiAoc2l6ZV90KW1yLmJsb2NrX25yICE9IDRVICogMTAyNFUg
KiAxMDI0VSkgcmV0dXJuIGZhbHNlOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBzZXR1
cF9tbWFwX3JpbmcoaW50IGZkLCBNbWFwUmluZyAmbXIpIHsKICBpZiAoIXZhbGlkX3JpbmdfZ2Vv
bWV0cnkobXIpKSB7CiAgICBsb2dtc2coImludmFsaWQgZml4ZWQgVFBBQ0tFVF9WMiByaW5nIGdl
b21ldHJ5Iik7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIGludCB2ZXIgPSBUUEFDS0VUX1YyOwog
IGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfVkVSU0lPTiwgJnZlciwgc2l6
ZW9mKHZlcikpIDwgMCkgewogICAgcmV0dXJuIGZhbHNlOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9y
ZXEgcmVxOwogIG1lbXNldCgmcmVxLCAwLCBzaXplb2YocmVxKSk7CiAgcmVxLnRwX2Jsb2NrX3Np
emUgPSBtci5ibG9ja19zaXplOwogIHJlcS50cF9ibG9ja19uciA9IG1yLmJsb2NrX25yOwogIHJl
cS50cF9mcmFtZV9zaXplID0gbXIuZnJhbWVfc2l6ZTsKICByZXEudHBfZnJhbWVfbnIgPSBtci5m
cmFtZV9ucjsKCiAgaWYgKHNldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9SWF9SSU5H
LCAmcmVxLCBzaXplb2YocmVxKSkgPCAwKSB7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIG1yLnJp
bmdfc2l6ZSA9IChzaXplX3QpcmVxLnRwX2Jsb2NrX3NpemUgKiAoc2l6ZV90KXJlcS50cF9ibG9j
a19ucjsKICBtci5mcmFtZXNfcGVyX2Jsb2NrID0gcmVxLnRwX2Jsb2NrX3NpemUgLyByZXEudHBf
ZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9pZHggPSAwOwoKICBtci5yaW5nID0gbW1hcChOVUxMLCBt
ci5yaW5nX3NpemUsIFBST1RfUkVBRCB8IFBST1RfV1JJVEUsIE1BUF9TSEFSRUQsIGZkLCAwKTsK
ICBpZiAobXIucmluZyA9PSBNQVBfRkFJTEVEKSB7CiAgICBtci5yaW5nX3NpemUgPSAwOwogICAg
cmV0dXJuIGZhbHNlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgcmVsZWFzZV9t
bWFwX3JpbmcoaW50IGZkLCBNbWFwUmluZyAmbXIpIHsKICBib29sIG9rID0gdHJ1ZTsKICBpZiAo
bXIucmluZyAhPSBNQVBfRkFJTEVEKSB7CiAgICBpZiAobXVubWFwKG1yLnJpbmcsIG1yLnJpbmdf
c2l6ZSkgIT0gMCkgb2sgPSBmYWxzZTsKICAgIG1yLnJpbmcgPSBNQVBfRkFJTEVEOwogIH0KICBz
dHJ1Y3QgdHBhY2tldF9yZXEgZW1wdHlfcmVxOwogIG1lbXNldCgmZW1wdHlfcmVxLCAwLCBzaXpl
b2YoZW1wdHlfcmVxKSk7CiAgaWYgKHNldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9S
WF9SSU5HLAogICAgICAgICAgICAgICAgICZlbXB0eV9yZXEsIHNpemVvZihlbXB0eV9yZXEpKSAh
PSAwKSBvayA9IGZhbHNlOwogIG1yLnJpbmdfc2l6ZSA9IDA7CiAgcmV0dXJuIG9rOwp9CgpzdGF0
aWMgYm9vbCB2YWxpZF9yaW5nX2ZyYW1lKGNvbnN0IHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciwK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1bnNpZ25lZCBmcmFtZV9zaXplLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCAqcGFja2V0X29mZnNldCwKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBzaXplX3QgKnBhY2tldF9sZW5ndGgpIHsKICBjb25zdCB1bnNpZ25l
ZCBtYWMgPSBoZHItPnRwX21hYzsKICBjb25zdCB1bnNpZ25lZCBuZXQgPSBoZHItPnRwX25ldDsK
ICBjb25zdCB1bnNpZ25lZCBzbmFwbGVuID0gaGRyLT50cF9zbmFwbGVuOwogIGNvbnN0IHVuc2ln
bmVkIHdpcmVfbGVuID0gaGRyLT50cF9sZW47CiAgaWYgKG1hYyA8IFRQQUNLRVQyX0hEUkxFTiB8
fCBtYWMgPiBmcmFtZV9zaXplKSByZXR1cm4gZmFsc2U7CiAgaWYgKHNuYXBsZW4gPiB3aXJlX2xl
biB8fCBzbmFwbGVuID4gZnJhbWVfc2l6ZSAtIG1hYykgcmV0dXJuIGZhbHNlOwogIGlmIChuZXQg
PCBtYWMgfHwgbmV0ID4gbWFjICsgc25hcGxlbikgcmV0dXJuIGZhbHNlOwogICpwYWNrZXRfb2Zm
c2V0ID0gbWFjOwogICpwYWNrZXRfbGVuZ3RoID0gc25hcGxlbjsKICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIGludCBydW5fcmluZ19maXh0dXJlKCkgewogIE1tYXBSaW5nIG1yOwogIHVpbnQ4X3Qg
ZnJhbWVbMjA0OF07CiAgbWVtc2V0KGZyYW1lLCAwLCBzaXplb2YoZnJhbWUpKTsKICBzdHJ1Y3Qg
dHBhY2tldDJfaGRyICpoZHIgPSAoc3RydWN0IHRwYWNrZXQyX2hkciAqKWZyYW1lOwogIGhkci0+
dHBfbWFjID0gVFBBQ0tFVDJfSERSTEVOOwogIGhkci0+dHBfbmV0ID0gVFBBQ0tFVDJfSERSTEVO
OwogIGhkci0+dHBfc25hcGxlbiA9IDEyODsKICBoZHItPnRwX2xlbiA9IDEyODsKICBzaXplX3Qg
b2ZmID0gMCwgbGVuID0gMDsKICBpZiAoIXZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJh
bWUpLCAmb2ZmLCAmbGVuKSB8fAogICAgICBvZmYgIT0gVFBBQ0tFVDJfSERSTEVOIHx8IGxlbiAh
PSAxMjgpIHJldHVybiAyMTsKICBoZHItPnRwX21hYyA9IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAg
aWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0
dXJuIDIyOwogIGhkci0+dHBfbWFjID0gVFBBQ0tFVDJfSERSTEVOOwogIGhkci0+dHBfc25hcGxl
biA9IHNpemVvZihmcmFtZSk7CiAgaGRyLT50cF9sZW4gPSBzaXplb2YoZnJhbWUpOwogIGlmICh2
YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikpIHJldHVybiAy
MzsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjk7CiAgaGRyLT50cF9sZW4gPSAxMjg7CiAgaWYgKHZh
bGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDI0
OwogIGhkci0+dHBfc25hcGxlbiA9IDEyODsKICBoZHItPnRwX2xlbiA9IDEyODsKICBoZHItPnRw
X25ldCA9IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBz
aXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDI1OwogIG1yLmZyYW1lX25yKys7CiAg
aWYgKHZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSByZXR1cm4gMjY7CiAgcmV0dXJuIDA7Cn0KCnN0
YXRpYyBpbnQgcnVuX2ZpeHR1cmUoKSB7CiAgc3RkOjpzdHJpbmcgcmVxID0gIkdFVCAvYXBpL2l0
ZW1zP3g9MSBIVFRQLzEuMVxyXG5Ib3N0OiBhcGkubG9jYWxcclxuQXV0aG9yaXphdGlvbjogQmFz
aWMgWVd4cFkyVTZjMlZqY21WMFxyXG5UcmFjZXBhcmVudDogMDAtMDEyMzQ1Njc4OWFiY2RlZjAx
MjM0NTY3ODlhYmNkZWYtMDEyMzQ1Njc4OWFiY2RlZi0wMVxyXG5cclxuIjsKICBFdmVudCBlOyBS
ZXF1ZXN0TWV0YSBtZXRhOyBlLnRzID0gMTcwMDAwMDAwMDsgZS5ob3N0ID0gImNwcC1ub2RlIjsg
ZS5zZXJ2aWNlID0gInBvcnQ6ODA4MCI7IGUuY2FsbGVyID0gIjEwLjAuMC45IjsgZS5jYWxsZXJf
cG9ydCA9IDUxMDAwOyBlLmRzdF9pcCA9ICIxMC4wLjAuMiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBl
LnJlcV9ieXRlcyA9ICh1bnNpZ25lZClyZXEuc2l6ZSgpOyBwYXJzZV9yZXF1ZXN0KHJlcS5kYXRh
KCksIHJlcS5zaXplKCkgLSA0LCAmZSwgJm1ldGEpOyBlLnN0YXR1cyA9IDIwMDsgZS5oYXNfc3Rh
dHVzID0gdHJ1ZTsgZS5kdXJhdGlvbl9tcyA9IDM7IGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsgZS5y
ZXNwX2J5dGVzID0gNDI7IGUuaGFzX3Jlc3AgPSB0cnVlOyBlbWl0X2V2ZW50KGUpOyByZXR1cm4g
MDsKfQoKc3RhdGljIGludCBydW5fd3NzZV9maXh0dXJlKCkgewogIGNvbnN0IGNoYXIgKm5hbWVz
cGFjZXNbXSA9IHsKICAgICJodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9v
YXNpcy0yMDA0MDEtd3NzLXdzc2VjdXJpdHktc2VjZXh0LTEuMC54c2QiLAogICAgImh0dHA6Ly9z
Y2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMDcvc2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1h
cy54bWxzb2FwLm9yZy93cy8yMDAyLzEyL3NlY2V4dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1s
c29hcC5vcmcvd3MvMjAwMy8wNi9zZWNleHQiCiAgfTsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8
IDQ7ICsraSkgewogICAgc3RkOjpzdHJpbmcgYm9keSA9ICI8czpFbnZlbG9wZSB4bWxuczpzPSd1
cm46c29hcCcgeG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbaV0pICsKICAgICAg
Iic+PHM6SGVhZGVyPjx3OlVzZXJuYW1lVG9rZW4+PHc6VXNlcm5hbWU+bmF0aXZlLmZpeHR1cmU8
L3c6VXNlcm5hbWU+IgogICAgICAiPHc6UGFzc3dvcmQ+U0VOU0lUSVZFX1BBU1NXT1JEPC93OlBh
c3N3b3JkPjwvdzpVc2VybmFtZVRva2VuPjwvczpIZWFkZXI+IjsKICAgIHN0ZDo6c3RyaW5nIHVz
ZXIgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoYm9keSk7CiAgICBpZiAodXNlciAhPSAibmF0aXZl
LmZpeHR1cmUiKSByZXR1cm4gMzsKICAgIHN0ZDo6Y291dCA8PCB1c2VyIDw8ICJcbiI7CiAgfQog
IHN0ZDo6c3RyaW5nIG1hbGljaW91cyA9ICI8IURPQ1RZUEUgeCBbPCFFTlRJVFkgcHcgJ3NlY3Jl
dCc+XT48dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9JyIgKwogICAgc3RkOjpzdHJpbmcobmFtZXNw
YWNlc1swXSkgKyAiJz48dzpVc2VybmFtZT4mcHc7PC93OlVzZXJuYW1lPjwvdzpVc2VybmFtZVRv
a2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5hbWUobWFsaWNpb3VzKS5lbXB0eSgpKSBy
ZXR1cm4gNDsKICBzdGQ6OnN0cmluZyB3cm9uZ19ucyA9ICI8dzpVc2VybmFtZVRva2VuIHhtbG5z
Onc9J3Vybjpub3Qtd3NzZSc+PHc6VXNlcm5hbWU+d3Jvbmc8L3c6VXNlcm5hbWU+PC93OlVzZXJu
YW1lVG9rZW4+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZSh3cm9uZ19ucykuZW1wdHko
KSkgcmV0dXJuIDU7CiAgc3RkOjpzdHJpbmcgdW5uYW1lc3BhY2VkID0gIjxVc2VybmFtZVRva2Vu
PjxVc2VybmFtZT53cm9uZzwvVXNlcm5hbWU+PC9Vc2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRy
YWN0X3dzc2VfdXNlcm5hbWUodW5uYW1lc3BhY2VkKS5lbXB0eSgpKSByZXR1cm4gNjsKICBzdGQ6
OnN0cmluZyBlc2NhcGVkID0gIjx3OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0nIiArIHN0ZDo6c3Ry
aW5nKG5hbWVzcGFjZXNbMF0pICsKICAgICInPjx3OlVzZXJuYW1lPm5hdGl2ZSZhbXA7Zml4dHVy
ZTwvdzpVc2VybmFtZT4iOwogIGlmIChleHRyYWN0X3dzc2VfdXNlcm5hbWUoZXNjYXBlZCkgIT0g
Im5hdGl2ZSZmaXh0dXJlIikgcmV0dXJuIDc7CiAgc3RkOjpzdHJpbmcgdG9vX2xvbmcgPSAiPHc6
VXNlcm5hbWVUb2tlbiB4bWxuczp3PSciICsgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKwog
ICAgIic+PHc6VXNlcm5hbWU+IiArIHN0ZDo6c3RyaW5nKE1BWF9XU1NFX1VTRVJOQU1FICsgMSwg
J3gnKSArICI8L3c6VXNlcm5hbWU+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZSh0b29f
bG9uZykuZW1wdHkoKSkgcmV0dXJuIDg7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2R1
YWxfYXV0aF9maXh0dXJlKCkgewogIGNvbnN0IHN0ZDo6c3RyaW5nIGJvZHkgPQogICAgIjxzOkVu
dmVsb3BlIHhtbG5zOnM9J3Vybjpzb2FwJyB4bWxuczp3PSdodHRwOi8vZG9jcy5vYXNpcy1vcGVu
Lm9yZy93c3MvMjAwNC8wMS8iCiAgICAib2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4
dC0xLjAueHNkJz48czpIZWFkZXI+PHc6VXNlcm5hbWVUb2tlbj4iCiAgICAiPHc6VXNlcm5hbWU+
c29hcC51c2VyPC93OlVzZXJuYW1lPjx3OlBhc3N3b3JkPlNFTlNJVElWRV9QQVNTV09SRDwvdzpQ
YXNzd29yZD4iCiAgICAiPC93OlVzZXJuYW1lVG9rZW4+PC9zOkhlYWRlcj48L3M6RW52ZWxvcGU+
IjsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gcmVxdWVzdDsKICByZXF1ZXN0IDw8ICJQT1NUIC9zb2Fw
IEhUVFAvMS4xXHJcbkhvc3Q6IGZpeHR1cmVcclxuIgogICAgICAgICAgPDwgIkF1dGhvcml6YXRp
b246IEJhc2ljIFltRnphV011ZFhObGNqcHdZWE56ZDI5eVpBPT1cclxuIgogICAgICAgICAgPDwg
IkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vc29hcCt4bWxcclxuQ29udGVudC1MZW5ndGg6ICIK
ICAgICAgICAgIDw8IGJvZHkuc2l6ZSgpIDw8ICJcclxuXHJcbiIgPDwgYm9keTsKICBjb25zdCBz
dGQ6OnN0cmluZyBwYXlsb2FkID0gcmVxdWVzdC5zdHIoKTsKCiAgc3RkOjp2ZWN0b3I8dW5zaWdu
ZWQgY2hhcj4gcGFja2V0KDE0ICsgMjAgKyAyMCArIHBheWxvYWQuc2l6ZSgpLCAwKTsKICBwYWNr
ZXRbMTJdID0gMHgwODsgcGFja2V0WzEzXSA9IDB4MDA7CiAgcGFja2V0WzE0XSA9IDB4NDU7IHBh
Y2tldFsyM10gPSBJUFBST1RPX1RDUDsKICB1aW50MTZfdCB0b3RfbGVuID0gKHVpbnQxNl90KSgy
MCArIDIwICsgcGF5bG9hZC5zaXplKCkpOwogIHBhY2tldFsxNl0gPSAodW5zaWduZWQgY2hhciko
dG90X2xlbiA+PiA4KTsgcGFja2V0WzE3XSA9ICh1bnNpZ25lZCBjaGFyKSh0b3RfbGVuICYgMHhm
Zik7CiAgcGFja2V0WzI2XSA9IDE5MjsgcGFja2V0WzI3XSA9IDA7IHBhY2tldFsyOF0gPSAyOyBw
YWNrZXRbMjldID0gMjsKICBwYWNrZXRbMzBdID0gMTkyOyBwYWNrZXRbMzFdID0gMDsgcGFja2V0
WzMyXSA9IDI7IHBhY2tldFszM10gPSAxOwogIHVuc2lnbmVkIHNob3J0IHNwb3J0ID0gaHRvbnMo
NTEwMDApLCBkcG9ydCA9IGh0b25zKDgwODApOwogIG1lbWNweSgmcGFja2V0WzM0XSwgJnNwb3J0
LCBzaXplb2Yoc3BvcnQpKTsKICBtZW1jcHkoJnBhY2tldFszNl0sICZkcG9ydCwgc2l6ZW9mKGRw
b3J0KSk7CiAgcGFja2V0WzQ2XSA9IDVVIDw8IDQ7IHBhY2tldFs0N10gPSAweDE5OwogIG1lbWNw
eSgmcGFja2V0WzU0XSwgcGF5bG9hZC5kYXRhKCksIHBheWxvYWQuc2l6ZSgpKTsKCiAgZ193c3Nl
X2JvZHlfYnl0ZXMgPSA4MTkyOwogIG1lbXNldChnX21vbml0b3JlZF9wb3J0cywgMCwgc2l6ZW9m
KGdfbW9uaXRvcmVkX3BvcnRzKSk7CiAgZ19tb25pdG9yZWRfcG9ydHNbODA4MF0gPSB0cnVlOwog
IGdfZW5kcG9pbnQuY2xlYXIoKTsKICBpbml0X3JuZygpOwogIHN0ZDo6dmVjdG9yPHVuc2lnbmVk
PiBwb3J0cygxLCA4MDgwKTsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiBmbG93czsKICBzdGQ6
Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gcGVuZGluZzsKICBpZiAoIWhh
bmRsZV9wYWNrZXQoJnBhY2tldFswXSwgcGFja2V0LnNpemUoKSwgImNwcC1kdWFsLWZpeHR1cmUi
LAogICAgICAgICAgICAgICAgICAgICBwb3J0cywgZmxvd3MsIHBlbmRpbmcpKSByZXR1cm4gOTsK
ICBpZiAoIWZsb3dzLmVtcHR5KCkgfHwgcGVuZGluZy5zaXplKCkgIT0gMSkgcmV0dXJuIDEwOwog
IGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwogIHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1
bl9zaGlwX3JhdGVfZml4dHVyZSgpIHsKICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gZXZlbnRz
OwogIGV2ZW50cy5wdXNoX2JhY2soc3RkOjpzdHJpbmcoNDAwMDAsICd4JykpOwogIGV2ZW50cy5w
dXNoX2JhY2soc3RkOjpzdHJpbmcoNDAwMDAsICd5JykpOwogIGlmIChib3VuZGVkX2JhdGNoX2Nv
dW50KGV2ZW50cywgImZpeHR1cmUiKSAhPSAxKSByZXR1cm4gMzA7CiAgZXZlbnRzLmNsZWFyKCk7
CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyhNQVhfUE9TVF9CWVRFUyArIDEsICd4Jykp
OwogIGlmIChib3VuZGVkX2JhdGNoX2NvdW50KGV2ZW50cywgImZpeHR1cmUiKSAhPSAwKSByZXR1
cm4gMzE7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX3N0YXRzX2ZpeHR1cmUoKSB7CiAg
Z19zaGlwX25vZGUgPSAiZml4dHVyZS1ub2RlIjsKICBnX2luc3RhbmNlX2lkID0gImZpeHR1cmUt
MSI7CiAgZ19zdGF0c19sYXN0X2F0ID0gd2FsbF9zZWNvbmRzKCkgLSAzMC4wOwogIGdfY2FwdHVy
ZV9wYWNrZXRzID0gMTAwOwogIGdfY2FwdHVyZV9ieXRlcyA9IDY0MDA7CiAgZ19ldmVudHNfZW1p
dHRlZCA9IGdfZXZlbnRzX2luID0gMTA7CiAgZ19ldmVudHNfcHVzaGVkID0gODsKICBnX2V2ZW50
c19kcm9wcGVkID0gZ19kcm9wX3F1ZXVlID0gMjsKICBzdGQ6OnN0cmluZyBib2R5ID0gYWdlbnRf
c3RhdHNfYm9keSgtMSwgMywgMiwgMSk7CiAgaWYgKGJvZHkuc2l6ZSgpID4gTUFYX1NUQVRTX0JZ
VEVTKSByZXR1cm4gNDA7CiAgaWYgKGJvZHkuZmluZCgiXCJ0eXBlXCI6XCJhZ2VudF9zdGF0c1wi
IikgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiA0MTsKICBpZiAoYm9keS5maW5kKCJcImRy
b3BfcGVyY2VudFwiOjIwLjAwMDAiKSA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIDQyOwog
IGlmIChib2R5LmZpbmQoIlwibW9kZVwiOlwiY3BwXCIiKSA9PSBzdGQ6OnN0cmluZzo6bnBvcykg
cmV0dXJuIDQzOwogIHN0ZDo6Y291dCA8PCBib2R5IDw8ICJcbiI7CiAgcmV0dXJuIDA7Cn0KCnN0
YXRpYyBib29sIHBhcnNlX3dzc2Vfc2l6ZShjb25zdCBjaGFyICp2YWx1ZSwgc2l6ZV90ICpyZXN1
bHQpIHsKICBpZiAoIXZhbHVlIHx8ICEqdmFsdWUpIHJldHVybiBmYWxzZTsKICBzaXplX3QgbiA9
IDA7CiAgaWYgKCFwYXJzZV9kZWNpbWFsX3NpemUodmFsdWUsIHN0cmxlbih2YWx1ZSksICZuKSB8
fCBuID4gTUFYX1dTU0VfQk9EWV9CWVRFUykgcmV0dXJuIGZhbHNlOwogICpyZXN1bHQgPSBuOwog
IHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBkcm9wX2FsbF9jYXBhYmlsaXRpZXMoKSB7CiAg
c3RydWN0IF9fdXNlcl9jYXBfaGVhZGVyX3N0cnVjdCBoZWFkZXI7CiAgc3RydWN0IF9fdXNlcl9j
YXBfZGF0YV9zdHJ1Y3QgZGF0YVsyXTsKICBtZW1zZXQoJmhlYWRlciwgMCwgc2l6ZW9mKGhlYWRl
cikpOwogIG1lbXNldChkYXRhLCAwLCBzaXplb2YoZGF0YSkpOwogIGhlYWRlci52ZXJzaW9uID0g
X0xJTlVYX0NBUEFCSUxJVFlfVkVSU0lPTl8zOwogIGhlYWRlci5waWQgPSAwOwogIHJldHVybiBz
eXNjYWxsKFNZU19jYXBzZXQsICZoZWFkZXIsIGRhdGEpID09IDA7Cn0KCnN0YXRpYyBpbnQgb3Bl
bl9jYXB0dXJlX3NvY2tldChjb25zdCBzdGQ6OnN0cmluZyAmaWZhY2UsCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgTW1hcFJpbmcgJnJpbmcpIHsKICBpbnQgZmQgPSBz
b2NrZXQoQUZfUEFDS0VULCBTT0NLX1JBVywgaHRvbnMoRVRIX1BfQUxMKSk7CiAgaWYgKGZkIDwg
MCkgeyBwZXJyb3IoIkFGX1BBQ0tFVCIpOyByZXR1cm4gLTE7IH0KICBmY250bChmZCwgRl9TRVRG
RCwgRkRfQ0xPRVhFQyk7CiAgaW50IHJiID0gOCAqIDEwMjQgKiAxMDI0OwogIHNldHNvY2tvcHQo
ZmQsIFNPTF9TT0NLRVQsIFNPX1JDVkJVRiwgJnJiLCBzaXplb2YocmIpKTsKICBpZiAoIWF0dGFj
aF9icGYoZmQsIHBvcnRzKSkgewogICAgbG9nbXNnKCJCUEYgYXR0YWNoIGZhaWxlZDsgcmVmdXNp
bmcgdW5maWx0ZXJlZCBjYXB0dXJlIik7CiAgICBjbG9zZShmZCk7CiAgICByZXR1cm4gLTE7CiAg
fQoKICBzdHJ1Y3Qgc29ja2FkZHJfbGwgc2E7CiAgbWVtc2V0KCZzYSwgMCwgc2l6ZW9mKHNhKSk7
CiAgc2Euc2xsX2ZhbWlseSA9IEFGX1BBQ0tFVDsKICBzYS5zbGxfcHJvdG9jb2wgPSBodG9ucyhF
VEhfUF9BTEwpOwogIGlmICghaWZhY2UuZW1wdHkoKSkgewogICAgc2Euc2xsX2lmaW5kZXggPSAo
aW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3RyKCkpOwogICAgaWYgKCFzYS5zbGxfaWZpbmRl
eCkgewogICAgICBsb2dtc2coImJhZCBpbnRlcmZhY2UiKTsKICAgICAgY2xvc2UoZmQpOwogICAg
ICByZXR1cm4gLTE7CiAgICB9CiAgfQogIGlmIChiaW5kKGZkLCAoc3RydWN0IHNvY2thZGRyICop
JnNhLCBzaXplb2Yoc2EpKSA8IDApIHsKICAgIHBlcnJvcigiYmluZCIpOwogICAgY2xvc2UoZmQp
OwogICAgcmV0dXJuIC0xOwogIH0KICBpZiAoIXNldHVwX21tYXBfcmluZyhmZCwgcmluZykpIHsK
ICAgIGxvZ21zZygiVFBBQ0tFVF9WMiBzZXR1cCBmYWlsZWQ7IHJlZnVzaW5nIG5vbi1yaW5nIGZh
bGxiYWNrIik7CiAgICBjbG9zZShmZCk7CiAgICByZXR1cm4gLTE7CiAgfQogIGlmICghZHJvcF9h
bGxfY2FwYWJpbGl0aWVzKCkpIHsKICAgIGxvZ21zZygiY2FwYWJpbGl0eSBkcm9wIGZhaWxlZDsg
cmVmdXNpbmcgdW5zYWZlIGNhcHR1cmUiKTsKICAgIHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5n
KTsKICAgIGNsb3NlKGZkKTsKICAgIHJldHVybiAtMTsKICB9CiAgcmV0dXJuIGZkOwp9CgpzdGF0
aWMgaW50IHJ1bl9jYXBhYmlsaXR5X3Byb2JlKGNvbnN0IHN0ZDo6c3RyaW5nICZpZmFjZSwKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4g
JnBvcnRzKSB7CiAgTW1hcFJpbmcgcmluZzsKICBpbnQgZmQgPSBvcGVuX2NhcHR1cmVfc29ja2V0
KGlmYWNlLCBwb3J0cywgcmluZyk7CiAgaWYgKGZkIDwgMCkgcmV0dXJuIDI7CgogIGJvb2wgcmVs
ZWFzZWQgPSByZWxlYXNlX21tYXBfcmluZyhmZCwgcmluZyk7CiAgY2xvc2UoZmQpOwogIGlmICgh
cmVsZWFzZWQpIHsKICAgIGxvZ21zZygiVFBBQ0tFVF9WMiBwcm9iZSBjbGVhbnVwIGZhaWxlZCIp
OwogICAgcmV0dXJuIDI7CiAgfQogIHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1bl9sb2Nrb3V0
X2ZpeHR1cmUoKSB7CiAgY29ycl9kaXNhYmxlZF9jbGVhcigpOwogIC8vIEluc2VydCAxMCwwMDAg
ZGlzdGluY3QgY29ubmVjdGlvbiBrZXlzIGludG8gdGhlIHJlZ2lzdHJ5IHZpYSBjb3JyX2Rpc2Fi
bGVkX2luc2VydAogIGZvciAodW5zaWduZWQgaSA9IDA7IGkgPCAxMDAwMDsgKytpKSB7CiAgICBQ
YWNrZXRLZXkgazsKICAgIGsuc19pcCA9IDB4MGEwMDAwMDI7CiAgICBrLnNwb3J0ID0gODA4MDsK
ICAgIGsuZF9pcCA9IDB4MGEwMDAwMDE7CiAgICBrLmRwb3J0ID0gKHVpbnQxNl90KSgxMDAwMCAr
IChpICUgNTUwMDApKTsKICAgIGNvcnJfZGlzYWJsZWRfaW5zZXJ0KGspOwogIH0KICAvLyBNdXN0
IGJlIHN0cmljdGx5IGNhcHBlZCBhdCBNQVhfQ09SUl9ESVNBQkxFRCAoMjA0OCkKICBpZiAoZ19j
b3JyX2Rpc2FibGVkLnNpemUoKSA+IE1BWF9DT1JSX0RJU0FCTEVEKSB7CiAgICBmcHJpbnRmKHN0
ZGVyciwgIkxvY2tvdXQgZml4dHVyZSBmYWlsZWQ6IHNpemUgJWx1ID4gJWx1XG4iLAogICAgICAg
ICAgICAodW5zaWduZWQgbG9uZylnX2NvcnJfZGlzYWJsZWQuc2l6ZSgpLCAodW5zaWduZWQgbG9u
ZylNQVhfQ09SUl9ESVNBQkxFRCk7CiAgICByZXR1cm4gMTsKICB9CiAgaWYgKCFnX2NvcnJfY2Fw
YWNpdHlfcmVhY2hlZCkgewogICAgZnByaW50ZihzdGRlcnIsICJMb2Nrb3V0IGZpeHR1cmUgZmFp
bGVkOiBnX2NvcnJfY2FwYWNpdHlfcmVhY2hlZCBub3Qgc2V0XG4iKTsKICAgIHJldHVybiAxOwog
IH0KICAvLyBFdmljdGVkIGtleSB3aXRob3V0IHZlcmlmaWVkIFNZTiBtdXN0IGhhdmUgY29ycmVs
YXRpb24gZGlzYWJsZWQ6CiAgUGFja2V0S2V5IGV2aWN0ZWRfa2V5OwogIGV2aWN0ZWRfa2V5LnNf
aXAgPSAweDBhMDAwMDAyOwogIGV2aWN0ZWRfa2V5LnNwb3J0ID0gODA4MDsKICBldmljdGVkX2tl
eS5kX2lwID0gMHgwYTAwMDAwMTsKICBldmljdGVkX2tleS5kcG9ydCA9IDEwMDAwOwogIGlmICgh
aXNfY29ycmVsYXRpb25fZGlzYWJsZWQoZXZpY3RlZF9rZXksIGZhbHNlKSkgewogICAgZnByaW50
ZihzdGRlcnIsICJMb2Nrb3V0IGZpeHR1cmUgZmFpbGVkOiBldmljdGVkIGtleSB3aXRob3V0IFNZ
TiBtdXN0IGhhdmUgY29ycmVsYXRpb24gZGlzYWJsZWRcbiIpOwogICAgcmV0dXJuIDE7CiAgfQog
IC8vIFdpdGggdmVyaWZpZWQgU1lOLCBjb3JyZWxhdGlvbiBtdXN0IGJlIGFsbG93ZWQ6CiAgaWYg
KGlzX2NvcnJlbGF0aW9uX2Rpc2FibGVkKGV2aWN0ZWRfa2V5LCB0cnVlKSkgewogICAgZnByaW50
ZihzdGRlcnIsICJMb2Nrb3V0IGZpeHR1cmUgZmFpbGVkOiBrZXkgd2l0aCB2ZXJpZmllZCBTWU4g
bXVzdCBhbGxvdyBjb3JyZWxhdGlvblxuIik7CiAgICByZXR1cm4gMTsKICB9CiAgY29ycl9kaXNh
YmxlZF9jbGVhcigpOwogIGZwcmludGYoc3RkZXJyLCAiTG9ja291dCByZWdpc3RyeSAxMGsgYm91
bmRlZCBmaXh0dXJlOiBQQVNTIChzaXplPSVsdSwgY2FwYWNpdHlfZmFsbGJhY2s9dmVyaWZpZWQp
XG4iLAogICAgICAgICAgKHVuc2lnbmVkIGxvbmcpTUFYX0NPUlJfRElTQUJMRUQpOwogIHJldHVy
biAwOwp9CgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqKmFyZ3YpIHsKICBpZiAoYXJnYyA+IDEg
JiYgIXN0cmNtcChhcmd2WzFdLCAiLS1maXh0dXJlIikpIHJldHVybiBydW5fZml4dHVyZSgpOwog
IGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLXdzc2UtZml4dHVyZSIpKSByZXR1
cm4gcnVuX3dzc2VfZml4dHVyZSgpOwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0s
ICItLWR1YWwtYXV0aC1maXh0dXJlIikpIHJldHVybiBydW5fZHVhbF9hdXRoX2ZpeHR1cmUoKTsK
ICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2WzFdLCAiLS1yaW5nLWZpeHR1cmUiKSkgcmV0
dXJuIHJ1bl9yaW5nX2ZpeHR1cmUoKTsKICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2WzFd
LCAiLS1zaGlwLXJhdGUtZml4dHVyZSIpKSByZXR1cm4gcnVuX3NoaXBfcmF0ZV9maXh0dXJlKCk7
CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0tc3RhdHMtZml4dHVyZSIpKSBy
ZXR1cm4gcnVuX3N0YXRzX2ZpeHR1cmUoKTsKICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2
WzFdLCAiLS1sb2Nrb3V0LWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9sb2Nrb3V0X2ZpeHR1cmUoKTsK
CiAgc3RkOjpzdHJpbmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0czsgaW50IGk7
IGludCB3b3JrZXJzID0gMTsKICBzdGQ6OnN0cmluZyBlbmRwb2ludDsKICBib29sIGNhcGFiaWxp
dHlfcHJvYmUgPSBmYWxzZTsKICBjb25zdCBjaGFyICp3c3NlX2VudiA9IGdldGVudigiTlRfV1NT
RV9CT0RZX0JZVEVTIik7CiAgaWYgKHdzc2VfZW52ICYmICFwYXJzZV93c3NlX3NpemUod3NzZV9l
bnYsICZnX3dzc2VfYm9keV9ieXRlcykpIHsKICAgIGZwcmludGYoc3RkZXJyLCAid3NzZSBib2R5
IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4uNjU1MzZcbiIpOyByZXR1cm4gMjsKICB9CiAgY29u
c3QgY2hhciAqcmF0ZV9lbnYgPSBnZXRlbnYoIk5UX1NISVBfUkFURV9LQlBTIik7CiAgaWYgKHJh
dGVfZW52ICYmICpyYXRlX2VudikgZ19zaGlwX3JhdGVfa2JwcyA9ICh1bnNpZ25lZClhdG9pKHJh
dGVfZW52KTsKICBjb25zdCBjaGFyICpzdGF0c19lbnYgPSBnZXRlbnYoIk5UX1NUQVRTX0lOVEVS
VkFMX1NFQyIpOwogIGlmIChzdGF0c19lbnYgJiYgKnN0YXRzX2VudikgZ19zdGF0c19pbnRlcnZh
bF9zZWMgPSAodW5zaWduZWQpYXRvaShzdGF0c19lbnYpOwogIGNvbnN0IGNoYXIgKnR0bF9lbnYg
PSBnZXRlbnYoIk5UX1BFTkRJTkdfVFRMX1NFQyIpOwogIGlmICh0dGxfZW52ICYmICp0dGxfZW52
KSBnX3BlbmRpbmdfdHRsX3NlYyA9ICh1bnNpZ25lZClhdG9pKHR0bF9lbnYpOwoKICBmb3IgKGkg
PSAxOyBpIDwgYXJnYzsgKytpKSB7CiAgICBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWkiKSAmJiBp
ICsgMSA8IGFyZ2MpIGlmYWNlID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2
W2ldLCAiLXAiKSAmJiBpICsgMSA8IGFyZ2MpIHsKICAgICAgd2hpbGUgKGkgKyAxIDwgYXJnYyAm
JiBhcmd2W2kgKyAxXVswXSAhPSAnLScpIHsKICAgICAgICBjaGFyICpxID0gc3RydG9rKGFyZ3Zb
KytpXSwgIiwgIik7CiAgICAgICAgd2hpbGUgKHEpIHsgbG9uZyBwID0gYXRvbChxKTsgaWYgKHZh
bGlkX3BvcnQoKHVuc2lnbmVkKXApKSBwb3J0cy5wdXNoX2JhY2soKHVuc2lnbmVkKXApOyBxID0g
c3RydG9rKE5VTEwsICIsICIpOyB9CiAgICAgIH0KICAgIH0KICAgIGVsc2UgaWYgKCFzdHJjbXAo
YXJndltpXSwgIi0tZW5kcG9pbnQiKSAmJiBpICsgMSA8IGFyZ2MpIGVuZHBvaW50ID0gYXJndlsr
K2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1zaGlwLXJhdGUta2JwcyIpICYm
IGkgKyAxIDwgYXJnYykgZ19zaGlwX3JhdGVfa2JwcyA9ICh1bnNpZ25lZClhdG9pKGFyZ3ZbKytp
XSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItLXN0YXRzLWludGVydmFsLXNlYyIp
ICYmIGkgKyAxIDwgYXJnYykgZ19zdGF0c19pbnRlcnZhbF9zZWMgPSAodW5zaWduZWQpYXRvaShh
cmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1wZW5kaW5nLXR0bC1z
ZWMiKSAmJiBpICsgMSA8IGFyZ2MpIGdfcGVuZGluZ190dGxfc2VjID0gKHVuc2lnbmVkKWF0b2ko
YXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tY2FwYWJpbGl0eS1w
cm9iZSIpKSBjYXBhYmlsaXR5X3Byb2JlID0gdHJ1ZTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJn
dltpXSwgIi0tc3Bvb2wiKSAmJiBpICsgMSA8IGFyZ2MpICsraTsKICAgIGVsc2UgaWYgKCFzdHJj
bXAoYXJndltpXSwgIi1qIikgJiYgaSArIDEgPCBhcmdjKSB3b3JrZXJzID0gYXRvaShhcmd2Wysr
aV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS13c3NlLWJvZHktYnl0ZXMiKSAm
JiBpICsgMSA8IGFyZ2MpIHsKICAgICAgaWYgKCFwYXJzZV93c3NlX3NpemUoYXJndlsrK2ldLCAm
Z193c3NlX2JvZHlfYnl0ZXMpKSB7CiAgICAgICAgZnByaW50ZihzdGRlcnIsICJ3c3NlIGJvZHkg
Ynl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi42NTUzNlxuIik7IHJldHVybiAyOwogICAgICB9CiAg
ICB9CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaCIpIHx8ICFzdHJjbXAoYXJndltp
XSwgIi0taGVscCIpKSB7CiAgICAgIGZwcmludGYoc3RkZXJyLCAidXNhZ2U6IG50LXNuaWZmLWNw
cCBbLWkgaWZhY2VdIFstcCBwb3J0c10gWy0tZW5kcG9pbnQgVVJMXSBbLS1zaGlwLXJhdGUta2Jw
cyA2NC4uMTAwMDBdIFstLXN0YXRzLWludGVydmFsLXNlYyAxMC4uMzAwXSBbLS1wZW5kaW5nLXR0
bC1zZWMgMS4uMzAwXSBbLWogd29ya2Vyc10gWy0td3NzZS1ib2R5LWJ5dGVzIDAuLjY1NTM2XVxu
Iik7CiAgICAgIHJldHVybiAwOwogICAgfQogICAgZWxzZSB7IGZwcmludGYoc3RkZXJyLCAidW5r
bm93biBvciBpbmNvbXBsZXRlIGFyZ3VtZW50OiAlc1xuIiwgYXJndltpXSk7IHJldHVybiAyOyB9
CiAgfQogIGlmIChwb3J0cy5lbXB0eSgpKSB7IHBvcnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1
c2hfYmFjayg4MDAzKTsgcG9ydHMucHVzaF9iYWNrKDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAw
Nyk7IHBvcnRzLnB1c2hfYmFjayg4MDA5KTsgcG9ydHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5w
dXNoX2JhY2soODAxMSk7IH0KICBpZiAoZ19zaGlwX3JhdGVfa2JwcyA8IDY0IHx8IGdfc2hpcF9y
YXRlX2ticHMgPiAxMDAwMCkgewogICAgZnByaW50ZihzdGRlcnIsICJzaGlwIHJhdGUgbXVzdCBi
ZSBpbiByYW5nZSA2NC4uMTAwMDAga2JpdC9zXG4iKTsKICAgIHJldHVybiAyOwogIH0KICBpZiAo
Z19zdGF0c19pbnRlcnZhbF9zZWMgPCAxMCB8fCBnX3N0YXRzX2ludGVydmFsX3NlYyA+IDMwMCkg
ewogICAgZnByaW50ZihzdGRlcnIsICJzdGF0cyBpbnRlcnZhbCBtdXN0IGJlIGluIHJhbmdlIDEw
Li4zMDAgc2Vjb25kc1xuIik7CiAgICByZXR1cm4gMjsKICB9CiAgaWYgKGdfcGVuZGluZ190dGxf
c2VjIDwgMSB8fCBnX3BlbmRpbmdfdHRsX3NlYyA+IDMwMCkgewogICAgZnByaW50ZihzdGRlcnIs
ICJwZW5kaW5nIHR0bCBtdXN0IGJlIGluIHJhbmdlIDEuLjMwMCBzZWNvbmRzXG4iKTsKICAgIHJl
dHVybiAyOwogIH0KICBpZiAocG9ydHMuc2l6ZSgpID4gTUFYX1BPUlRTKSB7CiAgICBmcHJpbnRm
KHN0ZGVyciwgImF0IG1vc3QgMzAgbW9uaXRvcmVkIHBvcnRzIGFyZSBzdXBwb3J0ZWQgYnkgdGhl
IHNhZmUgY0JQRiBwcm9ncmFtXG4iKTsKICAgIHJldHVybiAyOwogIH0KICBpZiAod29ya2VycyAh
PSAxKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgIm9ubHkgb25lIGNhcHR1cmUgd29ya2VyIGlzIHBl
cm1pdHRlZFxuIik7CiAgICByZXR1cm4gMjsKICB9CiAgKHZvaWQpd29ya2VyczsKCiAgaWYgKGNh
cGFiaWxpdHlfcHJvYmUpIHJldHVybiBydW5fY2FwYWJpbGl0eV9wcm9iZShpZmFjZSwgcG9ydHMp
OwoKICBpbml0X3JuZygpOwogIG1lbXNldChnX21vbml0b3JlZF9wb3J0cywgMCwgc2l6ZW9mKGdf
bW9uaXRvcmVkX3BvcnRzKSk7CiAgZm9yIChzaXplX3QgayA9IDA7IGsgPCBwb3J0cy5zaXplKCk7
ICsraykgewogICAgaWYgKHBvcnRzW2tdIDwgNjU1MzYpIGdfbW9uaXRvcmVkX3BvcnRzW3BvcnRz
W2tdXSA9IHRydWU7CiAgfQoKICBjb25zdCBjaGFyICpub2RlX2VudiA9IGdldGVudigiTlRfTk9E
RV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2RlX2VudiAmJiAqbm9kZV9lbnYpID8g
bm9kZV9lbnYgOiBob3N0X25hbWUoKTsKCiAgZ19lbmRwb2ludCA9IGVuZHBvaW50OwogIGdfc2hp
cF9ub2RlID0gbm9kZTsKICBnX2luc3RhbmNlX2lkID0gbnVtYmVyX3N0cmluZygoc2l6ZV90KXRp
bWUoTlVMTCkpICsgIi0iICsgbnVtYmVyX3N0cmluZygoc2l6ZV90KWdldHBpZCgpKTsKICBnX3N0
YXRzX2xhc3RfYXQgPSB3YWxsX3NlY29uZHMoKTsKCiAgTW1hcFJpbmcgcmluZzsKICBpbnQgZmQg
PSBvcGVuX2NhcHR1cmVfc29ja2V0KGlmYWNlLCBwb3J0cywgcmluZyk7CiAgaWYgKGZkIDwgMCkg
cmV0dXJuIDI7CgogIHNpZ25hbChTSUdQSVBFLCBTSUdfSUdOKTsKCiAgaWYgKGdfZW5kcG9pbnQu
ZW1wdHkoKSkgewogICAgaW50IG91dHB1dF9mbGFncyA9IGZjbnRsKFNURE9VVF9GSUxFTk8sIEZf
R0VURkwsIDApOwogICAgaWYgKG91dHB1dF9mbGFncyA8IDAgfHwKICAgICAgICBmY250bChTVERP
VVRfRklMRU5PLCBGX1NFVEZMLCBvdXRwdXRfZmxhZ3MgfCBPX05PTkJMT0NLKSA8IDApIHsKICAg
ICAgbG9nbXNnKCJjYW5ub3QgbWFrZSBzaGlwcGVyIHBpcGUgbm9uLWJsb2NraW5nOyByZWZ1c2lu
ZyB1bnNhZmUgcGlwZWxpbmUiKTsKICAgICAgcmVsZWFzZV9tbWFwX3JpbmcoZmQsIHJpbmcpOwog
ICAgICBjbG9zZShmZCk7CiAgICAgIHJldHVybiAyOwogICAgfQogIH0gZWxzZSB7CiAgICBnX3No
aXBfd29ya2VyX2FjdGl2ZSA9IHRydWU7CiAgICBpZiAocHRocmVhZF9jcmVhdGUoJmdfc2hpcF93
b3JrZXJfdGlkLCBOVUxMLCBzaGlwX3dvcmtlcl90aHJlYWQsIE5VTEwpICE9IDApIHsKICAgICAg
bG9nbXNnKCJmYWlsZWQgdG8gc3Bhd24gc2hpcHBpbmcgd29ya2VyIHRocmVhZCIpOwogICAgICBy
ZWxlYXNlX21tYXBfcmluZyhmZCwgcmluZyk7CiAgICAgIGNsb3NlKGZkKTsKICAgICAgcmV0dXJu
IDI7CiAgICB9CiAgfQoKICBzaWduYWwoU0lHVEVSTSwgc3RvcF9zaWduYWwpOwogIHNpZ25hbChT
SUdJTlQsIHN0b3Bfc2lnbmFsKTsKICBzZXR2YnVmKHN0ZG91dCwgTlVMTCwgX0lPTEJGLCA2NTUz
Nik7CiAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0S2V5
LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+IHBlbmRpbmc7CgogIGxvZ21zZygiUEFDS0VUX01NQVAg
KFRQQUNLRVRfVjIpIHN0cmljdCBSWCByaW5nIGVuYWJsZWQgKDRNQiwgMjA0OCBmcmFtZXMpIik7
CiAgaWYgKGdfd3NzZV9ib2R5X2J5dGVzKSB7CiAgICBsb2dtc2coIldTU0UgVXNlcm5hbWVUb2tl
biBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5kZWQgdG8gIiArIG51bWJlcl9zdHJpbmcoZ193c3Nl
X2JvZHlfYnl0ZXMpICsgIiBieXRlcy9yZXF1ZXN0KSIpOwogIH0KICBpZiAoIWdfZW5kcG9pbnQu
ZW1wdHkoKSkgewogICAgbG9nbXNnKCJzaW5nbGUtYmluYXJ5IG1vZGU6IG5vbi1ibG9ja2luZyB0
aHJlYWQgc2hpcHBpbmcgZGlyZWN0bHkgdG8gIiArIGdfZW5kcG9pbnQgKyAiICgwIGRpc2sgSS9P
KSIpOwogIH0gZWxzZSB7CiAgICBsb2dtc2coIm5vbi1ibG9ja2luZyBuYXRpdmUgcGlwZWxpbmUg
bW9kZSBlbmFibGVkOyBXQU4gSS9PIGlzb2xhdGVkIGluIG50LXNoaXAtY3BwIik7CiAgfQogIGxv
Z21zZygibGlzdGVuaW5nIik7CgogIHRpbWVfdCBsYXN0ID0gdGltZShOVUxMKTsKICBib29sIHJp
bmdfaW50ZWdyaXR5X2ZhaWx1cmUgPSBmYWxzZTsKCiAgc3RydWN0IHBvbGxmZCBwZmQ7CiAgcGZk
LmZkID0gZmQ7CiAgcGZkLmV2ZW50cyA9IFBPTExJTiB8IFBPTExFUlIgfCBQT0xMSFVQIHwgUE9M
TE5WQUw7CiAgcGZkLnJldmVudHMgPSAwOwoKICB3aGlsZSAoZ19ydW5uaW5nKSB7CiAgICBpbnQg
cmMgPSBwb2xsKCZwZmQsIDEsIDEwMDApOwogICAgaWYgKHJjIDwgMCAmJiBlcnJubyA9PSBFSU5U
UikgewogICAgICAvLyBTaWduYWwgaGFuZGxlZAogICAgfSBlbHNlIGlmIChyYyA8IDApIHsKICAg
ICAgbG9nbXNnKCJwb2xsIGVycm9yIGVuY291bnRlcmVkIik7CiAgICAgIGdfcnVubmluZyA9IDA7
CiAgICAgIGJyZWFrOwogICAgfSBlbHNlIGlmIChyYyA+IDAgJiYgKHBmZC5yZXZlbnRzICYgKFBP
TExFUlIgfCBQT0xMTlZBTCkpKSB7CiAgICAgIGxvZ21zZygicG9sbCBlcnJvciByZXZlbnRzIGRl
dGVjdGVkIik7CiAgICAgIGdfcnVubmluZyA9IDA7CiAgICAgIGJyZWFrOwogICAgfSBlbHNlIGlm
IChyYyA+IDApIHsKICAgICAgc2l6ZV90IGRyYWluX2NvdW50ID0gMDsKICAgICAgd2hpbGUgKGdf
cnVubmluZyAmJiBkcmFpbl9jb3VudCA8IE1BWF9EUkFJTl9QRVJfUEFTUykgewogICAgICAgIHVu
c2lnbmVkIGJfaWR4ID0gcmluZy5mcmFtZV9pZHggLyByaW5nLmZyYW1lc19wZXJfYmxvY2s7CiAg
ICAgICAgdW5zaWduZWQgZl9pbl9iID0gcmluZy5mcmFtZV9pZHggJSByaW5nLmZyYW1lc19wZXJf
YmxvY2s7CiAgICAgICAgdWludDhfdCAqZnJhbWVfcHRyID0gKCh1aW50OF90ICopcmluZy5yaW5n
KSArIChiX2lkeCAqIHJpbmcuYmxvY2tfc2l6ZSkgKyAoZl9pbl9iICogcmluZy5mcmFtZV9zaXpl
KTsKICAgICAgICB2b2xhdGlsZSBzdHJ1Y3QgdHBhY2tldDJfaGRyICp2b2xhdGlsZV9oZHIgPQog
ICAgICAgICAgICAodm9sYXRpbGUgc3RydWN0IHRwYWNrZXQyX2hkciAqKWZyYW1lX3B0cjsKCiAg
ICAgICAgaWYgKCEodm9sYXRpbGVfaGRyLT50cF9zdGF0dXMgJiBUUF9TVEFUVVNfVVNFUikpIHsK
ICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsK
CiAgICAgICAgY29uc3Qgc3RydWN0IHRwYWNrZXQyX2hkciAqaGRyID0KICAgICAgICAgICAgKGNv
bnN0IHN0cnVjdCB0cGFja2V0Ml9oZHIgKilmcmFtZV9wdHI7CiAgICAgICAgc2l6ZV90IHBhY2tl
dF9vZmZzZXQgPSAwLCBwYWNrZXRfbGVuZ3RoID0gMDsKICAgICAgICBpZiAoIXZhbGlkX3Jpbmdf
ZnJhbWUoaGRyLCByaW5nLmZyYW1lX3NpemUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICZwYWNrZXRfb2Zmc2V0LCAmcGFja2V0X2xlbmd0aCkpIHsKICAgICAgICAgIF9fc3luY19zeW5j
aHJvbml6ZSgpOwogICAgICAgICAgdm9sYXRpbGVfaGRyLT50cF9zdGF0dXMgPSBUUF9TVEFUVVNf
S0VSTkVMOwogICAgICAgICAgcmluZ19pbnRlZ3JpdHlfZmFpbHVyZSA9IHRydWU7CiAgICAgICAg
ICArK2dfaW52YWxpZF9mcmFtZXM7CiAgICAgICAgICBnX3J1bm5pbmcgPSAwOwogICAgICAgICAg
bG9nbXNnKCJpbnZhbGlkIFRQQUNLRVRfVjIgZnJhbWUgbWV0YWRhdGE7IHN0b3BwaW5nIGNhcHR1
cmUiKTsKICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgICAgICBpZiAocGFja2V0X2xlbmd0
aCA+IDApIHsKICAgICAgICAgIGNvbnN0IHVuc2lnbmVkIGNoYXIgKnBrdCA9IGZyYW1lX3B0ciAr
IHBhY2tldF9vZmZzZXQ7CiAgICAgICAgICArK2dfY2FwdHVyZV9wYWNrZXRzOwogICAgICAgICAg
Z19jYXB0dXJlX2J5dGVzICs9IHBhY2tldF9sZW5ndGg7CiAgICAgICAgICBoYW5kbGVfcGFja2V0
KHBrdCwgcGFja2V0X2xlbmd0aCwgbm9kZSwgcG9ydHMsIGZsb3dzLCBwZW5kaW5nKTsKICAgICAg
ICB9CgogICAgICAgIF9fc3luY19zeW5jaHJvbml6ZSgpOwogICAgICAgIHZvbGF0aWxlX2hkci0+
dHBfc3RhdHVzID0gVFBfU1RBVFVTX0tFUk5FTDsKICAgICAgICByaW5nLmZyYW1lX2lkeCA9IChy
aW5nLmZyYW1lX2lkeCArIDEpICUgcmluZy5mcmFtZV9ucjsKICAgICAgICArK2RyYWluX2NvdW50
OwogICAgICB9CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgp
OwogICAgfQoKICAgIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAtIGxhc3Qg
Pj0gMSkgewogICAgICBzd2VlcChmbG93cywgcGVuZGluZywgbm93LCBnX3BlbmRpbmdfdHRsX3Nl
Yyk7CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgpOwogICAg
ICBsYXN0ID0gbm93OwogICAgfQoKICAgIGlmICh3YWxsX3NlY29uZHMoKSAtIGdfc3RhdHNfbGFz
dF9hdCA+PSBnX3N0YXRzX2ludGVydmFsX3NlYykgewogICAgICBzaXplX3QgcGVuZGluZ19jb3Vu
dCA9IDAsIHdzc2VfY291bnQgPSAwOwogICAgICBmb3IgKHN0ZDo6bWFwPFBhY2tldEtleSwgc3Rk
Ojp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcGkgPSBwZW5kaW5nLmJlZ2luKCk7IHBpICE9
IHBlbmRpbmcuZW5kKCk7ICsrcGkpCiAgICAgICAgcGVuZGluZ19jb3VudCArPSBwaS0+c2Vjb25k
LnNpemUoKTsKICAgICAgZm9yIChzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgZmkg
PSBmbG93cy5iZWdpbigpOyBmaSAhPSBmbG93cy5lbmQoKTsgKytmaSkKICAgICAgICBpZiAoZmkt
PnNlY29uZC5hd2FpdGluZ193c3NlKSArK3dzc2VfY291bnQ7CiAgICAgIGlmICghZ19lbmRwb2lu
dC5lbXB0eSgpKQogICAgICAgIHNlbmRfYWdlbnRfc3RhdHMoZmQsIGZsb3dzLnNpemUoKSwgcGVu
ZGluZ19jb3VudCwgd3NzZV9jb3VudCk7CiAgICAgIGVsc2UKICAgICAgICBlbWl0X2NhcHR1cmVf
c3RhdHNfaW50ZXJuYWwoZmQsIGZsb3dzLnNpemUoKSwgcGVuZGluZ19jb3VudCwgd3NzZV9jb3Vu
dCk7CiAgICB9CiAgfQoKICBmbHVzaF9pbmNvbXBsZXRlX3dzc2UoZmxvd3MsIHBlbmRpbmcpOwog
IGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwogIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0
ZDo6Y291dC5mbHVzaCgpOwoKICBpZiAoZ19zaGlwX3dvcmtlcl9hY3RpdmUpIHsKICAgIHB0aHJl
YWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgIGdfcHJvZHVjZXJfZmluaXNo
ZWQgPSB0cnVlOwogICAgcHRocmVhZF9jb25kX2Jyb2FkY2FzdCgmZ19zaGlwX3F1ZXVlX2NvbmQp
OwogICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICBwdGhy
ZWFkX2pvaW4oZ19zaGlwX3dvcmtlcl90aWQsIE5VTEwpOwogIH0gZWxzZSBpZiAoZ19lbmRwb2lu
dC5lbXB0eSgpKSB7CiAgICBzaXplX3QgcGVuZGluZ19jb3VudCA9IDA7CiAgICBlbWl0X2NhcHR1
cmVfc3RhdHNfaW50ZXJuYWwoZmQsIDAsIHBlbmRpbmdfY291bnQsIDApOwogIH0KCiAgdXBkYXRl
X2tlcm5lbF9kcm9wcyhmZCk7CiAgbG9nbXNnKCJwYWNrZXQgc3RhdHM6IHJlY2VpdmVkPSIgKyB1
bGxfc3RyaW5nKGdfY2FwdHVyZV9wYWNrZXRzKSArCiAgICAgICAgICIgZHJvcHBlZD0iICsgdWxs
X3N0cmluZyhnX2tlcm5lbF9kcm9wcykpOwogIGlmICghcmVsZWFzZV9tbWFwX3JpbmcoZmQsIHJp
bmcpKSB7CiAgICBsb2dtc2coIlRQQUNLRVRfVjIgY2xlYW51cCBmYWlsZWQiKTsKICAgIHJpbmdf
aW50ZWdyaXR5X2ZhaWx1cmUgPSB0cnVlOwogIH0KICBjbG9zZShmZCk7CiAgbG9nbXNnKCJzdG9w
cGVkIik7CiAgcmV0dXJuIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPyAyIDogMDsKfQo=
#__END_CPP__
#__CPP_MAKE_B64__
IyBHQ0MgNC40IC8gQ2VudE9TIDYgY29tcGF0aWJsZTogQysrMDMsIGdudSsrMDMgb3IgZ251Kys5
OC4KQ1hYID89IGcrKwpDWFhTVEQgPz0gJChzaGVsbCAkKENYWCkgLXN0ZD1nbnUrKzAzIC14IGMr
KyAtRSAvZGV2L251bGwgPi9kZXYvbnVsbCAyPiYxICYmIGVjaG8gLXN0ZD1nbnUrKzAzIHx8IGVj
aG8gLXN0ZD1nbnUrKzk4KQpDWFhGTEFHUyA/PSAtTzIgLVdhbGwgLVdleHRyYSAkKENYWFNURCkg
LXB0aHJlYWQgLWxydAoKLlBIT05ZOiBhbGwgY3BwIGNwcC1zaGlwIGNwcC1kZWJ1ZyBmaXh0dXJl
IHBjYXAtZml4dHVyZSBjbGVhbgoKYWxsOiBjcHAgY3BwLXNoaXAKCmNwcDoKCSQoQ1hYKSAkKENY
WEZMQUdTKSBudC1zbmlmZi1jcHAuY3BwIC1vIG50LXNuaWZmLWNwcAoKY3BwLXNoaXA6CgkkKENY
WCkgJChDWFhGTEFHUykgbnQtc2hpcC1jcHAuY3BwIC1vIG50LXNoaXAtY3BwCgpjcHAtZGVidWc6
CgkkKENYWCkgLU8wIC1nIC1XYWxsIC1XZXh0cmEgLXN0ZD1nbnUrKzAzIG50LXNuaWZmLWNwcC5j
cHAgLW8gbnQtc25pZmYtY3BwLWRlYnVnCgpmaXh0dXJlOiBjcHAKCS4vbnQtc25pZmYtY3BwIC0t
Zml4dHVyZQoJLi9udC1zbmlmZi1jcHAgLS1yaW5nLWZpeHR1cmUKCS4vbnQtc25pZmYtY3BwIC0t
c2hpcC1yYXRlLWZpeHR1cmUKCS4vbnQtc25pZmYtY3BwIC0tc3RhdHMtZml4dHVyZQoKcGNhcC1m
aXh0dXJlOiBwY2FwX3Rlc3RfY3BwCgpwY2FwX3Rlc3RfY3BwOiBwY2FwX3Rlc3RfY3BwLmNwcCBu
dC1zbmlmZi1jcHAuY3BwCgkkKENYWCkgJChDWFhGTEFHUykgcGNhcF90ZXN0X2NwcC5jcHAgLW8g
cGNhcF90ZXN0X2NwcAoKY2xlYW46CglybSAtZiBudC1zbmlmZi1jcHAgbnQtc25pZmYtY3BwLWRl
YnVnIG50LXNoaXAtY3BwIHBjYXBfdGVzdF9jcHAK
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
