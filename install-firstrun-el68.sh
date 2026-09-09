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
bmRpbmcgPSB7fQpjb3JyX2Rpc2FibGVkID0gc2V0KCkKCgpkZWYgcGVuZGluZ19kZWwocmspOgog
ICAgcGVuZGluZy5wb3AocmssIE5vbmUpCiAgICBjb3JyX2Rpc2FibGVkLmRpc2NhcmQocmspCgoK
CmRlZiBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibD1Ob25lKToKICAgICIiIkZsdXNo
IHRoZSBvbGRlc3QgcGVuZGluZyBldmVudCBmb3IgdGhpcyByZXNwb25zZSB0dXBsZSAoRklOL1JT
VCBvcgogICAgb3ZlcmZsb3cgcGF0aCkuIEVtaXRzIHdoYXRldmVyIHRoZSBldmVudCBoYXMg4oCU
IHN0YXR1cyBzdGF5cyBudWxsLiIiIgogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAg
ICBwZW5kaW5nX3RibCA9IHBlbmRpbmcKICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAg
IGlmIG5vdCBsc3Q6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGl0ZW0gPSBsc3QucG9wKDApCiAg
ICBpZiBub3QgbHN0OgogICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgIGlzX3Rv
bWJzdG9uZSA9IGl0ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZhbHNlCiAgICBpZiBub3Qg
aXNfdG9tYnN0b25lOgogICAgICAgIG91dC5hcHBlbmQoaXRlbVswXSkKICAgICAgICByZXR1cm4g
aXRlbVswXQogICAgcmV0dXJuIE5vbmUKCgpkZWYgcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2Fk
KToKICAgICIiIkZpcnN0IGxpbmUgJ0hUVFAvMS54IE5OTiAuLi4nIC0+IChzdGF0dXNfaW50fE5v
bmUsIGNvbnRlbnRfbGVufE5vbmUsIGhlYWRfZW5kX2lkeHxOb25lLCBpc19jaHVua2VkLCBpc19j
bG9zZSkuIiIiCiAgICB0cnk6CiAgICAgICAgcmF3ID0gYnl0ZXMocGF5bG9hZCkKICAgICAgICBp
ZHggPSByYXcuZmluZChiIlxyXG5cclxuIikKICAgICAgICBpZiBpZHggPCAwOgogICAgICAgICAg
ICByZXR1cm4gTm9uZSwgTm9uZSwgTm9uZSwgRmFsc2UsIEZhbHNlCiAgICAgICAgaGVhZCA9IHJh
d1s6aWR4XQogICAgICAgIGxpbmVzID0gaGVhZC5yZXBsYWNlKGIiXHJcbiIsIGIiXG4iKS5zcGxp
dChiIlxuIikKICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnNwbGl0KCkKICAgICAgICBpZiBsZW4o
Zmlyc3QpIDwgMiBvciBub3QgZmlyc3RbMF0uc3RhcnRzd2l0aChiIkhUVFAvIik6CiAgICAgICAg
ICAgIHJldHVybiBOb25lLCBOb25lLCBpZHggKyA0LCBGYWxzZSwgRmFsc2UKICAgICAgICBzdCA9
IGludChmaXJzdFsxXSkKICAgICAgICBpZiBzdCA8IDEwMCBvciBzdCA+IDU5OToKICAgICAgICAg
ICAgcmV0dXJuIE5vbmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBGYWxzZQogICAgZXhjZXB0IChWYWx1
ZUVycm9yLCBJbmRleEVycm9yKToKICAgICAgICByZXR1cm4gTm9uZSwgTm9uZSwgTm9uZSwgRmFs
c2UsIEZhbHNlCiAgICBjbGVuID0gTm9uZQogICAgaGFzX2NsZW4gPSBGYWxzZQogICAgaGFzX2Nv
bmZsaWN0X2NsID0gRmFsc2UKICAgIGlzX2NodW5rZWQgPSBGYWxzZQogICAgaXNfY2xvc2UgPSBG
YWxzZQogICAgaXNfaHR0cF8xMCA9IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLzEuMCIpCiAg
ICBjb25uX2Nsb3NlID0gRmFsc2UKICAgIGNvbm5fa2VlcF9hbGl2ZSA9IEZhbHNlCiAgICBmb3Ig
bG4gaW4gbGluZXNbMTpdOgogICAgICAgIGxvdyA9IGxuLmxvd2VyKCkKICAgICAgICBpZiBsb3cu
c3RhcnRzd2l0aChiImNvbnRlbnQtbGVuZ3RoOiIpOgogICAgICAgICAgICB0cnk6CiAgICAgICAg
ICAgICAgICB2YWwgPSBpbnQobG4uc3BsaXQoYiI6IiwgMSlbMV0uc3RyaXAoKSkKICAgICAgICAg
ICAgICAgIGlmIHZhbCA8IDA6CiAgICAgICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0g
VHJ1ZQogICAgICAgICAgICAgICAgZWxpZiBoYXNfY2xlbiBhbmQgY2xlbiAhPSB2YWw6CiAgICAg
ICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAgICAgICAgICAgY2xl
biA9IHZhbAogICAgICAgICAgICAgICAgaGFzX2NsZW4gPSBUcnVlCiAgICAgICAgICAgIGV4Y2Vw
dCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAg
ICAgIGVsaWYgbG93LnN0YXJ0c3dpdGgoYiJ0cmFuc2Zlci1lbmNvZGluZzoiKToKICAgICAgICAg
ICAgaWYgYiJjaHVua2VkIiBpbiBsb3c6CiAgICAgICAgICAgICAgICBpc19jaHVua2VkID0gVHJ1
ZQogICAgICAgIGVsaWYgbG93LnN0YXJ0c3dpdGgoYiJjb25uZWN0aW9uOiIpOgogICAgICAgICAg
ICBpZiBiImNsb3NlIiBpbiBsb3c6CiAgICAgICAgICAgICAgICBjb25uX2Nsb3NlID0gVHJ1ZQog
ICAgICAgICAgICBlbGlmIGIia2VlcC1hbGl2ZSIgaW4gbG93OgogICAgICAgICAgICAgICAgY29u
bl9rZWVwX2FsaXZlID0gVHJ1ZQogICAgaWYgaGFzX2NvbmZsaWN0X2NsIG9yIChoYXNfY2xlbiBh
bmQgaXNfY2h1bmtlZCk6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBG
YWxzZQogICAgaWYgaXNfaHR0cF8xMCBhbmQgbm90IGNvbm5fa2VlcF9hbGl2ZToKICAgICAgICBp
c19jbG9zZSA9IFRydWUKICAgIGVsaWYgY29ubl9jbG9zZToKICAgICAgICBpc19jbG9zZSA9IFRy
dWUKICAgIHJldHVybiBzdCwgY2xlbiwgaWR4ICsgNCwgaXNfY2h1bmtlZCwgaXNfY2xvc2UKCgoK
ZGVmIGhhbmRsZV9yZXNwb25zZShyZXNwX2Zsb3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBl
bmRpbmdfdGJsLCBzZXE9Tm9uZSwgZmxhZ3M9MCwgaXNfdHJ1bmNhdGVkPUZhbHNlKToKICAgIGlm
IGZsYWdzICYgMHgwMiBhbmQgc2VxIGlzIG5vdCBOb25lOgogICAgICAgIHJmbCA9IHJlc3BfZmxv
d3NbcmtdID0gRmxvdygpCiAgICAgICAgcmZsLmhhc19zZXEgPSBUcnVlCiAgICAgICAgcmZsLm5l
eHRfc2VxID0gKHNlcSArIDEpICYgMHhGRkZGRkZGRgogICAgICAgIHJmbC50b3VjaGVkID0gbm93
CiAgICAgICAgcmV0dXJuCgogICAgcmZsID0gcmVzcF9mbG93cy5nZXQocmspCiAgICBpZiByZmwg
aXMgTm9uZToKICAgICAgICByZmwgPSBGbG93KCkKICAgICAgICByZXNwX2Zsb3dzW3JrXSA9IHJm
bAogICAgcmZsLnRvdWNoZWQgPSBub3cKCiAgICBwbGVuID0gbGVuKHBheWxvYWQpIGlmIHBheWxv
YWQgZWxzZSAwCiAgICBpZiBwbGVuID4gMDoKICAgICAgICBpZiBzZXEgaXMgTm9uZToKICAgICAg
ICAgICAgcmZsLmJ1Zi5leHRlbmQocGF5bG9hZCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBp
ZiBub3QgcmZsLmhhc19zZXE6CiAgICAgICAgICAgICAgICBpZiAocGxlbiA+PSA1IGFuZCBwYXls
b2FkWzo1XSA9PSBiIkhUVFAvIikgb3IgKHBsZW4gPCA1IGFuZCBiIkhUVFAvIi5zdGFydHN3aXRo
KHBheWxvYWQpKToKICAgICAgICAgICAgICAgICAgICByZmwuaGFzX3NlcSA9IFRydWUKICAgICAg
ICAgICAgICAgICAgICByZmwubmV4dF9zZXEgPSBzZXEKICAgICAgICAgICAgICAgICAgICByZmwu
aXNfYnJva2VuID0gRmFsc2UKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAg
ICAgaWYgbGVuKHJmbC5vb28pIDwgTUFYX09PT19TRUdNRU5UUyBhbmQgbm90IGlzX3RydW5jYXRl
ZDoKICAgICAgICAgICAgICAgICAgICAgICAgaWYgbm90IGFueShzID09IHNlcSBmb3IgcywgXyBp
biByZmwub29vKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5vb28uYXBwZW5kKChz
ZXEsIGJ5dGVzKHBheWxvYWQpKSkKICAgICAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAg
ICAgIGRpZmYgPSBzZXFfZGlmZihzZXEsIHJmbC5uZXh0X3NlcSkKICAgICAgICAgICAgaWYgZGlm
ZiA9PSAwOgogICAgICAgICAgICAgICAgaWYgaXNfdHJ1bmNhdGVkOgogICAgICAgICAgICAgICAg
ICAgIHJmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAg
ICAgICAgICAgIHJmbC5idWYuZXh0ZW5kKHBheWxvYWQpCiAgICAgICAgICAgICAgICAgICAgcmZs
Lm5leHRfc2VxID0gKHJmbC5uZXh0X3NlcSArIHBsZW4pICYgMHhGRkZGRkZGRgogICAgICAgICAg
ICAgICAgICAgIF9kcmFpbl9vb28ocmZsKQogICAgICAgICAgICBlbGlmIGRpZmYgPCAwOgogICAg
ICAgICAgICAgICAgb3ZlcmxhcCA9IC1kaWZmCiAgICAgICAgICAgICAgICBpZiBvdmVybGFwIDwg
cGxlbiBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICByZmwuYnVmLmV4
dGVuZChwYXlsb2FkW292ZXJsYXA6XSkKICAgICAgICAgICAgICAgICAgICByZmwubmV4dF9zZXEg
PSAocmZsLm5leHRfc2VxICsgcGxlbiAtIG92ZXJsYXApICYgMHhGRkZGRkZGRgogICAgICAgICAg
ICAgICAgICAgIF9kcmFpbl9vb28ocmZsKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAg
ICAgaWYgbGVuKHJmbC5vb28pIDwgTUFYX09PT19TRUdNRU5UUyBhbmQgbm90IGlzX3RydW5jYXRl
ZDoKICAgICAgICAgICAgICAgICAgICBpZiBub3QgYW55KHMgPT0gc2VxIGZvciBzLCBfIGluIHJm
bC5vb28pOgogICAgICAgICAgICAgICAgICAgICAgICByZmwub29vLmFwcGVuZCgoc2VxLCBieXRl
cyhwYXlsb2FkKSkpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHJm
bC5pc19icm9rZW4gPSBUcnVlCgogICAgIyBQYXJzZSBjb21wbGV0ZSByZXNwb25zZXMgZnJvbSBy
ZWFzc2VtYmxlZCBidWZmZXIgdXNpbmcgSFRUUCBmcmFtaW5nCiAgICB3aGlsZSByZmwuYnVmIGFu
ZCBub3QgcmZsLmlzX2Jyb2tlbjoKICAgICAgICBpZiByZmwuc3RhdGUgPT0gSFRUUF9TVEFURV9I
RUFERVI6CiAgICAgICAgICAgIHN0LCBjbGVuLCBoZWFkX2xlbiwgaXNfY2h1bmtlZCwgaXNfY2xv
c2UgPSBwYXJzZV9yZXNwb25zZV9oZWFkKHJmbC5idWYpCiAgICAgICAgICAgIGlmIHN0IGlzIE5v
bmU6CiAgICAgICAgICAgICAgICBpZiBoZWFkX2xlbiBpcyBub3QgTm9uZToKICAgICAgICAgICAg
ICAgICAgICBkZWwgcmZsLmJ1Zls6aGVhZF9sZW5dCiAgICAgICAgICAgICAgICBlbGlmIHJmbC5i
dWYuZmluZChiIlxyXG5cclxuIikgIT0gLTE6CiAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9
IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IFRydWUKICAg
ICAgICAgICAgICAgIGJyZWFrCgogICAgICAgICAgICBpZiAxMDAgPD0gc3QgPD0gMTk5IGFuZCBz
dCAhPSAxMDE6CiAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6aGVhZF9sZW5dCiAgICAgICAg
ICAgICAgICBjb250aW51ZQoKICAgICAgICAgICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKSBp
ZiByayBub3QgaW4gY29ycl9kaXNhYmxlZCBlbHNlIE5vbmUKICAgICAgICAgICAgaXNfaGVhZCA9
IEZhbHNlCiAgICAgICAgICAgIGlmIGVudDoKICAgICAgICAgICAgICAgIGl0ZW0gPSBlbnRbMF0K
ICAgICAgICAgICAgICAgIGlzX3RvbWJzdG9uZSA9IGl0ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBl
bHNlIEZhbHNlCiAgICAgICAgICAgICAgICBnZW4gPSBpdGVtWzRdIGlmIGxlbihpdGVtKSA+IDQg
ZWxzZSAwCiAgICAgICAgICAgICAgICBpZiByZmwuZ2VuZXJhdGlvbiAhPSAwIGFuZCBnZW4gIT0g
MCBhbmQgZ2VuICE9IHJmbC5nZW5lcmF0aW9uOgogICAgICAgICAgICAgICAgICAgIGV2ID0gaXRl
bVswXQogICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgICAgICAgICAg
ICAgZW50LnBvcCgwKQogICAgICAgICAgICAgICAgICAgIGlmIG5vdCBlbnQ6CiAgICAgICAgICAg
ICAgICAgICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgICAgICAgICAgICAgIGVs
aWYgaXNfdG9tYnN0b25lOgogICAgICAgICAgICAgICAgICAgIGVudC5wb3AoMCkKICAgICAgICAg
ICAgICAgICAgICBpZiBub3QgZW50OgogICAgICAgICAgICAgICAgICAgICAgICBwZW5kaW5nX3Ri
bC5wb3AocmssIE5vbmUpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAg
IGV2LCBzdGFydGVkID0gaXRlbVswXSwgaXRlbVsxXQogICAgICAgICAgICAgICAgICAgIGVudC5w
b3AoMCkKICAgICAgICAgICAgICAgICAgICBpZiBub3QgZW50OgogICAgICAgICAgICAgICAgICAg
ICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAgICAgICAgICAgICAgaWYgZXYu
Z2V0KCJtZXRob2QiKSA9PSAiSEVBRCI6CiAgICAgICAgICAgICAgICAgICAgICAgIGlzX2hlYWQg
PSBUcnVlCiAgICAgICAgICAgICAgICAgICAgZXZbInN0YXR1cyJdID0gc3QKICAgICAgICAgICAg
ICAgICAgICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgwLCBpbnQoKG5vdyAtIHN0YXJ0ZWQpICog
MTAwMCkpCiAgICAgICAgICAgICAgICAgICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAgICAg
ICAgICAgICAgICAgICAgZXZbInJlc3BfYnl0ZXMiXSA9IGNsZW4KICAgICAgICAgICAgICAgICAg
ICBvdXQuYXBwZW5kKGV2KQoKICAgICAgICAgICAgZGVsIHJmbC5idWZbOmhlYWRfbGVuXQoKICAg
ICAgICAgICAgaWYgaXNfaGVhZCBvciBzdCA9PSAyMDQgb3Igc3QgPT0gMzA0OgogICAgICAgICAg
ICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgZWxpZiBpc19j
aHVua2VkOgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9DSFVOSwogICAg
ICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0gVHJ1ZQogICAgICAgICAgICAgICAg
cmZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IEZhbHNlCiAgICAgICAgICAgICAgICByZmwuY2h1bmtf
cmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgIHJmbC5jaHVua19wYXlsb2Fk
X3JlbWFpbmluZyA9IDAKICAgICAgICAgICAgZWxpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAg
ICAgICAgICAgaWYgY2xlbiA+IDA6CiAgICAgICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRU
UF9TVEFURV9CT0RZCiAgICAgICAgICAgICAgICAgICAgcmZsLmJvZHlfcmVtYWluaW5nID0gY2xl
bgogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICByZmwuc3RhdGUgPSBI
VFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmZsLnN0
YXRlID0gSFRUUF9TVEFURV9DTE9TRV9CT0RZCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAg
IGlmIHJmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0JPRFk6CiAgICAgICAgICAgIGlmIG5vdCByZmwu
YnVmOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgdG9fY29uc3VtZSA9IG1pbihs
ZW4ocmZsLmJ1ZiksIHJmbC5ib2R5X3JlbWFpbmluZykKICAgICAgICAgICAgZGVsIHJmbC5idWZb
OnRvX2NvbnN1bWVdCiAgICAgICAgICAgIHJmbC5ib2R5X3JlbWFpbmluZyAtPSB0b19jb25zdW1l
CiAgICAgICAgICAgIGlmIHJmbC5ib2R5X3JlbWFpbmluZyA9PSAwOgogICAgICAgICAgICAgICAg
cmZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgY29udGludWUKCiAgICAg
ICAgaWYgcmZsLnN0YXRlID09IEhUVFBfU1RBVEVfQ0hVTks6CiAgICAgICAgICAgIGlmIG5vdCBy
ZmwuYnVmOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYgcmZsLmNodW5rX3Jl
YWRpbmdfdHJhaWxlcjoKICAgICAgICAgICAgICAgIGlmIGxlbihyZmwuYnVmKSA+PSAyIGFuZCBy
ZmwuYnVmWzoyXSA9PSBiIlxyXG4iOgogICAgICAgICAgICAgICAgICAgIGRlbCByZmwuYnVmWzoy
XQogICAgICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQog
ICAgICAgICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAg
ICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIHRyX2VuZCA9IHJmbC5idWYuZmlu
ZChiIlxyXG5cclxuIikKICAgICAgICAgICAgICAgIGlmIHRyX2VuZCAhPSAtMToKICAgICAgICAg
ICAgICAgICAgICBkZWwgcmZsLmJ1Zls6dHJfZW5kICsgNF0KICAgICAgICAgICAgICAgICAgICBy
ZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICByZmwu
c3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAg
ICAgICAgICAgICAgICBpZiBsZW4ocmZsLmJ1ZikgPiBNQVhfSERSUzoKICAgICAgICAgICAgICAg
ICAgICByZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJv
a2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYgcmZsLmNodW5r
X3JlYWRpbmdfbGVuOgogICAgICAgICAgICAgICAgY3JsZiA9IHJmbC5idWYuZmluZChiIlxyXG4i
KQogICAgICAgICAgICAgICAgaWYgY3JsZiA9PSAtMToKICAgICAgICAgICAgICAgICAgICBpZiBs
ZW4ocmZsLmJ1ZikgPiA2NDoKICAgICAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVh
cnJheSgpCiAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVlCiAgICAg
ICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGxpbmUgPSBieXRlcyhyZmwuYnVm
WzpjcmxmXSkuc3RyaXAoKQogICAgICAgICAgICAgICAgc2VtaSA9IGxpbmUuZmluZChiIjsiKQog
ICAgICAgICAgICAgICAgaGV4X3N0ciA9IGxpbmVbOnNlbWldLnN0cmlwKCkgaWYgc2VtaSAhPSAt
MSBlbHNlIGxpbmUKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBjaHVu
a19sZW4gPSBpbnQoaGV4X3N0ciwgMTYpCiAgICAgICAgICAgICAgICAgICAgaWYgY2h1bmtfbGVu
IDwgMCBvciBjaHVua19sZW4gPiAxNjc3NzIxNjoKICAgICAgICAgICAgICAgICAgICAgICAgcmZs
LmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4g
PSBUcnVlCiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBleGNl
cHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICByZmwuYnVmID0gYnl0ZWFycmF5KCkK
ICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAg
ICAgIGJyZWFrCiAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6Y3JsZiArIDJdCiAgICAgICAg
ICAgICAgICBpZiBjaHVua19sZW4gPT0gMDoKICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtf
cmVhZGluZ190cmFpbGVyID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFk
aW5nX2xlbiA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAg
ICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5n
ID0gY2h1bmtfbGVuCiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0g
RmFsc2UKICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gRmFsc2UK
ICAgICAgICAgICAgZWxpZiBnZXRhdHRyKHJmbCwgImNodW5rX3JlYWRpbmdfY3JsZiIsIEZhbHNl
KToKICAgICAgICAgICAgICAgIGlmIGxlbihyZmwuYnVmKSA8IDI6CiAgICAgICAgICAgICAgICAg
ICAgYnJlYWsKICAgICAgICAgICAgICAgIGlmIHJmbC5idWZbOjJdICE9IGIiXHJcbiI6CiAgICAg
ICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAg
cmZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAg
ICAgICAgZGVsIHJmbC5idWZbOjJdCiAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19j
cmxmID0gRmFsc2UKICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IFRydWUK
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4obGVuKHJm
bC5idWYpLCByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcpCiAgICAgICAgICAgICAgICBkZWwg
cmZsLmJ1Zls6dG9fY29uc3VtZV0KICAgICAgICAgICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3Jl
bWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAgICAgICBpZiByZmwuY2h1bmtfcGF5bG9h
ZF9yZW1haW5pbmcgPT0gMDoKICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19j
cmxmID0gVHJ1ZQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBpZiByZmwuc3RhdGUgPT0g
SFRUUF9TVEFURV9DTE9TRV9CT0RZOgogICAgICAgICAgICBkZWwgcmZsLmJ1Zls6XQogICAgICAg
ICAgICBicmVhawoKICAgIGlmIGZsYWdzICYgMHgwNToKICAgICAgICByZXNwX2Zsb3dzLnBvcChy
aywgTm9uZSkKICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibCkKCgpkZWYg
Y29ycmVsYXRlX3Jlc3BvbnNlKHBlbmRpbmdfdGJsLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHJl
c3BfZmxvd3M9Tm9uZSwgc2VxPU5vbmUsIGZsYWdzPTAsIGlzX3RydW5jYXRlZD1GYWxzZSk6CiAg
ICAiIiJBdHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhlIG9sZGVzdCByZXF1ZXN0IG9uIGEg
Y29ubmVjdGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5nIGNhbiBsZWF2ZSBzZXZlcmFsIHJl
cXVlc3RzIHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXItdHVwbGUuIENvbnN1bWUgZXhhY3Rs
eSBvbmUgZW50cnk7IGRlbGV0aW5nIHRoZSB3aG9sZSBrZXkgaGVyZSBsb3NlcwogICAgZXZlcnkg
cmVxdWVzdCBhZnRlciB0aGUgZmlyc3QgcmVzcG9uc2UuCiAgICAiIiIKICAgIGlmIHJlc3BfZmxv
d3MgaXMgbm90IE5vbmU6CiAgICAgICAgaGFuZGxlX3Jlc3BvbnNlKHJlc3BfZmxvd3MsIHJrLCBw
YXlsb2FkLCBub3csIG91dCwgcGVuZGluZ190YmwsCiAgICAgICAgICAgICAgICAgICAgICAgIHNl
cT1zZXEsIGZsYWdzPWZsYWdzLCBpc190cnVuY2F0ZWQ9aXNfdHJ1bmNhdGVkKQogICAgICAgIHJl
dHVybiBUcnVlCiAgICByZXMgPSBwYXJzZV9yZXNwb25zZV9oZWFkKHBheWxvYWQpCiAgICBpZiBy
ZXNbMF0gaXMgTm9uZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHN0LCBjbGVuLCBoZWFkX2xl
biA9IHJlc1swXSwgcmVzWzFdLCByZXNbMl0KICAgIGlmIDEwMCA8PSBzdCA8PSAxOTkgYW5kIHN0
ICE9IDEwMToKICAgICAgICBpZiBoZWFkX2xlbiBpcyBub3QgTm9uZSBhbmQgbGVuKHBheWxvYWQp
ID4gaGVhZF9sZW46CiAgICAgICAgICAgIHJldHVybiBjb3JyZWxhdGVfcmVzcG9uc2UocGVuZGlu
Z190YmwsIHJrLCBwYXlsb2FkW2hlYWRfbGVuOl0sIG5vdywgb3V0KQogICAgICAgIHJldHVybiBG
YWxzZQogICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQogICAgaWYgbm90IGVudDoKICAgICAg
ICByZXR1cm4gRmFsc2UKICAgIGV2LCBzdGFydGVkID0gZW50LnBvcCgwKQogICAgaWYgbm90IGVu
dDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICBldlsic3RhdHVzIl0gPSBz
dAogICAgZXZbImR1cmF0aW9uX21zIl0gPSBtYXgoMCwgaW50KChub3cgLSBzdGFydGVkKSAqIDEw
MDApKQogICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAgICBldlsicmVzcF9ieXRlcyJdID0g
Y2xlbgogICAgb3V0LmFwcGVuZChldikKICAgIHJldHVybiBUcnVlCgoKZGVmIHZhbGlkX3BvcnQo
cCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIDEgPD0gaW50KHApIDw9IDY1NTM1CiAgICBleGNl
cHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGJh
c2ljX3VzZXIodmFsdWUpOgogICAgIiIiQXV0aG9yaXphdGlvbiBoZWFkZXIgdmFsdWUgLT4gKHVz
ZXJ8Tm9uZSwgc2NoZW1lfE5vbmUpLiBCYXNpYyBvbmx5LiIiIgogICAgcGFydHMgPSB2YWx1ZS5z
dHJpcCgpLnNwbGl0KE5vbmUsIDEpCiAgICBpZiBsZW4ocGFydHMpICE9IDI6CiAgICAgICAgcmV0
dXJuIE5vbmUsIE5vbmUKICAgIHNjaGVtZSA9IHBhcnRzWzBdLmxvd2VyKCkKICAgIGlmIHNjaGVt
ZSA9PSAiYmFzaWMiOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGFkID0gcGFydHNbMV0uc3Ry
aXAoKQogICAgICAgICAgICBpZiBsZW4ocGFkKSA+IDEwMjQ6CiAgICAgICAgICAgICAgICByZXR1
cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBwYWQgKz0gIj0iICogKC1sZW4ocGFkKSAlIDQpCiAg
ICAgICAgICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNvZGUocGFkKQogICAgICAgICAgICBpZiBsZW4o
cmF3KSA+IDUxMjoKICAgICAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAg
IGlmIGIiOiIgaW4gcmF3OgogICAgICAgICAgICAgICAgdXNlciA9IHJhdy5zcGxpdChiIjoiLCAx
KVswXQogICAgICAgICAgICAgICAgdXNlciA9IHVzZXIuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNl
IilbOjY0XQogICAgICAgICAgICAgICAgaWYgdXNlcjoKICAgICAgICAgICAgICAgICAgICByZXR1
cm4gdXNlciwgImJhc2ljIgogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHJl
dHVybiBOb25lLCBOb25lCiAgICBlbGlmIHNjaGVtZSA9PSAiYmVhcmVyIjoKICAgICAgICByZXR1
cm4gTm9uZSwgImJlYXJlciIKICAgIHJldHVybiBOb25lLCBOb25lCgoKZGVmIG5vcm1hbGl6ZV93
c3NlX3VzZXJuYW1lKHZhbHVlKToKICAgICIiIlJldHVybiBhIHNtYWxsLCBwcmludGFibGUgdXNl
cm5hbWUgb3IgTm9uZTsgbmV2ZXIgcmV0dXJuIHRva2VuIGRhdGEuIiIiCiAgICBpZiB2YWx1ZSBp
cyBOb25lOgogICAgICAgIHJldHVybiBOb25lCiAgICB0cnk6CiAgICAgICAgdXNlcm5hbWUgPSB2
YWx1ZS5zdHJpcCgpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBOb25lCiAg
ICBpZiBub3QgdXNlcm5hbWUgb3IgbGVuKHVzZXJuYW1lKSA+IE1BWF9XU1NFX1VTRVJOQU1FOgog
ICAgICAgIHJldHVybiBOb25lCiAgICBmb3IgY2hhciBpbiB1c2VybmFtZToKICAgICAgICBpZiB1
bmljb2RlZGF0YS5jYXRlZ29yeShjaGFyKS5zdGFydHN3aXRoKCJDIik6CiAgICAgICAgICAgIHJl
dHVybiBOb25lCiAgICByZXR1cm4gdXNlcm5hbWUKCgpkZWYgZXh0cmFjdF93c3NlX3VzZXJuYW1l
KGJvZHkpOgogICAgIiIiUGFyc2UgYSBib3VuZGVkLCBwb3NzaWJseSBwYXJ0aWFsIFNPQVAgcHJl
Zml4IGFuZCByZXR1cm4gb25seSBVc2VybmFtZS4KCiAgICBFeHBhdCBpcyBydW4gaW5jcmVtZW50
YWxseSBzbyBhIFVzZXJuYW1lVG9rZW4gaW4gdGhlIFNPQVAgSGVhZGVyIGNhbiBiZQogICAgcmVj
b2duaXplZCB3aXRob3V0IHJldGFpbmluZyBvciByZXF1aXJpbmcgdGhlIGNvbXBsZXRlIHJlcXVl
c3QgYm9keS4KICAgIERURC9lbnRpdHkgZGVjbGFyYXRpb25zIGFyZSByZWplY3RlZCBiZWZvcmUg
cGFyc2luZy4KICAgICIiIgogICAgaWYgbm90IGJvZHkgb3IgbGVuKGJvZHkpID4gTUFYX1dTU0Vf
Qk9EWV9CWVRFUyBvciBiIlx4MDAiIGluIGJvZHk6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGxv
d2VyZWQgPSBieXRlcyhib2R5KS5sb3dlcigpCiAgICBpZiBiIjwhZG9jdHlwZSIgaW4gbG93ZXJl
ZCBvciBiIjwhZW50aXR5IiBpbiBsb3dlcmVkOgogICAgICAgIHJldHVybiBOb25lCgogICAgc3Rh
dGUgPSB7InN0YWNrIjogW10sICJ0b2tlbl9kZXB0aCI6IDAsICJ1c2VybmFtZV9kZXB0aCI6IDAs
CiAgICAgICAgICAgICAiY2hhcnMiOiBbXSwgInRvb19sb25nIjogRmFsc2UsICJyZXN1bHQiOiBO
b25lfQoKICAgIGRlZiBzcGxpdF9uYW1lKG5hbWUpOgogICAgICAgIGlmICJ9IiBub3QgaW4gbmFt
ZToKICAgICAgICAgICAgcmV0dXJuICIiLCBuYW1lCiAgICAgICAgcmV0dXJuIG5hbWUucnNwbGl0
KCJ9IiwgMSkKCiAgICBkZWYgc3RhcnQobmFtZSwgYXR0cnMpOgogICAgICAgIG5hbWVzcGFjZSwg
bG9jYWxfbmFtZSA9IHNwbGl0X25hbWUobmFtZSkKICAgICAgICBzdGF0ZVsic3RhY2siXS5hcHBl
bmQoKG5hbWVzcGFjZSwgbG9jYWxfbmFtZSkpCiAgICAgICAgZGVwdGggPSBsZW4oc3RhdGVbInN0
YWNrIl0pCiAgICAgICAgaWYgKG5vdCBzdGF0ZVsidG9rZW5fZGVwdGgiXSBhbmQgbG9jYWxfbmFt
ZSA9PSAiVXNlcm5hbWVUb2tlbiIgYW5kCiAgICAgICAgICAgICAgICBuYW1lc3BhY2UgaW4gV1NT
RV9OQU1FU1BBQ0VTKToKICAgICAgICAgICAgc3RhdGVbInRva2VuX2RlcHRoIl0gPSBkZXB0aAog
ICAgICAgIGVsaWYgKHN0YXRlWyJ0b2tlbl9kZXB0aCJdIGFuZAogICAgICAgICAgICAgIGRlcHRo
ID09IHN0YXRlWyJ0b2tlbl9kZXB0aCJdICsgMSBhbmQKICAgICAgICAgICAgICBsb2NhbF9uYW1l
ID09ICJVc2VybmFtZSIgYW5kCiAgICAgICAgICAgICAgbmFtZXNwYWNlID09IHN0YXRlWyJzdGFj
ayJdW3N0YXRlWyJ0b2tlbl9kZXB0aCJdIC0gMV1bMF0pOgogICAgICAgICAgICBzdGF0ZVsidXNl
cm5hbWVfZGVwdGgiXSA9IGRlcHRoCiAgICAgICAgICAgIHN0YXRlWyJjaGFycyJdID0gW10KICAg
ICAgICAgICAgc3RhdGVbInRvb19sb25nIl0gPSBGYWxzZQoKICAgIGRlZiBjaGFycyh2YWx1ZSk6
CiAgICAgICAgaWYgbm90IHN0YXRlWyJ1c2VybmFtZV9kZXB0aCJdIG9yIHN0YXRlWyJ0b29fbG9u
ZyJdOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBzdGF0ZVsiY2hhcnMiXS5hcHBlbmQodmFs
dWUpCiAgICAgICAgaWYgc3VtKFtsZW4ocGFydCkgZm9yIHBhcnQgaW4gc3RhdGVbImNoYXJzIl1d
KSA+IE1BWF9XU1NFX1VTRVJOQU1FICsgMjoKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0gPSBb
XQogICAgICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IFRydWUKCiAgICBkZWYgZW5kKG5hbWUp
OgogICAgICAgIGRlcHRoID0gbGVuKHN0YXRlWyJzdGFjayJdKQogICAgICAgIGlmIHN0YXRlWyJ1
c2VybmFtZV9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAgICBpZiBub3Qgc3RhdGVbInRvb19s
b25nIl0gYW5kIHN0YXRlWyJyZXN1bHQiXSBpcyBOb25lOgogICAgICAgICAgICAgICAgc3RhdGVb
InJlc3VsdCJdID0gbm9ybWFsaXplX3dzc2VfdXNlcm5hbWUoCiAgICAgICAgICAgICAgICAgICAg
dSIiLmpvaW4oc3RhdGVbImNoYXJzIl0pKQogICAgICAgICAgICBzdGF0ZVsidXNlcm5hbWVfZGVw
dGgiXSA9IDAKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAgICAgIGlmIHN0YXRl
WyJ0b2tlbl9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAgICBzdGF0ZVsidG9rZW5fZGVwdGgi
XSA9IDAKICAgICAgICBpZiBzdGF0ZVsic3RhY2siXToKICAgICAgICAgICAgc3RhdGVbInN0YWNr
Il0ucG9wKCkKCiAgICB0cnk6CiAgICAgICAgcGFyc2VyID0gZXhwYXQuUGFyc2VyQ3JlYXRlKE5v
bmUsICJ9IikKICAgICAgICBpZiBoYXNhdHRyKHBhcnNlciwgInJldHVybnNfdW5pY29kZSIpOgog
ICAgICAgICAgICBwYXJzZXIucmV0dXJuc191bmljb2RlID0gVHJ1ZQogICAgICAgIHBhcnNlci5T
dGFydEVsZW1lbnRIYW5kbGVyID0gc3RhcnQKICAgICAgICBwYXJzZXIuQ2hhcmFjdGVyRGF0YUhh
bmRsZXIgPSBjaGFycwogICAgICAgIHBhcnNlci5FbmRFbGVtZW50SGFuZGxlciA9IGVuZAogICAg
ICAgIGlmIChoYXNhdHRyKHBhcnNlciwgIlNldFBhcmFtRW50aXR5UGFyc2luZyIpIGFuZAogICAg
ICAgICAgICAgICAgaGFzYXR0cihleHBhdCwgIlhNTF9QQVJBTV9FTlRJVFlfUEFSU0lOR19ORVZF
UiIpKToKICAgICAgICAgICAgcGFyc2VyLlNldFBhcmFtRW50aXR5UGFyc2luZyhleHBhdC5YTUxf
UEFSQU1fRU5USVRZX1BBUlNJTkdfTkVWRVIpCiAgICAgICAgcGFyc2VyLlBhcnNlKGJ5dGVzKGJv
ZHkpLCBGYWxzZSkKICAgIGV4Y2VwdCAoZXhwYXQuRXhwYXRFcnJvciwgVmFsdWVFcnJvciwgVHlw
ZUVycm9yKToKICAgICAgICAjIEEgYm91bmRlZCBwcmVmaXggaXMgY29tbW9ubHkgaW5jb21wbGV0
ZS4gQSB1c2VybmFtZSBmdWxseSBjbG9zZWQKICAgICAgICAjIGJlZm9yZSB0aGUgdHJ1bmNhdGlv
biBwb2ludCBpcyBzdGlsbCBzYWZlIHRvIHVzZS4KICAgICAgICBwYXNzCiAgICByZXR1cm4gc3Rh
dGVbInJlc3VsdCJdCgoKZGVmIGlzX3NvYXBfY29udGVudF90eXBlKHZhbHVlKToKICAgIGlmIG5v
dCB2YWx1ZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIG1lZGlhX3R5cGUgPSB2YWx1ZS5zcGxp
dCgiOyIsIDEpWzBdLnN0cmlwKCkubG93ZXIoKQogICAgcmV0dXJuIChtZWRpYV90eXBlIGluICgi
dGV4dC94bWwiLCAiYXBwbGljYXRpb24veG1sIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ImFwcGxpY2F0aW9uL3NvYXAreG1sIikgb3IKICAgICAgICAgICAgbWVkaWFfdHlwZS5lbmRzd2l0
aCgiK3htbCIpKQoKCmRlZiBmaW5pc2hfZXZlbnQoZmxvdywga2V5LCBkc3RfaXAsIGRwb3J0LCBz
cmNfaXAsIHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KToKICAgIGggPSBmbG93LmhkcnMKICAgIHVz
ZXIgPSBzY2hlbWUgPSBOb25lCiAgICBhdXRoeiA9IGguZ2V0KCJhdXRob3JpemF0aW9uIikKICAg
IGlmIGF1dGh6OgogICAgICAgIHVzZXIsIHNjaGVtZSA9IGJhc2ljX3VzZXIoYXV0aHopCiAgICAj
IFczQyB0cmFjZSBjb250ZXh0OiBob25vciBpbmNvbWluZyB0cmFjZXBhcmVudCwgZWxzZSBnZW5l
cmF0ZSBvbmUgc28KICAgICMgZXZlcnkgdHJhbnNhY3Rpb24gY2FycmllcyBhIHRyYWNlX2lkIGZv
ciBodWItc2lkZSBjb3JyZWxhdGlvbi4KICAgICMgTk9URSBweTIuNjogYnl0ZXMgaGFzIG5vIC5o
ZXgoKSDigJQgdXNlIGJpbmFzY2lpLmhleGxpZnkuCiAgICB0cCA9IGguZ2V0KCJ0cmFjZXBhcmVu
dCIpCiAgICB0cmFjZV9pZCA9IE5vbmUKICAgIGlmIHRwOgogICAgICAgIHBhcnRzID0gdHAuc3Bs
aXQoIi0iKQogICAgICAgIGlmIGxlbihwYXJ0cykgPT0gNCBhbmQgbGVuKHBhcnRzWzFdKSA9PSAz
MjoKICAgICAgICAgICAgdHJhY2VfaWQgPSBwYXJ0c1sxXS5sb3dlcigpCiAgICBpZiBub3QgdHJh
Y2VfaWQ6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBybmQgPSBiaW5hc2NpaS5oZXhsaWZ5KG9z
LnVyYW5kb20oMTYpKQogICAgICAgICAgICBybmQgPSBybmQuZGVjb2RlKCJhc2NpaSIpIGlmIGhh
c2F0dHIocm5kLCAiZGVjb2RlIikgZWxzZSBybmQKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgog
ICAgICAgICAgICBybmQgPSAoIiUwMzJ4IiAlIChpbnQodGltZS50aW1lKCkgKiAxMDAwKSkpWy0z
MjpdCiAgICAgICAgcGlkOCA9IGJpbmFzY2lpLmhleGxpZnkob3MudXJhbmRvbSg4KSkKICAgICAg
ICBwaWQ4ID0gcGlkOC5kZWNvZGUoImFzY2lpIikgaWYgaGFzYXR0cihwaWQ4LCAiZGVjb2RlIikg
ZWxzZSBwaWQ4CiAgICAgICAgdHAgPSAiMDAtJXMtJXMtMDEiICUgKHJuZCwgcGlkOCkKICAgICAg
ICB0cmFjZV9pZCA9IHJuZAogICAgZXYgPSB7CiAgICAgICAgInRzIjogaW50KHRpbWUudGltZSgp
KSwKICAgICAgICAiaG9zdCI6IG5vZGVfaG9zdCwKICAgICAgICAic3JjIjogInBjYXAiLAogICAg
ICAgICJzZXJ2aWNlIjogInBvcnQ6JWQiICUgZHBvcnQsCiAgICAgICAgIm1ldGhvZCI6IGguZ2V0
KCJfbWV0aG9kIikgb3IgIi0iLAogICAgICAgICJwYXRoIjogKGguZ2V0KCJfcGF0aCIpIG9yICIt
Iikuc3BsaXQoIj8iLCAxKVswXVs6MTIwXSwKICAgICAgICAidXNlciI6IHVzZXIsCiAgICAgICAg
InNjaGVtZSI6IHNjaGVtZSwKICAgICAgICAiYmFzaWNfdXNlciI6IHVzZXIgaWYgc2NoZW1lID09
ICJiYXNpYyIgYW5kIHVzZXIgZWxzZSBOb25lLAogICAgICAgICJ3c3NlX3VzZXIiOiBOb25lLAog
ICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJzb3VyY2VfcHJvYmUiOiAicGNhcC1odHRwIiwK
ICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIpLAogICAgICAgICJ1c2VyX2FnZW50Ijog
aC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAieF9mb3J3YXJkZWRfZm9yIjogaC5nZXQoIngt
Zm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIiOiBzcmNfaXAsCiAgICAgICAgImNhbGxl
cl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6IGRzdF9pcCwKICAgICAgICAiZHN0X3Bv
cnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRvcmluZyBzY2hlbWEgKG9wcyBBUEktbG9n
IGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgYXJl
IHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1vbmx5CiAgICAgICAgIyBjYXB0dXJlIGNh
bm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUgaHViIHRvIGVucmljaCBvciBsZWF2ZS4K
ICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAogICAgICAgICJ0cmFjZV9pZCI6IHRyYWNl
X2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwgICAgICAgICAgIyBodWIgbWFwcyBwb3J0
LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAgICAibW9kdWxlX2lkIjogInBjYXAtaHR0
cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNlIGNvcnJlbGF0aW9uIG9ubHkgZm9yIG1v
bml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyByZXNwb25zZS1zaWRlIGZpbHRlciBtYXkg
c3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNwb3J0IGVxdWFsIHRvIGEKICAgICMgbW9u
aXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVjYXVzZSBwYXJzZV9yZXNwb25zZV9oZWFk
IHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRwb3J0IGluIHBvcnRzIG9yIGguZ2V0KCJf
bWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBt
ZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiRGlzY2FyZCBjYXB0dXJlIGJ1ZmZl
cnMsIHRoZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRpemVkIGV2ZW50IG9ubHkuIiIiCiAgICBkc3Rf
aXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAgZXYgPSBmbC53c3NlX2V2ZW50IGlm
IGZsLmF3YWl0aW5nX3dzc2UgZWxzZSBmbC5ldmVudAogICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZh
bHNlCiAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgaWYgbm90IGV2OgogICAgICAgIHJldHVy
bgogICAgZXZbInJlcV9ieXRlcyJdID0gZmwuaGVhZF9ieXRlcwogICAgaWYgcGVuZGluZ190Ymwg
aXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgIHJldHVybgogICAgcmsgPSAo
ZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgIGlmIHJrIGluIGNvcnJfZGlzYWJsZWQ6
CiAgICAgICAgb3V0LmFwcGVuZChldikKICAgICAgICByZXR1cm4KICAgIGVudCA9IHBlbmRpbmdf
dGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgIGlmIGxlbihwZW5kaW5nX3Ri
bCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5k
aW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3JrXSA9IFtdCiAgICBlbGlm
IGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAgICAgICAgd2hpbGUgcGVuZGluZ190Ymwu
Z2V0KHJrKToKICAgICAgICAgICAgcGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCiAg
ICAgICAgY29ycl9kaXNhYmxlZC5hZGQocmspCiAgICAgICAgb3V0LmFwcGVuZChldikKICAgICAg
ICByZXR1cm4KICAgIHN0YXJ0ZWQgPSBmbC5maXJzdF9ieXRlX3RzIGlmIGZsLmZpcnN0X2J5dGVf
dHMgPiAwIGVsc2UgKG5vdyBpZiBub3cgaXMgbm90IE5vbmUgZWxzZSB0aW1lLnRpbWUoKSkKICAg
IGVudC5hcHBlbmQoW2V2LCBzdGFydGVkXSkKCgpkZWYgX2VtaXRfcmVxdWVzdF90b19wZW5kaW5n
KGV2LCBoZWFkX2J5dGVzLCBmaXJzdF9ieXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBu
b3csIGdlbmVyYXRpb249MCk6CiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0
YQogICAgaWYgbm90IGV2OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gaGVh
ZF9ieXRlcwogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2
KQogICAgICAgIHJldHVybgogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkK
ICAgIGlmIHJrIGluIGNvcnJfZGlzYWJsZWQ6CiAgICAgICAgb3V0LmFwcGVuZChldikKICAgICAg
ICByZXR1cm4KICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25l
OgogICAgICAgIGlmIGxlbihwZW5kaW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAg
IF9mbHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBl
bmRpbmdfdGJsW3JrXSA9IFtdCiAgICBlbGlmIGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6
CiAgICAgICAgd2hpbGUgcGVuZGluZ190YmwuZ2V0KHJrKToKICAgICAgICAgICAgcGVuZGluZ19w
b3AocmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgY29ycl9kaXNhYmxlZC5hZGQocmspCiAg
ICAgICAgb3V0LmFwcGVuZChldikKICAgICAgICByZXR1cm4KICAgIHN0YXJ0ZWQgPSBmaXJzdF9i
eXRlX3RzIGlmIGZpcnN0X2J5dGVfdHMgPiAwIGVsc2UgKG5vdyBpZiBub3cgaXMgbm90IE5vbmUg
ZWxzZSB0aW1lLnRpbWUoKSkKICAgIGVudC5hcHBlbmQoW2V2LCBzdGFydGVkLCBGYWxzZSwgMC4w
LCBnZW5lcmF0aW9uXSkKCgoKZGVmIF90cnlfd3NzZV9ib2R5KGZsb3dzLCBrZXksIGZsLCBwYXls
b2FkLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiQXBwZW5kIG5vIG1vcmUg
dGhhbiBib2R5X2dvYWwgYnl0ZXMgYW5kIGZpbmlzaCBhcyBzb29uIGFzIHBvc3NpYmxlLiIiIgog
ICAgcmVtYWluaW5nID0gZmwud3NzZV9nb2FsIC0gbGVuKGZsLndzc2VfYnVmKQogICAgaWYgcmVt
YWluaW5nID4gMCBhbmQgcGF5bG9hZDoKICAgICAgICBjb3B5X2xlbiA9IG1pbihyZW1haW5pbmcs
IGxlbihwYXlsb2FkKSkKICAgICAgICBmbC53c3NlX2J1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxv
YWRbOmNvcHlfbGVuXSkpCiAgICB1c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC53
c3NlX2J1ZikKICAgIGlmIHVzZXJuYW1lOgogICAgICAgIGZsLndzc2VfZXZlbnRbIndzc2VfdXNl
ciJdID0gdXNlcm5hbWUKICAgICAgICBmbC53c3NlX2V2ZW50WyJ1c2VyIl0gPSB1c2VybmFtZQog
ICAgICAgIGZsLndzc2VfZXZlbnRbInNjaGVtZSJdID0gIndzc2UiCiAgICBpZiB1c2VybmFtZSBv
ciBsZW4oZmwud3NzZV9idWYpID49IGZsLndzc2VfZ29hbDoKICAgICAgICBfZW1pdF9yZXF1ZXN0
X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0ZV90
cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YSwgb3V0LCBwZW5kaW5nX3Ri
bCwgbm93LCBnZW5lcmF0aW9uPWZsLmdlbmVyYXRpb24pCiAgICAgICAgZmwuYXdhaXRpbmdfd3Nz
ZSA9IEZhbHNlCiAgICAgICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBoYW5k
bGVfcGF5bG9hZChmbG93cywga2V5LCByZXZfa2V5LCBwYXlsb2FkLCBtZXRhLCBwb3J0cywgbm9k
ZV9ob3N0LCBvdXQsCiAgICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibD1Ob25lLCBub3c9Tm9u
ZSwgd3NzZV9ib2R5X2J5dGVzPTAsCiAgICAgICAgICAgICAgICAgICBzZXE9Tm9uZSwgZmxhZ3M9
MCwgaXNfdHJ1bmNhdGVkPUZhbHNlLCByZXNwX2Zsb3dzPU5vbmUpOgogICAgZHN0X2lwLCBkcG9y
dCwgc3JjX2lwLCBzcG9ydCA9IG1ldGEKICAgIGlmIG5vdCB2YWxpZF9wb3J0KGRwb3J0KSBvciBu
b3QgdmFsaWRfcG9ydChzcG9ydCk6CiAgICAgICAgcmV0dXJuCiAgICBpZiBub3cgaXMgTm9uZToK
ICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQoKICAgICMgU1lOIGhhbmRsaW5nOiByZXNldCBmbG93
IGFuZCBzdGFydCBzZXF1ZW5jZSB0cmFja2luZwogICAgaWYgZmxhZ3MgJiAweDAyIGFuZCBzZXEg
aXMgbm90IE5vbmU6CiAgICAgICAgZmwgPSBmbG93cy5nZXQoa2V5KQogICAgICAgIGlmIGZsIGlz
IG5vdCBOb25lIGFuZCBmbC5hd2FpdGluZ193c3NlIGFuZCBmbC53c3NlX2V2ZW50OgogICAgICAg
ICAgICBvdXQuYXBwZW5kKGZsLndzc2VfZXZlbnQpCiAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dz
c2UgPSBGYWxzZQogICAgICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpCiAg
ICAgICAgY29ycl9kaXNhYmxlZC5kaXNjYXJkKHJrKQogICAgICAgIGlmIHBlbmRpbmdfdGJsIGlz
IG5vdCBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAg
ICAgICAgICAgIGlmIGVudDoKICAgICAgICAgICAgICAgIGZvciBpdGVtIGluIGVudDoKICAgICAg
ICAgICAgICAgICAgICBpc190b21iID0gaXRlbVsyXSBpZiBsZW4oaXRlbSkgPiAyIGVsc2UgRmFs
c2UKICAgICAgICAgICAgICAgICAgICBpZiBub3QgaXNfdG9tYjoKICAgICAgICAgICAgICAgICAg
ICAgICAgb3V0LmFwcGVuZChpdGVtWzBdKQoKICAgICAgICBpZiByZXNwX2Zsb3dzIGlzIG5vdCBO
b25lIGFuZCByayBpbiByZXNwX2Zsb3dzOgogICAgICAgICAgICByZXNwX2Zsb3dzLnBvcChyaywg
Tm9uZSkKICAgICAgICBpZiByZXZfa2V5IGlzIG5vdCBOb25lIGFuZCByZXZfa2V5IGluIGZsb3dz
OgogICAgICAgICAgICBmbG93cy5wb3AocmV2X2tleSwgTm9uZSkKCiAgICAgICAgb2xkX2dlbiA9
IGZsLmdlbmVyYXRpb24gaWYgZmwgaXMgbm90IE5vbmUgZWxzZSAwCiAgICAgICAgZmwgPSBGbG93
KCkKICAgICAgICBmbC5nZW5lcmF0aW9uID0gb2xkX2dlbiArIDEKICAgICAgICBmbC5oYXNfc2Vx
ID0gVHJ1ZQogICAgICAgIGZsLm5leHRfc2VxID0gKHNlcSArIDEpICYgMHhGRkZGRkZGRgogICAg
ICAgIGZsLnRvdWNoZWQgPSBub3cKICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gMC4wCiAgICAg
ICAgZmxvd3Nba2V5XSA9IGZsCiAgICAgICAgcmV0dXJuCgogICAgZmwgPSBmbG93cy5nZXQoa2V5
KQogICAgaWYgZmwgaXMgTm9uZToKICAgICAgICBmbCA9IEZsb3coKQogICAgICAgIGZsb3dzW2tl
eV0gPSBmbAogICAgICAgIGlmIGxlbihmbG93cykgPiBNQVhfRkxPV1M6CiAgICAgICAgICAgIGVu
Zm9yY2VfbGltaXQoZmxvd3MsIG5vdykKICAgIGZsLnRvdWNoZWQgPSBub3cKCiAgICAjIENoZWNr
IGtlZXAtYWxpdmUgcmVxdWVzdCB0cmFuc2l0aW9uIHdoaWxlIHdhaXRpbmcgZm9yIGJvZHkgaW4g
ZGlyZWN0IHRlc3QgZmVlZCBtb2RlCiAgICBpZiBzZXEgaXMgTm9uZSBhbmQgZmwuYXdhaXRpbmdf
d3NzZSBhbmQgcGF5bG9hZCBhbmQgaXNfbWV0aG9kX29yX3ByZWZpeChwYXlsb2FkKToKICAgICAg
ICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywg
ZmwuZmlyc3RfYnl0ZV90cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YSwg
b3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQog
ICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICBmbC5idWYgPSBieXRl
YXJyYXkoKQoKICAgIHBsZW4gPSBsZW4ocGF5bG9hZCkgaWYgcGF5bG9hZCBlbHNlIDAKICAgIGlm
IHBsZW4gPiAwOgogICAgICAgIGlmIHNlcSBpcyBOb25lOgogICAgICAgICAgICBmbC5idWYuZXh0
ZW5kKHBheWxvYWQpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgaWYgbm90IGZsLmhhc19zZXE6
CiAgICAgICAgICAgICAgICBpZiBpc19tZXRob2Rfb3JfcHJlZml4KHBheWxvYWQpOgogICAgICAg
ICAgICAgICAgICAgIGZsLmhhc19zZXEgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgZmwubmV4
dF9zZXEgPSBzZXEKICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBGYWxzZQogICAg
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBpZiBsZW4oZmwub29vKSA8IE1B
WF9PT09fU0VHTUVOVFMgYW5kIG5vdCBpc190cnVuY2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAg
ICAgIGlmIG5vdCBhbnkocyA9PSBzZXEgZm9yIHMsIF8gaW4gZmwub29vKToKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGZsLm9vby5hcHBlbmQoKHNlcSwgYnl0ZXMocGF5bG9hZCkpKQogICAg
ICAgICAgICAgICAgICAgIHJldHVybgoKICAgICAgICAgICAgZGlmZiA9IHNlcV9kaWZmKHNlcSwg
ZmwubmV4dF9zZXEpCiAgICAgICAgICAgIGlmIGRpZmYgPT0gMDoKICAgICAgICAgICAgICAgIGlm
IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAg
ICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIGZsLmJ1Zi5leHRlbmQocGF5
bG9hZCkKICAgICAgICAgICAgICAgICAgICBmbC5uZXh0X3NlcSA9IChmbC5uZXh0X3NlcSArIHBs
ZW4pICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgIF9kcmFpbl9vb28oZmwpCiAgICAg
ICAgICAgIGVsaWYgZGlmZiA8IDA6CiAgICAgICAgICAgICAgICBvdmVybGFwID0gLWRpZmYKICAg
ICAgICAgICAgICAgIGlmIG92ZXJsYXAgPCBwbGVuIGFuZCBub3QgaXNfdHJ1bmNhdGVkOgogICAg
ICAgICAgICAgICAgICAgIGZsLmJ1Zi5leHRlbmQocGF5bG9hZFtvdmVybGFwOl0pCiAgICAgICAg
ICAgICAgICAgICAgZmwubmV4dF9zZXEgPSAoZmwubmV4dF9zZXEgKyBwbGVuIC0gb3ZlcmxhcCkg
JiAweEZGRkZGRkZGCiAgICAgICAgICAgICAgICAgICAgX2RyYWluX29vbyhmbCkKICAgICAgICAg
ICAgZWxzZToKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5vb28pIDwgTUFYX09PT19TRUdNRU5U
UyBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICBpZiBub3QgYW55KHMg
PT0gc2VxIGZvciBzLCBfIGluIGZsLm9vbyk6CiAgICAgICAgICAgICAgICAgICAgICAgIGZsLm9v
by5hcHBlbmQoKHNlcSwgYnl0ZXMocGF5bG9hZCkpKQogICAgICAgICAgICAgICAgZWxzZToKICAg
ICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCgogICAgIyBIVFRQIGZyYW1pbmcg
c3RhdGUgbWFjaGluZQogICAgd2hpbGUgbGVuKGZsLmJ1ZikgPiAwIGFuZCBub3QgZmwuaXNfYnJv
a2VuOgogICAgICAgIGlmIGZsLnN0YXRlID09IEhUVFBfU1RBVEVfSEVBREVSOgogICAgICAgICAg
ICBpZiBub3QgZmwuZmlyc3RfYnl0ZV90czoKICAgICAgICAgICAgICAgIGZsLmZpcnN0X2J5dGVf
dHMgPSBub3cKCiAgICAgICAgICAgIGlkeCA9IGZsLmJ1Zi5maW5kKGIiXHJcblxyXG4iKQogICAg
ICAgICAgICBpZiBpZHggPCAwOgogICAgICAgICAgICAgICAgaWYgbGVuKGZsLmJ1ZikgPiBNQVhf
SERSUzoKICAgICAgICAgICAgICAgICAgICBmbC5idWYgPSBieXRlYXJyYXkoKQogICAgICAgICAg
ICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAg
ICAgICAgIHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0KGZsLmJ1ZikKICAgICAgICAgICAgaWYgc3Rh
cnQgPCAwIG9yIHN0YXJ0ID4gaWR4OgogICAgICAgICAgICAgICAgZGVsIGZsLmJ1Zls6aWR4ICsg
NF0KICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGlmIHN0YXJ0ID4gMDoKICAg
ICAgICAgICAgICAgIGRlbCBmbC5idWZbOnN0YXJ0XQogICAgICAgICAgICAgICAgaWR4IC09IHN0
YXJ0CgogICAgICAgICAgICBoZWFkID0gYnl0ZXMoZmwuYnVmWzppZHhdKQogICAgICAgICAgICBs
aW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQoYiJcbiIpCiAgICAgICAg
ICAgIGZpcnN0ID0gbGluZXNbMF0uc3RyaXAoKS5zcGxpdCgpCiAgICAgICAgICAgIGlmIGxlbihm
aXJzdCkgPCAyIG9yIGZpcnN0WzBdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpIG5vdCBpbiBN
RVRIT0RTOgogICAgICAgICAgICAgICAgZGVsIGZsLmJ1Zls6aWR4ICsgNF0KICAgICAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGhkcnMgPSB7fQogICAgICAgICAgICBoZHJzWyJfbWV0
aG9kIl0gPSBmaXJzdFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgICAgICAgICBo
ZHJzWyJfcGF0aCJdID0gZmlyc3RbMV0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAg
ICAgICAgaGFzX2NvbmZsaWN0X2NsID0gRmFsc2UKICAgICAgICAgICAgZmlyc3RfY2wgPSBOb25l
CiAgICAgICAgICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAgICAgICAgICAgICAgICBpZiBiIjoi
IG5vdCBpbiBsbjoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAg
a24sIGt2ID0gbG4uc3BsaXQoYiI6IiwgMSkKICAgICAgICAgICAgICAgIGtfbm9ybSA9IGtuLnN0
cmlwKCkubG93ZXIoKS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2UiKQogICAgICAgICAgICAgICAg
dl9ub3JtID0ga3Yuc3RyaXAoKS5kZWNvZGUoInV0Zi04IiwgInJlcGxhY2UiKVs6MTgwXQogICAg
ICAgICAgICAgICAgaWYga19ub3JtID09ICJjb250ZW50LWxlbmd0aCI6CiAgICAgICAgICAgICAg
ICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWRfY2wgPSBpbnQodl9ub3Jt
KQogICAgICAgICAgICAgICAgICAgICAgICBpZiBwYXJzZWRfY2wgPCAwOgogICAgICAgICAgICAg
ICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAgICAgICAgICAgICAg
ICAgICBlbGlmIGZpcnN0X2NsIGlzIE5vbmU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBm
aXJzdF9jbCA9IHBhcnNlZF9jbAogICAgICAgICAgICAgICAgICAgICAgICBlbGlmIGZpcnN0X2Ns
ICE9IHBhcnNlZF9jbDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9j
bCA9IFRydWUKICAgICAgICAgICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAg
ICAgICAgICAgICAgICAgaGFzX2NvbmZsaWN0X2NsID0gVHJ1ZQogICAgICAgICAgICAgICAgaGRy
c1trX25vcm1dID0gdl9ub3JtCiAgICAgICAgICAgIGZsLmhkcnMgPSBoZHJzCiAgICAgICAgICAg
IGZsLmV2ZW50ID0gZmluaXNoX2V2ZW50KGZsLCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwg
c3BvcnQsIHBvcnRzLCBub2RlX2hvc3QpCiAgICAgICAgICAgIGZsLmhlYWRfYnl0ZXMgPSBpZHgg
KyA0CiAgICAgICAgICAgIGRlbCBmbC5idWZbOmlkeCArIDRdCgogICAgICAgICAgICBpZiBub3Qg
ZmwuZXZlbnQ6CiAgICAgICAgICAgICAgICBjb250aW51ZQoKICAgICAgICAgICAgdHJ5OgogICAg
ICAgICAgICAgICAgY29udGVudF9sZW5ndGggPSBpbnQoaGRycy5nZXQoImNvbnRlbnQtbGVuZ3Ro
IiwgIjAiKSkKICAgICAgICAgICAgZXhjZXB0IChWYWx1ZUVycm9yLCBUeXBlRXJyb3IpOgogICAg
ICAgICAgICAgICAgY29udGVudF9sZW5ndGggPSAwCiAgICAgICAgICAgIHRlID0gaGRycy5nZXQo
InRyYW5zZmVyLWVuY29kaW5nIiwgIiIpLmxvd2VyKCkKICAgICAgICAgICAgaXNfY2h1bmtlZCA9
ICJjaHVua2VkIiBpbiB0ZQoKICAgICAgICAgICAgaWYgaGFzX2NvbmZsaWN0X2NsIG9yIChjb250
ZW50X2xlbmd0aCA+IDAgYW5kIGlzX2NodW5rZWQpIG9yICgiY29udGVudC1sZW5ndGgiIGluIGhk
cnMgYW5kIGlzX2NodW5rZWQpOgogICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkK
ICAgICAgICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgIGJyZWFr
CgogICAgICAgICAgICBhY3RpdmVfYm9keV9mbG93cyA9IHN1bSgxIGZvciBjYW5kIGluIGZsb3dz
LnZhbHVlcygpIGlmIGNhbmQuYXdhaXRpbmdfd3NzZSBvciAoY2FuZC5ldmVudCBpcyBub3QgTm9u
ZSBhbmQgZ2V0YXR0cihjYW5kLCAiYm9keV9nb2FsIiwgMCkgPiAwKSkKICAgICAgICAgICAgd3Nz
ZV9lbGlnaWJsZSA9ICh3c3NlX2JvZHlfYnl0ZXMgPiAwIGFuZAogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIGlzX3NvYXBfY29udGVudF90eXBlKGhkcnMuZ2V0KCJjb250ZW50LXR5cGUiKSkg
YW5kCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGVudF9sZW5ndGggPiAwIGFuZAog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5vdCBpc19jaHVua2VkIGFuZAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgIGFjdGl2ZV9ib2R5X2Zsb3dzIDwgTUFYX1dTU0VfQk9EWV9GTE9X
UykKCiAgICAgICAgICAgIGlmIHdzc2VfZWxpZ2libGU6CiAgICAgICAgICAgICAgICBmbC5hd2Fp
dGluZ193c3NlID0gVHJ1ZQogICAgICAgICAgICAgICAgZmwud3NzZV9ldmVudCA9IGZsLmV2ZW50
CiAgICAgICAgICAgICAgICBmbC53c3NlX2J1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAg
ICBmbC53c3NlX2dvYWwgPSBtaW4oY29udGVudF9sZW5ndGgsIHdzc2VfYm9keV9ieXRlcywgTUFY
X1dTU0VfQk9EWV9CWVRFUykKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIF9lbWl0
X3JlcXVlc3RfdG9fcGVuZGluZyhmbC5ldmVudCwgZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0
ZV90cywgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93LCBnZW5lcmF0aW9uPWZsLmdlbmVyYXRp
b24pCiAgICAgICAgICAgIGZsLmV2ZW50ID0gTm9uZQoKICAgICAgICAgICAgaWYgY29udGVudF9s
ZW5ndGggPiAwOgogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0JPRFkKICAg
ICAgICAgICAgICAgIGZsLmJvZHlfcmVtYWluaW5nID0gY29udGVudF9sZW5ndGgKICAgICAgICAg
ICAgZWxpZiBpc19jaHVua2VkOgogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRF
X0NIVU5LCiAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xlbiA9IFRydWUKICAgICAg
ICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IEZhbHNlCiAgICAgICAgICAgICAgICBm
bC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQogICAgICAgICAgICAgICAgZmwuY2h1bmtf
cGF5bG9hZF9yZW1haW5pbmcgPSAwCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBm
bC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRl
X3RzID0gbm93IGlmIGZsLmJ1ZiBlbHNlIDAuMAogICAgICAgICAgICBjb250aW51ZQoKICAgICAg
ICBlbGlmIGZsLnN0YXRlID09IEhUVFBfU1RBVEVfQk9EWToKICAgICAgICAgICAgaWYgbm90IGZs
LmJ1ZjoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4o
bGVuKGZsLmJ1ZiksIGZsLmJvZHlfcmVtYWluaW5nKQogICAgICAgICAgICBpZiBmbC5hd2FpdGlu
Z193c3NlOgogICAgICAgICAgICAgICAgd3NzZV9uZWVkID0gZmwud3NzZV9nb2FsIC0gbGVuKGZs
Lndzc2VfYnVmKQogICAgICAgICAgICAgICAgaWYgd3NzZV9uZWVkID4gMDoKICAgICAgICAgICAg
ICAgICAgICBjb3B5X2xlbiA9IG1pbih0b19jb25zdW1lLCB3c3NlX25lZWQpCiAgICAgICAgICAg
ICAgICAgICAgZmwud3NzZV9idWYuZXh0ZW5kKGZsLmJ1Zls6Y29weV9sZW5dKQogICAgICAgICAg
ICAgICAgdXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwud3NzZV9idWYpCiAgICAg
ICAgICAgICAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwud3NzZV9idWYpID49IGZsLndzc2VfZ29h
bDoKICAgICAgICAgICAgICAgICAgICBldiA9IGZsLndzc2VfZXZlbnQKICAgICAgICAgICAgICAg
ICAgICBpZiB1c2VybmFtZToKICAgICAgICAgICAgICAgICAgICAgICAgZXZbIndzc2VfdXNlciJd
ID0gdXNlcm5hbWUKICAgICAgICAgICAgICAgICAgICAgICAgZXZbInVzZXIiXSA9IHVzZXJuYW1l
CiAgICAgICAgICAgICAgICAgICAgICAgIGV2WyJzY2hlbWUiXSA9ICJ3c3NlIgogICAgICAgICAg
ICAgICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGluZyhldiwgZmwuaGVhZF9ieXRlcywgZmwu
Zmlyc3RfYnl0ZV90cywgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93LCBnZW5lcmF0aW9uPWZs
LmdlbmVyYXRpb24pCiAgICAgICAgICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNl
CgogICAgICAgICAgICBkZWwgZmwuYnVmWzp0b19jb25zdW1lXQogICAgICAgICAgICBmbC5ib2R5
X3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAgIGlmIGZsLmJvZHlfcmVtYWluaW5n
ID09IDA6CiAgICAgICAgICAgICAgICBpZiBmbC5hd2FpdGluZ193c3NlOgogICAgICAgICAgICAg
ICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGluZyhmbC53c3NlX2V2ZW50LCBmbC5oZWFkX2J5
dGVzLCBmbC5maXJzdF9ieXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3csIGdlbmVy
YXRpb249ZmwuZ2VuZXJhdGlvbikKICAgICAgICAgICAgICAgICAgICBmbC5hd2FpdGluZ193c3Nl
ID0gRmFsc2UKICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAg
ICAgICAgICAgICAgIGZsLmZpcnN0X2J5dGVfdHMgPSBub3cgaWYgZmwuYnVmIGVsc2UgMC4wCiAg
ICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIGVsaWYgZmwuc3RhdGUgPT0gSFRUUF9TVEFURV9D
SFVOSzoKICAgICAgICAgICAgaWYgbm90IGZsLmJ1ZjoKICAgICAgICAgICAgICAgIGJyZWFrCiAg
ICAgICAgICAgIGlmIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlcjoKICAgICAgICAgICAgICAgIGlm
IGxlbihmbC5idWYpID49IDIgYW5kIGZsLmJ1Zls6Ml0gPT0gYiJcclxuIjoKICAgICAgICAgICAg
ICAgICAgICBkZWwgZmwuYnVmWzoyXQogICAgICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRp
bmdfdHJhaWxlciA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NU
QVRFX0hFQURFUgogICAgICAgICAgICAgICAgICAgIGZsLmZpcnN0X2J5dGVfdHMgPSBub3cgaWYg
ZmwuYnVmIGVsc2UgMC4wCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAg
ICAgIHRyX2VuZCA9IGZsLmJ1Zi5maW5kKGIiXHJcblxyXG4iKQogICAgICAgICAgICAgICAgaWYg
dHJfZW5kICE9IC0xOgogICAgICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOnRyX2VuZCArIDRd
CiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAg
ICAgICAgICAgICAgICAgICBmbC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAg
ICAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IG5vdyBpZiBmbC5idWYgZWxzZSAwLjAKICAgICAg
ICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgaWYgbGVuKGZsLmJ1ZikgPiBN
QVhfSERSUzoKICAgICAgICAgICAgICAgICAgICBmbC5idWYgPSBieXRlYXJyYXkoKQogICAgICAg
ICAgICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgIGJyZWFrCiAg
ICAgICAgICAgIGlmIGZsLmNodW5rX3JlYWRpbmdfbGVuOgogICAgICAgICAgICAgICAgY3JsZiA9
IGZsLmJ1Zi5maW5kKGIiXHJcbiIpCiAgICAgICAgICAgICAgICBpZiBjcmxmIDwgMDoKICAgICAg
ICAgICAgICAgICAgICBpZiBsZW4oZmwuYnVmKSA+IDY0OgogICAgICAgICAgICAgICAgICAgICAg
ICBmbC5idWYgPSBieXRlYXJyYXkoKQogICAgICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9r
ZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGxpbmUg
PSBieXRlcyhmbC5idWZbOmNybGZdKS5zdHJpcCgpCiAgICAgICAgICAgICAgICBzZW1pID0gbGlu
ZS5maW5kKGIiOyIpCiAgICAgICAgICAgICAgICBoZXhfc3RyID0gbGluZVs6c2VtaV0uc3RyaXAo
KSBpZiBzZW1pICE9IC0xIGVsc2UgbGluZQogICAgICAgICAgICAgICAgaWYgbGVuKGhleF9zdHIp
ID4gMTY6CiAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAg
ICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgYnJlYWsK
ICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBjaHVua19sZW4gPSBpbnQo
aGV4X3N0ciwgMTYpCiAgICAgICAgICAgICAgICAgICAgaWYgY2h1bmtfbGVuIDwgMCBvciBjaHVu
a19sZW4gPiAweDdGRkZGRkZGOgogICAgICAgICAgICAgICAgICAgICAgICBmbC5idWYgPSBieXRl
YXJyYXkoKQogICAgICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAg
ICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJv
cjoKICAgICAgICAgICAgICAgICAgICBmbC5idWYgPSBieXRlYXJyYXkoKQogICAgICAgICAgICAg
ICAgICAgIGZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgICAgICBicmVhawogICAg
ICAgICAgICAgICAgZGVsIGZsLmJ1Zls6Y3JsZiArIDJdCiAgICAgICAgICAgICAgICBpZiBjaHVu
a19sZW4gPT0gMDoKICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIg
PSBUcnVlCiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBGYWxzZQog
ICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAg
ICAgICAgICAgICAgIGZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gY2h1bmtfbGVuCiAgICAg
ICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBGYWxzZQogICAgICAgICAgICAg
ICAgICAgIGZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IEZhbHNlCiAgICAgICAgICAgIGVsaWYgZmwu
Y2h1bmtfcmVhZGluZ19jcmxmOgogICAgICAgICAgICAgICAgaWYgbGVuKGZsLmJ1ZikgPCAyOgog
ICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBpZiBmbC5idWZbOjJdICE9
IGIiXHJcbiI6CiAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAg
ICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgYnJl
YWsKICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOjJdCiAgICAgICAgICAgICAgICBmbC5jaHVu
a19yZWFkaW5nX2NybGYgPSBGYWxzZQogICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19s
ZW4gPSBUcnVlCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICB0b19jb25zdW1lID0g
bWluKGxlbihmbC5idWYpLCBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZykKICAgICAgICAgICAg
ICAgIGRlbCBmbC5idWZbOnRvX2NvbnN1bWVdCiAgICAgICAgICAgICAgICBmbC5jaHVua19wYXls
b2FkX3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAgICAgICBpZiBmbC5jaHVua19w
YXlsb2FkX3JlbWFpbmluZyA9PSAwOgogICAgICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRp
bmdfY3JsZiA9IFRydWUKICAgICAgICAgICAgY29udGludWUKCiAgICBpZiBmbGFncyAmIDB4MDU6
CiAgICAgICAgaWYgZmwuYXdhaXRpbmdfd3NzZSBhbmQgZmwud3NzZV9ldmVudDoKICAgICAgICAg
ICAgX2VtaXRfcmVxdWVzdF90b19wZW5kaW5nKGZsLndzc2VfZXZlbnQsIGZsLmhlYWRfYnl0ZXMs
IGZsLmZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICAg
ICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkK
ICAgIGVsaWYgc2VxIGlzIE5vbmUgYW5kIGZsLnN0YXRlID09IEhUVFBfU1RBVEVfSEVBREVSIGFu
ZCBub3QgZmwuYnVmIGFuZCBub3QgZmwub29vIGFuZCBub3QgZmwuYXdhaXRpbmdfd3NzZToKICAg
ICAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQoKCmRlZiBzd2VlcF9pZGxlKGZsb3dzLCBub3csIG91
dD1Ob25lLCBwZW5kaW5nX3RibD1Ob25lLCByZXNwX2Zsb3dzPU5vbmUpOgogICAgc3RhbGUgPSBb
XQogICAgZm9yIGssIGZsIGluIGZsb3dzLml0ZW1zKCk6CiAgICAgICAgaWYgbm93IC0gZmwudG91
Y2hlZCA+IEZMT1dfVFRMOgogICAgICAgICAgICBzdGFsZS5hcHBlbmQoaykKICAgIGZvciBrIGlu
IHN0YWxlOgogICAgICAgIGZsID0gZmxvd3MuZ2V0KGspCiAgICAgICAgaWYgZmwgaXMgbm90IE5v
bmUgYW5kIGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQgaXMgbm90IE5vbmU6CiAg
ICAgICAgICAgIGlmIG91dCBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgIG91dC5hcHBlbmQo
Zmwud3NzZV9ldmVudCkKICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICAg
ICAgZmxvd3MucG9wKGssIE5vbmUpCiAgICBpZiByZXNwX2Zsb3dzIGlzIG5vdCBOb25lOgogICAg
ICAgIHJzdGFsZSA9IFtrIGZvciBrLCByZmwgaW4gcmVzcF9mbG93cy5pdGVtcygpIGlmIG5vdyAt
IHJmbC50b3VjaGVkID4gRkxPV19UVExdCiAgICAgICAgZm9yIGsgaW4gcnN0YWxlOgogICAgICAg
ICAgICByZXNwX2Zsb3dzLnBvcChrLCBOb25lKQoKCmRlZiBkcmFpbl9pbmNvbXBsZXRlX3dzc2Uo
Zmxvd3MsIG91dCwgcGVuZGluZ190YmwsIG5vdz1Ob25lKToKICAgICIiIkZhbGwgYmFjayB0byBl
bWl0dGluZyB0aGUgcmVxdWVzdCBldmVudCBpZiBXU1NFIGluc3BlY3Rpb24gd2FzIGluY29tcGxl
dGUuIiIiCiAgICBpZiBub3cgaXMgTm9uZToKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAg
Zm9yIGtleSBpbiBsaXN0KGZsb3dzLmtleXMoKSk6CiAgICAgICAgZmwgPSBmbG93cy5nZXQoa2V5
KQogICAgICAgIGlmIGZsIGlzIE5vbmU6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYg
ZmwuYXdhaXRpbmdfd3NzZSBhbmQgZmwud3NzZV9ldmVudCBpcyBub3QgTm9uZToKICAgICAgICAg
ICAgb3V0LmFwcGVuZChmbC53c3NlX2V2ZW50KQogICAgICAgICAgICBmbC5hd2FpdGluZ193c3Nl
ID0gRmFsc2UKICAgICAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQoKCmRlZiBwcm9jZXNzX3BhY2tl
dChwa3QsIHBvcnRzLCBub2RlX2hvc3QsIGZsb3dzLCByZXNwX2Zsb3dzLCBwZW5kaW5nX3RibCwg
b3V0LCBub3c9Tm9uZSwgd3NzZV9ib2R5X2J5dGVzPTApOgogICAgbiA9IGxlbihwa3QpCiAgICBp
ZiBuIDwgMzQ6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBpZiBub3cgaXMgTm9uZToKICAgICAg
ICBub3cgPSB0aW1lLnRpbWUoKQogICAgb2ZmID0gMTQKICAgIGV0eXBlID0gc3RydWN0LnVucGFj
aygiIUgiLCBwa3RbMTI6MTRdKVswXQogICAgaWYgZXR5cGUgPT0gRVRIX1BfVkxBTjoKICAgICAg
ICBpZiBuIDwgMzg6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGV0eXBlID0gc3Ry
dWN0LnVucGFjaygiIUgiLCBwa3RbMTY6MThdKVswXQogICAgICAgIG9mZiA9IDE4CiAgICBlbGlm
IGV0eXBlICE9IEVUSF9QX0lQOgogICAgICAgIHJldHVybiBGYWxzZQoKICAgIGlwMCA9IGIyaShw
a3Rbb2ZmXSkKICAgIGlmIChpcDAgPj4gNCkgIT0gNCBvciBiMmkocGt0W29mZiArIDldKSAhPSA2
OgogICAgICAgIHJldHVybiBGYWxzZQogICAgaWhsID0gKGlwMCAmIDB4MEYpICogNAogICAgaWYg
aWhsIDwgMjAgb3IgbiA8IG9mZiArIGlobCArIDIwOgogICAgICAgIHJldHVybiBGYWxzZQoKICAg
IGZyYWcgPSBzdHJ1Y3QudW5wYWNrKCIhSCIsIHBrdFtvZmYgKyA2Om9mZiArIDhdKVswXQogICAg
aWYgZnJhZyAmIDB4MUZGRjoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBpcF90b3RhbF9sZW4g
PSBzdHJ1Y3QudW5wYWNrKCIhSCIsIHBrdFtvZmYgKyAyOm9mZiArIDRdKVswXQogICAgaXNfdHJ1
bmNhdGVkID0gRmFsc2UKICAgIGlmIGlwX3RvdGFsX2xlbiA+IDA6CiAgICAgICAgaWYgaXBfdG90
YWxfbGVuIDwgaWhsICsgMjA6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGlmIG4g
LSBvZmYgPCBpcF90b3RhbF9sZW46CiAgICAgICAgICAgIGlzX3RydW5jYXRlZCA9IFRydWUKICAg
ICAgICBlbGlmIG4gLSBvZmYgPiBpcF90b3RhbF9sZW46CiAgICAgICAgICAgIG4gPSBvZmYgKyBp
cF90b3RhbF9sZW4KCiAgICBzcmNfaXAgPSBzb2NrZXQuaW5ldF9udG9hKHBrdFtvZmYgKyAxMjpv
ZmYgKyAxNl0pCiAgICBkc3RfaXAgPSBzb2NrZXQuaW5ldF9udG9hKHBrdFtvZmYgKyAxNjpvZmYg
KyAyMF0pCiAgICB0Y3Bfb2ZmID0gb2ZmICsgaWhsCiAgICBzcG9ydCwgZHBvcnQgPSBzdHJ1Y3Qu
dW5wYWNrKCIhSEgiLCBwa3RbdGNwX29mZjp0Y3Bfb2ZmICsgNF0pCiAgICBzZXEgPSBzdHJ1Y3Qu
dW5wYWNrKCIhSSIsIHBrdFt0Y3Bfb2ZmICsgNDp0Y3Bfb2ZmICsgOF0pWzBdCiAgICBkb2ZmX2J5
dGUgPSBiMmkocGt0W3RjcF9vZmYgKyAxMl0pCiAgICBkb2ZmID0gKGRvZmZfYnl0ZSA+PiA0KSAq
IDQKICAgIGlmIGRvZmYgPCAyMCBvciBuIDwgdGNwX29mZiArIGRvZmY6CiAgICAgICAgcmV0dXJu
IEZhbHNlCgogICAgZmxhZ3MgPSBiMmkocGt0W3RjcF9vZmYgKyAxM10pCiAgICBwYXlfc3RhcnQg
PSB0Y3Bfb2ZmICsgZG9mZgogICAgcGF5bG9hZCA9IHBrdFtwYXlfc3RhcnQ6bl0gaWYgbiA+IHBh
eV9zdGFydCBlbHNlIGIiIgoKICAgICMgUmVzcG9uc2UgZGlyZWN0aW9uOiBTZXJ2ZXIgLT4gQ2xp
ZW50CiAgICBpZiBzcG9ydCBpbiBwb3J0cyBhbmQgZHBvcnQgbm90IGluIHBvcnRzOgogICAgICAg
IHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgaGFuZGxlX3Jlc3Bv
bnNlKHJlc3BfZmxvd3MsIHJrLCBwYXlsb2FkLCBub3csIG91dCwgcGVuZGluZ190YmwsCiAgICAg
ICAgICAgICAgICAgICAgICAgIHNlcT1zZXEsIGZsYWdzPWZsYWdzLCBpc190cnVuY2F0ZWQ9aXNf
dHJ1bmNhdGVkKQogICAgICAgIHJldHVybiBUcnVlCgogICAgIyBSZXF1ZXN0IGRpcmVjdGlvbjog
Q2xpZW50IC0+IFNlcnZlcgogICAgZWxpZiBkcG9ydCBpbiBwb3J0czoKICAgICAgICBrZXkgPSAo
c3JjX2lwLCBzcG9ydCwgZHN0X2lwLCBkcG9ydCkKICAgICAgICBtZXRhID0gKGRzdF9pcCwgZHBv
cnQsIHNyY19pcCwgc3BvcnQpCiAgICAgICAgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgTm9u
ZSwgcGF5bG9hZCwgbWV0YSwgcG9ydHMsIG5vZGVfaG9zdCwgb3V0LAogICAgICAgICAgICAgICAg
ICAgICAgIHBlbmRpbmdfdGJsLCBub3csIHdzc2VfYm9keV9ieXRlcywKICAgICAgICAgICAgICAg
ICAgICAgICBzZXE9c2VxLCBmbGFncz1mbGFncywgaXNfdHJ1bmNhdGVkPWlzX3RydW5jYXRlZCwK
ICAgICAgICAgICAgICAgICAgICAgICByZXNwX2Zsb3dzPXJlc3BfZmxvd3MpCgogICAgICAgIHJl
dHVybiBUcnVlCgogICAgcmV0dXJuIEZhbHNlCgoKZGVmIF9mbHVzaF9vbGRlc3RfcGVuZGluZyhw
ZW5kaW5nX3RibCwgb3V0KToKICAgICIiIk92ZXJmbG93IGd1YXJkOiBlbWl0IGFsbCBldmVudHMg
Zm9yIHRoZSBvbGRlc3QgcGVuZGluZyBrZXkgYW5kIGxvY2sgaXQgb3V0LiIiIgogICAgb2xkZXN0
X2tleSwgb2xkZXN0X3RzID0gTm9uZSwgTm9uZQogICAgZm9yIHJrLCBsc3QgaW4gcGVuZGluZ190
YmwuaXRlbXMoKToKICAgICAgICBpZiBub3QgbHN0OgogICAgICAgICAgICBjb250aW51ZQogICAg
ICAgIHRzID0gbHN0WzBdWzFdCiAgICAgICAgaWYgb2xkZXN0X3RzIGlzIE5vbmUgb3IgdHMgPCBv
bGRlc3RfdHM6CiAgICAgICAgICAgIG9sZGVzdF9rZXksIG9sZGVzdF90cyA9IHJrLCB0cwogICAg
aWYgb2xkZXN0X2tleSBpcyBub3QgTm9uZToKICAgICAgICB3aGlsZSBwZW5kaW5nX3RibC5nZXQo
b2xkZXN0X2tleSk6CiAgICAgICAgICAgIHBlbmRpbmdfcG9wKG9sZGVzdF9rZXksIG91dCwgcGVu
ZGluZ190YmwpCiAgICAgICAgY29ycl9kaXNhYmxlZC5hZGQob2xkZXN0X2tleSkKICAgICAgICBw
ZW5kaW5nX3RibC5wb3Aob2xkZXN0X2tleSwgTm9uZSkKCgpkZWYgc3dlZXBfcGVuZGluZyhwZW5k
aW5nX3RibCwgbm93LCBvdXQpOgogICAgIiIiVFRMIGZsdXNoOiBlbWl0IHJlcXVlc3RzIHdob3Nl
IHJlc3BvbnNlcyBuZXZlciBzaG93ZWQgdXAuIiIiCiAgICBmb3IgcmsgaW4gbGlzdChwZW5kaW5n
X3RibC5rZXlzKCkpOgogICAgICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgICAgICBp
ZiBub3QgbHN0OgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGkgPSAwCiAgICAgICAgd2hp
bGUgaSA8IGxlbihsc3QpOgogICAgICAgICAgICBpdGVtID0gbHN0W2ldCiAgICAgICAgICAgIGlz
X3RvbWIgPSBpdGVtWzJdIGlmIGxlbihpdGVtKSA+IDIgZWxzZSBGYWxzZQogICAgICAgICAgICB0
b21iX3RzID0gaXRlbVszXSBpZiBsZW4oaXRlbSkgPiAzIGVsc2UgMC4wCiAgICAgICAgICAgIGlm
IGlzX3RvbWI6CiAgICAgICAgICAgICAgICBpZiBub3cgLSB0b21iX3RzID4gMTAuMDoKICAgICAg
ICAgICAgICAgICAgICAjIFRvbWJzdG9uZSBleHBpcmVkIHVuLWNvbnN1bWVkOiBvcmRlcmluZyBp
cyBub3cgYW1iaWd1b3VzLgogICAgICAgICAgICAgICAgICAgICMgRmx1c2ggYWxsIHJlbWFpbmlu
ZyBlbnRyaWVzIGltbWVkaWF0ZWx5IGFuZCBwZXJzaXN0ZW50bHkKICAgICAgICAgICAgICAgICAg
ICAjIGRpc2FibGUgcmVzcG9uc2UgY29ycmVsYXRpb24gZm9yIHRoaXMgY29ubmVjdGlvbiB1bnRp
bCBTWU4uCiAgICAgICAgICAgICAgICAgICAgbHN0LnBvcChpKQogICAgICAgICAgICAgICAgICAg
IHdoaWxlIGkgPCBsZW4obHN0KToKICAgICAgICAgICAgICAgICAgICAgICAgdGFpbCA9IGxzdFtp
XQogICAgICAgICAgICAgICAgICAgICAgICB0YWlsX3RvbWIgPSB0YWlsWzJdIGlmIGxlbih0YWls
KSA+IDIgZWxzZSBGYWxzZQogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3QgdGFpbF90b21i
OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3V0LmFwcGVuZCh0YWlsWzBdKQogICAgICAg
ICAgICAgICAgICAgICAgICBsc3QucG9wKGkpCiAgICAgICAgICAgICAgICAgICAgY29ycl9kaXNh
YmxlZC5hZGQocmspCiAgICAgICAgICAgICAgICAgICAgIyBMZWF2ZSBpIHVuY2hhbmdlZDsgdGhl
IHdoaWxlIGNvbmRpdGlvbiB3aWxsIGV4aXQgbmF0dXJhbGx5CiAgICAgICAgICAgICAgICBlbHNl
OgogICAgICAgICAgICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICBlbGlmIG5vdyAtIGl0ZW1b
MV0gPiBQRU5ESU5HX1RUTDoKICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoaXRlbVswXSkKICAg
ICAgICAgICAgICAgIGlmIGxlbihpdGVtKSA+IDM6CiAgICAgICAgICAgICAgICAgICAgaXRlbVsy
XSA9IFRydWUKICAgICAgICAgICAgICAgICAgICBpdGVtWzNdID0gbm93CiAgICAgICAgICAgICAg
ICBlbHNlOgogICAgICAgICAgICAgICAgICAgIGl0ZW0uZXh0ZW5kKFtUcnVlLCBub3csIDBdKQog
ICAgICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBp
ICs9IDEKICAgICAgICBpZiBub3QgbHN0OgogICAgICAgICAgICBwZW5kaW5nX3RibC5wb3Aocmss
IE5vbmUpCgoKCmRlZiBkcmFpbl9wZW5kaW5nKHBlbmRpbmdfdGJsLCBvdXQpOgogICAgIiIiRW1p
dCBldmVyeSBjYXB0dXJlZCByZXF1ZXN0IGJlZm9yZSBjYXB0dXJlIHNodXRkb3duLgoKICAgIFJl
c3BvbnNlcyBhcmUgb3B0aW9uYWwgZW5yaWNobWVudC4gQSBzdG9wL3Jlc3RhcnQgbXVzdCBub3Qg
ZGlzY2FyZCBhCiAgICByZXF1ZXN0IG1lcmVseSBiZWNhdXNlIGl0cyByZXNwb25zZSB3YXMgZmls
dGVyZWQsIHNwbGl0LCBvciBzdGlsbCBpbgogICAgZmxpZ2h0IHdoZW4gdGhlIHByb2Nlc3MgcmVj
ZWl2ZWQgU0lHVEVSTS4KICAgICIiIgogICAgZm9yIHJrIGluIGxpc3QocGVuZGluZ190Ymwua2V5
cygpKToKICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAgaWYg
bHN0OgogICAgICAgICAgICBmb3IgaXRlbSBpbiBsc3Q6CiAgICAgICAgICAgICAgICBpc190b21i
ID0gaXRlbVsyXSBpZiBsZW4oaXRlbSkgPiAyIGVsc2UgRmFsc2UKICAgICAgICAgICAgICAgIGlm
IG5vdCBpc190b21iOgogICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoaXRlbVswXSkKICAg
IGNvcnJfZGlzYWJsZWQuY2xlYXIoKQoKCgpkZWYgbWFpbnRlbmFuY2VfZHVlKG5vdywgbGFzdF9z
d2VlcCk6CiAgICByZXR1cm4gbm93IC0gbGFzdF9zd2VlcCA+PSBTV0VFUF9JTlRFUlZBTAoKCmRl
ZiBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFibGUgc2l6ZSAo
cHkyLjY6IG5vIE9yZGVyZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZPCiAgICBieSBp
bnNlcnRpb24gb3JkZXIsIHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQeXRob24pLiIi
IgogICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dzKSA+IE1BWF9G
TE9XUzoKICAgICAgICBmbG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3QtaW5zZXJ0ZWQg
a2V5IG9uIENQeXRob24gMi42LzIuNwoKCmRlZiBfY29udHJvbF9jb25maWcoKToKICAgICIiIlJl
YWQgb3B0aW9uYWwgY29udHJvbCBzZXR0aW5ncyB3aXRob3V0IGV4cG9zaW5nIHRoZSBiZWFyZXIg
dG9rZW4uIiIiCiAgICBlbmRwb2ludCA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX0VORFBP
SU5UIikgb3Igb3MuZW52aXJvbi5nZXQoIk5UX0VORFBPSU5UIikKICAgIHRva2VuX2ZpbGUgPSBv
cy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTl9GSUxFIiwgIiIpCiAgICB0b2tlbiA9IG9z
LmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOIiwgIiIpCiAgICBpZiB0b2tlbl9maWxlOgog
ICAgICAgIHRyeToKICAgICAgICAgICAgZiA9IG9wZW4odG9rZW5fZmlsZSwgInIiKQogICAgICAg
ICAgICB0cnk6CiAgICAgICAgICAgICAgICB0b2tlbiA9IGYucmVhZCgpLnN0cmlwKCkKICAgICAg
ICAgICAgZmluYWxseToKICAgICAgICAgICAgICAgIGYuY2xvc2UoKQogICAgICAgIGV4Y2VwdCBJ
T0Vycm9yOgogICAgICAgICAgICB0b2tlbiA9ICIiCiAgICBub2RlID0gb3MuZW52aXJvbi5nZXQo
Ik5UX05PREVfTkFNRSIpIG9yIHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KICAg
IHJ1bl9kaXIgPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9SVU4iLCAiL3Zhci9saWIvbmV0
d29ya3RyYWNpbmciKQogICAgdHJ5OgogICAgICAgIGludGVydmFsID0gbWF4KDUsIG1pbihpbnQo
b3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfU0VDIiwgIjMwIikpLCAzMDApKQogICAgZXhjZXB0
IFZhbHVlRXJyb3I6CiAgICAgICAgaW50ZXJ2YWwgPSAzMAogICAgcmV0dXJuIGVuZHBvaW50LCB0
b2tlbiwgbm9kZSwgcnVuX2RpciwgaW50ZXJ2YWwKCgpkZWYgX3J1bl9jb250cm9sX3RpY2socG9y
dHMsIGlmYWNlLCBydW5fZGlyLCBjbGllbnQpOgogICAgcmVwbHkgPSBjbGllbnQucG9sbCgpCiAg
ICBpZiBub3QgcmVwbHk6CiAgICAgICAgcmV0dXJuIHBvcnRzLCBpZmFjZSwgTm9uZSwgInBvbGwg
ZmFpbGVkIgogICAgZGVzaXJlZCA9IHJlcGx5LmdldCgiZGVzaXJlZCIpIG9yIHt9CiAgICBzdGF0
ZSA9IGRpY3QoZGVzaXJlZCkKICAgIGdlbmVyYXRpb24gPSBkZXNpcmVkLmdldCgiZ2VuZXJhdGlv
biIsIDApCiAgICBjb250cm9sX2FjdGlvbiA9IE5vbmUKICAgIHN0b3BfcmVxdWVzdGVkID0gRmFs
c2UKICAgIGlmIGRlc2lyZWQuZ2V0KCJwb3J0cyIpOgogICAgICAgIG5ld19wb3J0cyA9IHNldChk
ZXNpcmVkWyJwb3J0cyJdKQogICAgICAgIGlmIG5ld19wb3J0cyAhPSBwb3J0czoKICAgICAgICAg
ICAgcG9ydHMgPSBuZXdfcG9ydHMKICAgICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAicmVzdGFy
dCIKICAgIGlmIGRlc2lyZWQuZ2V0KCJpZmFjZSIpOgogICAgICAgIG5ld19pZmFjZSA9IGRlc2ly
ZWRbImlmYWNlIl0KICAgICAgICBpZiBuZXdfaWZhY2UgIT0gaWZhY2U6CiAgICAgICAgICAgIGlm
YWNlID0gbmV3X2lmYWNlCiAgICAgICAgICAgIGNvbnRyb2xfYWN0aW9uID0gInJlc3RhcnQiCiAg
ICBmb3IgdGFzayBpbiByZXBseS5nZXQoInRhc2tzIiwgW10pOgogICAgICAgIGFjdGlvbiA9IHRh
c2suZ2V0KCJhY3Rpb24iKQogICAgICAgIGlmIGFjdGlvbiA9PSAiaGVhbHRoIjoKICAgICAgICAg
ICAgbWVzc2FnZSA9ICJoZWFsdGh5IgogICAgICAgICAgICBzdGF0dXMgPSAiZG9uZSIKICAgICAg
ICBlbGlmIGFjdGlvbiBpbiAoInJlc3RhcnQiLCAicmVsb2FkIiwgInNldF9wb3J0cyIpOgogICAg
ICAgICAgICBtZXNzYWdlID0gImFjY2VwdGVkOyBjYXB0dXJlIHJlc3RhcnQgcmVxdWVzdGVkIgog
ICAgICAgICAgICBzdGF0dXMgPSAiZG9uZSIKICAgICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAi
cmVzdGFydCIKICAgICAgICAgICAgaWYgYWN0aW9uID09ICJzZXRfcG9ydHMiOgogICAgICAgICAg
ICAgICAgYXJncyA9IHRhc2suZ2V0KCJhcmdzIikgb3Ige30KICAgICAgICAgICAgICAgIGlmIGFy
Z3MuZ2V0KCJwb3J0cyIpOgogICAgICAgICAgICAgICAgICAgIHBvcnRzID0gc2V0KGFyZ3NbInBv
cnRzIl0pCiAgICAgICAgICAgICAgICAgICAgc3RhdGUudXBkYXRlKHsicG9ydHMiOiBzb3J0ZWQo
cG9ydHMpLCAibW9kZSI6ICJweXRob24iLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgImdlbmVyYXRpb24iOiBnZW5lcmF0aW9ufSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAic3Rv
cCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAic3RvcCByZXF1ZXN0ZWQiCiAgICAgICAgICAgIHN0
YXR1cyA9ICJkb25lIgogICAgICAgICAgICBzdG9wX3JlcXVlc3RlZCA9IFRydWUKICAgICAgICBl
bHNlOgogICAgICAgICAgICBtZXNzYWdlID0gInVuc3VwcG9ydGVkIGJ5IGRpcmVjdCBzbmlmZmVy
IgogICAgICAgICAgICBzdGF0dXMgPSAiZmFpbGVkIgogICAgICAgIGNsaWVudC5yZXBvcnQodGFz
ay5nZXQoImlkIiksIHN0YXR1cywgbWVzc2FnZSkKICAgIGlmIHN0b3BfcmVxdWVzdGVkOgogICAg
ICAgIGNvbnRyb2xfYWN0aW9uID0gInN0b3AiCiAgICBhcHBsaWVkID0gKCJzdG9wIHJlcXVlc3Rl
ZCIgaWYgY29udHJvbF9hY3Rpb24gPT0gInN0b3AiIGVsc2UKICAgICAgICAgICAgICAgInJlc3Rh
cnQgcmVxdWlyZWQiIGlmIGNvbnRyb2xfYWN0aW9uID09ICJyZXN0YXJ0IiBlbHNlCiAgICAgICAg
ICAgICAgICJwb2xsIG9rIikKICAgIG50X2NvbnRyb2wud3JpdGVfc3RhdGUob3MucGF0aC5qb2lu
KHJ1bl9kaXIsICJyZW1vdGUtZGVzaXJlZC5qc29uIiksCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgIHN0YXRlLCBhcHBsaWVkKQogICAgY2xpZW50LmhlYXJ0YmVhdChnZW5lcmF0aW9uLCBhcHBs
aWVkKQogICAgcmV0dXJuIHBvcnRzLCBpZmFjZSwgY29udHJvbF9hY3Rpb24sIGFwcGxpZWQKCgpk
ZWYgX3Jlc3RhcnRfYXJncyhzY3JpcHQsIGlmYWNlLCBwb3J0cywgdmVyYm9zZSwgd29ya2Vycywg
d3NzZV9ib2R5X2J5dGVzPTApOgogICAgIiIiQnVpbGQgYSBmcmVzaCBhcmd2IGZvciBhbiBpbi1w
bGFjZSByZS1leGVjIGFmdGVyIGEgY29udHJvbCB1cGRhdGUuIiIiCiAgICAjIFByZXNlcnZlIHVu
YnVmZmVyZWQgSlNPTkwgZGVsaXZlcnk7IHRoZSBpbnN0YWxsZXIgc3RhcnRzIFB5dGhvbiB3aXRo
IC11LgogICAgYXJncyA9IFtzeXMuZXhlY3V0YWJsZSwgIi11Iiwgb3MucGF0aC5hYnNwYXRoKHNj
cmlwdCldCiAgICBpZiBpZmFjZToKICAgICAgICBhcmdzLmV4dGVuZChbIi1pIiwgaWZhY2VdKQog
ICAgYXJncy5leHRlbmQoWyItcCIsICIsIi5qb2luKFtzdHIocCkgZm9yIHAgaW4gc29ydGVkKHBv
cnRzKV0pXSkKICAgIGFyZ3MuZXh0ZW5kKFsiLWoiLCAiMSJdKQogICAgaWYgd3NzZV9ib2R5X2J5
dGVzOgogICAgICAgIGFyZ3MuZXh0ZW5kKFsiLS13c3NlLWJvZHktYnl0ZXMiLCBzdHIod3NzZV9i
b2R5X2J5dGVzKV0pCiAgICBpZiB2ZXJib3NlOgogICAgICAgIGFyZ3MuYXBwZW5kKCItdiIpCiAg
ICByZXR1cm4gYXJncwoKCmRlZiBtYWluKCk6CiAgICBpZmFjZSwgcG9ydHMsIHZlcmJvc2UsIHdv
cmtlcnMsIHdzc2VfYm9keV9ieXRlcyA9IHBhcnNlX2FyZ3Moc3lzLmFyZ3ZbMTpdKQogICAgbm9k
ZV9ob3N0ID0gc29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4iKVswXQogICAgY29udHJvbF9j
bGllbnQgPSBOb25lCiAgICBlbmRwb2ludCwgdG9rZW4sIGNvbnRyb2xfbm9kZSwgY29udHJvbF9y
dW4sIGNvbnRyb2xfaW50ZXJ2YWwgPSBfY29udHJvbF9jb25maWcoKQogICAgaWYgbnRfY29udHJv
bCBpcyBub3QgTm9uZSBhbmQgZW5kcG9pbnQgYW5kIHRva2VuOgogICAgICAgIHRyeToKICAgICAg
ICAgICAgY29udHJvbF9jbGllbnQgPSBudF9jb250cm9sLkNvbnRyb2xDbGllbnQoZW5kcG9pbnQs
IHRva2VuLCBjb250cm9sX25vZGUpCiAgICAgICAgICAgIGlmIG5vdCBvcy5wYXRoLmlzZGlyKGNv
bnRyb2xfcnVuKToKICAgICAgICAgICAgICAgIG9zLm1ha2VkaXJzKGNvbnRyb2xfcnVuKQogICAg
ICAgICAgICBsb2coInJlbW90ZSBjb250cm9sIGVuYWJsZWQiKQogICAgICAgIGV4Y2VwdCBFeGNl
cHRpb24gYXMgZToKICAgICAgICAgICAgbG9nKCJXQVJOOiByZW1vdGUgY29udHJvbCBkaXNhYmxl
ZCAoJXMpIiAlIG50X2NvbnRyb2wuc2FmZV9tZXNzYWdlKGUpKQoKICAgIHRyeToKICAgICAgICAj
IHByb3RvY29sIE1VU1QgYmUgaHRvbnMoRVRIX1BfQUxMKSB0byByZWNlaXZlIGJvdGggSU5HUkVT
UyAocmVxKSBhbmQKICAgICAgICAjIEVHUkVTUyAocmVzcCkgcGFja2V0cyBvbiBMaW51eCBrZXJu
ZWwgcGFja2V0IHNvY2tldHMuCiAgICAgICAgcyA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX1BB
Q0tFVCwgc29ja2V0LlNPQ0tfUkFXLAogICAgICAgICAgICAgICAgICAgICAgICAgIHNvY2tldC5o
dG9ucyhFVEhfUF9BTEwpKQogICAgZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgogICAgICAgIHJhaXNl
IFN5c3RlbUV4aXQoIkFGX1BBQ0tFVCB1bmF2YWlsYWJsZSBvbiB0aGlzIHBsYXRmb3JtIikKICAg
IGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5u
b3Qgb3BlbiBBRl9QQUNLRVQgc29ja2V0ICglcykg4oCUIG5lZWQgIgogICAgICAgICAgICAgICAg
ICAgICAgICAgIkNBUF9ORVRfUkFXIC8gcm9vdCIgJSBlKQogICAgcy5zZXR0aW1lb3V0KDEuMCkK
ICAgIGlmIG5vdCBhcHBseV9wZXJmX29wdHMocywgcG9ydHMpOgogICAgICAgIHMuY2xvc2UoKQog
ICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImtlcm5lbCBCUEYgc2FmZXR5IGZpbHRlciB1bmF2YWls
YWJsZTsgcmVmdXNpbmcgdW5maWx0ZXJlZCBjYXB0dXJlIikKICAgIHRyeToKICAgICAgICBzLmJp
bmQoKGlmYWNlIG9yICIiLCBFVEhfUF9BTEwpKQogICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBl
OgogICAgICAgIHMuY2xvc2UoKQogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBiaW5k
IEFGX1BBQ0tFVCB0byAlcyAoJXMpIiAlCiAgICAgICAgICAgICAgICAgICAgICAgICAoaWZhY2Ug
b3IgIjxhbGw+IiwgZSkpCiAgICBpZiBub3QgZHJvcF9jYXB0dXJlX2NhcGFiaWxpdGllcygpOgog
ICAgICAgIHMuY2xvc2UoKQogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImNhbm5vdCBkcm9wIENB
UF9ORVRfUkFXIGFmdGVyIHNvY2tldCBzZXR1cDsgcmVmdXNpbmcgdW5zYWZlIGNhcHR1cmUiKQoK
ICAgICMgcHJlY29tcGlsZWQgc3RydWN0IHJlYWRlcnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0
cmFpZ2h0IG91dCBvZiB0aGUKICAgICMgcGFja2V0IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBh
bmQgeWllbGRzIGludHMgdW5kZXIgcHkyIEFORCBweTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3Qo
IiFIIikudW5wYWNrX2Zyb20KICAgIHVoID0gc3RydWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zy
b20gICAjIHNwb3J0LGRwb3J0IGluIG9uZSByZWFkCiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFC
QiIpLnVucGFja19mcm9tCiAgICBudG9hID0gc29ja2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0g
e30KICAgIHJlc3BfZmxvd3MgPSB7fQogICAgcnVubmluZyA9IFtUcnVlXQogICAgc3RhdHNfaW50
ZXJ2YWwgPSBzdGF0c19pbnRlcnZhbF9zZWNvbmRzKCkKICAgIHN0YXRzX3N0YXRlID0geyJwYWNr
ZXRzX3RvdGFsIjogMCwgInBhY2tldF9ieXRlc190b3RhbCI6IDAsCiAgICAgICAgICAgICAgICAg
ICAiZXZlbnRzX2VtaXR0ZWRfdG90YWwiOiAwLCAia2VybmVsX2Ryb3BzX3RvdGFsIjogMCwKICAg
ICAgICAgICAgICAgICAgICJsYXN0X3BhY2tldHMiOiAwLCAibGFzdF9wYWNrZXRfYnl0ZXMiOiAw
LAogICAgICAgICAgICAgICAgICAgImxhc3RfZXZlbnRzIjogMCwgImxhc3RfYXQiOiB0aW1lLnRp
bWUoKX0KCiAgICBkZWYgd3JpdGVfZXZlbnRzKGl0ZW1zKToKICAgICAgICBpZiBub3QgaXRlbXM6
CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHcgPSBzeXMuc3Rkb3V0LndyaXRlCiAgICAgICAg
Zm9yIGl0ZW0gaW4gaXRlbXM6CiAgICAgICAgICAgIHcoanNvbi5kdW1wcyhpdGVtKSArICJcbiIp
CiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAgc3RhdHNfc3RhdGVbImV2ZW50c19l
bWl0dGVkX3RvdGFsIl0gKz0gbGVuKGl0ZW1zKQoKICAgIGRlZiBlbWl0X2NhcHR1cmVfc3RhdHMo
Zm9yY2U9RmFsc2UpOgogICAgICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAgZWxhcHNlZCA9
IG5vdyAtIHN0YXRzX3N0YXRlWyJsYXN0X2F0Il0KICAgICAgICBpZiBub3QgZm9yY2UgYW5kIGVs
YXBzZWQgPCBzdGF0c19pbnRlcnZhbDoKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgZHJvcHBl
ZF9kZWx0YSA9IDAKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJhd19zdGF0cyA9IHMuZ2V0c29j
a29wdChTT0xfUEFDS0VULCBQQUNLRVRfU1RBVElTVElDUywgOCkKICAgICAgICAgICAgXywgZHJv
cHBlZF9kZWx0YSA9IHN0cnVjdC51bnBhY2soIklJIiwgcmF3X3N0YXRzWzo4XSkKICAgICAgICBl
eGNlcHQgKHNvY2tldC5lcnJvciwgc3RydWN0LmVycm9yKToKICAgICAgICAgICAgZHJvcHBlZF9k
ZWx0YSA9IDAKICAgICAgICBzdGF0c19zdGF0ZVsia2VybmVsX2Ryb3BzX3RvdGFsIl0gKz0gZHJv
cHBlZF9kZWx0YQogICAgICAgIHBhY2tldHNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbInBhY2tldHNf
dG90YWwiXSAtCiAgICAgICAgICAgICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9wYWNr
ZXRzIl0pCiAgICAgICAgYnl0ZXNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbInBhY2tldF9ieXRlc190
b3RhbCJdIC0KICAgICAgICAgICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9wYWNrZXRf
Ynl0ZXMiXSkKICAgICAgICBldmVudHNfZGVsdGEgPSAoc3RhdHNfc3RhdGVbImV2ZW50c19lbWl0
dGVkX3RvdGFsIl0gLQogICAgICAgICAgICAgICAgICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9l
dmVudHMiXSkKICAgICAgICB3YWl0aW5nX3dzc2UgPSAwCiAgICAgICAgZm9yIGZsb3cgaW4gZmxv
d3MudmFsdWVzKCk6CiAgICAgICAgICAgIGlmIGZsb3cuZXZlbnQgaXMgbm90IE5vbmUgYW5kIGZs
b3cuYm9keV9nb2FsOgogICAgICAgICAgICAgICAgd2FpdGluZ193c3NlICs9IDEKICAgICAgICBw
ZW5kaW5nX2NvdW50ID0gc3VtKGxlbihpdGVtcykgZm9yIGl0ZW1zIGluIHBlbmRpbmcudmFsdWVz
KCkpCiAgICAgICAgZHJvcF9wY3QgPSAxMDAuMCAqIGRyb3BwZWRfZGVsdGEgLyBtYXgoMSwgcGFj
a2V0c19kZWx0YSkKICAgICAgICBjYXB0dXJlID0gewogICAgICAgICAgICAicGFja2V0c190b3Rh
bCI6IHN0YXRzX3N0YXRlWyJwYWNrZXRzX3RvdGFsIl0sCiAgICAgICAgICAgICJwYWNrZXRzX2Rl
bHRhIjogcGFja2V0c19kZWx0YSwKICAgICAgICAgICAgInBhY2tldF9ieXRlc190b3RhbCI6IHN0
YXRzX3N0YXRlWyJwYWNrZXRfYnl0ZXNfdG90YWwiXSwKICAgICAgICAgICAgInBhY2tldF9ieXRl
c19kZWx0YSI6IGJ5dGVzX2RlbHRhLAogICAgICAgICAgICAia2VybmVsX2Ryb3BzX3RvdGFsIjog
c3RhdHNfc3RhdGVbImtlcm5lbF9kcm9wc190b3RhbCJdLAogICAgICAgICAgICAia2VybmVsX2Ry
b3BzX2RlbHRhIjogZHJvcHBlZF9kZWx0YSwKICAgICAgICAgICAgImtlcm5lbF9kcm9wX3BlcmNl
bnQiOiByb3VuZChkcm9wX3BjdCwgNCksCiAgICAgICAgICAgICJpbnZhbGlkX2ZyYW1lc190b3Rh
bCI6IDAsCiAgICAgICAgICAgICJldmVudHNfZW1pdHRlZF90b3RhbCI6IHN0YXRzX3N0YXRlWyJl
dmVudHNfZW1pdHRlZF90b3RhbCJdLAogICAgICAgICAgICAiZXZlbnRzX2VtaXR0ZWRfZGVsdGEi
OiBldmVudHNfZGVsdGEsCiAgICAgICAgICAgICJmbG93c19hY3RpdmUiOiBsZW4oZmxvd3MpLAog
ICAgICAgICAgICAicGVuZGluZ19yZXF1ZXN0cyI6IHBlbmRpbmdfY291bnQsCiAgICAgICAgICAg
ICJ3c3NlX2JvZHlfZmxvd3NfYWN0aXZlIjogd2FpdGluZ193c3NlfQogICAgICAgIHN5cy5zdGRv
dXQud3JpdGUoanNvbi5kdW1wcyh7Il9udF9pbnRlcm5hbCI6ICJjYXB0dXJlX3N0YXRzX3YxIiwK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjYXB0dXJlIjogY2FwdHVyZX0s
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlcGFyYXRvcnM9KCIsIiwgIjoi
KSkgKyAiXG4iKQogICAgICAgIHN5cy5zdGRvdXQuZmx1c2goKQogICAgICAgIHN0YXRzX3N0YXRl
WyJsYXN0X3BhY2tldHMiXSA9IHN0YXRzX3N0YXRlWyJwYWNrZXRzX3RvdGFsIl0KICAgICAgICBz
dGF0c19zdGF0ZVsibGFzdF9wYWNrZXRfYnl0ZXMiXSA9IHN0YXRzX3N0YXRlWyJwYWNrZXRfYnl0
ZXNfdG90YWwiXQogICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X2V2ZW50cyJdID0gc3RhdHNfc3Rh
dGVbImV2ZW50c19lbWl0dGVkX3RvdGFsIl0KICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9hdCJd
ID0gbm93CgogICAgZGVmIHN0b3Aoc2lnbnVtLCBmcmFtZSk6CiAgICAgICAgcnVubmluZ1swXSA9
IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLCBzdG9wKQogICAgc2lnbmFs
LnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9wKQoKICAgIGxhc3Rfc3dlZXAgPSB0aW1lLnRpbWUo
KQogICAgY29udHJvbF9uZXh0ID0gdGltZS50aW1lKCkKICAgIGxvZygibGlzdGVuaW5nIG9uICVz
IHBvcnRzPSVzIHBpZD0lZCIgJQogICAgICAgIChpZmFjZSBvciAiPGFsbD4iLCBzb3J0ZWQocG9y
dHMpLCBvcy5nZXRwaWQoKSkpCiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6CiAgICAgICAgbG9nKCJX
U1NFIFVzZXJuYW1lVG9rZW4gaW5zcGVjdGlvbiBlbmFibGVkIChib3VuZGVkIHRvICVkIGJ5dGVz
L3JlcXVlc3QpIiAlCiAgICAgICAgICAgIHdzc2VfYm9keV9ieXRlcykKCiAgICAjIDFzIHJlY3Yg
dGltZW91dDogKGEpIGxldHMgdGhlIHBlbmRpbmcvZmxvdyBzd2VlcHMgYWN0dWFsbHkgZmlyZSDi
gJQKICAgICMgd2l0aG91dCBpdCBgZXhjZXB0IHNvY2tldC50aW1lb3V0YCBuZXZlciBydW5zOyAo
YikgZW1waXJpY2FsbHkgUkVRVUlSRUQKICAgICMgd2l0aCB0aGUgQlBGIGZpbHRlciBhdHRhY2hl
ZDogYSBmdWxseS1ibG9ja2luZyByZWN2IG9uIHRoaXMga2VybmVsCiAgICAjIHN0YXJ2ZXMgYWZ0
ZXIgdGhlIGZpcnN0IHBhY2tldCwgd2hpbGUgdGhlIHRpbWVvdXQnZCByZWN2IGRlbGl2ZXJzCiAg
ICAjIGNvbnRpbnVvdXNseSAodmVyaWZpZWQgYnkgQS9COiByeD0xIHZzIHJ4PTI5IGlkZW50aWNh
bCBvdGhlcndpc2UpLgogICAgcy5zZXR0aW1lb3V0KDEuMCkKCiAgICBkYmcgPSBvcy5lbnZpcm9u
LmdldCgiTlRfU05JRkZfREVCVUciKSA9PSAiMSIKICAgIGRiZ19yeCA9IDAKICAgIGRiZ19sYXN0
ID0gdGltZS50aW1lKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF06CiAgICAgICAgZW1pdF9jYXB0dXJl
X3N0YXRzKCkKICAgICAgICAjIFBvbGwgaW5kZXBlbmRlbnRseSBvZiBzb2NrZXQgaWRsZSB0aW1l
LiBBIGJ1c3kgbW9uaXRvcmVkIGludGVyZmFjZQogICAgICAgICMgbWF5IG5ldmVyIHJhaXNlIHNv
Y2tldC50aW1lb3V0LCBidXQgY29udHJvbCBjaGFuZ2VzIG11c3Qgc3RpbGwgYXBwbHkuCiAgICAg
ICAgaWYgY29udHJvbF9jbGllbnQgaXMgbm90IE5vbmUgYW5kIHRpbWUudGltZSgpID49IGNvbnRy
b2xfbmV4dDoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBj
b250cm9sX2FjdGlvbiwgY29udHJvbF9zdGF0dXMgPSBfcnVuX2NvbnRyb2xfdGljaygKICAgICAg
ICAgICAgICAgICAgICBwb3J0cywgaWZhY2UsIGNvbnRyb2xfcnVuLCBjb250cm9sX2NsaWVudCkK
ICAgICAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2w6ICVzIiAlIGNvbnRyb2xfc3RhdHVz
KQogICAgICAgICAgICAgICAgaWYgY29udHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiOgogICAgICAg
ICAgICAgICAgICAgIGFyZ3MgPSBfcmVzdGFydF9hcmdzKHN5cy5hcmd2WzBdLCBpZmFjZSwgcG9y
dHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyYm9zZSwgd29y
a2Vycywgd3NzZV9ib2R5X2J5dGVzKQogICAgICAgICAgICAgICAgICAgIGxvZygicmVtb3RlIGNv
bnRyb2w6IHJlLWV4ZWN1dGluZyBjYXB0dXJlIHdpdGggdXBkYXRlZCBjb25maWd1cmF0aW9uIikK
ICAgICAgICAgICAgICAgICAgICBzLmNsb3NlKCkKICAgICAgICAgICAgICAgICAgICBvcy5leGVj
dihzeXMuZXhlY3V0YWJsZSwgYXJncykKICAgICAgICAgICAgICAgIGVsaWYgY29udHJvbF9hY3Rp
b24gPT0gInN0b3AiOgogICAgICAgICAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2w6IHN0
b3AgcmVxdWVzdGVkOyBleGl0aW5nIikKICAgICAgICAgICAgICAgICAgICBydW5uaW5nWzBdID0g
RmFsc2UKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBleGNlcHQgRXhj
ZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIHRp
Y2sgZmFpbGVkICglcykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCiAgICAgICAgICAg
IGNvbnRyb2xfbmV4dCA9IHRpbWUudGltZSgpICsgY29udHJvbF9pbnRlcnZhbAogICAgICAgIHRy
eToKICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQogICAgICAgICAgICBkYmdfcnggKz0g
MQogICAgICAgICAgICBzdGF0c19zdGF0ZVsicGFja2V0c190b3RhbCJdICs9IDEKICAgICAgICAg
ICAgc3RhdHNfc3RhdGVbInBhY2tldF9ieXRlc190b3RhbCJdICs9IGxlbihwa3QpCiAgICAgICAg
ICAgIGlmIGRiZyBhbmQgdGltZS50aW1lKCkgLSBkYmdfbGFzdCA+IDU6CiAgICAgICAgICAgICAg
ICBsb2coIkRFQlVHIHJ4PSVkIiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0ID0g
dGltZS50aW1lKCkKICAgICAgICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6CiAgICAgICAgICAgIGlm
IGRiZzoKICAgICAgICAgICAgICAgIGxvZygiREVCVUcgdGltZW91dCByeD0lZCIgJSBkYmdfcngp
CiAgICAgICAgICAgICAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgICAgIG5vdyA9
IHRpbWUudGltZSgpCiAgICAgICAgICAgIGlmIG1haW50ZW5hbmNlX2R1ZShub3csIGxhc3Rfc3dl
ZXApOgogICAgICAgICAgICAgICAgb3V0X3MgPSBbXQogICAgICAgICAgICAgICAgc3dlZXBfaWRs
ZShmbG93cywgbm93LCBvdXRfcywgcGVuZGluZywgcmVzcF9mbG93cykKICAgICAgICAgICAgICAg
IHN3ZWVwX3BlbmRpbmcocGVuZGluZywgbm93LCBvdXRfcykKICAgICAgICAgICAgICAgIHdyaXRl
X2V2ZW50cyhvdXRfcykKICAgICAgICAgICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKICAgICAgICAg
ICAgY29udGludWUKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgICAg
IGlmIGUuZXJybm8gPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAg
ICAgICAgICByYWlzZQoKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIG91dCA9IFtd
CiAgICAgICAgcHJvY2Vzc19wYWNrZXQocGt0LCBwb3J0cywgbm9kZV9ob3N0LCBmbG93cywgcmVz
cF9mbG93cywgcGVuZGluZywKICAgICAgICAgICAgICAgICAgICAgICBvdXQsIG5vdywgd3NzZV9i
b2R5X2J5dGVzKQogICAgICAgIGlmIG91dDoKICAgICAgICAgICAgd3JpdGVfZXZlbnRzKG91dCkK
CiAgICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6CiAgICAgICAgICAg
IG91dF9zID0gW10KICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93LCBvdXRfcywgcGVu
ZGluZywgcmVzcF9mbG93cykKICAgICAgICAgICAgc3dlZXBfcGVuZGluZyhwZW5kaW5nLCBub3cs
IG91dF9zKQogICAgICAgICAgICB3cml0ZV9ldmVudHMob3V0X3MpCiAgICAgICAgICAgIGxhc3Rf
c3dlZXAgPSBub3cKCiAgICBvdXRfcyA9IFtdCiAgICBkcmFpbl9pbmNvbXBsZXRlX3dzc2UoZmxv
d3MsIG91dF9zLCBwZW5kaW5nLCB0aW1lLnRpbWUoKSkKICAgIGRyYWluX3BlbmRpbmcocGVuZGlu
Zywgb3V0X3MpCiAgICB3cml0ZV9ldmVudHMob3V0X3MpCiAgICBlbWl0X2NhcHR1cmVfc3RhdHMo
Zm9yY2U9VHJ1ZSkKICAgIGxvZygic3RvcHBlZCAoJWQgcGVuZGluZyByZXF1ZXN0cyBmbHVzaGVk
KSIgJSBsZW4ob3V0X3MpKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK
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
ZW47CiAgYm9vbCBjb3JyZWxhdGlvbl9kaXNhYmxlZDsKICB0aW1lX3QgdG91Y2hlZDsKICBsb25n
IGxvbmcgZmlyc3RfYnl0ZV9tb25vX21zOwogIHVpbnQzMl90IGdlbmVyYXRpb247CiAgc3RkOjpz
dHJpbmcgYnVmOwogIHN0ZDo6dmVjdG9yPFRjcFNlZ21lbnQ+IG9vbzsKCiAgZW51bSBIdHRwU3Rh
dGUgewogICAgSFRUUF9TVEFURV9IRUFERVIsCiAgICBIVFRQX1NUQVRFX0JPRFksCiAgICBIVFRQ
X1NUQVRFX0NIVU5LLAogICAgSFRUUF9TVEFURV9DTE9TRV9CT0RZCiAgfSBzdGF0ZTsKCiAgc2l6
ZV90IGJvZHlfcmVtYWluaW5nOwogIHNpemVfdCBjaHVua19wYXlsb2FkX3JlbWFpbmluZzsKICBi
b29sIGNodW5rX3JlYWRpbmdfbGVuOwogIGJvb2wgY2h1bmtfcmVhZGluZ19jcmxmOwogIGJvb2wg
Y2h1bmtfcmVhZGluZ190cmFpbGVyOwoKICBib29sIGF3YWl0aW5nX3dzc2U7CiAgRXZlbnQgd3Nz
ZV9ldmVudDsKICBzdGQ6OnN0cmluZyB3c3NlX2J1ZjsKICBzaXplX3Qgd3NzZV9nb2FsOwoKICBG
bG93KCkgOiBuZXh0X3NlcSgwKSwgaGFzX3NlcShmYWxzZSksIGlzX2Jyb2tlbihmYWxzZSksIGNv
cnJlbGF0aW9uX2Rpc2FibGVkKGZhbHNlKSwKICAgICAgICAgICB0b3VjaGVkKHRpbWUoTlVMTCkp
LCBmaXJzdF9ieXRlX21vbm9fbXMoMCksIGdlbmVyYXRpb24oMCksCiAgICAgICAgICAgc3RhdGUo
SFRUUF9TVEFURV9IRUFERVIpLCBib2R5X3JlbWFpbmluZygwKSwgY2h1bmtfcGF5bG9hZF9yZW1h
aW5pbmcoMCksCiAgICAgICAgICAgY2h1bmtfcmVhZGluZ19sZW4odHJ1ZSksIGNodW5rX3JlYWRp
bmdfY3JsZihmYWxzZSksIGNodW5rX3JlYWRpbmdfdHJhaWxlcihmYWxzZSksCiAgICAgICAgICAg
YXdhaXRpbmdfd3NzZShmYWxzZSksIHdzc2VfZ29hbCgwKSB7fQoKICB2b2lkIGNsZWFyX2J1ZmZl
cnMoKSB7CiAgICBmbG93X2J5dGVzX3N1YihidWYuc2l6ZSgpKTsKICAgIGJ1Zi5jbGVhcigpOwog
ICAgZmxvd19ieXRlc19zdWIod3NzZV9idWYuc2l6ZSgpKTsKICAgIHdzc2VfYnVmLmNsZWFyKCk7
CiAgICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IG9vby5zaXplKCk7ICsraSkgewogICAgICBmbG93
X2J5dGVzX3N1Yihvb29baV0uZGF0YS5zaXplKCkpOwogICAgfQogICAgb29vLmNsZWFyKCk7CiAg
fQoKICBib29sIGJ1Zl9hcHBlbmQoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbikgewogICAg
aWYgKGJ1Zi5zaXplKCkgKyBsZW4gPiBNQVhfRkxPV19CVUZGRVJfQllURVMpIHsKICAgICAgY2xl
YXJfYnVmZmVycygpOwogICAgICBpc19icm9rZW4gPSB0cnVlOwogICAgICByZXR1cm4gZmFsc2U7
CiAgICB9CiAgICBidWYuYXBwZW5kKGRhdGEsIGxlbik7CiAgICBmbG93X2J5dGVzX2FkZChsZW4p
OwogICAgcmV0dXJuIHRydWU7CiAgfQoKICB2b2lkIGJ1Zl9lcmFzZShzaXplX3Qgb2ZmLCBzaXpl
X3QgbGVuKSB7CiAgICBpZiAob2ZmID49IGJ1Zi5zaXplKCkpIHJldHVybjsKICAgIGlmIChsZW4g
PiBidWYuc2l6ZSgpIC0gb2ZmKSBsZW4gPSBidWYuc2l6ZSgpIC0gb2ZmOwogICAgYnVmLmVyYXNl
KG9mZiwgbGVuKTsKICAgIGZsb3dfYnl0ZXNfc3ViKGxlbik7CiAgfQoKICB2b2lkIHdzc2VfYXBw
ZW5kKGNvbnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4pIHsKICAgIHdzc2VfYnVmLmFwcGVuZChk
YXRhLCBsZW4pOwogICAgZmxvd19ieXRlc19hZGQobGVuKTsKICB9CgogIGJvb2wgb29vX3B1c2go
dWludDMyX3Qgc2VxLCBjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuKSB7CiAgICBpZiAob29v
LnNpemUoKSA+PSBNQVhfT09PX1NFR01FTlRTKSByZXR1cm4gZmFsc2U7CiAgICBUY3BTZWdtZW50
IHNlZzsKICAgIHNlZy5zZXEgPSBzZXE7CiAgICBzZWcuZGF0YS5hc3NpZ24oZGF0YSwgbGVuKTsK
ICAgIG9vby5wdXNoX2JhY2soc2VnKTsKICAgIGZsb3dfYnl0ZXNfYWRkKGxlbik7CiAgICByZXR1
cm4gdHJ1ZTsKICB9CgogIHZvaWQgb29vX2VyYXNlKHNpemVfdCBpZHgpIHsKICAgIGlmIChpZHgg
PCBvb28uc2l6ZSgpKSB7CiAgICAgIGZsb3dfYnl0ZXNfc3ViKG9vb1tpZHhdLmRhdGEuc2l6ZSgp
KTsKICAgICAgb29vLmVyYXNlKG9vby5iZWdpbigpICsgaWR4KTsKICAgIH0KICB9Cn07CgpzdHJ1
Y3QgRmxvd0tleSB7CiAgdWludDMyX3Qgc19pcDsKICB1aW50MTZfdCBzcG9ydDsKICB1aW50MzJf
dCBkX2lwOwogIHVpbnQxNl90IGRwb3J0OwogIGJvb2wgb3BlcmF0b3I8KGNvbnN0IEZsb3dLZXkg
JngpIGNvbnN0IHsKICAgIGlmIChzX2lwICE9IHguc19pcCkgcmV0dXJuIHNfaXAgPCB4LnNfaXA7
CiAgICBpZiAoc3BvcnQgIT0geC5zcG9ydCkgcmV0dXJuIHNwb3J0IDwgeC5zcG9ydDsKICAgIGlm
IChkX2lwICE9IHguZF9pcCkgcmV0dXJuIGRfaXAgPCB4LmRfaXA7CiAgICByZXR1cm4gZHBvcnQg
PCB4LmRwb3J0OwogIH0KfTsKdHlwZWRlZiBGbG93S2V5IFBhY2tldEtleTsKCnN0YXRpYyB1aW50
NjRfdCBnX3JlcV9pZF9zZXEgPSAwOwoKc3RydWN0IFBlbmRpbmcgewogIHVpbnQ2NF90IHJlcV9p
ZDsKICB1aW50MzJfdCBnZW5lcmF0aW9uOwogIEV2ZW50IGV2OwogIGxvbmcgbG9uZyBzdGFydGVk
X3dhbGxfbXM7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbW9ub19tczsKICBib29sIGlzX3RvbWJzdG9u
ZTsKICBsb25nIGxvbmcgdG9tYnN0b25lX21vbm9fbXM7CiAgUGVuZGluZygpIDogcmVxX2lkKDAp
LCBnZW5lcmF0aW9uKDApLCBzdGFydGVkX3dhbGxfbXMoMCksIHN0YXJ0ZWRfbW9ub19tcygwKSwK
ICAgICAgICAgICAgICBpc190b21ic3RvbmUoZmFsc2UpLCB0b21ic3RvbmVfbW9ub19tcygwKSB7
fQogIFBlbmRpbmcodWludDY0X3QgaWQsIHVpbnQzMl90IGdlbiwgY29uc3QgRXZlbnQgJmUsIGxv
bmcgbG9uZyB3YWxsX3QsIGxvbmcgbG9uZyBtb25vX3QpCiAgICA6IHJlcV9pZChpZCksIGdlbmVy
YXRpb24oZ2VuKSwgZXYoZSksIHN0YXJ0ZWRfd2FsbF9tcyh3YWxsX3QpLCBzdGFydGVkX21vbm9f
bXMobW9ub190KSwKICAgICAgaXNfdG9tYnN0b25lKGZhbHNlKSwgdG9tYnN0b25lX21vbm9fbXMo
MCkge30KfTsKCnN0cnVjdCBQZW5kaW5nUXVldWVSZWYgewogIHVpbnQ2NF90IHJlcV9pZDsKICB1
aW50MzJfdCBnZW5lcmF0aW9uOwogIFBhY2tldEtleSBrZXk7CiAgbG9uZyBsb25nIHN0YXJ0ZWRf
bW9ub19tczsKfTsKCnN0YXRpYyBzaXplX3QgZ190b3RhbF9wZW5kaW5nX2NvdW50ID0gMDsKc3Rh
dGljIHN0ZDo6bGlzdDxQZW5kaW5nUXVldWVSZWY+IGdfcGVuZGluZ19maWZvOwovLyBQYWNrZXRL
ZXkgZW50cmllcyAocmVzcG9uc2UtZGlyZWN0aW9uOiBzZXJ2ZXLihpJjbGllbnQpIGZvciB3aGlj
aCByZXNwb25zZQovLyBjb3JyZWxhdGlvbiBpcyBwZXJtYW5lbnRseSBkaXNhYmxlZCB1bnRpbCBh
IHZlcmlmaWVkIG5ldyBTWU4gYXJyaXZlcy4KLy8gU2V0IHdoZW4gYSB0b21ic3RvbmUgZXhwaXJl
cyB1bi1jb25zdW1lZCBvciB3aGVuIGEgcGVuZGluZyBlbnRyeSBpcwovLyBmb3JjZS1ldmljdGVk
OyBjbGVhcmVkIG9ubHkgb24gY2xpZW50IFNZTi4Kc3RhdGljIHN0ZDo6c2V0PFBhY2tldEtleT4g
Z19jb3JyX2Rpc2FibGVkOwoKc3RhdGljIHZvaWQgbG9nbXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZz
KSB7IGZwcmludGYoc3RkZXJyLCAibnQtc25pZmYtY3BwOiAlc1xuIiwgcy5jX3N0cigpKTsgZmZs
dXNoKHN0ZGVycik7IH0KCnN0YXRpYyBib29sIHBhcnNlX2RlY2ltYWxfc2l6ZShjb25zdCBjaGFy
ICpwLCBzaXplX3Qgbiwgc2l6ZV90ICpvdXQpIHsKICB3aGlsZSAobiAmJiBpc3NwYWNlKCh1bnNp
Z25lZCBjaGFyKSpwKSkgeyArK3A7IC0tbjsgfQogIHdoaWxlIChuICYmIGlzc3BhY2UoKHVuc2ln
bmVkIGNoYXIpcFtuIC0gMV0pKSAtLW47CiAgaWYgKCFuKSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90
IHZhbHVlID0gMDsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IG47ICsraSkgewogICAgaWYgKHBb
aV0gPCAnMCcgfHwgcFtpXSA+ICc5JykgcmV0dXJuIGZhbHNlOwogICAgdW5zaWduZWQgZGlnaXQg
PSAodW5zaWduZWQpKHBbaV0gLSAnMCcpOwogICAgaWYgKHZhbHVlID4gKHNpemVfdCktMSAvIDEw
IHx8IHZhbHVlICogMTAgPiAoc2l6ZV90KS0xIC0gZGlnaXQpIHJldHVybiBmYWxzZTsKICAgIHZh
bHVlID0gdmFsdWUgKiAxMCArIGRpZ2l0OwogIH0KICAqb3V0ID0gdmFsdWU7CiAgcmV0dXJuIHRy
dWU7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3JlcXVlc3QoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90
IGxlbiwgRXZlbnQgKmUsIFJlcXVlc3RNZXRhICptZXRhKSB7CiAgY29uc3QgY2hhciAqZW5kID0g
ZGF0YSArIGxlbjsKICBjb25zdCBjaGFyICpwID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAo
Y29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJu
IGZhbHNlOwogIGNvbnN0IGNoYXIgKnNwMSA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICcgJywg
ZW9sIC0gcCk7CiAgaWYgKCFzcDEpIHJldHVybiBmYWxzZTsKICBlLT5tZXRob2QuYXNzaWduKHAs
IHNwMSAtIHApOwogIGlmICghaGFzX21ldGhvZChlLT5tZXRob2QpKSByZXR1cm4gZmFsc2U7Cgog
IGNvbnN0IGNoYXIgKnBhdGhfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChwYXRoX3N0YXJ0IDwg
ZW9sICYmICpwYXRoX3N0YXJ0ID09ICcgJykgKytwYXRoX3N0YXJ0OwogIGNvbnN0IGNoYXIgKnNw
MiA9IChjb25zdCBjaGFyICopbWVtY2hyKHBhdGhfc3RhcnQsICcgJywgZW9sIC0gcGF0aF9zdGFy
dCk7CiAgaWYgKCFzcDIpIHNwMiA9IChlb2wgPiBkYXRhICYmICooZW9sIC0gMSkgPT0gJ1xyJykg
PyBlb2wgLSAxIDogZW9sOwogIGNvbnN0IGNoYXIgKnFtYXJrID0gKGNvbnN0IGNoYXIgKiltZW1j
aHIocGF0aF9zdGFydCwgJz8nLCBzcDIgLSBwYXRoX3N0YXJ0KTsKICBzaXplX3QgcGF0aF9sZW4g
PSAocW1hcmsgPyBxbWFyayA6IHNwMikgLSBwYXRoX3N0YXJ0OwogIGlmIChwYXRoX2xlbiA+IDEy
MCkgcGF0aF9sZW4gPSAxMjA7CiAgZS0+cGF0aC5hc3NpZ24ocGF0aF9zdGFydCwgcGF0aF9sZW4p
OwoKICBwID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYgKCpwID09ICdccicg
fHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2VuZCA9IChjb25zdCBj
aGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5lX2VuZCkgbGluZV9l
bmQgPSBlbmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFyICopbWVtY2hyKHAs
ICc6JywgbGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBzaXplX3QgaG5hbWVf
bGVuID0gY29sb24gLSBwOwogICAgICBjb25zdCBjaGFyICp2YWxfc3RhcnQgPSBjb2xvbiArIDE7
CiAgICAgIHdoaWxlICh2YWxfc3RhcnQgPCBsaW5lX2VuZCAmJiAoKnZhbF9zdGFydCA9PSAnICcg
fHwgKnZhbF9zdGFydCA9PSAnXHQnKSkgKyt2YWxfc3RhcnQ7CiAgICAgIGNvbnN0IGNoYXIgKnZh
bF9lbmQgPSBsaW5lX2VuZDsKICAgICAgd2hpbGUgKHZhbF9lbmQgPiB2YWxfc3RhcnQgJiYgKHZh
bF9lbmRbLTFdID09ICdccicgfHwgdmFsX2VuZFstMV0gPT0gJ1xuJyB8fCB2YWxfZW5kWy0xXSA9
PSAnICcgfHwgdmFsX2VuZFstMV0gPT0gJ1x0JykpIC0tdmFsX2VuZDsKICAgICAgc2l6ZV90IHZh
bF9sZW4gPSB2YWxfZW5kIC0gdmFsX3N0YXJ0OwoKICAgICAgaWYgKGhuYW1lX2xlbiA9PSAxMyAm
JiAhc3RybmNhc2VjbXAocCwgImF1dGhvcml6YXRpb24iLCAxMykpIHsKICAgICAgICBpZiAodmFs
X2xlbiA+IDYgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJhc2ljICIsIDYpKSB7CiAgICAg
ICAgICBzdGQ6OnN0cmluZyBiYXNpY191c2VyID0gYjY0ZGVjb2RlX3VzZXIodmFsX3N0YXJ0ICsg
NiwgdmFsX2xlbiAtIDYpOwogICAgICAgICAgaWYgKCFiYXNpY191c2VyLmVtcHR5KCkpIHsKICAg
ICAgICAgICAgZS0+YmFzaWNfdXNlciA9IGJhc2ljX3VzZXI7CiAgICAgICAgICAgIGUtPnVzZXIg
PSBiYXNpY191c2VyOwogICAgICAgICAgICBlLT5zY2hlbWUgPSAiYmFzaWMiOwogICAgICAgICAg
fQogICAgICAgIH0gZWxzZSBpZiAodmFsX2xlbiA+IDcgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFy
dCwgIkJlYXJlciAiLCA3KSkgewogICAgICAgICAgZS0+c2NoZW1lID0gImJlYXJlciI7CiAgICAg
ICAgfQogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xlbiA9PSAxMSAmJiAhc3RybmNhc2VjbXAocCwg
InRyYWNlcGFyZW50IiwgMTEpKSB7CiAgICAgICAgZS0+dHJhY2VwYXJlbnQuYXNzaWduKHZhbF9z
dGFydCwgdmFsX2xlbik7CiAgICAgICAgZS0+dHJhY2VfaWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVu
dChlLT50cmFjZXBhcmVudCk7CiAgICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDQgJiYgIXN0
cm5jYXNlY21wKHAsICJob3N0IiwgNCkpIHsKICAgICAgICBlLT5ob3N0X2hkci5hc3NpZ24odmFs
X3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTAgJiYgIXN0
cm5jYXNlY21wKHAsICJ1c2VyLWFnZW50IiwgMTApKSB7CiAgICAgICAgZS0+dXNlcl9hZ2VudC5h
c3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0g
MTUgJiYgIXN0cm5jYXNlY21wKHAsICJ4LWZvcndhcmRlZC1mb3IiLCAxNSkpIHsKICAgICAgICBl
LT54ZmYuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAm
JiBobmFtZV9sZW4gPT0gMTIgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LXR5cGUiLCAxMikp
IHsKICAgICAgICBtZXRhLT5jb250ZW50X3R5cGUuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7
CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFtZV9sZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21w
KHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkgewogICAgICAgIHNpemVfdCBjbGVuX3ZhbCA9IDA7
CiAgICAgICAgaWYgKHBhcnNlX2RlY2ltYWxfc2l6ZSh2YWxfc3RhcnQsIHZhbF9sZW4sICZjbGVu
X3ZhbCkpIHsKICAgICAgICAgIGlmIChtZXRhLT5oYXNfY29udGVudF9sZW5ndGggJiYgbWV0YS0+
Y29udGVudF9sZW5ndGggIT0gY2xlbl92YWwpIHsKICAgICAgICAgICAgbWV0YS0+aGFzX2NvbmZs
aWN0X2NsID0gdHJ1ZTsKICAgICAgICAgIH0KICAgICAgICAgIG1ldGEtPmNvbnRlbnRfbGVuZ3Ro
ID0gY2xlbl92YWw7CiAgICAgICAgICBtZXRhLT5oYXNfY29udGVudF9sZW5ndGggPSB0cnVlOwog
ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBtZXRhLT5oYXNfY29uZmxpY3RfY2wgPSB0cnVlOwog
ICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChtZXRhICYmIGhuYW1lX2xlbiA9PSAxNyAmJiAhc3Ry
bmNhc2VjbXAocCwgInRyYW5zZmVyLWVuY29kaW5nIiwgMTcpKSB7CiAgICAgICAgbWV0YS0+dHJh
bnNmZXJfZW5jb2RpbmcuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0KICAgIH0K
ICAgIHAgPSBsaW5lX2VuZCArIDE7CiAgfQoKCgogIGlmIChlLT51c2VyLmVtcHR5KCkpIGUtPnVz
ZXIgPSAiLWFub255bW91cy0iOwogIGlmIChlLT5zY2hlbWUuZW1wdHkoKSkgZS0+c2NoZW1lID0g
Im5vbmUiOwogIGlmIChlLT50cmFjZV9pZC5lbXB0eSgpKSBlLT50cmFjZXBhcmVudCA9IG1ha2Vf
dHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lkKTsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wg
aXNfd3NzZV9uYW1lc3BhY2UoY29uc3Qgc3RkOjpzdHJpbmcgJnVyaSkgewogIHJldHVybiB1cmkg
PT0gImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxL29hc2lzLTIwMDQwMS13
c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIgfHwKICAgICAgICAgdXJpID09ICJodHRwOi8v
c2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3L3NlY2V4dCIgfHwKICAgICAgICAgdXJpID09
ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzEyL3NlY2V4dCIgfHwKICAgICAg
ICAgdXJpID09ICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAzLzA2L3NlY2V4dCI7
Cn0KCnN0YXRpYyBib29sIGlzX3NvYXBfY29udGVudF90eXBlKGNvbnN0IHN0ZDo6c3RyaW5nICZj
dCkgewogIHN0ZDo6c3RyaW5nIHggPSBsb3dlcihjdCk7CiAgcmV0dXJuIHguZmluZCgidGV4dC94
bWwiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAgICAgICB4LmZpbmQoImFwcGxpY2F0aW9u
L3NvYXAreG1sIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwKICAgICAgICAgeC5maW5kKCIreG1s
IikgIT0gc3RkOjpzdHJpbmc6Om5wb3M7Cn0KCnN0YXRpYyB2b2lkIHNwbGl0X3FuYW1lKGNvbnN0
IHN0ZDo6c3RyaW5nICZxbmFtZSwgc3RkOjpzdHJpbmcgKnByZWZpeCwgc3RkOjpzdHJpbmcgKmxv
Y2FsKSB7CiAgc2l6ZV90IHAgPSBxbmFtZS5maW5kKCc6Jyk7CiAgaWYgKHAgPT0gc3RkOjpzdHJp
bmc6Om5wb3MpIHsgcHJlZml4LT5jbGVhcigpOyAqbG9jYWwgPSBxbmFtZTsgfQogIGVsc2UgeyAq
cHJlZml4ID0gcW5hbWUuc3Vic3RyKDAsIHApOyAqbG9jYWwgPSBxbmFtZS5zdWJzdHIocCArIDEp
OyB9Cn0KCnN0YXRpYyBib29sIHhtbF91bmVzY2FwZShjb25zdCBzdGQ6OnN0cmluZyAmaW4sIHN0
ZDo6c3RyaW5nICpvdXQpIHsKICBvdXQtPmNsZWFyKCk7CiAgb3V0LT5yZXNlcnZlKGluLnNpemUo
KSk7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBpbi5zaXplKCk7ICsraSkgewogICAgaWYgKGlu
W2ldICE9ICcmJykgeyBvdXQtPnB1c2hfYmFjayhpbltpXSk7IGNvbnRpbnVlOyB9CiAgICBzaXpl
X3Qgc2VtaSA9IGluLmZpbmQoJzsnLCBpICsgMSk7CiAgICBpZiAoc2VtaSA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcykgcmV0dXJuIGZhbHNlOwogICAgc3RkOjpzdHJpbmcgcmVmID0gaW4uc3Vic3RyKGkg
KyAxLCBzZW1pIC0gaSAtIDEpOwogICAgaWYgKHJlZiA9PSAiYW1wIikgb3V0LT5wdXNoX2JhY2so
JyYnKTsKICAgIGVsc2UgaWYgKHJlZiA9PSAibHQiKSBvdXQtPnB1c2hfYmFjaygnPCcpOwogICAg
ZWxzZSBpZiAocmVmID09ICJndCIpIG91dC0+cHVzaF9iYWNrKCc+Jyk7CiAgICBlbHNlIGlmIChy
ZWYgPT0gInF1b3QiKSBvdXQtPnB1c2hfYmFjaygnIicpOwogICAgZWxzZSBpZiAocmVmID09ICJh
cG9zIikgb3V0LT5wdXNoX2JhY2soJ1wnJyk7CiAgICBlbHNlIGlmICghcmVmLmVtcHR5KCkgJiYg
cmVmWzBdID09ICcjJykgewogICAgICB1bnNpZ25lZCBsb25nIHZhbCA9IDA7CiAgICAgIGNoYXIg
KmVuZHAgPSBOVUxMOwogICAgICBpZiAocmVmLnNpemUoKSA+IDIgJiYgKHJlZlsxXSA9PSAneCcg
fHwgcmVmWzFdID09ICdYJykpIHsKICAgICAgICB2YWwgPSBzdHJ0b3VsKHJlZi5jX3N0cigpICsg
MiwgJmVuZHAsIDE2KTsKICAgICAgfSBlbHNlIHsKICAgICAgICB2YWwgPSBzdHJ0b3VsKHJlZi5j
X3N0cigpICsgMSwgJmVuZHAsIDEwKTsKICAgICAgfQogICAgICBpZiAoIWVuZHAgfHwgKmVuZHAg
IT0gJ1wwJyB8fCB2YWwgPiAweDEwZmZmZlVMKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmICh2YWwg
PCAweDgwKSB7CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpdmFsKTsKICAgICAgfSBlbHNl
IGlmICh2YWwgPCAweDgwMCkgewogICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGMwIHwg
KHZhbCA+PiA2KSkpOwogICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKHZhbCAm
IDB4M2YpKSk7CiAgICAgIH0gZWxzZSBpZiAodmFsIDwgMHgxMDAwMCkgewogICAgICAgIG91dC0+
cHVzaF9iYWNrKChjaGFyKSgweGUwIHwgKHZhbCA+PiAxMikpKTsKICAgICAgICBvdXQtPnB1c2hf
YmFjaygoY2hhcikoMHg4MCB8ICgodmFsID4+IDYpICYgMHgzZikpKTsKICAgICAgICBvdXQtPnB1
c2hfYmFjaygoY2hhcikoMHg4MCB8ICh2YWwgJiAweDNmKSkpOwogICAgICB9IGVsc2UgewogICAg
ICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGYwIHwgKHZhbCA+PiAxOCkpKTsKICAgICAgICBv
dXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgodmFsID4+IDEyKSAmIDB4M2YpKSk7CiAgICAg
ICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoKHZhbCA+PiA2KSAmIDB4M2YpKSk7CiAg
ICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAodmFsICYgMHgzZikpKTsKICAgICAg
fQogICAgfSBlbHNlIHsKICAgICAgcmV0dXJuIGZhbHNlOwogICAgfQogICAgaSA9IHNlbWk7CiAg
fQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCB2YWxpZF91dGY4X3VzZXJuYW1lKGNvbnN0
IHN0ZDo6c3RyaW5nICZzKSB7CiAgaWYgKHMuZW1wdHkoKSB8fCBzLnNpemUoKSA+IE1BWF9XU1NF
X1VTRVJOQU1FICogNCkgcmV0dXJuIGZhbHNlOwogIHNpemVfdCBjaGFyYWN0ZXJzID0gMDsKICBm
b3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOykgewogICAgdW5zaWduZWQgY2hhciBjID0g
KHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIHVuc2lnbmVkIGxvbmcgY3AgPSAwOwogICAgc2l6ZV90
IG5lZWQgPSAwOwogICAgaWYgKGMgPCAweDgwKSB7IGNwID0gYzsgbmVlZCA9IDA7ICsraTsgfQog
ICAgZWxzZSBpZiAoKGMgJiAweGUwKSA9PSAweGMwKSB7IG5lZWQgPSAxOyB9CiAgICBlbHNlIGlm
ICgoYyAmIDB4ZjApID09IDB4ZTApIHsgbmVlZCA9IDI7IH0KICAgIGVsc2UgaWYgKChjICYgMHhm
OCkgPT0gMHhmMCkgeyBuZWVkID0gMzsgfQogICAgZWxzZSByZXR1cm4gZmFsc2U7CgogICAgaWYg
KG5lZWQpIHsKICAgICAgaWYgKGkgKyBuZWVkID49IHMuc2l6ZSgpKSByZXR1cm4gZmFsc2U7CiAg
ICAgIGlmIChuZWVkID09IDEgJiYgYyA8IDB4YzIpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKG5l
ZWQgPT0gMiAmJiBjID09IDB4ZTAgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPCAweGEwKSBy
ZXR1cm4gZmFsc2U7CiAgICAgIGlmIChuZWVkID09IDIgJiYgYyA9PSAweGVkICYmICh1bnNpZ25l
ZCBjaGFyKXNbaSArIDFdID49IDB4YTApIHJldHVybiBmYWxzZTsKICAgICAgaWYgKG5lZWQgPT0g
MyAmJiBjID09IDB4ZjAgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPCAweDkwKSByZXR1cm4g
ZmFsc2U7CiAgICAgIGlmIChuZWVkID09IDMgJiYgYyA9PSAweGY0ICYmICh1bnNpZ25lZCBjaGFy
KXNbaSArIDFdID49IDB4OTApIHJldHVybiBmYWxzZTsKICAgICAgY3AgPSBjICYgKCgxVSA8PCAo
NyAtIG5lZWQgLSAxKSkgLSAxKTsKICAgICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0gbmVlZDsg
KytqKSBjcCA9IChjcCA8PCA2KSB8ICgodW5zaWduZWQgY2hhcilzW2kgKyBqXSAmIDB4M2YpOwog
ICAgICBpICs9IG5lZWQgKyAxOwogICAgfQogICAgaWYgKCsrY2hhcmFjdGVycyA+IE1BWF9XU1NF
X1VTRVJOQU1FKSByZXR1cm4gZmFsc2U7CiAgICBpZiAoY3AgPCAweDIwIHx8IChjcCA+PSAweDdm
ICYmIGNwIDw9IDB4OWYpIHx8CiAgICAgICAgKGNwID49IDB4ZTAwMCAmJiBjcCA8PSAweGY4ZmYp
IHx8CiAgICAgICAgKGNwID49IDB4ZjAwMDAgJiYgY3AgPD0gMHhmZmZmZCkgfHwKICAgICAgICAo
Y3AgPj0gMHgxMDAwMDAgJiYgY3AgPD0gMHgxMGZmZmQpIHx8CiAgICAgICAgKGNwID49IDB4ZmRk
MCAmJiBjcCA8PSAweGZkZWYpIHx8IChjcCAmIDB4ZmZmZlVMKSA+PSAweGZmZmVVTCB8fAogICAg
ICAgIGNwID09IDB4MDBhZCB8fCBjcCA9PSAweDA2MWMgfHwgY3AgPT0gMHgwNmRkIHx8IGNwID09
IDB4MDcwZiB8fAogICAgICAgIGNwID09IDB4MTgwZSB8fCAoY3AgPj0gMHgyMDBiICYmIGNwIDw9
IDB4MjAwZikgfHwKICAgICAgICAoY3AgPj0gMHgyMDJhICYmIGNwIDw9IDB4MjAyZSkgfHwgKGNw
ID49IDB4MjA2MCAmJiBjcCA8PSAweDIwNmYpIHx8CiAgICAgICAgY3AgPT0gMHhmZWZmKSByZXR1
cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdHJ1Y3QgWG1sRnJhbWUgewogIHN0ZDo6
bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz4gbnM7CiAgc3RkOjpzdHJpbmcgcW5hbWUsIHVy
aSwgbG9jYWw7Cn07CgpzdGF0aWMgYm9vbCBwYXJzZV94bWxfbmFtZShjb25zdCBzdGQ6OnN0cmlu
ZyAmYm9keSwgc2l6ZV90IGxpbWl0LCBzaXplX3QgKnBvcywKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgc3RkOjpzdHJpbmcgKm5hbWUpIHsKICBzaXplX3Qgc3RhcnQgPSAqcG9zOwogIHdoaWxl
ICgqcG9zIDwgbGltaXQpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWJv
ZHlbKnBvc107CiAgICBpZiAoIShpc2FsbnVtKGMpIHx8IGMgPT0gJ18nIHx8IGMgPT0gJy0nIHx8
IGMgPT0gJy4nIHx8IGMgPT0gJzonKSkgYnJlYWs7CiAgICArKypwb3M7CiAgfQogIGlmICgqcG9z
ID09IHN0YXJ0IHx8ICpwb3MgLSBzdGFydCA+IDI1NikgcmV0dXJuIGZhbHNlOwogIG5hbWUtPmFz
c2lnbihib2R5LCBzdGFydCwgKnBvcyAtIHN0YXJ0KTsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGlj
IHN0ZDo6c3RyaW5nIGV4dHJhY3Rfd3NzZV91c2VybmFtZShjb25zdCBzdGQ6OnN0cmluZyAmYm9k
eSkgewogIGlmIChib2R5LmVtcHR5KCkgfHwgYm9keS5zaXplKCkgPiBNQVhfV1NTRV9CT0RZX0JZ
VEVTIHx8CiAgICAgIGJvZHkuZmluZCgnXDAnKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJu
ICIiOwogIHN0ZDo6c3RyaW5nIGxvd2VyZWQgPSBsb3dlcihib2R5KTsKICBpZiAobG93ZXJlZC5m
aW5kKCI8IWRvY3R5cGUiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAgICBsb3dlcmVkLmZp
bmQoIjwhZW50aXR5IikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiAiIjsKCiAgc3RkOjp2
ZWN0b3I8WG1sRnJhbWU+IHN0YWNrOwogIHNpemVfdCB0b2tlbl9kZXB0aCA9IDAsIHVzZXJuYW1l
X2RlcHRoID0gMCwgcG9zID0gMDsKICBzdGQ6OnN0cmluZyB0b2tlbl91cmksIGNoYXJzLCByZXN1
bHQ7CiAgYm9vbCB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICB3aGlsZSAocG9zIDwgYm9keS5zaXpl
KCkpIHsKICAgIHNpemVfdCBsdCA9IGJvZHkuZmluZCgnPCcsIHBvcyk7CiAgICBpZiAobHQgPT0g
c3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2VybmFt
ZV9iYWQgJiYgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cihwb3MpLCAmY2hhcnMpKSB1c2VybmFt
ZV9iYWQgPSB0cnVlOwogICAgICBicmVhazsKICAgIH0KICAgIGlmICh1c2VybmFtZV9kZXB0aCAm
JiAhdXNlcm5hbWVfYmFkICYmIGx0ID4gcG9zICYmCiAgICAgICAgIXhtbF91bmVzY2FwZShib2R5
LnN1YnN0cihwb3MsIGx0IC0gcG9zKSwgJmNoYXJzKSkgdXNlcm5hbWVfYmFkID0gdHJ1ZTsKICAg
IGlmIChjaGFycy5zaXplKCkgPiBNQVhfV1NTRV9VU0VSTkFNRSAqIDQgKyAyKSB7IGNoYXJzLmNs
ZWFyKCk7IHVzZXJuYW1lX2JhZCA9IHRydWU7IH0KCiAgICBpZiAoYm9keS5jb21wYXJlKGx0LCA0
LCAiPCEtLSIpID09IDApIHsKICAgICAgc2l6ZV90IGVuZCA9IGJvZHkuZmluZCgiLS0+IiwgbHQg
KyA0KTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICAgIHBvcyA9IGVu
ZCArIDM7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgOSwgIjwhW0NE
QVRBWyIpID09IDApIHsKICAgICAgc2l6ZV90IGVuZCA9IGJvZHkuZmluZCgiXV0+IiwgbHQgKyA5
KTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICAgIGlmICh1c2VybmFt
ZV9kZXB0aCAmJiAhdXNlcm5hbWVfYmFkKSBjaGFycy5hcHBlbmQoYm9keSwgbHQgKyA5LCBlbmQg
LSBsdCAtIDkpOwogICAgICBwb3MgPSBlbmQgKyAzOyBjb250aW51ZTsKICAgIH0KICAgIGlmIChi
b2R5LmNvbXBhcmUobHQsIDIsICI8PyIpID09IDApIHsKICAgICAgc2l6ZV90IGVuZCA9IGJvZHku
ZmluZCgiPz4iLCBsdCArIDIpOyBpZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsK
ICAgICAgcG9zID0gZW5kICsgMjsgY29udGludWU7CiAgICB9CiAgICBpZiAoYm9keS5jb21wYXJl
KGx0LCAyLCAiPCEiKSA9PSAwKSByZXR1cm4gIiI7CgogICAgYm9vbCBjbG9zaW5nID0gKGx0ICsg
MSA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbbHQgKyAxXSA9PSAnLycpOwogICAgc2l6ZV90IHAgPSBs
dCArIChjbG9zaW5nID8gMiA6IDEpOwogICAgc3RkOjpzdHJpbmcgcW5hbWU7CiAgICBpZiAoIXBh
cnNlX3htbF9uYW1lKGJvZHksIGJvZHkuc2l6ZSgpLCAmcCwgJnFuYW1lKSkgYnJlYWs7CiAgICBp
ZiAoY2xvc2luZykgewogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGlzc3BhY2UoKHVu
c2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0gYm9keS5zaXplKCkgfHwg
Ym9keVtwXSAhPSAnPicpIGJyZWFrOwogICAgICBpZiAoc3RhY2suZW1wdHkoKSkgYnJlYWs7CiAg
ICAgIHN0ZDo6c3RyaW5nIHByZWZpeCwgbG9jYWw7IHNwbGl0X3FuYW1lKHFuYW1lLCAmcHJlZml4
LCAmbG9jYWwpOwogICAgICBYbWxGcmFtZSAmdG9wID0gc3RhY2suYmFjaygpOwogICAgICBpZiAo
dG9wLnFuYW1lICE9IHFuYW1lIHx8IHRvcC5sb2NhbCAhPSBsb2NhbCkgYnJlYWs7CiAgICAgIHNp
emVfdCBkZXB0aCA9IHN0YWNrLnNpemUoKTsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoID09IGRl
cHRoKSB7CiAgICAgICAgc3RkOjpzdHJpbmcgdXNlcm5hbWUgPSB0cmltKGNoYXJzKTsKICAgICAg
ICBpZiAoIXVzZXJuYW1lX2JhZCAmJiB2YWxpZF91dGY4X3VzZXJuYW1lKHVzZXJuYW1lKSAmJiBy
ZXN1bHQuZW1wdHkoKSkgcmVzdWx0ID0gdXNlcm5hbWU7CiAgICAgICAgdXNlcm5hbWVfZGVwdGgg
PSAwOyBjaGFycy5jbGVhcigpOyB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICAgICAgfQogICAgICBp
ZiAodG9rZW5fZGVwdGggPT0gZGVwdGgpIHsgdG9rZW5fZGVwdGggPSAwOyB0b2tlbl91cmkuY2xl
YXIoKTsgfQogICAgICBzdGFjay5wb3BfYmFjaygpOyBwb3MgPSBwICsgMTsKICAgICAgaWYgKCFy
ZXN1bHQuZW1wdHkoKSkgcmV0dXJuIHJlc3VsdDsKICAgICAgY29udGludWU7CiAgICB9CgogICAg
WG1sRnJhbWUgZnJhbWU7CiAgICBpZiAoc3RhY2suc2l6ZSgpID49IDY0KSByZXR1cm4gIiI7CiAg
ICBpZiAoIXN0YWNrLmVtcHR5KCkpIGZyYW1lLm5zID0gc3RhY2suYmFjaygpLm5zOwogICAgYm9v
bCBzZWxmX2Nsb3NpbmcgPSBmYWxzZSwgY29tcGxldGUgPSBmYWxzZTsKICAgIHNpemVfdCBhdHRy
X2NvdW50ID0gMDsKICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkpIHsKICAgICAgd2hpbGUgKHAg
PCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAg
ICAgIGlmIChwID49IGJvZHkuc2l6ZSgpKSBicmVhazsKICAgICAgaWYgKGJvZHlbcF0gPT0gJz4n
KSB7ICsrcDsgY29tcGxldGUgPSB0cnVlOyBicmVhazsgfQogICAgICBpZiAoYm9keVtwXSA9PSAn
LycgJiYgcCArIDEgPCBib2R5LnNpemUoKSAmJiBib2R5W3AgKyAxXSA9PSAnPicpIHsKICAgICAg
ICBwICs9IDI7IHNlbGZfY2xvc2luZyA9IHRydWU7IGNvbXBsZXRlID0gdHJ1ZTsgYnJlYWs7CiAg
ICAgIH0KICAgICAgc3RkOjpzdHJpbmcgYW5hbWU7CiAgICAgIGlmICghcGFyc2VfeG1sX25hbWUo
Ym9keSwgYm9keS5zaXplKCksICZwLCAmYW5hbWUpKSBicmVhazsKICAgICAgaWYgKCsrYXR0cl9j
b3VudCA+IDEyOCkgcmV0dXJuICIiOwogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGlz
c3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0gYm9keS5z
aXplKCkgfHwgYm9keVtwKytdICE9ICc9JykgYnJlYWs7CiAgICAgIHdoaWxlIChwIDwgYm9keS5z
aXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBpZiAo
cCA+PSBib2R5LnNpemUoKSB8fCAoYm9keVtwXSAhPSAnXCcnICYmIGJvZHlbcF0gIT0gJyInKSkg
YnJlYWs7CiAgICAgIGNoYXIgcXVvdGUgPSBib2R5W3ArK107IHNpemVfdCB2YWx1ZV9zdGFydCA9
IHA7CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkgJiYgYm9keVtwXSAhPSBxdW90ZSkgKytw
OwogICAgICBpZiAocCA+PSBib2R5LnNpemUoKSkgYnJlYWs7CiAgICAgIHN0ZDo6c3RyaW5nIHZh
bHVlOwogICAgICBpZiAoIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cih2YWx1ZV9zdGFydCwgcCAt
IHZhbHVlX3N0YXJ0KSwgJnZhbHVlKSkgcmV0dXJuICIiOwogICAgICArK3A7CiAgICAgIGlmIChh
bmFtZSA9PSAieG1sbnMiKSBmcmFtZS5uc1siIl0gPSB2YWx1ZTsKICAgICAgZWxzZSBpZiAoYW5h
bWUuY29tcGFyZSgwLCA2LCAieG1sbnM6IikgPT0gMCkgZnJhbWUubnNbYW5hbWUuc3Vic3RyKDYp
XSA9IHZhbHVlOwogICAgICBpZiAoZnJhbWUubnMuc2l6ZSgpID4gNjQpIHJldHVybiAiIjsKICAg
IH0KICAgIGlmICghY29tcGxldGUpIGJyZWFrOwogICAgc3RkOjpzdHJpbmcgcHJlZml4LCBsb2Nh
bDsgc3BsaXRfcW5hbWUocW5hbWUsICZwcmVmaXgsICZsb2NhbCk7CiAgICBzdGQ6Om1hcDxzdGQ6
OnN0cmluZywgc3RkOjpzdHJpbmc+Ojpjb25zdF9pdGVyYXRvciBucyA9IGZyYW1lLm5zLmZpbmQo
cHJlZml4KTsKICAgIGZyYW1lLnVyaSA9IChucyA9PSBmcmFtZS5ucy5lbmQoKSkgPyAiIiA6IG5z
LT5zZWNvbmQ7CiAgICBmcmFtZS5xbmFtZSA9IHFuYW1lOwogICAgZnJhbWUubG9jYWwgPSBsb2Nh
bDsKICAgIHN0YWNrLnB1c2hfYmFjayhmcmFtZSk7CiAgICBzaXplX3QgZGVwdGggPSBzdGFjay5z
aXplKCk7CiAgICBpZiAoIXRva2VuX2RlcHRoICYmIGxvY2FsID09ICJVc2VybmFtZVRva2VuIiAm
JiBpc193c3NlX25hbWVzcGFjZShmcmFtZS51cmkpKSB7CiAgICAgIHRva2VuX2RlcHRoID0gZGVw
dGg7IHRva2VuX3VyaSA9IGZyYW1lLnVyaTsKICAgIH0gZWxzZSBpZiAodG9rZW5fZGVwdGggJiYg
ZGVwdGggPT0gdG9rZW5fZGVwdGggKyAxICYmCiAgICAgICAgICAgICAgIGxvY2FsID09ICJVc2Vy
bmFtZSIgJiYgZnJhbWUudXJpID09IHRva2VuX3VyaSkgewogICAgICB1c2VybmFtZV9kZXB0aCA9
IGRlcHRoOyBjaGFycy5jbGVhcigpOyB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICAgIH0KICAgIGlm
IChzZWxmX2Nsb3NpbmcpIHsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoID09IGRlcHRoKSB1c2Vy
bmFtZV9kZXB0aCA9IDA7CiAgICAgIGlmICh0b2tlbl9kZXB0aCA9PSBkZXB0aCkgeyB0b2tlbl9k
ZXB0aCA9IDA7IHRva2VuX3VyaS5jbGVhcigpOyB9CiAgICAgIHN0YWNrLnBvcF9iYWNrKCk7CiAg
ICB9CiAgICBwb3MgPSBwOwogIH0KICByZXR1cm4gcmVzdWx0Owp9CgpzdGF0aWMgYm9vbCBwYXJz
ZV9yZXNwb25zZShjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuLCBpbnQgKnN0YXR1cywgc2l6
ZV90ICpjbGVuLAogICAgICAgICAgICAgICAgICAgICAgICAgICBib29sICpoYXNfY2xlbiwgYm9v
bCAqaXNfY2h1bmtlZCwgYm9vbCAqaXNfY2xvc2UpIHsKICAqaGFzX2NsZW4gPSBmYWxzZTsKICAq
Y2xlbiA9IDA7CiAgKmlzX2NodW5rZWQgPSBmYWxzZTsKICAqaXNfY2xvc2UgPSBmYWxzZTsKICBj
b25zdCBjaGFyICplbmQgPSBkYXRhICsgbGVuOwogIGNvbnN0IGNoYXIgKnAgPSBkYXRhOwogIGNv
bnN0IGNoYXIgKmVvbCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwog
IGlmICghZW9sKSByZXR1cm4gZmFsc2U7CiAgaWYgKHN0cm5jbXAocCwgIkhUVFAvIiwgNSkgIT0g
MCkgcmV0dXJuIGZhbHNlOwogIGJvb2wgaXNfaHR0cF8xMCA9IChlb2wgLSBwID49IDggJiYgc3Ry
bmNtcChwLCAiSFRUUC8xLjAiLCA4KSA9PSAwKTsKICBib29sIGNvbm5fY2xvc2UgPSBmYWxzZTsK
ICBib29sIGNvbm5fa2VlcF9hbGl2ZSA9IGZhbHNlOwoKICBjb25zdCBjaGFyICpzcDEgPSAoY29u
c3QgY2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFs
c2U7CiAgY29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChzY19zdGFydCA8
IGVvbCAmJiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0YXJ0OwogICpzdGF0dXMgPSBhdG9pKHNj
X3N0YXJ0KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAqc3RhdHVzID4gNTk5KSByZXR1cm4gZmFs
c2U7CiAgcCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBlbmQpIHsKICAgIGlmICgqcCA9PSAnXHIn
IHx8ICpwID09ICdcbicpIGJyZWFrOwogICAgY29uc3QgY2hhciAqbGluZV9lbmQgPSAoY29uc3Qg
Y2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICAgIGlmICghbGluZV9lbmQpIGxpbmVf
ZW5kID0gZW5kOwogICAgY29uc3QgY2hhciAqY29sb24gPSAoY29uc3QgY2hhciAqKW1lbWNocihw
LCAnOicsIGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29sb24pIHsKICAgICAgc2l6ZV90IGhsZW4g
PSBjb2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnYgPSBjb2xvbiArIDE7CiAgICAgIHdoaWxl
ICh2IDwgbGluZV9lbmQgJiYgKCp2ID09ICcgJyB8fCAqdiA9PSAnXHQnKSkgKyt2OwogICAgICBj
b25zdCBjaGFyICp2ZSA9IGxpbmVfZW5kOwogICAgICB3aGlsZSAodmUgPiB2ICYmICh2ZVstMV0g
PT0gJ1xyJyB8fCB2ZVstMV0gPT0gJ1xuJyB8fCB2ZVstMV0gPT0gJyAnIHx8IHZlWy0xXSA9PSAn
XHQnKSkgLS12ZTsKICAgICAgc2l6ZV90IHZsZW4gPSAoc2l6ZV90KSh2ZSAtIHYpOwoKICAgICAg
aWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxlbmd0aCIsIDE0KSkg
ewogICAgICAgIHNpemVfdCBuID0gMDsKICAgICAgICBpZiAocGFyc2VfZGVjaW1hbF9zaXplKHYs
IHZsZW4sICZuKSkgewogICAgICAgICAgaWYgKCpoYXNfY2xlbiAmJiAqY2xlbiAhPSBuKSB7CiAg
ICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICAgIH0KICAgICAgICAgICpjbGVuID0gbjsK
ICAgICAgICAgICpoYXNfY2xlbiA9IHRydWU7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHJl
dHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAoaGxlbiA9PSAxNyAmJiAhc3Ry
bmNhc2VjbXAocCwgInRyYW5zZmVyLWVuY29kaW5nIiwgMTcpKSB7CiAgICAgICAgc3RkOjpzdHJp
bmcgdGUodiwgdmxlbik7CiAgICAgICAgaWYgKGxvd2VyKHRlKS5maW5kKCJjaHVua2VkIikgIT0g
c3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICppc19jaHVua2VkID0gdHJ1ZTsKICAgICAg
ICB9CiAgICAgIH0gZWxzZSBpZiAoaGxlbiA9PSAxMCAmJiAhc3RybmNhc2VjbXAocCwgImNvbm5l
Y3Rpb24iLCAxMCkpIHsKICAgICAgICBzdGQ6OnN0cmluZyBjb25uKHYsIHZsZW4pOwogICAgICAg
IGlmIChsb3dlcihjb25uKS5maW5kKCJjbG9zZSIpICE9IHN0ZDo6c3RyaW5nOjpucG9zKSB7CiAg
ICAgICAgICBjb25uX2Nsb3NlID0gdHJ1ZTsKICAgICAgICB9IGVsc2UgaWYgKGxvd2VyKGNvbm4p
LmZpbmQoImtlZXAtYWxpdmUiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgY29u
bl9rZWVwX2FsaXZlID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KICAgIH0KICAgIHAgPSBsaW5l
X2VuZCArIDE7CiAgfQogIGlmICgqaGFzX2NsZW4gJiYgKmlzX2NodW5rZWQpIHJldHVybiBmYWxz
ZTsKICBpZiAoaXNfaHR0cF8xMCAmJiAhY29ubl9rZWVwX2FsaXZlKSB7CiAgICAqaXNfY2xvc2Ug
PSB0cnVlOwogIH0gZWxzZSBpZiAoY29ubl9jbG9zZSkgewogICAgKmlzX2Nsb3NlID0gdHJ1ZTsK
ICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyBnX2VuZHBvaW50OwpzdGF0
aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRpYyB1bnNpZ25lZCBnX3NoaXBfcmF0ZV9r
YnBzID0gREVGQVVMVF9TSElQX1JBVEVfS0JQUzsKc3RhdGljIHVuc2lnbmVkIGdfc3RhdHNfaW50
ZXJ2YWxfc2VjID0gMzA7CnN0YXRpYyBzaXplX3QgZ193c3NlX2JvZHlfYnl0ZXMgPSAwOwpzdGF0
aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfY2FwdHVyZV9wYWNrZXRzID0gMCwgZ19jYXB0dXJlX2J5
dGVzID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2tlcm5lbF9kcm9wcyA9IDAsIGdf
aW52YWxpZF9mcmFtZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfZXZlbnRzX2Vt
aXR0ZWQgPSAwLCBnX2V2ZW50c19pbiA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19l
dmVudHNfcHVzaGVkID0gMCwgZ19ldmVudHNfZHJvcHBlZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBs
b25nIGxvbmcgZ19kcm9wX3F1ZXVlID0gMCwgZ19kcm9wX2h1YiA9IDAsIGdfZHJvcF9vdmVyc2l6
ZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfYmF0Y2hlc19wdXNoZWQgPSAwLCBn
X2JhdGNoZXNfZmFpbGVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2J5dGVzX3B1
c2hlZCA9IDAsIGdfc3RhdHNfZHJvcHBlZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcg
Z19vdXRwdXRfcGlwZV9kcm9wcyA9IDAsIGdfcHJldl9vdXRwdXRfcGlwZV9kcm9wcyA9IDA7CnN0
YXRpYyBzaXplX3QgZ19xdWV1ZV9oaWdoX3dhdGVyID0gMDsKc3RhdGljIHVuc2lnbmVkIGdfY29u
c2VjdXRpdmVfZmFpbHVyZXMgPSAwLCBnX2xhc3RfcHVzaF9zdGF0dXMgPSAwOwpzdGF0aWMgdGlt
ZV90IGdfbGFzdF9zdWNjZXNzX2F0ID0gMDsKc3RhdGljIGRvdWJsZSBnX3N0YXRzX2xhc3RfYXQg
PSAwLjAsIGdfc3RhdHNfbGFzdF9jcHUgPSAwLjA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcg
Z19wcmV2X2NhcHR1cmVfcGFja2V0cyA9IDAsIGdfcHJldl9jYXB0dXJlX2J5dGVzID0gMDsKc3Rh
dGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfZXZlbnRzX2VtaXR0ZWQgPSAwLCBnX3ByZXZf
ZXZlbnRzX2luID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfZXZlbnRzX3B1
c2hlZCA9IDAsIGdfcHJldl9ldmVudHNfZHJvcHBlZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25n
IGxvbmcgZ19wcmV2X2JhdGNoZXNfcHVzaGVkID0gMCwgZ19wcmV2X2JhdGNoZXNfZmFpbGVkID0g
MDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfYnl0ZXNfcHVzaGVkID0gMCwgZ19w
cmV2X2Ryb3BfcXVldWUgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9kcm9w
X2h1YiA9IDAsIGdfcHJldl9kcm9wX292ZXJzaXplZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25n
IGxvbmcgZ19zdGF0c19zZXF1ZW5jZSA9IDA7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX2luc3RhbmNl
X2lkOwoKc3RhdGljIHB0aHJlYWRfdCBnX3NoaXBfd29ya2VyX3RpZDsKc3RhdGljIHB0aHJlYWRf
bXV0ZXhfdCBnX3NoaXBfcXVldWVfbXV0ZXggPSBQVEhSRUFEX01VVEVYX0lOSVRJQUxJWkVSOwpz
dGF0aWMgcHRocmVhZF9jb25kX3QgZ19zaGlwX3F1ZXVlX2NvbmQgPSBQVEhSRUFEX0NPTkRfSU5J
VElBTElaRVI7CnN0YXRpYyBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gZ19zaGlwX2J1ZjsKc3Rh
dGljIGJvb2wgZ19zaGlwX3dvcmtlcl9hY3RpdmUgPSBmYWxzZTsKc3RhdGljIGJvb2wgZ19wcm9k
dWNlcl9maW5pc2hlZCA9IGZhbHNlOwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19wZW5kaW5nX3N0YXRz
X2JvZHk7CgpzdGF0aWMgc3RkOjpzdHJpbmcgc2hlbGxxKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7
CiAgc3RkOjpzdHJpbmcgbyA9ICInIjsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgp
OyArK2kpIHsgaWYgKHNbaV0gPT0gJ1wnJykgbyArPSAiJ1xcJyciOyBlbHNlIG8gKz0gc1tpXTsg
fQogIHJldHVybiBvICsgIiciOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1iZXJfc3RyaW5nKHNp
emVfdCBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9
CnN0YXRpYyBzdGQ6OnN0cmluZyB1bGxfc3RyaW5nKHVuc2lnbmVkIGxvbmcgbG9uZyBuKSB7IHN0
ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6
OnN0cmluZyBkb3VibGVfc3RyaW5nKGRvdWJsZSBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBv
LnNldGYoc3RkOjppb3M6OmZpeGVkKTsgby5wcmVjaXNpb24oNCk7IG8gPDwgbjsgcmV0dXJuIG8u
c3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25fYXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8
c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICJbIjsgZm9yIChzaXplX3QgaSA9
IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBvICs9ICIsIjsgbyArPSBhW2ldOyB9IHJl
dHVybiBvICsgIl0iOwp9CnN0YXRpYyBkb3VibGUgd2FsbF9zZWNvbmRzKCkgewogIHN0cnVjdCB0
aW1ldmFsIHR2OwogIGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVybiAoZG91YmxlKXR2
LnR2X3NlYyArIChkb3VibGUpdHYudHZfdXNlYyAvIDEwMDAwMDAuMDsKfQpzdGF0aWMgdm9pZCBw
YWNlX3VwbG9hZChzaXplX3QgYnl0ZXMsIGRvdWJsZSAqbmV4dF9zbG90KSB7CiAgaWYgKCFnX3No
aXBfcmF0ZV9rYnBzKSByZXR1cm47CiAgZG91YmxlIGJ5dGVzX3Blcl9zZWMgPSAoZG91YmxlKWdf
c2hpcF9yYXRlX2ticHMgKiAxMDAwLjAgLyA4LjA7CiAgZG91YmxlIG5vdyA9IHdhbGxfc2Vjb25k
cygpOwogIGlmICgqbmV4dF9zbG90IDwgbm93KSAqbmV4dF9zbG90ID0gbm93OwogIGRvdWJsZSBz
bG90ID0gKm5leHRfc2xvdDsKICAqbmV4dF9zbG90ICs9IChkb3VibGUpYnl0ZXMgLyBieXRlc19w
ZXJfc2VjOwogIHdoaWxlIChzbG90ID4gKG5vdyA9IHdhbGxfc2Vjb25kcygpKSkgewogICAgZG91
YmxlIHJlbWFpbmluZyA9IHNsb3QgLSBub3c7CiAgICB1c2Vjb25kc190IGRlbGF5ID0gKHVzZWNv
bmRzX3QpKHJlbWFpbmluZyA+IDAuNSA/IDUwMDAwMCA6IHJlbWFpbmluZyAqIDEwMDAwMDAuMCk7
CiAgICBpZiAoZGVsYXkpIHVzbGVlcChkZWxheSk7CiAgfQp9CnN0YXRpYyBzaXplX3QgYm91bmRl
ZF9iYXRjaF9jb3VudChjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJ1ZiwKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlKSB7CiAg
c2l6ZV90IHNpemUgPSBzdGQ6OnN0cmluZygie1wibm9kZVwiOiIpLnNpemUoKSArIGpzb25xKG5v
ZGUpLnNpemUoKSArCiAgICAgICAgICAgICAgICBzdGQ6OnN0cmluZygiLFwiZXZlbnRzXCI6W119
Iikuc2l6ZSgpOwogIHNpemVfdCBuID0gMCwgbGltaXQgPSBidWYuc2l6ZSgpIDwgTUFYX0JBVENI
ID8gYnVmLnNpemUoKSA6IE1BWF9CQVRDSDsKICB3aGlsZSAobiA8IGxpbWl0KSB7CiAgICBzaXpl
X3QgZXh0cmEgPSBidWZbbl0uc2l6ZSgpICsgKG4gPyAxIDogMCk7CiAgICBpZiAoZXh0cmEgPiBN
QVhfUE9TVF9CWVRFUyAtIHNpemUpIGJyZWFrOwogICAgc2l6ZSArPSBleHRyYTsKICAgICsrbjsK
ICB9CiAgcmV0dXJuIG47Cn0KCnN0YXRpYyBib29sIHBvc3RfYm9keShjb25zdCBzdGQ6OnN0cmlu
ZyAmZW5kcG9pbnQsIGNvbnN0IHN0ZDo6c3RyaW5nICZwYXRoLAogICAgICAgICAgICAgICAgICAg
ICAgIGNvbnN0IHN0ZDo6c3RyaW5nICZib2R5LCB1bnNpZ25lZCB0aW1lb3V0X3NlYywgZG91Ymxl
ICpuZXh0X3Nsb3QpIHsKICBpZiAobmV4dF9zbG90KSBwYWNlX3VwbG9hZChib2R5LnNpemUoKSwg
bmV4dF9zbG90KTsKICBzdGQ6OnN0cmluZyBjbWQgPSAiY3VybCAtc1NmIC0tbWF4LXRpbWUgIiAr
IG51bWJlcl9zdHJpbmcodGltZW91dF9zZWMpICsgIiAtLWxpbWl0LXJhdGUgIiArCiAgICBudW1i
ZXJfc3RyaW5nKChzaXplX3QpZ19zaGlwX3JhdGVfa2JwcyAqIDEwMDBVIC8gOFUpICsKICAgICIg
LW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1i
aW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCArIHBhdGgpOwogIEZJTEUgKmZwID0gcG9wZW4o
Y21kLmNfc3RyKCksICJ3Iik7IGlmICghZnApIHJldHVybiBmYWxzZTsKICBmd3JpdGUoYm9keS5k
YXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAgaW50IHJjID0gcGNsb3NlKGZwKTsKICByZXR1
cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRVUyhyYykgPT0gMDsKfQoKc3RhdGljIHZvaWQg
KnNoaXBfd29ya2VyX3RocmVhZCh2b2lkICopIHsKICBkb3VibGUgbmV4dF9zbG90ID0gd2FsbF9z
ZWNvbmRzKCk7CiAgZG91YmxlIG5leHRfc3RhdHNfc2xvdCA9IHdhbGxfc2Vjb25kcygpOwogIGRv
dWJsZSBzaHV0ZG93bl9kZWFkbGluZSA9IDAuMDsKICB3aGlsZSAodHJ1ZSkgewogICAgc3RkOjp2
ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoOwogICAgc3RkOjpzdHJpbmcgc3RhdHNfYm9keTsKICAg
IHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgIHdoaWxlIChnX3J1
bm5pbmcgJiYgIWdfcHJvZHVjZXJfZmluaXNoZWQgJiYgZ19zaGlwX2J1Zi5lbXB0eSgpICYmIGdf
cGVuZGluZ19zdGF0c19ib2R5LmVtcHR5KCkpIHsKICAgICAgc3RydWN0IHRpbWVzcGVjIHRzOwog
ICAgICBjbG9ja19nZXR0aW1lKENMT0NLX1JFQUxUSU1FLCAmdHMpOwogICAgICB0cy50dl9zZWMg
Kz0gMTsKICAgICAgcHRocmVhZF9jb25kX3RpbWVkd2FpdCgmZ19zaGlwX3F1ZXVlX2NvbmQsICZn
X3NoaXBfcXVldWVfbXV0ZXgsICZ0cyk7CiAgICB9CiAgICBpZiAoIWdfcnVubmluZyAmJiBzaHV0
ZG93bl9kZWFkbGluZSA9PSAwLjApIHsKICAgICAgc2h1dGRvd25fZGVhZGxpbmUgPSB3YWxsX3Nl
Y29uZHMoKSArIDEwLjA7CiAgICB9CiAgICBpZiAoZ19wcm9kdWNlcl9maW5pc2hlZCAmJiBnX3No
aXBfYnVmLmVtcHR5KCkgJiYgZ19wZW5kaW5nX3N0YXRzX2JvZHkuZW1wdHkoKSkgewogICAgICBw
dGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgYnJlYWs7CiAg
ICB9CiAgICBpZiAoc2h1dGRvd25fZGVhZGxpbmUgPiAwLjAgJiYgd2FsbF9zZWNvbmRzKCkgPiBz
aHV0ZG93bl9kZWFkbGluZSkgewogICAgICBnX2V2ZW50c19kcm9wcGVkICs9IGdfc2hpcF9idWYu
c2l6ZSgpOwogICAgICBnX2Ryb3BfaHViICs9IGdfc2hpcF9idWYuc2l6ZSgpOwogICAgICBnX3No
aXBfYnVmLmNsZWFyKCk7CiAgICAgIGdfcGVuZGluZ19zdGF0c19ib2R5LmNsZWFyKCk7CiAgICAg
IHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICBicmVhazsK
ICAgIH0KICAgIGlmICghZ19wZW5kaW5nX3N0YXRzX2JvZHkuZW1wdHkoKSkgewogICAgICBzdGF0
c19ib2R5LnN3YXAoZ19wZW5kaW5nX3N0YXRzX2JvZHkpOwogICAgfQogICAgaWYgKCFnX3NoaXBf
YnVmLmVtcHR5KCkpIHsKICAgICAgc2l6ZV90IG4gPSBib3VuZGVkX2JhdGNoX2NvdW50KGdfc2hp
cF9idWYsIGdfc2hpcF9ub2RlKTsKICAgICAgaWYgKCFuKSB7CiAgICAgICAgZ19zaGlwX2J1Zi5l
cmFzZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgICAgICsrZ19ldmVudHNfZHJvcHBlZDsKICAg
ICAgICArK2dfZHJvcF9vdmVyc2l6ZWQ7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgYmF0Y2guYXNz
aWduKGdfc2hpcF9idWYuYmVnaW4oKSwgZ19zaGlwX2J1Zi5iZWdpbigpICsgbik7CiAgICAgICAg
Z19zaGlwX2J1Zi5lcmFzZShnX3NoaXBfYnVmLmJlZ2luKCksIGdfc2hpcF9idWYuYmVnaW4oKSAr
IG4pOwogICAgICB9CiAgICB9CiAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVl
X211dGV4KTsKCiAgICBpZiAoIXN0YXRzX2JvZHkuZW1wdHkoKSkgewogICAgICBpZiAoIXBvc3Rf
Ym9keShnX2VuZHBvaW50LCAiL2FwaS9hZ2VudC9zdGF0cyIsIHN0YXRzX2JvZHksIDIsICZuZXh0
X3N0YXRzX3Nsb3QpKSB7CiAgICAgICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVf
bXV0ZXgpOwogICAgICAgICsrZ19zdGF0c19kcm9wcGVkOwogICAgICAgIHB0aHJlYWRfbXV0ZXhf
dW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICB9CiAgICB9CgogICAgaWYgKCFiYXRj
aC5lbXB0eSgpKSB7CiAgICAgIHN0ZDo6c3RyaW5nIGJvZHkgPSAie1wibm9kZVwiOiIgKyBqc29u
cShnX3NoaXBfbm9kZSkgKyAiLFwiZXZlbnRzXCI6IiArIGpzb25fYXJyYXkoYmF0Y2gpICsgIn0i
OwogICAgICBpZiAocG9zdF9ib2R5KGdfZW5kcG9pbnQsICIvYXBpL2luZ2VzdCIsIGJvZHksIDEw
LCAmbmV4dF9zbG90KSkgewogICAgICAgIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVl
X211dGV4KTsKICAgICAgICBnX2V2ZW50c19wdXNoZWQgKz0gYmF0Y2guc2l6ZSgpOwogICAgICAg
ICsrZ19iYXRjaGVzX3B1c2hlZDsKICAgICAgICBnX2J5dGVzX3B1c2hlZCArPSBib2R5LnNpemUo
KTsKICAgICAgICBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzID0gMDsKICAgICAgICBnX2xhc3RfcHVz
aF9zdGF0dXMgPSAyMDA7CiAgICAgICAgZ19sYXN0X3N1Y2Nlc3NfYXQgPSB0aW1lKE5VTEwpOwog
ICAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICB9
IGVsc2UgewogICAgICAgIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsK
ICAgICAgICBnX2V2ZW50c19kcm9wcGVkICs9IGJhdGNoLnNpemUoKTsKICAgICAgICBnX2Ryb3Bf
aHViICs9IGJhdGNoLnNpemUoKTsKICAgICAgICArK2dfYmF0Y2hlc19mYWlsZWQ7CiAgICAgICAg
KytnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzOwogICAgICAgIGdfbGFzdF9wdXNoX3N0YXR1cyA9IDA7
CiAgICAgICAgaWYgKHNodXRkb3duX2RlYWRsaW5lID4gMC4wICYmIGdfY29uc2VjdXRpdmVfZmFp
bHVyZXMgPj0gMykgewogICAgICAgICAgZ19ldmVudHNfZHJvcHBlZCArPSBnX3NoaXBfYnVmLnNp
emUoKTsKICAgICAgICAgIGdfZHJvcF9odWIgKz0gZ19zaGlwX2J1Zi5zaXplKCk7CiAgICAgICAg
ICBnX3NoaXBfYnVmLmNsZWFyKCk7CiAgICAgICAgICBnX3BlbmRpbmdfc3RhdHNfYm9keS5jbGVh
cigpOwogICAgICAgICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICAgICAgcHRocmVhZF9tdXRleF91bmxvY2so
Jmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgIH0KICAgIH0KICB9CiAgcmV0dXJuIE5VTEw7Cn0K
CnN0YXRpYyB1bnNpZ25lZCBjb3VudF9vcGVuX2ZkcygpIHsKICBESVIgKmRpciA9IG9wZW5kaXIo
Ii9wcm9jL3NlbGYvZmQiKTsKICBpZiAoIWRpcikgcmV0dXJuIDA7CiAgdW5zaWduZWQgY291bnQg
PSAwOwogIHN0cnVjdCBkaXJlbnQgKmVudHJ5OwogIHdoaWxlICgoZW50cnkgPSByZWFkZGlyKGRp
cikpICE9IE5VTEwpIHsKICAgIGlmIChzdHJjbXAoZW50cnktPmRfbmFtZSwgIi4iKSAmJiBzdHJj
bXAoZW50cnktPmRfbmFtZSwgIi4uIikpICsrY291bnQ7CiAgfQogIGNsb3NlZGlyKGRpcik7CiAg
cmV0dXJuIGNvdW50Owp9CgpzdGF0aWMgdm9pZCBwcm9jX3N0YXR1cyhzaXplX3QgKnJzcywgc2l6
ZV90ICp2aXJ0LCB1bnNpZ25lZCAqdGhyZWFkcywKICAgICAgICAgICAgICAgICAgICAgICAgdW5z
aWduZWQgKmNwdV9jb3JlKSB7CiAgKnJzcyA9IDA7ICp2aXJ0ID0gMDsgKnRocmVhZHMgPSAxOyAq
Y3B1X2NvcmUgPSAwOwogIHN0ZDo6aWZzdHJlYW0gaW4oIi9wcm9jL3NlbGYvc3RhdHVzIik7CiAg
c3RkOjpzdHJpbmcgbGluZTsKICB3aGlsZSAoc3RkOjpnZXRsaW5lKGluLCBsaW5lKSkgewogICAg
dW5zaWduZWQgbG9uZyB2YWx1ZSA9IDA7CiAgICBpZiAoc3NjYW5mKGxpbmUuY19zdHIoKSwgIlZt
UlNTOiAlbHUga0IiLCAmdmFsdWUpID09IDEpICpyc3MgPSAoc2l6ZV90KXZhbHVlICogMTAyNFU7
CiAgICBlbHNlIGlmIChzc2NhbmYobGluZS5jX3N0cigpLCAiVm1TaXplOiAlbHUga0IiLCAmdmFs
dWUpID09IDEpICp2aXJ0ID0gKHNpemVfdCl2YWx1ZSAqIDEwMjRVOwogICAgZWxzZSBpZiAoc3Nj
YW5mKGxpbmUuY19zdHIoKSwgIlRocmVhZHM6ICVsdSIsICZ2YWx1ZSkgPT0gMSkgKnRocmVhZHMg
PSAodW5zaWduZWQpdmFsdWU7CiAgICBlbHNlIGlmIChzc2NhbmYobGluZS5jX3N0cigpLCAiQ3B1
c19hbGxvd2VkX2xpc3Q6ICVsdSIsICZ2YWx1ZSkgPT0gMSkgKmNwdV9jb3JlID0gKHVuc2lnbmVk
KXZhbHVlOwogIH0KfQoKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyB1cGRhdGVfa2VybmVsX2Ry
b3BzKGludCBmZCkgewogIGlmIChmZCA8IDApIHJldHVybiAwOwogIHN0cnVjdCB0cGFja2V0X3N0
YXRzIHBhY2tldF9zdGF0czsKICBzb2NrbGVuX3QgcGFja2V0X3N0YXRzX2xlbiA9IHNpemVvZihw
YWNrZXRfc3RhdHMpOwogIG1lbXNldCgmcGFja2V0X3N0YXRzLCAwLCBzaXplb2YocGFja2V0X3N0
YXRzKSk7CiAgaWYgKGdldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9TVEFUSVNUSUNT
LAogICAgICAgICAgICAgICAgICZwYWNrZXRfc3RhdHMsICZwYWNrZXRfc3RhdHNfbGVuKSAhPSAw
KSByZXR1cm4gMDsKICBnX2tlcm5lbF9kcm9wcyArPSBwYWNrZXRfc3RhdHMudHBfZHJvcHM7CiAg
cmV0dXJuIHBhY2tldF9zdGF0cy50cF9kcm9wczsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIGFnZW50
X3N0YXRzX2JvZHkoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0aXZlLAogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBzaXplX3QgcGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90IHdzc2VfYm9keV9mbG93cykgewogIGRvdWJs
ZSBub3cgPSB3YWxsX3NlY29uZHMoKTsKICBkb3VibGUgZWxhcHNlZCA9IG5vdyAtIGdfc3RhdHNf
bGFzdF9hdDsKICBpZiAoZWxhcHNlZCA8IDAuMDAxKSBlbGFwc2VkID0gMC4wMDE7CiAgdW5zaWdu
ZWQgbG9uZyBsb25nIGtlcm5lbF9kcm9wX2RlbHRhID0gdXBkYXRlX2tlcm5lbF9kcm9wcyhmZCk7
CiAgdW5zaWduZWQgbG9uZyBsb25nIHBhY2tldF9kZWx0YSA9IGdfY2FwdHVyZV9wYWNrZXRzIC0g
Z19wcmV2X2NhcHR1cmVfcGFja2V0czsKICB1bnNpZ25lZCBsb25nIGxvbmcgcGFja2V0X2J5dGVz
X2RlbHRhID0gZ19jYXB0dXJlX2J5dGVzIC0gZ19wcmV2X2NhcHR1cmVfYnl0ZXM7CiAgdW5zaWdu
ZWQgbG9uZyBsb25nIGVtaXR0ZWRfZGVsdGEgPSBnX2V2ZW50c19lbWl0dGVkIC0gZ19wcmV2X2V2
ZW50c19lbWl0dGVkOwoKICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CiAgdW5zaWduZWQgbG9uZyBsb25nIGluX2RlbHRhID0gZ19ldmVudHNfaW4gLSBnX3ByZXZfZXZl
bnRzX2luOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBwdXNoZWRfZGVsdGEgPSBnX2V2ZW50c19wdXNo
ZWQgLSBnX3ByZXZfZXZlbnRzX3B1c2hlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgZHJvcHBlZF9k
ZWx0YSA9IGdfZXZlbnRzX2Ryb3BwZWQgLSBnX3ByZXZfZXZlbnRzX2Ryb3BwZWQ7CiAgdW5zaWdu
ZWQgbG9uZyBsb25nIGJhdGNoZXNfcHVzaGVkX2RlbHRhID0gZ19iYXRjaGVzX3B1c2hlZCAtIGdf
cHJldl9iYXRjaGVzX3B1c2hlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgYmF0Y2hlc19mYWlsZWRf
ZGVsdGEgPSBnX2JhdGNoZXNfZmFpbGVkIC0gZ19wcmV2X2JhdGNoZXNfZmFpbGVkOwogIHVuc2ln
bmVkIGxvbmcgbG9uZyBieXRlc19kZWx0YSA9IGdfYnl0ZXNfcHVzaGVkIC0gZ19wcmV2X2J5dGVz
X3B1c2hlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgcXVldWVfZGVsdGEgPSBnX2Ryb3BfcXVldWUg
LSBnX3ByZXZfZHJvcF9xdWV1ZTsKICB1bnNpZ25lZCBsb25nIGxvbmcgaHViX2RlbHRhID0gZ19k
cm9wX2h1YiAtIGdfcHJldl9kcm9wX2h1YjsKICB1bnNpZ25lZCBsb25nIGxvbmcgb3ZlcnNpemVk
X2RlbHRhID0gZ19kcm9wX292ZXJzaXplZCAtIGdfcHJldl9kcm9wX292ZXJzaXplZDsKICBzaXpl
X3Qgc2hpcF9idWZfc2l6ZSA9IGdfc2hpcF9idWYuc2l6ZSgpOwogIHNpemVfdCBxdWV1ZV9oaWdo
ID0gZ19xdWV1ZV9oaWdoX3dhdGVyOwogIHVuc2lnbmVkIGxhc3Rfc3RhdHVzID0gZ19sYXN0X3B1
c2hfc3RhdHVzOwogIHRpbWVfdCBsYXN0X3N1Y2MgPSBnX2xhc3Rfc3VjY2Vzc19hdDsKICB1bnNp
Z25lZCBjb25zZWNfZmFpbHMgPSBnX2NvbnNlY3V0aXZlX2ZhaWx1cmVzOwogIHVuc2lnbmVkIGxv
bmcgbG9uZyBzdGF0c19kcm9wID0gZ19zdGF0c19kcm9wcGVkOwogIHB0aHJlYWRfbXV0ZXhfdW5s
b2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwoKICB1bnNpZ25lZCBsb25nIGxvbmcgcGlwZV9kcm9w
X2RlbHRhID0gZ19vdXRwdXRfcGlwZV9kcm9wcyAtIGdfcHJldl9vdXRwdXRfcGlwZV9kcm9wczsK
ICBzdHJ1Y3QgcnVzYWdlIHVzYWdlOwogIG1lbXNldCgmdXNhZ2UsIDAsIHNpemVvZih1c2FnZSkp
OwogIGdldHJ1c2FnZShSVVNBR0VfU0VMRiwgJnVzYWdlKTsKICBkb3VibGUgdXNlcl9jcHUgPSB1
c2FnZS5ydV91dGltZS50dl9zZWMgKyB1c2FnZS5ydV91dGltZS50dl91c2VjIC8gMTAwMDAwMC4w
OwogIGRvdWJsZSBzeXNfY3B1ID0gdXNhZ2UucnVfc3RpbWUudHZfc2VjICsgdXNhZ2UucnVfc3Rp
bWUudHZfdXNlYyAvIDEwMDAwMDAuMDsKICBkb3VibGUgY3B1X3RvdGFsID0gdXNlcl9jcHUgKyBz
eXNfY3B1OwogIGRvdWJsZSBjcHVfcGN0ID0gMTAwLjAgKiAoY3B1X3RvdGFsIC0gZ19zdGF0c19s
YXN0X2NwdSkgLyBlbGFwc2VkOwogIGlmIChjcHVfcGN0IDwgMCkgY3B1X3BjdCA9IDA7CiAgc2l6
ZV90IHJzcyA9IDAsIHZpcnQgPSAwOwogIHVuc2lnbmVkIHRocmVhZHMgPSAxLCBjcHVfY29yZSA9
IDA7CiAgcHJvY19zdGF0dXMoJnJzcywgJnZpcnQsICZ0aHJlYWRzLCAmY3B1X2NvcmUpOwogIHN0
ZDo6c3RyaW5nIHJlYXNvbnM7CiAgaWYgKGtlcm5lbF9kcm9wX2RlbHRhKSByZWFzb25zICs9ICJc
Imtlcm5lbF9kcm9wXCIiOwogIGlmIChkcm9wcGVkX2RlbHRhKSB7IGlmICghcmVhc29ucy5lbXB0
eSgpKSByZWFzb25zICs9ICIsIjsgcmVhc29ucyArPSAiXCJzaGlwX2Ryb3BcIiI7IH0KICBpZiAo
aHViX2RlbHRhKSB7IGlmICghcmVhc29ucy5lbXB0eSgpKSByZWFzb25zICs9ICIsIjsgcmVhc29u
cyArPSAiXCJodWJfdW5yZWFjaGFibGVcIiI7IH0KICBpZiAocXVldWVfZGVsdGEgfHwgcGlwZV9k
cm9wX2RlbHRhKSB7IGlmICghcmVhc29ucy5lbXB0eSgpKSByZWFzb25zICs9ICIsIjsgcmVhc29u
cyArPSAiXCJxdWV1ZV9wcmVzc3VyZVwiIjsgfQogIHN0ZDo6b3N0cmluZ3N0cmVhbSBvdXQ7CiAg
b3V0IDw8ICJ7XCJzY2hlbWFfdmVyc2lvblwiOjEsXCJ0eXBlXCI6XCJhZ2VudF9zdGF0c1wiLFwi
bm9kZVwiOiIgPDwganNvbnEoZ19zaGlwX25vZGUpCiAgICAgIDw8ICIsXCJpbnN0YW5jZV9pZFwi
OiIgPDwganNvbnEoZ19pbnN0YW5jZV9pZCkgPDwgIixcInNlcXVlbmNlXCI6IiA8PCArK2dfc3Rh
dHNfc2VxdWVuY2UKICAgICAgPDwgIixcIm9ic2VydmVkX2F0XCI6IiA8PCAodW5zaWduZWQgbG9u
Zylub3cgPDwgIixcIndpbmRvd19zZWNvbmRzXCI6IiA8PCBkb3VibGVfc3RyaW5nKGVsYXBzZWQp
CiAgICAgIDw8ICIsXCJtb2RlXCI6XCJjcHBcIixcInN0YXR1c1wiOiIgPDwgKHJlYXNvbnMuZW1w
dHkoKSA/ICJcIm9rXCIiIDogIlwiZGVncmFkZWRcIiIpCiAgICAgIDw8ICIsXCJyZWFzb25zXCI6
WyIgPDwgcmVhc29ucyA8PCAiXSxcImNhcHR1cmVcIjp7IgogICAgICA8PCAiXCJwYWNrZXRzX3Rv
dGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfY2FwdHVyZV9wYWNrZXRzKSA8PCAiLFwicGFja2V0c19k
ZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwYWNrZXRfZGVsdGEpCiAgICAgIDw8ICIsXCJwYWNrZXRf
Ynl0ZXNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19jYXB0dXJlX2J5dGVzKSA8PCAiLFwicGFj
a2V0X2J5dGVzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHBhY2tldF9ieXRlc19kZWx0YSkKICAg
ICAgPDwgIixcImtlcm5lbF9kcm9wc190b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2tlcm5lbF9k
cm9wcykgPDwgIixcImtlcm5lbF9kcm9wc19kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhrZXJuZWxf
ZHJvcF9kZWx0YSkKICAgICAgPDwgIixcImtlcm5lbF9kcm9wX3BlcmNlbnRcIjoiIDw8IGRvdWJs
ZV9zdHJpbmcoMTAwLjAgKiBrZXJuZWxfZHJvcF9kZWx0YSAvIChwYWNrZXRfZGVsdGEgPyBwYWNr
ZXRfZGVsdGEgOiAxKSkKICAgICAgPDwgIixcImludmFsaWRfZnJhbWVzX3RvdGFsXCI6IiA8PCB1
bGxfc3RyaW5nKGdfaW52YWxpZF9mcmFtZXMpCiAgICAgIDw8ICIsXCJldmVudHNfZW1pdHRlZF90
b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19lbWl0dGVkKSA8PCAiLFwiZXZlbnRzX2Vt
aXR0ZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoZW1pdHRlZF9kZWx0YSkKICAgICAgPDwgIixc
ImZsb3dzX2FjdGl2ZVwiOiIgPDwgZmxvd3NfYWN0aXZlIDw8ICIsXCJwZW5kaW5nX3JlcXVlc3Rz
XCI6IiA8PCBwZW5kaW5nX3JlcXVlc3RzCiAgICAgIDw8ICIsXCJ3c3NlX2JvZHlfZmxvd3NfYWN0
aXZlXCI6IiA8PCB3c3NlX2JvZHlfZmxvd3MKICAgICAgPDwgIixcIndzc2VfYm9keV9ieXRlc1wi
OiIgPDwgZ193c3NlX2JvZHlfYnl0ZXMKICAgICAgPDwgIixcIm91dHB1dF9waXBlX2Ryb3BzX3Rv
dGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfb3V0cHV0X3BpcGVfZHJvcHMpCiAgICAgIDw8ICIsXCJv
dXRwdXRfcGlwZV9kcm9wc19kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwaXBlX2Ryb3BfZGVsdGEp
IDw8ICJ9LFwic2hpcHBpbmdcIjp7IgogICAgICA8PCAiXCJldmVudHNfaW5fdG90YWxcIjoiIDw8
IHVsbF9zdHJpbmcoZ19ldmVudHNfaW4pIDw8ICIsXCJldmVudHNfaW5fZGVsdGFcIjoiIDw8IHVs
bF9zdHJpbmcoaW5fZGVsdGEpCiAgICAgIDw8ICIsXCJldmVudHNfcHVzaGVkX3RvdGFsXCI6IiA8
PCB1bGxfc3RyaW5nKGdfZXZlbnRzX3B1c2hlZCkgPDwgIixcImV2ZW50c19wdXNoZWRfZGVsdGFc
IjoiIDw8IHVsbF9zdHJpbmcocHVzaGVkX2RlbHRhKQogICAgICA8PCAiLFwiZXZlbnRzX2Ryb3Bw
ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVudHNfZHJvcHBlZCkgPDwgIixcImV2ZW50
c19kcm9wcGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGRyb3BwZWRfZGVsdGEpCiAgICAgIDw8
ICIsXCJkcm9wX2NhdXNlc1wiOntcInF1ZXVlX2Z1bGxfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmco
Z19kcm9wX3F1ZXVlKSA8PCAiLFwicXVldWVfZnVsbF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhx
dWV1ZV9kZWx0YSkKICAgICAgPDwgIixcImh1Yl9mYWlsdXJlX3RvdGFsXCI6IiA8PCB1bGxfc3Ry
aW5nKGdfZHJvcF9odWIpIDw8ICIsXCJodWJfZmFpbHVyZV9kZWx0YVwiOiIgPDwgdWxsX3N0cmlu
ZyhodWJfZGVsdGEpCiAgICAgIDw8ICIsXCJvdmVyc2l6ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJp
bmcoZ19kcm9wX292ZXJzaXplZCkgPDwgIixcIm92ZXJzaXplZF9kZWx0YVwiOiIgPDwgdWxsX3N0
cmluZyhvdmVyc2l6ZWRfZGVsdGEpIDw8ICJ9IgogICAgICA8PCAiLFwiYmF0Y2hlc19wdXNoZWRf
dG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19iYXRjaGVzX3B1c2hlZCkgPDwgIixcImJhdGNoZXNf
cHVzaGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGJhdGNoZXNfcHVzaGVkX2RlbHRhKQogICAg
ICA8PCAiLFwiYmF0Y2hlc19mYWlsZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19iYXRjaGVz
X2ZhaWxlZCkgPDwgIixcImJhdGNoZXNfZmFpbGVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGJh
dGNoZXNfZmFpbGVkX2RlbHRhKQogICAgICA8PCAiLFwiYnl0ZXNfcHVzaGVkX3RvdGFsXCI6IiA8
PCB1bGxfc3RyaW5nKGdfYnl0ZXNfcHVzaGVkKSA8PCAiLFwiYnl0ZXNfcHVzaGVkX2RlbHRhXCI6
IiA8PCB1bGxfc3RyaW5nKGJ5dGVzX2RlbHRhKQogICAgICA8PCAiLFwicHVzaF9ldmVudHNfcGVy
X3NlY29uZFwiOiIgPDwgZG91YmxlX3N0cmluZyhwdXNoZWRfZGVsdGEgLyBlbGFwc2VkKQogICAg
ICA8PCAiLFwicHVzaF9rYnBzXCI6IiA8PCBkb3VibGVfc3RyaW5nKDguMCAqIGJ5dGVzX2RlbHRh
IC8gKDEwMDAuMCAqIGVsYXBzZWQpKQogICAgICA8PCAiLFwiZHJvcF9ldmVudHNfcGVyX3NlY29u
ZFwiOiIgPDwgZG91YmxlX3N0cmluZyhkcm9wcGVkX2RlbHRhIC8gZWxhcHNlZCkKICAgICAgPDwg
IixcImRyb3BfcGVyY2VudFwiOiIgPDwgZG91YmxlX3N0cmluZygxMDAuMCAqIGRyb3BwZWRfZGVs
dGEgLyAoaW5fZGVsdGEgPyBpbl9kZWx0YSA6IDEpKQogICAgICA8PCAiLFwicXVldWVfZGVwdGhf
ZXZlbnRzXCI6IiA8PCBzaGlwX2J1Zl9zaXplIDw8ICIsXCJxdWV1ZV9jYXBhY2l0eV9ldmVudHNc
IjoiIDw8IE1BWF9RVUVVRQogICAgICA8PCAiLFwicXVldWVfaGlnaF93YXRlcl9ldmVudHNcIjoi
IDw8IHF1ZXVlX2hpZ2ggPDwgIixcImxhc3RfcHVzaF9odHRwX3N0YXR1c1wiOiIgPDwgbGFzdF9z
dGF0dXMKICAgICAgPDwgIixcImxhc3Rfc3VjY2Vzc19hdFwiOiIgPDwgKHVuc2lnbmVkIGxvbmcp
bGFzdF9zdWNjIDw8ICIsXCJjb25zZWN1dGl2ZV9mYWlsdXJlc1wiOiIgPDwgY29uc2VjX2ZhaWxz
CiAgICAgIDw8ICIsXCJzdGF0c19zYW1wbGVzX2Ryb3BwZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJp
bmcoc3RhdHNfZHJvcCkgPDwgIn0sXCJyZXNvdXJjZXNcIjp7IgogICAgICA8PCAiXCJjcHVfdXNl
cl9zZWNvbmRzXCI6IiA8PCBkb3VibGVfc3RyaW5nKHVzZXJfY3B1KSA8PCAiLFwiY3B1X3N5c3Rl
bV9zZWNvbmRzXCI6IiA8PCBkb3VibGVfc3RyaW5nKHN5c19jcHUpCiAgICAgIDw8ICIsXCJjcHVf
cGVyY2VudF9vbmVfY29yZVwiOiIgPDwgZG91YmxlX3N0cmluZyhjcHVfcGN0KSA8PCAiLFwicnNz
X2J5dGVzXCI6IiA8PCByc3MKICAgICAgPDwgIixcInZpcnR1YWxfYnl0ZXNcIjoiIDw8IHZpcnQg
PDwgIixcIm9wZW5fZmRzXCI6IiA8PCBjb3VudF9vcGVuX2ZkcygpIDw8ICIsXCJ0aHJlYWRzXCI6
IiA8PCB0aHJlYWRzCiAgICAgIDw8ICJ9LFwibGltaXRzXCI6e1wiY3B1X2NvcmVcIjoiIDw8IGNw
dV9jb3JlIDw8ICIsXCJhZGRyZXNzX3NwYWNlX2J5dGVzXCI6MjY4NDM1NDU2IgogICAgICA8PCAi
LFwic2hpcF9yYXRlX2ticHNcIjoiIDw8IGdfc2hpcF9yYXRlX2ticHMgPDwgIixcImh0dHBfYm9k
eV9tYXhfYnl0ZXNcIjoiIDw8IE1BWF9QT1NUX0JZVEVTCiAgICAgIDw8ICIsXCJzaGlwX3RocmVh
ZHNfbWF4XCI6MSxcIndzc2VfYm9keV9ieXRlc1wiOiIgPDwgZ193c3NlX2JvZHlfYnl0ZXMgPDwg
In19IjsKICBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzID0gZ19jYXB0dXJlX3BhY2tldHM7IGdfcHJl
dl9jYXB0dXJlX2J5dGVzID0gZ19jYXB0dXJlX2J5dGVzOwogIGdfcHJldl9ldmVudHNfZW1pdHRl
ZCA9IGdfZXZlbnRzX2VtaXR0ZWQ7CiAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVf
bXV0ZXgpOwogIGdfcHJldl9ldmVudHNfaW4gPSBnX2V2ZW50c19pbjsKICBnX3ByZXZfZXZlbnRz
X3B1c2hlZCA9IGdfZXZlbnRzX3B1c2hlZDsgZ19wcmV2X2V2ZW50c19kcm9wcGVkID0gZ19ldmVu
dHNfZHJvcHBlZDsKICBnX3ByZXZfYmF0Y2hlc19wdXNoZWQgPSBnX2JhdGNoZXNfcHVzaGVkOyBn
X3ByZXZfYmF0Y2hlc19mYWlsZWQgPSBnX2JhdGNoZXNfZmFpbGVkOwogIGdfcHJldl9ieXRlc19w
dXNoZWQgPSBnX2J5dGVzX3B1c2hlZDsgZ19wcmV2X2Ryb3BfcXVldWUgPSBnX2Ryb3BfcXVldWU7
CiAgZ19wcmV2X2Ryb3BfaHViID0gZ19kcm9wX2h1YjsgZ19wcmV2X2Ryb3Bfb3ZlcnNpemVkID0g
Z19kcm9wX292ZXJzaXplZDsKICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211
dGV4KTsKICBnX3ByZXZfb3V0cHV0X3BpcGVfZHJvcHMgPSBnX291dHB1dF9waXBlX2Ryb3BzOwog
IGdfc3RhdHNfbGFzdF9jcHUgPSBjcHVfdG90YWw7IGdfc3RhdHNfbGFzdF9hdCA9IG5vdzsKICBy
ZXR1cm4gb3V0LnN0cigpOwp9CgpzdGF0aWMgdm9pZCBzZW5kX2FnZW50X3N0YXRzKGludCBmZCwg
c2l6ZV90IGZsb3dzX2FjdGl2ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3Qg
cGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3Qgd3Nz
ZV9ib2R5X2Zsb3dzKSB7CiAgc3RkOjpzdHJpbmcgYm9keSA9IGFnZW50X3N0YXRzX2JvZHkoZmQs
IGZsb3dzX2FjdGl2ZSwgcGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICB3c3NlX2JvZHlfZmxvd3MpOwogIGlmIChib2R5LnNpemUoKSA+IE1BWF9T
VEFUU19CWVRFUykgewogICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgp
OwogICAgKytnX3N0YXRzX2Ryb3BwZWQ7CiAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlw
X3F1ZXVlX211dGV4KTsKICAgIHJldHVybjsKICB9CiAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3No
aXBfcXVldWVfbXV0ZXgpOwogIGdfcGVuZGluZ19zdGF0c19ib2R5ID0gYm9keTsKICBwdGhyZWFk
X2NvbmRfc2lnbmFsKCZnX3NoaXBfcXVldWVfY29uZCk7CiAgcHRocmVhZF9tdXRleF91bmxvY2so
Jmdfc2hpcF9xdWV1ZV9tdXRleCk7Cn0KCnN0YXRpYyBib29sIHdyaXRlX25vbmJsb2NraW5nX2xp
bmUoY29uc3Qgc3RkOjpzdHJpbmcgJmxpbmUpIHsKICBpZiAobGluZS5zaXplKCkgKyAxID4gUElQ
RV9CVUYpIHsKICAgICsrZ19vdXRwdXRfcGlwZV9kcm9wczsKICAgIHJldHVybiB0cnVlOwogIH0K
ICBzdGQ6OnN0cmluZyBmcmFtZWQgPSBsaW5lICsgIlxuIjsKICBzc2l6ZV90IHdyaXR0ZW47CiAg
ZG8geyB3cml0dGVuID0gd3JpdGUoU1RET1VUX0ZJTEVOTywgZnJhbWVkLmRhdGEoKSwgZnJhbWVk
LnNpemUoKSk7IH0KICB3aGlsZSAod3JpdHRlbiA8IDAgJiYgZXJybm8gPT0gRUlOVFIgJiYgZ19y
dW5uaW5nKTsKICBpZiAod3JpdHRlbiA9PSAoc3NpemVfdClmcmFtZWQuc2l6ZSgpKSByZXR1cm4g
dHJ1ZTsKICBpZiAod3JpdHRlbiA8IDAgJiYgKGVycm5vID09IEVBR0FJTiB8fCBlcnJubyA9PSBF
V09VTERCTE9DSykpIHsKICAgICsrZ19vdXRwdXRfcGlwZV9kcm9wczsKICAgIHJldHVybiB0cnVl
OwogIH0KICBpZiAod3JpdHRlbiA8IDAgJiYgZXJybm8gPT0gRVBJUEUpIHsKICAgIGxvZ21zZygi
c2hpcHBlciBwaXBlIGNsb3NlZDsgc3RvcHBpbmcgY2FwdHVyZSBmb3Igc3VwZXJ2aXNlZCByZXN0
YXJ0Iik7CiAgfSBlbHNlIHsKICAgIGxvZ21zZygic2hpcHBlciBwaXBlIHdyaXRlIGZhaWxlZDsg
c3RvcHBpbmcgY2FwdHVyZSBmb3Igc3VwZXJ2aXNlZCByZXN0YXJ0Iik7CiAgfQogIGdfcnVubmlu
ZyA9IDA7CiAgcmV0dXJuIGZhbHNlOwp9CgpzdGF0aWMgdm9pZCBlbWl0X2NhcHR1cmVfc3RhdHNf
aW50ZXJuYWwoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0aXZlLAogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgc2l6ZV90IHBlbmRpbmdfcmVxdWVzdHMsCiAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3Qgd3NzZV9ib2R5X2Zsb3dzKSB7CiAg
c3RkOjpzdHJpbmcgZnVsbCA9IGFnZW50X3N0YXRzX2JvZHkoZmQsIGZsb3dzX2FjdGl2ZSwgcGVu
ZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3c3Nl
X2JvZHlfZmxvd3MpOwogIGNvbnN0IHN0ZDo6c3RyaW5nIG1hcmtlciA9ICJcImNhcHR1cmVcIjoi
OwogIHNpemVfdCBzdGFydCA9IGZ1bGwuZmluZChtYXJrZXIpOwogIHNpemVfdCBlbmQgPSBmdWxs
LmZpbmQoIixcInNoaXBwaW5nXCI6Iiwgc3RhcnQpOwogIGlmIChzdGFydCA9PSBzdGQ6OnN0cmlu
Zzo6bnBvcyB8fCBlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICsrZ19vdXRwdXRfcGlw
ZV9kcm9wczsKICAgIHJldHVybjsKICB9CiAgc3RhcnQgKz0gbWFya2VyLnNpemUoKTsKICB3cml0
ZV9ub25ibG9ja2luZ19saW5lKCJ7XCJfbnRfaW50ZXJuYWxcIjpcImNhcHR1cmVfc3RhdHNfdjFc
IixcImNhcHR1cmVcIjoiICsKICAgICAgICAgICAgICAgICAgICAgICAgIGZ1bGwuc3Vic3RyKHN0
YXJ0LCBlbmQgLSBzdGFydCkgKyAifSIpOwp9CgpzdGF0aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0
IEV2ZW50ICZlKSB7CiAgc3RkOjpvc3RyaW5nc3RyZWFtIHNzOwogIHNzIDw8ICJ7XCJ0c1wiOiIg
PDwgZS50cyA8PCAiLFwiaG9zdFwiOiIgPDwganNvbnEoZS5ob3N0KSA8PCAiLFwic3JjXCI6XCJw
Y2FwXCIsXCJzZXJ2aWNlXCI6IiA8PCBqc29ucShlLnNlcnZpY2UpCiAgICAgPDwgIixcIm1ldGhv
ZFwiOiIgPDwganNvbnEoZS5tZXRob2QpIDw8ICIsXCJwYXRoXCI6IiA8PCBqc29ucShlLnBhdGgp
IDw8ICIsXCJ1c2VyXCI6IiA8PCBqc29ucShlLnVzZXIpCiAgICAgPDwgIixcInNjaGVtZVwiOiIg
PDwganNvbnEoZS5zY2hlbWUpCiAgICAgPDwgIixcImJhc2ljX3VzZXJcIjoiIDw8IChlLmJhc2lj
X3VzZXIuZW1wdHkoKSA/ICJudWxsIiA6IGpzb25xKGUuYmFzaWNfdXNlcikpCiAgICAgPDwgIixc
Indzc2VfdXNlclwiOiIgPDwgKGUud3NzZV91c2VyLmVtcHR5KCkgPyAibnVsbCIgOiBqc29ucShl
Lndzc2VfdXNlcikpCiAgICAgPDwgIixcInNvdXJjZV9wcm9iZVwiOlwicGNhcC1odHRwLWNwcFwi
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
c1wiOm51bGwiOwogIHNzIDw8ICJ9IjsKICArK2dfZXZlbnRzX2VtaXR0ZWQ7CgogIGlmICghZ19l
bmRwb2ludC5lbXB0eSgpKSB7CiAgICArK2dfZXZlbnRzX2luOwogICAgcHRocmVhZF9tdXRleF9s
b2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgaWYgKGdfc2hpcF9idWYuc2l6ZSgpID49IE1B
WF9RVUVVRSkgewogICAgICBnX3NoaXBfYnVmLmVyYXNlKGdfc2hpcF9idWYuYmVnaW4oKSk7CiAg
ICAgICsrZ19ldmVudHNfZHJvcHBlZDsKICAgICAgKytnX2Ryb3BfcXVldWU7CiAgICB9CiAgICBn
X3NoaXBfYnVmLnB1c2hfYmFjayhzcy5zdHIoKSk7CiAgICBpZiAoZ19zaGlwX2J1Zi5zaXplKCkg
PiBnX3F1ZXVlX2hpZ2hfd2F0ZXIpIGdfcXVldWVfaGlnaF93YXRlciA9IGdfc2hpcF9idWYuc2l6
ZSgpOwogICAgcHRocmVhZF9jb25kX3NpZ25hbCgmZ19zaGlwX3F1ZXVlX2NvbmQpOwogICAgcHRo
cmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgfSBlbHNlIHsKICAgIHdy
aXRlX25vbmJsb2NraW5nX2xpbmUoc3Muc3RyKCkpOwogIH0KfQoKc3RhdGljIHZvaWQgcXVldWVf
cmVxdWVzdChjb25zdCBFdmVudCAmZSwgdWludDMyX3Qgc19pcCwgdW5zaWduZWQgc3BvcnQsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgdWludDMyX3QgZF9pcCwgdW5zaWduZWQgZHBvcnQsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQ
ZW5kaW5nPiA+ICZwZW5kaW5nLAogICAgICAgICAgICAgICAgICAgICAgICAgIGxvbmcgbG9uZyBm
aXJzdF9ieXRlX21vbm9fbXMgPSAwLAogICAgICAgICAgICAgICAgICAgICAgICAgIHVpbnQzMl90
IGdlbiA9IDApIHsKICBQYWNrZXRLZXkgcms7CiAgcmsuc19pcCA9IGRfaXA7IHJrLnNwb3J0ID0g
KHVpbnQxNl90KWRwb3J0OwogIHJrLmRfaXAgPSBzX2lwOyByay5kcG9ydCA9ICh1aW50MTZfdClz
cG9ydDsKCiAgbG9uZyBsb25nIG1vbm9fbm93ID0gbm93X21vbm90b25pY19tcygpOwogIGxvbmcg
bG9uZyBzdGFydGVkX21vbm8gPSAoZmlyc3RfYnl0ZV9tb25vX21zID4gMCkgPyBmaXJzdF9ieXRl
X21vbm9fbXMgOiBtb25vX25vdzsKCiAgLy8gSWYgb3JkZXJpbmcgd2FzIGxvc3QgZm9yIHRoaXMg
NC10dXBsZSAodG9tYnN0b25lIGV4cGlyZWQsIGV2aWN0aW9uKSwgZW1pdAogIC8vIHdpdGhvdXQg
cXVldWluZyBzbyBubyBmdXR1cmUgcmVzcG9uc2UgY2FuIGJlIGF0dGFjaGVkIHRvIHRoaXMgcmVx
dWVzdC4KICBpZiAoZ19jb3JyX2Rpc2FibGVkLmNvdW50KHJrKSkgewogICAgZW1pdF9ldmVudChl
KTsKICAgIHJldHVybjsKICB9CgogIHdoaWxlIChnX3RvdGFsX3BlbmRpbmdfY291bnQgPj0gTUFY
X1BFTkRJTkdfVE9UQUwgJiYgIWdfcGVuZGluZ19maWZvLmVtcHR5KCkpIHsKICAgIFBlbmRpbmdR
dWV1ZVJlZiByZWYgPSBnX3BlbmRpbmdfZmlmby5mcm9udCgpOwogICAgZ19wZW5kaW5nX2ZpZm8u
cG9wX2Zyb250KCk7CiAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+
ID46Oml0ZXJhdG9yIGl0ID0gcGVuZGluZy5maW5kKHJlZi5rZXkpOwogICAgaWYgKGl0ICE9IHBl
bmRpbmcuZW5kKCkpIHsKICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBpdC0+c2Vjb25kLnNp
emUoKTsgKytpKSB7CiAgICAgICAgaWYgKGl0LT5zZWNvbmRbaV0ucmVxX2lkID09IHJlZi5yZXFf
aWQpIHsKICAgICAgICAgIC8vIEdsb2JhbCBldmljdGlvbiBkaXNydXB0cyBvcmRlcmluZyBmb3Ig
dGhpcyBrZXk6IGZsdXNoIGFsbCBhbmQgbG9jayBvdXQuCiAgICAgICAgICB3aGlsZSAoIWl0LT5z
ZWNvbmQuZW1wdHkoKSkgewogICAgICAgICAgICBpZiAoIWl0LT5zZWNvbmQuZnJvbnQoKS5pc190
b21ic3RvbmUpIHsKICAgICAgICAgICAgICBlbWl0X2V2ZW50KGl0LT5zZWNvbmQuZnJvbnQoKS5l
dik7CiAgICAgICAgICAgICAgaWYgKGdfdG90YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3Rh
bF9wZW5kaW5nX2NvdW50OwogICAgICAgICAgICB9CiAgICAgICAgICAgIGl0LT5zZWNvbmQuZXJh
c2UoaXQtPnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgIH0KICAgICAgICAgIHBlbmRpbmcuZXJh
c2UoaXQpOwogICAgICAgICAgZ19jb3JyX2Rpc2FibGVkLmluc2VydChyZWYua2V5KTsKICAgICAg
ICAgIGJyZWFrOwogICAgICAgIH0KICAgICAgfQogICAgfQogIH0KCiAgaWYgKGdfY29ycl9kaXNh
YmxlZC5jb3VudChyaykpIHsKICAgIGVtaXRfZXZlbnQoZSk7CiAgICByZXR1cm47CiAgfQoKICBz
dGQ6OnZlY3RvcjxQZW5kaW5nPiAmcXVldWUgPSBwZW5kaW5nW3JrXTsKICBpZiAocXVldWUuc2l6
ZSgpID49IE1BWF9QRU5ESU5HX1BFUl9GTE9XKSB7CiAgICAvLyBQZXItZmxvdyBvdmVyZmxvdzog
Zmx1c2ggYWxsIGVudHJpZXMgZm9yIHRoaXMgNC10dXBsZSwgcGVybWFuZW50bHkgbG9jayBvdXQu
CiAgICB3aGlsZSAoIXF1ZXVlLmVtcHR5KCkpIHsKICAgICAgaWYgKCFxdWV1ZS5mcm9udCgpLmlz
X3RvbWJzdG9uZSkgewogICAgICAgIGVtaXRfZXZlbnQocXVldWUuZnJvbnQoKS5ldik7CiAgICAg
ICAgaWYgKGdfdG90YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50
OwogICAgICB9CiAgICAgIHF1ZXVlLmVyYXNlKHF1ZXVlLmJlZ2luKCkpOwogICAgfQogICAgcGVu
ZGluZy5lcmFzZShyayk7CiAgICBnX2NvcnJfZGlzYWJsZWQuaW5zZXJ0KHJrKTsKICAgIGVtaXRf
ZXZlbnQoZSk7CiAgICByZXR1cm47CiAgfQogIHVpbnQ2NF90IHJlcV9pZCA9ICsrZ19yZXFfaWRf
c2VxOwogIHF1ZXVlLnB1c2hfYmFjayhQZW5kaW5nKHJlcV9pZCwgZ2VuLCBlLCBub3dfbXMoKSwg
c3RhcnRlZF9tb25vKSk7CiAgKytnX3RvdGFsX3BlbmRpbmdfY291bnQ7CgoKICBQZW5kaW5nUXVl
dWVSZWYgbmV3X3JlZjsKICBuZXdfcmVmLnJlcV9pZCA9IHJlcV9pZDsKICBuZXdfcmVmLmdlbmVy
YXRpb24gPSBnZW47CiAgbmV3X3JlZi5rZXkgPSByazsKICBuZXdfcmVmLnN0YXJ0ZWRfbW9ub19t
cyA9IHN0YXJ0ZWRfbW9ubzsKICBnX3BlbmRpbmdfZmlmby5wdXNoX2JhY2sobmV3X3JlZik7Cgog
IGlmIChnX3BlbmRpbmdfZmlmby5zaXplKCkgPiBNQVhfUEVORElOR19UT1RBTCAqIDIpIHsKICAg
IHN0ZDo6bGlzdDxQZW5kaW5nUXVldWVSZWY+OjppdGVyYXRvciBmaSA9IGdfcGVuZGluZ19maWZv
LmJlZ2luKCk7CiAgICB3aGlsZSAoZmkgIT0gZ19wZW5kaW5nX2ZpZm8uZW5kKCkpIHsKICAgICAg
c3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9
IHBlbmRpbmcuZmluZChmaS0+a2V5KTsKICAgICAgYm9vbCBhbGl2ZSA9IGZhbHNlOwogICAgICBp
ZiAoaXQgIT0gcGVuZGluZy5lbmQoKSkgewogICAgICAgIGZvciAoc2l6ZV90IGogPSAwOyBqIDwg
aXQtPnNlY29uZC5zaXplKCk7ICsraikgewogICAgICAgICAgaWYgKGl0LT5zZWNvbmRbal0ucmVx
X2lkID09IGZpLT5yZXFfaWQpIHsKICAgICAgICAgICAgYWxpdmUgPSB0cnVlOwogICAgICAgICAg
ICBicmVhazsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0KICAgICAgaWYgKCFhbGl2ZSkg
ewogICAgICAgIGZpID0gZ19wZW5kaW5nX2ZpZm8uZXJhc2UoZmkpOwogICAgICB9IGVsc2Ugewog
ICAgICAgICsrZmk7CiAgICAgIH0KICAgIH0KICB9Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX2luY29t
cGxldGVfd3NzZShzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRp
bmc+ID4gJnBlbmRpbmcpIHsKICBmb3IgKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRv
ciBmID0gZmxvd3MuYmVnaW4oKTsgZiAhPSBmbG93cy5lbmQoKTsgKytmKSB7CiAgICBpZiAoZi0+
c2Vjb25kLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgcXVldWVfcmVxdWVzdChmLT5zZWNvbmQud3Nz
ZV9ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+Zmlyc3Quc3BvcnQsCiAgICAgICAgICAgICAgICAg
ICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3QuZHBvcnQsIHBlbmRpbmcsIGYtPnNlY29uZC5maXJz
dF9ieXRlX21vbm9fbXMsCiAgICAgICAgICAgICAgICAgICAgZi0+c2Vjb25kLmdlbmVyYXRpb24p
OwogICAgICBmLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSA9IGZhbHNlOwogICAgfQogICAgZi0+c2Vj
b25kLmNsZWFyX2J1ZmZlcnMoKTsKICB9CiAgZmxvd3MuY2xlYXIoKTsKICBnX3RvdGFsX2Zsb3df
Ynl0ZXMgPSAwOwp9CgpzdGF0aWMgdm9pZCBmbHVzaF9hbGxfcGVuZGluZyhzdGQ6Om1hcDxQYWNr
ZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBmb3IgKHN0ZDo6bWFw
PFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCA9IHBlbmRpbmcu
YmVnaW4oKTsgcCAhPSBwZW5kaW5nLmVuZCgpOyArK3ApIHsKICAgIGZvciAoc2l6ZV90IGkgPSAw
OyBpIDwgcC0+c2Vjb25kLnNpemUoKTsgKytpKSB7CiAgICAgIGlmICghcC0+c2Vjb25kW2ldLmlz
X3RvbWJzdG9uZSkgewogICAgICAgIGVtaXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgICAg
fQogICAgfQogIH0KICBwZW5kaW5nLmNsZWFyKCk7CiAgZ19wZW5kaW5nX2ZpZm8uY2xlYXIoKTsK
ICBnX3RvdGFsX3BlbmRpbmdfY291bnQgPSAwOwogIGdfY29ycl9kaXNhYmxlZC5jbGVhcigpOwp9
CgoKCnN0YXRpYyB2b2lkIHN3ZWVwKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cywKICAg
ICAgICAgICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
ICZwZW5kaW5nLAogICAgICAgICAgICAgICAgICB0aW1lX3Qgbm93LCB1bnNpZ25lZCBwZW5kaW5n
X3R0bF9zZWMsCiAgICAgICAgICAgICAgICAgIGxvbmcgbG9uZyBub3dfbW9ubyA9IDApIHsKICBm
b3IgKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBmID0gZmxvd3MuYmVnaW4oKTsg
ZiAhPSBmbG93cy5lbmQoKTspIHsKICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRv
ciBmbiA9IGY7ICsrZm47CiAgICBpZiAoKHVuc2lnbmVkKShub3cgLSBmLT5zZWNvbmQudG91Y2hl
ZCkgPiBGTE9XX1RUTCkgewogICAgICBpZiAoZi0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpIHsKICAg
ICAgICBlbWl0X2V2ZW50KGYtPnNlY29uZC53c3NlX2V2ZW50KTsKICAgICAgICBmLT5zZWNvbmQu
YXdhaXRpbmdfd3NzZSA9IGZhbHNlOwogICAgICB9CiAgICAgIGYtPnNlY29uZC5jbGVhcl9idWZm
ZXJzKCk7CiAgICAgIGZsb3dzLmVyYXNlKGYpOwogICAgfQogICAgZiA9IGZuOwogIH0KCiAgaWYg
KG5vd19tb25vIDw9IDApIG5vd19tb25vID0gbm93X21vbm90b25pY19tcygpOwogIGxvbmcgbG9u
ZyB0dGxfbXMgPSAobG9uZyBsb25nKXBlbmRpbmdfdHRsX3NlYyAqIDEwMDBMTDsKICBmb3IgKHN0
ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCA9IHBl
bmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5nLmVuZCgpOykgewogICAgc3RkOjptYXA8UGFja2V0
S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwbiA9IHA7ICsrcG47CiAgICBz
aXplX3QgaSA9IDA7CiAgICB3aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAgUGVu
ZGluZyAmZW50cnkgPSBwLT5zZWNvbmRbaV07CiAgICAgIGlmIChlbnRyeS5pc190b21ic3RvbmUp
IHsKICAgICAgICBpZiAobm93X21vbm8gLSBlbnRyeS50b21ic3RvbmVfbW9ub19tcyA+IDEwMDAw
TEwpIHsKICAgICAgICAgIC8vIFRvbWJzdG9uZSBleHBpcmVkIHVuLWNvbnN1bWVkOiBmbHVzaCBh
bGwgcmVtYWluaW5nIGVudHJpZXMgaW4gdGhpcwogICAgICAgICAgLy8gcXVldWUgaW1tZWRpYXRl
bHkgKG9yZGVyaW5nIGlzIG5vdyBhbWJpZ3VvdXMpLiBUaGVuIHBlcm1hbmVudGx5CiAgICAgICAg
ICAvLyBkaXNhYmxlIHJlc3BvbnNlIGNvcnJlbGF0aW9uIGZvciB0aGlzIDQtdHVwbGUgdW50aWwg
YSBuZXcgU1lOLgogICAgICAgICAgUGFja2V0S2V5IGRpc2FibGVkX2tleSA9IHAtPmZpcnN0Owog
ICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgICAg
ICB3aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAgICAgICAgUGVuZGluZyAmdGFp
bCA9IHAtPnNlY29uZFtpXTsKICAgICAgICAgICAgaWYgKCF0YWlsLmlzX3RvbWJzdG9uZSkgewog
ICAgICAgICAgICAgIGVtaXRfZXZlbnQodGFpbC5ldik7CiAgICAgICAgICAgICAgaWYgKGdfdG90
YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogICAgICAgICAg
ICB9CiAgICAgICAgICAgIHAtPnNlY29uZC5lcmFzZShwLT5zZWNvbmQuYmVnaW4oKSArIGkpOwog
ICAgICAgICAgfQogICAgICAgICAgZ19jb3JyX2Rpc2FibGVkLmluc2VydChkaXNhYmxlZF9rZXkp
OwogICAgICAgICAgLy8gTGVhdmUgaSB1bmNoYW5nZWQ7IGlubmVyIHdoaWxlIGV4aXRzIG9uIG5l
eHQgY2hlY2sKICAgICAgICB9IGVsc2UgewogICAgICAgICAgKytpOwogICAgICAgIH0KICAgICAg
fSBlbHNlIGlmIChub3dfbW9ubyAtIGVudHJ5LnN0YXJ0ZWRfbW9ub19tcyA+IHR0bF9tcykgewog
ICAgICAgIGVtaXRfZXZlbnQoZW50cnkuZXYpOwogICAgICAgIGlmIChnX3RvdGFsX3BlbmRpbmdf
Y291bnQgPiAwKSAtLWdfdG90YWxfcGVuZGluZ19jb3VudDsKICAgICAgICBlbnRyeS5pc190b21i
c3RvbmUgPSB0cnVlOwogICAgICAgIGVudHJ5LnRvbWJzdG9uZV9tb25vX21zID0gbm93X21vbm87
CiAgICAgICAgKytpOwogICAgICB9IGVsc2UgewogICAgICAgICsraTsKICAgICAgfQogICAgfQog
ICAgaWYgKHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgcCA9IHBuOwog
IH0KCiAgd2hpbGUgKCFnX3BlbmRpbmdfZmlmby5lbXB0eSgpICYmCiAgICAgICAgIChub3dfbW9u
byAtIGdfcGVuZGluZ19maWZvLmZyb250KCkuc3RhcnRlZF9tb25vX21zID4gdHRsX21zICogMkxM
KSkgewogICAgZ19wZW5kaW5nX2ZpZm8ucG9wX2Zyb250KCk7CiAgfQp9CgoKc3RhdGljIGJvb2wg
ZHJhaW5fb29vX3NlZ21lbnRzKEZsb3cgJmZsKSB7CiAgYm9vbCBkcmFpbmVkID0gdHJ1ZTsKICB3
aGlsZSAoZHJhaW5lZCAmJiAhZmwub29vLmVtcHR5KCkpIHsKICAgIGRyYWluZWQgPSBmYWxzZTsK
ICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgZmwub29vLnNpemUoKTsgKytpKSB7CiAgICAgIGlu
dDMyX3Qgb2RpZmYgPSBzZXFfZGlmZihmbC5vb29baV0uc2VxLCBmbC5uZXh0X3NlcSk7CiAgICAg
IGlmIChvZGlmZiA9PSAwKSB7CiAgICAgICAgaWYgKCFmbC5idWZfYXBwZW5kKGZsLm9vb1tpXS5k
YXRhLmRhdGEoKSwgZmwub29vW2ldLmRhdGEuc2l6ZSgpKSkgcmV0dXJuIGZhbHNlOwogICAgICAg
IGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClmbC5vb29baV0uZGF0YS5zaXplKCk7CiAgICAgICAg
Zmwub29vX2VyYXNlKGkpOwogICAgICAgIGRyYWluZWQgPSB0cnVlOyBicmVhazsKICAgICAgfSBl
bHNlIGlmIChvZGlmZiA8IDApIHsKICAgICAgICBpbnQzMl90IG9fb3ZlcmxhcCA9IC1vZGlmZjsK
ICAgICAgICBpZiAoKHNpemVfdClvX292ZXJsYXAgPCBmbC5vb29baV0uZGF0YS5zaXplKCkpIHsK
ICAgICAgICAgIHNpemVfdCBmbGVuID0gZmwub29vW2ldLmRhdGEuc2l6ZSgpIC0gb19vdmVybGFw
OwogICAgICAgICAgaWYgKCFmbC5idWZfYXBwZW5kKGZsLm9vb1tpXS5kYXRhLmRhdGEoKSArIG9f
b3ZlcmxhcCwgZmxlbikpIHJldHVybiBmYWxzZTsKICAgICAgICAgIGZsLm5leHRfc2VxICs9ICh1
aW50MzJfdClmbGVuOwogICAgICAgIH0KICAgICAgICBmbC5vb29fZXJhc2UoaSk7CiAgICAgICAg
ZHJhaW5lZCA9IHRydWU7IGJyZWFrOwogICAgICB9CiAgICB9CiAgfQogIHJldHVybiB0cnVlOwp9
CgpzdGF0aWMgc2l6ZV90IGZpbmRfaHR0cF9zdGFydChjb25zdCBzdGQ6OnN0cmluZyAmcykgewog
IGNvbnN0IGNoYXIgKm1bXSA9IHsgIkdFVCAiLCAiUE9TVCAiLCAiUFVUICIsICJERUxFVEUgIiwg
IlBBVENIICIsICJIRUFEICIsICJPUFRJT05TICIgfTsKICBzaXplX3QgYmVzdCA9IHN0ZDo6c3Ry
aW5nOjpucG9zOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNzsgKytpKSB7CiAgICBzaXplX3Qg
cG9zID0gcy5maW5kKG1baV0pOwogICAgaWYgKHBvcyAhPSBzdGQ6OnN0cmluZzo6bnBvcyAmJiAo
YmVzdCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBwb3MgPCBiZXN0KSkgYmVzdCA9IHBvczsKICB9
CiAgcmV0dXJuIGJlc3Q7Cn0KCnN0YXRpYyBib29sIGlzX21ldGhvZF9vcl9wcmVmaXgoY29uc3Qg
Y2hhciAqcCwgc2l6ZV90IGxlbikgewogIGlmICghbGVuKSByZXR1cm4gZmFsc2U7CiAgY29uc3Qg
Y2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwgIkRFTEVURSAiLCAiUEFUQ0gg
IiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNzsgKytp
KSB7CiAgICBzaXplX3QgbWxlbiA9IHN0cmxlbihtW2ldKTsKICAgIHNpemVfdCBjaGVja19sZW4g
PSBsZW4gPCBtbGVuID8gbGVuIDogbWxlbjsKICAgIGlmIChtZW1jbXAocCwgbVtpXSwgY2hlY2tf
bGVuKSA9PSAwKSByZXR1cm4gdHJ1ZTsKICB9CiAgcmV0dXJuIGZhbHNlOwp9CgpzdGF0aWMgYm9v
bCBnX21vbml0b3JlZF9wb3J0c1s2NTUzNl07CgpzdGF0aWMgc2l6ZV90IGFjdGl2ZV93c3NlX2Zs
b3dzKGNvbnN0IHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cykgewogIHNpemVfdCBjb3Vu
dCA9IDA7CiAgZm9yIChzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6Y29uc3RfaXRlcmF0b3IgaXQg
PSBmbG93cy5iZWdpbigpOyBpdCAhPSBmbG93cy5lbmQoKTsgKytpdCkKICAgIGlmIChpdC0+c2Vj
b25kLmF3YWl0aW5nX3dzc2UpICsrY291bnQ7CiAgcmV0dXJuIGNvdW50Owp9CgpzdGF0aWMgdm9p
ZCBldmljdF9vbGRlc3RfZmxvd19pZl9uZWVkZWQoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZs
b3dzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8UGFj
a2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgd2hpbGUgKCFmbG93
cy5lbXB0eSgpICYmIChmbG93cy5zaXplKCkgPj0gTUFYX0ZMT1dTIHx8IGdfdG90YWxfZmxvd19i
eXRlcyA+PSBNQVhfVE9UQUxfQlVGRkVSX0JZVEVTKSkgewogICAgc3RkOjptYXA8Rmxvd0tleSwg
Rmxvdz46Oml0ZXJhdG9yIG9sZGVzdCA9IGZsb3dzLmJlZ2luKCk7CiAgICBmb3IgKHN0ZDo6bWFw
PEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBpdCA9IGZsb3dzLmJlZ2luKCk7IGl0ICE9IGZsb3dz
LmVuZCgpOyArK2l0KSB7CiAgICAgIGlmIChpdC0+c2Vjb25kLnRvdWNoZWQgPCBvbGRlc3QtPnNl
Y29uZC50b3VjaGVkKSBvbGRlc3QgPSBpdDsKICAgIH0KICAgIGlmIChvbGRlc3QtPnNlY29uZC5h
d2FpdGluZ193c3NlKSB7CiAgICAgIHF1ZXVlX3JlcXVlc3Qob2xkZXN0LT5zZWNvbmQud3NzZV9l
dmVudCwgb2xkZXN0LT5maXJzdC5zX2lwLCBvbGRlc3QtPmZpcnN0LnNwb3J0LAogICAgICAgICAg
ICAgICAgICAgIG9sZGVzdC0+Zmlyc3QuZF9pcCwgb2xkZXN0LT5maXJzdC5kcG9ydCwgcGVuZGlu
Zywgb2xkZXN0LT5zZWNvbmQuZmlyc3RfYnl0ZV9tb25vX21zLAogICAgICAgICAgICAgICAgICAg
IG9sZGVzdC0+c2Vjb25kLmdlbmVyYXRpb24pOwogICAgICBvbGRlc3QtPnNlY29uZC5hd2FpdGlu
Z193c3NlID0gZmFsc2U7CiAgICB9CiAgICBvbGRlc3QtPnNlY29uZC5jbGVhcl9idWZmZXJzKCk7
CiAgICBmbG93cy5lcmFzZShvbGRlc3QpOwogIH0KfQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tl
dChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAm
bm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAg
ICAgICAgICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tl
dEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywKICAgICAgICAgICAgICAgICAg
ICAgICAgICB0aW1lX3QgcGNhcF9ub3cgPSAwLCBsb25nIGxvbmcgcGNhcF9tb25vX25vdyA9IDAp
IHsKICAodm9pZClwb3J0czsKICBpZiAobiA8IDM0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9m
ZiA9IDE0OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRvaHMocmVhZF91MTYoYnVmICsgMTIpKTsK
ICBpZiAoZXQgPT0gRVRIX1BfODAyMVEpIHsgaWYgKG4gPCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9
IG50b2hzKHJlYWRfdTE2KGJ1ZiArIDE2KSk7IG9mZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9Q
X0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1bnNpZ25lZCBjaGFyIGlobCA9
ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAqIDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0
KSAhPSA0IHx8IGlobCA8IDIwIHx8IGJ1ZltvZmYgKyA5XSAhPSA2KSByZXR1cm4gZmFsc2U7Cgog
IC8vIFJlamVjdCBmcmFnbWVudGVkIElQIHBhY2tldHMgKG5vbi1maXJzdCBmcmFnbWVudCBoYXMg
ZnJhZyBvZmZzZXQgPiAwKQogIHVpbnQxNl90IGZyYWcgPSBudG9ocyhyZWFkX3UxNihidWYgKyBv
ZmYgKyA2KSk7CiAgaWYgKGZyYWcgJiAweDFmZmYpIHJldHVybiBmYWxzZTsKCiAgLy8gSVB2NCB0
b3RhbCBsZW5ndGggdmFsaWRhdGlvbiBhbmQgdHJ1bmNhdGlvbiBjaGVjawogIHVpbnQxNl90IGlw
X3RvdGFsX2xlbiA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIG9mZiArIDIpKTsKICBib29sIGlzX3Ry
dW5jYXRlZCA9IGZhbHNlOwogIGlmIChpcF90b3RhbF9sZW4gPiAwKSB7CiAgICBpZiAoaXBfdG90
YWxfbGVuIDwgaWhsICsgMjApIHJldHVybiBmYWxzZTsKICAgIGlmIChuIC0gb2ZmIDwgaXBfdG90
YWxfbGVuKSB7CiAgICAgIGlzX3RydW5jYXRlZCA9IHRydWU7CiAgICB9IGVsc2UgaWYgKG4gLSBv
ZmYgPiBpcF90b3RhbF9sZW4pIHsKICAgICAgbiA9IG9mZiArIGlwX3RvdGFsX2xlbjsgLy8gRXhj
bHVkZSBFdGhlcm5ldCBwYWRkaW5nCiAgICB9CiAgfQoKICB1aW50MzJfdCBzX2lwID0gcmVhZF91
MzIoYnVmICsgb2ZmICsgMTIpOwogIHVpbnQzMl90IGRfaXAgPSByZWFkX3UzMihidWYgKyBvZmYg
KyAxNik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwogIGlmIChuIDwgdG8gKyAyMCkgcmV0dXJu
IGZhbHNlOwoKICB1bnNpZ25lZCBzcG9ydCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIHRvKSk7CiAg
dW5zaWduZWQgZHBvcnQgPSBudG9ocyhyZWFkX3UxNihidWYgKyB0byArIDIpKTsKICB1aW50MzJf
dCBzZXEgPSBudG9obChyZWFkX3UzMihidWYgKyB0byArIDQpKTsKICB1bnNpZ25lZCBkb2ZmID0g
KGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYgKGRvZmYgPCAyMCB8fCBuIDwgdG8gKyBkb2Zm
KSByZXR1cm4gZmFsc2U7CgogIHVuc2lnbmVkIGNoYXIgdGNwX2ZsYWdzID0gYnVmW3RvICsgMTNd
OwogIGNvbnN0IGNoYXIgKnBheWxvYWQgPSAoY29uc3QgY2hhciAqKShidWYgKyB0byArIGRvZmYp
OwogIHNpemVfdCBwbGVuID0gbiAtIHRvIC0gZG9mZjsKCiAgdGltZV90IG5vdyA9IChwY2FwX25v
dyA+IDApID8gcGNhcF9ub3cgOiB0aW1lKE5VTEwpOwogIGxvbmcgbG9uZyBtb25vX25vdyA9IChw
Y2FwX21vbm9fbm93ID4gMCkgPyBwY2FwX21vbm9fbm93IDogbm93X21vbm90b25pY19tcygpOwoK
ICBib29sIGRzdF9tb24gPSAoZHBvcnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tkcG9y
dF0gOiBmYWxzZTsKICBib29sIHNyY19tb24gPSAoc3BvcnQgPCA2NTUzNikgPyBnX21vbml0b3Jl
ZF9wb3J0c1tzcG9ydF0gOiBmYWxzZTsKCiAgLy8gRGlyZWN0aW9uIEE6IFNlcnZlciAtPiBDbGll
bnQgUmVzcG9uc2UgUmVhc3NlbWJseQogIGlmIChzcmNfbW9uICYmICFkc3RfbW9uKSB7CiAgICBG
bG93S2V5IHJmazsKICAgIHJmay5zX2lwID0gc19pcDsgcmZrLnNwb3J0ID0gKHVpbnQxNl90KXNw
b3J0OwogICAgcmZrLmRfaXAgPSBkX2lwOyByZmsuZHBvcnQgPSAodWludDE2X3QpZHBvcnQ7Cgog
ICAgaWYgKHRjcF9mbGFncyAmIDB4MDIpIHsgLy8gU1lOIGZyb20gc2VydmVyCiAgICAgIGV2aWN0
X29sZGVzdF9mbG93X2lmX25lZWRlZChmbG93cywgcGVuZGluZyk7CiAgICAgIEZsb3cgJnJmbCA9
IGZsb3dzW3Jma107CiAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgIHJmbCA9IEZsb3co
KTsKICAgICAgcmZsLmhhc19zZXEgPSB0cnVlOwogICAgICByZmwubmV4dF9zZXEgPSBzZXEgKyAx
OwogICAgICByZmwuaXNfYnJva2VuID0gZmFsc2U7CiAgICAgIHJmbC50b3VjaGVkID0gbm93Owog
ICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICBpZiAocGxlbiA+IDApIHsKICAgICAgZXZpY3Rf
b2xkZXN0X2Zsb3dfaWZfbmVlZGVkKGZsb3dzLCBwZW5kaW5nKTsKICAgICAgRmxvdyAmcmZsID0g
Zmxvd3NbcmZrXTsKICAgICAgcmZsLnRvdWNoZWQgPSBub3c7CgogICAgICBpZiAoIXJmbC5oYXNf
c2VxKSB7CiAgICAgICAgaWYgKChwbGVuID49IDUgJiYgbWVtY21wKHBheWxvYWQsICJIVFRQLyIs
IDUpID09IDApIHx8CiAgICAgICAgICAgIChwbGVuIDwgNSAmJiBtZW1jbXAocGF5bG9hZCwgIkhU
VFAvIiwgcGxlbikgPT0gMCkpIHsKICAgICAgICAgIHJmbC5oYXNfc2VxID0gdHJ1ZTsKICAgICAg
ICAgIHJmbC5uZXh0X3NlcSA9IHNlcTsKICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBmYWxzZTsK
ICAgICAgICB9IGVsc2UgewogICAgICAgICAgaWYgKHJmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19T
RUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICAgIGJvb2wgZHVwID0gZmFsc2U7
CiAgICAgICAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcmZsLm9vby5zaXplKCk7ICsraSkg
ewogICAgICAgICAgICAgIGlmIChyZmwub29vW2ldLnNlcSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsg
YnJlYWs7IH0KICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAg
ICAgIHJmbC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgICB9CiAgICAg
ICAgICB9CiAgICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGlu
dDMyX3QgZGlmZiA9IHNlcV9kaWZmKHNlcSwgcmZsLm5leHRfc2VxKTsKICAgICAgaWYgKGRpZmYg
PT0gMCkgewogICAgICAgIGlmIChpc190cnVuY2F0ZWQpIHsKICAgICAgICAgIHJmbC5pc19icm9r
ZW4gPSB0cnVlOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBpZiAoIXJmbC5idWZfYXBwZW5k
KHBheWxvYWQsIHBsZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgIHJmbC5uZXh0X3NlcSArPSAo
dWludDMyX3QpcGxlbjsKICAgICAgICAgIGlmICghZHJhaW5fb29vX3NlZ21lbnRzKHJmbCkpIHJl
dHVybiB0cnVlOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChkaWZmIDwgMCkgewogICAgICAg
IGludDMyX3Qgb3ZlcmxhcCA9IC1kaWZmOwogICAgICAgIGlmICgoc2l6ZV90KW92ZXJsYXAgPCBw
bGVuICYmICFpc190cnVuY2F0ZWQpIHsKICAgICAgICAgIHNpemVfdCBmbGVuID0gcGxlbiAtIG92
ZXJsYXA7CiAgICAgICAgICBpZiAoIXJmbC5idWZfYXBwZW5kKHBheWxvYWQgKyBvdmVybGFwLCBm
bGVuKSkgcmV0dXJuIHRydWU7CiAgICAgICAgICByZmwubmV4dF9zZXEgKz0gKHVpbnQzMl90KWZs
ZW47CiAgICAgICAgICBpZiAoIWRyYWluX29vb19zZWdtZW50cyhyZmwpKSByZXR1cm4gdHJ1ZTsK
ICAgICAgICB9CiAgICAgIH0gZWxzZSB7IC8vIGRpZmYgPiAwCiAgICAgICAgaWYgKHJmbC5vb28u
c2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICBi
b29sIGR1cCA9IGZhbHNlOwogICAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCByZmwub29v
LnNpemUoKTsgKytpKSB7CiAgICAgICAgICAgIGlmIChyZmwub29vW2ldLnNlcSA9PSBzZXEpIHsg
ZHVwID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgICAgIH0KICAgICAgICAgIGlmICghZHVwKSB7CiAg
ICAgICAgICAgIHJmbC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgfQog
ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICB9
CiAgICAgIH0KCiAgICAgIC8vIFBhcnNlIGNvbXBsZXRlIHJlc3BvbnNlcyBmcm9tIHJlYXNzZW1i
bGVkIGJ1ZmZlciB1c2luZyBIVFRQIGZyYW1pbmcKICAgICAgd2hpbGUgKCFyZmwuYnVmLmVtcHR5
KCkgJiYgIXJmbC5pc19icm9rZW4pIHsKICAgICAgICBpZiAocmZsLnN0YXRlID09IEZsb3c6OkhU
VFBfU1RBVEVfSEVBREVSKSB7CiAgICAgICAgICBzaXplX3QgZW5kID0gcmZsLmJ1Zi5maW5kKCJc
clxuXHJcbiIpOwogICAgICAgICAgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAg
ICAgICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAgICAg
ICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0g
dHJ1ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KCiAgICAg
ICAgICBpZiAocmZsLmJ1Zi5jb21wYXJlKDAsIDUsICJIVFRQLyIpICE9IDApIHsKICAgICAgICAg
ICAgc2l6ZV90IGhwb3MgPSByZmwuYnVmLmZpbmQoIkhUVFAvIik7CiAgICAgICAgICAgIGlmICho
cG9zID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IGhwb3MgPiBlbmQpIHsKICAgICAgICAgICAgICBy
ZmwuYnVmX2VyYXNlKDAsIGVuZCArIDQpOwogICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAg
ICAgICB9CiAgICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgaHBvcyk7CiAgICAgICAgICAgIGVu
ZCAtPSBocG9zOwogICAgICAgICAgfQoKICAgICAgICAgIGludCBzdCA9IDA7IHNpemVfdCBjbCA9
IDA7IGJvb2wgaGFzX2NsID0gZmFsc2UsIGlzX2NodW5rZWQgPSBmYWxzZSwgaXNfY2xvc2UgPSBm
YWxzZTsKICAgICAgICAgIGlmICghcGFyc2VfcmVzcG9uc2UocmZsLmJ1Zi5kYXRhKCksIGVuZCAr
IDIsICZzdCwgJmNsLCAmaGFzX2NsLCAmaXNfY2h1bmtlZCwgJmlzX2Nsb3NlKSkgewogICAgICAg
ICAgICAvLyBBbWJpZ3VvdXMgZnJhbWluZyAoY29uZmxpY3RpbmcgQ29udGVudC1MZW5ndGgsIGJh
ZCBzdGF0dXMsIGV0Yy4pLgogICAgICAgICAgICAvLyBEaXNjYXJkIHRoZSBoZWFkZXIgYW5kIG1h
cmsgdGhlIHN0cmVhbSBicm9rZW4gc28gYm9keSBieXRlcyBhcmUKICAgICAgICAgICAgLy8gbm90
IHJlLXNjYW5uZWQgYXMgYSBuZXcgcmVzcG9uc2Ug4oCTIHByZXZlbnRzIGZhYnJpY2F0ZWQgc3Rh
dHVzZXMuCiAgICAgICAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIHJmbC5p
c19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KCiAgICAgICAg
ICBpZiAoc3QgPj0gMTAwICYmIHN0IDw9IDE5OSAmJiBzdCAhPSAxMDEpIHsKICAgICAgICAgICAg
cmZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAg
ICB9CgogICAgICAgICAgUGFja2V0S2V5IHBrOwogICAgICAgICAgcGsuc19pcCA9IHNfaXA7IHBr
LnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICAgICAgcGsuZF9pcCA9IGRfaXA7IHBrLmRw
b3J0ID0gKHVpbnQxNl90KWRwb3J0OwogICAgICAgICAgLy8gQ29ycmVsYXRpb24gcGVybWFuZW50
bHkgZGlzYWJsZWQgZm9yIHRoaXMgNC10dXBsZTogZGlzY2FyZCByZXNwb25zZS4KICAgICAgICAg
IGlmIChnX2NvcnJfZGlzYWJsZWQuY291bnQocGspKSB7CiAgICAgICAgICAgIC8vIENvbnN1bWUg
dGhpcyByZXNwb25zZSBoZWFkZXIrYm9keSBzbyBwYXJzaW5nIGNhbiBjb250aW51ZSwgYnV0CiAg
ICAgICAgICAgIC8vIGRvIG5vdCBhdHRhY2ggaXQgdG8gYW55IHBlbmRpbmcgcmVxdWVzdC4KICAg
ICAgICAgICAgLy8gRmFsbCB0aHJvdWdoIHRvIGJvZHktc3RhdGUgdHJhbnNpdGlvbnMgYmVsb3cg
KGlzX2hlYWQ9ZmFsc2UpLgogICAgICAgICAgfQogICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5
LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0KICAgICAgICAgICAgICBnX2Nv
cnJfZGlzYWJsZWQuY291bnQocGspID8gcGVuZGluZy5lbmQoKSA6IHBlbmRpbmcuZmluZChwayk7
CiAgICAgICAgICBib29sIGlzX2hlYWQgPSBmYWxzZTsKICAgICAgICAgIGlmIChwICE9IHBlbmRp
bmcuZW5kKCkgJiYgIXAtPnNlY29uZC5lbXB0eSgpKSB7CiAgICAgICAgICAgIGlmIChyZmwuZ2Vu
ZXJhdGlvbiAhPSAwICYmIHAtPnNlY29uZFswXS5nZW5lcmF0aW9uICE9IDAgJiYgcC0+c2Vjb25k
WzBdLmdlbmVyYXRpb24gIT0gcmZsLmdlbmVyYXRpb24pIHsKICAgICAgICAgICAgICAvLyBHZW5l
cmF0aW9uIG1pc21hdGNoISBTdGFsZSByZXF1ZXN0IGZyb20gcHJldmlvdXMgY29ubmVjdGlvbi4K
ICAgICAgICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFswXS5ldik7CiAgICAgICAgICAgICAg
aWYgKCFwLT5zZWNvbmRbMF0uaXNfdG9tYnN0b25lICYmIGdfdG90YWxfcGVuZGluZ19jb3VudCA+
IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogICAgICAgICAgICAgIHAtPnNlY29uZC5lcmFz
ZShwLT5zZWNvbmQuYmVnaW4oKSk7CiAgICAgICAgICAgICAgaWYgKHAtPnNlY29uZC5lbXB0eSgp
KSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgICAgICB9IGVsc2UgaWYgKHAtPnNlY29uZFswXS5p
c190b21ic3RvbmUpIHsKICAgICAgICAgICAgICAvLyBMYXRlIHJlc3BvbnNlIGZvciBleHBpcmVk
IHJlcXVlc3Q6IGNvbnN1bWUgdG9tYnN0b25lLCBkbyBub3QgYXR0YWNoIHRvIG5ld2VyIHJlcXVl
c3RzCiAgICAgICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpKTsKICAg
ICAgICAgICAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICAg
ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgRXZlbnQgZSA9IHAtPnNlY29uZFswXS5ldjsK
ICAgICAgICAgICAgICBpZiAoZS5tZXRob2QgPT0gIkhFQUQiKSBpc19oZWFkID0gdHJ1ZTsKICAg
ICAgICAgICAgICBlLnN0YXR1cyA9IHN0OwogICAgICAgICAgICAgIGUuaGFzX3N0YXR1cyA9IHRy
dWU7CiAgICAgICAgICAgICAgZS5kdXJhdGlvbl9tcyA9IChsb25nKShtb25vX25vdyAtIHAtPnNl
Y29uZFswXS5zdGFydGVkX21vbm9fbXMpOwogICAgICAgICAgICAgIGlmIChlLmR1cmF0aW9uX21z
IDwgMCkgZS5kdXJhdGlvbl9tcyA9IDA7CiAgICAgICAgICAgICAgZS5oYXNfZHVyYXRpb24gPSB0
cnVlOwogICAgICAgICAgICAgIGlmIChoYXNfY2wpIHsKICAgICAgICAgICAgICAgIGUucmVzcF9i
eXRlcyA9ICh1bnNpZ25lZCljbDsKICAgICAgICAgICAgICAgIGUuaGFzX3Jlc3AgPSB0cnVlOwog
ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICBlbWl0X2V2ZW50KGUpOwogICAgICAgICAgICAg
IHAtPnNlY29uZC5lcmFzZShwLT5zZWNvbmQuYmVnaW4oKSk7CiAgICAgICAgICAgICAgaWYgKGdf
dG90YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogICAgICAg
ICAgICAgIGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICAg
ICAgfQogICAgICAgICAgfQoKICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgZW5kICsgNCk7Cgog
ICAgICAgICAgaWYgKGlzX2hlYWQgfHwgc3QgPT0gMjA0IHx8IHN0ID09IDMwNCkgewogICAgICAg
ICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgIH0gZWxz
ZSBpZiAoaXNfY2h1bmtlZCkgewogICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NU
QVRFX0NIVU5LOwogICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19sZW4gPSB0cnVlOwogICAg
ICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFsc2U7CiAgICAgICAgICAgIHJmbC5j
aHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxzZTsKICAgICAgICAgICAgcmZsLmNodW5rX3BheWxv
YWRfcmVtYWluaW5nID0gMDsKICAgICAgICAgIH0gZWxzZSBpZiAoaGFzX2NsKSB7CiAgICAgICAg
ICAgIGlmIChjbCA+IDApIHsKICAgICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NU
QVRFX0JPRFk7CiAgICAgICAgICAgICAgcmZsLmJvZHlfcmVtYWluaW5nID0gY2w7CiAgICAgICAg
ICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgcmZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9I
RUFERVI7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gZWxzZSBpZiAoaXNfY2xvc2UpIHsKICAg
ICAgICAgICAgcmZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9DTE9TRV9CT0RZOwogICAgICAg
ICAgfSBlbHNlIHsKICAgICAgICAgICAgcmZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9DTE9T
RV9CT0RZOwogICAgICAgICAgfQogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQoKICAgICAg
ICBpZiAocmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfQk9EWSkgewogICAgICAgICAgaWYg
KHJmbC5idWYuZW1wdHkoKSkgYnJlYWs7CiAgICAgICAgICBzaXplX3QgdG9fY29uc3VtZSA9IChy
ZmwuYnVmLnNpemUoKSA8IHJmbC5ib2R5X3JlbWFpbmluZykgPyByZmwuYnVmLnNpemUoKSA6IHJm
bC5ib2R5X3JlbWFpbmluZzsKICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgdG9fY29uc3VtZSk7
CiAgICAgICAgICByZmwuYm9keV9yZW1haW5pbmcgLT0gdG9fY29uc3VtZTsKICAgICAgICAgIGlm
IChyZmwuYm9keV9yZW1haW5pbmcgPT0gMCkgewogICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93
OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgIH0KICAgICAgICAgIGNvbnRpbnVlOwogICAg
ICAgIH0KCiAgICAgICAgaWYgKHJmbC5zdGF0ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0NIVU5LKSB7
CiAgICAgICAgICBpZiAocmZsLmJ1Zi5lbXB0eSgpKSBicmVhazsKICAgICAgICAgIGlmIChyZmwu
Y2h1bmtfcmVhZGluZ190cmFpbGVyKSB7CiAgICAgICAgICAgIGlmIChyZmwuYnVmLnNpemUoKSA+
PSAyICYmIHJmbC5idWZbMF0gPT0gJ1xyJyAmJiByZmwuYnVmWzFdID09ICdcbicpIHsKICAgICAg
ICAgICAgICByZmwuYnVmX2VyYXNlKDAsIDIpOwogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFk
aW5nX3RyYWlsZXIgPSBmYWxzZTsKICAgICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQ
X1NUQVRFX0hFQURFUjsKICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAg
ICAgICAgICBzaXplX3QgdHJfZW5kID0gcmZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAg
ICAgICBpZiAodHJfZW5kICE9IHN0ZDo6c3RyaW5nOjpucG9zKSB7CiAgICAgICAgICAgICAgcmZs
LmJ1Zl9lcmFzZSgwLCB0cl9lbmQgKyA0KTsKICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGlu
Z190cmFpbGVyID0gZmFsc2U7CiAgICAgICAgICAgICAgcmZsLnN0YXRlID0gRmxvdzo6SFRUUF9T
VEFURV9IRUFERVI7CiAgICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICAgIH0KICAgICAg
ICAgICAgaWYgKHJmbC5idWYuc2l6ZSgpID4gTUFYX0hFQURFUl9CWVRFUykgewogICAgICAgICAg
ICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRy
dWU7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9CiAgICAgICAg
ICBpZiAocmZsLmNodW5rX3JlYWRpbmdfbGVuKSB7CiAgICAgICAgICAgIHNpemVfdCBjcmxmID0g
cmZsLmJ1Zi5maW5kKCJcclxuIik7CiAgICAgICAgICAgIGlmIChjcmxmID09IHN0ZDo6c3RyaW5n
OjpucG9zKSB7CiAgICAgICAgICAgICAgaWYgKHJmbC5idWYuc2l6ZSgpID4gNjQpIHsKICAgICAg
ICAgICAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgICAgICByZmwuaXNfYnJv
a2VuID0gdHJ1ZTsKICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAg
ICAgIH0KICAgICAgICAgICAgc3RkOjpzdHJpbmcgbGluZSA9IHRyaW0ocmZsLmJ1Zi5zdWJzdHIo
MCwgY3JsZikpOwogICAgICAgICAgICBzaXplX3Qgc2VtaSA9IGxpbmUuZmluZCgnOycpOwogICAg
ICAgICAgICBzdGQ6OnN0cmluZyBoZXhfc3RyID0gKHNlbWkgIT0gc3RkOjpzdHJpbmc6Om5wb3Mp
ID8gdHJpbShsaW5lLnN1YnN0cigwLCBzZW1pKSkgOiBsaW5lOwogICAgICAgICAgICBpZiAoaGV4
X3N0ci5lbXB0eSgpIHx8IGhleF9zdHIuc2l6ZSgpID4gMTYpIHsKICAgICAgICAgICAgICByZmwu
Y2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAg
ICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGJvb2wgdmFsaWRfaGV4
ID0gdHJ1ZTsKICAgICAgICAgICAgZm9yIChzaXplX3QgaGkgPSAwOyBoaSA8IGhleF9zdHIuc2l6
ZSgpOyArK2hpKSB7CiAgICAgICAgICAgICAgaWYgKCFpc3hkaWdpdCgodW5zaWduZWQgY2hhcilo
ZXhfc3RyW2hpXSkpIHsgdmFsaWRfaGV4ID0gZmFsc2U7IGJyZWFrOyB9CiAgICAgICAgICAgIH0K
ICAgICAgICAgICAgaWYgKCF2YWxpZF9oZXgpIHsKICAgICAgICAgICAgICByZmwuY2xlYXJfYnVm
ZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICAg
IGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGNoYXIgKmVuZHB0ciA9IE5VTEw7CiAg
ICAgICAgICAgIGVycm5vID0gMDsKICAgICAgICAgICAgdW5zaWduZWQgbG9uZyBsb25nIHBhcnNl
ZF9sZW4gPSBzdHJ0b3VsbChoZXhfc3RyLmNfc3RyKCksICZlbmRwdHIsIDE2KTsKICAgICAgICAg
ICAgaWYgKGVycm5vICE9IDAgfHwgZW5kcHRyICE9IGhleF9zdHIuY19zdHIoKSArIGhleF9zdHIu
c2l6ZSgpIHx8IHBhcnNlZF9sZW4gPiAxNjc3NzIxNlVMTCkgewogICAgICAgICAgICAgIHJmbC5j
bGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAg
ICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgw
LCBjcmxmICsgMik7CiAgICAgICAgICAgIGlmIChwYXJzZWRfbGVuID09IDApIHsKICAgICAgICAg
ICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gdHJ1ZTsKICAgICAgICAgICAgICByZmwu
Y2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsKICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAg
ICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcg
PSAoc2l6ZV90KXBhcnNlZF9sZW47CiAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVu
ID0gZmFsc2U7CiAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IGZhbHNlOwog
ICAgICAgICAgICB9CiAgICAgICAgICB9IGVsc2UgaWYgKHJmbC5jaHVua19yZWFkaW5nX2NybGYp
IHsKICAgICAgICAgICAgaWYgKHJmbC5idWYuc2l6ZSgpIDwgMikgYnJlYWs7CiAgICAgICAgICAg
IGlmIChyZmwuYnVmWzBdICE9ICdccicgfHwgcmZsLmJ1ZlsxXSAhPSAnXG4nKSB7CiAgICAgICAg
ICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0g
dHJ1ZTsKICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgfQogICAgICAgICAgICByZmwu
YnVmX2VyYXNlKDAsIDIpOwogICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFs
c2U7CiAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IHRydWU7CiAgICAgICAgICB9
IGVsc2UgewogICAgICAgICAgICBzaXplX3QgdG9fY29uc3VtZSA9IChyZmwuYnVmLnNpemUoKSA8
IHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZykgPyByZmwuYnVmLnNpemUoKSA6IHJmbC5jaHVu
a19wYXlsb2FkX3JlbWFpbmluZzsKICAgICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCB0b19jb25z
dW1lKTsKICAgICAgICAgICAgcmZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nIC09IHRvX2NvbnN1
bWU7CiAgICAgICAgICAgIGlmIChyZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPT0gMCkgewog
ICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2NybGYgPSB0cnVlOwogICAgICAgICAgICB9
CiAgICAgICAgICB9CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CgogICAgICAgIGlmIChy
Zmwuc3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFURV9DTE9TRV9CT0RZKSB7CiAgICAgICAgICByZmwu
YnVmX2VyYXNlKDAsIHJmbC5idWYuc2l6ZSgpKTsKICAgICAgICAgIGJyZWFrOwogICAgICAgIH0K
ICAgICAgfQogICAgfQoKICAgIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7IC8vIFNlcnZlciBGSU4g
b3IgUlNUCiAgICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBpdCA9IGZsb3dz
LmZpbmQocmZrKTsKICAgICAgaWYgKGl0ICE9IGZsb3dzLmVuZCgpKSB7CiAgICAgICAgaXQtPnNl
Y29uZC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgZmxvd3MuZXJhc2UoaXQpOwogICAgICB9CiAg
ICB9CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIC8vIERpcmVjdGlvbiBCOiBDbGllbnQgLT4gU2Vy
dmVyIFJlcXVlc3QgUmVhc3NlbWJseQogIGlmICghZHN0X21vbikgewogICAgaWYgKHRjcF9mbGFn
cyAmIDB4MDUpIHsKICAgICAgRmxvd0tleSByZms7IHJmay5zX2lwID0gZF9pcDsgcmZrLnNwb3J0
ID0gKHVpbnQxNl90KWRwb3J0OyByZmsuZF9pcCA9IHNfaXA7IHJmay5kcG9ydCA9ICh1aW50MTZf
dClzcG9ydDsKICAgICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGl0ID0gZmxv
d3MuZmluZChyZmspOwogICAgICBpZiAoaXQgIT0gZmxvd3MuZW5kKCkpIHsKICAgICAgICBpdC0+
c2Vjb25kLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICBmbG93cy5lcmFzZShpdCk7CiAgICAgIH0K
ICAgIH0KICAgIHJldHVybiBmYWxzZTsKICB9CgogIEZsb3dLZXkgZms7CiAgZmsuc19pcCA9IHNf
aXA7IGZrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OyBmay5kX2lwID0gZF9pcDsgZmsuZHBvcnQg
PSAodWludDE2X3QpZHBvcnQ7CgogIGlmICh0Y3BfZmxhZ3MgJiAweDAyKSB7IC8vIFNZTiBmcm9t
IGNsaWVudDogbmV3IGNvbm5lY3Rpb24gZ2VuZXJhdGlvbiEKICAgIGV2aWN0X29sZGVzdF9mbG93
X2lmX25lZWRlZChmbG93cywgcGVuZGluZyk7CiAgICBQYWNrZXRLZXkgcms7IHJrLnNfaXAgPSBk
X2lwOyByay5zcG9ydCA9ICh1aW50MTZfdClkcG9ydDsgcmsuZF9pcCA9IHNfaXA7IHJrLmRwb3J0
ID0gKHVpbnQxNl90KXNwb3J0OwoKICAgIC8vIFB1cmdlIHByZXZpb3VzIGdlbmVyYXRpb24ncyBw
ZW5kaW5nIHJlcXVlc3RzIGZvciB0aGlzIDQtdHVwbGUKICAgIHN0ZDo6bWFwPFBhY2tldEtleSwg
c3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCA9IHBlbmRpbmcuZmluZChyayk7CiAg
ICBpZiAocCAhPSBwZW5kaW5nLmVuZCgpKSB7CiAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwg
cC0+c2Vjb25kLnNpemUoKTsgKytpKSB7CiAgICAgICAgaWYgKCFwLT5zZWNvbmRbaV0uaXNfdG9t
YnN0b25lKSB7CiAgICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAgICAg
ICBpZiAoZ190b3RhbF9wZW5kaW5nX2NvdW50ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7
CiAgICAgICAgfQogICAgICB9CiAgICAgIHBlbmRpbmcuZXJhc2UocCk7CiAgICB9CiAgICAvLyBS
ZS1lbmFibGUgY29ycmVsYXRpb24gZm9yIHRoaXMgNC10dXBsZTogU1lOIHByb3ZlcyBhIGZyZXNo
IFRDUCBjb25uZWN0aW9uCiAgICAvLyB3aXRoIG5vIGFtYmlndW91cyBvcmRlcmluZyBzdGF0ZSBm
cm9tIHRoZSBwcmV2aW91cyBzdHJlYW0uCiAgICBnX2NvcnJfZGlzYWJsZWQuZXJhc2UocmspOwoK
ICAgIEZsb3cgJmZsID0gZmxvd3NbZmtdOwogICAgaWYgKGZsLmF3YWl0aW5nX3dzc2UpIHsKICAg
ICAgaWYgKCFmbC53c3NlX2V2ZW50Lm1ldGhvZC5lbXB0eSgpKSB7CiAgICAgICAgZW1pdF9ldmVu
dChmbC53c3NlX2V2ZW50KTsKICAgICAgfQogICAgICBmbC5hd2FpdGluZ193c3NlID0gZmFsc2U7
CiAgICB9CiAgICB1aW50MzJfdCBuZXh0X2dlbiA9IGZsLmdlbmVyYXRpb24gKyAxOwogICAgZmwu
Y2xlYXJfYnVmZmVycygpOwogICAgZmwgPSBGbG93KCk7CiAgICBmbC5nZW5lcmF0aW9uID0gbmV4
dF9nZW47CiAgICBmbC5oYXNfc2VxID0gdHJ1ZTsKICAgIGZsLm5leHRfc2VxID0gc2VxICsgMTsK
ICAgIGZsLnRvdWNoZWQgPSBub3c7CiAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSAwOwoKICAg
IC8vIFJlc2V0IHNlcnZlciByZXNwb25zZSBmbG93IGZvciB0aGlzIDQtdHVwbGUgYW5kIGNhcnJ5
IGZvcndhcmQgbmV3IGdlbmVyYXRpb24KICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVy
YXRvciByZml0ID0gZmxvd3MuZmluZChyayk7CiAgICBpZiAocmZpdCAhPSBmbG93cy5lbmQoKSkg
ewogICAgICByZml0LT5zZWNvbmQuY2xlYXJfYnVmZmVycygpOwogICAgfQogICAgRmxvdyAmcmVz
cF9mbCA9IGZsb3dzW3JrXTsKICAgIHJlc3BfZmwgPSBGbG93KCk7CiAgICByZXNwX2ZsLmdlbmVy
YXRpb24gPSBuZXh0X2dlbjsKICAgIHJldHVybiB0cnVlOwogIH0KCiAgZXZpY3Rfb2xkZXN0X2Zs
b3dfaWZfbmVlZGVkKGZsb3dzLCBwZW5kaW5nKTsKICBGbG93ICZmbCA9IGZsb3dzW2ZrXTsKICBm
bC50b3VjaGVkID0gbm93OwoKICBpZiAocGxlbiA+IDApIHsKICAgIGlmICghZmwuaGFzX3NlcSkg
ewogICAgICBpZiAoaXNfbWV0aG9kX29yX3ByZWZpeChwYXlsb2FkLCBwbGVuKSkgewogICAgICAg
IGZsLmhhc19zZXEgPSB0cnVlOwogICAgICAgIGZsLm5leHRfc2VxID0gc2VxOwogICAgICAgIGZs
LmlzX2Jyb2tlbiA9IGZhbHNlOwogICAgICB9IGVsc2UgewogICAgICAgIGlmIChmbC5vb28uc2l6
ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICBib29s
IGR1cCA9IGZhbHNlOwogICAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBmbC5vb28uc2l6
ZSgpOyArK2kpIHsKICAgICAgICAgICAgaWYgKGZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9
IHRydWU7IGJyZWFrOyB9CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAg
ICAgICBmbC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgfQogICAgICAg
IH0KICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgfQogICAgfQoKICAgIGludDMyX3QgZGlmZiA9
IHNlcV9kaWZmKHNlcSwgZmwubmV4dF9zZXEpOwogICAgaWYgKGRpZmYgPT0gMCkgewogICAgICBp
ZiAoaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgfSBl
bHNlIHsKICAgICAgICBpZiAoIWZsLmJ1Zl9hcHBlbmQocGF5bG9hZCwgcGxlbikpIHJldHVybiB0
cnVlOwogICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClwbGVuOwogICAgICAgIGlmICgh
ZHJhaW5fb29vX3NlZ21lbnRzKGZsKSkgcmV0dXJuIHRydWU7CiAgICAgIH0KICAgIH0gZWxzZSBp
ZiAoZGlmZiA8IDApIHsKICAgICAgaW50MzJfdCBvdmVybGFwID0gLWRpZmY7CiAgICAgIGlmICgo
c2l6ZV90KW92ZXJsYXAgPCBwbGVuICYmICFpc190cnVuY2F0ZWQpIHsKICAgICAgICBzaXplX3Qg
ZmxlbiA9IHBsZW4gLSBvdmVybGFwOwogICAgICAgIGlmICghZmwuYnVmX2FwcGVuZChwYXlsb2Fk
ICsgb3ZlcmxhcCwgZmxlbikpIHJldHVybiB0cnVlOwogICAgICAgIGZsLm5leHRfc2VxICs9ICh1
aW50MzJfdClmbGVuOwogICAgICAgIGlmICghZHJhaW5fb29vX3NlZ21lbnRzKGZsKSkgcmV0dXJu
IHRydWU7CiAgICAgIH0KICAgIH0gZWxzZSB7IC8vIGRpZmYgPiAwIChvdXQgb2Ygb3JkZXIgZ2Fw
KQogICAgICBpZiAoZmwub29vLnNpemUoKSA8IE1BWF9PT09fU0VHTUVOVFMgJiYgIWlzX3RydW5j
YXRlZCkgewogICAgICAgIGJvb2wgZHVwID0gZmFsc2U7CiAgICAgICAgZm9yIChzaXplX3QgaSA9
IDA7IGkgPCBmbC5vb28uc2l6ZSgpOyArK2kpIHsKICAgICAgICAgIGlmIChmbC5vb29baV0uc2Vx
ID09IHNlcSkgeyBkdXAgPSB0cnVlOyBicmVhazsgfQogICAgICAgIH0KICAgICAgICBpZiAoIWR1
cCkgewogICAgICAgICAgZmwub29vX3B1c2goc2VxLCBwYXlsb2FkLCBwbGVuKTsKICAgICAgICB9
CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgfQogICAg
fQoKICAgIC8vIEhUVFAgRnJhbWluZyBTdGF0ZSBNYWNoaW5lIGZvciByZXF1ZXN0cwogICAgd2hp
bGUgKCFmbC5idWYuZW1wdHkoKSAmJiAhZmwuaXNfYnJva2VuKSB7CiAgICAgIGlmIChmbC5zdGF0
ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUikgewogICAgICAgIGlmICghZmwuZmlyc3RfYnl0
ZV9tb25vX21zKSBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSBtb25vX25vdzsKCiAgICAgICAgc2l6
ZV90IGVuZCA9IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAgIGlmIChlbmQgPT0gc3Rk
OjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgIGlmIChmbC5idWYuc2l6ZSgpID4gTUFYX0hFQURF
Ul9CWVRFUykgewogICAgICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZs
LmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICB9CiAgICAgICAgICBicmVhazsKICAgICAgICB9
CgogICAgICAgIHNpemVfdCBzdGFydCA9IGZpbmRfaHR0cF9zdGFydChmbC5idWYpOwogICAgICAg
IGlmIChzdGFydCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBzdGFydCA+IGVuZCkgewogICAgICAg
ICAgZmwuYnVmX2VyYXNlKDAsIGVuZCArIDQpOwogICAgICAgICAgY29udGludWU7CiAgICAgICAg
fQogICAgICAgIGlmIChzdGFydCA+IDApIHsKICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBzdGFy
dCk7CiAgICAgICAgICBlbmQgLT0gc3RhcnQ7CiAgICAgICAgfQoKICAgICAgICBFdmVudCBlOyBS
ZXF1ZXN0TWV0YSBtZXRhOwogICAgICAgIGUudHMgPSBub3c7IGUuaG9zdCA9IG5vZGU7IGUuc2Vy
dmljZSA9ICJwb3J0OiIgKyBudW0oZHBvcnQpOwogICAgICAgIGUuY2FsbGVyID0gaXBfdG9fc3Ry
KHNfaXApOyBlLmNhbGxlcl9wb3J0ID0gc3BvcnQ7CiAgICAgICAgZS5kc3RfaXAgPSBpcF90b19z
dHIoZF9pcCk7IGUuZHN0X3BvcnQgPSBkcG9ydDsKICAgICAgICBlLnJlcV9ieXRlcyA9ICh1bnNp
Z25lZCkoZW5kICsgNCk7CgogICAgICAgIGlmICghcGFyc2VfcmVxdWVzdChmbC5idWYuZGF0YSgp
LCBlbmQgKyAyLCAmZSwgJm1ldGEpKSB7CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgZW5kICsg
NCk7CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CgogICAgICAgIC8vIFJlamVjdCBjb25m
bGljdGluZyBDb250ZW50LUxlbmd0aCArIGNodW5rZWQgZW5jb2RpbmcgKFJGQyA3MjMwIHJlcXVl
c3Qgc211Z2dsaW5nIHByZXZlbnRpb24pCiAgICAgICAgYm9vbCBoYXNfY2h1bmtlZCA9IChsb3dl
cihtZXRhLnRyYW5zZmVyX2VuY29kaW5nKS5maW5kKCJjaHVua2VkIikgIT0gc3RkOjpzdHJpbmc6
Om5wb3MpOwogICAgICAgIGlmIChtZXRhLmhhc19jb25mbGljdF9jbCB8fCAobWV0YS5oYXNfY29u
dGVudF9sZW5ndGggJiYgaGFzX2NodW5rZWQpKSB7CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwg
ZW5kICsgNCk7CiAgICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICBmbC5pc19i
cm9rZW4gPSB0cnVlOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQoKICAgICAgICBmbC5idWZf
ZXJhc2UoMCwgZW5kICsgNCk7CgogICAgICAgIGJvb2wgd3NzZV9lbGlnaWJsZSA9IChnX3dzc2Vf
Ym9keV9ieXRlcyA+IDAgJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaXNfc29hcF9j
b250ZW50X3R5cGUobWV0YS5jb250ZW50X3R5cGUpICYmCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIG1ldGEuaGFzX2NvbnRlbnRfbGVuZ3RoICYmCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIG1ldGEuY29udGVudF9sZW5ndGggPiAwICYmCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICFoYXNfY2h1bmtlZCAmJgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3Rp
dmVfd3NzZV9mbG93cyhmbG93cykgPCBNQVhfV1NTRV9CT0RZX0ZMT1dTKTsKCiAgICAgICAgaWYg
KHdzc2VfZWxpZ2libGUpIHsKICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSB0cnVlOwogICAg
ICAgICAgZmwud3NzZV9ldmVudCA9IGU7CiAgICAgICAgICBmbG93X2J5dGVzX3N1YihmbC53c3Nl
X2J1Zi5zaXplKCkpOwogICAgICAgICAgZmwud3NzZV9idWYuY2xlYXIoKTsKICAgICAgICAgIGZs
Lndzc2VfZ29hbCA9IG1ldGEuY29udGVudF9sZW5ndGggPCBnX3dzc2VfYm9keV9ieXRlcyA/IG1l
dGEuY29udGVudF9sZW5ndGggOiBnX3dzc2VfYm9keV9ieXRlczsKICAgICAgICB9IGVsc2Ugewog
ICAgICAgICAgcXVldWVfcmVxdWVzdChlLCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRp
bmcsIGZsLmZpcnN0X2J5dGVfbW9ub19tcywgZmwuZ2VuZXJhdGlvbik7CiAgICAgICAgfQoKICAg
ICAgICBpZiAobWV0YS5oYXNfY29udGVudF9sZW5ndGggJiYgbWV0YS5jb250ZW50X2xlbmd0aCA+
IDApIHsKICAgICAgICAgIGZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9CT0RZOwogICAgICAg
ICAgZmwuYm9keV9yZW1haW5pbmcgPSBtZXRhLmNvbnRlbnRfbGVuZ3RoOwogICAgICAgIH0gZWxz
ZSBpZiAoaGFzX2NodW5rZWQpIHsKICAgICAgICAgIGZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFU
RV9DSFVOSzsKICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gdHJ1ZTsKICAgICAgICAg
IGZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IGZhbHNlOwogICAgICAgICAgZmwuY2h1bmtfcmVhZGlu
Z190cmFpbGVyID0gZmFsc2U7CiAgICAgICAgICBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9
IDA7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFU
RV9IRUFERVI7CiAgICAgICAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSBmbC5idWYuZW1wdHko
KSA/IDAgOiBtb25vX25vdzsKICAgICAgICB9CiAgICAgICAgY29udGludWU7CiAgICAgIH0KCiAg
ICAgIGlmIChmbC5zdGF0ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0JPRFkpIHsKICAgICAgICBpZiAo
ZmwuYnVmLmVtcHR5KCkpIGJyZWFrOwogICAgICAgIHNpemVfdCB0b19jb25zdW1lID0gKGZsLmJ1
Zi5zaXplKCkgPCBmbC5ib2R5X3JlbWFpbmluZykgPyBmbC5idWYuc2l6ZSgpIDogZmwuYm9keV9y
ZW1haW5pbmc7CgogICAgICAgIGlmIChmbC5hd2FpdGluZ193c3NlKSB7CiAgICAgICAgICBzaXpl
X3Qgd3NzZV9uZWVkID0gZmwud3NzZV9nb2FsID4gZmwud3NzZV9idWYuc2l6ZSgpID8gZmwud3Nz
ZV9nb2FsIC0gZmwud3NzZV9idWYuc2l6ZSgpIDogMDsKICAgICAgICAgIGlmICh3c3NlX25lZWQg
PiAwKSB7CiAgICAgICAgICAgIHNpemVfdCBjb3B5X2xlbiA9ICh0b19jb25zdW1lIDwgd3NzZV9u
ZWVkKSA/IHRvX2NvbnN1bWUgOiB3c3NlX25lZWQ7CiAgICAgICAgICAgIGZsLndzc2VfYXBwZW5k
KGZsLmJ1Zi5kYXRhKCksIGNvcHlfbGVuKTsKICAgICAgICAgIH0KICAgICAgICAgIHN0ZDo6c3Ry
aW5nIHVzZXJuYW1lID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLndzc2VfYnVmKTsKICAgICAg
ICAgIGlmICghdXNlcm5hbWUuZW1wdHkoKSB8fCBmbC53c3NlX2J1Zi5zaXplKCkgPj0gZmwud3Nz
ZV9nb2FsKSB7CiAgICAgICAgICAgIEV2ZW50IGV2ID0gZmwud3NzZV9ldmVudDsKICAgICAgICAg
ICAgaWYgKCF1c2VybmFtZS5lbXB0eSgpKSB7CiAgICAgICAgICAgICAgZXYud3NzZV91c2VyID0g
dXNlcm5hbWU7IGV2LnVzZXIgPSB1c2VybmFtZTsgZXYuc2NoZW1lID0gIndzc2UiOwogICAgICAg
ICAgICB9CiAgICAgICAgICAgIHF1ZXVlX3JlcXVlc3QoZXYsIHNfaXAsIHNwb3J0LCBkX2lwLCBk
cG9ydCwgcGVuZGluZywgZmwuZmlyc3RfYnl0ZV9tb25vX21zLCBmbC5nZW5lcmF0aW9uKTsKICAg
ICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IGZhbHNlOwogICAgICAgICAgfQogICAgICAgIH0K
CiAgICAgICAgZmwuYnVmX2VyYXNlKDAsIHRvX2NvbnN1bWUpOwogICAgICAgIGZsLmJvZHlfcmVt
YWluaW5nIC09IHRvX2NvbnN1bWU7CiAgICAgICAgaWYgKGZsLmJvZHlfcmVtYWluaW5nID09IDAp
IHsKICAgICAgICAgIGlmIChmbC5hd2FpdGluZ193c3NlKSB7CiAgICAgICAgICAgIHF1ZXVlX3Jl
cXVlc3QoZmwud3NzZV9ldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nLCBm
bC5maXJzdF9ieXRlX21vbm9fbXMsIGZsLmdlbmVyYXRpb24pOwogICAgICAgICAgICBmbC5hd2Fp
dGluZ193c3NlID0gZmFsc2U7CiAgICAgICAgICB9CiAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6
OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgZmwuZmlyc3RfYnl0ZV9tb25vX21zID0gZmwu
YnVmLmVtcHR5KCkgPyAwIDogbW9ub19ub3c7CiAgICAgICAgfQogICAgICAgIGNvbnRpbnVlOwog
ICAgICB9CgogICAgICBpZiAoZmwuc3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFURV9DSFVOSykgewog
ICAgICAgIGlmIChmbC5idWYuZW1wdHkoKSkgYnJlYWs7CiAgICAgICAgaWYgKGZsLmNodW5rX3Jl
YWRpbmdfdHJhaWxlcikgewogICAgICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPj0gMiAmJiBmbC5i
dWZbMF0gPT0gJ1xyJyAmJiBmbC5idWZbMV0gPT0gJ1xuJykgewogICAgICAgICAgICBmbC5idWZf
ZXJhc2UoMCwgMik7CiAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IGZhbHNl
OwogICAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAg
ICAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSBmbC5idWYuZW1wdHkoKSA/IDAgOiBtb25vX25v
dzsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICB9CiAgICAgICAgICBzaXplX3QgdHJf
ZW5kID0gZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAgICAgICAgICBpZiAodHJfZW5kICE9IHN0
ZDo6c3RyaW5nOjpucG9zKSB7CiAgICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCB0cl9lbmQgKyA0
KTsKICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gZmFsc2U7CiAgICAgICAg
ICAgIGZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9IRUFERVI7CiAgICAgICAgICAgIGZsLmZp
cnN0X2J5dGVfbW9ub19tcyA9IGZsLmJ1Zi5lbXB0eSgpID8gMCA6IG1vbm9fbm93OwogICAgICAg
ICAgICBjb250aW51ZTsKICAgICAgICAgIH0KICAgICAgICAgIGlmIChmbC5idWYuc2l6ZSgpID4g
TUFYX0hFQURFUl9CWVRFUykgewogICAgICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAg
ICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICB9CiAgICAgICAgICBicmVhazsK
ICAgICAgICB9CiAgICAgICAgaWYgKGZsLmNodW5rX3JlYWRpbmdfbGVuKSB7CiAgICAgICAgICBz
aXplX3QgY3JsZiA9IGZsLmJ1Zi5maW5kKCJcclxuIik7CiAgICAgICAgICBpZiAoY3JsZiA9PSBz
dGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgICBpZiAoZmwuYnVmLnNpemUoKSA+IDY0KSB7
CiAgICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICAgIGZsLmlzX2Jy
b2tlbiA9IHRydWU7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9
CiAgICAgICAgICBzdGQ6OnN0cmluZyBsaW5lID0gdHJpbShmbC5idWYuc3Vic3RyKDAsIGNybGYp
KTsKICAgICAgICAgIHNpemVfdCBzZW1pID0gbGluZS5maW5kKCc7Jyk7CiAgICAgICAgICBzdGQ6
OnN0cmluZyBoZXhfc3RyID0gKHNlbWkgIT0gc3RkOjpzdHJpbmc6Om5wb3MpID8gdHJpbShsaW5l
LnN1YnN0cigwLCBzZW1pKSkgOiBsaW5lOwogICAgICAgICAgaWYgKGhleF9zdHIuZW1wdHkoKSB8
fCBoZXhfc3RyLnNpemUoKSA+IDE2KSB7CiAgICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsK
ICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgYnJlYWs7CiAgICAg
ICAgICB9CiAgICAgICAgICBib29sIHZhbGlkX2hleCA9IHRydWU7CiAgICAgICAgICBmb3IgKHNp
emVfdCBoaSA9IDA7IGhpIDwgaGV4X3N0ci5zaXplKCk7ICsraGkpIHsKICAgICAgICAgICAgaWYg
KCFpc3hkaWdpdCgodW5zaWduZWQgY2hhciloZXhfc3RyW2hpXSkpIHsgdmFsaWRfaGV4ID0gZmFs
c2U7IGJyZWFrOyB9CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIXZhbGlkX2hleCkgewogICAg
ICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRy
dWU7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgfQogICAgICAgICAgY2hhciAqZW5kcHRy
ID0gTlVMTDsKICAgICAgICAgIGVycm5vID0gMDsKICAgICAgICAgIHVuc2lnbmVkIGxvbmcgbG9u
ZyBwYXJzZWRfbGVuID0gc3RydG91bGwoaGV4X3N0ci5jX3N0cigpLCAmZW5kcHRyLCAxNik7CiAg
ICAgICAgICBpZiAoZXJybm8gIT0gMCB8fCBlbmRwdHIgIT0gaGV4X3N0ci5jX3N0cigpICsgaGV4
X3N0ci5zaXplKCkgfHwgcGFyc2VkX2xlbiA+IDE2Nzc3MjE2VUxMKSB7CiAgICAgICAgICAgIGZs
LmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAg
ICAgICAgYnJlYWs7CiAgICAgICAgICB9CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgY3JsZiAr
IDIpOwogICAgICAgICAgaWYgKHBhcnNlZF9sZW4gPT0gMCkgewogICAgICAgICAgICBmbC5jaHVu
a19yZWFkaW5nX3RyYWlsZXIgPSB0cnVlOwogICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xl
biA9IGZhbHNlOwogICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgIH0gZWxzZSB7CiAgICAg
ICAgICAgIGZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gKHNpemVfdClwYXJzZWRfbGVuOwog
ICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xlbiA9IGZhbHNlOwogICAgICAgICAgICBmbC5j
aHVua19yZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgaWYg
KGZsLmNodW5rX3JlYWRpbmdfY3JsZikgewogICAgICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPCAy
KSBicmVhazsKICAgICAgICAgIGlmIChmbC5idWZbMF0gIT0gJ1xyJyB8fCBmbC5idWZbMV0gIT0g
J1xuJykgewogICAgICAgICAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgIGZsLmlz
X2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgfQogICAgICAgICAg
ZmwuYnVmX2VyYXNlKDAsIDIpOwogICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFs
c2U7CiAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xlbiA9IHRydWU7CiAgICAgICAgfSBlbHNl
IHsKICAgICAgICAgIHNpemVfdCB0b19jb25zdW1lID0gKGZsLmJ1Zi5zaXplKCkgPCBmbC5jaHVu
a19wYXlsb2FkX3JlbWFpbmluZykgPyBmbC5idWYuc2l6ZSgpIDogZmwuY2h1bmtfcGF5bG9hZF9y
ZW1haW5pbmc7CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgdG9fY29uc3VtZSk7CiAgICAgICAg
ICBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyAtPSB0b19jb25zdW1lOwogICAgICAgICAgaWYg
KGZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID09IDApIHsKICAgICAgICAgICAgZmwuY2h1bmtf
cmVhZGluZ19jcmxmID0gdHJ1ZTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgY29udGlu
dWU7CiAgICAgIH0KICAgIH0KICB9CgogIC8vIEZJTiAvIFJTVCBMaWZlY3ljbGU6IHByb2Nlc3Mg
YWZ0ZXIgcGF5bG9hZAogIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7CiAgICBpZiAoZmwuYXdhaXRp
bmdfd3NzZSkgewogICAgICBxdWV1ZV9yZXF1ZXN0KGZsLndzc2VfZXZlbnQsIHNfaXAsIHNwb3J0
LCBkX2lwLCBkcG9ydCwgcGVuZGluZywgZmwuZmlyc3RfYnl0ZV9tb25vX21zLCBmbC5nZW5lcmF0
aW9uKTsKICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IGZhbHNlOwogICAgfQogICAgZmwuY2xlYXJf
YnVmZmVycygpOwogICAgZmxvd3MuZXJhc2UoZmspOwogIH0KCiAgcmV0dXJuIHRydWU7Cn0KCnN0
YXRpYyBib29sIGF0dGFjaF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4g
JnBvcnRzKSB7CiAgaWYgKHBvcnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OnZlY3Rv
cjxzdHJ1Y3Qgc29ja19maWx0ZXI+IGY7IHNpemVfdCBpOwogIHVuc2lnbmVkIE4gPSAodW5zaWdu
ZWQpcG9ydHMuc2l6ZSgpOwogIHVuc2lnbmVkIHJlamVjdCA9IDExICsgTiAqIDg7CiAgdW5zaWdu
ZWQgYWNjZXB0ID0gcmVqZWN0ICsgMTsKICBzdHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmluZSBB
REQoQyxKLFQsSykgZG8geyBcCiAgdW5zaWduZWQgX2p0ID0gKHVuc2lnbmVkKShKKSwgX2pmID0g
KHVuc2lnbmVkKShUKTsgXAogIGlmIChfanQgPiBVQ0hBUl9NQVggfHwgX2pmID4gVUNIQVJfTUFY
KSByZXR1cm4gZmFsc2U7IFwKICB4LmNvZGU9KEMpOyB4Lmp0PSh1bnNpZ25lZCBjaGFyKV9qdDsg
eC5qZj0odW5zaWduZWQgY2hhcilfamY7IHguaz0oSyk7IFwKICBmLnB1c2hfYmFjayh4KTsgXAp9
IHdoaWxlKDApCiAgQUREKEJQRl9MRHxCUEZfSHxCUEZfQUJTLCAwLCAwLCAxMik7CiAgQUREKEJQ
Rl9KTVB8QlBGX0pFUXxCUEZfSywgKHVuc2lnbmVkKSg2ICsgNCAqIE4pLCAwLCBFVEhfUF9JUF9I
T1NUKTsKCiAgLy8gUGF0aCBCOiA4MDIuMVEgVkxBTgogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBG
X0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9Q
XzgwMjFRX0hPU1QpOwogIEFERChCUEZfTER8QlBGX0h8QlBGX0FCUywgMCwgMCwgMTYpOwogIEFE
RChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVk
KWYuc2l6ZSgpIC0gMSksIEVUSF9QX0lQX0hPU1QpOwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FC
UywgMCwgMCwgMjcpOwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCko
cmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICBBREQoQlBG
X0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxOCk7CiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNp
emUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDIwKTsKICAg
IHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIEFERChC
UEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCAwLCBwb3J0c1tpXSk7CiAgfQogIGZvciAoaSA9IDA7
IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAw
LCAwLCAxOCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAt
IDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwgcG9ydHMuc2l6ZSgpIC0gMSkgPyAwIDogKHJlamVj
dCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZf
SywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQoKICAvLyBQYXRoIEE6IFN0YW5kYXJkIElQdjQKICBB
REQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsIDAsIDAsIDIzKTsKICBBREQoQlBGX0pNUHxCUEZfSkVR
fEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJ
UFBST1RPX1RDUCk7CiAgQUREKEJQRl9MRFh8QlBGX0J8QlBGX01TSCwgMCwgMCwgMTQpOwogIGZv
ciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxC
UEZfSU5ELCAwLCAwLCAxNik7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClm
LnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNb
aV0pOwogIH0KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChC
UEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTQpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQg
LSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNp
emUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFE
RChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgQUREKEJQ
Rl9SRVR8QlBGX0ssIDAsIDAsIDApOwogIEFERChCUEZfUkVUfEJQRl9LLCAwLCAwLCBBQ0NFUFQp
OwojdW5kZWYgQURECiAgaWYgKGYuc2l6ZSgpID4gNDA5NikgcmV0dXJuIGZhbHNlOwogIHN0cnVj
dCBzb2NrX2Zwcm9nIHByb2c7IHByb2cubGVuID0gKHVuc2lnbmVkIHNob3J0KWYuc2l6ZSgpOyBw
cm9nLmZpbHRlciA9ICZmWzBdOwogIHJldHVybiBzZXRzb2Nrb3B0KGZkLCBTT0xfU09DS0VULCBT
T19BVFRBQ0hfRklMVEVSX09MRCwgJnByb2csIHNpemVvZihwcm9nKSkgPT0gMDsKfQoKc3RydWN0
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
ewogIE1tYXBSaW5nIG1yOwogIHVpbnQ4X3QgZnJhbWVbMjA0OF07CiAgbWVtc2V0KGZyYW1lLCAw
LCBzaXplb2YoZnJhbWUpKTsKICBzdHJ1Y3QgdHBhY2tldDJfaGRyICpoZHIgPSAoc3RydWN0IHRw
YWNrZXQyX2hkciAqKWZyYW1lOwogIGhkci0+dHBfbWFjID0gVFBBQ0tFVDJfSERSTEVOOwogIGhk
ci0+dHBfbmV0ID0gVFBBQ0tFVDJfSERSTEVOOwogIGhkci0+dHBfc25hcGxlbiA9IDEyODsKICBo
ZHItPnRwX2xlbiA9IDEyODsKICBzaXplX3Qgb2ZmID0gMCwgbGVuID0gMDsKICBpZiAoIXZhbGlk
X3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSB8fAogICAgICBvZmYg
IT0gVFBBQ0tFVDJfSERSTEVOIHx8IGxlbiAhPSAxMjgpIHJldHVybiAyMTsKICBoZHItPnRwX21h
YyA9IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXpl
b2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDIyOwogIGhkci0+dHBfbWFjID0gVFBBQ0tF
VDJfSERSTEVOOwogIGhkci0+dHBfc25hcGxlbiA9IHNpemVvZihmcmFtZSk7CiAgaGRyLT50cF9s
ZW4gPSBzaXplb2YoZnJhbWUpOwogIGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZy
YW1lKSwgJm9mZiwgJmxlbikpIHJldHVybiAyMzsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjk7CiAg
aGRyLT50cF9sZW4gPSAxMjg7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJh
bWUpLCAmb2ZmLCAmbGVuKSkgcmV0dXJuIDI0OwogIGhkci0+dHBfc25hcGxlbiA9IDEyODsKICBo
ZHItPnRwX2xlbiA9IDEyODsKICBoZHItPnRwX25ldCA9IFRQQUNLRVQyX0hEUkxFTiAtIDE7CiAg
aWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVuKSkgcmV0
dXJuIDI1OwogIG1yLmZyYW1lX25yKys7CiAgaWYgKHZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSBy
ZXR1cm4gMjY7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2ZpeHR1cmUoKSB7CiAgc3Rk
OjpzdHJpbmcgcmVxID0gIkdFVCAvYXBpL2l0ZW1zP3g9MSBIVFRQLzEuMVxyXG5Ib3N0OiBhcGku
bG9jYWxcclxuQXV0aG9yaXphdGlvbjogQmFzaWMgWVd4cFkyVTZjMlZqY21WMFxyXG5UcmFjZXBh
cmVudDogMDAtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYtMDEyMzQ1Njc4OWFiY2Rl
Zi0wMVxyXG5cclxuIjsKICBFdmVudCBlOyBSZXF1ZXN0TWV0YSBtZXRhOyBlLnRzID0gMTcwMDAw
MDAwMDsgZS5ob3N0ID0gImNwcC1ub2RlIjsgZS5zZXJ2aWNlID0gInBvcnQ6ODA4MCI7IGUuY2Fs
bGVyID0gIjEwLjAuMC45IjsgZS5jYWxsZXJfcG9ydCA9IDUxMDAwOyBlLmRzdF9pcCA9ICIxMC4w
LjAuMiI7IGUuZHN0X3BvcnQgPSA4MDgwOyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZClyZXEuc2l6
ZSgpOyBwYXJzZV9yZXF1ZXN0KHJlcS5kYXRhKCksIHJlcS5zaXplKCkgLSA0LCAmZSwgJm1ldGEp
OyBlLnN0YXR1cyA9IDIwMDsgZS5oYXNfc3RhdHVzID0gdHJ1ZTsgZS5kdXJhdGlvbl9tcyA9IDM7
IGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsgZS5yZXNwX2J5dGVzID0gNDI7IGUuaGFzX3Jlc3AgPSB0
cnVlOyBlbWl0X2V2ZW50KGUpOyByZXR1cm4gMDsKfQoKc3RhdGljIGludCBydW5fd3NzZV9maXh0
dXJlKCkgewogIGNvbnN0IGNoYXIgKm5hbWVzcGFjZXNbXSA9IHsKICAgICJodHRwOi8vZG9jcy5v
YXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS9vYXNpcy0yMDA0MDEtd3NzLXdzc2VjdXJpdHktc2Vj
ZXh0LTEuMC54c2QiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMDcv
c2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzEyL3NlY2V4
dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwMy8wNi9zZWNleHQiCiAg
fTsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDQ7ICsraSkgewogICAgc3RkOjpzdHJpbmcgYm9k
eSA9ICI8czpFbnZlbG9wZSB4bWxuczpzPSd1cm46c29hcCcgeG1sbnM6dz0nIiArIHN0ZDo6c3Ry
aW5nKG5hbWVzcGFjZXNbaV0pICsKICAgICAgIic+PHM6SGVhZGVyPjx3OlVzZXJuYW1lVG9rZW4+
PHc6VXNlcm5hbWU+bmF0aXZlLmZpeHR1cmU8L3c6VXNlcm5hbWU+IgogICAgICAiPHc6UGFzc3dv
cmQ+U0VOU0lUSVZFX1BBU1NXT1JEPC93OlBhc3N3b3JkPjwvdzpVc2VybmFtZVRva2VuPjwvczpI
ZWFkZXI+IjsKICAgIHN0ZDo6c3RyaW5nIHVzZXIgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoYm9k
eSk7CiAgICBpZiAodXNlciAhPSAibmF0aXZlLmZpeHR1cmUiKSByZXR1cm4gMzsKICAgIHN0ZDo6
Y291dCA8PCB1c2VyIDw8ICJcbiI7CiAgfQogIHN0ZDo6c3RyaW5nIG1hbGljaW91cyA9ICI8IURP
Q1RZUEUgeCBbPCFFTlRJVFkgcHcgJ3NlY3JldCc+XT48dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9
JyIgKwogICAgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKyAiJz48dzpVc2VybmFtZT4mcHc7
PC93OlVzZXJuYW1lPjwvdzpVc2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNl
cm5hbWUobWFsaWNpb3VzKS5lbXB0eSgpKSByZXR1cm4gNDsKICBzdGQ6OnN0cmluZyB3cm9uZ19u
cyA9ICI8dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9J3Vybjpub3Qtd3NzZSc+PHc6VXNlcm5hbWU+
d3Jvbmc8L3c6VXNlcm5hbWU+PC93OlVzZXJuYW1lVG9rZW4+IjsKICBpZiAoIWV4dHJhY3Rfd3Nz
ZV91c2VybmFtZSh3cm9uZ19ucykuZW1wdHkoKSkgcmV0dXJuIDU7CiAgc3RkOjpzdHJpbmcgdW5u
YW1lc3BhY2VkID0gIjxVc2VybmFtZVRva2VuPjxVc2VybmFtZT53cm9uZzwvVXNlcm5hbWU+PC9V
c2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5hbWUodW5uYW1lc3BhY2Vk
KS5lbXB0eSgpKSByZXR1cm4gNjsKICBzdGQ6OnN0cmluZyBlc2NhcGVkID0gIjx3OlVzZXJuYW1l
VG9rZW4geG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbMF0pICsKICAgICInPjx3
OlVzZXJuYW1lPm5hdGl2ZSZhbXA7Zml4dHVyZTwvdzpVc2VybmFtZT4iOwogIGlmIChleHRyYWN0
X3dzc2VfdXNlcm5hbWUoZXNjYXBlZCkgIT0gIm5hdGl2ZSZmaXh0dXJlIikgcmV0dXJuIDc7CiAg
c3RkOjpzdHJpbmcgdG9vX2xvbmcgPSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSciICsgc3Rk
OjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKwogICAgIic+PHc6VXNlcm5hbWU+IiArIHN0ZDo6c3Ry
aW5nKE1BWF9XU1NFX1VTRVJOQU1FICsgMSwgJ3gnKSArICI8L3c6VXNlcm5hbWU+IjsKICBpZiAo
IWV4dHJhY3Rfd3NzZV91c2VybmFtZSh0b29fbG9uZykuZW1wdHkoKSkgcmV0dXJuIDg7CiAgcmV0
dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX2R1YWxfYXV0aF9maXh0dXJlKCkgewogIGNvbnN0IHN0
ZDo6c3RyaW5nIGJvZHkgPQogICAgIjxzOkVudmVsb3BlIHhtbG5zOnM9J3Vybjpzb2FwJyB4bWxu
czp3PSdodHRwOi8vZG9jcy5vYXNpcy1vcGVuLm9yZy93c3MvMjAwNC8wMS8iCiAgICAib2FzaXMt
MjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNkJz48czpIZWFkZXI+PHc6VXNlcm5h
bWVUb2tlbj4iCiAgICAiPHc6VXNlcm5hbWU+c29hcC51c2VyPC93OlVzZXJuYW1lPjx3OlBhc3N3
b3JkPlNFTlNJVElWRV9QQVNTV09SRDwvdzpQYXNzd29yZD4iCiAgICAiPC93OlVzZXJuYW1lVG9r
ZW4+PC9zOkhlYWRlcj48L3M6RW52ZWxvcGU+IjsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gcmVxdWVz
dDsKICByZXF1ZXN0IDw8ICJQT1NUIC9zb2FwIEhUVFAvMS4xXHJcbkhvc3Q6IGZpeHR1cmVcclxu
IgogICAgICAgICAgPDwgIkF1dGhvcml6YXRpb246IEJhc2ljIFltRnphV011ZFhObGNqcHdZWE56
ZDI5eVpBPT1cclxuIgogICAgICAgICAgPDwgIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vc29h
cCt4bWxcclxuQ29udGVudC1MZW5ndGg6ICIKICAgICAgICAgIDw8IGJvZHkuc2l6ZSgpIDw8ICJc
clxuXHJcbiIgPDwgYm9keTsKICBjb25zdCBzdGQ6OnN0cmluZyBwYXlsb2FkID0gcmVxdWVzdC5z
dHIoKTsKCiAgc3RkOjp2ZWN0b3I8dW5zaWduZWQgY2hhcj4gcGFja2V0KDE0ICsgMjAgKyAyMCAr
IHBheWxvYWQuc2l6ZSgpLCAwKTsKICBwYWNrZXRbMTJdID0gMHgwODsgcGFja2V0WzEzXSA9IDB4
MDA7CiAgcGFja2V0WzE0XSA9IDB4NDU7IHBhY2tldFsyM10gPSBJUFBST1RPX1RDUDsKICB1aW50
MTZfdCB0b3RfbGVuID0gKHVpbnQxNl90KSgyMCArIDIwICsgcGF5bG9hZC5zaXplKCkpOwogIHBh
Y2tldFsxNl0gPSAodW5zaWduZWQgY2hhcikodG90X2xlbiA+PiA4KTsgcGFja2V0WzE3XSA9ICh1
bnNpZ25lZCBjaGFyKSh0b3RfbGVuICYgMHhmZik7CiAgcGFja2V0WzI2XSA9IDE5MjsgcGFja2V0
WzI3XSA9IDA7IHBhY2tldFsyOF0gPSAyOyBwYWNrZXRbMjldID0gMjsKICBwYWNrZXRbMzBdID0g
MTkyOyBwYWNrZXRbMzFdID0gMDsgcGFja2V0WzMyXSA9IDI7IHBhY2tldFszM10gPSAxOwogIHVu
c2lnbmVkIHNob3J0IHNwb3J0ID0gaHRvbnMoNTEwMDApLCBkcG9ydCA9IGh0b25zKDgwODApOwog
IG1lbWNweSgmcGFja2V0WzM0XSwgJnNwb3J0LCBzaXplb2Yoc3BvcnQpKTsKICBtZW1jcHkoJnBh
Y2tldFszNl0sICZkcG9ydCwgc2l6ZW9mKGRwb3J0KSk7CiAgcGFja2V0WzQ2XSA9IDVVIDw8IDQ7
IHBhY2tldFs0N10gPSAweDE5OwogIG1lbWNweSgmcGFja2V0WzU0XSwgcGF5bG9hZC5kYXRhKCks
IHBheWxvYWQuc2l6ZSgpKTsKCiAgZ193c3NlX2JvZHlfYnl0ZXMgPSA4MTkyOwogIG1lbXNldChn
X21vbml0b3JlZF9wb3J0cywgMCwgc2l6ZW9mKGdfbW9uaXRvcmVkX3BvcnRzKSk7CiAgZ19tb25p
dG9yZWRfcG9ydHNbODA4MF0gPSB0cnVlOwogIGdfZW5kcG9pbnQuY2xlYXIoKTsKICBpbml0X3Ju
ZygpOwogIHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0cygxLCA4MDgwKTsKICBzdGQ6Om1hcDxG
bG93S2V5LCBGbG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBl
bmRpbmc+ID4gcGVuZGluZzsKICBpZiAoIWhhbmRsZV9wYWNrZXQoJnBhY2tldFswXSwgcGFja2V0
LnNpemUoKSwgImNwcC1kdWFsLWZpeHR1cmUiLAogICAgICAgICAgICAgICAgICAgICBwb3J0cywg
Zmxvd3MsIHBlbmRpbmcpKSByZXR1cm4gOTsKICBpZiAoIWZsb3dzLmVtcHR5KCkgfHwgcGVuZGlu
Zy5zaXplKCkgIT0gMSkgcmV0dXJuIDEwOwogIGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwog
IHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1bl9zaGlwX3JhdGVfZml4dHVyZSgpIHsKICBzdGQ6
OnZlY3RvcjxzdGQ6OnN0cmluZz4gZXZlbnRzOwogIGV2ZW50cy5wdXNoX2JhY2soc3RkOjpzdHJp
bmcoNDAwMDAsICd4JykpOwogIGV2ZW50cy5wdXNoX2JhY2soc3RkOjpzdHJpbmcoNDAwMDAsICd5
JykpOwogIGlmIChib3VuZGVkX2JhdGNoX2NvdW50KGV2ZW50cywgImZpeHR1cmUiKSAhPSAxKSBy
ZXR1cm4gMzA7CiAgZXZlbnRzLmNsZWFyKCk7CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmlu
ZyhNQVhfUE9TVF9CWVRFUyArIDEsICd4JykpOwogIGlmIChib3VuZGVkX2JhdGNoX2NvdW50KGV2
ZW50cywgImZpeHR1cmUiKSAhPSAwKSByZXR1cm4gMzE7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBp
bnQgcnVuX3N0YXRzX2ZpeHR1cmUoKSB7CiAgZ19zaGlwX25vZGUgPSAiZml4dHVyZS1ub2RlIjsK
ICBnX2luc3RhbmNlX2lkID0gImZpeHR1cmUtMSI7CiAgZ19zdGF0c19sYXN0X2F0ID0gd2FsbF9z
ZWNvbmRzKCkgLSAzMC4wOwogIGdfY2FwdHVyZV9wYWNrZXRzID0gMTAwOwogIGdfY2FwdHVyZV9i
eXRlcyA9IDY0MDA7CiAgZ19ldmVudHNfZW1pdHRlZCA9IGdfZXZlbnRzX2luID0gMTA7CiAgZ19l
dmVudHNfcHVzaGVkID0gODsKICBnX2V2ZW50c19kcm9wcGVkID0gZ19kcm9wX3F1ZXVlID0gMjsK
ICBzdGQ6OnN0cmluZyBib2R5ID0gYWdlbnRfc3RhdHNfYm9keSgtMSwgMywgMiwgMSk7CiAgaWYg
KGJvZHkuc2l6ZSgpID4gTUFYX1NUQVRTX0JZVEVTKSByZXR1cm4gNDA7CiAgaWYgKGJvZHkuZmlu
ZCgiXCJ0eXBlXCI6XCJhZ2VudF9zdGF0c1wiIikgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVy
biA0MTsKICBpZiAoYm9keS5maW5kKCJcImRyb3BfcGVyY2VudFwiOjIwLjAwMDAiKSA9PSBzdGQ6
OnN0cmluZzo6bnBvcykgcmV0dXJuIDQyOwogIGlmIChib2R5LmZpbmQoIlwibW9kZVwiOlwiY3Bw
XCIiKSA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIDQzOwogIHN0ZDo6Y291dCA8PCBib2R5
IDw8ICJcbiI7CiAgcmV0dXJuIDA7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3dzc2Vfc2l6ZShjb25z
dCBjaGFyICp2YWx1ZSwgc2l6ZV90ICpyZXN1bHQpIHsKICBpZiAoIXZhbHVlIHx8ICEqdmFsdWUp
IHJldHVybiBmYWxzZTsKICBzaXplX3QgbiA9IDA7CiAgaWYgKCFwYXJzZV9kZWNpbWFsX3NpemUo
dmFsdWUsIHN0cmxlbih2YWx1ZSksICZuKSB8fCBuID4gTUFYX1dTU0VfQk9EWV9CWVRFUykgcmV0
dXJuIGZhbHNlOwogICpyZXN1bHQgPSBuOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBk
cm9wX2FsbF9jYXBhYmlsaXRpZXMoKSB7CiAgc3RydWN0IF9fdXNlcl9jYXBfaGVhZGVyX3N0cnVj
dCBoZWFkZXI7CiAgc3RydWN0IF9fdXNlcl9jYXBfZGF0YV9zdHJ1Y3QgZGF0YVsyXTsKICBtZW1z
ZXQoJmhlYWRlciwgMCwgc2l6ZW9mKGhlYWRlcikpOwogIG1lbXNldChkYXRhLCAwLCBzaXplb2Yo
ZGF0YSkpOwogIGhlYWRlci52ZXJzaW9uID0gX0xJTlVYX0NBUEFCSUxJVFlfVkVSU0lPTl8zOwog
IGhlYWRlci5waWQgPSAwOwogIHJldHVybiBzeXNjYWxsKFNZU19jYXBzZXQsICZoZWFkZXIsIGRh
dGEpID09IDA7Cn0KCnN0YXRpYyBpbnQgb3Blbl9jYXB0dXJlX3NvY2tldChjb25zdCBzdGQ6OnN0
cmluZyAmaWZhY2UsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBzdGQ6OnZl
Y3Rvcjx1bnNpZ25lZD4gJnBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTW1h
cFJpbmcgJnJpbmcpIHsKICBpbnQgZmQgPSBzb2NrZXQoQUZfUEFDS0VULCBTT0NLX1JBVywgaHRv
bnMoRVRIX1BfQUxMKSk7CiAgaWYgKGZkIDwgMCkgeyBwZXJyb3IoIkFGX1BBQ0tFVCIpOyByZXR1
cm4gLTE7IH0KICBmY250bChmZCwgRl9TRVRGRCwgRkRfQ0xPRVhFQyk7CiAgaW50IHJiID0gOCAq
IDEwMjQgKiAxMDI0OwogIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX1JDVkJVRiwgJnJi
LCBzaXplb2YocmIpKTsKICBpZiAoIWF0dGFjaF9icGYoZmQsIHBvcnRzKSkgewogICAgbG9nbXNn
KCJCUEYgYXR0YWNoIGZhaWxlZDsgcmVmdXNpbmcgdW5maWx0ZXJlZCBjYXB0dXJlIik7CiAgICBj
bG9zZShmZCk7CiAgICByZXR1cm4gLTE7CiAgfQoKICBzdHJ1Y3Qgc29ja2FkZHJfbGwgc2E7CiAg
bWVtc2V0KCZzYSwgMCwgc2l6ZW9mKHNhKSk7CiAgc2Euc2xsX2ZhbWlseSA9IEFGX1BBQ0tFVDsK
ICBzYS5zbGxfcHJvdG9jb2wgPSBodG9ucyhFVEhfUF9BTEwpOwogIGlmICghaWZhY2UuZW1wdHko
KSkgewogICAgc2Euc2xsX2lmaW5kZXggPSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3Ry
KCkpOwogICAgaWYgKCFzYS5zbGxfaWZpbmRleCkgewogICAgICBsb2dtc2coImJhZCBpbnRlcmZh
Y2UiKTsKICAgICAgY2xvc2UoZmQpOwogICAgICByZXR1cm4gLTE7CiAgICB9CiAgfQogIGlmIChi
aW5kKGZkLCAoc3RydWN0IHNvY2thZGRyICopJnNhLCBzaXplb2Yoc2EpKSA8IDApIHsKICAgIHBl
cnJvcigiYmluZCIpOwogICAgY2xvc2UoZmQpOwogICAgcmV0dXJuIC0xOwogIH0KICBpZiAoIXNl
dHVwX21tYXBfcmluZyhmZCwgcmluZykpIHsKICAgIGxvZ21zZygiVFBBQ0tFVF9WMiBzZXR1cCBm
YWlsZWQ7IHJlZnVzaW5nIG5vbi1yaW5nIGZhbGxiYWNrIik7CiAgICBjbG9zZShmZCk7CiAgICBy
ZXR1cm4gLTE7CiAgfQogIGlmICghZHJvcF9hbGxfY2FwYWJpbGl0aWVzKCkpIHsKICAgIGxvZ21z
ZygiY2FwYWJpbGl0eSBkcm9wIGZhaWxlZDsgcmVmdXNpbmcgdW5zYWZlIGNhcHR1cmUiKTsKICAg
IHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5nKTsKICAgIGNsb3NlKGZkKTsKICAgIHJldHVybiAt
MTsKICB9CiAgcmV0dXJuIGZkOwp9CgpzdGF0aWMgaW50IHJ1bl9jYXBhYmlsaXR5X3Byb2JlKGNv
bnN0IHN0ZDo6c3RyaW5nICZpZmFjZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBj
b25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgTW1hcFJpbmcgcmluZzsKICBp
bnQgZmQgPSBvcGVuX2NhcHR1cmVfc29ja2V0KGlmYWNlLCBwb3J0cywgcmluZyk7CiAgaWYgKGZk
IDwgMCkgcmV0dXJuIDI7CgogIGJvb2wgcmVsZWFzZWQgPSByZWxlYXNlX21tYXBfcmluZyhmZCwg
cmluZyk7CiAgY2xvc2UoZmQpOwogIGlmICghcmVsZWFzZWQpIHsKICAgIGxvZ21zZygiVFBBQ0tF
VF9WMiBwcm9iZSBjbGVhbnVwIGZhaWxlZCIpOwogICAgcmV0dXJuIDI7CiAgfQogIHJldHVybiAw
Owp9CgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqKmFyZ3YpIHsKICBpZiAoYXJnYyA+IDEgJiYg
IXN0cmNtcChhcmd2WzFdLCAiLS1maXh0dXJlIikpIHJldHVybiBydW5fZml4dHVyZSgpOwogIGlm
IChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLXdzc2UtZml4dHVyZSIpKSByZXR1cm4g
cnVuX3dzc2VfZml4dHVyZSgpOwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICIt
LWR1YWwtYXV0aC1maXh0dXJlIikpIHJldHVybiBydW5fZHVhbF9hdXRoX2ZpeHR1cmUoKTsKICBp
ZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2WzFdLCAiLS1yaW5nLWZpeHR1cmUiKSkgcmV0dXJu
IHJ1bl9yaW5nX2ZpeHR1cmUoKTsKICBpZiAoYXJnYyA+IDEgJiYgIXN0cmNtcChhcmd2WzFdLCAi
LS1zaGlwLXJhdGUtZml4dHVyZSIpKSByZXR1cm4gcnVuX3NoaXBfcmF0ZV9maXh0dXJlKCk7CiAg
aWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0tc3RhdHMtZml4dHVyZSIpKSByZXR1
cm4gcnVuX3N0YXRzX2ZpeHR1cmUoKTsKICBzdGQ6OnN0cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8
dW5zaWduZWQ+IHBvcnRzOyBpbnQgaTsgaW50IHdvcmtlcnMgPSAxOwogIHN0ZDo6c3RyaW5nIGVu
ZHBvaW50OwogIGJvb2wgY2FwYWJpbGl0eV9wcm9iZSA9IGZhbHNlOwogIGNvbnN0IGNoYXIgKndz
c2VfZW52ID0gZ2V0ZW52KCJOVF9XU1NFX0JPRFlfQllURVMiKTsKICBpZiAod3NzZV9lbnYgJiYg
IXBhcnNlX3dzc2Vfc2l6ZSh3c3NlX2VudiwgJmdfd3NzZV9ib2R5X2J5dGVzKSkgewogICAgZnBy
aW50ZihzdGRlcnIsICJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi42NTUzNlxu
Iik7IHJldHVybiAyOwogIH0KICBjb25zdCBjaGFyICpyYXRlX2VudiA9IGdldGVudigiTlRfU0hJ
UF9SQVRFX0tCUFMiKTsKICBpZiAocmF0ZV9lbnYgJiYgKnJhdGVfZW52KSBnX3NoaXBfcmF0ZV9r
YnBzID0gKHVuc2lnbmVkKWF0b2kocmF0ZV9lbnYpOwogIGNvbnN0IGNoYXIgKnN0YXRzX2VudiA9
IGdldGVudigiTlRfU1RBVFNfSU5URVJWQUxfU0VDIik7CiAgaWYgKHN0YXRzX2VudiAmJiAqc3Rh
dHNfZW52KSBnX3N0YXRzX2ludGVydmFsX3NlYyA9ICh1bnNpZ25lZClhdG9pKHN0YXRzX2Vudik7
CiAgY29uc3QgY2hhciAqdHRsX2VudiA9IGdldGVudigiTlRfUEVORElOR19UVExfU0VDIik7CiAg
aWYgKHR0bF9lbnYgJiYgKnR0bF9lbnYpIGdfcGVuZGluZ190dGxfc2VjID0gKHVuc2lnbmVkKWF0
b2kodHRsX2Vudik7CgogIGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAgIGlmICghc3Ry
Y21wKGFyZ3ZbaV0sICItaSIpICYmIGkgKyAxIDwgYXJnYykgaWZhY2UgPSBhcmd2WysraV07CiAg
ICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItcCIpICYmIGkgKyAxIDwgYXJnYykgewogICAg
ICB3aGlsZSAoaSArIDEgPCBhcmdjICYmIGFyZ3ZbaSArIDFdWzBdICE9ICctJykgewogICAgICAg
IGNoYXIgKnEgPSBzdHJ0b2soYXJndlsrK2ldLCAiLCAiKTsKICAgICAgICB3aGlsZSAocSkgeyBs
b25nIHAgPSBhdG9sKHEpOyBpZiAodmFsaWRfcG9ydCgodW5zaWduZWQpcCkpIHBvcnRzLnB1c2hf
YmFjaygodW5zaWduZWQpcCk7IHEgPSBzdHJ0b2soTlVMTCwgIiwgIik7IH0KICAgICAgfQogICAg
fQogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1lbmRwb2ludCIpICYmIGkgKyAxIDwg
YXJnYykgZW5kcG9pbnQgPSBhcmd2WysraV07CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0s
ICItLXNoaXAtcmF0ZS1rYnBzIikgJiYgaSArIDEgPCBhcmdjKSBnX3NoaXBfcmF0ZV9rYnBzID0g
KHVuc2lnbmVkKWF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwg
Ii0tc3RhdHMtaW50ZXJ2YWwtc2VjIikgJiYgaSArIDEgPCBhcmdjKSBnX3N0YXRzX2ludGVydmFs
X3NlYyA9ICh1bnNpZ25lZClhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFy
Z3ZbaV0sICItLXBlbmRpbmctdHRsLXNlYyIpICYmIGkgKyAxIDwgYXJnYykgZ19wZW5kaW5nX3R0
bF9zZWMgPSAodW5zaWduZWQpYXRvaShhcmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChh
cmd2W2ldLCAiLS1jYXBhYmlsaXR5LXByb2JlIikpIGNhcGFiaWxpdHlfcHJvYmUgPSB0cnVlOwog
ICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1zcG9vbCIpICYmIGkgKyAxIDwgYXJnYykg
KytpOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWoiKSAmJiBpICsgMSA8IGFyZ2Mp
IHdvcmtlcnMgPSBhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0s
ICItLXdzc2UtYm9keS1ieXRlcyIpICYmIGkgKyAxIDwgYXJnYykgewogICAgICBpZiAoIXBhcnNl
X3dzc2Vfc2l6ZShhcmd2WysraV0sICZnX3dzc2VfYm9keV9ieXRlcykpIHsKICAgICAgICBmcHJp
bnRmKHN0ZGVyciwgIndzc2UgYm9keSBieXRlcyBtdXN0IGJlIGluIHJhbmdlIDAuLjY1NTM2XG4i
KTsgcmV0dXJuIDI7CiAgICAgIH0KICAgIH0KICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwg
Ii1oIikgfHwgIXN0cmNtcChhcmd2W2ldLCAiLS1oZWxwIikpIHsKICAgICAgZnByaW50ZihzdGRl
cnIsICJ1c2FnZTogbnQtc25pZmYtY3BwIFstaSBpZmFjZV0gWy1wIHBvcnRzXSBbLS1lbmRwb2lu
dCBVUkxdIFstLXNoaXAtcmF0ZS1rYnBzIDY0Li4xMDAwMF0gWy0tc3RhdHMtaW50ZXJ2YWwtc2Vj
IDEwLi4zMDBdIFstLXBlbmRpbmctdHRsLXNlYyAxLi4zMDBdIFstaiB3b3JrZXJzXSBbLS13c3Nl
LWJvZHktYnl0ZXMgMC4uNjU1MzZdXG4iKTsKICAgICAgcmV0dXJuIDA7CiAgICB9CiAgICBlbHNl
IHsgZnByaW50ZihzdGRlcnIsICJ1bmtub3duIG9yIGluY29tcGxldGUgYXJndW1lbnQ6ICVzXG4i
LCBhcmd2W2ldKTsgcmV0dXJuIDI7IH0KICB9CiAgaWYgKHBvcnRzLmVtcHR5KCkpIHsgcG9ydHMu
cHVzaF9iYWNrKDgwKTsgcG9ydHMucHVzaF9iYWNrKDgwMDMpOyBwb3J0cy5wdXNoX2JhY2soODAw
NSk7IHBvcnRzLnB1c2hfYmFjayg4MDA3KTsgcG9ydHMucHVzaF9iYWNrKDgwMDkpOyBwb3J0cy5w
dXNoX2JhY2soODAxMCk7IHBvcnRzLnB1c2hfYmFjayg4MDExKTsgfQogIGlmIChnX3NoaXBfcmF0
ZV9rYnBzIDwgNjQgfHwgZ19zaGlwX3JhdGVfa2JwcyA+IDEwMDAwKSB7CiAgICBmcHJpbnRmKHN0
ZGVyciwgInNoaXAgcmF0ZSBtdXN0IGJlIGluIHJhbmdlIDY0Li4xMDAwMCBrYml0L3NcbiIpOwog
ICAgcmV0dXJuIDI7CiAgfQogIGlmIChnX3N0YXRzX2ludGVydmFsX3NlYyA8IDEwIHx8IGdfc3Rh
dHNfaW50ZXJ2YWxfc2VjID4gMzAwKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgInN0YXRzIGludGVy
dmFsIG11c3QgYmUgaW4gcmFuZ2UgMTAuLjMwMCBzZWNvbmRzXG4iKTsKICAgIHJldHVybiAyOwog
IH0KICBpZiAoZ19wZW5kaW5nX3R0bF9zZWMgPCAxIHx8IGdfcGVuZGluZ190dGxfc2VjID4gMzAw
KSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgInBlbmRpbmcgdHRsIG11c3QgYmUgaW4gcmFuZ2UgMS4u
MzAwIHNlY29uZHNcbiIpOwogICAgcmV0dXJuIDI7CiAgfQogIGlmIChwb3J0cy5zaXplKCkgPiBN
QVhfUE9SVFMpIHsKICAgIGZwcmludGYoc3RkZXJyLCAiYXQgbW9zdCAzMCBtb25pdG9yZWQgcG9y
dHMgYXJlIHN1cHBvcnRlZCBieSB0aGUgc2FmZSBjQlBGIHByb2dyYW1cbiIpOwogICAgcmV0dXJu
IDI7CiAgfQogIGlmICh3b3JrZXJzICE9IDEpIHsKICAgIGZwcmludGYoc3RkZXJyLCAib25seSBv
bmUgY2FwdHVyZSB3b3JrZXIgaXMgcGVybWl0dGVkXG4iKTsKICAgIHJldHVybiAyOwogIH0KICAo
dm9pZCl3b3JrZXJzOwoKICBpZiAoY2FwYWJpbGl0eV9wcm9iZSkgcmV0dXJuIHJ1bl9jYXBhYmls
aXR5X3Byb2JlKGlmYWNlLCBwb3J0cyk7CgogIGluaXRfcm5nKCk7CiAgbWVtc2V0KGdfbW9uaXRv
cmVkX3BvcnRzLCAwLCBzaXplb2YoZ19tb25pdG9yZWRfcG9ydHMpKTsKICBmb3IgKHNpemVfdCBr
ID0gMDsgayA8IHBvcnRzLnNpemUoKTsgKytrKSB7CiAgICBpZiAocG9ydHNba10gPCA2NTUzNikg
Z19tb25pdG9yZWRfcG9ydHNbcG9ydHNba11dID0gdHJ1ZTsKICB9CgogIGNvbnN0IGNoYXIgKm5v
ZGVfZW52ID0gZ2V0ZW52KCJOVF9OT0RFX05BTUUiKTsKICBzdGQ6OnN0cmluZyBub2RlID0gKG5v
ZGVfZW52ICYmICpub2RlX2VudikgPyBub2RlX2VudiA6IGhvc3RfbmFtZSgpOwoKICBnX2VuZHBv
aW50ID0gZW5kcG9pbnQ7CiAgZ19zaGlwX25vZGUgPSBub2RlOwogIGdfaW5zdGFuY2VfaWQgPSBu
dW1iZXJfc3RyaW5nKChzaXplX3QpdGltZShOVUxMKSkgKyAiLSIgKyBudW1iZXJfc3RyaW5nKChz
aXplX3QpZ2V0cGlkKCkpOwogIGdfc3RhdHNfbGFzdF9hdCA9IHdhbGxfc2Vjb25kcygpOwoKICBN
bWFwUmluZyByaW5nOwogIGludCBmZCA9IG9wZW5fY2FwdHVyZV9zb2NrZXQoaWZhY2UsIHBvcnRz
LCByaW5nKTsKICBpZiAoZmQgPCAwKSByZXR1cm4gMjsKCiAgc2lnbmFsKFNJR1BJUEUsIFNJR19J
R04pOwoKICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBpbnQgb3V0cHV0X2ZsYWdzID0g
ZmNudGwoU1RET1VUX0ZJTEVOTywgRl9HRVRGTCwgMCk7CiAgICBpZiAob3V0cHV0X2ZsYWdzIDwg
MCB8fAogICAgICAgIGZjbnRsKFNURE9VVF9GSUxFTk8sIEZfU0VURkwsIG91dHB1dF9mbGFncyB8
IE9fTk9OQkxPQ0spIDwgMCkgewogICAgICBsb2dtc2coImNhbm5vdCBtYWtlIHNoaXBwZXIgcGlw
ZSBub24tYmxvY2tpbmc7IHJlZnVzaW5nIHVuc2FmZSBwaXBlbGluZSIpOwogICAgICByZWxlYXNl
X21tYXBfcmluZyhmZCwgcmluZyk7CiAgICAgIGNsb3NlKGZkKTsKICAgICAgcmV0dXJuIDI7CiAg
ICB9CiAgfSBlbHNlIHsKICAgIGdfc2hpcF93b3JrZXJfYWN0aXZlID0gdHJ1ZTsKICAgIGlmIChw
dGhyZWFkX2NyZWF0ZSgmZ19zaGlwX3dvcmtlcl90aWQsIE5VTEwsIHNoaXBfd29ya2VyX3RocmVh
ZCwgTlVMTCkgIT0gMCkgewogICAgICBsb2dtc2coImZhaWxlZCB0byBzcGF3biBzaGlwcGluZyB3
b3JrZXIgdGhyZWFkIik7CiAgICAgIHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5nKTsKICAgICAg
Y2xvc2UoZmQpOwogICAgICByZXR1cm4gMjsKICAgIH0KICB9CgogIHNpZ25hbChTSUdURVJNLCBz
dG9wX3NpZ25hbCk7CiAgc2lnbmFsKFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHNldHZidWYoc3Rk
b3V0LCBOVUxMLCBfSU9MQkYsIDY1NTM2KTsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiBmbG93
czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gcGVuZGluZzsK
CiAgbG9nbXNnKCJQQUNLRVRfTU1BUCAoVFBBQ0tFVF9WMikgc3RyaWN0IFJYIHJpbmcgZW5hYmxl
ZCAoNE1CLCAyMDQ4IGZyYW1lcykiKTsKICBpZiAoZ193c3NlX2JvZHlfYnl0ZXMpIHsKICAgIGxv
Z21zZygiV1NTRSBVc2VybmFtZVRva2VuIGluc3BlY3Rpb24gZW5hYmxlZCAoYm91bmRlZCB0byAi
ICsgbnVtYmVyX3N0cmluZyhnX3dzc2VfYm9keV9ieXRlcykgKyAiIGJ5dGVzL3JlcXVlc3QpIik7
CiAgfQogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBsb2dtc2coInNpbmdsZS1iaW5h
cnkgbW9kZTogbm9uLWJsb2NraW5nIHRocmVhZCBzaGlwcGluZyBkaXJlY3RseSB0byAiICsgZ19l
bmRwb2ludCArICIgKDAgZGlzayBJL08pIik7CiAgfSBlbHNlIHsKICAgIGxvZ21zZygibm9uLWJs
b2NraW5nIG5hdGl2ZSBwaXBlbGluZSBtb2RlIGVuYWJsZWQ7IFdBTiBJL08gaXNvbGF0ZWQgaW4g
bnQtc2hpcC1jcHAiKTsKICB9CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKCiAgdGltZV90IGxhc3Qg
PSB0aW1lKE5VTEwpOwogIGJvb2wgcmluZ19pbnRlZ3JpdHlfZmFpbHVyZSA9IGZhbHNlOwoKICBz
dHJ1Y3QgcG9sbGZkIHBmZDsKICBwZmQuZmQgPSBmZDsKICBwZmQuZXZlbnRzID0gUE9MTElOIHwg
UE9MTEVSUiB8IFBPTExIVVAgfCBQT0xMTlZBTDsKICBwZmQucmV2ZW50cyA9IDA7CgogIHdoaWxl
IChnX3J1bm5pbmcpIHsKICAgIGludCByYyA9IHBvbGwoJnBmZCwgMSwgMTAwMCk7CiAgICBpZiAo
cmMgPCAwICYmIGVycm5vID09IEVJTlRSKSB7CiAgICAgIC8vIFNpZ25hbCBoYW5kbGVkCiAgICB9
IGVsc2UgaWYgKHJjIDwgMCkgewogICAgICBsb2dtc2coInBvbGwgZXJyb3IgZW5jb3VudGVyZWQi
KTsKICAgICAgZ19ydW5uaW5nID0gMDsKICAgICAgYnJlYWs7CiAgICB9IGVsc2UgaWYgKHJjID4g
MCAmJiAocGZkLnJldmVudHMgJiAoUE9MTEVSUiB8IFBPTExOVkFMKSkpIHsKICAgICAgbG9nbXNn
KCJwb2xsIGVycm9yIHJldmVudHMgZGV0ZWN0ZWQiKTsKICAgICAgZ19ydW5uaW5nID0gMDsKICAg
ICAgYnJlYWs7CiAgICB9IGVsc2UgaWYgKHJjID4gMCkgewogICAgICBzaXplX3QgZHJhaW5fY291
bnQgPSAwOwogICAgICB3aGlsZSAoZ19ydW5uaW5nICYmIGRyYWluX2NvdW50IDwgTUFYX0RSQUlO
X1BFUl9QQVNTKSB7CiAgICAgICAgdW5zaWduZWQgYl9pZHggPSByaW5nLmZyYW1lX2lkeCAvIHJp
bmcuZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICB1bnNpZ25lZCBmX2luX2IgPSByaW5nLmZyYW1l
X2lkeCAlIHJpbmcuZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICB1aW50OF90ICpmcmFtZV9wdHIg
PSAoKHVpbnQ4X3QgKilyaW5nLnJpbmcpICsgKGJfaWR4ICogcmluZy5ibG9ja19zaXplKSArIChm
X2luX2IgKiByaW5nLmZyYW1lX3NpemUpOwogICAgICAgIHZvbGF0aWxlIHN0cnVjdCB0cGFja2V0
Ml9oZHIgKnZvbGF0aWxlX2hkciA9CiAgICAgICAgICAgICh2b2xhdGlsZSBzdHJ1Y3QgdHBhY2tl
dDJfaGRyICopZnJhbWVfcHRyOwoKICAgICAgICBpZiAoISh2b2xhdGlsZV9oZHItPnRwX3N0YXR1
cyAmIFRQX1NUQVRVU19VU0VSKSkgewogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICAg
IF9fc3luY19zeW5jaHJvbml6ZSgpOwoKICAgICAgICBjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRy
ICpoZHIgPQogICAgICAgICAgICAoY29uc3Qgc3RydWN0IHRwYWNrZXQyX2hkciAqKWZyYW1lX3B0
cjsKICAgICAgICBzaXplX3QgcGFja2V0X29mZnNldCA9IDAsIHBhY2tldF9sZW5ndGggPSAwOwog
ICAgICAgIGlmICghdmFsaWRfcmluZ19mcmFtZShoZHIsIHJpbmcuZnJhbWVfc2l6ZSwKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgJnBhY2tldF9vZmZzZXQsICZwYWNrZXRfbGVuZ3RoKSkg
ewogICAgICAgICAgX19zeW5jX3N5bmNocm9uaXplKCk7CiAgICAgICAgICB2b2xhdGlsZV9oZHIt
PnRwX3N0YXR1cyA9IFRQX1NUQVRVU19LRVJORUw7CiAgICAgICAgICByaW5nX2ludGVncml0eV9m
YWlsdXJlID0gdHJ1ZTsKICAgICAgICAgICsrZ19pbnZhbGlkX2ZyYW1lczsKICAgICAgICAgIGdf
cnVubmluZyA9IDA7CiAgICAgICAgICBsb2dtc2coImludmFsaWQgVFBBQ0tFVF9WMiBmcmFtZSBt
ZXRhZGF0YTsgc3RvcHBpbmcgY2FwdHVyZSIpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQog
ICAgICAgIGlmIChwYWNrZXRfbGVuZ3RoID4gMCkgewogICAgICAgICAgY29uc3QgdW5zaWduZWQg
Y2hhciAqcGt0ID0gZnJhbWVfcHRyICsgcGFja2V0X29mZnNldDsKICAgICAgICAgICsrZ19jYXB0
dXJlX3BhY2tldHM7CiAgICAgICAgICBnX2NhcHR1cmVfYnl0ZXMgKz0gcGFja2V0X2xlbmd0aDsK
ICAgICAgICAgIGhhbmRsZV9wYWNrZXQocGt0LCBwYWNrZXRfbGVuZ3RoLCBub2RlLCBwb3J0cywg
Zmxvd3MsIHBlbmRpbmcpOwogICAgICAgIH0KCiAgICAgICAgX19zeW5jX3N5bmNocm9uaXplKCk7
CiAgICAgICAgdm9sYXRpbGVfaGRyLT50cF9zdGF0dXMgPSBUUF9TVEFUVVNfS0VSTkVMOwogICAg
ICAgIHJpbmcuZnJhbWVfaWR4ID0gKHJpbmcuZnJhbWVfaWR4ICsgMSkgJSByaW5nLmZyYW1lX25y
OwogICAgICAgICsrZHJhaW5fY291bnQ7CiAgICAgIH0KICAgICAgaWYgKGdfZW5kcG9pbnQuZW1w
dHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICB9CgogICAgdGltZV90IG5vdyA9IHRpbWUoTlVM
TCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVwKGZsb3dzLCBwZW5kaW5n
LCBub3csIGdfcGVuZGluZ190dGxfc2VjKTsKICAgICAgaWYgKGdfZW5kcG9pbnQuZW1wdHkoKSkg
c3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgIGxhc3QgPSBub3c7CiAgICB9CgogICAgaWYgKHdhbGxf
c2Vjb25kcygpIC0gZ19zdGF0c19sYXN0X2F0ID49IGdfc3RhdHNfaW50ZXJ2YWxfc2VjKSB7CiAg
ICAgIHNpemVfdCBwZW5kaW5nX2NvdW50ID0gMCwgd3NzZV9jb3VudCA9IDA7CiAgICAgIGZvciAo
c3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwaSA9
IHBlbmRpbmcuYmVnaW4oKTsgcGkgIT0gcGVuZGluZy5lbmQoKTsgKytwaSkKICAgICAgICBwZW5k
aW5nX2NvdW50ICs9IHBpLT5zZWNvbmQuc2l6ZSgpOwogICAgICBmb3IgKHN0ZDo6bWFwPEZsb3dL
ZXksIEZsb3c+OjppdGVyYXRvciBmaSA9IGZsb3dzLmJlZ2luKCk7IGZpICE9IGZsb3dzLmVuZCgp
OyArK2ZpKQogICAgICAgIGlmIChmaS0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpICsrd3NzZV9jb3Vu
dDsKICAgICAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpCiAgICAgICAgc2VuZF9hZ2VudF9zdGF0
cyhmZCwgZmxvd3Muc2l6ZSgpLCBwZW5kaW5nX2NvdW50LCB3c3NlX2NvdW50KTsKICAgICAgZWxz
ZQogICAgICAgIGVtaXRfY2FwdHVyZV9zdGF0c19pbnRlcm5hbChmZCwgZmxvd3Muc2l6ZSgpLCBw
ZW5kaW5nX2NvdW50LCB3c3NlX2NvdW50KTsKICAgIH0KICB9CgogIGZsdXNoX2luY29tcGxldGVf
d3NzZShmbG93cywgcGVuZGluZyk7CiAgZmx1c2hfYWxsX3BlbmRpbmcocGVuZGluZyk7CiAgaWYg
KGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CgogIGlmIChnX3NoaXBfd29y
a2VyX2FjdGl2ZSkgewogICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgp
OwogICAgZ19wcm9kdWNlcl9maW5pc2hlZCA9IHRydWU7CiAgICBwdGhyZWFkX2NvbmRfYnJvYWRj
YXN0KCZnX3NoaXBfcXVldWVfY29uZCk7CiAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlw
X3F1ZXVlX211dGV4KTsKICAgIHB0aHJlYWRfam9pbihnX3NoaXBfd29ya2VyX3RpZCwgTlVMTCk7
CiAgfSBlbHNlIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgIHNpemVfdCBwZW5kaW5nX2Nv
dW50ID0gMDsKICAgIGVtaXRfY2FwdHVyZV9zdGF0c19pbnRlcm5hbChmZCwgMCwgcGVuZGluZ19j
b3VudCwgMCk7CiAgfQoKICB1cGRhdGVfa2VybmVsX2Ryb3BzKGZkKTsKICBsb2dtc2coInBhY2tl
dCBzdGF0czogcmVjZWl2ZWQ9IiArIHVsbF9zdHJpbmcoZ19jYXB0dXJlX3BhY2tldHMpICsKICAg
ICAgICAgIiBkcm9wcGVkPSIgKyB1bGxfc3RyaW5nKGdfa2VybmVsX2Ryb3BzKSk7CiAgaWYgKCFy
ZWxlYXNlX21tYXBfcmluZyhmZCwgcmluZykpIHsKICAgIGxvZ21zZygiVFBBQ0tFVF9WMiBjbGVh
bnVwIGZhaWxlZCIpOwogICAgcmluZ19pbnRlZ3JpdHlfZmFpbHVyZSA9IHRydWU7CiAgfQogIGNs
b3NlKGZkKTsKICBsb2dtc2coInN0b3BwZWQiKTsKICByZXR1cm4gcmluZ19pbnRlZ3JpdHlfZmFp
bHVyZSA/IDIgOiAwOwp9Cg==
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
