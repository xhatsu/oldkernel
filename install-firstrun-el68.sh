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
bmRpbmcgPSB7fQoKCmRlZiBwZW5kaW5nX2RlbChyayk6CiAgICBwZW5kaW5nLnBvcChyaywgTm9u
ZSkKCgpkZWYgcGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190Ymw9Tm9uZSk6CiAgICAiIiJG
bHVzaCB0aGUgb2xkZXN0IHBlbmRpbmcgZXZlbnQgZm9yIHRoaXMgcmVzcG9uc2UgdHVwbGUgKEZJ
Ti9SU1Qgb3IKICAgIG92ZXJmbG93IHBhdGgpLiBFbWl0cyB3aGF0ZXZlciB0aGUgZXZlbnQgaGFz
IOKAlCBzdGF0dXMgc3RheXMgbnVsbC4iIiIKICAgIGlmIHBlbmRpbmdfdGJsIGlzIE5vbmU6CiAg
ICAgICAgcGVuZGluZ190YmwgPSBwZW5kaW5nCiAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmsp
CiAgICBpZiBub3QgbHN0OgogICAgICAgIHJldHVybiBOb25lCiAgICBpdGVtID0gbHN0LnBvcCgw
KQogICAgaWYgbm90IGxzdDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICBp
c190b21ic3RvbmUgPSBpdGVtWzJdIGlmIGxlbihpdGVtKSA+IDIgZWxzZSBGYWxzZQogICAgaWYg
bm90IGlzX3RvbWJzdG9uZToKICAgICAgICBvdXQuYXBwZW5kKGl0ZW1bMF0pCiAgICAgICAgcmV0
dXJuIGl0ZW1bMF0KICAgIHJldHVybiBOb25lCgoKZGVmIHBhcnNlX3Jlc3BvbnNlX2hlYWQocGF5
bG9hZCk6CiAgICAiIiJGaXJzdCBsaW5lICdIVFRQLzEueCBOTk4gLi4uJyAtPiAoc3RhdHVzX2lu
dHxOb25lLCBjb250ZW50X2xlbnxOb25lLCBoZWFkX2VuZF9pZHh8Tm9uZSwgaXNfY2h1bmtlZCwg
aXNfY2xvc2UpLiIiIgogICAgdHJ5OgogICAgICAgIHJhdyA9IGJ5dGVzKHBheWxvYWQpCiAgICAg
ICAgaWR4ID0gcmF3LmZpbmQoYiJcclxuXHJcbiIpCiAgICAgICAgaWYgaWR4IDwgMDoKICAgICAg
ICAgICAgcmV0dXJuIE5vbmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBGYWxzZQogICAgICAgIGhlYWQg
PSByYXdbOmlkeF0KICAgICAgICBsaW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIiku
c3BsaXQoYiJcbiIpCiAgICAgICAgZmlyc3QgPSBsaW5lc1swXS5zcGxpdCgpCiAgICAgICAgaWYg
bGVuKGZpcnN0KSA8IDIgb3Igbm90IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLyIpOgogICAg
ICAgICAgICByZXR1cm4gTm9uZSwgTm9uZSwgaWR4ICsgNCwgRmFsc2UsIEZhbHNlCiAgICAgICAg
c3QgPSBpbnQoZmlyc3RbMV0pCiAgICAgICAgaWYgc3QgPCAxMDAgb3Igc3QgPiA1OTk6CiAgICAg
ICAgICAgIHJldHVybiBOb25lLCBOb25lLCBOb25lLCBGYWxzZSwgRmFsc2UKICAgIGV4Y2VwdCAo
VmFsdWVFcnJvciwgSW5kZXhFcnJvcik6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUsIE5vbmUs
IEZhbHNlLCBGYWxzZQogICAgY2xlbiA9IE5vbmUKICAgIGhhc19jbGVuID0gRmFsc2UKICAgIGhh
c19jb25mbGljdF9jbCA9IEZhbHNlCiAgICBpc19jaHVua2VkID0gRmFsc2UKICAgIGlzX2Nsb3Nl
ID0gRmFsc2UKICAgIGlzX2h0dHBfMTAgPSBmaXJzdFswXS5zdGFydHN3aXRoKGIiSFRUUC8xLjAi
KQogICAgY29ubl9jbG9zZSA9IEZhbHNlCiAgICBjb25uX2tlZXBfYWxpdmUgPSBGYWxzZQogICAg
Zm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBsb3cgPSBsbi5sb3dlcigpCiAgICAgICAgaWYg
bG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0aDoiKToKICAgICAgICAgICAgdHJ5OgogICAg
ICAgICAgICAgICAgdmFsID0gaW50KGxuLnNwbGl0KGIiOiIsIDEpWzFdLnN0cmlwKCkpCiAgICAg
ICAgICAgICAgICBpZiB2YWwgPCAwOgogICAgICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9j
bCA9IFRydWUKICAgICAgICAgICAgICAgIGVsaWYgaGFzX2NsZW4gYW5kIGNsZW4gIT0gdmFsOgog
ICAgICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUKICAgICAgICAgICAgICAg
IGNsZW4gPSB2YWwKICAgICAgICAgICAgICAgIGhhc19jbGVuID0gVHJ1ZQogICAgICAgICAgICBl
eGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUK
ICAgICAgICBlbGlmIGxvdy5zdGFydHN3aXRoKGIidHJhbnNmZXItZW5jb2Rpbmc6Iik6CiAgICAg
ICAgICAgIGlmIGIiY2h1bmtlZCIgaW4gbG93OgogICAgICAgICAgICAgICAgaXNfY2h1bmtlZCA9
IFRydWUKICAgICAgICBlbGlmIGxvdy5zdGFydHN3aXRoKGIiY29ubmVjdGlvbjoiKToKICAgICAg
ICAgICAgaWYgYiJjbG9zZSIgaW4gbG93OgogICAgICAgICAgICAgICAgY29ubl9jbG9zZSA9IFRy
dWUKICAgICAgICAgICAgZWxpZiBiImtlZXAtYWxpdmUiIGluIGxvdzoKICAgICAgICAgICAgICAg
IGNvbm5fa2VlcF9hbGl2ZSA9IFRydWUKICAgIGlmIGhhc19jb25mbGljdF9jbCBvciAoaGFzX2Ns
ZW4gYW5kIGlzX2NodW5rZWQpOgogICAgICAgIHJldHVybiBOb25lLCBOb25lLCBOb25lLCBGYWxz
ZSwgRmFsc2UKICAgIGlmIGlzX2h0dHBfMTAgYW5kIG5vdCBjb25uX2tlZXBfYWxpdmU6CiAgICAg
ICAgaXNfY2xvc2UgPSBUcnVlCiAgICBlbGlmIGNvbm5fY2xvc2U6CiAgICAgICAgaXNfY2xvc2Ug
PSBUcnVlCiAgICByZXR1cm4gc3QsIGNsZW4sIGlkeCArIDQsIGlzX2NodW5rZWQsIGlzX2Nsb3Nl
CgoKCmRlZiBoYW5kbGVfcmVzcG9uc2UocmVzcF9mbG93cywgcmssIHBheWxvYWQsIG5vdywgb3V0
LCBwZW5kaW5nX3RibCwgc2VxPU5vbmUsIGZsYWdzPTAsIGlzX3RydW5jYXRlZD1GYWxzZSk6CiAg
ICBpZiBmbGFncyAmIDB4MDIgYW5kIHNlcSBpcyBub3QgTm9uZToKICAgICAgICByZmwgPSByZXNw
X2Zsb3dzW3JrXSA9IEZsb3coKQogICAgICAgIHJmbC5oYXNfc2VxID0gVHJ1ZQogICAgICAgIHJm
bC5uZXh0X3NlcSA9IChzZXEgKyAxKSAmIDB4RkZGRkZGRkYKICAgICAgICByZmwudG91Y2hlZCA9
IG5vdwogICAgICAgIHJldHVybgoKICAgIHJmbCA9IHJlc3BfZmxvd3MuZ2V0KHJrKQogICAgaWYg
cmZsIGlzIE5vbmU6CiAgICAgICAgcmZsID0gRmxvdygpCiAgICAgICAgcmVzcF9mbG93c1tya10g
PSByZmwKICAgIHJmbC50b3VjaGVkID0gbm93CgogICAgcGxlbiA9IGxlbihwYXlsb2FkKSBpZiBw
YXlsb2FkIGVsc2UgMAogICAgaWYgcGxlbiA+IDA6CiAgICAgICAgaWYgc2VxIGlzIE5vbmU6CiAg
ICAgICAgICAgIHJmbC5idWYuZXh0ZW5kKHBheWxvYWQpCiAgICAgICAgZWxzZToKICAgICAgICAg
ICAgaWYgbm90IHJmbC5oYXNfc2VxOgogICAgICAgICAgICAgICAgaWYgKHBsZW4gPj0gNSBhbmQg
cGF5bG9hZFs6NV0gPT0gYiJIVFRQLyIpIG9yIChwbGVuIDwgNSBhbmQgYiJIVFRQLyIuc3RhcnRz
d2l0aChwYXlsb2FkKSk6CiAgICAgICAgICAgICAgICAgICAgcmZsLmhhc19zZXEgPSBUcnVlCiAg
ICAgICAgICAgICAgICAgICAgcmZsLm5leHRfc2VxID0gc2VxCiAgICAgICAgICAgICAgICAgICAg
cmZsLmlzX2Jyb2tlbiA9IEZhbHNlCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAg
ICAgICAgIGlmIGxlbihyZmwub29vKSA8IE1BWF9PT09fU0VHTUVOVFMgYW5kIG5vdCBpc190cnVu
Y2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIG5vdCBhbnkocyA9PSBzZXEgZm9yIHMs
IF8gaW4gcmZsLm9vbyk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZmwub29vLmFwcGVu
ZCgoc2VxLCBieXRlcyhwYXlsb2FkKSkpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuCgogICAg
ICAgICAgICBkaWZmID0gc2VxX2RpZmYoc2VxLCByZmwubmV4dF9zZXEpCiAgICAgICAgICAgIGlm
IGRpZmYgPT0gMDoKICAgICAgICAgICAgICAgIGlmIGlzX3RydW5jYXRlZDoKICAgICAgICAgICAg
ICAgICAgICByZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgZWxzZToKICAgICAg
ICAgICAgICAgICAgICByZmwuYnVmLmV4dGVuZChwYXlsb2FkKQogICAgICAgICAgICAgICAgICAg
IHJmbC5uZXh0X3NlcSA9IChyZmwubmV4dF9zZXEgKyBwbGVuKSAmIDB4RkZGRkZGRkYKICAgICAg
ICAgICAgICAgICAgICBfZHJhaW5fb29vKHJmbCkKICAgICAgICAgICAgZWxpZiBkaWZmIDwgMDoK
ICAgICAgICAgICAgICAgIG92ZXJsYXAgPSAtZGlmZgogICAgICAgICAgICAgICAgaWYgb3Zlcmxh
cCA8IHBsZW4gYW5kIG5vdCBpc190cnVuY2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgcmZsLmJ1
Zi5leHRlbmQocGF5bG9hZFtvdmVybGFwOl0pCiAgICAgICAgICAgICAgICAgICAgcmZsLm5leHRf
c2VxID0gKHJmbC5uZXh0X3NlcSArIHBsZW4gLSBvdmVybGFwKSAmIDB4RkZGRkZGRkYKICAgICAg
ICAgICAgICAgICAgICBfZHJhaW5fb29vKHJmbCkKICAgICAgICAgICAgZWxzZToKICAgICAgICAg
ICAgICAgIGlmIGxlbihyZmwub29vKSA8IE1BWF9PT09fU0VHTUVOVFMgYW5kIG5vdCBpc190cnVu
Y2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGFueShzID09IHNlcSBmb3IgcywgXyBp
biByZmwub29vKToKICAgICAgICAgICAgICAgICAgICAgICAgcmZsLm9vby5hcHBlbmQoKHNlcSwg
Ynl0ZXMocGF5bG9hZCkpKQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAg
ICByZmwuaXNfYnJva2VuID0gVHJ1ZQoKICAgICMgUGFyc2UgY29tcGxldGUgcmVzcG9uc2VzIGZy
b20gcmVhc3NlbWJsZWQgYnVmZmVyIHVzaW5nIEhUVFAgZnJhbWluZwogICAgd2hpbGUgcmZsLmJ1
ZiBhbmQgbm90IHJmbC5pc19icm9rZW46CiAgICAgICAgaWYgcmZsLnN0YXRlID09IEhUVFBfU1RB
VEVfSEVBREVSOgogICAgICAgICAgICBzdCwgY2xlbiwgaGVhZF9sZW4sIGlzX2NodW5rZWQsIGlz
X2Nsb3NlID0gcGFyc2VfcmVzcG9uc2VfaGVhZChyZmwuYnVmKQogICAgICAgICAgICBpZiBzdCBp
cyBOb25lOgogICAgICAgICAgICAgICAgaWYgaGVhZF9sZW4gaXMgbm90IE5vbmU6CiAgICAgICAg
ICAgICAgICAgICAgZGVsIHJmbC5idWZbOmhlYWRfbGVuXQogICAgICAgICAgICAgICAgZWxpZiBy
ZmwuYnVmLmZpbmQoYiJcclxuXHJcbiIpICE9IC0xOgogICAgICAgICAgICAgICAgICAgIHJmbC5i
dWYgPSBieXRlYXJyYXkoKQogICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVl
CiAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgaWYgMTAwIDw9IHN0IDw9IDE5OSBh
bmQgc3QgIT0gMTAxOgogICAgICAgICAgICAgICAgZGVsIHJmbC5idWZbOmhlYWRfbGVuXQogICAg
ICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChy
aykKICAgICAgICAgICAgaXNfaGVhZCA9IEZhbHNlCiAgICAgICAgICAgIGlmIGVudDoKICAgICAg
ICAgICAgICAgIGl0ZW0gPSBlbnRbMF0KICAgICAgICAgICAgICAgIGlzX3RvbWJzdG9uZSA9IGl0
ZW1bMl0gaWYgbGVuKGl0ZW0pID4gMiBlbHNlIEZhbHNlCiAgICAgICAgICAgICAgICBnZW4gPSBp
dGVtWzRdIGlmIGxlbihpdGVtKSA+IDQgZWxzZSAwCiAgICAgICAgICAgICAgICBpZiByZmwuZ2Vu
ZXJhdGlvbiAhPSAwIGFuZCBnZW4gIT0gMCBhbmQgZ2VuICE9IHJmbC5nZW5lcmF0aW9uOgogICAg
ICAgICAgICAgICAgICAgIGV2ID0gaXRlbVswXQogICAgICAgICAgICAgICAgICAgIG91dC5hcHBl
bmQoZXYpCiAgICAgICAgICAgICAgICAgICAgZW50LnBvcCgwKQogICAgICAgICAgICAgICAgICAg
IGlmIG5vdCBlbnQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHBlbmRpbmdfdGJsLnBvcChyaywg
Tm9uZSkKICAgICAgICAgICAgICAgIGVsaWYgaXNfdG9tYnN0b25lOgogICAgICAgICAgICAgICAg
ICAgIGVudC5wb3AoMCkKICAgICAgICAgICAgICAgICAgICBpZiBub3QgZW50OgogICAgICAgICAg
ICAgICAgICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAgICAgICAgICBl
bHNlOgogICAgICAgICAgICAgICAgICAgIGV2LCBzdGFydGVkID0gaXRlbVswXSwgaXRlbVsxXQog
ICAgICAgICAgICAgICAgICAgIGVudC5wb3AoMCkKICAgICAgICAgICAgICAgICAgICBpZiBub3Qg
ZW50OgogICAgICAgICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAg
ICAgICAgICAgICAgICAgICAgaWYgZXYuZ2V0KCJtZXRob2QiKSA9PSAiSEVBRCI6CiAgICAgICAg
ICAgICAgICAgICAgICAgIGlzX2hlYWQgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgZXZbInN0
YXR1cyJdID0gc3QKICAgICAgICAgICAgICAgICAgICBldlsiZHVyYXRpb25fbXMiXSA9IG1heCgw
LCBpbnQoKG5vdyAtIHN0YXJ0ZWQpICogMTAwMCkpCiAgICAgICAgICAgICAgICAgICAgaWYgY2xl
biBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICAgICAgZXZbInJlc3BfYnl0ZXMiXSA9
IGNsZW4KICAgICAgICAgICAgICAgICAgICBvdXQuYXBwZW5kKGV2KQoKICAgICAgICAgICAgZGVs
IHJmbC5idWZbOmhlYWRfbGVuXQoKICAgICAgICAgICAgaWYgaXNfaGVhZCBvciBzdCA9PSAyMDQg
b3Igc3QgPT0gMzA0OgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFE
RVIKICAgICAgICAgICAgZWxpZiBpc19jaHVua2VkOgogICAgICAgICAgICAgICAgcmZsLnN0YXRl
ID0gSFRUUF9TVEFURV9DSFVOSwogICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVu
ID0gVHJ1ZQogICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IEZhbHNlCiAg
ICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAg
ICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IDAKICAgICAgICAgICAgZWxpZiBj
bGVuIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgaWYgY2xlbiA+IDA6CiAgICAgICAgICAg
ICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9CT0RZCiAgICAgICAgICAgICAgICAgICAg
cmZsLmJvZHlfcmVtYWluaW5nID0gY2xlbgogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAg
ICAgICAgICAgICByZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICBlbHNl
OgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9DTE9TRV9CT0RZCiAgICAg
ICAgICAgIGNvbnRpbnVlCgogICAgICAgIGlmIHJmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0JPRFk6
CiAgICAgICAgICAgIGlmIG5vdCByZmwuYnVmOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAg
ICAgICAgdG9fY29uc3VtZSA9IG1pbihsZW4ocmZsLmJ1ZiksIHJmbC5ib2R5X3JlbWFpbmluZykK
ICAgICAgICAgICAgZGVsIHJmbC5idWZbOnRvX2NvbnN1bWVdCiAgICAgICAgICAgIHJmbC5ib2R5
X3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAgIGlmIHJmbC5ib2R5X3JlbWFpbmlu
ZyA9PSAwOgogICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAg
ICAgICAgICAgY29udGludWUKCiAgICAgICAgaWYgcmZsLnN0YXRlID09IEhUVFBfU1RBVEVfQ0hV
Tks6CiAgICAgICAgICAgIGlmIG5vdCByZmwuYnVmOgogICAgICAgICAgICAgICAgYnJlYWsKICAg
ICAgICAgICAgaWYgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxlcjoKICAgICAgICAgICAgICAgIGlm
IGxlbihyZmwuYnVmKSA+PSAyIGFuZCByZmwuYnVmWzoyXSA9PSBiIlxyXG4iOgogICAgICAgICAg
ICAgICAgICAgIGRlbCByZmwuYnVmWzoyXQogICAgICAgICAgICAgICAgICAgIHJmbC5jaHVua19y
ZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQogICAgICAgICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEhU
VFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAg
ICAgIHRyX2VuZCA9IHJmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgICAgICAgICAgICAgIGlm
IHRyX2VuZCAhPSAtMToKICAgICAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6dHJfZW5kICsg
NF0KICAgICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UK
ICAgICAgICAgICAgICAgICAgICByZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAg
ICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBpZiBsZW4ocmZsLmJ1ZikgPiBN
QVhfSERSUzoKICAgICAgICAgICAgICAgICAgICByZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAg
ICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsK
ICAgICAgICAgICAgaWYgcmZsLmNodW5rX3JlYWRpbmdfbGVuOgogICAgICAgICAgICAgICAgY3Js
ZiA9IHJmbC5idWYuZmluZChiIlxyXG4iKQogICAgICAgICAgICAgICAgaWYgY3JsZiA9PSAtMToK
ICAgICAgICAgICAgICAgICAgICBpZiBsZW4ocmZsLmJ1ZikgPiA2NDoKICAgICAgICAgICAgICAg
ICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgICAgIHJm
bC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAg
ICAgIGxpbmUgPSBieXRlcyhyZmwuYnVmWzpjcmxmXSkuc3RyaXAoKQogICAgICAgICAgICAgICAg
c2VtaSA9IGxpbmUuZmluZChiIjsiKQogICAgICAgICAgICAgICAgaGV4X3N0ciA9IGxpbmVbOnNl
bWldLnN0cmlwKCkgaWYgc2VtaSAhPSAtMSBlbHNlIGxpbmUKICAgICAgICAgICAgICAgIHRyeToK
ICAgICAgICAgICAgICAgICAgICBjaHVua19sZW4gPSBpbnQoaGV4X3N0ciwgMTYpCiAgICAgICAg
ICAgICAgICAgICAgaWYgY2h1bmtfbGVuIDwgMCBvciBjaHVua19sZW4gPiAxNjc3NzIxNjoKICAg
ICAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAg
ICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgICAgIGJy
ZWFrCiAgICAgICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgICAg
ICByZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2Vu
ID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBkZWwgcmZs
LmJ1Zls6Y3JsZiArIDJdCiAgICAgICAgICAgICAgICBpZiBjaHVua19sZW4gPT0gMDoKICAgICAg
ICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gVHJ1ZQogICAgICAgICAg
ICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IEZhbHNlCiAgICAgICAgICAgICAgICAg
ICAgY29udGludWUKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgcmZs
LmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gY2h1bmtfbGVuCiAgICAgICAgICAgICAgICAgICAg
cmZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICByZmwuY2h1
bmtfcmVhZGluZ19jcmxmID0gRmFsc2UKICAgICAgICAgICAgZWxpZiBnZXRhdHRyKHJmbCwgImNo
dW5rX3JlYWRpbmdfY3JsZiIsIEZhbHNlKToKICAgICAgICAgICAgICAgIGlmIGxlbihyZmwuYnVm
KSA8IDI6CiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGlmIHJmbC5i
dWZbOjJdICE9IGIiXHJcbiI6CiAgICAgICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJh
eSgpCiAgICAgICAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAg
ICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZGVsIHJmbC5idWZbOjJdCiAgICAgICAgICAg
ICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gRmFsc2UKICAgICAgICAgICAgICAgIHJmbC5j
aHVua19yZWFkaW5nX2xlbiA9IFRydWUKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAg
IHRvX2NvbnN1bWUgPSBtaW4obGVuKHJmbC5idWYpLCByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5p
bmcpCiAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6dG9fY29uc3VtZV0KICAgICAgICAgICAg
ICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAgICAgICAg
ICAgICBpZiByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPT0gMDoKICAgICAgICAgICAgICAg
ICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gVHJ1ZQogICAgICAgICAgICBjb250aW51ZQoK
ICAgICAgICBpZiByZmwuc3RhdGUgPT0gSFRUUF9TVEFURV9DTE9TRV9CT0RZOgogICAgICAgICAg
ICBkZWwgcmZsLmJ1Zls6XQogICAgICAgICAgICBicmVhawoKICAgIGlmIGZsYWdzICYgMHgwNToK
ICAgICAgICByZXNwX2Zsb3dzLnBvcChyaywgTm9uZSkKICAgICAgICBwZW5kaW5nX3BvcChyaywg
b3V0LCBwZW5kaW5nX3RibCkKCgpkZWYgY29ycmVsYXRlX3Jlc3BvbnNlKHBlbmRpbmdfdGJsLCBy
aywgcGF5bG9hZCwgbm93LCBvdXQsIHJlc3BfZmxvd3M9Tm9uZSwgc2VxPU5vbmUsIGZsYWdzPTAs
IGlzX3RydW5jYXRlZD1GYWxzZSk6CiAgICAiIiJBdHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8g
dGhlIG9sZGVzdCByZXF1ZXN0IG9uIGEgY29ubmVjdGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGlu
aW5nIGNhbiBsZWF2ZSBzZXZlcmFsIHJlcXVlc3RzIHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZv
dXItdHVwbGUuIENvbnN1bWUgZXhhY3RseSBvbmUgZW50cnk7IGRlbGV0aW5nIHRoZSB3aG9sZSBr
ZXkgaGVyZSBsb3NlcwogICAgZXZlcnkgcmVxdWVzdCBhZnRlciB0aGUgZmlyc3QgcmVzcG9uc2Uu
CiAgICAiIiIKICAgIGlmIHJlc3BfZmxvd3MgaXMgbm90IE5vbmU6CiAgICAgICAgaGFuZGxlX3Jl
c3BvbnNlKHJlc3BfZmxvd3MsIHJrLCBwYXlsb2FkLCBub3csIG91dCwgcGVuZGluZ190YmwsCiAg
ICAgICAgICAgICAgICAgICAgICAgIHNlcT1zZXEsIGZsYWdzPWZsYWdzLCBpc190cnVuY2F0ZWQ9
aXNfdHJ1bmNhdGVkKQogICAgICAgIHJldHVybiBUcnVlCiAgICByZXMgPSBwYXJzZV9yZXNwb25z
ZV9oZWFkKHBheWxvYWQpCiAgICBpZiByZXNbMF0gaXMgTm9uZToKICAgICAgICByZXR1cm4gRmFs
c2UKICAgIHN0LCBjbGVuLCBoZWFkX2xlbiA9IHJlc1swXSwgcmVzWzFdLCByZXNbMl0KICAgIGlm
IDEwMCA8PSBzdCA8PSAxOTkgYW5kIHN0ICE9IDEwMToKICAgICAgICBpZiBoZWFkX2xlbiBpcyBu
b3QgTm9uZSBhbmQgbGVuKHBheWxvYWQpID4gaGVhZF9sZW46CiAgICAgICAgICAgIHJldHVybiBj
b3JyZWxhdGVfcmVzcG9uc2UocGVuZGluZ190YmwsIHJrLCBwYXlsb2FkW2hlYWRfbGVuOl0sIG5v
dywgb3V0KQogICAgICAgIHJldHVybiBGYWxzZQogICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJr
KQogICAgaWYgbm90IGVudDoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGV2LCBzdGFydGVkID0g
ZW50LnBvcCgwKQogICAgaWYgbm90IGVudDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5v
bmUpCiAgICBldlsic3RhdHVzIl0gPSBzdAogICAgZXZbImR1cmF0aW9uX21zIl0gPSBtYXgoMCwg
aW50KChub3cgLSBzdGFydGVkKSAqIDEwMDApKQogICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAg
ICAgICBldlsicmVzcF9ieXRlcyJdID0gY2xlbgogICAgb3V0LmFwcGVuZChldikKICAgIHJldHVy
biBUcnVlCgoKZGVmIHZhbGlkX3BvcnQocCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIDEgPD0g
aW50KHApIDw9IDY1NTM1CiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAg
ICAgcmV0dXJuIEZhbHNlCgoKZGVmIGJhc2ljX3VzZXIodmFsdWUpOgogICAgIiIiQXV0aG9yaXph
dGlvbiBoZWFkZXIgdmFsdWUgLT4gKHVzZXJ8Tm9uZSwgc2NoZW1lfE5vbmUpLiBCYXNpYyBvbmx5
LiIiIgogICAgcGFydHMgPSB2YWx1ZS5zdHJpcCgpLnNwbGl0KE5vbmUsIDEpCiAgICBpZiBsZW4o
cGFydHMpICE9IDI6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIHNjaGVtZSA9IHBhcnRz
WzBdLmxvd2VyKCkKICAgIGlmIHNjaGVtZSA9PSAiYmFzaWMiOgogICAgICAgIHRyeToKICAgICAg
ICAgICAgcGFkID0gcGFydHNbMV0uc3RyaXAoKQogICAgICAgICAgICBpZiBsZW4ocGFkKSA+IDEw
MjQ6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBwYWQgKz0g
Ij0iICogKC1sZW4ocGFkKSAlIDQpCiAgICAgICAgICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNvZGUo
cGFkKQogICAgICAgICAgICBpZiBsZW4ocmF3KSA+IDUxMjoKICAgICAgICAgICAgICAgIHJldHVy
biBOb25lLCBOb25lCiAgICAgICAgICAgIGlmIGIiOiIgaW4gcmF3OgogICAgICAgICAgICAgICAg
dXNlciA9IHJhdy5zcGxpdChiIjoiLCAxKVswXQogICAgICAgICAgICAgICAgdXNlciA9IHVzZXIu
ZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjY0XQogICAgICAgICAgICAgICAgaWYgdXNlcjoK
ICAgICAgICAgICAgICAgICAgICByZXR1cm4gdXNlciwgImJhc2ljIgogICAgICAgIGV4Y2VwdCBF
eGNlcHRpb246CiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBlbGlmIHNjaGVtZSA9
PSAiYmVhcmVyIjoKICAgICAgICByZXR1cm4gTm9uZSwgImJlYXJlciIKICAgIHJldHVybiBOb25l
LCBOb25lCgoKZGVmIG5vcm1hbGl6ZV93c3NlX3VzZXJuYW1lKHZhbHVlKToKICAgICIiIlJldHVy
biBhIHNtYWxsLCBwcmludGFibGUgdXNlcm5hbWUgb3IgTm9uZTsgbmV2ZXIgcmV0dXJuIHRva2Vu
IGRhdGEuIiIiCiAgICBpZiB2YWx1ZSBpcyBOb25lOgogICAgICAgIHJldHVybiBOb25lCiAgICB0
cnk6CiAgICAgICAgdXNlcm5hbWUgPSB2YWx1ZS5zdHJpcCgpCiAgICBleGNlcHQgRXhjZXB0aW9u
OgogICAgICAgIHJldHVybiBOb25lCiAgICBpZiBub3QgdXNlcm5hbWUgb3IgbGVuKHVzZXJuYW1l
KSA+IE1BWF9XU1NFX1VTRVJOQU1FOgogICAgICAgIHJldHVybiBOb25lCiAgICBmb3IgY2hhciBp
biB1c2VybmFtZToKICAgICAgICBpZiB1bmljb2RlZGF0YS5jYXRlZ29yeShjaGFyKS5zdGFydHN3
aXRoKCJDIik6CiAgICAgICAgICAgIHJldHVybiBOb25lCiAgICByZXR1cm4gdXNlcm5hbWUKCgpk
ZWYgZXh0cmFjdF93c3NlX3VzZXJuYW1lKGJvZHkpOgogICAgIiIiUGFyc2UgYSBib3VuZGVkLCBw
b3NzaWJseSBwYXJ0aWFsIFNPQVAgcHJlZml4IGFuZCByZXR1cm4gb25seSBVc2VybmFtZS4KCiAg
ICBFeHBhdCBpcyBydW4gaW5jcmVtZW50YWxseSBzbyBhIFVzZXJuYW1lVG9rZW4gaW4gdGhlIFNP
QVAgSGVhZGVyIGNhbiBiZQogICAgcmVjb2duaXplZCB3aXRob3V0IHJldGFpbmluZyBvciByZXF1
aXJpbmcgdGhlIGNvbXBsZXRlIHJlcXVlc3QgYm9keS4KICAgIERURC9lbnRpdHkgZGVjbGFyYXRp
b25zIGFyZSByZWplY3RlZCBiZWZvcmUgcGFyc2luZy4KICAgICIiIgogICAgaWYgbm90IGJvZHkg
b3IgbGVuKGJvZHkpID4gTUFYX1dTU0VfQk9EWV9CWVRFUyBvciBiIlx4MDAiIGluIGJvZHk6CiAg
ICAgICAgcmV0dXJuIE5vbmUKICAgIGxvd2VyZWQgPSBieXRlcyhib2R5KS5sb3dlcigpCiAgICBp
ZiBiIjwhZG9jdHlwZSIgaW4gbG93ZXJlZCBvciBiIjwhZW50aXR5IiBpbiBsb3dlcmVkOgogICAg
ICAgIHJldHVybiBOb25lCgogICAgc3RhdGUgPSB7InN0YWNrIjogW10sICJ0b2tlbl9kZXB0aCI6
IDAsICJ1c2VybmFtZV9kZXB0aCI6IDAsCiAgICAgICAgICAgICAiY2hhcnMiOiBbXSwgInRvb19s
b25nIjogRmFsc2UsICJyZXN1bHQiOiBOb25lfQoKICAgIGRlZiBzcGxpdF9uYW1lKG5hbWUpOgog
ICAgICAgIGlmICJ9IiBub3QgaW4gbmFtZToKICAgICAgICAgICAgcmV0dXJuICIiLCBuYW1lCiAg
ICAgICAgcmV0dXJuIG5hbWUucnNwbGl0KCJ9IiwgMSkKCiAgICBkZWYgc3RhcnQobmFtZSwgYXR0
cnMpOgogICAgICAgIG5hbWVzcGFjZSwgbG9jYWxfbmFtZSA9IHNwbGl0X25hbWUobmFtZSkKICAg
ICAgICBzdGF0ZVsic3RhY2siXS5hcHBlbmQoKG5hbWVzcGFjZSwgbG9jYWxfbmFtZSkpCiAgICAg
ICAgZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0pCiAgICAgICAgaWYgKG5vdCBzdGF0ZVsidG9r
ZW5fZGVwdGgiXSBhbmQgbG9jYWxfbmFtZSA9PSAiVXNlcm5hbWVUb2tlbiIgYW5kCiAgICAgICAg
ICAgICAgICBuYW1lc3BhY2UgaW4gV1NTRV9OQU1FU1BBQ0VTKToKICAgICAgICAgICAgc3RhdGVb
InRva2VuX2RlcHRoIl0gPSBkZXB0aAogICAgICAgIGVsaWYgKHN0YXRlWyJ0b2tlbl9kZXB0aCJd
IGFuZAogICAgICAgICAgICAgIGRlcHRoID09IHN0YXRlWyJ0b2tlbl9kZXB0aCJdICsgMSBhbmQK
ICAgICAgICAgICAgICBsb2NhbF9uYW1lID09ICJVc2VybmFtZSIgYW5kCiAgICAgICAgICAgICAg
bmFtZXNwYWNlID09IHN0YXRlWyJzdGFjayJdW3N0YXRlWyJ0b2tlbl9kZXB0aCJdIC0gMV1bMF0p
OgogICAgICAgICAgICBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9IGRlcHRoCiAgICAgICAgICAg
IHN0YXRlWyJjaGFycyJdID0gW10KICAgICAgICAgICAgc3RhdGVbInRvb19sb25nIl0gPSBGYWxz
ZQoKICAgIGRlZiBjaGFycyh2YWx1ZSk6CiAgICAgICAgaWYgbm90IHN0YXRlWyJ1c2VybmFtZV9k
ZXB0aCJdIG9yIHN0YXRlWyJ0b29fbG9uZyJdOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBz
dGF0ZVsiY2hhcnMiXS5hcHBlbmQodmFsdWUpCiAgICAgICAgaWYgc3VtKFtsZW4ocGFydCkgZm9y
IHBhcnQgaW4gc3RhdGVbImNoYXJzIl1dKSA+IE1BWF9XU1NFX1VTRVJOQU1FICsgMjoKICAgICAg
ICAgICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAgICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9
IFRydWUKCiAgICBkZWYgZW5kKG5hbWUpOgogICAgICAgIGRlcHRoID0gbGVuKHN0YXRlWyJzdGFj
ayJdKQogICAgICAgIGlmIHN0YXRlWyJ1c2VybmFtZV9kZXB0aCJdID09IGRlcHRoOgogICAgICAg
ICAgICBpZiBub3Qgc3RhdGVbInRvb19sb25nIl0gYW5kIHN0YXRlWyJyZXN1bHQiXSBpcyBOb25l
OgogICAgICAgICAgICAgICAgc3RhdGVbInJlc3VsdCJdID0gbm9ybWFsaXplX3dzc2VfdXNlcm5h
bWUoCiAgICAgICAgICAgICAgICAgICAgdSIiLmpvaW4oc3RhdGVbImNoYXJzIl0pKQogICAgICAg
ICAgICBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9IDAKICAgICAgICAgICAgc3RhdGVbImNoYXJz
Il0gPSBbXQogICAgICAgIGlmIHN0YXRlWyJ0b2tlbl9kZXB0aCJdID09IGRlcHRoOgogICAgICAg
ICAgICBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9IDAKICAgICAgICBpZiBzdGF0ZVsic3RhY2siXToK
ICAgICAgICAgICAgc3RhdGVbInN0YWNrIl0ucG9wKCkKCiAgICB0cnk6CiAgICAgICAgcGFyc2Vy
ID0gZXhwYXQuUGFyc2VyQ3JlYXRlKE5vbmUsICJ9IikKICAgICAgICBpZiBoYXNhdHRyKHBhcnNl
ciwgInJldHVybnNfdW5pY29kZSIpOgogICAgICAgICAgICBwYXJzZXIucmV0dXJuc191bmljb2Rl
ID0gVHJ1ZQogICAgICAgIHBhcnNlci5TdGFydEVsZW1lbnRIYW5kbGVyID0gc3RhcnQKICAgICAg
ICBwYXJzZXIuQ2hhcmFjdGVyRGF0YUhhbmRsZXIgPSBjaGFycwogICAgICAgIHBhcnNlci5FbmRF
bGVtZW50SGFuZGxlciA9IGVuZAogICAgICAgIGlmIChoYXNhdHRyKHBhcnNlciwgIlNldFBhcmFt
RW50aXR5UGFyc2luZyIpIGFuZAogICAgICAgICAgICAgICAgaGFzYXR0cihleHBhdCwgIlhNTF9Q
QVJBTV9FTlRJVFlfUEFSU0lOR19ORVZFUiIpKToKICAgICAgICAgICAgcGFyc2VyLlNldFBhcmFt
RW50aXR5UGFyc2luZyhleHBhdC5YTUxfUEFSQU1fRU5USVRZX1BBUlNJTkdfTkVWRVIpCiAgICAg
ICAgcGFyc2VyLlBhcnNlKGJ5dGVzKGJvZHkpLCBGYWxzZSkKICAgIGV4Y2VwdCAoZXhwYXQuRXhw
YXRFcnJvciwgVmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAgICAgICAjIEEgYm91bmRlZCBwcmVm
aXggaXMgY29tbW9ubHkgaW5jb21wbGV0ZS4gQSB1c2VybmFtZSBmdWxseSBjbG9zZWQKICAgICAg
ICAjIGJlZm9yZSB0aGUgdHJ1bmNhdGlvbiBwb2ludCBpcyBzdGlsbCBzYWZlIHRvIHVzZS4KICAg
ICAgICBwYXNzCiAgICByZXR1cm4gc3RhdGVbInJlc3VsdCJdCgoKZGVmIGlzX3NvYXBfY29udGVu
dF90eXBlKHZhbHVlKToKICAgIGlmIG5vdCB2YWx1ZToKICAgICAgICByZXR1cm4gRmFsc2UKICAg
IG1lZGlhX3R5cGUgPSB2YWx1ZS5zcGxpdCgiOyIsIDEpWzBdLnN0cmlwKCkubG93ZXIoKQogICAg
cmV0dXJuIChtZWRpYV90eXBlIGluICgidGV4dC94bWwiLCAiYXBwbGljYXRpb24veG1sIiwKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgImFwcGxpY2F0aW9uL3NvYXAreG1sIikgb3IKICAgICAg
ICAgICAgbWVkaWFfdHlwZS5lbmRzd2l0aCgiK3htbCIpKQoKCmRlZiBmaW5pc2hfZXZlbnQoZmxv
dywga2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KToK
ICAgIGggPSBmbG93LmhkcnMKICAgIHVzZXIgPSBzY2hlbWUgPSBOb25lCiAgICBhdXRoeiA9IGgu
Z2V0KCJhdXRob3JpemF0aW9uIikKICAgIGlmIGF1dGh6OgogICAgICAgIHVzZXIsIHNjaGVtZSA9
IGJhc2ljX3VzZXIoYXV0aHopCiAgICAjIFczQyB0cmFjZSBjb250ZXh0OiBob25vciBpbmNvbWlu
ZyB0cmFjZXBhcmVudCwgZWxzZSBnZW5lcmF0ZSBvbmUgc28KICAgICMgZXZlcnkgdHJhbnNhY3Rp
b24gY2FycmllcyBhIHRyYWNlX2lkIGZvciBodWItc2lkZSBjb3JyZWxhdGlvbi4KICAgICMgTk9U
RSBweTIuNjogYnl0ZXMgaGFzIG5vIC5oZXgoKSDigJQgdXNlIGJpbmFzY2lpLmhleGxpZnkuCiAg
ICB0cCA9IGguZ2V0KCJ0cmFjZXBhcmVudCIpCiAgICB0cmFjZV9pZCA9IE5vbmUKICAgIGlmIHRw
OgogICAgICAgIHBhcnRzID0gdHAuc3BsaXQoIi0iKQogICAgICAgIGlmIGxlbihwYXJ0cykgPT0g
NCBhbmQgbGVuKHBhcnRzWzFdKSA9PSAzMjoKICAgICAgICAgICAgdHJhY2VfaWQgPSBwYXJ0c1sx
XS5sb3dlcigpCiAgICBpZiBub3QgdHJhY2VfaWQ6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBy
bmQgPSBiaW5hc2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oMTYpKQogICAgICAgICAgICBybmQgPSBy
bmQuZGVjb2RlKCJhc2NpaSIpIGlmIGhhc2F0dHIocm5kLCAiZGVjb2RlIikgZWxzZSBybmQKICAg
ICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBybmQgPSAoIiUwMzJ4IiAlIChpbnQo
dGltZS50aW1lKCkgKiAxMDAwKSkpWy0zMjpdCiAgICAgICAgcGlkOCA9IGJpbmFzY2lpLmhleGxp
Znkob3MudXJhbmRvbSg4KSkKICAgICAgICBwaWQ4ID0gcGlkOC5kZWNvZGUoImFzY2lpIikgaWYg
aGFzYXR0cihwaWQ4LCAiZGVjb2RlIikgZWxzZSBwaWQ4CiAgICAgICAgdHAgPSAiMDAtJXMtJXMt
MDEiICUgKHJuZCwgcGlkOCkKICAgICAgICB0cmFjZV9pZCA9IHJuZAogICAgZXYgPSB7CiAgICAg
ICAgInRzIjogaW50KHRpbWUudGltZSgpKSwKICAgICAgICAiaG9zdCI6IG5vZGVfaG9zdCwKICAg
ICAgICAic3JjIjogInBjYXAiLAogICAgICAgICJzZXJ2aWNlIjogInBvcnQ6JWQiICUgZHBvcnQs
CiAgICAgICAgIm1ldGhvZCI6IGguZ2V0KCJfbWV0aG9kIikgb3IgIi0iLAogICAgICAgICJwYXRo
IjogKGguZ2V0KCJfcGF0aCIpIG9yICItIikuc3BsaXQoIj8iLCAxKVswXVs6MTIwXSwKICAgICAg
ICAidXNlciI6IHVzZXIsCiAgICAgICAgInNjaGVtZSI6IHNjaGVtZSwKICAgICAgICAiYmFzaWNf
dXNlciI6IHVzZXIgaWYgc2NoZW1lID09ICJiYXNpYyIgYW5kIHVzZXIgZWxzZSBOb25lLAogICAg
ICAgICJ3c3NlX3VzZXIiOiBOb25lLAogICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJzb3Vy
Y2VfcHJvYmUiOiAicGNhcC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIp
LAogICAgICAgICJ1c2VyX2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAieF9m
b3J3YXJkZWRfZm9yIjogaC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIi
OiBzcmNfaXAsCiAgICAgICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6
IGRzdF9pcCwKICAgICAgICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRv
cmluZyBzY2hlbWEgKG9wcyBBUEktbG9nIGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1
cmF0aW9uX21zL3Jlc3BfYnl0ZXMgYXJlIHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1v
bmx5CiAgICAgICAgIyBjYXB0dXJlIGNhbm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUg
aHViIHRvIGVucmljaCBvciBsZWF2ZS4KICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAog
ICAgICAgICJ0cmFjZV9pZCI6IHRyYWNlX2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwg
ICAgICAgICAgIyBodWIgbWFwcyBwb3J0LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAg
ICAibW9kdWxlX2lkIjogInBjYXAtaHR0cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNl
IGNvcnJlbGF0aW9uIG9ubHkgZm9yIG1vbml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyBy
ZXNwb25zZS1zaWRlIGZpbHRlciBtYXkgc3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNw
b3J0IGVxdWFsIHRvIGEKICAgICMgbW9uaXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVj
YXVzZSBwYXJzZV9yZXNwb25zZV9oZWFkIHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRw
b3J0IGluIHBvcnRzIG9yIGguZ2V0KCJfbWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBfZW1pdF9y
ZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAg
IiIiRGlzY2FyZCBjYXB0dXJlIGJ1ZmZlcnMsIHRoZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRpemVk
IGV2ZW50IG9ubHkuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQog
ICAgZXYgPSBmbC53c3NlX2V2ZW50IGlmIGZsLmF3YWl0aW5nX3dzc2UgZWxzZSBmbC5ldmVudAog
ICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAg
aWYgbm90IGV2OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gZmwuaGVhZF9i
eXRlcwogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQog
ICAgICAgIHJldHVybgogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAg
IGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgIGlm
IGxlbihwZW5kaW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9vbGRl
c3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3Jr
XSA9IFtdCiAgICBlbGlmIGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAgICAgICAgcGVu
ZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgZW50ID0gcGVuZGluZ190Ymwu
Z2V0KHJrKQogICAgICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5n
X3RibFtya10gPSBbXQogICAgc3RhcnRlZCA9IGZsLmZpcnN0X2J5dGVfdHMgaWYgZmwuZmlyc3Rf
Ynl0ZV90cyA+IDAgZWxzZSAobm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNlIHRpbWUudGltZSgp
KQogICAgZW50LmFwcGVuZChbZXYsIHN0YXJ0ZWRdKQoKCmRlZiBfZW1pdF9yZXF1ZXN0X3RvX3Bl
bmRpbmcoZXYsIGhlYWRfYnl0ZXMsIGZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190
YmwsIG5vdywgZ2VuZXJhdGlvbj0wKToKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQg
PSBtZXRhCiAgICBpZiBub3QgZXY6CiAgICAgICAgcmV0dXJuCiAgICBldlsicmVxX2J5dGVzIl0g
PSBoZWFkX2J5dGVzCiAgICBpZiBwZW5kaW5nX3RibCBpcyBOb25lOgogICAgICAgIG91dC5hcHBl
bmQoZXYpCiAgICAgICAgcmV0dXJuCiAgICByayA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNw
b3J0KQogICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQogICAgaWYgZW50IGlzIE5vbmU6CiAg
ICAgICAgaWYgbGVuKHBlbmRpbmdfdGJsKSA+PSBQRU5ESU5HX01BWDoKICAgICAgICAgICAgX2Zs
dXNoX29sZGVzdF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBvdXQpCiAgICAgICAgZW50ID0gcGVuZGlu
Z190YmxbcmtdID0gW10KICAgIGVsaWYgbGVuKGVudCkgPj0gUEVORElOR19QRVJfRkxPVzoKICAg
ICAgICBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibCkKICAgICAgICBlbnQgPSBwZW5k
aW5nX3RibC5nZXQocmspCiAgICAgICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgICAgIGVudCA9
IHBlbmRpbmdfdGJsW3JrXSA9IFtdCiAgICBzdGFydGVkID0gZmlyc3RfYnl0ZV90cyBpZiBmaXJz
dF9ieXRlX3RzID4gMCBlbHNlIChub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGltZS50aW1l
KCkpCiAgICBlbnQuYXBwZW5kKFtldiwgc3RhcnRlZCwgRmFsc2UsIDAuMCwgZ2VuZXJhdGlvbl0p
CgoKZGVmIF90cnlfd3NzZV9ib2R5KGZsb3dzLCBrZXksIGZsLCBwYXlsb2FkLCBtZXRhLCBvdXQs
IHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiQXBwZW5kIG5vIG1vcmUgdGhhbiBib2R5X2dvYWwg
Ynl0ZXMgYW5kIGZpbmlzaCBhcyBzb29uIGFzIHBvc3NpYmxlLiIiIgogICAgcmVtYWluaW5nID0g
Zmwud3NzZV9nb2FsIC0gbGVuKGZsLndzc2VfYnVmKQogICAgaWYgcmVtYWluaW5nID4gMCBhbmQg
cGF5bG9hZDoKICAgICAgICBjb3B5X2xlbiA9IG1pbihyZW1haW5pbmcsIGxlbihwYXlsb2FkKSkK
ICAgICAgICBmbC53c3NlX2J1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWRbOmNvcHlfbGVuXSkp
CiAgICB1c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC53c3NlX2J1ZikKICAgIGlm
IHVzZXJuYW1lOgogICAgICAgIGZsLndzc2VfZXZlbnRbIndzc2VfdXNlciJdID0gdXNlcm5hbWUK
ICAgICAgICBmbC53c3NlX2V2ZW50WyJ1c2VyIl0gPSB1c2VybmFtZQogICAgICAgIGZsLndzc2Vf
ZXZlbnRbInNjaGVtZSJdID0gIndzc2UiCiAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwud3NzZV9i
dWYpID49IGZsLndzc2VfZ29hbDoKICAgICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwu
d3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0ZV90cywKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93LCBnZW5lcmF0
aW9uPWZsLmdlbmVyYXRpb24pCiAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICAg
ICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBoYW5kbGVfcGF5bG9hZChmbG93
cywga2V5LCByZXZfa2V5LCBwYXlsb2FkLCBtZXRhLCBwb3J0cywgbm9kZV9ob3N0LCBvdXQsCiAg
ICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibD1Ob25lLCBub3c9Tm9uZSwgd3NzZV9ib2R5X2J5
dGVzPTAsCiAgICAgICAgICAgICAgICAgICBzZXE9Tm9uZSwgZmxhZ3M9MCwgaXNfdHJ1bmNhdGVk
PUZhbHNlKToKICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBpZiBu
b3QgdmFsaWRfcG9ydChkcG9ydCkgb3Igbm90IHZhbGlkX3BvcnQoc3BvcnQpOgogICAgICAgIHJl
dHVybgogICAgaWYgbm93IGlzIE5vbmU6CiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKCiAgICAj
IFNZTiBoYW5kbGluZzogcmVzZXQgZmxvdyBhbmQgc3RhcnQgc2VxdWVuY2UgdHJhY2tpbmcKICAg
IGlmIGZsYWdzICYgMHgwMiBhbmQgc2VxIGlzIG5vdCBOb25lOgogICAgICAgIGZsID0gZmxvd3Mu
Z2V0KGtleSkKICAgICAgICBpZiBmbCBpcyBub3QgTm9uZSBhbmQgZmwuYXdhaXRpbmdfd3NzZSBh
bmQgZmwud3NzZV9ldmVudDoKICAgICAgICAgICAgb3V0LmFwcGVuZChmbC53c3NlX2V2ZW50KQog
ICAgICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gRmFsc2UKICAgICAgICByayA9IChkc3RfaXAs
IGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgICAgIGlmIHBlbmRpbmdfdGJsIGlzIG5vdCBOb25l
OgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAgICAg
IGlmIGVudDoKICAgICAgICAgICAgICAgIGZvciBpdGVtIGluIGVudDoKICAgICAgICAgICAgICAg
ICAgICBpc190b21iID0gaXRlbVsyXSBpZiBsZW4oaXRlbSkgPiAyIGVsc2UgRmFsc2UKICAgICAg
ICAgICAgICAgICAgICBpZiBub3QgaXNfdG9tYjoKICAgICAgICAgICAgICAgICAgICAgICAgb3V0
LmFwcGVuZChpdGVtWzBdKQogICAgICAgIGlmIHJldl9rZXkgaXMgbm90IE5vbmUgYW5kIHJldl9r
ZXkgaW4gZmxvd3M6CiAgICAgICAgICAgIGZsb3dzLnBvcChyZXZfa2V5LCBOb25lKQogICAgICAg
IG9sZF9nZW4gPSBmbC5nZW5lcmF0aW9uIGlmIGZsIGlzIG5vdCBOb25lIGVsc2UgMAogICAgICAg
IGZsID0gRmxvdygpCiAgICAgICAgZmwuZ2VuZXJhdGlvbiA9IG9sZF9nZW4gKyAxCiAgICAgICAg
ZmwuaGFzX3NlcSA9IFRydWUKICAgICAgICBmbC5uZXh0X3NlcSA9IChzZXEgKyAxKSAmIDB4RkZG
RkZGRkYKICAgICAgICBmbC50b3VjaGVkID0gbm93CiAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9
IDAuMAogICAgICAgIGZsb3dzW2tleV0gPSBmbAogICAgICAgIHJldHVybgoKICAgIGZsID0gZmxv
d3MuZ2V0KGtleSkKICAgIGlmIGZsIGlzIE5vbmU6CiAgICAgICAgZmwgPSBGbG93KCkKICAgICAg
ICBmbG93c1trZXldID0gZmwKICAgICAgICBpZiBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAg
ICAgICAgICBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpCiAgICBmbC50b3VjaGVkID0gbm93Cgog
ICAgIyBDaGVjayBrZWVwLWFsaXZlIHJlcXVlc3QgdHJhbnNpdGlvbiB3aGlsZSB3YWl0aW5nIGZv
ciBib2R5IGluIGRpcmVjdCB0ZXN0IGZlZWQgbW9kZQogICAgaWYgc2VxIGlzIE5vbmUgYW5kIGZs
LmF3YWl0aW5nX3dzc2UgYW5kIHBheWxvYWQgYW5kIGlzX21ldGhvZF9vcl9wcmVmaXgocGF5bG9h
ZCk6CiAgICAgICAgX2VtaXRfcmVxdWVzdF90b19wZW5kaW5nKGZsLndzc2VfZXZlbnQsIGZsLmhl
YWRfYnl0ZXMsIGZsLmZpcnN0X2J5dGVfdHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICBmbC5hd2FpdGluZ193c3Nl
ID0gRmFsc2UKICAgICAgICBmbC5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgZmwu
YnVmID0gYnl0ZWFycmF5KCkKCiAgICBwbGVuID0gbGVuKHBheWxvYWQpIGlmIHBheWxvYWQgZWxz
ZSAwCiAgICBpZiBwbGVuID4gMDoKICAgICAgICBpZiBzZXEgaXMgTm9uZToKICAgICAgICAgICAg
ZmwuYnVmLmV4dGVuZChwYXlsb2FkKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGlmIG5vdCBm
bC5oYXNfc2VxOgogICAgICAgICAgICAgICAgaWYgaXNfbWV0aG9kX29yX3ByZWZpeChwYXlsb2Fk
KToKICAgICAgICAgICAgICAgICAgICBmbC5oYXNfc2VxID0gVHJ1ZQogICAgICAgICAgICAgICAg
ICAgIGZsLm5leHRfc2VxID0gc2VxCiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0g
RmFsc2UKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKGZs
Lm9vbykgPCBNQVhfT09PX1NFR01FTlRTIGFuZCBub3QgaXNfdHJ1bmNhdGVkOgogICAgICAgICAg
ICAgICAgICAgICAgICBpZiBub3QgYW55KHMgPT0gc2VxIGZvciBzLCBfIGluIGZsLm9vbyk6CiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBheWxv
YWQpKSkKICAgICAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAgICAgIGRpZmYgPSBzZXFf
ZGlmZihzZXEsIGZsLm5leHRfc2VxKQogICAgICAgICAgICBpZiBkaWZmID09IDA6CiAgICAgICAg
ICAgICAgICBpZiBpc190cnVuY2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2Vu
ID0gVHJ1ZQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBmbC5idWYu
ZXh0ZW5kKHBheWxvYWQpCiAgICAgICAgICAgICAgICAgICAgZmwubmV4dF9zZXEgPSAoZmwubmV4
dF9zZXEgKyBwbGVuKSAmIDB4RkZGRkZGRkYKICAgICAgICAgICAgICAgICAgICBfZHJhaW5fb29v
KGZsKQogICAgICAgICAgICBlbGlmIGRpZmYgPCAwOgogICAgICAgICAgICAgICAgb3ZlcmxhcCA9
IC1kaWZmCiAgICAgICAgICAgICAgICBpZiBvdmVybGFwIDwgcGxlbiBhbmQgbm90IGlzX3RydW5j
YXRlZDoKICAgICAgICAgICAgICAgICAgICBmbC5idWYuZXh0ZW5kKHBheWxvYWRbb3ZlcmxhcDpd
KQogICAgICAgICAgICAgICAgICAgIGZsLm5leHRfc2VxID0gKGZsLm5leHRfc2VxICsgcGxlbiAt
IG92ZXJsYXApICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgIF9kcmFpbl9vb28oZmwp
CiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBpZiBsZW4oZmwub29vKSA8IE1BWF9P
T09fU0VHTUVOVFMgYW5kIG5vdCBpc190cnVuY2F0ZWQ6CiAgICAgICAgICAgICAgICAgICAgaWYg
bm90IGFueShzID09IHNlcSBmb3IgcywgXyBpbiBmbC5vb28pOgogICAgICAgICAgICAgICAgICAg
ICAgICBmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBheWxvYWQpKSkKICAgICAgICAgICAgICAg
IGVsc2U6CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQoKICAgICMgSFRU
UCBmcmFtaW5nIHN0YXRlIG1hY2hpbmUKICAgIHdoaWxlIGxlbihmbC5idWYpID4gMCBhbmQgbm90
IGZsLmlzX2Jyb2tlbjoKICAgICAgICBpZiBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0hFQURFUjoK
ICAgICAgICAgICAgaWYgbm90IGZsLmZpcnN0X2J5dGVfdHM6CiAgICAgICAgICAgICAgICBmbC5m
aXJzdF9ieXRlX3RzID0gbm93CgogICAgICAgICAgICBpZHggPSBmbC5idWYuZmluZChiIlxyXG5c
clxuIikKICAgICAgICAgICAgaWYgaWR4IDwgMDoKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5i
dWYpID4gTUFYX0hEUlM6CiAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkK
ICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICBi
cmVhawogICAgICAgICAgICBzdGFydCA9IGZpbmRfaHR0cF9zdGFydChmbC5idWYpCiAgICAgICAg
ICAgIGlmIHN0YXJ0IDwgMCBvciBzdGFydCA+IGlkeDoKICAgICAgICAgICAgICAgIGRlbCBmbC5i
dWZbOmlkeCArIDRdCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBpZiBzdGFy
dCA+IDA6CiAgICAgICAgICAgICAgICBkZWwgZmwuYnVmWzpzdGFydF0KICAgICAgICAgICAgICAg
IGlkeCAtPSBzdGFydAoKICAgICAgICAgICAgaGVhZCA9IGJ5dGVzKGZsLmJ1Zls6aWR4XSkKICAg
ICAgICAgICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwgYiJcbiIpLnNwbGl0KGIiXG4i
KQogICAgICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnN0cmlwKCkuc3BsaXQoKQogICAgICAgICAg
ICBpZiBsZW4oZmlyc3QpIDwgMiBvciBmaXJzdFswXS5kZWNvZGUoImFzY2lpIiwgInJlcGxhY2Ui
KSBub3QgaW4gTUVUSE9EUzoKICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOmlkeCArIDRdCiAg
ICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBoZHJzID0ge30KICAgICAgICAgICAg
aGRyc1siX21ldGhvZCJdID0gZmlyc3RbMF0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAg
ICAgICAgICAgaGRyc1siX3BhdGgiXSA9IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFj
ZSIpCiAgICAgICAgICAgIGhhc19jb25mbGljdF9jbCA9IEZhbHNlCiAgICAgICAgICAgIGZpcnN0
X2NsID0gTm9uZQogICAgICAgICAgICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgICAgICAg
ICAgaWYgYiI6IiBub3QgaW4gbG46CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAg
ICAgICAgICAgIGtuLCBrdiA9IGxuLnNwbGl0KGIiOiIsIDEpCiAgICAgICAgICAgICAgICBrX25v
cm0gPSBrbi5zdHJpcCgpLmxvd2VyKCkuZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAg
ICAgICAgICAgIHZfbm9ybSA9IGt2LnN0cmlwKCkuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilb
OjE4MF0KICAgICAgICAgICAgICAgIGlmIGtfbm9ybSA9PSAiY29udGVudC1sZW5ndGgiOgogICAg
ICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgcGFyc2VkX2NsID0g
aW50KHZfbm9ybSkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgcGFyc2VkX2NsIDwgMDoKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUKICAgICAgICAg
ICAgICAgICAgICAgICAgZWxpZiBmaXJzdF9jbCBpcyBOb25lOgogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgZmlyc3RfY2wgPSBwYXJzZWRfY2wKICAgICAgICAgICAgICAgICAgICAgICAgZWxp
ZiBmaXJzdF9jbCAhPSBwYXJzZWRfY2w6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYXNf
Y29uZmxpY3RfY2wgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6
CiAgICAgICAgICAgICAgICAgICAgICAgIGhhc19jb25mbGljdF9jbCA9IFRydWUKICAgICAgICAg
ICAgICAgIGhkcnNba19ub3JtXSA9IHZfbm9ybQogICAgICAgICAgICBmbC5oZHJzID0gaGRycwog
ICAgICAgICAgICBmbC5ldmVudCA9IGZpbmlzaF9ldmVudChmbCwga2V5LCBkc3RfaXAsIGRwb3J0
LCBzcmNfaXAsIHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KQogICAgICAgICAgICBmbC5oZWFkX2J5
dGVzID0gaWR4ICsgNAogICAgICAgICAgICBkZWwgZmwuYnVmWzppZHggKyA0XQoKICAgICAgICAg
ICAgaWYgbm90IGZsLmV2ZW50OgogICAgICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgICAg
IHRyeToKICAgICAgICAgICAgICAgIGNvbnRlbnRfbGVuZ3RoID0gaW50KGhkcnMuZ2V0KCJjb250
ZW50LWxlbmd0aCIsICIwIikpCiAgICAgICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgVHlwZUVy
cm9yKToKICAgICAgICAgICAgICAgIGNvbnRlbnRfbGVuZ3RoID0gMAogICAgICAgICAgICB0ZSA9
IGhkcnMuZ2V0KCJ0cmFuc2Zlci1lbmNvZGluZyIsICIiKS5sb3dlcigpCiAgICAgICAgICAgIGlz
X2NodW5rZWQgPSAiY2h1bmtlZCIgaW4gdGUKCiAgICAgICAgICAgIGlmIGhhc19jb25mbGljdF9j
bCBvciAoY29udGVudF9sZW5ndGggPiAwIGFuZCBpc19jaHVua2VkKSBvciAoImNvbnRlbnQtbGVu
Z3RoIiBpbiBoZHJzIGFuZCBpc19jaHVua2VkKToKICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5
dGVhcnJheSgpCiAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAg
ICAgICBicmVhawoKICAgICAgICAgICAgYWN0aXZlX2JvZHlfZmxvd3MgPSBzdW0oMSBmb3IgY2Fu
ZCBpbiBmbG93cy52YWx1ZXMoKSBpZiBjYW5kLmF3YWl0aW5nX3dzc2Ugb3IgKGNhbmQuZXZlbnQg
aXMgbm90IE5vbmUgYW5kIGdldGF0dHIoY2FuZCwgImJvZHlfZ29hbCIsIDApID4gMCkpCiAgICAg
ICAgICAgIHdzc2VfZWxpZ2libGUgPSAod3NzZV9ib2R5X2J5dGVzID4gMCBhbmQKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBpc19zb2FwX2NvbnRlbnRfdHlwZShoZHJzLmdldCgiY29udGVu
dC10eXBlIikpIGFuZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRlbnRfbGVuZ3Ro
ID4gMCBhbmQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBub3QgaXNfY2h1bmtlZCBhbmQK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3RpdmVfYm9keV9mbG93cyA8IE1BWF9XU1NF
X0JPRFlfRkxPV1MpCgogICAgICAgICAgICBpZiB3c3NlX2VsaWdpYmxlOgogICAgICAgICAgICAg
ICAgZmwuYXdhaXRpbmdfd3NzZSA9IFRydWUKICAgICAgICAgICAgICAgIGZsLndzc2VfZXZlbnQg
PSBmbC5ldmVudAogICAgICAgICAgICAgICAgZmwud3NzZV9idWYgPSBieXRlYXJyYXkoKQogICAg
ICAgICAgICAgICAgZmwud3NzZV9nb2FsID0gbWluKGNvbnRlbnRfbGVuZ3RoLCB3c3NlX2JvZHlf
Ynl0ZXMsIE1BWF9XU1NFX0JPRFlfQllURVMpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAg
ICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwuZXZlbnQsIGZsLmhlYWRfYnl0ZXMsIGZs
LmZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdywgZ2VuZXJhdGlvbj1m
bC5nZW5lcmF0aW9uKQogICAgICAgICAgICBmbC5ldmVudCA9IE5vbmUKCiAgICAgICAgICAgIGlm
IGNvbnRlbnRfbGVuZ3RoID4gMDoKICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFU
RV9CT0RZCiAgICAgICAgICAgICAgICBmbC5ib2R5X3JlbWFpbmluZyA9IGNvbnRlbnRfbGVuZ3Ro
CiAgICAgICAgICAgIGVsaWYgaXNfY2h1bmtlZDoKICAgICAgICAgICAgICAgIGZsLnN0YXRlID0g
SFRUUF9TVEFURV9DSFVOSwogICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBU
cnVlCiAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2NybGYgPSBGYWxzZQogICAgICAg
ICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAg
IGZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gMAogICAgICAgICAgICBlbHNlOgogICAgICAg
ICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAgZmwu
Zmlyc3RfYnl0ZV90cyA9IG5vdyBpZiBmbC5idWYgZWxzZSAwLjAKICAgICAgICAgICAgY29udGlu
dWUKCiAgICAgICAgZWxpZiBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0JPRFk6CiAgICAgICAgICAg
IGlmIG5vdCBmbC5idWY6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICB0b19jb25z
dW1lID0gbWluKGxlbihmbC5idWYpLCBmbC5ib2R5X3JlbWFpbmluZykKICAgICAgICAgICAgaWYg
ZmwuYXdhaXRpbmdfd3NzZToKICAgICAgICAgICAgICAgIHdzc2VfbmVlZCA9IGZsLndzc2VfZ29h
bCAtIGxlbihmbC53c3NlX2J1ZikKICAgICAgICAgICAgICAgIGlmIHdzc2VfbmVlZCA+IDA6CiAg
ICAgICAgICAgICAgICAgICAgY29weV9sZW4gPSBtaW4odG9fY29uc3VtZSwgd3NzZV9uZWVkKQog
ICAgICAgICAgICAgICAgICAgIGZsLndzc2VfYnVmLmV4dGVuZChmbC5idWZbOmNvcHlfbGVuXSkK
ICAgICAgICAgICAgICAgIHVzZXJuYW1lID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLndzc2Vf
YnVmKQogICAgICAgICAgICAgICAgaWYgdXNlcm5hbWUgb3IgbGVuKGZsLndzc2VfYnVmKSA+PSBm
bC53c3NlX2dvYWw6CiAgICAgICAgICAgICAgICAgICAgZXYgPSBmbC53c3NlX2V2ZW50CiAgICAg
ICAgICAgICAgICAgICAgaWYgdXNlcm5hbWU6CiAgICAgICAgICAgICAgICAgICAgICAgIGV2WyJ3
c3NlX3VzZXIiXSA9IHVzZXJuYW1lCiAgICAgICAgICAgICAgICAgICAgICAgIGV2WyJ1c2VyIl0g
PSB1c2VybmFtZQogICAgICAgICAgICAgICAgICAgICAgICBldlsic2NoZW1lIl0gPSAid3NzZSIK
ICAgICAgICAgICAgICAgICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZXYsIGZsLmhlYWRf
Ynl0ZXMsIGZsLmZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdywgZ2Vu
ZXJhdGlvbj1mbC5nZW5lcmF0aW9uKQogICAgICAgICAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dz
c2UgPSBGYWxzZQoKICAgICAgICAgICAgZGVsIGZsLmJ1Zls6dG9fY29uc3VtZV0KICAgICAgICAg
ICAgZmwuYm9keV9yZW1haW5pbmcgLT0gdG9fY29uc3VtZQogICAgICAgICAgICBpZiBmbC5ib2R5
X3JlbWFpbmluZyA9PSAwOgogICAgICAgICAgICAgICAgaWYgZmwuYXdhaXRpbmdfd3NzZToKICAg
ICAgICAgICAgICAgICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVudCwg
ZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0ZV90cywgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwg
bm93LCBnZW5lcmF0aW9uPWZsLmdlbmVyYXRpb24pCiAgICAgICAgICAgICAgICAgICAgZmwuYXdh
aXRpbmdfd3NzZSA9IEZhbHNlCiAgICAgICAgICAgICAgICBmbC5zdGF0ZSA9IEhUVFBfU1RBVEVf
SEVBREVSCiAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gbm93IGlmIGZsLmJ1ZiBl
bHNlIDAuMAogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBlbGlmIGZsLnN0YXRlID09IEhU
VFBfU1RBVEVfQ0hVTks6CiAgICAgICAgICAgIGlmIG5vdCBmbC5idWY6CiAgICAgICAgICAgICAg
ICBicmVhawogICAgICAgICAgICBpZiBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXI6CiAgICAgICAg
ICAgICAgICBpZiBsZW4oZmwuYnVmKSA+PSAyIGFuZCBmbC5idWZbOjJdID09IGIiXHJcbiI6CiAg
ICAgICAgICAgICAgICAgICAgZGVsIGZsLmJ1Zls6Ml0KICAgICAgICAgICAgICAgICAgICBmbC5j
aHVua19yZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQogICAgICAgICAgICAgICAgICAgIGZsLnN0YXRl
ID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3Rz
ID0gbm93IGlmIGZsLmJ1ZiBlbHNlIDAuMAogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAg
ICAgICAgICAgICAgICB0cl9lbmQgPSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgICAgICAg
ICAgICAgIGlmIHRyX2VuZCAhPSAtMToKICAgICAgICAgICAgICAgICAgICBkZWwgZmwuYnVmWzp0
cl9lbmQgKyA0XQogICAgICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9
IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgog
ICAgICAgICAgICAgICAgICAgIGZsLmZpcnN0X2J5dGVfdHMgPSBub3cgaWYgZmwuYnVmIGVsc2Ug
MC4wCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGlmIGxlbihm
bC5idWYpID4gTUFYX0hEUlM6CiAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5
KCkKICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAg
ICBicmVhawogICAgICAgICAgICBpZiBmbC5jaHVua19yZWFkaW5nX2xlbjoKICAgICAgICAgICAg
ICAgIGNybGYgPSBmbC5idWYuZmluZChiIlxyXG4iKQogICAgICAgICAgICAgICAgaWYgY3JsZiA8
IDA6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKGZsLmJ1ZikgPiA2NDoKICAgICAgICAgICAg
ICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICAgICAg
ZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAg
ICAgICBsaW5lID0gYnl0ZXMoZmwuYnVmWzpjcmxmXSkuc3RyaXAoKQogICAgICAgICAgICAgICAg
c2VtaSA9IGxpbmUuZmluZChiIjsiKQogICAgICAgICAgICAgICAgaGV4X3N0ciA9IGxpbmVbOnNl
bWldLnN0cmlwKCkgaWYgc2VtaSAhPSAtMSBlbHNlIGxpbmUKICAgICAgICAgICAgICAgIGlmIGxl
bihoZXhfc3RyKSA+IDE2OgogICAgICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgp
CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAg
ICAgIGJyZWFrCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgY2h1bmtf
bGVuID0gaW50KGhleF9zdHIsIDE2KQogICAgICAgICAgICAgICAgICAgIGlmIGNodW5rX2xlbiA8
IDAgb3IgY2h1bmtfbGVuID4gMHg3RkZGRkZGRjoKICAgICAgICAgICAgICAgICAgICAgICAgZmwu
YnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0g
VHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZXhjZXB0
IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgZmwuYnVmID0gYnl0ZWFycmF5KCkKICAg
ICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVlCiAgICAgICAgICAgICAgICAgICAg
YnJlYWsKICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOmNybGYgKyAyXQogICAgICAgICAgICAg
ICAgaWYgY2h1bmtfbGVuID09IDA6CiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGlu
Z190cmFpbGVyID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVu
ID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgZWxz
ZToKICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IGNodW5r
X2xlbgogICAgICAgICAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UKICAg
ICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2NybGYgPSBGYWxzZQogICAgICAgICAg
ICBlbGlmIGZsLmNodW5rX3JlYWRpbmdfY3JsZjoKICAgICAgICAgICAgICAgIGlmIGxlbihmbC5i
dWYpIDwgMjoKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgaWYgZmwu
YnVmWzoyXSAhPSBiIlxyXG4iOgogICAgICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJh
eSgpCiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBkZWwgZmwuYnVmWzoyXQogICAgICAgICAgICAg
ICAgZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gRmFsc2UKICAgICAgICAgICAgICAgIGZsLmNodW5r
X3JlYWRpbmdfbGVuID0gVHJ1ZQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgdG9f
Y29uc3VtZSA9IG1pbihsZW4oZmwuYnVmKSwgZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcpCiAg
ICAgICAgICAgICAgICBkZWwgZmwuYnVmWzp0b19jb25zdW1lXQogICAgICAgICAgICAgICAgZmwu
Y2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgLT0gdG9fY29uc3VtZQogICAgICAgICAgICAgICAgaWYg
ZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgPT0gMDoKICAgICAgICAgICAgICAgICAgICBmbC5j
aHVua19yZWFkaW5nX2NybGYgPSBUcnVlCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgaWYgZmxh
Z3MgJiAweDA1OgogICAgICAgIGlmIGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQ6
CiAgICAgICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGluZyhmbC53c3NlX2V2ZW50LCBmbC5o
ZWFkX2J5dGVzLCBmbC5maXJzdF9ieXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cp
CiAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQogICAgICAgIGZsb3dzLnBvcChr
ZXksIE5vbmUpCiAgICBlbGlmIHNlcSBpcyBOb25lIGFuZCBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRF
X0hFQURFUiBhbmQgbm90IGZsLmJ1ZiBhbmQgbm90IGZsLm9vbyBhbmQgbm90IGZsLmF3YWl0aW5n
X3dzc2U6CiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKCgpkZWYgc3dlZXBfaWRsZShmbG93
cywgbm93LCBvdXQ9Tm9uZSwgcGVuZGluZ190Ymw9Tm9uZSwgcmVzcF9mbG93cz1Ob25lKToKICAg
IHN0YWxlID0gW10KICAgIGZvciBrLCBmbCBpbiBmbG93cy5pdGVtcygpOgogICAgICAgIGlmIG5v
dyAtIGZsLnRvdWNoZWQgPiBGTE9XX1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKGspCiAg
ICBmb3IgayBpbiBzdGFsZToKICAgICAgICBmbCA9IGZsb3dzLmdldChrKQogICAgICAgIGlmIGZs
IGlzIG5vdCBOb25lIGFuZCBmbC5hd2FpdGluZ193c3NlIGFuZCBmbC53c3NlX2V2ZW50IGlzIG5v
dCBOb25lOgogICAgICAgICAgICBpZiBvdXQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBv
dXQuYXBwZW5kKGZsLndzc2VfZXZlbnQpCiAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBG
YWxzZQogICAgICAgIGZsb3dzLnBvcChrLCBOb25lKQogICAgaWYgcmVzcF9mbG93cyBpcyBub3Qg
Tm9uZToKICAgICAgICByc3RhbGUgPSBbayBmb3IgaywgcmZsIGluIHJlc3BfZmxvd3MuaXRlbXMo
KSBpZiBub3cgLSByZmwudG91Y2hlZCA+IEZMT1dfVFRMXQogICAgICAgIGZvciBrIGluIHJzdGFs
ZToKICAgICAgICAgICAgcmVzcF9mbG93cy5wb3AoaywgTm9uZSkKCgpkZWYgZHJhaW5faW5jb21w
bGV0ZV93c3NlKGZsb3dzLCBvdXQsIHBlbmRpbmdfdGJsLCBub3c9Tm9uZSk6CiAgICAiIiJGYWxs
IGJhY2sgdG8gZW1pdHRpbmcgdGhlIHJlcXVlc3QgZXZlbnQgaWYgV1NTRSBpbnNwZWN0aW9uIHdh
cyBpbmNvbXBsZXRlLiIiIgogICAgaWYgbm93IGlzIE5vbmU6CiAgICAgICAgbm93ID0gdGltZS50
aW1lKCkKICAgIGZvciBrZXkgaW4gbGlzdChmbG93cy5rZXlzKCkpOgogICAgICAgIGZsID0gZmxv
d3MuZ2V0KGtleSkKICAgICAgICBpZiBmbCBpcyBOb25lOgogICAgICAgICAgICBjb250aW51ZQog
ICAgICAgIGlmIGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQgaXMgbm90IE5vbmU6
CiAgICAgICAgICAgIG91dC5hcHBlbmQoZmwud3NzZV9ldmVudCkKICAgICAgICAgICAgZmwuYXdh
aXRpbmdfd3NzZSA9IEZhbHNlCiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKCgpkZWYgcHJv
Y2Vzc19wYWNrZXQocGt0LCBwb3J0cywgbm9kZV9ob3N0LCBmbG93cywgcmVzcF9mbG93cywgcGVu
ZGluZ190YmwsIG91dCwgbm93PU5vbmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgIG4gPSBsZW4o
cGt0KQogICAgaWYgbiA8IDM0OgogICAgICAgIHJldHVybiBGYWxzZQogICAgaWYgbm93IGlzIE5v
bmU6CiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgIG9mZiA9IDE0CiAgICBldHlwZSA9IHN0
cnVjdC51bnBhY2soIiFIIiwgcGt0WzEyOjE0XSlbMF0KICAgIGlmIGV0eXBlID09IEVUSF9QX1ZM
QU46CiAgICAgICAgaWYgbiA8IDM4OgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBl
dHlwZSA9IHN0cnVjdC51bnBhY2soIiFIIiwgcGt0WzE2OjE4XSlbMF0KICAgICAgICBvZmYgPSAx
OAogICAgZWxpZiBldHlwZSAhPSBFVEhfUF9JUDoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBp
cDAgPSBiMmkocGt0W29mZl0pCiAgICBpZiAoaXAwID4+IDQpICE9IDQgb3IgYjJpKHBrdFtvZmYg
KyA5XSkgIT0gNjoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlobCA9IChpcDAgJiAweDBGKSAq
IDQKICAgIGlmIGlobCA8IDIwIG9yIG4gPCBvZmYgKyBpaGwgKyAyMDoKICAgICAgICByZXR1cm4g
RmFsc2UKCiAgICBmcmFnID0gc3RydWN0LnVucGFjaygiIUgiLCBwa3Rbb2ZmICsgNjpvZmYgKyA4
XSlbMF0KICAgIGlmIGZyYWcgJiAweDFGRkY6CiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgaXBf
dG90YWxfbGVuID0gc3RydWN0LnVucGFjaygiIUgiLCBwa3Rbb2ZmICsgMjpvZmYgKyA0XSlbMF0K
ICAgIGlzX3RydW5jYXRlZCA9IEZhbHNlCiAgICBpZiBpcF90b3RhbF9sZW4gPiAwOgogICAgICAg
IGlmIGlwX3RvdGFsX2xlbiA8IGlobCArIDIwOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAg
ICAgICBpZiBuIC0gb2ZmIDwgaXBfdG90YWxfbGVuOgogICAgICAgICAgICBpc190cnVuY2F0ZWQg
PSBUcnVlCiAgICAgICAgZWxpZiBuIC0gb2ZmID4gaXBfdG90YWxfbGVuOgogICAgICAgICAgICBu
ID0gb2ZmICsgaXBfdG90YWxfbGVuCgogICAgc3JjX2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rb
b2ZmICsgMTI6b2ZmICsgMTZdKQogICAgZHN0X2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rbb2Zm
ICsgMTY6b2ZmICsgMjBdKQogICAgdGNwX29mZiA9IG9mZiArIGlobAogICAgc3BvcnQsIGRwb3J0
ID0gc3RydWN0LnVucGFjaygiIUhIIiwgcGt0W3RjcF9vZmY6dGNwX29mZiArIDRdKQogICAgc2Vx
ID0gc3RydWN0LnVucGFjaygiIUkiLCBwa3RbdGNwX29mZiArIDQ6dGNwX29mZiArIDhdKVswXQog
ICAgZG9mZl9ieXRlID0gYjJpKHBrdFt0Y3Bfb2ZmICsgMTJdKQogICAgZG9mZiA9IChkb2ZmX2J5
dGUgPj4gNCkgKiA0CiAgICBpZiBkb2ZmIDwgMjAgb3IgbiA8IHRjcF9vZmYgKyBkb2ZmOgogICAg
ICAgIHJldHVybiBGYWxzZQoKICAgIGZsYWdzID0gYjJpKHBrdFt0Y3Bfb2ZmICsgMTNdKQogICAg
cGF5X3N0YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Om5d
IGlmIG4gPiBwYXlfc3RhcnQgZWxzZSBiIiIKCiAgICAjIFJlc3BvbnNlIGRpcmVjdGlvbjogU2Vy
dmVyIC0+IENsaWVudAogICAgaWYgc3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0
czoKICAgICAgICByayA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgIGhh
bmRsZV9yZXNwb25zZShyZXNwX2Zsb3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBlbmRpbmdf
dGJsLAogICAgICAgICAgICAgICAgICAgICAgICBzZXE9c2VxLCBmbGFncz1mbGFncywgaXNfdHJ1
bmNhdGVkPWlzX3RydW5jYXRlZCkKICAgICAgICByZXR1cm4gVHJ1ZQoKICAgICMgUmVxdWVzdCBk
aXJlY3Rpb246IENsaWVudCAtPiBTZXJ2ZXIKICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAg
ICAga2V5ID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgbWV0YSA9IChk
c3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgICAgIGhhbmRsZV9wYXlsb2FkKGZsb3dz
LCBrZXksIE5vbmUsIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAg
ICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibCwgbm93LCB3c3NlX2JvZHlfYnl0ZXMsCiAgICAg
ICAgICAgICAgICAgICAgICAgc2VxPXNlcSwgZmxhZ3M9ZmxhZ3MsIGlzX3RydW5jYXRlZD1pc190
cnVuY2F0ZWQpCiAgICAgICAgcmV0dXJuIFRydWUKCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgX2Zs
dXNoX29sZGVzdF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBvdXQpOgogICAgIiIiT3ZlcmZsb3cgZ3Vh
cmQ6IGVtaXQgdGhlIHNpbmdsZSBvbGRlc3QgcGVuZGluZyBldmVudCBhcy1pcy4iIiIKICAgIG9s
ZGVzdF9rZXksIG9sZGVzdF90cyA9IE5vbmUsIE5vbmUKICAgIGZvciByaywgbHN0IGluIHBlbmRp
bmdfdGJsLml0ZW1zKCk6CiAgICAgICAgaWYgbm90IGxzdDoKICAgICAgICAgICAgY29udGludWUK
ICAgICAgICB0cyA9IGxzdFswXVsxXQogICAgICAgIGlmIG9sZGVzdF90cyBpcyBOb25lIG9yIHRz
IDwgb2xkZXN0X3RzOgogICAgICAgICAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSByaywgdHMK
ICAgIGlmIG9sZGVzdF9rZXkgaXMgbm90IE5vbmU6CiAgICAgICAgcGVuZGluZ19wb3Aob2xkZXN0
X2tleSwgb3V0LCBwZW5kaW5nX3RibCkKCgpkZWYgc3dlZXBfcGVuZGluZyhwZW5kaW5nX3RibCwg
bm93LCBvdXQpOgogICAgIiIiVFRMIGZsdXNoOiBlbWl0IHJlcXVlc3RzIHdob3NlIHJlc3BvbnNl
cyBuZXZlciBzaG93ZWQgdXAuIiIiCiAgICBmb3IgcmsgaW4gbGlzdChwZW5kaW5nX3RibC5rZXlz
KCkpOgogICAgICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgICAgICBpZiBub3QgbHN0
OgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGkgPSAwCiAgICAgICAgd2hpbGUgaSA8IGxl
bihsc3QpOgogICAgICAgICAgICBpdGVtID0gbHN0W2ldCiAgICAgICAgICAgIGlzX3RvbWIgPSBp
dGVtWzJdIGlmIGxlbihpdGVtKSA+IDIgZWxzZSBGYWxzZQogICAgICAgICAgICB0b21iX3RzID0g
aXRlbVszXSBpZiBsZW4oaXRlbSkgPiAzIGVsc2UgMC4wCiAgICAgICAgICAgIGlmIGlzX3RvbWI6
CiAgICAgICAgICAgICAgICBpZiBub3cgLSB0b21iX3RzID4gMTAuMDoKICAgICAgICAgICAgICAg
ICAgICBsc3QucG9wKGkpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAg
IGkgKz0gMQogICAgICAgICAgICBlbGlmIG5vdyAtIGl0ZW1bMV0gPiBQRU5ESU5HX1RUTDoKICAg
ICAgICAgICAgICAgIG91dC5hcHBlbmQoaXRlbVswXSkKICAgICAgICAgICAgICAgIGlmIGxlbihp
dGVtKSA+IDM6CiAgICAgICAgICAgICAgICAgICAgaXRlbVsyXSA9IFRydWUKICAgICAgICAgICAg
ICAgICAgICBpdGVtWzNdID0gbm93CiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAg
ICAgICAgIGl0ZW0uZXh0ZW5kKFtUcnVlLCBub3csIDBdKQogICAgICAgICAgICAgICAgaSArPSAx
CiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBpICs9IDEKICAgICAgICBpZiBub3Qg
bHN0OgogICAgICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCgoKZGVmIGRyYWluX3Bl
bmRpbmcocGVuZGluZ190YmwsIG91dCk6CiAgICAiIiJFbWl0IGV2ZXJ5IGNhcHR1cmVkIHJlcXVl
c3QgYmVmb3JlIGNhcHR1cmUgc2h1dGRvd24uCgogICAgUmVzcG9uc2VzIGFyZSBvcHRpb25hbCBl
bnJpY2htZW50LiBBIHN0b3AvcmVzdGFydCBtdXN0IG5vdCBkaXNjYXJkIGEKICAgIHJlcXVlc3Qg
bWVyZWx5IGJlY2F1c2UgaXRzIHJlc3BvbnNlIHdhcyBmaWx0ZXJlZCwgc3BsaXQsIG9yIHN0aWxs
IGluCiAgICBmbGlnaHQgd2hlbiB0aGUgcHJvY2VzcyByZWNlaXZlZCBTSUdURVJNLgogICAgIiIi
CiAgICBmb3IgcmsgaW4gbGlzdChwZW5kaW5nX3RibC5rZXlzKCkpOgogICAgICAgIGxzdCA9IHBl
bmRpbmdfdGJsLnBvcChyaywgTm9uZSkKICAgICAgICBpZiBsc3Q6CiAgICAgICAgICAgIGZvciBp
dGVtIGluIGxzdDoKICAgICAgICAgICAgICAgIGlzX3RvbWIgPSBpdGVtWzJdIGlmIGxlbihpdGVt
KSA+IDIgZWxzZSBGYWxzZQogICAgICAgICAgICAgICAgaWYgbm90IGlzX3RvbWI6CiAgICAgICAg
ICAgICAgICAgICAgb3V0LmFwcGVuZChpdGVtWzBdKQoKCmRlZiBtYWludGVuYW5jZV9kdWUobm93
LCBsYXN0X3N3ZWVwKToKICAgIHJldHVybiBub3cgLSBsYXN0X3N3ZWVwID49IFNXRUVQX0lOVEVS
VkFMCgoKZGVmIGVuZm9yY2VfbGltaXQoZmxvd3MsIG5vdyk6CiAgICAiIiJDYXAgZmxvdy10YWJs
ZSBzaXplIChweTIuNjogbm8gT3JkZXJlZERpY3Qg4oCUIHN3ZWVwIHN0YWxlLCB0aGVuIEZJRk8K
ICAgIGJ5IGluc2VydGlvbiBvcmRlciwgd2hpY2ggcGxhaW4gZGljdHMgcHJlc2VydmUgaW4gQ1B5
dGhvbikuIiIiCiAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICB3aGlsZSBsZW4oZmxvd3Mp
ID4gTUFYX0ZMT1dTOgogICAgICAgIGZsb3dzLnBvcGl0ZW0oKSAgICAgICAgICAjIG9sZGVzdC1p
bnNlcnRlZCBrZXkgb24gQ1B5dGhvbiAyLjYvMi43CgoKZGVmIF9jb250cm9sX2NvbmZpZygpOgog
ICAgIiIiUmVhZCBvcHRpb25hbCBjb250cm9sIHNldHRpbmdzIHdpdGhvdXQgZXhwb3NpbmcgdGhl
IGJlYXJlciB0b2tlbi4iIiIKICAgIGVuZHBvaW50ID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRS
T0xfRU5EUE9JTlQiKSBvciBvcy5lbnZpcm9uLmdldCgiTlRfRU5EUE9JTlQiKQogICAgdG9rZW5f
ZmlsZSA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOX0ZJTEUiLCAiIikKICAgIHRv
a2VuID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9LRU4iLCAiIikKICAgIGlmIHRva2Vu
X2ZpbGU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBmID0gb3Blbih0b2tlbl9maWxlLCAiciIp
CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRva2VuID0gZi5yZWFkKCkuc3RyaXAo
KQogICAgICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgZi5jbG9zZSgpCiAgICAgICAg
ZXhjZXB0IElPRXJyb3I6CiAgICAgICAgICAgIHRva2VuID0gIiIKICAgIG5vZGUgPSBvcy5lbnZp
cm9uLmdldCgiTlRfTk9ERV9OQU1FIikgb3Igc29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4i
KVswXQogICAgcnVuX2RpciA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1JVTiIsICIvdmFy
L2xpYi9uZXR3b3JrdHJhY2luZyIpCiAgICB0cnk6CiAgICAgICAgaW50ZXJ2YWwgPSBtYXgoNSwg
bWluKGludChvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9TRUMiLCAiMzAiKSksIDMwMCkpCiAg
ICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICBpbnRlcnZhbCA9IDMwCiAgICByZXR1cm4gZW5k
cG9pbnQsIHRva2VuLCBub2RlLCBydW5fZGlyLCBpbnRlcnZhbAoKCmRlZiBfcnVuX2NvbnRyb2xf
dGljayhwb3J0cywgaWZhY2UsIHJ1bl9kaXIsIGNsaWVudCk6CiAgICByZXBseSA9IGNsaWVudC5w
b2xsKCkKICAgIGlmIG5vdCByZXBseToKICAgICAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBOb25l
LCAicG9sbCBmYWlsZWQiCiAgICBkZXNpcmVkID0gcmVwbHkuZ2V0KCJkZXNpcmVkIikgb3Ige30K
ICAgIHN0YXRlID0gZGljdChkZXNpcmVkKQogICAgZ2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJn
ZW5lcmF0aW9uIiwgMCkKICAgIGNvbnRyb2xfYWN0aW9uID0gTm9uZQogICAgc3RvcF9yZXF1ZXN0
ZWQgPSBGYWxzZQogICAgaWYgZGVzaXJlZC5nZXQoInBvcnRzIik6CiAgICAgICAgbmV3X3BvcnRz
ID0gc2V0KGRlc2lyZWRbInBvcnRzIl0pCiAgICAgICAgaWYgbmV3X3BvcnRzICE9IHBvcnRzOgog
ICAgICAgICAgICBwb3J0cyA9IG5ld19wb3J0cwogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9
ICJyZXN0YXJ0IgogICAgaWYgZGVzaXJlZC5nZXQoImlmYWNlIik6CiAgICAgICAgbmV3X2lmYWNl
ID0gZGVzaXJlZFsiaWZhY2UiXQogICAgICAgIGlmIG5ld19pZmFjZSAhPSBpZmFjZToKICAgICAg
ICAgICAgaWZhY2UgPSBuZXdfaWZhY2UKICAgICAgICAgICAgY29udHJvbF9hY3Rpb24gPSAicmVz
dGFydCIKICAgIGZvciB0YXNrIGluIHJlcGx5LmdldCgidGFza3MiLCBbXSk6CiAgICAgICAgYWN0
aW9uID0gdGFzay5nZXQoImFjdGlvbiIpCiAgICAgICAgaWYgYWN0aW9uID09ICJoZWFsdGgiOgog
ICAgICAgICAgICBtZXNzYWdlID0gImhlYWx0aHkiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25l
IgogICAgICAgIGVsaWYgYWN0aW9uIGluICgicmVzdGFydCIsICJyZWxvYWQiLCAic2V0X3BvcnRz
Iik6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAiYWNjZXB0ZWQ7IGNhcHR1cmUgcmVzdGFydCByZXF1
ZXN0ZWQiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgICAgICBjb250cm9sX2Fj
dGlvbiA9ICJyZXN0YXJ0IgogICAgICAgICAgICBpZiBhY3Rpb24gPT0gInNldF9wb3J0cyI6CiAg
ICAgICAgICAgICAgICBhcmdzID0gdGFzay5nZXQoImFyZ3MiKSBvciB7fQogICAgICAgICAgICAg
ICAgaWYgYXJncy5nZXQoInBvcnRzIik6CiAgICAgICAgICAgICAgICAgICAgcG9ydHMgPSBzZXQo
YXJnc1sicG9ydHMiXSkKICAgICAgICAgICAgICAgICAgICBzdGF0ZS51cGRhdGUoeyJwb3J0cyI6
IHNvcnRlZChwb3J0cyksICJtb2RlIjogInB5dGhvbiIsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAiZ2VuZXJhdGlvbiI6IGdlbmVyYXRpb259KQogICAgICAgIGVsaWYgYWN0aW9u
ID09ICJzdG9wIjoKICAgICAgICAgICAgbWVzc2FnZSA9ICJzdG9wIHJlcXVlc3RlZCIKICAgICAg
ICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgICAgIHN0b3BfcmVxdWVzdGVkID0gVHJ1ZQog
ICAgICAgIGVsc2U6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAidW5zdXBwb3J0ZWQgYnkgZGlyZWN0
IHNuaWZmZXIiCiAgICAgICAgICAgIHN0YXR1cyA9ICJmYWlsZWQiCiAgICAgICAgY2xpZW50LnJl
cG9ydCh0YXNrLmdldCgiaWQiKSwgc3RhdHVzLCBtZXNzYWdlKQogICAgaWYgc3RvcF9yZXF1ZXN0
ZWQ6CiAgICAgICAgY29udHJvbF9hY3Rpb24gPSAic3RvcCIKICAgIGFwcGxpZWQgPSAoInN0b3Ag
cmVxdWVzdGVkIiBpZiBjb250cm9sX2FjdGlvbiA9PSAic3RvcCIgZWxzZQogICAgICAgICAgICAg
ICAicmVzdGFydCByZXF1aXJlZCIgaWYgY29udHJvbF9hY3Rpb24gPT0gInJlc3RhcnQiIGVsc2UK
ICAgICAgICAgICAgICAgInBvbGwgb2siKQogICAgbnRfY29udHJvbC53cml0ZV9zdGF0ZShvcy5w
YXRoLmpvaW4ocnVuX2RpciwgInJlbW90ZS1kZXNpcmVkLmpzb24iKSwKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgc3RhdGUsIGFwcGxpZWQpCiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRp
b24sIGFwcGxpZWQpCiAgICByZXR1cm4gcG9ydHMsIGlmYWNlLCBjb250cm9sX2FjdGlvbiwgYXBw
bGllZAoKCmRlZiBfcmVzdGFydF9hcmdzKHNjcmlwdCwgaWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3
b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXM9MCk6CiAgICAiIiJCdWlsZCBhIGZyZXNoIGFyZ3YgZm9y
IGFuIGluLXBsYWNlIHJlLWV4ZWMgYWZ0ZXIgYSBjb250cm9sIHVwZGF0ZS4iIiIKICAgICMgUHJl
c2VydmUgdW5idWZmZXJlZCBKU09OTCBkZWxpdmVyeTsgdGhlIGluc3RhbGxlciBzdGFydHMgUHl0
aG9uIHdpdGggLXUuCiAgICBhcmdzID0gW3N5cy5leGVjdXRhYmxlLCAiLXUiLCBvcy5wYXRoLmFi
c3BhdGgoc2NyaXB0KV0KICAgIGlmIGlmYWNlOgogICAgICAgIGFyZ3MuZXh0ZW5kKFsiLWkiLCBp
ZmFjZV0pCiAgICBhcmdzLmV4dGVuZChbIi1wIiwgIiwiLmpvaW4oW3N0cihwKSBmb3IgcCBpbiBz
b3J0ZWQocG9ydHMpXSldKQogICAgYXJncy5leHRlbmQoWyItaiIsICIxIl0pCiAgICBpZiB3c3Nl
X2JvZHlfYnl0ZXM6CiAgICAgICAgYXJncy5leHRlbmQoWyItLXdzc2UtYm9keS1ieXRlcyIsIHN0
cih3c3NlX2JvZHlfYnl0ZXMpXSkKICAgIGlmIHZlcmJvc2U6CiAgICAgICAgYXJncy5hcHBlbmQo
Ii12IikKICAgIHJldHVybiBhcmdzCgoKZGVmIG1haW4oKToKICAgIGlmYWNlLCBwb3J0cywgdmVy
Ym9zZSwgd29ya2Vycywgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0p
CiAgICBub2RlX2hvc3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBj
b250cm9sX2NsaWVudCA9IE5vbmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBj
b250cm9sX3J1biwgY29udHJvbF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBu
dF9jb250cm9sIGlzIG5vdCBOb25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5
OgogICAgICAgICAgICBjb250cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChl
bmRwb2ludCwgdG9rZW4sIGNvbnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGgu
aXNkaXIoY29udHJvbF9ydW4pOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9y
dW4pCiAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhj
ZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9s
IGRpc2FibGVkICglcykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5Ogog
ICAgICAgICMgcHJvdG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90
aCBJTkdSRVNTIChyZXEpIGFuZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExp
bnV4IGtlcm5lbCBwYWNrZXQgc29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2Nr
ZXQuQUZfUEFDS0VULCBzb2NrZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAg
c29ja2V0Lmh0b25zKEVUSF9QX0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAg
ICAgcmFpc2UgU3lzdGVtRXhpdCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZv
cm0iKQogICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoImNhbm5vdCBvcGVuIEFGX1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAg
ICAgICAgICAgICAgICAgICAiQ0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVv
dXQoMS4wKQogICAgaWYgbm90IGFwcGx5X3BlcmZfb3B0cyhzLCBwb3J0cyk6CiAgICAgICAgcy5j
bG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgia2VybmVsIEJQRiBzYWZldHkgZmlsdGVy
IHVuYXZhaWxhYmxlOyByZWZ1c2luZyB1bmZpbHRlcmVkIGNhcHR1cmUiKQogICAgdHJ5OgogICAg
ICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIsIEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVy
cm9yIGFzIGU6CiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fu
bm90IGJpbmQgQUZfUEFDS0VUIHRvICVzICglcykiICUKICAgICAgICAgICAgICAgICAgICAgICAg
IChpZmFjZSBvciAiPGFsbD4iLCBlKSkKICAgIGlmIG5vdCBkcm9wX2NhcHR1cmVfY2FwYWJpbGl0
aWVzKCk6CiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90
IGRyb3AgQ0FQX05FVF9SQVcgYWZ0ZXIgc29ja2V0IHNldHVwOyByZWZ1c2luZyB1bnNhZmUgY2Fw
dHVyZSIpCgogICAgIyBwcmVjb21waWxlZCBzdHJ1Y3QgcmVhZGVycyDigJQgdW5wYWNrX2Zyb20g
cmVhZHMgc3RyYWlnaHQgb3V0IG9mIHRoZQogICAgIyBwYWNrZXQgYnVmZmVyIChubyBzbGljZSBj
b3BpZXMpIGFuZCB5aWVsZHMgaW50cyB1bmRlciBweTIgQU5EIHB5MwogICAgdTE2ID0gc3RydWN0
LlN0cnVjdCgiIUgiKS51bnBhY2tfZnJvbQogICAgdWggPSBzdHJ1Y3QuU3RydWN0KCIhSEgiKS51
bnBhY2tfZnJvbSAgICMgc3BvcnQsZHBvcnQgaW4gb25lIHJlYWQKICAgIHViID0gc3RydWN0LlN0
cnVjdCgiIUJCIikudW5wYWNrX2Zyb20KICAgIG50b2EgPSBzb2NrZXQuaW5ldF9udG9hCgogICAg
Zmxvd3MgPSB7fQogICAgcmVzcF9mbG93cyA9IHt9CiAgICBydW5uaW5nID0gW1RydWVdCiAgICBz
dGF0c19pbnRlcnZhbCA9IHN0YXRzX2ludGVydmFsX3NlY29uZHMoKQogICAgc3RhdHNfc3RhdGUg
PSB7InBhY2tldHNfdG90YWwiOiAwLCAicGFja2V0X2J5dGVzX3RvdGFsIjogMCwKICAgICAgICAg
ICAgICAgICAgICJldmVudHNfZW1pdHRlZF90b3RhbCI6IDAsICJrZXJuZWxfZHJvcHNfdG90YWwi
OiAwLAogICAgICAgICAgICAgICAgICAgImxhc3RfcGFja2V0cyI6IDAsICJsYXN0X3BhY2tldF9i
eXRlcyI6IDAsCiAgICAgICAgICAgICAgICAgICAibGFzdF9ldmVudHMiOiAwLCAibGFzdF9hdCI6
IHRpbWUudGltZSgpfQoKICAgIGRlZiB3cml0ZV9ldmVudHMoaXRlbXMpOgogICAgICAgIGlmIG5v
dCBpdGVtczoKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgdyA9IHN5cy5zdGRvdXQud3JpdGUK
ICAgICAgICBmb3IgaXRlbSBpbiBpdGVtczoKICAgICAgICAgICAgdyhqc29uLmR1bXBzKGl0ZW0p
ICsgIlxuIikKICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICBzdGF0c19zdGF0ZVsi
ZXZlbnRzX2VtaXR0ZWRfdG90YWwiXSArPSBsZW4oaXRlbXMpCgogICAgZGVmIGVtaXRfY2FwdHVy
ZV9zdGF0cyhmb3JjZT1GYWxzZSk6CiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICBl
bGFwc2VkID0gbm93IC0gc3RhdHNfc3RhdGVbImxhc3RfYXQiXQogICAgICAgIGlmIG5vdCBmb3Jj
ZSBhbmQgZWxhcHNlZCA8IHN0YXRzX2ludGVydmFsOgogICAgICAgICAgICByZXR1cm4KICAgICAg
ICBkcm9wcGVkX2RlbHRhID0gMAogICAgICAgIHRyeToKICAgICAgICAgICAgcmF3X3N0YXRzID0g
cy5nZXRzb2Nrb3B0KFNPTF9QQUNLRVQsIFBBQ0tFVF9TVEFUSVNUSUNTLCA4KQogICAgICAgICAg
ICBfLCBkcm9wcGVkX2RlbHRhID0gc3RydWN0LnVucGFjaygiSUkiLCByYXdfc3RhdHNbOjhdKQog
ICAgICAgIGV4Y2VwdCAoc29ja2V0LmVycm9yLCBzdHJ1Y3QuZXJyb3IpOgogICAgICAgICAgICBk
cm9wcGVkX2RlbHRhID0gMAogICAgICAgIHN0YXRzX3N0YXRlWyJrZXJuZWxfZHJvcHNfdG90YWwi
XSArPSBkcm9wcGVkX2RlbHRhCiAgICAgICAgcGFja2V0c19kZWx0YSA9IChzdGF0c19zdGF0ZVsi
cGFja2V0c190b3RhbCJdIC0KICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJs
YXN0X3BhY2tldHMiXSkKICAgICAgICBieXRlc19kZWx0YSA9IChzdGF0c19zdGF0ZVsicGFja2V0
X2J5dGVzX3RvdGFsIl0gLQogICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0
X3BhY2tldF9ieXRlcyJdKQogICAgICAgIGV2ZW50c19kZWx0YSA9IChzdGF0c19zdGF0ZVsiZXZl
bnRzX2VtaXR0ZWRfdG90YWwiXSAtCiAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRzX3N0YXRl
WyJsYXN0X2V2ZW50cyJdKQogICAgICAgIHdhaXRpbmdfd3NzZSA9IDAKICAgICAgICBmb3IgZmxv
dyBpbiBmbG93cy52YWx1ZXMoKToKICAgICAgICAgICAgaWYgZmxvdy5ldmVudCBpcyBub3QgTm9u
ZSBhbmQgZmxvdy5ib2R5X2dvYWw6CiAgICAgICAgICAgICAgICB3YWl0aW5nX3dzc2UgKz0gMQog
ICAgICAgIHBlbmRpbmdfY291bnQgPSBzdW0obGVuKGl0ZW1zKSBmb3IgaXRlbXMgaW4gcGVuZGlu
Zy52YWx1ZXMoKSkKICAgICAgICBkcm9wX3BjdCA9IDEwMC4wICogZHJvcHBlZF9kZWx0YSAvIG1h
eCgxLCBwYWNrZXRzX2RlbHRhKQogICAgICAgIGNhcHR1cmUgPSB7CiAgICAgICAgICAgICJwYWNr
ZXRzX3RvdGFsIjogc3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXSwKICAgICAgICAgICAgInBh
Y2tldHNfZGVsdGEiOiBwYWNrZXRzX2RlbHRhLAogICAgICAgICAgICAicGFja2V0X2J5dGVzX3Rv
dGFsIjogc3RhdHNfc3RhdGVbInBhY2tldF9ieXRlc190b3RhbCJdLAogICAgICAgICAgICAicGFj
a2V0X2J5dGVzX2RlbHRhIjogYnl0ZXNfZGVsdGEsCiAgICAgICAgICAgICJrZXJuZWxfZHJvcHNf
dG90YWwiOiBzdGF0c19zdGF0ZVsia2VybmVsX2Ryb3BzX3RvdGFsIl0sCiAgICAgICAgICAgICJr
ZXJuZWxfZHJvcHNfZGVsdGEiOiBkcm9wcGVkX2RlbHRhLAogICAgICAgICAgICAia2VybmVsX2Ry
b3BfcGVyY2VudCI6IHJvdW5kKGRyb3BfcGN0LCA0KSwKICAgICAgICAgICAgImludmFsaWRfZnJh
bWVzX3RvdGFsIjogMCwKICAgICAgICAgICAgImV2ZW50c19lbWl0dGVkX3RvdGFsIjogc3RhdHNf
c3RhdGVbImV2ZW50c19lbWl0dGVkX3RvdGFsIl0sCiAgICAgICAgICAgICJldmVudHNfZW1pdHRl
ZF9kZWx0YSI6IGV2ZW50c19kZWx0YSwKICAgICAgICAgICAgImZsb3dzX2FjdGl2ZSI6IGxlbihm
bG93cyksCiAgICAgICAgICAgICJwZW5kaW5nX3JlcXVlc3RzIjogcGVuZGluZ19jb3VudCwKICAg
ICAgICAgICAgIndzc2VfYm9keV9mbG93c19hY3RpdmUiOiB3YWl0aW5nX3dzc2V9CiAgICAgICAg
c3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKHsiX250X2ludGVybmFsIjogImNhcHR1cmVfc3Rh
dHNfdjEiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNhcHR1cmUiOiBj
YXB0dXJlfSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VwYXJhdG9ycz0o
IiwiLCAiOiIpKSArICJcbiIpCiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAgc3Rh
dHNfc3RhdGVbImxhc3RfcGFja2V0cyJdID0gc3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXQog
ICAgICAgIHN0YXRzX3N0YXRlWyJsYXN0X3BhY2tldF9ieXRlcyJdID0gc3RhdHNfc3RhdGVbInBh
Y2tldF9ieXRlc190b3RhbCJdCiAgICAgICAgc3RhdHNfc3RhdGVbImxhc3RfZXZlbnRzIl0gPSBz
dGF0c19zdGF0ZVsiZXZlbnRzX2VtaXR0ZWRfdG90YWwiXQogICAgICAgIHN0YXRzX3N0YXRlWyJs
YXN0X2F0Il0gPSBub3cKCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5u
aW5nWzBdID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAg
ICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRp
bWUudGltZSgpCiAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5p
bmcgb24gJXMgcG9ydHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNv
cnRlZChwb3J0cyksIG9zLmdldHBpZCgpKSkKICAgIGlmIHdzc2VfYm9keV9ieXRlczoKICAgICAg
ICBsb2coIldTU0UgVXNlcm5hbWVUb2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5kZWQgdG8g
JWQgYnl0ZXMvcmVxdWVzdCkiICUKICAgICAgICAgICAgd3NzZV9ib2R5X2J5dGVzKQoKICAgICMg
MXMgcmVjdiB0aW1lb3V0OiAoYSkgbGV0cyB0aGUgcGVuZGluZy9mbG93IHN3ZWVwcyBhY3R1YWxs
eSBmaXJlIOKAlAogICAgIyB3aXRob3V0IGl0IGBleGNlcHQgc29ja2V0LnRpbWVvdXRgIG5ldmVy
IHJ1bnM7IChiKSBlbXBpcmljYWxseSBSRVFVSVJFRAogICAgIyB3aXRoIHRoZSBCUEYgZmlsdGVy
IGF0dGFjaGVkOiBhIGZ1bGx5LWJsb2NraW5nIHJlY3Ygb24gdGhpcyBrZXJuZWwKICAgICMgc3Rh
cnZlcyBhZnRlciB0aGUgZmlyc3QgcGFja2V0LCB3aGlsZSB0aGUgdGltZW91dCdkIHJlY3YgZGVs
aXZlcnMKICAgICMgY29udGludW91c2x5ICh2ZXJpZmllZCBieSBBL0I6IHJ4PTEgdnMgcng9Mjkg
aWRlbnRpY2FsIG90aGVyd2lzZSkuCiAgICBzLnNldHRpbWVvdXQoMS4wKQoKICAgIGRiZyA9IG9z
LmVudmlyb24uZ2V0KCJOVF9TTklGRl9ERUJVRyIpID09ICIxIgogICAgZGJnX3J4ID0gMAogICAg
ZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgd2hpbGUgcnVubmluZ1swXToKICAgICAgICBlbWl0
X2NhcHR1cmVfc3RhdHMoKQogICAgICAgICMgUG9sbCBpbmRlcGVuZGVudGx5IG9mIHNvY2tldCBp
ZGxlIHRpbWUuIEEgYnVzeSBtb25pdG9yZWQgaW50ZXJmYWNlCiAgICAgICAgIyBtYXkgbmV2ZXIg
cmFpc2Ugc29ja2V0LnRpbWVvdXQsIGJ1dCBjb250cm9sIGNoYW5nZXMgbXVzdCBzdGlsbCBhcHBs
eS4KICAgICAgICBpZiBjb250cm9sX2NsaWVudCBpcyBub3QgTm9uZSBhbmQgdGltZS50aW1lKCkg
Pj0gY29udHJvbF9uZXh0OgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBwb3J0cywg
aWZhY2UsIGNvbnRyb2xfYWN0aW9uLCBjb250cm9sX3N0YXR1cyA9IF9ydW5fY29udHJvbF90aWNr
KAogICAgICAgICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwgY29udHJvbF9ydW4sIGNvbnRyb2xf
Y2xpZW50KQogICAgICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29udHJvbDogJXMiICUgY29udHJv
bF9zdGF0dXMpCiAgICAgICAgICAgICAgICBpZiBjb250cm9sX2FjdGlvbiA9PSAicmVzdGFydCI6
CiAgICAgICAgICAgICAgICAgICAgYXJncyA9IF9yZXN0YXJ0X2FyZ3Moc3lzLmFyZ3ZbMF0sIGlm
YWNlLCBwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJi
b3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgICAgICAgICAgICAgbG9nKCJy
ZW1vdGUgY29udHJvbDogcmUtZXhlY3V0aW5nIGNhcHR1cmUgd2l0aCB1cGRhdGVkIGNvbmZpZ3Vy
YXRpb24iKQogICAgICAgICAgICAgICAgICAgIHMuY2xvc2UoKQogICAgICAgICAgICAgICAgICAg
IG9zLmV4ZWN2KHN5cy5leGVjdXRhYmxlLCBhcmdzKQogICAgICAgICAgICAgICAgZWxpZiBjb250
cm9sX2FjdGlvbiA9PSAic3RvcCI6CiAgICAgICAgICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29u
dHJvbDogc3RvcCByZXF1ZXN0ZWQ7IGV4aXRpbmciKQogICAgICAgICAgICAgICAgICAgIHJ1bm5p
bmdbMF0gPSBGYWxzZQogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGV4
Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgIGxvZygiV0FSTjogcmVtb3RlIGNv
bnRyb2wgdGljayBmYWlsZWQgKCVzKSIgJSBudF9jb250cm9sLnNhZmVfbWVzc2FnZShlKSkKICAg
ICAgICAgICAgY29udHJvbF9uZXh0ID0gdGltZS50aW1lKCkgKyBjb250cm9sX2ludGVydmFsCiAg
ICAgICAgdHJ5OgogICAgICAgICAgICBwa3QgPSBzLnJlY3YoNjU1MzUpCiAgICAgICAgICAgIGRi
Z19yeCArPSAxCiAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJwYWNrZXRzX3RvdGFsIl0gKz0gMQog
ICAgICAgICAgICBzdGF0c19zdGF0ZVsicGFja2V0X2J5dGVzX3RvdGFsIl0gKz0gbGVuKHBrdCkK
ICAgICAgICAgICAgaWYgZGJnIGFuZCB0aW1lLnRpbWUoKSAtIGRiZ19sYXN0ID4gNToKICAgICAg
ICAgICAgICAgIGxvZygiREVCVUcgcng9JWQiICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJn
X2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAg
ICAgICAgaWYgZGJnOgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAl
IGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgICAgICAg
ICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5vdywg
bGFzdF9zd2VlcCk6CiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgICAgICBz
d2VlcF9pZGxlKGZsb3dzLCBub3csIG91dF9zLCBwZW5kaW5nLCByZXNwX2Zsb3dzKQogICAgICAg
ICAgICAgICAgc3dlZXBfcGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICAg
ICAgd3JpdGVfZXZlbnRzKG91dF9zKQogICAgICAgICAgICAgICAgbGFzdF9zd2VlcCA9IG5vdwog
ICAgICAgICAgICBjb250aW51ZQogICAgICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAg
ICAgICAgICAgaWYgZS5lcnJubyA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRp
bnVlCiAgICAgICAgICAgIHJhaXNlCgogICAgICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAg
b3V0ID0gW10KICAgICAgICBwcm9jZXNzX3BhY2tldChwa3QsIHBvcnRzLCBub2RlX2hvc3QsIGZs
b3dzLCByZXNwX2Zsb3dzLCBwZW5kaW5nLAogICAgICAgICAgICAgICAgICAgICAgIG91dCwgbm93
LCB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgaWYgb3V0OgogICAgICAgICAgICB3cml0ZV9ldmVu
dHMob3V0KQoKICAgICAgICBpZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAg
ICAgICAgICAgb3V0X3MgPSBbXQogICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3csIG91
dF9zLCBwZW5kaW5nLCByZXNwX2Zsb3dzKQogICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRp
bmcsIG5vdywgb3V0X3MpCiAgICAgICAgICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgICAgICAg
ICAgbGFzdF9zd2VlcCA9IG5vdwoKICAgIG91dF9zID0gW10KICAgIGRyYWluX2luY29tcGxldGVf
d3NzZShmbG93cywgb3V0X3MsIHBlbmRpbmcsIHRpbWUudGltZSgpKQogICAgZHJhaW5fcGVuZGlu
ZyhwZW5kaW5nLCBvdXRfcykKICAgIHdyaXRlX2V2ZW50cyhvdXRfcykKICAgIGVtaXRfY2FwdHVy
ZV9zdGF0cyhmb3JjZT1UcnVlKQogICAgbG9nKCJzdG9wcGVkICglZCBwZW5kaW5nIHJlcXVlc3Rz
IGZsdXNoZWQpIiAlIGxlbihvdXRfcykpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAg
IG1haW4oKQo=
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
CiNpbmNsdWRlIDxmc3RyZWFtPgojaW5jbHVkZSA8bWFwPgojaW5jbHVkZSA8bGlzdD4KI2luY2x1
ZGUgPHNzdHJlYW0+CiNpbmNsdWRlIDxzdHJpbmc+CiNpbmNsdWRlIDx2ZWN0b3I+CiNpbmNsdWRl
IDxhbGdvcml0aG0+CgpzdGF0aWMgdm9sYXRpbGUgc2lnX2F0b21pY190IGdfcnVubmluZyA9IDE7
CnN0YXRpYyB2b2lkIHN0b3Bfc2lnbmFsKGludCkgeyBnX3J1bm5pbmcgPSAwOyB9CgpzdGF0aWMg
Y29uc3Qgc2l6ZV90IE1BWF9GTE9XUyA9IDQwOTY7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1RP
VEFMX0JVRkZFUl9CWVRFUyA9IDE2ICogMTAyNCAqIDEwMjQ7IC8vIDE2IE1pQiBhZ2dyZWdhdGUg
YnVkZ2V0CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BFTkRJTkdfVE9UQUwgPSA0MDk2OyAgICAg
ICAgICAgICAgICAgICAvLyA0MDk2IGdsb2JhbCBwZW5kaW5nIHJlcXVlc3RzCnN0YXRpYyBjb25z
dCBzaXplX3QgTUFYX1BFTkRJTkdfUEVSX0ZMT1cgPSAzMjsKc3RhdGljIGNvbnN0IHNpemVfdCBN
QVhfUE9SVFMgPSAzMDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfSEVBREVSX0JZVEVTID0gMzI3
Njg7ICAgICAgICAgICAgICAgICAgIC8vIDMyIEtpQgpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9G
TE9XX0JVRkZFUl9CWVRFUyA9IDY1NTM2OyAgICAgICAgICAgICAgLy8gNjQgS2lCCnN0YXRpYyBj
b25zdCBzaXplX3QgTUFYX1dTU0VfQk9EWV9CWVRFUyA9IDY1NTM2OwpzdGF0aWMgY29uc3Qgc2l6
ZV90IE1BWF9XU1NFX0JPRFlfRkxPV1MgPSAyNTY7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1dT
U0VfVVNFUk5BTUUgPSAyMDA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0JBVENIID0gNDAwOwpz
dGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9RVUVVRSA9IDQwMDA7CnN0YXRpYyBjb25zdCBzaXplX3Qg
TUFYX1BPU1RfQllURVMgPSA2NTUzNjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfU1RBVFNfQllU
RVMgPSAxNjM4NDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIERFRkFVTFRfU0hJUF9SQVRFX0tCUFMg
PSAxMDI0OwpzdGF0aWMgY29uc3QgaW50IEZMVVNIX1NFQyA9IDU7CnN0YXRpYyBjb25zdCBpbnQg
UkVUUllfU0VDID0gNjA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RUTCA9IDE1OwpzdGF0
aWMgY29uc3QgdW5zaWduZWQgREVGQVVMVF9QRU5ESU5HX1RUTCA9IDMwOwpzdGF0aWMgdW5zaWdu
ZWQgZ19wZW5kaW5nX3R0bF9zZWMgPSBERUZBVUxUX1BFTkRJTkdfVFRMOwpzdGF0aWMgY29uc3Qg
dW5zaWduZWQgQUNDRVBUID0gMjA0ODsKc3RhdGljIGNvbnN0IGludCBTT19BVFRBQ0hfRklMVEVS
X09MRCA9IDI2OwpzdGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfSVBfSE9TVCA9IDB4
MDgwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNob3J0IEVUSF9QXzgwMjFRX0hPU1QgPSAweDgx
MDA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX09PT19TRUdNRU5UUyA9IDQ7CnN0YXRpYyBjb25z
dCBzaXplX3QgTUFYX0RSQUlOX1BFUl9QQVNTID0gMjU2OwoKc3RhdGljIGlubGluZSBsb25nIGxv
bmcgbm93X21vbm90b25pY19tcygpIHsKICBzdHJ1Y3QgdGltZXNwZWMgdHM7CiAgY2xvY2tfZ2V0
dGltZShDTE9DS19NT05PVE9OSUMsICZ0cyk7CiAgcmV0dXJuIChsb25nIGxvbmcpdHMudHZfc2Vj
ICogMTAwMExMICsgdHMudHZfbnNlYyAvIDEwMDAwMDBMTDsKfQoKc3RhdGljIGlubGluZSBpbnQz
Ml90IHNlcV9kaWZmKHVpbnQzMl90IGEsIHVpbnQzMl90IGIpIHsKICByZXR1cm4gKGludDMyX3Qp
KGEgLSBiKTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIHRyaW0oY29uc3Qgc3RkOjpzdHJpbmcgJnMp
IHsKICBzaXplX3QgYSA9IDAsIGIgPSBzLnNpemUoKTsKICB3aGlsZSAoYSA8IGIgJiYgaXNzcGFj
ZSgodW5zaWduZWQgY2hhcilzW2FdKSkgKythOwogIHdoaWxlIChiID4gYSAmJiBpc3NwYWNlKCh1
bnNpZ25lZCBjaGFyKXNbYiAtIDFdKSkgLS1iOwogIHJldHVybiBzLnN1YnN0cihhLCBiIC0gYSk7
Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGxvd2VyKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3Rk
OjpzdHJpbmcgeCA9IHM7CiAgc2l6ZV90IGk7IGZvciAoaSA9IDA7IGkgPCB4LnNpemUoKTsgKytp
KSB4W2ldID0gKGNoYXIpdG9sb3dlcigodW5zaWduZWQgY2hhcil4W2ldKTsKICByZXR1cm4geDsK
fQpzdGF0aWMgc3RkOjpzdHJpbmcganNvbnEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6
OnN0cmluZyB4ID0gIlwiIjsgc2l6ZV90IGk7CiAgZm9yIChpID0gMDsgaSA8IHMuc2l6ZSgpOyAr
K2kpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKXNbaV07CiAgICBpZiAo
YyA9PSAnXFwnIHx8IGMgPT0gJ1wiJykgeyB4ICs9ICdcXCc7IHggKz0gKGNoYXIpYzsgfQogICAg
ZWxzZSBpZiAoYyA9PSAnXG4nKSB4ICs9ICJcXG4iOwogICAgZWxzZSBpZiAoYyA9PSAnXHInKSB4
ICs9ICJcXHIiOwogICAgZWxzZSBpZiAoYyA9PSAnXHQnKSB4ICs9ICJcXHQiOwogICAgZWxzZSBp
ZiAoYyA8IDMyKSB4ICs9ICc/JzsKICAgIGVsc2UgeCArPSAoY2hhciljOwogIH0KICB4ICs9ICdc
Iic7IHJldHVybiB4Owp9CnN0YXRpYyBsb25nIGxvbmcgbm93X21zKCkgewogIHN0cnVjdCB0aW1l
dmFsIHR2OyBnZXR0aW1lb2ZkYXkoJnR2LCBOVUxMKTsKICByZXR1cm4gKGxvbmcgbG9uZyl0di50
dl9zZWMgKiAxMDAwTEwgKyB0di50dl91c2VjIC8gMTAwMDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcg
bnVtKGxvbmcgdikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsgbyA8PCB2OyByZXR1cm4gby5zdHIo
KTsgfQpzdGF0aWMgYm9vbCB2YWxpZF9wb3J0KHVuc2lnbmVkIHApIHsgcmV0dXJuIHAgPiAwICYm
IHAgPD0gNjU1MzU7IH0KCnN0YXRpYyB1aW50MTZfdCByZWFkX3UxNihjb25zdCB1bnNpZ25lZCBj
aGFyICpwKSB7CiAgdWludDE2X3QgdmFsdWU7CiAgbWVtY3B5KCZ2YWx1ZSwgcCwgc2l6ZW9mKHZh
bHVlKSk7CiAgcmV0dXJuIHZhbHVlOwp9CgpzdGF0aWMgdWludDMyX3QgcmVhZF91MzIoY29uc3Qg
dW5zaWduZWQgY2hhciAqcCkgewogIHVpbnQzMl90IHZhbHVlOwogIG1lbWNweSgmdmFsdWUsIHAs
IHNpemVvZih2YWx1ZSkpOwogIHJldHVybiB2YWx1ZTsKfQpzdGF0aWMgYm9vbCBoYXNfbWV0aG9k
KGNvbnN0IHN0ZDo6c3RyaW5nICZtKSB7CiAgcmV0dXJuIG0gPT0gIkdFVCIgfHwgbSA9PSAiUE9T
VCIgfHwgbSA9PSAiUFVUIiB8fCBtID09ICJERUxFVEUiIHx8CiAgICAgICAgIG0gPT0gIlBBVENI
IiB8fCBtID09ICJIRUFEIiB8fCBtID09ICJPUFRJT05TIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcg
aG9zdF9uYW1lKCkgewogIGNoYXIgYlsyNTZdOyBpZiAoZ2V0aG9zdG5hbWUoYiwgc2l6ZW9mKGIp
IC0gMSkgIT0gMCkgcmV0dXJuICJ1bmtub3duLW5vZGUiOwogIGJbc2l6ZW9mKGIpIC0gMV0gPSAw
OyBjaGFyICpwID0gc3RyY2hyKGIsICcuJyk7IGlmIChwKSAqcCA9IDA7IHJldHVybiBiOwp9Cgov
KiBTdHJpY3QgQmFzZTY0IGRlY29kZXIgd2l0aCB1aW50MzIgYWNjdW11bGF0b3IsIGltbWVkaWF0
ZSBzdG9wIGF0ICc6JywgYW5kIGludmFsaWQgY2hhciByZWplY3Rpb24gKi8Kc3RhdGljIHN0ZDo6
c3RyaW5nIGI2NGRlY29kZV91c2VyKGNvbnN0IGNoYXIgKmluLCBzaXplX3QgaW5fbGVuKSB7CiAg
d2hpbGUgKGluX2xlbiA+IDAgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcikqaW4pKSB7ICsraW47
IC0taW5fbGVuOyB9CiAgd2hpbGUgKGluX2xlbiA+IDAgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hh
cilpbltpbl9sZW4gLSAxXSkpIHsgLS1pbl9sZW47IH0KICBzdGQ6OnN0cmluZyBvdXQ7CiAgdWlu
dDMyX3QgdmFsID0gMDsKICBpbnQgYml0cyA9IC04OwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwg
aW5fbGVuOyArK2kpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWluW2ld
OwogICAgaW50IGQgPSAtMTsKICAgIGlmIChjID49ICdBJyAmJiBjIDw9ICdaJykgZCA9IGMgLSAn
QSc7CiAgICBlbHNlIGlmIChjID49ICdhJyAmJiBjIDw9ICd6JykgZCA9IGMgLSAnYScgKyAyNjsK
ICAgIGVsc2UgaWYgKGMgPj0gJzAnICYmIGMgPD0gJzknKSBkID0gYyAtICcwJyArIDUyOwogICAg
ZWxzZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsKICAgIGVsc2UgaWYgKGMgPT0gJy8nKSBkID0gNjM7
CiAgICBlbHNlIGlmIChjID09ICc9JykgYnJlYWs7CiAgICBlbHNlIGlmIChpc3NwYWNlKGMpKSBj
b250aW51ZTsKICAgIGVsc2UgcmV0dXJuICIiOwogICAgdmFsID0gKHZhbCA8PCA2KSB8ICh1aW50
MzJfdClkOwogICAgYml0cyArPSA2OwogICAgaWYgKGJpdHMgPj0gMCkgewogICAgICBjaGFyIGNo
ID0gKGNoYXIpKCh2YWwgPj4gYml0cykgJiAweGZmKTsKICAgICAgYml0cyAtPSA4OwogICAgICBp
ZiAoY2ggPT0gJzonKSBicmVhazsKICAgICAgb3V0ICs9IGNoOwogICAgICBpZiAob3V0LnNpemUo
KSA+IDY0KSBicmVhazsKICAgIH0KICB9CiAgcmV0dXJuIG91dDsKfQoKc3RhdGljIHN0ZDo6c3Ry
aW5nIGlwX3RvX3N0cih1aW50MzJfdCBpcF9iZSkgewogIGNoYXIgYltJTkVUX0FERFJTVFJMRU5d
OwogIGluZXRfbnRvcChBRl9JTkVULCAmaXBfYmUsIGIsIHNpemVvZihiKSk7CiAgcmV0dXJuIGI7
Cn0KCnN0YXRpYyBpbmxpbmUgYm9vbCBpc19oZXgoY2hhciBjKSB7CiAgcmV0dXJuIChjID49ICcw
JyAmJiBjIDw9ICc5JykgfHwgKGMgPj0gJ2EnICYmIGMgPD0gJ2YnKSB8fCAoYyA+PSAnQScgJiYg
YyA8PSAnRicpOwp9CgpzdGF0aWMgc3RkOjpzdHJpbmcgdHJhY2VfaWRfZnJvbV9wYXJlbnQoY29u
c3Qgc3RkOjpzdHJpbmcgJnRwKSB7CiAgc3RkOjpzdHJpbmcgeCA9IHRyaW0odHApOwogIGlmICh4
LnNpemUoKSAhPSA1NSB8fCB4WzJdICE9ICctJyB8fCB4WzM1XSAhPSAnLScgfHwgeFs1Ml0gIT0g
Jy0nKSByZXR1cm4gIiI7CiAgaWYgKHhbMF0gIT0gJzAnIHx8IHhbMV0gIT0gJzAnKSByZXR1cm4g
IiI7CiAgYm9vbCBhbGxfemVyb3MgPSB0cnVlOwogIGZvciAoc2l6ZV90IGkgPSAzOyBpIDwgMzU7
ICsraSkgewogICAgaWYgKCFpc19oZXgoeFtpXSkpIHJldHVybiAiIjsKICAgIGlmICh4W2ldICE9
ICcwJykgYWxsX3plcm9zID0gZmFsc2U7CiAgfQogIGlmIChhbGxfemVyb3MpIHJldHVybiAiIjsK
ICBib29sIHNwYW5femVyb3MgPSB0cnVlOwogIGZvciAoc2l6ZV90IGkgPSAzNjsgaSA8IDUyOyAr
K2kpIHsKICAgIGlmICghaXNfaGV4KHhbaV0pKSByZXR1cm4gIiI7CiAgICBpZiAoeFtpXSAhPSAn
MCcpIHNwYW5femVyb3MgPSBmYWxzZTsKICB9CiAgaWYgKHNwYW5femVyb3MpIHJldHVybiAiIjsK
ICByZXR1cm4gbG93ZXIoeC5zdWJzdHIoMywgMzIpKTsKfQoKc3RhdGljIHVpbnQ2NF90IGdfcm5n
X3N0YXRlID0gMDsKc3RhdGljIHZvaWQgaW5pdF9ybmcoKSB7CiAgRklMRSAqZiA9IGZvcGVuKCIv
ZGV2L3VyYW5kb20iLCAicmIiKTsKICBpZiAoZikgewogICAgc2l6ZV90IG4gPSBmcmVhZCgmZ19y
bmdfc3RhdGUsIDEsIHNpemVvZihnX3JuZ19zdGF0ZSksIGYpOwogICAgKHZvaWQpbjsKICAgIGZj
bG9zZShmKTsKICB9CiAgaWYgKCFnX3JuZ19zdGF0ZSkgewogICAgZ19ybmdfc3RhdGUgPSAoKHVp
bnQ2NF90KXRpbWUoTlVMTCkgPDwgMzIpIF4gKHVpbnQ2NF90KWdldHBpZCgpOwogIH0KfQpzdGF0
aWMgaW5saW5lIHVpbnQ2NF90IG5leHRfcm5nKCkgewogIHVpbnQ2NF90IHggPSBnX3JuZ19zdGF0
ZTsKICB4IF49IHggPDwgMTM7IHggXj0geCA+PiA3OyB4IF49IHggPDwgMTc7CiAgcmV0dXJuIGdf
cm5nX3N0YXRlID0gKHggPyB4IDogMHg4NTNjNDllNjc0OGZlYTliVUxMKTsKfQoKc3RhdGljIHN0
ZDo6c3RyaW5nIG1ha2VfdHJhY2VwYXJlbnQoc3RkOjpzdHJpbmcgKnRpZCkgewogIHVpbnQ2NF90
IHIxID0gbmV4dF9ybmcoKTsKICB1aW50NjRfdCByMiA9IG5leHRfcm5nKCk7CiAgdWludDY0X3Qg
cjMgPSBuZXh0X3JuZygpOwogIGNoYXIgYnVmWzY0XTsKICBzbnByaW50ZihidWYsIHNpemVvZihi
dWYpLCAiMDAtJTAxNmxseCUwMTZsbHgtJTAxNmxseC0wMSIsCiAgICAgICAgICAgKHVuc2lnbmVk
IGxvbmcgbG9uZylyMSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMiwgKHVuc2lnbmVkIGxvbmcgbG9u
ZylyMyk7CiAgY2hhciB0aWRfYnVmWzMzXTsKICBzbnByaW50Zih0aWRfYnVmLCBzaXplb2YodGlk
X2J1ZiksICIlMDE2bGx4JTAxNmxseCIsCiAgICAgICAgICAgKHVuc2lnbmVkIGxvbmcgbG9uZyly
MSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMik7CiAgKnRpZCA9IHRpZF9idWY7CiAgcmV0dXJuIGJ1
ZjsKfQoKc3RydWN0IEV2ZW50IHsKICBsb25nIHRzOyBzdGQ6OnN0cmluZyBob3N0LCBzcmMsIHNl
cnZpY2UsIG1ldGhvZCwgcGF0aCwgdXNlciwgc2NoZW1lLCBwcm9iZTsKICBzdGQ6OnN0cmluZyBi
YXNpY191c2VyLCB3c3NlX3VzZXI7CiAgc3RkOjpzdHJpbmcgaG9zdF9oZHIsIHVzZXJfYWdlbnQs
IHhmZiwgY2FsbGVyLCBkc3RfaXAsIHRyYWNlcGFyZW50LCB0cmFjZV9pZDsKICB1bnNpZ25lZCBj
YWxsZXJfcG9ydCwgZHN0X3BvcnQsIHJlcV9ieXRlcywgcmVzcF9ieXRlczsgaW50IHN0YXR1czsg
bG9uZyBkdXJhdGlvbl9tczsKICBib29sIGhhc19zdGF0dXMsIGhhc19kdXJhdGlvbiwgaGFzX3Jl
c3A7CiAgRXZlbnQoKSA6IHRzKDApLCBjYWxsZXJfcG9ydCgwKSwgZHN0X3BvcnQoMCksIHJlcV9i
eXRlcygwKSwgcmVzcF9ieXRlcygwKSwgc3RhdHVzKDApLCBkdXJhdGlvbl9tcygwKSwgaGFzX3N0
YXR1cyhmYWxzZSksIGhhc19kdXJhdGlvbihmYWxzZSksIGhhc19yZXNwKGZhbHNlKSB7fQp9Owpz
dHJ1Y3QgUmVxdWVzdE1ldGEgewogIHN0ZDo6c3RyaW5nIGNvbnRlbnRfdHlwZSwgdHJhbnNmZXJf
ZW5jb2Rpbmc7CiAgc2l6ZV90IGNvbnRlbnRfbGVuZ3RoOwogIGJvb2wgaGFzX2NvbnRlbnRfbGVu
Z3RoOwogIGJvb2wgaGFzX2NvbmZsaWN0X2NsOwogIFJlcXVlc3RNZXRhKCkgOiBjb250ZW50X2xl
bmd0aCgwKSwgaGFzX2NvbnRlbnRfbGVuZ3RoKGZhbHNlKSwgaGFzX2NvbmZsaWN0X2NsKGZhbHNl
KSB7fQp9OwoKc3RydWN0IFRjcFNlZ21lbnQgewogIHVpbnQzMl90IHNlcTsKICBzdGQ6OnN0cmlu
ZyBkYXRhOwp9OwoKc3RhdGljIHNpemVfdCBnX3RvdGFsX2Zsb3dfYnl0ZXMgPSAwOwpzdGF0aWMg
aW5saW5lIHZvaWQgZmxvd19ieXRlc19hZGQoc2l6ZV90IG4pIHsKICBnX3RvdGFsX2Zsb3dfYnl0
ZXMgKz0gbjsKfQpzdGF0aWMgaW5saW5lIHZvaWQgZmxvd19ieXRlc19zdWIoc2l6ZV90IG4pIHsK
ICBpZiAoZ190b3RhbF9mbG93X2J5dGVzID49IG4pIGdfdG90YWxfZmxvd19ieXRlcyAtPSBuOwog
IGVsc2UgZ190b3RhbF9mbG93X2J5dGVzID0gMDsKfQoKc3RydWN0IEZsb3cgewogIHVpbnQzMl90
IG5leHRfc2VxOwogIGJvb2wgaGFzX3NlcTsKICBib29sIGlzX2Jyb2tlbjsKICBib29sIGNvcnJl
bGF0aW9uX2Rpc2FibGVkOwogIHRpbWVfdCB0b3VjaGVkOwogIGxvbmcgbG9uZyBmaXJzdF9ieXRl
X21vbm9fbXM7CiAgdWludDMyX3QgZ2VuZXJhdGlvbjsKICBzdGQ6OnN0cmluZyBidWY7CiAgc3Rk
Ojp2ZWN0b3I8VGNwU2VnbWVudD4gb29vOwoKICBlbnVtIEh0dHBTdGF0ZSB7CiAgICBIVFRQX1NU
QVRFX0hFQURFUiwKICAgIEhUVFBfU1RBVEVfQk9EWSwKICAgIEhUVFBfU1RBVEVfQ0hVTkssCiAg
ICBIVFRQX1NUQVRFX0NMT1NFX0JPRFkKICB9IHN0YXRlOwoKICBzaXplX3QgYm9keV9yZW1haW5p
bmc7CiAgc2l6ZV90IGNodW5rX3BheWxvYWRfcmVtYWluaW5nOwogIGJvb2wgY2h1bmtfcmVhZGlu
Z19sZW47CiAgYm9vbCBjaHVua19yZWFkaW5nX2NybGY7CiAgYm9vbCBjaHVua19yZWFkaW5nX3Ry
YWlsZXI7CgogIGJvb2wgYXdhaXRpbmdfd3NzZTsKICBFdmVudCB3c3NlX2V2ZW50OwogIHN0ZDo6
c3RyaW5nIHdzc2VfYnVmOwogIHNpemVfdCB3c3NlX2dvYWw7CgogIEZsb3coKSA6IG5leHRfc2Vx
KDApLCBoYXNfc2VxKGZhbHNlKSwgaXNfYnJva2VuKGZhbHNlKSwgY29ycmVsYXRpb25fZGlzYWJs
ZWQoZmFsc2UpLAogICAgICAgICAgIHRvdWNoZWQodGltZShOVUxMKSksIGZpcnN0X2J5dGVfbW9u
b19tcygwKSwgZ2VuZXJhdGlvbigwKSwKICAgICAgICAgICBzdGF0ZShIVFRQX1NUQVRFX0hFQURF
UiksIGJvZHlfcmVtYWluaW5nKDApLCBjaHVua19wYXlsb2FkX3JlbWFpbmluZygwKSwKICAgICAg
ICAgICBjaHVua19yZWFkaW5nX2xlbih0cnVlKSwgY2h1bmtfcmVhZGluZ19jcmxmKGZhbHNlKSwg
Y2h1bmtfcmVhZGluZ190cmFpbGVyKGZhbHNlKSwKICAgICAgICAgICBhd2FpdGluZ193c3NlKGZh
bHNlKSwgd3NzZV9nb2FsKDApIHt9CgogIHZvaWQgY2xlYXJfYnVmZmVycygpIHsKICAgIGZsb3df
Ynl0ZXNfc3ViKGJ1Zi5zaXplKCkpOwogICAgYnVmLmNsZWFyKCk7CiAgICBmbG93X2J5dGVzX3N1
Yih3c3NlX2J1Zi5zaXplKCkpOwogICAgd3NzZV9idWYuY2xlYXIoKTsKICAgIGZvciAoc2l6ZV90
IGkgPSAwOyBpIDwgb29vLnNpemUoKTsgKytpKSB7CiAgICAgIGZsb3dfYnl0ZXNfc3ViKG9vb1tp
XS5kYXRhLnNpemUoKSk7CiAgICB9CiAgICBvb28uY2xlYXIoKTsKICB9CgogIGJvb2wgYnVmX2Fw
cGVuZChjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuKSB7CiAgICBpZiAoYnVmLnNpemUoKSAr
IGxlbiA+IE1BWF9GTE9XX0JVRkZFUl9CWVRFUykgewogICAgICBjbGVhcl9idWZmZXJzKCk7CiAg
ICAgIGlzX2Jyb2tlbiA9IHRydWU7CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KICAgIGJ1Zi5h
cHBlbmQoZGF0YSwgbGVuKTsKICAgIGZsb3dfYnl0ZXNfYWRkKGxlbik7CiAgICByZXR1cm4gdHJ1
ZTsKICB9CgogIHZvaWQgYnVmX2VyYXNlKHNpemVfdCBvZmYsIHNpemVfdCBsZW4pIHsKICAgIGlm
IChvZmYgPj0gYnVmLnNpemUoKSkgcmV0dXJuOwogICAgaWYgKGxlbiA+IGJ1Zi5zaXplKCkgLSBv
ZmYpIGxlbiA9IGJ1Zi5zaXplKCkgLSBvZmY7CiAgICBidWYuZXJhc2Uob2ZmLCBsZW4pOwogICAg
Zmxvd19ieXRlc19zdWIobGVuKTsKICB9CgogIHZvaWQgd3NzZV9hcHBlbmQoY29uc3QgY2hhciAq
ZGF0YSwgc2l6ZV90IGxlbikgewogICAgd3NzZV9idWYuYXBwZW5kKGRhdGEsIGxlbik7CiAgICBm
bG93X2J5dGVzX2FkZChsZW4pOwogIH0KCiAgYm9vbCBvb29fcHVzaCh1aW50MzJfdCBzZXEsIGNv
bnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4pIHsKICAgIGlmIChvb28uc2l6ZSgpID49IE1BWF9P
T09fU0VHTUVOVFMpIHJldHVybiBmYWxzZTsKICAgIFRjcFNlZ21lbnQgc2VnOwogICAgc2VnLnNl
cSA9IHNlcTsKICAgIHNlZy5kYXRhLmFzc2lnbihkYXRhLCBsZW4pOwogICAgb29vLnB1c2hfYmFj
ayhzZWcpOwogICAgZmxvd19ieXRlc19hZGQobGVuKTsKICAgIHJldHVybiB0cnVlOwogIH0KCiAg
dm9pZCBvb29fZXJhc2Uoc2l6ZV90IGlkeCkgewogICAgaWYgKGlkeCA8IG9vby5zaXplKCkpIHsK
ICAgICAgZmxvd19ieXRlc19zdWIob29vW2lkeF0uZGF0YS5zaXplKCkpOwogICAgICBvb28uZXJh
c2Uob29vLmJlZ2luKCkgKyBpZHgpOwogICAgfQogIH0KfTsKCnN0cnVjdCBGbG93S2V5IHsKICB1
aW50MzJfdCBzX2lwOwogIHVpbnQxNl90IHNwb3J0OwogIHVpbnQzMl90IGRfaXA7CiAgdWludDE2
X3QgZHBvcnQ7CiAgYm9vbCBvcGVyYXRvcjwoY29uc3QgRmxvd0tleSAmeCkgY29uc3QgewogICAg
aWYgKHNfaXAgIT0geC5zX2lwKSByZXR1cm4gc19pcCA8IHguc19pcDsKICAgIGlmIChzcG9ydCAh
PSB4LnNwb3J0KSByZXR1cm4gc3BvcnQgPCB4LnNwb3J0OwogICAgaWYgKGRfaXAgIT0geC5kX2lw
KSByZXR1cm4gZF9pcCA8IHguZF9pcDsKICAgIHJldHVybiBkcG9ydCA8IHguZHBvcnQ7CiAgfQp9
Owp0eXBlZGVmIEZsb3dLZXkgUGFja2V0S2V5OwoKc3RhdGljIHVpbnQ2NF90IGdfcmVxX2lkX3Nl
cSA9IDA7CgpzdHJ1Y3QgUGVuZGluZyB7CiAgdWludDY0X3QgcmVxX2lkOwogIHVpbnQzMl90IGdl
bmVyYXRpb247CiAgRXZlbnQgZXY7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfd2FsbF9tczsKICBsb25n
IGxvbmcgc3RhcnRlZF9tb25vX21zOwogIGJvb2wgaXNfdG9tYnN0b25lOwogIGxvbmcgbG9uZyB0
b21ic3RvbmVfbW9ub19tczsKICBQZW5kaW5nKCkgOiByZXFfaWQoMCksIGdlbmVyYXRpb24oMCks
IHN0YXJ0ZWRfd2FsbF9tcygwKSwgc3RhcnRlZF9tb25vX21zKDApLAogICAgICAgICAgICAgIGlz
X3RvbWJzdG9uZShmYWxzZSksIHRvbWJzdG9uZV9tb25vX21zKDApIHt9CiAgUGVuZGluZyh1aW50
NjRfdCBpZCwgdWludDMyX3QgZ2VuLCBjb25zdCBFdmVudCAmZSwgbG9uZyBsb25nIHdhbGxfdCwg
bG9uZyBsb25nIG1vbm9fdCkKICAgIDogcmVxX2lkKGlkKSwgZ2VuZXJhdGlvbihnZW4pLCBldihl
KSwgc3RhcnRlZF93YWxsX21zKHdhbGxfdCksIHN0YXJ0ZWRfbW9ub19tcyhtb25vX3QpLAogICAg
ICBpc190b21ic3RvbmUoZmFsc2UpLCB0b21ic3RvbmVfbW9ub19tcygwKSB7fQp9OwoKc3RydWN0
IFBlbmRpbmdRdWV1ZVJlZiB7CiAgdWludDY0X3QgcmVxX2lkOwogIHVpbnQzMl90IGdlbmVyYXRp
b247CiAgUGFja2V0S2V5IGtleTsKICBsb25nIGxvbmcgc3RhcnRlZF9tb25vX21zOwp9OwoKc3Rh
dGljIHNpemVfdCBnX3RvdGFsX3BlbmRpbmdfY291bnQgPSAwOwpzdGF0aWMgc3RkOjpsaXN0PFBl
bmRpbmdRdWV1ZVJlZj4gZ19wZW5kaW5nX2ZpZm87CgpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qg
c3RkOjpzdHJpbmcgJnMpIHsgZnByaW50ZihzdGRlcnIsICJudC1zbmlmZi1jcHA6ICVzXG4iLCBz
LmNfc3RyKCkpOyBmZmx1c2goc3RkZXJyKTsgfQoKc3RhdGljIGJvb2wgcGFyc2VfZGVjaW1hbF9z
aXplKGNvbnN0IGNoYXIgKnAsIHNpemVfdCBuLCBzaXplX3QgKm91dCkgewogIHdoaWxlIChuICYm
IGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpKnApKSB7ICsrcDsgLS1uOyB9CiAgd2hpbGUgKG4gJiYg
aXNzcGFjZSgodW5zaWduZWQgY2hhcilwW24gLSAxXSkpIC0tbjsKICBpZiAoIW4pIHJldHVybiBm
YWxzZTsKICBzaXplX3QgdmFsdWUgPSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgbjsgKytp
KSB7CiAgICBpZiAocFtpXSA8ICcwJyB8fCBwW2ldID4gJzknKSByZXR1cm4gZmFsc2U7CiAgICB1
bnNpZ25lZCBkaWdpdCA9ICh1bnNpZ25lZCkocFtpXSAtICcwJyk7CiAgICBpZiAodmFsdWUgPiAo
c2l6ZV90KS0xIC8gMTAgfHwgdmFsdWUgKiAxMCA+IChzaXplX3QpLTEgLSBkaWdpdCkgcmV0dXJu
IGZhbHNlOwogICAgdmFsdWUgPSB2YWx1ZSAqIDEwICsgZGlnaXQ7CiAgfQogICpvdXQgPSB2YWx1
ZTsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgcGFyc2VfcmVxdWVzdChjb25zdCBjaGFy
ICpkYXRhLCBzaXplX3QgbGVuLCBFdmVudCAqZSwgUmVxdWVzdE1ldGEgKm1ldGEpIHsKICBjb25z
dCBjaGFyICplbmQgPSBkYXRhICsgbGVuOwogIGNvbnN0IGNoYXIgKnAgPSBkYXRhOwogIGNvbnN0
IGNoYXIgKmVvbCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogIGlm
ICghZW9sKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKilt
ZW1jaHIocCwgJyAnLCBlb2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGUtPm1l
dGhvZC5hc3NpZ24ocCwgc3AxIC0gcCk7CiAgaWYgKCFoYXNfbWV0aG9kKGUtPm1ldGhvZCkpIHJl
dHVybiBmYWxzZTsKCiAgY29uc3QgY2hhciAqcGF0aF9zdGFydCA9IHNwMSArIDE7CiAgd2hpbGUg
KHBhdGhfc3RhcnQgPCBlb2wgJiYgKnBhdGhfc3RhcnQgPT0gJyAnKSArK3BhdGhfc3RhcnQ7CiAg
Y29uc3QgY2hhciAqc3AyID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJyAnLCBl
b2wgLSBwYXRoX3N0YXJ0KTsKICBpZiAoIXNwMikgc3AyID0gKGVvbCA+IGRhdGEgJiYgKihlb2wg
LSAxKSA9PSAnXHInKSA/IGVvbCAtIDEgOiBlb2w7CiAgY29uc3QgY2hhciAqcW1hcmsgPSAoY29u
c3QgY2hhciAqKW1lbWNocihwYXRoX3N0YXJ0LCAnPycsIHNwMiAtIHBhdGhfc3RhcnQpOwogIHNp
emVfdCBwYXRoX2xlbiA9IChxbWFyayA/IHFtYXJrIDogc3AyKSAtIHBhdGhfc3RhcnQ7CiAgaWYg
KHBhdGhfbGVuID4gMTIwKSBwYXRoX2xlbiA9IDEyMDsKICBlLT5wYXRoLmFzc2lnbihwYXRoX3N0
YXJ0LCBwYXRoX2xlbik7CgogIHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBp
ZiAoKnAgPT0gJ1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVf
ZW5kID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxp
bmVfZW5kKSBsaW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNo
YXIgKiltZW1jaHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAg
IHNpemVfdCBobmFtZV9sZW4gPSBjb2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9zdGFy
dCA9IGNvbG9uICsgMTsKICAgICAgd2hpbGUgKHZhbF9zdGFydCA8IGxpbmVfZW5kICYmICgqdmFs
X3N0YXJ0ID09ICcgJyB8fCAqdmFsX3N0YXJ0ID09ICdcdCcpKSArK3ZhbF9zdGFydDsKICAgICAg
Y29uc3QgY2hhciAqdmFsX2VuZCA9IGxpbmVfZW5kOwogICAgICB3aGlsZSAodmFsX2VuZCA+IHZh
bF9zdGFydCAmJiAodmFsX2VuZFstMV0gPT0gJ1xyJyB8fCB2YWxfZW5kWy0xXSA9PSAnXG4nIHx8
IHZhbF9lbmRbLTFdID09ICcgJyB8fCB2YWxfZW5kWy0xXSA9PSAnXHQnKSkgLS12YWxfZW5kOwog
ICAgICBzaXplX3QgdmFsX2xlbiA9IHZhbF9lbmQgLSB2YWxfc3RhcnQ7CgogICAgICBpZiAoaG5h
bWVfbGVuID09IDEzICYmICFzdHJuY2FzZWNtcChwLCAiYXV0aG9yaXphdGlvbiIsIDEzKSkgewog
ICAgICAgIGlmICh2YWxfbGVuID4gNiAmJiAhc3RybmNhc2VjbXAodmFsX3N0YXJ0LCAiQmFzaWMg
IiwgNikpIHsKICAgICAgICAgIHN0ZDo6c3RyaW5nIGJhc2ljX3VzZXIgPSBiNjRkZWNvZGVfdXNl
cih2YWxfc3RhcnQgKyA2LCB2YWxfbGVuIC0gNik7CiAgICAgICAgICBpZiAoIWJhc2ljX3VzZXIu
ZW1wdHkoKSkgewogICAgICAgICAgICBlLT5iYXNpY191c2VyID0gYmFzaWNfdXNlcjsKICAgICAg
ICAgICAgZS0+dXNlciA9IGJhc2ljX3VzZXI7CiAgICAgICAgICAgIGUtPnNjaGVtZSA9ICJiYXNp
YyI7CiAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIGlmICh2YWxfbGVuID4gNyAmJiAhc3RybmNh
c2VjbXAodmFsX3N0YXJ0LCAiQmVhcmVyICIsIDcpKSB7CiAgICAgICAgICBlLT5zY2hlbWUgPSAi
YmVhcmVyIjsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDExICYmICFz
dHJuY2FzZWNtcChwLCAidHJhY2VwYXJlbnQiLCAxMSkpIHsKICAgICAgICBlLT50cmFjZXBhcmVu
dC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgICBlLT50cmFjZV9pZCA9IHRyYWNl
X2lkX2Zyb21fcGFyZW50KGUtPnRyYWNlcGFyZW50KTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9s
ZW4gPT0gNCAmJiAhc3RybmNhc2VjbXAocCwgImhvc3QiLCA0KSkgewogICAgICAgIGUtPmhvc3Rf
aGRyLmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2UgaWYgKGhuYW1lX2xl
biA9PSAxMCAmJiAhc3RybmNhc2VjbXAocCwgInVzZXItYWdlbnQiLCAxMCkpIHsKICAgICAgICBl
LT51c2VyX2FnZW50LmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2UgaWYg
KGhuYW1lX2xlbiA9PSAxNSAmJiAhc3RybmNhc2VjbXAocCwgIngtZm9yd2FyZGVkLWZvciIsIDE1
KSkgewogICAgICAgIGUtPnhmZi5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBl
bHNlIGlmIChtZXRhICYmIGhuYW1lX2xlbiA9PSAxMiAmJiAhc3RybmNhc2VjbXAocCwgImNvbnRl
bnQtdHlwZSIsIDEyKSkgewogICAgICAgIG1ldGEtPmNvbnRlbnRfdHlwZS5hc3NpZ24odmFsX3N0
YXJ0LCB2YWxfbGVuKTsKICAgICAgfSBlbHNlIGlmIChtZXRhICYmIGhuYW1lX2xlbiA9PSAxNCAm
JiAhc3RybmNhc2VjbXAocCwgImNvbnRlbnQtbGVuZ3RoIiwgMTQpKSB7CiAgICAgICAgc2l6ZV90
IGNsZW5fdmFsID0gMDsKICAgICAgICBpZiAocGFyc2VfZGVjaW1hbF9zaXplKHZhbF9zdGFydCwg
dmFsX2xlbiwgJmNsZW5fdmFsKSkgewogICAgICAgICAgaWYgKG1ldGEtPmhhc19jb250ZW50X2xl
bmd0aCAmJiBtZXRhLT5jb250ZW50X2xlbmd0aCAhPSBjbGVuX3ZhbCkgewogICAgICAgICAgICBt
ZXRhLT5oYXNfY29uZmxpY3RfY2wgPSB0cnVlOwogICAgICAgICAgfQogICAgICAgICAgbWV0YS0+
Y29udGVudF9sZW5ndGggPSBjbGVuX3ZhbDsKICAgICAgICAgIG1ldGEtPmhhc19jb250ZW50X2xl
bmd0aCA9IHRydWU7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIG1ldGEtPmhhc19jb25mbGlj
dF9jbCA9IHRydWU7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVu
ID09IDE3ICYmICFzdHJuY2FzZWNtcChwLCAidHJhbnNmZXItZW5jb2RpbmciLCAxNykpIHsKICAg
ICAgICBtZXRhLT50cmFuc2Zlcl9lbmNvZGluZy5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsK
ICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CgoKCiAgaWYgKGUtPnVzZXIu
ZW1wdHkoKSkgZS0+dXNlciA9ICItYW5vbnltb3VzLSI7CiAgaWYgKGUtPnNjaGVtZS5lbXB0eSgp
KSBlLT5zY2hlbWUgPSAibm9uZSI7CiAgaWYgKGUtPnRyYWNlX2lkLmVtcHR5KCkpIGUtPnRyYWNl
cGFyZW50ID0gbWFrZV90cmFjZXBhcmVudCgmZS0+dHJhY2VfaWQpOwogIHJldHVybiB0cnVlOwp9
CgpzdGF0aWMgYm9vbCBpc193c3NlX25hbWVzcGFjZShjb25zdCBzdGQ6OnN0cmluZyAmdXJpKSB7
CiAgcmV0dXJuIHVyaSA9PSAiaHR0cDovL2RvY3Mub2FzaXMtb3Blbi5vcmcvd3NzLzIwMDQvMDEv
b2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNkIiB8fAogICAgICAgICB1
cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMDcvc2VjZXh0IiB8fAog
ICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMTIvc2Vj
ZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIw
MDMvMDYvc2VjZXh0IjsKfQoKc3RhdGljIGJvb2wgaXNfc29hcF9jb250ZW50X3R5cGUoY29uc3Qg
c3RkOjpzdHJpbmcgJmN0KSB7CiAgc3RkOjpzdHJpbmcgeCA9IGxvd2VyKGN0KTsKICByZXR1cm4g
eC5maW5kKCJ0ZXh0L3htbCIpICE9IHN0ZDo6c3RyaW5nOjpucG9zIHx8CiAgICAgICAgIHguZmlu
ZCgiYXBwbGljYXRpb24vc29hcCt4bWwiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAgICAg
ICB4LmZpbmQoIit4bWwiKSAhPSBzdGQ6OnN0cmluZzo6bnBvczsKfQoKc3RhdGljIHZvaWQgc3Bs
aXRfcW5hbWUoY29uc3Qgc3RkOjpzdHJpbmcgJnFuYW1lLCBzdGQ6OnN0cmluZyAqcHJlZml4LCBz
dGQ6OnN0cmluZyAqbG9jYWwpIHsKICBzaXplX3QgcCA9IHFuYW1lLmZpbmQoJzonKTsKICBpZiAo
cCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgeyBwcmVmaXgtPmNsZWFyKCk7ICpsb2NhbCA9IHFuYW1l
OyB9CiAgZWxzZSB7ICpwcmVmaXggPSBxbmFtZS5zdWJzdHIoMCwgcCk7ICpsb2NhbCA9IHFuYW1l
LnN1YnN0cihwICsgMSk7IH0KfQoKc3RhdGljIGJvb2wgeG1sX3VuZXNjYXBlKGNvbnN0IHN0ZDo6
c3RyaW5nICZpbiwgc3RkOjpzdHJpbmcgKm91dCkgewogIG91dC0+Y2xlYXIoKTsKICBvdXQtPnJl
c2VydmUoaW4uc2l6ZSgpKTsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGluLnNpemUoKTsgKytp
KSB7CiAgICBpZiAoaW5baV0gIT0gJyYnKSB7IG91dC0+cHVzaF9iYWNrKGluW2ldKTsgY29udGlu
dWU7IH0KICAgIHNpemVfdCBzZW1pID0gaW4uZmluZCgnOycsIGkgKyAxKTsKICAgIGlmIChzZW1p
ID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gZmFsc2U7CiAgICBzdGQ6OnN0cmluZyByZWYg
PSBpbi5zdWJzdHIoaSArIDEsIHNlbWkgLSBpIC0gMSk7CiAgICBpZiAocmVmID09ICJhbXAiKSBv
dXQtPnB1c2hfYmFjaygnJicpOwogICAgZWxzZSBpZiAocmVmID09ICJsdCIpIG91dC0+cHVzaF9i
YWNrKCc8Jyk7CiAgICBlbHNlIGlmIChyZWYgPT0gImd0Iikgb3V0LT5wdXNoX2JhY2soJz4nKTsK
ICAgIGVsc2UgaWYgKHJlZiA9PSAicXVvdCIpIG91dC0+cHVzaF9iYWNrKCciJyk7CiAgICBlbHNl
IGlmIChyZWYgPT0gImFwb3MiKSBvdXQtPnB1c2hfYmFjaygnXCcnKTsKICAgIGVsc2UgaWYgKCFy
ZWYuZW1wdHkoKSAmJiByZWZbMF0gPT0gJyMnKSB7CiAgICAgIHVuc2lnbmVkIGxvbmcgdmFsID0g
MDsKICAgICAgY2hhciAqZW5kcCA9IE5VTEw7CiAgICAgIGlmIChyZWYuc2l6ZSgpID4gMiAmJiAo
cmVmWzFdID09ICd4JyB8fCByZWZbMV0gPT0gJ1gnKSkgewogICAgICAgIHZhbCA9IHN0cnRvdWwo
cmVmLmNfc3RyKCkgKyAyLCAmZW5kcCwgMTYpOwogICAgICB9IGVsc2UgewogICAgICAgIHZhbCA9
IHN0cnRvdWwocmVmLmNfc3RyKCkgKyAxLCAmZW5kcCwgMTApOwogICAgICB9CiAgICAgIGlmICgh
ZW5kcCB8fCAqZW5kcCAhPSAnXDAnIHx8IHZhbCA+IDB4MTBmZmZmVUwpIHJldHVybiBmYWxzZTsK
ICAgICAgaWYgKHZhbCA8IDB4ODApIHsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcil2YWwp
OwogICAgICB9IGVsc2UgaWYgKHZhbCA8IDB4ODAwKSB7CiAgICAgICAgb3V0LT5wdXNoX2JhY2so
KGNoYXIpKDB4YzAgfCAodmFsID4+IDYpKSk7CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIp
KDB4ODAgfCAodmFsICYgMHgzZikpKTsKICAgICAgfSBlbHNlIGlmICh2YWwgPCAweDEwMDAwKSB7
CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ZTAgfCAodmFsID4+IDEyKSkpOwogICAg
ICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKCh2YWwgPj4gNikgJiAweDNmKSkpOwog
ICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKHZhbCAmIDB4M2YpKSk7CiAgICAg
IH0gZWxzZSB7CiAgICAgICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ZjAgfCAodmFsID4+IDE4
KSkpOwogICAgICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKCh2YWwgPj4gMTIpICYg
MHgzZikpKTsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgodmFsID4+IDYp
ICYgMHgzZikpKTsKICAgICAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICh2YWwgJiAw
eDNmKSkpOwogICAgICB9CiAgICB9IGVsc2UgewogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAg
ICBpID0gc2VtaTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHZhbGlkX3V0Zjhf
dXNlcm5hbWUoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBpZiAocy5lbXB0eSgpIHx8IHMuc2l6
ZSgpID4gTUFYX1dTU0VfVVNFUk5BTUUgKiA0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IGNoYXJh
Y3RlcnMgPSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7KSB7CiAgICB1bnNp
Z25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgdW5zaWduZWQgbG9uZyBjcCA9
IDA7CiAgICBzaXplX3QgbmVlZCA9IDA7CiAgICBpZiAoYyA8IDB4ODApIHsgY3AgPSBjOyBuZWVk
ID0gMDsgKytpOyB9CiAgICBlbHNlIGlmICgoYyAmIDB4ZTApID09IDB4YzApIHsgbmVlZCA9IDE7
IH0KICAgIGVsc2UgaWYgKChjICYgMHhmMCkgPT0gMHhlMCkgeyBuZWVkID0gMjsgfQogICAgZWxz
ZSBpZiAoKGMgJiAweGY4KSA9PSAweGYwKSB7IG5lZWQgPSAzOyB9CiAgICBlbHNlIHJldHVybiBm
YWxzZTsKCiAgICBpZiAobmVlZCkgewogICAgICBpZiAoaSArIG5lZWQgPj0gcy5zaXplKCkpIHJl
dHVybiBmYWxzZTsKICAgICAgaWYgKG5lZWQgPT0gMSAmJiBjIDwgMHhjMikgcmV0dXJuIGZhbHNl
OwogICAgICBpZiAobmVlZCA9PSAyICYmIGMgPT0gMHhlMCAmJiAodW5zaWduZWQgY2hhcilzW2kg
KyAxXSA8IDB4YTApIHJldHVybiBmYWxzZTsKICAgICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4
ZWQgJiYgKHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPj0gMHhhMCkgcmV0dXJuIGZhbHNlOwogICAg
ICBpZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmMCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA8
IDB4OTApIHJldHVybiBmYWxzZTsKICAgICAgaWYgKG5lZWQgPT0gMyAmJiBjID09IDB4ZjQgJiYg
KHVuc2lnbmVkIGNoYXIpc1tpICsgMV0gPj0gMHg5MCkgcmV0dXJuIGZhbHNlOwogICAgICBjcCA9
IGMgJiAoKDFVIDw8ICg3IC0gbmVlZCAtIDEpKSAtIDEpOwogICAgICBmb3IgKHNpemVfdCBqID0g
MTsgaiA8PSBuZWVkOyArK2opIGNwID0gKGNwIDw8IDYpIHwgKCh1bnNpZ25lZCBjaGFyKXNbaSAr
IGpdICYgMHgzZik7CiAgICAgIGkgKz0gbmVlZCArIDE7CiAgICB9CiAgICBpZiAoKytjaGFyYWN0
ZXJzID4gTUFYX1dTU0VfVVNFUk5BTUUpIHJldHVybiBmYWxzZTsKICAgIGlmIChjcCA8IDB4MjAg
fHwgKGNwID49IDB4N2YgJiYgY3AgPD0gMHg5ZikgfHwKICAgICAgICAoY3AgPj0gMHhlMDAwICYm
IGNwIDw9IDB4ZjhmZikgfHwKICAgICAgICAoY3AgPj0gMHhmMDAwMCAmJiBjcCA8PSAweGZmZmZk
KSB8fAogICAgICAgIChjcCA+PSAweDEwMDAwMCAmJiBjcCA8PSAweDEwZmZmZCkgfHwKICAgICAg
ICAoY3AgPj0gMHhmZGQwICYmIGNwIDw9IDB4ZmRlZikgfHwgKGNwICYgMHhmZmZmVUwpID49IDB4
ZmZmZVVMIHx8CiAgICAgICAgY3AgPT0gMHgwMGFkIHx8IGNwID09IDB4MDYxYyB8fCBjcCA9PSAw
eDA2ZGQgfHwgY3AgPT0gMHgwNzBmIHx8CiAgICAgICAgY3AgPT0gMHgxODBlIHx8IChjcCA+PSAw
eDIwMGIgJiYgY3AgPD0gMHgyMDBmKSB8fAogICAgICAgIChjcCA+PSAweDIwMmEgJiYgY3AgPD0g
MHgyMDJlKSB8fCAoY3AgPj0gMHgyMDYwICYmIGNwIDw9IDB4MjA2ZikgfHwKICAgICAgICBjcCA9
PSAweGZlZmYpIHJldHVybiBmYWxzZTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0cnVjdCBYbWxG
cmFtZSB7CiAgc3RkOjptYXA8c3RkOjpzdHJpbmcsIHN0ZDo6c3RyaW5nPiBuczsKICBzdGQ6OnN0
cmluZyBxbmFtZSwgdXJpLCBsb2NhbDsKfTsKCnN0YXRpYyBib29sIHBhcnNlX3htbF9uYW1lKGNv
bnN0IHN0ZDo6c3RyaW5nICZib2R5LCBzaXplX3QgbGltaXQsIHNpemVfdCAqcG9zLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICBzdGQ6OnN0cmluZyAqbmFtZSkgewogIHNpemVfdCBzdGFydCA9
ICpwb3M7CiAgd2hpbGUgKCpwb3MgPCBsaW1pdCkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVu
c2lnbmVkIGNoYXIpYm9keVsqcG9zXTsKICAgIGlmICghKGlzYWxudW0oYykgfHwgYyA9PSAnXycg
fHwgYyA9PSAnLScgfHwgYyA9PSAnLicgfHwgYyA9PSAnOicpKSBicmVhazsKICAgICsrKnBvczsK
ICB9CiAgaWYgKCpwb3MgPT0gc3RhcnQgfHwgKnBvcyAtIHN0YXJ0ID4gMjU2KSByZXR1cm4gZmFs
c2U7CiAgbmFtZS0+YXNzaWduKGJvZHksIHN0YXJ0LCAqcG9zIC0gc3RhcnQpOwogIHJldHVybiB0
cnVlOwp9CgpzdGF0aWMgc3RkOjpzdHJpbmcgZXh0cmFjdF93c3NlX3VzZXJuYW1lKGNvbnN0IHN0
ZDo6c3RyaW5nICZib2R5KSB7CiAgaWYgKGJvZHkuZW1wdHkoKSB8fCBib2R5LnNpemUoKSA+IE1B
WF9XU1NFX0JPRFlfQllURVMgfHwKICAgICAgYm9keS5maW5kKCdcMCcpICE9IHN0ZDo6c3RyaW5n
OjpucG9zKSByZXR1cm4gIiI7CiAgc3RkOjpzdHJpbmcgbG93ZXJlZCA9IGxvd2VyKGJvZHkpOwog
IGlmIChsb3dlcmVkLmZpbmQoIjwhZG9jdHlwZSIpICE9IHN0ZDo6c3RyaW5nOjpucG9zIHx8CiAg
ICAgIGxvd2VyZWQuZmluZCgiPCFlbnRpdHkiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJu
ICIiOwoKICBzdGQ6OnZlY3RvcjxYbWxGcmFtZT4gc3RhY2s7CiAgc2l6ZV90IHRva2VuX2RlcHRo
ID0gMCwgdXNlcm5hbWVfZGVwdGggPSAwLCBwb3MgPSAwOwogIHN0ZDo6c3RyaW5nIHRva2VuX3Vy
aSwgY2hhcnMsIHJlc3VsdDsKICBib29sIHVzZXJuYW1lX2JhZCA9IGZhbHNlOwogIHdoaWxlIChw
b3MgPCBib2R5LnNpemUoKSkgewogICAgc2l6ZV90IGx0ID0gYm9keS5maW5kKCc8JywgcG9zKTsK
ICAgIGlmIChsdCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICBpZiAodXNlcm5hbWVfZGVw
dGggJiYgIXVzZXJuYW1lX2JhZCAmJiAheG1sX3VuZXNjYXBlKGJvZHkuc3Vic3RyKHBvcyksICZj
aGFycykpIHVzZXJuYW1lX2JhZCA9IHRydWU7CiAgICAgIGJyZWFrOwogICAgfQogICAgaWYgKHVz
ZXJuYW1lX2RlcHRoICYmICF1c2VybmFtZV9iYWQgJiYgbHQgPiBwb3MgJiYKICAgICAgICAheG1s
X3VuZXNjYXBlKGJvZHkuc3Vic3RyKHBvcywgbHQgLSBwb3MpLCAmY2hhcnMpKSB1c2VybmFtZV9i
YWQgPSB0cnVlOwogICAgaWYgKGNoYXJzLnNpemUoKSA+IE1BWF9XU1NFX1VTRVJOQU1FICogNCAr
IDIpIHsgY2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gdHJ1ZTsgfQoKICAgIGlmIChib2R5
LmNvbXBhcmUobHQsIDQsICI8IS0tIikgPT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5m
aW5kKCItLT4iLCBsdCArIDQpOyBpZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsK
ICAgICAgcG9zID0gZW5kICsgMzsgY29udGludWU7CiAgICB9CiAgICBpZiAoYm9keS5jb21wYXJl
KGx0LCA5LCAiPCFbQ0RBVEFbIikgPT0gMCkgewogICAgICBzaXplX3QgZW5kID0gYm9keS5maW5k
KCJdXT4iLCBsdCArIDkpOyBpZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAg
ICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2VybmFtZV9iYWQpIGNoYXJzLmFwcGVuZChib2R5
LCBsdCArIDksIGVuZCAtIGx0IC0gOSk7CiAgICAgIHBvcyA9IGVuZCArIDM7IGNvbnRpbnVlOwog
ICAgfQogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgMiwgIjw/IikgPT0gMCkgewogICAgICBzaXpl
X3QgZW5kID0gYm9keS5maW5kKCI/PiIsIGx0ICsgMik7IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6
Om5wb3MpIGJyZWFrOwogICAgICBwb3MgPSBlbmQgKyAyOyBjb250aW51ZTsKICAgIH0KICAgIGlm
IChib2R5LmNvbXBhcmUobHQsIDIsICI8ISIpID09IDApIHJldHVybiAiIjsKCiAgICBib29sIGNs
b3NpbmcgPSAobHQgKyAxIDwgYm9keS5zaXplKCkgJiYgYm9keVtsdCArIDFdID09ICcvJyk7CiAg
ICBzaXplX3QgcCA9IGx0ICsgKGNsb3NpbmcgPyAyIDogMSk7CiAgICBzdGQ6OnN0cmluZyBxbmFt
ZTsKICAgIGlmICghcGFyc2VfeG1sX25hbWUoYm9keSwgYm9keS5zaXplKCksICZwLCAmcW5hbWUp
KSBicmVhazsKICAgIGlmIChjbG9zaW5nKSB7CiAgICAgIHdoaWxlIChwIDwgYm9keS5zaXplKCkg
JiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBpZiAocCA+PSBi
b2R5LnNpemUoKSB8fCBib2R5W3BdICE9ICc+JykgYnJlYWs7CiAgICAgIGlmIChzdGFjay5lbXB0
eSgpKSBicmVhazsKICAgICAgc3RkOjpzdHJpbmcgcHJlZml4LCBsb2NhbDsgc3BsaXRfcW5hbWUo
cW5hbWUsICZwcmVmaXgsICZsb2NhbCk7CiAgICAgIFhtbEZyYW1lICZ0b3AgPSBzdGFjay5iYWNr
KCk7CiAgICAgIGlmICh0b3AucW5hbWUgIT0gcW5hbWUgfHwgdG9wLmxvY2FsICE9IGxvY2FsKSBi
cmVhazsKICAgICAgc2l6ZV90IGRlcHRoID0gc3RhY2suc2l6ZSgpOwogICAgICBpZiAodXNlcm5h
bWVfZGVwdGggPT0gZGVwdGgpIHsKICAgICAgICBzdGQ6OnN0cmluZyB1c2VybmFtZSA9IHRyaW0o
Y2hhcnMpOwogICAgICAgIGlmICghdXNlcm5hbWVfYmFkICYmIHZhbGlkX3V0ZjhfdXNlcm5hbWUo
dXNlcm5hbWUpICYmIHJlc3VsdC5lbXB0eSgpKSByZXN1bHQgPSB1c2VybmFtZTsKICAgICAgICB1
c2VybmFtZV9kZXB0aCA9IDA7IGNoYXJzLmNsZWFyKCk7IHVzZXJuYW1lX2JhZCA9IGZhbHNlOwog
ICAgICB9CiAgICAgIGlmICh0b2tlbl9kZXB0aCA9PSBkZXB0aCkgeyB0b2tlbl9kZXB0aCA9IDA7
IHRva2VuX3VyaS5jbGVhcigpOyB9CiAgICAgIHN0YWNrLnBvcF9iYWNrKCk7IHBvcyA9IHAgKyAx
OwogICAgICBpZiAoIXJlc3VsdC5lbXB0eSgpKSByZXR1cm4gcmVzdWx0OwogICAgICBjb250aW51
ZTsKICAgIH0KCiAgICBYbWxGcmFtZSBmcmFtZTsKICAgIGlmIChzdGFjay5zaXplKCkgPj0gNjQp
IHJldHVybiAiIjsKICAgIGlmICghc3RhY2suZW1wdHkoKSkgZnJhbWUubnMgPSBzdGFjay5iYWNr
KCkubnM7CiAgICBib29sIHNlbGZfY2xvc2luZyA9IGZhbHNlLCBjb21wbGV0ZSA9IGZhbHNlOwog
ICAgc2l6ZV90IGF0dHJfY291bnQgPSAwOwogICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSkgewog
ICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9k
eVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0gYm9keS5zaXplKCkpIGJyZWFrOwogICAgICBpZiAo
Ym9keVtwXSA9PSAnPicpIHsgKytwOyBjb21wbGV0ZSA9IHRydWU7IGJyZWFrOyB9CiAgICAgIGlm
IChib2R5W3BdID09ICcvJyAmJiBwICsgMSA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbcCArIDFdID09
ICc+JykgewogICAgICAgIHAgKz0gMjsgc2VsZl9jbG9zaW5nID0gdHJ1ZTsgY29tcGxldGUgPSB0
cnVlOyBicmVhazsKICAgICAgfQogICAgICBzdGQ6OnN0cmluZyBhbmFtZTsKICAgICAgaWYgKCFw
YXJzZV94bWxfbmFtZShib2R5LCBib2R5LnNpemUoKSwgJnAsICZhbmFtZSkpIGJyZWFrOwogICAg
ICBpZiAoKythdHRyX2NvdW50ID4gMTI4KSByZXR1cm4gIiI7CiAgICAgIHdoaWxlIChwIDwgYm9k
eS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBp
ZiAocCA+PSBib2R5LnNpemUoKSB8fCBib2R5W3ArK10gIT0gJz0nKSBicmVhazsKICAgICAgd2hp
bGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSAr
K3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8IChib2R5W3BdICE9ICdcJycgJiYgYm9k
eVtwXSAhPSAnIicpKSBicmVhazsKICAgICAgY2hhciBxdW90ZSA9IGJvZHlbcCsrXTsgc2l6ZV90
IHZhbHVlX3N0YXJ0ID0gcDsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBib2R5W3Bd
ICE9IHF1b3RlKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpKSBicmVhazsKICAgICAg
c3RkOjpzdHJpbmcgdmFsdWU7CiAgICAgIGlmICgheG1sX3VuZXNjYXBlKGJvZHkuc3Vic3RyKHZh
bHVlX3N0YXJ0LCBwIC0gdmFsdWVfc3RhcnQpLCAmdmFsdWUpKSByZXR1cm4gIiI7CiAgICAgICsr
cDsKICAgICAgaWYgKGFuYW1lID09ICJ4bWxucyIpIGZyYW1lLm5zWyIiXSA9IHZhbHVlOwogICAg
ICBlbHNlIGlmIChhbmFtZS5jb21wYXJlKDAsIDYsICJ4bWxuczoiKSA9PSAwKSBmcmFtZS5uc1th
bmFtZS5zdWJzdHIoNildID0gdmFsdWU7CiAgICAgIGlmIChmcmFtZS5ucy5zaXplKCkgPiA2NCkg
cmV0dXJuICIiOwogICAgfQogICAgaWYgKCFjb21wbGV0ZSkgYnJlYWs7CiAgICBzdGQ6OnN0cmlu
ZyBwcmVmaXgsIGxvY2FsOyBzcGxpdF9xbmFtZShxbmFtZSwgJnByZWZpeCwgJmxvY2FsKTsKICAg
IHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz46OmNvbnN0X2l0ZXJhdG9yIG5zID0g
ZnJhbWUubnMuZmluZChwcmVmaXgpOwogICAgZnJhbWUudXJpID0gKG5zID09IGZyYW1lLm5zLmVu
ZCgpKSA/ICIiIDogbnMtPnNlY29uZDsKICAgIGZyYW1lLnFuYW1lID0gcW5hbWU7CiAgICBmcmFt
ZS5sb2NhbCA9IGxvY2FsOwogICAgc3RhY2sucHVzaF9iYWNrKGZyYW1lKTsKICAgIHNpemVfdCBk
ZXB0aCA9IHN0YWNrLnNpemUoKTsKICAgIGlmICghdG9rZW5fZGVwdGggJiYgbG9jYWwgPT0gIlVz
ZXJuYW1lVG9rZW4iICYmIGlzX3dzc2VfbmFtZXNwYWNlKGZyYW1lLnVyaSkpIHsKICAgICAgdG9r
ZW5fZGVwdGggPSBkZXB0aDsgdG9rZW5fdXJpID0gZnJhbWUudXJpOwogICAgfSBlbHNlIGlmICh0
b2tlbl9kZXB0aCAmJiBkZXB0aCA9PSB0b2tlbl9kZXB0aCArIDEgJiYKICAgICAgICAgICAgICAg
bG9jYWwgPT0gIlVzZXJuYW1lIiAmJiBmcmFtZS51cmkgPT0gdG9rZW5fdXJpKSB7CiAgICAgIHVz
ZXJuYW1lX2RlcHRoID0gZGVwdGg7IGNoYXJzLmNsZWFyKCk7IHVzZXJuYW1lX2JhZCA9IGZhbHNl
OwogICAgfQogICAgaWYgKHNlbGZfY2xvc2luZykgewogICAgICBpZiAodXNlcm5hbWVfZGVwdGgg
PT0gZGVwdGgpIHVzZXJuYW1lX2RlcHRoID0gMDsKICAgICAgaWYgKHRva2VuX2RlcHRoID09IGRl
cHRoKSB7IHRva2VuX2RlcHRoID0gMDsgdG9rZW5fdXJpLmNsZWFyKCk7IH0KICAgICAgc3RhY2su
cG9wX2JhY2soKTsKICAgIH0KICAgIHBvcyA9IHA7CiAgfQogIHJldHVybiByZXN1bHQ7Cn0KCnN0
YXRpYyBib29sIHBhcnNlX3Jlc3BvbnNlKGNvbnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4sIGlu
dCAqc3RhdHVzLCBzaXplX3QgKmNsZW4sCiAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvb2wg
Kmhhc19jbGVuLCBib29sICppc19jaHVua2VkLCBib29sICppc19jbG9zZSkgewogICpoYXNfY2xl
biA9IGZhbHNlOwogICpjbGVuID0gMDsKICAqaXNfY2h1bmtlZCA9IGZhbHNlOwogICppc19jbG9z
ZSA9IGZhbHNlOwogIGNvbnN0IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAq
cCA9IGRhdGE7CiAgY29uc3QgY2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xu
JywgZW5kIC0gcCk7CiAgaWYgKCFlb2wpIHJldHVybiBmYWxzZTsKICBpZiAoc3RybmNtcChwLCAi
SFRUUC8iLCA1KSAhPSAwKSByZXR1cm4gZmFsc2U7CiAgYm9vbCBpc19odHRwXzEwID0gKGVvbCAt
IHAgPj0gOCAmJiBzdHJuY21wKHAsICJIVFRQLzEuMCIsIDgpID09IDApOwogIGJvb2wgY29ubl9j
bG9zZSA9IGZhbHNlOwogIGJvb2wgY29ubl9rZWVwX2FsaXZlID0gZmFsc2U7CgogIGNvbnN0IGNo
YXIgKnNwMSA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICcgJywgZW9sIC0gcCk7CiAgaWYgKCFz
cDEpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzY19zdGFydCA9IHNwMSArIDE7CiAgd2hp
bGUgKHNjX3N0YXJ0IDwgZW9sICYmICpzY19zdGFydCA9PSAnICcpICsrc2Nfc3RhcnQ7CiAgKnN0
YXR1cyA9IGF0b2koc2Nfc3RhcnQpOwogIGlmICgqc3RhdHVzIDwgMTAwIHx8ICpzdGF0dXMgPiA1
OTkpIHJldHVybiBmYWxzZTsKICBwID0gZW9sICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAg
aWYgKCpwID09ICdccicgfHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5l
X2VuZCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFs
aW5lX2VuZCkgbGluZV9lbmQgPSBlbmQ7CiAgICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBj
aGFyICopbWVtY2hyKHAsICc6JywgbGluZV9lbmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAg
ICBzaXplX3QgaGxlbiA9IGNvbG9uIC0gcDsKICAgICAgY29uc3QgY2hhciAqdiA9IGNvbG9uICsg
MTsKICAgICAgd2hpbGUgKHYgPCBsaW5lX2VuZCAmJiAoKnYgPT0gJyAnIHx8ICp2ID09ICdcdCcp
KSArK3Y7CiAgICAgIGNvbnN0IGNoYXIgKnZlID0gbGluZV9lbmQ7CiAgICAgIHdoaWxlICh2ZSA+
IHYgJiYgKHZlWy0xXSA9PSAnXHInIHx8IHZlWy0xXSA9PSAnXG4nIHx8IHZlWy0xXSA9PSAnICcg
fHwgdmVbLTFdID09ICdcdCcpKSAtLXZlOwogICAgICBzaXplX3QgdmxlbiA9IChzaXplX3QpKHZl
IC0gdik7CgogICAgICBpZiAoaGxlbiA9PSAxNCAmJiAhc3RybmNhc2VjbXAocCwgImNvbnRlbnQt
bGVuZ3RoIiwgMTQpKSB7CiAgICAgICAgc2l6ZV90IG4gPSAwOwogICAgICAgIGlmIChwYXJzZV9k
ZWNpbWFsX3NpemUodiwgdmxlbiwgJm4pKSB7CiAgICAgICAgICBpZiAoKmhhc19jbGVuICYmICpj
bGVuICE9IG4pIHsKICAgICAgICAgICAgcmV0dXJuIGZhbHNlOwogICAgICAgICAgfQogICAgICAg
ICAgKmNsZW4gPSBuOwogICAgICAgICAgKmhhc19jbGVuID0gdHJ1ZTsKICAgICAgICB9IGVsc2Ug
ewogICAgICAgICAgcmV0dXJuIGZhbHNlOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChobGVu
ID09IDE3ICYmICFzdHJuY2FzZWNtcChwLCAidHJhbnNmZXItZW5jb2RpbmciLCAxNykpIHsKICAg
ICAgICBzdGQ6OnN0cmluZyB0ZSh2LCB2bGVuKTsKICAgICAgICBpZiAobG93ZXIodGUpLmZpbmQo
ImNodW5rZWQiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgKmlzX2NodW5rZWQg
PSB0cnVlOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChobGVuID09IDEwICYmICFzdHJuY2Fz
ZWNtcChwLCAiY29ubmVjdGlvbiIsIDEwKSkgewogICAgICAgIHN0ZDo6c3RyaW5nIGNvbm4odiwg
dmxlbik7CiAgICAgICAgaWYgKGxvd2VyKGNvbm4pLmZpbmQoImNsb3NlIikgIT0gc3RkOjpzdHJp
bmc6Om5wb3MpIHsKICAgICAgICAgIGNvbm5fY2xvc2UgPSB0cnVlOwogICAgICAgIH0gZWxzZSBp
ZiAobG93ZXIoY29ubikuZmluZCgia2VlcC1hbGl2ZSIpICE9IHN0ZDo6c3RyaW5nOjpucG9zKSB7
CiAgICAgICAgICBjb25uX2tlZXBfYWxpdmUgPSB0cnVlOwogICAgICAgIH0KICAgICAgfQogICAg
fQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CiAgaWYgKCpoYXNfY2xlbiAmJiAqaXNfY2h1bmtl
ZCkgcmV0dXJuIGZhbHNlOwogIGlmIChpc19odHRwXzEwICYmICFjb25uX2tlZXBfYWxpdmUpIHsK
ICAgICppc19jbG9zZSA9IHRydWU7CiAgfSBlbHNlIGlmIChjb25uX2Nsb3NlKSB7CiAgICAqaXNf
Y2xvc2UgPSB0cnVlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIGdf
ZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX3NoaXBfbm9kZTsKc3RhdGljIHVuc2lnbmVk
IGdfc2hpcF9yYXRlX2ticHMgPSBERUZBVUxUX1NISVBfUkFURV9LQlBTOwpzdGF0aWMgdW5zaWdu
ZWQgZ19zdGF0c19pbnRlcnZhbF9zZWMgPSAzMDsKc3RhdGljIHNpemVfdCBnX3dzc2VfYm9keV9i
eXRlcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19jYXB0dXJlX3BhY2tldHMgPSAw
LCBnX2NhcHR1cmVfYnl0ZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfa2VybmVs
X2Ryb3BzID0gMCwgZ19pbnZhbGlkX2ZyYW1lcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxv
bmcgZ19ldmVudHNfZW1pdHRlZCA9IDAsIGdfZXZlbnRzX2luID0gMDsKc3RhdGljIHVuc2lnbmVk
IGxvbmcgbG9uZyBnX2V2ZW50c19wdXNoZWQgPSAwLCBnX2V2ZW50c19kcm9wcGVkID0gMDsKc3Rh
dGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2Ryb3BfcXVldWUgPSAwLCBnX2Ryb3BfaHViID0gMCwg
Z19kcm9wX292ZXJzaXplZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19iYXRjaGVz
X3B1c2hlZCA9IDAsIGdfYmF0Y2hlc19mYWlsZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBs
b25nIGdfYnl0ZXNfcHVzaGVkID0gMCwgZ19zdGF0c19kcm9wcGVkID0gMDsKc3RhdGljIHVuc2ln
bmVkIGxvbmcgbG9uZyBnX291dHB1dF9waXBlX2Ryb3BzID0gMCwgZ19wcmV2X291dHB1dF9waXBl
X2Ryb3BzID0gMDsKc3RhdGljIHNpemVfdCBnX3F1ZXVlX2hpZ2hfd2F0ZXIgPSAwOwpzdGF0aWMg
dW5zaWduZWQgZ19jb25zZWN1dGl2ZV9mYWlsdXJlcyA9IDAsIGdfbGFzdF9wdXNoX3N0YXR1cyA9
IDA7CnN0YXRpYyB0aW1lX3QgZ19sYXN0X3N1Y2Nlc3NfYXQgPSAwOwpzdGF0aWMgZG91YmxlIGdf
c3RhdHNfbGFzdF9hdCA9IDAuMCwgZ19zdGF0c19sYXN0X2NwdSA9IDAuMDsKc3RhdGljIHVuc2ln
bmVkIGxvbmcgbG9uZyBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzID0gMCwgZ19wcmV2X2NhcHR1cmVf
Ynl0ZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9ldmVudHNfZW1pdHRl
ZCA9IDAsIGdfcHJldl9ldmVudHNfaW4gPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdf
cHJldl9ldmVudHNfcHVzaGVkID0gMCwgZ19wcmV2X2V2ZW50c19kcm9wcGVkID0gMDsKc3RhdGlj
IHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfYmF0Y2hlc19wdXNoZWQgPSAwLCBnX3ByZXZfYmF0
Y2hlc19mYWlsZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJldl9ieXRlc19w
dXNoZWQgPSAwLCBnX3ByZXZfZHJvcF9xdWV1ZSA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxv
bmcgZ19wcmV2X2Ryb3BfaHViID0gMCwgZ19wcmV2X2Ryb3Bfb3ZlcnNpemVkID0gMDsKc3RhdGlj
IHVuc2lnbmVkIGxvbmcgbG9uZyBnX3N0YXRzX3NlcXVlbmNlID0gMDsKc3RhdGljIHN0ZDo6c3Ry
aW5nIGdfaW5zdGFuY2VfaWQ7CgpzdGF0aWMgcHRocmVhZF90IGdfc2hpcF93b3JrZXJfdGlkOwpz
dGF0aWMgcHRocmVhZF9tdXRleF90IGdfc2hpcF9xdWV1ZV9tdXRleCA9IFBUSFJFQURfTVVURVhf
SU5JVElBTElaRVI7CnN0YXRpYyBwdGhyZWFkX2NvbmRfdCBnX3NoaXBfcXVldWVfY29uZCA9IFBU
SFJFQURfQ09ORF9JTklUSUFMSVpFUjsKc3RhdGljIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBn
X3NoaXBfYnVmOwpzdGF0aWMgYm9vbCBnX3NoaXBfd29ya2VyX2FjdGl2ZSA9IGZhbHNlOwpzdGF0
aWMgYm9vbCBnX3Byb2R1Y2VyX2ZpbmlzaGVkID0gZmFsc2U7CnN0YXRpYyBzdGQ6OnN0cmluZyBn
X3BlbmRpbmdfc3RhdHNfYm9keTsKCnN0YXRpYyBzdGQ6OnN0cmluZyBzaGVsbHEoY29uc3Qgc3Rk
OjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZvciAoc2l6ZV90IGkgPSAw
OyBpIDwgcy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcnKSBvICs9ICInXFwnJyI7IGVs
c2UgbyArPSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIG51
bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgbjsgcmV0
dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIHVsbF9zdHJpbmcodW5zaWduZWQgbG9u
ZyBsb25nIG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7
IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGRvdWJsZV9zdHJpbmcoZG91YmxlIG4pIHsgc3RkOjpvc3Ry
aW5nc3RyZWFtIG87IG8uc2V0ZihzdGQ6Omlvczo6Zml4ZWQpOyBvLnByZWNpc2lvbig0KTsgbyA8
PCBuOyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgc3RkOjpzdHJpbmcganNvbl9hcnJheShjb25z
dCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmEpIHsKICBzdGQ6OnN0cmluZyBvID0gIlsiOyBm
b3IgKHNpemVfdCBpID0gMDsgaSA8IGEuc2l6ZSgpOyArK2kpIHsgaWYgKGkpIG8gKz0gIiwiOyBv
ICs9IGFbaV07IH0gcmV0dXJuIG8gKyAiXSI7Cn0Kc3RhdGljIGRvdWJsZSB3YWxsX3NlY29uZHMo
KSB7CiAgc3RydWN0IHRpbWV2YWwgdHY7CiAgZ2V0dGltZW9mZGF5KCZ0diwgTlVMTCk7CiAgcmV0
dXJuIChkb3VibGUpdHYudHZfc2VjICsgKGRvdWJsZSl0di50dl91c2VjIC8gMTAwMDAwMC4wOwp9
CnN0YXRpYyB2b2lkIHBhY2VfdXBsb2FkKHNpemVfdCBieXRlcywgZG91YmxlICpuZXh0X3Nsb3Qp
IHsKICBpZiAoIWdfc2hpcF9yYXRlX2ticHMpIHJldHVybjsKICBkb3VibGUgYnl0ZXNfcGVyX3Nl
YyA9IChkb3VibGUpZ19zaGlwX3JhdGVfa2JwcyAqIDEwMDAuMCAvIDguMDsKICBkb3VibGUgbm93
ID0gd2FsbF9zZWNvbmRzKCk7CiAgaWYgKCpuZXh0X3Nsb3QgPCBub3cpICpuZXh0X3Nsb3QgPSBu
b3c7CiAgZG91YmxlIHNsb3QgPSAqbmV4dF9zbG90OwogICpuZXh0X3Nsb3QgKz0gKGRvdWJsZSli
eXRlcyAvIGJ5dGVzX3Blcl9zZWM7CiAgd2hpbGUgKHNsb3QgPiAobm93ID0gd2FsbF9zZWNvbmRz
KCkpKSB7CiAgICBkb3VibGUgcmVtYWluaW5nID0gc2xvdCAtIG5vdzsKICAgIHVzZWNvbmRzX3Qg
ZGVsYXkgPSAodXNlY29uZHNfdCkocmVtYWluaW5nID4gMC41ID8gNTAwMDAwIDogcmVtYWluaW5n
ICogMTAwMDAwMC4wKTsKICAgIGlmIChkZWxheSkgdXNsZWVwKGRlbGF5KTsKICB9Cn0Kc3RhdGlj
IHNpemVfdCBib3VuZGVkX2JhdGNoX2NvdW50KGNvbnN0IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5n
PiAmYnVmLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qgc3RkOjpzdHJp
bmcgJm5vZGUpIHsKICBzaXplX3Qgc2l6ZSA9IHN0ZDo6c3RyaW5nKCJ7XCJub2RlXCI6Iikuc2l6
ZSgpICsganNvbnEobm9kZSkuc2l6ZSgpICsKICAgICAgICAgICAgICAgIHN0ZDo6c3RyaW5nKCIs
XCJldmVudHNcIjpbXX0iKS5zaXplKCk7CiAgc2l6ZV90IG4gPSAwLCBsaW1pdCA9IGJ1Zi5zaXpl
KCkgPCBNQVhfQkFUQ0ggPyBidWYuc2l6ZSgpIDogTUFYX0JBVENIOwogIHdoaWxlIChuIDwgbGlt
aXQpIHsKICAgIHNpemVfdCBleHRyYSA9IGJ1ZltuXS5zaXplKCkgKyAobiA/IDEgOiAwKTsKICAg
IGlmIChleHRyYSA+IE1BWF9QT1NUX0JZVEVTIC0gc2l6ZSkgYnJlYWs7CiAgICBzaXplICs9IGV4
dHJhOwogICAgKytuOwogIH0KICByZXR1cm4gbjsKfQoKc3RhdGljIGJvb2wgcG9zdF9ib2R5KGNv
bnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJnBhdGgsCiAgICAg
ICAgICAgICAgICAgICAgICAgY29uc3Qgc3RkOjpzdHJpbmcgJmJvZHksIHVuc2lnbmVkIHRpbWVv
dXRfc2VjLCBkb3VibGUgKm5leHRfc2xvdCkgewogIGlmIChuZXh0X3Nsb3QpIHBhY2VfdXBsb2Fk
KGJvZHkuc2l6ZSgpLCBuZXh0X3Nsb3QpOwogIHN0ZDo6c3RyaW5nIGNtZCA9ICJjdXJsIC1zU2Yg
LS1tYXgtdGltZSAiICsgbnVtYmVyX3N0cmluZyh0aW1lb3V0X3NlYykgKyAiIC0tbGltaXQtcmF0
ZSAiICsKICAgIG51bWJlcl9zdHJpbmcoKHNpemVfdClnX3NoaXBfcmF0ZV9rYnBzICogMTAwMFUg
LyA4VSkgKwogICAgIiAtbyAvZGV2L251bGwgLUggJ0NvbnRlbnQtVHlwZTogYXBwbGljYXRpb24v
anNvbicgLS1kYXRhLWJpbmFyeSBALSAiICsgc2hlbGxxKGVuZHBvaW50ICsgcGF0aCk7CiAgRklM
RSAqZnAgPSBwb3BlbihjbWQuY19zdHIoKSwgInciKTsgaWYgKCFmcCkgcmV0dXJuIGZhbHNlOwog
IGZ3cml0ZShib2R5LmRhdGEoKSwgMSwgYm9keS5zaXplKCksIGZwKTsKICBpbnQgcmMgPSBwY2xv
c2UoZnApOwogIHJldHVybiBXSUZFWElURUQocmMpICYmIFdFWElUU1RBVFVTKHJjKSA9PSAwOwp9
CgpzdGF0aWMgdm9pZCAqc2hpcF93b3JrZXJfdGhyZWFkKHZvaWQgKikgewogIGRvdWJsZSBuZXh0
X3Nsb3QgPSB3YWxsX3NlY29uZHMoKTsKICBkb3VibGUgbmV4dF9zdGF0c19zbG90ID0gd2FsbF9z
ZWNvbmRzKCk7CiAgZG91YmxlIHNodXRkb3duX2RlYWRsaW5lID0gMC4wOwogIHdoaWxlICh0cnVl
KSB7CiAgICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gYmF0Y2g7CiAgICBzdGQ6OnN0cmluZyBz
dGF0c19ib2R5OwogICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwog
ICAgd2hpbGUgKGdfcnVubmluZyAmJiAhZ19wcm9kdWNlcl9maW5pc2hlZCAmJiBnX3NoaXBfYnVm
LmVtcHR5KCkgJiYgZ19wZW5kaW5nX3N0YXRzX2JvZHkuZW1wdHkoKSkgewogICAgICBzdHJ1Y3Qg
dGltZXNwZWMgdHM7CiAgICAgIGNsb2NrX2dldHRpbWUoQ0xPQ0tfUkVBTFRJTUUsICZ0cyk7CiAg
ICAgIHRzLnR2X3NlYyArPSAxOwogICAgICBwdGhyZWFkX2NvbmRfdGltZWR3YWl0KCZnX3NoaXBf
cXVldWVfY29uZCwgJmdfc2hpcF9xdWV1ZV9tdXRleCwgJnRzKTsKICAgIH0KICAgIGlmICghZ19y
dW5uaW5nICYmIHNodXRkb3duX2RlYWRsaW5lID09IDAuMCkgewogICAgICBzaHV0ZG93bl9kZWFk
bGluZSA9IHdhbGxfc2Vjb25kcygpICsgMTAuMDsKICAgIH0KICAgIGlmIChnX3Byb2R1Y2VyX2Zp
bmlzaGVkICYmIGdfc2hpcF9idWYuZW1wdHkoKSAmJiBnX3BlbmRpbmdfc3RhdHNfYm9keS5lbXB0
eSgpKSB7CiAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwog
ICAgICBicmVhazsKICAgIH0KICAgIGlmIChzaHV0ZG93bl9kZWFkbGluZSA+IDAuMCAmJiB3YWxs
X3NlY29uZHMoKSA+IHNodXRkb3duX2RlYWRsaW5lKSB7CiAgICAgIGdfZXZlbnRzX2Ryb3BwZWQg
Kz0gZ19zaGlwX2J1Zi5zaXplKCk7CiAgICAgIGdfZHJvcF9odWIgKz0gZ19zaGlwX2J1Zi5zaXpl
KCk7CiAgICAgIGdfc2hpcF9idWYuY2xlYXIoKTsKICAgICAgZ19wZW5kaW5nX3N0YXRzX2JvZHku
Y2xlYXIoKTsKICAgICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CiAgICAgIGJyZWFrOwogICAgfQogICAgaWYgKCFnX3BlbmRpbmdfc3RhdHNfYm9keS5lbXB0eSgp
KSB7CiAgICAgIHN0YXRzX2JvZHkuc3dhcChnX3BlbmRpbmdfc3RhdHNfYm9keSk7CiAgICB9CiAg
ICBpZiAoIWdfc2hpcF9idWYuZW1wdHkoKSkgewogICAgICBzaXplX3QgbiA9IGJvdW5kZWRfYmF0
Y2hfY291bnQoZ19zaGlwX2J1ZiwgZ19zaGlwX25vZGUpOwogICAgICBpZiAoIW4pIHsKICAgICAg
ICBnX3NoaXBfYnVmLmVyYXNlKGdfc2hpcF9idWYuYmVnaW4oKSk7CiAgICAgICAgKytnX2V2ZW50
c19kcm9wcGVkOwogICAgICAgICsrZ19kcm9wX292ZXJzaXplZDsKICAgICAgfSBlbHNlIHsKICAg
ICAgICBiYXRjaC5hc3NpZ24oZ19zaGlwX2J1Zi5iZWdpbigpLCBnX3NoaXBfYnVmLmJlZ2luKCkg
KyBuKTsKICAgICAgICBnX3NoaXBfYnVmLmVyYXNlKGdfc2hpcF9idWYuYmVnaW4oKSwgZ19zaGlw
X2J1Zi5iZWdpbigpICsgbik7CiAgICAgIH0KICAgIH0KICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2Nr
KCZnX3NoaXBfcXVldWVfbXV0ZXgpOwoKICAgIGlmICghc3RhdHNfYm9keS5lbXB0eSgpKSB7CiAg
ICAgIGlmICghcG9zdF9ib2R5KGdfZW5kcG9pbnQsICIvYXBpL2FnZW50L3N0YXRzIiwgc3RhdHNf
Ym9keSwgMiwgJm5leHRfc3RhdHNfc2xvdCkpIHsKICAgICAgICBwdGhyZWFkX211dGV4X2xvY2so
Jmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgICAgKytnX3N0YXRzX2Ryb3BwZWQ7CiAgICAgICAg
cHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgIH0KICAgIH0K
CiAgICBpZiAoIWJhdGNoLmVtcHR5KCkpIHsKICAgICAgc3RkOjpzdHJpbmcgYm9keSA9ICJ7XCJu
b2RlXCI6IiArIGpzb25xKGdfc2hpcF9ub2RlKSArICIsXCJldmVudHNcIjoiICsganNvbl9hcnJh
eShiYXRjaCkgKyAifSI7CiAgICAgIGlmIChwb3N0X2JvZHkoZ19lbmRwb2ludCwgIi9hcGkvaW5n
ZXN0IiwgYm9keSwgMTAsICZuZXh0X3Nsb3QpKSB7CiAgICAgICAgcHRocmVhZF9tdXRleF9sb2Nr
KCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICAgIGdfZXZlbnRzX3B1c2hlZCArPSBiYXRjaC5z
aXplKCk7CiAgICAgICAgKytnX2JhdGNoZXNfcHVzaGVkOwogICAgICAgIGdfYnl0ZXNfcHVzaGVk
ICs9IGJvZHkuc2l6ZSgpOwogICAgICAgIGdfY29uc2VjdXRpdmVfZmFpbHVyZXMgPSAwOwogICAg
ICAgIGdfbGFzdF9wdXNoX3N0YXR1cyA9IDIwMDsKICAgICAgICBnX2xhc3Rfc3VjY2Vzc19hdCA9
IHRpbWUoTlVMTCk7CiAgICAgICAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9t
dXRleCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgcHRocmVhZF9tdXRleF9sb2NrKCZnX3NoaXBf
cXVldWVfbXV0ZXgpOwogICAgICAgIGdfZXZlbnRzX2Ryb3BwZWQgKz0gYmF0Y2guc2l6ZSgpOwog
ICAgICAgIGdfZHJvcF9odWIgKz0gYmF0Y2guc2l6ZSgpOwogICAgICAgICsrZ19iYXRjaGVzX2Zh
aWxlZDsKICAgICAgICArK2dfY29uc2VjdXRpdmVfZmFpbHVyZXM7CiAgICAgICAgZ19sYXN0X3B1
c2hfc3RhdHVzID0gMDsKICAgICAgICBpZiAoc2h1dGRvd25fZGVhZGxpbmUgPiAwLjAgJiYgZ19j
b25zZWN1dGl2ZV9mYWlsdXJlcyA+PSAzKSB7CiAgICAgICAgICBnX2V2ZW50c19kcm9wcGVkICs9
IGdfc2hpcF9idWYuc2l6ZSgpOwogICAgICAgICAgZ19kcm9wX2h1YiArPSBnX3NoaXBfYnVmLnNp
emUoKTsKICAgICAgICAgIGdfc2hpcF9idWYuY2xlYXIoKTsKICAgICAgICAgIGdfcGVuZGluZ19z
dGF0c19ib2R5LmNsZWFyKCk7CiAgICAgICAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlw
X3F1ZXVlX211dGV4KTsKICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgICAgICBwdGhyZWFk
X211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgfQogICAgfQogIH0KICBy
ZXR1cm4gTlVMTDsKfQoKc3RhdGljIHVuc2lnbmVkIGNvdW50X29wZW5fZmRzKCkgewogIERJUiAq
ZGlyID0gb3BlbmRpcigiL3Byb2Mvc2VsZi9mZCIpOwogIGlmICghZGlyKSByZXR1cm4gMDsKICB1
bnNpZ25lZCBjb3VudCA9IDA7CiAgc3RydWN0IGRpcmVudCAqZW50cnk7CiAgd2hpbGUgKChlbnRy
eSA9IHJlYWRkaXIoZGlyKSkgIT0gTlVMTCkgewogICAgaWYgKHN0cmNtcChlbnRyeS0+ZF9uYW1l
LCAiLiIpICYmIHN0cmNtcChlbnRyeS0+ZF9uYW1lLCAiLi4iKSkgKytjb3VudDsKICB9CiAgY2xv
c2VkaXIoZGlyKTsKICByZXR1cm4gY291bnQ7Cn0KCnN0YXRpYyB2b2lkIHByb2Nfc3RhdHVzKHNp
emVfdCAqcnNzLCBzaXplX3QgKnZpcnQsIHVuc2lnbmVkICp0aHJlYWRzLAogICAgICAgICAgICAg
ICAgICAgICAgICB1bnNpZ25lZCAqY3B1X2NvcmUpIHsKICAqcnNzID0gMDsgKnZpcnQgPSAwOyAq
dGhyZWFkcyA9IDE7ICpjcHVfY29yZSA9IDA7CiAgc3RkOjppZnN0cmVhbSBpbigiL3Byb2Mvc2Vs
Zi9zdGF0dXMiKTsKICBzdGQ6OnN0cmluZyBsaW5lOwogIHdoaWxlIChzdGQ6OmdldGxpbmUoaW4s
IGxpbmUpKSB7CiAgICB1bnNpZ25lZCBsb25nIHZhbHVlID0gMDsKICAgIGlmIChzc2NhbmYobGlu
ZS5jX3N0cigpLCAiVm1SU1M6ICVsdSBrQiIsICZ2YWx1ZSkgPT0gMSkgKnJzcyA9IChzaXplX3Qp
dmFsdWUgKiAxMDI0VTsKICAgIGVsc2UgaWYgKHNzY2FuZihsaW5lLmNfc3RyKCksICJWbVNpemU6
ICVsdSBrQiIsICZ2YWx1ZSkgPT0gMSkgKnZpcnQgPSAoc2l6ZV90KXZhbHVlICogMTAyNFU7CiAg
ICBlbHNlIGlmIChzc2NhbmYobGluZS5jX3N0cigpLCAiVGhyZWFkczogJWx1IiwgJnZhbHVlKSA9
PSAxKSAqdGhyZWFkcyA9ICh1bnNpZ25lZCl2YWx1ZTsKICAgIGVsc2UgaWYgKHNzY2FuZihsaW5l
LmNfc3RyKCksICJDcHVzX2FsbG93ZWRfbGlzdDogJWx1IiwgJnZhbHVlKSA9PSAxKSAqY3B1X2Nv
cmUgPSAodW5zaWduZWQpdmFsdWU7CiAgfQp9CgpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIHVw
ZGF0ZV9rZXJuZWxfZHJvcHMoaW50IGZkKSB7CiAgaWYgKGZkIDwgMCkgcmV0dXJuIDA7CiAgc3Ry
dWN0IHRwYWNrZXRfc3RhdHMgcGFja2V0X3N0YXRzOwogIHNvY2tsZW5fdCBwYWNrZXRfc3RhdHNf
bGVuID0gc2l6ZW9mKHBhY2tldF9zdGF0cyk7CiAgbWVtc2V0KCZwYWNrZXRfc3RhdHMsIDAsIHNp
emVvZihwYWNrZXRfc3RhdHMpKTsKICBpZiAoZ2V0c29ja29wdChmZCwgU09MX1BBQ0tFVCwgUEFD
S0VUX1NUQVRJU1RJQ1MsCiAgICAgICAgICAgICAgICAgJnBhY2tldF9zdGF0cywgJnBhY2tldF9z
dGF0c19sZW4pICE9IDApIHJldHVybiAwOwogIGdfa2VybmVsX2Ryb3BzICs9IHBhY2tldF9zdGF0
cy50cF9kcm9wczsKICByZXR1cm4gcGFja2V0X3N0YXRzLnRwX2Ryb3BzOwp9CgpzdGF0aWMgc3Rk
OjpzdHJpbmcgYWdlbnRfc3RhdHNfYm9keShpbnQgZmQsIHNpemVfdCBmbG93c19hY3RpdmUsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCBwZW5kaW5nX3JlcXVlc3Rz
LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3Qgd3NzZV9ib2R5X2Zs
b3dzKSB7CiAgZG91YmxlIG5vdyA9IHdhbGxfc2Vjb25kcygpOwogIGRvdWJsZSBlbGFwc2VkID0g
bm93IC0gZ19zdGF0c19sYXN0X2F0OwogIGlmIChlbGFwc2VkIDwgMC4wMDEpIGVsYXBzZWQgPSAw
LjAwMTsKICB1bnNpZ25lZCBsb25nIGxvbmcga2VybmVsX2Ryb3BfZGVsdGEgPSB1cGRhdGVfa2Vy
bmVsX2Ryb3BzKGZkKTsKICB1bnNpZ25lZCBsb25nIGxvbmcgcGFja2V0X2RlbHRhID0gZ19jYXB0
dXJlX3BhY2tldHMgLSBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzOwogIHVuc2lnbmVkIGxvbmcgbG9u
ZyBwYWNrZXRfYnl0ZXNfZGVsdGEgPSBnX2NhcHR1cmVfYnl0ZXMgLSBnX3ByZXZfY2FwdHVyZV9i
eXRlczsKICB1bnNpZ25lZCBsb25nIGxvbmcgZW1pdHRlZF9kZWx0YSA9IGdfZXZlbnRzX2VtaXR0
ZWQgLSBnX3ByZXZfZXZlbnRzX2VtaXR0ZWQ7CgogIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlw
X3F1ZXVlX211dGV4KTsKICB1bnNpZ25lZCBsb25nIGxvbmcgaW5fZGVsdGEgPSBnX2V2ZW50c19p
biAtIGdfcHJldl9ldmVudHNfaW47CiAgdW5zaWduZWQgbG9uZyBsb25nIHB1c2hlZF9kZWx0YSA9
IGdfZXZlbnRzX3B1c2hlZCAtIGdfcHJldl9ldmVudHNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcg
bG9uZyBkcm9wcGVkX2RlbHRhID0gZ19ldmVudHNfZHJvcHBlZCAtIGdfcHJldl9ldmVudHNfZHJv
cHBlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgYmF0Y2hlc19wdXNoZWRfZGVsdGEgPSBnX2JhdGNo
ZXNfcHVzaGVkIC0gZ19wcmV2X2JhdGNoZXNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBi
YXRjaGVzX2ZhaWxlZF9kZWx0YSA9IGdfYmF0Y2hlc19mYWlsZWQgLSBnX3ByZXZfYmF0Y2hlc19m
YWlsZWQ7CiAgdW5zaWduZWQgbG9uZyBsb25nIGJ5dGVzX2RlbHRhID0gZ19ieXRlc19wdXNoZWQg
LSBnX3ByZXZfYnl0ZXNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBxdWV1ZV9kZWx0YSA9
IGdfZHJvcF9xdWV1ZSAtIGdfcHJldl9kcm9wX3F1ZXVlOwogIHVuc2lnbmVkIGxvbmcgbG9uZyBo
dWJfZGVsdGEgPSBnX2Ryb3BfaHViIC0gZ19wcmV2X2Ryb3BfaHViOwogIHVuc2lnbmVkIGxvbmcg
bG9uZyBvdmVyc2l6ZWRfZGVsdGEgPSBnX2Ryb3Bfb3ZlcnNpemVkIC0gZ19wcmV2X2Ryb3Bfb3Zl
cnNpemVkOwogIHNpemVfdCBzaGlwX2J1Zl9zaXplID0gZ19zaGlwX2J1Zi5zaXplKCk7CiAgc2l6
ZV90IHF1ZXVlX2hpZ2ggPSBnX3F1ZXVlX2hpZ2hfd2F0ZXI7CiAgdW5zaWduZWQgbGFzdF9zdGF0
dXMgPSBnX2xhc3RfcHVzaF9zdGF0dXM7CiAgdGltZV90IGxhc3Rfc3VjYyA9IGdfbGFzdF9zdWNj
ZXNzX2F0OwogIHVuc2lnbmVkIGNvbnNlY19mYWlscyA9IGdfY29uc2VjdXRpdmVfZmFpbHVyZXM7
CiAgdW5zaWduZWQgbG9uZyBsb25nIHN0YXRzX2Ryb3AgPSBnX3N0YXRzX2Ryb3BwZWQ7CiAgcHRo
cmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CgogIHVuc2lnbmVkIGxvbmcg
bG9uZyBwaXBlX2Ryb3BfZGVsdGEgPSBnX291dHB1dF9waXBlX2Ryb3BzIC0gZ19wcmV2X291dHB1
dF9waXBlX2Ryb3BzOwogIHN0cnVjdCBydXNhZ2UgdXNhZ2U7CiAgbWVtc2V0KCZ1c2FnZSwgMCwg
c2l6ZW9mKHVzYWdlKSk7CiAgZ2V0cnVzYWdlKFJVU0FHRV9TRUxGLCAmdXNhZ2UpOwogIGRvdWJs
ZSB1c2VyX2NwdSA9IHVzYWdlLnJ1X3V0aW1lLnR2X3NlYyArIHVzYWdlLnJ1X3V0aW1lLnR2X3Vz
ZWMgLyAxMDAwMDAwLjA7CiAgZG91YmxlIHN5c19jcHUgPSB1c2FnZS5ydV9zdGltZS50dl9zZWMg
KyB1c2FnZS5ydV9zdGltZS50dl91c2VjIC8gMTAwMDAwMC4wOwogIGRvdWJsZSBjcHVfdG90YWwg
PSB1c2VyX2NwdSArIHN5c19jcHU7CiAgZG91YmxlIGNwdV9wY3QgPSAxMDAuMCAqIChjcHVfdG90
YWwgLSBnX3N0YXRzX2xhc3RfY3B1KSAvIGVsYXBzZWQ7CiAgaWYgKGNwdV9wY3QgPCAwKSBjcHVf
cGN0ID0gMDsKICBzaXplX3QgcnNzID0gMCwgdmlydCA9IDA7CiAgdW5zaWduZWQgdGhyZWFkcyA9
IDEsIGNwdV9jb3JlID0gMDsKICBwcm9jX3N0YXR1cygmcnNzLCAmdmlydCwgJnRocmVhZHMsICZj
cHVfY29yZSk7CiAgc3RkOjpzdHJpbmcgcmVhc29uczsKICBpZiAoa2VybmVsX2Ryb3BfZGVsdGEp
IHJlYXNvbnMgKz0gIlwia2VybmVsX2Ryb3BcIiI7CiAgaWYgKGRyb3BwZWRfZGVsdGEpIHsgaWYg
KCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcInNoaXBfZHJv
cFwiIjsgfQogIGlmIChodWJfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMg
Kz0gIiwiOyByZWFzb25zICs9ICJcImh1Yl91bnJlYWNoYWJsZVwiIjsgfQogIGlmIChxdWV1ZV9k
ZWx0YSB8fCBwaXBlX2Ryb3BfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMg
Kz0gIiwiOyByZWFzb25zICs9ICJcInF1ZXVlX3ByZXNzdXJlXCIiOyB9CiAgc3RkOjpvc3RyaW5n
c3RyZWFtIG91dDsKICBvdXQgPDwgIntcInNjaGVtYV92ZXJzaW9uXCI6MSxcInR5cGVcIjpcImFn
ZW50X3N0YXRzXCIsXCJub2RlXCI6IiA8PCBqc29ucShnX3NoaXBfbm9kZSkKICAgICAgPDwgIixc
Imluc3RhbmNlX2lkXCI6IiA8PCBqc29ucShnX2luc3RhbmNlX2lkKSA8PCAiLFwic2VxdWVuY2Vc
IjoiIDw8ICsrZ19zdGF0c19zZXF1ZW5jZQogICAgICA8PCAiLFwib2JzZXJ2ZWRfYXRcIjoiIDw8
ICh1bnNpZ25lZCBsb25nKW5vdyA8PCAiLFwid2luZG93X3NlY29uZHNcIjoiIDw8IGRvdWJsZV9z
dHJpbmcoZWxhcHNlZCkKICAgICAgPDwgIixcIm1vZGVcIjpcImNwcFwiLFwic3RhdHVzXCI6IiA8
PCAocmVhc29ucy5lbXB0eSgpID8gIlwib2tcIiIgOiAiXCJkZWdyYWRlZFwiIikKICAgICAgPDwg
IixcInJlYXNvbnNcIjpbIiA8PCByZWFzb25zIDw8ICJdLFwiY2FwdHVyZVwiOnsiCiAgICAgIDw8
ICJcInBhY2tldHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19jYXB0dXJlX3BhY2tldHMpIDw8
ICIsXCJwYWNrZXRzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHBhY2tldF9kZWx0YSkKICAgICAg
PDwgIixcInBhY2tldF9ieXRlc190b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2NhcHR1cmVfYnl0
ZXMpIDw8ICIsXCJwYWNrZXRfYnl0ZXNfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcocGFja2V0X2J5
dGVzX2RlbHRhKQogICAgICA8PCAiLFwia2VybmVsX2Ryb3BzX3RvdGFsXCI6IiA8PCB1bGxfc3Ry
aW5nKGdfa2VybmVsX2Ryb3BzKSA8PCAiLFwia2VybmVsX2Ryb3BzX2RlbHRhXCI6IiA8PCB1bGxf
c3RyaW5nKGtlcm5lbF9kcm9wX2RlbHRhKQogICAgICA8PCAiLFwia2VybmVsX2Ryb3BfcGVyY2Vu
dFwiOiIgPDwgZG91YmxlX3N0cmluZygxMDAuMCAqIGtlcm5lbF9kcm9wX2RlbHRhIC8gKHBhY2tl
dF9kZWx0YSA/IHBhY2tldF9kZWx0YSA6IDEpKQogICAgICA8PCAiLFwiaW52YWxpZF9mcmFtZXNf
dG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19pbnZhbGlkX2ZyYW1lcykKICAgICAgPDwgIixcImV2
ZW50c19lbWl0dGVkX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfZXZlbnRzX2VtaXR0ZWQpIDw8
ICIsXCJldmVudHNfZW1pdHRlZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhlbWl0dGVkX2RlbHRh
KQogICAgICA8PCAiLFwiZmxvd3NfYWN0aXZlXCI6IiA8PCBmbG93c19hY3RpdmUgPDwgIixcInBl
bmRpbmdfcmVxdWVzdHNcIjoiIDw8IHBlbmRpbmdfcmVxdWVzdHMKICAgICAgPDwgIixcIndzc2Vf
Ym9keV9mbG93c19hY3RpdmVcIjoiIDw8IHdzc2VfYm9keV9mbG93cwogICAgICA8PCAiLFwid3Nz
ZV9ib2R5X2J5dGVzXCI6IiA8PCBnX3dzc2VfYm9keV9ieXRlcwogICAgICA8PCAiLFwib3V0cHV0
X3BpcGVfZHJvcHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19vdXRwdXRfcGlwZV9kcm9wcykK
ICAgICAgPDwgIixcIm91dHB1dF9waXBlX2Ryb3BzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHBp
cGVfZHJvcF9kZWx0YSkgPDwgIn0sXCJzaGlwcGluZ1wiOnsiCiAgICAgIDw8ICJcImV2ZW50c19p
bl90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19pbikgPDwgIixcImV2ZW50c19pbl9k
ZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhpbl9kZWx0YSkKICAgICAgPDwgIixcImV2ZW50c19wdXNo
ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVudHNfcHVzaGVkKSA8PCAiLFwiZXZlbnRz
X3B1c2hlZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwdXNoZWRfZGVsdGEpCiAgICAgIDw8ICIs
XCJldmVudHNfZHJvcHBlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19kcm9wcGVk
KSA8PCAiLFwiZXZlbnRzX2Ryb3BwZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoZHJvcHBlZF9k
ZWx0YSkKICAgICAgPDwgIixcImRyb3BfY2F1c2VzXCI6e1wicXVldWVfZnVsbF90b3RhbFwiOiIg
PDwgdWxsX3N0cmluZyhnX2Ryb3BfcXVldWUpIDw8ICIsXCJxdWV1ZV9mdWxsX2RlbHRhXCI6IiA8
PCB1bGxfc3RyaW5nKHF1ZXVlX2RlbHRhKQogICAgICA8PCAiLFwiaHViX2ZhaWx1cmVfdG90YWxc
IjoiIDw8IHVsbF9zdHJpbmcoZ19kcm9wX2h1YikgPDwgIixcImh1Yl9mYWlsdXJlX2RlbHRhXCI6
IiA8PCB1bGxfc3RyaW5nKGh1Yl9kZWx0YSkKICAgICAgPDwgIixcIm92ZXJzaXplZF90b3RhbFwi
OiIgPDwgdWxsX3N0cmluZyhnX2Ryb3Bfb3ZlcnNpemVkKSA8PCAiLFwib3ZlcnNpemVkX2RlbHRh
XCI6IiA8PCB1bGxfc3RyaW5nKG92ZXJzaXplZF9kZWx0YSkgPDwgIn0iCiAgICAgIDw8ICIsXCJi
YXRjaGVzX3B1c2hlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2JhdGNoZXNfcHVzaGVkKSA8
PCAiLFwiYmF0Y2hlc19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYmF0Y2hlc19wdXNo
ZWRfZGVsdGEpCiAgICAgIDw8ICIsXCJiYXRjaGVzX2ZhaWxlZF90b3RhbFwiOiIgPDwgdWxsX3N0
cmluZyhnX2JhdGNoZXNfZmFpbGVkKSA8PCAiLFwiYmF0Y2hlc19mYWlsZWRfZGVsdGFcIjoiIDw8
IHVsbF9zdHJpbmcoYmF0Y2hlc19mYWlsZWRfZGVsdGEpCiAgICAgIDw8ICIsXCJieXRlc19wdXNo
ZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ieXRlc19wdXNoZWQpIDw8ICIsXCJieXRlc19w
dXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYnl0ZXNfZGVsdGEpCiAgICAgIDw8ICIsXCJw
dXNoX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3RyaW5nKHB1c2hlZF9kZWx0YSAv
IGVsYXBzZWQpCiAgICAgIDw8ICIsXCJwdXNoX2ticHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcoOC4w
ICogYnl0ZXNfZGVsdGEgLyAoMTAwMC4wICogZWxhcHNlZCkpCiAgICAgIDw8ICIsXCJkcm9wX2V2
ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3RyaW5nKGRyb3BwZWRfZGVsdGEgLyBlbGFw
c2VkKQogICAgICA8PCAiLFwiZHJvcF9wZXJjZW50XCI6IiA8PCBkb3VibGVfc3RyaW5nKDEwMC4w
ICogZHJvcHBlZF9kZWx0YSAvIChpbl9kZWx0YSA/IGluX2RlbHRhIDogMSkpCiAgICAgIDw8ICIs
XCJxdWV1ZV9kZXB0aF9ldmVudHNcIjoiIDw8IHNoaXBfYnVmX3NpemUgPDwgIixcInF1ZXVlX2Nh
cGFjaXR5X2V2ZW50c1wiOiIgPDwgTUFYX1FVRVVFCiAgICAgIDw8ICIsXCJxdWV1ZV9oaWdoX3dh
dGVyX2V2ZW50c1wiOiIgPDwgcXVldWVfaGlnaCA8PCAiLFwibGFzdF9wdXNoX2h0dHBfc3RhdHVz
XCI6IiA8PCBsYXN0X3N0YXR1cwogICAgICA8PCAiLFwibGFzdF9zdWNjZXNzX2F0XCI6IiA8PCAo
dW5zaWduZWQgbG9uZylsYXN0X3N1Y2MgPDwgIixcImNvbnNlY3V0aXZlX2ZhaWx1cmVzXCI6IiA8
PCBjb25zZWNfZmFpbHMKICAgICAgPDwgIixcInN0YXRzX3NhbXBsZXNfZHJvcHBlZF90b3RhbFwi
OiIgPDwgdWxsX3N0cmluZyhzdGF0c19kcm9wKSA8PCAifSxcInJlc291cmNlc1wiOnsiCiAgICAg
IDw8ICJcImNwdV91c2VyX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcodXNlcl9jcHUpIDw8
ICIsXCJjcHVfc3lzdGVtX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcoc3lzX2NwdSkKICAg
ICAgPDwgIixcImNwdV9wZXJjZW50X29uZV9jb3JlXCI6IiA8PCBkb3VibGVfc3RyaW5nKGNwdV9w
Y3QpIDw8ICIsXCJyc3NfYnl0ZXNcIjoiIDw8IHJzcwogICAgICA8PCAiLFwidmlydHVhbF9ieXRl
c1wiOiIgPDwgdmlydCA8PCAiLFwib3Blbl9mZHNcIjoiIDw8IGNvdW50X29wZW5fZmRzKCkgPDwg
IixcInRocmVhZHNcIjoiIDw8IHRocmVhZHMKICAgICAgPDwgIn0sXCJsaW1pdHNcIjp7XCJjcHVf
Y29yZVwiOiIgPDwgY3B1X2NvcmUgPDwgIixcImFkZHJlc3Nfc3BhY2VfYnl0ZXNcIjoyNjg0MzU0
NTYiCiAgICAgIDw8ICIsXCJzaGlwX3JhdGVfa2Jwc1wiOiIgPDwgZ19zaGlwX3JhdGVfa2JwcyA8
PCAiLFwiaHR0cF9ib2R5X21heF9ieXRlc1wiOiIgPDwgTUFYX1BPU1RfQllURVMKICAgICAgPDwg
IixcInNoaXBfdGhyZWFkc19tYXhcIjoxLFwid3NzZV9ib2R5X2J5dGVzXCI6IiA8PCBnX3dzc2Vf
Ym9keV9ieXRlcyA8PCAifX0iOwogIGdfcHJldl9jYXB0dXJlX3BhY2tldHMgPSBnX2NhcHR1cmVf
cGFja2V0czsgZ19wcmV2X2NhcHR1cmVfYnl0ZXMgPSBnX2NhcHR1cmVfYnl0ZXM7CiAgZ19wcmV2
X2V2ZW50c19lbWl0dGVkID0gZ19ldmVudHNfZW1pdHRlZDsKICBwdGhyZWFkX211dGV4X2xvY2so
Jmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgZ19wcmV2X2V2ZW50c19pbiA9IGdfZXZlbnRzX2luOwog
IGdfcHJldl9ldmVudHNfcHVzaGVkID0gZ19ldmVudHNfcHVzaGVkOyBnX3ByZXZfZXZlbnRzX2Ry
b3BwZWQgPSBnX2V2ZW50c19kcm9wcGVkOwogIGdfcHJldl9iYXRjaGVzX3B1c2hlZCA9IGdfYmF0
Y2hlc19wdXNoZWQ7IGdfcHJldl9iYXRjaGVzX2ZhaWxlZCA9IGdfYmF0Y2hlc19mYWlsZWQ7CiAg
Z19wcmV2X2J5dGVzX3B1c2hlZCA9IGdfYnl0ZXNfcHVzaGVkOyBnX3ByZXZfZHJvcF9xdWV1ZSA9
IGdfZHJvcF9xdWV1ZTsKICBnX3ByZXZfZHJvcF9odWIgPSBnX2Ryb3BfaHViOyBnX3ByZXZfZHJv
cF9vdmVyc2l6ZWQgPSBnX2Ryb3Bfb3ZlcnNpemVkOwogIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZn
X3NoaXBfcXVldWVfbXV0ZXgpOwogIGdfcHJldl9vdXRwdXRfcGlwZV9kcm9wcyA9IGdfb3V0cHV0
X3BpcGVfZHJvcHM7CiAgZ19zdGF0c19sYXN0X2NwdSA9IGNwdV90b3RhbDsgZ19zdGF0c19sYXN0
X2F0ID0gbm93OwogIHJldHVybiBvdXQuc3RyKCk7Cn0KCnN0YXRpYyB2b2lkIHNlbmRfYWdlbnRf
c3RhdHMoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0aXZlLAogICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIHNpemVfdCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIHNpemVfdCB3c3NlX2JvZHlfZmxvd3MpIHsKICBzdGQ6OnN0cmluZyBib2R5ID0gYWdlbnRf
c3RhdHNfYm9keShmZCwgZmxvd3NfYWN0aXZlLCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdzc2VfYm9keV9mbG93cyk7CiAgaWYgKGJvZHku
c2l6ZSgpID4gTUFYX1NUQVRTX0JZVEVTKSB7CiAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hp
cF9xdWV1ZV9tdXRleCk7CiAgICArK2dfc3RhdHNfZHJvcHBlZDsKICAgIHB0aHJlYWRfbXV0ZXhf
dW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgcmV0dXJuOwogIH0KICBwdGhyZWFkX211
dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgZ19wZW5kaW5nX3N0YXRzX2JvZHkgPSBi
b2R5OwogIHB0aHJlYWRfY29uZF9zaWduYWwoJmdfc2hpcF9xdWV1ZV9jb25kKTsKICBwdGhyZWFk
X211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKfQoKc3RhdGljIGJvb2wgd3JpdGVf
bm9uYmxvY2tpbmdfbGluZShjb25zdCBzdGQ6OnN0cmluZyAmbGluZSkgewogIGlmIChsaW5lLnNp
emUoKSArIDEgPiBQSVBFX0JVRikgewogICAgKytnX291dHB1dF9waXBlX2Ryb3BzOwogICAgcmV0
dXJuIHRydWU7CiAgfQogIHN0ZDo6c3RyaW5nIGZyYW1lZCA9IGxpbmUgKyAiXG4iOwogIHNzaXpl
X3Qgd3JpdHRlbjsKICBkbyB7IHdyaXR0ZW4gPSB3cml0ZShTVERPVVRfRklMRU5PLCBmcmFtZWQu
ZGF0YSgpLCBmcmFtZWQuc2l6ZSgpKTsgfQogIHdoaWxlICh3cml0dGVuIDwgMCAmJiBlcnJubyA9
PSBFSU5UUiAmJiBnX3J1bm5pbmcpOwogIGlmICh3cml0dGVuID09IChzc2l6ZV90KWZyYW1lZC5z
aXplKCkpIHJldHVybiB0cnVlOwogIGlmICh3cml0dGVuIDwgMCAmJiAoZXJybm8gPT0gRUFHQUlO
IHx8IGVycm5vID09IEVXT1VMREJMT0NLKSkgewogICAgKytnX291dHB1dF9waXBlX2Ryb3BzOwog
ICAgcmV0dXJuIHRydWU7CiAgfQogIGlmICh3cml0dGVuIDwgMCAmJiBlcnJubyA9PSBFUElQRSkg
ewogICAgbG9nbXNnKCJzaGlwcGVyIHBpcGUgY2xvc2VkOyBzdG9wcGluZyBjYXB0dXJlIGZvciBz
dXBlcnZpc2VkIHJlc3RhcnQiKTsKICB9IGVsc2UgewogICAgbG9nbXNnKCJzaGlwcGVyIHBpcGUg
d3JpdGUgZmFpbGVkOyBzdG9wcGluZyBjYXB0dXJlIGZvciBzdXBlcnZpc2VkIHJlc3RhcnQiKTsK
ICB9CiAgZ19ydW5uaW5nID0gMDsKICByZXR1cm4gZmFsc2U7Cn0KCnN0YXRpYyB2b2lkIGVtaXRf
Y2FwdHVyZV9zdGF0c19pbnRlcm5hbChpbnQgZmQsIHNpemVfdCBmbG93c19hY3RpdmUsCiAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3QgcGVuZGluZ19yZXF1ZXN0
cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCB3c3NlX2Jv
ZHlfZmxvd3MpIHsKICBzdGQ6OnN0cmluZyBmdWxsID0gYWdlbnRfc3RhdHNfYm9keShmZCwgZmxv
d3NfYWN0aXZlLCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIHdzc2VfYm9keV9mbG93cyk7CiAgY29uc3Qgc3RkOjpzdHJpbmcgbWFya2VyID0g
IlwiY2FwdHVyZVwiOiI7CiAgc2l6ZV90IHN0YXJ0ID0gZnVsbC5maW5kKG1hcmtlcik7CiAgc2l6
ZV90IGVuZCA9IGZ1bGwuZmluZCgiLFwic2hpcHBpbmdcIjoiLCBzdGFydCk7CiAgaWYgKHN0YXJ0
ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAg
KytnX291dHB1dF9waXBlX2Ryb3BzOwogICAgcmV0dXJuOwogIH0KICBzdGFydCArPSBtYXJrZXIu
c2l6ZSgpOwogIHdyaXRlX25vbmJsb2NraW5nX2xpbmUoIntcIl9udF9pbnRlcm5hbFwiOlwiY2Fw
dHVyZV9zdGF0c192MVwiLFwiY2FwdHVyZVwiOiIgKwogICAgICAgICAgICAgICAgICAgICAgICAg
ZnVsbC5zdWJzdHIoc3RhcnQsIGVuZCAtIHN0YXJ0KSArICJ9Iik7Cn0KCnN0YXRpYyB2b2lkIGVt
aXRfZXZlbnQoY29uc3QgRXZlbnQgJmUpIHsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gc3M7CiAgc3Mg
PDwgIntcInRzXCI6IiA8PCBlLnRzIDw8ICIsXCJob3N0XCI6IiA8PCBqc29ucShlLmhvc3QpIDw8
ICIsXCJzcmNcIjpcInBjYXBcIixcInNlcnZpY2VcIjoiIDw8IGpzb25xKGUuc2VydmljZSkKICAg
ICA8PCAiLFwibWV0aG9kXCI6IiA8PCBqc29ucShlLm1ldGhvZCkgPDwgIixcInBhdGhcIjoiIDw8
IGpzb25xKGUucGF0aCkgPDwgIixcInVzZXJcIjoiIDw8IGpzb25xKGUudXNlcikKICAgICA8PCAi
LFwic2NoZW1lXCI6IiA8PCBqc29ucShlLnNjaGVtZSkKICAgICA8PCAiLFwiYmFzaWNfdXNlclwi
OiIgPDwgKGUuYmFzaWNfdXNlci5lbXB0eSgpID8gIm51bGwiIDoganNvbnEoZS5iYXNpY191c2Vy
KSkKICAgICA8PCAiLFwid3NzZV91c2VyXCI6IiA8PCAoZS53c3NlX3VzZXIuZW1wdHkoKSA/ICJu
dWxsIiA6IGpzb25xKGUud3NzZV91c2VyKSkKICAgICA8PCAiLFwic291cmNlX3Byb2JlXCI6XCJw
Y2FwLWh0dHAtY3BwXCIsXCJob3N0X2hkclwiOiIgPDwganNvbnEoZS5ob3N0X2hkcikKICAgICA8
PCAiLFwidXNlcl9hZ2VudFwiOiIgPDwganNvbnEoZS51c2VyX2FnZW50KSA8PCAiLFwieF9mb3J3
YXJkZWRfZm9yXCI6IiA8PCBqc29ucShlLnhmZikKICAgICA8PCAiLFwiY2FsbGVyXCI6IiA8PCBq
c29ucShlLmNhbGxlcikgPDwgIixcImNhbGxlcl9wb3J0XCI6IiA8PCBlLmNhbGxlcl9wb3J0IDw8
ICIsXCJkc3RfaXBcIjoiIDw8IGpzb25xKGUuZHN0X2lwKQogICAgIDw8ICIsXCJkc3RfcG9ydFwi
OiIgPDwgZS5kc3RfcG9ydCA8PCAiLFwidHJhY2VwYXJlbnRcIjoiIDw8IGpzb25xKGUudHJhY2Vw
YXJlbnQpIDw8ICIsXCJ0cmFjZV9pZFwiOiIgPDwganNvbnEoZS50cmFjZV9pZCkKICAgICA8PCAi
LFwic2VydmljZV9pZFwiOm51bGwsXCJtb2R1bGVfaWRcIjpcInBjYXAtaHR0cC1jcHBcIixcInJl
cV9ieXRlc1wiOiIgPDwgZS5yZXFfYnl0ZXM7CiAgaWYgKGUuaGFzX3N0YXR1cykgc3MgPDwgIixc
InN0YXR1c1wiOiIgPDwgZS5zdGF0dXM7IGVsc2Ugc3MgPDwgIixcInN0YXR1c1wiOm51bGwiOwog
IGlmIChlLmhhc19kdXJhdGlvbikgc3MgPDwgIixcImR1cmF0aW9uX21zXCI6IiA8PCBlLmR1cmF0
aW9uX21zOyBlbHNlIHNzIDw8ICIsXCJkdXJhdGlvbl9tc1wiOm51bGwiOwogIGlmIChlLmhhc19y
ZXNwKSBzcyA8PCAiLFwicmVzcF9ieXRlc1wiOiIgPDwgZS5yZXNwX2J5dGVzOyBlbHNlIHNzIDw8
ICIsXCJyZXNwX2J5dGVzXCI6bnVsbCI7CiAgc3MgPDwgIn0iOwogICsrZ19ldmVudHNfZW1pdHRl
ZDsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgICsrZ19ldmVudHNfaW47CiAgICBw
dGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICBpZiAoZ19zaGlwX2J1
Zi5zaXplKCkgPj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9idWYuZXJhc2UoZ19zaGlwX2J1
Zi5iZWdpbigpKTsKICAgICAgKytnX2V2ZW50c19kcm9wcGVkOwogICAgICArK2dfZHJvcF9xdWV1
ZTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNrKHNzLnN0cigpKTsKICAgIGlmIChnX3No
aXBfYnVmLnNpemUoKSA+IGdfcXVldWVfaGlnaF93YXRlcikgZ19xdWV1ZV9oaWdoX3dhdGVyID0g
Z19zaGlwX2J1Zi5zaXplKCk7CiAgICBwdGhyZWFkX2NvbmRfc2lnbmFsKCZnX3NoaXBfcXVldWVf
Y29uZCk7CiAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICB9
IGVsc2UgewogICAgd3JpdGVfbm9uYmxvY2tpbmdfbGluZShzcy5zdHIoKSk7CiAgfQp9CgpzdGF0
aWMgdm9pZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1aW50MzJfdCBzX2lwLCB1bnNp
Z25lZCBzcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1aW50MzJfdCBkX2lwLCB1bnNp
Z25lZCBkcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXks
IHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgbG9uZyBsb25nIGZpcnN0X2J5dGVfbW9ub19tcyA9IDAsCiAgICAgICAgICAgICAgICAgICAg
ICAgICAgdWludDMyX3QgZ2VuID0gMCkgewogIFBhY2tldEtleSByazsKICByay5zX2lwID0gZF9p
cDsgcmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgcmsuZF9pcCA9IHNfaXA7IHJrLmRwb3J0
ID0gKHVpbnQxNl90KXNwb3J0OwoKICBsb25nIGxvbmcgbW9ub19ub3cgPSBub3dfbW9ub3Rvbmlj
X21zKCk7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbW9ubyA9IChmaXJzdF9ieXRlX21vbm9fbXMgPiAw
KSA/IGZpcnN0X2J5dGVfbW9ub19tcyA6IG1vbm9fbm93OwoKICB3aGlsZSAoZ190b3RhbF9wZW5k
aW5nX2NvdW50ID49IE1BWF9QRU5ESU5HX1RPVEFMICYmICFnX3BlbmRpbmdfZmlmby5lbXB0eSgp
KSB7CiAgICBQZW5kaW5nUXVldWVSZWYgcmVmID0gZ19wZW5kaW5nX2ZpZm8uZnJvbnQoKTsKICAg
IGdfcGVuZGluZ19maWZvLnBvcF9mcm9udCgpOwogICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9IHBlbmRpbmcuZmluZChyZWYua2V5KTsK
ICAgIGlmIChpdCAhPSBwZW5kaW5nLmVuZCgpKSB7CiAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBp
IDwgaXQtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICAgIGlmIChpdC0+c2Vjb25kW2ldLnJl
cV9pZCA9PSByZWYucmVxX2lkKSB7CiAgICAgICAgICBlbWl0X2V2ZW50KGl0LT5zZWNvbmRbaV0u
ZXYpOwogICAgICAgICAgaXQtPnNlY29uZC5lcmFzZShpdC0+c2Vjb25kLmJlZ2luKCkgKyBpKTsK
ICAgICAgICAgIGlmIChnX3RvdGFsX3BlbmRpbmdfY291bnQgPiAwKSAtLWdfdG90YWxfcGVuZGlu
Z19jb3VudDsKICAgICAgICAgIGlmIChpdC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2Uo
aXQpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQoKICBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiAmcXVldWUgPSBwZW5kaW5nW3JrXTsKICBpZiAocXVldWUuc2l6ZSgp
ID49IE1BWF9QRU5ESU5HX1BFUl9GTE9XKSB7CiAgICBlbWl0X2V2ZW50KHF1ZXVlWzBdLmV2KTsK
ICAgIHF1ZXVlLmVyYXNlKHF1ZXVlLmJlZ2luKCkpOwogICAgaWYgKGdfdG90YWxfcGVuZGluZ19j
b3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogIH0KICB1aW50NjRfdCByZXFfaWQg
PSArK2dfcmVxX2lkX3NlcTsKICBxdWV1ZS5wdXNoX2JhY2soUGVuZGluZyhyZXFfaWQsIGdlbiwg
ZSwgbm93X21zKCksIHN0YXJ0ZWRfbW9ubykpOwogICsrZ190b3RhbF9wZW5kaW5nX2NvdW50OwoK
ICBQZW5kaW5nUXVldWVSZWYgbmV3X3JlZjsKICBuZXdfcmVmLnJlcV9pZCA9IHJlcV9pZDsKICBu
ZXdfcmVmLmdlbmVyYXRpb24gPSBnZW47CiAgbmV3X3JlZi5rZXkgPSByazsKICBuZXdfcmVmLnN0
YXJ0ZWRfbW9ub19tcyA9IHN0YXJ0ZWRfbW9ubzsKICBnX3BlbmRpbmdfZmlmby5wdXNoX2JhY2so
bmV3X3JlZik7CgogIGlmIChnX3BlbmRpbmdfZmlmby5zaXplKCkgPiBNQVhfUEVORElOR19UT1RB
TCAqIDIpIHsKICAgIHN0ZDo6bGlzdDxQZW5kaW5nUXVldWVSZWY+OjppdGVyYXRvciBmaSA9IGdf
cGVuZGluZ19maWZvLmJlZ2luKCk7CiAgICB3aGlsZSAoZmkgIT0gZ19wZW5kaW5nX2ZpZm8uZW5k
KCkpIHsKICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+Ojpp
dGVyYXRvciBpdCA9IHBlbmRpbmcuZmluZChmaS0+a2V5KTsKICAgICAgYm9vbCBhbGl2ZSA9IGZh
bHNlOwogICAgICBpZiAoaXQgIT0gcGVuZGluZy5lbmQoKSkgewogICAgICAgIGZvciAoc2l6ZV90
IGogPSAwOyBqIDwgaXQtPnNlY29uZC5zaXplKCk7ICsraikgewogICAgICAgICAgaWYgKGl0LT5z
ZWNvbmRbal0ucmVxX2lkID09IGZpLT5yZXFfaWQpIHsKICAgICAgICAgICAgYWxpdmUgPSB0cnVl
OwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0KICAgICAg
aWYgKCFhbGl2ZSkgewogICAgICAgIGZpID0gZ19wZW5kaW5nX2ZpZm8uZXJhc2UoZmkpOwogICAg
ICB9IGVsc2UgewogICAgICAgICsrZmk7CiAgICAgIH0KICAgIH0KICB9Cn0KCnN0YXRpYyB2b2lk
IGZsdXNoX2luY29tcGxldGVfd3NzZShzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBmb3IgKHN0ZDo6bWFwPEZsb3dLZXksIEZs
b3c+OjppdGVyYXRvciBmID0gZmxvd3MuYmVnaW4oKTsgZiAhPSBmbG93cy5lbmQoKTsgKytmKSB7
CiAgICBpZiAoZi0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgcXVldWVfcmVxdWVzdChm
LT5zZWNvbmQud3NzZV9ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+Zmlyc3Quc3BvcnQsCiAgICAg
ICAgICAgICAgICAgICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3QuZHBvcnQsIHBlbmRpbmcsIGYt
PnNlY29uZC5maXJzdF9ieXRlX21vbm9fbXMsCiAgICAgICAgICAgICAgICAgICAgZi0+c2Vjb25k
LmdlbmVyYXRpb24pOwogICAgICBmLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSA9IGZhbHNlOwogICAg
fQogICAgZi0+c2Vjb25kLmNsZWFyX2J1ZmZlcnMoKTsKICB9CiAgZmxvd3MuY2xlYXIoKTsKICBn
X3RvdGFsX2Zsb3dfYnl0ZXMgPSAwOwp9CgpzdGF0aWMgdm9pZCBmbHVzaF9hbGxfcGVuZGluZyhz
dGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBm
b3IgKHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3Ig
cCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5nLmVuZCgpOyArK3ApIHsKICAgIGZvciAo
c2l6ZV90IGkgPSAwOyBpIDwgcC0+c2Vjb25kLnNpemUoKTsgKytpKSB7CiAgICAgIGVtaXRfZXZl
bnQocC0+c2Vjb25kW2ldLmV2KTsKICAgIH0KICB9CiAgcGVuZGluZy5jbGVhcigpOwogIGdfcGVu
ZGluZ19maWZvLmNsZWFyKCk7CiAgZ190b3RhbF9wZW5kaW5nX2NvdW50ID0gMDsKfQoKc3RhdGlj
IHZvaWQgc3dlZXAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLAogICAgICAgICAgICAg
ICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcs
CiAgICAgICAgICAgICAgICAgIHRpbWVfdCBub3csIHVuc2lnbmVkIHBlbmRpbmdfdHRsX3NlYywK
ICAgICAgICAgICAgICAgICAgbG9uZyBsb25nIG5vd19tb25vID0gMCkgewogIGZvciAoc3RkOjpt
YXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGYgPSBmbG93cy5iZWdpbigpOyBmICE9IGZsb3dz
LmVuZCgpOykgewogICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGZuID0gZjsg
KytmbjsKICAgIGlmICgodW5zaWduZWQpKG5vdyAtIGYtPnNlY29uZC50b3VjaGVkKSA+IEZMT1df
VFRMKSB7CiAgICAgIGlmIChmLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSkgewogICAgICAgIGVtaXRf
ZXZlbnQoZi0+c2Vjb25kLndzc2VfZXZlbnQpOwogICAgICAgIGYtPnNlY29uZC5hd2FpdGluZ193
c3NlID0gZmFsc2U7CiAgICAgIH0KICAgICAgZi0+c2Vjb25kLmNsZWFyX2J1ZmZlcnMoKTsKICAg
ICAgZmxvd3MuZXJhc2UoZik7CiAgICB9CiAgICBmID0gZm47CiAgfQoKICBpZiAobm93X21vbm8g
PD0gMCkgbm93X21vbm8gPSBub3dfbW9ub3RvbmljX21zKCk7CiAgbG9uZyBsb25nIHR0bF9tcyA9
IChsb25nIGxvbmcpcGVuZGluZ190dGxfc2VjICogMTAwMExMOwogIGZvciAoc3RkOjptYXA8UGFj
a2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5iZWdp
bigpOyBwICE9IHBlbmRpbmcuZW5kKCk7KSB7CiAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHBuID0gcDsgKytwbjsKICAgIHNpemVfdCBpID0g
MDsKICAgIHdoaWxlIChpIDwgcC0+c2Vjb25kLnNpemUoKSkgewogICAgICBQZW5kaW5nICZlbnRy
eSA9IHAtPnNlY29uZFtpXTsKICAgICAgaWYgKGVudHJ5LmlzX3RvbWJzdG9uZSkgewogICAgICAg
IGlmIChub3dfbW9ubyAtIGVudHJ5LnRvbWJzdG9uZV9tb25vX21zID4gMTAwMDBMTCkgewogICAg
ICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgICAgfSBl
bHNlIHsKICAgICAgICAgICsraTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAobm93X21vbm8g
LSBlbnRyeS5zdGFydGVkX21vbm9fbXMgPiB0dGxfbXMpIHsKICAgICAgICBlbWl0X2V2ZW50KGVu
dHJ5LmV2KTsKICAgICAgICBpZiAoZ190b3RhbF9wZW5kaW5nX2NvdW50ID4gMCkgLS1nX3RvdGFs
X3BlbmRpbmdfY291bnQ7CiAgICAgICAgZW50cnkuaXNfdG9tYnN0b25lID0gdHJ1ZTsKICAgICAg
ICBlbnRyeS50b21ic3RvbmVfbW9ub19tcyA9IG5vd19tb25vOwogICAgICAgICsraTsKICAgICAg
fSBlbHNlIHsKICAgICAgICArK2k7CiAgICAgIH0KICAgIH0KICAgIGlmIChwLT5zZWNvbmQuZW1w
dHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgIHAgPSBwbjsKICB9CgogIHdoaWxlICghZ19wZW5k
aW5nX2ZpZm8uZW1wdHkoKSAmJgogICAgICAgICAobm93X21vbm8gLSBnX3BlbmRpbmdfZmlmby5m
cm9udCgpLnN0YXJ0ZWRfbW9ub19tcyA+IHR0bF9tcyAqIDJMTCkpIHsKICAgIGdfcGVuZGluZ19m
aWZvLnBvcF9mcm9udCgpOwogIH0KfQoKc3RhdGljIGJvb2wgZHJhaW5fb29vX3NlZ21lbnRzKEZs
b3cgJmZsKSB7CiAgYm9vbCBkcmFpbmVkID0gdHJ1ZTsKICB3aGlsZSAoZHJhaW5lZCAmJiAhZmwu
b29vLmVtcHR5KCkpIHsKICAgIGRyYWluZWQgPSBmYWxzZTsKICAgIGZvciAoc2l6ZV90IGkgPSAw
OyBpIDwgZmwub29vLnNpemUoKTsgKytpKSB7CiAgICAgIGludDMyX3Qgb2RpZmYgPSBzZXFfZGlm
ZihmbC5vb29baV0uc2VxLCBmbC5uZXh0X3NlcSk7CiAgICAgIGlmIChvZGlmZiA9PSAwKSB7CiAg
ICAgICAgaWYgKCFmbC5idWZfYXBwZW5kKGZsLm9vb1tpXS5kYXRhLmRhdGEoKSwgZmwub29vW2ld
LmRhdGEuc2l6ZSgpKSkgcmV0dXJuIGZhbHNlOwogICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50
MzJfdClmbC5vb29baV0uZGF0YS5zaXplKCk7CiAgICAgICAgZmwub29vX2VyYXNlKGkpOwogICAg
ICAgIGRyYWluZWQgPSB0cnVlOyBicmVhazsKICAgICAgfSBlbHNlIGlmIChvZGlmZiA8IDApIHsK
ICAgICAgICBpbnQzMl90IG9fb3ZlcmxhcCA9IC1vZGlmZjsKICAgICAgICBpZiAoKHNpemVfdClv
X292ZXJsYXAgPCBmbC5vb29baV0uZGF0YS5zaXplKCkpIHsKICAgICAgICAgIHNpemVfdCBmbGVu
ID0gZmwub29vW2ldLmRhdGEuc2l6ZSgpIC0gb19vdmVybGFwOwogICAgICAgICAgaWYgKCFmbC5i
dWZfYXBwZW5kKGZsLm9vb1tpXS5kYXRhLmRhdGEoKSArIG9fb3ZlcmxhcCwgZmxlbikpIHJldHVy
biBmYWxzZTsKICAgICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClmbGVuOwogICAgICAg
IH0KICAgICAgICBmbC5vb29fZXJhc2UoaSk7CiAgICAgICAgZHJhaW5lZCA9IHRydWU7IGJyZWFr
OwogICAgICB9CiAgICB9CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgc2l6ZV90IGZpbmRf
aHR0cF9zdGFydChjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIGNvbnN0IGNoYXIgKm1bXSA9IHsg
IkdFVCAiLCAiUE9TVCAiLCAiUFVUICIsICJERUxFVEUgIiwgIlBBVENIICIsICJIRUFEICIsICJP
UFRJT05TICIgfTsKICBzaXplX3QgYmVzdCA9IHN0ZDo6c3RyaW5nOjpucG9zOwogIGZvciAoc2l6
ZV90IGkgPSAwOyBpIDwgNzsgKytpKSB7CiAgICBzaXplX3QgcG9zID0gcy5maW5kKG1baV0pOwog
ICAgaWYgKHBvcyAhPSBzdGQ6OnN0cmluZzo6bnBvcyAmJiAoYmVzdCA9PSBzdGQ6OnN0cmluZzo6
bnBvcyB8fCBwb3MgPCBiZXN0KSkgYmVzdCA9IHBvczsKICB9CiAgcmV0dXJuIGJlc3Q7Cn0KCnN0
YXRpYyBib29sIGlzX21ldGhvZF9vcl9wcmVmaXgoY29uc3QgY2hhciAqcCwgc2l6ZV90IGxlbikg
ewogIGlmICghbGVuKSByZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIs
ICJQT1NUICIsICJQVVQgIiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMg
IiB9OwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNzsgKytpKSB7CiAgICBzaXplX3QgbWxlbiA9
IHN0cmxlbihtW2ldKTsKICAgIHNpemVfdCBjaGVja19sZW4gPSBsZW4gPCBtbGVuID8gbGVuIDog
bWxlbjsKICAgIGlmIChtZW1jbXAocCwgbVtpXSwgY2hlY2tfbGVuKSA9PSAwKSByZXR1cm4gdHJ1
ZTsKICB9CiAgcmV0dXJuIGZhbHNlOwp9CgpzdGF0aWMgYm9vbCBnX21vbml0b3JlZF9wb3J0c1s2
NTUzNl07CgpzdGF0aWMgc2l6ZV90IGFjdGl2ZV93c3NlX2Zsb3dzKGNvbnN0IHN0ZDo6bWFwPEZs
b3dLZXksIEZsb3c+ICZmbG93cykgewogIHNpemVfdCBjb3VudCA9IDA7CiAgZm9yIChzdGQ6Om1h
cDxGbG93S2V5LCBGbG93Pjo6Y29uc3RfaXRlcmF0b3IgaXQgPSBmbG93cy5iZWdpbigpOyBpdCAh
PSBmbG93cy5lbmQoKTsgKytpdCkKICAgIGlmIChpdC0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpICsr
Y291bnQ7CiAgcmV0dXJuIGNvdW50Owp9CgpzdGF0aWMgdm9pZCBldmljdF9vbGRlc3RfZmxvd19p
Zl9uZWVkZWQoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZsb3dzLAogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQ
ZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgd2hpbGUgKCFmbG93cy5lbXB0eSgpICYmIChmbG93cy5z
aXplKCkgPj0gTUFYX0ZMT1dTIHx8IGdfdG90YWxfZmxvd19ieXRlcyA+PSBNQVhfVE9UQUxfQlVG
RkVSX0JZVEVTKSkgewogICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIG9sZGVz
dCA9IGZsb3dzLmJlZ2luKCk7CiAgICBmb3IgKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVy
YXRvciBpdCA9IGZsb3dzLmJlZ2luKCk7IGl0ICE9IGZsb3dzLmVuZCgpOyArK2l0KSB7CiAgICAg
IGlmIChpdC0+c2Vjb25kLnRvdWNoZWQgPCBvbGRlc3QtPnNlY29uZC50b3VjaGVkKSBvbGRlc3Qg
PSBpdDsKICAgIH0KICAgIGlmIChvbGRlc3QtPnNlY29uZC5hd2FpdGluZ193c3NlKSB7CiAgICAg
IHF1ZXVlX3JlcXVlc3Qob2xkZXN0LT5zZWNvbmQud3NzZV9ldmVudCwgb2xkZXN0LT5maXJzdC5z
X2lwLCBvbGRlc3QtPmZpcnN0LnNwb3J0LAogICAgICAgICAgICAgICAgICAgIG9sZGVzdC0+Zmly
c3QuZF9pcCwgb2xkZXN0LT5maXJzdC5kcG9ydCwgcGVuZGluZywgb2xkZXN0LT5zZWNvbmQuZmly
c3RfYnl0ZV9tb25vX21zLAogICAgICAgICAgICAgICAgICAgIG9sZGVzdC0+c2Vjb25kLmdlbmVy
YXRpb24pOwogICAgICBvbGRlc3QtPnNlY29uZC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICB9
CiAgICBvbGRlc3QtPnNlY29uZC5jbGVhcl9idWZmZXJzKCk7CiAgICBmbG93cy5lcmFzZShvbGRl
c3QpOwogIH0KfQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFy
ICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0
b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxG
bG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVu
ZGluZz4gPiAmcGVuZGluZywKICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lX3QgcGNhcF9u
b3cgPSAwLCBsb25nIGxvbmcgcGNhcF9tb25vX25vdyA9IDApIHsKICAodm9pZClwb3J0czsKICBp
ZiAobiA8IDM0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNo
b3J0IGV0ID0gbnRvaHMocmVhZF91MTYoYnVmICsgMTIpKTsKICBpZiAoZXQgPT0gRVRIX1BfODAy
MVEpIHsgaWYgKG4gPCAzOCkgcmV0dXJuIGZhbHNlOyBldCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiAr
IDE2KSk7IG9mZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkg
cmV0dXJuIGZhbHNlOwoKICB1bnNpZ25lZCBjaGFyIGlobCA9ICh1bnNpZ25lZCBjaGFyKShidWZb
b2ZmXSAmIDE1KSAqIDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0KSAhPSA0IHx8IGlobCA8IDIwIHx8
IGJ1ZltvZmYgKyA5XSAhPSA2KSByZXR1cm4gZmFsc2U7CgogIC8vIFJlamVjdCBmcmFnbWVudGVk
IElQIHBhY2tldHMgKG5vbi1maXJzdCBmcmFnbWVudCBoYXMgZnJhZyBvZmZzZXQgPiAwKQogIHVp
bnQxNl90IGZyYWcgPSBudG9ocyhyZWFkX3UxNihidWYgKyBvZmYgKyA2KSk7CiAgaWYgKGZyYWcg
JiAweDFmZmYpIHJldHVybiBmYWxzZTsKCiAgLy8gSVB2NCB0b3RhbCBsZW5ndGggdmFsaWRhdGlv
biBhbmQgdHJ1bmNhdGlvbiBjaGVjawogIHVpbnQxNl90IGlwX3RvdGFsX2xlbiA9IG50b2hzKHJl
YWRfdTE2KGJ1ZiArIG9mZiArIDIpKTsKICBib29sIGlzX3RydW5jYXRlZCA9IGZhbHNlOwogIGlm
IChpcF90b3RhbF9sZW4gPiAwKSB7CiAgICBpZiAoaXBfdG90YWxfbGVuIDwgaWhsICsgMjApIHJl
dHVybiBmYWxzZTsKICAgIGlmIChuIC0gb2ZmIDwgaXBfdG90YWxfbGVuKSB7CiAgICAgIGlzX3Ry
dW5jYXRlZCA9IHRydWU7CiAgICB9IGVsc2UgaWYgKG4gLSBvZmYgPiBpcF90b3RhbF9sZW4pIHsK
ICAgICAgbiA9IG9mZiArIGlwX3RvdGFsX2xlbjsgLy8gRXhjbHVkZSBFdGhlcm5ldCBwYWRkaW5n
CiAgICB9CiAgfQoKICB1aW50MzJfdCBzX2lwID0gcmVhZF91MzIoYnVmICsgb2ZmICsgMTIpOwog
IHVpbnQzMl90IGRfaXAgPSByZWFkX3UzMihidWYgKyBvZmYgKyAxNik7CiAgc2l6ZV90IHRvID0g
b2ZmICsgaWhsOwogIGlmIChuIDwgdG8gKyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1bnNpZ25lZCBz
cG9ydCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIHRvKSk7CiAgdW5zaWduZWQgZHBvcnQgPSBudG9o
cyhyZWFkX3UxNihidWYgKyB0byArIDIpKTsKICB1aW50MzJfdCBzZXEgPSBudG9obChyZWFkX3Uz
MihidWYgKyB0byArIDQpKTsKICB1bnNpZ25lZCBkb2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAq
IDQ7CiAgaWYgKGRvZmYgPCAyMCB8fCBuIDwgdG8gKyBkb2ZmKSByZXR1cm4gZmFsc2U7CgogIHVu
c2lnbmVkIGNoYXIgdGNwX2ZsYWdzID0gYnVmW3RvICsgMTNdOwogIGNvbnN0IGNoYXIgKnBheWxv
YWQgPSAoY29uc3QgY2hhciAqKShidWYgKyB0byArIGRvZmYpOwogIHNpemVfdCBwbGVuID0gbiAt
IHRvIC0gZG9mZjsKCiAgdGltZV90IG5vdyA9IChwY2FwX25vdyA+IDApID8gcGNhcF9ub3cgOiB0
aW1lKE5VTEwpOwogIGxvbmcgbG9uZyBtb25vX25vdyA9IChwY2FwX21vbm9fbm93ID4gMCkgPyBw
Y2FwX21vbm9fbm93IDogbm93X21vbm90b25pY19tcygpOwoKICBib29sIGRzdF9tb24gPSAoZHBv
cnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tkcG9ydF0gOiBmYWxzZTsKICBib29sIHNy
Y19tb24gPSAoc3BvcnQgPCA2NTUzNikgPyBnX21vbml0b3JlZF9wb3J0c1tzcG9ydF0gOiBmYWxz
ZTsKCiAgLy8gRGlyZWN0aW9uIEE6IFNlcnZlciAtPiBDbGllbnQgUmVzcG9uc2UgUmVhc3NlbWJs
eQogIGlmIChzcmNfbW9uICYmICFkc3RfbW9uKSB7CiAgICBGbG93S2V5IHJmazsKICAgIHJmay5z
X2lwID0gc19pcDsgcmZrLnNwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgcmZrLmRfaXAgPSBk
X2lwOyByZmsuZHBvcnQgPSAodWludDE2X3QpZHBvcnQ7CgogICAgaWYgKHRjcF9mbGFncyAmIDB4
MDIpIHsgLy8gU1lOIGZyb20gc2VydmVyCiAgICAgIGV2aWN0X29sZGVzdF9mbG93X2lmX25lZWRl
ZChmbG93cywgcGVuZGluZyk7CiAgICAgIEZsb3cgJnJmbCA9IGZsb3dzW3Jma107CiAgICAgIHJm
bC5jbGVhcl9idWZmZXJzKCk7CiAgICAgIHJmbCA9IEZsb3coKTsKICAgICAgcmZsLmhhc19zZXEg
PSB0cnVlOwogICAgICByZmwubmV4dF9zZXEgPSBzZXEgKyAxOwogICAgICByZmwuaXNfYnJva2Vu
ID0gZmFsc2U7CiAgICAgIHJmbC50b3VjaGVkID0gbm93OwogICAgICByZXR1cm4gdHJ1ZTsKICAg
IH0KCiAgICBpZiAocGxlbiA+IDApIHsKICAgICAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVk
KGZsb3dzLCBwZW5kaW5nKTsKICAgICAgRmxvdyAmcmZsID0gZmxvd3NbcmZrXTsKICAgICAgcmZs
LnRvdWNoZWQgPSBub3c7CgogICAgICBpZiAoIXJmbC5oYXNfc2VxKSB7CiAgICAgICAgaWYgKChw
bGVuID49IDUgJiYgbWVtY21wKHBheWxvYWQsICJIVFRQLyIsIDUpID09IDApIHx8CiAgICAgICAg
ICAgIChwbGVuIDwgNSAmJiBtZW1jbXAocGF5bG9hZCwgIkhUVFAvIiwgcGxlbikgPT0gMCkpIHsK
ICAgICAgICAgIHJmbC5oYXNfc2VxID0gdHJ1ZTsKICAgICAgICAgIHJmbC5uZXh0X3NlcSA9IHNl
cTsKICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBmYWxzZTsKICAgICAgICB9IGVsc2UgewogICAg
ICAgICAgaWYgKHJmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNh
dGVkKSB7CiAgICAgICAgICAgIGJvb2wgZHVwID0gZmFsc2U7CiAgICAgICAgICAgIGZvciAoc2l6
ZV90IGkgPSAwOyBpIDwgcmZsLm9vby5zaXplKCk7ICsraSkgewogICAgICAgICAgICAgIGlmIChy
Zmwub29vW2ldLnNlcSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgICAgICAg
fQogICAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAgICAgIHJmbC5vb29fcHVzaChzZXEs
IHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICByZXR1
cm4gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGludDMyX3QgZGlmZiA9IHNlcV9kaWZm
KHNlcSwgcmZsLm5leHRfc2VxKTsKICAgICAgaWYgKGRpZmYgPT0gMCkgewogICAgICAgIGlmIChp
c190cnVuY2F0ZWQpIHsKICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgIH0g
ZWxzZSB7CiAgICAgICAgICBpZiAoIXJmbC5idWZfYXBwZW5kKHBheWxvYWQsIHBsZW4pKSByZXR1
cm4gdHJ1ZTsKICAgICAgICAgIHJmbC5uZXh0X3NlcSArPSAodWludDMyX3QpcGxlbjsKICAgICAg
ICAgIGlmICghZHJhaW5fb29vX3NlZ21lbnRzKHJmbCkpIHJldHVybiB0cnVlOwogICAgICAgIH0K
ICAgICAgfSBlbHNlIGlmIChkaWZmIDwgMCkgewogICAgICAgIGludDMyX3Qgb3ZlcmxhcCA9IC1k
aWZmOwogICAgICAgIGlmICgoc2l6ZV90KW92ZXJsYXAgPCBwbGVuICYmICFpc190cnVuY2F0ZWQp
IHsKICAgICAgICAgIHNpemVfdCBmbGVuID0gcGxlbiAtIG92ZXJsYXA7CiAgICAgICAgICBpZiAo
IXJmbC5idWZfYXBwZW5kKHBheWxvYWQgKyBvdmVybGFwLCBmbGVuKSkgcmV0dXJuIHRydWU7CiAg
ICAgICAgICByZmwubmV4dF9zZXEgKz0gKHVpbnQzMl90KWZsZW47CiAgICAgICAgICBpZiAoIWRy
YWluX29vb19zZWdtZW50cyhyZmwpKSByZXR1cm4gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0gZWxz
ZSB7IC8vIGRpZmYgPiAwCiAgICAgICAgaWYgKHJmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdN
RU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICBib29sIGR1cCA9IGZhbHNlOwogICAg
ICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCByZmwub29vLnNpemUoKTsgKytpKSB7CiAgICAg
ICAgICAgIGlmIChyZmwub29vW2ldLnNlcSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0K
ICAgICAgICAgIH0KICAgICAgICAgIGlmICghZHVwKSB7CiAgICAgICAgICAgIHJmbC5vb29fcHVz
aChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAg
ICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIC8vIFBh
cnNlIGNvbXBsZXRlIHJlc3BvbnNlcyBmcm9tIHJlYXNzZW1ibGVkIGJ1ZmZlciB1c2luZyBIVFRQ
IGZyYW1pbmcKICAgICAgd2hpbGUgKCFyZmwuYnVmLmVtcHR5KCkgJiYgIXJmbC5pc19icm9rZW4p
IHsKICAgICAgICBpZiAocmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSKSB7CiAg
ICAgICAgICBzaXplX3QgZW5kID0gcmZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAgICAg
aWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgICBpZiAocmZsLmJ1Zi5z
aXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZl
cnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgfQog
ICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KCiAgICAgICAgICBpZiAocmZsLmJ1Zi5jb21w
YXJlKDAsIDUsICJIVFRQLyIpICE9IDApIHsKICAgICAgICAgICAgc2l6ZV90IGhwb3MgPSByZmwu
YnVmLmZpbmQoIkhUVFAvIik7CiAgICAgICAgICAgIGlmIChocG9zID09IHN0ZDo6c3RyaW5nOjpu
cG9zIHx8IGhwb3MgPiBlbmQpIHsKICAgICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIGVuZCAr
IDQpOwogICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJm
bC5idWZfZXJhc2UoMCwgaHBvcyk7CiAgICAgICAgICAgIGVuZCAtPSBocG9zOwogICAgICAgICAg
fQoKICAgICAgICAgIGludCBzdCA9IDA7IHNpemVfdCBjbCA9IDA7IGJvb2wgaGFzX2NsID0gZmFs
c2UsIGlzX2NodW5rZWQgPSBmYWxzZSwgaXNfY2xvc2UgPSBmYWxzZTsKICAgICAgICAgIGlmICgh
cGFyc2VfcmVzcG9uc2UocmZsLmJ1Zi5kYXRhKCksIGVuZCArIDIsICZzdCwgJmNsLCAmaGFzX2Ns
LCAmaXNfY2h1bmtlZCwgJmlzX2Nsb3NlKSkgewogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAs
IGVuZCArIDQpOwogICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgIH0KCiAgICAgICAgICBp
ZiAoc3QgPj0gMTAwICYmIHN0IDw9IDE5OSAmJiBzdCAhPSAxMDEpIHsKICAgICAgICAgICAgcmZs
LmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICB9
CgogICAgICAgICAgUGFja2V0S2V5IHBrOwogICAgICAgICAgcGsuc19pcCA9IHNfaXA7IHBrLnNw
b3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICAgICAgcGsuZF9pcCA9IGRfaXA7IHBrLmRwb3J0
ID0gKHVpbnQxNl90KWRwb3J0OwogICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZl
Y3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKHBrKTsKICAgICAgICAg
IGJvb2wgaXNfaGVhZCA9IGZhbHNlOwogICAgICAgICAgaWYgKHAgIT0gcGVuZGluZy5lbmQoKSAm
JiAhcC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgICAgICAgICAgaWYgKHJmbC5nZW5lcmF0aW9uICE9
IDAgJiYgcC0+c2Vjb25kWzBdLmdlbmVyYXRpb24gIT0gMCAmJiBwLT5zZWNvbmRbMF0uZ2VuZXJh
dGlvbiAhPSByZmwuZ2VuZXJhdGlvbikgewogICAgICAgICAgICAgIC8vIEdlbmVyYXRpb24gbWlz
bWF0Y2ghIFN0YWxlIHJlcXVlc3QgZnJvbSBwcmV2aW91cyBjb25uZWN0aW9uLgogICAgICAgICAg
ICAgIGVtaXRfZXZlbnQocC0+c2Vjb25kWzBdLmV2KTsKICAgICAgICAgICAgICBpZiAoIXAtPnNl
Y29uZFswXS5pc190b21ic3RvbmUgJiYgZ190b3RhbF9wZW5kaW5nX2NvdW50ID4gMCkgLS1nX3Rv
dGFsX3BlbmRpbmdfY291bnQ7CiAgICAgICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29u
ZC5iZWdpbigpKTsKICAgICAgICAgICAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcu
ZXJhc2UocCk7CiAgICAgICAgICAgIH0gZWxzZSBpZiAocC0+c2Vjb25kWzBdLmlzX3RvbWJzdG9u
ZSkgewogICAgICAgICAgICAgIC8vIExhdGUgcmVzcG9uc2UgZm9yIGV4cGlyZWQgcmVxdWVzdDog
Y29uc3VtZSB0b21ic3RvbmUsIGRvIG5vdCBhdHRhY2ggdG8gbmV3ZXIgcmVxdWVzdHMKICAgICAg
ICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkpOwogICAgICAgICAgICAg
IGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgICAgICAgICAgfSBl
bHNlIHsKICAgICAgICAgICAgICBFdmVudCBlID0gcC0+c2Vjb25kWzBdLmV2OwogICAgICAgICAg
ICAgIGlmIChlLm1ldGhvZCA9PSAiSEVBRCIpIGlzX2hlYWQgPSB0cnVlOwogICAgICAgICAgICAg
IGUuc3RhdHVzID0gc3Q7CiAgICAgICAgICAgICAgZS5oYXNfc3RhdHVzID0gdHJ1ZTsKICAgICAg
ICAgICAgICBlLmR1cmF0aW9uX21zID0gKGxvbmcpKG1vbm9fbm93IC0gcC0+c2Vjb25kWzBdLnN0
YXJ0ZWRfbW9ub19tcyk7CiAgICAgICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBlLmR1
cmF0aW9uX21zID0gMDsKICAgICAgICAgICAgICBlLmhhc19kdXJhdGlvbiA9IHRydWU7CiAgICAg
ICAgICAgICAgaWYgKGhhc19jbCkgewogICAgICAgICAgICAgICAgZS5yZXNwX2J5dGVzID0gKHVu
c2lnbmVkKWNsOwogICAgICAgICAgICAgICAgZS5oYXNfcmVzcCA9IHRydWU7CiAgICAgICAgICAg
ICAgfQogICAgICAgICAgICAgIGVtaXRfZXZlbnQoZSk7CiAgICAgICAgICAgICAgcC0+c2Vjb25k
LmVyYXNlKHAtPnNlY29uZC5iZWdpbigpKTsKICAgICAgICAgICAgICBpZiAoZ190b3RhbF9wZW5k
aW5nX2NvdW50ID4gMCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgICAgICAgICAgaWYg
KHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgICAgICB9CiAgICAg
ICAgICB9CgogICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKCiAgICAgICAgICBp
ZiAoaXNfaGVhZCB8fCBzdCA9PSAyMDQgfHwgc3QgPT0gMzA0KSB7CiAgICAgICAgICAgIHJmbC5z
dGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgfSBlbHNlIGlmIChpc19j
aHVua2VkKSB7CiAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTks7
CiAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IHRydWU7CiAgICAgICAgICAgIHJm
bC5jaHVua19yZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRp
bmdfdHJhaWxlciA9IGZhbHNlOwogICAgICAgICAgICByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5p
bmcgPSAwOwogICAgICAgICAgfSBlbHNlIGlmIChoYXNfY2wpIHsKICAgICAgICAgICAgaWYgKGNs
ID4gMCkgewogICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQk9EWTsK
ICAgICAgICAgICAgICByZmwuYm9keV9yZW1haW5pbmcgPSBjbDsKICAgICAgICAgICAgfSBlbHNl
IHsKICAgICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAg
ICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIGlmIChpc19jbG9zZSkgewogICAgICAgICAgICBy
Zmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFk7CiAgICAgICAgICB9IGVsc2Ug
ewogICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFk7CiAg
ICAgICAgICB9CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CgogICAgICAgIGlmIChyZmwu
c3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFURV9CT0RZKSB7CiAgICAgICAgICBpZiAocmZsLmJ1Zi5l
bXB0eSgpKSBicmVhazsKICAgICAgICAgIHNpemVfdCB0b19jb25zdW1lID0gKHJmbC5idWYuc2l6
ZSgpIDwgcmZsLmJvZHlfcmVtYWluaW5nKSA/IHJmbC5idWYuc2l6ZSgpIDogcmZsLmJvZHlfcmVt
YWluaW5nOwogICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCB0b19jb25zdW1lKTsKICAgICAgICAg
IHJmbC5ib2R5X3JlbWFpbmluZyAtPSB0b19jb25zdW1lOwogICAgICAgICAgaWYgKHJmbC5ib2R5
X3JlbWFpbmluZyA9PSAwKSB7CiAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RB
VEVfSEVBREVSOwogICAgICAgICAgfQogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQoKICAg
ICAgICBpZiAocmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTkspIHsKICAgICAgICAg
IGlmIChyZmwuYnVmLmVtcHR5KCkpIGJyZWFrOwogICAgICAgICAgaWYgKHJmbC5jaHVua19yZWFk
aW5nX3RyYWlsZXIpIHsKICAgICAgICAgICAgaWYgKHJmbC5idWYuc2l6ZSgpID49IDIgJiYgcmZs
LmJ1ZlswXSA9PSAnXHInICYmIHJmbC5idWZbMV0gPT0gJ1xuJykgewogICAgICAgICAgICAgIHJm
bC5idWZfZXJhc2UoMCwgMik7CiAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxl
ciA9IGZhbHNlOwogICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVB
REVSOwogICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHNp
emVfdCB0cl9lbmQgPSByZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAgICAgICAgICAgIGlmICh0
cl9lbmQgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgICByZmwuYnVmX2VyYXNl
KDAsIHRyX2VuZCArIDQpOwogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIg
PSBmYWxzZTsKICAgICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURF
UjsKICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAo
cmZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAgICAgICAgICAgcmZsLmNs
ZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAg
ICAgICAgfQogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICAgIGlmIChyZmwu
Y2h1bmtfcmVhZGluZ19sZW4pIHsKICAgICAgICAgICAgc2l6ZV90IGNybGYgPSByZmwuYnVmLmZp
bmQoIlxyXG4iKTsKICAgICAgICAgICAgaWYgKGNybGYgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsK
ICAgICAgICAgICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPiA2NCkgewogICAgICAgICAgICAgICAg
cmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVl
OwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgfQogICAg
ICAgICAgICBzdGQ6OnN0cmluZyBsaW5lID0gdHJpbShyZmwuYnVmLnN1YnN0cigwLCBjcmxmKSk7
CiAgICAgICAgICAgIHNpemVfdCBzZW1pID0gbGluZS5maW5kKCc7Jyk7CiAgICAgICAgICAgIHN0
ZDo6c3RyaW5nIGhleF9zdHIgPSAoc2VtaSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgPyB0cmltKGxp
bmUuc3Vic3RyKDAsIHNlbWkpKSA6IGxpbmU7CiAgICAgICAgICAgIGlmIChoZXhfc3RyLmVtcHR5
KCkgfHwgaGV4X3N0ci5zaXplKCkgPiAxNikgewogICAgICAgICAgICAgIHJmbC5jbGVhcl9idWZm
ZXJzKCk7CiAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgICAg
YnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgYm9vbCB2YWxpZF9oZXggPSB0cnVlOwog
ICAgICAgICAgICBmb3IgKHNpemVfdCBoaSA9IDA7IGhpIDwgaGV4X3N0ci5zaXplKCk7ICsraGkp
IHsKICAgICAgICAgICAgICBpZiAoIWlzeGRpZ2l0KCh1bnNpZ25lZCBjaGFyKWhleF9zdHJbaGld
KSkgeyB2YWxpZF9oZXggPSBmYWxzZTsgYnJlYWs7IH0KICAgICAgICAgICAgfQogICAgICAgICAg
ICBpZiAoIXZhbGlkX2hleCkgewogICAgICAgICAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAg
ICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgICAgYnJlYWs7CiAg
ICAgICAgICAgIH0KICAgICAgICAgICAgY2hhciAqZW5kcHRyID0gTlVMTDsKICAgICAgICAgICAg
ZXJybm8gPSAwOwogICAgICAgICAgICB1bnNpZ25lZCBsb25nIGxvbmcgcGFyc2VkX2xlbiA9IHN0
cnRvdWxsKGhleF9zdHIuY19zdHIoKSwgJmVuZHB0ciwgMTYpOwogICAgICAgICAgICBpZiAoZXJy
bm8gIT0gMCB8fCBlbmRwdHIgIT0gaGV4X3N0ci5jX3N0cigpICsgaGV4X3N0ci5zaXplKCkgfHwg
cGFyc2VkX2xlbiA+IDE2Nzc3MjE2VUxMKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZl
cnMoKTsKICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgICBi
cmVhazsKICAgICAgICAgICAgfQogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIGNybGYgKyAy
KTsKICAgICAgICAgICAgaWYgKHBhcnNlZF9sZW4gPT0gMCkgewogICAgICAgICAgICAgIHJmbC5j
aHVua19yZWFkaW5nX3RyYWlsZXIgPSB0cnVlOwogICAgICAgICAgICAgIHJmbC5jaHVua19yZWFk
aW5nX2xlbiA9IGZhbHNlOwogICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9IGVs
c2UgewogICAgICAgICAgICAgIHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9IChzaXplX3Qp
cGFyc2VkX2xlbjsKICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsK
ICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19jcmxmID0gZmFsc2U7CiAgICAgICAgICAg
IH0KICAgICAgICAgIH0gZWxzZSBpZiAocmZsLmNodW5rX3JlYWRpbmdfY3JsZikgewogICAgICAg
ICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPCAyKSBicmVhazsKICAgICAgICAgICAgaWYgKHJmbC5i
dWZbMF0gIT0gJ1xyJyB8fCByZmwuYnVmWzFdICE9ICdcbicpIHsKICAgICAgICAgICAgICByZmwu
Y2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAg
ICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJmbC5idWZfZXJhc2Uo
MCwgMik7CiAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAg
ICAgICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0gdHJ1ZTsKICAgICAgICAgIH0gZWxzZSB7CiAg
ICAgICAgICAgIHNpemVfdCB0b19jb25zdW1lID0gKHJmbC5idWYuc2l6ZSgpIDwgcmZsLmNodW5r
X3BheWxvYWRfcmVtYWluaW5nKSA/IHJmbC5idWYuc2l6ZSgpIDogcmZsLmNodW5rX3BheWxvYWRf
cmVtYWluaW5nOwogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIHRvX2NvbnN1bWUpOwogICAg
ICAgICAgICByZmwuY2h1bmtfcGF5bG9hZF9yZW1haW5pbmcgLT0gdG9fY29uc3VtZTsKICAgICAg
ICAgICAgaWYgKHJmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZyA9PSAwKSB7CiAgICAgICAgICAg
ICAgcmZsLmNodW5rX3JlYWRpbmdfY3JsZiA9IHRydWU7CiAgICAgICAgICAgIH0KICAgICAgICAg
IH0KICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgIH0KCiAgICAgICAgaWYgKHJmbC5zdGF0ZSA9
PSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFkpIHsKICAgICAgICAgIHJmbC5idWZfZXJhc2Uo
MCwgcmZsLmJ1Zi5zaXplKCkpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICB9CiAg
ICB9CgogICAgaWYgKHRjcF9mbGFncyAmIDB4MDUpIHsgLy8gU2VydmVyIEZJTiBvciBSU1QKICAg
ICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGl0ID0gZmxvd3MuZmluZChyZmsp
OwogICAgICBpZiAoaXQgIT0gZmxvd3MuZW5kKCkpIHsKICAgICAgICBpdC0+c2Vjb25kLmNsZWFy
X2J1ZmZlcnMoKTsKICAgICAgICBmbG93cy5lcmFzZShpdCk7CiAgICAgIH0KICAgIH0KICAgIHJl
dHVybiB0cnVlOwogIH0KCiAgLy8gRGlyZWN0aW9uIEI6IENsaWVudCAtPiBTZXJ2ZXIgUmVxdWVz
dCBSZWFzc2VtYmx5CiAgaWYgKCFkc3RfbW9uKSB7CiAgICBpZiAodGNwX2ZsYWdzICYgMHgwNSkg
ewogICAgICBGbG93S2V5IHJmazsgcmZrLnNfaXAgPSBkX2lwOyByZmsuc3BvcnQgPSAodWludDE2
X3QpZHBvcnQ7IHJmay5kX2lwID0gc19pcDsgcmZrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0Owog
ICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgaXQgPSBmbG93cy5maW5kKHJm
ayk7CiAgICAgIGlmIChpdCAhPSBmbG93cy5lbmQoKSkgewogICAgICAgIGl0LT5zZWNvbmQuY2xl
YXJfYnVmZmVycygpOwogICAgICAgIGZsb3dzLmVyYXNlKGl0KTsKICAgICAgfQogICAgfQogICAg
cmV0dXJuIGZhbHNlOwogIH0KCiAgRmxvd0tleSBmazsKICBmay5zX2lwID0gc19pcDsgZmsuc3Bv
cnQgPSAodWludDE2X3Qpc3BvcnQ7IGZrLmRfaXAgPSBkX2lwOyBmay5kcG9ydCA9ICh1aW50MTZf
dClkcG9ydDsKCiAgaWYgKHRjcF9mbGFncyAmIDB4MDIpIHsgLy8gU1lOIGZyb20gY2xpZW50OiBu
ZXcgY29ubmVjdGlvbiBnZW5lcmF0aW9uIQogICAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVk
KGZsb3dzLCBwZW5kaW5nKTsKICAgIFBhY2tldEtleSByazsgcmsuc19pcCA9IGRfaXA7IHJrLnNw
b3J0ID0gKHVpbnQxNl90KWRwb3J0OyByay5kX2lwID0gc19pcDsgcmsuZHBvcnQgPSAodWludDE2
X3Qpc3BvcnQ7CgogICAgLy8gUHVyZ2UgcHJldmlvdXMgZ2VuZXJhdGlvbidzIHBlbmRpbmcgcmVx
dWVzdHMgZm9yIHRoaXMgNC10dXBsZQogICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3Rv
cjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKHJrKTsKICAgIGlmIChwICE9
IHBlbmRpbmcuZW5kKCkpIHsKICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBwLT5zZWNvbmQu
c2l6ZSgpOyArK2kpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAg
ICAgaWYgKGdfdG90YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50
OwogICAgICB9CiAgICAgIHBlbmRpbmcuZXJhc2UocCk7CiAgICB9CgogICAgRmxvdyAmZmwgPSBm
bG93c1tma107CiAgICBpZiAoZmwuYXdhaXRpbmdfd3NzZSkgewogICAgICBpZiAoIWZsLndzc2Vf
ZXZlbnQubWV0aG9kLmVtcHR5KCkpIHsKICAgICAgICBlbWl0X2V2ZW50KGZsLndzc2VfZXZlbnQp
OwogICAgICB9CiAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBmYWxzZTsKICAgIH0KICAgIHVpbnQz
Ml90IG5leHRfZ2VuID0gZmwuZ2VuZXJhdGlvbiArIDE7CiAgICBmbC5jbGVhcl9idWZmZXJzKCk7
CiAgICBmbCA9IEZsb3coKTsKICAgIGZsLmdlbmVyYXRpb24gPSBuZXh0X2dlbjsKICAgIGZsLmhh
c19zZXEgPSB0cnVlOwogICAgZmwubmV4dF9zZXEgPSBzZXEgKyAxOwogICAgZmwudG91Y2hlZCA9
IG5vdzsKICAgIGZsLmZpcnN0X2J5dGVfbW9ub19tcyA9IDA7CgogICAgLy8gUmVzZXQgc2VydmVy
IHJlc3BvbnNlIGZsb3cgZm9yIHRoaXMgNC10dXBsZSBhbmQgY2FycnkgZm9yd2FyZCBuZXcgZ2Vu
ZXJhdGlvbgogICAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIHJmaXQgPSBmbG93
cy5maW5kKHJrKTsKICAgIGlmIChyZml0ICE9IGZsb3dzLmVuZCgpKSB7CiAgICAgIHJmaXQtPnNl
Y29uZC5jbGVhcl9idWZmZXJzKCk7CiAgICB9CiAgICBGbG93ICZyZXNwX2ZsID0gZmxvd3Nbcmtd
OwogICAgcmVzcF9mbCA9IEZsb3coKTsKICAgIHJlc3BfZmwuZ2VuZXJhdGlvbiA9IG5leHRfZ2Vu
OwogICAgcmV0dXJuIHRydWU7CiAgfQoKICBldmljdF9vbGRlc3RfZmxvd19pZl9uZWVkZWQoZmxv
d3MsIHBlbmRpbmcpOwogIEZsb3cgJmZsID0gZmxvd3NbZmtdOwogIGZsLnRvdWNoZWQgPSBub3c7
CgogIGlmIChwbGVuID4gMCkgewogICAgaWYgKCFmbC5oYXNfc2VxKSB7CiAgICAgIGlmIChpc19t
ZXRob2Rfb3JfcHJlZml4KHBheWxvYWQsIHBsZW4pKSB7CiAgICAgICAgZmwuaGFzX3NlcSA9IHRy
dWU7CiAgICAgICAgZmwubmV4dF9zZXEgPSBzZXE7CiAgICAgICAgZmwuaXNfYnJva2VuID0gZmFs
c2U7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgaWYgKGZsLm9vby5zaXplKCkgPCBNQVhfT09PX1NF
R01FTlRTICYmICFpc190cnVuY2F0ZWQpIHsKICAgICAgICAgIGJvb2wgZHVwID0gZmFsc2U7CiAg
ICAgICAgICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGZsLm9vby5zaXplKCk7ICsraSkgewogICAg
ICAgICAgICBpZiAoZmwub29vW2ldLnNlcSA9PSBzZXEpIHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0K
ICAgICAgICAgIH0KICAgICAgICAgIGlmICghZHVwKSB7CiAgICAgICAgICAgIGZsLm9vb19wdXNo
KHNlcSwgcGF5bG9hZCwgcGxlbik7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIHJldHVy
biB0cnVlOwogICAgICB9CiAgICB9CgogICAgaW50MzJfdCBkaWZmID0gc2VxX2RpZmYoc2VxLCBm
bC5uZXh0X3NlcSk7CiAgICBpZiAoZGlmZiA9PSAwKSB7CiAgICAgIGlmIChpc190cnVuY2F0ZWQp
IHsKICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICB9IGVsc2UgewogICAgICAgIGlm
ICghZmwuYnVmX2FwcGVuZChwYXlsb2FkLCBwbGVuKSkgcmV0dXJuIHRydWU7CiAgICAgICAgZmwu
bmV4dF9zZXEgKz0gKHVpbnQzMl90KXBsZW47CiAgICAgICAgaWYgKCFkcmFpbl9vb29fc2VnbWVu
dHMoZmwpKSByZXR1cm4gdHJ1ZTsKICAgICAgfQogICAgfSBlbHNlIGlmIChkaWZmIDwgMCkgewog
ICAgICBpbnQzMl90IG92ZXJsYXAgPSAtZGlmZjsKICAgICAgaWYgKChzaXplX3Qpb3ZlcmxhcCA8
IHBsZW4gJiYgIWlzX3RydW5jYXRlZCkgewogICAgICAgIHNpemVfdCBmbGVuID0gcGxlbiAtIG92
ZXJsYXA7CiAgICAgICAgaWYgKCFmbC5idWZfYXBwZW5kKHBheWxvYWQgKyBvdmVybGFwLCBmbGVu
KSkgcmV0dXJuIHRydWU7CiAgICAgICAgZmwubmV4dF9zZXEgKz0gKHVpbnQzMl90KWZsZW47CiAg
ICAgICAgaWYgKCFkcmFpbl9vb29fc2VnbWVudHMoZmwpKSByZXR1cm4gdHJ1ZTsKICAgICAgfQog
ICAgfSBlbHNlIHsgLy8gZGlmZiA+IDAgKG91dCBvZiBvcmRlciBnYXApCiAgICAgIGlmIChmbC5v
b28uc2l6ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAg
Ym9vbCBkdXAgPSBmYWxzZTsKICAgICAgICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGZsLm9vby5z
aXplKCk7ICsraSkgewogICAgICAgICAgaWYgKGZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9
IHRydWU7IGJyZWFrOyB9CiAgICAgICAgfQogICAgICAgIGlmICghZHVwKSB7CiAgICAgICAgICBm
bC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsK
ICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICB9CiAgICB9CgogICAgLy8gSFRUUCBG
cmFtaW5nIFN0YXRlIE1hY2hpbmUgZm9yIHJlcXVlc3RzCiAgICB3aGlsZSAoIWZsLmJ1Zi5lbXB0
eSgpICYmICFmbC5pc19icm9rZW4pIHsKICAgICAgaWYgKGZsLnN0YXRlID09IEZsb3c6OkhUVFBf
U1RBVEVfSEVBREVSKSB7CiAgICAgICAgaWYgKCFmbC5maXJzdF9ieXRlX21vbm9fbXMpIGZsLmZp
cnN0X2J5dGVfbW9ub19tcyA9IG1vbm9fbm93OwoKICAgICAgICBzaXplX3QgZW5kID0gZmwuYnVm
LmZpbmQoIlxyXG5cclxuIik7CiAgICAgICAgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykg
ewogICAgICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAg
ICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1
ZTsKICAgICAgICAgIH0KICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KCiAgICAgICAgc2l6ZV90
IHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0KGZsLmJ1Zik7CiAgICAgICAgaWYgKHN0YXJ0ID09IHN0
ZDo6c3RyaW5nOjpucG9zIHx8IHN0YXJ0ID4gZW5kKSB7CiAgICAgICAgICBmbC5idWZfZXJhc2Uo
MCwgZW5kICsgNCk7CiAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CiAgICAgICAgaWYgKHN0
YXJ0ID4gMCkgewogICAgICAgICAgZmwuYnVmX2VyYXNlKDAsIHN0YXJ0KTsKICAgICAgICAgIGVu
ZCAtPSBzdGFydDsKICAgICAgICB9CgogICAgICAgIEV2ZW50IGU7IFJlcXVlc3RNZXRhIG1ldGE7
CiAgICAgICAgZS50cyA9IG5vdzsgZS5ob3N0ID0gbm9kZTsgZS5zZXJ2aWNlID0gInBvcnQ6IiAr
IG51bShkcG9ydCk7CiAgICAgICAgZS5jYWxsZXIgPSBpcF90b19zdHIoc19pcCk7IGUuY2FsbGVy
X3BvcnQgPSBzcG9ydDsKICAgICAgICBlLmRzdF9pcCA9IGlwX3RvX3N0cihkX2lwKTsgZS5kc3Rf
cG9ydCA9IGRwb3J0OwogICAgICAgIGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKShlbmQgKyA0KTsK
CiAgICAgICAgaWYgKCFwYXJzZV9yZXF1ZXN0KGZsLmJ1Zi5kYXRhKCksIGVuZCArIDIsICZlLCAm
bWV0YSkpIHsKICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAgICAgIGNv
bnRpbnVlOwogICAgICAgIH0KCiAgICAgICAgLy8gUmVqZWN0IGNvbmZsaWN0aW5nIENvbnRlbnQt
TGVuZ3RoICsgY2h1bmtlZCBlbmNvZGluZyAoUkZDIDcyMzAgcmVxdWVzdCBzbXVnZ2xpbmcgcHJl
dmVudGlvbikKICAgICAgICBib29sIGhhc19jaHVua2VkID0gKGxvd2VyKG1ldGEudHJhbnNmZXJf
ZW5jb2RpbmcpLmZpbmQoImNodW5rZWQiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyk7CiAgICAgICAg
aWYgKG1ldGEuaGFzX2NvbmZsaWN0X2NsIHx8IChtZXRhLmhhc19jb250ZW50X2xlbmd0aCAmJiBo
YXNfY2h1bmtlZCkpIHsKICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAg
ICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRydWU7CiAg
ICAgICAgICBicmVhazsKICAgICAgICB9CgogICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0
KTsKCiAgICAgICAgYm9vbCB3c3NlX2VsaWdpYmxlID0gKGdfd3NzZV9ib2R5X2J5dGVzID4gMCAm
JgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpc19zb2FwX2NvbnRlbnRfdHlwZShtZXRh
LmNvbnRlbnRfdHlwZSkgJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YS5oYXNf
Y29udGVudF9sZW5ndGggJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YS5jb250
ZW50X2xlbmd0aCA+IDAgJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIWhhc19jaHVu
a2VkICYmCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGl2ZV93c3NlX2Zsb3dzKGZs
b3dzKSA8IE1BWF9XU1NFX0JPRFlfRkxPV1MpOwoKICAgICAgICBpZiAod3NzZV9lbGlnaWJsZSkg
ewogICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IHRydWU7CiAgICAgICAgICBmbC53c3NlX2V2
ZW50ID0gZTsKICAgICAgICAgIGZsb3dfYnl0ZXNfc3ViKGZsLndzc2VfYnVmLnNpemUoKSk7CiAg
ICAgICAgICBmbC53c3NlX2J1Zi5jbGVhcigpOwogICAgICAgICAgZmwud3NzZV9nb2FsID0gbWV0
YS5jb250ZW50X2xlbmd0aCA8IGdfd3NzZV9ib2R5X2J5dGVzID8gbWV0YS5jb250ZW50X2xlbmd0
aCA6IGdfd3NzZV9ib2R5X2J5dGVzOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBxdWV1ZV9y
ZXF1ZXN0KGUsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZywgZmwuZmlyc3RfYnl0
ZV9tb25vX21zLCBmbC5nZW5lcmF0aW9uKTsKICAgICAgICB9CgogICAgICAgIGlmIChtZXRhLmhh
c19jb250ZW50X2xlbmd0aCAmJiBtZXRhLmNvbnRlbnRfbGVuZ3RoID4gMCkgewogICAgICAgICAg
Zmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0JPRFk7CiAgICAgICAgICBmbC5ib2R5X3JlbWFp
bmluZyA9IG1ldGEuY29udGVudF9sZW5ndGg7CiAgICAgICAgfSBlbHNlIGlmIChoYXNfY2h1bmtl
ZCkgewogICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0NIVU5LOwogICAgICAg
ICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSB0cnVlOwogICAgICAgICAgZmwuY2h1bmtfcmVhZGlu
Z19jcmxmID0gZmFsc2U7CiAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxz
ZTsKICAgICAgICAgIGZsLmNodW5rX3BheWxvYWRfcmVtYWluaW5nID0gMDsKICAgICAgICB9IGVs
c2UgewogICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAg
ICAgIGZsLmZpcnN0X2J5dGVfbW9ub19tcyA9IGZsLmJ1Zi5lbXB0eSgpID8gMCA6IG1vbm9fbm93
OwogICAgICAgIH0KICAgICAgICBjb250aW51ZTsKICAgICAgfQoKICAgICAgaWYgKGZsLnN0YXRl
ID09IEZsb3c6OkhUVFBfU1RBVEVfQk9EWSkgewogICAgICAgIGlmIChmbC5idWYuZW1wdHkoKSkg
YnJlYWs7CiAgICAgICAgc2l6ZV90IHRvX2NvbnN1bWUgPSAoZmwuYnVmLnNpemUoKSA8IGZsLmJv
ZHlfcmVtYWluaW5nKSA/IGZsLmJ1Zi5zaXplKCkgOiBmbC5ib2R5X3JlbWFpbmluZzsKCiAgICAg
ICAgaWYgKGZsLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgICAgIHNpemVfdCB3c3NlX25lZWQgPSBm
bC53c3NlX2dvYWwgPiBmbC53c3NlX2J1Zi5zaXplKCkgPyBmbC53c3NlX2dvYWwgLSBmbC53c3Nl
X2J1Zi5zaXplKCkgOiAwOwogICAgICAgICAgaWYgKHdzc2VfbmVlZCA+IDApIHsKICAgICAgICAg
ICAgc2l6ZV90IGNvcHlfbGVuID0gKHRvX2NvbnN1bWUgPCB3c3NlX25lZWQpID8gdG9fY29uc3Vt
ZSA6IHdzc2VfbmVlZDsKICAgICAgICAgICAgZmwud3NzZV9hcHBlbmQoZmwuYnVmLmRhdGEoKSwg
Y29weV9sZW4pOwogICAgICAgICAgfQogICAgICAgICAgc3RkOjpzdHJpbmcgdXNlcm5hbWUgPSBl
eHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwud3NzZV9idWYpOwogICAgICAgICAgaWYgKCF1c2VybmFt
ZS5lbXB0eSgpIHx8IGZsLndzc2VfYnVmLnNpemUoKSA+PSBmbC53c3NlX2dvYWwpIHsKICAgICAg
ICAgICAgRXZlbnQgZXYgPSBmbC53c3NlX2V2ZW50OwogICAgICAgICAgICBpZiAoIXVzZXJuYW1l
LmVtcHR5KCkpIHsKICAgICAgICAgICAgICBldi53c3NlX3VzZXIgPSB1c2VybmFtZTsgZXYudXNl
ciA9IHVzZXJuYW1lOyBldi5zY2hlbWUgPSAid3NzZSI7CiAgICAgICAgICAgIH0KICAgICAgICAg
ICAgcXVldWVfcmVxdWVzdChldiwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nLCBm
bC5maXJzdF9ieXRlX21vbm9fbXMsIGZsLmdlbmVyYXRpb24pOwogICAgICAgICAgICBmbC5hd2Fp
dGluZ193c3NlID0gZmFsc2U7CiAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBmbC5idWZf
ZXJhc2UoMCwgdG9fY29uc3VtZSk7CiAgICAgICAgZmwuYm9keV9yZW1haW5pbmcgLT0gdG9fY29u
c3VtZTsKICAgICAgICBpZiAoZmwuYm9keV9yZW1haW5pbmcgPT0gMCkgewogICAgICAgICAgaWYg
KGZsLmF3YWl0aW5nX3dzc2UpIHsKICAgICAgICAgICAgcXVldWVfcmVxdWVzdChmbC53c3NlX2V2
ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcsIGZsLmZpcnN0X2J5dGVfbW9u
b19tcywgZmwuZ2VuZXJhdGlvbik7CiAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBmYWxz
ZTsKICAgICAgICAgIH0KICAgICAgICAgIGZsLnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9IRUFE
RVI7CiAgICAgICAgICBmbC5maXJzdF9ieXRlX21vbm9fbXMgPSBmbC5idWYuZW1wdHkoKSA/IDAg
OiBtb25vX25vdzsKICAgICAgICB9CiAgICAgICAgY29udGludWU7CiAgICAgIH0KCiAgICAgIGlm
IChmbC5zdGF0ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0NIVU5LKSB7CiAgICAgICAgaWYgKGZsLmJ1
Zi5lbXB0eSgpKSBicmVhazsKICAgICAgICBpZiAoZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyKSB7
CiAgICAgICAgICBpZiAoZmwuYnVmLnNpemUoKSA+PSAyICYmIGZsLmJ1ZlswXSA9PSAnXHInICYm
IGZsLmJ1ZlsxXSA9PSAnXG4nKSB7CiAgICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCAyKTsKICAg
ICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gZmFsc2U7CiAgICAgICAgICAgIGZs
LnN0YXRlID0gRmxvdzo6SFRUUF9TVEFURV9IRUFERVI7CiAgICAgICAgICAgIGZsLmZpcnN0X2J5
dGVfbW9ub19tcyA9IGZsLmJ1Zi5lbXB0eSgpID8gMCA6IG1vbm9fbm93OwogICAgICAgICAgICBj
b250aW51ZTsKICAgICAgICAgIH0KICAgICAgICAgIHNpemVfdCB0cl9lbmQgPSBmbC5idWYuZmlu
ZCgiXHJcblxyXG4iKTsKICAgICAgICAgIGlmICh0cl9lbmQgIT0gc3RkOjpzdHJpbmc6Om5wb3Mp
IHsKICAgICAgICAgICAgZmwuYnVmX2VyYXNlKDAsIHRyX2VuZCArIDQpOwogICAgICAgICAgICBm
bC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxzZTsKICAgICAgICAgICAgZmwuc3RhdGUgPSBG
bG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV9tb25vX21z
ID0gZmwuYnVmLmVtcHR5KCkgPyAwIDogbW9ub19ub3c7CiAgICAgICAgICAgIGNvbnRpbnVlOwog
ICAgICAgICAgfQogICAgICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSX0JZVEVT
KSB7CiAgICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgZmwuaXNfYnJv
a2VuID0gdHJ1ZTsKICAgICAgICAgIH0KICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgICAg
ICBpZiAoZmwuY2h1bmtfcmVhZGluZ19sZW4pIHsKICAgICAgICAgIHNpemVfdCBjcmxmID0gZmwu
YnVmLmZpbmQoIlxyXG4iKTsKICAgICAgICAgIGlmIChjcmxmID09IHN0ZDo6c3RyaW5nOjpucG9z
KSB7CiAgICAgICAgICAgIGlmIChmbC5idWYuc2l6ZSgpID4gNjQpIHsKICAgICAgICAgICAgICBm
bC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAg
ICAgICAgICAgfQogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICAgIHN0ZDo6
c3RyaW5nIGxpbmUgPSB0cmltKGZsLmJ1Zi5zdWJzdHIoMCwgY3JsZikpOwogICAgICAgICAgc2l6
ZV90IHNlbWkgPSBsaW5lLmZpbmQoJzsnKTsKICAgICAgICAgIHN0ZDo6c3RyaW5nIGhleF9zdHIg
PSAoc2VtaSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgPyB0cmltKGxpbmUuc3Vic3RyKDAsIHNlbWkp
KSA6IGxpbmU7CiAgICAgICAgICBpZiAoaGV4X3N0ci5lbXB0eSgpIHx8IGhleF9zdHIuc2l6ZSgp
ID4gMTYpIHsKICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICBmbC5p
c19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICAg
IGJvb2wgdmFsaWRfaGV4ID0gdHJ1ZTsKICAgICAgICAgIGZvciAoc2l6ZV90IGhpID0gMDsgaGkg
PCBoZXhfc3RyLnNpemUoKTsgKytoaSkgewogICAgICAgICAgICBpZiAoIWlzeGRpZ2l0KCh1bnNp
Z25lZCBjaGFyKWhleF9zdHJbaGldKSkgeyB2YWxpZF9oZXggPSBmYWxzZTsgYnJlYWs7IH0KICAg
ICAgICAgIH0KICAgICAgICAgIGlmICghdmFsaWRfaGV4KSB7CiAgICAgICAgICAgIGZsLmNsZWFy
X2J1ZmZlcnMoKTsKICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAg
YnJlYWs7CiAgICAgICAgICB9CiAgICAgICAgICBjaGFyICplbmRwdHIgPSBOVUxMOwogICAgICAg
ICAgZXJybm8gPSAwOwogICAgICAgICAgdW5zaWduZWQgbG9uZyBsb25nIHBhcnNlZF9sZW4gPSBz
dHJ0b3VsbChoZXhfc3RyLmNfc3RyKCksICZlbmRwdHIsIDE2KTsKICAgICAgICAgIGlmIChlcnJu
byAhPSAwIHx8IGVuZHB0ciAhPSBoZXhfc3RyLmNfc3RyKCkgKyBoZXhfc3RyLnNpemUoKSB8fCBw
YXJzZWRfbGVuID4gMTY3NzcyMTZVTEwpIHsKICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygp
OwogICAgICAgICAgICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAg
ICAgICAgIH0KICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBjcmxmICsgMik7CiAgICAgICAgICBp
ZiAocGFyc2VkX2xlbiA9PSAwKSB7CiAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxl
ciA9IHRydWU7CiAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gZmFsc2U7CiAgICAg
ICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgZmwuY2h1bmtf
cGF5bG9hZF9yZW1haW5pbmcgPSAoc2l6ZV90KXBhcnNlZF9sZW47CiAgICAgICAgICAgIGZsLmNo
dW5rX3JlYWRpbmdfbGVuID0gZmFsc2U7CiAgICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfY3Js
ZiA9IGZhbHNlOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSBpZiAoZmwuY2h1bmtfcmVhZGlu
Z19jcmxmKSB7CiAgICAgICAgICBpZiAoZmwuYnVmLnNpemUoKSA8IDIpIGJyZWFrOwogICAgICAg
ICAgaWYgKGZsLmJ1ZlswXSAhPSAnXHInIHx8IGZsLmJ1ZlsxXSAhPSAnXG4nKSB7CiAgICAgICAg
ICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsK
ICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwg
Mik7CiAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2NybGYgPSBmYWxzZTsKICAgICAgICAgIGZs
LmNodW5rX3JlYWRpbmdfbGVuID0gdHJ1ZTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2l6
ZV90IHRvX2NvbnN1bWUgPSAoZmwuYnVmLnNpemUoKSA8IGZsLmNodW5rX3BheWxvYWRfcmVtYWlu
aW5nKSA/IGZsLmJ1Zi5zaXplKCkgOiBmbC5jaHVua19wYXlsb2FkX3JlbWFpbmluZzsKICAgICAg
ICAgIGZsLmJ1Zl9lcmFzZSgwLCB0b19jb25zdW1lKTsKICAgICAgICAgIGZsLmNodW5rX3BheWxv
YWRfcmVtYWluaW5nIC09IHRvX2NvbnN1bWU7CiAgICAgICAgICBpZiAoZmwuY2h1bmtfcGF5bG9h
ZF9yZW1haW5pbmcgPT0gMCkgewogICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2NybGYgPSB0
cnVlOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBjb250aW51ZTsKICAgICAgfQogICAg
fQogIH0KCiAgLy8gRklOIC8gUlNUIExpZmVjeWNsZTogcHJvY2VzcyBhZnRlciBwYXlsb2FkCiAg
aWYgKHRjcF9mbGFncyAmIDB4MDUpIHsKICAgIGlmIChmbC5hd2FpdGluZ193c3NlKSB7CiAgICAg
IHF1ZXVlX3JlcXVlc3QoZmwud3NzZV9ldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBw
ZW5kaW5nLCBmbC5maXJzdF9ieXRlX21vbm9fbXMsIGZsLmdlbmVyYXRpb24pOwogICAgICBmbC5h
d2FpdGluZ193c3NlID0gZmFsc2U7CiAgICB9CiAgICBmbC5jbGVhcl9idWZmZXJzKCk7CiAgICBm
bG93cy5lcmFzZShmayk7CiAgfQoKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgYXR0YWNo
X2JwZihpbnQgZmQsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAmcG9ydHMpIHsKICBpZiAo
cG9ydHMuZW1wdHkoKSkgcmV0dXJuIGZhbHNlOwogIHN0ZDo6dmVjdG9yPHN0cnVjdCBzb2NrX2Zp
bHRlcj4gZjsgc2l6ZV90IGk7CiAgdW5zaWduZWQgTiA9ICh1bnNpZ25lZClwb3J0cy5zaXplKCk7
CiAgdW5zaWduZWQgcmVqZWN0ID0gMTEgKyBOICogODsKICB1bnNpZ25lZCBhY2NlcHQgPSByZWpl
Y3QgKyAxOwogIHN0cnVjdCBzb2NrX2ZpbHRlciB4OwojZGVmaW5lIEFERChDLEosVCxLKSBkbyB7
IFwKICB1bnNpZ25lZCBfanQgPSAodW5zaWduZWQpKEopLCBfamYgPSAodW5zaWduZWQpKFQpOyBc
CiAgaWYgKF9qdCA+IFVDSEFSX01BWCB8fCBfamYgPiBVQ0hBUl9NQVgpIHJldHVybiBmYWxzZTsg
XAogIHguY29kZT0oQyk7IHguanQ9KHVuc2lnbmVkIGNoYXIpX2p0OyB4LmpmPSh1bnNpZ25lZCBj
aGFyKV9qZjsgeC5rPShLKTsgXAogIGYucHVzaF9iYWNrKHgpOyBcCn0gd2hpbGUoMCkKICBBREQo
QlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAsIDEyKTsKICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQ
Rl9LLCAodW5zaWduZWQpKDYgKyA0ICogTiksIDAsIEVUSF9QX0lQX0hPU1QpOwoKICAvLyBQYXRo
IEI6IDgwMi4xUSBWTEFOCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVk
KShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRIX1BfODAyMVFfSE9TVCk7CiAg
QUREKEJQRl9MRHxCUEZfSHxCUEZfQUJTLCAwLCAwLCAxNik7CiAgQUREKEJQRl9KTVB8QlBGX0pF
UXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwg
RVRIX1BfSVBfSE9TVCk7CiAgQUREKEJQRl9MRHxCUEZfQnxCUEZfQUJTLCAwLCAwLCAyNyk7CiAg
QUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWdu
ZWQpZi5zaXplKCkgLSAxKSwgSVBQUk9UT19UQ1ApOwogIEFERChCUEZfTERYfEJQRl9CfEJQRl9N
U0gsIDAsIDAsIDE4KTsKICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAg
IEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMjApOwogICAgdW5zaWduZWQganQgPSBh
Y2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxC
UEZfSywganQsIDAsIHBvcnRzW2ldKTsKICB9CiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUo
KTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE4KTsKICAgIHVu
c2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVk
IGpmID0gKGkgPCBwb3J0cy5zaXplKCkgLSAxKSA/IDAgOiAocmVqZWN0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMSk7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgamYsIHBvcnRz
W2ldKTsKICB9CgogIC8vIFBhdGggQTogU3RhbmRhcmQgSVB2NAogIEFERChCUEZfTER8QlBGX0J8
QlBGX0FCUywgMCwgMCwgMjMpOwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNp
Z25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICBB
REQoQlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxNCk7CiAgZm9yIChpID0gMDsgaSA8IHBv
cnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE2
KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAg
IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCAwLCBwb3J0c1tpXSk7CiAgfQogIGZvciAo
aSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZf
SU5ELCAwLCAwLCAxNCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNp
emUoKSAtIDE7CiAgICB1bnNpZ25lZCBqZiA9IChpIDwgcG9ydHMuc2l6ZSgpIC0gMSkgPyAwIDog
KHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpOwogICAgQUREKEJQRl9KTVB8QlBGX0pF
UXxCUEZfSywganQsIGpmLCBwb3J0c1tpXSk7CiAgfQoKICBBREQoQlBGX1JFVHxCUEZfSywgMCwg
MCwgMCk7CiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIEFDQ0VQVCk7CiN1bmRlZiBBREQKICBp
ZiAoZi5zaXplKCkgPiA0MDk2KSByZXR1cm4gZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJv
ZzsgcHJvZy5sZW4gPSAodW5zaWduZWQgc2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZb
MF07CiAgcmV0dXJuIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX0FUVEFDSF9GSUxURVJf
T0xELCAmcHJvZywgc2l6ZW9mKHByb2cpKSA9PSAwOwp9CgpzdHJ1Y3QgTW1hcFJpbmcgewogIHZv
aWQgKnJpbmc7CiAgc2l6ZV90IHJpbmdfc2l6ZTsKICB1bnNpZ25lZCBibG9ja19zaXplOwogIHVu
c2lnbmVkIGJsb2NrX25yOwogIHVuc2lnbmVkIGZyYW1lX3NpemU7CiAgdW5zaWduZWQgZnJhbWVf
bnI7CiAgdW5zaWduZWQgZnJhbWVzX3Blcl9ibG9jazsKICB1bnNpZ25lZCBmcmFtZV9pZHg7Cgog
IE1tYXBSaW5nKCkgOiByaW5nKE1BUF9GQUlMRUQpLCByaW5nX3NpemUoMCksIGJsb2NrX3NpemUo
NjU1MzYpLCBibG9ja19ucig2NCksCiAgICAgICAgICAgICAgIGZyYW1lX3NpemUoMjA0OCksIGZy
YW1lX25yKDIwNDgpLCBmcmFtZXNfcGVyX2Jsb2NrKDMyKSwgZnJhbWVfaWR4KDApIHt9Cn07Cgpz
dGF0aWMgYm9vbCB2YWxpZF9yaW5nX2dlb21ldHJ5KGNvbnN0IE1tYXBSaW5nICZtcikgewogIGNv
bnN0IHNpemVfdCBzaXplX21heCA9IChzaXplX3QpLTE7CiAgbG9uZyBwYWdlX3NpemUgPSBzeXNj
b25mKF9TQ19QQUdFU0laRSk7CiAgaWYgKHBhZ2Vfc2l6ZSA8PSAwKSByZXR1cm4gZmFsc2U7CiAg
aWYgKG1yLmJsb2NrX3NpemUgPT0gMCB8fCBtci5ibG9ja19zaXplICUgKHVuc2lnbmVkIGxvbmcp
cGFnZV9zaXplICE9IDApIHJldHVybiBmYWxzZTsKICBpZiAobXIuZnJhbWVfc2l6ZSA8IFRQQUNL
RVQyX0hEUkxFTiB8fAogICAgICBtci5mcmFtZV9zaXplICUgVFBBQ0tFVF9BTElHTk1FTlQgIT0g
MCkgcmV0dXJuIGZhbHNlOwogIGlmIChtci5ibG9ja19zaXplICUgbXIuZnJhbWVfc2l6ZSAhPSAw
KSByZXR1cm4gZmFsc2U7CiAgdW5zaWduZWQgZnJhbWVzX3Blcl9ibG9jayA9IG1yLmJsb2NrX3Np
emUgLyBtci5mcmFtZV9zaXplOwogIGlmIChmcmFtZXNfcGVyX2Jsb2NrID09IDAgfHwgbXIuYmxv
Y2tfbnIgPT0gMCkgcmV0dXJuIGZhbHNlOwogIGlmIChmcmFtZXNfcGVyX2Jsb2NrID4gVUlOVF9N
QVggLyBtci5ibG9ja19ucikgcmV0dXJuIGZhbHNlOwogIGlmIChmcmFtZXNfcGVyX2Jsb2NrICog
bXIuYmxvY2tfbnIgIT0gbXIuZnJhbWVfbnIpIHJldHVybiBmYWxzZTsKICBpZiAoKHNpemVfdClt
ci5ibG9ja19zaXplID4gc2l6ZV9tYXggLyAoc2l6ZV90KW1yLmJsb2NrX25yKSByZXR1cm4gZmFs
c2U7CiAgaWYgKChzaXplX3QpbXIuYmxvY2tfc2l6ZSAqIChzaXplX3QpbXIuYmxvY2tfbnIgIT0g
NFUgKiAxMDI0VSAqIDEwMjRVKSByZXR1cm4gZmFsc2U7CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRp
YyBib29sIHNldHVwX21tYXBfcmluZyhpbnQgZmQsIE1tYXBSaW5nICZtcikgewogIGlmICghdmFs
aWRfcmluZ19nZW9tZXRyeShtcikpIHsKICAgIGxvZ21zZygiaW52YWxpZCBmaXhlZCBUUEFDS0VU
X1YyIHJpbmcgZ2VvbWV0cnkiKTsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgaW50IHZlciA9IFRQ
QUNLRVRfVjI7CiAgaWYgKHNldHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9WRVJTSU9O
LCAmdmVyLCBzaXplb2YodmVyKSkgPCAwKSB7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIHN0cnVj
dCB0cGFja2V0X3JlcSByZXE7CiAgbWVtc2V0KCZyZXEsIDAsIHNpemVvZihyZXEpKTsKICByZXEu
dHBfYmxvY2tfc2l6ZSA9IG1yLmJsb2NrX3NpemU7CiAgcmVxLnRwX2Jsb2NrX25yID0gbXIuYmxv
Y2tfbnI7CiAgcmVxLnRwX2ZyYW1lX3NpemUgPSBtci5mcmFtZV9zaXplOwogIHJlcS50cF9mcmFt
ZV9uciA9IG1yLmZyYW1lX25yOwoKICBpZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tFVCwgUEFD
S0VUX1JYX1JJTkcsICZyZXEsIHNpemVvZihyZXEpKSA8IDApIHsKICAgIHJldHVybiBmYWxzZTsK
ICB9CiAgbXIucmluZ19zaXplID0gKHNpemVfdClyZXEudHBfYmxvY2tfc2l6ZSAqIChzaXplX3Qp
cmVxLnRwX2Jsb2NrX25yOwogIG1yLmZyYW1lc19wZXJfYmxvY2sgPSByZXEudHBfYmxvY2tfc2l6
ZSAvIHJlcS50cF9mcmFtZV9zaXplOwogIG1yLmZyYW1lX2lkeCA9IDA7CgogIG1yLnJpbmcgPSBt
bWFwKE5VTEwsIG1yLnJpbmdfc2l6ZSwgUFJPVF9SRUFEIHwgUFJPVF9XUklURSwgTUFQX1NIQVJF
RCwgZmQsIDApOwogIGlmIChtci5yaW5nID09IE1BUF9GQUlMRUQpIHsKICAgIG1yLnJpbmdfc2l6
ZSA9IDA7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9v
bCByZWxlYXNlX21tYXBfcmluZyhpbnQgZmQsIE1tYXBSaW5nICZtcikgewogIGJvb2wgb2sgPSB0
cnVlOwogIGlmIChtci5yaW5nICE9IE1BUF9GQUlMRUQpIHsKICAgIGlmIChtdW5tYXAobXIucmlu
ZywgbXIucmluZ19zaXplKSAhPSAwKSBvayA9IGZhbHNlOwogICAgbXIucmluZyA9IE1BUF9GQUlM
RUQ7CiAgfQogIHN0cnVjdCB0cGFja2V0X3JlcSBlbXB0eV9yZXE7CiAgbWVtc2V0KCZlbXB0eV9y
ZXEsIDAsIHNpemVvZihlbXB0eV9yZXEpKTsKICBpZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tF
VCwgUEFDS0VUX1JYX1JJTkcsCiAgICAgICAgICAgICAgICAgJmVtcHR5X3JlcSwgc2l6ZW9mKGVt
cHR5X3JlcSkpICE9IDApIG9rID0gZmFsc2U7CiAgbXIucmluZ19zaXplID0gMDsKICByZXR1cm4g
b2s7Cn0KCnN0YXRpYyBib29sIHZhbGlkX3JpbmdfZnJhbWUoY29uc3Qgc3RydWN0IHRwYWNrZXQy
X2hkciAqaGRyLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuc2lnbmVkIGZyYW1lX3Np
emUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90ICpwYWNrZXRfb2Zmc2V0LAog
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCAqcGFja2V0X2xlbmd0aCkgewogIGNv
bnN0IHVuc2lnbmVkIG1hYyA9IGhkci0+dHBfbWFjOwogIGNvbnN0IHVuc2lnbmVkIG5ldCA9IGhk
ci0+dHBfbmV0OwogIGNvbnN0IHVuc2lnbmVkIHNuYXBsZW4gPSBoZHItPnRwX3NuYXBsZW47CiAg
Y29uc3QgdW5zaWduZWQgd2lyZV9sZW4gPSBoZHItPnRwX2xlbjsKICBpZiAobWFjIDwgVFBBQ0tF
VDJfSERSTEVOIHx8IG1hYyA+IGZyYW1lX3NpemUpIHJldHVybiBmYWxzZTsKICBpZiAoc25hcGxl
biA+IHdpcmVfbGVuIHx8IHNuYXBsZW4gPiBmcmFtZV9zaXplIC0gbWFjKSByZXR1cm4gZmFsc2U7
CiAgaWYgKG5ldCA8IG1hYyB8fCBuZXQgPiBtYWMgKyBzbmFwbGVuKSByZXR1cm4gZmFsc2U7CiAg
KnBhY2tldF9vZmZzZXQgPSBtYWM7CiAgKnBhY2tldF9sZW5ndGggPSBzbmFwbGVuOwogIHJldHVy
biB0cnVlOwp9CgpzdGF0aWMgaW50IHJ1bl9yaW5nX2ZpeHR1cmUoKSB7CiAgTW1hcFJpbmcgbXI7
CiAgdWludDhfdCBmcmFtZVsyMDQ4XTsKICBtZW1zZXQoZnJhbWUsIDAsIHNpemVvZihmcmFtZSkp
OwogIHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciA9IChzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJh
bWU7CiAgaGRyLT50cF9tYWMgPSBUUEFDS0VUMl9IRFJMRU47CiAgaGRyLT50cF9uZXQgPSBUUEFD
S0VUMl9IRFJMRU47CiAgaGRyLT50cF9zbmFwbGVuID0gMTI4OwogIGhkci0+dHBfbGVuID0gMTI4
OwogIHNpemVfdCBvZmYgPSAwLCBsZW4gPSAwOwogIGlmICghdmFsaWRfcmluZ19mcmFtZShoZHIs
IHNpemVvZihmcmFtZSksICZvZmYsICZsZW4pIHx8CiAgICAgIG9mZiAhPSBUUEFDS0VUMl9IRFJM
RU4gfHwgbGVuICE9IDEyOCkgcmV0dXJuIDIxOwogIGhkci0+dHBfbWFjID0gVFBBQ0tFVDJfSERS
TEVOIC0gMTsKICBpZiAodmFsaWRfcmluZ19mcmFtZShoZHIsIHNpemVvZihmcmFtZSksICZvZmYs
ICZsZW4pKSByZXR1cm4gMjI7CiAgaGRyLT50cF9tYWMgPSBUUEFDS0VUMl9IRFJMRU47CiAgaGRy
LT50cF9zbmFwbGVuID0gc2l6ZW9mKGZyYW1lKTsKICBoZHItPnRwX2xlbiA9IHNpemVvZihmcmFt
ZSk7CiAgaWYgKHZhbGlkX3JpbmdfZnJhbWUoaGRyLCBzaXplb2YoZnJhbWUpLCAmb2ZmLCAmbGVu
KSkgcmV0dXJuIDIzOwogIGhkci0+dHBfc25hcGxlbiA9IDEyOTsKICBoZHItPnRwX2xlbiA9IDEy
ODsKICBpZiAodmFsaWRfcmluZ19mcmFtZShoZHIsIHNpemVvZihmcmFtZSksICZvZmYsICZsZW4p
KSByZXR1cm4gMjQ7CiAgaGRyLT50cF9zbmFwbGVuID0gMTI4OwogIGhkci0+dHBfbGVuID0gMTI4
OwogIGhkci0+dHBfbmV0ID0gVFBBQ0tFVDJfSERSTEVOIC0gMTsKICBpZiAodmFsaWRfcmluZ19m
cmFtZShoZHIsIHNpemVvZihmcmFtZSksICZvZmYsICZsZW4pKSByZXR1cm4gMjU7CiAgbXIuZnJh
bWVfbnIrKzsKICBpZiAodmFsaWRfcmluZ19nZW9tZXRyeShtcikpIHJldHVybiAyNjsKICByZXR1
cm4gMDsKfQoKc3RhdGljIGludCBydW5fZml4dHVyZSgpIHsKICBzdGQ6OnN0cmluZyByZXEgPSAi
R0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJcbkhvc3Q6IGFwaS5sb2NhbFxyXG5BdXRob3Jp
emF0aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYwXHJcblRyYWNlcGFyZW50OiAwMC0wMTIzNDU2
Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIzNDU2Nzg5YWJjZGVmLTAxXHJcblxyXG4iOwog
IEV2ZW50IGU7IFJlcXVlc3RNZXRhIG1ldGE7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAi
Y3BwLW5vZGUiOyBlLnNlcnZpY2UgPSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjki
OyBlLmNhbGxlcl9wb3J0ID0gNTEwMDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9y
dCA9IDgwODA7IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVl
c3QocmVxLmRhdGEoKSwgcmVxLnNpemUoKSAtIDQsICZlLCAmbWV0YSk7IGUuc3RhdHVzID0gMjAw
OyBlLmhhc19zdGF0dXMgPSB0cnVlOyBlLmR1cmF0aW9uX21zID0gMzsgZS5oYXNfZHVyYXRpb24g
PSB0cnVlOyBlLnJlc3BfYnl0ZXMgPSA0MjsgZS5oYXNfcmVzcCA9IHRydWU7IGVtaXRfZXZlbnQo
ZSk7IHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1bl93c3NlX2ZpeHR1cmUoKSB7CiAgY29uc3Qg
Y2hhciAqbmFtZXNwYWNlc1tdID0gewogICAgImh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dz
cy8yMDA0LzAxL29hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS1zZWNleHQtMS4wLnhzZCIsCiAg
ICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwMi8wNy9zZWNleHQiLAogICAgImh0
dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMTIvc2VjZXh0IiwKICAgICJodHRwOi8v
c2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAzLzA2L3NlY2V4dCIKICB9OwogIGZvciAoc2l6ZV90
IGkgPSAwOyBpIDwgNDsgKytpKSB7CiAgICBzdGQ6OnN0cmluZyBib2R5ID0gIjxzOkVudmVsb3Bl
IHhtbG5zOnM9J3Vybjpzb2FwJyB4bWxuczp3PSciICsgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1tp
XSkgKwogICAgICAiJz48czpIZWFkZXI+PHc6VXNlcm5hbWVUb2tlbj48dzpVc2VybmFtZT5uYXRp
dmUuZml4dHVyZTwvdzpVc2VybmFtZT4iCiAgICAgICI8dzpQYXNzd29yZD5TRU5TSVRJVkVfUEFT
U1dPUkQ8L3c6UGFzc3dvcmQ+PC93OlVzZXJuYW1lVG9rZW4+PC9zOkhlYWRlcj4iOwogICAgc3Rk
OjpzdHJpbmcgdXNlciA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShib2R5KTsKICAgIGlmICh1c2Vy
ICE9ICJuYXRpdmUuZml4dHVyZSIpIHJldHVybiAzOwogICAgc3RkOjpjb3V0IDw8IHVzZXIgPDwg
IlxuIjsKICB9CiAgc3RkOjpzdHJpbmcgbWFsaWNpb3VzID0gIjwhRE9DVFlQRSB4IFs8IUVOVElU
WSBwdyAnc2VjcmV0Jz5dPjx3OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0nIiArCiAgICBzdGQ6OnN0
cmluZyhuYW1lc3BhY2VzWzBdKSArICInPjx3OlVzZXJuYW1lPiZwdzs8L3c6VXNlcm5hbWU+PC93
OlVzZXJuYW1lVG9rZW4+IjsKICBpZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZShtYWxpY2lvdXMp
LmVtcHR5KCkpIHJldHVybiA0OwogIHN0ZDo6c3RyaW5nIHdyb25nX25zID0gIjx3OlVzZXJuYW1l
VG9rZW4geG1sbnM6dz0ndXJuOm5vdC13c3NlJz48dzpVc2VybmFtZT53cm9uZzwvdzpVc2VybmFt
ZT48L3c6VXNlcm5hbWVUb2tlbj4iOwogIGlmICghZXh0cmFjdF93c3NlX3VzZXJuYW1lKHdyb25n
X25zKS5lbXB0eSgpKSByZXR1cm4gNTsKICBzdGQ6OnN0cmluZyB1bm5hbWVzcGFjZWQgPSAiPFVz
ZXJuYW1lVG9rZW4+PFVzZXJuYW1lPndyb25nPC9Vc2VybmFtZT48L1VzZXJuYW1lVG9rZW4+IjsK
ICBpZiAoIWV4dHJhY3Rfd3NzZV91c2VybmFtZSh1bm5hbWVzcGFjZWQpLmVtcHR5KCkpIHJldHVy
biA2OwogIHN0ZDo6c3RyaW5nIGVzY2FwZWQgPSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSci
ICsgc3RkOjpzdHJpbmcobmFtZXNwYWNlc1swXSkgKwogICAgIic+PHc6VXNlcm5hbWU+bmF0aXZl
JmFtcDtmaXh0dXJlPC93OlVzZXJuYW1lPiI7CiAgaWYgKGV4dHJhY3Rfd3NzZV91c2VybmFtZShl
c2NhcGVkKSAhPSAibmF0aXZlJmZpeHR1cmUiKSByZXR1cm4gNzsKICBzdGQ6OnN0cmluZyB0b29f
bG9uZyA9ICI8dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9JyIgKyBzdGQ6OnN0cmluZyhuYW1lc3Bh
Y2VzWzBdKSArCiAgICAiJz48dzpVc2VybmFtZT4iICsgc3RkOjpzdHJpbmcoTUFYX1dTU0VfVVNF
Uk5BTUUgKyAxLCAneCcpICsgIjwvdzpVc2VybmFtZT4iOwogIGlmICghZXh0cmFjdF93c3NlX3Vz
ZXJuYW1lKHRvb19sb25nKS5lbXB0eSgpKSByZXR1cm4gODsKICByZXR1cm4gMDsKfQoKc3RhdGlj
IGludCBydW5fZHVhbF9hdXRoX2ZpeHR1cmUoKSB7CiAgY29uc3Qgc3RkOjpzdHJpbmcgYm9keSA9
CiAgICAiPHM6RW52ZWxvcGUgeG1sbnM6cz0ndXJuOnNvYXAnIHhtbG5zOnc9J2h0dHA6Ly9kb2Nz
Lm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxLyIKICAgICJvYXNpcy0yMDA0MDEtd3NzLXdzc2Vj
dXJpdHktc2VjZXh0LTEuMC54c2QnPjxzOkhlYWRlcj48dzpVc2VybmFtZVRva2VuPiIKICAgICI8
dzpVc2VybmFtZT5zb2FwLnVzZXI8L3c6VXNlcm5hbWU+PHc6UGFzc3dvcmQ+U0VOU0lUSVZFX1BB
U1NXT1JEPC93OlBhc3N3b3JkPiIKICAgICI8L3c6VXNlcm5hbWVUb2tlbj48L3M6SGVhZGVyPjwv
czpFbnZlbG9wZT4iOwogIHN0ZDo6b3N0cmluZ3N0cmVhbSByZXF1ZXN0OwogIHJlcXVlc3QgPDwg
IlBPU1QgL3NvYXAgSFRUUC8xLjFcclxuSG9zdDogZml4dHVyZVxyXG4iCiAgICAgICAgICA8PCAi
QXV0aG9yaXphdGlvbjogQmFzaWMgWW1GemFXTXVkWE5sY2pwd1lYTnpkMjl5WkE9PVxyXG4iCiAg
ICAgICAgICA8PCAiQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9zb2FwK3htbFxyXG5Db250ZW50
LUxlbmd0aDogIgogICAgICAgICAgPDwgYm9keS5zaXplKCkgPDwgIlxyXG5cclxuIiA8PCBib2R5
OwogIGNvbnN0IHN0ZDo6c3RyaW5nIHBheWxvYWQgPSByZXF1ZXN0LnN0cigpOwoKICBzdGQ6OnZl
Y3Rvcjx1bnNpZ25lZCBjaGFyPiBwYWNrZXQoMTQgKyAyMCArIDIwICsgcGF5bG9hZC5zaXplKCks
IDApOwogIHBhY2tldFsxMl0gPSAweDA4OyBwYWNrZXRbMTNdID0gMHgwMDsKICBwYWNrZXRbMTRd
ID0gMHg0NTsgcGFja2V0WzIzXSA9IElQUFJPVE9fVENQOwogIHVpbnQxNl90IHRvdF9sZW4gPSAo
dWludDE2X3QpKDIwICsgMjAgKyBwYXlsb2FkLnNpemUoKSk7CiAgcGFja2V0WzE2XSA9ICh1bnNp
Z25lZCBjaGFyKSh0b3RfbGVuID4+IDgpOyBwYWNrZXRbMTddID0gKHVuc2lnbmVkIGNoYXIpKHRv
dF9sZW4gJiAweGZmKTsKICBwYWNrZXRbMjZdID0gMTkyOyBwYWNrZXRbMjddID0gMDsgcGFja2V0
WzI4XSA9IDI7IHBhY2tldFsyOV0gPSAyOwogIHBhY2tldFszMF0gPSAxOTI7IHBhY2tldFszMV0g
PSAwOyBwYWNrZXRbMzJdID0gMjsgcGFja2V0WzMzXSA9IDE7CiAgdW5zaWduZWQgc2hvcnQgc3Bv
cnQgPSBodG9ucyg1MTAwMCksIGRwb3J0ID0gaHRvbnMoODA4MCk7CiAgbWVtY3B5KCZwYWNrZXRb
MzRdLCAmc3BvcnQsIHNpemVvZihzcG9ydCkpOwogIG1lbWNweSgmcGFja2V0WzM2XSwgJmRwb3J0
LCBzaXplb2YoZHBvcnQpKTsKICBwYWNrZXRbNDZdID0gNVUgPDwgNDsgcGFja2V0WzQ3XSA9IDB4
MTk7CiAgbWVtY3B5KCZwYWNrZXRbNTRdLCBwYXlsb2FkLmRhdGEoKSwgcGF5bG9hZC5zaXplKCkp
OwoKICBnX3dzc2VfYm9keV9ieXRlcyA9IDgxOTI7CiAgbWVtc2V0KGdfbW9uaXRvcmVkX3BvcnRz
LCAwLCBzaXplb2YoZ19tb25pdG9yZWRfcG9ydHMpKTsKICBnX21vbml0b3JlZF9wb3J0c1s4MDgw
XSA9IHRydWU7CiAgZ19lbmRwb2ludC5jbGVhcigpOwogIGluaXRfcm5nKCk7CiAgc3RkOjp2ZWN0
b3I8dW5zaWduZWQ+IHBvcnRzKDEsIDgwODApOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+IGZs
b3dzOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiBwZW5kaW5n
OwogIGlmICghaGFuZGxlX3BhY2tldCgmcGFja2V0WzBdLCBwYWNrZXQuc2l6ZSgpLCAiY3BwLWR1
YWwtZml4dHVyZSIsCiAgICAgICAgICAgICAgICAgICAgIHBvcnRzLCBmbG93cywgcGVuZGluZykp
IHJldHVybiA5OwogIGlmICghZmxvd3MuZW1wdHkoKSB8fCBwZW5kaW5nLnNpemUoKSAhPSAxKSBy
ZXR1cm4gMTA7CiAgZmx1c2hfYWxsX3BlbmRpbmcocGVuZGluZyk7CiAgcmV0dXJuIDA7Cn0KCnN0
YXRpYyBpbnQgcnVuX3NoaXBfcmF0ZV9maXh0dXJlKCkgewogIHN0ZDo6dmVjdG9yPHN0ZDo6c3Ry
aW5nPiBldmVudHM7CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyg0MDAwMCwgJ3gnKSk7
CiAgZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyg0MDAwMCwgJ3knKSk7CiAgaWYgKGJvdW5k
ZWRfYmF0Y2hfY291bnQoZXZlbnRzLCAiZml4dHVyZSIpICE9IDEpIHJldHVybiAzMDsKICBldmVu
dHMuY2xlYXIoKTsKICBldmVudHMucHVzaF9iYWNrKHN0ZDo6c3RyaW5nKE1BWF9QT1NUX0JZVEVT
ICsgMSwgJ3gnKSk7CiAgaWYgKGJvdW5kZWRfYmF0Y2hfY291bnQoZXZlbnRzLCAiZml4dHVyZSIp
ICE9IDApIHJldHVybiAzMTsKICByZXR1cm4gMDsKfQoKc3RhdGljIGludCBydW5fc3RhdHNfZml4
dHVyZSgpIHsKICBnX3NoaXBfbm9kZSA9ICJmaXh0dXJlLW5vZGUiOwogIGdfaW5zdGFuY2VfaWQg
PSAiZml4dHVyZS0xIjsKICBnX3N0YXRzX2xhc3RfYXQgPSB3YWxsX3NlY29uZHMoKSAtIDMwLjA7
CiAgZ19jYXB0dXJlX3BhY2tldHMgPSAxMDA7CiAgZ19jYXB0dXJlX2J5dGVzID0gNjQwMDsKICBn
X2V2ZW50c19lbWl0dGVkID0gZ19ldmVudHNfaW4gPSAxMDsKICBnX2V2ZW50c19wdXNoZWQgPSA4
OwogIGdfZXZlbnRzX2Ryb3BwZWQgPSBnX2Ryb3BfcXVldWUgPSAyOwogIHN0ZDo6c3RyaW5nIGJv
ZHkgPSBhZ2VudF9zdGF0c19ib2R5KC0xLCAzLCAyLCAxKTsKICBpZiAoYm9keS5zaXplKCkgPiBN
QVhfU1RBVFNfQllURVMpIHJldHVybiA0MDsKICBpZiAoYm9keS5maW5kKCJcInR5cGVcIjpcImFn
ZW50X3N0YXRzXCIiKSA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0dXJuIDQxOwogIGlmIChib2R5
LmZpbmQoIlwiZHJvcF9wZXJjZW50XCI6MjAuMDAwMCIpID09IHN0ZDo6c3RyaW5nOjpucG9zKSBy
ZXR1cm4gNDI7CiAgaWYgKGJvZHkuZmluZCgiXCJtb2RlXCI6XCJjcHBcIiIpID09IHN0ZDo6c3Ry
aW5nOjpucG9zKSByZXR1cm4gNDM7CiAgc3RkOjpjb3V0IDw8IGJvZHkgPDwgIlxuIjsKICByZXR1
cm4gMDsKfQoKc3RhdGljIGJvb2wgcGFyc2Vfd3NzZV9zaXplKGNvbnN0IGNoYXIgKnZhbHVlLCBz
aXplX3QgKnJlc3VsdCkgewogIGlmICghdmFsdWUgfHwgISp2YWx1ZSkgcmV0dXJuIGZhbHNlOwog
IHNpemVfdCBuID0gMDsKICBpZiAoIXBhcnNlX2RlY2ltYWxfc2l6ZSh2YWx1ZSwgc3RybGVuKHZh
bHVlKSwgJm4pIHx8IG4gPiBNQVhfV1NTRV9CT0RZX0JZVEVTKSByZXR1cm4gZmFsc2U7CiAgKnJl
c3VsdCA9IG47CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIGRyb3BfYWxsX2NhcGFiaWxp
dGllcygpIHsKICBzdHJ1Y3QgX191c2VyX2NhcF9oZWFkZXJfc3RydWN0IGhlYWRlcjsKICBzdHJ1
Y3QgX191c2VyX2NhcF9kYXRhX3N0cnVjdCBkYXRhWzJdOwogIG1lbXNldCgmaGVhZGVyLCAwLCBz
aXplb2YoaGVhZGVyKSk7CiAgbWVtc2V0KGRhdGEsIDAsIHNpemVvZihkYXRhKSk7CiAgaGVhZGVy
LnZlcnNpb24gPSBfTElOVVhfQ0FQQUJJTElUWV9WRVJTSU9OXzM7CiAgaGVhZGVyLnBpZCA9IDA7
CiAgcmV0dXJuIHN5c2NhbGwoU1lTX2NhcHNldCwgJmhlYWRlciwgZGF0YSkgPT0gMDsKfQoKc3Rh
dGljIGludCBvcGVuX2NhcHR1cmVfc29ja2V0KGNvbnN0IHN0ZDo6c3RyaW5nICZpZmFjZSwKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiAm
cG9ydHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBNbWFwUmluZyAmcmluZykgewog
IGludCBmZCA9IHNvY2tldChBRl9QQUNLRVQsIFNPQ0tfUkFXLCBodG9ucyhFVEhfUF9BTEwpKTsK
ICBpZiAoZmQgPCAwKSB7IHBlcnJvcigiQUZfUEFDS0VUIik7IHJldHVybiAtMTsgfQogIGZjbnRs
KGZkLCBGX1NFVEZELCBGRF9DTE9FWEVDKTsKICBpbnQgcmIgPSA4ICogMTAyNCAqIDEwMjQ7CiAg
c2V0c29ja29wdChmZCwgU09MX1NPQ0tFVCwgU09fUkNWQlVGLCAmcmIsIHNpemVvZihyYikpOwog
IGlmICghYXR0YWNoX2JwZihmZCwgcG9ydHMpKSB7CiAgICBsb2dtc2coIkJQRiBhdHRhY2ggZmFp
bGVkOyByZWZ1c2luZyB1bmZpbHRlcmVkIGNhcHR1cmUiKTsKICAgIGNsb3NlKGZkKTsKICAgIHJl
dHVybiAtMTsKICB9CgogIHN0cnVjdCBzb2NrYWRkcl9sbCBzYTsKICBtZW1zZXQoJnNhLCAwLCBz
aXplb2Yoc2EpKTsKICBzYS5zbGxfZmFtaWx5ID0gQUZfUEFDS0VUOwogIHNhLnNsbF9wcm90b2Nv
bCA9IGh0b25zKEVUSF9QX0FMTCk7CiAgaWYgKCFpZmFjZS5lbXB0eSgpKSB7CiAgICBzYS5zbGxf
aWZpbmRleCA9IChpbnQpaWZfbmFtZXRvaW5kZXgoaWZhY2UuY19zdHIoKSk7CiAgICBpZiAoIXNh
LnNsbF9pZmluZGV4KSB7CiAgICAgIGxvZ21zZygiYmFkIGludGVyZmFjZSIpOwogICAgICBjbG9z
ZShmZCk7CiAgICAgIHJldHVybiAtMTsKICAgIH0KICB9CiAgaWYgKGJpbmQoZmQsIChzdHJ1Y3Qg
c29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkpIDwgMCkgewogICAgcGVycm9yKCJiaW5kIik7CiAg
ICBjbG9zZShmZCk7CiAgICByZXR1cm4gLTE7CiAgfQogIGlmICghc2V0dXBfbW1hcF9yaW5nKGZk
LCByaW5nKSkgewogICAgbG9nbXNnKCJUUEFDS0VUX1YyIHNldHVwIGZhaWxlZDsgcmVmdXNpbmcg
bm9uLXJpbmcgZmFsbGJhY2siKTsKICAgIGNsb3NlKGZkKTsKICAgIHJldHVybiAtMTsKICB9CiAg
aWYgKCFkcm9wX2FsbF9jYXBhYmlsaXRpZXMoKSkgewogICAgbG9nbXNnKCJjYXBhYmlsaXR5IGRy
b3AgZmFpbGVkOyByZWZ1c2luZyB1bnNhZmUgY2FwdHVyZSIpOwogICAgcmVsZWFzZV9tbWFwX3Jp
bmcoZmQsIHJpbmcpOwogICAgY2xvc2UoZmQpOwogICAgcmV0dXJuIC0xOwogIH0KICByZXR1cm4g
ZmQ7Cn0KCnN0YXRpYyBpbnQgcnVuX2NhcGFiaWxpdHlfcHJvYmUoY29uc3Qgc3RkOjpzdHJpbmcg
JmlmYWNlLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6dmVjdG9y
PHVuc2lnbmVkPiAmcG9ydHMpIHsKICBNbWFwUmluZyByaW5nOwogIGludCBmZCA9IG9wZW5fY2Fw
dHVyZV9zb2NrZXQoaWZhY2UsIHBvcnRzLCByaW5nKTsKICBpZiAoZmQgPCAwKSByZXR1cm4gMjsK
CiAgYm9vbCByZWxlYXNlZCA9IHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5nKTsKICBjbG9zZShm
ZCk7CiAgaWYgKCFyZWxlYXNlZCkgewogICAgbG9nbXNnKCJUUEFDS0VUX1YyIHByb2JlIGNsZWFu
dXAgZmFpbGVkIik7CiAgICByZXR1cm4gMjsKICB9CiAgcmV0dXJuIDA7Cn0KCmludCBtYWluKGlu
dCBhcmdjLCBjaGFyICoqYXJndikgewogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0s
ICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFz
dHJjbXAoYXJndlsxXSwgIi0td3NzZS1maXh0dXJlIikpIHJldHVybiBydW5fd3NzZV9maXh0dXJl
KCk7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0tZHVhbC1hdXRoLWZpeHR1
cmUiKSkgcmV0dXJuIHJ1bl9kdWFsX2F1dGhfZml4dHVyZSgpOwogIGlmIChhcmdjID4gMSAmJiAh
c3RyY21wKGFyZ3ZbMV0sICItLXJpbmctZml4dHVyZSIpKSByZXR1cm4gcnVuX3JpbmdfZml4dHVy
ZSgpOwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLXNoaXAtcmF0ZS1maXh0
dXJlIikpIHJldHVybiBydW5fc2hpcF9yYXRlX2ZpeHR1cmUoKTsKICBpZiAoYXJnYyA+IDEgJiYg
IXN0cmNtcChhcmd2WzFdLCAiLS1zdGF0cy1maXh0dXJlIikpIHJldHVybiBydW5fc3RhdHNfZml4
dHVyZSgpOwogIHN0ZDo6c3RyaW5nIGlmYWNlOyBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gcG9ydHM7
IGludCBpOyBpbnQgd29ya2VycyA9IDE7CiAgc3RkOjpzdHJpbmcgZW5kcG9pbnQ7CiAgYm9vbCBj
YXBhYmlsaXR5X3Byb2JlID0gZmFsc2U7CiAgY29uc3QgY2hhciAqd3NzZV9lbnYgPSBnZXRlbnYo
Ik5UX1dTU0VfQk9EWV9CWVRFUyIpOwogIGlmICh3c3NlX2VudiAmJiAhcGFyc2Vfd3NzZV9zaXpl
KHdzc2VfZW52LCAmZ193c3NlX2JvZHlfYnl0ZXMpKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgIndz
c2UgYm9keSBieXRlcyBtdXN0IGJlIGluIHJhbmdlIDAuLjY1NTM2XG4iKTsgcmV0dXJuIDI7CiAg
fQogIGNvbnN0IGNoYXIgKnJhdGVfZW52ID0gZ2V0ZW52KCJOVF9TSElQX1JBVEVfS0JQUyIpOwog
IGlmIChyYXRlX2VudiAmJiAqcmF0ZV9lbnYpIGdfc2hpcF9yYXRlX2ticHMgPSAodW5zaWduZWQp
YXRvaShyYXRlX2Vudik7CiAgY29uc3QgY2hhciAqc3RhdHNfZW52ID0gZ2V0ZW52KCJOVF9TVEFU
U19JTlRFUlZBTF9TRUMiKTsKICBpZiAoc3RhdHNfZW52ICYmICpzdGF0c19lbnYpIGdfc3RhdHNf
aW50ZXJ2YWxfc2VjID0gKHVuc2lnbmVkKWF0b2koc3RhdHNfZW52KTsKICBjb25zdCBjaGFyICp0
dGxfZW52ID0gZ2V0ZW52KCJOVF9QRU5ESU5HX1RUTF9TRUMiKTsKICBpZiAodHRsX2VudiAmJiAq
dHRsX2VudikgZ19wZW5kaW5nX3R0bF9zZWMgPSAodW5zaWduZWQpYXRvaSh0dGxfZW52KTsKCiAg
Zm9yIChpID0gMTsgaSA8IGFyZ2M7ICsraSkgewogICAgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1p
IikgJiYgaSArIDEgPCBhcmdjKSBpZmFjZSA9IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJj
bXAoYXJndltpXSwgIi1wIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIHdoaWxlIChpICsgMSA8
IGFyZ2MgJiYgYXJndltpICsgMV1bMF0gIT0gJy0nKSB7CiAgICAgICAgY2hhciAqcSA9IHN0cnRv
ayhhcmd2WysraV0sICIsICIpOwogICAgICAgIHdoaWxlIChxKSB7IGxvbmcgcCA9IGF0b2wocSk7
IGlmICh2YWxpZF9wb3J0KCh1bnNpZ25lZClwKSkgcG9ydHMucHVzaF9iYWNrKCh1bnNpZ25lZClw
KTsgcSA9IHN0cnRvayhOVUxMLCAiLCAiKTsgfQogICAgICB9CiAgICB9CiAgICBlbHNlIGlmICgh
c3RyY21wKGFyZ3ZbaV0sICItLWVuZHBvaW50IikgJiYgaSArIDEgPCBhcmdjKSBlbmRwb2ludCA9
IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tc2hpcC1yYXRlLWti
cHMiKSAmJiBpICsgMSA8IGFyZ2MpIGdfc2hpcF9yYXRlX2ticHMgPSAodW5zaWduZWQpYXRvaShh
cmd2WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1zdGF0cy1pbnRlcnZh
bC1zZWMiKSAmJiBpICsgMSA8IGFyZ2MpIGdfc3RhdHNfaW50ZXJ2YWxfc2VjID0gKHVuc2lnbmVk
KWF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tcGVuZGlu
Zy10dGwtc2VjIikgJiYgaSArIDEgPCBhcmdjKSBnX3BlbmRpbmdfdHRsX3NlYyA9ICh1bnNpZ25l
ZClhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItLWNhcGFi
aWxpdHktcHJvYmUiKSkgY2FwYWJpbGl0eV9wcm9iZSA9IHRydWU7CiAgICBlbHNlIGlmICghc3Ry
Y21wKGFyZ3ZbaV0sICItLXNwb29sIikgJiYgaSArIDEgPCBhcmdjKSArK2k7CiAgICBlbHNlIGlm
ICghc3RyY21wKGFyZ3ZbaV0sICItaiIpICYmIGkgKyAxIDwgYXJnYykgd29ya2VycyA9IGF0b2ko
YXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0td3NzZS1ib2R5LWJ5
dGVzIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIGlmICghcGFyc2Vfd3NzZV9zaXplKGFyZ3Zb
KytpXSwgJmdfd3NzZV9ib2R5X2J5dGVzKSkgewogICAgICAgIGZwcmludGYoc3RkZXJyLCAid3Nz
ZSBib2R5IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4uNjU1MzZcbiIpOyByZXR1cm4gMjsKICAg
ICAgfQogICAgfQogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWgiKSB8fCAhc3RyY21w
KGFyZ3ZbaV0sICItLWhlbHAiKSkgewogICAgICBmcHJpbnRmKHN0ZGVyciwgInVzYWdlOiBudC1z
bmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAgcG9ydHNdIFstLWVuZHBvaW50IFVSTF0gWy0tc2hpcC1y
YXRlLWticHMgNjQuLjEwMDAwXSBbLS1zdGF0cy1pbnRlcnZhbC1zZWMgMTAuLjMwMF0gWy0tcGVu
ZGluZy10dGwtc2VjIDEuLjMwMF0gWy1qIHdvcmtlcnNdIFstLXdzc2UtYm9keS1ieXRlcyAwLi42
NTUzNl1cbiIpOwogICAgICByZXR1cm4gMDsKICAgIH0KICAgIGVsc2UgeyBmcHJpbnRmKHN0ZGVy
ciwgInVua25vd24gb3IgaW5jb21wbGV0ZSBhcmd1bWVudDogJXNcbiIsIGFyZ3ZbaV0pOyByZXR1
cm4gMjsgfQogIH0KICBpZiAocG9ydHMuZW1wdHkoKSkgeyBwb3J0cy5wdXNoX2JhY2soODApOyBw
b3J0cy5wdXNoX2JhY2soODAwMyk7IHBvcnRzLnB1c2hfYmFjayg4MDA1KTsgcG9ydHMucHVzaF9i
YWNrKDgwMDcpOyBwb3J0cy5wdXNoX2JhY2soODAwOSk7IHBvcnRzLnB1c2hfYmFjayg4MDEwKTsg
cG9ydHMucHVzaF9iYWNrKDgwMTEpOyB9CiAgaWYgKGdfc2hpcF9yYXRlX2ticHMgPCA2NCB8fCBn
X3NoaXBfcmF0ZV9rYnBzID4gMTAwMDApIHsKICAgIGZwcmludGYoc3RkZXJyLCAic2hpcCByYXRl
IG11c3QgYmUgaW4gcmFuZ2UgNjQuLjEwMDAwIGtiaXQvc1xuIik7CiAgICByZXR1cm4gMjsKICB9
CiAgaWYgKGdfc3RhdHNfaW50ZXJ2YWxfc2VjIDwgMTAgfHwgZ19zdGF0c19pbnRlcnZhbF9zZWMg
PiAzMDApIHsKICAgIGZwcmludGYoc3RkZXJyLCAic3RhdHMgaW50ZXJ2YWwgbXVzdCBiZSBpbiBy
YW5nZSAxMC4uMzAwIHNlY29uZHNcbiIpOwogICAgcmV0dXJuIDI7CiAgfQogIGlmIChnX3BlbmRp
bmdfdHRsX3NlYyA8IDEgfHwgZ19wZW5kaW5nX3R0bF9zZWMgPiAzMDApIHsKICAgIGZwcmludGYo
c3RkZXJyLCAicGVuZGluZyB0dGwgbXVzdCBiZSBpbiByYW5nZSAxLi4zMDAgc2Vjb25kc1xuIik7
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
ZCA8IDApIHJldHVybiAyOwoKICBzaWduYWwoU0lHUElQRSwgU0lHX0lHTik7CgogIGlmIChnX2Vu
ZHBvaW50LmVtcHR5KCkpIHsKICAgIGludCBvdXRwdXRfZmxhZ3MgPSBmY250bChTVERPVVRfRklM
RU5PLCBGX0dFVEZMLCAwKTsKICAgIGlmIChvdXRwdXRfZmxhZ3MgPCAwIHx8CiAgICAgICAgZmNu
dGwoU1RET1VUX0ZJTEVOTywgRl9TRVRGTCwgb3V0cHV0X2ZsYWdzIHwgT19OT05CTE9DSykgPCAw
KSB7CiAgICAgIGxvZ21zZygiY2Fubm90IG1ha2Ugc2hpcHBlciBwaXBlIG5vbi1ibG9ja2luZzsg
cmVmdXNpbmcgdW5zYWZlIHBpcGVsaW5lIik7CiAgICAgIHJlbGVhc2VfbW1hcF9yaW5nKGZkLCBy
aW5nKTsKICAgICAgY2xvc2UoZmQpOwogICAgICByZXR1cm4gMjsKICAgIH0KICB9IGVsc2Ugewog
ICAgZ19zaGlwX3dvcmtlcl9hY3RpdmUgPSB0cnVlOwogICAgaWYgKHB0aHJlYWRfY3JlYXRlKCZn
X3NoaXBfd29ya2VyX3RpZCwgTlVMTCwgc2hpcF93b3JrZXJfdGhyZWFkLCBOVUxMKSAhPSAwKSB7
CiAgICAgIGxvZ21zZygiZmFpbGVkIHRvIHNwYXduIHNoaXBwaW5nIHdvcmtlciB0aHJlYWQiKTsK
ICAgICAgcmVsZWFzZV9tbWFwX3JpbmcoZmQsIHJpbmcpOwogICAgICBjbG9zZShmZCk7CiAgICAg
IHJldHVybiAyOwogICAgfQogIH0KCiAgc2lnbmFsKFNJR1RFUk0sIHN0b3Bfc2lnbmFsKTsKICBz
aWduYWwoU0lHSU5ULCBzdG9wX3NpZ25hbCk7CiAgc2V0dmJ1ZihzdGRvdXQsIE5VTEwsIF9JT0xC
RiwgNjU1MzYpOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+IGZsb3dzOwogIHN0ZDo6bWFwPFBh
Y2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiBwZW5kaW5nOwoKICBsb2dtc2coIlBBQ0tF
VF9NTUFQIChUUEFDS0VUX1YyKSBzdHJpY3QgUlggcmluZyBlbmFibGVkICg0TUIsIDIwNDggZnJh
bWVzKSIpOwogIGlmIChnX3dzc2VfYm9keV9ieXRlcykgewogICAgbG9nbXNnKCJXU1NFIFVzZXJu
YW1lVG9rZW4gaW5zcGVjdGlvbiBlbmFibGVkIChib3VuZGVkIHRvICIgKyBudW1iZXJfc3RyaW5n
KGdfd3NzZV9ib2R5X2J5dGVzKSArICIgYnl0ZXMvcmVxdWVzdCkiKTsKICB9CiAgaWYgKCFnX2Vu
ZHBvaW50LmVtcHR5KCkpIHsKICAgIGxvZ21zZygic2luZ2xlLWJpbmFyeSBtb2RlOiBub24tYmxv
Y2tpbmcgdGhyZWFkIHNoaXBwaW5nIGRpcmVjdGx5IHRvICIgKyBnX2VuZHBvaW50ICsgIiAoMCBk
aXNrIEkvTykiKTsKICB9IGVsc2UgewogICAgbG9nbXNnKCJub24tYmxvY2tpbmcgbmF0aXZlIHBp
cGVsaW5lIG1vZGUgZW5hYmxlZDsgV0FOIEkvTyBpc29sYXRlZCBpbiBudC1zaGlwLWNwcCIpOwog
IH0KICBsb2dtc2coImxpc3RlbmluZyIpOwoKICB0aW1lX3QgbGFzdCA9IHRpbWUoTlVMTCk7CiAg
Ym9vbCByaW5nX2ludGVncml0eV9mYWlsdXJlID0gZmFsc2U7CgogIHN0cnVjdCBwb2xsZmQgcGZk
OwogIHBmZC5mZCA9IGZkOwogIHBmZC5ldmVudHMgPSBQT0xMSU4gfCBQT0xMRVJSIHwgUE9MTEhV
UCB8IFBPTExOVkFMOwogIHBmZC5yZXZlbnRzID0gMDsKCiAgd2hpbGUgKGdfcnVubmluZykgewog
ICAgaW50IHJjID0gcG9sbCgmcGZkLCAxLCAxMDAwKTsKICAgIGlmIChyYyA8IDAgJiYgZXJybm8g
PT0gRUlOVFIpIHsKICAgICAgLy8gU2lnbmFsIGhhbmRsZWQKICAgIH0gZWxzZSBpZiAocmMgPCAw
KSB7CiAgICAgIGxvZ21zZygicG9sbCBlcnJvciBlbmNvdW50ZXJlZCIpOwogICAgICBnX3J1bm5p
bmcgPSAwOwogICAgICBicmVhazsKICAgIH0gZWxzZSBpZiAocmMgPiAwICYmIChwZmQucmV2ZW50
cyAmIChQT0xMRVJSIHwgUE9MTE5WQUwpKSkgewogICAgICBsb2dtc2coInBvbGwgZXJyb3IgcmV2
ZW50cyBkZXRlY3RlZCIpOwogICAgICBnX3J1bm5pbmcgPSAwOwogICAgICBicmVhazsKICAgIH0g
ZWxzZSBpZiAocmMgPiAwKSB7CiAgICAgIHNpemVfdCBkcmFpbl9jb3VudCA9IDA7CiAgICAgIHdo
aWxlIChnX3J1bm5pbmcgJiYgZHJhaW5fY291bnQgPCBNQVhfRFJBSU5fUEVSX1BBU1MpIHsKICAg
ICAgICB1bnNpZ25lZCBiX2lkeCA9IHJpbmcuZnJhbWVfaWR4IC8gcmluZy5mcmFtZXNfcGVyX2Js
b2NrOwogICAgICAgIHVuc2lnbmVkIGZfaW5fYiA9IHJpbmcuZnJhbWVfaWR4ICUgcmluZy5mcmFt
ZXNfcGVyX2Jsb2NrOwogICAgICAgIHVpbnQ4X3QgKmZyYW1lX3B0ciA9ICgodWludDhfdCAqKXJp
bmcucmluZykgKyAoYl9pZHggKiByaW5nLmJsb2NrX3NpemUpICsgKGZfaW5fYiAqIHJpbmcuZnJh
bWVfc2l6ZSk7CiAgICAgICAgdm9sYXRpbGUgc3RydWN0IHRwYWNrZXQyX2hkciAqdm9sYXRpbGVf
aGRyID0KICAgICAgICAgICAgKHZvbGF0aWxlIHN0cnVjdCB0cGFja2V0Ml9oZHIgKilmcmFtZV9w
dHI7CgogICAgICAgIGlmICghKHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzICYgVFBfU1RBVFVTX1VT
RVIpKSB7CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICAgICAgX19zeW5jX3N5bmNocm9u
aXplKCk7CgogICAgICAgIGNvbnN0IHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciA9CiAgICAgICAg
ICAgIChjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVfcHRyOwogICAgICAgIHNpemVf
dCBwYWNrZXRfb2Zmc2V0ID0gMCwgcGFja2V0X2xlbmd0aCA9IDA7CiAgICAgICAgaWYgKCF2YWxp
ZF9yaW5nX2ZyYW1lKGhkciwgcmluZy5mcmFtZV9zaXplLAogICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAmcGFja2V0X29mZnNldCwgJnBhY2tldF9sZW5ndGgpKSB7CiAgICAgICAgICBfX3N5
bmNfc3luY2hyb25pemUoKTsKICAgICAgICAgIHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzID0gVFBf
U1RBVFVTX0tFUk5FTDsKICAgICAgICAgIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPSB0cnVlOwog
ICAgICAgICAgKytnX2ludmFsaWRfZnJhbWVzOwogICAgICAgICAgZ19ydW5uaW5nID0gMDsKICAg
ICAgICAgIGxvZ21zZygiaW52YWxpZCBUUEFDS0VUX1YyIGZyYW1lIG1ldGFkYXRhOyBzdG9wcGlu
ZyBjYXB0dXJlIik7CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICAgICAgaWYgKHBhY2tl
dF9sZW5ndGggPiAwKSB7CiAgICAgICAgICBjb25zdCB1bnNpZ25lZCBjaGFyICpwa3QgPSBmcmFt
ZV9wdHIgKyBwYWNrZXRfb2Zmc2V0OwogICAgICAgICAgKytnX2NhcHR1cmVfcGFja2V0czsKICAg
ICAgICAgIGdfY2FwdHVyZV9ieXRlcyArPSBwYWNrZXRfbGVuZ3RoOwogICAgICAgICAgaGFuZGxl
X3BhY2tldChwa3QsIHBhY2tldF9sZW5ndGgsIG5vZGUsIHBvcnRzLCBmbG93cywgcGVuZGluZyk7
CiAgICAgICAgfQoKICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsKICAgICAgICB2b2xhdGls
ZV9oZHItPnRwX3N0YXR1cyA9IFRQX1NUQVRVU19LRVJORUw7CiAgICAgICAgcmluZy5mcmFtZV9p
ZHggPSAocmluZy5mcmFtZV9pZHggKyAxKSAlIHJpbmcuZnJhbWVfbnI7CiAgICAgICAgKytkcmFp
bl9jb3VudDsKICAgICAgfQogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNvdXQu
Zmx1c2goKTsKICAgIH0KCiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICAgIGlmIChub3cg
LSBsYXN0ID49IDEpIHsKICAgICAgc3dlZXAoZmxvd3MsIHBlbmRpbmcsIG5vdywgZ19wZW5kaW5n
X3R0bF9zZWMpOwogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2go
KTsKICAgICAgbGFzdCA9IG5vdzsKICAgIH0KCiAgICBpZiAod2FsbF9zZWNvbmRzKCkgLSBnX3N0
YXRzX2xhc3RfYXQgPj0gZ19zdGF0c19pbnRlcnZhbF9zZWMpIHsKICAgICAgc2l6ZV90IHBlbmRp
bmdfY291bnQgPSAwLCB3c3NlX2NvdW50ID0gMDsKICAgICAgZm9yIChzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHBpID0gcGVuZGluZy5iZWdpbigp
OyBwaSAhPSBwZW5kaW5nLmVuZCgpOyArK3BpKQogICAgICAgIHBlbmRpbmdfY291bnQgKz0gcGkt
PnNlY29uZC5zaXplKCk7CiAgICAgIGZvciAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJh
dG9yIGZpID0gZmxvd3MuYmVnaW4oKTsgZmkgIT0gZmxvd3MuZW5kKCk7ICsrZmkpCiAgICAgICAg
aWYgKGZpLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSkgKyt3c3NlX2NvdW50OwogICAgICBpZiAoIWdf
ZW5kcG9pbnQuZW1wdHkoKSkKICAgICAgICBzZW5kX2FnZW50X3N0YXRzKGZkLCBmbG93cy5zaXpl
KCksIHBlbmRpbmdfY291bnQsIHdzc2VfY291bnQpOwogICAgICBlbHNlCiAgICAgICAgZW1pdF9j
YXB0dXJlX3N0YXRzX2ludGVybmFsKGZkLCBmbG93cy5zaXplKCksIHBlbmRpbmdfY291bnQsIHdz
c2VfY291bnQpOwogICAgfQogIH0KCiAgZmx1c2hfaW5jb21wbGV0ZV93c3NlKGZsb3dzLCBwZW5k
aW5nKTsKICBmbHVzaF9hbGxfcGVuZGluZyhwZW5kaW5nKTsKICBpZiAoZ19lbmRwb2ludC5lbXB0
eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKCiAgaWYgKGdfc2hpcF93b3JrZXJfYWN0aXZlKSB7CiAg
ICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICBnX3Byb2R1Y2Vy
X2ZpbmlzaGVkID0gdHJ1ZTsKICAgIHB0aHJlYWRfY29uZF9icm9hZGNhc3QoJmdfc2hpcF9xdWV1
ZV9jb25kKTsKICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwog
ICAgcHRocmVhZF9qb2luKGdfc2hpcF93b3JrZXJfdGlkLCBOVUxMKTsKICB9IGVsc2UgaWYgKGdf
ZW5kcG9pbnQuZW1wdHkoKSkgewogICAgc2l6ZV90IHBlbmRpbmdfY291bnQgPSAwOwogICAgZW1p
dF9jYXB0dXJlX3N0YXRzX2ludGVybmFsKGZkLCAwLCBwZW5kaW5nX2NvdW50LCAwKTsKICB9Cgog
IHVwZGF0ZV9rZXJuZWxfZHJvcHMoZmQpOwogIGxvZ21zZygicGFja2V0IHN0YXRzOiByZWNlaXZl
ZD0iICsgdWxsX3N0cmluZyhnX2NhcHR1cmVfcGFja2V0cykgKwogICAgICAgICAiIGRyb3BwZWQ9
IiArIHVsbF9zdHJpbmcoZ19rZXJuZWxfZHJvcHMpKTsKICBpZiAoIXJlbGVhc2VfbW1hcF9yaW5n
KGZkLCByaW5nKSkgewogICAgbG9nbXNnKCJUUEFDS0VUX1YyIGNsZWFudXAgZmFpbGVkIik7CiAg
ICByaW5nX2ludGVncml0eV9mYWlsdXJlID0gdHJ1ZTsKICB9CiAgY2xvc2UoZmQpOwogIGxvZ21z
Zygic3RvcHBlZCIpOwogIHJldHVybiByaW5nX2ludGVncml0eV9mYWlsdXJlID8gMiA6IDA7Cn0K
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
