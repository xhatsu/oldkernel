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
ICAgICAiY2h1bmtfcmVhZGluZ19sZW4iLCAiY2h1bmtfcmVhZGluZ190cmFpbGVyIiwgImF3YWl0
aW5nX3dzc2UiLCAid3NzZV9ldmVudCIsICJ3c3NlX2J1ZiIsCiAgICAgICAgICAgICAgICAgIndz
c2VfZ29hbCIsICJldmVudCIsICJoZHJzIiwgImhlYWRfYnl0ZXMiLCAiYm9keV9nb2FsIikKCiAg
ICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5uZXh0X3NlcSA9IDAKICAgICAgICBz
ZWxmLmhhc19zZXEgPSBGYWxzZQogICAgICAgIHNlbGYuaXNfYnJva2VuID0gRmFsc2UKICAgICAg
ICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQogICAgICAgIHNlbGYuZmlyc3RfYnl0ZV90cyA9
IDAuMAogICAgICAgIHNlbGYuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICBzZWxmLm9vbyA9IFtd
CiAgICAgICAgc2VsZi5zdGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgc2VsZi5ib2R5
X3JlbWFpbmluZyA9IDAKICAgICAgICBzZWxmLmNodW5rX3JlbWFpbmluZyA9IDAKICAgICAgICBz
ZWxmLmNodW5rX3JlYWRpbmdfbGVuID0gVHJ1ZQogICAgICAgIHNlbGYuY2h1bmtfcmVhZGluZ190
cmFpbGVyID0gRmFsc2UKICAgICAgICBzZWxmLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQogICAgICAg
IHNlbGYud3NzZV9ldmVudCA9IE5vbmUKICAgICAgICBzZWxmLndzc2VfYnVmID0gYnl0ZWFycmF5
KCkKICAgICAgICBzZWxmLndzc2VfZ29hbCA9IDAKICAgICAgICBzZWxmLmV2ZW50ID0gTm9uZQog
ICAgICAgIHNlbGYuaGRycyA9IE5vbmUKICAgICAgICBzZWxmLmhlYWRfYnl0ZXMgPSAwCiAgICAg
ICAgc2VsZi5ib2R5X2dvYWwgPSAwCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tIHJlc3BvbnNlIGNvcnJlbGF0aW9uIC0tLS0KUEVORElOR19UVEwg
PSA1LjAgICAgICAgICMgZmx1c2ggdW5tYXRjaGVkIHJlcXVlc3RzIGFmdGVyIHRoaXMgbWFueSBz
ZWNvbmRzClBFTkRJTkdfTUFYID0gODE5MiAgICAgICAjIGhhcmQgY2FwOyBvdmVyZmxvdyBmbHVz
aGVzIG9sZGVzdCBmaXJzdApQRU5ESU5HX1BFUl9GTE9XID0gMzIgICAgIyBib3VuZCBhIHNpbmds
ZSBwaXBlbGluZWQvaG9zdGlsZSBrZWVwLWFsaXZlIGZsb3cKU1dFRVBfSU5URVJWQUwgPSAxLjAg
ICAgICMgaG9ub3IgUEVORElOR19UVEwgZXZlbiB3aGVuIHRoZSBzb2NrZXQgZ29lcyBpZGxlCgoj
IHBlbmRpbmdbKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpXSAgLS0ga2V5IGlzIHRoZSBS
RVNQT05TRSB0dXBsZToKIyBzZXJ2ZXItPmNsaWVudC4gVmFsdWU6IFtldmVudCwgcmVxX3RzXS4g
QSBsaXN0IHBlciBrZXkgaGFuZGxlcyBIVFRQCiMga2VlcC1hbGl2ZSBwaXBlbGluaW5nIChzZXZl
cmFsIHJlcXVlc3RzIGJlZm9yZSByZXNwb25zZXMgYXJyaXZlKS4KcGVuZGluZyA9IHt9CgoKZGVm
IHBlbmRpbmdfZGVsKHJrKToKICAgIHBlbmRpbmcucG9wKHJrLCBOb25lKQoKCmRlZiBwZW5kaW5n
X3BvcChyaywgb3V0LCBwZW5kaW5nX3RibD1Ob25lKToKICAgICIiIkZsdXNoIHRoZSBvbGRlc3Qg
cGVuZGluZyBldmVudCBmb3IgdGhpcyByZXNwb25zZSB0dXBsZSAoRklOL1JTVCBvcgogICAgb3Zl
cmZsb3cgcGF0aCkuIEVtaXRzIHdoYXRldmVyIHRoZSBldmVudCBoYXMg4oCUIHN0YXR1cyBzdGF5
cyBudWxsLiIiIgogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBwZW5kaW5nX3Ri
bCA9IHBlbmRpbmcKICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIG5vdCBsc3Q6
CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGV2LCBfID0gbHN0LnBvcCgwKQogICAgaWYgbm90IGxz
dDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICBvdXQuYXBwZW5kKGV2KQog
ICAgcmV0dXJuIGV2CgoKZGVmIHBhcnNlX3Jlc3BvbnNlX2hlYWQocGF5bG9hZCk6CiAgICAiIiJG
aXJzdCBsaW5lICdIVFRQLzEueCBOTk4gLi4uJyAtPiAoc3RhdHVzX2ludHxOb25lLCBjb250ZW50
X2xlbnxOb25lLCBoZWFkX2VuZF9pZHh8Tm9uZSwgaXNfY2h1bmtlZCwgaXNfY2xvc2UpLiIiIgog
ICAgdHJ5OgogICAgICAgIHJhdyA9IGJ5dGVzKHBheWxvYWQpCiAgICAgICAgaWR4ID0gcmF3LmZp
bmQoYiJcclxuXHJcbiIpCiAgICAgICAgaWYgaWR4IDwgMDoKICAgICAgICAgICAgcmV0dXJuIE5v
bmUsIE5vbmUsIE5vbmUsIEZhbHNlLCBGYWxzZQogICAgICAgIGhlYWQgPSByYXdbOmlkeF0KICAg
ICAgICBsaW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQoYiJcbiIpCiAg
ICAgICAgZmlyc3QgPSBsaW5lc1swXS5zcGxpdCgpCiAgICAgICAgaWYgbGVuKGZpcnN0KSA8IDIg
b3Igbm90IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLyIpOgogICAgICAgICAgICByZXR1cm4g
Tm9uZSwgTm9uZSwgaWR4ICsgNCwgRmFsc2UsIEZhbHNlCiAgICAgICAgc3QgPSBpbnQoZmlyc3Rb
MV0pCiAgICBleGNlcHQgKFZhbHVlRXJyb3IsIEluZGV4RXJyb3IpOgogICAgICAgIHJldHVybiBO
b25lLCBOb25lLCBOb25lLCBGYWxzZSwgRmFsc2UKICAgIGNsZW4gPSBOb25lCiAgICBpc19jaHVu
a2VkID0gRmFsc2UKICAgIGlzX2Nsb3NlID0gRmFsc2UKICAgIGlzX2h0dHBfMTAgPSBmaXJzdFsw
XS5zdGFydHN3aXRoKGIiSFRUUC8xLjAiKQogICAgY29ubl9jbG9zZSA9IEZhbHNlCiAgICBjb25u
X2tlZXBfYWxpdmUgPSBGYWxzZQogICAgZm9yIGxuIGluIGxpbmVzWzE6XToKICAgICAgICBsb3cg
PSBsbi5sb3dlcigpCiAgICAgICAgaWYgbG93LnN0YXJ0c3dpdGgoYiJjb250ZW50LWxlbmd0aDoi
KToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY2xlbiA9IGludChsbi5zcGxpdChi
IjoiLCAxKVsxXS5zdHJpcCgpKQogICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAg
ICAgICAgICAgIHBhc3MKICAgICAgICBlbGlmIGxvdy5zdGFydHN3aXRoKGIidHJhbnNmZXItZW5j
b2Rpbmc6Iik6CiAgICAgICAgICAgIGlmIGIiY2h1bmtlZCIgaW4gbG93OgogICAgICAgICAgICAg
ICAgaXNfY2h1bmtlZCA9IFRydWUKICAgICAgICBlbGlmIGxvdy5zdGFydHN3aXRoKGIiY29ubmVj
dGlvbjoiKToKICAgICAgICAgICAgaWYgYiJjbG9zZSIgaW4gbG93OgogICAgICAgICAgICAgICAg
Y29ubl9jbG9zZSA9IFRydWUKICAgICAgICAgICAgZWxpZiBiImtlZXAtYWxpdmUiIGluIGxvdzoK
ICAgICAgICAgICAgICAgIGNvbm5fa2VlcF9hbGl2ZSA9IFRydWUKICAgIGlmIGlzX2h0dHBfMTAg
YW5kIG5vdCBjb25uX2tlZXBfYWxpdmU6CiAgICAgICAgaXNfY2xvc2UgPSBUcnVlCiAgICBlbGlm
IGNvbm5fY2xvc2U6CiAgICAgICAgaXNfY2xvc2UgPSBUcnVlCiAgICByZXR1cm4gc3QsIGNsZW4s
IGlkeCArIDQsIGlzX2NodW5rZWQsIGlzX2Nsb3NlCgoKZGVmIGhhbmRsZV9yZXNwb25zZShyZXNw
X2Zsb3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBlbmRpbmdfdGJsLCBzZXE9Tm9uZSwgZmxh
Z3M9MCwgaXNfdHJ1bmNhdGVkPUZhbHNlKToKICAgIGlmIGZsYWdzICYgMHgwMiBhbmQgc2VxIGlz
IG5vdCBOb25lOgogICAgICAgIHJmbCA9IHJlc3BfZmxvd3NbcmtdID0gRmxvdygpCiAgICAgICAg
cmZsLmhhc19zZXEgPSBUcnVlCiAgICAgICAgcmZsLm5leHRfc2VxID0gKHNlcSArIDEpICYgMHhG
RkZGRkZGRgogICAgICAgIHJmbC50b3VjaGVkID0gbm93CiAgICAgICAgcmV0dXJuCgogICAgcmZs
ID0gcmVzcF9mbG93cy5nZXQocmspCiAgICBpZiByZmwgaXMgTm9uZToKICAgICAgICByZmwgPSBG
bG93KCkKICAgICAgICByZXNwX2Zsb3dzW3JrXSA9IHJmbAogICAgcmZsLnRvdWNoZWQgPSBub3cK
CiAgICBwbGVuID0gbGVuKHBheWxvYWQpIGlmIHBheWxvYWQgZWxzZSAwCiAgICBpZiBwbGVuID4g
MDoKICAgICAgICBpZiBzZXEgaXMgTm9uZToKICAgICAgICAgICAgcmZsLmJ1Zi5leHRlbmQocGF5
bG9hZCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBpZiBub3QgcmZsLmhhc19zZXE6CiAgICAg
ICAgICAgICAgICBpZiAocGxlbiA+PSA1IGFuZCBwYXlsb2FkWzo1XSA9PSBiIkhUVFAvIikgb3Ig
KHBsZW4gPCA1IGFuZCBiIkhUVFAvIi5zdGFydHN3aXRoKHBheWxvYWQpKToKICAgICAgICAgICAg
ICAgICAgICByZmwuaGFzX3NlcSA9IFRydWUKICAgICAgICAgICAgICAgICAgICByZmwubmV4dF9z
ZXEgPSBzZXEKICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gRmFsc2UKICAgICAg
ICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKHJmbC5vb28pIDwgTUFY
X09PT19TRUdNRU5UUyBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICAg
ICAgaWYgbm90IGFueShzID09IHNlcSBmb3IgcywgXyBpbiByZmwub29vKToKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIHJmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBheWxvYWQpKSkKICAg
ICAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAgICAgIGRpZmYgPSBzZXFfZGlmZihzZXEs
IHJmbC5uZXh0X3NlcSkKICAgICAgICAgICAgaWYgZGlmZiA9PSAwOgogICAgICAgICAgICAgICAg
aWYgaXNfdHJ1bmNhdGVkOgogICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVl
CiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHJmbC5idWYuZXh0ZW5k
KHBheWxvYWQpCiAgICAgICAgICAgICAgICAgICAgcmZsLm5leHRfc2VxID0gKHJmbC5uZXh0X3Nl
cSArIHBsZW4pICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgIGRyYWluZWQgPSBUcnVl
CiAgICAgICAgICAgICAgICAgICAgd2hpbGUgZHJhaW5lZCBhbmQgcmZsLm9vbzoKICAgICAgICAg
ICAgICAgICAgICAgICAgZHJhaW5lZCA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIGZv
ciBpLCAob3NlcSwgb2RhdGEpIGluIGVudW1lcmF0ZShyZmwub29vKToKICAgICAgICAgICAgICAg
ICAgICAgICAgICAgIG9kaWZmID0gc2VxX2RpZmYob3NlcSwgcmZsLm5leHRfc2VxKQogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgaWYgb2RpZmYgPT0gMDoKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICByZmwuYnVmLmV4dGVuZChvZGF0YSkKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICByZmwubmV4dF9zZXEgPSAocmZsLm5leHRfc2VxICsgbGVuKG9kYXRhKSkgJiAweEZG
RkZGRkZGCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmZsLm9vby5wb3AoaSkKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkcmFpbmVkID0gVHJ1ZQogICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlm
IG9kaWZmIDwgMDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvX292ZXJsYXAgPSAt
b2RpZmYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvX292ZXJsYXAgPCBsZW4o
b2RhdGEpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZmwuYnVmLmV4dGVu
ZChvZGF0YVtvX292ZXJsYXA6XSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
cmZsLm5leHRfc2VxID0gKHJmbC5uZXh0X3NlcSArIGxlbihvZGF0YSkgLSBvX292ZXJsYXApICYg
MHhGRkZGRkZGRgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5vb28ucG9wKGkp
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZHJhaW5lZCA9IFRydWUKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBlbGlmIGRpZmYgPCAwOgog
ICAgICAgICAgICAgICAgb3ZlcmxhcCA9IC1kaWZmCiAgICAgICAgICAgICAgICBpZiBvdmVybGFw
IDwgcGxlbiBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICByZmwuYnVm
LmV4dGVuZChwYXlsb2FkW292ZXJsYXA6XSkKICAgICAgICAgICAgICAgICAgICByZmwubmV4dF9z
ZXEgPSAocmZsLm5leHRfc2VxICsgcGxlbiAtIG92ZXJsYXApICYgMHhGRkZGRkZGRgogICAgICAg
ICAgICBlbHNlOgogICAgICAgICAgICAgICAgaWYgbGVuKHJmbC5vb28pIDwgTUFYX09PT19TRUdN
RU5UUyBhbmQgbm90IGlzX3RydW5jYXRlZDoKICAgICAgICAgICAgICAgICAgICBpZiBub3QgYW55
KHMgPT0gc2VxIGZvciBzLCBfIGluIHJmbC5vb28pOgogICAgICAgICAgICAgICAgICAgICAgICBy
Zmwub29vLmFwcGVuZCgoc2VxLCBieXRlcyhwYXlsb2FkKSkpCiAgICAgICAgICAgICAgICBlbHNl
OgogICAgICAgICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSBUcnVlCgogICAgIyBQYXJzZSBj
b21wbGV0ZSByZXNwb25zZXMgZnJvbSByZWFzc2VtYmxlZCBidWZmZXIgdXNpbmcgSFRUUCBmcmFt
aW5nCiAgICB3aGlsZSByZmwuYnVmIGFuZCBub3QgcmZsLmlzX2Jyb2tlbjoKICAgICAgICBpZiBy
Zmwuc3RhdGUgPT0gSFRUUF9TVEFURV9IRUFERVI6CiAgICAgICAgICAgIHN0LCBjbGVuLCBoZWFk
X2xlbiwgaXNfY2h1bmtlZCwgaXNfY2xvc2UgPSBwYXJzZV9yZXNwb25zZV9oZWFkKHJmbC5idWYp
CiAgICAgICAgICAgIGlmIHN0IGlzIE5vbmU6CiAgICAgICAgICAgICAgICBpZiBoZWFkX2xlbiBp
cyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6aGVhZF9sZW5dCiAg
ICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgaWYgMTAwIDw9IHN0IDw9IDE5OSBhbmQg
c3QgIT0gMTAxOgogICAgICAgICAgICAgICAgZGVsIHJmbC5idWZbOmhlYWRfbGVuXQogICAgICAg
ICAgICAgICAgY29udGludWUKCiAgICAgICAgICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykK
ICAgICAgICAgICAgaXNfaGVhZCA9IEZhbHNlCiAgICAgICAgICAgIGlmIGVudDoKICAgICAgICAg
ICAgICAgIGV2LCBzdGFydGVkID0gZW50LnBvcCgwKQogICAgICAgICAgICAgICAgaWYgbm90IGVu
dDoKICAgICAgICAgICAgICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAgICAgICAg
ICAgICAgICBpZiBldi5nZXQoIm1ldGhvZCIpID09ICJIRUFEIjoKICAgICAgICAgICAgICAgICAg
ICBpc19oZWFkID0gVHJ1ZQogICAgICAgICAgICAgICAgZXZbInN0YXR1cyJdID0gc3QKICAgICAg
ICAgICAgICAgIGV2WyJkdXJhdGlvbl9tcyJdID0gbWF4KDAsIGludCgobm93IC0gc3RhcnRlZCkg
KiAxMDAwKSkKICAgICAgICAgICAgICAgIGlmIGNsZW4gaXMgbm90IE5vbmU6CiAgICAgICAgICAg
ICAgICAgICAgZXZbInJlc3BfYnl0ZXMiXSA9IGNsZW4KICAgICAgICAgICAgICAgIG91dC5hcHBl
bmQoZXYpCgogICAgICAgICAgICBkZWwgcmZsLmJ1Zls6aGVhZF9sZW5dCgogICAgICAgICAgICBp
ZiBpc19oZWFkIG9yIHN0ID09IDIwNCBvciBzdCA9PSAzMDQ6CiAgICAgICAgICAgICAgICByZmwu
c3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICBlbGlmIGlzX2NodW5rZWQ6CiAg
ICAgICAgICAgICAgICByZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0NIVU5LCiAgICAgICAgICAgICAg
ICByZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBUcnVlCiAgICAgICAgICAgICAgICByZmwuY2h1bmtf
cmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZW1haW5p
bmcgPSAwCiAgICAgICAgICAgIGVsaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAg
IGlmIGNsZW4gPiAwOgogICAgICAgICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEhUVFBfU1RBVEVf
Qk9EWQogICAgICAgICAgICAgICAgICAgIHJmbC5ib2R5X3JlbWFpbmluZyA9IGNsZW4KICAgICAg
ICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgcmZsLnN0YXRlID0gSFRUUF9TVEFU
RV9IRUFERVIKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHJmbC5zdGF0ZSA9IEhU
VFBfU1RBVEVfQ0xPU0VfQk9EWQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBpZiByZmwu
c3RhdGUgPT0gSFRUUF9TVEFURV9CT0RZOgogICAgICAgICAgICBpZiBub3QgcmZsLmJ1ZjoKICAg
ICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4obGVuKHJmbC5i
dWYpLCByZmwuYm9keV9yZW1haW5pbmcpCiAgICAgICAgICAgIGRlbCByZmwuYnVmWzp0b19jb25z
dW1lXQogICAgICAgICAgICByZmwuYm9keV9yZW1haW5pbmcgLT0gdG9fY29uc3VtZQogICAgICAg
ICAgICBpZiByZmwuYm9keV9yZW1haW5pbmcgPT0gMDoKICAgICAgICAgICAgICAgIHJmbC5zdGF0
ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIGlmIHJm
bC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0NIVU5LOgogICAgICAgICAgICBpZiBub3QgcmZsLmJ1ZjoK
ICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGlmIHJmbC5jaHVua19yZWFkaW5nX3Ry
YWlsZXI6CiAgICAgICAgICAgICAgICBpZiBsZW4ocmZsLmJ1ZikgPj0gMiBhbmQgcmZsLmJ1Zls6
Ml0gPT0gYiJcclxuIjoKICAgICAgICAgICAgICAgICAgICBkZWwgcmZsLmJ1Zls6Ml0KICAgICAg
ICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAg
ICAgICAgICAgICByZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgogICAgICAgICAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICB0cl9lbmQgPSByZmwuYnVmLmZpbmQoYiJcclxu
XHJcbiIpCiAgICAgICAgICAgICAgICBpZiB0cl9lbmQgIT0gLTE6CiAgICAgICAgICAgICAgICAg
ICAgZGVsIHJmbC5idWZbOnRyX2VuZCArIDRdCiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5r
X3JlYWRpbmdfdHJhaWxlciA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgcmZsLnN0YXRlID0g
SFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAg
ICAgICAgaWYgbGVuKHJmbC5idWYpID4gTUFYX0hEUlM6CiAgICAgICAgICAgICAgICAgICAgcmZs
LmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IFRy
dWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGlmIHJmbC5jaHVua19yZWFkaW5n
X2xlbjoKICAgICAgICAgICAgICAgIGNybGYgPSByZmwuYnVmLmZpbmQoYiJcclxuIikKICAgICAg
ICAgICAgICAgIGlmIGNybGYgPT0gLTE6CiAgICAgICAgICAgICAgICAgICAgaWYgbGVuKHJmbC5i
dWYpID4gNjQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHJmbC5idWYgPSBieXRlYXJyYXkoKQog
ICAgICAgICAgICAgICAgICAgICAgICByZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBsaW5lID0gYnl0ZXMocmZsLmJ1Zls6Y3JsZl0p
LnN0cmlwKCkKICAgICAgICAgICAgICAgIHNlbWkgPSBsaW5lLmZpbmQoYiI7IikKICAgICAgICAg
ICAgICAgIGhleF9zdHIgPSBsaW5lWzpzZW1pXS5zdHJpcCgpIGlmIHNlbWkgIT0gLTEgZWxzZSBs
aW5lCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgY2h1bmtfbGVuID0g
aW50KGhleF9zdHIsIDE2KQogICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAg
ICAgICAgICAgICAgICAgcmZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAg
cmZsLmlzX2Jyb2tlbiA9IFRydWUKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAg
ICAgICAgZGVsIHJmbC5idWZbOmNybGYgKyAyXQogICAgICAgICAgICAgICAgaWYgY2h1bmtfbGVu
ID09IDA6CiAgICAgICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IFRy
dWUKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgZWxzZToKICAg
ICAgICAgICAgICAgICAgICByZmwuY2h1bmtfcmVtYWluaW5nID0gY2h1bmtfbGVuICsgMgogICAg
ICAgICAgICAgICAgICAgIHJmbC5jaHVua19yZWFkaW5nX2xlbiA9IEZhbHNlCiAgICAgICAgICAg
IGVsc2U6CiAgICAgICAgICAgICAgICB0b19jb25zdW1lID0gbWluKGxlbihyZmwuYnVmKSwgcmZs
LmNodW5rX3JlbWFpbmluZykKICAgICAgICAgICAgICAgIGRlbCByZmwuYnVmWzp0b19jb25zdW1l
XQogICAgICAgICAgICAgICAgcmZsLmNodW5rX3JlbWFpbmluZyAtPSB0b19jb25zdW1lCiAgICAg
ICAgICAgICAgICBpZiByZmwuY2h1bmtfcmVtYWluaW5nID09IDA6CiAgICAgICAgICAgICAgICAg
ICAgcmZsLmNodW5rX3JlYWRpbmdfbGVuID0gVHJ1ZQogICAgICAgICAgICBjb250aW51ZQoKICAg
ICAgICBpZiByZmwuc3RhdGUgPT0gSFRUUF9TVEFURV9DTE9TRV9CT0RZOgogICAgICAgICAgICBk
ZWwgcmZsLmJ1Zls6XQogICAgICAgICAgICBicmVhawoKICAgIGlmIGZsYWdzICYgMHgwNToKICAg
ICAgICByZXNwX2Zsb3dzLnBvcChyaywgTm9uZSkKICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0
LCBwZW5kaW5nX3RibCkKCgpkZWYgY29ycmVsYXRlX3Jlc3BvbnNlKHBlbmRpbmdfdGJsLCByaywg
cGF5bG9hZCwgbm93LCBvdXQsIHJlc3BfZmxvd3M9Tm9uZSwgc2VxPU5vbmUsIGZsYWdzPTAsIGlz
X3RydW5jYXRlZD1GYWxzZSk6CiAgICAiIiJBdHRhY2ggb25lIHJlc3BvbnNlIGhlYWQgdG8gdGhl
IG9sZGVzdCByZXF1ZXN0IG9uIGEgY29ubmVjdGlvbi4KCiAgICBIVFRQLzEuMSBwaXBlbGluaW5n
IGNhbiBsZWF2ZSBzZXZlcmFsIHJlcXVlc3RzIHF1ZXVlZCBmb3IgdGhlIHNhbWUKICAgIGZvdXIt
dHVwbGUuIENvbnN1bWUgZXhhY3RseSBvbmUgZW50cnk7IGRlbGV0aW5nIHRoZSB3aG9sZSBrZXkg
aGVyZSBsb3NlcwogICAgZXZlcnkgcmVxdWVzdCBhZnRlciB0aGUgZmlyc3QgcmVzcG9uc2UuCiAg
ICAiIiIKICAgIGlmIHJlc3BfZmxvd3MgaXMgbm90IE5vbmU6CiAgICAgICAgaGFuZGxlX3Jlc3Bv
bnNlKHJlc3BfZmxvd3MsIHJrLCBwYXlsb2FkLCBub3csIG91dCwgcGVuZGluZ190YmwsCiAgICAg
ICAgICAgICAgICAgICAgICAgIHNlcT1zZXEsIGZsYWdzPWZsYWdzLCBpc190cnVuY2F0ZWQ9aXNf
dHJ1bmNhdGVkKQogICAgICAgIHJldHVybiBUcnVlCiAgICByZXMgPSBwYXJzZV9yZXNwb25zZV9o
ZWFkKHBheWxvYWQpCiAgICBpZiByZXNbMF0gaXMgTm9uZToKICAgICAgICByZXR1cm4gRmFsc2UK
ICAgIHN0LCBjbGVuLCBoZWFkX2xlbiA9IHJlc1swXSwgcmVzWzFdLCByZXNbMl0KICAgIGlmIDEw
MCA8PSBzdCA8PSAxOTkgYW5kIHN0ICE9IDEwMToKICAgICAgICBpZiBoZWFkX2xlbiBpcyBub3Qg
Tm9uZSBhbmQgbGVuKHBheWxvYWQpID4gaGVhZF9sZW46CiAgICAgICAgICAgIHJldHVybiBjb3Jy
ZWxhdGVfcmVzcG9uc2UocGVuZGluZ190YmwsIHJrLCBwYXlsb2FkW2hlYWRfbGVuOl0sIG5vdywg
b3V0KQogICAgICAgIHJldHVybiBGYWxzZQogICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQog
ICAgaWYgbm90IGVudDoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGV2LCBzdGFydGVkID0gZW50
LnBvcCgwKQogICAgaWYgbm90IGVudDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUp
CiAgICBldlsic3RhdHVzIl0gPSBzdAogICAgZXZbImR1cmF0aW9uX21zIl0gPSBtYXgoMCwgaW50
KChub3cgLSBzdGFydGVkKSAqIDEwMDApKQogICAgaWYgY2xlbiBpcyBub3QgTm9uZToKICAgICAg
ICBldlsicmVzcF9ieXRlcyJdID0gY2xlbgogICAgb3V0LmFwcGVuZChldikKICAgIHJldHVybiBU
cnVlCgoKZGVmIHZhbGlkX3BvcnQocCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIDEgPD0gaW50
KHApIDw9IDY1NTM1CiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAg
cmV0dXJuIEZhbHNlCgoKZGVmIGJhc2ljX3VzZXIodmFsdWUpOgogICAgIiIiQXV0aG9yaXphdGlv
biBoZWFkZXIgdmFsdWUgLT4gKHVzZXJ8Tm9uZSwgc2NoZW1lfE5vbmUpLiBCYXNpYyBvbmx5LiIi
IgogICAgcGFydHMgPSB2YWx1ZS5zdHJpcCgpLnNwbGl0KE5vbmUsIDEpCiAgICBpZiBsZW4ocGFy
dHMpICE9IDI6CiAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIHNjaGVtZSA9IHBhcnRzWzBd
Lmxvd2VyKCkKICAgIGlmIHNjaGVtZSA9PSAiYmFzaWMiOgogICAgICAgIHRyeToKICAgICAgICAg
ICAgcGFkID0gcGFydHNbMV0uc3RyaXAoKQogICAgICAgICAgICBpZiBsZW4ocGFkKSA+IDEwMjQ6
CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBwYWQgKz0gIj0i
ICogKC1sZW4ocGFkKSAlIDQpCiAgICAgICAgICAgIHJhdyA9IGJhc2U2NC5iNjRkZWNvZGUocGFk
KQogICAgICAgICAgICBpZiBsZW4ocmF3KSA+IDUxMjoKICAgICAgICAgICAgICAgIHJldHVybiBO
b25lLCBOb25lCiAgICAgICAgICAgIGlmIGIiOiIgaW4gcmF3OgogICAgICAgICAgICAgICAgdXNl
ciA9IHJhdy5zcGxpdChiIjoiLCAxKVswXQogICAgICAgICAgICAgICAgdXNlciA9IHVzZXIuZGVj
b2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjY0XQogICAgICAgICAgICAgICAgaWYgdXNlcjoKICAg
ICAgICAgICAgICAgICAgICByZXR1cm4gdXNlciwgImJhc2ljIgogICAgICAgIGV4Y2VwdCBFeGNl
cHRpb246CiAgICAgICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBlbGlmIHNjaGVtZSA9PSAi
YmVhcmVyIjoKICAgICAgICByZXR1cm4gTm9uZSwgImJlYXJlciIKICAgIHJldHVybiBOb25lLCBO
b25lCgoKZGVmIG5vcm1hbGl6ZV93c3NlX3VzZXJuYW1lKHZhbHVlKToKICAgICIiIlJldHVybiBh
IHNtYWxsLCBwcmludGFibGUgdXNlcm5hbWUgb3IgTm9uZTsgbmV2ZXIgcmV0dXJuIHRva2VuIGRh
dGEuIiIiCiAgICBpZiB2YWx1ZSBpcyBOb25lOgogICAgICAgIHJldHVybiBOb25lCiAgICB0cnk6
CiAgICAgICAgdXNlcm5hbWUgPSB2YWx1ZS5zdHJpcCgpCiAgICBleGNlcHQgRXhjZXB0aW9uOgog
ICAgICAgIHJldHVybiBOb25lCiAgICBpZiBub3QgdXNlcm5hbWUgb3IgbGVuKHVzZXJuYW1lKSA+
IE1BWF9XU1NFX1VTRVJOQU1FOgogICAgICAgIHJldHVybiBOb25lCiAgICBmb3IgY2hhciBpbiB1
c2VybmFtZToKICAgICAgICBpZiB1bmljb2RlZGF0YS5jYXRlZ29yeShjaGFyKS5zdGFydHN3aXRo
KCJDIik6CiAgICAgICAgICAgIHJldHVybiBOb25lCiAgICByZXR1cm4gdXNlcm5hbWUKCgpkZWYg
ZXh0cmFjdF93c3NlX3VzZXJuYW1lKGJvZHkpOgogICAgIiIiUGFyc2UgYSBib3VuZGVkLCBwb3Nz
aWJseSBwYXJ0aWFsIFNPQVAgcHJlZml4IGFuZCByZXR1cm4gb25seSBVc2VybmFtZS4KCiAgICBF
eHBhdCBpcyBydW4gaW5jcmVtZW50YWxseSBzbyBhIFVzZXJuYW1lVG9rZW4gaW4gdGhlIFNPQVAg
SGVhZGVyIGNhbiBiZQogICAgcmVjb2duaXplZCB3aXRob3V0IHJldGFpbmluZyBvciByZXF1aXJp
bmcgdGhlIGNvbXBsZXRlIHJlcXVlc3QgYm9keS4KICAgIERURC9lbnRpdHkgZGVjbGFyYXRpb25z
IGFyZSByZWplY3RlZCBiZWZvcmUgcGFyc2luZy4KICAgICIiIgogICAgaWYgbm90IGJvZHkgb3Ig
bGVuKGJvZHkpID4gTUFYX1dTU0VfQk9EWV9CWVRFUyBvciBiIlx4MDAiIGluIGJvZHk6CiAgICAg
ICAgcmV0dXJuIE5vbmUKICAgIGxvd2VyZWQgPSBieXRlcyhib2R5KS5sb3dlcigpCiAgICBpZiBi
IjwhZG9jdHlwZSIgaW4gbG93ZXJlZCBvciBiIjwhZW50aXR5IiBpbiBsb3dlcmVkOgogICAgICAg
IHJldHVybiBOb25lCgogICAgc3RhdGUgPSB7InN0YWNrIjogW10sICJ0b2tlbl9kZXB0aCI6IDAs
ICJ1c2VybmFtZV9kZXB0aCI6IDAsCiAgICAgICAgICAgICAiY2hhcnMiOiBbXSwgInRvb19sb25n
IjogRmFsc2UsICJyZXN1bHQiOiBOb25lfQoKICAgIGRlZiBzcGxpdF9uYW1lKG5hbWUpOgogICAg
ICAgIGlmICJ9IiBub3QgaW4gbmFtZToKICAgICAgICAgICAgcmV0dXJuICIiLCBuYW1lCiAgICAg
ICAgcmV0dXJuIG5hbWUucnNwbGl0KCJ9IiwgMSkKCiAgICBkZWYgc3RhcnQobmFtZSwgYXR0cnMp
OgogICAgICAgIG5hbWVzcGFjZSwgbG9jYWxfbmFtZSA9IHNwbGl0X25hbWUobmFtZSkKICAgICAg
ICBzdGF0ZVsic3RhY2siXS5hcHBlbmQoKG5hbWVzcGFjZSwgbG9jYWxfbmFtZSkpCiAgICAgICAg
ZGVwdGggPSBsZW4oc3RhdGVbInN0YWNrIl0pCiAgICAgICAgaWYgKG5vdCBzdGF0ZVsidG9rZW5f
ZGVwdGgiXSBhbmQgbG9jYWxfbmFtZSA9PSAiVXNlcm5hbWVUb2tlbiIgYW5kCiAgICAgICAgICAg
ICAgICBuYW1lc3BhY2UgaW4gV1NTRV9OQU1FU1BBQ0VTKToKICAgICAgICAgICAgc3RhdGVbInRv
a2VuX2RlcHRoIl0gPSBkZXB0aAogICAgICAgIGVsaWYgKHN0YXRlWyJ0b2tlbl9kZXB0aCJdIGFu
ZAogICAgICAgICAgICAgIGRlcHRoID09IHN0YXRlWyJ0b2tlbl9kZXB0aCJdICsgMSBhbmQKICAg
ICAgICAgICAgICBsb2NhbF9uYW1lID09ICJVc2VybmFtZSIgYW5kCiAgICAgICAgICAgICAgbmFt
ZXNwYWNlID09IHN0YXRlWyJzdGFjayJdW3N0YXRlWyJ0b2tlbl9kZXB0aCJdIC0gMV1bMF0pOgog
ICAgICAgICAgICBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9IGRlcHRoCiAgICAgICAgICAgIHN0
YXRlWyJjaGFycyJdID0gW10KICAgICAgICAgICAgc3RhdGVbInRvb19sb25nIl0gPSBGYWxzZQoK
ICAgIGRlZiBjaGFycyh2YWx1ZSk6CiAgICAgICAgaWYgbm90IHN0YXRlWyJ1c2VybmFtZV9kZXB0
aCJdIG9yIHN0YXRlWyJ0b29fbG9uZyJdOgogICAgICAgICAgICByZXR1cm4KICAgICAgICBzdGF0
ZVsiY2hhcnMiXS5hcHBlbmQodmFsdWUpCiAgICAgICAgaWYgc3VtKFtsZW4ocGFydCkgZm9yIHBh
cnQgaW4gc3RhdGVbImNoYXJzIl1dKSA+IE1BWF9XU1NFX1VTRVJOQU1FICsgMjoKICAgICAgICAg
ICAgc3RhdGVbImNoYXJzIl0gPSBbXQogICAgICAgICAgICBzdGF0ZVsidG9vX2xvbmciXSA9IFRy
dWUKCiAgICBkZWYgZW5kKG5hbWUpOgogICAgICAgIGRlcHRoID0gbGVuKHN0YXRlWyJzdGFjayJd
KQogICAgICAgIGlmIHN0YXRlWyJ1c2VybmFtZV9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAg
ICBpZiBub3Qgc3RhdGVbInRvb19sb25nIl0gYW5kIHN0YXRlWyJyZXN1bHQiXSBpcyBOb25lOgog
ICAgICAgICAgICAgICAgc3RhdGVbInJlc3VsdCJdID0gbm9ybWFsaXplX3dzc2VfdXNlcm5hbWUo
CiAgICAgICAgICAgICAgICAgICAgdSIiLmpvaW4oc3RhdGVbImNoYXJzIl0pKQogICAgICAgICAg
ICBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9IDAKICAgICAgICAgICAgc3RhdGVbImNoYXJzIl0g
PSBbXQogICAgICAgIGlmIHN0YXRlWyJ0b2tlbl9kZXB0aCJdID09IGRlcHRoOgogICAgICAgICAg
ICBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9IDAKICAgICAgICBpZiBzdGF0ZVsic3RhY2siXToKICAg
ICAgICAgICAgc3RhdGVbInN0YWNrIl0ucG9wKCkKCiAgICB0cnk6CiAgICAgICAgcGFyc2VyID0g
ZXhwYXQuUGFyc2VyQ3JlYXRlKE5vbmUsICJ9IikKICAgICAgICBpZiBoYXNhdHRyKHBhcnNlciwg
InJldHVybnNfdW5pY29kZSIpOgogICAgICAgICAgICBwYXJzZXIucmV0dXJuc191bmljb2RlID0g
VHJ1ZQogICAgICAgIHBhcnNlci5TdGFydEVsZW1lbnRIYW5kbGVyID0gc3RhcnQKICAgICAgICBw
YXJzZXIuQ2hhcmFjdGVyRGF0YUhhbmRsZXIgPSBjaGFycwogICAgICAgIHBhcnNlci5FbmRFbGVt
ZW50SGFuZGxlciA9IGVuZAogICAgICAgIGlmIChoYXNhdHRyKHBhcnNlciwgIlNldFBhcmFtRW50
aXR5UGFyc2luZyIpIGFuZAogICAgICAgICAgICAgICAgaGFzYXR0cihleHBhdCwgIlhNTF9QQVJB
TV9FTlRJVFlfUEFSU0lOR19ORVZFUiIpKToKICAgICAgICAgICAgcGFyc2VyLlNldFBhcmFtRW50
aXR5UGFyc2luZyhleHBhdC5YTUxfUEFSQU1fRU5USVRZX1BBUlNJTkdfTkVWRVIpCiAgICAgICAg
cGFyc2VyLlBhcnNlKGJ5dGVzKGJvZHkpLCBGYWxzZSkKICAgIGV4Y2VwdCAoZXhwYXQuRXhwYXRF
cnJvciwgVmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAgICAgICAjIEEgYm91bmRlZCBwcmVmaXgg
aXMgY29tbW9ubHkgaW5jb21wbGV0ZS4gQSB1c2VybmFtZSBmdWxseSBjbG9zZWQKICAgICAgICAj
IGJlZm9yZSB0aGUgdHJ1bmNhdGlvbiBwb2ludCBpcyBzdGlsbCBzYWZlIHRvIHVzZS4KICAgICAg
ICBwYXNzCiAgICByZXR1cm4gc3RhdGVbInJlc3VsdCJdCgoKZGVmIGlzX3NvYXBfY29udGVudF90
eXBlKHZhbHVlKToKICAgIGlmIG5vdCB2YWx1ZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIG1l
ZGlhX3R5cGUgPSB2YWx1ZS5zcGxpdCgiOyIsIDEpWzBdLnN0cmlwKCkubG93ZXIoKQogICAgcmV0
dXJuIChtZWRpYV90eXBlIGluICgidGV4dC94bWwiLCAiYXBwbGljYXRpb24veG1sIiwKICAgICAg
ICAgICAgICAgICAgICAgICAgICAgImFwcGxpY2F0aW9uL3NvYXAreG1sIikgb3IKICAgICAgICAg
ICAgbWVkaWFfdHlwZS5lbmRzd2l0aCgiK3htbCIpKQoKCmRlZiBmaW5pc2hfZXZlbnQoZmxvdywg
a2V5LCBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0LCBwb3J0cywgbm9kZV9ob3N0KToKICAg
IGggPSBmbG93LmhkcnMKICAgIHVzZXIgPSBzY2hlbWUgPSBOb25lCiAgICBhdXRoeiA9IGguZ2V0
KCJhdXRob3JpemF0aW9uIikKICAgIGlmIGF1dGh6OgogICAgICAgIHVzZXIsIHNjaGVtZSA9IGJh
c2ljX3VzZXIoYXV0aHopCiAgICAjIFczQyB0cmFjZSBjb250ZXh0OiBob25vciBpbmNvbWluZyB0
cmFjZXBhcmVudCwgZWxzZSBnZW5lcmF0ZSBvbmUgc28KICAgICMgZXZlcnkgdHJhbnNhY3Rpb24g
Y2FycmllcyBhIHRyYWNlX2lkIGZvciBodWItc2lkZSBjb3JyZWxhdGlvbi4KICAgICMgTk9URSBw
eTIuNjogYnl0ZXMgaGFzIG5vIC5oZXgoKSDigJQgdXNlIGJpbmFzY2lpLmhleGxpZnkuCiAgICB0
cCA9IGguZ2V0KCJ0cmFjZXBhcmVudCIpCiAgICB0cmFjZV9pZCA9IE5vbmUKICAgIGlmIHRwOgog
ICAgICAgIHBhcnRzID0gdHAuc3BsaXQoIi0iKQogICAgICAgIGlmIGxlbihwYXJ0cykgPT0gNCBh
bmQgbGVuKHBhcnRzWzFdKSA9PSAzMjoKICAgICAgICAgICAgdHJhY2VfaWQgPSBwYXJ0c1sxXS5s
b3dlcigpCiAgICBpZiBub3QgdHJhY2VfaWQ6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBybmQg
PSBiaW5hc2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oMTYpKQogICAgICAgICAgICBybmQgPSBybmQu
ZGVjb2RlKCJhc2NpaSIpIGlmIGhhc2F0dHIocm5kLCAiZGVjb2RlIikgZWxzZSBybmQKICAgICAg
ICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBybmQgPSAoIiUwMzJ4IiAlIChpbnQodGlt
ZS50aW1lKCkgKiAxMDAwKSkpWy0zMjpdCiAgICAgICAgcGlkOCA9IGJpbmFzY2lpLmhleGxpZnko
b3MudXJhbmRvbSg4KSkKICAgICAgICBwaWQ4ID0gcGlkOC5kZWNvZGUoImFzY2lpIikgaWYgaGFz
YXR0cihwaWQ4LCAiZGVjb2RlIikgZWxzZSBwaWQ4CiAgICAgICAgdHAgPSAiMDAtJXMtJXMtMDEi
ICUgKHJuZCwgcGlkOCkKICAgICAgICB0cmFjZV9pZCA9IHJuZAogICAgZXYgPSB7CiAgICAgICAg
InRzIjogaW50KHRpbWUudGltZSgpKSwKICAgICAgICAiaG9zdCI6IG5vZGVfaG9zdCwKICAgICAg
ICAic3JjIjogInBjYXAiLAogICAgICAgICJzZXJ2aWNlIjogInBvcnQ6JWQiICUgZHBvcnQsCiAg
ICAgICAgIm1ldGhvZCI6IGguZ2V0KCJfbWV0aG9kIikgb3IgIi0iLAogICAgICAgICJwYXRoIjog
KGguZ2V0KCJfcGF0aCIpIG9yICItIikuc3BsaXQoIj8iLCAxKVswXVs6MTIwXSwKICAgICAgICAi
dXNlciI6IHVzZXIsCiAgICAgICAgInNjaGVtZSI6IHNjaGVtZSwKICAgICAgICAiYmFzaWNfdXNl
ciI6IHVzZXIgaWYgc2NoZW1lID09ICJiYXNpYyIgYW5kIHVzZXIgZWxzZSBOb25lLAogICAgICAg
ICJ3c3NlX3VzZXIiOiBOb25lLAogICAgICAgICJwaWQiOiBOb25lLAogICAgICAgICJzb3VyY2Vf
cHJvYmUiOiAicGNhcC1odHRwIiwKICAgICAgICAiaG9zdF9oZHIiOiBoLmdldCgiaG9zdCIpLAog
ICAgICAgICJ1c2VyX2FnZW50IjogaC5nZXQoInVzZXItYWdlbnQiKSwKICAgICAgICAieF9mb3J3
YXJkZWRfZm9yIjogaC5nZXQoIngtZm9yd2FyZGVkLWZvciIpLAogICAgICAgICJjYWxsZXIiOiBz
cmNfaXAsCiAgICAgICAgImNhbGxlcl9wb3J0Ijogc3BvcnQsCiAgICAgICAgImRzdF9pcCI6IGRz
dF9pcCwKICAgICAgICAiZHN0X3BvcnQiOiBkcG9ydCwKICAgICAgICAjIC0tLS0gbW9uaXRvcmlu
ZyBzY2hlbWEgKG9wcyBBUEktbG9nIGZvcm1hdCkgLS0tLQogICAgICAgICMgc3RhdHVzL2R1cmF0
aW9uX21zL3Jlc3BfYnl0ZXMgYXJlIHJlc3BvbnNlLXNpZGU6IHBhc3NpdmUgcmVxdWVzdC1vbmx5
CiAgICAgICAgIyBjYXB0dXJlIGNhbm5vdCBzZWUgdGhlbTsgbGVmdCBudWxsIGZvciB0aGUgaHVi
IHRvIGVucmljaCBvciBsZWF2ZS4KICAgICAgICAidHJhY2VwYXJlbnQiOiB0cFs6ODBdLAogICAg
ICAgICJ0cmFjZV9pZCI6IHRyYWNlX2lkLAogICAgICAgICJzZXJ2aWNlX2lkIjogTm9uZSwgICAg
ICAgICAgIyBodWIgbWFwcyBwb3J0LT5zZXJ2aWNlIHZpYSBwb2xpY3kgbGF0ZXIKICAgICAgICAi
bW9kdWxlX2lkIjogInBjYXAtaHR0cCIsCiAgICB9CiAgICAjIFByZXNlcnZlIHJlc3BvbnNlIGNv
cnJlbGF0aW9uIG9ubHkgZm9yIG1vbml0b3JlZCBkZXN0aW5hdGlvbnMuIFRoZQogICAgIyByZXNw
b25zZS1zaWRlIGZpbHRlciBtYXkgc3RpbGwgYWRtaXQgYSBjbGllbnQgZXBoZW1lcmFsIHNwb3J0
IGVxdWFsIHRvIGEKICAgICMgbW9uaXRvcmVkIHBvcnQ7IHRoaXMgaXMgaGFybWxlc3MgYmVjYXVz
ZSBwYXJzZV9yZXNwb25zZV9oZWFkIHJlamVjdHMgaXQuCiAgICByZXR1cm4gZXYgaWYgKGRwb3J0
IGluIHBvcnRzIG9yIGguZ2V0KCJfbWV0aG9kIikpIGVsc2UgTm9uZQoKCmRlZiBfZW1pdF9yZXF1
ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIi
RGlzY2FyZCBjYXB0dXJlIGJ1ZmZlcnMsIHRoZW4gZW1pdC9xdWV1ZSB0aGUgc2FuaXRpemVkIGV2
ZW50IG9ubHkuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAg
ZXYgPSBmbC53c3NlX2V2ZW50IGlmIGZsLmF3YWl0aW5nX3dzc2UgZWxzZSBmbC5ldmVudAogICAg
ZmwuYXdhaXRpbmdfd3NzZSA9IEZhbHNlCiAgICBmbG93cy5wb3Aoa2V5LCBOb25lKQogICAgaWYg
bm90IGV2OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gZmwuaGVhZF9ieXRl
cwogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAg
ICAgIHJldHVybgogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgIGVu
dCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgIGlmIGxl
bihwZW5kaW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9vbGRlc3Rf
cGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3JrXSA9
IFtdCiAgICBlbGlmIGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAgICAgICAgcGVuZGlu
Z19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmwuZ2V0
KHJrKQogICAgICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3Ri
bFtya10gPSBbXQogICAgc3RhcnRlZCA9IGZsLmZpcnN0X2J5dGVfdHMgaWYgZmwuZmlyc3RfYnl0
ZV90cyA+IDAgZWxzZSAobm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNlIHRpbWUudGltZSgpKQog
ICAgZW50LmFwcGVuZChbZXYsIHN0YXJ0ZWRdKQoKCmRlZiBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRp
bmcoZXYsIGhlYWRfYnl0ZXMsIGZpcnN0X2J5dGVfdHMsIG1ldGEsIG91dCwgcGVuZGluZ190Ymws
IG5vdyk6CiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAgaWYgbm90
IGV2OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0gaGVhZF9ieXRlcwogICAg
aWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgIHJl
dHVybgogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgIGVudCA9IHBl
bmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgIGlmIGxlbihwZW5k
aW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9mbHVzaF9vbGRlc3RfcGVuZGlu
ZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3JrXSA9IFtdCiAg
ICBlbGlmIGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAgICAgICAgcGVuZGluZ19wb3Ao
cmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmwuZ2V0KHJrKQog
ICAgICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3RibFtya10g
PSBbXQogICAgc3RhcnRlZCA9IGZpcnN0X2J5dGVfdHMgaWYgZmlyc3RfYnl0ZV90cyA+IDAgZWxz
ZSAobm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNlIHRpbWUudGltZSgpKQogICAgZW50LmFwcGVu
ZChbZXYsIHN0YXJ0ZWRdKQoKCmRlZiBfdHJ5X3dzc2VfYm9keShmbG93cywga2V5LCBmbCwgcGF5
bG9hZCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KToKICAgICIiIkFwcGVuZCBubyBtb3Jl
IHRoYW4gYm9keV9nb2FsIGJ5dGVzIGFuZCBmaW5pc2ggYXMgc29vbiBhcyBwb3NzaWJsZS4iIiIK
ICAgIHJlbWFpbmluZyA9IGZsLndzc2VfZ29hbCAtIGxlbihmbC53c3NlX2J1ZikKICAgIGlmIHJl
bWFpbmluZyA+IDAgYW5kIHBheWxvYWQ6CiAgICAgICAgY29weV9sZW4gPSBtaW4ocmVtYWluaW5n
LCBsZW4ocGF5bG9hZCkpCiAgICAgICAgZmwud3NzZV9idWYuZXh0ZW5kKGJ5dGVhcnJheShwYXls
b2FkWzpjb3B5X2xlbl0pKQogICAgdXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwu
d3NzZV9idWYpCiAgICBpZiB1c2VybmFtZToKICAgICAgICBmbC53c3NlX2V2ZW50WyJ3c3NlX3Vz
ZXIiXSA9IHVzZXJuYW1lCiAgICAgICAgZmwud3NzZV9ldmVudFsidXNlciJdID0gdXNlcm5hbWUK
ICAgICAgICBmbC53c3NlX2V2ZW50WyJzY2hlbWUiXSA9ICJ3c3NlIgogICAgaWYgdXNlcm5hbWUg
b3IgbGVuKGZsLndzc2VfYnVmKSA+PSBmbC53c3NlX2dvYWw6CiAgICAgICAgX2VtaXRfcmVxdWVz
dF90b19wZW5kaW5nKGZsLndzc2VfZXZlbnQsIGZsLmhlYWRfYnl0ZXMsIGZsLmZpcnN0X2J5dGVf
dHMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1ldGEsIG91dCwgcGVuZGluZ190
YmwsIG5vdykKICAgICAgICBmbC5hd2FpdGluZ193c3NlID0gRmFsc2UKICAgICAgICByZXR1cm4g
VHJ1ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIHJl
dl9rZXksIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAgICAgICAg
ICAgICAgIHBlbmRpbmdfdGJsPU5vbmUsIG5vdz1Ob25lLCB3c3NlX2JvZHlfYnl0ZXM9MCwKICAg
ICAgICAgICAgICAgICAgIHNlcT1Ob25lLCBmbGFncz0wLCBpc190cnVuY2F0ZWQ9RmFsc2UpOgog
ICAgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCA9IG1ldGEKICAgIGlmIG5vdCB2YWxpZF9w
b3J0KGRwb3J0KSBvciBub3QgdmFsaWRfcG9ydChzcG9ydCk6CiAgICAgICAgcmV0dXJuCiAgICBp
ZiBub3cgaXMgTm9uZToKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQoKICAgICMgU1lOIGhhbmRs
aW5nOiByZXNldCBmbG93IGFuZCBzdGFydCBzZXF1ZW5jZSB0cmFja2luZwogICAgaWYgZmxhZ3Mg
JiAweDAyIGFuZCBzZXEgaXMgbm90IE5vbmU6CiAgICAgICAgZmwgPSBmbG93cy5nZXQoa2V5KQog
ICAgICAgIGlmIGZsIGlzIG5vdCBOb25lIGFuZCBmbC5hd2FpdGluZ193c3NlIGFuZCBmbC53c3Nl
X2V2ZW50OgogICAgICAgICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVu
dCwgZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0ZV90cywKICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICByayA9
IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgICAgIGlmIHBlbmRpbmdfdGJsIGlz
IG5vdCBOb25lOgogICAgICAgICAgICBlbnQgPSBwZW5kaW5nX3RibC5wb3AocmssIE5vbmUpCiAg
ICAgICAgICAgIGlmIGVudDoKICAgICAgICAgICAgICAgIGZvciBwZXYsIF8gaW4gZW50OgogICAg
ICAgICAgICAgICAgICAgIG91dC5hcHBlbmQocGV2KQogICAgICAgIGlmIHJldl9rZXkgaXMgbm90
IE5vbmUgYW5kIHJldl9rZXkgaW4gZmxvd3M6CiAgICAgICAgICAgIGZsb3dzLnBvcChyZXZfa2V5
LCBOb25lKQogICAgICAgIGZsID0gRmxvdygpCiAgICAgICAgZmwuaGFzX3NlcSA9IFRydWUKICAg
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
RkZGRkYKICAgICAgICAgICAgICAgICAgICBkcmFpbmVkID0gVHJ1ZQogICAgICAgICAgICAgICAg
ICAgIHdoaWxlIGRyYWluZWQgYW5kIGZsLm9vbzoKICAgICAgICAgICAgICAgICAgICAgICAgZHJh
aW5lZCA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIGZvciBpLCAob3NlcSwgb2RhdGEp
IGluIGVudW1lcmF0ZShmbC5vb28pOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgb2RpZmYg
PSBzZXFfZGlmZihvc2VxLCBmbC5uZXh0X3NlcSkKICAgICAgICAgICAgICAgICAgICAgICAgICAg
IGlmIG9kaWZmID09IDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmwuYnVmLmV4
dGVuZChvZGF0YSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmbC5uZXh0X3NlcSA9
IChmbC5uZXh0X3NlcSArIGxlbihvZGF0YSkpICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGZsLm9vby5wb3AoaSkKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBkcmFpbmVkID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFr
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlmIG9kaWZmIDwgMDoKICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBvX292ZXJsYXAgPSAtb2RpZmYKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICBpZiBvX292ZXJsYXAgPCBsZW4ob2RhdGEpOgogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICBmbC5idWYuZXh0ZW5kKG9kYXRhW29fb3ZlcmxhcDpdKQogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmbC5uZXh0X3NlcSA9IChmbC5uZXh0X3Nl
cSArIGxlbihvZGF0YSkgLSBvX292ZXJsYXApICYgMHhGRkZGRkZGRgogICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGZsLm9vby5wb3AoaSkKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBkcmFpbmVkID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFr
CiAgICAgICAgICAgIGVsaWYgZGlmZiA8IDA6CiAgICAgICAgICAgICAgICBvdmVybGFwID0gLWRp
ZmYKICAgICAgICAgICAgICAgIGlmIG92ZXJsYXAgPCBwbGVuIGFuZCBub3QgaXNfdHJ1bmNhdGVk
OgogICAgICAgICAgICAgICAgICAgIGZsLmJ1Zi5leHRlbmQocGF5bG9hZFtvdmVybGFwOl0pCiAg
ICAgICAgICAgICAgICAgICAgZmwubmV4dF9zZXEgPSAoZmwubmV4dF9zZXEgKyBwbGVuIC0gb3Zl
cmxhcCkgJiAweEZGRkZGRkZGCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBpZiBs
ZW4oZmwub29vKSA8IE1BWF9PT09fU0VHTUVOVFMgYW5kIG5vdCBpc190cnVuY2F0ZWQ6CiAgICAg
ICAgICAgICAgICAgICAgaWYgbm90IGFueShzID09IHNlcSBmb3IgcywgXyBpbiBmbC5vb28pOgog
ICAgICAgICAgICAgICAgICAgICAgICBmbC5vb28uYXBwZW5kKChzZXEsIGJ5dGVzKHBheWxvYWQp
KSkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgZmwuaXNfYnJva2Vu
ID0gVHJ1ZQoKICAgICMgSFRUUCBmcmFtaW5nIHN0YXRlIG1hY2hpbmUKICAgIHdoaWxlIGxlbihm
bC5idWYpID4gMCBhbmQgbm90IGZsLmlzX2Jyb2tlbjoKICAgICAgICBpZiBmbC5zdGF0ZSA9PSBI
VFRQX1NUQVRFX0hFQURFUjoKICAgICAgICAgICAgaWYgbm90IGZsLmZpcnN0X2J5dGVfdHM6CiAg
ICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gbm93CgogICAgICAgICAgICBpZHggPSBm
bC5idWYuZmluZChiIlxyXG5cclxuIikKICAgICAgICAgICAgaWYgaWR4IDwgMDoKICAgICAgICAg
ICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6CiAgICAgICAgICAgICAgICAgICAgZmwu
YnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICBmbC5pc19icm9rZW4gPSBUcnVl
CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBzdGFydCA9IGZpbmRfaHR0cF9zdGFy
dChmbC5idWYpCiAgICAgICAgICAgIGlmIHN0YXJ0IDwgMCBvciBzdGFydCA+IGlkeDoKICAgICAg
ICAgICAgICAgIGRlbCBmbC5idWZbOmlkeCArIDRdCiAgICAgICAgICAgICAgICBjb250aW51ZQog
ICAgICAgICAgICBpZiBzdGFydCA+IDA6CiAgICAgICAgICAgICAgICBkZWwgZmwuYnVmWzpzdGFy
dF0KICAgICAgICAgICAgICAgIGlkeCAtPSBzdGFydAoKICAgICAgICAgICAgaGVhZCA9IGJ5dGVz
KGZsLmJ1Zls6aWR4XSkKICAgICAgICAgICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwg
YiJcbiIpLnNwbGl0KGIiXG4iKQogICAgICAgICAgICBmaXJzdCA9IGxpbmVzWzBdLnN0cmlwKCku
c3BsaXQoKQogICAgICAgICAgICBpZiBsZW4oZmlyc3QpIDwgMiBvciBmaXJzdFswXS5kZWNvZGUo
ImFzY2lpIiwgInJlcGxhY2UiKSBub3QgaW4gTUVUSE9EUzoKICAgICAgICAgICAgICAgIGRlbCBm
bC5idWZbOmlkeCArIDRdCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBoZHJz
ID0ge30KICAgICAgICAgICAgaGRyc1siX21ldGhvZCJdID0gZmlyc3RbMF0uZGVjb2RlKCJhc2Np
aSIsICJyZXBsYWNlIikKICAgICAgICAgICAgaGRyc1siX3BhdGgiXSA9IGZpcnN0WzFdLmRlY29k
ZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAgICAgICAgICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAg
ICAgICAgICAgICAgICBpZiBiIjoiIG5vdCBpbiBsbjoKICAgICAgICAgICAgICAgICAgICBjb250
aW51ZQogICAgICAgICAgICAgICAga24sIGt2ID0gbG4uc3BsaXQoYiI6IiwgMSkKICAgICAgICAg
ICAgICAgIGhkcnNba24uc3RyaXAoKS5sb3dlcigpLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIp
XSA9IGt2LnN0cmlwKCkuZGVjb2RlKCJ1dGYtOCIsICJyZXBsYWNlIilbOjE4MF0KICAgICAgICAg
ICAgZmwuaGRycyA9IGhkcnMKICAgICAgICAgICAgZmwuZXZlbnQgPSBmaW5pc2hfZXZlbnQoZmws
IGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCwgcG9ydHMsIG5vZGVfaG9zdCkKICAg
ICAgICAgICAgZmwuaGVhZF9ieXRlcyA9IGlkeCArIDQKICAgICAgICAgICAgZGVsIGZsLmJ1Zls6
aWR4ICsgNF0KCiAgICAgICAgICAgIGlmIG5vdCBmbC5ldmVudDoKICAgICAgICAgICAgICAgIGNv
bnRpbnVlCgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjb250ZW50X2xlbmd0aCA9
IGludChoZHJzLmdldCgiY29udGVudC1sZW5ndGgiLCAiMCIpKQogICAgICAgICAgICBleGNlcHQg
KFZhbHVlRXJyb3IsIFR5cGVFcnJvcik6CiAgICAgICAgICAgICAgICBjb250ZW50X2xlbmd0aCA9
IDAKICAgICAgICAgICAgdGUgPSBoZHJzLmdldCgidHJhbnNmZXItZW5jb2RpbmciLCAiIikubG93
ZXIoKQogICAgICAgICAgICBpc19jaHVua2VkID0gImNodW5rZWQiIGluIHRlCgogICAgICAgICAg
ICBpZiBjb250ZW50X2xlbmd0aCA+IDAgYW5kIGlzX2NodW5rZWQ6CiAgICAgICAgICAgICAgICBm
bC5idWYgPSBieXRlYXJyYXkoKQogICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQog
ICAgICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgICAgIGFjdGl2ZV9ib2R5X2Zsb3dzID0gc3Vt
KDEgZm9yIGNhbmQgaW4gZmxvd3MudmFsdWVzKCkgaWYgY2FuZC5hd2FpdGluZ193c3NlIG9yIChj
YW5kLmV2ZW50IGlzIG5vdCBOb25lIGFuZCBnZXRhdHRyKGNhbmQsICJib2R5X2dvYWwiLCAwKSA+
IDApKQogICAgICAgICAgICB3c3NlX2VsaWdpYmxlID0gKHdzc2VfYm9keV9ieXRlcyA+IDAgYW5k
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaXNfc29hcF9jb250ZW50X3R5cGUoaGRycy5n
ZXQoImNvbnRlbnQtdHlwZSIpKSBhbmQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb250
ZW50X2xlbmd0aCA+IDAgYW5kCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbm90IGlzX2No
dW5rZWQgYW5kCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aXZlX2JvZHlfZmxvd3Mg
PCBNQVhfV1NTRV9CT0RZX0ZMT1dTKQoKICAgICAgICAgICAgaWYgd3NzZV9lbGlnaWJsZToKICAg
ICAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBUcnVlCiAgICAgICAgICAgICAgICBmbC53
c3NlX2V2ZW50ID0gZmwuZXZlbnQKICAgICAgICAgICAgICAgIGZsLndzc2VfYnVmID0gYnl0ZWFy
cmF5KCkKICAgICAgICAgICAgICAgIGZsLndzc2VfZ29hbCA9IG1pbihjb250ZW50X2xlbmd0aCwg
d3NzZV9ib2R5X2J5dGVzLCBNQVhfV1NTRV9CT0RZX0JZVEVTKQogICAgICAgICAgICBlbHNlOgog
ICAgICAgICAgICAgICAgX2VtaXRfcmVxdWVzdF90b19wZW5kaW5nKGZsLmV2ZW50LCBmbC5oZWFk
X2J5dGVzLCBmbC5maXJzdF9ieXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAg
ICAgICAgICAgIGZsLmV2ZW50ID0gTm9uZQoKICAgICAgICAgICAgaWYgY29udGVudF9sZW5ndGgg
PiAwOgogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0JPRFkKICAgICAgICAg
ICAgICAgIGZsLmJvZHlfcmVtYWluaW5nID0gY29udGVudF9sZW5ndGgKICAgICAgICAgICAgZWxp
ZiBpc19jaHVua2VkOgogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0NIVU5L
CiAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX2xlbiA9IFRydWUKICAgICAgICAgICAg
ICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IEZhbHNlCiAgICAgICAgICAgICAgICBmbC5j
aHVua19yZW1haW5pbmcgPSAwCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBmbC5z
dGF0ZSA9IEhUVFBfU1RBVEVfSEVBREVSCiAgICAgICAgICAgICAgICBmbC5maXJzdF9ieXRlX3Rz
ID0gbm93IGlmIGZsLmJ1ZiBlbHNlIDAuMAogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBl
bGlmIGZsLnN0YXRlID09IEhUVFBfU1RBVEVfQk9EWToKICAgICAgICAgICAgaWYgbm90IGZsLmJ1
ZjoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4obGVu
KGZsLmJ1ZiksIGZsLmJvZHlfcmVtYWluaW5nKQogICAgICAgICAgICBpZiBmbC5hd2FpdGluZ193
c3NlOgogICAgICAgICAgICAgICAgd3NzZV9uZWVkID0gZmwud3NzZV9nb2FsIC0gbGVuKGZsLndz
c2VfYnVmKQogICAgICAgICAgICAgICAgaWYgd3NzZV9uZWVkID4gMDoKICAgICAgICAgICAgICAg
ICAgICBjb3B5X2xlbiA9IG1pbih0b19jb25zdW1lLCB3c3NlX25lZWQpCiAgICAgICAgICAgICAg
ICAgICAgZmwud3NzZV9idWYuZXh0ZW5kKGZsLmJ1Zls6Y29weV9sZW5dKQogICAgICAgICAgICAg
ICAgdXNlcm5hbWUgPSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwud3NzZV9idWYpCiAgICAgICAg
ICAgICAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwud3NzZV9idWYpID49IGZsLndzc2VfZ29hbDoK
ICAgICAgICAgICAgICAgICAgICBldiA9IGZsLndzc2VfZXZlbnQKICAgICAgICAgICAgICAgICAg
ICBpZiB1c2VybmFtZToKICAgICAgICAgICAgICAgICAgICAgICAgZXZbIndzc2VfdXNlciJdID0g
dXNlcm5hbWUKICAgICAgICAgICAgICAgICAgICAgICAgZXZbInVzZXIiXSA9IHVzZXJuYW1lCiAg
ICAgICAgICAgICAgICAgICAgICAgIGV2WyJzY2hlbWUiXSA9ICJ3c3NlIgogICAgICAgICAgICAg
ICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGluZyhldiwgZmwuaGVhZF9ieXRlcywgZmwuZmly
c3RfYnl0ZV90cywgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgICAgICAgICAg
ICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQoKICAgICAgICAgICAgZGVsIGZsLmJ1Zls6dG9f
Y29uc3VtZV0KICAgICAgICAgICAgZmwuYm9keV9yZW1haW5pbmcgLT0gdG9fY29uc3VtZQogICAg
ICAgICAgICBpZiBmbC5ib2R5X3JlbWFpbmluZyA9PSAwOgogICAgICAgICAgICAgICAgaWYgZmwu
YXdhaXRpbmdfd3NzZToKICAgICAgICAgICAgICAgICAgICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRp
bmcoZmwud3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywgZmwuZmlyc3RfYnl0ZV90cywgbWV0YSwg
b3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgICAgICAgICAgICAgIGZsLmF3YWl0aW5nX3dz
c2UgPSBGYWxzZQogICAgICAgICAgICAgICAgZmwuc3RhdGUgPSBIVFRQX1NUQVRFX0hFQURFUgog
ICAgICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IG5vdyBpZiBmbC5idWYgZWxzZSAwLjAK
ICAgICAgICAgICAgY29udGludWUKCiAgICAgICAgZWxpZiBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRF
X0NIVU5LOgogICAgICAgICAgICBpZiBub3QgZmwuYnVmOgogICAgICAgICAgICAgICAgYnJlYWsK
ICAgICAgICAgICAgaWYgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyOgogICAgICAgICAgICAgICAg
aWYgbGVuKGZsLmJ1ZikgPj0gMiBhbmQgZmwuYnVmWzoyXSA9PSBiIlxyXG4iOgogICAgICAgICAg
ICAgICAgICAgIGRlbCBmbC5idWZbOjJdCiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtfcmVh
ZGluZ190cmFpbGVyID0gRmFsc2UKICAgICAgICAgICAgICAgICAgICBmbC5zdGF0ZSA9IEhUVFBf
U1RBVEVfSEVBREVSCiAgICAgICAgICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IG5vdyBp
ZiBmbC5idWYgZWxzZSAwLjAKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAg
ICAgICAgdHJfZW5kID0gZmwuYnVmLmZpbmQoYiJcclxuXHJcbiIpCiAgICAgICAgICAgICAgICBp
ZiB0cl9lbmQgIT0gLTE6CiAgICAgICAgICAgICAgICAgICAgZGVsIGZsLmJ1Zls6dHJfZW5kICsg
NF0KICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBGYWxzZQog
ICAgICAgICAgICAgICAgICAgIGZsLnN0YXRlID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAg
ICAgICAgICAgICBmbC5maXJzdF9ieXRlX3RzID0gbm93IGlmIGZsLmJ1ZiBlbHNlIDAuMAogICAg
ICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBpZiBsZW4oZmwuYnVmKSA+
IE1BWF9IRFJTOgogICAgICAgICAgICAgICAgICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAg
ICAgICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gVHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsK
ICAgICAgICAgICAgaWYgZmwuY2h1bmtfcmVhZGluZ19sZW46CiAgICAgICAgICAgICAgICBjcmxm
ID0gZmwuYnVmLmZpbmQoYiJcclxuIikKICAgICAgICAgICAgICAgIGlmIGNybGYgPCAwOgogICAg
ICAgICAgICAgICAgICAgIGlmIGxlbihmbC5idWYpID4gNjQ6CiAgICAgICAgICAgICAgICAgICAg
ICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgICAgICAgICAgICAgICAgIGZsLnN0YXRl
ID0gSFRUUF9TVEFURV9IRUFERVIKICAgICAgICAgICAgICAgICAgICAgICAgZmwuZmlyc3RfYnl0
ZV90cyA9IG5vdyBpZiBmbC5idWYgZWxzZSAwLjAKICAgICAgICAgICAgICAgICAgICBicmVhawog
ICAgICAgICAgICAgICAgbGluZSA9IGJ5dGVzKGZsLmJ1Zls6Y3JsZl0pLnN0cmlwKCkKICAgICAg
ICAgICAgICAgIHNlbWkgPSBsaW5lLmZpbmQoYiI7IikKICAgICAgICAgICAgICAgIGhleF9zdHIg
PSBsaW5lWzpzZW1pXS5zdHJpcCgpIGlmIHNlbWkgIT0gLTEgZWxzZSBsaW5lCiAgICAgICAgICAg
ICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgY2h1bmtfbGVuID0gaW50KGhleF9zdHIsIDE2
KQogICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAg
ZmwuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICAgICAgICAgICAgICBmbC5zdGF0ZSA9IEhUVFBf
U1RBVEVfSEVBREVSCiAgICAgICAgICAgICAgICAgICAgZmwuZmlyc3RfYnl0ZV90cyA9IG5vdyBp
ZiBmbC5idWYgZWxzZSAwLjAKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAg
ICAgZGVsIGZsLmJ1Zls6Y3JsZiArIDJdCiAgICAgICAgICAgICAgICBpZiBjaHVua19sZW4gPT0g
MDoKICAgICAgICAgICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBUcnVlCiAg
ICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAg
ICAgICAgICAgICAgZmwuY2h1bmtfcmVtYWluaW5nID0gY2h1bmtfbGVuICsgMgogICAgICAgICAg
ICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfbGVuID0gRmFsc2UKICAgICAgICAgICAgZWxzZToK
ICAgICAgICAgICAgICAgIHRvX2NvbnN1bWUgPSBtaW4obGVuKGZsLmJ1ZiksIGZsLmNodW5rX3Jl
bWFpbmluZykKICAgICAgICAgICAgICAgIGRlbCBmbC5idWZbOnRvX2NvbnN1bWVdCiAgICAgICAg
ICAgICAgICBmbC5jaHVua19yZW1haW5pbmcgLT0gdG9fY29uc3VtZQogICAgICAgICAgICAgICAg
aWYgZmwuY2h1bmtfcmVtYWluaW5nID09IDA6CiAgICAgICAgICAgICAgICAgICAgZmwuY2h1bmtf
cmVhZGluZ19sZW4gPSBUcnVlCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgaWYgZmxhZ3MgJiAw
eDA1OgogICAgICAgIGlmIGZsLmF3YWl0aW5nX3dzc2UgYW5kIGZsLndzc2VfZXZlbnQ6CiAgICAg
ICAgICAgIF9lbWl0X3JlcXVlc3RfdG9fcGVuZGluZyhmbC53c3NlX2V2ZW50LCBmbC5oZWFkX2J5
dGVzLCBmbC5maXJzdF9ieXRlX3RzLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAg
ICAgICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBGYWxzZQogICAgICAgIGZsb3dzLnBvcChrZXksIE5v
bmUpCiAgICBlbGlmIHNlcSBpcyBOb25lIGFuZCBmbC5zdGF0ZSA9PSBIVFRQX1NUQVRFX0hFQURF
UiBhbmQgbm90IGZsLmJ1ZiBhbmQgbm90IGZsLm9vbyBhbmQgbm90IGZsLmF3YWl0aW5nX3dzc2U6
CiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKCgpkZWYgc3dlZXBfaWRsZShmbG93cywgbm93
LCBvdXQ9Tm9uZSwgcGVuZGluZ190Ymw9Tm9uZSwgcmVzcF9mbG93cz1Ob25lKToKICAgIHN0YWxl
ID0gW10KICAgIGZvciBrLCBmbCBpbiBmbG93cy5pdGVtcygpOgogICAgICAgIGlmIG5vdyAtIGZs
LnRvdWNoZWQgPiBGTE9XX1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKGspCiAgICBmb3Ig
ayBpbiBzdGFsZToKICAgICAgICBmbCA9IGZsb3dzLmdldChrKQogICAgICAgIGlmIGZsIGlzIG5v
dCBOb25lIGFuZCBmbC5hd2FpdGluZ193c3NlIGFuZCBmbC53c3NlX2V2ZW50IGlzIG5vdCBOb25l
OgogICAgICAgICAgICBpZiBvdXQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBzcmNfaXAs
IHNwb3J0LCBkc3RfaXAsIGRwb3J0ID0gawogICAgICAgICAgICAgICAgX2VtaXRfcmVxdWVzdF90
b19wZW5kaW5nKGZsLndzc2VfZXZlbnQsIGZsLmhlYWRfYnl0ZXMsIGZsLmZpcnN0X2J5dGVfdHMs
CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKGRzdF9pcCwgZHBvcnQs
IHNyY19pcCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
IG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IEZh
bHNlCiAgICAgICAgZmxvd3MucG9wKGssIE5vbmUpCiAgICBpZiByZXNwX2Zsb3dzIGlzIG5vdCBO
b25lOgogICAgICAgIHJzdGFsZSA9IFtrIGZvciBrLCByZmwgaW4gcmVzcF9mbG93cy5pdGVtcygp
IGlmIG5vdyAtIHJmbC50b3VjaGVkID4gRkxPV19UVExdCiAgICAgICAgZm9yIGsgaW4gcnN0YWxl
OgogICAgICAgICAgICByZXNwX2Zsb3dzLnBvcChrLCBOb25lKQoKCmRlZiBkcmFpbl9pbmNvbXBs
ZXRlX3dzc2UoZmxvd3MsIG91dCwgcGVuZGluZ190YmwsIG5vdz1Ob25lKToKICAgICIiIkZhbGwg
YmFjayB0byBlbWl0dGluZyB0aGUgcmVxdWVzdCBldmVudCBpZiBXU1NFIGluc3BlY3Rpb24gd2Fz
IGluY29tcGxldGUuIiIiCiAgICBpZiBub3cgaXMgTm9uZToKICAgICAgICBub3cgPSB0aW1lLnRp
bWUoKQogICAgZm9yIGtleSBpbiBsaXN0KGZsb3dzLmtleXMoKSk6CiAgICAgICAgZmwgPSBmbG93
cy5nZXQoa2V5KQogICAgICAgIGlmIGZsIGlzIE5vbmU6CiAgICAgICAgICAgIGNvbnRpbnVlCiAg
ICAgICAgaWYgZmwuYXdhaXRpbmdfd3NzZSBhbmQgZmwud3NzZV9ldmVudCBpcyBub3QgTm9uZToK
ICAgICAgICAgICAgc3JjX2lwLCBzcG9ydCwgZHN0X2lwLCBkcG9ydCA9IGtleQogICAgICAgICAg
ICBfZW1pdF9yZXF1ZXN0X3RvX3BlbmRpbmcoZmwud3NzZV9ldmVudCwgZmwuaGVhZF9ieXRlcywg
ZmwuZmlyc3RfYnl0ZV90cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIChk
c3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgIG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICAgICAgZmwuYXdhaXRpbmdf
d3NzZSA9IEZhbHNlCiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKCgpkZWYgcHJvY2Vzc19w
YWNrZXQocGt0LCBwb3J0cywgbm9kZV9ob3N0LCBmbG93cywgcmVzcF9mbG93cywgcGVuZGluZ190
YmwsIG91dCwgbm93PU5vbmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgIG4gPSBsZW4ocGt0KQog
ICAgaWYgbiA8IDM0OgogICAgICAgIHJldHVybiBGYWxzZQogICAgaWYgbm93IGlzIE5vbmU6CiAg
ICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgIG9mZiA9IDE0CiAgICBldHlwZSA9IHN0cnVjdC51
bnBhY2soIiFIIiwgcGt0WzEyOjE0XSlbMF0KICAgIGlmIGV0eXBlID09IEVUSF9QX1ZMQU46CiAg
ICAgICAgaWYgbiA8IDM4OgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBldHlwZSA9
IHN0cnVjdC51bnBhY2soIiFIIiwgcGt0WzE2OjE4XSlbMF0KICAgICAgICBvZmYgPSAxOAogICAg
ZWxpZiBldHlwZSAhPSBFVEhfUF9JUDoKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBpcDAgPSBi
MmkocGt0W29mZl0pCiAgICBpZiAoaXAwID4+IDQpICE9IDQgb3IgYjJpKHBrdFtvZmYgKyA5XSkg
IT0gNjoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlobCA9IChpcDAgJiAweDBGKSAqIDQKICAg
IGlmIGlobCA8IDIwIG9yIG4gPCBvZmYgKyBpaGwgKyAyMDoKICAgICAgICByZXR1cm4gRmFsc2UK
CiAgICBmcmFnID0gc3RydWN0LnVucGFjaygiIUgiLCBwa3Rbb2ZmICsgNjpvZmYgKyA4XSlbMF0K
ICAgIGlmIGZyYWcgJiAweDFGRkY6CiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgaXBfdG90YWxf
bGVuID0gc3RydWN0LnVucGFjaygiIUgiLCBwa3Rbb2ZmICsgMjpvZmYgKyA0XSlbMF0KICAgIGlz
X3RydW5jYXRlZCA9IEZhbHNlCiAgICBpZiBpcF90b3RhbF9sZW4gPiAwOgogICAgICAgIGlmIGlw
X3RvdGFsX2xlbiA8IGlobCArIDIwOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBp
ZiBuIC0gb2ZmIDwgaXBfdG90YWxfbGVuOgogICAgICAgICAgICBpc190cnVuY2F0ZWQgPSBUcnVl
CiAgICAgICAgZWxpZiBuIC0gb2ZmID4gaXBfdG90YWxfbGVuOgogICAgICAgICAgICBuID0gb2Zm
ICsgaXBfdG90YWxfbGVuCgogICAgc3JjX2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rbb2ZmICsg
MTI6b2ZmICsgMTZdKQogICAgZHN0X2lwID0gc29ja2V0LmluZXRfbnRvYShwa3Rbb2ZmICsgMTY6
b2ZmICsgMjBdKQogICAgdGNwX29mZiA9IG9mZiArIGlobAogICAgc3BvcnQsIGRwb3J0ID0gc3Ry
dWN0LnVucGFjaygiIUhIIiwgcGt0W3RjcF9vZmY6dGNwX29mZiArIDRdKQogICAgc2VxID0gc3Ry
dWN0LnVucGFjaygiIUkiLCBwa3RbdGNwX29mZiArIDQ6dGNwX29mZiArIDhdKVswXQogICAgZG9m
Zl9ieXRlID0gYjJpKHBrdFt0Y3Bfb2ZmICsgMTJdKQogICAgZG9mZiA9IChkb2ZmX2J5dGUgPj4g
NCkgKiA0CiAgICBpZiBkb2ZmIDwgMjAgb3IgbiA8IHRjcF9vZmYgKyBkb2ZmOgogICAgICAgIHJl
dHVybiBGYWxzZQoKICAgIGZsYWdzID0gYjJpKHBrdFt0Y3Bfb2ZmICsgMTNdKQogICAgcGF5X3N0
YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Om5dIGlmIG4g
PiBwYXlfc3RhcnQgZWxzZSBiIiIKCiAgICAjIFJlc3BvbnNlIGRpcmVjdGlvbjogU2VydmVyIC0+
IENsaWVudAogICAgaWYgc3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0czoKICAg
ICAgICByayA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgIGhhbmRsZV9y
ZXNwb25zZShyZXNwX2Zsb3dzLCByaywgcGF5bG9hZCwgbm93LCBvdXQsIHBlbmRpbmdfdGJsLAog
ICAgICAgICAgICAgICAgICAgICAgICBzZXE9c2VxLCBmbGFncz1mbGFncywgaXNfdHJ1bmNhdGVk
PWlzX3RydW5jYXRlZCkKICAgICAgICByZXR1cm4gVHJ1ZQoKICAgICMgUmVxdWVzdCBkaXJlY3Rp
b246IENsaWVudCAtPiBTZXJ2ZXIKICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAga2V5
ID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQpCiAgICAgICAgbWV0YSA9IChkc3RfaXAs
IGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgICAgIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXks
IE5vbmUsIHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAgICAgICAg
ICAgICAgICAgICBwZW5kaW5nX3RibCwgbm93LCB3c3NlX2JvZHlfYnl0ZXMsCiAgICAgICAgICAg
ICAgICAgICAgICAgc2VxPXNlcSwgZmxhZ3M9ZmxhZ3MsIGlzX3RydW5jYXRlZD1pc190cnVuY2F0
ZWQpCiAgICAgICAgcmV0dXJuIFRydWUKCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgX2ZsdXNoX29s
ZGVzdF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBvdXQpOgogICAgIiIiT3ZlcmZsb3cgZ3VhcmQ6IGVt
aXQgdGhlIHNpbmdsZSBvbGRlc3QgcGVuZGluZyBldmVudCBhcy1pcy4iIiIKICAgIG9sZGVzdF9r
ZXksIG9sZGVzdF90cyA9IE5vbmUsIE5vbmUKICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJs
Lml0ZW1zKCk6CiAgICAgICAgdHMgPSBsc3RbMF1bMV0KICAgICAgICBpZiBvbGRlc3RfdHMgaXMg
Tm9uZSBvciB0cyA8IG9sZGVzdF90czoKICAgICAgICAgICAgb2xkZXN0X2tleSwgb2xkZXN0X3Rz
ID0gcmssIHRzCiAgICBpZiBvbGRlc3Rfa2V5IGlzIG5vdCBOb25lOgogICAgICAgIHBlbmRpbmdf
cG9wKG9sZGVzdF9rZXksIG91dCwgcGVuZGluZ190YmwpCgoKZGVmIHN3ZWVwX3BlbmRpbmcocGVu
ZGluZ190YmwsIG5vdywgb3V0KToKICAgICIiIlRUTCBmbHVzaDogZW1pdCByZXF1ZXN0cyB3aG9z
ZSByZXNwb25zZXMgbmV2ZXIgc2hvd2VkIHVwLiIiIgogICAgZm9yIHJrIGluIGxpc3QocGVuZGlu
Z190Ymwua2V5cygpKToKICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICAgICAg
d2hpbGUgbHN0IGFuZCBub3cgLSBsc3RbMF1bMV0gPiBQRU5ESU5HX1RUTDoKICAgICAgICAgICAg
cGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgICAgIGxzdCA9IHBlbmRp
bmdfdGJsLmdldChyaykKCgpkZWYgZHJhaW5fcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToKICAg
ICIiIkVtaXQgZXZlcnkgY2FwdHVyZWQgcmVxdWVzdCBiZWZvcmUgY2FwdHVyZSBzaHV0ZG93bi4K
CiAgICBSZXNwb25zZXMgYXJlIG9wdGlvbmFsIGVucmljaG1lbnQuIEEgc3RvcC9yZXN0YXJ0IG11
c3Qgbm90IGRpc2NhcmQgYQogICAgcmVxdWVzdCBtZXJlbHkgYmVjYXVzZSBpdHMgcmVzcG9uc2Ug
d2FzIGZpbHRlcmVkLCBzcGxpdCwgb3Igc3RpbGwgaW4KICAgIGZsaWdodCB3aGVuIHRoZSBwcm9j
ZXNzIHJlY2VpdmVkIFNJR1RFUk0uCiAgICAiIiIKICAgIGZvciByayBpbiBsaXN0KHBlbmRpbmdf
dGJsLmtleXMoKSk6CiAgICAgICAgd2hpbGUgcGVuZGluZ190YmwuZ2V0KHJrKToKICAgICAgICAg
ICAgcGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCgoKZGVmIG1haW50ZW5hbmNlX2R1
ZShub3csIGxhc3Rfc3dlZXApOgogICAgcmV0dXJuIG5vdyAtIGxhc3Rfc3dlZXAgPj0gU1dFRVBf
SU5URVJWQUwKCgpkZWYgZW5mb3JjZV9saW1pdChmbG93cywgbm93KToKICAgICIiIkNhcCBmbG93
LXRhYmxlIHNpemUgKHB5Mi42OiBubyBPcmRlcmVkRGljdCDigJQgc3dlZXAgc3RhbGUsIHRoZW4g
RklGTwogICAgYnkgaW5zZXJ0aW9uIG9yZGVyLCB3aGljaCBwbGFpbiBkaWN0cyBwcmVzZXJ2ZSBp
biBDUHl0aG9uKS4iIiIKICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdykKICAgIHdoaWxlIGxlbihm
bG93cykgPiBNQVhfRkxPV1M6CiAgICAgICAgZmxvd3MucG9waXRlbSgpICAgICAgICAgICMgb2xk
ZXN0LWluc2VydGVkIGtleSBvbiBDUHl0aG9uIDIuNi8yLjcKCgpkZWYgX2NvbnRyb2xfY29uZmln
KCk6CiAgICAiIiJSZWFkIG9wdGlvbmFsIGNvbnRyb2wgc2V0dGluZ3Mgd2l0aG91dCBleHBvc2lu
ZyB0aGUgYmVhcmVyIHRva2VuLiIiIgogICAgZW5kcG9pbnQgPSBvcy5lbnZpcm9uLmdldCgiTlRf
Q09OVFJPTF9FTkRQT0lOVCIpIG9yIG9zLmVudmlyb24uZ2V0KCJOVF9FTkRQT0lOVCIpCiAgICB0
b2tlbl9maWxlID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9LRU5fRklMRSIsICIiKQog
ICAgdG9rZW4gPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTiIsICIiKQogICAgaWYg
dG9rZW5fZmlsZToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGYgPSBvcGVuKHRva2VuX2ZpbGUs
ICJyIikKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgdG9rZW4gPSBmLnJlYWQoKS5z
dHJpcCgpCiAgICAgICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgICAgICBmLmNsb3NlKCkKICAg
ICAgICBleGNlcHQgSU9FcnJvcjoKICAgICAgICAgICAgdG9rZW4gPSAiIgogICAgbm9kZSA9IG9z
LmVudmlyb24uZ2V0KCJOVF9OT0RFX05BTUUiKSBvciBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxp
dCgiLiIpWzBdCiAgICBydW5fZGlyID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfUlVOIiwg
Ii92YXIvbGliL25ldHdvcmt0cmFjaW5nIikKICAgIHRyeToKICAgICAgICBpbnRlcnZhbCA9IG1h
eCg1LCBtaW4oaW50KG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1NFQyIsICIzMCIpKSwgMzAw
KSkKICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgIGludGVydmFsID0gMzAKICAgIHJldHVy
biBlbmRwb2ludCwgdG9rZW4sIG5vZGUsIHJ1bl9kaXIsIGludGVydmFsCgoKZGVmIF9ydW5fY29u
dHJvbF90aWNrKHBvcnRzLCBpZmFjZSwgcnVuX2RpciwgY2xpZW50KToKICAgIHJlcGx5ID0gY2xp
ZW50LnBvbGwoKQogICAgaWYgbm90IHJlcGx5OgogICAgICAgIHJldHVybiBwb3J0cywgaWZhY2Us
IE5vbmUsICJwb2xsIGZhaWxlZCIKICAgIGRlc2lyZWQgPSByZXBseS5nZXQoImRlc2lyZWQiKSBv
ciB7fQogICAgc3RhdGUgPSBkaWN0KGRlc2lyZWQpCiAgICBnZW5lcmF0aW9uID0gZGVzaXJlZC5n
ZXQoImdlbmVyYXRpb24iLCAwKQogICAgY29udHJvbF9hY3Rpb24gPSBOb25lCiAgICBzdG9wX3Jl
cXVlc3RlZCA9IEZhbHNlCiAgICBpZiBkZXNpcmVkLmdldCgicG9ydHMiKToKICAgICAgICBuZXdf
cG9ydHMgPSBzZXQoZGVzaXJlZFsicG9ydHMiXSkKICAgICAgICBpZiBuZXdfcG9ydHMgIT0gcG9y
dHM6CiAgICAgICAgICAgIHBvcnRzID0gbmV3X3BvcnRzCiAgICAgICAgICAgIGNvbnRyb2xfYWN0
aW9uID0gInJlc3RhcnQiCiAgICBpZiBkZXNpcmVkLmdldCgiaWZhY2UiKToKICAgICAgICBuZXdf
aWZhY2UgPSBkZXNpcmVkWyJpZmFjZSJdCiAgICAgICAgaWYgbmV3X2lmYWNlICE9IGlmYWNlOgog
ICAgICAgICAgICBpZmFjZSA9IG5ld19pZmFjZQogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9
ICJyZXN0YXJ0IgogICAgZm9yIHRhc2sgaW4gcmVwbHkuZ2V0KCJ0YXNrcyIsIFtdKToKICAgICAg
ICBhY3Rpb24gPSB0YXNrLmdldCgiYWN0aW9uIikKICAgICAgICBpZiBhY3Rpb24gPT0gImhlYWx0
aCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAiaGVhbHRoeSIKICAgICAgICAgICAgc3RhdHVzID0g
ImRvbmUiCiAgICAgICAgZWxpZiBhY3Rpb24gaW4gKCJyZXN0YXJ0IiwgInJlbG9hZCIsICJzZXRf
cG9ydHMiKToKICAgICAgICAgICAgbWVzc2FnZSA9ICJhY2NlcHRlZDsgY2FwdHVyZSByZXN0YXJ0
IHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgICAgIGNvbnRy
b2xfYWN0aW9uID0gInJlc3RhcnQiCiAgICAgICAgICAgIGlmIGFjdGlvbiA9PSAic2V0X3BvcnRz
IjoKICAgICAgICAgICAgICAgIGFyZ3MgPSB0YXNrLmdldCgiYXJncyIpIG9yIHt9CiAgICAgICAg
ICAgICAgICBpZiBhcmdzLmdldCgicG9ydHMiKToKICAgICAgICAgICAgICAgICAgICBwb3J0cyA9
IHNldChhcmdzWyJwb3J0cyJdKQogICAgICAgICAgICAgICAgICAgIHN0YXRlLnVwZGF0ZSh7InBv
cnRzIjogc29ydGVkKHBvcnRzKSwgIm1vZGUiOiAicHl0aG9uIiwKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICJnZW5lcmF0aW9uIjogZ2VuZXJhdGlvbn0pCiAgICAgICAgZWxpZiBh
Y3Rpb24gPT0gInN0b3AiOgogICAgICAgICAgICBtZXNzYWdlID0gInN0b3AgcmVxdWVzdGVkIgog
ICAgICAgICAgICBzdGF0dXMgPSAiZG9uZSIKICAgICAgICAgICAgc3RvcF9yZXF1ZXN0ZWQgPSBU
cnVlCiAgICAgICAgZWxzZToKICAgICAgICAgICAgbWVzc2FnZSA9ICJ1bnN1cHBvcnRlZCBieSBk
aXJlY3Qgc25pZmZlciIKICAgICAgICAgICAgc3RhdHVzID0gImZhaWxlZCIKICAgICAgICBjbGll
bnQucmVwb3J0KHRhc2suZ2V0KCJpZCIpLCBzdGF0dXMsIG1lc3NhZ2UpCiAgICBpZiBzdG9wX3Jl
cXVlc3RlZDoKICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJzdG9wIgogICAgYXBwbGllZCA9ICgi
c3RvcCByZXF1ZXN0ZWQiIGlmIGNvbnRyb2xfYWN0aW9uID09ICJzdG9wIiBlbHNlCiAgICAgICAg
ICAgICAgICJyZXN0YXJ0IHJlcXVpcmVkIiBpZiBjb250cm9sX2FjdGlvbiA9PSAicmVzdGFydCIg
ZWxzZQogICAgICAgICAgICAgICAicG9sbCBvayIpCiAgICBudF9jb250cm9sLndyaXRlX3N0YXRl
KG9zLnBhdGguam9pbihydW5fZGlyLCAicmVtb3RlLWRlc2lyZWQuanNvbiIpLAogICAgICAgICAg
ICAgICAgICAgICAgICAgICBzdGF0ZSwgYXBwbGllZCkKICAgIGNsaWVudC5oZWFydGJlYXQoZ2Vu
ZXJhdGlvbiwgYXBwbGllZCkKICAgIHJldHVybiBwb3J0cywgaWZhY2UsIGNvbnRyb2xfYWN0aW9u
LCBhcHBsaWVkCgoKZGVmIF9yZXN0YXJ0X2FyZ3Moc2NyaXB0LCBpZmFjZSwgcG9ydHMsIHZlcmJv
c2UsIHdvcmtlcnMsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgICIiIkJ1aWxkIGEgZnJlc2ggYXJn
diBmb3IgYW4gaW4tcGxhY2UgcmUtZXhlYyBhZnRlciBhIGNvbnRyb2wgdXBkYXRlLiIiIgogICAg
IyBQcmVzZXJ2ZSB1bmJ1ZmZlcmVkIEpTT05MIGRlbGl2ZXJ5OyB0aGUgaW5zdGFsbGVyIHN0YXJ0
cyBQeXRob24gd2l0aCAtdS4KICAgIGFyZ3MgPSBbc3lzLmV4ZWN1dGFibGUsICItdSIsIG9zLnBh
dGguYWJzcGF0aChzY3JpcHQpXQogICAgaWYgaWZhY2U6CiAgICAgICAgYXJncy5leHRlbmQoWyIt
aSIsIGlmYWNlXSkKICAgIGFyZ3MuZXh0ZW5kKFsiLXAiLCAiLCIuam9pbihbc3RyKHApIGZvciBw
IGluIHNvcnRlZChwb3J0cyldKV0pCiAgICBhcmdzLmV4dGVuZChbIi1qIiwgIjEiXSkKICAgIGlm
IHdzc2VfYm9keV9ieXRlczoKICAgICAgICBhcmdzLmV4dGVuZChbIi0td3NzZS1ib2R5LWJ5dGVz
Iiwgc3RyKHdzc2VfYm9keV9ieXRlcyldKQogICAgaWYgdmVyYm9zZToKICAgICAgICBhcmdzLmFw
cGVuZCgiLXYiKQogICAgcmV0dXJuIGFyZ3MKCgpkZWYgbWFpbigpOgogICAgaWZhY2UsIHBvcnRz
LCB2ZXJib3NlLCB3b3JrZXJzLCB3c3NlX2JvZHlfYnl0ZXMgPSBwYXJzZV9hcmdzKHN5cy5hcmd2
WzE6XSkKICAgIG5vZGVfaG9zdCA9IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0K
ICAgIGNvbnRyb2xfY2xpZW50ID0gTm9uZQogICAgZW5kcG9pbnQsIHRva2VuLCBjb250cm9sX25v
ZGUsIGNvbnRyb2xfcnVuLCBjb250cm9sX2ludGVydmFsID0gX2NvbnRyb2xfY29uZmlnKCkKICAg
IGlmIG50X2NvbnRyb2wgaXMgbm90IE5vbmUgYW5kIGVuZHBvaW50IGFuZCB0b2tlbjoKICAgICAg
ICB0cnk6CiAgICAgICAgICAgIGNvbnRyb2xfY2xpZW50ID0gbnRfY29udHJvbC5Db250cm9sQ2xp
ZW50KGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlKQogICAgICAgICAgICBpZiBub3Qgb3Mu
cGF0aC5pc2Rpcihjb250cm9sX3J1bik6CiAgICAgICAgICAgICAgICBvcy5tYWtlZGlycyhjb250
cm9sX3J1bikKICAgICAgICAgICAgbG9nKCJyZW1vdGUgY29udHJvbCBlbmFibGVkIikKICAgICAg
ICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIGxvZygiV0FSTjogcmVtb3RlIGNv
bnRyb2wgZGlzYWJsZWQgKCVzKSIgJSBudF9jb250cm9sLnNhZmVfbWVzc2FnZShlKSkKCiAgICB0
cnk6CiAgICAgICAgIyBwcm90b2NvbCBNVVNUIGJlIGh0b25zKEVUSF9QX0FMTCkgdG8gcmVjZWl2
ZSBib3RoIElOR1JFU1MgKHJlcSkgYW5kCiAgICAgICAgIyBFR1JFU1MgKHJlc3ApIHBhY2tldHMg
b24gTGludXgga2VybmVsIHBhY2tldCBzb2NrZXRzLgogICAgICAgIHMgPSBzb2NrZXQuc29ja2V0
KHNvY2tldC5BRl9QQUNLRVQsIHNvY2tldC5TT0NLX1JBVywKICAgICAgICAgICAgICAgICAgICAg
ICAgICBzb2NrZXQuaHRvbnMoRVRIX1BfQUxMKSkKICAgIGV4Y2VwdCBBdHRyaWJ1dGVFcnJvcjoK
ICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJBRl9QQUNLRVQgdW5hdmFpbGFibGUgb24gdGhpcyBw
bGF0Zm9ybSIpCiAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgcmFpc2UgU3lz
dGVtRXhpdCgiY2Fubm90IG9wZW4gQUZfUEFDS0VUIHNvY2tldCAoJXMpIOKAlCBuZWVkICIKICAg
ICAgICAgICAgICAgICAgICAgICAgICJDQVBfTkVUX1JBVyAvIHJvb3QiICUgZSkKICAgIHMuc2V0
dGltZW91dCgxLjApCiAgICBpZiBub3QgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKToKICAgICAg
ICBzLmNsb3NlKCkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJrZXJuZWwgQlBGIHNhZmV0eSBm
aWx0ZXIgdW5hdmFpbGFibGU7IHJlZnVzaW5nIHVuZmlsdGVyZWQgY2FwdHVyZSIpCiAgICB0cnk6
CiAgICAgICAgcy5iaW5kKChpZmFjZSBvciAiIiwgRVRIX1BfQUxMKSkKICAgIGV4Y2VwdCBzb2Nr
ZXQuZXJyb3IgYXMgZToKICAgICAgICBzLmNsb3NlKCkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0
KCJjYW5ub3QgYmluZCBBRl9QQUNLRVQgdG8gJXMgKCVzKSIgJQogICAgICAgICAgICAgICAgICAg
ICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIGUpKQogICAgaWYgbm90IGRyb3BfY2FwdHVyZV9jYXBh
YmlsaXRpZXMoKToKICAgICAgICBzLmNsb3NlKCkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJj
YW5ub3QgZHJvcCBDQVBfTkVUX1JBVyBhZnRlciBzb2NrZXQgc2V0dXA7IHJlZnVzaW5nIHVuc2Fm
ZSBjYXB0dXJlIikKCiAgICAjIHByZWNvbXBpbGVkIHN0cnVjdCByZWFkZXJzIOKAlCB1bnBhY2tf
ZnJvbSByZWFkcyBzdHJhaWdodCBvdXQgb2YgdGhlCiAgICAjIHBhY2tldCBidWZmZXIgKG5vIHNs
aWNlIGNvcGllcykgYW5kIHlpZWxkcyBpbnRzIHVuZGVyIHB5MiBBTkQgcHkzCiAgICB1MTYgPSBz
dHJ1Y3QuU3RydWN0KCIhSCIpLnVucGFja19mcm9tCiAgICB1aCA9IHN0cnVjdC5TdHJ1Y3QoIiFI
SCIpLnVucGFja19mcm9tICAgIyBzcG9ydCxkcG9ydCBpbiBvbmUgcmVhZAogICAgdWIgPSBzdHJ1
Y3QuU3RydWN0KCIhQkIiKS51bnBhY2tfZnJvbQogICAgbnRvYSA9IHNvY2tldC5pbmV0X250b2EK
CiAgICBmbG93cyA9IHt9CiAgICByZXNwX2Zsb3dzID0ge30KICAgIHJ1bm5pbmcgPSBbVHJ1ZV0K
ICAgIHN0YXRzX2ludGVydmFsID0gc3RhdHNfaW50ZXJ2YWxfc2Vjb25kcygpCiAgICBzdGF0c19z
dGF0ZSA9IHsicGFja2V0c190b3RhbCI6IDAsICJwYWNrZXRfYnl0ZXNfdG90YWwiOiAwLAogICAg
ICAgICAgICAgICAgICAgImV2ZW50c19lbWl0dGVkX3RvdGFsIjogMCwgImtlcm5lbF9kcm9wc190
b3RhbCI6IDAsCiAgICAgICAgICAgICAgICAgICAibGFzdF9wYWNrZXRzIjogMCwgImxhc3RfcGFj
a2V0X2J5dGVzIjogMCwKICAgICAgICAgICAgICAgICAgICJsYXN0X2V2ZW50cyI6IDAsICJsYXN0
X2F0IjogdGltZS50aW1lKCl9CgogICAgZGVmIHdyaXRlX2V2ZW50cyhpdGVtcyk6CiAgICAgICAg
aWYgbm90IGl0ZW1zOgogICAgICAgICAgICByZXR1cm4KICAgICAgICB3ID0gc3lzLnN0ZG91dC53
cml0ZQogICAgICAgIGZvciBpdGVtIGluIGl0ZW1zOgogICAgICAgICAgICB3KGpzb24uZHVtcHMo
aXRlbSkgKyAiXG4iKQogICAgICAgIHN5cy5zdGRvdXQuZmx1c2goKQogICAgICAgIHN0YXRzX3N0
YXRlWyJldmVudHNfZW1pdHRlZF90b3RhbCJdICs9IGxlbihpdGVtcykKCiAgICBkZWYgZW1pdF9j
YXB0dXJlX3N0YXRzKGZvcmNlPUZhbHNlKToKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAg
ICAgIGVsYXBzZWQgPSBub3cgLSBzdGF0c19zdGF0ZVsibGFzdF9hdCJdCiAgICAgICAgaWYgbm90
IGZvcmNlIGFuZCBlbGFwc2VkIDwgc3RhdHNfaW50ZXJ2YWw6CiAgICAgICAgICAgIHJldHVybgog
ICAgICAgIGRyb3BwZWRfZGVsdGEgPSAwCiAgICAgICAgdHJ5OgogICAgICAgICAgICByYXdfc3Rh
dHMgPSBzLmdldHNvY2tvcHQoU09MX1BBQ0tFVCwgUEFDS0VUX1NUQVRJU1RJQ1MsIDgpCiAgICAg
ICAgICAgIF8sIGRyb3BwZWRfZGVsdGEgPSBzdHJ1Y3QudW5wYWNrKCJJSSIsIHJhd19zdGF0c1s6
OF0pCiAgICAgICAgZXhjZXB0IChzb2NrZXQuZXJyb3IsIHN0cnVjdC5lcnJvcik6CiAgICAgICAg
ICAgIGRyb3BwZWRfZGVsdGEgPSAwCiAgICAgICAgc3RhdHNfc3RhdGVbImtlcm5lbF9kcm9wc190
b3RhbCJdICs9IGRyb3BwZWRfZGVsdGEKICAgICAgICBwYWNrZXRzX2RlbHRhID0gKHN0YXRzX3N0
YXRlWyJwYWNrZXRzX3RvdGFsIl0gLQogICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHNfc3Rh
dGVbImxhc3RfcGFja2V0cyJdKQogICAgICAgIGJ5dGVzX2RlbHRhID0gKHN0YXRzX3N0YXRlWyJw
YWNrZXRfYnl0ZXNfdG90YWwiXSAtCiAgICAgICAgICAgICAgICAgICAgICAgc3RhdHNfc3RhdGVb
Imxhc3RfcGFja2V0X2J5dGVzIl0pCiAgICAgICAgZXZlbnRzX2RlbHRhID0gKHN0YXRzX3N0YXRl
WyJldmVudHNfZW1pdHRlZF90b3RhbCJdIC0KICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHNf
c3RhdGVbImxhc3RfZXZlbnRzIl0pCiAgICAgICAgd2FpdGluZ193c3NlID0gMAogICAgICAgIGZv
ciBmbG93IGluIGZsb3dzLnZhbHVlcygpOgogICAgICAgICAgICBpZiBmbG93LmV2ZW50IGlzIG5v
dCBOb25lIGFuZCBmbG93LmJvZHlfZ29hbDoKICAgICAgICAgICAgICAgIHdhaXRpbmdfd3NzZSAr
PSAxCiAgICAgICAgcGVuZGluZ19jb3VudCA9IHN1bShsZW4oaXRlbXMpIGZvciBpdGVtcyBpbiBw
ZW5kaW5nLnZhbHVlcygpKQogICAgICAgIGRyb3BfcGN0ID0gMTAwLjAgKiBkcm9wcGVkX2RlbHRh
IC8gbWF4KDEsIHBhY2tldHNfZGVsdGEpCiAgICAgICAgY2FwdHVyZSA9IHsKICAgICAgICAgICAg
InBhY2tldHNfdG90YWwiOiBzdGF0c19zdGF0ZVsicGFja2V0c190b3RhbCJdLAogICAgICAgICAg
ICAicGFja2V0c19kZWx0YSI6IHBhY2tldHNfZGVsdGEsCiAgICAgICAgICAgICJwYWNrZXRfYnl0
ZXNfdG90YWwiOiBzdGF0c19zdGF0ZVsicGFja2V0X2J5dGVzX3RvdGFsIl0sCiAgICAgICAgICAg
ICJwYWNrZXRfYnl0ZXNfZGVsdGEiOiBieXRlc19kZWx0YSwKICAgICAgICAgICAgImtlcm5lbF9k
cm9wc190b3RhbCI6IHN0YXRzX3N0YXRlWyJrZXJuZWxfZHJvcHNfdG90YWwiXSwKICAgICAgICAg
ICAgImtlcm5lbF9kcm9wc19kZWx0YSI6IGRyb3BwZWRfZGVsdGEsCiAgICAgICAgICAgICJrZXJu
ZWxfZHJvcF9wZXJjZW50Ijogcm91bmQoZHJvcF9wY3QsIDQpLAogICAgICAgICAgICAiaW52YWxp
ZF9mcmFtZXNfdG90YWwiOiAwLAogICAgICAgICAgICAiZXZlbnRzX2VtaXR0ZWRfdG90YWwiOiBz
dGF0c19zdGF0ZVsiZXZlbnRzX2VtaXR0ZWRfdG90YWwiXSwKICAgICAgICAgICAgImV2ZW50c19l
bWl0dGVkX2RlbHRhIjogZXZlbnRzX2RlbHRhLAogICAgICAgICAgICAiZmxvd3NfYWN0aXZlIjog
bGVuKGZsb3dzKSwKICAgICAgICAgICAgInBlbmRpbmdfcmVxdWVzdHMiOiBwZW5kaW5nX2NvdW50
LAogICAgICAgICAgICAid3NzZV9ib2R5X2Zsb3dzX2FjdGl2ZSI6IHdhaXRpbmdfd3NzZX0KICAg
ICAgICBzeXMuc3Rkb3V0LndyaXRlKGpzb24uZHVtcHMoeyJfbnRfaW50ZXJuYWwiOiAiY2FwdHVy
ZV9zdGF0c192MSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiY2FwdHVy
ZSI6IGNhcHR1cmV9LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXBhcmF0
b3JzPSgiLCIsICI6IikpICsgIlxuIikKICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAg
ICBzdGF0c19zdGF0ZVsibGFzdF9wYWNrZXRzIl0gPSBzdGF0c19zdGF0ZVsicGFja2V0c190b3Rh
bCJdCiAgICAgICAgc3RhdHNfc3RhdGVbImxhc3RfcGFja2V0X2J5dGVzIl0gPSBzdGF0c19zdGF0
ZVsicGFja2V0X2J5dGVzX3RvdGFsIl0KICAgICAgICBzdGF0c19zdGF0ZVsibGFzdF9ldmVudHMi
XSA9IHN0YXRzX3N0YXRlWyJldmVudHNfZW1pdHRlZF90b3RhbCJdCiAgICAgICAgc3RhdHNfc3Rh
dGVbImxhc3RfYXQiXSA9IG5vdwoKICAgIGRlZiBzdG9wKHNpZ251bSwgZnJhbWUpOgogICAgICAg
IHJ1bm5pbmdbMF0gPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgc3Rv
cCkKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0lOVCwgc3RvcCkKCiAgICBsYXN0X3N3ZWVw
ID0gdGltZS50aW1lKCkKICAgIGNvbnRyb2xfbmV4dCA9IHRpbWUudGltZSgpCiAgICBsb2coImxp
c3RlbmluZyBvbiAlcyBwb3J0cz0lcyBwaWQ9JWQiICUKICAgICAgICAoaWZhY2Ugb3IgIjxhbGw+
Iiwgc29ydGVkKHBvcnRzKSwgb3MuZ2V0cGlkKCkpKQogICAgaWYgd3NzZV9ib2R5X2J5dGVzOgog
ICAgICAgIGxvZygiV1NTRSBVc2VybmFtZVRva2VuIGluc3BlY3Rpb24gZW5hYmxlZCAoYm91bmRl
ZCB0byAlZCBieXRlcy9yZXF1ZXN0KSIgJQogICAgICAgICAgICB3c3NlX2JvZHlfYnl0ZXMpCgog
ICAgIyAxcyByZWN2IHRpbWVvdXQ6IChhKSBsZXRzIHRoZSBwZW5kaW5nL2Zsb3cgc3dlZXBzIGFj
dHVhbGx5IGZpcmUg4oCUCiAgICAjIHdpdGhvdXQgaXQgYGV4Y2VwdCBzb2NrZXQudGltZW91dGAg
bmV2ZXIgcnVuczsgKGIpIGVtcGlyaWNhbGx5IFJFUVVJUkVECiAgICAjIHdpdGggdGhlIEJQRiBm
aWx0ZXIgYXR0YWNoZWQ6IGEgZnVsbHktYmxvY2tpbmcgcmVjdiBvbiB0aGlzIGtlcm5lbAogICAg
IyBzdGFydmVzIGFmdGVyIHRoZSBmaXJzdCBwYWNrZXQsIHdoaWxlIHRoZSB0aW1lb3V0J2QgcmVj
diBkZWxpdmVycwogICAgIyBjb250aW51b3VzbHkgKHZlcmlmaWVkIGJ5IEEvQjogcng9MSB2cyBy
eD0yOSBpZGVudGljYWwgb3RoZXJ3aXNlKS4KICAgIHMuc2V0dGltZW91dCgxLjApCgogICAgZGJn
ID0gb3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX0RFQlVHIikgPT0gIjEiCiAgICBkYmdfcnggPSAw
CiAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAg
IGVtaXRfY2FwdHVyZV9zdGF0cygpCiAgICAgICAgIyBQb2xsIGluZGVwZW5kZW50bHkgb2Ygc29j
a2V0IGlkbGUgdGltZS4gQSBidXN5IG1vbml0b3JlZCBpbnRlcmZhY2UKICAgICAgICAjIG1heSBu
ZXZlciByYWlzZSBzb2NrZXQudGltZW91dCwgYnV0IGNvbnRyb2wgY2hhbmdlcyBtdXN0IHN0aWxs
IGFwcGx5LgogICAgICAgIGlmIGNvbnRyb2xfY2xpZW50IGlzIG5vdCBOb25lIGFuZCB0aW1lLnRp
bWUoKSA+PSBjb250cm9sX25leHQ6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBv
cnRzLCBpZmFjZSwgY29udHJvbF9hY3Rpb24sIGNvbnRyb2xfc3RhdHVzID0gX3J1bl9jb250cm9s
X3RpY2soCiAgICAgICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBjb250cm9sX3J1biwgY29u
dHJvbF9jbGllbnQpCiAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiAlcyIgJSBj
b250cm9sX3N0YXR1cykKICAgICAgICAgICAgICAgIGlmIGNvbnRyb2xfYWN0aW9uID09ICJyZXN0
YXJ0IjoKICAgICAgICAgICAgICAgICAgICBhcmdzID0gX3Jlc3RhcnRfYXJncyhzeXMuYXJndlsw
XSwgaWZhY2UsIHBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
IHZlcmJvc2UsIHdvcmtlcnMsIHdzc2VfYm9keV9ieXRlcykKICAgICAgICAgICAgICAgICAgICBs
b2coInJlbW90ZSBjb250cm9sOiByZS1leGVjdXRpbmcgY2FwdHVyZSB3aXRoIHVwZGF0ZWQgY29u
ZmlndXJhdGlvbiIpCiAgICAgICAgICAgICAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgICAgICAg
ICAgICAgb3MuZXhlY3Yoc3lzLmV4ZWN1dGFibGUsIGFyZ3MpCiAgICAgICAgICAgICAgICBlbGlm
IGNvbnRyb2xfYWN0aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90
ZSBjb250cm9sOiBzdG9wIHJlcXVlc3RlZDsgZXhpdGluZyIpCiAgICAgICAgICAgICAgICAgICAg
cnVubmluZ1swXSA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg
ICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiByZW1v
dGUgY29udHJvbCB0aWNrIGZhaWxlZCAoJXMpIiAlIG50X2NvbnRyb2wuc2FmZV9tZXNzYWdlKGUp
KQogICAgICAgICAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSArIGNvbnRyb2xfaW50ZXJ2
YWwKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBrdCA9IHMucmVjdig2NTUzNSkKICAgICAgICAg
ICAgZGJnX3J4ICs9IDEKICAgICAgICAgICAgc3RhdHNfc3RhdGVbInBhY2tldHNfdG90YWwiXSAr
PSAxCiAgICAgICAgICAgIHN0YXRzX3N0YXRlWyJwYWNrZXRfYnl0ZXNfdG90YWwiXSArPSBsZW4o
cGt0KQogICAgICAgICAgICBpZiBkYmcgYW5kIHRpbWUudGltZSgpIC0gZGJnX2xhc3QgPiA1Ogog
ICAgICAgICAgICAgICAgbG9nKCJERUJVRyByeD0lZCIgJSBkYmdfcngpCiAgICAgICAgICAgICAg
ICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgZXhjZXB0IHNvY2tldC50aW1lb3V0Ogog
ICAgICAgICAgICBpZiBkYmc6CiAgICAgICAgICAgICAgICBsb2coIkRFQlVHIHRpbWVvdXQgcng9
JWQiICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAg
ICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgICAgICBpZiBtYWludGVuYW5jZV9kdWUo
bm93LCBsYXN0X3N3ZWVwKToKICAgICAgICAgICAgICAgIG91dF9zID0gW10KICAgICAgICAgICAg
ICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdywgb3V0X3MsIHBlbmRpbmcsIHJlc3BfZmxvd3MpCiAg
ICAgICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0X3MpCiAgICAgICAg
ICAgICAgICB3cml0ZV9ldmVudHMob3V0X3MpCiAgICAgICAgICAgICAgICBsYXN0X3N3ZWVwID0g
bm93CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBl
OgogICAgICAgICAgICBpZiBlLmVycm5vID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAg
Y29udGludWUKICAgICAgICAgICAgcmFpc2UKCiAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAg
ICAgICBvdXQgPSBbXQogICAgICAgIHByb2Nlc3NfcGFja2V0KHBrdCwgcG9ydHMsIG5vZGVfaG9z
dCwgZmxvd3MsIHJlc3BfZmxvd3MsIHBlbmRpbmcsCiAgICAgICAgICAgICAgICAgICAgICAgb3V0
LCBub3csIHdzc2VfYm9keV9ieXRlcykKICAgICAgICBpZiBvdXQ6CiAgICAgICAgICAgIHdyaXRl
X2V2ZW50cyhvdXQpCgogICAgICAgIGlmIG1haW50ZW5hbmNlX2R1ZShub3csIGxhc3Rfc3dlZXAp
OgogICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5v
dywgb3V0X3MsIHBlbmRpbmcsIHJlc3BfZmxvd3MpCiAgICAgICAgICAgIHN3ZWVwX3BlbmRpbmco
cGVuZGluZywgbm93LCBvdXRfcykKICAgICAgICAgICAgd3JpdGVfZXZlbnRzKG91dF9zKQogICAg
ICAgICAgICBsYXN0X3N3ZWVwID0gbm93CgogICAgb3V0X3MgPSBbXQogICAgZHJhaW5faW5jb21w
bGV0ZV93c3NlKGZsb3dzLCBvdXRfcywgcGVuZGluZywgdGltZS50aW1lKCkpCiAgICBkcmFpbl9w
ZW5kaW5nKHBlbmRpbmcsIG91dF9zKQogICAgd3JpdGVfZXZlbnRzKG91dF9zKQogICAgZW1pdF9j
YXB0dXJlX3N0YXRzKGZvcmNlPVRydWUpCiAgICBsb2coInN0b3BwZWQgKCVkIHBlbmRpbmcgcmVx
dWVzdHMgZmx1c2hlZCkiICUgbGVuKG91dF9zKSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18i
OgogICAgbWFpbigpCg==
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
Z3RoOwogIFJlcXVlc3RNZXRhKCkgOiBjb250ZW50X2xlbmd0aCgwKSwgaGFzX2NvbnRlbnRfbGVu
Z3RoKGZhbHNlKSB7fQp9OwoKc3RydWN0IFRjcFNlZ21lbnQgewogIHVpbnQzMl90IHNlcTsKICBz
dGQ6OnN0cmluZyBkYXRhOwp9OwoKc3RhdGljIHNpemVfdCBnX3RvdGFsX2Zsb3dfYnl0ZXMgPSAw
OwpzdGF0aWMgaW5saW5lIHZvaWQgZmxvd19ieXRlc19hZGQoc2l6ZV90IG4pIHsKICBnX3RvdGFs
X2Zsb3dfYnl0ZXMgKz0gbjsKfQpzdGF0aWMgaW5saW5lIHZvaWQgZmxvd19ieXRlc19zdWIoc2l6
ZV90IG4pIHsKICBpZiAoZ190b3RhbF9mbG93X2J5dGVzID49IG4pIGdfdG90YWxfZmxvd19ieXRl
cyAtPSBuOwogIGVsc2UgZ190b3RhbF9mbG93X2J5dGVzID0gMDsKfQoKc3RydWN0IEZsb3cgewog
IHVpbnQzMl90IG5leHRfc2VxOwogIGJvb2wgaGFzX3NlcTsKICBib29sIGlzX2Jyb2tlbjsKICB0
aW1lX3QgdG91Y2hlZDsKICBsb25nIGxvbmcgZmlyc3RfYnl0ZV9tb25vX21zOwogIHVpbnQzMl90
IGdlbmVyYXRpb247CiAgc3RkOjpzdHJpbmcgYnVmOwogIHN0ZDo6dmVjdG9yPFRjcFNlZ21lbnQ+
IG9vbzsKCiAgZW51bSBIdHRwU3RhdGUgewogICAgSFRUUF9TVEFURV9IRUFERVIsCiAgICBIVFRQ
X1NUQVRFX0JPRFksCiAgICBIVFRQX1NUQVRFX0NIVU5LLAogICAgSFRUUF9TVEFURV9DTE9TRV9C
T0RZCiAgfSBzdGF0ZTsKCiAgc2l6ZV90IGJvZHlfcmVtYWluaW5nOwogIHNpemVfdCBjaHVua19y
ZW1haW5pbmc7CiAgYm9vbCBjaHVua19yZWFkaW5nX2xlbjsKICBib29sIGNodW5rX3JlYWRpbmdf
dHJhaWxlcjsKCiAgYm9vbCBhd2FpdGluZ193c3NlOwogIEV2ZW50IHdzc2VfZXZlbnQ7CiAgc3Rk
OjpzdHJpbmcgd3NzZV9idWY7CiAgc2l6ZV90IHdzc2VfZ29hbDsKCiAgRmxvdygpIDogbmV4dF9z
ZXEoMCksIGhhc19zZXEoZmFsc2UpLCBpc19icm9rZW4oZmFsc2UpLAogICAgICAgICAgIHRvdWNo
ZWQodGltZShOVUxMKSksIGZpcnN0X2J5dGVfbW9ub19tcygwKSwgZ2VuZXJhdGlvbigwKSwKICAg
ICAgICAgICBzdGF0ZShIVFRQX1NUQVRFX0hFQURFUiksIGJvZHlfcmVtYWluaW5nKDApLCBjaHVu
a19yZW1haW5pbmcoMCksCiAgICAgICAgICAgY2h1bmtfcmVhZGluZ19sZW4odHJ1ZSksIGNodW5r
X3JlYWRpbmdfdHJhaWxlcihmYWxzZSksCiAgICAgICAgICAgYXdhaXRpbmdfd3NzZShmYWxzZSks
IHdzc2VfZ29hbCgwKSB7fQoKICB2b2lkIGNsZWFyX2J1ZmZlcnMoKSB7CiAgICBmbG93X2J5dGVz
X3N1YihidWYuc2l6ZSgpKTsKICAgIGJ1Zi5jbGVhcigpOwogICAgZmxvd19ieXRlc19zdWIod3Nz
ZV9idWYuc2l6ZSgpKTsKICAgIHdzc2VfYnVmLmNsZWFyKCk7CiAgICBmb3IgKHNpemVfdCBpID0g
MDsgaSA8IG9vby5zaXplKCk7ICsraSkgewogICAgICBmbG93X2J5dGVzX3N1Yihvb29baV0uZGF0
YS5zaXplKCkpOwogICAgfQogICAgb29vLmNsZWFyKCk7CiAgfQoKICBib29sIGJ1Zl9hcHBlbmQo
Y29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbikgewogICAgaWYgKGJ1Zi5zaXplKCkgKyBsZW4g
PiBNQVhfRkxPV19CVUZGRVJfQllURVMpIHsKICAgICAgY2xlYXJfYnVmZmVycygpOwogICAgICBp
c19icm9rZW4gPSB0cnVlOwogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CiAgICBidWYuYXBwZW5k
KGRhdGEsIGxlbik7CiAgICBmbG93X2J5dGVzX2FkZChsZW4pOwogICAgcmV0dXJuIHRydWU7CiAg
fQoKICB2b2lkIGJ1Zl9lcmFzZShzaXplX3Qgb2ZmLCBzaXplX3QgbGVuKSB7CiAgICBpZiAob2Zm
ID49IGJ1Zi5zaXplKCkpIHJldHVybjsKICAgIGlmIChsZW4gPiBidWYuc2l6ZSgpIC0gb2ZmKSBs
ZW4gPSBidWYuc2l6ZSgpIC0gb2ZmOwogICAgYnVmLmVyYXNlKG9mZiwgbGVuKTsKICAgIGZsb3df
Ynl0ZXNfc3ViKGxlbik7CiAgfQoKICB2b2lkIHdzc2VfYXBwZW5kKGNvbnN0IGNoYXIgKmRhdGEs
IHNpemVfdCBsZW4pIHsKICAgIHdzc2VfYnVmLmFwcGVuZChkYXRhLCBsZW4pOwogICAgZmxvd19i
eXRlc19hZGQobGVuKTsKICB9CgogIGJvb2wgb29vX3B1c2godWludDMyX3Qgc2VxLCBjb25zdCBj
aGFyICpkYXRhLCBzaXplX3QgbGVuKSB7CiAgICBpZiAob29vLnNpemUoKSA+PSBNQVhfT09PX1NF
R01FTlRTKSByZXR1cm4gZmFsc2U7CiAgICBUY3BTZWdtZW50IHNlZzsKICAgIHNlZy5zZXEgPSBz
ZXE7CiAgICBzZWcuZGF0YS5hc3NpZ24oZGF0YSwgbGVuKTsKICAgIG9vby5wdXNoX2JhY2soc2Vn
KTsKICAgIGZsb3dfYnl0ZXNfYWRkKGxlbik7CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIHZvaWQg
b29vX2VyYXNlKHNpemVfdCBpZHgpIHsKICAgIGlmIChpZHggPCBvb28uc2l6ZSgpKSB7CiAgICAg
IGZsb3dfYnl0ZXNfc3ViKG9vb1tpZHhdLmRhdGEuc2l6ZSgpKTsKICAgICAgb29vLmVyYXNlKG9v
by5iZWdpbigpICsgaWR4KTsKICAgIH0KICB9Cn07CgpzdHJ1Y3QgRmxvd0tleSB7CiAgdWludDMy
X3Qgc19pcDsKICB1aW50MTZfdCBzcG9ydDsKICB1aW50MzJfdCBkX2lwOwogIHVpbnQxNl90IGRw
b3J0OwogIGJvb2wgb3BlcmF0b3I8KGNvbnN0IEZsb3dLZXkgJngpIGNvbnN0IHsKICAgIGlmIChz
X2lwICE9IHguc19pcCkgcmV0dXJuIHNfaXAgPCB4LnNfaXA7CiAgICBpZiAoc3BvcnQgIT0geC5z
cG9ydCkgcmV0dXJuIHNwb3J0IDwgeC5zcG9ydDsKICAgIGlmIChkX2lwICE9IHguZF9pcCkgcmV0
dXJuIGRfaXAgPCB4LmRfaXA7CiAgICByZXR1cm4gZHBvcnQgPCB4LmRwb3J0OwogIH0KfTsKdHlw
ZWRlZiBGbG93S2V5IFBhY2tldEtleTsKCnN0YXRpYyB1aW50NjRfdCBnX3JlcV9pZF9zZXEgPSAw
OwoKc3RydWN0IFBlbmRpbmcgewogIHVpbnQ2NF90IHJlcV9pZDsKICB1aW50MzJfdCBnZW5lcmF0
aW9uOwogIEV2ZW50IGV2OwogIGxvbmcgbG9uZyBzdGFydGVkX3dhbGxfbXM7CiAgbG9uZyBsb25n
IHN0YXJ0ZWRfbW9ub19tczsKICBQZW5kaW5nKCkgOiByZXFfaWQoMCksIGdlbmVyYXRpb24oMCks
IHN0YXJ0ZWRfd2FsbF9tcygwKSwgc3RhcnRlZF9tb25vX21zKDApIHt9CiAgUGVuZGluZyh1aW50
NjRfdCBpZCwgdWludDMyX3QgZ2VuLCBjb25zdCBFdmVudCAmZSwgbG9uZyBsb25nIHdhbGxfdCwg
bG9uZyBsb25nIG1vbm9fdCkKICAgIDogcmVxX2lkKGlkKSwgZ2VuZXJhdGlvbihnZW4pLCBldihl
KSwgc3RhcnRlZF93YWxsX21zKHdhbGxfdCksIHN0YXJ0ZWRfbW9ub19tcyhtb25vX3QpIHt9Cn07
CgpzdHJ1Y3QgUGVuZGluZ1F1ZXVlUmVmIHsKICB1aW50NjRfdCByZXFfaWQ7CiAgdWludDMyX3Qg
Z2VuZXJhdGlvbjsKICBQYWNrZXRLZXkga2V5OwogIGxvbmcgbG9uZyBzdGFydGVkX21vbm9fbXM7
Cn07CgpzdGF0aWMgc2l6ZV90IGdfdG90YWxfcGVuZGluZ19jb3VudCA9IDA7CnN0YXRpYyBzdGQ6
Omxpc3Q8UGVuZGluZ1F1ZXVlUmVmPiBnX3BlbmRpbmdfZmlmbzsKCnN0YXRpYyB2b2lkIGxvZ21z
Zyhjb25zdCBzdGQ6OnN0cmluZyAmcykgeyBmcHJpbnRmKHN0ZGVyciwgIm50LXNuaWZmLWNwcDog
JXNcbiIsIHMuY19zdHIoKSk7IGZmbHVzaChzdGRlcnIpOyB9CgpzdGF0aWMgYm9vbCBwYXJzZV9k
ZWNpbWFsX3NpemUoY29uc3QgY2hhciAqcCwgc2l6ZV90IG4sIHNpemVfdCAqb3V0KSB7CiAgd2hp
bGUgKG4gJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcikqcCkpIHsgKytwOyAtLW47IH0KICB3aGls
ZSAobiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKXBbbiAtIDFdKSkgLS1uOwogIGlmICghbikg
cmV0dXJuIGZhbHNlOwogIHNpemVfdCB2YWx1ZSA9IDA7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkg
PCBuOyArK2kpIHsKICAgIGlmIChwW2ldIDwgJzAnIHx8IHBbaV0gPiAnOScpIHJldHVybiBmYWxz
ZTsKICAgIHVuc2lnbmVkIGRpZ2l0ID0gKHVuc2lnbmVkKShwW2ldIC0gJzAnKTsKICAgIGlmICh2
YWx1ZSA+IChzaXplX3QpLTEgLyAxMCB8fCB2YWx1ZSAqIDEwID4gKHNpemVfdCktMSAtIGRpZ2l0
KSByZXR1cm4gZmFsc2U7CiAgICB2YWx1ZSA9IHZhbHVlICogMTAgKyBkaWdpdDsKICB9CiAgKm91
dCA9IHZhbHVlOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBwYXJzZV9yZXF1ZXN0KGNv
bnN0IGNoYXIgKmRhdGEsIHNpemVfdCBsZW4sIEV2ZW50ICplLCBSZXF1ZXN0TWV0YSAqbWV0YSkg
ewogIGNvbnN0IGNoYXIgKmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7
CiAgY29uc3QgY2hhciAqZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0g
cCk7CiAgaWYgKCFlb2wpIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3Qg
Y2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7
CiAgZS0+bWV0aG9kLmFzc2lnbihwLCBzcDEgLSBwKTsKICBpZiAoIWhhc19tZXRob2QoZS0+bWV0
aG9kKSkgcmV0dXJuIGZhbHNlOwoKICBjb25zdCBjaGFyICpwYXRoX3N0YXJ0ID0gc3AxICsgMTsK
ICB3aGlsZSAocGF0aF9zdGFydCA8IGVvbCAmJiAqcGF0aF9zdGFydCA9PSAnICcpICsrcGF0aF9z
dGFydDsKICBjb25zdCBjaGFyICpzcDIgPSAoY29uc3QgY2hhciAqKW1lbWNocihwYXRoX3N0YXJ0
LCAnICcsIGVvbCAtIHBhdGhfc3RhcnQpOwogIGlmICghc3AyKSBzcDIgPSAoZW9sID4gZGF0YSAm
JiAqKGVvbCAtIDEpID09ICdccicpID8gZW9sIC0gMSA6IGVvbDsKICBjb25zdCBjaGFyICpxbWFy
ayA9IChjb25zdCBjaGFyICopbWVtY2hyKHBhdGhfc3RhcnQsICc/Jywgc3AyIC0gcGF0aF9zdGFy
dCk7CiAgc2l6ZV90IHBhdGhfbGVuID0gKHFtYXJrID8gcW1hcmsgOiBzcDIpIC0gcGF0aF9zdGFy
dDsKICBpZiAocGF0aF9sZW4gPiAxMjApIHBhdGhfbGVuID0gMTIwOwogIGUtPnBhdGguYXNzaWdu
KHBhdGhfc3RhcnQsIHBhdGhfbGVuKTsKCiAgcCA9IGVvbCArIDE7CiAgd2hpbGUgKHAgPCBlbmQp
IHsKICAgIGlmICgqcCA9PSAnXHInIHx8ICpwID09ICdcbicpIGJyZWFrOwogICAgY29uc3QgY2hh
ciAqbGluZV9lbmQgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBlbmQgLSBwKTsKICAg
IGlmICghbGluZV9lbmQpIGxpbmVfZW5kID0gZW5kOwogICAgY29uc3QgY2hhciAqY29sb24gPSAo
Y29uc3QgY2hhciAqKW1lbWNocihwLCAnOicsIGxpbmVfZW5kIC0gcCk7CiAgICBpZiAoY29sb24p
IHsKICAgICAgc2l6ZV90IGhuYW1lX2xlbiA9IGNvbG9uIC0gcDsKICAgICAgY29uc3QgY2hhciAq
dmFsX3N0YXJ0ID0gY29sb24gKyAxOwogICAgICB3aGlsZSAodmFsX3N0YXJ0IDwgbGluZV9lbmQg
JiYgKCp2YWxfc3RhcnQgPT0gJyAnIHx8ICp2YWxfc3RhcnQgPT0gJ1x0JykpICsrdmFsX3N0YXJ0
OwogICAgICBjb25zdCBjaGFyICp2YWxfZW5kID0gbGluZV9lbmQ7CiAgICAgIHdoaWxlICh2YWxf
ZW5kID4gdmFsX3N0YXJ0ICYmICh2YWxfZW5kWy0xXSA9PSAnXHInIHx8IHZhbF9lbmRbLTFdID09
ICdcbicgfHwgdmFsX2VuZFstMV0gPT0gJyAnIHx8IHZhbF9lbmRbLTFdID09ICdcdCcpKSAtLXZh
bF9lbmQ7CiAgICAgIHNpemVfdCB2YWxfbGVuID0gdmFsX2VuZCAtIHZhbF9zdGFydDsKCiAgICAg
IGlmIChobmFtZV9sZW4gPT0gMTMgJiYgIXN0cm5jYXNlY21wKHAsICJhdXRob3JpemF0aW9uIiwg
MTMpKSB7CiAgICAgICAgaWYgKHZhbF9sZW4gPiA2ICYmICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQs
ICJCYXNpYyAiLCA2KSkgewogICAgICAgICAgc3RkOjpzdHJpbmcgYmFzaWNfdXNlciA9IGI2NGRl
Y29kZV91c2VyKHZhbF9zdGFydCArIDYsIHZhbF9sZW4gLSA2KTsKICAgICAgICAgIGlmICghYmFz
aWNfdXNlci5lbXB0eSgpKSB7CiAgICAgICAgICAgIGUtPmJhc2ljX3VzZXIgPSBiYXNpY191c2Vy
OwogICAgICAgICAgICBlLT51c2VyID0gYmFzaWNfdXNlcjsKICAgICAgICAgICAgZS0+c2NoZW1l
ID0gImJhc2ljIjsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgaWYgKHZhbF9sZW4gPiA3ICYm
ICFzdHJuY2FzZWNtcCh2YWxfc3RhcnQsICJCZWFyZXIgIiwgNykpIHsKICAgICAgICAgIGUtPnNj
aGVtZSA9ICJiZWFyZXIiOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0g
MTEgJiYgIXN0cm5jYXNlY21wKHAsICJ0cmFjZXBhcmVudCIsIDExKSkgewogICAgICAgIGUtPnRy
YWNlcGFyZW50LmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICAgIGUtPnRyYWNlX2lk
ID0gdHJhY2VfaWRfZnJvbV9wYXJlbnQoZS0+dHJhY2VwYXJlbnQpOwogICAgICB9IGVsc2UgaWYg
KGhuYW1lX2xlbiA9PSA0ICYmICFzdHJuY2FzZWNtcChwLCAiaG9zdCIsIDQpKSB7CiAgICAgICAg
ZS0+aG9zdF9oZHIuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAo
aG5hbWVfbGVuID09IDEwICYmICFzdHJuY2FzZWNtcChwLCAidXNlci1hZ2VudCIsIDEwKSkgewog
ICAgICAgIGUtPnVzZXJfYWdlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0g
ZWxzZSBpZiAoaG5hbWVfbGVuID09IDE1ICYmICFzdHJuY2FzZWNtcChwLCAieC1mb3J3YXJkZWQt
Zm9yIiwgMTUpKSB7CiAgICAgICAgZS0+eGZmLmFzc2lnbih2YWxfc3RhcnQsIHZhbF9sZW4pOwog
ICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVuID09IDEyICYmICFzdHJuY2FzZWNtcChw
LCAiY29udGVudC10eXBlIiwgMTIpKSB7CiAgICAgICAgbWV0YS0+Y29udGVudF90eXBlLmFzc2ln
bih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9IGVsc2UgaWYgKG1ldGEgJiYgaG5hbWVfbGVu
ID09IDE0ICYmICFzdHJuY2FzZWNtcChwLCAiY29udGVudC1sZW5ndGgiLCAxNCkpIHsKICAgICAg
ICBtZXRhLT5oYXNfY29udGVudF9sZW5ndGggPSBwYXJzZV9kZWNpbWFsX3NpemUodmFsX3N0YXJ0
LCB2YWxfbGVuLCAmbWV0YS0+Y29udGVudF9sZW5ndGgpOwogICAgICB9IGVsc2UgaWYgKG1ldGEg
JiYgaG5hbWVfbGVuID09IDE3ICYmICFzdHJuY2FzZWNtcChwLCAidHJhbnNmZXItZW5jb2Rpbmci
LCAxNykpIHsKICAgICAgICBtZXRhLT50cmFuc2Zlcl9lbmNvZGluZy5hc3NpZ24odmFsX3N0YXJ0
LCB2YWxfbGVuKTsKICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsKICB9CgogIGlm
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
ZiAocGFyc2VfZGVjaW1hbF9zaXplKHYsIHZsZW4sICZuKSkgewogICAgICAgICAgKmNsZW4gPSBu
OwogICAgICAgICAgKmhhc19jbGVuID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAo
aGxlbiA9PSAxNyAmJiAhc3RybmNhc2VjbXAocCwgInRyYW5zZmVyLWVuY29kaW5nIiwgMTcpKSB7
CiAgICAgICAgc3RkOjpzdHJpbmcgdGUodiwgdmxlbik7CiAgICAgICAgaWYgKGxvd2VyKHRlKS5m
aW5kKCJjaHVua2VkIikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICppc19jaHVu
a2VkID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAoaGxlbiA9PSAxMCAmJiAhc3Ry
bmNhc2VjbXAocCwgImNvbm5lY3Rpb24iLCAxMCkpIHsKICAgICAgICBzdGQ6OnN0cmluZyBjb25u
KHYsIHZsZW4pOwogICAgICAgIGlmIChsb3dlcihjb25uKS5maW5kKCJjbG9zZSIpICE9IHN0ZDo6
c3RyaW5nOjpucG9zKSB7CiAgICAgICAgICBjb25uX2Nsb3NlID0gdHJ1ZTsKICAgICAgICB9IGVs
c2UgaWYgKGxvd2VyKGNvbm4pLmZpbmQoImtlZXAtYWxpdmUiKSAhPSBzdGQ6OnN0cmluZzo6bnBv
cykgewogICAgICAgICAgY29ubl9rZWVwX2FsaXZlID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0K
ICAgIH0KICAgIHAgPSBsaW5lX2VuZCArIDE7CiAgfQogIGlmIChpc19odHRwXzEwICYmICFjb25u
X2tlZXBfYWxpdmUpIHsKICAgICppc19jbG9zZSA9IHRydWU7CiAgfSBlbHNlIGlmIChjb25uX2Ns
b3NlKSB7CiAgICAqaXNfY2xvc2UgPSB0cnVlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGlj
IHN0ZDo6c3RyaW5nIGdfZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX3NoaXBfbm9kZTsK
c3RhdGljIHVuc2lnbmVkIGdfc2hpcF9yYXRlX2ticHMgPSBERUZBVUxUX1NISVBfUkFURV9LQlBT
OwpzdGF0aWMgdW5zaWduZWQgZ19zdGF0c19pbnRlcnZhbF9zZWMgPSAzMDsKc3RhdGljIHNpemVf
dCBnX3dzc2VfYm9keV9ieXRlcyA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25nIGxvbmcgZ19jYXB0
dXJlX3BhY2tldHMgPSAwLCBnX2NhcHR1cmVfYnl0ZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9u
ZyBsb25nIGdfa2VybmVsX2Ryb3BzID0gMCwgZ19pbnZhbGlkX2ZyYW1lcyA9IDA7CnN0YXRpYyB1
bnNpZ25lZCBsb25nIGxvbmcgZ19ldmVudHNfZW1pdHRlZCA9IDAsIGdfZXZlbnRzX2luID0gMDsK
c3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2V2ZW50c19wdXNoZWQgPSAwLCBnX2V2ZW50c19k
cm9wcGVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX2Ryb3BfcXVldWUgPSAwLCBn
X2Ryb3BfaHViID0gMCwgZ19kcm9wX292ZXJzaXplZCA9IDA7CnN0YXRpYyB1bnNpZ25lZCBsb25n
IGxvbmcgZ19iYXRjaGVzX3B1c2hlZCA9IDAsIGdfYmF0Y2hlc19mYWlsZWQgPSAwOwpzdGF0aWMg
dW5zaWduZWQgbG9uZyBsb25nIGdfYnl0ZXNfcHVzaGVkID0gMCwgZ19zdGF0c19kcm9wcGVkID0g
MDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX291dHB1dF9waXBlX2Ryb3BzID0gMCwgZ19w
cmV2X291dHB1dF9waXBlX2Ryb3BzID0gMDsKc3RhdGljIHNpemVfdCBnX3F1ZXVlX2hpZ2hfd2F0
ZXIgPSAwOwpzdGF0aWMgdW5zaWduZWQgZ19jb25zZWN1dGl2ZV9mYWlsdXJlcyA9IDAsIGdfbGFz
dF9wdXNoX3N0YXR1cyA9IDA7CnN0YXRpYyB0aW1lX3QgZ19sYXN0X3N1Y2Nlc3NfYXQgPSAwOwpz
dGF0aWMgZG91YmxlIGdfc3RhdHNfbGFzdF9hdCA9IDAuMCwgZ19zdGF0c19sYXN0X2NwdSA9IDAu
MDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzID0gMCwg
Z19wcmV2X2NhcHR1cmVfYnl0ZXMgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25nIGdfcHJl
dl9ldmVudHNfZW1pdHRlZCA9IDAsIGdfcHJldl9ldmVudHNfaW4gPSAwOwpzdGF0aWMgdW5zaWdu
ZWQgbG9uZyBsb25nIGdfcHJldl9ldmVudHNfcHVzaGVkID0gMCwgZ19wcmV2X2V2ZW50c19kcm9w
cGVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3ByZXZfYmF0Y2hlc19wdXNoZWQg
PSAwLCBnX3ByZXZfYmF0Y2hlc19mYWlsZWQgPSAwOwpzdGF0aWMgdW5zaWduZWQgbG9uZyBsb25n
IGdfcHJldl9ieXRlc19wdXNoZWQgPSAwLCBnX3ByZXZfZHJvcF9xdWV1ZSA9IDA7CnN0YXRpYyB1
bnNpZ25lZCBsb25nIGxvbmcgZ19wcmV2X2Ryb3BfaHViID0gMCwgZ19wcmV2X2Ryb3Bfb3ZlcnNp
emVkID0gMDsKc3RhdGljIHVuc2lnbmVkIGxvbmcgbG9uZyBnX3N0YXRzX3NlcXVlbmNlID0gMDsK
c3RhdGljIHN0ZDo6c3RyaW5nIGdfaW5zdGFuY2VfaWQ7CgpzdGF0aWMgcHRocmVhZF90IGdfc2hp
cF93b3JrZXJfdGlkOwpzdGF0aWMgcHRocmVhZF9tdXRleF90IGdfc2hpcF9xdWV1ZV9tdXRleCA9
IFBUSFJFQURfTVVURVhfSU5JVElBTElaRVI7CnN0YXRpYyBwdGhyZWFkX2NvbmRfdCBnX3NoaXBf
cXVldWVfY29uZCA9IFBUSFJFQURfQ09ORF9JTklUSUFMSVpFUjsKc3RhdGljIHN0ZDo6dmVjdG9y
PHN0ZDo6c3RyaW5nPiBnX3NoaXBfYnVmOwpzdGF0aWMgYm9vbCBnX3NoaXBfd29ya2VyX2FjdGl2
ZSA9IGZhbHNlOwpzdGF0aWMgc3RkOjpzdHJpbmcgZ19wZW5kaW5nX3N0YXRzX2JvZHk7CgpzdGF0
aWMgc3RkOjpzdHJpbmcgc2hlbGxxKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpzdHJp
bmcgbyA9ICInIjsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHMuc2l6ZSgpOyArK2kpIHsgaWYg
KHNbaV0gPT0gJ1wnJykgbyArPSAiJ1xcJyciOyBlbHNlIG8gKz0gc1tpXTsgfQogIHJldHVybiBv
ICsgIiciOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1iZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0
ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6
OnN0cmluZyB1bGxfc3RyaW5nKHVuc2lnbmVkIGxvbmcgbG9uZyBuKSB7IHN0ZDo6b3N0cmluZ3N0
cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBkb3Vi
bGVfc3RyaW5nKGRvdWJsZSBuKSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvLnNldGYoc3RkOjpp
b3M6OmZpeGVkKTsgby5wcmVjaXNpb24oNCk7IG8gPDwgbjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3Rh
dGljIHN0ZDo6c3RyaW5nIGpzb25fYXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+
ICZhKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICJbIjsgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBhLnNp
emUoKTsgKytpKSB7IGlmIChpKSBvICs9ICIsIjsgbyArPSBhW2ldOyB9IHJldHVybiBvICsgIl0i
Owp9CnN0YXRpYyBkb3VibGUgd2FsbF9zZWNvbmRzKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2Owog
IGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVybiAoZG91YmxlKXR2LnR2X3NlYyArIChk
b3VibGUpdHYudHZfdXNlYyAvIDEwMDAwMDAuMDsKfQpzdGF0aWMgdm9pZCBwYWNlX3VwbG9hZChz
aXplX3QgYnl0ZXMsIGRvdWJsZSAqbmV4dF9zbG90KSB7CiAgY29uc3QgZG91YmxlIGJ5dGVzX3Bl
cl9zZWMgPSAoZG91YmxlKWdfc2hpcF9yYXRlX2ticHMgKiAxMDAwLjAgLyA4LjA7CiAgZG91Ymxl
IG5vdyA9IHdhbGxfc2Vjb25kcygpOwogIGlmICgqbmV4dF9zbG90IDwgbm93IHx8ICpuZXh0X3Ns
b3QgLSBub3cgPiA2MC4wKSAqbmV4dF9zbG90ID0gbm93OwogIGRvdWJsZSBzbG90ID0gKm5leHRf
c2xvdDsKICAqbmV4dF9zbG90ICs9IChkb3VibGUpYnl0ZXMgLyBieXRlc19wZXJfc2VjOwogIHdo
aWxlIChzbG90ID4gKG5vdyA9IHdhbGxfc2Vjb25kcygpKSkgewogICAgZG91YmxlIHJlbWFpbmlu
ZyA9IHNsb3QgLSBub3c7CiAgICB1c2Vjb25kc190IGRlbGF5ID0gKHVzZWNvbmRzX3QpKHJlbWFp
bmluZyA+IDAuNSA/IDUwMDAwMCA6IHJlbWFpbmluZyAqIDEwMDAwMDAuMCk7CiAgICBpZiAoZGVs
YXkpIHVzbGVlcChkZWxheSk7CiAgfQp9CnN0YXRpYyBzaXplX3QgYm91bmRlZF9iYXRjaF9jb3Vu
dChjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJ1ZiwKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlKSB7CiAgc2l6ZV90IHNpemUg
PSBzdGQ6OnN0cmluZygie1wibm9kZVwiOiIpLnNpemUoKSArIGpzb25xKG5vZGUpLnNpemUoKSAr
CiAgICAgICAgICAgICAgICBzdGQ6OnN0cmluZygiLFwiZXZlbnRzXCI6W119Iikuc2l6ZSgpOwog
IHNpemVfdCBuID0gMCwgbGltaXQgPSBidWYuc2l6ZSgpIDwgTUFYX0JBVENIID8gYnVmLnNpemUo
KSA6IE1BWF9CQVRDSDsKICB3aGlsZSAobiA8IGxpbWl0KSB7CiAgICBzaXplX3QgZXh0cmEgPSBi
dWZbbl0uc2l6ZSgpICsgKG4gPyAxIDogMCk7CiAgICBpZiAoZXh0cmEgPiBNQVhfUE9TVF9CWVRF
UyAtIHNpemUpIGJyZWFrOwogICAgc2l6ZSArPSBleHRyYTsKICAgICsrbjsKICB9CiAgcmV0dXJu
IG47Cn0KCnN0YXRpYyBib29sIHBvc3RfYm9keShjb25zdCBzdGQ6OnN0cmluZyAmZW5kcG9pbnQs
IGNvbnN0IHN0ZDo6c3RyaW5nICZwYXRoLAogICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHN0
ZDo6c3RyaW5nICZib2R5LCB1bnNpZ25lZCB0aW1lb3V0X3NlYywgZG91YmxlICpuZXh0X3Nsb3Qp
IHsKICBpZiAobmV4dF9zbG90KSBwYWNlX3VwbG9hZChib2R5LnNpemUoKSwgbmV4dF9zbG90KTsK
ICBzdGQ6OnN0cmluZyBjbWQgPSAiY3VybCAtc1NmIC0tbWF4LXRpbWUgIiArIG51bWJlcl9zdHJp
bmcodGltZW91dF9zZWMpICsgIiAtLWxpbWl0LXJhdGUgIiArCiAgICBudW1iZXJfc3RyaW5nKChz
aXplX3QpZ19zaGlwX3JhdGVfa2JwcyAqIDEwMDBVIC8gOFUpICsKICAgICIgLW8gL2Rldi9udWxs
IC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1iaW5hcnkgQC0gIiAr
IHNoZWxscShlbmRwb2ludCArIHBhdGgpOwogIEZJTEUgKmZwID0gcG9wZW4oY21kLmNfc3RyKCks
ICJ3Iik7IGlmICghZnApIHJldHVybiBmYWxzZTsKICBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJv
ZHkuc2l6ZSgpLCBmcCk7CiAgaW50IHJjID0gcGNsb3NlKGZwKTsKICByZXR1cm4gV0lGRVhJVEVE
KHJjKSAmJiBXRVhJVFNUQVRVUyhyYykgPT0gMDsKfQoKc3RhdGljIHZvaWQgKnNoaXBfd29ya2Vy
X3RocmVhZCh2b2lkICopIHsKICBkb3VibGUgbmV4dF9zbG90ID0gd2FsbF9zZWNvbmRzKCk7CiAg
ZG91YmxlIG5leHRfc3RhdHNfc2xvdCA9IHdhbGxfc2Vjb25kcygpOwogIHdoaWxlIChnX3J1bm5p
bmcgfHwgIWdfc2hpcF9idWYuZW1wdHkoKSB8fCAhZ19wZW5kaW5nX3N0YXRzX2JvZHkuZW1wdHko
KSkgewogICAgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoOwogICAgc3RkOjpzdHJpbmcg
c3RhdHNfYm9keTsKICAgIHB0aHJlYWRfbXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsK
ICAgIHdoaWxlIChnX3J1bm5pbmcgJiYgZ19zaGlwX2J1Zi5lbXB0eSgpICYmIGdfcGVuZGluZ19z
dGF0c19ib2R5LmVtcHR5KCkpIHsKICAgICAgc3RydWN0IHRpbWVzcGVjIHRzOwogICAgICBjbG9j
a19nZXR0aW1lKENMT0NLX1JFQUxUSU1FLCAmdHMpOwogICAgICB0cy50dl9zZWMgKz0gMTsKICAg
ICAgcHRocmVhZF9jb25kX3RpbWVkd2FpdCgmZ19zaGlwX3F1ZXVlX2NvbmQsICZnX3NoaXBfcXVl
dWVfbXV0ZXgsICZ0cyk7CiAgICB9CiAgICBpZiAoIWdfcGVuZGluZ19zdGF0c19ib2R5LmVtcHR5
KCkpIHsKICAgICAgc3RhdHNfYm9keS5zd2FwKGdfcGVuZGluZ19zdGF0c19ib2R5KTsKICAgIH0K
ICAgIGlmICghZ19zaGlwX2J1Zi5lbXB0eSgpKSB7CiAgICAgIHNpemVfdCBuID0gYm91bmRlZF9i
YXRjaF9jb3VudChnX3NoaXBfYnVmLCBnX3NoaXBfbm9kZSk7CiAgICAgIGlmICghbikgewogICAg
ICAgIGdfc2hpcF9idWYuZXJhc2UoZ19zaGlwX2J1Zi5iZWdpbigpKTsKICAgICAgICArK2dfZXZl
bnRzX2Ryb3BwZWQ7CiAgICAgICAgKytnX2Ryb3Bfb3ZlcnNpemVkOwogICAgICB9IGVsc2Ugewog
ICAgICAgIGJhdGNoLmFzc2lnbihnX3NoaXBfYnVmLmJlZ2luKCksIGdfc2hpcF9idWYuYmVnaW4o
KSArIG4pOwogICAgICAgIGdfc2hpcF9idWYuZXJhc2UoZ19zaGlwX2J1Zi5iZWdpbigpLCBnX3No
aXBfYnVmLmJlZ2luKCkgKyBuKTsKICAgICAgfQogICAgfQogICAgcHRocmVhZF9tdXRleF91bmxv
Y2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CgogICAgaWYgKCFzdGF0c19ib2R5LmVtcHR5KCkpIHsK
ICAgICAgaWYgKCFwb3N0X2JvZHkoZ19lbmRwb2ludCwgIi9hcGkvYWdlbnQvc3RhdHMiLCBzdGF0
c19ib2R5LCAyLCAmbmV4dF9zdGF0c19zbG90KSkgewogICAgICAgIHB0aHJlYWRfbXV0ZXhfbG9j
aygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgICArK2dfc3RhdHNfZHJvcHBlZDsKICAgICAg
ICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgICAgfQogICAg
fQoKICAgIGlmICghYmF0Y2guZW1wdHkoKSkgewogICAgICBzdGQ6OnN0cmluZyBib2R5ID0gIntc
Im5vZGVcIjoiICsganNvbnEoZ19zaGlwX25vZGUpICsgIixcImV2ZW50c1wiOiIgKyBqc29uX2Fy
cmF5KGJhdGNoKSArICJ9IjsKICAgICAgaWYgKHBvc3RfYm9keShnX2VuZHBvaW50LCAiL2FwaS9p
bmdlc3QiLCBib2R5LCAxMCwgJm5leHRfc2xvdCkpIHsKICAgICAgICBwdGhyZWFkX211dGV4X2xv
Y2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICAgICAgZ19ldmVudHNfcHVzaGVkICs9IGJhdGNo
LnNpemUoKTsKICAgICAgICArK2dfYmF0Y2hlc19wdXNoZWQ7CiAgICAgICAgZ19ieXRlc19wdXNo
ZWQgKz0gYm9keS5zaXplKCk7CiAgICAgICAgZ19jb25zZWN1dGl2ZV9mYWlsdXJlcyA9IDA7CiAg
ICAgICAgZ19sYXN0X3B1c2hfc3RhdHVzID0gMjAwOwogICAgICAgIGdfbGFzdF9zdWNjZXNzX2F0
ID0gdGltZShOVUxMKTsKICAgICAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVl
X211dGV4KTsKICAgICAgfSBlbHNlIHsKICAgICAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hp
cF9xdWV1ZV9tdXRleCk7CiAgICAgICAgZ19ldmVudHNfZHJvcHBlZCArPSBiYXRjaC5zaXplKCk7
CiAgICAgICAgZ19kcm9wX2h1YiArPSBiYXRjaC5zaXplKCk7CiAgICAgICAgKytnX2JhdGNoZXNf
ZmFpbGVkOwogICAgICAgICsrZ19jb25zZWN1dGl2ZV9mYWlsdXJlczsKICAgICAgICBnX2xhc3Rf
cHVzaF9zdGF0dXMgPSAwOwogICAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVl
dWVfbXV0ZXgpOwogICAgICB9CiAgICB9CgogICAgaWYgKCFnX3J1bm5pbmcpIHsKICAgICAgcHRo
cmVhZF9tdXRleF9sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgICBpZiAoZ19jb25zZWN1
dGl2ZV9mYWlsdXJlcyA+PSAzKSB7CiAgICAgICAgZ19ldmVudHNfZHJvcHBlZCArPSBnX3NoaXBf
YnVmLnNpemUoKTsKICAgICAgICBnX2Ryb3BfaHViICs9IGdfc2hpcF9idWYuc2l6ZSgpOwogICAg
ICAgIGdfc2hpcF9idWYuY2xlYXIoKTsKICAgICAgICBnX3BlbmRpbmdfc3RhdHNfYm9keS5jbGVh
cigpOwogICAgICB9CiAgICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0
ZXgpOwogICAgfQogIH0KICByZXR1cm4gTlVMTDsKfQoKc3RhdGljIHVuc2lnbmVkIGNvdW50X29w
ZW5fZmRzKCkgewogIERJUiAqZGlyID0gb3BlbmRpcigiL3Byb2Mvc2VsZi9mZCIpOwogIGlmICgh
ZGlyKSByZXR1cm4gMDsKICB1bnNpZ25lZCBjb3VudCA9IDA7CiAgc3RydWN0IGRpcmVudCAqZW50
cnk7CiAgd2hpbGUgKChlbnRyeSA9IHJlYWRkaXIoZGlyKSkgIT0gTlVMTCkgewogICAgaWYgKHN0
cmNtcChlbnRyeS0+ZF9uYW1lLCAiLiIpICYmIHN0cmNtcChlbnRyeS0+ZF9uYW1lLCAiLi4iKSkg
Kytjb3VudDsKICB9CiAgY2xvc2VkaXIoZGlyKTsKICByZXR1cm4gY291bnQ7Cn0KCnN0YXRpYyB2
b2lkIHByb2Nfc3RhdHVzKHNpemVfdCAqcnNzLCBzaXplX3QgKnZpcnQsIHVuc2lnbmVkICp0aHJl
YWRzLAogICAgICAgICAgICAgICAgICAgICAgICB1bnNpZ25lZCAqY3B1X2NvcmUpIHsKICAqcnNz
ID0gMDsgKnZpcnQgPSAwOyAqdGhyZWFkcyA9IDE7ICpjcHVfY29yZSA9IDA7CiAgc3RkOjppZnN0
cmVhbSBpbigiL3Byb2Mvc2VsZi9zdGF0dXMiKTsKICBzdGQ6OnN0cmluZyBsaW5lOwogIHdoaWxl
IChzdGQ6OmdldGxpbmUoaW4sIGxpbmUpKSB7CiAgICB1bnNpZ25lZCBsb25nIHZhbHVlID0gMDsK
ICAgIGlmIChzc2NhbmYobGluZS5jX3N0cigpLCAiVm1SU1M6ICVsdSBrQiIsICZ2YWx1ZSkgPT0g
MSkgKnJzcyA9IChzaXplX3QpdmFsdWUgKiAxMDI0VTsKICAgIGVsc2UgaWYgKHNzY2FuZihsaW5l
LmNfc3RyKCksICJWbVNpemU6ICVsdSBrQiIsICZ2YWx1ZSkgPT0gMSkgKnZpcnQgPSAoc2l6ZV90
KXZhbHVlICogMTAyNFU7CiAgICBlbHNlIGlmIChzc2NhbmYobGluZS5jX3N0cigpLCAiVGhyZWFk
czogJWx1IiwgJnZhbHVlKSA9PSAxKSAqdGhyZWFkcyA9ICh1bnNpZ25lZCl2YWx1ZTsKICAgIGVs
c2UgaWYgKHNzY2FuZihsaW5lLmNfc3RyKCksICJDcHVzX2FsbG93ZWRfbGlzdDogJWx1IiwgJnZh
bHVlKSA9PSAxKSAqY3B1X2NvcmUgPSAodW5zaWduZWQpdmFsdWU7CiAgfQp9CgpzdGF0aWMgdW5z
aWduZWQgbG9uZyBsb25nIHVwZGF0ZV9rZXJuZWxfZHJvcHMoaW50IGZkKSB7CiAgaWYgKGZkIDwg
MCkgcmV0dXJuIDA7CiAgc3RydWN0IHRwYWNrZXRfc3RhdHMgcGFja2V0X3N0YXRzOwogIHNvY2ts
ZW5fdCBwYWNrZXRfc3RhdHNfbGVuID0gc2l6ZW9mKHBhY2tldF9zdGF0cyk7CiAgbWVtc2V0KCZw
YWNrZXRfc3RhdHMsIDAsIHNpemVvZihwYWNrZXRfc3RhdHMpKTsKICBpZiAoZ2V0c29ja29wdChm
ZCwgU09MX1BBQ0tFVCwgUEFDS0VUX1NUQVRJU1RJQ1MsCiAgICAgICAgICAgICAgICAgJnBhY2tl
dF9zdGF0cywgJnBhY2tldF9zdGF0c19sZW4pICE9IDApIHJldHVybiAwOwogIGdfa2VybmVsX2Ry
b3BzICs9IHBhY2tldF9zdGF0cy50cF9kcm9wczsKICByZXR1cm4gcGFja2V0X3N0YXRzLnRwX2Ry
b3BzOwp9CgpzdGF0aWMgc3RkOjpzdHJpbmcgYWdlbnRfc3RhdHNfYm9keShpbnQgZmQsIHNpemVf
dCBmbG93c19hY3RpdmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVf
dCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBz
aXplX3Qgd3NzZV9ib2R5X2Zsb3dzKSB7CiAgZG91YmxlIG5vdyA9IHdhbGxfc2Vjb25kcygpOwog
IGRvdWJsZSBlbGFwc2VkID0gbm93IC0gZ19zdGF0c19sYXN0X2F0OwogIGlmIChlbGFwc2VkIDwg
MC4wMDEpIGVsYXBzZWQgPSAwLjAwMTsKICB1bnNpZ25lZCBsb25nIGxvbmcga2VybmVsX2Ryb3Bf
ZGVsdGEgPSB1cGRhdGVfa2VybmVsX2Ryb3BzKGZkKTsKICB1bnNpZ25lZCBsb25nIGxvbmcgcGFj
a2V0X2RlbHRhID0gZ19jYXB0dXJlX3BhY2tldHMgLSBnX3ByZXZfY2FwdHVyZV9wYWNrZXRzOwog
IHVuc2lnbmVkIGxvbmcgbG9uZyBwYWNrZXRfYnl0ZXNfZGVsdGEgPSBnX2NhcHR1cmVfYnl0ZXMg
LSBnX3ByZXZfY2FwdHVyZV9ieXRlczsKICB1bnNpZ25lZCBsb25nIGxvbmcgZW1pdHRlZF9kZWx0
YSA9IGdfZXZlbnRzX2VtaXR0ZWQgLSBnX3ByZXZfZXZlbnRzX2VtaXR0ZWQ7CgogIHB0aHJlYWRf
bXV0ZXhfbG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICB1bnNpZ25lZCBsb25nIGxvbmcgaW5f
ZGVsdGEgPSBnX2V2ZW50c19pbiAtIGdfcHJldl9ldmVudHNfaW47CiAgdW5zaWduZWQgbG9uZyBs
b25nIHB1c2hlZF9kZWx0YSA9IGdfZXZlbnRzX3B1c2hlZCAtIGdfcHJldl9ldmVudHNfcHVzaGVk
OwogIHVuc2lnbmVkIGxvbmcgbG9uZyBkcm9wcGVkX2RlbHRhID0gZ19ldmVudHNfZHJvcHBlZCAt
IGdfcHJldl9ldmVudHNfZHJvcHBlZDsKICB1bnNpZ25lZCBsb25nIGxvbmcgYmF0Y2hlc19wdXNo
ZWRfZGVsdGEgPSBnX2JhdGNoZXNfcHVzaGVkIC0gZ19wcmV2X2JhdGNoZXNfcHVzaGVkOwogIHVu
c2lnbmVkIGxvbmcgbG9uZyBiYXRjaGVzX2ZhaWxlZF9kZWx0YSA9IGdfYmF0Y2hlc19mYWlsZWQg
LSBnX3ByZXZfYmF0Y2hlc19mYWlsZWQ7CiAgdW5zaWduZWQgbG9uZyBsb25nIGJ5dGVzX2RlbHRh
ID0gZ19ieXRlc19wdXNoZWQgLSBnX3ByZXZfYnl0ZXNfcHVzaGVkOwogIHVuc2lnbmVkIGxvbmcg
bG9uZyBxdWV1ZV9kZWx0YSA9IGdfZHJvcF9xdWV1ZSAtIGdfcHJldl9kcm9wX3F1ZXVlOwogIHVu
c2lnbmVkIGxvbmcgbG9uZyBodWJfZGVsdGEgPSBnX2Ryb3BfaHViIC0gZ19wcmV2X2Ryb3BfaHVi
OwogIHVuc2lnbmVkIGxvbmcgbG9uZyBvdmVyc2l6ZWRfZGVsdGEgPSBnX2Ryb3Bfb3ZlcnNpemVk
IC0gZ19wcmV2X2Ryb3Bfb3ZlcnNpemVkOwogIHNpemVfdCBzaGlwX2J1Zl9zaXplID0gZ19zaGlw
X2J1Zi5zaXplKCk7CiAgc2l6ZV90IHF1ZXVlX2hpZ2ggPSBnX3F1ZXVlX2hpZ2hfd2F0ZXI7CiAg
dW5zaWduZWQgbGFzdF9zdGF0dXMgPSBnX2xhc3RfcHVzaF9zdGF0dXM7CiAgdGltZV90IGxhc3Rf
c3VjYyA9IGdfbGFzdF9zdWNjZXNzX2F0OwogIHVuc2lnbmVkIGNvbnNlY19mYWlscyA9IGdfY29u
c2VjdXRpdmVfZmFpbHVyZXM7CiAgdW5zaWduZWQgbG9uZyBsb25nIHN0YXRzX2Ryb3AgPSBnX3N0
YXRzX2Ryb3BwZWQ7CiAgcHRocmVhZF9tdXRleF91bmxvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CgogIHVuc2lnbmVkIGxvbmcgbG9uZyBwaXBlX2Ryb3BfZGVsdGEgPSBnX291dHB1dF9waXBlX2Ry
b3BzIC0gZ19wcmV2X291dHB1dF9waXBlX2Ryb3BzOwogIHN0cnVjdCBydXNhZ2UgdXNhZ2U7CiAg
bWVtc2V0KCZ1c2FnZSwgMCwgc2l6ZW9mKHVzYWdlKSk7CiAgZ2V0cnVzYWdlKFJVU0FHRV9TRUxG
LCAmdXNhZ2UpOwogIGRvdWJsZSB1c2VyX2NwdSA9IHVzYWdlLnJ1X3V0aW1lLnR2X3NlYyArIHVz
YWdlLnJ1X3V0aW1lLnR2X3VzZWMgLyAxMDAwMDAwLjA7CiAgZG91YmxlIHN5c19jcHUgPSB1c2Fn
ZS5ydV9zdGltZS50dl9zZWMgKyB1c2FnZS5ydV9zdGltZS50dl91c2VjIC8gMTAwMDAwMC4wOwog
IGRvdWJsZSBjcHVfdG90YWwgPSB1c2VyX2NwdSArIHN5c19jcHU7CiAgZG91YmxlIGNwdV9wY3Qg
PSAxMDAuMCAqIChjcHVfdG90YWwgLSBnX3N0YXRzX2xhc3RfY3B1KSAvIGVsYXBzZWQ7CiAgaWYg
KGNwdV9wY3QgPCAwKSBjcHVfcGN0ID0gMDsKICBzaXplX3QgcnNzID0gMCwgdmlydCA9IDA7CiAg
dW5zaWduZWQgdGhyZWFkcyA9IDEsIGNwdV9jb3JlID0gMDsKICBwcm9jX3N0YXR1cygmcnNzLCAm
dmlydCwgJnRocmVhZHMsICZjcHVfY29yZSk7CiAgc3RkOjpzdHJpbmcgcmVhc29uczsKICBpZiAo
a2VybmVsX2Ryb3BfZGVsdGEpIHJlYXNvbnMgKz0gIlwia2VybmVsX2Ryb3BcIiI7CiAgaWYgKGRy
b3BwZWRfZGVsdGEpIHsgaWYgKCFyZWFzb25zLmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFz
b25zICs9ICJcInNoaXBfZHJvcFwiIjsgfQogIGlmIChodWJfZGVsdGEpIHsgaWYgKCFyZWFzb25z
LmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcImh1Yl91bnJlYWNoYWJsZVwi
IjsgfQogIGlmIChxdWV1ZV9kZWx0YSB8fCBwaXBlX2Ryb3BfZGVsdGEpIHsgaWYgKCFyZWFzb25z
LmVtcHR5KCkpIHJlYXNvbnMgKz0gIiwiOyByZWFzb25zICs9ICJcInF1ZXVlX3ByZXNzdXJlXCIi
OyB9CiAgc3RkOjpvc3RyaW5nc3RyZWFtIG91dDsKICBvdXQgPDwgIntcInNjaGVtYV92ZXJzaW9u
XCI6MSxcInR5cGVcIjpcImFnZW50X3N0YXRzXCIsXCJub2RlXCI6IiA8PCBqc29ucShnX3NoaXBf
bm9kZSkKICAgICAgPDwgIixcImluc3RhbmNlX2lkXCI6IiA8PCBqc29ucShnX2luc3RhbmNlX2lk
KSA8PCAiLFwic2VxdWVuY2VcIjoiIDw8ICsrZ19zdGF0c19zZXF1ZW5jZQogICAgICA8PCAiLFwi
b2JzZXJ2ZWRfYXRcIjoiIDw8ICh1bnNpZ25lZCBsb25nKW5vdyA8PCAiLFwid2luZG93X3NlY29u
ZHNcIjoiIDw8IGRvdWJsZV9zdHJpbmcoZWxhcHNlZCkKICAgICAgPDwgIixcIm1vZGVcIjpcImNw
cFwiLFwic3RhdHVzXCI6IiA8PCAocmVhc29ucy5lbXB0eSgpID8gIlwib2tcIiIgOiAiXCJkZWdy
YWRlZFwiIikKICAgICAgPDwgIixcInJlYXNvbnNcIjpbIiA8PCByZWFzb25zIDw8ICJdLFwiY2Fw
dHVyZVwiOnsiCiAgICAgIDw8ICJcInBhY2tldHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19j
YXB0dXJlX3BhY2tldHMpIDw8ICIsXCJwYWNrZXRzX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHBh
Y2tldF9kZWx0YSkKICAgICAgPDwgIixcInBhY2tldF9ieXRlc190b3RhbFwiOiIgPDwgdWxsX3N0
cmluZyhnX2NhcHR1cmVfYnl0ZXMpIDw8ICIsXCJwYWNrZXRfYnl0ZXNfZGVsdGFcIjoiIDw8IHVs
bF9zdHJpbmcocGFja2V0X2J5dGVzX2RlbHRhKQogICAgICA8PCAiLFwia2VybmVsX2Ryb3BzX3Rv
dGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdfa2VybmVsX2Ryb3BzKSA8PCAiLFwia2VybmVsX2Ryb3Bz
X2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGtlcm5lbF9kcm9wX2RlbHRhKQogICAgICA8PCAiLFwi
a2VybmVsX2Ryb3BfcGVyY2VudFwiOiIgPDwgZG91YmxlX3N0cmluZygxMDAuMCAqIGtlcm5lbF9k
cm9wX2RlbHRhIC8gKHBhY2tldF9kZWx0YSA/IHBhY2tldF9kZWx0YSA6IDEpKQogICAgICA8PCAi
LFwiaW52YWxpZF9mcmFtZXNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19pbnZhbGlkX2ZyYW1l
cykKICAgICAgPDwgIixcImV2ZW50c19lbWl0dGVkX3RvdGFsXCI6IiA8PCB1bGxfc3RyaW5nKGdf
ZXZlbnRzX2VtaXR0ZWQpIDw8ICIsXCJldmVudHNfZW1pdHRlZF9kZWx0YVwiOiIgPDwgdWxsX3N0
cmluZyhlbWl0dGVkX2RlbHRhKQogICAgICA8PCAiLFwiZmxvd3NfYWN0aXZlXCI6IiA8PCBmbG93
c19hY3RpdmUgPDwgIixcInBlbmRpbmdfcmVxdWVzdHNcIjoiIDw8IHBlbmRpbmdfcmVxdWVzdHMK
ICAgICAgPDwgIixcIndzc2VfYm9keV9mbG93c19hY3RpdmVcIjoiIDw8IHdzc2VfYm9keV9mbG93
cwogICAgICA8PCAiLFwid3NzZV9ib2R5X2J5dGVzXCI6IiA8PCBnX3dzc2VfYm9keV9ieXRlcwog
ICAgICA8PCAiLFwib3V0cHV0X3BpcGVfZHJvcHNfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19v
dXRwdXRfcGlwZV9kcm9wcykKICAgICAgPDwgIixcIm91dHB1dF9waXBlX2Ryb3BzX2RlbHRhXCI6
IiA8PCB1bGxfc3RyaW5nKHBpcGVfZHJvcF9kZWx0YSkgPDwgIn0sXCJzaGlwcGluZ1wiOnsiCiAg
ICAgIDw8ICJcImV2ZW50c19pbl90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2V2ZW50c19pbikg
PDwgIixcImV2ZW50c19pbl9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhpbl9kZWx0YSkKICAgICAg
PDwgIixcImV2ZW50c19wdXNoZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ldmVudHNfcHVz
aGVkKSA8PCAiLFwiZXZlbnRzX3B1c2hlZF9kZWx0YVwiOiIgPDwgdWxsX3N0cmluZyhwdXNoZWRf
ZGVsdGEpCiAgICAgIDw8ICIsXCJldmVudHNfZHJvcHBlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmlu
ZyhnX2V2ZW50c19kcm9wcGVkKSA8PCAiLFwiZXZlbnRzX2Ryb3BwZWRfZGVsdGFcIjoiIDw8IHVs
bF9zdHJpbmcoZHJvcHBlZF9kZWx0YSkKICAgICAgPDwgIixcImRyb3BfY2F1c2VzXCI6e1wicXVl
dWVfZnVsbF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2Ryb3BfcXVldWUpIDw8ICIsXCJxdWV1
ZV9mdWxsX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKHF1ZXVlX2RlbHRhKQogICAgICA8PCAiLFwi
aHViX2ZhaWx1cmVfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19kcm9wX2h1YikgPDwgIixcImh1
Yl9mYWlsdXJlX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKGh1Yl9kZWx0YSkKICAgICAgPDwgIixc
Im92ZXJzaXplZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2Ryb3Bfb3ZlcnNpemVkKSA8PCAi
LFwib3ZlcnNpemVkX2RlbHRhXCI6IiA8PCB1bGxfc3RyaW5nKG92ZXJzaXplZF9kZWx0YSkgPDwg
In0iCiAgICAgIDw8ICIsXCJiYXRjaGVzX3B1c2hlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhn
X2JhdGNoZXNfcHVzaGVkKSA8PCAiLFwiYmF0Y2hlc19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9z
dHJpbmcoYmF0Y2hlc19wdXNoZWRfZGVsdGEpCiAgICAgIDw8ICIsXCJiYXRjaGVzX2ZhaWxlZF90
b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhnX2JhdGNoZXNfZmFpbGVkKSA8PCAiLFwiYmF0Y2hlc19m
YWlsZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYmF0Y2hlc19mYWlsZWRfZGVsdGEpCiAgICAg
IDw8ICIsXCJieXRlc19wdXNoZWRfdG90YWxcIjoiIDw8IHVsbF9zdHJpbmcoZ19ieXRlc19wdXNo
ZWQpIDw8ICIsXCJieXRlc19wdXNoZWRfZGVsdGFcIjoiIDw8IHVsbF9zdHJpbmcoYnl0ZXNfZGVs
dGEpCiAgICAgIDw8ICIsXCJwdXNoX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3Ry
aW5nKHB1c2hlZF9kZWx0YSAvIGVsYXBzZWQpCiAgICAgIDw8ICIsXCJwdXNoX2ticHNcIjoiIDw8
IGRvdWJsZV9zdHJpbmcoOC4wICogYnl0ZXNfZGVsdGEgLyAoMTAwMC4wICogZWxhcHNlZCkpCiAg
ICAgIDw8ICIsXCJkcm9wX2V2ZW50c19wZXJfc2Vjb25kXCI6IiA8PCBkb3VibGVfc3RyaW5nKGRy
b3BwZWRfZGVsdGEgLyBlbGFwc2VkKQogICAgICA8PCAiLFwiZHJvcF9wZXJjZW50XCI6IiA8PCBk
b3VibGVfc3RyaW5nKDEwMC4wICogZHJvcHBlZF9kZWx0YSAvIChpbl9kZWx0YSA/IGluX2RlbHRh
IDogMSkpCiAgICAgIDw8ICIsXCJxdWV1ZV9kZXB0aF9ldmVudHNcIjoiIDw8IHNoaXBfYnVmX3Np
emUgPDwgIixcInF1ZXVlX2NhcGFjaXR5X2V2ZW50c1wiOiIgPDwgTUFYX1FVRVVFCiAgICAgIDw8
ICIsXCJxdWV1ZV9oaWdoX3dhdGVyX2V2ZW50c1wiOiIgPDwgcXVldWVfaGlnaCA8PCAiLFwibGFz
dF9wdXNoX2h0dHBfc3RhdHVzXCI6IiA8PCBsYXN0X3N0YXR1cwogICAgICA8PCAiLFwibGFzdF9z
dWNjZXNzX2F0XCI6IiA8PCAodW5zaWduZWQgbG9uZylsYXN0X3N1Y2MgPDwgIixcImNvbnNlY3V0
aXZlX2ZhaWx1cmVzXCI6IiA8PCBjb25zZWNfZmFpbHMKICAgICAgPDwgIixcInN0YXRzX3NhbXBs
ZXNfZHJvcHBlZF90b3RhbFwiOiIgPDwgdWxsX3N0cmluZyhzdGF0c19kcm9wKSA8PCAifSxcInJl
c291cmNlc1wiOnsiCiAgICAgIDw8ICJcImNwdV91c2VyX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9z
dHJpbmcodXNlcl9jcHUpIDw8ICIsXCJjcHVfc3lzdGVtX3NlY29uZHNcIjoiIDw8IGRvdWJsZV9z
dHJpbmcoc3lzX2NwdSkKICAgICAgPDwgIixcImNwdV9wZXJjZW50X29uZV9jb3JlXCI6IiA8PCBk
b3VibGVfc3RyaW5nKGNwdV9wY3QpIDw8ICIsXCJyc3NfYnl0ZXNcIjoiIDw8IHJzcwogICAgICA8
PCAiLFwidmlydHVhbF9ieXRlc1wiOiIgPDwgdmlydCA8PCAiLFwib3Blbl9mZHNcIjoiIDw8IGNv
dW50X29wZW5fZmRzKCkgPDwgIixcInRocmVhZHNcIjoiIDw8IHRocmVhZHMKICAgICAgPDwgIn0s
XCJsaW1pdHNcIjp7XCJjcHVfY29yZVwiOiIgPDwgY3B1X2NvcmUgPDwgIixcImFkZHJlc3Nfc3Bh
Y2VfYnl0ZXNcIjoyNjg0MzU0NTYiCiAgICAgIDw8ICIsXCJzaGlwX3JhdGVfa2Jwc1wiOiIgPDwg
Z19zaGlwX3JhdGVfa2JwcyA8PCAiLFwiaHR0cF9ib2R5X21heF9ieXRlc1wiOiIgPDwgTUFYX1BP
U1RfQllURVMKICAgICAgPDwgIixcInNoaXBfdGhyZWFkc19tYXhcIjoxLFwid3NzZV9ib2R5X2J5
dGVzXCI6IiA8PCBnX3dzc2VfYm9keV9ieXRlcyA8PCAifX0iOwogIGdfcHJldl9jYXB0dXJlX3Bh
Y2tldHMgPSBnX2NhcHR1cmVfcGFja2V0czsgZ19wcmV2X2NhcHR1cmVfYnl0ZXMgPSBnX2NhcHR1
cmVfYnl0ZXM7CiAgZ19wcmV2X2V2ZW50c19lbWl0dGVkID0gZ19ldmVudHNfZW1pdHRlZDsKICBw
dGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgZ19wcmV2X2V2ZW50c19p
biA9IGdfZXZlbnRzX2luOwogIGdfcHJldl9ldmVudHNfcHVzaGVkID0gZ19ldmVudHNfcHVzaGVk
OyBnX3ByZXZfZXZlbnRzX2Ryb3BwZWQgPSBnX2V2ZW50c19kcm9wcGVkOwogIGdfcHJldl9iYXRj
aGVzX3B1c2hlZCA9IGdfYmF0Y2hlc19wdXNoZWQ7IGdfcHJldl9iYXRjaGVzX2ZhaWxlZCA9IGdf
YmF0Y2hlc19mYWlsZWQ7CiAgZ19wcmV2X2J5dGVzX3B1c2hlZCA9IGdfYnl0ZXNfcHVzaGVkOyBn
X3ByZXZfZHJvcF9xdWV1ZSA9IGdfZHJvcF9xdWV1ZTsKICBnX3ByZXZfZHJvcF9odWIgPSBnX2Ry
b3BfaHViOyBnX3ByZXZfZHJvcF9vdmVyc2l6ZWQgPSBnX2Ryb3Bfb3ZlcnNpemVkOwogIHB0aHJl
YWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogIGdfcHJldl9vdXRwdXRfcGlw
ZV9kcm9wcyA9IGdfb3V0cHV0X3BpcGVfZHJvcHM7CiAgZ19zdGF0c19sYXN0X2NwdSA9IGNwdV90
b3RhbDsgZ19zdGF0c19sYXN0X2F0ID0gbm93OwogIHJldHVybiBvdXQuc3RyKCk7Cn0KCnN0YXRp
YyB2b2lkIHNlbmRfYWdlbnRfc3RhdHMoaW50IGZkLCBzaXplX3QgZmxvd3NfYWN0aXZlLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIHNpemVfdCB3c3NlX2JvZHlfZmxvd3MpIHsKICBzdGQ6OnN0
cmluZyBib2R5ID0gYWdlbnRfc3RhdHNfYm9keShmZCwgZmxvd3NfYWN0aXZlLCBwZW5kaW5nX3Jl
cXVlc3RzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdzc2VfYm9keV9m
bG93cyk7CiAgaWYgKGJvZHkuc2l6ZSgpID4gTUFYX1NUQVRTX0JZVEVTKSB7CiAgICBwdGhyZWFk
X211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgICArK2dfc3RhdHNfZHJvcHBlZDsK
ICAgIHB0aHJlYWRfbXV0ZXhfdW5sb2NrKCZnX3NoaXBfcXVldWVfbXV0ZXgpOwogICAgcmV0dXJu
OwogIH0KICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7CiAgZ19wZW5k
aW5nX3N0YXRzX2JvZHkgPSBib2R5OwogIHB0aHJlYWRfY29uZF9zaWduYWwoJmdfc2hpcF9xdWV1
ZV9jb25kKTsKICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKfQoK
c3RhdGljIGJvb2wgd3JpdGVfbm9uYmxvY2tpbmdfbGluZShjb25zdCBzdGQ6OnN0cmluZyAmbGlu
ZSkgewogIGlmIChsaW5lLnNpemUoKSArIDEgPiBQSVBFX0JVRikgewogICAgKytnX291dHB1dF9w
aXBlX2Ryb3BzOwogICAgcmV0dXJuIHRydWU7CiAgfQogIHN0ZDo6c3RyaW5nIGZyYW1lZCA9IGxp
bmUgKyAiXG4iOwogIHNzaXplX3Qgd3JpdHRlbjsKICBkbyB7IHdyaXR0ZW4gPSB3cml0ZShTVERP
VVRfRklMRU5PLCBmcmFtZWQuZGF0YSgpLCBmcmFtZWQuc2l6ZSgpKTsgfQogIHdoaWxlICh3cml0
dGVuIDwgMCAmJiBlcnJubyA9PSBFSU5UUiAmJiBnX3J1bm5pbmcpOwogIGlmICh3cml0dGVuID09
IChzc2l6ZV90KWZyYW1lZC5zaXplKCkpIHJldHVybiB0cnVlOwogIGlmICh3cml0dGVuIDwgMCAm
JiAoZXJybm8gPT0gRUFHQUlOIHx8IGVycm5vID09IEVXT1VMREJMT0NLKSkgewogICAgKytnX291
dHB1dF9waXBlX2Ryb3BzOwogICAgcmV0dXJuIHRydWU7CiAgfQogIGlmICh3cml0dGVuIDwgMCAm
JiBlcnJubyA9PSBFUElQRSkgewogICAgbG9nbXNnKCJzaGlwcGVyIHBpcGUgY2xvc2VkOyBzdG9w
cGluZyBjYXB0dXJlIGZvciBzdXBlcnZpc2VkIHJlc3RhcnQiKTsKICB9IGVsc2UgewogICAgbG9n
bXNnKCJzaGlwcGVyIHBpcGUgd3JpdGUgZmFpbGVkOyBzdG9wcGluZyBjYXB0dXJlIGZvciBzdXBl
cnZpc2VkIHJlc3RhcnQiKTsKICB9CiAgZ19ydW5uaW5nID0gMDsKICByZXR1cm4gZmFsc2U7Cn0K
CnN0YXRpYyB2b2lkIGVtaXRfY2FwdHVyZV9zdGF0c19pbnRlcm5hbChpbnQgZmQsIHNpemVfdCBm
bG93c19hY3RpdmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXpl
X3QgcGVuZGluZ19yZXF1ZXN0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIHNpemVfdCB3c3NlX2JvZHlfZmxvd3MpIHsKICBzdGQ6OnN0cmluZyBmdWxsID0gYWdlbnRf
c3RhdHNfYm9keShmZCwgZmxvd3NfYWN0aXZlLCBwZW5kaW5nX3JlcXVlc3RzLAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdzc2VfYm9keV9mbG93cyk7CiAgY29uc3Qgc3Rk
OjpzdHJpbmcgbWFya2VyID0gIlwiY2FwdHVyZVwiOiI7CiAgc2l6ZV90IHN0YXJ0ID0gZnVsbC5m
aW5kKG1hcmtlcik7CiAgc2l6ZV90IGVuZCA9IGZ1bGwuZmluZCgiLFwic2hpcHBpbmdcIjoiLCBz
dGFydCk7CiAgaWYgKHN0YXJ0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IGVuZCA9PSBzdGQ6OnN0
cmluZzo6bnBvcykgewogICAgKytnX291dHB1dF9waXBlX2Ryb3BzOwogICAgcmV0dXJuOwogIH0K
ICBzdGFydCArPSBtYXJrZXIuc2l6ZSgpOwogIHdyaXRlX25vbmJsb2NraW5nX2xpbmUoIntcIl9u
dF9pbnRlcm5hbFwiOlwiY2FwdHVyZV9zdGF0c192MVwiLFwiY2FwdHVyZVwiOiIgKwogICAgICAg
ICAgICAgICAgICAgICAgICAgZnVsbC5zdWJzdHIoc3RhcnQsIGVuZCAtIHN0YXJ0KSArICJ9Iik7
Cn0KCnN0YXRpYyB2b2lkIGVtaXRfZXZlbnQoY29uc3QgRXZlbnQgJmUpIHsKICBzdGQ6Om9zdHJp
bmdzdHJlYW0gc3M7CiAgc3MgPDwgIntcInRzXCI6IiA8PCBlLnRzIDw8ICIsXCJob3N0XCI6IiA8
PCBqc29ucShlLmhvc3QpIDw8ICIsXCJzcmNcIjpcInBjYXBcIixcInNlcnZpY2VcIjoiIDw8IGpz
b25xKGUuc2VydmljZSkKICAgICA8PCAiLFwibWV0aG9kXCI6IiA8PCBqc29ucShlLm1ldGhvZCkg
PDwgIixcInBhdGhcIjoiIDw8IGpzb25xKGUucGF0aCkgPDwgIixcInVzZXJcIjoiIDw8IGpzb25x
KGUudXNlcikKICAgICA8PCAiLFwic2NoZW1lXCI6IiA8PCBqc29ucShlLnNjaGVtZSkKICAgICA8
PCAiLFwiYmFzaWNfdXNlclwiOiIgPDwgKGUuYmFzaWNfdXNlci5lbXB0eSgpID8gIm51bGwiIDog
anNvbnEoZS5iYXNpY191c2VyKSkKICAgICA8PCAiLFwid3NzZV91c2VyXCI6IiA8PCAoZS53c3Nl
X3VzZXIuZW1wdHkoKSA/ICJudWxsIiA6IGpzb25xKGUud3NzZV91c2VyKSkKICAgICA8PCAiLFwi
c291cmNlX3Byb2JlXCI6XCJwY2FwLWh0dHAtY3BwXCIsXCJob3N0X2hkclwiOiIgPDwganNvbnEo
ZS5ob3N0X2hkcikKICAgICA8PCAiLFwidXNlcl9hZ2VudFwiOiIgPDwganNvbnEoZS51c2VyX2Fn
ZW50KSA8PCAiLFwieF9mb3J3YXJkZWRfZm9yXCI6IiA8PCBqc29ucShlLnhmZikKICAgICA8PCAi
LFwiY2FsbGVyXCI6IiA8PCBqc29ucShlLmNhbGxlcikgPDwgIixcImNhbGxlcl9wb3J0XCI6IiA8
PCBlLmNhbGxlcl9wb3J0IDw8ICIsXCJkc3RfaXBcIjoiIDw8IGpzb25xKGUuZHN0X2lwKQogICAg
IDw8ICIsXCJkc3RfcG9ydFwiOiIgPDwgZS5kc3RfcG9ydCA8PCAiLFwidHJhY2VwYXJlbnRcIjoi
IDw8IGpzb25xKGUudHJhY2VwYXJlbnQpIDw8ICIsXCJ0cmFjZV9pZFwiOiIgPDwganNvbnEoZS50
cmFjZV9pZCkKICAgICA8PCAiLFwic2VydmljZV9pZFwiOm51bGwsXCJtb2R1bGVfaWRcIjpcInBj
YXAtaHR0cC1jcHBcIixcInJlcV9ieXRlc1wiOiIgPDwgZS5yZXFfYnl0ZXM7CiAgaWYgKGUuaGFz
X3N0YXR1cykgc3MgPDwgIixcInN0YXR1c1wiOiIgPDwgZS5zdGF0dXM7IGVsc2Ugc3MgPDwgIixc
InN0YXR1c1wiOm51bGwiOwogIGlmIChlLmhhc19kdXJhdGlvbikgc3MgPDwgIixcImR1cmF0aW9u
X21zXCI6IiA8PCBlLmR1cmF0aW9uX21zOyBlbHNlIHNzIDw8ICIsXCJkdXJhdGlvbl9tc1wiOm51
bGwiOwogIGlmIChlLmhhc19yZXNwKSBzcyA8PCAiLFwicmVzcF9ieXRlc1wiOiIgPDwgZS5yZXNw
X2J5dGVzOyBlbHNlIHNzIDw8ICIsXCJyZXNwX2J5dGVzXCI6bnVsbCI7CiAgc3MgPDwgIn0iOwog
ICsrZ19ldmVudHNfZW1pdHRlZDsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgICsr
Z19ldmVudHNfaW47CiAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CiAgICBpZiAoZ19zaGlwX2J1Zi5zaXplKCkgPj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9i
dWYuZXJhc2UoZ19zaGlwX2J1Zi5iZWdpbigpKTsKICAgICAgKytnX2V2ZW50c19kcm9wcGVkOwog
ICAgICArK2dfZHJvcF9xdWV1ZTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNrKHNzLnN0
cigpKTsKICAgIGlmIChnX3NoaXBfYnVmLnNpemUoKSA+IGdfcXVldWVfaGlnaF93YXRlcikgZ19x
dWV1ZV9oaWdoX3dhdGVyID0gZ19zaGlwX2J1Zi5zaXplKCk7CiAgICBwdGhyZWFkX2NvbmRfc2ln
bmFsKCZnX3NoaXBfcXVldWVfY29uZCk7CiAgICBwdGhyZWFkX211dGV4X3VubG9jaygmZ19zaGlw
X3F1ZXVlX211dGV4KTsKICB9IGVsc2UgewogICAgd3JpdGVfbm9uYmxvY2tpbmdfbGluZShzcy5z
dHIoKSk7CiAgfQp9CgpzdGF0aWMgdm9pZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1
aW50MzJfdCBzX2lwLCB1bnNpZ25lZCBzcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1
aW50MzJfdCBkX2lwLCB1bnNpZ25lZCBkcG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBz
dGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcsCiAgICAg
ICAgICAgICAgICAgICAgICAgICAgbG9uZyBsb25nIGZpcnN0X2J5dGVfbW9ub19tcyA9IDAsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgdWludDMyX3QgZ2VuID0gMCkgewogIFBhY2tldEtleSBy
azsKICByay5zX2lwID0gZF9pcDsgcmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgcmsuZF9p
cCA9IHNfaXA7IHJrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwoKICBsb25nIGxvbmcgbW9ub19u
b3cgPSBub3dfbW9ub3RvbmljX21zKCk7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbW9ubyA9IChmaXJz
dF9ieXRlX21vbm9fbXMgPiAwKSA/IGZpcnN0X2J5dGVfbW9ub19tcyA6IG1vbm9fbm93OwoKICB3
aGlsZSAoZ190b3RhbF9wZW5kaW5nX2NvdW50ID49IE1BWF9QRU5ESU5HX1RPVEFMICYmICFnX3Bl
bmRpbmdfZmlmby5lbXB0eSgpKSB7CiAgICBQZW5kaW5nUXVldWVSZWYgcmVmID0gZ19wZW5kaW5n
X2ZpZm8uZnJvbnQoKTsKICAgIGdfcGVuZGluZ19maWZvLnBvcF9mcm9udCgpOwogICAgc3RkOjpt
YXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9IHBlbmRp
bmcuZmluZChyZWYua2V5KTsKICAgIGlmIChpdCAhPSBwZW5kaW5nLmVuZCgpKSB7CiAgICAgIGZv
ciAoc2l6ZV90IGkgPSAwOyBpIDwgaXQtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICAgIGlm
IChpdC0+c2Vjb25kW2ldLnJlcV9pZCA9PSByZWYucmVxX2lkKSB7CiAgICAgICAgICBlbWl0X2V2
ZW50KGl0LT5zZWNvbmRbaV0uZXYpOwogICAgICAgICAgaXQtPnNlY29uZC5lcmFzZShpdC0+c2Vj
b25kLmJlZ2luKCkgKyBpKTsKICAgICAgICAgIGlmIChnX3RvdGFsX3BlbmRpbmdfY291bnQgPiAw
KSAtLWdfdG90YWxfcGVuZGluZ19jb3VudDsKICAgICAgICAgIGlmIChpdC0+c2Vjb25kLmVtcHR5
KCkpIHBlbmRpbmcuZXJhc2UoaXQpOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICB9
CiAgICB9CiAgfQoKICBzdGQ6OnZlY3RvcjxQZW5kaW5nPiAmcXVldWUgPSBwZW5kaW5nW3JrXTsK
ICBpZiAocXVldWUuc2l6ZSgpID49IE1BWF9QRU5ESU5HX1BFUl9GTE9XKSB7CiAgICBlbWl0X2V2
ZW50KHF1ZXVlWzBdLmV2KTsKICAgIHF1ZXVlLmVyYXNlKHF1ZXVlLmJlZ2luKCkpOwogICAgaWYg
KGdfdG90YWxfcGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogIH0K
ICB1aW50NjRfdCByZXFfaWQgPSArK2dfcmVxX2lkX3NlcTsKICBxdWV1ZS5wdXNoX2JhY2soUGVu
ZGluZyhyZXFfaWQsIGdlbiwgZSwgbm93X21zKCksIHN0YXJ0ZWRfbW9ubykpOwogICsrZ190b3Rh
bF9wZW5kaW5nX2NvdW50OwoKICBQZW5kaW5nUXVldWVSZWYgbmV3X3JlZjsKICBuZXdfcmVmLnJl
cV9pZCA9IHJlcV9pZDsKICBuZXdfcmVmLmdlbmVyYXRpb24gPSBnZW47CiAgbmV3X3JlZi5rZXkg
PSByazsKICBuZXdfcmVmLnN0YXJ0ZWRfbW9ub19tcyA9IHN0YXJ0ZWRfbW9ubzsKICBnX3BlbmRp
bmdfZmlmby5wdXNoX2JhY2sobmV3X3JlZik7CgogIGlmIChnX3BlbmRpbmdfZmlmby5zaXplKCkg
PiBNQVhfUEVORElOR19UT1RBTCAqIDIpIHsKICAgIHN0ZDo6bGlzdDxQZW5kaW5nUXVldWVSZWY+
OjppdGVyYXRvciBmaSA9IGdfcGVuZGluZ19maWZvLmJlZ2luKCk7CiAgICB3aGlsZSAoZmkgIT0g
Z19wZW5kaW5nX2ZpZm8uZW5kKCkpIHsKICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZl
Y3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpdCA9IHBlbmRpbmcuZmluZChmaS0+a2V5KTsKICAg
ICAgYm9vbCBhbGl2ZSA9IGZhbHNlOwogICAgICBpZiAoaXQgIT0gcGVuZGluZy5lbmQoKSkgewog
ICAgICAgIGZvciAoc2l6ZV90IGogPSAwOyBqIDwgaXQtPnNlY29uZC5zaXplKCk7ICsraikgewog
ICAgICAgICAgaWYgKGl0LT5zZWNvbmRbal0ucmVxX2lkID09IGZpLT5yZXFfaWQpIHsKICAgICAg
ICAgICAgYWxpdmUgPSB0cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAg
ICB9CiAgICAgIH0KICAgICAgaWYgKCFhbGl2ZSkgewogICAgICAgIGZpID0gZ19wZW5kaW5nX2Zp
Zm8uZXJhc2UoZmkpOwogICAgICB9IGVsc2UgewogICAgICAgICsrZmk7CiAgICAgIH0KICAgIH0K
ICB9Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX2luY29tcGxldGVfd3NzZShzdGQ6Om1hcDxGbG93S2V5
LCBGbG93PiAmZmxvd3MsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1h
cDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBmb3IgKHN0
ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBmID0gZmxvd3MuYmVnaW4oKTsgZiAhPSBm
bG93cy5lbmQoKTsgKytmKSB7CiAgICBpZiAoZi0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpIHsKICAg
ICAgcXVldWVfcmVxdWVzdChmLT5zZWNvbmQud3NzZV9ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+
Zmlyc3Quc3BvcnQsCiAgICAgICAgICAgICAgICAgICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3Qu
ZHBvcnQsIHBlbmRpbmcsIGYtPnNlY29uZC5maXJzdF9ieXRlX21vbm9fbXMsCiAgICAgICAgICAg
ICAgICAgICAgZi0+c2Vjb25kLmdlbmVyYXRpb24pOwogICAgICBmLT5zZWNvbmQuYXdhaXRpbmdf
d3NzZSA9IGZhbHNlOwogICAgfQogICAgZi0+c2Vjb25kLmNsZWFyX2J1ZmZlcnMoKTsKICB9CiAg
Zmxvd3MuY2xlYXIoKTsKICBnX3RvdGFsX2Zsb3dfYnl0ZXMgPSAwOwp9CgpzdGF0aWMgdm9pZCBm
bHVzaF9hbGxfcGVuZGluZyhzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+
ID4gJnBlbmRpbmcpIHsKICBmb3IgKHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVu
ZGluZz4gPjo6aXRlcmF0b3IgcCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5nLmVuZCgp
OyArK3ApIHsKICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcC0+c2Vjb25kLnNpemUoKTsgKytp
KSB7CiAgICAgIGVtaXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgIH0KICB9CiAgcGVuZGlu
Zy5jbGVhcigpOwogIGdfcGVuZGluZ19maWZvLmNsZWFyKCk7CiAgZ190b3RhbF9wZW5kaW5nX2Nv
dW50ID0gMDsKfQoKc3RhdGljIHZvaWQgc3dlZXAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz4gJmZs
b3dzLAogICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBl
bmRpbmc+ID4gJnBlbmRpbmcsCiAgICAgICAgICAgICAgICAgIHRpbWVfdCBub3csIHVuc2lnbmVk
IHBlbmRpbmdfdHRsX3NlYykgewogIGZvciAoc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJh
dG9yIGYgPSBmbG93cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAgc3RkOjptYXA8
Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIGZuID0gZjsgKytmbjsKICAgIGlmICgodW5zaWduZWQp
KG5vdyAtIGYtPnNlY29uZC50b3VjaGVkKSA+IEZMT1dfVFRMKSB7CiAgICAgIGlmIChmLT5zZWNv
bmQuYXdhaXRpbmdfd3NzZSkgewogICAgICAgIHF1ZXVlX3JlcXVlc3QoZi0+c2Vjb25kLndzc2Vf
ZXZlbnQsIGYtPmZpcnN0LnNfaXAsIGYtPmZpcnN0LnNwb3J0LAogICAgICAgICAgICAgICAgICAg
ICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3QuZHBvcnQsIHBlbmRpbmcsIGYtPnNlY29uZC5maXJz
dF9ieXRlX21vbm9fbXMsCiAgICAgICAgICAgICAgICAgICAgICBmLT5zZWNvbmQuZ2VuZXJhdGlv
bik7CiAgICAgICAgZi0+c2Vjb25kLmF3YWl0aW5nX3dzc2UgPSBmYWxzZTsKICAgICAgfQogICAg
ICBmLT5zZWNvbmQuY2xlYXJfYnVmZmVycygpOwogICAgICBmbG93cy5lcmFzZShmKTsKICAgIH0K
ICAgIGYgPSBmbjsKICB9CgogIGxvbmcgbG9uZyBub3dfbW9ubyA9IG5vd19tb25vdG9uaWNfbXMo
KTsKICBsb25nIGxvbmcgdHRsX21zID0gKGxvbmcgbG9uZylwZW5kaW5nX3R0bF9zZWMgKiAxMDAw
TEw7CiAgZm9yIChzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0
ZXJhdG9yIHAgPSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTspIHsKICAgIHN0
ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcG4gPSBw
OyArK3BuOwogICAgc2l6ZV90IGkgPSAwOwogICAgd2hpbGUgKGkgPCBwLT5zZWNvbmQuc2l6ZSgp
KSB7CiAgICAgIGlmIChub3dfbW9ubyAtIHAtPnNlY29uZFtpXS5zdGFydGVkX21vbm9fbXMgPiB0
dGxfbXMpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAgICAgcC0+
c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgICAgaWYgKGdfdG90YWxf
cGVuZGluZ19jb3VudCA+IDApIC0tZ190b3RhbF9wZW5kaW5nX2NvdW50OwogICAgICB9IGVsc2Ug
ewogICAgICAgICsraTsKICAgICAgfQogICAgfQogICAgaWYgKHAtPnNlY29uZC5lbXB0eSgpKSBw
ZW5kaW5nLmVyYXNlKHApOwogICAgcCA9IHBuOwogIH0KCiAgd2hpbGUgKCFnX3BlbmRpbmdfZmlm
by5lbXB0eSgpICYmCiAgICAgICAgIChub3dfbW9ubyAtIGdfcGVuZGluZ19maWZvLmZyb250KCku
c3RhcnRlZF9tb25vX21zID4gdHRsX21zICogMkxMKSkgewogICAgZ19wZW5kaW5nX2ZpZm8ucG9w
X2Zyb250KCk7CiAgfQp9CgpzdGF0aWMgc2l6ZV90IGZpbmRfaHR0cF9zdGFydChjb25zdCBzdGQ6
OnN0cmluZyAmcykgewogIGNvbnN0IGNoYXIgKm1bXSA9IHsgIkdFVCAiLCAiUE9TVCAiLCAiUFVU
ICIsICJERUxFVEUgIiwgIlBBVENIICIsICJIRUFEICIsICJPUFRJT05TICIgfTsKICBzaXplX3Qg
YmVzdCA9IHN0ZDo6c3RyaW5nOjpucG9zOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgNzsgKytp
KSB7CiAgICBzaXplX3QgcG9zID0gcy5maW5kKG1baV0pOwogICAgaWYgKHBvcyAhPSBzdGQ6OnN0
cmluZzo6bnBvcyAmJiAoYmVzdCA9PSBzdGQ6OnN0cmluZzo6bnBvcyB8fCBwb3MgPCBiZXN0KSkg
YmVzdCA9IHBvczsKICB9CiAgcmV0dXJuIGJlc3Q7Cn0KCnN0YXRpYyBib29sIGlzX21ldGhvZF9v
cl9wcmVmaXgoY29uc3QgY2hhciAqcCwgc2l6ZV90IGxlbikgewogIGlmICghbGVuKSByZXR1cm4g
ZmFsc2U7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwgIkRF
TEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIGZvciAoc2l6ZV90IGkg
PSAwOyBpIDwgNzsgKytpKSB7CiAgICBzaXplX3QgbWxlbiA9IHN0cmxlbihtW2ldKTsKICAgIHNp
emVfdCBjaGVja19sZW4gPSBsZW4gPCBtbGVuID8gbGVuIDogbWxlbjsKICAgIGlmIChtZW1jbXAo
cCwgbVtpXSwgY2hlY2tfbGVuKSA9PSAwKSByZXR1cm4gdHJ1ZTsKICB9CiAgcmV0dXJuIGZhbHNl
Owp9CgpzdGF0aWMgYm9vbCBnX21vbml0b3JlZF9wb3J0c1s2NTUzNl07CgpzdGF0aWMgc2l6ZV90
IGFjdGl2ZV93c3NlX2Zsb3dzKGNvbnN0IHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cykg
ewogIHNpemVfdCBjb3VudCA9IDA7CiAgZm9yIChzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6Y29u
c3RfaXRlcmF0b3IgaXQgPSBmbG93cy5iZWdpbigpOyBpdCAhPSBmbG93cy5lbmQoKTsgKytpdCkK
ICAgIGlmIChpdC0+c2Vjb25kLmF3YWl0aW5nX3dzc2UpICsrY291bnQ7CiAgcmV0dXJuIGNvdW50
Owp9CgpzdGF0aWMgdm9pZCBldmljdF9vbGRlc3RfZmxvd19pZl9uZWVkZWQoc3RkOjptYXA8Rmxv
d0tleSwgRmxvdz4gJmZsb3dzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7
CiAgd2hpbGUgKCFmbG93cy5lbXB0eSgpICYmIChmbG93cy5zaXplKCkgPj0gTUFYX0ZMT1dTIHx8
IGdfdG90YWxfZmxvd19ieXRlcyA+PSBNQVhfVE9UQUxfQlVGRkVSX0JZVEVTKSkgewogICAgc3Rk
OjptYXA8Rmxvd0tleSwgRmxvdz46Oml0ZXJhdG9yIG9sZGVzdCA9IGZsb3dzLmJlZ2luKCk7CiAg
ICBmb3IgKHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBpdCA9IGZsb3dzLmJlZ2lu
KCk7IGl0ICE9IGZsb3dzLmVuZCgpOyArK2l0KSB7CiAgICAgIGlmIChpdC0+c2Vjb25kLnRvdWNo
ZWQgPCBvbGRlc3QtPnNlY29uZC50b3VjaGVkKSBvbGRlc3QgPSBpdDsKICAgIH0KICAgIGlmIChv
bGRlc3QtPnNlY29uZC5hd2FpdGluZ193c3NlKSB7CiAgICAgIHF1ZXVlX3JlcXVlc3Qob2xkZXN0
LT5zZWNvbmQud3NzZV9ldmVudCwgb2xkZXN0LT5maXJzdC5zX2lwLCBvbGRlc3QtPmZpcnN0LnNw
b3J0LAogICAgICAgICAgICAgICAgICAgIG9sZGVzdC0+Zmlyc3QuZF9pcCwgb2xkZXN0LT5maXJz
dC5kcG9ydCwgcGVuZGluZywgb2xkZXN0LT5zZWNvbmQuZmlyc3RfYnl0ZV9tb25vX21zLAogICAg
ICAgICAgICAgICAgICAgIG9sZGVzdC0+c2Vjb25kLmdlbmVyYXRpb24pOwogICAgICBvbGRlc3Qt
PnNlY29uZC5hd2FpdGluZ193c3NlID0gZmFsc2U7CiAgICB9CiAgICBvbGRlc3QtPnNlY29uZC5j
bGVhcl9idWZmZXJzKCk7CiAgICBmbG93cy5lcmFzZShvbGRlc3QpOwogIH0KfQoKc3RhdGljIGJv
b2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVfdCBuLCBjb25z
dCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywK
ICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3Ms
IHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywKICAg
ICAgICAgICAgICAgICAgICAgICAgICB0aW1lX3QgcGNhcF9ub3cgPSAwLCBsb25nIGxvbmcgcGNh
cF9tb25vX25vdyA9IDApIHsKICAodm9pZClwb3J0czsKICBpZiAobiA8IDM0KSByZXR1cm4gZmFs
c2U7CiAgc2l6ZV90IG9mZiA9IDE0OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRvaHMocmVhZF91
MTYoYnVmICsgMTIpKTsKICBpZiAoZXQgPT0gRVRIX1BfODAyMVEpIHsgaWYgKG4gPCAzOCkgcmV0
dXJuIGZhbHNlOyBldCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIDE2KSk7IG9mZiA9IDE4OyB9CiAg
aWYgKGV0ICE9IEVUSF9QX0lQIHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1bnNp
Z25lZCBjaGFyIGlobCA9ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAqIDQ7CiAgaWYg
KChidWZbb2ZmXSA+PiA0KSAhPSA0IHx8IGlobCA8IDIwIHx8IGJ1ZltvZmYgKyA5XSAhPSA2KSBy
ZXR1cm4gZmFsc2U7CgogIC8vIFJlamVjdCBmcmFnbWVudGVkIElQIHBhY2tldHMgKG5vbi1maXJz
dCBmcmFnbWVudCBoYXMgZnJhZyBvZmZzZXQgPiAwKQogIHVpbnQxNl90IGZyYWcgPSBudG9ocyhy
ZWFkX3UxNihidWYgKyBvZmYgKyA2KSk7CiAgaWYgKGZyYWcgJiAweDFmZmYpIHJldHVybiBmYWxz
ZTsKCiAgLy8gSVB2NCB0b3RhbCBsZW5ndGggdmFsaWRhdGlvbiBhbmQgdHJ1bmNhdGlvbiBjaGVj
awogIHVpbnQxNl90IGlwX3RvdGFsX2xlbiA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIG9mZiArIDIp
KTsKICBib29sIGlzX3RydW5jYXRlZCA9IGZhbHNlOwogIGlmIChpcF90b3RhbF9sZW4gPiAwKSB7
CiAgICBpZiAoaXBfdG90YWxfbGVuIDwgaWhsICsgMjApIHJldHVybiBmYWxzZTsKICAgIGlmIChu
IC0gb2ZmIDwgaXBfdG90YWxfbGVuKSB7CiAgICAgIGlzX3RydW5jYXRlZCA9IHRydWU7CiAgICB9
IGVsc2UgaWYgKG4gLSBvZmYgPiBpcF90b3RhbF9sZW4pIHsKICAgICAgbiA9IG9mZiArIGlwX3Rv
dGFsX2xlbjsgLy8gRXhjbHVkZSBFdGhlcm5ldCBwYWRkaW5nCiAgICB9CiAgfQoKICB1aW50MzJf
dCBzX2lwID0gcmVhZF91MzIoYnVmICsgb2ZmICsgMTIpOwogIHVpbnQzMl90IGRfaXAgPSByZWFk
X3UzMihidWYgKyBvZmYgKyAxNik7CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwogIGlmIChuIDwg
dG8gKyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1bnNpZ25lZCBzcG9ydCA9IG50b2hzKHJlYWRfdTE2
KGJ1ZiArIHRvKSk7CiAgdW5zaWduZWQgZHBvcnQgPSBudG9ocyhyZWFkX3UxNihidWYgKyB0byAr
IDIpKTsKICB1aW50MzJfdCBzZXEgPSBudG9obChyZWFkX3UzMihidWYgKyB0byArIDQpKTsKICB1
bnNpZ25lZCBkb2ZmID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYgKGRvZmYgPCAyMCB8
fCBuIDwgdG8gKyBkb2ZmKSByZXR1cm4gZmFsc2U7CgogIHVuc2lnbmVkIGNoYXIgdGNwX2ZsYWdz
ID0gYnVmW3RvICsgMTNdOwogIGNvbnN0IGNoYXIgKnBheWxvYWQgPSAoY29uc3QgY2hhciAqKShi
dWYgKyB0byArIGRvZmYpOwogIHNpemVfdCBwbGVuID0gbiAtIHRvIC0gZG9mZjsKCiAgdGltZV90
IG5vdyA9IChwY2FwX25vdyA+IDApID8gcGNhcF9ub3cgOiB0aW1lKE5VTEwpOwogIGxvbmcgbG9u
ZyBtb25vX25vdyA9IChwY2FwX21vbm9fbm93ID4gMCkgPyBwY2FwX21vbm9fbm93IDogbm93X21v
bm90b25pY19tcygpOwoKICBib29sIGRzdF9tb24gPSAoZHBvcnQgPCA2NTUzNikgPyBnX21vbml0
b3JlZF9wb3J0c1tkcG9ydF0gOiBmYWxzZTsKICBib29sIHNyY19tb24gPSAoc3BvcnQgPCA2NTUz
NikgPyBnX21vbml0b3JlZF9wb3J0c1tzcG9ydF0gOiBmYWxzZTsKCiAgLy8gRGlyZWN0aW9uIEE6
IFNlcnZlciAtPiBDbGllbnQgUmVzcG9uc2UgUmVhc3NlbWJseQogIGlmIChzcmNfbW9uICYmICFk
c3RfbW9uKSB7CiAgICBGbG93S2V5IHJmazsKICAgIHJmay5zX2lwID0gc19pcDsgcmZrLnNwb3J0
ID0gKHVpbnQxNl90KXNwb3J0OwogICAgcmZrLmRfaXAgPSBkX2lwOyByZmsuZHBvcnQgPSAodWlu
dDE2X3QpZHBvcnQ7CgogICAgaWYgKHRjcF9mbGFncyAmIDB4MDIpIHsgLy8gU1lOIGZyb20gc2Vy
dmVyCiAgICAgIGV2aWN0X29sZGVzdF9mbG93X2lmX25lZWRlZChmbG93cywgcGVuZGluZyk7CiAg
ICAgIEZsb3cgJnJmbCA9IGZsb3dzW3Jma107CiAgICAgIHJmbC5jbGVhcl9idWZmZXJzKCk7CiAg
ICAgIHJmbCA9IEZsb3coKTsKICAgICAgcmZsLmhhc19zZXEgPSB0cnVlOwogICAgICByZmwubmV4
dF9zZXEgPSBzZXEgKyAxOwogICAgICByZmwuaXNfYnJva2VuID0gZmFsc2U7CiAgICAgIHJmbC50
b3VjaGVkID0gbm93OwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICBpZiAocGxlbiA+IDAp
IHsKICAgICAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZfbmVlZGVkKGZsb3dzLCBwZW5kaW5nKTsKICAg
ICAgRmxvdyAmcmZsID0gZmxvd3NbcmZrXTsKICAgICAgcmZsLnRvdWNoZWQgPSBub3c7CgogICAg
ICBpZiAoIXJmbC5oYXNfc2VxKSB7CiAgICAgICAgaWYgKChwbGVuID49IDUgJiYgbWVtY21wKHBh
eWxvYWQsICJIVFRQLyIsIDUpID09IDApIHx8CiAgICAgICAgICAgIChwbGVuIDwgNSAmJiBtZW1j
bXAocGF5bG9hZCwgIkhUVFAvIiwgcGxlbikgPT0gMCkpIHsKICAgICAgICAgIHJmbC5oYXNfc2Vx
ID0gdHJ1ZTsKICAgICAgICAgIHJmbC5uZXh0X3NlcSA9IHNlcTsKICAgICAgICAgIHJmbC5pc19i
cm9rZW4gPSBmYWxzZTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgaWYgKHJmbC5vb28uc2l6
ZSgpIDwgTUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICAgIGJv
b2wgZHVwID0gZmFsc2U7CiAgICAgICAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcmZsLm9v
by5zaXplKCk7ICsraSkgewogICAgICAgICAgICAgIGlmIChyZmwub29vW2ldLnNlcSA9PSBzZXEp
IHsgZHVwID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIWR1
cCkgewogICAgICAgICAgICAgIHJmbC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAg
ICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgICB9CiAg
ICAgIH0KCiAgICAgIGludDMyX3QgZGlmZiA9IHNlcV9kaWZmKHNlcSwgcmZsLm5leHRfc2VxKTsK
ICAgICAgaWYgKGRpZmYgPT0gMCkgewogICAgICAgIGlmIChpc190cnVuY2F0ZWQpIHsKICAgICAg
ICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBpZiAo
IXJmbC5idWZfYXBwZW5kKHBheWxvYWQsIHBsZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgIHJm
bC5uZXh0X3NlcSArPSAodWludDMyX3QpcGxlbjsKCiAgICAgICAgICAvLyBEcmFpbiBvdXQgb2Yg
b3JkZXIgc2VnbWVudHMKICAgICAgICAgIGJvb2wgZHJhaW5lZCA9IHRydWU7CiAgICAgICAgICB3
aGlsZSAoZHJhaW5lZCAmJiAhcmZsLm9vby5lbXB0eSgpKSB7CiAgICAgICAgICAgIGRyYWluZWQg
PSBmYWxzZTsKICAgICAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCByZmwub29vLnNpemUo
KTsgKytpKSB7CiAgICAgICAgICAgICAgaW50MzJfdCBvZGlmZiA9IHNlcV9kaWZmKHJmbC5vb29b
aV0uc2VxLCByZmwubmV4dF9zZXEpOwogICAgICAgICAgICAgIGlmIChvZGlmZiA9PSAwKSB7CiAg
ICAgICAgICAgICAgICBpZiAoIXJmbC5idWZfYXBwZW5kKHJmbC5vb29baV0uZGF0YS5kYXRhKCks
IHJmbC5vb29baV0uZGF0YS5zaXplKCkpKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgICAgICAgIHJm
bC5uZXh0X3NlcSArPSAodWludDMyX3QpcmZsLm9vb1tpXS5kYXRhLnNpemUoKTsKICAgICAgICAg
ICAgICAgIHJmbC5vb29fZXJhc2UoaSk7CiAgICAgICAgICAgICAgICBkcmFpbmVkID0gdHJ1ZTsg
YnJlYWs7CiAgICAgICAgICAgICAgfSBlbHNlIGlmIChvZGlmZiA8IDApIHsKICAgICAgICAgICAg
ICAgIGludDMyX3Qgb19vdmVybGFwID0gLW9kaWZmOwogICAgICAgICAgICAgICAgaWYgKChzaXpl
X3Qpb19vdmVybGFwIDwgcmZsLm9vb1tpXS5kYXRhLnNpemUoKSkgewogICAgICAgICAgICAgICAg
ICBzaXplX3QgZmxlbiA9IHJmbC5vb29baV0uZGF0YS5zaXplKCkgLSBvX292ZXJsYXA7CiAgICAg
ICAgICAgICAgICAgIGlmICghcmZsLmJ1Zl9hcHBlbmQocmZsLm9vb1tpXS5kYXRhLmRhdGEoKSAr
IG9fb3ZlcmxhcCwgZmxlbikpIHJldHVybiB0cnVlOwogICAgICAgICAgICAgICAgICByZmwubmV4
dF9zZXEgKz0gKHVpbnQzMl90KWZsZW47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg
ICByZmwub29vX2VyYXNlKGkpOwogICAgICAgICAgICAgICAgZHJhaW5lZCA9IHRydWU7IGJyZWFr
OwogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAg
ICAgfSBlbHNlIGlmIChkaWZmIDwgMCkgewogICAgICAgIGludDMyX3Qgb3ZlcmxhcCA9IC1kaWZm
OwogICAgICAgIGlmICgoc2l6ZV90KW92ZXJsYXAgPCBwbGVuICYmICFpc190cnVuY2F0ZWQpIHsK
ICAgICAgICAgIHNpemVfdCBmbGVuID0gcGxlbiAtIG92ZXJsYXA7CiAgICAgICAgICBpZiAoIXJm
bC5idWZfYXBwZW5kKHBheWxvYWQgKyBvdmVybGFwLCBmbGVuKSkgcmV0dXJuIHRydWU7CiAgICAg
ICAgICByZmwubmV4dF9zZXEgKz0gKHVpbnQzMl90KWZsZW47CiAgICAgICAgfQogICAgICB9IGVs
c2UgeyAvLyBkaWZmID4gMAogICAgICAgIGlmIChyZmwub29vLnNpemUoKSA8IE1BWF9PT09fU0VH
TUVOVFMgJiYgIWlzX3RydW5jYXRlZCkgewogICAgICAgICAgYm9vbCBkdXAgPSBmYWxzZTsKICAg
ICAgICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcmZsLm9vby5zaXplKCk7ICsraSkgewogICAg
ICAgICAgICBpZiAocmZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9IHRydWU7IGJyZWFrOyB9
CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAgICByZmwub29vX3B1
c2goc2VxLCBwYXlsb2FkLCBwbGVuKTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAg
ICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgfQogICAgICB9CgogICAgICAvLyBQ
YXJzZSBjb21wbGV0ZSByZXNwb25zZXMgZnJvbSByZWFzc2VtYmxlZCBidWZmZXIgdXNpbmcgSFRU
UCBmcmFtaW5nCiAgICAgIHdoaWxlICghcmZsLmJ1Zi5lbXB0eSgpICYmICFyZmwuaXNfYnJva2Vu
KSB7CiAgICAgICAgaWYgKHJmbC5zdGF0ZSA9PSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUikgewog
ICAgICAgICAgc2l6ZV90IGVuZCA9IHJmbC5idWYuZmluZCgiXHJcblxyXG4iKTsKICAgICAgICAg
IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgaWYgKHJmbC5idWYu
c2l6ZSgpID4gTUFYX0hFQURFUl9CWVRFUykgewogICAgICAgICAgICAgIHJmbC5jbGVhcl9idWZm
ZXJzKCk7CiAgICAgICAgICAgICAgcmZsLmlzX2Jyb2tlbiA9IHRydWU7CiAgICAgICAgICAgIH0K
ICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9CgogICAgICAgICAgaWYgKHJmbC5idWYuY29t
cGFyZSgwLCA1LCAiSFRUUC8iKSAhPSAwKSB7CiAgICAgICAgICAgIHNpemVfdCBocG9zID0gcmZs
LmJ1Zi5maW5kKCJIVFRQLyIpOwogICAgICAgICAgICBpZiAoaHBvcyA9PSBzdGQ6OnN0cmluZzo6
bnBvcyB8fCBocG9zID4gZW5kKSB7CiAgICAgICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCBlbmQg
KyA0KTsKICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBy
ZmwuYnVmX2VyYXNlKDAsIGhwb3MpOwogICAgICAgICAgICBlbmQgLT0gaHBvczsKICAgICAgICAg
IH0KCiAgICAgICAgICBpbnQgc3QgPSAwOyBzaXplX3QgY2wgPSAwOyBib29sIGhhc19jbCA9IGZh
bHNlLCBpc19jaHVua2VkID0gZmFsc2UsIGlzX2Nsb3NlID0gZmFsc2U7CiAgICAgICAgICBpZiAo
IXBhcnNlX3Jlc3BvbnNlKHJmbC5idWYuZGF0YSgpLCBlbmQsICZzdCwgJmNsLCAmaGFzX2NsLCAm
aXNfY2h1bmtlZCwgJmlzX2Nsb3NlKSkgewogICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIGVu
ZCArIDQpOwogICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgIH0KCiAgICAgICAgICBpZiAo
c3QgPj0gMTAwICYmIHN0IDw9IDE5OSAmJiBzdCAhPSAxMDEpIHsKICAgICAgICAgICAgcmZsLmJ1
Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICB9Cgog
ICAgICAgICAgUGFja2V0S2V5IHBrOwogICAgICAgICAgcGsuc19pcCA9IHNfaXA7IHBrLnNwb3J0
ID0gKHVpbnQxNl90KXNwb3J0OwogICAgICAgICAgcGsuZF9pcCA9IGRfaXA7IHBrLmRwb3J0ID0g
KHVpbnQxNl90KWRwb3J0OwogICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3Rv
cjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKHBrKTsKICAgICAgICAgIGJv
b2wgaXNfaGVhZCA9IGZhbHNlOwogICAgICAgICAgaWYgKHAgIT0gcGVuZGluZy5lbmQoKSAmJiAh
cC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgICAgICAgICAgRXZlbnQgZSA9IHAtPnNlY29uZFswXS5l
djsKICAgICAgICAgICAgaWYgKGUubWV0aG9kID09ICJIRUFEIikgaXNfaGVhZCA9IHRydWU7CiAg
ICAgICAgICAgIGUuc3RhdHVzID0gc3Q7CiAgICAgICAgICAgIGUuaGFzX3N0YXR1cyA9IHRydWU7
CiAgICAgICAgICAgIGUuZHVyYXRpb25fbXMgPSAobG9uZykobW9ub19ub3cgLSBwLT5zZWNvbmRb
MF0uc3RhcnRlZF9tb25vX21zKTsKICAgICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBl
LmR1cmF0aW9uX21zID0gMDsKICAgICAgICAgICAgZS5oYXNfZHVyYXRpb24gPSB0cnVlOwogICAg
ICAgICAgICBpZiAoaGFzX2NsKSB7CiAgICAgICAgICAgICAgZS5yZXNwX2J5dGVzID0gKHVuc2ln
bmVkKWNsOwogICAgICAgICAgICAgIGUuaGFzX3Jlc3AgPSB0cnVlOwogICAgICAgICAgICB9CiAg
ICAgICAgICAgIGVtaXRfZXZlbnQoZSk7CiAgICAgICAgICAgIHAtPnNlY29uZC5lcmFzZShwLT5z
ZWNvbmQuYmVnaW4oKSk7CiAgICAgICAgICAgIGlmIChnX3RvdGFsX3BlbmRpbmdfY291bnQgPiAw
KSAtLWdfdG90YWxfcGVuZGluZ19jb3VudDsKICAgICAgICAgICAgaWYgKHAtPnNlY29uZC5lbXB0
eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgICAgfQoKICAgICAgICAgIHJmbC5idWZfZXJh
c2UoMCwgZW5kICsgNCk7CgogICAgICAgICAgaWYgKGlzX2hlYWQgfHwgc3QgPT0gMjA0IHx8IHN0
ID09IDMwNCkgewogICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURF
UjsKICAgICAgICAgIH0gZWxzZSBpZiAoaXNfY2h1bmtlZCkgewogICAgICAgICAgICByZmwuc3Rh
dGUgPSBGbG93OjpIVFRQX1NUQVRFX0NIVU5LOwogICAgICAgICAgICByZmwuY2h1bmtfcmVhZGlu
Z19sZW4gPSB0cnVlOwogICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gZmFs
c2U7CiAgICAgICAgICAgIHJmbC5jaHVua19yZW1haW5pbmcgPSAwOwogICAgICAgICAgfSBlbHNl
IGlmIChoYXNfY2wpIHsKICAgICAgICAgICAgaWYgKGNsID4gMCkgewogICAgICAgICAgICAgIHJm
bC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfQk9EWTsKICAgICAgICAgICAgICByZmwuYm9keV9y
ZW1haW5pbmcgPSBjbDsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICByZmwuc3Rh
dGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgICAgfQogICAgICAgICAgfSBl
bHNlIGlmIChpc19jbG9zZSkgewogICAgICAgICAgICByZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NU
QVRFX0NMT1NFX0JPRFk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICByZmwuc3RhdGUg
PSBGbG93OjpIVFRQX1NUQVRFX0NMT1NFX0JPRFk7CiAgICAgICAgICB9CiAgICAgICAgICBjb250
aW51ZTsKICAgICAgICB9CgogICAgICAgIGlmIChyZmwuc3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFU
RV9CT0RZKSB7CiAgICAgICAgICBpZiAocmZsLmJ1Zi5lbXB0eSgpKSBicmVhazsKICAgICAgICAg
IHNpemVfdCB0b19jb25zdW1lID0gKHJmbC5idWYuc2l6ZSgpIDwgcmZsLmJvZHlfcmVtYWluaW5n
KSA/IHJmbC5idWYuc2l6ZSgpIDogcmZsLmJvZHlfcmVtYWluaW5nOwogICAgICAgICAgcmZsLmJ1
Zl9lcmFzZSgwLCB0b19jb25zdW1lKTsKICAgICAgICAgIHJmbC5ib2R5X3JlbWFpbmluZyAtPSB0
b19jb25zdW1lOwogICAgICAgICAgaWYgKHJmbC5ib2R5X3JlbWFpbmluZyA9PSAwKSB7CiAgICAg
ICAgICAgIHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgfQog
ICAgICAgICAgY29udGludWU7CiAgICAgICAgfQoKICAgICAgICBpZiAocmZsLnN0YXRlID09IEZs
b3c6OkhUVFBfU1RBVEVfQ0hVTkspIHsKICAgICAgICAgIGlmIChyZmwuYnVmLmVtcHR5KCkpIGJy
ZWFrOwogICAgICAgICAgaWYgKHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIpIHsKICAgICAgICAg
ICAgaWYgKHJmbC5idWYuc2l6ZSgpID49IDIgJiYgcmZsLmJ1ZlswXSA9PSAnXHInICYmIHJmbC5i
dWZbMV0gPT0gJ1xuJykgewogICAgICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgMik7CiAgICAg
ICAgICAgICAgcmZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IGZhbHNlOwogICAgICAgICAgICAg
IHJmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgICAgIGNvbnRp
bnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHNpemVfdCB0cl9lbmQgPSByZmwuYnVmLmZp
bmQoIlxyXG5cclxuIik7CiAgICAgICAgICAgIGlmICh0cl9lbmQgIT0gc3RkOjpzdHJpbmc6Om5w
b3MpIHsKICAgICAgICAgICAgICByZmwuYnVmX2VyYXNlKDAsIHRyX2VuZCArIDQpOwogICAgICAg
ICAgICAgIHJmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxzZTsKICAgICAgICAgICAgICBy
Zmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgICAgICBjb250aW51
ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAocmZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVB
REVSX0JZVEVTKSB7CiAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAg
ICAgICByZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBicmVh
azsKICAgICAgICAgIH0KICAgICAgICAgIGlmIChyZmwuY2h1bmtfcmVhZGluZ19sZW4pIHsKICAg
ICAgICAgICAgc2l6ZV90IGNybGYgPSByZmwuYnVmLmZpbmQoIlxyXG4iKTsKICAgICAgICAgICAg
aWYgKGNybGYgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgICBpZiAocmZsLmJ1
Zi5zaXplKCkgPiA2NCkgewogICAgICAgICAgICAgICAgcmZsLmNsZWFyX2J1ZmZlcnMoKTsKICAg
ICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICAgIH0KICAgICAg
ICAgICAgICBicmVhazsKICAgICAgICAgICAgfQogICAgICAgICAgICBzdGQ6OnN0cmluZyBsaW5l
ID0gdHJpbShyZmwuYnVmLnN1YnN0cigwLCBjcmxmKSk7CiAgICAgICAgICAgIHNpemVfdCBzZW1p
ID0gbGluZS5maW5kKCc7Jyk7CiAgICAgICAgICAgIHN0ZDo6c3RyaW5nIGhleF9zdHIgPSAoc2Vt
aSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgPyB0cmltKGxpbmUuc3Vic3RyKDAsIHNlbWkpKSA6IGxp
bmU7CiAgICAgICAgICAgIGlmIChoZXhfc3RyLmVtcHR5KCkpIHsKICAgICAgICAgICAgICByZmwu
Y2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAg
ICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGJvb2wgdmFsaWRfaGV4
ID0gdHJ1ZTsKICAgICAgICAgICAgZm9yIChzaXplX3QgaGkgPSAwOyBoaSA8IGhleF9zdHIuc2l6
ZSgpOyArK2hpKSB7CiAgICAgICAgICAgICAgaWYgKCFpc3hkaWdpdCgodW5zaWduZWQgY2hhcilo
ZXhfc3RyW2hpXSkpIHsgdmFsaWRfaGV4ID0gZmFsc2U7IGJyZWFrOyB9CiAgICAgICAgICAgIH0K
ICAgICAgICAgICAgaWYgKCF2YWxpZF9oZXgpIHsKICAgICAgICAgICAgICByZmwuY2xlYXJfYnVm
ZmVycygpOwogICAgICAgICAgICAgIHJmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgICAg
IGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGNoYXIgKmVuZHB0ciA9IE5VTEw7CiAg
ICAgICAgICAgIHNpemVfdCBjaHVua19sZW4gPSAoc2l6ZV90KXN0cnRvdWwoaGV4X3N0ci5jX3N0
cigpLCAmZW5kcHRyLCAxNik7CiAgICAgICAgICAgIHJmbC5idWZfZXJhc2UoMCwgY3JsZiArIDIp
OwogICAgICAgICAgICBpZiAoY2h1bmtfbGVuID09IDApIHsKICAgICAgICAgICAgICByZmwuY2h1
bmtfcmVhZGluZ190cmFpbGVyID0gdHJ1ZTsKICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAg
ICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICByZmwuY2h1bmtfcmVtYWluaW5nID0gY2h1bmtf
bGVuICsgMjsKICAgICAgICAgICAgICByZmwuY2h1bmtfcmVhZGluZ19sZW4gPSBmYWxzZTsKICAg
ICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgc2l6ZV90IHRvX2NvbnN1
bWUgPSAocmZsLmJ1Zi5zaXplKCkgPCByZmwuY2h1bmtfcmVtYWluaW5nKSA/IHJmbC5idWYuc2l6
ZSgpIDogcmZsLmNodW5rX3JlbWFpbmluZzsKICAgICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCB0
b19jb25zdW1lKTsKICAgICAgICAgICAgcmZsLmNodW5rX3JlbWFpbmluZyAtPSB0b19jb25zdW1l
OwogICAgICAgICAgICBpZiAocmZsLmNodW5rX3JlbWFpbmluZyA9PSAwKSByZmwuY2h1bmtfcmVh
ZGluZ19sZW4gPSB0cnVlOwogICAgICAgICAgfQogICAgICAgICAgY29udGludWU7CiAgICAgICAg
fQoKICAgICAgICBpZiAocmZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfQ0xPU0VfQk9EWSkg
ewogICAgICAgICAgcmZsLmJ1Zl9lcmFzZSgwLCByZmwuYnVmLnNpemUoKSk7CiAgICAgICAgICBi
cmVhazsKICAgICAgICB9CiAgICAgIH0KICAgIH0KCiAgICBpZiAodGNwX2ZsYWdzICYgMHgwNSkg
eyAvLyBTZXJ2ZXIgRklOIG9yIFJTVAogICAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRl
cmF0b3IgaXQgPSBmbG93cy5maW5kKHJmayk7CiAgICAgIGlmIChpdCAhPSBmbG93cy5lbmQoKSkg
ewogICAgICAgIGl0LT5zZWNvbmQuY2xlYXJfYnVmZmVycygpOwogICAgICAgIGZsb3dzLmVyYXNl
KGl0KTsKICAgICAgfQogICAgfQogICAgcmV0dXJuIHRydWU7CiAgfQoKICAvLyBEaXJlY3Rpb24g
QjogQ2xpZW50IC0+IFNlcnZlciBSZXF1ZXN0IFJlYXNzZW1ibHkKICBpZiAoIWRzdF9tb24pIHsK
ICAgIGlmICh0Y3BfZmxhZ3MgJiAweDA1KSB7CiAgICAgIEZsb3dLZXkgcmZrOyByZmsuc19pcCA9
IGRfaXA7IHJmay5zcG9ydCA9ICh1aW50MTZfdClkcG9ydDsgcmZrLmRfaXAgPSBzX2lwOyByZmsu
ZHBvcnQgPSAodWludDE2X3Qpc3BvcnQ7CiAgICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+Ojpp
dGVyYXRvciBpdCA9IGZsb3dzLmZpbmQocmZrKTsKICAgICAgaWYgKGl0ICE9IGZsb3dzLmVuZCgp
KSB7CiAgICAgICAgaXQtPnNlY29uZC5jbGVhcl9idWZmZXJzKCk7CiAgICAgICAgZmxvd3MuZXJh
c2UoaXQpOwogICAgICB9CiAgICB9CiAgICByZXR1cm4gZmFsc2U7CiAgfQoKICBGbG93S2V5IGZr
OwogIGZrLnNfaXAgPSBzX2lwOyBmay5zcG9ydCA9ICh1aW50MTZfdClzcG9ydDsgZmsuZF9pcCA9
IGRfaXA7IGZrLmRwb3J0ID0gKHVpbnQxNl90KWRwb3J0OwoKICBpZiAodGNwX2ZsYWdzICYgMHgw
MikgeyAvLyBTWU4gZnJvbSBjbGllbnQ6IG5ldyBjb25uZWN0aW9uIGdlbmVyYXRpb24hCiAgICBl
dmljdF9vbGRlc3RfZmxvd19pZl9uZWVkZWQoZmxvd3MsIHBlbmRpbmcpOwogICAgUGFja2V0S2V5
IHJrOyByay5zX2lwID0gZF9pcDsgcmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7IHJrLmRfaXAg
PSBzX2lwOyByay5kcG9ydCA9ICh1aW50MTZfdClzcG9ydDsKCiAgICAvLyBQdXJnZSBwcmV2aW91
cyBnZW5lcmF0aW9uJ3MgcGVuZGluZyByZXF1ZXN0cyBmb3IgdGhpcyA0LXR1cGxlCiAgICBzdGQ6
Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHAgPSBwZW5k
aW5nLmZpbmQocmspOwogICAgaWYgKHAgIT0gcGVuZGluZy5lbmQoKSkgewogICAgICBmb3IgKHNp
emVfdCBpID0gMDsgaSA8IHAtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICAgIGVtaXRfZXZl
bnQocC0+c2Vjb25kW2ldLmV2KTsKICAgICAgICBpZiAoZ190b3RhbF9wZW5kaW5nX2NvdW50ID4g
MCkgLS1nX3RvdGFsX3BlbmRpbmdfY291bnQ7CiAgICAgIH0KICAgICAgcGVuZGluZy5lcmFzZShw
KTsKICAgIH0KCiAgICAvLyBSZXNldCBzZXJ2ZXIgcmVzcG9uc2UgZmxvdyBmb3IgdGhpcyA0LXR1
cGxlCiAgICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgcmZpdCA9IGZsb3dzLmZp
bmQocmspOwogICAgaWYgKHJmaXQgIT0gZmxvd3MuZW5kKCkpIHsKICAgICAgcmZpdC0+c2Vjb25k
LmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgZmxvd3MuZXJhc2UocmZpdCk7CiAgICB9CgogICAgRmxv
dyAmZmwgPSBmbG93c1tma107CiAgICBpZiAoZmwuYXdhaXRpbmdfd3NzZSkgewogICAgICBxdWV1
ZV9yZXF1ZXN0KGZsLndzc2VfZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGlu
ZywgZmwuZmlyc3RfYnl0ZV9tb25vX21zLCBmbC5nZW5lcmF0aW9uKTsKICAgICAgZmwuYXdhaXRp
bmdfd3NzZSA9IGZhbHNlOwogICAgfQogICAgdWludDMyX3QgbmV4dF9nZW4gPSBmbC5nZW5lcmF0
aW9uICsgMTsKICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgIGZsID0gRmxvdygpOwogICAgZmwu
Z2VuZXJhdGlvbiA9IG5leHRfZ2VuOwogICAgZmwuaGFzX3NlcSA9IHRydWU7CiAgICBmbC5uZXh0
X3NlcSA9IHNlcSArIDE7CiAgICBmbC50b3VjaGVkID0gbm93OwogICAgZmwuZmlyc3RfYnl0ZV9t
b25vX21zID0gMDsKICAgIHJldHVybiB0cnVlOwogIH0KCiAgZXZpY3Rfb2xkZXN0X2Zsb3dfaWZf
bmVlZGVkKGZsb3dzLCBwZW5kaW5nKTsKICBGbG93ICZmbCA9IGZsb3dzW2ZrXTsKICBmbC50b3Vj
aGVkID0gbm93OwoKICBpZiAocGxlbiA+IDApIHsKICAgIGlmICghZmwuaGFzX3NlcSkgewogICAg
ICBpZiAoaXNfbWV0aG9kX29yX3ByZWZpeChwYXlsb2FkLCBwbGVuKSkgewogICAgICAgIGZsLmhh
c19zZXEgPSB0cnVlOwogICAgICAgIGZsLm5leHRfc2VxID0gc2VxOwogICAgICAgIGZsLmlzX2Jy
b2tlbiA9IGZhbHNlOwogICAgICB9IGVsc2UgewogICAgICAgIGlmIChmbC5vb28uc2l6ZSgpIDwg
TUFYX09PT19TRUdNRU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgICBib29sIGR1cCA9
IGZhbHNlOwogICAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBmbC5vb28uc2l6ZSgpOyAr
K2kpIHsKICAgICAgICAgICAgaWYgKGZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9IHRydWU7
IGJyZWFrOyB9CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIWR1cCkgewogICAgICAgICAgICBm
bC5vb29fcHVzaChzZXEsIHBheWxvYWQsIHBsZW4pOwogICAgICAgICAgfQogICAgICAgIH0KICAg
ICAgICByZXR1cm4gdHJ1ZTsKICAgICAgfQogICAgfQoKICAgIGludDMyX3QgZGlmZiA9IHNlcV9k
aWZmKHNlcSwgZmwubmV4dF9zZXEpOwogICAgaWYgKGRpZmYgPT0gMCkgewogICAgICBpZiAoaXNf
dHJ1bmNhdGVkKSB7CiAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgfSBlbHNlIHsK
ICAgICAgICBpZiAoIWZsLmJ1Zl9hcHBlbmQocGF5bG9hZCwgcGxlbikpIHJldHVybiB0cnVlOwog
ICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClwbGVuOwoKICAgICAgICAvLyBEcmFpbiBv
dXQtb2Ytb3JkZXIgc2VnbWVudHMKICAgICAgICBib29sIGRyYWluZWQgPSB0cnVlOwogICAgICAg
IHdoaWxlIChkcmFpbmVkICYmICFmbC5vb28uZW1wdHkoKSkgewogICAgICAgICAgZHJhaW5lZCA9
IGZhbHNlOwogICAgICAgICAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCBmbC5vb28uc2l6ZSgpOyAr
K2kpIHsKICAgICAgICAgICAgaW50MzJfdCBvZGlmZiA9IHNlcV9kaWZmKGZsLm9vb1tpXS5zZXEs
IGZsLm5leHRfc2VxKTsKICAgICAgICAgICAgaWYgKG9kaWZmID09IDApIHsKICAgICAgICAgICAg
ICBpZiAoIWZsLmJ1Zl9hcHBlbmQoZmwub29vW2ldLmRhdGEuZGF0YSgpLCBmbC5vb29baV0uZGF0
YS5zaXplKCkpKSByZXR1cm4gdHJ1ZTsKICAgICAgICAgICAgICBmbC5uZXh0X3NlcSArPSAodWlu
dDMyX3QpZmwub29vW2ldLmRhdGEuc2l6ZSgpOwogICAgICAgICAgICAgIGZsLm9vb19lcmFzZShp
KTsKICAgICAgICAgICAgICBkcmFpbmVkID0gdHJ1ZTsgYnJlYWs7CiAgICAgICAgICAgIH0gZWxz
ZSBpZiAob2RpZmYgPCAwKSB7CiAgICAgICAgICAgICAgaW50MzJfdCBvX292ZXJsYXAgPSAtb2Rp
ZmY7CiAgICAgICAgICAgICAgaWYgKChzaXplX3Qpb19vdmVybGFwIDwgZmwub29vW2ldLmRhdGEu
c2l6ZSgpKSB7CiAgICAgICAgICAgICAgICBzaXplX3QgZmxlbiA9IGZsLm9vb1tpXS5kYXRhLnNp
emUoKSAtIG9fb3ZlcmxhcDsKICAgICAgICAgICAgICAgIGlmICghZmwuYnVmX2FwcGVuZChmbC5v
b29baV0uZGF0YS5kYXRhKCkgKyBvX292ZXJsYXAsIGZsZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAg
ICAgICAgICAgIGZsLm5leHRfc2VxICs9ICh1aW50MzJfdClmbGVuOwogICAgICAgICAgICAgIH0K
ICAgICAgICAgICAgICBmbC5vb29fZXJhc2UoaSk7CiAgICAgICAgICAgICAgZHJhaW5lZCA9IHRy
dWU7IGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAg
ICB9IGVsc2UgaWYgKGRpZmYgPCAwKSB7CiAgICAgIGludDMyX3Qgb3ZlcmxhcCA9IC1kaWZmOwog
ICAgICBpZiAoKHNpemVfdClvdmVybGFwIDwgcGxlbiAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAg
ICAgc2l6ZV90IGZsZW4gPSBwbGVuIC0gb3ZlcmxhcDsKICAgICAgICBpZiAoIWZsLmJ1Zl9hcHBl
bmQocGF5bG9hZCArIG92ZXJsYXAsIGZsZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAgICBmbC5uZXh0
X3NlcSArPSAodWludDMyX3QpZmxlbjsKICAgICAgfQogICAgfSBlbHNlIHsgLy8gZGlmZiA+IDAg
KG91dCBvZiBvcmRlciBnYXApCiAgICAgIGlmIChmbC5vb28uc2l6ZSgpIDwgTUFYX09PT19TRUdN
RU5UUyAmJiAhaXNfdHJ1bmNhdGVkKSB7CiAgICAgICAgYm9vbCBkdXAgPSBmYWxzZTsKICAgICAg
ICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGZsLm9vby5zaXplKCk7ICsraSkgewogICAgICAgICAg
aWYgKGZsLm9vb1tpXS5zZXEgPT0gc2VxKSB7IGR1cCA9IHRydWU7IGJyZWFrOyB9CiAgICAgICAg
fQogICAgICAgIGlmICghZHVwKSB7CiAgICAgICAgICBmbC5vb29fcHVzaChzZXEsIHBheWxvYWQs
IHBsZW4pOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICBmbC5pc19icm9rZW4gPSB0
cnVlOwogICAgICB9CiAgICB9CgogICAgLy8gSFRUUCBGcmFtaW5nIFN0YXRlIE1hY2hpbmUgZm9y
IHJlcXVlc3RzCiAgICB3aGlsZSAoIWZsLmJ1Zi5lbXB0eSgpICYmICFmbC5pc19icm9rZW4pIHsK
ICAgICAgaWYgKGZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSKSB7CiAgICAgICAg
aWYgKCFmbC5maXJzdF9ieXRlX21vbm9fbXMpIGZsLmZpcnN0X2J5dGVfbW9ub19tcyA9IG1vbm9f
bm93OwoKICAgICAgICBzaXplX3QgZW5kID0gZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAgICAg
ICAgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICAgICAgaWYgKGZsLmJ1Zi5z
aXplKCkgPiBNQVhfSEVBREVSX0JZVEVTKSB7CiAgICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMo
KTsKICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgIH0KICAgICAgICAg
IGJyZWFrOwogICAgICAgIH0KCiAgICAgICAgc2l6ZV90IHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0
KGZsLmJ1Zik7CiAgICAgICAgaWYgKHN0YXJ0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHN0YXJ0
ID4gZW5kKSB7CiAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgZW5kICsgNCk7CiAgICAgICAgICBj
b250aW51ZTsKICAgICAgICB9CiAgICAgICAgaWYgKHN0YXJ0ID4gMCkgewogICAgICAgICAgZmwu
YnVmX2VyYXNlKDAsIHN0YXJ0KTsKICAgICAgICAgIGVuZCAtPSBzdGFydDsKICAgICAgICB9Cgog
ICAgICAgIEV2ZW50IGU7IFJlcXVlc3RNZXRhIG1ldGE7CiAgICAgICAgZS50cyA9IG5vdzsgZS5o
b3N0ID0gbm9kZTsgZS5zZXJ2aWNlID0gInBvcnQ6IiArIG51bShkcG9ydCk7CiAgICAgICAgZS5j
YWxsZXIgPSBpcF90b19zdHIoc19pcCk7IGUuY2FsbGVyX3BvcnQgPSBzcG9ydDsKICAgICAgICBl
LmRzdF9pcCA9IGlwX3RvX3N0cihkX2lwKTsgZS5kc3RfcG9ydCA9IGRwb3J0OwogICAgICAgIGUu
cmVxX2J5dGVzID0gKHVuc2lnbmVkKShlbmQgKyA0KTsKCiAgICAgICAgaWYgKCFwYXJzZV9yZXF1
ZXN0KGZsLmJ1Zi5kYXRhKCksIGVuZCwgJmUsICZtZXRhKSkgewogICAgICAgICAgZmwuYnVmX2Vy
YXNlKDAsIGVuZCArIDQpOwogICAgICAgICAgY29udGludWU7CiAgICAgICAgfQoKICAgICAgICAv
LyBSZWplY3QgY29uZmxpY3RpbmcgQ29udGVudC1MZW5ndGggKyBjaHVua2VkIGVuY29kaW5nIChS
RkMgNzIzMCByZXF1ZXN0IHNtdWdnbGluZyBwcmV2ZW50aW9uKQogICAgICAgIGJvb2wgaGFzX2No
dW5rZWQgPSAobG93ZXIobWV0YS50cmFuc2Zlcl9lbmNvZGluZykuZmluZCgiY2h1bmtlZCIpICE9
IHN0ZDo6c3RyaW5nOjpucG9zKTsKICAgICAgICBpZiAobWV0YS5oYXNfY29udGVudF9sZW5ndGgg
JiYgaGFzX2NodW5rZWQpIHsKICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBlbmQgKyA0KTsKICAg
ICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgIGZsLmlzX2Jyb2tlbiA9IHRydWU7
CiAgICAgICAgICBicmVhazsKICAgICAgICB9CgogICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBlbmQg
KyA0KTsKCiAgICAgICAgYm9vbCB3c3NlX2VsaWdpYmxlID0gKGdfd3NzZV9ib2R5X2J5dGVzID4g
MCAmJgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpc19zb2FwX2NvbnRlbnRfdHlwZSht
ZXRhLmNvbnRlbnRfdHlwZSkgJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YS5o
YXNfY29udGVudF9sZW5ndGggJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWV0YS5j
b250ZW50X2xlbmd0aCA+IDAgJiYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIWhhc19j
aHVua2VkICYmCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGl2ZV93c3NlX2Zsb3dz
KGZsb3dzKSA8IE1BWF9XU1NFX0JPRFlfRkxPV1MpOwoKICAgICAgICBpZiAod3NzZV9lbGlnaWJs
ZSkgewogICAgICAgICAgZmwuYXdhaXRpbmdfd3NzZSA9IHRydWU7CiAgICAgICAgICBmbC53c3Nl
X2V2ZW50ID0gZTsKICAgICAgICAgIGZsb3dfYnl0ZXNfc3ViKGZsLndzc2VfYnVmLnNpemUoKSk7
CiAgICAgICAgICBmbC53c3NlX2J1Zi5jbGVhcigpOwogICAgICAgICAgZmwud3NzZV9nb2FsID0g
bWV0YS5jb250ZW50X2xlbmd0aCA8IGdfd3NzZV9ib2R5X2J5dGVzID8gbWV0YS5jb250ZW50X2xl
bmd0aCA6IGdfd3NzZV9ib2R5X2J5dGVzOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBxdWV1
ZV9yZXF1ZXN0KGUsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZywgZmwuZmlyc3Rf
Ynl0ZV9tb25vX21zLCBmbC5nZW5lcmF0aW9uKTsKICAgICAgICB9CgogICAgICAgIGlmIChtZXRh
Lmhhc19jb250ZW50X2xlbmd0aCAmJiBtZXRhLmNvbnRlbnRfbGVuZ3RoID4gMCkgewogICAgICAg
ICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0JPRFk7CiAgICAgICAgICBmbC5ib2R5X3Jl
bWFpbmluZyA9IG1ldGEuY29udGVudF9sZW5ndGg7CiAgICAgICAgfSBlbHNlIGlmIChoYXNfY2h1
bmtlZCkgewogICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0NIVU5LOwogICAg
ICAgICAgZmwuY2h1bmtfcmVhZGluZ19sZW4gPSB0cnVlOwogICAgICAgICAgZmwuY2h1bmtfcmVh
ZGluZ190cmFpbGVyID0gZmFsc2U7CiAgICAgICAgICBmbC5jaHVua19yZW1haW5pbmcgPSAwOwog
ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBmbC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVB
REVSOwogICAgICAgICAgZmwuZmlyc3RfYnl0ZV9tb25vX21zID0gZmwuYnVmLmVtcHR5KCkgPyAw
IDogbW9ub19ub3c7CiAgICAgICAgfQogICAgICAgIGNvbnRpbnVlOwogICAgICB9CgogICAgICBp
ZiAoZmwuc3RhdGUgPT0gRmxvdzo6SFRUUF9TVEFURV9CT0RZKSB7CiAgICAgICAgaWYgKGZsLmJ1
Zi5lbXB0eSgpKSBicmVhazsKICAgICAgICBzaXplX3QgdG9fY29uc3VtZSA9IChmbC5idWYuc2l6
ZSgpIDwgZmwuYm9keV9yZW1haW5pbmcpID8gZmwuYnVmLnNpemUoKSA6IGZsLmJvZHlfcmVtYWlu
aW5nOwoKICAgICAgICBpZiAoZmwuYXdhaXRpbmdfd3NzZSkgewogICAgICAgICAgc2l6ZV90IHdz
c2VfbmVlZCA9IGZsLndzc2VfZ29hbCA+IGZsLndzc2VfYnVmLnNpemUoKSA/IGZsLndzc2VfZ29h
bCAtIGZsLndzc2VfYnVmLnNpemUoKSA6IDA7CiAgICAgICAgICBpZiAod3NzZV9uZWVkID4gMCkg
ewogICAgICAgICAgICBzaXplX3QgY29weV9sZW4gPSAodG9fY29uc3VtZSA8IHdzc2VfbmVlZCkg
PyB0b19jb25zdW1lIDogd3NzZV9uZWVkOwogICAgICAgICAgICBmbC53c3NlX2FwcGVuZChmbC5i
dWYuZGF0YSgpLCBjb3B5X2xlbik7CiAgICAgICAgICB9CiAgICAgICAgICBzdGQ6OnN0cmluZyB1
c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC53c3NlX2J1Zik7CiAgICAgICAgICBp
ZiAoIXVzZXJuYW1lLmVtcHR5KCkgfHwgZmwud3NzZV9idWYuc2l6ZSgpID49IGZsLndzc2VfZ29h
bCkgewogICAgICAgICAgICBFdmVudCBldiA9IGZsLndzc2VfZXZlbnQ7CiAgICAgICAgICAgIGlm
ICghdXNlcm5hbWUuZW1wdHkoKSkgewogICAgICAgICAgICAgIGV2Lndzc2VfdXNlciA9IHVzZXJu
YW1lOyBldi51c2VyID0gdXNlcm5hbWU7IGV2LnNjaGVtZSA9ICJ3c3NlIjsKICAgICAgICAgICAg
fQogICAgICAgICAgICBxdWV1ZV9yZXF1ZXN0KGV2LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQs
IHBlbmRpbmcsIGZsLmZpcnN0X2J5dGVfbW9ub19tcywgZmwuZ2VuZXJhdGlvbik7CiAgICAgICAg
ICAgIGZsLmF3YWl0aW5nX3dzc2UgPSBmYWxzZTsKICAgICAgICAgIH0KICAgICAgICB9CgogICAg
ICAgIGZsLmJ1Zl9lcmFzZSgwLCB0b19jb25zdW1lKTsKICAgICAgICBmbC5ib2R5X3JlbWFpbmlu
ZyAtPSB0b19jb25zdW1lOwogICAgICAgIGlmIChmbC5ib2R5X3JlbWFpbmluZyA9PSAwKSB7CiAg
ICAgICAgICBpZiAoZmwuYXdhaXRpbmdfd3NzZSkgewogICAgICAgICAgICBxdWV1ZV9yZXF1ZXN0
KGZsLndzc2VfZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZywgZmwuZmly
c3RfYnl0ZV9tb25vX21zLCBmbC5nZW5lcmF0aW9uKTsKICAgICAgICAgICAgZmwuYXdhaXRpbmdf
d3NzZSA9IGZhbHNlOwogICAgICAgICAgfQogICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQ
X1NUQVRFX0hFQURFUjsKICAgICAgICAgIGZsLmZpcnN0X2J5dGVfbW9ub19tcyA9IGZsLmJ1Zi5l
bXB0eSgpID8gMCA6IG1vbm9fbm93OwogICAgICAgIH0KICAgICAgICBjb250aW51ZTsKICAgICAg
fQoKICAgICAgaWYgKGZsLnN0YXRlID09IEZsb3c6OkhUVFBfU1RBVEVfQ0hVTkspIHsKICAgICAg
ICBpZiAoZmwuYnVmLmVtcHR5KCkpIGJyZWFrOwogICAgICAgIGlmIChmbC5jaHVua19yZWFkaW5n
X3RyYWlsZXIpIHsKICAgICAgICAgIGlmIChmbC5idWYuc2l6ZSgpID49IDIgJiYgZmwuYnVmWzBd
ID09ICdccicgJiYgZmwuYnVmWzFdID09ICdcbicpIHsKICAgICAgICAgICAgZmwuYnVmX2VyYXNl
KDAsIDIpOwogICAgICAgICAgICBmbC5jaHVua19yZWFkaW5nX3RyYWlsZXIgPSBmYWxzZTsKICAg
ICAgICAgICAgZmwuc3RhdGUgPSBGbG93OjpIVFRQX1NUQVRFX0hFQURFUjsKICAgICAgICAgICAg
ZmwuZmlyc3RfYnl0ZV9tb25vX21zID0gZmwuYnVmLmVtcHR5KCkgPyAwIDogbW9ub19ub3c7CiAg
ICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgfQogICAgICAgICAgc2l6ZV90IHRyX2VuZCA9
IGZsLmJ1Zi5maW5kKCJcclxuXHJcbiIpOwogICAgICAgICAgaWYgKHRyX2VuZCAhPSBzdGQ6OnN0
cmluZzo6bnBvcykgewogICAgICAgICAgICBmbC5idWZfZXJhc2UoMCwgdHJfZW5kICsgNCk7CiAg
ICAgICAgICAgIGZsLmNodW5rX3JlYWRpbmdfdHJhaWxlciA9IGZhbHNlOwogICAgICAgICAgICBm
bC5zdGF0ZSA9IEZsb3c6OkhUVFBfU1RBVEVfSEVBREVSOwogICAgICAgICAgICBmbC5maXJzdF9i
eXRlX21vbm9fbXMgPSBmbC5idWYuZW1wdHkoKSA/IDAgOiBtb25vX25vdzsKICAgICAgICAgICAg
Y29udGludWU7CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoZmwuYnVmLnNpemUoKSA+IE1BWF9I
RUFERVJfQllURVMpIHsKICAgICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgICAgICAg
ICBmbC5pc19icm9rZW4gPSB0cnVlOwogICAgICAgICAgfQogICAgICAgICAgYnJlYWs7CiAgICAg
ICAgfQogICAgICAgIGlmIChmbC5jaHVua19yZWFkaW5nX2xlbikgewogICAgICAgICAgc2l6ZV90
IGNybGYgPSBmbC5idWYuZmluZCgiXHJcbiIpOwogICAgICAgICAgaWYgKGNybGYgPT0gc3RkOjpz
dHJpbmc6Om5wb3MpIHsKICAgICAgICAgICAgaWYgKGZsLmJ1Zi5zaXplKCkgPiA2NCkgewogICAg
ICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsKICAgICAgICAgICAgICBmbC5pc19icm9rZW4g
PSB0cnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgfQogICAg
ICAgICAgc3RkOjpzdHJpbmcgbGluZSA9IHRyaW0oZmwuYnVmLnN1YnN0cigwLCBjcmxmKSk7CiAg
ICAgICAgICBzaXplX3Qgc2VtaSA9IGxpbmUuZmluZCgnOycpOwogICAgICAgICAgc3RkOjpzdHJp
bmcgaGV4X3N0ciA9IChzZW1pICE9IHN0ZDo6c3RyaW5nOjpucG9zKSA/IHRyaW0obGluZS5zdWJz
dHIoMCwgc2VtaSkpIDogbGluZTsKICAgICAgICAgIGlmIChoZXhfc3RyLmVtcHR5KCkpIHsKICAg
ICAgICAgICAgZmwuY2xlYXJfYnVmZmVycygpOwogICAgICAgICAgICBmbC5pc19icm9rZW4gPSB0
cnVlOwogICAgICAgICAgICBicmVhazsKICAgICAgICAgIH0KICAgICAgICAgIGJvb2wgdmFsaWRf
aGV4ID0gdHJ1ZTsKICAgICAgICAgIGZvciAoc2l6ZV90IGhpID0gMDsgaGkgPCBoZXhfc3RyLnNp
emUoKTsgKytoaSkgewogICAgICAgICAgICBpZiAoIWlzeGRpZ2l0KCh1bnNpZ25lZCBjaGFyKWhl
eF9zdHJbaGldKSkgeyB2YWxpZF9oZXggPSBmYWxzZTsgYnJlYWs7IH0KICAgICAgICAgIH0KICAg
ICAgICAgIGlmICghdmFsaWRfaGV4KSB7CiAgICAgICAgICAgIGZsLmNsZWFyX2J1ZmZlcnMoKTsK
ICAgICAgICAgICAgZmwuaXNfYnJva2VuID0gdHJ1ZTsKICAgICAgICAgICAgYnJlYWs7CiAgICAg
ICAgICB9CiAgICAgICAgICBjaGFyICplbmRwdHIgPSBOVUxMOwogICAgICAgICAgc2l6ZV90IGNo
dW5rX2xlbiA9IChzaXplX3Qpc3RydG91bChoZXhfc3RyLmNfc3RyKCksICZlbmRwdHIsIDE2KTsK
ICAgICAgICAgIGZsLmJ1Zl9lcmFzZSgwLCBjcmxmICsgMik7CiAgICAgICAgICBpZiAoY2h1bmtf
bGVuID09IDApIHsKICAgICAgICAgICAgZmwuY2h1bmtfcmVhZGluZ190cmFpbGVyID0gdHJ1ZTsK
ICAgICAgICAgICAgY29udGludWU7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBmbC5j
aHVua19yZW1haW5pbmcgPSBjaHVua19sZW4gKyAyOwogICAgICAgICAgICBmbC5jaHVua19yZWFk
aW5nX2xlbiA9IGZhbHNlOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBz
aXplX3QgdG9fY29uc3VtZSA9IChmbC5idWYuc2l6ZSgpIDwgZmwuY2h1bmtfcmVtYWluaW5nKSA/
IGZsLmJ1Zi5zaXplKCkgOiBmbC5jaHVua19yZW1haW5pbmc7CiAgICAgICAgICBmbC5idWZfZXJh
c2UoMCwgdG9fY29uc3VtZSk7CiAgICAgICAgICBmbC5jaHVua19yZW1haW5pbmcgLT0gdG9fY29u
c3VtZTsKICAgICAgICAgIGlmIChmbC5jaHVua19yZW1haW5pbmcgPT0gMCkgZmwuY2h1bmtfcmVh
ZGluZ19sZW4gPSB0cnVlOwogICAgICAgIH0KICAgICAgICBjb250aW51ZTsKICAgICAgfQogICAg
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
KSB7CiAgICAgIGxvZ21zZygicG9sbCBlcnJvciBlbmNvdW50ZXJlZCIpOwogICAgICBicmVhazsK
ICAgIH0gZWxzZSBpZiAocmMgPiAwICYmIChwZmQucmV2ZW50cyAmIChQT0xMRVJSIHwgUE9MTE5W
QUwpKSkgewogICAgICBsb2dtc2coInBvbGwgZXJyb3IgcmV2ZW50cyBkZXRlY3RlZCIpOwogICAg
ICBicmVhazsKICAgIH0gZWxzZSBpZiAocmMgPiAwKSB7CiAgICAgIHNpemVfdCBkcmFpbl9jb3Vu
dCA9IDA7CiAgICAgIHdoaWxlIChnX3J1bm5pbmcgJiYgZHJhaW5fY291bnQgPCBNQVhfRFJBSU5f
UEVSX1BBU1MpIHsKICAgICAgICB1bnNpZ25lZCBiX2lkeCA9IHJpbmcuZnJhbWVfaWR4IC8gcmlu
Zy5mcmFtZXNfcGVyX2Jsb2NrOwogICAgICAgIHVuc2lnbmVkIGZfaW5fYiA9IHJpbmcuZnJhbWVf
aWR4ICUgcmluZy5mcmFtZXNfcGVyX2Jsb2NrOwogICAgICAgIHVpbnQ4X3QgKmZyYW1lX3B0ciA9
ICgodWludDhfdCAqKXJpbmcucmluZykgKyAoYl9pZHggKiByaW5nLmJsb2NrX3NpemUpICsgKGZf
aW5fYiAqIHJpbmcuZnJhbWVfc2l6ZSk7CiAgICAgICAgdm9sYXRpbGUgc3RydWN0IHRwYWNrZXQy
X2hkciAqdm9sYXRpbGVfaGRyID0KICAgICAgICAgICAgKHZvbGF0aWxlIHN0cnVjdCB0cGFja2V0
Ml9oZHIgKilmcmFtZV9wdHI7CgogICAgICAgIGlmICghKHZvbGF0aWxlX2hkci0+dHBfc3RhdHVz
ICYgVFBfU1RBVFVTX1VTRVIpKSB7CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICAgICAg
X19zeW5jX3N5bmNocm9uaXplKCk7CgogICAgICAgIGNvbnN0IHN0cnVjdCB0cGFja2V0Ml9oZHIg
KmhkciA9CiAgICAgICAgICAgIChjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVfcHRy
OwogICAgICAgIHNpemVfdCBwYWNrZXRfb2Zmc2V0ID0gMCwgcGFja2V0X2xlbmd0aCA9IDA7CiAg
ICAgICAgaWYgKCF2YWxpZF9yaW5nX2ZyYW1lKGhkciwgcmluZy5mcmFtZV9zaXplLAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAmcGFja2V0X29mZnNldCwgJnBhY2tldF9sZW5ndGgpKSB7
CiAgICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsKICAgICAgICAgIHZvbGF0aWxlX2hkci0+
dHBfc3RhdHVzID0gVFBfU1RBVFVTX0tFUk5FTDsKICAgICAgICAgIHJpbmdfaW50ZWdyaXR5X2Zh
aWx1cmUgPSB0cnVlOwogICAgICAgICAgKytnX2ludmFsaWRfZnJhbWVzOwogICAgICAgICAgZ19y
dW5uaW5nID0gMDsKICAgICAgICAgIGxvZ21zZygiaW52YWxpZCBUUEFDS0VUX1YyIGZyYW1lIG1l
dGFkYXRhOyBzdG9wcGluZyBjYXB0dXJlIik7CiAgICAgICAgICBicmVhazsKICAgICAgICB9CiAg
ICAgICAgaWYgKHBhY2tldF9sZW5ndGggPiAwKSB7CiAgICAgICAgICBjb25zdCB1bnNpZ25lZCBj
aGFyICpwa3QgPSBmcmFtZV9wdHIgKyBwYWNrZXRfb2Zmc2V0OwogICAgICAgICAgKytnX2NhcHR1
cmVfcGFja2V0czsKICAgICAgICAgIGdfY2FwdHVyZV9ieXRlcyArPSBwYWNrZXRfbGVuZ3RoOwog
ICAgICAgICAgaGFuZGxlX3BhY2tldChwa3QsIHBhY2tldF9sZW5ndGgsIG5vZGUsIHBvcnRzLCBm
bG93cywgcGVuZGluZyk7CiAgICAgICAgfQoKICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsK
ICAgICAgICB2b2xhdGlsZV9oZHItPnRwX3N0YXR1cyA9IFRQX1NUQVRVU19LRVJORUw7CiAgICAg
ICAgcmluZy5mcmFtZV9pZHggPSAocmluZy5mcmFtZV9pZHggKyAxKSAlIHJpbmcuZnJhbWVfbnI7
CiAgICAgICAgKytkcmFpbl9jb3VudDsKICAgICAgfQogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0
eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKICAgIH0KCiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxM
KTsKICAgIGlmIChub3cgLSBsYXN0ID49IDEpIHsKICAgICAgc3dlZXAoZmxvd3MsIHBlbmRpbmcs
IG5vdywgZ19wZW5kaW5nX3R0bF9zZWMpOwogICAgICBpZiAoZ19lbmRwb2ludC5lbXB0eSgpKSBz
dGQ6OmNvdXQuZmx1c2goKTsKICAgICAgbGFzdCA9IG5vdzsKICAgIH0KCiAgICBpZiAod2FsbF9z
ZWNvbmRzKCkgLSBnX3N0YXRzX2xhc3RfYXQgPj0gZ19zdGF0c19pbnRlcnZhbF9zZWMpIHsKICAg
ICAgc2l6ZV90IHBlbmRpbmdfY291bnQgPSAwLCB3c3NlX2NvdW50ID0gMDsKICAgICAgZm9yIChz
dGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHBpID0g
cGVuZGluZy5iZWdpbigpOyBwaSAhPSBwZW5kaW5nLmVuZCgpOyArK3BpKQogICAgICAgIHBlbmRp
bmdfY291bnQgKz0gcGktPnNlY29uZC5zaXplKCk7CiAgICAgIGZvciAoc3RkOjptYXA8Rmxvd0tl
eSwgRmxvdz46Oml0ZXJhdG9yIGZpID0gZmxvd3MuYmVnaW4oKTsgZmkgIT0gZmxvd3MuZW5kKCk7
ICsrZmkpCiAgICAgICAgaWYgKGZpLT5zZWNvbmQuYXdhaXRpbmdfd3NzZSkgKyt3c3NlX2NvdW50
OwogICAgICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSkKICAgICAgICBzZW5kX2FnZW50X3N0YXRz
KGZkLCBmbG93cy5zaXplKCksIHBlbmRpbmdfY291bnQsIHdzc2VfY291bnQpOwogICAgICBlbHNl
CiAgICAgICAgZW1pdF9jYXB0dXJlX3N0YXRzX2ludGVybmFsKGZkLCBmbG93cy5zaXplKCksIHBl
bmRpbmdfY291bnQsIHdzc2VfY291bnQpOwogICAgfQogIH0KCiAgZmx1c2hfaW5jb21wbGV0ZV93
c3NlKGZsb3dzLCBwZW5kaW5nKTsKICBmbHVzaF9hbGxfcGVuZGluZyhwZW5kaW5nKTsKICBpZiAo
Z19lbmRwb2ludC5lbXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKCiAgaWYgKGdfc2hpcF93b3Jr
ZXJfYWN0aXZlKSB7CiAgICBwdGhyZWFkX211dGV4X2xvY2soJmdfc2hpcF9xdWV1ZV9tdXRleCk7
CiAgICBwdGhyZWFkX2NvbmRfc2lnbmFsKCZnX3NoaXBfcXVldWVfY29uZCk7CiAgICBwdGhyZWFk
X211dGV4X3VubG9jaygmZ19zaGlwX3F1ZXVlX211dGV4KTsKICAgIHB0aHJlYWRfam9pbihnX3No
aXBfd29ya2VyX3RpZCwgTlVMTCk7CiAgfSBlbHNlIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHsK
ICAgIHNpemVfdCBwZW5kaW5nX2NvdW50ID0gMDsKICAgIGVtaXRfY2FwdHVyZV9zdGF0c19pbnRl
cm5hbChmZCwgMCwgcGVuZGluZ19jb3VudCwgMCk7CiAgfQoKICB1cGRhdGVfa2VybmVsX2Ryb3Bz
KGZkKTsKICBsb2dtc2coInBhY2tldCBzdGF0czogcmVjZWl2ZWQ9IiArIHVsbF9zdHJpbmcoZ19j
YXB0dXJlX3BhY2tldHMpICsKICAgICAgICAgIiBkcm9wcGVkPSIgKyB1bGxfc3RyaW5nKGdfa2Vy
bmVsX2Ryb3BzKSk7CiAgaWYgKCFyZWxlYXNlX21tYXBfcmluZyhmZCwgcmluZykpIHsKICAgIGxv
Z21zZygiVFBBQ0tFVF9WMiBjbGVhbnVwIGZhaWxlZCIpOwogICAgcmluZ19pbnRlZ3JpdHlfZmFp
bHVyZSA9IHRydWU7CiAgfQogIGNsb3NlKGZkKTsKICBsb2dtc2coInN0b3BwZWQiKTsKICByZXR1
cm4gcmluZ19pbnRlZ3JpdHlfZmFpbHVyZSA/IDIgOiAwOwp9Cg==
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
