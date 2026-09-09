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
           && su -s /bin/sh "$SNIFF_USER" -c "$PREFIX/nt-sniff-cpp --capability-probe -i $IFACE -p $PORTS" >/dev/null 2>&1; then
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
        RUN_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT --ship-rate-kbps $SHIP_RATE_KBPS --wsse-body-bytes $WSSE_BODY_BYTES' >>\$PREFIX/sniff.log 2>&1"
    else
        RUN_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS --endpoint $ENDPOINT --ship-rate-kbps $SHIP_RATE_KBPS --wsse-body-bytes $WSSE_BODY_BYTES >>\$PREFIX/sniff.log 2>&1"
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
export NT_SHIP_RATE_KBPS=$SHIP_RATE_KBPS
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
log "Safety: rootless, cpu=$CPU_CORE (one logical core/SCHED_IDLE/nice 19), memory=256MiB, fds=1024, output-file=32MiB, crash circuit=5"
log "Network egress: aggregate application payload limit=${SHIP_RATE_KBPS}kbit/s, HTTP body cap=65536 bytes"
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
Cgp0cnk6CiAgICBpbXBvcnQgbnRfY29udHJvbApleGNlcHQgSW1wb3J0RXJyb3I6CiAgICBudF9j
b250cm9sID0gTm9uZQoKIyBweTIuNiBzdHItaW5kZXhpbmcgeWllbGRzIDEtY2hhciBzdHIsIG5v
dCBpbnQgKHByb3ZlbiBvbiByZWFsIGVsNiBWTSk7CiMgbm9ybWFsaXplIHNvIGJ5dGUtYXQtaW5k
ZXggd29ya3MgaWRlbnRpY2FsbHkgdW5kZXIgcHl0aG9uIDIgYW5kIDMKUFkyID0gc3lzLnZlcnNp
b25faW5mb1swXSA9PSAyCgoKZGVmIGIyaShjKToKICAgIHJldHVybiBvcmQoYykgaWYgUFkyIGVs
c2UgYwoKTUVUSE9EUyA9ICgiR0VUIiwgIlBPU1QiLCAiUFVUIiwgIkRFTEVURSIsICJQQVRDSCIs
ICJIRUFEIiwgIk9QVElPTlMiKQoKTUFYX0ZMT1dTID0gODE5MiAgICAgICAgICAgICMgY29uY3Vy
cmVudCB0cmFja2VkIGhhbGYtZmxvd3MgKHBlciBkaXJlY3Rpb24pCk1BWF9IRFJTID0gMjYyMTQ0
ICAgICAgICAgICAjIG1heCBieXRlcyBidWZmZXJlZCB3YWl0aW5nIGZvciBcclxuXHJcbgpGTE9X
X1RUTCA9IDMwMCAgICAgICAgICAgICAgIyBzZWNvbmRzIGJlZm9yZSBpZGxlIGZsb3cgYnVmZmVy
cyBhcmUgZHJvcHBlZApNQVhfV1NTRV9CT0RZX0JZVEVTID0gNjU1MzYgIyBoYXJkIGNlaWxpbmcg
ZXZlbiBpZiBjb25maWd1cmF0aW9uIGlzIGxhcmdlcgpNQVhfV1NTRV9CT0RZX0ZMT1dTID0gMjU2
ICAgIyBhdCBtb3N0IDE2IE1pQiBvZiBvcHQtaW4gYm9keSBidWZmZXJzIGdsb2JhbGx5Ck1BWF9X
U1NFX1VTRVJOQU1FID0gMjAwCgpXU1NFX05BTUVTUEFDRVMgPSBzZXQoKAogICAgImh0dHA6Ly9k
b2NzLm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxL29hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0
eS1zZWNleHQtMS4wLnhzZCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAw
Mi8wNy9zZWNleHQiLAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMTIv
c2VjZXh0IiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAzLzA2L3NlY2V4
dCIsCikpCgoKZGVmIGxvZyhtc2cpOgogICAgc3lzLnN0ZGVyci53cml0ZSgibnQtc25pZmY6ICVz
XG4iICUgbXNnKQogICAgc3lzLnN0ZGVyci5mbHVzaCgpCgoKZGVmIGRyb3BfY2FwdHVyZV9jYXBh
YmlsaXRpZXMoKToKICAgICIiIklycmV2ZXJzaWJseSBjbGVhciBDQVBfTkVUX1JBVyBhZnRlciB0
aGUgcGFja2V0IHNvY2tldCBpcyByZWFkeS4iIiIKICAgIHRyeToKICAgICAgICBpbXBvcnQgY3R5
cGVzCiAgICAgICAgbGliY2FwID0gY3R5cGVzLkNETEwoImxpYmNhcC5zby4yIikKICAgICAgICBs
aWJjYXAuY2FwX2luaXQucmVzdHlwZSA9IGN0eXBlcy5jX3ZvaWRfcAogICAgICAgIGVtcHR5ID0g
bGliY2FwLmNhcF9pbml0KCkKICAgICAgICBpZiBub3QgZW1wdHk6CiAgICAgICAgICAgIHJldHVy
biBGYWxzZQogICAgICAgIHRyeToKICAgICAgICAgICAgcmV0dXJuIGxpYmNhcC5jYXBfc2V0X3By
b2MoY3R5cGVzLmNfdm9pZF9wKGVtcHR5KSkgPT0gMAogICAgICAgIGZpbmFsbHk6CiAgICAgICAg
ICAgIGxpYmNhcC5jYXBfZnJlZShjdHlwZXMuY192b2lkX3AoZW1wdHkpKQogICAgZXhjZXB0IEV4
Y2VwdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gcGVyZjogY0JQRgojIEF0
dGFjaCBhIGNsYXNzaWMgQlBGIHByb2dyYW0gc28gdGhlIEtFUk5FTCBkcm9wcyBldmVyeXRoaW5n
IHRoYXQgaXMgbm90CiMgSVB2NCBUQ1AgdG8gb3IgZnJvbSBhIG1vbml0b3JlZCBwb3J0LiBSZXF1
ZXN0IGhlYWRlcnMgZHJpdmUgZXZlbnRzIGFuZAojIHJlc3BvbnNlIGhlYWRlcnMgZW5yaWNoIHRo
ZW07IHVucmVsYXRlZCB0cmFmZmljIG5ldmVyIHJlYWNoZXMgdXNlcnNwYWNlLgpTT19BVFRBQ0hf
RklMVEVSID0gMjYKCmRlZiBidWlsZF9icGYocG9ydHMpOgogICAgIiIiQ2xhc3NpYyBCUEY6IGV0
aGVydHlwZT09SVAgJiYgcHJvdG89PVRDUCAmJiBkcG9ydCBpbiBwb3J0cy4KICAgIFJldHVybnMg
KGZwcm9nX3N0cnVjdCwgZmlsdGVyX2FycmF5KSBmb3IgdGhlIGxpYmMgc2V0c29ja29wdCBjYWxs
LAogICAgb3IgTm9uZSBvbiBmYWlsdXJlLiBOT1RFOiBzb2NrX2Zwcm9nIGNhcnJpZXMgYSBQT0lO
VEVSIHRvIHRoZSBmaWx0ZXIKICAgIGFycmF5LCBzbyBpdCBtdXN0IHN0YXkgYWxpdmUgdW50aWwg
dGhlIHN5c2NhbGwg4oCUIHB5dGhvbidzCiAgICBzb2NrZXQuc2V0c29ja29wdChzdHIpIGZsYXR0
ZW5pbmcgY2Fubm90IHByZXNlcnZlIGl0LiIiIgoKICAgIExESF9BQlMgPSAweDI4ICAgIyBsZCBb
a106aAogICAgTERCX0FCUyA9IDB4MzAgICAjIGxkIFtrXTpiCiAgICBKRVFfSyA9IDB4MTUgICAg
ICMgamVxIGsKICAgIExEWF9NU0ggPSAweEIxICAgIyB4ID0gNCooW2tdJjB4ZikgIChpaGwgYnl0
ZXMpCiAgICBMREhfSU5EID0gMHg0OCAgICMgbGQgW3gra106aAogICAgUkVUX0sgPSAweDA2Cgog
ICAgIyBQUk9WRU4gZHBvcnQgYmxvY2sgKyBzcG9ydCBibG9jayBhdCBYKzE0IChjYWxpYnJhdGVk
IEVNUElSSUNBTExZIG9uCiAgICAjIGEgbGl2ZSBrZXJuZWw6IGs9MTQgZGVsaXZlcnMgcmVzcG9u
c2UgcGFja2V0czsgdGhlIGNvcnJlbGF0aW9uIHRoZW4KICAgICMgeWllbGRzIHN0YXR1cy9kdXJh
dGlvbl9tcy9yZXNwX2J5dGVzIGVuZC10by1lbmQpLiBSZXF1aXJlcyB0aGUgMXMKICAgICMgcmVj
diB0aW1lb3V0IGluIG1haW4oKSDigJQgYmxvY2tpbmcgcmVjdiArIEJQRiBzdGFydmVzIGFmdGVy
IG9uZSBwa3QuCiAgICBzayA9IGludChvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfU1BPUlRfSyIs
ICIxNCIpKQogICAgcHMgPSBzb3J0ZWQocG9ydHMpCiAgICBuID0gbGVuKHBzKQogICAgcmV0X3Jl
aiA9IDUgKyAoNCBpZiBzayBlbHNlIDIpICogbgogICAgcmV0X2FjYyA9IHJldF9yZWogKyAxCiAg
ICBwcm9nID0gW10KICAgIHByb2cuYXBwZW5kKChMREhfQUJTLCAwLCAwLCAxMikpICAgICAgICAg
ICAgICAgICAjIGV0aGVydHlwZSA9PSBJUD8KICAgIHByb2cuYXBwZW5kKChKRVFfSywgMCwgcmV0
X3JlaiAtIDIsIDB4MDgwMCkpCiAgICBwcm9nLmFwcGVuZCgoTERCX0FCUywgMCwgMCwgMjMpKSAg
ICAgICAgICAgICAgICAgIyBwcm90byA9PSBUQ1A/CiAgICBwcm9nLmFwcGVuZCgoSkVRX0ssIDAs
IHJldF9yZWogLSA0LCA2KSkKICAgIHByb2cuYXBwZW5kKChMRFhfTVNILCAwLCAwLCAxNCkpICAg
ICAgICAgICAgICAgICAjIFggPSBpaGwqNAogICAgZm9yIGksIHAgaW4gZW51bWVyYXRlKHBzKTog
ICAgICAgICAgICAgICAgICAgICAgICMgQTogZHBvcnQgQCBYKzE2CiAgICAgICAgcHJvZy5hcHBl
bmQoKExESF9JTkQsIDAsIDAsIDE2KSkKICAgICAgICBqdCA9IHJldF9hY2MgLSAobGVuKHByb2cp
ICsgMSkKICAgICAgICBqZiA9IDAgaWYgKGkgPCBuIC0gMSBvciBzaykgZWxzZSAocmV0X3JlaiAt
IChsZW4ocHJvZykgKyAxKSkKICAgICAgICBwcm9nLmFwcGVuZCgoSkVRX0ssIGp0LCBqZiwgcCkp
CiAgICBpZiBzazogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIyBC
OiBzcG9ydCBAIFgrc2sKICAgICAgICBmb3IgaSwgcCBpbiBlbnVtZXJhdGUocHMpOgogICAgICAg
ICAgICBwcm9nLmFwcGVuZCgoTERIX0lORCwgMCwgMCwgc2spKQogICAgICAgICAgICBqdCA9IHJl
dF9hY2MgLSAobGVuKHByb2cpICsgMSkKICAgICAgICAgICAgamYgPSAwIGlmIGkgPCBuIC0gMSBl
bHNlIChyZXRfcmVqIC0gKGxlbihwcm9nKSArIDEpKQogICAgICAgICAgICBwcm9nLmFwcGVuZCgo
SkVRX0ssIGp0LCBqZiwgcCkpCiAgICBwcm9nLmFwcGVuZCgoUkVUX0ssIDAsIDAsIDApKSAgICAg
ICAgICAgICAgICAgICAgIyByZWplY3QKICAgIHByb2cuYXBwZW5kKChSRVRfSywgMCwgMCwgMHg0
MDAwMCkpICAgICAgICAgICAgICAjIGFjY2VwdAogICAgaWYgYW55KGp0ID4gMjU1IG9yIGpmID4g
MjU1IGZvciBfLCBqdCwgamYsIF8gaW4gcHJvZyk6CiAgICAgICAgcmV0dXJuIE5vbmUKCiAgICB0
cnk6CiAgICAgICAgaW1wb3J0IGN0eXBlcwoKICAgICAgICBjbGFzcyBTb2NrRmlsdGVyKGN0eXBl
cy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImNvZGUiLCBjdHlwZXMuY191
aW50MTYpLCAoImp0IiwgY3R5cGVzLmNfdWludDgpLAogICAgICAgICAgICAgICAgICAgICAgICAo
ImpmIiwgY3R5cGVzLmNfdWludDgpLCAoImsiLCBjdHlwZXMuY191aW50MzIpXQoKICAgICAgICBj
bGFzcyBTb2NrRnByb2coY3R5cGVzLlN0cnVjdHVyZSk6CiAgICAgICAgICAgICMgbWlycm9ycyBz
dHJ1Y3Qgc29ja19mcHJvZyB7dTE2IGxlbjsgc29ja19maWx0ZXIgKmZpbHRlcn07CiAgICAgICAg
ICAgICMgY3R5cGVzIGFwcGxpZXMgdGhlIHNhbWUgcG9pbnRlciBhbGlnbm1lbnQgYXMgdGhlIGNv
bXBpbGVyCiAgICAgICAgICAgIF9maWVsZHNfID0gWygibGVuIiwgY3R5cGVzLmNfdWludDE2KSwK
ICAgICAgICAgICAgICAgICAgICAgICAgKCJmaWx0ZXIiLCBjdHlwZXMuUE9JTlRFUihTb2NrRmls
dGVyKSldCgogICAgICAgIGFyciA9IChTb2NrRmlsdGVyICogbGVuKHByb2cpKSgpCiAgICAgICAg
Zm9yIGksIChjb2RlLCBqdCwgamYsIGspIGluIGVudW1lcmF0ZShwcm9nKToKICAgICAgICAgICAg
YXJyW2ldLmNvZGUgPSBjb2RlOyBhcnJbaV0uanQgPSBqdAogICAgICAgICAgICBhcnJbaV0uamYg
PSBqZjsgYXJyW2ldLmsgPSBrCiAgICAgICAgcmV0dXJuIFNvY2tGcHJvZyhsZW4ocHJvZyksIGFy
ciksIGFycgogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBh
cHBseV9wZXJmX29wdHMoc29jaywgcG9ydHMpOgogICAgIiIiQXR0YWNoIHRoZSBtYW5kYXRvcnkg
a2VybmVsIHBvcnQgZmlsdGVyIGFuZCB0dW5lIHRoZSByZWNlaXZlIGJ1ZmZlci4iIiIKICAgIGJ1
aWx0ID0gYnVpbGRfYnBmKHBvcnRzKQogICAgZmlsdGVyX29rID0gRmFsc2UKICAgIGlmIGJ1aWx0
IGlzIG5vdCBOb25lOgogICAgICAgIHRyeToKICAgICAgICAgICAgaW1wb3J0IGN0eXBlcwogICAg
ICAgICAgICBsaWJjID0gY3R5cGVzLkNETEwoImxpYmMuc28uNiIpCiAgICAgICAgICAgIGZwcm9n
LCBhcnIgPSBidWlsdCAgICAgICAgICAgICAgICAgICAgICAjIGtlZXAgYXJyIHJlZmVyZW5jZWQh
CiAgICAgICAgICAgIHJldCA9IGxpYmMuc2V0c29ja29wdChzb2NrLmZpbGVubygpLCBzb2NrZXQu
U09MX1NPQ0tFVCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNPX0FUVEFDSF9G
SUxURVIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuYnlyZWYoZnBy
b2cpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3R5cGVzLnNpemVvZihmcHJv
ZykpCiAgICAgICAgICAgIGlmIHJldCA9PSAwOgogICAgICAgICAgICAgICAgbG9nKCJrZXJuZWwg
QlBGIGZpbHRlciBhdHRhY2hlZCAoJWQgbW9uaXRvcmVkIHBvcnRzKSIKICAgICAgICAgICAgICAg
ICAgICAlIGxlbihwb3J0cykpCiAgICAgICAgICAgICAgICBmaWx0ZXJfb2sgPSBUcnVlCiAgICAg
ICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBsb2coIkJQRiBhdHRhY2ggcmVqZWN0ZWQgYnkg
a2VybmVsIChyZXQ9JWQpIiAlIHJldCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAg
ICAgICAgICAgIGxvZygiQlBGIGZpbHRlciBhdHRhY2ggZmFpbGVkICglcykiICUgZSkKICAgIGVs
c2U6CiAgICAgICAgbG9nKCJCUEYgY29uc3RydWN0aW9uIHVuYXZhaWxhYmxlIikKICAgIHRyeToK
ICAgICAgICB3YW50ID0gOCAqIDEwMjQgKiAxMDI0CiAgICAgICAgc29jay5zZXRzb2Nrb3B0KHNv
Y2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fUkNWQlVGLCB3YW50KQogICAgICAgIGdvdCA9IHNv
Y2suZ2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCwgc29ja2V0LlNPX1JDVkJVRikKICAgICAg
ICBsb2coInJjdmJ1ZjogJWQgYnl0ZXMiICUgZ290KQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBl
OgogICAgICAgIGxvZygiV0FSTjogU09fUkNWQlVGIHJhaXNlIGZhaWxlZDogJXMiICUgZSkKICAg
IHJldHVybiBmaWx0ZXJfb2sKCgpkZWYgcGFyc2Vfd3NzZV9ib2R5X2J5dGVzKHZhbHVlKToKICAg
ICIiIlZhbGlkYXRlIHRoZSBvcHQtaW4gYm9keSB3aW5kb3cgd2l0aG91dCBhbGxvd2luZyB1bmJv
dW5kZWQgYnVmZmVycy4iIiIKICAgIHRyeToKICAgICAgICBzaXplID0gaW50KHZhbHVlIG9yIDAp
CiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmFpc2UgU3lzdGVt
RXhpdCgid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgYW4gaW50ZWdlciIpCiAgICBpZiBzaXplIDwg
MCBvciBzaXplID4gTUFYX1dTU0VfQk9EWV9CWVRFUzoKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0
KCJ3c3NlIGJvZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi4lZCIgJQogICAgICAgICAgICAg
ICAgICAgICAgICAgTUFYX1dTU0VfQk9EWV9CWVRFUykKICAgIHJldHVybiBzaXplCgoKZGVmIHBh
cnNlX2FyZ3MoYXJndik6CiAgICBpZmFjZSA9IE5vbmUKICAgIHBvcnRzID0gWzgwLCA4MDAzLCA4
MDA1LCA4MDA3LCA4MDA5LCA4MDEwLCA4MDExXQogICAgdmVyYm9zZSA9IEZhbHNlCiAgICB3b3Jr
ZXJzID0gMQogICAgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2Vfd3NzZV9ib2R5X2J5dGVzKAogICAg
ICAgIG9zLmVudmlyb24uZ2V0KCJOVF9XU1NFX0JPRFlfQllURVMiLCAiMCIpKQogICAgaSA9IDAK
ICAgIHdoaWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFyZ3ZbaV0KICAgICAgICBpZiBh
ID09ICItaSI6CiAgICAgICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAgICAgICAg
ICAgIHJhaXNlIFN5c3RlbUV4aXQoIi1pIHJlcXVpcmVzIGFuIGludGVyZmFjZSIpCiAgICAgICAg
ICAgIGkgKz0gMTsgaWZhY2UgPSBhcmd2W2ldCiAgICAgICAgZWxpZiBhID09ICItcCI6CiAgICAg
ICAgICAgIGlmIGkgKyAxID49IGxlbihhcmd2KToKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3Rl
bUV4aXQoIi1wIHJlcXVpcmVzIGEgY29tbWEtc2VwYXJhdGVkIHBvcnQgbGlzdCIpCiAgICAgICAg
ICAgIGkgKz0gMQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBwb3J0cyA9IFtpbnQo
eCkgZm9yIHggaW4gYXJndltpXS5zcGxpdCgiLCIpIGlmIHguc3RyaXAoKV0KICAgICAgICAgICAg
ZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJpbnZh
bGlkIHBvcnQgbGlzdCIpCiAgICAgICAgICAgIGlmIG5vdCBwb3J0cyBvciBhbnkobm90IHZhbGlk
X3BvcnQoeCkgZm9yIHggaW4gcG9ydHMpOgogICAgICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhp
dCgicG9ydHMgbXVzdCBiZSBpbiByYW5nZSAxLi42NTUzNSIpCiAgICAgICAgICAgIGlmIGxlbihw
b3J0cykgPiAzMDoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoImF0IG1vc3QgMzAg
bW9uaXRvcmVkIHBvcnRzIGFyZSBzdXBwb3J0ZWQiKQogICAgICAgIGVsaWYgYSA9PSAiLWoiOgog
ICAgICAgICAgICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCItaiByZXF1aXJlcyBhIHdvcmtlciBjb3VudCIpCiAgICAgICAgICAgIGkgKz0g
MQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB3b3JrZXJzID0gaW50KGFyZ3ZbaV0p
CiAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAgcmFpc2UgU3lz
dGVtRXhpdCgiaW52YWxpZCB3b3JrZXIgY291bnQiKQogICAgICAgICAgICBpZiB3b3JrZXJzICE9
IDE6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJvbmx5IG9uZSBjYXB0dXJlIHdv
cmtlciBpcyBwZXJtaXR0ZWQiKQogICAgICAgIGVsaWYgYSA9PSAiLXYiOgogICAgICAgICAgICB2
ZXJib3NlID0gVHJ1ZQogICAgICAgIGVsaWYgYSA9PSAiLS13c3NlLWJvZHktYnl0ZXMiOgogICAg
ICAgICAgICBpZiBpICsgMSA+PSBsZW4oYXJndik6CiAgICAgICAgICAgICAgICByYWlzZSBTeXN0
ZW1FeGl0KCItLXdzc2UtYm9keS1ieXRlcyByZXF1aXJlcyBhIGJ5dGUgY291bnQiKQogICAgICAg
ICAgICBpICs9IDEKICAgICAgICAgICAgd3NzZV9ib2R5X2J5dGVzID0gcGFyc2Vfd3NzZV9ib2R5
X2J5dGVzKGFyZ3ZbaV0pCiAgICAgICAgZWxpZiBhIGluICgiLWgiLCAiLS1oZWxwIik6CiAgICAg
ICAgICAgIHByaW50KF9fZG9jX18pOyByYWlzZSBTeXN0ZW1FeGl0KDApCiAgICAgICAgZWxzZToK
ICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgidW5rbm93biBhcmc6ICVzIiAlIGEpCiAgICAg
ICAgaSArPSAxCiAgICByZXR1cm4gaWZhY2UsIHNldChwb3J0cyksIHZlcmJvc2UsIHdvcmtlcnMs
IHdzc2VfYm9keV9ieXRlcwoKCmNsYXNzIEZsb3cob2JqZWN0KToKICAgIF9fc2xvdHNfXyA9ICgi
YnVmIiwgImhkcnMiLCAidG91Y2hlZCIsICJldmVudCIsICJib2R5X2dvYWwiLAogICAgICAgICAg
ICAgICAgICJoZWFkX2J5dGVzIikKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxm
LmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgc2VsZi5oZHJzID0gTm9uZQogICAgICAgIHNlbGYu
dG91Y2hlZCA9IHRpbWUudGltZSgpCiAgICAgICAgc2VsZi5ldmVudCA9IE5vbmUKICAgICAgICBz
ZWxmLmJvZHlfZ29hbCA9IDAKICAgICAgICBzZWxmLmhlYWRfYnl0ZXMgPSAwCgoKIyAtLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHJlc3BvbnNlIGNvcnJl
bGF0aW9uIC0tLS0KUEVORElOR19UVEwgPSA1LjAgICAgICAgICMgZmx1c2ggdW5tYXRjaGVkIHJl
cXVlc3RzIGFmdGVyIHRoaXMgbWFueSBzZWNvbmRzClBFTkRJTkdfTUFYID0gODE5MiAgICAgICAj
IGhhcmQgY2FwOyBvdmVyZmxvdyBmbHVzaGVzIG9sZGVzdCBmaXJzdApQRU5ESU5HX1BFUl9GTE9X
ID0gMzIgICAgIyBib3VuZCBhIHNpbmdsZSBwaXBlbGluZWQvaG9zdGlsZSBrZWVwLWFsaXZlIGZs
b3cKU1dFRVBfSU5URVJWQUwgPSAxLjAgICAgICMgaG9ub3IgUEVORElOR19UVEwgZXZlbiB3aGVu
IHRoZSBzb2NrZXQgZ29lcyBpZGxlCgojIHBlbmRpbmdbKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwg
ZHBvcnQpXSAgLS0ga2V5IGlzIHRoZSBSRVNQT05TRSB0dXBsZToKIyBzZXJ2ZXItPmNsaWVudC4g
VmFsdWU6IFtldmVudCwgcmVxX3RzXS4gQSBsaXN0IHBlciBrZXkgaGFuZGxlcyBIVFRQCiMga2Vl
cC1hbGl2ZSBwaXBlbGluaW5nIChzZXZlcmFsIHJlcXVlc3RzIGJlZm9yZSByZXNwb25zZXMgYXJy
aXZlKS4KcGVuZGluZyA9IHt9CgoKZGVmIHBlbmRpbmdfZGVsKHJrKToKICAgIHBlbmRpbmcucG9w
KHJrLCBOb25lKQoKCmRlZiBwZW5kaW5nX3BvcChyaywgb3V0LCBwZW5kaW5nX3RibD1Ob25lKToK
ICAgICIiIkZsdXNoIHRoZSBvbGRlc3QgcGVuZGluZyBldmVudCBmb3IgdGhpcyByZXNwb25zZSB0
dXBsZSAoRklOL1JTVCBvcgogICAgb3ZlcmZsb3cgcGF0aCkuIEVtaXRzIHdoYXRldmVyIHRoZSBl
dmVudCBoYXMg4oCUIHN0YXR1cyBzdGF5cyBudWxsLiIiIgogICAgaWYgcGVuZGluZ190YmwgaXMg
Tm9uZToKICAgICAgICBwZW5kaW5nX3RibCA9IHBlbmRpbmcKICAgIGxzdCA9IHBlbmRpbmdfdGJs
LmdldChyaykKICAgIGlmIG5vdCBsc3Q6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGV2LCBfID0g
bHN0LnBvcCgwKQogICAgaWYgbm90IGxzdDoKICAgICAgICBwZW5kaW5nX3RibC5wb3AocmssIE5v
bmUpCiAgICBvdXQuYXBwZW5kKGV2KQogICAgcmV0dXJuIGV2CgoKZGVmIHBhcnNlX3Jlc3BvbnNl
X2hlYWQocGF5bG9hZCk6CiAgICAiIiJGaXJzdCBsaW5lICdIVFRQLzEueCBOTk4gLi4uJyAtPiAo
c3RhdHVzX2ludHxOb25lLCBjb250ZW50X2xlbnxOb25lKS4KICAgIE9ubHkgbG9va3MgYXQgd2hh
dCdzIGluIHRoaXMgc2VnbWVudDsgaGVhZGVycyBmaXQgb25lIHNlZ21lbnQgZm9yIGFsbAogICAg
cmVhbGlzdGljIEFQSSByZXNwb25zZXMuIiIiCiAgICB0cnk6CiAgICAgICAgaGVhZCA9IHBheWxv
YWQuc3BsaXQoYiJcclxuXHJcbiIsIDEpWzBdCiAgICAgICAgbGluZXMgPSBoZWFkLnJlcGxhY2Uo
YiJcclxuIiwgYiJcbiIpLnNwbGl0KGIiXG4iKQogICAgICAgIGZpcnN0ID0gbGluZXNbMF0uc3Bs
aXQoKQogICAgICAgIGlmIGxlbihmaXJzdCkgPCAyIG9yIG5vdCBmaXJzdFswXS5zdGFydHN3aXRo
KGIiSFRUUC8iKToKICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAgICBzdCA9IGlu
dChmaXJzdFsxXSkKICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgSW5kZXhFcnJvcik6CiAgICAgICAg
cmV0dXJuIE5vbmUsIE5vbmUKICAgIGNsZW4gPSBOb25lCiAgICBmb3IgbG4gaW4gbGluZXNbMTpd
OgogICAgICAgIGxvdyA9IGxuLmxvd2VyKCkKICAgICAgICBpZiBsb3cuc3RhcnRzd2l0aChiImNv
bnRlbnQtbGVuZ3RoOiIpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjbGVuID0g
aW50KGxuLnNwbGl0KGIiOiIsIDEpWzFdLnN0cmlwKCkpCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1
ZUVycm9yOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICBicmVhawogICAgcmV0dXJu
IHN0LCBjbGVuCgoKZGVmIGNvcnJlbGF0ZV9yZXNwb25zZShwZW5kaW5nX3RibCwgcmssIHBheWxv
YWQsIG5vdywgb3V0KToKICAgICIiIkF0dGFjaCBvbmUgcmVzcG9uc2UgaGVhZCB0byB0aGUgb2xk
ZXN0IHJlcXVlc3Qgb24gYSBjb25uZWN0aW9uLgoKICAgIEhUVFAvMS4xIHBpcGVsaW5pbmcgY2Fu
IGxlYXZlIHNldmVyYWwgcmVxdWVzdHMgcXVldWVkIGZvciB0aGUgc2FtZQogICAgZm91ci10dXBs
ZS4gIENvbnN1bWUgZXhhY3RseSBvbmUgZW50cnk7IGRlbGV0aW5nIHRoZSB3aG9sZSBrZXkgaGVy
ZSBsb3NlcwogICAgZXZlcnkgcmVxdWVzdCBhZnRlciB0aGUgZmlyc3QgcmVzcG9uc2UuCiAgICAi
IiIKICAgIHN0LCBjbGVuID0gcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2FkKQogICAgaWYgc3Qg
aXMgTm9uZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChy
aykKICAgIGlmIG5vdCBlbnQ6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBldiwgc3RhcnRlZCA9
IGVudC5wb3AoMCkKICAgIGlmIG5vdCBlbnQ6CiAgICAgICAgcGVuZGluZ190YmwucG9wKHJrLCBO
b25lKQogICAgZXZbInN0YXR1cyJdID0gc3QKICAgIGV2WyJkdXJhdGlvbl9tcyJdID0gbWF4KDAs
IGludCgobm93IC0gc3RhcnRlZCkgKiAxMDAwKSkKICAgIGlmIGNsZW4gaXMgbm90IE5vbmU6CiAg
ICAgICAgZXZbInJlc3BfYnl0ZXMiXSA9IGNsZW4KICAgIG91dC5hcHBlbmQoZXYpCiAgICByZXR1
cm4gVHJ1ZQoKCmRlZiB2YWxpZF9wb3J0KHApOgogICAgdHJ5OgogICAgICAgIHJldHVybiAxIDw9
IGludChwKSA8PSA2NTUzNQogICAgZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVlRXJyb3IpOgogICAg
ICAgIHJldHVybiBGYWxzZQoKCmRlZiBiYXNpY191c2VyKHZhbHVlKToKICAgICIiIkF1dGhvcml6
YXRpb24gaGVhZGVyIHZhbHVlIC0+ICh1c2VyfE5vbmUsIHNjaGVtZXxOb25lKS4gQmFzaWMgb25s
eS4iIiIKICAgIHBhcnRzID0gdmFsdWUuc3RyaXAoKS5zcGxpdChOb25lLCAxKQogICAgaWYgbGVu
KHBhcnRzKSAhPSAyOgogICAgICAgIHJldHVybiBOb25lLCBOb25lCiAgICBzY2hlbWUgPSBwYXJ0
c1swXS5sb3dlcigpCiAgICBpZiBzY2hlbWUgPT0gImJhc2ljIjoKICAgICAgICB0cnk6CiAgICAg
ICAgICAgIHBhZCA9IHBhcnRzWzFdLnN0cmlwKCkKICAgICAgICAgICAgaWYgbGVuKHBhZCkgPiAx
MDI0OgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAgICAgICAgcGFkICs9
ICI9IiAqICgtbGVuKHBhZCkgJSA0KQogICAgICAgICAgICByYXcgPSBiYXNlNjQuYjY0ZGVjb2Rl
KHBhZCkKICAgICAgICAgICAgaWYgbGVuKHJhdykgPiA1MTI6CiAgICAgICAgICAgICAgICByZXR1
cm4gTm9uZSwgTm9uZQogICAgICAgICAgICBpZiBiIjoiIGluIHJhdzoKICAgICAgICAgICAgICAg
IHVzZXIgPSByYXcuc3BsaXQoYiI6IiwgMSlbMF0KICAgICAgICAgICAgICAgIHVzZXIgPSB1c2Vy
LmRlY29kZSgidXRmLTgiLCAicmVwbGFjZSIpWzo2NF0KICAgICAgICAgICAgICAgIGlmIHVzZXI6
CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHVzZXIsICJiYXNpYyIKICAgICAgICBleGNlcHQg
RXhjZXB0aW9uOgogICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgZWxpZiBzY2hlbWUg
PT0gImJlYXJlciI6CiAgICAgICAgcmV0dXJuIE5vbmUsICJiZWFyZXIiCiAgICByZXR1cm4gTm9u
ZSwgTm9uZQoKCmRlZiBub3JtYWxpemVfd3NzZV91c2VybmFtZSh2YWx1ZSk6CiAgICAiIiJSZXR1
cm4gYSBzbWFsbCwgcHJpbnRhYmxlIHVzZXJuYW1lIG9yIE5vbmU7IG5ldmVyIHJldHVybiB0b2tl
biBkYXRhLiIiIgogICAgaWYgdmFsdWUgaXMgTm9uZToKICAgICAgICByZXR1cm4gTm9uZQogICAg
dHJ5OgogICAgICAgIHVzZXJuYW1lID0gdmFsdWUuc3RyaXAoKQogICAgZXhjZXB0IEV4Y2VwdGlv
bjoKICAgICAgICByZXR1cm4gTm9uZQogICAgaWYgbm90IHVzZXJuYW1lIG9yIGxlbih1c2VybmFt
ZSkgPiBNQVhfV1NTRV9VU0VSTkFNRToKICAgICAgICByZXR1cm4gTm9uZQogICAgZm9yIGNoYXIg
aW4gdXNlcm5hbWU6CiAgICAgICAgaWYgdW5pY29kZWRhdGEuY2F0ZWdvcnkoY2hhcikuc3RhcnRz
d2l0aCgiQyIpOgogICAgICAgICAgICByZXR1cm4gTm9uZQogICAgcmV0dXJuIHVzZXJuYW1lCgoK
ZGVmIGV4dHJhY3Rfd3NzZV91c2VybmFtZShib2R5KToKICAgICIiIlBhcnNlIGEgYm91bmRlZCwg
cG9zc2libHkgcGFydGlhbCBTT0FQIHByZWZpeCBhbmQgcmV0dXJuIG9ubHkgVXNlcm5hbWUuCgog
ICAgRXhwYXQgaXMgcnVuIGluY3JlbWVudGFsbHkgc28gYSBVc2VybmFtZVRva2VuIGluIHRoZSBT
T0FQIEhlYWRlciBjYW4gYmUKICAgIHJlY29nbml6ZWQgd2l0aG91dCByZXRhaW5pbmcgb3IgcmVx
dWlyaW5nIHRoZSBjb21wbGV0ZSByZXF1ZXN0IGJvZHkuCiAgICBEVEQvZW50aXR5IGRlY2xhcmF0
aW9ucyBhcmUgcmVqZWN0ZWQgYmVmb3JlIHBhcnNpbmcuCiAgICAiIiIKICAgIGlmIG5vdCBib2R5
IG9yIGxlbihib2R5KSA+IE1BWF9XU1NFX0JPRFlfQllURVMgb3IgYiJceDAwIiBpbiBib2R5Ogog
ICAgICAgIHJldHVybiBOb25lCiAgICBsb3dlcmVkID0gYnl0ZXMoYm9keSkubG93ZXIoKQogICAg
aWYgYiI8IWRvY3R5cGUiIGluIGxvd2VyZWQgb3IgYiI8IWVudGl0eSIgaW4gbG93ZXJlZDoKICAg
ICAgICByZXR1cm4gTm9uZQoKICAgIHN0YXRlID0geyJzdGFjayI6IFtdLCAidG9rZW5fZGVwdGgi
OiAwLCAidXNlcm5hbWVfZGVwdGgiOiAwLAogICAgICAgICAgICAgImNoYXJzIjogW10sICJ0b29f
bG9uZyI6IEZhbHNlLCAicmVzdWx0IjogTm9uZX0KCiAgICBkZWYgc3BsaXRfbmFtZShuYW1lKToK
ICAgICAgICBpZiAifSIgbm90IGluIG5hbWU6CiAgICAgICAgICAgIHJldHVybiAiIiwgbmFtZQog
ICAgICAgIHJldHVybiBuYW1lLnJzcGxpdCgifSIsIDEpCgogICAgZGVmIHN0YXJ0KG5hbWUsIGF0
dHJzKToKICAgICAgICBuYW1lc3BhY2UsIGxvY2FsX25hbWUgPSBzcGxpdF9uYW1lKG5hbWUpCiAg
ICAgICAgc3RhdGVbInN0YWNrIl0uYXBwZW5kKChuYW1lc3BhY2UsIGxvY2FsX25hbWUpKQogICAg
ICAgIGRlcHRoID0gbGVuKHN0YXRlWyJzdGFjayJdKQogICAgICAgIGlmIChub3Qgc3RhdGVbInRv
a2VuX2RlcHRoIl0gYW5kIGxvY2FsX25hbWUgPT0gIlVzZXJuYW1lVG9rZW4iIGFuZAogICAgICAg
ICAgICAgICAgbmFtZXNwYWNlIGluIFdTU0VfTkFNRVNQQUNFUyk6CiAgICAgICAgICAgIHN0YXRl
WyJ0b2tlbl9kZXB0aCJdID0gZGVwdGgKICAgICAgICBlbGlmIChzdGF0ZVsidG9rZW5fZGVwdGgi
XSBhbmQKICAgICAgICAgICAgICBkZXB0aCA9PSBzdGF0ZVsidG9rZW5fZGVwdGgiXSArIDEgYW5k
CiAgICAgICAgICAgICAgbG9jYWxfbmFtZSA9PSAiVXNlcm5hbWUiIGFuZAogICAgICAgICAgICAg
IG5hbWVzcGFjZSA9PSBzdGF0ZVsic3RhY2siXVtzdGF0ZVsidG9rZW5fZGVwdGgiXSAtIDFdWzBd
KToKICAgICAgICAgICAgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gPSBkZXB0aAogICAgICAgICAg
ICBzdGF0ZVsiY2hhcnMiXSA9IFtdCiAgICAgICAgICAgIHN0YXRlWyJ0b29fbG9uZyJdID0gRmFs
c2UKCiAgICBkZWYgY2hhcnModmFsdWUpOgogICAgICAgIGlmIG5vdCBzdGF0ZVsidXNlcm5hbWVf
ZGVwdGgiXSBvciBzdGF0ZVsidG9vX2xvbmciXToKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAg
c3RhdGVbImNoYXJzIl0uYXBwZW5kKHZhbHVlKQogICAgICAgIGlmIHN1bShbbGVuKHBhcnQpIGZv
ciBwYXJ0IGluIHN0YXRlWyJjaGFycyJdXSkgPiBNQVhfV1NTRV9VU0VSTkFNRSArIDI6CiAgICAg
ICAgICAgIHN0YXRlWyJjaGFycyJdID0gW10KICAgICAgICAgICAgc3RhdGVbInRvb19sb25nIl0g
PSBUcnVlCgogICAgZGVmIGVuZChuYW1lKToKICAgICAgICBkZXB0aCA9IGxlbihzdGF0ZVsic3Rh
Y2siXSkKICAgICAgICBpZiBzdGF0ZVsidXNlcm5hbWVfZGVwdGgiXSA9PSBkZXB0aDoKICAgICAg
ICAgICAgaWYgbm90IHN0YXRlWyJ0b29fbG9uZyJdIGFuZCBzdGF0ZVsicmVzdWx0Il0gaXMgTm9u
ZToKICAgICAgICAgICAgICAgIHN0YXRlWyJyZXN1bHQiXSA9IG5vcm1hbGl6ZV93c3NlX3VzZXJu
YW1lKAogICAgICAgICAgICAgICAgICAgIHUiIi5qb2luKHN0YXRlWyJjaGFycyJdKSkKICAgICAg
ICAgICAgc3RhdGVbInVzZXJuYW1lX2RlcHRoIl0gPSAwCiAgICAgICAgICAgIHN0YXRlWyJjaGFy
cyJdID0gW10KICAgICAgICBpZiBzdGF0ZVsidG9rZW5fZGVwdGgiXSA9PSBkZXB0aDoKICAgICAg
ICAgICAgc3RhdGVbInRva2VuX2RlcHRoIl0gPSAwCiAgICAgICAgaWYgc3RhdGVbInN0YWNrIl06
CiAgICAgICAgICAgIHN0YXRlWyJzdGFjayJdLnBvcCgpCgogICAgdHJ5OgogICAgICAgIHBhcnNl
ciA9IGV4cGF0LlBhcnNlckNyZWF0ZShOb25lLCAifSIpCiAgICAgICAgaWYgaGFzYXR0cihwYXJz
ZXIsICJyZXR1cm5zX3VuaWNvZGUiKToKICAgICAgICAgICAgcGFyc2VyLnJldHVybnNfdW5pY29k
ZSA9IFRydWUKICAgICAgICBwYXJzZXIuU3RhcnRFbGVtZW50SGFuZGxlciA9IHN0YXJ0CiAgICAg
ICAgcGFyc2VyLkNoYXJhY3RlckRhdGFIYW5kbGVyID0gY2hhcnMKICAgICAgICBwYXJzZXIuRW5k
RWxlbWVudEhhbmRsZXIgPSBlbmQKICAgICAgICBpZiAoaGFzYXR0cihwYXJzZXIsICJTZXRQYXJh
bUVudGl0eVBhcnNpbmciKSBhbmQKICAgICAgICAgICAgICAgIGhhc2F0dHIoZXhwYXQsICJYTUxf
UEFSQU1fRU5USVRZX1BBUlNJTkdfTkVWRVIiKSk6CiAgICAgICAgICAgIHBhcnNlci5TZXRQYXJh
bUVudGl0eVBhcnNpbmcoZXhwYXQuWE1MX1BBUkFNX0VOVElUWV9QQVJTSU5HX05FVkVSKQogICAg
ICAgIHBhcnNlci5QYXJzZShieXRlcyhib2R5KSwgRmFsc2UpCiAgICBleGNlcHQgKGV4cGF0LkV4
cGF0RXJyb3IsIFZhbHVlRXJyb3IsIFR5cGVFcnJvcik6CiAgICAgICAgIyBBIGJvdW5kZWQgcHJl
Zml4IGlzIGNvbW1vbmx5IGluY29tcGxldGUuIEEgdXNlcm5hbWUgZnVsbHkgY2xvc2VkCiAgICAg
ICAgIyBiZWZvcmUgdGhlIHRydW5jYXRpb24gcG9pbnQgaXMgc3RpbGwgc2FmZSB0byB1c2UuCiAg
ICAgICAgcGFzcwogICAgcmV0dXJuIHN0YXRlWyJyZXN1bHQiXQoKCmRlZiBpc19zb2FwX2NvbnRl
bnRfdHlwZSh2YWx1ZSk6CiAgICBpZiBub3QgdmFsdWU6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAg
ICBtZWRpYV90eXBlID0gdmFsdWUuc3BsaXQoIjsiLCAxKVswXS5zdHJpcCgpLmxvd2VyKCkKICAg
IHJldHVybiAobWVkaWFfdHlwZSBpbiAoInRleHQveG1sIiwgImFwcGxpY2F0aW9uL3htbCIsCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICJhcHBsaWNhdGlvbi9zb2FwK3htbCIpIG9yCiAgICAg
ICAgICAgIG1lZGlhX3R5cGUuZW5kc3dpdGgoIit4bWwiKSkKCgpkZWYgZmluaXNoX2V2ZW50KGZs
b3csIGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCwgcG9ydHMsIG5vZGVfaG9zdCk6
CiAgICBoID0gZmxvdy5oZHJzCiAgICB1c2VyID0gc2NoZW1lID0gTm9uZQogICAgYXV0aHogPSBo
LmdldCgiYXV0aG9yaXphdGlvbiIpCiAgICBpZiBhdXRoejoKICAgICAgICB1c2VyLCBzY2hlbWUg
PSBiYXNpY191c2VyKGF1dGh6KQogICAgIyBXM0MgdHJhY2UgY29udGV4dDogaG9ub3IgaW5jb21p
bmcgdHJhY2VwYXJlbnQsIGVsc2UgZ2VuZXJhdGUgb25lIHNvCiAgICAjIGV2ZXJ5IHRyYW5zYWN0
aW9uIGNhcnJpZXMgYSB0cmFjZV9pZCBmb3IgaHViLXNpZGUgY29ycmVsYXRpb24uCiAgICAjIE5P
VEUgcHkyLjY6IGJ5dGVzIGhhcyBubyAuaGV4KCkg4oCUIHVzZSBiaW5hc2NpaS5oZXhsaWZ5Lgog
ICAgdHAgPSBoLmdldCgidHJhY2VwYXJlbnQiKQogICAgdHJhY2VfaWQgPSBOb25lCiAgICBpZiB0
cDoKICAgICAgICBwYXJ0cyA9IHRwLnNwbGl0KCItIikKICAgICAgICBpZiBsZW4ocGFydHMpID09
IDQgYW5kIGxlbihwYXJ0c1sxXSkgPT0gMzI6CiAgICAgICAgICAgIHRyYWNlX2lkID0gcGFydHNb
MV0ubG93ZXIoKQogICAgaWYgbm90IHRyYWNlX2lkOgogICAgICAgIHRyeToKICAgICAgICAgICAg
cm5kID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDE2KSkKICAgICAgICAgICAgcm5kID0g
cm5kLmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHJuZCwgImRlY29kZSIpIGVsc2Ugcm5kCiAg
ICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcm5kID0gKCIlMDMyeCIgJSAoaW50
KHRpbWUudGltZSgpICogMTAwMCkpKVstMzI6XQogICAgICAgIHBpZDggPSBiaW5hc2NpaS5oZXhs
aWZ5KG9zLnVyYW5kb20oOCkpCiAgICAgICAgcGlkOCA9IHBpZDguZGVjb2RlKCJhc2NpaSIpIGlm
IGhhc2F0dHIocGlkOCwgImRlY29kZSIpIGVsc2UgcGlkOAogICAgICAgIHRwID0gIjAwLSVzLSVz
LTAxIiAlIChybmQsIHBpZDgpCiAgICAgICAgdHJhY2VfaWQgPSBybmQKICAgIGV2ID0gewogICAg
ICAgICJ0cyI6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAgImhvc3QiOiBub2RlX2hvc3QsCiAg
ICAgICAgInNyYyI6ICJwY2FwIiwKICAgICAgICAic2VydmljZSI6ICJwb3J0OiVkIiAlIGRwb3J0
LAogICAgICAgICJtZXRob2QiOiBoLmdldCgiX21ldGhvZCIpIG9yICItIiwKICAgICAgICAicGF0
aCI6IChoLmdldCgiX3BhdGgiKSBvciAiLSIpLnNwbGl0KCI/IiwgMSlbMF1bOjEyMF0sCiAgICAg
ICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBzY2hlbWUsCiAgICAgICAgImJhc2lj
X3VzZXIiOiB1c2VyIGlmIHNjaGVtZSA9PSAiYmFzaWMiIGFuZCB1c2VyIGVsc2UgTm9uZSwKICAg
ICAgICAid3NzZV91c2VyIjogTm9uZSwKICAgICAgICAicGlkIjogTm9uZSwKICAgICAgICAic291
cmNlX3Byb2JlIjogInBjYXAtaHR0cCIsCiAgICAgICAgImhvc3RfaGRyIjogaC5nZXQoImhvc3Qi
KSwKICAgICAgICAidXNlcl9hZ2VudCI6IGguZ2V0KCJ1c2VyLWFnZW50IiksCiAgICAgICAgInhf
Zm9yd2FyZGVkX2ZvciI6IGguZ2V0KCJ4LWZvcndhcmRlZC1mb3IiKSwKICAgICAgICAiY2FsbGVy
Ijogc3JjX2lwLAogICAgICAgICJjYWxsZXJfcG9ydCI6IHNwb3J0LAogICAgICAgICJkc3RfaXAi
OiBkc3RfaXAsCiAgICAgICAgImRzdF9wb3J0IjogZHBvcnQsCiAgICAgICAgIyAtLS0tIG1vbml0
b3Jpbmcgc2NoZW1hIChvcHMgQVBJLWxvZyBmb3JtYXQpIC0tLS0KICAgICAgICAjIHN0YXR1cy9k
dXJhdGlvbl9tcy9yZXNwX2J5dGVzIGFyZSByZXNwb25zZS1zaWRlOiBwYXNzaXZlIHJlcXVlc3Qt
b25seQogICAgICAgICMgY2FwdHVyZSBjYW5ub3Qgc2VlIHRoZW07IGxlZnQgbnVsbCBmb3IgdGhl
IGh1YiB0byBlbnJpY2ggb3IgbGVhdmUuCiAgICAgICAgInRyYWNlcGFyZW50IjogdHBbOjgwXSwK
ICAgICAgICAidHJhY2VfaWQiOiB0cmFjZV9pZCwKICAgICAgICAic2VydmljZV9pZCI6IE5vbmUs
ICAgICAgICAgICMgaHViIG1hcHMgcG9ydC0+c2VydmljZSB2aWEgcG9saWN5IGxhdGVyCiAgICAg
ICAgIm1vZHVsZV9pZCI6ICJwY2FwLWh0dHAiLAogICAgfQogICAgIyBQcmVzZXJ2ZSByZXNwb25z
ZSBjb3JyZWxhdGlvbiBvbmx5IGZvciBtb25pdG9yZWQgZGVzdGluYXRpb25zLiBUaGUKICAgICMg
cmVzcG9uc2Utc2lkZSBmaWx0ZXIgbWF5IHN0aWxsIGFkbWl0IGEgY2xpZW50IGVwaGVtZXJhbCBz
cG9ydCBlcXVhbCB0byBhCiAgICAjIG1vbml0b3JlZCBwb3J0OyB0aGlzIGlzIGhhcm1sZXNzIGJl
Y2F1c2UgcGFyc2VfcmVzcG9uc2VfaGVhZCByZWplY3RzIGl0LgogICAgcmV0dXJuIGV2IGlmIChk
cG9ydCBpbiBwb3J0cyBvciBoLmdldCgiX21ldGhvZCIpKSBlbHNlIE5vbmUKCgpkZWYgX2VtaXRf
cmVxdWVzdChmbG93cywga2V5LCBmbCwgbWV0YSwgb3V0LCBwZW5kaW5nX3RibCwgbm93KToKICAg
ICIiIkRpc2NhcmQgY2FwdHVyZSBidWZmZXJzLCB0aGVuIGVtaXQvcXVldWUgdGhlIHNhbml0aXpl
ZCBldmVudCBvbmx5LiIiIgogICAgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCA9IG1ldGEK
ICAgIGV2ID0gZmwuZXZlbnQKICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICBpZiBub3QgZXY6
CiAgICAgICAgcmV0dXJuCiAgICBldlsicmVxX2J5dGVzIl0gPSBmbC5oZWFkX2J5dGVzCiAgICBp
ZiBwZW5kaW5nX3RibCBpcyBOb25lOgogICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgcmV0
dXJuCiAgICByayA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgZW50ID0gcGVu
ZGluZ190YmwuZ2V0KHJrKQogICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgaWYgbGVuKHBlbmRp
bmdfdGJsKSA+PSBQRU5ESU5HX01BWDoKICAgICAgICAgICAgX2ZsdXNoX29sZGVzdF9wZW5kaW5n
KHBlbmRpbmdfdGJsLCBvdXQpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmxbcmtdID0gW10KICAg
IGVsaWYgbGVuKGVudCkgPj0gUEVORElOR19QRVJfRkxPVzoKICAgICAgICBwZW5kaW5nX3BvcChy
aywgb3V0LCBwZW5kaW5nX3RibCkKICAgICAgICBlbnQgPSBwZW5kaW5nX3RibC5nZXQocmspCiAg
ICAgICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgICAgIGVudCA9IHBlbmRpbmdfdGJsW3JrXSA9
IFtdCiAgICBlbnQuYXBwZW5kKFtldiwgbm93IGlmIG5vdyBpcyBub3QgTm9uZSBlbHNlIHRpbWUu
dGltZSgpXSkKCgpkZWYgX3RyeV93c3NlX2JvZHkoZmxvd3MsIGtleSwgZmwsIHBheWxvYWQsIG1l
dGEsIG91dCwgcGVuZGluZ190YmwsIG5vdyk6CiAgICAiIiJBcHBlbmQgbm8gbW9yZSB0aGFuIGJv
ZHlfZ29hbCBieXRlcyBhbmQgZmluaXNoIGFzIHNvb24gYXMgcG9zc2libGUuIiIiCiAgICByZW1h
aW5pbmcgPSBmbC5ib2R5X2dvYWwgLSBsZW4oZmwuYnVmKQogICAgaWYgcmVtYWluaW5nID4gMCBh
bmQgcGF5bG9hZDoKICAgICAgICBmbC5idWYuZXh0ZW5kKGJ5dGVhcnJheShwYXlsb2FkWzpyZW1h
aW5pbmddKSkKICAgIHVzZXJuYW1lID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGZsLmJ1ZikKICAg
IGlmIHVzZXJuYW1lOgogICAgICAgIGZsLmV2ZW50WyJ3c3NlX3VzZXIiXSA9IHVzZXJuYW1lCiAg
ICAgICAgZmwuZXZlbnRbInVzZXIiXSA9IHVzZXJuYW1lCiAgICAgICAgZmwuZXZlbnRbInNjaGVt
ZSJdID0gIndzc2UiCiAgICBpZiB1c2VybmFtZSBvciBsZW4oZmwuYnVmKSA+PSBmbC5ib2R5X2dv
YWw6CiAgICAgICAgX2VtaXRfcmVxdWVzdChmbG93cywga2V5LCBmbCwgbWV0YSwgb3V0LCBwZW5k
aW5nX3RibCwgbm93KQogICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYg
aGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2X2tleSwgcGF5bG9hZCwgbWV0YSwgcG9ydHMs
IG5vZGVfaG9zdCwgb3V0LAogICAgICAgICAgICAgICAgICAgcGVuZGluZ190Ymw9Tm9uZSwgbm93
PU5vbmUsIHdzc2VfYm9keV9ieXRlcz0wKToKICAgICIiIkZlZWQgb25lIGRpcmVjdGlvbidzIHBh
eWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0KS4KCiAgICBCb2RpZXMgYXJl
IGlnbm9yZWQgdW5sZXNzIHdzc2VfYm9keV9ieXRlcyBpcyBub24temVyby4gSW4gb3B0LWluIG1v
ZGUsCiAgICBvbmx5IFhNTCByZXF1ZXN0cyB3aXRoIENvbnRlbnQtTGVuZ3RoIGFyZSBpbnNwZWN0
ZWQsIGVhY2ggYnVmZmVyIGlzCiAgICBib3VuZGVkIGJ5IHdzc2VfYm9keV9ieXRlcywgYW5kIG9u
bHkgYSByZWNvZ25pemVkIFdTU0UgdXNlcm5hbWUgcmVhY2hlcwogICAgdGhlIGV2ZW50LiBUaGUg
Ym9keSBhbmQgYWxsIG90aGVyIFVzZXJuYW1lVG9rZW4gbWF0ZXJpYWwgYXJlIGRpc2NhcmRlZC4K
ICAgICIiIgogICAgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCA9IG1ldGEKICAgIGlmIG5v
dCB2YWxpZF9wb3J0KGRwb3J0KSBvciBub3QgdmFsaWRfcG9ydChzcG9ydCk6CiAgICAgICAgcmV0
dXJuCiAgICBmbCA9IGZsb3dzLmdldChrZXkpCiAgICBpZiBmbCBpcyBOb25lOgogICAgICAgIGZs
ID0gRmxvdygpCiAgICAgICAgZmxvd3Nba2V5XSA9IGZsCiAgICAgICAgaWYgbGVuKGZsb3dzKSA+
IE1BWF9GTE9XUzoKICAgICAgICAgICAgZW5mb3JjZV9saW1pdChmbG93cywgdGltZS50aW1lKCkp
CiAgICBmbC50b3VjaGVkID0gdGltZS50aW1lKCkKCiAgICBpZiAoZmwuZXZlbnQgaXMgbm90IE5v
bmUgYW5kIGZsLmV2ZW50LmdldCgiYmFzaWNfdXNlciIpIGFuZAogICAgICAgICAgICBhbnkocGF5
bG9hZC5zdGFydHN3aXRoKG1ldGhvZC5lbmNvZGUoImFzY2lpIikgKyBiIiAiKQogICAgICAgICAg
ICAgICAgZm9yIG1ldGhvZCBpbiBNRVRIT0RTKSk6CiAgICAgICAgIyBBIG5ldyBrZWVwLWFsaXZl
IHJlcXVlc3Qgc3RhcnRlZCBiZWZvcmUgdGhlIGJvdW5kZWQgV1NTRSB3aW5kb3cKICAgICAgICAj
IGNvbXBsZXRlZC4gUHJlc2VydmUgdGhlIEJhc2ljIGV2ZW50LCB0aGVuIHBhcnNlIHRoZSBuZXcg
cmVxdWVzdC4KICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQs
IHBlbmRpbmdfdGJsLCBub3cpCiAgICAgICAgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2
X2tleSwgcGF5bG9hZCwgbWV0YSwgcG9ydHMsIG5vZGVfaG9zdCwKICAgICAgICAgICAgICAgICAg
ICAgICBvdXQsIHBlbmRpbmdfdGJsLCBub3csIHdzc2VfYm9keV9ieXRlcykKICAgICAgICByZXR1
cm4KICAgIGlmIGZsLmV2ZW50IGlzIG5vdCBOb25lOgogICAgICAgIF90cnlfd3NzZV9ib2R5KGZs
b3dzLCBrZXksIGZsLCBwYXlsb2FkLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAg
ICAgcmV0dXJuCgogICAgZmwuYnVmLmV4dGVuZChieXRlYXJyYXkocGF5bG9hZCkpCiAgICBpZHgg
PSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgIGlmIGlkeCA8IDA6CiAgICAgICAgaWYgbGVu
KGZsLmJ1ZikgPiBNQVhfSERSUzoKICAgICAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkKICAg
ICAgICByZXR1cm4KICAgIGhlYWQgPSBieXRlcyhmbC5idWZbOmlkeF0pCiAgICBsaW5lcyA9IGhl
YWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQoYiJcbiIpCiAgICBoZHJzID0ge30KICAg
IGZpcnN0ID0gbGluZXNbMF0uc3RyaXAoKS5zcGxpdCgpCiAgICBpZiBsZW4oZmlyc3QpID49IDIg
YW5kIGZpcnN0WzBdIGluIFttLmVuY29kZSgpIGZvciBtIGluIE1FVEhPRFNdOgogICAgICAgIGhk
cnNbIl9tZXRob2QiXSA9IGZpcnN0WzBdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAgICAg
ICAgaGRyc1siX3BhdGgiXSA9IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpCiAg
ICBlbHNlOgogICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBm
b3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgIGlmIGIiOiIgbm90IGluIGxuOgogICAgICAgICAg
ICBjb250aW51ZQogICAgICAgIGtuLCBrdiA9IGxuLnNwbGl0KGIiOiIsIDEpCiAgICAgICAgaGRy
c1trbi5zdHJpcCgpLmxvd2VyKCkuZGVjb2RlKAogICAgICAgICAgICAiYXNjaWkiLCAicmVwbGFj
ZSIpXSA9IGt2LnN0cmlwKCkuZGVjb2RlKAogICAgICAgICAgICAgICAgInV0Zi04IiwgInJlcGxh
Y2UiKVs6MTgwXQogICAgZmwuaGRycyA9IGhkcnMKICAgIGZsLmV2ZW50ID0gZmluaXNoX2V2ZW50
KGZsLCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgICBwb3J0cywgbm9kZV9ob3N0KQogICAgaWYgbm90IGZsLmV2ZW50OgogICAgICAg
IGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBmbC5oZWFkX2J5dGVzID0g
aWR4ICsgNAogICAgaW5pdGlhbF9ib2R5ID0gYnl0ZXMoZmwuYnVmW2lkeCArIDQ6XSkKICAgIGZs
LmJ1ZiA9IGJ5dGVhcnJheSgpCgogICAgaWYgKG5vdCB3c3NlX2JvZHlfYnl0ZXMgb3IKICAgICAg
ICAgICAgbm90IGlzX3NvYXBfY29udGVudF90eXBlKGhkcnMuZ2V0KCJjb250ZW50LXR5cGUiKSkp
OgogICAgICAgIF9lbWl0X3JlcXVlc3QoZmxvd3MsIGtleSwgZmwsIG1ldGEsIG91dCwgcGVuZGlu
Z190YmwsIG5vdykKICAgICAgICByZXR1cm4KICAgIHRyeToKICAgICAgICBjb250ZW50X2xlbmd0
aCA9IGludChoZHJzLmdldCgiY29udGVudC1sZW5ndGgiLCAiIikpCiAgICBleGNlcHQgKFR5cGVF
cnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgY29udGVudF9sZW5ndGggPSAwCiAgICBhY3RpdmVf
Ym9keV9mbG93cyA9IHN1bShbMSBmb3IgY2FuZGlkYXRlIGluIGZsb3dzLnZhbHVlcygpCiAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgaWYgY2FuZGlkYXRlLmV2ZW50IGlzIG5vdCBOb25lIGFu
ZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhbmRpZGF0ZS5ib2R5X2dvYWwgPiAwXSkK
ICAgIGlmIChjb250ZW50X2xlbmd0aCA8PSAwIG9yIGFjdGl2ZV9ib2R5X2Zsb3dzID49IE1BWF9X
U1NFX0JPRFlfRkxPV1Mgb3IKICAgICAgICAgICAgImNodW5rZWQiIGluIGhkcnMuZ2V0KCJ0cmFu
c2Zlci1lbmNvZGluZyIsICIiKS5sb3dlcigpKToKICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dz
LCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAgICAgcmV0dXJuCiAg
ICBmbC5ib2R5X2dvYWwgPSBtaW4oY29udGVudF9sZW5ndGgsIHdzc2VfYm9keV9ieXRlcywgTUFY
X1dTU0VfQk9EWV9CWVRFUykKICAgIF90cnlfd3NzZV9ib2R5KGZsb3dzLCBrZXksIGZsLCBpbml0
aWFsX2JvZHksIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdykKCgpkZWYgc3dlZXBfaWRsZShm
bG93cywgbm93LCBvdXQ9Tm9uZSwgcGVuZGluZ190Ymw9Tm9uZSk6CiAgICBzdGFsZSA9IFtdCiAg
ICBmb3IgaywgZmwgaW4gZmxvd3MuaXRlbXMoKToKICAgICAgICBpZiBub3cgLSBmbC50b3VjaGVk
ID4gRkxPV19UVEw6CiAgICAgICAgICAgIHN0YWxlLmFwcGVuZChrKQogICAgZm9yIGsgaW4gc3Rh
bGU6CiAgICAgICAgZmwgPSBmbG93cy5nZXQoaykKICAgICAgICBpZiAob3V0IGlzIG5vdCBOb25l
IGFuZCBmbCBpcyBub3QgTm9uZSBhbmQgZmwuZXZlbnQgaXMgbm90IE5vbmUgYW5kCiAgICAgICAg
ICAgICAgICBmbC5ldmVudC5nZXQoImJhc2ljX3VzZXIiKSk6CiAgICAgICAgICAgIHNyY19pcCwg
c3BvcnQsIGRzdF9pcCwgZHBvcnQgPSBrCiAgICAgICAgICAgIF9lbWl0X3JlcXVlc3QoZmxvd3Ms
IGssIGZsLCAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAgICAg
ICAgICAgICAgb3V0LCBwZW5kaW5nX3RibCwgbm93KQogICAgICAgIGVsc2U6CiAgICAgICAgICAg
IGZsb3dzLnBvcChrLCBOb25lKQoKCmRlZiBkcmFpbl9pbmNvbXBsZXRlX3dzc2UoZmxvd3MsIG91
dCwgcGVuZGluZ190YmwsIG5vdz1Ob25lKToKICAgICIiIkZhbGwgYmFjayB0byB0aGUgcmV0YWlu
ZWQgcHJlLVdTU0UgaWRlbnRpdHkgZHVyaW5nIGNsZWFuIHNodXRkb3duLiIiIgogICAgZm9yIGtl
eSBpbiBsaXN0KGZsb3dzLmtleXMoKSk6CiAgICAgICAgZmwgPSBmbG93cy5nZXQoa2V5KQogICAg
ICAgIGlmIChmbCBpcyBOb25lIG9yIGZsLmV2ZW50IGlzIE5vbmUgb3IKICAgICAgICAgICAgICAg
IG5vdCBmbC5ldmVudC5nZXQoImJhc2ljX3VzZXIiKSk6CiAgICAgICAgICAgIGNvbnRpbnVlCiAg
ICAgICAgc3JjX2lwLCBzcG9ydCwgZHN0X2lwLCBkcG9ydCA9IGtleQogICAgICAgIF9lbWl0X3Jl
cXVlc3QoZmxvd3MsIGtleSwgZmwsIChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KSwKICAg
ICAgICAgICAgICAgICAgICAgIG91dCwgcGVuZGluZ190YmwsIG5vdykKCgpkZWYgX2ZsdXNoX29s
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
CiAgICBmbG93cyA9IHt9CiAgICBydW5uaW5nID0gW1RydWVdCgogICAgZGVmIHN0b3Aoc2lnbnVt
LCBmcmFtZSk6CiAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNp
Z25hbC5TSUdURVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9w
KQoKICAgIGxhc3Rfc3dlZXAgPSB0aW1lLnRpbWUoKQogICAgY29udHJvbF9uZXh0ID0gdGltZS50
aW1lKCkKICAgIGxvZygibGlzdGVuaW5nIG9uICVzIHBvcnRzPSVzIHBpZD0lZCIgJQogICAgICAg
IChpZmFjZSBvciAiPGFsbD4iLCBzb3J0ZWQocG9ydHMpLCBvcy5nZXRwaWQoKSkpCiAgICBpZiB3
c3NlX2JvZHlfYnl0ZXM6CiAgICAgICAgbG9nKCJXU1NFIFVzZXJuYW1lVG9rZW4gaW5zcGVjdGlv
biBlbmFibGVkIChib3VuZGVkIHRvICVkIGJ5dGVzL3JlcXVlc3QpIiAlCiAgICAgICAgICAgIHdz
c2VfYm9keV9ieXRlcykKCiAgICAjIDFzIHJlY3YgdGltZW91dDogKGEpIGxldHMgdGhlIHBlbmRp
bmcvZmxvdyBzd2VlcHMgYWN0dWFsbHkgZmlyZSDigJQKICAgICMgd2l0aG91dCBpdCBgZXhjZXB0
IHNvY2tldC50aW1lb3V0YCBuZXZlciBydW5zOyAoYikgZW1waXJpY2FsbHkgUkVRVUlSRUQKICAg
ICMgd2l0aCB0aGUgQlBGIGZpbHRlciBhdHRhY2hlZDogYSBmdWxseS1ibG9ja2luZyByZWN2IG9u
IHRoaXMga2VybmVsCiAgICAjIHN0YXJ2ZXMgYWZ0ZXIgdGhlIGZpcnN0IHBhY2tldCwgd2hpbGUg
dGhlIHRpbWVvdXQnZCByZWN2IGRlbGl2ZXJzCiAgICAjIGNvbnRpbnVvdXNseSAodmVyaWZpZWQg
YnkgQS9COiByeD0xIHZzIHJ4PTI5IGlkZW50aWNhbCBvdGhlcndpc2UpLgogICAgcy5zZXR0aW1l
b3V0KDEuMCkKCiAgICBkYmcgPSBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfREVCVUciKSA9PSAi
MSIKICAgIGRiZ19yeCA9IDAKICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgIHdoaWxlIHJ1
bm5pbmdbMF06CiAgICAgICAgIyBQb2xsIGluZGVwZW5kZW50bHkgb2Ygc29ja2V0IGlkbGUgdGlt
ZS4gQSBidXN5IG1vbml0b3JlZCBpbnRlcmZhY2UKICAgICAgICAjIG1heSBuZXZlciByYWlzZSBz
b2NrZXQudGltZW91dCwgYnV0IGNvbnRyb2wgY2hhbmdlcyBtdXN0IHN0aWxsIGFwcGx5LgogICAg
ICAgIGlmIGNvbnRyb2xfY2xpZW50IGlzIG5vdCBOb25lIGFuZCB0aW1lLnRpbWUoKSA+PSBjb250
cm9sX25leHQ6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwg
Y29udHJvbF9hY3Rpb24sIGNvbnRyb2xfc3RhdHVzID0gX3J1bl9jb250cm9sX3RpY2soCiAgICAg
ICAgICAgICAgICAgICAgcG9ydHMsIGlmYWNlLCBjb250cm9sX3J1biwgY29udHJvbF9jbGllbnQp
CiAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiAlcyIgJSBjb250cm9sX3N0YXR1
cykKICAgICAgICAgICAgICAgIGlmIGNvbnRyb2xfYWN0aW9uID09ICJyZXN0YXJ0IjoKICAgICAg
ICAgICAgICAgICAgICBhcmdzID0gX3Jlc3RhcnRfYXJncyhzeXMuYXJndlswXSwgaWZhY2UsIHBv
cnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcmJvc2UsIHdv
cmtlcnMsIHdzc2VfYm9keV9ieXRlcykKICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBj
b250cm9sOiByZS1leGVjdXRpbmcgY2FwdHVyZSB3aXRoIHVwZGF0ZWQgY29uZmlndXJhdGlvbiIp
CiAgICAgICAgICAgICAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgICAgICAgICAgICAgb3MuZXhl
Y3Yoc3lzLmV4ZWN1dGFibGUsIGFyZ3MpCiAgICAgICAgICAgICAgICBlbGlmIGNvbnRyb2xfYWN0
aW9uID09ICJzdG9wIjoKICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiBz
dG9wIHJlcXVlc3RlZDsgZXhpdGluZyIpCiAgICAgICAgICAgICAgICAgICAgcnVubmluZ1swXSA9
IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgZXhjZXB0IEV4
Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiByZW1vdGUgY29udHJvbCB0
aWNrIGZhaWxlZCAoJXMpIiAlIG50X2NvbnRyb2wuc2FmZV9tZXNzYWdlKGUpKQogICAgICAgICAg
ICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSArIGNvbnRyb2xfaW50ZXJ2YWwKICAgICAgICB0
cnk6CiAgICAgICAgICAgIHBrdCA9IHMucmVjdig2NTUzNSkKICAgICAgICAgICAgZGJnX3J4ICs9
IDEKICAgICAgICAgICAgaWYgZGJnIGFuZCB0aW1lLnRpbWUoKSAtIGRiZ19sYXN0ID4gNToKICAg
ICAgICAgICAgICAgIGxvZygiREVCVUcgcng9JWQiICUgZGJnX3J4KQogICAgICAgICAgICAgICAg
ZGJnX2xhc3QgPSB0aW1lLnRpbWUoKQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAg
ICAgICAgICAgaWYgZGJnOgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyB0aW1lb3V0IHJ4PSVk
IiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgICAg
ICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5v
dywgbGFzdF9zd2VlcCk6CiAgICAgICAgICAgICAgICBvdXRfcyA9IFtdCiAgICAgICAgICAgICAg
ICBzd2VlcF9pZGxlKGZsb3dzLCBub3csIG91dF9zLCBwZW5kaW5nKQogICAgICAgICAgICAgICAg
c3dlZXBfcGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICAgICAgZm9yIGV2
IGluIG91dF9zOgogICAgICAgICAgICAgICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1w
cyhldikgKyAiXG4iKQogICAgICAgICAgICAgICAgaWYgb3V0X3M6CiAgICAgICAgICAgICAgICAg
ICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAgICAgICAgICBsYXN0X3N3ZWVwID0gbm93CiAg
ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAg
ICAgICAgICBpZiBlLmVycm5vID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAgY29udGlu
dWUKICAgICAgICAgICAgcmFpc2UKICAgICAgICBuID0gbGVuKHBrdCkKICAgICAgICBpZiBuIDwg
MzQ6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgb3V0ID0gW10KICAgICAgICBvZmYgPSAx
NCAgICAgICAgICAgICAgICAgICAgICAjIGV0aGVybmV0IGhlYWRlcgogICAgICAgIGV0eXBlID0g
dTE2KHBrdCwgMTIpWzBdCiAgICAgICAgaWYgZXR5cGUgPT0gRVRIX1BfVkxBTjoKICAgICAgICAg
ICAgZXR5cGUgPSB1MTYocGt0LCAxNilbMF0KICAgICAgICAgICAgb2ZmID0gMTgKICAgICAgICBl
bGlmIGV0eXBlICE9IEVUSF9QX0lQOgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAg
ICAgICMgd2l0aCBCUEYgYXR0YWNoZWQgdGhpcyBpcyByYXJlCiAgICAgICAgaXAwID0gdWIocGt0
LCBvZmYpWzBdCiAgICAgICAgaWYgaXAwID4+IDQgIT0gNCBvciB1Yihwa3QsIG9mZiArIDkpWzBd
ICE9IDY6ICAgIyBJUHY0IFRDUCBvbmx5CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWhs
ID0gKGlwMCAmIDB4MEYpICogNAogICAgICAgIGZyYWcgPSB1MTYocGt0LCBvZmYgKyA2KVswXQog
ICAgICAgIGlmIGZyYWcgJiAweDFGRkY6ICAgICAgICAgICAgICAgICAgICAgICAgICMgbm9uLWZp
cnN0IGZyYWdtZW50CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgc3JjX2lwID0gbnRvYShw
a3Rbb2ZmICsgMTI6b2ZmICsgMTZdKQogICAgICAgIGRzdF9pcCA9IG50b2EocGt0W29mZiArIDE2
Om9mZiArIDIwXSkKICAgICAgICB0Y3Bfb2ZmID0gb2ZmICsgaWhsCiAgICAgICAgc3BvcnQsIGRw
b3J0ID0gdWgocGt0LCB0Y3Bfb2ZmKQogICAgICAgIGRvZmZfZmxhZ3MgPSB1Yihwa3QsIHRjcF9v
ZmYgKyAxMikKICAgICAgICBkb2ZmID0gKGRvZmZfZmxhZ3NbMF0gPj4gNCkgKiA0CiAgICAgICAg
cGF5X3N0YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgICAgICBpZiBuIDw9IHBheV9zdGFydDoKICAg
ICAgICAgICAgY29udGludWUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIG5vIHBheWxv
YWQgaW4gc2VnbWVudAogICAgICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Ol0KICAgICAgICBm
bGFncyA9IGRvZmZfZmxhZ3NbMV0KICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQoKICAgICAgICAj
IC0tLS0tLS0tLS0tLS0tLS0gUkVTUE9OU0UgZGlyZWN0aW9uIChzZXJ2ZXIgLT4gY2xpZW50KSAt
LS0tLS0tLS0tCiAgICAgICAgaWYgc3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0
czoKICAgICAgICAgICAgIyBwZW5kaW5nIGtleSB3YXMgc3RvcmVkIGFzIChzZXJ2ZXJfaXAsIHNl
cnZlcl9wb3J0LCBjbGllbnRfaXAsCiAgICAgICAgICAgICMgY2xpZW50X3BvcnQpID09IChzcmMs
IHNwb3J0LCBkc3QsIGRwb3J0KSBPRiBUSElTIHJlc3BvbnNlIHBrdAogICAgICAgICAgICByayA9
IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBpZiBwYXlsb2FkWzo1
XSA9PSBiIkhUVFAvIjoKICAgICAgICAgICAgICAgIGNvcnJlbGF0ZV9yZXNwb25zZShwZW5kaW5n
LCByaywgcGF5bG9hZCwgbm93LCBvdXQpCiAgICAgICAgICAgIGVsaWYgZmxhZ3MgJiAweDA1OiAg
ICAgICAgICAgICAgICAgICAgICAjIEZJTnxSU1Q6IGZsdXNoIHVubWF0Y2hlZAogICAgICAgICAg
ICAgICAgZXYgPSBwZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAgICMgLS0tLS0tLS0tLS0tLS0t
LSBSRVFVRVNUIGRpcmVjdGlvbiAoY2xpZW50IC0+IHNlcnZlcikgLS0tLS0tLS0tLS0KICAgICAg
ICBlbGlmIGRwb3J0IGluIHBvcnRzOgogICAgICAgICAgICBpZiBmbGFncyAmIDB4MDU6ICAgICAg
ICAgICAgICAgICAgICAgICMgdGVhcmRvd24gdy9vIHJlc3BvbnNlIHNlZW4KICAgICAgICAgICAg
ICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpCiAgICAgICAgICAgICAgICBw
ZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAgICAgICBrZXkgPSAoc3JjX2lwLCBzcG9ydCwgZHN0
X2lwLCBkcG9ydCkKICAgICAgICAgICAgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgTm9uZSwg
cGF5bG9hZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKGRzdF9pcCwgZHBvcnQsIHNyY19p
cCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICBwb3J0cywgbm9kZV9ob3N0LCBv
dXQsIHBlbmRpbmcsIG5vdywKICAgICAgICAgICAgICAgICAgICAgICAgICAgd3NzZV9ib2R5X2J5
dGVzKQogICAgICAgIGlmIG91dDoKICAgICAgICAgICAgdyA9IHN5cy5zdGRvdXQud3JpdGUKICAg
ICAgICAgICAgZm9yIGV2IGluIG91dDoKICAgICAgICAgICAgICAgIHcoanNvbi5kdW1wcyhldikg
KyAiXG4iKQogICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKCiAgICAgICAgaWYgbWFpbnRl
bmFuY2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6CiAgICAgICAgICAgIG91dF9zID0gW10KICAgICAg
ICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93LCBvdXRfcywgcGVuZGluZykKICAgICAgICAgICAg
c3dlZXBfcGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICBmb3IgZXYgaW4g
b3V0X3M6CiAgICAgICAgICAgICAgICBzeXMuc3Rkb3V0LndyaXRlKGpzb24uZHVtcHMoZXYpICsg
IlxuIikKICAgICAgICAgICAgaWYgb3V0X3M6CiAgICAgICAgICAgICAgICBzeXMuc3Rkb3V0LmZs
dXNoKCkKICAgICAgICAgICAgbGFzdF9zd2VlcCA9IG5vdwoKICAgIG91dF9zID0gW10KICAgIGRy
YWluX2luY29tcGxldGVfd3NzZShmbG93cywgb3V0X3MsIHBlbmRpbmcsIHRpbWUudGltZSgpKQog
ICAgZHJhaW5fcGVuZGluZyhwZW5kaW5nLCBvdXRfcykKICAgIGZvciBldiBpbiBvdXRfczoKICAg
ICAgICBzeXMuc3Rkb3V0LndyaXRlKGpzb24uZHVtcHMoZXYpICsgIlxuIikKICAgIGlmIG91dF9z
OgogICAgICAgIHN5cy5zdGRvdXQuZmx1c2goKQogICAgbG9nKCJzdG9wcGVkICglZCBwZW5kaW5n
IHJlcXVlc3RzIGZsdXNoZWQpIiAlIGxlbihvdXRfcykpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFp
bl9fIjoKICAgIG1haW4oKQo=
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
WVRFUyA9IDY1NTM2Ck1BWF9RVUVVRV9CQVRDSEVTID0gMTYKREVGQVVMVF9SQVRFX0tCUFMgPSAx
MDI0Ck1JTl9SQVRFX0tCUFMgPSA2NApNQVhfUkFURV9LQlBTID0gMTAwMDAKRkxVU0hfU0VDID0g
NS4wCgoKZGVmIGxvZyhtc2cpOgogICAgc3lzLnN0ZGVyci53cml0ZSgibnQtc2hpcDogJXNcbiIg
JSBtc2cpCiAgICBzeXMuc3RkZXJyLmZsdXNoKCkKCgpjbGFzcyBSYXRlTGltaXRlcihvYmplY3Qp
OgogICAgIiIiUmVzZXJ2ZSBhZ2dyZWdhdGUgdXBsb2FkIHNsb3RzIGFjcm9zcyBhbGwgcG9zdGVy
IHRocmVhZHMuIiIiCiAgICBkZWYgX19pbml0X18oc2VsZiwga2Jwcyk6CiAgICAgICAgc2VsZi5i
eXRlc19wZXJfc2VjID0gbWF4KDEsIChrYnBzICogMTAwMCkgLy8gOCkKICAgICAgICBzZWxmLm5l
eHRfc2xvdCA9IDAuMAogICAgICAgIHNlbGYubG9jayA9IHRocmVhZGluZy5Mb2NrKCkKCiAgICBk
ZWYgd2FpdChzZWxmLCBzaXplKToKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIHNl
bGYubG9jay5hY3F1aXJlKCkKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIHNlbGYubmV4dF9z
bG90IDwgbm93IG9yIHNlbGYubmV4dF9zbG90IC0gbm93ID4gNjAuMDoKICAgICAgICAgICAgICAg
IHNlbGYubmV4dF9zbG90ID0gbm93CiAgICAgICAgICAgIHNsb3QgPSBzZWxmLm5leHRfc2xvdAog
ICAgICAgICAgICBzZWxmLm5leHRfc2xvdCArPSBmbG9hdChzaXplKSAvIHNlbGYuYnl0ZXNfcGVy
X3NlYwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNlbGYubG9jay5yZWxlYXNlKCkKICAg
ICAgICBkZWxheSA9IHNsb3QgLSBub3cKICAgICAgICBpZiBkZWxheSA+IDA6CiAgICAgICAgICAg
IHRpbWUuc2xlZXAoZGVsYXkpCgoKZGVmIHJlYWRfYm91bmRlZF9pbnQobmFtZSwgZGVmYXVsdCwg
bWluaW11bSwgbWF4aW11bSk6CiAgICB0cnk6CiAgICAgICAgdmFsdWUgPSBpbnQob3MuZW52aXJv
bi5nZXQobmFtZSwgc3RyKGRlZmF1bHQpKSkKICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAg
IHZhbHVlID0gZGVmYXVsdAogICAgcmV0dXJuIG1heChtaW5pbXVtLCBtaW4odmFsdWUsIG1heGlt
dW0pKQoKCmRlZiB0YWtlX2JvdW5kZWRfYmF0Y2goYnVmLCBub2RlKToKICAgICIiIlJlbW92ZSBv
bmUgPD02NCBLaUIgZW5jb2RlZCBiYXRjaCwgZHJvcHBpbmcgaW1wb3NzaWJsZSBnaWFudCBldmVu
dHMuIiIiCiAgICB3aGlsZSBidWY6CiAgICAgICAgYmF0Y2ggPSBbXQogICAgICAgIGVtcHR5X3Np
emUgPSBsZW4oanNvbi5kdW1wcyh7Im5vZGUiOiBub2RlLCAiZXZlbnRzIjogW119LAogICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29k
ZSgidXRmLTgiKSkKICAgICAgICBlbmNvZGVkX3NpemUgPSBlbXB0eV9zaXplCiAgICAgICAgZm9y
IGV2ZW50IGluIGJ1Zls6TUFYX0JBVENIXToKICAgICAgICAgICAgZXZlbnRfc2l6ZSA9IGxlbihq
c29uLmR1bXBzKGV2ZW50LCBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29kZSgidXRmLTgiKSkK
ICAgICAgICAgICAgY2FuZGlkYXRlX3NpemUgPSBlbmNvZGVkX3NpemUgKyBldmVudF9zaXplICsg
KDEgaWYgYmF0Y2ggZWxzZSAwKQogICAgICAgICAgICBpZiBjYW5kaWRhdGVfc2l6ZSA+IE1BWF9Q
T1NUX0JZVEVTOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgYmF0Y2guYXBwZW5k
KGV2ZW50KQogICAgICAgICAgICBlbmNvZGVkX3NpemUgPSBjYW5kaWRhdGVfc2l6ZQogICAgICAg
IGlmIGJhdGNoOgogICAgICAgICAgICBkZWwgYnVmWzpsZW4oYmF0Y2gpXQogICAgICAgICAgICBy
ZXR1cm4gYmF0Y2gKICAgICAgICBkZWwgYnVmWzBdCiAgICAgICAgbG9nKCJXQVJOOiBkcm9wcGVk
IG92ZXJzaXplZCBldmVudDsgZW5jb2RlZCBib2R5IGV4Y2VlZHMgJWQgYnl0ZXMiICUKICAgICAg
ICAgICAgTUFYX1BPU1RfQllURVMpCiAgICByZXR1cm4gW10KCgpkZWYgbWFpbigpOgogICAgZW5k
cG9pbnQgPSBOb25lCiAgICBzcG9vbCA9ICIvdmFyL2xpYi9uZXR3b3JrdHJhY2luZy9zbmlmZi1z
cG9vbC5qc29ubCIKICAgIGFyZ3YgPSBzeXMuYXJndlsxOl0KICAgIGkgPSAwCiAgICB3aGlsZSBp
IDwgbGVuKGFyZ3YpOgogICAgICAgIGEgPSBhcmd2W2ldCiAgICAgICAgaWYgYSA9PSAiLS1lbmRw
b2ludCI6CiAgICAgICAgICAgIGkgKz0gMTsgZW5kcG9pbnQgPSBhcmd2W2ldLnJzdHJpcCgiLyIp
CiAgICAgICAgZWxpZiBhID09ICItLXNwb29sIjoKICAgICAgICAgICAgaSArPSAxOyBzcG9vbCA9
IGFyZ3ZbaV0KICAgICAgICBlbGlmIGEgaW4gKCItaCIsICItLWhlbHAiKToKICAgICAgICAgICAg
cHJpbnQoX19kb2NfXyk7IHJhaXNlIFN5c3RlbUV4aXQoMCkKICAgICAgICBlbHNlOgogICAgICAg
ICAgICByYWlzZSBTeXN0ZW1FeGl0KCJ1bmtub3duIGFyZzogJXMiICUgYSkKICAgICAgICBpICs9
IDEKICAgIGlmIG5vdCBlbmRwb2ludDoKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCItLWVuZHBv
aW50IHJlcXVpcmVkIikKCiAgICBub2RlID0gc29ja2V0LmdldGhvc3RuYW1lKCkuc3BsaXQoIi4i
KVswXQogICAgcmF0ZV9rYnBzID0gcmVhZF9ib3VuZGVkX2ludCgiTlRfU0hJUF9SQVRFX0tCUFMi
LCBERUZBVUxUX1JBVEVfS0JQUywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTUlO
X1JBVEVfS0JQUywgTUFYX1JBVEVfS0JQUykKICAgIGxpbWl0ZXIgPSBSYXRlTGltaXRlcihyYXRl
X2ticHMpCiAgICBydW5uaW5nID0gW1RydWVdCgogICAgZGVmIHN0b3Aoc2lnbnVtLCBmcmFtZSk6
CiAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdU
RVJNLCBzdG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9wKQoKICAgIGRl
ZiBmbHVzaChiYXRjaCk6CiAgICAgICAgaWYgbm90IGJhdGNoOgogICAgICAgICAgICByZXR1cm4g
VHJ1ZQogICAgICAgIGJvZHkgPSBqc29uLmR1bXBzKHsibm9kZSI6IG5vZGUsICJldmVudHMiOiBi
YXRjaH0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKQog
ICAgICAgICMgcHkyIHVybGxpYjIgYWNjZXB0cyBzdHI7IHB5MyBzaGltL3Rlc3QgbmVlZHMgYnl0
ZXMg4oCUIGVuY29kZSB3aGVuCiAgICAgICAgIyB0aGUgcnVudGltZSBleHBvc2VzIGl0IChweTIg
c3RyIGhhcyBubyAuZW5jb2RlIG9uIGFsbCBidWlsZHMsIHNvCiAgICAgICAgIyBndWFyZCB3aXRo
IGhhc2F0dHIpCiAgICAgICAgaWYgaGFzYXR0cihib2R5LCAiZW5jb2RlIik6CiAgICAgICAgICAg
IGJvZHkgPSBib2R5LmVuY29kZSgidXRmLTgiKQogICAgICAgIGlmIGxlbihib2R5KSA+IE1BWF9Q
T1NUX0JZVEVTOgogICAgICAgICAgICBsb2coIldBUk46IHJlZnVzaW5nIG92ZXJzaXplZCB1cGxv
YWQgYm9keSAoJWQgYnl0ZXMpIiAlIGxlbihib2R5KSkKICAgICAgICAgICAgcmV0dXJuIEZhbHNl
CiAgICAgICAgbGltaXRlci53YWl0KGxlbihib2R5KSkKICAgICAgICByZXEgPSB1cmxsaWIyLlJl
cXVlc3QoZW5kcG9pbnQgKyAiL2FwaS9pbmdlc3QiLCBkYXRhPWJvZHksCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgIGhlYWRlcnM9eyJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNv
biJ9KQogICAgICAgIHRyeToKICAgICAgICAgICAgcmVzcCA9IHVybGxpYjIudXJsb3BlbihyZXEs
IHRpbWVvdXQ9MTApCiAgICAgICAgICAgIG9rID0gKHJlc3AuZ2V0Y29kZSgpID09IDIwMCkKICAg
ICAgICAgICAgcmVzcC5yZWFkKCkKICAgICAgICAgICAgcmVzcC5jbG9zZSgpCiAgICAgICAgICAg
IGlmIG9rOgogICAgICAgICAgICAgICAgbG9nKCJmbHVzaGVkICVkIGV2ZW50cyIgJSBsZW4oYmF0
Y2gpKQogICAgICAgICAgICByZXR1cm4gb2sKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6
CiAgICAgICAgICAgIGxvZygic2hpcCBmYWlsZWQ6ICVzIiAlIGUpCiAgICAgICAgICAgIHJldHVy
biBGYWxzZQoKICAgICMgLS0tLSBjb25jdXJyZW50IHNoaXBwaW5nIC0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgICMgaHViIGluZ2VzdCBsYXRlbmN5ICh+MzAw
LTUwMG1zIHBlciA0MDAtZXZlbnQgUE9TVCBvdmVyIFdBTikgbWFrZXMKICAgICMgc2VxdWVudGlh
bCBwb3N0aW5nIGEgfjEwMDAgZXYvcyBjZWlsaW5nOyBOIHBvc3RlciB0aHJlYWRzIHBvc3RpbmcK
ICAgICMgaW5kZXBlbmRlbnQgYmF0Y2hlcyBtdWx0aXBseSB0aGF0IGJ5IE5UX1NISVBfVEhSRUFE
UwogICAgbnRocmVhZHMgPSByZWFkX2JvdW5kZWRfaW50KCJOVF9TSElQX1RIUkVBRFMiLCA0LCAx
LCA4KQogICAgcSA9IFF1ZXVlLlF1ZXVlKG1heHNpemU9bWluKE1BWF9RVUVVRV9CQVRDSEVTLCBt
YXgoMiwgbnRocmVhZHMgKiAyKSkpCgogICAgZGVmIHBvc3RlcigpOgogICAgICAgIHdoaWxlIFRy
dWU6CiAgICAgICAgICAgIGJhdGNoID0gcS5nZXQoKQogICAgICAgICAgICBpZiBiYXRjaCBpcyBO
b25lOgogICAgICAgICAgICAgICAgcS50YXNrX2RvbmUoKQogICAgICAgICAgICAgICAgcmV0dXJu
CiAgICAgICAgICAgIGlmIG5vdCBmbHVzaChiYXRjaCk6CiAgICAgICAgICAgICAgICBsb2coIldB
Uk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAlZCBldmVudHMgKGluLW1lbW9yeSBkcm9wLCAw
IGRpc2sgSS9PKSIgJSBsZW4oYmF0Y2gpKQogICAgICAgICAgICBxLnRhc2tfZG9uZSgpCgogICAg
c3RhcnRlZF90aHJlYWRzID0gMAogICAgZm9yIF8gaW4gcmFuZ2UobnRocmVhZHMpOgogICAgICAg
IHRyeToKICAgICAgICAgICAgdCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXBvc3RlcikKICAg
ICAgICAgICAgdC5kYWVtb24gPSBUcnVlCiAgICAgICAgICAgIHQuc3RhcnQoKQogICAgICAgICAg
ICBzdGFydGVkX3RocmVhZHMgKz0gMQogICAgICAgIGV4Y2VwdCAoUnVudGltZUVycm9yLCB0aHJl
YWRpbmcuVGhyZWFkRXJyb3IpOgogICAgICAgICAgICBsb2coIldBUk46IHRocmVhZCBhbGxvY2F0
aW9uIHN0b3BwZWQgYXQgJWQgcG9zdGVyKHMpIiAlCiAgICAgICAgICAgICAgICBzdGFydGVkX3Ro
cmVhZHMpCiAgICAgICAgICAgIGJyZWFrCiAgICBpZiBzdGFydGVkX3RocmVhZHMgPT0gMDoKICAg
ICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5ub3Qgc3RhcnQgYW55IHNoaXBwZXIgdGhyZWFkIikK
ICAgIGxvZygiZWdyZXNzIGxpbWl0OiAlZCBrYml0L3MsICVkIHBvc3RlcihzKSwgJWQtYnl0ZSBI
VFRQIGJvZHkgY2FwIiAlCiAgICAgICAgKHJhdGVfa2Jwcywgc3RhcnRlZF90aHJlYWRzLCBNQVhf
UE9TVF9CWVRFUykpCgogICAgYnVmID0gW10KICAgIGxhc3RfZmx1c2ggPSB0aW1lLnRpbWUoKQoK
ICAgIHdoaWxlIHJ1bm5pbmdbMF06CiAgICAgICAgdHJ5OgogICAgICAgICAgICByLCBfLCBfID0g
c2VsZWN0LnNlbGVjdChbc3lzLnN0ZGluXSwgW10sIFtdLCAxLjApCiAgICAgICAgZXhjZXB0IHNl
bGVjdC5lcnJvciBhcyBlOgogICAgICAgICAgICBpZiBlWzBdID09IGVycm5vLkVJTlRSOgogICAg
ICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgaWYgcjoKICAg
ICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcmF3ID0gc3lzLnN0ZGluLnJlYWRsaW5lKCkK
ICAgICAgICAgICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yKSBhcyBlOgogICAgICAgICAgICAg
ICAgaWYgZ2V0YXR0cihlLCAnZXJybm8nLCBOb25lKSA9PSBlcnJuby5FSU5UUjoKICAgICAgICAg
ICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgaWYg
bm90IHJhdzoKICAgICAgICAgICAgICAgIGJyZWFrICAgICAgICAgICAgICAgICAgIyBFT0YKICAg
ICAgICAgICAgcmF3ID0gcmF3LnN0cmlwKCkKICAgICAgICAgICAgaWYgcmF3OgogICAgICAgICAg
ICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIGV2ID0ganNvbi5sb2FkcyhyYXcpCiAgICAg
ICAgICAgICAgICAgICAgaWYgaXNpbnN0YW5jZShldiwgZGljdCk6CiAgICAgICAgICAgICAgICAg
ICAgICAgIGlmIGxlbihidWYpID49IDQwMDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBk
ZWwgYnVmWzBdCiAgICAgICAgICAgICAgICAgICAgICAgIGJ1Zi5hcHBlbmQoZXYpCiAgICAgICAg
ICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICBwYXNzCgogICAg
ICAgIG5vdyA9IHRpbWUudGltZSgpCiAgICAgICAgd2hpbGUgbGVuKGJ1ZikgPj0gTUFYX0JBVENI
IG9yIChidWYgYW5kIG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDKToKICAgICAgICAgICAg
bGFzdF9mbHVzaCA9IG5vdwogICAgICAgICAgICBiYXRjaCA9IHRha2VfYm91bmRlZF9iYXRjaChi
dWYsIG5vZGUpCiAgICAgICAgICAgIGlmIG5vdCBiYXRjaDoKICAgICAgICAgICAgICAgIGJyZWFr
CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHEucHV0X25vd2FpdChiYXRjaCkKICAg
ICAgICAgICAgZXhjZXB0IFF1ZXVlLkZ1bGw6CiAgICAgICAgICAgICAgICBsb2coIldBUk46IGVn
cmVzcyBxdWV1ZSBmdWxsLCBkcm9wcGVkICVkIGV2ZW50cyIgJSBsZW4oYmF0Y2gpKQoKICAgICMg
c3RkaW4gY2xvc2VkIChzbmlmZmVyIHN0b3BwZWQpIOKAlCBlbnF1ZXVlIHRoZSBmaW5hbCBwYXJ0
aWFsIGJhdGNoIGJlZm9yZQogICAgIyB3YWl0aW5nIGZvciBwb3N0ZXIgdGhyZWFkcy4gUHJldmlv
dXNseSBldmVyeSBzaHV0ZG93biBsb3N0IDEuLjM5OSBldmVudHMuCiAgICBpZiBidWY6CiAgICAg
ICAgd2hpbGUgYnVmOgogICAgICAgICAgICBiYXRjaCA9IHRha2VfYm91bmRlZF9iYXRjaChidWYs
IG5vZGUpCiAgICAgICAgICAgIGlmIG5vdCBiYXRjaDoKICAgICAgICAgICAgICAgIGJyZWFrCiAg
ICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHEucHV0X25vd2FpdChiYXRjaCkKICAgICAg
ICAgICAgZXhjZXB0IFF1ZXVlLkZ1bGw6CiAgICAgICAgICAgICAgICBsb2coIldBUk46IGVncmVz
cyBxdWV1ZSBmdWxsIGF0IHNodXRkb3duLCBkcm9wcGVkICVkIGV2ZW50cyIgJQogICAgICAgICAg
ICAgICAgICAgIGxlbihiYXRjaCkpCiAgICBxLmpvaW4oKQogICAgbG9nKCJzdG9wcGVkICglZCBl
dmVudHMgcGVuZGluZyBvbiBleGl0KSIgJSBsZW4oYnVmKSkKCgppZiBfX25hbWVfXyA9PSAiX19t
YWluX18iOgogICAgbWFpbigpCg==
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
PgojaW5jbHVkZSA8c3lzL3RpbWUuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8c2ln
bmFsLmg+CgpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9CQVRDSCA9IDQwMDsKc3RhdGljIGNvbnN0
IHNpemVfdCBNQVhfUVVFVUUgPSA0MDAwOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QT1NUX0JZ
VEVTID0gNjU1MzY7CnN0YXRpYyB1bnNpZ25lZCBzaGlwX3JhdGVfa2JwcyA9IDEwMjQ7CnN0YXRp
YyBkb3VibGUgbmV4dF9zaGlwX3Nsb3QgPSAwLjA7CnN0YXRpYyBjb25zdCBpbnQgRkxVU0hfU0VD
ID0gNTsKc3RhdGljIGNvbnN0IGludCBSRVRSWV9TRUMgPSA2MDsKc3RhdGljIHZvbGF0aWxlIHNp
Z19hdG9taWNfdCBydW5uaW5nID0gMTsKc3RhdGljIHZvaWQgc3RvcF9zaWduYWwoaW50KSB7IHJ1
bm5pbmcgPSAwOyB9CnN0YXRpYyB2b2lkIGxvZ21zZyhjb25zdCBzdGQ6OnN0cmluZyAmcykgeyBz
dGQ6OmNlcnIgPDwgIm50LXNoaXAtY3BwOiAiIDw8IHMgPDwgc3RkOjplbmRsOyB9CnN0YXRpYyBz
dGQ6OnN0cmluZyBqc29ucShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHgg
PSAiXCIiOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgewogICAgdW5z
aWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIGlmIChjID09ICdcXCcgfHwg
YyA9PSAnIicpIHsgeCArPSAnXFwnOyB4ICs9IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0g
J1xuJykgeCArPSAiXFxuIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAg
IGVsc2UgaWYgKGMgPT0gJ1x0JykgeCArPSAiXFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCAr
PSAnPyc7CiAgICBlbHNlIHggKz0gKGNoYXIpYzsKICB9CiAgcmV0dXJuIHggKyAiXCIiOwp9CnN0
YXRpYyBzdGQ6OnN0cmluZyBzaGVsbHEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0
cmluZyBvID0gIiciOwogIGZvciAoc2l6ZV90IGk9MDtpPHMuc2l6ZSgpOysraSkgeyBpZiAoc1tp
XT09J1wnJykgbyArPSAiJ1xcJyciOyBlbHNlIG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIici
Owp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1iZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0ZDo6b3N0
cmluZ3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmlu
ZyBqc29uX2FycmF5KGNvbnN0IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAmYSkgewogIHN0ZDo6
c3RyaW5nIG89IlsiOyBmb3Ioc2l6ZV90IGk9MDtpPGEuc2l6ZSgpOysraSl7aWYoaSlvKz0iLCI7
bys9YVtpXTt9IHJldHVybiBvKyJdIjsKfQpzdGF0aWMgZG91YmxlIHdhbGxfc2Vjb25kcygpIHsg
c3RydWN0IHRpbWV2YWwgdHY7IGdldHRpbWVvZmRheSgmdHYsTlVMTCk7IHJldHVybiAoZG91Ymxl
KXR2LnR2X3NlYysoZG91YmxlKXR2LnR2X3VzZWMvMTAwMDAwMC4wOyB9CnN0YXRpYyB2b2lkIHBh
Y2VfdXBsb2FkKHNpemVfdCBieXRlcykgewogIGRvdWJsZSByYXRlPShkb3VibGUpc2hpcF9yYXRl
X2ticHMqMTAwMC4wLzguMCwgbm93PXdhbGxfc2Vjb25kcygpOwogIGlmKG5leHRfc2hpcF9zbG90
PG5vd3x8bmV4dF9zaGlwX3Nsb3Qtbm93PjYwLjApIG5leHRfc2hpcF9zbG90PW5vdzsKICBkb3Vi
bGUgc2xvdD1uZXh0X3NoaXBfc2xvdDsgbmV4dF9zaGlwX3Nsb3QrPShkb3VibGUpYnl0ZXMvcmF0
ZTsKICB3aGlsZShzbG90Pihub3c9d2FsbF9zZWNvbmRzKCkpKSB7IGRvdWJsZSBsZWZ0PXNsb3Qt
bm93OyB1c2Vjb25kc190IGRlbGF5PSh1c2Vjb25kc190KShsZWZ0PjAuNT81MDAwMDA6bGVmdCox
MDAwMDAwLjApOyBpZihkZWxheSkgdXNsZWVwKGRlbGF5KTsgfQp9CnN0YXRpYyBzaXplX3QgYm91
bmRlZF9iYXRjaF9jb3VudChjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJ1Zixjb25z
dCBzdGQ6OnN0cmluZyAmbm9kZSkgewogIHNpemVfdCBzaXplPXN0ZDo6c3RyaW5nKCJ7XCJub2Rl
XCI6Iikuc2l6ZSgpK2pzb25xKG5vZGUpLnNpemUoKStzdGQ6OnN0cmluZygiLFwiZXZlbnRzXCI6
W119Iikuc2l6ZSgpLCBuPTAsIGxpbWl0PWJ1Zi5zaXplKCk8TUFYX0JBVENIP2J1Zi5zaXplKCk6
TUFYX0JBVENIOwogIHdoaWxlKG48bGltaXQpIHsgc2l6ZV90IGV4dHJhPWJ1ZltuXS5zaXplKCkr
KG4/MTowKTsgaWYoZXh0cmE+TUFYX1BPU1RfQllURVMtc2l6ZSkgYnJlYWs7IHNpemUrPWV4dHJh
OyArK247IH0KICByZXR1cm4gbjsKfQpzdGF0aWMgYm9vbCBwb3N0KGNvbnN0IHN0ZDo6c3RyaW5n
ICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgY29u
c3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHk9
IntcIm5vZGVcIjoiK2pzb25xKG5vZGUpKyIsXCJldmVudHNcIjoiK2pzb25fYXJyYXkoYmF0Y2gp
KyJ9IjsKICBpZihib2R5LnNpemUoKT5NQVhfUE9TVF9CWVRFUykgcmV0dXJuIGZhbHNlOwogIHBh
Y2VfdXBsb2FkKGJvZHkuc2l6ZSgpKTsKICBzdGQ6OnN0cmluZyBjbWQ9ImN1cmwgLXNTZiAtLW1h
eC10aW1lIDEwIC0tbGltaXQtcmF0ZSAiK251bWJlcl9zdHJpbmcoKHNpemVfdClzaGlwX3JhdGVf
a2JwcyoxMDAwVS84VSkrIiAtbyAvZGV2L251bGwgLUggJ0NvbnRlbnQtVHlwZTogYXBwbGljYXRp
b24vanNvbicgLS1kYXRhLWJpbmFyeSBALSAiK3NoZWxscShlbmRwb2ludCsiL2FwaS9pbmdlc3Qi
KTsKICBGSUxFICpmcD1wb3BlbihjbWQuY19zdHIoKSwidyIpOyBpZighZnApIHJldHVybiBmYWxz
ZTsKICBmd3JpdGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAgaW50IHJjPXBj
bG9zZShmcCk7CiAgcmV0dXJuIFdJRkVYSVRFRChyYykgJiYgV0VYSVRTVEFUVVMocmMpID09IDA7
Cn0Kc3RhdGljIHZvaWQgc2VuZF9iYXRjaGVzKGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCxj
b25zdCBzdGQ6OnN0cmluZyAmbm9kZSwKICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6dmVj
dG9yPHN0ZDo6c3RyaW5nPiAqYnVmLCBib29sIGZsdXNoX2FsbCkgewogIHdoaWxlICghYnVmLT5l
bXB0eSgpICYmIChmbHVzaF9hbGwgfHwgYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIKSkgewogICAg
c2l6ZV90IG49Ym91bmRlZF9iYXRjaF9jb3VudCgqYnVmLG5vZGUpOwogICAgaWYoIW4pe2J1Zi0+
ZXJhc2UoYnVmLT5iZWdpbigpKTtsb2dtc2coIldBUk46IGRyb3BwZWQgb3ZlcnNpemVkIGV2ZW50
OyBlbmNvZGVkIGJvZHkgZXhjZWVkcyA2NTUzNiBieXRlcyIpO2NvbnRpbnVlO30KICAgIHN0ZDo6
dmVjdG9yPHN0ZDo6c3RyaW5nPiBiYXRjaChidWYtPmJlZ2luKCksYnVmLT5iZWdpbigpK24pOwog
ICAgaWYocG9zdChlbmRwb2ludCxub2RlLGJhdGNoKSkgewogICAgICBidWYtPmVyYXNlKGJ1Zi0+
YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7CiAgICAgIGxvZ21zZygiZmx1c2hlZCAiK251bWJlcl9z
dHJpbmcobikrIiBldmVudHMiKTsKICAgIH0gZWxzZSB7CiAgICAgIGJ1Zi0+ZXJhc2UoYnVmLT5i
ZWdpbigpLGJ1Zi0+YmVnaW4oKStuKTsKICAgICAgbG9nbXNnKCJXQVJOOiBIdWIgdW5yZWFjaGFi
bGUsIGRyb3BwZWQgIitudW1iZXJfc3RyaW5nKG4pKyIgZXZlbnRzIChpbi1tZW1vcnkgZHJvcCwg
MCBkaXNrIEkvTykiKTsKICAgICAgYnJlYWs7CiAgICB9CiAgfQp9CmludCBtYWluKGludCBhcmdj
LGNoYXIgKiphcmd2KSB7CiAgc3RkOjpzdHJpbmcgZW5kcG9pbnQ7IGludCBpOwogIGNvbnN0IGNo
YXIgKnJhdGVfZW52PWdldGVudigiTlRfU0hJUF9SQVRFX0tCUFMiKTsgaWYocmF0ZV9lbnYmJipy
YXRlX2Vudikgc2hpcF9yYXRlX2ticHM9KHVuc2lnbmVkKWF0b2kocmF0ZV9lbnYpOwogIGZvcihp
PTE7aTxhcmdjOysraSl7c3RkOjpzdHJpbmcgYT1hcmd2W2ldOyBpZihhPT0iLS1lbmRwb2ludCIm
JmkrMTxhcmdjKWVuZHBvaW50PWFyZ3ZbKytpXTsgZWxzZSBpZihhPT0iLS1zaGlwLXJhdGUta2Jw
cyImJmkrMTxhcmdjKXNoaXBfcmF0ZV9rYnBzPSh1bnNpZ25lZClhdG9pKGFyZ3ZbKytpXSk7IGVs
c2UgaWYoYT09Ii0tc3Bvb2wiJiZpKzE8YXJnYykrK2k7IGVsc2UgaWYoYT09Ii1oInx8YT09Ii0t
aGVscCIpe3N0ZDo6Y291dDw8InVzYWdlOiBudC1zaGlwLWNwcCAtLWVuZHBvaW50IFVSTCBbLS1z
aGlwLXJhdGUta2JwcyA2NC4uMTAwMDBdXG4iO3JldHVybiAwO30gZWxzZSB7c3RkOjpjZXJyPDwi
dW5rbm93biBhcmc6ICI8PGE8PCJcbiI7cmV0dXJuIDI7fX0KICBpZihlbmRwb2ludC5lbXB0eSgp
KXtzdGQ6OmNlcnI8PCItLWVuZHBvaW50IHJlcXVpcmVkXG4iO3JldHVybiAyO30KICBpZihzaGlw
X3JhdGVfa2Jwczw2NHx8c2hpcF9yYXRlX2ticHM+MTAwMDApe3N0ZDo6Y2Vycjw8InNoaXAgcmF0
ZSBtdXN0IGJlIGluIHJhbmdlIDY0Li4xMDAwMCBrYml0L3NcbiI7cmV0dXJuIDI7fQogIHNpZ25h
bChTSUdURVJNLHN0b3Bfc2lnbmFsKTsgc2lnbmFsKFNJR0lOVCxzdG9wX3NpZ25hbCk7CiAgY2hh
ciBob3N0WzI1Nl07IGdldGhvc3RuYW1lKGhvc3Qsc2l6ZW9mKGhvc3QpKTsgaG9zdFtzaXplb2Yo
aG9zdCktMV09MDsKICBjb25zdCBjaGFyICpub2RlX2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1F
Iik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2RlX2VudiAmJiAqbm9kZV9lbnYpID8gbm9kZV9l
bnYgOiBob3N0OwogIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBidWY7IHRpbWVfdCBsYXN0PXRp
bWUoTlVMTCk7CiAgc3RkOjpzdHJpbmcgbGluZTsKICB3aGlsZShydW5uaW5nKSB7CiAgICBmZF9z
ZXQgcjsgRkRfWkVSTygmcik7IEZEX1NFVCgwLCAmcik7CiAgICBzdHJ1Y3QgdGltZXZhbCB0djsg
dHYudHZfc2VjID0gMTsgdHYudHZfdXNlYyA9IDA7CiAgICBpbnQgcmMgPSBzZWxlY3QoMSwgJnIs
IE5VTEwsIE5VTEwsICZ0dik7CiAgICBpZiAocmMgPiAwICYmIEZEX0lTU0VUKDAsICZyKSkgewog
ICAgICB3aGlsZSAocnVubmluZyAmJiBzdGQ6OmNpbiAmJiBidWYuc2l6ZSgpIDwgTUFYX1FVRVVF
KSB7CiAgICAgICAgaWYgKCFzdGQ6OmdldGxpbmUoc3RkOjpjaW4sIGxpbmUpKSBicmVhazsKICAg
ICAgICBpZiAoIWxpbmUuZW1wdHkoKSkgewogICAgICAgICAgaWYgKGJ1Zi5zaXplKCkgPj0gTUFY
X1FVRVVFKSBidWYuZXJhc2UoYnVmLmJlZ2luKCkpOwogICAgICAgICAgYnVmLnB1c2hfYmFjayhs
aW5lKTsKICAgICAgICB9CiAgICAgICAgaWYgKGJ1Zi5zaXplKCkgPj0gTUFYX0JBVENIKSB7CiAg
ICAgICAgICBzZW5kX2JhdGNoZXMoZW5kcG9pbnQsIG5vZGUsICZidWYsIGZhbHNlKTsKICAgICAg
ICB9CiAgICAgICAgaWYgKHN0ZDo6Y2luLnJkYnVmKCktPmluX2F2YWlsKCkgPD0gMCkgYnJlYWs7
CiAgICAgIH0KICAgIH0KICAgIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAt
IGxhc3QgPj0gRkxVU0hfU0VDIHx8IGJ1Zi5zaXplKCkgPj0gTUFYX0JBVENIKSB7CiAgICAgIGlm
ICghYnVmLmVtcHR5KCkpIHNlbmRfYmF0Y2hlcyhlbmRwb2ludCwgbm9kZSwgJmJ1ZiwgdHJ1ZSk7
CiAgICAgIGxhc3QgPSBub3c7CiAgICB9CiAgfQogIGlmICghYnVmLmVtcHR5KCkpIHNlbmRfYmF0
Y2hlcyhlbmRwb2ludCxub2RlLCZidWYsdHJ1ZSk7CiAgbG9nbXNnKCJzdG9wcGVkIik7IHJldHVy
biAwOwp9Cg==
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
CiNpbmNsdWRlIDxzeXMvc29ja2V0Lmg+CiNpbmNsdWRlIDxzeXMvdHlwZXMuaD4KI2luY2x1ZGUg
PHRpbWUuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8bGludXgvZmlsdGVyLmg+CiNp
bmNsdWRlIDxsaW51eC9jYXBhYmlsaXR5Lmg+CiNpbmNsdWRlIDxsaW51eC9pZl9wYWNrZXQuaD4K
I2luY2x1ZGUgPGxpbnV4L2lmX2V0aGVyLmg+CiNpbmNsdWRlIDxpb3N0cmVhbT4KI2luY2x1ZGUg
PGZzdHJlYW0+CiNpbmNsdWRlIDxtYXA+CiNpbmNsdWRlIDxzc3RyZWFtPgojaW5jbHVkZSA8c3Ry
aW5nPgojaW5jbHVkZSA8dmVjdG9yPgoKc3RhdGljIHZvbGF0aWxlIHNpZ19hdG9taWNfdCBnX3J1
bm5pbmcgPSAxOwpzdGF0aWMgdm9pZCBzdG9wX3NpZ25hbChpbnQpIHsgZ19ydW5uaW5nID0gMDsg
fQoKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfRkxPV1MgPSA4MTkyOwpzdGF0aWMgY29uc3Qgc2l6
ZV90IE1BWF9QRU5ESU5HID0gODE5MjsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUEVORElOR19Q
RVJfRkxPVyA9IDMyOwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9QT1JUUyA9IDMwOwpzdGF0aWMg
Y29uc3Qgc2l6ZV90IE1BWF9IRUFERVIgPSAyNjIxNDQ7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFY
X1dTU0VfQk9EWV9CWVRFUyA9IDY1NTM2OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9XU1NFX0JP
RFlfRkxPV1MgPSAyNTY7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1dTU0VfVVNFUk5BTUUgPSAy
MDA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX0JBVENIID0gNDAwOwpzdGF0aWMgY29uc3Qgc2l6
ZV90IE1BWF9RVUVVRSA9IDQwMDA7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BPU1RfQllURVMg
PSA2NTUzNjsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIERFRkFVTFRfU0hJUF9SQVRFX0tCUFMgPSAx
MDI0OwpzdGF0aWMgY29uc3QgaW50IEZMVVNIX1NFQyA9IDU7CnN0YXRpYyBjb25zdCBpbnQgUkVU
UllfU0VDID0gNjA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RUTCA9IDE1OwpzdGF0aWMg
Y29uc3QgdW5zaWduZWQgUEVORElOR19UVEwgPSAzOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgQUND
RVBUID0gMjA0ODsKc3RhdGljIGNvbnN0IGludCBTT19BVFRBQ0hfRklMVEVSX09MRCA9IDI2Owpz
dGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfSVBfSE9TVCA9IDB4MDgwMDsKc3RhdGlj
IGNvbnN0IHVuc2lnbmVkIHNob3J0IEVUSF9QXzgwMjFRX0hPU1QgPSAweDgxMDA7CgpzdGF0aWMg
c3RkOjpzdHJpbmcgdHJpbShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHNpemVfdCBhID0gMCwg
YiA9IHMuc2l6ZSgpOwogIHdoaWxlIChhIDwgYiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKXNb
YV0pKSArK2E7CiAgd2hpbGUgKGIgPiBhICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1tiIC0g
MV0pKSAtLWI7CiAgcmV0dXJuIHMuc3Vic3RyKGEsIGIgLSBhKTsKfQpzdGF0aWMgc3RkOjpzdHJp
bmcgbG93ZXIoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyB4ID0gczsKICBz
aXplX3QgaTsgZm9yIChpID0gMDsgaSA8IHguc2l6ZSgpOyArK2kpIHhbaV0gPSAoY2hhcil0b2xv
d2VyKCh1bnNpZ25lZCBjaGFyKXhbaV0pOwogIHJldHVybiB4Owp9CnN0YXRpYyBzdGQ6OnN0cmlu
ZyBqc29ucShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSAiXCIiOyBz
aXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgewogICAgdW5zaWduZWQg
Y2hhciBjID0gKHVuc2lnbmVkIGNoYXIpc1tpXTsKICAgIGlmIChjID09ICdcXCcgfHwgYyA9PSAn
IicpIHsgeCArPSAnXFwnOyB4ICs9IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0gJ1xuJykg
eCArPSAiXFxuIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAgIGVsc2Ug
aWYgKGMgPT0gJ1x0JykgeCArPSAiXFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCArPSAnPyc7
CiAgICBlbHNlIHggKz0gKGNoYXIpYzsKICB9CiAgeCArPSAnIic7IHJldHVybiB4Owp9CnN0YXRp
YyBsb25nIGxvbmcgbm93X21zKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2OyBnZXR0aW1lb2ZkYXko
JnR2LCBOVUxMKTsKICByZXR1cm4gKGxvbmcgbG9uZyl0di50dl9zZWMgKiAxMDAwTEwgKyB0di50
dl91c2VjIC8gMTAwMDsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbnVtKGxvbmcgdikgeyBzdGQ6Om9z
dHJpbmdzdHJlYW0gbzsgbyA8PCB2OyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgYm9vbCB2YWxp
ZF9wb3J0KHVuc2lnbmVkIHApIHsgcmV0dXJuIHAgPiAwICYmIHAgPD0gNjU1MzU7IH0KCnN0YXRp
YyB1aW50MTZfdCByZWFkX3UxNihjb25zdCB1bnNpZ25lZCBjaGFyICpwKSB7CiAgdWludDE2X3Qg
dmFsdWU7CiAgbWVtY3B5KCZ2YWx1ZSwgcCwgc2l6ZW9mKHZhbHVlKSk7CiAgcmV0dXJuIHZhbHVl
Owp9CgpzdGF0aWMgdWludDMyX3QgcmVhZF91MzIoY29uc3QgdW5zaWduZWQgY2hhciAqcCkgewog
IHVpbnQzMl90IHZhbHVlOwogIG1lbWNweSgmdmFsdWUsIHAsIHNpemVvZih2YWx1ZSkpOwogIHJl
dHVybiB2YWx1ZTsKfQpzdGF0aWMgYm9vbCBoYXNfbWV0aG9kKGNvbnN0IHN0ZDo6c3RyaW5nICZt
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
bWV0aG9kLCBwYXRoLCB1c2VyLCBzY2hlbWUsIHByb2JlOwogIHN0ZDo6c3RyaW5nIGJhc2ljX3Vz
ZXIsIHdzc2VfdXNlcjsKICBzdGQ6OnN0cmluZyBob3N0X2hkciwgdXNlcl9hZ2VudCwgeGZmLCBj
YWxsZXIsIGRzdF9pcCwgdHJhY2VwYXJlbnQsIHRyYWNlX2lkOwogIHVuc2lnbmVkIGNhbGxlcl9w
b3J0LCBkc3RfcG9ydCwgcmVxX2J5dGVzLCByZXNwX2J5dGVzOyBpbnQgc3RhdHVzOyBsb25nIGR1
cmF0aW9uX21zOwogIGJvb2wgaGFzX3N0YXR1cywgaGFzX2R1cmF0aW9uLCBoYXNfcmVzcDsKICBF
dmVudCgpIDogdHMoMCksIGNhbGxlcl9wb3J0KDApLCBkc3RfcG9ydCgwKSwgcmVxX2J5dGVzKDAp
LCByZXNwX2J5dGVzKDApLCBzdGF0dXMoMCksIGR1cmF0aW9uX21zKDApLCBoYXNfc3RhdHVzKGZh
bHNlKSwgaGFzX2R1cmF0aW9uKGZhbHNlKSwgaGFzX3Jlc3AoZmFsc2UpIHt9Cn07CnN0cnVjdCBS
ZXF1ZXN0TWV0YSB7CiAgc3RkOjpzdHJpbmcgY29udGVudF90eXBlLCB0cmFuc2Zlcl9lbmNvZGlu
ZzsKICBzaXplX3QgY29udGVudF9sZW5ndGg7CiAgYm9vbCBoYXNfY29udGVudF9sZW5ndGg7CiAg
UmVxdWVzdE1ldGEoKSA6IGNvbnRlbnRfbGVuZ3RoKDApLCBoYXNfY29udGVudF9sZW5ndGgoZmFs
c2UpIHt9Cn07CnN0cnVjdCBGbG93IHsKICBzdGQ6OnN0cmluZyBidWY7CiAgdGltZV90IHRvdWNo
ZWQ7CiAgRXZlbnQgZXZlbnQ7CiAgc2l6ZV90IGJvZHlfZ29hbDsKICBib29sIGF3YWl0aW5nX2Jv
ZHk7CiAgRmxvdygpIDogdG91Y2hlZCh0aW1lKE5VTEwpKSwgYm9keV9nb2FsKDApLCBhd2FpdGlu
Z19ib2R5KGZhbHNlKSB7fQp9OwpzdHJ1Y3QgUGVuZGluZyB7CiAgRXZlbnQgZXY7CiAgbG9uZyBs
b25nIHN0YXJ0ZWRfbXM7CiAgUGVuZGluZygpIDogc3RhcnRlZF9tcygwKSB7fQogIFBlbmRpbmco
Y29uc3QgRXZlbnQgJmUsIGxvbmcgbG9uZyB0KSA6IGV2KGUpLCBzdGFydGVkX21zKHQpIHt9Cn07
CnN0cnVjdCBGbG93S2V5IHsKICB1aW50MzJfdCBzX2lwOwogIHVpbnQxNl90IHNwb3J0OwogIHVp
bnQzMl90IGRfaXA7CiAgdWludDE2X3QgZHBvcnQ7CiAgYm9vbCBvcGVyYXRvcjwoY29uc3QgRmxv
d0tleSAmeCkgY29uc3QgewogICAgaWYgKHNfaXAgIT0geC5zX2lwKSByZXR1cm4gc19pcCA8IHgu
c19pcDsKICAgIGlmIChzcG9ydCAhPSB4LnNwb3J0KSByZXR1cm4gc3BvcnQgPCB4LnNwb3J0Owog
ICAgaWYgKGRfaXAgIT0geC5kX2lwKSByZXR1cm4gZF9pcCA8IHguZF9pcDsKICAgIHJldHVybiBk
cG9ydCA8IHguZHBvcnQ7CiAgfQp9Owp0eXBlZGVmIEZsb3dLZXkgUGFja2V0S2V5OwoKc3RhdGlj
IHZvaWQgbG9nbXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7IGZwcmludGYoc3RkZXJyLCAibnQt
c25pZmYtY3BwOiAlc1xuIiwgcy5jX3N0cigpKTsgZmZsdXNoKHN0ZGVycik7IH0KCnN0YXRpYyBi
b29sIHBhcnNlX2RlY2ltYWxfc2l6ZShjb25zdCBjaGFyICpwLCBzaXplX3Qgbiwgc2l6ZV90ICpv
dXQpIHsKICB3aGlsZSAobiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKSpwKSkgeyArK3A7IC0t
bjsgfQogIHdoaWxlIChuICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpcFtuIC0gMV0pKSAtLW47
CiAgaWYgKCFuKSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IHZhbHVlID0gMDsKICBmb3IgKHNpemVf
dCBpID0gMDsgaSA8IG47ICsraSkgewogICAgaWYgKHBbaV0gPCAnMCcgfHwgcFtpXSA+ICc5Jykg
cmV0dXJuIGZhbHNlOwogICAgdW5zaWduZWQgZGlnaXQgPSAodW5zaWduZWQpKHBbaV0gLSAnMCcp
OwogICAgaWYgKHZhbHVlID4gKHNpemVfdCktMSAvIDEwIHx8IHZhbHVlICogMTAgPiAoc2l6ZV90
KS0xIC0gZGlnaXQpIHJldHVybiBmYWxzZTsKICAgIHZhbHVlID0gdmFsdWUgKiAxMCArIGRpZ2l0
OwogIH0KICAqb3V0ID0gdmFsdWU7CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHBhcnNl
X3JlcXVlc3QoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgRXZlbnQgKmUsIFJlcXVlc3RN
ZXRhICptZXRhKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSArIGxlbjsKICBjb25zdCBjaGFy
ICpwID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAn
XG4nLCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNoYXIgKnNw
MSA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICcgJywgZW9sIC0gcCk7CiAgaWYgKCFzcDEpIHJl
dHVybiBmYWxzZTsKICBlLT5tZXRob2QuYXNzaWduKHAsIHNwMSAtIHApOwogIGlmICghaGFzX21l
dGhvZChlLT5tZXRob2QpKSByZXR1cm4gZmFsc2U7CgogIGNvbnN0IGNoYXIgKnBhdGhfc3RhcnQg
PSBzcDEgKyAxOwogIHdoaWxlIChwYXRoX3N0YXJ0IDwgZW9sICYmICpwYXRoX3N0YXJ0ID09ICcg
JykgKytwYXRoX3N0YXJ0OwogIGNvbnN0IGNoYXIgKnNwMiA9IChjb25zdCBjaGFyICopbWVtY2hy
KHBhdGhfc3RhcnQsICcgJywgZW9sIC0gcGF0aF9zdGFydCk7CiAgaWYgKCFzcDIpIHNwMiA9IChl
b2wgPiBkYXRhICYmICooZW9sIC0gMSkgPT0gJ1xyJykgPyBlb2wgLSAxIDogZW9sOwogIGNvbnN0
IGNoYXIgKnFtYXJrID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJz8nLCBzcDIg
LSBwYXRoX3N0YXJ0KTsKICBzaXplX3QgcGF0aF9sZW4gPSAocW1hcmsgPyBxbWFyayA6IHNwMikg
LSBwYXRoX3N0YXJ0OwogIGlmIChwYXRoX2xlbiA+IDEyMCkgcGF0aF9sZW4gPSAxMjA7CiAgZS0+
cGF0aC5hc3NpZ24ocGF0aF9zdGFydCwgcGF0aF9sZW4pOwoKICBwID0gZW9sICsgMTsKICB3aGls
ZSAocCA8IGVuZCkgewogICAgaWYgKCpwID09ICdccicgfHwgKnAgPT0gJ1xuJykgYnJlYWs7CiAg
ICBjb25zdCBjaGFyICpsaW5lX2VuZCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVu
ZCAtIHApOwogICAgaWYgKCFsaW5lX2VuZCkgbGluZV9lbmQgPSBlbmQ7CiAgICBjb25zdCBjaGFy
ICpjb2xvbiA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICc6JywgbGluZV9lbmQgLSBwKTsKICAg
IGlmIChjb2xvbikgewogICAgICBzaXplX3QgaG5hbWVfbGVuID0gY29sb24gLSBwOwogICAgICBj
b25zdCBjaGFyICp2YWxfc3RhcnQgPSBjb2xvbiArIDE7CiAgICAgIHdoaWxlICh2YWxfc3RhcnQg
PCBsaW5lX2VuZCAmJiAoKnZhbF9zdGFydCA9PSAnICcgfHwgKnZhbF9zdGFydCA9PSAnXHQnKSkg
Kyt2YWxfc3RhcnQ7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9lbmQgPSBsaW5lX2VuZDsKICAgICAg
d2hpbGUgKHZhbF9lbmQgPiB2YWxfc3RhcnQgJiYgKHZhbF9lbmRbLTFdID09ICdccicgfHwgdmFs
X2VuZFstMV0gPT0gJ1xuJyB8fCB2YWxfZW5kWy0xXSA9PSAnICcgfHwgdmFsX2VuZFstMV0gPT0g
J1x0JykpIC0tdmFsX2VuZDsKICAgICAgc2l6ZV90IHZhbF9sZW4gPSB2YWxfZW5kIC0gdmFsX3N0
YXJ0OwoKICAgICAgaWYgKGhuYW1lX2xlbiA9PSAxMyAmJiAhc3RybmNhc2VjbXAocCwgImF1dGhv
cml6YXRpb24iLCAxMykpIHsKICAgICAgICBpZiAodmFsX2xlbiA+IDYgJiYgIXN0cm5jYXNlY21w
KHZhbF9zdGFydCwgIkJhc2ljICIsIDYpKSB7CiAgICAgICAgICBzdGQ6OnN0cmluZyBiYXNpY191
c2VyID0gYjY0ZGVjb2RlX3VzZXIodmFsX3N0YXJ0ICsgNiwgdmFsX2xlbiAtIDYpOwogICAgICAg
ICAgaWYgKCFiYXNpY191c2VyLmVtcHR5KCkpIHsKICAgICAgICAgICAgZS0+YmFzaWNfdXNlciA9
IGJhc2ljX3VzZXI7CiAgICAgICAgICAgIGUtPnVzZXIgPSBiYXNpY191c2VyOwogICAgICAgICAg
ICBlLT5zY2hlbWUgPSAiYmFzaWMiOwogICAgICAgICAgfQogICAgICAgIH0gZWxzZSBpZiAodmFs
X2xlbiA+IDcgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJlYXJlciAiLCA3KSkgewogICAg
ICAgICAgZS0+c2NoZW1lID0gImJlYXJlciI7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYgKGhu
YW1lX2xlbiA9PSAxMSAmJiAhc3RybmNhc2VjbXAocCwgInRyYWNlcGFyZW50IiwgMTEpKSB7CiAg
ICAgICAgZS0+dHJhY2VwYXJlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgICAg
ZS0+dHJhY2VfaWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVudChlLT50cmFjZXBhcmVudCk7CiAgICAg
IH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDQgJiYgIXN0cm5jYXNlY21wKHAsICJob3N0IiwgNCkp
IHsKICAgICAgICBlLT5ob3N0X2hkci5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAgICAg
fSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTAgJiYgIXN0cm5jYXNlY21wKHAsICJ1c2VyLWFnZW50
IiwgMTApKSB7CiAgICAgICAgZS0+dXNlcl9hZ2VudC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVu
KTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTUgJiYgIXN0cm5jYXNlY21wKHAsICJ4
LWZvcndhcmRlZC1mb3IiLCAxNSkpIHsKICAgICAgICBlLT54ZmYuYXNzaWduKHZhbF9zdGFydCwg
dmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAmJiBobmFtZV9sZW4gPT0gMTIgJiYgIXN0
cm5jYXNlY21wKHAsICJjb250ZW50LXR5cGUiLCAxMikpIHsKICAgICAgICBtZXRhLT5jb250ZW50
X3R5cGUuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAgIH0gZWxzZSBpZiAobWV0YSAm
JiBobmFtZV9sZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxlbmd0aCIsIDE0
KSkgewogICAgICAgIG1ldGEtPmhhc19jb250ZW50X2xlbmd0aCA9IHBhcnNlX2RlY2ltYWxfc2l6
ZSh2YWxfc3RhcnQsIHZhbF9sZW4sICZtZXRhLT5jb250ZW50X2xlbmd0aCk7CiAgICAgIH0gZWxz
ZSBpZiAobWV0YSAmJiBobmFtZV9sZW4gPT0gMTcgJiYgIXN0cm5jYXNlY21wKHAsICJ0cmFuc2Zl
ci1lbmNvZGluZyIsIDE3KSkgewogICAgICAgIG1ldGEtPnRyYW5zZmVyX2VuY29kaW5nLmFzc2ln
bih2YWxfc3RhcnQsIHZhbF9sZW4pOwogICAgICB9CiAgICB9CiAgICBwID0gbGluZV9lbmQgKyAx
OwogIH0KCiAgaWYgKGUtPnVzZXIuZW1wdHkoKSkgZS0+dXNlciA9ICItYW5vbnltb3VzLSI7CiAg
aWYgKGUtPnNjaGVtZS5lbXB0eSgpKSBlLT5zY2hlbWUgPSAibm9uZSI7CiAgaWYgKGUtPnRyYWNl
X2lkLmVtcHR5KCkpIGUtPnRyYWNlcGFyZW50ID0gbWFrZV90cmFjZXBhcmVudCgmZS0+dHJhY2Vf
aWQpOwogIHJldHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBpc193c3NlX25hbWVzcGFjZShjb25z
dCBzdGQ6OnN0cmluZyAmdXJpKSB7CiAgcmV0dXJuIHVyaSA9PSAiaHR0cDovL2RvY3Mub2FzaXMt
b3Blbi5vcmcvd3NzLzIwMDQvMDEvb2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0x
LjAueHNkIiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dz
LzIwMDIvMDcvc2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNv
YXAub3JnL3dzLzIwMDIvMTIvc2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hl
bWFzLnhtbHNvYXAub3JnL3dzLzIwMDMvMDYvc2VjZXh0IjsKfQoKc3RhdGljIGJvb2wgaXNfc29h
cF9jb250ZW50X3R5cGUoY29uc3Qgc3RkOjpzdHJpbmcgJnZhbHVlKSB7CiAgc3RkOjpzdHJpbmcg
bWVkaWEgPSBsb3dlcih2YWx1ZSk7CiAgc2l6ZV90IHNlbWkgPSBtZWRpYS5maW5kKCc7Jyk7CiAg
aWYgKHNlbWkgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIG1lZGlhLmVyYXNlKHNlbWkpOwogIG1lZGlh
ID0gdHJpbShtZWRpYSk7CiAgcmV0dXJuIG1lZGlhID09ICJ0ZXh0L3htbCIgfHwgbWVkaWEgPT0g
ImFwcGxpY2F0aW9uL3htbCIgfHwKICAgICAgICAgbWVkaWEgPT0gImFwcGxpY2F0aW9uL3NvYXAr
eG1sIiB8fAogICAgICAgICAobWVkaWEuc2l6ZSgpID4gNCAmJiBtZWRpYS5jb21wYXJlKG1lZGlh
LnNpemUoKSAtIDQsIDQsICIreG1sIikgPT0gMCk7Cn0KCnN0YXRpYyB2b2lkIHNwbGl0X3FuYW1l
KGNvbnN0IHN0ZDo6c3RyaW5nICZuYW1lLCBzdGQ6OnN0cmluZyAqcHJlZml4LCBzdGQ6OnN0cmlu
ZyAqbG9jYWwpIHsKICBzaXplX3QgY29sb24gPSBuYW1lLmZpbmQoJzonKTsKICBpZiAoY29sb24g
PT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsgcHJlZml4LT5jbGVhcigpOyAqbG9jYWwgPSBuYW1lOyB9
CiAgZWxzZSB7ICpwcmVmaXggPSBuYW1lLnN1YnN0cigwLCBjb2xvbik7ICpsb2NhbCA9IG5hbWUu
c3Vic3RyKGNvbG9uICsgMSk7IH0KfQoKc3RhdGljIGJvb2wgYXBwZW5kX3V0ZjgodW5zaWduZWQg
bG9uZyBjcCwgc3RkOjpzdHJpbmcgKm91dCkgewogIGlmIChjcCA9PSAwIHx8IGNwID4gMHgxMGZm
ZmZVTCB8fCAoY3AgPj0gMHhkODAwVUwgJiYgY3AgPD0gMHhkZmZmVUwpKSByZXR1cm4gZmFsc2U7
CiAgaWYgKGNwIDwgMHg4MCkgb3V0LT5wdXNoX2JhY2soKGNoYXIpY3ApOwogIGVsc2UgaWYgKGNw
IDwgMHg4MDApIHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGMwIHwgKGNwID4+IDYpKSk7
CiAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfSBlbHNl
IGlmIChjcCA8IDB4MTAwMDApIHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGUwIHwgKGNw
ID4+IDEyKSkpOwogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoKGNwID4+IDYpICYg
MHgzZikpKTsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKGNwICYgMHgzZikpKTsK
ICB9IGVsc2UgewogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ZjAgfCAoY3AgPj4gMTgpKSk7
CiAgICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgoY3AgPj4gMTIpICYgMHgzZikpKTsK
ICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKChjcCA+PiA2KSAmIDB4M2YpKSk7CiAg
ICBvdXQtPnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfQogIHJldHVy
biB0cnVlOwp9CgpzdGF0aWMgYm9vbCB4bWxfdW5lc2NhcGUoY29uc3Qgc3RkOjpzdHJpbmcgJnRl
eHQsIHN0ZDo6c3RyaW5nICpvdXQpIHsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHRleHQuc2l6
ZSgpOykgewogICAgaWYgKHRleHRbaV0gIT0gJyYnKSB7IG91dC0+cHVzaF9iYWNrKHRleHRbaSsr
XSk7IGNvbnRpbnVlOyB9CiAgICBzaXplX3Qgc2VtaSA9IHRleHQuZmluZCgnOycsIGkgKyAxKTsK
ICAgIGlmIChzZW1pID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHNlbWkgLSBpID4gMTIpIHJldHVy
biBmYWxzZTsKICAgIHN0ZDo6c3RyaW5nIGVudCA9IHRleHQuc3Vic3RyKGkgKyAxLCBzZW1pIC0g
aSAtIDEpOwogICAgaWYgKGVudCA9PSAiYW1wIikgb3V0LT5wdXNoX2JhY2soJyYnKTsKICAgIGVs
c2UgaWYgKGVudCA9PSAibHQiKSBvdXQtPnB1c2hfYmFjaygnPCcpOwogICAgZWxzZSBpZiAoZW50
ID09ICJndCIpIG91dC0+cHVzaF9iYWNrKCc+Jyk7CiAgICBlbHNlIGlmIChlbnQgPT0gInF1b3Qi
KSBvdXQtPnB1c2hfYmFjaygnIicpOwogICAgZWxzZSBpZiAoZW50ID09ICJhcG9zIikgb3V0LT5w
dXNoX2JhY2soJ1wnJyk7CiAgICBlbHNlIGlmICghZW50LmVtcHR5KCkgJiYgZW50WzBdID09ICcj
JykgewogICAgICBjaGFyICplbmRwID0gTlVMTDsKICAgICAgdW5zaWduZWQgbG9uZyBjcCA9IHN0
cnRvdWwoZW50LmNfc3RyKCkgKyAoKGVudC5zaXplKCkgPiAxICYmIChlbnRbMV0gPT0gJ3gnIHx8
IGVudFsxXSA9PSAnWCcpKSA/IDIgOiAxKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgJmVuZHAsIChlbnQuc2l6ZSgpID4gMSAmJiAoZW50WzFdID09ICd4JyB8fCBlbnRbMV0gPT0g
J1gnKSkgPyAxNiA6IDEwKTsKICAgICAgaWYgKCFlbmRwIHx8ICplbmRwIHx8ICFhcHBlbmRfdXRm
OChjcCwgb3V0KSkgcmV0dXJuIGZhbHNlOwogICAgfSBlbHNlIHJldHVybiBmYWxzZTsKICAgIGkg
PSBzZW1pICsgMTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHZhbGlkX3V0Zjhf
dXNlcm5hbWUoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBpZiAocy5lbXB0eSgpIHx8IHMuc2l6
ZSgpID4gTUFYX1dTU0VfVVNFUk5BTUUgKiA0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IGNoYXJh
Y3RlcnMgPSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7KSB7CiAgICB1bnNp
Z25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgdW5zaWduZWQgbG9uZyBjcCA9
IGM7CiAgICBpZiAoYyA8IDB4ODApIHsgKytpOyB9CiAgICBlbHNlIHsKICAgIHNpemVfdCBuZWVk
ID0gKGMgPj0gMHhjMiAmJiBjIDw9IDB4ZGYpID8gMSA6CiAgICAgICAgICAgICAgICAgIChjID49
IDB4ZTAgJiYgYyA8PSAweGVmKSA/IDIgOgogICAgICAgICAgICAgICAgICAoYyA+PSAweGYwICYm
IGMgPD0gMHhmNCkgPyAzIDogOTk7CiAgICBpZiAobmVlZCA9PSA5OSB8fCBpICsgbmVlZCA+PSBz
LnNpemUoKSkgcmV0dXJuIGZhbHNlOwogICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0gbmVlZDsg
KytqKQogICAgICBpZiAoKCh1bnNpZ25lZCBjaGFyKXNbaSArIGpdICYgMHhjMCkgIT0gMHg4MCkg
cmV0dXJuIGZhbHNlOwogICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4ZTAgJiYgKHVuc2lnbmVk
IGNoYXIpc1tpICsgMV0gPCAweGEwKSByZXR1cm4gZmFsc2U7CiAgICBpZiAobmVlZCA9PSAyICYm
IGMgPT0gMHhlZCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA+PSAweGEwKSByZXR1cm4gZmFs
c2U7CiAgICBpZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmMCAmJiAodW5zaWduZWQgY2hhcilzW2kg
KyAxXSA8IDB4OTApIHJldHVybiBmYWxzZTsKICAgIGlmIChuZWVkID09IDMgJiYgYyA9PSAweGY0
ICYmICh1bnNpZ25lZCBjaGFyKXNbaSArIDFdID49IDB4OTApIHJldHVybiBmYWxzZTsKICAgIGNw
ID0gYyAmICgoMVUgPDwgKDcgLSBuZWVkIC0gMSkpIC0gMSk7CiAgICBmb3IgKHNpemVfdCBqID0g
MTsgaiA8PSBuZWVkOyArK2opIGNwID0gKGNwIDw8IDYpIHwgKCh1bnNpZ25lZCBjaGFyKXNbaSAr
IGpdICYgMHgzZik7CiAgICBpICs9IG5lZWQgKyAxOwogICAgfQogICAgaWYgKCsrY2hhcmFjdGVy
cyA+IE1BWF9XU1NFX1VTRVJOQU1FKSByZXR1cm4gZmFsc2U7CiAgICBpZiAoY3AgPCAweDIwIHx8
IChjcCA+PSAweDdmICYmIGNwIDw9IDB4OWYpIHx8CiAgICAgICAgKGNwID49IDB4ZTAwMCAmJiBj
cCA8PSAweGY4ZmYpIHx8CiAgICAgICAgKGNwID49IDB4ZjAwMDAgJiYgY3AgPD0gMHhmZmZmZCkg
fHwKICAgICAgICAoY3AgPj0gMHgxMDAwMDAgJiYgY3AgPD0gMHgxMGZmZmQpIHx8CiAgICAgICAg
KGNwID49IDB4ZmRkMCAmJiBjcCA8PSAweGZkZWYpIHx8IChjcCAmIDB4ZmZmZlVMKSA+PSAweGZm
ZmVVTCB8fAogICAgICAgIGNwID09IDB4MDBhZCB8fCBjcCA9PSAweDA2MWMgfHwgY3AgPT0gMHgw
NmRkIHx8IGNwID09IDB4MDcwZiB8fAogICAgICAgIGNwID09IDB4MTgwZSB8fCAoY3AgPj0gMHgy
MDBiICYmIGNwIDw9IDB4MjAwZikgfHwKICAgICAgICAoY3AgPj0gMHgyMDJhICYmIGNwIDw9IDB4
MjAyZSkgfHwgKGNwID49IDB4MjA2MCAmJiBjcCA8PSAweDIwNmYpIHx8CiAgICAgICAgY3AgPT0g
MHhmZWZmKSByZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdHJ1Y3QgWG1sRnJh
bWUgewogIHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz4gbnM7CiAgc3RkOjpzdHJp
bmcgcW5hbWUsIHVyaSwgbG9jYWw7Cn07CgpzdGF0aWMgYm9vbCBwYXJzZV94bWxfbmFtZShjb25z
dCBzdGQ6OnN0cmluZyAmYm9keSwgc2l6ZV90IGxpbWl0LCBzaXplX3QgKnBvcywKICAgICAgICAg
ICAgICAgICAgICAgICAgICAgc3RkOjpzdHJpbmcgKm5hbWUpIHsKICBzaXplX3Qgc3RhcnQgPSAq
cG9zOwogIHdoaWxlICgqcG9zIDwgbGltaXQpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNp
Z25lZCBjaGFyKWJvZHlbKnBvc107CiAgICBpZiAoIShpc2FsbnVtKGMpIHx8IGMgPT0gJ18nIHx8
IGMgPT0gJy0nIHx8IGMgPT0gJy4nIHx8IGMgPT0gJzonKSkgYnJlYWs7CiAgICArKypwb3M7CiAg
fQogIGlmICgqcG9zID09IHN0YXJ0IHx8ICpwb3MgLSBzdGFydCA+IDI1NikgcmV0dXJuIGZhbHNl
OwogIG5hbWUtPmFzc2lnbihib2R5LCBzdGFydCwgKnBvcyAtIHN0YXJ0KTsKICByZXR1cm4gdHJ1
ZTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIGV4dHJhY3Rfd3NzZV91c2VybmFtZShjb25zdCBzdGQ6
OnN0cmluZyAmYm9keSkgewogIGlmIChib2R5LmVtcHR5KCkgfHwgYm9keS5zaXplKCkgPiBNQVhf
V1NTRV9CT0RZX0JZVEVTIHx8CiAgICAgIGJvZHkuZmluZCgnXDAnKSAhPSBzdGQ6OnN0cmluZzo6
bnBvcykgcmV0dXJuICIiOwogIHN0ZDo6c3RyaW5nIGxvd2VyZWQgPSBsb3dlcihib2R5KTsKICBp
ZiAobG93ZXJlZC5maW5kKCI8IWRvY3R5cGUiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAg
ICBsb3dlcmVkLmZpbmQoIjwhZW50aXR5IikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiAi
IjsKCiAgc3RkOjp2ZWN0b3I8WG1sRnJhbWU+IHN0YWNrOwogIHNpemVfdCB0b2tlbl9kZXB0aCA9
IDAsIHVzZXJuYW1lX2RlcHRoID0gMCwgcG9zID0gMDsKICBzdGQ6OnN0cmluZyB0b2tlbl91cmks
IGNoYXJzLCByZXN1bHQ7CiAgYm9vbCB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICB3aGlsZSAocG9z
IDwgYm9keS5zaXplKCkpIHsKICAgIHNpemVfdCBsdCA9IGJvZHkuZmluZCgnPCcsIHBvcyk7CiAg
ICBpZiAobHQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRo
ICYmICF1c2VybmFtZV9iYWQgJiYgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cihwb3MpLCAmY2hh
cnMpKSB1c2VybmFtZV9iYWQgPSB0cnVlOwogICAgICBicmVhazsgLyogYSBib3VuZGVkIHByZWZp
eCBpcyBjb21tb25seSBpbmNvbXBsZXRlICovCiAgICB9CiAgICBpZiAodXNlcm5hbWVfZGVwdGgg
JiYgIXVzZXJuYW1lX2JhZCAmJiBsdCA+IHBvcyAmJgogICAgICAgICF4bWxfdW5lc2NhcGUoYm9k
eS5zdWJzdHIocG9zLCBsdCAtIHBvcyksICZjaGFycykpIHVzZXJuYW1lX2JhZCA9IHRydWU7CiAg
ICBpZiAoY2hhcnMuc2l6ZSgpID4gTUFYX1dTU0VfVVNFUk5BTUUgKiA0ICsgMikgeyBjaGFycy5j
bGVhcigpOyB1c2VybmFtZV9iYWQgPSB0cnVlOyB9CgogICAgaWYgKGJvZHkuY29tcGFyZShsdCwg
NCwgIjwhLS0iKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIi0tPiIsIGx0
ICsgNCk7IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBwb3MgPSBl
bmQgKyAzOyBjb250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDksICI8IVtD
REFUQVsiKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIl1dPiIsIGx0ICsg
OSk7IGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBpZiAodXNlcm5h
bWVfZGVwdGggJiYgIXVzZXJuYW1lX2JhZCkgY2hhcnMuYXBwZW5kKGJvZHksIGx0ICsgOSwgZW5k
IC0gbHQgLSA5KTsKICAgICAgcG9zID0gZW5kICsgMzsgY29udGludWU7CiAgICB9CiAgICBpZiAo
Ym9keS5jb21wYXJlKGx0LCAyLCAiPD8iKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5
LmZpbmQoIj8+IiwgbHQgKyAyKTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7
CiAgICAgIHBvcyA9IGVuZCArIDI7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29tcGFy
ZShsdCwgMiwgIjwhIikgPT0gMCkgcmV0dXJuICIiOwoKICAgIGJvb2wgY2xvc2luZyA9IChsdCAr
IDEgPCBib2R5LnNpemUoKSAmJiBib2R5W2x0ICsgMV0gPT0gJy8nKTsKICAgIHNpemVfdCBwID0g
bHQgKyAoY2xvc2luZyA/IDIgOiAxKTsKICAgIHN0ZDo6c3RyaW5nIHFuYW1lOwogICAgaWYgKCFw
YXJzZV94bWxfbmFtZShib2R5LCBib2R5LnNpemUoKSwgJnAsICZxbmFtZSkpIGJyZWFrOwogICAg
aWYgKGNsb3NpbmcpIHsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1
bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8
IGJvZHlbcF0gIT0gJz4nKSBicmVhazsKICAgICAgaWYgKHN0YWNrLmVtcHR5KCkpIGJyZWFrOwog
ICAgICBzdGQ6OnN0cmluZyBwcmVmaXgsIGxvY2FsOyBzcGxpdF9xbmFtZShxbmFtZSwgJnByZWZp
eCwgJmxvY2FsKTsKICAgICAgWG1sRnJhbWUgJnRvcCA9IHN0YWNrLmJhY2soKTsKICAgICAgaWYg
KHRvcC5xbmFtZSAhPSBxbmFtZSB8fCB0b3AubG9jYWwgIT0gbG9jYWwpIGJyZWFrOwogICAgICBz
aXplX3QgZGVwdGggPSBzdGFjay5zaXplKCk7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBk
ZXB0aCkgewogICAgICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0gdHJpbShjaGFycyk7CiAgICAg
ICAgaWYgKCF1c2VybmFtZV9iYWQgJiYgdmFsaWRfdXRmOF91c2VybmFtZSh1c2VybmFtZSkgJiYg
cmVzdWx0LmVtcHR5KCkpIHJlc3VsdCA9IHVzZXJuYW1lOwogICAgICAgIHVzZXJuYW1lX2RlcHRo
ID0gMDsgY2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICAgIH0KICAgICAg
aWYgKHRva2VuX2RlcHRoID09IGRlcHRoKSB7IHRva2VuX2RlcHRoID0gMDsgdG9rZW5fdXJpLmNs
ZWFyKCk7IH0KICAgICAgc3RhY2sucG9wX2JhY2soKTsgcG9zID0gcCArIDE7CiAgICAgIGlmICgh
cmVzdWx0LmVtcHR5KCkpIHJldHVybiByZXN1bHQ7CiAgICAgIGNvbnRpbnVlOwogICAgfQoKICAg
IFhtbEZyYW1lIGZyYW1lOwogICAgaWYgKHN0YWNrLnNpemUoKSA+PSA2NCkgcmV0dXJuICIiOwog
ICAgaWYgKCFzdGFjay5lbXB0eSgpKSBmcmFtZS5ucyA9IHN0YWNrLmJhY2soKS5uczsKICAgIGJv
b2wgc2VsZl9jbG9zaW5nID0gZmFsc2UsIGNvbXBsZXRlID0gZmFsc2U7CiAgICBzaXplX3QgYXR0
cl9jb3VudCA9IDA7CiAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpKSB7CiAgICAgIHdoaWxlIChw
IDwgYm9keS5zaXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwog
ICAgICBpZiAocCA+PSBib2R5LnNpemUoKSkgYnJlYWs7CiAgICAgIGlmIChib2R5W3BdID09ICc+
JykgeyArK3A7IGNvbXBsZXRlID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgaWYgKGJvZHlbcF0gPT0g
Jy8nICYmIHAgKyAxIDwgYm9keS5zaXplKCkgJiYgYm9keVtwICsgMV0gPT0gJz4nKSB7CiAgICAg
ICAgcCArPSAyOyBzZWxmX2Nsb3NpbmcgPSB0cnVlOyBjb21wbGV0ZSA9IHRydWU7IGJyZWFrOwog
ICAgICB9CiAgICAgIHN0ZDo6c3RyaW5nIGFuYW1lOwogICAgICBpZiAoIXBhcnNlX3htbF9uYW1l
KGJvZHksIGJvZHkuc2l6ZSgpLCAmcCwgJmFuYW1lKSkgYnJlYWs7CiAgICAgIGlmICgrK2F0dHJf
Y291bnQgPiAxMjgpIHJldHVybiAiIjsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBp
c3NwYWNlKCh1bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHku
c2l6ZSgpIHx8IGJvZHlbcCsrXSAhPSAnPScpIGJyZWFrOwogICAgICB3aGlsZSAocCA8IGJvZHku
c2l6ZSgpICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYg
KHAgPj0gYm9keS5zaXplKCkgfHwgKGJvZHlbcF0gIT0gJ1wnJyAmJiBib2R5W3BdICE9ICciJykp
IGJyZWFrOwogICAgICBjaGFyIHF1b3RlID0gYm9keVtwKytdOyBzaXplX3QgdmFsdWVfc3RhcnQg
PSBwOwogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbcF0gIT0gcXVvdGUpICsr
cDsKICAgICAgaWYgKHAgPj0gYm9keS5zaXplKCkpIGJyZWFrOwogICAgICBzdGQ6OnN0cmluZyB2
YWx1ZTsKICAgICAgaWYgKCF4bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIodmFsdWVfc3RhcnQsIHAg
LSB2YWx1ZV9zdGFydCksICZ2YWx1ZSkpIHJldHVybiAiIjsKICAgICAgKytwOwogICAgICBpZiAo
YW5hbWUgPT0gInhtbG5zIikgZnJhbWUubnNbIiJdID0gdmFsdWU7CiAgICAgIGVsc2UgaWYgKGFu
YW1lLmNvbXBhcmUoMCwgNiwgInhtbG5zOiIpID09IDApIGZyYW1lLm5zW2FuYW1lLnN1YnN0cig2
KV0gPSB2YWx1ZTsKICAgICAgaWYgKGZyYW1lLm5zLnNpemUoKSA+IDY0KSByZXR1cm4gIiI7CiAg
ICB9CiAgICBpZiAoIWNvbXBsZXRlKSBicmVhazsKICAgIHN0ZDo6c3RyaW5nIHByZWZpeCwgbG9j
YWw7IHNwbGl0X3FuYW1lKHFuYW1lLCAmcHJlZml4LCAmbG9jYWwpOwogICAgc3RkOjptYXA8c3Rk
OjpzdHJpbmcsIHN0ZDo6c3RyaW5nPjo6Y29uc3RfaXRlcmF0b3IgbnMgPSBmcmFtZS5ucy5maW5k
KHByZWZpeCk7CiAgICBmcmFtZS51cmkgPSAobnMgPT0gZnJhbWUubnMuZW5kKCkpID8gIiIgOiBu
cy0+c2Vjb25kOwogICAgZnJhbWUucW5hbWUgPSBxbmFtZTsKICAgIGZyYW1lLmxvY2FsID0gbG9j
YWw7CiAgICBzdGFjay5wdXNoX2JhY2soZnJhbWUpOwogICAgc2l6ZV90IGRlcHRoID0gc3RhY2su
c2l6ZSgpOwogICAgaWYgKCF0b2tlbl9kZXB0aCAmJiBsb2NhbCA9PSAiVXNlcm5hbWVUb2tlbiIg
JiYgaXNfd3NzZV9uYW1lc3BhY2UoZnJhbWUudXJpKSkgewogICAgICB0b2tlbl9kZXB0aCA9IGRl
cHRoOyB0b2tlbl91cmkgPSBmcmFtZS51cmk7CiAgICB9IGVsc2UgaWYgKHRva2VuX2RlcHRoICYm
IGRlcHRoID09IHRva2VuX2RlcHRoICsgMSAmJgogICAgICAgICAgICAgICBsb2NhbCA9PSAiVXNl
cm5hbWUiICYmIGZyYW1lLnVyaSA9PSB0b2tlbl91cmkpIHsKICAgICAgdXNlcm5hbWVfZGVwdGgg
PSBkZXB0aDsgY2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICB9CiAgICBp
ZiAoc2VsZl9jbG9zaW5nKSB7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBkZXB0aCkgdXNl
cm5hbWVfZGVwdGggPSAwOwogICAgICBpZiAodG9rZW5fZGVwdGggPT0gZGVwdGgpIHsgdG9rZW5f
ZGVwdGggPSAwOyB0b2tlbl91cmkuY2xlYXIoKTsgfQogICAgICBzdGFjay5wb3BfYmFjaygpOwog
ICAgfQogICAgcG9zID0gcDsKICB9CiAgcmV0dXJuIHJlc3VsdDsKfQoKc3RhdGljIGJvb2wgcGFy
c2VfcmVzcG9uc2UoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgaW50ICpzdGF0dXMsIHVu
c2lnbmVkICpjbGVuKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSArIGxlbjsKICBjb25zdCBj
aGFyICpwID0gZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3QgY2hhciAqKW1lbWNocihw
LCAnXG4nLCBlbmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNlOwogIGlmIChzdHJuY21w
KHAsICJIVFRQLyIsIDUpICE9IDApIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAo
Y29uc3QgY2hhciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4g
ZmFsc2U7CiAgY29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChzY19zdGFy
dCA8IGVvbCAmJiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0YXJ0OwogICpzdGF0dXMgPSBhdG9p
KHNjX3N0YXJ0KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAqc3RhdHVzID4gNTk5KSByZXR1cm4g
ZmFsc2U7CiAgKmNsZW4gPSAwOwogIHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAg
ICBpZiAoKnAgPT0gJ1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxp
bmVfZW5kID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAo
IWxpbmVfZW5kKSBsaW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0
IGNoYXIgKiltZW1jaHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAg
ICAgIHNpemVfdCBobGVuID0gY29sb24gLSBwOwogICAgICBpZiAoaGxlbiA9PSAxNCAmJiAhc3Ry
bmNhc2VjbXAocCwgImNvbnRlbnQtbGVuZ3RoIiwgMTQpKSB7CiAgICAgICAgY29uc3QgY2hhciAq
diA9IGNvbG9uICsgMTsKICAgICAgICB3aGlsZSAodiA8IGxpbmVfZW5kICYmICgqdiA9PSAnICcg
fHwgKnYgPT0gJ1x0JykpICsrdjsKICAgICAgICBsb25nIG4gPSBhdG9sKHYpOwogICAgICAgIGlm
IChuID49IDAgJiYgbiA8PSAweDdmZmZmZmZmKSAqY2xlbiA9ICh1bnNpZ25lZCluOwogICAgICB9
CiAgICB9CiAgICBwID0gbGluZV9lbmQgKyAxOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGlj
IHN0ZDo6c3RyaW5nIGdfZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX3NoaXBfbm9kZTsK
c3RhdGljIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBnX3NoaXBfYnVmOwpzdGF0aWMgdW5zaWdu
ZWQgZ19zaGlwX3JhdGVfa2JwcyA9IERFRkFVTFRfU0hJUF9SQVRFX0tCUFM7CnN0YXRpYyBkb3Vi
bGUgZ19uZXh0X3NoaXBfc2xvdCA9IDAuMDsKCnN0YXRpYyBzdGQ6OnN0cmluZyBzaGVsbHEoY29u
c3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZvciAoc2l6ZV90
IGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcnKSBvICs9ICInXFwn
JyI7IGVsc2UgbyArPSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGljIHN0ZDo6c3Ry
aW5nIG51bWJlcl9zdHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwg
bjsgcmV0dXJuIG8uc3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25fYXJyYXkoY29uc3Qg
c3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICJbIjsgZm9y
IChzaXplX3QgaSA9IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBvICs9ICIsIjsgbyAr
PSBhW2ldOyB9IHJldHVybiBvICsgIl0iOwp9CnN0YXRpYyBkb3VibGUgd2FsbF9zZWNvbmRzKCkg
ewogIHN0cnVjdCB0aW1ldmFsIHR2OwogIGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVy
biAoZG91YmxlKXR2LnR2X3NlYyArIChkb3VibGUpdHYudHZfdXNlYyAvIDEwMDAwMDAuMDsKfQpz
dGF0aWMgdm9pZCBwYWNlX3VwbG9hZChzaXplX3QgYnl0ZXMpIHsKICBjb25zdCBkb3VibGUgYnl0
ZXNfcGVyX3NlYyA9IChkb3VibGUpZ19zaGlwX3JhdGVfa2JwcyAqIDEwMDAuMCAvIDguMDsKICBk
b3VibGUgbm93ID0gd2FsbF9zZWNvbmRzKCk7CiAgaWYgKGdfbmV4dF9zaGlwX3Nsb3QgPCBub3cg
fHwgZ19uZXh0X3NoaXBfc2xvdCAtIG5vdyA+IDYwLjApIGdfbmV4dF9zaGlwX3Nsb3QgPSBub3c7
CiAgZG91YmxlIHNsb3QgPSBnX25leHRfc2hpcF9zbG90OwogIGdfbmV4dF9zaGlwX3Nsb3QgKz0g
KGRvdWJsZSlieXRlcyAvIGJ5dGVzX3Blcl9zZWM7CiAgd2hpbGUgKHNsb3QgPiAobm93ID0gd2Fs
bF9zZWNvbmRzKCkpKSB7CiAgICBkb3VibGUgcmVtYWluaW5nID0gc2xvdCAtIG5vdzsKICAgIHVz
ZWNvbmRzX3QgZGVsYXkgPSAodXNlY29uZHNfdCkocmVtYWluaW5nID4gMC41ID8gNTAwMDAwIDog
cmVtYWluaW5nICogMTAwMDAwMC4wKTsKICAgIGlmIChkZWxheSkgdXNsZWVwKGRlbGF5KTsKICB9
Cn0Kc3RhdGljIHNpemVfdCBib3VuZGVkX2JhdGNoX2NvdW50KGNvbnN0IHN0ZDo6dmVjdG9yPHN0
ZDo6c3RyaW5nPiAmYnVmLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qg
c3RkOjpzdHJpbmcgJm5vZGUpIHsKICBzaXplX3Qgc2l6ZSA9IHN0ZDo6c3RyaW5nKCJ7XCJub2Rl
XCI6Iikuc2l6ZSgpICsganNvbnEobm9kZSkuc2l6ZSgpICsKICAgICAgICAgICAgICAgIHN0ZDo6
c3RyaW5nKCIsXCJldmVudHNcIjpbXX0iKS5zaXplKCk7CiAgc2l6ZV90IG4gPSAwLCBsaW1pdCA9
IGJ1Zi5zaXplKCkgPCBNQVhfQkFUQ0ggPyBidWYuc2l6ZSgpIDogTUFYX0JBVENIOwogIHdoaWxl
IChuIDwgbGltaXQpIHsKICAgIHNpemVfdCBleHRyYSA9IGJ1ZltuXS5zaXplKCkgKyAobiA/IDEg
OiAwKTsKICAgIGlmIChleHRyYSA+IE1BWF9QT1NUX0JZVEVTIC0gc2l6ZSkgYnJlYWs7CiAgICBz
aXplICs9IGV4dHJhOwogICAgKytuOwogIH0KICByZXR1cm4gbjsKfQpzdGF0aWMgaW50IHJ1bl9z
aGlwX3JhdGVfZml4dHVyZSgpIHsKICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gZXZlbnRzOwog
IGV2ZW50cy5wdXNoX2JhY2soc3RkOjpzdHJpbmcoNDAwMDAsICd4JykpOwogIGV2ZW50cy5wdXNo
X2JhY2soc3RkOjpzdHJpbmcoNDAwMDAsICd5JykpOwogIGlmIChib3VuZGVkX2JhdGNoX2NvdW50
KGV2ZW50cywgImZpeHR1cmUiKSAhPSAxKSByZXR1cm4gMzA7CiAgZXZlbnRzLmNsZWFyKCk7CiAg
ZXZlbnRzLnB1c2hfYmFjayhzdGQ6OnN0cmluZyhNQVhfUE9TVF9CWVRFUyArIDEsICd4JykpOwog
IGlmIChib3VuZGVkX2JhdGNoX2NvdW50KGV2ZW50cywgImZpeHR1cmUiKSAhPSAwKSByZXR1cm4g
MzE7CiAgcmV0dXJuIDA7Cn0Kc3RhdGljIGJvb2wgcG9zdChjb25zdCBzdGQ6OnN0cmluZyAmZW5k
cG9pbnQsIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlLCBjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0
cmluZz4gJmJhdGNoKSB7CiAgc3RkOjpzdHJpbmcgYm9keSA9ICJ7XCJub2RlXCI6IiArIGpzb25x
KG5vZGUpICsgIixcImV2ZW50c1wiOiIgKyBqc29uX2FycmF5KGJhdGNoKSArICJ9IjsKICBpZiAo
Ym9keS5zaXplKCkgPiBNQVhfUE9TVF9CWVRFUykgcmV0dXJuIGZhbHNlOwogIHBhY2VfdXBsb2Fk
KGJvZHkuc2l6ZSgpKTsKICBzdGQ6OnN0cmluZyBjbWQgPSAiY3VybCAtc1NmIC0tbWF4LXRpbWUg
MTAgLS1saW1pdC1yYXRlICIgKwogICAgbnVtYmVyX3N0cmluZygoc2l6ZV90KWdfc2hpcF9yYXRl
X2ticHMgKiAxMDAwVSAvIDhVKSArCiAgICAiIC1vIC9kZXYvbnVsbCAtSCAnQ29udGVudC1UeXBl
OiBhcHBsaWNhdGlvbi9qc29uJyAtLWRhdGEtYmluYXJ5IEAtICIgKyBzaGVsbHEoZW5kcG9pbnQg
KyAiL2FwaS9pbmdlc3QiKTsKICBGSUxFICpmcCA9IHBvcGVuKGNtZC5jX3N0cigpLCAidyIpOyBp
ZiAoIWZwKSByZXR1cm4gZmFsc2U7CiAgZndyaXRlKGJvZHkuZGF0YSgpLCAxLCBib2R5LnNpemUo
KSwgZnApOwogIGludCByYyA9IHBjbG9zZShmcCk7CiAgcmV0dXJuIFdJRkVYSVRFRChyYykgJiYg
V0VYSVRTVEFUVVMocmMpID09IDA7Cn0Kc3RhdGljIHZvaWQgc2VuZF9iYXRjaGVzKGNvbnN0IHN0
ZDo6c3RyaW5nICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAg
ICAgICAgICAgICAgICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gKmJ1ZiwgYm9vbCBmbHVzaF9h
bGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1wdHkoKSAmJiAoZmx1c2hfYWxsIHx8IGJ1Zi0+c2l6ZSgp
ID49IE1BWF9CQVRDSCkpIHsKICAgIHNpemVfdCBuID0gYm91bmRlZF9iYXRjaF9jb3VudCgqYnVm
LCBub2RlKTsKICAgIGlmICghbikgewogICAgICBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSk7CiAg
ICAgIGxvZ21zZygiV0FSTjogZHJvcHBlZCBvdmVyc2l6ZWQgZXZlbnQ7IGVuY29kZWQgYm9keSBl
eGNlZWRzIDY1NTM2IGJ5dGVzIik7CiAgICAgIGNvbnRpbnVlOwogICAgfQogICAgc3RkOjp2ZWN0
b3I8c3RkOjpzdHJpbmc+IGJhdGNoKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigpICsgbik7CiAg
ICBpZiAocG9zdChlbmRwb2ludCwgbm9kZSwgYmF0Y2gpKSB7CiAgICAgIGJ1Zi0+ZXJhc2UoYnVm
LT5iZWdpbigpLCBidWYtPmJlZ2luKCkgKyBuKTsKICAgICAgbG9nbXNnKCJmbHVzaGVkICIgKyBu
dW1iZXJfc3RyaW5nKG4pICsgIiBldmVudHMiKTsKICAgIH0gZWxzZSB7CiAgICAgIC8qIFB1cmUg
aW4tbWVtb3J5IGRyb3Agd2hlbiBIdWIgdW5yZWFjaGFibGUgKHplcm8gZGlzayBJL08pICovCiAg
ICAgIGJ1Zi0+ZXJhc2UoYnVmLT5iZWdpbigpLCBidWYtPmJlZ2luKCkgKyBuKTsKICAgICAgbG9n
bXNnKCJXQVJOOiBIdWIgdW5yZWFjaGFibGUsIGRyb3BwZWQgIiArIG51bWJlcl9zdHJpbmcobikg
KyAiIGV2ZW50cyAoaW4tbWVtb3J5IGRyb3AsIDAgZGlzayBJL08pIik7CiAgICAgIGJyZWFrOwog
ICAgfQogIH0KfQoKc3RhdGljIHZvaWQgZW1pdF9ldmVudChjb25zdCBFdmVudCAmZSkgewogIHN0
ZDo6b3N0cmluZ3N0cmVhbSBzczsKICBzcyA8PCAie1widHNcIjoiIDw8IGUudHMgPDwgIixcImhv
c3RcIjoiIDw8IGpzb25xKGUuaG9zdCkgPDwgIixcInNyY1wiOlwicGNhcFwiLFwic2VydmljZVwi
OiIgPDwganNvbnEoZS5zZXJ2aWNlKQogICAgIDw8ICIsXCJtZXRob2RcIjoiIDw8IGpzb25xKGUu
bWV0aG9kKSA8PCAiLFwicGF0aFwiOiIgPDwganNvbnEoZS5wYXRoKSA8PCAiLFwidXNlclwiOiIg
PDwganNvbnEoZS51c2VyKQogICAgIDw8ICIsXCJzY2hlbWVcIjoiIDw8IGpzb25xKGUuc2NoZW1l
KQogICAgIDw8ICIsXCJiYXNpY191c2VyXCI6IiA8PCAoZS5iYXNpY191c2VyLmVtcHR5KCkgPyAi
bnVsbCIgOiBqc29ucShlLmJhc2ljX3VzZXIpKQogICAgIDw8ICIsXCJ3c3NlX3VzZXJcIjoiIDw8
IChlLndzc2VfdXNlci5lbXB0eSgpID8gIm51bGwiIDoganNvbnEoZS53c3NlX3VzZXIpKQogICAg
IDw8ICIsXCJzb3VyY2VfcHJvYmVcIjpcInBjYXAtaHR0cC1jcHBcIixcImhvc3RfaGRyXCI6IiA8
PCBqc29ucShlLmhvc3RfaGRyKQogICAgIDw8ICIsXCJ1c2VyX2FnZW50XCI6IiA8PCBqc29ucShl
LnVzZXJfYWdlbnQpIDw8ICIsXCJ4X2ZvcndhcmRlZF9mb3JcIjoiIDw8IGpzb25xKGUueGZmKQog
ICAgIDw8ICIsXCJjYWxsZXJcIjoiIDw8IGpzb25xKGUuY2FsbGVyKSA8PCAiLFwiY2FsbGVyX3Bv
cnRcIjoiIDw8IGUuY2FsbGVyX3BvcnQgPDwgIixcImRzdF9pcFwiOiIgPDwganNvbnEoZS5kc3Rf
aXApCiAgICAgPDwgIixcImRzdF9wb3J0XCI6IiA8PCBlLmRzdF9wb3J0IDw8ICIsXCJ0cmFjZXBh
cmVudFwiOiIgPDwganNvbnEoZS50cmFjZXBhcmVudCkgPDwgIixcInRyYWNlX2lkXCI6IiA8PCBq
c29ucShlLnRyYWNlX2lkKQogICAgIDw8ICIsXCJzZXJ2aWNlX2lkXCI6bnVsbCxcIm1vZHVsZV9p
ZFwiOlwicGNhcC1odHRwLWNwcFwiLFwicmVxX2J5dGVzXCI6IiA8PCBlLnJlcV9ieXRlczsKICBp
ZiAoZS5oYXNfc3RhdHVzKSBzcyA8PCAiLFwic3RhdHVzXCI6IiA8PCBlLnN0YXR1czsgZWxzZSBz
cyA8PCAiLFwic3RhdHVzXCI6bnVsbCI7CiAgaWYgKGUuaGFzX2R1cmF0aW9uKSBzcyA8PCAiLFwi
ZHVyYXRpb25fbXNcIjoiIDw8IGUuZHVyYXRpb25fbXM7IGVsc2Ugc3MgPDwgIixcImR1cmF0aW9u
X21zXCI6bnVsbCI7CiAgaWYgKGUuaGFzX3Jlc3ApIHNzIDw8ICIsXCJyZXNwX2J5dGVzXCI6IiA8
PCBlLnJlc3BfYnl0ZXM7IGVsc2Ugc3MgPDwgIixcInJlc3BfYnl0ZXNcIjpudWxsIjsKICBzcyA8
PCAifSI7CgogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBpZiAoZ19zaGlwX2J1Zi5z
aXplKCkgPj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9idWYuZXJhc2UoZ19zaGlwX2J1Zi5i
ZWdpbigpKTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNrKHNzLnN0cigpKTsKICB9IGVs
c2UgewogICAgc3RkOjpjb3V0IDw8IHNzLnN0cigpIDw8ICJcbiI7CiAgfQp9CgpzdGF0aWMgdm9p
ZCBxdWV1ZV9yZXF1ZXN0KGNvbnN0IEV2ZW50ICZlLCB1aW50MzJfdCBzX2lwLCB1bnNpZ25lZCBz
cG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICB1aW50MzJfdCBkX2lwLCB1bnNpZ25lZCBk
cG9ydCwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpOwoKc3RhdGljIHZvaWQgZmx1c2hfb2xkZXN0KHN0
ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIGlm
IChwZW5kaW5nLmVtcHR5KCkpIHJldHVybjsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVj
dG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIGl0ID0gcGVuZGluZy5iZWdpbigpOwogIGlmICghaXQt
PnNlY29uZC5lbXB0eSgpKSB7CiAgICBlbWl0X2V2ZW50KGl0LT5zZWNvbmRbMF0uZXYpOwogICAg
aXQtPnNlY29uZC5lcmFzZShpdC0+c2Vjb25kLmJlZ2luKCkpOwogIH0KICBpZiAoaXQtPnNlY29u
ZC5lbXB0eSgpKSB7CiAgICBwZW5kaW5nLmVyYXNlKGl0KTsKICB9Cn0Kc3RhdGljIHZvaWQgZmx1
c2hfYWxsX3BlbmRpbmcoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
ICZwZW5kaW5nKSB7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+
OjppdGVyYXRvciBwOwogIGZvciAocCA9IHBlbmRpbmcuYmVnaW4oKTsgcCAhPSBwZW5kaW5nLmVu
ZCgpOyArK3ApIHsKICAgIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcC0+c2Vjb25kLnNpemUoKTsg
KytpKSB7CiAgICAgIGVtaXRfZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgIH0KICB9CiAgcGVu
ZGluZy5jbGVhcigpOwp9CnN0YXRpYyB2b2lkIGZsdXNoX2luY29tcGxldGVfd3NzZShzdGQ6Om1h
cDxGbG93S2V5LCBGbG93PiAmZmxvd3MsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsK
ICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93Pjo6aXRlcmF0b3IgZjsKICBmb3IgKGYgPSBmbG93cy5i
ZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOyArK2YpIHsKICAgIGlmIChmLT5zZWNvbmQuYXdhaXRp
bmdfYm9keSAmJiAhZi0+c2Vjb25kLmV2ZW50LmJhc2ljX3VzZXIuZW1wdHkoKSkgewogICAgICBx
dWV1ZV9yZXF1ZXN0KGYtPnNlY29uZC5ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+Zmlyc3Quc3Bv
cnQsCiAgICAgICAgICAgICAgICAgICAgZi0+Zmlyc3QuZF9pcCwgZi0+Zmlyc3QuZHBvcnQsIHBl
bmRpbmcpOwogICAgfQogIH0KICBmbG93cy5jbGVhcigpOwp9CnN0YXRpYyB2b2lkIHN3ZWVwKHN0
ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cywgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZl
Y3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5nLCB0aW1lX3Qgbm93KSB7CiAgc3RkOjptYXA8Rmxvd0tl
eSwgRmxvdz46Oml0ZXJhdG9yIGYsIGZuOwogIGZvciAoZiA9IGZsb3dzLmJlZ2luKCk7IGYgIT0g
Zmxvd3MuZW5kKCk7KSB7CiAgICBmbiA9IGY7ICsrZm47CiAgICBpZiAoKHVuc2lnbmVkKShub3cg
LSBmLT5zZWNvbmQudG91Y2hlZCkgPiBGTE9XX1RUTCkgewogICAgICBpZiAoZi0+c2Vjb25kLmF3
YWl0aW5nX2JvZHkgJiYgIWYtPnNlY29uZC5ldmVudC5iYXNpY191c2VyLmVtcHR5KCkpIHsKICAg
ICAgICBxdWV1ZV9yZXF1ZXN0KGYtPnNlY29uZC5ldmVudCwgZi0+Zmlyc3Quc19pcCwgZi0+Zmly
c3Quc3BvcnQsCiAgICAgICAgICAgICAgICAgICAgICBmLT5maXJzdC5kX2lwLCBmLT5maXJzdC5k
cG9ydCwgcGVuZGluZyk7CiAgICAgIH0KICAgICAgZmxvd3MuZXJhc2UoZik7CiAgICB9CiAgICBm
ID0gZm47CiAgfQogIGxvbmcgbG9uZyBjdXJyZW50X21zID0gKGxvbmcgbG9uZylub3cgKiAxMDAw
TEw7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRv
ciBwLCBwbjsKICBmb3IgKHAgPSBwZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTsp
IHsKICAgIHBuID0gcDsgKytwbjsKICAgIHNpemVfdCBpID0gMDsKICAgIHdoaWxlIChpIDwgcC0+
c2Vjb25kLnNpemUoKSkgewogICAgICBpZiAoY3VycmVudF9tcyAtIHAtPnNlY29uZFtpXS5zdGFy
dGVkX21zID4gKGxvbmcgbG9uZylQRU5ESU5HX1RUTCAqIDEwMDBMTCkgewogICAgICAgIGVtaXRf
ZXZlbnQocC0+c2Vjb25kW2ldLmV2KTsKICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25k
LmJlZ2luKCkgKyBpKTsKICAgICAgfSBlbHNlIHsKICAgICAgICArK2k7CiAgICAgIH0KICAgIH0K
ICAgIGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5lcmFzZShwKTsKICAgIHAgPSBwbjsK
ICB9Cn0Kc3RhdGljIHNpemVfdCBmaW5kX2h0dHBfc3RhcnQoY29uc3Qgc3RkOjpzdHJpbmcgJnMp
IHsKICBjb25zdCBjaGFyICptW10gPSB7ICJHRVQgIiwgIlBPU1QgIiwgIlBVVCAiLCAiREVMRVRF
ICIsICJQQVRDSCAiLCAiSEVBRCAiLCAiT1BUSU9OUyAiIH07CiAgc2l6ZV90IGJlc3QgPSBzdGQ6
OnN0cmluZzo6bnBvczsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IDc7ICsraSkgewogICAgc2l6
ZV90IHBvcyA9IHMuZmluZChtW2ldKTsKICAgIGlmIChwb3MgIT0gc3RkOjpzdHJpbmc6Om5wb3Mg
JiYgKGJlc3QgPT0gc3RkOjpzdHJpbmc6Om5wb3MgfHwgcG9zIDwgYmVzdCkpIGJlc3QgPSBwb3M7
CiAgfQogIHJldHVybiBiZXN0Owp9CgpzdGF0aWMgYm9vbCBnX21vbml0b3JlZF9wb3J0c1s2NTUz
Nl07CnN0YXRpYyBzaXplX3QgZ193c3NlX2JvZHlfYnl0ZXMgPSAwOwoKc3RhdGljIHZvaWQgcXVl
dWVfcmVxdWVzdChjb25zdCBFdmVudCAmZSwgdWludDMyX3Qgc19pcCwgdW5zaWduZWQgc3BvcnQs
CiAgICAgICAgICAgICAgICAgICAgICAgICAgdWludDMyX3QgZF9pcCwgdW5zaWduZWQgZHBvcnQs
CiAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3Rv
cjxQZW5kaW5nPiA+ICZwZW5kaW5nKSB7CiAgUGFja2V0S2V5IHJrOwogIHJrLnNfaXAgPSBkX2lw
OyByay5zcG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICByay5kX2lwID0gc19pcDsgcmsuZHBvcnQg
PSAodWludDE2X3Qpc3BvcnQ7CiAgaWYgKHBlbmRpbmcuZmluZChyaykgPT0gcGVuZGluZy5lbmQo
KSAmJiBwZW5kaW5nLnNpemUoKSA+PSBNQVhfUEVORElORykgewogICAgZmx1c2hfb2xkZXN0KHBl
bmRpbmcpOwogIH0KICBzdGQ6OnZlY3RvcjxQZW5kaW5nPiAmcXVldWUgPSBwZW5kaW5nW3JrXTsK
ICBpZiAocXVldWUuc2l6ZSgpID49IE1BWF9QRU5ESU5HX1BFUl9GTE9XKSB7CiAgICBlbWl0X2V2
ZW50KHF1ZXVlWzBdLmV2KTsKICAgIHF1ZXVlLmVyYXNlKHF1ZXVlLmJlZ2luKCkpOwogIH0KICBx
dWV1ZS5wdXNoX2JhY2soUGVuZGluZyhlLCBub3dfbXMoKSkpOwp9CgpzdGF0aWMgc2l6ZV90IGFj
dGl2ZV93c3NlX2Zsb3dzKGNvbnN0IHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+ICZmbG93cykgewog
IHNpemVfdCBjb3VudCA9IDA7CiAgc3RkOjptYXA8Rmxvd0tleSwgRmxvdz46OmNvbnN0X2l0ZXJh
dG9yIGl0OwogIGZvciAoaXQgPSBmbG93cy5iZWdpbigpOyBpdCAhPSBmbG93cy5lbmQoKTsgKytp
dCkKICAgIGlmIChpdC0+c2Vjb25kLmF3YWl0aW5nX2JvZHkpICsrY291bnQ7CiAgcmV0dXJuIGNv
dW50Owp9CgpzdGF0aWMgYm9vbCBoYW5kbGVfcGFja2V0KGNvbnN0IHVuc2lnbmVkIGNoYXIgKmJ1
Ziwgc2l6ZV90IG4sIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlLCBjb25zdCBzdGQ6OnZlY3Rvcjx1
bnNpZ25lZD4gJnBvcnRzLAogICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6bWFwPEZsb3dL
ZXksIEZsb3c+ICZmbG93cywgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5n
PiA+ICZwZW5kaW5nKSB7CiAgKHZvaWQpcG9ydHM7CiAgaWYgKG4gPCAzNCkgcmV0dXJuIGZhbHNl
OwogIHNpemVfdCBvZmYgPSAxNDsKICB1bnNpZ25lZCBzaG9ydCBldCA9IG50b2hzKHJlYWRfdTE2
KGJ1ZiArIDEyKSk7CiAgaWYgKGV0ID09IEVUSF9QXzgwMjFRKSB7IGlmIChuIDwgMzgpIHJldHVy
biBmYWxzZTsgZXQgPSBudG9ocyhyZWFkX3UxNihidWYgKyAxNikpOyBvZmYgPSAxODsgfQogIGlm
IChldCAhPSBFVEhfUF9JUCB8fCBuIDwgb2ZmICsgMjApIHJldHVybiBmYWxzZTsKICB1bnNpZ25l
ZCBjaGFyIGlobCA9ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1KSAqIDQ7CiAgaWYgKChi
dWZbb2ZmXSA+PiA0KSAhPSA0IHx8IGJ1ZltvZmYgKyA5XSAhPSA2IHx8IG4gPCBvZmYgKyBpaGwg
KyAyMCkgcmV0dXJuIGZhbHNlOwoKICB1aW50MzJfdCBzX2lwID0gcmVhZF91MzIoYnVmICsgb2Zm
ICsgMTIpOwogIHVpbnQzMl90IGRfaXAgPSByZWFkX3UzMihidWYgKyBvZmYgKyAxNik7CiAgc2l6
ZV90IHRvID0gb2ZmICsgaWhsOwogIHVuc2lnbmVkIHNwb3J0ID0gbnRvaHMocmVhZF91MTYoYnVm
ICsgdG8pKTsKICB1bnNpZ25lZCBkcG9ydCA9IG50b2hzKHJlYWRfdTE2KGJ1ZiArIHRvICsgMikp
OwogIHVuc2lnbmVkIGRvZmYgPSAoYnVmW3RvICsgMTJdID4+IDQpICogNDsKICBpZiAobiA8IHRv
ICsgZG9mZikgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNoYXIgKnBheWxvYWQgPSAoY29uc3QgY2hh
ciAqKShidWYgKyB0byArIGRvZmYpOwogIHNpemVfdCBwbGVuID0gbiAtIHRvIC0gZG9mZjsKICBp
ZiAoIXBsZW4pIHJldHVybiBmYWxzZTsKCiAgdGltZV90IG5vdyA9IHRpbWUoTlVMTCk7CiAgYm9v
bCBkc3RfbW9uID0gKGRwb3J0IDwgNjU1MzYpID8gZ19tb25pdG9yZWRfcG9ydHNbZHBvcnRdIDog
ZmFsc2U7CiAgYm9vbCBzcmNfbW9uID0gKHNwb3J0IDwgNjU1MzYpID8gZ19tb25pdG9yZWRfcG9y
dHNbc3BvcnRdIDogZmFsc2U7CgogIGlmIChzcmNfbW9uICYmICFkc3RfbW9uICYmIHBsZW4gPj0g
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
Ki8KICAgIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBleGlzdGluZyA9IGZsb3dz
LmZpbmQoZmspOwogICAgaWYgKGV4aXN0aW5nICE9IGZsb3dzLmVuZCgpICYmIGV4aXN0aW5nLT5z
ZWNvbmQuYXdhaXRpbmdfYm9keSAmJgogICAgICAgICFleGlzdGluZy0+c2Vjb25kLmV2ZW50LmJh
c2ljX3VzZXIuZW1wdHkoKSkgewogICAgICBxdWV1ZV9yZXF1ZXN0KGV4aXN0aW5nLT5zZWNvbmQu
ZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGluZyk7CiAgICB9CiAgICBmbG93
cy5lcmFzZShmayk7CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIGlmIChmbG93cy5maW5kKGZrKSA9
PSBmbG93cy5lbmQoKSAmJiBmbG93cy5zaXplKCkgPj0gTUFYX0ZMT1dTKSB7CiAgICBmbG93cy5l
cmFzZShmbG93cy5iZWdpbigpKTsKICB9CiAgRmxvdyAmZmwgPSBmbG93c1tma107IGZsLnRvdWNo
ZWQgPSBub3c7CiAgaWYgKGZsLmF3YWl0aW5nX2JvZHkpIHsKICAgIHN0ZDo6c3RyaW5nIG5leHRf
c2VnbWVudChwYXlsb2FkLCBwbGVuKTsKICAgIGlmICghZmwuZXZlbnQuYmFzaWNfdXNlci5lbXB0
eSgpICYmIGZpbmRfaHR0cF9zdGFydChuZXh0X3NlZ21lbnQpID09IDApIHsKICAgICAgRXZlbnQg
cHJldmlvdXMgPSBmbC5ldmVudDsKICAgICAgZmwgPSBGbG93KCk7CiAgICAgIGZsLnRvdWNoZWQg
PSBub3c7CiAgICAgIHF1ZXVlX3JlcXVlc3QocHJldmlvdXMsIHNfaXAsIHNwb3J0LCBkX2lwLCBk
cG9ydCwgcGVuZGluZyk7CiAgICB9IGVsc2UgewogICAgICBzaXplX3QgcmVtYWluaW5nID0gZmwu
Ym9keV9nb2FsID4gZmwuYnVmLnNpemUoKSA/IGZsLmJvZHlfZ29hbCAtIGZsLmJ1Zi5zaXplKCkg
OiAwOwogICAgICBpZiAocmVtYWluaW5nKSBmbC5idWYuYXBwZW5kKHBheWxvYWQsIHBsZW4gPCBy
ZW1haW5pbmcgPyBwbGVuIDogcmVtYWluaW5nKTsKICAgICAgc3RkOjpzdHJpbmcgdXNlcm5hbWUg
PSBleHRyYWN0X3dzc2VfdXNlcm5hbWUoZmwuYnVmKTsKICAgICAgaWYgKCF1c2VybmFtZS5lbXB0
eSgpIHx8IGZsLmJ1Zi5zaXplKCkgPj0gZmwuYm9keV9nb2FsKSB7CiAgICAgICAgRXZlbnQgZXZl
bnQgPSBmbC5ldmVudDsKICAgICAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkpIHsKICAgICAgICAg
IGV2ZW50Lndzc2VfdXNlciA9IHVzZXJuYW1lOyBldmVudC51c2VyID0gdXNlcm5hbWU7IGV2ZW50
LnNjaGVtZSA9ICJ3c3NlIjsKICAgICAgICB9CiAgICAgICAgZmxvd3MuZXJhc2UoZmspOwogICAg
ICAgIHF1ZXVlX3JlcXVlc3QoZXZlbnQsIHNfaXAsIHNwb3J0LCBkX2lwLCBkcG9ydCwgcGVuZGlu
Zyk7CiAgICAgIH0KICAgICAgcmV0dXJuIHRydWU7CiAgICB9CiAgfQogIGZsLmJ1Zi5hcHBlbmQo
cGF5bG9hZCwgcGxlbik7CiAgaWYgKGZsLmJ1Zi5zaXplKCkgPiBNQVhfSEVBREVSKSB7IGZsb3dz
LmVyYXNlKGZrKTsgcmV0dXJuIGZhbHNlOyB9CiAgd2hpbGUgKHRydWUpIHsKICAgIHNpemVfdCBz
dGFydCA9IGZpbmRfaHR0cF9zdGFydChmbC5idWYpOwogICAgaWYgKHN0YXJ0ID09IHN0ZDo6c3Ry
aW5nOjpucG9zKSB7IGZsLmJ1Zi5jbGVhcigpOyBicmVhazsgfQogICAgaWYgKHN0YXJ0ID4gMCkg
ZmwuYnVmLmVyYXNlKDAsIHN0YXJ0KTsKICAgIHNpemVfdCBlbmQgPSBmbC5idWYuZmluZCgiXHJc
blxyXG4iKTsKICAgIGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgRXZl
bnQgZTsgUmVxdWVzdE1ldGEgbWV0YTsgZS50cyA9IG5vdzsgZS5ob3N0ID0gbm9kZTsgZS5zZXJ2
aWNlID0gInBvcnQ6IiArIG51bShkcG9ydCk7IGUuY2FsbGVyID0gaXBfdG9fc3RyKHNfaXApOyBl
LmNhbGxlcl9wb3J0ID0gc3BvcnQ7IGUuZHN0X2lwID0gaXBfdG9fc3RyKGRfaXApOyBlLmRzdF9w
b3J0ID0gZHBvcnQ7IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKShlbmQgKyA0KTsKICAgIGlmICgh
cGFyc2VfcmVxdWVzdChmbC5idWYuZGF0YSgpLCBlbmQsICZlLCAmbWV0YSkpIHsgZmwuYnVmLmVy
YXNlKDAsIGVuZCArIDQpOyBjb250aW51ZTsgfQogICAgZmwuYnVmLmVyYXNlKDAsIGVuZCArIDQp
OwogICAgaWYgKGdfd3NzZV9ib2R5X2J5dGVzICYmCiAgICAgICAgaXNfc29hcF9jb250ZW50X3R5
cGUobWV0YS5jb250ZW50X3R5cGUpICYmIG1ldGEuaGFzX2NvbnRlbnRfbGVuZ3RoICYmCiAgICAg
ICAgbWV0YS5jb250ZW50X2xlbmd0aCA+IDAgJiYKICAgICAgICBsb3dlcihtZXRhLnRyYW5zZmVy
X2VuY29kaW5nKS5maW5kKCJjaHVua2VkIikgPT0gc3RkOjpzdHJpbmc6Om5wb3MgJiYKICAgICAg
ICBhY3RpdmVfd3NzZV9mbG93cyhmbG93cykgPCBNQVhfV1NTRV9CT0RZX0ZMT1dTKSB7CiAgICAg
IGZsLmV2ZW50ID0gZTsKICAgICAgZmwuYXdhaXRpbmdfYm9keSA9IHRydWU7CiAgICAgIGZsLmJv
ZHlfZ29hbCA9IG1ldGEuY29udGVudF9sZW5ndGggPCBnX3dzc2VfYm9keV9ieXRlcyA/IG1ldGEu
Y29udGVudF9sZW5ndGggOiBnX3dzc2VfYm9keV9ieXRlczsKICAgICAgaWYgKGZsLmJvZHlfZ29h
bCA+IE1BWF9XU1NFX0JPRFlfQllURVMpIGZsLmJvZHlfZ29hbCA9IE1BWF9XU1NFX0JPRFlfQllU
RVM7CiAgICAgIGlmIChmbC5idWYuc2l6ZSgpID4gZmwuYm9keV9nb2FsKSBmbC5idWYucmVzaXpl
KGZsLmJvZHlfZ29hbCk7CiAgICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0gZXh0cmFjdF93c3Nl
X3VzZXJuYW1lKGZsLmJ1Zik7CiAgICAgIGlmICghdXNlcm5hbWUuZW1wdHkoKSB8fCBmbC5idWYu
c2l6ZSgpID49IGZsLmJvZHlfZ29hbCkgewogICAgICAgIEV2ZW50IGV2ZW50ID0gZmwuZXZlbnQ7
CiAgICAgICAgaWYgKCF1c2VybmFtZS5lbXB0eSgpKSB7CiAgICAgICAgICBldmVudC53c3NlX3Vz
ZXIgPSB1c2VybmFtZTsgZXZlbnQudXNlciA9IHVzZXJuYW1lOyBldmVudC5zY2hlbWUgPSAid3Nz
ZSI7CiAgICAgICAgfQogICAgICAgIGZsb3dzLmVyYXNlKGZrKTsKICAgICAgICBxdWV1ZV9yZXF1
ZXN0KGV2ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcpOwogICAgICB9CiAg
ICAgIHJldHVybiB0cnVlOwogICAgfQogICAgcXVldWVfcmVxdWVzdChlLCBzX2lwLCBzcG9ydCwg
ZF9pcCwgZHBvcnQsIHBlbmRpbmcpOwogIH0KICBpZiAoZmwuYnVmLmVtcHR5KCkpIHsKICAgIGZs
b3dzLmVyYXNlKGZrKTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIGF0dGFjaF9i
cGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgaWYgKHBv
cnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OnZlY3RvcjxzdHJ1Y3Qgc29ja19maWx0
ZXI+IGY7IHNpemVfdCBpOwogIC8qIER1YWwtcGF0aCBjQlBGOiBQYXRoIEEgKHN0YW5kYXJkIElQ
djQpIGFuZCBQYXRoIEIgKDgwMi4xUSBWTEFOIHRhZ2dlZCBJUHY0KS4gKi8KICB1bnNpZ25lZCBO
ID0gKHVuc2lnbmVkKXBvcnRzLnNpemUoKTsKICB1bnNpZ25lZCByZWplY3QgPSAxMSArIE4gKiA4
OwogIHVuc2lnbmVkIGFjY2VwdCA9IHJlamVjdCArIDE7CiAgc3RydWN0IHNvY2tfZmlsdGVyIHg7
CiNkZWZpbmUgQUREKEMsSixULEspIGRvIHsgXAogIHVuc2lnbmVkIF9qdCA9ICh1bnNpZ25lZCko
SiksIF9qZiA9ICh1bnNpZ25lZCkoVCk7IFwKICBpZiAoX2p0ID4gVUNIQVJfTUFYIHx8IF9qZiA+
IFVDSEFSX01BWCkgcmV0dXJuIGZhbHNlOyBcCiAgeC5jb2RlPShDKTsgeC5qdD0odW5zaWduZWQg
Y2hhcilfanQ7IHguamY9KHVuc2lnbmVkIGNoYXIpX2pmOyB4Lms9KEspOyBcCiAgZi5wdXNoX2Jh
Y2soeCk7IFwKfSB3aGlsZSgwKQogIC8qIFswXSBMb2FkIEV0aGVyVHlwZSBhdCBvZmZzZXQgMTIg
Ki8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAsIDEyKTsKICAvKiBbMV0gSWYgc3Rh
bmRhcmQgSVB2NCAoMHgwODAwKSwganVtcCBvdmVyIFBhdGggQiAoNiArIDQqTiBpbnN0cnVjdGlv
bnMpIHRvIFBhdGggQSAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssICh1bnNpZ25lZCko
NiArIDQgKiBOKSwgMCwgRVRIX1BfSVBfSE9TVCk7CgogIC8qIC0tLSBQYXRoIEI6IDgwMi4xUSBW
TEFOIChpbmRleCAyKSAtLS0gKi8KICAvKiBbMl0gSWYgbm90IDgwMi4xUSAoMHg4MTAwKSwgcmVq
ZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3Qg
LSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRIX1BfODAyMVFfSE9TVCk7CiAgLyogWzNdIExv
YWQgZW5jYXBzdWxhdGVkIEV0aGVyVHlwZSBhdCBvZmZzZXQgMTYgKi8KICBBREQoQlBGX0xEfEJQ
Rl9IfEJQRl9BQlMsIDAsIDAsIDE2KTsKICAvKiBbNF0gSWYgZW5jYXBzdWxhdGVkICE9IElQdjQs
IHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVq
ZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVUSF9QX0lQX0hPU1QpOwogIC8qIFs1XSBM
b2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyNyAoMjMgKyA0KSAqLwogIEFERChCUEZfTER8QlBG
X0J8QlBGX0FCUywgMCwgMCwgMjcpOwogIC8qIFs2XSBJZiBub3QgVENQLCByZWplY3QgKi8KICBB
REQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25l
ZClmLnNpemUoKSAtIDEpLCBJUFBST1RPX1RDUCk7CiAgLyogWzddIExvYWQgSUhMIGF0IG9mZnNl
dCAxOCAoMTQgKyA0KSAqLwogIEFERChCUEZfTERYfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE4KTsK
ICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNrcyBmb3IgVkxBTiAqLwogIGZvciAoaSA9IDA7IGkg
PCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAw
LCAyMCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7
CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICAv
KiBTb3VyY2UgcG9ydCBjaGVja3MgZm9yIFZMQU4gKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMu
c2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTgpOwog
ICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5z
aWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWdu
ZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwg
cG9ydHNbaV0pOwogIH0KCiAgLyogLS0tIFBhdGggQTogU3RhbmRhcmQgSVB2NCAtLS0gKi8KICAv
KiBMb2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyMyAqLwogIEFERChCUEZfTER8QlBGX0J8QlBG
X0FCUywgMCwgMCwgMjMpOwogIC8qIElmIG5vdCBUQ1AsIHJlamVjdCAqLwogIEFERChCUEZfSk1Q
fEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgp
IC0gMSksIElQUFJPVE9fVENQKTsKICAvKiBMb2FkIElITCBhdCBvZmZzZXQgMTQgKi8KICBBREQo
QlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxNCk7CiAgLyogRGVzdGluYXRpb24gcG9ydCBj
aGVja3MgZm9yIHN0YW5kYXJkIElQdjQgKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgp
OyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTYpOwogICAgdW5z
aWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgQUREKEJQRl9K
TVB8QlBGX0pFUXxCUEZfSywganQsIDAsIHBvcnRzW2ldKTsKICB9CiAgLyogU291cmNlIHBvcnQg
Y2hlY2tzIGZvciBzdGFuZGFyZCBJUHY0ICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUo
KTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE0KTsKICAgIHVu
c2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVk
IGpmID0gKGkgPCBwb3J0cy5zaXplKCkgLSAxKSA/IDAgOiAocmVqZWN0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMSk7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgamYsIHBvcnRz
W2ldKTsKICB9CgogIC8qIFtyZWplY3RdIERyb3AgcGFja2V0ICovCiAgQUREKEJQRl9SRVR8QlBG
X0ssIDAsIDAsIDApOwogIC8qIFthY2NlcHRdIEFjY2VwdCBwYWNrZXQgKDIwNDggYnl0ZXMpICov
CiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIEFDQ0VQVCk7CiN1bmRlZiBBREQKICBpZiAoZi5z
aXplKCkgPiA0MDk2KSByZXR1cm4gZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJvZzsgcHJv
Zy5sZW4gPSAodW5zaWduZWQgc2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07CiNp
Zm5kZWYgU09fQVRUQUNIX0ZJTFRFUgojZGVmaW5lIFNPX0FUVEFDSF9GSUxURVIgMjYKI2VuZGlm
CiAgcmV0dXJuIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX0FUVEFDSF9GSUxURVIsICZw
cm9nLCBzaXplb2YocHJvZykpID09IDA7Cn0KCnN0cnVjdCBNbWFwUmluZyB7CiAgdm9pZCAqcmlu
ZzsKICBzaXplX3QgcmluZ19zaXplOwogIHVuc2lnbmVkIGJsb2NrX3NpemU7CiAgdW5zaWduZWQg
YmxvY2tfbnI7CiAgdW5zaWduZWQgZnJhbWVfc2l6ZTsKICB1bnNpZ25lZCBmcmFtZV9ucjsKICB1
bnNpZ25lZCBmcmFtZXNfcGVyX2Jsb2NrOwogIHVuc2lnbmVkIGZyYW1lX2lkeDsKCiAgTW1hcFJp
bmcoKSA6IHJpbmcoTUFQX0ZBSUxFRCksIHJpbmdfc2l6ZSgwKSwgYmxvY2tfc2l6ZSg2NTUzNiks
IGJsb2NrX25yKDY0KSwKICAgICAgICAgICAgICAgZnJhbWVfc2l6ZSgyMDQ4KSwgZnJhbWVfbnIo
MjA0OCksIGZyYW1lc19wZXJfYmxvY2soMzIpLCBmcmFtZV9pZHgoMCkge30KfTsKCnN0YXRpYyBi
b29sIHZhbGlkX3JpbmdfZ2VvbWV0cnkoY29uc3QgTW1hcFJpbmcgJm1yKSB7CiAgY29uc3Qgc2l6
ZV90IHNpemVfbWF4ID0gKHNpemVfdCktMTsKICBsb25nIHBhZ2Vfc2l6ZSA9IHN5c2NvbmYoX1ND
X1BBR0VTSVpFKTsKICBpZiAocGFnZV9zaXplIDw9IDApIHJldHVybiBmYWxzZTsKICBpZiAobXIu
YmxvY2tfc2l6ZSA9PSAwIHx8IG1yLmJsb2NrX3NpemUgJSAodW5zaWduZWQgbG9uZylwYWdlX3Np
emUgIT0gMCkgcmV0dXJuIGZhbHNlOwogIGlmIChtci5mcmFtZV9zaXplIDwgVFBBQ0tFVDJfSERS
TEVOIHx8CiAgICAgIG1yLmZyYW1lX3NpemUgJSBUUEFDS0VUX0FMSUdOTUVOVCAhPSAwKSByZXR1
cm4gZmFsc2U7CiAgaWYgKG1yLmJsb2NrX3NpemUgJSBtci5mcmFtZV9zaXplICE9IDApIHJldHVy
biBmYWxzZTsKICB1bnNpZ25lZCBmcmFtZXNfcGVyX2Jsb2NrID0gbXIuYmxvY2tfc2l6ZSAvIG1y
LmZyYW1lX3NpemU7CiAgaWYgKGZyYW1lc19wZXJfYmxvY2sgPT0gMCB8fCBtci5ibG9ja19uciA9
PSAwKSByZXR1cm4gZmFsc2U7CiAgaWYgKGZyYW1lc19wZXJfYmxvY2sgPiBVSU5UX01BWCAvIG1y
LmJsb2NrX25yKSByZXR1cm4gZmFsc2U7CiAgaWYgKGZyYW1lc19wZXJfYmxvY2sgKiBtci5ibG9j
a19uciAhPSBtci5mcmFtZV9ucikgcmV0dXJuIGZhbHNlOwogIGlmICgoc2l6ZV90KW1yLmJsb2Nr
X3NpemUgPiBzaXplX21heCAvIChzaXplX3QpbXIuYmxvY2tfbnIpIHJldHVybiBmYWxzZTsKICBp
ZiAoKHNpemVfdCltci5ibG9ja19zaXplICogKHNpemVfdCltci5ibG9ja19uciAhPSA0VSAqIDEw
MjRVICogMTAyNFUpIHJldHVybiBmYWxzZTsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wg
c2V0dXBfbW1hcF9yaW5nKGludCBmZCwgTW1hcFJpbmcgJm1yKSB7CiAgaWYgKCF2YWxpZF9yaW5n
X2dlb21ldHJ5KG1yKSkgewogICAgbG9nbXNnKCJpbnZhbGlkIGZpeGVkIFRQQUNLRVRfVjIgcmlu
ZyBnZW9tZXRyeSIpOwogICAgcmV0dXJuIGZhbHNlOwogIH0KICBpbnQgdmVyID0gVFBBQ0tFVF9W
MjsKICBpZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tFVCwgUEFDS0VUX1ZFUlNJT04sICZ2ZXIs
IHNpemVvZih2ZXIpKSA8IDApIHsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgc3RydWN0IHRwYWNr
ZXRfcmVxIHJlcTsKICBtZW1zZXQoJnJlcSwgMCwgc2l6ZW9mKHJlcSkpOwogIHJlcS50cF9ibG9j
a19zaXplID0gbXIuYmxvY2tfc2l6ZTsKICByZXEudHBfYmxvY2tfbnIgPSBtci5ibG9ja19ucjsK
ICByZXEudHBfZnJhbWVfc2l6ZSA9IG1yLmZyYW1lX3NpemU7CiAgcmVxLnRwX2ZyYW1lX25yID0g
bXIuZnJhbWVfbnI7CgogIGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfUlhf
UklORywgJnJlcSwgc2l6ZW9mKHJlcSkpIDwgMCkgewogICAgcmV0dXJuIGZhbHNlOwogIH0KICBt
ci5yaW5nX3NpemUgPSAoc2l6ZV90KXJlcS50cF9ibG9ja19zaXplICogKHNpemVfdClyZXEudHBf
YmxvY2tfbnI7CiAgbXIuZnJhbWVzX3Blcl9ibG9jayA9IHJlcS50cF9ibG9ja19zaXplIC8gcmVx
LnRwX2ZyYW1lX3NpemU7CiAgbXIuZnJhbWVfaWR4ID0gMDsKCiAgbXIucmluZyA9IG1tYXAoTlVM
TCwgbXIucmluZ19zaXplLCBQUk9UX1JFQUQgfCBQUk9UX1dSSVRFLCBNQVBfU0hBUkVELCBmZCwg
MCk7CiAgaWYgKG1yLnJpbmcgPT0gTUFQX0ZBSUxFRCkgewogICAgbXIucmluZ19zaXplID0gMDsK
ICAgIHJldHVybiBmYWxzZTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHJlbGVh
c2VfbW1hcF9yaW5nKGludCBmZCwgTW1hcFJpbmcgJm1yKSB7CiAgYm9vbCBvayA9IHRydWU7CiAg
aWYgKG1yLnJpbmcgIT0gTUFQX0ZBSUxFRCkgewogICAgaWYgKG11bm1hcChtci5yaW5nLCBtci5y
aW5nX3NpemUpICE9IDApIG9rID0gZmFsc2U7CiAgICBtci5yaW5nID0gTUFQX0ZBSUxFRDsKICB9
CiAgc3RydWN0IHRwYWNrZXRfcmVxIGVtcHR5X3JlcTsKICBtZW1zZXQoJmVtcHR5X3JlcSwgMCwg
c2l6ZW9mKGVtcHR5X3JlcSkpOwogIGlmIChzZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNL
RVRfUlhfUklORywKICAgICAgICAgICAgICAgICAmZW1wdHlfcmVxLCBzaXplb2YoZW1wdHlfcmVx
KSkgIT0gMCkgb2sgPSBmYWxzZTsKICBtci5yaW5nX3NpemUgPSAwOwogIHJldHVybiBvazsKfQoK
c3RhdGljIGJvb2wgdmFsaWRfcmluZ19mcmFtZShjb25zdCBzdHJ1Y3QgdHBhY2tldDJfaGRyICpo
ZHIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdW5zaWduZWQgZnJhbWVfc2l6ZSwKICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3QgKnBhY2tldF9vZmZzZXQsCiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgc2l6ZV90ICpwYWNrZXRfbGVuZ3RoKSB7CiAgY29uc3QgdW5z
aWduZWQgbWFjID0gaGRyLT50cF9tYWM7CiAgY29uc3QgdW5zaWduZWQgbmV0ID0gaGRyLT50cF9u
ZXQ7CiAgY29uc3QgdW5zaWduZWQgc25hcGxlbiA9IGhkci0+dHBfc25hcGxlbjsKICBjb25zdCB1
bnNpZ25lZCB3aXJlX2xlbiA9IGhkci0+dHBfbGVuOwogIGlmIChtYWMgPCBUUEFDS0VUMl9IRFJM
RU4gfHwgbWFjID4gZnJhbWVfc2l6ZSkgcmV0dXJuIGZhbHNlOwogIGlmIChzbmFwbGVuID4gd2ly
ZV9sZW4gfHwgc25hcGxlbiA+IGZyYW1lX3NpemUgLSBtYWMpIHJldHVybiBmYWxzZTsKICBpZiAo
bmV0IDwgbWFjIHx8IG5ldCA+IG1hYyArIHNuYXBsZW4pIHJldHVybiBmYWxzZTsKICAqcGFja2V0
X29mZnNldCA9IG1hYzsKICAqcGFja2V0X2xlbmd0aCA9IHNuYXBsZW47CiAgcmV0dXJuIHRydWU7
Cn0KCnN0YXRpYyBpbnQgcnVuX3JpbmdfZml4dHVyZSgpIHsKICBNbWFwUmluZyBtcjsKICBpZiAo
IXZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSByZXR1cm4gMjA7CiAgdW5zaWduZWQgY2hhciBmcmFt
ZVsyMDQ4XTsKICBtZW1zZXQoZnJhbWUsIDAsIHNpemVvZihmcmFtZSkpOwogIHN0cnVjdCB0cGFj
a2V0Ml9oZHIgKmhkciA9IChzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWU7CiAgc2l6ZV90IG9m
ZiA9IDAsIGxlbiA9IDA7CiAgaGRyLT50cF9tYWMgPSBUUEFDS0VUMl9IRFJMRU47CiAgaGRyLT50
cF9uZXQgPSBUUEFDS0VUMl9IRFJMRU4gKyAxNDsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjg7CiAg
aGRyLT50cF9sZW4gPSAxMjg7CiAgaWYgKCF2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZy
YW1lKSwgJm9mZiwgJmxlbikgfHwKICAgICAgb2ZmICE9IFRQQUNLRVQyX0hEUkxFTiB8fCBsZW4g
IT0gMTI4KSByZXR1cm4gMjE7CiAgaGRyLT50cF9tYWMgPSBUUEFDS0VUMl9IRFJMRU4gLSAxOwog
IGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikpIHJl
dHVybiAyMjsKICBoZHItPnRwX21hYyA9IFRQQUNLRVQyX0hEUkxFTjsKICBoZHItPnRwX3NuYXBs
ZW4gPSBzaXplb2YoZnJhbWUpOwogIGhkci0+dHBfbGVuID0gc2l6ZW9mKGZyYW1lKTsKICBpZiAo
dmFsaWRfcmluZ19mcmFtZShoZHIsIHNpemVvZihmcmFtZSksICZvZmYsICZsZW4pKSByZXR1cm4g
MjM7CiAgaGRyLT50cF9zbmFwbGVuID0gMTI5OwogIGhkci0+dHBfbGVuID0gMTI4OwogIGlmICh2
YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikpIHJldHVybiAy
NDsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjg7CiAgaGRyLT50cF9sZW4gPSAxMjg7CiAgaGRyLT50
cF9uZXQgPSBUUEFDS0VUMl9IRFJMRU4gLSAxOwogIGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwg
c2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikpIHJldHVybiAyNTsKICBtci5mcmFtZV9ucisrOwog
IGlmICh2YWxpZF9yaW5nX2dlb21ldHJ5KG1yKSkgcmV0dXJuIDI2OwogIHJldHVybiAwOwp9Cgpz
dGF0aWMgaW50IHJ1bl9maXh0dXJlKCkgewogIHN0ZDo6c3RyaW5nIHJlcSA9ICJHRVQgL2FwaS9p
dGVtcz94PTEgSFRUUC8xLjFcclxuSG9zdDogYXBpLmxvY2FsXHJcbkF1dGhvcml6YXRpb246IEJh
c2ljIFlXeHBZMlU2YzJWamNtVjBcclxuVHJhY2VwYXJlbnQ6IDAwLTAxMjM0NTY3ODlhYmNkZWYw
MTIzNDU2Nzg5YWJjZGVmLTAxMjM0NTY3ODlhYmNkZWYtMDFcclxuXHJcbiI7CiAgRXZlbnQgZTsg
UmVxdWVzdE1ldGEgbWV0YTsgZS50cyA9IDE3MDAwMDAwMDA7IGUuaG9zdCA9ICJjcHAtbm9kZSI7
IGUuc2VydmljZSA9ICJwb3J0OjgwODAiOyBlLmNhbGxlciA9ICIxMC4wLjAuOSI7IGUuY2FsbGVy
X3BvcnQgPSA1MTAwMDsgZS5kc3RfaXAgPSAiMTAuMC4wLjIiOyBlLmRzdF9wb3J0ID0gODA4MDsg
ZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQpcmVxLnNpemUoKTsgcGFyc2VfcmVxdWVzdChyZXEuZGF0
YSgpLCByZXEuc2l6ZSgpIC0gNCwgJmUsICZtZXRhKTsgZS5zdGF0dXMgPSAyMDA7IGUuaGFzX3N0
YXR1cyA9IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlvbiA9IHRydWU7IGUu
cmVzcF9ieXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVudChlKTsgcmV0dXJu
IDA7Cn0KCnN0YXRpYyBpbnQgcnVuX3dzc2VfZml4dHVyZSgpIHsKICBjb25zdCBjaGFyICpuYW1l
c3BhY2VzW10gPSB7CiAgICAiaHR0cDovL2RvY3Mub2FzaXMtb3Blbi5vcmcvd3NzLzIwMDQvMDEv
b2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNkIiwKICAgICJodHRwOi8v
c2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3L3NlY2V4dCIsCiAgICAiaHR0cDovL3NjaGVt
YXMueG1sc29hcC5vcmcvd3MvMjAwMi8xMi9zZWNleHQiLAogICAgImh0dHA6Ly9zY2hlbWFzLnht
bHNvYXAub3JnL3dzLzIwMDMvMDYvc2VjZXh0IgogIH07CiAgZm9yIChzaXplX3QgaSA9IDA7IGkg
PCA0OyArK2kpIHsKICAgIHN0ZDo6c3RyaW5nIGJvZHkgPSAiPHM6RW52ZWxvcGUgeG1sbnM6cz0n
dXJuOnNvYXAnIHhtbG5zOnc9JyIgKyBzdGQ6OnN0cmluZyhuYW1lc3BhY2VzW2ldKSArCiAgICAg
ICInPjxzOkhlYWRlcj48dzpVc2VybmFtZVRva2VuPjx3OlVzZXJuYW1lPm5hdGl2ZS5maXh0dXJl
PC93OlVzZXJuYW1lPiIKICAgICAgIjx3OlBhc3N3b3JkPlNFTlNJVElWRV9QQVNTV09SRDwvdzpQ
YXNzd29yZD48L3c6VXNlcm5hbWVUb2tlbj48L3M6SGVhZGVyPiI7CiAgICBzdGQ6OnN0cmluZyB1
c2VyID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGJvZHkpOwogICAgaWYgKHVzZXIgIT0gIm5hdGl2
ZS5maXh0dXJlIikgcmV0dXJuIDM7CiAgICBzdGQ6OmNvdXQgPDwgdXNlciA8PCAiXG4iOwogIH0K
ICBzdGQ6OnN0cmluZyBtYWxpY2lvdXMgPSAiPCFET0NUWVBFIHggWzwhRU5USVRZIHB3ICdzZWNy
ZXQnPl0+PHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSciICsKICAgIHN0ZDo6c3RyaW5nKG5hbWVz
cGFjZXNbMF0pICsgIic+PHc6VXNlcm5hbWU+JnB3OzwvdzpVc2VybmFtZT48L3c6VXNlcm5hbWVU
b2tlbj4iOwogIGlmICghZXh0cmFjdF93c3NlX3VzZXJuYW1lKG1hbGljaW91cykuZW1wdHkoKSkg
cmV0dXJuIDQ7CiAgc3RkOjpzdHJpbmcgd3JvbmdfbnMgPSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxu
czp3PSd1cm46bm90LXdzc2UnPjx3OlVzZXJuYW1lPndyb25nPC93OlVzZXJuYW1lPjwvdzpVc2Vy
bmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5hbWUod3JvbmdfbnMpLmVtcHR5
KCkpIHJldHVybiA1OwogIHN0ZDo6c3RyaW5nIHVubmFtZXNwYWNlZCA9ICI8VXNlcm5hbWVUb2tl
bj48VXNlcm5hbWU+d3Jvbmc8L1VzZXJuYW1lPjwvVXNlcm5hbWVUb2tlbj4iOwogIGlmICghZXh0
cmFjdF93c3NlX3VzZXJuYW1lKHVubmFtZXNwYWNlZCkuZW1wdHkoKSkgcmV0dXJuIDY7CiAgc3Rk
OjpzdHJpbmcgZXNjYXBlZCA9ICI8dzpVc2VybmFtZVRva2VuIHhtbG5zOnc9JyIgKyBzdGQ6OnN0
cmluZyhuYW1lc3BhY2VzWzBdKSArCiAgICAiJz48dzpVc2VybmFtZT5uYXRpdmUmYW1wO2ZpeHR1
cmU8L3c6VXNlcm5hbWU+IjsKICBpZiAoZXh0cmFjdF93c3NlX3VzZXJuYW1lKGVzY2FwZWQpICE9
ICJuYXRpdmUmZml4dHVyZSIpIHJldHVybiA3OwogIHN0ZDo6c3RyaW5nIHRvb19sb25nID0gIjx3
OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0nIiArIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbMF0pICsK
ICAgICInPjx3OlVzZXJuYW1lPiIgKyBzdGQ6OnN0cmluZyhNQVhfV1NTRV9VU0VSTkFNRSArIDEs
ICd4JykgKyAiPC93OlVzZXJuYW1lPiI7CiAgaWYgKCFleHRyYWN0X3dzc2VfdXNlcm5hbWUodG9v
X2xvbmcpLmVtcHR5KCkpIHJldHVybiA4OwogIHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1bl9k
dWFsX2F1dGhfZml4dHVyZSgpIHsKICBjb25zdCBzdGQ6OnN0cmluZyBib2R5ID0KICAgICI8czpF
bnZlbG9wZSB4bWxuczpzPSd1cm46c29hcCcgeG1sbnM6dz0naHR0cDovL2RvY3Mub2FzaXMtb3Bl
bi5vcmcvd3NzLzIwMDQvMDEvIgogICAgIm9hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS1zZWNl
eHQtMS4wLnhzZCc+PHM6SGVhZGVyPjx3OlVzZXJuYW1lVG9rZW4+IgogICAgIjx3OlVzZXJuYW1l
PnNvYXAudXNlcjwvdzpVc2VybmFtZT48dzpQYXNzd29yZD5TRU5TSVRJVkVfUEFTU1dPUkQ8L3c6
UGFzc3dvcmQ+IgogICAgIjwvdzpVc2VybmFtZVRva2VuPjwvczpIZWFkZXI+PC9zOkVudmVsb3Bl
PiI7CiAgc3RkOjpvc3RyaW5nc3RyZWFtIHJlcXVlc3Q7CiAgcmVxdWVzdCA8PCAiUE9TVCAvc29h
cCBIVFRQLzEuMVxyXG5Ib3N0OiBmaXh0dXJlXHJcbiIKICAgICAgICAgIDw8ICJBdXRob3JpemF0
aW9uOiBCYXNpYyBZbUZ6YVdNdWRYTmxjanB3WVhOemQyOXlaQT09XHJcbiIKICAgICAgICAgIDw8
ICJDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3NvYXAreG1sXHJcbkNvbnRlbnQtTGVuZ3RoOiAi
CiAgICAgICAgICA8PCBib2R5LnNpemUoKSA8PCAiXHJcblxyXG4iIDw8IGJvZHk7CiAgY29uc3Qg
c3RkOjpzdHJpbmcgcGF5bG9hZCA9IHJlcXVlc3Quc3RyKCk7CgogIHN0ZDo6dmVjdG9yPHVuc2ln
bmVkIGNoYXI+IHBhY2tldCgxNCArIDIwICsgMjAgKyBwYXlsb2FkLnNpemUoKSwgMCk7CiAgcGFj
a2V0WzEyXSA9IDB4MDg7IHBhY2tldFsxM10gPSAweDAwOwogIHBhY2tldFsxNF0gPSAweDQ1OyBw
YWNrZXRbMjNdID0gSVBQUk9UT19UQ1A7CiAgcGFja2V0WzI2XSA9IDE5MjsgcGFja2V0WzI3XSA9
IDA7IHBhY2tldFsyOF0gPSAyOyBwYWNrZXRbMjldID0gMjsKICBwYWNrZXRbMzBdID0gMTkyOyBw
YWNrZXRbMzFdID0gMDsgcGFja2V0WzMyXSA9IDI7IHBhY2tldFszM10gPSAxOwogIHVuc2lnbmVk
IHNob3J0IHNwb3J0ID0gaHRvbnMoNTEwMDApLCBkcG9ydCA9IGh0b25zKDgwODApOwogIG1lbWNw
eSgmcGFja2V0WzM0XSwgJnNwb3J0LCBzaXplb2Yoc3BvcnQpKTsKICBtZW1jcHkoJnBhY2tldFsz
Nl0sICZkcG9ydCwgc2l6ZW9mKGRwb3J0KSk7CiAgcGFja2V0WzQ2XSA9IDVVIDw8IDQ7IHBhY2tl
dFs0N10gPSAweDE4OwogIG1lbWNweSgmcGFja2V0WzU0XSwgcGF5bG9hZC5kYXRhKCksIHBheWxv
YWQuc2l6ZSgpKTsKCiAgZ193c3NlX2JvZHlfYnl0ZXMgPSA4MTkyOwogIG1lbXNldChnX21vbml0
b3JlZF9wb3J0cywgMCwgc2l6ZW9mKGdfbW9uaXRvcmVkX3BvcnRzKSk7CiAgZ19tb25pdG9yZWRf
cG9ydHNbODA4MF0gPSB0cnVlOwogIGdfZW5kcG9pbnQuY2xlYXIoKTsKICBpbml0X3JuZygpOwog
IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0cygxLCA4MDgwKTsKICBzdGQ6Om1hcDxGbG93S2V5
LCBGbG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+
ID4gcGVuZGluZzsKICBpZiAoIWhhbmRsZV9wYWNrZXQoJnBhY2tldFswXSwgcGFja2V0LnNpemUo
KSwgImNwcC1kdWFsLWZpeHR1cmUiLAogICAgICAgICAgICAgICAgICAgICBwb3J0cywgZmxvd3Ms
IHBlbmRpbmcpKSByZXR1cm4gOTsKICBpZiAoIWZsb3dzLmVtcHR5KCkgfHwgcGVuZGluZy5zaXpl
KCkgIT0gMSkgcmV0dXJuIDEwOwogIGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwogIHJldHVy
biAwOwp9CgpzdGF0aWMgYm9vbCBwYXJzZV93c3NlX3NpemUoY29uc3QgY2hhciAqdmFsdWUsIHNp
emVfdCAqcmVzdWx0KSB7CiAgaWYgKCF2YWx1ZSB8fCAhKnZhbHVlKSByZXR1cm4gZmFsc2U7CiAg
c2l6ZV90IG4gPSAwOwogIGlmICghcGFyc2VfZGVjaW1hbF9zaXplKHZhbHVlLCBzdHJsZW4odmFs
dWUpLCAmbikgfHwgbiA+IE1BWF9XU1NFX0JPRFlfQllURVMpIHJldHVybiBmYWxzZTsKICAqcmVz
dWx0ID0gbjsKICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgZHJvcF9hbGxfY2FwYWJpbGl0
aWVzKCkgewogIHN0cnVjdCBfX3VzZXJfY2FwX2hlYWRlcl9zdHJ1Y3QgaGVhZGVyOwogIHN0cnVj
dCBfX3VzZXJfY2FwX2RhdGFfc3RydWN0IGRhdGFbMl07CiAgbWVtc2V0KCZoZWFkZXIsIDAsIHNp
emVvZihoZWFkZXIpKTsKICBtZW1zZXQoZGF0YSwgMCwgc2l6ZW9mKGRhdGEpKTsKICBoZWFkZXIu
dmVyc2lvbiA9IF9MSU5VWF9DQVBBQklMSVRZX1ZFUlNJT05fMzsKICBoZWFkZXIucGlkID0gMDsK
ICByZXR1cm4gc3lzY2FsbChTWVNfY2Fwc2V0LCAmaGVhZGVyLCBkYXRhKSA9PSAwOwp9CgpzdGF0
aWMgaW50IG9wZW5fY2FwdHVyZV9zb2NrZXQoY29uc3Qgc3RkOjpzdHJpbmcgJmlmYWNlLAogICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+ICZw
b3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIE1tYXBSaW5nICZyaW5nKSB7CiAg
aW50IGZkID0gc29ja2V0KEFGX1BBQ0tFVCwgU09DS19SQVcsIGh0b25zKEVUSF9QX0FMTCkpOwog
IGlmIChmZCA8IDApIHsgcGVycm9yKCJBRl9QQUNLRVQiKTsgcmV0dXJuIC0xOyB9CiAgaW50IHJi
ID0gOCAqIDEwMjQgKiAxMDI0OwogIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NLRVQsIFNPX1JDVkJV
RiwgJnJiLCBzaXplb2YocmIpKTsKICBpZiAoIWF0dGFjaF9icGYoZmQsIHBvcnRzKSkgewogICAg
bG9nbXNnKCJCUEYgYXR0YWNoIGZhaWxlZDsgcmVmdXNpbmcgdW5maWx0ZXJlZCBjYXB0dXJlIik7
CiAgICBjbG9zZShmZCk7CiAgICByZXR1cm4gLTE7CiAgfQoKICBzdHJ1Y3Qgc29ja2FkZHJfbGwg
c2E7CiAgbWVtc2V0KCZzYSwgMCwgc2l6ZW9mKHNhKSk7CiAgc2Euc2xsX2ZhbWlseSA9IEFGX1BB
Q0tFVDsKICBzYS5zbGxfcHJvdG9jb2wgPSBodG9ucyhFVEhfUF9BTEwpOwogIGlmICghaWZhY2Uu
ZW1wdHkoKSkgewogICAgc2Euc2xsX2lmaW5kZXggPSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNl
LmNfc3RyKCkpOwogICAgaWYgKCFzYS5zbGxfaWZpbmRleCkgewogICAgICBsb2dtc2coImJhZCBp
bnRlcmZhY2UiKTsKICAgICAgY2xvc2UoZmQpOwogICAgICByZXR1cm4gLTE7CiAgICB9CiAgfQog
IGlmIChiaW5kKGZkLCAoc3RydWN0IHNvY2thZGRyICopJnNhLCBzaXplb2Yoc2EpKSA8IDApIHsK
ICAgIHBlcnJvcigiYmluZCIpOwogICAgY2xvc2UoZmQpOwogICAgcmV0dXJuIC0xOwogIH0KICBp
ZiAoIXNldHVwX21tYXBfcmluZyhmZCwgcmluZykpIHsKICAgIGxvZ21zZygiVFBBQ0tFVF9WMiBz
ZXR1cCBmYWlsZWQ7IHJlZnVzaW5nIG5vbi1yaW5nIGZhbGxiYWNrIik7CiAgICBjbG9zZShmZCk7
CiAgICByZXR1cm4gLTE7CiAgfQogIGlmICghZHJvcF9hbGxfY2FwYWJpbGl0aWVzKCkpIHsKICAg
IGxvZ21zZygiY2FwYWJpbGl0eSBkcm9wIGZhaWxlZDsgcmVmdXNpbmcgdW5zYWZlIGNhcHR1cmUi
KTsKICAgIHJlbGVhc2VfbW1hcF9yaW5nKGZkLCByaW5nKTsKICAgIGNsb3NlKGZkKTsKICAgIHJl
dHVybiAtMTsKICB9CiAgcmV0dXJuIGZkOwp9CgpzdGF0aWMgaW50IHJ1bl9jYXBhYmlsaXR5X3By
b2JlKGNvbnN0IHN0ZDo6c3RyaW5nICZpZmFjZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25lZD4gJnBvcnRzKSB7CiAgTW1hcFJpbmcgcmlu
ZzsKICBpbnQgZmQgPSBvcGVuX2NhcHR1cmVfc29ja2V0KGlmYWNlLCBwb3J0cywgcmluZyk7CiAg
aWYgKGZkIDwgMCkgcmV0dXJuIDI7CiAgYm9vbCByZWxlYXNlZCA9IHJlbGVhc2VfbW1hcF9yaW5n
KGZkLCByaW5nKTsKICBjbG9zZShmZCk7CiAgaWYgKCFyZWxlYXNlZCkgewogICAgbG9nbXNnKCJU
UEFDS0VUX1YyIHByb2JlIGNsZWFudXAgZmFpbGVkIik7CiAgICByZXR1cm4gMjsKICB9CiAgcmV0
dXJuIDA7Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikgewogIGlmIChhcmdjID4g
MSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9maXh0dXJlKCk7
CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsxXSwgIi0td3NzZS1maXh0dXJlIikpIHJl
dHVybiBydW5fd3NzZV9maXh0dXJlKCk7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJjbXAoYXJndlsx
XSwgIi0tZHVhbC1hdXRoLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9kdWFsX2F1dGhfZml4dHVyZSgp
OwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLXJpbmctZml4dHVyZSIpKSBy
ZXR1cm4gcnVuX3JpbmdfZml4dHVyZSgpOwogIGlmIChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3Zb
MV0sICItLXNoaXAtcmF0ZS1maXh0dXJlIikpIHJldHVybiBydW5fc2hpcF9yYXRlX2ZpeHR1cmUo
KTsKICBzdGQ6OnN0cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBvcnRzOyBpbnQg
aTsgaW50IHdvcmtlcnMgPSAxOwogIHN0ZDo6c3RyaW5nIGVuZHBvaW50OwogIGJvb2wgY2FwYWJp
bGl0eV9wcm9iZSA9IGZhbHNlOwogIGNvbnN0IGNoYXIgKndzc2VfZW52ID0gZ2V0ZW52KCJOVF9X
U1NFX0JPRFlfQllURVMiKTsKICBpZiAod3NzZV9lbnYgJiYgIXBhcnNlX3dzc2Vfc2l6ZSh3c3Nl
X2VudiwgJmdfd3NzZV9ib2R5X2J5dGVzKSkgewogICAgZnByaW50ZihzdGRlcnIsICJ3c3NlIGJv
ZHkgYnl0ZXMgbXVzdCBiZSBpbiByYW5nZSAwLi42NTUzNlxuIik7IHJldHVybiAyOwogIH0KICBj
b25zdCBjaGFyICpyYXRlX2VudiA9IGdldGVudigiTlRfU0hJUF9SQVRFX0tCUFMiKTsKICBpZiAo
cmF0ZV9lbnYgJiYgKnJhdGVfZW52KSBnX3NoaXBfcmF0ZV9rYnBzID0gKHVuc2lnbmVkKWF0b2ko
cmF0ZV9lbnYpOwogIGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAgIGlmICghc3RyY21w
KGFyZ3ZbaV0sICItaSIpICYmIGkgKyAxIDwgYXJnYykgaWZhY2UgPSBhcmd2WysraV07CiAgICBl
bHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItcCIpICYmIGkgKyAxIDwgYXJnYykgewogICAgICB3
aGlsZSAoaSArIDEgPCBhcmdjICYmIGFyZ3ZbaSArIDFdWzBdICE9ICctJykgewogICAgICAgIGNo
YXIgKnEgPSBzdHJ0b2soYXJndlsrK2ldLCAiLCAiKTsKICAgICAgICB3aGlsZSAocSkgeyBsb25n
IHAgPSBhdG9sKHEpOyBpZiAodmFsaWRfcG9ydCgodW5zaWduZWQpcCkpIHBvcnRzLnB1c2hfYmFj
aygodW5zaWduZWQpcCk7IHEgPSBzdHJ0b2soTlVMTCwgIiwgIik7IH0KICAgICAgfQogICAgfQog
ICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1lbmRwb2ludCIpICYmIGkgKyAxIDwgYXJn
YykgZW5kcG9pbnQgPSBhcmd2WysraV07CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICIt
LXNoaXAtcmF0ZS1rYnBzIikgJiYgaSArIDEgPCBhcmdjKSBnX3NoaXBfcmF0ZV9rYnBzID0gKHVu
c2lnbmVkKWF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0t
Y2FwYWJpbGl0eS1wcm9iZSIpKSBjYXBhYmlsaXR5X3Byb2JlID0gdHJ1ZTsKICAgIGVsc2UgaWYg
KCFzdHJjbXAoYXJndltpXSwgIi0tc3Bvb2wiKSAmJiBpICsgMSA8IGFyZ2MpICsraTsgLyogaWdu
b3JlZDogMCBkaXNrIHdyaXRlICovCiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaiIp
ICYmIGkgKyAxIDwgYXJnYykgd29ya2VycyA9IGF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYg
KCFzdHJjbXAoYXJndltpXSwgIi0td3NzZS1ib2R5LWJ5dGVzIikgJiYgaSArIDEgPCBhcmdjKSB7
CiAgICAgIGlmICghcGFyc2Vfd3NzZV9zaXplKGFyZ3ZbKytpXSwgJmdfd3NzZV9ib2R5X2J5dGVz
KSkgewogICAgICAgIGZwcmludGYoc3RkZXJyLCAid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgaW4g
cmFuZ2UgMC4uNjU1MzZcbiIpOyByZXR1cm4gMjsKICAgICAgfQogICAgfQogICAgZWxzZSBpZiAo
IXN0cmNtcChhcmd2W2ldLCAiLWgiKSB8fCAhc3RyY21wKGFyZ3ZbaV0sICItLWhlbHAiKSkgewog
ICAgICBmcHJpbnRmKHN0ZGVyciwgInVzYWdlOiBudC1zbmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAg
cG9ydHNdIFstLWVuZHBvaW50IFVSTF0gWy0tc2hpcC1yYXRlLWticHMgNjQuLjEwMDAwXSBbLWog
d29ya2Vyc10gWy0td3NzZS1ib2R5LWJ5dGVzIDAuLjY1NTM2XVxuIik7CiAgICAgIHJldHVybiAw
OwogICAgfQogICAgZWxzZSB7IGZwcmludGYoc3RkZXJyLCAidW5rbm93biBvciBpbmNvbXBsZXRl
IGFyZ3VtZW50OiAlc1xuIiwgYXJndltpXSk7IHJldHVybiAyOyB9CiAgfQogIGlmIChwb3J0cy5l
bXB0eSgpKSB7IHBvcnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9y
dHMucHVzaF9iYWNrKDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFj
ayg4MDA5KTsgcG9ydHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0K
ICBpZiAoZ19zaGlwX3JhdGVfa2JwcyA8IDY0IHx8IGdfc2hpcF9yYXRlX2ticHMgPiAxMDAwMCkg
ewogICAgZnByaW50ZihzdGRlcnIsICJzaGlwIHJhdGUgbXVzdCBiZSBpbiByYW5nZSA2NC4uMTAw
MDAga2JpdC9zXG4iKTsKICAgIHJldHVybiAyOwogIH0KICBpZiAocG9ydHMuc2l6ZSgpID4gTUFY
X1BPUlRTKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgImF0IG1vc3QgMzAgbW9uaXRvcmVkIHBvcnRz
IGFyZSBzdXBwb3J0ZWQgYnkgdGhlIHNhZmUgY0JQRiBwcm9ncmFtXG4iKTsKICAgIHJldHVybiAy
OwogIH0KICBpZiAod29ya2VycyAhPSAxKSB7CiAgICBmcHJpbnRmKHN0ZGVyciwgIm9ubHkgb25l
IGNhcHR1cmUgd29ya2VyIGlzIHBlcm1pdHRlZFxuIik7CiAgICByZXR1cm4gMjsKICB9CiAgKHZv
aWQpd29ya2VyczsKCiAgaWYgKGNhcGFiaWxpdHlfcHJvYmUpIHJldHVybiBydW5fY2FwYWJpbGl0
eV9wcm9iZShpZmFjZSwgcG9ydHMpOwoKICBpbml0X3JuZygpOwogIG1lbXNldChnX21vbml0b3Jl
ZF9wb3J0cywgMCwgc2l6ZW9mKGdfbW9uaXRvcmVkX3BvcnRzKSk7CiAgZm9yIChzaXplX3QgayA9
IDA7IGsgPCBwb3J0cy5zaXplKCk7ICsraykgewogICAgaWYgKHBvcnRzW2tdIDwgNjU1MzYpIGdf
bW9uaXRvcmVkX3BvcnRzW3BvcnRzW2tdXSA9IHRydWU7CiAgfQoKICBjb25zdCBjaGFyICpub2Rl
X2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2Rl
X2VudiAmJiAqbm9kZV9lbnYpID8gbm9kZV9lbnYgOiBob3N0X25hbWUoKTsKCiAgZ19lbmRwb2lu
dCA9IGVuZHBvaW50OwogIGdfc2hpcF9ub2RlID0gbm9kZTsKCiAgTW1hcFJpbmcgcmluZzsKICBp
bnQgZmQgPSBvcGVuX2NhcHR1cmVfc29ja2V0KGlmYWNlLCBwb3J0cywgcmluZyk7CiAgaWYgKGZk
IDwgMCkgcmV0dXJuIDI7CgogIHNpZ25hbChTSUdURVJNLCBzdG9wX3NpZ25hbCk7CiAgc2lnbmFs
KFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHNldHZidWYoc3Rkb3V0LCBOVUxMLCBfSU9MQkYsIDY1
NTM2KTsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRL
ZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gcGVuZGluZzsKCiAgbG9nbXNnKCJQQUNLRVRfTU1B
UCAoVFBBQ0tFVF9WMikgc3RyaWN0IFJYIHJpbmcgZW5hYmxlZCAoNE1CLCAyMDQ4IGZyYW1lcyki
KTsKICBpZiAoZ193c3NlX2JvZHlfYnl0ZXMpIHsKICAgIGxvZ21zZygiV1NTRSBVc2VybmFtZVRv
a2VuIGluc3BlY3Rpb24gZW5hYmxlZCAoYm91bmRlZCB0byAiICsgbnVtYmVyX3N0cmluZyhnX3dz
c2VfYm9keV9ieXRlcykgKyAiIGJ5dGVzL3JlcXVlc3QpIik7CiAgfQogIGlmICghZ19lbmRwb2lu
dC5lbXB0eSgpKSB7CiAgICBsb2dtc2coInNpbmdsZS1iaW5hcnkgaW4tbWVtb3J5IG1vZGU6IHNo
aXBwaW5nIGRpcmVjdGx5IHRvICIgKyBnX2VuZHBvaW50ICsgIiAoMCBkaXNrIEkvTykiKTsKICB9
CiAgbG9nbXNnKCJsaXN0ZW5pbmciKTsKCiAgdGltZV90IGxhc3QgPSB0aW1lKE5VTEwpLCBsYXN0
X2ZsdXNoID0gbGFzdDsKICBib29sIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPSBmYWxzZTsKCiAg
c3RydWN0IHBvbGxmZCBwZmQ7CiAgcGZkLmZkID0gZmQ7CiAgcGZkLmV2ZW50cyA9IFBPTExJTiB8
IFBPTExFUlI7CiAgcGZkLnJldmVudHMgPSAwOwoKICB3aGlsZSAoZ19ydW5uaW5nKSB7CiAgICBp
bnQgcmMgPSBwb2xsKCZwZmQsIDEsIDEwMDApOwogICAgaWYgKHJjIDwgMCAmJiBlcnJubyA9PSBF
SU5UUikgewogICAgICAvKiBTaWduYWwgaGFuZGxlZCwgbG9vcCBjb25kaXRpb24gd2lsbCBjaGVj
ayBnX3J1bm5pbmcgKi8KICAgIH0gZWxzZSBpZiAocmMgPj0gMCkgewogICAgICAvKiBEcmFpbiBh
bGwgcmVhZHkgZnJhbWVzIGluIHRoZSByaW5nIHdpdGhvdXQgZXh0cmEgc3lzY2FsbHMuICovCiAg
ICAgIHdoaWxlIChnX3J1bm5pbmcpIHsKICAgICAgICAgIHVuc2lnbmVkIGJfaWR4ID0gcmluZy5m
cmFtZV9pZHggLyByaW5nLmZyYW1lc19wZXJfYmxvY2s7CiAgICAgICAgICB1bnNpZ25lZCBmX2lu
X2IgPSByaW5nLmZyYW1lX2lkeCAlIHJpbmcuZnJhbWVzX3Blcl9ibG9jazsKICAgICAgICAgIHVp
bnQ4X3QgKmZyYW1lX3B0ciA9ICgodWludDhfdCAqKXJpbmcucmluZykgKyAoYl9pZHggKiByaW5n
LmJsb2NrX3NpemUpICsgKGZfaW5fYiAqIHJpbmcuZnJhbWVfc2l6ZSk7CiAgICAgICAgICB2b2xh
dGlsZSBzdHJ1Y3QgdHBhY2tldDJfaGRyICp2b2xhdGlsZV9oZHIgPQogICAgICAgICAgICAgICh2
b2xhdGlsZSBzdHJ1Y3QgdHBhY2tldDJfaGRyICopZnJhbWVfcHRyOwoKICAgICAgICAgIGlmICgh
KHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzICYgVFBfU1RBVFVTX1VTRVIpKSB7CiAgICAgICAgICAg
IGJyZWFrOyAvKiBObyBtb3JlIGtlcm5lbC1wb3B1bGF0ZWQgZnJhbWVzIGluIHJpbmcgcmlnaHQg
bm93ICovCiAgICAgICAgICB9CiAgICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsgLyogYWNx
dWlyZSBrZXJuZWwtb3duZWQgZnJhbWUgY29udGVudHMgKi8KCiAgICAgICAgICBjb25zdCBzdHJ1
Y3QgdHBhY2tldDJfaGRyICpoZHIgPQogICAgICAgICAgICAgIChjb25zdCBzdHJ1Y3QgdHBhY2tl
dDJfaGRyICopZnJhbWVfcHRyOwogICAgICAgICAgc2l6ZV90IHBhY2tldF9vZmZzZXQgPSAwLCBw
YWNrZXRfbGVuZ3RoID0gMDsKICAgICAgICAgIGlmICghdmFsaWRfcmluZ19mcmFtZShoZHIsIHJp
bmcuZnJhbWVfc2l6ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmcGFja2V0X29m
ZnNldCwgJnBhY2tldF9sZW5ndGgpKSB7CiAgICAgICAgICAgIF9fc3luY19zeW5jaHJvbml6ZSgp
OwogICAgICAgICAgICB2b2xhdGlsZV9oZHItPnRwX3N0YXR1cyA9IFRQX1NUQVRVU19LRVJORUw7
CiAgICAgICAgICAgIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPSB0cnVlOwogICAgICAgICAgICBn
X3J1bm5pbmcgPSAwOwogICAgICAgICAgICBsb2dtc2coImludmFsaWQgVFBBQ0tFVF9WMiBmcmFt
ZSBtZXRhZGF0YTsgc3RvcHBpbmcgY2FwdHVyZSIpOwogICAgICAgICAgICBicmVhazsKICAgICAg
ICAgIH0KICAgICAgICAgIGlmIChwYWNrZXRfbGVuZ3RoID4gMCkgewogICAgICAgICAgICBjb25z
dCB1bnNpZ25lZCBjaGFyICpwa3QgPSBmcmFtZV9wdHIgKyBwYWNrZXRfb2Zmc2V0OwogICAgICAg
ICAgICBoYW5kbGVfcGFja2V0KHBrdCwgcGFja2V0X2xlbmd0aCwgbm9kZSwgcG9ydHMsIGZsb3dz
LCBwZW5kaW5nKTsKICAgICAgICAgIH0KCiAgICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsg
LyogcmVsZWFzZSBhbGwgcmVhZHMgYmVmb3JlIHJldHVybmluZyBvd25lcnNoaXAgKi8KICAgICAg
ICAgIHZvbGF0aWxlX2hkci0+dHBfc3RhdHVzID0gVFBfU1RBVFVTX0tFUk5FTDsKICAgICAgICAg
IHJpbmcuZnJhbWVfaWR4ID0gKHJpbmcuZnJhbWVfaWR4ICsgMSkgJSByaW5nLmZyYW1lX25yOwog
ICAgICB9CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgpOwog
ICAgfQoKICAgIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAtIGxhc3QgPj0g
MSkgewogICAgICBzd2VlcChmbG93cywgcGVuZGluZywgbm93KTsKICAgICAgaWYgKGdfZW5kcG9p
bnQuZW1wdHkoKSkgc3RkOjpjb3V0LmZsdXNoKCk7CiAgICAgIGxhc3QgPSBub3c7CiAgICB9Cgog
ICAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgICAgaWYgKG5vdyAtIGxhc3RfZmx1c2gg
Pj0gRkxVU0hfU0VDIHx8IGdfc2hpcF9idWYuc2l6ZSgpID49IE1BWF9CQVRDSCkgewogICAgICAg
IGlmICghZ19zaGlwX2J1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMoZ19lbmRwb2ludCwgZ19zaGlw
X25vZGUsICZnX3NoaXBfYnVmLCB0cnVlKTsKICAgICAgICBsYXN0X2ZsdXNoID0gbm93OwogICAg
ICB9CiAgICB9CiAgfQoKICAvKiBBIHJlc3BvbnNlIGlzIG9wdGlvbmFsIGVucmljaG1lbnQuIFBy
ZXNlcnZlIHJlcXVlc3RzIHN0aWxsIGF3YWl0aW5nIGEKICAgKiByZXNwb25zZSB3aGVuIFNJR1RF
Uk0vcmVzdGFydCBlbmRzIGNhcHR1cmUuICovCiAgZmx1c2hfaW5jb21wbGV0ZV93c3NlKGZsb3dz
LCBwZW5kaW5nKTsKICBmbHVzaF9hbGxfcGVuZGluZyhwZW5kaW5nKTsKICBpZiAoZ19lbmRwb2lu
dC5lbXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkg
JiYgIWdfc2hpcF9idWYuZW1wdHkoKSkgewogICAgc2VuZF9iYXRjaGVzKGdfZW5kcG9pbnQsIGdf
c2hpcF9ub2RlLCAmZ19zaGlwX2J1ZiwgdHJ1ZSk7CiAgfQoKICBzdHJ1Y3QgdHBhY2tldF9zdGF0
cyBwYWNrZXRfc3RhdHM7CiAgc29ja2xlbl90IHBhY2tldF9zdGF0c19sZW4gPSBzaXplb2YocGFj
a2V0X3N0YXRzKTsKICBtZW1zZXQoJnBhY2tldF9zdGF0cywgMCwgc2l6ZW9mKHBhY2tldF9zdGF0
cykpOwogIGlmIChnZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfU1RBVElTVElDUywK
ICAgICAgICAgICAgICAgICAmcGFja2V0X3N0YXRzLCAmcGFja2V0X3N0YXRzX2xlbikgPT0gMCkg
ewogICAgbG9nbXNnKCJwYWNrZXQgc3RhdHM6IHJlY2VpdmVkPSIgKyBudW1iZXJfc3RyaW5nKHBh
Y2tldF9zdGF0cy50cF9wYWNrZXRzKSArCiAgICAgICAgICAgIiBkcm9wcGVkPSIgKyBudW1iZXJf
c3RyaW5nKHBhY2tldF9zdGF0cy50cF9kcm9wcykpOwogIH0KICBpZiAoIXJlbGVhc2VfbW1hcF9y
aW5nKGZkLCByaW5nKSkgewogICAgbG9nbXNnKCJUUEFDS0VUX1YyIGNsZWFudXAgZmFpbGVkIik7
CiAgICByaW5nX2ludGVncml0eV9mYWlsdXJlID0gdHJ1ZTsKICB9CiAgY2xvc2UoZmQpOwogIGxv
Z21zZygic3RvcHBlZCIpOwogIHJldHVybiByaW5nX2ludGVncml0eV9mYWlsdXJlID8gMiA6IDA7
Cn0K
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
LWNwcC1kZWJ1ZwoKZml4dHVyZTogY3BwCgkuL250LXNuaWZmLWNwcCAtLWZpeHR1cmUKCS4vbnQt
c25pZmYtY3BwIC0tcmluZy1maXh0dXJlCgkuL250LXNuaWZmLWNwcCAtLXNoaXAtcmF0ZS1maXh0
dXJlCgpwY2FwLWZpeHR1cmU6IHBjYXBfdGVzdF9jcHAKCnBjYXBfdGVzdF9jcHA6IHBjYXBfdGVz
dF9jcHAuY3BwIG50LXNuaWZmLWNwcC5jcHAKCSQoQ1hYKSAkKENYWEZMQUdTKSBwY2FwX3Rlc3Rf
Y3BwLmNwcCAtbyBwY2FwX3Rlc3RfY3BwCgpjbGVhbjoKCXJtIC1mIG50LXNuaWZmLWNwcCBudC1z
bmlmZi1jcHAtZGVidWcgbnQtc2hpcC1jcHAgcGNhcF90ZXN0X2NwcAo=
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
