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
set -u

PREFIX=/opt/networktracing-legacy
INIT=/etc/init.d/networktracing-legacy
SNIFF_USER=ntsniff
MODE=install
ENDPOINT=""
IFACE="${NT_IFACE:-}"
PORTS="${NT_PORTS:-80,8003,8005,8007,8009,8010,8011}"
WORKERS="${NT_WORKERS:-1}"   # compatibility input; capture is always single-worker
SHIPPERS="${NT_SHIP_THREADS:-8}"  # concurrent hub POST threads
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
  --ship-threads N          Python poster threads, 1..32
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
case "$SHIPPERS" in ''|*[!0-9]*) die "ship threads must be an integer 1..32" ;; esac
[ "$SHIPPERS" -ge 1 ] && [ "$SHIPPERS" -le 32 ] || die "ship threads must be in range 1..32"

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
log "Safety: rootless, cpu=$CPU_CORE (one logical core/SCHED_IDLE/nice 19), memory=256MiB, fds=1024, output-file=32MiB, crash circuit=5"
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
IHVzZXIgPSByYXcuc3BsaXQoYiI6IiwgMSlbMF0KICAgICAgICAgICAgICAgIHJldHVybiB1c2Vy
LmRlY29kZSgidXRmLTgiLCAicmVwbGFjZSIpWzo2NF0sICJiYXNpYyIKICAgICAgICBleGNlcHQg
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
ICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBzY2hlbWUsCiAgICAgICAgInBpZCI6
IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6ICJwY2FwLWh0dHAiLAogICAgICAgICJob3N0
X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAgInVzZXJfYWdlbnQiOiBoLmdldCgidXNlci1h
Z2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9mb3IiOiBoLmdldCgieC1mb3J3YXJkZWQtZm9y
IiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwKICAgICAgICAiY2FsbGVyX3BvcnQiOiBzcG9y
dCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAogICAgICAgICJkc3RfcG9ydCI6IGRwb3J0LAog
ICAgICAgICMgLS0tLSBtb25pdG9yaW5nIHNjaGVtYSAob3BzIEFQSS1sb2cgZm9ybWF0KSAtLS0t
CiAgICAgICAgIyBzdGF0dXMvZHVyYXRpb25fbXMvcmVzcF9ieXRlcyBhcmUgcmVzcG9uc2Utc2lk
ZTogcGFzc2l2ZSByZXF1ZXN0LW9ubHkKICAgICAgICAjIGNhcHR1cmUgY2Fubm90IHNlZSB0aGVt
OyBsZWZ0IG51bGwgZm9yIHRoZSBodWIgdG8gZW5yaWNoIG9yIGxlYXZlLgogICAgICAgICJ0cmFj
ZXBhcmVudCI6IHRwWzo4MF0sCiAgICAgICAgInRyYWNlX2lkIjogdHJhY2VfaWQsCiAgICAgICAg
InNlcnZpY2VfaWQiOiBOb25lLCAgICAgICAgICAjIGh1YiBtYXBzIHBvcnQtPnNlcnZpY2Ugdmlh
IHBvbGljeSBsYXRlcgogICAgICAgICJtb2R1bGVfaWQiOiAicGNhcC1odHRwIiwKICAgIH0KICAg
ICMgUHJlc2VydmUgcmVzcG9uc2UgY29ycmVsYXRpb24gb25seSBmb3IgbW9uaXRvcmVkIGRlc3Rp
bmF0aW9ucy4gVGhlCiAgICAjIHJlc3BvbnNlLXNpZGUgZmlsdGVyIG1heSBzdGlsbCBhZG1pdCBh
IGNsaWVudCBlcGhlbWVyYWwgc3BvcnQgZXF1YWwgdG8gYQogICAgIyBtb25pdG9yZWQgcG9ydDsg
dGhpcyBpcyBoYXJtbGVzcyBiZWNhdXNlIHBhcnNlX3Jlc3BvbnNlX2hlYWQgcmVqZWN0cyBpdC4K
ICAgIHJldHVybiBldiBpZiAoZHBvcnQgaW4gcG9ydHMgb3IgaC5nZXQoIl9tZXRob2QiKSkgZWxz
ZSBOb25lCgoKZGVmIF9lbWl0X3JlcXVlc3QoZmxvd3MsIGtleSwgZmwsIG1ldGEsIG91dCwgcGVu
ZGluZ190YmwsIG5vdyk6CiAgICAiIiJEaXNjYXJkIGNhcHR1cmUgYnVmZmVycywgdGhlbiBlbWl0
L3F1ZXVlIHRoZSBzYW5pdGl6ZWQgZXZlbnQgb25seS4iIiIKICAgIGRzdF9pcCwgZHBvcnQsIHNy
Y19pcCwgc3BvcnQgPSBtZXRhCiAgICBldiA9IGZsLmV2ZW50CiAgICBmbG93cy5wb3Aoa2V5LCBO
b25lKQogICAgaWYgbm90IGV2OgogICAgICAgIHJldHVybgogICAgZXZbInJlcV9ieXRlcyJdID0g
ZmwuaGVhZF9ieXRlcwogICAgaWYgcGVuZGluZ190YmwgaXMgTm9uZToKICAgICAgICBvdXQuYXBw
ZW5kKGV2KQogICAgICAgIHJldHVybgogICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBz
cG9ydCkKICAgIGVudCA9IHBlbmRpbmdfdGJsLmdldChyaykKICAgIGlmIGVudCBpcyBOb25lOgog
ICAgICAgIGlmIGxlbihwZW5kaW5nX3RibCkgPj0gUEVORElOR19NQVg6CiAgICAgICAgICAgIF9m
bHVzaF9vbGRlc3RfcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KQogICAgICAgIGVudCA9IHBlbmRp
bmdfdGJsW3JrXSA9IFtdCiAgICBlbGlmIGxlbihlbnQpID49IFBFTkRJTkdfUEVSX0ZMT1c6CiAg
ICAgICAgcGVuZGluZ19wb3AocmssIG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgZW50ID0gcGVu
ZGluZ190YmwuZ2V0KHJrKQogICAgICAgIGlmIGVudCBpcyBOb25lOgogICAgICAgICAgICBlbnQg
PSBwZW5kaW5nX3RibFtya10gPSBbXQogICAgZW50LmFwcGVuZChbZXYsIG5vdyBpZiBub3cgaXMg
bm90IE5vbmUgZWxzZSB0aW1lLnRpbWUoKV0pCgoKZGVmIF90cnlfd3NzZV9ib2R5KGZsb3dzLCBr
ZXksIGZsLCBwYXlsb2FkLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpOgogICAgIiIiQXBw
ZW5kIG5vIG1vcmUgdGhhbiBib2R5X2dvYWwgYnl0ZXMgYW5kIGZpbmlzaCBhcyBzb29uIGFzIHBv
c3NpYmxlLiIiIgogICAgcmVtYWluaW5nID0gZmwuYm9keV9nb2FsIC0gbGVuKGZsLmJ1ZikKICAg
IGlmIHJlbWFpbmluZyA+IDAgYW5kIHBheWxvYWQ6CiAgICAgICAgZmwuYnVmLmV4dGVuZChieXRl
YXJyYXkocGF5bG9hZFs6cmVtYWluaW5nXSkpCiAgICB1c2VybmFtZSA9IGV4dHJhY3Rfd3NzZV91
c2VybmFtZShmbC5idWYpCiAgICBpZiB1c2VybmFtZToKICAgICAgICBmbC5ldmVudFsidXNlciJd
ID0gdXNlcm5hbWUKICAgICAgICBmbC5ldmVudFsic2NoZW1lIl0gPSAid3NzZSIKICAgIGlmIHVz
ZXJuYW1lIG9yIGxlbihmbC5idWYpID49IGZsLmJvZHlfZ29hbDoKICAgICAgICBfZW1pdF9yZXF1
ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cpCiAgICAgICAg
cmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBoYW5kbGVfcGF5bG9hZChmbG93cywg
a2V5LCByZXZfa2V5LCBwYXlsb2FkLCBtZXRhLCBwb3J0cywgbm9kZV9ob3N0LCBvdXQsCiAgICAg
ICAgICAgICAgICAgICBwZW5kaW5nX3RibD1Ob25lLCBub3c9Tm9uZSwgd3NzZV9ib2R5X2J5dGVz
PTApOgogICAgIiIiRmVlZCBvbmUgZGlyZWN0aW9uJ3MgcGF5bG9hZDsgZW1pdCBmaW5pc2hlZCBl
dmVudHMgdG8gb3V0KGxpc3QpLgoKICAgIEJvZGllcyBhcmUgaWdub3JlZCB1bmxlc3Mgd3NzZV9i
b2R5X2J5dGVzIGlzIG5vbi16ZXJvLiBJbiBvcHQtaW4gbW9kZSwKICAgIG9ubHkgWE1MIHJlcXVl
c3RzIHdpdGggQ29udGVudC1MZW5ndGggYXJlIGluc3BlY3RlZCwgZWFjaCBidWZmZXIgaXMKICAg
IGJvdW5kZWQgYnkgd3NzZV9ib2R5X2J5dGVzLCBhbmQgb25seSBhIHJlY29nbml6ZWQgV1NTRSB1
c2VybmFtZSByZWFjaGVzCiAgICB0aGUgZXZlbnQuIFRoZSBib2R5IGFuZCBhbGwgb3RoZXIgVXNl
cm5hbWVUb2tlbiBtYXRlcmlhbCBhcmUgZGlzY2FyZGVkLgogICAgIiIiCiAgICBkc3RfaXAsIGRw
b3J0LCBzcmNfaXAsIHNwb3J0ID0gbWV0YQogICAgaWYgbm90IHZhbGlkX3BvcnQoZHBvcnQpIG9y
IG5vdCB2YWxpZF9wb3J0KHNwb3J0KToKICAgICAgICByZXR1cm4KICAgIGZsID0gZmxvd3MuZ2V0
KGtleSkKICAgIGlmIGZsIGlzIE5vbmU6CiAgICAgICAgZmwgPSBGbG93KCkKICAgICAgICBmbG93
c1trZXldID0gZmwKICAgICAgICBpZiBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgICAg
ICBlbmZvcmNlX2xpbWl0KGZsb3dzLCB0aW1lLnRpbWUoKSkKICAgIGZsLnRvdWNoZWQgPSB0aW1l
LnRpbWUoKQoKICAgIGlmIGZsLmV2ZW50IGlzIG5vdCBOb25lOgogICAgICAgIF90cnlfd3NzZV9i
b2R5KGZsb3dzLCBrZXksIGZsLCBwYXlsb2FkLCBtZXRhLCBvdXQsIHBlbmRpbmdfdGJsLCBub3cp
CiAgICAgICAgcmV0dXJuCgogICAgZmwuYnVmLmV4dGVuZChieXRlYXJyYXkocGF5bG9hZCkpCiAg
ICBpZHggPSBmbC5idWYuZmluZChiIlxyXG5cclxuIikKICAgIGlmIGlkeCA8IDA6CiAgICAgICAg
aWYgbGVuKGZsLmJ1ZikgPiBNQVhfSERSUzoKICAgICAgICAgICAgZmxvd3MucG9wKGtleSwgTm9u
ZSkKICAgICAgICByZXR1cm4KICAgIGhlYWQgPSBieXRlcyhmbC5idWZbOmlkeF0pCiAgICBsaW5l
cyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQoYiJcbiIpCiAgICBoZHJzID0g
e30KICAgIGZpcnN0ID0gbGluZXNbMF0uc3RyaXAoKS5zcGxpdCgpCiAgICBpZiBsZW4oZmlyc3Qp
ID49IDIgYW5kIGZpcnN0WzBdIGluIFttLmVuY29kZSgpIGZvciBtIGluIE1FVEhPRFNdOgogICAg
ICAgIGhkcnNbIl9tZXRob2QiXSA9IGZpcnN0WzBdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIp
CiAgICAgICAgaGRyc1siX3BhdGgiXSA9IGZpcnN0WzFdLmRlY29kZSgiYXNjaWkiLCAicmVwbGFj
ZSIpCiAgICBlbHNlOgogICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJu
CiAgICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgIGlmIGIiOiIgbm90IGluIGxuOgogICAg
ICAgICAgICBjb250aW51ZQogICAgICAgIGtuLCBrdiA9IGxuLnNwbGl0KGIiOiIsIDEpCiAgICAg
ICAgaGRyc1trbi5zdHJpcCgpLmxvd2VyKCkuZGVjb2RlKAogICAgICAgICAgICAiYXNjaWkiLCAi
cmVwbGFjZSIpXSA9IGt2LnN0cmlwKCkuZGVjb2RlKAogICAgICAgICAgICAgICAgInV0Zi04Iiwg
InJlcGxhY2UiKVs6MTgwXQogICAgZmwuaGRycyA9IGhkcnMKICAgIGZsLmV2ZW50ID0gZmluaXNo
X2V2ZW50KGZsLCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsCiAgICAgICAgICAg
ICAgICAgICAgICAgICAgICBwb3J0cywgbm9kZV9ob3N0KQogICAgaWYgbm90IGZsLmV2ZW50Ogog
ICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBmbC5oZWFkX2J5
dGVzID0gaWR4ICsgNAogICAgaW5pdGlhbF9ib2R5ID0gYnl0ZXMoZmwuYnVmW2lkeCArIDQ6XSkK
ICAgIGZsLmJ1ZiA9IGJ5dGVhcnJheSgpCgogICAgaWYgKGZsLmV2ZW50LmdldCgidXNlciIpIG9y
IG5vdCB3c3NlX2JvZHlfYnl0ZXMgb3IKICAgICAgICAgICAgbm90IGlzX3NvYXBfY29udGVudF90
eXBlKGhkcnMuZ2V0KCJjb250ZW50LXR5cGUiKSkpOgogICAgICAgIF9lbWl0X3JlcXVlc3QoZmxv
d3MsIGtleSwgZmwsIG1ldGEsIG91dCwgcGVuZGluZ190YmwsIG5vdykKICAgICAgICByZXR1cm4K
ICAgIHRyeToKICAgICAgICBjb250ZW50X2xlbmd0aCA9IGludChoZHJzLmdldCgiY29udGVudC1s
ZW5ndGgiLCAiIikpCiAgICBleGNlcHQgKFR5cGVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAg
Y29udGVudF9sZW5ndGggPSAwCiAgICBhY3RpdmVfYm9keV9mbG93cyA9IHN1bShbMSBmb3IgY2Fu
ZGlkYXRlIGluIGZsb3dzLnZhbHVlcygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYg
Y2FuZGlkYXRlLmV2ZW50IGlzIG5vdCBOb25lIGFuZAogICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIGNhbmRpZGF0ZS5ib2R5X2dvYWwgPiAwXSkKICAgIGlmIChjb250ZW50X2xlbmd0aCA8PSAw
IG9yIGFjdGl2ZV9ib2R5X2Zsb3dzID49IE1BWF9XU1NFX0JPRFlfRkxPV1Mgb3IKICAgICAgICAg
ICAgImNodW5rZWQiIGluIGhkcnMuZ2V0KCJ0cmFuc2Zlci1lbmNvZGluZyIsICIiKS5sb3dlcigp
KToKICAgICAgICBfZW1pdF9yZXF1ZXN0KGZsb3dzLCBrZXksIGZsLCBtZXRhLCBvdXQsIHBlbmRp
bmdfdGJsLCBub3cpCiAgICAgICAgcmV0dXJuCiAgICBmbC5ib2R5X2dvYWwgPSBtaW4oY29udGVu
dF9sZW5ndGgsIHdzc2VfYm9keV9ieXRlcywgTUFYX1dTU0VfQk9EWV9CWVRFUykKICAgIF90cnlf
d3NzZV9ib2R5KGZsb3dzLCBrZXksIGZsLCBpbml0aWFsX2JvZHksIG1ldGEsIG91dCwgcGVuZGlu
Z190YmwsIG5vdykKCgpkZWYgc3dlZXBfaWRsZShmbG93cywgbm93KToKICAgIHN0YWxlID0gW10K
ICAgIGZvciBrLCBmbCBpbiBmbG93cy5pdGVtcygpOgogICAgICAgIGlmIG5vdyAtIGZsLnRvdWNo
ZWQgPiBGTE9XX1RUTDoKICAgICAgICAgICAgc3RhbGUuYXBwZW5kKGspCiAgICBmb3IgayBpbiBz
dGFsZToKICAgICAgICBkZWwgZmxvd3Nba10KCgpkZWYgX2ZsdXNoX29sZGVzdF9wZW5kaW5nKHBl
bmRpbmdfdGJsLCBvdXQpOgogICAgIiIiT3ZlcmZsb3cgZ3VhcmQ6IGVtaXQgdGhlIHNpbmdsZSBv
bGRlc3QgcGVuZGluZyBldmVudCBhcy1pcy4iIiIKICAgIG9sZGVzdF9rZXksIG9sZGVzdF90cyA9
IE5vbmUsIE5vbmUKICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJsLml0ZW1zKCk6CiAgICAg
ICAgdHMgPSBsc3RbMF1bMV0KICAgICAgICBpZiBvbGRlc3RfdHMgaXMgTm9uZSBvciB0cyA8IG9s
ZGVzdF90czoKICAgICAgICAgICAgb2xkZXN0X2tleSwgb2xkZXN0X3RzID0gcmssIHRzCiAgICBp
ZiBvbGRlc3Rfa2V5IGlzIG5vdCBOb25lOgogICAgICAgIHBlbmRpbmdfcG9wKG9sZGVzdF9rZXks
IG91dCwgcGVuZGluZ190YmwpCgoKZGVmIHN3ZWVwX3BlbmRpbmcocGVuZGluZ190YmwsIG5vdywg
b3V0KToKICAgICIiIlRUTCBmbHVzaDogZW1pdCByZXF1ZXN0cyB3aG9zZSByZXNwb25zZXMgbmV2
ZXIgc2hvd2VkIHVwLiIiIgogICAgZm9yIHJrIGluIGxpc3QocGVuZGluZ190Ymwua2V5cygpKToK
ICAgICAgICBsc3QgPSBwZW5kaW5nX3RibC5nZXQocmspCiAgICAgICAgd2hpbGUgbHN0IGFuZCBu
b3cgLSBsc3RbMF1bMV0gPiBQRU5ESU5HX1RUTDoKICAgICAgICAgICAgcGVuZGluZ19wb3Aocmss
IG91dCwgcGVuZGluZ190YmwpCiAgICAgICAgICAgIGxzdCA9IHBlbmRpbmdfdGJsLmdldChyaykK
CgpkZWYgZHJhaW5fcGVuZGluZyhwZW5kaW5nX3RibCwgb3V0KToKICAgICIiIkVtaXQgZXZlcnkg
Y2FwdHVyZWQgcmVxdWVzdCBiZWZvcmUgY2FwdHVyZSBzaHV0ZG93bi4KCiAgICBSZXNwb25zZXMg
YXJlIG9wdGlvbmFsIGVucmljaG1lbnQuIEEgc3RvcC9yZXN0YXJ0IG11c3Qgbm90IGRpc2NhcmQg
YQogICAgcmVxdWVzdCBtZXJlbHkgYmVjYXVzZSBpdHMgcmVzcG9uc2Ugd2FzIGZpbHRlcmVkLCBz
cGxpdCwgb3Igc3RpbGwgaW4KICAgIGZsaWdodCB3aGVuIHRoZSBwcm9jZXNzIHJlY2VpdmVkIFNJ
R1RFUk0uCiAgICAiIiIKICAgIGZvciByayBpbiBsaXN0KHBlbmRpbmdfdGJsLmtleXMoKSk6CiAg
ICAgICAgd2hpbGUgcGVuZGluZ190YmwuZ2V0KHJrKToKICAgICAgICAgICAgcGVuZGluZ19wb3Ao
cmssIG91dCwgcGVuZGluZ190YmwpCgoKZGVmIG1haW50ZW5hbmNlX2R1ZShub3csIGxhc3Rfc3dl
ZXApOgogICAgcmV0dXJuIG5vdyAtIGxhc3Rfc3dlZXAgPj0gU1dFRVBfSU5URVJWQUwKCgpkZWYg
ZW5mb3JjZV9saW1pdChmbG93cywgbm93KToKICAgICIiIkNhcCBmbG93LXRhYmxlIHNpemUgKHB5
Mi42OiBubyBPcmRlcmVkRGljdCDigJQgc3dlZXAgc3RhbGUsIHRoZW4gRklGTwogICAgYnkgaW5z
ZXJ0aW9uIG9yZGVyLCB3aGljaCBwbGFpbiBkaWN0cyBwcmVzZXJ2ZSBpbiBDUHl0aG9uKS4iIiIK
ICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdykKICAgIHdoaWxlIGxlbihmbG93cykgPiBNQVhfRkxP
V1M6CiAgICAgICAgZmxvd3MucG9waXRlbSgpICAgICAgICAgICMgb2xkZXN0LWluc2VydGVkIGtl
eSBvbiBDUHl0aG9uIDIuNi8yLjcKCgpkZWYgX2NvbnRyb2xfY29uZmlnKCk6CiAgICAiIiJSZWFk
IG9wdGlvbmFsIGNvbnRyb2wgc2V0dGluZ3Mgd2l0aG91dCBleHBvc2luZyB0aGUgYmVhcmVyIHRv
a2VuLiIiIgogICAgZW5kcG9pbnQgPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9FTkRQT0lO
VCIpIG9yIG9zLmVudmlyb24uZ2V0KCJOVF9FTkRQT0lOVCIpCiAgICB0b2tlbl9maWxlID0gb3Mu
ZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfVE9LRU5fRklMRSIsICIiKQogICAgdG9rZW4gPSBvcy5l
bnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTiIsICIiKQogICAgaWYgdG9rZW5fZmlsZToKICAg
ICAgICB0cnk6CiAgICAgICAgICAgIGYgPSBvcGVuKHRva2VuX2ZpbGUsICJyIikKICAgICAgICAg
ICAgdHJ5OgogICAgICAgICAgICAgICAgdG9rZW4gPSBmLnJlYWQoKS5zdHJpcCgpCiAgICAgICAg
ICAgIGZpbmFsbHk6CiAgICAgICAgICAgICAgICBmLmNsb3NlKCkKICAgICAgICBleGNlcHQgSU9F
cnJvcjoKICAgICAgICAgICAgdG9rZW4gPSAiIgogICAgbm9kZSA9IG9zLmVudmlyb24uZ2V0KCJO
VF9OT0RFX05BTUUiKSBvciBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBy
dW5fZGlyID0gb3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfUlVOIiwgIi92YXIvbGliL25ldHdv
cmt0cmFjaW5nIikKICAgIHRyeToKICAgICAgICBpbnRlcnZhbCA9IG1heCg1LCBtaW4oaW50KG9z
LmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1NFQyIsICIzMCIpKSwgMzAwKSkKICAgIGV4Y2VwdCBW
YWx1ZUVycm9yOgogICAgICAgIGludGVydmFsID0gMzAKICAgIHJldHVybiBlbmRwb2ludCwgdG9r
ZW4sIG5vZGUsIHJ1bl9kaXIsIGludGVydmFsCgoKZGVmIF9ydW5fY29udHJvbF90aWNrKHBvcnRz
LCBpZmFjZSwgcnVuX2RpciwgY2xpZW50KToKICAgIHJlcGx5ID0gY2xpZW50LnBvbGwoKQogICAg
aWYgbm90IHJlcGx5OgogICAgICAgIHJldHVybiBwb3J0cywgaWZhY2UsIE5vbmUsICJwb2xsIGZh
aWxlZCIKICAgIGRlc2lyZWQgPSByZXBseS5nZXQoImRlc2lyZWQiKSBvciB7fQogICAgc3RhdGUg
PSBkaWN0KGRlc2lyZWQpCiAgICBnZW5lcmF0aW9uID0gZGVzaXJlZC5nZXQoImdlbmVyYXRpb24i
LCAwKQogICAgY29udHJvbF9hY3Rpb24gPSBOb25lCiAgICBzdG9wX3JlcXVlc3RlZCA9IEZhbHNl
CiAgICBpZiBkZXNpcmVkLmdldCgicG9ydHMiKToKICAgICAgICBuZXdfcG9ydHMgPSBzZXQoZGVz
aXJlZFsicG9ydHMiXSkKICAgICAgICBpZiBuZXdfcG9ydHMgIT0gcG9ydHM6CiAgICAgICAgICAg
IHBvcnRzID0gbmV3X3BvcnRzCiAgICAgICAgICAgIGNvbnRyb2xfYWN0aW9uID0gInJlc3RhcnQi
CiAgICBpZiBkZXNpcmVkLmdldCgiaWZhY2UiKToKICAgICAgICBuZXdfaWZhY2UgPSBkZXNpcmVk
WyJpZmFjZSJdCiAgICAgICAgaWYgbmV3X2lmYWNlICE9IGlmYWNlOgogICAgICAgICAgICBpZmFj
ZSA9IG5ld19pZmFjZQogICAgICAgICAgICBjb250cm9sX2FjdGlvbiA9ICJyZXN0YXJ0IgogICAg
Zm9yIHRhc2sgaW4gcmVwbHkuZ2V0KCJ0YXNrcyIsIFtdKToKICAgICAgICBhY3Rpb24gPSB0YXNr
LmdldCgiYWN0aW9uIikKICAgICAgICBpZiBhY3Rpb24gPT0gImhlYWx0aCI6CiAgICAgICAgICAg
IG1lc3NhZ2UgPSAiaGVhbHRoeSIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAg
ZWxpZiBhY3Rpb24gaW4gKCJyZXN0YXJ0IiwgInJlbG9hZCIsICJzZXRfcG9ydHMiKToKICAgICAg
ICAgICAgbWVzc2FnZSA9ICJhY2NlcHRlZDsgY2FwdHVyZSByZXN0YXJ0IHJlcXVlc3RlZCIKICAg
ICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgICAgIGNvbnRyb2xfYWN0aW9uID0gInJl
c3RhcnQiCiAgICAgICAgICAgIGlmIGFjdGlvbiA9PSAic2V0X3BvcnRzIjoKICAgICAgICAgICAg
ICAgIGFyZ3MgPSB0YXNrLmdldCgiYXJncyIpIG9yIHt9CiAgICAgICAgICAgICAgICBpZiBhcmdz
LmdldCgicG9ydHMiKToKICAgICAgICAgICAgICAgICAgICBwb3J0cyA9IHNldChhcmdzWyJwb3J0
cyJdKQogICAgICAgICAgICAgICAgICAgIHN0YXRlLnVwZGF0ZSh7InBvcnRzIjogc29ydGVkKHBv
cnRzKSwgIm1vZGUiOiAicHl0aG9uIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICJnZW5lcmF0aW9uIjogZ2VuZXJhdGlvbn0pCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInN0b3Ai
OgogICAgICAgICAgICBtZXNzYWdlID0gInN0b3AgcmVxdWVzdGVkIgogICAgICAgICAgICBzdGF0
dXMgPSAiZG9uZSIKICAgICAgICAgICAgc3RvcF9yZXF1ZXN0ZWQgPSBUcnVlCiAgICAgICAgZWxz
ZToKICAgICAgICAgICAgbWVzc2FnZSA9ICJ1bnN1cHBvcnRlZCBieSBkaXJlY3Qgc25pZmZlciIK
ICAgICAgICAgICAgc3RhdHVzID0gImZhaWxlZCIKICAgICAgICBjbGllbnQucmVwb3J0KHRhc2su
Z2V0KCJpZCIpLCBzdGF0dXMsIG1lc3NhZ2UpCiAgICBpZiBzdG9wX3JlcXVlc3RlZDoKICAgICAg
ICBjb250cm9sX2FjdGlvbiA9ICJzdG9wIgogICAgYXBwbGllZCA9ICgic3RvcCByZXF1ZXN0ZWQi
IGlmIGNvbnRyb2xfYWN0aW9uID09ICJzdG9wIiBlbHNlCiAgICAgICAgICAgICAgICJyZXN0YXJ0
IHJlcXVpcmVkIiBpZiBjb250cm9sX2FjdGlvbiA9PSAicmVzdGFydCIgZWxzZQogICAgICAgICAg
ICAgICAicG9sbCBvayIpCiAgICBudF9jb250cm9sLndyaXRlX3N0YXRlKG9zLnBhdGguam9pbihy
dW5fZGlyLCAicmVtb3RlLWRlc2lyZWQuanNvbiIpLAogICAgICAgICAgICAgICAgICAgICAgICAg
ICBzdGF0ZSwgYXBwbGllZCkKICAgIGNsaWVudC5oZWFydGJlYXQoZ2VuZXJhdGlvbiwgYXBwbGll
ZCkKICAgIHJldHVybiBwb3J0cywgaWZhY2UsIGNvbnRyb2xfYWN0aW9uLCBhcHBsaWVkCgoKZGVm
IF9yZXN0YXJ0X2FyZ3Moc2NyaXB0LCBpZmFjZSwgcG9ydHMsIHZlcmJvc2UsIHdvcmtlcnMsIHdz
c2VfYm9keV9ieXRlcz0wKToKICAgICIiIkJ1aWxkIGEgZnJlc2ggYXJndiBmb3IgYW4gaW4tcGxh
Y2UgcmUtZXhlYyBhZnRlciBhIGNvbnRyb2wgdXBkYXRlLiIiIgogICAgIyBQcmVzZXJ2ZSB1bmJ1
ZmZlcmVkIEpTT05MIGRlbGl2ZXJ5OyB0aGUgaW5zdGFsbGVyIHN0YXJ0cyBQeXRob24gd2l0aCAt
dS4KICAgIGFyZ3MgPSBbc3lzLmV4ZWN1dGFibGUsICItdSIsIG9zLnBhdGguYWJzcGF0aChzY3Jp
cHQpXQogICAgaWYgaWZhY2U6CiAgICAgICAgYXJncy5leHRlbmQoWyItaSIsIGlmYWNlXSkKICAg
IGFyZ3MuZXh0ZW5kKFsiLXAiLCAiLCIuam9pbihbc3RyKHApIGZvciBwIGluIHNvcnRlZChwb3J0
cyldKV0pCiAgICBhcmdzLmV4dGVuZChbIi1qIiwgIjEiXSkKICAgIGlmIHdzc2VfYm9keV9ieXRl
czoKICAgICAgICBhcmdzLmV4dGVuZChbIi0td3NzZS1ib2R5LWJ5dGVzIiwgc3RyKHdzc2VfYm9k
eV9ieXRlcyldKQogICAgaWYgdmVyYm9zZToKICAgICAgICBhcmdzLmFwcGVuZCgiLXYiKQogICAg
cmV0dXJuIGFyZ3MKCgpkZWYgbWFpbigpOgogICAgaWZhY2UsIHBvcnRzLCB2ZXJib3NlLCB3b3Jr
ZXJzLCB3c3NlX2JvZHlfYnl0ZXMgPSBwYXJzZV9hcmdzKHN5cy5hcmd2WzE6XSkKICAgIG5vZGVf
aG9zdCA9IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KICAgIGNvbnRyb2xfY2xp
ZW50ID0gTm9uZQogICAgZW5kcG9pbnQsIHRva2VuLCBjb250cm9sX25vZGUsIGNvbnRyb2xfcnVu
LCBjb250cm9sX2ludGVydmFsID0gX2NvbnRyb2xfY29uZmlnKCkKICAgIGlmIG50X2NvbnRyb2wg
aXMgbm90IE5vbmUgYW5kIGVuZHBvaW50IGFuZCB0b2tlbjoKICAgICAgICB0cnk6CiAgICAgICAg
ICAgIGNvbnRyb2xfY2xpZW50ID0gbnRfY29udHJvbC5Db250cm9sQ2xpZW50KGVuZHBvaW50LCB0
b2tlbiwgY29udHJvbF9ub2RlKQogICAgICAgICAgICBpZiBub3Qgb3MucGF0aC5pc2Rpcihjb250
cm9sX3J1bik6CiAgICAgICAgICAgICAgICBvcy5tYWtlZGlycyhjb250cm9sX3J1bikKICAgICAg
ICAgICAgbG9nKCJyZW1vdGUgY29udHJvbCBlbmFibGVkIikKICAgICAgICBleGNlcHQgRXhjZXB0
aW9uIGFzIGU6CiAgICAgICAgICAgIGxvZygiV0FSTjogcmVtb3RlIGNvbnRyb2wgZGlzYWJsZWQg
KCVzKSIgJSBudF9jb250cm9sLnNhZmVfbWVzc2FnZShlKSkKCiAgICB0cnk6CiAgICAgICAgIyBw
cm90b2NvbCBNVVNUIGJlIGh0b25zKEVUSF9QX0FMTCkgdG8gcmVjZWl2ZSBib3RoIElOR1JFU1Mg
KHJlcSkgYW5kCiAgICAgICAgIyBFR1JFU1MgKHJlc3ApIHBhY2tldHMgb24gTGludXgga2VybmVs
IHBhY2tldCBzb2NrZXRzLgogICAgICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9QQUNL
RVQsIHNvY2tldC5TT0NLX1JBVywKICAgICAgICAgICAgICAgICAgICAgICAgICBzb2NrZXQuaHRv
bnMoRVRIX1BfQUxMKSkKICAgIGV4Y2VwdCBBdHRyaWJ1dGVFcnJvcjoKICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCJBRl9QQUNLRVQgdW5hdmFpbGFibGUgb24gdGhpcyBwbGF0Zm9ybSIpCiAgICBl
eGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiY2Fubm90
IG9wZW4gQUZfUEFDS0VUIHNvY2tldCAoJXMpIOKAlCBuZWVkICIKICAgICAgICAgICAgICAgICAg
ICAgICAgICJDQVBfTkVUX1JBVyAvIHJvb3QiICUgZSkKICAgIHMuc2V0dGltZW91dCgxLjApCiAg
ICBpZiBub3QgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKToKICAgICAgICBzLmNsb3NlKCkKICAg
ICAgICByYWlzZSBTeXN0ZW1FeGl0KCJrZXJuZWwgQlBGIHNhZmV0eSBmaWx0ZXIgdW5hdmFpbGFi
bGU7IHJlZnVzaW5nIHVuZmlsdGVyZWQgY2FwdHVyZSIpCiAgICB0cnk6CiAgICAgICAgcy5iaW5k
KChpZmFjZSBvciAiIiwgRVRIX1BfQUxMKSkKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToK
ICAgICAgICBzLmNsb3NlKCkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5ub3QgYmluZCBB
Rl9QQUNLRVQgdG8gJXMgKCVzKSIgJQogICAgICAgICAgICAgICAgICAgICAgICAgKGlmYWNlIG9y
ICI8YWxsPiIsIGUpKQogICAgaWYgbm90IGRyb3BfY2FwdHVyZV9jYXBhYmlsaXRpZXMoKToKICAg
ICAgICBzLmNsb3NlKCkKICAgICAgICByYWlzZSBTeXN0ZW1FeGl0KCJjYW5ub3QgZHJvcCBDQVBf
TkVUX1JBVyBhZnRlciBzb2NrZXQgc2V0dXA7IHJlZnVzaW5nIHVuc2FmZSBjYXB0dXJlIikKCiAg
ICAjIHByZWNvbXBpbGVkIHN0cnVjdCByZWFkZXJzIOKAlCB1bnBhY2tfZnJvbSByZWFkcyBzdHJh
aWdodCBvdXQgb2YgdGhlCiAgICAjIHBhY2tldCBidWZmZXIgKG5vIHNsaWNlIGNvcGllcykgYW5k
IHlpZWxkcyBpbnRzIHVuZGVyIHB5MiBBTkQgcHkzCiAgICB1MTYgPSBzdHJ1Y3QuU3RydWN0KCIh
SCIpLnVucGFja19mcm9tCiAgICB1aCA9IHN0cnVjdC5TdHJ1Y3QoIiFISCIpLnVucGFja19mcm9t
ICAgIyBzcG9ydCxkcG9ydCBpbiBvbmUgcmVhZAogICAgdWIgPSBzdHJ1Y3QuU3RydWN0KCIhQkIi
KS51bnBhY2tfZnJvbQogICAgbnRvYSA9IHNvY2tldC5pbmV0X250b2EKCiAgICBmbG93cyA9IHt9
CiAgICBydW5uaW5nID0gW1RydWVdCgogICAgZGVmIHN0b3Aoc2lnbnVtLCBmcmFtZSk6CiAgICAg
ICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLCBz
dG9wKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBzdG9wKQoKICAgIGxhc3Rfc3dl
ZXAgPSB0aW1lLnRpbWUoKQogICAgY29udHJvbF9uZXh0ID0gdGltZS50aW1lKCkKICAgIGxvZygi
bGlzdGVuaW5nIG9uICVzIHBvcnRzPSVzIHBpZD0lZCIgJQogICAgICAgIChpZmFjZSBvciAiPGFs
bD4iLCBzb3J0ZWQocG9ydHMpLCBvcy5nZXRwaWQoKSkpCiAgICBpZiB3c3NlX2JvZHlfYnl0ZXM6
CiAgICAgICAgbG9nKCJXU1NFIFVzZXJuYW1lVG9rZW4gaW5zcGVjdGlvbiBlbmFibGVkIChib3Vu
ZGVkIHRvICVkIGJ5dGVzL3JlcXVlc3QpIiAlCiAgICAgICAgICAgIHdzc2VfYm9keV9ieXRlcykK
CiAgICAjIDFzIHJlY3YgdGltZW91dDogKGEpIGxldHMgdGhlIHBlbmRpbmcvZmxvdyBzd2VlcHMg
YWN0dWFsbHkgZmlyZSDigJQKICAgICMgd2l0aG91dCBpdCBgZXhjZXB0IHNvY2tldC50aW1lb3V0
YCBuZXZlciBydW5zOyAoYikgZW1waXJpY2FsbHkgUkVRVUlSRUQKICAgICMgd2l0aCB0aGUgQlBG
IGZpbHRlciBhdHRhY2hlZDogYSBmdWxseS1ibG9ja2luZyByZWN2IG9uIHRoaXMga2VybmVsCiAg
ICAjIHN0YXJ2ZXMgYWZ0ZXIgdGhlIGZpcnN0IHBhY2tldCwgd2hpbGUgdGhlIHRpbWVvdXQnZCBy
ZWN2IGRlbGl2ZXJzCiAgICAjIGNvbnRpbnVvdXNseSAodmVyaWZpZWQgYnkgQS9COiByeD0xIHZz
IHJ4PTI5IGlkZW50aWNhbCBvdGhlcndpc2UpLgogICAgcy5zZXR0aW1lb3V0KDEuMCkKCiAgICBk
YmcgPSBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfREVCVUciKSA9PSAiMSIKICAgIGRiZ19yeCA9
IDAKICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF06CiAgICAg
ICAgIyBQb2xsIGluZGVwZW5kZW50bHkgb2Ygc29ja2V0IGlkbGUgdGltZS4gQSBidXN5IG1vbml0
b3JlZCBpbnRlcmZhY2UKICAgICAgICAjIG1heSBuZXZlciByYWlzZSBzb2NrZXQudGltZW91dCwg
YnV0IGNvbnRyb2wgY2hhbmdlcyBtdXN0IHN0aWxsIGFwcGx5LgogICAgICAgIGlmIGNvbnRyb2xf
Y2xpZW50IGlzIG5vdCBOb25lIGFuZCB0aW1lLnRpbWUoKSA+PSBjb250cm9sX25leHQ6CiAgICAg
ICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwgY29udHJvbF9hY3Rpb24s
IGNvbnRyb2xfc3RhdHVzID0gX3J1bl9jb250cm9sX3RpY2soCiAgICAgICAgICAgICAgICAgICAg
cG9ydHMsIGlmYWNlLCBjb250cm9sX3J1biwgY29udHJvbF9jbGllbnQpCiAgICAgICAgICAgICAg
ICBsb2coInJlbW90ZSBjb250cm9sOiAlcyIgJSBjb250cm9sX3N0YXR1cykKICAgICAgICAgICAg
ICAgIGlmIGNvbnRyb2xfYWN0aW9uID09ICJyZXN0YXJ0IjoKICAgICAgICAgICAgICAgICAgICBh
cmdzID0gX3Jlc3RhcnRfYXJncyhzeXMuYXJndlswXSwgaWZhY2UsIHBvcnRzLAogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcmJvc2UsIHdvcmtlcnMsIHdzc2VfYm9k
eV9ieXRlcykKICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiByZS1leGVj
dXRpbmcgY2FwdHVyZSB3aXRoIHVwZGF0ZWQgY29uZmlndXJhdGlvbiIpCiAgICAgICAgICAgICAg
ICAgICAgcy5jbG9zZSgpCiAgICAgICAgICAgICAgICAgICAgb3MuZXhlY3Yoc3lzLmV4ZWN1dGFi
bGUsIGFyZ3MpCiAgICAgICAgICAgICAgICBlbGlmIGNvbnRyb2xfYWN0aW9uID09ICJzdG9wIjoK
ICAgICAgICAgICAgICAgICAgICBsb2coInJlbW90ZSBjb250cm9sOiBzdG9wIHJlcXVlc3RlZDsg
ZXhpdGluZyIpCiAgICAgICAgICAgICAgICAgICAgcnVubmluZ1swXSA9IEZhbHNlCiAgICAgICAg
ICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgog
ICAgICAgICAgICAgICAgbG9nKCJXQVJOOiByZW1vdGUgY29udHJvbCB0aWNrIGZhaWxlZCAoJXMp
IiAlIG50X2NvbnRyb2wuc2FmZV9tZXNzYWdlKGUpKQogICAgICAgICAgICBjb250cm9sX25leHQg
PSB0aW1lLnRpbWUoKSArIGNvbnRyb2xfaW50ZXJ2YWwKICAgICAgICB0cnk6CiAgICAgICAgICAg
IHBrdCA9IHMucmVjdig2NTUzNSkKICAgICAgICAgICAgZGJnX3J4ICs9IDEKICAgICAgICAgICAg
aWYgZGJnIGFuZCB0aW1lLnRpbWUoKSAtIGRiZ19sYXN0ID4gNToKICAgICAgICAgICAgICAgIGxv
ZygiREVCVUcgcng9JWQiICUgZGJnX3J4KQogICAgICAgICAgICAgICAgZGJnX2xhc3QgPSB0aW1l
LnRpbWUoKQogICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICAgICAgaWYgZGJn
OgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAg
ICAgICAgICAgICAgIGRiZ19sYXN0ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgbm93ID0gdGlt
ZS50aW1lKCkKICAgICAgICAgICAgaWYgbWFpbnRlbmFuY2VfZHVlKG5vdywgbGFzdF9zd2VlcCk6
CiAgICAgICAgICAgICAgICBzd2VlcF9pZGxlKGZsb3dzLCBub3cpCiAgICAgICAgICAgICAgICBv
dXRfcyA9IFtdCiAgICAgICAgICAgICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0
X3MpCiAgICAgICAgICAgICAgICBmb3IgZXYgaW4gb3V0X3M6CiAgICAgICAgICAgICAgICAgICAg
c3lzLnN0ZG91dC53cml0ZShqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgICAgICBp
ZiBvdXRfczoKICAgICAgICAgICAgICAgICAgICBzeXMuc3Rkb3V0LmZsdXNoKCkKICAgICAgICAg
ICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKICAgICAgICAgICAgY29udGludWUKICAgICAgICBleGNl
cHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgICAgIGlmIGUuZXJybm8gPT0gZXJybm8uRUlO
VFI6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICByYWlzZQogICAgICAgIG4g
PSBsZW4ocGt0KQogICAgICAgIGlmIG4gPCAzNDoKICAgICAgICAgICAgY29udGludWUKICAgICAg
ICBvdXQgPSBbXQogICAgICAgIG9mZiA9IDE0ICAgICAgICAgICAgICAgICAgICAgICMgZXRoZXJu
ZXQgaGVhZGVyCiAgICAgICAgZXR5cGUgPSB1MTYocGt0LCAxMilbMF0KICAgICAgICBpZiBldHlw
ZSA9PSBFVEhfUF9WTEFOOgogICAgICAgICAgICBldHlwZSA9IHUxNihwa3QsIDE2KVswXQogICAg
ICAgICAgICBvZmYgPSAxOAogICAgICAgIGVsaWYgZXR5cGUgIT0gRVRIX1BfSVA6CiAgICAgICAg
ICAgIGNvbnRpbnVlICAgICAgICAgICAgICAgICAgIyB3aXRoIEJQRiBhdHRhY2hlZCB0aGlzIGlz
IHJhcmUKICAgICAgICBpcDAgPSB1Yihwa3QsIG9mZilbMF0KICAgICAgICBpZiBpcDAgPj4gNCAh
PSA0IG9yIHViKHBrdCwgb2ZmICsgOSlbMF0gIT0gNjogICAjIElQdjQgVENQIG9ubHkKICAgICAg
ICAgICAgY29udGludWUKICAgICAgICBpaGwgPSAoaXAwICYgMHgwRikgKiA0CiAgICAgICAgZnJh
ZyA9IHUxNihwa3QsIG9mZiArIDYpWzBdCiAgICAgICAgaWYgZnJhZyAmIDB4MUZGRjogICAgICAg
ICAgICAgICAgICAgICAgICAgIyBub24tZmlyc3QgZnJhZ21lbnQKICAgICAgICAgICAgY29udGlu
dWUKICAgICAgICBzcmNfaXAgPSBudG9hKHBrdFtvZmYgKyAxMjpvZmYgKyAxNl0pCiAgICAgICAg
ZHN0X2lwID0gbnRvYShwa3Rbb2ZmICsgMTY6b2ZmICsgMjBdKQogICAgICAgIHRjcF9vZmYgPSBv
ZmYgKyBpaGwKICAgICAgICBzcG9ydCwgZHBvcnQgPSB1aChwa3QsIHRjcF9vZmYpCiAgICAgICAg
ZG9mZl9mbGFncyA9IHViKHBrdCwgdGNwX29mZiArIDEyKQogICAgICAgIGRvZmYgPSAoZG9mZl9m
bGFnc1swXSA+PiA0KSAqIDQKICAgICAgICBwYXlfc3RhcnQgPSB0Y3Bfb2ZmICsgZG9mZgogICAg
ICAgIGlmIG4gPD0gcGF5X3N0YXJ0OgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICMgbm8gcGF5bG9hZCBpbiBzZWdtZW50CiAgICAgICAgcGF5bG9hZCA9
IHBrdFtwYXlfc3RhcnQ6XQogICAgICAgIGZsYWdzID0gZG9mZl9mbGFnc1sxXQogICAgICAgIG5v
dyA9IHRpbWUudGltZSgpCgogICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLSBSRVNQT05TRSBkaXJl
Y3Rpb24gKHNlcnZlciAtPiBjbGllbnQpIC0tLS0tLS0tLS0KICAgICAgICBpZiBzcG9ydCBpbiBw
b3J0cyBhbmQgZHBvcnQgbm90IGluIHBvcnRzOgogICAgICAgICAgICAjIHBlbmRpbmcga2V5IHdh
cyBzdG9yZWQgYXMgKHNlcnZlcl9pcCwgc2VydmVyX3BvcnQsIGNsaWVudF9pcCwKICAgICAgICAg
ICAgIyBjbGllbnRfcG9ydCkgPT0gKHNyYywgc3BvcnQsIGRzdCwgZHBvcnQpIE9GIFRISVMgcmVz
cG9uc2UgcGt0CiAgICAgICAgICAgIHJrID0gKHNyY19pcCwgc3BvcnQsIGRzdF9pcCwgZHBvcnQp
CiAgICAgICAgICAgIGlmIHBheWxvYWRbOjVdID09IGIiSFRUUC8iOgogICAgICAgICAgICAgICAg
Y29ycmVsYXRlX3Jlc3BvbnNlKHBlbmRpbmcsIHJrLCBwYXlsb2FkLCBub3csIG91dCkKICAgICAg
ICAgICAgZWxpZiBmbGFncyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgRklOfFJTVDog
Zmx1c2ggdW5tYXRjaGVkCiAgICAgICAgICAgICAgICBldiA9IHBlbmRpbmdfcG9wKHJrLCBvdXQp
CiAgICAgICAgIyAtLS0tLS0tLS0tLS0tLS0tIFJFUVVFU1QgZGlyZWN0aW9uIChjbGllbnQgLT4g
c2VydmVyKSAtLS0tLS0tLS0tLQogICAgICAgIGVsaWYgZHBvcnQgaW4gcG9ydHM6CiAgICAgICAg
ICAgIGlmIGZsYWdzICYgMHgwNTogICAgICAgICAgICAgICAgICAgICAgIyB0ZWFyZG93biB3L28g
cmVzcG9uc2Ugc2VlbgogICAgICAgICAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lw
LCBzcG9ydCkKICAgICAgICAgICAgICAgIHBlbmRpbmdfcG9wKHJrLCBvdXQpCiAgICAgICAgICAg
IGtleSA9IChzcmNfaXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBoYW5kbGVf
cGF5bG9hZChmbG93cywga2V5LCBOb25lLCBwYXlsb2FkLAogICAgICAgICAgICAgICAgICAgICAg
ICAgICAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCksCiAgICAgICAgICAgICAgICAgICAg
ICAgICAgIHBvcnRzLCBub2RlX2hvc3QsIG91dCwgcGVuZGluZywgbm93LAogICAgICAgICAgICAg
ICAgICAgICAgICAgICB3c3NlX2JvZHlfYnl0ZXMpCiAgICAgICAgaWYgb3V0OgogICAgICAgICAg
ICB3ID0gc3lzLnN0ZG91dC53cml0ZQogICAgICAgICAgICBmb3IgZXYgaW4gb3V0OgogICAgICAg
ICAgICAgICAgdyhqc29uLmR1bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgIHN5cy5zdGRvdXQu
Zmx1c2goKQoKICAgICAgICBpZiBtYWludGVuYW5jZV9kdWUobm93LCBsYXN0X3N3ZWVwKToKICAg
ICAgICAgICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgICAgICAgICBvdXRfcyA9IFtdCiAg
ICAgICAgICAgIHN3ZWVwX3BlbmRpbmcocGVuZGluZywgbm93LCBvdXRfcykKICAgICAgICAgICAg
Zm9yIGV2IGluIG91dF9zOgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0ZShqc29uLmR1
bXBzKGV2KSArICJcbiIpCiAgICAgICAgICAgIGlmIG91dF9zOgogICAgICAgICAgICAgICAgc3lz
LnN0ZG91dC5mbHVzaCgpCiAgICAgICAgICAgIGxhc3Rfc3dlZXAgPSBub3cKCiAgICBvdXRfcyA9
IFtdCiAgICBkcmFpbl9wZW5kaW5nKHBlbmRpbmcsIG91dF9zKQogICAgZm9yIGV2IGluIG91dF9z
OgogICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1wcyhldikgKyAiXG4iKQogICAgaWYg
b3V0X3M6CiAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICBsb2coInN0b3BwZWQgKCVkIHBl
bmRpbmcgcmVxdWVzdHMgZmx1c2hlZCkiICUgbGVuKG91dF9zKSkKCgppZiBfX25hbWVfXyA9PSAi
X19tYWluX18iOgogICAgbWFpbigpCg==
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
ZV90IE1BWF9RVUVVRSA9IDQwMDA7CnN0YXRpYyBjb25zdCBpbnQgRkxVU0hfU0VDID0gNTsKc3Rh
dGljIGNvbnN0IGludCBSRVRSWV9TRUMgPSA2MDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIEZMT1df
VFRMID0gMTU7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBQRU5ESU5HX1RUTCA9IDM7CnN0YXRpYyBj
b25zdCB1bnNpZ25lZCBBQ0NFUFQgPSAyMDQ4OwpzdGF0aWMgY29uc3QgaW50IFNPX0FUVEFDSF9G
SUxURVJfT0xEID0gMjY7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBFVEhfUF9JUF9IT1NU
ID0gMHgwODAwOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgc2hvcnQgRVRIX1BfODAyMVFfSE9TVCA9
IDB4ODEwMDsKCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmltKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7
CiAgc2l6ZV90IGEgPSAwLCBiID0gcy5zaXplKCk7CiAgd2hpbGUgKGEgPCBiICYmIGlzc3BhY2Uo
KHVuc2lnbmVkIGNoYXIpc1thXSkpICsrYTsKICB3aGlsZSAoYiA+IGEgJiYgaXNzcGFjZSgodW5z
aWduZWQgY2hhcilzW2IgLSAxXSkpIC0tYjsKICByZXR1cm4gcy5zdWJzdHIoYSwgYiAtIGEpOwp9
CnN0YXRpYyBzdGQ6OnN0cmluZyBsb3dlcihjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6
c3RyaW5nIHggPSBzOwogIHNpemVfdCBpOyBmb3IgKGkgPSAwOyBpIDwgeC5zaXplKCk7ICsraSkg
eFtpXSA9IChjaGFyKXRvbG93ZXIoKHVuc2lnbmVkIGNoYXIpeFtpXSk7CiAgcmV0dXJuIHg7Cn0K
c3RhdGljIHN0ZDo6c3RyaW5nIGpzb25xKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpz
dHJpbmcgeCA9ICJcIiI7IHNpemVfdCBpOwogIGZvciAoaSA9IDA7IGkgPCBzLnNpemUoKTsgKytp
KSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgaWYgKGMg
PT0gJ1xcJyB8fCBjID09ICciJykgeyB4ICs9ICdcXCc7IHggKz0gKGNoYXIpYzsgfQogICAgZWxz
ZSBpZiAoYyA9PSAnXG4nKSB4ICs9ICJcXG4iOwogICAgZWxzZSBpZiAoYyA9PSAnXHInKSB4ICs9
ICJcXHIiOwogICAgZWxzZSBpZiAoYyA9PSAnXHQnKSB4ICs9ICJcXHQiOwogICAgZWxzZSBpZiAo
YyA8IDMyKSB4ICs9ICc/JzsKICAgIGVsc2UgeCArPSAoY2hhciljOwogIH0KICB4ICs9ICciJzsg
cmV0dXJuIHg7Cn0Kc3RhdGljIGxvbmcgbG9uZyBub3dfbXMoKSB7CiAgc3RydWN0IHRpbWV2YWwg
dHY7IGdldHRpbWVvZmRheSgmdHYsIE5VTEwpOwogIHJldHVybiAobG9uZyBsb25nKXR2LnR2X3Nl
YyAqIDEwMDBMTCArIHR2LnR2X3VzZWMgLyAxMDAwOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBudW0o
bG9uZyB2KSB7IHN0ZDo6b3N0cmluZ3N0cmVhbSBvOyBvIDw8IHY7IHJldHVybiBvLnN0cigpOyB9
CnN0YXRpYyBib29sIHZhbGlkX3BvcnQodW5zaWduZWQgcCkgeyByZXR1cm4gcCA+IDAgJiYgcCA8
PSA2NTUzNTsgfQpzdGF0aWMgYm9vbCBoYXNfbWV0aG9kKGNvbnN0IHN0ZDo6c3RyaW5nICZtKSB7
CiAgcmV0dXJuIG0gPT0gIkdFVCIgfHwgbSA9PSAiUE9TVCIgfHwgbSA9PSAiUFVUIiB8fCBtID09
ICJERUxFVEUiIHx8CiAgICAgICAgIG0gPT0gIlBBVENIIiB8fCBtID09ICJIRUFEIiB8fCBtID09
ICJPUFRJT05TIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgaG9zdF9uYW1lKCkgewogIGNoYXIgYlsy
NTZdOyBpZiAoZ2V0aG9zdG5hbWUoYiwgc2l6ZW9mKGIpIC0gMSkgIT0gMCkgcmV0dXJuICJ1bmtu
b3duLW5vZGUiOwogIGJbc2l6ZW9mKGIpIC0gMV0gPSAwOyBjaGFyICpwID0gc3RyY2hyKGIsICcu
Jyk7IGlmIChwKSAqcCA9IDA7IHJldHVybiBiOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBiNjRkZWNv
ZGVfdXNlcihjb25zdCBjaGFyICppbiwgc2l6ZV90IGluX2xlbikgewogIHdoaWxlIChpbl9sZW4g
PiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpKmluKSkgeyArK2luOyAtLWluX2xlbjsgfQog
IHdoaWxlIChpbl9sZW4gPiAwICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpaW5baW5fbGVuIC0g
MV0pKSB7IC0taW5fbGVuOyB9CiAgc3RkOjpzdHJpbmcgb3V0OyBpbnQgdmFsID0gMCwgYml0cyA9
IC04OyBzaXplX3QgaTsKICBmb3IgKGkgPSAwOyBpIDwgaW5fbGVuOyArK2kpIHsKICAgIHVuc2ln
bmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKWluW2ldOyBpbnQgZCA9IC0xOwogICAgaWYgKGMg
Pj0gJ0EnICYmIGMgPD0gJ1onKSBkID0gYyAtICdBJzsKICAgIGVsc2UgaWYgKGMgPj0gJ2EnICYm
IGMgPD0gJ3onKSBkID0gYyAtICdhJyArIDI2OwogICAgZWxzZSBpZiAoYyA+PSAnMCcgJiYgYyA8
PSAnOScpIGQgPSBjIC0gJzAnICsgNTI7CiAgICBlbHNlIGlmIChjID09ICcrJykgZCA9IDYyOwog
ICAgZWxzZSBpZiAoYyA9PSAnLycpIGQgPSA2MzsKICAgIGVsc2UgaWYgKGMgPT0gJz0nKSBicmVh
azsKICAgIGlmIChkIDwgMCkgY29udGludWU7CiAgICB2YWwgPSAodmFsIDw8IDYpICsgZDsKICAg
IGJpdHMgKz0gNjsKICAgIGlmIChiaXRzID49IDApIHsKICAgICAgb3V0ICs9IChjaGFyKSgodmFs
ID4+IGJpdHMpICYgMHhmZik7CiAgICAgIGJpdHMgLT0gODsKICAgICAgaWYgKG91dC5zaXplKCkg
PiA1MTIpIHJldHVybiAiIjsKICAgIH0KICB9CiAgc2l6ZV90IHAgPSBvdXQuZmluZCgnOicpOwog
IGlmIChwID09IHN0ZDo6c3RyaW5nOjpucG9zKSByZXR1cm4gIiI7CiAgcmV0dXJuIG91dC5zdWJz
dHIoMCwgcCA+IDY0ID8gNjQgOiBwKTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgaXBfdG9fc3RyKHVp
bnQzMl90IGlwX2JlKSB7CiAgY2hhciBiW0lORVRfQUREUlNUUkxFTl07CiAgaW5ldF9udG9wKEFG
X0lORVQsICZpcF9iZSwgYiwgc2l6ZW9mKGIpKTsKICByZXR1cm4gYjsKfQoKc3RhdGljIHN0ZDo6
c3RyaW5nIHRyYWNlX2lkX2Zyb21fcGFyZW50KGNvbnN0IHN0ZDo6c3RyaW5nICZ0cCkgewogIHN0
ZDo6c3RyaW5nIHggPSB0cmltKHRwKTsKICBpZiAoeC5zaXplKCkgPT0gNTUgJiYgeFsyXSA9PSAn
LScgJiYgeFszNV0gPT0gJy0nICYmIHhbNTJdID09ICctJykgcmV0dXJuIGxvd2VyKHguc3Vic3Ry
KDMsIDMyKSk7CiAgcmV0dXJuICIiOwp9CgpzdGF0aWMgdWludDY0X3QgZ19ybmdfc3RhdGUgPSAw
OwpzdGF0aWMgdm9pZCBpbml0X3JuZygpIHsKICBGSUxFICpmID0gZm9wZW4oIi9kZXYvdXJhbmRv
bSIsICJyYiIpOwogIGlmIChmKSB7CiAgICBzaXplX3QgbiA9IGZyZWFkKCZnX3JuZ19zdGF0ZSwg
MSwgc2l6ZW9mKGdfcm5nX3N0YXRlKSwgZik7CiAgICAodm9pZCluOwogICAgZmNsb3NlKGYpOwog
IH0KICBpZiAoIWdfcm5nX3N0YXRlKSB7CiAgICBnX3JuZ19zdGF0ZSA9ICgodWludDY0X3QpdGlt
ZShOVUxMKSA8PCAzMikgXiAodWludDY0X3QpZ2V0cGlkKCk7CiAgfQp9CnN0YXRpYyBpbmxpbmUg
dWludDY0X3QgbmV4dF9ybmcoKSB7CiAgdWludDY0X3QgeCA9IGdfcm5nX3N0YXRlOwogIHggXj0g
eCA8PCAxMzsgeCBePSB4ID4+IDc7IHggXj0geCA8PCAxNzsKICByZXR1cm4gZ19ybmdfc3RhdGUg
PSAoeCA/IHggOiAweDg1M2M0OWU2NzQ4ZmVhOWJVTEwpOwp9CgpzdGF0aWMgc3RkOjpzdHJpbmcg
bWFrZV90cmFjZXBhcmVudChzdGQ6OnN0cmluZyAqdGlkKSB7CiAgdWludDY0X3QgcjEgPSBuZXh0
X3JuZygpOwogIHVpbnQ2NF90IHIyID0gbmV4dF9ybmcoKTsKICB1aW50NjRfdCByMyA9IG5leHRf
cm5nKCk7CiAgY2hhciBidWZbNjRdOwogIHNucHJpbnRmKGJ1Ziwgc2l6ZW9mKGJ1ZiksICIwMC0l
MDE2bGx4JTAxNmxseC0lMDE2bGx4LTAxIiwKICAgICAgICAgICAodW5zaWduZWQgbG9uZyBsb25n
KXIxLCAodW5zaWduZWQgbG9uZyBsb25nKXIyLCAodW5zaWduZWQgbG9uZyBsb25nKXIzKTsKICBj
aGFyIHRpZF9idWZbMzNdOwogIHNucHJpbnRmKHRpZF9idWYsIHNpemVvZih0aWRfYnVmKSwgIiUw
MTZsbHglMDE2bGx4IiwKICAgICAgICAgICAodW5zaWduZWQgbG9uZyBsb25nKXIxLCAodW5zaWdu
ZWQgbG9uZyBsb25nKXIyKTsKICAqdGlkID0gdGlkX2J1ZjsKICByZXR1cm4gYnVmOwp9CgpzdHJ1
Y3QgRXZlbnQgewogIGxvbmcgdHM7IHN0ZDo6c3RyaW5nIGhvc3QsIHNyYywgc2VydmljZSwgbWV0
aG9kLCBwYXRoLCB1c2VyLCBzY2hlbWUsIHByb2JlOwogIHN0ZDo6c3RyaW5nIGhvc3RfaGRyLCB1
c2VyX2FnZW50LCB4ZmYsIGNhbGxlciwgZHN0X2lwLCB0cmFjZXBhcmVudCwgdHJhY2VfaWQ7CiAg
dW5zaWduZWQgY2FsbGVyX3BvcnQsIGRzdF9wb3J0LCByZXFfYnl0ZXMsIHJlc3BfYnl0ZXM7IGlu
dCBzdGF0dXM7IGxvbmcgZHVyYXRpb25fbXM7CiAgYm9vbCBoYXNfc3RhdHVzLCBoYXNfZHVyYXRp
b24sIGhhc19yZXNwOwogIEV2ZW50KCkgOiB0cygwKSwgY2FsbGVyX3BvcnQoMCksIGRzdF9wb3J0
KDApLCByZXFfYnl0ZXMoMCksIHJlc3BfYnl0ZXMoMCksIHN0YXR1cygwKSwgZHVyYXRpb25fbXMo
MCksIGhhc19zdGF0dXMoZmFsc2UpLCBoYXNfZHVyYXRpb24oZmFsc2UpLCBoYXNfcmVzcChmYWxz
ZSkge30KfTsKc3RydWN0IFJlcXVlc3RNZXRhIHsKICBzdGQ6OnN0cmluZyBjb250ZW50X3R5cGUs
IHRyYW5zZmVyX2VuY29kaW5nOwogIHNpemVfdCBjb250ZW50X2xlbmd0aDsKICBib29sIGhhc19j
b250ZW50X2xlbmd0aDsKICBSZXF1ZXN0TWV0YSgpIDogY29udGVudF9sZW5ndGgoMCksIGhhc19j
b250ZW50X2xlbmd0aChmYWxzZSkge30KfTsKc3RydWN0IEZsb3cgewogIHN0ZDo6c3RyaW5nIGJ1
ZjsKICB0aW1lX3QgdG91Y2hlZDsKICBFdmVudCBldmVudDsKICBzaXplX3QgYm9keV9nb2FsOwog
IGJvb2wgYXdhaXRpbmdfYm9keTsKICBGbG93KCkgOiB0b3VjaGVkKHRpbWUoTlVMTCkpLCBib2R5
X2dvYWwoMCksIGF3YWl0aW5nX2JvZHkoZmFsc2UpIHt9Cn07CnN0cnVjdCBQZW5kaW5nIHsKICBF
dmVudCBldjsKICBsb25nIGxvbmcgc3RhcnRlZF9tczsKICBQZW5kaW5nKCkgOiBzdGFydGVkX21z
KDApIHt9CiAgUGVuZGluZyhjb25zdCBFdmVudCAmZSwgbG9uZyBsb25nIHQpIDogZXYoZSksIHN0
YXJ0ZWRfbXModCkge30KfTsKc3RydWN0IEZsb3dLZXkgewogIHVpbnQzMl90IHNfaXA7CiAgdWlu
dDE2X3Qgc3BvcnQ7CiAgdWludDMyX3QgZF9pcDsKICB1aW50MTZfdCBkcG9ydDsKICBib29sIG9w
ZXJhdG9yPChjb25zdCBGbG93S2V5ICZ4KSBjb25zdCB7CiAgICBpZiAoc19pcCAhPSB4LnNfaXAp
IHJldHVybiBzX2lwIDwgeC5zX2lwOwogICAgaWYgKHNwb3J0ICE9IHguc3BvcnQpIHJldHVybiBz
cG9ydCA8IHguc3BvcnQ7CiAgICBpZiAoZF9pcCAhPSB4LmRfaXApIHJldHVybiBkX2lwIDwgeC5k
X2lwOwogICAgcmV0dXJuIGRwb3J0IDwgeC5kcG9ydDsKICB9Cn07CnR5cGVkZWYgRmxvd0tleSBQ
YWNrZXRLZXk7CgpzdGF0aWMgdm9pZCBsb2dtc2coY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsgZnBy
aW50ZihzdGRlcnIsICJudC1zbmlmZi1jcHA6ICVzXG4iLCBzLmNfc3RyKCkpOyBmZmx1c2goc3Rk
ZXJyKTsgfQoKc3RhdGljIGJvb2wgcGFyc2VfZGVjaW1hbF9zaXplKGNvbnN0IGNoYXIgKnAsIHNp
emVfdCBuLCBzaXplX3QgKm91dCkgewogIHdoaWxlIChuICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNo
YXIpKnApKSB7ICsrcDsgLS1uOyB9CiAgd2hpbGUgKG4gJiYgaXNzcGFjZSgodW5zaWduZWQgY2hh
cilwW24gLSAxXSkpIC0tbjsKICBpZiAoIW4pIHJldHVybiBmYWxzZTsKICBzaXplX3QgdmFsdWUg
PSAwOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgbjsgKytpKSB7CiAgICBpZiAocFtpXSA8ICcw
JyB8fCBwW2ldID4gJzknKSByZXR1cm4gZmFsc2U7CiAgICB1bnNpZ25lZCBkaWdpdCA9ICh1bnNp
Z25lZCkocFtpXSAtICcwJyk7CiAgICBpZiAodmFsdWUgPiAoc2l6ZV90KS0xIC8gMTAgfHwgdmFs
dWUgKiAxMCA+IChzaXplX3QpLTEgLSBkaWdpdCkgcmV0dXJuIGZhbHNlOwogICAgdmFsdWUgPSB2
YWx1ZSAqIDEwICsgZGlnaXQ7CiAgfQogICpvdXQgPSB2YWx1ZTsKICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIGJvb2wgcGFyc2VfcmVxdWVzdChjb25zdCBjaGFyICpkYXRhLCBzaXplX3QgbGVuLCBF
dmVudCAqZSwgUmVxdWVzdE1ldGEgKm1ldGEpIHsKICBjb25zdCBjaGFyICplbmQgPSBkYXRhICsg
bGVuOwogIGNvbnN0IGNoYXIgKnAgPSBkYXRhOwogIGNvbnN0IGNoYXIgKmVvbCA9IChjb25zdCBj
aGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogIGlmICghZW9sKSByZXR1cm4gZmFsc2U7
CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJyAnLCBlb2wgLSBw
KTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGUtPm1ldGhvZC5hc3NpZ24ocCwgc3AxIC0g
cCk7CiAgaWYgKCFoYXNfbWV0aG9kKGUtPm1ldGhvZCkpIHJldHVybiBmYWxzZTsKCiAgY29uc3Qg
Y2hhciAqcGF0aF9zdGFydCA9IHNwMSArIDE7CiAgd2hpbGUgKHBhdGhfc3RhcnQgPCBlb2wgJiYg
KnBhdGhfc3RhcnQgPT0gJyAnKSArK3BhdGhfc3RhcnQ7CiAgY29uc3QgY2hhciAqc3AyID0gKGNv
bnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJyAnLCBlb2wgLSBwYXRoX3N0YXJ0KTsKICBp
ZiAoIXNwMikgc3AyID0gKGVvbCA+IGRhdGEgJiYgKihlb2wgLSAxKSA9PSAnXHInKSA/IGVvbCAt
IDEgOiBlb2w7CiAgY29uc3QgY2hhciAqcW1hcmsgPSAoY29uc3QgY2hhciAqKW1lbWNocihwYXRo
X3N0YXJ0LCAnPycsIHNwMiAtIHBhdGhfc3RhcnQpOwogIHNpemVfdCBwYXRoX2xlbiA9IChxbWFy
ayA/IHFtYXJrIDogc3AyKSAtIHBhdGhfc3RhcnQ7CiAgaWYgKHBhdGhfbGVuID4gMTIwKSBwYXRo
X2xlbiA9IDEyMDsKICBlLT5wYXRoLmFzc2lnbihwYXRoX3N0YXJ0LCBwYXRoX2xlbik7CgogIHAg
PSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBpZiAoKnAgPT0gJ1xyJyB8fCAqcCA9
PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5kID0gKGNvbnN0IGNoYXIgKilt
ZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVfZW5kKSBsaW5lX2VuZCA9IGVu
ZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJzonLCBs
aW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAgIHNpemVfdCBobmFtZV9sZW4gPSBj
b2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9zdGFydCA9IGNvbG9uICsgMTsKICAgICAg
d2hpbGUgKHZhbF9zdGFydCA8IGxpbmVfZW5kICYmICgqdmFsX3N0YXJ0ID09ICcgJyB8fCAqdmFs
X3N0YXJ0ID09ICdcdCcpKSArK3ZhbF9zdGFydDsKICAgICAgY29uc3QgY2hhciAqdmFsX2VuZCA9
IGxpbmVfZW5kOwogICAgICB3aGlsZSAodmFsX2VuZCA+IHZhbF9zdGFydCAmJiAodmFsX2VuZFst
MV0gPT0gJ1xyJyB8fCB2YWxfZW5kWy0xXSA9PSAnXG4nIHx8IHZhbF9lbmRbLTFdID09ICcgJyB8
fCB2YWxfZW5kWy0xXSA9PSAnXHQnKSkgLS12YWxfZW5kOwogICAgICBzaXplX3QgdmFsX2xlbiA9
IHZhbF9lbmQgLSB2YWxfc3RhcnQ7CgogICAgICBpZiAoaG5hbWVfbGVuID09IDEzICYmICFzdHJu
Y2FzZWNtcChwLCAiYXV0aG9yaXphdGlvbiIsIDEzKSkgewogICAgICAgIGlmICh2YWxfbGVuID4g
NiAmJiAhc3RybmNhc2VjbXAodmFsX3N0YXJ0LCAiQmFzaWMgIiwgNikpIHsKICAgICAgICAgIGUt
PnVzZXIgPSBiNjRkZWNvZGVfdXNlcih2YWxfc3RhcnQgKyA2LCB2YWxfbGVuIC0gNik7CiAgICAg
ICAgICBlLT5zY2hlbWUgPSAiYmFzaWMiOwogICAgICAgIH0gZWxzZSBpZiAodmFsX2xlbiA+IDcg
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
ICAgIG1ldGEtPmhhc19jb250ZW50X2xlbmd0aCA9IHBhcnNlX2RlY2ltYWxfc2l6ZSh2YWxfc3Rh
cnQsIHZhbF9sZW4sICZtZXRhLT5jb250ZW50X2xlbmd0aCk7CiAgICAgIH0gZWxzZSBpZiAobWV0
YSAmJiBobmFtZV9sZW4gPT0gMTcgJiYgIXN0cm5jYXNlY21wKHAsICJ0cmFuc2Zlci1lbmNvZGlu
ZyIsIDE3KSkgewogICAgICAgIG1ldGEtPnRyYW5zZmVyX2VuY29kaW5nLmFzc2lnbih2YWxfc3Rh
cnQsIHZhbF9sZW4pOwogICAgICB9CiAgICB9CiAgICBwID0gbGluZV9lbmQgKyAxOwogIH0KCiAg
aWYgKGUtPnVzZXIuZW1wdHkoKSkgZS0+dXNlciA9ICItYW5vbnltb3VzLSI7CiAgaWYgKGUtPnNj
aGVtZS5lbXB0eSgpKSBlLT5zY2hlbWUgPSAibm9uZSI7CiAgaWYgKGUtPnRyYWNlX2lkLmVtcHR5
KCkpIGUtPnRyYWNlcGFyZW50ID0gbWFrZV90cmFjZXBhcmVudCgmZS0+dHJhY2VfaWQpOwogIHJl
dHVybiB0cnVlOwp9CgpzdGF0aWMgYm9vbCBpc193c3NlX25hbWVzcGFjZShjb25zdCBzdGQ6OnN0
cmluZyAmdXJpKSB7CiAgcmV0dXJuIHVyaSA9PSAiaHR0cDovL2RvY3Mub2FzaXMtb3Blbi5vcmcv
d3NzLzIwMDQvMDEvb2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4dC0xLjAueHNkIiB8
fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDIvMDcv
c2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dz
LzIwMDIvMTIvc2VjZXh0IiB8fAogICAgICAgICB1cmkgPT0gImh0dHA6Ly9zY2hlbWFzLnhtbHNv
YXAub3JnL3dzLzIwMDMvMDYvc2VjZXh0IjsKfQoKc3RhdGljIGJvb2wgaXNfc29hcF9jb250ZW50
X3R5cGUoY29uc3Qgc3RkOjpzdHJpbmcgJnZhbHVlKSB7CiAgc3RkOjpzdHJpbmcgbWVkaWEgPSBs
b3dlcih2YWx1ZSk7CiAgc2l6ZV90IHNlbWkgPSBtZWRpYS5maW5kKCc7Jyk7CiAgaWYgKHNlbWkg
IT0gc3RkOjpzdHJpbmc6Om5wb3MpIG1lZGlhLmVyYXNlKHNlbWkpOwogIG1lZGlhID0gdHJpbSht
ZWRpYSk7CiAgcmV0dXJuIG1lZGlhID09ICJ0ZXh0L3htbCIgfHwgbWVkaWEgPT0gImFwcGxpY2F0
aW9uL3htbCIgfHwKICAgICAgICAgbWVkaWEgPT0gImFwcGxpY2F0aW9uL3NvYXAreG1sIiB8fAog
ICAgICAgICAobWVkaWEuc2l6ZSgpID4gNCAmJiBtZWRpYS5jb21wYXJlKG1lZGlhLnNpemUoKSAt
IDQsIDQsICIreG1sIikgPT0gMCk7Cn0KCnN0YXRpYyB2b2lkIHNwbGl0X3FuYW1lKGNvbnN0IHN0
ZDo6c3RyaW5nICZuYW1lLCBzdGQ6OnN0cmluZyAqcHJlZml4LCBzdGQ6OnN0cmluZyAqbG9jYWwp
IHsKICBzaXplX3QgY29sb24gPSBuYW1lLmZpbmQoJzonKTsKICBpZiAoY29sb24gPT0gc3RkOjpz
dHJpbmc6Om5wb3MpIHsgcHJlZml4LT5jbGVhcigpOyAqbG9jYWwgPSBuYW1lOyB9CiAgZWxzZSB7
ICpwcmVmaXggPSBuYW1lLnN1YnN0cigwLCBjb2xvbik7ICpsb2NhbCA9IG5hbWUuc3Vic3RyKGNv
bG9uICsgMSk7IH0KfQoKc3RhdGljIGJvb2wgYXBwZW5kX3V0ZjgodW5zaWduZWQgbG9uZyBjcCwg
c3RkOjpzdHJpbmcgKm91dCkgewogIGlmIChjcCA9PSAwIHx8IGNwID4gMHgxMGZmZmZVTCB8fCAo
Y3AgPj0gMHhkODAwVUwgJiYgY3AgPD0gMHhkZmZmVUwpKSByZXR1cm4gZmFsc2U7CiAgaWYgKGNw
IDwgMHg4MCkgb3V0LT5wdXNoX2JhY2soKGNoYXIpY3ApOwogIGVsc2UgaWYgKGNwIDwgMHg4MDAp
IHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGMwIHwgKGNwID4+IDYpKSk7CiAgICBvdXQt
PnB1c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfSBlbHNlIGlmIChjcCA8
IDB4MTAwMDApIHsKICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweGUwIHwgKGNwID4+IDEyKSkp
OwogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ODAgfCAoKGNwID4+IDYpICYgMHgzZikpKTsK
ICAgIG91dC0+cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKGNwICYgMHgzZikpKTsKICB9IGVsc2Ug
ewogICAgb3V0LT5wdXNoX2JhY2soKGNoYXIpKDB4ZjAgfCAoY3AgPj4gMTgpKSk7CiAgICBvdXQt
PnB1c2hfYmFjaygoY2hhcikoMHg4MCB8ICgoY3AgPj4gMTIpICYgMHgzZikpKTsKICAgIG91dC0+
cHVzaF9iYWNrKChjaGFyKSgweDgwIHwgKChjcCA+PiA2KSAmIDB4M2YpKSk7CiAgICBvdXQtPnB1
c2hfYmFjaygoY2hhcikoMHg4MCB8IChjcCAmIDB4M2YpKSk7CiAgfQogIHJldHVybiB0cnVlOwp9
CgpzdGF0aWMgYm9vbCB4bWxfdW5lc2NhcGUoY29uc3Qgc3RkOjpzdHJpbmcgJnRleHQsIHN0ZDo6
c3RyaW5nICpvdXQpIHsKICBmb3IgKHNpemVfdCBpID0gMDsgaSA8IHRleHQuc2l6ZSgpOykgewog
ICAgaWYgKHRleHRbaV0gIT0gJyYnKSB7IG91dC0+cHVzaF9iYWNrKHRleHRbaSsrXSk7IGNvbnRp
bnVlOyB9CiAgICBzaXplX3Qgc2VtaSA9IHRleHQuZmluZCgnOycsIGkgKyAxKTsKICAgIGlmIChz
ZW1pID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHNlbWkgLSBpID4gMTIpIHJldHVybiBmYWxzZTsK
ICAgIHN0ZDo6c3RyaW5nIGVudCA9IHRleHQuc3Vic3RyKGkgKyAxLCBzZW1pIC0gaSAtIDEpOwog
ICAgaWYgKGVudCA9PSAiYW1wIikgb3V0LT5wdXNoX2JhY2soJyYnKTsKICAgIGVsc2UgaWYgKGVu
dCA9PSAibHQiKSBvdXQtPnB1c2hfYmFjaygnPCcpOwogICAgZWxzZSBpZiAoZW50ID09ICJndCIp
IG91dC0+cHVzaF9iYWNrKCc+Jyk7CiAgICBlbHNlIGlmIChlbnQgPT0gInF1b3QiKSBvdXQtPnB1
c2hfYmFjaygnIicpOwogICAgZWxzZSBpZiAoZW50ID09ICJhcG9zIikgb3V0LT5wdXNoX2JhY2so
J1wnJyk7CiAgICBlbHNlIGlmICghZW50LmVtcHR5KCkgJiYgZW50WzBdID09ICcjJykgewogICAg
ICBjaGFyICplbmRwID0gTlVMTDsKICAgICAgdW5zaWduZWQgbG9uZyBjcCA9IHN0cnRvdWwoZW50
LmNfc3RyKCkgKyAoKGVudC5zaXplKCkgPiAxICYmIChlbnRbMV0gPT0gJ3gnIHx8IGVudFsxXSA9
PSAnWCcpKSA/IDIgOiAxKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJmVuZHAs
IChlbnQuc2l6ZSgpID4gMSAmJiAoZW50WzFdID09ICd4JyB8fCBlbnRbMV0gPT0gJ1gnKSkgPyAx
NiA6IDEwKTsKICAgICAgaWYgKCFlbmRwIHx8ICplbmRwIHx8ICFhcHBlbmRfdXRmOChjcCwgb3V0
KSkgcmV0dXJuIGZhbHNlOwogICAgfSBlbHNlIHJldHVybiBmYWxzZTsKICAgIGkgPSBzZW1pICsg
MTsKICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHZhbGlkX3V0ZjhfdXNlcm5hbWUo
Y29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBpZiAocy5lbXB0eSgpIHx8IHMuc2l6ZSgpID4gTUFY
X1dTU0VfVVNFUk5BTUUgKiA0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IGNoYXJhY3RlcnMgPSAw
OwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwgcy5zaXplKCk7KSB7CiAgICB1bnNpZ25lZCBjaGFy
IGMgPSAodW5zaWduZWQgY2hhcilzW2ldOwogICAgdW5zaWduZWQgbG9uZyBjcCA9IGM7CiAgICBp
ZiAoYyA8IDB4ODApIHsgKytpOyB9CiAgICBlbHNlIHsKICAgIHNpemVfdCBuZWVkID0gKGMgPj0g
MHhjMiAmJiBjIDw9IDB4ZGYpID8gMSA6CiAgICAgICAgICAgICAgICAgIChjID49IDB4ZTAgJiYg
YyA8PSAweGVmKSA/IDIgOgogICAgICAgICAgICAgICAgICAoYyA+PSAweGYwICYmIGMgPD0gMHhm
NCkgPyAzIDogOTk7CiAgICBpZiAobmVlZCA9PSA5OSB8fCBpICsgbmVlZCA+PSBzLnNpemUoKSkg
cmV0dXJuIGZhbHNlOwogICAgZm9yIChzaXplX3QgaiA9IDE7IGogPD0gbmVlZDsgKytqKQogICAg
ICBpZiAoKCh1bnNpZ25lZCBjaGFyKXNbaSArIGpdICYgMHhjMCkgIT0gMHg4MCkgcmV0dXJuIGZh
bHNlOwogICAgaWYgKG5lZWQgPT0gMiAmJiBjID09IDB4ZTAgJiYgKHVuc2lnbmVkIGNoYXIpc1tp
ICsgMV0gPCAweGEwKSByZXR1cm4gZmFsc2U7CiAgICBpZiAobmVlZCA9PSAyICYmIGMgPT0gMHhl
ZCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA+PSAweGEwKSByZXR1cm4gZmFsc2U7CiAgICBp
ZiAobmVlZCA9PSAzICYmIGMgPT0gMHhmMCAmJiAodW5zaWduZWQgY2hhcilzW2kgKyAxXSA8IDB4
OTApIHJldHVybiBmYWxzZTsKICAgIGlmIChuZWVkID09IDMgJiYgYyA9PSAweGY0ICYmICh1bnNp
Z25lZCBjaGFyKXNbaSArIDFdID49IDB4OTApIHJldHVybiBmYWxzZTsKICAgIGNwID0gYyAmICgo
MVUgPDwgKDcgLSBuZWVkIC0gMSkpIC0gMSk7CiAgICBmb3IgKHNpemVfdCBqID0gMTsgaiA8PSBu
ZWVkOyArK2opIGNwID0gKGNwIDw8IDYpIHwgKCh1bnNpZ25lZCBjaGFyKXNbaSArIGpdICYgMHgz
Zik7CiAgICBpICs9IG5lZWQgKyAxOwogICAgfQogICAgaWYgKCsrY2hhcmFjdGVycyA+IE1BWF9X
U1NFX1VTRVJOQU1FKSByZXR1cm4gZmFsc2U7CiAgICBpZiAoY3AgPCAweDIwIHx8IChjcCA+PSAw
eDdmICYmIGNwIDw9IDB4OWYpIHx8CiAgICAgICAgKGNwID49IDB4ZTAwMCAmJiBjcCA8PSAweGY4
ZmYpIHx8CiAgICAgICAgKGNwID49IDB4ZjAwMDAgJiYgY3AgPD0gMHhmZmZmZCkgfHwKICAgICAg
ICAoY3AgPj0gMHgxMDAwMDAgJiYgY3AgPD0gMHgxMGZmZmQpIHx8CiAgICAgICAgKGNwID49IDB4
ZmRkMCAmJiBjcCA8PSAweGZkZWYpIHx8IChjcCAmIDB4ZmZmZlVMKSA+PSAweGZmZmVVTCB8fAog
ICAgICAgIGNwID09IDB4MDBhZCB8fCBjcCA9PSAweDA2MWMgfHwgY3AgPT0gMHgwNmRkIHx8IGNw
ID09IDB4MDcwZiB8fAogICAgICAgIGNwID09IDB4MTgwZSB8fCAoY3AgPj0gMHgyMDBiICYmIGNw
IDw9IDB4MjAwZikgfHwKICAgICAgICAoY3AgPj0gMHgyMDJhICYmIGNwIDw9IDB4MjAyZSkgfHwg
KGNwID49IDB4MjA2MCAmJiBjcCA8PSAweDIwNmYpIHx8CiAgICAgICAgY3AgPT0gMHhmZWZmKSBy
ZXR1cm4gZmFsc2U7CiAgfQogIHJldHVybiB0cnVlOwp9CgpzdHJ1Y3QgWG1sRnJhbWUgewogIHN0
ZDo6bWFwPHN0ZDo6c3RyaW5nLCBzdGQ6OnN0cmluZz4gbnM7CiAgc3RkOjpzdHJpbmcgcW5hbWUs
IHVyaSwgbG9jYWw7Cn07CgpzdGF0aWMgYm9vbCBwYXJzZV94bWxfbmFtZShjb25zdCBzdGQ6OnN0
cmluZyAmYm9keSwgc2l6ZV90IGxpbWl0LCBzaXplX3QgKnBvcywKICAgICAgICAgICAgICAgICAg
ICAgICAgICAgc3RkOjpzdHJpbmcgKm5hbWUpIHsKICBzaXplX3Qgc3RhcnQgPSAqcG9zOwogIHdo
aWxlICgqcG9zIDwgbGltaXQpIHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFy
KWJvZHlbKnBvc107CiAgICBpZiAoIShpc2FsbnVtKGMpIHx8IGMgPT0gJ18nIHx8IGMgPT0gJy0n
IHx8IGMgPT0gJy4nIHx8IGMgPT0gJzonKSkgYnJlYWs7CiAgICArKypwb3M7CiAgfQogIGlmICgq
cG9zID09IHN0YXJ0IHx8ICpwb3MgLSBzdGFydCA+IDI1NikgcmV0dXJuIGZhbHNlOwogIG5hbWUt
PmFzc2lnbihib2R5LCBzdGFydCwgKnBvcyAtIHN0YXJ0KTsKICByZXR1cm4gdHJ1ZTsKfQoKc3Rh
dGljIHN0ZDo6c3RyaW5nIGV4dHJhY3Rfd3NzZV91c2VybmFtZShjb25zdCBzdGQ6OnN0cmluZyAm
Ym9keSkgewogIGlmIChib2R5LmVtcHR5KCkgfHwgYm9keS5zaXplKCkgPiBNQVhfV1NTRV9CT0RZ
X0JZVEVTIHx8CiAgICAgIGJvZHkuZmluZCgnXDAnKSAhPSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0
dXJuICIiOwogIHN0ZDo6c3RyaW5nIGxvd2VyZWQgPSBsb3dlcihib2R5KTsKICBpZiAobG93ZXJl
ZC5maW5kKCI8IWRvY3R5cGUiKSAhPSBzdGQ6OnN0cmluZzo6bnBvcyB8fAogICAgICBsb3dlcmVk
LmZpbmQoIjwhZW50aXR5IikgIT0gc3RkOjpzdHJpbmc6Om5wb3MpIHJldHVybiAiIjsKCiAgc3Rk
Ojp2ZWN0b3I8WG1sRnJhbWU+IHN0YWNrOwogIHNpemVfdCB0b2tlbl9kZXB0aCA9IDAsIHVzZXJu
YW1lX2RlcHRoID0gMCwgcG9zID0gMDsKICBzdGQ6OnN0cmluZyB0b2tlbl91cmksIGNoYXJzLCBy
ZXN1bHQ7CiAgYm9vbCB1c2VybmFtZV9iYWQgPSBmYWxzZTsKICB3aGlsZSAocG9zIDwgYm9keS5z
aXplKCkpIHsKICAgIHNpemVfdCBsdCA9IGJvZHkuZmluZCgnPCcsIHBvcyk7CiAgICBpZiAobHQg
PT0gc3RkOjpzdHJpbmc6Om5wb3MpIHsKICAgICAgaWYgKHVzZXJuYW1lX2RlcHRoICYmICF1c2Vy
bmFtZV9iYWQgJiYgIXhtbF91bmVzY2FwZShib2R5LnN1YnN0cihwb3MpLCAmY2hhcnMpKSB1c2Vy
bmFtZV9iYWQgPSB0cnVlOwogICAgICBicmVhazsgLyogYSBib3VuZGVkIHByZWZpeCBpcyBjb21t
b25seSBpbmNvbXBsZXRlICovCiAgICB9CiAgICBpZiAodXNlcm5hbWVfZGVwdGggJiYgIXVzZXJu
YW1lX2JhZCAmJiBsdCA+IHBvcyAmJgogICAgICAgICF4bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIo
cG9zLCBsdCAtIHBvcyksICZjaGFycykpIHVzZXJuYW1lX2JhZCA9IHRydWU7CiAgICBpZiAoY2hh
cnMuc2l6ZSgpID4gTUFYX1dTU0VfVVNFUk5BTUUgKiA0ICsgMikgeyBjaGFycy5jbGVhcigpOyB1
c2VybmFtZV9iYWQgPSB0cnVlOyB9CgogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgNCwgIjwhLS0i
KSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIi0tPiIsIGx0ICsgNCk7IGlm
IChlbmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBwb3MgPSBlbmQgKyAzOyBj
b250aW51ZTsKICAgIH0KICAgIGlmIChib2R5LmNvbXBhcmUobHQsIDksICI8IVtDREFUQVsiKSA9
PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIl1dPiIsIGx0ICsgOSk7IGlmIChl
bmQgPT0gc3RkOjpzdHJpbmc6Om5wb3MpIGJyZWFrOwogICAgICBpZiAodXNlcm5hbWVfZGVwdGgg
JiYgIXVzZXJuYW1lX2JhZCkgY2hhcnMuYXBwZW5kKGJvZHksIGx0ICsgOSwgZW5kIC0gbHQgLSA5
KTsKICAgICAgcG9zID0gZW5kICsgMzsgY29udGludWU7CiAgICB9CiAgICBpZiAoYm9keS5jb21w
YXJlKGx0LCAyLCAiPD8iKSA9PSAwKSB7CiAgICAgIHNpemVfdCBlbmQgPSBib2R5LmZpbmQoIj8+
IiwgbHQgKyAyKTsgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7CiAgICAgIHBv
cyA9IGVuZCArIDI7IGNvbnRpbnVlOwogICAgfQogICAgaWYgKGJvZHkuY29tcGFyZShsdCwgMiwg
IjwhIikgPT0gMCkgcmV0dXJuICIiOwoKICAgIGJvb2wgY2xvc2luZyA9IChsdCArIDEgPCBib2R5
LnNpemUoKSAmJiBib2R5W2x0ICsgMV0gPT0gJy8nKTsKICAgIHNpemVfdCBwID0gbHQgKyAoY2xv
c2luZyA/IDIgOiAxKTsKICAgIHN0ZDo6c3RyaW5nIHFuYW1lOwogICAgaWYgKCFwYXJzZV94bWxf
bmFtZShib2R5LCBib2R5LnNpemUoKSwgJnAsICZxbmFtZSkpIGJyZWFrOwogICAgaWYgKGNsb3Np
bmcpIHsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1bnNpZ25lZCBj
aGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8IGJvZHlbcF0g
IT0gJz4nKSBicmVhazsKICAgICAgaWYgKHN0YWNrLmVtcHR5KCkpIGJyZWFrOwogICAgICBzdGQ6
OnN0cmluZyBwcmVmaXgsIGxvY2FsOyBzcGxpdF9xbmFtZShxbmFtZSwgJnByZWZpeCwgJmxvY2Fs
KTsKICAgICAgWG1sRnJhbWUgJnRvcCA9IHN0YWNrLmJhY2soKTsKICAgICAgaWYgKHRvcC5xbmFt
ZSAhPSBxbmFtZSB8fCB0b3AubG9jYWwgIT0gbG9jYWwpIGJyZWFrOwogICAgICBzaXplX3QgZGVw
dGggPSBzdGFjay5zaXplKCk7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBkZXB0aCkgewog
ICAgICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0gdHJpbShjaGFycyk7CiAgICAgICAgaWYgKCF1
c2VybmFtZV9iYWQgJiYgdmFsaWRfdXRmOF91c2VybmFtZSh1c2VybmFtZSkgJiYgcmVzdWx0LmVt
cHR5KCkpIHJlc3VsdCA9IHVzZXJuYW1lOwogICAgICAgIHVzZXJuYW1lX2RlcHRoID0gMDsgY2hh
cnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICAgIH0KICAgICAgaWYgKHRva2Vu
X2RlcHRoID09IGRlcHRoKSB7IHRva2VuX2RlcHRoID0gMDsgdG9rZW5fdXJpLmNsZWFyKCk7IH0K
ICAgICAgc3RhY2sucG9wX2JhY2soKTsgcG9zID0gcCArIDE7CiAgICAgIGlmICghcmVzdWx0LmVt
cHR5KCkpIHJldHVybiByZXN1bHQ7CiAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIFhtbEZyYW1l
IGZyYW1lOwogICAgaWYgKHN0YWNrLnNpemUoKSA+PSA2NCkgcmV0dXJuICIiOwogICAgaWYgKCFz
dGFjay5lbXB0eSgpKSBmcmFtZS5ucyA9IHN0YWNrLmJhY2soKS5uczsKICAgIGJvb2wgc2VsZl9j
bG9zaW5nID0gZmFsc2UsIGNvbXBsZXRlID0gZmFsc2U7CiAgICBzaXplX3QgYXR0cl9jb3VudCA9
IDA7CiAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpKSB7CiAgICAgIHdoaWxlIChwIDwgYm9keS5z
aXplKCkgJiYgaXNzcGFjZSgodW5zaWduZWQgY2hhcilib2R5W3BdKSkgKytwOwogICAgICBpZiAo
cCA+PSBib2R5LnNpemUoKSkgYnJlYWs7CiAgICAgIGlmIChib2R5W3BdID09ICc+JykgeyArK3A7
IGNvbXBsZXRlID0gdHJ1ZTsgYnJlYWs7IH0KICAgICAgaWYgKGJvZHlbcF0gPT0gJy8nICYmIHAg
KyAxIDwgYm9keS5zaXplKCkgJiYgYm9keVtwICsgMV0gPT0gJz4nKSB7CiAgICAgICAgcCArPSAy
OyBzZWxmX2Nsb3NpbmcgPSB0cnVlOyBjb21wbGV0ZSA9IHRydWU7IGJyZWFrOwogICAgICB9CiAg
ICAgIHN0ZDo6c3RyaW5nIGFuYW1lOwogICAgICBpZiAoIXBhcnNlX3htbF9uYW1lKGJvZHksIGJv
ZHkuc2l6ZSgpLCAmcCwgJmFuYW1lKSkgYnJlYWs7CiAgICAgIGlmICgrK2F0dHJfY291bnQgPiAx
MjgpIHJldHVybiAiIjsKICAgICAgd2hpbGUgKHAgPCBib2R5LnNpemUoKSAmJiBpc3NwYWNlKCh1
bnNpZ25lZCBjaGFyKWJvZHlbcF0pKSArK3A7CiAgICAgIGlmIChwID49IGJvZHkuc2l6ZSgpIHx8
IGJvZHlbcCsrXSAhPSAnPScpIGJyZWFrOwogICAgICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYm
IGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpYm9keVtwXSkpICsrcDsKICAgICAgaWYgKHAgPj0gYm9k
eS5zaXplKCkgfHwgKGJvZHlbcF0gIT0gJ1wnJyAmJiBib2R5W3BdICE9ICciJykpIGJyZWFrOwog
ICAgICBjaGFyIHF1b3RlID0gYm9keVtwKytdOyBzaXplX3QgdmFsdWVfc3RhcnQgPSBwOwogICAg
ICB3aGlsZSAocCA8IGJvZHkuc2l6ZSgpICYmIGJvZHlbcF0gIT0gcXVvdGUpICsrcDsKICAgICAg
aWYgKHAgPj0gYm9keS5zaXplKCkpIGJyZWFrOwogICAgICBzdGQ6OnN0cmluZyB2YWx1ZTsKICAg
ICAgaWYgKCF4bWxfdW5lc2NhcGUoYm9keS5zdWJzdHIodmFsdWVfc3RhcnQsIHAgLSB2YWx1ZV9z
dGFydCksICZ2YWx1ZSkpIHJldHVybiAiIjsKICAgICAgKytwOwogICAgICBpZiAoYW5hbWUgPT0g
InhtbG5zIikgZnJhbWUubnNbIiJdID0gdmFsdWU7CiAgICAgIGVsc2UgaWYgKGFuYW1lLmNvbXBh
cmUoMCwgNiwgInhtbG5zOiIpID09IDApIGZyYW1lLm5zW2FuYW1lLnN1YnN0cig2KV0gPSB2YWx1
ZTsKICAgICAgaWYgKGZyYW1lLm5zLnNpemUoKSA+IDY0KSByZXR1cm4gIiI7CiAgICB9CiAgICBp
ZiAoIWNvbXBsZXRlKSBicmVhazsKICAgIHN0ZDo6c3RyaW5nIHByZWZpeCwgbG9jYWw7IHNwbGl0
X3FuYW1lKHFuYW1lLCAmcHJlZml4LCAmbG9jYWwpOwogICAgc3RkOjptYXA8c3RkOjpzdHJpbmcs
IHN0ZDo6c3RyaW5nPjo6Y29uc3RfaXRlcmF0b3IgbnMgPSBmcmFtZS5ucy5maW5kKHByZWZpeCk7
CiAgICBmcmFtZS51cmkgPSAobnMgPT0gZnJhbWUubnMuZW5kKCkpID8gIiIgOiBucy0+c2Vjb25k
OwogICAgZnJhbWUucW5hbWUgPSBxbmFtZTsKICAgIGZyYW1lLmxvY2FsID0gbG9jYWw7CiAgICBz
dGFjay5wdXNoX2JhY2soZnJhbWUpOwogICAgc2l6ZV90IGRlcHRoID0gc3RhY2suc2l6ZSgpOwog
ICAgaWYgKCF0b2tlbl9kZXB0aCAmJiBsb2NhbCA9PSAiVXNlcm5hbWVUb2tlbiIgJiYgaXNfd3Nz
ZV9uYW1lc3BhY2UoZnJhbWUudXJpKSkgewogICAgICB0b2tlbl9kZXB0aCA9IGRlcHRoOyB0b2tl
bl91cmkgPSBmcmFtZS51cmk7CiAgICB9IGVsc2UgaWYgKHRva2VuX2RlcHRoICYmIGRlcHRoID09
IHRva2VuX2RlcHRoICsgMSAmJgogICAgICAgICAgICAgICBsb2NhbCA9PSAiVXNlcm5hbWUiICYm
IGZyYW1lLnVyaSA9PSB0b2tlbl91cmkpIHsKICAgICAgdXNlcm5hbWVfZGVwdGggPSBkZXB0aDsg
Y2hhcnMuY2xlYXIoKTsgdXNlcm5hbWVfYmFkID0gZmFsc2U7CiAgICB9CiAgICBpZiAoc2VsZl9j
bG9zaW5nKSB7CiAgICAgIGlmICh1c2VybmFtZV9kZXB0aCA9PSBkZXB0aCkgdXNlcm5hbWVfZGVw
dGggPSAwOwogICAgICBpZiAodG9rZW5fZGVwdGggPT0gZGVwdGgpIHsgdG9rZW5fZGVwdGggPSAw
OyB0b2tlbl91cmkuY2xlYXIoKTsgfQogICAgICBzdGFjay5wb3BfYmFjaygpOwogICAgfQogICAg
cG9zID0gcDsKICB9CiAgcmV0dXJuIHJlc3VsdDsKfQoKc3RhdGljIGJvb2wgcGFyc2VfcmVzcG9u
c2UoY29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgaW50ICpzdGF0dXMsIHVuc2lnbmVkICpj
bGVuKSB7CiAgY29uc3QgY2hhciAqZW5kID0gZGF0YSArIGxlbjsKICBjb25zdCBjaGFyICpwID0g
ZGF0YTsKICBjb25zdCBjaGFyICplb2wgPSAoY29uc3QgY2hhciAqKW1lbWNocihwLCAnXG4nLCBl
bmQgLSBwKTsKICBpZiAoIWVvbCkgcmV0dXJuIGZhbHNlOwogIGlmIChzdHJuY21wKHAsICJIVFRQ
LyIsIDUpICE9IDApIHJldHVybiBmYWxzZTsKICBjb25zdCBjaGFyICpzcDEgPSAoY29uc3QgY2hh
ciAqKW1lbWNocihwLCAnICcsIGVvbCAtIHApOwogIGlmICghc3AxKSByZXR1cm4gZmFsc2U7CiAg
Y29uc3QgY2hhciAqc2Nfc3RhcnQgPSBzcDEgKyAxOwogIHdoaWxlIChzY19zdGFydCA8IGVvbCAm
JiAqc2Nfc3RhcnQgPT0gJyAnKSArK3NjX3N0YXJ0OwogICpzdGF0dXMgPSBhdG9pKHNjX3N0YXJ0
KTsKICBpZiAoKnN0YXR1cyA8IDEwMCB8fCAqc3RhdHVzID4gNTk5KSByZXR1cm4gZmFsc2U7CiAg
KmNsZW4gPSAwOwogIHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBpZiAoKnAg
PT0gJ1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5kID0g
KGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVfZW5k
KSBsaW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNoYXIgKilt
ZW1jaHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAgIHNpemVf
dCBobGVuID0gY29sb24gLSBwOwogICAgICBpZiAoaGxlbiA9PSAxNCAmJiAhc3RybmNhc2VjbXAo
cCwgImNvbnRlbnQtbGVuZ3RoIiwgMTQpKSB7CiAgICAgICAgY29uc3QgY2hhciAqdiA9IGNvbG9u
ICsgMTsKICAgICAgICB3aGlsZSAodiA8IGxpbmVfZW5kICYmICgqdiA9PSAnICcgfHwgKnYgPT0g
J1x0JykpICsrdjsKICAgICAgICBsb25nIG4gPSBhdG9sKHYpOwogICAgICAgIGlmIChuID49IDAg
JiYgbiA8PSAweDdmZmZmZmZmKSAqY2xlbiA9ICh1bnNpZ25lZCluOwogICAgICB9CiAgICB9CiAg
ICBwID0gbGluZV9lbmQgKyAxOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIHN0ZDo6c3Ry
aW5nIGdfZW5kcG9pbnQ7CnN0YXRpYyBzdGQ6OnN0cmluZyBnX3NoaXBfbm9kZTsKc3RhdGljIHN0
ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBnX3NoaXBfYnVmOwoKc3RhdGljIHN0ZDo6c3RyaW5nIHNo
ZWxscShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIG8gPSAiJyI7CiAgZm9y
IChzaXplX3QgaSA9IDA7IGkgPCBzLnNpemUoKTsgKytpKSB7IGlmIChzW2ldID09ICdcJycpIG8g
Kz0gIidcXCcnIjsgZWxzZSBvICs9IHNbaV07IH0KICByZXR1cm4gbyArICInIjsKfQpzdGF0aWMg
c3RkOjpzdHJpbmcgbnVtYmVyX3N0cmluZyhzaXplX3QgbikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0g
bzsgbyA8PCBuOyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgc3RkOjpzdHJpbmcganNvbl9hcnJh
eShjb25zdCBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmEpIHsKICBzdGQ6OnN0cmluZyBvID0g
IlsiOyBmb3IgKHNpemVfdCBpID0gMDsgaSA8IGEuc2l6ZSgpOyArK2kpIHsgaWYgKGkpIG8gKz0g
IiwiOyBvICs9IGFbaV07IH0gcmV0dXJuIG8gKyAiXSI7Cn0Kc3RhdGljIGJvb2wgcG9zdChjb25z
dCBzdGQ6OnN0cmluZyAmZW5kcG9pbnQsIGNvbnN0IHN0ZDo6c3RyaW5nICZub2RlLCBjb25zdCBz
dGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gJmJhdGNoKSB7CiAgc3RkOjpzdHJpbmcgYm9keSA9ICJ7
XCJub2RlXCI6IiArIGpzb25xKG5vZGUpICsgIixcImV2ZW50c1wiOiIgKyBqc29uX2FycmF5KGJh
dGNoKSArICJ9IjsKICBzdGQ6OnN0cmluZyBjbWQgPSAiY3VybCAtc1NmIC0tbWF4LXRpbWUgMTAg
LW8gL2Rldi9udWxsIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0YS1i
aW5hcnkgQC0gIiArIHNoZWxscShlbmRwb2ludCArICIvYXBpL2luZ2VzdCIpOwogIEZJTEUgKmZw
ID0gcG9wZW4oY21kLmNfc3RyKCksICJ3Iik7IGlmICghZnApIHJldHVybiBmYWxzZTsKICBmd3Jp
dGUoYm9keS5kYXRhKCksIDEsIGJvZHkuc2l6ZSgpLCBmcCk7CiAgaW50IHJjID0gcGNsb3NlKGZw
KTsKICByZXR1cm4gV0lGRVhJVEVEKHJjKSAmJiBXRVhJVFNUQVRVUyhyYykgPT0gMDsKfQpzdGF0
aWMgdm9pZCBzZW5kX2JhdGNoZXMoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBvaW50LCBjb25zdCBz
dGQ6OnN0cmluZyAmbm9kZSwKICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6dmVjdG9yPHN0
ZDo6c3RyaW5nPiAqYnVmLCBib29sIGZsdXNoX2FsbCkgewogIHdoaWxlICghYnVmLT5lbXB0eSgp
ICYmIChmbHVzaF9hbGwgfHwgYnVmLT5zaXplKCkgPj0gTUFYX0JBVENIKSkgewogICAgc2l6ZV90
IG4gPSBidWYtPnNpemUoKSA+PSBNQVhfQkFUQ0ggPyBNQVhfQkFUQ0ggOiBidWYtPnNpemUoKTsK
ICAgIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiBiYXRjaChidWYtPmJlZ2luKCksIGJ1Zi0+YmVn
aW4oKSArIG4pOwogICAgaWYgKHBvc3QoZW5kcG9pbnQsIG5vZGUsIGJhdGNoKSkgewogICAgICBi
dWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigpICsgbik7CiAgICAgIGxvZ21zZygi
Zmx1c2hlZCAiICsgbnVtYmVyX3N0cmluZyhuKSArICIgZXZlbnRzIik7CiAgICB9IGVsc2Ugewog
ICAgICAvKiBQdXJlIGluLW1lbW9yeSBkcm9wIHdoZW4gSHViIHVucmVhY2hhYmxlICh6ZXJvIGRp
c2sgSS9PKSAqLwogICAgICBidWYtPmVyYXNlKGJ1Zi0+YmVnaW4oKSwgYnVmLT5iZWdpbigpICsg
bik7CiAgICAgIGxvZ21zZygiV0FSTjogSHViIHVucmVhY2hhYmxlLCBkcm9wcGVkICIgKyBudW1i
ZXJfc3RyaW5nKG4pICsgIiBldmVudHMgKGluLW1lbW9yeSBkcm9wLCAwIGRpc2sgSS9PKSIpOwog
ICAgICBicmVhazsKICAgIH0KICB9Cn0KCnN0YXRpYyB2b2lkIGVtaXRfZXZlbnQoY29uc3QgRXZl
bnQgJmUpIHsKICBzdGQ6Om9zdHJpbmdzdHJlYW0gc3M7CiAgc3MgPDwgIntcInRzXCI6IiA8PCBl
LnRzIDw8ICIsXCJob3N0XCI6IiA8PCBqc29ucShlLmhvc3QpIDw8ICIsXCJzcmNcIjpcInBjYXBc
IixcInNlcnZpY2VcIjoiIDw8IGpzb25xKGUuc2VydmljZSkKICAgICA8PCAiLFwibWV0aG9kXCI6
IiA8PCBqc29ucShlLm1ldGhvZCkgPDwgIixcInBhdGhcIjoiIDw8IGpzb25xKGUucGF0aCkgPDwg
IixcInVzZXJcIjoiIDw8IGpzb25xKGUudXNlcikKICAgICA8PCAiLFwic2NoZW1lXCI6IiA8PCBq
c29ucShlLnNjaGVtZSkgPDwgIixcInNvdXJjZV9wcm9iZVwiOlwicGNhcC1odHRwLWNwcFwiLFwi
aG9zdF9oZHJcIjoiIDw8IGpzb25xKGUuaG9zdF9oZHIpCiAgICAgPDwgIixcInVzZXJfYWdlbnRc
IjoiIDw8IGpzb25xKGUudXNlcl9hZ2VudCkgPDwgIixcInhfZm9yd2FyZGVkX2ZvclwiOiIgPDwg
anNvbnEoZS54ZmYpCiAgICAgPDwgIixcImNhbGxlclwiOiIgPDwganNvbnEoZS5jYWxsZXIpIDw8
ICIsXCJjYWxsZXJfcG9ydFwiOiIgPDwgZS5jYWxsZXJfcG9ydCA8PCAiLFwiZHN0X2lwXCI6IiA8
PCBqc29ucShlLmRzdF9pcCkKICAgICA8PCAiLFwiZHN0X3BvcnRcIjoiIDw8IGUuZHN0X3BvcnQg
PDwgIixcInRyYWNlcGFyZW50XCI6IiA8PCBqc29ucShlLnRyYWNlcGFyZW50KSA8PCAiLFwidHJh
Y2VfaWRcIjoiIDw8IGpzb25xKGUudHJhY2VfaWQpCiAgICAgPDwgIixcInNlcnZpY2VfaWRcIjpu
dWxsLFwibW9kdWxlX2lkXCI6XCJwY2FwLWh0dHAtY3BwXCIsXCJyZXFfYnl0ZXNcIjoiIDw8IGUu
cmVxX2J5dGVzOwogIGlmIChlLmhhc19zdGF0dXMpIHNzIDw8ICIsXCJzdGF0dXNcIjoiIDw8IGUu
c3RhdHVzOyBlbHNlIHNzIDw8ICIsXCJzdGF0dXNcIjpudWxsIjsKICBpZiAoZS5oYXNfZHVyYXRp
b24pIHNzIDw8ICIsXCJkdXJhdGlvbl9tc1wiOiIgPDwgZS5kdXJhdGlvbl9tczsgZWxzZSBzcyA8
PCAiLFwiZHVyYXRpb25fbXNcIjpudWxsIjsKICBpZiAoZS5oYXNfcmVzcCkgc3MgPDwgIixcInJl
c3BfYnl0ZXNcIjoiIDw8IGUucmVzcF9ieXRlczsgZWxzZSBzcyA8PCAiLFwicmVzcF9ieXRlc1wi
Om51bGwiOwogIHNzIDw8ICJ9IjsKCiAgaWYgKCFnX2VuZHBvaW50LmVtcHR5KCkpIHsKICAgIGlm
IChnX3NoaXBfYnVmLnNpemUoKSA+PSBNQVhfUVVFVUUpIHsKICAgICAgZ19zaGlwX2J1Zi5lcmFz
ZShnX3NoaXBfYnVmLmJlZ2luKCkpOwogICAgfQogICAgZ19zaGlwX2J1Zi5wdXNoX2JhY2soc3Mu
c3RyKCkpOwogIH0gZWxzZSB7CiAgICBzdGQ6OmNvdXQgPDwgc3Muc3RyKCkgPDwgIlxuIjsKICB9
Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX29sZGVzdChzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVj
dG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBpZiAocGVuZGluZy5lbXB0eSgpKSByZXR1cm47
CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBp
dCA9IHBlbmRpbmcuYmVnaW4oKTsKICBpZiAoIWl0LT5zZWNvbmQuZW1wdHkoKSkgewogICAgZW1p
dF9ldmVudChpdC0+c2Vjb25kWzBdLmV2KTsKICAgIGl0LT5zZWNvbmQuZXJhc2UoaXQtPnNlY29u
ZC5iZWdpbigpKTsKICB9CiAgaWYgKGl0LT5zZWNvbmQuZW1wdHkoKSkgewogICAgcGVuZGluZy5l
cmFzZShpdCk7CiAgfQp9CnN0YXRpYyB2b2lkIGZsdXNoX2FsbF9wZW5kaW5nKHN0ZDo6bWFwPFBh
Y2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIHN0ZDo6bWFwPFBh
Y2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcDsKICBmb3IgKHAgPSBw
ZW5kaW5nLmJlZ2luKCk7IHAgIT0gcGVuZGluZy5lbmQoKTsgKytwKSB7CiAgICBmb3IgKHNpemVf
dCBpID0gMDsgaSA8IHAtPnNlY29uZC5zaXplKCk7ICsraSkgewogICAgICBlbWl0X2V2ZW50KHAt
PnNlY29uZFtpXS5ldik7CiAgICB9CiAgfQogIHBlbmRpbmcuY2xlYXIoKTsKfQpzdGF0aWMgdm9p
ZCBzd2VlcChzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtl
eSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywgdGltZV90IG5vdykgewogIHN0ZDo6
bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBmLCBmbjsKICBmb3IgKGYgPSBmbG93cy5iZWdp
bigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAgZm4gPSBmOyArK2ZuOwogICAgaWYgKCh1bnNp
Z25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNoZWQpID4gRkxPV19UVEwpIGZsb3dzLmVyYXNlKGYp
OwogICAgZiA9IGZuOwogIH0KICBsb25nIGxvbmcgY3VycmVudF9tcyA9IChsb25nIGxvbmcpbm93
ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6
aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0gcGVuZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcu
ZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47CiAgICBzaXplX3QgaSA9IDA7CiAgICB3aGlsZSAo
aSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAgaWYgKGN1cnJlbnRfbXMgLSBwLT5zZWNvbmRb
aV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcpUEVORElOR19UVEwgKiAxMDAwTEwpIHsKICAgICAg
ICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAt
PnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgKytpOwogICAgICB9
CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICBw
ID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmluZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6c3Ry
aW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwg
IkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIHNpemVfdCBiZXN0
ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCA3OyArK2kpIHsK
ICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7CiAgICBpZiAocG9zICE9IHN0ZDo6c3RyaW5n
OjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHBvcyA8IGJlc3QpKSBiZXN0
ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoKc3RhdGljIGJvb2wgZ19tb25pdG9yZWRfcG9y
dHNbNjU1MzZdOwpzdGF0aWMgc2l6ZV90IGdfd3NzZV9ib2R5X2J5dGVzID0gMDsKCnN0YXRpYyB2
b2lkIHF1ZXVlX3JlcXVlc3QoY29uc3QgRXZlbnQgJmUsIHVpbnQzMl90IHNfaXAsIHVuc2lnbmVk
IHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgIHVpbnQzMl90IGRfaXAsIHVuc2lnbmVk
IGRwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZDo6bWFwPFBhY2tldEtleSwgc3Rk
Ojp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZykgewogIFBhY2tldEtleSByazsKICByay5zX2lw
ID0gZF9pcDsgcmsuc3BvcnQgPSAodWludDE2X3QpZHBvcnQ7CiAgcmsuZF9pcCA9IHNfaXA7IHJr
LmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogIGlmIChwZW5kaW5nLmZpbmQocmspID09IHBlbmRp
bmcuZW5kKCkgJiYgcGVuZGluZy5zaXplKCkgPj0gTUFYX1BFTkRJTkcpIHsKICAgIGZsdXNoX29s
ZGVzdChwZW5kaW5nKTsKICB9CiAgc3RkOjp2ZWN0b3I8UGVuZGluZz4gJnF1ZXVlID0gcGVuZGlu
Z1tya107CiAgaWYgKHF1ZXVlLnNpemUoKSA+PSBNQVhfUEVORElOR19QRVJfRkxPVykgewogICAg
ZW1pdF9ldmVudChxdWV1ZVswXS5ldik7CiAgICBxdWV1ZS5lcmFzZShxdWV1ZS5iZWdpbigpKTsK
ICB9CiAgcXVldWUucHVzaF9iYWNrKFBlbmRpbmcoZSwgbm93X21zKCkpKTsKfQoKc3RhdGljIHNp
emVfdCBhY3RpdmVfd3NzZV9mbG93cyhjb25zdCBzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxv
d3MpIHsKICBzaXplX3QgY291bnQgPSAwOwogIHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+Ojpjb25z
dF9pdGVyYXRvciBpdDsKICBmb3IgKGl0ID0gZmxvd3MuYmVnaW4oKTsgaXQgIT0gZmxvd3MuZW5k
KCk7ICsraXQpCiAgICBpZiAoaXQtPnNlY29uZC5hd2FpdGluZ19ib2R5KSArK2NvdW50OwogIHJl
dHVybiBjb3VudDsKfQoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBj
aGFyICpidWYsIHNpemVfdCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2
ZWN0b3I8dW5zaWduZWQ+ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1h
cDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8
UGVuZGluZz4gPiAmcGVuZGluZykgewogICh2b2lkKXBvcnRzOwogIGlmIChuIDwgMzQpIHJldHVy
biBmYWxzZTsKICBzaXplX3Qgb2ZmID0gMTQ7CiAgdW5zaWduZWQgc2hvcnQgZXQgPSBudG9ocygq
KGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIDEyKSk7CiAgaWYgKGV0ID09IEVUSF9QXzgw
MjFRKSB7IGlmIChuIDwgMzgpIHJldHVybiBmYWxzZTsgZXQgPSBudG9ocygqKGNvbnN0IHVuc2ln
bmVkIHNob3J0ICopKGJ1ZiArIDE2KSk7IG9mZiA9IDE4OyB9CiAgaWYgKGV0ICE9IEVUSF9QX0lQ
IHx8IG4gPCBvZmYgKyAyMCkgcmV0dXJuIGZhbHNlOwogIHVuc2lnbmVkIGNoYXIgaWhsID0gKHVu
c2lnbmVkIGNoYXIpKGJ1ZltvZmZdICYgMTUpICogNDsKICBpZiAoKGJ1ZltvZmZdID4+IDQpICE9
IDQgfHwgYnVmW29mZiArIDldICE9IDYgfHwgbiA8IG9mZiArIGlobCArIDIwKSByZXR1cm4gZmFs
c2U7CgogIHVpbnQzMl90IHNfaXAgPSAqKGNvbnN0IHVpbnQzMl90ICopKGJ1ZiArIG9mZiArIDEy
KTsKICB1aW50MzJfdCBkX2lwID0gKihjb25zdCB1aW50MzJfdCAqKShidWYgKyBvZmYgKyAxNik7
CiAgc2l6ZV90IHRvID0gb2ZmICsgaWhsOwogIHVuc2lnbmVkIHNwb3J0ID0gbnRvaHMoKihjb25z
dCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0bykpOwogIHVuc2lnbmVkIGRwb3J0ID0gbnRvaHMo
Kihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0byArIDIpKTsKICB1bnNpZ25lZCBkb2Zm
ID0gKGJ1Zlt0byArIDEyXSA+PiA0KSAqIDQ7CiAgaWYgKG4gPCB0byArIGRvZmYpIHJldHVybiBm
YWxzZTsKICBjb25zdCBjaGFyICpwYXlsb2FkID0gKGNvbnN0IGNoYXIgKikoYnVmICsgdG8gKyBk
b2ZmKTsKICBzaXplX3QgcGxlbiA9IG4gLSB0byAtIGRvZmY7CiAgaWYgKCFwbGVuKSByZXR1cm4g
ZmFsc2U7CgogIHRpbWVfdCBub3cgPSB0aW1lKE5VTEwpOwogIGJvb2wgZHN0X21vbiA9IChkcG9y
dCA8IDY1NTM2KSA/IGdfbW9uaXRvcmVkX3BvcnRzW2Rwb3J0XSA6IGZhbHNlOwogIGJvb2wgc3Jj
X21vbiA9IChzcG9ydCA8IDY1NTM2KSA/IGdfbW9uaXRvcmVkX3BvcnRzW3Nwb3J0XSA6IGZhbHNl
OwoKICBpZiAoc3JjX21vbiAmJiAhZHN0X21vbiAmJiBwbGVuID49IDUpIHsKICAgIGlmIChtZW1j
bXAocGF5bG9hZCwgIkhUVFAvIiwgNSkgPT0gMCkgewogICAgICBQYWNrZXRLZXkgazsKICAgICAg
ay5zX2lwID0gc19pcDsgay5zcG9ydCA9ICh1aW50MTZfdClzcG9ydDsgay5kX2lwID0gZF9pcDsg
ay5kcG9ydCA9ICh1aW50MTZfdClkcG9ydDsKICAgICAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBwID0gcGVuZGluZy5maW5kKGspOwogICAgICBp
ZiAocCAhPSBwZW5kaW5nLmVuZCgpICYmICFwLT5zZWNvbmQuZW1wdHkoKSkgewogICAgICAgIGlu
dCBzdDsgdW5zaWduZWQgY2w7CiAgICAgICAgaWYgKHBhcnNlX3Jlc3BvbnNlKHBheWxvYWQsIHBs
ZW4sICZzdCwgJmNsKSkgewogICAgICAgICAgRXZlbnQgZSA9IHAtPnNlY29uZFswXS5ldjsKICAg
ICAgICAgIGUuc3RhdHVzID0gc3Q7IGUuaGFzX3N0YXR1cyA9IHRydWU7CiAgICAgICAgICBlLmR1
cmF0aW9uX21zID0gKGxvbmcpKG5vd19tcygpIC0gcC0+c2Vjb25kWzBdLnN0YXJ0ZWRfbXMpOwog
ICAgICAgICAgaWYgKGUuZHVyYXRpb25fbXMgPCAwKSBlLmR1cmF0aW9uX21zID0gMDsKICAgICAg
ICAgIGUuaGFzX2R1cmF0aW9uID0gdHJ1ZTsKICAgICAgICAgIGlmIChjbCkgeyBlLnJlc3BfYnl0
ZXMgPSBjbDsgZS5oYXNfcmVzcCA9IHRydWU7IH0KICAgICAgICAgIGVtaXRfZXZlbnQoZSk7CiAg
ICAgICAgICBwLT5zZWNvbmQuZXJhc2UocC0+c2Vjb25kLmJlZ2luKCkpOwogICAgICAgICAgaWYg
KHAtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKHApOwogICAgICAgIH0KICAgICAgfQog
ICAgfQogICAgcmV0dXJuIHRydWU7CiAgfQogIHVuc2lnbmVkIGNoYXIgdGNwX2ZsYWdzID0gYnVm
W3RvICsgMTNdOwogIGlmICghZHN0X21vbikgewogICAgaWYgKHRjcF9mbGFncyAmIDB4MDUpIHsg
LyogRklOIG9yIFJTVCAqLwogICAgICBGbG93S2V5IHJmazsgcmZrLnNfaXAgPSBkX2lwOyByZmsu
c3BvcnQgPSAodWludDE2X3QpZHBvcnQ7IHJmay5kX2lwID0gc19pcDsgcmZrLmRwb3J0ID0gKHVp
bnQxNl90KXNwb3J0OwogICAgICBmbG93cy5lcmFzZShyZmspOwogICAgfQogICAgcmV0dXJuIGZh
bHNlOwogIH0KCiAgRmxvd0tleSBmazsKICBmay5zX2lwID0gc19pcDsgZmsuc3BvcnQgPSAodWlu
dDE2X3Qpc3BvcnQ7IGZrLmRfaXAgPSBkX2lwOyBmay5kcG9ydCA9ICh1aW50MTZfdClkcG9ydDsK
ICBpZiAodGNwX2ZsYWdzICYgMHgwNSkgeyAvKiBGSU4gb3IgUlNUICovCiAgICBmbG93cy5lcmFz
ZShmayk7CiAgICByZXR1cm4gdHJ1ZTsKICB9CgogIGlmIChmbG93cy5maW5kKGZrKSA9PSBmbG93
cy5lbmQoKSAmJiBmbG93cy5zaXplKCkgPj0gTUFYX0ZMT1dTKSB7CiAgICBmbG93cy5lcmFzZShm
bG93cy5iZWdpbigpKTsKICB9CiAgRmxvdyAmZmwgPSBmbG93c1tma107IGZsLnRvdWNoZWQgPSBu
b3c7CiAgaWYgKGZsLmF3YWl0aW5nX2JvZHkpIHsKICAgIHNpemVfdCByZW1haW5pbmcgPSBmbC5i
b2R5X2dvYWwgPiBmbC5idWYuc2l6ZSgpID8gZmwuYm9keV9nb2FsIC0gZmwuYnVmLnNpemUoKSA6
IDA7CiAgICBpZiAocmVtYWluaW5nKSBmbC5idWYuYXBwZW5kKHBheWxvYWQsIHBsZW4gPCByZW1h
aW5pbmcgPyBwbGVuIDogcmVtYWluaW5nKTsKICAgIHN0ZDo6c3RyaW5nIHVzZXJuYW1lID0gZXh0
cmFjdF93c3NlX3VzZXJuYW1lKGZsLmJ1Zik7CiAgICBpZiAoIXVzZXJuYW1lLmVtcHR5KCkgfHwg
ZmwuYnVmLnNpemUoKSA+PSBmbC5ib2R5X2dvYWwpIHsKICAgICAgRXZlbnQgZXZlbnQgPSBmbC5l
dmVudDsKICAgICAgaWYgKCF1c2VybmFtZS5lbXB0eSgpKSB7IGV2ZW50LnVzZXIgPSB1c2VybmFt
ZTsgZXZlbnQuc2NoZW1lID0gIndzc2UiOyB9CiAgICAgIGZsb3dzLmVyYXNlKGZrKTsKICAgICAg
cXVldWVfcmVxdWVzdChldmVudCwgc19pcCwgc3BvcnQsIGRfaXAsIGRwb3J0LCBwZW5kaW5nKTsK
ICAgIH0KICAgIHJldHVybiB0cnVlOwogIH0KICBmbC5idWYuYXBwZW5kKHBheWxvYWQsIHBsZW4p
OwogIGlmIChmbC5idWYuc2l6ZSgpID4gTUFYX0hFQURFUikgeyBmbG93cy5lcmFzZShmayk7IHJl
dHVybiBmYWxzZTsgfQogIHdoaWxlICh0cnVlKSB7CiAgICBzaXplX3Qgc3RhcnQgPSBmaW5kX2h0
dHBfc3RhcnQoZmwuYnVmKTsKICAgIGlmIChzdGFydCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgeyBm
bC5idWYuY2xlYXIoKTsgYnJlYWs7IH0KICAgIGlmIChzdGFydCA+IDApIGZsLmJ1Zi5lcmFzZSgw
LCBzdGFydCk7CiAgICBzaXplX3QgZW5kID0gZmwuYnVmLmZpbmQoIlxyXG5cclxuIik7CiAgICBp
ZiAoZW5kID09IHN0ZDo6c3RyaW5nOjpucG9zKSBicmVhazsKICAgIEV2ZW50IGU7IFJlcXVlc3RN
ZXRhIG1ldGE7IGUudHMgPSBub3c7IGUuaG9zdCA9IG5vZGU7IGUuc2VydmljZSA9ICJwb3J0OiIg
KyBudW0oZHBvcnQpOyBlLmNhbGxlciA9IGlwX3RvX3N0cihzX2lwKTsgZS5jYWxsZXJfcG9ydCA9
IHNwb3J0OyBlLmRzdF9pcCA9IGlwX3RvX3N0cihkX2lwKTsgZS5kc3RfcG9ydCA9IGRwb3J0OyBl
LnJlcV9ieXRlcyA9ICh1bnNpZ25lZCkoZW5kICsgNCk7CiAgICBpZiAoIXBhcnNlX3JlcXVlc3Qo
ZmwuYnVmLmRhdGEoKSwgZW5kLCAmZSwgJm1ldGEpKSB7IGZsLmJ1Zi5lcmFzZSgwLCBlbmQgKyA0
KTsgY29udGludWU7IH0KICAgIGZsLmJ1Zi5lcmFzZSgwLCBlbmQgKyA0KTsKICAgIGlmIChlLnVz
ZXIgPT0gIi1hbm9ueW1vdXMtIiAmJiBnX3dzc2VfYm9keV9ieXRlcyAmJgogICAgICAgIGlzX3Nv
YXBfY29udGVudF90eXBlKG1ldGEuY29udGVudF90eXBlKSAmJiBtZXRhLmhhc19jb250ZW50X2xl
bmd0aCAmJgogICAgICAgIG1ldGEuY29udGVudF9sZW5ndGggPiAwICYmCiAgICAgICAgbG93ZXIo
bWV0YS50cmFuc2Zlcl9lbmNvZGluZykuZmluZCgiY2h1bmtlZCIpID09IHN0ZDo6c3RyaW5nOjpu
cG9zICYmCiAgICAgICAgYWN0aXZlX3dzc2VfZmxvd3MoZmxvd3MpIDwgTUFYX1dTU0VfQk9EWV9G
TE9XUykgewogICAgICBmbC5ldmVudCA9IGU7CiAgICAgIGZsLmF3YWl0aW5nX2JvZHkgPSB0cnVl
OwogICAgICBmbC5ib2R5X2dvYWwgPSBtZXRhLmNvbnRlbnRfbGVuZ3RoIDwgZ193c3NlX2JvZHlf
Ynl0ZXMgPyBtZXRhLmNvbnRlbnRfbGVuZ3RoIDogZ193c3NlX2JvZHlfYnl0ZXM7CiAgICAgIGlm
IChmbC5ib2R5X2dvYWwgPiBNQVhfV1NTRV9CT0RZX0JZVEVTKSBmbC5ib2R5X2dvYWwgPSBNQVhf
V1NTRV9CT0RZX0JZVEVTOwogICAgICBpZiAoZmwuYnVmLnNpemUoKSA+IGZsLmJvZHlfZ29hbCkg
ZmwuYnVmLnJlc2l6ZShmbC5ib2R5X2dvYWwpOwogICAgICBzdGQ6OnN0cmluZyB1c2VybmFtZSA9
IGV4dHJhY3Rfd3NzZV91c2VybmFtZShmbC5idWYpOwogICAgICBpZiAoIXVzZXJuYW1lLmVtcHR5
KCkgfHwgZmwuYnVmLnNpemUoKSA+PSBmbC5ib2R5X2dvYWwpIHsKICAgICAgICBFdmVudCBldmVu
dCA9IGZsLmV2ZW50OwogICAgICAgIGlmICghdXNlcm5hbWUuZW1wdHkoKSkgeyBldmVudC51c2Vy
ID0gdXNlcm5hbWU7IGV2ZW50LnNjaGVtZSA9ICJ3c3NlIjsgfQogICAgICAgIGZsb3dzLmVyYXNl
KGZrKTsKICAgICAgICBxdWV1ZV9yZXF1ZXN0KGV2ZW50LCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBv
cnQsIHBlbmRpbmcpOwogICAgICB9CiAgICAgIHJldHVybiB0cnVlOwogICAgfQogICAgcXVldWVf
cmVxdWVzdChlLCBzX2lwLCBzcG9ydCwgZF9pcCwgZHBvcnQsIHBlbmRpbmcpOwogIH0KICBpZiAo
ZmwuYnVmLmVtcHR5KCkpIHsKICAgIGZsb3dzLmVyYXNlKGZrKTsKICB9CiAgcmV0dXJuIHRydWU7
Cn0KCnN0YXRpYyBib29sIGF0dGFjaF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNp
Z25lZD4gJnBvcnRzKSB7CiAgaWYgKHBvcnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6
OnZlY3RvcjxzdHJ1Y3Qgc29ja19maWx0ZXI+IGY7IHNpemVfdCBpOwogIC8qIER1YWwtcGF0aCBj
QlBGOiBQYXRoIEEgKHN0YW5kYXJkIElQdjQpIGFuZCBQYXRoIEIgKDgwMi4xUSBWTEFOIHRhZ2dl
ZCBJUHY0KS4gKi8KICB1bnNpZ25lZCBOID0gKHVuc2lnbmVkKXBvcnRzLnNpemUoKTsKICB1bnNp
Z25lZCByZWplY3QgPSAxMSArIE4gKiA4OwogIHVuc2lnbmVkIGFjY2VwdCA9IHJlamVjdCArIDE7
CiAgc3RydWN0IHNvY2tfZmlsdGVyIHg7CiNkZWZpbmUgQUREKEMsSixULEspIGRvIHsgXAogIHVu
c2lnbmVkIF9qdCA9ICh1bnNpZ25lZCkoSiksIF9qZiA9ICh1bnNpZ25lZCkoVCk7IFwKICBpZiAo
X2p0ID4gVUNIQVJfTUFYIHx8IF9qZiA+IFVDSEFSX01BWCkgcmV0dXJuIGZhbHNlOyBcCiAgeC5j
b2RlPShDKTsgeC5qdD0odW5zaWduZWQgY2hhcilfanQ7IHguamY9KHVuc2lnbmVkIGNoYXIpX2pm
OyB4Lms9KEspOyBcCiAgZi5wdXNoX2JhY2soeCk7IFwKfSB3aGlsZSgwKQogIC8qIFswXSBMb2Fk
IEV0aGVyVHlwZSBhdCBvZmZzZXQgMTIgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAs
IDAsIDEyKTsKICAvKiBbMV0gSWYgc3RhbmRhcmQgSVB2NCAoMHgwODAwKSwganVtcCBvdmVyIFBh
dGggQiAoNiArIDQqTiBpbnN0cnVjdGlvbnMpIHRvIFBhdGggQSAqLwogIEFERChCUEZfSk1QfEJQ
Rl9KRVF8QlBGX0ssICh1bnNpZ25lZCkoNiArIDQgKiBOKSwgMCwgRVRIX1BfSVBfSE9TVCk7Cgog
IC8qIC0tLSBQYXRoIEI6IDgwMi4xUSBWTEFOIChpbmRleCAyKSAtLS0gKi8KICAvKiBbMl0gSWYg
bm90IDgwMi4xUSAoMHg4MTAwKSwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZf
SywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKSwgRVRIX1Bf
ODAyMVFfSE9TVCk7CiAgLyogWzNdIExvYWQgZW5jYXBzdWxhdGVkIEV0aGVyVHlwZSBhdCBvZmZz
ZXQgMTYgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAsIDE2KTsKICAvKiBbNF0g
SWYgZW5jYXBzdWxhdGVkICE9IElQdjQsIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8
QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIEVU
SF9QX0lQX0hPU1QpOwogIC8qIFs1XSBMb2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyNyAoMjMg
KyA0KSAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjcpOwogIC8qIFs2XSBJ
ZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCAwLCAodW5z
aWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJUFBST1RPX1RDUCk7CiAg
LyogWzddIExvYWQgSUhMIGF0IG9mZnNldCAxOCAoMTQgKyA0KSAqLwogIEFERChCUEZfTERYfEJQ
Rl9CfEJQRl9NU0gsIDAsIDAsIDE4KTsKICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNrcyBmb3Ig
VkxBTiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAgQUREKEJQ
Rl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAyMCk7CiAgICB1bnNpZ25lZCBqdCA9IGFjY2VwdCAt
ICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBq
dCwgMCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVja3MgZm9yIFZMQU4gKi8K
ICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBG
X0h8QlBGX0lORCwgMCwgMCwgMTgpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWdu
ZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUoKSAtIDEp
ID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChCUEZfSk1Q
fEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgLyogLS0tIFBhdGggQTog
U3RhbmRhcmQgSVB2NCAtLS0gKi8KICAvKiBMb2FkIElQIHByb3RvY29sIGF0IG9mZnNldCAyMyAq
LwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjMpOwogIC8qIElmIG5vdCBUQ1As
IHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVq
ZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQKTsKICAvKiBMb2FkIElI
TCBhdCBvZmZzZXQgMTQgKi8KICBBREQoQlBGX0xEWHxCUEZfQnxCUEZfTVNILCAwLCAwLCAxNCk7
CiAgLyogRGVzdGluYXRpb24gcG9ydCBjaGVja3MgZm9yIHN0YW5kYXJkIElQdjQgKi8KICBmb3Ig
KGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZfTER8QlBGX0h8QlBG
X0lORCwgMCwgMCwgMTYpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAodW5zaWduZWQpZi5z
aXplKCkgLSAxOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywganQsIDAsIHBvcnRzW2ld
KTsKICB9CiAgLyogU291cmNlIHBvcnQgY2hlY2tzIGZvciBzdGFuZGFyZCBJUHY0ICovCiAgZm9y
IChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQoQlBGX0xEfEJQRl9IfEJQ
Rl9JTkQsIDAsIDAsIDE0KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gKGkgPCBwb3J0cy5zaXplKCkgLSAxKSA/IDAg
OiAocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSk7CiAgICBBREQoQlBGX0pNUHxCUEZf
SkVRfEJQRl9LLCBqdCwgamYsIHBvcnRzW2ldKTsKICB9CgogIC8qIFtyZWplY3RdIERyb3AgcGFj
a2V0ICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIDApOwogIC8qIFthY2NlcHRdIEFjY2Vw
dCBwYWNrZXQgKDIwNDggYnl0ZXMpICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIEFDQ0VQ
VCk7CiN1bmRlZiBBREQKICBpZiAoZi5zaXplKCkgPiA0MDk2KSByZXR1cm4gZmFsc2U7CiAgc3Ry
dWN0IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5sZW4gPSAodW5zaWduZWQgc2hvcnQpZi5zaXplKCk7
IHByb2cuZmlsdGVyID0gJmZbMF07CiNpZm5kZWYgU09fQVRUQUNIX0ZJTFRFUgojZGVmaW5lIFNP
X0FUVEFDSF9GSUxURVIgMjYKI2VuZGlmCiAgcmV0dXJuIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NL
RVQsIFNPX0FUVEFDSF9GSUxURVIsICZwcm9nLCBzaXplb2YocHJvZykpID09IDA7Cn0KCnN0cnVj
dCBNbWFwUmluZyB7CiAgdm9pZCAqcmluZzsKICBzaXplX3QgcmluZ19zaXplOwogIHVuc2lnbmVk
IGJsb2NrX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfbnI7CiAgdW5zaWduZWQgZnJhbWVfc2l6ZTsK
ICB1bnNpZ25lZCBmcmFtZV9ucjsKICB1bnNpZ25lZCBmcmFtZXNfcGVyX2Jsb2NrOwogIHVuc2ln
bmVkIGZyYW1lX2lkeDsKCiAgTW1hcFJpbmcoKSA6IHJpbmcoTUFQX0ZBSUxFRCksIHJpbmdfc2l6
ZSgwKSwgYmxvY2tfc2l6ZSg2NTUzNiksIGJsb2NrX25yKDY0KSwKICAgICAgICAgICAgICAgZnJh
bWVfc2l6ZSgyMDQ4KSwgZnJhbWVfbnIoMjA0OCksIGZyYW1lc19wZXJfYmxvY2soMzIpLCBmcmFt
ZV9pZHgoMCkge30KfTsKCnN0YXRpYyBib29sIHZhbGlkX3JpbmdfZ2VvbWV0cnkoY29uc3QgTW1h
cFJpbmcgJm1yKSB7CiAgY29uc3Qgc2l6ZV90IHNpemVfbWF4ID0gKHNpemVfdCktMTsKICBsb25n
IHBhZ2Vfc2l6ZSA9IHN5c2NvbmYoX1NDX1BBR0VTSVpFKTsKICBpZiAocGFnZV9zaXplIDw9IDAp
IHJldHVybiBmYWxzZTsKICBpZiAobXIuYmxvY2tfc2l6ZSA9PSAwIHx8IG1yLmJsb2NrX3NpemUg
JSAodW5zaWduZWQgbG9uZylwYWdlX3NpemUgIT0gMCkgcmV0dXJuIGZhbHNlOwogIGlmIChtci5m
cmFtZV9zaXplIDwgVFBBQ0tFVDJfSERSTEVOIHx8CiAgICAgIG1yLmZyYW1lX3NpemUgJSBUUEFD
S0VUX0FMSUdOTUVOVCAhPSAwKSByZXR1cm4gZmFsc2U7CiAgaWYgKG1yLmJsb2NrX3NpemUgJSBt
ci5mcmFtZV9zaXplICE9IDApIHJldHVybiBmYWxzZTsKICB1bnNpZ25lZCBmcmFtZXNfcGVyX2Js
b2NrID0gbXIuYmxvY2tfc2l6ZSAvIG1yLmZyYW1lX3NpemU7CiAgaWYgKGZyYW1lc19wZXJfYmxv
Y2sgPT0gMCB8fCBtci5ibG9ja19uciA9PSAwKSByZXR1cm4gZmFsc2U7CiAgaWYgKGZyYW1lc19w
ZXJfYmxvY2sgPiBVSU5UX01BWCAvIG1yLmJsb2NrX25yKSByZXR1cm4gZmFsc2U7CiAgaWYgKGZy
YW1lc19wZXJfYmxvY2sgKiBtci5ibG9ja19uciAhPSBtci5mcmFtZV9ucikgcmV0dXJuIGZhbHNl
OwogIGlmICgoc2l6ZV90KW1yLmJsb2NrX3NpemUgPiBzaXplX21heCAvIChzaXplX3QpbXIuYmxv
Y2tfbnIpIHJldHVybiBmYWxzZTsKICBpZiAoKHNpemVfdCltci5ibG9ja19zaXplICogKHNpemVf
dCltci5ibG9ja19uciAhPSA0VSAqIDEwMjRVICogMTAyNFUpIHJldHVybiBmYWxzZTsKICByZXR1
cm4gdHJ1ZTsKfQoKc3RhdGljIGJvb2wgc2V0dXBfbW1hcF9yaW5nKGludCBmZCwgTW1hcFJpbmcg
Jm1yKSB7CiAgaWYgKCF2YWxpZF9yaW5nX2dlb21ldHJ5KG1yKSkgewogICAgbG9nbXNnKCJpbnZh
bGlkIGZpeGVkIFRQQUNLRVRfVjIgcmluZyBnZW9tZXRyeSIpOwogICAgcmV0dXJuIGZhbHNlOwog
IH0KICBpbnQgdmVyID0gVFBBQ0tFVF9WMjsKICBpZiAoc2V0c29ja29wdChmZCwgU09MX1BBQ0tF
VCwgUEFDS0VUX1ZFUlNJT04sICZ2ZXIsIHNpemVvZih2ZXIpKSA8IDApIHsKICAgIHJldHVybiBm
YWxzZTsKICB9CiAgc3RydWN0IHRwYWNrZXRfcmVxIHJlcTsKICBtZW1zZXQoJnJlcSwgMCwgc2l6
ZW9mKHJlcSkpOwogIHJlcS50cF9ibG9ja19zaXplID0gbXIuYmxvY2tfc2l6ZTsKICByZXEudHBf
YmxvY2tfbnIgPSBtci5ibG9ja19ucjsKICByZXEudHBfZnJhbWVfc2l6ZSA9IG1yLmZyYW1lX3Np
emU7CiAgcmVxLnRwX2ZyYW1lX25yID0gbXIuZnJhbWVfbnI7CgogIGlmIChzZXRzb2Nrb3B0KGZk
LCBTT0xfUEFDS0VULCBQQUNLRVRfUlhfUklORywgJnJlcSwgc2l6ZW9mKHJlcSkpIDwgMCkgewog
ICAgcmV0dXJuIGZhbHNlOwogIH0KICBtci5yaW5nX3NpemUgPSAoc2l6ZV90KXJlcS50cF9ibG9j
a19zaXplICogKHNpemVfdClyZXEudHBfYmxvY2tfbnI7CiAgbXIuZnJhbWVzX3Blcl9ibG9jayA9
IHJlcS50cF9ibG9ja19zaXplIC8gcmVxLnRwX2ZyYW1lX3NpemU7CiAgbXIuZnJhbWVfaWR4ID0g
MDsKCiAgbXIucmluZyA9IG1tYXAoTlVMTCwgbXIucmluZ19zaXplLCBQUk9UX1JFQUQgfCBQUk9U
X1dSSVRFLCBNQVBfU0hBUkVELCBmZCwgMCk7CiAgaWYgKG1yLnJpbmcgPT0gTUFQX0ZBSUxFRCkg
ewogICAgbXIucmluZ19zaXplID0gMDsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgcmV0dXJuIHRy
dWU7Cn0KCnN0YXRpYyBib29sIHJlbGVhc2VfbW1hcF9yaW5nKGludCBmZCwgTW1hcFJpbmcgJm1y
KSB7CiAgYm9vbCBvayA9IHRydWU7CiAgaWYgKG1yLnJpbmcgIT0gTUFQX0ZBSUxFRCkgewogICAg
aWYgKG11bm1hcChtci5yaW5nLCBtci5yaW5nX3NpemUpICE9IDApIG9rID0gZmFsc2U7CiAgICBt
ci5yaW5nID0gTUFQX0ZBSUxFRDsKICB9CiAgc3RydWN0IHRwYWNrZXRfcmVxIGVtcHR5X3JlcTsK
ICBtZW1zZXQoJmVtcHR5X3JlcSwgMCwgc2l6ZW9mKGVtcHR5X3JlcSkpOwogIGlmIChzZXRzb2Nr
b3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfUlhfUklORywKICAgICAgICAgICAgICAgICAmZW1w
dHlfcmVxLCBzaXplb2YoZW1wdHlfcmVxKSkgIT0gMCkgb2sgPSBmYWxzZTsKICBtci5yaW5nX3Np
emUgPSAwOwogIHJldHVybiBvazsKfQoKc3RhdGljIGJvb2wgdmFsaWRfcmluZ19mcmFtZShjb25z
dCBzdHJ1Y3QgdHBhY2tldDJfaGRyICpoZHIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
dW5zaWduZWQgZnJhbWVfc2l6ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplX3Qg
KnBhY2tldF9vZmZzZXQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZV90ICpwYWNr
ZXRfbGVuZ3RoKSB7CiAgY29uc3QgdW5zaWduZWQgbWFjID0gaGRyLT50cF9tYWM7CiAgY29uc3Qg
dW5zaWduZWQgbmV0ID0gaGRyLT50cF9uZXQ7CiAgY29uc3QgdW5zaWduZWQgc25hcGxlbiA9IGhk
ci0+dHBfc25hcGxlbjsKICBjb25zdCB1bnNpZ25lZCB3aXJlX2xlbiA9IGhkci0+dHBfbGVuOwog
IGlmIChtYWMgPCBUUEFDS0VUMl9IRFJMRU4gfHwgbWFjID4gZnJhbWVfc2l6ZSkgcmV0dXJuIGZh
bHNlOwogIGlmIChzbmFwbGVuID4gd2lyZV9sZW4gfHwgc25hcGxlbiA+IGZyYW1lX3NpemUgLSBt
YWMpIHJldHVybiBmYWxzZTsKICBpZiAobmV0IDwgbWFjIHx8IG5ldCA+IG1hYyArIHNuYXBsZW4p
IHJldHVybiBmYWxzZTsKICAqcGFja2V0X29mZnNldCA9IG1hYzsKICAqcGFja2V0X2xlbmd0aCA9
IHNuYXBsZW47CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBpbnQgcnVuX3JpbmdfZml4dHVyZSgp
IHsKICBNbWFwUmluZyBtcjsKICBpZiAoIXZhbGlkX3JpbmdfZ2VvbWV0cnkobXIpKSByZXR1cm4g
MjA7CiAgdW5zaWduZWQgY2hhciBmcmFtZVsyMDQ4XTsKICBtZW1zZXQoZnJhbWUsIDAsIHNpemVv
ZihmcmFtZSkpOwogIHN0cnVjdCB0cGFja2V0Ml9oZHIgKmhkciA9IChzdHJ1Y3QgdHBhY2tldDJf
aGRyICopZnJhbWU7CiAgc2l6ZV90IG9mZiA9IDAsIGxlbiA9IDA7CiAgaGRyLT50cF9tYWMgPSBU
UEFDS0VUMl9IRFJMRU47CiAgaGRyLT50cF9uZXQgPSBUUEFDS0VUMl9IRFJMRU4gKyAxNDsKICBo
ZHItPnRwX3NuYXBsZW4gPSAxMjg7CiAgaGRyLT50cF9sZW4gPSAxMjg7CiAgaWYgKCF2YWxpZF9y
aW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikgfHwKICAgICAgb2ZmICE9
IFRQQUNLRVQyX0hEUkxFTiB8fCBsZW4gIT0gMTI4KSByZXR1cm4gMjE7CiAgaGRyLT50cF9tYWMg
PSBUUEFDS0VUMl9IRFJMRU4gLSAxOwogIGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9m
KGZyYW1lKSwgJm9mZiwgJmxlbikpIHJldHVybiAyMjsKICBoZHItPnRwX21hYyA9IFRQQUNLRVQy
X0hEUkxFTjsKICBoZHItPnRwX3NuYXBsZW4gPSBzaXplb2YoZnJhbWUpOwogIGhkci0+dHBfbGVu
ID0gc2l6ZW9mKGZyYW1lKTsKICBpZiAodmFsaWRfcmluZ19mcmFtZShoZHIsIHNpemVvZihmcmFt
ZSksICZvZmYsICZsZW4pKSByZXR1cm4gMjM7CiAgaGRyLT50cF9zbmFwbGVuID0gMTI5OwogIGhk
ci0+dHBfbGVuID0gMTI4OwogIGlmICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1l
KSwgJm9mZiwgJmxlbikpIHJldHVybiAyNDsKICBoZHItPnRwX3NuYXBsZW4gPSAxMjg7CiAgaGRy
LT50cF9sZW4gPSAxMjg7CiAgaGRyLT50cF9uZXQgPSBUUEFDS0VUMl9IRFJMRU4gLSAxOwogIGlm
ICh2YWxpZF9yaW5nX2ZyYW1lKGhkciwgc2l6ZW9mKGZyYW1lKSwgJm9mZiwgJmxlbikpIHJldHVy
biAyNTsKICBtci5mcmFtZV9ucisrOwogIGlmICh2YWxpZF9yaW5nX2dlb21ldHJ5KG1yKSkgcmV0
dXJuIDI2OwogIHJldHVybiAwOwp9CgpzdGF0aWMgaW50IHJ1bl9maXh0dXJlKCkgewogIHN0ZDo6
c3RyaW5nIHJlcSA9ICJHRVQgL2FwaS9pdGVtcz94PTEgSFRUUC8xLjFcclxuSG9zdDogYXBpLmxv
Y2FsXHJcbkF1dGhvcml6YXRpb246IEJhc2ljIFlXeHBZMlU2YzJWamNtVjBcclxuVHJhY2VwYXJl
bnQ6IDAwLTAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmLTAxMjM0NTY3ODlhYmNkZWYt
MDFcclxuXHJcbiI7CiAgRXZlbnQgZTsgUmVxdWVzdE1ldGEgbWV0YTsgZS50cyA9IDE3MDAwMDAw
MDA7IGUuaG9zdCA9ICJjcHAtbm9kZSI7IGUuc2VydmljZSA9ICJwb3J0OjgwODAiOyBlLmNhbGxl
ciA9ICIxMC4wLjAuOSI7IGUuY2FsbGVyX3BvcnQgPSA1MTAwMDsgZS5kc3RfaXAgPSAiMTAuMC4w
LjIiOyBlLmRzdF9wb3J0ID0gODA4MDsgZS5yZXFfYnl0ZXMgPSAodW5zaWduZWQpcmVxLnNpemUo
KTsgcGFyc2VfcmVxdWVzdChyZXEuZGF0YSgpLCByZXEuc2l6ZSgpIC0gNCwgJmUsICZtZXRhKTsg
ZS5zdGF0dXMgPSAyMDA7IGUuaGFzX3N0YXR1cyA9IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBl
Lmhhc19kdXJhdGlvbiA9IHRydWU7IGUucmVzcF9ieXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1
ZTsgZW1pdF9ldmVudChlKTsgcmV0dXJuIDA7Cn0KCnN0YXRpYyBpbnQgcnVuX3dzc2VfZml4dHVy
ZSgpIHsKICBjb25zdCBjaGFyICpuYW1lc3BhY2VzW10gPSB7CiAgICAiaHR0cDovL2RvY3Mub2Fz
aXMtb3Blbi5vcmcvd3NzLzIwMDQvMDEvb2FzaXMtMjAwNDAxLXdzcy13c3NlY3VyaXR5LXNlY2V4
dC0xLjAueHNkIiwKICAgICJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDAyLzA3L3Nl
Y2V4dCIsCiAgICAiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwMi8xMi9zZWNleHQi
LAogICAgImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDMvMDYvc2VjZXh0IgogIH07
CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCA0OyArK2kpIHsKICAgIHN0ZDo6c3RyaW5nIGJvZHkg
PSAiPHM6RW52ZWxvcGUgeG1sbnM6cz0ndXJuOnNvYXAnIHhtbG5zOnc9JyIgKyBzdGQ6OnN0cmlu
ZyhuYW1lc3BhY2VzW2ldKSArCiAgICAgICInPjxzOkhlYWRlcj48dzpVc2VybmFtZVRva2VuPjx3
OlVzZXJuYW1lPm5hdGl2ZS5maXh0dXJlPC93OlVzZXJuYW1lPiIKICAgICAgIjx3OlBhc3N3b3Jk
PlNFTlNJVElWRV9QQVNTV09SRDwvdzpQYXNzd29yZD48L3c6VXNlcm5hbWVUb2tlbj48L3M6SGVh
ZGVyPiI7CiAgICBzdGQ6OnN0cmluZyB1c2VyID0gZXh0cmFjdF93c3NlX3VzZXJuYW1lKGJvZHkp
OwogICAgaWYgKHVzZXIgIT0gIm5hdGl2ZS5maXh0dXJlIikgcmV0dXJuIDM7CiAgICBzdGQ6OmNv
dXQgPDwgdXNlciA8PCAiXG4iOwogIH0KICBzdGQ6OnN0cmluZyBtYWxpY2lvdXMgPSAiPCFET0NU
WVBFIHggWzwhRU5USVRZIHB3ICdzZWNyZXQnPl0+PHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSci
ICsKICAgIHN0ZDo6c3RyaW5nKG5hbWVzcGFjZXNbMF0pICsgIic+PHc6VXNlcm5hbWU+JnB3Ozwv
dzpVc2VybmFtZT48L3c6VXNlcm5hbWVUb2tlbj4iOwogIGlmICghZXh0cmFjdF93c3NlX3VzZXJu
YW1lKG1hbGljaW91cykuZW1wdHkoKSkgcmV0dXJuIDQ7CiAgc3RkOjpzdHJpbmcgd3JvbmdfbnMg
PSAiPHc6VXNlcm5hbWVUb2tlbiB4bWxuczp3PSd1cm46bm90LXdzc2UnPjx3OlVzZXJuYW1lPndy
b25nPC93OlVzZXJuYW1lPjwvdzpVc2VybmFtZVRva2VuPiI7CiAgaWYgKCFleHRyYWN0X3dzc2Vf
dXNlcm5hbWUod3JvbmdfbnMpLmVtcHR5KCkpIHJldHVybiA1OwogIHN0ZDo6c3RyaW5nIHVubmFt
ZXNwYWNlZCA9ICI8VXNlcm5hbWVUb2tlbj48VXNlcm5hbWU+d3Jvbmc8L1VzZXJuYW1lPjwvVXNl
cm5hbWVUb2tlbj4iOwogIGlmICghZXh0cmFjdF93c3NlX3VzZXJuYW1lKHVubmFtZXNwYWNlZCku
ZW1wdHkoKSkgcmV0dXJuIDY7CiAgc3RkOjpzdHJpbmcgZXNjYXBlZCA9ICI8dzpVc2VybmFtZVRv
a2VuIHhtbG5zOnc9JyIgKyBzdGQ6OnN0cmluZyhuYW1lc3BhY2VzWzBdKSArCiAgICAiJz48dzpV
c2VybmFtZT5uYXRpdmUmYW1wO2ZpeHR1cmU8L3c6VXNlcm5hbWU+IjsKICBpZiAoZXh0cmFjdF93
c3NlX3VzZXJuYW1lKGVzY2FwZWQpICE9ICJuYXRpdmUmZml4dHVyZSIpIHJldHVybiA3OwogIHN0
ZDo6c3RyaW5nIHRvb19sb25nID0gIjx3OlVzZXJuYW1lVG9rZW4geG1sbnM6dz0nIiArIHN0ZDo6
c3RyaW5nKG5hbWVzcGFjZXNbMF0pICsKICAgICInPjx3OlVzZXJuYW1lPiIgKyBzdGQ6OnN0cmlu
ZyhNQVhfV1NTRV9VU0VSTkFNRSArIDEsICd4JykgKyAiPC93OlVzZXJuYW1lPiI7CiAgaWYgKCFl
eHRyYWN0X3dzc2VfdXNlcm5hbWUodG9vX2xvbmcpLmVtcHR5KCkpIHJldHVybiA4OwogIHJldHVy
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
XSwgIi0tcmluZy1maXh0dXJlIikpIHJldHVybiBydW5fcmluZ19maXh0dXJlKCk7CiAgc3RkOjpz
dHJpbmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0czsgaW50IGk7IGludCB3b3Jr
ZXJzID0gMTsKICBzdGQ6OnN0cmluZyBlbmRwb2ludDsKICBib29sIGNhcGFiaWxpdHlfcHJvYmUg
PSBmYWxzZTsKICBjb25zdCBjaGFyICp3c3NlX2VudiA9IGdldGVudigiTlRfV1NTRV9CT0RZX0JZ
VEVTIik7CiAgaWYgKHdzc2VfZW52ICYmICFwYXJzZV93c3NlX3NpemUod3NzZV9lbnYsICZnX3dz
c2VfYm9keV9ieXRlcykpIHsKICAgIGZwcmludGYoc3RkZXJyLCAid3NzZSBib2R5IGJ5dGVzIG11
c3QgYmUgaW4gcmFuZ2UgMC4uNjU1MzZcbiIpOyByZXR1cm4gMjsKICB9CiAgZm9yIChpID0gMTsg
aSA8IGFyZ2M7ICsraSkgewogICAgaWYgKCFzdHJjbXAoYXJndltpXSwgIi1pIikgJiYgaSArIDEg
PCBhcmdjKSBpZmFjZSA9IGFyZ3ZbKytpXTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwg
Ii1wIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIHdoaWxlIChpICsgMSA8IGFyZ2MgJiYgYXJn
dltpICsgMV1bMF0gIT0gJy0nKSB7CiAgICAgICAgY2hhciAqcSA9IHN0cnRvayhhcmd2WysraV0s
ICIsICIpOwogICAgICAgIHdoaWxlIChxKSB7IGxvbmcgcCA9IGF0b2wocSk7IGlmICh2YWxpZF9w
b3J0KCh1bnNpZ25lZClwKSkgcG9ydHMucHVzaF9iYWNrKCh1bnNpZ25lZClwKTsgcSA9IHN0cnRv
ayhOVUxMLCAiLCAiKTsgfQogICAgICB9CiAgICB9CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3Zb
aV0sICItLWVuZHBvaW50IikgJiYgaSArIDEgPCBhcmdjKSBlbmRwb2ludCA9IGFyZ3ZbKytpXTsK
ICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tY2FwYWJpbGl0eS1wcm9iZSIpKSBjYXBh
YmlsaXR5X3Byb2JlID0gdHJ1ZTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0tc3Bv
b2wiKSAmJiBpICsgMSA8IGFyZ2MpICsraTsgLyogaWdub3JlZDogMCBkaXNrIHdyaXRlICovCiAg
ICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaiIpICYmIGkgKyAxIDwgYXJnYykgd29ya2Vy
cyA9IGF0b2koYXJndlsrK2ldKTsKICAgIGVsc2UgaWYgKCFzdHJjbXAoYXJndltpXSwgIi0td3Nz
ZS1ib2R5LWJ5dGVzIikgJiYgaSArIDEgPCBhcmdjKSB7CiAgICAgIGlmICghcGFyc2Vfd3NzZV9z
aXplKGFyZ3ZbKytpXSwgJmdfd3NzZV9ib2R5X2J5dGVzKSkgewogICAgICAgIGZwcmludGYoc3Rk
ZXJyLCAid3NzZSBib2R5IGJ5dGVzIG11c3QgYmUgaW4gcmFuZ2UgMC4uNjU1MzZcbiIpOyByZXR1
cm4gMjsKICAgICAgfQogICAgfQogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWgiKSB8
fCAhc3RyY21wKGFyZ3ZbaV0sICItLWhlbHAiKSkgewogICAgICBmcHJpbnRmKHN0ZGVyciwgInVz
YWdlOiBudC1zbmlmZi1jcHAgWy1pIGlmYWNlXSBbLXAgcG9ydHNdIFstLWVuZHBvaW50IFVSTF0g
Wy1qIHdvcmtlcnNdIFstLXdzc2UtYm9keS1ieXRlcyAwLi42NTUzNl1cbiIpOwogICAgICByZXR1
cm4gMDsKICAgIH0KICAgIGVsc2UgeyBmcHJpbnRmKHN0ZGVyciwgInVua25vd24gb3IgaW5jb21w
bGV0ZSBhcmd1bWVudDogJXNcbiIsIGFyZ3ZbaV0pOyByZXR1cm4gMjsgfQogIH0KICBpZiAocG9y
dHMuZW1wdHkoKSkgeyBwb3J0cy5wdXNoX2JhY2soODApOyBwb3J0cy5wdXNoX2JhY2soODAwMyk7
IHBvcnRzLnB1c2hfYmFjayg4MDA1KTsgcG9ydHMucHVzaF9iYWNrKDgwMDcpOyBwb3J0cy5wdXNo
X2JhY2soODAwOSk7IHBvcnRzLnB1c2hfYmFjayg4MDEwKTsgcG9ydHMucHVzaF9iYWNrKDgwMTEp
OyB9CiAgaWYgKHBvcnRzLnNpemUoKSA+IE1BWF9QT1JUUykgewogICAgZnByaW50ZihzdGRlcnIs
ICJhdCBtb3N0IDMwIG1vbml0b3JlZCBwb3J0cyBhcmUgc3VwcG9ydGVkIGJ5IHRoZSBzYWZlIGNC
UEYgcHJvZ3JhbVxuIik7CiAgICByZXR1cm4gMjsKICB9CiAgaWYgKHdvcmtlcnMgIT0gMSkgewog
ICAgZnByaW50ZihzdGRlcnIsICJvbmx5IG9uZSBjYXB0dXJlIHdvcmtlciBpcyBwZXJtaXR0ZWRc
biIpOwogICAgcmV0dXJuIDI7CiAgfQogICh2b2lkKXdvcmtlcnM7CgogIGlmIChjYXBhYmlsaXR5
X3Byb2JlKSByZXR1cm4gcnVuX2NhcGFiaWxpdHlfcHJvYmUoaWZhY2UsIHBvcnRzKTsKCiAgaW5p
dF9ybmcoKTsKICBtZW1zZXQoZ19tb25pdG9yZWRfcG9ydHMsIDAsIHNpemVvZihnX21vbml0b3Jl
ZF9wb3J0cykpOwogIGZvciAoc2l6ZV90IGsgPSAwOyBrIDwgcG9ydHMuc2l6ZSgpOyArK2spIHsK
ICAgIGlmIChwb3J0c1trXSA8IDY1NTM2KSBnX21vbml0b3JlZF9wb3J0c1twb3J0c1trXV0gPSB0
cnVlOwogIH0KCiAgY29uc3QgY2hhciAqbm9kZV9lbnYgPSBnZXRlbnYoIk5UX05PREVfTkFNRSIp
OwogIHN0ZDo6c3RyaW5nIG5vZGUgPSAobm9kZV9lbnYgJiYgKm5vZGVfZW52KSA/IG5vZGVfZW52
IDogaG9zdF9uYW1lKCk7CgogIGdfZW5kcG9pbnQgPSBlbmRwb2ludDsKICBnX3NoaXBfbm9kZSA9
IG5vZGU7CgogIE1tYXBSaW5nIHJpbmc7CiAgaW50IGZkID0gb3Blbl9jYXB0dXJlX3NvY2tldChp
ZmFjZSwgcG9ydHMsIHJpbmcpOwogIGlmIChmZCA8IDApIHJldHVybiAyOwoKICBzaWduYWwoU0lH
VEVSTSwgc3RvcF9zaWduYWwpOwogIHNpZ25hbChTSUdJTlQsIHN0b3Bfc2lnbmFsKTsKICBzZXR2
YnVmKHN0ZG91dCwgTlVMTCwgX0lPTEJGLCA2NTUzNik7CiAgc3RkOjptYXA8Rmxvd0tleSwgRmxv
dz4gZmxvd3M7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+IHBl
bmRpbmc7CgogIGxvZ21zZygiUEFDS0VUX01NQVAgKFRQQUNLRVRfVjIpIHN0cmljdCBSWCByaW5n
IGVuYWJsZWQgKDRNQiwgMjA0OCBmcmFtZXMpIik7CiAgaWYgKGdfd3NzZV9ib2R5X2J5dGVzKSB7
CiAgICBsb2dtc2coIldTU0UgVXNlcm5hbWVUb2tlbiBpbnNwZWN0aW9uIGVuYWJsZWQgKGJvdW5k
ZWQgdG8gIiArIG51bWJlcl9zdHJpbmcoZ193c3NlX2JvZHlfYnl0ZXMpICsgIiBieXRlcy9yZXF1
ZXN0KSIpOwogIH0KICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSkgewogICAgbG9nbXNnKCJzaW5n
bGUtYmluYXJ5IGluLW1lbW9yeSBtb2RlOiBzaGlwcGluZyBkaXJlY3RseSB0byAiICsgZ19lbmRw
b2ludCArICIgKDAgZGlzayBJL08pIik7CiAgfQogIGxvZ21zZygibGlzdGVuaW5nIik7CgogIHRp
bWVfdCBsYXN0ID0gdGltZShOVUxMKSwgbGFzdF9mbHVzaCA9IGxhc3Q7CiAgYm9vbCByaW5nX2lu
dGVncml0eV9mYWlsdXJlID0gZmFsc2U7CgogIHN0cnVjdCBwb2xsZmQgcGZkOwogIHBmZC5mZCA9
IGZkOwogIHBmZC5ldmVudHMgPSBQT0xMSU4gfCBQT0xMRVJSOwogIHBmZC5yZXZlbnRzID0gMDsK
CiAgd2hpbGUgKGdfcnVubmluZykgewogICAgaW50IHJjID0gcG9sbCgmcGZkLCAxLCAxMDAwKTsK
ICAgIGlmIChyYyA8IDAgJiYgZXJybm8gPT0gRUlOVFIpIHsKICAgICAgLyogU2lnbmFsIGhhbmRs
ZWQsIGxvb3AgY29uZGl0aW9uIHdpbGwgY2hlY2sgZ19ydW5uaW5nICovCiAgICB9IGVsc2UgaWYg
KHJjID49IDApIHsKICAgICAgLyogRHJhaW4gYWxsIHJlYWR5IGZyYW1lcyBpbiB0aGUgcmluZyB3
aXRob3V0IGV4dHJhIHN5c2NhbGxzLiAqLwogICAgICB3aGlsZSAoZ19ydW5uaW5nKSB7CiAgICAg
ICAgICB1bnNpZ25lZCBiX2lkeCA9IHJpbmcuZnJhbWVfaWR4IC8gcmluZy5mcmFtZXNfcGVyX2Js
b2NrOwogICAgICAgICAgdW5zaWduZWQgZl9pbl9iID0gcmluZy5mcmFtZV9pZHggJSByaW5nLmZy
YW1lc19wZXJfYmxvY2s7CiAgICAgICAgICB1aW50OF90ICpmcmFtZV9wdHIgPSAoKHVpbnQ4X3Qg
KilyaW5nLnJpbmcpICsgKGJfaWR4ICogcmluZy5ibG9ja19zaXplKSArIChmX2luX2IgKiByaW5n
LmZyYW1lX3NpemUpOwogICAgICAgICAgdm9sYXRpbGUgc3RydWN0IHRwYWNrZXQyX2hkciAqdm9s
YXRpbGVfaGRyID0KICAgICAgICAgICAgICAodm9sYXRpbGUgc3RydWN0IHRwYWNrZXQyX2hkciAq
KWZyYW1lX3B0cjsKCiAgICAgICAgICBpZiAoISh2b2xhdGlsZV9oZHItPnRwX3N0YXR1cyAmIFRQ
X1NUQVRVU19VU0VSKSkgewogICAgICAgICAgICBicmVhazsgLyogTm8gbW9yZSBrZXJuZWwtcG9w
dWxhdGVkIGZyYW1lcyBpbiByaW5nIHJpZ2h0IG5vdyAqLwogICAgICAgICAgfQogICAgICAgICAg
X19zeW5jX3N5bmNocm9uaXplKCk7IC8qIGFjcXVpcmUga2VybmVsLW93bmVkIGZyYW1lIGNvbnRl
bnRzICovCgogICAgICAgICAgY29uc3Qgc3RydWN0IHRwYWNrZXQyX2hkciAqaGRyID0KICAgICAg
ICAgICAgICAoY29uc3Qgc3RydWN0IHRwYWNrZXQyX2hkciAqKWZyYW1lX3B0cjsKICAgICAgICAg
IHNpemVfdCBwYWNrZXRfb2Zmc2V0ID0gMCwgcGFja2V0X2xlbmd0aCA9IDA7CiAgICAgICAgICBp
ZiAoIXZhbGlkX3JpbmdfZnJhbWUoaGRyLCByaW5nLmZyYW1lX3NpemUsCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgJnBhY2tldF9vZmZzZXQsICZwYWNrZXRfbGVuZ3RoKSkgewogICAg
ICAgICAgICBfX3N5bmNfc3luY2hyb25pemUoKTsKICAgICAgICAgICAgdm9sYXRpbGVfaGRyLT50
cF9zdGF0dXMgPSBUUF9TVEFUVVNfS0VSTkVMOwogICAgICAgICAgICByaW5nX2ludGVncml0eV9m
YWlsdXJlID0gdHJ1ZTsKICAgICAgICAgICAgZ19ydW5uaW5nID0gMDsKICAgICAgICAgICAgbG9n
bXNnKCJpbnZhbGlkIFRQQUNLRVRfVjIgZnJhbWUgbWV0YWRhdGE7IHN0b3BwaW5nIGNhcHR1cmUi
KTsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICB9CiAgICAgICAgICBpZiAocGFja2V0X2xl
bmd0aCA+IDApIHsKICAgICAgICAgICAgY29uc3QgdW5zaWduZWQgY2hhciAqcGt0ID0gZnJhbWVf
cHRyICsgcGFja2V0X29mZnNldDsKICAgICAgICAgICAgaGFuZGxlX3BhY2tldChwa3QsIHBhY2tl
dF9sZW5ndGgsIG5vZGUsIHBvcnRzLCBmbG93cywgcGVuZGluZyk7CiAgICAgICAgICB9CgogICAg
ICAgICAgX19zeW5jX3N5bmNocm9uaXplKCk7IC8qIHJlbGVhc2UgYWxsIHJlYWRzIGJlZm9yZSBy
ZXR1cm5pbmcgb3duZXJzaGlwICovCiAgICAgICAgICB2b2xhdGlsZV9oZHItPnRwX3N0YXR1cyA9
IFRQX1NUQVRVU19LRVJORUw7CiAgICAgICAgICByaW5nLmZyYW1lX2lkeCA9IChyaW5nLmZyYW1l
X2lkeCArIDEpICUgcmluZy5mcmFtZV9ucjsKICAgICAgfQogICAgICBpZiAoZ19lbmRwb2ludC5l
bXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKICAgIH0KCiAgICB0aW1lX3Qgbm93ID0gdGltZShO
VUxMKTsKICAgIGlmIChub3cgLSBsYXN0ID49IDEpIHsKICAgICAgc3dlZXAoZmxvd3MsIHBlbmRp
bmcsIG5vdyk7CiAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291dC5mbHVzaCgp
OwogICAgICBsYXN0ID0gbm93OwogICAgfQoKICAgIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7
CiAgICAgIGlmIChub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyB8fCBnX3NoaXBfYnVmLnNp
emUoKSA+PSBNQVhfQkFUQ0gpIHsKICAgICAgICBpZiAoIWdfc2hpcF9idWYuZW1wdHkoKSkgc2Vu
ZF9iYXRjaGVzKGdfZW5kcG9pbnQsIGdfc2hpcF9ub2RlLCAmZ19zaGlwX2J1ZiwgdHJ1ZSk7CiAg
ICAgICAgbGFzdF9mbHVzaCA9IG5vdzsKICAgICAgfQogICAgfQogIH0KCiAgLyogQSByZXNwb25z
ZSBpcyBvcHRpb25hbCBlbnJpY2htZW50LiBQcmVzZXJ2ZSByZXF1ZXN0cyBzdGlsbCBhd2FpdGlu
ZyBhCiAgICogcmVzcG9uc2Ugd2hlbiBTSUdURVJNL3Jlc3RhcnQgZW5kcyBjYXB0dXJlLiAqLwog
IGZsdXNoX2FsbF9wZW5kaW5nKHBlbmRpbmcpOwogIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0
ZDo6Y291dC5mbHVzaCgpOwoKICBpZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSAmJiAhZ19zaGlwX2J1
Zi5lbXB0eSgpKSB7CiAgICBzZW5kX2JhdGNoZXMoZ19lbmRwb2ludCwgZ19zaGlwX25vZGUsICZn
X3NoaXBfYnVmLCB0cnVlKTsKICB9CgogIHN0cnVjdCB0cGFja2V0X3N0YXRzIHBhY2tldF9zdGF0
czsKICBzb2NrbGVuX3QgcGFja2V0X3N0YXRzX2xlbiA9IHNpemVvZihwYWNrZXRfc3RhdHMpOwog
IG1lbXNldCgmcGFja2V0X3N0YXRzLCAwLCBzaXplb2YocGFja2V0X3N0YXRzKSk7CiAgaWYgKGdl
dHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9TVEFUSVNUSUNTLAogICAgICAgICAgICAg
ICAgICZwYWNrZXRfc3RhdHMsICZwYWNrZXRfc3RhdHNfbGVuKSA9PSAwKSB7CiAgICBsb2dtc2co
InBhY2tldCBzdGF0czogcmVjZWl2ZWQ9IiArIG51bWJlcl9zdHJpbmcocGFja2V0X3N0YXRzLnRw
X3BhY2tldHMpICsKICAgICAgICAgICAiIGRyb3BwZWQ9IiArIG51bWJlcl9zdHJpbmcocGFja2V0
X3N0YXRzLnRwX2Ryb3BzKSk7CiAgfQogIGlmICghcmVsZWFzZV9tbWFwX3JpbmcoZmQsIHJpbmcp
KSB7CiAgICBsb2dtc2coIlRQQUNLRVRfVjIgY2xlYW51cCBmYWlsZWQiKTsKICAgIHJpbmdfaW50
ZWdyaXR5X2ZhaWx1cmUgPSB0cnVlOwogIH0KICBjbG9zZShmZCk7CiAgbG9nbXNnKCJzdG9wcGVk
Iik7CiAgcmV0dXJuIHJpbmdfaW50ZWdyaXR5X2ZhaWx1cmUgPyAyIDogMDsKfQo=
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
c25pZmYtY3BwIC0tcmluZy1maXh0dXJlCgpwY2FwLWZpeHR1cmU6IHBjYXBfdGVzdF9jcHAKCnBj
YXBfdGVzdF9jcHA6IHBjYXBfdGVzdF9jcHAuY3BwIG50LXNuaWZmLWNwcC5jcHAKCSQoQ1hYKSAk
KENYWEZMQUdTKSBwY2FwX3Rlc3RfY3BwLmNwcCAtbyBwY2FwX3Rlc3RfY3BwCgpjbGVhbjoKCXJt
IC1mIG50LXNuaWZmLWNwcCBudC1zbmlmZi1jcHAtZGVidWcgbnQtc2hpcC1jcHAgcGNhcF90ZXN0
X2NwcAo=
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
