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
#        --endpoint http://HUB:31115
#
# Local bundle usage:
#   sh install-oldkernel.sh --endpoint http://hub:31115
#   sh install-oldkernel.sh --check [--endpoint ...]
#   sh install-oldkernel.sh --uninstall
#
# Env overrides: NT_IFACE=eth1  NT_PORTS=80,...  NT_HUB=http://HUB:30105/oldkernel
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

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --hub)      KIT_URLS="$2"; shift 2 ;;
        --mode)     CAPTURE_MODE="$2"; shift 2 ;;
        --check)    MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        *) die "unknown arg: $1" ;;
    esac
done

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
    [ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1 || true
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
        *'"ok"'*) log "hub protocol OK ($ENDPOINT)" ;;
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
[ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1 || true
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
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
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
PIDFILE=/var/run/networktracing-legacy.pid
CONTROL_FILE=/var/lib/networktracing/remote-desired.json
CONTROL_TOKEN_FILE=/var/lib/networktracing/control.token
CONTROL_RUN=/var/lib/networktracing

case "\$1" in
    start)
        if pgrep -f "\\\$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "\\\$PREFIX/nt-sniff-cpp" >/dev/null; then
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

"$INIT" start || {
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "service failed to start"
}
sleep 2
if ! pgrep -f "$PREFIX/nt-sniff.py" >/dev/null && ! pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null; then
    [ -f "$PREFIX/sniff.log" ] && { echo "--- $PREFIX/sniff.log ---"; cat "$PREFIX/sniff.log"; }
    [ -f "$PREFIX/ship.log" ] && { echo "--- $PREFIX/ship.log ---"; cat "$PREFIX/ship.log"; }
    die "sniffer not running after start"
fi

log "DONE. Sniffer iface=$IFACE ports=$PORTS -> hub $ENDPOINT (capture-as=$SNIFF_AS)"
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
U1NFIHVzZXJuYW1lcyBhcmUgTk9UIGV4dHJhY3RlZCAocHJvZHVjdCBkZWNpc2lvbjogQmFzaWMt
b25seSkuCgpQZXJmb3JtYW5jZToKICAqIGtlcm5lbCBCUEYgZmlsdGVyIChTT19BVFRBQ0hfRklM
VEVSKTogb25seSBJUHY0L1RDUCByZXF1ZXN0cyBkZXN0aW5lZAogICAgdG8gbW9uaXRvcmVkIHBv
cnRzIGFyZSBjb3BpZWQgdXAg4oCUIHJlc3BvbnNlcy9ub2lzZSBuZXZlciByZWFjaCBweXRob24K
ICAqIEhFQURFUi1PTkxZIGNhcHR1cmU6IGV2ZW50cyBlbWl0IGF0IFxyXG5cclxuOyBib2RpZXMg
YXJlIG5vdCBidWZmZXJlZAogICogUEFDS0VUX0ZBTk9VVCAoLWogTik6IE4gZm9ya2VkIHdvcmtl
cnMgc2hhcmUgdGhlIE5JQyBhY3Jvc3MgY29yZXMKVXNhZ2U6ICBweXRob24gbnQtc25pZmYucHkg
Wy1pIGV0aDBdIFstcCA4MCw4MDAzLC4uLl0gWy1qIHdvcmtlcnNdClN0ZG91dDogb25lIEpTT04g
ZXZlbnQgcGVyIGxpbmUgLT4gcGlwZSBpbnRvIG50LXNoaXAucHkuCiIiIgpmcm9tIF9fZnV0dXJl
X18gaW1wb3J0IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBiaW5hc2NpaSwgZXJybm8s
IGpzb24sIG9zLCBzaWduYWwsIHNvY2tldCwgc3RydWN0LCBzeXMsIHRpbWUKCkVUSF9QX0FMTCA9
IDB4MDAwMwpFVEhfUF9JUCA9IDB4MDgwMApFVEhfUF9WTEFOID0gMHg4MTAwCgp0cnk6CiAgICBp
bXBvcnQgbnRfY29udHJvbApleGNlcHQgSW1wb3J0RXJyb3I6CiAgICBudF9jb250cm9sID0gTm9u
ZQoKIyBweTIuNiBzdHItaW5kZXhpbmcgeWllbGRzIDEtY2hhciBzdHIsIG5vdCBpbnQgKHByb3Zl
biBvbiByZWFsIGVsNiBWTSk7CiMgbm9ybWFsaXplIHNvIGJ5dGUtYXQtaW5kZXggd29ya3MgaWRl
bnRpY2FsbHkgdW5kZXIgcHl0aG9uIDIgYW5kIDMKUFkyID0gc3lzLnZlcnNpb25faW5mb1swXSA9
PSAyCgoKZGVmIGIyaShjKToKICAgIHJldHVybiBvcmQoYykgaWYgUFkyIGVsc2UgYwoKTUVUSE9E
UyA9ICgiR0VUIiwgIlBPU1QiLCAiUFVUIiwgIkRFTEVURSIsICJQQVRDSCIsICJIRUFEIiwgIk9Q
VElPTlMiKQoKTUFYX0ZMT1dTID0gODE5MiAgICAgICAgICAgICMgY29uY3VycmVudCB0cmFja2Vk
IGhhbGYtZmxvd3MgKHBlciBkaXJlY3Rpb24pCk1BWF9IRFJTID0gMjYyMTQ0ICAgICAgICAgICAj
IG1heCBieXRlcyBidWZmZXJlZCB3YWl0aW5nIGZvciBcclxuXHJcbgpGTE9XX1RUTCA9IDMwMCAg
ICAgICAgICAgICAgIyBzZWNvbmRzIGJlZm9yZSBpZGxlIGZsb3cgYnVmZmVycyBhcmUgZHJvcHBl
ZAoKCmRlZiBsb2cobXNnKToKICAgIHN5cy5zdGRlcnIud3JpdGUoIm50LXNuaWZmOiAlc1xuIiAl
IG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBwZXJmOiBjQlBGCiMgQXR0
YWNoIGEgY2xhc3NpYyBCUEYgcHJvZ3JhbSBzbyB0aGUgS0VSTkVMIGRyb3BzIGV2ZXJ5dGhpbmcg
dGhhdCBpcyBub3QKIyBJUHY0IFRDUCBkZXN0aW5lZCBUTyBhIG1vbml0b3JlZCBwb3J0LiBSZXF1
ZXN0cyBhbG9uZSBkcml2ZSBldmVudHMKIyAoaGVhZGVyLW9ubHkgY2FwdHVyZSk7IHJlc3BvbnNl
cywgQUNLcyBhbmQgdW5yZWxhdGVkIHRyYWZmaWMgbmV2ZXIgZ2V0CiMgY29waWVkIHRvIHVzZXJz
cGFjZSBhdCBhbGwuClNPX0FUVEFDSF9GSUxURVIgPSAyNgoKZGVmIGJ1aWxkX2JwZihwb3J0cyk6
CiAgICAiIiJDbGFzc2ljIEJQRjogZXRoZXJ0eXBlPT1JUCAmJiBwcm90bz09VENQICYmIGRwb3J0
IGluIHBvcnRzLgogICAgUmV0dXJucyAoZnByb2dfc3RydWN0LCBmaWx0ZXJfYXJyYXkpIGZvciB0
aGUgbGliYyBzZXRzb2Nrb3B0IGNhbGwsCiAgICBvciBOb25lIG9uIGZhaWx1cmUuIE5PVEU6IHNv
Y2tfZnByb2cgY2FycmllcyBhIFBPSU5URVIgdG8gdGhlIGZpbHRlcgogICAgYXJyYXksIHNvIGl0
IG11c3Qgc3RheSBhbGl2ZSB1bnRpbCB0aGUgc3lzY2FsbCDigJQgcHl0aG9uJ3MKICAgIHNvY2tl
dC5zZXRzb2Nrb3B0KHN0cikgZmxhdHRlbmluZyBjYW5ub3QgcHJlc2VydmUgaXQuIiIiCgogICAg
TERIX0FCUyA9IDB4MjggICAjIGxkIFtrXTpoCiAgICBMREJfQUJTID0gMHgzMCAgICMgbGQgW2td
OmIKICAgIEpFUV9LID0gMHgxNSAgICAgIyBqZXEgawogICAgTERYX01TSCA9IDB4QjEgICAjIHgg
PSA0Kihba10mMHhmKSAgKGlobCBieXRlcykKICAgIExESF9JTkQgPSAweDQ4ICAgIyBsZCBbeCtr
XTpoCiAgICBSRVRfSyA9IDB4MDYKCiAgICAjIFBST1ZFTiBkcG9ydCBibG9jayArIHNwb3J0IGJs
b2NrIGF0IFgrMTQgKGNhbGlicmF0ZWQgRU1QSVJJQ0FMTFkgb24KICAgICMgYSBsaXZlIGtlcm5l
bDogaz0xNCBkZWxpdmVycyByZXNwb25zZSBwYWNrZXRzOyB0aGUgY29ycmVsYXRpb24gdGhlbgog
ICAgIyB5aWVsZHMgc3RhdHVzL2R1cmF0aW9uX21zL3Jlc3BfYnl0ZXMgZW5kLXRvLWVuZCkuIFJl
cXVpcmVzIHRoZSAxcwogICAgIyByZWN2IHRpbWVvdXQgaW4gbWFpbigpIOKAlCBibG9ja2luZyBy
ZWN2ICsgQlBGIHN0YXJ2ZXMgYWZ0ZXIgb25lIHBrdC4KICAgIHNrID0gaW50KG9zLmVudmlyb24u
Z2V0KCJOVF9TTklGRl9TUE9SVF9LIiwgIjE0IikpCiAgICBwcyA9IHNvcnRlZChwb3J0cykKICAg
IG4gPSBsZW4ocHMpCiAgICByZXRfcmVqID0gNSArICg0IGlmIHNrIGVsc2UgMikgKiBuCiAgICBy
ZXRfYWNjID0gcmV0X3JlaiArIDEKICAgIHByb2cgPSBbXQogICAgcHJvZy5hcHBlbmQoKExESF9B
QlMsIDAsIDAsIDEyKSkgICAgICAgICAgICAgICAgICMgZXRoZXJ0eXBlID09IElQPwogICAgcHJv
Zy5hcHBlbmQoKEpFUV9LLCAwLCByZXRfcmVqIC0gMiwgMHgwODAwKSkKICAgIHByb2cuYXBwZW5k
KChMREJfQUJTLCAwLCAwLCAyMykpICAgICAgICAgICAgICAgICAjIHByb3RvID09IFRDUD8KICAg
IHByb2cuYXBwZW5kKChKRVFfSywgMCwgcmV0X3JlaiAtIDQsIDYpKQogICAgcHJvZy5hcHBlbmQo
KExEWF9NU0gsIDAsIDAsIDE0KSkgICAgICAgICAgICAgICAgICMgWCA9IGlobCo0CiAgICBmb3Ig
aSwgcCBpbiBlbnVtZXJhdGUocHMpOiAgICAgICAgICAgICAgICAgICAgICAgIyBBOiBkcG9ydCBA
IFgrMTYKICAgICAgICBwcm9nLmFwcGVuZCgoTERIX0lORCwgMCwgMCwgMTYpKQogICAgICAgIGp0
ID0gcmV0X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgIGpmID0gMCBpZiAoaSA8IG4gLSAx
IG9yIHNrKSBlbHNlIChyZXRfcmVqIC0gKGxlbihwcm9nKSArIDEpKQogICAgICAgIHByb2cuYXBw
ZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIGlmIHNrOiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAjIEI6IHNwb3J0IEAgWCtzawogICAgICAgIGZvciBpLCBwIGlu
IGVudW1lcmF0ZShwcyk6CiAgICAgICAgICAgIHByb2cuYXBwZW5kKChMREhfSU5ELCAwLCAwLCBz
aykpCiAgICAgICAgICAgIGp0ID0gcmV0X2FjYyAtIChsZW4ocHJvZykgKyAxKQogICAgICAgICAg
ICBqZiA9IDAgaWYgaSA8IG4gLSAxIGVsc2UgKHJldF9yZWogLSAobGVuKHByb2cpICsgMSkpCiAg
ICAgICAgICAgIHByb2cuYXBwZW5kKChKRVFfSywganQsIGpmLCBwKSkKICAgIHByb2cuYXBwZW5k
KChSRVRfSywgMCwgMCwgMCkpICAgICAgICAgICAgICAgICAgICAjIHJlamVjdAogICAgcHJvZy5h
cHBlbmQoKFJFVF9LLCAwLCAwLCAweDQwMDAwKSkgICAgICAgICAgICAgICMgYWNjZXB0CgogICAg
dHJ5OgogICAgICAgIGltcG9ydCBjdHlwZXMKCiAgICAgICAgY2xhc3MgU29ja0ZpbHRlcihjdHlw
ZXMuU3RydWN0dXJlKToKICAgICAgICAgICAgX2ZpZWxkc18gPSBbKCJjb2RlIiwgY3R5cGVzLmNf
dWludDE2KSwgKCJqdCIsIGN0eXBlcy5jX3VpbnQ4KSwKICAgICAgICAgICAgICAgICAgICAgICAg
KCJqZiIsIGN0eXBlcy5jX3VpbnQ4KSwgKCJrIiwgY3R5cGVzLmNfdWludDMyKV0KCiAgICAgICAg
Y2xhc3MgU29ja0Zwcm9nKGN0eXBlcy5TdHJ1Y3R1cmUpOgogICAgICAgICAgICAjIG1pcnJvcnMg
c3RydWN0IHNvY2tfZnByb2cge3UxNiBsZW47IHNvY2tfZmlsdGVyICpmaWx0ZXJ9OwogICAgICAg
ICAgICAjIGN0eXBlcyBhcHBsaWVzIHRoZSBzYW1lIHBvaW50ZXIgYWxpZ25tZW50IGFzIHRoZSBj
b21waWxlcgogICAgICAgICAgICBfZmllbGRzXyA9IFsoImxlbiIsIGN0eXBlcy5jX3VpbnQxNiks
CiAgICAgICAgICAgICAgICAgICAgICAgICgiZmlsdGVyIiwgY3R5cGVzLlBPSU5URVIoU29ja0Zp
bHRlcikpXQoKICAgICAgICBhcnIgPSAoU29ja0ZpbHRlciAqIGxlbihwcm9nKSkoKQogICAgICAg
IGZvciBpLCAoY29kZSwganQsIGpmLCBrKSBpbiBlbnVtZXJhdGUocHJvZyk6CiAgICAgICAgICAg
IGFycltpXS5jb2RlID0gY29kZTsgYXJyW2ldLmp0ID0ganQKICAgICAgICAgICAgYXJyW2ldLmpm
ID0gamY7IGFycltpXS5rID0gawogICAgICAgIHJldHVybiBTb2NrRnByb2cobGVuKHByb2cpLCBh
cnIpLCBhcnIKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYg
YXBwbHlfcGVyZl9vcHRzKHNvY2ssIHBvcnRzKToKICAgICIiIkJlc3QtZWZmb3J0IGtlcm5lbCBh
c3Npc3Q6IEJQRiBwb3J0IGZpbHRlciArIGJpZyByY3ZidWYuCiAgICBOVF9TTklGRl9OT19CUEY9
MSBkaXNhYmxlcyB0aGUgZmlsdGVyIChkZWJ1Z2dpbmcpLiIiIgogICAgYnVpbHQgPSBOb25lCiAg
ICBpZiBvcy5lbnZpcm9uLmdldCgiTlRfU05JRkZfTk9fQlBGIikgPT0gIjEiOgogICAgICAgIGxv
ZygiTlRfU05JRkZfTk9fQlBGIHNldCDigJQgc2tpcHBpbmcga2VybmVsIGZpbHRlciIpCiAgICBl
bHNlOgogICAgICAgIGJ1aWx0ID0gYnVpbGRfYnBmKHBvcnRzKQogICAgaWYgYnVpbHQgaXMgbm90
IE5vbmU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpbXBvcnQgY3R5cGVzCiAgICAgICAgICAg
IGxpYmMgPSBjdHlwZXMuQ0RMTCgibGliYy5zby42IikKICAgICAgICAgICAgZnByb2csIGFyciA9
IGJ1aWx0ICAgICAgICAgICAgICAgICAgICAgICMga2VlcCBhcnIgcmVmZXJlbmNlZCEKICAgICAg
ICAgICAgcmV0ID0gbGliYy5zZXRzb2Nrb3B0KHNvY2suZmlsZW5vKCksIHNvY2tldC5TT0xfU09D
S0VULAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgU09fQVRUQUNIX0ZJTFRFUiwK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN0eXBlcy5ieXJlZihmcHJvZyksCiAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdHlwZXMuc2l6ZW9mKGZwcm9nKSkKICAg
ICAgICAgICAgaWYgcmV0ID09IDA6CiAgICAgICAgICAgICAgICBsb2coImtlcm5lbCBCUEYgZmls
dGVyIGF0dGFjaGVkICglZCBtb25pdG9yZWQgcG9ydHMpIgogICAgICAgICAgICAgICAgICAgICUg
bGVuKHBvcnRzKSkKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGxvZygiV0FSTjog
QlBGIGF0dGFjaCByZWplY3RlZCBieSBrZXJuZWwgKHJldD0lZCkgIgogICAgICAgICAgICAgICAg
ICAgICLigJQgcnVubmluZyB1bmZpbHRlcmVkIiAlIHJldCkKICAgICAgICBleGNlcHQgRXhjZXB0
aW9uIGFzIGU6CiAgICAgICAgICAgIGxvZygiV0FSTjogQlBGIGZpbHRlciBhdHRhY2ggZmFpbGVk
ICglcykg4oCUIHJ1bm5pbmcgdW5maWx0ZXJlZCIKICAgICAgICAgICAgICAgICUgZSkKICAgIGVs
c2U6CiAgICAgICAgbG9nKCJXQVJOOiBjdHlwZXMgdW5hdmFpbGFibGUg4oCUIHJ1bm5pbmcgd2l0
aG91dCBCUEYgZmlsdGVyIikKICAgIHRyeToKICAgICAgICB3YW50ID0gOCAqIDEwMjQgKiAxMDI0
CiAgICAgICAgc29jay5zZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fUkNW
QlVGLCB3YW50KQogICAgICAgIGdvdCA9IHNvY2suZ2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tF
VCwgc29ja2V0LlNPX1JDVkJVRikKICAgICAgICBsb2coInJjdmJ1ZjogJWQgYnl0ZXMiICUgZ290
KQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZygiV0FSTjogU09fUkNWQlVG
IHJhaXNlIGZhaWxlZDogJXMiICUgZSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gcGVyZjogZmFub3V0ClNPTF9QQUNL
RVQgPSAyNjMKUEFDS0VUX0ZBTk9VVCA9IDE4CgpkZWYgYXBwbHlfZmFub3V0KHNvY2ssIGdyb3Vw
X2lkKToKICAgICIiIktlcm5lbCBsb2FkLWJhbGFuY2VzIHBhY2tldHMgYWNyb3NzIGFsbCBzb2Nr
ZXRzIHNoYXJpbmcgdGhlIGdyb3VwLgogICAgSGFzaGluZyBpcyBwZXItZmxvdy1kaXJlY3Rpb25h
bDsgcmVxdWVzdCBkaXJlY3Rpb24gYWxvbmUgZHJpdmVzIGV2ZW50CiAgICBlbWlzc2lvbiwgc28g
ZGlyZWN0aW9uYWwgc3BsaXRzIGFyZSBzYWZlLiBSZXR1cm5zIFRydWUgb24gc3VjY2Vzcy4iIiIK
ICAgIHRyeToKICAgICAgICBzb2NrLnNldHNvY2tvcHQoU09MX1BBQ0tFVCwgUEFDS0VUX0ZBTk9V
VCwKICAgICAgICAgICAgICAgICAgICAgICAgc3RydWN0LnBhY2soIkkiLCBncm91cF9pZCAmIDB4
RkZGRikpCiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAg
ICAgICBsb2coIldBUk46IFBBQ0tFVF9GQU5PVVQgZmFpbGVkICglcykg4oCUIHNpbmdsZS1wcm9j
ZXNzIGNhcHR1cmUiICUgZSkKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgcGFyc2VfYXJncyhh
cmd2KToKICAgIGlmYWNlID0gTm9uZQogICAgcG9ydHMgPSBbODAsIDgwMDMsIDgwMDUsIDgwMDcs
IDgwMDksIDgwMTAsIDgwMTFdCiAgICB2ZXJib3NlID0gRmFsc2UKICAgIHdvcmtlcnMgPSAxCiAg
ICBpID0gMAogICAgd2hpbGUgaSA8IGxlbihhcmd2KToKICAgICAgICBhID0gYXJndltpXQogICAg
ICAgIGlmIGEgPT0gIi1pIjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAg
ICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLWkgcmVxdWlyZXMgYW4gaW50ZXJmYWNlIikK
ICAgICAgICAgICAgaSArPSAxOyBpZmFjZSA9IGFyZ3ZbaV0KICAgICAgICBlbGlmIGEgPT0gIi1w
IjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAgICAgICAgcmFp
c2UgU3lzdGVtRXhpdCgiLXAgcmVxdWlyZXMgYSBjb21tYS1zZXBhcmF0ZWQgcG9ydCBsaXN0IikK
ICAgICAgICAgICAgaSArPSAxCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHBvcnRz
ID0gW2ludCh4KSBmb3IgeCBpbiBhcmd2W2ldLnNwbGl0KCIsIikgaWYgeC5zdHJpcCgpXQogICAg
ICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoKICAgICAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoImludmFsaWQgcG9ydCBsaXN0IikKICAgICAgICAgICAgaWYgbm90IHBvcnRzIG9yIGFueShu
b3QgdmFsaWRfcG9ydCh4KSBmb3IgeCBpbiBwb3J0cyk6CiAgICAgICAgICAgICAgICByYWlzZSBT
eXN0ZW1FeGl0KCJwb3J0cyBtdXN0IGJlIGluIHJhbmdlIDEuLjY1NTM1IikKICAgICAgICBlbGlm
IGEgPT0gIi1qIjoKICAgICAgICAgICAgaWYgaSArIDEgPj0gbGVuKGFyZ3YpOgogICAgICAgICAg
ICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiLWogcmVxdWlyZXMgYSB3b3JrZXIgY291bnQiKQogICAg
ICAgICAgICBpICs9IDEKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd29ya2VycyA9
IG1heCgxLCBpbnQoYXJndltpXSkpCiAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAg
ICAgICAgICAgICAgcmFpc2UgU3lzdGVtRXhpdCgiaW52YWxpZCB3b3JrZXIgY291bnQiKQogICAg
ICAgIGVsaWYgYSA9PSAiLXYiOgogICAgICAgICAgICB2ZXJib3NlID0gVHJ1ZQogICAgICAgIGVs
aWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFp
c2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4
aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0dXJuIGlmYWNl
LCBzZXQocG9ydHMpLCB2ZXJib3NlLCB3b3JrZXJzCgoKY2xhc3MgRmxvdyhvYmplY3QpOgogICAg
X19zbG90c19fID0gKCJidWYiLCAiaGRycyIsICJ0b3VjaGVkIikKICAgIGRlZiBfX2luaXRfXyhz
ZWxmKToKICAgICAgICBzZWxmLmJ1ZiA9IGJ5dGVhcnJheSgpCiAgICAgICAgc2VsZi5oZHJzID0g
e30KICAgICAgICBzZWxmLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQoKCiMgLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSByZXNwb25zZSBjb3JyZWxhdGlvbiAt
LS0tClBFTkRJTkdfVFRMID0gNS4wICAgICAgICAjIGZsdXNoIHVubWF0Y2hlZCByZXF1ZXN0cyBh
ZnRlciB0aGlzIG1hbnkgc2Vjb25kcwpQRU5ESU5HX01BWCA9IDgxOTIgICAgICAgIyBoYXJkIGNh
cDsgb3ZlcmZsb3cgZmx1c2hlcyBvbGRlc3QgZmlyc3QKCiMgcGVuZGluZ1soc3JjX2lwLCBzcG9y
dCwgZHN0X2lwLCBkcG9ydCldICAtLSBrZXkgaXMgdGhlIFJFU1BPTlNFIHR1cGxlOgojIHNlcnZl
ci0+Y2xpZW50LiBWYWx1ZTogW2V2ZW50LCByZXFfdHNdLiBBIGxpc3QgcGVyIGtleSBoYW5kbGVz
IEhUVFAKIyBrZWVwLWFsaXZlIHBpcGVsaW5pbmcgKHNldmVyYWwgcmVxdWVzdHMgYmVmb3JlIHJl
c3BvbnNlcyBhcnJpdmUpLgpwZW5kaW5nID0ge30KCgpkZWYgcGVuZGluZ19kZWwocmspOgogICAg
cGVuZGluZy5wb3AocmssIE5vbmUpCgoKZGVmIHBlbmRpbmdfcG9wKHJrLCBvdXQpOgogICAgIiIi
Rmx1c2ggdGhlIG9sZGVzdCBwZW5kaW5nIGV2ZW50IGZvciB0aGlzIHJlc3BvbnNlIHR1cGxlIChG
SU4vUlNUIG9yCiAgICBvdmVyZmxvdyBwYXRoKS4gRW1pdHMgd2hhdGV2ZXIgdGhlIGV2ZW50IGhh
cyDigJQgc3RhdHVzIHN0YXlzIG51bGwuIiIiCiAgICBsc3QgPSBwZW5kaW5nLmdldChyaykKICAg
IGlmIG5vdCBsc3Q6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGV2LCBfID0gbHN0LnBvcCgwKQog
ICAgaWYgbm90IGxzdDoKICAgICAgICBwZW5kaW5nX2RlbChyaykKICAgIG91dC5hcHBlbmQoZXYp
CiAgICByZXR1cm4gZXYKCgpkZWYgcGFyc2VfcmVzcG9uc2VfaGVhZChwYXlsb2FkKToKICAgICIi
IkZpcnN0IGxpbmUgJ0hUVFAvMS54IE5OTiAuLi4nIC0+IChzdGF0dXNfaW50fE5vbmUsIGNvbnRl
bnRfbGVufE5vbmUpLgogICAgT25seSBsb29rcyBhdCB3aGF0J3MgaW4gdGhpcyBzZWdtZW50OyBo
ZWFkZXJzIGZpdCBvbmUgc2VnbWVudCBmb3IgYWxsCiAgICByZWFsaXN0aWMgQVBJIHJlc3BvbnNl
cy4iIiIKICAgIHRyeToKICAgICAgICBoZWFkID0gcGF5bG9hZC5zcGxpdChiIlxyXG5cclxuIiwg
MSlbMF0KICAgICAgICBsaW5lcyA9IGhlYWQucmVwbGFjZShiIlxyXG4iLCBiIlxuIikuc3BsaXQo
YiJcbiIpCiAgICAgICAgZmlyc3QgPSBsaW5lc1swXS5zcGxpdCgpCiAgICAgICAgaWYgbGVuKGZp
cnN0KSA8IDIgb3Igbm90IGZpcnN0WzBdLnN0YXJ0c3dpdGgoYiJIVFRQLyIpOgogICAgICAgICAg
ICByZXR1cm4gTm9uZSwgTm9uZQogICAgICAgIHN0ID0gaW50KGZpcnN0WzFdKQogICAgZXhjZXB0
IChWYWx1ZUVycm9yLCBJbmRleEVycm9yKToKICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAg
Y2xlbiA9IE5vbmUKICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAgICAgICAgbG93ID0gbG4ubG93
ZXIoKQogICAgICAgIGlmIGxvdy5zdGFydHN3aXRoKGIiY29udGVudC1sZW5ndGg6Iik6CiAgICAg
ICAgICAgIHRyeToKICAgICAgICAgICAgICAgIGNsZW4gPSBpbnQobG4uc3BsaXQoYiI6IiwgMSlb
MV0uc3RyaXAoKSkKICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAg
ICBwYXNzCiAgICAgICAgICAgIGJyZWFrCiAgICByZXR1cm4gc3QsIGNsZW4KCgpkZWYgdmFsaWRf
cG9ydChwKToKICAgIHRyeToKICAgICAgICByZXR1cm4gMSA8PSBpbnQocCkgPD0gNjU1MzUKICAg
IGV4Y2VwdCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UKCgpk
ZWYgYmFzaWNfdXNlcih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRlciB2YWx1ZSAt
PiAodXNlcnxOb25lLCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBwYXJ0cyA9IHZh
bHVlLnN0cmlwKCkuc3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0gMjoKICAgICAg
ICByZXR1cm4gTm9uZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAgaWYg
c2NoZW1lID09ICJiYXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQgPSBwYXJ0c1sx
XS5zdHJpcCgpCiAgICAgICAgICAgIGlmIGxlbihwYWQpID4gMTAyNDoKICAgICAgICAgICAgICAg
IHJldHVybiBOb25lLCBOb25lCiAgICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxlbihwYWQpICUg
NCkKICAgICAgICAgICAgcmF3ID0gYmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAgICAgICAgIGlm
IGxlbihyYXcpID4gNTEyOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgICAg
ICAgICAgaWYgYiI6IiBpbiByYXc6CiAgICAgICAgICAgICAgICB1c2VyID0gcmF3LnNwbGl0KGIi
OiIsIDEpWzBdCiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci5kZWNvZGUoInV0Zi04IiwgInJl
cGxhY2UiKVs6NjRdLCAiYmFzaWMiCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAg
ICAgcmV0dXJuIE5vbmUsIE5vbmUKICAgIGVsaWYgc2NoZW1lID09ICJiZWFyZXIiOgogICAgICAg
IHJldHVybiBOb25lLCAiYmVhcmVyIgogICAgcmV0dXJuIE5vbmUsIE5vbmUKCgpkZWYgZmluaXNo
X2V2ZW50KGZsb3csIGtleSwgZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCwgcG9ydHMsIG5v
ZGVfaG9zdCk6CiAgICBoID0gZmxvdy5oZHJzCiAgICB1c2VyID0gc2NoZW1lID0gTm9uZQogICAg
YXV0aHogPSBoLmdldCgiYXV0aG9yaXphdGlvbiIpCiAgICBpZiBhdXRoejoKICAgICAgICB1c2Vy
LCBzY2hlbWUgPSBiYXNpY191c2VyKGF1dGh6KQogICAgIyBXM0MgdHJhY2UgY29udGV4dDogaG9u
b3IgaW5jb21pbmcgdHJhY2VwYXJlbnQsIGVsc2UgZ2VuZXJhdGUgb25lIHNvCiAgICAjIGV2ZXJ5
IHRyYW5zYWN0aW9uIGNhcnJpZXMgYSB0cmFjZV9pZCBmb3IgaHViLXNpZGUgY29ycmVsYXRpb24u
CiAgICAjIE5PVEUgcHkyLjY6IGJ5dGVzIGhhcyBubyAuaGV4KCkg4oCUIHVzZSBiaW5hc2NpaS5o
ZXhsaWZ5LgogICAgdHAgPSBoLmdldCgidHJhY2VwYXJlbnQiKQogICAgdHJhY2VfaWQgPSBOb25l
CiAgICBpZiB0cDoKICAgICAgICBwYXJ0cyA9IHRwLnNwbGl0KCItIikKICAgICAgICBpZiBsZW4o
cGFydHMpID09IDQgYW5kIGxlbihwYXJ0c1sxXSkgPT0gMzI6CiAgICAgICAgICAgIHRyYWNlX2lk
ID0gcGFydHNbMV0ubG93ZXIoKQogICAgaWYgbm90IHRyYWNlX2lkOgogICAgICAgIHRyeToKICAg
ICAgICAgICAgcm5kID0gYmluYXNjaWkuaGV4bGlmeShvcy51cmFuZG9tKDE2KSkKICAgICAgICAg
ICAgcm5kID0gcm5kLmRlY29kZSgiYXNjaWkiKSBpZiBoYXNhdHRyKHJuZCwgImRlY29kZSIpIGVs
c2Ugcm5kCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcm5kID0gKCIlMDMy
eCIgJSAoaW50KHRpbWUudGltZSgpICogMTAwMCkpKVstMzI6XQogICAgICAgIHBpZDggPSBiaW5h
c2NpaS5oZXhsaWZ5KG9zLnVyYW5kb20oOCkpCiAgICAgICAgcGlkOCA9IHBpZDguZGVjb2RlKCJh
c2NpaSIpIGlmIGhhc2F0dHIocGlkOCwgImRlY29kZSIpIGVsc2UgcGlkOAogICAgICAgIHRwID0g
IjAwLSVzLSVzLTAxIiAlIChybmQsIHBpZDgpCiAgICAgICAgdHJhY2VfaWQgPSBybmQKICAgIGV2
ID0gewogICAgICAgICJ0cyI6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAgImhvc3QiOiBub2Rl
X2hvc3QsCiAgICAgICAgInNyYyI6ICJwY2FwIiwKICAgICAgICAic2VydmljZSI6ICJwb3J0OiVk
IiAlIGRwb3J0LAogICAgICAgICJtZXRob2QiOiBoLmdldCgiX21ldGhvZCIpIG9yICItIiwKICAg
ICAgICAicGF0aCI6IChoLmdldCgiX3BhdGgiKSBvciAiLSIpLnNwbGl0KCI/IiwgMSlbMF1bOjEy
MF0sCiAgICAgICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBzY2hlbWUsCiAgICAg
ICAgInBpZCI6IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6ICJwY2FwLWh0dHAiLAogICAg
ICAgICJob3N0X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAgInVzZXJfYWdlbnQiOiBoLmdl
dCgidXNlci1hZ2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9mb3IiOiBoLmdldCgieC1mb3J3
YXJkZWQtZm9yIiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwKICAgICAgICAiY2FsbGVyX3Bv
cnQiOiBzcG9ydCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAogICAgICAgICJkc3RfcG9ydCI6
IGRwb3J0LAogICAgICAgICMgLS0tLSBtb25pdG9yaW5nIHNjaGVtYSAob3BzIEFQSS1sb2cgZm9y
bWF0KSAtLS0tCiAgICAgICAgIyBzdGF0dXMvZHVyYXRpb25fbXMvcmVzcF9ieXRlcyBhcmUgcmVz
cG9uc2Utc2lkZTogcGFzc2l2ZSByZXF1ZXN0LW9ubHkKICAgICAgICAjIGNhcHR1cmUgY2Fubm90
IHNlZSB0aGVtOyBsZWZ0IG51bGwgZm9yIHRoZSBodWIgdG8gZW5yaWNoIG9yIGxlYXZlLgogICAg
ICAgICJ0cmFjZXBhcmVudCI6IHRwWzo4MF0sCiAgICAgICAgInRyYWNlX2lkIjogdHJhY2VfaWQs
CiAgICAgICAgInNlcnZpY2VfaWQiOiBOb25lLCAgICAgICAgICAjIGh1YiBtYXBzIHBvcnQtPnNl
cnZpY2UgdmlhIHBvbGljeSBsYXRlcgogICAgICAgICJtb2R1bGVfaWQiOiAicGNhcC1odHRwIiwK
ICAgIH0KICAgICMgUHJlc2VydmUgcmVzcG9uc2UgY29ycmVsYXRpb24gb25seSBmb3IgbW9uaXRv
cmVkIGRlc3RpbmF0aW9ucy4gVGhlCiAgICAjIHJlc3BvbnNlLXNpZGUgZmlsdGVyIG1heSBzdGls
bCBhZG1pdCBhIGNsaWVudCBlcGhlbWVyYWwgc3BvcnQgZXF1YWwgdG8gYQogICAgIyBtb25pdG9y
ZWQgcG9ydDsgdGhpcyBpcyBoYXJtbGVzcyBiZWNhdXNlIHBhcnNlX3Jlc3BvbnNlX2hlYWQgcmVq
ZWN0cyBpdC4KICAgIHJldHVybiBldiBpZiAoZHBvcnQgaW4gcG9ydHMgb3IgaC5nZXQoIl9tZXRo
b2QiKSkgZWxzZSBOb25lCgoKZGVmIGhhbmRsZV9wYXlsb2FkKGZsb3dzLCBrZXksIHJldl9rZXks
IHBheWxvYWQsIG1ldGEsIHBvcnRzLCBub2RlX2hvc3QsIG91dCwKICAgICAgICAgICAgICAgICAg
IHBlbmRpbmdfdGJsPU5vbmUsIG5vdz1Ob25lKToKICAgICIiIkZlZWQgb25lIGRpcmVjdGlvbidz
IHBheWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0KS4KCiAgICBIRUFERVIt
T05MWSBjYXB0dXJlOiB0aGUgcmVxdWVzdCBldmVudCBpcyBidWlsdCB0aGUgbW9tZW50IFxcclxc
blxcclxcbiBpcwogICAgc2Vlbi4gV2l0aCByZXNwb25zZSBjb3JyZWxhdGlvbiBlbmFibGVkIChw
ZW5kaW5nX3RibCksIHRoZSBmaW5pc2hlZAogICAgZXZlbnQgZ29lcyBpbnRvIHRoZSBwZW5kaW5n
IHRhYmxlIGluc3RlYWQgb2Ygb3V0IOKAlCBpdCBpcyBlbWl0dGVkIHdoZW4KICAgIHRoZSBtYXRj
aGluZyByZXNwb25zZSBoZWFkIGFycml2ZXMsIG9yIG9uIFRUTC90ZWFyZG93biBmYWxsYmFjay4K
ICAgIFJlcXVlc3QgYm9kaWVzIGFyZSBOT1QgYnVmZmVyZWQg4oCUIEJhc2ljIGF1dGggKGFsbCB3
ZSBtaW5lKSByaWRlcyBoZWFkZXJzLAogICAgc28gYm9keSBieXRlcyBjb3N0IG1lbW9yeSBhbmQg
ZGVsYXkgZXZlbnRzIGZvciB6ZXJvIGluZm9ybWF0aW9uLiBBIGxhdGVyCiAgICBzZWdtZW50IG9u
IHRoZSBzYW1lIGNvbm5lY3Rpb24gc2ltcGx5IGZhaWxzIHRoZSByZXF1ZXN0LWxpbmUgY2hlY2sg
YW5kCiAgICBpcyBkaXNjYXJkZWQuIiIiCiAgICBkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0
ID0gbWV0YQogICAgaWYgbm90IHZhbGlkX3BvcnQoZHBvcnQpIG9yIG5vdCB2YWxpZF9wb3J0KHNw
b3J0KToKICAgICAgICByZXR1cm4KICAgIGZsID0gZmxvd3MuZ2V0KGtleSkKICAgIGlmIGZsIGlz
IE5vbmU6CiAgICAgICAgZmwgPSBGbG93KCkKICAgICAgICBmbG93c1trZXldID0gZmwKICAgICAg
ICBpZiBsZW4oZmxvd3MpID4gTUFYX0ZMT1dTOgogICAgICAgICAgICBlbmZvcmNlX2xpbWl0KGZs
b3dzLCB0aW1lLnRpbWUoKSkKICAgIGZsLnRvdWNoZWQgPSB0aW1lLnRpbWUoKQogICAgZmwuYnVm
LmV4dGVuZChieXRlYXJyYXkocGF5bG9hZCkpCgogICAgaWR4ID0gZmwuYnVmLmZpbmQoYiJcclxu
XHJcbiIpCiAgICBpZiBpZHggPCAwOgogICAgICAgIGlmIGxlbihmbC5idWYpID4gTUFYX0hEUlM6
CiAgICAgICAgICAgIGZsb3dzLnBvcChrZXksIE5vbmUpCiAgICAgICAgcmV0dXJuCiAgICBoZWFk
ID0gYnl0ZXMoZmwuYnVmWzppZHhdKQogICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwg
YiJcbiIpLnNwbGl0KGIiXG4iKQogICAgaGRycyA9IHt9CiAgICBmaXJzdCA9IGxpbmVzWzBdLnN0
cmlwKCkuc3BsaXQoKQogICAgaWYgbGVuKGZpcnN0KSA+PSAyIGFuZCBmaXJzdFswXSBpbiBbCiAg
ICAgICAgICAgIG0uZW5jb2RlKCkgZm9yIG0gaW4gTUVUSE9EU106CiAgICAgICAgaGRyc1siX21l
dGhvZCJdID0gZmlyc3RbMF0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAgICBoZHJz
WyJfcGF0aCJdID0gZmlyc3RbMV0uZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikKICAgIGVsc2U6
CiAgICAgICAgZmxvd3MucG9wKGtleSwgTm9uZSkgICAgICAgIyBub3QgYSByZXF1ZXN0IHN0YXJ0
CiAgICAgICAgcmV0dXJuCiAgICBmb3IgbG4gaW4gbGluZXNbMTpdOgogICAgICAgIGlmIGIiOiIg
bm90IGluIGxuOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGtuLCBrdiA9IGxuLnNwbGl0
KGIiOiIsIDEpCiAgICAgICAgaGRyc1trbi5zdHJpcCgpLmxvd2VyKCkuZGVjb2RlKAogICAgICAg
ICAgICAiYXNjaWkiLCAicmVwbGFjZSIpXSA9IGt2LnN0cmlwKCkuZGVjb2RlKAogICAgICAgICAg
ICAgICAgInV0Zi04IiwgInJlcGxhY2UiKVs6MTgwXQogICAgZmwuaGRycyA9IGhkcnMKICAgIGV2
ID0gZmluaXNoX2V2ZW50KGZsLCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsCiAg
ICAgICAgICAgICAgICAgICAgICBwb3J0cywgbm9kZV9ob3N0KQogICAgZGVsIGZsb3dzW2tleV0K
ICAgIGlmIG5vdCBldjoKICAgICAgICByZXR1cm4KICAgIGV2WyJyZXFfYnl0ZXMiXSA9IGlkeCAr
IDQgICAgICAgICAgIyBjYXB0dXJlZCByZXF1ZXN0IGhlYWQgKyB0ZXJtaW5hdG9yCiAgICBpZiBw
ZW5kaW5nX3RibCBpcyBOb25lOgogICAgICAgIG91dC5hcHBlbmQoZXYpICAgICAgICAgICAgICAg
ICAjIGNvcnJlbGF0aW9uIGRpc2FibGVkIChsZWdhY3kgcGF0aCkKICAgICAgICByZXR1cm4KICAg
ICMgcXVldWUgZm9yIHJlc3BvbnNlIGNvcnJlbGF0aW9uOyBrZXkgaXMgdGhlIFJFU1BPTlNFIHR1
cGxlCiAgICByayA9IChkc3RfaXAsIGRwb3J0LCBzcmNfaXAsIHNwb3J0KQogICAgZW50ID0gcGVu
ZGluZ190YmwuZ2V0KHJrKQogICAgaWYgZW50IGlzIE5vbmU6CiAgICAgICAgaWYgbGVuKHBlbmRp
bmdfdGJsKSA+PSBQRU5ESU5HX01BWDoKICAgICAgICAgICAgX2ZsdXNoX29sZGVzdF9wZW5kaW5n
KHBlbmRpbmdfdGJsLCBvdXQpCiAgICAgICAgZW50ID0gcGVuZGluZ190YmxbcmtdID0gW10KICAg
IGVudC5hcHBlbmQoW2V2LCBub3cgaWYgbm93IGlzIG5vdCBOb25lIGVsc2UgdGltZS50aW1lKCld
KQoKCmRlZiBzd2VlcF9pZGxlKGZsb3dzLCBub3cpOgogICAgc3RhbGUgPSBbXQogICAgZm9yIGss
IGZsIGluIGZsb3dzLml0ZW1zKCk6CiAgICAgICAgaWYgbm93IC0gZmwudG91Y2hlZCA+IEZMT1df
VFRMOgogICAgICAgICAgICBzdGFsZS5hcHBlbmQoaykKICAgIGZvciBrIGluIHN0YWxlOgogICAg
ICAgIGRlbCBmbG93c1trXQoKCmRlZiBfZmx1c2hfb2xkZXN0X3BlbmRpbmcocGVuZGluZ190Ymws
IG91dCk6CiAgICAiIiJPdmVyZmxvdyBndWFyZDogZW1pdCB0aGUgc2luZ2xlIG9sZGVzdCBwZW5k
aW5nIGV2ZW50IGFzLWlzLiIiIgogICAgb2xkZXN0X2tleSwgb2xkZXN0X3RzID0gTm9uZSwgTm9u
ZQogICAgZm9yIHJrLCBsc3QgaW4gcGVuZGluZ190YmwuaXRlbXMoKToKICAgICAgICB0cyA9IGxz
dFswXVsxXQogICAgICAgIGlmIG9sZGVzdF90cyBpcyBOb25lIG9yIHRzIDwgb2xkZXN0X3RzOgog
ICAgICAgICAgICBvbGRlc3Rfa2V5LCBvbGRlc3RfdHMgPSByaywgdHMKICAgIGlmIG9sZGVzdF9r
ZXkgaXMgbm90IE5vbmU6CiAgICAgICAgcGVuZGluZ19wb3Aob2xkZXN0X2tleSwgb3V0KQoKCmRl
ZiBzd2VlcF9wZW5kaW5nKHBlbmRpbmdfdGJsLCBub3csIG91dCk6CiAgICAiIiJUVEwgZmx1c2g6
IGVtaXQgcmVxdWVzdHMgd2hvc2UgcmVzcG9uc2VzIG5ldmVyIHNob3dlZCB1cC4iIiIKICAgIHN0
YWxlID0gW10KICAgIGZvciByaywgbHN0IGluIHBlbmRpbmdfdGJsLml0ZW1zKCk6CiAgICAgICAg
aWYgbm93IC0gbHN0WzBdWzFdID4gUEVORElOR19UVEw6CiAgICAgICAgICAgIHN0YWxlLmFwcGVu
ZChyaykKICAgIGZvciByayBpbiBzdGFsZToKICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0KQoK
CmRlZiBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFibGUgc2l6
ZSAocHkyLjY6IG5vIE9yZGVyZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZPCiAgICBi
eSBpbnNlcnRpb24gb3JkZXIsIHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQeXRob24p
LiIiIgogICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dzKSA+IE1B
WF9GTE9XUzoKICAgICAgICBmbG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3QtaW5zZXJ0
ZWQga2V5IG9uIENQeXRob24gMi42LzIuNwoKCmRlZiBfY29udHJvbF9jb25maWcoKToKICAgICIi
IlJlYWQgb3B0aW9uYWwgY29udHJvbCBzZXR0aW5ncyB3aXRob3V0IGV4cG9zaW5nIHRoZSBiZWFy
ZXIgdG9rZW4uIiIiCiAgICBlbmRwb2ludCA9IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX0VO
RFBPSU5UIikgb3Igb3MuZW52aXJvbi5nZXQoIk5UX0VORFBPSU5UIikKICAgIHRva2VuX2ZpbGUg
PSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9UT0tFTl9GSUxFIiwgIiIpCiAgICB0b2tlbiA9
IG9zLmVudmlyb24uZ2V0KCJOVF9DT05UUk9MX1RPS0VOIiwgIiIpCiAgICBpZiB0b2tlbl9maWxl
OgogICAgICAgIHRyeToKICAgICAgICAgICAgZiA9IG9wZW4odG9rZW5fZmlsZSwgInIiKQogICAg
ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB0b2tlbiA9IGYucmVhZCgpLnN0cmlwKCkKICAg
ICAgICAgICAgZmluYWxseToKICAgICAgICAgICAgICAgIGYuY2xvc2UoKQogICAgICAgIGV4Y2Vw
dCBJT0Vycm9yOgogICAgICAgICAgICB0b2tlbiA9ICIiCiAgICBub2RlID0gb3MuZW52aXJvbi5n
ZXQoIk5UX05PREVfTkFNRSIpIG9yIHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0K
ICAgIHJ1bl9kaXIgPSBvcy5lbnZpcm9uLmdldCgiTlRfQ09OVFJPTF9SVU4iLCAiL3Zhci9saWIv
bmV0d29ya3RyYWNpbmciKQogICAgdHJ5OgogICAgICAgIGludGVydmFsID0gbWF4KDUsIG1pbihp
bnQob3MuZW52aXJvbi5nZXQoIk5UX0NPTlRST0xfU0VDIiwgIjMwIikpLCAzMDApKQogICAgZXhj
ZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgaW50ZXJ2YWwgPSAzMAogICAgcmV0dXJuIGVuZHBvaW50
LCB0b2tlbiwgbm9kZSwgcnVuX2RpciwgaW50ZXJ2YWwKCgpkZWYgX3J1bl9jb250cm9sX3RpY2so
cG9ydHMsIGlmYWNlLCBydW5fZGlyLCBjbGllbnQpOgogICAgcmVwbHkgPSBjbGllbnQucG9sbCgp
CiAgICBpZiBub3QgcmVwbHk6CiAgICAgICAgcmV0dXJuIHBvcnRzLCBpZmFjZSwgRmFsc2UsICJw
b2xsIGZhaWxlZCIKICAgIGRlc2lyZWQgPSByZXBseS5nZXQoImRlc2lyZWQiKSBvciB7fQogICAg
Z2VuZXJhdGlvbiA9IGRlc2lyZWQuZ2V0KCJnZW5lcmF0aW9uIiwgMCkKICAgIHJlc3RhcnRfcmVx
dWVzdGVkID0gRmFsc2UKICAgIGlmIGRlc2lyZWQuZ2V0KCJwb3J0cyIpOgogICAgICAgIG5ld19w
b3J0cyA9IHNldChkZXNpcmVkWyJwb3J0cyJdKQogICAgICAgIGlmIG5ld19wb3J0cyAhPSBwb3J0
czoKICAgICAgICAgICAgcG9ydHMgPSBuZXdfcG9ydHMKICAgIGlmIGRlc2lyZWQuZ2V0KCJpZmFj
ZSIpOgogICAgICAgIGlmYWNlID0gZGVzaXJlZFsiaWZhY2UiXQogICAgbnRfY29udHJvbC53cml0
ZV9zdGF0ZShvcy5wYXRoLmpvaW4ocnVuX2RpciwgInJlbW90ZS1kZXNpcmVkLmpzb24iKSwgZGVz
aXJlZCwgInJlc3RhcnQgcmVxdWlyZWQiKQogICAgZm9yIHRhc2sgaW4gcmVwbHkuZ2V0KCJ0YXNr
cyIsIFtdKToKICAgICAgICBhY3Rpb24gPSB0YXNrLmdldCgiYWN0aW9uIikKICAgICAgICBpZiBh
Y3Rpb24gPT0gImhlYWx0aCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAiaGVhbHRoeSIKICAgICAg
ICAgICAgc3RhdHVzID0gImRvbmUiCiAgICAgICAgZWxpZiBhY3Rpb24gaW4gKCJyZXN0YXJ0Iiwg
InJlbG9hZCIsICJzZXRfcG9ydHMiKToKICAgICAgICAgICAgbWVzc2FnZSA9ICJhY2NlcHRlZDsg
Y2FwdHVyZSByZXN0YXJ0IHJlcXVlc3RlZCIKICAgICAgICAgICAgc3RhdHVzID0gImRvbmUiCiAg
ICAgICAgICAgIHJlc3RhcnRfcmVxdWVzdGVkID0gVHJ1ZQogICAgICAgICAgICBpZiBhY3Rpb24g
PT0gInNldF9wb3J0cyI6CiAgICAgICAgICAgICAgICBhcmdzID0gdGFzay5nZXQoImFyZ3MiKSBv
ciB7fQogICAgICAgICAgICAgICAgaWYgYXJncy5nZXQoInBvcnRzIik6CiAgICAgICAgICAgICAg
ICAgICAgcG9ydHMgPSBzZXQoYXJnc1sicG9ydHMiXSkKICAgICAgICAgICAgICAgICAgICBudF9j
b250cm9sLndyaXRlX3N0YXRlKG9zLnBhdGguam9pbihydW5fZGlyLCAicmVtb3RlLWRlc2lyZWQu
anNvbiIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeyJwb3J0
cyI6IHNvcnRlZChwb3J0cyksICJtb2RlIjogInB5dGhvbiIsCiAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgImdlbmVyYXRpb24iOiBnZW5lcmF0aW9ufSwgbWVzc2Fn
ZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAic3RvcCI6CiAgICAgICAgICAgIG1lc3NhZ2UgPSAi
c3RvcCByZXF1ZXN0ZWQiCiAgICAgICAgICAgIHN0YXR1cyA9ICJkb25lIgogICAgICAgICAgICBy
ZXN0YXJ0X3JlcXVlc3RlZCA9IEZhbHNlCiAgICAgICAgZWxzZToKICAgICAgICAgICAgbWVzc2Fn
ZSA9ICJ1bnN1cHBvcnRlZCBieSBkaXJlY3Qgc25pZmZlciIKICAgICAgICAgICAgc3RhdHVzID0g
ImZhaWxlZCIKICAgICAgICBjbGllbnQucmVwb3J0KHRhc2suZ2V0KCJpZCIpLCBzdGF0dXMsIG1l
c3NhZ2UpCiAgICBjbGllbnQuaGVhcnRiZWF0KGdlbmVyYXRpb24sICJyZXN0YXJ0IHJlcXVpcmVk
IiBpZiByZXN0YXJ0X3JlcXVlc3RlZCBlbHNlICJwb2xsIG9rIikKICAgIHJldHVybiBwb3J0cywg
aWZhY2UsIHJlc3RhcnRfcmVxdWVzdGVkLCAicG9sbCBvayIKCgpkZWYgbWFpbigpOgogICAgaWZh
Y2UsIHBvcnRzLCB2ZXJib3NlLCB3b3JrZXJzID0gcGFyc2VfYXJncyhzeXMuYXJndlsxOl0pCiAg
ICBub2RlX2hvc3QgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxpdCgiLiIpWzBdCiAgICBjb250
cm9sX2NsaWVudCA9IE5vbmUKICAgIGVuZHBvaW50LCB0b2tlbiwgY29udHJvbF9ub2RlLCBjb250
cm9sX3J1biwgY29udHJvbF9pbnRlcnZhbCA9IF9jb250cm9sX2NvbmZpZygpCiAgICBpZiBudF9j
b250cm9sIGlzIG5vdCBOb25lIGFuZCBlbmRwb2ludCBhbmQgdG9rZW46CiAgICAgICAgdHJ5Ogog
ICAgICAgICAgICBjb250cm9sX2NsaWVudCA9IG50X2NvbnRyb2wuQ29udHJvbENsaWVudChlbmRw
b2ludCwgdG9rZW4sIGNvbnRyb2xfbm9kZSkKICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNk
aXIoY29udHJvbF9ydW4pOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoY29udHJvbF9ydW4p
CiAgICAgICAgICAgIGxvZygicmVtb3RlIGNvbnRyb2wgZW5hYmxlZCIpCiAgICAgICAgZXhjZXB0
IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBsb2coIldBUk46IHJlbW90ZSBjb250cm9sIGRp
c2FibGVkICglcykiICUgbnRfY29udHJvbC5zYWZlX21lc3NhZ2UoZSkpCgogICAgdHJ5OgogICAg
ICAgICMgcHJvdG9jb2wgTVVTVCBiZSBodG9ucyhFVEhfUF9BTEwpIHRvIHJlY2VpdmUgYm90aCBJ
TkdSRVNTIChyZXEpIGFuZAogICAgICAgICMgRUdSRVNTIChyZXNwKSBwYWNrZXRzIG9uIExpbnV4
IGtlcm5lbCBwYWNrZXQgc29ja2V0cy4KICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQu
QUZfUEFDS0VULCBzb2NrZXQuU09DS19SQVcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgc29j
a2V0Lmh0b25zKEVUSF9QX0FMTCkpCiAgICBleGNlcHQgQXR0cmlidXRlRXJyb3I6CiAgICAgICAg
cmFpc2UgU3lzdGVtRXhpdCgiQUZfUEFDS0VUIHVuYXZhaWxhYmxlIG9uIHRoaXMgcGxhdGZvcm0i
KQogICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQo
ImNhbm5vdCBvcGVuIEFGX1BBQ0tFVCBzb2NrZXQgKCVzKSDigJQgbmVlZCAiCiAgICAgICAgICAg
ICAgICAgICAgICAgICAiQ0FQX05FVF9SQVcgLyByb290IiAlIGUpCiAgICBzLnNldHRpbWVvdXQo
MS4wKQogICAgYXBwbHlfcGVyZl9vcHRzKHMsIHBvcnRzKQogICAgdHJ5OgogICAgICAgIHMuYmlu
ZCgoaWZhY2Ugb3IgIiIsIEVUSF9QX0FMTCkpCiAgICBleGNlcHQgc29ja2V0LmVycm9yOgogICAg
ICAgIHRyeToKICAgICAgICAgICAgcy5iaW5kKCgiIiwgRVRIX1BfQUxMKSkKICAgICAgICBleGNl
cHQgc29ja2V0LmVycm9yOgogICAgICAgICAgICBwYXNzCiAgICBmYW5vdXRfb2sgPSBGYWxzZQog
ICAgaWYgd29ya2VycyA+IDE6CiAgICAgICAgZmFub3V0X29rID0gYXBwbHlfZmFub3V0KHMsIDB4
RjAwRCkKICAgICAgICBpZiBmYW5vdXRfb2s6CiAgICAgICAgICAgIGxvZygiZmFub3V0IGdyb3Vw
IDB4RjAwRDogc3Bhd25pbmcgJWQgd29ya2VycyIgJSB3b3JrZXJzKQoKICAgICMgcHJlY29tcGls
ZWQgc3RydWN0IHJlYWRlcnMg4oCUIHVucGFja19mcm9tIHJlYWRzIHN0cmFpZ2h0IG91dCBvZiB0
aGUKICAgICMgcGFja2V0IGJ1ZmZlciAobm8gc2xpY2UgY29waWVzKSBhbmQgeWllbGRzIGludHMg
dW5kZXIgcHkyIEFORCBweTMKICAgIHUxNiA9IHN0cnVjdC5TdHJ1Y3QoIiFIIikudW5wYWNrX2Zy
b20KICAgIHVoID0gc3RydWN0LlN0cnVjdCgiIUhIIikudW5wYWNrX2Zyb20gICAjIHNwb3J0LGRw
b3J0IGluIG9uZSByZWFkCiAgICB1YiA9IHN0cnVjdC5TdHJ1Y3QoIiFCQiIpLnVucGFja19mcm9t
CiAgICBudG9hID0gc29ja2V0LmluZXRfbnRvYQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5pbmcg
PSBbVHJ1ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBd
ID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWdu
YWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGlt
ZSgpCiAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKQogICAgbG9nKCJsaXN0ZW5pbmcgb24g
JXMgcG9ydHM9JXMgcGlkPSVkIiAlCiAgICAgICAgKGlmYWNlIG9yICI8YWxsPiIsIHNvcnRlZChw
b3J0cyksIG9zLmdldHBpZCgpKSkKCiAgICAjIGZvcmsgZXh0cmEgY2FwdHVyZSB3b3JrZXJzIEFG
VEVSIGZhbm91dCBhdHRhY2g7IFdJVEhPVVQgYSB3b3JraW5nCiAgICAjIGZhbm91dCBncm91cCBl
dmVyeSBwcm9jZXNzIHdvdWxkIHJlY2VpdmUgRVZFUlkgcGFja2V0IChkdXBsaWNhdGVzKSwKICAg
ICMgc28gc2luZ2xlLXByb2Nlc3MgbW9kZSBpcyBmb3JjZWQgd2hlbiB0aGUga2VybmVsIGxhY2tz
IHN1cHBvcnQKICAgICMgKFBBQ0tFVF9GQU5PVVQgbmVlZHMga2VybmVsID49IDMuMTsgZWw2IDIu
Ni4zMiBkb2VzIG5vdCBoYXZlIGl0KQogICAgaWYgZmFub3V0X29rOgogICAgICAgIGZvciBfIGlu
IHJhbmdlKHdvcmtlcnMgLSAxKToKICAgICAgICAgICAgaWYgb3MuZm9yaygpID09IDA6CiAgICAg
ICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAgIyBjaGlsZDogZmFsbCB0aHJvdWdoIGlu
dG8gaXRzIG93biBsb29wCgogICAgIyAxcyByZWN2IHRpbWVvdXQ6IChhKSBsZXRzIHRoZSBwZW5k
aW5nL2Zsb3cgc3dlZXBzIGFjdHVhbGx5IGZpcmUg4oCUCiAgICAjIHdpdGhvdXQgaXQgYGV4Y2Vw
dCBzb2NrZXQudGltZW91dGAgbmV2ZXIgcnVuczsgKGIpIGVtcGlyaWNhbGx5IFJFUVVJUkVECiAg
ICAjIHdpdGggdGhlIEJQRiBmaWx0ZXIgYXR0YWNoZWQ6IGEgZnVsbHktYmxvY2tpbmcgcmVjdiBv
biB0aGlzIGtlcm5lbAogICAgIyBzdGFydmVzIGFmdGVyIHRoZSBmaXJzdCBwYWNrZXQsIHdoaWxl
IHRoZSB0aW1lb3V0J2QgcmVjdiBkZWxpdmVycwogICAgIyBjb250aW51b3VzbHkgKHZlcmlmaWVk
IGJ5IEEvQjogcng9MSB2cyByeD0yOSBpZGVudGljYWwgb3RoZXJ3aXNlKS4KICAgIHMuc2V0dGlt
ZW91dCgxLjApCgogICAgZGJnID0gb3MuZW52aXJvbi5nZXQoIk5UX1NOSUZGX0RFQlVHIikgPT0g
IjEiCiAgICBkYmdfcnggPSAwCiAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICB3aGlsZSBy
dW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAgcGt0ID0gcy5yZWN2KDY1NTM1KQog
ICAgICAgICAgICBkYmdfcnggKz0gMQogICAgICAgICAgICBpZiBkYmcgYW5kIHRpbWUudGltZSgp
IC0gZGJnX2xhc3QgPiA1OgogICAgICAgICAgICAgICAgbG9nKCJERUJVRyByeD0lZCIgJSBkYmdf
cngpCiAgICAgICAgICAgICAgICBkYmdfbGFzdCA9IHRpbWUudGltZSgpCiAgICAgICAgZXhjZXB0
IHNvY2tldC50aW1lb3V0OgogICAgICAgICAgICBpZiBjb250cm9sX2NsaWVudCBpcyBub3QgTm9u
ZSBhbmQgdGltZS50aW1lKCkgPj0gY29udHJvbF9uZXh0OgogICAgICAgICAgICAgICAgdHJ5Ogog
ICAgICAgICAgICAgICAgICAgIHBvcnRzLCBpZmFjZSwgcmVzdGFydF9yZXF1ZXN0ZWQsIGNvbnRy
b2xfc3RhdHVzID0gX3J1bl9jb250cm9sX3RpY2soCiAgICAgICAgICAgICAgICAgICAgICAgIHBv
cnRzLCBpZmFjZSwgY29udHJvbF9ydW4sIGNvbnRyb2xfY2xpZW50KQogICAgICAgICAgICAgICAg
ICAgIGxvZygicmVtb3RlIGNvbnRyb2w6ICVzIiAlIGNvbnRyb2xfc3RhdHVzKQogICAgICAgICAg
ICAgICAgICAgIGlmIHJlc3RhcnRfcmVxdWVzdGVkOgogICAgICAgICAgICAgICAgICAgICAgICBs
b2coInJlbW90ZSBjb250cm9sOiByZXN0YXJ0IHJlcXVpcmVkOyBleGl0aW5nIGZvciBTeXNWIHdy
YXBwZXIiKQogICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgICAg
ICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgICAgICBsb2co
IldBUk46IHJlbW90ZSBjb250cm9sIHRpY2sgZmFpbGVkICglcykiICUgbnRfY29udHJvbC5zYWZl
X21lc3NhZ2UoZSkpCiAgICAgICAgICAgICAgICBjb250cm9sX25leHQgPSB0aW1lLnRpbWUoKSAr
IGNvbnRyb2xfaW50ZXJ2YWwKICAgICAgICAgICAgaWYgZGJnOgogICAgICAgICAgICAgICAgbG9n
KCJERUJVRyB0aW1lb3V0IHJ4PSVkIiAlIGRiZ19yeCkKICAgICAgICAgICAgICAgIGRiZ19sYXN0
ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgbm93ID0gdGltZS50aW1lKCkKICAgICAgICAgICAg
aWYgbm93IC0gbGFzdF9zd2VlcCA+IDMwOgogICAgICAgICAgICAgICAgc3dlZXBfaWRsZShmbG93
cywgbm93KQogICAgICAgICAgICAgICAgb3V0X3MgPSBbXQogICAgICAgICAgICAgICAgc3dlZXBf
cGVuZGluZyhwZW5kaW5nLCBub3csIG91dF9zKQogICAgICAgICAgICAgICAgZm9yIGV2IGluIG91
dF9zOgogICAgICAgICAgICAgICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1wcyhldikg
KyAiXG4iKQogICAgICAgICAgICAgICAgaWYgb3V0X3M6CiAgICAgICAgICAgICAgICAgICAgc3lz
LnN0ZG91dC5mbHVzaCgpCiAgICAgICAgICAgICAgICBsYXN0X3N3ZWVwID0gbm93CiAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAgICAg
ICBpZiBlLmVycm5vID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAgY29udGludWUKICAg
ICAgICAgICAgcmFpc2UKICAgICAgICBuID0gbGVuKHBrdCkKICAgICAgICBpZiBuIDwgMzQ6CiAg
ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgb3V0ID0gW10KICAgICAgICBvZmYgPSAxNCAgICAg
ICAgICAgICAgICAgICAgICAjIGV0aGVybmV0IGhlYWRlcgogICAgICAgIGV0eXBlID0gdTE2KHBr
dCwgMTIpWzBdCiAgICAgICAgaWYgZXR5cGUgPT0gRVRIX1BfVkxBTjoKICAgICAgICAgICAgZXR5
cGUgPSB1MTYocGt0LCAxNilbMF0KICAgICAgICAgICAgb2ZmID0gMTgKICAgICAgICBlbGlmIGV0
eXBlICE9IEVUSF9QX0lQOgogICAgICAgICAgICBjb250aW51ZSAgICAgICAgICAgICAgICAgICMg
d2l0aCBCUEYgYXR0YWNoZWQgdGhpcyBpcyByYXJlCiAgICAgICAgaXAwID0gdWIocGt0LCBvZmYp
WzBdCiAgICAgICAgaWYgaXAwID4+IDQgIT0gNCBvciB1Yihwa3QsIG9mZiArIDkpWzBdICE9IDY6
ICAgIyBJUHY0IFRDUCBvbmx5CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWhsID0gKGlw
MCAmIDB4MEYpICogNAogICAgICAgIGZyYWcgPSB1MTYocGt0LCBvZmYgKyA2KVswXQogICAgICAg
IGlmIGZyYWcgJiAweDFGRkY6ICAgICAgICAgICAgICAgICAgICAgICAgICMgbm9uLWZpcnN0IGZy
YWdtZW50CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgc3JjX2lwID0gbnRvYShwa3Rbb2Zm
ICsgMTI6b2ZmICsgMTZdKQogICAgICAgIGRzdF9pcCA9IG50b2EocGt0W29mZiArIDE2Om9mZiAr
IDIwXSkKICAgICAgICB0Y3Bfb2ZmID0gb2ZmICsgaWhsCiAgICAgICAgc3BvcnQsIGRwb3J0ID0g
dWgocGt0LCB0Y3Bfb2ZmKQogICAgICAgIGRvZmZfZmxhZ3MgPSB1Yihwa3QsIHRjcF9vZmYgKyAx
MikKICAgICAgICBkb2ZmID0gKGRvZmZfZmxhZ3NbMF0gPj4gNCkgKiA0CiAgICAgICAgcGF5X3N0
YXJ0ID0gdGNwX29mZiArIGRvZmYKICAgICAgICBpZiBuIDw9IHBheV9zdGFydDoKICAgICAgICAg
ICAgY29udGludWUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIG5vIHBheWxvYWQgaW4g
c2VnbWVudAogICAgICAgIHBheWxvYWQgPSBwa3RbcGF5X3N0YXJ0Ol0KICAgICAgICBmbGFncyA9
IGRvZmZfZmxhZ3NbMV0KICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQoKICAgICAgICAjIC0tLS0t
LS0tLS0tLS0tLS0gUkVTUE9OU0UgZGlyZWN0aW9uIChzZXJ2ZXIgLT4gY2xpZW50KSAtLS0tLS0t
LS0tCiAgICAgICAgaWYgc3BvcnQgaW4gcG9ydHMgYW5kIGRwb3J0IG5vdCBpbiBwb3J0czoKICAg
ICAgICAgICAgIyBwZW5kaW5nIGtleSB3YXMgc3RvcmVkIGFzIChzZXJ2ZXJfaXAsIHNlcnZlcl9w
b3J0LCBjbGllbnRfaXAsCiAgICAgICAgICAgICMgY2xpZW50X3BvcnQpID09IChzcmMsIHNwb3J0
LCBkc3QsIGRwb3J0KSBPRiBUSElTIHJlc3BvbnNlIHBrdAogICAgICAgICAgICByayA9IChzcmNf
aXAsIHNwb3J0LCBkc3RfaXAsIGRwb3J0KQogICAgICAgICAgICBpZiBwYXlsb2FkWzo1XSA9PSBi
IkhUVFAvIjoKICAgICAgICAgICAgICAgIHN0LCBjbGVuID0gcGFyc2VfcmVzcG9uc2VfaGVhZChw
YXlsb2FkKQogICAgICAgICAgICAgICAgZW50ID0gcGVuZGluZy5nZXQocmspCiAgICAgICAgICAg
ICAgICBpZiBlbnQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgZXYgPSBlbnRbMF1b
MF0KICAgICAgICAgICAgICAgICAgICBldlsic3RhdHVzIl0gPSBzdAogICAgICAgICAgICAgICAg
ICAgIGV2WyJkdXJhdGlvbl9tcyJdID0gaW50KChub3cgLSBlbnRbMF1bMV0pICogMTAwMCkKICAg
ICAgICAgICAgICAgICAgICBpZiBjbGVuIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAg
ICAgICBldlsicmVzcF9ieXRlcyJdID0gY2xlbgogICAgICAgICAgICAgICAgICAgIHBlbmRpbmdf
ZGVsKHJrKQogICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAgICAgICAgIGVs
aWYgZmxhZ3MgJiAweDA1OiAgICAgICAgICAgICAgICAgICAgICAjIEZJTnxSU1Q6IGZsdXNoIHVu
bWF0Y2hlZAogICAgICAgICAgICAgICAgZXYgPSBwZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAg
ICMgLS0tLS0tLS0tLS0tLS0tLSBSRVFVRVNUIGRpcmVjdGlvbiAoY2xpZW50IC0+IHNlcnZlcikg
LS0tLS0tLS0tLS0KICAgICAgICBlbGlmIGRwb3J0IGluIHBvcnRzOgogICAgICAgICAgICBpZiBm
bGFncyAmIDB4MDU6ICAgICAgICAgICAgICAgICAgICAgICMgdGVhcmRvd24gdy9vIHJlc3BvbnNl
IHNlZW4KICAgICAgICAgICAgICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQp
CiAgICAgICAgICAgICAgICBwZW5kaW5nX3BvcChyaywgb3V0KQogICAgICAgICAgICBrZXkgPSAo
c3JjX2lwLCBzcG9ydCwgZHN0X2lwLCBkcG9ydCkKICAgICAgICAgICAgaGFuZGxlX3BheWxvYWQo
Zmxvd3MsIGtleSwgTm9uZSwgcGF5bG9hZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKGRz
dF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICBw
b3J0cywgbm9kZV9ob3N0LCBvdXQsIHBlbmRpbmcsIG5vdykKICAgICAgICBpZiBvdXQ6CiAgICAg
ICAgICAgIHcgPSBzeXMuc3Rkb3V0LndyaXRlCiAgICAgICAgICAgIGZvciBldiBpbiBvdXQ6CiAg
ICAgICAgICAgICAgICB3KGpzb24uZHVtcHMoZXYpICsgIlxuIikKICAgICAgICAgICAgc3lzLnN0
ZG91dC5mbHVzaCgpCgogICAgICAgIGlmIG5vdyAtIGxhc3Rfc3dlZXAgPiA1LjA6CiAgICAgICAg
ICAgIHN3ZWVwX2lkbGUoZmxvd3MsIG5vdykKICAgICAgICAgICAgb3V0X3MgPSBbXQogICAgICAg
ICAgICBzd2VlcF9wZW5kaW5nKHBlbmRpbmcsIG5vdywgb3V0X3MpCiAgICAgICAgICAgIGZvciBl
diBpbiBvdXRfczoKICAgICAgICAgICAgICAgIHN5cy5zdGRvdXQud3JpdGUoanNvbi5kdW1wcyhl
dikgKyAiXG4iKQogICAgICAgICAgICBpZiBvdXRfczoKICAgICAgICAgICAgICAgIHN5cy5zdGRv
dXQuZmx1c2goKQogICAgICAgICAgICBsYXN0X3N3ZWVwID0gbm93CgogICAgbG9nKCJzdG9wcGVk
IikKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg==
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
eHNpemU9MTI4KQogICAgc3Bvb2xfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkKICAgIG50aHJlYWRz
ID0gaW50KG9zLmVudmlyb24uZ2V0KCJOVF9TSElQX1RIUkVBRFMiLCAiNCIpKQoKICAgIGRlZiBw
b3N0ZXIoKToKICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBiYXRjaCA9IHEuZ2V0KCkK
ICAgICAgICAgICAgaWYgYmF0Y2ggaXMgTm9uZToKICAgICAgICAgICAgICAgIHEudGFza19kb25l
KCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBub3QgZmx1c2goYmF0Y2gp
OgogICAgICAgICAgICAgICAgbG9nKCJXQVJOOiBIdWIgdW5yZWFjaGFibGUsIGRyb3BwZWQgJWQg
ZXZlbnRzIChpbi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTykiICUgbGVuKGJhdGNoKSkKICAgICAg
ICAgICAgcS50YXNrX2RvbmUoKQoKICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAgICAg
ICB0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgIHQuZGFlbW9uID0g
VHJ1ZQogICAgICAgIHQuc3RhcnQoKQoKICAgIGJ1ZiA9IFtdCiAgICBsYXN0X2ZsdXNoID0gdGlt
ZS50aW1lKCkKCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAgIHRyeToKICAgICAgICAgICAg
ciwgXywgXyA9IHNlbGVjdC5zZWxlY3QoW3N5cy5zdGRpbl0sIFtdLCBbXSwgMS4wKQogICAgICAg
IGV4Y2VwdCBzZWxlY3QuZXJyb3IgYXMgZToKICAgICAgICAgICAgaWYgZVswXSA9PSBlcnJuby5F
SU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGJyZWFrCgogICAgICAg
IGlmIHI6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHJhdyA9IHN5cy5zdGRpbi5y
ZWFkbGluZSgpCiAgICAgICAgICAgIGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJvcikgYXMgZToKICAg
ICAgICAgICAgICAgIGlmIGdldGF0dHIoZSwgJ2Vycm5vJywgTm9uZSkgPT0gZXJybm8uRUlOVFI6
CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAg
ICAgICAgIGlmIG5vdCByYXc6CiAgICAgICAgICAgICAgICBicmVhayAgICAgICAgICAgICAgICAg
ICMgRU9GCiAgICAgICAgICAgIHJhdyA9IHJhdy5zdHJpcCgpCiAgICAgICAgICAgIGlmIHJhdzoK
ICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBldiA9IGpzb24ubG9hZHMo
cmF3KQogICAgICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2UoZXYsIGRpY3QpOgogICAgICAg
ICAgICAgICAgICAgICAgICBpZiBsZW4oYnVmKSA+PSA0MDAwOgogICAgICAgICAgICAgICAgICAg
ICAgICAgICAgZGVsIGJ1ZlswXQogICAgICAgICAgICAgICAgICAgICAgICBidWYuYXBwZW5kKGV2
KQogICAgICAgICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAg
cGFzcwoKICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIHdoaWxlIGxlbihidWYpID49
IE1BWF9CQVRDSCBvciAoYnVmIGFuZCBub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyk6CiAg
ICAgICAgICAgIGxhc3RfZmx1c2ggPSBub3cKICAgICAgICAgICAgcS5wdXQoYnVmWzpNQVhfQkFU
Q0hdKQogICAgICAgICAgICBkZWwgYnVmWzpNQVhfQkFUQ0hdCgogICAgIyBzdGRpbiBjbG9zZWQg
KHNuaWZmZXIgc3RvcHBlZCkg4oCUIGRyYWluIGluLW1lbW9yeSBxdWV1ZQogICAgcS5qb2luKCkK
ICAgIGxvZygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRpbmcgb24gZXhpdCkiICUgbGVuKGJ1Zikp
CgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQo=
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
IHNpemVfdCBNQVhfSEVBREVSID0gMjYyMTQ0OwpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9CQVRD
SCA9IDQwMDsKc3RhdGljIGNvbnN0IHNpemVfdCBNQVhfUVVFVUUgPSA0MDAwOwpzdGF0aWMgY29u
c3QgaW50IEZMVVNIX1NFQyA9IDU7CnN0YXRpYyBjb25zdCBpbnQgUkVUUllfU0VDID0gNjA7CnN0
YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RUTCA9IDE1OwpzdGF0aWMgY29uc3QgdW5zaWduZWQg
UEVORElOR19UVEwgPSAzOwpzdGF0aWMgY29uc3QgdW5zaWduZWQgQUNDRVBUID0gMjA0ODsKc3Rh
dGljIGNvbnN0IGludCBTT19BVFRBQ0hfRklMVEVSX09MRCA9IDI2OwpzdGF0aWMgY29uc3QgdW5z
aWduZWQgc2hvcnQgRVRIX1BfSVBfSE9TVCA9IDB4MDgwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVk
IHNob3J0IEVUSF9QXzgwMjFRX0hPU1QgPSAweDgxMDA7CgpzdGF0aWMgc3RkOjpzdHJpbmcgdHJp
bShjb25zdCBzdGQ6OnN0cmluZyAmcykgewogIHNpemVfdCBhID0gMCwgYiA9IHMuc2l6ZSgpOwog
IHdoaWxlIChhIDwgYiAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKXNbYV0pKSArK2E7CiAgd2hp
bGUgKGIgPiBhICYmIGlzc3BhY2UoKHVuc2lnbmVkIGNoYXIpc1tiIC0gMV0pKSAtLWI7CiAgcmV0
dXJuIHMuc3Vic3RyKGEsIGIgLSBhKTsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgbG93ZXIoY29uc3Qg
c3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0cmluZyB4ID0gczsKICBzaXplX3QgaTsgZm9yIChp
ID0gMDsgaSA8IHguc2l6ZSgpOyArK2kpIHhbaV0gPSAoY2hhcil0b2xvd2VyKCh1bnNpZ25lZCBj
aGFyKXhbaV0pOwogIHJldHVybiB4Owp9CnN0YXRpYyBzdGQ6OnN0cmluZyBqc29ucShjb25zdCBz
dGQ6OnN0cmluZyAmcykgewogIHN0ZDo6c3RyaW5nIHggPSAiXCIiOyBzaXplX3QgaTsKICBmb3Ig
KGkgPSAwOyBpIDwgcy5zaXplKCk7ICsraSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2ln
bmVkIGNoYXIpc1tpXTsKICAgIGlmIChjID09ICdcXCcgfHwgYyA9PSAnIicpIHsgeCArPSAnXFwn
OyB4ICs9IChjaGFyKWM7IH0KICAgIGVsc2UgaWYgKGMgPT0gJ1xuJykgeCArPSAiXFxuIjsKICAg
IGVsc2UgaWYgKGMgPT0gJ1xyJykgeCArPSAiXFxyIjsKICAgIGVsc2UgaWYgKGMgPT0gJ1x0Jykg
eCArPSAiXFx0IjsKICAgIGVsc2UgaWYgKGMgPCAzMikgeCArPSAnPyc7CiAgICBlbHNlIHggKz0g
KGNoYXIpYzsKICB9CiAgeCArPSAnIic7IHJldHVybiB4Owp9CnN0YXRpYyBsb25nIGxvbmcgbm93
X21zKCkgewogIHN0cnVjdCB0aW1ldmFsIHR2OyBnZXR0aW1lb2ZkYXkoJnR2LCBOVUxMKTsKICBy
ZXR1cm4gKGxvbmcgbG9uZyl0di50dl9zZWMgKiAxMDAwTEwgKyB0di50dl91c2VjIC8gMTAwMDsK
fQpzdGF0aWMgc3RkOjpzdHJpbmcgbnVtKGxvbmcgdikgeyBzdGQ6Om9zdHJpbmdzdHJlYW0gbzsg
byA8PCB2OyByZXR1cm4gby5zdHIoKTsgfQpzdGF0aWMgYm9vbCB2YWxpZF9wb3J0KHVuc2lnbmVk
IHApIHsgcmV0dXJuIHAgPiAwICYmIHAgPD0gNjU1MzU7IH0Kc3RhdGljIGJvb2wgaGFzX21ldGhv
ZChjb25zdCBzdGQ6OnN0cmluZyAmbSkgewogIHJldHVybiBtID09ICJHRVQiIHx8IG0gPT0gIlBP
U1QiIHx8IG0gPT0gIlBVVCIgfHwgbSA9PSAiREVMRVRFIiB8fAogICAgICAgICBtID09ICJQQVRD
SCIgfHwgbSA9PSAiSEVBRCIgfHwgbSA9PSAiT1BUSU9OUyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5n
IGhvc3RfbmFtZSgpIHsKICBjaGFyIGJbMjU2XTsgaWYgKGdldGhvc3RuYW1lKGIsIHNpemVvZihi
KSAtIDEpICE9IDApIHJldHVybiAidW5rbm93bi1ub2RlIjsKICBiW3NpemVvZihiKSAtIDFdID0g
MDsgY2hhciAqcCA9IHN0cmNocihiLCAnLicpOyBpZiAocCkgKnAgPSAwOyByZXR1cm4gYjsKfQpz
dGF0aWMgc3RkOjpzdHJpbmcgYjY0ZGVjb2RlX3VzZXIoY29uc3QgY2hhciAqaW4sIHNpemVfdCBp
bl9sZW4pIHsKICB3aGlsZSAoaW5fbGVuID4gMCAmJiBpc3NwYWNlKCh1bnNpZ25lZCBjaGFyKSpp
bikpIHsgKytpbjsgLS1pbl9sZW47IH0KICB3aGlsZSAoaW5fbGVuID4gMCAmJiBpc3NwYWNlKCh1
bnNpZ25lZCBjaGFyKWluW2luX2xlbiAtIDFdKSkgeyAtLWluX2xlbjsgfQogIHN0ZDo6c3RyaW5n
IG91dDsgaW50IHZhbCA9IDAsIGJpdHMgPSAtODsgc2l6ZV90IGk7CiAgZm9yIChpID0gMDsgaSA8
IGluX2xlbjsgKytpKSB7CiAgICB1bnNpZ25lZCBjaGFyIGMgPSAodW5zaWduZWQgY2hhcilpbltp
XTsgaW50IGQgPSAtMTsKICAgIGlmIChjID49ICdBJyAmJiBjIDw9ICdaJykgZCA9IGMgLSAnQSc7
CiAgICBlbHNlIGlmIChjID49ICdhJyAmJiBjIDw9ICd6JykgZCA9IGMgLSAnYScgKyAyNjsKICAg
IGVsc2UgaWYgKGMgPj0gJzAnICYmIGMgPD0gJzknKSBkID0gYyAtICcwJyArIDUyOwogICAgZWxz
ZSBpZiAoYyA9PSAnKycpIGQgPSA2MjsKICAgIGVsc2UgaWYgKGMgPT0gJy8nKSBkID0gNjM7CiAg
ICBlbHNlIGlmIChjID09ICc9JykgYnJlYWs7CiAgICBpZiAoZCA8IDApIGNvbnRpbnVlOwogICAg
dmFsID0gKHZhbCA8PCA2KSArIGQ7CiAgICBiaXRzICs9IDY7CiAgICBpZiAoYml0cyA+PSAwKSB7
CiAgICAgIG91dCArPSAoY2hhcikoKHZhbCA+PiBiaXRzKSAmIDB4ZmYpOwogICAgICBiaXRzIC09
IDg7CiAgICAgIGlmIChvdXQuc2l6ZSgpID4gNTEyKSByZXR1cm4gIiI7CiAgICB9CiAgfQogIHNp
emVfdCBwID0gb3V0LmZpbmQoJzonKTsKICBpZiAocCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgcmV0
dXJuICIiOwogIHJldHVybiBvdXQuc3Vic3RyKDAsIHAgPiA2NCA/IDY0IDogcCk7Cn0Kc3RhdGlj
IHN0ZDo6c3RyaW5nIGlwX3RvX3N0cih1aW50MzJfdCBpcF9iZSkgewogIGNoYXIgYltJTkVUX0FE
RFJTVFJMRU5dOwogIGluZXRfbnRvcChBRl9JTkVULCAmaXBfYmUsIGIsIHNpemVvZihiKSk7CiAg
cmV0dXJuIGI7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyB0cmFjZV9pZF9mcm9tX3BhcmVudChjb25z
dCBzdGQ6OnN0cmluZyAmdHApIHsKICBzdGQ6OnN0cmluZyB4ID0gdHJpbSh0cCk7CiAgaWYgKHgu
c2l6ZSgpID09IDU1ICYmIHhbMl0gPT0gJy0nICYmIHhbMzVdID09ICctJyAmJiB4WzUyXSA9PSAn
LScpIHJldHVybiBsb3dlcih4LnN1YnN0cigzLCAzMikpOwogIHJldHVybiAiIjsKfQoKc3RhdGlj
IHVpbnQ2NF90IGdfcm5nX3N0YXRlID0gMDsKc3RhdGljIHZvaWQgaW5pdF9ybmcoKSB7CiAgRklM
RSAqZiA9IGZvcGVuKCIvZGV2L3VyYW5kb20iLCAicmIiKTsKICBpZiAoZikgewogICAgc2l6ZV90
IG4gPSBmcmVhZCgmZ19ybmdfc3RhdGUsIDEsIHNpemVvZihnX3JuZ19zdGF0ZSksIGYpOwogICAg
KHZvaWQpbjsKICAgIGZjbG9zZShmKTsKICB9CiAgaWYgKCFnX3JuZ19zdGF0ZSkgewogICAgZ19y
bmdfc3RhdGUgPSAoKHVpbnQ2NF90KXRpbWUoTlVMTCkgPDwgMzIpIF4gKHVpbnQ2NF90KWdldHBp
ZCgpOwogIH0KfQpzdGF0aWMgaW5saW5lIHVpbnQ2NF90IG5leHRfcm5nKCkgewogIHVpbnQ2NF90
IHggPSBnX3JuZ19zdGF0ZTsKICB4IF49IHggPDwgMTM7IHggXj0geCA+PiA3OyB4IF49IHggPDwg
MTc7CiAgcmV0dXJuIGdfcm5nX3N0YXRlID0gKHggPyB4IDogMHg4NTNjNDllNjc0OGZlYTliVUxM
KTsKfQoKc3RhdGljIHN0ZDo6c3RyaW5nIG1ha2VfdHJhY2VwYXJlbnQoc3RkOjpzdHJpbmcgKnRp
ZCkgewogIHVpbnQ2NF90IHIxID0gbmV4dF9ybmcoKTsKICB1aW50NjRfdCByMiA9IG5leHRfcm5n
KCk7CiAgdWludDY0X3QgcjMgPSBuZXh0X3JuZygpOwogIGNoYXIgYnVmWzY0XTsKICBzbnByaW50
ZihidWYsIHNpemVvZihidWYpLCAiMDAtJTAxNmxseCUwMTZsbHgtJTAxNmxseC0wMSIsCiAgICAg
ICAgICAgKHVuc2lnbmVkIGxvbmcgbG9uZylyMSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMiwgKHVu
c2lnbmVkIGxvbmcgbG9uZylyMyk7CiAgY2hhciB0aWRfYnVmWzMzXTsKICBzbnByaW50Zih0aWRf
YnVmLCBzaXplb2YodGlkX2J1ZiksICIlMDE2bGx4JTAxNmxseCIsCiAgICAgICAgICAgKHVuc2ln
bmVkIGxvbmcgbG9uZylyMSwgKHVuc2lnbmVkIGxvbmcgbG9uZylyMik7CiAgKnRpZCA9IHRpZF9i
dWY7CiAgcmV0dXJuIGJ1ZjsKfQoKc3RydWN0IEV2ZW50IHsKICBsb25nIHRzOyBzdGQ6OnN0cmlu
ZyBob3N0LCBzcmMsIHNlcnZpY2UsIG1ldGhvZCwgcGF0aCwgdXNlciwgc2NoZW1lLCBwcm9iZTsK
ICBzdGQ6OnN0cmluZyBob3N0X2hkciwgdXNlcl9hZ2VudCwgeGZmLCBjYWxsZXIsIGRzdF9pcCwg
dHJhY2VwYXJlbnQsIHRyYWNlX2lkOwogIHVuc2lnbmVkIGNhbGxlcl9wb3J0LCBkc3RfcG9ydCwg
cmVxX2J5dGVzLCByZXNwX2J5dGVzOyBpbnQgc3RhdHVzOyBsb25nIGR1cmF0aW9uX21zOwogIGJv
b2wgaGFzX3N0YXR1cywgaGFzX2R1cmF0aW9uLCBoYXNfcmVzcDsKICBFdmVudCgpIDogdHMoMCks
IGNhbGxlcl9wb3J0KDApLCBkc3RfcG9ydCgwKSwgcmVxX2J5dGVzKDApLCByZXNwX2J5dGVzKDAp
LCBzdGF0dXMoMCksIGR1cmF0aW9uX21zKDApLCBoYXNfc3RhdHVzKGZhbHNlKSwgaGFzX2R1cmF0
aW9uKGZhbHNlKSwgaGFzX3Jlc3AoZmFsc2UpIHt9Cn07CnN0cnVjdCBGbG93IHsgc3RkOjpzdHJp
bmcgYnVmOyB0aW1lX3QgdG91Y2hlZDsgRmxvdygpIDogdG91Y2hlZCh0aW1lKE5VTEwpKSB7fSB9
OwpzdHJ1Y3QgUGVuZGluZyB7CiAgRXZlbnQgZXY7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbXM7CiAg
UGVuZGluZygpIDogc3RhcnRlZF9tcygwKSB7fQogIFBlbmRpbmcoY29uc3QgRXZlbnQgJmUsIGxv
bmcgbG9uZyB0KSA6IGV2KGUpLCBzdGFydGVkX21zKHQpIHt9Cn07CnN0cnVjdCBGbG93S2V5IHsK
ICB1aW50MzJfdCBzX2lwOwogIHVpbnQxNl90IHNwb3J0OwogIHVpbnQzMl90IGRfaXA7CiAgdWlu
dDE2X3QgZHBvcnQ7CiAgYm9vbCBvcGVyYXRvcjwoY29uc3QgRmxvd0tleSAmeCkgY29uc3Qgewog
ICAgaWYgKHNfaXAgIT0geC5zX2lwKSByZXR1cm4gc19pcCA8IHguc19pcDsKICAgIGlmIChzcG9y
dCAhPSB4LnNwb3J0KSByZXR1cm4gc3BvcnQgPCB4LnNwb3J0OwogICAgaWYgKGRfaXAgIT0geC5k
X2lwKSByZXR1cm4gZF9pcCA8IHguZF9pcDsKICAgIHJldHVybiBkcG9ydCA8IHguZHBvcnQ7CiAg
fQp9Owp0eXBlZGVmIEZsb3dLZXkgUGFja2V0S2V5OwoKc3RhdGljIHZvaWQgbG9nbXNnKGNvbnN0
IHN0ZDo6c3RyaW5nICZzKSB7IGZwcmludGYoc3RkZXJyLCAibnQtc25pZmYtY3BwOiAlc1xuIiwg
cy5jX3N0cigpKTsgZmZsdXNoKHN0ZGVycik7IH0KCnN0YXRpYyBib29sIHBhcnNlX3JlcXVlc3Qo
Y29uc3QgY2hhciAqZGF0YSwgc2l6ZV90IGxlbiwgRXZlbnQgKmUpIHsKICBjb25zdCBjaGFyICpl
bmQgPSBkYXRhICsgbGVuOwogIGNvbnN0IGNoYXIgKnAgPSBkYXRhOwogIGNvbnN0IGNoYXIgKmVv
bCA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICdcbicsIGVuZCAtIHApOwogIGlmICghZW9sKSBy
ZXR1cm4gZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwg
JyAnLCBlb2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGUtPm1ldGhvZC5hc3Np
Z24ocCwgc3AxIC0gcCk7CiAgaWYgKCFoYXNfbWV0aG9kKGUtPm1ldGhvZCkpIHJldHVybiBmYWxz
ZTsKCiAgY29uc3QgY2hhciAqcGF0aF9zdGFydCA9IHNwMSArIDE7CiAgd2hpbGUgKHBhdGhfc3Rh
cnQgPCBlb2wgJiYgKnBhdGhfc3RhcnQgPT0gJyAnKSArK3BhdGhfc3RhcnQ7CiAgY29uc3QgY2hh
ciAqc3AyID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocGF0aF9zdGFydCwgJyAnLCBlb2wgLSBwYXRo
X3N0YXJ0KTsKICBpZiAoIXNwMikgc3AyID0gKGVvbCA+IGRhdGEgJiYgKihlb2wgLSAxKSA9PSAn
XHInKSA/IGVvbCAtIDEgOiBlb2w7CiAgY29uc3QgY2hhciAqcW1hcmsgPSAoY29uc3QgY2hhciAq
KW1lbWNocihwYXRoX3N0YXJ0LCAnPycsIHNwMiAtIHBhdGhfc3RhcnQpOwogIHNpemVfdCBwYXRo
X2xlbiA9IChxbWFyayA/IHFtYXJrIDogc3AyKSAtIHBhdGhfc3RhcnQ7CiAgaWYgKHBhdGhfbGVu
ID4gMTIwKSBwYXRoX2xlbiA9IDEyMDsKICBlLT5wYXRoLmFzc2lnbihwYXRoX3N0YXJ0LCBwYXRo
X2xlbik7CgogIHAgPSBlb2wgKyAxOwogIHdoaWxlIChwIDwgZW5kKSB7CiAgICBpZiAoKnAgPT0g
J1xyJyB8fCAqcCA9PSAnXG4nKSBicmVhazsKICAgIGNvbnN0IGNoYXIgKmxpbmVfZW5kID0gKGNv
bnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgICBpZiAoIWxpbmVfZW5kKSBs
aW5lX2VuZCA9IGVuZDsKICAgIGNvbnN0IGNoYXIgKmNvbG9uID0gKGNvbnN0IGNoYXIgKiltZW1j
aHIocCwgJzonLCBsaW5lX2VuZCAtIHApOwogICAgaWYgKGNvbG9uKSB7CiAgICAgIHNpemVfdCBo
bmFtZV9sZW4gPSBjb2xvbiAtIHA7CiAgICAgIGNvbnN0IGNoYXIgKnZhbF9zdGFydCA9IGNvbG9u
ICsgMTsKICAgICAgd2hpbGUgKHZhbF9zdGFydCA8IGxpbmVfZW5kICYmICgqdmFsX3N0YXJ0ID09
ICcgJyB8fCAqdmFsX3N0YXJ0ID09ICdcdCcpKSArK3ZhbF9zdGFydDsKICAgICAgY29uc3QgY2hh
ciAqdmFsX2VuZCA9IGxpbmVfZW5kOwogICAgICB3aGlsZSAodmFsX2VuZCA+IHZhbF9zdGFydCAm
JiAodmFsX2VuZFstMV0gPT0gJ1xyJyB8fCB2YWxfZW5kWy0xXSA9PSAnXG4nIHx8IHZhbF9lbmRb
LTFdID09ICcgJyB8fCB2YWxfZW5kWy0xXSA9PSAnXHQnKSkgLS12YWxfZW5kOwogICAgICBzaXpl
X3QgdmFsX2xlbiA9IHZhbF9lbmQgLSB2YWxfc3RhcnQ7CgogICAgICBpZiAoaG5hbWVfbGVuID09
IDEzICYmICFzdHJuY2FzZWNtcChwLCAiYXV0aG9yaXphdGlvbiIsIDEzKSkgewogICAgICAgIGlm
ICh2YWxfbGVuID4gNiAmJiAhc3RybmNhc2VjbXAodmFsX3N0YXJ0LCAiQmFzaWMgIiwgNikpIHsK
ICAgICAgICAgIGUtPnVzZXIgPSBiNjRkZWNvZGVfdXNlcih2YWxfc3RhcnQgKyA2LCB2YWxfbGVu
IC0gNik7CiAgICAgICAgICBlLT5zY2hlbWUgPSAiYmFzaWMiOwogICAgICAgIH0gZWxzZSBpZiAo
dmFsX2xlbiA+IDcgJiYgIXN0cm5jYXNlY21wKHZhbF9zdGFydCwgIkJlYXJlciAiLCA3KSkgewog
ICAgICAgICAgZS0+c2NoZW1lID0gImJlYXJlciI7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYg
KGhuYW1lX2xlbiA9PSAxMSAmJiAhc3RybmNhc2VjbXAocCwgInRyYWNlcGFyZW50IiwgMTEpKSB7
CiAgICAgICAgZS0+dHJhY2VwYXJlbnQuYXNzaWduKHZhbF9zdGFydCwgdmFsX2xlbik7CiAgICAg
ICAgZS0+dHJhY2VfaWQgPSB0cmFjZV9pZF9mcm9tX3BhcmVudChlLT50cmFjZXBhcmVudCk7CiAg
ICAgIH0gZWxzZSBpZiAoaG5hbWVfbGVuID09IDQgJiYgIXN0cm5jYXNlY21wKHAsICJob3N0Iiwg
NCkpIHsKICAgICAgICBlLT5ob3N0X2hkci5hc3NpZ24odmFsX3N0YXJ0LCB2YWxfbGVuKTsKICAg
ICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTAgJiYgIXN0cm5jYXNlY21wKHAsICJ1c2VyLWFn
ZW50IiwgMTApKSB7CiAgICAgICAgZS0+dXNlcl9hZ2VudC5hc3NpZ24odmFsX3N0YXJ0LCB2YWxf
bGVuKTsKICAgICAgfSBlbHNlIGlmIChobmFtZV9sZW4gPT0gMTUgJiYgIXN0cm5jYXNlY21wKHAs
ICJ4LWZvcndhcmRlZC1mb3IiLCAxNSkpIHsKICAgICAgICBlLT54ZmYuYXNzaWduKHZhbF9zdGFy
dCwgdmFsX2xlbik7CiAgICAgIH0KICAgIH0KICAgIHAgPSBsaW5lX2VuZCArIDE7CiAgfQoKICBp
ZiAoZS0+dXNlci5lbXB0eSgpKSBlLT51c2VyID0gIi1hbm9ueW1vdXMtIjsKICBpZiAoZS0+c2No
ZW1lLmVtcHR5KCkpIGUtPnNjaGVtZSA9ICJub25lIjsKICBpZiAoZS0+dHJhY2VfaWQuZW1wdHko
KSkgZS0+dHJhY2VwYXJlbnQgPSBtYWtlX3RyYWNlcGFyZW50KCZlLT50cmFjZV9pZCk7CiAgcmV0
dXJuIHRydWU7Cn0KCnN0YXRpYyBib29sIHBhcnNlX3Jlc3BvbnNlKGNvbnN0IGNoYXIgKmRhdGEs
IHNpemVfdCBsZW4sIGludCAqc3RhdHVzLCB1bnNpZ25lZCAqY2xlbikgewogIGNvbnN0IGNoYXIg
KmVuZCA9IGRhdGEgKyBsZW47CiAgY29uc3QgY2hhciAqcCA9IGRhdGE7CiAgY29uc3QgY2hhciAq
ZW9sID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJ1xuJywgZW5kIC0gcCk7CiAgaWYgKCFlb2wp
IHJldHVybiBmYWxzZTsKICBpZiAoc3RybmNtcChwLCAiSFRUUC8iLCA1KSAhPSAwKSByZXR1cm4g
ZmFsc2U7CiAgY29uc3QgY2hhciAqc3AxID0gKGNvbnN0IGNoYXIgKiltZW1jaHIocCwgJyAnLCBl
b2wgLSBwKTsKICBpZiAoIXNwMSkgcmV0dXJuIGZhbHNlOwogIGNvbnN0IGNoYXIgKnNjX3N0YXJ0
ID0gc3AxICsgMTsKICB3aGlsZSAoc2Nfc3RhcnQgPCBlb2wgJiYgKnNjX3N0YXJ0ID09ICcgJykg
KytzY19zdGFydDsKICAqc3RhdHVzID0gYXRvaShzY19zdGFydCk7CiAgaWYgKCpzdGF0dXMgPCAx
MDAgfHwgKnN0YXR1cyA+IDU5OSkgcmV0dXJuIGZhbHNlOwogICpjbGVuID0gMDsKICBwID0gZW9s
ICsgMTsKICB3aGlsZSAocCA8IGVuZCkgewogICAgaWYgKCpwID09ICdccicgfHwgKnAgPT0gJ1xu
JykgYnJlYWs7CiAgICBjb25zdCBjaGFyICpsaW5lX2VuZCA9IChjb25zdCBjaGFyICopbWVtY2hy
KHAsICdcbicsIGVuZCAtIHApOwogICAgaWYgKCFsaW5lX2VuZCkgbGluZV9lbmQgPSBlbmQ7CiAg
ICBjb25zdCBjaGFyICpjb2xvbiA9IChjb25zdCBjaGFyICopbWVtY2hyKHAsICc6JywgbGluZV9l
bmQgLSBwKTsKICAgIGlmIChjb2xvbikgewogICAgICBzaXplX3QgaGxlbiA9IGNvbG9uIC0gcDsK
ICAgICAgaWYgKGhsZW4gPT0gMTQgJiYgIXN0cm5jYXNlY21wKHAsICJjb250ZW50LWxlbmd0aCIs
IDE0KSkgewogICAgICAgIGNvbnN0IGNoYXIgKnYgPSBjb2xvbiArIDE7CiAgICAgICAgd2hpbGUg
KHYgPCBsaW5lX2VuZCAmJiAoKnYgPT0gJyAnIHx8ICp2ID09ICdcdCcpKSArK3Y7CiAgICAgICAg
bG9uZyBuID0gYXRvbCh2KTsKICAgICAgICBpZiAobiA+PSAwICYmIG4gPD0gMHg3ZmZmZmZmZikg
KmNsZW4gPSAodW5zaWduZWQpbjsKICAgICAgfQogICAgfQogICAgcCA9IGxpbmVfZW5kICsgMTsK
ICB9CiAgcmV0dXJuIHRydWU7Cn0KCnN0YXRpYyBzdGQ6OnN0cmluZyBnX2VuZHBvaW50OwpzdGF0
aWMgc3RkOjpzdHJpbmcgZ19zaGlwX25vZGU7CnN0YXRpYyBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmlu
Zz4gZ19zaGlwX2J1ZjsKCnN0YXRpYyBzdGQ6OnN0cmluZyBzaGVsbHEoY29uc3Qgc3RkOjpzdHJp
bmcgJnMpIHsKICBzdGQ6OnN0cmluZyBvID0gIiciOwogIGZvciAoc2l6ZV90IGkgPSAwOyBpIDwg
cy5zaXplKCk7ICsraSkgeyBpZiAoc1tpXSA9PSAnXCcnKSBvICs9ICInXFwnJyI7IGVsc2UgbyAr
PSBzW2ldOyB9CiAgcmV0dXJuIG8gKyAiJyI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIG51bWJlcl9z
dHJpbmcoc2l6ZV90IG4pIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgbjsgcmV0dXJuIG8u
c3RyKCk7IH0Kc3RhdGljIHN0ZDo6c3RyaW5nIGpzb25fYXJyYXkoY29uc3Qgc3RkOjp2ZWN0b3I8
c3RkOjpzdHJpbmc+ICZhKSB7CiAgc3RkOjpzdHJpbmcgbyA9ICJbIjsgZm9yIChzaXplX3QgaSA9
IDA7IGkgPCBhLnNpemUoKTsgKytpKSB7IGlmIChpKSBvICs9ICIsIjsgbyArPSBhW2ldOyB9IHJl
dHVybiBvICsgIl0iOwp9CnN0YXRpYyBib29sIHBvc3QoY29uc3Qgc3RkOjpzdHJpbmcgJmVuZHBv
aW50LCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJp
bmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHkgPSAie1wibm9kZVwiOiIgKyBqc29ucShu
b2RlKSArICIsXCJldmVudHNcIjoiICsganNvbl9hcnJheShiYXRjaCkgKyAifSI7CiAgc3RkOjpz
dHJpbmcgY21kID0gImN1cmwgLXNTZiAtLW1heC10aW1lIDEwIC1vIC9kZXYvbnVsbCAtSCAnQ29u
dGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uJyAtLWRhdGEtYmluYXJ5IEAtICIgKyBzaGVsbHEo
ZW5kcG9pbnQgKyAiL2FwaS9pbmdlc3QiKTsKICBGSUxFICpmcCA9IHBvcGVuKGNtZC5jX3N0cigp
LCAidyIpOyBpZiAoIWZwKSByZXR1cm4gZmFsc2U7CiAgZndyaXRlKGJvZHkuZGF0YSgpLCAxLCBi
b2R5LnNpemUoKSwgZnApOwogIGludCByYyA9IHBjbG9zZShmcCk7CiAgcmV0dXJuIFdJRkVYSVRF
RChyYykgJiYgV0VYSVRTVEFUVVMocmMpID09IDA7Cn0Kc3RhdGljIHZvaWQgc2VuZF9iYXRjaGVz
KGNvbnN0IHN0ZDo6c3RyaW5nICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAg
ICAgICAgICAgICAgICAgICAgICAgICBzdGQ6OnZlY3RvcjxzdGQ6OnN0cmluZz4gKmJ1ZiwgYm9v
bCBmbHVzaF9hbGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1wdHkoKSAmJiAoZmx1c2hfYWxsIHx8IGJ1
Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCkpIHsKICAgIHNpemVfdCBuID0gYnVmLT5zaXplKCkgPj0g
TUFYX0JBVENIID8gTUFYX0JBVENIIDogYnVmLT5zaXplKCk7CiAgICBzdGQ6OnZlY3RvcjxzdGQ6
OnN0cmluZz4gYmF0Y2goYnVmLT5iZWdpbigpLCBidWYtPmJlZ2luKCkgKyBuKTsKICAgIGlmIChw
b3N0KGVuZHBvaW50LCBub2RlLCBiYXRjaCkpIHsKICAgICAgYnVmLT5lcmFzZShidWYtPmJlZ2lu
KCksIGJ1Zi0+YmVnaW4oKSArIG4pOwogICAgICBsb2dtc2coImZsdXNoZWQgIiArIG51bWJlcl9z
dHJpbmcobikgKyAiIGV2ZW50cyIpOwogICAgfSBlbHNlIHsKICAgICAgLyogUHVyZSBpbi1tZW1v
cnkgZHJvcCB3aGVuIEh1YiB1bnJlYWNoYWJsZSAoemVybyBkaXNrIEkvTykgKi8KICAgICAgYnVm
LT5lcmFzZShidWYtPmJlZ2luKCksIGJ1Zi0+YmVnaW4oKSArIG4pOwogICAgICBsb2dtc2coIldB
Uk46IEh1YiB1bnJlYWNoYWJsZSwgZHJvcHBlZCAiICsgbnVtYmVyX3N0cmluZyhuKSArICIgZXZl
bnRzIChpbi1tZW1vcnkgZHJvcCwgMCBkaXNrIEkvTykiKTsKICAgICAgYnJlYWs7CiAgICB9CiAg
fQp9CgpzdGF0aWMgdm9pZCBlbWl0X2V2ZW50KGNvbnN0IEV2ZW50ICZlKSB7CiAgc3RkOjpvc3Ry
aW5nc3RyZWFtIHNzOwogIHNzIDw8ICJ7XCJ0c1wiOiIgPDwgZS50cyA8PCAiLFwiaG9zdFwiOiIg
PDwganNvbnEoZS5ob3N0KSA8PCAiLFwic3JjXCI6XCJwY2FwXCIsXCJzZXJ2aWNlXCI6IiA8PCBq
c29ucShlLnNlcnZpY2UpCiAgICAgPDwgIixcIm1ldGhvZFwiOiIgPDwganNvbnEoZS5tZXRob2Qp
IDw8ICIsXCJwYXRoXCI6IiA8PCBqc29ucShlLnBhdGgpIDw8ICIsXCJ1c2VyXCI6IiA8PCBqc29u
cShlLnVzZXIpCiAgICAgPDwgIixcInNjaGVtZVwiOiIgPDwganNvbnEoZS5zY2hlbWUpIDw8ICIs
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
CgogIGlmICghZ19lbmRwb2ludC5lbXB0eSgpKSB7CiAgICBpZiAoZ19zaGlwX2J1Zi5zaXplKCkg
Pj0gTUFYX1FVRVVFKSB7CiAgICAgIGdfc2hpcF9idWYuZXJhc2UoZ19zaGlwX2J1Zi5iZWdpbigp
KTsKICAgIH0KICAgIGdfc2hpcF9idWYucHVzaF9iYWNrKHNzLnN0cigpKTsKICB9IGVsc2Ugewog
ICAgc3RkOjpjb3V0IDw8IHNzLnN0cigpIDw8ICJcbiI7CiAgfQp9CgpzdGF0aWMgdm9pZCBmbHVz
aF9vbGRlc3Qoc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5k
aW5nKSB7CiAgaWYgKHBlbmRpbmcuZW1wdHkoKSkgcmV0dXJuOwogIHN0ZDo6bWFwPFBhY2tldEtl
eSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgaXQgPSBwZW5kaW5nLmJlZ2luKCk7
CiAgaWYgKCFpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgIGVtaXRfZXZlbnQoaXQtPnNlY29uZFsw
XS5ldik7CiAgICBpdC0+c2Vjb25kLmVyYXNlKGl0LT5zZWNvbmQuYmVnaW4oKSk7CiAgfQogIGlm
IChpdC0+c2Vjb25kLmVtcHR5KCkpIHsKICAgIHBlbmRpbmcuZXJhc2UoaXQpOwogIH0KfQpzdGF0
aWMgdm9pZCBzd2VlcChzdGQ6Om1hcDxGbG93S2V5LCBGbG93PiAmZmxvd3MsIHN0ZDo6bWFwPFBh
Y2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPiAmcGVuZGluZywgdGltZV90IG5vdykgewog
IHN0ZDo6bWFwPEZsb3dLZXksIEZsb3c+OjppdGVyYXRvciBmLCBmbjsKICBmb3IgKGYgPSBmbG93
cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAgZm4gPSBmOyArK2ZuOwogICAgaWYg
KCh1bnNpZ25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNoZWQpID4gRkxPV19UVEwpIGZsb3dzLmVy
YXNlKGYpOwogICAgZiA9IGZuOwogIH0KICBsb25nIGxvbmcgY3VycmVudF9tcyA9IChsb25nIGxv
bmcpbm93ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tldEtleSwgc3RkOjp2ZWN0b3I8UGVuZGlu
Zz4gPjo6aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0gcGVuZGluZy5iZWdpbigpOyBwICE9IHBl
bmRpbmcuZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47CiAgICBzaXplX3QgaSA9IDA7CiAgICB3
aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAgaWYgKGN1cnJlbnRfbXMgLSBwLT5z
ZWNvbmRbaV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcpUEVORElOR19UVEwgKiAxMDAwTEwpIHsK
ICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7CiAgICAgICAgcC0+c2Vjb25kLmVy
YXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgKytpOwog
ICAgICB9CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVtcHR5KCkpIHBlbmRpbmcuZXJhc2UocCk7
CiAgICBwID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmluZF9odHRwX3N0YXJ0KGNvbnN0IHN0
ZDo6c3RyaW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0geyAiR0VUICIsICJQT1NUICIsICJQ
VVQgIiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwgIk9QVElPTlMgIiB9OwogIHNpemVf
dCBiZXN0ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChzaXplX3QgaSA9IDA7IGkgPCA3OyAr
K2kpIHsKICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7CiAgICBpZiAocG9zICE9IHN0ZDo6
c3RyaW5nOjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5nOjpucG9zIHx8IHBvcyA8IGJlc3Qp
KSBiZXN0ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoKc3RhdGljIGJvb2wgZ19tb25pdG9y
ZWRfcG9ydHNbNjU1MzZdOwoKc3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25l
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
PSBub3c7IGZsLmJ1Zi5hcHBlbmQocGF5bG9hZCwgcGxlbik7CiAgaWYgKGZsLmJ1Zi5zaXplKCkg
PiBNQVhfSEVBREVSKSB7IGZsb3dzLmVyYXNlKGZrKTsgcmV0dXJuIGZhbHNlOyB9CiAgd2hpbGUg
KHRydWUpIHsKICAgIHNpemVfdCBzdGFydCA9IGZpbmRfaHR0cF9zdGFydChmbC5idWYpOwogICAg
aWYgKHN0YXJ0ID09IHN0ZDo6c3RyaW5nOjpucG9zKSB7IGZsLmJ1Zi5jbGVhcigpOyBicmVhazsg
fQogICAgaWYgKHN0YXJ0ID4gMCkgZmwuYnVmLmVyYXNlKDAsIHN0YXJ0KTsKICAgIHNpemVfdCBl
bmQgPSBmbC5idWYuZmluZCgiXHJcblxyXG4iKTsKICAgIGlmIChlbmQgPT0gc3RkOjpzdHJpbmc6
Om5wb3MpIGJyZWFrOwogICAgRXZlbnQgZTsgZS50cyA9IG5vdzsgZS5ob3N0ID0gbm9kZTsgZS5z
ZXJ2aWNlID0gInBvcnQ6IiArIG51bShkcG9ydCk7IGUuY2FsbGVyID0gaXBfdG9fc3RyKHNfaXAp
OyBlLmNhbGxlcl9wb3J0ID0gc3BvcnQ7IGUuZHN0X2lwID0gaXBfdG9fc3RyKGRfaXApOyBlLmRz
dF9wb3J0ID0gZHBvcnQ7IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKShlbmQgKyA0KTsKICAgIGlm
ICghcGFyc2VfcmVxdWVzdChmbC5idWYuZGF0YSgpLCBlbmQsICZlKSkgeyBmbC5idWYuZXJhc2Uo
MCwgZW5kICsgNCk7IGNvbnRpbnVlOyB9CiAgICBmbC5idWYuZXJhc2UoMCwgZW5kICsgNCk7CiAg
ICBQYWNrZXRLZXkgcms7IHJrLnNfaXAgPSBkX2lwOyByay5zcG9ydCA9ICh1aW50MTZfdClkcG9y
dDsgcmsuZF9pcCA9IHNfaXA7IHJrLmRwb3J0ID0gKHVpbnQxNl90KXNwb3J0OwogICAgaWYgKHBl
bmRpbmcuc2l6ZSgpID49IE1BWF9QRU5ESU5HKSBmbHVzaF9vbGRlc3QocGVuZGluZyk7CiAgICBw
ZW5kaW5nW3JrXS5wdXNoX2JhY2soUGVuZGluZyhlLCBub3dfbXMoKSkpOwogIH0KICBpZiAoZmwu
YnVmLmVtcHR5KCkpIHsKICAgIGZsb3dzLmVyYXNlKGZrKTsKICB9CiAgcmV0dXJuIHRydWU7Cn0K
CnN0YXRpYyBib29sIGF0dGFjaF9icGYoaW50IGZkLCBjb25zdCBzdGQ6OnZlY3Rvcjx1bnNpZ25l
ZD4gJnBvcnRzKSB7CiAgaWYgKHBvcnRzLmVtcHR5KCkpIHJldHVybiBmYWxzZTsKICBzdGQ6OnZl
Y3RvcjxzdHJ1Y3Qgc29ja19maWx0ZXI+IGY7IHNpemVfdCBpOwogIC8qIER1YWwtcGF0aCBjQlBG
OiBQYXRoIEEgKHN0YW5kYXJkIElQdjQpIGFuZCBQYXRoIEIgKDgwMi4xUSBWTEFOIHRhZ2dlZCBJ
UHY0KS4gKi8KICB1bnNpZ25lZCBOID0gKHVuc2lnbmVkKXBvcnRzLnNpemUoKTsKICB1bnNpZ25l
ZCByZWplY3QgPSAxMSArIE4gKiA4OwogIHVuc2lnbmVkIGFjY2VwdCA9IHJlamVjdCArIDE7CiAg
c3RydWN0IHNvY2tfZmlsdGVyIHg7CiNkZWZpbmUgQUREKEMsSixULEspIGRvIHsgeC5jb2RlPShD
KTsgeC5qdD0oSik7IHguamY9KFQpOyB4Lms9KEspOyBmLnB1c2hfYmFjayh4KTsgfSB3aGlsZSgw
KQogIC8qIFswXSBMb2FkIEV0aGVyVHlwZSBhdCBvZmZzZXQgMTIgKi8KICBBREQoQlBGX0xEfEJQ
Rl9IfEJQRl9BQlMsIDAsIDAsIDEyKTsKICAvKiBbMV0gSWYgc3RhbmRhcmQgSVB2NCAoMHgwODAw
KSwganVtcCBvdmVyIFBhdGggQiAoNiArIDQqTiBpbnN0cnVjdGlvbnMpIHRvIFBhdGggQSAqLwog
IEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssICh1bnNpZ25lZCkoNiArIDQgKiBOKSwgMCwgRVRI
X1BfSVBfSE9TVCk7CgogIC8qIC0tLSBQYXRoIEI6IDgwMi4xUSBWTEFOIChpbmRleCAyKSAtLS0g
Ki8KICAvKiBbMl0gSWYgbm90IDgwMi4xUSAoMHg4MTAwKSwgcmVqZWN0ICovCiAgQUREKEJQRl9K
TVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2lnbmVkKShyZWplY3QgLSAodW5zaWduZWQpZi5zaXpl
KCkgLSAxKSwgRVRIX1BfODAyMVFfSE9TVCk7CiAgLyogWzNdIExvYWQgZW5jYXBzdWxhdGVkIEV0
aGVyVHlwZSBhdCBvZmZzZXQgMTYgKi8KICBBREQoQlBGX0xEfEJQRl9IfEJQRl9BQlMsIDAsIDAs
IDE2KTsKICAvKiBbNF0gSWYgZW5jYXBzdWxhdGVkICE9IElQdjQsIHJlamVjdCAqLwogIEFERChC
UEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYu
c2l6ZSgpIC0gMSksIEVUSF9QX0lQX0hPU1QpOwogIC8qIFs1XSBMb2FkIElQIHByb3RvY29sIGF0
IG9mZnNldCAyNyAoMjMgKyA0KSAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwg
MjcpOwogIC8qIFs2XSBJZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVR
fEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJ
UFBST1RPX1RDUCk7CiAgLyogWzddIExvYWQgSUhMIGF0IG9mZnNldCAxOCAoMTQgKyA0KSAqLwog
IEFERChCUEZfTERYfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE4KTsKICAvKiBEZXN0aW5hdGlvbiBw
b3J0IGNoZWNrcyBmb3IgVkxBTiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsr
aSkgewogICAgQUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAyMCk7CiAgICB1bnNpZ25l
ZCBqdCA9IGFjY2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxC
UEZfSkVRfEJQRl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVj
a3MgZm9yIFZMQU4gKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAg
IEFERChCUEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTgpOwogICAgdW5zaWduZWQganQgPSBh
Y2NlcHQgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBv
cnRzLnNpemUoKSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsK
ICAgIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAg
LyogLS0tIFBhdGggQTogU3RhbmRhcmQgSVB2NCAtLS0gKi8KICAvKiBMb2FkIElQIHByb3RvY29s
IGF0IG9mZnNldCAyMyAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FCUywgMCwgMCwgMjMpOwog
IC8qIElmIG5vdCBUQ1AsIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBGX0ssIDAs
ICh1bnNpZ25lZCkocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSksIElQUFJPVE9fVENQ
KTsKICAvKiBMb2FkIElITCBhdCBvZmZzZXQgMTQgKi8KICBBREQoQlBGX0xEWHxCUEZfQnxCUEZf
TVNILCAwLCAwLCAxNCk7CiAgLyogRGVzdGluYXRpb24gcG9ydCBjaGVja3MgZm9yIHN0YW5kYXJk
IElQdjQgKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChC
UEZfTER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTYpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQg
LSAodW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywg
anQsIDAsIHBvcnRzW2ldKTsKICB9CiAgLyogU291cmNlIHBvcnQgY2hlY2tzIGZvciBzdGFuZGFy
ZCBJUHY0ICovCiAgZm9yIChpID0gMDsgaSA8IHBvcnRzLnNpemUoKTsgKytpKSB7CiAgICBBREQo
QlBGX0xEfEJQRl9IfEJQRl9JTkQsIDAsIDAsIDE0KTsKICAgIHVuc2lnbmVkIGp0ID0gYWNjZXB0
IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMTsKICAgIHVuc2lnbmVkIGpmID0gKGkgPCBwb3J0cy5z
aXplKCkgLSAxKSA/IDAgOiAocmVqZWN0IC0gKHVuc2lnbmVkKWYuc2l6ZSgpIC0gMSk7CiAgICBB
REQoQlBGX0pNUHxCUEZfSkVRfEJQRl9LLCBqdCwgamYsIHBvcnRzW2ldKTsKICB9CgogIC8qIFty
ZWplY3RdIERyb3AgcGFja2V0ICovCiAgQUREKEJQRl9SRVR8QlBGX0ssIDAsIDAsIDApOwogIC8q
IFthY2NlcHRdIEFjY2VwdCBwYWNrZXQgKDIwNDggYnl0ZXMpICovCiAgQUREKEJQRl9SRVR8QlBG
X0ssIDAsIDAsIEFDQ0VQVCk7CiN1bmRlZiBBREQKICBpZiAoZi5zaXplKCkgPiA0MDk2KSByZXR1
cm4gZmFsc2U7CiAgc3RydWN0IHNvY2tfZnByb2cgcHJvZzsgcHJvZy5sZW4gPSAodW5zaWduZWQg
c2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07CiNpZm5kZWYgU09fQVRUQUNIX0ZJ
TFRFUgojZGVmaW5lIFNPX0FUVEFDSF9GSUxURVIgMjYKI2VuZGlmCiAgcmV0dXJuIHNldHNvY2tv
cHQoZmQsIFNPTF9TT0NLRVQsIFNPX0FUVEFDSF9GSUxURVIsICZwcm9nLCBzaXplb2YocHJvZykp
ID09IDA7Cn0KCnN0cnVjdCBNbWFwUmluZyB7CiAgdm9pZCAqcmluZzsKICBzaXplX3QgcmluZ19z
aXplOwogIHVuc2lnbmVkIGJsb2NrX3NpemU7CiAgdW5zaWduZWQgYmxvY2tfbnI7CiAgdW5zaWdu
ZWQgZnJhbWVfc2l6ZTsKICB1bnNpZ25lZCBmcmFtZV9ucjsKICB1bnNpZ25lZCBmcmFtZXNfcGVy
X2Jsb2NrOwogIHVuc2lnbmVkIGZyYW1lX2lkeDsKCiAgTW1hcFJpbmcoKSA6IHJpbmcoTUFQX0ZB
SUxFRCksIHJpbmdfc2l6ZSgwKSwgYmxvY2tfc2l6ZSg2NTUzNiksIGJsb2NrX25yKDY0KSwKICAg
ICAgICAgICAgICAgZnJhbWVfc2l6ZSgyMDQ4KSwgZnJhbWVfbnIoMjA0OCksIGZyYW1lc19wZXJf
YmxvY2soMzIpLCBmcmFtZV9pZHgoMCkge30KfTsKCnN0YXRpYyBib29sIHNldHVwX21tYXBfcmlu
ZyhpbnQgZmQsIE1tYXBSaW5nICZtcikgewogIGludCB2ZXIgPSBUUEFDS0VUX1YyOwogIGlmIChz
ZXRzb2Nrb3B0KGZkLCBTT0xfUEFDS0VULCBQQUNLRVRfVkVSU0lPTiwgJnZlciwgc2l6ZW9mKHZl
cikpIDwgMCkgewogICAgcmV0dXJuIGZhbHNlOwogIH0KICBzdHJ1Y3QgdHBhY2tldF9yZXEgcmVx
OwogIG1lbXNldCgmcmVxLCAwLCBzaXplb2YocmVxKSk7CiAgcmVxLnRwX2Jsb2NrX3NpemUgPSA2
NTUzNjsKICByZXEudHBfYmxvY2tfbnIgPSA2NDsgICAgICAgLyogNE1CIHNoYXJlZCBtZW1vcnkg
cmluZyBidWZmZXIgKi8KICByZXEudHBfZnJhbWVfc2l6ZSA9IDIwNDg7ICAgLyogMktCIHBlciBm
cmFtZSAqLwogIHJlcS50cF9mcmFtZV9uciA9IChyZXEudHBfYmxvY2tfc2l6ZSAqIHJlcS50cF9i
bG9ja19ucikgLyByZXEudHBfZnJhbWVfc2l6ZTsgLyogMjA0OCBmcmFtZXMgKi8KCiAgaWYgKHNl
dHNvY2tvcHQoZmQsIFNPTF9QQUNLRVQsIFBBQ0tFVF9SWF9SSU5HLCAmcmVxLCBzaXplb2YocmVx
KSkgPCAwKSB7CiAgICByZXR1cm4gZmFsc2U7CiAgfQogIG1yLnJpbmdfc2l6ZSA9IChzaXplX3Qp
cmVxLnRwX2Jsb2NrX3NpemUgKiByZXEudHBfYmxvY2tfbnI7CiAgbXIuYmxvY2tfc2l6ZSA9IHJl
cS50cF9ibG9ja19zaXplOwogIG1yLmJsb2NrX25yID0gcmVxLnRwX2Jsb2NrX25yOwogIG1yLmZy
YW1lX3NpemUgPSByZXEudHBfZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9uciA9IHJlcS50cF9mcmFt
ZV9ucjsKICBtci5mcmFtZXNfcGVyX2Jsb2NrID0gcmVxLnRwX2Jsb2NrX3NpemUgLyByZXEudHBf
ZnJhbWVfc2l6ZTsKICBtci5mcmFtZV9pZHggPSAwOwoKICBtci5yaW5nID0gbW1hcChOVUxMLCBt
ci5yaW5nX3NpemUsIFBST1RfUkVBRCB8IFBST1RfV1JJVEUsIE1BUF9TSEFSRUQsIGZkLCAwKTsK
ICBpZiAobXIucmluZyA9PSBNQVBfRkFJTEVEKSB7CiAgICBtci5yaW5nX3NpemUgPSAwOwogICAg
cmV0dXJuIGZhbHNlOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoKc3RhdGljIGludCBydW5fZml4dHVy
ZSgpIHsKICBzdGQ6OnN0cmluZyByZXEgPSAiR0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJc
bkhvc3Q6IGFwaS5sb2NhbFxyXG5BdXRob3JpemF0aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYw
XHJcblRyYWNlcGFyZW50OiAwMC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIz
NDU2Nzg5YWJjZGVmLTAxXHJcblxyXG4iOwogIEV2ZW50IGU7IGUudHMgPSAxNzAwMDAwMDAwOyBl
Lmhvc3QgPSAiY3BwLW5vZGUiOyBlLnNlcnZpY2UgPSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAi
MTAuMC4wLjkiOyBlLmNhbGxlcl9wb3J0ID0gNTEwMDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsg
ZS5kc3RfcG9ydCA9IDgwODA7IGUucmVxX2J5dGVzID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBh
cnNlX3JlcXVlc3QocmVxLmRhdGEoKSwgcmVxLnNpemUoKSAtIDQsICZlKTsgZS5zdGF0dXMgPSAy
MDA7IGUuaGFzX3N0YXR1cyA9IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlv
biA9IHRydWU7IGUucmVzcF9ieXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVu
dChlKTsgcmV0dXJuIDA7Cn0KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikgewogIGlm
IChhcmdjID4gMSAmJiAhc3RyY21wKGFyZ3ZbMV0sICItLWZpeHR1cmUiKSkgcmV0dXJuIHJ1bl9m
aXh0dXJlKCk7CiAgc3RkOjpzdHJpbmcgaWZhY2U7IHN0ZDo6dmVjdG9yPHVuc2lnbmVkPiBwb3J0
czsgaW50IGk7IGludCB3b3JrZXJzID0gMTsKICBzdGQ6OnN0cmluZyBlbmRwb2ludDsKICBmb3Ig
KGkgPSAxOyBpIDwgYXJnYzsgKytpKSB7CiAgICBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWkiKSAm
JiBpICsgMSA8IGFyZ2MpIGlmYWNlID0gYXJndlsrK2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChh
cmd2W2ldLCAiLXAiKSAmJiBpICsgMSA8IGFyZ2MpIHsKICAgICAgd2hpbGUgKGkgKyAxIDwgYXJn
YyAmJiBhcmd2W2kgKyAxXVswXSAhPSAnLScpIHsKICAgICAgICBjaGFyICpxID0gc3RydG9rKGFy
Z3ZbKytpXSwgIiwgIik7CiAgICAgICAgd2hpbGUgKHEpIHsgbG9uZyBwID0gYXRvbChxKTsgaWYg
KHZhbGlkX3BvcnQoKHVuc2lnbmVkKXApKSBwb3J0cy5wdXNoX2JhY2soKHVuc2lnbmVkKXApOyBx
ID0gc3RydG9rKE5VTEwsICIsICIpOyB9CiAgICAgIH0KICAgIH0KICAgIGVsc2UgaWYgKCFzdHJj
bXAoYXJndltpXSwgIi0tZW5kcG9pbnQiKSAmJiBpICsgMSA8IGFyZ2MpIGVuZHBvaW50ID0gYXJn
dlsrK2ldOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLS1zcG9vbCIpICYmIGkgKyAx
IDwgYXJnYykgKytpOyAvKiBpZ25vcmVkOiAwIGRpc2sgd3JpdGUgKi8KICAgIGVsc2UgaWYgKCFz
dHJjbXAoYXJndltpXSwgIi1qIikgJiYgaSArIDEgPCBhcmdjKSB3b3JrZXJzID0gYXRvaShhcmd2
WysraV0pOwogICAgZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWgiKSB8fCAhc3RyY21wKGFy
Z3ZbaV0sICItLWhlbHAiKSkgewogICAgICBmcHJpbnRmKHN0ZGVyciwgInVzYWdlOiBudC1zbmlm
Zi1jcHAgWy1pIGlmYWNlXSBbLXAgcG9ydHNdIFstLWVuZHBvaW50IFVSTF0gWy1qIHdvcmtlcnNd
XG4iKTsKICAgICAgcmV0dXJuIDA7CiAgICB9CiAgfQogIGlmIChwb3J0cy5lbXB0eSgpKSB7IHBv
cnRzLnB1c2hfYmFjayg4MCk7IHBvcnRzLnB1c2hfYmFjayg4MDAzKTsgcG9ydHMucHVzaF9iYWNr
KDgwMDUpOyBwb3J0cy5wdXNoX2JhY2soODAwNyk7IHBvcnRzLnB1c2hfYmFjayg4MDA5KTsgcG9y
dHMucHVzaF9iYWNrKDgwMTApOyBwb3J0cy5wdXNoX2JhY2soODAxMSk7IH0KICAodm9pZCl3b3Jr
ZXJzOwoKICBpbml0X3JuZygpOwogIG1lbXNldChnX21vbml0b3JlZF9wb3J0cywgMCwgc2l6ZW9m
KGdfbW9uaXRvcmVkX3BvcnRzKSk7CiAgZm9yIChzaXplX3QgayA9IDA7IGsgPCBwb3J0cy5zaXpl
KCk7ICsraykgewogICAgaWYgKHBvcnRzW2tdIDwgNjU1MzYpIGdfbW9uaXRvcmVkX3BvcnRzW3Bv
cnRzW2tdXSA9IHRydWU7CiAgfQoKICBjb25zdCBjaGFyICpub2RlX2VudiA9IGdldGVudigiTlRf
Tk9ERV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2RlX2VudiAmJiAqbm9kZV9lbnYp
ID8gbm9kZV9lbnYgOiBob3N0X25hbWUoKTsKCiAgZ19lbmRwb2ludCA9IGVuZHBvaW50OwogIGdf
c2hpcF9ub2RlID0gbm9kZTsKCiAgaW50IGZkID0gc29ja2V0KEFGX1BBQ0tFVCwgU09DS19SQVcs
IGh0b25zKDMpKTsKICBpZiAoZmQgPCAwKSB7IHBlcnJvcigiQUZfUEFDS0VUIik7IHJldHVybiAy
OyB9CiAgaW50IHJiID0gOCAqIDEwMjQgKiAxMDI0OwogIHNldHNvY2tvcHQoZmQsIFNPTF9TT0NL
RVQsIFNPX1JDVkJVRiwgJnJiLCBzaXplb2YocmIpKTsKICBpZiAoIWF0dGFjaF9icGYoZmQsIHBv
cnRzKSkgbG9nbXNnKCJXQVJOOiBCUEYgYXR0YWNoIGZhaWxlZDsgY29udGludWluZyB1bmZpbHRl
cmVkIik7CgogIE1tYXBSaW5nIHJpbmc7CiAgYm9vbCB1c2VfbW1hcCA9IHNldHVwX21tYXBfcmlu
ZyhmZCwgcmluZyk7CgogIHN0cnVjdCBzb2NrYWRkcl9sbCBzYTsKICBtZW1zZXQoJnNhLCAwLCBz
aXplb2Yoc2EpKTsKICBzYS5zbGxfZmFtaWx5ID0gQUZfUEFDS0VUOwogIHNhLnNsbF9wcm90b2Nv
bCA9IGh0b25zKDMpOwogIGlmICghaWZhY2UuZW1wdHkoKSkgewogICAgc2Euc2xsX2lmaW5kZXgg
PSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3RyKCkpOwogICAgaWYgKCFzYS5zbGxfaWZp
bmRleCkgeyBsb2dtc2coImJhZCBpbnRlcmZhY2UiKTsgY2xvc2UoZmQpOyByZXR1cm4gMjsgfQog
IH0KICBpZiAoYmluZChmZCwgKHN0cnVjdCBzb2NrYWRkciAqKSZzYSwgc2l6ZW9mKHNhKSkgPCAw
KSB7IHBlcnJvcigiYmluZCIpOyBjbG9zZShmZCk7IHJldHVybiAyOyB9CgogIHNpZ25hbChTSUdU
RVJNLCBzdG9wX3NpZ25hbCk7CiAgc2lnbmFsKFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHNldHZi
dWYoc3Rkb3V0LCBOVUxMLCBfSU9MQkYsIDY1NTM2KTsKICBzdGQ6Om1hcDxGbG93S2V5LCBGbG93
PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4gcGVu
ZGluZzsKCiAgaWYgKHVzZV9tbWFwKSB7CiAgICBsb2dtc2coIlBBQ0tFVF9NTUFQIChUUEFDS0VU
X1YyKSB6ZXJvLWNvcHkgcmluZyBlbmFibGVkICg0TUIsIDIwNDggZnJhbWVzKSIpOwogIH0gZWxz
ZSB7CiAgICBsb2dtc2coIldBUk46IFBBQ0tFVF9NTUFQIHNldHVwIGZhaWxlZCwgZmFsbGluZyBi
YWNrIHRvIHN0YW5kYXJkIHNvY2tldCByZWN2Iik7CiAgfQogIGlmICghZ19lbmRwb2ludC5lbXB0
eSgpKSB7CiAgICBsb2dtc2coInNpbmdsZS1iaW5hcnkgaW4tbWVtb3J5IG1vZGU6IHNoaXBwaW5n
IGRpcmVjdGx5IHRvICIgKyBnX2VuZHBvaW50ICsgIiAoMCBkaXNrIEkvTykiKTsKICB9CiAgbG9n
bXNnKCJsaXN0ZW5pbmciKTsKCiAgdGltZV90IGxhc3QgPSB0aW1lKE5VTEwpLCBsYXN0X2ZsdXNo
ID0gbGFzdDsKICB1bnNpZ25lZCBjaGFyICpmYWxsYmFja19idWYgPSBOVUxMOwogIGlmICghdXNl
X21tYXApIHsKICAgIGZhbGxiYWNrX2J1ZiA9ICh1bnNpZ25lZCBjaGFyICopbWFsbG9jKDY1NTM2
KTsKICAgIGlmICghZmFsbGJhY2tfYnVmKSB7CiAgICAgIGNsb3NlKGZkKTsKICAgICAgbG9nbXNn
KCJidWZmZXIgYWxsb2NhdGlvbiBmYWlsZWQiKTsKICAgICAgcmV0dXJuIDI7CiAgICB9CiAgfQoK
ICBzdHJ1Y3QgcG9sbGZkIHBmZDsKICBwZmQuZmQgPSBmZDsKICBwZmQuZXZlbnRzID0gUE9MTElO
IHwgUE9MTEVSUjsKICBwZmQucmV2ZW50cyA9IDA7CgogIHdoaWxlIChnX3J1bm5pbmcpIHsKICAg
IGludCByYyA9IHBvbGwoJnBmZCwgMSwgMTAwMCk7CiAgICBpZiAocmMgPCAwICYmIGVycm5vID09
IEVJTlRSKSB7CiAgICAgIC8qIFNpZ25hbCBoYW5kbGVkLCBsb29wIGNvbmRpdGlvbiB3aWxsIGNo
ZWNrIGdfcnVubmluZyAqLwogICAgfSBlbHNlIGlmIChyYyA+PSAwKSB7CiAgICAgIGlmICh1c2Vf
bW1hcCkgewogICAgICAgIC8qIERyYWluIGFsbCByZWFkeSBmcmFtZXMgaW4gdGhlIHJpbmcgd2l0
aG91dCBleHRyYSBzeXNjYWxscyAqLwogICAgICAgIHdoaWxlIChnX3J1bm5pbmcpIHsKICAgICAg
ICAgIHVuc2lnbmVkIGJfaWR4ID0gcmluZy5mcmFtZV9pZHggLyByaW5nLmZyYW1lc19wZXJfYmxv
Y2s7CiAgICAgICAgICB1bnNpZ25lZCBmX2luX2IgPSByaW5nLmZyYW1lX2lkeCAlIHJpbmcuZnJh
bWVzX3Blcl9ibG9jazsKICAgICAgICAgIHVpbnQ4X3QgKmZyYW1lX3B0ciA9ICgodWludDhfdCAq
KXJpbmcucmluZykgKyAoYl9pZHggKiByaW5nLmJsb2NrX3NpemUpICsgKGZfaW5fYiAqIHJpbmcu
ZnJhbWVfc2l6ZSk7CiAgICAgICAgICBzdHJ1Y3QgdHBhY2tldDJfaGRyICpoZHIgPSAoc3RydWN0
IHRwYWNrZXQyX2hkciAqKWZyYW1lX3B0cjsKCiAgICAgICAgICBpZiAoIShoZHItPnRwX3N0YXR1
cyAmIFRQX1NUQVRVU19VU0VSKSkgewogICAgICAgICAgICBicmVhazsgLyogTm8gbW9yZSBrZXJu
ZWwtcG9wdWxhdGVkIGZyYW1lcyBpbiByaW5nIHJpZ2h0IG5vdyAqLwogICAgICAgICAgfQoKICAg
ICAgICAgIGlmIChoZHItPnRwX3NuYXBsZW4gPiAwKSB7CiAgICAgICAgICAgIGNvbnN0IHVuc2ln
bmVkIGNoYXIgKnBrdCA9ICgoY29uc3QgdW5zaWduZWQgY2hhciAqKWhkcikgKyBoZHItPnRwX21h
YzsKICAgICAgICAgICAgaGFuZGxlX3BhY2tldChwa3QsIChzaXplX3QpaGRyLT50cF9zbmFwbGVu
LCBub2RlLCBwb3J0cywgZmxvd3MsIHBlbmRpbmcpOwogICAgICAgICAgfQoKICAgICAgICAgIGhk
ci0+dHBfc3RhdHVzID0gVFBfU1RBVFVTX0tFUk5FTDsgLyogUmV0dXJuIGZyYW1lIG93bmVyc2hp
cCB0byBrZXJuZWwgKi8KICAgICAgICAgIHJpbmcuZnJhbWVfaWR4ID0gKHJpbmcuZnJhbWVfaWR4
ICsgMSkgJSByaW5nLmZyYW1lX25yOwogICAgICAgIH0KICAgICAgICBpZiAoZ19lbmRwb2ludC5l
bXB0eSgpKSBzdGQ6OmNvdXQuZmx1c2goKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBpZiAocGZk
LnJldmVudHMgJiBQT0xMSU4pIHsKICAgICAgICAgIHNzaXplX3QgbiA9IHJlY3YoZmQsIGZhbGxi
YWNrX2J1ZiwgNjU1MzYsIDApOwogICAgICAgICAgaWYgKG4gPiAwKSB7CiAgICAgICAgICAgIGhh
bmRsZV9wYWNrZXQoZmFsbGJhY2tfYnVmLCAoc2l6ZV90KW4sIG5vZGUsIHBvcnRzLCBmbG93cywg
cGVuZGluZyk7CiAgICAgICAgICAgIGlmIChnX2VuZHBvaW50LmVtcHR5KCkpIHN0ZDo6Y291dC5m
bHVzaCgpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfQogICAgfQoKICAgIHRpbWVfdCBu
b3cgPSB0aW1lKE5VTEwpOwogICAgaWYgKG5vdyAtIGxhc3QgPj0gMSkgewogICAgICBzd2VlcChm
bG93cywgcGVuZGluZywgbm93KTsKICAgICAgaWYgKGdfZW5kcG9pbnQuZW1wdHkoKSkgc3RkOjpj
b3V0LmZsdXNoKCk7CiAgICAgIGxhc3QgPSBub3c7CiAgICB9CgogICAgaWYgKCFnX2VuZHBvaW50
LmVtcHR5KCkpIHsKICAgICAgaWYgKG5vdyAtIGxhc3RfZmx1c2ggPj0gRkxVU0hfU0VDIHx8IGdf
c2hpcF9idWYuc2l6ZSgpID49IE1BWF9CQVRDSCkgewogICAgICAgIGlmICghZ19zaGlwX2J1Zi5l
bXB0eSgpKSBzZW5kX2JhdGNoZXMoZ19lbmRwb2ludCwgZ19zaGlwX25vZGUsICZnX3NoaXBfYnVm
LCB0cnVlKTsKICAgICAgICBsYXN0X2ZsdXNoID0gbm93OwogICAgICB9CiAgICB9CiAgfQoKICBp
ZiAoIWdfZW5kcG9pbnQuZW1wdHkoKSAmJiAhZ19zaGlwX2J1Zi5lbXB0eSgpKSB7CiAgICBzZW5k
X2JhdGNoZXMoZ19lbmRwb2ludCwgZ19zaGlwX25vZGUsICZnX3NoaXBfYnVmLCB0cnVlKTsKICB9
CgogIGlmICh1c2VfbW1hcCAmJiByaW5nLnJpbmcgIT0gTUFQX0ZBSUxFRCkgewogICAgbXVubWFw
KHJpbmcucmluZywgcmluZy5yaW5nX3NpemUpOwogIH0KICBpZiAoZmFsbGJhY2tfYnVmKSBmcmVl
KGZhbGxiYWNrX2J1Zik7CiAgY2xvc2UoZmQpOwogIGxvZ21zZygic3RvcHBlZCIpOwogIHJldHVy
biAwOwp9Cg==
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
