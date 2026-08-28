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

log()  { echo "[nt-legacy] $*"; }
die()  { echo "[nt-legacy] FAIL: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --hub)      KIT_URLS="$2"; shift 2 ;;
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
    python -m py_compile "$WORKDIR/nt-sniff.py" 2>/dev/null \
        || die "nt-sniff.py does not compile under node python"
    python -m py_compile "$WORKDIR/nt-ship.py" 2>/dev/null \
        || die "nt-ship.py does not compile under node python"
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
if [ "${NT_CAPTURE_MODE:-python}" = "cpp" ]; then
    have g++ || die "NT_CAPTURE_MODE=cpp requires g++ on target"
    have python || die "python shipper required on target"
else
    have python || die "python (2.6+) required on the node"
    python -c 'import sys; assert sys.version_info >= (2,6)' \
        || die "python 2.6+ required"
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

# privilege model: copy the interpreter, grant IT cap_net_raw, run sniffer
# as a locked account. Falls back to root when setcap/SELinux refuses.
SNIFF_AS=root
PYBIN=$(command -v python)
if have setcap && have useradd; then
    id "$SNIFF_USER" >/dev/null 2>&1 || useradd -r -s /sbin/nologin "$SNIFF_USER" 2>/dev/null || true
    cp "$PYBIN" "$PREFIX/python-capnetraw" 2>/dev/null || true
    # NOTE: chown BEFORE setcap — chown clears file capabilities
    # (proven on el6: setcap-then-chown left getcap empty -> EPERM)
    if [ -f "$PREFIX/python-capnetraw" ] \
       && chown "$SNIFF_USER" "$PREFIX"/python-capnetraw 2>/dev/null \
       && setcap cap_net_raw+ep "$PREFIX/python-capnetraw" 2>/dev/null; then
        SNIFF_AS="$SNIFF_USER"
        log "rootless mode: cap_net_raw on private interpreter, user=$SNIFF_USER"
    else
        rm -f "$PREFIX/python-capnetraw"
        log "WARN: setcap path failed — sniffer will run as root"
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
# Choose native C++ only when explicitly requested; Python remains default.
CAPTURE_MODE="${NT_CAPTURE_MODE:-python}"
# Native C++ builds from the copied source and uses the native C++ shipper.
# The default capture mode remains Python for compatibility.
if [ "$CAPTURE_MODE" = "cpp" ]; then
    CXXSTD=$(g++ -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
    (cd "$PREFIX" && g++ -O2 -Wall -Wextra $CXXSTD nt-sniff-cpp.cpp -o nt-sniff-cpp && g++ -O2 -Wall -Wextra $CXXSTD nt-ship-cpp.cpp -o nt-ship-cpp) || die "C++ build failed"
    SNIFF_CMD="exec $PREFIX/nt-sniff-cpp -i $IFACE -p $PORTS"
    SHIP_CMD="exec $PREFIX/nt-ship-cpp --endpoint $ENDPOINT --spool /var/lib/networktracing/sniff-spool.jsonl"
    log "native C++ capture + shipper selected"
else
    if [ "$SNIFF_AS" != root ]; then
        SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS'"
    else
        SNIFF_CMD="exec python -u $PREFIX/nt-sniff.py -j $WORKERS -i $IFACE -p $PORTS"
    fi
    SHIP_CMD="exec python -u $PREFIX/nt-ship.py --endpoint $ENDPOINT"
fi

cat > "$INIT" <<EOF
#!/bin/sh
# networktracing-legacy — pcap sniffer + shipper (SysV, el6)
# chkconfig: 2345 90 10
# description: NetworkTracing passive HTTP/SOAP capture (old-kernel kit)

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
        nohup sh -c "$SNIFF_CMD 2>>\$PREFIX/sniff.log | $SHIP_CMD >>\$PREFIX/ship.log 2>&1" >/dev/null 2>&1 &
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
            rm -f "\$INIT" "\$PIDFILE"
            rm -rf "\$PREFIX" /tmp/ntkit
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

"$INIT" start || die "service failed to start"
sleep 3
pgrep -f "$PREFIX/nt-sniff.py" >/dev/null || pgrep -f "$PREFIX/nt-sniff-cpp" >/dev/null || die "sniffer not running after start"

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
ZG91dC5mbHVzaCgpCgogICAgbG9nKCJzdG9wcGVkIikKCgppZiBfX25hbWVfXyA9PSAiX19tYWlu
X18iOgogICAgbWFpbigpCg==
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
IHNvY2tldC5nZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICAjIHJlcGxheSBzcG9vbGVk
IGV2ZW50cyBmaXJzdCAoYXQtbGVhc3Qtb25jZSkKICAgIHBlbmRpbmcgPSBbXQogICAgaWYgb3Mu
cGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcGVuKHNw
b29sKSBhcyBmOgogICAgICAgICAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAg
ICAgICBsaW5lID0gbGluZS5zdHJpcCgpCiAgICAgICAgICAgICAgICAgICAgaWYgbGluZToKICAg
ICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVu
ZGluZy5hcHBlbmQoanNvbi5sb2FkcyhsaW5lKSkKICAgICAgICAgICAgICAgICAgICAgICAgZXhj
ZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAg
ICAgIG9zLnJlbW92ZShzcG9vbCkKICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpIGFz
IGU6CiAgICAgICAgICAgIGxvZygic3Bvb2wgcmVhZCBmYWlsZWQ6ICVzIiAlIGUpCgogICAgcnVu
bmluZyA9IFtUcnVlXQoKICAgIGRlZiBzdG9wKHNpZ251bSwgZnJhbWUpOgogICAgICAgIHJ1bm5p
bmdbMF0gPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgc3RvcCkKICAg
IHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0lOVCwgc3RvcCkKCiAgICBkZWYgZmx1c2goYmF0Y2gp
OgogICAgICAgIGlmIG5vdCBiYXRjaDoKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBi
b2R5ID0ganNvbi5kdW1wcyh7Im5vZGUiOiBub2RlLCAiZXZlbnRzIjogYmF0Y2h9KQogICAgICAg
ICMgcHkyIHVybGxpYjIgYWNjZXB0cyBzdHI7IHB5MyBzaGltL3Rlc3QgbmVlZHMgYnl0ZXMg4oCU
IGVuY29kZSB3aGVuCiAgICAgICAgIyB0aGUgcnVudGltZSBleHBvc2VzIGl0IChweTIgc3RyIGhh
cyBubyAuZW5jb2RlIG9uIGFsbCBidWlsZHMsIHNvCiAgICAgICAgIyBndWFyZCB3aXRoIGhhc2F0
dHIpCiAgICAgICAgaWYgaGFzYXR0cihib2R5LCAiZW5jb2RlIik6CiAgICAgICAgICAgIGJvZHkg
PSBib2R5LmVuY29kZSgidXRmLTgiKQogICAgICAgIHJlcSA9IHVybGxpYjIuUmVxdWVzdChlbmRw
b2ludCArICIvYXBpL2luZ2VzdCIsIGRhdGE9Ym9keSwKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgaGVhZGVycz17IkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAg
ICAgdHJ5OgogICAgICAgICAgICByZXNwID0gdXJsbGliMi51cmxvcGVuKHJlcSwgdGltZW91dD0x
MCkKICAgICAgICAgICAgb2sgPSAocmVzcC5nZXRjb2RlKCkgPT0gMjAwKQogICAgICAgICAgICBy
ZXNwLnJlYWQoKQogICAgICAgICAgICByZXNwLmNsb3NlKCkKICAgICAgICAgICAgaWYgb2s6CiAg
ICAgICAgICAgICAgICBsb2coImZsdXNoZWQgJWQgZXZlbnRzIiAlIGxlbihiYXRjaCkpCiAgICAg
ICAgICAgIHJldHVybiBvawogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAg
ICAgbG9nKCJzaGlwIGZhaWxlZDogJXMiICUgZSkKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgog
ICAgIyAtLS0tIGNvbmN1cnJlbnQgc2hpcHBpbmcgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLQogICAgIyBodWIgaW5nZXN0IGxhdGVuY3kgKH4zMDAtNTAwbXMgcGVy
IDQwMC1ldmVudCBQT1NUIG92ZXIgV0FOKSBtYWtlcwogICAgIyBzZXF1ZW50aWFsIHBvc3Rpbmcg
YSB+MTAwMCBldi9zIGNlaWxpbmc7IE4gcG9zdGVyIHRocmVhZHMgcG9zdGluZwogICAgIyBpbmRl
cGVuZGVudCBiYXRjaGVzIG11bHRpcGx5IHRoYXQgYnkgTlRfU0hJUF9USFJFQURTCiAgICBxID0g
UXVldWUuUXVldWUobWF4c2l6ZT0xMjgpCiAgICBzcG9vbF9sb2NrID0gdGhyZWFkaW5nLkxvY2so
KQogICAgbnRocmVhZHMgPSBpbnQob3MuZW52aXJvbi5nZXQoIk5UX1NISVBfVEhSRUFEUyIsICI0
IikpCgogICAgZGVmIHBvc3RlcigpOgogICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgIGJh
dGNoID0gcS5nZXQoKQogICAgICAgICAgICBpZiBiYXRjaCBpcyBOb25lOgogICAgICAgICAgICAg
ICAgcS50YXNrX2RvbmUoKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIGZs
dXNoKGJhdGNoKToKICAgICAgICAgICAgICAgIGJhY2tvZmZfYm94WzBdID0gMQogICAgICAgICAg
ICBlbHNlOgogICAgICAgICAgICAgICAgd2l0aCBzcG9vbF9sb2NrOgogICAgICAgICAgICAgICAg
ICAgIF9zcG9vbF9hcHBlbmQoc3Bvb2wsIGJhdGNoKQogICAgICAgICAgICBxLnRhc2tfZG9uZSgp
CgogICAgYmFja29mZl9ib3ggPSBbMV0KICAgIGZvciBfIGluIHJhbmdlKG50aHJlYWRzKToKICAg
ICAgICB0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9cG9zdGVyKQogICAgICAgIHQuZGFlbW9u
ID0gVHJ1ZQogICAgICAgIHQuc3RhcnQoKQoKICAgIGJ1ZiA9IGxpc3QocGVuZGluZykKICAgIGxh
c3RfZmx1c2ggPSB0aW1lLnRpbWUoKQogICAgbGFzdF9zcG9vbF90cnkgPSB0aW1lLnRpbWUoKQoK
ICAgIGRlZiBmb2xkX3Nwb29sKCk6CiAgICAgICAgIiIiUmUtcXVldWUgc3Bvb2xlZCBldmVudHMg
KG1pZC1ydW4gcmV0cnkpOyByZXR1cm5zIGNvdW50IGZvbGRlZC4iIiIKICAgICAgICBuID0gMAog
ICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcGVuKHNwb29sKSBhcyBmOgogICAgICAgICAg
ICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAgICAgICBsaW5lID0gbGluZS5zdHJp
cCgpCiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGxpbmU6CiAgICAgICAgICAgICAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAg
ICAgICBldiA9IGpzb24ubG9hZHMobGluZSkKICAgICAgICAgICAgICAgICAgICBleGNlcHQgVmFs
dWVFcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAg
ICAgICBpZiBpc2luc3RhbmNlKGV2LCBkaWN0KToKICAgICAgICAgICAgICAgICAgICAgICAgYnVm
LmFwcGVuZChldikKICAgICAgICAgICAgICAgICAgICAgICAgbiArPSAxCiAgICAgICAgICAgIG9z
LnJlbW92ZShzcG9vbCkKICAgICAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3IpOgogICAgICAg
ICAgICBwYXNzCiAgICAgICAgcmV0dXJuIG4KCiAgICB3aGlsZSBydW5uaW5nWzBdOgogICAgICAg
IHRyeToKICAgICAgICAgICAgciwgXywgXyA9IHNlbGVjdC5zZWxlY3QoW3N5cy5zdGRpbl0sIFtd
LCBbXSwgMS4wKQogICAgICAgIGV4Y2VwdCBzZWxlY3QuZXJyb3IgYXMgZToKICAgICAgICAgICAg
aWYgZVswXSA9PSBlcnJuby5FSU5UUjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAg
ICAgIGJyZWFrCgogICAgICAgIGlmIHI6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAg
IHJhdyA9IHN5cy5zdGRpbi5yZWFkbGluZSgpCiAgICAgICAgICAgIGV4Y2VwdCAoSU9FcnJvciwg
T1NFcnJvcikgYXMgZToKICAgICAgICAgICAgICAgIGlmIGdldGF0dHIoZSwgJ2Vycm5vJywgTm9u
ZSkgPT0gZXJybm8uRUlOVFI6CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgIGlmIG5vdCByYXc6CiAgICAgICAgICAgICAgICBicmVh
ayAgICAgICAgICAgICAgICAgICMgRU9GCiAgICAgICAgICAgIHJhdyA9IHJhdy5zdHJpcCgpCiAg
ICAgICAgICAgIGlmIHJhdzoKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAg
ICBldiA9IGpzb24ubG9hZHMocmF3KQogICAgICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2Uo
ZXYsIGRpY3QpOgogICAgICAgICAgICAgICAgICAgICAgICBidWYuYXBwZW5kKGV2KQogICAgICAg
ICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgcGFzcwoKICAg
ICAgICBub3cgPSB0aW1lLnRpbWUoKQogICAgICAgIHdoaWxlIGxlbihidWYpID49IE1BWF9CQVRD
SCBvciAoYnVmIGFuZCBub3cgLSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQyk6CiAgICAgICAgICAg
IGxhc3RfZmx1c2ggPSBub3cKICAgICAgICAgICAgaWYgbm93IC0gbGFzdF9zcG9vbF90cnkgPj0g
NjAgYW5kIG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAgICAgICAgICAgIGxhc3Rfc3Bvb2xf
dHJ5ID0gbm93CiAgICAgICAgICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICAgICAgcS5wdXQo
YnVmWzpNQVhfQkFUQ0hdKQogICAgICAgICAgICBkZWwgYnVmWzpNQVhfQkFUQ0hdCgogICAgIyBz
dGRpbiBjbG9zZWQgKHNuaWZmZXIgc3RvcHBlZCkg4oCUIGRyYWluIHF1ZXVlLCB0aGVuIGtlZXAg
cmV0cnlpbmcKICAgICMgYW55dGhpbmcgc3Bvb2xlZCB1bnRpbCBpdCBsYW5kcyBvciBSRVRSWV9N
QVggZWxhcHNlcwogICAgZGVhZGxpbmUgPSB0aW1lLnRpbWUoKSArIFJFVFJZX01BWAogICAgcS5q
b2luKCkKICAgIHdoaWxlIHJ1bm5pbmdbMF0gYW5kIHRpbWUudGltZSgpIDwgZGVhZGxpbmUgYW5k
IG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICBpZiBu
b3QgYnVmOgogICAgICAgICAgICBicmVhawogICAgICAgIGlmIGZsdXNoKGJ1Zik6CiAgICAgICAg
ICAgIGRlbCBidWZbOl0KICAgICAgICBlbHNlOgogICAgICAgICAgICB3aXRoIHNwb29sX2xvY2s6
CiAgICAgICAgICAgICAgICBfc3Bvb2xfYXBwZW5kKHNwb29sLCBidWYpCiAgICAgICAgICAgICAg
ICBkZWwgYnVmWzpdCiAgICAgICAgdGltZS5zbGVlcChtaW4oYmFja29mZl9ib3hbMF0sIDYwKSkK
ICAgICAgICBiYWNrb2ZmX2JveFswXSAqPSAyCiAgICAgICAgaWYgb3MucGF0aC5leGlzdHMoc3Bv
b2wpOgogICAgICAgICAgICBmb2xkX3Nwb29sKCkKICAgICAgICBpZiBub3QgYnVmIGFuZCBub3Qg
b3MucGF0aC5leGlzdHMoc3Bvb2wpOgogICAgICAgICAgICBicmVhawogICAgbG9nKCJzdG9wcGVk
ICglZCBldmVudHMgcGVuZGluZyBvbiBleGl0KSIgJSBsZW4oYnVmKSkKCgpkZWYgX3Nwb29sX2Fw
cGVuZChwYXRoLCBiYXRjaCk6CiAgICBkID0gb3MucGF0aC5kaXJuYW1lKHBhdGgpCiAgICB0cnk6
CiAgICAgICAgaWYgZCBhbmQgbm90IG9zLnBhdGguaXNkaXIoZCk6CiAgICAgICAgICAgIG9zLm1h
a2VkaXJzKGQpCiAgICAgICAgd2l0aCBvcGVuKHBhdGgsICJhIikgYXMgZjoKICAgICAgICAgICAg
Zm9yIGV2IGluIGJhdGNoOgogICAgICAgICAgICAgICAgZi53cml0ZShqc29uLmR1bXBzKGV2KSAr
ICJcbiIpCiAgICAgICAgZGVsIGJhdGNoWzpdCiAgICBleGNlcHQgKElPRXJyb3IsIE9TRXJyb3Ip
IGFzIGU6CiAgICAgICAgbG9nKCJGQVRBTDogY2Fubm90IHdyaXRlIHNwb29sICVzOiAlcyIgJSAo
cGF0aCwgZSkpCiAgICAgICAgb3MuX2V4aXQoMykKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18i
OgogICAgbWFpbigpCg==
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
IG8gKz0gc1tpXTsgfQogIHJldHVybiBvICsgIiciOwp9CnN0YXRpYyBib29sIHJlYWRfZmlsZShj
b25zdCBzdGQ6OnN0cmluZyAmcCwgc3RkOjpzdHJpbmcgKm91dCkgewogIHN0ZDo6aWZzdHJlYW0g
ZihwLmNfc3RyKCkpOyBpZiAoIWYpIHJldHVybiBmYWxzZTsKICBzdGQ6Om9zdHJpbmdzdHJlYW0g
c3M7IHNzIDw8IGYucmRidWYoKTsgKm91dCA9IHNzLnN0cigpOyByZXR1cm4gdHJ1ZTsKfQpzdGF0
aWMgYm9vbCB3cml0ZV9hcHBlbmQoY29uc3Qgc3RkOjpzdHJpbmcgJnAsIGNvbnN0IHN0ZDo6c3Ry
aW5nICZkYXRhKSB7CiAgc3RkOjpzdHJpbmcgZGlyPXAuc3Vic3RyKDAscC5maW5kX2xhc3Rfb2Yo
Jy8nKSk7CiAgaWYgKCFkaXIuZW1wdHkoKSkgeyBzdGQ6OnN0cmluZyBjbWQ9Im1rZGlyIC1wICIr
c2hlbGxxKGRpcik7IGlmIChzeXN0ZW0oY21kLmNfc3RyKCkpICE9IDApIHJldHVybiBmYWxzZTsg
fQogIHN0ZDo6b2ZzdHJlYW0gZihwLmNfc3RyKCksIHN0ZDo6aW9zOjpvdXR8c3RkOjppb3M6OmFw
cCk7IGlmICghZikgcmV0dXJuIGZhbHNlOwogIGYgPDwgZGF0YTsgcmV0dXJuIGYuZ29vZCgpOwp9
CnN0YXRpYyBzdGQ6OnN0cmluZyBudW1iZXJfc3RyaW5nKHNpemVfdCBuKSB7IHN0ZDo6b3N0cmlu
Z3N0cmVhbSBvOyBvIDw8IG47IHJldHVybiBvLnN0cigpOyB9CnN0YXRpYyBzdGQ6OnN0cmluZyBq
c29uX2FycmF5KGNvbnN0IHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAmYSkgewogIHN0ZDo6c3Ry
aW5nIG89IlsiOyBmb3Ioc2l6ZV90IGk9MDtpPGEuc2l6ZSgpOysraSl7aWYoaSlvKz0iLCI7bys9
YVtpXTt9IHJldHVybiBvKyJdIjsKfQpzdGF0aWMgYm9vbCBwb3N0KGNvbnN0IHN0ZDo6c3RyaW5n
ICZlbmRwb2ludCwgY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsCiAgICAgICAgICAgICAgICAgY29u
c3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5nIGJvZHk9
IntcIm5vZGVcIjoiK2pzb25xKG5vZGUpKyIsXCJldmVudHNcIjoiK2pzb25fYXJyYXkoYmF0Y2gp
KyJ9IjsKICBjaGFyIGNvZGVfdG1wbFtdID0gIi90bXAvbnRfY29kZV9YWFhYWFgiOwogIGludCB0
bXBfZmQgPSBta3N0ZW1wKGNvZGVfdG1wbCk7CiAgaWYgKHRtcF9mZCA8IDApIHJldHVybiBmYWxz
ZTsKICBjbG9zZSh0bXBfZmQpOwogIHN0ZDo6c3RyaW5nIGNvZGVfZmlsZSA9IGNvZGVfdG1wbDsK
ICBzdGQ6OnN0cmluZyBjbWQ9ImN1cmwgLXNTIC0tbWF4LXRpbWUgMTUgLW8gL2Rldi9udWxsIC13
ICcle2h0dHBfY29kZX0nIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nIC0tZGF0
YS1iaW5hcnkgQC0gIitzaGVsbHEoZW5kcG9pbnQrIi9hcGkvaW5nZXN0IikrIiA+ICIrc2hlbGxx
KGNvZGVfZmlsZSk7CiAgRklMRSAqZnA9cG9wZW4oY21kLmNfc3RyKCksInciKTsgaWYoIWZwKXsg
dW5saW5rKGNvZGVfZmlsZS5jX3N0cigpKTsgcmV0dXJuIGZhbHNlOyB9CiAgZndyaXRlKGJvZHku
ZGF0YSgpLCAxLCBib2R5LnNpemUoKSwgZnApOwogIGludCByYz1wY2xvc2UoZnApOwogIHN0ZDo6
c3RyaW5nIGNvZGU7CiAgcmVhZF9maWxlKGNvZGVfZmlsZSwgJmNvZGUpOwogIHVubGluayhjb2Rl
X2ZpbGUuY19zdHIoKSk7CiAgd2hpbGUgKCFjb2RlLmVtcHR5KCkgJiYgKGNvZGVbY29kZS5zaXpl
KCktMV09PSdccicgfHwgY29kZVtjb2RlLnNpemUoKS0xXT09J1xuJyB8fCBjb2RlW2NvZGUuc2l6
ZSgpLTFdPT0nICcpKSBjb2RlLmVyYXNlKGNvZGUuc2l6ZSgpLTEpOwogIHJldHVybiByYz09MCAm
JiBjb2RlPT0iMjAwIjsKfQpzdGF0aWMgdm9pZCBzcG9vbChjb25zdCBzdGQ6OnN0cmluZyAmcGF0
aCwgY29uc3Qgc3RkOjp2ZWN0b3I8c3RkOjpzdHJpbmc+ICZiYXRjaCkgewogIHN0ZDo6c3RyaW5n
IGRhdGE7IGZvcihzaXplX3QgaT0wO2k8YmF0Y2guc2l6ZSgpOysraSlkYXRhKz1iYXRjaFtpXSsi
XG4iOwogIGlmKCF3cml0ZV9hcHBlbmQocGF0aCxkYXRhKSkgeyBsb2dtc2coIkZBVEFMOiBjYW5u
b3Qgd3JpdGUgc3Bvb2wiKTsgZXhpdCgzKTsgfQp9CnN0YXRpYyB2b2lkIGxvYWRfc3Bvb2woY29u
c3Qgc3RkOjpzdHJpbmcgJnBhdGgsIHN0ZDo6dmVjdG9yPHN0ZDo6c3RyaW5nPiAqYnVmKSB7CiAg
c3RkOjpzdHJpbmcgZGF0YTsgaWYoIXJlYWRfZmlsZShwYXRoLCZkYXRhKSlyZXR1cm47CiAgc3Rk
Ojppc3RyaW5nc3RyZWFtIGluKGRhdGEpOyBzdGQ6OnN0cmluZyBsaW5lOyB3aGlsZShzdGQ6Omdl
dGxpbmUoaW4sbGluZSkpIGlmKCFsaW5lLmVtcHR5KCkpIGJ1Zi0+cHVzaF9iYWNrKGxpbmUpOwog
IHVubGluayhwYXRoLmNfc3RyKCkpOwp9CnN0YXRpYyB2b2lkIHNlbmRfYmF0Y2hlcyhjb25zdCBz
dGQ6OnN0cmluZyAmZW5kcG9pbnQsY29uc3Qgc3RkOjpzdHJpbmcgJm5vZGUsY29uc3Qgc3RkOjpz
dHJpbmcgJnNwb29sX3BhdGgsCiAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6OnZlY3Rvcjxz
dGQ6OnN0cmluZz4gKmJ1ZiwgYm9vbCBmbHVzaF9hbGwpIHsKICB3aGlsZSAoIWJ1Zi0+ZW1wdHko
KSAmJiAoZmx1c2hfYWxsIHx8IGJ1Zi0+c2l6ZSgpID49IE1BWF9CQVRDSCkpIHsKICAgIHNpemVf
dCBuPWJ1Zi0+c2l6ZSgpPj1NQVhfQkFUQ0g/TUFYX0JBVENIOmJ1Zi0+c2l6ZSgpOwogICAgc3Rk
Ojp2ZWN0b3I8c3RkOjpzdHJpbmc+IGJhdGNoKGJ1Zi0+YmVnaW4oKSxidWYtPmJlZ2luKCkrbik7
CiAgICBpZihwb3N0KGVuZHBvaW50LG5vZGUsYmF0Y2gpKSB7IGJ1Zi0+ZXJhc2UoYnVmLT5iZWdp
bigpLGJ1Zi0+YmVnaW4oKStuKTsgbG9nbXNnKCJmbHVzaGVkICIrbnVtYmVyX3N0cmluZyhuKSsi
IGV2ZW50cyIpOyB9CiAgICBlbHNlIHsgc3Bvb2woc3Bvb2xfcGF0aCxiYXRjaCk7IGJ1Zi0+ZXJh
c2UoYnVmLT5iZWdpbigpLGJ1Zi0+YmVnaW4oKStuKTsgbG9nbXNnKCJzcG9vbGVkICIrbnVtYmVy
X3N0cmluZyhuKSsiIGV2ZW50cyIpOyBicmVhazsgfQogIH0KfQppbnQgbWFpbihpbnQgYXJnYyxj
aGFyICoqYXJndikgewogIHN0ZDo6c3RyaW5nIGVuZHBvaW50LCBzcG9vbF9wYXRoPSIvdmFyL2xp
Yi9uZXR3b3JrdHJhY2luZy9zbmlmZi1zcG9vbC5qc29ubCI7IGludCBpOwogIGZvcihpPTE7aTxh
cmdjOysraSl7c3RkOjpzdHJpbmcgYT1hcmd2W2ldOyBpZihhPT0iLS1lbmRwb2ludCImJmkrMTxh
cmdjKWVuZHBvaW50PWFyZ3ZbKytpXTsgZWxzZSBpZihhPT0iLS1zcG9vbCImJmkrMTxhcmdjKXNw
b29sX3BhdGg9YXJndlsrK2ldOyBlbHNlIGlmKGE9PSItaCJ8fGE9PSItLWhlbHAiKXtzdGQ6OmNv
dXQ8PCJ1c2FnZTogbnQtc2hpcC1jcHAgLS1lbmRwb2ludCBVUkwgWy0tc3Bvb2wgUEFUSF1cbiI7
cmV0dXJuIDA7fSBlbHNlIHtzdGQ6OmNlcnI8PCJ1bmtub3duIGFyZzogIjw8YTw8IlxuIjtyZXR1
cm4gMjt9fQogIGlmKGVuZHBvaW50LmVtcHR5KCkpe3N0ZDo6Y2Vycjw8Ii0tZW5kcG9pbnQgcmVx
dWlyZWRcbiI7cmV0dXJuIDI7fQogIHNpZ25hbChTSUdURVJNLHN0b3Bfc2lnbmFsKTsgc2lnbmFs
KFNJR0lOVCxzdG9wX3NpZ25hbCk7CiAgY2hhciBob3N0WzI1Nl07IGdldGhvc3RuYW1lKGhvc3Qs
c2l6ZW9mKGhvc3QpKTsgaG9zdFtzaXplb2YoaG9zdCktMV09MDsKICBjb25zdCBjaGFyICpub2Rl
X2VudiA9IGdldGVudigiTlRfTk9ERV9OQU1FIik7CiAgc3RkOjpzdHJpbmcgbm9kZSA9IChub2Rl
X2VudiAmJiAqbm9kZV9lbnYpID8gbm9kZV9lbnYgOiBob3N0OwogIHN0ZDo6dmVjdG9yPHN0ZDo6
c3RyaW5nPiBidWY7IGxvYWRfc3Bvb2woc3Bvb2xfcGF0aCwmYnVmKTsgdGltZV90IGxhc3Q9dGlt
ZShOVUxMKSwgbGFzdF9yZXRyeT1sYXN0OwogIHN0ZDo6c3RyaW5nIGxpbmU7CiAgd2hpbGUocnVu
bmluZykgewogICAgZmRfc2V0IHI7IEZEX1pFUk8oJnIpOyBGRF9TRVQoMCwgJnIpOwogICAgc3Ry
dWN0IHRpbWV2YWwgdHY7IHR2LnR2X3NlYyA9IDE7IHR2LnR2X3VzZWMgPSAwOwogICAgaW50IHJj
ID0gc2VsZWN0KDEsICZyLCBOVUxMLCBOVUxMLCAmdHYpOwogICAgaWYgKHJjID4gMCAmJiBGRF9J
U1NFVCgwLCAmcikpIHsKICAgICAgaWYgKCFzdGQ6OmdldGxpbmUoc3RkOjpjaW4sIGxpbmUpKSBi
cmVhazsKICAgICAgaWYgKCFsaW5lLmVtcHR5KCkpIHsKICAgICAgICBidWYucHVzaF9iYWNrKGxp
bmUpOwogICAgICAgIGlmIChidWYuc2l6ZSgpID49IE1BWF9RVUVVRSkgewogICAgICAgICAgc2Vu
ZF9iYXRjaGVzKGVuZHBvaW50LCBub2RlLCBzcG9vbF9wYXRoLCAmYnVmLCBmYWxzZSk7CiAgICAg
ICAgfQogICAgICB9CiAgICB9CiAgICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICAgIGlmIChu
b3cgLSBsYXN0ID49IEZMVVNIX1NFQyB8fCBidWYuc2l6ZSgpID49IE1BWF9CQVRDSCkgewogICAg
ICBpZiAoIWJ1Zi5lbXB0eSgpKSBzZW5kX2JhdGNoZXMoZW5kcG9pbnQsIG5vZGUsIHNwb29sX3Bh
dGgsICZidWYsIHRydWUpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogICAgaWYgKG5vdyAtIGxh
c3RfcmV0cnkgPj0gUkVUUllfU0VDKSB7CiAgICAgIGxvYWRfc3Bvb2woc3Bvb2xfcGF0aCwgJmJ1
Zik7CiAgICAgIGxhc3RfcmV0cnkgPSBub3c7CiAgICB9CiAgfQogIHNlbmRfYmF0Y2hlcyhlbmRw
b2ludCxub2RlLHNwb29sX3BhdGgsJmJ1Zix0cnVlKTsgbG9nbXNnKCJzdG9wcGVkIik7IHJldHVy
biAwOwp9Cg==
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
I2luY2x1ZGUgPHN5cy9pb2N0bC5oPgojaW5jbHVkZSA8c3lzL3NlbGVjdC5oPgojaW5jbHVkZSA8
c3lzL3RpbWUuaD4KI2luY2x1ZGUgPHN5cy9zb2NrZXQuaD4KI2luY2x1ZGUgPHN5cy90eXBlcy5o
PgojaW5jbHVkZSA8dGltZS5oPgojaW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxsaW51eC9m
aWx0ZXIuaD4KI2luY2x1ZGUgPGxpbnV4L2lmX3BhY2tldC5oPgojaW5jbHVkZSA8bGludXgvaWZf
ZXRoZXIuaD4KI2luY2x1ZGUgPGlvc3RyZWFtPgoKI2luY2x1ZGUgPG1hcD4KI2luY2x1ZGUgPHNz
dHJlYW0+CiNpbmNsdWRlIDxzdHJpbmc+CiNpbmNsdWRlIDx2ZWN0b3I+CgpzdGF0aWMgdm9sYXRp
bGUgc2lnX2F0b21pY190IGdfcnVubmluZyA9IDE7CnN0YXRpYyB2b2lkIHN0b3Bfc2lnbmFsKGlu
dCkgeyBnX3J1bm5pbmcgPSAwOyB9CgpzdGF0aWMgY29uc3Qgc2l6ZV90IE1BWF9GTE9XUyA9IDgx
OTI7CnN0YXRpYyBjb25zdCBzaXplX3QgTUFYX1BFTkRJTkcgPSA4MTkyOwpzdGF0aWMgY29uc3Qg
c2l6ZV90IE1BWF9IRUFERVIgPSAyNjIxNDQ7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBGTE9XX1RU
TCA9IDMwMDsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIFBFTkRJTkdfVFRMID0gNTsKc3RhdGljIGNv
bnN0IHVuc2lnbmVkIEFDQ0VQVCA9IDIwNDg7CnN0YXRpYyBjb25zdCBpbnQgU09fQVRUQUNIX0ZJ
TFRFUl9PTEQgPSAyNjsKc3RhdGljIGNvbnN0IHVuc2lnbmVkIHNob3J0IEVUSF9QX0lQX0hPU1Qg
PSAweDA4MDA7CnN0YXRpYyBjb25zdCB1bnNpZ25lZCBzaG9ydCBFVEhfUF84MDIxUV9IT1NUID0g
MHg4MTAwOwoKc3RhdGljIHN0ZDo6c3RyaW5nIHRyaW0oY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsK
ICBzaXplX3QgYSA9IDAsIGIgPSBzLnNpemUoKTsKICB3aGlsZSAoYSA8IGIgJiYgaXNzcGFjZSgo
dW5zaWduZWQgY2hhcilzW2FdKSkgKythOwogIHdoaWxlIChiID4gYSAmJiBpc3NwYWNlKCh1bnNp
Z25lZCBjaGFyKXNbYiAtIDFdKSkgLS1iOwogIHJldHVybiBzLnN1YnN0cihhLCBiIC0gYSk7Cn0K
c3RhdGljIHN0ZDo6c3RyaW5nIGxvd2VyKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgc3RkOjpz
dHJpbmcgeCA9IHM7CiAgc2l6ZV90IGk7IGZvciAoaSA9IDA7IGkgPCB4LnNpemUoKTsgKytpKSB4
W2ldID0gKGNoYXIpdG9sb3dlcigodW5zaWduZWQgY2hhcil4W2ldKTsKICByZXR1cm4geDsKfQpz
dGF0aWMgc3RkOjpzdHJpbmcganNvbnEoY29uc3Qgc3RkOjpzdHJpbmcgJnMpIHsKICBzdGQ6OnN0
cmluZyB4ID0gIlwiIjsgc2l6ZV90IGk7CiAgZm9yIChpID0gMDsgaSA8IHMuc2l6ZSgpOyArK2kp
IHsKICAgIHVuc2lnbmVkIGNoYXIgYyA9ICh1bnNpZ25lZCBjaGFyKXNbaV07CiAgICBpZiAoYyA9
PSAnXFwnIHx8IGMgPT0gJyInKSB7IHggKz0gJ1xcJzsgeCArPSAoY2hhciljOyB9CiAgICBlbHNl
IGlmIChjID09ICdcbicpIHggKz0gIlxcbiI7CiAgICBlbHNlIGlmIChjID09ICdccicpIHggKz0g
IlxcciI7CiAgICBlbHNlIGlmIChjID09ICdcdCcpIHggKz0gIlxcdCI7CiAgICBlbHNlIGlmIChj
IDwgMzIpIHggKz0gJz8nOwogICAgZWxzZSB4ICs9IChjaGFyKWM7CiAgfQogIHggKz0gJyInOyBy
ZXR1cm4geDsKfQpzdGF0aWMgbG9uZyBsb25nIG5vd19tcygpIHsKICBzdHJ1Y3QgdGltZXZhbCB0
djsgZ2V0dGltZW9mZGF5KCZ0diwgTlVMTCk7CiAgcmV0dXJuIChsb25nIGxvbmcpdHYudHZfc2Vj
ICogMTAwMExMICsgdHYudHZfdXNlYyAvIDEwMDA7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIG51bShs
b25nIHYpIHsgc3RkOjpvc3RyaW5nc3RyZWFtIG87IG8gPDwgdjsgcmV0dXJuIG8uc3RyKCk7IH0K
c3RhdGljIGJvb2wgdmFsaWRfcG9ydCh1bnNpZ25lZCBwKSB7IHJldHVybiBwID4gMCAmJiBwIDw9
IDY1NTM1OyB9CnN0YXRpYyBib29sIGhhc19tZXRob2QoY29uc3Qgc3RkOjpzdHJpbmcgJm0pIHsK
ICByZXR1cm4gbSA9PSAiR0VUIiB8fCBtID09ICJQT1NUIiB8fCBtID09ICJQVVQiIHx8IG0gPT0g
IkRFTEVURSIgfHwKICAgICAgICAgbSA9PSAiUEFUQ0giIHx8IG0gPT0gIkhFQUQiIHx8IG0gPT0g
Ik9QVElPTlMiOwp9CnN0YXRpYyBzdGQ6OnN0cmluZyBob3N0X25hbWUoKSB7CiAgY2hhciBiWzI1
Nl07IGlmIChnZXRob3N0bmFtZShiLCBzaXplb2YoYikgLSAxKSAhPSAwKSByZXR1cm4gInVua25v
d24tbm9kZSI7CiAgYltzaXplb2YoYikgLSAxXSA9IDA7IGNoYXIgKnAgPSBzdHJjaHIoYiwgJy4n
KTsgaWYgKHApICpwID0gMDsgcmV0dXJuIGI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIGI2NGRlY29k
ZV91c2VyKGNvbnN0IHN0ZDo6c3RyaW5nICZ2KSB7CiAgc3RkOjpzdHJpbmcgaW4gPSB0cmltKHYp
LCBvdXQ7IGludCB2YWwgPSAwLCBiaXRzID0gLTg7IHNpemVfdCBpOwogIGZvciAoaSA9IDA7IGkg
PCBpbi5zaXplKCk7ICsraSkgewogICAgdW5zaWduZWQgY2hhciBjID0gKHVuc2lnbmVkIGNoYXIp
aW5baV07IGludCBkID0gLTE7CiAgICBpZiAoYyA+PSAnQScgJiYgYyA8PSAnWicpIGQgPSBjIC0g
J0EnOwogICAgZWxzZSBpZiAoYyA+PSAnYScgJiYgYyA8PSAneicpIGQgPSBjIC0gJ2EnICsgMjY7
CiAgICBlbHNlIGlmIChjID49ICcwJyAmJiBjIDw9ICc5JykgZCA9IGMgLSAnMCcgKyA1MjsKICAg
IGVsc2UgaWYgKGMgPT0gJysnKSBkID0gNjI7CiAgICBlbHNlIGlmIChjID09ICcvJykgZCA9IDYz
OwogICAgZWxzZSBpZiAoYyA9PSAnPScpIGJyZWFrOwogICAgaWYgKGQgPCAwKSBjb250aW51ZTsK
ICAgIHZhbCA9ICh2YWwgPDwgNikgKyBkOwogICAgYml0cyArPSA2OwogICAgaWYgKGJpdHMgPj0g
MCkgewogICAgICBvdXQgKz0gKGNoYXIpKCh2YWwgPj4gYml0cykgJiAweGZmKTsKICAgICAgYml0
cyAtPSA4OwogICAgICBpZiAob3V0LnNpemUoKSA+IDUxMikgcmV0dXJuICIiOwogICAgfQogIH0K
ICBzaXplX3QgcCA9IG91dC5maW5kKCc6Jyk7CiAgaWYgKHAgPT0gc3RkOjpzdHJpbmc6Om5wb3Mp
IHJldHVybiAiIjsKICByZXR1cm4gb3V0LnN1YnN0cigwLCBwID4gNjQgPyA2NCA6IHApOwp9CnN0
YXRpYyBzdGQ6OnN0cmluZyBoZWFkZXJfdmFsdWUoY29uc3Qgc3RkOjpzdHJpbmcgJmhlYWQsIGNv
bnN0IHN0ZDo6c3RyaW5nICZ3YW50KSB7CiAgc3RkOjppc3RyaW5nc3RyZWFtIGluKGhlYWQpOyBz
dGQ6OnN0cmluZyBsaW5lLCB3ID0gbG93ZXIod2FudCk7CiAgd2hpbGUgKHN0ZDo6Z2V0bGluZShp
biwgbGluZSkpIHsKICAgIGlmICghbGluZS5lbXB0eSgpICYmIGxpbmVbbGluZS5zaXplKCkgLSAx
XSA9PSAnXHInKSBsaW5lLmVyYXNlKGxpbmUuc2l6ZSgpIC0gMSk7CiAgICBzaXplX3QgcCA9IGxp
bmUuZmluZCgnOicpOyBpZiAocCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgY29udGludWU7CiAgICBp
ZiAobG93ZXIodHJpbShsaW5lLnN1YnN0cigwLCBwKSkpID09IHcpIHJldHVybiB0cmltKGxpbmUu
c3Vic3RyKHAgKyAxKSk7CiAgfQogIHJldHVybiAiIjsKfQpzdGF0aWMgc3RkOjpzdHJpbmcgdHJh
Y2VfaWRfZnJvbV9wYXJlbnQoY29uc3Qgc3RkOjpzdHJpbmcgJnRwKSB7CiAgc3RkOjpzdHJpbmcg
eCA9IHRyaW0odHApOwogIGlmICh4LnNpemUoKSA9PSA1NSAmJiB4WzJdID09ICctJyAmJiB4WzM1
XSA9PSAnLScgJiYgeFs1Ml0gPT0gJy0nKSByZXR1cm4gbG93ZXIoeC5zdWJzdHIoMywgMzIpKTsK
ICByZXR1cm4gIiI7Cn0Kc3RhdGljIHN0ZDo6c3RyaW5nIG1ha2VfdHJhY2VwYXJlbnQoc3RkOjpz
dHJpbmcgKnRpZCkgewogIHVuc2lnbmVkIGNoYXIgYlsyNF07IHNpemVfdCBpOyBGSUxFICpmID0g
Zm9wZW4oIi9kZXYvdXJhbmRvbSIsICJyYiIpOwogIGlmIChmKSB7IHNpemVfdCBnb3QgPSBmcmVh
ZChiLCAxLCBzaXplb2YoYiksIGYpOyAodm9pZClnb3Q7IGZjbG9zZShmKTsgfQogIGVsc2UgeyB1
bnNpZ25lZCBsb25nIHQgPSAodW5zaWduZWQgbG9uZyl0aW1lKE5VTEwpIF4gKHVuc2lnbmVkIGxv
bmcpZ2V0cGlkKCk7IGZvciAoaSA9IDA7IGkgPCBzaXplb2YoYik7ICsraSkgYltpXSA9ICh1bnNp
Z25lZCBjaGFyKSh0ID0gdCAqIDExMDM1MTUyNDVVTCArIDEyMzQ1VUwpOyB9CiAgc3RhdGljIGNv
bnN0IGNoYXIgKmhleCA9ICIwMTIzNDU2Nzg5YWJjZGVmIjsgc3RkOjpzdHJpbmcgYSwgYzsKICBm
b3IgKGkgPSAwOyBpIDwgMTY7ICsraSkgeyBhICs9IGhleFtiW2ldID4+IDRdOyBhICs9IGhleFti
W2ldICYgMTVdOyB9CiAgZm9yIChpID0gMTY7IGkgPCAyNDsgKytpKSB7IGMgKz0gaGV4W2JbaV0g
Pj4gNF07IGMgKz0gaGV4W2JbaV0gJiAxNV07IH0KICAqdGlkID0gYTsgcmV0dXJuICIwMC0iICsg
YSArICItIiArIGMgKyAiLTAxIjsKfQoKc3RydWN0IEV2ZW50IHsKICBsb25nIHRzOyBzdGQ6OnN0
cmluZyBob3N0LCBzcmMsIHNlcnZpY2UsIG1ldGhvZCwgcGF0aCwgdXNlciwgc2NoZW1lLCBwcm9i
ZTsKICBzdGQ6OnN0cmluZyBob3N0X2hkciwgdXNlcl9hZ2VudCwgeGZmLCBjYWxsZXIsIGRzdF9p
cCwgdHJhY2VwYXJlbnQsIHRyYWNlX2lkOwogIHVuc2lnbmVkIGNhbGxlcl9wb3J0LCBkc3RfcG9y
dCwgcmVxX2J5dGVzLCByZXNwX2J5dGVzOyBpbnQgc3RhdHVzOyBsb25nIGR1cmF0aW9uX21zOwog
IGJvb2wgaGFzX3N0YXR1cywgaGFzX2R1cmF0aW9uLCBoYXNfcmVzcDsKICBFdmVudCgpIDogdHMo
MCksIGNhbGxlcl9wb3J0KDApLCBkc3RfcG9ydCgwKSwgcmVxX2J5dGVzKDApLCByZXNwX2J5dGVz
KDApLCBzdGF0dXMoMCksIGR1cmF0aW9uX21zKDApLCBoYXNfc3RhdHVzKGZhbHNlKSwgaGFzX2R1
cmF0aW9uKGZhbHNlKSwgaGFzX3Jlc3AoZmFsc2UpIHt9Cn07CnN0cnVjdCBGbG93IHsgc3RkOjpz
dHJpbmcgYnVmOyB0aW1lX3QgdG91Y2hlZDsgRmxvdygpIDogdG91Y2hlZCh0aW1lKE5VTEwpKSB7
fSB9OwpzdHJ1Y3QgUGVuZGluZyB7CiAgRXZlbnQgZXY7CiAgbG9uZyBsb25nIHN0YXJ0ZWRfbXM7
CiAgUGVuZGluZygpIDogc3RhcnRlZF9tcygwKSB7fQogIFBlbmRpbmcoY29uc3QgRXZlbnQgJmUs
IGxvbmcgbG9uZyB0KSA6IGV2KGUpLCBzdGFydGVkX21zKHQpIHt9Cn07CnN0cnVjdCBQYWNrZXRL
ZXkgeyBzdGQ6OnN0cmluZyBzcmM7IHVuc2lnbmVkIHNwb3J0OyBzdGQ6OnN0cmluZyBkc3Q7IHVu
c2lnbmVkIGRwb3J0OyBib29sIG9wZXJhdG9yPChjb25zdCBQYWNrZXRLZXkgJngpIGNvbnN0IHsg
cmV0dXJuIHNyYyAhPSB4LnNyYyA/IHNyYyA8IHguc3JjIDogc3BvcnQgIT0geC5zcG9ydCA/IHNw
b3J0IDwgeC5zcG9ydCA6IGRzdCAhPSB4LmRzdCA/IGRzdCA8IHguZHN0IDogZHBvcnQgPCB4LmRw
b3J0OyB9IH07CgpzdGF0aWMgc3RkOjpzdHJpbmcga2V5X3N0cmluZyhjb25zdCBzdGQ6OnN0cmlu
ZyAmYSwgdW5zaWduZWQgYXAsIGNvbnN0IHN0ZDo6c3RyaW5nICZiLCB1bnNpZ25lZCBicCkgeyBy
ZXR1cm4gYSArICI6IiArIG51bShhcCkgKyAiLT4iICsgYiArICI6IiArIG51bShicCk7IH0Kc3Rh
dGljIHZvaWQgbG9nbXNnKGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7IGZwcmludGYoc3RkZXJyLCAi
bnQtc25pZmYtY3BwOiAlc1xuIiwgcy5jX3N0cigpKTsgZmZsdXNoKHN0ZGVycik7IH0KCnN0YXRp
YyBib29sIHBhcnNlX3JlcXVlc3QoY29uc3Qgc3RkOjpzdHJpbmcgJmhlYWQsIEV2ZW50ICplKSB7
CiAgc3RkOjpzdHJpbmcgZmlyc3Q7IHN0ZDo6aXN0cmluZ3N0cmVhbSBpbihoZWFkKTsgaWYgKCFz
dGQ6OmdldGxpbmUoaW4sIGZpcnN0KSkgcmV0dXJuIGZhbHNlOwogIHN0ZDo6aXN0cmluZ3N0cmVh
bSBwKHRyaW0oZmlyc3QpKTsgaWYgKCEocCA+PiBlLT5tZXRob2QgPj4gZS0+cGF0aCkpIHJldHVy
biBmYWxzZTsKICBpZiAoIWhhc19tZXRob2QoZS0+bWV0aG9kKSkgcmV0dXJuIGZhbHNlOwogIHNp
emVfdCBxID0gZS0+cGF0aC5maW5kKCc/Jyk7IGlmIChxICE9IHN0ZDo6c3RyaW5nOjpucG9zKSBl
LT5wYXRoLmVyYXNlKHEpOwogIGlmIChlLT5wYXRoLnNpemUoKSA+IDEyMCkgZS0+cGF0aC5lcmFz
ZSgxMjApOwogIHN0ZDo6c3RyaW5nIGF1dGggPSBoZWFkZXJfdmFsdWUoaGVhZCwgImF1dGhvcml6
YXRpb24iKTsKICBpZiAobG93ZXIoYXV0aCkuZmluZCgiYmFzaWMgIikgPT0gMCkgeyBlLT51c2Vy
ID0gYjY0ZGVjb2RlX3VzZXIoYXV0aC5zdWJzdHIoNikpOyBlLT5zY2hlbWUgPSAiYmFzaWMiOyB9
CiAgZWxzZSBpZiAobG93ZXIoYXV0aCkuZmluZCgiYmVhcmVyICIpID09IDApIGUtPnNjaGVtZSA9
ICJiZWFyZXIiOwogIHN0ZDo6c3RyaW5nIHggPSBoZWFkZXJfdmFsdWUoaGVhZCwgInRyYWNlcGFy
ZW50Iik7IGUtPnRyYWNlX2lkID0gdHJhY2VfaWRfZnJvbV9wYXJlbnQoeCk7IGUtPnRyYWNlcGFy
ZW50ID0gZS0+dHJhY2VfaWQuZW1wdHkoKSA/IG1ha2VfdHJhY2VwYXJlbnQoJmUtPnRyYWNlX2lk
KSA6IHg7CiAgZS0+aG9zdF9oZHIgPSBoZWFkZXJfdmFsdWUoaGVhZCwgImhvc3QiKTsKICBlLT51
c2VyX2FnZW50ID0gaGVhZGVyX3ZhbHVlKGhlYWQsICJ1c2VyLWFnZW50Iik7CiAgZS0+eGZmID0g
aGVhZGVyX3ZhbHVlKGhlYWQsICJ4LWZvcndhcmRlZC1mb3IiKTsKICBpZiAoZS0+dXNlci5lbXB0
eSgpKSB7CiAgICBlLT51c2VyID0gIi1hbm9ueW1vdXMtIjsKICB9CiAgaWYgKGUtPnNjaGVtZS5l
bXB0eSgpKSB7CiAgICBlLT5zY2hlbWUgPSAibm9uZSI7CiAgfQogIHJldHVybiB0cnVlOwp9CnN0
YXRpYyBib29sIHBhcnNlX3Jlc3BvbnNlKGNvbnN0IHN0ZDo6c3RyaW5nICZwYXlsb2FkLCBpbnQg
KnN0YXR1cywgdW5zaWduZWQgKmNsZW4pIHsKICBzaXplX3QgZW5kID0gcGF5bG9hZC5maW5kKCJc
clxuXHJcbiIpOwogIHN0ZDo6c3RyaW5nIGggPSBwYXlsb2FkLnN1YnN0cigwLCBlbmQgPT0gc3Rk
OjpzdHJpbmc6Om5wb3MgPyBwYXlsb2FkLnNpemUoKSA6IGVuZCk7CiAgaWYgKGguc2l6ZSgpID4g
TUFYX0hFQURFUikgcmV0dXJuIGZhbHNlOwogIHN0ZDo6aXN0cmluZ3N0cmVhbSBpbihoKTsKICBz
dGQ6OnN0cmluZyBmaXJzdDsKICBpZiAoIXN0ZDo6Z2V0bGluZShpbiwgZmlyc3QpKSByZXR1cm4g
ZmFsc2U7CiAgc3RkOjppc3RyaW5nc3RyZWFtIHAoZmlyc3QpOwogIHN0ZDo6c3RyaW5nIHByb3Rv
OwogIGlmICghKHAgPj4gcHJvdG8gPj4gKnN0YXR1cykpIHJldHVybiBmYWxzZTsKICBpZiAocHJv
dG8uZmluZCgiSFRUUC8iKSAhPSAwIHx8ICpzdGF0dXMgPCAxMDAgfHwgKnN0YXR1cyA+IDU5OSkg
cmV0dXJuIGZhbHNlOwogICpjbGVuID0gMDsgc3RkOjpzdHJpbmcgbGluZTsKICB3aGlsZSAoc3Rk
OjpnZXRsaW5lKGluLCBsaW5lKSkgeyBzaXplX3QgeCA9IGxpbmUuZmluZCgnOicpOyBpZiAoeCAh
PSBzdGQ6OnN0cmluZzo6bnBvcyAmJiBsb3dlcih0cmltKGxpbmUuc3Vic3RyKDAsIHgpKSkgPT0g
ImNvbnRlbnQtbGVuZ3RoIikgeyBsb25nIG4gPSBhdG9sKHRyaW0obGluZS5zdWJzdHIoeCArIDEp
KS5jX3N0cigpKTsgaWYgKG4gPj0gMCAmJiBuIDw9IDB4N2ZmZmZmZmYpICpjbGVuID0gKHVuc2ln
bmVkKW47IH0gfQogIHJldHVybiB0cnVlOwp9CnN0YXRpYyB2b2lkIGVtaXRfZXZlbnQoY29uc3Qg
RXZlbnQgJmUpIHsKICBzdGQ6OmNvdXQgPDwgIntcInRzXCI6IiA8PCBlLnRzIDw8ICIsXCJob3N0
XCI6IiA8PCBqc29ucShlLmhvc3QpIDw8ICIsXCJzcmNcIjpcInBjYXBcIixcInNlcnZpY2VcIjoi
IDw8IGpzb25xKGUuc2VydmljZSkKICAgICAgICAgICAgPDwgIixcIm1ldGhvZFwiOiIgPDwganNv
bnEoZS5tZXRob2QpIDw8ICIsXCJwYXRoXCI6IiA8PCBqc29ucShlLnBhdGgpIDw8ICIsXCJ1c2Vy
XCI6IiA8PCBqc29ucShlLnVzZXIpCiAgICAgICAgICAgIDw8ICIsXCJzY2hlbWVcIjoiIDw8IGpz
b25xKGUuc2NoZW1lKSA8PCAiLFwic291cmNlX3Byb2JlXCI6XCJwY2FwLWh0dHAtY3BwXCIsXCJo
b3N0X2hkclwiOiIgPDwganNvbnEoZS5ob3N0X2hkcikKICAgICAgICAgICAgPDwgIixcInVzZXJf
YWdlbnRcIjoiIDw8IGpzb25xKGUudXNlcl9hZ2VudCkgPDwgIixcInhfZm9yd2FyZGVkX2Zvclwi
OiIgPDwganNvbnEoZS54ZmYpCiAgICAgICAgICAgIDw8ICIsXCJjYWxsZXJcIjoiIDw8IGpzb25x
KGUuY2FsbGVyKSA8PCAiLFwiY2FsbGVyX3BvcnRcIjoiIDw8IGUuY2FsbGVyX3BvcnQgPDwgIixc
ImRzdF9pcFwiOiIgPDwganNvbnEoZS5kc3RfaXApCiAgICAgICAgICAgIDw8ICIsXCJkc3RfcG9y
dFwiOiIgPDwgZS5kc3RfcG9ydCA8PCAiLFwidHJhY2VwYXJlbnRcIjoiIDw8IGpzb25xKGUudHJh
Y2VwYXJlbnQpIDw8ICIsXCJ0cmFjZV9pZFwiOiIgPDwganNvbnEoZS50cmFjZV9pZCkKICAgICAg
ICAgICAgPDwgIixcInNlcnZpY2VfaWRcIjpudWxsLFwibW9kdWxlX2lkXCI6XCJwY2FwLWh0dHAt
Y3BwXCIsXCJyZXFfYnl0ZXNcIjoiIDw8IGUucmVxX2J5dGVzOwogIGlmIChlLmhhc19zdGF0dXMp
IHN0ZDo6Y291dCA8PCAiLFwic3RhdHVzXCI6IiA8PCBlLnN0YXR1czsgZWxzZSBzdGQ6OmNvdXQg
PDwgIixcInN0YXR1c1wiOm51bGwiOwogIGlmIChlLmhhc19kdXJhdGlvbikgc3RkOjpjb3V0IDw8
ICIsXCJkdXJhdGlvbl9tc1wiOiIgPDwgZS5kdXJhdGlvbl9tczsgZWxzZSBzdGQ6OmNvdXQgPDwg
IixcImR1cmF0aW9uX21zXCI6bnVsbCI7CiAgaWYgKGUuaGFzX3Jlc3ApIHN0ZDo6Y291dCA8PCAi
LFwicmVzcF9ieXRlc1wiOiIgPDwgZS5yZXNwX2J5dGVzOyBlbHNlIHN0ZDo6Y291dCA8PCAiLFwi
cmVzcF9ieXRlc1wiOm51bGwiOwogIHN0ZDo6Y291dCA8PCAifVxuIjsgc3RkOjpjb3V0LmZsdXNo
KCk7Cn0KCnN0YXRpYyB2b2lkIGZsdXNoX29sZGVzdChzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID4gJnBlbmRpbmcpIHsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6
dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIGJlc3QgPSBwZW5kaW5nLmVuZCgpOyBsb25nIGxv
bmcgYnQgPSAwOyBib29sIGZvdW5kID0gZmFsc2U7CiAgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6
OnZlY3RvcjxQZW5kaW5nPiA+OjppdGVyYXRvciBpOwogIGZvciAoaSA9IHBlbmRpbmcuYmVnaW4o
KTsgaSAhPSBwZW5kaW5nLmVuZCgpOyArK2kpIGlmICghaS0+c2Vjb25kLmVtcHR5KCkgJiYgKCFm
b3VuZCB8fCBpLT5zZWNvbmRbMF0uc3RhcnRlZF9tcyA8IGJ0KSkgeyBiZXN0ID0gaTsgYnQgPSBp
LT5zZWNvbmRbMF0uc3RhcnRlZF9tczsgZm91bmQgPSB0cnVlOyB9CiAgaWYgKGZvdW5kKSB7IGVt
aXRfZXZlbnQoYmVzdC0+c2Vjb25kWzBdLmV2KTsgYmVzdC0+c2Vjb25kLmVyYXNlKGJlc3QtPnNl
Y29uZC5iZWdpbigpKTsgaWYgKGJlc3QtPnNlY29uZC5lbXB0eSgpKSBwZW5kaW5nLmVyYXNlKGJl
c3QpOyB9Cn0Kc3RhdGljIHZvaWQgc3dlZXAoc3RkOjptYXA8c3RkOjpzdHJpbmcsIEZsb3c+ICZm
bG93cywgc3RkOjptYXA8UGFja2V0S2V5LCBzdGQ6OnZlY3RvcjxQZW5kaW5nPiA+ICZwZW5kaW5n
LCB0aW1lX3Qgbm93KSB7CiAgc3RkOjptYXA8c3RkOjpzdHJpbmcsIEZsb3c+OjppdGVyYXRvciBm
LCBmbjsKICBmb3IgKGYgPSBmbG93cy5iZWdpbigpOyBmICE9IGZsb3dzLmVuZCgpOykgewogICAg
Zm4gPSBmOyArK2ZuOwogICAgaWYgKCh1bnNpZ25lZCkobm93IC0gZi0+c2Vjb25kLnRvdWNoZWQp
ID4gRkxPV19UVEwpIGZsb3dzLmVyYXNlKGYpOwogICAgZiA9IGZuOwogIH0KICBsb25nIGxvbmcg
Y3VycmVudF9tcyA9IChsb25nIGxvbmcpbm93ICogMTAwMExMOwogIHN0ZDo6bWFwPFBhY2tldEtl
eSwgc3RkOjp2ZWN0b3I8UGVuZGluZz4gPjo6aXRlcmF0b3IgcCwgcG47CiAgZm9yIChwID0gcGVu
ZGluZy5iZWdpbigpOyBwICE9IHBlbmRpbmcuZW5kKCk7KSB7CiAgICBwbiA9IHA7ICsrcG47CiAg
ICBzaXplX3QgaSA9IDA7CiAgICB3aGlsZSAoaSA8IHAtPnNlY29uZC5zaXplKCkpIHsKICAgICAg
aWYgKGN1cnJlbnRfbXMgLSBwLT5zZWNvbmRbaV0uc3RhcnRlZF9tcyA+IChsb25nIGxvbmcpUEVO
RElOR19UVEwgKiAxMDAwTEwpIHsKICAgICAgICBlbWl0X2V2ZW50KHAtPnNlY29uZFtpXS5ldik7
CiAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNlY29uZC5iZWdpbigpICsgaSk7CiAgICAgIH0g
ZWxzZSB7CiAgICAgICAgKytpOwogICAgICB9CiAgICB9CiAgICBpZiAocC0+c2Vjb25kLmVtcHR5
KCkpIHBlbmRpbmcuZXJhc2UocCk7CiAgICBwID0gcG47CiAgfQp9CnN0YXRpYyBzaXplX3QgZmlu
ZF9odHRwX3N0YXJ0KGNvbnN0IHN0ZDo6c3RyaW5nICZzKSB7CiAgY29uc3QgY2hhciAqbVtdID0g
eyAiR0VUICIsICJQT1NUICIsICJQVVQgIiwgIkRFTEVURSAiLCAiUEFUQ0ggIiwgIkhFQUQgIiwg
Ik9QVElPTlMgIiB9OwogIHNpemVfdCBiZXN0ID0gc3RkOjpzdHJpbmc6Om5wb3M7CiAgZm9yIChz
aXplX3QgaSA9IDA7IGkgPCA3OyArK2kpIHsKICAgIHNpemVfdCBwb3MgPSBzLmZpbmQobVtpXSk7
CiAgICBpZiAocG9zICE9IHN0ZDo6c3RyaW5nOjpucG9zICYmIChiZXN0ID09IHN0ZDo6c3RyaW5n
OjpucG9zIHx8IHBvcyA8IGJlc3QpKSBiZXN0ID0gcG9zOwogIH0KICByZXR1cm4gYmVzdDsKfQoK
c3RhdGljIGJvb2wgaGFuZGxlX3BhY2tldChjb25zdCB1bnNpZ25lZCBjaGFyICpidWYsIHNpemVf
dCBuLCBjb25zdCBzdGQ6OnN0cmluZyAmbm9kZSwgY29uc3Qgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+
ICZwb3J0cywKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGQ6Om1hcDxzdGQ6OnN0cmluZywg
Rmxvdz4gJmZsb3dzLCBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID4g
JnBlbmRpbmcpIHsKICBpZiAobiA8IDM0KSByZXR1cm4gZmFsc2U7CiAgc2l6ZV90IG9mZiA9IDE0
OwogIHVuc2lnbmVkIHNob3J0IGV0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShi
dWYgKyAxMikpOwogIGlmIChldCA9PSBFVEhfUF84MDIxUSkgeyBpZiAobiA8IDM4KSByZXR1cm4g
ZmFsc2U7IGV0ID0gbnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyAxNikpOyBv
ZmYgPSAxODsgfQogIGlmIChldCAhPSBFVEhfUF9JUCB8fCBuIDwgb2ZmICsgMjApIHJldHVybiBm
YWxzZTsKICB1bnNpZ25lZCBjaGFyIGlobCA9ICh1bnNpZ25lZCBjaGFyKShidWZbb2ZmXSAmIDE1
KSAqIDQ7CiAgaWYgKChidWZbb2ZmXSA+PiA0KSAhPSA0IHx8IGJ1ZltvZmYgKyA5XSAhPSA2IHx8
IG4gPCBvZmYgKyBpaGwgKyAyMCkgcmV0dXJuIGZhbHNlOwogIGNoYXIgYVtJTkVUX0FERFJTVFJM
RU5dLCBiW0lORVRfQUREUlNUUkxFTl07IGluZXRfbnRvcChBRl9JTkVULCBidWYgKyBvZmYgKyAx
MiwgYSwgc2l6ZW9mKGEpKTsgaW5ldF9udG9wKEFGX0lORVQsIGJ1ZiArIG9mZiArIDE2LCBiLCBz
aXplb2YoYikpOwogIHNpemVfdCB0byA9IG9mZiArIGlobDsgdW5zaWduZWQgc3BvcnQgPSBudG9o
cygqKGNvbnN0IHVuc2lnbmVkIHNob3J0ICopKGJ1ZiArIHRvKSk7IHVuc2lnbmVkIGRwb3J0ID0g
bnRvaHMoKihjb25zdCB1bnNpZ25lZCBzaG9ydCAqKShidWYgKyB0byArIDIpKTsgdW5zaWduZWQg
ZG9mZiA9IChidWZbdG8gKyAxMl0gPj4gNCkgKiA0OyBpZiAobiA8IHRvICsgZG9mZikgcmV0dXJu
IGZhbHNlOyBjb25zdCBjaGFyICpwYXlsb2FkID0gKGNvbnN0IGNoYXIgKikoYnVmICsgdG8gKyBk
b2ZmKTsgc2l6ZV90IHBsZW4gPSBuIC0gdG8gLSBkb2ZmOyBpZiAoIXBsZW4pIHJldHVybiBmYWxz
ZTsKICB0aW1lX3Qgbm93ID0gdGltZShOVUxMKTsKICBib29sIGRzdF9tb24gPSBmYWxzZSwgc3Jj
X21vbiA9IGZhbHNlOwogIHNpemVfdCBqOwogIGZvciAoaiA9IDA7IGogPCBwb3J0cy5zaXplKCk7
ICsraikgewogICAgaWYgKGRwb3J0ID09IHBvcnRzW2pdKSBkc3RfbW9uID0gdHJ1ZTsKICAgIGlm
IChzcG9ydCA9PSBwb3J0c1tqXSkgc3JjX21vbiA9IHRydWU7CiAgfQogIGlmIChzcmNfbW9uICYm
ICFkc3RfbW9uICYmIHBsZW4gPj0gNSkgewogICAgc3RkOjpzdHJpbmcgc19wYXkocGF5bG9hZCwg
cGxlbik7CiAgICBzaXplX3QgaHBvcyA9IHNfcGF5LmZpbmQoIkhUVFAvIik7CiAgICBpZiAoaHBv
cyAhPSBzdGQ6OnN0cmluZzo6bnBvcykgewogICAgICBQYWNrZXRLZXkgazsKICAgICAgay5zcmMg
PSBhOyBrLnNwb3J0ID0gc3BvcnQ7IGsuZHN0ID0gYjsgay5kcG9ydCA9IGRwb3J0OwogICAgICBz
dGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBlbmRpbmc+ID46Oml0ZXJhdG9yIHAgPSBw
ZW5kaW5nLmZpbmQoayk7CiAgICAgIGlmIChwICE9IHBlbmRpbmcuZW5kKCkgJiYgIXAtPnNlY29u
ZC5lbXB0eSgpKSB7CiAgICAgICAgaW50IHN0OyB1bnNpZ25lZCBjbDsKICAgICAgICBpZiAocGFy
c2VfcmVzcG9uc2Uoc19wYXkuc3Vic3RyKGhwb3MpLCAmc3QsICZjbCkpIHsKICAgICAgICAgIEV2
ZW50IGUgPSBwLT5zZWNvbmRbMF0uZXY7CiAgICAgICAgICBlLnN0YXR1cyA9IHN0OyBlLmhhc19z
dGF0dXMgPSB0cnVlOwogICAgICAgICAgZS5kdXJhdGlvbl9tcyA9IChsb25nKShub3dfbXMoKSAt
IHAtPnNlY29uZFswXS5zdGFydGVkX21zKTsKICAgICAgICAgIGlmIChlLmR1cmF0aW9uX21zIDwg
MCkgZS5kdXJhdGlvbl9tcyA9IDA7CiAgICAgICAgICBlLmhhc19kdXJhdGlvbiA9IHRydWU7CiAg
ICAgICAgICBpZiAoY2wpIHsgZS5yZXNwX2J5dGVzID0gY2w7IGUuaGFzX3Jlc3AgPSB0cnVlOyB9
CiAgICAgICAgICBlbWl0X2V2ZW50KGUpOwogICAgICAgICAgcC0+c2Vjb25kLmVyYXNlKHAtPnNl
Y29uZC5iZWdpbigpKTsKICAgICAgICAgIGlmIChwLT5zZWNvbmQuZW1wdHkoKSkgcGVuZGluZy5l
cmFzZShwKTsKICAgICAgICB9CiAgICAgIH0KICAgIH0KICAgIHJldHVybiB0cnVlOwogIH0KICBp
ZiAoIWRzdF9tb24pIHJldHVybiBmYWxzZTsKICBzdGQ6OnN0cmluZyBmayA9IGtleV9zdHJpbmco
YSwgc3BvcnQsIGIsIGRwb3J0KTsKICBpZiAoZmxvd3MuZmluZChmaykgPT0gZmxvd3MuZW5kKCkg
JiYgZmxvd3Muc2l6ZSgpID49IE1BWF9GTE9XUykgewogICAgdGltZV90IG9sZGVzdF90ID0gbm93
ICsgMTsKICAgIHN0ZDo6bWFwPHN0ZDo6c3RyaW5nLCBGbG93Pjo6aXRlcmF0b3Igb2xkZXN0X2l0
ID0gZmxvd3MuYmVnaW4oKTsKICAgIGZvciAoc3RkOjptYXA8c3RkOjpzdHJpbmcsIEZsb3c+Ojpp
dGVyYXRvciBmaSA9IGZsb3dzLmJlZ2luKCk7IGZpICE9IGZsb3dzLmVuZCgpOyArK2ZpKSB7CiAg
ICAgIGlmIChmaS0+c2Vjb25kLnRvdWNoZWQgPCBvbGRlc3RfdCkgewogICAgICAgIG9sZGVzdF90
ID0gZmktPnNlY29uZC50b3VjaGVkOwogICAgICAgIG9sZGVzdF9pdCA9IGZpOwogICAgICB9CiAg
ICB9CiAgICBpZiAob2xkZXN0X2l0ICE9IGZsb3dzLmVuZCgpKSBmbG93cy5lcmFzZShvbGRlc3Rf
aXQpOwogIH0KICBGbG93ICZmbCA9IGZsb3dzW2ZrXTsgZmwudG91Y2hlZCA9IG5vdzsgZmwuYnVm
LmFwcGVuZChwYXlsb2FkLCBwbGVuKTsKICBpZiAoZmwuYnVmLnNpemUoKSA+IE1BWF9IRUFERVIp
IHsgZmxvd3MuZXJhc2UoZmspOyByZXR1cm4gZmFsc2U7IH0KICB3aGlsZSAodHJ1ZSkgewogICAg
c2l6ZV90IHN0YXJ0ID0gZmluZF9odHRwX3N0YXJ0KGZsLmJ1Zik7CiAgICBpZiAoc3RhcnQgPT0g
c3RkOjpzdHJpbmc6Om5wb3MpIHsgZmwuYnVmLmNsZWFyKCk7IGJyZWFrOyB9CiAgICBpZiAoc3Rh
cnQgPiAwKSBmbC5idWYuZXJhc2UoMCwgc3RhcnQpOwogICAgc2l6ZV90IGVuZCA9IGZsLmJ1Zi5m
aW5kKCJcclxuXHJcbiIpOwogICAgaWYgKGVuZCA9PSBzdGQ6OnN0cmluZzo6bnBvcykgYnJlYWs7
CiAgICBFdmVudCBlOyBlLnRzID0gbm93OyBlLmhvc3QgPSBub2RlOyBlLnNlcnZpY2UgPSAicG9y
dDoiICsgbnVtKGRwb3J0KTsgZS5jYWxsZXIgPSBhOyBlLmNhbGxlcl9wb3J0ID0gc3BvcnQ7IGUu
ZHN0X2lwID0gYjsgZS5kc3RfcG9ydCA9IGRwb3J0OyBlLnJlcV9ieXRlcyA9ICh1bnNpZ25lZCko
ZW5kICsgNCk7CiAgICBpZiAoIXBhcnNlX3JlcXVlc3QoZmwuYnVmLnN1YnN0cigwLCBlbmQpLCAm
ZSkpIHsgZmwuYnVmLmVyYXNlKDAsIGVuZCArIDQpOyBjb250aW51ZTsgfQogICAgZmwuYnVmLmVy
YXNlKDAsIGVuZCArIDQpOwogICAgUGFja2V0S2V5IHJrOyByay5zcmMgPSBiOyByay5zcG9ydCA9
IGRwb3J0OyByay5kc3QgPSBhOyByay5kcG9ydCA9IHNwb3J0OwogICAgaWYgKHBlbmRpbmcuc2l6
ZSgpID49IE1BWF9QRU5ESU5HKSBmbHVzaF9vbGRlc3QocGVuZGluZyk7CiAgICBwZW5kaW5nW3Jr
XS5wdXNoX2JhY2soUGVuZGluZyhlLCBub3dfbXMoKSkpOwogIH0KICByZXR1cm4gdHJ1ZTsKfQoK
c3RhdGljIGJvb2wgYXR0YWNoX2JwZihpbnQgZmQsIGNvbnN0IHN0ZDo6dmVjdG9yPHVuc2lnbmVk
PiAmcG9ydHMpIHsKICBpZiAocG9ydHMuZW1wdHkoKSkgcmV0dXJuIGZhbHNlOwogIHN0ZDo6dmVj
dG9yPHN0cnVjdCBzb2NrX2ZpbHRlcj4gZjsgc2l6ZV90IGk7CiAgLyogRHVhbC1wYXRoIGNCUEY6
IFBhdGggQSAoc3RhbmRhcmQgSVB2NCkgYW5kIFBhdGggQiAoODAyLjFRIFZMQU4gdGFnZ2VkIElQ
djQpLiAqLwogIHVuc2lnbmVkIE4gPSAodW5zaWduZWQpcG9ydHMuc2l6ZSgpOwogIHVuc2lnbmVk
IHJlamVjdCA9IDExICsgTiAqIDQ7CiAgdW5zaWduZWQgYWNjZXB0ID0gcmVqZWN0ICsgMTsKICBz
dHJ1Y3Qgc29ja19maWx0ZXIgeDsKI2RlZmluZSBBREQoQyxKLFQsSykgZG8geyB4LmNvZGU9KEMp
OyB4Lmp0PShKKTsgeC5qZj0oVCk7IHguaz0oSyk7IGYucHVzaF9iYWNrKHgpOyB9IHdoaWxlKDAp
CiAgLyogWzBdIExvYWQgRXRoZXJUeXBlIGF0IG9mZnNldCAxMiAqLwogIEFERChCUEZfTER8QlBG
X0h8QlBGX0FCUywgMCwgMCwgMTIpOwogIC8qIFsxXSBJZiBzdGFuZGFyZCBJUHY0ICgweDA4MDAp
LCBqdW1wIHRvIFBhdGggQSBzdGFydCAoaW5kZXggOCArIDIqTikgKi8KICBBREQoQlBGX0pNUHxC
UEZfSkVRfEJQRl9LLCAodW5zaWduZWQpKDYgKyAyICogTiksIDAsIEVUSF9QX0lQX0hPU1QpOwoK
ICAvKiAtLS0gUGF0aCBCOiA4MDIuMVEgVkxBTiAoaW5kZXggMikgLS0tICovCiAgLyogWzJdIElm
IG5vdCA4MDIuMVEgKDB4ODEwMCksIHJlamVjdCAqLwogIEFERChCUEZfSk1QfEJQRl9KRVF8QlBG
X0ssIDAsICh1bnNpZ25lZCkocmVqZWN0IC0gMiAtIDEpLCBFVEhfUF84MDIxUV9IT1NUKTsKICAv
KiBbM10gTG9hZCBlbmNhcHN1bGF0ZWQgRXRoZXJUeXBlIGF0IG9mZnNldCAxNiAqLwogIEFERChC
UEZfTER8QlBGX0h8QlBGX0FCUywgMCwgMCwgMTYpOwogIC8qIFs0XSBJZiBlbmNhcHN1bGF0ZWQg
IT0gSVB2NCwgcmVqZWN0ICovCiAgQUREKEJQRl9KTVB8QlBGX0pFUXxCUEZfSywgMCwgKHVuc2ln
bmVkKShyZWplY3QgLSA0IC0gMSksIEVUSF9QX0lQX0hPU1QpOwogIC8qIFs1XSBMb2FkIElQIHBy
b3RvY29sIGF0IG9mZnNldCAyNyAoMjMgKyA0KSAqLwogIEFERChCUEZfTER8QlBGX0J8QlBGX0FC
UywgMCwgMCwgMjcpOwogIC8qIFs2XSBJZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pN
UHxCUEZfSkVRfEJQRl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtIDYgLSAxKSwgSVBQUk9UT19U
Q1ApOwogIC8qIFs3XSBMb2FkIElITCBhdCBvZmZzZXQgMTggKDE0ICsgNCkgKi8KICBBREQoQlBG
X0xEfEJQRl9CfEJQRl9NU0gsIDAsIDAsIDE4KTsKICAvKiBEZXN0aW5hdGlvbiBwb3J0IGNoZWNr
cyBmb3IgVkxBTiAqLwogIGZvciAoaSA9IDA7IGkgPCBwb3J0cy5zaXplKCk7ICsraSkgewogICAg
QUREKEJQRl9MRHxCUEZfSHxCUEZfSU5ELCAwLCAwLCAyMCk7CiAgICB1bnNpZ25lZCBqdCA9IGFj
Y2VwdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDE7CiAgICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQ
Rl9LLCBqdCwgMCwgcG9ydHNbaV0pOwogIH0KICAvKiBTb3VyY2UgcG9ydCBjaGVja3MgZm9yIFZM
QU4gKi8KICBmb3IgKGkgPSAwOyBpIDwgcG9ydHMuc2l6ZSgpOyArK2kpIHsKICAgIEFERChCUEZf
TER8QlBGX0h8QlBGX0lORCwgMCwgMCwgMTgpOwogICAgdW5zaWduZWQganQgPSBhY2NlcHQgLSAo
dW5zaWduZWQpZi5zaXplKCkgLSAxOwogICAgdW5zaWduZWQgamYgPSAoaSA8IHBvcnRzLnNpemUo
KSAtIDEpID8gMCA6IChyZWplY3QgLSAodW5zaWduZWQpZi5zaXplKCkgLSAxKTsKICAgIEFERChC
UEZfSk1QfEJQRl9KRVF8QlBGX0ssIGp0LCBqZiwgcG9ydHNbaV0pOwogIH0KCiAgLyogLS0tIFBh
dGggQTogU3RhbmRhcmQgSVB2NCAoaW5kZXggOCArIDIqTikgLS0tICovCiAgLyogTG9hZCBJUCBw
cm90b2NvbCBhdCBvZmZzZXQgMjMgKi8KICBBREQoQlBGX0xEfEJQRl9CfEJQRl9BQlMsIDAsIDAs
IDIzKTsKICAvKiBJZiBub3QgVENQLCByZWplY3QgKi8KICBBREQoQlBGX0pNUHxCUEZfSkVRfEJQ
Rl9LLCAwLCAodW5zaWduZWQpKHJlamVjdCAtICh1bnNpZ25lZClmLnNpemUoKSAtIDEpLCBJUFBS
T1RPX1RDUCk7CiAgLyogTG9hZCBJSEwgYXQgb2Zmc2V0IDE0ICovCiAgQUREKEJQRl9MRHxCUEZf
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
aWduZWQgc2hvcnQpZi5zaXplKCk7IHByb2cuZmlsdGVyID0gJmZbMF07IHJldHVybiBzZXRzb2Nr
b3B0KGZkLCBTT0xfU09DS0VULCBTT19BVFRBQ0hfRklMVEVSX09MRCwgJnByb2csIHNpemVvZihw
cm9nKSkgPT0gMDsKfQoKc3RhdGljIGludCBydW5fZml4dHVyZSgpIHsKICBzdGQ6OnN0cmluZyBy
ZXEgPSAiR0VUIC9hcGkvaXRlbXM/eD0xIEhUVFAvMS4xXHJcbkhvc3Q6IGFwaS5sb2NhbFxyXG5B
dXRob3JpemF0aW9uOiBCYXNpYyBZV3hwWTJVNmMyVmpjbVYwXHJcblRyYWNlcGFyZW50OiAwMC0w
MTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZi0wMTIzNDU2Nzg5YWJjZGVmLTAxXHJcblxy
XG4iOwogIEV2ZW50IGU7IGUudHMgPSAxNzAwMDAwMDAwOyBlLmhvc3QgPSAiY3BwLW5vZGUiOyBl
LnNlcnZpY2UgPSAicG9ydDo4MDgwIjsgZS5jYWxsZXIgPSAiMTAuMC4wLjkiOyBlLmNhbGxlcl9w
b3J0ID0gNTEwMDA7IGUuZHN0X2lwID0gIjEwLjAuMC4yIjsgZS5kc3RfcG9ydCA9IDgwODA7IGUu
cmVxX2J5dGVzID0gKHVuc2lnbmVkKXJlcS5zaXplKCk7IHBhcnNlX3JlcXVlc3QocmVxLnN1YnN0
cigwLCByZXEuc2l6ZSgpIC0gNCksICZlKTsgZS5zdGF0dXMgPSAyMDA7IGUuaGFzX3N0YXR1cyA9
IHRydWU7IGUuZHVyYXRpb25fbXMgPSAzOyBlLmhhc19kdXJhdGlvbiA9IHRydWU7IGUucmVzcF9i
eXRlcyA9IDQyOyBlLmhhc19yZXNwID0gdHJ1ZTsgZW1pdF9ldmVudChlKTsgcmV0dXJuIDA7Cn0K
aW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKiphcmd2KSB7CiAgaWYgKGFyZ2MgPiAxICYmICFzdHJj
bXAoYXJndlsxXSwgIi0tZml4dHVyZSIpKSByZXR1cm4gcnVuX2ZpeHR1cmUoKTsKICBzdGQ6OnN0
cmluZyBpZmFjZTsgc3RkOjp2ZWN0b3I8dW5zaWduZWQ+IHBvcnRzOyBpbnQgaTsgaW50IHdvcmtl
cnMgPSAxOwogIGZvciAoaSA9IDE7IGkgPCBhcmdjOyArK2kpIHsKICAgIGlmICghc3RyY21wKGFy
Z3ZbaV0sICItaSIpICYmIGkgKyAxIDwgYXJnYykgaWZhY2UgPSBhcmd2WysraV07CiAgICBlbHNl
IGlmICghc3RyY21wKGFyZ3ZbaV0sICItcCIpICYmIGkgKyAxIDwgYXJnYykgewogICAgICB3aGls
ZSAoaSArIDEgPCBhcmdjICYmIGFyZ3ZbaSArIDFdWzBdICE9ICctJykgewogICAgICAgIGNoYXIg
KnEgPSBzdHJ0b2soYXJndlsrK2ldLCAiLCAiKTsKICAgICAgICB3aGlsZSAocSkgeyBsb25nIHAg
PSBhdG9sKHEpOyBpZiAodmFsaWRfcG9ydCgodW5zaWduZWQpcCkpIHBvcnRzLnB1c2hfYmFjaygo
dW5zaWduZWQpcCk7IHEgPSBzdHJ0b2soTlVMTCwgIiwgIik7IH0KICAgICAgfQogICAgfQogICAg
ZWxzZSBpZiAoIXN0cmNtcChhcmd2W2ldLCAiLWoiKSAmJiBpICsgMSA8IGFyZ2MpIHdvcmtlcnMg
PSBhdG9pKGFyZ3ZbKytpXSk7CiAgICBlbHNlIGlmICghc3RyY21wKGFyZ3ZbaV0sICItaCIpKSB7
IGZwcmludGYoc3RkZXJyLCAidXNhZ2U6IG50LXNuaWZmLWNwcCBbLWkgaWZhY2VdIFstcCBwb3J0
c10gWy1qIHdvcmtlcnNdXG4iKTsgcmV0dXJuIDA7IH0KICB9CiAgaWYgKHBvcnRzLmVtcHR5KCkp
IHsgcG9ydHMucHVzaF9iYWNrKDgwKTsgcG9ydHMucHVzaF9iYWNrKDgwMDMpOyBwb3J0cy5wdXNo
X2JhY2soODAwNSk7IHBvcnRzLnB1c2hfYmFjayg4MDA3KTsgcG9ydHMucHVzaF9iYWNrKDgwMDkp
OyBwb3J0cy5wdXNoX2JhY2soODAxMCk7IHBvcnRzLnB1c2hfYmFjayg4MDExKTsgfQogICh2b2lk
KXdvcmtlcnM7IHN0ZDo6c3RyaW5nIG5vZGUgPSBob3N0X25hbWUoKTsgaW50IGZkID0gc29ja2V0
KEFGX1BBQ0tFVCwgU09DS19SQVcsIGh0b25zKDMpKTsgaWYgKGZkIDwgMCkgeyBwZXJyb3IoIkFG
X1BBQ0tFVCIpOyByZXR1cm4gMjsgfQogIGludCByYiA9IDggKiAxMDI0ICogMTAyNDsKICBzZXRz
b2Nrb3B0KGZkLCBTT0xfU09DS0VULCBTT19SQ1ZCVUYsICZyYiwgc2l6ZW9mKHJiKSk7CiAgaWYg
KCFhdHRhY2hfYnBmKGZkLCBwb3J0cykpIGxvZ21zZygiV0FSTjogQlBGIGF0dGFjaCBmYWlsZWQ7
IGNvbnRpbnVpbmcgdW5maWx0ZXJlZCIpOwogIHN0cnVjdCBzb2NrYWRkcl9sbCBzYTsgbWVtc2V0
KCZzYSwgMCwgc2l6ZW9mKHNhKSk7IHNhLnNsbF9mYW1pbHkgPSBBRl9QQUNLRVQ7IHNhLnNsbF9w
cm90b2NvbCA9IGh0b25zKDMpOyBpZiAoIWlmYWNlLmVtcHR5KCkpIHsgc2Euc2xsX2lmaW5kZXgg
PSAoaW50KWlmX25hbWV0b2luZGV4KGlmYWNlLmNfc3RyKCkpOyBpZiAoIXNhLnNsbF9pZmluZGV4
KSB7IGxvZ21zZygiYmFkIGludGVyZmFjZSIpOyBjbG9zZShmZCk7IHJldHVybiAyOyB9IH0gaWYg
KGJpbmQoZmQsIChzdHJ1Y3Qgc29ja2FkZHIgKikmc2EsIHNpemVvZihzYSkpIDwgMCkgeyBwZXJy
b3IoImJpbmQiKTsgY2xvc2UoZmQpOyByZXR1cm4gMjsgfQogIHNpZ25hbChTSUdURVJNLCBzdG9w
X3NpZ25hbCk7CiAgc2lnbmFsKFNJR0lOVCwgc3RvcF9zaWduYWwpOwogIHN0ZDo6bWFwPHN0ZDo6
c3RyaW5nLCBGbG93PiBmbG93czsKICBzdGQ6Om1hcDxQYWNrZXRLZXksIHN0ZDo6dmVjdG9yPFBl
bmRpbmc+ID4gcGVuZGluZzsKICBsb2dtc2coImxpc3RlbmluZyIpOwogIHRpbWVfdCBsYXN0ID0g
dGltZShOVUxMKTsKICB1bnNpZ25lZCBjaGFyICpidWYgPSAodW5zaWduZWQgY2hhciAqKW1hbGxv
Yyg2NTUzNik7CiAgaWYgKCFidWYpIHsKICAgIGNsb3NlKGZkKTsKICAgIGxvZ21zZygiYnVmZmVy
IGFsbG9jYXRpb24gZmFpbGVkIik7CiAgICByZXR1cm4gMjsKICB9CiAgd2hpbGUgKGdfcnVubmlu
ZykgewogICAgZmRfc2V0IHI7CiAgICBGRF9aRVJPKCZyKTsKICAgIEZEX1NFVChmZCwgJnIpOwog
ICAgc3RydWN0IHRpbWV2YWwgdHY7CiAgICB0di50dl9zZWMgPSAxOwogICAgdHYudHZfdXNlYyA9
IDA7CiAgICBpbnQgcmMgPSBzZWxlY3QoZmQgKyAxLCAmciwgTlVMTCwgTlVMTCwgJnR2KTsKICAg
IGlmIChyYyA+IDAgJiYgRkRfSVNTRVQoZmQsICZyKSkgewogICAgICBzc2l6ZV90IG4gPSByZWN2
KGZkLCBidWYsIDY1NTM2LCAwKTsKICAgICAgaWYgKG4gPiAwKSBoYW5kbGVfcGFja2V0KGJ1Ziwg
KHNpemVfdCluLCBub2RlLCBwb3J0cywgZmxvd3MsIHBlbmRpbmcpOwogICAgfQogICAgdGltZV90
IG5vdyA9IHRpbWUoTlVMTCk7CiAgICBpZiAobm93IC0gbGFzdCA+PSAxKSB7CiAgICAgIHN3ZWVw
KGZsb3dzLCBwZW5kaW5nLCBub3cpOwogICAgICBsYXN0ID0gbm93OwogICAgfQogIH0KICBmcmVl
KGJ1Zik7IGNsb3NlKGZkKTsgbG9nbXNnKCJzdG9wcGVkIik7IHJldHVybiAwOwp9Cg==
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
