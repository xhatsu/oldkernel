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
KIT_URLS="${NT_HUB:-}"

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
for f in nt-sniff.py nt-ship.py; do
    [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$f" ] || need_kit=1
done

if [ "$need_kit" = 1 ] && [ "$MODE" != uninstall ]; then
    WORKDIR=/tmp/ntkit
    mkdir -p "$WORKDIR" || die "cannot create $WORKDIR"

    # --- source 2: embedded payload -------------------------------------
    SELF="$0"
    [ -f "$SELF" ] || SELF=""
    if [ -n "$SELF" ] && grep -q '^#__SNIFF_B64__$' "$SELF" 2>/dev/null; then
        log "first run: extracting embedded kit -> $WORKDIR"
        sed -n '/^#__SNIFF_B64__$/,/^#__END_SNIFF__$/p' "$SELF" | sed '1d;$d' \
            | base64 -d > "$WORKDIR/nt-sniff.py" 2>/dev/null
        sed -n '/^#__SHIP_B64__$/,/^#__END_SHIP__$/p' "$SELF" | sed '1d;$d' \
            | base64 -d > "$WORKDIR/nt-ship.py" 2>/dev/null
    fi

    # --- source 3: hub bootstrap server ---------------------------------
    if [ ! -s "$WORKDIR/nt-sniff.py" ] || [ ! -s "$WORKDIR/nt-ship.py" ]; then
        if [ -z "$KIT_URLS" ] && [ -n "$ENDPOINT" ]; then
            HUBHOST=$(printf %s "$ENDPOINT" | sed -n 's#^\(https\?://[^/:]*\).*$#\1#p')
            [ -n "$HUBHOST" ] && KIT_URLS="$HUBHOST:30105/oldkernel"
        fi
        [ -n "$KIT_URLS" ] || die "kit files missing, no embedded payload, cannot derive hub URL — pass --hub http://HUB:30105/oldkernel"
        log "first run: fetching kit from $KIT_URLS -> $WORKDIR"
        have curl || have wget || die "neither curl nor wget present and no embedded payload"
        for f in nt-sniff.py nt-ship.py el68-smoke.sh README.md DEBUG-NOTES.md; do
            fetch "$KIT_URLS/$f" "$WORKDIR/$f.new" || die "cannot download $f from $KIT_URLS"
            mv "$WORKDIR/$f.new" "$WORKDIR/$f"
        done
    fi

    chmod 755 "$WORKDIR"/nt-*.py 2>/dev/null || true
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
    [ -x "$INIT" ] && "$INIT" stop >/dev/null 2>&1
    if have chkconfig; then chkconfig networktracing-legacy off >/dev/null 2>&1 || true; fi
    rm -f "$INIT"
    pkill -f "$PREFIX/nt-sniff.py" 2>/dev/null || true
    pkill -f "$PREFIX/nt-ship.py" 2>/dev/null || true
    rm -rf "$PREFIX"
    RESIDUE=""
    pgrep -f "$PREFIX/" >/dev/null 2>&1 && RESIDUE="$RESIDUE procs-alive"
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

have python || die "python (2.6/2.7) required on the node"
python -c 'import sys; assert sys.version_info >= (2,6) and sys.version_info < (3,)' \
    || die "python 2.6/2.7 required"

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
for f in nt-sniff.py nt-ship.py; do
    [ -f "$SCRIPT_DIR/$f" ] || die "bundle incomplete: missing $f"
done
cp "$SCRIPT_DIR"/nt-sniff.py "$PREFIX/"
cp "$SCRIPT_DIR"/nt-ship.py  "$PREFIX/"
chmod 755 "$PREFIX"/nt-*.py

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
if [ "$SNIFF_AS" != root ]; then
    SNIFF_CMD="su -s /bin/sh $SNIFF_AS -c 'exec $PREFIX/python-capnetraw $PREFIX/nt-sniff.py -i $IFACE -p $PORTS'"
else
    SNIFF_CMD="exec python $PREFIX/nt-sniff.py -i $IFACE -p $PORTS"
fi

cat > "$INIT" <<EOF
#!/bin/sh
# networktracing-legacy — pcap sniffer + shipper (SysV, el6)
# chkconfig: 2345 90 10
# description: NetworkTracing passive HTTP/SOAP capture (old-kernel kit)

PREFIX=$PREFIX
SNIFF_USER=$SNIFF_AS
PIDFILE=/var/run/networktracing-legacy.pid

case "\$1" in
    start)
        if pgrep -f "\\\$PREFIX/nt-sniff.py" >/dev/null; then
            echo "already running"; exit 0
        fi
        nohup sh -c "$SNIFF_CMD 2>>\$PREFIX/sniff.log | python \$PREFIX/nt-ship.py --endpoint $ENDPOINT >>\$PREFIX/ship.log 2>&1" >/dev/null 2>&1 &
        sleep 1
        pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null || { echo "sniffer failed to start"; exit 1; }
        echo "networktracing-legacy started"
        ;;
    stop)
        pkill -f "\$PREFIX/nt-sniff.py" 2>/dev/null
        pkill -f "\$PREFIX/nt-ship.py" 2>/dev/null
        rm -f "\$PIDFILE"
        echo "networktracing-legacy stopped"
        ;;
    status)
        if pgrep -f "\$PREFIX/nt-sniff.py" >/dev/null; then
            echo "running (pid \$(pgrep -f "\$PREFIX/nt-sniff.py"))"; exit 0
        fi
        echo "stopped"; exit 3
        ;;
    restart)
        \$0 stop; sleep 1; \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|status|restart}"; exit 2
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
pgrep -f "$PREFIX/nt-sniff.py" >/dev/null || die "sniffer not running after start"

log "DONE. Sniffer iface=$IFACE ports=$PORTS -> hub $ENDPOINT (capture-as=$SNIFF_AS)"
log "Logs: $PREFIX/sniff.log $PREFIX/ship.log"
log "Uninstall: sh $SCRIPT_DIR/install-oldkernel.sh --uninstall"

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
b25seSkuCgpVc2FnZTogIHB5dGhvbiBudC1zbmlmZi5weSBbLWkgZXRoMF0gWy1wIDgwLDgwMDMs
ODAwNSw4MDA5LDgwMTAsODAxMV0KU3Rkb3V0OiBvbmUgSlNPTiBldmVudCBwZXIgbGluZSAtPiBw
aXBlIGludG8gbnQtc2hpcC5weS4KIiIiCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgcHJpbnRfZnVu
Y3Rpb24KCmltcG9ydCBiYXNlNjQsIGVycm5vLCBqc29uLCBvcywgc2lnbmFsLCBzb2NrZXQsIHN0
cnVjdCwgc3lzLCB0aW1lCgpFVEhfUF9JUCA9IDB4MDgwMApFVEhfUF9WTEFOID0gMHg4MTAwCgoj
IHB5Mi42IHN0ci1pbmRleGluZyB5aWVsZHMgMS1jaGFyIHN0ciwgbm90IGludCAocHJvdmVuIG9u
IHJlYWwgZWw2IFZNKTsKIyBub3JtYWxpemUgc28gYnl0ZS1hdC1pbmRleCB3b3JrcyBpZGVudGlj
YWxseSB1bmRlciBweXRob24gMiBhbmQgMwpQWTIgPSBzeXMudmVyc2lvbl9pbmZvWzBdID09IDIK
CgpkZWYgYjJpKGMpOgogICAgcmV0dXJuIG9yZChjKSBpZiBQWTIgZWxzZSBjCgpNRVRIT0RTID0g
KCJHRVQiLCAiUE9TVCIsICJQVVQiLCAiREVMRVRFIiwgIlBBVENIIiwgIkhFQUQiLCAiT1BUSU9O
UyIpCgpNQVhfRkxPV1MgPSA4MTkyICAgICAgICAgICAgIyBjb25jdXJyZW50IHRyYWNrZWQgaGFs
Zi1mbG93cyAocGVyIGRpcmVjdGlvbikKTUFYX0hEUlMgPSAyNjIxNDQgICAgICAgICAgICMgbWF4
IGJ5dGVzIGJ1ZmZlcmVkIHdhaXRpbmcgZm9yIFxcclxcblxcclxcbgpNQVhfQk9EWSA9IDEzMTA3
MiAgICAgICAgICAgIyBtYXggcmVxdWVzdCBib2R5IGNvbnN1bWVkIGZvciBhdXRoIHBhcnNpbmcK
RkxPV19UVEwgPSAzMDAgICAgICAgICAgICAgICMgc2Vjb25kcyBiZWZvcmUgaWRsZSBmbG93IGJ1
ZmZlcnMgYXJlIGRyb3BwZWQKCgpkZWYgbG9nKG1zZyk6CiAgICBzeXMuc3RkZXJyLndyaXRlKCJu
dC1zbmlmZjogJXNcbiIgJSBtc2cpCiAgICBzeXMuc3RkZXJyLmZsdXNoKCkKCgpkZWYgcGFyc2Vf
YXJncyhhcmd2KToKICAgIGlmYWNlID0gTm9uZQogICAgcG9ydHMgPSBbODAsIDgwMDMsIDgwMDUs
IDgwMDcsIDgwMDksIDgwMTAsIDgwMTFdCiAgICB2ZXJib3NlID0gRmFsc2UKICAgIGkgPSAwCiAg
ICB3aGlsZSBpIDwgbGVuKGFyZ3YpOgogICAgICAgIGEgPSBhcmd2W2ldCiAgICAgICAgaWYgYSA9
PSAiLWkiOgogICAgICAgICAgICBpICs9IDE7IGlmYWNlID0gYXJndltpXQogICAgICAgIGVsaWYg
YSA9PSAiLXAiOgogICAgICAgICAgICBpICs9IDE7IHBvcnRzID0gW2ludCh4KSBmb3IgeCBpbiBh
cmd2W2ldLnNwbGl0KCIsIikgaWYgeC5zdHJpcCgpXQogICAgICAgIGVsaWYgYSA9PSAiLXYiOgog
ICAgICAgICAgICB2ZXJib3NlID0gVHJ1ZQogICAgICAgIGVsaWYgYSBpbiAoIi1oIiwgIi0taGVs
cCIpOgogICAgICAgICAgICBwcmludChfX2RvY19fKTsgcmFpc2UgU3lzdGVtRXhpdCgwKQogICAg
ICAgIGVsc2U6CiAgICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoInVua25vd24gYXJnOiAlcyIg
JSBhKQogICAgICAgIGkgKz0gMQogICAgcmV0dXJuIGlmYWNlLCBzZXQocG9ydHMpLCB2ZXJib3Nl
CgoKY2xhc3MgRmxvdyhvYmplY3QpOgogICAgX19zbG90c19fID0gKCJidWYiLCAic3RhdGUiLCAi
bmVlZCIsICJoZHJzIiwgInRvdWNoZWQiKQogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAg
IHNlbGYuYnVmID0gYnl0ZWFycmF5KCkKICAgICAgICBzZWxmLnN0YXRlID0gMCAgICAgICAgICAj
IDA9aGVhZGVycywgMT1ib2R5CiAgICAgICAgc2VsZi5uZWVkID0gMAogICAgICAgIHNlbGYuaGRy
cyA9IHt9CiAgICAgICAgc2VsZi50b3VjaGVkID0gdGltZS50aW1lKCkKCgpkZWYgYmFzaWNfdXNl
cih2YWx1ZSk6CiAgICAiIiJBdXRob3JpemF0aW9uIGhlYWRlciB2YWx1ZSAtPiAodXNlcnxOb25l
LCBzY2hlbWV8Tm9uZSkuIEJhc2ljIG9ubHkuIiIiCiAgICBwYXJ0cyA9IHZhbHVlLnN0cmlwKCku
c3BsaXQoTm9uZSwgMSkKICAgIGlmIGxlbihwYXJ0cykgIT0gMjoKICAgICAgICByZXR1cm4gTm9u
ZSwgTm9uZQogICAgc2NoZW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAgaWYgc2NoZW1lID09ICJi
YXNpYyI6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYWQgPSBwYXJ0c1sxXS5zdHJpcCgpCiAg
ICAgICAgICAgIHBhZCArPSAiPSIgKiAoLWxlbihwYWQpICUgNCkKICAgICAgICAgICAgcmF3ID0g
YmFzZTY0LmI2NGRlY29kZShwYWQpCiAgICAgICAgICAgIGlmIGIiOiIgaW4gcmF3OgogICAgICAg
ICAgICAgICAgdXNlciA9IHJhdy5zcGxpdChiIjoiLCAxKVswXQogICAgICAgICAgICAgICAgIyBu
ZXZlciByZXR1cm4gdGhlIHBhc3N3b3JkOyB1c2VyIG9ubHkKICAgICAgICAgICAgICAgIHJldHVy
biB1c2VyLmRlY29kZSgidXRmLTgiLCAicmVwbGFjZSIpWzo2NF0sICJiYXNpYyIKICAgICAgICBl
eGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9uZQogICAgZWxpZiBz
Y2hlbWUgPT0gImJlYXJlciI6CiAgICAgICAgcmV0dXJuIE5vbmUsICJiZWFyZXIiICAgICAgICMg
dG9rZW4gb3BhcXVlOyB1c2VyIG1hcHBpbmcgaXMgaHViLXNpZGUKICAgIHJldHVybiBOb25lLCBO
b25lCgoKZGVmIGZpbmlzaF9ldmVudChmbG93LCBrZXksIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwg
c3BvcnQsIHBvcnRzLCBub2RlX2hvc3QpOgogICAgaCA9IGZsb3cuaGRycwogICAgdXNlciA9IHNj
aGVtZSA9IE5vbmUKICAgIGF1dGh6ID0gaC5nZXQoImF1dGhvcml6YXRpb24iKQogICAgaWYgYXV0
aHo6CiAgICAgICAgdXNlciwgc2NoZW1lID0gYmFzaWNfdXNlcihhdXRoeikKICAgIGV2ID0gewog
ICAgICAgICJ0cyI6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAgImhvc3QiOiBub2RlX2hvc3Qs
CiAgICAgICAgInNyYyI6ICJwY2FwIiwKICAgICAgICAic2VydmljZSI6ICJwb3J0OiVkIiAlIGRw
b3J0LAogICAgICAgICJtZXRob2QiOiBoLmdldCgiX21ldGhvZCIpIG9yICItIiwKICAgICAgICAi
cGF0aCI6IChoLmdldCgiX3BhdGgiKSBvciAiLSIpLnNwbGl0KCI/IiwgMSlbMF1bOjEyMF0sCiAg
ICAgICAgInVzZXIiOiB1c2VyLAogICAgICAgICJzY2hlbWUiOiBzY2hlbWUsCiAgICAgICAgInBp
ZCI6IE5vbmUsCiAgICAgICAgInNvdXJjZV9wcm9iZSI6ICJwY2FwLWh0dHAiLAogICAgICAgICJo
b3N0X2hkciI6IGguZ2V0KCJob3N0IiksCiAgICAgICAgInVzZXJfYWdlbnQiOiBoLmdldCgidXNl
ci1hZ2VudCIpLAogICAgICAgICJ4X2ZvcndhcmRlZF9mb3IiOiBoLmdldCgieC1mb3J3YXJkZWQt
Zm9yIiksCiAgICAgICAgImNhbGxlciI6IHNyY19pcCwKICAgICAgICAiY2FsbGVyX3BvcnQiOiBz
cG9ydCwKICAgICAgICAiZHN0X2lwIjogZHN0X2lwLAogICAgICAgICJkc3RfcG9ydCI6IGRwb3J0
LAogICAgfQogICAgcmV0dXJuIGV2IGlmIChkcG9ydCBpbiBwb3J0cyBvciBoLmdldCgiX21ldGhv
ZCIpKSBlbHNlIE5vbmUKCgpkZWYgaGFuZGxlX3BheWxvYWQoZmxvd3MsIGtleSwgcmV2X2tleSwg
cGF5bG9hZCwgbWV0YSwgcG9ydHMsIG5vZGVfaG9zdCwgb3V0KToKICAgICIiIkZlZWQgb25lIGRp
cmVjdGlvbidzIHBheWxvYWQ7IGVtaXQgZmluaXNoZWQgZXZlbnRzIHRvIG91dChsaXN0KS4iIiIK
ICAgIGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQgPSBtZXRhCiAgICBmbCA9IGZsb3dzLmdl
dChrZXkpCiAgICBpZiBmbCBpcyBOb25lOgogICAgICAgIGZsID0gRmxvdygpCiAgICAgICAgZmxv
d3Nba2V5XSA9IGZsCiAgICAgICAgaWYgbGVuKGZsb3dzKSA+IE1BWF9GTE9XUzoKICAgICAgICAg
ICAgZW5mb3JjZV9saW1pdChmbG93cywgdGltZS50aW1lKCkpCiAgICBmbC50b3VjaGVkID0gdGlt
ZS50aW1lKCkKICAgIGZsLmJ1Zi5leHRlbmQoYnl0ZWFycmF5KHBheWxvYWQpKQoKICAgIHdoaWxl
IFRydWU6CiAgICAgICAgaWYgZmwuc3RhdGUgPT0gMDoKICAgICAgICAgICAgaWR4ID0gZmwuYnVm
LmZpbmQoYiJcclxuXHJcbiIpCiAgICAgICAgICAgIGlmIGlkeCA8IDA6CiAgICAgICAgICAgICAg
ICBpZiBsZW4oZmwuYnVmKSA+IE1BWF9IRFJTOgogICAgICAgICAgICAgICAgICAgIGZsb3dzLnBv
cChrZXksIE5vbmUpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgaGVhZCA9IGJ5
dGVzKGZsLmJ1Zls6aWR4XSkKICAgICAgICAgICAgcmVzdCA9IGZsLmJ1ZltpZHggKyA0Ol0KICAg
ICAgICAgICAgbGluZXMgPSBoZWFkLnJlcGxhY2UoYiJcclxuIiwgYiJcbiIpLnNwbGl0KGIiXG4i
KQogICAgICAgICAgICBoZHJzID0ge30KICAgICAgICAgICAgZmlyc3QgPSBsaW5lc1swXS5zdHJp
cCgpLnNwbGl0KCkKICAgICAgICAgICAgaWYgbGVuKGZpcnN0KSA+PSAyIGFuZCBmaXJzdFswXSBp
biBbCiAgICAgICAgICAgICAgICAgICAgbS5lbmNvZGUoKSBmb3IgbSBpbiBNRVRIT0RTXToKICAg
ICAgICAgICAgICAgIGhkcnNbIl9tZXRob2QiXSA9IGZpcnN0WzBdLmRlY29kZSgiYXNjaWkiLCAi
cmVwbGFjZSIpCiAgICAgICAgICAgICAgICBoZHJzWyJfcGF0aCJdID0gZmlyc3RbMV0uZGVjb2Rl
KCJhc2NpaSIsICJyZXBsYWNlIikKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGZs
b3dzLnBvcChrZXksIE5vbmUpICAgICAgICMgbm90IGEgcmVxdWVzdCBzdGFydAogICAgICAgICAg
ICAgICAgcmV0dXJuCiAgICAgICAgICAgIGZvciBsbiBpbiBsaW5lc1sxOl06CiAgICAgICAgICAg
ICAgICBpZiBiIjoiIG5vdCBpbiBsbjoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAg
ICAgICAgICAgICAga24sIGt2ID0gbG4uc3BsaXQoYiI6IiwgMSkKICAgICAgICAgICAgICAgIGhk
cnNba24uc3RyaXAoKS5sb3dlcigpLmRlY29kZSgKICAgICAgICAgICAgICAgICAgICAiYXNjaWki
LCAicmVwbGFjZSIpXSA9IGt2LnN0cmlwKCkuZGVjb2RlKAogICAgICAgICAgICAgICAgICAgICAg
ICAidXRmLTgiLCAicmVwbGFjZSIpWzoxODBdCiAgICAgICAgICAgIGNsID0gMAogICAgICAgICAg
ICBpZiAiY29udGVudC1sZW5ndGgiIGluIGhkcnM6CiAgICAgICAgICAgICAgICB0cnk6CiAgICAg
ICAgICAgICAgICAgICAgY2wgPSBtaW4oaW50KGhkcnNbImNvbnRlbnQtbGVuZ3RoIl0pLCBNQVhf
Qk9EWSkKICAgICAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAg
ICAgIGNsID0gMAogICAgICAgICAgICBpZiBjbCA9PSAwOgogICAgICAgICAgICAgICAgZmwuaGRy
cyA9IGhkcnMKICAgICAgICAgICAgICAgIGV2ID0gZmluaXNoX2V2ZW50KGZsLCBrZXksIGRzdF9p
cCwgZHBvcnQsIHNyY19pcCwgc3BvcnQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICBwb3J0cywgbm9kZV9ob3N0KQogICAgICAgICAgICAgICAgZGVsIGZsb3dzW2tleV0KICAgICAg
ICAgICAgICAgIGlmIGV2OgogICAgICAgICAgICAgICAgICAgIG91dC5hcHBlbmQoZXYpCiAgICAg
ICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgZmwuaGRycyA9IGhkcnMKICAgICAgICAgICAg
Zmwuc3RhdGUgPSAxCiAgICAgICAgICAgIGZsLm5lZWQgPSBjbAogICAgICAgICAgICBmbC5idWYg
PSBieXRlYXJyYXkocmVzdFs6Y2wgKiAyXSkgICAjIGtlZXAgc29tZSBzbGFjawogICAgICAgICAg
ICBjb250aW51ZSAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIHJlLWNoZWNrIGJvZHkgaW4g
bmV4dCBsb29wCiAgICAgICAgaWYgZmwuc3RhdGUgPT0gMToKICAgICAgICAgICAgaWYgbGVuKGZs
LmJ1ZikgPj0gZmwubmVlZDoKICAgICAgICAgICAgICAgICMgYm9keSBjYXB0dXJlZCAoYXV0aCBt
YXkgcmlkZSBpbnNpZGUgUE9TVCBib2RpZXMgZm9yIHNvbWUKICAgICAgICAgICAgICAgICMgdGll
cnMsIGJ1dCBwZXIgcHJvZHVjdCBkZWNpc2lvbiB3ZSBkbyBOT1QgbWluZSBTT0FQIGJvZGllczsK
ICAgICAgICAgICAgICAgICMgYnVmZmVyIGtlcHQgb25seSBzbyBDb250ZW50LUxlbmd0aCBmcmFt
aW5nIHN0YXlzIGhvbmVzdCkKICAgICAgICAgICAgICAgIGV2ID0gZmluaXNoX2V2ZW50KGZsLCBr
ZXksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkc3RfaXAsIGRwb3J0LCBzcmNf
aXAsIHNwb3J0LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcG9ydHMsIG5vZGVf
aG9zdCkKICAgICAgICAgICAgICAgIGRlbCBmbG93c1trZXldCiAgICAgICAgICAgICAgICBpZiBl
djoKICAgICAgICAgICAgICAgICAgICBvdXQuYXBwZW5kKGV2KQogICAgICAgICAgICAgICAgcmV0
dXJuCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICByZXR1cm4gICAgICAgICAgICAg
ICAgICAgICAgICAgICMgd2FpdCBmb3IgbW9yZSBzZWdtZW50cwoKCmRlZiBzd2VlcF9pZGxlKGZs
b3dzLCBub3cpOgogICAgc3RhbGUgPSBbXQogICAgZm9yIGssIGZsIGluIGZsb3dzLml0ZW1zKCk6
CiAgICAgICAgaWYgbm93IC0gZmwudG91Y2hlZCA+IEZMT1dfVFRMOgogICAgICAgICAgICBzdGFs
ZS5hcHBlbmQoaykKICAgIGZvciBrIGluIHN0YWxlOgogICAgICAgIGRlbCBmbG93c1trXQoKCmRl
ZiBlbmZvcmNlX2xpbWl0KGZsb3dzLCBub3cpOgogICAgIiIiQ2FwIGZsb3ctdGFibGUgc2l6ZSAo
cHkyLjY6IG5vIE9yZGVyZWREaWN0IOKAlCBzd2VlcCBzdGFsZSwgdGhlbiBGSUZPCiAgICBieSBp
bnNlcnRpb24gb3JkZXIsIHdoaWNoIHBsYWluIGRpY3RzIHByZXNlcnZlIGluIENQeXRob24pLiIi
IgogICAgc3dlZXBfaWRsZShmbG93cywgbm93KQogICAgd2hpbGUgbGVuKGZsb3dzKSA+IE1BWF9G
TE9XUzoKICAgICAgICBmbG93cy5wb3BpdGVtKCkgICAgICAgICAgIyBvbGRlc3QtaW5zZXJ0ZWQg
a2V5IG9uIENQeXRob24gMi42LzIuNwoKCmRlZiBtYWluKCk6CiAgICBpZmFjZSwgcG9ydHMsIHZl
cmJvc2UgPSBwYXJzZV9hcmdzKHN5cy5hcmd2WzE6XSkKICAgIG5vZGVfaG9zdCA9IHNvY2tldC5n
ZXRob3N0bmFtZSgpLnNwbGl0KCIuIilbMF0KCiAgICB0cnk6CiAgICAgICAgIyBwcm90b2NvbCBN
VVNUIGJlIGh0b25zKEVUSF9QX0lQKTogYSAwLXByb3RvY29sIHNvY2tldCByZWNlaXZlcwogICAg
ICAgICMgTk9USElORyAoa2VybmVsIGRlbGl2ZXJzIG9ubHkgbWF0Y2hpbmcgZXRoZXJ0eXBlOyAw
IG1hdGNoZXMgbm9uZSkuCiAgICAgICAgIyBzb2NrZXQuaHRvbnMgaXMgY29ycmVjdCBvbiBldmVy
eSBwbGF0Zm9ybSDigJQgZG8gTk9UIHVzZSBudG9ocyBoZXJlLgogICAgICAgIHMgPSBzb2NrZXQu
c29ja2V0KHNvY2tldC5BRl9QQUNLRVQsIHNvY2tldC5TT0NLX1JBVywKICAgICAgICAgICAgICAg
ICAgICAgICAgICBzb2NrZXQuaHRvbnMoRVRIX1BfSVApKQogICAgZXhjZXB0IEF0dHJpYnV0ZUVy
cm9yOgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIkFGX1BBQ0tFVCB1bmF2YWlsYWJsZSBvbiB0
aGlzIHBsYXRmb3JtIikKICAgIGV4Y2VwdCBzb2NrZXQuZXJyb3IgYXMgZToKICAgICAgICByYWlz
ZSBTeXN0ZW1FeGl0KCJjYW5ub3Qgb3BlbiBBRl9QQUNLRVQgc29ja2V0ICglcykg4oCUIG5lZWQg
IgogICAgICAgICAgICAgICAgICAgICAgICAgIkNBUF9ORVRfUkFXIC8gcm9vdCIgJSBlKQogICAg
dHJ5OgogICAgICAgIHMuYmluZCgoaWZhY2Ugb3IgIiIsIDApKQogICAgZXhjZXB0IHNvY2tldC5l
cnJvcjoKICAgICAgICAjIGJpbmRpbmcgdG8gYSBzcGVjaWZpYyBpZmFjZSBmYWlsZWQg4oCUIGZh
bGwgYmFjayB0byBhbGwgaW50ZXJmYWNlcwogICAgICAgIHRyeToKICAgICAgICAgICAgcy5iaW5k
KCgiIiwgMCkpCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvcjoKICAgICAgICAgICAgcGFzcyAg
ICAgICAgICAjIHVuYm91bmQgc29ja2V0IHN0aWxsIHJlY2VpdmVzIG9uIGFsbCBpbnRlcmZhY2Vz
CiAgICBzLnNldHRpbWVvdXQoMS4wKQoKICAgIGZsb3dzID0ge30KICAgIHJ1bm5pbmcgPSBbVHJ1
ZV0KCiAgICBkZWYgc3RvcChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFs
c2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2ln
bmFsKHNpZ25hbC5TSUdJTlQsIHN0b3ApCgogICAgbGFzdF9zd2VlcCA9IHRpbWUudGltZSgpCiAg
ICBsb2coImxpc3RlbmluZyBvbiAlcyBwb3J0cz0lcyBwaWQ9JWQiICUKICAgICAgICAoaWZhY2Ug
b3IgIjxhbGw+Iiwgc29ydGVkKHBvcnRzKSwgb3MuZ2V0cGlkKCkpKQoKICAgIHdoaWxlIHJ1bm5p
bmdbMF06CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwa3QgPSBzLnJlY3YoNjU1MzUpCiAgICAg
ICAgZXhjZXB0IHNvY2tldC50aW1lb3V0OgogICAgICAgICAgICBub3cgPSB0aW1lLnRpbWUoKQog
ICAgICAgICAgICBpZiBub3cgLSBsYXN0X3N3ZWVwID4gMzA6CiAgICAgICAgICAgICAgICBzd2Vl
cF9pZGxlKGZsb3dzLCBub3cpCiAgICAgICAgICAgICAgICBsYXN0X3N3ZWVwID0gbm93CiAgICAg
ICAgICAgIGNvbnRpbnVlCiAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvciBhcyBlOgogICAgICAg
ICAgICBpZiBlLmVycm5vID09IGVycm5vLkVJTlRSOgogICAgICAgICAgICAgICAgY29udGludWUK
ICAgICAgICAgICAgcmFpc2UKICAgICAgICBpZiBsZW4ocGt0KSA8IDM0OgogICAgICAgICAgICBj
b250aW51ZQogICAgICAgIG9mZiA9IDAKICAgICAgICBldHlwZSA9IHN0cnVjdC51bnBhY2soIiFI
IiwgcGt0WzEyOjE0XSlbMF0KICAgICAgICBpZiBldHlwZSA9PSBFVEhfUF9WTEFOOgogICAgICAg
ICAgICBldHlwZSA9IHN0cnVjdC51bnBhY2soIiFIIiwgcGt0WzE2OjE4XSlbMF0KICAgICAgICAg
ICAgb2ZmID0gNAogICAgICAgIGlmIGV0eXBlICE9IEVUSF9QX0lQOgogICAgICAgICAgICBjb250
aW51ZQogICAgICAgIGlwID0gcGt0WzE0ICsgb2ZmOl0KICAgICAgICBpZiBsZW4oaXApIDwgMjA6
CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWhsID0gKGIyaShpcFswXSkgJiAweDBGKSAq
IDQKICAgICAgICBpZiAoYjJpKGlwWzBdKSA+PiA0KSAhPSA0IG9yIGIyaShpcFs5XSkgIT0gNjog
ICAjIElQdjQgVENQIG9ubHkKICAgICAgICAgICAgY29udGludWUKICAgICAgICBmcmFnID0gc3Ry
dWN0LnVucGFjaygiIUgiLCBpcFs2OjhdKVswXQogICAgICAgIGlmIGZyYWcgJiAweDFGRkY6ICAg
ICAgICAgICAgICAgICAgICAgICAgICMgbm9uLWZpcnN0IGZyYWdtZW50CiAgICAgICAgICAgIGNv
bnRpbnVlCiAgICAgICAgc3JjX2lwID0gc29ja2V0LmluZXRfbnRvYShpcFsxMjoxNl0pCiAgICAg
ICAgZHN0X2lwID0gc29ja2V0LmluZXRfbnRvYShpcFsxNjoyMF0pCiAgICAgICAgdGNwID0gaXBb
aWhsOl0KICAgICAgICBpZiBsZW4odGNwKSA8IDIwOgogICAgICAgICAgICBjb250aW51ZQogICAg
ICAgIHNwb3J0LCBkcG9ydCA9IHN0cnVjdC51bnBhY2soIiFISCIsIHRjcFswOjRdKQogICAgICAg
IGRvZmYgPSAoKGIyaSh0Y3BbMTJdKSA+PiA0KSAmIDB4MEYpICogNAogICAgICAgIGZsYWdzID0g
YjJpKHRjcFsxM10pCiAgICAgICAgcGF5bG9hZCA9IHRjcFtkb2ZmOl0KICAgICAgICBpZiBub3Qg
cGF5bG9hZDoKICAgICAgICAgICAgIyBGSU4vUlNUIHRlYXJkb3duOiBkcm9wIGJvdGggZGlyZWN0
aW9ucycgYnVmZmVycwogICAgICAgICAgICBpZiBmbGFncyAmIDB4MDU6ICAgICAgICAgICAgICAg
ICAgICAgICMgRklOfFJTVAogICAgICAgICAgICAgICAgZmsgPSAoc3JjX2lwLCBzcG9ydCwgZHN0
X2lwLCBkcG9ydCkKICAgICAgICAgICAgICAgIHJrID0gKGRzdF9pcCwgZHBvcnQsIHNyY19pcCwg
c3BvcnQpCiAgICAgICAgICAgICAgICBmbG93cy5wb3AoZmssIE5vbmUpCiAgICAgICAgICAgICAg
ICBmbG93cy5wb3AocmssIE5vbmUpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgIyByZXF1
ZXN0cyBUTyBvdXIgbW9uaXRvcmVkIHBvcnRzIChpbmJvdW5kIHRvIHNlcnZpY2VzKQogICAgICAg
IGlmIGRwb3J0IGluIHBvcnRzOgogICAgICAgICAgICBrZXkgPSAoc3JjX2lwLCBzcG9ydCwgZHN0
X2lwLCBkcG9ydCkKICAgICAgICAgICAgb3V0ID0gW10KICAgICAgICAgICAgaGFuZGxlX3BheWxv
YWQoZmxvd3MsIGtleSwgTm9uZSwgcGF5bG9hZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAg
KGRzdF9pcCwgZHBvcnQsIHNyY19pcCwgc3BvcnQpLAogICAgICAgICAgICAgICAgICAgICAgICAg
ICBwb3J0cywgbm9kZV9ob3N0LCBvdXQpCiAgICAgICAgICAgIGZvciBldiBpbiBvdXQ6CiAgICAg
ICAgICAgICAgICBzeXMuc3Rkb3V0LndyaXRlKGpzb24uZHVtcHMoZXYpICsgIlxuIikKICAgICAg
ICAgICAgaWYgb3V0OgogICAgICAgICAgICAgICAgc3lzLnN0ZG91dC5mbHVzaCgpCiAgICAgICAg
IyByZXNwb25zZXMgRlJPTSBtb25pdG9yZWQgcG9ydHM6IHVzZWQgb25seSBmb3IgdGVhcmRvd24g
Ym9va2tlZXBpbmcKICAgICAgICBlbGlmIHNwb3J0IGluIHBvcnRzIGFuZCAoZmxhZ3MgJiAweDA1
KToKICAgICAgICAgICAgcmsgPSAoZHN0X2lwLCBkcG9ydCwgc3JjX2lwLCBzcG9ydCkKICAgICAg
ICAgICAgZmxvd3MucG9wKHJrLCBOb25lKQoKICAgIGxvZygic3RvcHBlZCIpCgoKaWYgX19uYW1l
X18gPT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQo=
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
IHByaW50X2Z1bmN0aW9uCgppbXBvcnQgYmFzZTY0LCBqc29uLCBvcywgc2lnbmFsLCBzb2NrZXQs
IHN5cywgdGltZSwgdXJsbGliMgoKTUFYX0JBVENIID0gNDAwCkZMVVNIX1NFQyA9IDUuMApSRVRS
WV9NQVggPSA4NjQwMC4wICAgICAgICAjIGtlZXAgc3Bvb2wtcmV0cnlpbmcgZm9yIGEgZGF5IGJl
Zm9yZSBnaXZpbmcgdXAKCgpkZWYgbG9nKG1zZyk6CiAgICBzeXMuc3RkZXJyLndyaXRlKCJudC1z
aGlwOiAlc1xuIiAlIG1zZykKICAgIHN5cy5zdGRlcnIuZmx1c2goKQoKCmRlZiBtYWluKCk6CiAg
ICBlbmRwb2ludCA9IE5vbmUKICAgIHNwb29sID0gIi92YXIvbGliL25ldHdvcmt0cmFjaW5nL3Nu
aWZmLXNwb29sLmpzb25sIgogICAgYXJndiA9IHN5cy5hcmd2WzE6XQogICAgaSA9IDAKICAgIHdo
aWxlIGkgPCBsZW4oYXJndik6CiAgICAgICAgYSA9IGFyZ3ZbaV0KICAgICAgICBpZiBhID09ICIt
LWVuZHBvaW50IjoKICAgICAgICAgICAgaSArPSAxOyBlbmRwb2ludCA9IGFyZ3ZbaV0ucnN0cmlw
KCIvIikKICAgICAgICBlbGlmIGEgPT0gIi0tc3Bvb2wiOgogICAgICAgICAgICBpICs9IDE7IHNw
b29sID0gYXJndltpXQogICAgICAgIGVsaWYgYSBpbiAoIi1oIiwgIi0taGVscCIpOgogICAgICAg
ICAgICBwcmludChfX2RvY19fKTsgcmFpc2UgU3lzdGVtRXhpdCgwKQogICAgICAgIGVsc2U6CiAg
ICAgICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoInVua25vd24gYXJnOiAlcyIgJSBhKQogICAgICAg
IGkgKz0gMQogICAgaWYgbm90IGVuZHBvaW50OgogICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoIi0t
ZW5kcG9pbnQgcmVxdWlyZWQiKQoKICAgIG5vZGUgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5zcGxp
dCgiLiIpWzBdCgogICAgIyByZXBsYXkgc3Bvb2xlZCBldmVudHMgZmlyc3QgKGF0LWxlYXN0LW9u
Y2UpCiAgICBwZW5kaW5nID0gW10KICAgIGlmIG9zLnBhdGguZXhpc3RzKHNwb29sKToKICAgICAg
ICB0cnk6CiAgICAgICAgICAgIHdpdGggb3BlbihzcG9vbCkgYXMgZjoKICAgICAgICAgICAgICAg
IGZvciBsaW5lIGluIGY6CiAgICAgICAgICAgICAgICAgICAgbGluZSA9IGxpbmUuc3RyaXAoKQog
ICAgICAgICAgICAgICAgICAgIGlmIGxpbmU6CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeToK
ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlbmRpbmcuYXBwZW5kKGpzb24ubG9hZHMobGlu
ZSkpCiAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAg
ICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICBvcy5yZW1vdmUoc3Bvb2wpCiAgICAg
ICAgZXhjZXB0IChJT0Vycm9yLCBPU0Vycm9yKSBhcyBlOgogICAgICAgICAgICBsb2coInNwb29s
IHJlYWQgZmFpbGVkOiAlcyIgJSBlKQoKICAgIHJ1bm5pbmcgPSBbVHJ1ZV0KCiAgICBkZWYgc3Rv
cChzaWdudW0sIGZyYW1lKToKICAgICAgICBydW5uaW5nWzBdID0gRmFsc2UKICAgIHNpZ25hbC5z
aWduYWwoc2lnbmFsLlNJR1RFUk0sIHN0b3ApCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJ
TlQsIHN0b3ApCgogICAgZGVmIGZsdXNoKGJhdGNoKToKICAgICAgICBpZiBub3QgYmF0Y2g6CiAg
ICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgYm9keSA9IGpzb24uZHVtcHMoeyJub2RlIjog
bm9kZSwgImV2ZW50cyI6IGJhdGNofSkKICAgICAgICAjIHB5MiB1cmxsaWIyIGFjY2VwdHMgc3Ry
OyBweTMgc2hpbS90ZXN0IG5lZWRzIGJ5dGVzIOKAlCBlbmNvZGUgd2hlbgogICAgICAgICMgdGhl
IHJ1bnRpbWUgZXhwb3NlcyBpdCAocHkyIHN0ciBoYXMgbm8gLmVuY29kZSBvbiBhbGwgYnVpbGRz
LCBzbwogICAgICAgICMgZ3VhcmQgd2l0aCBoYXNhdHRyKQogICAgICAgIGlmIGhhc2F0dHIoYm9k
eSwgImVuY29kZSIpOgogICAgICAgICAgICBib2R5ID0gYm9keS5lbmNvZGUoInV0Zi04IikKICAg
ICAgICByZXEgPSB1cmxsaWIyLlJlcXVlc3QoZW5kcG9pbnQgKyAiL2FwaS9pbmdlc3QiLCBkYXRh
PWJvZHksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9eyJDb250ZW50LVR5
cGUiOiAiYXBwbGljYXRpb24vanNvbiJ9KQogICAgICAgIHRyeToKICAgICAgICAgICAgcmVzcCA9
IHVybGxpYjIudXJsb3BlbihyZXEsIHRpbWVvdXQ9MTApCiAgICAgICAgICAgIG9rID0gKHJlc3Au
Z2V0Y29kZSgpID09IDIwMCkKICAgICAgICAgICAgcmVzcC5yZWFkKCkKICAgICAgICAgICAgcmVz
cC5jbG9zZSgpCiAgICAgICAgICAgIHJldHVybiBvawogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24g
YXMgZToKICAgICAgICAgICAgbG9nKCJzaGlwIGZhaWxlZDogJXMiICUgZSkKICAgICAgICAgICAg
cmV0dXJuIEZhbHNlCgogICAgYnVmID0gbGlzdChwZW5kaW5nKQogICAgbGFzdF9mbHVzaCA9IHRp
bWUudGltZSgpCiAgICBiYWNrb2ZmID0gMQoKICAgIGZvciByYXcgaW4gaXRlcihzeXMuc3RkaW4u
cmVhZGxpbmUsICIiKToKICAgICAgICBpZiBub3QgcnVubmluZ1swXToKICAgICAgICAgICAgYnJl
YWsKICAgICAgICByYXcgPSByYXcuc3RyaXAoKQogICAgICAgIGlmIG5vdCByYXc6CiAgICAgICAg
ICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBldiA9IGpzb24ubG9hZHMocmF3
KQogICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAgICBjb250aW51ZSAgICAgICAg
ICAgICAgICAgICAgICAjIGdhcmJhZ2UgaW4sIHNpbGVudGx5IGRyb3BwZWQKICAgICAgICBpZiBp
c2luc3RhbmNlKGV2LCBkaWN0KToKICAgICAgICAgICAgYnVmLmFwcGVuZChldikKICAgICAgICBu
b3cgPSB0aW1lLnRpbWUoKQogICAgICAgIGlmIGxlbihidWYpID49IE1BWF9CQVRDSCBvciBub3cg
LSBsYXN0X2ZsdXNoID49IEZMVVNIX1NFQzoKICAgICAgICAgICAgbGFzdF9mbHVzaCA9IG5vdwog
ICAgICAgICAgICBpZiBub3QgZmx1c2goYnVmKToKICAgICAgICAgICAgICAgIF9zcG9vbF9hcHBl
bmQoc3Bvb2wsIGJ1ZikKICAgICAgICAgICAgICAgIGJ1ZiA9IFtdCiAgICAgICAgICAgICAgICB0
aW1lLnNsZWVwKG1pbihiYWNrb2ZmLCA2MCkpCiAgICAgICAgICAgICAgICBiYWNrb2ZmICo9IDIK
ICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGJhY2tvZmYgPSAxCgogICAgIyBzdGRp
biBjbG9zZWQgKHNuaWZmZXIgc3RvcHBlZCkg4oCUIGZpbmFsIGZsdXNoCiAgICBpZiBidWYgYW5k
IG5vdCBmbHVzaChidWYpOgogICAgICAgIF9zcG9vbF9hcHBlbmQoc3Bvb2wsIGJ1ZikKICAgIGxv
Zygic3RvcHBlZCAoJWQgZXZlbnRzIHBlbmRpbmcgb24gZXhpdCkiICUKICAgICAgICBsZW4oYnVm
KSBpZiBub3QgYnVmIGVsc2UgInN0b3BwZWQgY2xlYW4iKQoKCmRlZiBfc3Bvb2xfYXBwZW5kKHBh
dGgsIGJhdGNoKToKICAgIGQgPSBvcy5wYXRoLmRpcm5hbWUocGF0aCkKICAgIHRyeToKICAgICAg
ICBpZiBkIGFuZCBub3Qgb3MucGF0aC5pc2RpcihkKToKICAgICAgICAgICAgb3MubWFrZWRpcnMo
ZCkKICAgICAgICB3aXRoIG9wZW4ocGF0aCwgImEiKSBhcyBmOgogICAgICAgICAgICBmb3IgZXYg
aW4gYmF0Y2g6CiAgICAgICAgICAgICAgICBmLndyaXRlKGpzb24uZHVtcHMoZXYpICsgIlxuIikK
ICAgICAgICBkZWwgYmF0Y2hbOl0KICAgIGV4Y2VwdCAoSU9FcnJvciwgT1NFcnJvcikgYXMgZToK
ICAgICAgICBsb2coIkZBVEFMOiBjYW5ub3Qgd3JpdGUgc3Bvb2wgJXM6ICVzIiAlIChwYXRoLCBl
KSkKICAgICAgICBvcy5fZXhpdCgzKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBt
YWluKCkK
#__END_SHIP__
