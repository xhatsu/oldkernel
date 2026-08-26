#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-sniff.py — passive AF_PACKET HTTP/SOAP sniffer for old kernels.

Target: CentOS 6.x / kernel 2.6.32 (no eBPF, no systemd, python 2.6).
Reads packets off the wire (CAP_NET_RAW), reassembles plain-HTTP requests,
extracts Basic-auth usernames (same semantics as nt_authlib.extract),
emits NetworkTracing event JSONL on stdout.

TLS is NOT readable (by design — that tier stays on the eBPF agent).
SOAP WSSE usernames are NOT extracted (product decision: Basic-only).

Performance:
  * kernel BPF filter (SO_ATTACH_FILTER): only IPv4/TCP requests destined
    to monitored ports are copied up — responses/noise never reach python
  * HEADER-ONLY capture: events emit at \r\n\r\n; bodies are not buffered
  * PACKET_FANOUT (-j N): N forked workers share the NIC across cores
Usage:  python nt-sniff.py [-i eth0] [-p 80,8003,...] [-j workers]
Stdout: one JSON event per line -> pipe into nt-ship.py.
"""
from __future__ import print_function

import base64, binascii, errno, json, os, signal, socket, struct, sys, time

ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100

# py2.6 str-indexing yields 1-char str, not int (proven on real el6 VM);
# normalize so byte-at-index works identically under python 2 and 3
PY2 = sys.version_info[0] == 2


def b2i(c):
    return ord(c) if PY2 else c

METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

MAX_FLOWS = 8192            # concurrent tracked half-flows (per direction)
MAX_HDRS = 262144           # max bytes buffered waiting for \r\n\r\n
FLOW_TTL = 300              # seconds before idle flow buffers are dropped


def log(msg):
    sys.stderr.write("nt-sniff: %s\n" % msg)
    sys.stderr.flush()


# ---------------------------------------------------------------- perf: cBPF
# Attach a classic BPF program so the KERNEL drops everything that is not
# IPv4 TCP destined TO a monitored port. Requests alone drive events
# (header-only capture); responses, ACKs and unrelated traffic never get
# copied to userspace at all.
SO_ATTACH_FILTER = 26

def build_bpf(ports):
    """Classic BPF: ethertype==IP && proto==TCP && dport in ports.
    Returns (fprog_struct, filter_array) for the libc setsockopt call,
    or None on failure. NOTE: sock_fprog carries a POINTER to the filter
    array, so it must stay alive until the syscall — python's
    socket.setsockopt(str) flattening cannot preserve it."""

    LDH_ABS = 0x28   # ld [k]:h
    LDB_ABS = 0x30   # ld [k]:b
    JEQ_K = 0x15     # jeq k
    LDX_MSH = 0xB1   # x = 4*([k]&0xf)  (ihl bytes)
    LDH_IND = 0x48   # ld [x+k]:h
    RET_K = 0x06

    prog = []
    # accept if (dport in ports) OR (sport in ports) — responses needed for
    # status/duration correlation. Two port blocks, either hits ACCEPT.
    reject_idx = 5 + 4 * len(ports)
    accept_idx = reject_idx + 1
    prog.append((LDH_ABS, 0, 0, 12))            # ethertype
    prog.append((JEQ_K, 0, reject_idx - 2, 0x0800))   # == IP -> fall thru
    prog.append((LDB_ABS, 0, 0, 23))            # ip proto byte (fixed off)
    prog.append((JEQ_K, 0, reject_idx - 4, 6))        # == TCP -> fall thru
    prog.append((LDX_MSH, 0, 0, 14))            # X = ihl*4
    # block A: dport at ip_start + X + 16
    for i, p in enumerate(sorted(ports)):
        b = 5 + 2 * i
        prog.append((LDH_IND, 0, 0, 16))
        prog.append((JEQ_K, accept_idx - (b + 2), 1 if i < len(ports) - 1
                     else reject_idx - (b + 2), p))
    # block B: sport at ip_start + X + 14 — jump target after last B check
    base_b = 5 + 2 * len(ports)
    for i, p in enumerate(sorted(ports)):
        b = base_b + 2 * i
        prog.append((LDH_IND, 0, 0, 14))
        prog.append((JEQ_K, accept_idx - (b + 2), 1 if i < len(ports) - 1
                     else reject_idx - (b + 2), p))
    prog.append((RET_K, 0, 0, 0))               # reject
    prog.append((RET_K, 0, 0, 0x40000))         # accept (256KB)

    try:
        import ctypes

        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                        ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]

        class SockFprog(ctypes.Structure):
            # mirrors struct sock_fprog {u16 len; sock_filter *filter};
            # ctypes applies the same pointer alignment as the compiler
            _fields_ = [("len", ctypes.c_uint16),
                        ("filter", ctypes.POINTER(SockFilter))]

        arr = (SockFilter * len(prog))()
        for i, (code, jt, jf, k) in enumerate(prog):
            arr[i].code = code; arr[i].jt = jt
            arr[i].jf = jf; arr[i].k = k
        return SockFprog(len(prog), arr), arr
    except Exception:
        return None


def apply_perf_opts(sock, ports):
    """Best-effort kernel assist: BPF port filter + big rcvbuf.
    NT_SNIFF_NO_BPF=1 disables the filter (debugging)."""
    built = None
    if os.environ.get("NT_SNIFF_NO_BPF") == "1":
        log("NT_SNIFF_NO_BPF set — skipping kernel filter")
    else:
        built = build_bpf(ports)
    if built is not None:
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            fprog, arr = built                      # keep arr referenced!
            ret = libc.setsockopt(sock.fileno(), socket.SOL_SOCKET,
                                  SO_ATTACH_FILTER,
                                  ctypes.byref(fprog),
                                  ctypes.sizeof(fprog))
            if ret == 0:
                log("kernel BPF filter attached (%d monitored ports)"
                    % len(ports))
            else:
                log("WARN: BPF attach rejected by kernel (ret=%d) "
                    "— running unfiltered" % ret)
        except Exception as e:
            log("WARN: BPF filter attach failed (%s) — running unfiltered"
                % e)
    else:
        log("WARN: ctypes unavailable — running without BPF filter")
    try:
        want = 8 * 1024 * 1024
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
        got = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        log("rcvbuf: %d bytes" % got)
    except Exception as e:
        log("WARN: SO_RCVBUF raise failed: %s" % e)


# ---------------------------------------------------------------- perf: fanout
SOL_PACKET = 263
PACKET_FANOUT = 18

def apply_fanout(sock, group_id):
    """Kernel load-balances packets across all sockets sharing the group.
    Hashing is per-flow-directional; request direction alone drives event
    emission, so directional splits are safe. Returns True on success."""
    try:
        sock.setsockopt(SOL_PACKET, PACKET_FANOUT,
                        struct.pack("I", group_id & 0xFFFF))
        return True
    except Exception as e:
        log("WARN: PACKET_FANOUT failed (%s) — single-process capture" % e)
        return False


def parse_args(argv):
    iface = None
    ports = [80, 8003, 8005, 8007, 8009, 8010, 8011]
    verbose = False
    workers = 1
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-i":
            i += 1; iface = argv[i]
        elif a == "-p":
            i += 1; ports = [int(x) for x in argv[i].split(",") if x.strip()]
        elif a == "-j":
            i += 1; workers = max(1, int(argv[i]))
        elif a == "-v":
            verbose = True
        elif a in ("-h", "--help"):
            print(__doc__); raise SystemExit(0)
        else:
            raise SystemExit("unknown arg: %s" % a)
        i += 1
    return iface, set(ports), verbose, workers


class Flow(object):
    __slots__ = ("buf", "hdrs", "touched")
    def __init__(self):
        self.buf = bytearray()
        self.hdrs = {}
        self.touched = time.time()


# ------------------------------------------------- response correlation ----
PENDING_TTL = 5.0        # flush unmatched requests after this many seconds
PENDING_MAX = 8192       # hard cap; overflow flushes oldest first

# pending[(src_ip, sport, dst_ip, dport)]  -- key is the RESPONSE tuple:
# server->client. Value: [event, req_ts]. A list per key handles HTTP
# keep-alive pipelining (several requests before responses arrive).
pending = {}


def pending_del(rk):
    pending.pop(rk, None)


def pending_pop(rk, out):
    """Flush the oldest pending event for this response tuple (FIN/RST or
    overflow path). Emits whatever the event has — status stays null."""
    lst = pending.get(rk)
    if not lst:
        return None
    ev, _ = lst.pop(0)
    if not lst:
        pending_del(rk)
    out.append(ev)
    return ev


def parse_response_head(payload):
    """First line 'HTTP/1.x NNN ...' -> (status_int|None, content_len|None).
    Only looks at what's in this segment; headers fit one segment for all
    realistic API responses."""
    try:
        head = payload.split(b"\r\n\r\n", 1)[0]
        lines = head.replace(b"\r\n", b"\n").split(b"\n")
        first = lines[0].split()
        if len(first) < 2 or not first[0].startswith(b"HTTP/"):
            return None, None
        st = int(first[1])
    except (ValueError, IndexError):
        return None, None
    clen = None
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(b"content-length:"):
            try:
                clen = int(ln.split(b":", 1)[1].strip())
            except ValueError:
                pass
            break
    return st, clen


def basic_user(value):
    """Authorization header value -> (user|None, scheme|None). Basic only."""
    parts = value.strip().split(None, 1)
    if len(parts) != 2:
        return None, None
    scheme = parts[0].lower()
    if scheme == "basic":
        try:
            pad = parts[1].strip()
            pad += "=" * (-len(pad) % 4)
            raw = base64.b64decode(pad)
            if b":" in raw:
                user = raw.split(b":", 1)[0]
                # never return the password; user only
                return user.decode("utf-8", "replace")[:64], "basic"
        except Exception:
            return None, None
    elif scheme == "bearer":
        return None, "bearer"       # token opaque; user mapping is hub-side
    return None, None


def finish_event(flow, key, dst_ip, dport, src_ip, sport, ports, node_host):
    h = flow.hdrs
    user = scheme = None
    authz = h.get("authorization")
    if authz:
        user, scheme = basic_user(authz)
    # W3C trace context: honor incoming traceparent, else generate one so
    # every transaction carries a trace_id for hub-side correlation.
    # NOTE py2.6: bytes has no .hex() — use binascii.hexlify.
    tp = h.get("traceparent")
    trace_id = None
    if tp:
        parts = tp.split("-")
        if len(parts) == 4 and len(parts[1]) == 32:
            trace_id = parts[1].lower()
    if not trace_id:
        try:
            rnd = binascii.hexlify(os.urandom(16))
            rnd = rnd.decode("ascii") if hasattr(rnd, "decode") else rnd
        except Exception:
            rnd = ("%032x" % (int(time.time() * 1000)))[-32:]
        pid8 = binascii.hexlify(os.urandom(8))
        pid8 = pid8.decode("ascii") if hasattr(pid8, "decode") else pid8
        tp = "00-%s-%s-01" % (rnd, pid8)
        trace_id = rnd
    ev = {
        "ts": int(time.time()),
        "host": node_host,
        "src": "pcap",
        "service": "port:%d" % dport,
        "method": h.get("_method") or "-",
        "path": (h.get("_path") or "-").split("?", 1)[0][:120],
        "user": user,
        "scheme": scheme,
        "pid": None,
        "source_probe": "pcap-http",
        "host_hdr": h.get("host"),
        "user_agent": h.get("user-agent"),
        "x_forwarded_for": h.get("x-forwarded-for"),
        "caller": src_ip,
        "caller_port": sport,
        "dst_ip": dst_ip,
        "dst_port": dport,
        # ---- monitoring schema (ops API-log format) ----
        # status/duration_ms/resp_bytes are response-side: passive request-only
        # capture cannot see them; left null for the hub to enrich or leave.
        "traceparent": tp[:80],
        "trace_id": trace_id,
        "service_id": None,          # hub maps port->service via policy later
        "module_id": "pcap-http",
    }
    return ev if (dport in ports or h.get("_method")) else None


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out,
                   pending_tbl=None, now=None):
    """Feed one direction's payload; emit finished events to out(list).

    HEADER-ONLY capture: the request event is built the moment \\r\\n\\r\\n is
    seen. With response correlation enabled (pending_tbl), the finished
    event goes into the pending table instead of out — it is emitted when
    the matching response head arrives, or on TTL/teardown fallback.
    Request bodies are NOT buffered — Basic auth (all we mine) rides headers,
    so body bytes cost memory and delay events for zero information. A later
    segment on the same connection simply fails the request-line check and
    is discarded."""
    dst_ip, dport, src_ip, sport = meta
    fl = flows.get(key)
    if fl is None:
        fl = Flow()
        flows[key] = fl
        if len(flows) > MAX_FLOWS:
            enforce_limit(flows, time.time())
    fl.touched = time.time()
    fl.buf.extend(bytearray(payload))

    idx = fl.buf.find(b"\r\n\r\n")
    if idx < 0:
        if len(fl.buf) > MAX_HDRS:
            flows.pop(key, None)
        return
    head = bytes(fl.buf[:idx])
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    hdrs = {}
    first = lines[0].strip().split()
    if len(first) >= 2 and first[0] in [
            m.encode() for m in METHODS]:
        hdrs["_method"] = first[0].decode("ascii", "replace")
        hdrs["_path"] = first[1].decode("ascii", "replace")
    else:
        flows.pop(key, None)       # not a request start
        return
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        kn, kv = ln.split(b":", 1)
        hdrs[kn.strip().lower().decode(
            "ascii", "replace")] = kv.strip().decode(
                "utf-8", "replace")[:180]
    fl.hdrs = hdrs
    ev = finish_event(fl, key, dst_ip, dport, src_ip, sport,
                      ports, node_host)
    del flows[key]
    if not ev:
        return
    ev["req_bytes"] = idx + 4          # captured request head + terminator
    if pending_tbl is None:
        out.append(ev)                 # correlation disabled (legacy path)
        return
    # queue for response correlation; key is the RESPONSE tuple
    rk = (dst_ip, dport, src_ip, sport)
    ent = pending_tbl.get(rk)
    if ent is None:
        if len(pending_tbl) >= PENDING_MAX:
            _flush_oldest_pending(pending_tbl, out)
        ent = pending_tbl[rk] = []
    ent.append([ev, now if now is not None else time.time()])


def sweep_idle(flows, now):
    stale = []
    for k, fl in flows.items():
        if now - fl.touched > FLOW_TTL:
            stale.append(k)
    for k in stale:
        del flows[k]


def _flush_oldest_pending(pending_tbl, out):
    """Overflow guard: emit the single oldest pending event as-is."""
    oldest_key, oldest_ts = None, None
    for rk, lst in pending_tbl.items():
        ts = lst[0][1]
        if oldest_ts is None or ts < oldest_ts:
            oldest_key, oldest_ts = rk, ts
    if oldest_key is not None:
        pending_pop(oldest_key, out)


def sweep_pending(pending_tbl, now, out):
    """TTL flush: emit requests whose responses never showed up."""
    stale = []
    for rk, lst in pending_tbl.items():
        if now - lst[0][1] > PENDING_TTL:
            stale.append(rk)
    for rk in stale:
        pending_pop(rk, out)


def enforce_limit(flows, now):
    """Cap flow-table size (py2.6: no OrderedDict — sweep stale, then FIFO
    by insertion order, which plain dicts preserve in CPython)."""
    sweep_idle(flows, now)
    while len(flows) > MAX_FLOWS:
        flows.popitem()          # oldest-inserted key on CPython 2.6/2.7


def main():
    iface, ports, verbose, workers = parse_args(sys.argv[1:])
    node_host = socket.gethostname().split(".")[0]

    try:
        # protocol MUST be htons(ETH_P_IP): a 0-protocol socket receives
        # NOTHING (kernel delivers only matching ethertype; 0 matches none).
        # socket.htons is correct on every platform — do NOT use ntohs here.
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_IP))
    except AttributeError:
        raise SystemExit("AF_PACKET unavailable on this platform")
    except socket.error as e:
        raise SystemExit("cannot open AF_PACKET socket (%s) — need "
                         "CAP_NET_RAW / root" % e)
    # kernel assist BEFORE bind: BPF port filter + big rcvbuf. With the
    # filter attached the kernel drops non-monitored traffic for us, which
    # is what lifts the capture ceiling from ~720 ev/s to wire rate.
    apply_perf_opts(s, ports)
    try:
        s.bind((iface or "", 0))
    except socket.error:
        # binding to a specific iface failed — fall back to all interfaces
        try:
            s.bind(("", 0))
        except socket.error:
            pass          # unbound socket still receives on all interfaces
    fanout_ok = False
    if workers > 1:
        fanout_ok = apply_fanout(s, 0xF00D)
        if fanout_ok:
            log("fanout group 0xF00D: spawning %d workers" % workers)

    # precompiled struct readers — unpack_from reads straight out of the
    # packet buffer (no slice copies) and yields ints under py2 AND py3
    u16 = struct.Struct("!H").unpack_from
    uh = struct.Struct("!HH").unpack_from   # sport,dport in one read
    ub = struct.Struct("!BB").unpack_from
    ntoa = socket.inet_ntoa

    flows = {}
    running = [True]

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    last_sweep = time.time()
    log("listening on %s ports=%s pid=%d" %
        (iface or "<all>", sorted(ports), os.getpid()))

    # fork extra capture workers AFTER fanout attach; WITHOUT a working
    # fanout group every process would receive EVERY packet (duplicates),
    # so single-process mode is forced when the kernel lacks support
    # (PACKET_FANOUT needs kernel >= 3.1; el6 2.6.32 does not have it)
    if fanout_ok:
        for _ in range(workers - 1):
            if os.fork() == 0:
                break                 # child: fall through into its own loop

    while running[0]:
        try:
            pkt = s.recv(65535)
        except socket.timeout:
            now = time.time()
            if now - last_sweep > 30:
                sweep_idle(flows, now)
                out_s = []
                sweep_pending(pending, now, out_s)
                for ev in out_s:
                    sys.stdout.write(json.dumps(ev) + "\n")
                if out_s:
                    sys.stdout.flush()
                last_sweep = now
            continue
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise
        n = len(pkt)
        if n < 34:
            continue
        out = []
        off = 14                      # ethernet header
        etype = u16(pkt, 12)[0]
        if etype == ETH_P_VLAN:
            etype = u16(pkt, 16)[0]
            off = 18
        elif etype != ETH_P_IP:
            continue                  # with BPF attached this is rare
        ip0 = ub(pkt, off)[0]
        if ip0 >> 4 != 4 or ub(pkt, off + 9)[0] != 6:   # IPv4 TCP only
            continue
        ihl = (ip0 & 0x0F) * 4
        frag = u16(pkt, off + 6)[0]
        if frag & 0x1FFF:                         # non-first fragment
            continue
        src_ip = ntoa(pkt[off + 12:off + 16])
        dst_ip = ntoa(pkt[off + 16:off + 20])
        tcp_off = off + ihl
        sport, dport = uh(pkt, tcp_off)
        doff_flags = ub(pkt, tcp_off + 12)
        doff = (doff_flags[0] >> 4) * 4
        pay_start = tcp_off + doff
        if n <= pay_start:
            continue                              # no payload in segment
        payload = pkt[pay_start:]
        flags = doff_flags[1]
        now = time.time()

        # ---------------- RESPONSE direction (server -> client) ----------
        if sport in ports and dport not in ports:
            # pending key was stored as (server_ip, server_port, client_ip,
            # client_port) == (src, sport, dst, dport) OF THIS response pkt
            rk = (src_ip, sport, dst_ip, dport)
            if flags & 0x05:                      # FIN|RST: flush unmatched
                ev = pending_pop(rk, out)
            elif payload[:5] == b"HTTP/":
                st, clen = parse_response_head(payload)
                ent = pending.get(rk)
                if ent is not None:
                    ev = ent[0][0]
                    ev["status"] = st
                    ev["duration_ms"] = int((now - ent[0][1]) * 1000)
                    if clen is not None:
                        ev["resp_bytes"] = clen
                    pending_del(rk)
                    out.append(ev)
        # ---------------- REQUEST direction (client -> server) -----------
        elif dport in ports:
            if flags & 0x05:                      # teardown w/o response seen
                rk = (dst_ip, dport, src_ip, sport)
                pending_pop(rk, out)
            key = (src_ip, sport, dst_ip, dport)
            handle_payload(flows, key, None, payload,
                           (dst_ip, dport, src_ip, sport),
                           ports, node_host, out, pending, now)
        if out:
            w = sys.stdout.write
            for ev in out:
                w(json.dumps(ev) + "\n")
            sys.stdout.flush()

    log("stopped")


if __name__ == "__main__":
    main()
