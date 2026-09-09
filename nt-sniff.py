#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-sniff.py — passive AF_PACKET HTTP/SOAP sniffer for old kernels.

Target: CentOS 6.x / kernel 2.6.32 (no eBPF, no systemd, python 2.6).
Reads packets off the wire (CAP_NET_RAW), reassembles plain-HTTP requests,
extracts Basic-auth usernames (same semantics as nt_authlib.extract),
emits NetworkTracing event JSONL on stdout.

TLS is NOT readable (by design — that tier stays on the eBPF agent).
SOAP WSSE UsernameToken extraction is available only when explicitly enabled
with NT_WSSE_BODY_BYTES or --wsse-body-bytes. The default remains header-only.

Performance:
  * kernel BPF filter (SO_ATTACH_FILTER): IPv4/TCP requests and responses
    for monitored ports are copied up; unrelated traffic stays in kernel
  * HEADER-ONLY by default; opt-in WSSE parsing has strict per-flow/global bounds
Usage:  python nt-sniff.py [-i eth0] [-p 80,8003,...] [-j workers]
                           [--wsse-body-bytes 0..65536]
Stdout: one JSON event per line -> pipe into nt-ship.py.
"""
from __future__ import print_function

import base64, binascii, errno, json, os, signal, socket, struct, sys, time
import unicodedata
from xml.parsers import expat

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100
SOL_PACKET = 263
PACKET_STATISTICS = 6
DEFAULT_STATS_INTERVAL = 30

try:
    import nt_control
except ImportError:
    nt_control = None

# py2.6 str-indexing yields 1-char str, not int (proven on real el6 VM);
# normalize so byte-at-index works identically under python 2 and 3
PY2 = sys.version_info[0] == 2


def b2i(c):
    return ord(c) if PY2 else c

METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

MAX_FLOWS = 8192            # concurrent tracked half-flows (per direction)
MAX_HDRS = 262144           # max bytes buffered waiting for \r\n\r\n
FLOW_TTL = 300              # seconds before idle flow buffers are dropped
MAX_WSSE_BODY_BYTES = 65536 # hard ceiling even if configuration is larger
MAX_WSSE_BODY_FLOWS = 256   # at most 16 MiB of opt-in body buffers globally
MAX_WSSE_USERNAME = 200

WSSE_NAMESPACES = set((
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "http://schemas.xmlsoap.org/ws/2002/07/secext",
    "http://schemas.xmlsoap.org/ws/2002/12/secext",
    "http://schemas.xmlsoap.org/ws/2003/06/secext",
))


def log(msg):
    sys.stderr.write("nt-sniff: %s\n" % msg)
    sys.stderr.flush()


def stats_interval_seconds():
    try:
        value = int(os.environ.get("NT_STATS_INTERVAL_SEC",
                                   str(DEFAULT_STATS_INTERVAL)))
    except ValueError:
        value = DEFAULT_STATS_INTERVAL
    return max(10, min(value, 300))


def drop_capture_capabilities():
    """Irreversibly clear CAP_NET_RAW after the packet socket is ready."""
    try:
        import ctypes
        libcap = ctypes.CDLL("libcap.so.2")
        libcap.cap_init.restype = ctypes.c_void_p
        empty = libcap.cap_init()
        if not empty:
            return False
        try:
            return libcap.cap_set_proc(ctypes.c_void_p(empty)) == 0
        finally:
            libcap.cap_free(ctypes.c_void_p(empty))
    except Exception:
        return False


# ---------------------------------------------------------------- perf: cBPF
# Attach a classic BPF program so the KERNEL drops everything that is not
# IPv4 TCP to or from a monitored port. Request headers drive events and
# response headers enrich them; unrelated traffic never reaches userspace.
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

    # PROVEN dport block + sport block at X+14 (calibrated EMPIRICALLY on
    # a live kernel: k=14 delivers response packets; the correlation then
    # yields status/duration_ms/resp_bytes end-to-end). Requires the 1s
    # recv timeout in main() — blocking recv + BPF starves after one pkt.
    sk = int(os.environ.get("NT_SNIFF_SPORT_K", "14"))
    ps = sorted(ports)
    n = len(ps)
    ret_rej = 5 + (4 if sk else 2) * n
    ret_acc = ret_rej + 1
    prog = []
    prog.append((LDH_ABS, 0, 0, 12))                 # ethertype == IP?
    prog.append((JEQ_K, 0, ret_rej - 2, 0x0800))
    prog.append((LDB_ABS, 0, 0, 23))                 # proto == TCP?
    prog.append((JEQ_K, 0, ret_rej - 4, 6))
    prog.append((LDX_MSH, 0, 0, 14))                 # X = ihl*4
    for i, p in enumerate(ps):                       # A: dport @ X+16
        prog.append((LDH_IND, 0, 0, 16))
        jt = ret_acc - (len(prog) + 1)
        jf = 0 if (i < n - 1 or sk) else (ret_rej - (len(prog) + 1))
        prog.append((JEQ_K, jt, jf, p))
    if sk:                                           # B: sport @ X+sk
        for i, p in enumerate(ps):
            prog.append((LDH_IND, 0, 0, sk))
            jt = ret_acc - (len(prog) + 1)
            jf = 0 if i < n - 1 else (ret_rej - (len(prog) + 1))
            prog.append((JEQ_K, jt, jf, p))
    prog.append((RET_K, 0, 0, 0))                    # reject
    prog.append((RET_K, 0, 0, 0x40000))              # accept
    if any(jt > 255 or jf > 255 for _, jt, jf, _ in prog):
        return None

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
    """Attach the mandatory kernel port filter and tune the receive buffer."""
    built = build_bpf(ports)
    filter_ok = False
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
                filter_ok = True
            else:
                log("BPF attach rejected by kernel (ret=%d)" % ret)
        except Exception as e:
            log("BPF filter attach failed (%s)" % e)
    else:
        log("BPF construction unavailable")
    try:
        want = 8 * 1024 * 1024
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
        got = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        log("rcvbuf: %d bytes" % got)
    except Exception as e:
        log("WARN: SO_RCVBUF raise failed: %s" % e)
    return filter_ok


def parse_wsse_body_bytes(value):
    """Validate the opt-in body window without allowing unbounded buffers."""
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        raise SystemExit("wsse body bytes must be an integer")
    if size < 0 or size > MAX_WSSE_BODY_BYTES:
        raise SystemExit("wsse body bytes must be in range 0..%d" %
                         MAX_WSSE_BODY_BYTES)
    return size


def parse_args(argv):
    iface = None
    ports = [80, 8003, 8005, 8007, 8009, 8010, 8011]
    verbose = False
    workers = 1
    wsse_body_bytes = parse_wsse_body_bytes(
        os.environ.get("NT_WSSE_BODY_BYTES", "0"))
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-i":
            if i + 1 >= len(argv):
                raise SystemExit("-i requires an interface")
            i += 1; iface = argv[i]
        elif a == "-p":
            if i + 1 >= len(argv):
                raise SystemExit("-p requires a comma-separated port list")
            i += 1
            try:
                ports = [int(x) for x in argv[i].split(",") if x.strip()]
            except ValueError:
                raise SystemExit("invalid port list")
            if not ports or any(not valid_port(x) for x in ports):
                raise SystemExit("ports must be in range 1..65535")
            if len(ports) > 30:
                raise SystemExit("at most 30 monitored ports are supported")
        elif a == "-j":
            if i + 1 >= len(argv):
                raise SystemExit("-j requires a worker count")
            i += 1
            try:
                workers = int(argv[i])
            except ValueError:
                raise SystemExit("invalid worker count")
            if workers != 1:
                raise SystemExit("only one capture worker is permitted")
        elif a == "-v":
            verbose = True
        elif a == "--wsse-body-bytes":
            if i + 1 >= len(argv):
                raise SystemExit("--wsse-body-bytes requires a byte count")
            i += 1
            wsse_body_bytes = parse_wsse_body_bytes(argv[i])
        elif a in ("-h", "--help"):
            print(__doc__); raise SystemExit(0)
        else:
            raise SystemExit("unknown arg: %s" % a)
        i += 1
    return iface, set(ports), verbose, workers, wsse_body_bytes


HTTP_STATE_HEADER = 0
HTTP_STATE_BODY = 1
HTTP_STATE_CHUNK = 2
HTTP_STATE_CLOSE_BODY = 3

MAX_OOO_SEGMENTS = 4
MAX_OOO_BYTES = 16384
MAX_TOTAL_BUFFER_BYTES = 16 * 1024 * 1024


def seq_diff(a, b):
    diff = (a - b) & 0xFFFFFFFF
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


def is_method_or_prefix(payload):
    if not payload:
        return False
    p = bytes(payload[:8])
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        check_len = min(len(p), len(m))
        if p[:check_len] == m[:check_len]:
            return True
    return False


def find_http_start(buf):
    b = bytes(buf)
    best = -1
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        pos = b.find(m)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


class Flow(object):
    __slots__ = ("next_seq", "has_seq", "is_broken", "touched", "first_byte_ts",
                 "buf", "ooo", "state", "body_remaining", "chunk_remaining",
                 "chunk_payload_remaining", "chunk_reading_len", "chunk_reading_crlf",
                 "chunk_reading_trailer", "awaiting_wsse", "wsse_event", "wsse_buf",
                 "wsse_goal", "event", "hdrs", "head_bytes", "body_goal", "generation")

    def __init__(self):
        self.next_seq = 0
        self.has_seq = False
        self.is_broken = False
        self.touched = time.time()
        self.first_byte_ts = 0.0
        self.buf = bytearray()
        self.ooo = []
        self.state = HTTP_STATE_HEADER
        self.body_remaining = 0
        self.chunk_remaining = 0
        self.chunk_payload_remaining = 0
        self.chunk_reading_len = True
        self.chunk_reading_crlf = False
        self.chunk_reading_trailer = False
        self.awaiting_wsse = False
        self.wsse_event = None
        self.wsse_buf = bytearray()
        self.wsse_goal = 0
        self.event = None
        self.hdrs = None
        self.head_bytes = 0
        self.body_goal = 0
        self.generation = 0


def _drain_ooo(fl):
    drained = True
    while drained and fl.ooo:
        drained = False
        for i, (oseq, odata) in enumerate(fl.ooo):
            odiff = seq_diff(oseq, fl.next_seq)
            if odiff == 0:
                fl.buf.extend(odata)
                fl.next_seq = (fl.next_seq + len(odata)) & 0xFFFFFFFF
                fl.ooo.pop(i)
                drained = True
                break
            elif odiff < 0:
                o_overlap = -odiff
                if o_overlap < len(odata):
                    fl.buf.extend(odata[o_overlap:])
                    fl.next_seq = (fl.next_seq + len(odata) - o_overlap) & 0xFFFFFFFF
                fl.ooo.pop(i)
                drained = True
                break


# ------------------------------------------------- response correlation ----
PENDING_TTL = 5.0        # flush unmatched requests after this many seconds
PENDING_MAX = 8192       # hard cap; overflow flushes oldest first
PENDING_PER_FLOW = 32    # bound a single pipelined/hostile keep-alive flow
SWEEP_INTERVAL = 1.0     # honor PENDING_TTL even when the socket goes idle

# pending[(src_ip, sport, dst_ip, dport)]  -- key is the RESPONSE tuple:
# server->client. Value: [event, req_ts]. A list per key handles HTTP
# keep-alive pipelining (several requests before responses arrive).
pending = {}
MAX_CORR_DISABLED = 2048
corr_disabled = set()
corr_disabled_fifo = []
corr_capacity_reached = False


def corr_disabled_insert(rk):
    global corr_capacity_reached
    if rk in corr_disabled:
        return
    while len(corr_disabled) >= MAX_CORR_DISABLED and corr_disabled_fifo:
        corr_capacity_reached = True
        old_k = corr_disabled_fifo.pop(0)
        corr_disabled.discard(old_k)
    corr_disabled.add(rk)
    corr_disabled_fifo.append(rk)


def corr_disabled_erase(rk):
    if rk in corr_disabled:
        corr_disabled.discard(rk)
        try:
            corr_disabled_fifo.remove(rk)
        except ValueError:
            pass


def corr_disabled_clear():
    global corr_capacity_reached
    corr_disabled.clear()
    del corr_disabled_fifo[:]
    corr_capacity_reached = False


def is_correlation_disabled(rk, syn_seen):
    if rk in corr_disabled:
        return True
    if corr_capacity_reached and not syn_seen:
        return True
    return False


def pending_del(rk):
    pending.pop(rk, None)
    corr_disabled_erase(rk)




def pending_pop(rk, out, pending_tbl=None):
    """Flush the oldest pending event for this response tuple (FIN/RST or
    overflow path). Emits whatever the event has — status stays null."""
    if pending_tbl is None:
        pending_tbl = pending
    lst = pending_tbl.get(rk)
    if not lst:
        return None
    item = lst.pop(0)
    if not lst:
        pending_tbl.pop(rk, None)
    is_tombstone = item[2] if len(item) > 2 else False
    if not is_tombstone:
        out.append(item[0])
        return item[0]
    return None


def parse_response_head(payload):
    """First line 'HTTP/1.x NNN ...' -> (status_int|None, content_len|None, head_end_idx|None, is_chunked, is_close)."""
    try:
        raw = bytes(payload)
        idx = raw.find(b"\r\n\r\n")
        if idx < 0:
            return None, None, None, False, False
        head = raw[:idx]
        lines = head.replace(b"\r\n", b"\n").split(b"\n")
        first = lines[0].split()
        if len(first) < 2 or not first[0].startswith(b"HTTP/"):
            return None, None, idx + 4, False, False
        st = int(first[1])
        if st < 100 or st > 599:
            return None, None, None, False, False
    except (ValueError, IndexError):
        return None, None, None, False, False
    clen = None
    has_clen = False
    has_conflict_cl = False
    is_chunked = False
    is_close = False
    is_http_10 = first[0].startswith(b"HTTP/1.0")
    conn_close = False
    conn_keep_alive = False
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(b"content-length:"):
            try:
                val = int(ln.split(b":", 1)[1].strip())
                if val < 0:
                    has_conflict_cl = True
                elif has_clen and clen != val:
                    has_conflict_cl = True
                clen = val
                has_clen = True
            except ValueError:
                has_conflict_cl = True
        elif low.startswith(b"transfer-encoding:"):
            if b"chunked" in low:
                is_chunked = True
        elif low.startswith(b"connection:"):
            if b"close" in low:
                conn_close = True
            elif b"keep-alive" in low:
                conn_keep_alive = True
    if has_conflict_cl or (has_clen and is_chunked):
        return None, None, None, False, False
    if is_http_10 and not conn_keep_alive:
        is_close = True
    elif conn_close:
        is_close = True
    return st, clen, idx + 4, is_chunked, is_close



def handle_response(resp_flows, rk, payload, now, out, pending_tbl, seq=None, flags=0, is_truncated=False):
    if flags & 0x02 and seq is not None:
        rfl = resp_flows[rk] = Flow()
        rfl.has_seq = True
        rfl.next_seq = (seq + 1) & 0xFFFFFFFF
        rfl.touched = now
        return

    rfl = resp_flows.get(rk)
    if rfl is None:
        rfl = Flow()
        resp_flows[rk] = rfl
    rfl.touched = now

    plen = len(payload) if payload else 0
    if plen > 0:
        if seq is None:
            rfl.buf.extend(payload)
        else:
            if not rfl.has_seq:
                if (plen >= 5 and payload[:5] == b"HTTP/") or (plen < 5 and b"HTTP/".startswith(payload)):
                    rfl.has_seq = True
                    rfl.next_seq = seq
                    rfl.is_broken = False
                else:
                    if len(rfl.ooo) < MAX_OOO_SEGMENTS and not is_truncated:
                        if not any(s == seq for s, _ in rfl.ooo):
                            rfl.ooo.append((seq, bytes(payload)))
                    return

            diff = seq_diff(seq, rfl.next_seq)
            if diff == 0:
                if is_truncated:
                    rfl.is_broken = True
                else:
                    rfl.buf.extend(payload)
                    rfl.next_seq = (rfl.next_seq + plen) & 0xFFFFFFFF
                    _drain_ooo(rfl)
            elif diff < 0:
                overlap = -diff
                if overlap < plen and not is_truncated:
                    rfl.buf.extend(payload[overlap:])
                    rfl.next_seq = (rfl.next_seq + plen - overlap) & 0xFFFFFFFF
                    _drain_ooo(rfl)
            else:
                if len(rfl.ooo) < MAX_OOO_SEGMENTS and not is_truncated:
                    if not any(s == seq for s, _ in rfl.ooo):
                        rfl.ooo.append((seq, bytes(payload)))
                else:
                    rfl.is_broken = True

    # Parse complete responses from reassembled buffer using HTTP framing
    while rfl.buf and not rfl.is_broken:
        if rfl.state == HTTP_STATE_HEADER:
            st, clen, head_len, is_chunked, is_close = parse_response_head(rfl.buf)
            if st is None:
                if head_len is not None:
                    del rfl.buf[:head_len]
                elif rfl.buf.find(b"\r\n\r\n") != -1:
                    rfl.buf = bytearray()
                    rfl.is_broken = True
                break

            if 100 <= st <= 199 and st != 101:
                del rfl.buf[:head_len]
                continue

            verified = (rfl.generation > 0)
            ent = pending_tbl.get(rk) if not is_correlation_disabled(rk, verified) else None
            is_head = False

            if ent:
                item = ent[0]
                is_tombstone = item[2] if len(item) > 2 else False
                gen = item[4] if len(item) > 4 else 0
                if rfl.generation != 0 and gen != 0 and gen != rfl.generation:
                    ev = item[0]
                    out.append(ev)
                    ent.pop(0)
                    if not ent:
                        pending_tbl.pop(rk, None)
                elif is_tombstone:
                    ent.pop(0)
                    if not ent:
                        pending_tbl.pop(rk, None)
                else:
                    ev, started = item[0], item[1]
                    ent.pop(0)
                    if not ent:
                        pending_tbl.pop(rk, None)
                    if ev.get("method") == "HEAD":
                        is_head = True
                    ev["status"] = st
                    ev["duration_ms"] = max(0, int((now - started) * 1000))
                    if clen is not None:
                        ev["resp_bytes"] = clen
                    out.append(ev)

            del rfl.buf[:head_len]

            if is_head or st == 204 or st == 304:
                rfl.state = HTTP_STATE_HEADER
            elif is_chunked:
                rfl.state = HTTP_STATE_CHUNK
                rfl.chunk_reading_len = True
                rfl.chunk_reading_crlf = False
                rfl.chunk_reading_trailer = False
                rfl.chunk_payload_remaining = 0
            elif clen is not None:
                if clen > 0:
                    rfl.state = HTTP_STATE_BODY
                    rfl.body_remaining = clen
                else:
                    rfl.state = HTTP_STATE_HEADER
            else:
                rfl.state = HTTP_STATE_CLOSE_BODY
            continue

        if rfl.state == HTTP_STATE_BODY:
            if not rfl.buf:
                break
            to_consume = min(len(rfl.buf), rfl.body_remaining)
            del rfl.buf[:to_consume]
            rfl.body_remaining -= to_consume
            if rfl.body_remaining == 0:
                rfl.state = HTTP_STATE_HEADER
            continue

        if rfl.state == HTTP_STATE_CHUNK:
            if not rfl.buf:
                break
            if rfl.chunk_reading_trailer:
                if len(rfl.buf) >= 2 and rfl.buf[:2] == b"\r\n":
                    del rfl.buf[:2]
                    rfl.chunk_reading_trailer = False
                    rfl.state = HTTP_STATE_HEADER
                    continue
                tr_end = rfl.buf.find(b"\r\n\r\n")
                if tr_end != -1:
                    del rfl.buf[:tr_end + 4]
                    rfl.chunk_reading_trailer = False
                    rfl.state = HTTP_STATE_HEADER
                    continue
                if len(rfl.buf) > MAX_HDRS:
                    rfl.buf = bytearray()
                    rfl.is_broken = True
                break
            if rfl.chunk_reading_len:
                crlf = rfl.buf.find(b"\r\n")
                if crlf == -1:
                    if len(rfl.buf) > 64:
                        rfl.buf = bytearray()
                        rfl.is_broken = True
                    break
                line = bytes(rfl.buf[:crlf]).strip()
                semi = line.find(b";")
                hex_str = line[:semi].strip() if semi != -1 else line
                try:
                    chunk_len = int(hex_str, 16)
                    if chunk_len < 0 or chunk_len > 16777216:
                        rfl.buf = bytearray()
                        rfl.is_broken = True
                        break
                except ValueError:
                    rfl.buf = bytearray()
                    rfl.is_broken = True
                    break
                del rfl.buf[:crlf + 2]
                if chunk_len == 0:
                    rfl.chunk_reading_trailer = True
                    rfl.chunk_reading_len = False
                    continue
                else:
                    rfl.chunk_payload_remaining = chunk_len
                    rfl.chunk_reading_len = False
                    rfl.chunk_reading_crlf = False
            elif getattr(rfl, "chunk_reading_crlf", False):
                if len(rfl.buf) < 2:
                    break
                if rfl.buf[:2] != b"\r\n":
                    rfl.buf = bytearray()
                    rfl.is_broken = True
                    break
                del rfl.buf[:2]
                rfl.chunk_reading_crlf = False
                rfl.chunk_reading_len = True
            else:
                to_consume = min(len(rfl.buf), rfl.chunk_payload_remaining)
                del rfl.buf[:to_consume]
                rfl.chunk_payload_remaining -= to_consume
                if rfl.chunk_payload_remaining == 0:
                    rfl.chunk_reading_crlf = True
            continue

        if rfl.state == HTTP_STATE_CLOSE_BODY:
            del rfl.buf[:]
            break

    if flags & 0x05:
        resp_flows.pop(rk, None)
        pending_pop(rk, out, pending_tbl)


def correlate_response(pending_tbl, rk, payload, now, out, resp_flows=None, seq=None, flags=0, is_truncated=False):
    """Attach one response head to the oldest request on a connection.

    HTTP/1.1 pipelining can leave several requests queued for the same
    four-tuple. Consume exactly one entry; deleting the whole key here loses
    every request after the first response.
    """
    if resp_flows is not None:
        handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                        seq=seq, flags=flags, is_truncated=is_truncated)
        return True
    res = parse_response_head(payload)
    if res[0] is None:
        return False
    st, clen, head_len = res[0], res[1], res[2]
    if 100 <= st <= 199 and st != 101:
        if head_len is not None and len(payload) > head_len:
            return correlate_response(pending_tbl, rk, payload[head_len:], now, out)
        return False
    ent = pending_tbl.get(rk)
    if not ent:
        return False
    ev, started = ent.pop(0)
    if not ent:
        pending_tbl.pop(rk, None)
    ev["status"] = st
    ev["duration_ms"] = max(0, int((now - started) * 1000))
    if clen is not None:
        ev["resp_bytes"] = clen
    out.append(ev)
    return True


def valid_port(p):
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


def basic_user(value):
    """Authorization header value -> (user|None, scheme|None). Basic only."""
    parts = value.strip().split(None, 1)
    if len(parts) != 2:
        return None, None
    scheme = parts[0].lower()
    if scheme == "basic":
        try:
            pad = parts[1].strip()
            if len(pad) > 1024:
                return None, None
            pad += "=" * (-len(pad) % 4)
            raw = base64.b64decode(pad)
            if len(raw) > 512:
                return None, None
            if b":" in raw:
                user = raw.split(b":", 1)[0]
                user = user.decode("utf-8", "replace")[:64]
                if user:
                    return user, "basic"
        except Exception:
            return None, None
    elif scheme == "bearer":
        return None, "bearer"
    return None, None


def normalize_wsse_username(value):
    """Return a small, printable username or None; never return token data."""
    if value is None:
        return None
    try:
        username = value.strip()
    except Exception:
        return None
    if not username or len(username) > MAX_WSSE_USERNAME:
        return None
    for char in username:
        if unicodedata.category(char).startswith("C"):
            return None
    return username


def extract_wsse_username(body):
    """Parse a bounded, possibly partial SOAP prefix and return only Username.

    Expat is run incrementally so a UsernameToken in the SOAP Header can be
    recognized without retaining or requiring the complete request body.
    DTD/entity declarations are rejected before parsing.
    """
    if not body or len(body) > MAX_WSSE_BODY_BYTES or b"\x00" in body:
        return None
    lowered = bytes(body).lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return None

    state = {"stack": [], "token_depth": 0, "username_depth": 0,
             "chars": [], "too_long": False, "result": None}

    def split_name(name):
        if "}" not in name:
            return "", name
        return name.rsplit("}", 1)

    def start(name, attrs):
        namespace, local_name = split_name(name)
        state["stack"].append((namespace, local_name))
        depth = len(state["stack"])
        if (not state["token_depth"] and local_name == "UsernameToken" and
                namespace in WSSE_NAMESPACES):
            state["token_depth"] = depth
        elif (state["token_depth"] and
              depth == state["token_depth"] + 1 and
              local_name == "Username" and
              namespace == state["stack"][state["token_depth"] - 1][0]):
            state["username_depth"] = depth
            state["chars"] = []
            state["too_long"] = False

    def chars(value):
        if not state["username_depth"] or state["too_long"]:
            return
        state["chars"].append(value)
        if sum([len(part) for part in state["chars"]]) > MAX_WSSE_USERNAME + 2:
            state["chars"] = []
            state["too_long"] = True

    def end(name):
        depth = len(state["stack"])
        if state["username_depth"] == depth:
            if not state["too_long"] and state["result"] is None:
                state["result"] = normalize_wsse_username(
                    u"".join(state["chars"]))
            state["username_depth"] = 0
            state["chars"] = []
        if state["token_depth"] == depth:
            state["token_depth"] = 0
        if state["stack"]:
            state["stack"].pop()

    try:
        parser = expat.ParserCreate(None, "}")
        if hasattr(parser, "returns_unicode"):
            parser.returns_unicode = True
        parser.StartElementHandler = start
        parser.CharacterDataHandler = chars
        parser.EndElementHandler = end
        if (hasattr(parser, "SetParamEntityParsing") and
                hasattr(expat, "XML_PARAM_ENTITY_PARSING_NEVER")):
            parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        parser.Parse(bytes(body), False)
    except (expat.ExpatError, ValueError, TypeError):
        # A bounded prefix is commonly incomplete. A username fully closed
        # before the truncation point is still safe to use.
        pass
    return state["result"]


def is_soap_content_type(value):
    if not value:
        return False
    media_type = value.split(";", 1)[0].strip().lower()
    return (media_type in ("text/xml", "application/xml",
                           "application/soap+xml") or
            media_type.endswith("+xml"))


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
        "basic_user": user if scheme == "basic" and user else None,
        "wsse_user": None,
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
    # Preserve response correlation only for monitored destinations. The
    # response-side filter may still admit a client ephemeral sport equal to a
    # monitored port; this is harmless because parse_response_head rejects it.
    return ev if (dport in ports or h.get("_method")) else None


def _emit_request(flows, key, fl, meta, out, pending_tbl, now):
    """Discard capture buffers, then emit/queue the sanitized event only."""
    dst_ip, dport, src_ip, sport = meta
    ev = fl.wsse_event if fl.awaiting_wsse else fl.event
    fl.awaiting_wsse = False
    flows.pop(key, None)
    if not ev:
        return
    ev["req_bytes"] = fl.head_bytes
    if pending_tbl is None:
        out.append(ev)
        return
    rk = (dst_ip, dport, src_ip, sport)
    verified = (fl.generation > 0)
    if is_correlation_disabled(rk, verified):
        out.append(ev)
        return
    ent = pending_tbl.get(rk)
    if ent is None:
        if len(pending_tbl) >= PENDING_MAX:
            _flush_oldest_pending(pending_tbl, out)
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)
        corr_disabled_insert(rk)
        out.append(ev)
        return
    started = fl.first_byte_ts if fl.first_byte_ts > 0 else (now if now is not None else time.time())
    ent.append([ev, started])


def _emit_request_to_pending(ev, head_bytes, first_byte_ts, meta, out, pending_tbl, now, generation=0):
    dst_ip, dport, src_ip, sport = meta
    if not ev:
        return
    ev["req_bytes"] = head_bytes
    if pending_tbl is None:
        out.append(ev)
        return
    rk = (dst_ip, dport, src_ip, sport)
    verified = (generation > 0)
    if is_correlation_disabled(rk, verified):
        out.append(ev)
        return
    ent = pending_tbl.get(rk)
    if ent is None:
        if len(pending_tbl) >= PENDING_MAX:
            _flush_oldest_pending(pending_tbl, out)
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)
        corr_disabled_insert(rk)
        out.append(ev)
        return
    started = first_byte_ts if first_byte_ts > 0 else (now if now is not None else time.time())
    ent.append([ev, started, False, 0.0, generation])




def _try_wsse_body(flows, key, fl, payload, meta, out, pending_tbl, now):
    """Append no more than body_goal bytes and finish as soon as possible."""
    remaining = fl.wsse_goal - len(fl.wsse_buf)
    if remaining > 0 and payload:
        copy_len = min(remaining, len(payload))
        fl.wsse_buf.extend(bytearray(payload[:copy_len]))
    username = extract_wsse_username(fl.wsse_buf)
    if username:
        fl.wsse_event["wsse_user"] = username
        fl.wsse_event["user"] = username
        fl.wsse_event["scheme"] = "wsse"
    if username or len(fl.wsse_buf) >= fl.wsse_goal:
        _emit_request_to_pending(fl.wsse_event, fl.head_bytes, fl.first_byte_ts,
                                 meta, out, pending_tbl, now, generation=fl.generation)
        fl.awaiting_wsse = False
        return True
    return False


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out,
                   pending_tbl=None, now=None, wsse_body_bytes=0,
                   seq=None, flags=0, is_truncated=False, resp_flows=None):
    dst_ip, dport, src_ip, sport = meta
    if not valid_port(dport) or not valid_port(sport):
        return
    if now is None:
        now = time.time()

    # SYN handling: reset flow and start sequence tracking
    if flags & 0x02 and seq is not None:
        fl = flows.get(key)
        if fl is not None and fl.awaiting_wsse and fl.wsse_event:
            out.append(fl.wsse_event)
            fl.awaiting_wsse = False
        rk = (dst_ip, dport, src_ip, sport)
        corr_disabled_erase(rk)

        if pending_tbl is not None:
            ent = pending_tbl.pop(rk, None)
            if ent:
                for item in ent:
                    is_tomb = item[2] if len(item) > 2 else False
                    if not is_tomb:
                        out.append(item[0])

        if resp_flows is not None and rk in resp_flows:
            resp_flows.pop(rk, None)
        if rev_key is not None and rev_key in flows:
            flows.pop(rev_key, None)

        old_gen = fl.generation if fl is not None else 0
        fl = Flow()
        fl.generation = old_gen + 1
        fl.has_seq = True
        fl.next_seq = (seq + 1) & 0xFFFFFFFF
        fl.touched = now
        fl.first_byte_ts = 0.0
        flows[key] = fl
        return

    fl = flows.get(key)
    if fl is None:
        fl = Flow()
        flows[key] = fl
        if len(flows) > MAX_FLOWS:
            enforce_limit(flows, now)
    fl.touched = now

    # Check keep-alive request transition while waiting for body in direct test feed mode
    if seq is None and fl.awaiting_wsse and payload and is_method_or_prefix(payload):
        _emit_request_to_pending(fl.wsse_event, fl.head_bytes, fl.first_byte_ts,
                                 meta, out, pending_tbl, now)
        fl.awaiting_wsse = False
        fl.state = HTTP_STATE_HEADER
        fl.buf = bytearray()

    plen = len(payload) if payload else 0
    if plen > 0:
        if seq is None:
            fl.buf.extend(payload)
        else:
            if not fl.has_seq:
                if is_method_or_prefix(payload):
                    fl.has_seq = True
                    fl.next_seq = seq
                    fl.is_broken = False
                else:
                    if len(fl.ooo) < MAX_OOO_SEGMENTS and not is_truncated:
                        if not any(s == seq for s, _ in fl.ooo):
                            fl.ooo.append((seq, bytes(payload)))
                    return

            diff = seq_diff(seq, fl.next_seq)
            if diff == 0:
                if is_truncated:
                    fl.is_broken = True
                else:
                    fl.buf.extend(payload)
                    fl.next_seq = (fl.next_seq + plen) & 0xFFFFFFFF
                    _drain_ooo(fl)
            elif diff < 0:
                overlap = -diff
                if overlap < plen and not is_truncated:
                    fl.buf.extend(payload[overlap:])
                    fl.next_seq = (fl.next_seq + plen - overlap) & 0xFFFFFFFF
                    _drain_ooo(fl)
            else:
                if len(fl.ooo) < MAX_OOO_SEGMENTS and not is_truncated:
                    if not any(s == seq for s, _ in fl.ooo):
                        fl.ooo.append((seq, bytes(payload)))
                else:
                    fl.is_broken = True

    # HTTP framing state machine
    while len(fl.buf) > 0 and not fl.is_broken:
        if fl.state == HTTP_STATE_HEADER:
            if not fl.first_byte_ts:
                fl.first_byte_ts = now

            idx = fl.buf.find(b"\r\n\r\n")
            if idx < 0:
                if len(fl.buf) > MAX_HDRS:
                    fl.buf = bytearray()
                    fl.is_broken = True
                break
            start = find_http_start(fl.buf)
            if start < 0 or start > idx:
                del fl.buf[:idx + 4]
                continue
            if start > 0:
                del fl.buf[:start]
                idx -= start

            head = bytes(fl.buf[:idx])
            lines = head.replace(b"\r\n", b"\n").split(b"\n")
            first = lines[0].strip().split()
            if len(first) < 2 or first[0].decode("ascii", "replace") not in METHODS:
                del fl.buf[:idx + 4]
                continue
            hdrs = {}
            hdrs["_method"] = first[0].decode("ascii", "replace")
            hdrs["_path"] = first[1].decode("ascii", "replace")
            has_conflict_cl = False
            first_cl = None
            for ln in lines[1:]:
                if b":" not in ln:
                    continue
                kn, kv = ln.split(b":", 1)
                k_norm = kn.strip().lower().decode("ascii", "replace")
                v_norm = kv.strip().decode("utf-8", "replace")[:180]
                if k_norm == "content-length":
                    try:
                        parsed_cl = int(v_norm)
                        if parsed_cl < 0:
                            has_conflict_cl = True
                        elif first_cl is None:
                            first_cl = parsed_cl
                        elif first_cl != parsed_cl:
                            has_conflict_cl = True
                    except ValueError:
                        has_conflict_cl = True
                hdrs[k_norm] = v_norm
            fl.hdrs = hdrs
            fl.event = finish_event(fl, key, dst_ip, dport, src_ip, sport, ports, node_host)
            fl.head_bytes = idx + 4
            del fl.buf[:idx + 4]

            if not fl.event:
                continue

            try:
                content_length = int(hdrs.get("content-length", "0"))
            except (ValueError, TypeError):
                content_length = 0
            te = hdrs.get("transfer-encoding", "").lower()
            is_chunked = "chunked" in te

            if has_conflict_cl or (content_length > 0 and is_chunked) or ("content-length" in hdrs and is_chunked):
                fl.buf = bytearray()
                fl.is_broken = True
                break

            active_body_flows = sum(1 for cand in flows.values() if cand.awaiting_wsse or (cand.event is not None and getattr(cand, "body_goal", 0) > 0))
            wsse_eligible = (wsse_body_bytes > 0 and
                             is_soap_content_type(hdrs.get("content-type")) and
                             content_length > 0 and
                             not is_chunked and
                             active_body_flows < MAX_WSSE_BODY_FLOWS)

            if wsse_eligible:
                fl.awaiting_wsse = True
                fl.wsse_event = fl.event
                fl.wsse_buf = bytearray()
                fl.wsse_goal = min(content_length, wsse_body_bytes, MAX_WSSE_BODY_BYTES)
            else:
                _emit_request_to_pending(fl.event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now, generation=fl.generation)
            fl.event = None

            if content_length > 0:
                fl.state = HTTP_STATE_BODY
                fl.body_remaining = content_length
            elif is_chunked:
                fl.state = HTTP_STATE_CHUNK
                fl.chunk_reading_len = True
                fl.chunk_reading_crlf = False
                fl.chunk_reading_trailer = False
                fl.chunk_payload_remaining = 0
            else:
                fl.state = HTTP_STATE_HEADER
                fl.first_byte_ts = now if fl.buf else 0.0
            continue

        elif fl.state == HTTP_STATE_BODY:
            if not fl.buf:
                break
            to_consume = min(len(fl.buf), fl.body_remaining)
            if fl.awaiting_wsse:
                wsse_need = fl.wsse_goal - len(fl.wsse_buf)
                if wsse_need > 0:
                    copy_len = min(to_consume, wsse_need)
                    fl.wsse_buf.extend(fl.buf[:copy_len])
                username = extract_wsse_username(fl.wsse_buf)
                if username or len(fl.wsse_buf) >= fl.wsse_goal:
                    ev = fl.wsse_event
                    if username:
                        ev["wsse_user"] = username
                        ev["user"] = username
                        ev["scheme"] = "wsse"
                    _emit_request_to_pending(ev, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now, generation=fl.generation)
                    fl.awaiting_wsse = False

            del fl.buf[:to_consume]
            fl.body_remaining -= to_consume
            if fl.body_remaining == 0:
                if fl.awaiting_wsse:
                    _emit_request_to_pending(fl.wsse_event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now, generation=fl.generation)
                    fl.awaiting_wsse = False
                fl.state = HTTP_STATE_HEADER
                fl.first_byte_ts = now if fl.buf else 0.0
            continue

        elif fl.state == HTTP_STATE_CHUNK:
            if not fl.buf:
                break
            if fl.chunk_reading_trailer:
                if len(fl.buf) >= 2 and fl.buf[:2] == b"\r\n":
                    del fl.buf[:2]
                    fl.chunk_reading_trailer = False
                    fl.state = HTTP_STATE_HEADER
                    fl.first_byte_ts = now if fl.buf else 0.0
                    continue
                tr_end = fl.buf.find(b"\r\n\r\n")
                if tr_end != -1:
                    del fl.buf[:tr_end + 4]
                    fl.chunk_reading_trailer = False
                    fl.state = HTTP_STATE_HEADER
                    fl.first_byte_ts = now if fl.buf else 0.0
                    continue
                if len(fl.buf) > MAX_HDRS:
                    fl.buf = bytearray()
                    fl.is_broken = True
                break
            if fl.chunk_reading_len:
                crlf = fl.buf.find(b"\r\n")
                if crlf < 0:
                    if len(fl.buf) > 64:
                        fl.buf = bytearray()
                        fl.is_broken = True
                    break
                line = bytes(fl.buf[:crlf]).strip()
                semi = line.find(b";")
                hex_str = line[:semi].strip() if semi != -1 else line
                if len(hex_str) > 16:
                    fl.buf = bytearray()
                    fl.is_broken = True
                    break
                try:
                    chunk_len = int(hex_str, 16)
                    if chunk_len < 0 or chunk_len > 0x7FFFFFFF:
                        fl.buf = bytearray()
                        fl.is_broken = True
                        break
                except ValueError:
                    fl.buf = bytearray()
                    fl.is_broken = True
                    break
                del fl.buf[:crlf + 2]
                if chunk_len == 0:
                    fl.chunk_reading_trailer = True
                    fl.chunk_reading_len = False
                    continue
                else:
                    fl.chunk_payload_remaining = chunk_len
                    fl.chunk_reading_len = False
                    fl.chunk_reading_crlf = False
            elif fl.chunk_reading_crlf:
                if len(fl.buf) < 2:
                    break
                if fl.buf[:2] != b"\r\n":
                    fl.buf = bytearray()
                    fl.is_broken = True
                    break
                del fl.buf[:2]
                fl.chunk_reading_crlf = False
                fl.chunk_reading_len = True
            else:
                to_consume = min(len(fl.buf), fl.chunk_payload_remaining)
                del fl.buf[:to_consume]
                fl.chunk_payload_remaining -= to_consume
                if fl.chunk_payload_remaining == 0:
                    fl.chunk_reading_crlf = True
            continue

    if flags & 0x05:
        if fl.awaiting_wsse and fl.wsse_event:
            _emit_request_to_pending(fl.wsse_event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now)
            fl.awaiting_wsse = False
        flows.pop(key, None)
    elif seq is None and fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo and not fl.awaiting_wsse:
        flows.pop(key, None)


def sweep_idle(flows, now, out=None, pending_tbl=None, resp_flows=None):
    stale = []
    for k, fl in flows.items():
        if now - fl.touched > FLOW_TTL:
            stale.append(k)
    for k in stale:
        fl = flows.get(k)
        if fl is not None and fl.awaiting_wsse and fl.wsse_event is not None:
            if out is not None:
                out.append(fl.wsse_event)
            fl.awaiting_wsse = False
        flows.pop(k, None)
    if resp_flows is not None:
        rstale = [k for k, rfl in resp_flows.items() if now - rfl.touched > FLOW_TTL]
        for k in rstale:
            resp_flows.pop(k, None)


def drain_incomplete_wsse(flows, out, pending_tbl, now=None):
    """Fall back to emitting the request event if WSSE inspection was incomplete."""
    if now is None:
        now = time.time()
    for key in list(flows.keys()):
        fl = flows.get(key)
        if fl is None:
            continue
        if fl.awaiting_wsse and fl.wsse_event is not None:
            out.append(fl.wsse_event)
            fl.awaiting_wsse = False
        flows.pop(key, None)


def process_packet(pkt, ports, node_host, flows, resp_flows, pending_tbl, out, now=None, wsse_body_bytes=0):
    n = len(pkt)
    if n < 34:
        return False
    if now is None:
        now = time.time()
    off = 14
    etype = struct.unpack("!H", pkt[12:14])[0]
    if etype == ETH_P_VLAN:
        if n < 38:
            return False
        etype = struct.unpack("!H", pkt[16:18])[0]
        off = 18
    elif etype != ETH_P_IP:
        return False

    ip0 = b2i(pkt[off])
    if (ip0 >> 4) != 4 or b2i(pkt[off + 9]) != 6:
        return False
    ihl = (ip0 & 0x0F) * 4
    if ihl < 20 or n < off + ihl + 20:
        return False

    frag = struct.unpack("!H", pkt[off + 6:off + 8])[0]
    if frag & 0x1FFF:
        return False

    ip_total_len = struct.unpack("!H", pkt[off + 2:off + 4])[0]
    is_truncated = False
    if ip_total_len > 0:
        if ip_total_len < ihl + 20:
            return False
        if n - off < ip_total_len:
            is_truncated = True
        elif n - off > ip_total_len:
            n = off + ip_total_len

    src_ip = socket.inet_ntoa(pkt[off + 12:off + 16])
    dst_ip = socket.inet_ntoa(pkt[off + 16:off + 20])
    tcp_off = off + ihl
    sport, dport = struct.unpack("!HH", pkt[tcp_off:tcp_off + 4])
    seq = struct.unpack("!I", pkt[tcp_off + 4:tcp_off + 8])[0]
    doff_byte = b2i(pkt[tcp_off + 12])
    doff = (doff_byte >> 4) * 4
    if doff < 20 or n < tcp_off + doff:
        return False

    flags = b2i(pkt[tcp_off + 13])
    pay_start = tcp_off + doff
    payload = pkt[pay_start:n] if n > pay_start else b""

    # Response direction: Server -> Client
    if sport in ports and dport not in ports:
        rk = (src_ip, sport, dst_ip, dport)
        handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                        seq=seq, flags=flags, is_truncated=is_truncated)
        return True

    # Request direction: Client -> Server
    elif dport in ports:
        key = (src_ip, sport, dst_ip, dport)
        meta = (dst_ip, dport, src_ip, sport)
        handle_payload(flows, key, None, payload, meta, ports, node_host, out,
                       pending_tbl, now, wsse_body_bytes,
                       seq=seq, flags=flags, is_truncated=is_truncated,
                       resp_flows=resp_flows)

        return True

    return False


def _flush_oldest_pending(pending_tbl, out):
    """Overflow guard: emit all events for the oldest pending key and lock it out."""
    oldest_key, oldest_ts = None, None
    for rk, lst in pending_tbl.items():
        if not lst:
            continue
        ts = lst[0][1]
        if oldest_ts is None or ts < oldest_ts:
            oldest_key, oldest_ts = rk, ts
    if oldest_key is not None:
        while pending_tbl.get(oldest_key):
            pending_pop(oldest_key, out, pending_tbl)
        corr_disabled_insert(oldest_key)
        pending_tbl.pop(oldest_key, None)


def sweep_pending(pending_tbl, now, out):
    """TTL flush: emit requests whose responses never showed up."""
    for rk in list(pending_tbl.keys()):
        lst = pending_tbl.get(rk)
        if not lst:
            continue
        i = 0
        while i < len(lst):
            item = lst[i]
            is_tomb = item[2] if len(item) > 2 else False
            tomb_ts = item[3] if len(item) > 3 else 0.0
            if is_tomb:
                if now - tomb_ts > 10.0:
                    # Tombstone expired un-consumed: ordering is now ambiguous.
                    # Flush all remaining entries immediately and persistently
                    # disable response correlation for this connection until SYN.
                    lst.pop(i)
                    while i < len(lst):
                        tail = lst[i]
                        tail_tomb = tail[2] if len(tail) > 2 else False
                        if not tail_tomb:
                            out.append(tail[0])
                        lst.pop(i)
                    corr_disabled_insert(rk)
                    # Leave i unchanged; the while condition will exit naturally
                else:
                    i += 1
            elif now - item[1] > PENDING_TTL:
                out.append(item[0])
                if len(item) > 3:
                    item[2] = True
                    item[3] = now
                else:
                    item.extend([True, now, 0])
                i += 1
            else:
                i += 1
        if not lst:
            pending_tbl.pop(rk, None)



def drain_pending(pending_tbl, out):
    """Emit every captured request before capture shutdown.

    Responses are optional enrichment. A stop/restart must not discard a
    request merely because its response was filtered, split, or still in
    flight when the process received SIGTERM.
    """
    for rk in list(pending_tbl.keys()):
        lst = pending_tbl.pop(rk, None)
        if lst:
            for item in lst:
                is_tomb = item[2] if len(item) > 2 else False
                if not is_tomb:
                    out.append(item[0])
    corr_disabled_clear()




def maintenance_due(now, last_sweep):
    return now - last_sweep >= SWEEP_INTERVAL


def enforce_limit(flows, now):
    """Cap flow-table size (py2.6: no OrderedDict — sweep stale, then FIFO
    by insertion order, which plain dicts preserve in CPython)."""
    sweep_idle(flows, now)
    while len(flows) > MAX_FLOWS:
        flows.popitem()          # oldest-inserted key on CPython 2.6/2.7


def _control_config():
    """Read optional control settings without exposing the bearer token."""
    endpoint = os.environ.get("NT_CONTROL_ENDPOINT") or os.environ.get("NT_ENDPOINT")
    token_file = os.environ.get("NT_CONTROL_TOKEN_FILE", "")
    token = os.environ.get("NT_CONTROL_TOKEN", "")
    if token_file:
        try:
            f = open(token_file, "r")
            try:
                token = f.read().strip()
            finally:
                f.close()
        except IOError:
            token = ""
    node = os.environ.get("NT_NODE_NAME") or socket.gethostname().split(".")[0]
    run_dir = os.environ.get("NT_CONTROL_RUN", "/var/lib/networktracing")
    try:
        interval = max(5, min(int(os.environ.get("NT_CONTROL_SEC", "30")), 300))
    except ValueError:
        interval = 30
    return endpoint, token, node, run_dir, interval


def _run_control_tick(ports, iface, run_dir, client):
    reply = client.poll()
    if not reply:
        return ports, iface, None, "poll failed"
    desired = reply.get("desired") or {}
    state = dict(desired)
    generation = desired.get("generation", 0)
    control_action = None
    stop_requested = False
    if desired.get("ports"):
        new_ports = set(desired["ports"])
        if new_ports != ports:
            ports = new_ports
            control_action = "restart"
    if desired.get("iface"):
        new_iface = desired["iface"]
        if new_iface != iface:
            iface = new_iface
            control_action = "restart"
    for task in reply.get("tasks", []):
        action = task.get("action")
        if action == "health":
            message = "healthy"
            status = "done"
        elif action in ("restart", "reload", "set_ports"):
            message = "accepted; capture restart requested"
            status = "done"
            control_action = "restart"
            if action == "set_ports":
                args = task.get("args") or {}
                if args.get("ports"):
                    ports = set(args["ports"])
                    state.update({"ports": sorted(ports), "mode": "python",
                                  "generation": generation})
        elif action == "stop":
            message = "stop requested"
            status = "done"
            stop_requested = True
        else:
            message = "unsupported by direct sniffer"
            status = "failed"
        client.report(task.get("id"), status, message)
    if stop_requested:
        control_action = "stop"
    applied = ("stop requested" if control_action == "stop" else
               "restart required" if control_action == "restart" else
               "poll ok")
    nt_control.write_state(os.path.join(run_dir, "remote-desired.json"),
                           state, applied)
    client.heartbeat(generation, applied)
    return ports, iface, control_action, applied


def _restart_args(script, iface, ports, verbose, workers, wsse_body_bytes=0):
    """Build a fresh argv for an in-place re-exec after a control update."""
    # Preserve unbuffered JSONL delivery; the installer starts Python with -u.
    args = [sys.executable, "-u", os.path.abspath(script)]
    if iface:
        args.extend(["-i", iface])
    args.extend(["-p", ",".join([str(p) for p in sorted(ports)])])
    args.extend(["-j", "1"])
    if wsse_body_bytes:
        args.extend(["--wsse-body-bytes", str(wsse_body_bytes)])
    if verbose:
        args.append("-v")
    return args


def main():
    iface, ports, verbose, workers, wsse_body_bytes = parse_args(sys.argv[1:])
    node_host = socket.gethostname().split(".")[0]
    control_client = None
    endpoint, token, control_node, control_run, control_interval = _control_config()
    if nt_control is not None and endpoint and token:
        try:
            control_client = nt_control.ControlClient(endpoint, token, control_node)
            if not os.path.isdir(control_run):
                os.makedirs(control_run)
            log("remote control enabled")
        except Exception as e:
            log("WARN: remote control disabled (%s)" % nt_control.safe_message(e))

    try:
        # protocol MUST be htons(ETH_P_ALL) to receive both INGRESS (req) and
        # EGRESS (resp) packets on Linux kernel packet sockets.
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
    except AttributeError:
        raise SystemExit("AF_PACKET unavailable on this platform")
    except socket.error as e:
        raise SystemExit("cannot open AF_PACKET socket (%s) — need "
                         "CAP_NET_RAW / root" % e)
    s.settimeout(1.0)
    if not apply_perf_opts(s, ports):
        s.close()
        raise SystemExit("kernel BPF safety filter unavailable; refusing unfiltered capture")
    try:
        s.bind((iface or "", ETH_P_ALL))
    except socket.error as e:
        s.close()
        raise SystemExit("cannot bind AF_PACKET to %s (%s)" %
                         (iface or "<all>", e))
    if not drop_capture_capabilities():
        s.close()
        raise SystemExit("cannot drop CAP_NET_RAW after socket setup; refusing unsafe capture")

    # precompiled struct readers — unpack_from reads straight out of the
    # packet buffer (no slice copies) and yields ints under py2 AND py3
    u16 = struct.Struct("!H").unpack_from
    uh = struct.Struct("!HH").unpack_from   # sport,dport in one read
    ub = struct.Struct("!BB").unpack_from
    ntoa = socket.inet_ntoa

    flows = {}
    resp_flows = {}
    running = [True]
    stats_interval = stats_interval_seconds()
    stats_state = {"packets_total": 0, "packet_bytes_total": 0,
                   "events_emitted_total": 0, "kernel_drops_total": 0,
                   "last_packets": 0, "last_packet_bytes": 0,
                   "last_events": 0, "last_at": time.time()}

    def write_events(items):
        if not items:
            return
        w = sys.stdout.write
        for item in items:
            w(json.dumps(item) + "\n")
        sys.stdout.flush()
        stats_state["events_emitted_total"] += len(items)

    def emit_capture_stats(force=False):
        now = time.time()
        elapsed = now - stats_state["last_at"]
        if not force and elapsed < stats_interval:
            return
        dropped_delta = 0
        try:
            raw_stats = s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            _, dropped_delta = struct.unpack("II", raw_stats[:8])
        except (socket.error, struct.error):
            dropped_delta = 0
        stats_state["kernel_drops_total"] += dropped_delta
        packets_delta = (stats_state["packets_total"] -
                         stats_state["last_packets"])
        bytes_delta = (stats_state["packet_bytes_total"] -
                       stats_state["last_packet_bytes"])
        events_delta = (stats_state["events_emitted_total"] -
                        stats_state["last_events"])
        waiting_wsse = 0
        for flow in flows.values():
            if flow.event is not None and flow.body_goal:
                waiting_wsse += 1
        pending_count = sum(len(items) for items in pending.values())
        drop_pct = 100.0 * dropped_delta / max(1, packets_delta)
        capture = {
            "packets_total": stats_state["packets_total"],
            "packets_delta": packets_delta,
            "packet_bytes_total": stats_state["packet_bytes_total"],
            "packet_bytes_delta": bytes_delta,
            "kernel_drops_total": stats_state["kernel_drops_total"],
            "kernel_drops_delta": dropped_delta,
            "kernel_drop_percent": round(drop_pct, 4),
            "invalid_frames_total": 0,
            "events_emitted_total": stats_state["events_emitted_total"],
            "events_emitted_delta": events_delta,
            "flows_active": len(flows),
            "pending_requests": pending_count,
            "wsse_body_flows_active": waiting_wsse}
        sys.stdout.write(json.dumps({"_nt_internal": "capture_stats_v1",
                                     "capture": capture},
                                    separators=(",", ":")) + "\n")
        sys.stdout.flush()
        stats_state["last_packets"] = stats_state["packets_total"]
        stats_state["last_packet_bytes"] = stats_state["packet_bytes_total"]
        stats_state["last_events"] = stats_state["events_emitted_total"]
        stats_state["last_at"] = now

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    last_sweep = time.time()
    control_next = time.time()
    log("listening on %s ports=%s pid=%d" %
        (iface or "<all>", sorted(ports), os.getpid()))
    if wsse_body_bytes:
        log("WSSE UsernameToken inspection enabled (bounded to %d bytes/request)" %
            wsse_body_bytes)

    # 1s recv timeout: (a) lets the pending/flow sweeps actually fire —
    # without it `except socket.timeout` never runs; (b) empirically REQUIRED
    # with the BPF filter attached: a fully-blocking recv on this kernel
    # starves after the first packet, while the timeout'd recv delivers
    # continuously (verified by A/B: rx=1 vs rx=29 identical otherwise).
    s.settimeout(1.0)

    dbg = os.environ.get("NT_SNIFF_DEBUG") == "1"
    dbg_rx = 0
    dbg_last = time.time()
    while running[0]:
        emit_capture_stats()
        # Poll independently of socket idle time. A busy monitored interface
        # may never raise socket.timeout, but control changes must still apply.
        if control_client is not None and time.time() >= control_next:
            try:
                ports, iface, control_action, control_status = _run_control_tick(
                    ports, iface, control_run, control_client)
                log("remote control: %s" % control_status)
                if control_action == "restart":
                    args = _restart_args(sys.argv[0], iface, ports,
                                         verbose, workers, wsse_body_bytes)
                    log("remote control: re-executing capture with updated configuration")
                    s.close()
                    os.execv(sys.executable, args)
                elif control_action == "stop":
                    log("remote control: stop requested; exiting")
                    running[0] = False
                    continue
            except Exception as e:
                log("WARN: remote control tick failed (%s)" % nt_control.safe_message(e))
            control_next = time.time() + control_interval
        try:
            pkt = s.recv(65535)
            dbg_rx += 1
            stats_state["packets_total"] += 1
            stats_state["packet_bytes_total"] += len(pkt)
            if dbg and time.time() - dbg_last > 5:
                log("DEBUG rx=%d" % dbg_rx)
                dbg_last = time.time()
        except socket.timeout:
            if dbg:
                log("DEBUG timeout rx=%d" % dbg_rx)
                dbg_last = time.time()
            now = time.time()
            if maintenance_due(now, last_sweep):
                out_s = []
                sweep_idle(flows, now, out_s, pending, resp_flows)
                sweep_pending(pending, now, out_s)
                write_events(out_s)
                last_sweep = now
            continue
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise

        now = time.time()
        out = []
        process_packet(pkt, ports, node_host, flows, resp_flows, pending,
                       out, now, wsse_body_bytes)
        if out:
            write_events(out)

        if maintenance_due(now, last_sweep):
            out_s = []
            sweep_idle(flows, now, out_s, pending, resp_flows)
            sweep_pending(pending, now, out_s)
            write_events(out_s)
            last_sweep = now

    out_s = []
    drain_incomplete_wsse(flows, out_s, pending, time.time())
    drain_pending(pending, out_s)
    write_events(out_s)
    emit_capture_stats(force=True)
    log("stopped (%d pending requests flushed)" % len(out_s))


if __name__ == "__main__":
    main()
