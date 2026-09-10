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
METHODS_BYTES = set((b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"))

_STRUCT_B = struct.Struct("!B")
_STRUCT_H = struct.Struct("!H")
_STRUCT_HH = struct.Struct("!HH")
_STRUCT_I = struct.Struct("!I")

_IP_CACHE = {}


def _fast_inet_ntoa(raw4):
    ip = _IP_CACHE.get(raw4)
    if ip is None:
        if len(_IP_CACHE) > 4096:
            _IP_CACHE.clear()
        ip = socket.inet_ntoa(raw4)
        _IP_CACHE[raw4] = ip
    return ip


g_wsse_active_flows = 0


def reset_wsse_active_flows():
    global g_wsse_active_flows
    g_wsse_active_flows = 0


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
    """Irreversibly drop root privileges and clear CAP_NET_RAW after socket setup."""
    try:
        import os, pwd
        if os.getuid() == 0 or os.geteuid() == 0:
            target_user = os.environ.get("NT_USER", "ntsniff")
            try:
                pw = pwd.getpwnam(target_user)
            except KeyError:
                try:
                    pw = pwd.getpwnam("nobody")
                except KeyError:
                    return False
            try:
                os.setgroups([])
            except Exception:
                pass
            try:
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
            except Exception:
                return False
    except Exception:
        return False

    try:
        import ctypes
        libcap = ctypes.CDLL("libcap.so.2")
        libcap.cap_init.restype = ctypes.c_void_p
        empty = libcap.cap_init()
        if not empty:
            return False
        try:
            return libcap.cap_set_proc(ctypes.c_void_p(empty)) == 0 and os.getuid() != 0 and os.geteuid() != 0
        finally:
            libcap.cap_free(ctypes.c_void_p(empty))
    except Exception:
        return os.getuid() != 0 and os.geteuid() != 0


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
HTTP_STATE_UNSYNCED = 4

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
    p = payload[:8]
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        if p.startswith(m[:len(p)]):
            return True
    return False


def find_http_start(buf):
    best = -1
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        pos = buf.find(m)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


_RESYNC_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def find_request_resync_py(payload):
    scan_limit = min(len(payload), 16384)
    sub = bytes(payload[:scan_limit])
    best = None
    # First prefer a complete method.
    for m in _RESYNC_METHODS:
        pos = sub.find(m)
        if pos != -1 and (best is None or pos < best):
            best = pos
    if best is not None:
        return best
    # Then allow a method beginning near the end and continuing into next segment
    for m in _RESYNC_METHODS:
        mlen = len(m)
        for prefix_len in range(1, mlen):
            if prefix_len > scan_limit:
                continue
            off = scan_limit - prefix_len
            if sub[off:] == m[:prefix_len]:
                return off
    return None


def find_response_resync_py(payload):
    scan_limit = min(len(payload), 16384)
    sub = bytes(payload[:scan_limit])
    pos = sub.find(b"HTTP/")
    if pos != -1:
        return pos
    for n in range(4, 0, -1):
        if n <= scan_limit:
            off = scan_limit - n
            if sub[off:] == b"HTTP/"[:n]:
                return off
    return None


class Flow(object):
    __slots__ = ("next_seq", "has_seq", "is_broken", "touched", "first_byte_ts",
                 "buf", "ooo", "state", "body_remaining", "chunk_remaining",
                 "chunk_payload_remaining", "chunk_reading_len", "chunk_reading_crlf",
                 "chunk_reading_trailer", "_awaiting_wsse", "wsse_event", "wsse_buf",
                 "wsse_goal", "wsse_req_id", "wsse_rk", "event", "hdrs", "head_bytes",
                 "_body_goal", "generation", "syn_seen", "corr_eligible",
                 "fin_seen", "fin_seq", "wsse_last_parsed_len", "client_isn")

    def __init__(self):
        self.next_seq = 0
        self.has_seq = False
        self.is_broken = False
        self.client_isn = None
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
        self._awaiting_wsse = False
        self.wsse_event = None
        self.wsse_buf = bytearray()
        self.wsse_goal = 0
        self.wsse_req_id = 0
        self.wsse_rk = None
        self.event = None
        self.hdrs = None
        self.head_bytes = 0
        self._body_goal = 0
        self.generation = 0
        self.syn_seen = False
        self.corr_eligible = True
        self.fin_seen = False
        self.fin_seq = 0
        self.wsse_last_parsed_len = 0

    @property
    def awaiting_wsse(self):
        return self._awaiting_wsse

    @awaiting_wsse.setter
    def awaiting_wsse(self, val):
        global g_wsse_active_flows
        v = bool(val)
        if self._awaiting_wsse != v:
            old_active = self._awaiting_wsse or (self._body_goal > 0)
            self._awaiting_wsse = v
            new_active = self._awaiting_wsse or (self._body_goal > 0)
            if old_active != new_active:
                if new_active:
                    g_wsse_active_flows += 1
                elif g_wsse_active_flows > 0:
                    g_wsse_active_flows -= 1

    @property
    def body_goal(self):
        return self._body_goal

    @body_goal.setter
    def body_goal(self, val):
        global g_wsse_active_flows
        v = int(val) if val else 0
        if self._body_goal != v:
            old_active = self._awaiting_wsse or (self._body_goal > 0)
            self._body_goal = v
            new_active = self._awaiting_wsse or (self._body_goal > 0)
            if old_active != new_active:
                if new_active:
                    g_wsse_active_flows += 1
                elif g_wsse_active_flows > 0:
                    g_wsse_active_flows -= 1

    def __del__(self):
        global g_wsse_active_flows
        if getattr(self, "_awaiting_wsse", False) or getattr(self, "_body_goal", 0) > 0:
            if g_wsse_active_flows > 0:
                g_wsse_active_flows -= 1

    def reset_for_new_connection(self, next_gen, now=None, syn_seen=True, corr_eligible=True):
        self.next_seq = 0
        self.has_seq = False
        self.is_broken = False
        self.touched = time.time() if now is None else now
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
        self.wsse_req_id = 0
        self.wsse_rk = None
        self.event = None
        self.hdrs = None
        self.head_bytes = 0
        self.body_goal = 0
        self.generation = next_gen
        self.syn_seen = syn_seen
        self.corr_eligible = corr_eligible
        self.fin_seen = False
        self.fin_seq = 0
        self.wsse_last_parsed_len = 0


def _ooo_insert(fl, seq, payload, is_truncated=False):
    if is_truncated:
        return True
    b_pay = bytes(payload)
    plen = len(b_pay)
    for i, (s, d) in enumerate(fl.ooo):
        if s == seq:
            old_len = len(d)
            common = min(old_len, plen)
            if common and d[:common] != b_pay[:common]:
                return False
            if old_len >= plen:
                return True
            fl.ooo[i] = (seq, b_pay)
            return True
    if len(fl.ooo) >= MAX_OOO_SEGMENTS:
        return False
    fl.ooo.append((seq, b_pay))
    return True


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


def seq_in_window(seq, base, window):
    return 0 <= seq_diff(seq, base) < window


DEFAULT_PENDING_TTL = 30.0
try:
    PENDING_TTL = float(os.getenv("NT_PENDING_TTL_SEC", "30.0"))
except (ValueError, TypeError):
    PENDING_TTL = DEFAULT_PENDING_TTL
PENDING_MAX = 8192       # hard cap; overflow flushes oldest first
PENDING_PER_FLOW = 32    # bound a single pipelined/hostile keep-alive flow
SWEEP_INTERVAL = 1.0     # honor PENDING_TTL even when the socket goes idle

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


def invalidate_connection_correlation(flows, resp_flows, rk):
    corr_disabled_insert(rk)
    if resp_flows is not None:
        rfl = resp_flows.get(rk)
        if rfl is not None:
            rfl.corr_eligible = False
            rfl.is_broken = False
            rfl.has_seq = False
            del rfl.buf[:]
            del rfl.ooo[:]
            rfl.state = HTTP_STATE_HEADER
    if flows is not None:
        cfk = (rk[2], rk[3], rk[0], rk[1])
        cfl = flows.get(cfk)
        if cfl is not None:
            cfl.corr_eligible = False
            cfl.is_broken = False
            cfl.has_seq = False
            del cfl.buf[:]
            del cfl.ooo[:]
            cfl.state = HTTP_STATE_HEADER


def is_correlation_allowed(rk, flows=None, resp_flows=None, gen=0, syn_seen=False, corr_eligible=True):
    if rk in corr_disabled:
        return False
    if not corr_eligible:
        return False
    if resp_flows is not None:
        rfl = resp_flows.get(rk)
        if rfl is not None:
            if not getattr(rfl, "corr_eligible", True) or getattr(rfl, "is_broken", False):
                return False
    if flows is not None:
        cfk = (rk[2], rk[3], rk[0], rk[1])
        cfl = flows.get(cfk)
        if cfl is not None:
            if not getattr(cfl, "corr_eligible", True) or getattr(cfl, "is_broken", False):
                return False
    if corr_capacity_reached:
        if not syn_seen or gen == 0:
            return False
    return True


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


def transfer_encoding_final_chunked(raw):
    if not raw:
        return False
    if isinstance(raw, bytes):
        raw = raw.decode("latin1", "replace")
    s = raw.strip().lower()
    if not s:
        return False
    tokens = [p.strip() for p in s.split(",")]
    if any(not tok for tok in tokens) or tokens[-1] != "chunked":
        return False
    if any(tok == "chunked" for tok in tokens[:-1]):
        return False
    return True


def parse_response_head(payload):
    """First line 'HTTP/1.x NNN ...' -> (status_int|None, content_len|None, head_end_idx|None, is_chunked, is_close)."""
    try:
        raw = bytes(payload)
        idx = raw.find(b"\r\n\r\n")
        if idx < 0:
            return None, None, None, False, False
        head = raw[:idx]
        lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
        first = lines[0].split()
        if len(first) < 2 or first[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
            return None, None, idx + 4, False, False
        if len(first[1]) != 3 or not first[1].isdigit():
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
    has_te = False
    invalid_te = False
    resp_te = b""
    for ln in lines[1:]:
        if not ln:
            continue
        c0 = ln[:1]
        if c0 not in (b"c", b"C", b"t", b"T"):
            continue
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
            has_te = True
            v = ln.split(b":", 1)[1].strip()
            if len(v) > 256:
                invalid_te = True
            else:
                if resp_te:
                    resp_te += b","
                if len(resp_te) + len(v) > 256:
                    invalid_te = True
                else:
                    resp_te += v
        elif low.startswith(b"connection:"):
            if b"close" in low:
                conn_close = True
            elif b"keep-alive" in low:
                conn_keep_alive = True
    if has_te:
        if invalid_te or not transfer_encoding_final_chunked(resp_te):
            return None, None, None, False, False
        is_chunked = True
    if has_conflict_cl or (has_clen and (has_te or is_chunked)):
        return None, None, None, False, False
    if is_http_10 and not conn_keep_alive:
        is_close = True
    elif conn_close:
        is_close = True
    return st, clen, idx + 4, is_chunked, is_close



def handle_response(resp_flows, rk, payload, now, out, pending_tbl, seq=None, flags=0, is_truncated=False, flows=None):
    if flags & 0x02 and seq is not None:
        rfl = resp_flows.get(rk)
        if rfl is not None and getattr(rfl, "has_seq", False):
            return
        gen = rfl.generation if rfl is not None else 0
        syn = rfl.syn_seen if rfl is not None else False
        eligible = rfl.corr_eligible if rfl is not None else True
        if gen == 0 and flows is not None:
            cfk = (rk[2], rk[3], rk[0], rk[1])
            cfl = flows.get(cfk)
            if cfl is not None and cfl.generation > 0:
                gen = cfl.generation
                syn = cfl.syn_seen
                eligible = cfl.corr_eligible
        if rfl is None:
            rfl = Flow()
            resp_flows[rk] = rfl
        rfl.reset_for_new_connection(gen, now=now, syn_seen=syn or True, corr_eligible=eligible if gen > 0 else True)
        rfl.has_seq = True
        rfl.next_seq = (seq + 1) & 0xFFFFFFFF
        return

    rfl = resp_flows.get(rk)
    if rfl is None:
        rfl = Flow()
        resp_flows[rk] = rfl
    rfl.touched = now

    plen = len(payload) if payload else 0

    allowed = is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                     gen=rfl.generation, syn_seen=rfl.syn_seen,
                                     corr_eligible=getattr(rfl, "corr_eligible", True))
    if not allowed or getattr(rfl, "state", None) == HTTP_STATE_UNSYNCED:
        del rfl.buf[:]
        del rfl.ooo[:]
        if flags & 0x04:
            resp_flows.pop(rk, None)
            pending_pop(rk, out, pending_tbl)
        elif flags & 0x01:
            if seq is not None:
                rfl.fin_seen = True
                rfl.fin_seq = (seq + plen) & 0xFFFFFFFF
            if not rfl.has_seq or seq_diff(rfl.fin_seq, rfl.next_seq) <= 0:
                if getattr(rfl, "state", None) in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY, HTTP_STATE_UNSYNCED) and not rfl.buf and not rfl.ooo:
                    resp_flows.pop(rk, None)
                    pending_pop(rk, out, pending_tbl)
        return
    if plen > 0:
        if is_truncated:
            rfl.is_broken = True
            invalidate_connection_correlation(flows, resp_flows, rk)
            if pending_tbl and rk in pending_tbl:
                if out is not None:
                    for item in pending_tbl[rk]:
                        if not item[2]:
                            out.append(item[0])
                del pending_tbl[rk]
            return

        if seq is None:
            rfl.buf.extend(payload)
        else:
            if not rfl.has_seq:
                start = find_response_resync_py(payload)
                if start is not None:
                    rfl.has_seq = True
                    rfl.next_seq = (seq + start) & 0xFFFFFFFF
                    rfl.is_broken = False
                    rfl.state = HTTP_STATE_HEADER
                    payload = payload[start:]
                    plen -= start
                    seq = (seq + start) & 0xFFFFFFFF
                elif (plen >= 5 and payload[:5] == b"HTTP/") or (plen < 5 and b"HTTP/".startswith(payload)):
                    rfl.has_seq = True
                    rfl.next_seq = seq
                    rfl.is_broken = False
                else:
                    if not _ooo_insert(rfl, seq, payload, is_truncated):
                        rfl.is_broken = True
                    return

            diff = seq_diff(seq, rfl.next_seq)
            if diff == 0:
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
                if not _ooo_insert(rfl, seq, payload, is_truncated):
                    rfl.is_broken = True

    # Parse complete responses from reassembled buffer using HTTP framing
    if rfl.fin_seen and rfl.has_seq:
        fdiff = seq_diff(rfl.fin_seq, rfl.next_seq)
        if fdiff <= 0:
            if rfl.state == HTTP_STATE_HEADER and not rfl.buf and not rfl.ooo:
                rfl.state = HTTP_STATE_CLOSE_BODY

    while rfl.buf and not rfl.is_broken:
        if rfl.state == HTTP_STATE_HEADER:
            st, clen, head_len, is_chunked, is_close = parse_response_head(rfl.buf)
            if st is None:
                if head_len is not None:
                    del rfl.buf[:head_len]
                elif rfl.buf.find(b"\r\n\r\n") != -1:
                    rfl.buf = bytearray()
                    rfl.is_broken = True
                    invalidate_connection_correlation(flows, resp_flows, rk)
                break

            if 100 <= st <= 199 and st != 101:
                del rfl.buf[:head_len]
                continue

            allowed = is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                             gen=rfl.generation, syn_seen=rfl.syn_seen,
                                             corr_eligible=rfl.corr_eligible)
            ent = pending_tbl.get(rk) if allowed else None

            if st == 101:
                del rfl.buf[:head_len]
                if ent:
                    item = ent[0]
                    is_tombstone = item[2] if len(item) > 2 else False
                    if not is_tombstone:
                        ev = item[0]
                        started = item[1]
                        ev["status"] = 101
                        ev["duration_ms"] = max(0, int((now - started) * 1000))
                        ev["resp_bytes"] = 0
                        out.append(ev)
                    ent.pop(0)
                    while ent:
                        rem_item = ent.pop(0)
                        if not (rem_item[2] if len(rem_item) > 2 else False):
                            out.append(rem_item[0])
                    pending_tbl.pop(rk, None)
                corr_disabled_insert(rk)
                rfl.corr_eligible = False
                rfl.state = HTTP_STATE_UNSYNCED
                rfl.is_broken = True
                if flows is not None:
                    cfk = (rk[2], rk[3], rk[0], rk[1])
                    cfl = flows.get(cfk)
                    if cfl is not None:
                        cfl.corr_eligible = False
                        cfl.state = HTTP_STATE_UNSYNCED
                        cfl.is_broken = True
                break

            if flows is not None:
                cfk = (rk[2], rk[3], rk[0], rk[1])
                cfl = flows.get(cfk)
                if cfl is not None and cfl.awaiting_wsse and cfl.wsse_buf:
                    username = extract_wsse_username(cfl.wsse_buf)
                    if username and ent:
                        for pitem in ent:
                            if len(pitem) > 5 and pitem[5] == cfl.wsse_req_id:
                                pitem[0]["wsse_user"] = username
                                pitem[0]["user"] = username
                                pitem[0]["scheme"] = "wsse"
                                break
                    cfl.awaiting_wsse = False
                    cfl.wsse_buf = bytearray()

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
                else:
                    ev = item[0]
                    if ev.get("method") == "HEAD":
                        is_head = True
                    if is_tombstone:
                        ent.pop(0)
                        if not ent:
                            pending_tbl.pop(rk, None)
                    else:
                        started = item[1]
                        ent.pop(0)
                        if not ent:
                            pending_tbl.pop(rk, None)
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

    if rfl.fin_seen and rfl.has_seq:
        fdiff = seq_diff(rfl.fin_seq, rfl.next_seq)
        if fdiff <= 0:
            if rfl.state == HTTP_STATE_HEADER and not rfl.buf and not rfl.ooo:
                rfl.state = HTTP_STATE_CLOSE_BODY

    if flags & 0x04:
        resp_flows.pop(rk, None)
        pending_pop(rk, out, pending_tbl)
    elif flags & 0x01:
        if seq is not None:
            rfl.fin_seen = True
            rfl.fin_seq = (seq + plen) & 0xFFFFFFFF
        if not rfl.has_seq or seq_diff(rfl.fin_seq, rfl.next_seq) <= 0:
            if rfl.state in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY) and not rfl.buf and not rfl.ooo:
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
            token = parts[1].strip()
            if not token or len(token) > 1024 or len(token) % 4 != 0:
                return None, None
            saw_pad = False
            pad_count = 0
            for ch in token:
                if saw_pad:
                    if ch == '=':
                        pad_count += 1
                        if pad_count > 2:
                            return None, None
                    else:
                        return None, None
                elif ch == '=':
                    saw_pad = True
                    pad_count = 1
                elif not (('A' <= ch <= 'Z') or ('a' <= ch <= 'z') or ('0' <= ch <= '9') or ch in ('+', '/')):
                    return None, None
            raw = base64.b64decode(token)
            if len(raw) > 512:
                return None, None
            if b":" in raw:
                user_raw = raw.split(b":", 1)[0]
                if len(user_raw) >= 256:
                    return None, None
                user = user_raw.decode("utf-8", "replace")[:64]
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
    # Fast path for common ASCII printable usernames (ord 32..126)
    try:
        is_ascii = True
        for ch in username:
            o = ord(ch)
            if o < 32 or o > 126:
                is_ascii = False
                break
        if is_ascii:
            return username
    except Exception:
        pass

    for char in username:
        if unicodedata.category(char).startswith("C"):
            return None
    return username


class _UsernameFound(Exception):
    pass


def extract_wsse_username(body):
    """Parse a bounded, possibly partial SOAP prefix and return only Username.

    Expat is run incrementally so a UsernameToken in the SOAP Header can be
    recognized without retaining or requiring the complete request body.
    DTD/entity declarations are rejected before parsing.
    """
    if not body or len(body) > MAX_WSSE_BODY_BYTES or b"\x00" in body:
        return None
    if b"UsernameToken" not in body:
        return None
    if b"<!" in body:
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
                if state["result"] is not None:
                    raise _UsernameFound()
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
    except _UsernameFound:
        pass
    except (expat.ExpatError, ValueError, TypeError):
        # A bounded prefix is commonly incomplete. A username fully closed
        # before the truncation point is still safe to use.
        pass
    return state["result"]


def is_soap_content_type(value):
    if not value or "xml" not in value:
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
        if len(parts) == 4 and len(parts[1]) == 32 and len(parts[2]) == 16 and len(parts[3]) == 2:
            try:
                int(parts[3], 16)
                trace_id = parts[1].lower()
            except ValueError:
                pass
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


def _emit_request(flows, key, fl, meta, out, pending_tbl, now, resp_flows=None):
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
    if not is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                  gen=fl.generation, syn_seen=fl.syn_seen,
                                  corr_eligible=fl.corr_eligible):
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
        invalidate_connection_correlation(flows, resp_flows, rk)
        out.append(ev)
        return
    started = fl.first_byte_ts if fl.first_byte_ts > 0 else (now if now is not None else time.time())
    ent.append([ev, started, False, 0.0, fl.generation])


_req_id_seq = [0]


def _emit_request_to_pending(ev, head_bytes, first_byte_ts, meta, out, pending_tbl, now,
                             generation=0, syn_seen=False, corr_eligible=True,
                             flows=None, resp_flows=None):
    dst_ip, dport, src_ip, sport = meta
    if not ev:
        return 0
    ev["req_bytes"] = head_bytes
    if pending_tbl is None:
        out.append(ev)
        return 0
    rk = (dst_ip, dport, src_ip, sport)
    if not is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                  gen=generation, syn_seen=syn_seen,
                                  corr_eligible=corr_eligible):
        out.append(ev)
        return 0
    ent = pending_tbl.get(rk)
    if ent is None:
        if len(pending_tbl) >= PENDING_MAX:
            _flush_oldest_pending(pending_tbl, out)
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)
        invalidate_connection_correlation(flows, resp_flows, rk)
        out.append(ev)
        return 0
    started = first_byte_ts if first_byte_ts > 0 else (now if now is not None else time.time())
    _req_id_seq[0] += 1
    req_id = _req_id_seq[0]
    ent.append([ev, started, False, 0.0, generation, req_id])
    return req_id




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
                                 meta, out, pending_tbl, now, generation=fl.generation,
                                 syn_seen=fl.syn_seen, corr_eligible=fl.corr_eligible,
                                 flows=flows)
        fl.awaiting_wsse = False
        return True
    return False


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out,
                   pending_tbl=None, now=None, wsse_body_bytes=0,
                   seq=None, flags=0, is_truncated=False, resp_flows=None):
    dst_ip, dport, src_ip, sport = meta
    if not (1 <= dport <= 65535 and 1 <= sport <= 65535):
        return
    if not flows:
        reset_wsse_active_flows()
    if now is None:
        now = time.time()

    # SYN handling: reset flow and start sequence tracking
    if flags & 0x02 and seq is not None:
        fl = flows.get(key)
        if fl is not None and getattr(fl, "syn_seen", False) and getattr(fl, "client_isn", None) == seq:
            return
        if fl is not None:
            fl.awaiting_wsse = False
        rk = (dst_ip, dport, src_ip, sport)
        corr_disabled_erase(rk)

        if pending_tbl is not None:
            ent = pending_tbl.get(rk)
            if ent:
                for item in list(ent):
                    is_tomb = item[2] if len(item) > 2 else False
                    if not is_tomb and out is not None:
                        out.append(item[0])
                pending_tbl.pop(rk, None)

        next_gen = (fl.generation + 1) if fl else 1
        fl = Flow()
        fl.reset_for_new_connection(next_gen, now, syn_seen=True, corr_eligible=True)
        fl.has_seq = True
        fl.next_seq = (seq + 1) & 0xFFFFFFFF
        fl.client_isn = seq
        flows[key] = fl

        rfl = Flow()
        rfl.reset_for_new_connection(next_gen, now, syn_seen=True, corr_eligible=True)
        if resp_flows is not None:
            resp_flows[rk] = rfl
        return

    fl = flows.get(key)
    if fl is None:
        fl = Flow()
        flows[key] = fl
        if len(flows) > MAX_FLOWS:
            enforce_limit(flows, now, out=out, pending_tbl=pending_tbl, resp_flows=resp_flows)
    fl.touched = now

    # Check keep-alive request transition while waiting for body in direct test feed mode
    if seq is None and fl.awaiting_wsse and payload and is_method_or_prefix(payload):
        if pending_tbl is None and fl.wsse_event is not None:
            out.append(fl.wsse_event)
        fl.awaiting_wsse = False
        fl.state = HTTP_STATE_HEADER
        fl.buf = bytearray()

    plen = len(payload) if payload else 0

    if getattr(fl, "state", None) == HTTP_STATE_UNSYNCED:
        if flags & 0x04:
            if fl.awaiting_wsse:
                fl.awaiting_wsse = False
            flows.pop(key, None)
        elif flags & 0x01:
            if seq is not None:
                fl.fin_seen = True
                fl.fin_seq = (seq + plen) & 0xFFFFFFFF
            if not fl.has_seq or seq_diff(fl.fin_seq, fl.next_seq) <= 0:
                if getattr(fl, "state", None) in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY, HTTP_STATE_UNSYNCED) and not fl.buf and not fl.ooo and not fl.awaiting_wsse:
                    flows.pop(key, None)
        return
    if plen > 0:
        if is_truncated:
            fl.is_broken = True
            rk = (dst_ip, dport, src_ip, sport)
            invalidate_connection_correlation(flows, resp_flows, rk)
            if pending_tbl and rk in pending_tbl:
                if out is not None:
                    for item in pending_tbl[rk]:
                        if not item[2]:
                            out.append(item[0])
                del pending_tbl[rk]
            return

        if seq is None:
            fl.buf.extend(payload)
        else:
            if not fl.has_seq:
                start = find_request_resync_py(payload)
                if start is not None:
                    fl.has_seq = True
                    fl.next_seq = (seq + start) & 0xFFFFFFFF
                    fl.is_broken = False
                    fl.state = HTTP_STATE_HEADER
                    payload = payload[start:]
                    plen -= start
                    seq = (seq + start) & 0xFFFFFFFF
                elif is_method_or_prefix(payload):
                    fl.has_seq = True
                    fl.next_seq = seq
                    fl.is_broken = False
                else:
                    if not _ooo_insert(fl, seq, payload, is_truncated):
                        fl.is_broken = True
                    return

            diff = seq_diff(seq, fl.next_seq)
            if diff == 0:
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
                if not _ooo_insert(fl, seq, payload, is_truncated):
                    fl.is_broken = True

    # HTTP framing state machine
    if fl.fin_seen and fl.has_seq:
        fdiff = seq_diff(fl.fin_seq, fl.next_seq)
        if fdiff <= 0:
            if fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo:
                fl.state = HTTP_STATE_CLOSE_BODY

    while len(fl.buf) > 0 and not fl.is_broken:
        if fl.state == HTTP_STATE_CLOSE_BODY:
            del fl.buf[:]
            break

        if fl.state == HTTP_STATE_HEADER:
            if not fl.first_byte_ts:
                fl.first_byte_ts = now

            idx = fl.buf.find(b"\r\n\r\n")
            if idx < 0:
                if len(fl.buf) > MAX_HDRS:
                    fl.buf = bytearray()
                    fl.is_broken = True
                break
            p0 = fl.buf[:8]
            if (p0.startswith(b"GET ") or p0.startswith(b"POST ") or
                p0.startswith(b"PUT ") or p0.startswith(b"DELETE ") or
                p0.startswith(b"HEAD ") or p0.startswith(b"OPTIONS ") or
                p0.startswith(b"PATCH ")):
                start = 0
            else:
                start = find_http_start(fl.buf)
            if start < 0 or start > idx:
                del fl.buf[:idx + 4]
                continue
            if start > 0:
                del fl.buf[:start]
                idx -= start

            head = bytes(fl.buf[:idx])
            lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
            first = lines[0].strip().split()
            if len(first) < 3 or first[0] not in METHODS_BYTES or first[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                del fl.buf[:idx + 4]
                continue
            hdrs = {}
            hdrs["_method"] = first[0].decode("ascii", "replace")
            hdrs["_path"] = first[1].decode("ascii", "replace")
            has_conflict_cl = False
            first_cl = None
            has_transfer_encoding = False
            invalid_transfer_encoding = False
            te_raw = b""
            for ln in lines[1:]:
                if not ln:
                    continue
                c0 = ln[:1]
                if c0 not in (b"a", b"A", b"c", b"C", b"h", b"H", b"t", b"T", b"u", b"U", b"x", b"X"):
                    continue
                if b":" not in ln:
                    continue
                kn, kv = ln.split(b":", 1)
                kn_low = kn.strip().lower()
                if kn_low == b"content-length":
                    v_raw = kv.strip()
                    try:
                        parsed_cl = int(v_raw)
                        if parsed_cl < 0:
                            has_conflict_cl = True
                        elif first_cl is None:
                            first_cl = parsed_cl
                        elif first_cl != parsed_cl:
                            has_conflict_cl = True
                    except ValueError:
                        has_conflict_cl = True
                    hdrs["content-length"] = v_raw.decode("ascii", "replace")[:180]
                elif kn_low == b"transfer-encoding":
                    has_transfer_encoding = True
                    v_te = kv.strip()
                    if len(v_te) > 256:
                        invalid_transfer_encoding = True
                    else:
                        if te_raw:
                            te_raw += b","
                        if len(te_raw) + len(v_te) > 256:
                            invalid_transfer_encoding = True
                        else:
                            te_raw += v_te
                    hdrs["transfer-encoding"] = te_raw.decode("ascii", "replace")[:180]
                elif kn_low == b"content-type":
                    hdrs["content-type"] = kv.strip().decode("ascii", "replace")[:180]
                elif kn_low == b"authorization":
                    hdrs["authorization"] = kv.strip().decode("ascii", "replace")[:180]
                elif kn_low == b"traceparent":
                    hdrs["traceparent"] = kv.strip().decode("ascii", "replace")[:180]
                elif kn_low == b"host":
                    hdrs["host"] = kv.strip().decode("utf-8", "replace")[:180]
                elif kn_low == b"user-agent":
                    hdrs["user-agent"] = kv.strip().decode("utf-8", "replace")[:180]
                elif kn_low == b"x-forwarded-for":
                    hdrs["x-forwarded-for"] = kv.strip().decode("utf-8", "replace")[:180]
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
            has_te = has_transfer_encoding
            is_chunked = False
            if has_te:
                if not invalid_transfer_encoding and transfer_encoding_final_chunked(te_raw):
                    is_chunked = True

            if (has_conflict_cl or invalid_transfer_encoding or
                (has_te and not is_chunked) or
                (has_te and "content-length" in hdrs)):
                del fl.buf[:]
                del fl.ooo[:]
                fl.has_seq = False
                fl.is_broken = False
                fl.state = HTTP_STATE_HEADER
                rk = (dst_ip, dport, src_ip, sport)
                invalidate_connection_correlation(flows, resp_flows, rk)
                break

            wsse_eligible = (wsse_body_bytes > 0 and
                             is_soap_content_type(hdrs.get("content-type")) and
                             content_length > 0 and
                             not is_chunked and
                             g_wsse_active_flows < MAX_WSSE_BODY_FLOWS)

            if wsse_eligible:
                fl.awaiting_wsse = True
                fl.wsse_event = fl.event
                fl.wsse_buf = bytearray()
                fl.wsse_goal = min(content_length, wsse_body_bytes, MAX_WSSE_BODY_BYTES)
                fl.wsse_last_parsed_len = 0
                if pending_tbl is not None:
                    rk = (dst_ip, dport, src_ip, sport)
                    if is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                              gen=fl.generation, syn_seen=fl.syn_seen,
                                              corr_eligible=fl.corr_eligible):
                        req_id = _emit_request_to_pending(fl.event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now,
                                                         generation=fl.generation, syn_seen=fl.syn_seen, corr_eligible=fl.corr_eligible,
                                                         flows=flows, resp_flows=resp_flows)
                        fl.wsse_req_id = req_id
                        fl.wsse_rk = rk
                    else:
                        fl.wsse_req_id = 0
                        fl.wsse_rk = None
                else:
                    fl.wsse_req_id = 0
                    fl.wsse_rk = None
            else:
                fl.awaiting_wsse = False
                _emit_request_to_pending(fl.event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now,
                                         generation=fl.generation, syn_seen=fl.syn_seen, corr_eligible=fl.corr_eligible,
                                         flows=flows, resp_flows=resp_flows)
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
                buf_len = len(fl.wsse_buf)
                should_parse = (buf_len >= fl.wsse_goal or
                                fl.body_remaining <= to_consume or
                                buf_len >= fl.wsse_last_parsed_len + 512)
                if should_parse:
                    fl.wsse_last_parsed_len = buf_len
                    username = extract_wsse_username(fl.wsse_buf)
                    if username or buf_len >= fl.wsse_goal:
                        if username and fl.wsse_event is not None:
                            fl.wsse_event["wsse_user"] = username
                            fl.wsse_event["user"] = username
                            fl.wsse_event["scheme"] = "wsse"
                        if pending_tbl is not None:
                            if fl.wsse_rk in pending_tbl:
                                for item in pending_tbl[fl.wsse_rk]:
                                    if len(item) > 5 and item[5] == fl.wsse_req_id:
                                        if username:
                                            item[0]["wsse_user"] = username
                                            item[0]["user"] = username
                                            item[0]["scheme"] = "wsse"
                                        break
                        else:
                            if fl.wsse_event is not None:
                                out.append(fl.wsse_event)
                        fl.awaiting_wsse = False

            del fl.buf[:to_consume]
            fl.body_remaining -= to_consume
            if fl.body_remaining == 0:
                if fl.awaiting_wsse:
                    if pending_tbl is None and fl.wsse_event is not None:
                        out.append(fl.wsse_event)
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

    if fl.fin_seen and fl.has_seq:
        fdiff = seq_diff(fl.fin_seq, fl.next_seq)
        if fdiff <= 0:
            if fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo:
                fl.state = HTTP_STATE_CLOSE_BODY

    if flags & 0x04:
        if fl.awaiting_wsse:
            fl.awaiting_wsse = False
        flows.pop(key, None)
    elif flags & 0x01:
        if seq is not None:
            fl.fin_seen = True
            fl.fin_seq = (seq + plen) & 0xFFFFFFFF
        if not fl.has_seq or seq_diff(fl.fin_seq, fl.next_seq) <= 0:
            if fl.state in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY) and not fl.buf and not fl.ooo and not fl.awaiting_wsse:
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
        if fl is not None:
            fl.awaiting_wsse = False
            rk = (k[2], k[3], k[0], k[1])
            invalidate_connection_correlation(flows, resp_flows, rk)
            if pending_tbl is not None and rk in pending_tbl:
                if out is not None:
                    for item in pending_tbl[rk]:
                        if not item[2]:
                            out.append(item[0])
                del pending_tbl[rk]
        flows.pop(k, None)
    if resp_flows is not None:
        rstale = [k for k, rfl in resp_flows.items() if now - rfl.touched > FLOW_TTL]
        for k in rstale:
            rk = k
            invalidate_connection_correlation(flows, resp_flows, rk)
            if pending_tbl is not None and rk in pending_tbl:
                if out is not None:
                    for item in pending_tbl[rk]:
                        if not item[2]:
                            out.append(item[0])
                del pending_tbl[rk]
            resp_flows.pop(k, None)


def drain_incomplete_wsse(flows, out, pending_tbl, now=None):
    """Fall back to clearing awaiting_wsse without re-emitting (already in pending)."""
    for key in list(flows.keys()):
        fl = flows.get(key)
        if fl is None:
            continue
        fl.awaiting_wsse = False
        flows.pop(key, None)


def process_packet(pkt, ports, node_host, flows, resp_flows, pending_tbl, out, now=None, wsse_body_bytes=0):
    n = len(pkt)
    if n < 34:
        return False
    if now is None:
        now = time.time()
    off = 14
    etype = _STRUCT_H.unpack_from(pkt, 12)[0]
    if etype == ETH_P_VLAN:
        if n < 38:
            return False
        etype = _STRUCT_H.unpack_from(pkt, 16)[0]
        off = 18
    elif etype != ETH_P_IP:
        return False

    ip0 = _STRUCT_B.unpack_from(pkt, off)[0]
    if (ip0 >> 4) != 4 or _STRUCT_B.unpack_from(pkt, off + 9)[0] != 6:
        return False
    ihl = (ip0 & 0x0F) * 4
    if ihl < 20 or n < off + ihl + 20:
        return False

    frag = _STRUCT_H.unpack_from(pkt, off + 6)[0]
    if frag & 0x3FFF:
        return False

    tcp_off = off + ihl
    sport, dport = _STRUCT_HH.unpack_from(pkt, tcp_off)
    sport_mon = sport in ports
    dport_mon = dport in ports
    if not (sport_mon or dport_mon):
        return False

    ip_total_len = _STRUCT_H.unpack_from(pkt, off + 2)[0]
    if ip_total_len < ihl + 20:
        return False
    is_truncated = False
    if n - off < ip_total_len:
        is_truncated = True
    elif n - off > ip_total_len:
        n = off + ip_total_len

    doff_byte = _STRUCT_B.unpack_from(pkt, tcp_off + 12)[0]
    doff = (doff_byte >> 4) * 4
    if doff < 20 or n < tcp_off + doff:
        return False

    src_ip = _fast_inet_ntoa(pkt[off + 12:off + 16])
    dst_ip = _fast_inet_ntoa(pkt[off + 16:off + 20])
    seq = _STRUCT_I.unpack_from(pkt, tcp_off + 4)[0]
    flags = _STRUCT_B.unpack_from(pkt, tcp_off + 13)[0]
    pay_start = tcp_off + doff
    payload = pkt[pay_start:n] if n > pay_start else b""

    # Response direction: Server -> Client
    if sport_mon and not dport_mon:
        rk = (src_ip, sport, dst_ip, dport)
        handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                        seq=seq, flags=flags, is_truncated=is_truncated, flows=flows)
        return True

    # Both ports monitored: latch roles via handshake, existing flow, or HTTP prefix
    elif sport_mon and dport_mon:
        rk = (src_ip, sport, dst_ip, dport)
        req_k = (src_ip, sport, dst_ip, dport)
        is_resp = False
        if resp_flows is not None and rk in resp_flows:
            is_resp = True
        elif flows is not None and (dst_ip, dport, src_ip, sport) in flows:
            is_resp = True
        elif flows is not None and req_k in flows:
            is_resp = False
        elif (flags & 0x12) == 0x12:
            is_resp = True
        elif flags & 0x02:
            is_resp = False
        elif payload and payload.startswith(b"HTTP/"):
            is_resp = True
        else:
            is_resp = False

        if is_resp:
            handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                            seq=seq, flags=flags, is_truncated=is_truncated, flows=flows)
        else:
            meta = (dst_ip, dport, src_ip, sport)
            handle_payload(flows, req_k, None, payload, meta, ports, node_host, out,
                           pending_tbl, now, wsse_body_bytes,
                           seq=seq, flags=flags, is_truncated=is_truncated,
                           resp_flows=resp_flows)
        return True

    # Request direction: Client -> Server
    else:
        key = (src_ip, sport, dst_ip, dport)
        meta = (dst_ip, dport, src_ip, sport)
        handle_payload(flows, key, None, payload, meta, ports, node_host, out,
                       pending_tbl, now, wsse_body_bytes,
                       seq=seq, flags=flags, is_truncated=is_truncated,
                       resp_flows=resp_flows)

        return True

    return False


def _flush_oldest_pending(pending_tbl, out, flows=None, resp_flows=None):
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
        invalidate_connection_correlation(flows, resp_flows, oldest_key)
        pending_tbl.pop(oldest_key, None)


def sweep_pending(pending_tbl, now, out, flows=None, resp_flows=None):
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
                    invalidate_connection_correlation(flows, resp_flows, rk)
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


def enforce_limit(flows, now, out=None, pending_tbl=None, resp_flows=None):
    """Cap flow-table size (py2.6: no OrderedDict — sweep stale, then FIFO
    by insertion order, which plain dicts preserve in CPython)."""
    sweep_idle(flows, now, out=out, pending_tbl=pending_tbl, resp_flows=resp_flows)
    while len(flows) > MAX_FLOWS:
        k, fl = flows.popitem()          # oldest-inserted key on CPython 2.6/2.7
        if fl is not None:
            fl.awaiting_wsse = False
            rk = (k[2], k[3], k[0], k[1])
            invalidate_connection_correlation(flows, resp_flows, rk)
            if pending_tbl is not None and rk in pending_tbl:
                if out is not None:
                    for item in pending_tbl[rk]:
                        if not item[2]:
                            out.append(item[0])
                del pending_tbl[rk]


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
        import resource
        target = 256 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard != resource.RLIM_INFINITY and hard < target:
            target = hard
        resource.setrlimit(resource.RLIMIT_AS, (target, target))
    except Exception:
        pass

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
        waiting_wsse = g_wsse_active_flows
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
    pkt_batch_cnt = 0
    while running[0]:
        pkt_batch_cnt += 1
        if (pkt_batch_cnt & 0xFF) == 0:
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
            emit_capture_stats()
            if dbg:
                log("DEBUG timeout rx=%d" % dbg_rx)
                dbg_last = time.time()
            now = time.time()
            if control_client is not None and now >= control_next:
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
                control_next = now + control_interval
            if maintenance_due(now, last_sweep):
                out_s = []
                sweep_idle(flows, now, out_s, pending, resp_flows)
                sweep_pending(pending, now, out_s, flows=flows, resp_flows=resp_flows)
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

        if (pkt_batch_cnt & 0xFF) == 0 and maintenance_due(now, last_sweep):
            out_s = []
            sweep_idle(flows, now, out_s, pending, resp_flows)
            sweep_pending(pending, now, out_s, flows=flows, resp_flows=resp_flows)
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
