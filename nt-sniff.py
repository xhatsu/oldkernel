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

# Stdlib-only imports: this file must run on a bare CentOS 6.x node whose
# Python 2.6 has no third-party packages available. xml.parsers.expat is
# bundled with CPython (as pyexpat).
import base64, binascii, errno, json, os, signal, socket, struct, sys, time
import unicodedata
from collections import deque
from xml.parsers import expat

# --------------------------------------------------------------- constants --
# AF_PACKET protocol argument: ETH_P_ALL makes the socket receive every
# ethertype in BOTH directions (ingress requests AND egress responses).
# A request-only filter could never see responses, so response correlation
# would be impossible.
ETH_P_ALL = 0x0003
# Ethernet ethertypes we recognize: IPv4 (the only L3 we parse) and the
# 802.1Q VLAN tag (handled by skipping the 4-byte tag).
ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100
# SOL_PACKET / PACKET_STATISTICS come from linux/if_packet.h: the packet
# socket option level and the option id used to read (and reset) the kernel's
# frame drop counters.
SOL_PACKET = 263
PACKET_STATISTICS = 6
# Default seconds between "capture_stats_v1" telemetry lines on stdout.
DEFAULT_STATS_INTERVAL = 30

# Remote control is optional: nt_control.py provides the ControlClient used
# to poll desired configuration. If it is absent the sniffer runs standalone.
try:
    import nt_control
except ImportError:
    nt_control = None

# py2.6 str-indexing yields 1-char str, not int (proven on real el6 VM);
# normalize so byte-at-index works identically under python 2 and 3
PY2 = sys.version_info[0] == 2


def b2i(c):
    """Return the integer value of a single byte/character.

    Python 2 indexes str as a 1-char str (needs ord()); Python 3 indexes a
    bytes object as an int already. This shim keeps packet[i] handling
    identical on both interpreters.
    """
    return ord(c) if PY2 else c

# HTTP methods accepted at the start of a request line. METHODS is the text
# form; METHODS_BYTES is the bytes form matched against raw packet payloads.
METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
METHODS_BYTES = set((b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"))

# Precompiled struct readers. "!" selects network (big-endian) byte order.
# B = u8, H = u16, HH = two consecutive u16, I = u32. unpack_from() reads
# directly out of a buffer with no slice copy.
_STRUCT_B = struct.Struct("!B")
_STRUCT_H = struct.Struct("!H")
_STRUCT_HH = struct.Struct("!HH")
_STRUCT_I = struct.Struct("!I")

# Bounded memo of packed-IPv4 -> dotted-quad strings; the same handful of
# addresses recur constantly during capture, so this avoids repeated work.
_IP_CACHE = {}


def _fast_inet_ntoa(raw4):
    """socket.inet_ntoa with a small bounded memo cache (<= 4096 entries).

    raw4 is the 4-byte packed IPv4 address straight out of the IP header.
    The cache is flushed wholesale rather than evicted per-entry, which is
    cheaper than an LRU under capture load.
    """
    ip = _IP_CACHE.get(raw4)
    if ip is None:
        if len(_IP_CACHE) > 4096:
            _IP_CACHE.clear()
        ip = socket.inet_ntoa(raw4)
        _IP_CACHE[raw4] = ip
    return ip


# Global tally of flows currently holding a WSSE body buffer (or awaiting the
# body). Bounded by MAX_WSSE_BODY_FLOWS so total opt-in body memory stays
# capped in aggregate, not just per flow.
g_wsse_active_flows = 0

# Runtime telemetry counters reported via capture_stats_v1.
g_effective_so_rcvbuf = 0
g_invalid_frames_total = 0
g_truncated_frames_total = 0
g_correlation_disabled_total = 0
g_parser_resync_total = 0
g_seq_counter = [0]


def reset_wsse_active_flows():
    """Reset the global WSSE body-buffer flow counter to zero.

    Called when the flow table is empty so a leaked count can never
    permanently block new WSSE body capture.
    """
    global g_wsse_active_flows
    g_wsse_active_flows = 0


# ----------------------------------------------------- flow-tracking bounds --
# All of these are hard caps so a busy or hostile host cannot make the sniffer
# allocate unbounded memory. They are limits, not tuning hints.
MAX_TRACKED_HALF_FLOWS = 8192 # combined tracked half-flows (flows + resp_flows)
MAX_FLOWS = 8192              # alias for backward compatibility
MAX_HDRS = 262144             # max bytes buffered waiting for \r\n\r\n (256 KiB)
FLOW_IDLE_TTL = 300           # seconds before clean idle flow buffers are dropped
FLOW_STALE_TTL = 600          # seconds before stale mid-stream flows are invalidated
FLOW_TTL = FLOW_IDLE_TTL      # alias for backward compatibility
MAX_WSSE_BODY_BYTES = 65536   # hard ceiling even if configuration is larger
MAX_WSSE_BODY_FLOWS = 256     # at most 16 MiB of opt-in body buffers globally
MAX_WSSE_USERNAME = 200

# Accepted WS-Security SOAP namespaces (OASIS 2004 plus the three legacy
# drafts). A UsernameToken declared in any other namespace is ignored as
# untrusted body text.
WSSE_NAMESPACES = set((
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "http://schemas.xmlsoap.org/ws/2002/07/secext",
    "http://schemas.xmlsoap.org/ws/2002/12/secext",
    "http://schemas.xmlsoap.org/ws/2003/06/secext",
))


def log(msg):
    """Write a diagnostic line to stderr (never stdout -- stdout is JSONL)."""
    sys.stderr.write("nt-sniff: %s\n" % msg)
    sys.stderr.flush()


def stats_interval_seconds():
    """Return the capture-stats emit interval, clamped to 10..300 seconds.

    Reads NT_STATS_INTERVAL_SEC; falls back to DEFAULT_STATS_INTERVAL when the
    variable is missing or not an integer.
    """
    try:
        value = int(os.environ.get("NT_STATS_INTERVAL_SEC",
                                   str(DEFAULT_STATS_INTERVAL)))
    except ValueError:
        value = DEFAULT_STATS_INTERVAL
    return max(10, min(value, 300))


def verify_dropped_capabilities():
    """Verify that effective capabilities in /proc/self/status have no CAP_NET_RAW."""
    try:
        f = open("/proc/self/status", "r")
        try:
            for line in f:
                if line.startswith("CapEff:"):
                    parts = line.split()
                    if len(parts) > 1:
                        capeff = int(parts[1], 16)
                        # CAP_NET_RAW is bit 13 (1 << 13 = 0x2000)
                        if capeff & (1 << 13):
                            return False
                        return True
        finally:
            f.close()
    except Exception:
        pass
    return True


def drop_capture_capabilities():
    """Irreversibly drop root privileges and clear CAP_NET_RAW after socket setup."""
    try:
        import os, pwd
        # Only meaningful when started as root; the SysV installer launches us
        # privileged once to open the socket, then we permanently shed it.
        if os.getuid() == 0 or os.geteuid() == 0:
            target_user = os.environ.get("NT_USER", "ntsniff")
            # Resolve the dedicated unprivileged runtime account (NT_USER,
            # default "ntsniff"); fall back to "nobody" if it does not exist.
            try:
                pw = pwd.getpwnam(target_user)
            except KeyError:
                try:
                    pw = pwd.getpwnam("nobody")
                except KeyError:
                    return False
            try:
            # Drop supplementary groups FIRST: setgid/setuid are irreversible,
            # but a stale supplementary group would otherwise remain effective.
                os.setgroups([])
            except Exception:
                pass
            try:
                # Order matters: setgid must precede setuid, otherwise the
                # later group change would be silently denied.
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
            except Exception:
                return False
    except Exception:
        return False

    # Second phase: clear the process capability sets so CAP_NET_RAW (and
    # every other capability) is gone even though the socket stays open.
    try:
        import ctypes
        # libcap.so.2 supplies cap_init()/cap_set_proc() to empty the caps.
        libcap = ctypes.CDLL("libcap.so.2")
        libcap.cap_init.argtypes = []
        libcap.cap_init.restype = ctypes.c_void_p
        libcap.cap_set_proc.argtypes = [ctypes.c_void_p]
        libcap.cap_set_proc.restype = ctypes.c_int
        libcap.cap_free.argtypes = [ctypes.c_void_p]
        libcap.cap_free.restype = ctypes.c_int
        empty = libcap.cap_init()
        if not empty:
            return False
        try:
            # Success only if cap_set_proc worked AND we are no longer uid 0.
            ok = (libcap.cap_set_proc(ctypes.c_void_p(empty)) == 0 and
                  os.getuid() != 0 and os.geteuid() != 0)
            if not ok:
                return False
        finally:
            libcap.cap_free(ctypes.c_void_p(empty))
    except Exception:
        # libcap unavailable: fall back to the uid check alone.
        if not (os.getuid() != 0 and os.geteuid() != 0):
            return False
    return verify_dropped_capabilities()


# ---------------------------------------------------------------- perf: cBPF
# Attach a classic BPF program so the KERNEL drops everything that is not
# IPv4 TCP to or from a monitored port. Request headers drive events and
# response headers enrich them; unrelated traffic never reaches userspace.
# setsockopt option id that attaches a classic BPF program (linux/socket.h).
SO_ATTACH_FILTER = 26

def build_bpf(ports):
    """Classic BPF: ethertype==IP && proto==TCP && dport in ports.
    Returns (fprog_struct, filter_array) for the libc setsockopt call,
    or None on failure. NOTE: sock_fprog carries a POINTER to the filter
    array, so it must stay alive until the syscall — python's
    socket.setsockopt(str) flattening cannot preserve it."""

    # Classic-BPF opcodes (linux/filter.h). Each instruction is
    # (code, jt, jf, k):
    #   LDH_ABS  ld  [k] as u16 (absolute offset)
    #   LDB_ABS  ld  [k] as u8
    #   JEQ_K    jump by jt if A == k, else by jf (offsets are relative to the
    #            NEXT instruction)
    #   LDX_MSH  x = 4 * ([k] & 0x0f)  (IPv4 IHL converted to bytes)
    #   LDH_IND  ld  [x + k] as u16 (indexed)
    #   RET_K    return k (snapshot length; 0 = drop the packet)
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
    # NT_SNIFF_SPORT_K selects the offset used for the SOURCE-port match.
    # With a 20-byte IP header, X + 14 == TCP source port, so the kernel also
    # admits response packets whose SOURCE is a monitored port. Calibrated
    # empirically on a live kernel: without it responses never arrive and
    # correlation yields no status/duration/resp_bytes.
    # NOTE: this requires the 1-second recv timeout in main(); a fully
    # blocking recv with this program attached starves after one packet.
    sk = int(os.environ.get("NT_SNIFF_SPORT_K", "14"))
    # Deterministic ordering of monitored ports so jump offsets are stable.
    ps = sorted(ports)
    n = len(ps)
    # Program layout: 4 fixed prologue instructions, then 2 per dport, then
    # 2 per sport (when enabled), then 2 RETs. ret_rej / ret_acc are the
    # indices of the reject and accept terminators.
    ret_rej = 5 + (4 if sk else 2) * n
    ret_acc = ret_rej + 1
    prog = []
    # 1) Ethertype at byte offset 12 must be 0x0800 (IPv4).
    prog.append((LDH_ABS, 0, 0, 12))                 # ethertype == IP?
    prog.append((JEQ_K, 0, ret_rej - 2, 0x0800))
    # 2) IP protocol byte at offset 23 must be 6 (TCP).
    prog.append((LDB_ABS, 0, 0, 23))                 # proto == TCP?
    prog.append((JEQ_K, 0, ret_rej - 4, 6))
    # 3) X = IPv4 header length in bytes (IHL nibble * 4), so every TCP field
    #    offset below is relative to X and survives IP options.
    prog.append((LDX_MSH, 0, 0, 14))                 # X = ihl*4
    # 4) Destination-port block: compare [X+16] (TCP dport) to each monitored
    #    port and jump to the accept instruction on a hit.
    for i, p in enumerate(ps):                       # A: dport @ X+16
        prog.append((LDH_IND, 0, 0, 16))
        jt = ret_acc - (len(prog) + 1)
        jf = 0 if (i < n - 1 or sk) else (ret_rej - (len(prog) + 1))
        prog.append((JEQ_K, jt, jf, p))
    # 5) Source-port block (only when NT_SNIFF_SPORT_K is non-zero): compare
    #    [X+sk] so egress responses are delivered too.
    if sk:                                           # B: sport @ X+sk
        for i, p in enumerate(ps):
            prog.append((LDH_IND, 0, 0, sk))
            jt = ret_acc - (len(prog) + 1)
            jf = 0 if i < n - 1 else (ret_rej - (len(prog) + 1))
            prog.append((JEQ_K, jt, jf, p))
    # Terminators: reject (drop) then accept (snapshot up to 0x40000 bytes).
    prog.append((RET_K, 0, 0, 0))                    # reject
    prog.append((RET_K, 0, 0, 0x40000))              # accept
    # cBPF jump offsets are 8-bit; refuse to build if any offset overflows
    # instead of attaching a broken filter.
    if any(jt > 255 or jf > 255 for _, jt, jf, _ in prog):
        return None

    # Build the kernel structs. sock_fprog holds a POINTER to the filter array,
    # so the array must outlive the setsockopt call; both are returned and the
    # array is kept referenced by apply_perf_opts().
    try:
        import ctypes

        # struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                        ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]

        # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
        class SockFprog(ctypes.Structure):
            # mirrors struct sock_fprog {u16 len; sock_filter *filter};
            # ctypes applies the same pointer alignment as the compiler
            _fields_ = [("len", ctypes.c_uint16),
                        ("filter", ctypes.POINTER(SockFilter))]

        # Materialize the finished instruction list into a ctypes array.
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
    # Tracks whether the kernel actually accepted the program.
    filter_ok = False
    if built is not None:
        try:
            # setsockopt(2) cannot be expressed for SO_ATTACH_FILTER through
            # python's socket module (it needs a struct pointer, not a
            # flattened string), so call libc directly.
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            libc.setsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
            libc.setsockopt.restype = ctypes.c_int
            # Keep `arr` alive across the syscall: fprog.filter points into it.
            fprog, arr = built                      # keep arr referenced!
            ret = libc.setsockopt(sock.fileno(), socket.SOL_SOCKET,
                                  SO_ATTACH_FILTER,
                                  ctypes.byref(fprog),
                                  ctypes.sizeof(fprog))
            # ret == 0 means the kernel installed the filter.
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
    # Raise the receive buffer so bursts are absorbed in the kernel rather
    # than dropped while userspace parses the previous packet.
    global g_effective_so_rcvbuf
    try:
        want = 8 * 1024 * 1024
        # Request 8 MiB; the kernel may clamp this to net.core.rmem_max.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
        # Read back what was actually granted.
        got = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        g_effective_so_rcvbuf = got
        log("rcvbuf: %d bytes" % got)
    except Exception as e:
        log("WARN: SO_RCVBUF raise failed: %s" % e)
    return filter_ok


def parse_wsse_body_bytes(value):
    """Validate the opt-in body window without allowing unbounded buffers."""
    try:
        # Accept None/"" as 0; reject anything non-integer.
        size = int(value or 0)
    except (TypeError, ValueError):
        raise SystemExit("wsse body bytes must be an integer")
    # Enforce the documented 0..65536 window (MAX_WSSE_BODY_BYTES).
    if size < 0 or size > MAX_WSSE_BODY_BYTES:
        raise SystemExit("wsse body bytes must be in range 0..%d" %
                         MAX_WSSE_BODY_BYTES)
    return size


def parse_args(argv):
    """Parse the command-line arguments.

    Returns (iface, set(ports), verbose, workers, wsse_body_bytes). This is a
    hand-rolled parser to stay py2.6-compatible; it validates every bound
    before capture starts.
    """
    # Defaults: all interfaces, the historical NetworkTracing port set, one
    # worker, and header-only capture (no WSSE body scanning).
    iface = None
    ports = [80, 8003, 8005, 8007, 8009, 8010, 8011]
    verbose = False
    workers = 1
    # Seed the WSSE window from the environment so the installer can enable it
    # without changing the CLI (defaults to 0 = disabled).
    wsse_body_bytes = parse_wsse_body_bytes(
        os.environ.get("NT_WSSE_BODY_BYTES", "0"))
    i = 0
    while i < len(argv):
        a = argv[i]
        # -i <iface>: bind to a single interface instead of all of them.
        if a == "-i":
            if i + 1 >= len(argv):
                raise SystemExit("-i requires an interface")
            i += 1; iface = argv[i]
        # -p <csv ports>: replace the monitored port set (validated below).
        elif a == "-p":
            if i + 1 >= len(argv):
                raise SystemExit("-p requires a comma-separated port list")
            i += 1
            try:
                # Split on commas; ignore empty fields from trailing commas.
                ports = [int(x) for x in argv[i].split(",") if x.strip()]
            except ValueError:
                raise SystemExit("invalid port list")
            # Reject empty lists and any port outside 1..65535.
            if not ports or any(not valid_port(x) for x in ports):
                raise SystemExit("ports must be in range 1..65535")
            # The 30-port ceiling keeps every cBPF jump offset within 8 bits.
            if len(ports) > 30:
                raise SystemExit("at most 30 monitored ports are supported")
        # -j <workers>: accepted for CLI compatibility but only 1 is allowed
        # (packet fanout is not permitted in this deployment).
        elif a == "-j":
            if i + 1 >= len(argv):
                raise SystemExit("-j requires a worker count")
            i += 1
            try:
                workers = int(argv[i])
            except ValueError:
                raise SystemExit("invalid worker count")
            # A single capture worker is mandatory per deployment policy.
            if workers != 1:
                raise SystemExit("only one capture worker is permitted")
        # -v enables extra debug logging on stderr.
        elif a == "-v":
            verbose = True
        # --wsse-body-bytes N: opt in to scanning up to N bytes of SOAP body.
        elif a == "--wsse-body-bytes":
            if i + 1 >= len(argv):
                raise SystemExit("--wsse-body-bytes requires a byte count")
            i += 1
            wsse_body_bytes = parse_wsse_body_bytes(argv[i])
        # -h/--help prints the module docstring and exits cleanly.
        elif a in ("-h", "--help"):
            print(__doc__); raise SystemExit(0)
        else:
        # Fail closed on anything unrecognized rather than silently ignoring.
            raise SystemExit("unknown arg: %s" % a)
        i += 1
    return iface, set(ports), verbose, workers, wsse_body_bytes


# ------------------------------------------------------ HTTP parser states --
# Per-direction framing state machine shared by handle_payload (requests) and
# handle_response (responses). A flow normally idles in HEADER between
# messages and transitions through BODY/CHUNK while one is in flight.
HTTP_STATE_HEADER = 0
# Consuming a Content-Length body.
HTTP_STATE_BODY = 1
# Consuming a chunked body (size line -> payload -> CRLF -> trailer).
HTTP_STATE_CHUNK = 2
# Body is delimited by connection close (no Content-Length; responses).
HTTP_STATE_CLOSE_BODY = 3
# Framing is unreliable (e.g. after a 101 upgrade); stop correlating.
HTTP_STATE_UNSYNCED = 4

# Out-of-order reassembly bounds: at most 4 segments / 16 KiB held per flow
# while a sequence gap is waiting to be filled.
MAX_OOO_SEGMENTS = 4
MAX_OOO_BYTES = 16384
# Hard ceiling on total buffered bytes across the whole flow table.
MAX_TOTAL_BUFFER_BYTES = 16 * 1024 * 1024
MAX_HTTP_BODY_FRAMING = 67108864 # 64 MiB maximum recognized framing length

# Dual-tier pending request bounds
MAX_PENDING_KEYS = 8192
MAX_PENDING_EVENTS = 16384
PENDING_PER_FLOW = 32
PENDING_MAX = MAX_PENDING_KEYS


class BufferBudget(object):
    """Explicit byte accounting budget across all active flow buffers."""
    __slots__ = ("total", "ceiling")

    def __init__(self, ceiling=16777216): # 16 MiB default
        self.total = 0
        self.ceiling = ceiling

    def reserve(self, n):
        """Reserve n bytes from the budget; fails closed if exceeding ceiling."""
        if n <= 0:
            return True
        if self.total + n > self.ceiling:
            return False
        self.total += n
        return True

    def release(self, n):
        """Release n bytes back to the budget."""
        if n <= 0:
            return
        self.total -= n
        if self.total < 0:
            self.total = 0


# Module-level buffer budget shared across active flows and queues.
g_buffer_budget = BufferBudget(MAX_TOTAL_BUFFER_BYTES)


def append_flow_buf(fl, data, budget=None, flows=None, resp_flows=None,
                    pending_tbl=None, rk=None, req_k=None, out=None,
                    request_key=None, response_key=None):
    """Append payload data to flow buffer while enforcing global memory limits."""
    if budget is None:
        budget = g_buffer_budget
    if request_key is not None:
        req_k = request_key
    if response_key is not None:
        rk = response_key
    n = len(data)
    if n == 0:
        return True
    if not budget.reserve(n):
        quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                              response_key=rk, out=out, reason="global_buffer_ceiling")
        return False
    fl.buf.extend(data)
    return True


def consume_flow_buf(fl, n, budget=None):
    """Slice off n bytes from fl.buf and release n bytes from global budget."""
    if n <= 0:
        return
    actual = min(n, len(fl.buf))
    del fl.buf[:actual]
    if budget is not None:
        budget.release(actual)
    elif g_buffer_budget is not None:
        g_buffer_budget.release(actual)


def clear_main_buffer(fl, budget=None):
    """Clear fl.buf and accurately release its byte count from global budget."""
    if budget is None:
        budget = g_buffer_budget
    sz = len(fl.buf)
    if sz:
        del fl.buf[:]
        budget.release(sz)


def clear_ooo(fl, budget=None):
    """Release all out-of-order segment memory and clear the OOO queue."""
    if budget is None:
        budget = g_buffer_budget
    sz = getattr(fl, "ooo_bytes", 0)
    if sz:
        budget.release(sz)
        fl.ooo_bytes = 0
    del fl.ooo[:]


def clear_all_flow_buffers(fl, budget=None):
    """Release main buffer, OOO segments, and WSSE buffers to zero."""
    if budget is None:
        budget = g_buffer_budget
    clear_main_buffer(fl, budget)
    clear_ooo(fl, budget)
    if hasattr(fl, "wsse_cancel"):
        fl.wsse_cancel(budget)


def seq_diff(a, b):
    """Signed 32-bit difference a - b honouring TCP sequence wraparound.

    Returns the shortest signed distance, so a value "ahead" of b across the
    2^32 wrap is seen as a small positive number instead of a huge unsigned
    one.
    """
    # Unsigned modulo-2^32 difference first.
    diff = (a - b) & 0xFFFFFFFF
    # Anything in the upper half is really negative (a is behind b).
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


def is_method_or_prefix(payload):
    """True if payload begins with (part of) a known HTTP method.

    A first TCP segment may contain only a prefix of "POST " etc., so each
    candidate is truncated to the available length before comparison.
    """
    if not payload:
        return False
    # Methods are at most 8 bytes ("OPTIONS "), so only inspect the head.
    p = payload[:8]
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        # Compare against a truncated method so partial segments match.
        if p.startswith(m[:len(p)]):
            return True
    return False


def find_http_start(buf):
    """Byte offset of the earliest HTTP method token in buf, or -1.

    Used to resynchronize when a buffer contains leading noise before the real
    request line.
    """
    # Scan for every method and keep the leftmost occurrence.
    best = -1
    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS "):
        pos = buf.find(m)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


_RESYNC_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def find_request_resync_py(payload):
    """Find where a request begins inside a reassembly buffer, or None.

    Scans at most 16 KiB. First tries a complete method token; failing that,
    allows a method that starts near the end of the scan window and continues
    into the next TCP segment (a method split across segment boundaries).
    """
    # Never scan more than 16 KiB; keeps the search bounded and cheap.
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
    # Walk candidate prefix lengths (a method may be cut anywhere).
    for m in _RESYNC_METHODS:
        mlen = len(m)
        # Does the scan window end with the first prefix_len bytes of m?
        for prefix_len in range(1, mlen):
            if prefix_len > scan_limit:
                continue
            # Offset at which that partial method would start.
            off = scan_limit - prefix_len
            if sub[off:] == m[:prefix_len]:
                return off
    return None


def find_response_resync_py(payload):
    """Find where an HTTP response begins in a reassembly buffer, or None.

    Looks for the literal "HTTP/" within at most 16 KiB, including a split
    "HTTP/" whose tail lives in the following segment.
    """
    scan_limit = min(len(payload), 16384)
    sub = bytes(payload[:scan_limit])
    # Fast path: a complete "HTTP/" token is present.
    pos = sub.find(b"HTTP/")
    if pos != -1:
        return pos
    # Otherwise allow "HTTP/" to be truncated at the buffer end (n = 4..1).
    for n in range(4, 0, -1):
        if n <= scan_limit:
            off = scan_limit - n
            if sub[off:] == b"HTTP/"[:n]:
                return off
    return None


class Flow(object):
    """Per-direction TCP/HTTP reassembly state for one half of a connection.

    Keyed by the 4-tuple (src_ip, sport, dst_ip, dport): `flows` holds the
    client->server (request) direction and `resp_flows` the mirrored
    server->client (response) direction. __slots__ avoids per-instance dicts,
    keeping memory low across thousands of concurrent flows.
    """
    # Each attribute is allocated as a fixed slot (no __dict__):
    #   next_seq                expected next TCP sequence number
    #   has_seq                 True once a starting sequence is established
    #   is_broken               framing lost; stop parsing this direction
    #   touched                 last-activity timestamp (TTL sweeps)
    #   first_byte_ts           arrival time of the first request byte
    #   buf                     reassembled in-order byte buffer
    #   ooo                     out-of-order segments [(seq, bytes), ...]
    #   state                   one of the HTTP_STATE_* values
    #   body_remaining          Content-Length bytes still to consume
    #   chunk_remaining         reserved
    #   chunk_payload_remaining bytes left in the current chunk's payload
    #   chunk_reading_len       currently parsing a chunk-size line
    #   chunk_reading_crlf      expecting the CRLF after chunk payload
    #   chunk_reading_trailer   reading the trailer after the last chunk
    #   _awaiting_wsse          holding a WSSE body window (see property)
    #   wsse_event              request event awaiting WSSE enrichment
    #   wsse_buf                bounded SOAP-prefix buffer
    #   wsse_goal               byte target for the WSSE window
    #   wsse_req_id             id of the pending request to enrich
    #   wsse_rk                 response key associated with that request
    #   event                   finished event for the current request
    #   hdrs                    parsed header dict for the current request
    #   head_bytes              request header byte count (req_bytes)
    #   _body_goal              body bytes to capture (see property)
    #   generation              connection counter; detects stale entries
    #   syn_seen                a SYN established this flow
    #   corr_eligible           response correlation still trustworthy
    #   fin_seen                FIN observed for this direction
    #   fin_seq                 sequence just past the FIN's data
    #   wsse_last_parsed_len    buffer length at the last WSSE parse attempt
    #   client_isn              client initial sequence number (SYN de-dup)
    #   ooo_bytes               total bytes held in out-of-order queue
    #   correlation_allowed     directional correlation permitted
    __slots__ = ("next_seq", "has_seq", "is_broken", "touched", "first_byte_ts",
                 "buf", "ooo", "state", "body_remaining", "chunk_remaining",
                 "chunk_payload_remaining", "chunk_reading_len", "chunk_reading_crlf",
                 "chunk_reading_trailer", "_awaiting_wsse", "wsse_event", "wsse_buf",
                 "wsse_goal", "wsse_req_id", "wsse_rk", "event", "hdrs", "head_bytes",
                 "_body_goal", "generation", "syn_seen", "corr_eligible",
                 "fin_seen", "fin_seq", "wsse_last_parsed_len", "client_isn",
                 "ooo_bytes", "correlation_allowed")

    def __init__(self):
        """Allocate a fresh flow with default header-only framing state."""
        # Sequence tracking starts unset; the first segment (or SYN) pins it.
        self.next_seq = 0
        self.has_seq = False
        self.is_broken = False
        self.client_isn = None
        self.touched = time.time()
        self.first_byte_ts = 0.0
        # bytearray (not str) so consumed bytes can be slice-deleted in place.
        self.buf = bytearray()
        # Out-of-order segments held until the gap before them is filled.
        self.ooo = []
        self.ooo_bytes = 0
        self.state = HTTP_STATE_HEADER
        self.body_remaining = 0
        self.chunk_remaining = 0
        self.chunk_payload_remaining = 0
        # Chunked-body sub-state: read size -> payload -> CRLF -> trailer.
        self.chunk_reading_len = True
        self.chunk_reading_crlf = False
        self.chunk_reading_trailer = False
        # WSSE body-window state (used only when body capture is enabled).
        self._awaiting_wsse = False
        self.wsse_event = None
        self.wsse_buf = bytearray()
        self.wsse_goal = 0
        self.wsse_req_id = 0
        self.wsse_rk = None
        # Holds the in-progress request event and its parsed headers.
        self.event = None
        self.hdrs = None
        self.head_bytes = 0
        self._body_goal = 0
        self.generation = 0
        self.syn_seen = False
        self.corr_eligible = True
        self.correlation_allowed = True
        self.fin_seen = False
        self.fin_seq = 0
        self.wsse_last_parsed_len = 0

    @property
    def awaiting_wsse(self):
        """True while a WSSE body window is being buffered for this flow."""
        return self._awaiting_wsse

    @awaiting_wsse.setter
    def awaiting_wsse(self, val):
        # Keep the global WSSE-flow counter in sync so the aggregate bound
        # holds across every transition in/out of body-buffering state.
        global g_wsse_active_flows
        v = bool(val)
        # Only act on real changes; "active" is derived from BOTH
        # awaiting_wsse and a non-zero body_goal.
        if self._awaiting_wsse != v:
            old_active = self._awaiting_wsse or (self._body_goal > 0)
            self._awaiting_wsse = v
            new_active = self._awaiting_wsse or (self._body_goal > 0)
            # Increment/decrement the global counter at most once per change.
            if old_active != new_active:
                if new_active:
                    g_wsse_active_flows += 1
                elif g_wsse_active_flows > 0:
                    g_wsse_active_flows -= 1

    @property
    def body_goal(self):
        """Bytes of body to buffer for WSSE scanning (0 when disabled)."""
        return self._body_goal

    @body_goal.setter
    def body_goal(self, val):
        # Same dual-flag accounting as the awaiting_wsse setter above.
        global g_wsse_active_flows
        # Coerce falsy/None to 0; store an int so comparisons are stable.
        v = int(val) if val else 0
        if self._body_goal != v:
            old_active = self._awaiting_wsse or (self._body_goal > 0)
            self._body_goal = v
            new_active = self._awaiting_wsse or (self._body_goal > 0)
            # Adjust the shared WSSE-flow counter on an activity transition.
            if old_active != new_active:
                if new_active:
                    g_wsse_active_flows += 1
                elif g_wsse_active_flows > 0:
                    g_wsse_active_flows -= 1

    def __del__(self):
        """Release this flow's contribution to the global WSSE-flow counter.

        Called when the flow is garbage-collected so a dropped flow can never
        leak an entry against MAX_WSSE_BODY_FLOWS.
        """
        global g_wsse_active_flows
        # __del__ may run on a partially initialized object, so use getattr
        # with defaults rather than direct attribute access.
        if getattr(self, "_awaiting_wsse", False) or getattr(self, "_body_goal", 0) > 0:
            if g_wsse_active_flows > 0:
                g_wsse_active_flows -= 1

    def reset_for_new_connection(self, next_gen, now=None, syn_seen=True, corr_eligible=True):
        """Reset every field for a brand-new connection (new TCP generation).

        next_gen is the incremented connection counter; now/syn_seen/
        corr_eligible let the caller seed TTL, SYN state and correlation trust.
        """
        # Wipe sequence/framing state: this must behave like a fresh Flow().
        self.next_seq = 0
        self.has_seq = False
        self.is_broken = False
        self.touched = time.time() if now is None else now
        self.first_byte_ts = 0.0
        # Fresh buffers; the previous ones are dropped wholesale.
        self.buf = bytearray()
        self.ooo = []
        self.state = HTTP_STATE_HEADER
        self.body_remaining = 0
        self.chunk_remaining = 0
        self.chunk_payload_remaining = 0
        self.chunk_reading_len = True
        self.chunk_reading_crlf = False
        self.chunk_reading_trailer = False
        # Use the properties here so the global WSSE counter is updated.
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
        # Record the new generation and handshake/correlation metadata.
        self.generation = next_gen
        self.syn_seen = syn_seen
        self.corr_eligible = corr_eligible
        self.correlation_allowed = corr_eligible
        self.ooo_bytes = 0
        self.fin_seen = False
        self.fin_seq = 0
        self.wsse_last_parsed_len = 0

    def wsse_cancel(self, budget=None):
        """Atomically cancel WSSE inspection and decrement the global counter."""
        global g_wsse_active_flows
        was_active = self._awaiting_wsse or (self._body_goal > 0)
        self._awaiting_wsse = False
        self._body_goal = 0
        self.wsse_event = None
        if was_active and g_wsse_active_flows > 0:
            g_wsse_active_flows -= 1
        if self.wsse_buf:
            sz = len(self.wsse_buf)
            del self.wsse_buf[:]
            if budget is not None:
                budget.release(sz)
            elif g_buffer_budget is not None:
                g_buffer_budget.release(sz)
        self.wsse_goal = 0
        self.wsse_req_id = 0
        self.wsse_rk = None
        self.wsse_last_parsed_len = 0


def _ooo_insert(fl, seq, payload, is_truncated=False, budget=None,
                flows=None, resp_flows=None, pending_tbl=None,
                req_k=None, resp_k=None, out=None):
    """Buffer an out-of-order segment for later in-order draining.

    Enforces MAX_OOO_BYTES (16 KiB) and non-overlapping sequence bounds.
    If an overlapping segment contains conflicting byte data, immediately
    quarantines the connection rather than guessing reassembly.
    """
    if is_truncated:
        return True
    if budget is None:
        budget = g_buffer_budget

    b_pay = bytes(payload)
    plen = len(b_pay)
    if plen == 0:
        return True

    # Check for identical/extended sequence or overlapping conflict
    for i, seg in enumerate(fl.ooo):
        s = seg[0]
        d = seg[1] if len(seg) == 2 else seg[2]
        old_len = len(d)
        diff = seq_diff(seq, s)

        # Same starting sequence
        if diff == 0:
            common = min(old_len, plen)
            if common and d[:common] != b_pay[:common]:
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                      response_key=resp_k, out=out, reason="conflicting_retransmit")
                return False
            if old_len >= plen:
                return True
            extra = plen - old_len
            if getattr(fl, "ooo_bytes", 0) + extra > MAX_OOO_BYTES:
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                      response_key=resp_k, out=out, reason="ooo_byte_limit_exceeded")
                return False
            if not budget.reserve(extra):
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                      response_key=resp_k, out=out, reason="global_buffer_ceiling")
                return False
            fl.ooo_bytes += extra
            fl.ooo[i] = (seq, (seq + plen) & 0xFFFFFFFF, b_pay)
            return True

        # Overlapping ranges: check conflicting bytes
        if 0 < diff < old_len:
            overlap = min(old_len - diff, plen)
            if d[diff:diff + overlap] != b_pay[:overlap]:
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                      response_key=resp_k, out=out, reason="conflicting_retransmit")
                return False
            if plen <= overlap:
                return True
            b_pay = b_pay[overlap:]
            seq = (seq + overlap) & 0xFFFFFFFF
            plen = len(b_pay)

        elif -plen < diff < 0:
            overlap = min(plen + diff, old_len)
            off_in_new = -diff
            if b_pay[off_in_new:off_in_new + overlap] != d[:overlap]:
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                      response_key=resp_k, out=out, reason="conflicting_retransmit")
                return False

    if getattr(fl, "ooo_bytes", 0) + plen > MAX_OOO_BYTES:
        quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                              response_key=resp_k, out=out, reason="ooo_byte_limit_exceeded")
        return False

    if len(fl.ooo) >= MAX_OOO_SEGMENTS:
        quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                              response_key=resp_k, out=out, reason="gap_limit_exceeded")
        return False

    if not budget.reserve(plen):
        quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                              response_key=resp_k, out=out, reason="global_buffer_ceiling")
        return False

    fl.ooo_bytes += plen
    fl.ooo.append((seq, (seq + plen) & 0xFFFFFFFF, b_pay))
    return True


def _drain_ooo(fl, budget=None):
    """Move now-contiguous out-of-order segments into the in-order buffer."""
    if budget is None:
        budget = g_buffer_budget
    drained = True
    while drained and fl.ooo:
        drained = False
        for i, seg in enumerate(fl.ooo):
            oseq = seg[0]
            odata = seg[1] if len(seg) == 2 else seg[2]
            odiff = seq_diff(oseq, fl.next_seq)
            if odiff == 0:
                fl.buf.extend(odata)
                fl.next_seq = (fl.next_seq + len(odata)) & 0xFFFFFFFF
                fl.ooo.pop(i)
                fl.ooo_bytes -= len(odata)
                if fl.ooo_bytes < 0:
                    fl.ooo_bytes = 0
                drained = True
                break
            elif odiff < 0:
                o_overlap = -odiff
                seg_len = len(odata)
                if o_overlap < seg_len:
                    tail = odata[o_overlap:]
                    fl.buf.extend(tail)
                    fl.next_seq = (fl.next_seq + len(tail)) & 0xFFFFFFFF
                    budget.release(o_overlap)
                else:
                    budget.release(seg_len)
                fl.ooo.pop(i)
                fl.ooo_bytes -= seg_len
                if fl.ooo_bytes < 0:
                    fl.ooo_bytes = 0
                drained = True
                break


def seq_in_window(seq, base, window):
    """True if seq lies within [base, base + window) using TCP wrap math."""
    return 0 <= seq_diff(seq, base) < window


# --------------------------------------------------- pending-response table --
# Correlating a response to a request requires remembering each request until
# its response header arrives. The table and every entry in it are bounded.
DEFAULT_PENDING_TTL = 30.0
    # PENDING_TTL is configurable (NT_PENDING_TTL_SEC); a bad value falls back.
try:
    PENDING_TTL = float(os.getenv("NT_PENDING_TTL_SEC", "30.0"))
    # Any parse failure uses the compiled-in default.
except (ValueError, TypeError):
    PENDING_TTL = DEFAULT_PENDING_TTL
# Hard cap on distinct response keys; overflow flushes the oldest first.
PENDING_MAX = 8192       # hard cap; overflow flushes oldest first
# Per-key cap so one pipelined/hostile keep-alive connection cannot dominate.
PENDING_PER_FLOW = 32    # bound a single pipelined/hostile keep-alive flow
# Maintenance cadence; honours PENDING_TTL even when the socket stays busy.
SWEEP_INTERVAL = 1.0     # honor PENDING_TTL even when the socket goes idle

pending = {}
# Connections with untrustworthy framing are tracked here (bounded FIFO) so we
# stop trying to correlate their responses without growing without bound.
MAX_CORR_DISABLED = 2048
# Membership set + FIFO list implementing a capped set (py2.6 has no
# OrderedDict).
corr_disabled = set()
corr_disabled_fifo = []
# Sticky flag: once the disabled-set has overflowed, SYN-less new connections
# are also treated as uncorrelatable (fail safe rather than mis-attribute).
corr_capacity_reached = False


def corr_disabled_insert(rk):
    """Remember rk as a connection whose responses must not be correlated.

    Bounded: when the set is full the oldest key is evicted, and a sticky
    capacity flag is set so later SYN-less connections are also distrusted.
    """
    global corr_capacity_reached
    # Idempotent: re-inserting an existing key is a no-op.
    if rk in corr_disabled:
        return
    # Evict oldest entries until there is room (or the FIFO is drained).
    while len(corr_disabled) >= MAX_CORR_DISABLED and corr_disabled_fifo:
        corr_capacity_reached = True
        old_k = corr_disabled_fifo.pop(0)
        corr_disabled.discard(old_k)
    # Record in both the membership set and the FIFO.
    corr_disabled.add(rk)
    corr_disabled_fifo.append(rk)


def corr_disabled_erase(rk):
    """Forget a connection (e.g. a fresh SYN re-enabled its correlation)."""
    # Remove from the set and the FIFO; a missing FIFO entry is tolerated.
    if rk in corr_disabled:
        corr_disabled.discard(rk)
        try:
            corr_disabled_fifo.remove(rk)
        except ValueError:
            pass


def corr_disabled_clear():
    """Wipe the disabled set and reset the sticky capacity flag."""
    global corr_capacity_reached
    corr_disabled.clear()
    del corr_disabled_fifo[:]
    corr_capacity_reached = False


def is_correlation_disabled(rk, syn_seen):
    """True if responses for rk must not be correlated.

    Explicit membership always disables. Once capacity overflowed, only a
    connection that actually showed a SYN is trusted again.
    """
    if rk in corr_disabled:
        return True
    if corr_capacity_reached and not syn_seen:
        return True
    return False


class PendingRequest(object):
    """Track an in-flight HTTP request awaiting response correlation."""
    __slots__ = ("event", "started", "tombstone", "tomb_ts", "generation", "req_id")

    def __init__(self, event, started, generation=0, req_id=0):
        self.event = event
        self.started = started
        self.tombstone = False
        self.tomb_ts = 0.0
        self.generation = generation
        self.req_id = req_id

    def __getitem__(self, idx):
        if idx == 0: return self.event
        if idx == 1: return self.started
        if idx == 2: return self.tombstone
        if idx == 3: return self.tomb_ts
        if idx == 4: return self.generation
        if idx == 5: return self.req_id
        raise IndexError("PendingRequest index out of range: %s" % idx)

    def __setitem__(self, idx, val):
        if idx == 0: self.event = val
        elif idx == 1: self.started = val
        elif idx == 2: self.tombstone = val
        elif idx == 3: self.tomb_ts = val
        elif idx == 4: self.generation = val
        elif idx == 5: self.req_id = val
        else: raise IndexError("PendingRequest index out of range: %s" % idx)

    def __len__(self):
        return 6


g_flow_fifo = deque()
g_resp_flow_fifo = deque()
g_pending_events_total = 0


def pending_actual_count(pending_tbl):
    """Count actual entries across all keys in pending_tbl."""
    if not pending_tbl:
        return 0
    return sum(len(lst) for lst in pending_tbl.values())


def pending_repair_count(pending_tbl):
    """Repair g_pending_events_total if it drifted out of sync."""
    global g_pending_events_total
    actual = pending_actual_count(pending_tbl)
    if g_pending_events_total != actual:
        g_pending_events_total = actual
    return actual


def pending_take(pending_tbl, rk, index=0):
    """Remove exactly one pending entry and keep global accounting correct.

    Returns the PendingRequest, or None if the key/index does not exist.
    Does NOT emit the event.
    """
    global g_pending_events_total

    if pending_tbl is None:
        return None

    lst = pending_tbl.get(rk)
    if not lst:
        return None

    if index < 0 or index >= len(lst):
        return None

    item = lst.pop(index)

    if not lst:
        pending_tbl.pop(rk, None)

    if g_pending_events_total > 0:
        g_pending_events_total -= 1
    else:
        # Counter was already corrupt. Table is authoritative.
        pending_repair_count(pending_tbl)

    return item


def pending_take_all(pending_tbl, rk):
    """Remove all pending entries for rk and keep global accounting correct.

    Returns list of PendingRequests (may be empty).
    Does NOT emit the events.
    """
    global g_pending_events_total

    if pending_tbl is None:
        return []

    lst = pending_tbl.pop(rk, None)
    if not lst:
        return []

    count = len(lst)
    if g_pending_events_total >= count:
        g_pending_events_total -= count
    else:
        # Under-count detected.
        pending_repair_count(pending_tbl)

    return lst


def drain_pending_requests_unresolved(pending_tbl, rk, out=None, reason="unknown"):
    """Flush all uncompleted pending requests for rk without fake status or duration."""
    if pending_tbl is None:
        return
    lst = pending_take_all(pending_tbl, rk)
    if not lst:
        return
    for item in lst:
        is_tomb = item[2] if len(item) > 2 else False
        if not is_tomb:
            ev = item[0]
            ev["status"] = None
            ev["duration_ms"] = None
            ev["resp_bytes"] = None
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()


def reset_flow_for_resync(fl, budget=None):
    """Reset flow parser and reassembly state to allow clean resync."""
    clear_all_flow_buffers(fl, budget)
    fl.has_seq = False
    fl.next_seq = 0
    fl.is_broken = False
    fl.state = HTTP_STATE_HEADER
    fl.body_remaining = 0
    fl.chunk_payload_remaining = 0
    fl.chunk_reading_len = True
    fl.chunk_reading_crlf = False
    fl.chunk_reading_trailer = False
    fl.fin_seen = False
    fl.fin_seq = 0


def quarantine_connection(flows, resp_flows, pending_tbl,
                          request_key=None, response_key=None,
                          out=None, reason="unknown"):
    """Quarantine an untrusted TCP stream across both directions.

    Invoked when packet loss, capture truncation, conflicting retransmission,
    out-of-order segment exhaustion, framing ambiguity, or memory ceiling
    breaches make reliable stream reconstruction impossible.

    Actions:
      1. Flushes uncompleted pending requests to stdout with null status/duration.
      2. Permanently disables response correlation for this TCP generation.
      3. Clears and releases all request/response buffers, OOO segments, and WSSE state.
      4. Resets directional flow state via reset_flow_for_resync so parsers can
         resync on subsequent HTTP boundaries without fake correlation.
    """
    global g_correlation_disabled_total
    g_correlation_disabled_total += 1

    req_k = request_key
    resp_k = response_key
    if req_k is not None and resp_k is None:
        resp_k = (req_k[2], req_k[3], req_k[0], req_k[1])
    elif resp_k is not None and req_k is None:
        req_k = (resp_k[2], resp_k[3], resp_k[0], resp_k[1])

    if resp_k is not None:
        corr_disabled_insert(resp_k)

    if flows is not None and req_k is not None and req_k in flows:
        fl = flows[req_k]
        if getattr(fl, "awaiting_wsse", False) and getattr(fl, "wsse_event", None) is not None:
            ev = fl.wsse_event
            fl.wsse_event = None
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
        reset_flow_for_resync(fl, g_buffer_budget)
        fl.corr_eligible = False
        fl.correlation_allowed = False

    if resp_flows is not None and resp_k is not None and resp_k in resp_flows:
        rfl = resp_flows[resp_k]
        reset_flow_for_resync(rfl, g_buffer_budget)
        rfl.corr_eligible = False
        rfl.correlation_allowed = False

    if pending_tbl is not None:
        if resp_k is not None and resp_k in pending_tbl:
            drain_pending_requests_unresolved(pending_tbl, resp_k, out=out, reason=reason)
        if req_k is not None and req_k in pending_tbl:
            drain_pending_requests_unresolved(pending_tbl, req_k, out=out, reason=reason)


def terminate_connection(flows, resp_flows, pending_tbl, flow_fifo=None, resp_fifo=None,
                         budget=None, request_key=None, response_key=None,
                         out=None, reason="terminated"):
    """Completely tear down a TCP connection in both directions."""
    quarantine_connection(flows, resp_flows, pending_tbl, request_key=request_key,
                          response_key=response_key, out=out, reason=reason)
    if budget is None:
        budget = g_buffer_budget
    req_k = request_key
    resp_k = response_key
    if req_k is not None and resp_k is None:
        resp_k = (req_k[2], req_k[3], req_k[0], req_k[1])
    elif resp_k is not None and req_k is None:
        req_k = (resp_k[2], resp_k[3], resp_k[0], resp_k[1])

    if flows is not None and req_k is not None and req_k in flows:
        clear_all_flow_buffers(flows[req_k], budget)
        del flows[req_k]
    if resp_flows is not None and resp_k is not None and resp_k in resp_flows:
        clear_all_flow_buffers(resp_flows[resp_k], budget)
        del resp_flows[resp_k]
    if pending_tbl is not None:
        if resp_k is not None and resp_k in pending_tbl:
            pending_take_all(pending_tbl, resp_k)
        if req_k is not None and req_k in pending_tbl:
            pending_take_all(pending_tbl, req_k)


def ensure_flow_capacity(flows, resp_flows, flow_fifo, resp_fifo, pending_tbl,
                         reservation=1, out=None, budget=None, now=None):
    """Ensure tracked half-flows do not exceed MAX_TRACKED_HALF_FLOWS."""
    if budget is None:
        budget = g_buffer_budget
    if flow_fifo is None:
        flow_fifo = g_flow_fifo
    if resp_fifo is None:
        resp_fifo = g_resp_flow_fifo
    while ((len(flows) if flows is not None else 0) +
           (len(resp_flows) if resp_flows is not None else 0) +
           reservation) > MAX_TRACKED_HALF_FLOWS:
        evicted = False
        while flow_fifo and flows is not None:
            k = flow_fifo.popleft()
            fl = flows.get(k)
            if fl is not None:
                rk = (k[2], k[3], k[0], k[1])
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=k,
                                      response_key=rk, out=out, reason="flow_capacity_eviction")
                clear_all_flow_buffers(fl, budget)
                flows.pop(k, None)
                evicted = True
                break
        if not evicted and resp_fifo and resp_flows is not None:
            while resp_fifo:
                rk = resp_fifo.popleft()
                rfl = resp_flows.get(rk)
                if rfl is not None:
                    req_k = (rk[2], rk[3], rk[0], rk[1])
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=req_k,
                                          response_key=rk, out=out, reason="flow_capacity_eviction")
                    clear_all_flow_buffers(rfl, budget)
                    resp_flows.pop(rk, None)
                    evicted = True
                    break
        if not evicted:
            if flows:
                k = next(iter(flows))
                fl = flows.pop(k)
                clear_all_flow_buffers(fl, budget)
            elif resp_flows:
                rk = next(iter(resp_flows))
                rfl = resp_flows.pop(rk)
                clear_all_flow_buffers(rfl, budget)
            else:
                break


def get_or_create_request_flow(flows, resp_flows, key, flow_fifo=None, resp_fifo=None,
                               pending_tbl=None, now=None, budget=None, out=None):
    """Retrieve or allocate a tracked request half-flow within global capacity."""
    if flow_fifo is None:
        flow_fifo = g_flow_fifo
    if resp_fifo is None:
        resp_fifo = g_resp_flow_fifo
    fl = flows.get(key)
    if fl is not None:
        fl.touched = now if now is not None else time.time()
        return fl

    ensure_flow_capacity(flows, resp_flows, flow_fifo, resp_fifo, pending_tbl,
                         reservation=1, out=out, budget=budget, now=now)
    fl = Flow()
    fl.touched = now if now is not None else time.time()
    flows[key] = fl
    flow_fifo.append(key)
    return fl


def get_or_create_response_flow(flows, resp_flows, key, flow_fifo=None, resp_fifo=None,
                                pending_tbl=None, now=None, budget=None, out=None):
    """Retrieve or allocate a tracked response half-flow within global capacity."""
    if flow_fifo is None:
        flow_fifo = g_flow_fifo
    if resp_fifo is None:
        resp_fifo = g_resp_flow_fifo
    rfl = resp_flows.get(key)
    if rfl is not None:
        rfl.touched = now if now is not None else time.time()
        return rfl

    ensure_flow_capacity(flows, resp_flows, flow_fifo, resp_fifo, pending_tbl,
                         reservation=1, out=out, budget=budget, now=now)
    rfl = Flow()
    rfl.touched = now if now is not None else time.time()
    resp_flows[key] = rfl
    resp_fifo.append(key)
    return rfl


def assert_internal_invariants(flows, resp_flows, pending_tbl=None, budget=None):
    """Debug validator to enforce memory, flow, and framing invariants."""
    if budget is not None:
        assert 0 <= budget.total <= budget.ceiling, "Budget out of bounds: %d" % budget.total
    assert len(flows) + len(resp_flows) <= MAX_TRACKED_HALF_FLOWS, (
        "Flow table exceeds capacity: %d + %d > %d" %
        (len(flows), len(resp_flows), MAX_TRACKED_HALF_FLOWS)
    )
    for fl in flows.values():
        assert fl.ooo_bytes <= MAX_OOO_BYTES, "Req flow OOO exceeds limit: %d" % fl.ooo_bytes
        if fl.state == HTTP_STATE_UNSYNCED:
            assert len(fl.buf) == 0, "UNSYNCED req flow has non-empty buf: %d" % len(fl.buf)
    for rfl in resp_flows.values():
        assert rfl.ooo_bytes <= MAX_OOO_BYTES, "Resp flow OOO exceeds limit: %d" % rfl.ooo_bytes
        if rfl.state == HTTP_STATE_UNSYNCED:
            assert len(rfl.buf) == 0, "UNSYNCED resp flow has non-empty buf: %d" % len(rfl.buf)
    if pending_tbl is not None:
        actual = pending_actual_count(pending_tbl)
        assert g_pending_events_total == actual, (
            "Pending accounting mismatch: counter=%d actual=%d" %
            (g_pending_events_total, actual)
        )


def invalidate_connection_correlation(flows, resp_flows, rk, pending_tbl=None, out=None, reason="invalidated"):
    """Permanently stop correlating one connection's responses."""
    if pending_tbl is None:
        pending_tbl = pending
    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason=reason)


def is_correlation_allowed(rk, flows=None, resp_flows=None, gen=0, syn_seen=False, corr_eligible=True):
    """Whether a response may be attached to a pending request.

    Combines several vetoes: an explicitly disabled key, a caller-provided
    eligibility flag, the framing health of either direction, and -- once the
    overflow ceiling has been touched -- proof of a genuine new SYN.
    """
    global corr_capacity_reached
    # 1) Explicit disable (e.g. from an earlier overflow or parse error).
    if rk in corr_disabled:
        return False
    # 2) Caller-level veto (e.g. flow is un-synchronized).
    if not corr_eligible:
        return False
    # 3) Health of the response flow for this key.
    if resp_flows is not None:
        rfl = resp_flows.get(rk)
        if rfl is not None:
            if not getattr(rfl, "corr_eligible", True) or getattr(rfl, "is_broken", False):
                return False
    # 4) Request direction likewise.
    if flows is not None:
        cfk = (rk[2], rk[3], rk[0], rk[1])
        cfl = flows.get(cfk)
        if cfl is not None:
            if not getattr(cfl, "corr_eligible", True) or getattr(cfl, "is_broken", False):
                return False
    # 5) Post-overflow: require a genuine SYN (gen > 0) to trust a connection.
    if corr_capacity_reached:
        if not syn_seen or gen == 0:
            return False
    return True


def pending_del(rk):
    """Drop every pending request for rk and re-enable correlation for it."""
    pending_take_all(pending, rk)
    corr_disabled_erase(rk)


def pending_pop(rk, out, pending_tbl=None):
    """Flush the oldest pending event for this response tuple (FIN/RST or
    overflow path). Emits whatever the event has — status stays null."""
    if pending_tbl is None:
        pending_tbl = pending
    item = pending_take(pending_tbl, rk, 0)
    if item is None:
        return None
    is_tombstone = item[2] if len(item) > 2 else False
    if not is_tombstone:
        ev = item[0]
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return ev
    return None


def transfer_encoding_final_chunked(raw):
    """True only if Transfer-Encoding's final coding is exactly "chunked".

    Per RFC 7230 a message is chunked-framed only when the LAST transfer-coding
    is chunked and it is not repeated earlier. Anything else (e.g.
    "chunked, gzip" or a duplicated "chunked") is not safely parseable here.
    """
    if not raw:
        return False
    # Accept either bytes or text; normalize to text for token splitting.
    if isinstance(raw, bytes):
        raw = raw.decode("latin1", "replace")
    s = raw.strip().lower()
    if not s:
        return False
    # Transfer-Encoding is a comma-separated, ordered list of codings.
    tokens = [p.strip() for p in s.split(",")]
    # Empty token (bad syntax) or a final coding that is not chunked -> reject.
    if any(not tok for tok in tokens) or tokens[-1] != "chunked":
        return False
    # "chunked" appearing anywhere but last is invalid framing.
    if any(tok == "chunked" for tok in tokens[:-1]):
        return False
    return True


def parse_response_head(payload):
    """First line 'HTTP/1.x NNN ...' -> (status_int|None, content_len|None, head_end_idx|None, is_chunked, is_close)."""
    try:
        # Work on an immutable bytes snapshot of the reassembled buffer.
        raw = bytes(payload)
        # The head ends at the first blank line.
        idx = raw.find(b"\r\n\r\n")
        if idx < 0:
            return None, None, None, False, False
        head = raw[:idx]
        # Tolerate bare-LF line endings as a fallback.
        lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
        # Status line: "HTTP/1.x <3-digit> [reason]".
        first = lines[0].split()
        # Must be HTTP/1.0 or HTTP/1.1 and carry a status code.
        if len(first) < 2 or first[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
            return None, None, idx + 4, False, False
        # The status code must be exactly three digits.
        if len(first[1]) != 3 or not first[1].isdigit():
            return None, None, idx + 4, False, False
        # Status codes outside 100..599 are not valid HTTP. head_len is
        # returned so the caller can trim past this head even when the status
        # line itself is unusable.
        st = int(first[1])
        if st < 100 or st > 599:
            return None, None, None, False, False
    except (ValueError, IndexError):
        return None, None, None, False, False
    # Header scan state. Only Content-Length, Transfer-Encoding and
    # Connection matter; the first-byte filter below skips the rest cheaply.
    clen = None
    has_clen = False
    has_conflict_cl = False
    is_chunked = False
    is_close = False
    # HTTP/1.0 defaults to close-delimited bodies unless keep-alive is asked.
    is_http_10 = first[0].startswith(b"HTTP/1.0")
    conn_close = False
    conn_keep_alive = False
    has_te = False
    invalid_te = False
    resp_te = b""
    # Walk the remaining header lines.
    for ln in lines[1:]:
        if not ln:
            continue
        # Fast reject: only Content*/Transfer*/Connection* start with c/t;
        # everything else is skipped without lowercasing.
        c0 = ln[:1]
        if c0 not in (b"c", b"C", b"t", b"T"):
            continue
        low = ln.lower()
        # Content-Length: a non-negative int; a second differing value (or a
        # negative one) is a request-smuggling style conflict -> untrusted.
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
        # Transfer-Encoding: accumulate codings (bounded to 256 bytes).
        elif low.startswith(b"transfer-encoding:"):
            has_te = True
            v = ln.split(b":", 1)[1].strip()
            # A single oversized coding value is treated as invalid.
            if len(v) > 256:
                invalid_te = True
            else:
                if resp_te:
                    resp_te += b","
                # Keep the accumulated coding list bounded too.
                if len(resp_te) + len(v) > 256:
                    invalid_te = True
                else:
                    resp_te += v
        # Connection: close/keep-alive changes body framing for HTTP/1.0.
        elif low.startswith(b"connection:"):
            if b"close" in low:
                conn_close = True
            elif b"keep-alive" in low:
                conn_keep_alive = True
    # TE present: only a valid chunked-final encoding is parseable; otherwise
    # the whole head is untrusted and correlation is refused.
    if has_te:
        if invalid_te or not transfer_encoding_final_chunked(resp_te):
            return None, None, None, False, False
        is_chunked = True
    # Content-Length together with Transfer-Encoding (or a conflicting
    # Content-Length) is ambiguous framing -> refuse to parse.
    if has_conflict_cl or (has_clen and (has_te or is_chunked)):
        return None, None, None, False, False
    # Determine whether the body is delimited by connection close.
    if is_http_10 and not conn_keep_alive:
        is_close = True
    elif conn_close:
        is_close = True
    return st, clen, idx + 4, is_chunked, is_close



def handle_response(resp_flows, rk, payload, now, out, pending_tbl, seq=None, flags=0, is_truncated=False, flows=None):
    """Reassemble and interpret one server->client (response) segment.

    resp_flows is the response-direction flow table keyed by rk. seq/flags are
    the raw TCP sequence and flag byte from process_packet. Complete response
    heads are matched against pending_tbl and emitted with status/duration_ms/
    resp_bytes; bodies are consumed only to keep framing in sync.
    """
    global g_truncated_frames_total
    # SYN (0x02) in the response direction: start a fresh response generation,
    # seeded from the request direction's generation when available.
    if flags & 0x02 and seq is not None:
        rfl = resp_flows.get(rk) if resp_flows is not None else None
        # Duplicate SYN for an already-established flow: ignore.
        if rfl is not None and getattr(rfl, "has_seq", False):
            return
        gen = rfl.generation if rfl is not None else 0
        syn = rfl.syn_seen if rfl is not None else False
        eligible = rfl.corr_eligible if rfl is not None else True
        # If this side has no generation yet, inherit the request side's.
        if gen == 0 and flows is not None:
            cfk = (rk[2], rk[3], rk[0], rk[1])
            cfl = flows.get(cfk)
            if cfl is not None and cfl.generation > 0:
                gen = cfl.generation
                syn = cfl.syn_seen
                eligible = cfl.corr_eligible
        # Create the response flow lazily on first sight within global capacity.
        rfl = get_or_create_response_flow(flows, resp_flows, rk, g_flow_fifo, g_resp_flow_fifo,
                                          pending_tbl, now, budget=g_buffer_budget, out=out)
        # Reset all framing state for the new connection and pin the sequence
        # to just past the SYN.
        rfl.reset_for_new_connection(gen, now=now, syn_seen=syn or True, corr_eligible=eligible if gen > 0 else True)
        rfl.has_seq = True
        rfl.next_seq = (seq + 1) & 0xFFFFFFFF
        return

    # Non-SYN segment: get (or lazily create) the response flow.
    rfl = get_or_create_response_flow(flows, resp_flows, rk, g_flow_fifo, g_resp_flow_fifo,
                                      pending_tbl, now, budget=g_buffer_budget, out=out)
    rfl.touched = now

    # Length of this segment's TCP payload (0 for pure ACK/FIN).
    plen = len(payload) if payload else 0

    # If correlation is disallowed (or the flow is desynced), drop buffered
    # bytes and only handle teardown so the flow can be reaped.
    allowed = is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                     gen=rfl.generation, syn_seen=rfl.syn_seen,
                                     corr_eligible=getattr(rfl, "corr_eligible", True))
    if not allowed or getattr(rfl, "state", None) == HTTP_STATE_UNSYNCED:
        clear_all_flow_buffers(rfl, g_buffer_budget)
        # RST (0x04): connection is gone -> reap the flow and flush pending.
        if flags & 0x04:
            terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                 g_buffer_budget, response_key=rk, out=out, reason="rst_unsynced")
        # FIN (0x01): remember the end sequence and reap once drained.
        elif flags & 0x01:
            if seq is not None:
                rfl.fin_seen = True
                rfl.fin_seq = (seq + plen) & 0xFFFFFFFF
            if not rfl.has_seq or seq_diff(rfl.fin_seq, rfl.next_seq) <= 0:
                if getattr(rfl, "state", None) in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY, HTTP_STATE_UNSYNCED) and not rfl.buf and not rfl.ooo:
                    terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                         g_buffer_budget, response_key=rk, out=out, reason="fin_unsynced")
        return

    # Reassemble this segment into the in-order buffer.
    if plen > 0:
        # A truncated frame means the capture missed bytes: framing is no
        # longer trustworthy, so break the flow and flush its pending events.
        if is_truncated:
            g_truncated_frames_total += 1
            quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="truncated_frame")
            return

        # No sequence available (direct test feed): append blindly.
        if seq is None:
            append_flow_buf(rfl, payload, g_buffer_budget, flows, resp_flows, pending_tbl, response_key=rk, out=out)
        else:
            # First segment seen: try to locate the response start (resync).
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
                # Otherwise accept it if it already looks like an HTTP start
                # (or a prefix of one split across the segment boundary).
                elif (plen >= 5 and payload[:5] == b"HTTP/") or (plen < 5 and b"HTTP/".startswith(payload)):
                    rfl.has_seq = True
                    rfl.next_seq = seq
                    rfl.is_broken = False
                else:
                    # No HTTP start yet: hold the segment until a gap fills.
                    if not _ooo_insert(rfl, seq, payload, is_truncated, budget=g_buffer_budget):
                        quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="ooo_insert_failed")
                    return

            # Compare against the expected next sequence.
            diff = seq_diff(seq, rfl.next_seq)
            if diff == 0:
                append_flow_buf(rfl, payload, g_buffer_budget, flows, resp_flows, pending_tbl, response_key=rk, out=out)
                rfl.next_seq = (rfl.next_seq + plen) & 0xFFFFFFFF
                _drain_ooo(rfl, budget=g_buffer_budget)
            # Overlapping retransmission: append only the unseen tail.
            elif diff < 0:
                overlap = -diff
                if overlap < plen and not is_truncated:
                    append_flow_buf(rfl, payload[overlap:], g_buffer_budget, flows, resp_flows, pending_tbl, response_key=rk, out=out)
                    rfl.next_seq = (rfl.next_seq + plen - overlap) & 0xFFFFFFFF
                    _drain_ooo(rfl, budget=g_buffer_budget)
            # Gap (diff > 0): buffer as out-of-order.
            else:
                if not _ooo_insert(rfl, seq, payload, is_truncated, budget=g_buffer_budget):
                    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="ooo_insert_failed")

    # Parse complete responses from reassembled buffer using HTTP framing
    # If FIN arrived and we have consumed up to it with nothing buffered, the
    # response had a close-delimited body; switch to CLOSE_BODY.
    if rfl.fin_seen and rfl.has_seq:
        fdiff = seq_diff(rfl.fin_seq, rfl.next_seq)
        if fdiff <= 0:
            if rfl.state == HTTP_STATE_HEADER and not rfl.buf and not rfl.ooo:
                rfl.state = HTTP_STATE_CLOSE_BODY

    # Drain complete messages out of the reassembled buffer.
    while rfl.buf and not rfl.is_broken:
        # --- HEADER: find and classify one response head ---
        if rfl.state == HTTP_STATE_HEADER:
            st, clen, head_len, is_chunked, is_close = parse_response_head(rfl.buf)
            # Symmetrical response header cap check:
            if head_len is None and len(rfl.buf) > MAX_HDRS:
                quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_header_too_large")
                break
            # Absurd body framing check:
            if clen is not None and clen > MAX_HTTP_BODY_FRAMING:
                quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="absurd_body_framing")
                break

            # No usable status line yet.
            if st is None:
                # head_len set means a head ended but the status line was bad:
                # skip past it and keep looking.
                if head_len is not None:
                    consume_flow_buf(rfl, head_len, g_buffer_budget)
                elif rfl.buf.find(b"\r\n\r\n") != -1:
                    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="malformed_resp_head")
                break

            # Interim 1xx informational responses (except 101) are skipped;
            # the final response follows in the same stream.
            if 100 <= st <= 199 and st != 101:
                consume_flow_buf(rfl, head_len, g_buffer_budget)
                continue

            # Re-check correlation right before attaching this head.
            allowed = is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                             gen=rfl.generation, syn_seen=rfl.syn_seen,
                                             corr_eligible=rfl.corr_eligible)
            # Queue of pending requests for this connection (may be empty).
            ent = pending_tbl.get(rk) if (allowed and pending_tbl is not None) else None

            # 101 Switching Protocols (e.g. WebSocket upgrade): no further
            # HTTP framing can be trusted, so report the 101 and lock out.
            if st == 101:
                consume_flow_buf(rfl, head_len, g_buffer_budget)
                removed = pending_take_all(pending_tbl, rk)
                if removed:
                    item = removed[0]
                    is_tombstone = item[2] if len(item) > 2 else False
                    if not is_tombstone:
                        ev = item[0]
                        started = item[1]
                        ev["status"] = 101
                        ev["duration_ms"] = max(0, int((now - started) * 1000))
                        ev["resp_bytes"] = 0
                        if out is not None:
                            if isinstance(out, list):
                                out.append(ev)
                            elif hasattr(out, "write"):
                                out.write(json.dumps(ev) + "\n")
                                if hasattr(out, "flush"):
                                    out.flush()
                    for rem_item in removed[1:]:
                        if not (rem_item[2] if len(rem_item) > 2 else False):
                            if out is not None:
                                if isinstance(out, list):
                                    out.append(rem_item[0])
                                elif hasattr(out, "write"):
                                    out.write(json.dumps(rem_item[0]) + "\n")
                                    if hasattr(out, "flush"):
                                        out.flush()
                corr_disabled_insert(rk)
                quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="websocket_upgrade_101")
                rfl.state = HTTP_STATE_UNSYNCED
                if flows is not None:
                    cfk = (rk[2], rk[3], rk[0], rk[1])
                    cfl = flows.get(cfk)
                    if cfl is not None:
                        cfl.state = HTTP_STATE_UNSYNCED
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
                    cfl.wsse_cancel(g_buffer_budget)

            # A HEAD request has no body regardless of headers.
            is_head = False

            # Match this response head to the OLDEST pending request.
            if ent:
                item = ent[0]
                is_tombstone = item[2] if len(item) > 2 else False
                gen = item[4] if len(item) > 4 else 0
                # Stale generation: the queued request belongs to an older
                # connection, so emit it un-correlated instead of mismatching.
                if rfl.generation != 0 and gen != 0 and gen != rfl.generation:
                    titem = pending_take(pending_tbl, rk, 0)
                    if titem is not None:
                        ev = titem[0]
                        if out is not None:
                            if isinstance(out, list):
                                out.append(ev)
                            elif hasattr(out, "write"):
                                out.write(json.dumps(ev) + "\n")
                                if hasattr(out, "flush"):
                                    out.flush()
                else:
                    ev = item[0]
                    # Remember HEAD so no body is expected.
                    if ev.get("method") == "HEAD":
                        is_head = True
                    # Tombstone = request already emitted; drop and move on.
                    if is_tombstone:
                        pending_take(pending_tbl, rk, 0)
                    else:
                        # Attach status/duration_ms/resp_bytes to the match.
                        started = item[1]
                        titem = pending_take(pending_tbl, rk, 0)
                        if titem is not None:
                            ev = titem[0]
                            ev["status"] = st
                            ev["duration_ms"] = max(0, int((now - started) * 1000))
                            if clen is not None:
                                ev["resp_bytes"] = clen
                            if out is not None:
                                if isinstance(out, list):
                                    out.append(ev)
                                elif hasattr(out, "write"):
                                    out.write(json.dumps(ev) + "\n")
                                    if hasattr(out, "flush"):
                                        out.flush()

            # Consume the head just processed.
            consume_flow_buf(rfl, head_len, g_buffer_budget)

            # Bodyless responses -> back to HEADER immediately.
            if is_head or st == 204 or st == 304:
                rfl.state = HTTP_STATE_HEADER
            # Chunked framing -> CHUNK state.
            elif is_chunked:
                rfl.state = HTTP_STATE_CHUNK
                rfl.chunk_reading_len = True
                rfl.chunk_reading_crlf = False
                rfl.chunk_reading_trailer = False
                rfl.chunk_payload_remaining = 0
            # Content-Length framing; zero means no body.
            elif clen is not None:
                if clen > 0:
                    rfl.state = HTTP_STATE_BODY
                    rfl.body_remaining = clen
                else:
                    rfl.state = HTTP_STATE_HEADER
            # No length information: body runs until connection close.
            else:
                rfl.state = HTTP_STATE_CLOSE_BODY
            continue

        # --- BODY: discard Content-Length bytes (only the head matters) ---
        if rfl.state == HTTP_STATE_BODY:
            if not rfl.buf:
                break
            to_consume = min(len(rfl.buf), rfl.body_remaining)
            consume_flow_buf(rfl, to_consume, g_buffer_budget)
            rfl.body_remaining -= to_consume
            if rfl.body_remaining == 0:
                rfl.state = HTTP_STATE_HEADER
            continue

        # --- CHUNK: walk chunked framing to find the next response ---
        if rfl.state == HTTP_STATE_CHUNK:
            if not rfl.buf:
                break
            # Trailer section after the zero-length chunk; ends at CRLFCRLF
            # (or a lone CRLF when there is no trailer).
            if rfl.chunk_reading_trailer:
                if len(rfl.buf) >= 2 and rfl.buf[:2] == b"\r\n":
                    consume_flow_buf(rfl, 2, g_buffer_budget)
                    rfl.chunk_reading_trailer = False
                    rfl.state = HTTP_STATE_HEADER
                    continue
                tr_end = rfl.buf.find(b"\r\n\r\n")
                if tr_end != -1:
                    consume_flow_buf(rfl, tr_end + 4, g_buffer_budget)
                    rfl.chunk_reading_trailer = False
                    rfl.state = HTTP_STATE_HEADER
                    continue
                if len(rfl.buf) > MAX_HDRS:
                    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_chunk_trailer_too_large")
                break
            # Reading a chunk-size line: hex digits, optional ";ext".
            if rfl.chunk_reading_len:
                crlf = rfl.buf.find(b"\r\n")
                if crlf == -1:
                    if len(rfl.buf) > 64:
                        quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_chunk_line_too_large")
                    break
                line = bytes(rfl.buf[:crlf]).strip()
                semi = line.find(b";")
                hex_str = line[:semi].strip() if semi != -1 else line
                # Chunk size is hex; bound it to 16 MiB to reject garbage.
                try:
                    chunk_len = int(hex_str, 16)
                    if chunk_len < 0 or chunk_len > 16777216:
                        quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_absurd_chunk_len")
                        break
                except ValueError:
                    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_invalid_chunk_hex")
                    break
                consume_flow_buf(rfl, crlf + 2, g_buffer_budget)
                if chunk_len == 0:
                    rfl.chunk_reading_trailer = True
                    rfl.chunk_reading_len = False
                    continue
                else:
                    rfl.chunk_payload_remaining = chunk_len
                    rfl.chunk_reading_len = False
                    rfl.chunk_reading_crlf = False
            # Skip the CRLF that follows each chunk's payload.
            elif getattr(rfl, "chunk_reading_crlf", False):
                if len(rfl.buf) < 2:
                    break
                if rfl.buf[:2] != b"\r\n":
                    quarantine_connection(flows, resp_flows, pending_tbl, response_key=rk, out=out, reason="resp_chunk_missing_crlf")
                    break
                consume_flow_buf(rfl, 2, g_buffer_budget)
                rfl.chunk_reading_crlf = False
                rfl.chunk_reading_len = True
            # Consume chunk payload bytes (contents are discarded).
            else:
                to_consume = min(len(rfl.buf), rfl.chunk_payload_remaining)
                consume_flow_buf(rfl, to_consume, g_buffer_budget)
                rfl.chunk_payload_remaining -= to_consume
                if rfl.chunk_payload_remaining == 0:
                    rfl.chunk_reading_crlf = True
            continue

        # CLOSE_BODY: everything until FIN is body; drop it and stop.
        if rfl.state == HTTP_STATE_CLOSE_BODY:
            clear_main_buffer(rfl, g_buffer_budget)
            break

    # Post-loop FIN check (mirrors the pre-loop one in case state advanced).
    if rfl.fin_seen and rfl.has_seq:
        fdiff = seq_diff(rfl.fin_seq, rfl.next_seq)
        if fdiff <= 0:
            if rfl.state == HTTP_STATE_HEADER and not rfl.buf and not rfl.ooo:
                rfl.state = HTTP_STATE_CLOSE_BODY

    # RST -> reap. FIN -> reap once the stream is fully drained.
    if flags & 0x04:
        terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                             g_buffer_budget, response_key=rk, out=out, reason="rst")
    elif flags & 0x01:
        if seq is not None:
            rfl.fin_seen = True
            rfl.fin_seq = (seq + plen) & 0xFFFFFFFF
        if not rfl.has_seq or seq_diff(rfl.fin_seq, rfl.next_seq) <= 0:
            if rfl.state in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY) and not rfl.buf and not rfl.ooo:
                terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                     g_buffer_budget, response_key=rk, out=out, reason="fin")


def correlate_response(pending_tbl, rk, payload, now, out, resp_flows=None, seq=None, flags=0, is_truncated=False):
    """Attach one response head to the oldest request on a connection.

    HTTP/1.1 pipelining can leave several requests queued for the same
    four-tuple. Consume exactly one entry; deleting the whole key here loses
    every request after the first response.
    """
    # Full path: hand off to the streaming response state machine.
    if resp_flows is not None:
        handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                        seq=seq, flags=flags, is_truncated=is_truncated)
        return True
    # Legacy stateless path (no response flow table): parse a single head.
    res = parse_response_head(payload)
    if res[0] is None:
        return False
    st, clen, head_len = res[0], res[1], res[2]
    # Skip interim 1xx heads and recurse on the remainder.
    if 100 <= st <= 199 and st != 101:
        if head_len is not None and len(payload) > head_len:
            return correlate_response(pending_tbl, rk, payload[head_len:], now, out)
        return False
    item = pending_take(pending_tbl, rk, 0)
    if item is None:
        return False
    # Consume exactly one request (pipelining-safe) and enrich it.
    ev, started = item[0], item[1]
    ev["status"] = st
    ev["duration_ms"] = max(0, int((now - started) * 1000))
    if clen is not None:
        ev["resp_bytes"] = clen
    out.append(ev)
    return True


def valid_port(p):
    """True if p is an integer in the valid TCP port range 1..65535."""
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


def basic_user(value):
    """Authorization header value -> (user|None, scheme|None). Basic only."""
    # "Basic <base64>" / "Bearer <token>" -> at most two whitespace tokens.
    parts = value.strip().split(None, 1)
    if len(parts) != 2:
        return None, None
    # Lowercase the scheme for a case-insensitive match.
    scheme = parts[0].lower()
    # Basic auth: decode strictly, then take ONLY the part before the first
    # ':'. The password (everything after ':') is never returned, stored,
    # logged or serialized anywhere in this module.
    if scheme == "basic":
        try:
            token = parts[1].strip()
            # Reject empty/oversized tokens and anything not valid base64
            # length (must be a multiple of 4).
            if not token or len(token) > 1024 or len(token) % 4 != 0:
                return None, None
            # Strict base64 alphabet check: A-Z a-z 0-9 + / with at most two
            # trailing '=' padding chars and no data after padding begins.
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
            # Decode now that the token is known well-formed.
            raw = base64.b64decode(token)
            # Bound the decoded size (credentials are short in practice).
            if len(raw) > 512:
                return None, None
            # "user:password" -- split on the FIRST colon only, so a ':' in
            # the password cannot truncate or leak into the username.
            if b":" in raw:
                user_raw = raw.split(b":", 1)[0]
                # Refuse implausibly long usernames.
                if len(user_raw) >= 256:
                    return None, None
                # Decode leniently and clamp; only the username is kept.
                user = user_raw.decode("utf-8", "replace")[:64]
                if user:
                    return user, "basic"
        except Exception:
            return None, None
    # Bearer tokens carry no username; report the scheme with no user.
    elif scheme == "bearer":
        return None, "bearer"
    # Anything else (Digest, NTLM, ...) is not attributed.
    return None, None


def normalize_wsse_username(value):
    """Return a small, printable username or None; never return token data."""
    # Normalize a candidate SOAP username into something safe to emit:
    # printable, bounded, and never a credential.
    if value is None:
        return None
    try:
        username = value.strip()
    except Exception:
        return None
    # Empty or over-long values are rejected outright.
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

    # Slow path: reject any Unicode char whose category starts with "C"
    # (control/format/unassigned), which could smuggle control sequences.
    for char in username:
        if unicodedata.category(char).startswith("C"):
            return None
    return username


# Internal control-flow exception: raised inside the expat callbacks to stop
# parsing the instant a username has been found (avoids scanning the rest of
# the body).
class _UsernameFound(Exception):
    """Signal that a WSSE Username value was captured; aborts parsing early."""
    pass


def extract_wsse_username(body):
    """Parse a bounded, possibly partial SOAP prefix and return only Username.

    Expat is run incrementally so a UsernameToken in the SOAP Header can be
    recognized without retaining or requiring the complete request body.
    DTD/entity declarations are rejected before parsing.
    """
    # Reject empty/oversized buffers and any NUL (not valid XML text).
    if not body or len(body) > MAX_WSSE_BODY_BYTES or b"\x00" in body:
        return None
    # Cheap pre-filter: most bodies cannot contain a UsernameToken at all.
    if b"UsernameToken" not in body:
        return None
    # Refuse DTD/entity declarations before handing bytes to expat (XXE and
    # billion-laughs defence).
    if b"<!" in body:
        lowered = bytes(body).lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            return None

    # Parser state: element stack of (namespace, localname) pairs, depth of the
    # UsernameToken and its Username child, captured character chunks, an
    # over-length flag and the final result.
    state = {"stack": [], "token_depth": 0, "username_depth": 0,
             "chars": [], "too_long": False, "result": None}

    # expat with separator "}" reports names as "{namespace}localname".
    def split_name(name):
        """Split "{namespace}local" into (namespace, local); "" if unqualified."""
        if "}" not in name:
            return "", name
        return name.rsplit("}", 1)

    # StartElementHandler: track depth and recognize the UsernameToken element
    # in an accepted namespace, then its immediate Username child.
    def start(name, attrs):
        """Record element nesting and latch onto a trusted UsernameToken."""
        namespace, local_name = split_name(name)
        state["stack"].append((namespace, local_name))
        depth = len(state["stack"])
        # Only the FIRST UsernameToken is considered; it must sit in one of
        # the accepted WSSE namespaces.
        if (not state["token_depth"] and local_name == "UsernameToken" and
                namespace in WSSE_NAMESPACES):
            state["token_depth"] = depth
        # A Username element exactly one level under the token, in the same
        # namespace, is the field we want.
        elif (state["token_depth"] and
              depth == state["token_depth"] + 1 and
              local_name == "Username" and
              namespace == state["stack"][state["token_depth"] - 1][0]):
            state["username_depth"] = depth
            state["chars"] = []
            state["too_long"] = False

    # CharacterDataHandler: accumulate the Username text, bounded.
    def chars(value):
        """Collect Username character data, aborting once it is too long."""
        if not state["username_depth"] or state["too_long"]:
            return
        state["chars"].append(value)
        # Tolerate a couple of extra bytes, then give up on this token.
        if sum([len(part) for part in state["chars"]]) > MAX_WSSE_USERNAME + 2:
            state["chars"] = []
            state["too_long"] = True

    # EndElementHandler: on closing </Username> finalize the value; on closing
    # the token, forget its depth.
    def end(name):
        """Finalize a captured Username; stop parsing once it is accepted."""
        depth = len(state["stack"])
        # Closing the Username element: normalize and, if valid, raise to stop.
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

    # Run expat incrementally with "}" as the namespace separator. The body may
    # be a truncated prefix; a username fully closed before truncation is still
    # usable, which is why ExpatError below is swallowed.
    try:
        # ParserCreate(encoding=None, namespace_separator="}").
        parser = expat.ParserCreate(None, "}")
        # py2: request unicode character data so ord()/category work right.
        if hasattr(parser, "returns_unicode"):
            parser.returns_unicode = True
        parser.StartElementHandler = start
        parser.CharacterDataHandler = chars
        parser.EndElementHandler = end
        # Explicitly disable parameter-entity parsing as defence in depth.
        if (hasattr(parser, "SetParamEntityParsing") and
                hasattr(expat, "XML_PARAM_ENTITY_PARSING_NEVER")):
            parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        # Parse as a non-final chunk (False) so truncation is tolerated.
        parser.Parse(bytes(body), False)
    # Found a username: expected control-flow exit.
    except _UsernameFound:
        pass
    except (expat.ExpatError, ValueError, TypeError):
        # A bounded prefix is commonly incomplete. A username fully closed
        # before the truncation point is still safe to use.
        pass
    # Return the captured username, or None if none was safely extracted.
    return state["result"]


def is_soap_content_type(value):
    """True if a Content-Type value denotes XML (SOAP or generic).

    Accepts text/xml, application/xml, application/soap+xml and any "...+xml"
    media type; the charset parameter is ignored.
    """
    # Cheap pre-filter before the more precise media-type check.
    if not value or "xml" not in value:
        return False
    # Strip parameters (charset=...) and normalize case.
    media_type = value.split(";", 1)[0].strip().lower()
    return (media_type in ("text/xml", "application/xml",
                           "application/soap+xml") or
            media_type.endswith("+xml"))


def finish_event(flow, key, dst_ip, dport, src_ip, sport, ports, node_host):
    """Build the JSONL event dict for one completed request.

    flow carries the parsed headers; key/dst_ip/dport/src_ip/sport identify the
    connection; ports is the monitored set and node_host the node name. Returns
    None when the destination is not monitored and no method was parsed.
    """
    h = flow.hdrs
    user = scheme = None
    # Authorization header -> username + scheme (password never extracted).
    authz = h.get("authorization")
    if authz:
        user, scheme = basic_user(authz)
    # W3C trace context: honor incoming traceparent, else generate one so
    # every transaction carries a trace_id for hub-side correlation.
    # NOTE py2.6: bytes has no .hex() — use binascii.hexlify.
    # Honour a valid incoming traceparent so spans stitch together.
    tp = h.get("traceparent")
    trace_id = None
    if tp:
        parts = tp.split("-")
        # Valid form: 00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>.
        if len(parts) == 4 and len(parts[1]) == 32 and len(parts[2]) == 16 and len(parts[3]) == 2:
            try:
                int(parts[3], 16)
                trace_id = parts[1].lower()
            except ValueError:
                pass
    # No (valid) incoming trace context: mint a fresh traceparent. The
    # trace_id is 16 random bytes; the span-id 8 random bytes; flags 01=sampled.
    if not trace_id:
        try:
            raw = os.urandom(24)
            rnd = binascii.hexlify(raw[:16])
            rnd = rnd.decode("ascii") if hasattr(rnd, "decode") else rnd
            pid8 = binascii.hexlify(raw[16:24])
            pid8 = pid8.decode("ascii") if hasattr(pid8, "decode") else pid8
        except Exception:
            global g_seq_counter
            g_seq_counter += 1
            t = int(time.time() * 1000000)
            pid = os.getpid()
            rnd = "%016x%08x%08x" % (t, pid, g_seq_counter & 0xFFFFFFFF)
            pid8 = "%08x%08x" % (pid, (g_seq_counter + 1) & 0xFFFFFFFF)
        # Assemble the W3C traceparent: version-traceid-spanid-flags.
        tp = "00-%s-%s-01" % (rnd, pid8)
        trace_id = rnd
    # Event schema emitted on stdout (one JSON object per line). status/
    # duration_ms/resp_bytes are filled in later by response correlation.
    ev = {
        "ts": int(time.time()),
        "host": node_host,
        "src": "pcap",
        "service": "port:%d" % dport,
        "method": h.get("_method") or "-",
        # Path only (query string stripped) and clamped to 120 chars.
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
        # traceparent is clamped to 80 chars to match the hub's cap.
        "traceparent": tp[:80],
        "trace_id": trace_id,
        "service_id": None,          # hub maps port->service via policy later
        "module_id": "pcap-http",
    }
    # Preserve response correlation only for monitored destinations. The
    # response-side filter may still admit a client ephemeral sport equal to a
    # monitored port; this is harmless because parse_response_head rejects it.
    # Only emit for monitored destinations (or a parsed method).
    return ev if (dport in ports or h.get("_method")) else None


def _flush_oldest_pending(pending_tbl, out, flows=None, resp_flows=None):
    """Overflow guard: emit all events for the oldest pending key and lock it out.

    Returns True if at least one key/entry was flushed, False otherwise.
    """
    if not pending_tbl:
        return False

    oldest_key, oldest_ts = None, None
    for rk, lst in pending_tbl.items():
        if not lst:
            continue
        ts = lst[0][1]
        if oldest_ts is None or ts < oldest_ts:
            oldest_key, oldest_ts = rk, ts

    if oldest_key is None:
        pending_tbl.clear()
        pending_repair_count(pending_tbl)
        return False

    had_entries = False
    while pending_tbl.get(oldest_key):
        pending_pop(oldest_key, out, pending_tbl)
        had_entries = True

    invalidate_connection_correlation(flows, resp_flows, oldest_key)
    pending_take_all(pending_tbl, oldest_key)
    return True


def ensure_pending_capacity(pending_tbl, out, flows=None, resp_flows=None):
    """Ensure pending_tbl has room for at least one new entry."""
    global g_pending_events_total

    if pending_tbl is None:
        return True

    # Slow path / suspicious state:
    # table is authoritative before we evict anything.
    if (g_pending_events_total < 0 or
            g_pending_events_total >= MAX_PENDING_EVENTS or
            len(pending_tbl) >= MAX_PENDING_KEYS):
        pending_repair_count(pending_tbl)

    # After repair, capacity may already be fine.
    if (len(pending_tbl) < MAX_PENDING_KEYS and
            g_pending_events_total < MAX_PENDING_EVENTS):
        return True

    attempts = 0
    max_attempts = min(
        MAX_PENDING_KEYS + 1,
        max(32, len(pending_tbl) + 1)
    )

    while (len(pending_tbl) >= MAX_PENDING_KEYS or
           g_pending_events_total >= MAX_PENDING_EVENTS):

        if attempts >= max_attempts:
            pending_repair_count(pending_tbl)
            return False

        attempts += 1

        before_keys = len(pending_tbl)
        before_count = g_pending_events_total

        flushed = _flush_oldest_pending(
            pending_tbl,
            out,
            flows=flows,
            resp_flows=resp_flows
        )

        if (not flushed or
                (len(pending_tbl) >= before_keys and
                 g_pending_events_total >= before_count)):

            pending_repair_count(pending_tbl)

            if (len(pending_tbl) < MAX_PENDING_KEYS and
                    g_pending_events_total < MAX_PENDING_EVENTS):
                return True

            return False

    return True


def _emit_request(flows, key, fl, meta, out, pending_tbl, now, resp_flows=None):
    """Discard capture buffers, then emit/queue the sanitized event only."""
    global g_pending_events_total
    # meta is the request-direction tuple; used to build the response key rk.
    dst_ip, dport, src_ip, sport = meta
    # Pick whichever finished event this flow holds, then drop the flow.
    ev = fl.wsse_event if fl.awaiting_wsse else fl.event
    if fl.awaiting_wsse:
        fl.wsse_cancel(g_buffer_budget)
    clear_all_flow_buffers(fl, g_buffer_budget)
    flows.pop(key, None)
    if not ev:
        return
    # req_bytes = HTTP header bytes for this request.
    ev["req_bytes"] = fl.head_bytes
    # Without a pending table, emit immediately (no response correlation).
    if pending_tbl is None:
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return
    # rk mirrors the connection so response packets map back to this request.
    rk = (dst_ip, dport, src_ip, sport)
    if not is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                  gen=fl.generation, syn_seen=fl.syn_seen,
                                  corr_eligible=fl.corr_eligible):
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return
    # Queue the event for later enrichment. Two overflow guards follow: a
    # global key cap and a per-connection entry cap.
    ent = pending_tbl.get(rk)
    if ent is None:
        if not ensure_pending_capacity(pending_tbl, out, flows=flows, resp_flows=resp_flows):
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
            return
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)
        invalidate_connection_correlation(flows, resp_flows, rk)
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return

    if g_pending_events_total >= MAX_PENDING_EVENTS:
        if not ensure_pending_capacity(pending_tbl, out, flows=flows, resp_flows=resp_flows):
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
            return
        ent = pending_tbl.get(rk)
        if ent is None:
            ent = pending_tbl[rk] = []

    # Remember when the first request byte arrived so duration_ms is measured
    # from the request, not from when the response happened to be parsed.
    started = fl.first_byte_ts if fl.first_byte_ts > 0 else (now if now is not None else time.time())
    _req_id_seq[0] += 1
    req_id = _req_id_seq[0]
    preq = PendingRequest(ev, started, fl.generation, req_id)
    ent.append(preq)
    g_pending_events_total += 1


# Monotonic per-process request id used to match a WSSE body window back to
# the exact pending request it enriches.
_req_id_seq = [0]


def _emit_request_to_pending(ev, head_bytes, first_byte_ts, meta, out, pending_tbl, now,
                             generation=0, syn_seen=False, corr_eligible=True,
                             flows=None, resp_flows=None):
    """Queue an already-built event, returning its new request id (or 0).

    Same bounds and correlation checks as _emit_request, but the caller
    supplies the event instead of reading it off a flow, and a fresh req_id is
    returned so WSSE body capture can later find and enrich this exact entry.
    """
    global g_pending_events_total
    # meta is the request-direction 4-tuple.
    dst_ip, dport, src_ip, sport = meta
    if not ev:
        return 0
    # req_bytes = HTTP header byte count.
    ev["req_bytes"] = head_bytes
    # No correlation table: emit now and report id 0 (uncorrelated).
    if pending_tbl is None:
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return 0
    rk = (dst_ip, dport, src_ip, sport)
    if not is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                  gen=generation, syn_seen=syn_seen,
                                  corr_eligible=corr_eligible):
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return 0
    ent = pending_tbl.get(rk)
    if ent is None:
        if not ensure_pending_capacity(pending_tbl, out, flows=flows, resp_flows=resp_flows):
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
            return 0
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)
        invalidate_connection_correlation(flows, resp_flows, rk)
        if out is not None:
            if isinstance(out, list):
                out.append(ev)
            elif hasattr(out, "write"):
                out.write(json.dumps(ev) + "\n")
                if hasattr(out, "flush"):
                    out.flush()
        return 0

    if g_pending_events_total >= MAX_PENDING_EVENTS:
        if not ensure_pending_capacity(pending_tbl, out, flows=flows, resp_flows=resp_flows):
            if out is not None:
                if isinstance(out, list):
                    out.append(ev)
                elif hasattr(out, "write"):
                    out.write(json.dumps(ev) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
            return 0
        ent = pending_tbl.get(rk)
        if ent is None:
            ent = pending_tbl[rk] = []

    # Request start time for duration_ms.
    started = first_byte_ts if first_byte_ts > 0 else (now if now is not None else time.time())
    # Allocate the next request id and attach it to this event's entry.
    _req_id_seq[0] += 1
    req_id = _req_id_seq[0]
    preq = PendingRequest(ev, started, generation, req_id)
    ent.append(preq)
    g_pending_events_total += 1
    return req_id




def _try_wsse_body(flows, key, fl, payload, meta, out, pending_tbl, now):
    """Append no more than body_goal bytes and finish as soon as possible."""
    # Copy only as much body as remains within the bounded WSSE window.
    remaining = fl.wsse_goal - len(fl.wsse_buf)
    if remaining > 0 and payload:
        copy_len = min(remaining, len(payload))
        fl.wsse_buf.extend(bytearray(payload[:copy_len]))
    # Re-parse the (possibly still partial) prefix; returns None until a
    # Username is safely closed.
    username = extract_wsse_username(fl.wsse_buf)
    if username:
        fl.wsse_event["wsse_user"] = username
        fl.wsse_event["user"] = username
        fl.wsse_event["scheme"] = "wsse"
    # Done as soon as a username is found or the window is full.
    if username or len(fl.wsse_buf) >= fl.wsse_goal:
        _emit_request_to_pending(fl.wsse_event, fl.head_bytes, fl.first_byte_ts,
                                 meta, out, pending_tbl, now, generation=fl.generation,
                                 syn_seen=fl.syn_seen, corr_eligible=fl.corr_eligible,
                                 flows=flows)
        # Release the body-buffer slot (updates the global counter).
        fl.awaiting_wsse = False
        return True
    return False


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out,
                   pending_tbl=None, now=None, wsse_body_bytes=0,
                   seq=None, flags=0, is_truncated=False, resp_flows=None):
    """Reassemble and parse one client->server (request) segment.

    flows is the request-direction table keyed by `key`; meta is the
    (dst_ip, dport, src_ip, sport) view used for events. seq/flags come from the
    raw TCP header. On a complete request head an event is built and queued for
    response correlation; bodies are consumed only to keep framing in sync.
    """
    global g_truncated_frames_total
    dst_ip, dport, src_ip, sport = meta
    # Sanity-check the port pair before doing anything else.
    if not (1 <= dport <= 65535 and 1 <= sport <= 65535):
        return
    # Empty table: let the global WSSE counter re-sync (defensive).
    if not flows:
        reset_wsse_active_flows()
    if now is None:
        now = time.time()

    # SYN handling: reset flow and start sequence tracking
    # SYN (0x02): a new connection. Reset both directions and establish the
    # client's initial sequence number.
    if flags & 0x02 and seq is not None:
        fl = flows.get(key) if flows is not None else None
        # Retransmitted SYN for the same ISN: ignore (idempotent).
        if fl is not None and getattr(fl, "syn_seen", False) and getattr(fl, "client_isn", None) == seq:
            return
        rk = (dst_ip, dport, src_ip, sport)
        terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                             g_buffer_budget, request_key=key, response_key=rk, out=out, reason="client_syn")
        corr_disabled_erase(rk)
        next_gen = (fl.generation + 1) if fl else 1
        fl = get_or_create_request_flow(flows, resp_flows, key, g_flow_fifo, g_resp_flow_fifo,
                                        pending_tbl, now, budget=g_buffer_budget, out=out)
        fl.reset_for_new_connection(next_gen, now, syn_seen=True, corr_eligible=True)
        fl.has_seq = True
        fl.next_seq = (seq + 1) & 0xFFFFFFFF
        fl.client_isn = seq
        if resp_flows is not None:
            rfl = get_or_create_response_flow(flows, resp_flows, rk, g_flow_fifo, g_resp_flow_fifo,
                                              pending_tbl, now, budget=g_buffer_budget, out=out)
            rfl.reset_for_new_connection(next_gen, now, syn_seen=True, corr_eligible=True)
        return

    # Non-SYN segment: fetch or lazily create the request-direction flow.
    fl = get_or_create_request_flow(flows, resp_flows, key, g_flow_fifo, g_resp_flow_fifo,
                                    pending_tbl, now, budget=g_buffer_budget, out=out)
    fl.touched = now

    # Check keep-alive request transition while waiting for body in direct test feed mode
    # Direct test feed (no seq): a new method line means the previous
    # request's body is over, so stop waiting for WSSE and flush it.
    if seq is None and fl.awaiting_wsse and payload and is_method_or_prefix(payload):
        if pending_tbl is None and fl.wsse_event is not None:
            if out is not None:
                if isinstance(out, list):
                    out.append(fl.wsse_event)
                elif hasattr(out, "write"):
                    out.write(json.dumps(fl.wsse_event) + "\n")
                    if hasattr(out, "flush"):
                        out.flush()
        fl.wsse_cancel(g_buffer_budget)
        fl.state = HTTP_STATE_HEADER
        clear_main_buffer(fl, g_buffer_budget)

    # Payload length for this segment.
    plen = len(payload) if payload else 0

    # Desynced flow: only handle teardown.
    if getattr(fl, "state", None) == HTTP_STATE_UNSYNCED:
        clear_all_flow_buffers(fl, g_buffer_budget)
        if flags & 0x04:
            terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                 g_buffer_budget, request_key=key, out=out, reason="rst_unsynced")
        elif flags & 0x01:
            if seq is not None:
                fl.fin_seen = True
                fl.fin_seq = (seq + plen) & 0xFFFFFFFF
            if not fl.has_seq or seq_diff(fl.fin_seq, fl.next_seq) <= 0:
                if not fl.buf and not fl.ooo and not fl.awaiting_wsse:
                    terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                         g_buffer_budget, request_key=key, out=out, reason="fin_unsynced")
        return

    # Reassemble this segment.
    if plen > 0:
        # Truncated capture: framing unreliable, break correlation.
        if is_truncated:
            g_truncated_frames_total += 1
            quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="truncated_frame")
            return

        # Test-feed path: no sequence, just append.
        if seq is None:
            append_flow_buf(fl, payload, g_buffer_budget, flows, resp_flows, pending_tbl, request_key=key, out=out)
        else:
            # First sequenced segment: resync to a request start if possible.
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
                # Accept it if it already looks like a method (or prefix).
                elif is_method_or_prefix(payload):
                    fl.has_seq = True
                    fl.next_seq = seq
                    fl.is_broken = False
                else:
                    # Otherwise buffer out-of-order.
                    if not _ooo_insert(fl, seq, payload, is_truncated, budget=g_buffer_budget):
                        quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="ooo_insert_failed")
                    return

            # In-order / overlap / gap dispatch, identical to the response path.
            diff = seq_diff(seq, fl.next_seq)
            if diff == 0:
                append_flow_buf(fl, payload, g_buffer_budget, flows, resp_flows, pending_tbl, request_key=key, out=out)
                fl.next_seq = (fl.next_seq + plen) & 0xFFFFFFFF
                _drain_ooo(fl, budget=g_buffer_budget)
            elif diff < 0:
                overlap = -diff
                if overlap < plen and not is_truncated:
                    append_flow_buf(fl, payload[overlap:], g_buffer_budget, flows, resp_flows, pending_tbl, request_key=key, out=out)
                    fl.next_seq = (fl.next_seq + plen - overlap) & 0xFFFFFFFF
                    _drain_ooo(fl, budget=g_buffer_budget)
            else:
                if not _ooo_insert(fl, seq, payload, is_truncated, budget=g_buffer_budget):
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="ooo_insert_failed")

    # HTTP framing state machine
    # Close-delimited body detection (mirrors handle_response).
    if fl.fin_seen and fl.has_seq:
        fdiff = seq_diff(fl.fin_seq, fl.next_seq)
        if fdiff <= 0:
            if fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo:
                fl.state = HTTP_STATE_CLOSE_BODY

    # Drain complete requests out of the reassembled buffer.
    while len(fl.buf) > 0 and not fl.is_broken:
        # CLOSE_BODY for requests: discard until the connection ends.
        if fl.state == HTTP_STATE_CLOSE_BODY:
            clear_main_buffer(fl, g_buffer_budget)
            break

        # --- HEADER: find and parse one request head ---
        if fl.state == HTTP_STATE_HEADER:
            # Timestamp the first byte of this request (duration_ms origin).
            if not fl.first_byte_ts:
                fl.first_byte_ts = now

            # A request head ends at CRLFCRLF.
            idx = fl.buf.find(b"\r\n\r\n")
            if idx < 0:
                # A head that never ends is hostile/broken: drop and break.
                if len(fl.buf) > MAX_HDRS:
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_header_too_large")
                break
            # Fast path: the buffer already starts with a method.
            p0 = fl.buf[:8]
            if (p0.startswith(b"GET ") or p0.startswith(b"POST ") or
                p0.startswith(b"PUT ") or p0.startswith(b"DELETE ") or
                p0.startswith(b"HEAD ") or p0.startswith(b"OPTIONS ") or
                p0.startswith(b"PATCH ")):
                start = 0
            # Otherwise resync to the earliest method before the head end.
            else:
                start = find_http_start(fl.buf)
            # No valid request line: skip this head and continue.
            if start < 0 or start > idx:
                consume_flow_buf(fl, idx + 4, g_buffer_budget)
                continue
            # Trim leading noise before the request line.
            if start > 0:
                consume_flow_buf(fl, start, g_buffer_budget)
                idx -= start

            # Parse "METHOD path HTTP/1.x" then the header block.
            head = bytes(fl.buf[:idx])
            lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
            first = lines[0].strip().split()
            # Require a known method and an HTTP/1.x version token.
            if len(first) < 3 or first[0] not in METHODS_BYTES or first[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                consume_flow_buf(fl, idx + 4, g_buffer_budget)
                continue
            # Header dict. Keys are lowercased; only a whitelist of headers is
            # retained (authorization, content-*, traceparent, host, user-agent,
            # x-forwarded-for) so unrelated headers are never copied.
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
                # Cheap first-byte filter: only a/c/h/t/u/x headers matter.
                if c0 not in (b"a", b"A", b"c", b"C", b"h", b"H", b"t", b"T", b"u", b"U", b"x", b"X"):
                    continue
                if b":" not in ln:
                    continue
                kn, kv = ln.split(b":", 1)
                kn_low = kn.strip().lower()
                # Content-Length: validate and detect duplicates/conflicts.
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
                # Transfer-Encoding: accumulate and validate later.
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
                # Content-Type tells us whether a SOAP body is worth scanning.
                elif kn_low == b"content-type":
                    hdrs["content-type"] = kv.strip().decode("ascii", "replace")[:180]
                # Authorization: username attribution (Basic) lives here.
                elif kn_low == b"authorization":
                    hdrs["authorization"] = kv.strip().decode("ascii", "replace")[:180]
                # W3C trace context propagated by the caller.
                elif kn_low == b"traceparent":
                    hdrs["traceparent"] = kv.strip().decode("ascii", "replace")[:180]
                # Host / User-Agent / X-Forwarded-For: context fields only.
                elif kn_low == b"host":
                    hdrs["host"] = kv.strip().decode("utf-8", "replace")[:180]
                elif kn_low == b"user-agent":
                    hdrs["user-agent"] = kv.strip().decode("utf-8", "replace")[:180]
                elif kn_low == b"x-forwarded-for":
                    hdrs["x-forwarded-for"] = kv.strip().decode("utf-8", "replace")[:180]

            # Build the event now (headers are complete) and consume the head.
            fl.hdrs = hdrs
            fl.event = finish_event(fl, key, dst_ip, dport, src_ip, sport, ports, node_host)
            fl.head_bytes = idx + 4
            consume_flow_buf(fl, idx + 4, g_buffer_budget)

            # Non-monitored destination: nothing to emit; keep framing.
            if not fl.event:
                continue

            # Determine the request body framing.
            try:
                content_length = int(hdrs.get("content-length", "0"))
            except (ValueError, TypeError):
                content_length = 0

            # Absurd body framing sanity check.
            if content_length > MAX_HTTP_BODY_FRAMING:
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="absurd_body_framing")
                break

            # Chunked framing requires a valid final "chunked" coding.
            has_te = has_transfer_encoding
            is_chunked = False
            if has_te:
                if not invalid_transfer_encoding and transfer_encoding_final_chunked(te_raw):
                    is_chunked = True

            # Ambiguous/invalid framing: reset the flow and stop correlating
            # this connection rather than risk mixing up messages.
            if (has_conflict_cl or invalid_transfer_encoding or
                (has_te and not is_chunked) or
                (has_te and "content-length" in hdrs)):
                quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="ambiguous_framing")
                break

            # WSSE body capture is opt-in and requires: the feature enabled, a
            # SOAP/XML content type, a positive Content-Length, no chunked
            # encoding, and global headroom under MAX_WSSE_BODY_FLOWS.
            wsse_eligible = (wsse_body_bytes > 0 and
                             is_soap_content_type(hdrs.get("content-type")) and
                             content_length > 0 and
                             not is_chunked and
                             g_wsse_active_flows < MAX_WSSE_BODY_FLOWS)

            # Buffer up to min(content_length, wsse_body_bytes) bytes of the
            # SOAP prefix; queue the header-only event first so it can be
            # enriched in place once the Username is seen.
            if wsse_eligible:
                fl.awaiting_wsse = True
                fl.wsse_event = fl.event
                fl.wsse_buf = bytearray()
                fl.wsse_goal = min(content_length, wsse_body_bytes, MAX_WSSE_BODY_BYTES)
                fl.wsse_last_parsed_len = 0
                # Only queued (correlatable) events can be enriched later.
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
            # Not WSSE-eligible: emit the header-only event directly.
            else:
                fl.awaiting_wsse = False
                _emit_request_to_pending(fl.event, fl.head_bytes, fl.first_byte_ts, meta, out, pending_tbl, now,
                                         generation=fl.generation, syn_seen=fl.syn_seen, corr_eligible=fl.corr_eligible,
                                         flows=flows, resp_flows=resp_flows)
            # The event has been handed off; drop the flow's reference.
            fl.event = None

            # Continue into the body so the next request on a keep-alive
            # connection can be found.
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

        # --- BODY: consume Content-Length bytes; optionally capture a WSSE
        # prefix and enrich the queued event when a username appears. ---
        elif fl.state == HTTP_STATE_BODY:
            if not fl.buf:
                break
            to_consume = min(len(fl.buf), fl.body_remaining)
            # Copy a bounded slice of the body into the WSSE buffer.
            if fl.awaiting_wsse:
                wsse_need = fl.wsse_goal - len(fl.wsse_buf)
                if wsse_need > 0:
                    copy_len = min(to_consume, wsse_need)
                    fl.wsse_buf.extend(fl.buf[:copy_len])
                # Parse when the window is full, the body is ending, or another
                # 512 bytes accumulated (so a username is found promptly).
                buf_len = len(fl.wsse_buf)
                should_parse = (buf_len >= fl.wsse_goal or
                                fl.body_remaining <= to_consume or
                                buf_len >= fl.wsse_last_parsed_len + 512)
                # If a username was found, patch it into the queued event by
                # matching the stored request id.
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
                                if out is not None:
                                    if isinstance(out, list):
                                        out.append(fl.wsse_event)
                                    elif hasattr(out, "write"):
                                        out.write(json.dumps(fl.wsse_event) + "\n")
                                        if hasattr(out, "flush"):
                                            out.flush()
                        fl.wsse_cancel(g_buffer_budget)

            # Consume the body bytes and advance framing.
            consume_flow_buf(fl, to_consume, g_buffer_budget)
            fl.body_remaining -= to_consume
            # Body complete: release any WSSE slot and go back to HEADER.
            if fl.body_remaining == 0:
                if fl.awaiting_wsse:
                    if pending_tbl is None and fl.wsse_event is not None:
                        if out is not None:
                            if isinstance(out, list):
                                out.append(fl.wsse_event)
                            elif hasattr(out, "write"):
                                out.write(json.dumps(fl.wsse_event) + "\n")
                                if hasattr(out, "flush"):
                                    out.flush()
                    fl.wsse_cancel(g_buffer_budget)
                fl.state = HTTP_STATE_HEADER
                fl.first_byte_ts = now if fl.buf else 0.0
            continue

        # --- CHUNK: walk chunked framing for requests ---
        elif fl.state == HTTP_STATE_CHUNK:
            if not fl.buf:
                break
            # Trailer after the final chunk; ends at CRLF or CRLFCRLF.
            if fl.chunk_reading_trailer:
                if len(fl.buf) >= 2 and fl.buf[:2] == b"\r\n":
                    consume_flow_buf(fl, 2, g_buffer_budget)
                    fl.chunk_reading_trailer = False
                    fl.state = HTTP_STATE_HEADER
                    fl.first_byte_ts = now if fl.buf else 0.0
                    continue
                tr_end = fl.buf.find(b"\r\n\r\n")
                if tr_end != -1:
                    consume_flow_buf(fl, tr_end + 4, g_buffer_budget)
                    fl.chunk_reading_trailer = False
                    fl.state = HTTP_STATE_HEADER
                    fl.first_byte_ts = now if fl.buf else 0.0
                    continue
                if len(fl.buf) > MAX_HDRS:
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_chunk_trailer_too_large")
                break
            # Chunk-size line: hex length plus optional extensions.
            if fl.chunk_reading_len:
                crlf = fl.buf.find(b"\r\n")
                if crlf < 0:
                    if len(fl.buf) > 64:
                        quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_chunk_line_too_large")
                    break
                line = bytes(fl.buf[:crlf]).strip()
                semi = line.find(b";")
                hex_str = line[:semi].strip() if semi != -1 else line
                # Reject absurdly long size fields before int().
                if len(hex_str) > 16:
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_chunk_hex_too_long")
                    break
                try:
                    chunk_len = int(hex_str, 16)
                    if chunk_len < 0 or chunk_len > 0x7FFFFFFF or chunk_len > 16777216:
                        quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_absurd_chunk_len")
                        break
                except ValueError:
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_invalid_chunk_hex")
                    break
                consume_flow_buf(fl, crlf + 2, g_buffer_budget)
                if chunk_len == 0:
                    fl.chunk_reading_trailer = True
                    fl.chunk_reading_len = False
                    continue
                else:
                    fl.chunk_payload_remaining = chunk_len
                    fl.chunk_reading_len = False
                    fl.chunk_reading_crlf = False
            # Skip the CRLF after each chunk's payload.
            elif fl.chunk_reading_crlf:
                if len(fl.buf) < 2:
                    break
                if fl.buf[:2] != b"\r\n":
                    quarantine_connection(flows, resp_flows, pending_tbl, request_key=key, out=out, reason="req_chunk_missing_crlf")
                    break
                consume_flow_buf(fl, 2, g_buffer_budget)
                fl.chunk_reading_crlf = False
                fl.chunk_reading_len = True
            # Discard chunk payload bytes.
            else:
                to_consume = min(len(fl.buf), fl.chunk_payload_remaining)
                consume_flow_buf(fl, to_consume, g_buffer_budget)
                fl.chunk_payload_remaining -= to_consume
                if fl.chunk_payload_remaining == 0:
                    fl.chunk_reading_crlf = True
            continue

    # Post-loop FIN handling (as in handle_response).
    if fl.fin_seen and fl.has_seq:
        fdiff = seq_diff(fl.fin_seq, fl.next_seq)
        if fdiff <= 0:
            if fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo:
                fl.state = HTTP_STATE_CLOSE_BODY

    # RST -> reap. FIN -> reap when drained. For the seq-less test feed, reap
    # an empty header-state flow at end of message.
    if flags & 0x04:
        terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                             g_buffer_budget, request_key=key, out=out, reason="rst")
    elif flags & 0x01:
        if seq is not None:
            fl.fin_seen = True
            fl.fin_seq = (seq + plen) & 0xFFFFFFFF
        if not fl.has_seq or seq_diff(fl.fin_seq, fl.next_seq) <= 0:
            if fl.state in (HTTP_STATE_HEADER, HTTP_STATE_CLOSE_BODY) and not fl.buf and not fl.ooo and not fl.awaiting_wsse:
                terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                     g_buffer_budget, request_key=key, out=out, reason="fin")
    elif seq is None and fl.state == HTTP_STATE_HEADER and not fl.buf and not fl.ooo and not fl.awaiting_wsse:
        terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                             g_buffer_budget, request_key=key, out=out, reason="seqless_drain")


def sweep_idle(flows, now, out=None, pending_tbl=None, resp_flows=None):
    """Evict flows idle longer than FLOW_TTL seconds (both directions).

    Any requests still pending for an evicted connection are emitted first, so
    a response that never arrives does not silently discard the request. The
    connection's correlation is invalidated so late packets cannot mismatch.
    """
    if flows is not None:
        stale = [k for k, fl in flows.items() if now - fl.touched > FLOW_TTL]
        for k in stale:
            terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                 g_buffer_budget, request_key=k, out=out, reason="idle_sweep")
    if resp_flows is not None:
        rstale = [k for k, rfl in resp_flows.items() if now - rfl.touched > FLOW_TTL]
        for k in rstale:
            terminate_connection(flows, resp_flows, pending_tbl, g_flow_fifo, g_resp_flow_fifo,
                                 g_buffer_budget, response_key=k, out=out, reason="idle_sweep")


def drain_incomplete_wsse(flows, out, pending_tbl, now=None):
    """Fall back to clearing awaiting_wsse without re-emitting (already in pending)."""
    # Called at shutdown: release WSSE body slots; events are already queued in
    # `pending` and will be flushed by drain_pending.
    if flows is not None:
        for key in list(flows.keys()):
            fl = flows.get(key)
            if fl is None:
                continue
            if fl.awaiting_wsse:
                fl.wsse_cancel(g_buffer_budget)
            clear_all_flow_buffers(fl, g_buffer_budget)
            flows.pop(key, None)


def process_packet(pkt, ports, node_host, flows, resp_flows, pending_tbl, out, now=None, wsse_body_bytes=0):
    """Parse one raw Ethernet frame and dispatch it to the flow machinery.

    Decodes Ethernet/VLAN + IPv4 + TCP, extracts the payload, then routes it to
    handle_payload (request direction) or handle_response (response direction)
    based on which ports are monitored. Returns True if the frame was handled.
    Every struct offset below is documented against the wire layout.
    """
    # n = current end-of-frame index (also used to trim trailing padding).
    n = len(pkt)
    # Cheap early reject: anything under 34 bytes cannot hold Ethernet + IP +
    # TCP headers.
    if n < 34:
        return False
    if now is None:
        now = time.time()
    # off = start of the IP header: 14 = Ethernet header (dst MAC 6 + src MAC
    # 6 + ethertype 2). It becomes 18 when a 4-byte VLAN tag is present.
    off = 14
    # Ethertype is the last u16 of the Ethernet header (offset 12).
    etype = _STRUCT_H.unpack_from(pkt, 12)[0]
    # 802.1Q: skip the 4-byte VLAN tag (TPID 2 + TCI 2); the real ethertype is
    # then at offset 16 and the IP header starts at 18.
    if etype == ETH_P_VLAN:
        if n < 38:
            return False
        etype = _STRUCT_H.unpack_from(pkt, 16)[0]
        off = 18
    # Anything that is not IPv4 (ARP, IPv6, ...) is of no interest.
    elif etype != ETH_P_IP:
        return False

    # IP header byte 0: version (high nibble) and IHL (low nibble).
    ip0 = _STRUCT_B.unpack_from(pkt, off)[0]
    # Require IPv4 and protocol 6 (TCP) at IP byte 9.
    if (ip0 >> 4) != 4 or _STRUCT_B.unpack_from(pkt, off + 9)[0] != 6:
        return False
    # IHL counts 32-bit words, so the header length in bytes is IHL * 4.
    # Reject a too-short header and frames lacking the full 20-byte TCP header.
    ihl = (ip0 & 0x0F) * 4
    if ihl < 20 or n < off + ihl + 20:
        return False

    # Flags + Fragment-Offset is the u16 at IP offset 6. Any non-zero fragment
    # offset or MF bit means this is a fragment: skip it, since only the first
    # fragment carries the TCP header.
    frag = _STRUCT_H.unpack_from(pkt, off + 6)[0]
    if frag & 0x3FFF:
        return False

    # The TCP header begins immediately after the IP header.
    tcp_off = off + ihl
    # TCP source port (bytes 0-1) and destination port (bytes 2-3), one read.
    sport, dport = _STRUCT_HH.unpack_from(pkt, tcp_off)
    # At least one of the two ports must be monitored for this frame to matter.
    sport_mon = sport in ports
    dport_mon = dport in ports
    if not (sport_mon or dport_mon):
        return False

    # IP Total Length is the u16 at IP offset 2 (whole IP datagram, in bytes).
    ip_total_len = _STRUCT_H.unpack_from(pkt, off + 2)[0]
    if ip_total_len < ihl + 20:
        return False
    # Reconcile the frame length with IP Total Length. Fewer captured bytes
    # than declared means the capture dropped part of the datagram; extra bytes
    # are Ethernet padding and must be trimmed so payload parsing is exact.
    is_truncated = False
    if n - off < ip_total_len:
        is_truncated = True
    elif n - off > ip_total_len:
        n = off + ip_total_len

    # TCP byte 12: data offset (high nibble, in 32-bit words) + reserved bits.
    doff_byte = _STRUCT_B.unpack_from(pkt, tcp_off + 12)[0]
    # Convert the data-offset nibble to bytes; must be >= 20 and the frame must
    # contain that many bytes.
    doff = (doff_byte >> 4) * 4
    if doff < 20 or n < tcp_off + doff:
        return False

    # IPv4 source address is IP bytes 12-15; destination is bytes 16-19.
    src_ip = _fast_inet_ntoa(pkt[off + 12:off + 16])
    dst_ip = _fast_inet_ntoa(pkt[off + 16:off + 20])
    # TCP sequence number is a u32 at TCP offset 4.
    seq = _STRUCT_I.unpack_from(pkt, tcp_off + 4)[0]
    # TCP flags byte is at TCP offset 13 (FIN=0x01, SYN=0x02, RST=0x04,
    # PSH=0x08, ACK=0x10).
    flags = _STRUCT_B.unpack_from(pkt, tcp_off + 13)[0]
    # Payload begins after the TCP header.
    pay_start = tcp_off + doff
    # Slice out the payload (empty for pure ACK/FIN/SYN).
    payload = pkt[pay_start:n] if n > pay_start else b""

    # Response direction: Server -> Client
    # Only the source port is monitored -> a response from a monitored service
    # back to a client.
    if sport_mon and not dport_mon:
        # Response key: (server_ip, server_port, client_ip, client_port).
        rk = (src_ip, sport, dst_ip, dport)
        handle_response(resp_flows, rk, payload, now, out, pending_tbl,
                        seq=seq, flags=flags, is_truncated=is_truncated, flows=flows)
        return True

    # Both ends are monitored ports (e.g. service-to-service traffic): decide
    # which side is the responder using handshake flags, existing flow state,
    # or an HTTP/ prefix in the payload.
    # Both ports monitored: latch roles via handshake, existing flow, or HTTP prefix
    elif sport_mon and dport_mon:
        rk = (src_ip, sport, dst_ip, dport)
        req_k = (src_ip, sport, dst_ip, dport)
        is_resp = False
        # Already known as a response flow.
        if resp_flows is not None and rk in resp_flows:
            is_resp = True
        # The reverse tuple exists in the request table -> this direction is
        # the response.
        elif flows is not None and (dst_ip, dport, src_ip, sport) in flows:
            is_resp = True
        # This tuple is already a known request flow.
        elif flows is not None and req_k in flows:
            is_resp = False
        # SYN+ACK -> server side.
        elif (flags & 0x12) == 0x12:
            is_resp = True
        # Bare SYN -> client side.
        elif flags & 0x02:
            is_resp = False
        # Payload that starts with "HTTP/" is a response.
        elif payload and payload.startswith(b"HTTP/"):
            is_resp = True
        else:
            is_resp = False

        # Dispatch according to the latched role.
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
    # Only the destination port is monitored -> client request.
    else:
        # Request key: (client_ip, client_port, server_ip, server_port).
        key = (src_ip, sport, dst_ip, dport)
        meta = (dst_ip, dport, src_ip, sport)
        handle_payload(flows, key, None, payload, meta, ports, node_host, out,
                       pending_tbl, now, wsse_body_bytes,
                       seq=seq, flags=flags, is_truncated=is_truncated,
                       resp_flows=resp_flows)

        return True

    return False


def sweep_pending(pending_tbl, now, out, flows=None, resp_flows=None):
    """TTL flush: emit requests whose responses never showed up."""
    # Periodic self-healing invariant check
    pending_repair_count(pending_tbl)

    # Iterate over a snapshot of the keys; entries are mutated below.
    for rk in list(pending_tbl.keys()):
        lst = pending_tbl.get(rk)
        if not lst:
            continue
        i = 0
        while i < len(lst):
            item = lst[i]
            is_tomb = item[2] if len(item) > 2 else False
            tomb_ts = item[3] if len(item) > 3 else 0.0
            # Tombstone entries are requests already emitted whose response
            # might still arrive. If one lingers > 10s the ordering is
            # ambiguous, so flush the whole key and disable correlation.
            if is_tomb:
                if now - tomb_ts > 10.0:
                    # Tombstone expired un-consumed: ordering is now ambiguous.
                    # Flush all remaining entries immediately and persistently
                    # disable response correlation for this connection until SYN.
                    rem_entries = pending_take_all(pending_tbl, rk)
                    for rem_item in rem_entries:
                        rem_tomb = rem_item[2] if len(rem_item) > 2 else False
                        if not rem_tomb:
                            out.append(rem_item[0])
                    invalidate_connection_correlation(flows, resp_flows, rk)
                    break
                else:
                    i += 1
            # Live request whose response never arrived within PENDING_TTL:
            # emit it now and convert it to a tombstone.
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
        if not pending_tbl.get(rk):
            pending_tbl.pop(rk, None)


def drain_pending(pending_tbl, out):
    """Emit every captured request before capture shutdown.

    Responses are optional enrichment. A stop/restart must not discard a
    request merely because its response was filtered, split, or still in
    flight when the process received SIGTERM.
    """
    # Emit every non-tombstone request, ignoring response correlation.
    for rk in list(pending_tbl.keys()):
        lst = pending_take_all(pending_tbl, rk)
        if lst:
            for item in lst:
                is_tomb = item[2] if len(item) > 2 else False
                if not is_tomb:
                    out.append(item[0])
    corr_disabled_clear()
    pending_repair_count(pending_tbl)




def maintenance_due(now, last_sweep):
    """True if at least SWEEP_INTERVAL seconds have passed since last_sweep."""
    return now - last_sweep >= SWEEP_INTERVAL


def enforce_limit(flows, now, out=None, pending_tbl=None, resp_flows=None):
    """Cap flow-table size by sweeping idle then enforcing flow capacity."""
    sweep_idle(flows, now, out=out, pending_tbl=pending_tbl, resp_flows=resp_flows)
    ensure_flow_capacity(flows, resp_flows, g_flow_fifo, g_resp_flow_fifo, pending_tbl,
                         reservation=0, out=out, budget=g_buffer_budget, now=now)


def _control_config():
    """Read optional control settings without exposing the bearer token."""
    # Endpoint/env fallbacks; the token may come from a file (preferred) or the
    # environment.
    endpoint = os.environ.get("NT_CONTROL_ENDPOINT") or os.environ.get("NT_ENDPOINT")
    token_file = os.environ.get("NT_CONTROL_TOKEN_FILE", "")
    token = os.environ.get("NT_CONTROL_TOKEN", "")
    # Read the control token from a file when provided; treat IO errors as
    # "no token" rather than crashing capture.
    if token_file:
        try:
            f = open(token_file, "r")
            try:
                token = f.read().strip()
            finally:
                f.close()
        except IOError:
            token = ""
    # Node identity defaults to the short hostname; run_dir holds control
    # state files.
    node = os.environ.get("NT_NODE_NAME") or socket.gethostname().split(".")[0]
    run_dir = os.environ.get("NT_CONTROL_RUN", "/var/lib/networktracing")
    # Control poll interval, clamped to 5..300 seconds.
    try:
        interval = max(5, min(int(os.environ.get("NT_CONTROL_SEC", "30")), 300))
    except ValueError:
        interval = 30
    return endpoint, token, node, run_dir, interval


def _run_control_tick(ports, iface, run_dir, client):
    """Apply one remote-control poll and return the resulting capture state.

    Polls the control server, applies desired ports/interface, answers queued
    tasks (health/restart/reload/set_ports/stop), persists the desired state and
    sends a heartbeat. Returns (ports, iface, control_action, status_text)
    where control_action is None, "restart" or "stop".
    """
    # Fetch the latest desired state; a failed poll leaves capture unchanged.
    reply = client.poll()
    if not reply:
        return ports, iface, None, "poll failed"
    # Desired state (ports/iface/generation) and the state we will persist.
    desired = reply.get("desired") or {}
    state = dict(desired)
    generation = desired.get("generation", 0)
    control_action = None
    stop_requested = False
    # A changed monitored-port set requires a restart of capture.
    if desired.get("ports"):
        new_ports = set(desired["ports"])
        if new_ports != ports:
            ports = new_ports
            control_action = "restart"
    # A changed interface likewise.
    if desired.get("iface"):
        new_iface = desired["iface"]
        if new_iface != iface:
            iface = new_iface
            control_action = "restart"
    # Service queued operator tasks; unknown actions fail closed.
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
    # A stop task overrides any pending restart.
    if stop_requested:
        control_action = "stop"
    applied = ("stop requested" if control_action == "stop" else
               "restart required" if control_action == "restart" else
               "poll ok")
    # Persist the desired state atomically and report liveness to the server.
    nt_control.write_state(os.path.join(run_dir, "remote-desired.json"),
                           state, applied)
    client.heartbeat(generation, applied)
    return ports, iface, control_action, applied


def _restart_args(script, iface, ports, verbose, workers, wsse_body_bytes=0):
    """Build a fresh argv for an in-place re-exec after a control update."""
    # Preserve unbuffered JSONL delivery; the installer starts Python with -u.
    # Rebuild argv for os.execv: -u keeps stdout unbuffered so JSONL is emitted
    # immediately even when not attached to a terminal.
    args = [sys.executable, "-u", os.path.abspath(script)]
    if iface:
        args.extend(["-i", iface])
    # Re-serialize the current port set and the remaining options.
    args.extend(["-p", ",".join([str(p) for p in sorted(ports)])])
    args.extend(["-j", "1"])
    if wsse_body_bytes:
        args.extend(["--wsse-body-bytes", str(wsse_body_bytes)])
    if verbose:
        args.append("-v")
    return args


def main():
    """Sniffer entry point.

    Parse args, open and bind the AF_PACKET socket, attach the mandatory
    kernel BPF filter, drop privileges, then loop receiving and dispatching
    packets until SIGTERM/SIGINT, flushing pending events at shutdown.
    """
    # Parse CLI/env configuration.
    iface, ports, verbose, workers, wsse_body_bytes = parse_args(sys.argv[1:])
    # Short hostname is stamped into every event.
    node_host = socket.gethostname().split(".")[0]
    control_client = None
    # Set up optional remote control if both the client module and credentials
    # are present.
    endpoint, token, control_node, control_run, control_interval = _control_config()
    # Enable remote control only when fully configured.
    if nt_control is not None and endpoint and token:
        try:
            control_client = nt_control.ControlClient(endpoint, token, control_node)
            if not os.path.isdir(control_run):
                os.makedirs(control_run)
            log("remote control enabled")
        except Exception as e:
            log("WARN: remote control disabled (%s)" % nt_control.safe_message(e))

    # Self-impose a 256 MiB address-space cap (fail-closed).
    try:
        import resource
        target = 256 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_soft = target if soft == resource.RLIM_INFINITY or soft > target else soft
        new_hard = target if hard == resource.RLIM_INFINITY or hard > target else hard
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
        v_soft, v_hard = resource.getrlimit(resource.RLIMIT_AS)
        if v_soft > target:
            raise RuntimeError("Enforced RLIMIT_AS soft limit %d exceeds target %d" % (v_soft, target))
    except Exception as e:
        sys.stderr.write("nt-sniff: FATAL: cannot enforce address-space limit: %s\n" % e)
        sys.stderr.flush()
        sys.exit(70)

    # Open the AF_PACKET raw socket. ETH_P_ALL (htons) is required to receive
    # both ingress requests and egress responses.
    try:
        # protocol MUST be htons(ETH_P_ALL) to receive both INGRESS (req) and
        # EGRESS (resp) packets on Linux kernel packet sockets.
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
    # AF_PACKET is Linux-only.
    except AttributeError:
        raise SystemExit("AF_PACKET unavailable on this platform")
    # Opening the raw socket needs CAP_NET_RAW / root.
    except socket.error as e:
        raise SystemExit("cannot open AF_PACKET socket (%s) — need "
                         "CAP_NET_RAW / root" % e)
    # Initial 1s timeout (re-applied below) so idle periods let sweeps run.
    s.settimeout(1.0)
    # Mandatory kernel BPF filter: refuse to run unfiltered.
    if not apply_perf_opts(s, ports):
        s.close()
        raise SystemExit("kernel BPF safety filter unavailable; refusing unfiltered capture")
    # Bind to the chosen interface ("" = all interfaces) and ETH_P_ALL.
    try:
        s.bind((iface or "", ETH_P_ALL))
    except socket.error as e:
        s.close()
        raise SystemExit("cannot bind AF_PACKET to %s (%s)" %
                         (iface or "<all>", e))
    # Permanently drop root/CAP_NET_RAW now that the socket exists.
    if not drop_capture_capabilities():
        s.close()
        raise SystemExit("cannot drop CAP_NET_RAW after socket setup; refusing unsafe capture")
    if not verify_dropped_capabilities():
        s.close()
        sys.stderr.write("nt-sniff: FATAL: capability verification failed; CAP_NET_RAW still effective\n")
        sys.stderr.flush()
        sys.exit(70)

    # precompiled struct readers — unpack_from reads straight out of the
    # packet buffer (no slice copies) and yields ints under py2 AND py3
    # Pre-bound unpack_from helpers used by the packet loop hot path.
    u16 = struct.Struct("!H").unpack_from
    uh = struct.Struct("!HH").unpack_from   # sport,dport in one read
    ub = struct.Struct("!BB").unpack_from
    ntoa = socket.inet_ntoa

    # Request-direction and response-direction flow tables.
    flows = {}
    resp_flows = {}
    # List-wrapped flag: the SIGTERM/SIGINT handler mutates it.
    running = [True]
    # Capture-stats cadence and the counters behind the stats lines.
    stats_interval = stats_interval_seconds()
    stats_state = {"packets_total": 0, "packet_bytes_total": 0,
                   "events_emitted_total": 0, "kernel_drops_total": 0,
                   "last_packets": 0, "last_packet_bytes": 0,
                   "last_events": 0, "last_at": time.time()}

    # Serialize a batch of events to stdout as JSONL (one object per line).
    def write_events(items):
        """Write each event as one JSON line and flush; update the total."""
        if not items:
            return
        w = sys.stdout.write
        try:
            for item in items:
                w(json.dumps(item) + "\n")
            sys.stdout.flush()
        except (IOError, OSError) as e:
            if getattr(e, "errno", None) in (errno.EPIPE, errno.ESHUTDOWN):
                sys.stderr.write("nt-sniff: downstream shipper pipe closed; exiting\n")
                sys.stderr.flush()
                sys.exit(74)
            raise
        stats_state["events_emitted_total"] += len(items)

    # Emit a "_nt_internal: capture_stats_v1" line describing capture health.
    def emit_capture_stats(force=False, out=sys.stdout):
        """Emit coalesced capture statistics (throttled unless force=True)."""
        now = time.time()
        elapsed = now - stats_state["last_at"]
        if not force and elapsed < stats_interval:
            return
        # Ask the kernel how many frames it dropped since the last read; this
        # read also RESETS the per-socket counter, so the value is a delta.
        dropped_delta = 0
        try:
            # PACKET_STATISTICS returns two u32: packets and drops.
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
        # Surface current memory/flow pressure: WSSE body flows and pending
        # requests are the two bounded resources operators care about.
        waiting_wsse = g_wsse_active_flows
        pending_count = g_pending_events_total
        drop_pct = 100.0 * dropped_delta / max(1, packets_delta)
        # The capture dict is the machine-readable stats payload.
        capture = {
            "packets_total": stats_state["packets_total"],
            "packets_delta": packets_delta,
            "packet_bytes_total": stats_state["packet_bytes_total"],
            "packet_bytes_delta": bytes_delta,
            "kernel_drops_total": stats_state["kernel_drops_total"],
            "kernel_drops_delta": dropped_delta,
            "kernel_drop_percent": round(drop_pct, 4),
            "invalid_frames_total": g_invalid_frames_total,
            "truncated_frames_total": g_truncated_frames_total,
            "correlation_disabled_total": g_correlation_disabled_total,
            "parser_resync_total": g_parser_resync_total,
            "buffer_bytes_total": g_buffer_budget.total,
            "so_rcvbuf": g_effective_so_rcvbuf,
            "events_emitted_total": stats_state["events_emitted_total"],
            "events_emitted_delta": events_delta,
            "flows_active": len(flows) + len(resp_flows),
            "pending_requests": pending_count,
            "wsse_body_flows_active": waiting_wsse}
        # Emit as an internal JSONL record; nt-ship.py recognizes the marker.
        if hasattr(out, "write"):
            out.write(json.dumps({"_nt_internal": "capture_stats_v1",
                                  "capture": capture},
                                 separators=(",", ":")) + "\n")
            out.flush()
        stats_state["last_packets"] = stats_state["packets_total"]
        stats_state["last_packet_bytes"] = stats_state["packet_bytes_total"]
        stats_state["last_events"] = stats_state["events_emitted_total"]
        stats_state["last_at"] = now

    # Signal handler: request a clean shutdown (flushing happens after loop).
    def stop(signum, frame):
        """SIGTERM/SIGINT handler; sets the running flag so the loop exits."""
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

    # Optional packet-rate debug logging (NT_SNIFF_DEBUG=1).
    dbg = os.environ.get("NT_SNIFF_DEBUG") == "1"
    dbg_rx = 0
    dbg_last = time.time()
    pkt_batch_cnt = 0
    # Main receive loop.
    while running[0]:
        pkt_batch_cnt += 1
        # Every 256 packets: emit stats and poll remote control, independent of
        # socket idle time (a busy interface may never hit the timeout path).
        if (pkt_batch_cnt & 0xFF) == 0:
            emit_capture_stats()
            # Poll independently of socket idle time. A busy monitored interface
            # may never raise socket.timeout, but control changes must still apply.
            # Time to poll the control server.
            if control_client is not None and time.time() >= control_next:
                try:
                    ports, iface, control_action, control_status = _run_control_tick(
                        ports, iface, control_run, control_client)
                    log("remote control: %s" % control_status)
                    # Re-exec in place with the updated configuration.
                    if control_action == "restart":
                        args = _restart_args(sys.argv[0], iface, ports,
                                             verbose, workers, wsse_body_bytes)
                        log("remote control: re-executing capture with updated configuration")
                        s.close()
                        os.execv(sys.executable, args)
                    # Stop requested: leave the loop; shutdown flushes pending.
                    elif control_action == "stop":
                        log("remote control: stop requested; exiting")
                        running[0] = False
                        continue
                except Exception as e:
                    log("WARN: remote control tick failed (%s)" % nt_control.safe_message(e))
                control_next = time.time() + control_interval
        # Receive one frame (65535 allows for offload/oversized frames).
        try:
            # Bounded by the 1s timeout; counted toward capture statistics.
            pkt = s.recv(65535)
            dbg_rx += 1
            stats_state["packets_total"] += 1
            stats_state["packet_bytes_total"] += len(pkt)
            if dbg and time.time() - dbg_last > 5:
                log("DEBUG rx=%d" % dbg_rx)
                dbg_last = time.time()
        # Idle second: run maintenance (stats, control, TTL sweeps).
        except socket.timeout:
            emit_capture_stats()
            if dbg:
                log("DEBUG timeout rx=%d" % dbg_rx)
                dbg_last = time.time()
            # Control poll on the idle path too (covers quiet interfaces).
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
            # TTL maintenance: expire idle flows and unattributed requests.
            if maintenance_due(now, last_sweep):
                out_s = []
                sweep_idle(flows, now, out_s, pending, resp_flows)
                sweep_pending(pending, now, out_s, flows=flows, resp_flows=resp_flows)
                write_events(out_s)
                last_sweep = now
            continue
        # EINTR (e.g. a signal mid-recv) is not an error; retry.
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise

        # Dispatch the frame and write any events it produced.
        now = time.time()
        out = []
        try:
            process_packet(pkt, ports, node_host, flows, resp_flows, pending,
                           out, now, wsse_body_bytes)
        except (struct.error, ValueError, IndexError):
            global g_invalid_frames_total
            g_invalid_frames_total += 1
            continue
        except MemoryError:
            try:
                sys.stderr.write("nt-sniff: FATAL: out of memory under RLIMIT_AS\n")
                sys.stderr.flush()
                if s:
                    s.close()
            finally:
                os._exit(71)

        if out:
            write_events(out)

        # Periodic maintenance on the busy path (the sparse path is covered by
        # the timeout handler above).
        if (pkt_batch_cnt & 0xFF) == 0 and maintenance_due(now, last_sweep):
            out_s = []
            sweep_idle(flows, now, out_s, pending, resp_flows)
            sweep_pending(pending, now, out_s, flows=flows, resp_flows=resp_flows)
            write_events(out_s)
            last_sweep = now

    # Shutdown: release WSSE slots, flush every pending request, emit a final
    # stats line, and log how many requests were flushed.
    out_s = []
    drain_incomplete_wsse(flows, out_s, pending, time.time())
    drain_pending(pending, out_s)
    write_events(out_s)
    emit_capture_stats(force=True)
    log("stopped (%d pending requests flushed)" % len(out_s))


def graceful_capture_shutdown(sock, flows, resp_flows, pending_tbl, budget, out=sys.stdout):
    """Drain all in-flight pending requests and emit final stats before exit."""
    try:
        if sock:
            sock.close()
    except Exception:
        pass
    out_s = []
    drain_incomplete_wsse(flows, out_s, pending_tbl, time.time())
    drain_pending(pending_tbl, out_s)
    if out_s:
        if hasattr(out, "write"):
            for ev in out_s:
                out.write(json.dumps(ev) + "\n")
            out.flush()
        elif isinstance(out, list):
            out.extend(out_s)
    log("stopped (%d pending requests flushed)" % len(out_s))


# Only start capture when executed as a script (allows import for tests).
if __name__ == "__main__":
    main()
