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


class Flow(object):
    __slots__ = ("buf", "hdrs", "touched", "event", "body_goal",
                 "head_bytes")
    def __init__(self):
        self.buf = bytearray()
        self.hdrs = None
        self.touched = time.time()
        self.event = None
        self.body_goal = 0
        self.head_bytes = 0


# ------------------------------------------------- response correlation ----
PENDING_TTL = 5.0        # flush unmatched requests after this many seconds
PENDING_MAX = 8192       # hard cap; overflow flushes oldest first
PENDING_PER_FLOW = 32    # bound a single pipelined/hostile keep-alive flow
SWEEP_INTERVAL = 1.0     # honor PENDING_TTL even when the socket goes idle

# pending[(src_ip, sport, dst_ip, dport)]  -- key is the RESPONSE tuple:
# server->client. Value: [event, req_ts]. A list per key handles HTTP
# keep-alive pipelining (several requests before responses arrive).
pending = {}


def pending_del(rk):
    pending.pop(rk, None)


def pending_pop(rk, out, pending_tbl=None):
    """Flush the oldest pending event for this response tuple (FIN/RST or
    overflow path). Emits whatever the event has — status stays null."""
    if pending_tbl is None:
        pending_tbl = pending
    lst = pending_tbl.get(rk)
    if not lst:
        return None
    ev, _ = lst.pop(0)
    if not lst:
        pending_tbl.pop(rk, None)
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


def correlate_response(pending_tbl, rk, payload, now, out):
    """Attach one response head to the oldest request on a connection.

    HTTP/1.1 pipelining can leave several requests queued for the same
    four-tuple.  Consume exactly one entry; deleting the whole key here loses
    every request after the first response.
    """
    st, clen = parse_response_head(payload)
    if st is None:
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
    ev = fl.event
    flows.pop(key, None)
    if not ev:
        return
    ev["req_bytes"] = fl.head_bytes
    if pending_tbl is None:
        out.append(ev)
        return
    rk = (dst_ip, dport, src_ip, sport)
    ent = pending_tbl.get(rk)
    if ent is None:
        if len(pending_tbl) >= PENDING_MAX:
            _flush_oldest_pending(pending_tbl, out)
        ent = pending_tbl[rk] = []
    elif len(ent) >= PENDING_PER_FLOW:
        pending_pop(rk, out, pending_tbl)
        ent = pending_tbl.get(rk)
        if ent is None:
            ent = pending_tbl[rk] = []
    ent.append([ev, now if now is not None else time.time()])


def _try_wsse_body(flows, key, fl, payload, meta, out, pending_tbl, now):
    """Append no more than body_goal bytes and finish as soon as possible."""
    remaining = fl.body_goal - len(fl.buf)
    if remaining > 0 and payload:
        fl.buf.extend(bytearray(payload[:remaining]))
    username = extract_wsse_username(fl.buf)
    if username:
        fl.event["wsse_user"] = username
        fl.event["user"] = username
        fl.event["scheme"] = "wsse"
    if username or len(fl.buf) >= fl.body_goal:
        _emit_request(flows, key, fl, meta, out, pending_tbl, now)
        return True
    return False


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out,
                   pending_tbl=None, now=None, wsse_body_bytes=0):
    """Feed one direction's payload; emit finished events to out(list).

    Bodies are ignored unless wsse_body_bytes is non-zero. In opt-in mode,
    only XML requests with Content-Length are inspected, each buffer is
    bounded by wsse_body_bytes, and only a recognized WSSE username reaches
    the event. The body and all other UsernameToken material are discarded.
    """
    dst_ip, dport, src_ip, sport = meta
    if not valid_port(dport) or not valid_port(sport):
        return
    fl = flows.get(key)
    if fl is None:
        fl = Flow()
        flows[key] = fl
        if len(flows) > MAX_FLOWS:
            enforce_limit(flows, time.time())
    fl.touched = time.time()

    if (fl.event is not None and fl.event.get("basic_user") and
            any(payload.startswith(method.encode("ascii") + b" ")
                for method in METHODS)):
        # A new keep-alive request started before the bounded WSSE window
        # completed. Preserve the Basic event, then parse the new request.
        _emit_request(flows, key, fl, meta, out, pending_tbl, now)
        handle_payload(flows, key, rev_key, payload, meta, ports, node_host,
                       out, pending_tbl, now, wsse_body_bytes)
        return
    if fl.event is not None:
        _try_wsse_body(flows, key, fl, payload, meta, out, pending_tbl, now)
        return

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
    if len(first) >= 2 and first[0] in [m.encode() for m in METHODS]:
        hdrs["_method"] = first[0].decode("ascii", "replace")
        hdrs["_path"] = first[1].decode("ascii", "replace")
    else:
        flows.pop(key, None)
        return
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        kn, kv = ln.split(b":", 1)
        hdrs[kn.strip().lower().decode(
            "ascii", "replace")] = kv.strip().decode(
                "utf-8", "replace")[:180]
    fl.hdrs = hdrs
    fl.event = finish_event(fl, key, dst_ip, dport, src_ip, sport,
                            ports, node_host)
    if not fl.event:
        flows.pop(key, None)
        return
    fl.head_bytes = idx + 4
    initial_body = bytes(fl.buf[idx + 4:])
    fl.buf = bytearray()

    if (not wsse_body_bytes or
            not is_soap_content_type(hdrs.get("content-type"))):
        _emit_request(flows, key, fl, meta, out, pending_tbl, now)
        return
    try:
        content_length = int(hdrs.get("content-length", ""))
    except (TypeError, ValueError):
        content_length = 0
    active_body_flows = sum([1 for candidate in flows.values()
                             if candidate.event is not None and
                             candidate.body_goal > 0])
    if (content_length <= 0 or active_body_flows >= MAX_WSSE_BODY_FLOWS or
            "chunked" in hdrs.get("transfer-encoding", "").lower()):
        _emit_request(flows, key, fl, meta, out, pending_tbl, now)
        return
    fl.body_goal = min(content_length, wsse_body_bytes, MAX_WSSE_BODY_BYTES)
    _try_wsse_body(flows, key, fl, initial_body, meta, out, pending_tbl, now)


def sweep_idle(flows, now, out=None, pending_tbl=None):
    stale = []
    for k, fl in flows.items():
        if now - fl.touched > FLOW_TTL:
            stale.append(k)
    for k in stale:
        fl = flows.get(k)
        if (out is not None and fl is not None and fl.event is not None and
                fl.event.get("basic_user")):
            src_ip, sport, dst_ip, dport = k
            _emit_request(flows, k, fl, (dst_ip, dport, src_ip, sport),
                          out, pending_tbl, now)
        else:
            flows.pop(k, None)


def drain_incomplete_wsse(flows, out, pending_tbl, now=None):
    """Fall back to the retained pre-WSSE identity during clean shutdown."""
    for key in list(flows.keys()):
        fl = flows.get(key)
        if (fl is None or fl.event is None or
                not fl.event.get("basic_user")):
            continue
        src_ip, sport, dst_ip, dport = key
        _emit_request(flows, key, fl, (dst_ip, dport, src_ip, sport),
                      out, pending_tbl, now)


def _flush_oldest_pending(pending_tbl, out):
    """Overflow guard: emit the single oldest pending event as-is."""
    oldest_key, oldest_ts = None, None
    for rk, lst in pending_tbl.items():
        ts = lst[0][1]
        if oldest_ts is None or ts < oldest_ts:
            oldest_key, oldest_ts = rk, ts
    if oldest_key is not None:
        pending_pop(oldest_key, out, pending_tbl)


def sweep_pending(pending_tbl, now, out):
    """TTL flush: emit requests whose responses never showed up."""
    for rk in list(pending_tbl.keys()):
        lst = pending_tbl.get(rk)
        while lst and now - lst[0][1] > PENDING_TTL:
            pending_pop(rk, out, pending_tbl)
            lst = pending_tbl.get(rk)


def drain_pending(pending_tbl, out):
    """Emit every captured request before capture shutdown.

    Responses are optional enrichment. A stop/restart must not discard a
    request merely because its response was filtered, split, or still in
    flight when the process received SIGTERM.
    """
    for rk in list(pending_tbl.keys()):
        while pending_tbl.get(rk):
            pending_pop(rk, out, pending_tbl)


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
    running = [True]

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
                sweep_idle(flows, now, out_s, pending)
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
            if payload[:5] == b"HTTP/":
                correlate_response(pending, rk, payload, now, out)
            elif flags & 0x05:                      # FIN|RST: flush unmatched
                ev = pending_pop(rk, out)
        # ---------------- REQUEST direction (client -> server) -----------
        elif dport in ports:
            if flags & 0x05:                      # teardown w/o response seen
                rk = (dst_ip, dport, src_ip, sport)
                pending_pop(rk, out)
            key = (src_ip, sport, dst_ip, dport)
            handle_payload(flows, key, None, payload,
                           (dst_ip, dport, src_ip, sport),
                           ports, node_host, out, pending, now,
                           wsse_body_bytes)
        if out:
            w = sys.stdout.write
            for ev in out:
                w(json.dumps(ev) + "\n")
            sys.stdout.flush()

        if maintenance_due(now, last_sweep):
            out_s = []
            sweep_idle(flows, now, out_s, pending)
            sweep_pending(pending, now, out_s)
            for ev in out_s:
                sys.stdout.write(json.dumps(ev) + "\n")
            if out_s:
                sys.stdout.flush()
            last_sweep = now

    out_s = []
    drain_incomplete_wsse(flows, out_s, pending, time.time())
    drain_pending(pending, out_s)
    for ev in out_s:
        sys.stdout.write(json.dumps(ev) + "\n")
    if out_s:
        sys.stdout.flush()
    log("stopped (%d pending requests flushed)" % len(out_s))


if __name__ == "__main__":
    main()
