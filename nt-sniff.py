#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-sniff.py — passive AF_PACKET HTTP/SOAP sniffer for old kernels.

Target: CentOS 6.x / kernel 2.6.32 (no eBPF, no systemd, python 2.6).
Reads packets off the wire (CAP_NET_RAW), reassembles plain-HTTP requests,
extracts Basic-auth usernames (same semantics as nt_authlib.extract),
emits NetworkTracing event JSONL on stdout.

TLS is NOT readable (by design — that tier stays on the eBPF agent).
SOAP WSSE usernames are NOT extracted (product decision: Basic-only).

Usage:  python nt-sniff.py [-i eth0] [-p 80,8003,8005,8009,8010,8011]
Stdout: one JSON event per line -> pipe into nt-ship.py.
"""
from __future__ import print_function

import base64, errno, json, os, signal, socket, struct, sys, time

ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100

# py2.6 str-indexing yields 1-char str, not int (proven on real el6 VM);
# normalize so byte-at-index works identically under python 2 and 3
PY2 = sys.version_info[0] == 2


def b2i(c):
    return ord(c) if PY2 else c

METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

MAX_FLOWS = 8192            # concurrent tracked half-flows (per direction)
MAX_HDRS = 262144           # max bytes buffered waiting for \\r\\n\\r\\n
MAX_BODY = 131072           # max request body consumed for auth parsing
FLOW_TTL = 300              # seconds before idle flow buffers are dropped


def log(msg):
    sys.stderr.write("nt-sniff: %s\n" % msg)
    sys.stderr.flush()


def parse_args(argv):
    iface = None
    ports = [80, 8003, 8005, 8007, 8009, 8010, 8011]
    verbose = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-i":
            i += 1; iface = argv[i]
        elif a == "-p":
            i += 1; ports = [int(x) for x in argv[i].split(",") if x.strip()]
        elif a == "-v":
            verbose = True
        elif a in ("-h", "--help"):
            print(__doc__); raise SystemExit(0)
        else:
            raise SystemExit("unknown arg: %s" % a)
        i += 1
    return iface, set(ports), verbose


class Flow(object):
    __slots__ = ("buf", "state", "need", "hdrs", "touched")
    def __init__(self):
        self.buf = bytearray()
        self.state = 0          # 0=headers, 1=body
        self.need = 0
        self.hdrs = {}
        self.touched = time.time()


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
    }
    return ev if (dport in ports or h.get("_method")) else None


def handle_payload(flows, key, rev_key, payload, meta, ports, node_host, out):
    """Feed one direction's payload; emit finished events to out(list)."""
    dst_ip, dport, src_ip, sport = meta
    fl = flows.get(key)
    if fl is None:
        fl = Flow()
        flows[key] = fl
        if len(flows) > MAX_FLOWS:
            enforce_limit(flows, time.time())
    fl.touched = time.time()
    fl.buf.extend(bytearray(payload))

    while True:
        if fl.state == 0:
            idx = fl.buf.find(b"\r\n\r\n")
            if idx < 0:
                if len(fl.buf) > MAX_HDRS:
                    flows.pop(key, None)
                return
            head = bytes(fl.buf[:idx])
            rest = fl.buf[idx + 4:]
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
            cl = 0
            if "content-length" in hdrs:
                try:
                    cl = min(int(hdrs["content-length"]), MAX_BODY)
                except ValueError:
                    cl = 0
            if cl == 0:
                fl.hdrs = hdrs
                ev = finish_event(fl, key, dst_ip, dport, src_ip, sport,
                                  ports, node_host)
                del flows[key]
                if ev:
                    out.append(ev)
                return
            fl.hdrs = hdrs
            fl.state = 1
            fl.need = cl
            fl.buf = bytearray(rest[:cl * 2])   # keep some slack
            continue                            # re-check body in next loop
        if fl.state == 1:
            if len(fl.buf) >= fl.need:
                # body captured (auth may ride inside POST bodies for some
                # tiers, but per product decision we do NOT mine SOAP bodies;
                # buffer kept only so Content-Length framing stays honest)
                ev = finish_event(fl, key,
                                  dst_ip, dport, src_ip, sport,
                                  ports, node_host)
                del flows[key]
                if ev:
                    out.append(ev)
                return
            else:
                return                          # wait for more segments


def sweep_idle(flows, now):
    stale = []
    for k, fl in flows.items():
        if now - fl.touched > FLOW_TTL:
            stale.append(k)
    for k in stale:
        del flows[k]


def enforce_limit(flows, now):
    """Cap flow-table size (py2.6: no OrderedDict — sweep stale, then FIFO
    by insertion order, which plain dicts preserve in CPython)."""
    sweep_idle(flows, now)
    while len(flows) > MAX_FLOWS:
        flows.popitem()          # oldest-inserted key on CPython 2.6/2.7


def main():
    iface, ports, verbose = parse_args(sys.argv[1:])
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
    try:
        s.bind((iface or "", 0))
    except socket.error:
        # binding to a specific iface failed — fall back to all interfaces
        try:
            s.bind(("", 0))
        except socket.error:
            pass          # unbound socket still receives on all interfaces
    s.settimeout(1.0)

    flows = {}
    running = [True]

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    last_sweep = time.time()
    log("listening on %s ports=%s pid=%d" %
        (iface or "<all>", sorted(ports), os.getpid()))

    while running[0]:
        try:
            pkt = s.recv(65535)
        except socket.timeout:
            now = time.time()
            if now - last_sweep > 30:
                sweep_idle(flows, now)
                last_sweep = now
            continue
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise
        if len(pkt) < 34:
            continue
        off = 0
        etype = struct.unpack("!H", pkt[12:14])[0]
        if etype == ETH_P_VLAN:
            etype = struct.unpack("!H", pkt[16:18])[0]
            off = 4
        if etype != ETH_P_IP:
            continue
        ip = pkt[14 + off:]
        if len(ip) < 20:
            continue
        ihl = (b2i(ip[0]) & 0x0F) * 4
        if (b2i(ip[0]) >> 4) != 4 or b2i(ip[9]) != 6:   # IPv4 TCP only
            continue
        frag = struct.unpack("!H", ip[6:8])[0]
        if frag & 0x1FFF:                         # non-first fragment
            continue
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[0:4])
        doff = ((b2i(tcp[12]) >> 4) & 0x0F) * 4
        flags = b2i(tcp[13])
        payload = tcp[doff:]
        if not payload:
            # FIN/RST teardown: drop both directions' buffers
            if flags & 0x05:                      # FIN|RST
                fk = (src_ip, sport, dst_ip, dport)
                rk = (dst_ip, dport, src_ip, sport)
                flows.pop(fk, None)
                flows.pop(rk, None)
            continue
        # requests TO our monitored ports (inbound to services)
        if dport in ports:
            key = (src_ip, sport, dst_ip, dport)
            out = []
            handle_payload(flows, key, None, payload,
                           (dst_ip, dport, src_ip, sport),
                           ports, node_host, out)
            for ev in out:
                sys.stdout.write(json.dumps(ev) + "\n")
            if out:
                sys.stdout.flush()
        # responses FROM monitored ports: used only for teardown bookkeeping
        elif sport in ports and (flags & 0x05):
            rk = (dst_ip, dport, src_ip, sport)
            flows.pop(rk, None)

    log("stopped")


if __name__ == "__main__":
    main()
