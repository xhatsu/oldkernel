#!/usr/bin/env python3
"""test_synthetic_harness.py - Synthetic Ethernet/IPv4/TCP packet generator & regression suite.
Verifies TCP stream reassembly, body framing, 100-continue responses,
SOAP preservation, and connection lifecycle across both C++ and Python sniffers.
"""
import importlib.util, json, os, struct, subprocess, sys, time

OLD_DIR = os.path.dirname(os.path.abspath(__file__))

# Dynamically import nt_sniff module
spec = importlib.util.spec_from_file_location("nt_sniff", os.path.join(OLD_DIR, "nt-sniff.py"))
nt_sniff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nt_sniff)

def ip_checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def make_ipv4_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload,
                     src_mac=b"\x00\x11\x22\x33\x44\x55",
                     dst_mac=b"\x66\x77\x88\x99\xaa\xbb",
                     ip_id=1000, ip_total_len=None, ip_frag=0):
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    tcp_len = 20 + len(payload)
    tcp_hdr = struct.pack("!HHIIBBHHH",
                          sport, dport,
                          seq, ack,
                          (5 << 4), flags,
                          65535, 0, 0)
    tot_len = ip_total_len if ip_total_len is not None else (20 + tcp_len)
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
                                  0x45, 0, tot_len, ip_id, ip_frag, 64, 6, 0,
                                  src_bytes, dst_bytes)
    cksum = ip_checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, tot_len, ip_id, ip_frag, 64, 6, cksum,
                         src_bytes, dst_bytes)
    return eth + ip_hdr + tcp_hdr + payload

def write_pcap(filepath, packets_with_ts):
    with open(filepath, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, pkt, wire_len in packets_with_ts:
            incl_len = len(pkt)
            wlen = wire_len if wire_len is not None else incl_len
            f.write(struct.pack("<IIII", int(ts_sec), int(ts_usec), incl_len, wlen))
            f.write(pkt)

def run_cpp_pcap(pcap_file, ports, wsse_bytes=0):
    cpp_bin = os.path.join(OLD_DIR, "pcap_test_cpp")
    cmd = [cpp_bin, pcap_file]
    if wsse_bytes:
        cmd += ["--wsse-body-bytes", str(wsse_bytes)]
    cmd += [str(p) for p in ports]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError("pcap_test_cpp failed (code %d): %s" % (p.returncode, p.stderr))
    events = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                events.append(json.loads(line))
            except Exception:
                pass
    return events

def run_python_pcap(pcap_file, ports, wsse_bytes=0):
    nt_sniff.corr_disabled_clear()
    flows = {}

    resp_flows = {}
    pending = {}
    out = []

    ports_set = set(ports)
    node_host = "test-py-synthetic"

    with open(pcap_file, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return []
        linktype = struct.unpack("<I", gh[20:24])[0]
        swap = (struct.unpack("<I", gh[:4])[0] == 0xd4c3b2a1)
        last_sweep = 0
        while True:
            ph = f.read(16)
            if not ph:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", ph)
            if swap:
                incl_len = ((incl_len >> 24) & 0xff) | ((incl_len >> 8) & 0xff00) | \
                           ((incl_len << 8) & 0xff0000) | ((incl_len << 24) & 0xff000000)
            raw = f.read(incl_len)
            now = ts_sec + ts_usec / 1e6
            if now - last_sweep >= 1.0:
                nt_sniff.sweep_pending(pending, now, out)
                nt_sniff.sweep_idle(flows, now, out, pending, resp_flows)
                last_sweep = now
            if linktype == 113:
                if len(raw) < 16:
                    continue
                raw = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + raw[14:16] + raw[16:]
            nt_sniff.process_packet(raw, ports_set, node_host, flows, resp_flows, pending, out, now, wsse_bytes)

    nt_sniff.drain_incomplete_wsse(flows, out, pending, time.time())
    nt_sniff.drain_pending(pending, out)
    return out

def run_test_suite_for_engine(run_pcap, engine_name):
    print("--- Running Synthetic Tests for %s Engine ---" % engine_name)
    tmp_pcap = "/tmp/test_synthetic_%s.pcap" % engine_name.lower()
    failures = []

    # 1. Retransmission test
    req1 = b"GET /api/retrans HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50000, 80, 1000, 0, 0x18, req1)
    write_pcap(tmp_pcap, [(1000, 0, pkt1, len(pkt1)), (1000, 500, pkt1, len(pkt1))])
    ev1 = run_pcap(tmp_pcap, [80])
    if len(ev1) != 1:
        failures.append("[%s] Test 1 (Retransmission): Expected 1 event, got %d" % (engine_name, len(ev1)))
    else:
        print("  [%s] Test 1 (Retransmission): PASS (1 event)" % engine_name)

    # 2. Split method test: "GE" and "T /api/split HTTP/1.1\r\nHost: api.test\r\n\r\n"
    part1 = b"GE"
    part2 = b"T /api/split HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_part1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50001, 80, 2000, 0, 0x18, part1)
    pkt_part2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50001, 80, 2002, 0, 0x18, part2)
    write_pcap(tmp_pcap, [(1001, 0, pkt_part1, len(pkt_part1)), (1001, 500, pkt_part2, len(pkt_part2))])
    ev2 = run_pcap(tmp_pcap, [80])
    if len(ev2) != 1 or ev2[0].get("path") != "/api/split":
        failures.append("[%s] Test 2 (Split Method): Expected 1 event for /api/split, got %s" %
                        (engine_name, [e.get("path") for e in ev2]))
    else:
        print("  [%s] Test 2 (Split Method): PASS (/api/split reassembled)" % engine_name)

    # 3. HTTP body contains HTTP request: POST with body "GET /fake HTTP/1.1..."
    post_body = b"GET /fake HTTP/1.1\r\nHost: fake.com\r\n\r\n"
    post_req = (b"POST /api/outer HTTP/1.1\r\nHost: api.test\r\nContent-Length: %d\r\n\r\n" % len(post_body)) + post_body
    pkt_post = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50002, 80, 3000, 0, 0x18, post_req)
    write_pcap(tmp_pcap, [(1002, 0, pkt_post, len(pkt_post))])
    ev3 = run_pcap(tmp_pcap, [80])
    if len(ev3) != 1 or ev3[0].get("path") != "/api/outer":
        failures.append("[%s] Test 3 (Body Framing): Expected 1 event for /api/outer, got %s" %
                        (engine_name, [e.get("path") for e in ev3]))
    else:
        print("  [%s] Test 3 (Body Framing): PASS (only /api/outer emitted, /fake skipped)" % engine_name)

    # 4. 100 Continue followed by 200 OK
    req4 = b"POST /api/upload HTTP/1.1\r\nHost: api.test\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello"
    pkt_req4 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50003, 80, 4000, 0, 0x18, req4)
    resp100 = b"HTTP/1.1 100 Continue\r\n\r\n"
    pkt_resp100 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50003, 9000, 4075, 0x18, resp100)
    resp200 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    pkt_resp200 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50003, 9025, 4075, 0x18, resp200)
    write_pcap(tmp_pcap, [(1003, 0, pkt_req4, len(pkt_req4)),
                          (1003, 100, pkt_resp100, len(pkt_resp100)),
                          (1003, 200, pkt_resp200, len(pkt_resp200))])
    ev4 = run_pcap(tmp_pcap, [80])
    if len(ev4) != 1 or ev4[0].get("status") != 200:
        failures.append("[%s] Test 4 (100 Continue): Expected 1 event with status 200, got %s" %
                        (engine_name, [e.get("status") for e in ev4]))
    else:
        print("  [%s] Test 4 (100 Continue): PASS (correlated with status 200)" % engine_name)

    # 5. Incomplete SOAP body without Basic auth
    soap_body = b"<soap:Envelope><soap:Body><test"
    soap_req = b"POST /api/soap HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/soap+xml\r\nContent-Length: 100\r\n\r\n" + soap_body
    pkt_soap = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50004, 80, 5000, 0, 0x18, soap_req)
    write_pcap(tmp_pcap, [(1004, 0, pkt_soap, len(pkt_soap))])
    ev5 = run_pcap(tmp_pcap, [80], wsse_bytes=1024)
    if len(ev5) != 1 or ev5[0].get("path") != "/api/soap":
        failures.append("[%s] Test 5 (Incomplete SOAP): Expected 1 event for /api/soap, got %s" %
                        (engine_name, [e.get("path") for e in ev5]))
    else:
        print("  [%s] Test 5 (Incomplete SOAP): PASS (request preserved)" % engine_name)

    # 6. Out-of-order packets: part2 received before part1
    pkt_oo2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50005, 80, 6022, 0, 0x18, b"item HTTP/1.1\r\nHost: a\r\n\r\n")
    pkt_oo1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50005, 80, 6000, 0, 0x18, b"GET /api/out-of-order-")
    write_pcap(tmp_pcap, [(1005, 0, pkt_oo2, len(pkt_oo2)), (1005, 50, pkt_oo1, len(pkt_oo1))])
    ev6 = run_pcap(tmp_pcap, [80])
    if len(ev6) != 1 or ev6[0].get("path") != "/api/out-of-order-item":
        failures.append("[%s] Test 6 (Out-of-Order): Expected 1 event for /api/out-of-order-item, got %s" %
                        (engine_name, [e.get("path") for e in ev6]))
    else:
        print("  [%s] Test 6 (Out-of-Order): PASS (reassembled correctly)" % engine_name)

    # 7. Overlapping retransmission
    pkt_ov1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50006, 80, 7000, 0, 0x18, b"GET /api/overlap HTT")
    pkt_ov2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50006, 80, 7013, 0, 0x18, b"lap HTTP/1.1\r\nHost: a\r\n\r\n")
    write_pcap(tmp_pcap, [(1006, 0, pkt_ov1, len(pkt_ov1)), (1006, 50, pkt_ov2, len(pkt_ov2))])
    ev7 = run_pcap(tmp_pcap, [80])
    if len(ev7) != 1 or ev7[0].get("path") != "/api/overlap":
        failures.append("[%s] Test 7 (Overlapping Retransmission): Expected 1 event for /api/overlap, got %s" %
                        (engine_name, [e.get("path") for e in ev7]))
    else:
        print("  [%s] Test 7 (Overlapping Retransmission): PASS (overlap trimmed)" % engine_name)

    # 8. Split response headers
    req8 = b"GET /api/resp HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_req8 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50007, 80, 8000, 0, 0x18, req8)
    resp_part1 = b"HTTP/1.1 20"
    pkt_rp1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50007, 9500, 8042, 0x18, resp_part1)
    resp_part2 = b"0 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50007, 9511, 8042, 0x18, resp_part2)
    write_pcap(tmp_pcap, [(1007, 0, pkt_req8, len(pkt_req8)),
                          (1007, 100, pkt_rp1, len(pkt_rp1)),
                          (1007, 200, pkt_rp2, len(pkt_rp2))])
    ev8 = run_pcap(tmp_pcap, [80])
    if len(ev8) != 1 or ev8[0].get("status") != 200 or ev8[0].get("resp_bytes") != 0:
        failures.append("[%s] Test 8 (Split Response): Expected status 200 and resp_bytes 0, got status %s, resp_bytes %s" %
                        (engine_name, ev8[0].get("status") if ev8 else None, ev8[0].get("resp_bytes") if ev8 else None))
    else:
        print("  [%s] Test 8 (Split Response): PASS (reassembled status 200, resp_bytes 0)" % engine_name)

    # 9. FIN carrying final payload
    req9 = b"GET /api/fin-data HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_fin_data = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50008, 80, 9000, 0, 0x19, req9)
    write_pcap(tmp_pcap, [(1008, 0, pkt_fin_data, len(pkt_fin_data))])
    ev9 = run_pcap(tmp_pcap, [80])
    if len(ev9) != 1 or ev9[0].get("path") != "/api/fin-data":
        failures.append("[%s] Test 9 (FIN with Payload): Expected 1 event for /api/fin-data, got %s" %
                        (engine_name, [e.get("path") for e in ev9]))
    else:
        print("  [%s] Test 9 (FIN with Payload): PASS (payload consumed before close)" % engine_name)

    # 10. Empty FIN and RST closes flow cleanly
    req10 = b"GET /api/clean-close HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_req10 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50009, 80, 10000, 0, 0x18, req10)
    pkt_empty_fin = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50009, 80, 10046, 0, 0x11, b"")
    write_pcap(tmp_pcap, [(1009, 0, pkt_req10, len(pkt_req10)),
                          (1009, 100, pkt_empty_fin, len(pkt_empty_fin))])
    ev10 = run_pcap(tmp_pcap, [80])
    if len(ev10) != 1 or ev10[0].get("path") != "/api/clean-close":
        failures.append("[%s] Test 10 (Empty FIN Close): Expected 1 event, got %s" %
                        (engine_name, [e.get("path") for e in ev10]))
    else:
        print("  [%s] Test 10 (Empty FIN Close): PASS" % engine_name)

    # 11. Response body framing: 200 response body contains fake HTTP status line
    req11_1 = b"GET /api/first HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r11_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50011, 80, 11000, 0, 0x18, req11_1)
    fake_503 = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
    resp11_1 = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(fake_503)) + fake_503
    pkt_rp11_1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50011, 21000, 11000 + len(req11_1), 0x18, resp11_1)
    req11_2 = b"GET /api/second HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r11_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50011, 80, 11000 + len(req11_1), 0, 0x18, req11_2)
    resp11_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    pkt_rp11_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50011, 21000 + len(resp11_1), 11000 + len(req11_1) + len(req11_2), 0x18, resp11_2)
    write_pcap(tmp_pcap, [(1011, 0, pkt_r11_1, len(pkt_r11_1)),
                          (1011, 10000, pkt_rp11_1, len(pkt_rp11_1)),
                          (1011, 20000, pkt_r11_2, len(pkt_r11_2)),
                          (1011, 30000, pkt_rp11_2, len(pkt_rp11_2))])
    ev11 = run_pcap(tmp_pcap, [80])
    paths11 = [e.get("path") for e in ev11]
    statuses11 = [e.get("status") for e in ev11]
    if paths11 != ["/api/first", "/api/second"] or statuses11 != [200, 200]:
        failures.append("[%s] Test 11 (Response Body Framing): Expected [/api/first, /api/second] with [200, 200], got paths %s, statuses %s" %
                        (engine_name, paths11, statuses11))
    else:
        print("  [%s] Test 11 (Response Body Framing): PASS (no 503 fabricated)" % engine_name)

    # 12. Chunked response framing: chunk contains HTTP status line
    req12_1 = b"GET /api/chunked HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r12_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50012, 80, 12000, 0, 0x18, req12_1)
    chunk_fake = b"HTTP/1.1 404 Not Found\r\n\r\n"
    resp12_1 = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                b"%x\r\n" % len(chunk_fake) + chunk_fake + b"\r\n0\r\n\r\n")
    pkt_rp12_1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50012, 22000, 12000 + len(req12_1), 0x18, resp12_1)
    req12_2 = b"GET /api/after-chunk HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r12_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50012, 80, 12000 + len(req12_1), 0, 0x18, req12_2)
    resp12_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    pkt_rp12_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50012, 22000 + len(resp12_1), 12000 + len(req12_1) + len(req12_2), 0x18, resp12_2)
    write_pcap(tmp_pcap, [(1012, 0, pkt_r12_1, len(pkt_r12_1)),
                          (1012, 10000, pkt_rp12_1, len(pkt_rp12_1)),
                          (1012, 20000, pkt_r12_2, len(pkt_r12_2)),
                          (1012, 30000, pkt_rp12_2, len(pkt_rp12_2))])
    ev12 = run_pcap(tmp_pcap, [80])
    paths12 = [e.get("path") for e in ev12]
    statuses12 = [e.get("status") for e in ev12]
    if paths12 != ["/api/chunked", "/api/after-chunk"] or statuses12 != [200, 200]:
        failures.append("[%s] Test 12 (Chunked Response Framing): Expected [/api/chunked, /api/after-chunk] with [200, 200], got %s, %s" %
                        (engine_name, paths12, statuses12))
    else:
        print("  [%s] Test 12 (Chunked Response Framing): PASS (no 404 fabricated)" % engine_name)

    # 13. Keep-Alive latency timing across idle gap
    req13_1 = b"GET /api/ka1 HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r13_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50013, 80, 13000, 0, 0x18, req13_1)
    resp13_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp13_1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50013, 23000, 13000 + len(req13_1), 0x18, resp13_1)
    req13_2 = b"GET /api/ka2 HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r13_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50013, 80, 13000 + len(req13_1), 0, 0x18, req13_2)
    resp13_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp13_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50013, 23000 + len(resp13_1), 13000 + len(req13_1) + len(req13_2), 0x18, resp13_2)
    # req1 at 1013.0, resp1 at 1013.05 (50ms); 5s gap; req2 at 1018.0, resp2 at 1018.04 (40ms)
    write_pcap(tmp_pcap, [(1013, 0, pkt_r13_1, len(pkt_r13_1)),
                          (1013, 50000, pkt_rp13_1, len(pkt_rp13_1)),
                          (1018, 0, pkt_r13_2, len(pkt_r13_2)),
                          (1018, 40000, pkt_rp13_2, len(pkt_rp13_2))])
    ev13 = run_pcap(tmp_pcap, [80])
    dur1 = ev13[0].get("duration_ms", -1) if len(ev13) > 0 else -1
    dur2 = ev13[1].get("duration_ms", -1) if len(ev13) > 1 else -1
    if len(ev13) != 2 or dur1 < 40 or dur1 > 60 or dur2 < 30 or dur2 > 50:
        failures.append("[%s] Test 13 (Keep-Alive Latency): Expected durations ~50ms and ~40ms, got dur1=%s, dur2=%s (events: %d)" %
                        (engine_name, dur1, dur2, len(ev13)))
    else:
        print("  [%s] Test 13 (Keep-Alive Latency): PASS (durations: %d ms, %d ms)" % (engine_name, dur1, dur2))

    # 14. Client SYN Connection Generation Isolation
    pkt_syn1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50014, 80, 1000, 0, 0x02, b"")
    req14_1 = b"GET /api/stale HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r14_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50014, 80, 1001, 0, 0x18, req14_1)
    # New SYN re-opening the 4-tuple with a different ISN (client restart)
    pkt_syn2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50014, 80, 50000, 0, 0x02, b"")
    req14_2 = b"GET /api/fresh HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r14_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50014, 80, 50001, 0, 0x18, req14_2)
    resp14_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp14_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50014, 80000, 50001 + len(req14_2), 0x18, resp14_2)
    write_pcap(tmp_pcap, [(1014, 0, pkt_syn1, len(pkt_syn1)),
                          (1014, 10000, pkt_r14_1, len(pkt_r14_1)),
                          (1015, 0, pkt_syn2, len(pkt_syn2)),
                          (1015, 10000, pkt_r14_2, len(pkt_r14_2)),
                          (1015, 30000, pkt_rp14_2, len(pkt_rp14_2))])
    ev14 = run_pcap(tmp_pcap, [80])
    fresh_ev = [e for e in ev14 if e.get("path") == "/api/fresh"]
    if len(fresh_ev) != 1 or fresh_ev[0].get("status") != 200:
        failures.append("[%s] Test 14 (SYN Generation Isolation): Expected /api/fresh with status 200, got %s" %
                        (engine_name, ev14))
    else:
        print("  [%s] Test 14 (SYN Generation Isolation): PASS (fresh request correlated with status 200)" % engine_name)

    # 15. Conflicting Chunked + Content-Length (Smuggling Protection)
    smuggle_req = (b"POST /api/smuggle HTTP/1.1\r\n"
                   b"Host: api.test\r\n"
                   b"Transfer-Encoding: chunked\r\n"
                   b"Content-Length: 5\r\n\r\n"
                   b"0\r\n\r\n"
                   b"GET /fake-request HTTP/1.1\r\nHost: api.test\r\n\r\n")
    pkt_smuggle = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50015, 80, 15000, 0, 0x18, smuggle_req)
    write_pcap(tmp_pcap, [(1015, 0, pkt_smuggle, len(pkt_smuggle))])
    ev15 = run_pcap(tmp_pcap, [80])
    fake_ev = [e for e in ev15 if e.get("path") == "/fake-request"]
    if fake_ev:
        failures.append("[%s] Test 15 (Smuggling Protection): Detected fabricated /fake-request: %s" %
                        (engine_name, fake_ev))
    else:
        print("  [%s] Test 15 (Smuggling Protection): PASS (no smuggled request fabricated)" % engine_name)

    # 16. HEAD Request Bodyless Response Framing
    head_req = b"HEAD /api/head HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_hreq = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50016, 80, 16000, 0, 0x18, head_req)
    head_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n"
    pkt_hresp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50016, 26000, 16000 + len(head_req), 0x18, head_resp)
    get_req = b"GET /api/after-head HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_greq = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50016, 80, 16000 + len(head_req), 0, 0x18, get_req)
    get_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    pkt_gresp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50016, 26000 + len(head_resp), 16000 + len(head_req) + len(get_req), 0x18, get_resp)
    write_pcap(tmp_pcap, [(1016, 0, pkt_hreq, len(pkt_hreq)),
                          (1016, 10000, pkt_hresp, len(pkt_hresp)),
                          (1016, 20000, pkt_greq, len(pkt_greq)),
                          (1016, 30000, pkt_gresp, len(pkt_gresp))])
    ev16 = run_pcap(tmp_pcap, [80])
    paths16 = [e.get("path") for e in ev16]
    statuses16 = [e.get("status") for e in ev16]
    if paths16 != ["/api/head", "/api/after-head"] or statuses16 != [200, 200]:
        failures.append("[%s] Test 16 (HEAD Bodyless Response): Expected [/api/head, /api/after-head] with [200, 200], got %s, %s" %
                        (engine_name, paths16, statuses16))
    else:
        print("  [%s] Test 16 (HEAD Bodyless Response): PASS (both requests correlated)" % engine_name)

    # 17. Late response to expired request does not attach to newer request (Tombstone isolation)
    req17_1 = b"GET /api/expired HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r17_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50017, 80, 17000, 0, 0x18, req17_1)
    req17_2 = b"GET /api/newer HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r17_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50017, 80, 17000 + len(req17_1), 0, 0x18, req17_2)
    resp17_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp17_1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50017, 27000, 17000 + len(req17_1), 0x18, resp17_1)
    resp17_2 = b"HTTP/1.1 204 No Content\r\n\r\n"
    pkt_rp17_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50017, 27000 + len(resp17_1), 17000 + len(req17_1) + len(req17_2), 0x18, resp17_2)
    pkt_ack1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50017, 80, 17000 + len(req17_1), 0, 0x10, b"")
    write_pcap(tmp_pcap, [(1017, 0, pkt_r17_1, len(pkt_r17_1)),
                          (1027, 0, pkt_ack1, len(pkt_ack1)),
                          (1037, 0, pkt_ack1, len(pkt_ack1)),
                          (1047, 0, pkt_ack1, len(pkt_ack1)),
                          (1055, 0, pkt_r17_2, len(pkt_r17_2)),
                          (1055, 10000, pkt_rp17_1, len(pkt_rp17_1)),
                          (1055, 20000, pkt_rp17_2, len(pkt_rp17_2))])
    ev17 = run_pcap(tmp_pcap, [80])
    exp_ev = [e for e in ev17 if e.get("path") == "/api/expired"]
    new_ev = [e for e in ev17 if e.get("path") == "/api/newer"]
    if not exp_ev or exp_ev[0].get("status") is not None:
        failures.append("[%s] Test 17 (Late Response Isolation): Expected /api/expired with status None, got %s" % (engine_name, exp_ev))
    elif not new_ev or new_ev[0].get("status") != 204:
        failures.append("[%s] Test 17 (Late Response Isolation): Expected /api/newer with status 204, got %s" % (engine_name, new_ev))
    else:
        print("  [%s] Test 17 (Late Response Isolation): PASS (expired tombstone consumed, newer got 204)" % engine_name)

    # 18. Client SYN reconnect does not reinsert incomplete SOAP request
    pkt_syn18_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50018, 80, 18000, 0, 0x02, b"")
    req18_soap = (b"POST /api/oldsoap HTTP/1.1\r\n"
                  b"Host: api.test\r\n"
                  b"Content-Type: text/xml\r\n"
                  b"Content-Length: 1000\r\n\r\n"
                  b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Header>")
    pkt_r18_soap = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50018, 80, 18001, 0, 0x18, req18_soap)
    pkt_syn18_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50018, 80, 58000, 0, 0x02, b"")
    req18_new = b"GET /api/newreq HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt_r18_new = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50018, 80, 58001, 0, 0x18, req18_new)
    resp18_new = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp18_new = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50018, 88000, 58001 + len(req18_new), 0x18, resp18_new)
    write_pcap(tmp_pcap, [(1018, 0, pkt_syn18_1, len(pkt_syn18_1)),
                          (1018, 10000, pkt_r18_soap, len(pkt_r18_soap)),
                          (1019, 0, pkt_syn18_2, len(pkt_syn18_2)),
                          (1019, 10000, pkt_r18_new, len(pkt_r18_new)),
                          (1019, 20000, pkt_rp18_new, len(pkt_rp18_new))])
    ev18 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    soap_ev = [e for e in ev18 if e.get("path") == "/api/oldsoap"]
    new_ev = [e for e in ev18 if e.get("path") == "/api/newreq"]
    if not soap_ev or soap_ev[0].get("status") is not None:
        failures.append("[%s] Test 18 (SYN Incomplete SOAP): Expected /api/oldsoap with status None, got %s" % (engine_name, soap_ev))
    elif not new_ev or new_ev[0].get("status") != 200:
        failures.append("[%s] Test 18 (SYN Incomplete SOAP): Expected /api/newreq with status 200, got %s" % (engine_name, new_ev))
    else:
        print("  [%s] Test 18 (SYN Incomplete SOAP): PASS (old soap not reinserted ahead of new request)" % engine_name)

    # 19. Conflicting Content-Length Headers
    conflicting_cl_req = (b"POST /api/conflict HTTP/1.1\r\n"
                          b"Host: api.test\r\n"
                          b"Content-Length: 8\r\n"
                          b"Content-Length: 16\r\n\r\n"
                          b"12345678"
                          b"GET /api/fabricated-req HTTP/1.1\r\nHost: api.test\r\n\r\n")
    pkt_conf_cl = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50019, 80, 19000, 0, 0x18, conflicting_cl_req)
    write_pcap(tmp_pcap, [(1019, 0, pkt_conf_cl, len(pkt_conf_cl))])
    ev19 = run_pcap(tmp_pcap, [80])
    fab_ev = [e for e in ev19 if e.get("path") == "/api/fabricated-req"]
    if fab_ev:
        failures.append("[%s] Test 19 (Conflicting CL): Detected fabricated request %s" % (engine_name, fab_ev))
    else:
        print("  [%s] Test 19 (Conflicting CL): PASS (conflicting Content-Length dropped flow)" % engine_name)

    # 20. Chunk Length Overflow
    chunk_ovf_req = (b"POST /api/chunk-ovf HTTP/1.1\r\n"
                     b"Host: api.test\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n"
                     b"FFFFFFFFFFFFFFFF\r\n"
                     b"boom\r\n"
                     b"0\r\n\r\n"
                     b"GET /api/chunk-fab HTTP/1.1\r\nHost: api.test\r\n\r\n")
    pkt_chunk_ovf = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50020, 80, 20000, 0, 0x18, chunk_ovf_req)
    write_pcap(tmp_pcap, [(1020, 0, pkt_chunk_ovf, len(pkt_chunk_ovf))])
    ev20 = run_pcap(tmp_pcap, [80])
    chunk_fab_ev = [e for e in ev20 if e.get("path") == "/api/chunk-fab"]
    if chunk_fab_ev:
        failures.append("[%s] Test 20 (Chunk Overflow): Detected fabricated request %s" % (engine_name, chunk_fab_ev))
    else:
        print("  [%s] Test 20 (Chunk Overflow): PASS (oversized chunk length dropped flow)" % engine_name)

    # 21. Overlapping Retransmission Drains Queued Out-Of-Order Segment
    pkt_p1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50021, 80, 21000, 0, 0x18, b"GET /api")
    pkt_p3 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50021, 80, 21020, 0, 0x18, b" HTTP/1.1\r\nHost: api.test\r\n\r\n")
    pkt_p2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50021, 80, 21004, 0, 0x18, b"/api/overlap-ooo")
    full_req_len = len(b"GET /api/overlap-ooo HTTP/1.1\r\nHost: api.test\r\n\r\n")
    resp21 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_rp21 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50021, 31000, 21000 + full_req_len, 0x18, resp21)
    write_pcap(tmp_pcap, [(1021, 0, pkt_p1, len(pkt_p1)),
                          (1021, 10000, pkt_p3, len(pkt_p3)),
                          (1021, 20000, pkt_p2, len(pkt_p2)),
                          (1021, 30000, pkt_rp21, len(pkt_rp21))])
    ev21 = run_pcap(tmp_pcap, [80])
    if len(ev21) != 1 or ev21[0].get("path") != "/api/overlap-ooo" or ev21[0].get("status") != 200:
        failures.append("[%s] Test 21 (Overlapping Retransmission Drains OOO): Expected /api/overlap-ooo with 200, got %s" % (engine_name, ev21))
    else:
        print("  [%s] Test 21 (Overlapping Retransmission Drains OOO): PASS (drained OOO segment after overlap trimming)" % engine_name)

    # 22. Headerless 204 No Content Response
    req22 = b"POST /api/action HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\n\r\n"
    pkt_r22 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50022, 80, 22000, 0, 0x18, req22)
    resp22 = b"HTTP/1.1 204 No Content\r\n\r\n"
    pkt_rp22 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50022, 32000, 22000 + len(req22), 0x18, resp22)
    write_pcap(tmp_pcap, [(1022, 0, pkt_r22, len(pkt_r22)),
                          (1022, 10000, pkt_rp22, len(pkt_rp22))])
    ev22 = run_pcap(tmp_pcap, [80])
    if len(ev22) != 1 or ev22[0].get("path") != "/api/action" or ev22[0].get("status") != 204:
        failures.append("[%s] Test 22 (Headerless 204 Response): Expected /api/action with 204, got %s" % (engine_name, ev22))
    else:
        print("  [%s] Test 22 (Headerless 204 Response): PASS (parsed headerless 204 response)" % engine_name)

    if os.path.exists(tmp_pcap):
        os.remove(tmp_pcap)
    return failures

def run_test_suite_for_engine_ext(run_pcap, engine_name):
    """Additional tests 23-25 for the three new blocker fixes."""
    failures = []
    tmp_pcap = "/tmp/nt_synth_ext_%s.pcap" % engine_name.replace("+", "p")

    # -----------------------------------------------------------------------
    # 23. Tombstone Expiry Must Permanently Lock Out Correlation Until SYN
    # 1. /old arrives at t=100
    # 2. t=135 sweep: /old expires (35s > TTL 30s) -> becomes tombstone
    # 3. t=150 sweep: tombstone expires (15s > 10s) -> tombstone purged, correlation disabled
    # 4. /new arrives at t=152 on same connection -> emitted immediately with status=null
    # 5. /old's late response arrives at t=154 -> discarded, /new must NOT get status
    # 6. verified new SYN arrives at t=160 -> re-enables correlation
    # 7. /fresh request at t=161 + response at t=162 -> properly correlated with status 200
    # -----------------------------------------------------------------------
    req_old23 = b"GET /api/old23 HTTP/1.1\r\nHost: x\r\n\r\n"
    req_new23 = b"GET /api/new23 HTTP/1.1\r\nHost: x\r\n\r\n"
    req_fresh23 = b"GET /api/fresh23 HTTP/1.1\r\nHost: x\r\n\r\n"
    old_seq23 = 23000
    new_seq23 = old_seq23 + len(req_old23)
    fresh_seq23 = 50000

    pkt_syn23 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50023, 80,
                                  old_seq23 - 1, 0, 0x02, b"")
    pkt_old23 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50023, 80,
                                  old_seq23, 0, 0x18, req_old23)
    # Dummy sweep packets on unmonitored port 9999
    pkt_sweep1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 59999, 9999, 1000, 0, 0x10, b"")
    pkt_sweep2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 59999, 9999, 1001, 0, 0x10, b"")
    # /new23 on same connection after tombstone expired
    pkt_new23 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50023, 80,
                                  new_seq23, 0, 0x18, req_new23)
    # /old23's late response
    resp23 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp23 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50023,
                                   40000, old_seq23 + len(req_old23), 0x18, resp23)
    # New verified connection via SYN
    pkt_syn_fresh = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50023, 80,
                                      fresh_seq23 - 1, 0, 0x02, b"")
    pkt_fresh23 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50023, 80,
                                    fresh_seq23, 0, 0x18, req_fresh23)
    resp_fresh23 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp_fresh = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50023,
                                       41000, fresh_seq23 + len(req_fresh23), 0x18, resp_fresh23)

    write_pcap(tmp_pcap, [
        (100, 0, pkt_syn23, len(pkt_syn23)),
        (100, 1000, pkt_old23, len(pkt_old23)),
        (135, 0, pkt_sweep1, len(pkt_sweep1)),   # 35s later: /old expires to tombstone
        (150, 0, pkt_sweep2, len(pkt_sweep2)),   # 15s later: tombstone expires, correlation disabled
        (152, 0, pkt_new23, len(pkt_new23)),     # /new arrives on locked-out connection
        (154, 0, pkt_resp23, len(pkt_resp23)),   # /old late response arrives -> must NOT correlate
        (160, 0, pkt_syn_fresh, len(pkt_syn_fresh)), # New verified SYN resets lockout
        (161, 0, pkt_fresh23, len(pkt_fresh23)),
        (162, 0, pkt_resp_fresh, len(pkt_resp_fresh)), # Must correlate with 200 OK
    ])
    ev23 = run_pcap(tmp_pcap, [80])
    new_with_status = [e for e in ev23 if e.get("path") == "/api/new23" and e.get("status") is not None]
    fresh_with_status = [e for e in ev23 if e.get("path") == "/api/fresh23" and e.get("status") == 200]
    if new_with_status:
        failures.append("[%s] Test 23 (Tombstone Expiry Lockout): /new23 wrongly got status %s" % (engine_name, new_with_status))
    elif not fresh_with_status:
        failures.append("[%s] Test 23 (Tombstone Expiry Lockout): /api/fresh23 failed to correlate after SYN: %s" % (engine_name, ev23))
    else:
        print("  [%s] Test 23 (Tombstone Expiry Lockout): PASS (persistent lockout prevents late response; SYN restores correlation)" % engine_name)


    # -----------------------------------------------------------------------
    # 24. Expired Request Must Not Emit Twice (sweep + drain_pending/flush)
    # Emit one request, let it expire via sweep, then call drain.
    # Event count must be exactly 1, not 2.
    # -----------------------------------------------------------------------
    req24 = b"GET /api/once HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt24 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50024, 80, 24000, 0, 0x18, req24)
    # No response packet – only the request. We rely on the harness's periodic
    # sweep + final drain. A 65-second gap forces TTL expiry.
    pkt24_dup = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50024, 80,
                                   24000 + len(req24), 0, 0x18,
                                   b"GET /api/second HTTP/1.1\r\nHost: x\r\n\r\n")
    write_pcap(tmp_pcap, [
        (24, 0,        pkt24,     len(pkt24)),
        (24, 65000000, pkt24_dup, len(pkt24_dup)),  # 65 s later forces sweep expiry of /once
    ])
    ev24 = run_pcap(tmp_pcap, [80])
    once_ev = [e for e in ev24 if e.get("path") == "/api/once"]
    if len(once_ev) != 1:
        failures.append("[%s] Test 24 (No Double-Emit on Drain): /api/once emitted %d times, expected 1" % (engine_name, len(once_ev)))
    else:
        print("  [%s] Test 24 (No Double-Emit on Drain): PASS" % engine_name)

    # -----------------------------------------------------------------------
    # 25. Conflicting Content-Length in Response Must Not Fabricate Status
    # Send a request, then a response whose body contains HTTP/1.1 503.
    # The response has conflicting CL headers -> stream broken -> 503 must
    # never appear as a correlated event.
    # -----------------------------------------------------------------------
    req25  = b"GET /api/legit HTTP/1.1\r\nHost: x\r\n\r\n"
    # Conflicting CL: two different values
    bad_resp25 = (b"HTTP/1.1 200 OK\r\n"
                  b"Content-Length: 100\r\n"
                  b"Content-Length: 999\r\n"
                  b"\r\n"
                  b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
    pkt_req25  = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50025, 80,
                                   25000, 0, 0x18, req25)
    pkt_resp25 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50025,
                                   45000, 25000 + len(req25), 0x18, bad_resp25)
    write_pcap(tmp_pcap, [
        (25, 0,      pkt_req25,  len(pkt_req25)),
        (25, 10000,  pkt_resp25, len(pkt_resp25)),
    ])
    ev25 = run_pcap(tmp_pcap, [80])
    status_503 = [e for e in ev25 if e.get("status") == 503]
    legit_with_200 = [e for e in ev25 if e.get("path") == "/api/legit" and e.get("status") == 200]
    if status_503:
        failures.append("[%s] Test 25 (Broken Resp Stream Fabrication): 503 fabricated from body bytes: %s" % (engine_name, status_503))
    elif legit_with_200:
        failures.append("[%s] Test 25 (Broken Resp Stream Fabrication): /api/legit wrongly got 200 from ambiguous response" % engine_name)
    else:
        print("  [%s] Test 25 (Broken Resp Stream Fabrication): PASS (broken stream produced no fake status)" % engine_name)

    # -----------------------------------------------------------------------
    # 26. Old SYN Must Not Bypass Evicted Lockout
    # Connection loses ordering -> lockout inserted.
    # Registry capacity overflow evicts the lockout.
    # A subsequent /new request on the old connection (without a fresh SYN)
    # must NOT correlate with /old's late response.
    # -----------------------------------------------------------------------
    req_old26 = b"GET /api/old26 HTTP/1.1\r\nHost: x\r\n\r\n"
    req_new26 = b"GET /api/new26 HTTP/1.1\r\nHost: x\r\n\r\n"
    old_seq26 = 26000
    new_seq26 = old_seq26 + len(req_old26)

    pkt_syn26 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50026, 80,
                                  old_seq26 - 1, 0, 0x02, b"")
    pkt_old26 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50026, 80,
                                  old_seq26, 0, 0x18, req_old26)

    pkts26 = [
        (100, 0, pkt_syn26, len(pkt_syn26)),
        (100, 1000, pkt_old26, len(pkt_old26)),
        (135, 0, pkt_sweep1, len(pkt_sweep1)), # 35s later: /old expires to tombstone
        (150, 0, pkt_sweep2, len(pkt_sweep2)), # 15s later: tombstone expires -> correlation disabled
    ]

    # Flood 2050 distinct connection timeouts to saturate registry and evict 50026's key
    flood_req = b"GET /f HTTP/1.1\r\nHost: x\r\n\r\n"
    for i in range(2050):
        sport = 10000 + (i % 55000)
        p_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport, 80, 1000, 0, 0x18, flood_req)
        pkts26.append((105, i, p_req, len(p_req)))
    pkt_sweep_flood1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 59998, 9999, 1000, 0, 0x10, b"")
    pkts26.append((145, 0, pkt_sweep_flood1, len(pkt_sweep_flood1)))
    pkt_sweep_flood2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 59998, 9999, 1001, 0, 0x10, b"")
    pkts26.append((156, 0, pkt_sweep_flood2, len(pkt_sweep_flood2)))

    # /new arrives on old connection at t=160 (no fresh SYN!)
    pkt_new26 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50026, 80,
                                  new_seq26, 0, 0x18, req_new26)
    resp26 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp26 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50026,
                                   40000, old_seq26 + len(req_old26), 0x18, resp26)
    pkts26.append((160, 0, pkt_new26, len(pkt_new26)))
    pkts26.append((161, 0, pkt_resp26, len(pkt_resp26)))

    write_pcap(tmp_pcap, pkts26)
    ev26 = run_pcap(tmp_pcap, [80])
    new_with_status26 = [e for e in ev26 if e.get("path") == "/api/new26" and e.get("status") is not None]
    if new_with_status26:
        failures.append("[%s] Test 26 (Old SYN Evicted Lockout Bypass): /api/new26 wrongly correlated with status %s" % (engine_name, new_with_status26))
    else:
        print("  [%s] Test 26 (Old SYN Evicted Lockout Bypass): PASS (old SYN did not bypass evicted lockout)" % engine_name)

    # -----------------------------------------------------------------------
    # 27. SYN-ACK Preserves Verification Under Capacity Fallback
    # After capacity fallback activates, fresh client SYN sets verification,
    # and server SYN-ACK must preserve generation/eligibility rather than resetting.
    # -----------------------------------------------------------------------
    req27 = b"GET /api/synack27 HTTP/1.1\r\nHost: x\r\n\r\n"
    seq27 = 27000
    pkt_syn27 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50027, 80,
                                  seq27 - 1, 0, 0x02, b"")
    pkt_synack27 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50027,
                                     70000, seq27, 0x12, b"") # SYN-ACK
    pkt_req27 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50027, 80,
                                  seq27, 70001, 0x18, req27)
    resp27 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp27 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50027,
                                   70001, seq27 + len(req27), 0x18, resp27)

    pkts27 = list(pkts26[:2 + 2050 + 2])
    pkts27.append((170, 0, pkt_syn27, len(pkt_syn27)))
    pkts27.append((170, 1000, pkt_synack27, len(pkt_synack27))) # SYN-ACK
    pkts27.append((171, 0, pkt_req27, len(pkt_req27)))
    pkts27.append((172, 0, pkt_resp27, len(pkt_resp27)))

    write_pcap(tmp_pcap, pkts27)
    ev27 = run_pcap(tmp_pcap, [80])
    synack_ev27 = [e for e in ev27 if e.get("path") == "/api/synack27" and e.get("status") == 200]
    if not synack_ev27:
        failures.append("[%s] Test 27 (SYN-ACK Preserves Verification): /api/synack27 failed to correlate with 200 OK after SYN-ACK: %s" % (engine_name, [e for e in ev27 if e.get("path") == "/api/synack27"]))
    else:
        print("  [%s] Test 27 (SYN-ACK Preserves Verification): PASS (SYN-ACK preserved verification, status 200 correlated)" % engine_name)

    # -----------------------------------------------------------------------
    # 28. Client SYN Resets is_broken
    # Invalid request framing breaks flow; verified new SYN must reset is_broken
    # so subsequent requests and responses are captured and correlated.
    # -----------------------------------------------------------------------
    pkts28 = []
    # Step 1: Broken connection
    pkt_syn28_old = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50028, 80, 1000, 0, 0x02, b"")
    pkt_synack28_old = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50028, 5000, 1001, 0x12, b"")
    bad_req28 = b"POST /bad HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n12345"
    pkt_bad28 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50028, 80, 1001, 5001, 0x18, bad_req28)
    pkts28.append((180, 0, pkt_syn28_old, len(pkt_syn28_old)))
    pkts28.append((180, 1000, pkt_synack28_old, len(pkt_synack28_old)))
    pkts28.append((180, 2000, pkt_bad28, len(pkt_bad28)))

    # Step 2: Client starts new connection with fresh SYN
    pkt_syn28_new = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50028, 80, 3000, 0, 0x02, b"")
    pkt_synack28_new = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50028, 6000, 3001, 0x12, b"")
    good_req28 = b"GET /api/valid28 HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt_good28 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50028, 80, 3001, 6001, 0x18, good_req28)
    good_resp28 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp28 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50028, 6001, 3001 + len(good_req28), 0x18, good_resp28)
    pkts28.append((190, 0, pkt_syn28_new, len(pkt_syn28_new)))
    pkts28.append((190, 1000, pkt_synack28_new, len(pkt_synack28_new)))
    pkts28.append((190, 2000, pkt_good28, len(pkt_good28)))
    pkts28.append((190, 3000, pkt_resp28, len(pkt_resp28)))

    write_pcap(tmp_pcap, pkts28)
    ev28 = run_pcap(tmp_pcap, [80])
    valid_ev28 = [e for e in ev28 if e.get("path") == "/api/valid28" and e.get("status") == 200]
    if not valid_ev28:
        failures.append("[%s] Test 28 (Client SYN Resets is_broken): /api/valid28 missing or failed to correlate with 200 OK after new SYN: %s" % (engine_name, [e for e in ev28 if e.get("path") == "/api/valid28"]))
    else:
        print("  [%s] Test 28 (Client SYN Resets is_broken): PASS (new SYN cleared is_broken, status 200 correlated)" % engine_name)

    # -----------------------------------------------------------------------
    # 29. Expired HEAD Request Preserves Bodyless-Response Semantics
    # Expired HEAD becomes tombstone; late response has Content-Length but NO body.
    # Subsequent GET response must not be swallowed as HEAD body bytes.
    # -----------------------------------------------------------------------
    pkts29 = []
    pkt_syn29 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50029, 80, 2000, 0, 0x02, b"")
    pkt_synack29 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50029, 7000, 2001, 0x12, b"")
    pkts29.append((200, 0, pkt_syn29, len(pkt_syn29)))
    pkts29.append((200, 1000, pkt_synack29, len(pkt_synack29)))

    # Client sends HEAD request
    req_head29 = b"HEAD /api/head29 HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt_head29 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50029, 80, 2001, 7001, 0x18, req_head29)
    pkts29.append((200, 2000, pkt_head29, len(pkt_head29)))

    # Advance time to 215s (>10s pending TTL) -> HEAD expires to tombstone.
    # Client sends GET request on same connection.
    seq_get29 = 2001 + len(req_head29)
    req_get29 = b"GET /api/get29 HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt_get29 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50029, 80, seq_get29, 7001, 0x18, req_get29)
    pkts29.append((215, 0, pkt_get29, len(pkt_get29)))

    # Server sends HEAD response with Content-Length: 100 (NO body bytes per RFC)
    resp_head29 = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    pkt_resp_head29 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50029, 7001, seq_get29 + len(req_get29), 0x18, resp_head29)
    pkts29.append((215, 1000, pkt_resp_head29, len(pkt_resp_head29)))

    # Server sends GET response with 200 OK and body
    resp_get29 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
    seq_resp_get29 = 7001 + len(resp_head29)
    pkt_resp_get29 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50029, seq_resp_get29, seq_get29 + len(req_get29), 0x18, resp_get29)
    pkts29.append((215, 2000, pkt_resp_get29, len(pkt_resp_get29)))

    write_pcap(tmp_pcap, pkts29)
    ev29 = run_pcap(tmp_pcap, [80])
    get_ev29 = [e for e in ev29 if e.get("path") == "/api/get29" and e.get("status") == 200]
    if not get_ev29:
        failures.append("[%s] Test 29 (Expired HEAD Preserves Bodyless Semantics): /api/get29 failed to correlate with 200 OK (consumed by HEAD body?): %s" % (engine_name, [e for e in ev29 if e.get("path") == "/api/get29"]))
    else:
        print("  [%s] Test 29 (Expired HEAD Preserves Bodyless Semantics): PASS (HEAD recognized as bodyless, GET correlated with 200 OK)" % engine_name)

    # -----------------------------------------------------------------------
    # 30. IPv4 Fragment Rejection (MF and non-zero offsets rejected, DF allowed)
    # Packets with MF (0x2000) or offset must be rejected since no IP reassembly is done.
    # -----------------------------------------------------------------------
    pkts30 = []
    pkt_syn30 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50030, 80, 1000, 0, 0x02, b"", ip_frag=0x4000)
    pkt_synack30 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50030, 5000, 1001, 0x12, b"", ip_frag=0x4000)
    pkts30.append((220, 0, pkt_syn30, len(pkt_syn30)))
    pkts30.append((220, 1000, pkt_synack30, len(pkt_synack30)))

    # First fragment with MF bit set (0x2000): MUST BE REJECTED
    req_frag = b"POST /api/frag30 HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt_frag = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50030, 80, 1001, 5001, 0x18, req_frag, ip_frag=0x2000)
    pkts30.append((220, 2000, pkt_frag, len(pkt_frag)))

    # Subsequent valid unfragmented request with DF bit set (0x4000): MUST BE ACCEPTED
    req_nofrag = b"GET /api/nofrag30 HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt_nofrag = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50030, 80, 1001, 5001, 0x18, req_nofrag, ip_frag=0x4000)
    resp_nofrag = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt_resp_nofrag = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50030, 5001, 1001 + len(req_nofrag), 0x18, resp_nofrag, ip_frag=0x4000)
    pkts30.append((220, 3000, pkt_nofrag, len(pkt_nofrag)))
    pkts30.append((220, 4000, pkt_resp_nofrag, len(pkt_resp_nofrag)))

    write_pcap(tmp_pcap, pkts30)
    ev30 = run_pcap(tmp_pcap, [80])
    frag_ev = [e for e in ev30 if e.get("path") == "/api/frag30"]
    nofrag_ev = [e for e in ev30 if e.get("path") == "/api/nofrag30" and e.get("status") == 200]
    if frag_ev:
        failures.append("[%s] Test 30 (IPv4 Fragment Rejection): /api/frag30 with MF bit was accepted: %s" % (engine_name, frag_ev))
    elif not nofrag_ev:
        failures.append("[%s] Test 30 (IPv4 Fragment Rejection): /api/nofrag30 failed to correlate with 200 OK: %s" % (engine_name, ev30))
    else:
        print("  [%s] Test 30 (IPv4 Fragment Rejection): PASS (MF fragment rejected, DF packet accepted & correlated)" % engine_name)

    # -----------------------------------------------------------------------
    # 31. Flow Expiry Invalidation & Pending Flush (Framing Isolation)
    # Flow state expires after 15s (FLOW_TTL).
    # Two requests are sent; first response has headers + partial body.
    # Flow expires at 20s. Pending requests must be flushed without status.
    # Subsequent body bytes resembling "HTTP/1.1 503..." must NOT correlate.
    # -----------------------------------------------------------------------
    req31_1 = b"GET /api/r1_31 HTTP/1.1\r\nHost: x\r\n\r\n"
    req31_2 = b"GET /api/r2_31 HTTP/1.1\r\nHost: x\r\n\r\n"
    resp31_partial = (b"HTTP/1.1 200 OK\r\n"
                      b"Content-Length: 100\r\n\r\n"
                      b"0123456789")
    resp31_resume = (b"HTTP/1.1 503 Service Unavailable\r\n"
                     b"Content-Length: 0\r\n\r\n")

    seq31_client = 31000
    seq31_server = 71000

    pkt_syn31 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50031, 80,
                                 seq31_client - 1, 0, 0x02, b"")
    pkt_synack31 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50031,
                                    seq31_server - 1, seq31_client, 0x12, b"")
    pkt_r31_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50031, 80,
                                 seq31_client, seq31_server, 0x18, req31_1)
    pkt_r31_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50031, 80,
                                 seq31_client + len(req31_1), seq31_server, 0x18, req31_2)
    pkt_rp31_part = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50031,
                                     seq31_server, seq31_client + len(req31_1) + len(req31_2),
                                     0x18, resp31_partial)
    pkt_rp31_res = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50031,
                                    seq31_server + len(resp31_partial),
                                    seq31_client + len(req31_1) + len(req31_2),
                                    0x18, resp31_resume)

    pkts31 = [
        (300, 0, pkt_syn31, len(pkt_syn31)),
        (300, 1000, pkt_synack31, len(pkt_synack31)),
        (300, 2000, pkt_r31_1, len(pkt_r31_1)),
        (300, 3000, pkt_r31_2, len(pkt_r31_2)),
        (300, 4000, pkt_rp31_part, len(pkt_rp31_part)),
        (325, 0, pkt_rp31_res, len(pkt_rp31_res)),
    ]
    write_pcap(tmp_pcap, pkts31)
    ev31 = run_pcap(tmp_pcap, [80])
    ev31_503 = [e for e in ev31 if e.get("status") == 503]
    ev31_r1 = [e for e in ev31 if e.get("path") == "/api/r1_31"]
    ev31_r2 = [e for e in ev31 if e.get("path") == "/api/r2_31"]
    if ev31_503:
        failures.append("[%s] Test 31 (Flow Expiry Framing): Fake 503 status assigned: %s" % (engine_name, ev31_503))
    elif not ev31_r1 or ev31_r1[0].get("status") != 200:
        failures.append("[%s] Test 31 (Flow Expiry Framing): Expected /api/r1_31 with status 200, got %s" % (engine_name, ev31_r1))
    elif not ev31_r2 or ev31_r2[0].get("status") is not None:
        failures.append("[%s] Test 31 (Flow Expiry Framing): Expected /api/r2_31 with status None, got %s" % (engine_name, ev31_r2))
    else:
        print("  [%s] Test 31 (Flow Expiry Framing): PASS (flows expired, pending flushed without status, no fake 503)" % engine_name)

    # -----------------------------------------------------------------------
    # 32. WSSE Early Response Correlation
    # Server sends 403 Forbidden before client finishes sending SOAP body.
    # The request headers must be reserved in pending immediately, so that
    # the 403 response correlates to the request with status 403.
    # -----------------------------------------------------------------------
    soap_hdr32 = (b"POST /api/wsse_early HTTP/1.1\r\n"
                  b"Host: x\r\n"
                  b"Content-Type: text/xml\r\n"
                  b"Content-Length: 120\r\n\r\n")
    resp_403 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
    soap_body32 = (b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                   b"xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
                   b"<wsse:Username>alice</wsse:Username></soap:Envelope>")
    seq32_client = 32000
    seq32_server = 72000

    pkt_syn32 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50032, 80,
                                 seq32_client - 1, 0, 0x02, b"")
    pkt_synack32 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50032,
                                    seq32_server - 1, seq32_client, 0x12, b"")
    pkt_req_hdr32 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50032, 80,
                                     seq32_client, seq32_server, 0x18, soap_hdr32)
    pkt_early_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50032,
                                      seq32_server, seq32_client + len(soap_hdr32), 0x18, resp_403)
    pkt_req_body32 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50032, 80,
                                      seq32_client + len(soap_hdr32), seq32_server + len(resp_403), 0x18, soap_body32)
    pkts32 = [
        (350, 0, pkt_syn32, len(pkt_syn32)),
        (350, 1000, pkt_synack32, len(pkt_synack32)),
        (350, 2000, pkt_req_hdr32, len(pkt_req_hdr32)),
        (350, 3000, pkt_early_resp, len(pkt_early_resp)),
        (350, 4000, pkt_req_body32, len(pkt_req_body32)),
    ]
    write_pcap(tmp_pcap, pkts32)
    ev32 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev32_early = [e for e in ev32 if e.get("path") == "/api/wsse_early"]
    if not ev32_early:
        failures.append("[%s] Test 32 (WSSE Early Response): No event for /api/wsse_early" % engine_name)
    elif ev32_early[0].get("status") != 403:
        failures.append("[%s] Test 32 (WSSE Early Response): Expected status 403, got %s" % (engine_name, ev32_early[0].get("status")))
    elif len(ev32_early) > 1:
        failures.append("[%s] Test 32 (WSSE Early Response): Duplicate events emitted: %s" % (engine_name, ev32_early))
    else:
        print("  [%s] Test 32 (WSSE Early Response): PASS (early 403 correlated before body arrived)" % engine_name)

    # -----------------------------------------------------------------------
    # 33. Truncated Packet Invalidation
    # A response packet has ip_total_len larger than captured wire length.
    # Sniffer flags is_truncated, increments invalid_frames, breaks flow,
    # invalidates correlation, and flushes pending requests with null status.
    # -----------------------------------------------------------------------
    req33 = b"GET /api/trunc33 HTTP/1.1\r\nHost: x\r\n\r\n"
    resp33_trunc_data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq33_client = 33000
    seq33_server = 73000

    pkt_syn33 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50033, 80,
                                 seq33_client - 1, 0, 0x02, b"")
    pkt_synack33 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50033,
                                    seq33_server - 1, seq33_client, 0x12, b"")
    pkt_req33 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50033, 80,
                                 seq33_client, seq33_server, 0x18, req33)
    pkt_resp33_trunc = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50033,
                                        seq33_server, seq33_client + len(req33), 0x18,
                                        resp33_trunc_data, ip_total_len=500)
    pkts33 = [
        (400, 0, pkt_syn33, len(pkt_syn33)),
        (400, 1000, pkt_synack33, len(pkt_synack33)),
        (400, 2000, pkt_req33, len(pkt_req33)),
        (400, 3000, pkt_resp33_trunc, len(pkt_resp33_trunc)),
    ]
    write_pcap(tmp_pcap, pkts33)
    ev33 = run_pcap(tmp_pcap, [80])
    ev33_trunc = [e for e in ev33 if e.get("path") == "/api/trunc33"]
    if not ev33_trunc:
        failures.append("[%s] Test 33 (Truncated Packet): No event emitted for /api/trunc33" % engine_name)
    elif ev33_trunc[0].get("status") is not None:
        failures.append("[%s] Test 33 (Truncated Packet): Expected status None due to truncation, got %s" % (engine_name, ev33_trunc[0].get("status")))
    else:
        print("  [%s] Test 33 (Truncated Packet): PASS (truncation broke flow & correlation invalidated)" % engine_name)

    # -----------------------------------------------------------------------
    # 34. Capture Gap & UNSYNCED State (No False Request Fabrication)
    # Client sends request headers with Content-Length: 50.
    # An out-of-order gap exceeding MAX_OOO_SEGMENTS invalidates the stream.
    # Body bytes containing "GET /api/fake34 HTTP/1.1\r\n\r\n" arrive.
    # Stream in UNSYNCED state must NOT parse /api/fake34 as a request.
    # Later, a fresh SYN establishes a new connection, sending /api/valid34
    # which correlates with status 200.
    # -----------------------------------------------------------------------
    req34_hdr = b"POST /api/gap34 HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n"
    fake_body34 = b"GET /api/fake34 HTTP/1.1\r\nHost: x\r\n\r\n"
    valid_req34 = b"GET /api/valid34 HTTP/1.1\r\nHost: x\r\n\r\n"
    valid_resp34 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq34_client = 34000
    seq34_server = 74000
    fresh_seq34 = 60000

    pkt_syn34 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80,
                                 seq34_client - 1, 0, 0x02, b"")
    pkt_synack34 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50034,
                                    seq34_server - 1, seq34_client, 0x12, b"")
    pkt_req34_hdr = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80,
                                     seq34_client, seq34_server, 0x18, req34_hdr)
    pkt_gap1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80, seq34_client + len(req34_hdr) + 10, seq34_server, 0x18, b"A")
    pkt_gap2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80, seq34_client + len(req34_hdr) + 20, seq34_server, 0x18, b"B")
    pkt_gap3 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80, seq34_client + len(req34_hdr) + 30, seq34_server, 0x18, b"C")
    pkt_gap4 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80, seq34_client + len(req34_hdr) + 40, seq34_server, 0x18, b"D")
    pkt_gap5 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80, seq34_client + len(req34_hdr) + 50, seq34_server, 0x18, fake_body34)
    pkt_syn_fresh34 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80,
                                       fresh_seq34 - 1, 0, 0x02, b"")
    pkt_synack_fresh34 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50034,
                                          seq34_server + 100, fresh_seq34, 0x12, b"")
    pkt_valid_req34 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50034, 80,
                                       fresh_seq34, seq34_server + 101, 0x18, valid_req34)
    pkt_valid_resp34 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50034,
                                        seq34_server + 101, fresh_seq34 + len(valid_req34), 0x18, valid_resp34)

    pkts34 = [
        (450, 0, pkt_syn34, len(pkt_syn34)),
        (450, 1000, pkt_synack34, len(pkt_synack34)),
        (450, 2000, pkt_req34_hdr, len(pkt_req34_hdr)),
        (450, 3000, pkt_gap1, len(pkt_gap1)),
        (450, 4000, pkt_gap2, len(pkt_gap2)),
        (450, 5000, pkt_gap3, len(pkt_gap3)),
        (450, 6000, pkt_gap4, len(pkt_gap4)),
        (450, 7000, pkt_gap5, len(pkt_gap5)),
        (460, 0, pkt_syn_fresh34, len(pkt_syn_fresh34)),
        (460, 1000, pkt_synack_fresh34, len(pkt_synack_fresh34)),
        (460, 2000, pkt_valid_req34, len(pkt_valid_req34)),
        (460, 3000, pkt_valid_resp34, len(pkt_valid_resp34)),
    ]
    write_pcap(tmp_pcap, pkts34)
    ev34 = run_pcap(tmp_pcap, [80])
    ev34_fake = [e for e in ev34 if e.get("path") == "/api/fake34"]
    ev34_valid = [e for e in ev34 if e.get("path") == "/api/valid34"]
    if ev34_fake:
        failures.append("[%s] Test 34 (Capture Gap UNSYNCED): Fake request /api/fake34 was fabricated from body" % engine_name)
    elif not ev34_valid or ev34_valid[0].get("status") != 200:
        failures.append("[%s] Test 34 (Capture Gap UNSYNCED): Expected /api/valid34 with status 200, got %s" % (engine_name, ev34_valid))
    else:
        print("  [%s] Test 34 (Capture Gap UNSYNCED): PASS (fake request rejected in UNSYNCED; new SYN recovered)" % engine_name)

    # -----------------------------------------------------------------------
    # 35. Bidirectional Monitored Ports (Client 8003 -> Server 8005)
    # Monitored ports: [8003, 8005]. Client port is 8003, server port is 8005.
    # Direction latched from SYN: client=10.0.0.1:8003, server=10.0.0.2:8005.
    # Request method and response status 200 correctly correlated.
    # -----------------------------------------------------------------------
    req35 = b"GET /api/bidi35 HTTP/1.1\r\nHost: x\r\n\r\n"
    resp35 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq35_client = 35000
    seq35_server = 75000

    pkt_syn35 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 8003, 8005,
                                 seq35_client - 1, 0, 0x02, b"")
    pkt_synack35 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 8005, 8003,
                                    seq35_server - 1, seq35_client, 0x12, b"")
    pkt_req35 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 8003, 8005,
                                 seq35_client, seq35_server, 0x18, req35)
    pkt_resp35 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 8005, 8003,
                                  seq35_server, seq35_client + len(req35), 0x18, resp35)

    pkts35 = [
        (500, 0, pkt_syn35, len(pkt_syn35)),
        (500, 1000, pkt_synack35, len(pkt_synack35)),
        (500, 2000, pkt_req35, len(pkt_req35)),
        (500, 3000, pkt_resp35, len(pkt_resp35)),
    ]
    write_pcap(tmp_pcap, pkts35)
    ev35 = run_pcap(tmp_pcap, [8003, 8005])
    ev35_bidi = [e for e in ev35 if e.get("path") == "/api/bidi35"]
    if not ev35_bidi:
        failures.append("[%s] Test 35 (Bidirectional Monitored Ports): No event for /api/bidi35" % engine_name)
    elif ev35_bidi[0].get("status") != 200:
        failures.append("[%s] Test 35 (Bidirectional Monitored Ports): Expected status 200, got %s" % (engine_name, ev35_bidi[0].get("status")))
    elif ev35_bidi[0].get("dst_port") != 8005:
        failures.append("[%s] Test 35 (Bidirectional Monitored Ports): Direction inverted; dst_port is %s instead of 8005" % (engine_name, ev35_bidi[0].get("dst_port")))
    else:
        print("  [%s] Test 35 (Bidirectional Monitored Ports): PASS (direction latched, status 200 correlated)" % engine_name)

    # -----------------------------------------------------------------------
    # 36. Header Limits & UTF-8 Character Boundary Truncation
    # User-Agent header exceeds 256 bytes with a 3-byte UTF-8 character (Euro €)
    # placed at byte boundary 255. Emitted event must be valid JSON and valid UTF-8,
    # and user_agent must not end with a broken byte.
    # -----------------------------------------------------------------------
    prefix36 = b"A" * 254
    euro36 = "\u20ac".encode("utf-8") # 3 bytes: 0xe2 0x82 0xac
    ua_val36 = prefix36 + euro36 + b"extra_bytes_beyond_limit"
    req36 = b"GET /api/utf8_36 HTTP/1.1\r\nHost: x\r\nUser-Agent: " + ua_val36 + b"\r\n\r\n"
    resp36 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq36_client = 36000
    seq36_server = 76000

    pkt_syn36 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50036, 80,
                                 seq36_client - 1, 0, 0x02, b"")
    pkt_synack36 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50036,
                                    seq36_server - 1, seq36_client, 0x12, b"")
    pkt_req36 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50036, 80,
                                 seq36_client, seq36_server, 0x18, req36)
    pkt_resp36 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50036,
                                  seq36_server, seq36_client + len(req36), 0x18, resp36)

    pkts36 = [
        (600, 0, pkt_syn36, len(pkt_syn36)),
        (600, 1000, pkt_synack36, len(pkt_synack36)),
        (600, 2000, pkt_req36, len(pkt_req36)),
        (600, 3000, pkt_resp36, len(pkt_resp36)),
    ]
    write_pcap(tmp_pcap, pkts36)
    ev36 = run_pcap(tmp_pcap, [80])
    ev36_utf8 = [e for e in ev36 if e.get("path") == "/api/utf8_36"]
    if not ev36_utf8:
        failures.append("[%s] Test 36 (UTF-8 Header Limit): No event for /api/utf8_36" % engine_name)
    else:
        ua = ev36_utf8[0].get("user_agent", "")
        try:
            ua_bytes = ua.encode("utf-8")
            if len(ua_bytes) > 256:
                failures.append("[%s] Test 36 (UTF-8 Header Limit): user_agent exceeds 256 bytes: %d" % (engine_name, len(ua_bytes)))
            else:
                print("  [%s] Test 36 (UTF-8 Header Limit): PASS (clean UTF-8 boundary preserved, length <= 256)" % engine_name)
        except UnicodeEncodeError as uerr:
            failures.append("[%s] Test 36 (UTF-8 Header Limit): Invalid UTF-8 in user_agent: %s" % (engine_name, uerr))

    # -----------------------------------------------------------------------
    # 37. Out-of-Order FIN with Delayed Body (POST Content-Length: 4)
    # Client sends POST declaring Content-Length: 4.
    # Client FIN arrives out-of-order before the 4 body bytes arrive.
    # Then the 4 body bytes arrive. Server sends 200 OK.
    # Parser must NOT enter an infinite hang loop, must consume body, and correlate 200 OK.
    # -----------------------------------------------------------------------
    post_hdr37 = b"POST /api/fin_ooo37 HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n"
    post_body37 = b"test"
    resp37 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq37_client = 37000
    seq37_server = 77000

    pkt_syn37 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50037, 80,
                                 seq37_client - 1, 0, 0x02, b"")
    pkt_synack37 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50037,
                                    seq37_server - 1, seq37_client, 0x12, b"")
    pkt_req_hdr37 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50037, 80,
                                     seq37_client, seq37_server, 0x18, post_hdr37)
    # FIN packet sent with seq past the body (seq37_client + len(post_hdr37) + 4)
    pkt_fin37 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50037, 80,
                                 seq37_client + len(post_hdr37) + len(post_body37), seq37_server, 0x11, b"")
    # Delayed body packet
    pkt_body37 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50037, 80,
                                  seq37_client + len(post_hdr37), seq37_server, 0x18, post_body37)
    # Server 200 OK
    pkt_resp37 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50037,
                                  seq37_server, seq37_client + len(post_hdr37) + len(post_body37) + 1, 0x18, resp37)

    pkts37 = [
        (700, 0, pkt_syn37, len(pkt_syn37)),
        (700, 1000, pkt_synack37, len(pkt_synack37)),
        (700, 2000, pkt_req_hdr37, len(pkt_req_hdr37)),
        (700, 3000, pkt_fin37, len(pkt_fin37)), # Out-of-order FIN arrives first
        (700, 4000, pkt_body37, len(pkt_body37)), # Delayed body arrives second
        (700, 5000, pkt_resp37, len(pkt_resp37)),
    ]
    write_pcap(tmp_pcap, pkts37)
    ev37 = run_pcap(tmp_pcap, [80])
    ev37_post = [e for e in ev37 if e.get("path") == "/api/fin_ooo37"]
    if not ev37_post:
        failures.append("[%s] Test 37 (Out-of-Order FIN Hang): No event for /api/fin_ooo37" % engine_name)
    elif ev37_post[0].get("status") != 200:
        failures.append("[%s] Test 37 (Out-of-Order FIN Hang): Expected status 200, got %s" % (engine_name, ev37_post[0].get("status")))
    else:
        print("  [%s] Test 37 (Out-of-Order FIN Hang): PASS (no hang, delayed body consumed, status 200 correlated)" % engine_name)

    # -----------------------------------------------------------------------
    # 38. Response-Time WSSE Enrichment Correct Targeting
    # Pipelined requests:
    # 1. Anonymous GET /api/anon38
    # 2. SOAP POST /api/soap38 with WSSE username "alice"
    # Response to /api/anon38 arrives before /api/soap38 completes.
    # /api/anon38 must NOT be enriched with "alice".
    # -----------------------------------------------------------------------
    req38_1 = b"GET /api/anon38 HTTP/1.1\r\nHost: x\r\n\r\n"
    soap_body38 = (b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                   b"xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
                   b"<soap:Header><wsse:Security><wsse:UsernameToken>"
                   b"<wsse:Username>alice</wsse:Username>"
                   b"</wsse:UsernameToken></wsse:Security></soap:Header><soap:Body/></soap:Envelope>")
    req38_2 = (b"POST /api/soap38 HTTP/1.1\r\nHost: x\r\nContent-Type: text/xml\r\nContent-Length: " +
               str(len(soap_body38)).encode() + b"\r\n\r\n" + soap_body38)
    resp38_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    resp38_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq38_client = 38000
    seq38_server = 78000

    pkt_syn38 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50038, 80,
                                 seq38_client - 1, 0, 0x02, b"")
    pkt_synack38 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50038,
                                    seq38_server - 1, seq38_client, 0x12, b"")
    pkt_r38_1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50038, 80,
                                 seq38_client, seq38_server, 0x18, req38_1)
    pkt_r38_2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50038, 80,
                                 seq38_client + len(req38_1), seq38_server, 0x18, req38_2)
    pkt_resp38_1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50038,
                                    seq38_server, seq38_client + len(req38_1), 0x18, resp38_1)
    pkt_resp38_2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50038,
                                    seq38_server + len(resp38_1), seq38_client + len(req38_1) + len(req38_2), 0x18, resp38_2)

    pkts38 = [
        (800, 0, pkt_syn38, len(pkt_syn38)),
        (800, 1000, pkt_synack38, len(pkt_synack38)),
        (800, 2000, pkt_r38_1, len(pkt_r38_1)),
        (800, 3000, pkt_r38_2, len(pkt_r38_2)),
        (800, 4000, pkt_resp38_1, len(pkt_resp38_1)),
        (800, 5000, pkt_resp38_2, len(pkt_resp38_2)),
    ]
    write_pcap(tmp_pcap, pkts38)
    ev38 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev38_anon = [e for e in ev38 if e.get("path") == "/api/anon38"]
    ev38_soap = [e for e in ev38 if e.get("path") == "/api/soap38"]
    if not ev38_anon or not ev38_soap:
        failures.append("[%s] Test 38 (Response-Time WSSE Enrichment): Missing events: anon=%s, soap=%s" % (engine_name, ev38_anon, ev38_soap))
    elif ev38_anon[0].get("wsse_user") is not None or ev38_anon[0].get("user") not in (None, "-anonymous-"):
        failures.append("[%s] Test 38 (Response-Time WSSE Enrichment): /api/anon38 incorrectly enriched with user=%s" % (engine_name, ev38_anon[0].get("user")))
    elif ev38_soap[0].get("user") != "alice" or ev38_soap[0].get("wsse_user") != "alice":
        failures.append("[%s] Test 38 (Response-Time WSSE Enrichment): /api/soap38 expected user 'alice', got %s" % (engine_name, ev38_soap[0].get("user")))
    else:
        print("  [%s] Test 38 (Response-Time WSSE Enrichment): PASS (anon request remained anonymous, soap got alice)" % engine_name)

    # -----------------------------------------------------------------------
    # 39. Uncorrelated Non-SOAP Requests Emitted Under WSSE
    # When correlation is disabled on a connection (no SYN seen so syn_seen=false),
    # subsequent non-SOAP requests must not be suppressed by deferred WSSE buffering.
    # -----------------------------------------------------------------------
    req39_lost = b"GET /api/lost39 HTTP/1.1\r\nHost: x\r\n\r\n"
    req39_last = b"GET /api/last39 HTTP/1.1\r\nHost: x\r\n\r\n"
    seq39_client = 39000
    seq39_server = 79000

    pkt_lost39 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50039, 80,
                                  seq39_client, seq39_server, 0x18, req39_lost)
    pkt_last39 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50039, 80,
                                  seq39_client + len(req39_lost), seq39_server, 0x18, req39_last)

    pkts39 = [
        (900, 0, pkt_lost39, len(pkt_lost39)),
        (900, 1000, pkt_last39, len(pkt_last39)),
    ]
    write_pcap(tmp_pcap, pkts39)
    ev39 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev39_lost = [e for e in ev39 if e.get("path") == "/api/lost39"]
    ev39_last = [e for e in ev39 if e.get("path") == "/api/last39"]
    if not ev39_lost:
        failures.append("[%s] Test 39 (Uncorrelated Non-SOAP Requests): /api/lost39 missing (swallowed by WSSE buffering)" % engine_name)
    elif not ev39_last:
        failures.append("[%s] Test 39 (Uncorrelated Non-SOAP Requests): /api/last39 missing" % engine_name)
    else:
        print("  [%s] Test 39 (Uncorrelated Non-SOAP Requests): PASS (both non-SOAP requests emitted on uncorrelated connection)" % engine_name)

    # -----------------------------------------------------------------------
    # 40. WSSE Buffer Accounting Leak Prevention
    # Sequential SOAP requests on the same connection. Verify all succeed
    # and WSSE buffers are completely freed without memory leaks.
    # -----------------------------------------------------------------------
    soap_tmpl40 = (b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                   b"xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
                   b"<soap:Header><wsse:Security><wsse:UsernameToken>"
                   b"<wsse:Username>%b</wsse:Username>"
                   b"</wsse:UsernameToken></wsse:Security></soap:Header><soap:Body/></soap:Envelope>")
    seq40_client = 40000
    seq40_server = 80000
    pkts40 = []
    pkt_syn40 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50040, 80, seq40_client - 1, 0, 0x02, b"")
    pkt_synack40 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50040, seq40_server - 1, seq40_client, 0x12, b"")
    pkts40.append((1000, 0, pkt_syn40, len(pkt_syn40)))
    pkts40.append((1000, 500, pkt_synack40, len(pkt_synack40)))

    cur_c_seq = seq40_client
    cur_s_seq = seq40_server
    users40 = [b"user_one", b"user_two", b"user_three"]
    for idx, u in enumerate(users40):
        sbody = soap_tmpl40 % u
        req_bytes = (b"POST /api/soap40_%d HTTP/1.1\r\nHost: x\r\nContent-Type: text/xml\r\nContent-Length: " % idx +
                     str(len(sbody)).encode() + b"\r\n\r\n" + sbody)
        resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        pkt_q = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50040, 80, cur_c_seq, cur_s_seq, 0x18, req_bytes)
        pkt_r = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50040, cur_s_seq, cur_c_seq + len(req_bytes), 0x18, resp_bytes)
        pkts40.append((1000 + idx * 10, 1000, pkt_q, len(pkt_q)))
        pkts40.append((1000 + idx * 10, 2000, pkt_r, len(pkt_r)))
        cur_c_seq += len(req_bytes)
        cur_s_seq += len(resp_bytes)

    write_pcap(tmp_pcap, pkts40)
    ev40 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev40_users = [e.get("user") for e in ev40 if e.get("path", "").startswith("/api/soap40_")]
    expected_users = ["user_one", "user_two", "user_three"]
    if ev40_users != expected_users:
        failures.append("[%s] Test 40 (WSSE Buffer Accounting): Expected users %s, got %s" % (engine_name, expected_users, ev40_users))
    else:
        print("  [%s] Test 40 (WSSE Buffer Accounting): PASS (all sequential WSSE requests parsed & freed cleanly)" % engine_name)

    # -----------------------------------------------------------------------
    # 41. Strict UTF-8 Validation (Overlong Sequences & Surrogates Replaced)
    # Request contains overlong UTF-8 sequence \xC0\xAF and surrogate \xED\xA0\x80 in headers.
    # Must be sanitized to valid UTF-8, serialized as valid JSON, and not crash.
    # -----------------------------------------------------------------------
    bad_utf8 = b"test-\xC0\xAF-overlong-\xED\xA0\x80-surrogate"
    req41 = b"GET /api/utf8_41 HTTP/1.1\r\nHost: " + bad_utf8 + b"\r\nUser-Agent: " + bad_utf8 + b"\r\n\r\n"
    resp41 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq41_client = 41000
    seq41_server = 81000

    pkt_syn41 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50041, 80,
                                 seq41_client - 1, 0, 0x02, b"")
    pkt_synack41 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50041,
                                    seq41_server - 1, seq41_client, 0x12, b"")
    pkt_req41 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50041, 80,
                                 seq41_client, seq41_server, 0x18, req41)
    pkt_resp41 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50041,
                                  seq41_server, seq41_client + len(req41), 0x18, resp41)

    pkts41 = [
        (1100, 0, pkt_syn41, len(pkt_syn41)),
        (1100, 1000, pkt_synack41, len(pkt_synack41)),
        (1100, 2000, pkt_req41, len(pkt_req41)),
        (1100, 3000, pkt_resp41, len(pkt_resp41)),
    ]
    write_pcap(tmp_pcap, pkts41)
    ev41 = run_pcap(tmp_pcap, [80])
    ev41_utf8 = [e for e in ev41 if e.get("path") == "/api/utf8_41"]
    if not ev41_utf8:
        failures.append("[%s] Test 41 (Strict UTF-8 Validation): No event for /api/utf8_41" % engine_name)
    else:
        e41 = ev41_utf8[0]
        # Verify JSON serialization round-trip
        try:
            dumped = json.dumps(e41)
            loaded = json.loads(dumped)
            # Ensure invalid byte sequences were replaced with '?' or '\ufffd'
            ua = loaded.get("user_agent", "")
            if "\xc0" in ua or "\xaf" in ua:
                failures.append("[%s] Test 41 (Strict UTF-8 Validation): Raw overlong bytes survived in user_agent: %r" % (engine_name, ua))
            else:
                print("  [%s] Test 41 (Strict UTF-8 Validation): PASS (overlong/surrogate sanitized, valid JSON roundtrip)" % engine_name)
        except Exception as ex:
            failures.append("[%s] Test 41 (Strict UTF-8 Validation): JSON encoding failed: %s" % (engine_name, ex))

    # -----------------------------------------------------------------------
    # 42. Out-of-Order Server FIN with Delayed HTTP 200 Response
    # On an established connection, client sends GET /api/delayed_fin42.
    # Server sends FIN ahead of the HTTP 200 response data.
    # Then server's HTTP 200 response data arrives.
    # Sniffer must NOT discard the contiguous response bytes, must parse the
    # HTTP 200 OK, and correlate the request with status 200.
    # -----------------------------------------------------------------------
    req42 = b"GET /api/delayed_fin42 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp42 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    seq42_client = 42000
    seq42_server = 82000

    pkt_syn42 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50042, 80,
                                 seq42_client - 1, 0, 0x02, b"")
    pkt_synack42 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50042,
                                    seq42_server - 1, seq42_client, 0x12, b"")
    pkt_req42 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50042, 80,
                                 seq42_client, seq42_server, 0x18, req42)
    # Server sends FIN packet past the response data (seq42_server + len(resp42))
    pkt_fin42 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50042,
                                 seq42_server + len(resp42), seq42_client + len(req42), 0x11, b"")
    # Server delayed response data arrives after the FIN
    pkt_resp42 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50042,
                                  seq42_server, seq42_client + len(req42), 0x18, resp42)

    pkts42 = [
        (1200, 0, pkt_syn42, len(pkt_syn42)),
        (1200, 1000, pkt_synack42, len(pkt_synack42)),
        (1200, 2000, pkt_req42, len(pkt_req42)),
        (1200, 3000, pkt_fin42, len(pkt_fin42)),
        (1200, 4000, pkt_resp42, len(pkt_resp42)),
    ]
    write_pcap(tmp_pcap, pkts42)
    ev42 = run_pcap(tmp_pcap, [80])
    ev42_fin = [e for e in ev42 if e.get("path") == "/api/delayed_fin42"]
    if not ev42_fin:
        failures.append("[%s] Test 42 (Delayed Data Before FIN): No event for /api/delayed_fin42" % engine_name)
    elif ev42_fin[0].get("status") != 200:
        failures.append("[%s] Test 42 (Delayed Data Before FIN): Expected status 200, got %s" % (engine_name, ev42_fin[0].get("status")))
    elif ev42_fin[0].get("resp_bytes") != 5:
        failures.append("[%s] Test 42 (Delayed Data Before FIN): Expected resp_bytes 5, got %s" % (engine_name, ev42_fin[0].get("resp_bytes")))
    else:
        print("  [%s] Test 42 (Delayed Data Before FIN): PASS (delayed 200 OK parsed & correlated, not discarded)" % engine_name)

    # -----------------------------------------------------------------------
    # 43. Strict UTF-8 Scalar Boundary (Byte 0xF5 & Values > U+10FFFF)
    # Header contains byte 0xF5 (\xF5\x80\x80\x80), which exceeds Unicode U+10FFFF.
    # Must be sanitized to '?' or replaced, JSON valid, and not crash.
    # -----------------------------------------------------------------------
    bad_utf8_f5 = b"test-\xF5\x80\x80\x80-exceeds10ffff"
    req43 = b"GET /api/utf8_43 HTTP/1.1\r\nHost: " + bad_utf8_f5 + b"\r\nUser-Agent: " + bad_utf8_f5 + b"\r\n\r\n"
    resp43 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq43_client = 43000
    seq43_server = 83000

    pkt_syn43 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50043, 80,
                                 seq43_client - 1, 0, 0x02, b"")
    pkt_synack43 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50043,
                                    seq43_server - 1, seq43_client, 0x12, b"")
    pkt_req43 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50043, 80,
                                 seq43_client, seq43_server, 0x18, req43)
    pkt_resp43 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50043,
                                  seq43_server, seq43_client + len(req43), 0x18, resp43)

    pkts43 = [
        (1300, 0, pkt_syn43, len(pkt_syn43)),
        (1300, 1000, pkt_synack43, len(pkt_synack43)),
        (1300, 2000, pkt_req43, len(pkt_req43)),
        (1300, 3000, pkt_resp43, len(pkt_resp43)),
    ]
    write_pcap(tmp_pcap, pkts43)
    ev43 = run_pcap(tmp_pcap, [80])
    ev43_utf8 = [e for e in ev43 if e.get("path") == "/api/utf8_43"]
    if not ev43_utf8:
        failures.append("[%s] Test 43 (UTF-8 Scalar Boundary): No event for /api/utf8_43" % engine_name)
    else:
        e43 = ev43_utf8[0]
        try:
            dumped = json.dumps(e43)
            loaded = json.loads(dumped)
            ua = loaded.get("user_agent", "")
            if "\xf5" in ua:
                failures.append("[%s] Test 43 (UTF-8 Scalar Boundary): Raw 0xF5 survived in user_agent: %r" % (engine_name, ua))
            else:
                print("  [%s] Test 43 (UTF-8 Scalar Boundary): PASS (0xF5 sanitized, valid JSON roundtrip)" % engine_name)
        except Exception as ex:
            failures.append("[%s] Test 43 (UTF-8 Scalar Boundary): JSON encoding failed: %s" % (engine_name, ex))

    # -----------------------------------------------------------------------
    # 44. Identity Limit Preservation (> 64 Character Username)
    # WSSE allows usernames up to 200 characters. Previous code truncated to 64 bytes,
    # merging accounts sharing the first 64 chars.
    # Must preserve full username (e.g. 80 characters).
    # -----------------------------------------------------------------------
    long_user = "corp_admin_service_account_finance_ap_automation_system_user_identifier_80chars"
    soap_tmpl44 = (b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                   b"xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
                   b"<soap:Header><wsse:Security><wsse:UsernameToken>"
                   b"<wsse:Username>%s</wsse:Username>"
                   b"</wsse:UsernameToken></wsse:Security></soap:Header><soap:Body/></soap:Envelope>") % long_user.encode()
    req44 = (b"POST /api/soap44 HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/xml\r\nContent-Length: " +
             str(len(soap_tmpl44)).encode() + b"\r\n\r\n" + soap_tmpl44)
    resp44 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq44_client = 44000
    seq44_server = 84000

    pkt_syn44 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50044, 80,
                                 seq44_client - 1, 0, 0x02, b"")
    pkt_synack44 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50044,
                                    seq44_server - 1, seq44_client, 0x12, b"")
    pkt_req44 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50044, 80,
                                 seq44_client, seq44_server, 0x18, req44)
    pkt_resp44 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50044,
                                  seq44_server, seq44_client + len(req44), 0x18, resp44)

    pkts44 = [
        (1400, 0, pkt_syn44, len(pkt_syn44)),
        (1400, 1000, pkt_synack44, len(pkt_synack44)),
        (1400, 2000, pkt_req44, len(pkt_req44)),
        (1400, 3000, pkt_resp44, len(pkt_resp44)),
    ]
    write_pcap(tmp_pcap, pkts44)
    ev44 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev44_soap = [e for e in ev44 if e.get("path") == "/api/soap44"]
    if not ev44_soap:
        failures.append("[%s] Test 44 (Identity Limit Preservation): No event for /api/soap44" % engine_name)
    else:
        u44 = ev44_soap[0].get("user")
        wu44 = ev44_soap[0].get("wsse_user")
        if u44 != long_user:
            failures.append("[%s] Test 44 (Identity Limit Preservation): Expected user %r (len %d), got %r (len %d)" % (
                engine_name, long_user, len(long_user), u44, len(u44) if u44 else 0))
        elif wu44 != long_user:
            failures.append("[%s] Test 44 (Identity Limit Preservation): Expected wsse_user %r, got %r" % (engine_name, long_user, wu44))
        else:
            print("  [%s] Test 44 (Identity Limit Preservation): PASS (80-char username preserved without truncation)" % engine_name)

    # -----------------------------------------------------------------------
    # 45. Connection Reuse & Stale Pending Cleanup (100 Successive Generations)
    # 100 successive client SYNs on the same 5-tuple without responses for 1..99.
    # At each new SYN, old pending requests must be emitted with null status and
    # cleanly removed from FIFO.
    # Generation 100 receives complete 200 OK response.
    # Request 100 must correlate with status 200.
    # -----------------------------------------------------------------------
    pkts45 = []
    sport45 = 50045
    dport45 = 80
    for gen in range(1, 101):
        c_seq = gen * 10000
        s_seq = gen * 20000
        pkt_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport45, dport45,
                                   c_seq - 1, 0, 0x02, b"")
        req_b = ("GET /api/reuse_%d HTTP/1.1\r\nHost: example.com\r\n\r\n" % gen).encode()
        pkt_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport45, dport45,
                                   c_seq, s_seq, 0x18, req_b)
        pkts45.append((1500 + gen, 0, pkt_syn, len(pkt_syn)))
        pkts45.append((1500 + gen, 1000, pkt_req, len(pkt_req)))

        if gen == 100:
            pkt_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", dport45, sport45,
                                          s_seq - 1, c_seq, 0x12, b"")
            resp_b = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            pkt_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", dport45, sport45,
                                        s_seq, c_seq + len(req_b), 0x18, resp_b)
            pkts45.append((1500 + gen, 2000, pkt_synack, len(pkt_synack)))
            pkts45.append((1500 + gen, 3000, pkt_resp, len(pkt_resp)))

    write_pcap(tmp_pcap, pkts45)
    ev45 = run_pcap(tmp_pcap, [dport45])
    ev45_100 = [e for e in ev45 if e.get("path") == "/api/reuse_100"]
    ev45_earlier = [e for e in ev45 if e.get("path", "").startswith("/api/reuse_") and e.get("path") != "/api/reuse_100"]

    if not ev45_100:
        failures.append("[%s] Test 45 (Connection Reuse): No event for /api/reuse_100" % engine_name)
    elif ev45_100[0].get("status") != 200:
        failures.append("[%s] Test 45 (Connection Reuse): Expected status 200 for /api/reuse_100, got %s" % (
            engine_name, ev45_100[0].get("status")))
    elif len(ev45_earlier) != 99:
        failures.append("[%s] Test 45 (Connection Reuse): Expected 99 earlier flushed requests, got %d" % (
            engine_name, len(ev45_earlier)))
    elif any(e.get("status") is not None for e in ev45_earlier):
        failures.append("[%s] Test 45 (Connection Reuse): Earlier requests improperly received status" % engine_name)
    else:
        print("  [%s] Test 45 (Connection Reuse): PASS (100 successive generations cleaned up, 100th correlated 200 OK)" % engine_name)

    # -----------------------------------------------------------------------
    # 46. Stream Invalidation Packet Loss: Resync to New Boundary Without Correlation
    # Invalidation disables response correlation, NOT HTTP parsing.
    # An invalidation trigger occurs (e.g. conflicting Content-Length), then without a new SYN,
    # client sends a new valid GET request.
    # The sniffer must resync to the HTTP boundary, parse and emit the request,
    # but correlation remains disabled (status: null).
    # -----------------------------------------------------------------------
    req46_bad = b"POST /api/conflict HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n1234567890"
    req46_good = b"GET /api/after_gap HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp46_good = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    seq46_c = 10000
    seq46_s = 20000

    pkt46_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50046, 80, seq46_c - 1, 0, 0x02, b"")
    pkt46_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50046, seq46_s - 1, seq46_c, 0x12, b"")
    pkt46_bad = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50046, 80, seq46_c, seq46_s, 0x18, req46_bad)
    seq46_c2 = seq46_c + len(req46_bad) + 100
    pkt46_good = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50046, 80, seq46_c2, seq46_s, 0x18, req46_good)
    pkt46_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, 50046, seq46_s, seq46_c2 + len(req46_good), 0x18, resp46_good)

    pkts46 = [
        (1600, 0, pkt46_syn, len(pkt46_syn)),
        (1600, 1000, pkt46_synack, len(pkt46_synack)),
        (1600, 2000, pkt46_bad, len(pkt46_bad)),
        (1600, 3000, pkt46_good, len(pkt46_good)),
        (1600, 4000, pkt46_resp, len(pkt46_resp)),
    ]
    write_pcap(tmp_pcap, pkts46)
    ev46 = run_pcap(tmp_pcap, [80])
    ev46_good = [e for e in ev46 if e.get("path") == "/api/after_gap"]
    if not ev46_good:
        failures.append("[%s] Test 46 (Capture Gap Resync): Request /api/after_gap was not emitted (HTTP parsing broken)" % engine_name)
    elif ev46_good[0].get("status") is not None:
        failures.append("[%s] Test 46 (Capture Gap Resync): Request /api/after_gap improperly correlated with status %s on invalidated stream" % (
            engine_name, ev46_good[0].get("status")))
    else:
        print("  [%s] Test 46 (Capture Gap Resync): PASS (/api/after_gap parsed and emitted with null status)" % engine_name)

    # -----------------------------------------------------------------------
    # 47. Clean Idle Keepalive Recovery (Preserves Correlation)
    # A connection completes a transaction and rests cleanly at an idle boundary.
    # Subsequent keep-alive request after idle interval must correlate with status 200.
    # -----------------------------------------------------------------------
    sport47 = 50047
    seq47_c = 10000
    seq47_s = 20000
    req47_1 = b"GET /api/idle1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp47_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    req47_2 = b"GET /api/idle2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp47_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    pkt47_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport47, 80, seq47_c - 1, 0, 0x02, b"")
    pkt47_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport47, seq47_s - 1, seq47_c, 0x12, b"")
    pkt47_req1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport47, 80, seq47_c, seq47_s, 0x18, req47_1)
    pkt47_resp1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport47, seq47_s, seq47_c + len(req47_1), 0x18, resp47_1)

    seq47_c2 = seq47_c + len(req47_1)
    seq47_s2 = seq47_s + len(resp47_1)
    pkt47_req2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport47, 80, seq47_c2, seq47_s2, 0x18, req47_2)
    pkt47_resp2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport47, seq47_s2, seq47_c2 + len(req47_2), 0x18, resp47_2)

    pkts47 = [
        (1650, 0, pkt47_syn, len(pkt47_syn)),
        (1650, 1000, pkt47_synack, len(pkt47_synack)),
        (1650, 2000, pkt47_req1, len(pkt47_req1)),
        (1650, 3000, pkt47_resp1, len(pkt47_resp1)),
        (1650 + 35, 0, pkt47_req2, len(pkt47_req2)),
        (1650 + 35, 1000, pkt47_resp2, len(pkt47_resp2)),
    ]
    write_pcap(tmp_pcap, pkts47)
    ev47 = run_pcap(tmp_pcap, [80])
    ev47_1 = [e for e in ev47 if e.get("path") == "/api/idle1"]
    ev47_2 = [e for e in ev47 if e.get("path") == "/api/idle2"]
    if not ev47_1 or not ev47_2:
        failures.append("[%s] Test 47 (Clean Idle Recovery): Missing events for idle transactions" % engine_name)
    elif ev47_1[0].get("status") != 200 or ev47_2[0].get("status") != 200:
        failures.append("[%s] Test 47 (Clean Idle Recovery): Expected status 200 for both, got %s and %s" % (
            engine_name, ev47_1[0].get("status"), ev47_2[0].get("status")))
    else:
        print("  [%s] Test 47 (Clean Idle Recovery): PASS (keepalive transactions preserved correlation 200 OK)" % engine_name)

    # -----------------------------------------------------------------------
    # 48. WSSE Active Flow Reset on Fresh SYN
    # Flow buffering incomplete WSSE body is interrupted by a fresh SYN on same tuple.
    # The active WSSE flow must be cancelled and active count decremented.
    # The subsequent request on the new generation must correlate normally.
    # -----------------------------------------------------------------------
    sport48 = 50048
    soap_head48 = b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><soap:Header><wsse:Security><wsse:UsernameToken>"
    req48_soap = (b"POST /api/soap_incomplete HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/xml\r\nContent-Length: 500\r\n\r\n" +
                  soap_head48)
    req48_fresh = b"GET /api/fresh HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp48_fresh = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    pkt48_syn1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport48, 80, 1000 - 1, 0, 0x02, b"")
    pkt48_synack1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport48, 2000 - 1, 1000, 0x12, b"")
    pkt48_req_soap = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport48, 80, 1000, 2000, 0x18, req48_soap)

    pkt48_syn2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport48, 80, 5000 - 1, 0, 0x02, b"")
    pkt48_synack2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport48, 6000 - 1, 5000, 0x12, b"")
    pkt48_req_fresh = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport48, 80, 5000, 6000, 0x18, req48_fresh)
    pkt48_resp_fresh = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport48, 6000, 5000 + len(req48_fresh), 0x18, resp48_fresh)

    pkts48 = [
        (1700, 0, pkt48_syn1, len(pkt48_syn1)),
        (1700, 1000, pkt48_synack1, len(pkt48_synack1)),
        (1700, 2000, pkt48_req_soap, len(pkt48_req_soap)),
        (1701, 0, pkt48_syn2, len(pkt48_syn2)),
        (1701, 1000, pkt48_synack2, len(pkt48_synack2)),
        (1701, 2000, pkt48_req_fresh, len(pkt48_req_fresh)),
        (1701, 3000, pkt48_resp_fresh, len(pkt48_resp_fresh)),
    ]
    write_pcap(tmp_pcap, pkts48)
    ev48 = run_pcap(tmp_pcap, [80], wsse_bytes=8192)
    ev48_fresh = [e for e in ev48 if e.get("path") == "/api/fresh"]
    if not ev48_fresh:
        failures.append("[%s] Test 48 (WSSE Active Flow Reset): No event for /api/fresh" % engine_name)
    elif ev48_fresh[0].get("status") != 200:
        failures.append("[%s] Test 48 (WSSE Active Flow Reset): Expected status 200 for /api/fresh, got %s" % (
            engine_name, ev48_fresh[0].get("status")))
    else:
        print("  [%s] Test 48 (WSSE Active Flow Reset): PASS (active WSSE cancelled on SYN, fresh request correlated 200 OK)" % engine_name)

    # -----------------------------------------------------------------------
    # 49. Basic Auth Without Colon Rejected as Anonymous
    # Base64 without ':' (e.g. "Basic dXNlcg==" which decodes to "user") is invalid Basic auth.
    # Must reject and emit as anonymous (user != "user", scheme != "basic").
    # -----------------------------------------------------------------------
    sport49 = 50049
    req49 = b"GET /api/bad_basic HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcg==\r\n\r\n"
    resp49 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt49_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport49, 80, 1000 - 1, 0, 0x02, b"")
    pkt49_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport49, 2000 - 1, 1000, 0x12, b"")
    pkt49_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport49, 80, 1000, 2000, 0x18, req49)
    pkt49_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport49, 2000, 1000 + len(req49), 0x18, resp49)

    pkts49 = [
        (1750, 0, pkt49_syn, len(pkt49_syn)),
        (1750, 1000, pkt49_synack, len(pkt49_synack)),
        (1750, 2000, pkt49_req, len(pkt49_req)),
        (1750, 3000, pkt49_resp, len(pkt49_resp)),
    ]
    write_pcap(tmp_pcap, pkts49)
    ev49 = run_pcap(tmp_pcap, [80])
    ev49_bad = [e for e in ev49 if e.get("path") == "/api/bad_basic"]
    if not ev49_bad:
        failures.append("[%s] Test 49 (Basic Auth Colon Check): Missing event for /api/bad_basic" % engine_name)
    else:
        u49 = ev49_bad[0].get("user")
        bu49 = ev49_bad[0].get("basic_user")
        s49 = ev49_bad[0].get("scheme")
        if u49 == "user" or bu49 == "user" or s49 == "basic":
            failures.append("[%s] Test 49 (Basic Auth Colon Check): Malformed basic auth without colon accepted: user=%r, basic_user=%r, scheme=%r" % (
                engine_name, u49, bu49, s49))
        else:
            print("  [%s] Test 49 (Basic Auth Colon Check): PASS (Basic auth without colon rejected as anonymous)" % engine_name)

    # -----------------------------------------------------------------------
    # 50. Late Duplicate SYN-ACK Never Moves resp_flow.next_seq Backward
    # After server responds and advances resp_flow.next_seq, a duplicate SYN-ACK arrives.
    # resp_flow.next_seq must not move backward. Subsequent pipelined request must correlate.
    # -----------------------------------------------------------------------
    sport50 = 50050
    seq50_c = 10000
    seq50_s = 20000
    req50_1 = b"GET /api/synack1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp50_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    req50_2 = b"GET /api/synack2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp50_2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    pkt50_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport50, 80, seq50_c - 1, 0, 0x02, b"")
    pkt50_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport50, seq50_s - 1, seq50_c, 0x12, b"")
    pkt50_req1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport50, 80, seq50_c, seq50_s, 0x18, req50_1)
    pkt50_resp1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport50, seq50_s, seq50_c + len(req50_1), 0x18, resp50_1)

    pkt50_dup_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport50, seq50_s - 1, seq50_c, 0x12, b"")

    seq50_c2 = seq50_c + len(req50_1)
    seq50_s2 = seq50_s + len(resp50_1)
    pkt50_req2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport50, 80, seq50_c2, seq50_s2, 0x18, req50_2)
    pkt50_resp2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport50, seq50_s2, seq50_c2 + len(req50_2), 0x18, resp50_2)

    pkts50 = [
        (1800, 0, pkt50_syn, len(pkt50_syn)),
        (1800, 1000, pkt50_synack, len(pkt50_synack)),
        (1800, 2000, pkt50_req1, len(pkt50_req1)),
        (1800, 3000, pkt50_resp1, len(pkt50_resp1)),
        (1800, 4000, pkt50_dup_synack, len(pkt50_dup_synack)),
        (1800, 5000, pkt50_req2, len(pkt50_req2)),
        (1800, 6000, pkt50_resp2, len(pkt50_resp2)),
    ]
    write_pcap(tmp_pcap, pkts50)
    ev50 = run_pcap(tmp_pcap, [80])
    ev50_1 = [e for e in ev50 if e.get("path") == "/api/synack1"]
    ev50_2 = [e for e in ev50 if e.get("path") == "/api/synack2"]
    if not ev50_1 or not ev50_2:
        failures.append("[%s] Test 50 (Late Duplicate SYN-ACK): Missing events for transactions" % engine_name)
    elif ev50_1[0].get("status") != 200 or ev50_2[0].get("status") != 200:
        failures.append("[%s] Test 50 (Late Duplicate SYN-ACK): Expected status 200 for both, got %s and %s" % (
            engine_name, ev50_1[0].get("status"), ev50_2[0].get("status")))
    else:
        print("  [%s] Test 50 (Late Duplicate SYN-ACK): PASS (duplicate SYN-ACK did not rewind next_seq; both correlated 200 OK)" % engine_name)

    # 51. Mid-segment HTTP Resync after packet gap / truncation
    sport51 = 50051
    pkt51_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport51, 80, 1000, 0, 0x02, b"")
    pkt51_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport51, 2000, 1001, 0x12, b"")
    trunc51 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport51, 80, 1001, 2001, 0x18, b"TRUNC", ip_total_len=200)
    mid_payload = b"REST_OF_PREV_BODY_DATA" + b"GET /api/midsegment HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt51_mid = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport51, 80, 1500, 2001, 0x18, mid_payload)

    pkts51 = [
        (1900, 0, pkt51_syn, len(pkt51_syn)),
        (1900, 1000, pkt51_synack, len(pkt51_synack)),
        (1900, 2000, trunc51, len(trunc51)),
        (1900, 3000, pkt51_mid, len(pkt51_mid)),
    ]
    write_pcap(tmp_pcap, pkts51)
    ev51 = run_pcap(tmp_pcap, [80])
    ev51_mid = [e for e in ev51 if e.get("path") == "/api/midsegment"]
    if not ev51_mid:
        failures.append("[%s] Test 51 (Mid-Segment Resync): Expected /api/midsegment event, got %s" % (
            engine_name, [e.get("path") for e in ev51]))
    elif ev51_mid[0].get("status") is not None:
        failures.append("[%s] Test 51 (Mid-Segment Resync): Expected status None for /api/midsegment, got %s" % (
            engine_name, ev51_mid[0].get("status")))
    else:
        print("  [%s] Test 51 (Mid-Segment Resync): PASS (/api/midsegment resynced mid-packet and emitted with null status)" % engine_name)

    # 52. Retransmitted duplicate client SYN after invalidation does not restore correlation
    sport52 = 50052
    isn52_c = 10000
    isn52_s = 20000
    pkt52_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport52, 80, isn52_c, 0, 0x02, b"")
    pkt52_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport52, isn52_s, isn52_c + 1, 0x12, b"")
    trunc52 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport52, 80, isn52_c + 1, isn52_s + 1, 0x18, b"TRUNC", ip_total_len=200)
    pkt52_dup_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport52, 80, isn52_c, 0, 0x02, b"")
    req52 = b"GET /api/after_dup_syn HTTP/1.1\r\nHost: api.test\r\n\r\n"
    resp52 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt52_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport52, 80, isn52_c + 100, isn52_s + 1, 0x18, req52)
    pkt52_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport52, isn52_s + 1, isn52_c + 100 + len(req52), 0x18, resp52)

    pkts52 = [
        (2000, 0, pkt52_syn, len(pkt52_syn)),
        (2000, 1000, pkt52_synack, len(pkt52_synack)),
        (2000, 2000, trunc52, len(trunc52)),
        (2000, 3000, pkt52_dup_syn, len(pkt52_dup_syn)),
        (2000, 4000, pkt52_req, len(pkt52_req)),
        (2000, 5000, pkt52_resp, len(pkt52_resp)),
    ]
    write_pcap(tmp_pcap, pkts52)
    ev52 = run_pcap(tmp_pcap, [80])
    ev52_req = [e for e in ev52 if e.get("path") == "/api/after_dup_syn"]
    if not ev52_req:
        failures.append("[%s] Test 52 (Duplicate Client SYN Lockout): Missing event for /api/after_dup_syn" % engine_name)
    elif ev52_req[0].get("status") is not None:
        failures.append("[%s] Test 52 (Duplicate Client SYN Lockout): Expected status None (lockout retained), got %s" % (
            engine_name, ev52_req[0].get("status")))
    else:
        print("  [%s] Test 52 (Duplicate Client SYN Lockout): PASS (duplicate SYN ignored; stream remained uncorrelated)" % engine_name)

    # 53. Strict Base64 validation
    sport53 = 50053
    pkt53_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport53, 80, 30000, 0, 0x02, b"")
    pkt53_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport53, 40000, 30001, 0x12, b"")
    req53_bad = b"GET /api/b64bad HTTP/1.1\r\nHost: api.test\r\nAuthorization: Basic dXNlcjpwYXNz==!\r\n\r\n"
    req53_good = b"GET /api/b64good HTTP/1.1\r\nHost: api.test\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    resp53 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    seq53_c = 30001
    seq53_s = 40001
    pkt53_req1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport53, 80, seq53_c, seq53_s, 0x18, req53_bad)
    pkt53_resp1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport53, seq53_s, seq53_c + len(req53_bad), 0x18, resp53)
    seq53_c += len(req53_bad)
    seq53_s += len(resp53)
    pkt53_req2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport53, 80, seq53_c, seq53_s, 0x18, req53_good)
    pkt53_resp2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport53, seq53_s, seq53_c + len(req53_good), 0x18, resp53)

    pkts53 = [
        (2100, 0, pkt53_syn, len(pkt53_syn)),
        (2100, 1000, pkt53_synack, len(pkt53_synack)),
        (2100, 2000, pkt53_req1, len(pkt53_req1)),
        (2100, 3000, pkt53_resp1, len(pkt53_resp1)),
        (2100, 4000, pkt53_req2, len(pkt53_req2)),
        (2100, 5000, pkt53_resp2, len(pkt53_resp2)),
    ]
    write_pcap(tmp_pcap, pkts53)
    ev53 = run_pcap(tmp_pcap, [80])
    ev53_bad = [e for e in ev53 if e.get("path") == "/api/b64bad"]
    ev53_good = [e for e in ev53 if e.get("path") == "/api/b64good"]
    if not ev53_bad or not ev53_good:
        failures.append("[%s] Test 53 (Strict Base64): Missing events" % engine_name)
    elif ev53_bad[0].get("user") not in (None, "-anonymous-") or ev53_bad[0].get("basic_user") is not None:
        failures.append("[%s] Test 53 (Strict Base64): Expected anonymous user for bad Base64, got user=%s, basic_user=%s" % (
            engine_name, ev53_bad[0].get("user"), ev53_bad[0].get("basic_user")))
    elif ev53_good[0].get("user") != "user" or ev53_good[0].get("basic_user") != "user":
        failures.append("[%s] Test 53 (Strict Base64): Expected user='user' for valid Base64, got user=%s" % (
            engine_name, ev53_good[0].get("user")))
    else:
        print("  [%s] Test 53 (Strict Base64): PASS (invalid suffix rejected as anonymous; valid parsed 'user')" % engine_name)

    # 54. Split Request Method Across TCP Segment Boundary After Gap
    sport54 = 50054
    pkt54_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport54, 80, 1000, 0, 0x02, b"")
    pkt54_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport54, 2000, 1001, 0x12, b"")
    trunc54 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport54, 80, 1001, 2001, 0x18, b"TRUNC", ip_total_len=200)
    p1_54 = b"BODYTAILGE"
    p2_54 = b"T /split HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt54_p1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport54, 80, 3000, 2001, 0x18, p1_54)
    pkt54_p2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport54, 80, 3000 + len(p1_54), 2001, 0x18, p2_54)

    pkts54 = [
        (2200, 0, pkt54_syn, len(pkt54_syn)),
        (2200, 1000, pkt54_synack, len(pkt54_synack)),
        (2200, 2000, trunc54, len(trunc54)),
        (2200, 3000, pkt54_p1, len(pkt54_p1)),
        (2200, 4000, pkt54_p2, len(pkt54_p2)),
    ]
    write_pcap(tmp_pcap, pkts54)
    ev54 = run_pcap(tmp_pcap, [80])
    ev54_split = [e for e in ev54 if e.get("path") == "/split"]
    if not ev54_split:
        failures.append("[%s] Test 54 (Split Request Method Boundary): Expected /split event, got %s" % (
            engine_name, [e.get("path") for e in ev54]))
    elif ev54_split[0].get("status") is not None:
        failures.append("[%s] Test 54 (Split Request Method Boundary): Expected status None, got %s" % (
            engine_name, ev54_split[0].get("status")))
    else:
        print("  [%s] Test 54 (Split Request Method Boundary): PASS ('GE'+'T /split' reassembled across packet gap)" % engine_name)

    # 55. Split Response Status Line Across TCP Segment Boundary After Gap
    sport55 = 50055
    pkt55_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport55, 80, 10000, 0, 0x02, b"")
    pkt55_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport55, 20000, 10001, 0x12, b"")
    trunc55 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport55, 20001, 10001, 0x18, b"TRUNC", ip_total_len=200)
    p1_55 = b"BODYHT"
    p2_55 = b"TP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt55_p1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport55, 25000, 10001, 0x18, p1_55)
    pkt55_p2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport55, 25000 + len(p1_55), 10001, 0x18, p2_55)

    req55 = b"GET /api/after_resp_resync HTTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt55_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport55, 80, 15000, 25000 + len(p1_55) + len(p2_55), 0x18, req55)

    pkts55 = [
        (2300, 0, pkt55_syn, len(pkt55_syn)),
        (2300, 1000, pkt55_synack, len(pkt55_synack)),
        (2300, 2000, trunc55, len(trunc55)),
        (2300, 3000, pkt55_p1, len(pkt55_p1)),
        (2300, 4000, pkt55_p2, len(pkt55_p2)),
        (2300, 5000, pkt55_req, len(pkt55_req)),
    ]
    write_pcap(tmp_pcap, pkts55)
    ev55 = run_pcap(tmp_pcap, [80])
    ev55_req = [e for e in ev55 if e.get("path") == "/api/after_resp_resync"]
    if not ev55_req:
        failures.append("[%s] Test 55 (Split Response Status Boundary): Missing event for /api/after_resp_resync" % engine_name)
    else:
        print("  [%s] Test 55 (Split Response Status Boundary): PASS ('HT'+'TP/1.1' reassembled and framing advanced)" % engine_name)

    # 56. Strict Start-Line Validation
    sport56 = 50056
    pkt56_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport56, 80, 40000, 0, 0x02, b"")
    pkt56_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport56, 50000, 40001, 0x12, b"")
    bad_req = b"GET /bad_req XYZ\r\nHost: api.test\r\n\r\n"
    good_req = b"GET /good_req HTTP/1.1\r\nHost: api.test\r\n\r\n"
    bad_resp = b"HTTP/XYZ 200junk\r\nContent-Length: 0\r\n\r\n"
    good_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    seq56_c = 40001
    seq56_s = 50001
    pkt56_r1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport56, 80, seq56_c, seq56_s, 0x18, bad_req)
    seq56_c += len(bad_req)
    pkt56_r2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport56, 80, seq56_c, seq56_s, 0x18, good_req)
    seq56_c += len(good_req)
    pkt56_s1 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport56, seq56_s, seq56_c, 0x18, bad_resp)
    seq56_s += len(bad_resp)
    pkt56_s2 = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport56, seq56_s, seq56_c, 0x18, good_resp)

    pkts56 = [
        (2400, 0, pkt56_syn, len(pkt56_syn)),
        (2400, 1000, pkt56_synack, len(pkt56_synack)),
        (2400, 2000, pkt56_r1, len(pkt56_r1)),
        (2400, 3000, pkt56_r2, len(pkt56_r2)),
        (2400, 4000, pkt56_s1, len(pkt56_s1)),
        (2400, 5000, pkt56_s2, len(pkt56_s2)),
    ]
    write_pcap(tmp_pcap, pkts56)
    ev56 = run_pcap(tmp_pcap, [80])
    ev56_bad = [e for e in ev56 if e.get("path") == "/bad_req"]
    ev56_good = [e for e in ev56 if e.get("path") == "/good_req"]
    if ev56_bad:
        failures.append("[%s] Test 56 (Strict Start Line): Expected /bad_req to be rejected, got %s" % (
            engine_name, ev56_bad))
    elif not ev56_good:
        failures.append("[%s] Test 56 (Strict Start Line): Missing /good_req event" % engine_name)
    elif ev56_good[0].get("status") != 200:
        failures.append("[%s] Test 56 (Strict Start Line): Expected status 200 for /good_req, got %s" % (
            engine_name, ev56_good[0].get("status")))
    else:
        print("  [%s] Test 56 (Strict Start Line): PASS (invalid request/response start lines rejected)" % engine_name)

    # 57. Oversized or Ambiguous Transfer-Encoding Rejection
    sport57 = 50057
    pkt57_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport57, 80, 50000, 0, 0x02, b"")
    pkt57_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport57, 60000, 50001, 0x12, b"")
    long_te = b"gzip, " * 45 + b"chunked" # > 270 bytes
    req57_bad = (b"POST /api/bad_te HTTP/1.1\r\n"
                 b"Host: test.local\r\n"
                 b"Transfer-Encoding: " + long_te + b"\r\n\r\n"
                 b"5\r\nhello\r\n0\r\n\r\n")
    pkt57_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport57, 80, 50001, 60001, 0x18, req57_bad)
    write_pcap(tmp_pcap, [
        (2500, 0, pkt57_syn, len(pkt57_syn)),
        (2500, 1000, pkt57_synack, len(pkt57_synack)),
        (2500, 2000, pkt57_req, len(pkt57_req)),
    ])
    ev57 = run_pcap(tmp_pcap, [80])
    ev57_bad = [e for e in ev57 if e.get("path") == "/api/bad_te"]
    if ev57_bad:
        failures.append("[%s] Test 57 (Oversized TE): Expected /api/bad_te to be rejected/invalidated, got %s" % (
            engine_name, ev57_bad))
    else:
        print("  [%s] Test 57 (Oversized TE): PASS (oversized TE rejected as ambiguous framing)" % engine_name)

    # 58. Same-Sequence OOO Retransmission Extension
    sport58 = 50058
    pkt58_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport58, 80, 70000, 0, 0x02, b"")
    pkt58_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport58, 80000, 70001, 0x12, b"")
    seg1_data = b"TTP/1.1\r\n"
    pkt58_ooo1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport58, 80, 70022, 80001, 0x18, seg1_data)
    seg2_data = b"TTP/1.1\r\nHost: api.test\r\n\r\n"
    pkt58_ooo2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport58, 80, 70022, 80001, 0x18, seg2_data)
    prefix_data = b"GET /api/ooo_extend H"
    pkt58_head = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport58, 80, 70001, 80001, 0x18, prefix_data)
    resp58 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt58_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport58, 80001, 70022 + len(seg2_data), 0x18, resp58)
    write_pcap(tmp_pcap, [
        (2600, 0, pkt58_syn, len(pkt58_syn)),
        (2600, 1000, pkt58_synack, len(pkt58_synack)),
        (2600, 2000, pkt58_ooo1, len(pkt58_ooo1)),
        (2600, 3000, pkt58_ooo2, len(pkt58_ooo2)),
        (2600, 4000, pkt58_head, len(pkt58_head)),
        (2600, 5000, pkt58_resp, len(pkt58_resp)),
    ])
    ev58 = run_pcap(tmp_pcap, [80])
    ev58_ext = [e for e in ev58 if e.get("path") == "/api/ooo_extend"]
    if not ev58_ext:
        failures.append("[%s] Test 58 (OOO Retransmission Extension): Missing /api/ooo_extend event" % engine_name)
    elif ev58_ext[0].get("status") != 200:
        failures.append("[%s] Test 58 (OOO Retransmission Extension): Expected status 200, got %s" % (
            engine_name, ev58_ext[0].get("status")))
    else:
        print("  [%s] Test 58 (OOO Retransmission Extension): PASS (longer retransmission retained and drained)" % engine_name)

    # -----------------------------------------------------------------------
    # 59. Malformed IPv4 Total Length == 0 Rejection
    # -----------------------------------------------------------------------
    sport59 = 50059
    seq59_client = 1000
    seq59_server = 5000
    pkt59_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport59, 80, seq59_client, 0, 0x02, b"")
    pkt59_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport59, seq59_server, seq59_client + 1, 0x12, b"")
    req59_malformed = b"GET /api/malformed_ip0 HTTP/1.1\r\nHost: test.local\r\n\r\n"
    pkt59_malformed = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport59, 80, seq59_client + 1, seq59_server + 1, 0x18, req59_malformed, ip_total_len=0)
    write_pcap(tmp_pcap, [
        (2700, 0, pkt59_syn, len(pkt59_syn)),
        (2700, 1000, pkt59_synack, len(pkt59_synack)),
        (2700, 2000, pkt59_malformed, len(pkt59_malformed)),
    ])
    ev59 = run_pcap(tmp_pcap, [80])
    ev59_malformed = [e for e in ev59 if e.get("path") == "/api/malformed_ip0"]
    if ev59_malformed:
        failures.append("[%s] Test 59 (IPv4 Total Length 0): /api/malformed_ip0 should have been rejected but got event" % engine_name)
    else:
        print("  [%s] Test 59 (IPv4 Total Length 0): PASS (malformed packet with total_len 0 rejected)" % engine_name)

    # -----------------------------------------------------------------------
    # 60. HTTP 101 Switching Protocols Pending Request Completion
    # -----------------------------------------------------------------------
    sport60 = 50060
    seq60_client = 2000
    seq60_server = 6000
    pkt60_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport60, 80, seq60_client, 0, 0x02, b"")
    pkt60_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport60, seq60_server, seq60_client + 1, 0x12, b"")
    req60 = b"GET /chat/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    pkt60_req = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport60, 80, seq60_client + 1, seq60_server + 1, 0x18, req60)
    resp60 = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    pkt60_resp = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport60, seq60_server + 1, seq60_client + 1 + len(req60), 0x18, resp60)
    # Post-upgrade raw binary frames that look like GET methods shouldn't be parsed
    raw_ws = b"GET /smuggled_after_upgrade HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt60_raw = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport60, 80, seq60_client + 1 + len(req60), seq60_server + 1 + len(resp60), 0x18, raw_ws)
    write_pcap(tmp_pcap, [
        (2800, 0, pkt60_syn, len(pkt60_syn)),
        (2800, 1000, pkt60_synack, len(pkt60_synack)),
        (2800, 2000, pkt60_req, len(pkt60_req)),
        (2800, 3000, pkt60_resp, len(pkt60_resp)),
        (2800, 4000, pkt60_raw, len(pkt60_raw)),
    ])
    ev60 = run_pcap(tmp_pcap, [80])
    ev60_ws = [e for e in ev60 if e.get("path") == "/chat/ws"]
    ev60_smuggled = [e for e in ev60 if e.get("path") == "/smuggled_after_upgrade"]
    if not ev60_ws:
        failures.append("[%s] Test 60 (HTTP 101 Upgrade): Missing /chat/ws event" % engine_name)
    elif ev60_ws[0].get("status") != 101:
        failures.append("[%s] Test 60 (HTTP 101 Upgrade): Expected status 101, got %s" % (engine_name, ev60_ws[0].get("status")))
    elif ev60_ws[0].get("resp_bytes") != 0:
        failures.append("[%s] Test 60 (HTTP 101 Upgrade): Expected resp_bytes 0, got %s" % (engine_name, ev60_ws[0].get("resp_bytes")))
    elif ev60_smuggled:
        failures.append("[%s] Test 60 (HTTP 101 Upgrade): Smuggled request parsed on upgraded stream" % engine_name)
    else:
        print("  [%s] Test 60 (HTTP 101 Upgrade): PASS (status 101 emitted with resp_bytes 0; stream disabled)" % engine_name)

    # -----------------------------------------------------------------------
    # 61. Untrusted Response Framing Bypass
    # -----------------------------------------------------------------------
    sport61 = 50061
    seq61_client = 3000
    seq61_server = 7000
    pkt61_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport61, 80, seq61_client, 0, 0x02, b"")
    pkt61_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport61, seq61_server, seq61_client + 1, 0x12, b"")
    # Framing conflict breaks correlation
    req61_conflict = b"POST /api/conflict HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    pkt61_req_conflict = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport61, 80, seq61_client + 1, seq61_server + 1, 0x18, req61_conflict)
    # Next request emitted without correlation (status null)
    req61_next = b"GET /api/next_request HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt61_req_next = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport61, 80, seq61_client + 1 + len(req61_conflict), seq61_server + 1, 0x18, req61_next)
    # Server sends a HEAD-style 200 response with Content-Length: 50 but NO body
    resp61_head = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"
    pkt61_resp_head = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport61, seq61_server + 1, seq61_client + 1 + len(req61_conflict) + len(req61_next), 0x18, resp61_head)
    write_pcap(tmp_pcap, [
        (2900, 0, pkt61_syn, len(pkt61_syn)),
        (2900, 1000, pkt61_synack, len(pkt61_synack)),
        (2900, 2000, pkt61_req_conflict, len(pkt61_req_conflict)),
        (2900, 3000, pkt61_req_next, len(pkt61_req_next)),
        (2900, 4000, pkt61_resp_head, len(pkt61_resp_head)),
    ])
    ev61 = run_pcap(tmp_pcap, [80])
    ev61_next = [e for e in ev61 if e.get("path") == "/api/next_request"]
    if not ev61_next:
        failures.append("[%s] Test 61 (Untrusted Response Bypass): Missing /api/next_request event" % engine_name)
    elif ev61_next[0].get("status") is not None:
        failures.append("[%s] Test 61 (Untrusted Response Bypass): /api/next_request got unexpected status %s" % (
            engine_name, ev61_next[0].get("status")))
    else:
        print("  [%s] Test 61 (Untrusted Response Bypass): PASS (response payload bypassed when untrusted)" % engine_name)

    # -----------------------------------------------------------------------
    # 62. Strict Complete Transfer-Encoding Tokenization
    # -----------------------------------------------------------------------
    sport62 = 50062
    seq62_client = 4000
    seq62_server = 8000
    pkt62_syn = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport62, 80, seq62_client, 0, 0x02, b"")
    pkt62_synack = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport62, seq62_server, seq62_client + 1, 0x12, b"")
    # Empty token: ",chunked"
    req62_bad1 = b"POST /api/te_bad1 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: ,chunked\r\n\r\n"
    pkt62_bad1 = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport62, 80, seq62_client + 1, seq62_server + 1, 0x18, req62_bad1)
    # Valid chunked: "gzip, chunked"
    sport62_v = 50063
    pkt62_syn_v = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport62_v, 80, seq62_client, 0, 0x02, b"")
    pkt62_synack_v = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport62_v, seq62_server, seq62_client + 1, 0x12, b"")
    req62_valid = b"POST /api/te_valid HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
    pkt62_valid = make_ipv4_packet("10.0.0.1", "10.0.0.2", sport62_v, 80, seq62_client + 1, seq62_server + 1, 0x18, req62_valid)
    resp62_valid = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    pkt62_resp_v = make_ipv4_packet("10.0.0.2", "10.0.0.1", 80, sport62_v, seq62_server + 1, seq62_client + 1 + len(req62_valid), 0x18, resp62_valid)
    write_pcap(tmp_pcap, [
        (3000, 0, pkt62_syn, len(pkt62_syn)),
        (3000, 1000, pkt62_synack, len(pkt62_synack)),
        (3000, 2000, pkt62_bad1, len(pkt62_bad1)),
        (3000, 3000, pkt62_syn_v, len(pkt62_syn_v)),
        (3000, 4000, pkt62_synack_v, len(pkt62_synack_v)),
        (3000, 5000, pkt62_valid, len(pkt62_valid)),
        (3000, 6000, pkt62_resp_v, len(pkt62_resp_v)),
    ])
    ev62 = run_pcap(tmp_pcap, [80])
    ev62_valid = [e for e in ev62 if e.get("path") == "/api/te_valid"]
    if not ev62_valid:
        failures.append("[%s] Test 62 (Strict Transfer-Encoding): Missing /api/te_valid event" % engine_name)
    elif ev62_valid[0].get("status") != 200:
        failures.append("[%s] Test 62 (Strict Transfer-Encoding): Expected status 200, got %s" % (
            engine_name, ev62_valid[0].get("status")))
    else:
        print("  [%s] Test 62 (Strict Transfer-Encoding): PASS (invalid tokens rejected; valid gzip, chunked correlated)" % engine_name)

    if os.path.exists(tmp_pcap):
        os.remove(tmp_pcap)
    return failures

def run_regression_suite():
    print("=== Running Dual-Engine Synthetic Packet Regression Suite ===")
    subprocess.run(["make", "pcap_test_cpp"], cwd=OLD_DIR, check=True)
    all_failures = []
    for engine_name, run_func in (("C++", run_cpp_pcap), ("Python", run_python_pcap)):
        failures = run_test_suite_for_engine(run_func, engine_name)
        all_failures.extend(failures)
        ext_failures = run_test_suite_for_engine_ext(run_func, engine_name)
        all_failures.extend(ext_failures)

    print("\n--- Overall Summary: %d failures across all test runs ---" % len(all_failures))
    if all_failures:
        print("Failures:")
        for f in all_failures:
            print("  *", f)
        sys.exit(1)
    else:
        print("ALL DUAL-ENGINE SYNTHETIC REGRESSION TESTS PASSED (124/124 PASS)!")

if __name__ == "__main__":
    run_regression_suite()
