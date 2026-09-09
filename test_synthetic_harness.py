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
                     ip_id=1000, ip_total_len=None):
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
                                  0x45, 0, tot_len, ip_id, 0, 64, 6, 0,
                                  src_bytes, dst_bytes)
    cksum = ip_checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, tot_len, ip_id, 0, 64, 6, cksum,
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
    pkt_ov2 = make_ipv4_packet("10.0.0.1", "10.0.0.2", 50006, 80, 7010, 0, 0x18, b"lap HTTP/1.1\r\nHost: a\r\n\r\n")
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
    write_pcap(tmp_pcap, [(1017, 0, pkt_r17_1, len(pkt_r17_1)),
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

def run_regression_suite():
    print("=== Running Dual-Engine Synthetic Packet Regression Suite ===")
    subprocess.run(["make", "pcap_test_cpp"], cwd=OLD_DIR, check=True)
    all_failures = []
    for engine_name, run_func in (("C++", run_cpp_pcap), ("Python", run_python_pcap)):
        failures = run_test_suite_for_engine(run_func, engine_name)
        all_failures.extend(failures)

    print("\n--- Overall Summary: %d failures across all test runs ---" % len(all_failures))
    if all_failures:
        print("Failures:")
        for f in all_failures:
            print("  *", f)
        sys.exit(1)
    else:
        print("ALL DUAL-ENGINE SYNTHETIC REGRESSION TESTS PASSED (44/44 PASS)!")

if __name__ == "__main__":
    run_regression_suite()
