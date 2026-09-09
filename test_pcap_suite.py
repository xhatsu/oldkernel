#!/usr/bin/env python3
import struct, os, sys, time, json, subprocess, importlib.util, signal
__test__ = False

OLD_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = "/home/ubuntu/Viettel/Data"
PCAP_247 = os.path.join(DATA_DIR, "tcpdump_10.240.147.247.pcap")
PCAP_249 = os.path.join(DATA_DIR, "tcpdump_10.240.147.249.pcap")

# Load nt-sniff module dynamically
spec = importlib.util.spec_from_file_location("nt_sniff", os.path.join(OLD_DIR, "nt-sniff.py"))
nt_sniff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nt_sniff)

def test_offline_python(pcap_path, ports, wsse_bytes):
    flows = {}
    pending = {}
    out = []
    ports_set = set(ports)
    node_host = "test-py-offline"

    t0 = time.time()
    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        linktype = struct.unpack("<I", gh[20:24])[0]
        swap = (struct.unpack("<I", gh[:4])[0] == 0xd4c3b2a1)
        pkt_count = 0
        while True:
            ph = f.read(16)
            if not ph: break
            ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", ph)
            if swap:
                incl_len = ((incl_len >> 24) & 0xff) | ((incl_len >> 8) & 0xff00) | \
                           ((incl_len << 8) & 0xff0000) | ((incl_len << 24) & 0xff000000)
            raw = f.read(incl_len)
            pkt_count += 1
            now = ts_sec + ts_usec / 1e6

            # SLL (113) vs Ethernet (1)
            if linktype == 113:
                if len(raw) < 16 + 20: continue
                proto = struct.unpack("!H", raw[14:16])[0]
                if proto != 0x0800: continue
                ip = raw[16:]
            elif linktype == 1:
                if len(raw) < 14 + 20: continue
                proto = struct.unpack("!H", raw[12:14])[0]
                if proto != 0x0800: continue
                ip = raw[14:]
            else:
                continue

            if (ip[0] >> 4) != 4 or ip[9] != 6: continue
            ihl = (ip[0] & 0x0f) * 4
            if len(ip) < ihl + 20: continue
            tcp = ip[ihl:ihl+20]
            sp, dp = struct.unpack("!HH", tcp[:4])
            doff = (tcp[12] >> 4) * 4
            pay = ip[ihl+doff:]
            flags = tcp[13]
            src_ip = ".".join(map(str, ip[12:16]))
            dst_ip = ".".join(map(str, ip[16:20]))

            if sp in ports_set and dp not in ports_set:
                rk = (src_ip, sp, dst_ip, dp)
                if pay[:5] == b"HTTP/":
                    nt_sniff.correlate_response(pending, rk, pay, now, out)
                elif flags & 0x05:
                    nt_sniff.pending_pop(rk, out, pending)
            elif dp in ports_set:
                if flags & 0x05:
                    rk = (dst_ip, dp, src_ip, sp)
                    nt_sniff.pending_pop(rk, out, pending)
                key = (src_ip, sp, dst_ip, dp)
                nt_sniff.handle_payload(flows, key, None, pay, (dst_ip, dp, src_ip, sp),
                                        ports_set, node_host, out, pending, now, wsse_bytes)

    nt_sniff.drain_incomplete_wsse(flows, out, pending, time.time())
    nt_sniff.drain_pending(pending, out)
    elapsed = time.time() - t0
    return {
        "packets": pkt_count,
        "events": len(out),
        "elapsed": elapsed,
        "rate": int(pkt_count / max(0.001, elapsed)),
        "users": sorted(list(set(e["user"] for e in out if e.get("user")))),
        "schemes": sorted(list(set(e["scheme"] for e in out if e.get("scheme")))),
        "services": sorted(list(set(e["service"] for e in out))),
        "statuses": sorted(list(set(e["status"] for e in out if e.get("status") is not None))),
        "traces": sum(1 for e in out if e.get("traceparent")),
        "sample": out[0] if out else None
    }

def test_offline_cpp(pcap_path, ports, wsse_bytes=0):
    t0 = time.time()
    cmd = [os.path.join(OLD_DIR, "pcap_test_cpp"), pcap_path]
    if wsse_bytes:
        cmd += ["--wsse-body-bytes", str(wsse_bytes)]
    cmd += [str(p) for p in ports]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed = time.time() - t0
    lines = [ln for ln in p.stdout.splitlines() if ln.startswith("{")]
    events = [json.loads(ln) for ln in lines]
    return {
        "events": len(events),
        "elapsed": elapsed,
        "stderr": p.stderr.strip(),
        "users": sorted(list(set(e["user"] for e in events if e.get("user") and e["user"] != "-anonymous-"))),
        "schemes": sorted(list(set(e["scheme"] for e in events if e.get("scheme") and e["scheme"] != "none"))),
        "services": sorted(list(set(e["service"] for e in events))),
        "statuses": sorted(list(set(e["status"] for e in events if e.get("status") is not None))),
        "traces": sum(1 for e in events if e.get("traceparent")),
        "secret_leaks": any(token in p.stdout for token in
                            ("PasswordDigest", "soap:Envelope", "SENSITIVE_PASSWORD")),
        "sample": events[0] if events else None
    }

def test_live_veth(pcap_path, ports, mode="python", wsse_bytes=8192):
    import socket
    veth_inj = "nt_inj0"
    veth_cap = "nt_cap0"
    out_file = "/tmp/nt_live_test.jsonl"
    err_file = "/tmp/nt_live_test.err"
    if os.path.exists(out_file): os.remove(out_file)
    if os.path.exists(err_file): os.remove(err_file)

    # Teardown any existing veth
    subprocess.run(["sudo", "ip", "link", "del", veth_inj], stderr=subprocess.DEVNULL)
    # Create veth pair
    subprocess.run(["sudo", "ip", "link", "add", veth_inj, "type", "veth", "peer", "name", veth_cap], check=True)
    subprocess.run(["sudo", "ip", "link", "set", veth_inj, "up"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", veth_cap, "up"], check=True)

    # Start sniffer
    ports_str = ",".join(str(p) for p in ports)
    if mode == "python":
        agent_cmd = ["python3", "-u", os.path.join(OLD_DIR, "nt-sniff.py"),
                     "-i", veth_cap, "-p", ports_str, "--wsse-body-bytes", str(wsse_bytes)]
    else:
        agent_cmd = [os.path.join(OLD_DIR, "nt-sniff-cpp"),
                     "-i", veth_cap, "-p", ports_str,
                     "--wsse-body-bytes", str(wsse_bytes)]

    with open(out_file, "w") as out_f, open(err_file, "w") as err_f:
        agent_proc = subprocess.Popen(agent_cmd, stdout=out_f, stderr=err_f)

    time.sleep(0.5)

    # Replay packets from PCAP into veth_inj using AF_PACKET
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((veth_inj, 0))

    injected = 0
    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        linktype = struct.unpack("<I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if not ph: break
            _, _, incl_len, _ = struct.unpack("<IIII", ph)
            raw = f.read(incl_len)
            if linktype == 113:
                if len(raw) < 16: continue
                eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + raw[14:16] + raw[16:]
            else:
                eth = raw
            try:
                s.send(eth)
                injected += 1
            except Exception:
                pass
    s.close()
    time.sleep(1.0)

    # Stop sniffer cleanly with SIGTERM so pending buffers drain
    agent_proc.terminate()
    try:
        agent_proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        agent_proc.kill()
        agent_proc.wait()

    # Read captured events
    events = []
    if os.path.exists(out_file):
        with open(out_file) as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("{"):
                    events.append(json.loads(ln))

    # Teardown veth
    subprocess.run(["sudo", "ip", "link", "del", veth_inj], stderr=subprocess.DEVNULL)
    if os.path.exists(out_file): os.remove(out_file)
    if os.path.exists(err_file): os.remove(err_file)

    return {
        "injected": injected,
        "captured_events": len(events),
        "users": sorted(list(set(e["user"] for e in events if e.get("user") and e["user"] != "-anonymous-"))),
        "statuses": sorted(list(set(e["status"] for e in events if e.get("status") is not None))),
        "traces": sum(1 for e in events if e.get("traceparent"))
    }

if __name__ == "__main__":
    print("=== PCAP 247: Python Offline (WSSE=8192) ===")
    res_py_247 = test_offline_python(PCAP_247, [8001], 8192)
    print(json.dumps(res_py_247, indent=2, default=str))

    print("\n=== PCAP 247: C++ Offline ===")
    res_cpp_247 = test_offline_cpp(PCAP_247, [8001], 8192)
    assert "product" in res_cpp_247["users"] and "wsse" in res_cpp_247["schemes"]
    assert not res_cpp_247["secret_leaks"]
    print(json.dumps(res_cpp_247, indent=2, default=str))

    print("\n=== PCAP 249: Python Offline (WSSE=8192) ===")
    res_py_249 = test_offline_python(PCAP_249, [8003, 8005, 8007, 8009, 8010, 8011], 8192)
    print(json.dumps({k: v for k, v in res_py_249.items() if k != "sample"}, indent=2))

    print("\n=== PCAP 249: C++ Offline ===")
    res_cpp_249 = test_offline_cpp(PCAP_249, [8003, 8005, 8007, 8009, 8010, 8011], 8192)
    assert "wsse" in res_cpp_249["schemes"] and not res_cpp_249["secret_leaks"]
    print(json.dumps({k: v for k, v in res_cpp_249.items() if k != "sample"}, indent=2))

    print("\n=== PCAP 247: Live Kernel VETH Capture (Python) ===")
    res_live_py = test_live_veth(PCAP_247, [8001], mode="python", wsse_bytes=8192)
    print(json.dumps(res_live_py, indent=2))

    print("\n=== PCAP 247: Live Kernel VETH Capture (C++) ===")
    res_live_cpp = test_live_veth(PCAP_247, [8001], mode="cpp")
    print(json.dumps(res_live_cpp, indent=2))
