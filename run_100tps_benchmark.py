#!/usr/bin/env python3
import os, sys, time, subprocess, json, threading

OLD_DIR = "/home/ubuntu/Viettel/NetworkTracing/oldkernel"
MEASURE_PY = os.path.join(OLD_DIR, "measure_usage.py")

from measure_usage import get_proc_stats, monitor_pid

def setup_veth():
    subprocess.run(["sudo", "ip", "netns", "del", "nt_client"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "del", "ntv0"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "add", "ntv0", "type", "veth", "peer", "name", "ntv1"], check=True)
    subprocess.run(["sudo", "ip", "addr", "add", "192.0.2.1/24", "dev", "ntv0"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "ntv0", "up"], check=True)
    subprocess.run(["sudo", "ip", "netns", "add", "nt_client"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "ntv1", "netns", "nt_client"], check=True)
    subprocess.run(["sudo", "ip", "netns", "exec", "nt_client", "ip", "addr", "add", "192.0.2.2/24", "dev", "ntv1"], check=True)
    subprocess.run(["sudo", "ip", "netns", "exec", "nt_client", "ip", "link", "set", "ntv1", "up"], check=True)
    subprocess.run(["sudo", "ip", "netns", "exec", "nt_client", "ip", "route", "add", "default", "via", "192.0.2.1", "dev", "ntv1"], check=True)

def cleanup_veth():
    subprocess.run(["sudo", "ip", "netns", "del", "nt_client"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "del", "ntv0"], stderr=subprocess.DEVNULL)

def install_agent(mode="cpp", wsse_bytes=16384):
    env = os.environ.copy()
    env["NT_IFACE"] = "ntv0"
    env["NT_PORTS"] = "18080"
    cmd = ["sudo", "-E", "sh", os.path.join(OLD_DIR, "install-oldkernel.sh"),
           "--mode", mode,
           "--endpoint", "http://127.0.0.1:30102",
           "--wsse-body-bytes", str(wsse_bytes)]
    subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    time.sleep(1.0)

def find_agent_pids(mode="cpp"):
    pids = []
    if mode == "cpp":
        p = subprocess.run(["pgrep", "-f", "/opt/networktracing-legacy/nt-sniff-cpp"], stdout=subprocess.PIPE, text=True)
        pids = [int(x) for x in p.stdout.split() if x.strip()]
    else:
        p1 = subprocess.run(["pgrep", "-f", "/opt/networktracing-legacy/nt-sniff.py"], stdout=subprocess.PIPE, text=True)
        p2 = subprocess.run(["pgrep", "-f", "/opt/networktracing-legacy/nt-ship.py"], stdout=subprocess.PIPE, text=True)
        pids = [int(x) for x in (p1.stdout + " " + p2.stdout).split() if x.strip()]
    return pids

def benchmark_agent(mode="cpp", duration=15, target_tps=100, is_wsse=True):
    install_agent(mode=mode, wsse_bytes=16384)
    pids = find_agent_pids(mode=mode)
    if not pids:
        raise RuntimeError(f"Could not find agent PIDs for mode={mode}")

    initial_stats = [get_proc_stats(pid) for pid in pids]
    initial_rss_kb = sum(s[1] for s in initial_stats if s)

    # Launch background monitor
    monitor_samples = []
    stop_event = threading.Event()
    def monitor_thread():
        nonlocal monitor_samples
        monitor_samples = monitor_pid(pids, duration + 2, sample_interval=0.2)

    mon_t = threading.Thread(target=monitor_thread)
    mon_t.start()

    time.sleep(0.5)

    # Launch client inside namespace
    endpoint = "http://192.0.2.1:18080/wsse" if is_wsse else "http://192.0.2.1:18080/healthz"
    wsse_arg = "wsse" if is_wsse else "basic"
    client_cmd = ["sudo", "ip", "netns", "exec", "nt_client",
                  "python3", MEASURE_PY, "client", endpoint, str(target_tps), str(duration), wsse_arg]

    client_res = subprocess.run(client_cmd, stdout=subprocess.PIPE, text=True)
    mon_t.join()

    client_data = json.loads(client_res.stdout) if client_res.stdout else {}

    # Analyze samples
    cpu_samples = [s["cpu_pct"] for s in monitor_samples if s["cpu_pct"] > 0]
    rss_samples = [s["rss_kb"] for s in monitor_samples if s["rss_kb"] > 0]

    avg_cpu = round(sum(cpu_samples) / max(1, len(cpu_samples)), 2) if cpu_samples else 0.0
    peak_cpu = round(max(cpu_samples), 2) if cpu_samples else 0.0
    peak_rss_kb = max(rss_samples) if rss_samples else initial_rss_kb

    return {
        "mode": mode,
        "payload_type": "SOAP WSSE XML" if is_wsse else "HTTP Basic Auth",
        "requests_sent": client_data.get("sent", 0),
        "duration_sec": client_data.get("duration", duration),
        "actual_tps": client_data.get("actual_tps", 0.0),
        "initial_rss_mb": round(initial_rss_kb / 1024.0, 2),
        "peak_rss_mb": round(peak_rss_kb / 1024.0, 2),
        "avg_cpu_pct_1core": avg_cpu,
        "peak_cpu_pct_1core": peak_cpu,
        "pids": pids
    }

if __name__ == "__main__":
    setup_veth()
    try:
        print("Benchmarking C++ Agent at 100 TPS (SOAP WSSE)...")
        res_cpp = benchmark_agent(mode="cpp", duration=15, target_tps=100, is_wsse=True)
        print(json.dumps(res_cpp, indent=2))

        print("\nBenchmarking Python Agent at 100 TPS (SOAP WSSE)...")
        res_py = benchmark_agent(mode="python", duration=15, target_tps=100, is_wsse=True)
        print(json.dumps(res_py, indent=2))
    finally:
        cleanup_veth()
        # Restore service on enp0s6
        env = os.environ.copy()
        env["NT_IFACE"] = "enp0s6"
        env["NT_PORTS"] = "18080"
        cmd = ["sudo", "-E", "sh", os.path.join(OLD_DIR, "install-oldkernel.sh"),
               "--mode", "cpp", "--endpoint", "http://127.0.0.1:30102", "--wsse-body-bytes", "16384"]
        subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("\nService restored to enp0s6.")
