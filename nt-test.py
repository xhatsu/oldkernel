#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nt-test.py — Cong cu chay thu, kiem tra va do tai NetworkTracing Legacy Agent.

Usage:
  ./nt-test.py mock               : Ban cac request mau (200, 404, 500, delay) & check ket qua tren Hub
  ./nt-test.py stress [N] [W]     : Chay do tai stress test (mac dinh: N=1000 requests, W=40 workers)
  ./nt-test.py hub [limit] [user] : Truy van event truc tiep tu Hub Database
  ./nt-test.py deploy-cpp         : Go bo va cai dat lai che do Native C++ tren VM
  ./nt-test.py deploy-py          : Go bo va cai dat lai che do Python tren VM
  ./nt-test.py full               : Chay toan bo quy trinh kiem thu tu dong (All Gates)
"""

import urllib.request
import urllib.error
import multiprocessing
import subprocess
import base64
import time
import json
import sys
import os

VM_HOST = "192.168.122.236"
VM_PORT = 8010
HUB_ENDPOINT = "http://129.150.59.233:31115"
HUB_EVENTS = "http://129.150.59.233:31115/api/events"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SSH_EXEC = "/home/xhatsu/.gemini/antigravity-cli/brain/12d0d0ea-3ede-4452-80fb-803e659c1d06/scratch/ssh_exec.py"

def ssh(cmd):
    p = subprocess.run(["python3", SSH_EXEC, cmd], capture_output=True, text=True)
    return p.stdout.strip()

# -------------------------------------------------------------
# 1. COMMAND: MOCK TEST & VERIFY
# -------------------------------------------------------------
def cmd_mock():
    print("==================================================================")
    print("=== 1. GỬI CÁC REQUEST MẪU VỚI MOCK STATUS & LATENCY ===")
    print("==================================================================")
    uid = int(time.time()) % 10000
    tests = [
        (f"user_m200_{uid}", "GET",  "/v1/charge/charge_ok?status=200", None),
        (f"user_m201_{uid}", "POST", "/v1/charge/create_order?status=201", '{"order":123}'),
        (f"user_m400_{uid}", "GET",  "/v1/charge/bad_param?status=400", None),
        (f"user_m404_{uid}", "GET",  "/v1/charge/not_found?status=404", None),
        (f"user_m500_{uid}", "POST", "/v1/charge/db_fail?status=500", '{"err":"db"}'),
        (f"user_m503_{uid}", "GET",  "/v1/charge/maintenance?status=503", None),
        (f"user_mslow_{uid}","GET",  "/v1/charge/slow_tx?delay=200", None),
    ]

    for user, method, path, body in tests:
        url = f"http://{VM_HOST}:{VM_PORT}{path}"
        auth = base64.b64encode((user + ":pass123").encode("ascii")).decode("ascii")
        headers = {"Authorization": "Basic " + auth, "User-Agent": "NtTester/1.0"}
        data = body.encode("utf-8") if body else None
        if data: headers["Content-Type"] = "application/json"
        
        req = urllib.request.Request(url, data=data, headers=headers)
        req.get_method = lambda: method
        t0 = time.time()
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            code = resp.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            code = -1
        dur = (time.time() - t0) * 1000
        print("  - Req: %-18s | Method: %-4s | Status: %d | Time: %5.1f ms" % (user, method, code, dur))

    print("\nChờ 6s để Agent đóng gói và gửi về Hub...")
    time.sleep(6)

    print("\n==================================================================")
    print("=== 2. KẾT QUẢ ĐÃ GHI NHẬN TRÊN HUB API (129.150.59.233:31115) ===")
    print("==================================================================")
    url_q = f"{HUB_EVENTS}?limit=100"
    req = urllib.request.urlopen(url_q, timeout=10)
    data = json.loads(req.read().decode("utf-8"))
    events = data if isinstance(data, list) else data.get("events", [])
    matched = [e for e in events if e.get("host") == "testVM1" and str(e.get("user")).endswith(str(uid))]

    print(f"Tìm thấy {len(matched)}/{len(tests)} events khớp với đợt test vừa gửi:\n")
    for e in sorted(matched, key=lambda x: x.get("id", 0)):
        print(json.dumps({
            "id": e.get("id"),
            "user": e.get("user"),
            "method": e.get("method"),
            "route": e.get("path"),
            "status": e.get("status"),
            "duration_ms": e.get("duration_ms"),
            "error": e.get("error"),
            "error_kind": e.get("error_kind"),
            "upstream": f"{e.get('dst_ip')}:{e.get('dst_port')}"
        }, indent=2))

# -------------------------------------------------------------
# 2. COMMAND: STRESS TEST (2000+ RPS)
# -------------------------------------------------------------
def _stress_worker(num_requests, worker_id, results_queue):
    auth = base64.b64encode(f"stress_w_{worker_id}:p123".encode("ascii")).decode("ascii")
    headers = {"Authorization": "Basic " + auth, "User-Agent": "StressRunner/1.0"}
    url = f"http://{VM_HOST}:{VM_PORT}/v1/charge/stress"
    
    success, errors = 0, 0
    t0 = time.time()
    for _ in range(num_requests):
        try:
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.getcode() == 200:
                success += 1
            else:
                errors += 1
        except Exception:
            errors += 1
    results_queue.put((success, errors, time.time() - t0))

def cmd_stress(total_requests=1000, num_workers=40):
    reqs_per_worker = total_requests // num_workers
    print("==================================================================")
    print(f"=== BẮT ĐẦU ĐO TẢI STRESS TEST ({total_requests} REQUESTS, {num_workers} LUỒNG) ===")
    print("==================================================================")
    
    q = multiprocessing.Queue()
    procs = []
    t_start = time.time()

    for i in range(num_workers):
        p = multiprocessing.Process(target=_stress_worker, args=(reqs_per_worker, i+1, q))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()

    wall_clock = time.time() - t_start
    total_success, total_errors = 0, 0
    while not q.empty():
        s, e, _ = q.get()
        total_success += s
        total_errors += e

    rps = total_success / wall_clock if wall_clock > 0 else 0
    print("------------------------------------------------------------------")
    print(f"• Tổng số gửi:      {total_requests}")
    print(f"• Thành công (200):  {total_success}")
    print(f"• Lỗi (Errors):     {total_errors}")
    print(f"• Thời gian:        {wall_clock:.3f} giây")
    print(f"• Thông lượng đạt:  \033[92m{rps:.1f} RPS\033[0m")
    print("------------------------------------------------------------------")

    # Kiem tra RAM/CPU Agent tren VM
    print("\n>>> Mức chiếm dụng RAM/CPU của Agent trên VM ngay sau test:")
    stats = ssh("ps -u root -o pid,pcpu,pmem,rss,comm | grep -E 'nt-sniff|nt-ship'")
    print("PID   %CPU %MEM   RSS(KB) COMMAND")
    print(stats)

# -------------------------------------------------------------
# 3. COMMAND: QUERY HUB
# -------------------------------------------------------------
def cmd_hub(limit=20, filter_user=None):
    print("==================================================================")
    print(f"=== TRUY VẤN {limit} SỰ KIỆN MỚI NHẤT TRÊN HUB API ===")
    print("==================================================================")
    url = f"{HUB_EVENTS}?limit={limit}&order=desc"
    if filter_user:
        url += f"&user={filter_user}"
    req = urllib.request.urlopen(url, timeout=10)
    data = json.loads(req.read().decode("utf-8"))
    events = data if isinstance(data, list) else data.get("events", [])
    
    for e in events:
        print("ID=%-6s | Host=%-8s | User=%-18s | Route=%-24s | Status=%-4s | Dur=%-4sms | Error=%s" % (
            e.get("id"), e.get("host"), str(e.get("user")), str(e.get("path")),
            str(e.get("status")), str(e.get("duration_ms")), str(e.get("error"))
        ))

# -------------------------------------------------------------
# 4. COMMAND: DEPLOY MODES
# -------------------------------------------------------------
def cmd_deploy(mode):
    print("==================================================================")
    print(f"=== GỠ BỎ VÀ CÀI ĐẶT LẠI AGENT CHẾ ĐỘ: {mode.upper()} ===")
    print("==================================================================")
    subprocess.run(["python3", SSH_EXEC, "--copy-kit", "/tmp/networktracing-el67-test/kit"], capture_output=True)
    cmd = f"""
service networktracing-legacy stop 2>/dev/null || true
pkill -9 -f nt-sniff 2>/dev/null || true
pkill -9 -f nt-ship 2>/dev/null || true
cd /tmp/networktracing-el67-test/kit
sudo NT_CAPTURE_MODE={mode} NT_IFACE=eth0 NT_PORTS=8010 sh install-oldkernel.sh --endpoint {HUB_ENDPOINT}
service networktracing-legacy status
ps -ef | grep -E '[n]t-sniff|[n]t-ship'
"""
    out = ssh(cmd)
    print(out)

# -------------------------------------------------------------
# 5. MAIN DISPATCHER
# -------------------------------------------------------------
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return

    cmd = sys.argv[1].lower()
    if cmd == "mock":
        cmd_mock()
    elif cmd == "stress":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
        w = int(sys.argv[3]) if len(sys.argv) > 3 else 40
        cmd_stress(n, w)
    elif cmd == "hub":
        lim = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        usr = sys.argv[3] if len(sys.argv) > 3 else None
        cmd_hub(lim, usr)
    elif cmd in ("deploy-cpp", "cpp"):
        cmd_deploy("cpp")
    elif cmd in ("deploy-py", "py", "python"):
        cmd_deploy("python")
    else:
        print(f"Lệnh không hợp lệ: '{cmd}'. Xem trợ giúp:")
        print(__doc__)

if __name__ == "__main__":
    main()
