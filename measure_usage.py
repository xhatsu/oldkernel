#!/usr/bin/env python3
import os, sys, time, subprocess, threading, json, urllib.request

CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])

def get_proc_stats(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            utime = int(parts[13])
            stime = int(parts[14])
        rss_kb = 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        io_r, io_w = 0, 0
        try:
            with open(f"/proc/{pid}/io") as f:
                for line in f:
                    if line.startswith("read_bytes:"): io_r = int(line.split()[1])
                    elif line.startswith("write_bytes:"): io_w = int(line.split()[1])
        except Exception:
            pass
        return utime + stime, rss_kb, io_r, io_w
    except Exception:
        return None

def monitor_pid(pids, duration, sample_interval=0.2):
    samples = []
    t_end = time.time() + duration
    prev = {pid: (get_proc_stats(pid), time.time()) for pid in pids}
    time.sleep(sample_interval)
    while time.time() < t_end:
        now = time.time()
        for pid in pids:
            cur = get_proc_stats(pid)
            if cur and pid in prev and prev[pid][0]:
                prev_stat, prev_t = prev[pid]
                dt = now - prev_t
                dticks = cur[0] - prev_stat[0]
                cpu_pct = (dticks / CLK_TCK) / dt * 100.0 if dt > 0 else 0.0
                samples.append({
                    "pid": pid,
                    "time": now,
                    "cpu_pct": cpu_pct,
                    "rss_kb": cur[1],
                    "io_w": cur[3]
                })
            prev[pid] = (cur, now)
        time.sleep(sample_interval)
    return samples

def run_load_client(target_url, target_tps=100, duration=15, is_wsse=False):
    import http.client, urllib.parse
    url = urllib.parse.urlparse(target_url)
    host = url.hostname
    port = url.port or 80
    path = url.path or "/"

    soap_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        '<soap:Header><wsse:Security><wsse:UsernameToken><wsse:Username>bench.user</wsse:Username>'
        '<wsse:Password Type="PasswordDigest">DigestSecret</wsse:Password>'
        '</wsse:UsernameToken></wsse:Security></soap:Header>'
        '<soap:Body><Ping/></soap:Body></soap:Envelope>'
    ).encode("utf-8")

    sent = [0]
    errors = [0]
    t_end = time.time() + duration
    interval = 1.0 / target_tps

    # Use a persistent HTTP connection pool in a thread pool
    def worker(worker_id, worker_count):
        conn = http.client.HTTPConnection(host, port, timeout=2.0)
        headers = {
            "Host": f"{host}:{port}",
            "Connection": "keep-alive",
            "traceparent": "00-33333333333333333333333333333333-4444444444444444-01"
        }
        if is_wsse:
            headers["Content-Type"] = "text/xml; charset=utf-8"
            headers["Content-Length"] = str(len(soap_body))
        else:
            headers["Authorization"] = "Basic YmVuY2gudXNlcjpTZWNyZXQxMjM="

        local_sent = 0
        while time.time() < t_end:
            t0 = time.time()
            try:
                if is_wsse:
                    conn.request("POST", path, body=soap_body, headers=headers)
                else:
                    conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                resp.read()
                sent[0] += 1
                local_sent += 1
            except Exception:
                errors[0] += 1
                try: conn.close()
                except Exception: pass
                conn = http.client.HTTPConnection(host, port, timeout=2.0)
            
            elapsed = time.time() - t0
            sleep_t = (interval * worker_count) - elapsed
            if sleep_t > 0:
                time.sleep(sleep_t)
        try: conn.close()
        except Exception: pass

    num_workers = 10
    threads = []
    t_start = time.time()
    for i in range(num_workers):
        t = threading.Thread(target=worker, args=(i, num_workers))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    total_time = time.time() - t_start
    actual_tps = sent[0] / max(0.001, total_time)
    return {
        "sent": sent[0],
        "errors": errors[0],
        "duration": round(total_time, 2),
        "actual_tps": round(actual_tps, 1)
    }

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "client"
    if mode == "client":
        url = sys.argv[2] if len(sys.argv) > 2 else "http://192.0.2.1:18080/healthz"
        tps = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        dur = int(sys.argv[4]) if len(sys.argv) > 4 else 15
        is_wsse = (len(sys.argv) > 5 and sys.argv[5] == "wsse")
        res = run_load_client(url, tps, dur, is_wsse)
        print(json.dumps(res))
