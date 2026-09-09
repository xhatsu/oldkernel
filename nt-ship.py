#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-ship.py — event shipper for old-kernel nodes (python 2.6 compatible).

Reads NetworkTracing JSONL events on stdin, batches them, and POSTs to the Hub
/api/ingest. Uploads use bounded memory and drop on overload or Hub failure;
the compatibility --spool option does not enable disk writes.

Usage:
  NT_SHIP_RATE_KBPS=1024 python nt-ship.py --endpoint http://hub:31115
"""
from __future__ import print_function

import errno, json, os, select, signal, socket, sys

# py2.6/el6 names first; py3 fallbacks for dev-box testing. The urllib2
# str-vs-bytes encode guard in flush() stays — do not remove.
try:
    import Queue                      # py2: Queue module, class Queue.Queue
    import urllib2
except ImportError:                   # py3
    import queue as Queue
    import urllib.request as urllib2
import threading, time

MAX_BATCH = 400
MAX_POST_BYTES = 65536
MAX_STATS_BYTES = 16384
MAX_QUEUE_BATCHES = 16
MAX_SHIP_THREADS = 8
THREAD_STACK_BYTES = 262144
DEFAULT_RATE_KBPS = 1024
MIN_RATE_KBPS = 64
MAX_RATE_KBPS = 10000
FLUSH_SEC = 5.0


def log(msg):
    sys.stderr.write("nt-ship: %s\n" % msg)
    sys.stderr.flush()


class RateLimiter(object):
    """Reserve aggregate upload slots across all poster threads."""
    def __init__(self, kbps):
        self.bytes_per_sec = max(1, (kbps * 1000) // 8)
        self.next_slot = 0.0
        self.lock = threading.Lock()

    def wait(self, size):
        now = time.time()
        self.lock.acquire()
        try:
            if self.next_slot < now or self.next_slot - now > 60.0:
                self.next_slot = now
            slot = self.next_slot
            self.next_slot += float(size) / self.bytes_per_sec
        finally:
            self.lock.release()
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


def read_bounded_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def configure_thread_stack():
    """Bound virtual stack reservation for future Python poster threads."""
    try:
        threading.stack_size(THREAD_STACK_BYTES)
        return True
    except (ValueError, RuntimeError):
        log("WARN: cannot set %d-byte poster stack; thread startup remains adaptive" %
            THREAD_STACK_BYTES)
        return False


def take_bounded_batch(buf, node, on_drop=None):
    """Remove one <=64 KiB encoded batch, dropping impossible giant events."""
    while buf:
        batch = []
        empty_size = len(json.dumps({"node": node, "events": []},
                                    separators=(",", ":")).encode("utf-8"))
        encoded_size = empty_size
        for event in buf[:MAX_BATCH]:
            event_size = len(json.dumps(event, separators=(",", ":")).encode("utf-8"))
            candidate_size = encoded_size + event_size + (1 if batch else 0)
            if candidate_size > MAX_POST_BYTES:
                break
            batch.append(event)
            encoded_size = candidate_size
        if batch:
            del buf[:len(batch)]
            return batch
        del buf[0]
        if on_drop is not None:
            on_drop("oversized", 1)
        log("WARN: dropped oversized event; encoded body exceeds %d bytes" %
            MAX_POST_BYTES)
    return []


class ShipStats(object):
    """Small locked counter set shared by the bounded poster threads."""
    KEYS = ("events_in", "events_pushed", "events_dropped",
            "batches_pushed", "batches_failed", "bytes_pushed",
            "queue_full", "hub_failure", "oversized",
            "stats_samples_dropped")

    def __init__(self):
        self.lock = threading.Lock()
        self.total = dict((key, 0) for key in self.KEYS)
        self.previous = dict(self.total)
        self.last_at = time.time()
        self.last_cpu = None
        self.sequence = 0
        self.queued_events = 0
        self.queue_high_water = 0
        self.instance_id = "%d-%d" % (int(self.last_at), os.getpid())
        self.last_push_http_status = 0
        self.last_success_at = 0
        self.consecutive_failures = 0
        self.pending_sample = None

    def add(self, key, value=1):
        self.lock.acquire()
        try:
            self.total[key] += int(value)
        finally:
            self.lock.release()

    def dropped(self, cause, count):
        self.lock.acquire()
        try:
            self.total["events_dropped"] += int(count)
            self.total[cause] += int(count)
        finally:
            self.lock.release()

    def batch_success(self, count, body_bytes):
        self.lock.acquire()
        try:
            self.total["events_pushed"] += int(count)
            self.total["batches_pushed"] += 1
            self.total["bytes_pushed"] += int(body_bytes)
            self.last_push_http_status = 200
            self.last_success_at = int(time.time())
            self.consecutive_failures = 0
        finally:
            self.lock.release()

    def batch_failure(self, count):
        self.lock.acquire()
        try:
            self.total["batches_failed"] += 1
            self.total["events_dropped"] += int(count)
            self.total["hub_failure"] += int(count)
            self.last_push_http_status = 0
            self.consecutive_failures += 1
        finally:
            self.lock.release()

    def queued(self, delta):
        self.lock.acquire()
        try:
            self.queued_events = max(0, self.queued_events + int(delta))
            if self.queued_events > self.queue_high_water:
                self.queue_high_water = self.queued_events
        finally:
            self.lock.release()

    def offer_stats(self, sample):
        """Coalesce stats to one latest in-memory sample."""
        self.lock.acquire()
        try:
            needs_queue_item = self.pending_sample is None
            if not needs_queue_item:
                self.total["stats_samples_dropped"] += 1
            self.pending_sample = sample
            return needs_queue_item
        finally:
            self.lock.release()

    def take_stats(self):
        self.lock.acquire()
        try:
            sample = self.pending_sample
            self.pending_sample = None
            return sample
        finally:
            self.lock.release()

    def _resources(self, elapsed):
        times = os.times()
        cpu_total = float(times[0] + times[1])
        cpu_percent = 0.0
        if self.last_cpu is not None:
            cpu_percent = 100.0 * max(0.0, cpu_total - self.last_cpu) / elapsed
        self.last_cpu = cpu_total
        rss = 0
        virtual = 0
        try:
            for line in open("/proc/self/status", "r"):
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
                elif line.startswith("VmSize:"):
                    virtual = int(line.split()[1]) * 1024
        except (IOError, OSError, ValueError, IndexError):
            pass
        try:
            open_fds = len(os.listdir("/proc/self/fd"))
        except OSError:
            open_fds = 0
        active_count = getattr(threading, "active_count", threading.activeCount)
        return {"cpu_user_seconds": round(float(times[0]), 3),
                "cpu_system_seconds": round(float(times[1]), 3),
                "cpu_percent_one_core": round(cpu_percent, 4),
                "rss_bytes": rss, "virtual_bytes": virtual,
                "open_fds": open_fds,
                "threads": active_count()}

    def snapshot(self, capture, node, mode, rate_kbps, ship_threads,
                 wsse_body_bytes, buffered_events, queue_capacity):
        now = time.time()
        elapsed = max(0.001, now - self.last_at)
        self.lock.acquire()
        try:
            totals = dict(self.total)
            deltas = dict((key, totals[key] - self.previous[key])
                          for key in self.KEYS)
            self.previous = dict(totals)
            self.sequence += 1
            sequence = self.sequence
            queued_events = self.queued_events
            queue_high_water = self.queue_high_water
            last_push_http_status = self.last_push_http_status
            last_success_at = self.last_success_at
            consecutive_failures = self.consecutive_failures
        finally:
            self.lock.release()
        self.last_at = now
        drop_percent = (100.0 * deltas["events_dropped"] /
                        max(1, deltas["events_in"]))
        reasons = []
        if capture.get("kernel_drops_delta", 0): reasons.append("kernel_drop")
        if deltas["events_dropped"]: reasons.append("ship_drop")
        if deltas["hub_failure"]: reasons.append("hub_unreachable")
        if deltas["queue_full"]: reasons.append("queue_pressure")
        shipping = {
            "events_in_total": totals["events_in"],
            "events_in_delta": deltas["events_in"],
            "events_pushed_total": totals["events_pushed"],
            "events_pushed_delta": deltas["events_pushed"],
            "events_dropped_total": totals["events_dropped"],
            "events_dropped_delta": deltas["events_dropped"],
            "drop_causes": {
                "queue_full_total": totals["queue_full"],
                "queue_full_delta": deltas["queue_full"],
                "hub_failure_total": totals["hub_failure"],
                "hub_failure_delta": deltas["hub_failure"],
                "oversized_total": totals["oversized"],
                "oversized_delta": deltas["oversized"]},
            "batches_pushed_total": totals["batches_pushed"],
            "batches_pushed_delta": deltas["batches_pushed"],
            "batches_failed_total": totals["batches_failed"],
            "batches_failed_delta": deltas["batches_failed"],
            "bytes_pushed_total": totals["bytes_pushed"],
            "bytes_pushed_delta": deltas["bytes_pushed"],
            "push_events_per_second": round(deltas["events_pushed"] / elapsed, 4),
            "push_kbps": round(8.0 * deltas["bytes_pushed"] / (1000.0 * elapsed), 4),
            "drop_events_per_second": round(deltas["events_dropped"] / elapsed, 4),
            "drop_percent": round(drop_percent, 4),
            "queue_depth_events": int(buffered_events) + queued_events,
            "queue_capacity_events": queue_capacity,
            "queue_high_water_events": queue_high_water,
            "last_push_http_status": last_push_http_status,
            "last_success_at": last_success_at,
            "consecutive_failures": consecutive_failures,
            "stats_samples_dropped_total": totals["stats_samples_dropped"]}
        return {"schema_version": 1, "type": "agent_stats", "node": node,
                "instance_id": self.instance_id, "sequence": sequence,
                "observed_at": int(now), "window_seconds": round(elapsed, 3),
                "mode": mode, "status": "degraded" if reasons else "ok",
                "reasons": reasons, "capture": capture,
                "shipping": shipping, "resources": self._resources(elapsed),
                "limits": {"cpu_core": allowed_cpu(),
                           "address_space_bytes": 268435456,
                           "ship_rate_kbps": rate_kbps,
                           "http_body_max_bytes": MAX_POST_BYTES,
                           "ship_threads_max": MAX_SHIP_THREADS,
                           "wsse_body_bytes": wsse_body_bytes}}


def allowed_cpu():
    try:
        for line in open("/proc/self/status", "r"):
            if line.startswith("Cpus_allowed_list:"):
                return line.split(":", 1)[1].strip()
    except (IOError, OSError, IndexError):
        pass
    return "unknown"


def main():
    endpoint = None
    spool = "/var/lib/networktracing/sniff-spool.jsonl"
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--endpoint":
            i += 1; endpoint = argv[i].rstrip("/")
        elif a == "--spool":
            i += 1; spool = argv[i]
        elif a == "--ship-rate-kbps":
            i += 1; os.environ["NT_SHIP_RATE_KBPS"] = argv[i]
        elif a == "--stats-interval-sec":
            i += 1; os.environ["NT_STATS_INTERVAL_SEC"] = argv[i]
        elif a in ("-h", "--help"):
            print(__doc__); raise SystemExit(0)
        else:
            raise SystemExit("unknown arg: %s" % a)
        i += 1
    if not endpoint:
        raise SystemExit("--endpoint required")

    node = socket.gethostname().split(".")[0]
    rate_kbps = read_bounded_int("NT_SHIP_RATE_KBPS", DEFAULT_RATE_KBPS,
                                 MIN_RATE_KBPS, MAX_RATE_KBPS)
    limiter = RateLimiter(rate_kbps)
    stats = ShipStats()
    capture_latest = {}
    wsse_body_bytes = read_bounded_int("NT_WSSE_BODY_BYTES", 0, 0, 65536)
    running = [True]

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def request(path, body, timeout):
        limiter.wait(len(body))
        req = urllib2.Request(endpoint + path, data=body,
                              headers={"Content-Type": "application/json"})
        try:
            resp = urllib2.urlopen(req, timeout=timeout)
            ok = (resp.getcode() == 200)
            resp.read()
            resp.close()
            return ok
        except Exception as e:
            log("ship failed: %s" % e)
            return False

    def flush(batch):
        if not batch:
            return True
        body = json.dumps({"node": node, "events": batch},
                          separators=(",", ":"))
        # py2 urllib2 accepts str; py3 shim/test needs bytes — encode when
        # the runtime exposes it (py2 str has no .encode on all builds, so
        # guard with hasattr)
        if hasattr(body, "encode"):
            body = body.encode("utf-8")
        if len(body) > MAX_POST_BYTES:
            log("WARN: refusing oversized upload body (%d bytes)" % len(body))
            return False
        ok = request("/api/ingest", body, 10)
        if ok:
            stats.batch_success(len(batch), len(body))
            log("flushed %d events" % len(batch))
        return ok

    def flush_stats(sample):
        body = json.dumps(sample, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_STATS_BYTES:
            stats.add("stats_samples_dropped")
            log("WARN: dropped oversized agent stats sample")
            return
        if not request("/api/agent/stats", body, 5):
            stats.add("stats_samples_dropped")

    # ---- concurrent shipping -------------------------------------------
    # hub ingest latency (~300-500ms per 400-event POST over WAN) makes
    # sequential posting a ~1000 ev/s ceiling; N poster threads posting
    # independent batches multiply that by NT_SHIP_THREADS
    configure_thread_stack()
    nthreads = read_bounded_int("NT_SHIP_THREADS", 4, 1, MAX_SHIP_THREADS)
    q = Queue.Queue(maxsize=min(MAX_QUEUE_BATCHES, max(2, nthreads * 2)))

    def poster():
        while True:
            kind, item = q.get()
            if kind == "stats":
                sample = stats.take_stats()
                if sample is not None:
                    flush_stats(sample)
                q.task_done()
                continue
            stats.queued(-len(item))
            if not flush(item):
                stats.batch_failure(len(item))
                log("WARN: Hub unreachable, dropped %d events (in-memory drop, 0 disk I/O)" % len(item))
            q.task_done()

    started_threads = 0
    for _ in range(nthreads):
        try:
            t = threading.Thread(target=poster)
            t.daemon = True
            t.start()
            started_threads += 1
        except (RuntimeError, threading.ThreadError):
            log("WARN: thread allocation stopped at %d poster(s)" %
                started_threads)
            break
    if started_threads == 0:
        raise SystemExit("cannot start any shipper thread")
    log("egress limit: %d kbit/s, %d poster(s), %d-byte HTTP body cap" %
        (rate_kbps, started_threads, MAX_POST_BYTES))

    buf = []
    last_flush = time.time()

    while running[0]:
        try:
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            break

        if r:
            try:
                raw = sys.stdin.readline()
            except (IOError, OSError) as e:
                if getattr(e, 'errno', None) == errno.EINTR:
                    continue
                break
            if not raw:
                break                  # EOF
            raw = raw.strip()
            if raw:
                try:
                    ev = json.loads(raw)
                    if isinstance(ev, dict):
                        if ev.get("_nt_internal") == "capture_stats_v1":
                            capture_latest = ev.get("capture") or {}
                            sample = stats.snapshot(
                                capture_latest, node, "python", rate_kbps,
                                started_threads, wsse_body_bytes, len(buf),
                                4000 + q.maxsize * MAX_BATCH)
                            if stats.offer_stats(sample):
                                try:
                                    q.put_nowait(("stats", None))
                                except Queue.Full:
                                    stats.take_stats()
                                    stats.add("stats_samples_dropped")
                            continue
                        stats.add("events_in")
                        if len(buf) >= 4000:
                            del buf[0]
                            stats.dropped("queue_full", 1)
                        buf.append(ev)
                except ValueError:
                    pass

        now = time.time()
        while len(buf) >= MAX_BATCH or (buf and now - last_flush >= FLUSH_SEC):
            last_flush = now
            batch = take_bounded_batch(buf, node, stats.dropped)
            if not batch:
                break
            try:
                q.put_nowait(("events", batch))
                stats.queued(len(batch))
            except Queue.Full:
                stats.dropped("queue_full", len(batch))
                log("WARN: egress queue full, dropped %d events" % len(batch))

    # stdin closed (sniffer stopped) — enqueue the final partial batch before
    # waiting for poster threads. Previously every shutdown lost 1..399 events.
    if buf:
        while buf:
            batch = take_bounded_batch(buf, node, stats.dropped)
            if not batch:
                break
            try:
                q.put_nowait(("events", batch))
                stats.queued(len(batch))
            except Queue.Full:
                stats.dropped("queue_full", len(batch))
                log("WARN: egress queue full at shutdown, dropped %d events" %
                    len(batch))
    q.join()
    log("stopped (%d events pending on exit)" % len(buf))


if __name__ == "__main__":
    main()
