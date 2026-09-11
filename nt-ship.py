#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-ship.py — event shipper for old-kernel nodes (python 2.6 compatible).

Reads NetworkTracing JSONL events on stdin, batches them, and POSTs to the Hub
/api/ingest. Uploads use bounded memory, persistent HTTP/1.1 connections, and
drop on overload or Hub failure; the compatibility --spool option does not
enable disk writes.

Usage:
  NT_SHIP_RATE_KBPS=1024 python nt-ship.py --endpoint http://hub:31115
"""
#
# DESIGN NOTES — read this before changing anything below.
# ---------------------------------------------------------------------------
# Role in the pipeline:  nt-sniff.py | nt-ship.py
#   nt-sniff.py writes one JSON object per line ("JSONL") to stdout; this
#   process reads those lines on stdin, groups them into batches, and POSTs
#   {"node": <node>, "events": [<event>, ...]} to the Hub.
#
# Stability & Transport Hardening:
#   1. Zero Packet-Socket Interaction: Pure user-space process reading JSONL
#      from stdin and POSTing batches over plain HTTP. No AF_PACKET.
#   2. 256 MiB Address Space Safety: Strict RLIMIT_AS enforcement (256 MiB)
#      with fail-closed verification (exit code 70).
#   3. Dual Buffer Bounds: Buffer bounded by both event count (4000) and
#      payload bytes (8 MiB). Drops oldest on pressure.
#   4. Hard Line Size Cap: sys.stdin.readline(65537) drops and drains
#      un-terminated records > 64 KiB in chunks without memory inflation.
#   5. Single Serialization: Incoming JSON validated once; compact raw JSON
#      strings joined directly to assemble wire bodies without dict creation.
#   6. Pre-Built Batches: Batch objects constructed before queueing. Poster
#      threads perform zero JSON encoding.
#   7. Persistent HTTP/1.1 Transport: Per-thread persistent httplib.HTTPConnection
#      reused across batches. Reconnects on errors or Connection: close.
#   8. Threading Footprint: Default 2 persistent connections (max 4).
#   9. Bounded Response Reading: Hub response reading capped at 4096 bytes.
#  10. Bounded In-Memory Retries: Stable X-Batch-Id, up to 3 attempts with
#      exponential backoff for transient 408/429/5xx and network errors;
#      permanent 4xx dropped immediately. Capped at 60s age.
#  11. Clean Transition Logging: Per-batch success logs removed. Hub outages
#      log on transition, suppress repeat spam, summarize every 30s, and
#      log on recovery.
# ---------------------------------------------------------------------------
from __future__ import print_function

import collections
import errno
import json
import os
import select
import signal
import socket
import sys
import threading
import time

try:
    import httplib
    import urlparse
    import Queue
except ImportError:
    import http.client as httplib
    import urllib.parse as urlparse
    import queue as Queue

# ---------------------------------------------------------------------------
# Fixed tuning constants.
# ---------------------------------------------------------------------------
MAX_BATCH = 400              # max events packed into one /api/ingest POST
MAX_POST_BYTES = 65536       # hard cap (64 KiB) on any encoded ingest body
MAX_STATS_BYTES = 16384      # hard cap (16 KiB) on one agent-stats body
MAX_INPUT_LINE = 65536       # hard cap (64 KiB) on any single input line
MAX_BUFFER_EVENTS = 4000     # upper bound on pre-batch event count
MAX_BUFFER_BYTES = 8388608   # upper bound on pre-batch event bytes (8 MiB)
MAX_QUEUE_BATCHES = 8        # upper bound on pending-batch queue length
MAX_QUEUE_WIRE_BYTES = 524288 # upper bound on queued wire bytes (512 KiB)
DEFAULT_SHIP_THREADS = 2     # default poster threads (persistent connections)
MAX_SHIP_THREADS = 4         # upper bound on poster threads (NT_SHIP_THREADS)
THREAD_STACK_BYTES = 262144  # 256 KiB virtual stack requested per poster thread
DEFAULT_RATE_KBPS = 1024     # default aggregate egress ceiling (kbit/s)
MIN_RATE_KBPS = 64           # clamp floor for NT_SHIP_RATE_KBPS
MAX_RATE_KBPS = 10000        # clamp ceiling for NT_SHIP_RATE_KBPS
FLUSH_SEC = 1.0              # flush a partial batch after this many idle seconds
MAX_RETRIES = 3              # transient retry limit per batch
MAX_RETRY_AGE_SEC = 60.0     # drop batches older than 60s


def log(msg):
    """Write one line of diagnostics to stderr and flush it immediately."""
    sys.stderr.write("nt-ship: %s\n" % msg)
    sys.stderr.flush()


def enforce_rlimit_as():
    """Enforce and verify strict 256 MiB virtual address space limit."""
    try:
        import resource
        target = 256 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_soft = target if soft == resource.RLIM_INFINITY or soft > target else soft
        new_hard = target if hard == resource.RLIM_INFINITY or hard > target else hard
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
        v_soft, v_hard = resource.getrlimit(resource.RLIMIT_AS)
        if v_soft > target:
            raise RuntimeError("Enforced RLIMIT_AS soft limit exceeds target (%d > %d)" % (v_soft, target))
    except Exception as e:
        sys.stderr.write("nt-ship: FATAL: cannot enforce address-space limit: %s\n" % e)
        sys.stderr.flush()
        sys.exit(70)


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
    """Read integer environment variable clamped to [minimum, maximum]."""
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


class Batch(object):
    """Pre-built batch containing pre-encoded wire body and metadata."""
    __slots__ = ("body", "event_count", "batch_id", "attempts", "created_at")

    def __init__(self, body, event_count, batch_id, attempts=0, created_at=None):
        self.body = body
        self.event_count = event_count
        self.batch_id = batch_id
        self.attempts = attempts
        self.created_at = created_at if created_at is not None else time.time()

    def __len__(self):
        return self.event_count


def build_batch(events, node, batch_id):
    """Build pre-encoded wire body without double serialization."""
    node_json = json.dumps(node, separators=(",", ":"))
    if not events:
        body = "{\"node\":" + node_json + ",\"events\":[]}"
    elif isinstance(events[0], dict):
        body = json.dumps({"node": node, "events": events}, separators=(",", ":"))
    else:
        body = "{\"node\":" + node_json + ",\"events\":[" + ",".join(events) + "]}"
    if hasattr(body, "encode"):
        body = body.encode("utf-8")
    return Batch(body=body, event_count=len(events), batch_id=batch_id)


def take_bounded_batch(buf, node, on_drop=None):
    """Remove one <=64 KiB batch from buf, dropping impossible giant events.

    Supports both collections.deque and list, and elements as raw strings or dicts.
    """
    node_json = json.dumps(node, separators=(",", ":"))
    empty_size = len(("{\"node\":" + node_json + ",\"events\":[]}").encode("utf-8"))

    while buf:
        batch = []
        encoded_size = empty_size
        count = 0
        for event in buf:
            if count >= MAX_BATCH:
                break
            if isinstance(event, dict):
                ev_str = json.dumps(event, separators=(",", ":"))
            else:
                ev_str = event
            ev_bytes = ev_str.encode("utf-8") if hasattr(ev_str, "encode") else ev_str
            candidate_size = encoded_size + len(ev_bytes) + (1 if batch else 0)
            if candidate_size > MAX_POST_BYTES:
                break
            batch.append(event)
            encoded_size = candidate_size
            count += 1

        if batch:
            if isinstance(buf, collections.deque):
                for _ in range(len(batch)):
                    buf.popleft()
            else:
                del buf[:len(batch)]
            return batch

        if isinstance(buf, collections.deque):
            buf.popleft()
        else:
            del buf[0]
        if on_drop is not None:
            on_drop("oversized", 1)
        log("WARN: dropped oversized event; encoded body exceeds %d bytes" % MAX_POST_BYTES)

    return []


class ShipStats(object):
    """Locked counter set and transition-based outage reporter."""
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
        self.queued_wire_bytes = 0
        self.queue_high_water = 0
        self.instance_id = "%d-%d" % (int(self.last_at), os.getpid())
        self.last_push_http_status = 0
        self.last_success_at = 0
        self.consecutive_failures = 0
        self.pending_sample = None

        self.in_outage = False
        self.outage_started_at = 0.0
        self.last_outage_log_at = 0.0
        self.outage_batches_failed = 0
        self.outage_events_dropped = 0

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

    def queued(self, delta_events, delta_bytes=0):
        self.lock.acquire()
        try:
            self.queued_events = max(0, self.queued_events + int(delta_events))
            self.queued_wire_bytes = max(0, self.queued_wire_bytes + int(delta_bytes))
            if self.queued_events > self.queue_high_water:
                self.queue_high_water = self.queued_events
        finally:
            self.lock.release()

    def batch_success(self, count, body_bytes, status=200):
        recovery_msg = None
        self.lock.acquire()
        try:
            self.total["events_pushed"] += int(count)
            self.total["batches_pushed"] += 1
            self.total["bytes_pushed"] += int(body_bytes)
            self.last_push_http_status = status
            self.last_success_at = int(time.time())
            self.consecutive_failures = 0

            if self.in_outage:
                duration = int(time.time() - self.outage_started_at)
                recovery_msg = (
                    "INFO: Hub connection recovered after %ds outage "
                    "(%d batches failed, %d events dropped)" % (
                        duration, self.outage_batches_failed, self.outage_events_dropped))
                self.in_outage = False
                self.outage_started_at = 0.0
                self.outage_batches_failed = 0
                self.outage_events_dropped = 0
        finally:
            self.lock.release()

        if recovery_msg:
            log(recovery_msg)

    def attempt_failed(self, status=0):
        outage_msg = None
        now = time.time()
        self.lock.acquire()
        try:
            self.consecutive_failures += 1
            self.last_push_http_status = status

            if not self.in_outage:
                self.in_outage = True
                self.outage_started_at = now
                self.last_outage_log_at = now
                self.outage_batches_failed = 0
                self.outage_events_dropped = 0
                status_str = ("HTTP %d" % status) if status else "transport error"
                outage_msg = "WARN: Hub connection failed (%s); entering outage mode, suppressing repeat logs" % status_str
            elif now - self.last_outage_log_at >= 30.0:
                duration = int(now - self.outage_started_at)
                outage_msg = "WARN: Hub outage ongoing for %ds (%d batches failed, %d events dropped)" % (
                    duration, self.outage_batches_failed, self.outage_events_dropped)
                self.last_outage_log_at = now
        finally:
            self.lock.release()

        if outage_msg:
            log(outage_msg)

    def batch_dropped(self, count, status=0):
        self.lock.acquire()
        try:
            self.total["batches_failed"] += 1
            self.total["events_dropped"] += int(count)
            self.total["hub_failure"] += int(count)
            self.last_push_http_status = status
            if self.in_outage:
                self.outage_batches_failed += 1
                self.outage_events_dropped += int(count)
        finally:
            self.lock.release()

    def batch_failure(self, count, status=0):
        self.attempt_failed(status)
        self.batch_dropped(count, status)

    def offer_stats(self, sample):
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
    """Return this process's CPU affinity mask string, e.g. '0-3', or 'unknown'."""
    try:
        for line in open("/proc/self/status", "r"):
            if line.startswith("Cpus_allowed_list:"):
                return line.split(":", 1)[1].strip()
    except (IOError, OSError, IndexError):
        pass
    return "unknown"


def main():
    """Entry point: parse arguments, start poster threads, pump stdin."""
    enforce_rlimit_as()

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

    parsed_ep = urlparse.urlparse(endpoint)
    host = parsed_ep.hostname or "127.0.0.1"
    is_https = (parsed_ep.scheme == "https")
    port = parsed_ep.port
    if not port:
        port = 443 if is_https else 80
    base_path = parsed_ep.path.rstrip("/")
    if (is_https and port == 443) or (not is_https and port == 80):
        host_header = host
    else:
        host_header = "%s:%d" % (host, port)

    running = [True]
    shutdown_event = threading.Event()
    fatal_poster_error = [False]

    def stop(signum, frame):
        running[0] = False
        shutdown_event.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def make_connection():
        if is_https:
            return httplib.HTTPSConnection(host, port, timeout=10)
        else:
            return httplib.HTTPConnection(host, port, timeout=10)

    def make_headers(batch):
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(batch.body)),
            "Connection": "keep-alive",
            "X-Batch-Id": str(batch.batch_id),
            "User-Agent": "nt-ship-py/1",
        }
        if host_header:
            headers["Host"] = host_header
        return headers

    def flush_batch(conn, batch):
        """Pace and POST one pre-built batch to /api/ingest with bounded retries."""
        if not batch or not batch.body:
            return conn

        if len(batch.body) > MAX_POST_BYTES:
            stats.dropped("oversized", batch.event_count)
            log("WARN: refusing oversized upload body (%d bytes)" % len(batch.body))
            return conn

        path = base_path + "/api/ingest"

        while True:
            batch.attempts += 1
            limiter.wait(len(batch.body))

            if conn is None:
                try:
                    conn = make_connection()
                except (socket.error, httplib.HTTPException, IOError, OSError):
                    conn = None

            status = 0
            if conn is not None:
                try:
                    headers = make_headers(batch)
                    conn.request("POST", path, body=batch.body, headers=headers)
                    resp = conn.getresponse()
                    status = resp.status
                    resp.read(4096)
                    resp.close()

                    will_close = (getattr(resp, "will_close", False) or
                                  (resp.getheader("connection", "").lower() == "close") or
                                  getattr(resp, "version", 11) == 10)
                    if will_close or (hasattr(resp, "isclosed") and not resp.isclosed()):
                        conn.close()
                        conn = None

                except (socket.error, httplib.HTTPException, IOError, OSError):
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                    status = 0

            if 200 <= status < 300:
                stats.batch_success(batch.event_count, len(batch.body), status)
                return conn

            if status not in (408, 429) and (400 <= status < 500):
                stats.attempt_failed(status)
                stats.batch_dropped(batch.event_count, status)
                log("WARN: Hub rejected batch %s with HTTP %d, dropped %d events" %
                    (batch.batch_id, status, batch.event_count))
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                return None

            stats.attempt_failed(status)

            age = time.time() - batch.created_at
            if batch.attempts >= MAX_RETRIES or age >= MAX_RETRY_AGE_SEC or shutdown_event.is_set() or not running[0]:
                stats.batch_dropped(batch.event_count, status)
                log("WARN: Hub unreachable, dropped %d events (in-memory drop, 0 disk I/O)" % batch.event_count)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                return None

            delay = min(5.0, 0.5 * (2 ** (batch.attempts - 1)))
            if shutdown_event.wait(delay):
                stats.batch_dropped(batch.event_count, status)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                return None

    def flush_stats(conn, sample):
        """POST one coalesced agent-stats sample to /api/agent/stats."""
        body = json.dumps(sample, separators=(",", ":"))
        if hasattr(body, "encode"):
            body = body.encode("utf-8")

        if len(body) > MAX_STATS_BYTES:
            stats.add("stats_samples_dropped")
            log("WARN: dropped oversized agent stats sample (%d bytes)" % len(body))
            return conn

        limiter.wait(len(body))

        if conn is None:
            try:
                conn = make_connection()
            except (socket.error, httplib.HTTPException, IOError, OSError):
                stats.add("stats_samples_dropped")
                return None

        path = base_path + "/api/agent/stats"
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "keep-alive",
            "User-Agent": "nt-ship-py/1",
        }
        if host_header:
            headers["Host"] = host_header

        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            resp.read(4096)
            resp.close()

            will_close = (getattr(resp, "will_close", False) or
                          (resp.getheader("connection", "").lower() == "close") or
                          getattr(resp, "version", 11) == 10)
            if will_close or (hasattr(resp, "isclosed") and not resp.isclosed()):
                conn.close()
                conn = None

            if not (200 <= status < 300):
                stats.add("stats_samples_dropped")
            return conn

        except (socket.error, httplib.HTTPException, IOError, OSError):
            stats.add("stats_samples_dropped")
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            return None

    configure_thread_stack()
    nthreads = read_bounded_int("NT_SHIP_THREADS", DEFAULT_SHIP_THREADS, 1, MAX_SHIP_THREADS)
    q = Queue.Queue(maxsize=min(MAX_QUEUE_BATCHES, max(2, nthreads * 2)))

    def poster():
        conn = None
        while not shutdown_event.is_set():
            try:
                kind, item = q.get(timeout=0.5)
            except Queue.Empty:
                continue
            except Exception:
                break

            try:
                try:
                    if kind == "stats":
                        sample = stats.take_stats()
                        if sample is not None:
                            conn = flush_stats(conn, sample)
                    elif kind == "events":
                        batch = item
                        stats.queued(-batch.event_count, -len(batch.body))
                        conn = flush_batch(conn, batch)
                except MemoryError:
                    sys.stderr.write("nt-ship: FATAL: MemoryError under RLIMIT_AS\n")
                    sys.stderr.flush()
                    os._exit(71)
                except Exception as e:
                    log("ERROR: unexpected poster exception: %s" % e)
                    fatal_poster_error[0] = True
            finally:
                q.task_done()

        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    started_threads = 0
    for _ in range(nthreads):
        try:
            t = threading.Thread(target=poster)
            t.daemon = True
            t.start()
            started_threads += 1
        except (RuntimeError, threading.ThreadError):
            log("WARN: thread allocation stopped at %d poster(s)" % started_threads)
            break
    if started_threads == 0:
        raise SystemExit("cannot start any shipper thread")

    log("egress limit: %d kbit/s, %d poster(s), %d-byte HTTP body cap" %
        (rate_kbps, started_threads, MAX_POST_BYTES))

    buf = collections.deque()
    buf_bytes = 0
    last_flush = time.time()
    batch_sequence = 0

    while running[0] and not fatal_poster_error[0]:
        try:
            r, _, _ = select.select([sys.stdin], [], [], 0.2)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            break

        if r:
            try:
                raw = sys.stdin.readline(MAX_INPUT_LINE + 1)
            except (IOError, OSError) as e:
                if getattr(e, "errno", None) == errno.EINTR:
                    continue
                break
            if not raw:
                break

            if len(raw) > MAX_INPUT_LINE and not (raw.endswith("\n") or raw.endswith("\r")):
                while True:
                    chunk = sys.stdin.readline(4096)
                    if not chunk or chunk.endswith("\n") or chunk.endswith("\r"):
                        break
                stats.dropped("oversized", 1)
                log("WARN: dropped oversized input line (> %d bytes)" % MAX_INPUT_LINE)
                continue

            raw_stripped = raw.strip()
            if not raw_stripped:
                continue
            if len(raw_stripped) > MAX_INPUT_LINE:
                stats.dropped("oversized", 1)
                log("WARN: dropped oversized input line (> %d bytes)" % MAX_INPUT_LINE)
                continue

            if "\"_nt_internal\":\"capture_stats_v1\"" in raw_stripped or "\"_nt_internal\": \"capture_stats_v1\"" in raw_stripped:
                try:
                    ev = json.loads(raw_stripped)
                    if isinstance(ev, dict) and ev.get("_nt_internal") == "capture_stats_v1":
                        capture_latest = ev.get("capture") or {}
                        sample = stats.snapshot(
                            capture_latest, node, "python", rate_kbps,
                            started_threads, wsse_body_bytes, len(buf),
                            MAX_BUFFER_EVENTS + q.maxsize * MAX_BATCH)
                        if stats.offer_stats(sample):
                            try:
                                q.put_nowait(("stats", None))
                            except Queue.Full:
                                stats.take_stats()
                                stats.add("stats_samples_dropped")
                        continue
                except ValueError:
                    pass
                continue

            try:
                json.loads(raw_stripped)
            except ValueError:
                continue

            stats.add("events_in")
            raw_len = len(raw_stripped)

            while len(buf) >= MAX_BUFFER_EVENTS or (buf and buf_bytes + raw_len > MAX_BUFFER_BYTES):
                oldest = buf.popleft()
                oldest_len = len(oldest) if isinstance(oldest, (str, bytes)) else len(json.dumps(oldest, separators=(",", ":")))
                buf_bytes -= oldest_len
                if buf_bytes < 0:
                    buf_bytes = 0
                stats.dropped("queue_full", 1)

            buf.append(raw_stripped)
            buf_bytes += raw_len

        now = time.time()
        while len(buf) >= MAX_BATCH or (buf and now - last_flush >= FLUSH_SEC):
            last_flush = now
            batch_events = take_bounded_batch(buf, node, stats.dropped)
            if not batch_events:
                break
            for item in batch_events:
                item_len = len(item) if isinstance(item, (str, bytes)) else len(json.dumps(item, separators=(",", ":")))
                buf_bytes -= item_len
            if buf_bytes < 0 or not buf:
                buf_bytes = 0

            batch_sequence += 1
            batch_id = "%s-%d" % (stats.instance_id, batch_sequence)
            batch_obj = build_batch(batch_events, node, batch_id)

            if q.qsize() >= MAX_QUEUE_BATCHES or (stats.queued_wire_bytes + len(batch_obj.body) > MAX_QUEUE_WIRE_BYTES):
                stats.dropped("queue_full", batch_obj.event_count)
                log("WARN: egress queue full, dropped %d events" % batch_obj.event_count)
            else:
                try:
                    q.put_nowait(("events", batch_obj))
                    stats.queued(batch_obj.event_count, len(batch_obj.body))
                except Queue.Full:
                    stats.dropped("queue_full", batch_obj.event_count)
                    log("WARN: egress queue full, dropped %d events" % batch_obj.event_count)

    while buf:
        batch_events = take_bounded_batch(buf, node, stats.dropped)
        if not batch_events:
            break
        for item in batch_events:
            item_len = len(item) if isinstance(item, (str, bytes)) else len(json.dumps(item, separators=(",", ":")))
            buf_bytes -= item_len
        if buf_bytes < 0 or not buf:
            buf_bytes = 0

        batch_sequence += 1
        batch_id = "%s-%d" % (stats.instance_id, batch_sequence)
        batch_obj = build_batch(batch_events, node, batch_id)

        if q.qsize() >= MAX_QUEUE_BATCHES or (stats.queued_wire_bytes + len(batch_obj.body) > MAX_QUEUE_WIRE_BYTES):
            stats.dropped("queue_full", batch_obj.event_count)
            log("WARN: egress queue full at shutdown, dropped %d events" % batch_obj.event_count)
        else:
            try:
                q.put_nowait(("events", batch_obj))
                stats.queued(batch_obj.event_count, len(batch_obj.body))
            except Queue.Full:
                stats.dropped("queue_full", batch_obj.event_count)
                log("WARN: egress queue full at shutdown, dropped %d events" % batch_obj.event_count)

    q.join()
    shutdown_event.set()
    log("stopped (%d events pending on exit)" % len(buf))

    if fatal_poster_error[0]:
        sys.exit(72)


if __name__ == "__main__":
    main()
