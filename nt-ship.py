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
MAX_QUEUE_BATCHES = 16
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


def take_bounded_batch(buf, node):
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
        log("WARN: dropped oversized event; encoded body exceeds %d bytes" %
            MAX_POST_BYTES)
    return []


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
    running = [True]

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

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
        limiter.wait(len(body))
        req = urllib2.Request(endpoint + "/api/ingest", data=body,
                              headers={"Content-Type": "application/json"})
        try:
            resp = urllib2.urlopen(req, timeout=10)
            ok = (resp.getcode() == 200)
            resp.read()
            resp.close()
            if ok:
                log("flushed %d events" % len(batch))
            return ok
        except Exception as e:
            log("ship failed: %s" % e)
            return False

    # ---- concurrent shipping -------------------------------------------
    # hub ingest latency (~300-500ms per 400-event POST over WAN) makes
    # sequential posting a ~1000 ev/s ceiling; N poster threads posting
    # independent batches multiply that by NT_SHIP_THREADS
    nthreads = read_bounded_int("NT_SHIP_THREADS", 4, 1, 8)
    q = Queue.Queue(maxsize=min(MAX_QUEUE_BATCHES, max(2, nthreads * 2)))

    def poster():
        while True:
            batch = q.get()
            if batch is None:
                q.task_done()
                return
            if not flush(batch):
                log("WARN: Hub unreachable, dropped %d events (in-memory drop, 0 disk I/O)" % len(batch))
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
                        if len(buf) >= 4000:
                            del buf[0]
                        buf.append(ev)
                except ValueError:
                    pass

        now = time.time()
        while len(buf) >= MAX_BATCH or (buf and now - last_flush >= FLUSH_SEC):
            last_flush = now
            batch = take_bounded_batch(buf, node)
            if not batch:
                break
            try:
                q.put_nowait(batch)
            except Queue.Full:
                log("WARN: egress queue full, dropped %d events" % len(batch))

    # stdin closed (sniffer stopped) — enqueue the final partial batch before
    # waiting for poster threads. Previously every shutdown lost 1..399 events.
    if buf:
        while buf:
            batch = take_bounded_batch(buf, node)
            if not batch:
                break
            try:
                q.put_nowait(batch)
            except Queue.Full:
                log("WARN: egress queue full at shutdown, dropped %d events" %
                    len(batch))
    q.join()
    log("stopped (%d events pending on exit)" % len(buf))


if __name__ == "__main__":
    main()
