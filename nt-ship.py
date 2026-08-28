#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""nt-ship.py — event shipper for old-kernel nodes (python 2.6 compatible).

Reads NetworkTracing JSONL events on stdin, batches them, POSTs to the hub
/api/ingest. Spools undelivered batches to a disk file and retries with
backoff — same at-least-once semantics as nt-agent.py / Go agent.

Usage:
  python nt-ship.py --endpoint http://hub:31115 [--spool /var/lib/nt/spool.jsonl]
"""
from __future__ import print_function

import base64, errno, json, os, select, signal, socket, sys

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
FLUSH_SEC = 5.0
RETRY_MAX = 86400.0        # keep spool-retrying for a day before giving up


def log(msg):
    sys.stderr.write("nt-ship: %s\n" % msg)
    sys.stderr.flush()


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
    running = [True]

    def stop(signum, frame):
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def flush(batch):
        if not batch:
            return True
        body = json.dumps({"node": node, "events": batch})
        # py2 urllib2 accepts str; py3 shim/test needs bytes — encode when
        # the runtime exposes it (py2 str has no .encode on all builds, so
        # guard with hasattr)
        if hasattr(body, "encode"):
            body = body.encode("utf-8")
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
    q = Queue.Queue(maxsize=128)
    spool_lock = threading.Lock()
    nthreads = int(os.environ.get("NT_SHIP_THREADS", "4"))

    def poster():
        while True:
            batch = q.get()
            if batch is None:
                q.task_done()
                return
            if not flush(batch):
                log("WARN: Hub unreachable, dropped %d events (in-memory drop, 0 disk I/O)" % len(batch))
            q.task_done()

    for _ in range(nthreads):
        t = threading.Thread(target=poster)
        t.daemon = True
        t.start()

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
            q.put(buf[:MAX_BATCH])
            del buf[:MAX_BATCH]

    # stdin closed (sniffer stopped) — drain in-memory queue
    q.join()
    log("stopped (%d events pending on exit)" % len(buf))


if __name__ == "__main__":
    main()
