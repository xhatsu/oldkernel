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

import base64, json, os, signal, socket, sys, time, urllib2

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

    # replay spooled events first (at-least-once)
    pending = []
    if os.path.exists(spool):
        try:
            with open(spool) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            pending.append(json.loads(line))
                        except ValueError:
                            pass
            os.remove(spool)
        except (IOError, OSError) as e:
            log("spool read failed: %s" % e)

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
            return ok
        except Exception as e:
            log("ship failed: %s" % e)
            return False

    buf = list(pending)
    last_flush = time.time()
    backoff = 1

    for raw in iter(sys.stdin.readline, ""):
        if not running[0]:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except ValueError:
            continue                      # garbage in, silently dropped
        if isinstance(ev, dict):
            buf.append(ev)
        now = time.time()
        if len(buf) >= MAX_BATCH or now - last_flush >= FLUSH_SEC:
            last_flush = now
            if not flush(buf):
                _spool_append(spool, buf)
                buf = []
                time.sleep(min(backoff, 60))
                backoff *= 2
            else:
                backoff = 1

    # stdin closed (sniffer stopped) — final flush
    if buf and not flush(buf):
        _spool_append(spool, buf)
    log("stopped (%d events pending on exit)" %
        len(buf) if not buf else "stopped clean")


def _spool_append(path, batch):
    d = os.path.dirname(path)
    try:
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with open(path, "a") as f:
            for ev in batch:
                f.write(json.dumps(ev) + "\n")
        del batch[:]
    except (IOError, OSError) as e:
        log("FATAL: cannot write spool %s: %s" % (path, e))
        os._exit(3)


if __name__ == "__main__":
    main()
