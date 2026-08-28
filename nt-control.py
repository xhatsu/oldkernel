#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run the oldkernel Python control client as a bounded SysV child.

The parent/service wrapper owns capture restart. This process only polls hub,
updates desired state, and reports tasks; it never executes hub-provided shell.
"""
from __future__ import print_function

import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nt_control

running = [True]

def stop(signum, frame):
    running[0] = False

def main():
    endpoint = os.environ.get("NT_CONTROL_ENDPOINT") or os.environ.get("NT_ENDPOINT")
    token = os.environ.get("NT_CONTROL_TOKEN", "")
    node = os.environ.get("NT_NODE_NAME") or os.environ.get("NT_NODE")
    run_dir = os.environ.get("NT_CONTROL_RUN", "/var/lib/networktracing")
    interval = int(os.environ.get("NT_CONTROL_SEC", "30"))
    interval = max(5, min(interval, 300))
    if not endpoint or not token or not node:
        print("nt-control: endpoint, token, and node are required", file=sys.stderr)
        return 2
    client = nt_control.ControlClient(endpoint, token, node)
    state_path = os.path.join(run_dir, "remote-desired.json")
    last_generation = -1
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running[0]:
        try:
            reply = client.poll()
            if reply is not None:
                desired = reply.get("desired", {})
                generation = desired.get("generation", 0)
                if generation != last_generation:
                    nt_control.write_state(state_path, desired, "restart required")
                    last_generation = generation
                    client.heartbeat(generation, "restart required")
                for task in reply.get("tasks", []):
                    # The service wrapper can watch this bounded request marker.
                    marker = os.path.join(run_dir, "remote-task-%d.json" % task["id"])
                    nt_control.write_state(marker, task, "queued")
                    client.report(task["id"], "done", "task accepted; service wrapper action required")
                client.heartbeat(last_generation, "poll ok")
        except Exception as exc:
            print("nt-control: poll failed: %s" % nt_control.safe_message(exc), file=sys.stderr)
        for unused in range(interval):
            if not running[0]:
                break
            time.sleep(1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
