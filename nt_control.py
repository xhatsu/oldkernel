#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bounded Python 2.6-compatible control client for oldkernel capture.
Uses only standard-library HTTP and atomic local state."""
from __future__ import print_function

import json
import os
import re
import socket
import sys
import time

try:
    from urllib import quote
    import urllib2
except ImportError:
    from urllib.parse import quote
    import urllib.request as urllib2

try:
    JSON_ERRORS = (ValueError, json.JSONDecodeError)
except AttributeError:
    JSON_ERRORS = (ValueError,)

try:
    string_types = (str, unicode)
except NameError:
    string_types = (str,)
try:
    byte_types = (bytes, bytearray)
except NameError:
    byte_types = (bytearray,)

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

MAX_PORTS = 128
MAX_TASKS = 32
MAX_MESSAGE = 256
ACTIONS = ("health", "reload", "restart", "stop", "start", "set_ports")
_SECRET_RE = re.compile(r"(?i)(bearer\s+\S+|authorization\s*[:=]\s*\S+|password\s*[:=]\s*\S+|token\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|secret\s*[:=]\s*\S+)")


def safe_message(value):
    text = _SECRET_RE.sub("[REDACTED]", str(value or ""))
    return text[:MAX_MESSAGE]


def _ports(value):
    if not isinstance(value, list) or not value or len(value) > MAX_PORTS:
        raise ValueError("ports must contain 1..128 integers")
    result = []
    for port in value:
        if (isinstance(port, bool) or not isinstance(port, integer_types) or port < 1 or port > 65535):
            raise ValueError("invalid target port")
        if port not in result:
            result.append(port)
    return result


def _iface(value):
    if (isinstance(value, byte_types) or not isinstance(value, string_types)) or not value or len(value) > 32 or "/" in value or value in (".", ".."):
        raise ValueError("invalid interface")
    return value


def validate_desired(data):
    if not isinstance(data, dict):
        raise ValueError("desired state must be an object")
    out = {}
    if "generation" in data:
        generation = data["generation"]
        if isinstance(generation, bool) or not isinstance(generation, integer_types) or generation < 0:
            raise ValueError("invalid generation")
        out["generation"] = generation
    if "ports" in data and data["ports"] is not None:
        out["ports"] = _ports(data["ports"])
    if "iface" in data and data["iface"] is not None:
        out["iface"] = _iface(data["iface"])
    if "mode" in data and data["mode"] is not None:
        if data["mode"] != "python":
            raise ValueError("oldkernel Python agent accepts mode=python only")
        out["mode"] = "python"
    return out


def validate_task(task, node):
    if not isinstance(task, dict):
        raise ValueError("task must be an object")
    task_id = task.get("id")
    if task_id is None or isinstance(task_id, bool) or not isinstance(task_id, integer_types) or task_id < 1:
        raise ValueError("invalid task id")
    action = task.get("action")
    if action not in ACTIONS:
        raise ValueError("unsupported action")
    task_node = task.get("node", node)
    if task_node not in (node, "*"):
        raise ValueError("task node mismatch")
    if not isinstance(node, string_types):
        raise ValueError("invalid node")
    args = task.get("args") or {}
    if not isinstance(args, dict):
        raise ValueError("task args must be an object")
    if action == "set_ports":
        args = {"ports": _ports(args.get("ports"))}
    elif args:
        raise ValueError("task arguments not allowed")
    return {"id": task_id, "action": action, "args": args}


def write_state(path, desired, last_apply):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    data = dict(desired)
    data["updated_at"] = int(time.time())
    data["last_apply"] = safe_message(last_apply)
    tmp = path + ".tmp"
    f = open(tmp, "w")
    try:
        json.dump(data, f, sort_keys=True)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    finally:
        f.close()
    try:
        os.chmod(tmp, int("600", 8))
    except OSError:
        pass
    os.rename(tmp, path)


def apply_task(task, node, state_path, restart, stop):
    task = validate_task(task, node)
    action = task["action"]
    if action == "health":
        return "healthy"
    if action == "stop":
        stop()
        return "agent stop requested"
    if action in ("reload", "restart", "start"):
        restart()
        return "agent restart requested"
    desired = {"ports": task["args"]["ports"], "mode": "python"}
    write_state(state_path, desired, "restart requested")
    restart()
    return "target ports written; restart requested"


class ControlClient(object):
    def __init__(self, endpoint, token, node, timeout=10):
        if not token:
            raise ValueError("control token required")
        if not isinstance(node, string_types) or not node or len(node) > 128:
            raise ValueError("invalid node")
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.node = node
        self.timeout = max(1, min(int(timeout), 30))

    def _request(self, method, path, payload=None):
        url = self.endpoint + path
        body = None
        headers = {"Authorization": "Bearer " + self.token}
        if payload is not None:
            body = json.dumps(payload)
            if not isinstance(body, bytes):
                body = body.encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib2.Request(url, body, headers)
        if method != "POST":
            request.get_method = lambda: method
        try:
            response = urllib2.urlopen(request, timeout=self.timeout)
            raw = response.read()
            return json.loads(raw)
        except Exception:
            return None

    def poll(self):
        reply = self._request("GET", "/api/control/poll/" + quote(self.node, safe=""))
        if not isinstance(reply, dict):
            return None
        desired = validate_desired(reply.get("desired") or {})
        tasks = reply.get("tasks") or []
        if not isinstance(tasks, list) or len(tasks) > MAX_TASKS:
            raise ValueError("invalid task list")
        return {"desired": desired,
                "tasks": [validate_task(item, self.node) for item in tasks]}

    def report(self, task_id, status, message):
        if status not in ("done", "failed"):
            status = "failed"
        return self._request("POST", "/api/control/tasks/%d/result" % int(task_id), {
            "node": self.node, "status": status, "message": safe_message(message)})

    def heartbeat(self, generation, applied):
        return self._request("POST", "/api/control/heartbeat", {
            "node": self.node, "generation": generation,
            "applied": safe_message(applied)})
