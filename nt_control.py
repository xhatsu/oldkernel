#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bounded Python 2.6-compatible control client for oldkernel capture.
Uses only standard-library HTTP and atomic local state."""
from __future__ import print_function

import json
import hashlib
import hmac
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
MAX_COMMAND_ID = 128
MAX_CONTROL_RESPONSE = 4096
MAX_CONTROL_LIFETIME = 600
CONTROL_CLOCK_SKEW = 300
ACTIONS = ("health", "reload", "restart", "stop", "start", "set_ports")
STATS_COMMANDS = ("off",)
_SECRET_RE = re.compile(r"(?i)(bearer\s+\S+|authorization\s*[:=]\s*\S+|password\s*[:=]\s*\S+|token\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|secret\s*[:=]\s*\S+)")
_COMMAND_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def safe_message(value):
    text = _SECRET_RE.sub("[REDACTED]", str(value or ""))
    return text[:MAX_MESSAGE]


def load_control_token(path=None):
    """Read a bounded control token without exposing it in diagnostics."""
    direct = os.environ.get("NT_CONTROL_TOKEN", "")
    if direct:
        token = direct
    else:
        path = path or os.environ.get("NT_CONTROL_TOKEN_FILE", "")
        if not path:
            return ""
        try:
            f = open(path, "rb")
            try:
                raw = f.read(4097)
            finally:
                f.close()
        except (IOError, OSError):
            return ""
        if len(raw) > 4096:
            return ""
        if not isinstance(raw, str):
            raw = raw.decode("utf-8", "strict")
        token = raw.rstrip("\r\n")
    if not token or len(token) > 4096 or "\x00" in token:
        return ""
    return token


def stats_control_signing_input(node, command_id, command, issued_at, expires_at):
    """Return the exact UTF-8 bytes covered by a stats-response signature."""
    value = "v1\n%s\n%s\n%s\n%d\n%d\n" % (
        node, command_id, command, int(issued_at), int(expires_at))
    return value.encode("utf-8")


def sign_stats_control(token, node, command_id, command, issued_at, expires_at):
    key = token.encode("utf-8") if not isinstance(token, bytes) else token
    return hmac.new(
        key,
        stats_control_signing_input(node, command_id, command,
                                    issued_at, expires_at),
        hashlib.sha256).hexdigest()


def _constant_time_equal(left, right):
    if not isinstance(left, string_types) or not isinstance(right, string_types):
        return False
    mismatch = len(left) ^ len(right)
    for i in range(min(len(left), len(right))):
        mismatch |= ord(left[i]) ^ ord(right[i])
    return mismatch == 0


def validate_stats_control(reply, token, node, now=None):
    """Validate one signed, bounded command returned by POST agent/stats.

    Returns a normalized command dict, None when no command was offered, and
    raises ValueError for malformed, expired, or unauthenticated commands.
    """
    if not isinstance(reply, dict):
        raise ValueError("stats response must be an object")
    if "command" not in reply:
        return None
    if not token:
        raise ValueError("control token unavailable")
    if reply.get("control_version") != 1:
        raise ValueError("unsupported control version")
    command = reply.get("command")
    if command not in STATS_COMMANDS:
        raise ValueError("unsupported stats command")
    command_id = reply.get("command_id")
    if not isinstance(command_id, string_types) or not _COMMAND_ID_RE.match(command_id):
        raise ValueError("invalid command id")
    issued_at = reply.get("issued_at")
    expires_at = reply.get("expires_at")
    if (isinstance(issued_at, bool) or isinstance(expires_at, bool) or
            not isinstance(issued_at, integer_types) or
            not isinstance(expires_at, integer_types)):
        raise ValueError("invalid command time")
    if expires_at < issued_at or expires_at - issued_at > MAX_CONTROL_LIFETIME:
        raise ValueError("invalid command lifetime")
    current = int(time.time() if now is None else now)
    if issued_at > current + CONTROL_CLOCK_SKEW or expires_at < current - CONTROL_CLOCK_SKEW:
        raise ValueError("command outside accepted time window")
    signature = reply.get("signature")
    if (not isinstance(signature, string_types) or len(signature) != 64 or
            re.match(r"^[0-9a-f]{64}$", signature) is None):
        raise ValueError("invalid command signature")
    expected = sign_stats_control(token, node, command_id, command,
                                  issued_at, expires_at)
    if not _constant_time_equal(signature, expected):
        raise ValueError("command signature mismatch")
    return {"control_version": 1, "command_id": command_id,
            "command": command, "issued_at": issued_at,
            "expires_at": expires_at}


def record_stats_command(run_dir, command):
    """Persist an accepted command id atomically before applying it."""
    if not run_dir or not isinstance(command, dict):
        return False
    path = os.path.join(run_dir, "stats-control-applied.json")
    try:
        if not os.path.isdir(run_dir):
            os.makedirs(run_dir)
        try:
            existing = open(path, "r")
            try:
                current = json.load(existing)
            finally:
                existing.close()
            if current.get("command_id") == command.get("command_id"):
                return False
        except (IOError, OSError, ValueError, TypeError, AttributeError):
            pass
        data = dict(command)
        data["applied_at"] = int(time.time())
        tmp = path + ".tmp"
        f = open(tmp, "w")
        try:
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        finally:
            f.close()
        os.chmod(tmp, int("600", 8))
        os.rename(tmp, path)
        return True
    except (IOError, OSError, ValueError, TypeError):
        return False


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
