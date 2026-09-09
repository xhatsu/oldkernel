import json
import os
import subprocess
import sys
import threading
import importlib.util

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

SPEC = importlib.util.spec_from_file_location(
    "nt_ship", os.path.join(os.path.dirname(__file__), "nt-ship.py"))
nt_ship = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nt_ship)


class IngestHandler(BaseHTTPRequestHandler):
    received = []
    paths = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append(json.loads(self.rfile.read(length)))
        self.paths.append(self.path)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_encoded_batches_have_a_hard_64k_body_ceiling():
    buf = [{"value": "x" * 40000}, {"value": "y" * 40000}]
    first = nt_ship.take_bounded_batch(buf, "fixture")
    body = json.dumps({"node": "fixture", "events": first},
                      separators=(",", ":")).encode("utf-8")
    assert len(first) == 1
    assert len(body) <= nt_ship.MAX_POST_BYTES
    assert len(buf) == 1


def test_oversized_single_event_is_dropped_before_upload():
    buf = [{"value": "x" * (nt_ship.MAX_POST_BYTES + 1)}]
    assert nt_ship.take_bounded_batch(buf, "fixture") == []
    assert buf == []


def test_agent_stats_are_coalesced_to_one_latest_sample():
    stats = nt_ship.ShipStats()
    assert stats.offer_stats({"sequence": 1}) is True
    assert stats.offer_stats({"sequence": 2}) is False
    assert stats.take_stats() == {"sequence": 2}
    assert stats.take_stats() is None
    assert stats.total["stats_samples_dropped"] == 1


def test_python_poster_threads_use_bounded_virtual_stacks():
    previous = threading.stack_size()
    try:
        assert nt_ship.configure_thread_stack() is True
        assert threading.stack_size() == nt_ship.THREAD_STACK_BYTES
        assert nt_ship.THREAD_STACK_BYTES == 262144
    finally:
        threading.stack_size(previous)


def test_shipper_flushes_partial_batch_at_eof():
    IngestHandler.received = []
    IngestHandler.paths = []
    server = HTTPServer(("127.0.0.1", 0), IngestHandler)
    thread = threading.Thread(target=server.handle_request)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    stdout, stderr = process.communicate(json.dumps({"path": "/last"}) + "\n")
    thread.join(5)
    server.server_close()

    assert process.returncode == 0, stderr
    assert stdout == ""
    assert len(IngestHandler.received) == 1
    assert IngestHandler.received[0]["events"] == [{"path": "/last"}]
    assert "stopped (0 events pending on exit)" in stderr
    assert "egress limit: 10000 kbit/s" in stderr


def test_internal_capture_stats_use_separate_hub_endpoint():
    IngestHandler.received = []
    IngestHandler.paths = []
    server = HTTPServer(("127.0.0.1", 0), IngestHandler)
    thread = threading.Thread(target=server.handle_request)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")
    capture = {"packets_total": 10, "packets_delta": 10,
               "packet_bytes_total": 640, "packet_bytes_delta": 640,
               "kernel_drops_total": 1, "kernel_drops_delta": 1,
               "kernel_drop_percent": 10.0, "invalid_frames_total": 0,
               "events_emitted_total": 2, "events_emitted_delta": 2,
               "flows_active": 1, "pending_requests": 0,
               "wsse_body_flows_active": 0}
    internal = {"_nt_internal": "capture_stats_v1", "capture": capture}
    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    _, stderr = process.communicate(json.dumps(internal) + "\n")
    thread.join(5)
    server.server_close()

    assert process.returncode == 0, stderr
    assert IngestHandler.paths == ["/api/agent/stats"]
    sample = IngestHandler.received[0]
    assert sample["schema_version"] == 1
    assert sample["type"] == "agent_stats"
    assert sample["mode"] == "python"
    assert sample["capture"] == capture
    assert sample["status"] == "degraded"
    assert sample["reasons"] == ["kernel_drop"]
    assert len(json.dumps(sample, separators=(",", ":")).encode("utf-8")) <= 16384
