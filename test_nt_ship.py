import json
import os
import subprocess
import sys
import threading
import collections
import time
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


def test_input_line_size_bounding_64k():
    IngestHandler.received = []
    IngestHandler.paths = []
    server = HTTPServer(("127.0.0.1", 0), IngestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    # Valid event fitting in body cap (~50 KiB)
    valid_event = "{\"path\":\"%s\"}\n" % ("a" * 50000)
    # Oversized input line > 65536 bytes
    oversized = "{\"path\":\"%s\"}\n" % ("b" * 70000)
    small_valid = "{\"path\":\"/after_oversized\"}\n"

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    stdout, stderr = process.communicate(valid_event + oversized + small_valid)
    server.shutdown()
    server.server_close()

    assert process.returncode == 0, stderr
    assert "dropped oversized input line" in stderr
    paths = [ev["path"] for batch in IngestHandler.received for ev in batch.get("events", [])]
    assert len(paths) == 2
    assert paths[0].startswith("a")
    assert paths[1] == "/after_oversized"


def test_input_line_size_bounding_unterminated_drain():
    IngestHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), IngestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    huge_unterminated = ("x" * 262144) + "\n"
    valid = "{\"path\":\"/drained_ok\"}\n"

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    stdout, stderr = process.communicate(huge_unterminated + valid)
    server.shutdown()
    server.server_close()

    assert process.returncode == 0, stderr
    assert "dropped oversized input line" in stderr
    paths = [ev["path"] for batch in IngestHandler.received for ev in batch.get("events", [])]
    assert paths == ["/drained_ok"]


def test_dual_buffer_bounds_event_and_byte_caps():
    buf = collections.deque()
    stats = nt_ship.ShipStats()
    buf_bytes = 0

    for i in range(4005):
        raw = json.dumps({"idx": i})
        while len(buf) >= nt_ship.MAX_BUFFER_EVENTS:
            oldest = buf.popleft()
            stats.dropped("queue_full", 1)
        buf.append(raw)

    assert len(buf) == 4000
    assert stats.total["queue_full"] == 5
    assert json.loads(buf[0])["idx"] == 5

    buf.clear()
    stats = nt_ship.ShipStats()
    large_payload = "z" * (1024 * 1024)
    for i in range(9):
        raw = json.dumps({"idx": i, "payload": large_payload})
        raw_len = len(raw)
        while len(buf) >= nt_ship.MAX_BUFFER_EVENTS or (buf and buf_bytes + raw_len > nt_ship.MAX_BUFFER_BYTES):
            oldest = buf.popleft()
            buf_bytes -= len(oldest)
            stats.dropped("queue_full", 1)
        buf.append(raw)
        buf_bytes += raw_len

    assert buf_bytes <= nt_ship.MAX_BUFFER_BYTES
    assert len(buf) == 7
    assert stats.total["queue_full"] == 2
    assert json.loads(buf[0])["idx"] == 2


def test_fail_closed_rlimit_as_enforcement():
    script_path = os.path.join(os.path.dirname(__file__), "nt-ship.py")
    test_code = (
        "import sys, importlib.util\n"
        "spec = importlib.util.spec_from_file_location('nt_ship', %r)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "class FakeResource(object):\n"
        "    RLIMIT_AS = 9\n"
        "    RLIM_INFINITY = -1\n"
        "    @staticmethod\n"
        "    def getrlimit(res):\n"
        "        return (512*1024*1024, 512*1024*1024)\n"
        "    @staticmethod\n"
        "    def setrlimit(res, limits):\n"
        "        pass\n"
        "sys.modules['resource'] = FakeResource\n"
        "spec.loader.exec_module(m)\n"
        "m.enforce_rlimit_as()\n"
    ) % script_path
    process = subprocess.Popen(
        [sys.executable, "-c", test_code],
        stderr=subprocess.PIPE)
    _, stderr = process.communicate()
    assert process.returncode == 70
    assert b"cannot enforce address-space limit" in stderr


def test_keepalive_connection_reuse():
    class KeepAliveHandler(BaseHTTPRequestHandler):
        connection_ids = []
        def do_POST(self):
            sock_fd = self.connection.fileno()
            KeepAliveHandler.connection_ids.append(sock_fd)
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), KeepAliveHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    # Send 800 events so it packs into 2 batches of 400 events (MAX_BATCH = 400)
    events = "".join(json.dumps({"req": i}) + "\n" for i in range(800))
    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    process.communicate(events)
    server.shutdown()
    server.server_close()

    assert process.returncode == 0
    assert len(KeepAliveHandler.connection_ids) == 2
    # Both batches must reuse the exact same TCP socket fd!
    assert len(set(KeepAliveHandler.connection_ids)) == 1


def test_stable_x_batch_id_and_transient_retry():
    class RetryHandler(BaseHTTPRequestHandler):
        batch_ids = []
        attempts = 0
        def do_POST(self):
            RetryHandler.attempts += 1
            batch_id = self.headers.get("X-Batch-Id")
            RetryHandler.batch_ids.append(batch_id)
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.protocol_version = "HTTP/1.1"
            if RetryHandler.attempts == 1:
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")
        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), RetryHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    _, stderr = process.communicate(json.dumps({"retry": "test"}) + "\n")
    server.shutdown()
    server.server_close()

    assert process.returncode == 0, stderr
    assert RetryHandler.attempts == 2
    assert len(RetryHandler.batch_ids) == 2
    assert RetryHandler.batch_ids[0] == RetryHandler.batch_ids[1]
    assert RetryHandler.batch_ids[0] is not None
    assert "-1" in RetryHandler.batch_ids[0]


def test_permanent_4xx_dropped_without_retry():
    class Permanent400Handler(BaseHTTPRequestHandler):
        attempts = 0
        def do_POST(self):
            Permanent400Handler.attempts += 1
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Permanent400Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    _, stderr = process.communicate(json.dumps({"perm": "bad"}) + "\n")
    server.shutdown()
    server.server_close()

    assert process.returncode == 0, stderr
    assert Permanent400Handler.attempts == 1
    assert "rejected batch" in stderr


def test_all_2xx_responses_accepted():
    class Status204Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(204)
            self.end_headers()
        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Status204Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    endpoint = "http://127.0.0.1:%d" % server.server_address[1]
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")

    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="1", NT_SHIP_RATE_KBPS="10000"))
    _, stderr = process.communicate(json.dumps({"code": 204}) + "\n")
    server.shutdown()
    server.server_close()

    assert process.returncode == 0, stderr
    assert "dropped 0 events" not in stderr
    assert "Hub unreachable" not in stderr


def test_live_hub_ingest():
    script = os.path.join(os.path.dirname(__file__), "nt-ship.py")
    endpoint = "http://127.0.0.1:30102"
    test_event = {"path": "/live_hub_test", "node": "live-test", "ts": int(time.time())}
    process = subprocess.Popen(
        [sys.executable, script, "--endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
        env=dict(os.environ, NT_SHIP_THREADS="2", NT_SHIP_RATE_KBPS="10000"))
    _, stderr = process.communicate(json.dumps(test_event) + "\n")
    assert process.returncode == 0, stderr
    assert "stopped (0 events pending on exit)" in stderr
