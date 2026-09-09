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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append(json.loads(self.rfile.read(length)))
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


def test_shipper_flushes_partial_batch_at_eof():
    IngestHandler.received = []
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
