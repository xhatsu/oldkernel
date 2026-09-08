import json
import os
import subprocess
import sys
import threading

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


class IngestHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append(json.loads(self.rfile.read(length)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


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
        universal_newlines=True)
    stdout, stderr = process.communicate(json.dumps({"path": "/last"}) + "\n")
    thread.join(5)
    server.server_close()

    assert process.returncode == 0, stderr
    assert stdout == ""
    assert len(IngestHandler.received) == 1
    assert IngestHandler.received[0]["events"] == [{"path": "/last"}]
    assert "stopped (0 events pending on exit)" in stderr
