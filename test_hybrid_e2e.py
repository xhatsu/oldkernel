import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

HUB_PORT = 31300
TARGET_PORT = 31299

ingest_batches = []
agent_stats_reports = []

class MockHubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.path == "/api/ingest":
            try:
                data = json.loads(body.decode("utf-8"))
                ingest_batches.append(data)
            except Exception as e:
                print("Failed parsing ingest:", e)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"success":true}')
        elif self.path == "/api/agent/stats":
            try:
                data = json.loads(body.decode("utf-8"))
                agent_stats_reports.append(data)
            except Exception as e:
                print("Failed parsing stats:", e)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"accepted":true}')
        else:
            self.send_response(404)
            self.end_headers()

class TargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello from Hybrid Target")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(b"<soap:Response>OK</soap:Response>")

def main():
    hub_server = http.server.HTTPServer(("127.0.0.1", HUB_PORT), MockHubHandler)
    hub_thread = threading.Thread(target=hub_server.serve_forever)
    hub_thread.daemon = True
    hub_thread.start()

    target_server = http.server.HTTPServer(("127.0.0.1", TARGET_PORT), TargetHandler)
    target_thread = threading.Thread(target=target_server.serve_forever)
    target_thread.daemon = True
    target_thread.start()

    time.sleep(0.5)

    prefix = "/opt/networktracing-legacy"
    pipeline_cmd = (
        "sudo su -s /bin/sh ntsniff -c '"
        + "export NT_STATS_INTERVAL_SEC=10; "
        + prefix + "/python-capnetraw -u " + prefix + "/nt-sniff.py -j 1 -i lo -p " + str(TARGET_PORT) + " --wsse-body-bytes 16384' "
        + "| sudo su -s /bin/sh ntsniff -c '"
        + prefix + "/nt-ship-cpp --endpoint http://127.0.0.1:" + str(HUB_PORT) + " --ship-rate-kbps 1024 --stats-interval-sec 10'"
    )
    print("Starting pipeline:", pipeline_cmd)
    pipe_proc = subprocess.Popen(pipeline_cmd, shell=True, preexec_fn=os.setsid)

    time.sleep(1.5)

    print("Sending Basic Auth GET request...")
    req = urllib.request.Request("http://127.0.0.1:%d/hybrid-test" % TARGET_PORT)
    req.add_header("Authorization", "Basic YWxpY2U6c2VjcmV0") # alice:secret
    req.add_header("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    req.add_header("User-Agent", "hybrid-tester/1.0")
    with urllib.request.urlopen(req) as resp:
        body = resp.read()
        print("GET response:", resp.status, body)

    time.sleep(0.5)

    print("Sending WSSE SOAP POST request...")
    soap_body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        b'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">\n'
        b'  <soapenv:Header>\n'
        b'    <wsse:Security>\n'
        b'      <wsse:UsernameToken>\n'
        b'        <wsse:Username>bob_soap</wsse:Username>\n'
        b'        <wsse:Password Type="...#PasswordText">topsecretpass</wsse:Password>\n'
        b'      </wsse:UsernameToken>\n'
        b'    </wsse:Security>\n'
        b'  </soapenv:Header>\n'
        b'  <soapenv:Body>\n'
        b'    <testAction/>\n'
        b'  </soapenv:Body>\n'
        b'</soapenv:Envelope>'
    )
    req2 = urllib.request.Request("http://127.0.0.1:%d/hybrid-soap" % TARGET_PORT, data=soap_body)
    req2.add_header("Content-Type", "text/xml; charset=utf-8")
    with urllib.request.urlopen(req2) as resp:
        body2 = resp.read()
        print("POST response:", resp.status, body2)

    print("Waiting for shipper flush and stats...")
    deadline = time.time() + 15.0
    while time.time() < deadline and (not ingest_batches or not agent_stats_reports):
        time.sleep(0.5)

    try:
        os.killpg(os.getpgid(pipe_proc.pid), 15)
    except Exception:
        pass
    pipe_proc.poll()

    print("Total ingest batches received:", len(ingest_batches))
    print("Total agent stats received:", len(agent_stats_reports))

    assert len(ingest_batches) > 0, "No ingest batches received by mock Hub!"
    events = []
    for b in ingest_batches:
        assert "node" in b, "Missing node in batch: %s" % b
        assert "events" in b, "Missing events in batch: %s" % b
        events.extend(b["events"])

    print("Total events decoded:", len(events))
    assert len(events) >= 2, "Expected at least 2 events, got %d: %s" % (len(events), events)

    get_ev = [e for e in events if e.get("path") == "/hybrid-test"]
    assert len(get_ev) >= 1, "Missing GET event: %s" % events
    e1 = get_ev[0]
    print("GET Event:", json.dumps(e1, indent=2))
    assert e1["user"] == "alice", "Expected user alice, got %s" % e1.get("user")
    assert e1["scheme"] == "basic", "Expected scheme basic, got %s" % e1.get("scheme")
    assert e1["status"] == 200, "Expected status 200, got %s" % e1.get("status")
    assert e1["duration_ms"] is not None and e1["duration_ms"] >= 0, "Invalid duration_ms"
    assert e1["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736", "Trace ID mismatch"
    assert "secret" not in json.dumps(e1), "Secret leaked in basic auth event!"

    soap_ev = [e for e in events if e.get("path") == "/hybrid-soap"]
    assert len(soap_ev) >= 1, "Missing SOAP event: %s" % events
    e2 = soap_ev[0]
    print("SOAP Event:", json.dumps(e2, indent=2))
    assert e2["user"] == "bob_soap", "Expected wsse user bob_soap, got %s" % e2.get("user")
    assert e2["scheme"] == "wsse", "Expected scheme wsse, got %s" % e2.get("scheme")
    assert e2["status"] == 200, "Expected status 200, got %s" % e2.get("status")
    assert "topsecretpass" not in json.dumps(e2), "Password leaked in SOAP event!"

    assert len(agent_stats_reports) > 0, "No agent stats received by mock Hub!"
    st = agent_stats_reports[0]
    print("Agent Stats Sample:", json.dumps(st, indent=2))
    assert "capture" in st, "Missing capture stats in agent stats payload"
    assert st["capture"]["packets_total"] > 0, "No packets recorded by capture engine"

    print("\n>>> ALL HYBRID PIPELINE END-TO-END TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    main()
