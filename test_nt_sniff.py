import importlib.util
import json
import os
import pytest


SPEC = importlib.util.spec_from_file_location(
    "nt_sniff", os.path.join(os.path.dirname(__file__), "nt-sniff.py"))
nt_sniff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nt_sniff)

OASIS_2004 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
LEGACY_WSSE = (
    "http://schemas.xmlsoap.org/ws/2002/07/secext",
    "http://schemas.xmlsoap.org/ws/2002/12/secext",
    "http://schemas.xmlsoap.org/ws/2003/06/secext",
)


def soap(namespace, username="billing.fixture"):
    return (u'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            u'xmlns:wsse="%s"><soap:Header><wsse:Security>'
            u'<wsse:UsernameToken><wsse:Username>%s</wsse:Username>'
            u'<wsse:Password Type="PasswordDigest">SENSITIVE_PASSWORD</wsse:Password>'
            u'<wsse:Nonce>SENSITIVE_NONCE</wsse:Nonce></wsse:UsernameToken>'
            u'</wsse:Security></soap:Header><soap:Body><Get/></soap:Body>'
            u'</soap:Envelope>') % (namespace, username)


def request(body):
    raw = body.encode("utf-8")
    head = (b"POST /soap HTTP/1.1\r\nHost: fixture\r\n"
            b"Content-Type: application/soap+xml; charset=utf-8\r\n"
            b"Content-Length: %d\r\n\r\n" % len(raw))
    return head, raw


def feed(parts, wsse_body_bytes):
    flows = {}
    out = []
    key = ("192.0.2.2", 51000, "192.0.2.1", 18080)
    meta = ("192.0.2.1", 18080, "192.0.2.2", 51000)
    for part in parts:
        nt_sniff.handle_payload(flows, key, None, part, meta, set([18080]),
                                "fixture", out, None, 10.0,
                                wsse_body_bytes)
    return flows, out


@pytest.mark.parametrize("namespace", (OASIS_2004,) + LEGACY_WSSE)
def test_opt_in_wsse_extracts_only_username_across_segments(namespace):
    body = soap(namespace)
    head, raw = request(body)
    split = len(raw) // 2
    flows, out = feed((head + raw[:split], raw[split:]), 8192)

    assert flows == {}
    assert len(out) == 1
    assert out[0]["user"] == "billing.fixture"
    assert out[0]["scheme"] == "wsse"
    serialized = json.dumps(out[0])
    for forbidden in ("SENSITIVE_PASSWORD", "SENSITIVE_NONCE",
                      "PasswordDigest", "soap:Envelope", "soap_body"):
        assert forbidden not in serialized


def test_default_remains_header_only_and_never_retains_body():
    head, raw = request(soap(OASIS_2004))
    flows, out = feed((head + raw,), 0)

    assert flows == {}
    assert len(out) == 1
    assert out[0]["user"] is None
    assert out[0]["scheme"] is None
    assert "SENSITIVE" not in repr(out)


def test_wsse_window_is_hard_bounded_and_invalid_declarations_are_rejected():
    head, raw = request("X" * 512 + soap(OASIS_2004))
    flows, out = feed((head + raw,), 128)
    assert flows == {}
    assert out[0]["user"] is None

    malicious = ('<!DOCTYPE x [<!ENTITY pw "SENSITIVE_PASSWORD">]>' +
                 soap(OASIS_2004, "&pw;"))
    assert nt_sniff.extract_wsse_username(malicious.encode("utf-8")) is None


def test_wsse_configuration_bounds():
    assert nt_sniff.parse_args([])[4] == 0
    assert nt_sniff.parse_args(["--wsse-body-bytes", "4096"])[4] == 4096
    with pytest.raises(SystemExit):
        nt_sniff.parse_wsse_body_bytes(nt_sniff.MAX_WSSE_BODY_BYTES + 1)


def test_response_correlation_preserves_pipelined_requests():
    key = ("10.0.0.2", 8080, "10.0.0.1", 51000)
    first = {"path": "/first"}
    second = {"path": "/second"}
    pending = {key: [[first, 10.0], [second, 11.0]]}
    out = []

    assert nt_sniff.correlate_response(
        pending, key, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
        12.0, out)
    assert out == [first]
    assert pending[key] == [[second, 11.0]]
    assert first["status"] == 200
    assert first["resp_bytes"] == 4

    assert nt_sniff.correlate_response(
        pending, key, b"HTTP/1.1 204 No Content\r\n\r\n", 13.0, out)
    assert out == [first, second]
    assert key not in pending
    assert second["status"] == 204


def test_pending_sweep_flushes_all_stale_requests_for_connection():
    key = ("10.0.0.2", 8080, "10.0.0.1", 51000)
    pending = {key: [[{"path": "/one"}, 1.0],
                     [{"path": "/two"}, 2.0],
                     [{"path": "/fresh"}, 9.0]]}
    out = []

    nt_sniff.sweep_pending(pending, 10.0, out)

    assert [event["path"] for event in out] == ["/one", "/two"]
    assert pending[key][0][0]["path"] == "/fresh"


def test_idle_sweep_cadence_honors_pending_ttl():
    assert nt_sniff.SWEEP_INTERVAL <= nt_sniff.PENDING_TTL
    assert not nt_sniff.maintenance_due(100.5, 100.0)
    assert nt_sniff.maintenance_due(
        100.0 + nt_sniff.PENDING_TTL, 100.0)


def test_shutdown_drains_requests_awaiting_response():
    first_key = ("10.0.0.2", 8080, "10.0.0.1", 51000)
    second_key = ("10.0.0.3", 8080, "10.0.0.1", 51001)
    pending = {
        first_key: [[{"path": "/one"}, 1.0], [{"path": "/two"}, 2.0]],
        second_key: [[{"path": "/three"}, 3.0]],
    }
    out = []

    nt_sniff.drain_pending(pending, out)

    assert pending == {}
    assert sorted(event["path"] for event in out) == [
        "/one", "/three", "/two"]


class FakeControlClient(object):
    def __init__(self, reply):
        self.reply = reply
        self.reports = []
        self.heartbeats = []

    def poll(self):
        return self.reply

    def report(self, task_id, status, message):
        self.reports.append((task_id, status, message))

    def heartbeat(self, generation, applied):
        self.heartbeats.append((generation, applied))


def test_control_config_change_requests_in_place_restart(tmp_path):
    client = FakeControlClient({
        "desired": {"generation": 3, "ports": [8080], "iface": "eth1"},
        "tasks": [],
    })
    ports, iface, action, status = nt_sniff._run_control_tick(
        set([80]), "eth0", str(tmp_path), client)

    assert ports == set([8080])
    assert iface == "eth1"
    assert action == "restart"
    assert status == "restart required"
    args = nt_sniff._restart_args("nt-sniff.py", iface, ports, True, 2)
    assert args[1:] == ["-u", os.path.abspath("nt-sniff.py"), "-i", "eth1",
                       "-p", "8080", "-j", "1", "-v"]


def test_multiple_capture_workers_are_rejected():
    with pytest.raises(SystemExit, match="only one capture worker"):
        nt_sniff.parse_args(["-j", "2"])


def test_control_stop_requests_process_exit(tmp_path):
    client = FakeControlClient({
        "desired": {"generation": 4},
        "tasks": [{"id": 9, "action": "stop", "args": {}}],
    })
    ports, iface, action, status = nt_sniff._run_control_tick(
        set([80]), "eth0", str(tmp_path), client)

    assert ports == set([80])
    assert iface == "eth0"
    assert action == "stop"
    assert status == "stop requested"
    assert client.reports == [(9, "done", "stop requested")]
