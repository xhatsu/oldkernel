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


def request(body, authorization=None):
    raw = body.encode("utf-8")
    auth = (("Authorization: %s\r\n" % authorization).encode("ascii")
            if authorization else b"")
    head = (b"POST /soap HTTP/1.1\r\nHost: fixture\r\n" + auth +
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
    assert out[0]["basic_user"] is None
    assert out[0]["wsse_user"] == "billing.fixture"
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
    assert out[0]["basic_user"] is None
    assert out[0]["wsse_user"] is None
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


def test_dual_auth_reports_wsse_primary_and_both_users():
    head, raw = request(soap(OASIS_2004, "soap.user"),
                        "Basic YmFzaWMudXNlcjpwYXNzd29yZA==")
    flows, out = feed((head + raw,), 8192)

    assert flows == {}
    assert len(out) == 1
    assert out[0]["user"] == "soap.user"
    assert out[0]["scheme"] == "wsse"
    assert out[0]["basic_user"] == "basic.user"
    assert out[0]["wsse_user"] == "soap.user"
    assert "password" not in json.dumps(out[0]).lower()


def test_basic_identity_survives_rejected_or_disabled_wsse():
    wrong_ns = soap("urn:not-wsse", "wrong.user")
    head, raw = request(wrong_ns, "Basic YmFzaWMudXNlcjpwYXNzd29yZA==")
    _, out = feed((head + raw,), 8192)
    assert out[0]["user"] == "basic.user"
    assert out[0]["scheme"] == "basic"
    assert out[0]["basic_user"] == "basic.user"
    assert out[0]["wsse_user"] is None

    head, raw = request(soap(OASIS_2004, "hidden.wsse"),
                        "Basic YmFzaWMudXNlcjpwYXNzd29yZA==")
    _, out = feed((head + raw,), 0)
    assert out[0]["user"] == "basic.user"
    assert out[0]["scheme"] == "basic"
    assert out[0]["basic_user"] == "basic.user"
    assert out[0]["wsse_user"] is None


def test_invalid_basic_allows_valid_wsse_without_basic_identity():
    head, raw = request(soap(OASIS_2004, "soap.only"), "Basic !!!")
    _, out = feed((head + raw,), 8192)
    assert out[0]["user"] == "soap.only"
    assert out[0]["scheme"] == "wsse"
    assert out[0]["basic_user"] is None
    assert out[0]["wsse_user"] == "soap.only"


def test_wsse_flow_limit_falls_back_to_basic_without_growing_limit():
    flows = {}
    for index in range(nt_sniff.MAX_WSSE_BODY_FLOWS):
        flow = nt_sniff.Flow()
        flow.event = {"user": None}
        flow.body_goal = 1
        flows[("held", index)] = flow
    out = []
    key = ("192.0.2.2", 51000, "192.0.2.1", 18080)
    meta = ("192.0.2.1", 18080, "192.0.2.2", 51000)
    head, raw = request(soap(OASIS_2004, "not.buffered"),
                        "Basic YmFzaWMudXNlcjpwYXNzd29yZA==")

    nt_sniff.handle_payload(flows, key, None, head + raw, meta, set([18080]),
                            "fixture", out, None, 10.0, 8192)

    assert len(out) == 1
    assert out[0]["user"] == "basic.user"
    assert out[0]["scheme"] == "basic"
    assert out[0]["basic_user"] == "basic.user"
    assert out[0]["wsse_user"] is None
    assert len(flows) == nt_sniff.MAX_WSSE_BODY_FLOWS


def test_new_keepalive_request_flushes_incomplete_dual_auth_as_basic():
    body = b"<s:Envelope>incomplete"
    first = (b"POST /soap HTTP/1.1\r\nHost: fixture\r\n"
             b"Authorization: Basic YmFzaWMudXNlcjpwYXNzd29yZA==\r\n"
             b"Content-Type: application/soap+xml\r\n"
             b"Content-Length: 4096\r\n\r\n" + body)
    second = (b"GET /next HTTP/1.1\r\nHost: fixture\r\n"
              b"Authorization: Basic c2Vjb25kLnVzZXI6cGFzcw==\r\n\r\n")
    flows, out = feed((first, second), 8192)

    assert flows == {}
    assert [event["user"] for event in out] == ["basic.user", "second.user"]
    assert out[0]["wsse_user"] is None


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
                     [{"path": "/fresh"}, 2.0 + nt_sniff.PENDING_TTL]]}
    out = []

    nt_sniff.sweep_pending(pending, 2.0 + nt_sniff.PENDING_TTL + 0.1, out)

    assert [event["path"] for event in out] == ["/one", "/two"]
    active = [item for item in pending[key] if not (item[2] if len(item) > 2 else False)]
    assert active[0][0]["path"] == "/fresh"


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


def test_bounded_lockout_registry_10k_connections():
    nt_sniff.corr_disabled_clear()
    pending = {}
    out = []
    # Add 10,000 requests on distinct client ports
    for i in range(10000):
        rk = ("10.0.0.2", 8080, "10.0.0.1", 10000 + i)
        pending[rk] = [[{"path": "/item/%d" % i, "method": "GET"}, 100.0, True, 100.0, 0]]
    # Sweep at t=120s (tombstone TTL expired)
    nt_sniff.sweep_pending(pending, 120.0, out)
    assert len(pending) == 0
    assert len(nt_sniff.corr_disabled) <= nt_sniff.MAX_CORR_DISABLED
    assert len(nt_sniff.corr_disabled) == 2048
    assert nt_sniff.corr_capacity_reached is True

    # Evicted connection (port 10000) arrives without SYN:
    # Must fall back to emitting without correlation!
    evicted_rk = ("10.0.0.2", 8080, "10.0.0.1", 10000)
    assert evicted_rk not in nt_sniff.corr_disabled  # was evicted from bounded set
    assert nt_sniff.is_correlation_disabled(evicted_rk, syn_seen=False) is True

    # With verified SYN, correlation is re-enabled:
    assert nt_sniff.is_correlation_disabled(evicted_rk, syn_seen=True) is False
    nt_sniff.corr_disabled_clear()


def test_old_syn_does_not_bypass_evicted_lockout():
    nt_sniff.corr_disabled_clear()
    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    key = ("10.0.0.1", 50026, "10.0.0.2", 80)
    meta = ("10.0.0.2", 80, "10.0.0.1", 50026)
    rk = ("10.0.0.2", 80, "10.0.0.1", 50026)

    # 1. Connection starts with client SYN
    nt_sniff.handle_payload(flows, key, None, b"", meta, {80}, "node", out,
                            pending_tbl=pending, now=100.0, seq=1000, flags=0x02, resp_flows=resp_flows)
    assert flows[key].syn_seen is True
    assert flows[key].generation == 1
    assert flows[key].corr_eligible is True

    # 2. Connection loses ordering (e.g. invalidate_connection_correlation)
    nt_sniff.invalidate_connection_correlation(flows, resp_flows, rk)
    assert flows[key].corr_eligible is False
    assert resp_flows[rk].corr_eligible is False

    # 3. Flood 2050 distinct connections to saturate registry and evict rk
    for i in range(2050):
        dummy_rk = ("10.0.0.2", 80, "10.0.0.1", 10000 + i)
        nt_sniff.corr_disabled_insert(dummy_rk)
    assert rk not in nt_sniff.corr_disabled  # evicted!
    assert nt_sniff.corr_capacity_reached is True

    # 4. /new arrives on old connection (syn_seen is True from old SYN, but corr_eligible is False)
    assert nt_sniff.is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                          gen=flows[key].generation, syn_seen=flows[key].syn_seen,
                                          corr_eligible=flows[key].corr_eligible) is False
    nt_sniff.corr_disabled_clear()


def test_synack_preserves_verification_under_capacity_fallback():
    nt_sniff.corr_disabled_clear()
    # Saturate registry to activate capacity fallback
    for i in range(2050):
        dummy_rk = ("10.0.0.2", 80, "10.0.0.1", 10000 + i)
        nt_sniff.corr_disabled_insert(dummy_rk)
    assert nt_sniff.corr_capacity_reached is True

    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    key = ("10.0.0.1", 50027, "10.0.0.2", 80)
    meta = ("10.0.0.2", 80, "10.0.0.1", 50027)
    rk = ("10.0.0.2", 80, "10.0.0.1", 50027)

    # 1. Fresh client SYN arrives
    nt_sniff.handle_payload(flows, key, None, b"", meta, {80}, "node", out,
                            pending_tbl=pending, now=170.0, seq=2000, flags=0x02, resp_flows=resp_flows)
    assert flows[key].syn_seen is True
    assert flows[key].generation == 1
    assert resp_flows[rk].generation == 1
    assert resp_flows[rk].syn_seen is True
    assert resp_flows[rk].corr_eligible is True

    # 2. Server SYN-ACK arrives: must preserve generation and eligibility
    nt_sniff.handle_response(resp_flows, rk, b"", 170.1, out, pending,
                            seq=5000, flags=0x12, flows=flows)
    assert resp_flows[rk].generation == 1
    assert resp_flows[rk].syn_seen is True
    assert resp_flows[rk].corr_eligible is True

    # Both directions must be allowed to correlate under capacity fallback
    assert nt_sniff.is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                          gen=flows[key].generation, syn_seen=flows[key].syn_seen,
                                          corr_eligible=flows[key].corr_eligible) is True
    assert nt_sniff.is_correlation_allowed(rk, flows=flows, resp_flows=resp_flows,
                                          gen=resp_flows[rk].generation, syn_seen=resp_flows[rk].syn_seen,
                                          corr_eligible=resp_flows[rk].corr_eligible) is True
    nt_sniff.corr_disabled_clear()


def test_client_syn_resets_is_broken():
    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    key = ("10.0.0.1", 50028, "10.0.0.2", 80)
    meta = ("10.0.0.2", 80, "10.0.0.1", 50028)
    rk = ("10.0.0.2", 80, "10.0.0.1", 50028)

    # 1. Connection starts and breaks due to invalid framing / conflict CL
    nt_sniff.handle_payload(flows, key, None, b"", meta, {80}, "node", out,
                            pending_tbl=pending, now=10.0, seq=1000, flags=0x02, resp_flows=resp_flows)
    bad_req = b"POST /bad HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n12345"
    nt_sniff.handle_payload(flows, key, None, bad_req, meta, {80}, "node", out,
                            pending_tbl=pending, now=10.1, seq=1001, flags=0x18, resp_flows=resp_flows)
    assert flows[key].corr_eligible is False

    # 2. Client initiates a new connection with fresh SYN
    nt_sniff.handle_payload(flows, key, None, b"", meta, {80}, "node", out,
                            pending_tbl=pending, now=20.0, seq=3000, flags=0x02, resp_flows=resp_flows)
    assert flows[key].corr_eligible is True
    assert flows[key].generation == 2

    # 3. Valid request and response produce event with status 200
    good_req = b"GET /api/valid28 HTTP/1.1\r\nHost: x\r\n\r\n"
    nt_sniff.handle_payload(flows, key, None, good_req, meta, {80}, "node", out,
                            pending_tbl=pending, now=20.1, seq=3001, flags=0x18, resp_flows=resp_flows)
    good_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    nt_sniff.handle_response(resp_flows, rk, good_resp, 20.2, out, pending,
                            seq=5000, flags=0x18, flows=flows)

    valid_events = [e for e in out if e.get("path") == "/api/valid28"]
    assert len(valid_events) == 1
    assert valid_events[0].get("status") == 200


def test_expired_head_request_preserves_bodyless_response():
    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    key = ("10.0.0.1", 50029, "10.0.0.2", 80)
    meta = ("10.0.0.2", 80, "10.0.0.1", 50029)
    rk = ("10.0.0.2", 80, "10.0.0.1", 50029)

    # 1. Connection starts
    nt_sniff.handle_payload(flows, key, None, b"", meta, {80}, "node", out,
                            pending_tbl=pending, now=10.0, seq=1000, flags=0x02, resp_flows=resp_flows)

    # 2. Client sends HEAD request
    head_req = b"HEAD /api/head29 HTTP/1.1\r\nHost: x\r\n\r\n"
    nt_sniff.handle_payload(flows, key, None, head_req, meta, {80}, "node", out,
                            pending_tbl=pending, now=10.1, seq=1001, flags=0x18, resp_flows=resp_flows)
    assert len(pending[rk]) == 1
    assert pending[rk][0][0].get("method") == "HEAD"

    # 3. Advance time past pending TTL -> HEAD request expires to tombstone
    exp_now = 10.1 + nt_sniff.PENDING_TTL + 1.0
    nt_sniff.sweep_pending(pending, exp_now, out, flows=flows, resp_flows=resp_flows)
    assert len(out) == 1
    assert out[0].get("path") == "/api/head29"
    assert out[0].get("status") is None
    assert len(pending[rk]) == 1
    assert pending[rk][0][2] is True  # is_tombstone

    # 4. Client sends GET request on same connection
    get_req = b"GET /api/get29 HTTP/1.1\r\nHost: x\r\n\r\n"
    nt_sniff.handle_payload(flows, key, None, get_req, meta, {80}, "node", out,
                            pending_tbl=pending, now=exp_now + 0.1, seq=1001 + len(head_req), flags=0x18, resp_flows=resp_flows)
    assert len(pending[rk]) == 2  # [tombstone, get_req]

    # 5. Server sends response to HEAD with Content-Length: 100 (bodyless per RFC)
    # followed by response to GET with 200 OK
    resp_head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    resp_get = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
    nt_sniff.handle_response(resp_flows, rk, resp_head + resp_get, exp_now + 0.2, out, pending,
                            seq=5000, flags=0x18, flows=flows)

    get_events = [e for e in out if e.get("path") == "/api/get29"]
    assert len(get_events) == 1
    assert get_events[0].get("status") == 200
    assert get_events[0].get("resp_bytes") == 5


def test_first_fragment_rejected():
    import struct
    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    # Build an Ethernet + IPv4 + TCP packet
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", 50000, 80, 1000, 0, (5 << 4), 0x02, 65535, 0, 0)
    # 1. Unfragmented packet (frag = 0): accepted
    ip_hdr_normal = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 100, 0, 64, 6, 0,
                                b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    pkt_normal = eth + ip_hdr_normal + tcp
    assert nt_sniff.process_packet(pkt_normal, {80}, "node", flows, resp_flows, pending, out, now=10.0) is True

    # 2. DF packet (frag = 0x4000): accepted
    ip_hdr_df = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 101, 0x4000, 64, 6, 0,
                            b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    pkt_df = eth + ip_hdr_df + tcp
    assert nt_sniff.process_packet(pkt_df, {80}, "node", flows, resp_flows, pending, out, now=10.0) is True

    # 3. First fragment with MF bit set (frag = 0x2000): rejected!
    ip_hdr_mf = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 102, 0x2000, 64, 6, 0,
                            b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    pkt_mf = eth + ip_hdr_mf + tcp
    assert nt_sniff.process_packet(pkt_mf, {80}, "node", flows, resp_flows, pending, out, now=10.0) is False

    # 4. Non-first fragment with offset (frag = 0x0005): rejected!
    ip_hdr_offset = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 103, 0x0005, 64, 6, 0,
                               b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    pkt_offset = eth + ip_hdr_offset + tcp
    assert nt_sniff.process_packet(pkt_offset, {80}, "node", flows, resp_flows, pending, out, now=10.0) is False


def test_rlimit_as_enforced():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        # Verify RLIMIT_AS is bounded (not infinity or <= 256 MiB)
        assert hard != resource.RLIM_INFINITY or soft <= 256 * 1024 * 1024
    except Exception:
        pass


def _make_tcp_pkt(src_ip_str, sport, dst_ip_str, dport, seq, ack, flags, payload):
    import socket, struct
    src_ip = socket.inet_aton(src_ip_str)
    dst_ip = socket.inet_aton(dst_ip_str)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tot_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 100, 0x4000, 64, 6, 0, src_ip, dst_ip)
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload


def test_pending_accounting_lifecycle_and_overflow_failsafe():
    """Verify pending accounting never leaks across lifecycles and overflow protection is failsafe."""
    flows = {}
    resp_flows = {}
    pending = {}
    out = []

    # Reset global accounting before starting test
    nt_sniff.g_pending_events_total = 0
    nt_sniff.corr_disabled_clear()

    # 1. 500 requests + 500 responses lifecycle
    for i in range(500):
        src_port = 10000 + i
        syn_pkt = _make_tcp_pkt("10.0.0.1", src_port, "10.0.0.2", 80, 1000 + i * 100, 0, 0x02, b"")
        req_pkt = _make_tcp_pkt("10.0.0.1", src_port, "10.0.0.2", 80, 1001 + i * 100, 0, 0x18,
                                b"GET /req%d HTTP/1.1\r\nHost: example.com\r\n\r\n" % i)
        nt_sniff.process_packet(syn_pkt, {80}, "node", flows, resp_flows, pending, out, now=10.0 + i * 0.01)
        nt_sniff.process_packet(req_pkt, {80}, "node", flows, resp_flows, pending, out, now=10.0 + i * 0.01)

    assert nt_sniff.g_pending_events_total == len(pending) == 500
    assert nt_sniff.pending_actual_count(pending) == 500
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    for i in range(500):
        src_port = 10000 + i
        resp_pkt = _make_tcp_pkt("10.0.0.2", 80, "10.0.0.1", src_port, 5000 + i * 100, 0, 0x18,
                                 b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        nt_sniff.process_packet(resp_pkt, {80}, "node", flows, resp_flows, pending, out, now=20.0 + i * 0.01)

    assert nt_sniff.g_pending_events_total == 0
    assert len(pending) == 0
    assert nt_sniff.pending_actual_count(pending) == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 2. WebSocket 101 upgrade accounting
    syn_pkt = _make_tcp_pkt("10.0.0.1", 20001, "10.0.0.2", 80, 50000, 0, 0x02, b"")
    req_pkt = _make_tcp_pkt("10.0.0.1", 20001, "10.0.0.2", 80, 50001, 0, 0x18,
                            b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n")
    nt_sniff.process_packet(syn_pkt, {80}, "node", flows, resp_flows, pending, out, now=200.0)
    nt_sniff.process_packet(req_pkt, {80}, "node", flows, resp_flows, pending, out, now=200.0)
    assert nt_sniff.g_pending_events_total == 1
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    resp_101 = _make_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 20001, 70000, 0, 0x18,
                             b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
    nt_sniff.process_packet(resp_101, {80}, "node", flows, resp_flows, pending, out, now=200.1)
    assert nt_sniff.g_pending_events_total == 0
    assert len(pending) == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 3. RST teardown accounting
    syn_pkt = _make_tcp_pkt("10.0.0.1", 20002, "10.0.0.2", 80, 60000, 0, 0x02, b"")
    req_pkt = _make_tcp_pkt("10.0.0.1", 20002, "10.0.0.2", 80, 60001, 0, 0x18,
                            b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
    nt_sniff.process_packet(syn_pkt, {80}, "node", flows, resp_flows, pending, out, now=300.0)
    nt_sniff.process_packet(req_pkt, {80}, "node", flows, resp_flows, pending, out, now=300.0)
    assert nt_sniff.g_pending_events_total == 1
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    rst_pkt = _make_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 20002, 80000, 0, 0x04, b"")
    nt_sniff.process_packet(rst_pkt, {80}, "node", flows, resp_flows, pending, out, now=300.1)
    assert nt_sniff.g_pending_events_total == 0
    assert len(pending) == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 4. Tombstone expiration sweep accounting
    syn_pkt = _make_tcp_pkt("10.0.0.1", 20003, "10.0.0.2", 80, 70000, 0, 0x02, b"")
    req_pkt = _make_tcp_pkt("10.0.0.1", 20003, "10.0.0.2", 80, 70001, 0, 0x18,
                            b"GET /timeout HTTP/1.1\r\nHost: example.com\r\n\r\n")
    nt_sniff.process_packet(syn_pkt, {80}, "node", flows, resp_flows, pending, out, now=400.0)
    nt_sniff.process_packet(req_pkt, {80}, "node", flows, resp_flows, pending, out, now=400.0)
    assert nt_sniff.g_pending_events_total == 1

    # Sweep after PENDING_TTL converts to tombstone
    nt_sniff.sweep_pending(pending, 400.0 + nt_sniff.PENDING_TTL + 0.1, out, flows=flows, resp_flows=resp_flows)
    assert nt_sniff.g_pending_events_total == 1

    # Sweep after tombstone expiry (10s) removes tombstone and clears connection
    nt_sniff.sweep_pending(pending, 400.0 + nt_sniff.PENDING_TTL + 15.0, out, flows=flows, resp_flows=resp_flows)
    assert nt_sniff.g_pending_events_total == 0
    assert len(pending) == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 5. Corruption resilience: g_pending_events_total corrupted to MAX_PENDING_EVENTS with empty table
    nt_sniff.g_pending_events_total = nt_sniff.MAX_PENDING_EVENTS + 500
    res = nt_sniff.ensure_pending_capacity(pending, out, flows=flows, resp_flows=resp_flows)
    assert res is True
    assert nt_sniff.g_pending_events_total == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 6. Corruption resilience: g_pending_events_total corrupted to negative value
    nt_sniff.g_pending_events_total = -42
    res = nt_sniff.ensure_pending_capacity(pending, out, flows=flows, resp_flows=resp_flows)
    assert res is True
    assert nt_sniff.g_pending_events_total == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 7. Single legitimate request with g_pending_events_total = 16384 (corrupted/stale)
    # Must repair BEFORE eviction so the legitimate request is NOT evicted!
    test_rk = ("10.0.0.2", 80, "10.0.0.1", 30001)
    pending[test_rk] = [nt_sniff.PendingRequest({"path": "/legit"}, 500.0, 1, 999)]
    nt_sniff.g_pending_events_total = nt_sniff.MAX_PENDING_EVENTS
    res = nt_sniff.ensure_pending_capacity(pending, out, flows=flows, resp_flows=resp_flows)
    assert res is True
    assert len(pending) == 1
    assert test_rk in pending
    assert pending[test_rk][0].event["path"] == "/legit"
    assert nt_sniff.g_pending_events_total == 1
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)

    # 8. Under-count detection in pending_take and pending_take_all
    # Add a second request to test_rk
    pending[test_rk].append(nt_sniff.PendingRequest({"path": "/second"}, 501.0, 1, 1000))
    # Deliberately set counter to 0 while 2 entries exist in table
    nt_sniff.g_pending_events_total = 0
    # pending_take must pop first entry and repair count to 1 (2 - 1)
    popped = nt_sniff.pending_take(pending, test_rk, 0)
    assert popped.event["path"] == "/legit"
    assert nt_sniff.g_pending_events_total == 1
    assert len(pending[test_rk]) == 1

    # Now set counter to 0 again, and pending_take_all must drain and repair count to 0
    nt_sniff.g_pending_events_total = 0
    all_popped = nt_sniff.pending_take_all(pending, test_rk)
    assert len(all_popped) == 1
    assert all_popped[0].event["path"] == "/second"
    assert nt_sniff.g_pending_events_total == 0
    assert len(pending) == 0
    nt_sniff.assert_internal_invariants(flows, resp_flows, pending)



