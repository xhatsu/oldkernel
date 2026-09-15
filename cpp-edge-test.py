#!/usr/bin/env python3
import base64, hashlib, hmac, json, os, shutil, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# 1. Test Sniffer under AddressSanitizer & UndefinedBehaviorSanitizer
src_sniff = Path(__file__).with_name('nt-sniff-cpp.cpp')
out_sniff = Path('/tmp/nt-sniff-cpp-edge-test')
cmd_sniff = ['g++','-std=gnu++03','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread',str(src_sniff),'-o',str(out_sniff)]
r = subprocess.run(cmd_sniff, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if r.returncode:
    print('Sniffer compile failed:', r.stderr); sys.exit(r.returncode)

raw = subprocess.check_output([str(out_sniff), '--fixture'], text=True)
e = json.loads(raw)
assert e['user'] == 'alice'
assert e['basic_user'] == 'alice' and e['wsse_user'] is None
assert '[REDACTED]' not in raw
assert e['path'] == '/api/items'
assert e['status'] == 200 and e['resp_bytes'] == 42
assert e['trace_id'] == '0123456789abcdef0123456789abcdef'
assert e['source_probe'] == 'pcap-http-cpp'
assert len(e) == 26
print('Sniffer ASAN fixture: PASS (contract fields: 26)')

wsse_raw = subprocess.check_output([str(out_sniff), '--wsse-fixture'], text=True)
assert wsse_raw.splitlines() == ['native.fixture'] * 4
assert 'SENSITIVE_PASSWORD' not in wsse_raw
bad = subprocess.run([str(out_sniff), '--wsse-body-bytes', '65537'],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert bad.returncode == 2
bad_rate = subprocess.run([str(out_sniff), '--ship-rate-kbps', '63'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert bad_rate.returncode == 2
print('Sniffer bounded WSSE fixture: PASS (4 namespaces, DTD rejection, bounds)')

dual_raw = subprocess.check_output([str(out_sniff), '--dual-auth-fixture'], text=True)
dual = json.loads(dual_raw)
assert dual['user'] == 'soap.user' and dual['scheme'] == 'wsse'
assert dual['basic_user'] == 'basic.user' and dual['wsse_user'] == 'soap.user'
assert 'SENSITIVE_PASSWORD' not in dual_raw and 'Envelope' not in dual_raw
print('Sniffer dual Basic+WSSE identity fixture: PASS')

ring = subprocess.run([str(out_sniff), '--ring-fixture'],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert ring.returncode == 0, ring.stderr
print('Sniffer TPACKET_V2 geometry and frame bounds fixture: PASS')
rate = subprocess.run([str(out_sniff), '--ship-rate-fixture'],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
print('Native shipper 64 KiB batch ceiling fixture: PASS')

lockout = subprocess.run([str(out_sniff), '--lockout-fixture'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert lockout.returncode == 0, lockout.stderr
assert 'Lockout registry 10k bounded fixture: PASS' in lockout.stderr
print('Sniffer bounded lockout registry 10k fixture: PASS')

fifo = subprocess.run([str(out_sniff), '--fifo-fixture'],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert fifo.returncode == 0, fifo.stderr
assert 'FIFO removal fixture: PASS' in fifo.stderr
print('Sniffer FIFO removal & bounded scaling fixture: PASS')

flow_acc = subprocess.run([str(out_sniff), '--flow-accounting-fixture'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert flow_acc.returncode == 0, flow_acc.stderr
assert 'Flow accounting fixture: PASS' in flow_acc.stderr
print('Sniffer flow-accounting bounds & zero leak fixture: PASS')


stats = subprocess.run([str(out_sniff), '--stats-fixture'],
                       text=True, capture_output=True)
assert stats.returncode == 0, stats.stderr
stats_body = json.loads(stats.stdout)
assert stats_body['schema_version'] == 1
assert stats_body['type'] == 'agent_stats'
assert stats_body['mode'] == 'cpp'
assert stats_body['shipping']['drop_percent'] == 20.0
assert stats_body['capture']['cpu_user_seconds'] >= 0
assert stats_body['capture']['cpu_system_seconds'] >= 0
assert stats_body['capture']['cpu_percent_one_core'] >= 0
assert len(stats.stdout.encode('utf-8')) <= 16384
print('Native agent statistics v1 fixture: PASS')

# 2. Test Shipper under AddressSanitizer & UndefinedBehaviorSanitizer
src_ship = Path(__file__).with_name('nt-ship-cpp.cpp')
out_ship = Path('/tmp/nt-ship-cpp-edge-test')
cmd_ship = ['g++','-std=gnu++03','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread',str(src_ship),'-lrt','-o',str(out_ship)]
r = subprocess.run(cmd_ship, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if r.returncode:
    print('Shipper compile failed:', r.stderr); sys.exit(r.returncode)

# Verify shipper CLI help and argument parsing
help_out = subprocess.check_output([str(out_ship), '--help'], text=True)
assert 'usage: nt-ship-cpp' in help_out
bad_ship_rate = subprocess.run([str(out_ship), '--endpoint', 'http://127.0.0.1',
                                '--ship-rate-kbps', '10001'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
assert bad_ship_rate.returncode == 2
ship_stats = json.loads(subprocess.check_output(
    [str(out_ship), '--stats-fixture'], text=True))
assert ship_stats['schema_version'] == 1
assert ship_stats['type'] == 'agent_stats' and ship_stats['mode'] == 'cpp'
assert ship_stats['shipping']['drop_percent'] == 20.0
assert ship_stats['limits']['wsse_body_bytes'] == 8192
assert len(json.dumps(ship_stats, separators=(',', ':')).encode('utf-8')) <= 16384
print('Shipper bounded egress and statistics fixtures: PASS')

control = subprocess.run([str(out_ship), '--control-fixture'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
assert control.returncode == 0, control.stderr
assert 'stats control HMAC fixture: PASS' in control.stdout
print('Shipper authenticated stats-response control fixture: PASS')

class ControlHandler(BaseHTTPRequestHandler):
    response_body = b'{}'

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(self.response_body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, *args):
        pass

control_run = tempfile.mkdtemp(prefix='nt-stats-control-')
server = None
process = None
try:
    node = 'native-control-node'
    token = 'native-control-token'
    issued = int(time.time())
    expires = issued + 300
    command_id = 'native-off-1'
    canonical = 'v1\n%s\n%s\noff\n%d\n%d\n' % (
        node, command_id, issued, expires)
    signature = hmac.new(token.encode('utf-8'), canonical.encode('utf-8'),
                         hashlib.sha256).hexdigest()
    response = {'status': 200, 'ok': True, 'accepted': True,
                'control_version': 1, 'command': 'off',
                'command_id': command_id, 'issued_at': issued,
                'expires_at': expires, 'signature': signature}
    ControlHandler.response_body = json.dumps(
        response, separators=(',', ':')).encode('utf-8')
    server = HTTPServer(('127.0.0.1', 0), ControlHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token_file = Path(control_run) / 'control.token'
    token_file.write_text(token)
    env = dict(os.environ, NT_NODE_NAME=node,
               NT_CONTROL_TOKEN_FILE=str(token_file),
               NT_CONTROL_RUN=control_run)
    process = subprocess.Popen(
        [str(out_ship), '--endpoint',
         'http://127.0.0.1:%d' % server.server_address[1]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env)
    process.stdin.write(json.dumps({
        '_nt_internal': 'capture_stats_v1',
        'capture': {'packets_total': 1, 'packets_delta': 1}},
        separators=(',', ':')) + '\n')
    process.stdin.flush()
    process.wait(timeout=8)
    process.stdin.close()
    stderr = process.stderr.read()
    assert process.returncode == 0, stderr
    receipt = json.loads((Path(control_run) /
                          'stats-control-applied.json').read_text())
    assert receipt['command_id'] == command_id
    assert 'authenticated remote stats command accepted' in stderr
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait()
    if server is not None:
        server.shutdown()
        server.server_close()
    shutil.rmtree(control_run)
print('Shipper signed HTTP stats-response clean-stop fixture: PASS')

print('ALL CPP EDGE TESTS PASSED')
