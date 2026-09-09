#!/usr/bin/env python3
import base64, json, os, subprocess, sys
from pathlib import Path

# 1. Test Sniffer under AddressSanitizer & UndefinedBehaviorSanitizer
src_sniff = Path(__file__).with_name('nt-sniff-cpp.cpp')
out_sniff = Path('/tmp/nt-sniff-cpp-edge-test')
cmd_sniff = ['g++','-std=gnu++03','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(src_sniff),'-o',str(out_sniff)]
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
assert rate.returncode == 0, rate.stderr
print('Native shipper 64 KiB batch ceiling fixture: PASS')

# 2. Test Shipper under AddressSanitizer & UndefinedBehaviorSanitizer
src_ship = Path(__file__).with_name('nt-ship-cpp.cpp')
out_ship = Path('/tmp/nt-ship-cpp-edge-test')
cmd_ship = ['g++','-std=gnu++03','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(src_ship),'-o',str(out_ship)]
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
print('Shipper ASAN build & CLI: PASS')

print('ALL CPP EDGE TESTS PASSED')
