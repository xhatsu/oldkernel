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
assert '[REDACTED]' not in raw
assert e['path'] == '/api/items'
assert e['status'] == 200 and e['resp_bytes'] == 42
assert e['trace_id'] == '0123456789abcdef0123456789abcdef'
assert e['source_probe'] == 'pcap-http-cpp'
assert len(e) == 24
print('Sniffer ASAN fixture: PASS (contract fields: 24)')

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
print('Shipper ASAN build & CLI: PASS')

print('ALL CPP EDGE TESTS PASSED')
