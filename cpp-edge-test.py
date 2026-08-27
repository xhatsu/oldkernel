#!/usr/bin/env python3
import base64, json, subprocess, sys
from pathlib import Path
src = Path(__file__).with_name('nt-sniff-cpp.cpp')
out = Path('/tmp/nt-sniff-cpp-edge-test')
cmd = ['g++','-std=gnu++03','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(src),'-o',str(out)]
r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if r.returncode:
    print(r.stderr); sys.exit(r.returncode)
raw = subprocess.check_output([str(out), '--fixture'], text=True)
e = json.loads(raw)
assert e['user'] == 'alice'
assert '[REDACTED]' not in raw
assert e['path'] == '/api/items'
assert e['status'] == 200 and e['resp_bytes'] == 42
assert e['trace_id'] == '0123456789abcdef0123456789abcdef'
print('ASAN fixture: PASS')
print('contract fields:', len(e))
