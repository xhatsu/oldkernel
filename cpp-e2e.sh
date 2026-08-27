#!/bin/sh
# Validate the native C++ oldkernel capture path on this host.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PORT=${NT_CPP_TEST_PORT:-31299}
TMP=${TMPDIR:-/tmp}/nt-cpp-e2e.$$
CAP_PID=
HTTP_PID=
cleanup() {
    if [ -n "$CAP_PID" ]; then sudo -n kill -TERM "$CAP_PID" 2>/dev/null || true; fi
    if [ -n "$HTTP_PID" ]; then kill -TERM "$HTTP_PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
rm -rf "$TMP"
mkdir -p "$TMP"
make -C "$HERE" clean cpp
"$HERE/nt-sniff-cpp" --fixture >"$TMP/fixture.jsonl"
python3 - "$TMP/fixture.jsonl" <<'PY'
import json, sys
e=json.load(open(sys.argv[1]))
assert e['method']=='GET' and e['path']=='/api/items'
assert e['user']=='alice' and e['status']==200
assert e['duration_ms']==3 and e['req_bytes'] > 0 and e['resp_bytes']==42
assert e['trace_id']=='0123456789abcdef0123456789abcdef'
PY
sudo -n true
python3 -m http.server "$PORT" --bind 127.0.0.1 >"$TMP/http.log" 2>&1 &
HTTP_PID=$!
sleep 1
: >"$TMP/capture.jsonl"
: >"$TMP/capture.log"
sudo -n "$HERE/nt-sniff-cpp" -i lo -p "$PORT" >"$TMP/capture.jsonl" 2>"$TMP/capture.log" &
CAP_PID=$!
sleep 1
if ! kill -0 "$CAP_PID" 2>/dev/null; then
    echo "C++ capture failed to start" >&2
    cat "$TMP/capture.log" >&2 || true
    exit 1
fi
curl -sS -u alice:secret -H 'User-Agent: nt-cpp-e2e' -H 'Traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01' "http://127.0.0.1:$PORT/native-e2e" >/dev/null || true
sleep 2
sudo -n kill -TERM "$CAP_PID"
for i in 1 2 3 4 5; do
    if [ -s "$TMP/capture.jsonl" ]; then break; fi
    sleep 1
done
wait "$CAP_PID" 2>/dev/null || true
CAP_PID=
[ -f "$TMP/capture.jsonl" ] || { echo "capture output file missing" >&2; exit 1; }
python3 - "$TMP/capture.jsonl" <<'PY'
import json, sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
assert len(rows) == 1, rows
x=rows[0]
assert x['source_probe']=='pcap-http-cpp'
assert x['method']=='GET' and x['path']=='/native-e2e'
assert x['user']=='alice' and x['scheme']=='basic'
assert x['status'] == 404 and x['duration_ms'] is not None
assert x['req_bytes'] > 0 and x['resp_bytes'] is not None
assert x['trace_id']=='0123456789abcdef0123456789abcdef'
print('NT-CPP-E2E PASS status=%s duration_ms=%s req_bytes=%s resp_bytes=%s' % (x['status'],x['duration_ms'],x['req_bytes'],x['resp_bytes']))
PY
