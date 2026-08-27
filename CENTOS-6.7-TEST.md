# CentOS 6.7 / Linux 2.6.32 real-node test procedure

This procedure tests the legacy passive capture kit on a real CentOS 6.7 node. It is intentionally destructive only to the NetworkTracing test installation under `/opt/networktracing-legacy`, its SysV init entry, the test spool, and the test traffic generated for this procedure.

Do not run it against a production node unless the owner has explicitly approved installing, starting, restarting, and uninstalling the test service.

## Test goals

The test must prove all of the following with real command output:

1. The node is actually CentOS 6.7 with a 2.6.32 kernel and Python 2.6.
2. The node can open an AF_PACKET socket.
3. The supplied Python sniffer compiles under the node's Python.
4. The supplied C++03 capture and C++ shipper compile with the available compiler.
5. The installer can run its real preflight and install lifecycle.
6. The SysV service starts one capture-to-ship pipeline.
7. A real HTTP request is observed passively and arrives at the hub.
8. Basic authentication produces only the username/scheme; the password is never emitted.
9. The shipper spools when the hub is unavailable and drains after recovery.
10. A changed target-port list is applied through a controlled restart.
11. Stop and uninstall leave no service, process, PID file, or test prefix behind.

The old-kernel path does not decrypt TLS. Test HTTP first. Treat TLS coverage as a separate limitation unless the modern eBPF agent is being tested.

## 0. Test variables

Run these commands on the CentOS node as an unprivileged login user first:

```sh
export HUB_HOST=10.0.0.35                 # replace with the real hub address
export HUB_BOOTSTRAP=http://$HUB_HOST:30105/oldkernel
export HUB_ENDPOINT=http://$HUB_HOST:31115
export TEST_PORT=31299
export TEST_NODE=$(hostname -s)
export TEST_DIR=/tmp/networktracing-el67-test
```

Use a dedicated test port. Do not point the test server at an application port carrying real traffic.

On the hub, confirm the actual address and health before touching the node:

```sh
curl -fsS http://127.0.0.1:31115/healthz
curl -fsS http://127.0.0.1:30105/healthz
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"node":"centos6-preflight","events":[]}' \
  "$HUB_ENDPOINT/api/ingest"
```

Expected protocol responses are HTTP 200 with an `ok` response. If the hub is not reachable, stop here and fix routing/firewall/listener issues first.

## 1. Capture a complete baseline

Save output before installation. Do not use broad process-kill commands.

```sh
mkdir -p "$TEST_DIR/baseline"
{
  date
  id
  uname -a
  cat /etc/redhat-release
  python -V 2>&1
  command -v python || true
  command -v curl || true
  command -v wget || true
  command -v gcc || true
  command -v g++ || true
  command -v setcap || true
  command -v getcap || true
  command -v tcpdump || true
  command -v service || true
  command -v chkconfig || true
  getenforce 2>/dev/null || true
  awk 'NR <= 8 {print}' /proc/net/dev
  awk 'NR <= 8 {print}' /proc/net/route
  ps -eo pid,ppid,user,stat,args
  netstat -lnt 2>/dev/null || true
  netstat -ln 2>/dev/null | grep -E ':30105|:31115|:31299' || true
} > "$TEST_DIR/baseline/system.txt" 2>&1
```

Pass criteria:

```text
/etc/redhat-release: CentOS release 6.7
uname -r: 2.6.32...
python: 2.6.x
```

CentOS 6.7 may have a vendor kernel suffix such as `2.6.32-573.el6`. A different kernel family is a failed target validation, not a reason to silently reinterpret the result.

## 2. Fetch the exact kit from the bootstrap server

Fetch into a file first. Do not pipe an unverified network response directly into a root shell.

```sh
rm -rf "$TEST_DIR/kit"
mkdir -p "$TEST_DIR/kit"
cd "$TEST_DIR/kit"

for f in el68-smoke.sh nt-sniff.py nt-ship.py nt-ship-cpp.cpp \
         nt-sniff-cpp.cpp Makefile nt-run-cpp.sh install-oldkernel.sh; do
  curl -fsS "$HUB_BOOTSTRAP/$f" -o "$f"
done
chmod 755 *.sh *.py
```

Verify the downloaded files are non-empty and contain the expected markers:

```sh
for f in el68-smoke.sh nt-sniff.py nt-ship.py nt-ship-cpp.cpp \
         nt-sniff-cpp.cpp Makefile nt-run-cpp.sh install-oldkernel.sh; do
  test -s "$f" || { echo "MISSING_OR_EMPTY $f"; exit 1; }
done

grep -q 'def b2i' nt-sniff.py
grep -q 'gnu++03' Makefile
grep -q 'nt-ship-cpp.cpp' install-oldkernel.sh
sha256sum *.sh *.py *.cpp Makefile
```

Record the SHA-256 output. If the file was fetched from a different bootstrap instance, do not continue until the source and served file have been compared.

## 3. Run the prerequisite smoke test

Run as root because the smoke test checks both privileged and rootless paths:

```sh
cd "$TEST_DIR/kit"
sudo sh ./el68-smoke.sh | tee "$TEST_DIR/smoke.txt"
```

Expected checks:

```text
NT-SMOKE PASS: kernel 2.6.32 family
NT-SMOKE PASS: python version OK
NT-SMOKE PASS: downloader present
NT-SMOKE PASS: non-root CAP_NET_RAW capture works
NT-SMOKE PASS: AF_PACKET openable under capped interpreter
NT-SMOKE PASS: nt-sniff.py compiles under node python
NT-SMOKE done: N pass, 0 fail
```

Interpretation:

- `python not 2.6/2.7`: stop; this kit is not valid for that node.
- `setcap refused` or capped AF_PACKET failure: record SELinux/VFS details. The installer may use root capture, but root fallback must be explicit in its output.
- `tcpdump absent`: install it only if permitted by the test image, then rerun. Do not replace the capture test with an unverified assumption.

Also check the exact Python syntax directly:

```sh
python -m py_compile nt-sniff.py nt-ship.py
```

On Python 2.6, this creates `.pyc` files beside the sources. They are test artifacts and should not be copied into the final kit.

## 4. Build and test native C++03 components

Native mode requires a compiler on the target. Confirm the compiler version before building:

```sh
g++ --version
make --version 2>/dev/null || true
```

Build both capture and shipper:

```sh
cd "$TEST_DIR/kit"
make clean all
file nt-sniff-cpp nt-ship-cpp
./nt-ship-cpp --help
./nt-sniff-cpp --fixture
```

Pass criteria:

```text
compiler accepts -std=gnu++03
nt-ship-cpp prints its usage and exits 0
nt-sniff-cpp fixture reports the expected fixture success
```

CentOS 6.7 commonly has GCC 4.4.x. If the compiler cannot build the C++03 source, mark native mode as failed; do not switch compiler standards or silently fall back while reporting native mode as passed.

## 5. Test C++ shipper independently

This separates shipper failures from AF_PACKET and parser failures.

Create one metadata-only event. Never put a real password, bearer token, API key, cookie, or authorization value in the fixture:

```sh
cat > "$TEST_DIR/event.json" <<'EOF'
{"method":"GET","path":"/nt-cpp-ship-test","user":"fixture-user","scheme":"basic","source_probe":"pcap-http","req_bytes":64,"status":200,"resp_bytes":2}
EOF
```

Run the native shipper:

```sh
cd "$TEST_DIR/kit"
rm -f "$TEST_DIR/cpp-spool.jsonl"
cat "$TEST_DIR/event.json" | NT_NODE_NAME="$TEST_NODE" \
  ./nt-ship-cpp --endpoint "$HUB_ENDPOINT" \
  --spool "$TEST_DIR/cpp-spool.jsonl" \
  2>&1 | tee "$TEST_DIR/cpp-ship-live.txt"
```

Expected output includes:

```text
nt-ship-cpp: flushed 1 events
nt-ship-cpp: stopped
```

Verify the event on the hub, using a path filter if supported:

```sh
curl -fsS "$HUB_ENDPOINT/api/events?limit=5000&q=nt-cpp-ship-test"
```

Verify no credential-like fixture was sent:

```sh
! grep -Eiq 'password|secret|bearer|api[-_]?key|authorization|cookie' \
  "$TEST_DIR/cpp-ship-live.txt"
```

## 6. Test C++ shipper spool and recovery

Start a shipper against an unused local port so the first delivery fails:

```sh
rm -f "$TEST_DIR/outage-spool.jsonl"
printf '%s\n' '{"method":"GET","path":"/nt-spool-test","user":"fixture-user"}' |
  NT_NODE_NAME="$TEST_NODE" ./nt-ship-cpp \
  --endpoint http://127.0.0.1:39991 \
  --spool "$TEST_DIR/outage-spool.jsonl" \
  2>&1 | tee "$TEST_DIR/cpp-ship-outage.txt"
```

Expected result:

```text
nt-ship-cpp: spooled 1 events
```

Then run the same event against the real hub and verify the hub receives exactly one copy. If this implementation is being extended with a long-running outage test, keep the process alive, restore the endpoint, and verify the spool is drained. At-least-once delivery still requires downstream deduplication.

## 7. Real installer preflight

Before installation, inspect whether a previous test prefix exists:

```sh
sudo test -e /opt/networktracing-legacy && echo prefix-exists || echo prefix-absent
sudo test -e /etc/init.d/networktracing-legacy && echo init-exists || echo init-absent
sudo test -e /var/run/networktracing-legacy.pid && echo pid-exists || echo pid-absent
```

If this is a disposable test node and a prior test exists, uninstall it first and verify cleanup before continuing:

```sh
sudo sh "$TEST_DIR/kit/install-oldkernel.sh" --uninstall || true
sudo test ! -e /opt/networktracing-legacy
sudo test ! -e /etc/init.d/networktracing-legacy
```

Run the actual preflight:

```sh
sudo NT_IFACE=lo NT_PORTS="$TEST_PORT" \
  sh "$TEST_DIR/kit/install-oldkernel.sh" \
  --check --endpoint "$HUB_ENDPOINT" \
  2>&1 | tee "$TEST_DIR/preflight.txt"
```

`--check` must not create the installed prefix or init service.

## 8. Real Python-mode install and live HTTP test

Python mode is the compatibility baseline. Install it first:

```sh
sudo NT_IFACE=lo NT_PORTS="$TEST_PORT" \
  sh "$TEST_DIR/kit/install-oldkernel.sh" \
  --endpoint "$HUB_ENDPOINT" \
  2>&1 | tee "$TEST_DIR/install-python.txt"
```

Immediately inspect the generated service and installed files:

```sh
sudo service networktracing-legacy status || true
sudo sed -n '1,220p' /etc/init.d/networktracing-legacy
sudo find /opt/networktracing-legacy -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
sudo cat /var/run/networktracing-legacy.pid 2>/dev/null || true
sudo ps -eo pid,ppid,user,stat,args | grep -E '[n]t-sniff.py|[n]t-ship.py|[p]ython-capnetraw'
```

Confirm the service is a single pipeline, not two processes with an immediately closed shipper stdin. Check logs:

```sh
sudo tail -n 80 /opt/networktracing-legacy/sniff.log
sudo tail -n 80 /opt/networktracing-legacy/ship.log
```

Start a test HTTP server in a separate terminal on loopback:

```sh
python -m SimpleHTTPServer "$TEST_PORT"
```

From another terminal, generate a request. The password below is a disposable fixture only and must not appear in event output:

```sh
curl -sS -u fixture-user:fixture-password \
  -H 'X-Forwarded-For: 127.0.0.2' \
  "$TEST_NODE:$TEST_PORT/nt-python-live" -o /tmp/nt-python-response
```

Query the hub:

```sh
curl -fsS "$HUB_ENDPOINT/api/events?limit=5000&q=nt-python-live"
```

Pass criteria:

- one event appears within the configured flush interval plus network time;
- `source_probe` is `pcap-http`;
- `user` is `fixture-user`;
- `scheme` is `basic`;
- `path` is `/nt-python-live`;
- no password appears in sniffer log, shipper log, spool, or hub event JSON;
- `duration_ms`, `resp_bytes`, and `status` are present only when the observed correlation actually completed.

Do not use a browser to infer capture success. The hub event is the proof.

## 9. Native C++ capture + C++ shipper install

Stop and uninstall Python mode before testing native mode:

```sh
sudo service networktracing-legacy stop || true
sudo sh "$TEST_DIR/kit/install-oldkernel.sh" --uninstall
sudo test ! -e /opt/networktracing-legacy
sudo test ! -e /etc/init.d/networktracing-legacy
```

Install native mode explicitly:

```sh
sudo NT_CAPTURE_MODE=cpp NT_IFACE=lo NT_PORTS="$TEST_PORT" \
  sh "$TEST_DIR/kit/install-oldkernel.sh" \
  --endpoint "$HUB_ENDPOINT" \
  2>&1 | tee "$TEST_DIR/install-cpp.txt"
```

Verify both binaries were built on the node, not merely copied as source:

```sh
sudo test -x /opt/networktracing-legacy/nt-sniff-cpp
sudo test -x /opt/networktracing-legacy/nt-ship-cpp
sudo file /opt/networktracing-legacy/nt-sniff-cpp /opt/networktracing-legacy/nt-ship-cpp
sudo grep -n 'nt-ship-cpp\|nt-sniff-cpp' /etc/init.d/networktracing-legacy
sudo ps -eo pid,ppid,user,stat,args | grep -E '[n]t-sniff-cpp|[n]t-ship-cpp'
```

Run the same live request with a different path:

```sh
curl -sS -u fixture-user:fixture-password \
  "$TEST_NODE:$TEST_PORT/nt-cpp-live" -o /tmp/nt-cpp-response
curl -fsS "$HUB_ENDPOINT/api/events?limit=5000&q=nt-cpp-live"
```

Expected native startup diagnostics may include:

```text
nt-sniff-cpp: WARN: BPF attach failed; continuing unfiltered
nt-sniff-cpp: listening
```

That warning means the capture process is running in degraded unfiltered mode. It is not proof that the kernel filter attached. Record it and inspect packet volume/resource impact.

## 10. Target-port change test

The installed legacy service receives its target port list at install time. A desired port change must therefore be followed by an explicit controlled restart; do not claim an active-port change without verifying the generated command line.

1. Stop the test HTTP server on `$TEST_PORT`.
2. Choose a second unused test port:

```sh
export TEST_PORT_2=31300
```

3. Change the service configuration using the supported test procedure. For the current SysV kit, reinstalling with the new `NT_PORTS` is the deterministic path:

```sh
sudo service networktracing-legacy stop
sudo NT_CAPTURE_MODE=cpp NT_IFACE=lo NT_PORTS="$TEST_PORT_2" \
  sh "$TEST_DIR/kit/install-oldkernel.sh" \
  --endpoint "$HUB_ENDPOINT" 2>&1 | tee "$TEST_DIR/reconfigure-port.txt"
```

4. Confirm the generated init command contains only the new port list:

```sh
sudo grep -n -- "-p $TEST_PORT_2" /etc/init.d/networktracing-legacy
sudo grep -n -- "-p $TEST_PORT" /etc/init.d/networktracing-legacy && echo OLD_PORT_STILL_PRESENT || true
```

5. Start a server on `$TEST_PORT_2`, send `/nt-port-change`, and verify that event arrives.
6. Send the same request to the old port and verify it is not attributed to this capture instance.

The centralized control API can persist a desired port list and report `restart required`; it must not be interpreted as active capture reconfiguration until the restart and event test pass.

## 11. Restart and stop tests

```sh
sudo service networktracing-legacy restart
sleep 2
sudo service networktracing-legacy status
sudo ps -eo pid,ppid,user,stat,args | grep -E '[n]t-sniff-cpp|[n]t-ship-cpp|[n]t-sniff.py|[n]t-ship.py'
```

Record the parent/child relationship. Then stop through SysV:

```sh
sudo service networktracing-legacy stop
sleep 2
sudo service networktracing-legacy status || true
sudo ps -eo pid,ppid,user,stat,args | grep -E '[n]t-sniff-cpp|[n]t-ship-cpp|[n]t-sniff.py|[n]t-ship.py' || true
sudo test ! -e /var/run/networktracing-legacy.pid && echo pidfile-removed
```

If any process remains, identify it by exact PID and full command line before terminating it. Never use `pkill -f` during this test.

## 12. Real uninstall and residue check

```sh
sudo sh "$TEST_DIR/kit/install-oldkernel.sh" --uninstall \
  2>&1 | tee "$TEST_DIR/uninstall.txt"
```

Verify all NetworkTracing legacy artifacts:

```sh
sudo test ! -e /opt/networktracing-legacy && echo prefix-removed
sudo test ! -e /etc/init.d/networktracing-legacy && echo init-removed
sudo test ! -e /var/run/networktracing-legacy.pid && echo pidfile-removed
sudo ps -eo pid,user,args | grep -E '[n]t-sniff-cpp|[n]t-ship-cpp|[n]t-sniff.py|[n]t-ship.py' || true
sudo chkconfig --list networktracing-legacy 2>&1 || true
```

The installer intentionally may leave the locked `ntsniff` account and `/var/lib/networktracing` spool directory. Inspect them separately:

```sh
getent passwd ntsniff || true
sudo find /var/lib/networktracing -maxdepth 1 -type f -printf '%f %s bytes\n' 2>/dev/null || true
```

Remove those only if the node owner explicitly wants all test data deleted:

```sh
sudo userdel ntsniff 2>/dev/null || true
sudo rm -rf /var/lib/networktracing
```

## 13. Final evidence bundle

Collect the test evidence without credentials:

```sh
mkdir -p "$TEST_DIR/final"
cp "$TEST_DIR"/*.txt "$TEST_DIR/final/" 2>/dev/null || true
{
  date
  uname -a
  cat /etc/redhat-release
  python -V 2>&1
  sudo test ! -e /opt/networktracing-legacy && echo prefix-clean
  sudo test ! -e /etc/init.d/networktracing-legacy && echo init-clean
  sudo test ! -e /var/run/networktracing-legacy.pid && echo pid-clean
  sudo ps -eo pid,ppid,user,stat,args | grep -E '[n]t-sniff|[n]t-ship' || true
} > "$TEST_DIR/final/summary.txt"

# Redact before transferring evidence anywhere.
! grep -Eiq 'fixture-password|authorization:|bearer[[:space:]]+[^ ]+|x-api-key:|cookie:' \
  "$TEST_DIR"/final/*
```

## Pass/fail report format

Report one row per gate:

| Gate | Result | Evidence |
|---|---|---|
| CentOS 6.7 / 2.6.32 | PASS/FAIL | `baseline/system.txt` |
| Python 2.6 compile | PASS/FAIL | `smoke.txt` |
| rootless AF_PACKET | PASS/FAIL/FALLBACK | `smoke.txt` + SELinux mode |
| C++03 capture build | PASS/FAIL | build output |
| C++03 shipper build | PASS/FAIL | build output |
| C++ shipper live POST | PASS/FAIL | `cpp-ship-live.txt` + hub event |
| spool/recovery | PASS/FAIL | outage output + hub event count |
| Python live capture | PASS/FAIL | hub event JSON |
| native live capture | PASS/FAIL/DEGRADED | hub event + `sniff.log` |
| target-port change | PASS/FAIL | init command + second event |
| SysV restart/stop | PASS/FAIL | process/PID output |
| uninstall residue check | PASS/FAIL | `uninstall.txt` + final summary |

A test is not fully passed when only the installer exits 0. The minimum end-to-end proof is: real request → passive event JSONL → shipper POST → hub event query → credential absence check → clean uninstall.
