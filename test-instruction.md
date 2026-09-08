> **Port migration:** The active hub is OTelTrace on `0.0.0.0:30102`. The former NetworkTracing hub on `:31115` is legacy and is not used.

# NetworkTracing Oldkernel Agent — Remote Test Instruction Guide

This document provides exact, POSIX-compliant (`/bin/sh`) instructions for an automated agent or engineer to test the **NetworkTracing Oldkernel Kit** on a target Linux machine (CentOS 6.x / RHEL 6 / Debian / Ubuntu).

---

## 1. Environment Requirements & Rules

1. **Shell**: Strictly use standard POSIX `/bin/sh`. Do **not** use `bash`, `zsh`, or bashisms (`[[ ]]`, `local`, `declare`, `array[i]`, `&>`, etc.).
2. **Privileges**: Root access or `sudo -n` required for socket capabilities (`cap_net_raw`).
3. **No Kubernetes Commands**: Never run `kubectl`.
4. **Network Access**: Target node must reach the Hub bootstrap port (`:30105`) and/or Hub endpoint (`:30102`).

---

## 2. Test Configuration Variables

Set these environment variables before beginning:

```sh
HUB_IP="129.150.59.233"                   # Replace with your Hub IP
BOOTSTRAP_URL="http://${HUB_IP}:30105"
HUB_ENDPOINT="http://${HUB_IP}:30102"
TEST_PORT="31299"                         # Unused test port
TEST_IFACE="lo"                           # Use 'lo' for local loopback test or 'eth0' for wire
WORKDIR="/tmp/ntkit-test.$$"
```

---

## 3. Step-by-Step Test Procedure

### Gate 1: Check Bootstrap Availability & Fetch Kit

Verify that the bootstrap server is responding and download the self-extracting single-file installer:

```sh
mkdir -p "$WORKDIR" && cd "$WORKDIR"

# Probe bootstrap health
curl -sSf "${BOOTSTRAP_URL}/healthz" || { echo "FAIL: Bootstrap unreachable"; exit 1; }

# Download single-file standalone installer
curl -sSf "${BOOTSTRAP_URL}/oldkernel/install-firstrun-el68.sh" -o install-firstrun-el68.sh
chmod 755 install-firstrun-el68.sh
```

---

### Gate 2: Non-Destructive Preflight Check

Run the installer in `--check` mode. This verifies kernel compatibility, python/compiler availability, and network interface detection without modifying the operating system:

```sh
sudo -n NT_IFACE="$TEST_IFACE" NT_PORTS="$TEST_PORT" \
  sh ./install-firstrun-el68.sh --check --endpoint "$HUB_ENDPOINT"
```
**Pass Criteria**: Outputs `[nt-legacy] preflight OK (...) — no changes made` and exits with code 0.

---

### Gate 3: Production Installation (Native C++ Mode)

Install the high-performance native C++03 agent. This compiles the binary, sets rootless `cap_net_raw+ep` file capabilities on `/opt/networktracing-legacy/nt-sniff-cpp`, creates system account `ntsniff`, and launches the SysV daemon:

```sh
sudo -n NT_CAPTURE_MODE=cpp NT_IFACE="$TEST_IFACE" NT_PORTS="$TEST_PORT" \
  sh ./install-firstrun-el68.sh --endpoint "$HUB_ENDPOINT"
```

**Pass Criteria**:
1. Outputs `[nt-legacy] rootless mode: cap_net_raw on native C++ binary, user=ntsniff`.
2. Outputs `[nt-legacy] DONE. Sniffer iface=... (capture-as=ntsniff)`.
3. Process status check confirms running daemon:
   ```sh
   sudo -n service networktracing-legacy status
   ps -u ntsniff -o pid,user,args | grep -E '[n]t-sniff-cpp'
   ```

---

### Gate 4: Passive Traffic Capture & Attribution Test

Generate HTTP traffic on the monitored `$TEST_PORT` and confirm that the agent passively sniffs and processes the L7 request headers:

```sh
# 1. Start an ephemeral test HTTP server on the test port
python3 -m http.server "$TEST_PORT" --bind 127.0.0.1 >/tmp/http-test.log 2>&1 &
HTTP_PID=$!
sleep 1

# 2. Send synthetic request with Basic Auth and W3C Traceparent
curl -sS -u testuser:secretpass \
  -H "Traceparent: 00-11112222333344445555666677778888-9999aaaabbbbcccc-01" \
  "http://127.0.0.1:${TEST_PORT}/test-packet-trace" >/dev/null || true

# Wait 6 seconds for the agent batch flush interval (default 5s)
sleep 6

# 3. Terminate test HTTP server
kill -TERM "$HTTP_PID" 2>/dev/null || true
```

**Pass Criteria**:
Inspect the sniffer log to confirm capture:
```sh
sudo -n cat /opt/networktracing-legacy/sniff.log
```
Expected markers:
- `PACKET_MMAP (TPACKET_V2) zero-copy ring enabled`
- `listening`
- No password (`secretpass`) present in logs.
- Clean batch flush or in-memory bounded drop if Hub is not reachable.

---

### Gate 5: Clean Uninstallation & Zero Residue Check

Cleanly uninstall the agent service, remove binaries, and verify that no background processes remain:

```sh
# 1. Stop and uninstall service
sudo -n service networktracing-legacy stop
sudo -n sh /opt/networktracing-legacy/install-oldkernel.sh --uninstall

# 2. Verify all files and processes are removed
test ! -e /opt/networktracing-legacy && echo "PASS: /opt prefix removed"
test ! -e /etc/init.d/networktracing-legacy && echo "PASS: SysV init removed"
test ! -e /var/run/networktracing-legacy.pid && echo "PASS: PID file removed"

# Confirm no lingering processes
pgrep -f "nt-sniff" || echo "PASS: Zero leftover processes"

# Clean temporary test working directory
rm -rf "$WORKDIR" /tmp/http-test.log
```

---

## 4. Alternative: Python 2.6 / 2.7 Compatibility Mode

To test the Python capture mode (for legacy environments without `g++`), replace Gate 3 with:

```sh
sudo -n NT_CAPTURE_MODE=python NT_IFACE="$TEST_IFACE" NT_PORTS="$TEST_PORT" \
  sh ./install-firstrun-el68.sh --endpoint "$HUB_ENDPOINT"
```
Verify `python-capnetraw` was created and granted `cap_net_raw+ep` under `/opt/networktracing-legacy`.
Proceed through Gate 4 and Gate 5 identically.

---

## 5. Verification Checklist Summary

| Check Item | Command / Location | Expected Result |
|---|---|---|
| **Bootstrap Reachability** | `curl -sSf $BOOTSTRAP_URL/healthz` | HTTP 200 `{"status": "ok"}` |
| **Preflight Check** | `sh install-firstrun-el68.sh --check` | Preflight OK, no files written |
| **Rootless Privilege** | `ps -u ntsniff` | Daemon runs as locked `ntsniff` user |
| **Live Capture** | `/opt/networktracing-legacy/sniff.log` | Zero-copy ring initialized, events captured |
| **Credential Safety** | `grep -i "secretpass" /opt/networktracing-legacy/*.log` | Zero matches (password never emitted) |
| **Clean Uninstall** | `sh .../install-oldkernel.sh --uninstall` | Exit 0, 0 files or processes lingering |
