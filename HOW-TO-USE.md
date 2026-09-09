# NetworkTracing Oldkernel Agent — How To Use

> **Port migration notice:** The active Telemetry Hub is OTelTrace on `0.0.0.0:30102`. The bootstrap server runs on `0.0.0.0:30105`. The legacy port `:31115` is obsolete and unused.

This document is the definitive guide on how to configure, install, run, verify, and maintain the **NetworkTracing Oldkernel Agent** (`/opt/networktracing-legacy`) on CentOS 6.x, RHEL 6.x, and legacy Linux kernels (2.6.32+ up to modern kernels) where eBPF and systemd are unavailable.

---

## Table of Contents

1. [Architectural Overview & Recent Changes](#1-architectural-overview--recent-changes)
2. [Quick Start (One-Command Deployment)](#2-quick-start-one-command-deployment)
3. [Installation Methods](#3-installation-methods)
   - [Method A: One-Liner via Bootstrap Server](#method-a-one-liner-via-bootstrap-server)
   - [Method B: Direct Bundle Execution](#method-b-direct-bundle-execution)
   - [Method C: Airgapped / Offline Node Deployment](#method-c-airgapped--offline-node-deployment)
   - [Method D: Automated Fleet Deployment via Ansible](#method-d-automated-fleet-deployment-via-ansible)
4. [Complete Parameter & Environment Variable Reference](#4-complete-parameter--environment-variable-reference)
5. [Capture Engines: C++ vs. Python](#5-capture-engines-c-vs-python)
   - [Native C++03 Mode (`--mode cpp`) — Recommended](#native-c03-mode---mode-cpp---recommended)
   - [Python 2.6 Mode (`--mode python`)](#python-26-mode---mode-python)
6. [Advanced Features & Tuning](#6-advanced-features--tuning)
   - [SOAP / WSSE XML Body Username Extraction](#soap--wsse-xml-body-username-extraction)
   - [CPU Affinity & Core Isolation](#cpu-affinity--core-isolation)
   - [Remote Control & Secret Token Management](#remote-control--secret-token-management)
7. [Day-2 Operations & Service Management](#7-day-2-operations--service-management)
8. [Testing & Verification](#8-testing--verification)
9. [Troubleshooting & FAQ](#9-troubleshooting--faq)

---

## 1. Architectural Overview & Recent Changes

The Oldkernel agent captures L7 HTTP/SOAP traffic using native Linux `AF_PACKET` raw sockets and classic BPF (`cBPF`), running on hosts without eBPF support.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        LEGACY AGENT NODE                               │
│                                                                        │
│  SysV Service (/etc/init.d/networktracing-legacy)                      │
│       │                                                                │
│       ▼                                                                │
│  nt-resource-guard.sh (CPU % / RSS cap watchdog)                       │
│       │                                                                │
│       ▼                                                                │
│  nt-supervise.sh (Process supervisor & respawn loop)                   │
│       │                                                                │
│       ├─► [C++ Mode]: nt-sniff-cpp (Zero-copy TPACKET_V2 RX Ring)      │
│       │               └─► Direct HTTP Keep-Alive Poster                │
│       │                                                                │
│       └─► [Python Mode]: nt-sniff.py ──(stdout)──► nt-ship.py          │
│                          (Single-worker cBPF)      (8 poster threads)  │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │
                               POST /api/ingest
                                       ▼
                       Telemetry Hub (http://<hub>:30102)
```

### Recent Hardening & Architecture Updates

Recent updates to the legacy engine eliminate historical crash vectors and kernel panic risks on 2.6.32 kernels:

1. **Strict Fixed RX Ring (TPACKET_V2)**:
   - C++ engine strictly configures a 4MB memory-mapped ring (`block_size=65536`, `block_nr=64`, `frame_size=2048`, `frame_nr=2048`).
   - Removed socket `recv()` fallback buffer to guarantee bounded memory.
   - Strictly avoids `TPACKET_V3`, `PACKET_TX_RING`, `PACKET_RESERVE`, and `PACKET_VNET_HDR`, which trigger known kernel bugs/panics on older 2.6.32 releases.
2. **Safe cBPF Filter Limits (Max 30 Ports)**:
   - Monitored port list is strictly limited to 30 ports (`PORT_COUNT <= 30`).
   - Prevents classic BPF 1-byte jump target overflow (`jt > 255` or `jf > 255`), which would corrupt or invalidate socket filtering.
3. **Single-Worker Invariant**:
   - `PACKET_FANOUT` was eliminated because CentOS 6.x / Linux 2.6.32 lacks fanout support (requires kernel >= 3.1). Running multi-process without kernel fanout causes duplicated packets. Both Python and C++ strictly enforce `workers=1`.
4. **Enforced Security Handshake Order**:
   - Setup order is strictly: Attach BPF filter -> Bind socket to interface -> Initialize mmap ring -> Drop capabilities (`CAP_NET_RAW`). Socket runs entirely rootless as user `ntsniff`.
5. **Strict URL Scheme Validation**:
   - `--server` and `--endpoint` require an explicit scheme (`http://` or `https://`). Automatic port guessing has been removed.
6. **Airgapped Mode (`--offline`)**:
   - Dedicated flag prevents any remote HTTP kit downloads and relies 100% on embedded base64 payloads.

---

## 2. Quick Start (One-Command Deployment)

Run this one-liner on the target CentOS 6 / legacy node (replaces `10.0.0.10` with your Hub IP):

```sh
curl -sSf http://10.0.0.10:30105/oldkernel/bootstrap | sudo -n sh
```

To run a **safe preflight dry-run** first (verifies kernel, compiler, setcap, and disk without modifying the system):

```sh
curl -sSf http://10.0.0.10:30105/oldkernel/bootstrap | sudo -n sh -s -- --check
```

---

## 3. Installation Methods

### Method A: One-Liner via Bootstrap Server

The dedicated bootstrap server (`nt-bootstrap.py` on port `:30105`) dynamically resolves your Hub IP and streams a POSIX `/bin/sh` installer script.

**Production C++ Mode with custom ports and CPU pinning:**
```sh
curl -sSf http://10.0.0.10:30105/oldkernel/bootstrap | sudo -n sh -s -- \
  --mode cpp \
  --ports 80,8001,8080,9000 \
  --cpu 1
```

> **POSIX Shell Note:** Always include `-s --` when piping curl output into `sudo sh` so that arguments following `--` are passed directly into the installer script.

---

### Method B: Direct Bundle Execution

If you prefer downloading the standalone installer file before execution:

```sh
# 1. Download the self-contained installer (contains all 10 embedded payloads)
curl -sSf http://10.0.0.10:30105/oldkernel/install-firstrun-el68.sh -o install-firstrun-el68.sh

# 2. Run preflight dry-run
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 --check

# 3. Perform full installation
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 \
  --mode cpp \
  --iface eth0 \
  --ports 80,8080,8443
```

---

### Method C: Airgapped / Offline Node Deployment

In secure or isolated production environments where the target node cannot connect back to the bootstrap server on port `30105`:

1. Download `install-firstrun-el68.sh` on a jump host / build box.
2. Copy it to the isolated node via SCP, SFTP, or USB.
3. Install with the `--offline` flag:

```sh
sudo sh install-firstrun-el68.sh \
  --server http://10.0.0.10:30102 \
  --offline \
  --mode cpp \
  --ports 80,8080
```

> With `--offline`, the installer will extract the 10 embedded base64 components (C++ sources, precompiled binaries, Python scripts, supervisor, and guard). If any component is missing, it will abort immediately rather than attempting external network fetches.

---

### Method D: Automated Fleet Deployment via Ansible

For large clusters, see [ANSIBLE.md](file:///home/ubuntu/Viettel/NetworkTracing/oldkernel/ANSIBLE.md) for full playbook definitions.

**Key principles for Ansible:**
- Store `install-firstrun-el68.sh` in the Ansible role `files/` directory.
- Use `--offline` on all managed nodes to prevent bootstrap dependency.
- Configure variables in `group_vars`:
```yaml
nt_hub_url: "http://10.0.0.10:30102"
nt_capture_iface: "eth0"
nt_capture_ports: "80,8001,8003,8080"
nt_capture_mode: "cpp"
nt_wsse_bytes: "0"
```
- Execute the task:
```yaml
- name: Run idempotent installation
  command: >
    sh /tmp/install-firstrun-el68.sh
    --server {{ nt_hub_url }}
    --iface {{ nt_capture_iface }}
    --ports {{ nt_capture_ports }}
    --mode {{ nt_capture_mode }}
    --offline
```

---

## 4. Complete Parameter & Environment Variable Reference

All parameters can be passed as CLI arguments or configured through environment variables:

| CLI Option | Environment Variable | Default Value | Allowed Range / Format | Description |
|---|---|---|---|---|
| `--server URL`<br>`--endpoint URL` | — | Auto-detected | `http://HOST:PORT`<br>`https://HOST:PORT` | Telemetry Hub ingestion endpoint. Scheme (`http://` or `https://`) is strictly required. |
| `--kit-url URL`<br>`--hub URL` | `NT_HUB` | Auto-detected | `http://HOST:PORT/oldkernel` | Bootstrap server URL where fallback kit files reside. |
| `--iface IFACE` | `NT_IFACE` | Default route interface | String (max 32 chars) | Network interface to sniff (e.g. `eth0`, `enp0s6`, `lo`). |
| `--ports LIST` | `NT_PORTS` | `80,8003,8005,8007,8009,8010,8011` | Comma-separated (1..65535) | Monitored TCP ports. **Strict limit: max 30 ports** to avoid cBPF jump overflow. |
| `--mode MODE` | `NT_CAPTURE_MODE` | `python` | `python` or `cpp` | Capture engine: `cpp` (native zero-copy, recommended) or `python` (standard Python 2.6). |
| `--wsse-bytes N`<br>`--wsse-body-bytes N` | `NT_WSSE_BODY_BYTES` | `0` (disabled) | `0..65536` | Prefix window into HTTP request body to inspect for SOAP/WSSE XML credentials. |
| `--cpu N` | `NT_CPU_CORE` | Installer CPU | Integer logical core | Pins supervisor and sniffer processes to a single logical CPU core using `taskset -c N`. |
| `--ship-threads N` | `NT_SHIP_THREADS` | `8` | `1..32` | Number of concurrent shipping threads for Python mode (`nt-ship.py`). |
| `--control-token-file FILE` | `NT_CONTROL_TOKEN` | Empty | Path to readable file | File containing a shared secret token for remote control operations (`nt-control.py`). |
| `--offline` | `ALLOW_KIT_FETCH=0` | False | Flag | Disables external kit downloads; forces 100% extraction from embedded payloads. |
| `--check` | — | False | Flag | Dry-run audit mode: performs all preflight checks without modifying the system. |
| `--install` | — | True (default) | Flag | Installs service `/etc/init.d/networktracing-legacy` and starts background daemons. |
| `--uninstall` | — | False | Flag | Stops the agent, deletes SysV service, and purges `/opt/networktracing-legacy`. |
| `-h`, `--help` | — | — | Flag | Displays the CLI parameter help summary. |

---

## 5. Capture Engines: C++ vs. Python

### Native C++03 Mode (`--mode cpp`) — Recommended

The C++ engine is compiled against standard C++03 and libc 2.12 (CentOS 6.x default):
- **Zero-Copy TPACKET_V2 RX Ring**: Direct kernel ring memory map (4MB, 2048 frames). Drops syscall overhead.
- **In-Process Shipping**: Ships directly to the Hub over HTTP 1.1 Keep-Alive sockets without piping to a second process.
- **Resource Footprint**: < 20MB RSS memory and < 5% CPU even under heavy network load.
- **Crash Immunity**: Strict frame integrity validation, single-worker safety, and bounded queue spooling (4,000 events max).

**To install in C++ mode:**
```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 --mode cpp
```

### Python 2.6 Mode (`--mode python`)

The Python engine runs on stock Python 2.6.6 (standard on CentOS 6.x):
- **Architecture**: `nt-sniff.py` captures raw packets and emits JSON lines to standard output. `nt-ship.py` reads stdin and batches events to the Hub using 8 worker threads.
- **Optimizations**: Uses fast PRNG (`xorshift128+`) instead of per-request `/dev/urandom` syscalls, O(1) monitored port lookup, and zero-allocation base64 auth decoding.
- **Safe Single-Process**: Forced single-worker model prevents duplicate event shipping.

**To install in Python mode:**
```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 --mode python
```

---

## 6. Advanced Features & Tuning

### SOAP / WSSE XML Body Username Extraction

By default, the agent captures HTTP headers only (`--wsse-bytes 0`). If your legacy fleet runs SOAP XML web services and uses WS-Security (`wsse:UsernameToken`) inside the HTTP body:

```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 \
  --mode cpp \
  --ports 8003,8005 \
  --wsse-bytes 16384
```

- `--wsse-bytes 16384` instructs the parser to inspect up to the first 16 KB of the HTTP body for `<wsse:Username>...</wsse:Username>`.
- The parser strictly stops searching after 16 KB, preventing high CPU load on large XML payloads.

### CPU Affinity & Core Isolation

On multi-core production servers, pin the agent to an isolated core to prevent cache contention:

```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 \
  --cpu 2
```

The supervisor automatically wraps child processes in `taskset -c 2`.

### Remote Control & Secret Token Management

The agent supports live policy hot-reloading and diagnostics via `nt-control.py`. To protect these endpoints:

1. Create a secret token file with restricted permissions:
```sh
sudo mkdir -p /var/lib/networktracing
echo "my-super-secret-fleet-token-2026" | sudo tee /var/lib/networktracing/control.token >/dev/null
sudo chmod 600 /var/lib/networktracing/control.token
```

2. Pass the token file during installation:
```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:30102 \
  --control-token-file /var/lib/networktracing/control.token
```

---

## 7. Day-2 Operations & Service Management

### Service Controls (SysV Init)

The installed daemon is managed via standard SysV init commands:

```sh
# Check service status
sudo service networktracing-legacy status

# Restart the service
sudo service networktracing-legacy restart

# Stop the service
sudo service networktracing-legacy stop

# Start the service
sudo service networktracing-legacy start
```

### Inspecting Installed Files

- Installation Root: `/opt/networktracing-legacy`
- Runtime Configuration: `/opt/networktracing-legacy/config.env`
- Process Supervisor: `/opt/networktracing-legacy/nt-supervise.sh`
- Resource Guard: `/opt/networktracing-legacy/nt-resource-guard.sh`
- Token & State Directory: `/var/lib/networktracing`

### Inspecting Logs

To view live supervisor and capture output:
```sh
# In C++ mode:
tail -f /opt/networktracing-legacy/sniff.log

# In Python mode:
tail -f /opt/networktracing-legacy/ship.log
```

### Clean Uninstallation

To completely remove the agent, unbind raw sockets, stop daemons, and delete files:
```sh
sudo sh install-firstrun-el68.sh --uninstall
```
Or via the bootstrap one-liner:
```sh
curl -sSf http://10.0.0.10:30105/oldkernel/bootstrap | sudo -n sh -s -- --uninstall
```

---

## 8. Testing & Verification

### 1. Test Installer CLI Flag Parsing
Run the automated test suite on Python 3:
```sh
python3 -m pytest oldkernel/test_installer_cli.py
```

### 2. Verify Resource Guard & Architecture Invariants
```sh
python3 -m pytest oldkernel/test_resource_guard.py
```

### 3. Verify C++ Edge Cases & Ring Fixtures
```sh
make -C oldkernel fixture
python3 oldkernel/cpp-edge-test.py
```

### 4. Run Host Smoke Test
```sh
sh oldkernel/el68-smoke.sh
```

---

## 9. Troubleshooting & FAQ

#### Q1: Why does the installer fail with `URLs must start with http:// or https://`?
**A**: `--server` and `--endpoint` require an explicit scheme. Pass `http://10.0.0.10:30102` instead of `10.0.0.10:30102`.

#### Q2: Why does the installer fail with `at most 30 monitored ports are allowed`?
**A**: Classic BPF instruction jump offsets are stored as single bytes (`0..255`). Specifying more than 30 ports risks jumping past the 255-instruction boundary. Limit your `--ports` parameter to 30 or fewer critical ports.

#### Q3: Does the agent run as root?
**A**: No. Although installation requires root privileges, the installer configures Linux capabilities (`setcap cap_net_raw+ep`) on the capture binary and runs the process under the unprivileged service user `ntsniff`.

#### Q4: What happens if the Hub becomes unreachable?
**A**: 
- In C++ mode, events are buffered in memory up to `MAX_QUEUE=4000`. Once full, the oldest events are dropped to protect host memory.
- In Python mode, `nt-ship.py` spools batches to disk under `/opt/networktracing-legacy/spool/` with a bounded disk quota.

#### Q5: Can I run multiple capture workers (`-j 2`)?
**A**: No. The Linux 2.6.32 kernel lacks `PACKET_FANOUT` support. Spawning multiple workers without fanout causes every packet to be captured multiple times. Single-worker mode is strictly enforced.
