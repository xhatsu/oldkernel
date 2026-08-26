# oldkernel/ — NetworkTracing kit for CentOS 6.x / kernel 2.6.32

Passive HTTP/SOAP capture for nodes that **cannot run kyanos/ecapture**
(no eBPF, no systemd, python 2.6 only). Rootless after install via file
capability; falls back to root capture if SELinux refuses.

```
Target   : CentOS 6.8 / kernel 2.6.32-642.el6 (works on 2.6.27+)
Language : python 2.6 stdlib only (no pip, no Go on the node)
Impact   : passive listen-only; zero app changes; no kernel modules
```

## Architecture

```
                      OLD-KERNEL NODE (CentOS 6.x)
 ┌────────────────────────────────────────────────────────────┐
 │                                                            │
 │   wire ──► AF_PACKET socket (cap_net_raw)                  │
 │              │                                             │
 │              ▼                                             │
 │        nt-sniff.py                                         │
 │        · ethertype/IP/TCP filter (userspace)               │
 │        · per-flow TCP reassembly (8k flows, 5-min TTL,     │
 │          256 KiB header cap, Content-Length framing)       │
 │        · Basic-auth user extraction (vtp-style creds →     │
 │          scheme=basic; Bearer marked opaque)               │
 │        · event JSONL ──── stdout                           │
 │              │                        (TLS: NOT readable — │
 │              ▼                         stays on eBPF agent) │
 │        nt-ship.py                                          │
 │        · batch ≤400 events / 5 s flush                     │
 │        · POST {node,events[]} → hub /api/ingest            │
 │        · spool-to-disk + retry when hub down               │
 │                                                            │
 │  SysV service: /etc/init.d/networktracing-legacy           │
 │  (chkconfig on; sniffer as locked user via capped python   │
 │   copy; shipper unprivileged)                              │
 └──────────────────────────┬─────────────────────────────────┘
                            │ HTTP POST (plain JSON)
                            ▼
                   HUB :31115 /api/ingest      ← NO hub changes needed
                   same dashboard/users/violations views;
                   events tagged source_probe=pcap-http
```

### Event schema (identical to main agent)

```json
{"ts": 1787713270, "host": "sale-node01", "src": "pcap",
 "method": "POST", "path": "/SALE_SERVICE/bpm/sale/...",
 "user": "vtp", "scheme": "basic",
 "caller": "10.207.58.79", "dst_ip": "10.240.147.249", "dst_port": 8011,
 "user_agent": "ReactorNetty/1.0.19", "x_forwarded_for": "...",
 "source_probe": "pcap-http"}
```

### What it deliberately does NOT do

| Capability | Why |
|---|---|
| TLS payload | impossible without uprobes/root — that tier stays on the eBPF agent |
| SOAP WSSE usernames in body | product decision: Basic-header only (revisit later if wanted) |
| pid/process lineage | packets carry no process context rootless; port→service map instead |

## Files

| File | Purpose |
|---|---|
| `nt-sniff.py` | AF_PACKET sniffer + reassembly + Basic-auth extraction |
| `nt-ship.py` | batching shipper → `/api/ingest`, disk spool + backoff retry |
| `install-oldkernel.sh` | SysV installer: `--check` / install / `--uninstall` |
| `el68-smoke.sh` | run FIRST — proves kernel/python/setcap/AF_PACKET/SELinux |

## Usage

### 0. Pull the kit onto the node

```sh
HUB=10.0.0.35                       # your NetworkTracing hub
mkdir -p /tmp/ntkit && cd /tmp/ntkit
for f in el68-smoke.sh nt-sniff.py nt-ship.py install-oldkernel.sh; do
  curl -sSf http://$HUB:30105/oldkernel/$f -o $f || wget http://$HUB:30105/oldkernel/$f -O $f
done
chmod +x *.sh *.py
```

### 1. Smoke test (as root) — decide before installing

```sh
sudo sh el68-smoke.sh
```

Checks: kernel family → python 2.6 → setcap present → **non-root really
captures** (tcpdump copy test) → **capped interpreter opens AF_PACKET** →
sniffer compiles under node python. Exit 0 = proceed.

Interpreting failures:

```
setcap/capped-interpreter FAIL  → SELinux enforcing blocks filecaps.
    Either add a local SELinux exception, or accept the installer's
    fallback: sniffer runs as root (still passive, still no app impact).
python missing/wrong            → kit cannot run; install python26.
```

### 2. Preflight check (no changes made)

```sh
sudo sh install-oldkernel.sh --check --endpoint http://$HUB:31115
```

Verifies python presence/version, reachability of the hub, and that the
hub answers the ingest protocol probe (`{"ok":true}` on an empty batch).
Detects the default interface automatically (`NT_IFACE=eth1` to override).

### 3. Install

```sh
sudo sh install-oldkernel.sh --endpoint http://$HUB:31115
# optional env overrides:
#   NT_IFACE=eth1 NT_PORTS=80,8003,8005,8009,8010 sudo -E sh install-oldkernel.sh ...
```

What it does:

```
/opt/networktracing-legacy/{nt-sniff.py,nt-ship.py}
/opt/networktracing-legacy/python-capnetraw   ← interpreter copy with
                                                cap_net_raw+ep (rootless path)
useradd ntsniff                                ← locked account for sniffing
/etc/init.d/networktracing-legacy + chkconfig on
service started; verifies the sniffer PID exists before declaring DONE
```

Verify:

```sh
service networktracing-legacy status
tail -f /opt/networktracing-legacy/sniff.log     # sniffer stderr
tail -f /opt/networktracing-legacy/ship.log      # shipper errors
curl http://$HUB:31115/api/events?limit=20       # look for source_probe=pcap-http
```

Generate a test hit from any machine that routes through the node:

```sh
curl -u testuser:testpw http://<node-ip>:<monitored-port>/anything
→ appears in the hub as user=testuser scheme=basic within ~5 s
```

### 4. Uninstall (verifies zero residuals)

```sh
sudo sh install-oldkernel.sh --uninstall
# stops service, chkconfig off, removes init script, kills sniff/ship pids,
# wipes /opt/networktracing-legacy, then FAILS if anything remains.
# Note: does NOT remove the ntsniff account or /var/lib/networktracing
# spool dir (site data); remove manually if unwanted:
#   userdel ntsniff && rm -rf /var/lib/networktracing
```

## Operations notes

```
Hub outage        shipper spools to disk and retries with exponential
                  backoff; nothing is lost while the node keeps running.
Memory bounds     flow table hard-capped at 8192 flows; stale swept every
                  30 s; per-flow buffers capped (256 KiB headers / 128 KiB body).
Restart           service networktracing-legacy restart
Ports             default monitored: 80,8003,8005,8007,8009,8010,8011
                  (NT_PORTS at install time; edit init script to change later)
SELinux           smoke test decides; enforcing usually works with filecaps,
                  otherwise root fallback is automatic and announced loudly.
```

## Hub-side

Nothing to change. Events ride the standard `/api/ingest` contract
(`{"node": ..., "events": [...]}`, ≤500/request), dedupe downstream as
usual, and appear in the normal dashboard/users/violations views tagged
`source_probe=pcap-http`.
