# Running NetworkTracing Oldkernel

This guide explains how to install, configure, run, verify, reconfigure, and
remove the legacy NetworkTracing capture agent on CentOS 6.x and other Linux
hosts where eBPF and systemd cannot be assumed.

The production entry point is the self-contained `install-firstrun-el68.sh`.
Its public options are intentionally small and readable; preflight checks,
privilege setup, the supervisor, and the resource guard remain internal. Do
not run a sniffer binary directly in production.

## Quick install: one command

The installer download URL and Hub ingest URL are independent and may use any
ports. Download and execute the embedded bundle on one shell line:

```sh
curl -sSf http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh -o install-firstrun-el68.sh && sudo sh install-firstrun-el68.sh --server http://10.0.0.10:42000
```

Here `41000` is only an example kit-server port and `42000` is only an example
Hub ingest port. The installer does not supply or infer either port.

```text
download URL:    http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh
ingest endpoint: http://10.0.0.10:42000
```

All customization stays on that same command. For example:

```sh
curl -sSf http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh \
  -o install-firstrun-el68.sh && \
  sudo sh install-firstrun-el68.sh --server http://10.0.0.10:42000 \
  --mode cpp --iface eth0 --ports 80,8001,8080 \
  --wsse-bytes 16384 --cpu 2
```

If the file was downloaded already, installation is also one command:

```sh
sudo sh install-firstrun-el68.sh --server http://10.0.0.10:42000
```

Do not append agent parameters after curl's `-o FILE`; curl interprets them as
download options. To download and install on one command line, separate the
two programs with `&&`:

```sh
curl -sSf http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh \
  -o install-firstrun-el68.sh && \
  sudo sh install-firstrun-el68.sh --server http://10.0.0.10:42000
```

### Simple installer options

| Option | Meaning |
|---|---|
| `--server URL` | Exact HTTP(S) Hub ingest URL, including its configured port. |
| `--endpoint URL` | Alias for `--server URL`. |
| `--kit-url URL` | Use an exact HTTP(S) bootstrap-kit URL. |
| `--iface IFACE` | Capture one interface, such as `eth0` or `ens192`. |
| `--ports LIST` | Capture at most 30 comma-separated ports in `1..65535`. |
| `--mode python\|cpp` | Select the capture implementation; Python is the default. |
| `--wsse-bytes N` | Inspect a bounded `0..65536` byte SOAP prefix; zero is the safe header-only default. |
| `--cpu N` | Pin the complete runtime tree to this one allowed logical CPU. |
| `--ship-threads N` | Set Python Hub poster threads in `1..32`; this does not add CPU cores. |
| `--control-token-file FILE` | Read a control token from a protected file instead of putting it in shell history. |
| `--offline` | Require a local or embedded kit and prohibit fallback downloads; recommended for Ansible. |

Use `check` instead of `install` to run preflight without installation:

```sh
sh install-firstrun-el68.sh --server http://10.0.0.10:42000 --iface eth0 --cpu 2 --check
```

## 1. Runtime architecture

Python mode runs this pipeline:

```text
nt-resource-guard.sh
  -> nt-supervise.sh
     -> nt-resource-guard.sh
        -> nt-sniff.py | nt-ship.py
```

C++ mode uses the same guard and supervisor, but `nt-sniff-cpp` captures and
ships events directly:

```text
nt-resource-guard.sh
  -> nt-supervise.sh
     -> nt-resource-guard.sh
        -> nt-sniff-cpp --endpoint configured-Hub-URL
```

The installed service is `/etc/init.d/networktracing-legacy`. Installed files
are stored in `/opt/networktracing-legacy`, while control state is stored in
`/var/lib/networktracing`.

### Safety behavior

The installer refuses to start an unsafe configuration:

- Capture runs as the locked `ntsniff` account, never as root.
- `setcap cap_net_raw+ep` must succeed on the private Python interpreter or
  native C++ binary.
- A real `AF_PACKET` open is tested as `ntsniff` during installation.
- The kernel classic BPF port filter must attach. Unfiltered capture is not
  allowed.
- After socket, BPF, and interface setup, the sniffer drops all capabilities.
- Native capture uses only a fixed 4 MiB `TPACKET_V2` RX ring. It does not use
  TPACKET_V3, TX rings, private ring areas, `PACKET_RESERVE`, or virtual-network
  headers. BPF attachment and interface binding happen before ring creation.
- Neither capture engine contains a `PACKET_FANOUT` setup path. Both accept
  only one capture worker, avoiding the CVE-2017-6346 fanout race surface.
- Native startup fails if V2 ring setup or mapping fails; it never silently
  falls back to another capture path. Every kernel-provided frame offset and
  length is bounds-checked before packet parsing.
- The complete supervisor and worker tree is pinned to one allowed logical
  CPU and runs under `SCHED_IDLE` at nice level 19, below normal host work.
- Hard limits are 256 MiB virtual address space, 8 MiB stack, 64 KiB locked
  memory, 1,024 file descriptors, 32 MiB per regular output file, no core
  dumps, and 64 processes when the target `/bin/sh` supports `ulimit -u`.
- Abnormal exits restart after 1, 2, 4, and 8 seconds. Five short failures open
  the crash-loop circuit and stop the agent. A clean remote-control stop is
  not restarted.

These controls contain failures caused by the agent. No userspace program can
guarantee protection from hardware faults, administrator overrides, or unknown
kernel defects.

## 2. Prerequisites

The target host needs:

- Linux with `AF_PACKET` and classic socket BPF support.
- `/bin/sh` with POSIX shell behavior.
- `taskset`, `chrt`, `setcap`, `useradd`, `su`, `pgrep`, and standard core utilities.
- `curl` or `wget` for first-run kit download.
- Python 2.6 or newer for Python mode. The Python path also requires
  `libcap.so.2`, normally installed with the `libcap`/`libcap2` package.
- `g++` with GNU C++98/C++03 support for C++ mode.
- Root access for installation. Runtime capture itself is rootless.
- Network access from the node to the Hub ingest endpoint.

Run the prerequisite smoke test from a local checkout:

```sh
sudo sh el68-smoke.sh
```

The expected result on a supported target is:

```text
NT-SMOKE done: 6 pass, 0 fail
```

The smoke test is expected to reject modern development sandboxes that block
file capabilities or raw sockets. Do not bypass these failures by running the
sniffer as root.

## 3. Lower-level installation methods

### 3.1 Local kit installation

Run this from the directory containing all kit files:

```sh
sudo sh install-oldkernel.sh --server http://10.0.0.10:42000
```

Installation is the default action. `--install` is accepted for readability
but can be omitted.

### 3.2 Self-contained first-run bundle

Download first, then execute the downloaded file:

```sh
curl -sSf http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh \
  -o /tmp/install-firstrun-el68.sh
sudo sh /tmp/install-firstrun-el68.sh \
  --server http://10.0.0.10:42000
```

The two-step form makes download errors visible and ensures the script can
read its own embedded payload. A direct pipeline is also supported:

```sh
curl -sSf http://10.0.0.10:41000/oldkernel/install-firstrun-el68.sh | \
  sudo sh -s -- --server http://10.0.0.10:42000 \
  --kit-url http://10.0.0.10:41000/oldkernel
```

### 3.3 Preflight without installation

`--check` validates the selected runtime, Hub handshake, interface discovery,
and CPU affinity without writing installation files:

```sh
sh install-oldkernel.sh --check \
  --server http://10.0.0.10:42000
```

The rootless file-capability and raw-socket probes happen during installation,
because they require creating the private executable and system account.

## 4. Common configurations

### 4.1 Python mode

Python is the default capture mode:

```sh
sudo NT_IFACE=eth0 \
  NT_PORTS=80,8003,8005,8007,8009,8010,8011 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

Python mode pipes JSONL from `nt-sniff.py` to `nt-ship.py`. The installer
defaults to eight Hub posting threads, all constrained to the same selected
logical CPU and resource limits.

### 4.2 Native C++03 mode

Use native mode when Python parsing overhead is too high:

```sh
sudo NT_CAPTURE_MODE=cpp \
  NT_IFACE=eth0 \
  NT_PORTS=80,8003,8005,8007,8009,8010,8011 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

The installer compiles `nt-sniff-cpp` and `nt-ship-cpp`, grants the capture
binary only `CAP_NET_RAW`, verifies it as `ntsniff`, and starts the native
single-binary capture-and-ship path. `nt-ship-cpp` is still built for fixture
and compatibility use, but the installed native service ships from
`nt-sniff-cpp` directly.

### 4.3 SOAP WSSE username capture

Both modes remain HTTP-header-only when the body window is zero. Enable a
bounded SOAP prefix window when WSSE usernames are required:

```sh
sudo NT_CAPTURE_MODE=cpp \
  NT_IFACE=eth0 \
  NT_PORTS=8001,8003,8005 \
  NT_WSSE_BODY_BYTES=16384 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

The equivalent command-line option is:

```sh
sudo NT_CAPTURE_MODE=cpp sh install-oldkernel.sh \
  --server http://10.0.0.10:42000 \
  --wsse-body-bytes 16384
```

Accepted values are `0..65536`:

- `0`: default; never retain HTTP body bytes.
- `4096`: inspect at most the first 4 KiB of an eligible SOAP request.
- `16384`: inspect at most the first 16 KiB.
- `65536`: maximum 64 KiB per eligible request.

At most 256 requests can buffer SOAP prefixes concurrently. Only XML requests
with a positive `Content-Length` qualify. Chunked bodies, DTD/entity input,
unsupported namespaces, invalid usernames, and requests exceeding concurrency
bounds remain anonymous. Only the username is emitted; SOAP bodies, passwords,
digests, nonces, and timestamps are discarded.

### 4.4 Custom interface, ports, CPU, and ship threads

```sh
sudo NT_CAPTURE_MODE=python \
  NT_IFACE=ens192 \
  NT_PORTS=80,8080,8443 \
  NT_CPU_CORE=2 \
  NT_SHIP_THREADS=4 \
  NT_WSSE_BODY_BYTES=8192 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

Important details:

- `NT_CPU_CORE=2` must identify a CPU in the installer's current allowed CPU
  list. It does not mean "use two cores"; it selects logical CPU number 2.
- If `NT_CPU_CORE` is omitted, the first CPU in `Cpus_allowed_list` is used.
- `NT_PORTS` is a comma-separated list without spaces. TLS payload on port
  8443 remains unreadable even if that port is monitored.
- `NT_SHIP_THREADS` affects Python mode. Runtime code clamps it to `1..32`.
- `NT_WORKERS` is always overridden to `1` by the host safety boundary.

### 4.5 Explicit bootstrap source

The installer never derives a bootstrap URL from the ingest URL. Normally the
saved first-run file uses its embedded payload. If a plain installer has no
local or embedded kit, provide the independent source explicitly:

```sh
sudo sh install-oldkernel.sh \
  --kit-url http://10.0.0.10:41000/oldkernel \
  --server http://10.0.0.10:42000
```

### 4.6 Remote control token

Python capture can poll the Hub control API when a token is installed:

```sh
sudo NT_CONTROL_TOKEN='replace-with-issued-token' \
  NT_IFACE=eth0 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

The installer writes the token to:

```text
/var/lib/networktracing/control.token
```

The file mode is `0600`, and the installer removes the token from its own
environment after writing it. Do not place real tokens in shell history,
terminal recordings, or shared scripts. The integrated remote-control path is
implemented by the Python sniffer; native C++ mode does not currently poll or
apply desired-state changes.

## 5. Installer parameters

Command-line options override the corresponding environment-derived values
where both forms exist.

| Option | Required | Meaning |
|---|---:|---|
| `--server URL` | Recommended | Exact HTTP(S) Hub base URL, including its configured port. Events are sent to `URL/api/ingest`. |
| `--endpoint URL` | No | Alias for `--server URL`, retained for compatibility. |
| `--kit-url URL`, `--hub URL` | No | Bootstrap directory containing oldkernel kit files. Used only when local or embedded files are unavailable. |
| `--iface IFACE` | No | Capture interface; overrides `NT_IFACE`. |
| `--ports LIST` | No | At most 30 comma-separated monitored ports; overrides `NT_PORTS`. |
| `--mode python` | No | Select Python capture. This is the default. |
| `--mode cpp` | No | Select native C++03 capture and direct native shipping. |
| `--wsse-bytes N`, `--wsse-body-bytes N` | No | Set the SOAP prefix window to `0..65536`; overrides `NT_WSSE_BODY_BYTES`. |
| `--cpu N` | No | Select one allowed logical CPU; overrides `NT_CPU_CORE`. |
| `--ship-threads N` | No | Set Python poster threads to `1..32`; overrides `NT_SHIP_THREADS`. |
| `--control-token-file FILE` | No | Read a 1–4096 byte control token without putting it in shell history. |
| `--offline` | No | Use only the local or embedded kit and fail if it is incomplete. No fallback download is attempted. |
| `--install` | No | Explicitly select installation; installation is already the default. |
| `--check` | No | Run non-destructive preflight checks and exit. |
| `--uninstall` | No | Stop the service and remove installed files, PID/token state, and process residue. |

Unknown options fail immediately. Options that require a value must be
followed by that value.

For fleet deployment, use the checksum-controlled offline procedure in
[`ANSIBLE.md`](ANSIBLE.md).

## 6. Installer environment variables

| Variable | Default | What it does |
|---|---|---|
| `NT_IFACE` | First route-table interface | Interface passed to the packet socket, such as `eth0` or `ens192`. Explicit configuration is recommended. |
| `NT_PORTS` | `80,8003,8005,8007,8009,8010,8011` | Destination/service ports admitted by the kernel BPF filter. Use at most 30 comma-separated integers in `1..65535`. |
| `NT_CAPTURE_MODE` | `python` | Set to `cpp` for native mode. Any production configuration should use exactly `python` or `cpp`. |
| `NT_WSSE_BODY_BYTES` | `0` | SOAP body prefix window in bytes, from `0` through `65536`. |
| `NT_CPU_CORE` | First allowed CPU | Logical CPU number used by the complete supervisor/agent tree. |
| `NT_WORKERS` | `1` | Accepted for compatibility but forcibly reset to `1` by the safety boundary. |
| `NT_SHIP_THREADS` | `8` from installer | Python Hub poster threads. The shipper clamps the value to `1..32`; invalid runtime values fall back to `4`. |
| `NT_HUB` | Empty | Same bootstrap-kit purpose as `--hub`; it is not the ingest endpoint. |
| `NT_CONTROL_TOKEN` | Empty | One-time control token written to the protected token file during installation. |

Neither `--server` nor `--endpoint` has an installer environment-variable
equivalent. The URL must include the actual Hub port.

## 7. Service lifecycle

Start, stop, restart, or inspect the service with the platform service wrapper:

```sh
sudo service networktracing-legacy start
sudo service networktracing-legacy status
sudo service networktracing-legacy restart
sudo service networktracing-legacy reload
sudo service networktracing-legacy stop
```

The init script can also be called directly:

```sh
sudo /etc/init.d/networktracing-legacy status
```

`reload` currently performs a stop followed by a start. A normal stop first
terminates the supervisor so it cannot restart children, then terminates any
remaining sniffer/shipper processes. Processes that ignore termination receive
`SIGKILL` after the bounded grace period.

If five short abnormal exits open the supervisor circuit, `status` reports the
agent stopped. Inspect the logs, correct the cause, then issue an explicit
`start` or `restart`.

## 8. Logs and local state

| Path | Contents |
|---|---|
| `/opt/networktracing-legacy/sniff.log` | Python or C++ capture diagnostics. Native direct-shipping diagnostics also appear here. |
| `/opt/networktracing-legacy/ship.log` | Python shipper diagnostics. It can remain empty in C++ mode. |
| `/var/run/networktracing-legacy.pid` | Supervisor PID used for safe stop handling. |
| `/var/lib/networktracing/control.token` | Optional protected control token. |
| `/var/lib/networktracing/remote-desired.json` | Last validated Python desired state and apply result. |

Follow logs:

```sh
tail -f /opt/networktracing-legacy/sniff.log
tail -f /opt/networktracing-legacy/ship.log
```

Each regular output file has a hard 32 MiB process limit. If a log reaches the
limit, the writing process can terminate and eventually open the crash-loop
circuit. Rotate or truncate logs while the service is stopped:

```sh
sudo service networktracing-legacy stop
sudo sh -c ': > /opt/networktracing-legacy/sniff.log'
sudo sh -c ': > /opt/networktracing-legacy/ship.log'
sudo service networktracing-legacy start
```

The current Python and C++ shipping paths use bounded in-memory queues and
drop events when the Hub is unavailable. Although `--spool` is accepted by
compatibility launchers, current implementations do not persist failed events
to disk.

## 9. Verify a running installation

### 9.1 Process and safety limits

Find the capture PID:

```sh
PID=$(pgrep -f '/opt/networktracing-legacy/nt-sniff' | sed -n '1p')
test -n "$PID" || exit 1
```

Confirm CPU affinity and scheduling priority:

```sh
taskset -pc "$PID"
chrt -p "$PID"
ps -o pid,user,ni,pcpu,rss,args -p "$PID"
```

Confirm resource and capability state:

```sh
sed -n '/Max core file size/p;/Max file size/p;/Max open files/p;/Max address space/p;/Max processes/p' "/proc/$PID/limits"
awk '/^CapEff:|^CapPrm:|^Cpus_allowed_list:/{print}' "/proc/$PID/status"
```

After initialization, `CapEff` and `CapPrm` should be all zeroes. The allowed
CPU list should contain exactly the configured logical CPU.

### 9.2 Verify the network path before generating traffic

A request from a host to its own interface address is normally routed over
`lo`, not through that physical interface. Check the route first:

```sh
TARGET_IP=10.0.0.35
ip route get "$TARGET_IP"
```

If the output says `local ... dev lo`, that request does not prove capture on
`eth0` or `ens192`. Send traffic from another host, or use the namespace/veth
fixture described in `CENTOS-6.7-TEST.md`.

### 9.3 Basic-auth event test

From a machine whose traffic reaches the configured interface:

```sh
curl -sS -u testuser:testpassword \
  -H 'Traceparent: 00-11111111111111111111111111111111-2222222222222222-01' \
  http://10.0.0.35:8010/api/health
```

Then query the Hub:

```sh
curl -fsS 'http://10.0.0.10:42000/api/events?limit=10&q=testuser'
```

The username may appear in the event. The password must not appear in Hub
events, agent logs, or local state.

### 9.4 SOAP WSSE event test

Enable a nonzero body window first. Send a request containing an approved WSSE
namespace and a `Content-Length` header (curl sets the length automatically for
`--data-binary`):

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>wsse.test.user</wsse:Username>
        <wsse:Password>temporary-test-secret</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body><Health/></soap:Body>
</soap:Envelope>
```

Save that as `/tmp/nt-soap-test.xml`, then send it from a valid ingress path:

```sh
curl -sS -H 'Content-Type: application/soap+xml' \
  --data-binary @/tmp/nt-soap-test.xml \
  http://10.0.0.35:8001/soap/health
```

The event should contain `user=wsse.test.user` and `scheme=wsse`. The XML,
password, and other token material must not appear in JSON or logs. Delete the
temporary test file after verification.

## 10. Reconfiguration

Re-run the installer with the complete desired configuration. Installation
stops the existing service, replaces files and the init script, then verifies
the new service:

```sh
sudo NT_CAPTURE_MODE=cpp \
  NT_IFACE=ens192 \
  NT_PORTS=80,8001,8080 \
  NT_CPU_CORE=3 \
  NT_WSSE_BODY_BYTES=8192 \
  sh install-oldkernel.sh --server http://10.0.0.10:42000
```

Do not specify only the changed variable and assume all previous installer
values are retained. Unspecified values return to installer defaults.

## 11. Direct component parameters

These interfaces are primarily for development and fixtures. Production must
use the installed SysV service so the resource guard and supervisor are active.

### 11.1 `nt-sniff.py`

```text
python nt-sniff.py [-i IFACE] [-p PORTS] [-j WORKERS] [-v]
                   [--wsse-body-bytes 0..65536]
```

| Parameter | Meaning |
|---|---|
| `-i IFACE` | Bind the `AF_PACKET` socket to one interface. Empty means all interfaces. |
| `-p PORTS` | Comma-separated monitored ports. |
| `-j WORKERS` | Compatibility option; only `1` is accepted. The tracer has no packet-fanout path. |
| `-v` | Compatibility verbosity flag preserved during control-triggered re-exec; it currently adds no packet/body logging. |
| `--wsse-body-bytes N` | Bounded SOAP prefix window. |
| `-h`, `--help` | Print built-in usage text. |

Advanced runtime environment:

| Variable | Meaning |
|---|---|
| `NT_WSSE_BODY_BYTES` | Default SOAP body window when the CLI option is absent. |
| `NT_SNIFF_DEBUG=1` | Emit aggregate receive counters every five seconds; never emits packet contents. |
| `NT_CONTROL_ENDPOINT` or `NT_ENDPOINT` | Python control-plane base URL. |
| `NT_CONTROL_TOKEN_FILE` | File containing the control bearer token. |
| `NT_CONTROL_TOKEN` | Direct control token; prefer the token file. |
| `NT_CONTROL_RUN` | Directory for desired-state files; default `/var/lib/networktracing`. |
| `NT_CONTROL_SEC` | Poll interval clamped to 5–300 seconds. |
| `NT_NODE_NAME` | Override the node name reported to the Hub. |

`NT_SNIFF_SPORT_K` is an internal cBPF calibration control and should not be
changed during normal operation.

### 11.2 `nt-sniff-cpp`

```text
nt-sniff-cpp [-i IFACE] [-p PORTS] [--endpoint URL]
             [--wsse-body-bytes 0..65536]
```

| Parameter | Meaning |
|---|---|
| `-i IFACE` | Bind capture to one interface. |
| `-p PORTS` | Accept comma-separated ports or multiple port arguments. |
| `--endpoint URL` | Enable native in-memory batching and POST directly to `URL/api/ingest`. Without it, events are written as JSONL to stdout. |
| `--wsse-body-bytes N` | Bounded native SOAP prefix window. |
| `-j WORKERS` | Compatibility option; only `1` is accepted. |
| `--spool PATH` | Accepted for compatibility but ignored; native shipping remains in-memory. |
| `-h`, `--help` | Print usage. |

`--fixture`, `--wsse-fixture`, `--ring-fixture`, and `--capability-probe` are
internal validation actions, not production capture modes. The capability
probe exercises the configured BPF, interface bind, complete V2 ring lifecycle,
and capability drop rather than merely opening a raw socket.

### 11.3 `nt-ship.py`

```text
python nt-ship.py --endpoint URL [--spool PATH]
```

| Parameter | Meaning |
|---|---|
| `--endpoint URL` | Required Hub base URL. Reads JSONL events from stdin and posts to `/api/ingest`. |
| `--spool PATH` | Compatibility option. The current implementation accepts the value but uses bounded in-memory drop behavior rather than disk spooling. |
| `-h`, `--help` | Print help. |

`NT_SHIP_THREADS` selects poster threads and is clamped to `1..32`.

### 11.4 `nt-ship-cpp`

```text
nt-ship-cpp --endpoint URL
```

It reads JSONL from stdin, batches up to 400 events, and posts to the Hub.
`--spool PATH` is accepted but ignored. `NT_NODE_NAME` overrides the hostname.

### 11.5 `nt-run-cpp.sh`

This compatibility launcher pipes `nt-sniff-cpp` into the Python shipper:

```sh
NT_HUB_ENDPOINT=http://10.0.0.10:42000 \
  sh nt-run-cpp.sh -i eth0 -p 80,8001
```

| Variable | Meaning |
|---|---|
| `NT_HUB_ENDPOINT` | Required Hub URL passed to `nt-ship.py`. |
| `NT_SPOOL` | Compatibility spool path passed to `nt-ship.py`; current shipping remains in-memory. |

This launcher does not add the production supervisor or resource guard by
itself.

## 12. Troubleshooting

### `taskset required for the one-core runtime safety boundary`

Install the operating system package that provides `taskset` (normally
`util-linux`). The service will not start without enforceable CPU affinity.

### `CPU core N is outside this host/process cpuset`

Inspect the installer's allowed CPUs:

```sh
awk '/^Cpus_allowed_list:/{print $2}' /proc/self/status
```

Choose one listed CPU with `NT_CPU_CORE=N`, or omit the variable and allow the
installer to select the first listed CPU.

### `safe rootless ... capture unavailable`

Check all of the following:

```sh
command -v setcap
command -v useradd
mount | sed -n '/ \/opt /p'
getenforce 2>/dev/null || true
```

The filesystem containing `/opt` must support file capabilities, SELinux must
allow execution of the capped file, and the kernel/security policy must allow
`AF_PACKET` for `CAP_NET_RAW`. Do not work around this error with root capture.

### `kernel BPF safety filter unavailable`

The kernel rejected the classic port filter or Python could not construct it.
Verify that classic socket filters and Python `ctypes` are available. The agent
intentionally refuses to ingest every packet from a busy interface.

### `capability drop failed; refusing unsafe capture`

The capture socket was created but the process could not clear its remaining
capabilities. Verify `libcap.so.2` for Python mode and kernel capability syscall
support for native mode.

### Service repeatedly stops

Check `sniff.log` and `ship.log`. Common causes are an invalid interface, Hub
configuration, capability policy, or a 32 MiB log limit. The fifth short
failure opens the circuit; fix the cause before manually restarting.

### Hub is unreachable

Test from the node with a bounded request:

```sh
curl -sS --max-time 5 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"node":"legacy-manual-probe","events":[]}' \
  http://10.0.0.10:42000/api/ingest
```

Current shipping is bounded and in-memory: events are dropped during an
outage, then new events resume when the Hub is reachable. There is no unbounded
disk growth or retry queue.

## 13. Uninstall

Use either form:

```sh
sudo sh /opt/networktracing-legacy/install-oldkernel.sh --uninstall
```

```sh
sudo service networktracing-legacy uninstall
```

Uninstall stops the supervisor and workers, removes the SysV registration,
deletes `/etc/init.d/networktracing-legacy`, removes the control token/PID, and
deletes `/opt/networktracing-legacy`. It verifies that no matching processes or
installation paths remain.

## 14. Developer verification

Run commands from this directory with explicit timeouts:

```sh
timeout 120s make clean all fixture pcap-fixture
timeout 180s pytest -q --ignore=test_pcap_suite.py
timeout 120s env ASAN_OPTIONS=detect_leaks=0 python3 cpp-edge-test.py
timeout 60s sh verify-centos-runbook.sh
timeout 60s sh el68-smoke.sh
```

The real-PCAP runner expects these files:

```text
/home/ubuntu/Viettel/Data/tcpdump_10.240.147.247.pcap
/home/ubuntu/Viettel/Data/tcpdump_10.240.147.249.pcap
```

Run it with:

```sh
timeout 300s python3 test_pcap_suite.py
```

Its live phase uses `sudo` to create a temporary veth pair. Confirm that the
test host is disposable or otherwise approved before running it. The test
removes the veth pair when it completes.

After changing an embedded kit component, regenerate the first-run installer:

```sh
timeout 60s sh build-firstrun.sh
```
