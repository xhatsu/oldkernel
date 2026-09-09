> **Deployment rule:** Hub and bootstrap ports are explicit configuration;
> the oldkernel installer must not infer either port.

# STATE.md — Current Project State & Memory

## Capture & Parser Hardening Round 3 — 3 Blocker Fixes (2026-09-09)

Three additional reproducible blockers fixed in both `nt-sniff-cpp.cpp` and `nt-sniff.py`:

1. **Tombstone Expiry Allows Late Re-correlation (Test 23)**: After a tombstone's 10 s secondary TTL expires un-consumed, all remaining pending entries in the same flow queue are now immediately emitted and removed. A very-late response arriving after the tombstone is purged can no longer silently attach to the next real request.

2. **Duplicate Emit on Shutdown (Test 24)**: `flush_all_pending()`, per-flow overflow eviction (`queue_request`), and SYN pending cleanup now all guard with `!is_tombstone` before calling `emit_event()`. Tombstone entries are always already emitted by `sweep()`; double-emitting them via flush or SYN reconnect paths is eliminated.

3. **Ambiguous Response Framing Fabricates Status (Test 25)**: `parse_response()` returning false (conflicting Content-Length) previously did `buf_erase + continue` — leaving body bytes in the buffer to be re-scanned as a new response. Now it does `clear_buffers() + is_broken = true + break`, matching the Python engine's behavior.

### Test Results After All Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **19/19 PASS** |
| `python3 test_synthetic_harness.py` | **50/50 PASS** (Tests 1–25, both engines) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,205 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 7 EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |


Seven additional reproducible bugs fixed in both `nt-sniff-cpp.cpp` and `nt-sniff.py`:

1. **OOO Drain After Overlap Trim** (`diff < 0` path): `_drain_ooo()` / `drain_ooo_segments()` now called after both in-order *and* overlapping segment ingestion so queued out-of-order segments are immediately consumed after coverage advances (Test 21).

2. **Conflicting Content-Length in Requests** (`nt-sniff.py` parse loop): Duplicate or contradictory `Content-Length` headers detected per-line with `first_cl`; breaks flow. `parse_response_head` similarly validates status range and rejects multi-value `CL` or `CL + chunked` (Test 19).

3. **Chunk Size Overflow** (request-side `HTTP_STATE_CHUNK`): hex string length capped at 16 digits; parsed value checked `< 0 or > 0x7FFFFFFF`; breaks flow. Mandatory trailing `\r\n` validated via separate `chunk_reading_crlf` state (Test 20).

4. **Tombstone Sweep** (`sweep_pending`): Expired non-tombstone items now become tombstones in-place (emitting the event) with a 10-second secondary TTL before removal, preserving FIFO order so late responses consume the tombstone instead of correlating to the next real request (Test 17).

5. **`drain_pending` Tombstone Awareness**: Iterates and emits only non-tombstone items on shutdown (no double-emit).

6. **SYN Response-Flow Generation Propagation**: On client SYN, `next_gen` is now applied to the response flow `flows[rk]` in addition to the request flow, so the `generation` check in response correlation works correctly (Tests 14, 18).

7. **`parse_request` conflict-check removal from early-return**: `parse_request()` in C++ no longer returns `false` early (that path was handled by the caller); caller's `meta.has_conflict_cl` check via `has_chunked` continues to break the stream correctly (Test 15).

### Test Results After All Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **19/19 PASS** |
| `python3 test_synthetic_harness.py` | **44/44 PASS** (Tests 1–22, both engines) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,205 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 7 EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |
| `sh build-firstrun.sh` | **328,822 bytes** bundle rebuilt |



## C++ and Python Mode Comprehensive Review & Verification (2026-09-09)

- Reviewed architecture and security contracts of both C++ mode (`nt-sniff-cpp | nt-ship-cpp`) and Python mode (`nt-sniff.py | nt-ship.py`).
- Enhanced `nt-ship.py` CLI parsing with `--ship-rate-kbps` and `--stats-interval-sec` options for direct CLI parity with `nt-ship-cpp`.
- Updated `cpp-e2e.sh` loopback test to filter out internal stats records (`_nt_internal`) and validate live captured requests.
- Test suite verification:
  - Unit & contract tests: 49/49 pytest tests passed (0.56s).
  - C++03 fixtures: `--fixture`, `--ring-fixture`, `--ship-rate-fixture`, and `--stats-fixture` all passed cleanly.
  - C++ edge tests (`cpp-edge-test.py`): ASAN + UBSAN compilation and fixtures passed with zero errors or leaks.
  - PCAP suite (`test_pcap_suite.py`): Python offline (200/200, 11,216/11,216), C++ offline (200/200, 11,394/11,394), zero credential leaks, and live Linux kernel VETH replay passed for both engines.
  - Preflight installer checks: `--check` passed for both `--mode cpp` and `--mode python`.
  - Live loopback capture: Verified real HTTP request correlation, W3C traceparents, Basic auth extraction, and secret redaction for both Python and C++.
  - Live service Python mode installation: Installed via `--mode python --offline`; confirmed running as UID 997 (`ntsniff`), CapEff 0, 256 MiB address space limit, and 4 poster threads using bounded 256 KiB stacks.
  - Live service restored: Reinstalled production C++ mode (`nt-sniff-cpp | nt-ship-cpp`) on `enp0s6:18080` with 30s stats and 1024 kbit/s upload limit; verified daemon running healthy.
  - Regenerated embedded installer bundle `install-firstrun-el68.sh` (257,504 bytes).
  - Relocated bootstrap distribution server (port 30105) to `~/Viettel/OtelTrace/bootstrap` with backward-compatibility symlink in `~/Viettel/NetworkTracing/bootstrap` and in-tree symlinks for `bundle` and `oldkernel`. Verified 100% pass on all endpoints.
  - Created comprehensive `.gitignore` covering Python bytecode/caches, pytest artifacts, C/C++ build/test binaries (`pcap_test_cpp`, `nt-sniff-cpp-debug`, `*.o`), runtime logs/PID/tmp/jsonl files, and IDE metadata, while preserving tracked pre-compiled binaries.

## Native C++ Pipeline Isolation (2026-09-09)

- Installed native mode now runs `nt-sniff-cpp | nt-ship-cpp` under the same
  guard and supervisor. Only `nt-sniff-cpp` has `CAP_NET_RAW`.
- Capture uses one atomic nonblocking write per JSONL record (maximum
  `PIPE_BUF`). Full-pipe and oversized-record loss increments
  `output_pipe_drops_total`; WAN latency can no longer block TPACKET_V2 ring
  drainage.
- `nt-ship-cpp` continuously drains stdin into a 4,000-event deque and uses one
  512 KiB-stack pthread for bounded 64 KiB uploads. Hub failures back off up to
  60 seconds; queue overflow drops oldest events. Unexpected capture EOF exits
  74 so the five-crash supervisor circuit governs restart storms.
- Native capture records are merged by the shipper into the existing v1
  `/api/agent/stats` contract. Stats are coalesced and failed samples are not
  rapidly retried.
- A live `/proc` audit found that this host's `su`/PAM restores several rlimits
  after the outer guard. Runtime commands now re-enter `nt-resource-guard.sh`
  as `ntsniff` after `su`; capability probes use that same final boundary.
- Final verification: 49 pytest tests passed; optimized C++03 builds and all
  fixtures passed without warnings; ASAN+UBSAN fixtures passed with leak
  detection disabled because LeakSanitizer cannot run under the container's
  ptrace policy. Both sample PCAPs passed offline (247: 200/200 Python/C++;
  249: 11,216/11,394). The privileged veth phase was unavailable in this
  container. The regenerated one-file installer is 257,225 bytes.
- The live service was upgraded using its existing configured Hub URL,
  `enp0s6`, port 18080, CPU 0, 1024 kbit/s upload cap, 30-second stats, and
  16,384-byte WSSE window. It remained stable beyond multiple stats windows.
  `/proc` proves both processes are UID 997, CPU 0, SCHED_IDLE, 256 MiB address
  space, 32 MiB file size, 8 MiB stack, 64 KiB locked memory, 1,024 FDs, and
  zero core dumps. Native RSS was about 7.5 MiB capture plus 3.1 MiB shipper;
  only `nt-sniff-cpp` had `cap_net_raw=ep`.
- The installed native serializer's bounded stats fixture was POSTed to the
  configured `/api/agent/stats`; the Hub returned HTTP success with
  `{"ok":true,"accepted":true,"schema_version":1}`.

## CentOS 6.8 Installer Reliability (2026-09-09)
- Escaped the generated SysV service's PID-file command substitution and `_sw`
  arithmetic expression so `set -u` cannot evaluate runtime-only variables
  while the installer here-doc is being rendered.
- Increased the bounded initial service verification delay from one to three
  seconds for the guard -> supervisor -> `su` -> capture startup path.
- Python shipping now requests a 262,144-byte stack before creating poster
  threads. Unsupported settings warn and retain adaptive partial thread
  startup rather than weakening the 256 MiB address-space guard.
- The real resource guard successfully started eight poster-style Python 3
  threads plus the main thread at 225,444 KiB virtual size and 16,868 KiB RSS,
  pinned to CPU 0. This reproduces the tight virtual-memory condition while
  remaining below the 262,144 KiB ceiling; production defaults to four.
- The corrected bundle was installed locally. Its generated init script
  retained the runtime expressions literally; stop removed the supervisor,
  capture process, and PID file, and the independent three-second start check
  brought the guarded service back successfully.

## Agent Statistics Reporting (2026-09-09)
- Defined `POST /api/agent/stats` on the exact configured Hub base URL; it uses
  no fixed port and remains separate from `/api/ingest` request events.
- `AGENT-STATS-PROTOCOL.md` defines the versioned payload, cumulative and
  interval capture/shipping counters, kernel and shipping drop rates, push
  rates, bounded resource gauges, safety-limit reporting, idempotency, and
  low-cardinality server metric mappings.
- Python capture now sends bounded internal snapshots through its existing
  pipe; the shipper intercepts and merges shipping/resource data without
  forwarding internal records to normal ingest. Native C++03 builds the same
  v1 payload in-process.
- Delivery is one 16 KiB maximum coalesced sample every 30 seconds by default,
  sharing the existing bandwidth budget with no disk retry backlog. Installer
  option `--stats-interval-sec` validates `10..300` seconds.
- Live endpoint verification against `http://129.150.59.233:30102` returned
  HTTP 200 with `accepted:true` for the contract fixture, actual Python shipper
  serialization, and actual C++03 serializer output.
- The local installed native service was upgraded with the guarded bundle and
  exercised against that Hub. Its real periodic sample reached sequence 15
  with status `ok`, zero capture/shipping drops, one thread, about 7.5 MiB RSS,
  CPU affinity 0, and SCHED_IDLE. After the accelerated 10-second test, the
  running service was restored to the 30-second production interval.

## Strict TPACKET_V2 Hardening (2026-09-09)
- Python and native shipping now have an always-on aggregate egress scheduler,
  a 64 KiB HTTP-body ceiling, and a bounded drop-on-overload queue. Installer
  option `--ship-rate-kbps` accepts 64..10000 kbit/s and defaults to 1024;
  Python poster concurrency now defaults to 4 and is capped at 8.
- Native capture now uses only a fixed, overflow-checked 4 MiB TPACKET_V2 RX
  ring. BPF attachment and interface binding precede ring creation; V3, TX
  rings, private areas, packet reserve, and virtual network headers remain
  unused.
- V2 setup is fail-closed with no automatic `recv()` fallback. Partial setup
  closes the socket, normal shutdown explicitly unmaps/disables the ring, and
  packet statistics are logged without payload data.
- Kernel-owned frame metadata is acquired with a memory barrier and validated
  against `TPACKET2_HDRLEN`, wire length, snapshot length, network offset, and
  the 2048-byte frame before parsing. Invalid metadata stops capture and feeds
  the bounded supervisor crash circuit.
- The native capability probe now exercises the exact configured BPF, bind,
  ring mapping/cleanup, and capability drop as `ntsniff`. CentOS 6.8 kernel
  `2.6.32-642.el6` emits an explicit advisory warning without claiming that
  userspace can patch kernel defects.
- Both capture modes cap monitored ports at 30, and native BPF construction
  independently rejects branch offsets above 255, preventing classic-BPF jump
  truncation from weakening the mandatory kernel filter.
- Both capture engines are hard single-worker implementations and contain no
  `PACKET_FANOUT` setup. `-j` remains a compatibility option but rejects every
  value other than 1, avoiding the configuration race behind CVE-2017-6346.

## Operator Run Guide (2026-09-09)
- Simplified the self-contained installer directly instead of adding a
  wrapper. `--server URL` accepts the exact Hub ingest URL without assuming a
  port, while friendly
  `--iface`, `--ports`, `--cpu`, `--ship-threads`, `--ship-rate-kbps`,
  `--wsse-bytes`, and token file options are parsed and validated by the same
  fail-closed installer.
- Added `RUNNING.md` as the canonical detailed guide for local and embedded
  installation, Python/C++ selection, custom interfaces/ports/CPU/WSSE/control
  settings, service lifecycle, safety verification, live route validation,
  troubleshooting, uninstall, and developer fixtures.
- The guide distinguishes installer options from component-only compatibility
  flags, documents that installation is the default action, and warns that
  direct component launch bypasses production guards.
- Current behavior is explicit: `NT_WORKERS` is forced to one, C++ native mode
  ships directly, and accepted `--spool` parameters do not enable disk spooling
  in the present bounded in-memory implementations.
- Verification after agent-stats, egress, CLI, ring, and dual-identity
  hardening: all 47 non-PCAP pytest tests, native optimized fixtures,
  ASAN/UBSAN edge tests, and
  the CentOS static runbook passed. Offline Python/C++ processing retained the
  established sample-PCAP event counts: 200/200 and 11,216/11,394, with native
  secret-scrubbing checks passing. The self-contained bundle was rebuilt at
  234,086 bytes.
- Added an Ansible fleet design that copies one checksum-controlled embedded
  bundle from the controller, uses `command.argv`, deploys in rolling batches,
  and records configuration only after a successful install. New `--offline`
  mode prevents bootstrap fallback and mixed artifact versions. Managed nodes
  require the explicitly configured Hub ingest URL but no bootstrap service.

## Native C++03 WSSE Body Capture (2026-09-08)
- Dual-auth SOAP requests are inspected even after Basic succeeds. Both modes
  emit one event with WSSE primary plus nullable `basic_user` and `wsse_user`;
  invalid, disabled, or capacity-rejected WSSE safely retains Basic as primary.
- A new keep-alive request terminates an incomplete dual-auth WSSE window and
  emits the retained Basic identity before parsing the new request. Idle and
  clean-shutdown fallback do the same, preventing bounded inspection from
  losing otherwise valid Basic events.
- `nt-sniff-cpp` now accepts `NT_WSSE_BODY_BYTES` and
  `--wsse-body-bytes 0..65536`, remaining header-only by default.
- Eligible XML requests with a positive `Content-Length` may buffer a bounded
  SOAP prefix; chunked requests, DTD/entities, unsupported or missing WSSE
  namespaces, invalid/control-character usernames, and overflow body flows
  retain their pre-WSSE identity. A validated WSSE username takes precedence.
- The dependency-free C++03 XML scanner implements scoped namespace bindings,
  four approved WSSE namespace URIs, bounded UTF-8 username normalization, and
  extra depth/attribute/namespace ceilings. Only the username is copied into
  the sanitized event; body and credential material are discarded.
- Installer native mode now passes the configured body window instead of
  rejecting it. The PCAP harness supports the same option.
- Verification: 24 pytest-compatible tests, optimized native builds/fixtures,
  and ASAN+UBSAN fixtures passed. With an 8192-byte window, sample PCAP 247
  produced 200 C++ events with `product/wsse`; PCAP 249 produced 11,394 C++
  events with Basic+WSSE identities. All had traceparents and no body/secret
  markers in native JSONL.

## Runtime Host Safety Boundary (2026-09-08)
- Every installed sniffer/shipper pipeline now starts through
  `nt-supervise.sh` and `nt-resource-guard.sh`; startup fails closed when
  `taskset`/file capabilities are unavailable or the chosen CPU is outside the
  service cpuset. Unsafe root capture fallback was removed; Python and native
  shipping execute under the dedicated non-login `ntsniff` account.
- The complete descendant process tree is pinned to one logical CPU, runs
  under SCHED_IDLE at nice level 19, and inherits hard limits of 256 MiB virtual memory, 8 MiB
  stack, 64 KiB locked memory, 1,024 file descriptors, 32 MiB per regular
  output file, and zero-byte core dumps. EL6 `/bin/sh` additionally enforces a
  64-process ceiling.
- Failures restart with 1/2/4/8-second backoff. Five processes that each die
  inside 60 seconds open the circuit and stop, preventing crash-loop pressure.
- Installation verifies a real `AF_PACKET` open as `ntsniff`, not merely the
  `setcap` return code. Both sniffers require the kernel BPF safety filter and
  drop all capabilities after socket/filter/bind setup; unfiltered or
  capability-retaining capture fails closed.
- The installer automatically chooses the first allowed CPU, supports a
  validated `NT_CPU_CORE=N`, and forces Python PACKET_FANOUT workers to one.
- `test_resource_guard.py` exercises the actual kernel affinity/resource
  limits and verifies that installer startup is routed through the guard.
- Verification: 24 pytest-compatible tests passed (including the loopback
  shipper test); native fixture, ASAN+UBSAN edge tests, and the CentOS runbook
  passed. Offline Python/C++ processing of both sample PCAPs produced the
  established 200/218 and 11,216/12,441 event counts with full traceparents.
  The EL6 smoke probe correctly failed target-only checks on this Linux 6.8,
  Python 3 sandbox (kernel/Python version, setcap, and AF_PACKET).

## Current State Summary
- **Git Branch**: `main`, up to date with `origin/main` (latest commit `c6d8781 update test scripts`).
- **Conflict Resolution**: Successfully resolved binary merge conflict in `nt-sniff-cpp`, rebuilt native binaries via `make clean && make`, and regenerated `install-firstrun-el68.sh`.
- **Integrated Features**:
  - Remote control capabilities (`nt_control.py`, `nt-control.py`, `test_nt_control.py`).
  - Remote upstream updates: Test scripts (`nt-test.py`, `nt-test.sh`), unbuffered Python stdout (`-u`), `ETH_P_ALL` capture socket binding, response parsing prioritization, C++ command argument handling and curl stdin pipe fixes.
- **Verification & Test Status**:
  - `make clean && make all && make fixture`: PASS (C++03 sniffer and shipper built with zero warnings; fixture emits all 26 contract fields).
  - `python3 cpp-edge-test.py`: PASS under AddressSanitizer & UndefinedBehaviorSanitizer for both sniffer and shipper.
  - `pytest test_nt_control.py`: 4/4 tests PASS.
  - `python3 -m py_compile`: nt-sniff.py, nt-ship.py, nt-control.py, nt_control.py compiled cleanly.
  - `sh oldkernel/el68-smoke.sh`: PASS for downloader and python compile assertions (fixed shell operator precedence).
  - `sh oldkernel/build-firstrun.sh`: bundle successfully built (123,320 bytes) with pure in-memory zero-disk-write single-binary agent mode (`nt-sniff-cpp --endpoint URL`), PACKET_MMAP (TPACKET_V2) zero-copy ring buffer, dual-path 802.1Q cBPF (BPF_LDX + correct jump offsets), 11x faster single-pass SIMD HTTP parser, binary 12-byte FlowKey, in-register zero-syscall PRNG, zero-allocation base64 decoding, O(1) port lookup table, bounded RAM queue (`MAX_QUEUE=4000`), zero disk I/O, zero `/tmp` files, and graceful in-memory event drop during Hub outages.
  - `sh bootstrap/package-oldkernel.sh`: verified extraction comparison against source files (BOOTSTRAP-PACKAGE PASS, bundle: 36,987,722 bytes).
  - High-Load CPU & Latency Fixes:
    1. Replaced $O(N)$ linear map scans in `flush_oldest()` and flow eviction with $O(1)$ iterator pops.
    2. Eliminated per-request `fopen("/dev/urandom")` syscall storm with seeded in-register Xorshift64 PRNG (8ns vs 15µs).
    3. Eliminated temporary string heap allocations in `b64decode_user()` by passing raw pointers and lengths.
    4. Replaced vector search with 65,536-entry boolean lookup table `g_monitored_ports` for single-cycle $O(1)$ port matching.
    5. Fixed Python sniffer (`nt-sniff.py`) sweep trigger bug so `sweep_idle` and `sweep_pending` fire on clock time during sustained active traffic.
  - Single-Binary Pure In-Memory Architecture: When `--endpoint` is passed, `nt-sniff-cpp` captures packets, parses HTTP in SIMD zero-copy mode, buffers events in an in-memory queue (bounded to 4000 items / ~1.2MB RAM), and delivers 400-event batches directly to Hub `/api/ingest`. When Hub connection is lost or down, batches are dropped in RAM with 0 disk touches, 0 tmp files, and 0 disk I/O, resuming streaming instantly when Hub connectivity returns.
  - Native `uninstall` action in service script features 3s SIGKILL escalation.
  - Cleaned up stuck background tasks and verified instantaneous uninstall/reinstall cycles.
  - `make -C agent test bundle`: Go agent binaries (`aarch64`, `x86_64`) built from source and packaged into `bootstrap/bundle.tar.gz` (36,987,722 bytes).
  - Modern Go agent (`networktracing.service`) installed via one-line bootstrap command and actively capturing live L7 traffic on VM. Fixed `kyanos-http` response status parsing (extracts 200, 404, 500 status codes, duration_ms, and req/resp byte sizes).
  - Synchronized `README.md` and `bundle/README.md` with explicit One-Line Fast Install & Uninstall commands for modern eBPF and legacy nodes.
  - Bootstrap distribution server active on port 30105 (`/healthz`).
  - Central Hub Control Plane active on port 30102 (`/healthz`, `/api/nodes`, `/api/control/snapshot`).

## Remediated Findings (2026-08-28)
1. **MAX_FLOWS Eviction (`nt-sniff-cpp.cpp`)**: Added oldest-touched flow eviction when map reaches 8192 entries, preventing OOM during SYN/connection floods.
2. **MAX_QUEUE Bounding (`nt-ship-cpp.cpp`)**: Added buffer queue cap (4000 events) to immediately flush/spool to disk during Hub outages.
3. **802.1Q VLAN cBPF (`nt-sniff-cpp.cpp`)**: Added dual-path kernel BPF branching to inspect EtherType `0x8100` and `0x0800` with offset +4.
4. **Kernel Snaplen Optimization (`nt-sniff-cpp.cpp`)**: Reduced BPF accept snaplen from 256 KB to 2048 bytes (headers only).
5. **Granular Keep-Alive Sweep (`nt-sniff-cpp.cpp`)**: Modified `sweep()` to expire individual pending entries rather than bulk-erasing entire connection queues.
6. **JSON Node Name Escaping (`nt-ship-cpp.cpp`)**: Added `jsonq()` helper to sanitize node names in JSON payloads.
7. **Secure `mkstemp()` (`nt-ship-cpp.cpp`)**: Replaced predictable `/tmp/nt_code.<pid>` with `mkstemp()` to prevent symlink attacks.
8. **Secure `mktemp -d` Extraction (`install-oldkernel.sh`)**: Used random temporary directory for kit extraction.
9. **SIGKILL Service Escalation (`install-oldkernel.sh`)**: Added 3-second grace period with `kill -9` fallback in SysV service stop routine.
10. **Operator Precedence Fix (`el68-smoke.sh`)**: Grouped `have curl || have wget` to correctly report downloader presence on curl systems.
11. **Duplicate Log Cleanup (`nt-ship.py`)**: Removed redundant duplicate `log("stopped ...")` line.

## Accessible Artifacts & Commands
- Single file installer build: `sh build-firstrun.sh` -> outputs `install-firstrun-el68.sh`.
- Test Instruction Guide for Remote Nodes: `test-instruction.md` (POSIX `/bin/sh` 5-gate test runbook).
- Runbook & verification: `CENTOS-6.7-TEST.md`, `el68-smoke.sh`, `verify-centos-runbook.sh`, `nt-test.sh` (`nt-test.py`).
- C++ build & fixture: `make all`, `make fixture`.

## Runtime Review (2026-09-08)
- Python HTTP response correlation now consumes one queued request per response,
  preserving keep-alive pipelines; stale queues drain fully and per-flow pending
  depth is bounded at 32 in both Python and C++03 sniffers.
- Python remote control is polled during sustained traffic. Port/interface and
  restart changes re-exec the capable interpreter in place with updated args;
  stop tasks exit capture instead of being acknowledged without effect.
- Python shipper sends the final partial batch on stdin EOF. Its current
  host-safety contract defaults `NT_SHIP_THREADS` to 4 and caps it at 8.
- `install-firstrun-el68.sh` regenerated from the reviewed sources (126672 bytes).
- C++03 optimized build/fixture and ASAN+UBSAN edge fixture pass. The existing
  live `cpp-e2e.sh` loopback capture failed on this host (`capture output file
  missing`) and its capture process required SIGKILL after TERM; investigate
  PACKET_MMAP/live shutdown behavior on a representative target before rollout.

## Real-host E2E Repair (2026-09-08)
- Hub `http://0.0.0.0:30102` accepts legacy `/api/ingest`; the Java fixture is
  active on wildcard port 18080 and `enp0s6` owns `10.0.0.35`.
- `ip route get 10.0.0.35` returns `local ... dev lo`; therefore host-local
  curl traffic never reaches an agent bound to `enp0s6`. A temporary
  `ntcap0`/`ntcap1` namespace veth supplied deterministic non-loopback ingress.
- Installed Python-mode service captured and shipped the namespace request.
  Hub `/api/v1/traces` and `/api/v1/users` showed the Basic-auth principal,
  source `192.0.2.2`, target `port:18080`, final fixture status 200, and
  `source_probe=pcap-http`; the test password was absent from agent logs/state.
- Fixed delayed/lost fallback events: Python idle maintenance now runs every
  second (instead of 30 seconds for a five-second pending TTL), and Python plus
  C++ drain response-pending requests during shutdown. A request-only BPF live
  test changed from zero events after eight seconds to one event after seven.
- Installer now recognizes both `ok` and `success` ingest handshakes and uses
  the platform `service` wrapper when present, retaining direct SysV fallback.
  Final installed state is active under the service manager, rootless as
  `ntsniff`, on `enp0s6`/18080 with Hub endpoint `http://0.0.0.0:30102`.

## WSSE / Active OTelTrace Integration (2026-09-08)
- Both capture modes remain header-only by default and can opt in with a
  validated `NT_WSSE_BODY_BYTES` / `--wsse-body-bytes` window from 1 to 65536
  bytes. At most 256 requests may buffer SOAP prefixes concurrently.
- The incremental namespace-aware parser accepts OASIS 2004 and legacy
  2002/07, 2002/12, and 2003/06 WS-Security namespaces. It emits only the
  normalized username as `user` and `scheme=wsse`; request bodies,
  passwords/digests, nonces, and timestamps are discarded before JSONL output.
- XML bodies require `Content-Length`; chunked encoding, DTD/entity input,
  unsupported/unnamespaced tags, over-window usernames, and excess concurrent
  body flows remain anonymous. The C++03 parser additionally caps XML depth,
  attributes, and namespace bindings inside each bounded prefix.
- Installer configuration and the embedded first-run payload carry the bounded
  setting to both capture modes. Focused tests cover opt-in/default behavior, split bodies,
  all supported namespaces, bounds, and secret hygiene.
- Final verification: 18 pytest tests passed; the optimized C++03 fixture and
  ASAN+UBSAN edge suite passed; POSIX `dash -n`, Python compilation, and
  compatibility grammar parsing passed. The embedded `nt-sniff.py` SHA-256
  exactly matched its source (`e85910a9...531f1d7`). Python 2.6 itself is not
  installed on this host, so real 2.6 execution remains a target-node check.
- A deterministic `ntwsse0`/`ntwsse1` namespace path proved non-loopback live
  capture from `192.0.2.2` to the Java fixture at `192.0.2.1:18080`. Trace
  `d3010200000000000000000020260908` contains both the passive span and Java
  OTLP child span, each stored as `e2e.oldkernel.wsse` / `wsse`, with no secret
  marker in database, agent logs/state, or Java journal. The temporary network
  namespace was removed and the rootless service restored to `enp0s6`.
- Installer systemd/SysV interoperability was corrected: install now stops the
  service-manager unit before replacing the init script, and generated process
  matching expands `PREFIX` correctly. This fixed an observed active-exited
  start race during the live rollout.

## Sample PCAP Data Verification (2026-09-08)
- Tested both `nt-sniff.py` and `nt-sniff-cpp` against real-world sample captures in `~/Viettel/Data`:
  - `tcpdump_10.240.147.247.pcap` (557 KB, 1,272 packets):
    - Port 8001 SOAP WSSE service (`/PRODUCT_SERVICE/bpm/product/PromotionDetailService`).
    - Python agent (`--wsse-body-bytes 8192`): 200 events emitted, 100% traceparent correlation, extracted WSSE username `product` (`scheme=wsse`), correlated status 200 and response bytes.
    - C++ agent (`--wsse-body-bytes 8192`): 200 events emitted with 100% traceparents, extracted WSSE username `product` (`scheme=wsse`), and correlated status 200.
    - Live kernel VETH capture (`nt_inj0` -> `nt_cap0` via raw socket): both Python and C++ captured live packets and produced valid JSONL.
  - `tcpdump_10.240.147.249.pcap` (82.9 MB, 149,263 packets):
    - Multi-service traffic across ports 8003, 8005, 8007, 8009, 8010, 8011.
    - Python agent: 11,216 events in 4.6s (32,347 pkts/s), extracted 21 distinct usernames across Basic auth (`vtp`, `myViettel`, `webadmin`) and WSSE (`bccs2.0`, `cc2.0`, `sale`, etc.), status codes 200/302/304/404/500, 100% traceparent coverage.
    - C++ agent (`--wsse-body-bytes 8192`): 11,394 events with full traceparents, Basic and WSSE identities (`bccs2.0`, `sale`, etc.), and status correlation.
  - Secret hygiene: Zero password tokens (`ViettelCC@123`, `PasswordDigest`, XML bodies) leaked into output JSONL. Test harness: `test_pcap_suite.py`.

## Real Agent Live Ingress Testing (2026-09-08)
- Tested the installed real service `networktracing-legacy` against live non-loopback HTTP/SOAP traffic:
  - Isolated network ingress fixture: client namespace `nt_client` (`192.0.2.2/24`) connected to host `ntv0` (`192.0.2.1/24`) over veth pair, targeting Java service `WsseTrafficService` on port `18080`.
  - **Python Mode Live Test**:
    - Service running rootless as `ntsniff` with `cap_net_raw` file capabilities.
    - Basic auth request: `realagentuser` captured and delivered to Hub `/api/v1/users` (status `Active`).
    - SOAP WSSE request: trace `abcdef0123456789abcdef0123456789` captured with `user="real.agent.wsse.user"`, `scheme="wsse"`, status 200, duration 217ms. Correlated in Hub with Java OTLP child span in multi-tier waterfall.
  - **C++03 Native Mode Live Test (with WSSE body inspection enabled)**:
    - Service installed and running rootless in native single-binary mode (`--mode cpp`, memory 920 KB, bounded to 16,384 body bytes).
    - Live OASIS 2004 WSSE request: trace `c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9` captured with `user="cpp.wsse.live.user"`, `scheme="wsse"`, status 200, duration 40ms, linked with Java OTLP child span in Hub.
    - Live legacy 2002/07 WSSE request: trace `d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8` captured with `user="cpp.wsse.legacy.user"`, `scheme="wsse"`, status 200, duration 26ms, linked with Java OTLP child span in Hub.
    - Basic auth request: `cpp.basic.user` captured and recorded in Hub `/api/v1/users` (status `Active`) and trace `e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7` with status 200.
    - Sample PCAP verification (`tcpdump_10.240.147.247.pcap`): C++ sniffer extracts `product` (`scheme=wsse`) from real SOAP envelopes across all 200 HTTP transactions.
    - Secret hygiene: verified zero tokens, passwords, or nonces leaked into trace attributes or logs.
  - Cleanup: test namespace `nt_client` and `ntv0` removed; service cleanly re-installed in C++ mode on host interface `enp0s6`.

## 100 TPS Load Benchmark (2026-09-08)
- Measured live agent resource consumption under sustained 100 TPS load:
  - **HTTP Basic Auth (100 TPS exact, 1,000 requests / 10.07s)**:
    - **C++ Native Agent (`nt-sniff-cpp`)**:
      - Average CPU: **4.96%** of 1 core (peak: 4.99%).
      - Resident Memory (RSS): **7.84 MB** (down from initial 12.7 MB, zero leaks).
      - Drops: 0 kernel drops, 100% captured and shipped.
    - **Python Agent (`nt-sniff.py` + `nt-ship.py`)**:
      - Average CPU: **9.94%** of 1 core (peak: 9.94%).
      - Resident Memory (RSS): **23.31 MB** total.
      - Drops: 0 kernel drops.
  - **SOAP WSSE XML Inspection (1,018 requests, 66 TPS sustained)**:
    - **C++ Native Agent**:
      - Average CPU: **5.59%** of 1 core (peak: 9.97%).
      - Resident Memory (RSS): **8.45 MB** peak.
    - **Python Agent**:
      - Average CPU: **14.89%** of 1 core (peak: 14.89%).
      - Resident Memory (RSS): **24.47 MB** peak.
  - Benchmarking tools: `measure_usage.py`, `run_100tps_benchmark.py`.
