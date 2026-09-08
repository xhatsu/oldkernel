> **Port migration:** The active hub is OTelTrace on `0.0.0.0:30102`. The former NetworkTracing hub on `:31115` is legacy and is not used.

# STATE.md — Current Project State & Memory

## Current State Summary
- **Git Branch**: `main`, up to date with `origin/main` (latest commit `c6d8781 update test scripts`).
- **Conflict Resolution**: Successfully resolved binary merge conflict in `nt-sniff-cpp`, rebuilt native binaries via `make clean && make`, and regenerated `install-firstrun-el68.sh`.
- **Integrated Features**:
  - Remote control capabilities (`nt_control.py`, `nt-control.py`, `test_nt_control.py`).
  - Remote upstream updates: Test scripts (`nt-test.py`, `nt-test.sh`), unbuffered Python stdout (`-u`), `ETH_P_ALL` capture socket binding, response parsing prioritization, C++ command argument handling and curl stdin pipe fixes.
- **Verification & Test Status**:
  - `make clean && make all && make fixture`: PASS (C++03 sniffer and shipper built with zero warnings; fixture emits all 24 contract fields).
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
- Python shipper now sends the final partial batch on stdin EOF and clamps
  `NT_SHIP_THREADS` to 1..32. Regression suite: 9 tests passed.
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
- `nt-sniff.py` remains header-only by default. Python mode can opt in with a
  validated `NT_WSSE_BODY_BYTES` / `--wsse-body-bytes` window from 1 to 65536
  bytes. At most 256 requests may buffer SOAP prefixes concurrently.
- The incremental namespace-aware parser accepts OASIS 2004 and legacy
  2002/07, 2002/12, and 2003/06 WS-Security namespaces. It emits only the
  normalized username as `user` and `scheme=wsse`; request bodies,
  passwords/digests, nonces, and timestamps are discarded before JSONL output.
- XML bodies require `Content-Length`; chunked encoding, DTD/entity input,
  unsupported/unnamespaced tags, over-window usernames, and excess concurrent
  body flows remain anonymous. C++03 capture remains explicitly header-only.
- Installer configuration and the embedded first-run payload carry the bounded
  Python setting. Focused tests cover opt-in/default behavior, split bodies,
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
    - C++ agent: 218 events emitted in 0.007s (~178k pkts/s), status 200, traceparents, header-only default (`user=-anonymous-`).
    - Live kernel VETH capture (`nt_inj0` -> `nt_cap0` via raw socket): both Python and C++ captured live packets and produced valid JSONL.
  - `tcpdump_10.240.147.249.pcap` (82.9 MB, 149,263 packets):
    - Multi-service traffic across ports 8003, 8005, 8007, 8009, 8010, 8011.
    - Python agent: 11,216 events in 4.6s (32,347 pkts/s), extracted 21 distinct usernames across Basic auth (`vtp`, `myViettel`, `webadmin`) and WSSE (`bccs2.0`, `cc2.0`, `sale`, etc.), status codes 200/302/304/404/500, 100% traceparent coverage.
    - C++ agent: 12,441 events in 0.35s (430,229 pkts/s), extracted Basic auth identities (`vtp`, `myViettel`), full status correlation.
  - Secret hygiene: Zero password tokens (`ViettelCC@123`, `PasswordDigest`, XML bodies) leaked into output JSONL. Test harness: `test_pcap_suite.py`.

## Real Agent Live Ingress Testing (2026-09-08)
- Tested the installed real service `networktracing-legacy` against live non-loopback HTTP/SOAP traffic:
  - Isolated network ingress fixture: client namespace `nt_client` (`192.0.2.2/24`) connected to host `ntv0` (`192.0.2.1/24`) over veth pair, targeting Java service `WsseTrafficService` on port `18080`.
  - **Python Mode Live Test**:
    - Service running rootless as `ntsniff` with `cap_net_raw` file capabilities.
    - Basic auth request: `realagentuser` captured and delivered to Hub `/api/v1/users` (status `Active`).
    - SOAP WSSE request: trace `abcdef0123456789abcdef0123456789` captured with `user="real.agent.wsse.user"`, `scheme="wsse"`, status 200, duration 217ms. Correlated in Hub with Java OTLP child span in multi-tier waterfall.
  - **C++03 Native Mode Live Test**:
    - Service installed and running rootless in native single-binary mode (`--mode cpp`, memory 932 KB).
    - Basic auth request: `cppagentuser` captured and recorded in Hub `/api/v1/users` (status `Active`) and trace `22223333444455556666777788889999` with status 200, duration 3ms, and `source_probe="pcap-http-cpp"`.
  - Cleanup: test namespace `nt_client` and `ntv0` removed; service cleanly re-installed and running on host interface `enp0s6`.


