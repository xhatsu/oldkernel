# AGENTS.md — NetworkTracing Oldkernel Architecture & Operational Guide

## Overview & Context
This repository contains the **NetworkTracing legacy capture kit** for CentOS 6.x / Linux kernel 2.6.32+ nodes where modern eBPF tools cannot run (no eBPF, no systemd, Python 2.6 stdlib only, or native C++03).

### Key Components
- **`nt-sniff.py`**: AF_PACKET raw packet sniffer with classic BPF filter (`SO_ATTACH_FILTER`), TCP flow reassembly, HTTP/1.x header parsing, Basic auth extraction, W3C traceparent generation/parsing, and response correlation.
- **`nt-ship.py`**: Multi-threaded JSONL event shipper with a bounded in-memory queue, aggregate upload pacing, and drop-on-overload behavior for Hub `/api/ingest`; the compatibility spool argument performs no disk writes.
- **`nt_control.py` / `nt-control.py`**: Python 2.6-compatible remote control client supporting atomic desired state application (`remote-desired.json`), heartbeat reporting, and port reconfiguration.
- **`nt-sniff-cpp.cpp` / `nt-ship-cpp.cpp`**: High-performance C++03 replacement sniffer and shipper for >1000 rps environments.
- **`install-oldkernel.sh`**: SysV installer script supporting `--check`, `--install`, and `--uninstall`. Manages rootless `ntsniff` user with `cap_net_raw` file capabilities.
- **`build-firstrun.sh`**: Bundle generator creating `install-firstrun-el68.sh` with embedded base64 payloads of all kit components.
- **`install-firstrun-el68.sh`**: Self-contained single-file installer suitable for `curl | sh` bootstrap.
- **`RUNNING.md`**: Detailed operator guide for installation, custom
  parameters, safety behavior, service lifecycle, verification, and removal.
- **`ANSIBLE.md`**: Stable mass-deployment pattern using a controller-copied,
  checksum-controlled embedded bundle and `--offline` installation.

## Operational Rules & User Directives
1. **Shell Compatibility**: Standard POSIX `sh` (Bourne shell) strictly. No bashisms (`[[ ]]`, `local`, `declare`, `array[i]`, `&>`, etc.).
2. **Kubernetes Restrictions**: NEVER execute Kubernetes `kubectl` commands.
3. **Command Execution Safeguard**: Set execution timers to detect and retry frozen commands.
4. **Testing Mandate**: Always run test suites and fixtures before concluding tasks.
5. **State Tracking**: Maintain `AGENTS.md` and `STATE.md` with project state and architecture memory.
6. **Live Capture Proof**: Before treating a local curl as a NIC capture test,
   verify its route with `ip route get`. Linux routes requests to its own
   interface address over `lo`; use real ingress or an isolated namespace/veth
   fixture when the configured interface itself must be exercised.
7. **Host Resource Safety**: Installed runtime processes must launch through
   `nt-supervise.sh` and `nt-resource-guard.sh`. The agent must run as the
   dedicated non-login user and startup must fail closed if file capabilities
   or CPU affinity cannot be enforced. The full process tree is pinned to one
   allowed logical CPU under SCHED_IDLE at nice 19 and bounded to 256 MiB address space, 8 MiB
   stack, 64 KiB locked memory, 1,024 file descriptors, 32 MiB per output
   file, zero core dumps, and (where `/bin/sh` supports it) 64 processes.
   Five short crashes open the supervisor circuit to prevent restart storms.
   Installation must prove `AF_PACKET` access under `ntsniff`; after socket,
   BPF, and bind setup, capture processes must drop all capabilities.
   Python poster threads must request a 256 KiB stack before creation so the
   process remains viable under the 256 MiB virtual-address-space ceiling.
   The generated SysV script must retain runtime PID/arithmetic expansions
   literally and allow three seconds for the guarded EL6 process tree to start.
8. **Shipping Egress Safety**: Both capture modes must enforce the validated
   `NT_SHIP_RATE_KBPS` aggregate application-payload ceiling (`64..10000`,
   default `1024`), cap encoded HTTP request bodies at 64 KiB, bound all
   in-memory queues, and drop excess events instead of accumulating retries.
9. **Agent Statistics Contract**: Agent health telemetry uses the same exact
   Hub base URL but the separate `POST /api/agent/stats` contract documented
   in `AGENT-STATS-PROTOCOL.md`. It must share the existing egress budget,
   remain bounded/coalesced, contain no captured identity or payload data, and
   never enter the normal request-event stream.
   Both shipping modes must enforce the configured `64..10000` kbit/s
   application-payload ceiling (default 1024), cap each HTTP body at 64 KiB,
   and drop overload rather than create an unbounded queue or later burst.
8. **Native Packet Ring Safety**: C++ capture uses only `TPACKET_V2` with a
   fixed, validated 4 MiB RX ring. It must attach cBPF and bind the interface
   before creating the ring, reject malformed kernel frame metadata, use
   ownership memory barriers, and fail closed instead of falling back to
   `recv()`. TPACKET_V3, TX rings, private areas, packet reserve, and virtual
   network headers are not permitted. Monitored ports are capped at 30 so all
   classic-BPF 8-bit branch offsets remain representable. `PACKET_FANOUT` is
   not permitted; both capture engines must reject worker counts other than 1.
10. **Native Pipeline Isolation**: Installed C++ mode is
   `nt-sniff-cpp | nt-ship-cpp`. Capture stdout is nonblocking and emitted in
   atomic records no larger than `PIPE_BUF`; pipe pressure drops and counts an
   event rather than blocking TPACKET_V2 drainage. The shipper has a bounded
   4,000-event queue and one 512 KiB-stack uploader thread. Only the sniffer
   binary carries `CAP_NET_RAW`; unexpected pipe closure restarts the complete
   supervised pipeline.
11. **Post-Privilege Limits**: Every capture and ship executable must enter
   `nt-resource-guard.sh` again after `su` changes to `ntsniff`, because PAM may
   reset root-applied rlimits during session setup. The outer guard remains the
   supervisor boundary; the inner guard proves the final unprivileged process
   actually retains CPU scheduling and memory/file/process limits.

## WSSE Capture State (2026-09-08)
- Both Python and C++03 capture are header-only by default. `NT_WSSE_BODY_BYTES` or
  `--wsse-body-bytes` explicitly enables a bounded `0..65536` byte SOAP prefix
  window, with at most 256 body-buffering flows.
- Only namespaced OASIS 2004 and legacy 2002/07, 2002/12, or 2003/06
  UsernameToken usernames may become event `user` plus `scheme=wsse`.
  For dual-auth SOAP, WSSE is primary while nullable `basic_user` and
  `wsse_user` report both validated usernames in the same event.
  Credential material and SOAP bodies never enter event JSON or logs.
- C++03 matches the Python opt-in WSSE contract: bounded `Content-Length` XML
  prefixes, 256 concurrent body flows, supported namespace validation, and no
  credential/body material in events or logs.

## Sample PCAP Validation (2026-09-08)
- PCAP test runner `test_pcap_suite.py` validates `nt-sniff.py` and `nt-sniff-cpp`
  against real capture files in `~/Viettel/Data` (`tcpdump_*.pcap`).
- Converts Linux cooked `sll` (linktype 113) to Ethernet frames for native injection.
- Validates W3C traceparents, Basic auth, WSSE UsernameToken extraction, response
  correlation (status/duration/resp_bytes), and secret scrubbing.

## Dual-Mode Test & Verification State (2026-09-09)
- Both C++ mode (`nt-sniff-cpp | nt-ship-cpp`) and Python mode (`nt-sniff.py | nt-ship.py`)
  fully validated across all unit, contract, ASAN/UBSAN, offline PCAP, and live kernel capture tests.
- `nt-ship.py` supports `--ship-rate-kbps` and `--stats-interval-sec` for full CLI option
  parity with `nt-ship-cpp`.
- Live service validated in both Python mode and C++ mode under the real `nt-resource-guard.sh`
  and SysV supervisor, confirming rootless execution (`ntsniff`), 256 MiB address space bounds,
  and zero credential exposure. Production runs in native C++ mode on `enp0s6:18080`.

## Capture & Parser Hardening State (2026-09-09) — Final
- **TCP Stream Reassembly**: Modular `seq_diff`, duplicate suppression, overlap trimming, `_drain_ooo()` / `drain_ooo_segments()` called on BOTH in-order and overlapping paths, bounded OOO queues (4 segs / 16 KiB).
- **HTTP Request & Response Framing**: Explicit state machines on both request and response paths. Body bytes never scanned for HTTP status lines. Chunk size overflow (>16 hex digits or >0x7FFFFFFF) breaks flow. Mandatory trailing `\r\n` per chunk validated separately via `chunk_reading_crlf` state.
- **Conflicting Content-Length Detection**: Both engines parse every `Content-Length` header occurrence; mismatch, negative value, or `Content-Length + Transfer-Encoding: chunked` immediately breaks the flow and prevents smuggled request fabrication (Tests 15, 19).
- **Tombstone Pending Queue**: Expired requests become tombstones (C++: `is_tombstone=true`, Python: `item[2]=True`) with a 10-second secondary TTL. Late responses consume the tombstone without correlating to newer requests on the same connection (Test 17).
- **Connection Generation Isolation**: Client SYN increments `fl.generation` on request flow AND propagates to response flow. Response correlation checks generation equality to prevent cross-connection misattribution (Tests 14, 18).
- **Incomplete SOAP on SYN Reconnect**: Previous flow's WSSE event emitted directly to `out[]` (not re-queued into pending) before generation is incremented (Test 18).
- **sweep_pending Tombstone Handling**: Tombstones skip emission but are retained for 10s then purged; non-tombstone items past TTL become tombstones in-place instead of popping (preserves FIFO order for subsequent responses).
- **drain_pending Tombstone Awareness**: Emits only non-tombstone events on shutdown.
- **parse_response_head Hardening**: Status code range validated (100–599), negative `Content-Length` flagged as conflict, conflicting multi-value `Content-Length` or `CL+chunked` returns `None` to break response flow (C++ equivalent in `parse_response`).
- **Symmetrical Memory Accounting**: `flow_bytes_add()` / `flow_bytes_sub()` across all buffers against 16 MiB total / 64 KiB per-flow bounds.
- **Keep-Alive Timing Precision**: `first_byte_ts` / `first_byte_mono_ms` reset strictly at request boundaries.
- **Shipping Concurrency**: Mutex-guarded `g_producer_finished`, explicit 10s shutdown deadline, `pthread_cond_broadcast` on exit.
- **Dual-Engine Synthetic Regression Suite (`test_synthetic_harness.py`)**: **60/60 PASS** across both C++ and Python engines covering 30 distinct edge cases (Tests 1–30).
- **Persistent Correlation Lockout on Unresolved Tombstone Expiry or Eviction (Test 23)**: When a tombstone expires un-consumed or ordering information is lost via queue eviction, response correlation is permanently disabled for that 4-tuple (`g_corr_disabled` in C++, `corr_disabled` in Python). Subsequent requests on that connection emit immediately with null response fields; incoming responses are parsed to maintain HTTP framing but never correlate. Only a verified new connection (client SYN) resets the lockout and re-enables correlation.
- **Bounded Lockout Registry & Unverified Ordering Fallback**: The lockout registry is bounded to `MAX_CORR_DISABLED = 2048` entries with FIFO queue eviction. When capacity is reached, evicted entries are not re-enabled; instead, connections whose ordering cannot be verified (`!syn_seen`) fall back to emitting requests without response correlation. Verified connections (observed client SYN) correlate normally. Prevents unbounded memory growth across thousands of timed-out connections.
- **Generation-Scoped Correlation Eligibility & Evicted Lockout Safety (Test 26)**: Correlation eligibility (`corr_eligible`) is explicitly tracked per connection generation across both directions (`FlowKey` and reverse key). Once a generation loses ordering (tombstone expiry, queue eviction, or broken stream), `corr_eligible` is latched to `false` on both flow directions. Even if the 4-tuple is evicted from `g_corr_disabled` due to 2,048+ other timeouts, an old `syn_seen=true` cannot bypass the lockout. Requests on that connection emit immediately with null status; late responses do not correlate. Only a fresh TCP connection generation (client SYN) resets sequence state and restores correlation eligibility.
- **SYN-ACK Verification Preservation (Test 27)**: When capacity fallback is active, server SYN-ACK (`flags & 0x02` from server) preserves `rfl.generation`, `rfl.syn_seen`, and `rfl.corr_eligible` established by the client SYN instead of resetting them with a blank `Flow()`. Enables valid request/response correlation under active capacity fallback.
- **Unified Flow Reset on Client SYN (`reset_for_new_connection`, Test 28)**: In both C++ and Python engines, initializing a connection generation on client SYN and server SYN uses a unified `reset_for_new_connection` routine that completely resets flow state, clearing `is_broken = false`, resetting HTTP framing state, and sequence tracking. Prevents broken streams from leaking `is_broken` into subsequent new connections.
- **Expired HEAD Bodyless-Response Semantics (Test 29)**: The response matching logic in both C++ and Python engines checks `ev.method == "HEAD"` on the pending entry before evaluating or removing tombstones. A late response to an expired HEAD request is parsed as bodyless regardless of `Content-Length`, ensuring subsequent pipelined/keep-alive GET responses are not swallowed into the HEAD response body.
- **Complete Root Privilege Drop**: When launched as root (UID 0 / EUID 0), both C++ and Python capture engines drop auxiliary groups, change GID and UID to `ntsniff` (fallback `nobody`), and irreversibly zero all capabilities (`capset(all-zero)`), confirming non-root execution before capturing.
- **Enforced 256 MiB Virtual Memory (`RLIMIT_AS`)**: Enforced at the process level via `setrlimit(RLIMIT_AS)` across C++ and Python sniffers and shippers, guaranteeing that advertised memory limits are actively enforced by the Linux kernel.
- **IPv4 Fragment Rejection (Test 30)**: Packets with More Fragments (`frag & 0x2000`) or non-zero fragment offsets (`frag & 0x1fff`) are rejected (`frag & 0x3fff != 0`), ensuring un-reassembled fragments do not corrupt HTTP flow state while allowing Don't Fragment (`DF == 1`).
- **No Double-Emit on Drain (Test 24)**: `flush_all_pending()`, per-flow overflow eviction, and SYN cleanup all skip tombstone entries (already emitted by `sweep()`). `drain_pending()` in Python also skips tombstones.
- **Broken Response Stream Stops Scanning (Test 25)**: `parse_response` / `parse_response_head` failure on conflicting `Content-Length` now sets `rfl.is_broken = true` and clears the buffer rather than `continue`-ing into body bytes. Prevents body data from being re-scanned as a new response and emitting a fabricated status.
- **PCAP Verification Parity**: PCAP 247 → 109 events, status 200, duration 112ms, both engines. PCAP 249 → 6,204 events (Python) / 6,204 events (C++), zero credential leaks, both engines.
- **Unit Tests**: `pytest test_nt_sniff.py` 26/26 PASS.
- **ASAN/UBSAN**: `cpp-edge-test.py` ALL 8 EDGE TESTS PASS (sniffer, WSSE, dual-auth, TPACKET_V2, shipper ceiling, lockout 10k fixture, agent stats, bounded egress).




