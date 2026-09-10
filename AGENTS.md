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

## Production Hardening & Architectural Refinement State (2026-09-10) — Round 8
- **Central Safety Invariant**: When stream ordering becomes uncertain, emit unknown status/duration (`status: null, duration_ms: null, resp_bytes: null`) rather than attach another request's response.
- **Capture Gaps & Broken Streams**: `invalidate_stream(conn, reason)` explicitly resets correlation in both directions, flushes non-tombstone pending requests once with null status, clears all reassembly and WSSE buffers, and enters `HTTP_STATE_UNSYNCED`. Body bytes are never parsed as request methods while unsynced; only a verified new client SYN re-establishes synchronized HTTP framing (Test 34).
- **16 KiB RX Ring Geometry**: Configured `MmapRing` to 16 KiB frames (`frame_size = 16384`, `frame_nr = 256`, `frames_per_block = 4`, `block_size = 65536`, `block_nr = 64`, strict 4 MiB total), supporting frames up to 16 KiB without truncation. Truncated frames immediately trigger `invalidate_stream()`.
- **Bidirectional Monitored Ports**: Canonicalized `ConnectionKey` with latched `conn.client` and `conn.server` endpoints established from first observed packet (client SYN, server SYN-ACK, or HTTP method prefix) and never re-evaluated per packet, eliminating directional inversion when both proxy/service ports are monitored (Test 35).
- **Header Limits & Atomic PIPE_BUF Writes**: Header lengths bounded (Host 256B, UA 256B, XFF 512B) via `sanitize_utf8_truncate`, strictly preserving multibyte UTF-8 character boundaries (Test 36). W3C `traceparent` hex validated. Emitted JSON lines are progressively trimmed (`user_agent`, `xff`, `path`) to guarantee each line + `\n` is <= `PIPE_BUF` (4096B) for atomic single `write()` execution on stdout pipes.
- **Native Shipping Reliability**: Direct `pipe()`/`fork()`/`execvp()` execution of `curl` eliminates subshell overhead. Stable batch ID (`X-Batch-Id`) reused across retries. 1x transient retry after 500ms for 5xx/network errors (4xx dropped immediately). Rate-based dynamic post timeout calculation.
- **Condition Variable Shutdown**: Native shipper eliminates `usleep(100000)` busy-spin, using `pthread_cond_timedwait` on producer condition variable with monotonic 10-second deadline.
- **WSSE Parsing Checkpoints & Active Flow Tracking**: XML parsing evaluated only at `wsse_goal`, body end, or buffer growth >= 512B. `g_wsse_body_flows_active` accurately maintained across all lifecycle paths. XML text accumulated across comments and CDATA.
- **Coherent LRU Eviction**: Explicit `conn_lru` list tracks connections, cleanly separating connection table capacity (`MAX_FLOWS = 4096`) from payload byte ceiling (`MAX_TOTAL_FLOW_BYTES = 16 MiB`).
- **Decoupled Payload & Flags**: Payload processed before connection flags (`process_request_payload`, `process_response_payload`, `handle_connection_flags`). FIN operates as directional half-close; RST immediately invalidates and purges.
## Production Hardening & Architectural Refinement State (2026-09-10) — Round 9
- **Memory-Pressure Eviction Iterator Protection**: `in_lru` flag in `struct Connection` prevents double-erasure. Arriving packet's connection protected during eviction via `protected_key` rotation. Newly inserted connections guaranteed full LRU initialization.
- **Out-of-Order FIN Hang Prevention**: `fin_seen` and `fin_seq` in `Flow` track FIN arrival. `HTTP_STATE_CLOSE_BODY` entered only after TCP sequence is completely drained (`fdiff <= 0`). Explicit `HTTP_STATE_CLOSE_BODY` buffer consumption prevents infinite loops in request parser (Test 37).
- **Response-Time WSSE Enrichment Correct Targeting**: Targeted enrichment by `req_id` and `generation` in `conn.pending` prevents subsequent SOAP requests from contaminating prior pipelined anonymous requests with their credentials (Test 38).
- **Uncorrelated Non-SOAP Requests Emitted Under WSSE**: Only SOAP-eligible requests defer when correlation is disabled; all standard requests emit immediately without being lost or overwritten in `deferred_wsse_event` (Test 39).
- **WSSE Buffer Accounting Leak Prevention**: `Flow::wsse_clear()` decrements `g_total_flow_bytes` before clearing buffer, preventing memory accounting leakage across sequential SOAP flows (Test 40).
- **Complete Unicode/UTF-8 Validation**: Rejects 2-byte, 3-byte, and 4-byte overlong encodings (e.g. `\xC0\xAF`), UTF-16 surrogates (`0xD800..0xDFFF`), and codepoints > U+10FFFF in all emitted identity, header, and path fields (Test 41).
## Production Hardening & Architectural Refinement State (2026-09-10) — Round 10
- **FIFO Retention Bound & Overflow Single Ownership**: Stored iterators in `struct Pending` allow O(1) removal of completed/invalidated/expired requests from `g_pending_fifo`. Global overflow in `queue_request()` uses single-owner removal: `invalidate_stream()` owns the removal of live references, and `pop_front()` only removes unowned/orphaned references. The destination connection is explicitly rechecked post-eviction before enqueueing.
- **Connection Reuse Cleanup**: Arriving client SYNs on existing tuples invoke `remove_pending_from_fifo()` on all previous pending requests and tombstones before clearing `conn.pending`, preventing stale FIFO node accumulation across successive generations (Test 45).
- **Delayed Response Sequence Parsing Ahead of FIN**: In `process_request_payload` and `process_response_payload`, HTTP parser loops run before checking stream half-close. Delayed response data arriving after an out-of-order server FIN is completely reassembled and parsed before transitioning to `CLOSE_BODY` (Test 42).
- **Strict RFC 3629 UTF-8 Validation**: Rejects leading bytes > 0xF4 (e.g. 0xF5..0xF7) and code points > U+10FFFF in both `valid_utf8_username` and `sanitize_utf8_truncate` (Test 43).
- **Identity Limit Preservation**: `emit_event` preserves usernames up to `MAX_WSSE_USERNAME * 4` (800 bytes) and Basic auth usernames up to 256 bytes, preventing truncation/merging of distinct identities (Test 44).
- **Dual-Engine Synthetic Regression Suite (`test_synthetic_harness.py`)**: **90/90 PASS** across both C++ and Python engines covering 45 distinct edge cases (Tests 1–45).
- **Unit Tests**: `pytest test_nt_sniff.py` **26/26 PASS**.
- **ASAN/UBSAN**: `cpp-edge-test.py` **ALL 9 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Stats, Shipper).
- **PCAP Verification**: PCAP 247 → 109 events, status 200, duration 112ms, both engines. PCAP 249 → 6,041 events (0.52s C++), zero secret leaks, both engines.
- **Bundle**: `sh build-firstrun.sh` produces verified 410,235-byte self-contained installer `install-firstrun-el68.sh`. Preflight check against live hub OK.

## Python Engine Performance & Hot-Path Parser Optimization (2026-09-10) — Round 11
- **Elimination of $O(N)$ Active Flow Scans**: Replaced per-request linear scans over `flows.values()` with $O(1)$ tracked `g_wsse_active_flows` via `@awaiting_wsse.setter` and `@body_goal.setter` in `Flow`, eliminating >200ms of CPU overhead.
- **Fast-Path XML Early Termination & Checkpoint Parsing**:
  - Fast substring check `b"UsernameToken" not in body` bypasses Expat XML parser initialization for non-WSSE payloads.
  - Guarded DTD/entity inspection with `if b"<!" in body:`, preventing full body bytearray copying and lowercasing.
  - Checkpointed XML parsing in `handle_payload` (evaluating only at goal, body end, or 512B growth).
  - Immediate parser termination via `_UsernameFound` exception upon closing `<wsse:Username>` tag, avoiding parsing thousands of trailing SOAP body elements.
  - ASCII fast path in `normalize_wsse_username` bypasses `unicodedata.normalize` and category checks for printable ASCII (32..126).
- **Zero-Copy Packet Unpacking & Port Filtering**:
  - Replaced slice-based `struct.unpack` with pre-compiled `struct.Struct.unpack_from` (`_STRUCT_B`, `_STRUCT_H`, `_STRUCT_HH`, `_STRUCT_I`).
  - Evaluated `sport in ports` and `dport in ports` before IP total length, data offset, sequence number, and IP string conversions.
  - Cached IP string conversions via `_fast_inet_ntoa` (bounded 4,096-entry cache), eliminating >298,000 `inet_ntoa` conversions.
  - Reused `sport_mon` and `dport_mon` booleans in `process_packet` to eliminate redundant hash lookups.
- **Header Parsing Streamlining**:
  - Avoided intermediate `replace(b"\r\n", b"\n")` string copies, splitting directly on `\r\n`.
  - Filtered header lines by initial character before lowercasing, extracting only the 8 required headers (`content-length`, `transfer-encoding`, `content-type`, `authorization`, `traceparent`, `host`, `user-agent`, `x-forwarded-for`).
  - Pre-checked HTTP method prefix at index 0 against `METHODS_BYTES` set to avoid calling `find_http_start` on standard requests.
- **Syscall & Periodic Task Batching**:
  - Gated `emit_capture_stats()` and remote control polling to run every 256 packets or on `socket.timeout`, removing redundant `time.time()` syscalls from the hot packet ingestion loop.
  - Replaced `waiting_wsse` loop in `emit_capture_stats()` with direct `g_wsse_active_flows` lookup.
- **Performance Results**:
  - PCAP 249 Python offline runtime improved from **1.89s to 1.36s** (throughput increased from **78,978 pkts/s to 109,751 pkts/s**, a **>39% speedup**).
  - All **6,077 events**, 21 users, statuses, traceparents, and secret scrubbing preserved with 100% fidelity.
  - Dual-engine test suite: **90/90 PASS** (`test_synthetic_harness.py`).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - Rebuilt self-contained installer bundle: `install-firstrun-el68.sh` (410,235 bytes, preflight check OK).

## Production Hardening & Architectural Refinement State (2026-09-10) — Round 12
- **Stream Invalidation Resync Model (`reset_flow_for_resync`)**: Invalidation resets sequence state (`has_seq = false`, `next_seq = 0`, `is_broken = false`, `state = HTTP_STATE_HEADER`), flushes buffers, and keeps correlation disabled. Directional parsers seamlessly resync on the next HTTP method/status line boundary, parsing and emitting requests with `status: null` without permanent `HTTP_STATE_UNSYNCED` lockout (Test 46).
- **Flow TTL & Clean Idle Separation**: Raised TTL to `FLOW_IDLE_TTL = 300` and `FLOW_STALE_TTL = 600`. Connections at clean idle boundaries (`flow_at_clean_boundary()`, `connection_clean_idle()`) are cleanly erased without disabling correlation or poisoning registry. Expired stale mid-stream flows past `stale_ttl` trigger `invalidate_stream("stale_flow_expired")` (Test 47).
- **Centralized WSSE Flow Slot Management (`Flow::wsse_cancel()`)**: `g_wsse_body_flows_active` tracked centrally. `Flow::wsse_cancel()` atomically guards `awaiting_wsse`, decrements the global counter, and frees buffers. Called automatically in `Flow::clear_buffers()` and across all completion/timeout/SYN-reset paths (Test 48).
- **Capture Snap Length**: Classic BPF packet capture snap length elevated to `ACCEPT = 12288` to accommodate jumbo Ethernet frames and LRO/GRO offloaded packets up to 12 KiB.
- **Basic Auth Colon Requirement**: `b64decode_user()` strictly requires a colon `:` in decoded credentials; payloads without `:` or with invalid characters after padding `=` are rejected and emitted as anonymous (Test 49).
- **Parse-Time Header Length Bounding**: `bounded_assign()` caps headers at parse time: `Host` (256), `User-Agent` (256), `X-Forwarded-For` (512), `Content-Type` (256), `Transfer-Encoding` (256).
- **Shipping Queue Deque & 3x Transient Retry**: Native sniffer shipping queue upgraded to `std::deque<std::string>` with $O(1)$ `pop_front()`. Both `nt-sniff-cpp` and `nt-ship-cpp` enforce bounded 3x retry with 500ms delay for transient failures (5xx/connection errors; 4xx dropped immediately).
- **Protocol Polish**: `trace_id_from_parent` verifies hex characters for W3C flags `x[53]` and `x[54]`. Duplicate/late SYN-ACKs guarded to prevent moving `resp_flow.next_seq` backward (Test 50).
- **Verification Results**:
  - Dual-engine test suite: **100/100 PASS** (`test_synthetic_harness.py`, Tests 1–50 across C++ and Python).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - ASAN/UBSAN: `cpp-edge-test.py` **ALL 9 EDGE TESTS PASS** (0 leaks, 0 errors).
  - PCAPs: PCAP 247: 109 events, status 200, duration 112ms; PCAP 249: 6,216 events (C++), 6,077 events (Python, 108,190 pkts/s).
  - Self-contained installer bundle: `install-firstrun-el68.sh` (413,380 bytes, preflight check OK).

## Production Hardening & Architectural Refinement State (2026-09-10) — Round 13
- **Mid-Segment HTTP Resync (`find_request_resync`, `find_response_resync`)**: Invalidation and packet loss no longer require the HTTP method or status line to be at offset 0. Scans up to 16 KiB mid-segment, advances payload/sequence pointers, resets parser state to `HTTP_STATE_HEADER`, and preserves out-of-order queue (`fl.ooo`), parsing and emitting the request with `status: null` (Test 51). Symmetrically implemented in Python (`find_request_resync_py`, `find_response_resync_py`).
- **Client ISN Retention Across Invalidations**: `client_isn` is recorded on initial client SYN and retained across stream invalidations in `Connection::client_isn` / Python `Flow.client_isn`. Retransmitted original SYNs (`seq == client_isn`) are recognized as duplicates and ignored without resetting generation or prematurely re-enabling correlation (Test 52).
- **Monotonic & Rollback-Safe Touched Timestamp**: Added `long long touched_mono_ms` to `Connection`. Tracked with `now_monotonic_ms()` in `handle_packet()`, on new SYN, and in `touch_connection()`. `sweep()` computes `idle_ms = now_mono - conn.touched_mono_ms`, completely immune to wall-clock rollbacks and NTP step adjustments.
- **Strict Base64 Validation**: Scans through the complete Base64 token without early exit on `:`. Validates that all characters are legal Base64 digits or padding, enforces `(data_chars + pad_count) % 4 == 0`, maximum 2 `=` pads, zero data characters after padding, and rejects usernames $\ge 256$ bytes (Test 53).
- **Shipping Retry Shutdown Awareness**: Retry loops in `ship_worker_thread()` and `nt-ship-cpp.cpp` inspect `!g_running || g_producer_finished` before and after retry backoff delays. Ingest post timeout reduced from 10s to 3s.
- **Verification Results**:
  - Dual-engine test suite: **106/106 PASS** (`test_synthetic_harness.py`, Tests 1–53 across C++ and Python).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - ASAN/UBSAN: `cpp-edge-test.py` **ALL 9 EDGE TESTS PASS** (0 leaks, 0 errors).
## Production Hardening & Architectural Refinement State (2026-09-10) — Round 14
- **Resync Across TCP Segment Boundary (`find_request_resync`, `find_response_resync`)**: Detects partial HTTP methods (`GET `, `POST `, etc.) and `HTTP/` prefixes at segment ends (`plen - n`). Latches sequence number to the partial prefix offset, enabling seamless reassembly and resync when the remainder arrives in the subsequent segment (Tests 54 & 55). Symmetrically implemented in Python.
- **Graceful Shutdown Queue Flushing**: Replaced immediate abort on producer finish in retry loops with monotonic `shutdown_deadline` checks and dynamic timeout clamping, ensuring queued event batches flush cleanly within the grace period before process termination.
- **Strict Start-Line Validation & Framing Conflict Separation**: `parse_request()` strictly requires 8-byte version `HTTP/1.0` or `HTTP/1.1`. `parse_response()` strictly requires `HTTP/1.0 ` or `HTTP/1.1 ` with 3 ASCII digits. Distinguishes non-HTTP start lines (which are skipped up to `\r\n\r\n` without invalidating stream correlation) from framing conflicts like conflicting `Content-Length` or `Transfer-Encoding: chunked` (which clear buffers and invalidate stream correlation) (Tests 25 & 56). Symmetrically aligned with Python `parse_response_head`.
- **POLLHUP Ring Safety**: Added `POLLHUP` to poll event bitmask (`pfd.revents & (POLLERR | POLLHUP | POLLNVAL)`) in `nt-sniff-cpp.cpp` to prevent busy-spinning on interface closure.
- **CentOS 6 Build Compatibility**: Added `-pthread -lrt` in `LDLIBS` after source files in `Makefile` and `install-oldkernel.sh` for legacy glibc 2.12 compatibility.
- **Verification Results**:
  - Dual-engine test suite: **112/112 PASS** (`test_synthetic_harness.py`, Tests 1–56 across C++ and Python).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - ASAN/UBSAN: `cpp-edge-test.py` **ALL 9 EDGE TESTS PASS** (0 leaks, 0 errors).
  - PCAPs: PCAP 247: 109 events, status 200, duration 112ms; PCAP 249: 6,216 events (C++), 6,077 events (Python, 110,090 pkts/s).
  - Rebuilt self-contained installer bundle: `install-firstrun-el68.sh` (423,706 bytes, preflight check OK).

## Production Hardening & Architectural Refinement State (2026-09-10) — Round 15
- **Zero Flow-Byte Accounting Leak on Response Framing Conflict**: Removed manual `rfl.buf.clear()` in `process_response_payload`. When framing conflict occurs, `invalidate_stream()` triggers `clear_buffers()` which calls `flow_bytes_sub(buf.size())`, ensuring 100% accurate flow-byte counter tracking with 0 leaks. Built-in fixture `--flow-accounting-fixture` verified.
- **Shipping Statistics Concurrency TSAN Safety**: Snapshotted all shipping globals under `g_ship_queue_mutex`, committed `g_prev_*` in the same critical section, rendered JSON strictly from local snapshot variables, and removed the second lock, eliminating all data races.
- **Bounded Non-Truncating `Transfer-Encoding` Parsing**: Added `has_transfer_encoding` and `invalid_transfer_encoding` flags. Headers > 256 bytes are rejected as invalid rather than silently truncated, and `transfer_encoding_final_chunked()` verifies the trailing token, invalidating ambiguous framing in both request and response streams (Test 57).
- **Same-Sequence OOO Retransmission Extension**: Implemented `ooo_insert()` across both directions in C++ and Python. Compatible longer retransmissions update the stored segment, adjust `g_total_flow_bytes` accurately, and drain the complete reassembled payload without creating artificial gaps (Test 58).
- **Verification Results**:
  - Dual-engine test suite: **116/116 PASS** (`test_synthetic_harness.py`, Tests 1–58 across C++ and Python).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - ASAN/UBSAN: `cpp-edge-test.py` **ALL 10 EDGE TESTS PASS** (0 leaks, 0 errors, including flow accounting zero-leak fixture).
  - PCAPs: PCAP 247: 109 events, status 200, duration 112ms; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks.
  - Rebuilt self-contained installer bundle: `install-firstrun-el68.sh` (429,457 bytes, preflight check OK).
## Production Hardening & Architectural Refinement State (2026-09-10) — Round 16
- **Malformed IPv4 Total Length == 0 Rejection**: Removed conditional `if (ip_total_len > 0)`. Unconditionally validate `if (ip_total_len < ihl + 20) return false;` in both C++ `handle_packet()` and Python `process_packet()`, preventing spoofed/malformed L2 frames from injecting events (Test 59).
- **HTTP 101 Upgrade Pending Request Completion**: When `st == 101` arrives, pending upgrade requests are immediately completed with `status: 101`, `resp_bytes: 0`, and calculated duration. Removed from FIFO, decremented pending count, cleared `conn.pending`, and transitioned stream to `HTTP_STATE_UNSYNCED` with correlation disabled until fresh SYN (Test 60).
- **Untrusted Response Correlation Bypass (HEAD Framing Ambiguity Fix)**: When stream correlation is untrusted or disabled (`!allowed || rfl.state == HTTP_STATE_UNSYNCED`), response buffers are cleared and payload processing is bypassed entirely. Prevents bodyless HEAD responses from misframing subsequent data as response bodies, while preserving TCP FIN/RST tracking (Test 61).
- **Strict Complete Transfer-Encoding Tokenization**: Validates all comma-separated list tokens in `Transfer-Encoding`, rejecting empty tokens (`,chunked`, `gzip,,chunked`) or duplicate `chunked` tokens, requiring `chunked` exactly once and only as the final transfer-coding (Test 62).
- **Strict `-p` Port Parsing Rejection**: Added `ports_specified` tracking in `nt-sniff-cpp.cpp`. Invalid port tokens or empty port lists with `-p` immediately exit with error code 2.
- **Verification Results**:
  - Dual-engine test suite: **124/124 PASS** (`test_synthetic_harness.py`, Tests 1–62 across C++ and Python).
  - Unit tests: **26/26 PASS** (`pytest test_nt_sniff.py`).
  - ASAN/UBSAN: `cpp-edge-test.py` **ALL 10 EDGE TESTS PASS** (0 leaks, 0 errors).
  - PCAPs: PCAP 247: 109 events, status 200, duration 112ms; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks.
  - Rebuilt self-contained installer bundle: `install-firstrun-el68.sh` (436,662 bytes, preflight check OK).
