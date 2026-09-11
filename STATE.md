> **Deployment rule:** Hub and bootstrap ports are explicit configuration;
> the oldkernel installer must not infer either port.

# STATE.md — Current Project State & Memory

## Maintenance State Notice (2026-09-11)
- **TraceScope Hub Server & Bootstrap**: Stopped for maintenance via `/home/ubuntu/Viettel/OtelTrace/run_server.sh stop`.
- **Sessions & Ports**: `tracescope-30102` (port 30102), `tracescope-worker`, and bootstrap server (port 30105) cleanly shut down. Verified connection refused on both ports.

## Production Hardening Round 28 — CentOS 6.8 x86_64 Containerized Build & Embedded Binary Shipping (2026-09-11)

Enabled containerized builds for CentOS 6.8 x86_64 targets and embedded precompiled native binaries in `install-firstrun-el68.sh`:

1. **CentOS 6.8 Docker Builder (`Dockerfile.el68` & `build-el68-docker.sh`)**:
   - Uses `centos:6.8` base with `vault.centos.org` archive repositories.
   - Installs native GCC 4.4.7 (`gcc-c++`, `make`, `util-linux-ng`).
   - Compiles native C++03 binaries (`-std=gnu++98 -pthread -lrt`) targeting native glibc 2.12 / Linux 2.6.18+.
   - Generates stripped binaries in `bin/el68-x86_64/nt-sniff-cpp` and `bin/el68-x86_64/nt-ship-cpp`.

2. **Self-Contained Prebuilt Embedding (`build-firstrun.sh`)**:
   - Automatically embeds precompiled binaries as `#__CPP_SNIFF_BIN_B64__` and `#__CPP_SHIP_BIN_B64__` when present in `bin/el68-x86_64/`.
   - Single self-contained bundle `install-firstrun-el68.sh` contains both full source code and ready-to-run prebuilt binaries.

3. **Installer Auto-Detection & Fallback (`install-oldkernel.sh`)**:
   - Extracts precompiled binaries on first run.
   - During preflight and installation, verifies executable compatibility (`--help`).
   - Runs precompiled binaries directly on CentOS 6.8 nodes without requiring `g++` or dev headers.
   - Gracefully falls back to local `g++` compilation if prebuilt binaries are missing or incompatible.

## Production Hardening Round 27 — TraceScope Hub Event Loop Unblocking & Thread Offload (`OtelTrace`) (2026-09-11)

Eliminated 87–97% CPU event-loop blocking in the TraceScope Hub API server (`backend.main:app`) caused by synchronous database work scheduled inside coroutine background tasks:

1. **Root Cause Analysis**:
   - In `OtelTrace/backend/app/api/ingest.py`, `_aggregate_ingested_window(start_ms: int, end_ms: int)` was declared as `async def`.
   - Starlette's `BackgroundTasks` directly awaits coroutine functions on the main asyncio event loop thread instead of offloading them.
   - Inside `_aggregate_ingested_window`, `aggregate_traces()` and `process_principal_intelligence()` run heavy, synchronous SQLite aggregation queries and graph scans.
   - Under continuous agent ingestion, the main event loop thread was perpetually blocked, unable to promptly drain TCP sockets, and consumed 87–97% continuous CPU.

2. **Resolution & Thread Pool Offloading**:
   - Converted `_aggregate_ingested_window` from `async def` to synchronous `def` with internal exception containment.
   - Starlette now automatically offloads the task execution to its thread pool (`anyio.to_thread.run_sync`), keeping the main Uvicorn event loop completely non-blocking and responsive.

3. **Verification**:
   - Stopped and cleanly restarted server via `sh run_server.sh restart`.
   - CPU utilization dropped from 97.3% to **0.0%** (idle sleeping `S` state) while actively receiving live traffic from fleet agents (`116.98.134.138`, `158.178.228.216`, `129.150.59.233`).
   - Verified instantaneous responses across `/api/v1/health` (200 OK), `/api/ingest` (200 OK), and `/healthz` (200 OK).

## Production Hardening Round 26 — Centralized Pending Accounting & Failsafe Overflow Protection (`nt-sniff.py`) (2026-09-11)

Eliminated pending-entry accounting leaks and infinite 100% CPU overflow busy-loops in `nt-sniff.py` by centralizing all removal paths into authoritative accounting primitives, bounding loop termination, and adding automatic counter repair:

1. **Centralized Accounting Primitives with Underflow Self-Repair**:
   - `pending_take(pending_tbl, rk, index=0)`: Pops entry at `index`, safely decrements `g_pending_events_total` if $> 0$, or immediately repairs from the table via `pending_repair_count(pending_tbl)` if an under-count was detected. Automatically removes key from dict when empty.
   - `pending_take_all(pending_tbl, rk)`: Pops entire list `pending_tbl.pop(rk, None)`, decrements `g_pending_events_total -= len(lst)` if $\ge \text{len}$, or repairs from table via `pending_repair_count(pending_tbl)` if an under-count was detected.
   - `pending_actual_count(pending_tbl)`: Authoritative sum of `len(lst)` across all keys in `pending_tbl`.
   - `pending_repair_count(pending_tbl)`: Authoritatively re-synchronizes `g_pending_events_total` to actual table contents.

2. **Elimination of All Direct List/Dict Mutation Bypasses**:
   - In `handle_response`:
     * HTTP 101 WebSocket Upgrade: Uses `removed = pending_take_all(pending_tbl, rk)`. First request emitted with status 101, all subsequent pipelined requests emitted uncorrelated (`status: null`), cleanly draining all entries and updating accounting.
     * Stale Generation: Uses `titem = pending_take(pending_tbl, rk, 0)` and emits `titem[0]`.
     * Tombstone: Uses `pending_take(pending_tbl, rk, 0)` to drop expired entry.
     * Matched Response: Uses `titem = pending_take(pending_tbl, rk, 0)` and enriches `titem[0]`.
   - In `correlate_response`: Uses `item = pending_take(pending_tbl, rk, 0)`.
   - In `drain_pending_requests_unresolved`: Uses `lst = pending_take_all(pending_tbl, rk)`.
   - In `terminate_connection`: Uses `pending_take_all(pending_tbl, resp_k)` and `pending_take_all(pending_tbl, req_k)`.
   - In `pending_del`: Uses `pending_take_all(pending, rk)` and `corr_disabled_erase(rk)`.
   - In `pending_pop`: Uses `item = pending_take(pending_tbl, rk, 0)`.
   - In `sweep_pending`: Uses `rem_entries = pending_take_all(pending_tbl, rk)` on expired tombstones.
   - In `drain_pending`: Uses `lst = pending_take_all(pending_tbl, rk)` and synchronizes via `pending_repair_count`.

3. **Structural Loop Termination & Pre-Repair on Suspicious State (`ensure_pending_capacity`)**:
   - Replaced unbounded `while` loops with `ensure_pending_capacity(pending_tbl, out, flows, resp_flows)`.
   - Pre-repairs table when near capacity or in suspicious state (`g_pending_events_total < 0 or g_pending_events_total >= MAX_PENDING_EVENTS or len(pending_tbl) >= MAX_PENDING_KEYS`) **before** evicting anything. Legitimate requests are never evicted due to stale/inflated counters.
   - If capacity is fine after repair, returns `True` immediately without eviction.
   - Bounded attempts: `min(MAX_PENDING_KEYS + 1, max(32, len(pending_tbl) + 1))`.
   - Forward progress verification: Triggers `pending_repair_count` if `_flush_oldest_pending` frees nothing or does not reduce keys/events.
   - Fail-closed correlation: If capacity cannot be made after `max_attempts`, returns `False`, causing requests to emit immediately with `status: null` rather than spinning at 100% CPU.

4. **Continuous Invariant Verification & Self-Healing**:
   - `assert_internal_invariants` validates `g_pending_events_total == pending_actual_count(pending_tbl)` whenever `pending_tbl is not None`.
   - `sweep_pending` runs periodic self-healing `pending_repair_count(pending_tbl)` on every sweep tick.

### Test Results After Round 26 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **27/27 PASS** (includes comprehensive lifecycle, WebSocket 101, RST, tombstone, stale-counter non-eviction, and underflow detection tests) |
| `pytest test_nt_ship.py` | **15/15 PASS** |
| `python3 test_synthetic_harness.py` | **124/124 PASS** (Tests 1–62 across both C++ and Python engines) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `sh build-firstrun.sh` | **750,266 bytes** bundle rebuilt & verified |

## Production Hardening Round 23 — Python Sniffer Stability-Hardening (`nt-sniff.py`) (2026-09-11)

Implemented complete Python Capture Engine Stability-Hardening plan in `nt-sniff.py` under strict **Python 2.6 stdlib compatibility** and host resource bounds:

1. **Preserved Non-Ring Capture Architecture**:
   - Maintained `AF_PACKET + classic BPF + recv() + 1 worker` architecture.
   - Zero external third-party dependencies; fully compatible with CentOS 6.8 stdlib.

2. **Fail-Closed RLIMIT_AS (256 MiB) & Memory Bounds**:
   - `enforce_rlimit_as()` enforces and verifies 256 MiB address space limit, failing closed with exit code 70 on startup if unable to apply.
   - Fatal `MemoryError` handling in main capture loop flushes stderr diagnostic and exits with code 71 to trigger supervisor backoff.
   - Downstream pipe breakage (`EPIPE`) exits with code 74 to trigger supervisor pipeline restart.
   - Post-privilege `/proc/self/status` capability verification (`verify_dropped_capabilities`) proves unprivileged execution.

3. **Global Memory Accounting (`BufferBudget`)**:
   - Centralized 16 MiB ceiling (`MAX_TOTAL_BUFFER_BYTES = 16 * 1024 * 1024`).
   - Strict accounting across main in-order buffers, OOO segments, and WSSE text.
   - Guarded `append_flow_buf`, `consume_flow_buf`, `clear_main_buffer`, `clear_all_flow_buffers`.

4. **Hard Flow & Pending Capacity Bounds**:
   - Hard tracked half-flow capacity ceiling (`MAX_TRACKED_HALF_FLOWS = 8192`) using `g_flow_fifo` and `g_resp_flow_fifo` (`collections.deque`).
   - FIFO-evicted connections drain uncompleted pending requests with null status before deletion.
   - Global pending bounds: `MAX_PENDING_KEYS = 8192`, `MAX_PENDING_EVENTS = 16384`, `PENDING_PER_FLOW = 32`.
   - Memory-efficient `PendingRequest` class with `__slots__` and index-access compatibility.

5. **OOO Byte Ceiling & Deterministic Retransmission**:
   - Per-flow OOO ceiling (`MAX_OOO_BYTES = 16384`).
   - Tracked `fl.ooo_bytes` with non-overlapping sequence comparison and ambiguity detection.

6. **Symmetrical Framing Limits & Invalidation Model**:
   - Symmetrical response header limits (`MAX_HDRS = 64`) and body framing sanity ceilings (`MAX_HTTP_BODY_FRAMING = 64 MiB`).
   - Symmetrical stream invalidation via `reset_flow_for_resync()`: clears buffers, resets sequence state (`has_seq = False, next_seq = 0, is_broken = False, state = HTTP_STATE_HEADER`), locks out correlation (`fl.corr_eligible = False, corr_disabled_insert(rk)`), allowing directional parsers to resync on subsequent HTTP request boundaries without fake correlation.
   - `HTTP_STATE_UNSYNCED` strictly reserved for permanent framing discontinuation such as HTTP 101 Switching Protocols.

### Test Results After Round 23 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `pytest test_nt_ship.py` | **15/15 PASS** |
| `pytest test_resource_guard.py` | **16/16 PASS** |
| `python3 test_synthetic_harness.py` | **124/124 PASS** (Tests 1–62 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 10 EDGE TESTS PASS** |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `sh build-firstrun.sh` | **741,525 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 18 — Native libcurl Multi-Transfer & Gzip Level 1 Shipper Pipeline (2026-09-10)

Replaced the fork/exec-based C++ shipper with a high-performance native `libcurl` multi-interface and in-memory `zlib` (level 1 gzip) batching engine in `nt-ship-cpp.cpp` under strict **C++03/GCC 4.4 compatibility** and bounded host resources (256 MiB address space, 512 KiB uploader stack):

1. **Native libcurl Multi-Transfer Engine (`CURLM*`)**:
   - Replaced `fork()`/`pipe()`/`execvp("curl", ...)` with non-blocking `curl_multi_*` asynchronous HTTP pipeline supporting up to 4 concurrent in-flight requests (`--max-inflight 1..4`, default 2).
   - Dynamic per-connection upload rate throttling via `CURLOPT_MAX_SEND_SPEED_LARGE` enforcing configured `NT_SHIP_RATE_KBPS` (64..10000 kbit/s, default 1024).
   - TCP keepalive enabled (`CURLOPT_TCP_KEEPALIVE`) and connection reuse across batches without per-batch handshake overhead.

2. **In-Memory Gzip Level 1 Batch Compression (`deflateInit2`)**:
   - Compresses JSON batches on-the-fly (`Content-Encoding: gzip`) using fast gzip level 1 compression, reducing network egress bandwidth by >5x without CPU bottlenecks.
   - Preserves 64 KiB raw JSON batch ceiling (`MAX_POST_BYTES = 65536`) and 400-event batch ceiling (`MAX_BATCH_EVENTS = 400`).

3. **Strict Agent Statistics Protocol v1 Compatibility**:
   - Formats `/api/agent/stats` payloads strictly conforming to the Hub's schema v1 (`schema_version: 1`, `mode: "cpp"`), avoiding `additionalProperties` rejection and ensuring live telemetry acceptance (`{"ok":true,"accepted":true}`).
   - Retains 16 KiB stats body limit, non-retried low-priority side transfers, and exact drop rate calculations.

4. **Retry & Bounded Shutdown Lifecycle**:
   - Bounded exponential retry backoff with deterministic jitter for transient failures (5xx, 408, 429, connection drops), dropping client 4xx errors immediately.
   - Enforces 60-second max retry age and 10-second graceful shutdown flush deadline on capture stdin EOF before exiting with code 74 to trigger supervisor recovery.

### Test Results After Round 18 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **124/124 PASS** (Tests 1–62 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 10 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Flow Accounting Zero-Leak, Stats, Shipper with libcurl/gzip) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **453,325 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 17 — Allocator Capacity Release, Overflow-Safe Buffer Budgeting & bad_alloc Resilience (2026-09-10)

Implemented 3 critical production hardening and memory safety requirements in `nt-sniff-cpp.cpp` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **Allocator Capacity Release on Destructive Resets (`release_string`, `release_vector`)**:
   - Root Cause: Calling `std::string::clear()` or `std::vector::clear()` reduces container size to 0 but retains heap-allocated capacity (`capacity()` remains unchanged). Because `g_total_flow_bytes` tracks `size()`, lingering capacities on long-lived connections can inflate resident memory under RLIMIT_AS (256 MiB).
   - Fix: Added C++03-compatible swap idioms:
     ```cpp
     static void release_string(std::string &s) { std::string().swap(s); }
     template <typename T> static void release_vector(std::vector<T> &v) { std::vector<T>().swap(v); }
     ```
   - Used `release_string(wsse_buf)` in `Flow::wsse_clear()`.
   - Used `release_string(buf)` and `release_vector(ooo)` in `Flow::clear_buffers()`.
   - Used `release_vector(conn.pending)` on destructive connection invalidations, client SYN reuse, HTTP 101 switching protocols, and `flush_all_pending()`. Regular per-request completions (`conn.pending.erase()`) continue using normal container operations to prevent reallocations.

2. **Hard Overflow-Safe Global Memory Budget Enforcement**:
   - Subtractions `len > MAX_TOTAL_BUFFER_BYTES || g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - len` in `buf_append()`, `ooo_push()`, and `wsse_append()` prevent unsigned integer wrap-around vulnerabilities when checking against `MAX_TOTAL_BUFFER_BYTES` (16 MiB).
   - Enforced segment count limit (`fl.ooo.size() >= MAX_OOO_SEGMENTS`) before pushing out-of-order segments.
   - Enforced global budget in `ooo_insert()` with `len - old_len > MAX_TOTAL_BUFFER_BYTES || g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - (len - old_len)`.
   - Handled allocation failure in `wsse_append()` by cancelling WSSE inspection (`wsse_cancel()`) immediately.

3. **Explicit Allocation Failure Handling (`std::bad_alloc`)**:
   - Added `#include <new>`.
   - Wrapped the main capture loop in `try { ... } catch (const std::bad_alloc &) { ... } catch (...) { ... }`.
   - Set `memory_failure = true` on OOM; bypassed event flushing (`flush_incomplete_wsse()`, `flush_all_pending()`) to prevent secondary `bad_alloc` exceptions during heap exhaustion.
   - Cleanly closed raw AF_PACKET sockets, unmapped the TPACKET_V2 ring, and exited with status 2 to trigger the supervisor backoff and restart circuit.

### Test Results After Round 17 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **124/124 PASS** (Tests 1–62 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 10 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Flow Accounting Zero-Leak, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **438,441 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 16 — IPv4 Total Length 0, HTTP 101 Upgrade, Untrusted Response Bypass, Strict TE Tokenization & Strict Port Parsing (Tests 59–62) (2026-09-10)

Implemented 5 production hardening fixes across `nt-sniff-cpp.cpp` and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **MEDIUM-HIGH — Malformed IPv4 Total Length == 0 Rejection (Test 59)**:
   - Root Cause: The IPv4 length validation was guarded by `if (ip_total_len > 0)`. When a packet arrived with `ip_total_len == 0`, it bypassed `ip_total_len < ihl + 20` checks entirely, allowing spoofed or malformed L2 frames to be processed as valid TCP HTTP traffic.
   - Fix: Removed `if (ip_total_len > 0)`. Unconditionally validate `if (ip_total_len < ihl + 20) return false;` in both C++ `handle_packet()` and Python `process_packet()`.
   - Verification: Test 59 PASS on both C++ and Python engines.

2. **MEDIUM — HTTP 101 Switching Protocols Request Completion (Test 60)**:
   - Root Cause: When `st == 101` was received, the sniffer transitioned flows to `UNSYNCED` without completing the pending request. The upgrade request remained stranded in `conn.pending` until timeout or reset, where it was emitted with `status: null`.
   - Fix: Completed the pending upgrade request with `status: 101`, `resp_bytes: 0`, and elapsed duration; decremented global pending count, removed it from FIFO, cleared `conn.pending`, and transitioned flows to `HTTP_STATE_UNSYNCED` with correlation disabled. Subsequent post-upgrade raw frames (e.g. WebSockets) are ignored until a fresh SYN re-establishes an HTTP connection.
   - Verification: Test 60 PASS on both engines.

3. **MEDIUM — Untrusted Response Correlation Bypass (HEAD Framing Ambiguity Fix, Test 61)**:
   - Root Cause: When correlation was disabled or untrusted on a connection, `conn.pending` was empty. When a HEAD response arrived (`200 OK` with `Content-Length: N` but bodyless per RFC 2616), the response parser could not know the request was a HEAD request, so it entered `HTTP_STATE_BODY` and waited for N bytes, eating into subsequent responses.
   - Fix: In both C++ `process_response_payload` and Python `handle_response`, if correlation is untrusted or disabled (`!allowed || rfl.state == HTTP_STATE_UNSYNCED`), response buffers are cleared and payload processing is bypassed entirely. No response payload is buffered or misframed when correlation is disabled, while TCP FIN/RST tracking continues unaffected.
   - Verification: Test 61 PASS on both engines.

4. **LOW — Strict Complete Transfer-Encoding Tokenization (Test 62)**:
   - Root Cause: `transfer_encoding_final_chunked` checked only the last token via `rfind(',')`, permitting malformed list syntax such as `,chunked`, `gzip,,chunked`, or duplicate `chunked, chunked`.
   - Fix: Tokenized all comma-separated values; rejects empty tokens, requires `chunked` exactly once and only as the final token. Symmetrically implemented in C++ and Python.
   - Verification: Test 62 PASS on both engines.

5. **LOW — Strict `-p` Port Parsing Rejection**:
   - Root Cause: Specifying an invalid port such as `-p abc` or `-p 80,99999` was silently ignored, falling back to default ports.
   - Fix: Added `ports_specified` tracking. Invalid port tokens or empty port lists with `-p` immediately print an error and exit with code 2.
   - Verification: `./nt-sniff-cpp -p abc` exits with code 2.

### Test Results After Round 16 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **124/124 PASS** (Tests 1–62 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 10 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Flow Accounting Zero-Leak, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **436,662 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 15 — Release-Blocker Flow Accounting, Concurrency TSAN Safety, Strict Transfer-Encoding & OOO Extension (Tests 57–58) (2026-09-10)

Implemented 4 critical production hardening fixes across `nt-sniff-cpp.cpp` and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **HIGH (Release Blocker) — Zero Flow-Byte Accounting Leak on Response Framing Conflict**:
   - Root Cause: In `process_response_payload`, when `framing_conflict` occurred, `rfl.buf.clear()` was called immediately before `invalidate_stream(conn, "resp_framing_ambiguous")`. `buf.clear()` erased the buffer without decrementing `g_total_flow_bytes`. When `invalidate_stream()` then called `clear_buffers()`, the buffer was already empty, permanently leaking the un-decremented bytes in global accounting and eventually exhausting the 16 MiB buffer ceiling.
   - Fix: Removed manual `rfl.buf.clear()`. `invalidate_stream(conn, ...)` invokes `reset_flow_for_resync(conn.resp_flow)`, which calls `rfl.clear_buffers()`, cleanly executing `flow_bytes_sub(buf.size())` and eliminating any accounting leakage. Added built-in regression fixture `--flow-accounting-fixture`.
   - Verification: Built-in `--flow-accounting-fixture` PASS (`0 bytes leak`), integrated into `cpp-edge-test.py` under ASAN+UBSAN.

2. **MEDIUM — Concurrency TSAN Data Race Elimination in Shipping Statistics**:
   - Root Cause: `agent_stats_body()` acquired `g_ship_queue_mutex` to compute deltas, unlocked it, and then directly read `g_events_in`, `g_events_pushed`, `g_batches_pushed`, and `g_bytes_pushed` while constructing JSON, followed by a redundant second lock to update `g_prev_*`. ThreadSanitizer confirmed data races with concurrent shipping worker updates.
   - Fix: Completely snapshotted all shipping totals (`events_in_total`, `events_pushed_total`, `events_dropped_total`, `drop_queue_total`, `drop_hub_total`, `drop_oversized_total`, `batches_pushed_total`, `batches_failed_total`, `bytes_pushed_total`, `stats_drop_total`) under a single mutex critical section. Committed `g_prev_*` from that exact same snapshot, constructed JSON strictly from local snapshots, and removed the second lock. Eliminates all TSAN races and prevents delta discrepancies.

3. **MEDIUM — Bounded & Non-Truncating `Transfer-Encoding` Header Validation (Test 57)**:
   - Root Cause: `bounded_assign()` truncated `Transfer-Encoding` headers longer than 256 bytes. When a long header (e.g. 269 bytes) ended in `chunked`, truncation sliced off `chunked`, causing the tracer to treat the request as bodyless while the backend server treated it as chunked, corrupting subsequent request framing boundaries.
   - Fix: Added `has_transfer_encoding` and `invalid_transfer_encoding` flags to `RequestMeta`. Oversized (> 256 bytes) or comma-separated TE lines exceeding 256 bytes are flagged invalid rather than silently truncated. Added `transfer_encoding_final_chunked()` to inspect the last comma-delimited token. Any ambiguous, non-chunked, or conflicting TE immediately triggers `invalidate_stream("request_framing_ambiguous")`. Symmetrically implemented for responses and in Python engine.
   - Verification: Test 57 PASS on both C++ and Python engines.

4. **MEDIUM/LOW — Same-Sequence OOO Retransmission Extension (`ooo_insert`, Test 58)**:
   - Root Cause: Out-of-order segment handling deduplicated segments strictly by sequence number. A retransmission carrying an extended range for the same sequence (e.g. seq 200 len 10 followed by retransmission seq 200 len 30) was discarded, causing artificial packet gaps upon reassembly.
   - Fix: Replaced deduplication loops with `ooo_insert()` across request and response paths in C++ and `_ooo_insert()` in Python. If a segment with the same sequence arrives: verifies common bytes match (invalidating if conflicting/ambiguous); if the new segment is longer, updates the data, adjusts `g_total_flow_bytes` accurately (`flow_bytes_sub(old_len); flow_bytes_add(len)`), and retains the longer segment.
   - Verification: Test 58 PASS on both engines.

### Test Results After Round 15 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **116/116 PASS** (Tests 1–58 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 10 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Flow Accounting Zero-Leak, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **429,457 bytes** bundle rebuilt & verified (`--check --iface lo` preflight OK) |

## Production Hardening Round 14 — Five Production Hardening Fixes & Extended Suite (Tests 54–56) (2026-09-10)

Implemented 5 production hardening fixes and 3 new regression fixtures across `nt-sniff-cpp.cpp`, `nt-ship-cpp.cpp`, `nt-sniff.py`, `Makefile`, and `install-oldkernel.sh` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **HIGH — Resync Across TCP Segment Boundaries (`find_request_resync`, `find_response_resync`, Tests 54 & 55)**:
   - Root Cause: Resync search only identified complete signatures (`GET `, `POST `, `HTTP/`) within a single payload. If a method or status line was split across packet boundaries (e.g. `BODYTAILGE` in packet 1 and `T /split HTTP/1.1...` in packet 2, or `BODYHT` + `TP/1.1 200 OK`), resync failed and discarded the stream.
   - Fix: Enhanced `find_request_resync` and `find_response_resync` in C++ and `find_request_resync_py` / `find_response_resync_py` in Python. They search for complete signatures first, then check whether the segment ends with a partial prefix (`prefix = 1..mlen-1`) at offset `plen - n`. When a trailing prefix is detected, sequence tracking latches to that offset, enabling contiguous TCP reassembly and resync with the arriving continuation segment.
   - Verification: Test 54 (`'GE'+'T /split'`) and Test 55 (`'HT'+'TP/1.1'`) PASS on both C++ and Python engines.

2. **MEDIUM-HIGH — Graceful Shutdown Queue Flushing**:
   - Root Cause: Retry loops in `ship_worker_thread()` (`nt-sniff-cpp.cpp`) and `nt-ship-cpp.cpp` checked `g_producer_finished` or `g_input_done` and aborted immediately during retries, dropping queued batches during normal supervisor shutdown.
   - Fix: Removed premature termination on producer finish. Implemented monotonic `shutdown_deadline` checks with dynamic timeout clamping (`unsigned timeout = remaining < post_timeout ? (unsigned)remaining : post_timeout; if (!timeout) timeout = 1;`). Egress queues flush cleanly within the shutdown grace period.

3. **MEDIUM — Strict Start-Line Validation & Framing Conflict Separation (Tests 25 & 56)**:
   - Root Cause: Loose start-line parsing accepted malformed versions (e.g. `XYZ`, `HTT.1`), and C++ `parse_response()` treated invalid start lines identically to framing conflicts, either invalidating valid connections on non-HTTP body false-positives or allowing smuggled responses to correlate.
   - Fix:
     - `parse_request()`: strictly verifies delimiter and requires version to be exactly `HTTP/1.0` or `HTTP/1.1` (8 bytes).
     - `parse_response()`: strictly requires `HTTP/1.0 ` or `HTTP/1.1 ` followed by exactly 3 ASCII digits (100–599).
     - Added `bool *framing_conflict` parameter to `parse_response()`: invalid start lines skip past `\r\n\r\n` and continue searching without invalidating connection correlation; conflicting `Content-Length` or `Transfer-Encoding: chunked` clears buffers and triggers `invalidate_stream("resp_framing_ambiguous")`. Symmetrically aligned with Python `parse_response_head`.
   - Verification: Test 25 (framing conflict invalidation, 0 fake 503) and Test 56 (strict start line rejection) PASS on both engines.

4. **LOW — POLLHUP Ring Safety**:
   - Added `POLLHUP` to poll event bitmask (`pfd.revents & (POLLERR | POLLHUP | POLLNVAL)`) in `nt-sniff-cpp.cpp`, preventing busy spins if the network interface unbinds or closes unexpectedly.

5. **CentOS 6 Build Detail — Link With `-lrt`**:
   - Added `-pthread -lrt` in `LDLIBS` placed after source files in `Makefile` (`cpp`, `cpp-ship`, `cpp-debug`, `pcap_test_cpp`) and `install-oldkernel.sh` for legacy glibc 2.12 runtime library compatibility.

### Test Results After Round 14 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **112/112 PASS** (Tests 1–56 across both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 9 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **423,706 bytes** bundle rebuilt & verified (`--check --iface lo` preflight OK) |

## Production Hardening Round 13 — Five Production Fixes & Extended Suite (Tests 51–53) (2026-09-10)

Implemented 5 production hardening fixes and 3 new regression fixtures across `nt-sniff-cpp.cpp`, `nt-ship-cpp.cpp`, and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **HIGH — Mid-Segment HTTP Resync (`find_request_resync`, `find_response_resync`, Test 51)**:
   - Root Cause: Following packet loss or stream invalidation, parsers only resynchronized if an HTTP method or `HTTP/` was at offset 0 of the TCP packet. If the packet began with residual body bytes from a dropped request followed mid-segment by a new request, resync was missed.
   - Fix: Added `find_request_resync(payload, plen)` (methods `GET `, `POST `, `PUT `, `DELETE `, `PATCH `, `HEAD `, `OPTIONS `) and `find_response_resync(payload, plen)` (`HTTP/`) scanning up to 16 KiB. When found mid-segment (`start != -1`), sequence and payload pointers advance (`fl.next_seq = seq + start; payload += start; plen -= start; seq += start;`), state is reset to `HTTP_STATE_HEADER`, and the request is immediately parsed and emitted with `status: null`. Preserved `fl.ooo` out-of-order queue so out-of-order segments are not dropped during resync. Symmetrically added `find_request_resync_py` and `find_response_resync_py` in `nt-sniff.py`.
   - Verification: Test 51 PASS on both C++ and Python engines.

2. **MEDIUM-HIGH — Retain Client ISN Across Invalidations (Test 52)**:
   - Root Cause: `reset_flow_for_resync()` cleared `conn.req_flow.has_seq` and `next_seq`. Retransmitted original SYNs (`seq == client_isn`) were treated as new connection SYNs because `has_seq` was false, which bumped generation and prematurely restored correlation on broken streams.
   - Fix: Added `bool have_client_isn; uint32_t client_isn;` to `struct Connection` in `nt-sniff-cpp.cpp` and `client_isn` attribute to Python `Flow`. These persist across invalidations. Retransmitted duplicate client SYNs are recognized and ignored without resetting generation or restoring correlation.
   - Verification: Test 52 PASS on both engines.

3. **MEDIUM — Monotonic & Rollback-Safe Touched Timestamp**:
   - Root Cause: `conn.touched` relied solely on wall-clock `time(NULL)`. NTP backward clock steps caused unsigned time delta underflow or premature connection expiration.
   - Fix: Added `long long touched_mono_ms;` to `struct Connection`. Updated with monotonic time (`now_monotonic_ms()`) in `handle_packet()`, on new SYN, and in `touch_connection()`. `sweep()` calculates `idle_ms = now_mono - conn.touched_mono_ms`, completely immune to wall-clock rollbacks.

4. **MEDIUM-LOW — Strict Base64 Full-Token Validation (Test 53)**:
   - Root Cause: `b64decode_user()` broke on `:` without scanning the rest of the Base64 token, ignoring illegal characters, invalid padding, or trailing data after padding. Python `base64.b64decode()` silently ignored non-base64 characters.
   - Fix: Updated `b64decode_user()` in C++ and `basic_user()` in Python to scan through the complete Base64 token. Validates that all characters are legal Base64 digits or padding, enforces `(data_chars + pad_count) % 4 == 0`, maximum 2 `=` pads, zero data characters after padding, and rejects usernames >= 256 bytes.
   - Verification: Test 53 PASS on both engines (malformed trailing suffix rejected as anonymous; valid credentials parsed).

5. **LOW-MEDIUM — Shipping Retry Shutdown Awareness & Timeout Tuning**:
   - Root Cause: Ingest shipping retry loops did not inspect shutdown flags during 500ms backoff intervals.
   - Fix: In `ship_worker_thread()` (`nt-sniff-cpp.cpp`) and `nt-ship-cpp.cpp`, added `if (!g_running || g_producer_finished) break;` before and after retry backoff (`usleep(500000)`). Reduced ingest post timeout in `ship_worker_thread()` from 10s to 3s.

### Test Results After Round 13 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **106/106 PASS** (Tests 1–53, both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 9 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **419,698 bytes** bundle rebuilt & verified (`--check --server http://127.0.0.1:18081` preflight OK) |

## Production Hardening Round 12 — Eight Production Fixes & Extended Suite (Tests 46–50) (2026-09-10)

Implemented 8 production hardening fixes and 5 new regression fixtures across `nt-sniff-cpp.cpp`, `nt-ship-cpp.cpp`, and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **Stream Invalidation Resync Model (`reset_flow_for_resync`, Test 46)**:
   - Root Cause: When stream errors or packet loss occurred, `invalidate_stream()` set `fl.state = HTTP_STATE_UNSYNCED` and `is_broken = true`, permanently bricking the directional HTTP parser on that connection until a new client SYN arrived.
   - Fix: Added `reset_flow_for_resync(Flow &fl)`. Invalidation resets sequence state (`has_seq = false`, `next_seq = 0`, `is_broken = false`, `state = HTTP_STATE_HEADER`), flushes buffers, and keeps correlation disabled (`corr_eligible = false`). Directional parsers seamlessly resynchronize on the next HTTP method/status line boundary, parsing and emitting requests without response correlation (`status: null`), preserving the central safety invariant.
   - Verification: Test 46 PASS on both C++ and Python engines.

2. **Flow TTL & Clean Idle vs Stale Connection Sweep (Test 47)**:
   - Root Cause: Fixed 15s `FLOW_TTL` evicted active keep-alive connections prematurely and called `invalidate_stream()`, poisoning future correlation on that 5-tuple.
   - Fix: Changed TTL to `FLOW_IDLE_TTL = 300` and `FLOW_STALE_TTL = 600`. Added `flow_at_clean_boundary()` and `connection_clean_idle()`. Moved expiration check after pending/tombstone loop in `sweep()`. Cleanly idle connections at clean boundary are quietly erased without disabling correlation. Only connections hung mid-stream or with unresolved pending requests past `stale_ttl` trigger `invalidate_stream("stale_flow_expired")`.
   - Verification: Test 47 PASS on both C++ and Python engines (keepalive requests across 35s idle interval correlate with status 200).

3. **Centralized WSSE Flow Slot Management (`Flow::wsse_cancel()`, Test 48)**:
   - Root Cause: Dispersed manual decrements of `g_wsse_body_flows_active` across six disparate branches created potential slot leakage if any cancellation path missed a decrement.
   - Fix: Moved `g_wsse_body_flows_active` above `struct Flow`, defined `Flow::wsse_cancel()` which atomically guards `awaiting_wsse`, decrements `g_wsse_body_flows_active`, and calls `wsse_clear()`. Replaced all manual decrements with `fl.wsse_cancel()`, and invoked it automatically inside `Flow::clear_buffers()`.
   - Verification: Test 48 PASS on both engines (fresh SYN cancels active WSSE body buffering, decrements counter, and fresh request correlates with status 200).

4. **Capture Snap Length Elevation**:
   - Elevated classic-BPF packet capture length to `ACCEPT = 12288` to accommodate jumbo Ethernet frames and LRO/GRO offloaded packets up to 12 KiB without truncation.

5. **Basic Auth Colon Requirement & Padding Validation (Test 49)**:
   - Root Cause: `b64decode_user()` extracted base64 strings without requiring `:`, and ignored non-padding data following padding `=`.
   - Fix: Added `saw_colon` requirement: returns empty string if no colon is present in decoded data. Added strict padding check rejecting non-whitespace data following `=`.
   - Verification: Test 49 PASS on both engines (malformed `Basic dXNlcg==` without colon rejected, emitted as anonymous).

6. **Parse-Time Header Length Bounding (`bounded_assign`)**:
   - Added `bounded_assign()` helper. Enforces strict parse-time length caps: `Host` (256), `User-Agent` (256), `X-Forwarded-For` (512), `Content-Type` (256), `Transfer-Encoding` (256), preventing oversized headers from allocating unbounded heap memory.

7. **Shipping Queue Deque & Bounded 3x Transient Retry**:
   - In `nt-sniff-cpp.cpp`: Replaced `std::vector<std::string> g_ship_buf` with `std::deque<std::string>` and `pop_front()`, eliminating $O(N)$ copies on queue operations.
   - In both `nt-sniff-cpp.cpp` and `nt-ship-cpp.cpp`: Implemented bounded 3x retry with 500ms delay on transient failures (5xx or connection errors; 4xx client errors dropped immediately).

8. **Protocol Polish: Traceparent Hex Flags & Duplicate SYN-ACK Guard (Test 50)**:
   - In `trace_id_from_parent`: Validates hex characters for W3C flags `x[53]` and `x[54]`.
   - In SYN-ACK handling: Only sets `resp_flow.has_seq = true; resp_flow.next_seq = seq + 1;` if `!resp_flow.has_seq`, preventing duplicate or late SYN-ACKs from moving `resp_flow.next_seq` backward.
   - Verification: Test 50 PASS on both engines.

### Test Results After Round 12 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **100/100 PASS** (Tests 1–50, both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 9 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,216 events (C++), 6,077 events (Python), zero secret leaks ✓ |
| `make clean && make -j2 && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **413,380 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 10 — Six Production Fixes & Extended Suite (Tests 42–45) (2026-09-10)

Implemented fixes for 6 production issues across `nt-sniff-cpp.cpp` and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **[P1] Completed Requests Leave Growing FIFO Behind (Lines 1753 & 1813)**:
   - Root Cause: Every queued request added a `g_pending_fifo` entry, but successful responses did not remove it. Retention waited for 2x TTL (60s), causing memory to scale with traffic volume during retention independently of `MAX_PENDING_TOTAL`.
   - Fix: Added `std::list<PendingQueueRef>::iterator fifo_it;` and `bool in_fifo;` to `struct Pending`.
   - In `queue_request`: initializes `p.fifo_it = fit; p.in_fifo = true;`.
   - In `process_response_payload`: calls `remove_pending_from_fifo(front);` upon response correlation completion.
   - In `invalidate_stream`: calls `remove_pending_from_fifo(conn.pending[i]);` when flushing requests.
   - In `sweep`: calls `remove_pending_from_fifo(entry);` when requests expire to tombstone or prune.
   - Verification: Added `--fifo-fixture` simulating 20,000 requests and responses, invalidation, and sweep under AddressSanitizer. Verified `g_pending_fifo.empty() == true` and 0 leaks.

2. **[P1] Global Pending Overflow Double-Erasure & Heap-Use-After-Free (Lines 1744–1749 & 515)**:
   - Root Cause: `queue_request()` removed the oldest FIFO node with `g_pending_fifo.pop_front()`, then called `invalidate_stream(it->second, "global_pending_overflow")`. The associated `Pending` object in `conn.pending` still held `in_fifo = true` and `fifo_it` pointing to the freed node. When `invalidate_stream()` ran, `remove_pending_from_fifo()` erased that same iterator again, causing heap-use-after-free and double-erasure crashes under memory pressure.
   - Fix: Single-owner FIFO removal. For live references, `invalidate_stream()` owns the removal via `remove_pending_from_fifo()`. Directly call `g_pending_fifo.pop_front()` only for unowned/orphaned references where no live pending object exists.
   - Connection State Recheck: After eviction, explicitly recheck whether the connection receiving the new request was itself invalidated (`conn.corr_disabled || !conn.corr_eligible || conn.req_flow.is_broken || conn.resp_flow.is_broken || g_corr_disabled.count(rk) > 0`) before enqueueing.
   - Verification: Added 4,096-slot global pending overflow test across 128 connections in `--fifo-fixture` under AddressSanitizer. Verified zero heap-use-after-free and clean eviction without double-frees.

3. **[P2] New-SYN Cleanup Leaves Stale FIFO Entries (Lines 2681–2687, Test 45)**:
   - Root Cause: On arriving client SYN for a new connection generation, existing pending requests were emitted and cleared from `conn.pending` via `conn.pending.clear()`, but `remove_pending_from_fifo()` was omitted. Each successive generation left stale dangling FIFO nodes.
   - Fix: Loop over all pending entries (including tombstones) and call `remove_pending_from_fifo(conn.pending[pi]);` before clearing the vector.
   - Verification: Added Test 45 in `test_synthetic_harness.py` simulating 100 successive connection generations on one 5-tuple without responses for 1..99, with generation 100 receiving 200 OK. Verified 99 earlier requests cleanly flushed without status, 100th request correlated with status 200, and exactly 1 FIFO entry remained in `--fifo-fixture`.

4. **[P2] Out-of-Order FIN Discards Valid Delayed Data (Lines 1913 & 2237, Test 42)**:
   - Root Cause: After reassembly reached the FIN sequence (`fdiff >= 0`), code immediately switched `fl.state = HTTP_STATE_CLOSE_BODY` before running the while loop to parse the newly assembled bytes in `fl.buf`. The next branch discarded those bytes, dropping delayed HTTP 200 responses arriving after an out-of-order server FIN.
   - Fix: Removed premature transition to `CLOSE_BODY` prior to buffer parsing. The HTTP parser while loops in `process_request_payload` and `process_response_payload` parse contiguous data first. Only after `buf` and `ooo` are completely drained does the flow transition to `CLOSE_BODY`.
   - Verification: Added Test 42 to `test_synthetic_harness.py`. Server sends FIN before delayed HTTP 200 OK; response parsed and correlated with status 200 and resp_bytes 5.

5. **[P2] UTF-8 Validation Accepts Values Above U+10FFFF (Lines 797 & 1434, Test 43)**:
   - Root Cause: Leading bytes 0xF5–0xF7 were accepted in 4-byte check (`c >= 0xF0 && c <= 0xF7`). RFC 3629 restricts UTF-8 code points to U+10FFFF (max leading byte 0xF4 with second byte <= 0x8F).
   - Fix: In `valid_utf8_username` and `sanitize_utf8_truncate`, changed 4-byte check to `c >= 0xF0 && c <= 0xF4`. Explicitly reject `c > 0xF4` and `cp > 0x10FFFFUL`, replacing invalid bytes with `'?'`.
   - Verification: Added Test 43 to `test_synthetic_harness.py`. Byte sequence `\xF5\x80\x80\x80` sanitized to `'?'`, valid JSON roundtrip, 0 crashes.

6. **[P2] Export Truncation Merges Distinct Identities (Lines 1475–1478, Test 44)**:
   - Root Cause: `MAX_WSSE_USERNAME = 200`, but `emit_event` truncated `user` and `wsse_user` to 64 bytes (`sanitize_utf8_truncate(e.user, 64)`), truncating and merging accounts sharing that prefix.
   - Fix: Changed `emit_event` truncation ceiling to `MAX_WSSE_USERNAME * 4` (800 bytes) for `user` and `wsse_user`, and 256 bytes for `basic_user`.
   - Verification: Added Test 44 to `test_synthetic_harness.py` with an 80-character WSSE username; verified full username emitted without truncation. Verified real PCAP 249 long user `ENC(dBZp1w/CLci3X4HAhy3g2s60kpt4nYoIeIsFNy3sgrGQCCpXapHCJ9T3hPdeG` preserved.

### Test Results After Round 10 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **90/90 PASS** (Tests 1–45, both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 9 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, FIFO Removal 20k/Reuse 100/Overflow 4096, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,041 events (0.52s), zero secret leaks ✓ |
| `make clean && make all && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **402,150 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening Round 9 — Six Production Fixes & Extended Synthetic Suite (Tests 37–41) (2026-09-10)

Implemented fixes for 6 production issues across `nt-sniff-cpp.cpp` and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **Memory-Pressure Eviction Iterator Protection**:
   - In `nt-sniff-cpp.cpp`, `Connection` tracks `bool in_lru` (initialized to `false`).
   - In `touch_connection`: checks `if (conn.in_lru) conn_lru.erase(conn.lru_it); conn.in_lru = false;` and sets `conn.in_lru = true;`.
   - `evict_connection_if_needed`: takes `const ConnectionKey *protected_key`. Moves the arriving packet's active connection to the back of the LRU queue so it is never pruned mid-packet. Clears `it->second.in_lru = false;` on erasure.
   - In `handle_packet`: passes `&ckey` as `protected_key`. Rechecks existence via `cit = connections.find(ckey)` after eviction. If newly inserted, fully initializes `conn.key`, `conn_lru.push_back`, `conn.lru_it`, and `conn.in_lru = true;`.

2. **Out-of-Order FIN Hang Prevention (Test 37)**:
   - Added `fin_seen` and `fin_seq` to `Flow` (both C++ and Python).
   - In `handle_connection_flags` / `feed_flow`: records `fl.fin_seen = true; fl.fin_seq = seq + plen;`. Only transitions to `HTTP_STATE_CLOSE_BODY` if sequence is drained (`!fl.has_seq || fdiff <= 0`).
   - In `process_request_payload` / `feed_flow`: added `if (fl.state == HTTP_STATE_CLOSE_BODY) { del fl.buf[:]; break; }` guaranteeing bytes are consumed and the parser loop never hangs.
   - Symmetrically handled response flows (`rfl.fin_seen`, `rfl.fin_seq`).

3. **Response-Time WSSE Enrichment Correct Targeting (Test 38)**:
   - In C++, replaced `conn.pending[0].ev.wsse_user = username;` with a targeted loop over `conn.pending`: matches `conn.pending[pi].req_id == conn.req_flow.wsse_req_id && conn.pending[pi].generation == conn.req_flow.generation`. Anonymous pipelined requests in `pending[0]` are never contaminated with subsequent request's WSSE credentials.
   - Symmetrically brought `nt-sniff.py` into parity in `handle_response`.

4. **Uncorrelated Non-SOAP Requests Emitted Under WSSE (Test 39)**:
   - In `queue_request()` (C++): only defers to `conn.deferred_wsse_event` if `wsse_eligible == true`. If `conn.has_deferred_wsse` already exists, flushes the previous deferred event before storing the new one. Ineligible requests (like `GET /lost`) emit immediately via `emit_event(e); return 0;`.
   - In `nt-sniff.py`: `_emit_request_to_pending` emits immediately when correlation is not allowed; deferred WSSE is only active for SOAP-eligible requests.

5. **WSSE Buffer Accounting Leak Prevention (Test 40)**:
   - Added `Flow::wsse_clear()` in C++ that performs `flow_bytes_sub(wsse_buf.size()); wsse_buf.clear(); wsse_last_parsed_len = 0;`.
   - Replaced all direct `fl.wsse_buf.clear()` calls with `fl.wsse_clear()`.
   - Invoked `fl.wsse_clear()` across all extraction exit points (successful parse, goal reached, body exhausted, response enrichment).

6. **Complete Unicode/UTF-8 Validation (Test 41)**:
   - Rewrote `sanitize_utf8_truncate` with full Unicode decoding validation: rejects 2-byte overlongs (`need == 1 && c < 0xc2`), 3-byte overlongs (`c == 0xe0 && s[i+1] < 0xa0`), UTF-16 surrogates (`c == 0xed && s[i+1] >= 0xa0`), 4-byte overlongs (`c == 0xf0 && s[i+1] < 0x90`), and codepoints > U+10FFFF (`c == 0xf4 && s[i+1] >= 0x90`). Replaces all invalid bytes with `'?'`.
   - In `emit_event`: passes all exported strings through `sanitize_utf8_truncate` (`host`, `service`, `method`, `path`, `user`, `scheme`, `basic_user`, `wsse_user`, `host_hdr`, `user_agent`, `xff`, `caller`, `dst_ip`, `traceparent`, `trace_id`).

### Test Results After Round 9 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **82/82 PASS** (Tests 1–41, both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 8 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,041 events (0.52s), zero secret leaks ✓ |
| `make clean && make all && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **391,172 bytes** bundle rebuilt & verified (`--check --endpoint http://129.150.59.233:30102` preflight OK) |

## Production Hardening & Architectural Refinement Round 8 — 15-Point Implementation Checklist (2026-09-10)

Implemented the complete 15-point production hardening checklist across `nt-sniff-cpp.cpp`, `nt-ship-cpp.cpp`, `pcap_test_cpp.cpp`, and `nt-sniff.py` under strict **C++03/GCC 4.4 compatibility**, bounded host memory (256 MiB address space, 4 MiB RX ring), and maintaining all existing JSON fields:

1. **Capture Gaps & Broken Streams (`invalidate_stream`, Test 34)**:
   - Centralized stream integrity invalidation in `invalidate_stream(conn, reason)`.
   - Disables correlation in both directions, flushes pending non-tombstone requests once with null response fields, clears reassembly, out-of-order, and WSSE buffers, records invalidation counter, and enters explicit `HTTP_STATE_UNSYNCED`.
   - Body bytes cannot be misinterpreted as HTTP request methods while unsynced. Only a verified new client SYN re-establishes synchronized HTTP parsing.

2. **Ring Geometry & Frame Bounds**:
   - Configured `MmapRing` geometry to 16 KiB frames (`frame_size = 16384`, `frame_nr = 256`, `frames_per_block = 4`, `block_size = 65536`, `block_nr = 64`, strict 4 MiB total).
   - Prevents frame truncation on standard and jumbo frames up to 16 KiB while fitting all kernel ring metadata. Frame truncation immediately routes to `invalidate_stream(conn, "truncated_frame")`.

3. **Bidirectional Monitored Ports (Test 35)**:
   - Canonicalized `ConnectionKey(ep1, ep2)` with latched endpoint roles (`conn.client` and `conn.server`).
   - Direction established decisively on first packet (client SYN, server SYN-ACK, or HTTP method prefix) and never re-evaluated per packet, preventing directional inversion when proxy/service ports (e.g. 8003 -> 8005) are both in the monitored list.

4. **Header Limits & Atomic PIPE_BUF Writes (Test 36)**:
   - Sanitizes and truncates headers to bounded lengths (Host 256B, UA 256B, XFF 512B) using `sanitize_utf8_truncate`, strictly preserving multibyte UTF-8 character boundaries without splitting trailing code points.
   - Validates W3C `traceparent` format (version, 32-hex trace-id, 16-hex parent-id, 2-hex flags) before extraction.
   - Formats JSON lines and progressively trims optional fields (`user_agent`, `xff`, `path`) to guarantee each line + `\n` is <= `PIPE_BUF` (4096B) for atomic single `write()` execution on stdout pipes.

5. **Shipping Retries, Pacing & Timeouts**:
   - `nt-ship-cpp.cpp` generates a stable UUIDv4 batch ID (`X-Batch-Id`) reused across retries.
   - Implemented 1x transient retry after 500ms delay for 5xx/network errors; 4xx errors drop immediately.
   - Rate-based timeout calculation: `max(DEFAULT_POST_TIMEOUT_SEC, (int)(batch_bytes * 8 / ship_rate_bps) + 5)`.
   - Replaced shell `popen()` with direct `pipe()`/`fork()`/`execvp()` execution of `curl`, reading exit code and verifying exact HTTP status lines without shell overhead.

6. **Memory Ceiling & RLIMIT_AS Enforcement**:
   - Verified that `curl` processes launched by the native shipper operate within the 256 MiB address space limit enforced by `nt-resource-guard.sh` and internal `setrlimit(RLIMIT_AS)`.

7. **Shutdown Busy-Spin Elimination**:
   - In `nt-ship-cpp.cpp`, replaced `usleep(100000)` polling loop with `pthread_cond_timedwait` on producer condition variable with monotonic 10-second deadline. Discarded records on timeout are accounted in `drop_queue`.

8. **Generation Mismatch & Tombstone Safety**:
   - In `invalidate_stream` and queue sweeps: `if (!entry.is_tombstone) emit_event(entry.ev);`. Tombstones are never double-emitted.
   - Differentiates SYN retransmissions (`seq == conn.req_flow.next_seq - 1`) from new connections, preventing spurious generation increments.

9. **WSSE UTF-8 Validation & Text Accumulation**:
   - `valid_utf8_username` validates UTF-8 multi-byte sequences, checking continuation bytes `(byte & 0xC0) == 0x80` and rejecting overlong encodings, surrogates, and code points > U+10FFFF.
   - XML parsing accumulates text across comments and CDATA sections (`xml_unescape_append`).

10. **WSSE Parsing Cost & Active Body Counters**:
    - Limits XML parsing checkpoints to `wsse_goal`, body end, or buffer growth >= 512 bytes.
    - Accurately increments/decrements `g_wsse_body_flows_active` across all flow termination, expiry, and reset paths.
    - Early server responses attempt one final parse on accumulated buffer before immediate emission.

11. **Coherent LRU Connection Eviction**:
    - Connections tracked on `conn_lru` list. Differentiates connection table capacity (`connections.size() >= MAX_FLOWS = 4096`) from aggregate payload byte ceiling (`g_total_flow_bytes >= MAX_TOTAL_FLOW_BYTES = 16 MiB`).

12. **Decoupled Payload & Connection Flags**:
    - Decoupled payload processing (`process_request_payload`, `process_response_payload`) from connection flag handling (`handle_connection_flags`).
    - Payload is processed before FIN/RST. FIN operates as directional half-close; RST immediately invalidates and purges the connection.

13. **Empty WSSE on FIN Avoidance**:
    - Removed obsolete re-queueing of incomplete WSSE events on FIN packets, preventing duplicate or phantom empty WSSE emissions.

14. **Deferred WSSE Identity When Correlation Disabled**:
    - When correlation is disabled for a connection, valid WSSE authentication events are retained in `conn.deferred_wsse_event` and emitted once with null status/duration rather than discarded.

15. **Defensive Socket & Protocol Cleanup**:
    - Directly attaches BPF to AF_PACKET socket via `SO_ATTACH_FILTER`.
    - Creates socket with protocol 0 and binds before attaching filter.
    - Fixed signed negation overflow in sequence math via `(uint32_t)(-(int64_t)diff)`.
    - Limited chunk size line parsing to 64 bytes.
    - Mapped HTTP 101 (Switching Protocols) to `HTTP_STATE_UNSYNCED`.

### Test Results After Round 8 Implementation

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **72/72 PASS** (Tests 1–36, both C++ and Python engines) |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 8 EDGE TESTS PASS** (Sniffer, WSSE, Dual-Auth, TPACKET_V2, Ceiling, Lockout 10k, Stats, Shipper) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,031 events (0.38s), zero secret leaks ✓ |
| `make clean && make all && make pcap_test_cpp` | **PASS** (0 warnings under `-Wall -Wextra -std=gnu++03`) |
| `sh build-firstrun.sh` | **379,577 bytes** bundle rebuilt |

## Capture & Parser Hardening Round 7 — Flow Expiry Invalidation, WSSE Early Response, Ring Geometry & Truncation (2026-09-10)

Three critical production hardening and framing isolation issues resolved across both C++ and Python engines:

1. **Flow Expiry Framing Isolation & Correlation Invalidation (Test 31)**:
   - When flow state expires after 15 seconds (`FLOW_TTL = 15`), previously pending requests (default `PENDING_TTL = 30`) retained pending state while HTTP parser and TCP sequence state were reset. Resuming response body data could be misinterpreted as a new HTTP response header (e.g. `HTTP/1.1 503...`) and falsely correlated to queued requests.
   - Fixed by calling `invalidate_connection_correlation` for the canonical response key `rk` in `sweep()` (C++) and `sweep_idle()` (Python) before erasing flow state. All queued pending requests on that connection are immediately flushed without status (`status = None`), and subsequent requests on that flow cannot correlate until a fresh client SYN initializes a new connection.

2. **Immediate Pending Queue Reservation for WSSE Flows (Test 32)**:
   - Previously, when `--wsse-body-bytes` was enabled, requests were only enqueued to pending after SOAP body collection finished or reached `MAX_WSSE_BODY_BYTES`. An early server response (such as `403 Forbidden` or `500 Internal Server Error`) arriving before the body arrived could not find a pending entry and was discarded.
   - Fixed by immediately reserving the pending request slot upon header parsing completion (`queue_request` in C++, `_emit_request_to_pending` in Python), tracking `fl.wsse_req_id` and `fl.wsse_rk`. When the SOAP body arrives later, the pending entry is enriched in-place with extracted `wsse_user`. If an early response arrives before the body, it immediately matches the reserved pending request and emits with the correct status.

3. **Packet Ring Sizing & Truncated Frame Invalidation (Test 33)**:
   - Updated C++ packet capture ring geometry in `MmapRing` to `frame_size = 8192`, `frame_nr = 512`, `frames_per_block = 8`, `block_size = 65536`, `block_nr = 64`, maintaining the strict 4 MiB ring bound while supporting 8 KiB frame captures (`ACCEPT = 8192`).
   - Added explicit packet truncation detection (`n - off < ip_total_len`). When a truncated packet arrives, `is_truncated = true` increments `g_invalid_frames`, marks the flow broken (`is_broken = true`), invalidates correlation (`invalidate_connection_correlation`), and flushes pending requests with null status rather than attempting partial corrupt reassembly.

### Test Results After Round 7 Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **66/66 PASS** (Tests 1–33, both engines) |
| `./nt-sniff-cpp --lockout-fixture` | **PASS** (10k bounded registry + all 4 sequence reproductions) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,204 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 8 EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |
| `sh build-firstrun.sh` | **367,205 bytes** bundle rebuilt |

## Security Hardening & Correctness Round 6 — Privilege Drop, RLIMIT_AS Enforcement & IPv4 Fragment Rejection (2026-09-10)

Three critical production hardening and correctness issues resolved across both C++ and Python engines:

1. **Complete Privilege Drop from Root (`drop_all_capabilities` / `drop_capture_capabilities`)**:
   - If the binary is launched as root (UID 0 / EUID 0), it now explicitly drops privileges after socket creation and ring setup:
     1. Clears auxiliary groups with `setgroups(0, NULL)`.
     2. Looks up target non-login user (`NT_USER`, default `ntsniff`, fallback `nobody`).
     3. Drops group ID with `setgid(pw->pw_gid)`.
     4. Drops user ID with `setuid(pw->pw_uid)`.
     5. Irreversibly zeroes all capabilities using `capset(all-zero)`.
     6. Validates `getuid() != 0 && geteuid() != 0`.
   - Prevents child processes (such as curl in popen shipping mode) from ever executing as root.
   - For non-root invocations, preserves rootless operation with file capabilities (`CAP_NET_RAW`) and zeroes capabilities immediately after socket initialization.

2. **Real Enforced 256 MiB Virtual Memory Bound (`RLIMIT_AS`)**:
   - Enforced `setrlimit(RLIMIT_AS, &lim)` (256 MiB ceiling) in `main()` of `nt-sniff-cpp.cpp`, `nt-ship-cpp.cpp`, `nt-sniff.py`, and `nt-ship.py`.
   - Automatically adapts to existing lower limits (`rlim_max < 256 MiB`) without failing EPERM.
   - Portable preprocessor check (`#ifndef NT_HAS_ASAN`) avoids conflict with AddressSanitizer's multi-terabyte shadow memory mapping during edge testing.
   - The advertised `"address_space_bytes": 268435456` in agent telemetry is now backed by a hard kernel limit on the process itself.

3. **Reject First IPv4 Fragment (MF Flag, Test 30)**:
   - Updated fragment check from `frag & 0x1fff` (which only rejected non-zero offsets) to `frag & 0x3fff` (which rejects both `MF == 1` and non-zero offsets while preserving `DF == 1`).
   - Because the sniffer does not perform IP defragmentation, accepting the first fragment could lead to truncated or corrupted TCP payload analysis. Rejecting all fragmented packets ensures parser correctness.

### Test Results After Round 6 Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **26/26 PASS** |
| `python3 test_synthetic_harness.py` | **60/60 PASS** (Tests 1–30, both engines) |
| `./nt-sniff-cpp --lockout-fixture` | **PASS** (10k bounded registry + all 4 sequence reproductions) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,204 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 8 EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |
| `sh build-firstrun.sh` | **362,119 bytes** bundle rebuilt |

## Capture & Parser Hardening Round 5 — Unified Flow Reset & Expired HEAD Semantics (2026-09-09)

Two critical edge cases resolved in both `nt-sniff-cpp.cpp` and `nt-sniff.py`:

1. **Unified Flow Reset on Client SYN (`reset_for_new_connection`, Test 28)**:
   - Addressed reproduction where an invalid request framing broke a flow (`fl.is_broken = true`), and subsequent client SYN started a new connection generation without clearing `is_broken`.
   - Unified connection initialization across both directions (`fl` and `resp_fl`) and server SYN into a single complete reset routine (`Flow::reset_for_new_connection`). This guarantees `is_broken = false`, resets HTTP framing state, clears sequence tracking, and resets correlation eligibility without leaving any fields stale.
   - Subsequent valid requests and responses on the new connection correlate properly with status 200.

2. **Expired HEAD Bodyless-Response Semantics (Test 29)**:
   - Addressed reproduction where an expired HEAD request became a tombstone, and upon delivery of the late response, `is_head` was not checked because the tombstone was consumed in the tombstone branch before checking `e.method == "HEAD"`.
   - The sniffer fell back to non-HEAD response parsing, and with `Content-Length: X` present in the response headers, entered `HTTP_STATE_BODY`, consuming the subsequent GET response as HEAD body bytes.
   - Fixed by inspecting `p->second[0].ev.method == "HEAD"` (or Python equivalent `ev.get("method") == "HEAD"`) *before* checking or discarding its tombstone. A late HEAD response remains strictly bodyless regardless of `Content-Length`.

### Test Results After Round 5 Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **24/24 PASS** |
| `python3 test_synthetic_harness.py` | **58/58 PASS** (Tests 1–29, both engines) |
| `./nt-sniff-cpp --lockout-fixture` | **PASS** (10k bounded registry + all 4 sequence reproductions) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,204 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL 8 EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |
| `sh build-firstrun.sh` | **357,093 bytes** bundle rebuilt |

## Capture & Parser Hardening Round 4 — Generation-Scoped Eligibility & SYN-ACK Verification (2026-09-09)

Two critical edge cases resolved in both `nt-sniff-cpp.cpp` and `nt-sniff.py`:

1. **Generation-Scoped Correlation Eligibility (Test 26)**: Addressed reproduction where an old SYN bypassed an evicted lockout. A connection that loses ordering now has `corr_eligible` latched to `false` for that generation across both flow directions (`FlowKey` and reverse key). Even when the 4-tuple is evicted from `g_corr_disabled` due to 2,048+ other connections timing out, the connection remains ineligible for response correlation. Requests emit immediately with null status; late responses do not correlate. Only a fresh TCP connection (client SYN) resets sequence state and restores correlation eligibility.

2. **SYN-ACK Verification Preservation (Test 27)**: Addressed reproduction where server SYN-ACK wiped verification under capacity fallback. When processing server SYN-ACK (`flags & 0x02` from server in Direction A), `rfl.generation`, `rfl.syn_seen`, and `rfl.corr_eligible` are now preserved from the client SYN rather than reset with a blank `Flow()`. When capacity fallback is active, legitimate request/response pairs correlate properly with status 200.

### Test Results After Round 4 Fixes

| Suite | Result |
|---|---|
| `pytest test_nt_sniff.py` | **22/22 PASS** |
| `python3 test_synthetic_harness.py` | **54/54 PASS** (Tests 1–27, both engines) |
| `./nt-sniff-cpp --lockout-fixture` | **PASS** (10k bounded registry + packet sequence reproductions) |
| `python3 test_pcap_suite.py` | PCAP 247: 109 events ✓; PCAP 249: 6,204/6,204 events ✓ |
| `python3 cpp-edge-test.py` (ASAN/UBSAN) | **ALL EDGE TESTS PASS** |
| `make clean && make all && make fixture` | **PASS** (0 warnings) |
| `sh build-firstrun.sh` | **355,327 bytes** bundle rebuilt |




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

## Python Engine Performance & Hot-Path Parser Optimization (2026-09-10) — Round 11
- **Elimination of $O(N)$ Active Flow Scans**:
  - Replaced per-request linear scans over `flows.values()` with $O(1)$ tracked `g_wsse_active_flows` via `@awaiting_wsse.setter` and `@body_goal.setter` in `Flow`, eliminating >200ms of CPU overhead.
  - Automatically handles lifecycle cleanups, flow resets, and garbage collection via `__del__`.
- **Fast-Path XML Early Termination & Checkpoint Parsing**:
  - Fast substring check `b"UsernameToken" not in body` bypasses Expat XML parser initialization for non-WSSE payloads.
  - Guarded DTD/entity inspection with `if b"<!" in body:`, preventing full body bytearray copying and lowercasing.
  - Checkpointed XML parsing in `handle_payload` (evaluating only at goal, body end, or 512B growth).
  - Immediate parser termination via `_UsernameFound` exception upon closing `<wsse:Username>` tag, avoiding parsing thousands of trailing SOAP body elements.
  - ASCII fast path in `normalize_wsse_username` bypasses `unicodedata.normalize` and category checks for printable ASCII (32..126).
- **Zero-Copy Packet Unpacking & Port Filtering**:
  - Replaced slice-based `struct.unpack` with pre-compiled `struct.Struct.unpack_from` (`_STRUCT_B`, `_STRUCT_H`, `_STRUCT_HH`, `_STRUCT_I`).
  - Evaluated `sport in ports` and `dport in ports` before IP total length, data offset, sequence number, and IP string conversions.
  - Cached IP string conversions via `_fast_inet_ntoa` (bounded 4,096-entry cache), eliminating >298,000 `inet_ntoa` conversions on PCAP 249.
  - Reused `sport_mon` and `dport_mon` booleans in `process_packet` to eliminate redundant hash lookups.
  - Inlined `1 <= port <= 65535` range check in `handle_payload`, eliminating 161,470 `valid_port()` function calls and try/except blocks.
- **Header Parsing Streamlining**:
  - Avoided intermediate `replace(b"\r\n", b"\n")` string copies, splitting directly on `\r\n`.
  - Filtered header lines by initial character before lowercasing, extracting only the 8 required headers (`content-length`, `transfer-encoding`, `content-type`, `authorization`, `traceparent`, `host`, `user-agent`, `x-forwarded-for`).
  - Pre-checked HTTP method prefix at index 0 against `METHODS_BYTES` set to avoid calling `find_http_start` on standard requests.
- **Syscall & Periodic Task Batching**:
  - Gated `emit_capture_stats()` and remote control polling to run every 256 packets or on `socket.timeout`, removing redundant `time.time()` syscalls from the hot packet ingestion loop.
## Shipping Queue Capacity Increase & Hardening (2026-09-10) — Round 19
- **Event Queue Capacity Increased to 10,000**:
  - `nt-sniff-cpp.cpp`: updated `MAX_QUEUE = 10000;`. Telemetry and internal buffer limits export 10,000 event capacity.
  - `nt-ship-cpp.cpp`: updated `MAX_QUEUE = 10000;`, `MAX_QUEUE_EVENTS = 10000;`, and scaled `MAX_QUEUE_BYTES = 20U * 1024U * 1024U;` (20 MiB ceiling).
  - Maintains strict memory safety well within the 256 MiB `RLIMIT_AS` boundary enforced by `nt-resource-guard.sh`.
- **Test Suite Updates**:
  - `test_resource_guard.py`: updated assertions for `MAX_QUEUE` (10,000) and 16 KiB frame ring geometry (`frame_size = 16384, frame_nr = 256`).
- **Comprehensive Verification**:
  - `pytest test_resource_guard.py`: **16/16 PASS** (100%).
  - `python3 cpp-edge-test.py`: **ALL 10 EDGE TESTS PASS** under ASAN & UBSAN.
  - `python3 test_synthetic_harness.py`: **124/124 PASS** across C++ and Python engines.
  - `pytest test_nt_sniff.py`: **26/26 PASS**.
  - `python3 test_pcap_suite.py`: PCAP 247: 109 events; PCAP 249: 6,216 events (C++) / 6,077 events (Python).
  - Self-contained installer bundle: `sh build-firstrun.sh` generated `install-firstrun-el68.sh` (453,527 bytes, preflight OK).
  - Production service cleanly installed and running rootless (`ntsniff`) under SysV supervisor on `enp0s6:18080`.

## Zero-Third-Party POSIX HTTP Shipper Engine (2026-09-10) — Round 20
- **Elimination of All External Third-Party Library Dependencies**:
  - Replaced `libcurl` and `zlib` in `nt-ship-cpp.cpp` with pure POSIX socket networking (`sys/socket.h`, `netdb.h`, `poll()`).
  - Removed `-lcurl` and `-lz` link flags from `Makefile`, `install-oldkernel.sh`, and `cpp-edge-test.py`.
  - The entire C++03 agent pipeline now links solely against standard glibc (`-pthread -lrt`), eliminating all target host package requirements for `libcurl-devel` or `zlib-devel`.
- **POSIX HTTP/1.1 Engine Features**:
  - HTTP/1.1 persistent connection reuse across event batches using nonblocking sockets (`O_NONBLOCK`).
  - Strict response parsing supporting `Content-Length`, `Transfer-Encoding: chunked`, `Connection: close`, and unframed EOF termination.
  - Multi-connection pipelining supporting up to 4 concurrent in-flight connections (`--max-inflight 1..4`, default 2).
  - `TokenBucket` upload rate limiting implementing configured `--ship-rate-kbps` ceiling.
  - Exponential retry backoff with deterministic jitter for transient 408/429/5xx status codes.
  - Strict agent statistics protocol v1 compliance (`schema_version: 1`, `mode: "cpp"`), fully verified and accepted by live Hub validator (`accepted: true`).
- **Verification Results**:
  - `pytest test_resource_guard.py`: **16/16 PASS** (100%).
  - `python3 cpp-edge-test.py`: **ALL 10 EDGE TESTS PASS** under ASAN & UBSAN (zero memory leaks, zero sanitizer errors).
  - `python3 test_synthetic_harness.py`: **124/124 PASS** across C++ and Python engines.
  - `pytest test_nt_sniff.py`: **26/26 PASS**.
  - `python3 test_pcap_suite.py`: PCAP 247: 109 events; PCAP 249: 6,216 events (C++) / 6,077 events (Python).
  - First-run bundle: `sh build-firstrun.sh` generated `install-firstrun-el68.sh` (472,641 bytes, preflight OK).
  - Live daemon: Reinstalled and running rootless under `ntsniff` on `enp0s6:18080`.

## Python Engine Stability-Hardening Plan (2026-09-11) — Round 21
- **Architectural Directive**: Strict retention of existing capture architecture (`AF_PACKET + classic BPF + recv() + 1 worker`). No throughput optimization, packet ring introduction, or TPACKET/mmap capture until all stability, memory, and safety invariants pass.
- **Central Safety Invariant**: When stream ordering becomes uncertain, discard reconstruction state and emit only already-observed request events with null response enrichment (`status: None, duration_ms: None, resp_bytes: None`).
- **Core Components Designed**:
  - `quarantine_connection`: Unified teardown of untrusted streams, releasing all reassembly, OOO, and WSSE buffers to zero and entering `HTTP_STATE_UNSYNCED`.
  - `HTTP_STATE_UNSYNCED`: Pure non-buffering state inspecting only arriving packets for request boundaries without response correlation.
  - `MAX_TRACKED_HALF_FLOWS = 8192`: Global capacity enforced on every creation path via `get_or_create_request_flow` and `get_or_create_response_flow`.
  - `collections.deque` flow FIFOs: Deterministic O(1) eviction replacing unsafe `dict.popitem()` on Python 2.6.
  - `BufferBudget` & `MAX_OOO_BYTES = 16384`: Explicit byte accounting across all buffers and strict unique byte tracking with conflicting retransmission quarantine.
  - `PendingRequest` with `__slots__`: Replacing positional lists, bounded globally by `MAX_PENDING_EVENTS = 16384`.
  - Symmetrical response header limits (`MAX_HDRS`), framing ceilings (`MAX_HTTP_BODY_FRAMING = 64 MiB`).
  - Fail-closed `RLIMIT_AS` (256 MiB), controlled fatal `MemoryError` exit (code 71), narrow malformed packet boundaries, and capability verification (`verify_dropped_capabilities` via `/proc/self/status`).
  - Full plan specification: documented in [`python_stability_hardening_plan.md`](file:///home/ubuntu/.gemini/antigravity-cli/brain/02fb42a7-1c94-4b4c-8a38-944410d78ed6/python_stability_hardening_plan.md).

## Python Shipper Stability-Hardening & Transport Optimization (`nt-ship.py`) (2026-09-11) — Round 22
- **Zero AF_PACKET Pure User-Space Stdin Client**: Shipper retains strictly bounded stdin pipe ingestion and TCP HTTP client POST architecture.
- **Fail-Closed RLIMIT_AS Verification (256 MiB)**: `enforce_rlimit_as()` queries, clamps, enforces, and reads back `RLIMIT_AS`. Fails closed with code 70 and stderr fatal diagnostic if soft limit cannot be enforced.
- **Hard Line Size Cap (64 KiB)**: Replaced unbounded line reading with `sys.stdin.readline(65537)`. Un-terminated records exceeding 64 KiB are drained in 4096-byte chunks until newline and dropped as `oversized` without RSS inflation.
- **Dual Buffer Bounds (4000 events, 8 MiB)**: `buf` uses `collections.deque` with tracked `buf_bytes`. Automatically drops oldest elements from the front when either `len(buf) >= 4000` or `buf_bytes + new_bytes > 8 MiB`.
- **Single-Serialization Batch Pipeline**: Incoming lines are verified once with `json.loads()`; compact raw JSON strings are stored directly. `build_batch` constructs wire JSON via string concatenation (`'{"node":' + node_json + ',"events":[' + ','.join(events) + ']}'`), eliminating Python dictionary creation and double serialization.
- **Pre-Built Batch Objects**: Fully constructed `Batch` instances (`body`, `event_count`, `batch_id`, `attempts`, `created_at`) are queued to poster threads. Poster threads perform zero JSON encoding.
- **Persistent HTTP/1.1 Connections (`httplib.HTTPConnection`)**: Per-thread persistent `HTTPConnection` reused across batches. Reconnects on errors, timeouts, or `Connection: close`.
- **Guaranteed Task Done & Error Containment**: Poster thread item processing wrapped in `try ... finally: q.task_done()`, eliminating `q.join()` deadlock risks. Narrow exception catching for network/socket errors. Explicit `except MemoryError` terminates process with exit code 71 for clean supervisor restart.
- **Stable `X-Batch-Id` & Bounded Retry**: Emits `X-Batch-Id: <instance_id>-<seq>`. Up to 3 attempts with exponential backoff (0.5s..5s) and 60s age cap for transient 408/429/5xx and socket errors. Permanent 4xx errors are dropped immediately without retry. Accepts all 2xx statuses (200..299).
- **Clean Transition Logging**: Removed per-batch success spam. Outage mode logs on first failure, suppresses per-request spam, emits periodic summaries every 30s, and logs recovery upon reconnection.
- **Verification Results**:
  - `pytest test_nt_ship.py`: **15/15 PASS** (100%, covering input line bounding, unterminated drain, dual buffer bounds, fail-closed rlimit, keep-alive connection reuse, stable batch IDs, transient retries, permanent 4xx drop, 204 acceptance, and live Hub ingestion).
  - `pytest test_resource_guard.py`: **16/16 PASS**.
  - `python3 cpp-edge-test.py`: **ALL 10 EDGE TESTS PASS** (ASAN/UBSAN 0 errors).
  - `pytest test_nt_sniff.py`: **26/26 PASS**.
  - `python3 test_pcap_suite.py`: PCAP 247: 109 events; PCAP 249: 6,216 events (C++) / 6,077 events (Python).
  - First-run bundle: `sh build-firstrun.sh` generated `install-firstrun-el68.sh` (743,981 bytes, preflight OK against live Hub).

## Round 24 — Hybrid Pipeline Mode (`nt-sniff.py | nt-ship-cpp`) (2026-09-11)
- **Architecture**: Supports hybrid capture pipeline (`--mode hybrid` or `--mode py-cpp`) coupling the pure Python 2.6 sniffer (`nt-sniff.py`) with the zero-third-party C++03 HTTP shipper (`nt-ship-cpp`).
- **Pipeline Interoperability**:
  - Event Stream: Standard single-line JSONL events emitted to stdout by `nt-sniff.py` and ingested via stdin by `nt-ship-cpp`.
  - In-Band Telemetry: `{"_nt_internal":"capture_stats_v1", "capture": {...}}` envelopes recognized by `nt-ship-cpp`, extracted verbatim, and merged into the agent stats payload sent to `/api/agent/stats`.
  - Process Coupling: Closed stdout / broken pipe exits with code 74 to trigger supervised restart of the complete pipeline under `nt-supervise.sh`.
- **Packaging & Deployment**:
  - `install-oldkernel.sh` supports `--mode hybrid` / `--mode py-cpp`, enforcing `g++` and Python 2.6+ node requirements, compiling `nt-ship-cpp`, configuring `python-capnetraw` with `cap_net_raw+ep`, and running `nt-ship-cpp` unprivileged under `ntsniff`.
  - `nt-run-hybrid.sh` provides a standalone runner script.
  - `build-firstrun.sh` packages `nt-run-hybrid.sh` into `install-firstrun-el68.sh` (743,981 bytes).
- **Live Machine Verification Results**:
  - Service Installation: Installed daemon via `sudo sh install-oldkernel.sh --mode hybrid --endpoint http://129.150.59.233:30102 --iface enp0s6 --ports 18080 --wsse-bytes 16384`.
  - Process Inspection: Running rootless as `ntsniff`, CPU affinity pinned to CPU 0, SCHED_IDLE at nice 19, CapEff 0 (`python-capnetraw` dropped capabilities after bind; `nt-ship-cpp` unprivileged).
  - Memory Footprint: Python sniffer RSS ~24 MiB; C++ shipper RSS ~2.8 MiB, total < 30 MiB (far below 256 MiB `RLIMIT_AS`).
  - End-to-End Live Capture (`test_hybrid_e2e.py`):
    * Basic Auth GET: correlated with status 200, user `alice`, W3C trace ID parsed, 0 secrets leaked.
    * WSSE SOAP POST: correlated with status 200, user `bob_soap`, 0 passwords leaked.
    * Ingestion: Forwarded batches received and acknowledged by mock Hub `/api/ingest`.
    * Agent Telemetry: In-band `capture_stats_v1` captured, parsed, and posted to `/api/agent/stats` with full capture, shipping, and resource metrics.
    * Pipe Closure Recovery: Exit code 74 validated when shipper pipe closes.

## Round 25 — Ansible Fleet Deployment Automation (Approach A) (2026-09-11)
- **Architecture**:
  - Implemented Approach A: Ansible controller packages and stages the tested self-contained bundle `install-firstrun-el68.sh` via `ansible/stage-bundle.sh`.
  - Avoids glibc version mismatches by not compiling on the controller; nodes compile on-host via local `g++` or execute under pure Python 2.6 stdlib.
- **Directory Layout & Roles**:
  - `ansible/ansible.cfg`: Pipelining enabled, roles path configured, standard stdout callback.
  - `ansible/inventory/hosts.ini`: Inventory with `legacy_capture` group and `local_test` localhost target.
  - `ansible/group_vars/legacy_capture.yml`: Central configuration parameters (`nt_hub_url`, `nt_capture_iface`, `nt_capture_ports`, `nt_capture_mode`, `nt_wsse_bytes`, `nt_ship_rate_kbps`, `nt_stats_interval_sec`).
  - `ansible/roles/networktracing_legacy/tasks/main.yml`:
    * Copies tested bundle to `/var/tmp/install-firstrun-el68.sh`.
    * Computes desired configuration hash.
    * Inspects deployed stamp `/etc/networktracing-legacy.deploy` and service status.
    * Runs preflight check (`--check`) before mutation.
    * Installs with `--offline` and enforces fail-closed safeguards.
    * Stamps configuration and validates active running daemon.
  - `ansible/deploy-networktracing.yml`: Main rolling playbook with `serial: 10%` and `max_fail_percentage: 10`.
  - `ansible/verify-networktracing.yml`: Read-only health audit playbook checking SysV status, process list, CPU affinity, and RSS.
  - `ansible/uninstall-networktracing.yml`: Fleet-wide service uninstallation and cleanup.
  - `ansible/stage-bundle.sh`: Helper script to build and stage the installer bundle.
  - `ansible/README.md`: Operator runbook.
- **Verification Results**:
  - Syntax check: **PASS** across all 3 playbooks.
  - Local test deployment: **PASS** (`ok=11 changed=4 failed=0`).
  - Idempotency re-run: **PASS** (`ok=8 changed=0 skipped=3`).
  - Health audit: **PASS** (`ok=4 changed=0`).




