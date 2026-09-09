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

## Capture & Parser Hardening State (2026-09-09)
- **TCP Stream Reassembly**: Modular sequence-difference arithmetic (`seq_diff`), duplicate segment suppression, retransmission overlap trimming, and bounded out-of-order segment queues (up to 4 segments / 16 KiB per flow) implemented in both C++ (`nt-sniff-cpp.cpp`) and Python (`nt-sniff.py`).
- **HTTP Request & Response Framing**: Explicit state machines (`HTTP_STATE_HEADER`, `HTTP_STATE_BODY`, `HTTP_STATE_CHUNK`, `HTTP_STATE_CLOSE_BODY`) on both request and response paths. Eliminates body scanning for fake status lines, parses chunk extensions/trailers, respects HEAD request bodyless responses (RFC 7230 §3.3.3), and drops desynchronizing requests with conflicting Content-Length + chunked encoding.
- **Symmetrical Memory Accounting**: Symmetrical tracking via `flow_bytes_add()` and `flow_bytes_sub()` across all buffers (`buf`, `wsse_buf`, `ooo`) against `MAX_TOTAL_BUFFER_BYTES` (16 MiB) and `MAX_FLOW_BUFFER_BYTES` (64 KiB). Flow creation triggers oldest flow eviction.
- **Pending FIFO Leak Remediation**: Monotonic `req_id` and generation tracking per pending request; lazy reconciliation in `g_pending_fifo` prevents stale request leaks and avoids corrupting queue order.
- **Keep-Alive Timing Precision**: Request start timestamp reset at request boundaries (`first_byte_mono_ms` reset on `HTTP_STATE_HEADER`), avoiding latency inflation across idle gaps.
- **Connection Generations**: Client SYN increments flow generation, purges stale pending requests for that 4-tuple, and cleans up stale response flows, preventing cross-connection correlation errors.
- **Shipping Concurrency**: Thread-safe asynchronous stats upload via `g_pending_stats_body` and worker thread; `signal(SIGPIPE, SIG_IGN)` and mutex guards prevent capture stalls and race conditions.
- **Informational Response Handling**: Server response reassembly ignores `100 Continue`, `102 Processing`, and `103 Early Hints`, keeping requests pending until final status (>= 200 or 101) arrives.
- **Incomplete SOAP Preservation**: Incomplete WSSE requests without Basic auth fallback are safely emitted upon stream close or timeout instead of being discarded.
- **Dual-Engine Synthetic Regression Suite (`test_synthetic_harness.py`)**: 32/32 PASS across both C++ and Python engines covering 16 distinct edge cases.
- **PCAP Verification Parity**: Offline PCAP 247 yields 109 events with 100% traceparent correlation, duration 112ms, and status 200 in both Python and C++; PCAP 249 yields 6,204 events in both Python and C++ with exact username, scheme, and status parity.

