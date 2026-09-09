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
