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
  - `sh oldkernel/build-firstrun.sh`: bundle successfully built (122,291 bytes) with pure in-memory zero-disk-write single-binary agent mode (`nt-sniff-cpp --endpoint URL`), PACKET_MMAP (TPACKET_V2) zero-copy ring buffer, dual-path 802.1Q cBPF (BPF_LDX + correct jump offsets), 11x faster single-pass SIMD HTTP parser, binary 12-byte FlowKey, bounded RAM queue (`MAX_QUEUE=4000`), zero disk I/O, zero `/tmp` files, and graceful in-memory event drop during Hub outages.
  - `sh bootstrap/package-oldkernel.sh`: verified extraction comparison against source files (BOOTSTRAP-PACKAGE PASS, bundle: 36,987,722 bytes).
  - Single-Binary Pure In-Memory Architecture: When `--endpoint` is passed, `nt-sniff-cpp` captures packets, parses HTTP in SIMD zero-copy mode, buffers events in an in-memory queue (bounded to 4000 items / ~1.2MB RAM), and delivers 400-event batches directly to Hub `/api/ingest`. When Hub connection is lost or down, batches are dropped in RAM with 0 disk touches, 0 tmp files, and 0 disk I/O, resuming streaming instantly when Hub connectivity returns.
  - Native `uninstall` action in service script features 3s SIGKILL escalation.
  - Cleaned up stuck background tasks and verified instantaneous uninstall/reinstall cycles.
  - `make -C agent test bundle`: Go agent binaries (`aarch64`, `x86_64`) built from source and packaged into `bootstrap/bundle.tar.gz` (36,987,722 bytes).
  - Modern Go agent (`networktracing.service`) installed via one-line bootstrap command and actively capturing live L7 traffic on VM. Fixed `kyanos-http` response status parsing (extracts 200, 404, 500 status codes, duration_ms, and req/resp byte sizes).
  - Synchronized `README.md` and `bundle/README.md` with explicit One-Line Fast Install & Uninstall commands for modern eBPF and legacy nodes.
  - Bootstrap distribution server active on port 30105 (`/healthz`).
  - Central Hub Control Plane active on port 31115 (`/healthz`, `/api/nodes`, `/api/control/snapshot`).

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
- Runbook & verification: `CENTOS-6.7-TEST.md`, `el68-smoke.sh`, `verify-centos-runbook.sh`, `nt-test.sh` (`nt-test.py`).
- C++ build & fixture: `make all`, `make fixture`.
