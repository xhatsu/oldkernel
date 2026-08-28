# AGENTS.md — NetworkTracing Oldkernel Architecture & Operational Guide

## Overview & Context
This repository contains the **NetworkTracing legacy capture kit** for CentOS 6.x / Linux kernel 2.6.32+ nodes where modern eBPF tools cannot run (no eBPF, no systemd, Python 2.6 stdlib only, or native C++03).

### Key Components
- **`nt-sniff.py`**: AF_PACKET raw packet sniffer with classic BPF filter (`SO_ATTACH_FILTER`), TCP flow reassembly, HTTP/1.x header parsing, Basic auth extraction, W3C traceparent generation/parsing, and response correlation.
- **`nt-ship.py`**: Multi-threaded JSONL event shipper with disk spooling and backoff retries to Hub `/api/ingest`.
- **`nt_control.py` / `nt-control.py`**: Python 2.6-compatible remote control client supporting atomic desired state application (`remote-desired.json`), heartbeat reporting, and port reconfiguration.
- **`nt-sniff-cpp.cpp` / `nt-ship-cpp.cpp`**: High-performance C++03 replacement sniffer and shipper for >1000 rps environments.
- **`install-oldkernel.sh`**: SysV installer script supporting `--check`, `--install`, and `--uninstall`. Manages rootless `ntsniff` user with `cap_net_raw` file capabilities.
- **`build-firstrun.sh`**: Bundle generator creating `install-firstrun-el68.sh` with embedded base64 payloads of all kit components.
- **`install-firstrun-el68.sh`**: Self-contained single-file installer suitable for `curl | sh` bootstrap.

## Operational Rules & User Directives
1. **Shell Compatibility**: Standard POSIX `sh` (Bourne shell) strictly. No bashisms (`[[ ]]`, `local`, `declare`, `array[i]`, `&>`, etc.).
2. **Kubernetes Restrictions**: NEVER execute Kubernetes `kubectl` commands.
3. **Command Execution Safeguard**: Set execution timers to detect and retry frozen commands.
4. **Testing Mandate**: Always run test suites and fixtures before concluding tasks.
5. **State Tracking**: Maintain `AGENTS.md` and `STATE.md` with project state and architecture memory.
