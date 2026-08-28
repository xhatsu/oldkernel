# STATE.md — Current Project State & Memory

## Current State Summary
- **Git Branch**: `main`, up to date with `origin/main` (latest commit `c6d8781 update test scripts`).
- **Conflict Resolution**: Successfully resolved binary merge conflict in `nt-sniff-cpp`, rebuilt native binaries via `make clean && make`, and regenerated `install-firstrun-el68.sh`.
- **Integrated Features**:
  - Remote control capabilities (`nt_control.py`, `nt-control.py`, `test_nt_control.py`).
  - Remote upstream updates: Test scripts (`nt-test.py`, `nt-test.sh`), unbuffered Python stdout (`-u`), `ETH_P_ALL` capture socket binding, response parsing prioritization, C++ command argument handling and curl stdin pipe fixes.
- **Verification & Test Status**:
  - `pytest test_nt_control.py`: 4/4 tests PASS.
  - `python3 cpp-edge-test.py`: ASAN fixture PASS (contract fields: 24).
  - `make clean && make all && make fixture`: PASS.
  - `python3 -m py_compile`: nt-sniff.py, nt-ship.py, nt-control.py, nt_control.py, nt-test.py compiled cleanly.
  - `sh ./build-firstrun.sh`: bundle successfully built (110,020 bytes) with permanent installer copying to `/opt/networktracing-legacy/install-oldkernel.sh` and zero-blocking instant exits.
  - Added native `uninstall` action to `/etc/init.d/networktracing-legacy` service script (exits in < 1s).
  - Cleaned up stuck background tasks and verified instantaneous uninstall/reinstall cycles.
  - `make -C agent test bundle`: Go agent binaries (`aarch64`, `x86_64`) built from source and packaged into `bootstrap/bundle.tar.gz` (36,988,011 bytes).
  - Modern Go agent (`networktracing.service`) installed via one-line bootstrap command and actively capturing live L7 traffic on VM. Fixed `kyanos-http` response status parsing (extracts 200, 404, 500 status codes, duration_ms, and req/resp byte sizes).
  - Bootstrap distribution server active on port 30105 (`/healthz`).
  - Central Hub Control Plane active on port 31115 (`/healthz`, `/api/nodes`, `/api/control/snapshot`).

## Accessible Artifacts & Commands
- Single file installer build: `sh build-firstrun.sh` -> outputs `install-firstrun-el68.sh`.
- Runbook & verification: `CENTOS-6.7-TEST.md`, `el68-smoke.sh`, `verify-centos-runbook.sh`, `nt-test.sh` (`nt-test.py`).
- C++ build & fixture: `make all`, `make fixture`.
