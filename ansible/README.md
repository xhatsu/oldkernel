# NetworkTracing Legacy Capture — Ansible Fleet Deployment

This directory contains the complete, production-ready Ansible automation for deploying the NetworkTracing legacy capture agent to CentOS 6.x / Linux 2.6.32+ nodes using **Approach A** (controller-staged self-contained bundle with on-host compilation or pure Python execution).

## Architecture & Principles
1. **Controller Artifact Purity**: The Ansible controller runs `stage-bundle.sh` to package all agent components into `install-firstrun-el68.sh`. The controller does **not** compile binaries directly, avoiding glibc version mismatches.
2. **Deterministic Target Installation**: The bundle is copied to `/var/tmp/install-firstrun-el68.sh` and executed with `--offline`. Nodes with `g++` compile locally against their native glibc 2.12; nodes without a compiler run in `--mode python`.
3. **Idempotence & Safety**: The role maintains an explicit desired-configuration manifest at `/etc/networktracing-legacy.deploy`. Re-running the playbook is a no-op unless the bundle checksum, variables, or service health change.
4. **Preflight Guard**: Runs `--check` on each target host to verify network routes, taskset/CPU affinity, and Hub connectivity before taking any destructive action.
5. **Rolling Containment**: Defaults to `serial: "10%"` and `max_fail_percentage: 10` to protect the capture fleet and Hub from rollout spikes.

## Directory Structure
```text
ansible/
├── ansible.cfg                          # Global Ansible defaults (pipelining, roles_path)
├── inventory/
│   └── hosts.ini                        # Target fleet inventory
├── group_vars/
│   └── legacy_capture.yml               # Fleet configuration (Hub URL, iface, ports, mode)
├── roles/
│   └── networktracing_legacy/
│       ├── files/
│       │   ├── .gitkeep                 # Keeps files/ directory in git tracking
│       │   └── install-firstrun-el68.sh # Generated bundle (git-ignored, staged via stage-bundle.sh)
│       └── tasks/
│           └── main.yml                 # Safe, idempotent deployment tasks
├── deploy-networktracing.yml            # Main rollout playbook
├── verify-networktracing.yml            # Health audit playbook
├── uninstall-networktracing.yml         # Clean fleet uninstallation
└── stage-bundle.sh                      # Helper script to build & refresh staged bundle
```

> [!IMPORTANT]
> **Build Artifact Policy**: `ansible/roles/networktracing_legacy/files/install-firstrun-el68.sh` is a **generated build artifact and is NOT tracked in git by default**. You **must** build and stage it on the Ansible control machine before executing any Ansible deployment playbooks.

## Quick Start Runbook

### Step 1: Build and Stage the Bundle (Required Prerequisite)
Before running any Ansible playbook, generate and stage the self-contained installer bundle:

```sh
# Option A: From inside the ansible/ directory
cd ansible
sh stage-bundle.sh

# Option B: From the repository root
sh ansible/stage-bundle.sh
```

**What `stage-bundle.sh` does:**
1. Runs `build-firstrun.sh` at the repository root to package all agent scripts, C++ sources, and prebuilt EL6 native binaries (from `bin/el68-x86_64/` if present) into `install-firstrun-el68.sh`.
2. Automatically copies the built artifact to `roles/networktracing_legacy/files/install-firstrun-el68.sh`.
3. Sets secure permissions (`chmod 750`) and outputs the staged file size and SHA-256 checksum for audit and verification.

Verify the staged bundle:
```sh
ls -lh roles/networktracing_legacy/files/install-firstrun-el68.sh
sha256sum roles/networktracing_legacy/files/install-firstrun-el68.sh
```

### Step 2: Configure Inventory & Variables
Edit `inventory/hosts.ini` with your target hostnames/IPs:
```ini
[legacy_capture]
app01.prod.example ansible_host=10.240.147.201 nt_capture_iface=eth0
app02.prod.example ansible_host=10.240.147.202 nt_capture_iface=eth0
```

Edit `group_vars/legacy_capture.yml` for fleet-wide settings:
- `nt_hub_url`: Ingest endpoint URL (e.g., `http://129.150.59.233:30102`)
- `nt_capture_ports`: Monitored TCP ports (e.g., `80,8080,18080`)
- `nt_capture_mode`: `hybrid` (recommended), `cpp`, or `python`

### Step 3: Test Single Node First
```sh
ansible-playbook -i inventory/hosts.ini deploy-networktracing.yml --limit app01.prod.example
```

### Step 4: Execute Fleet Rollout
```sh
ansible-playbook -i inventory/hosts.ini deploy-networktracing.yml
```

### Step 5: Audit Fleet Status
```sh
ansible-playbook -i inventory/hosts.ini verify-networktracing.yml
```

### Step 6: Uninstall Fleet (if needed)
```sh
ansible-playbook -i inventory/hosts.ini uninstall-networktracing.yml
```
