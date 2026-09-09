# Stable Ansible Deployment

For mass deployment, let Ansible distribute the self-contained installer.
Managed nodes do not need access to a bootstrap server and should use
`--offline` so every node installs exactly the artifact tested by the operator.

The Hub itself is still required for the install-time ingest handshake and for
runtime event delivery. Its URL is explicit and may use any HTTP(S) port:

```text
--server https://trace.internal.example:9443
```

The installer never derives an ingest or kit port.

## 1. Build and stage one artifact

On the build/controller machine:

```sh
sh build-firstrun.sh
sha256sum install-firstrun-el68.sh
```

Store `install-firstrun-el68.sh` under the Ansible role's `files/` directory
and record its checksum in the release process. Do not rebuild the file during
a rollout.

## 2. Inventory variables

Keep the exact ingest URL in inventory. Interface and CPU values may differ by
host:

```yaml
# group_vars/legacy_capture.yml
nt_agent_version: "2026-09-09-1"
nt_hub_url: "https://trace.internal.example:9443"
nt_capture_iface: "eth0"
nt_capture_ports: "80,8001,8003,8080"
nt_capture_mode: "cpp"
nt_wsse_bytes: "16384"
nt_ship_threads: "4"
nt_ship_rate_kbps: "1024"
```

Do not put secrets in these variables unless Ansible Vault protects them.
Normally omit `--cpu`; the installer safely chooses the first CPU allowed for
each host. If an explicit CPU is required, define it in `host_vars` after
checking that host's `Cpus_allowed_list`.

## 3. Rolling, idempotent playbook

This example copies the bundle from the controller, computes a desired-state
stamp, installs only when the artifact/configuration changed or the service is
not healthy, and rolls through ten percent of the fleet at a time:

```yaml
---
- name: Deploy NetworkTracing oldkernel agent
  hosts: legacy_capture
  become: true
  serial: "10%"
  max_fail_percentage: 10

  vars:
    nt_bundle_dest: "/var/tmp/install-firstrun-el68.sh"
    nt_desired_dest: "/var/tmp/networktracing-legacy.desired"
    nt_deployed_stamp: "/etc/networktracing-legacy.deploy"

  tasks:
    - name: Copy the tested self-contained bundle
      ansible.builtin.copy:
        src: "files/install-firstrun-el68.sh"
        dest: "{{ nt_bundle_dest }}"
        owner: root
        group: root
        mode: "0700"
      register: nt_bundle_copy

    - name: Write non-secret desired configuration
      ansible.builtin.copy:
        dest: "{{ nt_desired_dest }}"
        owner: root
        group: root
        mode: "0600"
        content: |
          version={{ nt_agent_version }}
          bundle_checksum={{ nt_bundle_copy.checksum }}
          hub={{ nt_hub_url }}
          iface={{ nt_capture_iface }}
          ports={{ nt_capture_ports }}
          mode={{ nt_capture_mode }}
          wsse_bytes={{ nt_wsse_bytes }}
          ship_threads={{ nt_ship_threads }}
          ship_rate_kbps={{ nt_ship_rate_kbps }}
      register: nt_desired_copy

    - name: Inspect deployed configuration stamp
      ansible.builtin.stat:
        path: "{{ nt_deployed_stamp }}"
        checksum_algorithm: sha1
      register: nt_deployed

    - name: Inspect service script
      ansible.builtin.stat:
        path: /etc/init.d/networktracing-legacy
      register: nt_init

    - name: Check current service health
      ansible.builtin.command:
        argv:
          - /etc/init.d/networktracing-legacy
          - status
      register: nt_status
      changed_when: false
      failed_when: false
      when: nt_init.stat.exists

    - name: Decide whether installation is required
      ansible.builtin.set_fact:
        nt_install_required: >-
          {{
            (not nt_deployed.stat.exists) or
            (nt_deployed.stat.checksum != nt_desired_copy.checksum) or
            (not nt_init.stat.exists) or
            (nt_init.stat.exists and nt_status.rc != 0)
          }}

    - name: Install the exact embedded artifact with fail-closed safeguards
      ansible.builtin.command:
        argv:
          - sh
          - "{{ nt_bundle_dest }}"
          - --offline
          - --server
          - "{{ nt_hub_url }}"
          - --iface
          - "{{ nt_capture_iface }}"
          - --ports
          - "{{ nt_capture_ports }}"
          - --mode
          - "{{ nt_capture_mode }}"
          - --wsse-bytes
          - "{{ nt_wsse_bytes }}"
          - --ship-threads
          - "{{ nt_ship_threads }}"
          - --ship-rate-kbps
          - "{{ nt_ship_rate_kbps }}"
      when: nt_install_required | bool

    - name: Record configuration only after successful installation
      ansible.builtin.copy:
        src: "{{ nt_desired_dest }}"
        dest: "{{ nt_deployed_stamp }}"
        remote_src: true
        owner: root
        group: root
        mode: "0600"
      when: nt_install_required | bool
```

Using `argv` prevents shell interpretation of parameters. `--offline` prevents
fallback downloads or version mixing. The installer still refuses unsafe CPU
affinity, root capture, missing file capabilities, failed `AF_PACKET` access,
missing kernel BPF enforcement, or failure to create and map the strict fixed
`TPACKET_V2` RX ring.

## 4. Optional control token

Copy a Vault-protected token separately with mode `0600`, then add these two
items to the install task's `argv` list:

```yaml
          - --control-token-file
          - /var/tmp/networktracing-control.token
```

Delete the temporary token after a successful install. The installer copies
the value into `/var/lib/networktracing/control.token` with mode `0600` and
removes it from its environment.

## 5. Rollout recommendations

- Test one host first with `--limit hostname`.
- Keep `serial` small for the initial fleet rollout.
- Pin the bundle in source control or artifact storage by checksum.
- Use a complete Hub URL such as `https://host:port`; never construct a port
  inside the playbook from an assumed default.
- Do not use `shell: curl ... | sh`. Ansible `copy` plus `command.argv` gives
  deterministic bytes, clearer failures, and safer argument handling.
- Treat a fail-closed install error as a host prerequisite problem. Do not
  bypass file capabilities, CPU affinity, or rootless execution.
