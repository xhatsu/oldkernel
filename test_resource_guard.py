import os
import subprocess


HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "nt-resource-guard.sh")
SUPERVISOR = os.path.join(HERE, "nt-supervise.sh")
INSTALLER = os.path.join(HERE, "install-oldkernel.sh")


def first_allowed_cpu():
    with open("/proc/self/status", "r") as src:
        for line in src:
            if line.startswith("Cpus_allowed_list:"):
                return line.split(":", 1)[1].strip().split(",", 1)[0].split("-", 1)[0]
    raise AssertionError("Cpus_allowed_list missing")


def test_guard_applies_hard_limits_and_one_cpu():
    probe = (
        "import resource; "
        "print(open('/proc/self/status').read().split('Cpus_allowed_list:')[1].splitlines()[0].strip()); "
        "print(resource.getrlimit(resource.RLIMIT_AS)); "
        "print(resource.getrlimit(resource.RLIMIT_NOFILE)); "
        "print(resource.getrlimit(resource.RLIMIT_FSIZE)); "
        "print(resource.getrlimit(resource.RLIMIT_CORE)); "
        "print(resource.getrlimit(resource.RLIMIT_STACK)); "
        "print(resource.getrlimit(resource.RLIMIT_MEMLOCK)); "
        "print(__import__('os').nice(0)); "
        "print(__import__('os').sched_getscheduler(0))"
    )
    cpu = first_allowed_cpu()
    out = subprocess.check_output(["sh", GUARD, cpu, "python3", "-c", probe])
    values = out.decode("ascii").splitlines()
    assert values == [cpu, "(268435456, 268435456)", "(1024, 1024)",
                      "(33554432, 33554432)", "(0, 0)",
                      "(8388608, 8388608)", "(65536, 65536)", "19", "5"]


def test_guard_fails_closed_on_bad_cpu():
    proc = subprocess.Popen(["sh", GUARD, "not-a-cpu", "true"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate()
    assert proc.returncode == 70


def test_installer_routes_service_through_guard():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert 'have taskset || die' in installer
    assert 'have chrt || die' in installer
    assert 'nt-resource-guard.sh" "\\$CPU_CORE" \\' in installer
    assert "nt-resource-guard.sh" in installer.split("need_kit=0", 1)[1]
    assert "nt-supervise.sh" in installer.split("need_kit=0", 1)[1]
    assert "refusing to run the agent as root" in installer
    assert 'nt-resource-guard.sh" "\\$CPU_CORE" \\' in installer
    assert 'nt-supervise.sh" "\\$PREFIX/nt-resource-guard.sh"' in installer
    assert 'chrt -i 0 nice -n 19' in installer


def test_generated_init_defers_runtime_expansions_and_waits_for_el6():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert 'supervisor=\\$(cat "\\$PIDFILE" 2>/dev/null || true)' in installer
    assert '_sw=\\$((_sw + 1))' in installer
    assert 'echo "\\$supervisor_pid" > "\\$PIDFILE"' in installer
    startup = installer.split('echo "\\$supervisor_pid" > "\\$PIDFILE"', 1)[1]
    assert "sleep 3" in startup.split("if ! pgrep", 1)[0]


def test_supervisor_opens_circuit_after_five_fast_crashes(tmp_path):
    fake_guard = tmp_path / "guard.sh"
    fake_sleep = tmp_path / "sleep"
    fake_guard.write_text("#!/bin/sh\nshift\nexec \"$@\"\n")
    fake_sleep.write_text("#!/bin/sh\nexit 0\n")
    fake_guard.chmod(0o755)
    fake_sleep.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    proc = subprocess.Popen(["sh", SUPERVISOR, str(fake_guard), "0", "false"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env)
    _, stderr = proc.communicate(timeout=10)
    assert proc.returncode == 75
    assert stderr.count(b"child exited") == 4
    assert b"crash-loop circuit open after 5 failures" in stderr


def test_supervisor_does_not_restart_intentional_clean_stop(tmp_path):
    fake_guard = tmp_path / "guard.sh"
    fake_guard.write_text("#!/bin/sh\nshift\nexec \"$@\"\n")
    fake_guard.chmod(0o755)
    proc = subprocess.Popen(["sh", SUPERVISOR, str(fake_guard), "0", "true"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = proc.communicate(timeout=5)
    assert proc.returncode == 0
    assert stderr == b""


def test_installer_passes_wsse_window_to_native_capture():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    runtime = installer.split("# sniffer stdout must FEED", 1)[1]
    native = runtime.split('if [ "$CAPTURE_MODE" = "cpp" ]', 1)[1]
    native = native.split('\nelse\n    if [ "$SNIFF_AS"', 1)[0]
    assert "nt-sniff-cpp" in native
    assert "--wsse-body-bytes $WSSE_BODY_BYTES" in native
    assert "C++03 remains header-only" not in installer


def test_native_probe_exercises_production_interface_ports_and_strict_ring():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert "--capability-probe -i $IFACE -p $PORTS" in installer
    with open(os.path.join(HERE, "nt-sniff-cpp.cpp"), "r") as src:
        native = src.read()
    assert "TPACKET_V2 setup failed; refusing non-ring fallback" in native
    assert "falling back to standard socket recv" not in native
    assert "valid_ring_geometry" in native
    assert "valid_ring_frame" in native


def test_native_capture_has_only_the_fixed_rx_v2_ring_path():
    with open(os.path.join(HERE, "nt-sniff-cpp.cpp"), "r") as src:
        native = src.read()
    assert "TPACKET_V3" not in native
    assert "PACKET_TX_RING" not in native
    assert "PACKET_RESERVE" not in native
    assert "PACKET_VNET_HDR" not in native
    assert "PACKET_FANOUT" not in native
    assert "int ver = TPACKET_V2;" in native
    assert "block_size(65536), block_nr(64)" in native
    assert "frame_size(2048), frame_nr(2048)" in native
    assert "!= 4U * 1024U * 1024U" in native


def test_native_setup_order_is_filter_bind_ring_then_capability_drop():
    with open(os.path.join(HERE, "nt-sniff-cpp.cpp"), "r") as src:
        native = src.read()
    setup = native.split("static int open_capture_socket", 1)[1]
    setup = setup.split("static int run_capability_probe", 1)[0]
    assert setup.index("attach_bpf(fd, ports)") < setup.index("bind(fd,")
    assert setup.index("bind(fd,") < setup.index("setup_mmap_ring(fd, ring)")
    assert setup.index("setup_mmap_ring(fd, ring)") < setup.index("drop_all_capabilities()")


def test_python_capture_has_no_packet_fanout_path():
    with open(os.path.join(HERE, "nt-sniff.py"), "r") as src:
        python_capture = src.read()
    assert "PACKET_FANOUT" not in python_capture
    assert "only one capture worker is permitted" in python_capture


def test_installer_applies_egress_limit_to_both_modes():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert "export NT_SHIP_RATE_KBPS=$SHIP_RATE_KBPS" in installer
    assert "--ship-rate-kbps $SHIP_RATE_KBPS" in installer
    assert 'SHIP_RATE_KBPS="${NT_SHIP_RATE_KBPS:-1024}"' in installer


def test_installer_enables_bounded_agent_stats_for_both_modes():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert 'STATS_INTERVAL_SEC="${NT_STATS_INTERVAL_SEC:-30}"' in installer
    assert "export NT_STATS_INTERVAL_SEC=$STATS_INTERVAL_SEC" in installer
    assert "--stats-interval-sec $STATS_INTERVAL_SEC" in installer
    assert "/api/agent/stats" in installer


def test_both_shipping_modes_have_hard_egress_bounds():
    with open(os.path.join(HERE, "nt-ship.py"), "r") as src:
        python_ship = src.read()
    with open(os.path.join(HERE, "nt-ship-cpp.cpp"), "r") as src:
        native = src.read()
    assert "MAX_POST_BYTES = 65536" in python_ship
    assert "RateLimiter" in python_ship
    assert "put_nowait" in python_ship
    assert "MAX_POST_BYTES = 65536" in native
    assert "pace_upload" in native
    assert "--limit-rate" in native


def test_native_installer_uses_nonblocking_two_process_pipeline():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    with open(os.path.join(HERE, "nt-sniff-cpp.cpp"), "r") as src:
        sniffer = src.read()
    with open(os.path.join(HERE, "nt-ship-cpp.cpp"), "r") as src:
        shipper = src.read()
    assert "nt-sniff-cpp -i" in installer and "nt-ship-cpp --endpoint" in installer
    assert "nt-sniff-cpp -i $IFACE -p $PORTS --endpoint" not in installer
    assert "O_NONBLOCK" in sniffer and "PIPE_BUF" in sniffer
    assert "EAGAIN" in sniffer and "EPIPE" in sniffer
    assert "MAX_QUEUE = 4000" in shipper and "pthread_create" in shipper
    assert "capture input closed unexpectedly" in shipper


def test_runtime_reapplies_limits_after_su_drops_privileges():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert "-c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/nt-sniff-cpp" in installer
    assert "-c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/nt-ship-cpp" in installer
    assert "-c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE $PREFIX/python-capnetraw" in installer
    assert "-c 'exec $PREFIX/nt-resource-guard.sh $CPU_CORE python -u $PREFIX/nt-ship.py" in installer
