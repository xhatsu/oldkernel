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
        "print(__import__('os').nice(0))"
    )
    cpu = first_allowed_cpu()
    out = subprocess.check_output(["sh", GUARD, cpu, "python3", "-c", probe])
    values = out.decode("ascii").splitlines()
    assert values == [cpu, "(268435456, 268435456)", "(1024, 1024)",
                      "(33554432, 33554432)", "(0, 0)",
                      "(8388608, 8388608)", "(65536, 65536)", "19"]


def test_guard_fails_closed_on_bad_cpu():
    proc = subprocess.Popen(["sh", GUARD, "not-a-cpu", "true"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate()
    assert proc.returncode == 70


def test_installer_routes_service_through_guard():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert 'have taskset || die' in installer
    assert 'nt-resource-guard.sh" "\\$CPU_CORE" \\' in installer
    assert "nt-resource-guard.sh" in installer.split("need_kit=0", 1)[1]
    assert "nt-supervise.sh" in installer.split("need_kit=0", 1)[1]
    assert "refusing to run the agent as root" in installer
    assert 'nt-resource-guard.sh" "\\$CPU_CORE" \\' in installer
    assert 'nt-supervise.sh" "\\$PREFIX/nt-resource-guard.sh"' in installer


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
