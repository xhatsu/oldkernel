import os
import subprocess


HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "nt-resource-guard.sh")
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
        "print(__import__('os').nice(0))"
    )
    cpu = first_allowed_cpu()
    out = subprocess.check_output(["sh", GUARD, cpu, "python3", "-c", probe])
    values = out.decode("ascii").splitlines()
    assert values == [cpu, "(268435456, 268435456)", "(1024, 1024)",
                      "(33554432, 33554432)", "(0, 0)", "10"]


def test_guard_fails_closed_on_bad_cpu():
    proc = subprocess.Popen(["sh", GUARD, "not-a-cpu", "true"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate()
    assert proc.returncode == 70


def test_installer_routes_service_through_guard():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    assert 'have taskset || die' in installer
    assert 'nt-resource-guard.sh" "\\$CPU_CORE" sh -c' in installer
    assert "nt-resource-guard.sh" in installer.split("need_kit=0", 1)[1]


def test_installer_passes_wsse_window_to_native_capture():
    with open(INSTALLER, "r") as src:
        installer = src.read()
    runtime = installer.split("# sniffer stdout must FEED", 1)[1]
    native = runtime.split('if [ "$CAPTURE_MODE" = "cpp" ]', 1)[1]
    native = native.split('\nelse\n    if [ "$SNIFF_AS"', 1)[0]
    assert "nt-sniff-cpp" in native
    assert "--wsse-body-bytes $WSSE_BODY_BYTES" in native
    assert "C++03 remains header-only" not in installer
