import os
import subprocess


HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.path.join(HERE, "install-oldkernel.sh")


def checked_env(tmp_path):
    fake_curl = tmp_path / "curl"
    fake_curl.write_text("#!/bin/sh\nprintf '%s\\n' '{\"ok\":true}'\n")
    fake_curl.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    for name in ("NT_IFACE", "NT_PORTS", "NT_CAPTURE_MODE",
                 "NT_WSSE_BODY_BYTES", "NT_CPU_CORE", "NT_SHIP_THREADS",
                 "NT_SHIP_RATE_KBPS", "NT_HUB", "NT_CONTROL_TOKEN"):
        env.pop(name, None)
    return env


def test_server_url_and_friendly_flags_reach_preflight(tmp_path):
    proc = subprocess.run([
        "sh", INSTALLER, "--server", "http://hub.local:43123", "--iface", "eth0",
        "--ports", "80,8001,8080", "--mode", "python",
        "--wsse-bytes", "16384", "--ship-threads", "4", "--offline",
        "--ship-rate-kbps", "512",
        "--check"],
        env=checked_env(tmp_path), text=True, capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "hub protocol OK (http://hub.local:43123)" in proc.stdout
    assert "preflight OK (eth0" in proc.stdout


def test_exact_urls_and_legacy_wsse_name_remain_supported(tmp_path):
    proc = subprocess.run([
        "sh", INSTALLER, "--endpoint", "https://hub.example/otel",
        "--kit-url", "https://hub.example/oldkernel", "--iface", "eth0",
        "--wsse-body-bytes", "0", "--check"],
        env=checked_env(tmp_path), text=True, capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "endpoint=https://hub.example/otel" in proc.stdout


def test_invalid_friendly_values_fail_before_preflight(tmp_path):
    too_many_ports = ",".join(str(n) for n in range(1, 32))
    bad_args = (
        ("--server", "hub-without-scheme"),
        ("--server", "http://hub:43123", "--ports", "80,,8080"),
        ("--server", "http://hub:43123", "--ports", "65536"),
        ("--server", "http://hub:43123", "--mode", "fast"),
        ("--server", "http://hub:43123", "--wsse-bytes", "65537"),
        ("--server", "http://hub:43123", "--ship-threads", "0"),
        ("--server", "http://hub:43123", "--ship-threads", "9"),
        ("--server", "http://hub:43123", "--ship-rate-kbps", "63"),
        ("--server", "http://hub:43123", "--ship-rate-kbps", "10001"),
        ("--server", "http://hub:43123", "--ports", too_many_ports),
    )
    for args in bad_args:
        proc = subprocess.run(["sh", INSTALLER] + list(args),
                              env=checked_env(tmp_path),
                              text=True, capture_output=True)
        assert proc.returncode == 1


def test_missing_option_value_and_help():
    missing = subprocess.run(["sh", INSTALLER, "--server"],
                             text=True, capture_output=True)
    assert missing.returncode == 1
    help_result = subprocess.run(["sh", INSTALLER, "--help"],
                                 text=True, capture_output=True)
    assert help_result.returncode == 0
    assert "--server URL" in help_result.stdout
    assert "--offline" in help_result.stdout
    assert "--ship-rate-kbps" in help_result.stdout
