import importlib.util
import json
import os

SPEC = importlib.util.spec_from_file_location(
    "nt_control", os.path.join(os.path.dirname(__file__), "nt_control.py"))
nt_control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nt_control)


def test_desired_ports_are_validated_and_written_atomically(tmp_path):
    state = tmp_path / "remote-desired.json"
    desired = nt_control.validate_desired({
        "generation": 7, "ports": [80, 443, 443], "iface": "eth0", "mode": "python"})
    assert desired["ports"] == [80, 443]
    nt_control.write_state(str(state), desired, "restart required")
    saved = json.loads(state.read_text())
    assert saved["generation"] == 7
    assert saved["ports"] == [80, 443]
    assert "token" not in saved


def test_invalid_desired_and_arbitrary_task_are_rejected():
    for bad in ({"ports": [0]}, {"ports": [True]}, {"ports": list(range(1, 130))},
                {"iface": "../eth0"}, {"mode": "cpp"}):
        try:
            nt_control.validate_desired(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("expected invalid desired state")
    try:
        nt_control.validate_task({"id": 1, "action": "shell", "args": {"cmd": "id"}}, "n1")
    except ValueError:
        pass
    else:
        raise AssertionError("expected arbitrary action rejection")


def test_set_ports_only_calls_injected_restart_callback(tmp_path):
    calls = []
    result = nt_control.apply_task(
        {"id": 8, "action": "set_ports", "args": {"ports": [8080]}},
        "n1", str(tmp_path / "state.json"),
        lambda: calls.append("restart"),
        lambda: calls.append("stop"))
    assert result == "target ports written; restart requested"
    assert calls == ["restart"]
    assert json.loads((tmp_path / "state.json").read_text())["ports"] == [8080]


def test_message_redacts_secrets_and_is_bounded():
    msg = nt_control.safe_message("Bearer abc Authorization: secret password=hunter2 " + ("x" * 400))
    assert "hunter2" not in msg
    assert "secret" not in msg
    assert len(msg) <= 256
