import io
from types import SimpleNamespace

import pytest

from mcp_fuzzer.safety_system.blocking.shims import default_shim


def _raise_exit(code=0):
    raise SystemExit(code)


def test_default_shim_main_without_emoji(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "blocked.jsonl"
    monkeypatch.setattr(default_shim, "LOG_FILE", str(log_file))
    monkeypatch.setattr(default_shim, "HAS_EMOJI", False)
    monkeypatch.setattr(default_shim.sys, "argv", ["blocked-cmd", "--flag"])
    monkeypatch.setattr(default_shim.sys, "exit", _raise_exit)
    monkeypatch.setattr(default_shim.sys, "stderr", io.StringIO())

    with pytest.raises(SystemExit) as exc:
        default_shim.main()
    assert exc.value.code == 0
    assert log_file.exists()
    assert "blocked-cmd" in log_file.read_text()
    out = capsys.readouterr().out
    assert "Command 'blocked-cmd' was blocked" in out


def test_default_shim_main_with_emoji(monkeypatch, capsys):
    monkeypatch.setattr(default_shim, "LOG_FILE", "")
    monkeypatch.setattr(default_shim, "HAS_EMOJI", True)
    monkeypatch.setattr(
        default_shim,
        "emoji",
        SimpleNamespace(emojize=lambda value: value.replace(":", "")),
    )
    monkeypatch.setattr(default_shim.sys, "argv", ["blocked-cmd"])
    monkeypatch.setattr(default_shim.sys, "exit", _raise_exit)

    with pytest.raises(SystemExit) as exc:
        default_shim.main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "prohibited" in captured.err
    assert "shield" in captured.out
