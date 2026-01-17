#!/usr/bin/env python3
"""Tests for safety system shims."""

from __future__ import annotations

import json

import pytest

from mcp_fuzzer.safety_system.blocking.shims import default_shim, strict_shim

pytestmark = [pytest.mark.unit]


def test_default_shim_logs_and_exits(monkeypatch, tmp_path, capsys):
    log_path = tmp_path / "default_shim.log"
    monkeypatch.setattr(default_shim, "LOG_FILE", str(log_path))
    monkeypatch.setattr(default_shim.sys, "argv", ["blocked-cmd", "--flag", "value"])

    with pytest.raises(SystemExit) as excinfo:
        default_shim.main()

    assert excinfo.value.code == 0

    captured = capsys.readouterr()
    assert "[FUZZER BLOCKED]" in captured.err
    assert "blocked-cmd" in captured.err

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["command"] == "blocked-cmd"
    assert entry["args"] == "--flag value"
    assert entry["full_command"] == "blocked-cmd --flag value"


def test_strict_shim_logs_and_exits(monkeypatch, tmp_path, capsys):
    log_path = tmp_path / "strict_shim.log"
    monkeypatch.setattr(strict_shim, "LOG_FILE", str(log_path))
    monkeypatch.setattr(strict_shim.sys, "argv", ["blocked-cmd", "--flag", "value"])

    with pytest.raises(SystemExit) as excinfo:
        strict_shim.main()

    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert "[BLOCKED]" in captured.err
    assert "blocked-cmd" in captured.err

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["command"] == "blocked-cmd"
    assert entry["args"] == ["--flag", "value"]


def test_default_shim_without_emoji(monkeypatch, capsys):
    monkeypatch.setattr(default_shim, "HAS_EMOJI", False)
    monkeypatch.setattr(default_shim, "LOG_FILE", "")
    monkeypatch.setattr(default_shim.sys, "argv", ["blocked-cmd"])

    with pytest.raises(SystemExit) as excinfo:
        default_shim.main()

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "[X]" in captured.err
    assert "[*]" in captured.out


def test_strict_shim_log_write_failure(monkeypatch, capsys):
    monkeypatch.setattr(strict_shim, "LOG_FILE", "blocked.log")
    monkeypatch.setattr(strict_shim.sys, "argv", ["blocked-cmd"])

    def _raise_open(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr("builtins.open", _raise_open)

    with pytest.raises(SystemExit) as excinfo:
        strict_shim.main()

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "[BLOCKED]" in captured.err
