#!/usr/bin/env python3
"""Unit tests for the system command blocker."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.safety_system.blocking import command_blocker
from mcp_fuzzer.safety_system.blocking.command_blocker import (
    SystemCommandBlocker,
    _sanitize_command_name,
)

pytestmark = [pytest.mark.unit]


def test_sanitize_command_name_filters_bad_input():
    assert _sanitize_command_name("  /usr/bin/xdg-open  ") == "xdg-open"
    assert _sanitize_command_name("Open") == "Open"
    assert _sanitize_command_name("") is None
    assert _sanitize_command_name("rm -rf /") is None
    assert _sanitize_command_name("!invalid!") is None


def test_create_fake_executables_writes_files(tmp_path, monkeypatch):
    blocker = SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    blocker.blocked_commands = ["testcmd"]

    monkeypatch.setattr(
        command_blocker,
        "load_shim_template",
        lambda name: "#!/usr/bin/env python\nprint('blocked') <<<LOG_FILE>>>",
    )

    blocker._create_fake_executables()

    created = list(tmp_path.iterdir())
    assert any(p.name == "testcmd" for p in created)
    assert blocker.created_files


def test_create_fake_executable_handles_invalid_name(tmp_path, monkeypatch):
    blocker = SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    blocker.created_files.clear()

    blocker.create_fake_executable("!!!")

    assert not blocker.created_files


def test_block_command_adds_and_creates_when_active(tmp_path, monkeypatch):
    blocker = SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    blocker.blocked_commands = ["open"]

    tracker = MagicMock()
    monkeypatch.setattr(blocker, "create_fake_executable", tracker)
    monkeypatch.setattr(blocker, "is_blocking_active", lambda: True)

    blocker.block_command("new-app")

    assert "new-app" in blocker.blocked_commands
    tracker.assert_called_once_with("new-app")


def test_get_blocked_operations_parses_json(tmp_path):
    blocker = SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    log_file = tmp_path / "blocked_operations.log"
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"command": "open", "args": "--foo"}),
                "not-json",
                json.dumps({"command": "firefox"}),
            ]
        )
    )

    operations = blocker.get_blocked_operations()
    assert len(operations) == 2
    assert operations[0]["command"] == "open"


def test_clear_blocked_operations_removes_log(tmp_path):
    blocker = SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    log_file = tmp_path / "blocked_operations.log"
    log_file.write_text("payload")

    blocker.clear_blocked_operations()

    assert not log_file.exists()


def test_get_blocked_commands_wrapper_reflects_state(monkeypatch):
    monkeypatch.setattr(command_blocker._system_blocker, "blocked_commands", ["open"])
    assert "open" in command_blocker.get_blocked_commands()


def test_sanitize_command_name_variants():
    assert command_blocker._sanitize_command_name(None) is None
    assert command_blocker._sanitize_command_name("   ") is None
    assert command_blocker._sanitize_command_name("bad name!") is None


def test_start_blocking_creates_executables(tmp_path, monkeypatch):
    blocker = command_blocker.SystemCommandBlocker()

    monkeypatch.setenv("PATH", "orig")
    monkeypatch.setattr(
        command_blocker.tempfile,
        "mkdtemp",
        lambda prefix=None: str(tmp_path),
    )
    monkeypatch.setattr(
        command_blocker,
        "load_shim_template",
        lambda name: "#!/bin/sh\necho blocked > <<<LOG_FILE>>>\n",
    )

    blocker.start_blocking()
    try:
        assert blocker.temp_dir == tmp_path
        assert os.environ["PATH"].startswith(str(tmp_path))
        assert blocker.created_files
        for created in blocker.created_files:
            assert created.exists()
    finally:
        blocker.stop_blocking()

    assert os.environ["PATH"] == "orig"


def test_block_command_creates_shim(tmp_path, monkeypatch):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    monkeypatch.setattr(
        command_blocker,
        "load_shim_template",
        lambda name: "#!/bin/sh\nexit 1\n",
    )

    blocker.block_command("bad name!")
    assert "bad name!" not in blocker.blocked_commands

    blocker.block_command("custom-tool")
    shim = tmp_path / "custom-tool"
    assert shim.exists()


def test_create_fake_executables_requires_temp_dir():
    blocker = command_blocker.SystemCommandBlocker()
    with pytest.raises(RuntimeError):
        blocker._create_fake_executables()


def test_create_fake_executables_logs_errors(tmp_path, monkeypatch, caplog):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    monkeypatch.setattr(
        command_blocker,
        "load_shim_template",
        lambda name: "#!/bin/sh\nexit 0\n",
    )

    def _raise_write(self, *args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(Path, "write_text", _raise_write)
    blocker._create_fake_executables()
    assert "Failed to create fake executable" in caplog.text


def test_get_blocked_operations_log_read_error(tmp_path, caplog):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    log_file = tmp_path / "blocked_operations.log"
    log_file.mkdir()
    operations = blocker.get_blocked_operations()
    assert operations == []
    assert "Failed to read blocked operations log" in caplog.text


def test_clear_blocked_operations_warns_on_error(tmp_path, monkeypatch, caplog):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.temp_dir = tmp_path
    log_file = tmp_path / "blocked_operations.log"
    log_file.write_text(json.dumps({"cmd": "open"}))

    def _raise_unlink(*_args, **_kwargs):
        raise OSError("nope")

    monkeypatch.setattr(Path, "unlink", _raise_unlink)
    blocker.clear_blocked_operations()
    assert "Failed to clear blocked operations log" in caplog.text


def test_create_fake_executable_no_temp_dir(caplog):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.create_fake_executable("demo")
    assert "Temp directory not created" in caplog.text


def test_stop_blocking_handles_cleanup_error(monkeypatch, caplog):
    blocker = command_blocker.SystemCommandBlocker()
    blocker.original_path = "orig"

    def _boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(blocker, "cleanup", _boom)
    blocker.stop_blocking()
    assert "Error during cleanup" in caplog.text


def test_get_blocked_operations_without_temp_dir():
    blocker = command_blocker.SystemCommandBlocker()
    assert blocker.get_blocked_operations() == []


def test_cleanup_logs_failures(tmp_path, monkeypatch, caplog):
    blocker = command_blocker.SystemCommandBlocker()
    fake_exec = tmp_path / "fake"
    fake_exec.write_text("hi")
    blocker.created_files.append(fake_exec)
    blocker.temp_dir = tmp_path

    def _raise_unlink(*_args, **_kwargs):
        raise OSError("boom")

    def _raise_rmtree(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr(Path, "unlink", _raise_unlink)
    monkeypatch.setattr(command_blocker.shutil, "rmtree", _raise_rmtree)

    blocker.cleanup()
    assert "Failed to remove" in caplog.text
    assert "Failed to remove temp dir" in caplog.text
