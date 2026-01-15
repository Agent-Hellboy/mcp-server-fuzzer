#!/usr/bin/env python3
"""Unit tests for the system command blocker."""

from __future__ import annotations

import json
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
