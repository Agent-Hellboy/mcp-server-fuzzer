#!/usr/bin/env python3
"""
Unit tests for CLI startup info.
"""

import json
from argparse import Namespace

from mcp_fuzzer.cli import startup_info


def _dummy_console_factory(calls):
    class DummyConsole:
        def print(self, *args, **kwargs):
            calls.append((args, kwargs))

    return DummyConsole


def test_print_startup_info_basic(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(startup_info, "Console", _dummy_console_factory(calls))
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.argv_builder.prepare_inner_argv",
        lambda args: ["mcp-fuzzer", "--mode", "tools"],
    )
    monkeypatch.setattr(
        "mcp_fuzzer.client.adapters.config_mediator.load_file",
        lambda path: {"mode": "tools"},
    )

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"mode": "tools"}))

    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({"token": "abc"}))

    args = Namespace(
        config=str(cfg_path),
        auth_config=str(auth_path),
        auth_env=True,
        mode="tools",
        phase=None,
        protocol=None,
        endpoint=None,
        timeout=None,
        tool_timeout=None,
        runs=None,
        runs_per_type=None,
        protocol_type=None,
        enable_safety_system=None,
        no_safety=None,
        fs_root=None,
        no_network=None,
        allow_hosts=None,
        output_dir=None,
        export_csv=None,
        export_xml=None,
        export_html=None,
        export_markdown=None,
        output_format=None,
        watchdog_check_interval=None,
        watchdog_process_timeout=None,
        watchdog_extra_buffer=None,
        watchdog_max_hang_time=None,
        process_max_concurrency=None,
        process_retry_count=None,
        process_retry_delay=None,
        verbose=None,
        log_level=None,
        enable_aiomonitor=None,
        retry_with_safety_on_interrupt=None,
        validate_config=None,
        check_env=None,
    )

    startup_info.print_startup_info(args, config={"auth_manager": None})

    rendered = [" ".join(str(arg) for arg in call[0]) for call in calls]
    assert any("MCP Fuzzer v" in text for text in rendered)
    assert any("Main Configuration File" in text for text in rendered)
    assert not any("Could not build argv preview" in text for text in rendered)


def test_print_startup_info_argv_error(monkeypatch):
    calls = []
    monkeypatch.setattr(startup_info, "Console", _dummy_console_factory(calls))

    def _raise():
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.argv_builder.prepare_inner_argv",
        lambda args: _raise(),
    )

    args = Namespace(
        config=None,
        auth_config=None,
        auth_env=False,
        mode="tools",
        phase=None,
        protocol=None,
        endpoint=None,
        timeout=None,
        tool_timeout=None,
        runs=None,
        runs_per_type=None,
        protocol_type=None,
        enable_safety_system=None,
        no_safety=None,
        fs_root=None,
        no_network=None,
        allow_hosts=None,
        output_dir=None,
        export_csv=None,
        export_xml=None,
        export_html=None,
        export_markdown=None,
        output_format=None,
        watchdog_check_interval=None,
        watchdog_process_timeout=None,
        watchdog_extra_buffer=None,
        watchdog_max_hang_time=None,
        process_max_concurrency=None,
        process_retry_count=None,
        process_retry_delay=None,
        verbose=None,
        log_level=None,
        enable_aiomonitor=None,
        retry_with_safety_on_interrupt=None,
        validate_config=None,
        check_env=None,
    )

    startup_info.print_startup_info(args, config=None)

    rendered = [" ".join(str(arg) for arg in call[0]) for call in calls]
    assert any("Could not build argv preview" in text for text in rendered)
