#!/usr/bin/env python3
"""
Unit tests for CLI startup info.
"""

import json
import tempfile
from argparse import Namespace

import pytest

from mcp_fuzzer.cli import startup_info


def _dummy_console_factory(calls):
    class DummyConsole:
        def print(self, *args, **kwargs):
            calls.append((args, kwargs))

    return DummyConsole


def test_print_startup_info_basic(monkeypatch):
    calls = []
    monkeypatch.setattr(startup_info, "Console", _dummy_console_factory(calls))
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.argv_builder.prepare_inner_argv",
        lambda args: ["mcp-fuzzer", "--mode", "tool"],
    )
    monkeypatch.setattr(
        "mcp_fuzzer.client.adapters.config_mediator.load_file",
        lambda path: {"mode": "tool"},
    )

    with tempfile.NamedTemporaryFile("w", delete=False) as cfg:
        cfg.write(json.dumps({"mode": "tool"}))
        cfg_path = cfg.name

    with tempfile.NamedTemporaryFile("w", delete=False) as auth:
        auth.write(json.dumps({"token": "abc"}))
        auth_path = auth.name

    args = Namespace(
        config=cfg_path,
        auth_config=auth_path,
        auth_env=True,
        mode="tool",
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

    assert calls


def test_print_startup_info_argv_error(monkeypatch):
    calls = []
    monkeypatch.setattr(startup_info, "Console", _dummy_console_factory(calls))
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.argv_builder.prepare_inner_argv",
        lambda args: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    args = Namespace(
        config=None,
        auth_config=None,
        auth_env=False,
        mode="tool",
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

    assert calls
