#!/usr/bin/env python3
"""Tests for server-crash detection, classification, and repro artifacts."""

from __future__ import annotations

import pytest

from mcp_fuzzer.exceptions import ServerCrashError, TransportError
from mcp_fuzzer.outcomes import (
    FuzzOutcome,
    classify_protocol_run,
    classify_tool_run,
)
from mcp_fuzzer.reports.crash_repro import collect_crashes, write_crash_repros
from mcp_fuzzer.transport.drivers.stdio_driver import StdioDriver


# --- outcome classification ------------------------------------------------


def test_classify_tool_run_crash():
    success, outcome = classify_tool_run(exception=ServerCrashError("boom"))
    assert success is False
    assert outcome == FuzzOutcome.CRASHED


def test_classify_protocol_run_crash():
    success, outcome = classify_protocol_run(exception=ServerCrashError("boom"))
    assert success is False
    assert outcome == FuzzOutcome.CRASHED


def test_plain_transport_error_is_not_a_crash():
    _, outcome = classify_tool_run(exception=TransportError("no response"))
    assert outcome == FuzzOutcome.TRANSPORT_ERROR


# --- stdio crash detection (signal filtering) ------------------------------


class _FakeProc:
    def __init__(self, returncode):
        self.returncode = returncode

    async def wait(self):
        return self.returncode


def _driver_with_proc(returncode, stderr=None):
    driver = StdioDriver("dummy-cmd", timeout=5)
    driver.process = _FakeProc(returncode)
    for line in stderr or []:
        driver._stderr_tail.append(line)
    return driver


@pytest.mark.asyncio
async def test_detect_crash_on_segfault_signal():
    driver = _driver_with_proc(-11, stderr=["AddressSanitizer: SEGV"])
    ctx = await driver._detect_crash()
    assert ctx is not None
    assert ctx["exit_code"] == -11
    assert ctx["signal"] == 11
    assert ctx["signal_name"] == "SIGSEGV"
    assert ctx["stderr_tail"] == ["AddressSanitizer: SEGV"]


@pytest.mark.asyncio
async def test_detect_crash_on_nonzero_exit():
    driver = _driver_with_proc(2, stderr=["panic: runtime error"])
    ctx = await driver._detect_crash()
    assert ctx is not None
    assert ctx["exit_code"] == 2
    assert "signal" not in ctx


@pytest.mark.asyncio
async def test_our_sigkill_is_not_a_crash():
    # -9 (SIGKILL) and -15 (SIGTERM) are sent by the fuzzer itself, not crashes.
    assert await _driver_with_proc(-9)._detect_crash() is None
    assert await _driver_with_proc(-15)._detect_crash() is None


@pytest.mark.asyncio
async def test_clean_exit_and_running_are_not_crashes():
    assert await _driver_with_proc(0)._detect_crash() is None
    assert await _driver_with_proc(None)._detect_crash() is None


@pytest.mark.asyncio
async def test_raise_if_crashed_raises_server_crash_error():
    driver = _driver_with_proc(-6, stderr=["abort"])
    with pytest.raises(ServerCrashError) as exc:
        await driver._raise_if_crashed()
    assert exc.value.context["signal_name"] == "SIGABRT"


# --- crash repro artifacts -------------------------------------------------


def test_collect_and_write_crash_repros(tmp_path):
    tool_results = {
        "boom_tool": {
            "runs": [
                {"success": True, "outcome": "server_rejected"},
                {
                    "success": False,
                    "outcome": "crashed",
                    "error": "server_crashed",
                    "args": {"x": "A" * 5},
                    "crash": {"exit_code": -11, "signal": 11},
                    "exception": "Server process terminated abnormally",
                },
            ]
        }
    }
    protocol_results = {
        "InitializeRequest": [
            {
                "outcome": "crashed",
                "fuzz_data": {"jsonrpc": "2.0", "method": "initialize"},
                "crash": {"exit_code": 1},
            }
        ]
    }

    crashes = collect_crashes(tool_results, protocol_results)
    assert len(crashes) == 2
    kinds = {c["kind"] for c in crashes}
    assert kinds == {"tool", "protocol"}

    paths = write_crash_repros(tmp_path, tool_results, protocol_results)
    assert len(paths) == 2
    for path in paths:
        assert path.exists()
        assert path.parent.name == "crashes"


def test_write_crash_repros_no_crashes(tmp_path):
    clean = {"t": {"runs": [{"success": True}]}}
    assert write_crash_repros(tmp_path, clean, None) == []


# --- summary surfacing -----------------------------------------------------


def test_stdout_summary_reports_crashes(capsys):
    from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary

    write_stdout_summary(
        mode="tools",
        tool_results={
            "boom": {
                "runs": [
                    {
                        "success": False,
                        "outcome": "crashed",
                        "error": "server_crashed",
                    }
                ]
            }
        },
        protocol_results=None,
    )
    out = capsys.readouterr().out
    assert "CRASHES: 1" in out
    assert "1 crashes" in out
