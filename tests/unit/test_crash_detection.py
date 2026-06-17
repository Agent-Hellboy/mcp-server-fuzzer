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
        self.pid = 999999

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


# --- memory sampling + findings report + auth probe wiring -----------------


def test_sample_server_memory_returns_rss_for_live_pid():
    import os

    driver = StdioDriver("dummy", timeout=5)
    driver.process = _FakeProc(None)  # returncode None = running
    driver.process.pid = os.getpid()
    rss = driver.sample_server_memory()
    assert isinstance(rss, int) and rss > 0


def test_sample_server_memory_none_when_exited():
    driver = StdioDriver("dummy", timeout=5)
    driver.process = _FakeProc(0)
    driver.process.pid = 1  # exited (returncode set) -> None
    assert driver.sample_server_memory() is None


def test_sample_server_memory_none_without_process():
    driver = StdioDriver("dummy", timeout=5)
    driver.process = None
    assert driver.sample_server_memory() is None


def test_write_findings_report(tmp_path):
    from mcp_fuzzer.analysis import analyze_findings
    from mcp_fuzzer.reports.crash_repro import write_findings_report

    findings = analyze_findings(
        {"t": {"runs": [{"outcome": "timeout", "args": {"x": 1}}]}}, None
    )
    assert write_findings_report(tmp_path, []) is None
    path = write_findings_report(tmp_path, findings)
    assert path is not None and path.name == "findings.json"
    import json

    data = json.loads(path.read_text())
    assert data["count"] == len(findings)


def test_auth_probe_str_error_and_truncate():
    from mcp_fuzzer.analysis.auth_probe import is_auth_enforced, _truncate

    assert is_auth_enforced(response={"error": "Unauthorized access"}) is True
    assert is_auth_enforced(response={"error": "weird"}) is False
    assert _truncate("x" * 500).endswith("…")


import pytest as _pytest  # noqa: E402


@_pytest.mark.asyncio
async def test_auth_bypass_probe_skipped_without_auth_manager():
    from mcp_fuzzer.client.main import _run_auth_bypass_probe

    assert await _run_auth_bypass_probe({"auth_manager": None}) == []
