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
    from mcp_fuzzer.diagnostics import classify_fuzz_runs
    from mcp_fuzzer.diagnostics.auth_oauth import audit_as_metadata
    from mcp_fuzzer.reports.crash_repro import write_findings_report

    findings = classify_fuzz_runs(
        {"t": {"runs": [{"outcome": "timeout", "args": {"x": 1}}]}}, None
    )
    assert write_findings_report(tmp_path, []) is None
    path = write_findings_report(tmp_path, findings)
    assert path is not None and path.name == "findings.json"
    import json

    data = json.loads(path.read_text())
    assert data["count"] == len(findings)
    assert "auth_audit" not in data

    auth_findings = audit_as_metadata(
        type(
            "Meta",
            (),
            {
                "code_challenge_methods_supported": [],
                "grant_types_supported": ["authorization_code"],
            },
        )()
    )
    path = write_findings_report(tmp_path, auth_findings)
    data = json.loads(path.read_text())
    assert data["auth_audit"]["paper_url"] == "https://arxiv.org/abs/2605.22333"
    assert data["auth_audit"]["finding_count"] == len(auth_findings)


def test_auth_probe_str_error_and_truncate():
    from mcp_fuzzer.diagnostics.auth_probe import is_auth_enforced, _truncate

    assert is_auth_enforced(response={"error": "Unauthorized access"}) is True
    assert is_auth_enforced(response={"error": "weird"}) is False
    assert _truncate("x" * 500).endswith("…")


import pytest as _pytest  # noqa: E402


@_pytest.mark.asyncio
async def test_auth_bypass_probe_skipped_without_auth_manager():
    from mcp_fuzzer.orchestrator.session import run_auth_bypass_phase

    assert await run_auth_bypass_phase({"auth_manager": None}, lambda c: c) == []


@_pytest.mark.asyncio
async def test_auth_security_audit_skipped_when_disabled():
    from mcp_fuzzer.orchestrator.session import run_oauth_audit_phase

    result = await run_oauth_audit_phase(
        {"auth_audit": False}, object(), lambda c: c
    )
    assert result == ([], False)


@_pytest.mark.asyncio
async def test_auth_security_audit_skipped_without_probe_support():
    from mcp_fuzzer.orchestrator.session import run_oauth_audit_phase

    # auth_audit enabled but the transport cannot do auth discovery -> skipped,
    # reported as ran=False so it is not logged as a clean run.
    findings, ran = await run_oauth_audit_phase(
        {"auth_audit": True}, object(), lambda c: c
    )
    assert findings == []
    assert ran is False


def test_log_auth_audit_results_does_not_claim_clean_when_skipped(caplog):
    import logging as _logging

    from mcp_fuzzer.orchestrator.session import log_oauth_audit_results

    with caplog.at_level(_logging.INFO):
        log_oauth_audit_results([], enabled=True, ran=False)
    assert "no findings" not in caplog.text


@_pytest.mark.asyncio
async def test_probe_advertised_auth_open_tools():
    from mcp_fuzzer.diagnostics import probe_advertised_auth_open_tools

    findings = probe_advertised_auth_open_tools(
        [{"name": "alpha"}, {"name": "beta"}],
        auth_advertised=True,
    )
    assert len(findings) == 1
    assert findings[0].category == "unauthenticated_tools"
    assert findings[0].evidence["tool_count"] == 2
    assert probe_advertised_auth_open_tools([], auth_advertised=True) == []
    assert (
        probe_advertised_auth_open_tools([{"name": "x"}], auth_advertised=False)
        == []
    )
    findings = probe_advertised_auth_open_tools([{"name": "x"}], auth_advertised=True)
    assert findings[0].evidence["paper_url"] == "https://arxiv.org/abs/2605.22333"


def test_plain_summary_links_auth_audit_paper(capsys):
    from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary

    write_stdout_summary(
        mode="tools",
        tool_results={},
        protocol_results=None,
        findings_summary={"pkce_downgrade": 1},
    )
    out = capsys.readouterr().out
    assert "2605.22333" in out
    assert "https://arxiv.org/abs/2605.22333" in out


@_pytest.mark.asyncio
async def test_send_request_raises_server_crash_on_dead_process():
    from unittest.mock import AsyncMock

    driver = StdioDriver("dummy", timeout=5)
    driver._mcp_initialized = True
    driver._send_message = AsyncMock()
    driver._receive_message = AsyncMock(return_value=None)  # EOF / no response
    driver.process = _FakeProc(-11)  # crashed via SIGSEGV
    driver._stderr_tail.append("AddressSanitizer: SEGV on unknown address")
    with _pytest.raises(ServerCrashError) as exc:
        await driver.send_request("tools/list")
    assert exc.value.context["signal_name"] == "SIGSEGV"


@_pytest.mark.asyncio
async def test_receive_message_raises_crash_on_broken_read():
    from unittest.mock import AsyncMock

    driver = StdioDriver("dummy", timeout=5)
    driver._initialized = True
    driver.stdout = object()
    driver._readline_with_cap = AsyncMock(side_effect=OSError("broken pipe"))
    driver.process = _FakeProc(2)  # non-zero exit -> crash
    with _pytest.raises(ServerCrashError):
        await driver._receive_message()


@_pytest.mark.asyncio
async def test_send_request_transport_error_when_not_crashed():
    from unittest.mock import AsyncMock

    driver = StdioDriver("dummy", timeout=5)
    driver._mcp_initialized = True
    driver._send_message = AsyncMock()
    driver._receive_message = AsyncMock(return_value=None)
    driver.process = _FakeProc(0)  # clean / still-running -> not a crash
    from mcp_fuzzer.exceptions import TransportError

    with _pytest.raises(TransportError):
        await driver.send_request("tools/list")
