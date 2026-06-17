#!/usr/bin/env python3
"""Tests for the post-run findings analyzer and oversized-response detection."""

from __future__ import annotations

import pytest

from mcp_fuzzer.diagnostics import classify_fuzz_runs, summarize_findings
from mcp_fuzzer.exceptions import OversizedResponseError
from mcp_fuzzer.client.outcomes import FuzzOutcome, classify_tool_run


def _categories(findings):
    return {f.category for f in findings}


def test_oversized_response_classified():
    _, outcome = classify_tool_run(exception=OversizedResponseError("too big"))
    assert outcome == FuzzOutcome.OVERSIZED_RESPONSE


def test_crash_finding():
    results = {
        "t": {
            "runs": [
                {
                    "outcome": "crashed",
                    "error": "server_crashed",
                    "args": {"x": 1},
                    "crash": {"signal": 11},
                }
            ]
        }
    }
    findings = classify_fuzz_runs(results, None)
    assert len(findings) == 1
    assert findings[0].category == "crash"
    assert findings[0].severity == "critical"


def test_hang_and_oversized_and_accepted_malformed():
    results = {
        "t": {
            "runs": [
                {"outcome": "timeout", "args": {"x": 1}},
                {"outcome": "oversized_response", "args": {"x": 2}},
                {"outcome": "accepted_malformed", "args": {"x": 3}},
            ]
        }
    }
    cats = _categories(classify_fuzz_runs(results, None))
    assert {"hang", "oversized_response", "accepted_malformed"} <= cats


def test_internal_error_from_jsonrpc_code():
    results = {
        "t": {
            "runs": [
                {
                    "outcome": "valid_response",
                    "args": {},
                    "result": {"response": {"error": {"code": -32603, "m": "x"}}},
                }
            ]
        }
    }
    assert "internal_error" in _categories(classify_fuzz_runs(results, None))


def test_error_leakage_from_stderr_panic():
    results = {
        "t": {
            "runs": [
                {
                    "outcome": "crashed",
                    "error": "server_crashed",
                    "args": {},
                    "crash": {"stderr_tail": ["panic: runtime error: idx oob"]},
                }
            ]
        }
    }
    cats = _categories(classify_fuzz_runs(results, None))
    assert "error_leakage" in cats
    assert "crash" in cats


def test_injection_reflection():
    results = {
        "t": {
            "runs": [
                {
                    "outcome": "valid_response",
                    "args": {"path": "../../../etc/passwd"},
                    "result": {"echo": "reading ../../../etc/passwd now"},
                }
            ]
        }
    }
    assert "injection_reflection" in _categories(classify_fuzz_runs(results, None))


def test_performance_outlier():
    runs = [{"outcome": "valid_response", "args": {}, "response_time": 0.1}] * 4
    runs.append({"outcome": "valid_response", "args": {}, "response_time": 3.0})
    findings = classify_fuzz_runs({"t": {"runs": runs}}, None)
    assert "performance_outlier" in _categories(findings)


def test_non_determinism_same_input_different_outcomes():
    results = {
        "t": {
            "runs": [
                {"outcome": "valid_response", "args": {"x": 1}},
                {"outcome": "crashed", "args": {"x": 1}},
            ]
        }
    }
    assert "non_determinism" in _categories(classify_fuzz_runs(results, None))


def test_protocol_runs_analyzed():
    protocol_results = {
        "InitializeRequest": [
            {"outcome": "crashed", "fuzz_data": {"jsonrpc": "2.0"}, "crash": {}},
            {"outcome": "timeout", "fuzz_data": {"jsonrpc": "2.0"}},
        ]
    }
    findings = classify_fuzz_runs(None, protocol_results)
    cats = _categories(findings)
    assert {"crash", "hang"} <= cats
    assert all(f.kind == "protocol" for f in findings)


def test_summarize_findings_counts():
    results = {
        "t": {
            "runs": [
                {"outcome": "timeout", "args": {"a": 1}},
                {"outcome": "timeout", "args": {"b": 2}},
            ]
        }
    }
    summary = summarize_findings(classify_fuzz_runs(results, None))
    assert summary.get("hang") == 2


def test_clean_run_has_no_findings():
    results = {
        "t": {
            "runs": [
                {"outcome": "server_rejected", "args": {"x": 1}},
                {"outcome": "server_rejected", "args": {"x": 2}},
            ]
        }
    }
    assert classify_fuzz_runs(results, None) == []


def test_findings_to_dict_roundtrip():
    findings = classify_fuzz_runs(
        {"t": {"runs": [{"outcome": "timeout", "args": {"x": 1}}]}}, None
    )
    d = findings[0].to_dict()
    assert d["category"] == "hang"
    assert set(d) == {"category", "severity", "kind", "target", "run", "detail",
                      "evidence"}


# --- memory growth ----------------------------------------------------------


def test_memory_growth_detected():
    base = 50 * 1024 * 1024  # 50 MB
    runs = []
    for i in range(12):
        runs.append(
            {
                "outcome": "valid_response",
                "args": {"i": i},
                "rss_bytes": base + i * 15 * 1024 * 1024,  # grows ~15MB/run
            }
        )
    findings = classify_fuzz_runs({"leaky": {"runs": runs}}, None)
    assert "memory_growth" in _categories(findings)


def test_stable_memory_not_flagged():
    base = 50 * 1024 * 1024
    runs = [
        {"outcome": "valid_response", "args": {"i": i}, "rss_bytes": base + (i % 2)}
        for i in range(12)
    ]
    findings = classify_fuzz_runs({"stable": {"runs": runs}}, None)
    assert "memory_growth" not in _categories(findings)


# --- auth bypass ------------------------------------------------------------


def test_is_auth_enforced_classification():
    from mcp_fuzzer.diagnostics import is_auth_enforced
    from mcp_fuzzer.exceptions import AuthenticationError

    assert is_auth_enforced(exception=AuthenticationError("nope")) is True
    assert is_auth_enforced(exception=Exception("HTTP 401 Unauthorized")) is True
    assert is_auth_enforced(response={"error": {"code": 403, "message": "Forbidden"}})
    # success without auth -> NOT enforced (bypass)
    assert is_auth_enforced(response={"result": {"ok": True}}) is False
    assert is_auth_enforced(exception=Exception("boom")) is False


def test_secured_tool_names_with_mapping():
    from mcp_fuzzer.diagnostics import secured_tool_names

    class AM:
        tool_auth_mapping = {"secure_tool": "api"}
        default_provider = None

    tools = [{"name": "secure_tool"}, {"name": "open_tool"}]
    assert secured_tool_names(AM(), tools) == ["secure_tool"]


def test_secured_tool_names_default_provider_covers_all():
    from mcp_fuzzer.diagnostics import secured_tool_names

    class AM:
        tool_auth_mapping = {}
        default_provider = "api"

    tools = [{"name": "a"}, {"name": "b"}]
    assert set(secured_tool_names(AM(), tools)) == {"a", "b"}


@pytest.mark.asyncio
async def test_probe_auth_bypass_flags_unenforced_tool():
    from mcp_fuzzer.diagnostics import probe_auth_bypass

    async def attempt(tool_name):
        # Server happily answers without auth -> bypass.
        return {"result": {"content": []}}

    findings = await probe_auth_bypass(["secure_tool"], attempt)
    assert len(findings) == 1
    assert findings[0].category == "auth_bypass"
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_probe_auth_bypass_no_finding_when_enforced():
    from mcp_fuzzer.diagnostics import probe_auth_bypass
    from mcp_fuzzer.exceptions import AuthenticationError

    async def attempt(tool_name):
        raise AuthenticationError("401 Unauthorized")

    findings = await probe_auth_bypass(["secure_tool"], attempt)
    assert findings == []
