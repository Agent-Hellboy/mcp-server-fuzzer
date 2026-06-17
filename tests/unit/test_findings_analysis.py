#!/usr/bin/env python3
"""Tests for the post-run findings analyzer and oversized-response detection."""

from __future__ import annotations

from mcp_fuzzer.analysis import analyze_findings, summarize_findings
from mcp_fuzzer.exceptions import OversizedResponseError
from mcp_fuzzer.outcomes import FuzzOutcome, classify_tool_run


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
    findings = analyze_findings(results, None)
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
    cats = _categories(analyze_findings(results, None))
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
    assert "internal_error" in _categories(analyze_findings(results, None))


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
    cats = _categories(analyze_findings(results, None))
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
    assert "injection_reflection" in _categories(analyze_findings(results, None))


def test_performance_outlier():
    runs = [{"outcome": "valid_response", "args": {}, "response_time": 0.1}] * 4
    runs.append({"outcome": "valid_response", "args": {}, "response_time": 3.0})
    findings = analyze_findings({"t": {"runs": runs}}, None)
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
    assert "non_determinism" in _categories(analyze_findings(results, None))


def test_protocol_runs_analyzed():
    protocol_results = {
        "InitializeRequest": [
            {"outcome": "crashed", "fuzz_data": {"jsonrpc": "2.0"}, "crash": {}},
            {"outcome": "timeout", "fuzz_data": {"jsonrpc": "2.0"}},
        ]
    }
    findings = analyze_findings(None, protocol_results)
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
    summary = summarize_findings(analyze_findings(results, None))
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
    assert analyze_findings(results, None) == []


def test_findings_to_dict_roundtrip():
    findings = analyze_findings(
        {"t": {"runs": [{"outcome": "timeout", "args": {"x": 1}}]}}, None
    )
    d = findings[0].to_dict()
    assert d["category"] == "hang"
    assert set(d) == {"category", "severity", "kind", "target", "run", "detail",
                      "evidence"}
