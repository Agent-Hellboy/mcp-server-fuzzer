#!/usr/bin/env python3
"""
Unit tests for report formatter helpers.
"""

from types import SimpleNamespace

from mcp_fuzzer.reports.formatters.common import (
    normalize_report_data,
    extract_tool_runs,
    calculate_tool_success_rate,
)


def test_normalize_report_data_uses_to_dict():
    report = SimpleNamespace(to_dict=lambda: {"ok": True})
    assert normalize_report_data(report) == {"ok": True}


def test_extract_tool_runs_variants():
    runs, entry = extract_tool_runs({"runs": [{"ok": True}]})
    assert runs == [{"ok": True}]
    assert entry == {"runs": [{"ok": True}]}

    runs, entry = extract_tool_runs({"realistic": [{"a": 1}], "aggressive": []})
    assert runs == [{"a": 1}]
    assert entry["realistic"] == [{"a": 1}]

    runs, entry = extract_tool_runs([{"ok": True}])
    assert runs == [{"ok": True}]
    assert entry is None

    runs, entry = extract_tool_runs("nope")
    assert runs == []
    assert entry is None


def test_calculate_tool_success_rate():
    assert calculate_tool_success_rate(0, 0, 0) == 0.0
    assert calculate_tool_success_rate(10, 2, 3) == 50.0
