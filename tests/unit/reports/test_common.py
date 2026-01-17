#!/usr/bin/env python3
"""Tests for shared formatter helpers."""

from __future__ import annotations

import pytest

from mcp_fuzzer.reports.formatters.common import (
    calculate_protocol_success_rate,
    collect_and_summarize_protocol_items,
    collect_labeled_protocol_items,
    extract_tool_runs,
    normalize_report_data,
    result_has_failure,
    summarize_protocol_items,
)

pytestmark = [pytest.mark.unit]


def test_normalize_report_data_returns_dict_even_if_extra_keys():
    data = {"a": 1, "b": 2}
    normalized = normalize_report_data(data)
    assert normalized is data


def test_normalize_report_data_uses_to_dict_method():
    class ReportLike:
        def __init__(self):
            self.called = False

        def to_dict(self) -> dict[str, int]:
            self.called = True
            return {"converted": 1}

    report = ReportLike()
    normalized = normalize_report_data(report)
    assert normalized == {"converted": 1}
    assert report.called


def test_extract_tool_runs_from_runs_key():
    entry = {"runs": [{"success": True}]}
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}]
    assert metadata is entry


def test_extract_tool_runs_from_phase_keys():
    entry = {"realistic": [{"success": True}], "aggressive": [{"success": False}]}
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}, {"success": False}]
    assert metadata is entry


def test_extract_tool_runs_from_list():
    entry = [{"success": True}]
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}]
    assert metadata is None


def test_extract_tool_runs_from_unexpected_value():
    runs, metadata = extract_tool_runs(None)
    assert runs == []
    assert metadata is None


def test_calculate_protocol_success_rate_handles_zero_runs():
    assert calculate_protocol_success_rate(0, 1) == 0.0


def test_collect_labeled_protocol_items_filters_by_prefix():
    results = [
        {"label": "resource:file://alpha.txt", "success": True},
        {"label": "prompt:beta", "success": True},
        {"label": "tool:echo", "success": True},
        {"label": "resource:", "success": True},
        {"label": "unknown:gamma", "success": True},
        {"label": 123, "success": True},
    ]

    grouped = collect_labeled_protocol_items(results, "resource")

    assert "file://alpha.txt" in grouped
    assert "beta" not in grouped
    assert "echo" not in grouped
    assert len(grouped["file://alpha.txt"]) == 1

    tool_grouped = collect_labeled_protocol_items(results, "tool")
    assert "echo" in tool_grouped


def test_collect_and_summarize_protocol_items():
    results = [
        {"label": "prompt:alpha", "success": True},
        {"label": "prompt:alpha", "error": "boom", "success": False},
        {"label": "prompt:beta", "success": True},
    ]

    items, summary = collect_and_summarize_protocol_items(results, "prompt")

    assert set(items.keys()) == {"alpha", "beta"}
    assert summary["alpha"]["total_runs"] == 2
    assert summary["alpha"]["errors"] == 1


def test_summarize_protocol_items_detects_failures():
    items = {
        "alpha": [{"success": True}, {"success": False}],
        "beta": [{"exception": "boom"}],
    }

    summary = summarize_protocol_items(items)

    assert summary["alpha"]["errors"] == 1
    assert summary["beta"]["errors"] == 1
    assert result_has_failure({"success": False})
