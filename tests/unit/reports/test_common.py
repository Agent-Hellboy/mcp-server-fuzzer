#!/usr/bin/env python3
"""Tests for shared formatter helpers."""

from __future__ import annotations

import pytest

from mcp_fuzzer.reports.formatters.common import (
    extract_tool_runs,
    normalize_report_data,
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
