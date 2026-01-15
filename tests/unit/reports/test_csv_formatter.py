#!/usr/bin/env python3
"""Tests for the CSV formatter implementation."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from mcp_fuzzer.reports.formatters.csv_fmt import CSVFormatter

pytestmark = [pytest.mark.unit]


def _read_csv(path: Path) -> list[list[str]]:
    with path.open() as fh:
        return list(csv.reader(fh))


def test_save_csv_report_writes_expected_rows(tmp_path: Path):
    report_data = {
        "tool_results": {
            "tool-a": [
                {
                    "success": True,
                    "response_time": 0.12,
                    "exception": "boom",
                    "args": {"key": "value"},
                    "timestamp": "2023-01-01T10:00:00Z",
                }
            ]
        }
    }

    output = tmp_path / "report.csv"
    CSVFormatter().save_csv_report(report_data, output)

    rows = _read_csv(output)
    assert rows[0] == [
        "Tool Name",
        "Run Number",
        "Success",
        "Response Time",
        "Exception Message",
        "Arguments",
        "Timestamp",
    ]
    assert rows[1] == [
        "tool-a",
        "1",
        "True",
        "0.12",
        "boom",
        "{'key': 'value'}",
        "2023-01-01T10:00:00Z",
    ]


def test_save_csv_report_accepts_supports_to_dict(tmp_path: Path):
    class ReportLike:
        def to_dict(self) -> dict[str, list]:
            return {
                "tool_results": {
                    "x": [
                        {
                            "success": False,
                            "response_time": "",
                            "exception": "",
                            "args": "",
                            "timestamp": "",
                        }
                    ]
                }
            }

    output = tmp_path / "support.csv"
    CSVFormatter().save_csv_report(ReportLike(), output)

    rows = _read_csv(output)
    assert rows[0][0] == "Tool Name"
    assert rows[1][0] == "x"


def test_save_csv_report_multiple_tools_and_runs(tmp_path: Path):
    report_data = {
        "tool_results": {
            "tool-x": [{"success": True}, {"success": False}],
            "tool-y": [{"success": True}],
        }
    }

    output = tmp_path / "multi.csv"
    CSVFormatter().save_csv_report(report_data, output)

    rows = _read_csv(output)
    assert len(rows) == 1 + 3
    tool_names = [row[0] for row in rows[1:]]
    assert tool_names.count("tool-x") == 2
    assert tool_names.count("tool-y") == 1


def test_save_csv_report_with_runs_key(tmp_path: Path):
    report_data = {
        "tool_results": {"tool-x": {"runs": [{"success": True}, {"success": True}]}}
    }

    output = tmp_path / "runs_key.csv"
    CSVFormatter().save_csv_report(report_data, output)

    rows = _read_csv(output)
    assert len(rows) == 1 + 2
    assert all(row[0] == "tool-x" for row in rows[1:])


def test_save_csv_report_with_realistic_aggressive(tmp_path: Path):
    report_data = {
        "tool_results": {
            "tool-x": {
                "realistic": [{"success": True}],
                "aggressive": [{"success": False}],
            }
        }
    }

    output = tmp_path / "phases.csv"
    CSVFormatter().save_csv_report(report_data, output)

    rows = _read_csv(output)
    assert len(rows) == 1 + 2
