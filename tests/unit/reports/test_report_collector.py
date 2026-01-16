#!/usr/bin/env python3
"""Unit tests for ReportCollector."""

from datetime import datetime

import pytest

from mcp_fuzzer.reports.core.collector import ReportCollector
from mcp_fuzzer.reports.core.models import FuzzingMetadata


def _metadata():
    return FuzzingMetadata(
        session_id="sid",
        mode="tools",
        protocol="stdio",
        endpoint="endpoint",
        runs=2,
        runs_per_type=None,
        fuzzer_version="0.1",
        start_time=datetime.now(),
    )


def test_build_summary_counts():
    collector = ReportCollector()
    collector.add_tool_results(
        "tool_a",
        [
            {"success": True},
            {"success": False, "error": "bad"},
            {"exception": "boom"},
        ],
    )
    collector.add_protocol_results(
        "InitializeRequest",
        [
            {"success": True},
            {"success": False},
            {"exception": "bad"},
        ],
    )

    summary = collector.build_summary()

    assert summary.tools.total_tools == 1
    assert summary.tools.total_runs == 3
    assert summary.tools.tools_with_errors == 1
    assert summary.tools.tools_with_exceptions == 1
    assert summary.protocols.total_protocol_types == 1
    assert summary.protocols.total_runs == 3
    assert summary.protocols.protocol_types_with_errors == 1
    assert summary.protocols.protocol_types_with_exceptions == 1


def test_snapshot_builds_spec_summary_and_safety():
    collector = ReportCollector()
    collector.add_spec_checks(
        [
            {"spec_id": "S1", "status": "FAIL"},
            {"spec_id": "S1", "status": "WARN"},
        ]
    )
    collector.add_tool_results(
        "tool_a",
        [
            {
                "success": True,
                "spec_checks": [{"spec_id": "S2", "status": "PASS"}],
            }
        ],
    )
    collector.update_safety_data({"blocked": 1})

    snapshot = collector.snapshot(_metadata(), include_safety=False)

    assert snapshot.safety_data == {}
    assert snapshot.spec_summary["totals"]["total"] == 3
    assert snapshot.spec_summary["totals"]["failed"] == 1
    assert snapshot.spec_summary["totals"]["warned"] == 1
    assert snapshot.spec_summary["totals"]["passed"] == 1


def test_collect_errors_tool_and_protocol():
    collector = ReportCollector()
    collector.add_tool_results(
        "tool_a",
        [
            {"exception": "boom"},
            {"error": "bad"},
        ],
    )
    collector.add_protocol_results(
        "InitializeRequest",
        [
            {"error": "oops"},
        ],
    )

    errors = collector.collect_errors()

    assert len(errors) == 3
    assert errors[0]["severity"] == "high"
    assert errors[1]["severity"] == "medium"
    assert errors[2]["type"] == "protocol_error"
