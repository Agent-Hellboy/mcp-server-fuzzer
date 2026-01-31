#!/usr/bin/env python3
"""
Unit tests for security summary aggregation in reports.
"""

from __future__ import annotations

from datetime import datetime

from mcp_fuzzer.reports.core.collector import ReportCollector
from mcp_fuzzer.reports.core.models import FuzzingMetadata


def _make_metadata() -> FuzzingMetadata:
    return FuzzingMetadata(
        session_id="sess-123",
        mode="tools",
        protocol="http",
        endpoint="http://localhost",
        runs=1,
        runs_per_type=None,
        fuzzer_version="dev",
        start_time=datetime.now(),
    )


def test_security_summary_tracks_oracles_and_policy_controls():
    collector = ReportCollector()
    collector.add_tool_results(
        "probe-tool",
        [
            {
                "oracle_findings": [
                    {"oracle": "filesystem", "type": "created", "path": "/tmp/test"}
                ],
                "policy_violations": [
                    {
                        "domain": "authz",
                        "type": "missing_auth",
                        "controls": ["MCP-AUTHZ-01"],
                    }
                ],
            }
        ],
    )

    snapshot = collector.snapshot(_make_metadata())
    summary = snapshot.security_summary

    assert summary["oracle_findings_by_type"]["filesystem"] == 1
    assert summary["policy_violations_by_domain"]["authz"] == 1
    assert summary["policy_controls"]["MCP-AUTHZ-01"] == 1
