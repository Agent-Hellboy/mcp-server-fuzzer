"""Tests for compact CI run summaries."""

from __future__ import annotations

import json

from mcp_fuzzer.reports.run_summary import build_run_summary, write_run_summary


def test_build_run_summary_counts_tools_protocols_and_findings():
    summary = build_run_summary(
        mode="all",
        blocked=False,
        tool_results={
            "echo": {
                "runs": [
                    {"success": True, "outcome": "server_rejected"},
                    {
                        "success": False,
                        "accepted_malformed": True,
                        "outcome": "accepted_malformed",
                    },
                ]
            }
        },
        protocol_results={
            "PingRequest": [
                {"success": True, "outcome": "server_rejected"},
                {"success": False, "server_error": "boom"},
            ]
        },
        findings_summary={"accepted_malformed": 1},
    )

    assert summary["status"] == "completed"
    assert summary["tools"]["total"] == 1
    assert summary["tools"]["total_runs"] == 2
    assert summary["tools"]["by_name"]["echo"]["outcomes"]["server_rejected"] == 1
    assert summary["tools"]["by_name"]["echo"]["outcomes"]["accepted_malformed"] == 1
    assert summary["protocols"]["total_runs"] == 2
    assert summary["findings"]["total"] == 1


def test_write_run_summary_creates_root_json(tmp_path):
    path = write_run_summary(tmp_path, {"status": "blocked"})

    assert path == tmp_path / "run_summary.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {"status": "blocked"}
