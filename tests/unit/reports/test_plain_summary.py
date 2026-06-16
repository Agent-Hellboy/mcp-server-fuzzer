#!/usr/bin/env python3
"""Tests for plain-text stdout summaries."""

from __future__ import annotations

from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary


def test_write_stdout_summary_protocol_mode(capsys):
    write_stdout_summary(
        mode="protocol",
        tool_results=None,
        protocol_results={
            "PingRequest": [
                {
                    "outcome": "server_rejected",
                    "success": True,
                },
                {
                    "accepted_malformed": True,
                    "success": False,
                },
            ]
        },
    )
    captured = capsys.readouterr()
    assert "MCP Fuzzer Summary" in captured.out
    assert "Protocol Results:" in captured.out
    assert "PingRequest:" in captured.out
    assert "server-rejected" in captured.out
    assert "accepted-malformed" in captured.out


def test_write_stdout_summary_skips_non_list_protocol_entries(capsys):
    write_stdout_summary(
        mode="protocol",
        tool_results=None,
        protocol_results={"Broken": {"not": "a list"}},
    )
    captured = capsys.readouterr()
    assert "Protocol Results:" in captured.out
    assert "Broken" not in captured.out

    write_stdout_summary(
        mode="all",
        tool_results={
            "echo": {
                "runs": [
                    {
                        "success": True,
                        "safety_blocked": False,
                        "safety_sanitized": False,
                    }
                ]
            }
        },
        protocol_results={
            "PingRequest": [
                {
                    "outcome": "server_rejected",
                    "success": True,
                }
            ]
        },
    )
    captured = capsys.readouterr()
    assert "Tool Results:" in captured.out
    assert "Protocol Results:" in captured.out
    assert "echo:" in captured.out
