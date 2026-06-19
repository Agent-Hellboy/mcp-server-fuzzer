"""Tests for tool discovery diagnostics."""

from __future__ import annotations

from mcp_fuzzer.diagnostics.tool_discovery import (
    ToolDiscoveryFailure,
    ToolDiscoveryReport,
    classify_tool_discovery_error,
    classify_tools_list_response,
)


def test_classify_stdio_parse_error():
    report = classify_tool_discovery_error(
        RuntimeError("Failed to receive message from stdio transport: Expecting value")
    )
    assert report.failure is ToolDiscoveryFailure.STDIO_PARSE_ERROR


def test_classify_auth_error_from_tools_list():
    report = classify_tools_list_response(
        {"error": {"code": 401, "message": "Unauthorized"}}
    )
    assert report is not None
    assert report.failure is ToolDiscoveryFailure.AUTH_REQUIRED


def test_success_report_serializes():
    report = ToolDiscoveryReport.success(3)
    payload = report.to_dict()
    assert payload["tool_count"] == 3
    assert payload["failure"] == "none"
