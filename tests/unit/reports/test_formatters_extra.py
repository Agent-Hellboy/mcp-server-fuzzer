#!/usr/bin/env python3
"""Additional formatter tests that exercise HTML/Markdown/Text/XML outputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_fuzzer.reports.formatters.html_fmt import HTMLFormatter
from mcp_fuzzer.reports.formatters.markdown_fmt import MarkdownFormatter
from mcp_fuzzer.reports.formatters.text_fmt import TextFormatter
from mcp_fuzzer.reports.formatters.xml_fmt import XMLFormatter

pytestmark = [pytest.mark.unit]


@pytest.fixture
def sample_report():
    return {
        "metadata": {"session": "ci-run", "version": "1.0"},
        "spec_summary": {
            "totals": {"total": 1, "failed": 0, "warned": 1, "passed": 0},
            "by_spec_id": {
                "MCP-Test": {"failed": 0, "warned": 1, "passed": 0, "total": 1}
            },
        },
        "summary": {
            "tools": {
                "total_tools": 1,
                "total_runs": 2,
                "tools_with_errors": 0,
                "tools_with_exceptions": 1,
                "success_rate": 50.0,
            },
            "protocols": {
                "total_protocol_types": 1,
                "total_runs": 1,
                "protocol_types_with_errors": 0,
                "protocol_types_with_exceptions": 0,
                "success_rate": 100.0,
            },
        },
        "tool_results": {
            "demo-tool": [
                {"success": True, "exception": ""},
                {"success": False, "exception": "boom"},
            ]
        },
        "protocol_results": {
            "http": [{"success": True}],
            "ReadResourceRequest": [
                {"success": True, "label": "resource:file://alpha.txt"},
                {"success": False, "error": "nope", "label": "resource:file://alpha.txt"},
            ],
            "GetPromptRequest": [
                {"success": True, "label": "prompt:beta"},
            ],
        },
        "safety": {
            "summary": {
                "total_blocked": 1,
                "unique_tools_blocked": 1,
                "risk_assessment": "low",
            }
        },
    }


def test_html_formatter_outputs_metadata_and_scores(tmp_path: Path, sample_report):
    out = tmp_path / "report.html"
    HTMLFormatter().save_html_report(sample_report, out, title="<Browser>")
    text = out.read_text()
    assert "<h2>Metadata</h2>" in text
    assert "&lt;Browser&gt;" in text  # title should be escaped
    assert "<h2>Spec Guard Summary</h2>" in text
    assert "<td>demo-tool</td>" in text
    assert 'class="success">True<' in text
    assert 'class="error">False<' in text
    assert "<h2>Protocol Results</h2>" in text
    assert "<h2>Resource Item Summary</h2>" in text
    assert "<h2>Prompt Item Summary</h2>" in text


def test_markdown_formatter_generates_expected_sections(tmp_path: Path, sample_report):
    out = tmp_path / "report.md"
    MarkdownFormatter().save_markdown_report(sample_report, out)
    text = out.read_text()
    assert "## Metadata" in text
    assert "## Spec Guard Summary" in text
    assert "| Spec ID | Failed" in text
    assert "### demo-tool" in text
    assert "✔" in text
    assert "❌" in text
    assert "## Protocol Results" in text
    assert "## Resource Item Summary" in text
    assert "## Prompt Item Summary" in text


def test_text_formatter_includes_summary_blocks(tmp_path: Path, sample_report):
    out = tmp_path / "report.txt"
    TextFormatter().save_text_report(sample_report, out)
    text = out.read_text()
    assert "FUZZING SESSION METADATA" in text
    assert "SUMMARY STATISTICS" in text
    assert "Tools Tested: 1" in text
    assert "Protocol Success Rate: 100.0%" in text
    assert "SPEC GUARD SUMMARY" in text
    assert "demo-tool" in text
    assert "SAFETY SYSTEM DATA" in text


def test_xml_formatter_structures_nodes(tmp_path: Path, sample_report):
    out = tmp_path / "report.xml"
    XMLFormatter().save_xml_report(sample_report, out)
    text = out.read_text()
    assert "<metadata>" in text
    assert 'name="session"' in text or "session" in text
    assert "<tool-results>" in text
    assert 'name="demo-tool"' in text
