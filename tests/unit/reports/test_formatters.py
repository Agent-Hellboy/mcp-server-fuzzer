#!/usr/bin/env python3
"""
Tests for formatters module.
"""

import tempfile
from unittest.mock import MagicMock, patch, mock_open

import pytest

from mcp_fuzzer.reports.formatters import (
    ConsoleFormatter,
    JSONFormatter,
    TextFormatter,
    calculate_tool_success_rate,
)


class TestCalculateToolSuccessRate:
    """Test cases for calculate_tool_success_rate function."""

    def test_calculate_success_rate_normal_case(self):
        """Test calculating success rate with normal values."""
        result = calculate_tool_success_rate(100, 10, 5)
        assert result == 85.0  # (100 - 10 - 5) / 100 * 100

    def test_calculate_success_rate_zero_total_runs(self):
        """Test calculating success rate with zero total runs."""
        result = calculate_tool_success_rate(0, 10, 5)
        assert result == 0.0

    def test_calculate_success_rate_negative_total_runs(self):
        """Test calculating success rate with negative total runs."""
        result = calculate_tool_success_rate(-10, 5, 2)
        assert result == 0.0

    def test_calculate_success_rate_more_exceptions_than_runs(self):
        """Test calculating success rate when exceptions exceed total runs."""
        result = calculate_tool_success_rate(10, 15, 5)
        assert result == 0.0  # max(0, 10 - 15 - 5) = 0

    def test_calculate_success_rate_more_safety_blocked_than_runs(self):
        """Test calculating success rate when safety blocked exceed total runs."""
        result = calculate_tool_success_rate(10, 5, 15)
        assert result == 0.0  # max(0, 10 - 5 - 15) = 0

    def test_calculate_success_rate_perfect_success(self):
        """Test calculating success rate with no exceptions or safety blocks."""
        result = calculate_tool_success_rate(100, 0, 0)
        assert result == 100.0


class TestConsoleFormatter:
    """Test cases for ConsoleFormatter class."""

    @pytest.fixture
    def console_formatter(self):
        """Create a ConsoleFormatter instance for testing."""
        mock_console = MagicMock()
        return ConsoleFormatter(mock_console)

    def test_init(self, console_formatter):
        """Test ConsoleFormatter initialization."""
        assert console_formatter.console is not None

    def test_print_tool_summary_empty_results(self, console_formatter):
        """Test printing tool summary with empty results."""
        console_formatter.print_tool_summary({})

        console_formatter.console.print.assert_called_once_with(
            "[yellow]No tool results to display[/yellow]"
        )

    def test_print_tool_summary_with_results(self, console_formatter):
        """Test printing tool summary with results."""
        results = {
            "test_tool": [
                {"success": True},
                {"exception": "test_exception"},
                {"safety_blocked": True},
            ]
        }

        console_formatter.print_tool_summary(results)

        # Verify console.print was called (once for table)
        assert console_formatter.console.print.call_count == 1

        # Verify table was created and printed
        call_args = console_formatter.console.print.call_args[0]
        assert len(call_args) == 1  # Should be a table object

    def test_print_protocol_summary_empty_results(self, console_formatter):
        """Test printing protocol summary with empty results."""
        console_formatter.print_protocol_summary({})

        console_formatter.console.print.assert_called_once_with(
            "[yellow]No protocol results to display[/yellow]"
        )

    def test_print_protocol_summary_with_results(self, console_formatter):
        """Test printing protocol summary with results."""
        results = {
            "test_protocol": [
                {"success": True},
                {"success": False, "error": "test_error"},
            ]
        }

        console_formatter.print_protocol_summary(results)

        # Verify console.print was called (once for table)
        assert console_formatter.console.print.call_count == 1

    def test_print_overall_summary_with_results(self, console_formatter):
        """Test printing overall summary with results."""
        tool_results = {
            "tool1": [
                {"success": True},
                {"exception": "test_exception"},
                {"error": "test_error"},
            ]
        }
        protocol_results = {"protocol1": [{"success": True}, {"error": "test_error"}]}

        console_formatter.print_overall_summary(tool_results, protocol_results)

        # Verify console.print was called multiple times
        assert console_formatter.console.print.call_count > 0

        # Check that the summary text was printed
        print_calls = [
            call[0][0] for call in console_formatter.console.print.call_args_list
        ]
        summary_text = "\n".join(print_calls)
        assert "Overall Statistics:" in summary_text
        assert "Total tools tested: 1" in summary_text
        assert "Total protocol types tested: 1" in summary_text


class TestJSONFormatter:
    """Test cases for JSONFormatter class."""

    @pytest.fixture
    def json_formatter(self):
        """Create a JSONFormatter instance for testing."""
        return JSONFormatter()

    def test_format_tool_results_empty(self, json_formatter):
        """Test formatting empty tool results."""
        result = json_formatter.format_tool_results({})

        assert result["tool_results"] == {}
        assert result["summary"] == {}

    def test_format_tool_results_with_data(self, json_formatter):
        """Test formatting tool results with data."""
        results = {
            "test_tool": [
                {"success": True},
                {"exception": "test_exception"},
                {"safety_blocked": True},
            ]
        }

        formatted = json_formatter.format_tool_results(results)

        assert formatted["tool_results"] == results
        assert "summary" in formatted
        assert "test_tool" in formatted["summary"]

        tool_summary = formatted["summary"]["test_tool"]
        assert tool_summary["total_runs"] == 3
        assert tool_summary["exceptions"] == 1
        assert tool_summary["safety_blocked"] == 1
        assert tool_summary["success_rate"] == 33.33  # (3-1-1)/3 * 100

    def test_format_protocol_results_empty(self, json_formatter):
        """Test formatting empty protocol results."""
        result = json_formatter.format_protocol_results({})

        assert result["protocol_results"] == {}
        assert result["summary"] == {}

    def test_format_protocol_results_with_data(self, json_formatter):
        """Test formatting protocol results with data."""
        results = {
            "test_protocol": [
                {"success": True},
                {"success": False, "error": "test_error"},
            ]
        }

        formatted = json_formatter.format_protocol_results(results)

        assert formatted["protocol_results"] == results
        assert "summary" in formatted
        assert "test_protocol" in formatted["summary"]

        protocol_summary = formatted["summary"]["test_protocol"]
        assert protocol_summary["total_runs"] == 2
        assert protocol_summary["errors"] == 1
        assert protocol_summary["success_rate"] == 50.0  # (2-1)/2 * 100

    def test_generate_tool_summary_empty(self, json_formatter):
        """Test generating tool summary with empty results."""
        summary = json_formatter._generate_tool_summary({})
        assert summary == {}

    def test_generate_tool_summary_with_data(self, json_formatter):
        """Test generating tool summary with data."""
        results = {
            "tool1": [{"success": True}, {"exception": "test_exception"}],
            "tool2": [{"safety_blocked": True}],
        }

        summary = json_formatter._generate_tool_summary(results)

        assert "tool1" in summary
        assert "tool2" in summary

        tool1_summary = summary["tool1"]
        assert tool1_summary["total_runs"] == 2
        assert tool1_summary["exceptions"] == 1
        assert tool1_summary["safety_blocked"] == 0
        assert tool1_summary["success_rate"] == 50.0

        tool2_summary = summary["tool2"]
        assert tool2_summary["total_runs"] == 1
        assert tool2_summary["exceptions"] == 0
        assert tool2_summary["safety_blocked"] == 1
        assert tool2_summary["success_rate"] == 0.0

    def test_generate_protocol_summary_empty(self, json_formatter):
        """Test generating protocol summary with empty results."""
        summary = json_formatter._generate_protocol_summary({})
        assert summary == {}

    def test_generate_protocol_summary_with_data(self, json_formatter):
        """Test generating protocol summary with data."""
        results = {
            "protocol1": [{"success": True}, {"success": False}],
            "protocol2": [{"success": True}],
        }

        summary = json_formatter._generate_protocol_summary(results)

        assert "protocol1" in summary
        assert "protocol2" in summary

        protocol1_summary = summary["protocol1"]
        assert protocol1_summary["total_runs"] == 2
        assert protocol1_summary["errors"] == 1
        assert protocol1_summary["success_rate"] == 50.0

        protocol2_summary = summary["protocol2"]
        assert protocol2_summary["total_runs"] == 1
        assert protocol2_summary["errors"] == 0
        assert protocol2_summary["success_rate"] == 100.0


class TestTextFormatter:
    """Test cases for TextFormatter class."""

    @pytest.fixture
    def text_formatter(self):
        """Create a TextFormatter instance for testing."""
        return TextFormatter()

    def test_save_text_report_basic(self, text_formatter):
        """Test saving basic text report."""
        report_data = {
            "metadata": {
                "session_id": "test_session",
                "mode": "tool",
                "protocol": "stdio",
            },
            "summary": {
                "tools": {
                    "total_tools": 2,
                    "total_runs": 10,
                    "tools_with_errors": 1,
                    "tools_with_exceptions": 2,
                    "success_rate": 70.0,
                },
                "protocols": {
                    "total_protocol_types": 1,
                    "total_runs": 5,
                    "protocol_types_with_errors": 0,
                    "protocol_types_with_exceptions": 1,
                    "success_rate": 80.0,
                },
            },
            "tool_results": {
                "test_tool": [{"success": True}, {"exception": "test_exception"}]
            },
            "protocol_results": {"test_protocol": [{"success": True}]},
        }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            # Read the file and verify content
            with open(temp_filename, "r") as f:
                content = f.read()

            assert "MCP FUZZER REPORT" in content
            assert "FUZZING SESSION METADATA" in content
            assert "SUMMARY STATISTICS" in content
            assert "TOOL FUZZING RESULTS" in content
            assert "PROTOCOL FUZZING RESULTS" in content
            assert "test_session" in content
            assert "Tools Tested: 2" in content
            assert "Total Tool Runs: 10" in content
            assert "Tool Success Rate: 70.0%" in content

        finally:
            # Clean up
            import os

            os.unlink(temp_filename)

    def test_save_text_report_with_safety_data(self, text_formatter):
        """Test saving text report with safety data."""
        report_data = {
            "metadata": {"session_id": "test_session"},
            "summary": {},
            "safety": {
                "summary": {
                    "total_blocked": 5,
                    "unique_tools_blocked": 3,
                    "risk_assessment": "medium",
                }
            },
        }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "SAFETY SYSTEM DATA" in content
            assert "Total Operations Blocked: 5" in content
            assert "Unique Tools Blocked: 3" in content
            assert "Risk Assessment: MEDIUM" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_save_text_report_minimal_data(self, text_formatter):
        """Test saving text report with minimal data."""
        report_data = {"metadata": {"session_id": "test_session"}}

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "MCP FUZZER REPORT" in content
            assert "FUZZING SESSION METADATA" in content
            assert "test_session" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_save_text_report_empty_data(self, text_formatter):
        """Test saving text report with empty data."""
        report_data = {}

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "MCP FUZZER REPORT" in content
            assert "Report generated by MCP Fuzzer" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_save_text_report_file_creation_error(self, text_formatter):
        """Test handling file creation errors."""
        report_data = {"metadata": {"session_id": "test_session"}}

        # Test with invalid filename
        with pytest.raises((OSError, IOError)):
            text_formatter.save_text_report(report_data, "/invalid/path/file.txt")

    def test_save_text_report_tool_results_detailed(self, text_formatter):
        """Test saving text report with detailed tool results."""
        report_data = {
            "tool_results": {
                "tool1": [
                    {"success": True},
                    {"exception": "test_exception"},
                    {"safety_blocked": True},
                ],
                "tool2": [{"success": True}],
            }
        }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "Tool: tool1" in content
            assert "Total Runs: 3" in content
            assert "Exceptions: 1" in content
            assert "Safety Blocked: 1" in content
            assert "Success Rate: 33.3%" in content

            assert "Tool: tool2" in content
            assert "Total Runs: 1" in content
            assert "Success Rate: 100.0%" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_save_text_report_protocol_results_detailed(self, text_formatter):
        """Test saving text report with detailed protocol results."""
        report_data = {
            "protocol_results": {
                "protocol1": [
                    {"success": True},
                    {"success": False, "error": "test_error"},
                ],
                "protocol2": [{"success": True}],
            }
        }

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "Protocol Type: protocol1" in content
            assert "Total Runs: 2" in content
            assert "Errors: 1" in content
            assert "Success Rate: 50.0%" in content

            assert "Protocol Type: protocol2" in content
            assert "Total Runs: 1" in content
            assert "Success Rate: 100.0%" in content

        finally:
            import os

            os.unlink(temp_filename)
