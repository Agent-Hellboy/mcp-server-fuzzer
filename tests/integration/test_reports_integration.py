#!/usr/bin/env python3
"""
Integration tests for reporting system.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_fuzzer.reports.reporter import FuzzerReporter
from mcp_fuzzer.reports.formatters import ConsoleFormatter, JSONFormatter, TextFormatter
from mcp_fuzzer.reports.safety_reporter import SafetyReporter

pytestmark = [pytest.mark.integration, pytest.mark.reports]


class TestReporterIntegration:
    """Integration tests for the complete reporting system."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def mock_safety_filter(self):
        """Create a mock safety filter for testing."""
        mock_filter = MagicMock()
        mock_filter.get_safety_statistics.return_value = {
            "total_operations_blocked": 5,
            "unique_tools_blocked": 3,
            "risk_assessment": "medium",
            "most_blocked_tool": "dangerous_tool",
            "most_blocked_tool_count": 3,
            "dangerous_content_breakdown": {"file_access": 2, "network_access": 3},
        }
        mock_filter.get_blocked_operations_summary.return_value = {
            "total_blocked": 5,
            "tools_blocked": {"dangerous_tool": 3, "another_tool": 2},
            "dangerous_content_types": {"file_access": 2, "network_access": 3},
        }
        mock_filter.blocked_operations = [
            {
                "tool_name": "dangerous_tool",
                "reason": "File access attempt",
                "arguments": {"path": "/etc/passwd"},
            },
            {
                "tool_name": "another_tool",
                "reason": "Network access attempt",
                "arguments": {"url": "http://malicious.com"},
            },
        ]
        return mock_filter

    @pytest.fixture
    def mock_system_blocker(self):
        """Create a mock system blocker for testing."""

        def mock_get_blocked_operations():
            return [
                {
                    "command": "xdg-open",
                    "args": "http://malicious.com",
                    "timestamp": "2024-01-01T12:00:00.000Z",
                },
                {
                    "command": "firefox",
                    "args": "--new-window",
                    "timestamp": "2024-01-01T12:01:00.000Z",
                },
            ]

        def mock_is_system_blocking_active():
            return True

        return {
            "get_blocked_operations": mock_get_blocked_operations,
            "is_system_blocking_active": mock_is_system_blocking_active,
        }

    def test_reporter_safety_integration(
        self, temp_output_dir, mock_safety_filter, mock_system_blocker
    ):
        """Test integration between reporter and safety system."""
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Mock the safety components on the reporter instance
        reporter.safety_reporter.safety_filter = mock_safety_filter
        reporter.safety_reporter.get_blocked_operations = mock_system_blocker[
            "get_blocked_operations"
        ]
        reporter.safety_reporter.is_system_blocking_active = mock_system_blocker[
            "is_system_blocking_active"
        ]

        # Test safety data collection
        safety_data = reporter.safety_reporter.get_comprehensive_safety_data()

        # Verify safety data structure
        assert "safety_system" in safety_data
        assert safety_data["safety_system"]["active"] is True
        assert safety_data["safety_system"]["summary"]["total_blocked"] == 5
        assert "system_safety" in safety_data
        assert safety_data["system_safety"]["active"] is True
        assert safety_data["system_safety"]["total_blocked"] == 2

    def test_end_to_end_reporting_workflow(self, temp_output_dir):
        """Test complete end-to-end reporting workflow."""
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Set up fuzzing session
        reporter.set_fuzzing_metadata(
            mode="tool",
            protocol="stdio",
            endpoint="test_endpoint",
            runs=100,
            runs_per_type=10,
        )

        # Add tool results
        tool_results = {
            "test_tool": [
                {"success": True, "response": "test_response"},
                {"exception": "test_exception", "error": "test_error"},
                {"safety_blocked": True, "reason": "dangerous_operation"},
            ]
        }
        reporter.print_tool_summary(tool_results)

        # Add protocol results
        protocol_results = {
            "test_protocol": [
                {"success": True, "response": "test_response"},
                {"error": "test_error", "server_error": "server_error"},
            ]
        }
        reporter.print_protocol_summary(protocol_results)

        # Add safety data
        reporter.add_safety_data({"blocked_operations": 5, "risk_level": "medium"})

        # Generate final report
        report_file = reporter.generate_final_report(include_safety=False)

        # Verify report was created
        assert Path(report_file).exists()
        assert "fuzzing_report_" in report_file
        assert reporter.session_id in report_file

        # Verify report content
        with open(report_file, "r") as f:
            report_data = json.load(f)

        assert report_data["metadata"]["mode"] == "tool"
        assert report_data["metadata"]["protocol"] == "stdio"
        assert "test_tool" in report_data["tool_results"]
        assert "test_protocol" in report_data["protocol_results"]
        assert report_data["summary"]["tools"]["total_tools"] == 1
        assert report_data["summary"]["tools"]["total_runs"] == 3
        assert report_data["summary"]["protocols"]["total_protocol_types"] == 1
        assert report_data["summary"]["protocols"]["total_runs"] == 2

    def test_formatter_integration(self, temp_output_dir):
        """Test integration between different formatters."""
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Test data
        tool_results = {
            "tool1": [
                {"success": True},
                {"exception": "test_exception"},
                {"safety_blocked": True},
            ],
            "tool2": [{"success": True}],
        }

        protocol_results = {"protocol1": [{"success": True}, {"error": "test_error"}]}

        # Test console formatter
        with patch.object(
            reporter.console_formatter, "print_tool_summary"
        ) as mock_print_tool:
            reporter.print_tool_summary(tool_results)
            mock_print_tool.assert_called_once_with(tool_results)

        # Test JSON formatter
        json_formatted = reporter.json_formatter.format_tool_results(tool_results)
        assert json_formatted["tool_results"] == tool_results
        assert "summary" in json_formatted
        assert "tool1" in json_formatted["summary"]
        assert json_formatted["summary"]["tool1"]["total_runs"] == 3
        assert json_formatted["summary"]["tool1"]["exceptions"] == 1
        assert json_formatted["summary"]["tool1"]["safety_blocked"] == 1

        # Test text formatter
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            report_data = {
                "metadata": {"session_id": "test_session"},
                "tool_results": tool_results,
                "protocol_results": protocol_results,
            }

            reporter.text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "MCP FUZZER REPORT" in content
            assert "Tool: tool1" in content
            assert "Total Runs: 3" in content
            assert "Protocol Type: protocol1" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_safety_reporter_integration(self, mock_safety_filter, mock_system_blocker):
        """Test safety reporter integration with safety components."""
        safety_reporter = SafetyReporter()

        # Mock the safety components on the reporter instance
        safety_reporter.safety_filter = mock_safety_filter
        safety_reporter.get_blocked_operations = mock_system_blocker[
            "get_blocked_operations"
        ]
        safety_reporter.is_system_blocking_active = mock_system_blocker[
            "is_system_blocking_active"
        ]

        # Test safety summary
        with patch.object(safety_reporter.console, "print") as mock_print:
            safety_reporter.print_safety_summary()
            assert mock_print.call_count > 0

        # Test comprehensive safety report
        with patch.object(safety_reporter.console, "print") as mock_print:
            safety_reporter.print_comprehensive_safety_report()
            assert mock_print.call_count > 0

        # Test blocked operations summary
        with patch.object(safety_reporter.console, "print") as mock_print:
            safety_reporter.print_blocked_operations_summary()
            assert mock_print.call_count > 0

    def test_reporter_error_handling(self, temp_output_dir):
        """Test reporter error handling and edge cases."""
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Test with invalid output directory
        with pytest.raises((OSError, PermissionError)):
            FuzzerReporter(output_dir="/invalid/path/that/does/not/exist")

        # Test with empty results
        reporter.print_tool_summary({})
        reporter.print_protocol_summary({})

        # Test with malformed data
        malformed_results = {
            "tool1": [
                {"success": True},
                {},  # Empty result
                {"exception": None},  # None exception
                {"safety_blocked": "not_boolean"},  # Wrong type
            ]
        }

        # Should not raise exceptions
        reporter.print_tool_summary(malformed_results)

        # Test status with malformed data
        status = reporter.get_current_status()
        assert status["tool_results_count"] == 1  # Should count malformed results
        assert status["protocol_results_count"] == 0
        assert status["safety_data_available"] is False

    def test_cross_module_integration(self, temp_output_dir):
        """Test integration across different reporting modules."""
        # Test that all formatters work together
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Create test data
        test_data = {
            "tool1": [
                {"success": True, "response": "success"},
                {"exception": "test_exception", "error": "test_error"},
                {"safety_blocked": True, "reason": "dangerous"},
            ]
        }

        # Test that console formatter can handle the data
        with patch.object(
            reporter.console_formatter, "print_tool_summary"
        ) as mock_print:
            reporter.print_tool_summary(test_data)
            mock_print.assert_called_once()

        # Test that JSON formatter can handle the data
        json_result = reporter.json_formatter.format_tool_results(test_data)
        assert "tool1" in json_result["summary"]

        # Test that text formatter can handle the data
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            temp_filename = temp_file.name

        try:
            report_data = {
                "metadata": {"session_id": "test_session"},
                "tool_results": test_data,
            }

            reporter.text_formatter.save_text_report(report_data, temp_filename)

            with open(temp_filename, "r") as f:
                content = f.read()

            assert "Tool: tool1" in content
            assert "Total Runs: 3" in content

        finally:
            import os

            os.unlink(temp_filename)

    def test_reporter_performance_with_large_data(self, temp_output_dir):
        """Test reporter performance with large datasets."""
        reporter = FuzzerReporter(output_dir=temp_output_dir)

        # Create large dataset
        large_tool_results = {}
        for i in range(100):  # 100 tools
            tool_name = f"tool_{i}"
            results = []
            for j in range(1000):  # 1000 results per tool
                if j % 10 == 0:
                    results.append({"exception": f"exception_{j}"})
                elif j % 20 == 0:
                    results.append({"safety_blocked": True})
                else:
                    results.append({"success": True, "response": f"response_{j}"})
            large_tool_results[tool_name] = results

        # Test that reporter can handle large data
        reporter.print_tool_summary(large_tool_results)

        # Verify all data was stored
        assert len(reporter.tool_results) == 100
        assert sum(len(results) for results in reporter.tool_results.values()) == 100000

        # Test summary generation with large data
        stats = reporter._generate_summary_stats()
        assert stats["tools"]["total_tools"] == 100
        assert stats["tools"]["total_runs"] == 100000
        assert stats["tools"]["tools_with_exceptions"] == 10000  # 10% exceptions
        assert stats["tools"]["tools_with_errors"] == 0  # No errors, only exceptions

        # Test final report generation with large data
        report_file = reporter.generate_final_report(include_safety=False)
        assert Path(report_file).exists()

        # Verify report file is reasonable size (not too large)
        file_size = Path(report_file).stat().st_size
        assert file_size < 50 * 1024 * 1024  # Less than 50MB
