#!/usr/bin/env python3
"""
Tests for FuzzerReporter class.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from mcp_fuzzer.reports.reporter import FuzzerReporter


class TestFuzzerReporter:
    """Test cases for FuzzerReporter class."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def reporter(self, temp_output_dir):
        """Create a FuzzerReporter instance for testing."""
        with patch("mcp_fuzzer.reports.reporter.Console") as mock_console:
            with patch(
                "mcp_fuzzer.reports.reporter.ConsoleFormatter"
            ) as mock_console_formatter:
                with patch(
                    "mcp_fuzzer.reports.reporter.JSONFormatter"
                ) as mock_json_formatter:
                    with patch(
                        "mcp_fuzzer.reports.reporter.TextFormatter"
                    ) as mock_text_formatter:
                        with patch(
                            "mcp_fuzzer.reports.reporter.SafetyReporter"
                        ) as mock_safety_reporter:
                            reporter = FuzzerReporter(output_dir=temp_output_dir)
                            reporter.console = mock_console.return_value
                            reporter.console_formatter = (
                                mock_console_formatter.return_value
                            )
                            reporter.json_formatter = mock_json_formatter.return_value
                            reporter.text_formatter = mock_text_formatter.return_value
                            reporter.safety_reporter = mock_safety_reporter.return_value
                            return reporter

    def test_init_default_output_dir(self):
        """Test initialization with default output directory."""
        with patch("mcp_fuzzer.reports.reporter.Path.mkdir") as mock_mkdir:
            with patch("mcp_fuzzer.reports.reporter.Console") as mock_console:
                with patch("mcp_fuzzer.reports.reporter.ConsoleFormatter"):
                    with patch("mcp_fuzzer.reports.reporter.JSONFormatter"):
                        with patch("mcp_fuzzer.reports.reporter.TextFormatter"):
                            with patch("mcp_fuzzer.reports.reporter.SafetyReporter"):
                                with patch("mcp_fuzzer.config.config") as mock_config:
                                    # Mock config for output and output_dir
                                    def mock_get(key, default=None):
                                        return {} if key == "output" else default

                                    mock_config.get.side_effect = mock_get
                                    reporter = FuzzerReporter()
                                    assert reporter.output_dir == Path("reports")
                                    mock_mkdir.assert_called_once_with(exist_ok=True)

    def test_init_custom_output_dir(self, temp_output_dir):
        """Test initialization with custom output directory."""
        with patch("mcp_fuzzer.config.config") as mock_config:
            # Mock config to return None for output directory so it uses the parameter
            mock_config.get.return_value = {}
            reporter = FuzzerReporter(output_dir=temp_output_dir)
            assert reporter.output_dir == Path(temp_output_dir)

    def test_session_id_generation(self, reporter):
        """Test that session ID is generated correctly."""
        assert reporter.session_id is not None
        assert isinstance(reporter.session_id, str)
        # Should be a UUID format (36 characters with dashes)
        assert len(reporter.session_id) == 36
        assert "-" in reporter.session_id

    def test_set_fuzzing_metadata(self, reporter):
        """Test setting fuzzing metadata."""
        metadata = {
            "mode": "tool",
            "protocol": "stdio",
            "endpoint": "test_endpoint",
            "runs": 100,
            "runs_per_type": 10,
        }

        reporter.set_fuzzing_metadata(**metadata)

        assert reporter.fuzzing_metadata["session_id"] == reporter.session_id
        assert reporter.fuzzing_metadata["mode"] == "tool"
        assert reporter.fuzzing_metadata["protocol"] == "stdio"
        assert reporter.fuzzing_metadata["endpoint"] == "test_endpoint"
        assert reporter.fuzzing_metadata["runs"] == 100
        assert reporter.fuzzing_metadata["runs_per_type"] == 10
        assert "start_time" in reporter.fuzzing_metadata
        assert "fuzzer_version" in reporter.fuzzing_metadata

    def test_add_tool_results(self, reporter):
        """Test adding tool results."""
        tool_name = "test_tool"
        results = [
            {"success": True, "response": "test_response"},
            {"exception": "test_exception", "error": "test_error"},
        ]

        reporter.add_tool_results(tool_name, results)

        assert tool_name in reporter.tool_results
        assert reporter.tool_results[tool_name] == results

    def test_add_protocol_results(self, reporter):
        """Test adding protocol results."""
        protocol_type = "test_protocol"
        results = [
            {"success": True, "response": "test_response"},
            {"error": "test_error"},
        ]

        reporter.add_protocol_results(protocol_type, results)

        assert protocol_type in reporter.protocol_results
        assert reporter.protocol_results[protocol_type] == results

    def test_add_safety_data(self, reporter):
        """Test adding safety data."""
        safety_data = {"blocked_operations": 5, "risk_level": "high"}

        reporter.add_safety_data(safety_data)

        assert reporter.safety_data["blocked_operations"] == 5
        assert reporter.safety_data["risk_level"] == "high"

    def test_print_tool_summary(self, reporter):
        """Test printing tool summary."""
        results = {"test_tool": [{"success": True}, {"exception": "test_exception"}]}

        reporter.print_tool_summary(results)

        # Verify console formatter was called
        reporter.console_formatter.print_tool_summary.assert_called_once_with(results)
        # Verify results were stored
        assert "test_tool" in reporter.tool_results

    def test_print_protocol_summary(self, reporter):
        """Test printing protocol summary."""
        results = {"test_protocol": [{"success": True}, {"error": "test_error"}]}

        reporter.print_protocol_summary(results)

        # Verify console formatter was called
        reporter.console_formatter.print_protocol_summary.assert_called_once_with(
            results
        )
        # Verify results were stored
        assert "test_protocol" in reporter.protocol_results

    def test_print_overall_summary(self, reporter):
        """Test printing overall summary."""
        tool_results = {"tool1": [{"success": True}]}
        protocol_results = {"protocol1": [{"success": True}]}

        reporter.print_overall_summary(tool_results, protocol_results)

        reporter.console_formatter.print_overall_summary.assert_called_once_with(
            tool_results, protocol_results
        )

    def test_print_safety_summary(self, reporter):
        """Test printing safety summary."""
        reporter.print_safety_summary()

        reporter.safety_reporter.print_safety_summary.assert_called_once()

    def test_print_comprehensive_safety_report(self, reporter):
        """Test printing comprehensive safety report."""
        reporter.print_comprehensive_safety_report()

        reporter.safety_reporter.print_comprehensive_safety_report.assert_called_once()

    def test_print_blocked_operations_summary(self, reporter):
        """Test printing blocked operations summary."""
        reporter.print_blocked_operations_summary()

        reporter.safety_reporter.print_blocked_operations_summary.assert_called_once()

    def test_generate_final_report_without_safety(self, reporter, temp_output_dir):
        """Test generating final report without safety data."""
        # Set up test data
        reporter.set_fuzzing_metadata("tool", "stdio", "test", 10)
        reporter.add_tool_results("test_tool", [{"success": True}])
        reporter.add_protocol_results("test_protocol", [{"success": True}])

        # Mock file operations
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("json.dump") as mock_json_dump:
                with patch.object(
                    reporter.text_formatter, "save_text_report"
                ) as mock_save_text:
                    result = reporter.generate_final_report(include_safety=False)

                    # Verify JSON file was created
                    assert result.endswith(".json")
                    assert "fuzzing_report_" in result
                    assert reporter.session_id in result

                    # Verify JSON dump was called
                    mock_json_dump.assert_called_once()

                    # Verify text report was saved
                    mock_save_text.assert_called_once()

    def test_generate_final_report_with_safety(self, reporter, temp_output_dir):
        """Test generating final report with safety data."""
        # Set up test data
        reporter.set_fuzzing_metadata("tool", "stdio", "test", 10)
        reporter.add_tool_results("test_tool", [{"success": True}])

        # Mock safety reporter methods
        reporter.safety_reporter.get_comprehensive_safety_data.return_value = {
            "blocked_operations": 5
        }
        reporter.safety_reporter.has_safety_data.return_value = True
        reporter.safety_reporter.export_safety_data.return_value = "safety_file.json"

        # Mock file operations
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("json.dump") as mock_json_dump:
                with patch.object(reporter.text_formatter, "save_text_report"):
                    result = reporter.generate_final_report(include_safety=True)

                    # Verify safety data was included
                    call_args = mock_json_dump.call_args[0]
                    report_data = call_args[0]
                    assert "safety" in report_data
                    assert report_data["safety"]["blocked_operations"] == 5

                    # Verify safety export was called
                    reporter.safety_reporter.export_safety_data.assert_called_once()

    def test_generate_summary_stats_empty_results(self, reporter):
        """Test generating summary stats with empty results."""
        stats = reporter._generate_summary_stats()

        assert stats["tools"]["total_tools"] == 0
        assert stats["tools"]["total_runs"] == 0
        assert stats["tools"]["success_rate"] == 0
        assert stats["protocols"]["total_protocol_types"] == 0
        assert stats["protocols"]["total_runs"] == 0
        assert stats["protocols"]["success_rate"] == 0

    def test_generate_summary_stats_with_results(self, reporter):
        """Test generating summary stats with results."""
        # Add tool results
        reporter.add_tool_results(
            "tool1",
            [
                {"success": True},
                {"exception": "test_exception"},
                {"error": "test_error"},
            ],
        )

        # Add protocol results
        reporter.add_protocol_results(
            "protocol1", [{"success": True}, {"error": "test_error"}]
        )

        stats = reporter._generate_summary_stats()

        # Check tool stats
        assert stats["tools"]["total_tools"] == 1
        assert stats["tools"]["total_runs"] == 3
        assert stats["tools"]["tools_with_exceptions"] == 1
        assert stats["tools"]["tools_with_errors"] == 1

        # Check protocol stats
        assert stats["protocols"]["total_protocol_types"] == 1
        assert stats["protocols"]["total_runs"] == 2
        assert stats["protocols"]["protocol_types_with_errors"] == 1

    def test_export_safety_data(self, reporter):
        """Test exporting safety data."""
        reporter.safety_reporter.export_safety_data.return_value = "safety_export.json"

        result = reporter.export_safety_data("test_file.json")

        reporter.safety_reporter.export_safety_data.assert_called_once_with(
            "test_file.json"
        )
        assert result == "safety_export.json"

    def test_get_output_directory(self, reporter):
        """Test getting output directory."""
        # The reporter fixture already uses temp_output_dir, so we don't need it here
        result = reporter.get_output_directory()

        # Just verify it's a Path object and exists
        assert isinstance(result, Path)
        assert result.exists()

    def test_get_current_status(self, reporter):
        """Test getting current status."""
        reporter.set_fuzzing_metadata("tool", "stdio", "test", 10)
        reporter.add_tool_results("tool1", [{"success": True}])
        reporter.add_protocol_results("protocol1", [{"success": True}])
        reporter.add_safety_data({"test": "data"})

        status = reporter.get_current_status()

        assert status["session_id"] == reporter.session_id
        assert status["tool_results_count"] == 1
        assert status["protocol_results_count"] == 1
        assert status["safety_data_available"] is True
        assert "metadata" in status

    def test_print_status(self, reporter):
        """Test printing status."""
        reporter.set_fuzzing_metadata("tool", "stdio", "test", 10)

        reporter.print_status()

        # Verify console print was called multiple times
        assert reporter.console.print.call_count > 0

    def test_cleanup(self, reporter):
        """Test cleanup method."""
        # Should not raise any exceptions
        reporter.cleanup()

    def test_session_id_uniqueness(self):
        """Test that session IDs are unique across instances."""
        with patch("mcp_fuzzer.reports.reporter.Console"):
            with patch("mcp_fuzzer.reports.reporter.ConsoleFormatter"):
                with patch("mcp_fuzzer.reports.reporter.JSONFormatter"):
                    with patch("mcp_fuzzer.reports.reporter.TextFormatter"):
                        with patch("mcp_fuzzer.reports.reporter.SafetyReporter"):
                            reporter1 = FuzzerReporter()
                            reporter2 = FuzzerReporter()

                            # Session IDs should be different (UUID format)
                            assert reporter1.session_id != reporter2.session_id

                            # Also test session ID format (UUID v4)
                            import re

                            uuid_pattern = (
                                r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                            )
                            assert re.match(uuid_pattern, reporter1.session_id)
                            assert re.match(uuid_pattern, reporter2.session_id)

    def test_metadata_end_time_set(self, reporter, temp_output_dir):
        """Test that end time is set in final report."""
        reporter.set_fuzzing_metadata("tool", "stdio", "test", 10)

        with patch("builtins.open", mock_open()):
            with patch("json.dump") as mock_json_dump:
                with patch.object(reporter.text_formatter, "save_text_report"):
                    reporter.generate_final_report()

                    call_args = mock_json_dump.call_args[0]
                    report_data = call_args[0]

                    assert "end_time" in report_data["metadata"]
                    assert report_data["metadata"]["end_time"] is not None
