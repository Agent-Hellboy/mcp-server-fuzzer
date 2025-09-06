#!/usr/bin/env python3
"""
Integration tests for CLI argument handling with reporting options.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_fuzzer.cli.args import create_argument_parser
from mcp_fuzzer.reports.reporter import FuzzerReporter

pytestmark = [pytest.mark.integration, pytest.mark.cli, pytest.mark.reports]


class TestCLIReportingIntegration:
    """Integration tests for CLI argument handling with reporting options."""

    def test_cli_args_with_output_dir(self):
        """Test CLI parsing with custom output directory."""
        args = [
            "--output-dir",
            "/tmp/test_reports",
            "--mode",
            "tools",
            "--protocol",
            "stdio",
            "--endpoint",
            "test_endpoint",
            "--runs",
            "10",
        ]

        parser = create_argument_parser()
        parsed_args = parser.parse_args(args)

        assert parsed_args.output_dir == "/tmp/test_reports"
        assert parsed_args.mode == "tools"
        assert parsed_args.protocol == "stdio"
        assert parsed_args.endpoint == "test_endpoint"
        assert parsed_args.runs == 10

    def test_cli_args_with_reporting_options(self):
        """Test CLI parsing with various reporting options."""
        args = [
            "--mode",
            "tools",
            "--protocol",
            "stdio",
            "--endpoint",
            "test_endpoint",
            "--runs",
            "5",
            "--output-dir",
            "/tmp/reports",
            "--verbose",
        ]

        parser = create_argument_parser()
        parsed_args = parser.parse_args(args)

        assert parsed_args.output_dir == "/tmp/reports"
        assert parsed_args.verbose is True
        assert parsed_args.mode == "tools"

    def test_cli_args_default_values(self):
        """Test CLI parsing with default values."""
        args = ["--mode", "tools", "--protocol", "stdio", "--endpoint", "test_endpoint"]

        parser = create_argument_parser()
        parsed_args = parser.parse_args(args)

        # Check default values
        assert parsed_args.runs == 10  # Default runs
        assert parsed_args.output_dir == "reports"  # Default output dir
        assert parsed_args.verbose is False  # Default verbose

    def test_cli_integration_with_reporter(self):
        """Test CLI integration with reporter initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            args = [
                "--mode",
                "tools",
                "--protocol",
                "stdio",
                "--endpoint",
                "test_endpoint",
                "--runs",
                "5",
                "--output-dir",
                temp_dir,
            ]

            parser = create_argument_parser()
            parsed_args = parser.parse_args(args)

            # Test that reporter can be initialized with CLI args
            reporter = FuzzerReporter(output_dir=parsed_args.output_dir)

            assert reporter.output_dir == Path(temp_dir)
            assert reporter.session_id is not None

            # Test setting metadata from CLI args
            reporter.set_fuzzing_metadata(
                mode=parsed_args.mode,
                protocol=parsed_args.protocol,
                endpoint=parsed_args.endpoint,
                runs=parsed_args.runs,
            )

            assert reporter.fuzzing_metadata["mode"] == "tools"
            assert reporter.fuzzing_metadata["protocol"] == "stdio"
            assert reporter.fuzzing_metadata["endpoint"] == "test_endpoint"
            assert reporter.fuzzing_metadata["runs"] == 5

    def test_cli_integration_with_safety_reporting(self):
        """Test CLI integration with safety reporting options."""
        args = [
            "--mode",
            "tools",
            "--protocol",
            "stdio",
            "--endpoint",
            "test_endpoint",
            "--runs",
            "5",
            "--output-dir",
            "/tmp/safety_reports",
        ]

        parser = create_argument_parser()
        parsed_args = parser.parse_args(args)

        # Test that safety reporter can be initialized
        reporter = FuzzerReporter(output_dir=parsed_args.output_dir)

        # Test that safety reporter exists and has expected methods
        assert reporter.safety_reporter is not None
        assert hasattr(reporter.safety_reporter, "print_safety_summary")
        assert hasattr(reporter.safety_reporter, "print_comprehensive_safety_report")
        assert hasattr(reporter.safety_reporter, "print_blocked_operations_summary")

        # Test that methods can be called without errors
        reporter.safety_reporter.print_safety_summary()
        reporter.safety_reporter.print_comprehensive_safety_report()
        reporter.safety_reporter.print_blocked_operations_summary()

    def test_cli_output_directory_creation(self):
        """Test that CLI creates output directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a simple subdirectory that doesn't exist
            output_dir = Path(temp_dir) / "new_reports"

            args = [
                "--mode",
                "tools",
                "--protocol",
                "stdio",
                "--endpoint",
                "test_endpoint",
                "--output-dir",
                str(output_dir),
            ]

            parser = create_argument_parser()
            parsed_args = parser.parse_args(args)

            # Initialize reporter - should create directory
            reporter = FuzzerReporter(output_dir=parsed_args.output_dir)

            # The reporter should create the directory
            assert reporter.output_dir.exists()
            assert reporter.output_dir == output_dir

    def test_cli_integration_with_different_modes(self):
        """Test CLI integration with different fuzzing modes."""
        modes = ["tools", "protocol"]
        protocols = ["stdio", "http", "sse"]

        for mode in modes:
            for protocol in protocols:
                args = [
                    "--mode",
                    mode,
                    "--protocol",
                    protocol,
                    "--endpoint",
                    "test_endpoint",
                    "--runs",
                    "1",
                ]

                parser = create_argument_parser()
                parsed_args = parser.parse_args(args)

                # Test reporter initialization
                reporter = FuzzerReporter()
                reporter.set_fuzzing_metadata(
                    mode=parsed_args.mode,
                    protocol=parsed_args.protocol,
                    endpoint=parsed_args.endpoint,
                    runs=parsed_args.runs,
                )

                assert reporter.fuzzing_metadata["mode"] == mode
                assert reporter.fuzzing_metadata["protocol"] == protocol

    def test_cli_integration_error_recovery(self):
        """Test CLI integration error recovery and reporting."""
        with tempfile.TemporaryDirectory() as temp_dir:
            args = [
                "--mode",
                "tools",
                "--protocol",
                "stdio",
                "--endpoint",
                "test_endpoint",
                "--runs",
                "5",
                "--output-dir",
                temp_dir,
            ]

            parser = create_argument_parser()
            parsed_args = parser.parse_args(args)

            # Test reporter error recovery
            reporter = FuzzerReporter(output_dir=parsed_args.output_dir)

            # Simulate errors during fuzzing
            error_results = {
                "error_tool": [
                    {"exception": "ConnectionError", "error": "Failed to connect"},
                    {"exception": "TimeoutError", "error": "Request timeout"},
                ]
            }

            # Should handle errors gracefully
            reporter.print_tool_summary(error_results)

            # Verify error data was stored
            assert "error_tool" in reporter.tool_results
            assert len(reporter.tool_results["error_tool"]) == 2

            # Test final report generation with errors
            report_file = reporter.generate_final_report(include_safety=False)
            assert Path(report_file).exists()

            # Verify error information is in the report
            import json

            with open(report_file, "r") as f:
                report_data = json.load(f)

            assert report_data["summary"]["tools"]["tools_with_exceptions"] == 2
