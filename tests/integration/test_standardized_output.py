#!/usr/bin/env python3
"""
Integration tests for standardized output functionality
"""

import json
import tempfile
from pathlib import Path

import pytest

from mcp_fuzzer.client import MCPFuzzerClient
from mcp_fuzzer.reports import FuzzerReporter
from mcp_fuzzer.transport import create_transport


class TestStandardizedOutputIntegration:
    """Integration tests for standardized output generation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    @pytest.mark.asyncio
    async def test_full_fuzzing_workflow_with_standardized_output(self):
        """Test complete fuzzing workflow with standardized output generation."""
        # This test would require a mock MCP server
        # For now, we'll test the output generation components

        # Create reporter with output directory
        reporter = FuzzerReporter(output_dir=self.temp_dir)

        # Simulate fuzzing results
        tool_results = {
            "test_tool": [
                {"success": True, "args": {"param": "value1"}},
                {
                    "success": False,
                    "exception": "ValueError: invalid input",
                    "args": {"param": "value2"}
                },
                {"success": True, "args": {"param": "value3"}}
            ]
        }

        protocol_results = {
            "InitializeRequest": [
                {"success": True},
                {"success": True}
            ]
        }

        # Add results to reporter
        reporter.add_tool_results("test_tool", tool_results["test_tool"])
        reporter.add_protocol_results(
            "InitializeRequest", protocol_results["InitializeRequest"]
        )

        # Set fuzzing metadata
        reporter.set_fuzzing_metadata(
            mode="tools",
            protocol="http",
            endpoint="http://test-server:8000",
            runs=3,
            runs_per_type=2
        )

        # Generate standardized reports
        generated_files = reporter.generate_standardized_report()

        # Verify files were created
        assert "fuzzing_results" in generated_files

        fuzzing_file = generated_files["fuzzing_results"]
        assert Path(fuzzing_file).exists()

        # Verify file contents
        with open(fuzzing_file, "r") as f:
            data = json.load(f)

        assert data["protocol_version"] == "1.0.0"
        assert data["output_type"] == "fuzzing_results"
        assert data["data"]["mode"] == "tools"
        assert data["data"]["protocol"] == "http"
        assert data["data"]["endpoint"] == "http://test-server:8000"
        assert data["data"]["total_tools"] == 1
        assert data["data"]["total_protocol_types"] == 1

        # Verify tool results structure
        tools_tested = data["data"]["tools_tested"]
        assert len(tools_tested) == 1
        assert tools_tested[0]["name"] == "test_tool"
        assert tools_tested[0]["runs"] == 3
        assert tools_tested[0]["successful"] == 2
        assert len(tools_tested[0]["exception_details"]) == 1
        assert abs(tools_tested[0]["success_rate"] - 66.67) < 0.01

    def test_output_directory_structure(self):
        """Test that output directory structure is created correctly."""
        from mcp_fuzzer.reports.output_protocol import OutputManager

        manager = OutputManager(self.temp_dir)

        # Create a simple output
        output = manager.protocol.create_base_output(
            "fuzzing_results", {"test": "data"}
        )
        filepath = manager.protocol.save_output(output, self.temp_dir)

        # Verify directory structure
        session_dir = Path(self.temp_dir) / "sessions" / manager.protocol.session_id
        assert session_dir.exists()
        assert session_dir.is_dir()

        # Verify file exists in session directory
        assert Path(filepath).exists()
        assert Path(filepath).parent == session_dir

    def test_configuration_driven_output(self):
        """Test that output generation respects configuration settings."""
        from mcp_fuzzer.config import config

        # Set output configuration
        config.update({
            "output": {
                "format": "json",
                "directory": self.temp_dir,
                "compress": False,
                "types": ["fuzzing_results", "error_report"]
            }
        })

        # Create reporter (should pick up config)
        reporter = FuzzerReporter()

        # Verify configuration was loaded
        assert reporter.output_format == "json"
        assert reporter.output_types == ["fuzzing_results", "error_report"]
        assert str(reporter.output_dir) == self.temp_dir

    def test_error_report_generation(self):
        """Test error report generation with various error types."""
        from mcp_fuzzer.reports.output_protocol import OutputManager

        manager = OutputManager(self.temp_dir)

        # Create various types of errors
        errors = [
            {
                "type": "tool_error",
                "tool_name": "dangerous_tool",
                "severity": "high",
                "message": "Command injection detected",
                "arguments": {"cmd": "rm -rf /"}
            },
            {
                "type": "protocol_error",
                "protocol_type": "InitializeRequest",
                "severity": "medium",
                "message": "Invalid JSON in request",
                "details": {"field": "jsonrpc", "expected": "2.0", "got": "1.0"}
            },
            {
                "type": "system_error",
                "severity": "low",
                "message": "Network timeout",
                "context": {"endpoint": "http://test.com", "timeout": 30}
            }
        ]

        filepath = manager.save_error_report(errors=errors)

        # Verify file was created and contains correct data
        assert Path(filepath).exists()

        with open(filepath, "r") as f:
            data = json.load(f)

        assert data["output_type"] == "error_report"
        assert data["data"]["total_errors"] == 3
        assert data["data"]["total_warnings"] == 0
        assert len(data["data"]["errors"]) == 3
        assert data["metadata"]["error_severity"] == "high"  # Highest severity

    def test_safety_summary_generation(self):
        """Test safety summary generation with blocked operations."""
        from mcp_fuzzer.reports.output_protocol import OutputManager

        manager = OutputManager(self.temp_dir)

        # Mock safety data
        blocked_operations = [
            {
                "tool_name": "file_operations",
                "reason": "File system access blocked",
                "arguments": {"path": "/etc/passwd"},
                "timestamp": "2024-01-01T10:00:00Z"
            },
            {
                "tool_name": "network_tools",
                "reason": "Network access blocked",
                "arguments": {"url": "http://malicious.com"},
                "timestamp": "2024-01-01T10:01:00Z"
            }
        ]

        safety_data = {
            "active": True,
            "statistics": {
                "total_operations_blocked": 3,
                "unique_tools_blocked": 2,
                "risk_assessment": "medium"
            },
            "blocked_operations": blocked_operations,
            "risk_assessment": "medium"
        }

        filepath = manager.save_safety_summary(safety_data)

        # Verify file was created and contains correct data
        assert Path(filepath).exists()

        with open(filepath, "r") as f:
            data = json.load(f)

        assert data["output_type"] == "safety_summary"
        assert data["data"]["safety_system_active"] is True
        assert data["data"]["total_operations_blocked"] == 2
        assert data["data"]["risk_assessment"] == "medium"
        assert len(data["data"]["blocked_operations"]) == 2

    def test_multiple_output_types_generation(self):
        """Test generating multiple output types in a single session."""
        from mcp_fuzzer.reports import FuzzerReporter

        reporter = FuzzerReporter(output_dir=self.temp_dir)

        # Add some mock data with errors to ensure error report is generated
        reporter.add_tool_results("test_tool", [
            {"success": True},
            {"success": False, "exception": "ValueError: test error"}
        ])
        reporter.set_fuzzing_metadata(
            mode="tools",
            protocol="http",
            endpoint="http://test.com",
            runs=2
        )

        # Generate multiple output types
        output_types = ["fuzzing_results", "error_report"]
        generated_files = reporter.generate_standardized_report(
            output_types=output_types
        )

        # Verify both files were created
        assert "fuzzing_results" in generated_files
        assert "error_report" in generated_files

        # Verify both files exist
        assert Path(generated_files["fuzzing_results"]).exists()
        assert Path(generated_files["error_report"]).exists()

        # Verify they are in the same session directory
        # Use the reporter's actual output directory (may be different from
        # temp_dir if configured)
        session_dir = reporter.output_dir / "sessions" / reporter.session_id
        assert session_dir.exists()

        files_in_session = list(session_dir.glob("*.json"))
        assert len(files_in_session) == 2

    def test_output_file_naming_convention(self):
        """Test that output files follow the expected naming convention."""
        from mcp_fuzzer.reports.output_protocol import OutputManager
        import re

        manager = OutputManager(self.temp_dir)

        # Generate output
        output = manager.protocol.create_base_output(
            "fuzzing_results", {"test": "data"}
        )
        filepath = manager.protocol.save_output(output, self.temp_dir)

        # Verify filename format: timestamp_output_type.json
        filename = Path(filepath).name
        pattern = r'^\d{8}_\d{6}_fuzzing_results\.json$'
        assert re.match(pattern, filename)

    def test_session_isolation(self):
        """Test that different sessions create separate directories."""
        from mcp_fuzzer.reports.output_protocol import OutputProtocol

        # Create two different sessions
        protocol1 = OutputProtocol("session1")
        protocol2 = OutputProtocol("session2")

        # Create outputs for each session
        output1 = protocol1.create_base_output("fuzzing_results", {"session": 1})
        output2 = protocol2.create_base_output("fuzzing_results", {"session": 2})

        filepath1 = protocol1.save_output(output1, self.temp_dir)
        filepath2 = protocol2.save_output(output2, self.temp_dir)

        # Verify files are in different directories
        dir1 = Path(filepath1).parent
        dir2 = Path(filepath2).parent

        assert dir1 != dir2
        assert "session1" in str(dir1)
        assert "session2" in str(dir2)