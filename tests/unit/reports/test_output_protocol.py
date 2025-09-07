#!/usr/bin/env python3
"""
Unit tests for MCP Fuzzer Output Protocol
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_fuzzer.reports.output_protocol import OutputProtocol, OutputManager


class TestOutputProtocol:
    """Test cases for OutputProtocol class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.protocol = OutputProtocol(session_id="test-session-123")

    def test_create_base_output(self):
        """Test creating base output structure."""
        data = {"test": "data"}
        output = self.protocol.create_base_output("fuzzing_results", data)

        assert output["protocol_version"] == "1.0.0"
        assert output["tool_version"] == "0.1.6"
        assert output["session_id"] == "test-session-123"
        assert output["output_type"] == "fuzzing_results"
        assert output["data"] == data
        assert "timestamp" in output
        assert "metadata" in output

    def test_invalid_output_type(self):
        """Test that invalid output types raise ValidationError."""
        from mcp_fuzzer.exceptions import ValidationError

        with pytest.raises(ValidationError):
            self.protocol.create_base_output("invalid_type", {})

    def test_create_fuzzing_results_output(self):
        """Test creating fuzzing results output."""
        tool_results = {
            "tool1": [{"success": True}, {"success": False}],
            "tool2": [{"success": True}]
        }
        protocol_results = {
            "InitializeRequest": [{"success": True}],
        }

        output = self.protocol.create_fuzzing_results_output(
            mode="tools",
            protocol="http",
            endpoint="http://test.com",
            tool_results=tool_results,
            protocol_results=protocol_results,
            execution_time="PT30S",
            total_tests=3,
            success_rate=66.67,
            safety_enabled=True
        )

        assert output["output_type"] == "fuzzing_results"
        assert output["data"]["mode"] == "tools"
        assert output["data"]["protocol"] == "http"
        assert output["data"]["endpoint"] == "http://test.com"
        assert output["data"]["total_tools"] == 2
        assert output["data"]["total_protocol_types"] == 1
        assert output["metadata"]["execution_time"] == "PT30S"
        assert output["metadata"]["total_tests"] == 3
        assert output["metadata"]["success_rate"] == 66.67
        assert output["metadata"]["safety_enabled"] is True

    def test_create_error_report_output(self):
        """Test creating error report output."""
        errors = [
            {"type": "tool_error", "message": "Test error", "severity": "high"}
        ]
        warnings = [
            {"type": "config_warning", "message": "Test warning"}
        ]

        output = self.protocol.create_error_report_output(
            errors=errors,
            warnings=warnings,
            execution_context={"mode": "tools"}
        )

        assert output["output_type"] == "error_report"
        assert output["data"]["total_errors"] == 1
        assert output["data"]["total_warnings"] == 1
        assert output["data"]["errors"] == errors
        assert output["data"]["warnings"] == warnings
        assert output["data"]["execution_context"] == {"mode": "tools"}
        assert output["metadata"]["error_severity"] == "high"

    def test_create_safety_summary_output(self):
        """Test creating safety summary output."""
        safety_data = {
            "active": True,
            "statistics": {"total_blocked": 5}
        }
        blocked_operations = [
            {"tool_name": "dangerous_tool", "reason": "unsafe operation"}
        ]

        output = self.protocol.create_safety_summary_output(
            safety_data=safety_data,
            blocked_operations=blocked_operations,
            risk_assessment="high"
        )

        assert output["output_type"] == "safety_summary"
        assert output["data"]["safety_system_active"] is True
        assert output["data"]["total_operations_blocked"] == 1
        assert output["data"]["blocked_operations"] == blocked_operations
        assert output["data"]["risk_assessment"] == "high"

    def test_validate_output_valid(self):
        """Test validating valid output."""
        output = self.protocol.create_base_output("fuzzing_results", {"test": "data"})
        assert self.protocol.validate_output(output) is True

    def test_validate_output_invalid_missing_field(self):
        """Test validating output with missing required field."""
        output = self.protocol.create_base_output("fuzzing_results", {"test": "data"})
        del output["protocol_version"]

        assert self.protocol.validate_output(output) is False

    def test_validate_output_invalid_type(self):
        """Test validating output with invalid output type."""
        output = self.protocol.create_base_output("fuzzing_results", {"test": "data"})
        output["output_type"] = "invalid_type"

        assert self.protocol.validate_output(output) is False

    def test_save_output(self):
        """Test saving output to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self.protocol.create_base_output(
                "fuzzing_results", {"test": "data"}
            )

            filepath = self.protocol.save_output(output, temp_dir)

            assert Path(filepath).exists()

            # Verify file contents
            with open(filepath, "r") as f:
                saved_output = json.load(f)

            assert saved_output == output

    def test_save_output_invalid(self):
        """Test saving invalid output raises error."""
        from mcp_fuzzer.exceptions import ValidationError

        with tempfile.TemporaryDirectory() as temp_dir:
            output = self.protocol.create_base_output(
                "fuzzing_results", {"test": "data"}
            )
            del output["protocol_version"]

            with pytest.raises(ValidationError):
                self.protocol.save_output(output, temp_dir)


class TestOutputManager:
    """Test cases for OutputManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = OutputManager(self.temp_dir, compress=False)

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_save_fuzzing_results(self):
        """Test saving fuzzing results through manager."""
        tool_results = {"tool1": [{"success": True}]}
        protocol_results = {"InitializeRequest": [{"success": True}]}

        filepath = self.manager.save_fuzzing_results(
            mode="tools",
            protocol="http",
            endpoint="http://test.com",
            tool_results=tool_results,
            protocol_results=protocol_results,
            execution_time="PT30S",
            total_tests=2,
            success_rate=100.0,
            safety_enabled=False
        )

        assert Path(filepath).exists()

        # Verify session directory structure
        session_dir = (Path(self.temp_dir) / "sessions" /
                      self.manager.protocol.session_id)
        assert session_dir.exists()

    def test_save_error_report(self):
        """Test saving error report through manager."""
        errors = [{"type": "test_error", "message": "Test error"}]

        filepath = self.manager.save_error_report(errors=errors)

        assert Path(filepath).exists()

    def test_save_safety_summary(self):
        """Test saving safety summary through manager."""
        safety_data = {"active": True, "statistics": {"total_blocked": 0}}

        filepath = self.manager.save_safety_summary(safety_data)

        assert Path(filepath).exists()

    def test_get_session_directory(self):
        """Test getting session directory."""
        session_dir = self.manager.get_session_directory()
        expected_dir = (Path(self.temp_dir) / "sessions" /
                       self.manager.protocol.session_id)

        assert session_dir == expected_dir

    def test_list_session_outputs(self):
        """Test listing session outputs."""
        # Create some test files
        session_dir = self.manager.get_session_directory()
        session_dir.mkdir(parents=True, exist_ok=True)

        test_file1 = session_dir / "test1.json"
        test_file2 = session_dir / "test2.json"
        test_file1.write_text("{}")
        test_file2.write_text("{}")

        outputs = self.manager.list_session_outputs()

        assert len(outputs) == 2
        assert test_file1 in outputs
        assert test_file2 in outputs

    def test_list_session_outputs_no_session(self):
        """Test listing outputs when session directory doesn't exist."""
        outputs = self.manager.list_session_outputs()
        assert outputs == []


class TestOutputProtocolIntegration:
    """Integration tests for output protocol."""

    def test_full_workflow(self):
        """Test complete output generation workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = OutputManager(temp_dir)

            # Generate fuzzing results
            tool_results = {
                "example_tool": [
                    {"success": True, "args": {"param": "test"}},
                    {
                        "success": False,
                        "exception": "ValueError",
                        "args": {"param": "malformed"}
                    }
                ]
            }
            protocol_results = {
                "InitializeRequest": [{"success": True}]
            }

            fuzzing_filepath = manager.save_fuzzing_results(
                mode="tools",
                protocol="http",
                endpoint="http://localhost:8000",
                tool_results=tool_results,
                protocol_results=protocol_results,
                execution_time="PT45S",
                total_tests=3,
                success_rate=66.67,
                safety_enabled=True
            )

            # Generate error report
            errors = [
                {
                    "type": "tool_error",
                    "tool_name": "example_tool",
                    "severity": "medium",
                    "message": "Invalid argument format"
                }
            ]

            error_filepath = manager.save_error_report(errors=errors)

            # Verify files exist and contain valid JSON
            assert Path(fuzzing_filepath).exists()
            assert Path(error_filepath).exists()

            with open(fuzzing_filepath, "r") as f:
                fuzzing_data = json.load(f)
                assert fuzzing_data["output_type"] == "fuzzing_results"
                assert fuzzing_data["protocol_version"] == "1.0.0"

            with open(error_filepath, "r") as f:
                error_data = json.load(f)
                assert error_data["output_type"] == "error_report"
                assert error_data["data"]["total_errors"] == 1