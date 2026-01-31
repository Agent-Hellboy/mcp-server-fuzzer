#!/usr/bin/env python3
"""
Tests for FuzzerReporter class.
"""

import asyncio
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.reports.core import ReportCollector
from mcp_fuzzer.reports.reporter import FuzzerReporter
from mcp_fuzzer.reports.reporter.config import ReporterConfig
from mcp_fuzzer.reports.safety_reporter import SafetyReporter


def _make_output_manager(temp_output_dir: str, session_id: str | None = None):
    resolved_session = session_id or str(uuid4())
    output_manager = MagicMock()
    output_manager.protocol = SimpleNamespace(session_id=resolved_session)
    output_manager.save_fuzzing_snapshot.return_value = str(
        Path(temp_output_dir) / "fuzzing_results.json"
    )
    output_manager.save_safety_summary.return_value = str(
        Path(temp_output_dir) / "safety_summary.json"
    )
    output_manager.save_error_report.return_value = str(
        Path(temp_output_dir) / "error_report.json"
    )
    return output_manager


@contextmanager
def _patch_formatters():
    with (
        patch(
            "mcp_fuzzer.reports.reporter.ConsoleFormatter",
            return_value=MagicMock(),
        ) as console_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.JSONFormatter",
            return_value=MagicMock(),
        ) as json_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.TextFormatter",
            return_value=MagicMock(),
        ) as text_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.CSVFormatter",
            return_value=MagicMock(),
        ) as csv_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.XMLFormatter",
            return_value=MagicMock(),
        ) as xml_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.HTMLFormatter",
            return_value=MagicMock(),
        ) as html_formatter,
        patch(
            "mcp_fuzzer.reports.reporter.MarkdownFormatter",
            return_value=MagicMock(),
        ) as markdown_formatter,
    ):
        yield SimpleNamespace(
            console=console_formatter.return_value,
            json=json_formatter.return_value,
            text=text_formatter.return_value,
            csv=csv_formatter.return_value,
            xml=xml_formatter.return_value,
            html=html_formatter.return_value,
            markdown=markdown_formatter.return_value,
        )


class TestFuzzerReporter:
    """Test cases for FuzzerReporter class."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def config_stub(self, temp_output_dir):
        """Provide a deterministic ReporterConfig for fixtures."""
        return ReporterConfig(
            output_dir=Path(temp_output_dir),
            compress_output=False,
            output_format="json",
            output_types=None,
            output_schema=None,
        )

    @pytest.fixture
    def reporter(self, temp_output_dir, config_stub):
        """Create a FuzzerReporter instance with injected dependencies."""
        output_manager = _make_output_manager(temp_output_dir)
        safety = MagicMock(spec=SafetyReporter)
        console = MagicMock()
        collector = ReportCollector()

        with _patch_formatters() as formatters:
            reporter = FuzzerReporter(
                output_dir=temp_output_dir,
                config_provider={"output": {}},
                config=config_stub,
                console=console,
                collector=collector,
                output_manager=output_manager,
                safety_reporter=safety,
            )
        reporter._test_mocks = SimpleNamespace(
            output_manager=output_manager,
            safety=safety,
            console=console,
            console_formatter=formatters.console,
            json_formatter=formatters.json,
            text_formatter=formatters.text,
            csv_formatter=formatters.csv,
            xml_formatter=formatters.xml,
            html_formatter=formatters.html,
            markdown_formatter=formatters.markdown,
        )
        return reporter

    def test_init_default_output_dir(self):
        """Test initialization with default output directory."""
        output_manager = _make_output_manager("reports")
        cfg = ReporterConfig(
            output_dir=Path("reports"),
            compress_output=False,
            output_format="json",
            output_types=None,
            output_schema=None,
        )
        with _patch_formatters():
            with patch("mcp_fuzzer.reports.reporter.Path.mkdir") as mock_mkdir:
                reporter = FuzzerReporter(
                    config_provider={"output": {}},
                    config=cfg,
                    output_manager=output_manager,
                )
        assert reporter.output_dir == Path("reports")
        mock_mkdir.assert_called_once_with(exist_ok=True)

    def test_init_custom_output_dir(self, temp_output_dir):
        """Test initialization with custom output directory."""
        output_manager = _make_output_manager(temp_output_dir)
        cfg = ReporterConfig(
            output_dir=Path(temp_output_dir),
            compress_output=False,
            output_format="json",
            output_types=None,
            output_schema=None,
        )
        with _patch_formatters():
            reporter = FuzzerReporter(
                output_dir=temp_output_dir,
                config_provider={"output": {}},
                config=cfg,
                output_manager=output_manager,
            )
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
            "mode": "tools",
            "protocol": "stdio",
            "endpoint": "test_endpoint",
            "runs": 100,
            "runs_per_type": 10,
        }

        reporter.set_fuzzing_metadata(**metadata)

        metadata = reporter.get_current_status()["metadata"]
        assert metadata["session_id"] == reporter.session_id
        assert metadata["mode"] == "tools"
        assert metadata["protocol"] == "stdio"
        assert metadata["endpoint"] == "test_endpoint"
        assert metadata["runs"] == 100
        assert metadata["runs_per_type"] == 10
        assert "start_time" in metadata
        assert "fuzzer_version" in metadata

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
            results, title="MCP Protocol Fuzzing Summary"
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

    @pytest.mark.asyncio
    async def test_generate_final_report_without_safety(self, reporter):
        """Test generating final report without safety data."""
        # Set up test data
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)
        reporter.add_tool_results("test_tool", [{"success": True}])
        reporter.add_protocol_results("test_protocol", [{"success": True}])

        result = await reporter.generate_final_report(include_safety=False)

        # Verify JSON file was created
        assert result.endswith(".json")
        assert "fuzzing_report_" in result
        assert reporter.session_id in result

        reporter.json_formatter.save_report.assert_called_once()
        reporter.text_formatter.save_text_report.assert_called_once()
        reporter.safety_reporter.export_safety_data.assert_not_called()

    @pytest.mark.asyncio
    async def test_generate_final_report_with_safety(self, reporter):
        """Test generating final report with safety data."""
        # Set up test data
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)
        reporter.add_tool_results("test_tool", [{"success": True}])

        # Mock safety reporter methods
        reporter.safety_reporter.get_comprehensive_safety_data.return_value = {
            "blocked_operations": 5
        }
        reporter.safety_reporter.has_safety_data.return_value = True
        reporter.safety_reporter.export_safety_data.return_value = "safety_file.json"

        result = await reporter.generate_final_report(include_safety=True)

        args, _ = reporter.json_formatter.save_report.call_args
        saved_report = args[0]
        snapshot_dict = saved_report.to_dict()
        assert "safety" in snapshot_dict
        assert snapshot_dict["safety"]["blocked_operations"] == 5

        reporter.text_formatter.save_text_report.assert_called_once()
        reporter.safety_reporter.export_safety_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_summary_stats_empty_results(self, reporter):
        """Test generating summary stats with empty results."""
        snapshot = await reporter._prepare_snapshot(
            include_safety=False, finalize=False
        )
        stats = snapshot.summary.to_dict()

        assert stats["tools"]["total_tools"] == 0
        assert stats["tools"]["total_runs"] == 0
        assert stats["tools"]["success_rate"] == 0
        assert stats["protocols"]["total_protocol_types"] == 0
        assert stats["protocols"]["total_runs"] == 0
        assert stats["protocols"]["success_rate"] == 0

    @pytest.mark.asyncio
    async def test_generate_summary_stats_with_results(self, reporter):
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

        snapshot = await reporter._prepare_snapshot(
            include_safety=False, finalize=False
        )
        stats = snapshot.summary.to_dict()

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
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)
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
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)

        report_text = reporter.print_status()

        # Verify console print was called multiple times
        assert reporter.console.print.call_count > 0
        assert "Reporter Status" in report_text

    def test_cleanup(self, reporter):
        """Test cleanup method."""
        # Should not raise any exceptions
        reporter.cleanup()

    def test_session_id_uniqueness(self):
        """Test that session IDs are unique across instances."""
        output_manager1 = _make_output_manager("reports")
        output_manager2 = _make_output_manager("reports")
        cfg = ReporterConfig(
            output_dir=Path("reports"),
            compress_output=False,
            output_format="json",
            output_types=None,
            output_schema=None,
        )
        with _patch_formatters():
            reporter1 = FuzzerReporter(
                config_provider={"output": {}},
                config=cfg,
                output_manager=output_manager1,
            )
            reporter2 = FuzzerReporter(
                config_provider={"output": {}},
                config=cfg,
                output_manager=output_manager2,
            )

        assert reporter1.session_id != reporter2.session_id

        import re

        uuid_pattern = (
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        assert re.match(uuid_pattern, reporter1.session_id)
        assert re.match(uuid_pattern, reporter2.session_id)

    @pytest.mark.asyncio
    async def test_metadata_end_time_set(self, reporter):
        """Test that end time is set in final report."""
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)

        await reporter.generate_final_report()

        saved_report = reporter.json_formatter.save_report.call_args[0][0]
        snapshot_dict = saved_report.to_dict()
        assert "end_time" in snapshot_dict["metadata"]
        assert snapshot_dict["metadata"]["end_time"] is not None

    @pytest.mark.asyncio
    async def test_generate_standardized_report_defaults(self, reporter):
        """Test standardized report generation defaults."""
        reporter.set_fuzzing_metadata("tools", "stdio", "test", 10)
        reporter.safety_reporter.has_safety_data.return_value = True
        reporter.safety_reporter.get_comprehensive_safety_data.return_value = {
            "blocked": 1
        }

        result = await reporter.generate_standardized_report()

        assert "fuzzing_results" in result
        assert "safety_summary" in result
        reporter.output_manager.save_fuzzing_snapshot.assert_called_once()
        reporter.output_manager.save_safety_summary.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_standardized_report_error_report(self, reporter):
        """Test standardized error report generation."""
        reporter.add_tool_results("tool_a", [{"error": "bad"}])
        result = await reporter.generate_standardized_report(
            output_types=["error_report"], include_safety=False
        )

        assert "error_report" in result
        reporter.output_manager.save_error_report.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_standardized_report_handles_errors(self, reporter):
        """Test standardized report generation handles exceptions."""
        reporter.output_manager.save_fuzzing_snapshot.side_effect = RuntimeError("boom")
        result = await reporter.generate_standardized_report(
            output_types=["fuzzing_results"], include_safety=False
        )

        assert result == {}

    def test_gather_safety_data_failure(self, reporter):
        """Test safety data gathering failure returns empty dict."""
        reporter.safety_reporter.get_comprehensive_safety_data.side_effect = Exception(
            "boom"
        )

        data = reporter._gather_safety_data(True)

        assert data == {}

    @pytest.mark.asyncio
    async def test_gather_runtime_data(self, reporter):
        """Test runtime data collection from transport."""
        transport = MagicMock()
        transport.get_process_stats = AsyncMock(return_value={"active": 1})
        reporter.set_transport(transport)

        data = await reporter._gather_runtime_data()

        assert data == {"process_stats": {"active": 1}}

    @pytest.mark.asyncio
    async def test_gather_runtime_data_failure(self, reporter):
        """Test runtime data failures return empty dict."""
        transport = MagicMock()
        transport.get_process_stats = AsyncMock(side_effect=Exception("boom"))
        reporter.set_transport(transport)

        data = await reporter._gather_runtime_data()

        assert data == {}

    def test_ensure_metadata_defaults(self, reporter):
        """Test default metadata creation when missing."""
        reporter._metadata = None
        metadata = reporter._ensure_metadata()

        assert metadata.mode == "unknown"
        assert metadata.protocol == "unknown"
        assert metadata.endpoint == "unknown"

    @pytest.mark.asyncio
    async def test_export_formatters(self, reporter, tmp_path):
        """Test format-specific export helpers."""
        await reporter.export_format("csv", str(tmp_path / "report.csv"))
        await reporter.export_format("xml", str(tmp_path / "report.xml"))
        await reporter.export_format("html", str(tmp_path / "report.html"))
        await reporter.export_format("markdown", str(tmp_path / "report.md"))

        reporter.csv_formatter.save_csv_report.assert_called_once()
        reporter.xml_formatter.save_xml_report.assert_called_once()
        reporter.html_formatter.save_html_report.assert_called_once()
        reporter.markdown_formatter.save_markdown_report.assert_called_once()
