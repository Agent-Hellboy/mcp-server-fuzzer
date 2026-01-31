#!/usr/bin/env python3
"""
Main Reporter for MCP Fuzzer

Handles all reporting functionality including console output, file exports,
and result aggregation.
"""

import logging
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from rich.console import Console

from ..core import FuzzingMetadata, ReportCollector, ReportSnapshot
from ..formatters import (
    CSVFormatter,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    TextFormatter,
    XMLFormatter,
    ConsoleFormatter,
    ReportSaveAdapter,
    FormatterRegistry,
)
from ..formatters.common import extract_tool_runs
from ..output import OutputManager
from .config import ReporterConfig
from ..safety_reporter import SafetyReporter

from importlib.metadata import version, PackageNotFoundError

_AUTO_FILTER = object()


def _resolve_fuzzer_version() -> str:
    try:
        return version("mcp-fuzzer")
    except PackageNotFoundError:
        return "unknown"


class FuzzerReporter:
    """Centralized reporter for all MCP Fuzzer output and reporting."""

    def __init__(
        self,
        output_dir: str = "reports",
        compress_output: bool = False,
        config_provider: Mapping[str, Any] | None = None,
        safety_system=_AUTO_FILTER,
        collector: ReportCollector | None = None,
        output_manager: OutputManager | None = None,
        console: Console | None = None,
        safety_reporter: SafetyReporter | None = None,
        config: ReporterConfig | None = None,
    ):
        """
        Initialize the reporter.

        Args:
            output_dir: Output directory for reports
            compress_output: Whether to compress output
            config_provider: Configuration provider (dict-like). If None, uses the
                global config provider.
        """
        config_provider = self._resolve_config_provider(config_provider)

        resolved_config = config or ReporterConfig.from_provider(
            provider=config_provider,
            requested_output_dir=output_dir,
            compress_fallback=compress_output,
        )
        self._config = resolved_config
        self.output_format = resolved_config.output_format
        self.output_types = resolved_config.output_types
        self.output_schema = resolved_config.output_schema
        self.output_compress = resolved_config.compress_output

        self.output_dir = resolved_config.output_dir
        self.output_dir.mkdir(exist_ok=True)

        self.console = console or Console()
        self.collector = collector or ReportCollector()
        self.output_manager = output_manager or OutputManager(
            str(self.output_dir), self.output_compress
        )
        self.safety_reporter = self._resolve_safety_reporter(
            safety_reporter, safety_system
        )

        self.console_formatter = ConsoleFormatter(self.console)
        self.json_formatter = JSONFormatter()
        self.text_formatter = TextFormatter()
        self.csv_formatter = CSVFormatter()
        self.xml_formatter = XMLFormatter()
        self.html_formatter = HTMLFormatter()
        self.markdown_formatter = MarkdownFormatter()
        self.formatter_registry = FormatterRegistry()
        self._html_adapter = ReportSaveAdapter(
            self.html_formatter.save_html_report,
            "html",
            title="Fuzzing Results Report",
        )
        self._register_format_savers()

        self._metadata: FuzzingMetadata | None = None
        self._transport: Any = None
        self._fuzzer_version = _resolve_fuzzer_version()

        # Use session ID from output manager
        self.session_id = self.output_manager.protocol.session_id

        logging.info(
            f"FuzzerReporter initialized with output directory: {self.output_dir}"
        )

    @staticmethod
    def _resolve_config_provider(
        config_provider: Mapping[str, Any] | None
    ) -> Mapping[str, Any]:
        if config_provider is not None:
            return config_provider
        from ...client.adapters import config_mediator

        # config_mediator implements dict-like get()
        return config_mediator

    @staticmethod
    def _resolve_safety_reporter(
        safety_reporter: SafetyReporter | None,
        safety_system: Any,
    ) -> SafetyReporter:
        if safety_reporter is not None:
            return safety_reporter
        if safety_system is _AUTO_FILTER:
            return SafetyReporter()
        return SafetyReporter(safety_system)

    def _register_format_savers(self) -> None:
        self.formatter_registry.register(
            "json", ReportSaveAdapter(self.json_formatter.save_report, "json")
        )
        self.formatter_registry.register(
            "text", ReportSaveAdapter(self.text_formatter.save_text_report, "txt")
        )
        self.formatter_registry.register(
            "csv", ReportSaveAdapter(self.csv_formatter.save_csv_report, "csv")
        )
        self.formatter_registry.register(
            "xml", ReportSaveAdapter(self.xml_formatter.save_xml_report, "xml")
        )
        self.formatter_registry.register("html", self._html_adapter)
        self.formatter_registry.register(
            "markdown",
            ReportSaveAdapter(
                self.markdown_formatter.save_markdown_report,
                "md",
            ),
        )

    def set_fuzzing_metadata(
        self,
        mode: str,
        protocol: str,
        endpoint: str,
        runs: int,
        runs_per_type: int = None,
    ):
        """Set metadata about the current fuzzing session."""
        self._metadata = FuzzingMetadata(
            session_id=self.session_id,
            mode=mode,
            protocol=protocol,
            endpoint=endpoint,
            runs=runs,
            runs_per_type=runs_per_type,
            fuzzer_version=self._fuzzer_version,
            start_time=datetime.now(),
        )

    def add_tool_results(self, tool_name: str, results: list[dict[str, Any]]):
        """Add tool fuzzing results to the reporter."""
        self.collector.add_tool_results(tool_name, results)

    def add_protocol_results(self, protocol_type: str, results: list[dict[str, Any]]):
        """Add protocol fuzzing results to the reporter."""
        self.collector.add_protocol_results(protocol_type, results)

    def add_spec_checks(self, checks: list[dict[str, Any]]):
        """Add spec guard checks to the reporter."""
        self.collector.add_spec_checks(checks)

    def add_safety_data(self, safety_data: dict[str, Any]):
        """Add safety system data to the reporter."""
        self.collector.update_safety_data(safety_data)

    def print_tool_summary(self, results: dict[str, Any]):
        """Print tool fuzzing summary to console."""
        self.console_formatter.print_tool_summary(results)

        # Store results for final report
        for tool_name, tool_results in results.items():
            runs, _ = extract_tool_runs(tool_results)
            self.add_tool_results(tool_name, runs)

    def print_protocol_summary(
        self,
        results: dict[str, list[dict[str, Any]]],
        *,
        title: str = "MCP Protocol Fuzzing Summary",
    ):
        """Print protocol fuzzing summary to console."""
        self.console_formatter.print_protocol_summary(results, title=title)

        # Store results for final report
        for protocol_type, protocol_results in results.items():
            self.add_protocol_results(protocol_type, protocol_results)

    def print_spec_guard_summary(
        self,
        checks: list[dict[str, Any]],
        *,
        requested_version: str | None = None,
        negotiated_version: str | None = None,
    ):
        """Print spec guard (compliance) summary to console."""
        self.console_formatter.print_spec_guard_summary(
            checks,
            requested_version=requested_version,
            negotiated_version=negotiated_version,
        )

    def print_overall_summary(
        self,
        tool_results: dict[str, Any],
        protocol_results: dict[str, list[dict[str, Any]]],
    ):
        """Print overall summary to console."""
        self.console_formatter.print_overall_summary(tool_results, protocol_results)

    def print_safety_summary(self):
        """Print safety system summary to console."""
        self.safety_reporter.print_safety_summary()

    def print_comprehensive_safety_report(self):
        """Print comprehensive safety report to console."""
        self.safety_reporter.print_comprehensive_safety_report()

    def print_blocked_operations_summary(self):
        """Print blocked operations summary to console."""
        self.safety_reporter.print_blocked_operations_summary()

    async def generate_final_report(self, include_safety: bool = True) -> str:
        """Generate comprehensive final report and save to file."""
        snapshot = await self._prepare_snapshot(
            include_safety=include_safety, finalize=True
        )
        json_filename = f"fuzzing_report_{self.session_id}.json"
        self.formatter_registry.save(
            "json", snapshot, self.output_dir, json_filename
        )

        text_filename = f"fuzzing_report_{self.session_id}.txt"
        self.formatter_registry.save(
            "text", snapshot, self.output_dir, text_filename
        )

        if include_safety and self.safety_reporter.has_safety_data():
            safety_filename = self.output_dir / f"safety_report_{self.session_id}.json"
            self.safety_reporter.export_safety_data(str(safety_filename))

        logging.info(f"Final report generated: {json_filename}")
        return str(self.output_dir / json_filename)

    async def generate_standardized_report(
        self, output_types: list[str] = None, include_safety: bool = True
    ) -> dict[str, str]:
        """Generate standardized reports using the new output protocol."""
        generated_files = {}
        snapshot = await self._prepare_snapshot(
            include_safety=include_safety, finalize=True
        )

        # Use configured output types if none specified
        if output_types is None:
            if self.output_types:
                output_types = self.output_types
            else:
                output_types = ["fuzzing_results"]
                if include_safety and self.safety_reporter.has_safety_data():
                    output_types.append("safety_summary")

        # Generate fuzzing results
        if "fuzzing_results" in output_types:
            try:
                filepath = self.output_manager.save_fuzzing_snapshot(
                    snapshot=snapshot,
                    safety_enabled=include_safety,
                )
                generated_files["fuzzing_results"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized fuzzing results: {e}")

        # Generate safety summary
        if "safety_summary" in output_types and include_safety:
            try:
                safety_data = snapshot.safety_data or self._gather_safety_data(True)
                filepath = self.output_manager.save_safety_summary(safety_data)
                generated_files["safety_summary"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized safety summary: {e}")

        # Generate error report if there are errors
        if "error_report" in output_types:
            try:
                errors = self.collector.collect_errors()
                if errors:
                    filepath = self.output_manager.save_error_report(
                        errors=errors,
                        execution_context=snapshot.metadata.to_dict(),
                    )
                    generated_files["error_report"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized error report: {e}")

        return generated_files

    def export_safety_data(self, filename: str = None) -> str:
        """Export safety data to JSON file."""
        return self.safety_reporter.export_safety_data(filename)

    def get_output_directory(self) -> Path:
        """Get the output directory path."""
        return self.output_dir

    def get_current_status(self) -> dict[str, Any]:
        """Get current status of the reporter."""
        metadata = self._metadata.to_dict() if self._metadata else {}
        return {
            "session_id": self.session_id,
            "output_directory": str(self.output_dir),
            "tool_results_count": len(self.collector.tool_results),
            "protocol_results_count": len(self.collector.protocol_results),
            "safety_data_available": bool(self.collector.safety_data),
            "metadata": metadata,
        }

    def print_status(self):
        """Print current status to console."""
        status = self.get_current_status()
        report_text = self._render_status(status)
        for line in report_text.splitlines():
            self.console.print(line)
        return report_text

    async def export_format(
        self,
        format_name: str,
        filename: str,
        *,
        title: str | None = None,
        include_safety: bool = False,
    ) -> str:
        """Export report data to a named format."""
        snapshot = await self._prepare_snapshot(
            include_safety=include_safety, finalize=False
        )
        if title is not None and format_name == "html":
            self._html_adapter = replace(self._html_adapter, title=title)
            self.formatter_registry.register("html", self._html_adapter)
        return self.formatter_registry.save(
            format_name, snapshot, self.output_dir, filename
        )

    async def _prepare_snapshot(
        self, include_safety: bool, finalize: bool
    ) -> ReportSnapshot:
        """Create a snapshot of the current report state."""
        metadata = self._finalize_metadata() if finalize else self._ensure_metadata()
        safety_data = self._gather_safety_data(include_safety)
        if include_safety and safety_data:
            self.collector.update_safety_data(safety_data)
        runtime_data = await self._gather_runtime_data()
        if runtime_data:
            self.collector.update_runtime_data(runtime_data)
        return self.collector.snapshot(
            metadata,
            safety_data=None,
            runtime_data=None,
            include_safety=include_safety,
        )

    def _ensure_metadata(self) -> FuzzingMetadata:
        """Ensure metadata exists and return it."""
        if self._metadata:
            return self._metadata
        self._metadata = FuzzingMetadata(
            session_id=self.session_id,
            mode="unknown",
            protocol="unknown",
            endpoint="unknown",
            runs=0,
            runs_per_type=None,
            fuzzer_version=self._fuzzer_version,
            start_time=datetime.now(),
        )
        return self._metadata

    def _finalize_metadata(self) -> FuzzingMetadata:
        """Ensure metadata has an end_time and return it."""
        metadata = self._ensure_metadata()
        closed = metadata.close()
        self._metadata = closed
        return closed

    def _gather_safety_data(self, include_safety: bool) -> dict[str, Any]:
        if not include_safety:
            return {}
        try:
            return self.safety_reporter.get_comprehensive_safety_data()
        except Exception as exc:
            logging.error("Failed to gather safety data: %s", exc)
            return {}

    def set_transport(self, transport: Any) -> None:
        """Set the transport for gathering runtime statistics."""
        self._transport = transport

    async def _gather_runtime_data(self) -> dict[str, Any]:
        """Gather runtime/process statistics from transport if available."""
        if not self._transport:
            return {}

        try:
            # Check if transport has get_process_stats method
            if hasattr(self._transport, "get_process_stats"):
                stats = await self._transport.get_process_stats()
                return {"process_stats": stats}
        except Exception as exc:
            logging.debug("Failed to gather runtime data: %s", exc)

        return {}

    @property
    def tool_results(self) -> dict[str, list[dict[str, Any]]]:
        """Expose collected tool results as dictionaries."""
        return {
            name: [run.to_dict() for run in runs]
            for name, runs in self.collector.tool_results.items()
        }

    @property
    def protocol_results(self) -> dict[str, list[dict[str, Any]]]:
        """Expose collected protocol results as dictionaries."""
        return {
            name: [run.to_dict() for run in runs]
            for name, runs in self.collector.protocol_results.items()
        }

    @property
    def safety_data(self) -> dict[str, Any]:
        """Expose current safety data."""
        return dict(self.collector.safety_data)

    @staticmethod
    def _render_status(status: dict[str, Any]) -> str:
        lines = [
            "\n[bold blue]\U0001f4ca Reporter Status[/bold blue]",
            f"Session ID: {status['session_id']}",
            f"Output Directory: {status['output_directory']}",
            f"Tool Results: {status['tool_results_count']}",
            f"Protocol Results: {status['protocol_results_count']}",
            (
                "Safety Data: "
                f"{'Available' if status['safety_data_available'] else 'None'}"
            ),
        ]
        if status.get("metadata"):
            lines.append("\n[bold]Fuzzing Session:[/bold]")
            for key, value in status["metadata"].items():
                lines.append(f"  {key}: {value}")
        return "\n".join(lines)

    def cleanup(self):
        """Clean up reporter resources."""
        # Any cleanup needed
        pass
