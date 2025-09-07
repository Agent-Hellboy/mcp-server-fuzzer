#!/usr/bin/env python3
"""
Main Reporter for MCP Fuzzer

Handles all reporting functionality including console output, file exports,
and result aggregation.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console

from .formatters import (
    ConsoleFormatter,
    JSONFormatter,
    TextFormatter,
    CSVFormatter,
    XMLFormatter,
    HTMLFormatter,
    MarkdownFormatter,
)
from .output_protocol import OutputManager
from .safety_reporter import SafetyReporter


class FuzzerReporter:
    """Centralized reporter for all MCP Fuzzer output and reporting."""

    def __init__(self, output_dir: str = "reports", compress_output: bool = False):
        # Prioritize the output_dir parameter over global config
        from ..config import config

        # If a custom output_dir was passed (not the default), use it directly
        if output_dir != "reports":
            self.output_dir_config = output_dir
        else:
            # Check global config for custom output directory
            output_config = config.get("output", {})
            self.output_dir_config = config.get(
                "output_dir", output_config.get("directory", output_dir)
            )

        # Load other configuration from global config
        output_config = config.get("output", {})
        self.output_format = output_config.get("format", "json")
        self.output_types = output_config.get("types")
        self.output_schema = output_config.get("schema")
        self.output_compress = output_config.get("compress", compress_output)

        self.output_dir = Path(self.output_dir_config)
        self.output_dir.mkdir(exist_ok=True)

        # Initialize formatters
        self.console = Console()
        self.console_formatter = ConsoleFormatter(self.console)
        self.json_formatter = JSONFormatter()
        self.text_formatter = TextFormatter()
        self.csv_formatter = CSVFormatter()
        self.xml_formatter = XMLFormatter()
        self.html_formatter = HTMLFormatter()
        self.markdown_formatter = MarkdownFormatter()

        # Initialize standardized output manager
        self.output_manager = OutputManager(str(self.output_dir), self.output_compress)

        # Initialize safety reporter
        self.safety_reporter = SafetyReporter()

        # Track all results for final report
        self.tool_results: Dict[str, List[Dict[str, Any]]] = {}
        self.protocol_results: Dict[str, List[Dict[str, Any]]] = {}
        self.safety_data: Dict[str, Any] = {}
        self.fuzzing_metadata: Dict[str, Any] = {}

        # Use session ID from output manager
        self.session_id = self.output_manager.protocol.session_id

        logging.info(
            f"FuzzerReporter initialized with output directory: {self.output_dir}"
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
        self.fuzzing_metadata = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "mode": mode,
            "protocol": protocol,
            "endpoint": endpoint,
            "runs": runs,
            "runs_per_type": runs_per_type,
            "fuzzer_version": "1.0.0",  # TODO: Get from package
        }

    def add_tool_results(self, tool_name: str, results: List[Dict[str, Any]]):
        """Add tool fuzzing results to the reporter."""
        self.tool_results[tool_name] = results

    def add_protocol_results(self, protocol_type: str, results: List[Dict[str, Any]]):
        """Add protocol fuzzing results to the reporter."""
        self.protocol_results[protocol_type] = results

    def add_safety_data(self, safety_data: Dict[str, Any]):
        """Add safety system data to the reporter."""
        self.safety_data.update(safety_data)

    def print_tool_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print tool fuzzing summary to console."""
        self.console_formatter.print_tool_summary(results)

        # Store results for final report
        for tool_name, tool_results in results.items():
            self.add_tool_results(tool_name, tool_results)

    def print_protocol_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print protocol fuzzing summary to console."""
        self.console_formatter.print_protocol_summary(results)

        # Store results for final report
        for protocol_type, protocol_results in results.items():
            self.add_protocol_results(protocol_type, protocol_results)

    def print_overall_summary(
        self,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
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

    def generate_final_report(self, include_safety: bool = True) -> str:
        """Generate comprehensive final report and save to file."""
        report_data = {
            "metadata": self.fuzzing_metadata,
            "tool_results": self.tool_results,
            "protocol_results": self.protocol_results,
            "summary": self._generate_summary_stats(),
        }

        if include_safety:
            report_data["safety"] = self.safety_reporter.get_comprehensive_safety_data()

        # Add end time
        report_data["metadata"]["end_time"] = datetime.now().isoformat()

        # Save JSON report
        json_filename = self.output_dir / f"fuzzing_report_{self.session_id}.json"
        with open(json_filename, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        # Save text report
        text_filename = self.output_dir / f"fuzzing_report_{self.session_id}.txt"
        self.text_formatter.save_text_report(report_data, text_filename)

        # Save safety-specific report if available
        if include_safety and self.safety_reporter.has_safety_data():
            safety_filename = self.output_dir / f"safety_report_{self.session_id}.json"
            self.safety_reporter.export_safety_data(str(safety_filename))

        logging.info(f"Final report generated: {json_filename}")
        return str(json_filename)

    def generate_standardized_report(
        self,
        output_types: List[str] = None,
        include_safety: bool = True
    ) -> Dict[str, str]:
        """Generate standardized reports using the new output protocol."""
        generated_files = {}

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
                execution_time = self._calculate_execution_time()
                total_tests = self._get_total_test_count()
                success_rate = self._calculate_overall_success_rate()

                filepath = self.output_manager.save_fuzzing_results(
                    mode=self.fuzzing_metadata.get("mode", "unknown"),
                    protocol=self.fuzzing_metadata.get("protocol", "unknown"),
                    endpoint=self.fuzzing_metadata.get("endpoint", "unknown"),
                    tool_results=self.tool_results,
                    protocol_results=self.protocol_results,
                    execution_time=execution_time,
                    total_tests=total_tests,
                    success_rate=success_rate,
                    safety_enabled=include_safety,
                )
                generated_files["fuzzing_results"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized fuzzing results: {e}")

        # Generate safety summary
        if "safety_summary" in output_types and include_safety:
            try:
                safety_data = self.safety_reporter.get_comprehensive_safety_data()
                filepath = self.output_manager.save_safety_summary(safety_data)
                generated_files["safety_summary"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized safety summary: {e}")

        # Generate error report if there are errors
        if "error_report" in output_types:
            try:
                errors = self._collect_errors()
                if errors:
                    filepath = self.output_manager.save_error_report(
                        errors=errors,
                        execution_context=self.fuzzing_metadata
                    )
                    generated_files["error_report"] = filepath
            except Exception as e:
                logging.error(f"Failed to generate standardized error report: {e}")

        return generated_files

    def _generate_summary_stats(self) -> Dict[str, Any]:
        """Generate summary statistics from all results."""
        # Tool statistics
        total_tools = len(self.tool_results)
        tools_with_errors = 0
        tools_with_exceptions = 0
        total_tool_runs = 0

        for tool_results in self.tool_results.values():
            total_tool_runs += len(tool_results)
            for result in tool_results:
                if "error" in result:
                    tools_with_errors += 1
                if "exception" in result:
                    tools_with_exceptions += 1

        # Protocol statistics
        total_protocol_types = len(self.protocol_results)
        protocol_types_with_errors = 0
        protocol_types_with_exceptions = 0
        total_protocol_runs = 0

        for protocol_results in self.protocol_results.values():
            total_protocol_runs += len(protocol_results)
            for result in protocol_results:
                if "error" in result:
                    protocol_types_with_errors += 1
                if "exception" in result:
                    protocol_types_with_exceptions += 1

        return {
            "tools": {
                "total_tools": total_tools,
                "total_runs": total_tool_runs,
                "tools_with_errors": tools_with_errors,
                "tools_with_exceptions": tools_with_exceptions,
                "success_rate": (
                    (
                        (total_tool_runs - tools_with_errors - tools_with_exceptions)
                        / total_tool_runs
                        * 100
                    )
                    if total_tool_runs > 0
                    else 0
                ),
            },
            "protocols": {
                "total_protocol_types": total_protocol_types,
                "total_runs": total_protocol_runs,
                "protocol_types_with_errors": protocol_types_with_errors,
                "protocol_types_with_exceptions": protocol_types_with_exceptions,
                "success_rate": (
                    (
                        (
                            total_protocol_runs
                            - protocol_types_with_errors
                            - protocol_types_with_exceptions
                        )
                        / total_protocol_runs
                        * 100
                    )
                    if total_protocol_runs > 0
                    else 0
                ),
            },
        }

    def export_safety_data(self, filename: str = None) -> str:
        """Export safety data to JSON file."""
        return self.safety_reporter.export_safety_data(filename)

    def get_output_directory(self) -> Path:
        """Get the output directory path."""
        return self.output_dir

    def get_current_status(self) -> Dict[str, Any]:
        """Get current status of the reporter."""
        return {
            "session_id": self.session_id,
            "output_directory": str(self.output_dir),
            "tool_results_count": len(self.tool_results),
            "protocol_results_count": len(self.protocol_results),
            "safety_data_available": bool(self.safety_data),
            "metadata": self.fuzzing_metadata,
        }

    def print_status(self):
        """Print current status to console."""
        status = self.get_current_status()

        self.console.print("\n[bold blue]\U0001f4ca Reporter Status[/bold blue]")
        self.console.print(f"Session ID: {status['session_id']}")
        self.console.print(f"Output Directory: {status['output_directory']}")
        self.console.print(f"Tool Results: {status['tool_results_count']}")
        self.console.print(f"Protocol Results: {status['protocol_results_count']}")
        self.console.print(
            f"Safety Data: {'Available' if status['safety_data_available'] else 'None'}"
        )

        if status["metadata"]:
            self.console.print("\n[bold]Fuzzing Session:[/bold]")
            for key, value in status["metadata"].items():
                self.console.print(f"  {key}: {value}")

    def export_csv(self, filename: str):
        """Export report data to CSV format."""
        report_data = self._get_report_data()
        self.csv_formatter.save_csv_report(report_data, filename)

    def export_xml(self, filename: str):
        """Export report data to XML format."""
        report_data = self._get_report_data()
        self.xml_formatter.save_xml_report(report_data, filename)

    def export_html(self, filename: str, title: str = "Fuzzing Results Report"):
        """Export report data to HTML format."""
        report_data = self._get_report_data()
        self.html_formatter.save_html_report(report_data, filename, title)

    def export_markdown(self, filename: str):
        """Export report data to Markdown format."""
        report_data = self._get_report_data()
        self.markdown_formatter.save_markdown_report(report_data, filename)

    def _get_report_data(self) -> Dict[str, Any]:
        """Get complete report data for export."""
        return {
            "metadata": self.fuzzing_metadata,
            "tool_results": self.tool_results,
            "protocol_results": self.protocol_results,
            "summary": self._generate_summary_stats(),
            "safety": (
                self.safety_reporter.get_comprehensive_safety_data()
                if self.safety_data
                else {}
            ),
        }

    def _calculate_execution_time(self) -> str:
        """Calculate total execution time."""
        start_time = self.fuzzing_metadata.get("start_time")
        end_time = self.fuzzing_metadata.get("end_time", datetime.now().isoformat())

        if start_time:
            try:
                start = datetime.fromisoformat(start_time)
                end = datetime.fromisoformat(end_time)
                duration = end - start
                return f"PT{duration.total_seconds()}S"
            except Exception:
                pass

        return "PT0S"

    def _get_total_test_count(self) -> int:
        """Get total number of tests run."""
        tool_tests = sum(len(results) for results in self.tool_results.values())
        protocol_tests = sum(len(results) for results in self.protocol_results.values())
        return tool_tests + protocol_tests

    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate across all tests."""
        total_tests = self._get_total_test_count()
        if total_tests == 0:
            return 0.0

        successful_tests = 0

        # Count successful tool tests
        for tool_results in self.tool_results.values():
            for result in tool_results:
                if ("exception" not in result and
                    not result.get("safety_blocked", False)):
                    successful_tests += 1

        # Count successful protocol tests
        for protocol_results in self.protocol_results.values():
            for result in protocol_results:
                if result.get("success", True):
                    successful_tests += 1

        return (successful_tests / total_tests) * 100

    def _collect_errors(self) -> List[Dict[str, Any]]:
        """Collect all errors from test results."""
        errors = []

        # Collect tool errors
        for tool_name, tool_results in self.tool_results.items():
            for i, result in enumerate(tool_results):
                if "exception" in result:
                    errors.append({
                        "type": "tool_error",
                        "tool_name": tool_name,
                        "run_number": i + 1,
                        "severity": "medium",
                        "message": str(result["exception"]),
                        "arguments": result.get("args", {}),
                    })

        # Collect protocol errors
        for protocol_type, protocol_results in self.protocol_results.items():
            for i, result in enumerate(protocol_results):
                if not result.get("success", True):
                    errors.append({
                        "type": "protocol_error",
                        "protocol_type": protocol_type,
                        "run_number": i + 1,
                        "severity": "medium",
                        "message": result.get("error", "Unknown protocol error"),
                        "details": result,
                    })

        return errors

    def cleanup(self):
        """Clean up reporter resources."""
        # Any cleanup needed
        pass
