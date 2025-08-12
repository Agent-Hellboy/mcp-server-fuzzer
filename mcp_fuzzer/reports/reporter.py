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

from .formatters import ConsoleFormatter, JSONFormatter, TextFormatter
from .safety_reporter import SafetyReporter


class FuzzerReporter:
    """Centralized reporter for all MCP Fuzzer output and reporting."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Initialize formatters
        self.console = Console()
        self.console_formatter = ConsoleFormatter(self.console)
        self.json_formatter = JSONFormatter()
        self.text_formatter = TextFormatter()

        # Initialize safety reporter
        self.safety_reporter = SafetyReporter()

        # Track all results for final report
        self.tool_results: Dict[str, List[Dict[str, Any]]] = {}
        self.protocol_results: Dict[str, List[Dict[str, Any]]] = {}
        self.safety_data: Dict[str, Any] = {}
        self.fuzzing_metadata: Dict[str, Any] = {}

        # Generate unique session ID
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

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

    def cleanup(self):
        """Clean up reporter resources."""
        # Any cleanup needed
        pass
