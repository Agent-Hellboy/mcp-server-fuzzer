#!/usr/bin/env python3
"""
Formatters for MCP Fuzzer Reports

Handles different output formats including console, JSON, and text.
"""

from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table


def calculate_tool_success_rate(
    total_runs: int, exceptions: int, safety_blocked: int
) -> float:
    """Calculate success rate for tool runs."""
    if total_runs <= 0:
        return 0.0
    successful_runs = max(0, total_runs - exceptions - safety_blocked)
    return (successful_runs / total_runs) * 100


class ConsoleFormatter:
    """Handles console output formatting."""

    def __init__(self, console: Console):
        self.console = console

    def print_tool_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print tool fuzzing summary to console."""
        if not results:
            self.console.print("[yellow]No tool results to display[/yellow]")
            return

        # Create summary table
        table = Table(title="MCP Tool Fuzzing Summary")
        table.add_column("Tool", style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Exceptions", style="red")
        table.add_column("Safety Blocked", style="yellow")
        table.add_column("Success Rate", style="blue")

        for tool_name, tool_results in results.items():
            total_runs = len(tool_results)
            exceptions = sum(1 for r in tool_results if "exception" in r)
            safety_blocked = sum(
                1 for r in tool_results if r.get("safety_blocked", False)
            )
            success_rate = calculate_tool_success_rate(
                total_runs, exceptions, safety_blocked
            )

            table.add_row(
                tool_name,
                str(total_runs),
                str(exceptions),
                str(safety_blocked),
                f"{success_rate:.1f}%",
            )

        self.console.print(table)

    def print_protocol_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print protocol fuzzing summary to console."""
        if not results:
            self.console.print("[yellow]No protocol results to display[/yellow]")
            return

        # Create summary table
        table = Table(title="MCP Protocol Fuzzing Summary")
        table.add_column("Protocol Type", style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Errors", style="red")
        table.add_column("Success Rate", style="blue")

        for protocol_type, protocol_results in results.items():
            total_runs = len(protocol_results)
            errors = sum(1 for r in protocol_results if not r.get("success", True))
            success_rate = (
                ((total_runs - errors) / total_runs * 100) if total_runs > 0 else 0
            )

            table.add_row(
                protocol_type, str(total_runs), str(errors), f"{success_rate:.1f}%"
            )

        self.console.print(table)

    def print_overall_summary(
        self,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
    ):
        """Print overall summary statistics."""
        # Tool statistics
        total_tools = len(tool_results)
        tools_with_errors = 0
        tools_with_exceptions = 0
        total_tool_runs = 0

        for tool_results_list in tool_results.values():
            total_tool_runs += len(tool_results_list)
            for result in tool_results_list:
                if "error" in result:
                    tools_with_errors += 1
                if "exception" in result:
                    tools_with_exceptions += 1

        # Protocol statistics
        total_protocol_types = len(protocol_results)
        protocol_types_with_errors = 0
        protocol_types_with_exceptions = 0
        total_protocol_runs = 0

        for protocol_results_list in protocol_results.values():
            total_protocol_runs += len(protocol_results_list)
            for result in protocol_results_list:
                if "error" in result:
                    protocol_types_with_errors += 1
                if "exception" in result:
                    protocol_types_with_exceptions += 1

        self.console.print("\n[bold]Overall Statistics:[/bold]")
        self.console.print(f"Total tools tested: {total_tools}")
        self.console.print(f"Tools with errors: {tools_with_errors}")
        self.console.print(f"Tools with exceptions: {tools_with_exceptions}")
        self.console.print(f"Total protocol types tested: {total_protocol_types}")
        self.console.print(f"Protocol types with errors: {protocol_types_with_errors}")
        self.console.print(
            f"Protocol types with exceptions: {protocol_types_with_exceptions}"
        )


class JSONFormatter:
    """Handles JSON formatting for reports."""

    def format_tool_results(
        self, results: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Format tool results for JSON export."""
        return {
            "tool_results": results,
            "summary": self._generate_tool_summary(results),
        }

    def format_protocol_results(
        self, results: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Format protocol results for JSON export."""
        return {
            "protocol_results": results,
            "summary": self._generate_protocol_summary(results),
        }

    def _generate_tool_summary(
        self, results: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Generate tool summary statistics."""
        if not results:
            return {}

        summary = {}
        for tool_name, tool_results in results.items():
            total_runs = len(tool_results)
            exceptions = sum(1 for r in tool_results if "exception" in r)
            safety_blocked = sum(
                1 for r in tool_results if r.get("safety_blocked", False)
            )
            success_rate = calculate_tool_success_rate(
                total_runs, exceptions, safety_blocked
            )

            summary[tool_name] = {
                "total_runs": total_runs,
                "exceptions": exceptions,
                "safety_blocked": safety_blocked,
                "success_rate": round(success_rate, 2),
            }

        return summary

    def _generate_protocol_summary(
        self, results: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Generate protocol summary statistics."""
        if not results:
            return {}

        summary = {}
        for protocol_type, protocol_results in results.items():
            total_runs = len(protocol_results)
            errors = sum(1 for r in protocol_results if not r.get("success", True))
            success_rate = (
                ((total_runs - errors) / total_runs * 100) if total_runs > 0 else 0
            )

            summary[protocol_type] = {
                "total_runs": total_runs,
                "errors": errors,
                "success_rate": round(success_rate, 2),
            }

        return summary


class TextFormatter:
    """Handles text formatting for reports."""

    def save_text_report(self, report_data: Dict[str, Any], filename: str):
        """Save report data as formatted text file."""
        with open(filename, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("MCP FUZZER REPORT\n")
            f.write("=" * 80 + "\n\n")

            # Metadata
            if "metadata" in report_data:
                f.write("FUZZING SESSION METADATA\n")
                f.write("-" * 40 + "\n")
                for key, value in report_data["metadata"].items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")

            # Summary
            if "summary" in report_data:
                f.write("SUMMARY STATISTICS\n")
                f.write("-" * 40 + "\n")
                summary = report_data["summary"]

                if "tools" in summary:
                    tools = summary["tools"]
                    f.write(f"Tools Tested: {tools['total_tools']}\n")
                    f.write(f"Total Tool Runs: {tools['total_runs']}\n")
                    f.write(f"Tools with Errors: {tools['tools_with_errors']}\n")
                    f.write(
                        f"Tools with Exceptions: {tools['tools_with_exceptions']}\n"
                    )
                    f.write(f"Tool Success Rate: {tools['success_rate']:.1f}%\n\n")

                if "protocols" in summary:
                    protocols = summary["protocols"]
                    f.write(
                        f"Protocol Types Tested: {protocols['total_protocol_types']}\n"
                    )
                    f.write(f"Total Protocol Runs: {protocols['total_runs']}\n")
                    f.write(
                        (
                            "Protocol Types with Errors: "
                            f"{protocols['protocol_types_with_errors']}\n"
                        )
                    )
                    f.write(
                        (
                            "Protocol Types with Exceptions: "
                            f"{protocols['protocol_types_with_exceptions']}\n"
                        )
                    )
                    f.write(
                        f"Protocol Success Rate: {protocols['success_rate']:.1f}%\n\n"
                    )

            # Tool Results
            if "tool_results" in report_data:
                f.write("TOOL FUZZING RESULTS\n")
                f.write("-" * 40 + "\n")
                for tool_name, results in report_data["tool_results"].items():
                    f.write(f"\nTool: {tool_name}\n")
                    f.write(f"  Total Runs: {len(results)}\n")

                    exceptions = sum(1 for r in results if "exception" in r)
                    safety_blocked = sum(
                        1 for r in results if r.get("safety_blocked", False)
                    )
                    f.write(f"  Exceptions: {exceptions}\n")
                    f.write(f"  Safety Blocked: {safety_blocked}\n")

                    if results:
                        success_rate = (
                            (len(results) - exceptions - safety_blocked)
                            / len(results)
                            * 100
                        )
                        f.write(f"  Success Rate: {success_rate:.1f}%\n")

            # Protocol Results
            if "protocol_results" in report_data:
                f.write("\n\nPROTOCOL FUZZING RESULTS\n")
                f.write("-" * 40 + "\n")
                for protocol_type, results in report_data["protocol_results"].items():
                    f.write(f"\nProtocol Type: {protocol_type}\n")
                    f.write(f"  Total Runs: {len(results)}\n")

                    errors = sum(1 for r in results if not r.get("success", True))
                    f.write(f"  Errors: {errors}\n")

                    if results:
                        success_rate = (len(results) - errors) / len(results) * 100
                        f.write(f"  Success Rate: {success_rate:.1f}%\n")

            # Safety Data
            if "safety" in report_data:
                f.write("\n\nSAFETY SYSTEM DATA\n")
                f.write("-" * 40 + "\n")
                safety = report_data["safety"]
                if "summary" in safety:
                    summary = safety["summary"]
                    f.write(
                        f"Total Operations Blocked: {summary.get('total_blocked', 0)}\n"
                    )
                    f.write(
                        (
                            "Unique Tools Blocked: "
                            f"{summary.get('unique_tools_blocked', 0)}\n"
                        )
                    )
                    f.write(
                        (
                            "Risk Assessment: "
                            f"{summary.get('risk_assessment', 'unknown').upper()}\n"
                        )
                    )

            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by MCP Fuzzer\n")
            f.write("=" * 80 + "\n")
