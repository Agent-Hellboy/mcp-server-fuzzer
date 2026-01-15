"""Console formatter implementation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from .common import calculate_tool_success_rate, extract_tool_runs


def _result_has_failure(result: dict[str, Any]) -> bool:
    """Return True if a result represents a failure condition."""
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )


class ConsoleFormatter:
    """Handles console output formatting."""

    def __init__(self, console: Console):
        self.console = console

    def print_tool_summary(self, results: dict[str, Any]):
        """Print tool fuzzing summary to console."""
        if not results:
            self.console.print("[yellow]No tool results to display[/yellow]")
            return

        table = Table(title="MCP Tool Fuzzing Summary")
        table.add_column("Tool", style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Exceptions", style="red")
        table.add_column("Safety Blocked", style="yellow")
        table.add_column("Success Rate", style="blue")

        for tool_name, tool_results in results.items():
            runs, _ = extract_tool_runs(tool_results)
            total_runs = len(runs)
            exceptions = sum(1 for r in runs if "exception" in r)
            safety_blocked = sum(1 for r in runs if r.get("safety_blocked", False))
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

    def print_protocol_summary(self, results: dict[str, list[dict[str, Any]]]):
        """Print protocol fuzzing summary to console."""
        if not results:
            self.console.print("[yellow]No protocol results to display[/yellow]")
            return

        table = Table(title="MCP Protocol Fuzzing Summary")
        table.add_column("Protocol Type", style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Errors", style="red")
        table.add_column("Success Rate", style="blue")

        for protocol_type, protocol_results in results.items():
            total_runs = len(protocol_results)
            errors = sum(1 for r in protocol_results if _result_has_failure(r))
            successes = max(total_runs - errors, 0)
            success_rate = (successes / total_runs * 100) if total_runs > 0 else 0

            table.add_row(
                protocol_type, str(total_runs), str(errors), f"{success_rate:.1f}%"
            )

        self.console.print(table)

    def print_overall_summary(
        self,
        tool_results: dict[str, Any],
        protocol_results: dict[str, list[dict[str, Any]]],
    ):
        """Print overall summary statistics."""
        total_tools = len(tool_results)
        tools_with_errors = 0
        tools_with_exceptions = 0
        total_tool_runs = 0

        for tool_results_list in tool_results.values():
            runs, _ = extract_tool_runs(tool_results_list)
            total_tool_runs += len(runs)
            for result in runs:
                if "exception" in result:
                    tools_with_exceptions += 1
                elif _result_has_failure(result):
                    tools_with_errors += 1

        total_protocol_types = len(protocol_results)
        protocol_types_with_errors = 0
        protocol_types_with_exceptions = 0
        total_protocol_runs = 0

        for protocol_results_list in protocol_results.values():
            total_protocol_runs += len(protocol_results_list)
            for result in protocol_results_list:
                if "exception" in result:
                    protocol_types_with_exceptions += 1
                elif _result_has_failure(result):
                    protocol_types_with_errors += 1

        self.console.print("\n[bold]Overall Statistics:[/bold]")
        self.console.print(f"Total tools tested: {total_tools}")
        self.console.print(f"Tools with errors: {tools_with_errors}")
        self.console.print(f"Tools with exceptions: {tools_with_exceptions}")
        self.console.print(f"Total protocol types tested: {total_protocol_types}")
        self.console.print(f"Protocol types with errors: {protocol_types_with_errors}")
        self.console.print(
            f"Protocol types with exceptions: {protocol_types_with_exceptions}"
        )
