"""Console formatter implementation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from .common import (
    calculate_protocol_success_rate,
    calculate_tool_success_rate,
    collect_and_summarize_protocol_items,
    extract_tool_runs,
    result_has_failure,
)
from ...protocol_types import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST


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

    def print_protocol_summary(
        self,
        results: dict[str, list[dict[str, Any]]],
        *,
        title: str = "MCP Protocol Fuzzing Summary",
    ):
        """Print protocol fuzzing summary to console."""
        if not results:
            self.console.print("[yellow]No protocol results to display[/yellow]")
            return

        table = Table(title=title)
        table.add_column("Protocol Type", style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Errors", style="red")
        table.add_column("Success Rate", style="blue")

        for protocol_type, protocol_results in results.items():
            total_runs = len(protocol_results)
            errors = sum(1 for r in protocol_results if result_has_failure(r))
            success_rate = calculate_protocol_success_rate(total_runs, errors)

            table.add_row(
                protocol_type, str(total_runs), str(errors), f"{success_rate:.1f}%"
            )

        self.console.print(table)
        self._print_protocol_item_summaries(results)

    def _print_protocol_item_summaries(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> None:
        _, resource_summary = collect_and_summarize_protocol_items(
            results.get(READ_RESOURCE_REQUEST, []), "resource"
        )
        if resource_summary:
            self._print_protocol_item_summary(
                "MCP Resource Item Fuzzing Summary", "Resource", resource_summary
            )

        _, prompt_summary = collect_and_summarize_protocol_items(
            results.get(GET_PROMPT_REQUEST, []), "prompt"
        )
        if prompt_summary:
            self._print_protocol_item_summary(
                "MCP Prompt Item Fuzzing Summary", "Prompt", prompt_summary
            )
    def _print_protocol_item_summary(
        self, title: str, name_header: str, summary: dict[str, dict[str, Any]]
    ) -> None:
        table = Table(title=title)
        table.add_column(name_header, style="cyan", no_wrap=True)
        table.add_column("Total Runs", style="green")
        table.add_column("Errors", style="red")
        table.add_column("Success Rate", style="blue")

        for item_name, stats in summary.items():
            total_runs = stats.get("total_runs", 0)
            errors = stats.get("errors", 0)
            success_rate = calculate_protocol_success_rate(total_runs, errors)
            table.add_row(
                item_name, str(total_runs), str(errors), f"{success_rate:.1f}%"
            )

        self.console.print(table)

    def print_spec_guard_summary(
        self,
        checks: list[dict[str, Any]],
        *,
        requested_version: str | None = None,
        negotiated_version: str | None = None,
    ):
        """Print spec guard (compliance) summary to console."""
        if negotiated_version and requested_version:
            if negotiated_version != requested_version:
                self.console.print(
                    "[bold]Negotiated MCP spec version "
                    f"{negotiated_version} (requested {requested_version}); "
                    "compliance checks below.[/bold]"
                )
            else:
                self.console.print(
                    "[bold]Negotiated MCP spec version "
                    f"{negotiated_version}; compliance checks below.[/bold]"
                )
        elif negotiated_version:
            self.console.print(
                "[bold]Negotiated MCP spec version "
                f"{negotiated_version}; compliance checks below.[/bold]"
            )
        elif requested_version:
            self.console.print(
                "[bold]Compliance checks for MCP spec version "
                f"{requested_version}.[/bold]"
            )
        else:
            self.console.print("[bold]MCP compliance checks[/bold]")

        if not checks:
            self.console.print("[yellow]No compliance checks recorded[/yellow]")
            return

        totals = {"total": 0, "failed": 0, "warned": 0, "passed": 0}
        status_order = {"FAIL": 0, "FAILURE": 0, "ERROR": 0, "WARN": 1, "WARNING": 1}

        def _status_rank(status: str) -> int:
            return status_order.get(status, 2)

        table = Table(title="MCP Compliance Checks")
        table.add_column("Status", style="cyan", no_wrap=True)
        table.add_column("Check", style="green", no_wrap=True)
        table.add_column("Spec", style="magenta", no_wrap=True)
        table.add_column("Message", style="white", overflow="fold")

        for check in sorted(
            checks,
            key=lambda c: _status_rank(str(c.get("status", "")).upper()),
        ):
            status = str(check.get("status", "PASS")).upper()
            check_id = str(check.get("id", "unknown"))
            spec_id = str(check.get("spec_id", "UNKNOWN"))
            message = str(check.get("message", ""))

            totals["total"] += 1
            if status in ("FAIL", "FAILURE", "ERROR"):
                totals["failed"] += 1
                status_style = "red"
            elif status in ("WARN", "WARNING"):
                totals["warned"] += 1
                status_style = "yellow"
            else:
                totals["passed"] += 1
                status_style = "green"

            table.add_row(
                f"[{status_style}]{status}[/{status_style}]",
                check_id,
                spec_id,
                message,
            )

        table.caption = (
            "Total: {total} | Failed: {failed} | Warned: {warned} | Passed: {passed}"
        ).format(**totals)
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
                elif result_has_failure(result):
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
                elif result_has_failure(result):
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
