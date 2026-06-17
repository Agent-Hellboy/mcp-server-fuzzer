"""Console output helpers for ``FuzzerReporter``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..types import extract_tool_runs

if TYPE_CHECKING:
    from .reporter import FuzzerReporter


def print_tool_summary(reporter: FuzzerReporter, results: dict[str, Any]) -> None:
    reporter.console_formatter.print_tool_summary(results)
    for tool_name, tool_results in results.items():
        runs, _ = extract_tool_runs(tool_results)
        reporter.add_tool_results(tool_name, runs)


def print_tool_execution_summary(
    reporter: FuzzerReporter, results: dict[str, Any]
) -> None:
    reporter.console_formatter.print_tool_execution_summary(results)
    for tool_name, tool_results in results.items():
        runs, _ = extract_tool_runs(tool_results)
        reporter.add_tool_results(tool_name, runs)


def print_protocol_summary(
    reporter: FuzzerReporter,
    results: dict[str, list[dict[str, Any]]],
    *,
    title: str = "MCP Protocol Fuzzing Summary",
) -> None:
    reporter.console_formatter.print_protocol_summary(results, title=title)
    for protocol_type, protocol_results in results.items():
        reporter.add_protocol_results(protocol_type, protocol_results)


__all__ = [
    "print_protocol_summary",
    "print_tool_execution_summary",
    "print_tool_summary",
]
