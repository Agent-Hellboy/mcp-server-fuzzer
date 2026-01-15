"""Shared formatter helpers."""

from __future__ import annotations

from typing import Any, Protocol


class SupportsToDict(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


def normalize_report_data(
    report: dict[str, Any] | SupportsToDict,
) -> dict[str, Any]:
    if hasattr(report, "to_dict"):
        return report.to_dict()  # type: ignore[return-value]
    return report


def extract_tool_runs(
    tool_entry: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if isinstance(tool_entry, dict):
        if "runs" in tool_entry:
            runs = tool_entry.get("runs")
            if isinstance(runs, list):
                return runs, tool_entry
        realistic = tool_entry.get("realistic")
        aggressive = tool_entry.get("aggressive")
        if isinstance(realistic, list) or isinstance(aggressive, list):
            combined: list[dict[str, Any]] = []
            if isinstance(realistic, list):
                combined.extend(realistic)
            if isinstance(aggressive, list):
                combined.extend(aggressive)
            return combined, tool_entry
        return [], tool_entry
    if isinstance(tool_entry, list):
        return tool_entry, None
    return [], None


def calculate_tool_success_rate(
    total_runs: int,
    exceptions: int,
    safety_blocked: int,
) -> float:
    if total_runs <= 0:
        return 0.0
    successful_runs = max(0, total_runs - exceptions - safety_blocked)
    return (successful_runs / total_runs) * 100
