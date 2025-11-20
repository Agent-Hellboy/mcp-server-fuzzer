"""Shared formatter helpers."""

from __future__ import annotations

from typing import Any, Protocol


class SupportsToDict(Protocol):
    def to_dict(self) -> dict[str, Any]:
        ...


def normalize_report_data(
    report: dict[str, Any] | SupportsToDict,
) -> dict[str, Any]:
    if hasattr(report, "to_dict"):
        return report.to_dict()  # type: ignore[return-value]
    return report


def calculate_tool_success_rate(
    total_runs: int,
    exceptions: int,
    safety_blocked: int,
) -> float:
    if total_runs <= 0:
        return 0.0
    successful_runs = max(0, total_runs - exceptions - safety_blocked)
    return (successful_runs / total_runs) * 100
