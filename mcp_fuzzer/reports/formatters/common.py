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
    if isinstance(tool_entry, list):
        return tool_entry, None
    if not isinstance(tool_entry, dict):
        return [], None
    runs = tool_entry.get("runs")
    if isinstance(runs, list):
        return runs, tool_entry
    combined: list[dict[str, Any]] = []
    realistic = tool_entry.get("realistic")
    aggressive = tool_entry.get("aggressive")
    if isinstance(realistic, list):
        combined.extend(realistic)
    if isinstance(aggressive, list):
        combined.extend(aggressive)
    return combined, tool_entry


def calculate_tool_success_rate(
    total_runs: int,
    exceptions: int,
    safety_blocked: int,
) -> float:
    if total_runs <= 0:
        return 0.0
    successful_runs = max(0, total_runs - exceptions - safety_blocked)
    return (successful_runs / total_runs) * 100


def result_has_failure(result: dict[str, Any]) -> bool:
    """Return True if a protocol result represents an error condition."""
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )


def collect_labeled_protocol_items(
    protocol_results: list[dict[str, Any]], prefix: str
) -> dict[str, list[dict[str, Any]]]:
    """Collect protocol results grouped by a label prefix."""
    items: dict[str, list[dict[str, Any]]] = {}
    for result in protocol_results:
        label = result.get("label")
        if not isinstance(label, str) or not label.startswith(prefix):
            continue
        name = label[len(prefix) :]
        if not name:
            continue
        items.setdefault(name, []).append(result)
    return items


def summarize_protocol_items(
    items: dict[str, list[dict[str, Any]]]
) -> dict[str, dict[str, Any]]:
    """Summarize grouped protocol items by runs/errors/success rate."""
    summary: dict[str, dict[str, Any]] = {}
    for name, item_results in items.items():
        total_runs = len(item_results)
        errors = sum(1 for r in item_results if result_has_failure(r))
        successes = max(total_runs - errors, 0)
        success_rate = (successes / total_runs * 100) if total_runs > 0 else 0
        summary[name] = {
            "total_runs": total_runs,
            "errors": errors,
            "success_rate": round(success_rate, 2),
        }
    return summary
