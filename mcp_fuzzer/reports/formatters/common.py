"""Shared formatter helpers."""

from __future__ import annotations

from typing import Any, Iterable, Literal, Protocol


class SupportsToDict(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


LabelPrefix = Literal["resource", "prompt", "tool"]
LABEL_PREFIXES: tuple[LabelPrefix, ...] = ("resource", "prompt", "tool")


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
    if combined:
        return combined, tool_entry
    if "error" in tool_entry or "exception" in tool_entry:
        synthetic_run: dict[str, Any] = {
            "success": bool(tool_entry.get("success", False)),
            "safety_blocked": bool(tool_entry.get("safety_blocked", False)),
            "safety_sanitized": bool(tool_entry.get("safety_sanitized", False)),
        }
        if "args" in tool_entry:
            synthetic_run["args"] = tool_entry.get("args")
        if "label" in tool_entry:
            synthetic_run["label"] = tool_entry.get("label")
        if "error" in tool_entry:
            synthetic_run["error"] = tool_entry.get("error")
        if "exception" in tool_entry:
            synthetic_run["exception"] = tool_entry.get("exception")
        return [synthetic_run], tool_entry
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


def tool_run_has_exception(result: dict[str, Any] | None) -> bool:
    """Return True when a tool result has a non-safety exception."""
    if not isinstance(result, dict):
        return False
    if result.get("safety_blocked", False):
        return False
    return bool(result.get("exception"))


def tool_run_has_failure(result: dict[str, Any] | None) -> bool:
    """Return True when a tool result should count as a failed run."""
    if not isinstance(result, dict):
        return True
    if result.get("safety_blocked", False):
        return True
    return bool(
        tool_run_has_exception(result)
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )


def summarize_tool_runs(runs: list[dict[str, Any]]) -> dict[str, int | float]:
    """Return non-overlapping summary counters for tool run reporting."""
    total_runs = len(runs)
    exceptions = sum(1 for run in runs if tool_run_has_exception(run))
    safety_blocked = sum(1 for run in runs if run.get("safety_blocked", False))
    failures = sum(1 for run in runs if tool_run_has_failure(run))
    successful = max(total_runs - failures, 0)
    success_rate = (successful / total_runs) * 100 if total_runs > 0 else 0.0
    return {
        "total_runs": total_runs,
        "exceptions": exceptions,
        "safety_blocked": safety_blocked,
        "failures": failures,
        "successful": successful,
        "success_rate": success_rate,
    }


def calculate_protocol_success_rate(total_runs: int, errors: int) -> float:
    """Calculate success rate for protocol-style results."""
    if total_runs <= 0:
        return 0.0
    successful_runs = max(0, total_runs - errors)
    return (successful_runs / total_runs) * 100


def result_has_failure(result: dict[str, Any] | None) -> bool:
    """Return True if a protocol result represents an error condition."""
    if not isinstance(result, dict):
        return True
    nested_error = None
    result_payload = result.get("result")
    if isinstance(result_payload, dict):
        response = result_payload.get("response")
        if isinstance(response, dict):
            nested_error = response.get("error")
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
        or nested_error
    )


def _parse_label(label: Any) -> tuple[LabelPrefix | None, str | None]:
    """Parse a label formatted as '{prefix}:{name}'."""
    if not isinstance(label, str):
        return None, None
    prefix, separator, name = label.partition(":")
    if separator != ":" or not name:
        return None, None
    if prefix not in LABEL_PREFIXES:
        return None, None
    return prefix, name


def collect_labeled_protocol_items(
    protocol_results: Iterable[Any], prefix: LabelPrefix
) -> dict[str, list[dict[str, Any]]]:
    """Collect protocol results grouped by a known label prefix."""
    items: dict[str, list[dict[str, Any]]] = {}
    for result in protocol_results:
        if not isinstance(result, dict):
            continue
        label = result.get("label")
        parsed_prefix, name = _parse_label(label)
        if parsed_prefix != prefix or not name:
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
        success_rate = calculate_protocol_success_rate(total_runs, errors)
        summary[name] = {
            "total_runs": total_runs,
            "errors": errors,
            "success_rate": round(success_rate, 2),
        }
    return summary


def collect_and_summarize_protocol_items(
    protocol_results: Iterable[Any], prefix: LabelPrefix
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """Collect labeled protocol items and summarize them."""
    items = collect_labeled_protocol_items(protocol_results, prefix)
    return items, summarize_protocol_items(items)
