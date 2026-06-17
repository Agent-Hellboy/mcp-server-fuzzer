"""Normalize tool-run result shapes shared across diagnostics and reports."""

from __future__ import annotations

from typing import Any

from ..types import ExtractedToolRuns, ToolRunResult


def extract_tool_runs(tool_entry: Any) -> ExtractedToolRuns:
    """Extract runnable tool results from reporter or client payload shapes."""
    if isinstance(tool_entry, list):
        return ExtractedToolRuns(tool_entry, None)
    if not isinstance(tool_entry, dict):
        return ExtractedToolRuns([], None)
    runs = tool_entry.get("runs")
    if isinstance(runs, list):
        return ExtractedToolRuns(runs, tool_entry)
    combined: list[ToolRunResult] = []
    realistic = tool_entry.get("realistic")
    aggressive = tool_entry.get("aggressive")
    if isinstance(realistic, list):
        combined.extend(realistic)
    if isinstance(aggressive, list):
        combined.extend(aggressive)
    if combined:
        return ExtractedToolRuns(combined, tool_entry)
    if "error" in tool_entry or "exception" in tool_entry:
        synthetic_run: ToolRunResult = {
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
        return ExtractedToolRuns([synthetic_run], tool_entry)
    return ExtractedToolRuns(combined, tool_entry)


__all__ = ["extract_tool_runs"]
