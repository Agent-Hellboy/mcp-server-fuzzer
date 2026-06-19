"""Compact machine-readable run summary for CI integrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..types import ExtractedToolRuns, extract_tool_runs
from .formatters.common import (
    result_has_failure,
    summarize_tool_outcomes,
    summarize_tool_runs,
)


def build_run_summary(
    *,
    mode: str,
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
    blocked: bool,
    findings_summary: dict[str, int] | None = None,
    tool_discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a small JSON summary intended for CI post-run checks."""
    tool_entries: dict[str, Any] = {}
    total_tool_runs = 0
    for tool_name, entry in (tool_results or {}).items():
        extracted: ExtractedToolRuns = extract_tool_runs(entry)
        runs = extracted.runs
        stats = summarize_tool_runs(runs)
        buckets = summarize_tool_outcomes(runs)
        total_tool_runs += int(stats["total_runs"])
        tool_entries[tool_name] = {
            "total_runs": stats["total_runs"],
            "successful": stats["successful"],
            "failures": stats["failures"],
            "exceptions": stats["exceptions"],
            "safety_blocked": stats["safety_blocked"],
            "success_rate": round(float(stats["success_rate"]), 2),
            "outcomes": buckets,
        }

    protocol_entries: dict[str, Any] = {}
    total_protocol_runs = 0
    for protocol_type, runs in (protocol_results or {}).items():
        if not isinstance(runs, list):
            continue
        total_runs = len(runs)
        failures = sum(1 for run in runs if result_has_failure(run))
        total_protocol_runs += total_runs
        protocol_entries[protocol_type] = {
            "total_runs": total_runs,
            "failures": failures,
        }

    status = "blocked" if blocked else "completed"
    summary: dict[str, Any] = {
        "mode": mode,
        "status": status,
        "tools": {
            "total": len(tool_entries),
            "total_runs": total_tool_runs,
            "by_name": tool_entries,
        },
        "protocols": {
            "total": len(protocol_entries),
            "total_runs": total_protocol_runs,
            "by_type": protocol_entries,
        },
        "findings": {
            "total": sum((findings_summary or {}).values()),
            "by_category": findings_summary or {},
        },
    }
    if blocked and tool_discovery:
        summary["blocked_reason"] = tool_discovery.get("failure", "unknown")
        summary["blocked_detail"] = tool_discovery.get("detail", "")
        summary["tool_discovery"] = tool_discovery
    elif tool_discovery:
        summary["tool_discovery"] = tool_discovery
    return summary


def write_run_summary(output_dir: str | Path, summary: dict[str, Any]) -> Path:
    """Write ``run_summary.json`` to the configured output directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "run_summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = ["build_run_summary", "write_run_summary"]
