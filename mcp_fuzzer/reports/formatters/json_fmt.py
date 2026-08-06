"""JSON formatter implementation."""

from __future__ import annotations

from typing import Any

from ...types import extract_tool_runs
from .common import (
    iter_protocol_type_stats,
    normalize_report_data,
    protocol_item_summaries,
    result_has_failure,
    summarize_tool_outcomes,
    summarize_tool_runs,
)


class JSONFormatter:
    """Handles JSON formatting for reports."""

    def format_tool_results(self, results: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_results": results,
            "summary": self._generate_tool_summary(results),
        }

    def format_protocol_results(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
        return {
            "protocol_results": results,
            "summary": self._generate_protocol_summary(results),
            "item_summary": self._generate_protocol_item_summary(results),
        }

    def save_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        """Persist report data to JSON."""
        import json

        data = normalize_report_data(report_data)
        with open(filename, "w") as handle:
            json.dump(data, handle, indent=2, default=str)

    def _generate_tool_summary(self, results: dict[str, Any]) -> dict[str, Any]:
        if not results:
            return {}

        summary = {}
        for tool_name, tool_results in results.items():
            runs, _ = extract_tool_runs(tool_results)
            stats = summarize_tool_runs(runs)

            summary[tool_name] = {
                "total_runs": stats["total_runs"],
                "exceptions": stats["exceptions"],
                "safety_blocked": stats["safety_blocked"],
                "outcomes": summarize_tool_outcomes(runs),
                "success_rate": round(float(stats["success_rate"]), 2),
            }

        return summary

    def _generate_protocol_summary(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
        if not results:
            return {}

        summary = {}
        for protocol_type, total_runs, errors, success_rate in (
            iter_protocol_type_stats(results)
        ):
            summary[protocol_type] = {
                "total_runs": total_runs,
                "errors": errors,
                "success_rate": round(success_rate, 2),
            }

        return summary

    def _generate_protocol_item_summary(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
        if not results:
            return {}

        summary: dict[str, Any] = {}
        for prefix, raw, items in protocol_item_summaries(results):
            if not items:
                continue
            summary[f"{prefix}s"] = items
            summary[f"{prefix}s_failed"] = any(result_has_failure(r) for r in raw)
        return summary
