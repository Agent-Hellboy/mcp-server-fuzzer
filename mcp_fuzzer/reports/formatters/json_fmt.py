"""JSON formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import (
    calculate_protocol_success_rate,
    calculate_tool_success_rate,
    collect_and_summarize_protocol_items,
    extract_tool_runs,
    normalize_report_data,
    result_has_failure,
)
from ...protocol_types import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST


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
            total_runs = len(runs)
            exceptions = sum(1 for r in runs if "exception" in r)
            safety_blocked = sum(1 for r in runs if r.get("safety_blocked", False))
            success_rate = calculate_tool_success_rate(
                total_runs, exceptions, safety_blocked
            )

            summary[tool_name] = {
                "total_runs": total_runs,
                "exceptions": exceptions,
                "safety_blocked": safety_blocked,
                "success_rate": round(success_rate, 2),
            }

        return summary

    def _generate_protocol_summary(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
        if not results:
            return {}

        summary = {}
        for protocol_type, protocol_results in results.items():
            total_runs = len(protocol_results)
            errors = sum(1 for r in protocol_results if result_has_failure(r))
            success_rate = calculate_protocol_success_rate(total_runs, errors)

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

        _, resources = collect_and_summarize_protocol_items(
            results.get(READ_RESOURCE_REQUEST, []), "resource"
        )
        resources_failed = any(
            result_has_failure(r) for r in results.get(READ_RESOURCE_REQUEST, [])
        )
        _, prompts = collect_and_summarize_protocol_items(
            results.get(GET_PROMPT_REQUEST, []), "prompt"
        )
        prompts_failed = any(
            result_has_failure(r) for r in results.get(GET_PROMPT_REQUEST, [])
        )
        summary: dict[str, Any] = {}
        if resources:
            summary["resources"] = resources
            summary["resources_failed"] = resources_failed
        if prompts:
            summary["prompts"] = prompts
            summary["prompts_failed"] = prompts_failed
        return summary
