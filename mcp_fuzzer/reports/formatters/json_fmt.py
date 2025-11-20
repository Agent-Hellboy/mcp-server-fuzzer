"""JSON formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import (
    calculate_tool_success_rate,
    normalize_report_data,
)


class JSONFormatter:
    """Handles JSON formatting for reports."""

    def format_tool_results(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
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

    def _generate_tool_summary(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> dict[str, Any]:
        if not results:
            return {}

        summary = {}
        for tool_name, tool_results in results.items():
            total_runs = len(tool_results)
            exceptions = sum(1 for r in tool_results if "exception" in r)
            safety_blocked = sum(
                1 for r in tool_results if r.get("safety_blocked", False)
            )
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
            errors = sum(
                1
                for r in protocol_results
                if r.get("exception")
                or not r.get("success", True)
                or r.get("error")
                or r.get("server_error")
            )
            successes = max(total_runs - errors, 0)
            success_rate = (successes / total_runs * 100) if total_runs > 0 else 0

            summary[protocol_type] = {
                "total_runs": total_runs,
                "errors": errors,
                "success_rate": round(success_rate, 2),
            }

        return summary
