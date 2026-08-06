"""Markdown formatter implementation."""

from __future__ import annotations

from typing import Any

from ...types import extract_tool_runs
from .common import (
    iter_protocol_type_stats,
    normalize_report_data,
    protocol_item_summaries,
)
from ...icons import CHECK, CROSS


class MarkdownFormatter:
    """Handles Markdown formatting for reports."""

    @staticmethod
    def _escape_cell(value: str) -> str:
        escaped = value.replace("|", "\\|")
        return escaped.replace("\n", " ").replace("\r", " ")

    def save_markdown_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        data = normalize_report_data(report_data)
        mode = str((data.get("metadata") or {}).get("mode", "all"))
        parts: list[str] = ["# MCP Fuzzer Report\n\n"]

        if "metadata" in data:
            parts.append("## Metadata\n\n")
            for key, value in data["metadata"].items():
                parts.append(f"- **{key}**: {value}\n")
            parts.append("\n")

        if "spec_summary" in data and mode not in {"tools"}:
            spec_summary = data.get("spec_summary") or {}
            totals = spec_summary.get("totals", {})
            if totals.get("total", 0) > 0:
                parts.append("## Spec Guard Summary\n\n")
                parts.append(
                    f"- **Total Checks**: {totals.get('total', 0)}\n"
                    f"- **Failed**: {totals.get('failed', 0)}\n"
                    f"- **Warned**: {totals.get('warned', 0)}\n"
                    f"- **Passed**: {totals.get('passed', 0)}\n\n"
                )
                parts.append("| Spec ID | Failed | Warned | Passed | Total |\n")
                parts.append("|--------|--------|--------|--------|-------|\n")
                for spec_id, details in (spec_summary.get("by_spec_id") or {}).items():
                    spec_id_escaped = spec_id.replace("|", "\\|")
                    parts.append(
                        f"| {spec_id_escaped} | {details.get('failed', 0)} | "
                        f"{details.get('warned', 0)} | {details.get('passed', 0)} | "
                        f"{details.get('total', 0)} |\n"
                    )
                parts.append("\n")

        if "tool_results" in data:
            parts.append("## Tool Results\n\n")

            for tool_name, results in data["tool_results"].items():
                runs, _ = extract_tool_runs(results)
                parts.append(f"### {tool_name}\n\n")
                parts.append("| Run | Success | Exception |\n")
                parts.append("|-----|---------|-----------|\n")

                for i, result in enumerate(runs):
                    success = CHECK if result.get("success") else CROSS
                    exception = self._escape_cell(str(result.get("exception", "")))
                    parts.append(f"| {i + 1} | {success} | {exception} |\n")

                parts.append("\n")

        if "protocol_results" in data and mode not in {"tools"}:
            protocol_results = data["protocol_results"]
            parts.append("## Protocol Results\n\n")
            parts.append(
                "| Protocol Type | Total Runs | Errors | Success Rate |\n"
                "|---------------|------------|--------|--------------|\n"
            )
            for protocol_type, total_runs, errors, success_rate in (
                iter_protocol_type_stats(protocol_results)
            ):
                protocol_label = self._escape_cell(str(protocol_type))
                parts.append(
                    f"| {protocol_label} | {total_runs} | {errors} | "
                    f"{success_rate:.1f}% |\n"
                )
            parts.append("\n")

            for prefix, _raw, items in protocol_item_summaries(protocol_results):
                if not items:
                    continue
                label = prefix.capitalize()
                parts.append(f"## {label} Item Summary\n\n")
                parts.append(
                    f"| {label} | Total Runs | Errors | Success Rate |\n"
                    f"|{'-' * (len(label) + 2)}|------------|--------|"
                    "--------------|\n"
                )
                for name, stats in items.items():
                    escaped_name = self._escape_cell(str(name))
                    parts.append(
                        f"| {escaped_name} | {stats['total_runs']} | "
                        f"{stats['errors']} | {stats['success_rate']:.1f}% |\n"
                    )
                parts.append("\n")

        with open(filename, "w") as f:
            f.write("".join(parts))
