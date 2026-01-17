"""Markdown formatter implementation."""

from __future__ import annotations

import emoji
from typing import Any

from .common import (
    calculate_protocol_success_rate,
    collect_and_summarize_protocol_items,
    extract_tool_runs,
    normalize_report_data,
    result_has_failure,
)
from ...protocol_types import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST


class MarkdownFormatter:
    """Handles Markdown formatting for reports."""

    @staticmethod
    def _escape_cell(value: str) -> str:
        return value.replace("|", "\\|")

    def save_markdown_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        data = normalize_report_data(report_data)
        md_content = "# MCP Fuzzer Report\n\n"

        if "metadata" in data:
            md_content += "## Metadata\n\n"
            for key, value in data["metadata"].items():
                md_content += f"- **{key}**: {value}\n"
            md_content += "\n"

        if "spec_summary" in data:
            spec_summary = data.get("spec_summary") or {}
            totals = spec_summary.get("totals", {})
            if totals:
                md_content += "## Spec Guard Summary\n\n"
                md_content += (
                    f"- **Total Checks**: {totals.get('total', 0)}\n"
                    f"- **Failed**: {totals.get('failed', 0)}\n"
                    f"- **Warned**: {totals.get('warned', 0)}\n"
                    f"- **Passed**: {totals.get('passed', 0)}\n\n"
                )
                md_content += "| Spec ID | Failed | Warned | Passed | Total |\n"
                md_content += "|--------|--------|--------|--------|-------|\n"
                for spec_id, details in (spec_summary.get("by_spec_id") or {}).items():
                    spec_id_escaped = spec_id.replace("|", "\\|")
                    md_content += (
                        f"| {spec_id_escaped} | {details.get('failed', 0)} | "
                        f"{details.get('warned', 0)} | {details.get('passed', 0)} | "
                        f"{details.get('total', 0)} |\n"
                    )
                md_content += "\n"

        if "tool_results" in data:
            md_content += "## Tool Results\n\n"

            for tool_name, results in data["tool_results"].items():
                runs, _ = extract_tool_runs(results)
                md_content += f"### {tool_name}\n\n"
                md_content += "| Run | Success | Exception |\n"
                md_content += "|-----|---------|-----------|\n"

                for i, result in enumerate(runs):
                    success = (
                        emoji.emojize(":heavy_check_mark:", language="alias")
                        if result.get("success")
                        else emoji.emojize(":x:", language="alias")
                    )
                    exception = result.get("exception", "")
                    md_content += f"| {i + 1} | {success} | {exception} |\n"

                md_content += "\n"

        if "protocol_results" in data:
            protocol_results = data["protocol_results"]
            md_content += "## Protocol Results\n\n"
            md_content += (
                "| Protocol Type | Total Runs | Errors | Success Rate |\n"
                "|---------------|------------|--------|--------------|\n"
            )
            for protocol_type, results in protocol_results.items():
                protocol_label = self._escape_cell(str(protocol_type))
                total_runs = len(results)
                errors = sum(1 for r in results if result_has_failure(r))
                success_rate = calculate_protocol_success_rate(total_runs, errors)
                md_content += (
                    f"| {protocol_label} | {total_runs} | {errors} | "
                    f"{success_rate:.1f}% |\n"
                )
            md_content += "\n"

            _, resource_items = collect_and_summarize_protocol_items(
                protocol_results.get(READ_RESOURCE_REQUEST, []), "resource"
            )
            if resource_items:
                md_content += "## Resource Item Summary\n\n"
                md_content += (
                    "| Resource | Total Runs | Errors | Success Rate |\n"
                    "|----------|------------|--------|--------------|\n"
                )
                for name, stats in resource_items.items():
                    escaped_name = self._escape_cell(str(name))
                    resource_runs = stats["total_runs"]
                    resource_errors = stats["errors"]
                    md_content += (
                        f"| {escaped_name} | {resource_runs} | {resource_errors} | "
                        f"{stats['success_rate']:.1f}% |\n"
                    )
                md_content += "\n"

            _, prompt_items = collect_and_summarize_protocol_items(
                protocol_results.get(GET_PROMPT_REQUEST, []), "prompt"
            )
            if prompt_items:
                md_content += "## Prompt Item Summary\n\n"
                md_content += (
                    "| Prompt | Total Runs | Errors | Success Rate |\n"
                    "|--------|------------|--------|--------------|\n"
                )
                for name, stats in prompt_items.items():
                    escaped_name = self._escape_cell(str(name))
                    prompt_runs = stats["total_runs"]
                    prompt_errors = stats["errors"]
                    md_content += (
                        f"| {escaped_name} | {prompt_runs} | {prompt_errors} | "
                        f"{stats['success_rate']:.1f}% |\n"
                    )
                md_content += "\n"

        with open(filename, "w") as f:
            f.write(md_content)
