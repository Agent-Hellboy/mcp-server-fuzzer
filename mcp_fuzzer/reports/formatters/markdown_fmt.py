"""Markdown formatter implementation."""

from __future__ import annotations

import emoji
from typing import Any

from .common import normalize_report_data


class MarkdownFormatter:
    """Handles Markdown formatting for reports."""

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
                    md_content += (
                        f"| {spec_id} | {details.get('failed', 0)} | "
                        f"{details.get('warned', 0)} | {details.get('passed', 0)} | "
                        f"{details.get('total', 0)} |\n"
                    )
                md_content += "\n"

        if "tool_results" in data:
            md_content += "## Tool Results\n\n"

            for tool_name, results in data["tool_results"].items():
                md_content += f"### {tool_name}\n\n"
                md_content += "| Run | Success | Exception |\n"
                md_content += "|-----|---------|-----------|\n"

                for i, result in enumerate(results):
                    success = (
                        emoji.emojize(":heavy_check_mark:", language="alias")
                        if result.get("success")
                        else emoji.emojize(":x:", language="alias")
                    )
                    exception = result.get("exception", "")
                    md_content += f"| {i + 1} | {success} | {exception} |\n"

                md_content += "\n"

        with open(filename, "w") as f:
            f.write(md_content)
