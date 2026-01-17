"""HTML formatter implementation."""

from __future__ import annotations

from html import escape
from typing import Any

from .common import (
    calculate_protocol_success_rate,
    collect_and_summarize_protocol_items,
    extract_tool_runs,
    normalize_report_data,
    result_has_failure,
)
from ...protocol_types import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST


class HTMLFormatter:
    """Handles HTML formatting for reports."""

    def save_html_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
        title: str = "Fuzzing Results Report",
    ):
        data = normalize_report_data(report_data)
        escaped_title = escape(title)
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{escaped_title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <h1>{escaped_title}</h1>
"""

        if "metadata" in data:
            html_content += "<h2>Metadata</h2><ul>"
            for key, value in data["metadata"].items():
                html_content += (
                    f"<li><strong>{escape(str(key))}:</strong> "
                    f"{escape(str(value))}</li>"
                )
            html_content += "</ul>"

        if "spec_summary" in data:
            spec_summary = data.get("spec_summary") or {}
            totals = spec_summary.get("totals", {})
            if totals:
                html_content += "<h2>Spec Guard Summary</h2>"
                html_content += "<ul>"
                total_checks = escape(str(totals.get("total", 0)))
                failed = escape(str(totals.get("failed", 0)))
                warned = escape(str(totals.get("warned", 0)))
                passed = escape(str(totals.get("passed", 0)))
                html_content += (
                    f"<li><strong>Total Checks:</strong> {total_checks}</li>"
                    f"<li><strong>Failed:</strong> {failed}</li>"
                    f"<li><strong>Warned:</strong> {warned}</li>"
                    f"<li><strong>Passed:</strong> {passed}</li>"
                )
                html_content += "</ul>"
                html_content += "<table>"
                html_content += (
                    "<tr><th>Spec ID</th><th>Failed</th><th>Warned</th>"
                    "<th>Passed</th><th>Total</th></tr>"
                )
                for spec_id, details in (spec_summary.get("by_spec_id") or {}).items():
                    html_content += (
                        "<tr>"
                        f"<td>{escape(str(spec_id))}</td>"
                        f"<td>{escape(str(details.get('failed', 0)))}</td>"
                        f"<td>{escape(str(details.get('warned', 0)))}</td>"
                        f"<td>{escape(str(details.get('passed', 0)))}</td>"
                        f"<td>{escape(str(details.get('total', 0)))}</td>"
                        "</tr>"
                    )
                html_content += "</table>"

        if "tool_results" in data:
            html_content += "<h2>Tool Results</h2><table>"
            html_content += (
                "<tr><th>Tool Name</th><th>Run</th><th>Success</th>"
                "<th>Exception</th></tr>"
            )

            for tool_name, results in data["tool_results"].items():
                runs, _ = extract_tool_runs(results)
                for i, result in enumerate(runs):
                    success = result.get("success", False)
                    success_class = "success" if success else "error"
                    html_content += f"""
<tr>
    <td>{escape(str(tool_name))}</td>
    <td>{i + 1}</td>
    <td class="{success_class}">{escape(str(success))}</td>
    <td>{escape(str(result.get("exception", "")))}</td>
</tr>"""

            html_content += "</table>"

        if "protocol_results" in data:
            protocol_results = data["protocol_results"]
            html_content += "<h2>Protocol Results</h2><table>"
            html_content += (
                "<tr><th>Protocol Type</th><th>Total Runs</th>"
                "<th>Errors</th><th>Success Rate</th></tr>"
            )
            for protocol_type, results in protocol_results.items():
                total_runs = len(results)
                errors = sum(1 for r in results if result_has_failure(r))
                success_rate = calculate_protocol_success_rate(total_runs, errors)
                html_content += (
                    "<tr>"
                    f"<td>{escape(str(protocol_type))}</td>"
                    f"<td>{escape(str(total_runs))}</td>"
                    f"<td>{escape(str(errors))}</td>"
                    f"<td>{escape(f'{success_rate:.1f}%')}</td>"
                    "</tr>"
                )
            html_content += "</table>"

            _, resource_items = collect_and_summarize_protocol_items(
                protocol_results.get(READ_RESOURCE_REQUEST, []), "resource"
            )
            if resource_items:
                html_content += "<h2>Resource Item Summary</h2><table>"
                html_content += (
                    "<tr><th>Resource</th><th>Total Runs</th>"
                    "<th>Errors</th><th>Success Rate</th></tr>"
                )
                for name, stats in resource_items.items():
                    success_rate = f"{stats['success_rate']:.1f}%"
                    html_content += (
                        "<tr>"
                        f"<td>{escape(str(name))}</td>"
                        f"<td>{escape(str(stats['total_runs']))}</td>"
                        f"<td>{escape(str(stats['errors']))}</td>"
                        f"<td>{escape(success_rate)}</td>"
                        "</tr>"
                    )
                html_content += "</table>"

            _, prompt_items = collect_and_summarize_protocol_items(
                protocol_results.get(GET_PROMPT_REQUEST, []), "prompt"
            )
            if prompt_items:
                html_content += "<h2>Prompt Item Summary</h2><table>"
                html_content += (
                    "<tr><th>Prompt</th><th>Total Runs</th>"
                    "<th>Errors</th><th>Success Rate</th></tr>"
                )
                for name, stats in prompt_items.items():
                    success_rate = f"{stats['success_rate']:.1f}%"
                    html_content += (
                        "<tr>"
                        f"<td>{escape(str(name))}</td>"
                        f"<td>{escape(str(stats['total_runs']))}</td>"
                        f"<td>{escape(str(stats['errors']))}</td>"
                        f"<td>{escape(success_rate)}</td>"
                        "</tr>"
                    )
                html_content += "</table>"

        html_content += "</body></html>"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
