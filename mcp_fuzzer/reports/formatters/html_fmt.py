"""HTML formatter implementation."""

from __future__ import annotations

from html import escape
from typing import Any

from ...types import extract_tool_runs
from .common import (
    iter_protocol_type_stats,
    protocol_item_summaries,
    redact_report_data,
)


class HTMLFormatter:
    """Handles HTML formatting for reports."""

    def save_html_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
        title: str = "Fuzzing Results Report",
    ):
        data = redact_report_data(report_data)
        mode = str((data.get("metadata") or {}).get("mode", "all"))
        escaped_title = escape(title)
        parts: list[str] = [
            f"""
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
        ]

        if "metadata" in data:
            parts.append("<h2>Metadata</h2><ul>")
            for key, value in data["metadata"].items():
                parts.append(
                    f"<li><strong>{escape(str(key))}:</strong> "
                    f"{escape(str(value))}</li>"
                )
            parts.append("</ul>")

        if "spec_summary" in data and mode not in {"tools"}:
            spec_summary = data.get("spec_summary") or {}
            totals = spec_summary.get("totals", {})
            if totals.get("total", 0) > 0:
                parts.append("<h2>Spec Guard Summary</h2>")
                parts.append("<ul>")
                total_checks = escape(str(totals.get("total", 0)))
                failed = escape(str(totals.get("failed", 0)))
                warned = escape(str(totals.get("warned", 0)))
                passed = escape(str(totals.get("passed", 0)))
                parts.append(
                    f"<li><strong>Total Checks:</strong> {total_checks}</li>"
                    f"<li><strong>Failed:</strong> {failed}</li>"
                    f"<li><strong>Warned:</strong> {warned}</li>"
                    f"<li><strong>Passed:</strong> {passed}</li>"
                )
                parts.append("</ul>")
                parts.append("<table>")
                parts.append(
                    "<tr><th>Spec ID</th><th>Failed</th><th>Warned</th>"
                    "<th>Passed</th><th>Total</th></tr>"
                )
                for spec_id, details in (spec_summary.get("by_spec_id") or {}).items():
                    parts.append(
                        "<tr>"
                        f"<td>{escape(str(spec_id))}</td>"
                        f"<td>{escape(str(details.get('failed', 0)))}</td>"
                        f"<td>{escape(str(details.get('warned', 0)))}</td>"
                        f"<td>{escape(str(details.get('passed', 0)))}</td>"
                        f"<td>{escape(str(details.get('total', 0)))}</td>"
                        "</tr>"
                    )
                parts.append("</table>")

        if "tool_results" in data:
            parts.append("<h2>Tool Results</h2><table>")
            parts.append(
                "<tr><th>Tool Name</th><th>Run</th><th>Success</th>"
                "<th>Exception</th></tr>"
            )

            for tool_name, results in data["tool_results"].items():
                runs, _ = extract_tool_runs(results)
                for i, result in enumerate(runs):
                    success = result.get("success", False)
                    success_class = "success" if success else "error"
                    parts.append(
                        f"""
<tr>
    <td>{escape(str(tool_name))}</td>
    <td>{i + 1}</td>
    <td class="{success_class}">{escape(str(success))}</td>
    <td>{escape(str(result.get("exception", "")))}</td>
</tr>"""
                    )

            parts.append("</table>")

        if "protocol_results" in data and mode not in {"tools"}:
            protocol_results = data["protocol_results"]
            parts.append("<h2>Protocol Results</h2><table>")
            parts.append(
                "<tr><th>Protocol Type</th><th>Total Runs</th>"
                "<th>Errors</th><th>Success Rate</th></tr>"
            )
            for protocol_type, total_runs, errors, success_rate in (
                iter_protocol_type_stats(protocol_results)
            ):
                parts.append(
                    "<tr>"
                    f"<td>{escape(str(protocol_type))}</td>"
                    f"<td>{escape(str(total_runs))}</td>"
                    f"<td>{escape(str(errors))}</td>"
                    f"<td>{escape(f'{success_rate:.1f}%')}</td>"
                    "</tr>"
                )
            parts.append("</table>")

            for prefix, _raw, items in protocol_item_summaries(protocol_results):
                if not items:
                    continue
                label = prefix.capitalize()
                parts.append(f"<h2>{label} Item Summary</h2><table>")
                parts.append(
                    f"<tr><th>{label}</th><th>Total Runs</th>"
                    "<th>Errors</th><th>Success Rate</th></tr>"
                )
                for name, stats in items.items():
                    success_rate = f"{stats['success_rate']:.1f}%"
                    parts.append(
                        "<tr>"
                        f"<td>{escape(str(name))}</td>"
                        f"<td>{escape(str(stats['total_runs']))}</td>"
                        f"<td>{escape(str(stats['errors']))}</td>"
                        f"<td>{escape(success_rate)}</td>"
                        "</tr>"
                    )
                parts.append("</table>")

        parts.append("</body></html>")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("".join(parts))
