"""HTML formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import normalize_report_data


class HTMLFormatter:
    """Handles HTML formatting for reports."""

    def save_html_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
        title: str = "Fuzzing Results Report",
    ):
        data = normalize_report_data(report_data)
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
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
    <h1>{title}</h1>
"""

        if "metadata" in data:
            html_content += "<h2>Metadata</h2><ul>"
            for key, value in data["metadata"].items():
                html_content += f"<li><strong>{key}:</strong> {value}</li>"
            html_content += "</ul>"

        if "tool_results" in data:
            html_content += "<h2>Tool Results</h2><table>"
            html_content += (
                "<tr><th>Tool Name</th><th>Run</th><th>Success</th>"
                "<th>Exception</th></tr>"
            )

            for tool_name, results in data["tool_results"].items():
                for i, result in enumerate(results):
                    success_class = "success" if result.get("success") else "error"
                    html_content += f"""
<tr>
    <td>{tool_name}</td>
    <td>{i + 1}</td>
    <td class="{success_class}">{result.get("success", False)}</td>
    <td>{result.get("exception", "")}</td>
</tr>"""

            html_content += "</table>"

        html_content += "</body></html>"

        with open(filename, "w") as f:
            f.write(html_content)
