"""CSV formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import normalize_report_data


class CSVFormatter:
    """Handles CSV formatting for reports."""

    def save_csv_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        import csv

        data = normalize_report_data(report_data)
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Tool Name",
                    "Run Number",
                    "Success",
                    "Response Time",
                    "Exception Message",
                    "Arguments",
                    "Timestamp",
                ]
            )

            if "tool_results" in data:
                for tool_name, results in data["tool_results"].items():
                    for i, result in enumerate(results):
                        writer.writerow(
                            [
                                tool_name,
                                i + 1,
                                result.get("success", False),
                                result.get("response_time", ""),
                                result.get("exception", ""),
                                str(result.get("args", "")),
                                result.get("timestamp", ""),
                            ]
                        )
