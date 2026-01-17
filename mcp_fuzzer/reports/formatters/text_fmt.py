"""Text formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import (
    calculate_protocol_success_rate,
    calculate_tool_success_rate,
    extract_tool_runs,
    normalize_report_data,
)


def _result_has_failure(result: dict[str, Any]) -> bool:
    """Return True when a result represents an error condition."""
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )


class TextFormatter:
    """Handles text formatting for reports."""

    def save_text_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        data = normalize_report_data(report_data)
        with open(filename, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("MCP FUZZER REPORT\n")
            f.write("=" * 80 + "\n\n")

            if "metadata" in data:
                f.write("FUZZING SESSION METADATA\n")
                f.write("-" * 40 + "\n")
                for key, value in data["metadata"].items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")

            if "summary" in data:
                f.write("SUMMARY STATISTICS\n")
                f.write("-" * 40 + "\n")
                summary = data["summary"]

                if "tools" in summary:
                    tools = summary["tools"]
                    f.write(f"Tools Tested: {tools['total_tools']}\n")
                    f.write(f"Total Tool Runs: {tools['total_runs']}\n")
                    f.write(f"Tools with Errors: {tools['tools_with_errors']}\n")
                    f.write(
                        f"Tools with Exceptions: {tools['tools_with_exceptions']}\n"
                    )
                    f.write(f"Tool Success Rate: {tools['success_rate']:.1f}%\n\n")

                if "protocols" in summary:
                    protocols = summary["protocols"]
                    f.write(
                        f"Protocol Types Tested: {protocols['total_protocol_types']}\n"
                    )
                    f.write(f"Total Protocol Runs: {protocols['total_runs']}\n")
                    f.write(
                        (
                            "Protocol Types with Errors: "
                            f"{protocols['protocol_types_with_errors']}\n"
                        )
                    )
                    f.write(
                        (
                            "Protocol Types with Exceptions: "
                            f"{protocols['protocol_types_with_exceptions']}\n"
                        )
                    )
                    f.write(
                        f"Protocol Success Rate: {protocols['success_rate']:.1f}%\n\n"
                    )

            if "spec_summary" in data:
                spec_summary = data.get("spec_summary") or {}
                totals = spec_summary.get("totals", {})
                if totals:
                    f.write("SPEC GUARD SUMMARY\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Total Checks: {totals.get('total', 0)}\n")
                    f.write(f"Failed: {totals.get('failed', 0)}\n")
                    f.write(f"Warned: {totals.get('warned', 0)}\n")
                    f.write(f"Passed: {totals.get('passed', 0)}\n\n")
                    by_spec = spec_summary.get("by_spec_id") or {}
                    for spec_id, details in by_spec.items():
                        f.write(f"{spec_id}: ")
                        f.write(
                            f"{details.get('failed', 0)} failed, "
                            f"{details.get('warned', 0)} warned, "
                            f"{details.get('passed', 0)} passed "
                            f"({details.get('total', 0)} total)\n"
                        )
                    f.write("\n")

            if "tool_results" in data:
                f.write("TOOL FUZZING RESULTS\n")
                f.write("-" * 40 + "\n")
                for tool_name, results in data["tool_results"].items():
                    runs, _ = extract_tool_runs(results)
                    f.write(f"\nTool: {tool_name}\n")
                    f.write(f"  Total Runs: {len(runs)}\n")

                    exceptions = sum(1 for r in runs if "exception" in r)
                    safety_blocked = sum(
                        1 for r in runs if r.get("safety_blocked", False)
                    )
                    f.write(f"  Exceptions: {exceptions}\n")
                    f.write(f"  Safety Blocked: {safety_blocked}\n")

                    if runs:
                        success_rate = calculate_tool_success_rate(
                            len(runs), exceptions, safety_blocked
                        )
                        f.write(f"  Success Rate: {success_rate:.1f}%\n")

            if "protocol_results" in data:
                f.write("\n\nPROTOCOL FUZZING RESULTS\n")
                f.write("-" * 40 + "\n")
                for protocol_type, results in data["protocol_results"].items():
                    f.write(f"\nProtocol Type: {protocol_type}\n")
                    f.write(f"  Total Runs: {len(results)}\n")

                    errors = sum(1 for r in results if _result_has_failure(r))
                    f.write(f"  Errors: {errors}\n")

                    if results:
                        success_rate = calculate_protocol_success_rate(
                            len(results), errors
                        )
                        f.write(f"  Success Rate: {success_rate:.1f}%\n")

            if "safety" in data:
                f.write("\n\nSAFETY SYSTEM DATA\n")
                f.write("-" * 40 + "\n")
                safety = data["safety"]
                if "summary" in safety:
                    summary = safety["summary"]
                    f.write(
                        f"Total Operations Blocked: {summary.get('total_blocked', 0)}\n"
                    )
                    f.write(
                        (
                            "Unique Tools Blocked: "
                            f"{summary.get('unique_tools_blocked', 0)}\n"
                        )
                    )
                    f.write(
                        (
                            "Risk Assessment: "
                            f"{summary.get('risk_assessment', 'unknown').upper()}\n"
                        )
                    )

            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by MCP Fuzzer\n")
            f.write("=" * 80 + "\n")
