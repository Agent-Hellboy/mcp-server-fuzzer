"""Plain-text stdout summaries for non-TTY and CI environments."""

from __future__ import annotations

import sys
from typing import Any

from .common import extract_tool_runs, summarize_tool_runs


def write_stdout_summary(
    *,
    mode: str,
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> None:
    """Write a plain-text fuzzing summary to stdout (always, not only on TTY)."""
    lines: list[str] = ["", "=== MCP Fuzzer Summary ===", f"Mode: {mode}"]

    if mode in {"tools", "all"} and tool_results:
        lines.append("")
        lines.append("Tool Results:")
        for tool_name, entry in tool_results.items():
            runs, _ = extract_tool_runs(entry)
            stats = summarize_tool_runs(runs)
            lines.append(
                f"  {tool_name}: {stats['total_runs']} runs, "
                f"{stats['successful']} handled correctly, "
                f"{stats['failures']} findings/failures, "
                f"{stats['safety_blocked']} safety-blocked"
            )

    if mode in {"protocol", "all", "resources", "prompts"} and protocol_results:
        lines.append("")
        lines.append("Protocol Results:")
        for protocol_type, runs in protocol_results.items():
            if not isinstance(runs, list):
                continue
            total = len(runs)
            findings = sum(
                1
                for run in runs
                if isinstance(run, dict)
                and (
                    run.get("outcome") == "accepted_malformed"
                    or run.get("accepted_malformed")
                )
            )
            rejected = sum(
                1
                for run in runs
                if isinstance(run, dict)
                and run.get("outcome") == "server_rejected"
            )
            lines.append(
                f"  {protocol_type}: {total} runs, "
                f"{rejected} server-rejected, {findings} accepted-malformed findings"
            )

    lines.append("")
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
