"""Plain-text stdout summaries for non-TTY and CI environments."""

from __future__ import annotations

import sys
from typing import Any

from .common import extract_tool_runs, summarize_tool_runs


def _tool_outcome_buckets(runs: list[dict[str, Any]]) -> dict[str, int]:
    """Group tool runs by outcome so a server *rejecting* malformed input is not
    conflated with a transport/protocol anomaly or a real crash."""
    buckets = {
        "server_rejected": 0,
        "accepted_malformed": 0,
        "anomaly": 0,
        "crashed": 0,
    }
    for run in runs:
        if not isinstance(run, dict):
            continue
        outcome = run.get("outcome")
        if outcome == "crashed" or run.get("error") == "server_crashed":
            buckets["crashed"] += 1
        elif outcome == "server_rejected":
            buckets["server_rejected"] += 1
        elif outcome == "accepted_malformed" or run.get("accepted_malformed"):
            buckets["accepted_malformed"] += 1
        elif outcome in {"transport_error", "timeout", "phase_failed"}:
            buckets["anomaly"] += 1
    return buckets


def _count_crashes(
    tool_results: dict[str, Any] | None, protocol_results: dict[str, Any] | None
) -> int:
    total = 0
    for entry in (tool_results or {}).values():
        runs, _ = extract_tool_runs(entry)
        total += sum(
            1
            for r in runs
            if isinstance(r, dict)
            and (r.get("outcome") == "crashed" or r.get("error") == "server_crashed")
        )
    for runs in (protocol_results or {}).values():
        if isinstance(runs, list):
            total += sum(
                1
                for r in runs
                if isinstance(r, dict) and r.get("outcome") == "crashed"
            )
    return total


def write_stdout_summary(
    *,
    mode: str,
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
    blocked: bool = False,
) -> None:
    """Write a plain-text fuzzing summary to stdout (always, not only on TTY).

    ``blocked`` marks a run that could not start (no tools available, e.g. auth
    required or unreachable endpoint), so callers/CI can tell it apart from a
    genuinely completed run.
    """
    lines: list[str] = ["", "=== MCP Fuzzer Summary ===", f"Mode: {mode}"]

    tools_mode = mode in {"tools", "all"}
    if blocked:
        lines.append(
            "Status: BLOCKED — no tools available "
            "(auth required, endpoint unreachable, or no tools exposed)"
        )
    elif tools_mode:
        tool_count = len(tool_results) if isinstance(tool_results, dict) else 0
        lines.append(f"Status: completed — {tool_count} tool(s) fuzzed")

    crashes = _count_crashes(tool_results, protocol_results)
    if crashes:
        lines.append(
            f"⚠️  CRASHES: {crashes} run(s) terminated the server process "
            "(see the 'crashes/' directory for reproductions)"
        )

    if tools_mode and tool_results:
        lines.append("")
        lines.append("Tool Results:")
        for tool_name, entry in tool_results.items():
            runs, _ = extract_tool_runs(entry)
            stats = summarize_tool_runs(runs)
            buckets = _tool_outcome_buckets(runs)
            lines.append(
                f"  {tool_name}: {stats['total_runs']} runs, "
                f"{stats['successful']} handled correctly, "
                f"{stats['failures']} findings/failures, "
                f"{stats['safety_blocked']} safety-blocked"
            )
            lines.append(
                f"      ({buckets['server_rejected']} server-rejected input, "
                f"{buckets['accepted_malformed']} accepted-malformed findings, "
                f"{buckets['anomaly']} transport/protocol anomalies, "
                f"{buckets['crashed']} crashes)"
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
