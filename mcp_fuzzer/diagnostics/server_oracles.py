"""Fuzz-run output oracles for MCP server audit."""

from __future__ import annotations

import json
import re
from typing import Any

from ..types import extract_tool_runs
from .model import Finding
from .server import server_finding

_COMMAND_INPUT_MARKERS = ("$(id)", "`id`", "; id", "| id")
_COMMAND_OUTPUT = re.compile(r"uid=\d+.*gid=\d+", re.IGNORECASE)

_PATH_INPUT_MARKERS = ("../../../etc/passwd", "..\\..\\..\\etc\\passwd")
_PATH_OUTPUT = re.compile(r"root:x:0:0:", re.IGNORECASE)

_SQL_INPUT_MARKERS = ("' or 1=1", "union select", "'; drop table", "1=1--")
_SQL_OUTPUT = re.compile(
    r"sql syntax|sqlite|pg_query|mysql|ora-\d+|syntax error.*sql|"
    r"unrecognized token",
    re.IGNORECASE,
)

_OUTPUT_INJECTION_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"<\s*IMPORTANT\s*>",
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"do\s+not\s+tell\s+the\s+user",
        r"you\s+must\s+(now|always)\s+(call|use|invoke)",
    )
]


def _serialize_input(run: dict[str, Any]) -> str:
    args = run.get("args")
    if args is None:
        return ""
    try:
        return json.dumps(args, default=str)
    except (TypeError, ValueError):
        return str(args)


def _response_text(run: dict[str, Any]) -> str:
    parts: list[str] = []
    result = run.get("result")
    if result is not None:
        try:
            parts.append(json.dumps(result, default=str))
        except (TypeError, ValueError):
            parts.append(str(result))
    if run.get("exception"):
        parts.append(str(run.get("exception")))
    crash = run.get("crash")
    if isinstance(crash, dict) and crash.get("stderr_tail"):
        parts.append("\n".join(str(line) for line in crash["stderr_tail"]))
    return "\n".join(parts)


def audit_tool_run_oracles(
    tool_results: dict[str, Any] | None,
) -> list[Finding]:
    """Scan fuzz-run outputs for exploitation signatures (command/path/SQL/output)."""
    findings: list[Finding] = []
    if not tool_results:
        return findings

    for tool_name, entry in tool_results.items():
        runs, _ = extract_tool_runs(entry)
        for index, run in enumerate(runs):
            if not isinstance(run, dict):
                continue
            run_no = index + 1
            input_text = _serialize_input(run).lower()
            output_text = _response_text(run)

            if any(m in input_text for m in _COMMAND_INPUT_MARKERS):
                if _COMMAND_OUTPUT.search(output_text):
                    findings.append(
                        server_finding(
                            "CI1",
                            "command_injection",
                            "critical",
                            tool_name,
                            "Command-injection probe produced shell identity output "
                            "(uid=/gid= signature in tool response).",
                            run=run_no,
                            evidence={"signature": "uid_gid"},
                        )
                    )

            if any(m in input_text for m in _PATH_INPUT_MARKERS):
                if _PATH_OUTPUT.search(output_text):
                    findings.append(
                        server_finding(
                            "PT1",
                            "path_traversal",
                            "high",
                            tool_name,
                            "Path-traversal probe returned /etc/passwd-like content "
                            "in the tool response.",
                            run=run_no,
                            evidence={"signature": "passwd_entry"},
                        )
                    )

            if any(m in input_text for m in _SQL_INPUT_MARKERS):
                if _SQL_OUTPUT.search(output_text):
                    findings.append(
                        server_finding(
                            "SQ1",
                            "sql_injection",
                            "high",
                            tool_name,
                            "SQL-injection probe produced a database error signature "
                            "in the tool response.",
                            run=run_no,
                            evidence={"signature": "sql_error"},
                        )
                    )

            for pattern in _OUTPUT_INJECTION_PATTERNS:
                if pattern.search(output_text) and not pattern.search(input_text):
                    findings.append(
                        server_finding(
                            "OP1",
                            "output_prompt_injection",
                            "medium",
                            tool_name,
                            "Tool output contains injected instruction markers not "
                            "present in the request input (indirect prompt injection).",
                            run=run_no,
                            evidence={"pattern": pattern.pattern},
                        )
                    )
                    break

    return findings
