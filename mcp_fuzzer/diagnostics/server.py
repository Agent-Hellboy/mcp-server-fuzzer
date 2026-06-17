"""Paper-backed MCP server audit checks (non-OAuth).

Black-box checks derived from MCP-security research, grouped here as one
cohesive module:

- ``tools/list`` metadata scan -- tool poisoning, schema poisoning, tool
  shadowing, dangerous capability combinations (arXiv 2503.23278, 2509.06572).
- Fuzz-run output oracles -- command / path / SQL injection and indirect
  prompt injection signatures in tool responses.
- Transport surface -- cleartext HTTP endpoints (MCPSecBench, arXiv 2508.13220).

Each finding carries its ``check_id`` and a paper citation in ``evidence``.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from ..reports.formatters.common import extract_tool_runs
from .model import Finding

# --- paper citations --------------------------------------------------------

TOOL_POISONING_PAPER_ARXIV_ID = "2503.23278"
TOOL_POISONING_PAPER_TITLE = (
    "MCP Safety Audit: LLMs with the Model Context Protocol"
)
CAPABILITY_COMBO_PAPER_ARXIV_ID = "2509.06572"
CAPABILITY_COMBO_PAPER_TITLE = (
    "Uncovering MCP Security Vulnerabilities in AI Agent Ecosystems"
)
TRANSPORT_PAPER_ARXIV_ID = "2508.13220"
TRANSPORT_PAPER_TITLE = "MCPSecBench: A Benchmark for MCP Server Security"

SERVER_AUDIT_FLAW_CATEGORIES = frozenset(
    {
        "tool_poisoning",
        "schema_poisoning",
        "tool_shadowing",
        "dangerous_capability_combo",
        "insecure_transport",
        "command_injection",
        "path_traversal",
        "sql_injection",
        "output_prompt_injection",
    }
)

_PAPER_TITLES = {
    TOOL_POISONING_PAPER_ARXIV_ID: TOOL_POISONING_PAPER_TITLE,
    CAPABILITY_COMBO_PAPER_ARXIV_ID: CAPABILITY_COMBO_PAPER_TITLE,
    TRANSPORT_PAPER_ARXIV_ID: TRANSPORT_PAPER_TITLE,
}


def server_audit_paper_evidence(arxiv_id: str) -> dict[str, str]:
    """Return paper citation fields for a server-audit finding."""
    return {
        "paper_arxiv_id": arxiv_id,
        "paper_url": f"https://arxiv.org/abs/{arxiv_id}",
        "paper_title": _PAPER_TITLES.get(arxiv_id, arxiv_id),
    }


def server_audit_report_metadata() -> dict[str, str]:
    """Top-level metadata for findings reports (primary poisoning source)."""
    return server_audit_paper_evidence(TOOL_POISONING_PAPER_ARXIV_ID)


def is_server_audit_finding(finding: Finding) -> bool:
    """Return True when a finding comes from the server audit checks."""
    if finding.category in SERVER_AUDIT_FLAW_CATEGORIES:
        return True
    evidence = finding.evidence or {}
    return bool(evidence.get("check_id"))


def server_finding(
    check_id: str,
    category: str,
    severity: str,
    target: str,
    detail: str,
    *,
    arxiv_id: str = TOOL_POISONING_PAPER_ARXIV_ID,
    run: int | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    ev = {"check_id": check_id, **server_audit_paper_evidence(arxiv_id)}
    if evidence:
        ev.update(evidence)
    return Finding(category, severity, "tool", target, run, detail, ev)


# --- tools/list metadata checks ---------------------------------------------

_POISONING_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"<\s*IMPORTANT\s*>",
        r"<\s*CRITICAL\s*>",
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"do\s+not\s+tell\s+the\s+user",
        r"disregard\s+(prior|previous)",
        r"hidden\s+parameter",
        r"secretly\s+(call|use|invoke|run)",
    )
]

_SECRET_PATH_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"\.aws/credentials",
        r"\.env\b",
        r"\.ssh/",
        r"id_rsa",
        r"/etc/passwd",
    )
]

_LOCAL_READ_PATTERN = re.compile(
    r"\b(read|file|fs|cat|open|load|path|directory|glob|scan|filesystem)\b",
    re.IGNORECASE,
)
_NETWORK_EGRESS_PATTERN = re.compile(
    r"\b(http|fetch|request|curl|wget|post|url|webhook|upload|send|"
    r"egress|socket|download|api_call)\b",
    re.IGNORECASE,
)


def _tool_text(tool: dict[str, Any]) -> str:
    parts = [str(tool.get("name") or "")]
    if tool.get("description"):
        parts.append(str(tool["description"]))
    return "\n".join(parts)


def _collect_schema_text(value: Any) -> str:
    parts: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(key, str):
                    parts.append(key)
                walk(val)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str):
            parts.append(obj)

    walk(value)
    return "\n".join(parts)


def _matched_markers(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    return [p.pattern for p in patterns if p.search(text)]


def _scan_poisoning(text: str) -> list[str]:
    hits = _matched_markers(text, _POISONING_PATTERNS)
    hits.extend(_matched_markers(text, _SECRET_PATH_PATTERNS))
    return hits


def audit_tool_metadata(tools: list[dict[str, Any]]) -> list[Finding]:
    """Scan ``tools/list`` definitions for poisoning, shadowing, and exfil chains."""
    findings: list[Finding] = []
    if not tools:
        return findings

    names: list[str] = []
    has_local_read = False
    has_network_egress = False

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)

        visible = _tool_text(tool)
        if _LOCAL_READ_PATTERN.search(visible):
            has_local_read = True
        if _NETWORK_EGRESS_PATTERN.search(visible):
            has_network_egress = True

        poison_hits = _scan_poisoning(visible)
        if poison_hits and name:
            findings.append(
                server_finding(
                    "TP1",
                    "tool_poisoning",
                    "high",
                    str(name),
                    "Tool name or description contains injection/poisoning "
                    "markers (hidden instructions or secret-path references).",
                    evidence={"markers": poison_hits[:10]},
                )
            )

        schema = tool.get("inputSchema")
        if isinstance(schema, dict):
            schema_text = _collect_schema_text(schema)
            schema_hits = _scan_poisoning(schema_text)
            if schema_hits and name:
                findings.append(
                    server_finding(
                        "SP1",
                        "schema_poisoning",
                        "high",
                        str(name),
                        "Tool inputSchema text contains injection/poisoning "
                        "markers beyond the visible tool signature.",
                        evidence={"markers": schema_hits[:10]},
                    )
                )

    dupes = [n for n, count in Counter(names).items() if count > 1]
    for dupe in dupes:
        findings.append(
            server_finding(
                "TS1",
                "tool_shadowing",
                "medium",
                dupe,
                f"Duplicate tool name '{dupe}' appears {Counter(names)[dupe]} times "
                "(tool shadowing / name collision within this server).",
                evidence={"occurrences": Counter(names)[dupe]},
            )
        )

    if has_local_read and has_network_egress:
        findings.append(
            server_finding(
                "CC1",
                "dangerous_capability_combo",
                "medium",
                "mcp_endpoint",
                "Server exposes both local-read and network-egress style tools "
                "(parasitic toolchain / data-exfiltration chain risk).",
                arxiv_id=CAPABILITY_COMBO_PAPER_ARXIV_ID,
                evidence={"local_read": True, "network_egress": True},
            )
        )

    return findings


# --- fuzz-run output oracles ------------------------------------------------

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


# --- transport surface ------------------------------------------------------


def audit_insecure_transport(endpoint: str) -> list[Finding]:
    """Flag cleartext HTTP endpoints (MCPSecBench transport surface)."""
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme.lower() != "http":
        return []
    return [
        server_finding(
            "TR1",
            "insecure_transport",
            "medium",
            "mcp_endpoint",
            f"MCP endpoint uses cleartext HTTP ({endpoint!r}); credentials and "
            "tool traffic are not protected in transit.",
            arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
            evidence={"endpoint": endpoint, "scheme": parsed.scheme},
        )
    ]


# --- orchestration ----------------------------------------------------------


def run_server_audit(
    tools: list[dict[str, Any]] | None,
    *,
    endpoint: str,
    tool_results: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run all read-only MCP server audit checks."""
    findings: list[Finding] = []
    findings.extend(audit_insecure_transport(endpoint))
    if tools:
        findings.extend(audit_tool_metadata(tools))
    findings.extend(audit_tool_run_oracles(tool_results))
    return findings
