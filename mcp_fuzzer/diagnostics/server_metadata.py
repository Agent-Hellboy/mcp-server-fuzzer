"""Tool metadata and poisoning checks for MCP server audit."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .model import Finding
from .server import (
    CAPABILITY_COMBO_PAPER_ARXIV_ID,
    server_finding,
)

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
