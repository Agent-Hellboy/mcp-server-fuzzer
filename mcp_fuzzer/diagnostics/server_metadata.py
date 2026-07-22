"""Tool metadata and poisoning checks for MCP server audit."""

from __future__ import annotations

import re
import base64
import binascii
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
        r"override\s+(the\s+)?(system|developer|user)\s+(prompt|message)",
        r"reveal\s+(the\s+)?(system|developer)\s+(prompt|message)",
        r"hidden\s+parameter",
        r"secretly\s+(call|use|invoke|run)",
        r"\b(exfiltrate|steal|leak)\b",
        r"(send|upload|post)\s+.*\b(secret|credential|token|private\s+key|api\s+key)\b",
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
        r"private\s+key",
        r"bearer\s+token",
    )
]

_INVISIBLE_TEXT_PATTERNS = [
    re.compile(r, re.IGNORECASE | re.DOTALL)
    for r in (
        r"<!--.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?-->",
        r"/\*.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?\*/",
        r"```.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?```",
    )
]

_UNICODE_CONTROL_PATTERN = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)
_BASE64_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])"
)

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
    if tool.get("title"):
        parts.append(str(tool["title"]))
    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        parts.append(_collect_schema_text(annotations))
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


def _decode_base64_candidate(candidate: str) -> str | None:
    padded = candidate + ("=" * (-len(candidate) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    if printable / max(len(text), 1) < 0.85:
        return None
    return text


def _scan_hidden_instruction_carriers(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if _UNICODE_CONTROL_PATTERN.search(text):
        hits.append({"kind": "unicode_control"})
    for pattern in _INVISIBLE_TEXT_PATTERNS:
        if pattern.search(text):
            hits.append({"kind": "hidden_comment", "pattern": pattern.pattern})
    for match in _BASE64_CANDIDATE_PATTERN.finditer(text):
        decoded = _decode_base64_candidate(match.group(0))
        if not decoded:
            continue
        decoded_hits = _scan_poisoning(decoded)
        if decoded_hits:
            hits.append(
                {
                    "kind": "encoded_payload",
                    "encoding": "base64",
                    "markers": decoded_hits[:10],
                }
            )
    return hits


def audit_tool_metadata(tools: list[dict[str, Any]]) -> list[Finding]:
    """Scan ``tools/list`` definitions for poisoning, shadowing, and exfil chains."""
    findings: list[Finding] = []
    if not tools:
        return findings

    names: list[str] = []
    local_read_tools: set[str] = set()
    network_egress_tools: set[str] = set()

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)

        visible = _tool_text(tool)
        if _LOCAL_READ_PATTERN.search(visible):
            if name:
                local_read_tools.add(str(name))
        if _NETWORK_EGRESS_PATTERN.search(visible):
            if name:
                network_egress_tools.add(str(name))

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
        hidden_hits = _scan_hidden_instruction_carriers(visible)
        if hidden_hits and name:
            findings.append(
                server_finding(
                    "HI1",
                    "hidden_instruction",
                    "high",
                    str(name),
                    "Tool metadata contains hidden or encoded instruction "
                    "carriers (invisible Unicode, hidden comments, or encoded "
                    "prompt-injection payloads).",
                    evidence={"carriers": hidden_hits[:10]},
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
            hidden_schema_hits = _scan_hidden_instruction_carriers(schema_text)
            if hidden_schema_hits and name:
                findings.append(
                    server_finding(
                        "HI2",
                        "hidden_instruction",
                        "high",
                        str(name),
                        "Tool inputSchema contains hidden or encoded instruction "
                        "carriers.",
                        evidence={"carriers": hidden_schema_hits[:10]},
                    )
                )

    name_counts = Counter(names)
    dupes = [n for n, count in name_counts.items() if count > 1]
    for dupe in dupes:
        findings.append(
            server_finding(
                "TS1",
                "tool_shadowing",
                "medium",
                dupe,
                f"Duplicate tool name '{dupe}' appears {name_counts[dupe]} times "
                "(tool shadowing / name collision within this server).",
                evidence={"occurrences": name_counts[dupe]},
            )
        )

    if local_read_tools and network_egress_tools:
        findings.append(
            server_finding(
                "CC1",
                "dangerous_capability_combo",
                "medium",
                "mcp_endpoint",
                "Server exposes both local-read and network-egress style tools "
                "(parasitic toolchain / data-exfiltration chain risk).",
                arxiv_id=CAPABILITY_COMBO_PAPER_ARXIV_ID,
                evidence={
                    "local_read_tools": sorted(local_read_tools),
                    "network_egress_tools": sorted(network_egress_tools),
                },
            )
        )

    return findings
