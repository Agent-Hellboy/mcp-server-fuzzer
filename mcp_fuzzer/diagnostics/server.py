"""Paper-backed MCP server audit checks (non-OAuth).

Thin facade composing metadata, output-oracle, and transport submodules.
"""

from __future__ import annotations

from typing import Any

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


def run_server_audit(
    tools: list[dict[str, Any]] | None,
    *,
    endpoint: str,
    tool_results: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run all read-only MCP server audit checks."""
    from .server_metadata import audit_tool_metadata
    from .server_oracles import audit_tool_run_oracles
    from .server_transport import audit_insecure_transport

    findings: list[Finding] = []
    findings.extend(audit_insecure_transport(endpoint))
    if tools:
        findings.extend(audit_tool_metadata(tools))
    findings.extend(audit_tool_run_oracles(tool_results))
    return findings


__all__ = [
    "CAPABILITY_COMBO_PAPER_ARXIV_ID",
    "SERVER_AUDIT_FLAW_CATEGORIES",
    "TOOL_POISONING_PAPER_ARXIV_ID",
    "TRANSPORT_PAPER_ARXIV_ID",
    "audit_insecure_transport",
    "audit_tool_metadata",
    "audit_tool_run_oracles",
    "is_server_audit_finding",
    "run_server_audit",
    "server_audit_paper_evidence",
    "server_audit_report_metadata",
    "server_finding",
]

# Re-export check entry points for callers that import from server directly.
from .server_metadata import audit_tool_metadata  # noqa: E402
from .server_oracles import audit_tool_run_oracles  # noqa: E402
from .server_transport import audit_insecure_transport  # noqa: E402
