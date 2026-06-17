"""Audit taxonomy metadata for persisted reports and stdout summaries."""

from __future__ import annotations

from typing import Any


def build_findings_audit_sections(findings: list[Any]) -> dict[str, Any]:
    """Build optional audit metadata blocks for ``findings.json``."""
    from ..diagnostics.auth_oauth import (
        auth_audit_report_metadata,
        is_auth_audit_finding,
    )
    from ..diagnostics.server import (
        is_server_audit_finding,
        server_audit_report_metadata,
    )

    sections: dict[str, Any] = {}
    auth_audit_findings = [f for f in findings if is_auth_audit_finding(f)]
    if auth_audit_findings:
        sections["auth_audit"] = {
            **auth_audit_report_metadata(),
            "finding_count": len(auth_audit_findings),
        }
    server_findings = [f for f in findings if is_server_audit_finding(f)]
    if server_findings:
        sections["server_audit"] = {
            **server_audit_report_metadata(),
            "finding_count": len(server_findings),
        }
    return sections


def audit_summary_footnotes(findings_summary: dict[str, int]) -> list[str]:
    """Return plain-text footnotes linking finding categories to audit papers."""
    from ..diagnostics.auth_oauth import (
        AUTH_AUDIT_FLAW_CATEGORIES,
        AUTH_AUDIT_PAPER_ARXIV_ID,
        AUTH_AUDIT_PAPER_URL,
    )
    from ..diagnostics.server import (
        SERVER_AUDIT_FLAW_CATEGORIES,
        TOOL_POISONING_PAPER_ARXIV_ID,
        server_audit_paper_evidence,
    )

    lines: list[str] = []
    if AUTH_AUDIT_FLAW_CATEGORIES & set(findings_summary):
        lines.append(
            "Auth security audit findings map to flaw types in "
            f"arXiv {AUTH_AUDIT_PAPER_ARXIV_ID} ({AUTH_AUDIT_PAPER_URL})"
        )
    if SERVER_AUDIT_FLAW_CATEGORIES & set(findings_summary):
        paper_url = server_audit_paper_evidence(TOOL_POISONING_PAPER_ARXIV_ID)[
            "paper_url"
        ]
        lines.append(
            "Server audit findings map to checks from arXiv "
            f"{TOOL_POISONING_PAPER_ARXIV_ID} ({paper_url})"
        )
    return lines


__all__ = ["audit_summary_footnotes", "build_findings_audit_sections"]
