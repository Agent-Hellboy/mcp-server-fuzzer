"""Coordinate fuzz-run classification, security audits, and findings output."""

from __future__ import annotations

import logging
from typing import Any

from ..diagnostics import classify_fuzz_runs, summarize_findings
from .audit_registry import AuditContext, run_audit_phases
from .models import SessionContext, SessionResult
from .persist import persist_session_findings
from .run_plan import build_run_plan

logger = logging.getLogger(__name__)


async def collect_session_findings(
    config: dict[str, Any],
    transport: Any,
    *,
    mode: str,
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
    build_transport_request: Any,
) -> tuple[list[Any], dict[str, int]]:
    """Classify fuzz runs and run optional paper-backed audit phases."""
    findings = classify_fuzz_runs(tool_results, protocol_results)
    ctx = AuditContext(
        config=config,
        transport=transport,
        mode=mode,
        tool_results=tool_results,
        protocol_results=protocol_results,
        build_transport_request=build_transport_request,
    )
    findings.extend(await run_audit_phases(ctx))
    return findings, summarize_findings(findings)


async def run_session(
    context: SessionContext,
    *,
    transport: Any,
    build_transport_request: Any,
) -> SessionResult:
    """Drive a full session: run the fuzz_engine plan, then the findings pipeline.

    Raises ``ValueError`` if the run plan cannot be built for the mode.
    """
    config = context.config
    mode = config["mode"]
    plan = build_run_plan(mode, config)
    await plan.execute(context)

    tool_results = context.tool_results
    protocol_results = context.protocol_results
    tr = tool_results if isinstance(tool_results, dict) else None
    pr = protocol_results if isinstance(protocol_results, dict) else None

    findings: list[Any] = []
    findings_summary: dict[str, int] = {}
    try:
        findings, findings_summary = await collect_session_findings(
            config,
            transport,
            mode=mode,
            tool_results=tr,
            protocol_results=pr,
            build_transport_request=build_transport_request,
        )
        persist_session_findings(
            config,
            findings,
            findings_summary,
            tool_results=tr,
            protocol_results=pr,
        )
    except Exception as exc:  # pragma: no cover - analysis is best-effort
        logging.warning("Failed to analyze/record findings: %s", exc)
    tool_client = getattr(context.client, "tool_client", None)
    tool_discovery = (
        getattr(tool_client, "tool_discovery", None) if tool_client is not None else None
    )
    return SessionResult(
        tool_results=tool_results,
        protocol_results=protocol_results,
        findings=findings,
        findings_summary=findings_summary,
        tool_discovery=tool_discovery,
    )


__all__ = ["collect_session_findings", "run_session"]
