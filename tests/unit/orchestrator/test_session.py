"""Tests for orchestrator session spine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.diagnostics.model import Finding
from mcp_fuzzer.orchestrator.models import SessionContext, SessionResult
from mcp_fuzzer.orchestrator.session import collect_session_findings, run_session


def _finding() -> Finding:
    return Finding(
        category="tool_poisoning",
        severity="high",
        kind="tool",
        target="helper",
        run=None,
        detail="poisoned",
        evidence={},
    )


@pytest.mark.asyncio
async def test_collect_session_findings_runs_audit_registry():
    tool_results = {"echo": [{"success": True}]}
    audit_finding = _finding()

    with patch(
        "mcp_fuzzer.orchestrator.session.run_audit_phases",
        new=AsyncMock(return_value=[audit_finding]),
    ):
        findings, summary = await collect_session_findings(
            {"mode": "tools"},
            MagicMock(),
            mode="tools",
            tool_results=tool_results,
            protocol_results=None,
            build_transport_request=lambda c: c,
        )

    assert any(f.category == "tool_poisoning" for f in findings)
    assert audit_finding in findings
    assert summary


@pytest.mark.asyncio
async def test_run_session_returns_session_result():
    context = SessionContext(
        client=MagicMock(),
        config={"mode": "tools"},
        reporter=None,
        protocol_phase="realistic",
    )
    context.tool_results = {"echo": [{"success": True}]}
    mock_plan = MagicMock()
    mock_plan.execute = AsyncMock()

    with (
        patch(
            "mcp_fuzzer.orchestrator.session.build_run_plan",
            return_value=mock_plan,
        ),
        patch(
            "mcp_fuzzer.orchestrator.session.collect_session_findings",
            new=AsyncMock(return_value=([], {})),
        ),
        patch("mcp_fuzzer.orchestrator.session.persist_session_findings"),
    ):
        result = await run_session(
            context,
            transport=MagicMock(),
            build_transport_request=lambda c: c,
        )

    assert isinstance(result, SessionResult)
    assert result.tool_results == {"echo": [{"success": True}]}
    mock_plan.execute.assert_awaited_once_with(context)


@pytest.mark.asyncio
async def test_run_session_continues_when_findings_pipeline_fails(caplog):
    context = SessionContext(
        client=MagicMock(),
        config={"mode": "tools"},
        reporter=None,
        protocol_phase="realistic",
    )
    mock_plan = MagicMock()
    mock_plan.execute = AsyncMock()

    with (
        patch(
            "mcp_fuzzer.orchestrator.session.build_run_plan",
            return_value=mock_plan,
        ),
        patch(
            "mcp_fuzzer.orchestrator.session.collect_session_findings",
            new=AsyncMock(side_effect=RuntimeError("analysis failed")),
        ),
        caplog.at_level("WARNING"),
    ):
        result = await run_session(
            context,
            transport=MagicMock(),
            build_transport_request=lambda c: c,
        )

    assert isinstance(result, SessionResult)
    assert result.findings == []
    assert "Failed to analyze/record findings" in caplog.text
