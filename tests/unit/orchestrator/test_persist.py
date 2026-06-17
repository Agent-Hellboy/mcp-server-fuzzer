"""Tests for orchestrator findings persistence."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

from mcp_fuzzer.diagnostics.model import Finding
from mcp_fuzzer.orchestrator.persist import persist_session_findings


def _finding() -> Finding:
    return Finding(
        category="crash",
        severity="critical",
        kind="tool",
        target="echo",
        run=1,
        detail="server crashed",
        evidence={},
    )


def test_persist_session_findings_writes_crash_and_findings(caplog, tmp_path):
    crash_path = tmp_path / "crash.json"
    findings_path = tmp_path / "findings.json"
    finding = _finding()

    with (
        patch(
            "mcp_fuzzer.orchestrator.persist.write_crash_repros",
            return_value=[crash_path],
        ),
        patch(
            "mcp_fuzzer.orchestrator.persist.write_findings_report",
            return_value=findings_path,
        ),
        caplog.at_level(logging.WARNING),
    ):
        persist_session_findings(
            {"output_dir": str(tmp_path)},
            [finding],
            {"crash": 1},
            tool_results={"echo": []},
            protocol_results=None,
        )

    assert "crash reproduction" in caplog.text
    assert "Recorded 1 finding" in caplog.text


def test_persist_session_findings_skips_empty_findings():
    with (
        patch(
            "mcp_fuzzer.orchestrator.persist.write_crash_repros",
            return_value=[],
        ) as mock_crash,
        patch(
            "mcp_fuzzer.orchestrator.persist.write_findings_report",
        ) as mock_findings,
    ):
        persist_session_findings({}, [], {}, tool_results=None, protocol_results=None)

    mock_crash.assert_called_once()
    mock_findings.assert_not_called()
