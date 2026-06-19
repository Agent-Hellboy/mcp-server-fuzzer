"""Tests for post-session reporting presenter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.cli.post_run import PostRunPresenter, _requested_export_targets
from mcp_fuzzer.cli.session_settings import SessionSettings
from mcp_fuzzer.orchestrator.models import SessionResult


def test_requested_export_targets_collects_configured_formats():
    targets = _requested_export_targets(
        {"export_csv": "out.csv", "export_html": "out.html"}
    )
    assert targets == {"csv": "out.csv", "html": "out.html"}


@pytest.mark.asyncio
async def test_post_run_returns_two_when_no_tools_and_flag_set(tmp_path):
    settings = SessionSettings(
        {
            "mode": "tools",
            "fail_if_no_tools": True,
            "output_dir": str(tmp_path),
            "export_csv": None,
            "export_xml": None,
            "export_html": None,
            "export_markdown": None,
        }
    )
    reporter = MagicMock()
    reporter.print_tool_execution_summary = MagicMock()
    reporter.generate_standardized_report = AsyncMock(return_value={})
    reporter.export_requested_formats = AsyncMock(return_value={})
    presenter = PostRunPresenter(settings, reporter)
    result = SessionResult(
        tool_results={},
        protocol_results=None,
        findings=[],
        findings_summary={},
    )

    with patch("mcp_fuzzer.cli.post_run.write_stdout_summary"):
        exit_code = await presenter.present(result)

    assert exit_code == 2
    assert (tmp_path / "run_summary.json").exists()
