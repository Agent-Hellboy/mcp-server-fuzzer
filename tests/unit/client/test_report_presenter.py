"""Tests for FuzzReportPresenter."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.client.fuzzer_client import MCPFuzzerClient
from mcp_fuzzer.client.report_presenter import FuzzReportPresenter


def test_print_summary_methods_delegate():
    reporter = MagicMock()
    presenter = FuzzReportPresenter(reporter, safety_system=None)

    presenter.print_tool_summary({"tool": []})
    presenter.print_protocol_summary({"PingRequest": []}, title="Title")
    presenter.print_safety_statistics()
    presenter.print_safety_system_summary()
    presenter.print_overall_summary({}, {})

    reporter.print_tool_summary.assert_called_once()
    reporter.print_protocol_summary.assert_called_once()
    reporter.print_safety_summary.assert_called_once()
    reporter.print_safety_system_summary.assert_called_once()
    reporter.print_overall_summary.assert_called_once()


def test_print_blocked_operations_summary_collects_stats():
    safety = SimpleNamespace(get_statistics=MagicMock())
    reporter = MagicMock()
    presenter = FuzzReportPresenter(reporter, safety_system=safety)

    presenter.print_blocked_operations_summary()

    safety.get_statistics.assert_called_once()
    reporter.print_blocked_operations_summary.assert_called_once()


@pytest.mark.asyncio
async def test_generate_reports_delegate():
    reporter = MagicMock()
    reporter.generate_standardized_report = AsyncMock(return_value={"ok": True})
    reporter.generate_final_report = AsyncMock(return_value={"final": True})
    presenter = FuzzReportPresenter(reporter)

    output = await presenter.generate_standardized_reports(
        output_types=["json"], include_safety=False
    )
    final = await presenter.generate_final_report(include_safety=False)

    assert output == {"ok": True}
    assert final == {"final": True}
    reporter.generate_standardized_report.assert_called_once_with(
        output_types=["json"], include_safety=False
    )
    reporter.generate_final_report.assert_called_once_with(include_safety=False)


def test_fuzzer_client_exposes_report_presenter():
    reporter = MagicMock()
    client = MCPFuzzerClient(
        transport=MagicMock(), reporter=reporter, safety_enabled=False
    )
    assert isinstance(client.report_presenter, FuzzReportPresenter)
    assert client.report_presenter.reporter is reporter
