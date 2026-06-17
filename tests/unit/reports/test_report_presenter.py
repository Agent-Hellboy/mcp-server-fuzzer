"""Tests for FuzzReportPresenter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.reports.report_presenter import FuzzReportPresenter


def test_print_summary_methods_delegate():
    reporter = MagicMock()
    presenter = FuzzReportPresenter(reporter, safety_system=None)
    results = {"tool": {"runs": []}}

    presenter.print_tool_summary(results)
    presenter.print_tool_execution_summary(results)
    presenter.print_protocol_summary(results)
    presenter.print_safety_statistics()
    presenter.print_safety_system_summary()
    presenter.print_overall_summary(results, results)

    reporter.print_tool_summary.assert_called_once_with(results)
    reporter.print_tool_execution_summary.assert_called_once_with(results)
    reporter.print_protocol_summary.assert_called_once_with(results)
    reporter.print_safety_summary.assert_called_once()
    reporter.print_safety_system_summary.assert_called_once()
    reporter.print_overall_summary.assert_called_once_with(results, results)


def test_print_blocked_operations_summary_collects_stats():
    reporter = MagicMock()
    safety = MagicMock()
    safety.get_statistics.return_value = {"blocked": 1}
    presenter = FuzzReportPresenter(reporter, safety_system=safety)

    presenter.print_blocked_operations_summary()

    safety.get_statistics.assert_called_once()
    reporter.print_blocked_operations_summary.assert_called_once()


@pytest.mark.asyncio
async def test_generate_reports_delegate():
    reporter = MagicMock()
    reporter.generate_standardized_report = AsyncMock(return_value={"ok": True})
    reporter.export_requested_formats = AsyncMock(return_value={"csv": "out.csv"})
    reporter.generate_final_report = AsyncMock(return_value="/tmp/report.json")
    presenter = FuzzReportPresenter(reporter)

    output = await presenter.generate_standardized_reports(
        output_types=["fuzzing_results"], include_safety=False
    )
    exported = await presenter.export_requested_formats({"csv": "out.csv"})
    final = await presenter.generate_final_report(include_safety=False)

    assert output == {"ok": True}
    assert exported == {"csv": "out.csv"}
    assert final == "/tmp/report.json"
    reporter.generate_standardized_report.assert_called_once_with(
        output_types=["fuzzing_results"], include_safety=False
    )
