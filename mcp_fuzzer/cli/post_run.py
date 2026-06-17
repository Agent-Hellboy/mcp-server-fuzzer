#!/usr/bin/env python3
"""Post-session reporting: summaries, exports, and exit-code derivation."""

from __future__ import annotations

import logging
from typing import Any

from ..orchestrator.audit_metadata import audit_summary_footnotes
from ..orchestrator.models import SessionResult
from ..reports import FuzzerReporter
from ..reports.formatters.plain_summary import write_stdout_summary
from ..reports.report_presenter import FuzzReportPresenter
from .session_settings import SessionSettings


def _requested_export_targets(config: dict[str, Any]) -> dict[str, str]:
    export_targets: dict[str, str] = {}
    for config_key, format_name in (
        ("export_csv", "csv"),
        ("export_xml", "xml"),
        ("export_html", "html"),
        ("export_markdown", "markdown"),
    ):
        filename = config.get(config_key)
        if filename:
            export_targets[format_name] = filename
    return export_targets


class PostRunPresenter:
    """Handles all post-session reporting using the reporter and presenter."""

    def __init__(
        self,
        settings: SessionSettings,
        reporter: FuzzerReporter | None,
    ) -> None:
        self._settings = settings
        self._presenter = (
            FuzzReportPresenter(reporter) if reporter is not None else None
        )

    async def present(self, result: SessionResult) -> int:
        """Print summaries, export reports, and return the process exit code."""
        mode = self._settings.mode
        tool_results = result.tool_results
        protocol_results = result.protocol_results
        findings_summary = result.findings_summary

        tools_mode = mode in ("tools", "all")
        tools_fuzzed = isinstance(tool_results, dict) and len(tool_results) > 0
        no_tools_available = tools_mode and not tools_fuzzed

        if self._presenter is not None:
            try:  # pragma: no cover
                if mode in ("tools", "all") and tool_results:
                    self._presenter.print_tool_execution_summary(tool_results)
            except Exception as exc:  # pragma: no cover
                logging.warning("Failed to display table summary: %s", exc)

            try:  # pragma: no cover
                if mode not in ("tools",) and isinstance(protocol_results, dict):
                    if protocol_results:
                        self._presenter.print_protocol_summary(protocol_results)
            except Exception as exc:  # pragma: no cover
                logging.warning("Failed to display protocol summary tables: %s", exc)

        tr = tool_results if isinstance(tool_results, dict) else None
        pr = protocol_results if isinstance(protocol_results, dict) else None

        try:
            write_stdout_summary(
                mode=mode,
                tool_results=tr,
                protocol_results=pr,
                blocked=no_tools_available,
                findings_summary=findings_summary,
                audit_footnotes=(
                    audit_summary_footnotes(findings_summary)
                    if findings_summary
                    else None
                ),
            )
        except Exception as exc:  # pragma: no cover
            logging.warning("Failed to write plain stdout summary: %s", exc)

        if self._presenter is not None:
            try:  # pragma: no cover
                standardized_files = (
                    await self._presenter.generate_standardized_reports(
                        output_types=self._settings.output_types,
                        include_safety=self._settings.safety_report,
                    )
                )
                if standardized_files:
                    logging.info(
                        "Generated standardized reports: %s",
                        list(standardized_files.keys()),
                    )
            except Exception as exc:  # pragma: no cover
                logging.warning("Failed to generate standardized reports: %s", exc)

            try:  # pragma: no cover
                export_targets = _requested_export_targets(self._settings.config)
                exported_files = await self._presenter.export_requested_formats(
                    export_targets,
                    include_safety=self._settings.safety_report,
                )
                if exported_files:
                    logging.info("Exported report formats: %s", exported_files)
            except Exception as exc:  # pragma: no cover
                logging.warning("Failed to export additional report formats: %s", exc)
                logging.exception("Export error details:")

        if no_tools_available and self._settings.fail_if_no_tools:
            logging.warning(
                "No tools were available to fuzz; exiting non-zero due to "
                "--fail-if-no-tools"
            )
            return 2

        return 0


__all__ = ["PostRunPresenter"]
