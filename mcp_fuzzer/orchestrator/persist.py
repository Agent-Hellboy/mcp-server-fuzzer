"""Persist session findings and crash reproduction artifacts."""

from __future__ import annotations

import logging
from typing import Any

from ..reports.crash_repro import write_crash_repros, write_findings_report


def persist_session_findings(
    config: dict[str, Any],
    findings: list[Any],
    findings_summary: dict[str, int],
    *,
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> None:
    """Write crash repro artifacts and ``findings.json`` for a completed session."""
    out_dir = config.get("output_dir") or "reports"
    crash_files = write_crash_repros(out_dir, tool_results, protocol_results)
    if crash_files:
        logging.warning(
            "Recorded %d server crash reproduction(s) in %s",
            len(crash_files),
            crash_files[0].parent,
        )
    if findings:
        report_path = write_findings_report(out_dir, findings)
        logging.warning(
            "Recorded %d finding(s) across %d categor(y/ies) in %s",
            len(findings),
            len(findings_summary),
            report_path,
        )


__all__ = ["persist_session_findings"]
