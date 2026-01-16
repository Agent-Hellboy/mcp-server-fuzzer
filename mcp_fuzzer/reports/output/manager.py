#!/usr/bin/env python3
"""Filesystem manager for standardized output artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core import ReportSnapshot
from .protocol import OutputProtocol


class OutputManager:
    """Manages output generation and file organization."""

    def __init__(self, output_dir: str = "output", compress: bool = False):
        self.output_dir = Path(output_dir)
        self.compress = compress
        self.protocol = OutputProtocol()

    def _save(self, output: dict[str, Any]) -> str:
        return self.protocol.save_output(
            output, self.output_dir, compress=self.compress
        )

    def save_fuzzing_results(
        self,
        mode: str,
        protocol: str,
        endpoint: str,
        tool_results: dict[str, Any],
        protocol_results: dict[str, list[dict[str, Any]]],
        execution_time: str,
        total_tests: int,
        success_rate: float,
        safety_enabled: bool = False,
    ) -> str:
        """Save fuzzing results using standardized format."""
        output = self.protocol.create_fuzzing_results_output(
            mode=mode,
            protocol=protocol,
            endpoint=endpoint,
            tool_results=tool_results,
            protocol_results=protocol_results,
            execution_time=execution_time,
            total_tests=total_tests,
            success_rate=success_rate,
            safety_enabled=safety_enabled,
        )
        return self._save(output)

    def save_fuzzing_snapshot(
        self,
        snapshot: ReportSnapshot,
        safety_enabled: bool = False,
    ) -> str:
        """Save fuzzing results using a ReportSnapshot."""
        output = self.protocol.create_fuzzing_results_from_snapshot(
            snapshot=snapshot,
            safety_enabled=safety_enabled,
        )
        return self._save(output)

    def save_error_report(
        self,
        errors: list[dict[str, Any]],
        warnings: list[dict[str, Any]] | None = None,
        execution_context: dict[str, Any] | None = None,
    ) -> str:
        """Save error report using standardized format."""
        output = self.protocol.create_error_report_output(
            errors=errors,
            warnings=warnings,
            execution_context=execution_context,
        )
        return self._save(output)

    def save_safety_summary(self, safety_data: dict[str, Any]) -> str:
        """Save safety summary using standardized format."""
        blocked_operations = safety_data.get("blocked_operations", [])
        risk_assessment = safety_data.get("risk_assessment", "unknown")
        output = self.protocol.create_safety_summary_output(
            safety_data=safety_data,
            blocked_operations=blocked_operations,
            risk_assessment=risk_assessment,
        )
        return self._save(output)

    def get_session_directory(self, session_id: str | None = None) -> Path:
        """Get the session directory path."""
        session_id = session_id or self.protocol.session_id
        return self.output_dir / "sessions" / session_id

    def list_session_outputs(self, session_id: str | None = None) -> list[Path]:
        """List all output files for a session."""
        session_dir = self.get_session_directory(session_id)
        if not session_dir.exists():
            return []
        return list(session_dir.glob("*.json"))
