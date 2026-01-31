"""Formatter protocol definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..core.models import ReportSnapshot


class ReportSaver(Protocol):
    """Interface for report writers that can save to disk."""

    def save(
        self,
        report: ReportSnapshot,
        output_dir: Path,
        filename: str | None = None,
    ) -> str:
        """Format and save the report to a file."""
        ...


class ReportFormatter(ReportSaver, Protocol):
    """Interface for report formatters that can render to string content."""

    def format(self, report: ReportSnapshot) -> str:
        """Convert report data to string content."""
        ...
