"""Formatter protocol definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..core.models import ReportSnapshot


class ReportFormatter(Protocol):
    """Interface for report formatters."""

    def format(self, report: ReportSnapshot) -> str:
        """Convert report data to string content."""
        ...

    def save(
        self,
        report: ReportSnapshot,
        output_dir: Path,
        filename: str | None = None,
    ) -> str:
        """Format and save the report to a file."""
        ...
