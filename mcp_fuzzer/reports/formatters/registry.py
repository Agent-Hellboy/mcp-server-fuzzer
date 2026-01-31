#!/usr/bin/env python3
"""Registry for report formatters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .interface import ReportSaver
from ..core.models import ReportSnapshot


@dataclass(frozen=True)
class ReportSaveAdapter(ReportSaver):
    """Adapter that exposes a common formatter interface."""

    save_fn: Callable[..., None]
    default_extension: str
    title: str | None = None

    def save(
        self,
        report: ReportSnapshot,
        output_dir: Path,
        filename: str | None = None,
    ) -> str:
        output_dir.mkdir(parents=True, exist_ok=True)
        if filename:
            path = Path(filename)
            if not path.is_absolute():
                path = output_dir / filename
        else:
            path = output_dir / f"report.{self.default_extension}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.title is None:
            self.save_fn(report, str(path))
        else:
            self.save_fn(report, str(path), self.title)
        return str(path)


class FormatterRegistry:
    """Registry keyed by output type."""

    def __init__(self) -> None:
        self._formatters: dict[str, ReportSaver] = {}

    def register(self, name: str, formatter: ReportSaver) -> None:
        self._formatters[name] = formatter

    def get(self, name: str) -> ReportSaver | None:
        return self._formatters.get(name)

    def save(
        self,
        name: str,
        report: ReportSnapshot,
        output_dir: Path,
        filename: str | None = None,
    ) -> str:
        formatter = self.get(name)
        if formatter is None:
            raise KeyError(f"Unknown formatter: {name}")
        return formatter.save(report, output_dir, filename)


__all__ = ["ReportSaveAdapter", "FormatterRegistry"]
