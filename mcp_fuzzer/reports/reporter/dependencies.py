"""Dependency wiring helpers for the reporter module."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console

from ..core import ReportCollector
from ..formatters import (
    ConsoleFormatter,
    CSVFormatter,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    TextFormatter,
    XMLFormatter,
)
from ..output import OutputManager
from ..safety_reporter import SafetyReporter
from .contracts import (
    ConsoleSummaryPort,
    OutputManagerPort,
    ReportCollectorPort,
    SafetyReporterPort,
)


@dataclass(slots=True)
class FormatterRegistry:
    """Collection of formatter adapters used by the reporter."""

    console: ConsoleSummaryPort
    json: JSONFormatter
    text: TextFormatter
    csv: CSVFormatter
    xml: XMLFormatter
    html: HTMLFormatter
    markdown: MarkdownFormatter

    @classmethod
    def default(cls, *, console: Console) -> "FormatterRegistry":
        """Build the default formatter registry."""
        return cls(
            console=ConsoleFormatter(console),
            json=JSONFormatter(),
            text=TextFormatter(),
            csv=CSVFormatter(),
            xml=XMLFormatter(),
            html=HTMLFormatter(),
            markdown=MarkdownFormatter(),
        )


@dataclass(slots=True)
class ReporterDependencies:
    """Resolved dependencies for the reporter implementation."""

    console: Console
    formatters: FormatterRegistry
    collector: ReportCollectorPort
    output_manager: OutputManagerPort
    safety: SafetyReporterPort

    @classmethod
    def build(
        cls,
        *,
        output_dir: str,
        compress_output: bool,
        console: Console | None = None,
        collector: ReportCollectorPort | None = None,
        output_manager: OutputManagerPort | None = None,
        safety_reporter: SafetyReporterPort | None = None,
        formatter_registry: FormatterRegistry | None = None,
    ) -> "ReporterDependencies":
        """
        Construct dependencies with optional overrides.

        This keeps instantiation logic centralized and DI-friendly.
        """

        resolved_console = console or Console()
        resolved_collector: ReportCollectorPort = collector or ReportCollector()
        resolved_output_manager: OutputManagerPort = output_manager or OutputManager(
            output_dir, compress_output
        )
        resolved_safety: SafetyReporterPort = safety_reporter or SafetyReporter()
        resolved_formatters = formatter_registry or FormatterRegistry.default(
            console=resolved_console
        )

        return cls(
            console=resolved_console,
            formatters=resolved_formatters,
            collector=resolved_collector,
            output_manager=resolved_output_manager,
            safety=resolved_safety,
        )
