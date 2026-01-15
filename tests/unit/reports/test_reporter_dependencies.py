#!/usr/bin/env python3
"""Tests for reporter config and dependency wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from mcp_fuzzer.reports.formatters import (
    CSVFormatter,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    TextFormatter,
    XMLFormatter,
)
from mcp_fuzzer.reports.output import OutputManager
from mcp_fuzzer.reports.reporter.config import ReporterConfig
from mcp_fuzzer.reports.reporter.dependencies import (
    FormatterRegistry,
    ReporterDependencies,
)
from mcp_fuzzer.reports.core import ReportCollector
from mcp_fuzzer.reports.safety_reporter import SafetyReporter


@pytest.mark.unit
def test_reporter_config_defaults_to_report_directory():
    config = ReporterConfig.from_provider(provider=None, requested_output_dir="")

    assert config.output_dir == Path("reports")
    assert config.output_format == "json"
    assert config.compress_output is False
    assert config.output_types is None
    assert config.output_schema is None


@pytest.mark.unit
def test_reporter_config_uses_provider_overrides():
    provider = {
        "output_dir": "provider-dir",
        "output": {
            "compress": True,
            "format": "xml",
            "types": ["csv"],
            "schema": {"version": "1.0"},
        },
    }

    config = ReporterConfig.from_provider(provider=provider, requested_output_dir="")

    assert config.output_dir == Path("provider-dir")
    assert config.compress_output is True
    assert config.output_format == "xml"
    assert config.output_types == ["csv"]
    assert config.output_schema == {"version": "1.0"}


@pytest.mark.unit
def test_reporter_config_respects_requested_directory():
    provider = {"output_dir": "provider-dir", "output": {"directory": "should-not-use"}}

    config = ReporterConfig.from_provider(
        provider=provider, requested_output_dir="explicit-dir"
    )

    assert config.output_dir == Path("explicit-dir")


@pytest.mark.unit
def test_formatter_registry_default_wires_formatters():
    console = Console()
    registry = FormatterRegistry.default(console=console)

    assert registry.console.console is console
    assert isinstance(registry.json, JSONFormatter)
    assert isinstance(registry.text, TextFormatter)
    assert isinstance(registry.csv, CSVFormatter)
    assert isinstance(registry.xml, XMLFormatter)
    assert isinstance(registry.html, HTMLFormatter)
    assert isinstance(registry.markdown, MarkdownFormatter)


@pytest.mark.unit
def test_reporter_dependencies_build_defaults():
    deps = ReporterDependencies.build(output_dir="reports", compress_output=True)

    assert isinstance(deps.collector, ReportCollector)
    assert isinstance(deps.output_manager, OutputManager)
    assert isinstance(deps.safety, SafetyReporter)
    assert isinstance(deps.formatters, FormatterRegistry)
    assert str(deps.output_manager.output_dir) == "reports"


@pytest.mark.unit
def test_reporter_dependencies_allows_overrides():
    console = MagicMock(spec=Console)
    formatters = MagicMock()
    collector = MagicMock()
    output_manager = MagicMock()
    safety_reporter = MagicMock()

    deps = ReporterDependencies.build(
        output_dir="reports",
        compress_output=False,
        console=console,
        collector=collector,
        output_manager=output_manager,
        safety_reporter=safety_reporter,
        formatter_registry=formatters,
    )

    assert deps.console is console
    assert deps.collector is collector
    assert deps.output_manager is output_manager
    assert deps.safety is safety_reporter
    assert deps.formatters is formatters
