#!/usr/bin/env python3
"""Tests for report formatter protocol."""

from __future__ import annotations

import typing

import pytest

from mcp_fuzzer.reports.formatters.interface import ReportFormatter, ReportSaver

pytestmark = [pytest.mark.unit]


def test_report_formatter_protocol_importable():
    assert issubclass(ReportFormatter, typing.Protocol)
    assert hasattr(ReportFormatter, "format")
    assert hasattr(ReportFormatter, "save")


def test_report_saver_protocol_importable():
    assert issubclass(ReportSaver, typing.Protocol)
    assert hasattr(ReportSaver, "save")
