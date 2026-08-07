#!/usr/bin/env python3
"""A report must state the version of the code that produced it.

``importlib.metadata`` reads *installed distribution* metadata, which goes
stale the moment the working tree moves ahead of the last ``pip install``.
These tests pin report metadata to ``mcp_fuzzer.version.VERSION`` so the two
cannot drift again.
"""

from __future__ import annotations

import re

import mcp_fuzzer.reports.reporter as reporter_module
from mcp_fuzzer.reports.reporter import _resolve_fuzzer_version
from mcp_fuzzer.version import VERSION


def test_resolved_version_is_code_version():
    assert _resolve_fuzzer_version() == VERSION


def test_resolved_version_ignores_stale_installed_metadata(monkeypatch):
    """Even with bogus distribution metadata, the code version is reported."""
    monkeypatch.setattr(
        reporter_module, "version", lambda _name: "0.0.1-stale"
    )
    assert _resolve_fuzzer_version() == VERSION


def test_cli_version_string_matches_report_version(capsys):
    """`mcp-fuzzer --version` and report metadata must agree."""
    import pytest

    from mcp_fuzzer.cli.parser import create_argument_parser

    parser = create_argument_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])
    printed = capsys.readouterr().out.strip()

    assert printed.endswith(f"v{VERSION}")
    assert _resolve_fuzzer_version() == VERSION
    # The version the CLI advertises is the version reports will carry.
    assert printed.endswith(f"v{_resolve_fuzzer_version()}")


def test_version_is_pep440_release():
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-]?(a|b|rc|post|dev)\d+)?", VERSION), (
        f"VERSION {VERSION!r} is not a valid release version"
    )


def test_reporter_instance_records_code_version(tmp_path):
    reporter = reporter_module.FuzzerReporter(output_dir=str(tmp_path))
    assert reporter._fuzzer_version == VERSION
