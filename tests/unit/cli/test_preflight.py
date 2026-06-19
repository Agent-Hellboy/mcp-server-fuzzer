"""Tests for startup output path checks."""

from __future__ import annotations

from mcp_fuzzer.cli.preflight import verify_output_paths
from mcp_fuzzer.diagnostics.tool_discovery import ToolDiscoveryFailure


def test_verify_output_paths_succeeds_on_writable_dir(tmp_path):
    assert verify_output_paths(str(tmp_path), str(tmp_path / "sandbox")) is None


def test_verify_output_paths_reports_unwritable(monkeypatch, tmp_path):
    target = tmp_path / "out"
    target.mkdir()

    def _fail_write(*_args, **_kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr("pathlib.Path.write_text", _fail_write)
    report = verify_output_paths(str(target), None)
    assert report is not None
    assert report.failure is ToolDiscoveryFailure.OUTPUT_NOT_WRITABLE
