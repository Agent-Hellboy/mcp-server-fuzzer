"""Tests for shared tool-run shape normalization."""

from __future__ import annotations

from mcp_fuzzer.types import extract_tool_runs


def test_extract_tool_runs_from_runs_key():
    entry = {"runs": [{"success": True}]}
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}]
    assert metadata is entry


def test_extract_tool_runs_from_phase_keys():
    entry = {"realistic": [{"success": True}], "aggressive": [{"success": False}]}
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}, {"success": False}]
    assert metadata is entry


def test_extract_tool_runs_from_list():
    entry = [{"success": True}]
    runs, metadata = extract_tool_runs(entry)
    assert runs == [{"success": True}]
    assert metadata is None


def test_extract_tool_runs_from_unexpected_value():
    runs, metadata = extract_tool_runs(None)
    assert runs == []
    assert metadata is None


def test_extract_tool_runs_from_error_only_entry():
    entry = {"success": False, "error": "phase failed", "exception": "boom"}
    runs, metadata = extract_tool_runs(entry)
    assert runs == [
        {
            "success": False,
            "error": "phase failed",
            "exception": "boom",
            "safety_blocked": False,
            "safety_sanitized": False,
        }
    ]
    assert metadata is entry


def test_extract_tool_runs_from_error_entry_with_args_and_label():
    entry = {
        "success": False,
        "error": "phase failed",
        "args": {"x": 1},
        "label": "realistic",
    }
    runs, metadata = extract_tool_runs(entry)
    assert runs[0]["args"] == {"x": 1}
    assert runs[0]["label"] == "realistic"
    assert metadata is entry


def test_extract_tool_runs_from_empty_dict():
    runs, metadata = extract_tool_runs({})
    assert runs == []
    assert metadata == {}
