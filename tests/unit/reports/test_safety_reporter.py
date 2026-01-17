import builtins
from types import SimpleNamespace

import pytest

from mcp_fuzzer.reports.safety_reporter import SafetyReporter


class DummyConsole:
    def __init__(self):
        self.messages = []

    def print(self, *args, **_kwargs):
        self.messages.append(" ".join(str(arg) for arg in args))


def test_init_handles_import_errors(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.endswith("safety_system.safety") or name.endswith(
            "safety_system.blocking"
        ):
            raise ImportError("boom")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    reporter = SafetyReporter()

    assert reporter.safety_filter is None


def test_print_safety_summary_without_filter():
    reporter = SafetyReporter(safety_filter=None)
    reporter.console = DummyConsole()

    reporter.print_safety_summary()

    assert any("not available" in msg for msg in reporter.console.messages)


def test_print_safety_summary_with_stats():
    safety_filter = SimpleNamespace(
        get_safety_statistics=lambda: {
            "total_operations_blocked": 2,
            "unique_tools_blocked": 1,
            "risk_assessment": "high",
            "most_blocked_tool": "tool",
            "most_blocked_tool_count": 2,
            "dangerous_content_breakdown": {"x": 1},
        }
    )
    reporter = SafetyReporter(safety_filter=safety_filter)
    reporter.console = DummyConsole()

    reporter.print_safety_summary()

    assert any("Safety Statistics" in msg for msg in reporter.console.messages)


def test_print_safety_system_summary_with_blocks():
    safety_filter = SimpleNamespace(
        blocked_operations=[
            {"tool_name": "tool", "reason": "bad", "arguments": {"a": "b"}}
        ],
        get_blocked_operations_summary=lambda: {
            "total_blocked": 1,
            "tools_blocked": {"tool": 1},
            "dangerous_content_types": {"secrets": 1},
        },
    )
    reporter = SafetyReporter(safety_filter=safety_filter)
    reporter.console = DummyConsole()

    reporter.print_safety_system_summary()

    assert any("Blocked Operations Summary" in msg for msg in reporter.console.messages)


def test_print_blocked_operations_summary_disabled():
    reporter = SafetyReporter(safety_filter=None)
    reporter.console = DummyConsole()
    reporter.get_blocked_operations = lambda: []
    reporter.is_system_blocking_active = lambda: False

    reporter.print_blocked_operations_summary()

    assert any("disabled" in msg for msg in reporter.console.messages)


def test_print_blocked_operations_summary_with_ops():
    reporter = SafetyReporter(safety_filter=None)
    reporter.console = DummyConsole()
    reporter.get_blocked_operations = lambda: [
        {
            "command": "xdg-open",
            "args": "http://example.com",
            "timestamp": "2024-01-01T01:02:03.000Z",
        },
        {"command": "firefox", "args": "", "timestamp": "bad"},
        {"command": "rm", "args": "a" * 100, "timestamp": ""},
    ]
    reporter.is_system_blocking_active = lambda: True

    reporter.print_blocked_operations_summary()

    assert any(
        "Blocked System Operations Summary" in msg
        for msg in reporter.console.messages
    )


def test_print_blocked_operations_summary_handles_status_error():
    reporter = SafetyReporter(safety_filter=None)
    reporter.console = DummyConsole()
    reporter.get_blocked_operations = lambda: []

    def _raise():
        raise RuntimeError("boom")

    reporter.is_system_blocking_active = _raise

    reporter.print_blocked_operations_summary()

    assert any("No dangerous system" in msg for msg in reporter.console.messages)


def test_get_comprehensive_safety_data():
    safety_filter = SimpleNamespace(
        blocked_operations=[{"tool_name": "tool"}],
        get_blocked_operations_summary=lambda: {"total_blocked": 1},
        get_safety_statistics=lambda: {"total_operations_blocked": 1},
    )
    reporter = SafetyReporter(safety_filter=safety_filter)
    reporter.get_blocked_operations = lambda: [{"command": "rm"}]
    reporter.is_system_blocking_active = lambda: True

    data = reporter.get_comprehensive_safety_data()

    assert data["system_safety"]["total_blocked"] == 1
    assert data["safety_system"]["active"] is True


def test_get_comprehensive_safety_data_handles_errors():
    reporter = SafetyReporter(safety_filter=None)

    def _raise():
        raise RuntimeError("boom")

    reporter.get_blocked_operations = _raise

    data = reporter.get_comprehensive_safety_data()

    assert "error" in data["system_safety"]
    assert data["safety_system"]["active"] is False


def test_has_safety_data_and_export():
    safety_filter = SimpleNamespace(
        blocked_operations=[{"tool_name": "tool"}],
        export_safety_data=lambda _filename=None: "ok",
    )
    reporter = SafetyReporter(safety_filter=safety_filter)
    reporter.get_blocked_operations = lambda: []

    assert reporter.has_safety_data() is True
    assert reporter.export_safety_data() == "ok"

    reporter.safety_filter = None
    assert reporter.export_safety_data() == ""

    def _raise_export(_filename=None):
        raise RuntimeError("boom")

    reporter.safety_filter = SimpleNamespace(export_safety_data=_raise_export)
    assert reporter.export_safety_data() == ""


def test_print_comprehensive_safety_report_unknown_status():
    safety_filter = SimpleNamespace(
        get_blocked_operations_summary=lambda: {"total_blocked": 0}
    )
    reporter = SafetyReporter(safety_filter=safety_filter)
    reporter.console = DummyConsole()

    def _raise():
        raise RuntimeError("boom")

    reporter.is_system_blocking_active = _raise
    reporter.print_blocked_operations_summary = lambda: None
    reporter.print_safety_system_summary = lambda: None
    reporter.print_safety_summary = lambda: None

    reporter.print_comprehensive_safety_report()

    assert any("UNKNOWN STATUS" in msg for msg in reporter.console.messages)


def test_has_safety_data_handles_exception():
    class BadFilter:
        @property
        def blocked_operations(self):
            raise RuntimeError("boom")

    reporter = SafetyReporter(safety_filter=BadFilter())

    assert reporter.has_safety_data() is False
