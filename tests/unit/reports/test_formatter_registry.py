from datetime import datetime

import pytest

from mcp_fuzzer.reports.core.models import (
    FuzzingMetadata,
    ReportSnapshot,
    SummaryStats,
)
from mcp_fuzzer.reports.formatters.registry import (
    ReportSaveAdapter,
    FormatterRegistry,
)

pytestmark = [pytest.mark.unit]


def _snapshot() -> ReportSnapshot:
    metadata = FuzzingMetadata(
        session_id="session",
        mode="tools",
        protocol="http",
        endpoint="http://localhost",
        runs=1,
        runs_per_type=None,
        fuzzer_version="test",
        start_time=datetime.now(),
    )
    return ReportSnapshot(
        metadata=metadata,
        tool_results={},
        protocol_results={},
        summary=SummaryStats(),
    )


def test_formatter_registry_saves(tmp_path):
    saved = []

    def save_fn(report, filename):
        saved.append(filename)
        with open(filename, "w") as handle:
            handle.write("ok")

    registry = FormatterRegistry()
    registry.register("txt", ReportSaveAdapter(save_fn, "txt"))
    snapshot = _snapshot()
    path = registry.save("txt", snapshot, tmp_path)
    assert path.endswith(".txt")
    assert saved


def test_formatter_registry_unknown_name(tmp_path):
    registry = FormatterRegistry()
    snapshot = _snapshot()
    with pytest.raises(KeyError) as excinfo:
        registry.save("missing", snapshot, tmp_path)
    assert "Unknown formatter" in str(excinfo.value)


def test_formatter_adapter_save_with_filename(tmp_path):
    saved = []

    def save_fn(report, filename):
        saved.append(filename)
        with open(filename, "w") as handle:
            handle.write("ok")

    adapter = ReportSaveAdapter(save_fn, "json")
    snapshot = _snapshot()
    path = adapter.save(snapshot, tmp_path, filename="custom.out")
    assert path.endswith("custom.out")
    assert saved == [path]


def test_formatter_adapter_save_with_absolute_filename(tmp_path):
    saved = []
    absolute = tmp_path / "explicit.txt"

    def save_fn(report, filename):
        saved.append(filename)
        with open(filename, "w") as handle:
            handle.write("ok")

    adapter = ReportSaveAdapter(save_fn, "txt")
    snapshot = _snapshot()
    path = adapter.save(snapshot, tmp_path, filename=str(absolute))
    assert path == str(absolute)
    assert saved == [str(absolute)]


def test_html_formatter_adapter_save_uses_title(tmp_path):
    saved = []

    def save_fn(report, filename, title):
        saved.append((filename, title))
        with open(filename, "w") as handle:
            handle.write(title)

    adapter = ReportSaveAdapter(save_fn, "html", title="Custom Title")
    snapshot = _snapshot()
    path = adapter.save(snapshot, tmp_path)
    assert path.endswith("report.html")
    assert saved and saved[0][1] == "Custom Title"
