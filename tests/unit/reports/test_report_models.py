from datetime import datetime

from mcp_fuzzer.reports.core.models import (
    FuzzingMetadata,
    ReportSnapshot,
    RunRecord,
    SummaryStats,
)


def test_run_record_flags_and_dict():
    record = RunRecord({"success": True})
    assert record.has_exception is False
    assert record.has_error is False
    assert record.safety_blocked is False
    assert record.to_dict() == {"success": True}

    record = RunRecord({"exception": "boom"})
    assert record.has_exception is True
    assert record.has_error is True

    record = RunRecord({"success": False})
    assert record.has_error is True

    record = RunRecord({"error": "bad"})
    assert record.has_error is True

    record = RunRecord({"safety_blocked": True})
    assert record.safety_blocked is True


def test_fuzzing_metadata_close_and_duration():
    start = datetime(2024, 1, 1, 0, 0, 0)
    end = datetime(2024, 1, 1, 0, 0, 0)

    meta = FuzzingMetadata(
        session_id="s1",
        mode="tools",
        protocol="stdio",
        endpoint="endpoint",
        runs=1,
        runs_per_type=None,
        fuzzer_version="1.0.0",
        start_time=start,
        end_time=end,
    )
    assert meta.execution_time_iso() == "PT0.0S"
    assert meta.close() is meta

    meta_open = FuzzingMetadata(
        session_id="s2",
        mode="protocol",
        protocol="http",
        endpoint="endpoint",
        runs=1,
        runs_per_type=1,
        fuzzer_version="1.0.0",
        start_time=start,
    )
    assert meta_open.execution_time_iso() == "PT0S"
    closed = meta_open.close()
    assert closed.end_time is not None


def test_report_snapshot_rates_and_access():
    start = datetime(2024, 1, 1, 0, 0, 0)
    meta = FuzzingMetadata(
        session_id="s1",
        mode="tools",
        protocol="stdio",
        endpoint="endpoint",
        runs=1,
        runs_per_type=None,
        fuzzer_version="1.0.0",
        start_time=start,
        end_time=start,
    )
    tool_results = {
        "tool": [
            RunRecord({"success": True}),
            RunRecord({"safety_blocked": True}),
        ]
    }
    protocol_results = {
        "proto": [
            RunRecord({"success": True}),
            RunRecord({"error": "bad"}),
        ]
    }
    snapshot = ReportSnapshot(
        metadata=meta,
        tool_results=tool_results,
        protocol_results=protocol_results,
        summary=SummaryStats(),
    )

    assert snapshot.total_tests() == 4
    assert snapshot.overall_success_rate() == 50.0
    data = snapshot.to_dict()
    assert "metadata" in data
    assert data["metadata"]["mode"] == "tools"


def test_report_snapshot_no_tests_returns_zero():
    start = datetime(2024, 1, 1, 0, 0, 0)
    meta = FuzzingMetadata(
        session_id="s0",
        mode="tools",
        protocol="stdio",
        endpoint="endpoint",
        runs=0,
        runs_per_type=None,
        fuzzer_version="1.0.0",
        start_time=start,
        end_time=start,
    )
    snapshot = ReportSnapshot(
        metadata=meta,
        tool_results={},
        protocol_results={},
        summary=SummaryStats(),
    )

    assert snapshot.overall_success_rate() == 0.0
