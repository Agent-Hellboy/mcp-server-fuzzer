#!/usr/bin/env python3
"""Credentials must never reach an exported report artifact.

Each test plants a secret in the data a real run would collect, drives one
export path, and asserts the written file does not contain it while still
identifying the target and keeping the report structure intact.
"""

import json
from datetime import datetime

import pytest

from mcp_fuzzer.redaction import REDACTED
from mcp_fuzzer.reports.crash_repro import write_crash_repros, write_findings_report
from mcp_fuzzer.reports.formatters import (
    CSVFormatter,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    TextFormatter,
    XMLFormatter,
)
from mcp_fuzzer.reports.models import (
    FuzzingMetadata,
    ReportSnapshot,
    RunRecord,
    SummaryStats,
)
from mcp_fuzzer.reports.output_protocol import OutputProtocol
from mcp_fuzzer.reports.safety_reporter import SafetyReporter

SECRET = "hunter2-do-not-export"
SECRET_URL = f"https://svc:{SECRET}@target.example/mcp?access_token={SECRET}"


def build_snapshot() -> ReportSnapshot:
    """A snapshot shaped like a real run, with secrets planted throughout."""
    run = RunRecord(
        {
            "args": {"query": "safe", "api_key": SECRET},
            "result": {"headers": {"Authorization": f"Bearer {SECRET}"}},
            "success": True,
            "timestamp": "2024-01-01T00:00:00",
        }
    )
    protocol_run = RunRecord(
        {
            "fuzz_data": {"params": {"session_token": SECRET}},
            "success": True,
        }
    )
    metadata = FuzzingMetadata(
        session_id="s1",
        mode="tools",
        protocol="http",
        endpoint=SECRET_URL,
        runs=1,
        runs_per_type=None,
        fuzzer_version="1.0.0",
        start_time=datetime(2024, 1, 1),
        end_time=datetime(2024, 1, 1),
    )
    return ReportSnapshot(
        metadata=metadata,
        tool_results={"echo": [run]},
        protocol_results={"InitializeRequest": [protocol_run]},
        summary=SummaryStats(),
    )


def assert_target_still_identified(text: str) -> None:
    assert SECRET not in text
    assert "target.example" in text


class TestFileFormatters:
    """All six file exporters run through the same redaction pass."""

    def test_json_export_redacts_endpoint_and_run_payloads(self, tmp_path):
        path = tmp_path / "report.json"
        JSONFormatter().save_report(build_snapshot(), str(path))

        text = path.read_text()
        assert_target_still_identified(text)

        data = json.loads(text)
        assert data["metadata"]["endpoint"] == (
            f"https://target.example/mcp?access_token={REDACTED}"
        )
        run = data["tool_results"]["echo"][0]
        assert run["args"] == {"query": "safe", "api_key": REDACTED}
        assert run["result"]["headers"]["Authorization"] == REDACTED
        # Structure and non-sensitive values are untouched.
        assert run["success"] is True
        assert run["timestamp"] == "2024-01-01T00:00:00"
        assert data["metadata"]["mode"] == "tools"
        protocol_run = data["protocol_results"]["InitializeRequest"][0]
        assert protocol_run["fuzz_data"]["params"]["session_token"] == REDACTED

    def test_xml_export_redacts_endpoint_and_run_payloads(self, tmp_path):
        path = tmp_path / "report.xml"
        XMLFormatter().save_xml_report(build_snapshot(), str(path))

        text = path.read_text()
        assert_target_still_identified(text)
        assert 'name="endpoint"' in text
        assert REDACTED in text

    def test_csv_export_redacts_the_arguments_column(self, tmp_path):
        path = tmp_path / "report.csv"
        CSVFormatter().save_csv_report(build_snapshot(), str(path))

        text = path.read_text()
        assert SECRET not in text
        assert "echo" in text
        assert REDACTED in text

    @pytest.mark.parametrize(
        "formatter_cls,method,extension",
        [
            (HTMLFormatter, "save_html_report", "html"),
            (MarkdownFormatter, "save_markdown_report", "md"),
            (TextFormatter, "save_text_report", "txt"),
        ],
    )
    def test_rendered_exports_redact_the_endpoint(
        self, tmp_path, formatter_cls, method, extension
    ):
        path = tmp_path / f"report.{extension}"
        getattr(formatter_cls(), method)(build_snapshot(), str(path))

        assert_target_still_identified(path.read_text())

    def test_json_export_redacts_safety_blocked_operations(self, tmp_path):
        snapshot = build_snapshot()
        snapshot.safety_data = {
            "safety_system": {
                "active": True,
                "summary": {"tools_blocked": {"get_token": 3}},
                "blocked_operations": [
                    {"tool_name": "get_token", "arguments": {"secret": SECRET}}
                ],
            }
        }
        path = tmp_path / "report.json"
        JSONFormatter().save_report(snapshot, str(path))

        text = path.read_text()
        assert SECRET not in text

        safety = json.loads(text)["safety"]["safety_system"]
        assert safety["blocked_operations"][0]["arguments"] == {"secret": REDACTED}
        assert safety["blocked_operations"][0]["tool_name"] == "get_token"
        # A tool name that looks like a credential key is still a container
        # key, so its summary counter must survive untouched.
        assert safety["summary"]["tools_blocked"] == {"get_token": 3}

    def test_clean_report_is_not_altered(self, tmp_path):
        snapshot = build_snapshot()
        clean_metadata = FuzzingMetadata(
            session_id="s1",
            mode="tools",
            protocol="http",
            endpoint="https://target.example/mcp",
            runs=1,
            runs_per_type=None,
            fuzzer_version="1.0.0",
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 1),
        )
        clean = ReportSnapshot(
            metadata=clean_metadata,
            tool_results={"echo": [RunRecord({"args": {"q": "x"}, "success": True})]},
            protocol_results={},
            summary=snapshot.summary,
        )
        path = tmp_path / "clean.json"
        JSONFormatter().save_report(clean, str(path))

        assert json.loads(path.read_text()) == clean.to_dict()
        assert REDACTED not in path.read_text()


class TestMetadataModel:
    def test_metadata_to_dict_redacts_the_endpoint(self):
        data = build_snapshot().metadata.to_dict()
        assert SECRET not in json.dumps(data)
        assert data["endpoint"].startswith("https://target.example/mcp")

    def test_metadata_keeps_a_clean_endpoint_verbatim(self):
        metadata = FuzzingMetadata(
            session_id="s1",
            mode="tools",
            protocol="stdio",
            endpoint="python examples/test_server.py",
            runs=1,
            runs_per_type=None,
            fuzzer_version="1.0.0",
            start_time=datetime(2024, 1, 1),
        )
        assert metadata.to_dict()["endpoint"] == "python examples/test_server.py"


class TestOutputProtocol:
    def test_fuzzing_results_output_redacts_endpoint_and_arguments(self, tmp_path):
        snapshot = build_snapshot()
        snapshot.tool_results["echo"][0].payload["exception"] = "boom"
        protocol = OutputProtocol(session_id="s1")
        output = protocol.create_fuzzing_results_from_snapshot(snapshot)
        path = protocol.save_output(output, str(tmp_path), "fuzzing.json")

        text = open(path).read()
        assert_target_still_identified(text)

        data = json.loads(text)["data"]
        assert data["endpoint"] == (
            f"https://target.example/mcp?access_token={REDACTED}"
        )
        details = data["tools_tested"][0]["exception_details"][0]
        assert details["arguments"] == {"query": "safe", "api_key": REDACTED}

    def test_error_report_output_redacts_error_arguments(self, tmp_path):
        protocol = OutputProtocol(session_id="s1")
        output = protocol.create_error_report_output(
            errors=[
                {
                    "type": "tool_error",
                    "tool_name": "echo",
                    "severity": "high",
                    "message": "boom",
                    "arguments": {"api_key": SECRET},
                }
            ],
            execution_context={"endpoint": SECRET_URL},
        )
        path = protocol.save_output(output, str(tmp_path), "errors.json")

        text = open(path).read()
        assert_target_still_identified(text)

        data = json.loads(text)["data"]
        assert data["errors"][0]["arguments"] == {"api_key": REDACTED}
        assert data["errors"][0]["tool_name"] == "echo"
        assert data["total_errors"] == 1

    def test_safety_summary_output_redacts_blocked_arguments(self, tmp_path):
        protocol = OutputProtocol(session_id="s1")
        output = protocol.create_safety_summary_output(
            safety_data={"active": True},
            blocked_operations=[
                {
                    "tool_name": "open_url",
                    "reason": "dangerous",
                    "arguments": {"authorization": SECRET},
                }
            ],
            risk_assessment="high",
        )
        path = protocol.save_output(output, str(tmp_path), "safety.json")

        text = open(path).read()
        assert SECRET not in text

        data = json.loads(text)["data"]
        assert data["blocked_operations"][0]["arguments"] == {
            "authorization": REDACTED
        }
        assert data["blocked_operations"][0]["tool_name"] == "open_url"
        assert data["total_operations_blocked"] == 1


class TestSafetyReporter:
    def test_comprehensive_safety_data_redacts_blocked_operations(self):
        class FakeFilter:
            blocked_operations = [
                {
                    "tool_name": "open_url",
                    "reason": "dangerous",
                    "arguments": {"api_key": SECRET, "url": "http://x/y"},
                }
            ]

            def get_blocked_operations_summary(self):
                return {"total_blocked": 1, "tools_blocked": {"open_url": 1}}

            def get_safety_statistics(self):
                return {"total_operations_blocked": 1}

        reporter = SafetyReporter(safety_filter=FakeFilter())
        # NOTE: a system op's ``args`` is an opaque command-line string, so a
        # secret spliced into it cannot be found by key. Only keyed fields are
        # redacted here.
        reporter.get_blocked_operations = lambda: [
            {"command": "curl", "args": "http://host/x", "password": SECRET}
        ]
        reporter.is_system_blocking_active = lambda: True

        data = reporter.get_comprehensive_safety_data()
        assert SECRET not in json.dumps(data)

        blocked = data["safety_system"]["blocked_operations"][0]
        assert blocked["arguments"]["api_key"] == REDACTED
        assert blocked["arguments"]["url"] == "http://x/y"
        assert blocked["tool_name"] == "open_url"
        assert data["system_safety"]["total_blocked"] == 1


class TestCrashArtifacts:
    def test_crash_repro_redacts_injected_credentials(self, tmp_path):
        tool_results = {
            "echo": [
                {
                    "outcome": "crashed",
                    "args": {"payload": "AAAA", "api_key": SECRET},
                    "crash": {"exit_code": -11},
                }
            ]
        }
        written = write_crash_repros(str(tmp_path), tool_results, None)
        assert written

        record = json.loads(written[0].read_text())
        assert SECRET not in written[0].read_text()
        # The reproducible part of the input survives.
        assert record["input"]["payload"] == "AAAA"
        assert record["input"]["api_key"] == REDACTED
        assert record["crash"] == {"exit_code": -11}

    def test_findings_report_redacts_evidence(self, tmp_path):
        findings = [
            {
                "category": "token_passthrough",
                "severity": "high",
                "target": "echo",
                "evidence": {
                    "endpoint": SECRET_URL,
                    "authorization": f"Bearer {SECRET}",
                    "detail": "kept",
                },
            }
        ]
        path = write_findings_report(str(tmp_path), findings)
        assert path is not None

        text = path.read_text()
        assert_target_still_identified(text)

        doc = json.loads(text)
        evidence = doc["findings"][0]["evidence"]
        assert evidence["authorization"] == REDACTED
        assert evidence["detail"] == "kept"
        assert doc["findings"][0]["category"] == "token_passthrough"
        assert doc["count"] == 1
