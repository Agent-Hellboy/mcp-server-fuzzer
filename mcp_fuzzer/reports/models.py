"""Dataclasses for the reports module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class RunRecord:
    """Typed wrapper around a single fuzzing run payload."""

    payload: dict[str, Any]

    @property
    def has_exception(self) -> bool:
        return "exception" in self.payload

    @property
    def has_error(self) -> bool:
        if self.has_exception:
            return True
        if not self.payload.get("success", True):
            return True
        return bool(self.payload.get("error"))

    @property
    def safety_blocked(self) -> bool:
        return bool(self.payload.get("safety_blocked", False))

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass
class ToolSummary:
    total_tools: int = 0
    total_runs: int = 0
    tools_with_errors: int = 0
    tools_with_exceptions: int = 0
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tools": self.total_tools,
            "total_runs": self.total_runs,
            "tools_with_errors": self.tools_with_errors,
            "tools_with_exceptions": self.tools_with_exceptions,
            "success_rate": self.success_rate,
        }


@dataclass
class ProtocolSummary:
    total_protocol_types: int = 0
    total_runs: int = 0
    protocol_types_with_errors: int = 0
    protocol_types_with_exceptions: int = 0
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_protocol_types": self.total_protocol_types,
            "total_runs": self.total_runs,
            "protocol_types_with_errors": self.protocol_types_with_errors,
            "protocol_types_with_exceptions": self.protocol_types_with_exceptions,
            "success_rate": self.success_rate,
        }


@dataclass
class SummaryStats:
    tools: ToolSummary = field(default_factory=ToolSummary)
    protocols: ProtocolSummary = field(default_factory=ProtocolSummary)

    def to_dict(self) -> dict[str, Any]:
        return {"tools": self.tools.to_dict(), "protocols": self.protocols.to_dict()}


@dataclass
class FuzzingMetadata:
    """Metadata describing a fuzzing session."""

    session_id: str
    mode: str
    protocol: str
    endpoint: str
    runs: int
    runs_per_type: int | None
    fuzzer_version: str
    start_time: datetime
    end_time: datetime | None = None

    def close(self) -> "FuzzingMetadata":
        """Return a copy with end_time set to now."""
        if self.end_time:
            return self
        return FuzzingMetadata(
            session_id=self.session_id,
            mode=self.mode,
            protocol=self.protocol,
            endpoint=self.endpoint,
            runs=self.runs,
            runs_per_type=self.runs_per_type,
            fuzzer_version=self.fuzzer_version,
            start_time=self.start_time,
            end_time=datetime.now(),
        )

    def execution_time_iso(self) -> str:
        """Return ISO8601 duration string."""
        if not self.end_time:
            return "PT0S"
        duration = self.end_time - self.start_time
        seconds = max(duration.total_seconds(), 0)
        return f"PT{seconds}S"

    def to_dict(self) -> dict[str, Any]:
        data = {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "mode": self.mode,
            "protocol": self.protocol,
            "endpoint": self.endpoint,
            "runs": self.runs,
            "runs_per_type": self.runs_per_type,
            "fuzzer_version": self.fuzzer_version,
        }
        if self.end_time:
            data["end_time"] = self.end_time.isoformat()
        return data


@dataclass
class ReportSnapshot:
    """Snapshot of the current report state."""

    metadata: FuzzingMetadata
    tool_results: dict[str, list[RunRecord]]
    protocol_results: dict[str, list[RunRecord]]
    summary: SummaryStats
    spec_summary: dict[str, Any] = field(default_factory=dict)
    safety_data: dict[str, Any] = field(default_factory=dict)
    runtime_data: dict[str, Any] = field(default_factory=dict)

    def total_tests(self) -> int:
        tool_tests = sum(len(results) for results in self.tool_results.values())
        protocol_tests = sum(len(results) for results in self.protocol_results.values())
        return tool_tests + protocol_tests

    def overall_success_rate(self) -> float:
        total_tests = self.total_tests()
        if total_tests == 0:
            return 0.0

        successful = 0
        for runs in list(self.tool_results.values()) + list(
            self.protocol_results.values()
        ):
            for run in runs:
                if (not run.has_error) and (not run.safety_blocked):
                    successful += 1

        return (successful / total_tests) * 100

    def to_dict(self) -> dict[str, Any]:
        """Return serializable representation."""
        tool_dict = {
            name: [run.to_dict() for run in runs]
            for name, runs in self.tool_results.items()
        }
        protocol_dict = {
            name: [run.to_dict() for run in runs]
            for name, runs in self.protocol_results.items()
        }

        return {
            "metadata": self.metadata.to_dict(),
            "tool_results": tool_dict,
            "protocol_results": protocol_dict,
            "summary": self.summary.to_dict(),
            "spec_summary": self.spec_summary,
            "safety": self.safety_data,
            "runtime": self.runtime_data,
        }
