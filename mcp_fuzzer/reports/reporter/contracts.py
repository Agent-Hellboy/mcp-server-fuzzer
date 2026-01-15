"""Protocol contracts for the reporter module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..core import FuzzingMetadata, ReportSnapshot


@runtime_checkable
class ReportCollectorPort(Protocol):
    """Port interface for gathering fuzzing results."""

    tool_results: dict[str, list[Any]]
    protocol_results: dict[str, list[Any]]
    safety_data: dict[str, Any]

    def add_tool_results(
        self, tool_name: str, results: list[dict[str, Any]]
    ) -> None: ...

    def add_protocol_results(
        self, protocol_type: str, results: list[dict[str, Any]]
    ) -> None: ...

    def update_safety_data(self, safety_data: dict[str, Any]) -> None: ...

    def snapshot(
        self,
        metadata: FuzzingMetadata,
        safety_data: dict[str, Any] | None,
        include_safety: bool = True,
    ) -> ReportSnapshot: ...

    def collect_errors(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class OutputManagerPort(Protocol):
    """Port interface for persisting standardized protocol outputs."""

    def save_fuzzing_snapshot(
        self, snapshot: ReportSnapshot, safety_enabled: bool = False
    ) -> str: ...

    def save_safety_summary(self, safety_data: dict[str, Any]) -> str: ...

    def save_error_report(
        self,
        errors: list[dict[str, Any]],
        warnings: list[dict[str, Any]] | None = None,
        execution_context: dict[str, Any] | None = None,
    ) -> str: ...

    def get_session_directory(self, session_id: str | None = None) -> Path: ...


@runtime_checkable
class ConsoleSummaryPort(Protocol):
    """Port used for console summary output."""

    def print_tool_summary(self, results: dict[str, Any]) -> None: ...

    def print_protocol_summary(
        self, results: dict[str, list[dict[str, Any]]]
    ) -> None: ...

    def print_overall_summary(
        self,
        tool_results: dict[str, Any],
        protocol_results: dict[str, list[dict[str, Any]]],
    ) -> None: ...


@runtime_checkable
class SafetyReporterPort(Protocol):
    """Port interface for safety system reporting."""

    def print_safety_summary(self) -> None: ...

    def print_comprehensive_safety_report(self) -> None: ...

    def print_blocked_operations_summary(self) -> None: ...

    def has_safety_data(self) -> bool: ...

    def export_safety_data(self, filename: str | None = None) -> str: ...

    def get_comprehensive_safety_data(self) -> dict[str, Any]: ...
