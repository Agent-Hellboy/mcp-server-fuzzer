"""Console and file reporting for fuzz sessions (SRP split from MCPFuzzerClient)."""

from __future__ import annotations

from typing import Any

from .reporter import FuzzerReporter
from ..safety_system.safety import CombinedSafetyProvider


class FuzzReportPresenter:
    """Presents fuzz results via the shared ``FuzzerReporter``."""

    def __init__(
        self,
        reporter: FuzzerReporter,
        *,
        safety_system: CombinedSafetyProvider | None = None,
        safety_system_getter: Any | None = None,
    ) -> None:
        self._reporter = reporter
        self._safety_system = safety_system
        self._safety_system_getter = safety_system_getter

    def _active_safety_system(self) -> CombinedSafetyProvider | None:
        if self._safety_system_getter is not None:
            return self._safety_system_getter()
        return self._safety_system

    @property
    def reporter(self) -> FuzzerReporter:
        return self._reporter

    def print_tool_summary(self, results: Any) -> None:
        self._reporter.print_tool_summary(results)

    def print_tool_execution_summary(self, results: Any) -> None:
        self._reporter.print_tool_execution_summary(results)

    def print_protocol_summary(self, results: Any, title: str | None = None) -> None:
        if title is None:
            self._reporter.print_protocol_summary(results)
        else:
            self._reporter.print_protocol_summary(results, title=title)

    def print_safety_statistics(self) -> None:
        self._reporter.print_safety_summary()

    def print_safety_system_summary(self) -> None:
        self._reporter.print_safety_system_summary()

    def print_blocked_operations_summary(self) -> None:
        safety_system = self._active_safety_system()
        if safety_system and hasattr(safety_system, "get_statistics"):
            safety_system.get_statistics()
        self._reporter.print_blocked_operations_summary()

    def print_overall_summary(self, tool_results: Any, protocol_results: Any) -> None:
        self._reporter.print_overall_summary(tool_results, protocol_results)

    def print_comprehensive_safety_report(self) -> None:
        safety_system = self._active_safety_system()
        if safety_system:
            if hasattr(safety_system, "get_statistics"):
                safety_system.get_statistics()
            if hasattr(safety_system, "get_blocked_examples"):
                safety_system.get_blocked_examples()
        self._reporter.print_comprehensive_safety_report()

    async def generate_standardized_reports(
        self, output_types=None, include_safety=True
    ):
        return await self._reporter.generate_standardized_report(
            output_types=output_types, include_safety=include_safety
        )

    async def export_requested_formats(
        self, export_targets: dict[str, str], *, include_safety: bool = False
    ) -> dict[str, str]:
        return await self._reporter.export_requested_formats(
            export_targets, include_safety=include_safety
        )

    async def generate_final_report(self, include_safety=True):
        return await self._reporter.generate_final_report(include_safety=include_safety)
