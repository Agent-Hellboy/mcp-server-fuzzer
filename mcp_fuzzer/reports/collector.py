"""Report collection and aggregation utilities."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import (
    RunRecord,
    SummaryStats,
    ToolSummary,
    ProtocolSummary,
    ReportSnapshot,
    FuzzingMetadata,
)


class ReportCollector:
    """Collects fuzzing results and produces typed snapshots."""

    def __init__(self):
        self.tool_results: dict[str, list[RunRecord]] = {}
        self.protocol_results: dict[str, list[RunRecord]] = {}
        self.spec_checks: list[dict[str, Any]] = []
        self.safety_data: dict[str, Any] = {}
        self.runtime_data: dict[str, Any] = {}

    def add_tool_results(self, tool_name: str, results: list[dict[str, Any]]):
        bucket = self.tool_results.setdefault(tool_name, [])
        bucket.extend(self._coerce_result(r) for r in results)

    def add_protocol_results(self, protocol_type: str, results: list[dict[str, Any]]):
        bucket = self.protocol_results.setdefault(protocol_type, [])
        bucket.extend(self._coerce_result(r) for r in results)

    def add_spec_checks(self, checks: list[dict[str, Any]]):
        if not checks:
            return
        self.spec_checks.extend(deepcopy(checks))

    def update_safety_data(self, safety_data: dict[str, Any]):
        self.safety_data.update(deepcopy(safety_data))

    def update_runtime_data(self, runtime_data: dict[str, Any]):
        self.runtime_data.update(deepcopy(runtime_data))

    def build_summary(self) -> SummaryStats:
        tool_summary = ToolSummary(total_tools=len(self.tool_results))
        protocol_summary = ProtocolSummary(
            total_protocol_types=len(self.protocol_results)
        )

        for runs in self.tool_results.values():
            tool_summary.total_runs += len(runs)
            for run in runs:
                if run.has_error and not run.has_exception:
                    tool_summary.tools_with_errors += 1
                if run.has_exception:
                    tool_summary.tools_with_exceptions += 1

        for runs in self.protocol_results.values():
            protocol_summary.total_runs += len(runs)
            for run in runs:
                if run.has_exception:
                    protocol_summary.protocol_types_with_exceptions += 1
                elif (not run.payload.get("success", True)) or run.payload.get("error"):
                    protocol_summary.protocol_types_with_errors += 1

        tool_summary.success_rate = self._calculate_tool_success_rate(tool_summary)
        protocol_summary.success_rate = self._calculate_protocol_success_rate(
            protocol_summary
        )

        return SummaryStats(tools=tool_summary, protocols=protocol_summary)

    def snapshot(
        self,
        metadata: FuzzingMetadata,
        safety_data: dict[str, Any] | None = None,
        runtime_data: dict[str, Any] | None = None,
        include_safety: bool = True,
    ) -> ReportSnapshot:
        if include_safety:
            safety = deepcopy(self.safety_data)
            if safety_data:
                safety.update(deepcopy(safety_data))
        else:
            safety = {}

        runtime = deepcopy(self.runtime_data)
        if runtime_data:
            runtime.update(deepcopy(runtime_data))

        return ReportSnapshot(
            metadata=metadata,
            tool_results=deepcopy(self.tool_results),
            protocol_results=deepcopy(self.protocol_results),
            summary=self.build_summary(),
            spec_summary=self._build_spec_summary(),
            safety_data=safety,
            runtime_data=runtime,
        )

    def collect_errors(self) -> list[dict[str, Any]]:
        """Collect error details from stored runs."""
        errors: list[dict[str, Any]] = []
        for tool_name, runs in self.tool_results.items():
            for idx, run in enumerate(runs):
                if run.has_exception or run.has_error:
                    message = str(
                        run.payload.get(
                            "exception", run.payload.get("error", "Unknown tool error")
                        )
                    )
                    severity = "high" if run.has_exception else "medium"
                    errors.append(
                        {
                            "type": "tool_error",
                            "tool_name": tool_name,
                            "run_number": idx + 1,
                            "severity": severity,
                            "message": message,
                            "arguments": run.payload.get("args", {}),
                        }
                    )

        for protocol_type, runs in self.protocol_results.items():
            for idx, run in enumerate(runs):
                if run.has_error:
                    errors.append(
                        {
                            "type": "protocol_error",
                            "protocol_type": protocol_type,
                            "run_number": idx + 1,
                            "severity": "medium",
                            "message": run.payload.get(
                                "error", "Unknown protocol error"
                            ),
                            "details": run.payload,
                        }
                    )
        return errors

    def _calculate_tool_success_rate(self, summary: ToolSummary) -> float:
        failures = summary.tools_with_errors + summary.tools_with_exceptions
        return self._success_rate(summary.total_runs, failures)

    def _calculate_protocol_success_rate(self, summary: ProtocolSummary) -> float:
        failures = (
            summary.protocol_types_with_errors + summary.protocol_types_with_exceptions
        )
        return self._success_rate(summary.total_runs, failures)

    @staticmethod
    def _success_rate(total_runs: int, failures: int) -> float:
        if total_runs <= 0:
            return 0.0
        successes = max(total_runs - failures, 0)
        return (successes / total_runs) * 100

    def _coerce_result(self, result: dict[str, Any] | RunRecord) -> RunRecord:
        if isinstance(result, RunRecord):
            return result
        return RunRecord(payload=deepcopy(result))

    def _collect_spec_checks(self) -> list[dict[str, Any]]:
        checks: list[dict[str, Any]] = []
        checks.extend(deepcopy(self.spec_checks))
        for runs in self.tool_results.values():
            for run in runs:
                payload_checks = run.payload.get("spec_checks")
                if isinstance(payload_checks, list):
                    checks.extend(deepcopy(payload_checks))
        for runs in self.protocol_results.values():
            for run in runs:
                payload_checks = run.payload.get("spec_checks")
                if isinstance(payload_checks, list):
                    checks.extend(deepcopy(payload_checks))
        return checks

    def _build_spec_summary(self) -> dict[str, Any]:
        checks = self._collect_spec_checks()
        summary: dict[str, Any] = {
            "totals": {"total": 0, "failed": 0, "warned": 0, "passed": 0},
            "by_spec_id": {},
        }
        for check in checks:
            spec_id = check.get("spec_id") or "UNKNOWN"
            status = str(check.get("status", "")).upper()
            spec_bucket = summary["by_spec_id"].setdefault(
                spec_id,
                {
                    "spec_url": check.get("spec_url"),
                    "total": 0,
                    "failed": 0,
                    "warned": 0,
                    "passed": 0,
                },
            )
            spec_bucket["total"] += 1
            summary["totals"]["total"] += 1

            if status in ("FAIL", "FAILURE", "ERROR"):
                spec_bucket["failed"] += 1
                summary["totals"]["failed"] += 1
            elif status in ("WARN", "WARNING"):
                spec_bucket["warned"] += 1
                summary["totals"]["warned"] += 1
            else:
                spec_bucket["passed"] += 1
                summary["totals"]["passed"] += 1

        return summary
