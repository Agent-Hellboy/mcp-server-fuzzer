#!/usr/bin/env python3
"""Standardized output protocol builder for MCP Fuzzer."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from importlib.metadata import PackageNotFoundError, version

from ...exceptions import ValidationError
from ..core import ReportSnapshot
from ..formatters.common import extract_tool_runs

try:
    TOOL_VERSION = version("mcp-fuzzer")
except PackageNotFoundError:
    TOOL_VERSION = "unknown"


def _result_has_failure(result: dict[str, Any]) -> bool:
    """Return True when a result indicates a failure."""
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )


def _rate(total: int, failures: int) -> float:
    if total <= 0:
        return 0.0
    successes = max(total - failures, 0)
    return (successes / total) * 100


class OutputProtocol:
    """Handles standardized output format with mini-protocol for MCP Fuzzer."""

    PROTOCOL_VERSION = "1.0.0"
    TOOL_VERSION = TOOL_VERSION

    OUTPUT_TYPES = {
        "fuzzing_results",
        "error_report",
        "safety_summary",
        "performance_metrics",
        "configuration_dump",
    }

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = logging.getLogger(__name__)

    def create_base_output(
        self,
        output_type: str,
        data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a standardized output structure."""
        if output_type not in self.OUTPUT_TYPES:
            raise ValidationError(f"Invalid output type: {output_type}")

        return {
            "protocol_version": self.PROTOCOL_VERSION,
            "timestamp": datetime.now().isoformat(),
            "tool_version": self.TOOL_VERSION,
            "session_id": self.session_id,
            "output_type": output_type,
            "data": data,
            "metadata": metadata or {},
        }

    def create_fuzzing_results_output(
        self,
        mode: str,
        protocol: str,
        endpoint: str,
        tool_results: dict[str, Any],
        protocol_results: dict[str, list[dict[str, Any]]],
        execution_time: str,
        total_tests: int,
        success_rate: float,
        safety_enabled: bool = False,
        spec_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create fuzzing results output."""
        data = {
            "mode": mode,
            "protocol": protocol,
            "endpoint": endpoint,
            "total_tools": len(tool_results),
            "total_protocol_types": len(protocol_results),
            "tools_tested": self._format_tool_results(tool_results),
            "protocol_types_tested": self._format_protocol_results(protocol_results),
            "spec_summary": spec_summary or {},
        }
        metadata = {
            "execution_time": execution_time,
            "total_tests": total_tests,
            "success_rate": success_rate,
            "safety_enabled": safety_enabled,
        }
        return self.create_base_output("fuzzing_results", data, metadata)

    def create_fuzzing_results_from_snapshot(
        self,
        snapshot: ReportSnapshot,
        safety_enabled: bool = False,
    ) -> dict[str, Any]:
        """Create fuzzing results output from a report snapshot."""
        tool_results = {
            name: [run.to_dict() for run in runs]
            for name, runs in snapshot.tool_results.items()
        }
        protocol_results = {
            name: [run.to_dict() for run in runs]
            for name, runs in snapshot.protocol_results.items()
        }
        return self.create_fuzzing_results_output(
            mode=snapshot.metadata.mode,
            protocol=snapshot.metadata.protocol,
            endpoint=snapshot.metadata.endpoint,
            tool_results=tool_results,
            protocol_results=protocol_results,
            execution_time=snapshot.metadata.execution_time_iso(),
            total_tests=snapshot.total_tests(),
            success_rate=snapshot.overall_success_rate(),
            safety_enabled=safety_enabled,
            spec_summary=snapshot.spec_summary,
        )

    def create_error_report_output(
        self,
        errors: list[dict[str, Any]],
        warnings: list[dict[str, Any]] | None = None,
        execution_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create error report output."""
        data = {
            "total_errors": len(errors),
            "total_warnings": len(warnings) if warnings else 0,
            "errors": errors,
            "warnings": warnings or [],
            "execution_context": execution_context or {},
        }
        metadata = {
            "error_severity": self._calculate_error_severity(errors),
            "has_critical_errors": any(e.get("severity") == "critical" for e in errors),
        }
        return self.create_base_output("error_report", data, metadata)

    def create_safety_summary_output(
        self,
        safety_data: dict[str, Any],
        blocked_operations: list[dict[str, Any]],
        risk_assessment: str,
    ) -> dict[str, Any]:
        """Create safety summary output."""
        data = {
            "safety_system_active": safety_data.get("active", False),
            "total_operations_blocked": len(blocked_operations),
            "blocked_operations": blocked_operations,
            "risk_assessment": risk_assessment,
            "safety_statistics": safety_data.get("statistics", {}),
        }
        metadata = {
            "safety_enabled": safety_data.get("active", False),
            "total_blocked": len(blocked_operations),
            "unique_tools_blocked": len(
                set(op.get("tool_name", "") for op in blocked_operations)
            ),
        }
        return self.create_base_output("safety_summary", data, metadata)

    def create_performance_metrics_output(
        self,
        metrics: dict[str, Any],
        benchmarks: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create performance metrics output."""
        data = {"metrics": metrics, "benchmarks": benchmarks or {}}
        metadata = {
            "collection_timestamp": datetime.now().isoformat(),
            "metrics_count": len(metrics),
        }
        return self.create_base_output("performance_metrics", data, metadata)

    def create_configuration_dump_output(
        self,
        configuration: dict[str, Any],
        source: str = "runtime",
    ) -> dict[str, Any]:
        """Create configuration dump output."""
        data = {"configuration": configuration, "source": source}
        metadata = {
            "config_keys_count": len(configuration),
            "dump_timestamp": datetime.now().isoformat(),
        }
        return self.create_base_output("configuration_dump", data, metadata)

    def validate_output(self, output: dict[str, Any]) -> bool:
        """Validate output structure against protocol schema."""
        try:
            required_fields = [
                "protocol_version",
                "timestamp",
                "tool_version",
                "session_id",
                "output_type",
                "data",
                "metadata",
            ]
            for field in required_fields:
                if field not in output:
                    raise ValidationError(f"Missing required field: {field}")

            if output["output_type"] not in self.OUTPUT_TYPES:
                raise ValidationError(f"Invalid output type: {output['output_type']}")

            if output["protocol_version"] != self.PROTOCOL_VERSION:
                self.logger.warning(
                    "Protocol version mismatch: %s (expected %s)",
                    output["protocol_version"],
                    self.PROTOCOL_VERSION,
                )
            return True
        except Exception as exc:  # noqa: BLE001 - log validation issues
            self.logger.error("Output validation failed: %s", exc)
            return False

    def save_output(
        self,
        output: dict[str, Any],
        output_dir: str = "output",
        filename: str | None = None,
        compress: bool = False,
    ) -> str:
        """Save output to file with proper directory structure."""
        if not self.validate_output(output):
            raise ValidationError("Cannot save invalid output")

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        session_dir = output_path / "sessions" / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{output['output_type']}.json"

        filepath = session_dir / filename
        with open(filepath, "w") as handle:
            json.dump(output, handle, indent=2, default=str)

        self.logger.info("Output saved to: %s", filepath)
        return str(filepath)

    def _format_tool_results(
        self, tool_results: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Format tool results for output."""
        formatted = []
        for tool_name, results in tool_results.items():
            runs, _ = extract_tool_runs(results)
            total_runs = len(runs)
            exceptions = sum(1 for r in runs if "exception" in r)
            safety_blocked = sum(1 for r in runs if r.get("safety_blocked", False))
            successful = max(total_runs - exceptions - safety_blocked, 0)
            success_rate = _rate(total_runs, exceptions + safety_blocked)
            formatted.append(
                {
                    "name": tool_name,
                    "runs": total_runs,
                    "successful": successful,
                    "exceptions": exceptions,
                    "safety_blocked": safety_blocked,
                    "success_rate": success_rate,
                    "exception_details": [
                        {
                            "type": (
                                type(r.get("exception")).__name__
                                if r.get("exception")
                                else "Unknown"
                            ),
                            "message": str(r.get("exception", "")),
                            "arguments": r.get("args", {}),
                        }
                        for r in runs
                        if "exception" in r
                    ],
                }
            )
        return formatted

    def _format_protocol_results(
        self, protocol_results: dict[str, list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Format protocol results for output."""
        formatted = []
        for protocol_type, results in protocol_results.items():
            total_runs = len(results)
            errors = sum(1 for r in results if _result_has_failure(r))
            successes = max(total_runs - errors, 0)
            success_rate = _rate(total_runs, errors)
            formatted.append(
                {
                    "type": protocol_type,
                    "runs": total_runs,
                    "successful": successes,
                    "errors": errors,
                    "success_rate": success_rate,
                }
            )
        return formatted

    def _calculate_error_severity(self, errors: list[dict[str, Any]]) -> str:
        """Calculate overall error severity."""
        if not errors:
            return "none"
        severities = [e.get("severity", "low") for e in errors]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"
