#!/usr/bin/env python3
"""
MCP Fuzzer Output Protocol

Defines the standardized output format and mini-protocol for tool communication.
Provides schema validation and structured output generation.
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..exceptions import ValidationError


class OutputProtocol:
    """Handles standardized output format with mini-protocol for MCP Fuzzer."""

    PROTOCOL_VERSION = "1.0.0"
    TOOL_VERSION = "0.1.6"  # TODO: Get from package version

    # Output types
    OUTPUT_TYPES = {
        "fuzzing_results",
        "error_report",
        "safety_summary",
        "performance_metrics",
        "configuration_dump",
    }

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = logging.getLogger(__name__)

    def create_base_output(
        self,
        output_type: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a standardized output structure."""
        if output_type not in self.OUTPUT_TYPES:
            raise ValidationError(f"Invalid output type: {output_type}")

        base_output = {
            "protocol_version": self.PROTOCOL_VERSION,
            "timestamp": datetime.now().isoformat(),
            "tool_version": self.TOOL_VERSION,
            "session_id": self.session_id,
            "output_type": output_type,
            "data": data,
            "metadata": metadata or {},
        }

        return base_output

    def create_fuzzing_results_output(
        self,
        mode: str,
        protocol: str,
        endpoint: str,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
        execution_time: str,
        total_tests: int,
        success_rate: float,
        safety_enabled: bool = False,
    ) -> Dict[str, Any]:
        """Create fuzzing results output."""
        data = {
            "mode": mode,
            "protocol": protocol,
            "endpoint": endpoint,
            "total_tools": len(tool_results),
            "total_protocol_types": len(protocol_results),
            "tools_tested": self._format_tool_results(tool_results),
            "protocol_types_tested": self._format_protocol_results(protocol_results),
        }

        metadata = {
            "execution_time": execution_time,
            "total_tests": total_tests,
            "success_rate": success_rate,
            "safety_enabled": safety_enabled,
        }

        return self.create_base_output("fuzzing_results", data, metadata)

    def create_error_report_output(
        self,
        errors: List[Dict[str, Any]],
        warnings: List[Dict[str, Any]] = None,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
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
        safety_data: Dict[str, Any],
        blocked_operations: List[Dict[str, Any]],
        risk_assessment: str,
    ) -> Dict[str, Any]:
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
        metrics: Dict[str, Any],
        benchmarks: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create performance metrics output."""
        data = {
            "metrics": metrics,
            "benchmarks": benchmarks or {},
        }

        metadata = {
            "collection_timestamp": datetime.now().isoformat(),
            "metrics_count": len(metrics),
        }

        return self.create_base_output("performance_metrics", data, metadata)

    def create_configuration_dump_output(
        self,
        configuration: Dict[str, Any],
        source: str = "runtime",
    ) -> Dict[str, Any]:
        """Create configuration dump output."""
        data = {
            "configuration": configuration,
            "source": source,
        }

        metadata = {
            "config_keys_count": len(configuration),
            "dump_timestamp": datetime.now().isoformat(),
        }

        return self.create_base_output("configuration_dump", data, metadata)

    def validate_output(self, output: Dict[str, Any]) -> bool:
        """Validate output structure against protocol schema."""
        try:
            # Check required fields
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

            # Validate output type
            if output["output_type"] not in self.OUTPUT_TYPES:
                raise ValidationError(f"Invalid output type: {output['output_type']}")

            # Validate protocol version
            if output["protocol_version"] != self.PROTOCOL_VERSION:
                self.logger.warning(
                    f"Protocol version mismatch: {output['protocol_version']} "
                    f"(expected {self.PROTOCOL_VERSION})"
                )

            return True

        except Exception as e:
            self.logger.error(f"Output validation failed: {e}")
            return False

    def save_output(
        self,
        output: Dict[str, Any],
        output_dir: str = "output",
        filename: Optional[str] = None,
        compress: bool = False,
    ) -> str:
        """Save output to file with proper directory structure."""
        if not self.validate_output(output):
            raise ValidationError("Cannot save invalid output")

        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Create session directory
        session_dir = output_path / "sessions" / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_type = output["output_type"]
            filename = f"{timestamp}_{output_type}.json"

        filepath = session_dir / filename

        # Save output
        with open(filepath, "w") as f:
            json.dump(output, f, indent=2, default=str)

        self.logger.info(f"Output saved to: {filepath}")
        return str(filepath)

    def _format_tool_results(
        self, tool_results: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Format tool results for output."""
        formatted = []

        for tool_name, results in tool_results.items():
            total_runs = len(results)
            exceptions = sum(1 for r in results if "exception" in r)
            safety_blocked = sum(1 for r in results if r.get("safety_blocked", False))
            successful = total_runs - exceptions - safety_blocked
            success_rate = (successful / total_runs * 100) if total_runs > 0 else 0

            tool_data = {
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
                            if r.get("exception") else "Unknown"
                        ),
                        "message": str(r.get("exception", "")),
                        "arguments": r.get("args", {}),
                    }
                    for r in results
                    if "exception" in r
                ],
            }
            formatted.append(tool_data)

        return formatted

    def _format_protocol_results(
        self, protocol_results: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Format protocol results for output."""
        formatted = []

        for protocol_type, results in protocol_results.items():
            total_runs = len(results)
            errors = sum(1 for r in results if not r.get("success", True))
            success_rate = (
                ((total_runs - errors) / total_runs * 100)
                if total_runs > 0 else 0
            )

            protocol_data = {
                "type": protocol_type,
                "runs": total_runs,
                "successful": total_runs - errors,
                "errors": errors,
                "success_rate": success_rate,
            }
            formatted.append(protocol_data)

        return formatted

    def _calculate_error_severity(self, errors: List[Dict[str, Any]]) -> str:
        """Calculate overall error severity."""
        if not errors:
            return "none"

        severities = [e.get("severity", "low") for e in errors]
        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        else:
            return "low"


class OutputManager:
    """Manages output generation and file organization."""

    def __init__(self, output_dir: str = "output", compress: bool = False):
        self.output_dir = Path(output_dir)
        self.compress = compress
        self.protocol = OutputProtocol()

    def save_fuzzing_results(
        self,
        mode: str,
        protocol: str,
        endpoint: str,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
        execution_time: str,
        total_tests: int,
        success_rate: float,
        safety_enabled: bool = False,
    ) -> str:
        """Save fuzzing results using standardized format."""
        output = self.protocol.create_fuzzing_results_output(
            mode=mode,
            protocol=protocol,
            endpoint=endpoint,
            tool_results=tool_results,
            protocol_results=protocol_results,
            execution_time=execution_time,
            total_tests=total_tests,
            success_rate=success_rate,
            safety_enabled=safety_enabled,
        )

        return self.protocol.save_output(
            output, self.output_dir, compress=self.compress
        )

    def save_error_report(
        self,
        errors: List[Dict[str, Any]],
        warnings: Optional[List[Dict[str, Any]]] = None,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save error report using standardized format."""
        output = self.protocol.create_error_report_output(
            errors=errors,
            warnings=warnings,
            execution_context=execution_context,
        )

        return self.protocol.save_output(
            output, self.output_dir, compress=self.compress
        )

    def save_safety_summary(self, safety_data: Dict[str, Any]) -> str:
        """Save safety summary using standardized format."""
        blocked_operations = safety_data.get("blocked_operations", [])
        risk_assessment = safety_data.get("risk_assessment", "unknown")

        output = self.protocol.create_safety_summary_output(
            safety_data=safety_data,
            blocked_operations=blocked_operations,
            risk_assessment=risk_assessment,
        )

        return self.protocol.save_output(
            output, self.output_dir, compress=self.compress
        )

    def get_session_directory(self, session_id: Optional[str] = None) -> Path:
        """Get the session directory path."""
        session_id = session_id or self.protocol.session_id
        return self.output_dir / "sessions" / session_id

    def list_session_outputs(self, session_id: Optional[str] = None) -> List[Path]:
        """List all output files for a session."""
        session_dir = self.get_session_directory(session_id)
        if not session_dir.exists():
            return []

        return list(session_dir.glob("*.json"))