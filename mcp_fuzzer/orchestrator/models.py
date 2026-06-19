"""Session context and result models for orchestrator-driven runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..client.fuzzer_client import MCPFuzzerClient
from .pipeline import ClientExecutionPipeline
from ..reports import FuzzerReporter


@dataclass
class SessionContext:
    """Execution context shared across run-plan commands."""

    client: MCPFuzzerClient
    config: dict[str, Any]
    reporter: FuzzerReporter | None
    protocol_phase: str
    pipeline: ClientExecutionPipeline | None = None
    tool_results: dict[str, Any] = field(default_factory=dict)
    protocol_results: dict[str, Any] = field(default_factory=dict)

    def ensure_pipeline(self) -> ClientExecutionPipeline:
        if self.pipeline is None:
            self.pipeline = ClientExecutionPipeline(self.client, self.config)
        return self.pipeline


@dataclass
class SessionResult:
    """Aggregated output from a completed fuzz session."""

    tool_results: Any
    protocol_results: Any
    findings: list[Any]
    findings_summary: dict[str, int]
    tool_discovery: Any | None = None


__all__ = ["SessionContext", "SessionResult"]
