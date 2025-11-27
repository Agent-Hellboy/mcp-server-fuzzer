"""
MCP Server Fuzzer - Core Fuzzing Engine

This package contains the core fuzzing orchestration logic including:
- Mutators (data generation and mutation)
- Executors (execution and orchestration)
- FuzzerReporter (result collection and reporting)
- Runtime execution management (process lifecycle, monitoring, safety)
"""

from .mutators import (
    ToolMutator,
    ProtocolMutator,
    BatchMutator,
    ProtocolStrategies,
    ToolStrategies,
)
from .executor import (
    AsyncFuzzExecutor,
    ToolExecutor,
    ProtocolExecutor,
    BatchExecutor,
    InvariantViolation,
)
from .fuzzerreporter import (
    ResultBuilder,
    ResultCollector,
    MetricsCalculator,
)
from .runtime import ProcessManager, ProcessWatchdog

__all__ = [
    # Mutators
    "ToolMutator",
    "ProtocolMutator",
    "BatchMutator",
    "ProtocolStrategies",
    "ToolStrategies",
    # Executors
    "AsyncFuzzExecutor",
    "ToolExecutor",
    "ProtocolExecutor",
    "BatchExecutor",
    "InvariantViolation",
    # FuzzerReporter
    "ResultBuilder",
    "ResultCollector",
    "MetricsCalculator",
    # Runtime
    "ProcessManager",
    "ProcessWatchdog",
]
