"""
MCP Server Fuzzer - Core Fuzzing Engine

This package contains the core fuzzing orchestration logic including:
- Mutators (data generation and mutation)
- Executors (execution and orchestration)
- Executor results (collection, building, metrics)
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
from .executor.results import (
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
    # Executor results
    "ResultBuilder",
    "ResultCollector",
    "MetricsCalculator",
    # Runtime
    "ProcessManager",
    "ProcessWatchdog",
]
