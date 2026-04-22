#!/usr/bin/env python3
"""Common typed contracts shared across the MCP Fuzzer codebase."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, NamedTuple, Protocol, TypedDict, runtime_checkable

# JSON container types
JSONContainer = dict[str, Any] | list[Any]
SpecCheck = dict[str, Any]


class StringValueEnum(str, Enum):
    """Enum that preserves its raw string value in logs and JSON output."""

    def __str__(self) -> str:
        return str(self.value)


class ErrorType(StringValueEnum):
    """Canonical error identifiers used in tool fuzzing result payloads."""

    PHASE_EXECUTION_FAILED = "phase_execution_failed"
    SAFETY_BLOCKED = "safety_blocked"
    TOOL_CALL_FAILED = "tool_call_failed"
    TOOL_MUTATION_FAILED = "tool_mutation_failed"
    TOOL_TIMEOUT = "tool_timeout"


class TimeoutScope(StringValueEnum):
    """Scope of a timeout reported in a tool run."""

    CALL = "call"
    SESSION = "session"


@runtime_checkable
class AuthManagerProtocol(Protocol):
    """Minimal auth-manager behavior required by runtime clients."""

    def get_auth_headers_for_tool(self, tool_name: str) -> dict[str, str]: ...
    def get_auth_params_for_tool(self, tool_name: str) -> dict[str, Any]: ...
    def get_default_auth_headers(self) -> dict[str, str]: ...


@dataclass(frozen=True)
class ProtocolSpec:
    """Declarative protocol dispatch metadata."""

    handler_name: str
    method: str
    is_notification: bool


class ExtractedToolRuns(NamedTuple):
    """Structured tool-run extraction result that still supports unpacking."""

    runs: list["ToolRunResult"]
    metadata: Mapping[str, Any] | None


class FuzzDataResult(TypedDict, total=False):
    """TypedDict for fuzzing results data structure."""

    fuzz_data: dict[str, Any]
    success: bool
    # Absent when no response was captured; None when explicitly captured as null
    server_response: JSONContainer | None
    server_error: str | None
    server_rejected_input: bool
    spec_checks: list[dict[str, Any]]
    spec_scope: str
    run: int
    protocol_type: str
    exception: str | None
    invariant_violations: list[str]


class ProtocolFuzzResult(TypedDict, total=False):
    """TypedDict for protocol fuzzing results."""

    fuzz_data: dict[str, Any]
    result: dict[str, Any]
    spec_checks: list[SpecCheck]
    spec_scope: str
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: str | None
    traceback: str | None


class ToolRunResult(TypedDict, total=False):
    """TypedDict for a single tool run result."""

    args: dict[str, Any] | None
    label: str
    result: JSONContainer | None
    spec_checks: list[SpecCheck]
    spec_scope: str
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: str | None
    traceback: str | None
    error: ErrorType | str | None
    timeout_scope: TimeoutScope | str | None


ToolFuzzResult = ToolRunResult


class BatchExecutionResult(TypedDict):
    """TypedDict for batch execution results."""

    results: list[dict[str, Any]]
    errors: list[Exception]
    execution_time: float
    completed: int
    failed: int


class SafetyCheckResult(TypedDict):
    """TypedDict for safety check results."""

    blocked: bool
    sanitized: bool
    blocking_reason: str | None
    data: Any


class TransportStats(TypedDict, total=False):
    """TypedDict for transport statistics."""

    requests_sent: int
    successful_responses: int
    error_responses: int
    timeouts: int
    network_errors: int
    average_response_time: float
    last_activity: float
    process_id: int | None
    active: bool


# Constants for timeouts and other magic numbers
DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_CONCURRENCY = 5
PREVIEW_LENGTH = 200  # characters for data previews
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds
BUFFER_SIZE = 4096  # bytes

# Standard HTTP status codes with semantic names
HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_REDIRECT_TEMPORARY = 307
HTTP_REDIRECT_PERMANENT = 308
HTTP_NOT_FOUND = 404
