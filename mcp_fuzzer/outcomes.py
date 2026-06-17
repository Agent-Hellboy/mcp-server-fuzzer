"""Fuzz-run outcome classification for tools and protocol messages."""

from __future__ import annotations

from typing import Any

from .exceptions import ServerCrashError, ServerError
from .types import ErrorType, StringValueEnum


class FuzzOutcome(StringValueEnum):
    """Explicit buckets for fuzz-run results."""

    SERVER_REJECTED = "server_rejected"
    ACCEPTED_MALFORMED = "accepted_malformed"
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"
    SAFETY_BLOCKED = "safety_blocked"
    MUTATION_FAILED = "mutation_failed"
    PHASE_FAILED = "phase_failed"
    VALID_RESPONSE = "valid_response"
    # The server process terminated abnormally (signal / non-zero exit) while
    # handling the input -- the highest-signal fuzzing finding.
    CRASHED = "crashed"


# JSON-RPC codes indicating the server rejected malformed input (desired for fuzzing).
_REJECTION_CODES = frozenset({-32700, -32600, -32601, -32602, -32603})


def _jsonrpc_error_code(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        if isinstance(code, int):
            return code
    return None


def is_server_rejection_error(exc: BaseException) -> bool:
    """Return True when an exception represents a JSON-RPC rejection."""
    if isinstance(exc, ServerError):
        context = getattr(exc, "context", None) or {}
        error = context.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            return isinstance(code, int) and code in _REJECTION_CODES
        return True
    return False


def classify_tool_run(
    *,
    result: Any = None,
    exception: BaseException | None = None,
    safety_blocked: bool = False,
    timeout: bool = False,
    mutation_failed: bool = False,
) -> tuple[bool, FuzzOutcome]:
    """Classify a tool fuzz run.

    For a fuzzer, a server that rejects malformed input is a success; accepting
    malformed input without error is a potential finding.
    """
    if safety_blocked:
        return False, FuzzOutcome.SAFETY_BLOCKED
    if mutation_failed:
        return False, FuzzOutcome.MUTATION_FAILED
    if timeout:
        return False, FuzzOutcome.TIMEOUT
    if exception is not None:
        if isinstance(exception, ServerCrashError):
            return False, FuzzOutcome.CRASHED
        if is_server_rejection_error(exception):
            return True, FuzzOutcome.SERVER_REJECTED
        return False, FuzzOutcome.TRANSPORT_ERROR
    if isinstance(result, dict) and result.get("isError"):
        return True, FuzzOutcome.SERVER_REJECTED
    if result is not None:
        return False, FuzzOutcome.ACCEPTED_MALFORMED
    return False, FuzzOutcome.TRANSPORT_ERROR


def classify_protocol_run(
    *,
    server_response: Any = None,
    server_error: str | None = None,
    exception: BaseException | None = None,
    safety_blocked: bool = False,
) -> tuple[bool, FuzzOutcome]:
    """Classify a protocol fuzz run using the same fuzzer-oriented semantics."""
    if safety_blocked:
        return False, FuzzOutcome.SAFETY_BLOCKED
    if exception is not None:
        if isinstance(exception, ServerCrashError):
            return False, FuzzOutcome.CRASHED
        if is_server_rejection_error(exception):
            return True, FuzzOutcome.SERVER_REJECTED
        return False, FuzzOutcome.TRANSPORT_ERROR
    if server_error:
        return True, FuzzOutcome.SERVER_REJECTED
    if isinstance(server_response, dict):
        code = _jsonrpc_error_code(server_response)
        if code is not None:
            if code in _REJECTION_CODES:
                return True, FuzzOutcome.SERVER_REJECTED
            return False, FuzzOutcome.TRANSPORT_ERROR
        if "error" not in server_response:
            return False, FuzzOutcome.ACCEPTED_MALFORMED
        return True, FuzzOutcome.SERVER_REJECTED
    return False, FuzzOutcome.TRANSPORT_ERROR


def outcome_to_error_type(outcome: FuzzOutcome) -> ErrorType | None:
    """Map outcomes to canonical error types when the run failed fuzzer checks."""
    if outcome == FuzzOutcome.ACCEPTED_MALFORMED:
        return ErrorType.TOOL_CALL_FAILED
    if outcome == FuzzOutcome.TRANSPORT_ERROR:
        return ErrorType.TOOL_CALL_FAILED
    if outcome == FuzzOutcome.TIMEOUT:
        return ErrorType.TOOL_TIMEOUT
    if outcome == FuzzOutcome.MUTATION_FAILED:
        return ErrorType.TOOL_MUTATION_FAILED
    if outcome == FuzzOutcome.PHASE_FAILED:
        return ErrorType.PHASE_EXECUTION_FAILED
    return None
