"""Tool run result shaping for ToolClient."""

from __future__ import annotations

from typing import Any

from .outcomes import FuzzOutcome
from ..types import ErrorType, TimeoutScope, ToolRunResult


def build_tool_run_result(
    *,
    args: dict[str, Any] | None,
    label: str | None,
    success: bool,
    safety_blocked: bool,
    safety_sanitized: bool,
    result: Any = None,
    error: ErrorType | None = None,
    exception: str | None = None,
    timeout_scope: TimeoutScope | None = None,
    spec_checks: list[dict[str, Any]] | None = None,
    spec_scope: str | None = None,
    outcome: FuzzOutcome | str | None = None,
    accepted_malformed: bool = False,
    crash: dict[str, Any] | None = None,
) -> ToolRunResult:
    payload: ToolRunResult = {
        "args": args,
        "success": success,
        "safety_blocked": safety_blocked,
        "safety_sanitized": safety_sanitized,
    }
    if label is not None:
        payload["label"] = label
    if result is not None:
        payload["result"] = result
    if error is not None:
        payload["error"] = error
    if exception is not None:
        payload["exception"] = exception
    if timeout_scope is not None:
        payload["timeout_scope"] = timeout_scope
    if spec_checks:
        payload["spec_checks"] = spec_checks
    if spec_scope is not None:
        payload["spec_scope"] = spec_scope
    if outcome is not None:
        payload["outcome"] = str(outcome)
    if accepted_malformed:
        payload["accepted_malformed"] = True
    if crash:
        payload["crash"] = crash
    return payload


def build_phase_error(tool_name: str, message: str) -> dict[str, Any]:
    return {
        "runs": [
            build_tool_run_result(
                args=None,
                label=f"tool:{tool_name}",
                success=False,
                safety_blocked=False,
                safety_sanitized=False,
                error=ErrorType.PHASE_EXECUTION_FAILED,
                exception=message,
                outcome=FuzzOutcome.PHASE_FAILED,
            )
        ],
        "error": message,
    }


def tool_timeout_message(tool_timeout: float | None) -> str:
    if tool_timeout is None:
        return "Tool execution timed out"
    return f"Tool execution timed out after {tool_timeout}s"


def response_shape_signature(response: Any) -> str | None:
    if response is None:
        return None
    if isinstance(response, dict):
        keys = ",".join(sorted(response.keys()))
        content = response.get("content")
        if isinstance(content, list):
            types = sorted(
                {
                    item.get("type")
                    for item in content
                    if isinstance(item, dict) and isinstance(item.get("type"), str)
                }
            )
            type_sig = ",".join(types) if types else "unknown"
            return f"dict:{keys}:content[{type_sig}]"
        return f"dict:{keys}"
    if isinstance(response, list):
        return f"list:{len(response)}"
    return f"type:{type(response).__name__}"
