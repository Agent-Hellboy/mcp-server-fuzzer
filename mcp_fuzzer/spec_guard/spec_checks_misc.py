"""MCP spec checks - roots, sampling, elicitation, completions, and SSE checks."""

import os
from datetime import date
from typing import Any

from .check_ids import CheckID
from .helpers import (
    COMPLETIONS_SPEC,
    ELICITATION_SPEC,
    ROOTS_SPEC,
    SAMPLING_SPEC,
    SSE_SPEC,
    SpecCheck,
    fail as _fail,
    warn as _warn,
)

_ROOTS_SPEC = ROOTS_SPEC
_SAMPLING_SPEC = SAMPLING_SPEC
_ELICITATION_SPEC = ELICITATION_SPEC
_COMPLETIONS_SPEC = COMPLETIONS_SPEC
_SSE_SPEC = SSE_SPEC

def _spec_at_least(target: str) -> bool:
    current = os.getenv("MCP_SPEC_SCHEMA_VERSION", "2025-11-25")
    try:
        # Compare ISO dates when possible.
        return date.fromisoformat(current) >= date.fromisoformat(target)
    except ValueError:
        return current >= target

def check_roots_list(result: Any) -> list[SpecCheck]:
    """Validate roots/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    roots = result.get("roots")
    if roots is None:
        checks.append(
            _fail(CheckID.ROOTS_LIST_MISSING, "Missing roots array", _ROOTS_SPEC)
        )
        return checks

    if not isinstance(roots, list):
        checks.append(
            _fail(CheckID.ROOTS_LIST_TYPE, "roots is not an array", _ROOTS_SPEC)
        )
        return checks

    for idx, root in enumerate(roots):
        if not isinstance(root, dict):
            checks.append(
                _fail(
                    CheckID.ROOTS_LIST_ITEM,
                    f"Root {idx} is not an object",
                    _ROOTS_SPEC,
                )
            )
            continue
        if not isinstance(root.get("uri"), str) or not root.get("uri"):
            checks.append(
                _fail(CheckID.ROOTS_LIST_URI, f"Root {idx} missing uri", _ROOTS_SPEC)
            )

    return checks
def check_create_message_result(result: Any) -> list[SpecCheck]:
    """Validate sampling/createMessage response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    if not isinstance(result.get("model"), str) or not result.get("model"):
        checks.append(
            _fail(
                CheckID.SAMPLING_MODEL,
                "CreateMessageResult missing model",
                _SAMPLING_SPEC,
            )
        )
    role = result.get("role")
    if role is not None and (not isinstance(role, str) or not role):
        checks.append(
            _fail(
                CheckID.SAMPLING_ROLE,
                "CreateMessageResult missing role",
                _SAMPLING_SPEC,
            )
        )

    content = result.get("content")
    if not isinstance(content, (dict, list)):
        checks.append(
            _fail(
                CheckID.SAMPLING_CONTENT,
                "CreateMessageResult content must be an object or array",
                _SAMPLING_SPEC,
            )
        )

    stop_reason = result.get("stopReason")
    if stop_reason is not None and not isinstance(stop_reason, str):
        checks.append(
            _fail(
                CheckID.SAMPLING_STOP_REASON,
                "CreateMessageResult stopReason is not a string",
                _SAMPLING_SPEC,
            )
        )

    return checks


def check_elicit_result(result: Any) -> list[SpecCheck]:
    """Validate elicitation/create response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    if result.get("action") not in {"accept", "cancel", "decline"}:
        checks.append(
            _fail(
                CheckID.ELICITATION_ACTION,
                "ElicitResult action is invalid",
                _ELICITATION_SPEC,
            )
        )
    if "content" in result and not isinstance(result.get("content"), dict):
        checks.append(
            _fail(
                CheckID.ELICITATION_CONTENT,
                "ElicitResult content must be an object when present",
                _ELICITATION_SPEC,
            )
        )

    return checks
def check_completion_complete(result: Any) -> list[SpecCheck]:
    """Validate completion/complete response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    completion = result.get("completion")
    if completion is None:
        checks.append(
            _fail(
                CheckID.COMPLETION_MISSING,
                "completion/complete result missing completion object",
                _COMPLETIONS_SPEC,
            )
        )
        return checks

    if not isinstance(completion, dict):
        checks.append(
            _fail(
                CheckID.COMPLETION_TYPE,
                "completion/complete result completion is not an object",
                _COMPLETIONS_SPEC,
            )
        )
        return checks

    values = completion.get("values")
    if values is None:
        checks.append(
            _fail(
                CheckID.COMPLETION_VALUES_MISSING,
                "completion/complete result missing values array",
                _COMPLETIONS_SPEC,
            )
        )
    elif not isinstance(values, list):
        checks.append(
            _fail(
                CheckID.COMPLETION_VALUES_TYPE,
                "completion/complete result values is not an array",
                _COMPLETIONS_SPEC,
            )
        )
    else:
        for idx, val in enumerate(values):
            if not isinstance(val, str):
                checks.append(
                    _fail(
                        CheckID.COMPLETION_VALUES_ITEM,
                        f"completion/complete result values[{idx}] is not a string",
                        _COMPLETIONS_SPEC,
                    )
                )

    has_more = completion.get("hasMore")
    if has_more is not None and not isinstance(has_more, bool):
        checks.append(
            _fail(
                CheckID.COMPLETION_HAS_MORE_TYPE,
                "completion/complete result hasMore is not a boolean",
                _COMPLETIONS_SPEC,
            )
        )

    total = completion.get("total")
    if total is not None and (not isinstance(total, int) or isinstance(total, bool)):
        checks.append(
            _fail(
                CheckID.COMPLETION_TOTAL_TYPE,
                "completion/complete result total is not an integer",
                _COMPLETIONS_SPEC,
            )
        )

    return checks
def check_sse_event_text(event_text: str) -> list[SpecCheck]:
    """Validate SSE event control fields."""
    checks: list[SpecCheck] = []
    if not event_text:
        return checks

    saw_data = False
    for raw_line in event_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("data:"):
            saw_data = True
            continue
        if line.startswith("retry:"):
            retry_value = line[len("retry:") :].strip()
            if not retry_value.isdigit():
                checks.append(
                    _warn(
                        CheckID.SSE_RETRY_NONINT,
                        "SSE retry field is not an integer",
                        _SSE_SPEC,
                    )
                )
        if line.startswith("id:"):
            event_id = line[len("id:") :].strip()
            if not event_id:
                checks.append(
                    _warn(
                        CheckID.SSE_ID_EMPTY,
                        "SSE id field is empty",
                        _SSE_SPEC,
                    )
                )

    if not saw_data:
        checks.append(
            _warn(
                CheckID.SSE_NO_DATA, "SSE event contains no data payload", _SSE_SPEC
            )
        )

    return checks
