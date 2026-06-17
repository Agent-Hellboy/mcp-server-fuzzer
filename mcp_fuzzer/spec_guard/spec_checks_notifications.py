"""MCP spec checks - logging, progress, and protocol notification checks."""

from typing import Any

from .check_ids import CheckID
from .helpers import (
    ELICITATION_SPEC,
    LOGGING_SPEC,
    PROTOCOL_SPEC,
    SpecCheck,
    fail as _fail,
)

_LOGGING_SPEC = LOGGING_SPEC
_PROTOCOL_SPEC = PROTOCOL_SPEC
_ELICITATION_SPEC = ELICITATION_SPEC

def check_logging_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate logging notification payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if params is None:
        checks.append(
            _fail(
                CheckID.LOGGING_PARAMS_MISSING,
                "Logging notification params missing",
                _LOGGING_SPEC,
            )
        )
        return checks

    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.LOGGING_PARAMS_TYPE,
                "Logging notification params is not an object",
                _LOGGING_SPEC,
            )
        )
        return checks

    if "level" not in params:
        checks.append(
            _fail(
                CheckID.LOGGING_LEVEL_MISSING,
                "Logging notification level missing",
                _LOGGING_SPEC,
            )
        )
    elif not isinstance(params.get("level"), str):
        checks.append(
            _fail(
                CheckID.LOGGING_LEVEL_TYPE,
                "Logging notification level is not a string",
                _LOGGING_SPEC,
            )
        )

    if "data" not in params:
        checks.append(
            _fail(
                CheckID.LOGGING_DATA_MISSING,
                "Logging notification data missing",
                _LOGGING_SPEC,
            )
        )

    if "logger" in params and not isinstance(params.get("logger"), str):
        checks.append(
            _fail(
                CheckID.LOGGING_LOGGER_TYPE,
                "Logging notification logger is not a string",
                _LOGGING_SPEC,
            )
        )

    return checks
def check_elicitation_complete_notification(
    payload: dict[str, Any],
) -> list[SpecCheck]:
    """Validate notifications/elicitation/complete payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.ELICITATION_COMPLETE_PARAMS,
                "Elicitation completion params missing",
                _ELICITATION_SPEC,
            )
        )
        return checks

    if not isinstance(params.get("elicitationId"), str) or not params.get(
        "elicitationId"
    ):
        checks.append(
            _fail(
                CheckID.ELICITATION_COMPLETE_ID,
                "Elicitation completion missing elicitationId",
                _ELICITATION_SPEC,
            )
        )

    return checks
def check_progress_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/progress payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.PROGRESS_PARAMS_TYPE,
                "notifications/progress params is not an object",
                _PROTOCOL_SPEC,
            )
        )
        return checks

    token = params.get("progressToken")
    if token is None:
        checks.append(
            _fail(
                CheckID.PROGRESS_TOKEN_MISSING,
                "notifications/progress missing progressToken",
                _PROTOCOL_SPEC,
            )
        )
    elif not isinstance(token, (str, int)) or isinstance(token, bool):
        checks.append(
            _fail(
                CheckID.PROGRESS_TOKEN_TYPE,
                "notifications/progress progressToken must be string or integer",
                _PROTOCOL_SPEC,
            )
        )

    progress = params.get("progress")
    if progress is None:
        checks.append(
            _fail(
                CheckID.PROGRESS_VALUE_MISSING,
                "notifications/progress missing progress value",
                _PROTOCOL_SPEC,
            )
        )
    elif not isinstance(progress, (int, float)) or isinstance(progress, bool):
        checks.append(
            _fail(
                CheckID.PROGRESS_VALUE_TYPE,
                "notifications/progress progress must be a number",
                _PROTOCOL_SPEC,
            )
        )

    total = params.get("total")
    if total is not None and (
        not isinstance(total, (int, float)) or isinstance(total, bool)
    ):
        checks.append(
            _fail(
                CheckID.PROGRESS_TOTAL_TYPE,
                "notifications/progress total must be a number",
                _PROTOCOL_SPEC,
            )
        )

    return checks


def check_cancelled_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/cancelled payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.CANCELLED_PARAMS_TYPE,
                "notifications/cancelled params is not an object",
                _PROTOCOL_SPEC,
            )
        )
        return checks

    request_id = params.get("requestId")
    if request_id is None:
        checks.append(
            _fail(
                CheckID.CANCELLED_REQUEST_ID_MISSING,
                "notifications/cancelled missing requestId",
                _PROTOCOL_SPEC,
            )
        )
    elif not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
        checks.append(
            _fail(
                CheckID.CANCELLED_REQUEST_ID_TYPE,
                "notifications/cancelled requestId must be string or integer",
                _PROTOCOL_SPEC,
            )
        )

    reason = params.get("reason")
    if reason is not None and not isinstance(reason, str):
        checks.append(
            _fail(
                CheckID.CANCELLED_REASON_TYPE,
                "notifications/cancelled reason must be a string",
                _PROTOCOL_SPEC,
            )
        )

    return checks


def check_list_changed_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate list_changed notification payload (params must be object or absent)."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if params is not None and not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.LIST_CHANGED_PARAMS_TYPE,
                "list_changed notification params must be an object when present",
                _PROTOCOL_SPEC,
            )
        )
    return checks
