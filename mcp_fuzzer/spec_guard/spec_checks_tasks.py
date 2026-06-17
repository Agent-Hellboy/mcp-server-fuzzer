"""MCP spec checks - task list and task result checks."""

from .spec_checks_tools import check_tool_result_content
from typing import Any

from .check_ids import CheckID
from .helpers import (
    TASKS_SPEC,
    SpecCheck,
    fail as _fail,
)

_TASKS_SPEC = TASKS_SPEC

def _check_task_shape(task: Any, *, prefix: str) -> list[SpecCheck]:
    checks: list[SpecCheck] = []
    if not isinstance(task, dict):
        checks.append(_fail(f"{prefix}-type", "Task is not an object", _TASKS_SPEC))
        return checks

    for field in ("taskId", "status", "createdAt", "lastUpdatedAt"):
        if not isinstance(task.get(field), str) or not task.get(field):
            checks.append(
                _fail(
                    f"{prefix}-{field}",
                    f"Task missing valid {field}",
                    _TASKS_SPEC,
                )
            )

    ttl = task.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        checks.append(
            _fail(f"{prefix}-ttl", "Task ttl must be an integer", _TASKS_SPEC)
        )

    poll_interval = task.get("pollInterval")
    if poll_interval is not None and (
        not isinstance(poll_interval, int) or isinstance(poll_interval, bool)
    ):
        checks.append(
            _fail(
                f"{prefix}-poll-interval",
                "Task pollInterval must be an integer",
                _TASKS_SPEC,
            )
        )

    return checks


def check_tasks_list(result: Any) -> list[SpecCheck]:
    """Validate tasks/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    tasks = result.get("tasks")
    if tasks is None:
        checks.append(
            _fail(CheckID.TASKS_LIST_MISSING, "Missing tasks array", _TASKS_SPEC)
        )
        return checks

    if not isinstance(tasks, list):
        checks.append(
            _fail(CheckID.TASKS_LIST_TYPE, "tasks is not an array", _TASKS_SPEC)
        )
        return checks

    for idx, task in enumerate(tasks):
        checks.extend(_check_task_shape(task, prefix=f"tasks-list-{idx}"))

    return checks


def check_task_result(result: Any) -> list[SpecCheck]:
    """Validate a single-task response shape."""
    return _check_task_shape(result, prefix="task")


def check_task_payload_result(result: Any) -> list[SpecCheck]:
    """Validate tasks/result payloads when they resemble known result shapes."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        checks.append(
            _fail(
                CheckID.TASKS_RESULT_TYPE,
                "tasks/result payload is not an object",
                _TASKS_SPEC,
            )
        )
        return checks

    if "content" in result:
        checks.extend(check_tool_result_content(result))

    return checks
def check_task_status_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/tasks/status payload shape."""
    params = payload.get("params")
    return _check_task_shape(params, prefix="tasks-status")
