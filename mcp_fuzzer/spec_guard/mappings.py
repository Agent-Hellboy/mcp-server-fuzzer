"""Mappings for protocol/method spec guard checks."""

from __future__ import annotations

from typing import Any, Callable

from .helpers import SpecCheck
from .spec_checks import (
    check_tools_list,
    check_tool_result_content,
    check_task_result,
    check_task_payload_result,
    check_tasks_list,
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
    check_roots_list,
    check_create_message_result,
    check_elicit_result,
    check_logging_notification,
    check_task_status_notification,
    check_elicitation_complete_notification,
)

_CheckFn = Callable[[Any], list[SpecCheck]]

METHOD_CHECK_MAP: dict[str, tuple[_CheckFn, str]] = {
    "notifications/message": (check_logging_notification, "logging/message"),
    "notifications/tasks/status": (
        check_task_status_notification,
        "tasks/status",
    ),
    "notifications/elicitation/complete": (
        check_elicitation_complete_notification,
        "elicitation/complete",
    ),
    "tools/list": (check_tools_list, "tools/list"),
    "tools/call": (check_tool_result_content, "tools/call"),
    "resources/list": (check_resources_list, "resources/list"),
    "resources/read": (check_resources_read, "resources/read"),
    "resources/templates/list": (
        check_resource_templates_list,
        "resources/templates/list",
    ),
    "prompts/list": (check_prompts_list, "prompts/list"),
    "prompts/get": (check_prompts_get, "prompts/get"),
    "roots/list": (check_roots_list, "roots/list"),
    "sampling/createMessage": (
        check_create_message_result,
        "sampling/createMessage",
    ),
    "elicitation/create": (check_elicit_result, "elicitation/create"),
    "tasks/list": (check_tasks_list, "tasks/list"),
    "tasks/get": (check_task_result, "tasks/get"),
    "tasks/result": (check_task_payload_result, "tasks/result"),
    "tasks/cancel": (check_task_result, "tasks/cancel"),
}

PROTOCOL_TYPE_TO_METHOD: dict[str, str] = {
    "InitializedNotification": "notifications/initialized",
    "CancelledNotification": "notifications/cancelled",
    "ListToolsRequest": "tools/list",
    "CallToolRequest": "tools/call",
    "ListResourcesRequest": "resources/list",
    "ReadResourceRequest": "resources/read",
    "ListResourceTemplatesRequest": "resources/templates/list",
    "ListPromptsRequest": "prompts/list",
    "GetPromptRequest": "prompts/get",
    "ListRootsRequest": "roots/list",
    "CreateMessageRequest": "sampling/createMessage",
    "ElicitRequest": "elicitation/create",
    "ListTasksRequest": "tasks/list",
    "GetTaskRequest": "tasks/get",
    "GetTaskPayloadRequest": "tasks/result",
    "CancelTaskRequest": "tasks/cancel",
}


def get_spec_checks_for_method(
    method: str | None, payload: Any
) -> tuple[list[SpecCheck], str | None]:
    if not isinstance(method, str) or not method:
        return [], None
    entry = METHOD_CHECK_MAP.get(method)
    if not entry:
        return [], None
    check_fn, scope = entry
    return check_fn(payload), scope


def get_spec_checks_for_protocol_type(
    protocol_type: str | None, payload: Any, *, method: str | None = None
) -> tuple[list[SpecCheck], str | None]:
    if protocol_type == "GenericJSONRPCRequest":
        return get_spec_checks_for_method(method, payload)
    mapped_method = PROTOCOL_TYPE_TO_METHOD.get(protocol_type or "")
    return get_spec_checks_for_method(mapped_method, payload)


__all__ = [
    "METHOD_CHECK_MAP",
    "PROTOCOL_TYPE_TO_METHOD",
    "get_spec_checks_for_method",
    "get_spec_checks_for_protocol_type",
]
