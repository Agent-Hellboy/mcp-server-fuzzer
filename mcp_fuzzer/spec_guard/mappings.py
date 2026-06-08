"""Mappings for protocol/method spec guard checks."""

from __future__ import annotations

from typing import Any, Callable

from .helpers import SpecCheck
from .spec_checks import (
    check_cancelled_notification,
    check_completion_complete,
    check_create_message_result,
    check_elicit_result,
    check_elicitation_complete_notification,
    check_list_changed_notification,
    check_logging_notification,
    check_progress_notification,
    check_prompts_get,
    check_prompts_list,
    check_resource_templates_list,
    check_resources_list,
    check_resources_read,
    check_resources_updated_notification,
    check_roots_list,
    check_subscribe_result,
    check_task_payload_result,
    check_task_result,
    check_task_status_notification,
    check_tasks_list,
    check_tool_result_content,
    check_tools_list,
    check_unsubscribe_result,
)

_CheckFn = Callable[[Any], list[SpecCheck]]

METHOD_CHECK_MAP: dict[str, _CheckFn] = {
    "notifications/message": check_logging_notification,
    "notifications/tasks/status": check_task_status_notification,
    "notifications/elicitation/complete": check_elicitation_complete_notification,
    "notifications/progress": check_progress_notification,
    "notifications/cancelled": check_cancelled_notification,
    "notifications/resources/list_changed": check_list_changed_notification,
    "notifications/resources/updated": check_resources_updated_notification,
    "notifications/prompts/list_changed": check_list_changed_notification,
    "notifications/tools/list_changed": check_list_changed_notification,
    "notifications/roots/list_changed": check_list_changed_notification,
    "tools/list": check_tools_list,
    "tools/call": check_tool_result_content,
    "resources/list": check_resources_list,
    "resources/read": check_resources_read,
    "resources/subscribe": check_subscribe_result,
    "resources/unsubscribe": check_unsubscribe_result,
    "resources/templates/list": check_resource_templates_list,
    "prompts/list": check_prompts_list,
    "prompts/get": check_prompts_get,
    "roots/list": check_roots_list,
    "sampling/createMessage": check_create_message_result,
    "elicitation/create": check_elicit_result,
    "completion/complete": check_completion_complete,
    "tasks/list": check_tasks_list,
    "tasks/get": check_task_result,
    "tasks/result": check_task_payload_result,
    "tasks/cancel": check_task_result,
}

PROTOCOL_TYPE_TO_METHOD: dict[str, str] = {
    "InitializedNotification": "notifications/initialized",
    "CancelledNotification": "notifications/cancelled",
    "ProgressNotification": "notifications/progress",
    "ResourceListChangedNotification": "notifications/resources/list_changed",
    "ResourceUpdatedNotification": "notifications/resources/updated",
    "PromptListChangedNotification": "notifications/prompts/list_changed",
    "ToolListChangedNotification": "notifications/tools/list_changed",
    "RootsListChangedNotification": "notifications/roots/list_changed",
    "ListToolsRequest": "tools/list",
    "CallToolRequest": "tools/call",
    "ListResourcesRequest": "resources/list",
    "ReadResourceRequest": "resources/read",
    "SubscribeRequest": "resources/subscribe",
    "UnsubscribeRequest": "resources/unsubscribe",
    "ListResourceTemplatesRequest": "resources/templates/list",
    "ListPromptsRequest": "prompts/list",
    "GetPromptRequest": "prompts/get",
    "ListRootsRequest": "roots/list",
    "CreateMessageRequest": "sampling/createMessage",
    "ElicitRequest": "elicitation/create",
    "CompleteRequest": "completion/complete",
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
    check_fn = METHOD_CHECK_MAP.get(method)
    if not check_fn:
        return [], None
    scope = method
    return check_fn(payload), scope


def get_spec_checks_for_protocol_type(
    protocol_type: str | None, payload: Any, *, method: str | None = None
) -> tuple[list[SpecCheck], str | None]:
    if protocol_type == "GenericJSONRPCRequest":
        return get_spec_checks_for_method(method, payload)
    mapped_method = PROTOCOL_TYPE_TO_METHOD.get(protocol_type or "")
    return get_spec_checks_for_method(mapped_method, payload)


_NOTIFICATION_ONLY_METHODS: frozenset[str] = frozenset(
    {
        "notifications/initialized",
    }
)


def _validate_registry() -> None:
    """Assert every PROTOCOL_TYPE_TO_METHOD value is resolvable.

    A method is considered resolvable if it is present in METHOD_CHECK_MAP
    or is a known notification-only method that intentionally has no check.
    Raises AssertionError with a descriptive message on the first violation.
    """
    for protocol_type, method in PROTOCOL_TYPE_TO_METHOD.items():
        if method not in METHOD_CHECK_MAP and method not in _NOTIFICATION_ONLY_METHODS:
            raise AssertionError(
                f"PROTOCOL_TYPE_TO_METHOD entry {protocol_type!r} maps to method "
                f"{method!r}, which has no entry in METHOD_CHECK_MAP and is not a "
                "known notification-only method. Add it to METHOD_CHECK_MAP or to "
                "_NOTIFICATION_ONLY_METHODS."
            )


_validate_registry()

__all__ = [
    "METHOD_CHECK_MAP",
    "PROTOCOL_TYPE_TO_METHOD",
    "get_spec_checks_for_method",
    "get_spec_checks_for_protocol_type",
]
