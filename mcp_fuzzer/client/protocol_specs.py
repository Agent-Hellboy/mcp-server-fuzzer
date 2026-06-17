"""Protocol type registry and response-shape helpers for ProtocolClient."""

from typing import Any

from ..protocol_registry import (
    EXECUTABLE_PROTOCOL_TYPES,
    GET_PROMPT_REQUEST,
    READ_RESOURCE_REQUEST,
)
from ..types import ProtocolSpec

# ProtocolClient owns the executable protocol list it can iterate over.
SUPPORTED_PROTOCOL_TYPES = tuple(EXECUTABLE_PROTOCOL_TYPES)

_PROTOCOL_SPECS: dict[str, ProtocolSpec] = {
    "InitializeRequest": ProtocolSpec("_send_initialize_request", "initialize", False),
    "InitializedNotification": ProtocolSpec(
        "_send_initialized_notification",
        "notifications/initialized",
        True,
    ),
    "ProgressNotification": ProtocolSpec(
        "_send_progress_notification",
        "notifications/progress",
        True,
    ),
    "CancelledNotification": ProtocolSpec(
        "_send_cancelled_notification",
        "notifications/cancelled",
        True,
    ),
    "ListToolsRequest": ProtocolSpec("_send_list_tools_request", "tools/list", False),
    "CallToolRequest": ProtocolSpec("_send_call_tool_request", "tools/call", False),
    "ListResourcesRequest": ProtocolSpec(
        "_send_list_resources_request",
        "resources/list",
        False,
    ),
    READ_RESOURCE_REQUEST: ProtocolSpec(
        "_send_read_resource_request",
        "resources/read",
        False,
    ),
    "ListResourceTemplatesRequest": ProtocolSpec(
        "_send_list_resource_templates_request",
        "resources/templates/list",
        False,
    ),
    "SetLevelRequest": ProtocolSpec(
        "_send_set_level_request",
        "logging/setLevel",
        False,
    ),
    "CreateMessageRequest": ProtocolSpec(
        "_send_create_message_request",
        "sampling/createMessage",
        False,
    ),
    "ListPromptsRequest": ProtocolSpec(
        "_send_list_prompts_request",
        "prompts/list",
        False,
    ),
    GET_PROMPT_REQUEST: ProtocolSpec("_send_get_prompt_request", "prompts/get", False),
    "ListRootsRequest": ProtocolSpec("_send_list_roots_request", "roots/list", False),
    "SubscribeRequest": ProtocolSpec(
        "_send_subscribe_request",
        "resources/subscribe",
        False,
    ),
    "UnsubscribeRequest": ProtocolSpec(
        "_send_unsubscribe_request",
        "resources/unsubscribe",
        False,
    ),
    "CompleteRequest": ProtocolSpec(
        "_send_complete_request",
        "completion/complete",
        False,
    ),
    "ElicitRequest": ProtocolSpec(
        "_send_elicit_request",
        "elicitation/create",
        False,
    ),
    "ListTasksRequest": ProtocolSpec("_send_list_tasks_request", "tasks/list", False),
    "GetTaskRequest": ProtocolSpec("_send_get_task_request", "tasks/get", False),
    "GetTaskPayloadRequest": ProtocolSpec(
        "_send_get_task_payload_request",
        "tasks/result",
        False,
    ),
    "CancelTaskRequest": ProtocolSpec(
        "_send_cancel_task_request",
        "tasks/cancel",
        False,
    ),
    "PingRequest": ProtocolSpec("_send_ping_request", "ping", False),
}


def _validate_protocol_specs() -> None:
    for protocol_type, spec in _PROTOCOL_SPECS.items():
        if not spec.handler_name or not spec.method:
            raise ValueError(f"Invalid protocol spec for {protocol_type!r}")


_validate_protocol_specs()


def _response_shape_signature(response: Any) -> str | None:
    if response is None:
        return None
    if isinstance(response, dict):
        keys = ",".join(sorted(response.keys()))
        if "result" in response and isinstance(response.get("result"), dict):
            result_keys = ",".join(sorted(response["result"].keys()))
            return f"dict:{keys}:result[{result_keys}]"
        if "error" in response and isinstance(response.get("error"), dict):
            err_keys = ",".join(sorted(response["error"].keys()))
            return f"dict:{keys}:error[{err_keys}]"
        return f"dict:{keys}"
    if isinstance(response, list):
        return f"list:{len(response)}"
    return f"type:{type(response).__name__}"
