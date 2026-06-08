"""Lightweight MCP spec checks for fuzzing results."""

import os
from datetime import date
from typing import Any

from .check_ids import CheckID
from .helpers import (
    COMPLETIONS_SPEC,
    ELICITATION_SPEC,
    LOGGING_SPEC,
    PROMPTS_SPEC,
    PROTOCOL_SPEC,
    RESOURCES_SPEC,
    ROOTS_SPEC,
    SAMPLING_SPEC,
    SCHEMA_SPEC,
    SSE_SPEC,
    TASKS_SPEC,
    TOOLS_SPEC,
    SpecCheck,
    fail as _fail,
    spec_variant,
    warn as _warn,
)


_TOOLS_SPEC = spec_variant(
    TOOLS_SPEC,
    spec_id="MCP-Tools-Call",
    spec_url=(
        "https://modelcontextprotocol.io/specification/{version}/server/"
        "tools#calling-tools"
    ),
)
_LOGGING_SPEC = LOGGING_SPEC
_PROTOCOL_SPEC = PROTOCOL_SPEC
_SCHEMA_SPEC = spec_variant(SCHEMA_SPEC, spec_id="MCP-JSON-Schema")
_RESOURCES_SPEC = RESOURCES_SPEC
_PROMPTS_SPEC = PROMPTS_SPEC
_SSE_SPEC = SSE_SPEC
_ROOTS_SPEC = ROOTS_SPEC
_SAMPLING_SPEC = SAMPLING_SPEC
_ELICITATION_SPEC = ELICITATION_SPEC
_TASKS_SPEC = TASKS_SPEC
_COMPLETIONS_SPEC = COMPLETIONS_SPEC


def _spec_at_least(target: str) -> bool:
    current = os.getenv("MCP_SPEC_SCHEMA_VERSION", "2025-11-25")
    try:
        # Compare ISO dates when possible.
        return date.fromisoformat(current) >= date.fromisoformat(target)
    except ValueError:
        return current >= target


def check_tool_schema_fields(tool: dict[str, Any]) -> list[SpecCheck]:
    """Validate JSON Schema keywords in tool definitions."""
    checks: list[SpecCheck] = []
    if not isinstance(tool, dict):
        return checks

    name = tool.get("name")
    if name is not None and (not isinstance(name, str) or not name):
        checks.append(
            _fail(CheckID.TOOL_NAME, "Tool is missing a non-empty name", _TOOLS_SPEC)
        )

    schema = tool.get("inputSchema")
    schema_is_dict = isinstance(schema, dict)
    if schema_is_dict:
        if "$schema" in schema and not isinstance(schema.get("$schema"), str):
            checks.append(
                _fail(
                    CheckID.TOOL_SCHEMA_SCHEMA,
                    "Tool inputSchema has non-string $schema",
                    _SCHEMA_SPEC,
                )
            )

        if "$defs" in schema and not isinstance(schema.get("$defs"), dict):
            checks.append(
                _fail(
                    CheckID.TOOL_SCHEMA_DEFS,
                    "Tool inputSchema has non-object $defs",
                    _SCHEMA_SPEC,
                )
            )

        if "additionalProperties" in schema:
            additional = schema.get("additionalProperties")
            if not isinstance(additional, (bool, dict)):
                checks.append(
                    _fail(
                        CheckID.TOOL_SCHEMA_ADDITIONAL_PROPERTIES,
                        "Tool inputSchema has invalid additionalProperties type",
                        _SCHEMA_SPEC,
                    )
                )

    icons = tool.get("icons")
    if icons is not None and not isinstance(icons, list):
        checks.append(
            _fail(CheckID.TOOL_ICONS_TYPE, "Tool icons is not an array", _TOOLS_SPEC)
        )
    elif isinstance(icons, list):
        for idx, icon in enumerate(icons):
            if not isinstance(icon, dict):
                checks.append(
                    _fail(
                        CheckID.TOOL_ICON_ITEM,
                        f"Tool icon {idx} is not an object",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not isinstance(icon.get("src"), str) or not icon.get("src"):
                checks.append(
                    _fail(
                        CheckID.TOOL_ICON_SRC,
                        f"Tool icon {idx} missing src",
                        _TOOLS_SPEC,
                    )
                )

    execution = tool.get("execution")
    if execution is not None and not isinstance(execution, dict):
        checks.append(
            _fail(
                CheckID.TOOL_EXECUTION_TYPE,
                "Tool execution is not an object",
                _TOOLS_SPEC,
            )
        )
    elif isinstance(execution, dict) and "taskSupport" in execution:
        task_support = execution.get("taskSupport")
        if task_support not in {"forbidden", "optional", "required"}:
            checks.append(
                _fail(
                    CheckID.TOOL_EXECUTION_TASK_SUPPORT,
                    "Tool execution.taskSupport is invalid",
                    _TOOLS_SPEC,
                )
            )

    return checks


def check_tools_list(result: Any) -> list[SpecCheck]:
    """Validate tools/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    tools = result.get("tools")
    if tools is None:
        checks.append(
            _fail(CheckID.TOOLS_LIST_MISSING, "Missing tools array", _TOOLS_SPEC)
        )
        return checks

    if not isinstance(tools, list):
        checks.append(
            _fail(CheckID.TOOLS_LIST_TYPE, "tools is not an array", _TOOLS_SPEC)
        )
        return checks

    for tool in tools:
        if not isinstance(tool, dict):
            checks.append(
                _fail(
                    CheckID.TOOLS_LIST_ITEM, "Tool entry is not an object", _TOOLS_SPEC
                )
            )
            continue
        checks.extend(check_tool_schema_fields(tool))

    return checks


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


def check_tool_result_content(result: Any) -> list[SpecCheck]:
    """Validate tool call response content blocks."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    if "content" not in result:
        return checks

    content = result.get("content")
    if not isinstance(content, list):
        checks.append(
            _fail(
                CheckID.TOOLS_CONTENT_ARRAY, "Tool content is not an array", _TOOLS_SPEC
            )
        )
        return checks

    if not content:
        checks.append(
            _warn(
                CheckID.TOOLS_CONTENT_EMPTY,
                "Tool content array is empty",
                _TOOLS_SPEC,
            )
        )

    supports_audio = _spec_at_least("2025-03-26")
    supports_resource_link = _spec_at_least("2025-06-18")

    for idx, item in enumerate(content):
        if not isinstance(item, dict):
            checks.append(
                _fail(
                    CheckID.TOOLS_CONTENT_ITEM,
                    f"Content item {idx} is not an object",
                    _TOOLS_SPEC,
                )
            )
            continue

        ctype = item.get("type")
        if not isinstance(ctype, str):
            checks.append(
                _fail(
                    CheckID.TOOLS_CONTENT_TYPE,
                    f"Content item {idx} missing type",
                    _TOOLS_SPEC,
                )
            )
            continue

        if ctype == "text":
            text = item.get("text")
            if not isinstance(text, str) or not text:
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_TEXT,
                        "Text content missing text field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "image":
            if not isinstance(item.get("data"), str):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_IMAGE_DATA,
                        "Image content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not isinstance(item.get("mimeType"), str):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_IMAGE_MIME,
                        "Image content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "audio":
            if not supports_audio:
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_AUDIO_UNSUPPORTED,
                        "Audio content is not supported by this spec version",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not isinstance(item.get("data"), str):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_AUDIO_DATA,
                        "Audio content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not isinstance(item.get("mimeType"), str):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_AUDIO_MIME,
                        "Audio content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "resource":
            resource = item.get("resource")
            if resource is None:
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_RESOURCE,
                        "Resource content missing resource object",
                        _TOOLS_SPEC,
                    )
                )
            elif not isinstance(resource, dict):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_RESOURCE,
                        "Resource content missing resource object",
                        _TOOLS_SPEC,
                    )
                )
            else:
                if not resource.get("uri"):
                    checks.append(
                        _fail(
                            CheckID.TOOLS_CONTENT_RESOURCE_URI,
                            "Resource content missing uri field",
                            _TOOLS_SPEC,
                        )
                    )
                if not (resource.get("text") or resource.get("blob")):
                    checks.append(
                        _fail(
                            CheckID.TOOLS_CONTENT_RESOURCE_BODY,
                            "Resource content missing text or blob field",
                            _TOOLS_SPEC,
                        )
                    )
        elif ctype == "resource_link":
            if not supports_resource_link:
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_RESOURCE_LINK_UNSUPPORTED,
                        "Resource links are not supported by this spec version",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not item.get("uri"):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_RESOURCE_LINK_URI,
                        "Resource link missing uri field",
                        _TOOLS_SPEC,
                    )
                )
            if not item.get("name"):
                checks.append(
                    _fail(
                        CheckID.TOOLS_CONTENT_RESOURCE_LINK_NAME,
                        "Resource link missing name field",
                        _TOOLS_SPEC,
                    )
                )
        else:
            checks.append(
                _warn(
                    CheckID.TOOLS_CONTENT_UNKNOWN_TYPE,
                    f"Unknown content type: {ctype}",
                    _TOOLS_SPEC,
                )
            )

    if result.get("isError") is True:
        has_text = any(
            isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
            and item.get("text")
            for item in content
        )
        if not has_text:
            checks.append(
                _warn(
                    CheckID.TOOLS_ERROR_TEXT,
                    "isError=true without text error message",
                    _TOOLS_SPEC,
                )
            )

    return checks


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


def check_task_status_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/tasks/status payload shape."""
    params = payload.get("params")
    return _check_task_shape(params, prefix="tasks-status")


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


def check_resources_list(result: Any) -> list[SpecCheck]:
    """Validate resources/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    resources = result.get("resources")
    if resources is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_LIST_MISSING,
                "Missing resources array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(resources, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_LIST_TYPE,
                "resources is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, resource in enumerate(resources):
        if not isinstance(resource, dict):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_ITEM,
                    f"Resource {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not resource.get("uri"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_URI,
                    f"Resource {idx} missing uri",
                    _RESOURCES_SPEC,
                )
            )
        if not resource.get("name"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_NAME,
                    f"Resource {idx} missing name",
                    _RESOURCES_SPEC,
                )
            )

    return checks


def check_resources_read(result: Any) -> list[SpecCheck]:
    """Validate resources/read response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    contents = result.get("contents")
    if contents is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_READ_MISSING,
                "Missing contents array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(contents, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_READ_TYPE,
                "contents is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not contents:
        checks.append(
            _warn(
                CheckID.RESOURCES_READ_EMPTY,
                "contents array is empty",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, item in enumerate(contents):
        if isinstance(item, dict):
            if not item.get("uri"):
                checks.append(
                    _fail(
                        CheckID.RESOURCES_READ_URI,
                        f"Content {idx} missing uri",
                        _RESOURCES_SPEC,
                    )
                )
            if not (item.get("text") or item.get("blob")):
                checks.append(
                    _fail(
                        CheckID.RESOURCES_READ_BODY,
                        f"Content {idx} missing text or blob",
                        _RESOURCES_SPEC,
                    )
                )
        else:
            checks.append(
                _fail(
                    CheckID.RESOURCES_READ_ITEM,
                    f"Content {idx} is not object",
                    _RESOURCES_SPEC,
                )
            )

    return checks


def check_resource_templates_list(result: Any) -> list[SpecCheck]:
    """Validate resources/templates/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    templates = result.get("resourceTemplates")
    if templates is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_TEMPLATES_MISSING,
                "Missing resourceTemplates array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(templates, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_TEMPLATES_TYPE,
                "resourceTemplates is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, template in enumerate(templates):
        if not isinstance(template, dict):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_ITEM,
                    f"Template {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not template.get("uriTemplate"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_URI,
                    f"Template {idx} missing uriTemplate",
                    _RESOURCES_SPEC,
                )
            )
        if not template.get("name"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_NAME,
                    f"Template {idx} missing name",
                    _RESOURCES_SPEC,
                )
            )

    return checks


def check_prompts_list(result: Any) -> list[SpecCheck]:
    """Validate prompts/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    prompts = result.get("prompts")
    if prompts is None:
        checks.append(
            _fail(CheckID.PROMPTS_LIST_MISSING, "Missing prompts array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(prompts, list):
        checks.append(
            _fail(
                CheckID.PROMPTS_LIST_TYPE, "prompts is not an array", _PROMPTS_SPEC
            )
        )
        return checks

    for idx, prompt in enumerate(prompts):
        if not isinstance(prompt, dict):
            checks.append(
                _fail(
                    CheckID.PROMPTS_LIST_ITEM,
                    f"Prompt {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not prompt.get("name"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_LIST_NAME,
                    f"Prompt {idx} missing name",
                    _PROMPTS_SPEC,
                )
            )
    return checks


def check_prompts_get(result: Any) -> list[SpecCheck]:
    """Validate prompts/get response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    messages = result.get("messages")
    if messages is None:
        checks.append(
            _fail(CheckID.PROMPTS_GET_MISSING, "Missing messages array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(messages, list):
        checks.append(
            _fail(
                CheckID.PROMPTS_GET_TYPE, "messages is not an array", _PROMPTS_SPEC
            )
        )
        return checks

    if not messages:
        checks.append(
            _warn(
                CheckID.PROMPTS_GET_EMPTY, "messages array is empty", _PROMPTS_SPEC
            )
        )
        return checks

    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_ITEM,
                    f"Message {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not message.get("role"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_ROLE,
                    f"Message {idx} missing role",
                    _PROMPTS_SPEC,
                )
            )
        if not message.get("content"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_CONTENT,
                    f"Message {idx} missing content",
                    _PROMPTS_SPEC,
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


def check_subscribe_result(result: Any) -> list[SpecCheck]:
    """Validate resources/subscribe response shape (must be EmptyResult {})."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        checks.append(
            _fail(
                CheckID.SUBSCRIBE_RESULT_TYPE,
                "resources/subscribe result is not an object",
                _RESOURCES_SPEC,
            )
        )
    return checks


def check_unsubscribe_result(result: Any) -> list[SpecCheck]:
    """Validate resources/unsubscribe response shape (must be EmptyResult {})."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        checks.append(
            _fail(
                CheckID.UNSUBSCRIBE_RESULT_TYPE,
                "resources/unsubscribe result is not an object",
                _RESOURCES_SPEC,
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


def check_resources_updated_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/resources/updated payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.RESOURCES_UPDATED_PARAMS_TYPE,
                "notifications/resources/updated params is not an object",
                _RESOURCES_SPEC,
            )
        )
        return checks

    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        checks.append(
            _fail(
                CheckID.RESOURCES_UPDATED_URI_MISSING,
                "notifications/resources/updated missing uri",
                _RESOURCES_SPEC,
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
