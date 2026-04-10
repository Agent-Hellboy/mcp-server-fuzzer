"""Lightweight MCP spec checks for fuzzing results."""

import os
from datetime import date
from typing import Any

from .helpers import (
    ELICITATION_SPEC,
    LOGGING_SPEC,
    PROMPTS_SPEC,
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
        "https://modelcontextprotocol.io/specification/{version}/server/tools#calling-tools"
    ),
)
_LOGGING_SPEC = LOGGING_SPEC
_SCHEMA_SPEC = spec_variant(SCHEMA_SPEC, spec_id="MCP-JSON-Schema")
_RESOURCES_SPEC = RESOURCES_SPEC
_PROMPTS_SPEC = PROMPTS_SPEC
_SSE_SPEC = SSE_SPEC
_ROOTS_SPEC = ROOTS_SPEC
_SAMPLING_SPEC = SAMPLING_SPEC
_ELICITATION_SPEC = ELICITATION_SPEC
_TASKS_SPEC = TASKS_SPEC


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
    if not isinstance(name, str) or not name:
        checks.append(
            _fail("tool-name", "Tool is missing a non-empty name", _TOOLS_SPEC)
        )

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return checks

    if "$schema" in schema and not isinstance(schema.get("$schema"), str):
        checks.append(
            _fail(
                "tool-schema-$schema",
                "Tool inputSchema has non-string $schema",
                _SCHEMA_SPEC,
            )
        )

    if "$defs" in schema and not isinstance(schema.get("$defs"), dict):
        checks.append(
            _fail(
                "tool-schema-$defs",
                "Tool inputSchema has non-object $defs",
                _SCHEMA_SPEC,
            )
        )

    if "additionalProperties" in schema:
        additional = schema.get("additionalProperties")
        if not isinstance(additional, (bool, dict)):
            checks.append(
                _fail(
                    "tool-schema-additional-properties",
                    "Tool inputSchema has invalid additionalProperties type",
                    _SCHEMA_SPEC,
                )
            )

    icons = tool.get("icons")
    if icons is not None and not isinstance(icons, list):
        checks.append(
            _fail("tool-icons-type", "Tool icons is not an array", _TOOLS_SPEC)
        )
    elif isinstance(icons, list):
        for idx, icon in enumerate(icons):
            if not isinstance(icon, dict):
                checks.append(
                    _fail(
                        "tool-icon-item",
                        f"Tool icon {idx} is not an object",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not isinstance(icon.get("src"), str) or not icon.get("src"):
                checks.append(
                    _fail(
                        "tool-icon-src",
                        f"Tool icon {idx} missing src",
                        _TOOLS_SPEC,
                    )
                )

    execution = tool.get("execution")
    if execution is not None and not isinstance(execution, dict):
        checks.append(
            _fail(
                "tool-execution-type",
                "Tool execution is not an object",
                _TOOLS_SPEC,
            )
        )
    elif isinstance(execution, dict) and "taskSupport" in execution:
        task_support = execution.get("taskSupport")
        if task_support not in {"forbidden", "optional", "required"}:
            checks.append(
                _fail(
                    "tool-execution-task-support",
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
        checks.append(_fail("tools-list-missing", "Missing tools array", _TOOLS_SPEC))
        return checks

    if not isinstance(tools, list):
        checks.append(_fail("tools-list-type", "tools is not an array", _TOOLS_SPEC))
        return checks

    for tool in tools:
        if not isinstance(tool, dict):
            checks.append(
                _fail("tools-list-item", "Tool entry is not an object", _TOOLS_SPEC)
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

    if not isinstance(task.get("ttl"), int):
        checks.append(
            _fail(f"{prefix}-ttl", "Task ttl must be an integer", _TASKS_SPEC)
        )

    poll_interval = task.get("pollInterval")
    if poll_interval is not None and not isinstance(poll_interval, int):
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
        checks.append(_fail("tasks-list-missing", "Missing tasks array", _TASKS_SPEC))
        return checks

    if not isinstance(tasks, list):
        checks.append(_fail("tasks-list-type", "tasks is not an array", _TASKS_SPEC))
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
            _fail("tasks-result-type", "tasks/result payload is not an object", _TASKS_SPEC)
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
        checks.append(_fail("roots-list-missing", "Missing roots array", _ROOTS_SPEC))
        return checks

    if not isinstance(roots, list):
        checks.append(_fail("roots-list-type", "roots is not an array", _ROOTS_SPEC))
        return checks

    for idx, root in enumerate(roots):
        if not isinstance(root, dict):
            checks.append(
                _fail("roots-list-item", f"Root {idx} is not an object", _ROOTS_SPEC)
            )
            continue
        if not isinstance(root.get("uri"), str) or not root.get("uri"):
            checks.append(
                _fail("roots-list-uri", f"Root {idx} missing uri", _ROOTS_SPEC)
            )

    return checks


def check_create_message_result(result: Any) -> list[SpecCheck]:
    """Validate sampling/createMessage response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    if not isinstance(result.get("model"), str) or not result.get("model"):
        checks.append(
            _fail("sampling-model", "CreateMessageResult missing model", _SAMPLING_SPEC)
        )
    if not isinstance(result.get("role"), str) or not result.get("role"):
        checks.append(
            _fail("sampling-role", "CreateMessageResult missing role", _SAMPLING_SPEC)
        )

    content = result.get("content")
    if not isinstance(content, (dict, list)):
        checks.append(
            _fail(
                "sampling-content",
                "CreateMessageResult content must be an object or array",
                _SAMPLING_SPEC,
            )
        )

    stop_reason = result.get("stopReason")
    if stop_reason is not None and not isinstance(stop_reason, str):
        checks.append(
            _fail(
                "sampling-stop-reason",
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
            _fail("elicitation-action", "ElicitResult action is invalid", _ELICITATION_SPEC)
        )
    if "content" in result and not isinstance(result.get("content"), dict):
        checks.append(
            _fail(
                "elicitation-content",
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
            _fail("tools-content-array", "Tool content is not an array", _TOOLS_SPEC)
        )
        return checks

    if not content:
        checks.append(
            _warn("tools-content-empty", "Tool content array is empty", _TOOLS_SPEC)
        )

    supports_audio = _spec_at_least("2025-03-26")
    supports_resource_link = _spec_at_least("2025-06-18")

    for idx, item in enumerate(content):
        if not isinstance(item, dict):
            checks.append(
                _fail(
                    "tools-content-item",
                    f"Content item {idx} is not an object",
                    _TOOLS_SPEC,
                )
            )
            continue

        ctype = item.get("type")
        if not isinstance(ctype, str):
            checks.append(
                _fail(
                    "tools-content-type",
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
                        "tools-content-text",
                        "Text content missing text field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "image":
            if not isinstance(item.get("data"), str):
                checks.append(
                    _fail(
                        "tools-content-image-data",
                        "Image content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not isinstance(item.get("mimeType"), str):
                checks.append(
                    _fail(
                        "tools-content-image-mime",
                        "Image content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "audio":
            if not supports_audio:
                checks.append(
                    _fail(
                        "tools-content-audio-unsupported",
                        "Audio content is not supported by this spec version",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not isinstance(item.get("data"), str):
                checks.append(
                    _fail(
                        "tools-content-audio-data",
                        "Audio content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not isinstance(item.get("mimeType"), str):
                checks.append(
                    _fail(
                        "tools-content-audio-mime",
                        "Audio content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "resource":
            resource = item.get("resource")
            if resource is None:
                checks.append(
                    _fail(
                        "tools-content-resource",
                        "Resource content missing resource object",
                        _TOOLS_SPEC,
                    )
                )
            elif not isinstance(resource, dict):
                checks.append(
                    _fail(
                        "tools-content-resource",
                        "Resource content missing resource object",
                        _TOOLS_SPEC,
                    )
                )
            else:
                if not resource.get("uri"):
                    checks.append(
                        _fail(
                            "tools-content-resource-uri",
                            "Resource content missing uri field",
                            _TOOLS_SPEC,
                        )
                    )
                if not (resource.get("text") or resource.get("blob")):
                    checks.append(
                        _fail(
                            "tools-content-resource-body",
                            "Resource content missing text or blob field",
                            _TOOLS_SPEC,
                        )
                    )
        elif ctype == "resource_link":
            if not supports_resource_link:
                checks.append(
                    _fail(
                        "tools-content-resource-link-unsupported",
                        "Resource links are not supported by this spec version",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not item.get("uri"):
                checks.append(
                    _fail(
                        "tools-content-resource-link-uri",
                        "Resource link missing uri field",
                        _TOOLS_SPEC,
                    )
                )
            if not item.get("name"):
                checks.append(
                    _fail(
                        "tools-content-resource-link-name",
                        "Resource link missing name field",
                        _TOOLS_SPEC,
                    )
                )
        else:
            checks.append(
                _warn(
                    "tools-content-unknown-type",
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
                    "tools-error-text",
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
                "logging-params-missing",
                "Logging notification params missing",
                _LOGGING_SPEC,
            )
        )
        return checks

    if not isinstance(params, dict):
        checks.append(
            _fail(
                "logging-params-type",
                "Logging notification params is not an object",
                _LOGGING_SPEC,
            )
        )
        return checks

    if "level" not in params:
        checks.append(
            _fail(
                "logging-level-missing",
                "Logging notification level missing",
                _LOGGING_SPEC,
            )
        )
    elif not isinstance(params.get("level"), str):
        checks.append(
            _fail(
                "logging-level-type",
                "Logging notification level is not a string",
                _LOGGING_SPEC,
            )
        )

    if "data" not in params:
        checks.append(
            _fail(
                "logging-data-missing",
                "Logging notification data missing",
                _LOGGING_SPEC,
            )
        )

    if "logger" in params and not isinstance(params.get("logger"), str):
        checks.append(
            _fail(
                "logging-logger-type",
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
                "elicitation-complete-params",
                "Elicitation completion params missing",
                _ELICITATION_SPEC,
            )
        )
        return checks

    if not isinstance(params.get("elicitationId"), str) or not params.get("elicitationId"):
        checks.append(
            _fail(
                "elicitation-complete-id",
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
            _fail("resources-list-missing", "Missing resources array", _RESOURCES_SPEC)
        )
        return checks

    if not isinstance(resources, list):
        checks.append(
            _fail("resources-list-type", "resources is not an array", _RESOURCES_SPEC)
        )
        return checks

    for idx, resource in enumerate(resources):
        if not isinstance(resource, dict):
            checks.append(
                _fail(
                    "resources-list-item",
                    f"Resource {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not resource.get("uri"):
            checks.append(
                _fail(
                    "resources-list-uri",
                    f"Resource {idx} missing uri",
                    _RESOURCES_SPEC,
                )
            )
        if not resource.get("name"):
            checks.append(
                _fail(
                    "resources-list-name",
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
            _fail("resources-read-missing", "Missing contents array", _RESOURCES_SPEC)
        )
        return checks

    if not isinstance(contents, list):
        checks.append(
            _fail("resources-read-type", "contents is not an array", _RESOURCES_SPEC)
        )
        return checks

    if not contents:
        checks.append(
            _warn("resources-read-empty", "contents array is empty", _RESOURCES_SPEC)
        )
        return checks

    for idx, item in enumerate(contents):
        if isinstance(item, dict):
            if not item.get("uri"):
                checks.append(
                    _fail(
                        "resources-read-uri",
                        f"Content {idx} missing uri",
                        _RESOURCES_SPEC,
                    )
                )
            if not (item.get("text") or item.get("blob")):
                checks.append(
                    _fail(
                        "resources-read-body",
                        f"Content {idx} missing text or blob",
                        _RESOURCES_SPEC,
                    )
                )
        else:
            checks.append(
                _fail(
                    "resources-read-item",
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
                "resources-templates-missing",
                "Missing resourceTemplates array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(templates, list):
        checks.append(
            _fail(
                "resources-templates-type",
                "resourceTemplates is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, template in enumerate(templates):
        if not isinstance(template, dict):
            checks.append(
                _fail(
                    "resources-templates-item",
                    f"Template {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not template.get("uriTemplate"):
            checks.append(
                _fail(
                    "resources-templates-uri",
                    f"Template {idx} missing uriTemplate",
                    _RESOURCES_SPEC,
                )
            )
        if not template.get("name"):
            checks.append(
                _fail(
                    "resources-templates-name",
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
            _fail("prompts-list-missing", "Missing prompts array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(prompts, list):
        checks.append(
            _fail("prompts-list-type", "prompts is not an array", _PROMPTS_SPEC)
        )
        return checks

    for idx, prompt in enumerate(prompts):
        if not isinstance(prompt, dict):
            checks.append(
                _fail(
                    "prompts-list-item",
                    f"Prompt {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not prompt.get("name"):
            checks.append(
                _fail(
                    "prompts-list-name",
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
            _fail("prompts-get-missing", "Missing messages array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(messages, list):
        checks.append(
            _fail("prompts-get-type", "messages is not an array", _PROMPTS_SPEC)
        )
        return checks

    if not messages:
        checks.append(
            _warn("prompts-get-empty", "messages array is empty", _PROMPTS_SPEC)
        )
        return checks

    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            checks.append(
                _fail(
                    "prompts-get-item",
                    f"Message {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not message.get("role"):
            checks.append(
                _fail(
                    "prompts-get-role",
                    f"Message {idx} missing role",
                    _PROMPTS_SPEC,
                )
            )
        if not message.get("content"):
            checks.append(
                _fail(
                    "prompts-get-content",
                    f"Message {idx} missing content",
                    _PROMPTS_SPEC,
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
                        "sse-retry-nonint",
                        "SSE retry field is not an integer",
                        _SSE_SPEC,
                    )
                )
        if line.startswith("id:"):
            event_id = line[len("id:") :].strip()
            if not event_id:
                checks.append(
                    _warn(
                        "sse-id-empty",
                        "SSE id field is empty",
                        _SSE_SPEC,
                    )
                )

    if not saw_data:
        checks.append(
            _warn("sse-no-data", "SSE event contains no data payload", _SSE_SPEC)
        )

    return checks
