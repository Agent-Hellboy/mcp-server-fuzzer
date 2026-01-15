"""Lightweight MCP spec checks for fuzzing results."""

from typing import Any, TypedDict


class SpecCheck(TypedDict, total=False):
    """Minimal spec check record for reporting."""

    id: str
    status: str
    message: str
    spec_id: str
    spec_url: str
    details: dict[str, Any]


_TOOLS_SPEC = {
    "spec_id": "MCP-Tools-Call",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#calling-tools",
}

_LOGGING_SPEC = {
    "spec_id": "MCP-Logging",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/utilities/logging",
}

_SCHEMA_SPEC = {
    "spec_id": "MCP-JSON-Schema",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/schema",
}

_RESOURCES_SPEC = {
    "spec_id": "MCP-Resources",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
}

_PROMPTS_SPEC = {
    "spec_id": "MCP-Prompts",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
}

_SSE_SPEC = {
    "spec_id": "MCP-SSE",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#sse-transport",
}


def _fail(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    return {
        "id": check_id,
        "status": "FAIL",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def _warn(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    return {
        "id": check_id,
        "status": "WARN",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def check_tool_schema_fields(tool: dict[str, Any]) -> list[SpecCheck]:
    """Validate JSON Schema keywords in tool definitions."""
    checks: list[SpecCheck] = []
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
            _fail("tools-content-empty", "Tool content array is empty", _TOOLS_SPEC)
        )
        return checks

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
            if not isinstance(item.get("text"), str) or not item.get("text"):
                checks.append(
                    _fail(
                        "tools-content-text",
                        "Text content missing non-empty text field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "image":
            if not item.get("data"):
                checks.append(
                    _fail(
                        "tools-content-image-data",
                        "Image content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not item.get("mimeType"):
                checks.append(
                    _fail(
                        "tools-content-image-mime",
                        "Image content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "audio":
            if not item.get("data"):
                checks.append(
                    _fail(
                        "tools-content-audio-data",
                        "Audio content missing data field",
                        _TOOLS_SPEC,
                    )
                )
            if not item.get("mimeType"):
                checks.append(
                    _fail(
                        "tools-content-audio-mime",
                        "Audio content missing mimeType field",
                        _TOOLS_SPEC,
                    )
                )
        elif ctype == "resource":
            resource = item.get("resource")
            if not isinstance(resource, dict):
                checks.append(
                    _fail(
                        "tools-content-resource",
                        "Resource content missing resource object",
                        _TOOLS_SPEC,
                    )
                )
                continue
            if not resource.get("uri"):
                checks.append(
                    _fail(
                        "tools-content-resource-uri",
                        "Resource content missing uri field",
                        _TOOLS_SPEC,
                    )
                )
            if not resource.get("mimeType"):
                checks.append(
                    _fail(
                        "tools-content-resource-mime",
                        "Resource content missing mimeType field",
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
                _fail(
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

    if "level" in params and not isinstance(params.get("level"), str):
        checks.append(
            _fail(
                "logging-level-type",
                "Logging notification level is not a string",
                _LOGGING_SPEC,
            )
        )

    if "message" in params and not isinstance(params.get("message"), str):
        checks.append(
            _fail(
                "logging-message-type",
                "Logging notification message is not a string",
                _LOGGING_SPEC,
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
            _fail("resources-read-empty", "contents array is empty", _RESOURCES_SPEC)
        )
        return checks

    first = contents[0]
    if isinstance(first, dict):
        if not first.get("uri"):
            checks.append(
                _fail("resources-read-uri", "Content missing uri", _RESOURCES_SPEC)
            )
        if not (first.get("text") or first.get("blob")):
            checks.append(
                _fail(
                    "resources-read-body",
                    "Content missing text or blob",
                    _RESOURCES_SPEC,
                )
            )
    else:
        checks.append(
            _fail("resources-read-item", "Content item is not object", _RESOURCES_SPEC)
        )

    return checks


def check_resource_templates_list(result: Any) -> list[SpecCheck]:
    """Validate resources/templates/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    templates = result.get("resourceTemplates")
    if templates is None:
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
        if not template.get("uri"):
            checks.append(
                _fail(
                    "resources-templates-uri",
                    f"Template {idx} missing uri",
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
        if not prompt.get("description"):
            checks.append(
                _fail(
                    "prompts-list-description",
                    f"Prompt {idx} missing description",
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
            _fail("prompts-get-empty", "messages array is empty", _PROMPTS_SPEC)
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
