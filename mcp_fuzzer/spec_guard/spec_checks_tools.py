"""MCP spec checks - tool definition and tool result checks."""

from .spec_checks_misc import _spec_at_least
from typing import Any

from .check_ids import CheckID
from .helpers import (
    SCHEMA_SPEC,
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
_SCHEMA_SPEC = spec_variant(SCHEMA_SPEC, spec_id="MCP-JSON-Schema")

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

