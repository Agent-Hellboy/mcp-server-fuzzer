"""Mappings for protocol/method spec guard checks."""

from __future__ import annotations

from typing import Any, Callable

from .helpers import SpecCheck
from .spec_checks import (
    check_tool_result_content,
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
)

_CheckFn = Callable[[Any], list[SpecCheck]]

METHOD_CHECK_MAP: dict[str, tuple[_CheckFn, str]] = {
    "tools/call": (check_tool_result_content, "tools/call"),
    "resources/list": (check_resources_list, "resources/list"),
    "resources/read": (check_resources_read, "resources/read"),
    "resources/templates/list": (
        check_resource_templates_list,
        "resources/templates/list",
    ),
    "prompts/list": (check_prompts_list, "prompts/list"),
    "prompts/get": (check_prompts_get, "prompts/get"),
}

PROTOCOL_TYPE_TO_METHOD: dict[str, str] = {
    "ListResourcesRequest": "resources/list",
    "ReadResourceRequest": "resources/read",
    "ListResourceTemplatesRequest": "resources/templates/list",
    "ListPromptsRequest": "prompts/list",
    "GetPromptRequest": "prompts/get",
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
