"""Spec guard runner for targeted MCP protocol checks."""

from __future__ import annotations

import json
from typing import Any

from .helpers import SpecCheck, fail as _fail, warn as _warn
from .schema_validator import validate_definition
from .spec_checks import (
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
    check_tool_schema_fields,
)

_TOOLS_SPEC = {
    "spec_id": "MCP-Tools",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
}

_SCHEMA_SPEC = {
    "spec_id": "MCP-Schema",
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

_COMPLETIONS_SPEC = {
    "spec_id": "MCP-Completions",
    "spec_url": (
        "https://modelcontextprotocol.io/specification/2025-06-18/server/completions"
    ),
}


def _parse_prompt_args(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"spec_prompt_args is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("spec_prompt_args must be a JSON object")
    return parsed


async def run_spec_suite(
    transport: Any,
    resource_uri: str | None = None,
    prompt_name: str | None = None,
    prompt_args: str | None = None,
) -> list[SpecCheck]:
    """Run targeted spec guard checks against core MCP endpoints."""
    checks: list[SpecCheck] = []
    capabilities: dict[str, Any] = {}

    try:
        result = await transport.send_request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-fuzzer", "version": "0.0.0"},
            },
        )
        checks.extend(validate_definition("InitializeResult", result))
        if isinstance(result, dict):
            capabilities = result.get("capabilities") or {}
        await transport.send_notification("notifications/initialized")
    except Exception as exc:
        checks.append(_fail("initialize", f"initialize failed: {exc}", _SCHEMA_SPEC))
        return checks

    try:
        result = await transport.send_request("ping")
        checks.extend(validate_definition("EmptyResult", result))
    except Exception as exc:
        checks.append(_fail("ping", f"ping failed: {exc}", _SCHEMA_SPEC))

    if isinstance(capabilities, dict) and capabilities.get("tools") is not None:
        tools: list[Any] = []
        try:
            result = await transport.send_request("tools/list")
            checks.extend(validate_definition("ListToolsResult", result))
            if isinstance(result, dict):
                tools = result.get("tools") or []
            for tool in tools:
                checks.extend(check_tool_schema_fields(tool))
        except Exception as exc:
            checks.append(_fail("tools-list", f"tools/list failed: {exc}", _TOOLS_SPEC))
            tools = []

        callable_tool = None
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            schema = tool.get("inputSchema") or {}
            required = schema.get("required") if isinstance(schema, dict) else []
            if not required:
                callable_tool = tool
                break

        if callable_tool:
            try:
                result = await transport.send_request(
                    "tools/call",
                    {"name": callable_tool.get("name"), "arguments": {}},
                )
                checks.extend(validate_definition("CallToolResult", result))
            except Exception as exc:
                checks.append(
                    _fail("tools-call", f"tools/call failed: {exc}", _TOOLS_SPEC)
                )
        elif tools:
            checks.append(
                _warn(
                    "tools-call",
                    "No tool found without required arguments; skipping tools/call",
                    _TOOLS_SPEC,
                )
            )

    if isinstance(capabilities, dict) and capabilities.get("resources") is not None:
        try:
            result = await transport.send_request("resources/list")
            checks.extend(validate_definition("ListResourcesResult", result))
            checks.extend(check_resources_list(result))
        except Exception as exc:
            checks.append(
                _fail(
                    "resources-list",
                    f"resources/list failed: {exc}",
                    _RESOURCES_SPEC,
                )
            )

        try:
            result = await transport.send_request("resources/templates/list")
            checks.extend(validate_definition("ListResourceTemplatesResult", result))
            checks.extend(check_resource_templates_list(result))
        except Exception as exc:
            checks.append(
                _fail(
                    "resources-templates-list",
                    f"resources/templates/list failed: {exc}",
                    _RESOURCES_SPEC,
                )
            )

        if resource_uri:
            try:
                result = await transport.send_request(
                    "resources/read", {"uri": resource_uri}
                )
                checks.extend(validate_definition("ReadResourceResult", result))
                checks.extend(check_resources_read(result))
            except Exception as exc:
                checks.append(
                    _fail(
                        "resources-read",
                        f"resources/read failed: {exc}",
                        _RESOURCES_SPEC,
                    )
                )

    if isinstance(capabilities, dict) and capabilities.get("prompts") is not None:
        try:
            result = await transport.send_request("prompts/list")
            checks.extend(validate_definition("ListPromptsResult", result))
            checks.extend(check_prompts_list(result))
        except Exception as exc:
            checks.append(
                _fail("prompts-list", f"prompts/list failed: {exc}", _PROMPTS_SPEC)
            )

        if prompt_name:
            try:
                args = _parse_prompt_args(prompt_args) or {}
                result = await transport.send_request(
                    "prompts/get", {"name": prompt_name, "arguments": args}
                )
                checks.extend(validate_definition("GetPromptResult", result))
                checks.extend(check_prompts_get(result))
            except Exception as exc:
                checks.append(
                    _fail("prompts-get", f"prompts/get failed: {exc}", _PROMPTS_SPEC)
                )

    if isinstance(capabilities, dict) and capabilities.get("completions") is not None:
        if prompt_name:
            try:
                result = await transport.send_request(
                    "completion/complete",
                    {
                        "ref": {"type": "ref/prompt", "name": prompt_name},
                        "argument": {"name": "query", "value": "probe"},
                    },
                )
                checks.extend(validate_definition("CompleteResult", result))
            except Exception as exc:
                checks.append(
                    _fail(
                        "completion-complete",
                        f"completion/complete failed: {exc}",
                        _COMPLETIONS_SPEC,
                    )
                )
        else:
            checks.append(
                _warn(
                    "completion-complete",
                    "No prompt name provided; skipping completion/complete",
                    _COMPLETIONS_SPEC,
                )
            )

    return checks
