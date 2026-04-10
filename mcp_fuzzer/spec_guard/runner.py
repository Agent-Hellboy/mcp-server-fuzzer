"""Spec guard runner for targeted MCP protocol checks."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from .helpers import (
    COMPLETIONS_SPEC,
    PROMPTS_SPEC,
    RESOURCES_SPEC,
    SCHEMA_SPEC,
    TASKS_SPEC,
    TOOLS_SPEC,
    SpecCheck,
    fail as _fail,
    warn as _warn,
)
from .schema_validator import (
    SCHEMA_BASE_PATH,
    discover_testable_schemas,
    validate_definition,
)
from .spec_checks import (
    check_task_payload_result,
    check_task_result,
    check_tasks_list,
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
    check_tool_schema_fields,
)
from ..utils.schema_helpers import _build_tool_arguments, _tool_task_support

_TOOLS_SPEC = TOOLS_SPEC
_SCHEMA_SPEC = SCHEMA_SPEC
_RESOURCES_SPEC = RESOURCES_SPEC
_PROMPTS_SPEC = PROMPTS_SPEC
_COMPLETIONS_SPEC = COMPLETIONS_SPEC
_TASKS_SPEC = TASKS_SPEC


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


def _client_capabilities() -> dict[str, Any]:
    return {
        "elicitation": {"form": {}, "url": {}},
        "experimental": {},
        "roots": {"listChanged": True},
        "sampling": {"context": {}, "tools": {}},
        "tasks": {
            "cancel": {},
            "list": {},
            "requests": {
                "elicitation": {"create": {}},
                "sampling": {"createMessage": {}},
            },
        },
    }


async def run_spec_suite(
    transport: Any,
    resource_uri: str | None = None,
    prompt_name: str | None = None,
    prompt_args: str | None = None,
) -> list[SpecCheck]:
    """Run targeted spec guard checks against core MCP endpoints."""
    checks: list[SpecCheck] = []
    capabilities: dict[str, Any] = {}
    protocol_version = os.getenv("MCP_SPEC_SCHEMA_VERSION", "2025-11-25")
    version_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    task_id: str | None = None
    task_origin_method: str | None = None

    try:
        result = await transport.send_request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": _client_capabilities(),
                "clientInfo": {"name": "mcp-fuzzer", "version": "0.1.0"},
            },
        )
        if isinstance(result, dict):
            capabilities = result.get("capabilities") or {}
            server_version = result.get("protocolVersion")
            if not isinstance(server_version, str) or not server_version:
                checks.append(
                    _fail(
                        "protocol-version",
                        "Server did not return protocolVersion in initialize response",
                        _SCHEMA_SPEC,
                    )
                )
                return checks
            schema_path = SCHEMA_BASE_PATH / server_version / "schema.json"
            if not version_pattern.match(server_version) or not schema_path.exists():
                checks.append(
                    _fail(
                        "protocol-version",
                        "Server returned invalid or unsupported protocolVersion: "
                        f"{server_version}",
                        _SCHEMA_SPEC,
                    )
                )
                return checks
            protocol_version = server_version
        else:
            checks.append(
                _fail(
                    "protocol-version",
                    "Initialize response missing protocolVersion",
                    _SCHEMA_SPEC,
                )
            )
            return checks
        checks.extend(
            validate_definition("InitializeResult", result, version=protocol_version)
        )
        await transport.send_notification("notifications/initialized")
    except Exception as exc:
        checks.append(_fail("initialize", f"initialize failed: {exc}", _SCHEMA_SPEC))
        return checks

    # Discover all testable schemas based on server capabilities
    testable_schemas = discover_testable_schemas(
        version=protocol_version, capabilities=capabilities
    )
    
    # Track which methods we've already tested to avoid duplicates
    tested_methods: set[str] = set()

    try:
        result = await transport.send_request("ping")
        checks.extend(
            validate_definition("EmptyResult", result, version=protocol_version)
        )
        tested_methods.add("ping")
    except Exception as exc:
        checks.append(_fail("ping", f"ping failed: {exc}", _SCHEMA_SPEC))

    tasks_capability = (
        capabilities.get("tasks") if isinstance(capabilities, dict) else None
    )
    task_request_caps = (
        tasks_capability.get("requests")
        if isinstance(tasks_capability, dict)
        else None
    )
    tool_task_capability = (
        task_request_caps.get("tools")
        if isinstance(task_request_caps, dict)
        else None
    )
    supports_task_augmented_tools = (
        isinstance(tool_task_capability, dict)
        and tool_task_capability.get("call") is not None
    )

    if isinstance(capabilities, dict) and capabilities.get("tools") is not None:
        tools: list[Any] = []
        try:
            result = await transport.send_request("tools/list")
            checks.extend(
                validate_definition("ListToolsResult", result, version=protocol_version)
            )
            tested_methods.add("tools/list")
            if isinstance(result, dict):
                tools = result.get("tools") or []
            for tool in tools:
                checks.extend(check_tool_schema_fields(tool))
        except Exception as exc:
            checks.append(_fail("tools-list", f"tools/list failed: {exc}", _TOOLS_SPEC))
            tools = []

        callable_tool: dict[str, Any] | None = None
        task_callable_tool: dict[str, Any] | None = None
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            schema = tool.get("inputSchema")
            required = schema.get("required") if isinstance(schema, dict) else []
            if not isinstance(required, list):
                required = []
            arguments = _build_tool_arguments(tool)
            has_all_required_args = not required or len(arguments) == len(required)
            task_support = _tool_task_support(tool)
            if (
                callable_tool is None
                and task_support != "required"
                and has_all_required_args
            ):
                callable_tool = tool
            if (
                task_callable_tool is None
                and task_support in {"optional", "required"}
                and has_all_required_args
            ):
                task_callable_tool = tool

        if callable_tool:
            try:
                result = await transport.send_request(
                    "tools/call",
                    {
                        "name": callable_tool.get("name"),
                        "arguments": _build_tool_arguments(callable_tool),
                    },
                )
                checks.extend(
                    validate_definition(
                        "CallToolResult", result, version=protocol_version
                    )
                )
                tested_methods.add("tools/call")
            except Exception as exc:
                checks.append(
                    _fail("tools-call", f"tools/call failed: {exc}", _TOOLS_SPEC)
                )
        elif tools:
            checks.append(
                _warn(
                    "tools-call",
                    "No directly callable tool found; skipping non-task tools/call",
                    _TOOLS_SPEC,
                )
            )

        if supports_task_augmented_tools and task_callable_tool:
            try:
                result = await transport.send_request(
                    "tools/call",
                    {
                        "name": task_callable_tool.get("name"),
                        "arguments": _build_tool_arguments(task_callable_tool),
                        "task": {"ttl": 60000},
                    },
                )
                checks.extend(
                    validate_definition(
                        "CreateTaskResult", result, version=protocol_version
                    )
                )
                if isinstance(result, dict):
                    task = result.get("task")
                    if isinstance(task, dict):
                        task_id_candidate = task.get("taskId")
                        if isinstance(task_id_candidate, str) and task_id_candidate:
                            task_id = task_id_candidate
                            task_origin_method = "tools/call"
                            checks.extend(check_task_result(task))
            except Exception as exc:
                checks.append(
                    _fail(
                        "tools-call-task",
                        f"task-augmented tools/call failed: {exc}",
                        _TOOLS_SPEC,
                    )
                )

    if isinstance(capabilities, dict) and capabilities.get("resources") is not None:
        try:
            result = await transport.send_request("resources/list")
            checks.extend(
                validate_definition(
                    "ListResourcesResult", result, version=protocol_version
                )
            )
            tested_methods.add("resources/list")
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
            checks.extend(
                validate_definition(
                    "ListResourceTemplatesResult", result, version=protocol_version
                )
            )
            tested_methods.add("resources/templates/list")
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
                checks.extend(
                    validate_definition(
                        "ReadResourceResult", result, version=protocol_version
                    )
                )
                tested_methods.add("resources/read")
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
            checks.extend(
                validate_definition(
                    "ListPromptsResult", result, version=protocol_version
                )
            )
            tested_methods.add("prompts/list")
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
                checks.extend(
                    validate_definition(
                        "GetPromptResult", result, version=protocol_version
                    )
                )
                tested_methods.add("prompts/get")
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
                checks.extend(
                    validate_definition(
                        "CompleteResult", result, version=protocol_version
                    )
                )
                tested_methods.add("completion/complete")
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

    if isinstance(tasks_capability, dict):
        if tasks_capability.get("list") is not None:
            try:
                result = await transport.send_request("tasks/list")
                checks.extend(
                    validate_definition(
                        "ListTasksResult", result, version=protocol_version
                    )
                )
                tested_methods.add("tasks/list")
                checks.extend(check_tasks_list(result))
                if task_id is None and isinstance(result, dict):
                    tasks = result.get("tasks")
                    if isinstance(tasks, list):
                        for task in tasks:
                            if isinstance(task, dict):
                                task_id_candidate = task.get("taskId")
                                if (
                                    isinstance(task_id_candidate, str)
                                    and task_id_candidate
                                ):
                                    task_id = task_id_candidate
                                    break
            except Exception as exc:
                checks.append(
                    _fail("tasks-list", f"tasks/list failed: {exc}", _TASKS_SPEC)
                )

        if task_id:
            try:
                result = await transport.send_request("tasks/get", {"taskId": task_id})
                checks.extend(
                    validate_definition(
                        "GetTaskResult", result, version=protocol_version
                    )
                )
                tested_methods.add("tasks/get")
                checks.extend(check_task_result(result))
            except Exception as exc:
                checks.append(
                    _fail("tasks-get", f"tasks/get failed: {exc}", _TASKS_SPEC)
                )

            try:
                result = await transport.send_request(
                    "tasks/result", {"taskId": task_id}
                )
                checks.extend(
                    validate_definition(
                        "GetTaskPayloadResult", result, version=protocol_version
                    )
                )
                tested_methods.add("tasks/result")
                checks.extend(check_task_payload_result(result))
                if task_origin_method == "tools/call":
                    checks.extend(
                        validate_definition(
                            "CallToolResult", result, version=protocol_version
                        )
                    )
            except Exception as exc:
                checks.append(
                    _fail("tasks-result", f"tasks/result failed: {exc}", _TASKS_SPEC)
                )

            if tasks_capability.get("cancel") is not None:
                try:
                    result = await transport.send_request(
                        "tasks/cancel", {"taskId": task_id}
                    )
                    checks.extend(
                        validate_definition(
                            "CancelTaskResult", result, version=protocol_version
                        )
                    )
                    tested_methods.add("tasks/cancel")
                    checks.extend(check_task_result(result))
                except Exception as exc:
                    checks.append(
                        _fail(
                            "tasks-cancel",
                            f"tasks/cancel failed: {exc}",
                            _TASKS_SPEC,
                        )
                    )

    # Test all discovered schemas that haven't been tested yet
    # This ensures we validate all Result types from the schema if server supports them
    for result_type, method, capability_key in testable_schemas:
        if method in tested_methods:
            continue  # Already tested above with specific logic
        
        # Skip methods that need special handling (already covered above)
        if method in (
            "initialize",
            "ping",
            "tools/call",
            "completion/complete",
            "tasks/list",
            "tasks/get",
            "tasks/result",
            "tasks/cancel",
        ):
            continue
        
        # Skip methods that require specific parameters we don't have
        if method == "resources/read" and not resource_uri:
            continue
        if method == "prompts/get" and not prompt_name:
            continue
        if method == "tasks/get" and not task_id:
            continue
        if method == "tasks/result" and not task_id:
            continue
        if method == "tasks/cancel" and not task_id:
            continue

        try:
            # Build request params based on method
            params: dict[str, Any] = {}
            if method == "resources/read":
                params = {"uri": resource_uri}
            elif method == "prompts/get":
                args = _parse_prompt_args(prompt_args) or {}
                params = {"name": prompt_name, "arguments": args}
            elif method in {"tasks/get", "tasks/result", "tasks/cancel"}:
                params = {"taskId": task_id}
            # For other methods (roots/list, tasks/list, etc.), use empty params
            
            result = await transport.send_request(method, params)
            checks.extend(
                validate_definition(result_type, result, version=protocol_version)
            )
            tested_methods.add(method)
        except Exception as exc:
            # Only log as fail if it's a capability we detected
            # Otherwise it might be expected (e.g., method not implemented)
            if capability_key and isinstance(capabilities, dict):
                cap_value = capabilities.get(capability_key)
                if cap_value is not None and cap_value is not False:
                    checks.append(
                        _fail(
                            f"{method.replace('/', '-')}",
                            f"{method} failed: {exc}",
                            _SCHEMA_SPEC,
                        )
                    )

    return checks
